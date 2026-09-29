"""
holdout_sweep.py  Temporal-holdout threshold sweep for the binary detector.

Why temporal, not random
------------------------
Stride-1 windowing makes adjacent sequences share sub-windows, so a random
stratified split leaks: a test sequence's windows also live in a training
sequence. The only leak-free cut is at WHOLE-DAY boundaries — different capture
days are separate event streams (separate files, separate synthetic-time
anchors), so no window is shared across them. CIC-IDS-2017 was captured Mon->Fri,
so "hold out the last day(s)" == hold out whole later days.

Split (all leak-free at the day level)
--------------------------------------
* weights  : monday, tuesday, wednesday  (earlier days), MINUS a temporal tail
* calib T  : the last `--calib-frac` of that pool (falls inside wednesday), used
             ONLY to fit the temperature scalar — never scored. The
             weights/calib boundary is purged by SEQUENCE_LENGTH-1 sequences so
             the two do not share sub-windows either.
* test     : thursday, friday (the last capture days), scored for the sweep.

This is deliberately a hard, honest test: the test days carry attack families
(web/infiltration, botnet/DDoS/portscan) that the training days
(Patator, DoS) do not, so the numbers here are a lower, more trustworthy bound
than the in-distribution random-slice numbers.

Reuses deploy.py's data/inference/temperature primitives and train.py's training
loop unchanged. Does not touch gat.py, lstm.py, the stage classifier, the
architecture, or the feature set.

Run (from backend/):
    python holdout_sweep.py
    python holdout_sweep.py --train-days monday,tuesday,wednesday --test-days thursday,friday
"""

from __future__ import annotations

import argparse
import random
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.metrics import (average_precision_score, confusion_matrix,
                             f1_score, precision_recall_curve, roc_auc_score)

from app import config
from app.graph.builder import NODE_FEATURE_NAMES, EDGE_FEATURE_NAMES
from app.models.world_model import WorldModel
from app.models.seeding import set_seed

from train import train_one_epoch
from deploy import (build_day_pools, collect_logits, fit_temperature,
                    expected_calibration_error, nll)

SWEEP = [round(0.30 + 0.05 * i, 2) for i in range(14)]  # 0.30 .. 0.95


def _sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-z))


def metrics_at(probs: np.ndarray, y: np.ndarray, t: float) -> dict:
    pred = (probs >= t).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    sens = tp / (tp + fn) if (tp + fn) else float("nan")   # recall
    spec = tn / (tn + fp) if (tn + fp) else float("nan")
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    return {
        "t": t, "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
        "recall": sens, "specificity": spec, "precision": prec,
        "bacc": (sens + spec) / 2, "f1": f1_score(y, pred, zero_division=0),
        "youden": sens + spec - 1.0,
    }


def best_by(probs, y, key: str) -> dict:
    """Fine-grid threshold that maximises `key` (bacc or youden)."""
    best = None
    for t in np.linspace(0.01, 0.99, 99):
        m = metrics_at(probs, y, float(t))
        if best is None or m[key] > best[key]:
            best = m
    return best


def print_sweep(probs, y, label: str) -> None:
    print(f"\n  {label}: threshold sweep")
    print(f"  {'thr':>5}{'recall':>9}{'spec':>9}{'prec':>9}{'F1':>9}{'bal_acc':>9}"
          f"{'youden':>9}{'TP':>6}{'FP':>6}{'FN':>6}{'TN':>6}")
    for t in SWEEP:
        m = metrics_at(probs, y, t)
        print(f"  {t:>5.2f}{m['recall']:>9.4f}{m['specificity']:>9.4f}{m['precision']:>9.4f}"
              f"{m['f1']:>9.4f}{m['bacc']:>9.4f}{m['youden']:>9.4f}"
              f"{m['tp']:>6}{m['fp']:>6}{m['fn']:>6}{m['tn']:>6}")


def print_pr_curve(probs, y, label: str) -> None:
    ap = average_precision_score(y, probs)
    prec, rec, _ = precision_recall_curve(y, probs)
    print(f"\n  {label}: PR-AUC (average precision) = {ap:.4f}")
    print(f"  precision at recall levels:")
    line = "   "
    for target in [0.50, 0.60, 0.70, 0.80, 0.90, 0.95, 0.99, 1.00]:
        # highest precision achievable at recall >= target
        mask = rec >= target
        p = prec[mask].max() if mask.any() else float("nan")
        line += f" r>={target:.2f}:{p:.3f}"
    print(line)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-dir", type=str, default="data/raw")
    parser.add_argument("--train-days", type=str, default="monday,tuesday,wednesday")
    parser.add_argument("--test-days", type=str, default="thursday,friday")
    parser.add_argument("--calib-frac", type=float, default=0.15,
                        help="Temporal tail of the training pool held out to fit T (only)")
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--seed", type=int, default=config.GLOBAL_SEED)
    parser.add_argument("--device", type=str, default="cpu")
    parser.add_argument("--save", type=str, default="checkpoints/holdout/sentinel_holdout.pt")
    args = parser.parse_args()

    config.FEATURE_SCALING = "linear"
    set_seed(args.seed)
    device = torch.device(args.device)
    train_days = [d.strip() for d in args.train_days.split(",")]
    test_days = [d.strip() for d in args.test_days.split(",")]
    seq_len = config.SEQUENCE_LENGTH

    print(f"Feature scaling: {config.FEATURE_SCALING}   seed: {args.seed}   epochs: {args.epochs}")
    print(f"Train days: {train_days}   Test days: {test_days}   calib-frac: {args.calib_frac}")

    print("\nBuilding day pools ...")
    day_pools = build_day_pools(Path(args.data_dir))

    # Training pool in temporal (capture-day, then window) order.
    train_full = [item for d in train_days for item in day_pools.get(d, [])]
    test_pairs = [item for d in test_days for item in day_pools.get(d, [])]

    # Calibration slice = the last calib_frac of EACH training day (a per-day
    # temporal tail), unioned. A single tail of the concatenated pool lands
    # entirely in the last day, which on this dataset is attack-only (benign is
    # front-loaded on monday), giving a degenerate single-class T fit. Per-day
    # tails keep both classes in the calib slice. Each day's weights/calib
    # boundary is purged by seq_len-1 so the two never share sub-windows, and the
    # calib slice is still leak-free w.r.t. the test days (different files).
    weights_pairs, calib_pairs = [], []
    for d in train_days:
        items = day_pools.get(d, [])
        if not items:
            continue
        k = int(round(len(items) * args.calib_frac))
        if k == 0:
            weights_pairs.extend(items)
            continue
        cut_d = len(items) - k
        calib_pairs.extend(items[cut_d:])
        weights_pairs.extend(items[:max(0, cut_d - (seq_len - 1))])

    def counts(pairs):
        b = sum(1 for _s, t in pairs if t[0] == 0)
        a = sum(1 for _s, t in pairs if t[0] == 1)
        return b, a

    wb, wa = counts(weights_pairs)
    cb, ca = counts(calib_pairs)
    tb, ta = counts(test_pairs)
    print(f"  weights : {len(weights_pairs)} ({wb} benign / {wa} attack)")
    print(f"  calib T : {len(calib_pairs)} ({cb} benign / {ca} attack)  [temporal tail, purged {seq_len-1}]")
    print(f"  test    : {len(test_pairs)} ({tb} benign / {ta} attack)")
    if tb == 0 or ta == 0:
        print("STOP: test set is single-class; pick different --test-days.")
        return
    if cb == 0 or ca == 0:
        print("WARNING: calibration slice is single-class; temperature fit may be degenerate.")

    # ---- train fresh detector on the earlier days (binary only) ----
    random.shuffle(weights_pairs)
    tr_seqs = [s for s, _ in weights_pairs]
    tr_targets = [t for _, t in weights_pairs]
    model = WorldModel(
        node_in_dim=len(NODE_FEATURE_NAMES), edge_in_dim=len(EDGE_FEATURE_NAMES),
        gat_hidden_dim=128, gat_num_heads=4, gat_out_dim=64, gat_dropout=0.1,
        lstm_hidden_dim=128, lstm_num_layers=2, lstm_dropout=0.1,
        num_mitre_stages=config.NUM_MITRE_STAGES, window_feat_dim=config.NUM_FEATURES,
        mitre_arch="mlp",
    ).to(device)
    optimizer = optim.Adam(model.parameters(), lr=3e-4)
    attack_criterion = nn.BCEWithLogitsLoss()
    mitre_criterion = nn.CrossEntropyLoss()

    print(f"\nTraining {args.epochs} epochs on earlier days (binary only) ...")
    for epoch in range(1, args.epochs + 1):
        loss = train_one_epoch(model, optimizer, tr_seqs, tr_targets,
                               attack_criterion, mitre_criterion, mitre_weight=0.0)
        print(f"  epoch {epoch:2d}/{args.epochs} - loss {loss:.4f}", flush=True)

    save_path = Path(args.save)
    save_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), save_path)
    print(f"\nSaved holdout detector to {save_path}")

    # ---- inference: test (scored) + calib (T fit only) ----
    test_logits, test_y = collect_logits(model, test_pairs, device)
    calib_logits, calib_y = collect_logits(model, calib_pairs, device)
    probs_uncal = _sigmoid(test_logits)

    temperature = fit_temperature(calib_logits, calib_y)
    probs_cal = _sigmoid(test_logits / temperature)
    print(f"\nTemperature fit on calib slice (separate from test): T = {temperature:.4f}")

    # ---- threshold-free discrimination (identical for uncal/cal: monotonic) ----
    roc = roc_auc_score(test_y, probs_uncal)
    print("\n" + "=" * 78)
    print(f"TEMPORAL HOLDOUT  test = {test_days}  (n={len(test_y)}, "
          f"{tb} benign / {ta} attack)")
    print("=" * 78)
    print(f"  ROC-AUC = {roc:.4f}   (threshold-free; invariant to calibration)")
    print_pr_curve(probs_uncal, test_y, "UNCALIBRATED")
    print(f"  (PR-AUC is identical under temperature scaling; T only rescales the "
          f"threshold axis, not the ranking)")

    # ---- calibration quality on test (T fit elsewhere, so this is honest) ----
    print(f"\n  Calibration on test: ECE {expected_calibration_error(probs_uncal, test_y):.4f}"
          f" -> {expected_calibration_error(probs_cal, test_y):.4f}   |   "
          f"NLL {nll(probs_uncal, test_y):.4f} -> {nll(probs_cal, test_y):.4f}   (uncal -> cal)")

    # ---- sweeps ----
    print("\n" + "-" * 78)
    print("UNCALIBRATED")
    print("-" * 78)
    print_sweep(probs_uncal, test_y, "uncalibrated")
    print("\n" + "-" * 78)
    print(f"TEMPERATURE-CALIBRATED  (T = {temperature:.4f}, fit on separate calib slice)")
    print("-" * 78)
    print_sweep(probs_cal, test_y, "calibrated")

    # ---- optimal thresholds ----
    print("\n" + "=" * 78)
    print("OPTIMAL OPERATING POINTS")
    print("=" * 78)
    for label, probs in [("uncalibrated", probs_uncal), ("calibrated", probs_cal)]:
        jy = best_by(probs, test_y, "youden")
        ba = best_by(probs, test_y, "bacc")
        print(f"\n  {label}:")
        print(f"    max Youden J : t={jy['t']:.2f}  J={jy['youden']:.4f}  "
              f"recall={jy['recall']:.4f}  spec={jy['specificity']:.4f}  bal_acc={jy['bacc']:.4f}  F1={jy['f1']:.4f}")
        print(f"    max bal_acc  : t={ba['t']:.2f}  bal_acc={ba['bacc']:.4f}  "
              f"recall={ba['recall']:.4f}  spec={ba['specificity']:.4f}  youden={ba['youden']:.4f}  F1={ba['f1']:.4f}")


if __name__ == "__main__":
    main()
