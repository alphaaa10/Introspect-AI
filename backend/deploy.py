"""
deploy.py  All-days binary detector + temperature calibration.

What this trains
----------------
ONE binary GAT+LSTM attack detector on all five CIC-IDS-2017 days, with the
MITRE stage head switched off (--mitre-weight 0.0). This is the shippable
detector: unlike the LODO/blocked folds — which hold data out to *estimate*
generalisation — this run uses every day so the deployed weights have seen the
whole benign baseline (Monday included), which is what closes the Monday
false-positive gap.

Training schedule
-----------------
* Cosine LR decay from --lr (3e-4) to --lr-min (3e-5) over the epochs. The
  earlier fixed-LR run spiked at the final epoch (loss 0.09 -> 0.19) and shipped
  those noisy weights; decaying the LR toward ~0 removes the late thrashing.
* Lowest-training-loss checkpoint is what gets saved as sentinel_deploy.pt, not
  the final epoch. There is still no validation set and no early stopping; this
  is best-checkpoint on training loss, which fixes the spike without any
  hyperparameter chase.

Calibration protocol (read before trusting the numbers)
-------------------------------------------------------
* A 10% slice — the last 10% of EACH day (a per-day temporal tail), unioned — is
  held out ONLY to fit the temperature scalar and report calibration. Temporal,
  not random: stride-1 windowing makes adjacent sequences share sub-windows, so a
  random split would leak; the within-day weights/calib boundary is purged by
  SEQUENCE_LENGTH-1. Per-day tails (vs one tail of the pool) keep both classes in
  the slice, since monday's benign tail is included.
* Temperature scaling divides the logit by a single learned T>0. It is strictly
  monotonic, so at a fixed 0.5 threshold it CANNOT change any decision — lines
  (1) and (2) below are therefore equal by construction, and AUC is identical
  before/after. What temperature scaling changes is probability quality (ECE,
  NLL). Any balanced-accuracy improvement comes from moving the threshold
  (line 3), not from calibration. These are reported separately on purpose.

Run (from backend/):
    python deploy.py                       # 30 epochs, seed 42, all five days
    python deploy.py --epochs 30 --holdout 0.10
"""

from __future__ import annotations

import argparse
import bisect
import random
import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.metrics import balanced_accuracy_score, log_loss, roc_auc_score

from app import config
from app.schemas import DataSource
from app.ingestion.parser import parse_cicids2017_csv
from app.features.extractor import window_and_extract
from app.graph.builder import build_graph, NODE_FEATURE_NAMES, EDGE_FEATURE_NAMES
from app.models.world_model import WorldModel
from app.models.seeding import set_seed

# train.py's own primitives — imported, not reimplemented, so the deployment
# detector is built by the exact code path the experiments used.
from train import create_sequences, train_one_epoch, collate_sequences

DAYS = ["monday", "tuesday", "wednesday", "thursday", "friday"]
DEFAULT_SAVE = Path("checkpoints/deploy_all_days/sentinel_deploy.pt")


def build_day_pools(data_dir: Path) -> dict[str, list]:
    """parse -> window+extract -> build_graph (21 window features) ->
    contiguous-chunk -> create_sequences(dominant). Identical to train.py."""
    csv_files = [data_dir / f"{d}_plus.csv" for d in DAYS]
    missing = [p for p in csv_files if not p.exists()]
    if missing:
        print("STOP: missing data files (run from backend/):", file=sys.stderr)
        for p in missing:
            print(f"  {p.resolve()}", file=sys.stderr)
        sys.exit(1)

    day_pools: dict[str, list] = {}
    for fp in csv_files:
        print(f"  parsing {fp.name} ...", flush=True)
        events, _ = parse_cicids2017_csv(fp, source=DataSource.REAL)
        if not events:
            continue
        feature_records = window_and_extract(events)
        events_by_window: dict = {}
        window_starts = [fr.window_start for fr in feature_records]
        for e in events:
            idx = bisect.bisect_right(window_starts, e.timestamp) - 1
            if idx >= 0:
                fr = feature_records[idx]
                if fr.window_start <= e.timestamp < fr.window_end:
                    events_by_window.setdefault(fr.window_id, []).append(e)
        windows = []
        for fr in feature_records:
            windows.append(build_graph(
                events_by_window.get(fr.window_id, []),
                fr.window_id, fr.window_start, fr.window_end,
                fr.source, window_features=fr.feature_vector,
            ))
        chunks, current = [], []
        for w in windows:
            if not current or w.window_start == current[-1].window_end:
                current.append(w)
            else:
                chunks.append(current)
                current = [w]
        if current:
            chunks.append(current)
        day = fp.stem.split("_")[0]
        day_pools.setdefault(day, [])
        for chunk in chunks:
            seqs, targets = create_sequences(chunk, events, label_policy="dominant")
            if seqs:
                day_pools[day].extend(list(zip(seqs, targets)))
    return day_pools


@torch.no_grad()
def collect_logits(model: WorldModel, pairs, device) -> tuple[np.ndarray, np.ndarray]:
    """Attack logits (pre-sigmoid) and binary labels over a set of sequences,
    via the same batched encoder train.py uses."""
    model.eval()
    logits, labels = [], []
    for seq, (is_attack, mitre_idx) in pairs:
        collated = collate_sequences([(seq, (is_attack, mitre_idx))], device)
        attack_logits, _ = model.logits_batch(collated)
        logits.append(float(attack_logits.squeeze().item()))
        labels.append(int(is_attack))
    return np.asarray(logits, dtype=np.float64), np.asarray(labels, dtype=np.int64)


def fit_temperature(logits: np.ndarray, labels: np.ndarray) -> float:
    """Single-scalar temperature by NLL minimisation on the held-out slice.

    Optimises log T so T = exp(logT) stays strictly positive (a negative or zero
    temperature would flip or destroy the ranking). LBFGS on one parameter.
    """
    lt = torch.tensor(logits, dtype=torch.float64)
    yt = torch.tensor(labels, dtype=torch.float64)
    log_t = torch.zeros(1, dtype=torch.float64, requires_grad=True)  # T = 1.0 at start
    bce = nn.BCEWithLogitsLoss()
    opt = optim.LBFGS([log_t], lr=0.1, max_iter=200, line_search_fn="strong_wolfe")

    def closure():
        opt.zero_grad()
        loss = bce(lt / torch.exp(log_t), yt)
        loss.backward()
        return loss

    opt.step(closure)
    return float(torch.exp(log_t).item())


def expected_calibration_error(probs: np.ndarray, labels: np.ndarray, n_bins: int = 10) -> float:
    """Guo et al. confidence-based ECE: bin by max(p, 1-p), compare bin accuracy
    to bin mean confidence, weight by bin population."""
    probs = np.asarray(probs)
    labels = np.asarray(labels)
    conf = np.maximum(probs, 1.0 - probs)
    pred = (probs >= 0.5).astype(int)
    correct = (pred == labels).astype(float)
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    ece, n = 0.0, len(probs)
    for i in range(n_bins):
        lo, hi = edges[i], edges[i + 1]
        m = (conf > lo) & (conf <= hi) if i > 0 else (conf >= lo) & (conf <= hi)
        if not m.any():
            continue
        ece += abs(correct[m].mean() - conf[m].mean()) * m.sum() / n
    return float(ece)


def nll(probs: np.ndarray, labels: np.ndarray) -> float:
    return float(log_loss(labels, np.clip(probs, 1e-7, 1 - 1e-7), labels=[0, 1]))


def best_bacc_threshold(probs: np.ndarray, labels: np.ndarray) -> tuple[float, float]:
    """Threshold maximising balanced accuracy on the given probabilities."""
    best_t, best_b = 0.5, -1.0
    for t in np.linspace(0.01, 0.99, 99):
        b = balanced_accuracy_score(labels, (probs >= t).astype(int))
        if b > best_b:
            best_b, best_t = b, float(t)
    return best_t, best_b


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-dir", type=str, default="data/raw")
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--holdout", type=float, default=0.10,
                        help="Stratified fraction held out for temperature fitting ONLY")
    parser.add_argument("--seed", type=int, default=config.GLOBAL_SEED)
    parser.add_argument("--device", type=str, default="cpu")
    parser.add_argument("--lr", type=float, default=3e-4, help="Initial (cosine) LR")
    parser.add_argument("--lr-min", type=float, default=3e-5, help="Final (cosine) LR")
    parser.add_argument("--save", type=str, default=str(DEFAULT_SAVE))
    args = parser.parse_args()

    config.FEATURE_SCALING = "linear"
    set_seed(args.seed)
    device = torch.device(args.device)
    print(f"Feature scaling: {config.FEATURE_SCALING}   seed: {args.seed}   "
          f"epochs: {args.epochs}   device: {device}")

    # ---- data: all five days, flattened ----
    print("\nBuilding day pools (all five days) ...")
    day_pools = build_day_pools(Path(args.data_dir))
    all_pairs = [item for d in DAYS for item in day_pools.get(d, [])]
    print(f"  per-day sizes: {{ {', '.join(f'{d}:{len(day_pools.get(d, []))}' for d in DAYS)} }}")
    print(f"  total sequences: {len(all_pairs)}")

    y_all = [t[0] for _s, t in all_pairs]
    n_atk = sum(y_all)
    print(f"  labels: {len(y_all) - n_atk} benign, {n_atk} attack")

    # ---- temporal calibration slice: the last `holdout` of EACH day, unioned;
    #      temperature fitting ONLY (not validation, no model selection) ----
    # Temporal, not random: stride-1 windowing makes adjacent sequences share
    # sub-windows, so a random split leaks. A per-day tail is leak-free w.r.t.
    # the weights (the within-day boundary is purged by SEQUENCE_LENGTH-1) and,
    # unlike a single tail of the concatenated pool (which lands entirely in the
    # attack-heavy last day), keeps BOTH classes in the slice because monday's
    # benign tail is included.
    seq_len = config.SEQUENCE_LENGTH
    train_pairs, calib_pairs = [], []
    for d in DAYS:
        items = day_pools.get(d, [])
        if not items:
            continue
        k = int(round(len(items) * args.holdout))
        if k == 0:
            train_pairs.extend(items)
            continue
        cut_d = len(items) - k
        calib_pairs.extend(items[cut_d:])
        train_pairs.extend(items[:max(0, cut_d - (seq_len - 1))])
    print(f"  train weights: {len(train_pairs)} "
          f"({sum(1 for _s, t in train_pairs if t[0] == 0)} benign / "
          f"{sum(1 for _s, t in train_pairs if t[0] == 1)} attack)")
    print(f"  calib slice ({args.holdout:.0%} per-day temporal tail, temperature only): "
          f"{len(calib_pairs)} "
          f"({sum(1 for _s, t in calib_pairs if t[0] == 0)} benign / "
          f"{sum(1 for _s, t in calib_pairs if t[0] == 1)} attack)")

    # ---- train ONE binary detector; no validation set and no early stopping,
    #      but DO keep the lowest-training-loss checkpoint (fixes the epoch-30
    #      loss spike that shipped noisy final weights). mitre_weight=0. ----
    random.shuffle(train_pairs)
    train_seqs = [s for s, _ in train_pairs]
    train_targets = [t for _, t in train_pairs]

    model = WorldModel(
        node_in_dim=len(NODE_FEATURE_NAMES), edge_in_dim=len(EDGE_FEATURE_NAMES),
        gat_hidden_dim=128, gat_num_heads=4, gat_out_dim=64, gat_dropout=0.1,
        lstm_hidden_dim=128, lstm_num_layers=2, lstm_dropout=0.1,
        num_mitre_stages=config.NUM_MITRE_STAGES, window_feat_dim=config.NUM_FEATURES,
        mitre_arch="mlp",
    ).to(device)
    optimizer = optim.Adam(model.parameters(), lr=args.lr)
    # Cosine anneal the LR from --lr (3e-4) down to --lr-min (3e-5) over the run.
    # The epoch-30 loss spike in the earlier run was the late-epoch LR thrashing;
    # decaying it toward ~0 removes that. Stepped once per epoch.
    scheduler = optim.lr_scheduler.CosineAnnealingLR(
        optimizer, T_max=args.epochs, eta_min=args.lr_min)
    attack_criterion = nn.BCEWithLogitsLoss()
    mitre_criterion = nn.CrossEntropyLoss()  # unused at mitre_weight=0

    print(f"\nTraining {args.epochs} epochs (binary only, mitre_weight=0.0, "
          f"cosine LR {args.lr:g}->{args.lr_min:g}) ...")
    best_loss, best_epoch, best_state = float("inf"), 0, None
    for epoch in range(1, args.epochs + 1):
        lr_now = optimizer.param_groups[0]["lr"]
        loss = train_one_epoch(model, optimizer, train_seqs, train_targets,
                               attack_criterion, mitre_criterion, mitre_weight=0.0)
        scheduler.step()
        marker = ""
        if loss < best_loss:
            best_loss, best_epoch = loss, epoch
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
            marker = " *"
        print(f"  epoch {epoch:2d}/{args.epochs} - loss {loss:.4f} (lr {lr_now:.2e}){marker}",
              flush=True)

    # Ship the lowest-loss checkpoint, not the final epoch.
    model.load_state_dict(best_state)
    print(f"\nSelected epoch {best_epoch}/{args.epochs} (lowest training loss {best_loss:.4f}); "
          f"restored those weights for deployment.")

    save_path = Path(args.save)
    save_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), save_path)
    print(f"Saved deployment detector to {save_path}")

    # ---- inference: held-out slice + full training set (overfitting check) ----
    tr_logits, tr_labels = collect_logits(model, train_pairs, device)
    ca_logits, ca_labels = collect_logits(model, calib_pairs, device)

    tr_probs = 1.0 / (1.0 + np.exp(-tr_logits))
    ca_probs_uncal = 1.0 / (1.0 + np.exp(-ca_logits))

    print("\n" + "=" * 70)
    print("OVERFITTING CHECK  (balanced accuracy @ 0.5, uncalibrated)")
    print("=" * 70)
    tr_bacc = balanced_accuracy_score(tr_labels, (tr_probs >= 0.5).astype(int))
    ca_bacc = balanced_accuracy_score(ca_labels, (ca_probs_uncal >= 0.5).astype(int))
    print(f"  training weights set ({len(tr_labels)}):  {tr_bacc:.4f}")
    print(f"  held-out calib slice ({len(ca_labels)}):  {ca_bacc:.4f}")
    print(f"  gap (train - slice):              {tr_bacc - ca_bacc:+.4f}")

    # ---- temperature scaling on the slice ----
    temperature = fit_temperature(ca_logits, ca_labels)
    ca_probs_cal = 1.0 / (1.0 + np.exp(-ca_logits / temperature))
    print("\n" + "=" * 70)
    print(f"TEMPERATURE SCALING  (fit on held-out slice)   T = {temperature:.4f}")
    print("=" * 70)

    # four required lines, all on the held-out slice
    bacc_uncal_05 = balanced_accuracy_score(ca_labels, (ca_probs_uncal >= 0.5).astype(int))
    bacc_cal_05 = balanced_accuracy_score(ca_labels, (ca_probs_cal >= 0.5).astype(int))
    t_star, bacc_cal_tstar = best_bacc_threshold(ca_probs_cal, ca_labels)

    ece_before, ece_after = expected_calibration_error(ca_probs_uncal, ca_labels), \
        expected_calibration_error(ca_probs_cal, ca_labels)
    nll_before, nll_after = nll(ca_probs_uncal, ca_labels), nll(ca_probs_cal, ca_labels)

    print(f"  (1) Balanced accuracy @ 0.5, uncalibrated        : {bacc_uncal_05:.4f}")
    print(f"  (2) Balanced accuracy @ 0.5, calibrated          : {bacc_cal_05:.4f}")
    print(f"  (3) Balanced accuracy at tuned threshold T*={t_star:.2f}    : {bacc_cal_tstar:.4f}")
    print(f"  (4) ECE  {ece_before:.4f} -> {ece_after:.4f}   |   "
          f"NLL  {nll_before:.4f} -> {nll_after:.4f}   (before -> after)")

    # honesty notes tied to the monotonicity of temperature scaling
    auc_uncal = roc_auc_score(ca_labels, ca_probs_uncal) if len(set(ca_labels)) > 1 else float("nan")
    auc_cal = roc_auc_score(ca_labels, ca_probs_cal) if len(set(ca_labels)) > 1 else float("nan")
    print(f"\n  note: (1)==(2) by construction — temperature scaling is monotonic, so a")
    print(f"        fixed 0.5 cut is unchanged. AUC confirms invariance: "
          f"{auc_uncal:.4f} -> {auc_cal:.4f}.")
    print(f"        Line (3) improves only via the threshold move, not calibration; ECE/NLL")
    print(f"        (4) are what calibration actually improves.")


if __name__ == "__main__":
    main()
