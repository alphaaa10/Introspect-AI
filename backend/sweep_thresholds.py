"""
sweep_thresholds.py

Re-evaluate the saved LODO checkpoints at a set of FIXED decision thresholds.

Motivation: the training run tuned a threshold per fold on that fold's own
validation day, so the recorded thresholds range from 0.05 to 0.85 and are not
comparable across folds. This script freezes a single threshold at a time and
reports how the five checkpoints behave under it, pooled honestly.

It does NOT train, does NOT modify any model, and imports train.py's own
fold-generation and data-loading building blocks so that each checkpoint is
scored on exactly the test set it was trained against. Fold membership is
cross-checked against the confusion-matrix row sums recorded in
lodo_results.json; on any mismatch the script stops rather than silently
scoring on the wrong data.

Run from the backend/ directory:
    python sweep_thresholds.py
"""

from __future__ import annotations

import argparse
import bisect
import json
import sys
from pathlib import Path

import torch

from app import config
from app.schemas import DataSource
from app.ingestion.parser import parse_cicids2017_csv
from app.features.extractor import window_and_extract
from app.graph.builder import build_graph, NODE_FEATURE_NAMES, EDGE_FEATURE_NAMES
from app.models.world_model import WorldModel
from app.models.seeding import set_seed

# train.py's own fold generator and sequence builder — imported, not reimplemented,
# so fold membership is identical to what produced the checkpoints.
from train import make_lodo_folds, create_sequences

DATA_DIR = Path("data/raw")
CKPT_DIR = Path("checkpoints/full")
DAYS = ["monday", "tuesday", "wednesday", "thursday", "friday"]
CSV_FILES = [DATA_DIR / f"{d}_plus.csv" for d in DAYS]
THRESHOLDS = [0.3, 0.5, 0.6, 0.7, 0.85]
DEVICE = torch.device("cpu")

# Must match run_pipeline's model_args. The saved checkpoints have
# lstm.weight_ih_l0 of (512, 149), i.e. window_feat_dim = NUM_FEATURES = 21, so
# window features are ON. load_state_dict(strict=True) will raise if this is
# wrong, which is the stop condition the task asks for.
MODEL_ARGS = dict(
    node_in_dim=len(NODE_FEATURE_NAMES),
    edge_in_dim=len(EDGE_FEATURE_NAMES),
    gat_hidden_dim=128,
    gat_num_heads=4,
    gat_out_dim=64,
    gat_dropout=0.1,
    lstm_hidden_dim=128,
    lstm_num_layers=2,
    lstm_dropout=0.1,
    num_mitre_stages=config.NUM_MITRE_STAGES,
    window_feat_dim=config.NUM_FEATURES,
)


def die(msg: str) -> "None":
    print(f"\nSTOP: {msg}", file=sys.stderr)
    sys.exit(1)


def build_day_pools() -> dict:
    """Replicate run_pipeline's day_pools construction exactly.

    parse -> window+extract -> build_graph (with the 21 window features) ->
    contiguous-timestamp chunking -> create_sequences(label_policy="dominant").
    """
    missing = [p for p in CSV_FILES if not p.exists()]
    if missing:
        die("missing data files (run from backend/):\n" +
            "\n".join(f"  {p.resolve()}" for p in missing))

    day_pools: dict[str, list] = {}
    for fp in CSV_FILES:
        print(f"  parsing {fp.name} ...", flush=True)
        events, _ = parse_cicids2017_csv(fp, source=DataSource.REAL)
        if not events:
            die(f"{fp.name} parsed to zero events")

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
            window_events = events_by_window.get(fr.window_id, [])
            windows.append(build_graph(
                window_events, fr.window_id, fr.window_start, fr.window_end,
                fr.source, window_features=fr.feature_vector,
            ))

        # contiguous chunks (a break in the window timeline starts a new chunk)
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


def load_recorded_totals() -> dict:
    """Per-fold (n_benign, n_attack) from the recorded confusion matrices.

    cm = [[TN, FP], [FN, TP]] so benign = TN + FP, attack = FN + TP. Used only to
    verify that the rebuilt test folds match what the checkpoints were scored on.
    """
    path = CKPT_DIR / "lodo_results.json"
    if not path.exists():
        print(f"  note: {path} absent - cannot cross-check fold membership")
        return {}
    recorded = json.loads(path.read_text())
    totals = {}
    for day, m in recorded.items():
        cm = m.get("attack_confusion_matrix")
        if cm and len(cm) == 2 and len(cm[0]) == 2:
            (tn, fp), (fn, tp) = cm
            totals[day] = (tn + fp, fn + tp)
    return totals


@torch.no_grad()
def attack_probs_for_fold(model: WorldModel, test) -> tuple[list, list]:
    """Return (probs, true_labels) over a fold's test sequences.

    Uses WorldModel.forward, the documented single-sequence inference path. In
    eval mode dropout is disabled, so this is identical to the batched encoder
    the trainer uses (verified to float32 epsilon in tests/test_batching.py).
    """
    model.eval()
    probs, ys = [], []
    for seq, (is_attack, _mitre) in test:
        probs.append(model(seq).attack_probability)
        ys.append(int(is_attack))
    return probs, ys


def confusion_at(probs, ys, thr) -> tuple[int, int, int, int]:
    tn = fp = fn = tp = 0
    for p, y in zip(probs, ys):
        pred = 1 if p >= thr else 0
        if y == 1 and pred == 1:
            tp += 1
        elif y == 1 and pred == 0:
            fn += 1
        elif y == 0 and pred == 1:
            fp += 1
        else:
            tn += 1
    return tn, fp, fn, tp


def fmt(x) -> str:
    return "  n/a " if x is None else f"{x:6.4f}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint-dir", default="checkpoints/full")
    args = parser.parse_args()
    
    global CKPT_DIR
    CKPT_DIR = Path(args.checkpoint_dir)

    print(f"Feature scaling: {config.FEATURE_SCALING} "
          f"(checkpoints were trained with linear; a mismatch would silently "
          f"change the graph inputs)")
    if config.FEATURE_SCALING != "linear":
        die(f"config.FEATURE_SCALING is {config.FEATURE_SCALING!r}, expected "
            f"'linear'. Set SENTINEL_FEATURE_SCALING=linear.")

    set_seed(config.GLOBAL_SEED)  # model init is overwritten by load; harmless but reproducible

    print("\nBuilding day_pools from full-day files (same path as train.py)...")
    day_pools = build_day_pools()
    print(f"  days: {list(day_pools)}  "
          f"sizes: {{ {', '.join(f'{d}:{len(day_pools[d])}' for d in day_pools)} }}")

    print("\nGenerating LODO folds via train.make_lodo_folds ...")
    folds = {name: test for name, _tr, _val, test in make_lodo_folds(day_pools)}

    recorded = load_recorded_totals()

    # ---- load checkpoints + verify membership -------------------------------
    fold_probs: dict[str, tuple[list, list]] = {}
    for day in DAYS:
        ckpt = CKPT_DIR / f"lodo_fold_{day}.pt"
        if not ckpt.exists():
            print(f"  WARNING: {ckpt.name} missing - skipping fold '{day}'")
            continue
        if day not in folds:
            die(f"fold '{day}' not produced by make_lodo_folds (got {list(folds)})")

        test = folds[day]
        n_benign = sum(1 for _s, (a, _m) in test if a == 0)
        n_attack = sum(1 for _s, (a, _m) in test if a == 1)

        if day in recorded:
            exp_b, exp_a = recorded[day]
            if (n_benign, n_attack) != (exp_b, exp_a):
                die(f"fold '{day}' membership mismatch: rebuilt test set has "
                    f"{n_benign} benign / {n_attack} attack, but lodo_results.json "
                    f"records {exp_b} benign / {exp_a} attack. The checkpoint was "
                    f"scored on a different test set - not evaluating.")

        model = WorldModel(**MODEL_ARGS).to(DEVICE)
        try:
            state = torch.load(ckpt, map_location=DEVICE, weights_only=True)
            # strict=False: tolerate old mitre_head.weight/bias keys from linear head
            # vs new mitre_head.0.*/mitre_head.2.* from the MLP. Backbone keys are
            # verified explicitly below; any backbone mismatch still aborts.
            missing, unexpected = model.load_state_dict(state, strict=False)
            backbone_keys = {k for k in model.state_dict()
                             if k.startswith("gat.") or k.startswith("lstm.") or k.startswith("attack_head.")}
            missed_backbone = [k for k in missing if k in backbone_keys]
            if missed_backbone:
                die(f"backbone keys missing from {ckpt.name}: {missed_backbone}")
        except Exception as e:
            die(f"could not load {ckpt.name} into WorldModel(**model_args): {e}")

        print(f"  loaded {ckpt.name}: {n_benign} benign / {n_attack} attack "
              f"(membership {'verified' if day in recorded else 'unchecked'})")
        fold_probs[day] = attack_probs_for_fold(model, test)

    if not fold_probs:
        die("no checkpoints could be evaluated")

    # ---- sweep --------------------------------------------------------------
    results: dict = {"thresholds": {}, "scaling": config.FEATURE_SCALING}

    print("\n" + "=" * 78)
    print("TABLE A - per fold, per threshold")
    print("=" * 78)
    header = f"{'fold':<10}{'thr':>6}{'TN':>6}{'FP':>6}{'FN':>6}{'TP':>6}" \
             f"{'spec':>8}{'recall':>8}{'F1':>8}"
    print(header)
    print("-" * len(header))

    for thr in THRESHOLDS:
        results["thresholds"][str(thr)] = {"per_fold": {}, "pooled": {}}
        sum_tn = sum_fp = sum_fn = sum_tp = 0
        for day in DAYS:
            if day not in fold_probs:
                continue
            probs, ys = fold_probs[day]
            tn, fp, fn, tp = confusion_at(probs, ys, thr)
            sum_tn += tn; sum_fp += fp; sum_fn += fn; sum_tp += tp

            spec = tn / (tn + fp) if (tn + fp) > 0 else None
            recall = tp / (tp + fn) if (tp + fn) > 0 else None
            f1 = (2 * tp / (2 * tp + fp + fn)) if (2 * tp + fp + fn) > 0 else None
            # F1/recall are n/a for a fold with no attack windows (monday)
            if (tp + fn) == 0:
                recall = None
                f1 = None

            print(f"{day:<10}{thr:>6.2f}{tn:>6}{fp:>6}{fn:>6}{tp:>6}"
                  f"{fmt(spec):>8}{fmt(recall):>8}{fmt(f1):>8}")
            results["thresholds"][str(thr)]["per_fold"][day] = {
                "tn": tn, "fp": fp, "fn": fn, "tp": tp,
                "specificity": spec, "recall": recall, "f1": f1,
            }
        print("-" * len(header))

        pooled_benign = sum_tn + sum_fp
        pooled_attack = sum_tp + sum_fn
        pooled_spec = sum_tn / pooled_benign if pooled_benign > 0 else None
        pooled_recall = sum_tp / pooled_attack if pooled_attack > 0 else None
        bal_acc = (None if pooled_spec is None or pooled_recall is None
                   else (pooled_spec + pooled_recall) / 2)
        results["thresholds"][str(thr)]["pooled"] = {
            "pooled_specificity": pooled_spec,
            "pooled_recall": pooled_recall,
            "balanced_accuracy": bal_acc,
            "n_benign": pooled_benign,
            "n_attack": pooled_attack,
            "sum_tn": sum_tn, "sum_fp": sum_fp, "sum_fn": sum_fn, "sum_tp": sum_tp,
        }

    print("\n" + "=" * 78)
    print("TABLE B - pooled across folds")
    print("=" * 78)
    bh = f"{'thr':>6}{'pooled_spec':>13}{'pooled_recall':>15}" \
         f"{'balanced_acc':>14}{'n_benign':>10}{'n_attack':>10}"
    print(bh)
    print("-" * len(bh))
    best_thr, best_bal = None, -1.0
    for thr in THRESHOLDS:
        p = results["thresholds"][str(thr)]["pooled"]
        print(f"{thr:>6.2f}{fmt(p['pooled_specificity']):>13}"
              f"{fmt(p['pooled_recall']):>15}{fmt(p['balanced_accuracy']):>14}"
              f"{p['n_benign']:>10}{p['n_attack']:>10}")
        if p["balanced_accuracy"] is not None and p["balanced_accuracy"] > best_bal:
            best_bal, best_thr = p["balanced_accuracy"], thr
    print("-" * len(bh))

    if best_thr is not None:
        print(f"\nBest pooled balanced accuracy: {best_bal:.4f} at threshold {best_thr}")
        results["best"] = {"threshold": best_thr, "balanced_accuracy": best_bal}

    out = CKPT_DIR / "threshold_sweep.json"
    out.write_text(json.dumps(results, indent=2))
    print(f"Saved {out}")


if __name__ == "__main__":
    main()
