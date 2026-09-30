"""
diagnose_mitre_cm.py

Load the blocked-CV Stage-2 checkpoint for a given fold (default: block2)
and print the full MITRE confusion matrix (rows = true stage, cols = predicted
stage) over attack windows only.  Answers: which class is swallowing Impact
and Credential Access windows.

Run from backend/:
    python diagnose_mitre_cm.py               # block2
    python diagnose_mitre_cm.py --fold block1 # block1
"""
from __future__ import annotations

import argparse
import bisect
import sys
from collections import defaultdict
from pathlib import Path

import torch

from app import config
from app.schemas import DataSource, MitreStage
from app.ingestion.parser import parse_cicids2017_csv
from app.features.extractor import window_and_extract
from app.graph.builder import build_graph, NODE_FEATURE_NAMES, EDGE_FEATURE_NAMES
from app.models.world_model import WorldModel
from app.models.seeding import set_seed
from train import make_blocked_folds, create_sequences

DATA_DIR = Path("data/raw")
CKPT_DIR = Path("checkpoints/full_blocked_2stage")
DAYS = ["monday", "tuesday", "wednesday", "thursday", "friday"]
CSV_FILES = [DATA_DIR / f"{d}_plus.csv" for d in DAYS]
DEVICE = torch.device("cpu")
BLOCK_SIZE = 40
N_SPLITS = 5

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


def build_day_pools() -> dict:
    missing = [p for p in CSV_FILES if not p.exists()]
    if missing:
        print("Missing CSVs:\n" + "\n".join(str(p) for p in missing), file=sys.stderr)
        sys.exit(1)

    day_pools: dict[str, list] = {}
    for fp in CSV_FILES:
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
def run_fold(fold_name: str, ckpt: Path, head_arch: str) -> None:
    if not ckpt.exists():
        print(f"Checkpoint not found: {ckpt}", file=sys.stderr)
        sys.exit(1)

    print(f"\nBuilding day pools ...", flush=True)
    day_pools = build_day_pools()

    folds = {name: test for name, _tr, _val, test
             in make_blocked_folds(day_pools, n_splits=N_SPLITS, block_size=BLOCK_SIZE)}

    if fold_name not in folds:
        print(f"Fold '{fold_name}' not found. Available: {list(folds)}", file=sys.stderr)
        sys.exit(1)

    test = folds[fold_name]
    print(f"\nFold {fold_name}: {len(test)} test sequences")

    model = WorldModel(**MODEL_ARGS).to(DEVICE)
    # world_model.py's mitre_head is the MLP. To score a LINEAR checkpoint we
    # must build a matching linear head; swap it locally, touching nothing in
    # world_model.py. An MLP checkpoint keeps the model's own MLP head.
    if head_arch == "linear":
        model.mitre_head = torch.nn.Linear(
            MODEL_ARGS["lstm_hidden_dim"], MODEL_ARGS["num_mitre_stages"]
        ).to(DEVICE)
    print(f"Head architecture requested: {head_arch}")

    state = torch.load(ckpt, map_location=DEVICE, weights_only=True)

    # STRICT load. Previously this used strict=False and only guarded backbone
    # keys, so a linear checkpoint loaded into an MLP model left mitre_head at
    # random init and the diagnostic silently scored noise. strict=True plus the
    # explicit mitre-key checks below make an architecture mismatch a hard error
    # instead of a plausible-looking wrong answer.
    model_keys = set(model.state_dict().keys())
    ckpt_keys = set(state.keys())
    missing = sorted(model_keys - ckpt_keys)
    unexpected = sorted(ckpt_keys - model_keys)

    mitre_missing = [k for k in missing if k.startswith("mitre_head")]
    mitre_unexpected = [k for k in unexpected if k.startswith("mitre_head")]
    if mitre_missing or mitre_unexpected:
        print(
            f"ERROR: mitre_head key mismatch for --head-arch {head_arch}.\n"
            f"  missing mitre_head keys   (in model, absent in checkpoint): {mitre_missing}\n"
            f"  unexpected mitre_head keys(in checkpoint, absent in model): {mitre_unexpected}\n"
            f"  This checkpoint's head architecture does not match --head-arch "
            f"{head_arch}. Refusing to evaluate a partially/ randomly initialised "
            f"head. Re-run with the correct --head-arch.",
            file=sys.stderr,
        )
        sys.exit(1)

    # With the head matched, the whole state_dict must load strictly.
    model.load_state_dict(state, strict=True)
    model.eval()
    print(f"Loaded {ckpt.name}")
    print(f"  load check: missing_keys={missing}  unexpected_keys={unexpected}")

    stages = list(MitreStage)
    n = len(stages)
    # cm[true_idx][pred_idx]
    cm: dict[int, dict[int, int]] = defaultdict(lambda: defaultdict(int))
    stage_names = [s.value for s in stages]

    for seq, (is_attack, true_mitre_idx) in test:
        if is_attack != 1:
            continue
        from train import collate_sequences
        collated = collate_sequences([(seq, (is_attack, true_mitre_idx))], DEVICE)
        _, mitre_logits = model.logits_batch(collated)
        probs = torch.softmax(mitre_logits, dim=-1).squeeze(0).tolist()
        # Skip BENIGN (index 0) when predicting stage
        pred_idx = 1 + max(range(len(probs) - 1), key=lambda i: probs[i + 1])
        cm[true_mitre_idx][pred_idx] += 1

    # --- print matrix ---
    all_true  = sorted(set(cm.keys()))
    all_pred  = sorted({p for row in cm.values() for p in row})
    all_cols  = sorted(set(all_true) | set(all_pred))

    col_w = 6
    name_w = 24

    print(f"\n{'MITRE Confusion Matrix — Fold ' + fold_name:^{name_w + col_w * len(all_cols) + 3}}")
    print(f"Rows = true stage   Cols = predicted stage   (attack windows only)\n")

    # header
    hdr = f"{'True \\ Pred':{name_w}}"
    for c in all_cols:
        hdr += f"{stage_names[c][:col_w-1]:>{col_w}}"
    hdr += f"  {'Total':>6}"
    print(hdr)
    print("-" * len(hdr))

    for t in all_true:
        row_total = sum(cm[t].values())
        if row_total == 0:
            continue
        line = f"{stage_names[t]:{name_w}}"
        for c in all_cols:
            line += f"{cm[t].get(c, 0):>{col_w}}"
        line += f"  {row_total:>6}"
        print(line)

    print("-" * len(hdr))

    # column totals
    line = f"{'Predicted total':{name_w}}"
    for c in all_cols:
        col_total = sum(cm[t].get(c, 0) for t in all_true)
        line += f"{col_total:>{col_w}}"
    print(line)

    # --- per-stage capture rate ---
    print(f"\n{'Stage':24} {'Support':>8} {'Top pred (% captured)':}")
    print("-" * 60)
    for t in all_true:
        row_total = sum(cm[t].values())
        if row_total == 0:
            continue
        top_pred = max(cm[t], key=lambda p: cm[t][p])
        top_count = cm[t][top_pred]
        pct = 100 * top_count / row_total
        print(f"{stage_names[t]:24} {row_total:>8}   -> {stage_names[top_pred]} "
              f"({pct:.0f}%  {top_count}/{row_total})")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fold", default="block2")
    parser.add_argument("--checkpoint", default=None,
                        help="Path to the *_2stage.pt checkpoint. Defaults to "
                             "checkpoints/full_blocked_2stage/lodo_fold_<fold>_2stage.pt")
    parser.add_argument("--head-arch", choices=["linear", "mlp"], default="mlp",
                        help="Head architecture the checkpoint was trained with. "
                             "'linear' swaps in a linear mitre_head; 'mlp' keeps "
                             "world_model.py's MLP. Must match the checkpoint or "
                             "the strict load aborts.")
    args = parser.parse_args()
    config.FEATURE_SCALING = "linear"
    set_seed(config.GLOBAL_SEED)

    ckpt = (Path(args.checkpoint) if args.checkpoint
            else CKPT_DIR / f"lodo_fold_{args.fold}_2stage.pt")
    run_fold(args.fold, ckpt, args.head_arch)


if __name__ == "__main__":
    main()
