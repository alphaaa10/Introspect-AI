import argparse
import json
import logging
import math
import sys
import random
from datetime import datetime
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

from app import config
from app.schemas import DataSource, MitreStage, GraphWindow
from app.ingestion.parser import parse_csv, parse_cicids2017_csv
from app.features.extractor import window_and_extract
from app.graph.builder import build_graph, NODE_FEATURE_NAMES, EDGE_FEATURE_NAMES
from app.graph.converter import window_to_tensors
from app.models.world_model import WorldModel, set_seed

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

class FocalLoss(nn.Module):
    def __init__(self, gamma=2.0, pos_weight=None):
        super().__init__()
        self.gamma = gamma
        self.pos_weight = pos_weight

    def forward(self, logits, targets):
        if self.pos_weight is not None and self.pos_weight.device != logits.device:
            self.pos_weight = self.pos_weight.to(logits.device)
            
        bce_loss = nn.functional.binary_cross_entropy_with_logits(
            logits, targets, reduction='none', pos_weight=self.pos_weight
        )
        pt = torch.exp(-bce_loss)
        focal_loss = ((1 - pt) ** self.gamma) * bce_loss
        return focal_loss.mean()

# Label mapping for CIC-IDS-2018 (and similar) to MitreStage
LABEL_TO_MITRE = {
    "Benign": MitreStage.BENIGN,
    "Web Attack": MitreStage.INITIAL_ACCESS,  # Mock data has 'Web Attack'
    "Portscan": MitreStage.RECONNAISSANCE,
    "DDoS": MitreStage.IMPACT,
    "Botnet": MitreStage.C2,
    "Botnet - Attempted": MitreStage.C2,
    "Infiltration": MitreStage.LATERAL_MOVEMENT,
    "Infiltration - Portscan": MitreStage.RECONNAISSANCE,
    "Infiltration - Attempted": MitreStage.LATERAL_MOVEMENT,
    "FTP-Patator": MitreStage.CREDENTIAL_ACCESS,
    "FTP-Patator - Attempted": MitreStage.CREDENTIAL_ACCESS,
    "SSH-Patator": MitreStage.CREDENTIAL_ACCESS,
    "SSH-Patator - Attempted": MitreStage.CREDENTIAL_ACCESS,
    "Web Attack - Brute Force": MitreStage.INITIAL_ACCESS,
    "Web Attack - Brute Force - Attempted": MitreStage.INITIAL_ACCESS,
    "Web Attack - XSS": MitreStage.INITIAL_ACCESS,
    "Web Attack - XSS - Attempted": MitreStage.INITIAL_ACCESS,
    "Web Attack - SQL Injection": MitreStage.INITIAL_ACCESS,
    "Web Attack - SQL Injection - Attempted": MitreStage.INITIAL_ACCESS,
}

def get_window_label(window_events, policy="dominant"):
    """Aggregate event labels into a window-level binary and MITRE label.

    Two policies, because neither dominates the other on this data. Measured
    window-label support across the five slices:

        stage                dominant   most-advanced
        Reconnaissance             95               1
        Initial Access              0              84
        Credential Access          83              83
        Lateral Movement            0               9
        Command & Control          18              18
        Exfiltration                0               0
        Impact                    117             118

    "dominant" takes the most frequent attack label. It is stable but hides any
    stage that is numerically swamped: thursday's windows are ~23,675
    Infiltration-Portscan flows next to a few hundred Web Attack flows, so
    Initial Access and Lateral Movement never surface at all.

    "advanced" takes the furthest stage along the kill chain present in the
    window (MitreStage enum order is kill-chain order). That recovers Initial
    Access and Lateral Movement but costs almost all Reconnaissance, for the
    mirror-image reason.

    Neither is really right: a 60-second window genuinely can contain several
    stages at once, so the honest model is multi-label (sigmoid per stage)
    rather than a single softmax. That is a larger change; these two policies
    let you pick which single-label compromise you want in the meantime.
    """
    if not window_events:
        return 0, MitreStage.BENIGN

    attack_labels = [e.label for e in window_events if e.label.lower() != "benign"]

    if not attack_labels:
        return 0, MitreStage.BENIGN

    if policy == "advanced":
        stages = list(MitreStage)
        idx = max(stages.index(LABEL_TO_MITRE.get(lbl, MitreStage.IMPACT))
                  for lbl in set(attack_labels))
        return 1, stages[idx]

    # Mode of attack labels
    counts = {}
    for lbl in attack_labels:
        counts[lbl] = counts.get(lbl, 0) + 1

    # Sort by count descending, then lexicographically for deterministic tie-breaking
    sorted_labels = sorted(counts.items(), key=lambda x: (-x[1], x[0]))
    dominant_label = sorted_labels[0][0]

    mitre_stage = LABEL_TO_MITRE.get(dominant_label, MitreStage.IMPACT)
    return 1, mitre_stage

def create_sequences(windows, all_events, label_policy="dominant"):
    """Create sequences of windows up to config.SEQUENCE_LENGTH and their targets."""
    events_by_window = {}
    
    if not windows:
        return [], []
        
    window_starts = [w.window_start for w in windows]
    import bisect
    for e in all_events:
        idx = bisect.bisect_right(window_starts, e.timestamp) - 1
        if idx >= 0:
            w = windows[idx]
            if w.window_start <= e.timestamp < w.window_end:
                events_by_window.setdefault(w.window_id, []).append(e)

    sequences = []
    targets = [] # list of (is_attack: int, mitre_idx: int)
    
    for i in range(len(windows)):
        seq_start = max(0, i - config.SEQUENCE_LENGTH + 1)
        seq = windows[seq_start : i + 1]
        target_window = windows[i]
        
        is_attack, mitre_stage = get_window_label(
            events_by_window.get(target_window.window_id, []), policy=label_policy)
        mitre_idx = list(MitreStage).index(mitre_stage)
        
        sequences.append(seq)
        targets.append((is_attack, mitre_idx))
        
    return sequences, targets

def _read_fold_results(ckpt_dir):
    """Collect every fold_<name>.json written under ckpt_dir into one dict.

    Per-fold files are the source of truth so that parallel --only-fold
    processes never overwrite each other's results.
    """
    if not ckpt_dir or not Path(ckpt_dir).exists():
        return {}
    out = {}
    for f in sorted(Path(ckpt_dir).glob("fold_*.json")):
        try:
            out[f.stem[len("fold_"):]] = json.loads(f.read_text())
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Could not read {f.name}: {e}")
    return out


def make_lodo_folds(day_pools, val_fraction=0.15):
    """Leave-one-day-out: each fold holds out one whole day.

    Answers "does this detect an attack campaign it has never seen?" — the day
    and the attack family are almost the same thing in CIC-IDS-2017, so holding
    out a day is close to holding out an attack type. That makes it the right
    protocol for a zero-shot detection claim and the wrong one for stage
    classification, since the held-out stage is often absent from training.

    Yields (fold_name, train, val, test) where each is a list of (seq, target).
    """
    all_days = list(day_pools.keys())

    if len(all_days) < 2:
        # Holding out the only day empties the training pool. A single-day run
        # (--smoke on mock data) exists to prove the plumbing, so train == test.
        logger.warning(
            f"Only {len(all_days)} day(s) present ({all_days}) - LODO is not "
            f"possible. Falling back to train==test on the same sequences. This "
            f"validates the pipeline only; the metrics mean nothing as an "
            f"estimate of generalisation."
        )
        everything = [item for d in all_days for item in day_pools[d]]
        yield (all_days[0] if all_days else "empty"), everything, [], everything
        return

    logger.info(f"Protocol: LODO over {len(all_days)} days: {all_days}")

    for fold_idx, test_day in enumerate(all_days):
        # One remaining day becomes validation. Days with no attack windows
        # (monday) are never chosen: a single-class val set cannot tune a
        # threshold. They stay in training, where their benign windows matter.
        candidates = [
            d for d in all_days
            if d != test_day
            and any(t[0] == 1 for _, t in day_pools[d])
            and any(t[0] == 0 for _, t in day_pools[d])
        ]
        val_day = None
        if val_fraction > 0 and candidates:
            val_day = candidates[fold_idx % len(candidates)]

        train, val, test = [], [], []
        for d in all_days:
            if d == test_day:
                test.extend(day_pools[d])
            elif d == val_day:
                val.extend(day_pools[d])
            else:
                train.extend(day_pools[d])

        logger.info(f"[{test_day}] val day = {val_day or 'none'}")
        yield test_day, train, val, test


def make_blocked_folds(day_pools, n_splits=5, block_size=None):
    """Purged blocked k-fold, striped across every day.

    Why this exists: LODO cannot evaluate MITRE stage classification, because
    each CIC-IDS day carries essentially one stage and holding the day out
    removes that class from training. This protocol takes contiguous blocks from
    *every* day into *every* fold, so all stages appear on both sides of the
    split and the stage head has something learnable.

    Purging: sequences overlap by up to SEQUENCE_LENGTH windows, so a naive
    split leaks. A training sequence whose label window is j reads windows
    [j-SEQ+1, j]. If a test block covers windows [s, e), every training
    sequence with j in [s, e + SEQ - 1] touches a test window and is dropped.
    Blocks are contiguous so the striping does not shuffle time within a block.

    Test sequences near a block's start do read a few windows that sit in
    training blocks. That is deliberate and matches deployment: at inference the
    model legitimately has recent history. What must not leak — and does not —
    is a *label* appearing on both sides.
    """
    seq_len = config.SEQUENCE_LENGTH
    if block_size is None:
        # Two competing pressures. Larger blocks waste less to purging (each
        # held-out block costs seq_len-1 training sequences), but fewer blocks per
        # day means each fold's test set is dominated by one or two days, which
        # reverts toward LODO and takes stages out of training. seq_len + 10 keeps
        # enough blocks per day to mix stages on the current data; raise it via
        # --block-size once you train on the full *_plus.csv files.
        block_size = max(seq_len + 10, 30)

    if n_splits < 3:
        raise ValueError(
            f"--n-splits must be >= 3 (got {n_splits}): each fold needs a test "
            f"group, a validation group and something left to train on."
        )

    usable = {d: items for d, items in day_pools.items() if len(items) >= block_size}
    if not usable:
        longest = max((len(v) for v in day_pools.values()), default=0)
        raise ValueError(
            f"No day has at least block_size={block_size} sequences (longest is "
            f"{longest}). Use --protocol lodo, lower --block-size, or train on "
            f"more rows per day (the *_plus.csv files are ~7x the slices)."
        )
    skipped = set(day_pools) - set(usable)
    if skipped:
        logger.warning(f"Days too short for blocked CV, excluded: {sorted(skipped)}")

    # Cut every day into contiguous blocks, then pool the blocks globally.
    # Pooling rather than requiring each day to fill every fold means a short day
    # (monday) contributes to the folds it can and stays in training for the
    # rest, instead of capping n_splits at the shortest day's block count.
    # Fold assignment is diagonal: group = (block_index + day_index) % n_splits.
    #
    # A plain `global_position % n_splits` stripe aliases badly. With 5 days of 2
    # blocks each and n_splits=5, the stride equals the number of days, so both
    # of a day's blocks land in the same group and every fold's test set is one
    # whole day — silently collapsing this protocol back into LODO. Offsetting by
    # day index shifts each day's blocks into different groups.
    ordered_days = sorted(usable)
    all_blocks = []  # (group, day, start, end)
    for day_index, d in enumerate(ordered_days):
        items = usable[d]
        n_blocks = len(items) // block_size
        for b in range(n_blocks):
            s = b * block_size
            e = len(items) if b == n_blocks - 1 else (b + 1) * block_size
            all_blocks.append(((b + day_index) % n_splits, d, s, e))

    if len(all_blocks) < n_splits:
        raise ValueError(
            f"Only {len(all_blocks)} blocks of size {block_size} across all days, "
            f"need at least --n-splits={n_splits}. Lower --block-size or use more data."
        )

    blocks_per_day = {d: len(usable[d]) // block_size for d in ordered_days}
    if min(blocks_per_day.values()) < 2:
        logger.warning(
            f"Some days yield only one block ({blocks_per_day}); their data lands "
            f"in a single fold. Lower --block-size or use more rows per day for a "
            f"better mix."
        )

    logger.info(
        f"Protocol: purged blocked {n_splits}-fold over {len(all_blocks)} blocks "
        f"of {block_size}, days={sorted(usable)}"
    )
    logger.info(
        f"  purge cost: {seq_len - 1} training sequences dropped after each "
        f"held-out block ({100 * (seq_len - 1) / block_size:.0f}% of a block). "
        f"Blocks per day: {blocks_per_day}"
    )

    for k in range(n_splits):
        val_k = (k + 1) % n_splits
        # day -> held-out (start, end) ranges for this fold
        held_ranges = {}
        test, val = [], []

        for group, d, s, e in all_blocks:
            if group == k:
                test.extend(usable[d][s:e])
            elif group == val_k:
                val.extend(usable[d][s:e])
            else:
                continue
            held_ranges.setdefault(d, []).append((s, e))

        train = []
        for d, items in usable.items():
            held = set()
            for s, e in held_ranges.get(d, []):
                # A training sequence with label window j reads [j-seq_len+1, j],
                # so anything from s up to e+seq_len-2 touches a held-out window.
                held.update(range(s, min(len(items), e + seq_len - 1)))
            train.extend(items[i] for i in range(len(items)) if i not in held)

        if not train:
            raise ValueError(
                f"Fold {k} has an empty training set at block_size={block_size}, "
                f"n_splits={n_splits}. Raise --n-splits or lower --block-size."
            )

        yield f"block{k}", train, val, test


def compute_metrics(y_true_attack, y_pred_attack_probs, y_true_mitre, y_pred_mitre, threshold=0.5):
    """Compute scikit-learn metrics safely handling edge cases."""
    y_pred_attack_binary = [1 if p >= threshold else 0 for p in y_pred_attack_probs]
    
    metrics = {}
    # Attack binary metrics
    try:
        metrics['attack_accuracy'] = accuracy_score(y_true_attack, y_pred_attack_binary)
        # zero_division=0 gracefully handles undefined precision/recall when no attacks are predicted or exist
        metrics['attack_precision'] = precision_score(y_true_attack, y_pred_attack_binary, zero_division=0)
        metrics['attack_recall'] = recall_score(y_true_attack, y_pred_attack_binary, zero_division=0)
        metrics['attack_f1'] = f1_score(y_true_attack, y_pred_attack_binary, zero_division=0)
        
        if len(set(y_true_attack)) > 1:
            metrics['attack_roc_auc'] = roc_auc_score(y_true_attack, y_pred_attack_probs)
        else:
            metrics['attack_roc_auc'] = "N/A (single class in targets)"
            
        # labels=[0, 1] forces a 2x2 matrix even when a fold is single-class
        # (e.g. the all-BENIGN monday hold-out), which callers index as cm[i][j].
        metrics['attack_confusion_matrix'] = confusion_matrix(
            y_true_attack, y_pred_attack_binary, labels=[0, 1]
        ).tolist()
    except Exception as e:
        metrics['attack_error'] = str(e)

    # MITRE metrics are computed over attack windows only: the question the stage
    # head answers is "given this window is an attack, which stage is it?".
    # Including benign windows would let the BENIGN class dominate and make the
    # number look good while saying nothing about stage discrimination.
    attack_indices = [i for i, y in enumerate(y_true_attack) if y == 1]
    if attack_indices:
        yt_m = [y_true_mitre[i] for i in attack_indices]
        yp_m = [y_pred_mitre[i] for i in attack_indices]
        try:
            metrics['mitre_accuracy'] = accuracy_score(yt_m, yp_m)
            # Macro-F1 over the stages actually present, so an absent class does
            # not silently drag the average toward zero.
            present = sorted(set(yt_m) | set(yp_m))
            metrics['mitre_f1_macro'] = f1_score(
                yt_m, yp_m, average='macro', labels=present, zero_division=0
            )
            # Per-stage breakdown: a single macro number hides which stages the
            # head has actually learned versus which it never predicts.
            stages = list(MitreStage)
            per_stage = f1_score(yt_m, yp_m, average=None, labels=present, zero_division=0)
            metrics['mitre_f1_per_stage'] = {
                stages[lbl].value: {
                    "f1": float(f1),
                    "support": sum(1 for y in yt_m if y == lbl),
                }
                for lbl, f1 in zip(present, per_stage)
            }
        except Exception as e:
            metrics['mitre_error'] = str(e)
    else:
        metrics['mitre_accuracy'] = "N/A (no attack windows in set)"
        metrics['mitre_f1_macro'] = "N/A"

    return metrics

def collate_sequences(
    batch: list[tuple[list[GraphWindow], tuple[int, int]]],
    device: torch.device,
) -> dict:
    """Pack a list of (sequence, target) pairs into one disjoint-union graph.

    BATCHING STRATEGY: offset-based. Every graph's node indices are shifted by a
    running offset so no two graphs in the batch share a node index. The
    attention softmax inside GATLayer is a scatter over destination node
    indices, so disjoint indices make cross-graph message passing impossible and
    GATLayer needs no change whatsoever. Only GATEncoder's readout became
    per-graph aware. Test 3 asserts the no-leakage property empirically rather
    than trusting this argument.

    Padded timesteps are materialised as EMPTY graphs (zero nodes, zero edges)
    so that graph ids are exactly `b * T_max + t`. That keeps the reshape to
    [B, T_max, D] a plain view instead of a scatter, and costs nothing because
    an empty graph contributes no rows. They are excluded from the LSTM by
    packing, not by omission.

    Returns a dict with:
      graph_x                 [total_nodes, node_dim]
      graph_edge_index        [2, total_edges]      node offsets applied
      graph_edge_attr         [total_edges, edge_dim]
      graph_batch_index       [total_nodes]         node -> graph id (0..B*T_max-1)
      graph_window_features   [B*T_max, NUM_FEATURES]
      window_to_seq           [B*T_max]             graph id -> sequence id (0..B-1)
      seq_lengths             [B]                   valid timesteps per sequence
      seq_mask                [B, T_max] bool       True where valid
      is_attack               [B] float
      mitre_idx               [B] long
      T_max                   int

    `graph_window_features` is not in the original spec's list but is required:
    the current architecture fuses the extractor's 21 features at every
    timestep, so omitting them would silently drop that fusion in the batched
    path only — the exact class of divergence that the duplicated encoder in
    train_one_epoch used to cause.
    """
    if not batch:
        raise ValueError("collate_sequences received an empty batch")

    B = len(batch)
    T_max = max(len(seq) for seq, _ in batch)
    num_graphs = B * T_max
    n_node_feats = len(NODE_FEATURE_NAMES)
    n_edge_feats = len(EDGE_FEATURE_NAMES)

    xs, eis, eas, batch_idx = [], [], [], []
    window_to_seq = torch.zeros(num_graphs, dtype=torch.long)
    wf = torch.zeros((num_graphs, config.NUM_FEATURES), dtype=torch.float32)
    seq_lengths = torch.zeros(B, dtype=torch.long)
    seq_mask = torch.zeros((B, T_max), dtype=torch.bool)
    is_attack = torch.zeros(B, dtype=torch.float32)
    mitre_idx = torch.zeros(B, dtype=torch.long)

    node_offset = 0
    for b, (seq, (atk, mit)) in enumerate(batch):
        seq_lengths[b] = len(seq)
        is_attack[b] = float(atk)
        mitre_idx[b] = int(mit)
        for t in range(T_max):
            gid = b * T_max + t
            window_to_seq[gid] = b
            if t >= len(seq):
                continue  # padded slot: an empty graph contributes no rows
            seq_mask[b, t] = True
            gw = seq[t]
            x, ei, ea = window_to_tensors(gw, dtype=torch.float32, device="cpu")
            n = x.size(0)
            if gw.window_features:
                wf[gid] = torch.tensor(gw.window_features, dtype=torch.float32)
            if n == 0:
                # Empty graph: no nodes, no edges, nothing to offset. The
                # concatenation below simply skips it and its readout row stays
                # zero, matching GATEncoder's documented empty-graph policy.
                continue
            xs.append(x)
            batch_idx.append(torch.full((n,), gid, dtype=torch.long))
            if ei.size(1) > 0:
                eis.append(ei + node_offset)
                eas.append(ea)
            node_offset += n

    graph_x = torch.cat(xs, 0) if xs else torch.empty((0, n_node_feats), dtype=torch.float32)
    graph_batch_index = torch.cat(batch_idx, 0) if batch_idx else torch.empty(0, dtype=torch.long)
    graph_edge_index = torch.cat(eis, 1) if eis else torch.empty((2, 0), dtype=torch.long)
    graph_edge_attr = torch.cat(eas, 0) if eas else torch.empty((0, n_edge_feats), dtype=torch.float32)

    return {
        "graph_x": graph_x.to(device),
        "graph_edge_index": graph_edge_index.to(device),
        "graph_edge_attr": graph_edge_attr.to(device),
        "graph_batch_index": graph_batch_index.to(device),
        "graph_window_features": wf.to(device),
        "window_to_seq": window_to_seq.to(device),
        "seq_lengths": seq_lengths,          # stays on CPU: pack_padded_sequence needs it there
        "seq_mask": seq_mask.to(device),
        "is_attack": is_attack.to(device),
        "mitre_idx": mitre_idx.to(device),
        "T_max": T_max,
    }


ACCUM_STEPS = 64  # sequences per optimizer step (batch size is 1)

def train_one_epoch(model, optimizer, sequences, targets, attack_criterion,
                    mitre_criterion, mitre_weight=1.0):
    model.train()
    total_loss = 0.0
    optimizer.zero_grad()

    device = next(model.parameters()).device

    for i, (seq, (is_attack, mitre_idx)) in enumerate(zip(sequences, targets)):

        # Batched encoder at B=1. Identical maths to model.logits(seq), but the
        # sequence's windows are fused into ONE disjoint-union graph so the GAT
        # runs once instead of SEQUENCE_LENGTH times. Measured 2.60x faster at
        # 156 nodes/window (69.92 -> 26.88 ms/sequence); see docs/BATCHING.md.
        #
        # B=1 deliberately: the loss below sees exactly one sequence, so the
        # ACCUM_STEPS normalisation and optimizer cadence are untouched. B>1
        # would require reconciling three separate normalisations for a further
        # 1.35x, which is not worth the risk.
        #
        # model.logits(seq) remains callable and is what WorldModel.forward uses
        # for single-sequence inference.
        collated = collate_sequences([(seq, (is_attack, mitre_idx))], device)
        attack_logits, mitre_logits = model.logits_batch(collated)

        loss_attack = attack_criterion(attack_logits.squeeze(), torch.tensor(float(is_attack), device=device))

        # The stage loss applies to ATTACK windows only.
        #
        # Training it on benign windows too (target BENIGN) made BENIGN the
        # largest stage class, so the head learned to predict it: measured on a
        # blocked run, one fold predicted BENIGN for all 57 attack windows and
        # scored exactly 0.0 stage accuracy. Because stage metrics are computed
        # over attack windows only, every BENIGN prediction there is wrong by
        # construction — the objective and the metric were asking different
        # questions. Masking aligns them: "given this is an attack, which stage?"
        # Whether it is an attack at all is the binary head's job.
        loss = loss_attack
        if mitre_weight > 0 and is_attack == 1:
            loss_mitre = mitre_criterion(mitre_logits.squeeze(0), torch.tensor(mitre_idx, device=device))
            loss = loss + (loss_mitre * mitre_weight)

        loss = loss / ACCUM_STEPS  # Normalize for gradient accumulation
        loss.backward()

        if (i + 1) % ACCUM_STEPS == 0 or (i + 1) == len(sequences):
            optimizer.step()
            optimizer.zero_grad()

        total_loss += (loss.item() * ACCUM_STEPS)

    return total_loss / max(len(sequences), 1)

def select_threshold(model, sequences, targets):
    """Pick the decision threshold that maximises F1 on the given set.

    0.5 is only the right cut when the classes are balanced and the model is
    calibrated; here attack windows are ~65% of the data, so a fixed 0.5 leaves
    F1 on the table for reasons that have nothing to do with model quality.

    This must be called on validation data. Choosing it on the held-out day
    would tune a hyperparameter on the test set and inflate the reported score.
    """
    if not sequences:
        return 0.5

    model.eval()
    device = next(model.parameters()).device
    probs, ys = [], []
    with torch.no_grad():
        for seq, (is_attack, mitre_idx) in zip(sequences, targets):
            # Batched encoder at B=1, matching evaluate() so the threshold is
            # chosen on the same probabilities it will later be applied to.
            collated = collate_sequences([(seq, (is_attack, mitre_idx))], device)
            attack_logits, _ = model.logits_batch(collated)
            probs.append(torch.sigmoid(attack_logits).squeeze().item())
            ys.append(is_attack)

    if len(set(ys)) < 2:
        return 0.5  # single-class validation set: F1 is degenerate

    best_t, best_f1 = 0.5, -1.0
    for t in [i / 100.0 for i in range(5, 100, 5)]:
        f1 = f1_score(ys, [1 if p >= t else 0 for p in probs], zero_division=0)
        if f1 > best_f1:
            best_t, best_f1 = t, f1
    return best_t

def evaluate_loss(model, sequences, targets, attack_criterion, mitre_criterion, mitre_weight):
    """Mean loss over a set, used for early stopping and model selection."""
    model.eval()
    device = next(model.parameters()).device
    total = 0.0
    with torch.no_grad():
        for seq, (is_attack, mitre_idx) in zip(sequences, targets):
            # Batched encoder at B=1, matching train_one_epoch so the validation
            # loss is computed by the same code path that produced the weights.
            collated = collate_sequences([(seq, (is_attack, mitre_idx))], device)
            attack_logits, mitre_logits = model.logits_batch(collated)
            loss = attack_criterion(attack_logits.squeeze(), torch.tensor(float(is_attack), device=device))
            # Masked exactly as in train_one_epoch, or the validation loss would
            # measure a different objective than the one being optimised.
            if mitre_weight > 0 and is_attack == 1:
                lm = mitre_criterion(mitre_logits.squeeze(0), torch.tensor(mitre_idx, device=device))
                loss = loss + lm * mitre_weight
            total += loss.item()
    return total / max(len(sequences), 1)

def evaluate(model, sequences, targets, threshold=0.5):
    model.eval()
    device = next(model.parameters()).device
    y_true_attack, y_pred_attack_probs = [], []
    y_true_mitre, y_pred_mitre = [], []

    with torch.no_grad():
        for seq, (is_attack, mitre_idx) in zip(sequences, targets):
            # Batched encoder at B=1, the same path training uses. The
            # activations below reproduce exactly what WorldModel.forward
            # returns as attack_probability and stage_probabilities; forward
            # itself stays the single-sequence inference entry point for the API.
            collated = collate_sequences([(seq, (is_attack, mitre_idx))], device)
            attack_logits, mitre_logits = model.logits_batch(collated)

            y_true_attack.append(is_attack)
            y_pred_attack_probs.append(torch.sigmoid(attack_logits).squeeze().item())

            y_true_mitre.append(mitre_idx)
            # Pick among ATTACK stages, skipping BENIGN at index 0.
            #
            # The stage head is trained on attack windows only, so its BENIGN
            # logit is never supervised and is meaningless. Including it in the
            # argmax let an unsupervised logit win and be scored as a wrong
            # stage. The binary head answers "is this an attack"; this answers
            # "which stage, given that it is".
            probs = torch.softmax(mitre_logits, dim=-1).squeeze(0).tolist()
            pred_mitre_idx = 1 + max(range(len(probs) - 1), key=lambda i: probs[i + 1])
            y_pred_mitre.append(pred_mitre_idx)
            
    import numpy as np
    from collections import Counter

    if y_pred_attack_probs:
        probs = np.array(y_pred_attack_probs)
        q = np.percentile(probs, [0, 25, 50, 75, 100])
        logger.info(f"Attack Probability Distribution: Min={q[0]:.4f}, Q1={q[1]:.4f}, Median={q[2]:.4f}, Q3={q[3]:.4f}, Max={q[4]:.4f}")
        
        benign_probs = [p for p, t in zip(y_pred_attack_probs, y_true_attack) if t == 0]
        attack_probs = [p for p, t in zip(y_pred_attack_probs, y_true_attack) if t == 1]
        
        if benign_probs and attack_probs:
            b_med = np.median(benign_probs)
            a_med = np.median(attack_probs)
            gap = a_med - b_med
            logger.info(f"Separation: Benign Med={b_med:.4f}, Attack Med={a_med:.4f}, Gap={gap:.4f}")

    if y_pred_mitre:
        attack_mitre_preds = [p for p, t in zip(y_pred_mitre, y_true_attack) if t == 1]
        if attack_mitre_preds:
            mitre_counts = Counter(attack_mitre_preds)
            logger.info(f"MITRE Predictions (attacks only): {dict(mitre_counts)}")
            
    return compute_metrics(y_true_attack, y_pred_attack_probs, y_true_mitre, y_pred_mitre, threshold=threshold)

def run_pipeline(
    csv_paths: list[Path],
    is_smoke: bool = False,
    epochs: int = 30,
    save_path: str = None,
    resume_from: str = None,
    device: str = "cpu",
    resume_folds: bool = False,
    max_rows: int | None = None,
    use_window_features: bool = True,
    mitre_weight: float = 1.0,
    patience: int = 5,
    val_fraction: float = 0.15,
    pos_weight_mode: str = "none",
    protocol: str = "lodo",
    n_splits: int = 5,
    block_size: int | None = None,
    mitre_class_weights: bool = True,
    label_policy: str = "dominant",
    only_fold: str | None = None
) -> tuple[WorldModel, dict, list, list, list, dict, dict]:
    """
    End-to-end data ingestion, sequence building, and model training.
    """
    logger.info(f"Setting global seed to {config.GLOBAL_SEED}")
    set_seed(config.GLOBAL_SEED)
    
    day_pools = {}

    for filepath in csv_paths:
        logger.info(f"Parsing CSV: {filepath}")
        if is_smoke:
            events, errors = parse_csv(filepath, source=DataSource.MOCK)
        else:
            events, errors = parse_cicids2017_csv(filepath, source=DataSource.REAL)
            
        logger.info(f"Parsed {len(events)} valid events, {len(errors)} errors skipped.")
        if max_rows is not None and len(events) > max_rows:
            # Truncation is chronological (events carry row-order timestamps), so the
            # windowing and sequencing below behave exactly as on the full slice.
            events = events[:max_rows]
            logger.info(f"Truncated to first {max_rows} events (--max-rows)")
        if not events:
            continue
            
        logger.info("Windowing and extracting features...")
        feature_records = window_and_extract(events)
        logger.info(f"Generated {len(feature_records)} windows.")
        
        logger.info("Building graphs...")
        windows = []
        
        events_by_window = {}
        if feature_records:
            window_starts = [fr.window_start for fr in feature_records]
            import bisect
            for e in events:
                idx = bisect.bisect_right(window_starts, e.timestamp) - 1
                if idx >= 0:
                    fr = feature_records[idx]
                    if fr.window_start <= e.timestamp < fr.window_end:
                        events_by_window.setdefault(fr.window_id, []).append(e)

        for fr in feature_records:
            window_events = events_by_window.get(fr.window_id, [])
            # fr.feature_vector carries the 21 extractor features (flag counts,
            # unique_dst_ports, IAT stats, pkts/s). They used to be computed here
            # and discarded; the graph's 5 node + 6 edge features cannot express
            # them, and they are what distinguishes low-volume attacks such as
            # tuesday's Patator brute force from ordinary traffic.
            gw = build_graph(
                window_events, fr.window_id, fr.window_start, fr.window_end, fr.source,
                window_features=fr.feature_vector,
            )
            windows.append(gw)
            
        # Split windows into contiguous chunks based on timestamp
        chunks = []
        current_chunk = []
        for w in windows:
            if not current_chunk:
                current_chunk.append(w)
            else:
                prev_w = current_chunk[-1]
                if w.window_start == prev_w.window_end:
                    current_chunk.append(w)
                else:
                    chunks.append(current_chunk)
                    current_chunk = [w]
        if current_chunk:
            chunks.append(current_chunk)
            
        day_name = filepath.stem.split('_')[0]
        if day_name not in day_pools:
            day_pools[day_name] = []
            
        for chunk in chunks:
            chunk_seqs, chunk_targets = create_sequences(chunk, events, label_policy=label_policy)
            if chunk_seqs:
                day_pools[day_name].extend(list(zip(chunk_seqs, chunk_targets)))
            
    model_args = dict(
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
        window_feat_dim=config.NUM_FEATURES if use_window_features else 0,
    )
    
    all_days = list(day_pools.keys())

    if protocol == "blocked":
        folds = list(make_blocked_folds(day_pools, n_splits=n_splits, block_size=block_size))
    else:
        folds = list(make_lodo_folds(day_pools, val_fraction=val_fraction))

    if only_fold is not None:
        names = [n for n, *_ in folds]
        if only_fold not in names:
            raise ValueError(f"--only-fold {only_fold!r} not among {names}")
        folds = [f for f in folds if f[0] == only_fold]
        logger.info(f"Restricted to fold {only_fold!r} of {len(names)} "
                    f"(run the others as separate processes)")

    fold_results = []
    model = None  # stays None only if every fold was resumed from disk

    EPOCHS = epochs

    # Per-fold artifacts let a long LODO run survive an interrupted session
    # (e.g. a Colab runtime disconnect) instead of losing every completed fold.
    # Each fold owns its own results file. A combined lodo_results.json is
    # derived from them for convenience.
    #
    # One file shared by every fold would lose updates as soon as folds run in
    # parallel (--only-fold): each process reads the dict, adds its entry and
    # rewrites the whole thing, so the last writer wins and the rest vanish.
    # Per-fold files mean no process ever writes what another owns.
    ckpt_root = Path(save_path) if save_path else None
    results_path = ckpt_root / "lodo_results.json" if ckpt_root else None
    completed = _read_fold_results(ckpt_root) if resume_folds else {}
    if completed:
        logger.info(f"Resuming: {len(completed)} fold(s) already done: {sorted(completed)}")

    for fold_idx, (test_day, fold_train, fold_val, fold_test) in enumerate(folds):

        if test_day in completed:
            logger.info(f"[Fold {test_day}] Already complete - skipping (from {results_path})")
            fold_results.append((test_day, completed[test_day]))
            continue

        logger.info(f"\n{'='*50}\nFold {fold_idx+1}/{len(folds)}: {test_day}\n{'='*50}")

        train_seqs_f = [s for s, _ in fold_train]
        train_targets_f = [t for _, t in fold_train]
        val_seqs_f = [s for s, _ in fold_val]
        val_targets_f = [t for _, t in fold_val]
        test_seqs_f = [s for s, _ in fold_test]
        test_targets_f = [t for _, t in fold_test]

        combined = list(zip(train_seqs_f, train_targets_f))
        random.shuffle(combined)
        train_seqs_f, train_targets_f = map(list, zip(*combined))

        num_attacks = sum(1 for t in train_targets_f if t[0] == 1)
        num_benign = len(train_targets_f) - num_attacks
        attack_types = sorted(set(t[1] for t in train_targets_f if t[0] == 1))
        logger.info(f"[Fold {test_day}] Train pool: {num_benign} benign, {num_attacks} attack, MITRE types: {attack_types}")
        
        logger.info(f"[Fold {test_day}] Val: {len(val_seqs_f)} sequences "
                    f"({sum(1 for t in val_targets_f if t[0] == 1)} attack, "
                    f"{sum(1 for t in val_targets_f if t[0] == 0)} benign) | "
                    f"Test: {len(test_seqs_f)} sequences "
                    f"({sum(1 for t in test_targets_f if t[0] == 1)} attack, "
                    f"{sum(1 for t in test_targets_f if t[0] == 0)} benign)")

        # Under LODO a held-out day usually takes its MITRE stage out of training
        # entirely, so the stage head cannot predict it and the fold's stage
        # accuracy describes the split rather than the model. Blocked CV exists
        # to avoid exactly this; the warning should stay silent there.
        _stages = list(MitreStage)
        train_stages = {t[1] for t in train_targets_f if t[0] == 1}
        test_stages = {t[1] for t in test_targets_f if t[0] == 1}
        unseen = test_stages - train_stages
        if unseen:
            logger.warning(
                f"[Fold {test_day}] MITRE stages in test but never in training: "
                f"{[_stages[i].value for i in sorted(unseen)]} - stage metrics for "
                f"this fold are structurally capped at 0 for those classes."
            )

        set_seed(config.GLOBAL_SEED + fold_idx)
        model = WorldModel(**model_args).to(device)
        device = next(model.parameters()).device
        optimizer = optim.Adam(model.parameters(), lr=3e-4)

        if pos_weight_mode == "none":
            attack_criterion = nn.BCEWithLogitsLoss()
        else:
            # "auto" = num_benign/num_attacks. Attacks are the MAJORITY class
            # here (~65% of windows), so this is below 1.0 and down-weights them,
            # which is what stopped an earlier run collapsing to all-attack.
            pw = (num_benign / max(1, num_attacks)) if pos_weight_mode == "auto" else float(pos_weight_mode)
            logger.info(f"[Fold {test_day}] BCE pos_weight={pw:.4f}")
            attack_criterion = nn.BCEWithLogitsLoss(
                pos_weight=torch.tensor(pw, dtype=torch.float32, device=device)
            )
        # MITRE stages are badly imbalanced (measured on the 60k subset: Impact
        # 117, Reconnaissance 95, Credential Access 83, C2 18) on top of BENIGN
        # dominating every attack class. Unweighted cross-entropy lets the head
        # score well by ignoring the rare stages, which is exactly the failure
        # macro-F1 is meant to expose. Inverse-frequency weights counter that.
        if mitre_class_weights and mitre_weight > 0:
            # Attack windows only, matching the masked loss above. Counting
            # benign windows here would hand BENIGN a huge count and a tiny
            # weight for a class the head is no longer trained on.
            counts = np.bincount([t[1] for t in train_targets_f if t[0] == 1],
                                 minlength=config.NUM_MITRE_STAGES).astype(np.float64)
            present = counts > 0
            # Absent classes get weight 1.0, NOT 0.0. CrossEntropyLoss with
            # reduction='mean' divides by the summed weight of the batch, so a
            # zero-weight class yields 0/0 = NaN — which showed up as
            # "Val: nan" whenever the validation set contained a stage missing
            # from training (C2 has only 18 windows, so this is common).
            w = np.ones_like(counts)
            # sklearn's "balanced" formula: N / (K * n_c). Its useful property is
            # that sum_c(n_c * w_c) == N, i.e. the average weight *per training
            # sample* is exactly 1.0, which keeps the MITRE term on the same
            # scale as the binary term. (The mean weight per *class* is above 1
            # whenever the classes are imbalanced — not the invariant here.)
            w[present] = counts[present].sum() / (present.sum() * counts[present])
            mitre_criterion = nn.CrossEntropyLoss(
                weight=torch.tensor(w, dtype=torch.float32, device=device)
            )
            logger.info(f"[Fold {test_day}] MITRE class weights: "
                        + ", ".join(f"{_stages[i].value}={w[i]:.2f}"
                                    for i in range(len(w)) if present[i]))
        else:
            mitre_criterion = nn.CrossEntropyLoss()

        # Model selection runs against the validation tail, never the held-out
        # day. Selecting on the test fold would make the reported metrics an
        # optimistic estimate of a model chosen with knowledge of its own test set.
        best_val = float("inf")
        best_state = None
        epochs_without_improvement = 0

        for epoch in range(1, EPOCHS + 1):
            loss = train_one_epoch(model, optimizer, train_seqs_f, train_targets_f,
                                   attack_criterion, mitre_criterion, mitre_weight=mitre_weight)

            msg = f"[Fold {test_day}] Epoch {epoch}/{EPOCHS} - Loss: {loss:.4f}"

            if val_seqs_f:
                val_loss = evaluate_loss(model, val_seqs_f, val_targets_f,
                                         attack_criterion, mitre_criterion, mitre_weight)
                msg += f" - Val: {val_loss:.4f}"

                if not math.isfinite(val_loss):
                    # Never select weights on a non-finite score, and say so
                    # rather than silently treating it as "no improvement".
                    logger.warning(f"[Fold {test_day}] Epoch {epoch} val loss is "
                                   f"{val_loss} - ignoring for model selection")
                    epochs_without_improvement += 1
                elif val_loss < best_val - 1e-5:
                    best_val = val_loss
                    best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
                    epochs_without_improvement = 0
                    msg += " *"
                else:
                    epochs_without_improvement += 1

            logger.info(msg)

            if val_seqs_f and epochs_without_improvement >= patience:
                logger.info(f"[Fold {test_day}] Early stop at epoch {epoch} "
                            f"(no val improvement for {patience} epochs; best={best_val:.4f})")
                break

        if best_state is not None:
            model.load_state_dict(best_state)
            logger.info(f"[Fold {test_day}] Restored best-validation weights (val loss {best_val:.4f})")

        threshold = select_threshold(model, val_seqs_f, val_targets_f)
        logger.info(f"[Fold {test_day}] Decision threshold from validation: {threshold:.2f}")

        metrics = evaluate(model, test_seqs_f, test_targets_f, threshold=threshold)
        metrics['decision_threshold'] = threshold
        logger.info(f"[Fold {test_day}] Test metrics: {json.dumps(metrics, default=str)}")
        fold_results.append((test_day, metrics))

        # Persist this fold before starting the next one.
        if save_path:
            ckpt_dir = Path(save_path)
            ckpt_dir.mkdir(parents=True, exist_ok=True)
            fold_ckpt = ckpt_dir / f"lodo_fold_{test_day}.pt"
            torch.save(model.state_dict(), fold_ckpt)
            fold_json = ckpt_dir / f"fold_{test_day}.json"
            fold_json.write_text(json.dumps(
                json.loads(json.dumps(metrics, default=str)), indent=2))
            # Derived view; safe to clobber because every fold file is authoritative.
            merged = _read_fold_results(ckpt_dir)
            results_path.write_text(json.dumps(merged, indent=2))
            logger.info(f"[Fold {test_day}] Saved {fold_ckpt.name}, {fold_json.name} "
                        f"({len(merged)} fold(s) recorded)")

    # Aggregate
    logger.info("\n" + "="*70 + "\nAGGREGATE\n" + "="*70)
    specs, recs, aucs = [], [], []
    total_TN = 0; total_neg = 0
    total_TP = 0; total_pos = 0
    
    for day, mets in fold_results:
        cm = mets.get('attack_confusion_matrix', [[0, 0], [0, 0]])
        if len(cm) != 2 or len(cm[0]) != 2:
            logger.warning(f"[Fold {day}] Unexpected confusion matrix shape, skipping in aggregate")
            continue

        TN, FP, FN, TP = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
        # Row sums are the true class counts, so they hold for any fold naming
        # (LODO day names or blocked-CV block ids) without consulting day_pools.
        n_neg = TN + FP
        n_pos = FN + TP

        if n_neg > 0: specs.append(TN / n_neg)
        if n_pos > 0: recs.append(TP / n_pos)
        
        # Accumulate for pooled metrics
        total_TN += TN; total_neg += n_neg
        total_TP += TP; total_pos += n_pos
            
        auc = mets.get('attack_roc_auc')
        if isinstance(auc, (int, float)): aucs.append(auc)

    logger.info(f"Folds with benign samples:  {len(specs)}")
    logger.info(f"Folds with attack samples:  {len(recs)}")
    logger.info(f"Folds with valid ROC-AUC:   {len(aucs)}")

    if specs:
        logger.info(f"Specificity (mean ± std over folds with benigns): {np.mean(specs):.4f} ± {np.std(specs):.4f}")
    if recs:
        logger.info(f"Recall      (mean ± std over folds with attacks): {np.mean(recs):.4f} ± {np.std(recs):.4f}")
    if aucs:
        logger.info(f"ROC-AUC     (mean ± std over folds with both classes): {np.mean(aucs):.4f} ± {np.std(aucs):.4f}")
        
    logger.info("\n=== POOLED AGGREGATE (HONEST OVERALL METRICS) ===")
    if total_neg > 0:
        logger.info(f"Pooled specificity: {total_TN / total_neg:.4f}  (n={total_neg})")
    if total_pos > 0:
        logger.info(f"Pooled recall:      {total_TP / total_pos:.4f}  (n={total_pos})")

    logger.info("\nNOTE: Precision is reported per-fold only — it is not averaged across folds because class priors differ per fold.")

    # LODO evaluates; it does not produce a single deployment model. The model
    # returned is the last fold's, and the sequences are that fold's, which is
    # what the smoke path's save/reload check needs a real tensor from.
    run_summary = {
        "info": "LODO run; returned model is the final fold only",
        "folds": {day: mets for day, mets in fold_results},
    }
    last_train = locals().get("train_seqs_f") or []
    last_test = locals().get("test_seqs_f") or []
    last_test_targets = locals().get("test_targets_f") or []
    return (model, model_args, last_train, last_test, last_test_targets,
            run_summary, run_summary)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true", help="Run smoke test on mock data")
    parser.add_argument("--epochs", type=int, default=30, help="Number of training epochs")
    parser.add_argument("--patience", type=int, default=5,
                        help="Stop a fold after this many epochs without validation improvement")
    parser.add_argument("--save-path", type=str, default="checkpoints", help="Directory to save model checkpoints")
    parser.add_argument("--resume-from", type=str, default=None, help="Path to checkpoint file to resume from")
    parser.add_argument("--dry-run", action="store_true", help="Print label distribution and exit before training")
    parser.add_argument("--device", type=str, default=config.MODEL_DEVICE,
                        help="Torch device, e.g. 'cpu' or 'cuda' (default: SENTINEL_DEVICE env or 'cpu')")
    parser.add_argument("--resume-folds", action="store_true",
                        help="Skip folds already recorded as <save-path>/fold_<name>.json")
    parser.add_argument("--data-dir", type=str, default="data/raw",
                        help="Directory holding the *_slice CSVs")
    parser.add_argument("--max-rows", type=int, default=None,
                        help="Use only the first N rows of each day (fast experiments)")
    parser.add_argument("--no-window-features", action="store_true",
                        help="Disable fusion of the 21 extractor features (graph-only ablation)")
    parser.add_argument("--mitre-weight", type=float, default=1.0,
                        help="Weight on the MITRE loss; 0.0 isolates the binary head")
    parser.add_argument("--val-fraction", type=float, default=0.15,
                        help="Set to 0 to disable the nested validation day (no early stopping)")
    parser.add_argument("--pos-weight", type=str, default="none",
                        help="BCE pos_weight: 'none', 'auto' (benign/attack), or a float")
    parser.add_argument("--protocol", choices=["lodo", "blocked"], default="lodo",
                        help="lodo = leave-one-day-out (zero-shot detection claim); "
                             "blocked = purged blocked k-fold (required for MITRE stages)")
    parser.add_argument("--n-splits", type=int, default=5,
                        help="Folds for --protocol blocked")
    parser.add_argument("--block-size", type=int, default=None,
                        help="Sequences per contiguous block in blocked CV "
                             "(default max(2*SEQUENCE_LENGTH, 40))")
    parser.add_argument("--no-mitre-class-weights", action="store_true",
                        help="Disable inverse-frequency class weights on the MITRE loss")
    parser.add_argument("--only-fold", type=str, default=None,
                        help="Train just this one fold (e.g. 'monday' or 'block2') and exit. "
                             "Folds are independent, so several processes can run different "
                             "folds at once; combine with --threads 1")
    parser.add_argument("--threads", type=int, default=None,
                        help="torch intra-op threads. Measured on this pipeline: 1 thread is "
                             "58.6 ms/sequence vs 67.9 at 6 and 96.9 at 12 - the tensors are "
                             "too small for intra-op parallelism to pay off. Use 1 and "
                             "parallelise across folds instead")
    parser.add_argument("--scaling", choices=["linear", "log"], default=None,
                        help="Feature scaling mode (default: config.FEATURE_SCALING). "
                             "linear won on aggregate ROC-AUC; log wins on low-volume attacks")
    parser.add_argument("--label-policy", choices=["dominant", "advanced"], default="dominant",
                        help="Window stage label: 'dominant' = most frequent attack; "
                             "'advanced' = furthest along the kill chain (recovers "
                             "Initial Access and Lateral Movement, loses Reconnaissance)")
    args = parser.parse_args()

    if args.threads:
        torch.set_num_threads(args.threads)
    logger.info(f"torch threads: {torch.get_num_threads()}")
    
    if args.scaling:
        # Set before any parsing: _scale is applied during graph construction.
        config.FEATURE_SCALING = args.scaling
    logger.info(f"Feature scaling: {config.FEATURE_SCALING}")
    
    if args.device.startswith("cuda") and not torch.cuda.is_available():
        logger.warning(f"--device {args.device} requested but CUDA is unavailable; falling back to cpu")
        args.device = "cpu"
    logger.info(f"Training device: {args.device}")
    
    global dry_run
    dry_run = args.dry_run
    
    # Paths to real data slices
    data_dir = Path(args.data_dir)
    csv_paths = [
        data_dir / "monday_plus_slice.csv",
        data_dir / "tuesday_plus_slice.csv",
        data_dir / "wednesday_plus_slice.csv",
        data_dir / "thursday_plus_slice.csv",
        data_dir / "friday_plus_slice_mixed.csv",
    ]

    missing = [p for p in csv_paths if not p.exists()]
    if missing and not args.smoke:
        logger.error("Missing data slices (cwd must be the backend/ directory):")
        for p in missing:
            logger.error(f"  {p.resolve()}")
        sys.exit(1)
    
    if args.smoke:
        logger.info("=== RUNNING SMOKE TEST (Pass 1) ===")
        filepaths = [Path("data/samples/mock_cicids.csv")]
        model1, model_args, train_seqs, test_seqs, test_targets, train_metrics1, _ = run_pipeline(filepaths, is_smoke=True, epochs=args.epochs)
        
        logger.info("\n=== RUNNING SMOKE TEST (Pass 2 - Determinism Check) ===")
        model2, _, _, _, _, train_metrics2, _ = run_pipeline(filepaths, is_smoke=True, epochs=args.epochs)
        
        logger.info("\n=== DETERMINISM RESULTS ===")
        # Check if model1 and model2 produced identical metrics
        identical = True
        for k in train_metrics1:
            if train_metrics1[k] != train_metrics2[k]:
                logger.error(f"Mismatch in {k}: {train_metrics1[k]} != {train_metrics2[k]}")
                identical = False
        
        # Check model weights
        for (n1, p1), (n2, p2) in zip(model1.named_parameters(), model2.named_parameters()):
            if not torch.allclose(p1, p2):
                logger.error(f"Mismatch in parameter {n1}")
                identical = False
                
        if identical:
            logger.info("Determinism check PASSED: identical metrics and weights across runs.")
        else:
            logger.error("Determinism check FAILED.")
            
        logger.info("\n=== CHECKPOINT SAVE/RELOAD CHECK ===")
        ckpt_dir = Path("checkpoints")
        ckpt_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        pt_path = ckpt_dir / f"sentinel_{timestamp_str}.pt"
        meta_path = ckpt_dir / f"sentinel_{timestamp_str}_meta.json"
        
        # Save
        torch.save(model1.state_dict(), pt_path)
        meta_data = {
            "model_args": model_args,
            "train_metrics": train_metrics1,
            "timestamp": timestamp_str
        }
        with open(meta_path, "w") as f:
            json.dump(meta_data, f, indent=2)
            
        logger.info(f"Saved to {pt_path} and {meta_path}")
        
        # Reload
        reloaded_model = WorldModel(**model_args)
        reloaded_model.load_state_dict(torch.load(pt_path, weights_only=True))
        reloaded_model.eval()
        
        # Forward pass on same input
        model1.eval()
        test_seq = train_seqs[-1]
        
        with torch.no_grad():
            res1 = model1(test_seq)
            res2 = reloaded_model(test_seq)
            
        match = True
        if res1.attack_probability != res2.attack_probability:
            match = False
            logger.error("Reload check failed: attack_probability mismatch")
        if res1.stage_probabilities != res2.stage_probabilities:
            match = False
            logger.error("Reload check failed: stage_probabilities mismatch")
            
        if match:
            logger.info("Reload check PASSED: output is identical.")
        else:
            logger.error("Reload check FAILED.")
            
    else:
        logger.info("Running real data pipeline with combined slices...")
        model, model_args, train_seqs, test_seqs, test_targets, train_metrics, test_metrics = run_pipeline(
            csv_paths, is_smoke=False, epochs=args.epochs, save_path=args.save_path,
            resume_from=args.resume_from, device=args.device, resume_folds=args.resume_folds,
            max_rows=args.max_rows, use_window_features=not args.no_window_features,
            mitre_weight=args.mitre_weight, patience=args.patience,
            val_fraction=args.val_fraction, pos_weight_mode=args.pos_weight,
            protocol=args.protocol, n_splits=args.n_splits, block_size=args.block_size,
            mitre_class_weights=not args.no_mitre_class_weights,
            label_policy=args.label_policy, only_fold=args.only_fold
        )

        if model is None:
            logger.info("All folds were resumed from disk; no new weights to checkpoint.")
            return

        logger.info("\n=== SAVING CHECKPOINT ===")
        ckpt_dir = Path(args.save_path)
        ckpt_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        pt_path = ckpt_dir / f"sentinel_{timestamp_str}.pt"
        meta_path = ckpt_dir / f"sentinel_{timestamp_str}_meta.json"
        
        torch.save(model.state_dict(), pt_path)
        meta_data = {
            "model_args": model_args,
            "train_metrics": train_metrics,
            "test_metrics": test_metrics,
            "timestamp": timestamp_str,
            "epochs": args.epochs
        }
        with open(meta_path, "w") as f:
            json.dump(meta_data, f, indent=2)
            
        logger.info(f"Saved to {pt_path} and {meta_path}")

if __name__ == "__main__":
    main()
