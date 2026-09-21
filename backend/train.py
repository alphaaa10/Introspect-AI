import argparse
import json
import logging
import math
import sys
from datetime import datetime
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

from app import config
from app.schemas import DataSource, MitreStage
from app.ingestion.parser import parse_csv, parse_cicids2017_csv
from app.features.extractor import window_and_extract
from app.graph.builder import build_graph, NODE_FEATURE_NAMES, EDGE_FEATURE_NAMES
from app.models.world_model import WorldModel, set_seed

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Label mapping for CIC-IDS-2018 (and similar) to MitreStage
LABEL_TO_MITRE = {
    "Benign": MitreStage.BENIGN,
    "Web Attack": MitreStage.INITIAL_ACCESS,  # Mock data has 'Web Attack'
    "Portscan": MitreStage.RECONNAISSANCE,
    "DDoS": MitreStage.IMPACT,
    "Botnet": MitreStage.C2,
    "Botnet - Attempted": MitreStage.C2,
    "Infiltration": MitreStage.LATERAL_MOVEMENT,
}

def get_window_label(window_events):
    """Aggregate event labels into a single window-level binary and MITRE label."""
    if not window_events:
        return 0, MitreStage.BENIGN

    attack_labels = [e.label for e in window_events if e.label.lower() != "benign"]
    
    if not attack_labels:
        return 0, MitreStage.BENIGN
    
    # Mode of attack labels
    counts = {}
    for lbl in attack_labels:
        counts[lbl] = counts.get(lbl, 0) + 1
    
    # Sort by count descending, then lexicographically for deterministic tie-breaking
    sorted_labels = sorted(counts.items(), key=lambda x: (-x[1], x[0]))
    dominant_label = sorted_labels[0][0]
    
    mitre_stage = LABEL_TO_MITRE.get(dominant_label, MitreStage.IMPACT)
    return 1, mitre_stage

def create_sequences(windows, all_events):
    """Create sequences of windows up to config.SEQUENCE_LENGTH and their targets."""
    # Group events by window ID for label aggregation
    events_by_window = {}
    for e in all_events:
        wid = None
        for w in windows:
            if w.window_start <= e.timestamp < w.window_end:
                wid = w.window_id
                break
        if wid:
            events_by_window.setdefault(wid, []).append(e)

    sequences = []
    targets = [] # list of (is_attack: int, mitre_idx: int)
    
    for i in range(len(windows)):
        seq_start = max(0, i - config.SEQUENCE_LENGTH + 1)
        seq = windows[seq_start : i + 1]
        target_window = windows[i]
        
        is_attack, mitre_stage = get_window_label(events_by_window.get(target_window.window_id, []))
        mitre_idx = list(MitreStage).index(mitre_stage)
        
        sequences.append(seq)
        targets.append((is_attack, mitre_idx))
        
    return sequences, targets

def compute_metrics(y_true_attack, y_pred_attack_probs, y_true_mitre, y_pred_mitre):
    """Compute scikit-learn metrics safely handling edge cases."""
    y_pred_attack_binary = [1 if p >= 0.5 else 0 for p in y_pred_attack_probs]
    
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
            
        metrics['attack_confusion_matrix'] = confusion_matrix(y_true_attack, y_pred_attack_binary).tolist()
    except Exception as e:
        metrics['attack_error'] = str(e)

    # Mitre multiclass metrics (only calculated over attack windows if any)
    attack_indices = [i for i, y in enumerate(y_true_attack) if y == 1]
    if attack_indices:
        yt_m = [y_true_mitre[i] for i in attack_indices]
        yp_m = [y_pred_mitre[i] for i in attack_indices]
        try:
            metrics['mitre_accuracy'] = accuracy_score(yt_m, yp_m)
            metrics['mitre_f1_macro'] = f1_score(yt_m, yp_m, average='macro', zero_division=0)
        except Exception as e:
            metrics['mitre_error'] = str(e)
    else:
        metrics['mitre_accuracy'] = "N/A (no attack windows in set)"
        metrics['mitre_f1_macro'] = "N/A"

    return metrics

def train_one_epoch(model, optimizer, sequences, targets, attack_criterion, mitre_criterion):
    model.train()
    total_loss = 0.0
    for seq, (is_attack, mitre_idx) in zip(sequences, targets):
        optimizer.zero_grad()
        
        result = model(seq)
        
        # We need raw logits for loss calculation. Since WorldModel returns probabilities,
        # we compute the embedding manually here to respect the rule of not changing world_model.py
        from app.graph.converter import window_to_tensors
        gat_embeddings = []
        for gw in seq:
            x, edge_index, edge_attr = window_to_tensors(gw, dtype=torch.float32, device=next(model.parameters()).device)
            emb = model.gat(x, edge_index, edge_attr)
            gat_embeddings.append(emb)
        seq_tensor = torch.stack(gat_embeddings, dim=0).unsqueeze(0)
        embedding = model.lstm(seq_tensor)
        
        attack_logits = model.attack_head(embedding)
        mitre_logits = model.mitre_head(embedding)
        
        loss_attack = attack_criterion(attack_logits.squeeze(), torch.tensor(float(is_attack)))
        loss_mitre = mitre_criterion(mitre_logits.squeeze(0), torch.tensor(mitre_idx))
        
        # Loss weighting: MITRE loss only applies if it's an attack
        loss = loss_attack
        if is_attack:
            loss += loss_mitre
            
        loss.backward()
        optimizer.step()
        total_loss += loss.item()
        
    return total_loss / max(len(sequences), 1)

def evaluate(model, sequences, targets):
    model.eval()
    y_true_attack, y_pred_attack_probs = [], []
    y_true_mitre, y_pred_mitre = [], []
    
    with torch.no_grad():
        for seq, (is_attack, mitre_idx) in zip(sequences, targets):
            result = model(seq)
            y_true_attack.append(is_attack)
            y_pred_attack_probs.append(result.attack_probability)
            
            y_true_mitre.append(mitre_idx)
            pred_mitre_idx = list(MitreStage).index(result.predicted_stage)
            y_pred_mitre.append(pred_mitre_idx)
            
    return compute_metrics(y_true_attack, y_pred_attack_probs, y_true_mitre, y_pred_mitre)

def run_pipeline(
    csv_path: Path, 
    is_smoke: bool = False,
    epochs: int = 30
) -> tuple[WorldModel, dict, list, dict, str]:
    """
    End-to-end data ingestion, sequence building, and model training.
    """
    filepath = csv_path
    logger.info(f"Setting global seed to {config.GLOBAL_SEED}")
    set_seed(config.GLOBAL_SEED)
    
    logger.info(f"Parsing CSV: {filepath}")
    if is_smoke:
        events, errors = parse_csv(filepath, source=DataSource.MOCK)
    else:
        events, errors = parse_cicids2017_csv(filepath, source=DataSource.REAL)
        
    logger.info(f"Parsed {len(events)} valid events, {len(errors)} errors skipped.")
    if not events:
        logger.error("No valid events parsed. Aborting.")
        return None
        
    logger.info("Windowing and extracting features...")
    feature_records = window_and_extract(events)
    logger.info(f"Generated {len(feature_records)} windows.")
    
    logger.info("Building graphs...")
    windows = []
    for fr in feature_records:
        gw = build_graph(events, fr.window_id, fr.window_start, fr.window_end, fr.source)
        windows.append(gw)
        
    logger.info("Creating sequences...")
    # Fix: Split windows into contiguous chunks based on timestamp to avoid sequences straddling time gaps
    chunks = []
    current_chunk = []
    
    for w in windows:
        if not current_chunk:
            current_chunk.append(w)
        else:
            # Check if this window directly follows the previous one in time
            prev_w = current_chunk[-1]
            if w.window_start == prev_w.window_end:
                current_chunk.append(w)
            else:
                chunks.append(current_chunk)
                current_chunk = [w]
    if current_chunk:
        chunks.append(current_chunk)
        
    all_seqs = []
    all_targets = []
    for chunk in chunks:
        chunk_seqs, chunk_targets = create_sequences(chunk, events)
        all_seqs.extend(chunk_seqs)
        all_targets.extend(chunk_targets)
    
    # Phase 7 Requirement: Interleaved chronological split on SEQUENCES, not windows.
    # Standard single-cut chronological splitting is infeasible because the dataset
    # has a one-time, non-recurring benign-to-attack transition.
    # Interleaved splitting is a documented compromise to ensure computable validation metrics,
    # while preserving true local temporal adjacency within each sequence.
    train_seqs, train_targets = [], []
    val_seqs, val_targets = [], []
    test_seqs, test_targets = [], []
    
    for idx, (seq, tgt) in enumerate(zip(all_seqs, all_targets)):
        if idx % 7 == 5:
            val_seqs.append(seq)
            val_targets.append(tgt)
        elif idx % 7 == 6:
            test_seqs.append(seq)
            test_targets.append(tgt)
        else:
            train_seqs.append(seq)
            train_targets.append(tgt)
            
    logger.info(f"Sequence counts: Train={len(train_seqs)}, Val={len(val_seqs)}, Test={len(test_seqs)}")
    if len(train_seqs) == 0:
        logger.warning("Train set is empty! Defaulting to all sequences for training in smoke test.")
        train_seqs = all_seqs
        train_targets = all_targets
        val_seqs, val_targets = [], []
        test_seqs, test_targets = [], []
    
    # Label distribution reporting
    def report_dist(name, tgts):
        if not tgts:
            return
        attacks = sum(1 for t in tgts if t[0] == 1)
        benign = len(tgts) - attacks
        mitre_counts = {}
        for t in tgts:
            if t[0] == 1:
                stage_name = list(MitreStage)[t[1]].value
                mitre_counts[stage_name] = mitre_counts.get(stage_name, 0) + 1
        logger.info(f"--- {name} Label Distribution ---")
        logger.info(f"    Total: {len(tgts)} sequences")
        logger.info(f"    Binary: {benign} Benign, {attacks} Attack")
        if attacks > 0:
            logger.info(f"    Attack breakdown:")
            for k, v in mitre_counts.items():
                logger.info(f"        {k}: {v}")
                
    report_dist("Train", train_targets)
    report_dist("Val", val_targets)
    report_dist("Test", test_targets)
    
    if 'dry_run' in globals() and globals()['dry_run']:
        logger.info("Dry run complete. Exiting before training.")
        sys.exit(0)
    
    model_args = dict(
        node_in_dim=len(NODE_FEATURE_NAMES),
        edge_in_dim=len(EDGE_FEATURE_NAMES),
        gat_hidden_dim=16,
        gat_num_heads=2,
        gat_out_dim=8,
        gat_dropout=0.0,
        lstm_hidden_dim=32,
        lstm_num_layers=1,
        lstm_dropout=0.0,
        num_mitre_stages=config.NUM_MITRE_STAGES,
    )
    model = WorldModel(**model_args)
    
    optimizer = optim.Adam(model.parameters(), lr=1e-3)
    
    num_attacks = sum(1 for t in train_targets if t[0] == 1)
    num_benign = len(train_targets) - num_attacks
    
    # Weight = (Negative Samples) / (Positive Samples)
    pos_weight_val = num_benign / max(1, num_attacks)
    pos_weight = torch.tensor(pos_weight_val, dtype=torch.float32)
    logger.info(f"Using pos_weight={pos_weight.item():.4f} for attack_criterion")
    
    attack_criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    mitre_criterion = nn.CrossEntropyLoss()
    
    logger.info("Starting training...")
    for epoch in range(1, epochs + 1):
        loss = train_one_epoch(model, optimizer, train_seqs, train_targets, attack_criterion, mitre_criterion)
        logger.info(f"Epoch {epoch}/{epochs} - Loss: {loss:.4f}")
        
    logger.info("Evaluating on Train set:")
    train_metrics = evaluate(model, train_seqs, train_targets)
    for k, v in train_metrics.items():
        logger.info(f"  {k}: {v}")
        
    test_metrics = None
    if test_seqs:
        logger.info("Evaluating on Test set:")
        test_metrics = evaluate(model, test_seqs, test_targets)
        for k, v in test_metrics.items():
            logger.info(f"  {k}: {v}")
    else:
        logger.info("Test set empty, skipping test evaluation.")
        
    return model, model_args, train_seqs, train_metrics, test_metrics

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true", help="Run smoke test on mock data")
    parser.add_argument("--epochs", type=int, default=10, help="Number of training epochs")
    parser.add_argument("--patience", type=int, default=3, help="Early stopping patience")
    parser.add_argument("--save-path", type=str, default="checkpoints", help="Directory to save model checkpoints")
    parser.add_argument("--dry-run", action="store_true", help="Print label distribution and exit before training")
    args = parser.parse_args()
    
    global dry_run
    dry_run = args.dry_run
    
    # Path to real data slice
    csv_path = "data/raw/friday_plus_slice_mixed.csv"
    
    if args.smoke:
        logger.info("=== RUNNING SMOKE TEST (Pass 1) ===")
        filepath = Path("data/samples/mock_cicids.csv")
        model1, model_args, train_seqs, train_metrics1, _ = run_pipeline(filepath, is_smoke=True, epochs=args.epochs)
        
        logger.info("\n=== RUNNING SMOKE TEST (Pass 2 - Determinism Check) ===")
        model2, _, _, train_metrics2, _ = run_pipeline(filepath, is_smoke=True)
        
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
        ckpt_dir.mkdir(exist_ok=True)
        
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
        logger.info("Running real data pipeline (friday_plus_slice_mixed.csv)...")
        filepath = Path(csv_path)
        model, model_args, train_seqs, train_metrics, test_metrics = run_pipeline(filepath, is_smoke=False, epochs=args.epochs)
        
        logger.info("\n=== SAVING CHECKPOINT ===")
        ckpt_dir = Path(args.save_path)
        ckpt_dir.mkdir(exist_ok=True)
        
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
