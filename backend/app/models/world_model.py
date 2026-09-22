"""
models/world_model.py

Wires the GAT + LSTM pipeline together and provides BOTH prediction heads:
1. attack/infiltration probability (scalar, 0.0-1.0)
2. MITRE stage/technique classification (vector of length config.NUM_MITRE_STAGES)
"""

from __future__ import annotations

import torch
import torch.nn as nn
from app import config
from app.schemas import GraphWindow, PredictionResult, MitreStage
from app.graph.converter import window_to_tensors
from app.models.gat import GATEncoder
from app.models.lstm import LSTMEncoder

def set_seed(seed: int | None = None) -> None:
    s = seed if seed is not None else config.GLOBAL_SEED
    torch.manual_seed(s)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(s)

class WorldModel(nn.Module):
    def __init__(
        self,
        node_in_dim: int,
        edge_in_dim: int,
        gat_hidden_dim: int,
        gat_num_heads: int,
        gat_out_dim: int,
        gat_dropout: float,
        lstm_hidden_dim: int,
        lstm_num_layers: int,
        lstm_dropout: float,
        num_mitre_stages: int,
    ):
        super().__init__()
        
        self.gat = GATEncoder(
            node_in_dim=node_in_dim,
            edge_in_dim=edge_in_dim,
            hidden_dim=gat_hidden_dim,
            num_heads=gat_num_heads,
            output_dim=gat_out_dim,
            dropout=gat_dropout,
        )
        
        self.lstm = LSTMEncoder(
            input_dim=gat_out_dim * 2,
            hidden_dim=lstm_hidden_dim,
            num_layers=lstm_num_layers,
            dropout=lstm_dropout,
        )
        
        self.num_mitre_stages = num_mitre_stages
        
        # Head 1: Attack Probability (Binary)
        self.attack_head = nn.Linear(lstm_hidden_dim, 1)
        
        # Head 2: MITRE Stage Classification (Multi-class)
        self.mitre_head = nn.Linear(lstm_hidden_dim, num_mitre_stages)

    def forward(self, windows: list[GraphWindow]) -> PredictionResult:
        """
        Forward pass for a single sequence of GraphWindows.
        
        Parameters
        ----------
        windows : list[GraphWindow]
            A chronologically ordered sequence of graphs.
            Batching multiple sequences (list of lists) is EXPLICITLY NOT SUPPORTED.
            Variable length sequences (including length 1) are natively supported.
            If the list is empty, a ValueError is raised.
            
        Returns
        -------
        PredictionResult
            A typed pydantic object mapping the final outputs.
        """
        if not windows:
            raise ValueError("Input sequence cannot be empty.")

        gat_embeddings = []
        for gw in windows:
            # Convert to tensors
            x, edge_index, edge_attr = window_to_tensors(
                gw, dtype=torch.float32, device=next(self.parameters()).device
            )
            
            # GAT pass
            emb = self.gat(x, edge_index, edge_attr)
            gat_embeddings.append(emb)
            
        # Shape: [seq_len, gat_out_dim]
        seq_tensor = torch.stack(gat_embeddings, dim=0)
        
        # Add batch dimension: [1, seq_len, gat_out_dim]
        seq_tensor = seq_tensor.unsqueeze(0)
        
        # LSTM pass -> [1, lstm_hidden_dim]
        summary_state = self.lstm(seq_tensor)
        
        # Prediction Heads
        attack_logits = self.attack_head(summary_state) # [1, 1]
        mitre_logits = self.mitre_head(summary_state)   # [1, num_mitre_stages]
        
        # Activations
        attack_prob = torch.sigmoid(attack_logits).squeeze().item()
        mitre_probs = torch.softmax(mitre_logits, dim=-1).squeeze(0) # [num_mitre_stages]
        
        predicted_stage_idx = int(torch.argmax(mitre_probs).item())
        _all_stages = list(MitreStage)
        if not (0 <= predicted_stage_idx < len(_all_stages)):
            raise ValueError(
                f"predicted_stage_idx={predicted_stage_idx} is out of range for "
                f"MitreStage (len={len(_all_stages)}). This indicates num_mitre_stages "
                f"was set to a value inconsistent with the MitreStage enum."
            )
        predicted_stage = _all_stages[predicted_stage_idx]
        
        # Last window attention weights (flattened)
        attn_tensor = self.gat.latest_attention_weights
        if attn_tensor is not None:
            attn_list = attn_tensor.detach().cpu().flatten().tolist()
        else:
            attn_list = []
            
        return PredictionResult(
            window_id=windows[-1].window_id,
            attack_probability=attack_prob,
            stage_probabilities=mitre_probs.detach().cpu().tolist(),
            predicted_stage=predicted_stage,
            embedding=summary_state.squeeze(0).detach().cpu().tolist(),
            attention_weights=attn_list,
            source=windows[-1].source,
        )
