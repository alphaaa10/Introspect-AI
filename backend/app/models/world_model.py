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
from app.graph.converter import window_to_tensors, window_features_to_tensor
from app.models.gat import GATEncoder
from app.models.lstm import LSTMEncoder

# Re-exported so existing `from app.models.world_model import set_seed` keeps working.
from app.models.seeding import set_seed  # noqa: F401

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
        window_feat_dim: int = 0,
    ):
        super().__init__()

        # Width of the extractor's per-window feature vector fused into each
        # LSTM timestep alongside the GAT embedding. 0 disables fusion and
        # reproduces the graph-only architecture.
        self.window_feat_dim = window_feat_dim

        self.gat = GATEncoder(
            node_in_dim=node_in_dim,
            edge_in_dim=edge_in_dim,
            hidden_dim=gat_hidden_dim,
            num_heads=gat_num_heads,
            output_dim=gat_out_dim,
            dropout=gat_dropout,
        )
        
        # GAT readout is mean+max concatenated, hence the * 2.
        self.lstm = LSTMEncoder(
            input_dim=gat_out_dim * 2 + window_feat_dim,
            hidden_dim=lstm_hidden_dim,
            num_layers=lstm_num_layers,
            dropout=lstm_dropout,
        )
        
        self.num_mitre_stages = num_mitre_stages
        
        # Head 1: Attack Probability (Binary)
        self.attack_head = nn.Linear(lstm_hidden_dim, 1)
        
        # Head 2: MITRE Stage Classification (Multi-class)
        self.mitre_head = nn.Linear(lstm_hidden_dim, num_mitre_stages)

    def encode(self, windows: list[GraphWindow]) -> torch.Tensor:
        """Run GAT-per-window then the LSTM, returning [1, lstm_hidden_dim].

        This is the single encoding path. `forward` wraps it for inference and
        training calls it via `logits`, so the two cannot drift apart — they
        previously did, which is how the fused window features and any future
        encoder change would silently apply to only one of them.
        """
        if not windows:
            raise ValueError("Input sequence cannot be empty.")

        device = next(self.parameters()).device

        step_vectors = []
        for gw in windows:
            x, edge_index, edge_attr = window_to_tensors(
                gw, dtype=torch.float32, device=device
            )
            emb = self.gat(x, edge_index, edge_attr)

            if self.window_feat_dim > 0:
                wf = window_features_to_tensor(
                    gw, self.window_feat_dim, dtype=torch.float32, device=device
                )
                emb = torch.cat([emb, wf], dim=0)

            step_vectors.append(emb)

        # [seq_len, feat] -> [1, seq_len, feat]
        seq_tensor = torch.stack(step_vectors, dim=0).unsqueeze(0)
        return self.lstm(seq_tensor)

    def encode_batch(self, collated: dict) -> torch.Tensor:
        """Per-timestep embeddings for a collated batch: [B, T_max, D].

        D == gat_out_dim * 2 + window_feat_dim, i.e. the same vector the
        unbatched `encode` feeds the LSTM at each timestep.

        The whole batch's graphs are run through the GAT as ONE disjoint-union
        graph. `collate_sequences` has already offset node indices per graph, so
        attention cannot cross a graph boundary (see GATEncoder.forward).

        Padded timesteps are present as empty graphs and come back as zeros.
        They are excluded from the LSTM by `logits_batch` via packing, not by
        being absent here — keeping the tensor rectangular is what makes the
        reshape to [B, T_max, D] valid.
        """
        B = int(collated["seq_lengths"].size(0))
        T_max = int(collated["T_max"])
        num_graphs = B * T_max

        # [B*T_max, gat_out_dim * 2]
        graph_emb = self.gat(
            collated["graph_x"],
            collated["graph_edge_index"],
            collated["graph_edge_attr"],
            batch_index=collated["graph_batch_index"],
            num_graphs=num_graphs,
        )

        if self.window_feat_dim > 0:
            wf = collated["graph_window_features"]
            if wf.shape != (num_graphs, self.window_feat_dim):
                raise ValueError(
                    f"graph_window_features has shape {tuple(wf.shape)} but the "
                    f"model expects ({num_graphs}, {self.window_feat_dim})."
                )
            graph_emb = torch.cat([graph_emb, wf], dim=-1)

        return graph_emb.view(B, T_max, -1)

    def logits_batch(self, collated: dict) -> tuple[torch.Tensor, torch.Tensor]:
        """Raw (attack_logits [B,1], mitre_logits [B,num_stages]) for a batch.

        Mirrors `logits` for many sequences at once. The LSTM is fed through
        pack_padded_sequence using seq_lengths, so each sequence's summary state
        comes from its own last valid timestep and never from padding.
        """
        seq_inputs = self.encode_batch(collated)              # [B, T_max, D]
        summary = self.lstm(seq_inputs, lengths=collated["seq_lengths"])  # [B, H]
        return self.attack_head(summary), self.mitre_head(summary)

    def logits(self, windows: list[GraphWindow]) -> tuple[torch.Tensor, torch.Tensor]:
        """Raw (attack_logits [1,1], mitre_logits [1,num_stages]) for loss computation.

        Training needs logits, not the probabilities `forward` returns; exposing
        them here removes the duplicated encoder that used to live in train.py.
        """
        summary_state = self.encode(windows)
        return self.attack_head(summary_state), self.mitre_head(summary_state)

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
        summary_state = self.encode(windows)
        attack_logits = self.attack_head(summary_state)  # [1, 1]
        mitre_logits = self.mitre_head(summary_state)    # [1, num_mitre_stages]

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
