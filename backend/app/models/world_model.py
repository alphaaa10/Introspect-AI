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
        mitre_arch: str = "mlp",
    ):
        super().__init__()

        # Width of the extractor's per-window feature vector fused into each
        # LSTM timestep alongside the GAT embedding. 0 disables fusion and
        # reproduces the graph-only architecture.
        self.window_feat_dim = window_feat_dim

        # MITRE-head architecture. Made an explicit parameter, not a hardcoded
        # default, because the state_dict keys differ per arch and loading a
        # checkpoint into the wrong one silently leaves the head random (the bug
        # that produced a meaningless confusion matrix). The loader must build
        # the arch the checkpoint was trained with.
        #   "linear"    : Linear(H, S)                        - keys mitre_head.{weight,bias}
        #   "mlp"       : Linear(H,64)-ReLU-Linear(64,S)      - keys mitre_head.{0,2}.*
        #   "dual_lstm" : separate trainable lstm_mitre on the frozen GAT
        #                 embeddings, its summary concatenated with the target
        #                 window's raw features, then the MLP head. Tests whether
        #                 the binary-trained LSTM aggregation - not the GAT - is
        #                 what collapses the overlapping stages.
        if mitre_arch not in ("linear", "mlp", "dual_lstm"):
            raise ValueError(f"mitre_arch must be linear|mlp|dual_lstm, got {mitre_arch!r}")
        self.mitre_arch = mitre_arch

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
        if mitre_arch == "dual_lstm":
            # A second LSTM, trained only for stages, over the SAME frozen GAT
            # per-timestep embeddings the binary LSTM sees (identical config).
            self.lstm_mitre = LSTMEncoder(
                input_dim=gat_out_dim * 2 + window_feat_dim,
                hidden_dim=lstm_hidden_dim,
                num_layers=lstm_num_layers,
                dropout=lstm_dropout,
            )
            # Skip connection: the target window's raw features are concatenated
            # to lstm_mitre's summary, so the stage head sees the type-discriminative
            # signals (flag counts, unique_dst_ports, IAT) directly, not only what
            # the LSTM chose to keep.
            mitre_in_dim = lstm_hidden_dim + window_feat_dim
        else:
            mitre_in_dim = lstm_hidden_dim

        if mitre_arch == "linear":
            self.mitre_head = nn.Linear(mitre_in_dim, num_mitre_stages)
        else:  # "mlp" and "dual_lstm" both use the 2-layer MLP head
            # The MLP gives capacity to separate stage embeddings a single linear
            # layer cannot (Impact and Credential Access overlap in the
            # binary-trained embedding space).
            self.mitre_head = nn.Sequential(
                nn.Linear(mitre_in_dim, 64),
                nn.ReLU(),
                nn.Linear(64, num_mitre_stages),
            )

    def _build_seq_single(self, windows: list[GraphWindow]) -> tuple[torch.Tensor, torch.Tensor]:
        """GAT-per-window then fuse features -> ([1, seq_len, D], last_window_feats [1, wf]).

        Returns the per-timestep LSTM input plus the final window's raw features
        (for the dual_lstm skip connection). Factored out so the binary and
        mitre paths run the GAT once and share the sequence.
        """
        if not windows:
            raise ValueError("Input sequence cannot be empty.")

        device = next(self.parameters()).device

        step_vectors = []
        last_wf = None
        for gw in windows:
            x, edge_index, edge_attr = window_to_tensors(
                gw, dtype=torch.float32, device=device
            )
            emb = self.gat(x, edge_index, edge_attr)

            if self.window_feat_dim > 0:
                wf = window_features_to_tensor(
                    gw, self.window_feat_dim, dtype=torch.float32, device=device
                )
                last_wf = wf
                emb = torch.cat([emb, wf], dim=0)

            step_vectors.append(emb)

        seq_tensor = torch.stack(step_vectors, dim=0).unsqueeze(0)  # [1, L, D]
        if last_wf is None:
            last_wf = torch.zeros(self.window_feat_dim, device=device)
        return seq_tensor, last_wf.unsqueeze(0)  # [1, wf]

    def encode(self, windows: list[GraphWindow]) -> torch.Tensor:
        """Run GAT-per-window then the binary LSTM, returning [1, lstm_hidden_dim].

        This is the single encoding path for the binary summary. `forward` and
        `logits` share it so they cannot drift apart.
        """
        seq_tensor, _ = self._build_seq_single(windows)
        return self.lstm(seq_tensor)

    def _mitre_logits(self, seq_tensor: torch.Tensor, binary_summary: torch.Tensor,
                      last_wf: torch.Tensor, lengths: torch.Tensor | None) -> torch.Tensor:
        """Route the MITRE head according to mitre_arch.

        linear/mlp : read the binary LSTM summary (reused, not recomputed).
        dual_lstm  : run the separate lstm_mitre on the same per-timestep
                     sequence, concat the target window's raw features, then head.
        """
        if self.mitre_arch == "dual_lstm":
            m = self.lstm_mitre(seq_tensor, lengths=lengths)  # [B, H]
            if self.window_feat_dim > 0:
                m = torch.cat([m, last_wf], dim=-1)           # [B, H + wf]
            return self.mitre_head(m)
        return self.mitre_head(binary_summary)

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
        lengths = collated["seq_lengths"]
        summary = self.lstm(seq_inputs, lengths=lengths)      # [B, H]
        attack_logits = self.attack_head(summary)
        last_wf = self._last_window_features(collated)        # [B, wf]
        mitre_logits = self._mitre_logits(seq_inputs, summary, last_wf, lengths)
        return attack_logits, mitre_logits

    def _last_window_features(self, collated: dict) -> torch.Tensor:
        """Each sequence's TARGET (last valid) window features -> [B, wf].

        Graph id for sequence b, timestep t is b*T_max + t, so the last valid
        window is at b*T_max + (seq_lengths[b]-1). Only used by dual_lstm.
        """
        wf = collated["graph_window_features"]                # [B*T_max, wf]
        T_max = int(collated["T_max"])
        lengths = collated["seq_lengths"]
        B = int(lengths.size(0))
        idx = torch.arange(B) * T_max + (lengths - 1)
        return wf[idx.to(wf.device)]

    def logits(self, windows: list[GraphWindow]) -> tuple[torch.Tensor, torch.Tensor]:
        """Raw (attack_logits [1,1], mitre_logits [1,num_stages]) for loss computation.

        Training needs logits, not the probabilities `forward` returns; exposing
        them here removes the duplicated encoder that used to live in train.py.
        """
        seq_tensor, last_wf = self._build_seq_single(windows)
        summary_state = self.lstm(seq_tensor)
        attack_logits = self.attack_head(summary_state)
        mitre_logits = self._mitre_logits(seq_tensor, summary_state, last_wf, None)
        return attack_logits, mitre_logits

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
        seq_tensor, last_wf = self._build_seq_single(windows)
        summary_state = self.lstm(seq_tensor)
        attack_logits = self.attack_head(summary_state)  # [1, 1]
        mitre_logits = self._mitre_logits(seq_tensor, summary_state, last_wf, None)  # [1, S]

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

    @torch.no_grad()
    def attention_for_sequence(self, sequence, top_k: int = 5) -> list[dict]:
        """Top-K attended edges per window — read-only extraction of GAT attention.

        The GAT already computes per-edge attention during its forward pass and
        stores it in ``gat.latest_attention_weights`` as ``[E, num_heads]`` (a
        softmax over incoming edges per destination node, so weights sum to 1 per
        node). This re-runs the encoder per window on the single-graph path purely
        to read that tensor back out; it does NOT modify the forward pass and does
        NOT touch the detection path. Heads are averaged, then the highest-weight
        edges are mapped to (src_ip, dst_ip) through the window's own edge list
        (edge row j corresponds to ``window.edges[j]``).

        Returns a list aligned with ``sequence``:
            ``[{"window_id", "top_edges": [{"src","dst","weight"}, ...]}, ...]``

        Attention is per-window and order-independent, so callers may pass any set
        of windows (e.g. just the alert windows). Call in eval mode so attention
        dropout is disabled and the per-node weights sum to exactly 1.
        """
        from app.graph.converter import window_to_tensors

        device = next(self.parameters()).device
        out: list[dict] = []
        for gw in sequence:
            x, edge_index, edge_attr = window_to_tensors(gw, device=device)
            # Populate gat.latest_attention_weights for THIS window.
            self.gat(x, edge_index, edge_attr)
            alpha = self.gat.latest_attention_weights  # [E, num_heads] or empty
            edges: list[dict] = []
            if alpha is not None and alpha.numel() > 0 and gw.edges:
                w = alpha.mean(dim=1).detach().cpu().tolist()  # average heads -> [E]
                m = min(len(w), len(gw.edges))
                paired = [(gw.edges[j].src_ip, gw.edges[j].dst_ip, float(w[j])) for j in range(m)]
                paired.sort(key=lambda t: t[2], reverse=True)
                edges = [{"src": s, "dst": d, "weight": round(wt, 4)}
                         for s, d, wt in paired[:top_k]]
            out.append({"window_id": gw.window_id, "top_edges": edges})
        return out
