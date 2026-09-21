"""
models/gat.py

Graph Attention Network (GAT) encoder.
Converts a single GraphWindow's tensors into a fixed-dimension graph-level
embedding suitable for an LSTM timestep.

Hand-written in plain PyTorch to avoid PyTorch Geometric dependency hell on
Windows, per the approved Phase 5 plan.
"""

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F

from app import config


def set_seed(seed: int | None = None) -> None:
    """Explicit determinism mechanism. Call before model instantiation."""
    s = seed if seed is not None else config.GLOBAL_SEED
    torch.manual_seed(s)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(s)


class GATLayer(nn.Module):
    """
    A single-head GATv2-style layer with edge features.
    
    Attention formula:
        z_src_i  = W_src * h_j   (source node)
        z_dst_i  = W_dst * h_i   (target node)
        z_edge   = W_edge * e_ij (edge)
        score_ij = a^T * LeakyReLU(z_src_i + z_dst_i + z_edge)
        alpha_ij = softmax_i(score_ij)  # softmax over all j where dst == i
        h'_i     = sum_j(alpha_ij * (W_val * h_j))
    """
    def __init__(
        self,
        node_in_dim: int,
        edge_in_dim: int,
        out_dim: int,
        dropout: float = 0.0,
    ):
        super().__init__()
        self.node_in_dim = node_in_dim
        self.edge_in_dim = edge_in_dim
        self.out_dim = out_dim
        self.dropout = dropout

        # Projections
        self.W_src = nn.Linear(node_in_dim, out_dim, bias=False)
        self.W_dst = nn.Linear(node_in_dim, out_dim, bias=False)
        self.W_edge = nn.Linear(edge_in_dim, out_dim, bias=False)
        self.W_val = nn.Linear(node_in_dim, out_dim, bias=False)
        
        # Attention vector
        self.a = nn.Parameter(torch.empty(size=(out_dim, 1)))
        nn.init.xavier_uniform_(self.a.data, gain=1.414)

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_attr: torch.Tensor,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        num_nodes = x.size(0)
        num_edges = edge_index.size(1)

        # Empty graph or isolated nodes with no edges
        if num_edges == 0:
            if num_nodes == 0:
                return (
                    torch.zeros((0, self.out_dim), device=x.device, dtype=x.dtype),
                    torch.empty((0, 1), device=x.device, dtype=x.dtype)
                )
            else:
                return (
                    torch.zeros((num_nodes, self.out_dim), device=x.device, dtype=x.dtype),
                    torch.empty((0, 1), device=x.device, dtype=x.dtype)
                )

        src_idx = edge_index[0]
        dst_idx = edge_index[1]

        # 1. Project inputs
        z_src = self.W_src(x[src_idx])    # [E, out_dim]
        z_dst = self.W_dst(x[dst_idx])    # [E, out_dim]
        z_edge = self.W_edge(edge_attr)   # [E, out_dim]

        # 2. Compute attention scores
        e = F.leaky_relu(z_src + z_dst + z_edge, negative_slope=0.2)  # [E, out_dim]
        scores = torch.matmul(e, self.a).squeeze(-1)                  # [E]

        # 3. Softmax over neighborhoods (all j where dst_idx == i)
        # We need to compute max for numerical stability
        max_scores = torch.zeros(num_nodes, device=x.device, dtype=x.dtype)
        
        # Use amax via scatter_reduce_ which is available in torch >= 2.0
        max_scores.scatter_reduce_(0, dst_idx, scores, reduce="amax", include_self=False)
        
        scores_shifted = scores - max_scores[dst_idx]
        exp_scores = torch.exp(scores_shifted)
        
        sum_exp = torch.zeros(num_nodes, device=x.device, dtype=x.dtype)
        sum_exp.scatter_add_(0, dst_idx, exp_scores)
        
        # alpha_ij = exp(score_ij) / sum(exp(score_ik))
        alpha = exp_scores / (sum_exp[dst_idx] + 1e-16)  # [E]
        alpha = F.dropout(alpha, p=self.dropout, training=self.training)

        # 4. Aggregate values
        z_val = self.W_val(x[src_idx])  # [E, out_dim]
        weighted_val = z_val * alpha.unsqueeze(-1)  # [E, out_dim]

        out = torch.zeros((num_nodes, self.out_dim), device=x.device, dtype=x.dtype)
        out.scatter_add_(0, dst_idx.unsqueeze(-1).expand(-1, self.out_dim), weighted_val)

        return out, alpha.unsqueeze(-1)


class GATEncoder(nn.Module):
    """
    Multi-head GAT graph encoder.
    Processes a single GraphWindow and outputs a fixed-dimension embedding.
    """
    def __init__(
        self,
        node_in_dim: int,
        edge_in_dim: int,
        hidden_dim: int,
        num_heads: int,
        output_dim: int,
        dropout: float = 0.0,
    ):
        super().__init__()
        
        if hidden_dim <= 0 or num_heads <= 0 or output_dim <= 0 or node_in_dim <= 0:
            raise ValueError("Dimensions and heads must be > 0.")
        if hidden_dim % num_heads != 0:
            raise ValueError("hidden_dim must be divisible by num_heads.")
        if not (0.0 <= dropout < 1.0):
            raise ValueError("dropout must be in [0, 1).")

        self.node_in_dim = node_in_dim
        self.edge_in_dim = edge_in_dim
        self.hidden_dim = hidden_dim
        self.num_heads = num_heads
        self.output_dim = output_dim
        
        head_dim = hidden_dim // num_heads

        # Multi-head attention layer
        self.heads = nn.ModuleList([
            GATLayer(node_in_dim, edge_in_dim, head_dim, dropout)
            for _ in range(num_heads)
        ])
        
        # Final projection to output_dim
        self.out_proj = nn.Linear(hidden_dim, output_dim)
        
        # Store latest attention weights for explainability
        self.latest_attention_weights: torch.Tensor | None = None

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_attr: torch.Tensor,
    ) -> torch.Tensor:
        """
        Forward pass for a single graph.
        Returns:
            graph_embedding: [output_dim] tensor.
        """
        num_nodes = x.size(0)

        # ---------------------------------------------------------
        # EXPLICIT EMPTY GRAPH POLICY
        # ---------------------------------------------------------
        # If the graph has 0 nodes, we do not perform matrix ops or
        # torch.mean (which would return NaN). Instead, we return a
        # zero tensor of shape [output_dim] and an empty attention
        # weight tensor [0, num_heads].
        if num_nodes == 0:
            self.latest_attention_weights = torch.empty(
                (0, self.num_heads), device=x.device, dtype=x.dtype
            )
            return torch.zeros(self.output_dim, device=x.device, dtype=x.dtype)

        # 1. Run all attention heads
        head_outs = []
        head_alphas = []
        for head in self.heads:
            out, alpha = head(x, edge_index, edge_attr)
            head_outs.append(out)
            head_alphas.append(alpha)

        # Concatenate head outputs: [N, head_dim] * heads -> [N, hidden_dim]
        node_embeds = torch.cat(head_outs, dim=-1)
        node_embeds = F.elu(node_embeds)
        
        # Save attention weights: [E, num_heads]
        if edge_index.size(1) > 0:
            self.latest_attention_weights = torch.cat(head_alphas, dim=-1)
        else:
            self.latest_attention_weights = torch.empty(
                (0, self.num_heads), device=x.device, dtype=x.dtype
            )

        # 2. Final projection: [N, hidden_dim] -> [N, output_dim]
        node_embeds = self.out_proj(node_embeds)

        # 3. Graph-Level Readout (Global Mean Pooling)
        # Note: Global mean pooling weights all nodes equally, regardless
        # of anomaly signal. This is a documented limitation of the current
        # architecture (an attention-based or sum-based readout might
        # better preserve localized anomaly spikes).
        graph_embedding = torch.mean(node_embeds, dim=0)  # [output_dim]

        return graph_embedding
