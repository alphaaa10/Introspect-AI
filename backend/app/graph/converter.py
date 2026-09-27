"""
graph/converter.py

Converts a pure Pydantic GraphWindow into PyTorch tensors for GAT.
Separating this from builder.py ensures that builder.py remains purely
about parsing and aggregating raw events, while converter.py handles
tensorization.
"""

from __future__ import annotations

import torch

from app.schemas import GraphWindow
from app.graph.builder import NODE_FEATURE_NAMES, EDGE_FEATURE_NAMES


def window_features_to_tensor(
    gw: GraphWindow,
    expected_dim: int,
    dtype: torch.dtype = torch.float32,
    device: torch.device | str = "cpu",
) -> torch.Tensor:
    """Return the window's 21-dim extractor feature vector as a [expected_dim] tensor.

    These are the features config.FEATURE_NAMES describes — flag counts,
    unique_dst_ports, IAT statistics, packets/sec — which the graph's 5 node and
    6 edge features do not capture. They were computed by the extractor and then
    dropped on the floor before this was wired up.

    A window with no features attached yields zeros, so a model configured for
    fusion still runs on graph-only windows (the API's inference path) instead
    of raising a shape error.
    """
    feats = gw.window_features
    if not feats:
        return torch.zeros(expected_dim, dtype=dtype, device=device)
    if len(feats) != expected_dim:
        raise ValueError(
            f"window_features has length {len(feats)} but the model expects "
            f"{expected_dim}. These must agree with config.NUM_FEATURES."
        )
    return torch.tensor(feats, dtype=dtype, device=device)


def window_to_tensors(
    gw: GraphWindow,
    dtype: torch.dtype = torch.float32,
    device: torch.device | str = "cpu",
) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
    """Convert a GraphWindow to PyTorch tensors.

    Parameters
    ----------
    gw : GraphWindow
        The input graph window.
    dtype : torch.dtype
        The float dtype for feature tensors (default float32).
    device : torch.device | str
        The device to place tensors on (default "cpu").

    Returns
    -------
    x : torch.Tensor
        Node features, shape [num_nodes, len(NODE_FEATURE_NAMES)].
    edge_index : torch.Tensor
        Edge indices, shape [2, num_edges], dtype torch.long.
    edge_attr : torch.Tensor
        Edge features, shape [num_edges, len(EDGE_FEATURE_NAMES)].

    Empty Graph Policy
    ------------------
    If num_nodes == 0, returns empty tensors of the correct rank:
    - x: shape [0, len(NODE_FEATURE_NAMES)]
    - edge_index: shape [2, 0]
    - edge_attr: shape [0, len(EDGE_FEATURE_NAMES)]
    """
    num_nodes = gw.num_nodes
    num_edges = gw.num_edges

    num_node_feats = len(NODE_FEATURE_NAMES)
    num_edge_feats = len(EDGE_FEATURE_NAMES)

    if num_nodes == 0:
        x = torch.empty((0, num_node_feats), dtype=dtype, device=device)
        edge_index = torch.empty((2, 0), dtype=torch.long, device=device)
        edge_attr = torch.empty((0, num_edge_feats), dtype=dtype, device=device)
        return x, edge_index, edge_attr

    # 1. Build node feature matrix `x`
    x_list = []
    # Assumes nodes are strictly in `node_index` order (0 to N-1).
    # builder.py guarantees they are inserted in index order.
    for node in gw.nodes:
        feats = [getattr(node, fname) for fname in NODE_FEATURE_NAMES]
        x_list.append(feats)
    
    x = torch.tensor(x_list, dtype=dtype, device=device)

    if num_edges == 0:
        edge_index = torch.empty((2, 0), dtype=torch.long, device=device)
        edge_attr = torch.empty((0, num_edge_feats), dtype=dtype, device=device)
        return x, edge_index, edge_attr

    # 2. Build `edge_index` and `edge_attr`
    src_list = []
    dst_list = []
    attr_list = []

    for edge in gw.edges:
        src_list.append(edge.src_node_index)
        dst_list.append(edge.dst_node_index)
        
        feats = [getattr(edge, fname) for fname in EDGE_FEATURE_NAMES]
        attr_list.append(feats)

    edge_index = torch.tensor([src_list, dst_list], dtype=torch.long, device=device)
    edge_attr = torch.tensor(attr_list, dtype=dtype, device=device)

    return x, edge_index, edge_attr
