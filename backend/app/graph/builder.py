"""
graph/builder.py  Sentinel graph construction layer.

Converts a time-windowed set of NetworkEvent records into a deterministic
GraphWindow (pure Python/Pydantic representation). Does not perform any
tensor operations or ML. PyG conversion is deferred to a later phase.

Public API
----------
build_graph(events, window_id, window_start, window_end, source) -> GraphWindow
    Constructs a graph from the events in this window.

Design Policy & Known Limitations
---------------------------------
1. Empty windows:
   A window with 0 events produces a valid GraphWindow with 0 nodes and 0 edges.
2. Isolated hosts:
   A host involved in only a single, one-way event is still represented as
   a node (degree 1).
3. All events are placed:
   No NetworkEvent is silently discarded. Every event contributes to exactly
   one GraphEdge and updates the node features for its src_ip and dst_ip.
4. Self-loop policy:
   If event.src_ip == event.dst_ip, it produces a self-loop GraphEdge.
   The node's `total_flows` increments by 1. Its `out_bytes` and `in_bytes`
   are BOTH incremented by event.fwd_bytes. Its `out_degree` and `in_degree`
   DO account for this connection (i.e. if the only connection is a self-loop,
   both degrees are 1).
5. Known Modeling Limitation (bwd_bytes exclusion):
   Node-level `out_bytes` and `in_bytes` are computed EXCLUSIVELY from the
   fwd_bytes of the flows where the node is the src or dst, respectively.
   Traffic returned FROM dst TO src (bwd_bytes) is not added to the node
   totals to avoid double-counting, since we don't know the breakdown of
   who sent what portion. This means node-level totals do NOT capture response
   traffic on flows a host receives, potentially understating volume for
   hosts that primarily respond with large payloads.

PyG Mapping Contract
--------------------
When converted to a PyG Data object later:
- `x` (node features) [N, 5]:
  NODE_FEATURE_NAMES = ["out_bytes", "in_bytes", "out_degree", "in_degree", "total_flows"]
- `edge_index` [2, E]:
  [ [edge.src_node_index, ...], [edge.dst_node_index, ...] ]
- `edge_attr` (edge features) [E, 6]:
  EDGE_FEATURE_NAMES = ["total_fwd_bytes", "total_bwd_bytes", "total_fwd_packets",
                        "total_bwd_packets", "flow_count", "mean_duration_s"]
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from app.schemas import DataSource, NetworkEvent, GraphNode, GraphEdge, GraphWindow


NODE_FEATURE_NAMES = [
    "out_bytes",
    "in_bytes",
    "out_degree",
    "in_degree",
    "total_flows",
]

EDGE_FEATURE_NAMES = [
    "total_fwd_bytes",
    "total_bwd_bytes",
    "total_fwd_packets",
    "total_bwd_packets",
    "flow_count",
    "mean_duration_s",
]


_NODE_SCALE_BOUNDS: dict[str, tuple[float, float]] = {
    "out_bytes":   (0.0, 1e8),      # 100 MB per window
    "in_bytes":    (0.0, 1e8),      
    "out_degree":  (0.0, 1024.0),   # aggressive scan ceiling
    "in_degree":   (0.0, 1024.0),
    "total_flows": (0.0, 10_000.0), # flood ceiling
}

_EDGE_SCALE_BOUNDS: dict[str, tuple[float, float]] = {
    "total_fwd_bytes":   (0.0, 1e8),
    "total_bwd_bytes":   (0.0, 1e8),
    "total_fwd_packets": (0.0, 100_000.0),
    "total_bwd_packets": (0.0, 100_000.0),
    "flow_count":        (0.0, 10_000.0),
    "mean_duration_s":   (0.0, 600.0),
}

def _scale(value: float, feature_name: str, bounds_dict: dict) -> float:
    lo, hi = bounds_dict[feature_name]
    clipped = max(lo, min(value, hi))
    return clipped / hi

class _NodeBuilder:
    def __init__(self, ip: str) -> None:
        self.ip = ip
        self.out_bytes = 0
        self.in_bytes = 0
        self.total_flows = 0
        self.dst_ips: set[str] = set()
        self.src_ips: set[str] = set()

    def add_as_src(self, event: NetworkEvent) -> None:
        self.out_bytes += event.fwd_bytes
        self.total_flows += 1
        self.dst_ips.add(event.dst_ip)
        # Note: If self-loop (src == dst), add_as_dst will NOT be called
        # for this same flow if we process it from the event perspective,
        # so we must handle self-loops specially below.

    def add_as_dst(self, event: NetworkEvent) -> None:
        self.in_bytes += event.fwd_bytes
        self.total_flows += 1
        self.src_ips.add(event.src_ip)

    def add_self_loop(self, event: NetworkEvent) -> None:
        # A single event where src_ip == dst_ip
        self.out_bytes += event.fwd_bytes
        self.in_bytes += event.fwd_bytes
        self.total_flows += 1
        self.dst_ips.add(self.ip)
        self.src_ips.add(self.ip)

    def build(self, index: int) -> GraphNode:
        return GraphNode(
            node_index=index,
            ip=self.ip,
            out_bytes=_scale(float(self.out_bytes), "out_bytes", _NODE_SCALE_BOUNDS),
            in_bytes=_scale(float(self.in_bytes), "in_bytes", _NODE_SCALE_BOUNDS),
            out_degree=_scale(float(len(self.dst_ips)), "out_degree", _NODE_SCALE_BOUNDS),
            in_degree=_scale(float(len(self.src_ips)), "in_degree", _NODE_SCALE_BOUNDS),
            total_flows=_scale(float(self.total_flows), "total_flows", _NODE_SCALE_BOUNDS),
        )


class _EdgeBuilder:
    def __init__(self, src_ip: str, dst_ip: str) -> None:
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.total_fwd_bytes = 0
        self.total_bwd_bytes = 0
        self.total_fwd_packets = 0
        self.total_bwd_packets = 0
        self.flow_count = 0
        self.total_duration_s = 0.0

    def add_flow(self, event: NetworkEvent) -> None:
        self.total_fwd_bytes += event.fwd_bytes
        self.total_bwd_bytes += event.bwd_bytes
        self.total_fwd_packets += event.fwd_packets
        self.total_bwd_packets += event.bwd_packets
        self.flow_count += 1
        self.total_duration_s += event.duration_s

    def build(self, src_idx: int, dst_idx: int) -> GraphEdge:
        mean_dur = self.total_duration_s / self.flow_count if self.flow_count > 0 else 0.0
        return GraphEdge(
            src_node_index=src_idx,
            dst_node_index=dst_idx,
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            total_fwd_bytes=_scale(float(self.total_fwd_bytes), "total_fwd_bytes", _EDGE_SCALE_BOUNDS),
            total_bwd_bytes=_scale(float(self.total_bwd_bytes), "total_bwd_bytes", _EDGE_SCALE_BOUNDS),
            total_fwd_packets=_scale(float(self.total_fwd_packets), "total_fwd_packets", _EDGE_SCALE_BOUNDS),
            total_bwd_packets=_scale(float(self.total_bwd_packets), "total_bwd_packets", _EDGE_SCALE_BOUNDS),
            flow_count=_scale(float(self.flow_count), "flow_count", _EDGE_SCALE_BOUNDS),
            mean_duration_s=_scale(float(mean_dur), "mean_duration_s", _EDGE_SCALE_BOUNDS),
        )


def build_graph(
    events: list[NetworkEvent],
    window_id: str,
    window_start: datetime,
    window_end: datetime,
    source: DataSource = DataSource.REAL,
) -> GraphWindow:
    """Convert a window's NetworkEvents into a deterministic GraphWindow.

    Node IP ordering is lexicographic.
    Edge ordering is lexicographic by (src_node_index, dst_node_index).
    """
    if not events:
        return GraphWindow(
            window_id=window_id,
            window_start=window_start,
            window_end=window_end,
            nodes=[],
            edges=[],
            num_nodes=0,
            num_edges=0,
            source=source,
        )

    # 1. Aggregate data per node IP and per edge pair
    node_builders: dict[str, _NodeBuilder] = {}
    edge_builders: dict[tuple[str, str], _EdgeBuilder] = {}

    for event in events:
        s_ip = event.src_ip
        d_ip = event.dst_ip

        if s_ip not in node_builders:
            node_builders[s_ip] = _NodeBuilder(s_ip)
        if d_ip not in node_builders:
            node_builders[d_ip] = _NodeBuilder(d_ip)

        if s_ip == d_ip:
            node_builders[s_ip].add_self_loop(event)
        else:
            node_builders[s_ip].add_as_src(event)
            node_builders[d_ip].add_as_dst(event)

        pair = (s_ip, d_ip)
        if pair not in edge_builders:
            edge_builders[pair] = _EdgeBuilder(s_ip, d_ip)
        edge_builders[pair].add_flow(event)

    # 2. Assign deterministic node indices by sorting IP strings
    # This is confirmed intentional: lexicographic sorting provides a stable,
    # deterministic order for matrix row assignments.
    sorted_ips = sorted(node_builders.keys())
    ip_to_idx: dict[str, int] = {ip: idx for idx, ip in enumerate(sorted_ips)}

    nodes: list[GraphNode] = [
        node_builders[ip].build(ip_to_idx[ip])
        for ip in sorted_ips
    ]

    # 3. Build edges and sort them deterministically
    edges: list[GraphEdge] = []
    for (s_ip, d_ip), eb in edge_builders.items():
        edges.append(eb.build(ip_to_idx[s_ip], ip_to_idx[d_ip]))

    edges.sort(key=lambda e: (e.src_node_index, e.dst_node_index))

    return GraphWindow(
        window_id=window_id,
        window_start=window_start,
        window_end=window_end,
        nodes=nodes,
        edges=edges,
        num_nodes=len(nodes),
        num_edges=len(edges),
        source=source,
    )
