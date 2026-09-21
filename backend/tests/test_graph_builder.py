"""
tests/test_graph_builder.py

Tests for backend/app/graph/builder.py
"""

import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.schemas import DataSource, NetworkEvent, Protocol
from app.graph.builder import build_graph


_T0 = datetime(2018, 2, 14, 10, 0, 0, tzinfo=timezone.utc)
_W_START = _T0
_W_END = _T0 + timedelta(seconds=60)


def _event(
    src_ip: str,
    dst_ip: str,
    fwd_bytes: int = 100,
    bwd_bytes: int = 50,
    fwd_packets: int = 10,
    bwd_packets: int = 5,
    duration_s: float = 2.0,
) -> NetworkEvent:
    return NetworkEvent(
        flow_id="f-mock",
        timestamp=_T0,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=12345,
        dst_port=80,
        protocol=Protocol.TCP,
        fwd_packets=fwd_packets,
        bwd_packets=bwd_packets,
        fwd_bytes=fwd_bytes,
        bwd_bytes=bwd_bytes,
        tcp_flags="ACK",
        duration_s=duration_s,
        source=DataSource.MOCK,
    )


class TestGraphBuilder:
    def test_empty_window(self):
        gw = build_graph([], "w-000", _W_START, _W_END, DataSource.MOCK)
        assert gw.num_nodes == 0
        assert gw.num_edges == 0
        assert len(gw.nodes) == 0
        assert len(gw.edges) == 0
        assert gw.window_id == "w-000"
        assert gw.window_start == _W_START
        assert gw.window_end == _W_END

    def test_simple_3_host_graph_and_isolated_host(self):
        # A -> B
        # B -> C
        events = [
            _event("10.0.0.1", "10.0.0.2"),
            _event("10.0.0.2", "10.0.0.3"),
        ]
        gw = build_graph(events, "w-001", _W_START, _W_END, DataSource.MOCK)

        assert gw.num_nodes == 3
        assert gw.num_edges == 2
        
        # Lexicographic sort: .1 -> idx 0, .2 -> idx 1, .3 -> idx 2
        assert gw.nodes[0].ip == "10.0.0.1"
        assert gw.nodes[1].ip == "10.0.0.2"
        assert gw.nodes[2].ip == "10.0.0.3"

        # Check edges (sorted by src_idx, dst_idx)
        # Edge 0: 0 -> 1
        assert gw.edges[0].src_ip == "10.0.0.1"
        assert gw.edges[0].dst_ip == "10.0.0.2"
        # Edge 1: 1 -> 2
        assert gw.edges[1].src_ip == "10.0.0.2"
        assert gw.edges[1].dst_ip == "10.0.0.3"

        # Host 10.0.0.1 is isolated in terms of incoming traffic (degree 1 out, 0 in)
        # Host 10.0.0.3 is isolated in terms of outgoing traffic (degree 0 out, 1 in)
        assert gw.nodes[0].out_degree == 1
        assert gw.nodes[0].in_degree == 0
        assert gw.nodes[2].out_degree == 0
        assert gw.nodes[2].in_degree == 1

    def test_repeated_edge_aggregation(self):
        # 3 events between same (src, dst) pair
        events = [
            _event("10.0.0.1", "10.0.0.2", fwd_bytes=100, bwd_bytes=50, fwd_packets=2, bwd_packets=1, duration_s=1.0),
            _event("10.0.0.1", "10.0.0.2", fwd_bytes=200, bwd_bytes=10, fwd_packets=4, bwd_packets=0, duration_s=2.0),
            _event("10.0.0.1", "10.0.0.2", fwd_bytes=300, bwd_bytes=0,  fwd_packets=6, bwd_packets=0, duration_s=3.0),
        ]
        gw = build_graph(events, "w-001", _W_START, _W_END, DataSource.MOCK)

        # Should produce exactly 2 nodes and 1 edge
        assert gw.num_nodes == 2
        assert gw.num_edges == 1
        
        edge = gw.edges[0]
        assert edge.flow_count == 3
        assert edge.total_fwd_bytes == 600
        assert edge.total_bwd_bytes == 60
        assert edge.total_fwd_packets == 12
        assert edge.total_bwd_packets == 1
        assert edge.mean_duration_s == 2.0  # (1+2+3)/3

        # Node features
        n_src = gw.nodes[0]
        assert n_src.out_bytes == 600
        assert n_src.in_bytes == 0
        assert n_src.total_flows == 3
        assert n_src.out_degree == 1

        n_dst = gw.nodes[1]
        assert n_dst.in_bytes == 600
        assert n_dst.out_bytes == 0
        assert n_dst.total_flows == 3
        assert n_dst.in_degree == 1

    def test_self_loop_policy(self):
        # A single event where src == dst
        events = [_event("10.0.0.1", "10.0.0.1", fwd_bytes=500)]
        gw = build_graph(events, "w-001", _W_START, _W_END, DataSource.MOCK)

        assert gw.num_nodes == 1
        assert gw.num_edges == 1
        
        node = gw.nodes[0]
        assert node.out_degree == 1
        assert node.in_degree == 1
        assert node.total_flows == 1
        assert node.out_bytes == 500
        assert node.in_bytes == 500

        edge = gw.edges[0]
        assert edge.src_node_index == 0
        assert edge.dst_node_index == 0
        assert edge.flow_count == 1

    def test_multiple_windows_independence(self):
        ev1 = [_event("10.0.0.1", "10.0.0.2")]
        ev2 = [_event("192.168.1.1", "192.168.1.2")]
        
        gw1 = build_graph(ev1, "w-1", _W_START, _W_END, DataSource.MOCK)
        gw2 = build_graph(ev2, "w-2", _W_START, _W_END, DataSource.MOCK)

        assert gw1.nodes[0].ip == "10.0.0.1"
        assert gw2.nodes[0].ip == "192.168.1.1"
        assert gw1.window_id == "w-1"
        assert gw2.window_id == "w-2"

    def test_deterministic_construction(self):
        events = [
            _event("10.0.0.2", "10.0.0.3"),
            _event("10.0.0.1", "10.0.0.2"),
        ]
        gw1 = build_graph(events, "w-001", _W_START, _W_END, DataSource.MOCK)
        gw2 = build_graph(events, "w-001", _W_START, _W_END, DataSource.MOCK)
        
        # Test exact match of all output lists
        assert gw1.model_dump() == gw2.model_dump()

    def test_node_edge_feature_dimensions(self):
        # Specific hand-computed synthetic window to check exact expected fields and values
        events = [
            _event("A", "B", fwd_bytes=10, bwd_bytes=5),
            _event("A", "C", fwd_bytes=20, bwd_bytes=2),
            _event("B", "C", fwd_bytes=30, bwd_bytes=0),
        ]
        gw = build_graph(events, "w-001", _W_START, _W_END, DataSource.MOCK)
        
        # Nodes: A(0), B(1), C(2) due to lexicographic
        nodeA = gw.nodes[0]
        nodeB = gw.nodes[1]
        nodeC = gw.nodes[2]
        
        assert nodeA.out_bytes == 30   # 10 + 20
        assert nodeA.in_bytes == 0
        assert nodeA.total_flows == 2
        assert nodeA.out_degree == 2
        assert nodeA.in_degree == 0

        assert nodeB.out_bytes == 30   # 30
        assert nodeB.in_bytes == 10    # 10 from A
        assert nodeB.total_flows == 2
        assert nodeB.out_degree == 1
        assert nodeB.in_degree == 1

        assert nodeC.out_bytes == 0
        assert nodeC.in_bytes == 50    # 20 from A, 30 from B
        assert nodeC.total_flows == 2
        assert nodeC.out_degree == 0
        assert nodeC.in_degree == 2
