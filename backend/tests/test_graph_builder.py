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
from app.graph.builder import build_graph, _NODE_SCALE_BOUNDS, _EDGE_SCALE_BOUNDS

def sn(val, name):
    return pytest.approx(val / _NODE_SCALE_BOUNDS[name][1])

def se(val, name):
    return pytest.approx(val / _EDGE_SCALE_BOUNDS[name][1])


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
        assert gw.nodes[0].out_degree == sn(1, "out_degree")
        assert gw.nodes[0].in_degree == sn(0, "in_degree")
        assert gw.nodes[2].out_degree == sn(0, "out_degree")
        assert gw.nodes[2].in_degree == sn(1, "in_degree")

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
        assert edge.flow_count == se(3, "flow_count")
        assert edge.total_fwd_bytes == se(600, "total_fwd_bytes")
        assert edge.total_bwd_bytes == se(60, "total_bwd_bytes")
        assert edge.total_fwd_packets == se(12, "total_fwd_packets")
        assert edge.total_bwd_packets == se(1, "total_bwd_packets")
        assert edge.mean_duration_s == se(2.0, "mean_duration_s")

        # Node features
        n_src = gw.nodes[0]
        assert n_src.out_bytes == sn(600, "out_bytes")
        assert n_src.in_bytes == sn(0, "in_bytes")
        assert n_src.total_flows == sn(3, "total_flows")
        assert n_src.out_degree == sn(1, "out_degree")

        n_dst = gw.nodes[1]
        assert n_dst.in_bytes == sn(600, "in_bytes")
        assert n_dst.out_bytes == sn(0, "out_bytes")
        assert n_dst.total_flows == sn(3, "total_flows")
        assert n_dst.in_degree == sn(1, "in_degree")

    def test_self_loop_policy(self):
        # A single event where src == dst
        events = [_event("10.0.0.1", "10.0.0.1", fwd_bytes=500)]
        gw = build_graph(events, "w-001", _W_START, _W_END, DataSource.MOCK)

        assert gw.num_nodes == 1
        assert gw.num_edges == 1
        
        node = gw.nodes[0]
        assert node.out_degree == sn(1, "out_degree")
        assert node.in_degree == sn(1, "in_degree")
        assert node.total_flows == sn(1, "total_flows")
        assert node.out_bytes == sn(500, "out_bytes")
        assert node.in_bytes == sn(500, "in_bytes")

        edge = gw.edges[0]
        assert edge.src_node_index == 0
        assert edge.dst_node_index == 0
        assert edge.flow_count == se(1, "flow_count")

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
        
        assert nodeA.out_bytes == sn(30, "out_bytes")   # 10 + 20
        assert nodeA.in_bytes == sn(0, "in_bytes")
        assert nodeA.total_flows == sn(2, "total_flows")
        assert nodeA.out_degree == sn(2, "out_degree")
        assert nodeA.in_degree == sn(0, "in_degree")

        assert nodeB.out_bytes == sn(30, "out_bytes")   # 30
        assert nodeB.in_bytes == sn(10, "in_bytes")    # 10 from A
        assert nodeB.total_flows == sn(2, "total_flows")
        assert nodeB.out_degree == sn(1, "out_degree")
        assert nodeB.in_degree == sn(1, "in_degree")

        assert nodeC.out_bytes == sn(0, "out_bytes")
        assert nodeC.in_bytes == sn(50, "in_bytes")    # 20 from A, 30 from B
        assert nodeC.total_flows == sn(2, "total_flows")
        assert nodeC.out_degree == sn(0, "out_degree")
        assert nodeC.in_degree == sn(2, "in_degree")
