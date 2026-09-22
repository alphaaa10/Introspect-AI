"""
tests/test_gat.py

Tests for the GAT model and the GraphWindow -> tensor converter.
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.schemas import DataSource, GraphWindow, GraphNode, GraphEdge
from app.graph.builder import NODE_FEATURE_NAMES, EDGE_FEATURE_NAMES
from app.graph.converter import window_to_tensors
from app.models.gat import GATEncoder, set_seed


def _empty_gw() -> GraphWindow:
    return GraphWindow(
        window_id="w-empty",
        window_start=datetime(2023, 1, 1, tzinfo=timezone.utc),
        window_end=datetime(2023, 1, 1, tzinfo=timezone.utc),
        nodes=[],
        edges=[],
        num_nodes=0,
        num_edges=0,
        source=DataSource.MOCK,
    )


def _synthetic_gw() -> GraphWindow:
    """Returns a simple 3-node, 2-edge graph window."""
    n0 = GraphNode(node_index=0, ip="10.0.0.1", out_bytes=100, in_bytes=0, out_degree=1, in_degree=0, total_flows=1)
    n1 = GraphNode(node_index=1, ip="10.0.0.2", out_bytes=0, in_bytes=100, out_degree=0, in_degree=1, total_flows=1)
    n2 = GraphNode(node_index=2, ip="10.0.0.3", out_bytes=50, in_bytes=50, out_degree=1, in_degree=1, total_flows=2)
    
    e0 = GraphEdge(
        src_node_index=0, dst_node_index=1, src_ip="10.0.0.1", dst_ip="10.0.0.2",
        total_fwd_bytes=100, total_bwd_bytes=0, total_fwd_packets=2, total_bwd_packets=0,
        flow_count=1, mean_duration_s=1.0
    )
    e1 = GraphEdge(
        src_node_index=2, dst_node_index=1, src_ip="10.0.0.3", dst_ip="10.0.0.2",
        total_fwd_bytes=50, total_bwd_bytes=50, total_fwd_packets=1, total_bwd_packets=1,
        flow_count=1, mean_duration_s=0.5
    )

    return GraphWindow(
        window_id="w-001",
        window_start=datetime(2023, 1, 1, tzinfo=timezone.utc),
        window_end=datetime(2023, 1, 1, tzinfo=timezone.utc),
        nodes=[n0, n1, n2],
        edges=[e0, e1],
        num_nodes=3,
        num_edges=2,
        source=DataSource.MOCK,
    )


class TestConverter:
    def test_empty_graph_conversion(self):
        gw = _empty_gw()
        x, edge_index, edge_attr = window_to_tensors(gw)
        
        assert x.shape == (0, len(NODE_FEATURE_NAMES))
        assert edge_index.shape == (2, 0)
        assert edge_attr.shape == (0, len(EDGE_FEATURE_NAMES))

    def test_synthetic_graph_conversion(self):
        gw = _synthetic_gw()
        x, edge_index, edge_attr = window_to_tensors(gw)
        
        assert x.shape == (3, len(NODE_FEATURE_NAMES))
        assert edge_index.shape == (2, 2)
        assert edge_attr.shape == (2, len(EDGE_FEATURE_NAMES))
        
        # Check specific values based on names
        # out_bytes is index 0
        assert x[0, 0].item() == 100.0


class TestGATEncoder:
    def setup_method(self):
        self.node_dim = len(NODE_FEATURE_NAMES)
        self.edge_dim = len(EDGE_FEATURE_NAMES)

    def test_model_initialization_and_validation(self):
        # Valid init
        model = GATEncoder(
            node_in_dim=self.node_dim,
            edge_in_dim=self.edge_dim,
            hidden_dim=32,
            num_heads=4,
            output_dim=16,
            dropout=0.1
        )
        assert len(model.heads) == 4
        assert model.out_proj.out_features == 16

        # Invalid hidden_dim
        with pytest.raises(ValueError, match="divisible by num_heads"):
            GATEncoder(self.node_dim, self.edge_dim, hidden_dim=30, num_heads=4, output_dim=16)

        # Invalid dropout
        with pytest.raises(ValueError, match="dropout must be in"):
            GATEncoder(self.node_dim, self.edge_dim, hidden_dim=32, num_heads=4, output_dim=16, dropout=1.5)

        # Invalid dims
        with pytest.raises(ValueError, match="Dimensions and heads must be > 0"):
            GATEncoder(0, self.edge_dim, hidden_dim=32, num_heads=4, output_dim=16)

    def test_forward_pass_output_shape(self):
        """Regardless of node count, output is exactly [output_dim]. Single window per batch."""
        model = GATEncoder(self.node_dim, self.edge_dim, hidden_dim=32, num_heads=4, output_dim=16)
        model.eval()
        
        gw = _synthetic_gw()
        x, edge_index, edge_attr = window_to_tensors(gw)
        
        out = model(x, edge_index, edge_attr)
        assert out.shape == (32,)
        
        # Check attention weights
        attn = model.latest_attention_weights
        assert attn is not None
        assert attn.shape == (2, 4)  # [num_edges, num_heads]

    def test_empty_graph_policy(self):
        """Zero nodes should return a zero vector of [output_dim] without NaN/errors."""
        model = GATEncoder(self.node_dim, self.edge_dim, hidden_dim=32, num_heads=4, output_dim=16)
        model.eval()
        
        gw = _empty_gw()
        x, edge_index, edge_attr = window_to_tensors(gw)
        
        out = model(x, edge_index, edge_attr)
        assert out.shape == (32,)
        assert torch.all(out == 0.0)
        
        attn = model.latest_attention_weights
        assert attn is not None
        assert attn.shape == (0, 4)

    def test_determinism_identical_inputs(self):
        """Two identical forward passes with a seeded model in eval mode must be bit-identical."""
        gw = _synthetic_gw()
        x1, edge_index1, edge_attr1 = window_to_tensors(gw)
        x2, edge_index2, edge_attr2 = window_to_tensors(gw)
        
        # Pass 1
        set_seed(42)
        model1 = GATEncoder(self.node_dim, self.edge_dim, hidden_dim=32, num_heads=4, output_dim=16)
        model1.eval()
        out1 = model1(x1, edge_index1, edge_attr1)
        
        # Pass 2
        set_seed(42)
        model2 = GATEncoder(self.node_dim, self.edge_dim, hidden_dim=32, num_heads=4, output_dim=16)
        model2.eval()
        out2 = model2(x2, edge_index2, edge_attr2)
        
        # Assert exact equality
        assert torch.allclose(out1, out2, atol=1e-7, rtol=1e-5)
        
        attn1 = model1.latest_attention_weights
        attn2 = model2.latest_attention_weights
        assert torch.allclose(attn1, attn2, atol=1e-7, rtol=1e-5)
