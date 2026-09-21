"""
tests/test_world_model.py

Tests for the WorldModel, which orchestrates the GAT+LSTM pipeline and prediction heads.
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.schemas import DataSource, GraphWindow, GraphNode, GraphEdge, PredictionResult, MitreStage
from app.graph.builder import NODE_FEATURE_NAMES, EDGE_FEATURE_NAMES
from app.models.world_model import WorldModel, set_seed
from app import config


def _synthetic_gw(window_id: str) -> GraphWindow:
    """Returns a simple 2-node, 1-edge graph window."""
    n0 = GraphNode(node_index=0, ip="10.0.0.1", out_bytes=100, in_bytes=0, out_degree=1, in_degree=0, total_flows=1)
    n1 = GraphNode(node_index=1, ip="10.0.0.2", out_bytes=0, in_bytes=100, out_degree=0, in_degree=1, total_flows=1)
    
    e0 = GraphEdge(
        src_node_index=0, dst_node_index=1, src_ip="10.0.0.1", dst_ip="10.0.0.2",
        total_fwd_bytes=100, total_bwd_bytes=0, total_fwd_packets=2, total_bwd_packets=0,
        flow_count=1, mean_duration_s=1.0
    )

    return GraphWindow(
        window_id=window_id,
        window_start=datetime(2023, 1, 1, tzinfo=timezone.utc),
        window_end=datetime(2023, 1, 1, tzinfo=timezone.utc),
        nodes=[n0, n1],
        edges=[e0],
        num_nodes=2,
        num_edges=1,
        source=DataSource.MOCK,
    )


class TestWorldModel:
    def setup_method(self):
        self.node_dim = len(NODE_FEATURE_NAMES)
        self.edge_dim = len(EDGE_FEATURE_NAMES)
        self.num_mitre = config.NUM_MITRE_STAGES  # 8 — exact count of MitreStage enum values
        
        self.valid_args = dict(
            node_in_dim=self.node_dim,
            edge_in_dim=self.edge_dim,
            gat_hidden_dim=16,
            gat_num_heads=2,
            gat_out_dim=8,
            gat_dropout=0.0,
            lstm_hidden_dim=32,
            lstm_num_layers=1,
            lstm_dropout=0.0,
            num_mitre_stages=self.num_mitre,
        )

    def test_model_initialization_and_validation(self):
        # Valid init
        model = WorldModel(**self.valid_args)
        assert model.attack_head.out_features == 1
        assert model.mitre_head.out_features == self.num_mitre
        
        # Invalid dimensions pass down to submodules which raise ValueError
        invalid_args = self.valid_args.copy()
        invalid_args["gat_hidden_dim"] = -5
        
        with pytest.raises(ValueError):
            WorldModel(**invalid_args)

    def test_forward_pass_multi_window(self):
        """Test full pipeline on a sequence of length 2."""
        model = WorldModel(**self.valid_args)
        model.eval()
        
        gw1 = _synthetic_gw("w-1")
        gw2 = _synthetic_gw("w-2")
        
        result = model([gw1, gw2])
        
        assert isinstance(result, PredictionResult)
        assert result.window_id == "w-2"
        assert 0.0 <= result.attack_probability <= 1.0
        assert len(result.stage_probabilities) == self.num_mitre
        assert abs(sum(result.stage_probabilities) - 1.0) < 1e-5
        
        # Verify predicted_stage is exactly list(MitreStage)[argmax] of stage_probabilities
        expected_idx = result.stage_probabilities.index(max(result.stage_probabilities))
        assert result.predicted_stage == list(MitreStage)[expected_idx]
        
        # Embedding length should match lstm_hidden_dim
        assert len(result.embedding) == 32
        
        # Attention weights should be propagated (1 edge, 2 heads = 2 weights)
        assert len(result.attention_weights) == 2

    def test_forward_pass_single_window(self):
        """Test pipeline handles sequence length of 1 seamlessly."""
        model = WorldModel(**self.valid_args)
        model.eval()
        
        gw1 = _synthetic_gw("w-1")
        result = model([gw1])
        
        assert isinstance(result, PredictionResult)
        assert len(result.embedding) == 32

    def test_batching_not_supported(self):
        """Batching multiple sequences (list of lists) is rejected."""
        model = WorldModel(**self.valid_args)
        gw1 = _synthetic_gw("w-1")
        
        # A list of lists of GraphWindows should crash cleanly before tensor ops
        with pytest.raises((TypeError, AttributeError)):
            model([[gw1]])

    def test_empty_sequence_rejected(self):
        model = WorldModel(**self.valid_args)
        with pytest.raises(ValueError, match="Input sequence cannot be empty"):
            model([])

    def test_deterministic_inference(self):
        """Bit-identical predictions on identical inputs with fixed seed in eval mode."""
        gw1 = _synthetic_gw("w-1")
        gw2 = _synthetic_gw("w-2")
        sequence = [gw1, gw2]
        
        set_seed(42)
        model1 = WorldModel(**self.valid_args)
        model1.eval()
        result1 = model1(sequence)
        
        set_seed(42)
        model2 = WorldModel(**self.valid_args)
        model2.eval()
        result2 = model2(sequence)
        
        assert result1.attack_probability == result2.attack_probability
        assert result1.stage_probabilities == result2.stage_probabilities
        assert result1.embedding == result2.embedding
        assert result1.attention_weights == result2.attention_weights

    def test_predicted_stage_follows_argmax(self):
        """predicted_stage must equal list(MitreStage)[argmax(stage_probs)], never always BENIGN."""
        model = WorldModel(**self.valid_args)
        model.eval()
        gw1 = _synthetic_gw("w-1")
        result = model([gw1])

        # Derive expected stage independently from the returned probabilities
        all_stages = list(MitreStage)
        expected_idx = result.stage_probabilities.index(max(result.stage_probabilities))
        assert result.predicted_stage == all_stages[expected_idx], (
            f"predicted_stage={result.predicted_stage!r} does not match "
            f"list(MitreStage)[{expected_idx}]={all_stages[expected_idx]!r}"
        )

        # Confirm not always BENIGN: sweep 10 seeds — at least one non-BENIGN is expected
        # from random weights over 8 classes.
        any_non_benign = False
        for seed_val in range(10):
            set_seed(seed_val)
            m = WorldModel(**self.valid_args)
            m.eval()
            r = m([gw1])
            if r.predicted_stage != MitreStage.BENIGN:
                any_non_benign = True
                break
        assert any_non_benign, (
            "predicted_stage was BENIGN for all 10 seeds — "
            "this strongly suggests the stage lookup bug is still present."
        )

    def test_out_of_range_stage_index_raises(self):
        """A WorldModel with num_mitre_stages > len(MitreStage) will produce an argmax
        index >= len(MitreStage), which must raise a clear ValueError, not silently return BENIGN."""
        # Build a model where the head has more outputs than the enum has members.
        # With 20 output logits, argmax could be >= 8 (len(MitreStage)), triggering the guard.
        bad_args = self.valid_args.copy()
        bad_args["num_mitre_stages"] = 20  # more stages than MitreStage enum has
        model = WorldModel(**bad_args)
        model.eval()
        gw1 = _synthetic_gw("w-1")

        # Run enough seeds until argmax lands outside [0, 8) — which must happen eventually
        # with 20 outputs and random weights.
        raised = False
        for seed_val in range(50):
            set_seed(seed_val)
            m = WorldModel(**bad_args)
            m.eval()
            try:
                m([gw1])
            except ValueError as exc:
                assert "out of range for MitreStage" in str(exc), (
                    f"Unexpected ValueError message: {exc}"
                )
                raised = True
                break
        assert raised, (
            "Expected a ValueError for out-of-range stage index but none was raised "
            "across 50 seeds with num_mitre_stages=20."
        )
