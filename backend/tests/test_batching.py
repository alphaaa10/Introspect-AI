"""
tests/test_batching.py

Equivalence tests for the batched training path.

These guard against bugs that do not raise. A leaky batch, a padding-contaminated
LSTM state or a mis-normalised loss all still produce numbers; they are just the
wrong numbers, and they look like "the model got worse" rather than "the code is
broken". Each test therefore compares the batched path against the unbatched one
that is already known-good, rather than against a hand-computed constant.

Phase 1 covers Tests 1, 3, 4, 6 and 9. Tests 2, 5, 7 and 8 belong to the
training-loop work and are marked skipped with the reason, so the file's
numbering stays aligned with the specification.
"""

import sys
from pathlib import Path

import pytest
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import config
from app.schemas import DataSource, GraphNode, GraphEdge, GraphWindow, MitreStage
from app.graph.builder import NODE_FEATURE_NAMES, EDGE_FEATURE_NAMES
from app.models.seeding import set_seed
from app.models.world_model import WorldModel
from train import collate_sequences

from datetime import datetime, timezone

_T = datetime(2017, 7, 7, 9, 0, 0, tzinfo=timezone.utc)
DEV = torch.device("cpu")

MODEL_ARGS = dict(
    node_in_dim=len(NODE_FEATURE_NAMES),
    edge_in_dim=len(EDGE_FEATURE_NAMES),
    gat_hidden_dim=32,
    gat_num_heads=4,
    gat_out_dim=16,
    gat_dropout=0.0,      # dropout off: equivalence must be deterministic
    lstm_hidden_dim=24,
    lstm_num_layers=2,
    lstm_dropout=0.0,
    num_mitre_stages=config.NUM_MITRE_STAGES,
    window_feat_dim=config.NUM_FEATURES,
)


def make_window(wid, n_nodes=6, n_edges=8, feat_base=0.3, seed=0):
    """A GraphWindow with deterministic, distinguishable feature values."""
    g = torch.Generator().manual_seed(seed)
    def r():
        return float(torch.rand(1, generator=g).item()) * 0.5 + feat_base
    nodes = [
        GraphNode(node_index=i, ip=f"10.0.{i // 256}.{i % 256}",
                  out_bytes=r(), in_bytes=r(), out_degree=r(),
                  in_degree=r(), total_flows=r())
        for i in range(n_nodes)
    ]
    edges = [
        GraphEdge(src_node_index=i % max(n_nodes, 1), dst_node_index=(i + 1) % max(n_nodes, 1),
                  src_ip="a", dst_ip="b",
                  total_fwd_bytes=r(), total_bwd_bytes=r(), total_fwd_packets=r(),
                  total_bwd_packets=r(), flow_count=r(), mean_duration_s=r())
        for i in range(n_edges if n_nodes else 0)
    ]
    return GraphWindow(
        window_id=wid, window_start=_T, window_end=_T,
        nodes=nodes, edges=edges, num_nodes=len(nodes), num_edges=len(edges),
        source=DataSource.REAL,
        window_features=[feat_base + 0.01 * k for k in range(config.NUM_FEATURES)],
    )


def fresh_model():
    set_seed(1234)
    m = WorldModel(**MODEL_ARGS)
    m.eval()
    return m


# ══════════════════════════════════════════════════════════════
# Test 1 — batch_size=1 equals the unbatched path
# ══════════════════════════════════════════════════════════════

class TestOneBatchEqualsUnbatched:
    def test_logits_match_at_batch_size_one(self):
        model = fresh_model()
        seq = [make_window(f"w-{i}", seed=i) for i in range(5)]
        target = (1, 7)

        with torch.no_grad():
            a_un, m_un = model.logits(seq)
            collated = collate_sequences([(seq, target)], DEV)
            a_b, m_b = model.logits_batch(collated)

        assert a_b.shape == (1, 1)
        assert m_b.shape == (1, config.NUM_MITRE_STAGES)
        assert torch.allclose(a_un.reshape(-1), a_b.reshape(-1), atol=1e-5), \
            f"attack logits differ by {(a_un.reshape(-1) - a_b.reshape(-1)).abs().max():.3e}"
        assert torch.allclose(m_un.reshape(-1), m_b.reshape(-1), atol=1e-5), \
            f"mitre logits differ by {(m_un.reshape(-1) - m_b.reshape(-1)).abs().max():.3e}"

    def test_forward_is_unchanged_by_the_batching_work(self):
        """WorldModel.forward must still be the single-sequence inference path."""
        model = fresh_model()
        seq = [make_window(f"w-{i}", seed=i) for i in range(4)]
        with torch.no_grad():
            res = model(seq)
        assert 0.0 <= res.attack_probability <= 1.0
        assert len(res.stage_probabilities) == config.NUM_MITRE_STAGES
        assert res.predicted_stage in list(MitreStage)
        assert len(res.embedding) == MODEL_ARGS["lstm_hidden_dim"]

    @pytest.mark.parametrize("seq_len", [1, 2, 7, 20])
    def test_equivalence_holds_across_sequence_lengths(self, seq_len):
        model = fresh_model()
        seq = [make_window(f"w-{i}", seed=i) for i in range(seq_len)]
        with torch.no_grad():
            a_un, _ = model.logits(seq)
            a_b, _ = model.logits_batch(collate_sequences([(seq, (0, 0))], DEV))
        assert torch.allclose(a_un.reshape(-1), a_b.reshape(-1), atol=1e-5), \
            f"seq_len={seq_len}: diff {(a_un.reshape(-1)-a_b.reshape(-1)).abs().max():.3e}"


# ══════════════════════════════════════════════════════════════
# Test 3 — no cross-sequence attention leakage
# ══════════════════════════════════════════════════════════════

class TestNoCrossSequenceLeakage:
    def test_batched_embeddings_equal_solo_embeddings(self):
        """Two sequences with disjoint feature ranges, batched together.

        If offsetting failed, graph 2's nodes would appear in graph 1's attention
        neighbourhood and its embeddings would shift.
        """
        model = fresh_model()
        seq_a = [make_window(f"a-{i}", feat_base=0.10, seed=100 + i) for i in range(4)]
        seq_b = [make_window(f"b-{i}", feat_base=0.80, seed=200 + i) for i in range(4)]

        with torch.no_grad():
            solo_a = model.encode_batch(collate_sequences([(seq_a, (1, 7))], DEV))
            solo_b = model.encode_batch(collate_sequences([(seq_b, (0, 0))], DEV))
            both = model.encode_batch(collate_sequences(
                [(seq_a, (1, 7)), (seq_b, (0, 0))], DEV))

        assert torch.allclose(both[0], solo_a[0], atol=1e-5), \
            f"sequence 1 changed when batched: max diff {(both[0]-solo_a[0]).abs().max():.3e}"
        assert torch.allclose(both[1], solo_b[0], atol=1e-5), \
            f"sequence 2 changed when batched: max diff {(both[1]-solo_b[0]).abs().max():.3e}"

    def test_logits_unaffected_by_batch_companions(self):
        """A sequence's prediction must not depend on who it is batched with."""
        model = fresh_model()
        target_seq = [make_window(f"t-{i}", feat_base=0.4, seed=300 + i) for i in range(6)]

        with torch.no_grad():
            alone, _ = model.logits_batch(collate_sequences([(target_seq, (1, 7))], DEV))
            for companion_base in (0.05, 0.5, 0.95):
                comp = [make_window(f"c-{i}", feat_base=companion_base, seed=400 + i)
                        for i in range(6)]
                with_comp, _ = model.logits_batch(collate_sequences(
                    [(target_seq, (1, 7)), (comp, (0, 0))], DEV))
                assert torch.allclose(alone[0], with_comp[0], atol=1e-5), (
                    f"companion feat_base={companion_base} shifted the target by "
                    f"{(alone[0]-with_comp[0]).abs().max():.3e}"
                )

    def test_node_indices_are_disjoint_after_collation(self):
        """The structural property the no-leakage argument rests on."""
        seqs = [([make_window(f"s{b}-{i}", n_nodes=4 + b, seed=b * 10 + i) for i in range(3)],
                 (b % 2, 7)) for b in range(4)]
        c = collate_sequences(seqs, DEV)
        bi = c["graph_batch_index"]
        ei = c["graph_edge_index"]
        # every edge must connect two nodes belonging to the SAME graph
        assert ei.size(1) > 0
        src_graph = bi[ei[0]]
        dst_graph = bi[ei[1]]
        assert torch.equal(src_graph, dst_graph), "an edge spans two graphs"


# ══════════════════════════════════════════════════════════════
# Test 4 — LSTM masking
# ══════════════════════════════════════════════════════════════

class TestLstmMasking:
    def test_padded_sequence_matches_unpadded(self):
        """A length-5 sequence batched with a length-10 one, so it gets padded.

        Its summary state must come from timestep 5, not from five further steps
        of zero input.
        """
        model = fresh_model()
        short = [make_window(f"s-{i}", seed=500 + i) for i in range(5)]
        long = [make_window(f"l-{i}", seed=600 + i) for i in range(10)]

        with torch.no_grad():
            solo_short, _ = model.logits_batch(collate_sequences([(short, (1, 7))], DEV))
            padded, _ = model.logits_batch(collate_sequences(
                [(short, (1, 7)), (long, (0, 0))], DEV))

        assert padded[0].shape == solo_short[0].shape
        assert torch.allclose(solo_short[0], padded[0], atol=1e-5), (
            f"padding leaked into the summary state: diff "
            f"{(solo_short[0]-padded[0]).abs().max():.3e}"
        )

    def test_unbatched_path_agrees_with_the_padded_batch(self):
        model = fresh_model()
        short = [make_window(f"s-{i}", seed=700 + i) for i in range(5)]
        long = [make_window(f"l-{i}", seed=800 + i) for i in range(10)]
        with torch.no_grad():
            un, _ = model.logits(short)
            batched, _ = model.logits_batch(collate_sequences(
                [(short, (1, 7)), (long, (0, 0))], DEV))
        assert torch.allclose(un.reshape(-1), batched[0].reshape(-1), atol=1e-5)

    def test_mask_and_lengths_describe_the_same_thing(self):
        seqs = [([make_window(f"x{b}-{i}", seed=b + i) for i in range(n)], (1, 7))
                for b, n in enumerate([3, 8, 1, 5])]
        c = collate_sequences(seqs, DEV)
        assert c["T_max"] == 8
        assert c["seq_lengths"].tolist() == [3, 8, 1, 5]
        assert c["seq_mask"].sum(dim=1).tolist() == [3, 8, 1, 5]
        for b, n in enumerate([3, 8, 1, 5]):
            assert c["seq_mask"][b, :n].all()
            assert not c["seq_mask"][b, n:].any()


# ══════════════════════════════════════════════════════════════
# Test 6 — empty graphs inside a batch
# ══════════════════════════════════════════════════════════════

class TestEmptyGraphs:
    def test_all_empty_single_window(self):
        """Matches GATEncoder's documented policy: zeros, no NaN."""
        model = fresh_model()
        empty = make_window("e-0", n_nodes=0, n_edges=0)
        with torch.no_grad():
            a_un, _ = model.logits([empty])
            a_b, _ = model.logits_batch(collate_sequences([([empty], (0, 0))], DEV))
        assert torch.isfinite(a_b).all()
        assert torch.allclose(a_un.reshape(-1), a_b.reshape(-1), atol=1e-5)

    def test_empty_graph_mixed_into_a_populated_batch(self):
        model = fresh_model()
        seq_with_hole = [make_window("p-0", seed=1),
                         make_window("p-1", n_nodes=0, n_edges=0),
                         make_window("p-2", seed=3)]
        normal = [make_window(f"n-{i}", seed=900 + i) for i in range(3)]

        with torch.no_grad():
            un, _ = model.logits(seq_with_hole)
            b, _ = model.logits_batch(collate_sequences(
                [(seq_with_hole, (1, 7)), (normal, (0, 0))], DEV))
        assert torch.isfinite(b).all(), "empty graph produced NaN/Inf"
        assert torch.allclose(un.reshape(-1), b[0].reshape(-1), atol=1e-5), \
            f"empty-graph handling diverges: {(un.reshape(-1)-b[0].reshape(-1)).abs().max():.3e}"

    def test_nodes_but_no_edges(self):
        """Isolated hosts: GATLayer takes its no-edge branch (W_self only)."""
        model = fresh_model()
        seq = [make_window("iso-0", n_nodes=5, n_edges=0, seed=11)]
        with torch.no_grad():
            un, _ = model.logits(seq)
            b, _ = model.logits_batch(collate_sequences([(seq, (1, 7))], DEV))
        assert torch.isfinite(b).all()
        assert torch.allclose(un.reshape(-1), b[0].reshape(-1), atol=1e-5)

    def test_every_graph_empty_across_the_batch(self):
        model = fresh_model()
        e = [make_window("z", n_nodes=0, n_edges=0)]
        c = collate_sequences([(e, (0, 0)), (e, (0, 0))], DEV)
        assert c["graph_x"].shape == (0, len(NODE_FEATURE_NAMES))
        assert c["graph_edge_index"].shape == (2, 0)
        with torch.no_grad():
            emb = model.encode_batch(c)
            a, m = model.logits_batch(c)
        assert torch.isfinite(emb).all() and torch.isfinite(a).all() and torch.isfinite(m).all()
        assert a.shape == (2, 1)


# ══════════════════════════════════════════════════════════════
# Test 9 — checkpoint compatibility
# ══════════════════════════════════════════════════════════════

class TestCheckpointCompatibility:
    def test_state_dict_shapes_unchanged_by_batching(self, tmp_path):
        """Batching must not alter any parameter shape.

        Note: checkpoints/sentinel_best_val_auc.pt cannot be used here - it has
        lstm.weight_ih_l0 of (512, 128), i.e. window_feat_dim=0, predating the
        window-feature fusion. This test builds its own checkpoints from the
        current architecture instead.
        """
        model = fresh_model()
        p = tmp_path / "ckpt.pt"
        torch.save(model.state_dict(), p)

        set_seed(999)
        reloaded = WorldModel(**MODEL_ARGS)
        reloaded.load_state_dict(torch.load(p, weights_only=True))
        reloaded.eval()

        for (n1, p1), (n2, p2) in zip(model.named_parameters(), reloaded.named_parameters()):
            assert n1 == n2
            assert p1.shape == p2.shape
            assert torch.allclose(p1, p2)

    def test_checkpoint_roundtrip_gives_identical_output_on_both_paths(self, tmp_path):
        model = fresh_model()
        p = tmp_path / "rt.pt"
        torch.save(model.state_dict(), p)

        set_seed(4321)
        loaded = WorldModel(**MODEL_ARGS)
        loaded.load_state_dict(torch.load(p, weights_only=True))
        loaded.eval()

        seqs = [([make_window(f"r{b}-{i}", seed=b * 7 + i) for i in range(4 + b)], (b % 2, 7))
                for b in range(3)]
        c = collate_sequences(seqs, DEV)

        with torch.no_grad():
            a1, m1 = model.logits_batch(c)
            a2, m2 = loaded.logits_batch(c)
            u1, _ = model.logits(seqs[0][0])
            u2, _ = loaded.logits(seqs[0][0])

        assert torch.allclose(a1, a2, atol=1e-6)
        assert torch.allclose(m1, m2, atol=1e-6)
        assert torch.allclose(u1, u2, atol=1e-6)

    def test_saving_after_a_batched_forward_produces_the_same_keys(self, tmp_path):
        """A batched pass must not add or drop state_dict entries."""
        model = fresh_model()
        before = sorted(model.state_dict().keys())
        c = collate_sequences(
            [([make_window(f"k-{i}", seed=i) for i in range(3)], (1, 7))] * 4, DEV)
        with torch.no_grad():
            model.logits_batch(c)
        after = sorted(model.state_dict().keys())
        assert before == after
        p = tmp_path / "post.pt"
        torch.save(model.state_dict(), p)
        sd = torch.load(p, weights_only=True)
        assert sorted(sd.keys()) == before


# ══════════════════════════════════════════════════════════════
# Deferred to the training-loop phase
# ══════════════════════════════════════════════════════════════

@pytest.mark.skip(reason="Phase 2: requires train_one_epoch_batched")
def test_2_batched_loss_equals_mean_of_unbatched_losses():
    ...


@pytest.mark.skip(reason="Phase 2: requires train_one_epoch_batched")
def test_5_determinism_of_the_batched_training_step():
    ...


@pytest.mark.skip(reason="Phase 2: requires train_one_epoch_batched")
def test_7_incomplete_final_batch():
    ...


@pytest.mark.skip(reason="Phase 2: attention_weights on the batched path")
def test_8_attention_weights_field():
    ...


class TestAttentionWeightsPhase1:
    """Test 8's single-sequence half, which Phase 1 can already assert.

    The dashboard reads attention_weights off single-sequence inference, so that
    path must keep working regardless of what batching does.
    """

    def test_single_sequence_inference_still_populates_attention(self):
        model = fresh_model()
        seq = [make_window(f"att-{i}", n_nodes=6, n_edges=8, seed=i) for i in range(3)]
        with torch.no_grad():
            res = model(seq)
        assert len(res.attention_weights) > 0, "attention_weights is empty"
        assert all(isinstance(v, float) for v in res.attention_weights)

    def test_batched_path_attention_is_not_per_window(self):
        """Documents the known limitation rather than asserting it is fixed."""
        model = fresh_model()
        seqs = [([make_window(f"q{b}-{i}", seed=b + i) for i in range(2)], (1, 7))
                for b in range(3)]
        with torch.no_grad():
            model.logits_batch(collate_sequences(seqs, DEV))
        attn = model.gat.latest_attention_weights
        # It holds every graph's edges concatenated, with no edge -> graph map.
        assert attn is not None
        assert attn.shape[0] > 8, (
            "batched attention should span the whole batch; if this shrank to "
            "one window's worth, the batching collapsed"
        )
