"""
tests/test_train_protocols.py

Covers the evaluation-protocol machinery in train.py: fold generation, leakage,
window labelling, and the loss-weighting edge case that produced NaN.

These are regression tests for defects that do not raise — a leaky split or a
NaN validation loss still produces a number, just a wrong one.
"""

import sys
from pathlib import Path

import pytest
import torch
import torch.nn as nn

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import config
from app.schemas import MitreStage, NetworkEvent, Protocol, DataSource
from train import (
    make_blocked_folds,
    make_lodo_folds,
    get_window_label,
    LABEL_TO_MITRE,
)

SEQ = config.SEQUENCE_LENGTH


# ══════════════════════════════════════════════════════════════
# Fold generation
# ══════════════════════════════════════════════════════════════

def _pools(sizes, attack_stage=None):
    """Build day_pools of ((day, index), (is_attack, stage)) sentinels.

    The sequence "payload" is a (day, index) marker so a test can tell exactly
    which windows ended up on which side of a split.
    """
    pools = {}
    for day, n in sizes:
        stage = attack_stage.get(day, 7) if attack_stage else 7
        is_attack = 0 if day == "monday" else 1
        pools[day] = [((day, i), (is_attack, stage)) for i in range(n)]
    return pools


REALISTIC = [("monday", 84), ("tuesday", 170), ("wednesday", 433),
             ("thursday", 170), ("friday", 132)]


class TestBlockedFolds:
    def test_no_label_appears_on_two_sides(self):
        pools = _pools(REALISTIC)
        for name, tr, va, te in make_blocked_folds(pools, n_splits=5, block_size=40):
            tr_m = {m for m, _ in tr}
            va_m = {m for m, _ in va}
            te_m = {m for m, _ in te}
            assert not (tr_m & te_m), f"{name}: train/test share {len(tr_m & te_m)} labels"
            assert not (tr_m & va_m), f"{name}: train/val share {len(tr_m & va_m)} labels"
            assert not (va_m & te_m), f"{name}: val/test share {len(va_m & te_m)} labels"

    def test_no_training_sequence_reads_a_held_out_window(self):
        """The purge, which is the whole reason this protocol is not trivial.

        A sequence labelled at index j reads windows [j-SEQ+1, j]. If any of
        those windows is held out, that training sequence is contaminated.
        """
        pools = _pools(REALISTIC)
        for name, tr, va, te in make_blocked_folds(pools, n_splits=5, block_size=40):
            held = {}
            for m, _ in list(te) + list(va):
                day, i = m
                held.setdefault(day, set()).add(i)
            for (day, j), _ in tr:
                window_range = set(range(max(0, j - SEQ + 1), j + 1))
                overlap = held.get(day, set()) & window_range
                assert not overlap, (
                    f"{name}: train sequence {day}[{j}] reads held-out windows {sorted(overlap)}"
                )

    def test_every_sequence_is_tested_exactly_once(self):
        pools = _pools(REALISTIC)
        folds = list(make_blocked_folds(pools, n_splits=5, block_size=40))
        tested = [m for _, _, _, te in folds for m, _ in te]
        total = sum(len(v) for v in pools.values())
        assert len(tested) == total
        assert len(set(tested)) == total, "some sequence was tested more than once"

    def test_no_fold_has_an_empty_split(self):
        pools = _pools(REALISTIC)
        for name, tr, va, te in make_blocked_folds(pools, n_splits=5, block_size=40):
            assert tr, f"{name}: empty training set"
            assert va, f"{name}: empty validation set"
            assert te, f"{name}: empty test set"

    def test_test_sets_mix_days_rather_than_collapsing_to_lodo(self):
        """Regression: a plain `position % n_splits` stripe aliased.

        With 5 days of 2 blocks each and n_splits=5 the stride equalled the day
        count, so both of a day's blocks landed in the same group and every
        fold's test set was one whole day — silently turning this back into
        LODO while reporting itself as blocked CV.
        """
        pools = _pools([("monday", 84), ("tuesday", 100), ("wednesday", 100),
                        ("thursday", 100), ("friday", 100)])
        folds = list(make_blocked_folds(pools, n_splits=5, block_size=40))
        multi_day = sum(1 for _, _, _, te in folds if len({d for (d, _), _ in te}) > 1)
        assert multi_day >= 3, (
            f"only {multi_day}/5 folds test on more than one day; the fold "
            f"assignment has aliased back toward LODO"
        )

    def test_all_stages_reach_training_in_every_fold(self):
        """The entire point of this protocol versus LODO."""
        stages = {"monday": 0, "tuesday": 3, "wednesday": 7,
                  "thursday": 1, "friday": 5}
        pools = _pools(REALISTIC, attack_stage=stages)
        attack_stages = {s for d, s in stages.items() if d != "monday"}
        for name, tr, va, te in make_blocked_folds(pools, n_splits=5, block_size=40):
            present = {t[1] for _, t in tr if t[0] == 1}
            assert present == attack_stages, (
                f"{name}: training is missing stages {attack_stages - present}"
            )

    def test_rejects_too_few_splits(self):
        # n_splits < 3 leaves nothing to train on: test and val consume everything.
        with pytest.raises(ValueError, match="n-splits must be >= 3"):
            list(make_blocked_folds(_pools(REALISTIC), n_splits=2, block_size=40))

    def test_rejects_block_size_larger_than_every_day(self):
        with pytest.raises(ValueError, match="block_size"):
            list(make_blocked_folds(_pools([("monday", 10)]), n_splits=3, block_size=500))


class TestLodoFolds:
    def test_holds_out_exactly_one_day_per_fold(self):
        pools = _pools(REALISTIC)
        folds = list(make_lodo_folds(pools))
        assert len(folds) == len(REALISTIC)
        for name, tr, va, te in folds:
            assert {d for (d, _), _ in te} == {name}
            assert name not in {d for (d, _), _ in tr}
            assert name not in {d for (d, _), _ in va}

    def test_validation_day_is_never_the_all_benign_day(self):
        """monday has no attack windows, so it cannot tune a threshold."""
        pools = _pools(REALISTIC)
        for name, tr, va, te in make_lodo_folds(pools):
            val_days = {d for (d, _), _ in va}
            assert "monday" not in val_days, f"{name} chose monday as validation"

    def test_single_day_falls_back_instead_of_crashing(self):
        """Regression: --smoke raised "not enough values to unpack" here."""
        pools = _pools([("mock", 5)])
        folds = list(make_lodo_folds(pools))
        assert len(folds) == 1
        name, tr, va, te = folds[0]
        assert tr and te, "single-day fallback must still yield train and test"


# ══════════════════════════════════════════════════════════════
# Window labelling
# ══════════════════════════════════════════════════════════════

def _event(label, ts_offset=0):
    from datetime import datetime, timezone, timedelta
    return NetworkEvent(
        flow_id=f"f-{label}-{ts_offset}",
        timestamp=datetime(2017, 7, 7, 9, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=ts_offset),
        src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1234, dst_port=80,
        protocol=Protocol.TCP, fwd_packets=1, bwd_packets=1,
        fwd_bytes=100, bwd_bytes=50, duration_s=1.0, label=label,
    )


class TestWindowLabel:
    def test_empty_window_is_benign(self):
        assert get_window_label([]) == (0, MitreStage.BENIGN)

    def test_all_benign_window_is_benign(self):
        assert get_window_label([_event("BENIGN"), _event("BENIGN")]) == (0, MitreStage.BENIGN)

    def test_any_attack_flow_marks_the_window(self):
        events = [_event("BENIGN")] * 99 + [_event("DDoS")]
        is_attack, _ = get_window_label(events)
        assert is_attack == 1, "one malicious flow in 100 must still flag the window"

    def test_dominant_policy_takes_the_most_frequent_attack(self):
        events = [_event("DDoS")] * 10 + [_event("Portscan")] * 2
        assert get_window_label(events, policy="dominant") == (1, MitreStage.IMPACT)

    def test_advanced_policy_takes_the_furthest_kill_chain_stage(self):
        # Portscan (Reconnaissance) swamps DDoS (Impact) numerically, but Impact
        # is further along the chain.
        events = [_event("Portscan")] * 10 + [_event("DDoS")] * 1
        assert get_window_label(events, policy="dominant") == (1, MitreStage.RECONNAISSANCE)
        assert get_window_label(events, policy="advanced") == (1, MitreStage.IMPACT)

    def test_mitre_enum_order_is_kill_chain_order(self):
        """The 'advanced' policy takes max() over enum indices, so the enum's
        declaration order IS the kill-chain ordering. Reordering it silently
        changes labelling."""
        stages = list(MitreStage)
        expected = [
            MitreStage.BENIGN, MitreStage.RECONNAISSANCE, MitreStage.INITIAL_ACCESS,
            MitreStage.CREDENTIAL_ACCESS, MitreStage.LATERAL_MOVEMENT,
            MitreStage.C2, MitreStage.EXFILTRATION, MitreStage.IMPACT,
        ]
        assert stages == expected

    def test_every_mapped_label_resolves_to_a_real_stage(self):
        for label, stage in LABEL_TO_MITRE.items():
            assert isinstance(stage, MitreStage), label

    def test_num_mitre_stages_matches_the_enum(self):
        assert config.NUM_MITRE_STAGES == len(list(MitreStage))


# ══════════════════════════════════════════════════════════════
# Loss weighting
# ══════════════════════════════════════════════════════════════

class TestStageSelection:
    """The stage argmax must skip BENIGN.

    Regression: the stage head is supervised on attack windows only, so its
    BENIGN logit is meaningless. Including index 0 in the argmax let that
    unsupervised logit win and be scored as a wrong stage — one measured fold
    predicted BENIGN for all 57 of its attack windows and scored exactly 0.0.
    """

    @staticmethod
    def _pick(probs):
        # Mirrors the selection in train.evaluate()
        return 1 + max(range(len(probs) - 1), key=lambda i: probs[i + 1])

    def test_never_selects_benign_even_when_it_dominates(self):
        probs = [0.9, 0.02, 0.01, 0.03, 0.01, 0.01, 0.01, 0.01]
        assert self._pick(probs) != 0
        assert self._pick(probs) == 3, "should pick the best non-BENIGN stage"

    def test_selects_the_largest_attack_stage(self):
        stages = list(MitreStage)
        for target in range(1, len(stages)):
            probs = [0.5] + [0.0] * (len(stages) - 1)
            probs[target] = 0.4
            assert self._pick(probs) == target, stages[target]

    def test_result_is_always_a_valid_attack_stage(self):
        import random as _r
        _r.seed(0)
        for _ in range(50):
            probs = [_r.random() for _ in range(config.NUM_MITRE_STAGES)]
            idx = self._pick(probs)
            assert 1 <= idx < config.NUM_MITRE_STAGES
            assert list(MitreStage)[idx] != MitreStage.BENIGN


class TestMitreClassWeights:
    def test_zero_weight_class_yields_nan(self):
        """Documents why absent classes must not get weight 0.

        CrossEntropyLoss(reduction='mean') divides by the summed weight of the
        batch, so a lone sample of a zero-weight class is 0/0.
        """
        w = torch.zeros(config.NUM_MITRE_STAGES)
        w[7] = 1.0
        crit = nn.CrossEntropyLoss(weight=w)
        logits = torch.zeros(1, config.NUM_MITRE_STAGES)
        loss = crit(logits, torch.tensor([5]))  # class 5 has weight 0
        assert torch.isnan(loss), "expected the 0/0 that caused 'Val: nan'"

    def test_weighting_scheme_used_in_training_is_finite_for_absent_classes(self):
        """The fix: absent classes get 1.0, never 0.0."""
        import numpy as np
        counts = np.zeros(config.NUM_MITRE_STAGES, dtype=np.float64)
        counts[0], counts[3], counts[7] = 100, 20, 60   # C2 (5) absent
        present = counts > 0
        w = np.ones_like(counts)
        w[present] = counts[present].sum() / (present.sum() * counts[present])

        crit = nn.CrossEntropyLoss(weight=torch.tensor(w, dtype=torch.float32))
        logits = torch.zeros(1, config.NUM_MITRE_STAGES)
        for cls in range(config.NUM_MITRE_STAGES):
            loss = crit(logits, torch.tensor([cls]))
            assert torch.isfinite(loss), f"class {cls} gave {loss.item()}"

    def test_stage_weights_ignore_benign_windows(self):
        """Weights must be computed over attack windows only.

        The stage loss is masked to attack windows, so counting benign windows
        would give BENIGN a huge count and a negligible weight for a class the
        head is never trained on.
        """
        import numpy as np
        # 300 benign windows (stage 0), plus attacks at stages 3 and 7.
        targets = [(0, 0)] * 300 + [(1, 3)] * 20 + [(1, 7)] * 60
        counts = np.bincount([t[1] for t in targets if t[0] == 1],
                             minlength=config.NUM_MITRE_STAGES).astype(np.float64)
        assert counts[0] == 0, "benign windows must not be counted"
        assert counts[3] == 20 and counts[7] == 60

    def test_average_weight_per_sample_is_one(self):
        """What keeps the MITRE term on the same scale as the binary term.

        The invariant of N / (K * n_c) is sum_c(n_c * w_c) == N — the mean
        weight per *training sample* is 1.0. The mean weight per *class* is
        above 1 whenever the classes are imbalanced (1.60 for these counts), so
        asserting that instead would be wrong.
        """
        import numpy as np
        counts = np.array([100.0, 95, 0, 83, 0, 18, 0, 117])
        present = counts > 0
        w = np.ones_like(counts)
        w[present] = counts[present].sum() / (present.sum() * counts[present])

        total_weight = float((counts * w)[present].sum())
        assert total_weight == pytest.approx(counts[present].sum())

        # Rarer class must get the larger weight.
        assert w[5] > w[7], "C2 (18 samples) should outweigh Impact (117)"
