"""
tests/test_extractor.py

Tests for backend/app/features/extractor.py (Phase 3).

Hand-computed reference window
-------------------------------
One TCP event:
  src_ip=10.0.0.1, dst_ip=192.168.1.1
  src_port=54321, dst_port=80
  protocol=TCP
  fwd_packets=10, bwd_packets=5
  fwd_bytes=1000, bwd_bytes=500
  tcp_flags="SYN,ACK"
  duration_s=2.0

Expected raw aggregates (n=1 event):
  total_fwd_packets  = 10
  total_bwd_packets  = 5
  total_fwd_bytes    = 1000
  total_bwd_bytes    = 500
  total_duration_s   = 2.0
  mean_duration_s    = 2.0
  mean_src_port      = 54321.0
  mean_dst_port      = 80.0
  unique_dst_ips     = 1
  unique_dst_ports   = 1
  iat_mean           = 0.0  (only 1 event)
  iat_std            = 0.0

Expected derived:
  fwd_pkt_len_mean   = 1000 / 10 = 100.0
  bwd_pkt_len_mean   = 500  / 5  = 100.0
  flow_bytes_per_s   = (1000+500) / 2.0 = 750.0
  flow_pkts_per_s    = (10+5)     / 2.0 = 7.5

Expected categorical:
  protocol_type = 6.0  (TCP)
  syn_flag_cnt  = 1.0
  ack_flag_cnt  = 1.0
  psh_flag_cnt  = 0.0
  fin_flag_cnt  = 0.0
  rst_flag_cnt  = 0.0

Expected scaled (clip(x,0,hi)/hi):
  duration          = 2.0      / 600.0    ≈ 0.003333...
  protocol_type     = 6.0      / 17.0     ≈ 0.352941...
  src_port          = 54321.0  / 65535.0  ≈ 0.828872...
  dst_port          = 80.0     / 65535.0  ≈ 0.001220...
  fwd_packets       = 10.0     / 100000.0 = 0.0001
  bwd_packets       = 5.0      / 100000.0 = 0.00005
  fwd_bytes         = 1000.0   / 1e8      = 0.00001
  bwd_bytes         = 500.0    / 1e8      = 0.000005
  fwd_pkt_len_mean  = 100.0    / 1500.0   ≈ 0.066666...
  bwd_pkt_len_mean  = 100.0    / 1500.0   ≈ 0.066666...
  flow_bytes_per_s  = 750.0    / 1e9      = 0.00000075
  flow_pkts_per_s   = 7.5      / 1e6      = 0.0000075
  syn_flag_cnt      = 1.0      / 10000.0  = 0.0001
  ack_flag_cnt      = 1.0      / 10000.0  = 0.0001
  psh_flag_cnt      = 0.0      / 10000.0  = 0.0
  fin_flag_cnt      = 0.0      / 10000.0  = 0.0
  rst_flag_cnt      = 0.0      / 10000.0  = 0.0
  unique_dst_ports  = 1.0      / 1024.0   ≈ 0.000977...
  unique_dst_ips    = 1.0      / 5000.0   = 0.0002
  iat_mean          = 0.0      / 60.0     = 0.0
  iat_std           = 0.0      / 30.0     = 0.0
"""

import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from app import config
from app.schemas import DataSource, Protocol, NetworkEvent
from app.features.extractor import (
    extract_features,
    window_and_extract,
    _SCALE_BOUNDS,
    _PROTOCOL_ENCODE,
    _scale,
)


# ── Fixtures ───────────────────────────────────────────────────

_T0 = datetime(2018, 2, 14, 10, 0, 0, tzinfo=timezone.utc)


def _event(
    *,
    flow_id: str = "f-001",
    ts_offset_s: float = 0.0,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "192.168.1.1",
    src_port: int = 54321,
    dst_port: int = 80,
    protocol: Protocol = Protocol.TCP,
    fwd_packets: int = 10,
    bwd_packets: int = 5,
    fwd_bytes: int = 1000,
    bwd_bytes: int = 500,
    tcp_flags: str = "SYN,ACK",
    duration_s: float = 2.0,
    source: DataSource = DataSource.MOCK,
) -> NetworkEvent:
    return NetworkEvent(
        flow_id=flow_id,
        timestamp=_T0 + timedelta(seconds=ts_offset_s),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        fwd_packets=fwd_packets,
        bwd_packets=bwd_packets,
        fwd_bytes=fwd_bytes,
        bwd_bytes=bwd_bytes,
        tcp_flags=tcp_flags,
        duration_s=duration_s,
        source=source,
    )


_REF_EVENT = _event()  # single-event reference window

_W_START = _T0
_W_END   = _T0 + timedelta(seconds=60)


# ══════════════════════════════════════════════════════════════
# 1. Feature ordering
# ══════════════════════════════════════════════════════════════

class TestFeatureOrdering:
    def test_feature_vector_names_match_config(self):
        """Each position in feature_vector corresponds to config.FEATURE_NAMES[i]."""
        record = extract_features([_REF_EVENT], "w-0000", _W_START, _W_END, DataSource.MOCK)
        # Verify ordering by rebuilding feature names from bounds dict
        # and comparing to what config says.
        assert list(_SCALE_BOUNDS.keys()) == config.FEATURE_NAMES

    def test_feature_vector_is_in_config_names_order(self):
        """Verify that the feature at index i matches FEATURE_NAMES[i] by value."""
        record = extract_features([_REF_EVENT], "w-0000", _W_START, _W_END, DataSource.MOCK)
        fv = record.feature_vector

        # src_port is at index 2 per FEATURE_NAMES
        idx_src_port = config.FEATURE_NAMES.index("src_port")
        expected_src_port_scaled = 54321.0 / 65535.0
        assert fv[idx_src_port] == pytest.approx(expected_src_port_scaled, rel=1e-5)

        # dst_port is at index 3
        idx_dst_port = config.FEATURE_NAMES.index("dst_port")
        expected_dst_port_scaled = 80.0 / 65535.0
        assert fv[idx_dst_port] == pytest.approx(expected_dst_port_scaled, rel=1e-5)


# ══════════════════════════════════════════════════════════════
# 2. Dimension correctness
# ══════════════════════════════════════════════════════════════

class TestDimensions:
    def test_feature_vector_length_equals_num_features(self):
        record = extract_features([_REF_EVENT], "w-0000", _W_START, _W_END, DataSource.MOCK)
        assert len(record.feature_vector) == config.NUM_FEATURES

    def test_num_features_equals_21(self):
        """Guard against accidental FEATURE_NAMES drift."""
        assert config.NUM_FEATURES == 21

    def test_scale_bounds_covers_all_feature_names(self):
        """_SCALE_BOUNDS must have an entry for every feature in FEATURE_NAMES."""
        assert set(_SCALE_BOUNDS.keys()) == set(config.FEATURE_NAMES)


# ══════════════════════════════════════════════════════════════
# 3. Numeric correctness — hand-computed reference values
# ══════════════════════════════════════════════════════════════

class TestNumericCorrectness:
    def setup_method(self):
        self.record = extract_features(
            [_REF_EVENT], "w-0000", _W_START, _W_END, DataSource.MOCK
        )
        self.fv = self.record.feature_vector
        self.names = config.FEATURE_NAMES

    def _at(self, name: str) -> float:
        return self.fv[self.names.index(name)]

    def test_duration_scaled(self):
        assert self._at("duration") == pytest.approx(2.0 / 600.0, rel=1e-6)

    def test_protocol_type_tcp(self):
        assert self._at("protocol_type") == pytest.approx(6.0 / 17.0, rel=1e-6)

    def test_src_port_scaled(self):
        assert self._at("src_port") == pytest.approx(54321.0 / 65535.0, rel=1e-6)

    def test_dst_port_scaled(self):
        assert self._at("dst_port") == pytest.approx(80.0 / 65535.0, rel=1e-6)

    def test_fwd_packets_scaled(self):
        assert self._at("fwd_packets") == pytest.approx(10.0 / 100_000.0, rel=1e-6)

    def test_bwd_packets_scaled(self):
        assert self._at("bwd_packets") == pytest.approx(5.0 / 100_000.0, rel=1e-6)

    def test_fwd_bytes_scaled(self):
        assert self._at("fwd_bytes") == pytest.approx(1000.0 / 1e8, rel=1e-6)

    def test_bwd_bytes_scaled(self):
        assert self._at("bwd_bytes") == pytest.approx(500.0 / 1e8, rel=1e-6)

    def test_fwd_pkt_len_mean(self):
        # sum(fwd_bytes)/sum(fwd_pkts) = 1000/10 = 100.0, scaled /1500
        assert self._at("fwd_pkt_len_mean") == pytest.approx(100.0 / 1500.0, rel=1e-6)

    def test_bwd_pkt_len_mean(self):
        # 500/5 = 100.0, scaled /1500
        assert self._at("bwd_pkt_len_mean") == pytest.approx(100.0 / 1500.0, rel=1e-6)

    def test_flow_bytes_per_s(self):
        # (1000+500)/2.0 = 750.0, scaled /1e9
        assert self._at("flow_bytes_per_s") == pytest.approx(750.0 / 1e9, rel=1e-6)

    def test_flow_pkts_per_s(self):
        # (10+5)/2.0 = 7.5, scaled /1e6
        assert self._at("flow_pkts_per_s") == pytest.approx(7.5 / 1e6, rel=1e-6)

    def test_syn_flag_cnt(self):
        # tcp_flags="SYN,ACK" -> SYN present -> count=1, scaled /10000
        assert self._at("syn_flag_cnt") == pytest.approx(1.0 / 10_000.0, rel=1e-6)

    def test_ack_flag_cnt(self):
        assert self._at("ack_flag_cnt") == pytest.approx(1.0 / 10_000.0, rel=1e-6)

    def test_psh_flag_cnt_zero(self):
        assert self._at("psh_flag_cnt") == pytest.approx(0.0, abs=1e-12)

    def test_fin_flag_cnt_zero(self):
        assert self._at("fin_flag_cnt") == pytest.approx(0.0, abs=1e-12)

    def test_rst_flag_cnt_zero(self):
        assert self._at("rst_flag_cnt") == pytest.approx(0.0, abs=1e-12)

    def test_unique_dst_ports(self):
        # 1 unique port, scaled /1024
        assert self._at("unique_dst_ports") == pytest.approx(1.0 / 1024.0, rel=1e-6)

    def test_unique_dst_ips(self):
        # 1 unique IP, scaled /5000
        assert self._at("unique_dst_ips") == pytest.approx(1.0 / 5000.0, rel=1e-6)

    def test_iat_mean_single_event_sentinel(self):
        # Only 1 event -> IAT undefined -> sentinel 0.0
        assert self._at("iat_mean") == pytest.approx(0.0, abs=1e-12)

    def test_iat_std_single_event_sentinel(self):
        assert self._at("iat_std") == pytest.approx(0.0, abs=1e-12)

    def test_iat_computed_two_events(self):
        """IAT with two events 10 seconds apart: mean=10s, std=0.0."""
        e1 = _event(flow_id="f-1", ts_offset_s=0.0)
        e2 = _event(flow_id="f-2", ts_offset_s=10.0)
        record = extract_features([e1, e2], "w-0001", _W_START, _W_END, DataSource.MOCK)
        fv = record.feature_vector
        idx_iat_mean = config.FEATURE_NAMES.index("iat_mean")
        idx_iat_std  = config.FEATURE_NAMES.index("iat_std")
        # iat_mean = 10s, scaled /60.0
        assert fv[idx_iat_mean] == pytest.approx(10.0 / 60.0, rel=1e-6)
        # iat_std = 0.0 (only one IAT, variance=0)
        assert fv[idx_iat_std] == pytest.approx(0.0, abs=1e-12)


# ══════════════════════════════════════════════════════════════
# 4. Missing-value / sentinel handling
# ══════════════════════════════════════════════════════════════

class TestSentinelHandling:
    def test_empty_window_produces_all_zero_vector(self):
        """Empty event list must produce a valid all-zero feature vector."""
        record = extract_features([], "w-empty", _W_START, _W_END, DataSource.MOCK)
        assert len(record.feature_vector) == config.NUM_FEATURES
        assert all(v == pytest.approx(0.0, abs=1e-12) for v in record.feature_vector)

    def test_zero_duration_rate_sentinel(self):
        """If all flows have duration_s=0, rate features must be 0.0 (not NaN/inf)."""
        e = _event(duration_s=0.0)
        record = extract_features([e], "w-0000", _W_START, _W_END, DataSource.MOCK)
        fv = record.feature_vector
        idx_bps = config.FEATURE_NAMES.index("flow_bytes_per_s")
        idx_pps = config.FEATURE_NAMES.index("flow_pkts_per_s")
        assert fv[idx_bps] == pytest.approx(0.0, abs=1e-12)
        assert fv[idx_pps] == pytest.approx(0.0, abs=1e-12)

    def test_zero_fwd_packets_pkt_len_sentinel(self):
        """No forward packets -> fwd_pkt_len_mean = 0.0 (not division error)."""
        e = _event(fwd_packets=0, fwd_bytes=0)
        record = extract_features([e], "w-0000", _W_START, _W_END, DataSource.MOCK)
        fv = record.feature_vector
        idx = config.FEATURE_NAMES.index("fwd_pkt_len_mean")
        assert fv[idx] == pytest.approx(0.0, abs=1e-12)

    def test_value_above_bound_clipped_to_one(self):
        """A feature value exceeding hi must produce 1.0, not a value > 1."""
        # syn_flag_cnt hi = 10000; pass 99999 SYN events
        events = [
            _event(flow_id=f"f-{i}", ts_offset_s=float(i) * 0.001, tcp_flags="SYN")
            for i in range(20_000)
        ]
        record = extract_features(events, "w-clip", _W_START, _W_END, DataSource.MOCK)
        fv = record.feature_vector
        idx = config.FEATURE_NAMES.index("syn_flag_cnt")
        assert fv[idx] == pytest.approx(1.0, rel=1e-6)
        assert all(0.0 <= v <= 1.0 for v in fv), "All scaled values must be in [0, 1]"

    def test_no_nan_or_inf_in_output(self):
        """No NaN or inf may appear in the feature vector."""
        import math
        record = extract_features([_REF_EVENT], "w-0000", _W_START, _W_END, DataSource.MOCK)
        for v in record.feature_vector:
            assert math.isfinite(v), f"Non-finite value {v} found in feature vector"


# ══════════════════════════════════════════════════════════════
# 5. Determinism
# ══════════════════════════════════════════════════════════════

class TestDeterminism:
    def test_identical_input_identical_output(self):
        """Two calls on the same events produce bit-identical feature vectors."""
        events = [
            _event(flow_id="f-1", ts_offset_s=0.0),
            _event(flow_id="f-2", ts_offset_s=5.0, dst_ip="192.168.1.2", dst_port=443),
        ]
        r1 = extract_features(events, "w-0000", _W_START, _W_END, DataSource.MOCK)
        r2 = extract_features(events, "w-0000", _W_START, _W_END, DataSource.MOCK)
        assert r1.feature_vector == r2.feature_vector

    def test_unordered_input_same_result_as_sorted(self):
        """Windowing sorts by timestamp; unsorted input must produce same output."""
        e1 = _event(flow_id="f-1", ts_offset_s=0.0)
        e2 = _event(flow_id="f-2", ts_offset_s=5.0)
        r_sorted   = extract_features([e1, e2], "w-0000", _W_START, _W_END, DataSource.MOCK)
        r_unsorted = extract_features([e2, e1], "w-0000", _W_START, _W_END, DataSource.MOCK)
        # IAT is computed from sorted timestamps, so both must be identical
        assert r_sorted.feature_vector == r_unsorted.feature_vector


# ══════════════════════════════════════════════════════════════
# 6. Scaling metadata inspectability
# ══════════════════════════════════════════════════════════════

class TestScalingMetadata:
    def test_scale_bounds_are_module_level_constant(self):
        """_SCALE_BOUNDS is importable and contains the same values used at runtime."""
        # Re-import to confirm it's not computed on demand
        from app.features.extractor import _SCALE_BOUNDS as bounds
        assert bounds is _SCALE_BOUNDS  # same object, not a copy

    def test_scale_function_uses_bounds(self):
        """_scale('syn_flag_cnt', 5000) should equal 5000/10000 = 0.5."""
        result = _scale(5000.0, "syn_flag_cnt")
        assert result == pytest.approx(0.5, rel=1e-9)

    def test_scale_clipping_lower_bound(self):
        """Negative input must be clipped to lo (0.0)."""
        result = _scale(-100.0, "duration")
        assert result == pytest.approx(0.0, abs=1e-12)

    def test_scale_clipping_upper_bound(self):
        """Input above hi must produce exactly 1.0."""
        result = _scale(1_000_000.0, "duration")  # far above hi=600
        assert result == pytest.approx(1.0, rel=1e-9)

    def test_protocol_encode_is_deterministic(self):
        """Fixed protocol encoding dict values are stable."""
        assert _PROTOCOL_ENCODE["TCP"]   == 6.0
        assert _PROTOCOL_ENCODE["UDP"]   == 17.0
        assert _PROTOCOL_ENCODE["ICMP"]  == 1.0
        assert _PROTOCOL_ENCODE["OTHER"] == 0.0


# ══════════════════════════════════════════════════════════════
# 7. Windowing helper
# ══════════════════════════════════════════════════════════════

class TestWindowAndExtract:
    def test_single_window(self):
        """All events within one window -> one FeatureRecord."""
        events = [_event(flow_id=f"f-{i}", ts_offset_s=float(i)) for i in range(5)]
        records = window_and_extract(events, window_size_seconds=60, source=DataSource.MOCK)
        assert len(records) == 1
        assert records[0].flow_count == 5

    def test_two_windows(self):
        """Events spanning two 60s windows -> two FeatureRecords."""
        events = [
            _event(flow_id="f-0", ts_offset_s=0.0),
            _event(flow_id="f-1", ts_offset_s=30.0),
            _event(flow_id="f-2", ts_offset_s=61.0),  # second window
        ]
        records = window_and_extract(events, window_size_seconds=60, source=DataSource.MOCK)
        assert len(records) == 2
        assert records[0].flow_count == 2
        assert records[1].flow_count == 1

    def test_empty_input_returns_empty_list(self):
        records = window_and_extract([], window_size_seconds=60, source=DataSource.MOCK)
        assert records == []

    def test_window_ids_are_sequential(self):
        events = [
            _event(flow_id="f-0", ts_offset_s=0.0),
            _event(flow_id="f-1", ts_offset_s=61.0),
            _event(flow_id="f-2", ts_offset_s=122.0),
        ]
        records = window_and_extract(events, window_size_seconds=60, source=DataSource.MOCK)
        assert [r.window_id for r in records] == ["w-0000", "w-0001", "w-0002"]

    def test_window_determinism(self):
        """Same input, called twice -> identical list of FeatureRecords."""
        events = [
            _event(flow_id="f-0", ts_offset_s=0.0),
            _event(flow_id="f-1", ts_offset_s=70.0),
        ]
        r1 = window_and_extract(events, window_size_seconds=60, source=DataSource.MOCK)
        r2 = window_and_extract(events, window_size_seconds=60, source=DataSource.MOCK)
        assert len(r1) == len(r2)
        for a, b in zip(r1, r2):
            assert a.feature_vector == b.feature_vector
            assert a.window_id == b.window_id

    def test_source_tag_propagated(self):
        events = [_event()]
        records = window_and_extract(events, window_size_seconds=60, source=DataSource.MOCK)
        assert all(r.source == DataSource.MOCK for r in records)
