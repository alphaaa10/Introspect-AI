"""
tests/test_ingestion.py

Tests for backend/app/ingestion/parser.py (Phase 2).

Fixture: backend/data/samples/mock_cicids.csv
  source=mock — a synthetic file that must never be loaded with
  DataSource.REAL in production.

Test inventory
--------------
TestCsvParsing
  test_valid_row_field_values          -- exact field values for row 0
  test_two_valid_rows_parsed           -- correct valid-event count
  test_malformed_timestamp_skipped     -- row 2 skipped, reported
  test_malformed_ip_skipped            -- row 3 skipped, reported
  test_invalid_port_skipped            -- row 4 skipped, reported
  test_missing_optional_field_no_crash -- row 5 (empty duration) no crash
  test_valid_rows_still_returned       -- bad rows don't discard good ones
  test_error_list_contains_row_indices -- errors carry correct row_index
  test_determinism                     -- two runs produce identical output

TestHeaderLevelValidation
  test_missing_required_column_raises  -- raises MissingColumnsError
  test_missing_columns_listed          -- MissingColumnsError names columns

TestMockSourceTagging
  test_mock_source_tag                 -- DataSource.MOCK is preserved

TestPcapStub
  test_parse_pcap_raises_not_implemented
"""

import sys
import io
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from app.schemas import DataSource, Protocol
from app.ingestion.parser import parse_csv, parse_cicids2017_csv, parse_pcap, MissingColumnsError

# ── Fixture paths ──────────────────────────────────────────────

_BACKEND_ROOT = Path(__file__).resolve().parent.parent
_SAMPLE_CSV   = _BACKEND_ROOT / "data" / "samples" / "mock_cicids.csv"


# ══════════════════════════════════════════════════════════════
# CSV parsing — core behaviour
# ══════════════════════════════════════════════════════════════

class TestCsvParsing:
    """Tests that use the synthetic mock_cicids.csv fixture."""

    def test_valid_row_field_values(self):
        """Assert exact field values for the first valid row (row 0)."""
        events, errors = parse_csv(_SAMPLE_CSV, source=DataSource.MOCK)

        assert len(events) >= 1
        e = events[0]  # flow-001
        assert e.flow_id     == "flow-001"
        assert e.src_ip      == "192.168.1.10"
        assert e.dst_ip      == "10.0.0.1"
        assert e.src_port    == 54321
        assert e.dst_port    == 80
        assert e.protocol    == Protocol.TCP
        assert e.fwd_packets == 10
        assert e.bwd_packets == 5
        assert e.fwd_bytes   == 1000
        assert e.bwd_bytes   == 500
        assert e.label       == "Benign"
        assert e.source      == DataSource.MOCK
        # duration: 2000000 µs → 2.0 s
        assert abs(e.duration_s - 2.0) < 1e-9
        # tcp_flags: SYN=1, ACK=1, rest 0 → "SYN,ACK"
        assert e.tcp_flags   == "SYN,ACK"

    def test_two_valid_rows_parsed(self):
        """Rows 0 (flow-001) and 1 (flow-002) and 5 (flow-006) are valid."""
        events, _ = parse_csv(_SAMPLE_CSV, source=DataSource.MOCK)
        # rows 2 (bad ts), 3 (bad ip), 4 (bad port) are errors → 3 valid
        assert len(events) == 3

    def test_malformed_timestamp_skipped(self):
        """Row 2 (NOT_A_TIMESTAMP) must be in errors, not events."""
        events, errors = parse_csv(_SAMPLE_CSV, source=DataSource.MOCK)
        error_indices = [e["row_index"] for e in errors]
        assert 2 in error_indices
        # Confirm the reason mentions timestamp
        ts_error = next(e for e in errors if e["row_index"] == 2)
        assert "timestamp" in ts_error["reason"].lower()

    def test_malformed_ip_skipped(self):
        """Row 3 (NOT_AN_IP) must be in errors, not events."""
        events, errors = parse_csv(_SAMPLE_CSV, source=DataSource.MOCK)
        error_indices = [e["row_index"] for e in errors]
        assert 3 in error_indices
        ip_error = next(e for e in errors if e["row_index"] == 3)
        assert "ip" in ip_error["reason"].lower()

    def test_invalid_port_skipped(self):
        """Row 4 (src_port=99999) must be in errors, not events."""
        events, errors = parse_csv(_SAMPLE_CSV, source=DataSource.MOCK)
        error_indices = [e["row_index"] for e in errors]
        assert 4 in error_indices
        port_error = next(e for e in errors if e["row_index"] == 4)
        assert "range" in port_error["reason"].lower() or "port" in port_error["reason"].lower()

    def test_missing_optional_field_no_crash(self):
        """Row 5 (empty Flow Duration) must not crash; event is produced."""
        events, errors = parse_csv(_SAMPLE_CSV, source=DataSource.MOCK)
        # Row 5 is flow-006; should parse with duration_s defaulting to 0.0
        flow_ids = [e.flow_id for e in events]
        assert "flow-006" in flow_ids
        ev = next(e for e in events if e.flow_id == "flow-006")
        assert ev.duration_s == 0.0

    def test_valid_rows_still_returned(self):
        """Bad rows must not discard valid ones — all 3 good rows present."""
        events, errors = parse_csv(_SAMPLE_CSV, source=DataSource.MOCK)
        assert len(events) == 3
        assert len(errors) == 3

    def test_error_list_contains_row_indices(self):
        """Each error dict must have 'row_index' (int) and 'reason' (str)."""
        _, errors = parse_csv(_SAMPLE_CSV, source=DataSource.MOCK)
        for err in errors:
            assert isinstance(err["row_index"], int)
            assert isinstance(err["reason"], str)
            assert err["reason"]  # non-empty

    def test_determinism(self):
        """Two consecutive calls on the same file must produce identical output."""
        events_a, errors_a = parse_csv(_SAMPLE_CSV, source=DataSource.MOCK)
        events_b, errors_b = parse_csv(_SAMPLE_CSV, source=DataSource.MOCK)

        # Same number of events and errors
        assert len(events_a) == len(events_b)
        assert len(errors_a) == len(errors_b)

        # Same field values in the same order
        for ea, eb in zip(events_a, events_b):
            assert ea.model_dump() == eb.model_dump()

        # Same error row indices and reasons
        for erra, errb in zip(errors_a, errors_b):
            assert erra == errb


# ══════════════════════════════════════════════════════════════
# Header-level validation
# ══════════════════════════════════════════════════════════════

class TestHeaderLevelValidation:
    """Tests for column-level (header) failures — MissingColumnsError."""

    def _write_csv(self, tmp_path: Path, content: str) -> Path:
        p = tmp_path / "bad.csv"
        p.write_text(textwrap.dedent(content), encoding="utf-8")
        return p

    def test_missing_required_column_raises(self, tmp_path):
        """CSV missing 'Src IP' must raise MissingColumnsError before any row parsing."""
        csv_path = self._write_csv(tmp_path, """\
            Flow ID,Timestamp,Dst IP,Src Port,Dst Port,Protocol
            flow-001,14/02/2018 10:02:00,10.0.0.1,54321,80,6
        """)
        with pytest.raises(MissingColumnsError):
            parse_csv(csv_path, source=DataSource.MOCK)

    def test_missing_columns_listed(self, tmp_path):
        """MissingColumnsError.missing must list the absent column names."""
        csv_path = self._write_csv(tmp_path, """\
            Flow ID,Timestamp,Src IP
            flow-001,14/02/2018 10:02:00,192.168.1.1
        """)
        with pytest.raises(MissingColumnsError) as exc_info:
            parse_csv(csv_path, source=DataSource.MOCK)
        missing = exc_info.value.missing
        assert isinstance(missing, list)
        assert len(missing) > 0
        # The missing columns should be Dst IP, Src Port, Dst Port, Protocol
        missing_set = set(missing)
        assert "Dst IP" in missing_set
        assert "Src Port" in missing_set

    def test_header_error_not_per_row(self, tmp_path):
        """A missing required column must NOT produce one error per row."""
        csv_path = self._write_csv(tmp_path, """\
            Flow ID,Timestamp,Src IP,Src Port,Dst Port,Protocol
            flow-001,14/02/2018 10:02:00,192.168.1.1,80,443,6
            flow-002,14/02/2018 10:02:05,192.168.1.2,81,444,6
        """)
        # Dst IP is missing — must raise, not return 2 errors
        with pytest.raises(MissingColumnsError):
            parse_csv(csv_path, source=DataSource.MOCK)


# ══════════════════════════════════════════════════════════════
# Source tagging
# ══════════════════════════════════════════════════════════════

class TestMockSourceTagging:
    def test_mock_source_tag(self):
        """DataSource.MOCK passed to parse_csv must appear on every event."""
        events, _ = parse_csv(_SAMPLE_CSV, source=DataSource.MOCK)
        for ev in events:
            assert ev.source == DataSource.MOCK


# ══════════════════════════════════════════════════════════════
# CIC-IDS-2017 (friday_plus.csv) parsing
# ══════════════════════════════════════════════════════════════

class TestCicIds2017Parsing:
    """Tests for the CIC-IDS-2017 specific parsing logic."""

    def _write_csv(self, tmp_path: Path, content: str) -> Path:
        p = tmp_path / "friday_plus_mock.csv"
        p.write_text(textwrap.dedent(content), encoding="utf-8")
        return p

    def test_valid_row_parsing(self, tmp_path):
        csv_path = self._write_csv(tmp_path, """\
            Flow ID,Src IP dec,Dst IP dec,Src Port,Dst Port,Protocol,Timestamp,Flow Duration,Total Fwd Packet,Total Bwd packets,Total Length of Fwd Packet,Total Length of Bwd Packet,Label,SYN Flag Count,ACK Flag Count,PSH Flag Count,FIN Flag Count,RST Flag Count,URG Flag Count
            192.168.10.50-192.168.10.3-56108-3268-6,3232238130,3232238083,56108,3268,6,59:50.3,112740690,32,16,6448,1152,BENIGN,0,1,1,0,0,0
            8.6.0.1-8.0.6.4-0-0-0,134610945,134219268,0,0,0,00:31.4,112740560,3,2,600,400,Portscan,1,0,0,0,0,0
        """)
        events, errors = parse_cicids2017_csv(csv_path, source=DataSource.MOCK)
        
        assert len(errors) == 0
        assert len(events) == 2
        
        # Row 0
        e0 = events[0]
        assert e0.flow_id == "192.168.10.50-192.168.10.3-56108-3268-6"
        assert e0.src_ip == "192.168.10.50"
        assert e0.dst_ip == "192.168.10.3"
        assert e0.src_port == 56108
        assert e0.dst_port == 3268
        assert e0.protocol == Protocol.TCP
        # Anchor is 2017-07-07 09:00:00 UTC, row 0 gets 0 ms offset
        from datetime import datetime, timezone
        assert e0.timestamp == datetime(2017, 7, 7, 9, 0, 0, tzinfo=timezone.utc)
        assert abs(e0.duration_s - 112.740690) < 1e-9
        assert e0.fwd_packets == 32
        assert e0.bwd_packets == 16
        assert e0.fwd_bytes == 6448
        assert e0.bwd_bytes == 1152
        assert e0.label == "BENIGN"
        assert e0.tcp_flags == "ACK,PSH"
        assert e0.source == DataSource.MOCK

        # Row 1
        e1 = events[1]
        assert e1.src_ip == "8.6.0.1"
        assert e1.dst_ip == "8.0.6.4"
        # Row 1 gets 100 ms offset
        assert e1.timestamp == datetime(2017, 7, 7, 9, 0, 0, 100_000, tzinfo=timezone.utc)
        assert e1.tcp_flags == "SYN"

    def test_missing_flow_id_column(self, tmp_path):
        csv_path = self._write_csv(tmp_path, """\
            Src IP dec,Dst IP dec
            3232238130,3232238083
        """)
        with pytest.raises(MissingColumnsError) as exc_info:
            parse_cicids2017_csv(csv_path, source=DataSource.MOCK)
        assert "Flow ID" in exc_info.value.missing

    def test_malformed_flow_id(self, tmp_path):
        csv_path = self._write_csv(tmp_path, """\
            Flow ID
            NOT_ENOUGH_PARTS
            192.168.10.50-192.168.10.3-56108-3268-6
        """)
        events, errors = parse_cicids2017_csv(csv_path, source=DataSource.MOCK)
        # Row 0 error
        assert len(errors) == 2
        assert errors[0]["row_index"] == 0
        assert "Malformed 'Flow ID'" in errors[0]["reason"]
        
        # Row 1 success (though some fields default to 0/empty due to missing cols, which raises ValueError in inner parse funcs if empty)
        # Wait, if "Src Port" is missing from CSV, it gets parsed as "", which raises ValueError.
        # Let's verify that row 1 is actually in errors due to missing fields.
        assert len(events) == 0  # because Src Port etc are missing and _parse_port throws on ""


# ══════════════════════════════════════════════════════════════
# PCAP stub
# ══════════════════════════════════════════════════════════════

class TestPcapStub:
    def test_parse_pcap_raises_not_implemented(self):
        with pytest.raises(NotImplementedError) as exc_info:
            parse_pcap("/any/path/file.pcap", source=DataSource.MOCK)
        assert "not yet implemented" in str(exc_info.value).lower()
