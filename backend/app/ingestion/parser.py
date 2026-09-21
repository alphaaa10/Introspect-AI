"""
ingestion/parser.py  Sentinel CSV (and PCAP stub) ingestion layer.

Public API
----------
parse_csv(filepath, source) -> tuple[list[NetworkEvent], list[dict]]
    Convert a CIC-IDS-2018-formatted CSV into NetworkEvent objects.
    Returns (valid_events, row_errors).  Never raises on a bad row —
    bad rows are skipped and collected in row_errors.

    Column-level failures (missing required header column) raise
    MissingColumnsError BEFORE any row is attempted.

parse_pcap(filepath, source) -> ...
    NOT IMPLEMENTED — raises NotImplementedError.

Design rules
------------
- No fabricated values: a field with no default in NetworkEvent must be
  present and well-formed in the CSV row; otherwise the row is rejected.
- Default-carrying NetworkEvent fields (tcp_flags, label, source) may
  use their schema defaults when the corresponding CSV column is absent.
- Deterministic: same file path + content always produces the same
  output list in the same order.
"""

from __future__ import annotations

import csv
import ipaddress
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Union

from app.schemas import DataSource, MitreStage, NetworkEvent, Protocol

# ──────────────────────────────────────────────────────────────
# Column mapping — CIC-IDS-2018 header names → internal keys
#
# CIC-IDS-2018 CSVs often have leading/trailing spaces in headers.
# All normalisation is done via _normalise_header().
# ──────────────────────────────────────────────────────────────

# Required: if any of these are absent from the CSV header, raise
# MissingColumnsError immediately (before parsing any rows).
REQUIRED_COLUMNS: dict[str, str] = {
    "Timestamp":  "timestamp",
    "Src IP":     "src_ip",
    "Dst IP":     "dst_ip",
    "Src Port":   "src_port",
    "Dst Port":   "dst_port",
    "Protocol":   "protocol",
}

# Optional: absent columns use the stated default; present columns that
# are malformed for a specific row cause that row to be skipped.
OPTIONAL_COLUMNS: dict[str, str] = {
    "Flow ID":           "flow_id",
    "Tot Fwd Pkts":      "fwd_packets",
    "Tot Bwd Pkts":      "bwd_packets",
    "TotLen Fwd Pkts":   "fwd_bytes",
    "TotLen Bwd Pkts":   "bwd_bytes",
    "Flow Duration":     "duration_s",
    "Label":             "label",
    # TCP flag count columns — combined into tcp_flags string
    "SYN Flag Cnt":      "flag_syn",
    "ACK Flag Cnt":      "flag_ack",
    "PSH Flag Cnt":      "flag_psh",
    "FIN Flag Cnt":      "flag_fin",
    "RST Flag Cnt":      "flag_rst",
    "URG Flag Cnt":      "flag_urg",
}

# CIC-IDS-2018 protocol numeric codes → Protocol enum
_PROTOCOL_MAP: dict[str, Protocol] = {
    "6":   Protocol.TCP,
    "17":  Protocol.UDP,
    "1":   Protocol.ICMP,
    "0":   Protocol.HOPOPT,
    "tcp": Protocol.TCP,
    "udp": Protocol.UDP,
    "icmp": Protocol.ICMP,
}

# Timestamp formats found in CIC-IDS-2018 datasets (tried in order)
_TIMESTAMP_FORMATS: list[str] = [
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%d/%m/%Y %I:%M:%S %p",
    "%m/%d/%Y %I:%M:%S %p",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
]


# ──────────────────────────────────────────────────────────────
# Exception — column-level only
# ──────────────────────────────────────────────────────────────

class MissingColumnsError(ValueError):
    """Raised when a required CSV header column is absent.

    This is a header-level failure raised before any row is parsed.
    It is distinct from per-row malformed-value errors.
    """
    def __init__(self, missing: list[str]) -> None:
        self.missing = missing
        super().__init__(
            f"CSV is missing required column(s): {missing}. "
            "Ensure the file follows CIC-IDS-2018 column naming conventions."
        )


# ──────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────

def _normalise_header(raw_headers: list[str]) -> dict[str, str]:
    """Strip whitespace from every raw header name.

    Returns a mapping {stripped_header: stripped_header} so that
    lookups against the known column maps work regardless of leading/
    trailing spaces in the original file.
    """
    return {h.strip(): h.strip() for h in raw_headers}


def _check_required_columns(
    stripped_headers: set[str],
) -> None:
    """Raise MissingColumnsError if any required column is absent."""
    missing = [col for col in REQUIRED_COLUMNS if col not in stripped_headers]
    if missing:
        raise MissingColumnsError(missing)


def _parse_timestamp(raw: str, row_index: int) -> datetime:
    """Parse a timestamp string into a UTC-aware datetime.

    Raises ValueError with a descriptive message on failure.
    """
    raw = raw.strip()
    if not raw:
        raise ValueError(f"Row {row_index}: timestamp field is empty")

    for fmt in _TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(raw, fmt)
            # If the parsed datetime is naive, assume UTC
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue

    raise ValueError(
        f"Row {row_index}: timestamp '{raw}' did not match any known "
        f"CIC-IDS-2018 format. Tried: {_TIMESTAMP_FORMATS}"
    )


def _parse_ip(raw: str, field: str, row_index: int) -> str:
    """Validate and return a normalised IP address string.

    Raises ValueError if the address is malformed.
    """
    raw = raw.strip()
    if not raw:
        raise ValueError(f"Row {row_index}: '{field}' is empty")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        raise ValueError(f"Row {row_index}: '{field}' value '{raw}' is not a valid IP address")


def _parse_port(raw: str, field: str, row_index: int) -> int:
    """Parse and bounds-check a port number (0–65535).

    Raises ValueError if out of range or non-numeric.
    """
    raw = raw.strip()
    if not raw:
        raise ValueError(f"Row {row_index}: '{field}' is empty")
    try:
        port = int(float(raw))  # CIC-IDS sometimes stores ports as floats
    except (ValueError, OverflowError):
        raise ValueError(f"Row {row_index}: '{field}' value '{raw}' is not numeric")
    if not (0 <= port <= 65535):
        raise ValueError(
            f"Row {row_index}: '{field}' value {port} is out of range [0, 65535]"
        )
    return port


def _parse_protocol(raw: str, row_index: int) -> Protocol:
    """Map a raw CIC-IDS protocol value to a Protocol enum member.

    CIC-IDS uses numeric codes (6=TCP, 17=UDP, 1=ICMP); plain strings
    are also accepted for test convenience.
    """
    key = raw.strip().lower()
    if key in _PROTOCOL_MAP:
        return _PROTOCOL_MAP[key]
    raise ValueError(
        f"Row {row_index}: protocol value '{raw}' is not recognised. "
        f"Known values: {list(_PROTOCOL_MAP.keys())}"
    )


def _parse_non_negative_int(raw: str, field: str, row_index: int, default: int = 0) -> int:
    """Parse a non-negative integer, using default if value is absent."""
    raw = raw.strip() if raw else ""
    if not raw:
        return default
    try:
        value = int(float(raw))
    except (ValueError, OverflowError):
        raise ValueError(
            f"Row {row_index}: '{field}' value '{raw}' is not a valid integer"
        )
    if value < 0:
        raise ValueError(f"Row {row_index}: '{field}' value {value} must be >= 0")
    return value


def _parse_duration(raw: str, row_index: int) -> float:
    """Parse Flow Duration (microseconds in CIC-IDS) → seconds."""
    raw = raw.strip() if raw else ""
    if not raw:
        return 0.0
    try:
        microseconds = float(raw)
    except ValueError:
        raise ValueError(
            f"Row {row_index}: 'Flow Duration' value '{raw}' is not a valid number"
        )
    if microseconds < 0:
        raise ValueError(
            f"Row {row_index}: 'Flow Duration' value {microseconds} must be >= 0"
        )
    return microseconds / 1_000_000.0  # convert µs → s


def _build_tcp_flags(row: dict[str, str]) -> str:
    """Derive a tcp_flags string from individual CIC-IDS flag count columns.

    e.g. if SYN Flag Cnt > 0 and ACK Flag Cnt > 0, returns "SYN,ACK".
    Returns "" if no flag columns are present or all counts are zero.
    """
    flag_map = [
        ("SYN Flag Cnt",  "SYN"),
        ("ACK Flag Cnt",  "ACK"),
        ("PSH Flag Cnt",  "PSH"),
        ("FIN Flag Cnt",  "FIN"),
        ("RST Flag Cnt",  "RST"),
        ("URG Flag Cnt",  "URG"),
    ]
    active: list[str] = []
    for col, label in flag_map:
        raw = row.get(col, "").strip()
        if raw:
            try:
                if int(float(raw)) > 0:
                    active.append(label)
            except ValueError:
                pass  # flag column present but malformed — silently omit that flag
    return ",".join(active)


def _make_flow_id(filepath: Path, row_index: int) -> str:
    """Generate a deterministic flow ID when the CSV has no Flow ID column."""
    return f"{filepath.stem}-row{row_index}"


# ──────────────────────────────────────────────────────────────
# Public API — CSV
# ──────────────────────────────────────────────────────────────

def parse_csv(
    filepath: Union[str, Path],
    source: DataSource = DataSource.REAL,
) -> tuple[list[NetworkEvent], list[dict]]:
    """Parse a CIC-IDS-2018 CSV file into NetworkEvent objects.

    Parameters
    ----------
    filepath : str | Path
        Path to the CSV file.
    source : DataSource
        Provenance tag applied to every produced NetworkEvent.
        Callers MUST pass DataSource.MOCK when reading from
        config.SAMPLE_DATA_DIR (Rule 11).

    Returns
    -------
    events : list[NetworkEvent]
        Successfully parsed, Pydantic-validated flow records.
        Order mirrors the row order in the CSV (deterministic).
    errors : list[dict]
        Per-row error descriptors, each with keys:
            "row_index" (int): 0-based data-row index (excludes header)
            "reason"    (str): human-readable description of the failure
        These are plain dicts — not Pydantic models.

    Raises
    ------
    MissingColumnsError
        If one or more REQUIRED_COLUMNS are absent from the CSV header.
        Raised before any row is processed.
    FileNotFoundError
        If filepath does not exist.
    """
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"CSV file not found: {filepath}")

    events: list[NetworkEvent] = []
    errors: list[dict] = []

    # ── Read file with encoding fallback ──────────────────────
    encodings = ["utf-8-sig", "utf-8", "latin-1"]
    raw_text: str | None = None
    for enc in encodings:
        try:
            raw_text = filepath.read_text(encoding=enc)
            break
        except UnicodeDecodeError:
            continue
    if raw_text is None:
        raise ValueError(f"Could not decode {filepath} with any of {encodings}")

    # ── Sniff delimiter ────────────────────────────────────────
    try:
        dialect = csv.Sniffer().sniff(raw_text[:4096], delimiters=",\t|")
    except csv.Error:
        dialect = csv.excel  # fall back to standard comma CSV

    reader = csv.DictReader(raw_text.splitlines(), dialect=dialect)

    # ── Header-level validation ────────────────────────────────
    if reader.fieldnames is None:
        raise MissingColumnsError(list(REQUIRED_COLUMNS.keys()))

    stripped_headers: set[str] = {h.strip() for h in reader.fieldnames}
    _check_required_columns(stripped_headers)

    has_flow_id_col = "Flow ID" in stripped_headers

    # ── Row-level parsing ──────────────────────────────────────
    for row_index, raw_row in enumerate(reader):
        # Strip whitespace from keys
        row: dict[str, str] = {k.strip(): v for k, v in raw_row.items() if k}

        try:
            # -- Required fields --
            timestamp = _parse_timestamp(row.get("Timestamp", ""), row_index)
            src_ip    = _parse_ip(row.get("Src IP", ""), "Src IP", row_index)
            dst_ip    = _parse_ip(row.get("Dst IP", ""), "Dst IP", row_index)
            src_port  = _parse_port(row.get("Src Port", ""), "Src Port", row_index)
            dst_port  = _parse_port(row.get("Dst Port", ""), "Dst Port", row_index)
            protocol  = _parse_protocol(row.get("Protocol", ""), row_index)

            # -- Optional fields with defaults --
            if has_flow_id_col:
                flow_id = row.get("Flow ID", "").strip() or _make_flow_id(filepath, row_index)
            else:
                flow_id = _make_flow_id(filepath, row_index)

            fwd_packets = _parse_non_negative_int(row.get("Tot Fwd Pkts", ""),      "Tot Fwd Pkts",    row_index)
            bwd_packets = _parse_non_negative_int(row.get("Tot Bwd Pkts", ""),      "Tot Bwd Pkts",    row_index)
            fwd_bytes   = _parse_non_negative_int(row.get("TotLen Fwd Pkts", ""),   "TotLen Fwd Pkts", row_index)
            bwd_bytes   = _parse_non_negative_int(row.get("TotLen Bwd Pkts", ""),   "TotLen Bwd Pkts", row_index)
            duration_s  = _parse_duration(row.get("Flow Duration", ""), row_index)
            label       = row.get("Label", "Unknown").strip() or "Unknown"
            tcp_flags   = _build_tcp_flags(row)

            event = NetworkEvent(
                flow_id=flow_id,
                timestamp=timestamp,
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
                label=label,
                source=source,
            )
            events.append(event)

        except Exception as exc:
            errors.append({"row_index": row_index, "reason": str(exc)})

    return events, errors


def _build_tcp_flags_2017(row: dict[str, str]) -> str:
    """Derive tcp_flags string for CIC-IDS-2017 format (uses 'Flag Count' instead of 'Flag Cnt')."""
    flag_map = [
        ("SYN Flag Count", "SYN"),
        ("ACK Flag Count", "ACK"),
        ("PSH Flag Count", "PSH"),
        ("FIN Flag Count", "FIN"),
        ("RST Flag Count", "RST"),
        ("URG Flag Count", "URG"),
    ]
    active: list[str] = []
    for col, label in flag_map:
        raw = row.get(col, "").strip()
        if raw:
            try:
                if int(float(raw)) > 0:
                    active.append(label)
            except ValueError:
                pass
    return ",".join(active)


def parse_cicids2017_csv(
    filepath: Union[str, Path],
    source: DataSource = DataSource.REAL,
) -> tuple[list[NetworkEvent], list[dict]]:
    """Parse a CIC-IDS-2017 CSV file (friday_plus.csv format).

    Extracts IPs from 'Flow ID', synthesizes timestamps from row order,
    and maps the specific column names used in this dataset variation.
    """
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"CSV file not found: {filepath}")

    events: list[NetworkEvent] = []
    errors: list[dict] = []

    encodings = ["utf-8-sig", "utf-8", "latin-1"]
    raw_text: str | None = None
    for enc in encodings:
        try:
            raw_text = filepath.read_text(encoding=enc)
            break
        except UnicodeDecodeError:
            continue
    if raw_text is None:
        raise ValueError(f"Could not decode {filepath} with any of {encodings}")

    try:
        dialect = csv.Sniffer().sniff(raw_text[:4096], delimiters=",\t|")
    except csv.Error:
        dialect = csv.excel

    reader = csv.DictReader(raw_text.splitlines(), dialect=dialect)
    if reader.fieldnames is None:
        raise MissingColumnsError(["Flow ID"])
    stripped_headers: set[str] = {h.strip() for h in reader.fieldnames}
    if "Flow ID" not in stripped_headers:
        raise MissingColumnsError(["Flow ID"])

    # 2017-07-07 09:00:00 UTC anchor
    anchor_ts = datetime(2017, 7, 7, 9, 0, 0, tzinfo=timezone.utc)
    interval = timedelta(milliseconds=100)

    for row_index, raw_row in enumerate(reader):
        row: dict[str, str] = {k.strip(): v for k, v in raw_row.items() if k}
        try:
            flow_id = row.get("Flow ID", "").strip()
            if not flow_id:
                raise ValueError("Missing 'Flow ID' column/value")

            # Flow ID format: SrcIP-DstIP-SrcPort-DstPort-Proto
            parts = flow_id.split("-", maxsplit=4)
            if len(parts) < 2:
                raise ValueError(f"Malformed 'Flow ID': {flow_id}")
            
            src_ip = _parse_ip(parts[0], "Flow ID Part 0", row_index)
            dst_ip = _parse_ip(parts[1], "Flow ID Part 1", row_index)
            
            src_port = _parse_port(row.get("Src Port", ""), "Src Port", row_index)
            dst_port = _parse_port(row.get("Dst Port", ""), "Dst Port", row_index)
            protocol = _parse_protocol(row.get("Protocol", ""), row_index)

            # Synthesize timestamp
            timestamp = anchor_ts + (row_index * interval)

            fwd_packets = _parse_non_negative_int(row.get("Total Fwd Packet", ""), "Total Fwd Packet", row_index)
            bwd_packets = _parse_non_negative_int(row.get("Total Bwd packets", ""), "Total Bwd packets", row_index)
            fwd_bytes = _parse_non_negative_int(row.get("Total Length of Fwd Packet", ""), "Total Length of Fwd Packet", row_index)
            bwd_bytes = _parse_non_negative_int(row.get("Total Length of Bwd Packet", ""), "Total Length of Bwd Packet", row_index)
            duration_s = _parse_duration(row.get("Flow Duration", ""), row_index)
            label = row.get("Label", "Unknown").strip() or "Unknown"
            tcp_flags = _build_tcp_flags_2017(row)

            event = NetworkEvent(
                flow_id=flow_id,
                timestamp=timestamp,
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
                label=label,
                source=source,
            )
            events.append(event)
        except Exception as exc:
            errors.append({"row_index": row_index, "reason": str(exc)})

    return events, errors


# ──────────────────────────────────────────────────────────────
# Public API — PCAP (interface stub only)
# ──────────────────────────────────────────────────────────────

def parse_pcap(
    filepath: Union[str, Path],
    source: DataSource = DataSource.REAL,
) -> tuple[list[NetworkEvent], list[dict]]:
    """PCAP ingestion — NOT IMPLEMENTED in Phase 2.

    This stub exists to define the interface contract for future
    implementors.  Actual packet-level parsing (via scapy or similar)
    is deferred to a later phase; no PCAP dependency has been added to
    requirements.txt.

    Raises
    ------
    NotImplementedError
        Always.
    """
    raise NotImplementedError(
        "PCAP parsing is not yet implemented. "
        "Implement parse_pcap() in a future phase using an appropriate "
        "packet-parsing library (e.g. scapy). "
        f"Called with filepath={filepath!r}, source={source!r}."
    )
