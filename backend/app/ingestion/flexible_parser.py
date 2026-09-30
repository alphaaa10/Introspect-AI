"""
ingestion/flexible_parser.py  Alias-normalizing, coverage-checked flow-log parser.

Entry point
-----------
parse_flow_csv(text_or_path, source) -> (events, CoverageReport)

    * Normalizes headers to the canonical schema (schema.resolve_columns).
    * Computes 21-feature coverage (schema.compute_coverage).
    * Refusal policy:
        coverage < MIN_COVERAGE (18/21) -> raise CoverageError (nothing parsed).
        coverage in [18, 21)             -> proceed; report lists missing features.
        coverage == 21                   -> proceed clean.
    * No fabrication: absent source columns are not imputed. A feature whose
      columns are missing is reported missing; the few numeric fields with no
      column fall back to NetworkEvent's documented sentinel 0.0, which the
      coverage report surfaces (never silent).

Design: this does NOT modify the existing parse_cicids2017_csv (train.py depends
on it). It reuses that module's field-level validators so parsing behaviour is
identical, and matches training by deriving IPs from Flow ID and synthesising
row-order timestamps (the same 100 ms cadence training used, so the two IAT
features stay on the distribution the model saw).

Adding a new format touches only schema.ALIASES — not this file, the pipeline,
the API, or the UI.
"""

from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.schemas import DataSource, NetworkEvent
from app.ingestion import parser as _p
from app.ingestion.schema import CoverageReport, compute_coverage

# Same anchor/cadence as parse_cicids2017_csv, so synthesised timestamps (and the
# IAT features derived from them) match what the model was trained on.
_ANCHOR = datetime(2017, 7, 7, 9, 0, 0, tzinfo=timezone.utc)
_INTERVAL = timedelta(milliseconds=100)


class CoverageError(ValueError):
    """Raised when feature coverage is below the refusal threshold."""

    def __init__(self, report: CoverageReport):
        self.report = report
        super().__init__(
            f"Feature coverage {report.n_covered}/{report.n_total} is below the "
            f"minimum {report.to_dict()['min_coverage']}/21. Missing: {report.missing}"
        )


def _read_text(text_or_path: str | Path) -> str:
    p = Path(text_or_path) if not isinstance(text_or_path, str) else None
    if p is not None and p.exists():
        for enc in ("utf-8-sig", "utf-8", "latin-1"):
            try:
                return p.read_text(encoding=enc)
            except UnicodeDecodeError:
                continue
        raise ValueError(f"Could not decode {p}")
    return text_or_path  # already the CSV text


def parse_flow_csv(
    text_or_path: str | Path,
    source: DataSource = DataSource.REAL,
) -> tuple[list[NetworkEvent], CoverageReport]:
    raw_text = _read_text(text_or_path)

    try:
        dialect = csv.Sniffer().sniff(raw_text[:4096], delimiters=",\t|")
    except csv.Error:
        dialect = csv.excel

    reader = csv.DictReader(raw_text.splitlines(), dialect=dialect)
    headers = [h.strip() for h in (reader.fieldnames or []) if h]
    if not headers:
        raise ValueError("Uploaded file has no header row")

    report = compute_coverage(headers)
    if not report.ok:
        raise CoverageError(report)

    resolved = report.resolved  # canonical -> actual header
    has_flow_id = "Flow ID" in resolved
    has_src_ip = "Src IP" in resolved
    has_dst_ip = "Dst IP" in resolved

    events: list[NetworkEvent] = []
    for row_index, raw_row in enumerate(reader):
        row = {(k.strip() if k else k): v for k, v in raw_row.items()}
        # canonical-keyed view so we (and the reused flag builder) read by
        # canonical name regardless of the file's actual header spellings.
        crow = {canon: (row.get(actual, "") or "") for canon, actual in resolved.items()}
        try:
            # IPs: prefer Flow ID (SrcIP-DstIP-SrcPort-DstPort-Proto), else IP cols.
            if has_flow_id and crow.get("Flow ID", "").strip():
                flow_id = crow["Flow ID"].strip()
                parts = flow_id.split("-", maxsplit=4)
                if len(parts) < 2:
                    raise ValueError(f"Malformed Flow ID: {flow_id}")
                src_ip = _p._parse_ip(parts[0], "Flow ID[0]", row_index)
                dst_ip = _p._parse_ip(parts[1], "Flow ID[1]", row_index)
            elif has_src_ip and has_dst_ip:
                flow_id = _p._make_flow_id(Path("upload"), row_index)
                src_ip = _p._parse_ip(crow.get("Src IP", ""), "Src IP", row_index)
                dst_ip = _p._parse_ip(crow.get("Dst IP", ""), "Dst IP", row_index)
            else:
                # No IP source at all (already reflected as missing coverage).
                flow_id = _p._make_flow_id(Path("upload"), row_index)
                src_ip, dst_ip = "0.0.0.0", "0.0.0.1"

            src_port = _p._parse_port(crow.get("Src Port", ""), "Src Port", row_index)
            dst_port = _p._parse_port(crow.get("Dst Port", ""), "Dst Port", row_index)
            protocol = _p._parse_protocol(crow.get("Protocol", ""), row_index)

            # Row-order timestamp (matches training; keeps IAT on-distribution).
            timestamp = _ANCHOR + (row_index * _INTERVAL)

            fwd_packets = _p._parse_non_negative_int(crow.get("Total Fwd Packet", ""), "Total Fwd Packet", row_index)
            bwd_packets = _p._parse_non_negative_int(crow.get("Total Bwd packets", ""), "Total Bwd packets", row_index)
            fwd_bytes = _p._parse_non_negative_int(crow.get("Total Length of Fwd Packet", ""), "Total Length of Fwd Packet", row_index)
            bwd_bytes = _p._parse_non_negative_int(crow.get("Total Length of Bwd Packet", ""), "Total Length of Bwd Packet", row_index)
            duration_s = _p._parse_duration(crow.get("Flow Duration", ""), row_index)
            label = (crow.get("Label", "") or "Unknown").strip() or "Unknown"
            tcp_flags = _p._build_tcp_flags_2017(crow)

            events.append(NetworkEvent(
                flow_id=flow_id, timestamp=timestamp,
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port, protocol=protocol,
                fwd_packets=fwd_packets, bwd_packets=bwd_packets,
                fwd_bytes=fwd_bytes, bwd_bytes=bwd_bytes,
                tcp_flags=tcp_flags, duration_s=duration_s,
                label=label, source=source,
            ))
        except (ValueError, KeyError):
            # Skip malformed rows, consistent with parse_cicids2017_csv.
            continue

    return events, report
