"""
ingestion/schema.py  Canonical flow-log schema, column-alias normalization,
and 21-feature coverage checking.

Purpose
-------
Uploaded logs vary in column naming. This module maps whatever headers a file
provides onto the canonical CICFlowMeter / CIC-IDS-2017 layout the model was
trained on, then reports how many of the 21 window features
(config.FEATURE_NAMES) can actually be derived from the columns present.

Extensibility
-------------
Adding support for a new export format = adding alias strings to ALIASES (or, for
a genuinely different layout, a normalization function that returns a
{canonical: actual_header} mapping). Nothing downstream — the parser, the
pipeline, the API, the UI — changes.

No fabrication
--------------
Coverage is computed purely from which SOURCE columns are present. Features whose
source columns are absent are reported missing; they are never imputed from
unrelated columns. The caller's policy (flexible_parser) decides refuse vs.
proceed-with-warning from the coverage report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app import config

# ── Canonical columns (CICFlowMeter / CIC-IDS-2017 layout) ──────────────
# Only the columns the 21 features actually need are listed; a real file has
# many more, which are simply ignored.
CANONICAL = [
    "Flow ID", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "Timestamp",
    "Flow Duration", "Total Fwd Packet", "Total Bwd packets",
    "Total Length of Fwd Packet", "Total Length of Bwd Packet",
    "SYN Flag Count", "ACK Flag Count", "PSH Flag Count", "FIN Flag Count",
    "RST Flag Count", "URG Flag Count",
    "Flow IAT Mean", "Flow IAT Std", "Label",
]


def _norm(s: str) -> str:
    """Lowercase, collapse any run of non-alphanumerics to a single space, strip.
    'TotLen Fwd Pkts' -> 'totlen fwd pkts', 'Src_IP' -> 'src ip'."""
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()


# canonical -> set of accepted alias spellings (stored normalized).
# NB: decimal-encoded columns like 'Src IP dec' are intentionally NOT aliased to
# 'Src IP' — their values are integers, not dotted IPs; real files carry the true
# IPs inside 'Flow ID', from which the parser derives them.
_ALIAS_RAW: dict[str, list[str]] = {
    "Flow ID": ["Flow ID", "FlowID"],
    "Src IP": ["Src IP", "Source IP", "srcaddr", "src", "saddr", "ip src", "source address"],
    "Dst IP": ["Dst IP", "Destination IP", "dstaddr", "dst", "daddr", "ip dst", "destination address"],
    "Src Port": ["Src Port", "Source Port", "sport", "srcport", "l4 src port"],
    "Dst Port": ["Dst Port", "Destination Port", "dport", "dstport", "l4 dst port"],
    "Protocol": ["Protocol", "proto", "ip protocol", "protocol type"],
    "Timestamp": ["Timestamp", "time", "ts", "flow start", "stime", "start time"],
    "Flow Duration": ["Flow Duration", "duration", "dur"],
    "Total Fwd Packet": ["Total Fwd Packet", "Total Fwd Packets", "Tot Fwd Pkts",
                         "Fwd Packets", "Fwd Pkts", "total fwd pkts"],
    "Total Bwd packets": ["Total Bwd packets", "Total Bwd Packet", "Tot Bwd Pkts",
                          "Bwd Packets", "Bwd Pkts", "total bwd pkts"],
    "Total Length of Fwd Packet": ["Total Length of Fwd Packet", "TotLen Fwd Pkts",
                                   "Fwd Bytes", "Total Fwd Bytes", "totlen fwd"],
    "Total Length of Bwd Packet": ["Total Length of Bwd Packet", "TotLen Bwd Pkts",
                                   "Bwd Bytes", "Total Bwd Bytes", "totlen bwd"],
    "SYN Flag Count": ["SYN Flag Count", "SYN Flag Cnt", "SYN Count", "syn cnt", "syn flags"],
    "ACK Flag Count": ["ACK Flag Count", "ACK Flag Cnt", "ACK Count", "ack cnt", "ack flags"],
    "PSH Flag Count": ["PSH Flag Count", "PSH Flag Cnt", "PSH Count", "psh cnt", "psh flags"],
    "FIN Flag Count": ["FIN Flag Count", "FIN Flag Cnt", "FIN Count", "fin cnt", "fin flags"],
    "RST Flag Count": ["RST Flag Count", "RST Flag Cnt", "RST Count", "rst cnt", "rst flags"],
    "URG Flag Count": ["URG Flag Count", "URG Flag Cnt", "URG Count"],
    "Flow IAT Mean": ["Flow IAT Mean", "IAT Mean"],
    "Flow IAT Std": ["Flow IAT Std", "IAT Std"],
    "Label": ["Label", "attack", "class", "category", "attack type"],
}
ALIASES: dict[str, set[str]] = {
    canon: {_norm(a) for a in [canon, *alts]} for canon, alts in _ALIAS_RAW.items()
}

# ── 21 features -> source-column requirement, as AND-of-ORs ──────────────
# Each feature maps to a list of groups; a group is satisfied if ANY canonical
# column in it is present. The feature is covered iff every group is satisfied.
_F = config.FEATURE_NAMES  # the canonical 21, in order
REQUIREMENTS: dict[str, list[list[str]]] = {
    "duration":         [["Flow Duration"]],
    "protocol_type":    [["Protocol"]],
    "src_port":         [["Src Port"]],
    "dst_port":         [["Dst Port"]],
    "fwd_packets":      [["Total Fwd Packet"]],
    "bwd_packets":      [["Total Bwd packets"]],
    "fwd_bytes":        [["Total Length of Fwd Packet"]],
    "bwd_bytes":        [["Total Length of Bwd Packet"]],
    "fwd_pkt_len_mean": [["Total Length of Fwd Packet"], ["Total Fwd Packet"]],
    "bwd_pkt_len_mean": [["Total Length of Bwd Packet"], ["Total Bwd packets"]],
    "flow_bytes_per_s": [["Total Length of Fwd Packet", "Total Length of Bwd Packet"], ["Flow Duration"]],
    "flow_pkts_per_s":  [["Total Fwd Packet", "Total Bwd packets"], ["Flow Duration"]],
    "syn_flag_cnt":     [["SYN Flag Count"]],
    "ack_flag_cnt":     [["ACK Flag Count"]],
    "psh_flag_cnt":     [["PSH Flag Count"]],
    "fin_flag_cnt":     [["FIN Flag Count"]],
    "rst_flag_cnt":     [["RST Flag Count"]],
    "unique_dst_ports": [["Dst Port"]],
    "unique_dst_ips":   [["Dst IP", "Flow ID"]],
    "iat_mean":         [["Timestamp", "Flow IAT Mean"]],
    "iat_std":          [["Timestamp", "Flow IAT Std"]],
}

MIN_COVERAGE = 18       # < this => refuse
FULL_COVERAGE = len(_F)  # 21


@dataclass
class CoverageReport:
    resolved: dict[str, str]          # canonical -> actual header found
    available: set[str]               # canonical columns present (incl. derived)
    covered: list[str]                # feature names derivable
    missing: list[str]                # feature names NOT derivable
    unmatched_headers: list[str] = field(default_factory=list)

    @property
    def n_covered(self) -> int:
        return len(self.covered)

    @property
    def n_total(self) -> int:
        return FULL_COVERAGE

    @property
    def ok(self) -> bool:
        """True => proceed (>= MIN_COVERAGE)."""
        return self.n_covered >= MIN_COVERAGE

    @property
    def full(self) -> bool:
        return self.n_covered == FULL_COVERAGE

    def to_dict(self) -> dict:
        return {
            "n_covered": self.n_covered,
            "n_total": self.n_total,
            "ok": self.ok,
            "full": self.full,
            "covered": self.covered,
            "missing": self.missing,
            "resolved_columns": self.resolved,
            "unmatched_headers": self.unmatched_headers,
            "min_coverage": MIN_COVERAGE,
        }


def resolve_columns(headers: list[str]) -> tuple[dict[str, str], list[str]]:
    """Map raw headers onto canonical names via alias tables.

    Returns (resolved, unmatched) where resolved is {canonical: actual_header}
    and unmatched is the list of headers that matched no canonical column.
    First match wins if several headers alias to the same canonical column.
    """
    resolved: dict[str, str] = {}
    unmatched: list[str] = []
    for h in headers:
        if h is None:
            continue
        n = _norm(h)
        hit = None
        for canon, aset in ALIASES.items():
            if n in aset and canon not in resolved:
                hit = canon
                break
        if hit:
            resolved[hit] = h
        else:
            unmatched.append(h)
    return resolved, unmatched


def compute_coverage(headers: list[str]) -> CoverageReport:
    """Full coverage report for a file's header row."""
    resolved, unmatched = resolve_columns(headers)
    available = set(resolved.keys())
    # IPs are derivable from Flow ID (SrcIP-DstIP-SrcPort-DstPort-Proto), so a
    # file with Flow ID effectively has Src IP / Dst IP available.
    if "Flow ID" in available:
        available |= {"Src IP", "Dst IP"}

    covered, missing = [], []
    for feat in _F:
        groups = REQUIREMENTS[feat]
        if all(any(col in available for col in group) for group in groups):
            covered.append(feat)
        else:
            missing.append(feat)

    return CoverageReport(
        resolved=resolved, available=available,
        covered=covered, missing=missing, unmatched_headers=unmatched,
    )
