"""
features/extractor.py  Sentinel feature-extraction layer.

Public API
----------
extract_features(events, window_id, window_start, window_end, source)
    -> FeatureRecord
    Accepts a pre-windowed list[NetworkEvent] and returns a single
    FeatureRecord whose feature_vector follows config.FEATURE_NAMES
    order exactly.

window_and_extract(events, window_size_seconds, source)
    -> list[FeatureRecord]
    Windowing helper: groups a raw stream of NetworkEvent objects into
    WINDOW_SIZE_SECONDS buckets (sorted by timestamp, deterministic)
    and calls extract_features for each bucket.

Design decisions (all explicit, on the record)
----------------------------------------------
Scope:
    extractor.py owns windowing (as directed by the Phase 3 spec default).
    Windowing helper is in this file, not a separate module.

Aggregation semantics per feature at window level:
    duration        - MEAN of event.duration_s across all flows
    protocol_type   - MODE protocol, fixed encode: TCP=6, UDP=17, ICMP=1, OTHER=0
    src_port        - MEAN of event.src_port  [KNOWN LIMITATION: mean port is a
                      weak discriminator at window level; retained for schema
                      consistency with config.FEATURE_NAMES; unique_dst_ports
                      already captures port-scan behaviour more effectively]
    dst_port        - MEAN of event.dst_port  [same limitation as src_port]
    fwd_packets     - SUM of event.fwd_packets
    bwd_packets     - SUM of event.bwd_packets
    fwd_bytes       - SUM of event.fwd_bytes
    bwd_bytes       - SUM of event.bwd_bytes
    fwd_pkt_len_mean- sum(fwd_bytes) / sum(fwd_packets); sentinel 0.0 if no fwd pkts
    bwd_pkt_len_mean- sum(bwd_bytes) / sum(bwd_packets); sentinel 0.0 if no bwd pkts
    flow_bytes_per_s- (sum_fwd_bytes + sum_bwd_bytes) / sum_duration_s;
                      sentinel 0.0 if total duration == 0 (not NaN/inf)
    flow_pkts_per_s - (sum_fwd_pkts + sum_bwd_pkts) / sum_duration_s;
                      sentinel 0.0 if total duration == 0
    *_flag_cnt      - count of events where that flag name appears in event.tcp_flags
    unique_dst_ports- len(set of dst_port values)
    unique_dst_ips  - len(set of dst_ip values)
    iat_mean        - mean of consecutive-event timestamp differences (seconds);
                      sentinel 0.0 if window has <= 1 event
    iat_std         - std dev of IATs; sentinel 0.0 if window has <= 1 event

Failed-connection proxy:
    NetworkEvent has no explicit session-completion field.  A failed TCP
    connection is approximated by rst_flag_cnt (RST in tcp_flags), which
    is already in FEATURE_NAMES.  No separate "failed_connection" feature
    is added — doing so would duplicate rst_flag_cnt for TCP, and
    NetworkEvent provides no session-completion signal for UDP/ICMP.

Scaling:
    Fixed-bounds min-max: x_scaled = clip(x, lo, hi) / hi
    (lo == 0 for all features, so this simplifies to clip(x, 0, hi) / hi).
    Bounds stored in _SCALE_BOUNDS — a module-level named dict that is
    inspectable and identical at training and inference time.
    NaN and inf are impossible by construction: all raw values are
    non-negative (enforced by NetworkEvent validators or sentinel 0.0),
    and division is guarded.

CIC-IDS-2018 isolation:
    Dataset-specific assumptions live in parser.py (Phase 2).  extractor.py
    operates purely on NetworkEvent objects and has no knowledge of CSV
    column names or raw file formats.
"""

from __future__ import annotations

import math
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Union

from app import config
from app.schemas import DataSource, NetworkEvent, FeatureRecord


# ══════════════════════════════════════════════════════════════
# Scaling constants — fixed, named, module-level
# ══════════════════════════════════════════════════════════════

# Formula: x_scaled = clip(x, lo, hi) / hi   (lo == 0 for all features)
# Each entry: feature_name -> (lo, hi)
# Changing any value here is a breaking change to the pipeline — treat
# these as versioned constants.
_SCALE_BOUNDS: dict[str, tuple[float, float]] = {
    "duration":         (0.0,    600.0),     # mean flow duration up to 10 min
    "protocol_type":    (0.0,     17.0),     # UDP=17 is the max fixed encode
    "src_port":         (0.0,  65535.0),     # full port range
    "dst_port":         (0.0,  65535.0),     # full port range
    "fwd_packets":      (0.0, 100_000.0),    # ~100k pkts/60s is flood ceiling
    "bwd_packets":      (0.0, 100_000.0),
    "fwd_bytes":        (0.0,    1e8),       # 100 MB per window
    "bwd_bytes":        (0.0,    1e8),
    "fwd_pkt_len_mean": (0.0,   1500.0),    # Ethernet MTU
    "bwd_pkt_len_mean": (0.0,   1500.0),
    "flow_bytes_per_s": (0.0,    1e9),       # 1 GB/s ≈ gigabit saturation
    "flow_pkts_per_s":  (0.0,    1e6),       # 1 M pkt/s realistic DDoS ceiling
    "syn_flag_cnt":     (0.0, 10_000.0),    # 10k/min signals SYN flood
    "ack_flag_cnt":     (0.0, 10_000.0),
    "psh_flag_cnt":     (0.0, 10_000.0),
    "fin_flag_cnt":     (0.0, 10_000.0),
    "rst_flag_cnt":     (0.0, 10_000.0),
    "unique_dst_ports": (0.0,   1024.0),    # >1024 unique ports/min = extreme scan
    "unique_dst_ips":   (0.0,   5000.0),    # aggressive worm/scan ceiling for 60s
    "iat_mean":         (0.0,     60.0),    # mean IAT ≤ window size by construction
    "iat_std":          (0.0,     30.0),    # std dev at most half the window
}

# Protocol fixed encoding — deterministic, not hash-based.
_PROTOCOL_ENCODE: dict[str, float] = {
    "TCP":   6.0,
    "UDP":  17.0,
    "ICMP":  1.0,
    "OTHER": 0.0,
}


# ══════════════════════════════════════════════════════════════
# Internal helpers — three separated concerns
# ══════════════════════════════════════════════════════════════


def _aggregate_raw_fields(events: list[NetworkEvent]) -> dict[str, float]:
    """Concern 1: Direct sums/counts from NetworkEvent fields.

    No derived ratios here — only values that can be read directly
    from individual NetworkEvent instances.
    """
    n = len(events)
    if n == 0:
        return {
            "total_fwd_packets":  0.0,
            "total_bwd_packets":  0.0,
            "total_fwd_bytes":    0.0,
            "total_bwd_bytes":    0.0,
            "total_duration_s":   0.0,
            "mean_duration_s":    0.0,
            "mean_src_port":      0.0,
            "mean_dst_port":      0.0,
            "unique_dst_ips":     0.0,
            "unique_dst_ports":   0.0,
            "iat_mean":           0.0,
            "iat_std":            0.0,
        }

    total_fwd_packets = float(sum(e.fwd_packets for e in events))
    total_bwd_packets = float(sum(e.bwd_packets for e in events))
    total_fwd_bytes   = float(sum(e.fwd_bytes   for e in events))
    total_bwd_bytes   = float(sum(e.bwd_bytes   for e in events))
    total_duration_s  = float(sum(e.duration_s  for e in events))

    # Mean port values (see module docstring for known limitation)
    mean_src_port = sum(e.src_port for e in events) / n
    mean_dst_port = sum(e.dst_port for e in events) / n

    unique_dst_ips   = float(len({e.dst_ip   for e in events}))
    unique_dst_ports = float(len({e.dst_port for e in events}))

    # Inter-arrival times — sorted by timestamp for determinism
    sorted_ts = sorted(e.timestamp for e in events)
    if len(sorted_ts) >= 2:
        iats = [
            (sorted_ts[i + 1] - sorted_ts[i]).total_seconds()
            for i in range(len(sorted_ts) - 1)
        ]
        iat_mean = sum(iats) / len(iats)
        iat_var  = sum((x - iat_mean) ** 2 for x in iats) / len(iats)
        iat_std  = math.sqrt(iat_var)
    else:
        # Sentinel: 0.0 when there is only one event (undefined IAT)
        iat_mean = 0.0
        iat_std  = 0.0

    return {
        "total_fwd_packets":  total_fwd_packets,
        "total_bwd_packets":  total_bwd_packets,
        "total_fwd_bytes":    total_fwd_bytes,
        "total_bwd_bytes":    total_bwd_bytes,
        "total_duration_s":   total_duration_s,
        "mean_duration_s":    total_duration_s / n,
        "mean_src_port":      mean_src_port,
        "mean_dst_port":      mean_dst_port,
        "unique_dst_ips":     unique_dst_ips,
        "unique_dst_ports":   unique_dst_ports,
        "iat_mean":           iat_mean,
        "iat_std":            iat_std,
    }


def _derive_computed_features(raw: dict[str, float]) -> dict[str, float]:
    """Concern 2: Ratios and rates computed from raw aggregates.

    Divide-by-zero guards use sentinel 0.0, documented below:
      fwd_pkt_len_mean  -> 0.0 when no forward packets (sum = 0)
      bwd_pkt_len_mean  -> 0.0 when no backward packets (sum = 0)
      flow_bytes_per_s  -> 0.0 when total duration == 0 (e.g. all flows
                           reported 0-second duration, or empty window)
      flow_pkts_per_s   -> same guard
    """
    total_fwd_pkts  = raw["total_fwd_packets"]
    total_bwd_pkts  = raw["total_bwd_packets"]
    total_fwd_bytes = raw["total_fwd_bytes"]
    total_bwd_bytes = raw["total_bwd_bytes"]
    total_dur       = raw["total_duration_s"]

    fwd_pkt_len_mean = (
        total_fwd_bytes / total_fwd_pkts if total_fwd_pkts > 0 else 0.0
    )
    bwd_pkt_len_mean = (
        total_bwd_bytes / total_bwd_pkts if total_bwd_pkts > 0 else 0.0
    )
    flow_bytes_per_s = (
        (total_fwd_bytes + total_bwd_bytes) / total_dur if total_dur > 0 else 0.0
    )
    flow_pkts_per_s = (
        (total_fwd_pkts + total_bwd_pkts) / total_dur if total_dur > 0 else 0.0
    )

    return {
        "fwd_pkt_len_mean": fwd_pkt_len_mean,
        "bwd_pkt_len_mean": bwd_pkt_len_mean,
        "flow_bytes_per_s": flow_bytes_per_s,
        "flow_pkts_per_s":  flow_pkts_per_s,
    }


def _encode_categorical(events: list[NetworkEvent]) -> dict[str, float]:
    """Concern 3: Categorical features — deterministic fixed encodings.

    Protocol: mode of all protocols in the window, encoded with
    _PROTOCOL_ENCODE (fixed map, not a hash, not sklearn).

    TCP flag counts: per-flag count of events where that flag name
    appears as a substring of event.tcp_flags.  Note: tcp_flags is a
    comma-separated string (e.g. "SYN,ACK") set by parser.py from the
    CIC-IDS flag count columns.

    Failed connections: rst_flag_cnt acts as the proxy.  See module
    docstring for the full rationale.
    """
    if not events:
        return {
            "protocol_type": 0.0,
            "syn_flag_cnt":  0.0,
            "ack_flag_cnt":  0.0,
            "psh_flag_cnt":  0.0,
            "fin_flag_cnt":  0.0,
            "rst_flag_cnt":  0.0,
        }

    # Mode protocol
    # Note: Counter.most_common(1) tie-breaking relies on CPython's (3.7+)
    # guaranteed dict insertion-ordering. For equal-count ties, the protocol
    # encountered first (after sorting by timestamp) wins. This is an
    # implementation dependency, not a Python-language guarantee.
    proto_counts = Counter(e.protocol.value for e in events)
    mode_proto   = proto_counts.most_common(1)[0][0]
    protocol_type = _PROTOCOL_ENCODE.get(mode_proto, 0.0)

    # Flag counts — substring search is correct: "SYN" is always a
    # distinct comma-delimited token so partial matches (e.g. "SYNACK")
    # cannot occur with the format written by parser.py.
    syn_flag_cnt = float(sum(1 for e in events if "SYN" in e.tcp_flags))
    ack_flag_cnt = float(sum(1 for e in events if "ACK" in e.tcp_flags))
    psh_flag_cnt = float(sum(1 for e in events if "PSH" in e.tcp_flags))
    fin_flag_cnt = float(sum(1 for e in events if "FIN" in e.tcp_flags))
    rst_flag_cnt = float(sum(1 for e in events if "RST" in e.tcp_flags))

    return {
        "protocol_type": protocol_type,
        "syn_flag_cnt":  syn_flag_cnt,
        "ack_flag_cnt":  ack_flag_cnt,
        "psh_flag_cnt":  psh_flag_cnt,
        "fin_flag_cnt":  fin_flag_cnt,
        "rst_flag_cnt":  rst_flag_cnt,
    }


def _scale(value: float, feature_name: str) -> float:
    """Apply fixed-bounds min-max scaling.

    Formula: clip(value, lo, hi) / hi
    (lo == 0 for all features, so this is equivalent to min-max with
    a fixed zero lower bound.)

    Returns a value in [0.0, 1.0].
    """
    lo, hi = _SCALE_BOUNDS[feature_name]
    clipped = max(lo, min(value, hi))
    # hi > 0 guaranteed by construction; no division by zero possible.
    return clipped / hi


# ══════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════


def extract_features(
    events: list[NetworkEvent],
    window_id: str,
    window_start: datetime,
    window_end: datetime,
    source: DataSource = DataSource.REAL,
) -> FeatureRecord:
    """Extract and scale features for a pre-windowed list of NetworkEvents.

    Parameters
    ----------
    events : list[NetworkEvent]
        All flows belonging to this time window.  May be empty; an empty
        window produces an all-zero (sentinel) feature vector.
    window_id : str
        Caller-assigned identifier for this window.
    window_start, window_end : datetime
        Inclusive start and exclusive end of the window.
    source : DataSource
        Provenance tag.  Callers MUST pass DataSource.MOCK when operating
        on sample data (Rule 11).

    Returns
    -------
    FeatureRecord
        Validated Pydantic object.  feature_vector has exactly
        config.NUM_FEATURES elements in config.FEATURE_NAMES order.
    """
    raw        = _aggregate_raw_fields(events)
    derived    = _derive_computed_features(raw)
    categorical = _encode_categorical(events)

    # Assemble a named dict so the FEATURE_NAMES loop is the single
    # point of truth for ordering — no index arithmetic.
    feature_map: dict[str, float] = {
        "duration":         raw["mean_duration_s"],
        "protocol_type":    categorical["protocol_type"],
        "src_port":         raw["mean_src_port"],
        "dst_port":         raw["mean_dst_port"],
        "fwd_packets":      raw["total_fwd_packets"],
        "bwd_packets":      raw["total_bwd_packets"],
        "fwd_bytes":        raw["total_fwd_bytes"],
        "bwd_bytes":        raw["total_bwd_bytes"],
        "fwd_pkt_len_mean": derived["fwd_pkt_len_mean"],
        "bwd_pkt_len_mean": derived["bwd_pkt_len_mean"],
        "flow_bytes_per_s": derived["flow_bytes_per_s"],
        "flow_pkts_per_s":  derived["flow_pkts_per_s"],
        "syn_flag_cnt":     categorical["syn_flag_cnt"],
        "ack_flag_cnt":     categorical["ack_flag_cnt"],
        "psh_flag_cnt":     categorical["psh_flag_cnt"],
        "fin_flag_cnt":     categorical["fin_flag_cnt"],
        "rst_flag_cnt":     categorical["rst_flag_cnt"],
        "unique_dst_ports": raw["unique_dst_ports"],
        "unique_dst_ips":   raw["unique_dst_ips"],
        "iat_mean":         raw["iat_mean"],
        "iat_std":          raw["iat_std"],
    }

    feature_vector = [_scale(feature_map[name], name) for name in config.FEATURE_NAMES]

    return FeatureRecord(
        window_id=window_id,
        window_start=window_start,
        window_end=window_end,
        feature_vector=feature_vector,
        flow_count=len(events),
        source=source,
    )


def window_and_extract(
    events: list[NetworkEvent],
    window_size_seconds: int | None = None,
    source: DataSource = DataSource.REAL,
) -> list[FeatureRecord]:
    """Group a raw event stream into time windows and extract features.

    Windowing logic
    ---------------
    - Events are sorted by timestamp (ascending) for determinism.
    - The first window starts at the timestamp of the earliest event.
    - Each window spans exactly window_size_seconds seconds.
    - An event whose timestamp falls on a window boundary belongs to the
      NEXT window (windows are [start, end) half-open intervals).
    - Empty windows (no events fell in that bucket) are skipped.
    - Window IDs are zero-padded integers: "w-0000", "w-0001", ...

    Parameters
    ----------
    events : list[NetworkEvent]
        Raw, unordered network flows.
    window_size_seconds : int, optional
        Overrides config.WINDOW_SIZE_SECONDS when set.
    source : DataSource
        Propagated to every produced FeatureRecord.

    Returns
    -------
    list[FeatureRecord]
        One FeatureRecord per non-empty window, in chronological order.
    """
    if window_size_seconds is None:
        window_size_seconds = config.WINDOW_SIZE_SECONDS

    if not events:
        return []

    sorted_events = sorted(events, key=lambda e: e.timestamp)
    window_delta  = timedelta(seconds=window_size_seconds)

    # Anchor the first window to the earliest event's timestamp.
    first_ts      = sorted_events[0].timestamp
    window_start  = first_ts
    window_end    = first_ts + window_delta

    bucket: list[NetworkEvent] = []
    window_index = 0
    records: list[FeatureRecord] = []

    for event in sorted_events:
        # Advance windows until this event fits in [window_start, window_end)
        while event.timestamp >= window_end:
            if bucket:
                records.append(
                    extract_features(
                        bucket,
                        window_id=f"w-{window_index:04d}",
                        window_start=window_start,
                        window_end=window_end,
                        source=source,
                    )
                )
                window_index += 1
                bucket = []
            window_start = window_end
            window_end   = window_start + window_delta

        bucket.append(event)

    # Flush the final (possibly partial) window
    if bucket:
        records.append(
            extract_features(
                bucket,
                window_id=f"w-{window_index:04d}",
                window_start=window_start,
                window_end=window_end,
                source=source,
            )
        )

    return records
