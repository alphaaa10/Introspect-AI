"""
config.py  Sentinel backend configuration.
"""

import os
from pathlib import Path

BACKEND_ROOT: Path = Path(__file__).resolve().parent.parent

DATA_DIR: Path = BACKEND_ROOT / "data"
RAW_DATA_DIR: Path = DATA_DIR / "raw"
PROCESSED_DATA_DIR: Path = DATA_DIR / "processed"
SAMPLE_DATA_DIR: Path = DATA_DIR / "samples"
CHECKPOINTS_DIR: Path = BACKEND_ROOT / "checkpoints"
DB_PATH: Path = BACKEND_ROOT / "sentinel.db"

MODEL_DEVICE: str = os.environ.get("SENTINEL_DEVICE", "cpu")

# ── Feature extraction (added Phase 3) ────────────────────────
# Canonical ordered feature list produced by features/extractor.py.
# This is the single source of truth for feature ordering and length.
# Downstream modules that need a feature index MUST look it up here.
FEATURE_NAMES: list[str] = [
    "duration",           # Mean flow duration (s) across all flows in window
    "protocol_type",      # Mode protocol, fixed encoding: TCP=6, UDP=17, ICMP=1, OTHER=0
    "src_port",           # Mean src_port across flows (see extractor.py for limitation note)
    "dst_port",           # Mean dst_port across flows
    "fwd_packets",        # Sum of fwd_packets across all flows in window
    "bwd_packets",        # Sum of bwd_packets across all flows in window
    "fwd_bytes",          # Sum of fwd_bytes across all flows in window
    "bwd_bytes",          # Sum of bwd_bytes across all flows in window
    "fwd_pkt_len_mean",   # Window-level: sum(fwd_bytes) / sum(fwd_packets); 0.0 if no fwd packets
    "bwd_pkt_len_mean",   # Window-level: sum(bwd_bytes) / sum(bwd_packets); 0.0 if no bwd packets
    "flow_bytes_per_s",   # (sum_fwd_bytes + sum_bwd_bytes) / sum_duration_s; 0.0 if duration == 0
    "flow_pkts_per_s",    # (sum_fwd_pkts + sum_bwd_pkts) / sum_duration_s; 0.0 if duration == 0
    "syn_flag_cnt",       # Count of flows with "SYN" in tcp_flags
    "ack_flag_cnt",       # Count of flows with "ACK" in tcp_flags
    "psh_flag_cnt",       # Count of flows with "PSH" in tcp_flags
    "fin_flag_cnt",       # Count of flows with "FIN" in tcp_flags
    "rst_flag_cnt",       # Count of flows with "RST" in tcp_flags (proxy for failed connections)
    "unique_dst_ports",   # Distinct dst_port values in window
    "unique_dst_ips",     # Distinct dst_ip values in window
    "iat_mean",           # Mean inter-arrival time between consecutive events (s); 0.0 if <=1 event
    "iat_std",            # Std dev of inter-arrival times (s); 0.0 if <=1 event
]

NUM_FEATURES: int = len(FEATURE_NAMES)  # = 21

# ── Feature scaling mode ───────────────────────────────────────
# How graph/builder.py and features/extractor.py map raw values into [0, 1].
#
#   "linear" : clip(x, lo, hi) / hi
#   "log"    : log1p(clip(x, lo, hi) - lo) / log1p(hi - lo)
#
# Measured on the five day slices (LODO, 10 epochs, 4 training days, fixed 0.5
# threshold), mean ROC-AUC over the four evaluable folds:
#
#   linear : 0.9707
#   log    : 0.8941
#
# The two are not uniformly ordered. "log" wins on the low-volume fold
# (tuesday/Patator: 0.9759 -> 1.0000) because linear scaling against a 1e8
# ceiling squashes ordinary traffic to ~1e-4. But it loses on every volumetric
# fold (thursday 0.9787 -> 0.8191, friday 1.0000 -> 0.8796), because it
# compresses the upper tail where flood magnitude is the signal.
#
# "linear" is the default on the strength of the aggregate. Override per run
# with train.py --scaling, or SENTINEL_FEATURE_SCALING, and A/B it against your
# own attack mix before trusting either.
FEATURE_SCALING: str = os.environ.get("SENTINEL_FEATURE_SCALING", "linear")

# Temporal window size used by features/extractor.py windowing helper.
WINDOW_SIZE_SECONDS: int = 60

API_HOST: str = os.environ.get("SENTINEL_HOST", "0.0.0.0")
API_PORT: int = int(os.environ.get("SENTINEL_PORT", "8000"))

CORS_ORIGINS: list[str] = os.environ.get(
    "SENTINEL_CORS_ORIGINS",
    "http://localhost:5173",
).split(",")

# ── Model / training globals ────────────────────────────────────
# GLOBAL_SEED is a live runtime reference in gat.py, lstm.py, world_model.py
# via set_seed()'s fallback path: `s = seed if seed is not None else config.GLOBAL_SEED`.
GLOBAL_SEED: int = 42

# ── Architecture parameters ─────────────────────────────────────
# Dimensions for the Graph Attention Network encoder
GAT_HIDDEN_DIM: int = 128

# Recommended maximum sequence length fed to the LSTM encoder.
# The LSTM itself enforces nothing — this is a contract for upstream callers.
SEQUENCE_LENGTH: int = 20

# Number of MitreStage enum values in schemas.py.
# MUST equal len(list(MitreStage)). Update here if the enum changes.
# Used to size WorldModel's MITRE classification head.
NUM_MITRE_STAGES: int = 8
