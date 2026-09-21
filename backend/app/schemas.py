"""
schemas.py  Sentinel shared data contracts (Pydantic v2).
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator


# ══════════════════════════════════════════════════════════════
# Stable enumerations
# ══════════════════════════════════════════════════════════════

class DataSource(str, Enum):
    """Identifies data provenance."""
    REAL = "real"
    MOCK = "mock"

class Protocol(str, Enum):
    """Network protocol encoded in a flow record."""
    TCP    = "TCP"
    UDP    = "UDP"
    ICMP   = "ICMP"
    HOPOPT = "HOPOPT"
    OTHER  = "OTHER"

class MitreStage(str, Enum):
    """MITRE ATT&CK tactic stages."""
    BENIGN            = "Benign"
    RECONNAISSANCE    = "Reconnaissance"
    INITIAL_ACCESS    = "Initial Access"
    CREDENTIAL_ACCESS = "Credential Access"
    LATERAL_MOVEMENT  = "Lateral Movement"
    C2                = "Command & Control"
    EXFILTRATION      = "Exfiltration"
    IMPACT            = "Impact"


# ══════════════════════════════════════════════════════════════
# Models (12 classes)
# ══════════════════════════════════════════════════════════════

class NetworkEvent(BaseModel):
    flow_id: str
    timestamp: datetime
    src_ip: str = Field(min_length=1)
    dst_ip: str = Field(min_length=1)
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: Protocol
    fwd_packets: int  = Field(ge=0)
    bwd_packets: int  = Field(ge=0)
    fwd_bytes: int    = Field(ge=0)
    bwd_bytes: int    = Field(ge=0)
    tcp_flags: str    = ""
    duration_s: float = Field(ge=0.0)
    label: str        = "Unknown"
    source: DataSource = DataSource.REAL

class FeatureRecord(BaseModel):
    window_id: str
    window_start: datetime
    window_end: datetime
    feature_vector: list[float]
    flow_count: int = Field(ge=0)
    source: DataSource = DataSource.REAL

    @field_validator("feature_vector")
    @classmethod
    def _check_feature_length(cls, v: list[float]) -> list[float]:
        # Lazy import avoids any future circular-import risk;
        # config.py never imports from schemas.py.
        from app.config import NUM_FEATURES
        if len(v) != NUM_FEATURES:
            raise ValueError(
                f"feature_vector length {len(v)} != NUM_FEATURES ({NUM_FEATURES})"
            )
        return v

class GraphNode(BaseModel):
    node_index:  int   = Field(ge=0)
    ip:          str   = Field(min_length=1)
    out_bytes:   float = Field(ge=0.0)
    in_bytes:    float = Field(ge=0.0)
    out_degree:  float = Field(ge=0.0)
    in_degree:   float = Field(ge=0.0)
    total_flows: float = Field(ge=0.0)

class GraphEdge(BaseModel):
    src_node_index:    int   = Field(ge=0)
    dst_node_index:    int   = Field(ge=0)
    src_ip:            str   = Field(min_length=1)
    dst_ip:            str   = Field(min_length=1)
    total_fwd_bytes:   float = Field(ge=0.0)
    total_bwd_bytes:   float = Field(ge=0.0)
    total_fwd_packets: float = Field(ge=0.0)
    total_bwd_packets: float = Field(ge=0.0)
    flow_count:        float = Field(ge=0.0)
    mean_duration_s:   float = Field(ge=0.0)

class GraphWindow(BaseModel):
    window_id: str
    window_start: datetime
    window_end: datetime
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    num_nodes: int = Field(ge=0)
    num_edges: int = Field(ge=0)
    source: DataSource

class PredictionResult(BaseModel):
    window_id: str
    attack_probability: float = Field(ge=0.0, le=1.0)
    stage_probabilities: list[float]
    predicted_stage: MitreStage
    embedding: list[float]
    attention_weights: list[float] = []
    source: DataSource = DataSource.REAL

class ForecastStep(BaseModel):
    step_index: int
    window_label: str
    attack_probability: float = Field(ge=0.0, le=1.0)
    predicted_stage: MitreStage
    confidence: float = Field(ge=0.0, le=1.0)

class EvidenceItem(BaseModel):
    evidence_id: str
    timestamp: datetime
    source_type: str
    description: str = Field(min_length=1)
    supports_stage: MitreStage
    confidence_boost: float = Field(ge=0.0, le=1.0)

class FusionResult(BaseModel):
    window_id: str
    fused_probability: float = Field(ge=0.0, le=1.0)
    evidence_items: list[EvidenceItem]
    evidence_match_summary: str
    source: DataSource

class ExplanationResult(BaseModel):
    window_id: str
    shap_values: list[dict[str, Any]]
    calibrated_probability: float = Field(ge=0.0, le=1.0)
    confidence_level: Literal["LOW", "MEDIUM", "HIGH"]
    attention_weights: list[float] = []
    source: DataSource = DataSource.REAL

class MitreMapping(BaseModel):
    window_id: str
    tactics: list[dict[str, Any]]
    source: DataSource

class ReconstructionResult(BaseModel):
    scenario_id: str
    narrative: list[dict[str, Any]]
    raw_log_stream: list[dict[str, str]]
    source: DataSource

class AnalysisResult(BaseModel):
    scenario_id: str
    run_timestamp: datetime
    source: DataSource
    parse_result: dict[str, Any]
    extraction_result: dict[str, Any]
    graph_result: GraphWindow
    prediction_result: PredictionResult
    rollout_result: dict[str, Any]
    fusion_result: FusionResult
    explanation_result: ExplanationResult
    mitre_result: MitreMapping
    reconstruction_result: ReconstructionResult

class HealthResponse(BaseModel):
    status: Literal["ok"]
    service: str
