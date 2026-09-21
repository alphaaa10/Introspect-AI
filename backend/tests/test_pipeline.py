"""
tests/test_pipeline.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from datetime import datetime, timezone

from httpx import AsyncClient, ASGITransport
from app import config
from app.schemas import (
    MitreStage, DataSource, Protocol,
    NetworkEvent, FeatureRecord, GraphWindow, PredictionResult,
    ForecastStep, EvidenceItem, FusionResult, ExplanationResult,
    MitreMapping, ReconstructionResult, AnalysisResult, HealthResponse
)

def _now() -> datetime:
    return datetime.now(tz=timezone.utc)

class TestConfig:
    def test_data_dirs_exist(self):
        assert config.DATA_DIR
        assert config.RAW_DATA_DIR
        assert config.PROCESSED_DATA_DIR
        assert config.SAMPLE_DATA_DIR
        assert config.CHECKPOINTS_DIR

    def test_db_path_is_sqlite_file(self):
        assert config.DB_PATH.suffix == ".db"

    def test_cors_origins_is_list(self):
        assert isinstance(config.CORS_ORIGINS, list)

    def test_api_host_is_string(self):
        assert isinstance(config.API_HOST, str)

    def test_api_port_is_valid(self):
        assert 1 <= config.API_PORT <= 65535

    def test_model_device_is_string(self):
        assert isinstance(config.MODEL_DEVICE, str)

class TestNetworkEvent:
    def _valid(self, **kw):
        base = dict(
            flow_id="f-001", timestamp=_now(),
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12345, dst_port=22, protocol=Protocol.TCP,
            fwd_packets=10, bwd_packets=5,
            fwd_bytes=1000, bwd_bytes=500,
            tcp_flags="SYN", duration_s=1.5,
        )
        base.update(kw)
        return base

    def test_valid_construction(self):
        e = NetworkEvent(**self._valid())
        assert e.src_ip == "10.0.0.1"
        assert e.source == DataSource.REAL

    def test_src_port_out_of_range_rejected(self):
        with pytest.raises(Exception):
            NetworkEvent(**self._valid(src_port=70000))

    def test_negative_bytes_rejected(self):
        with pytest.raises(Exception):
            NetworkEvent(**self._valid(fwd_bytes=-1))

    def test_empty_src_ip_rejected(self):
        with pytest.raises(Exception):
            NetworkEvent(**self._valid(src_ip=""))

class TestFeatureRecord:
    def test_valid_construction(self):
        from app.config import NUM_FEATURES
        r = FeatureRecord(
            window_id="w-001",
            window_start=_now(), window_end=_now(),
            feature_vector=[0.0] * NUM_FEATURES,
            flow_count=42,
        )
        assert r.flow_count == 42

    def test_wrong_length_rejected(self):
        with pytest.raises(Exception):
            FeatureRecord(
                window_id="w-bad",
                window_start=_now(), window_end=_now(),
                feature_vector=[0.0],  # length 1, not NUM_FEATURES
                flow_count=0,
            )

    def test_negative_flow_count_rejected(self):
        from app.config import NUM_FEATURES
        with pytest.raises(Exception):
            FeatureRecord(
                window_id="w-neg",
                window_start=_now(), window_end=_now(),
                feature_vector=[0.0] * NUM_FEATURES,
                flow_count=-1,
            )

class TestGraphWindow:
    def test_valid_construction(self):
        gw = GraphWindow(
            window_id="w-001",
            window_start=_now(), window_end=_now(),
            nodes=[], edges=[],
            num_nodes=0, num_edges=0,
            source=DataSource.REAL,
        )
        assert gw.num_nodes == 0

    def test_negative_num_nodes_rejected(self):
        with pytest.raises(Exception):
            GraphWindow(
                window_id="w-bad",
                window_start=_now(), window_end=_now(),
                nodes=[], edges=[],
                num_nodes=-1, num_edges=0, source=DataSource.REAL,
            )

class TestPredictionResult:
    def _make(self, **kw):
        base = dict(
            window_id="w-001",
            attack_probability=0.82,
            stage_probabilities=[],
            predicted_stage=MitreStage.LATERAL_MOVEMENT,
            embedding=[],
            source=DataSource.REAL,
        )
        base.update(kw)
        return base

    def test_valid_construction(self):
        r = PredictionResult(**self._make())
        assert r.attack_probability == 0.82

    def test_probability_above_1_rejected(self):
        with pytest.raises(Exception):
            PredictionResult(**self._make(attack_probability=1.5))

    def test_probability_below_0_rejected(self):
        with pytest.raises(Exception):
            PredictionResult(**self._make(attack_probability=-0.01))

    def test_invalid_stage_rejected(self):
        with pytest.raises(Exception):
            PredictionResult(**self._make(predicted_stage="NotAStage"))

class TestForecastStep:
    def test_valid(self):
        fs = ForecastStep(
            step_index=1, window_label="t+1",
            attack_probability=0.87, predicted_stage=MitreStage.C2,
            confidence=0.9,
        )
        assert fs.window_label == "t+1"

    def test_confidence_above_1_rejected(self):
        with pytest.raises(Exception):
            ForecastStep(
                step_index=1, window_label="t+1",
                attack_probability=0.5, predicted_stage=MitreStage.C2,
                confidence=1.5,
            )

class TestEvidenceItem:
    def test_valid(self):
        ei = EvidenceItem(
            evidence_id="ev-001", timestamp=_now(),
            source_type="netflow",
            description="SYN flood",
            supports_stage=MitreStage.RECONNAISSANCE,
            confidence_boost=0.3,
        )
        assert ei.source_type == "netflow"

    def test_empty_description_rejected(self):
        with pytest.raises(Exception):
            EvidenceItem(
                evidence_id="ev-002", timestamp=_now(),
                source_type="netflow", description="",
                supports_stage=MitreStage.RECONNAISSANCE,
                confidence_boost=0.1,
            )
            
    def test_confidence_boost_out_of_range_rejected(self):
        with pytest.raises(Exception):
            EvidenceItem(
                evidence_id="ev-003", timestamp=_now(),
                source_type="netflow", description="desc",
                supports_stage=MitreStage.RECONNAISSANCE,
                confidence_boost=2.0,
            )

class TestFusionResult:
    def test_valid(self):
        fr = FusionResult(
            window_id="w-001",
            fused_probability=0.91,
            evidence_items=[],
            evidence_match_summary="3/3 Correlation",
            source=DataSource.REAL,
        )
        assert fr.fused_probability == 0.91

    def test_probability_out_of_range_rejected(self):
        with pytest.raises(Exception):
            FusionResult(
                window_id="w-001",
                fused_probability=1.2,
                evidence_items=[],
                evidence_match_summary="0/0",
                source=DataSource.REAL,
            )

class TestExplanationResult:
    def test_valid(self):
        er = ExplanationResult(
            window_id="w-001",
            shap_values=[],
            calibrated_probability=0.91,
            confidence_level="HIGH",
            source=DataSource.REAL,
        )
        assert er.confidence_level == "HIGH"

    def test_invalid_confidence_level_rejected(self):
        with pytest.raises(Exception):
            ExplanationResult(
                window_id="w-001",
                shap_values=[],
                calibrated_probability=0.5,
                confidence_level="VERY_HIGH",
                source=DataSource.REAL,
            )

    def test_calibrated_probability_out_of_range_rejected(self):
        with pytest.raises(Exception):
            ExplanationResult(
                window_id="w-001",
                shap_values=[],
                calibrated_probability=-0.1,
                confidence_level="LOW",
                source=DataSource.REAL,
            )

class TestMitreMapping:
    def test_valid(self):
        mm = MitreMapping(
            window_id="w-001",
            tactics=[],
            source=DataSource.REAL,
        )
        assert mm.source == DataSource.REAL

class TestReconstructionResult:
    def test_valid(self):
        rr = ReconstructionResult(
            scenario_id="sc-001",
            narrative=[],
            raw_log_stream=[],
            source=DataSource.REAL,
        )
        assert rr.scenario_id == "sc-001"

class TestAnalysisResult:
    def test_valid_full_assembly(self):
        gw = GraphWindow(window_id="w-0", window_start=_now(), window_end=_now(), nodes=[], edges=[], num_nodes=0, num_edges=0, source=DataSource.REAL)
        pr = PredictionResult(window_id="w-0", attack_probability=0.0, stage_probabilities=[], predicted_stage=MitreStage.BENIGN, embedding=[], source=DataSource.REAL)
        fr = FusionResult(window_id="w-0", fused_probability=0.0, evidence_items=[], evidence_match_summary="", source=DataSource.REAL)
        er = ExplanationResult(window_id="w-0", shap_values=[], calibrated_probability=0.0, confidence_level="HIGH", source=DataSource.REAL)
        mm = MitreMapping(window_id="w-0", tactics=[], source=DataSource.REAL)
        rr = ReconstructionResult(scenario_id="s-0", narrative=[], raw_log_stream=[], source=DataSource.REAL)
        
        ar = AnalysisResult(
            scenario_id="sc-001", run_timestamp=_now(), source=DataSource.REAL,
            parse_result={}, extraction_result={}, graph_result=gw,
            prediction_result=pr, rollout_result={}, fusion_result=fr,
            explanation_result=er, mitre_result=mm, reconstruction_result=rr
        )
        assert ar.scenario_id == "sc-001"

from app.main import app as sentinel_app

@pytest.mark.asyncio
async def test_health_returns_200():
    async with AsyncClient(
        transport=ASGITransport(app=sentinel_app), base_url="http://test"
    ) as client:
        response = await client.get("/health")
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_health_returns_correct_json():
    async with AsyncClient(
        transport=ASGITransport(app=sentinel_app), base_url="http://test"
    ) as client:
        response = await client.get("/health")
    body = response.json()
    assert body == {"status": "ok", "service": "sentinel-backend"}

@pytest.mark.asyncio
async def test_health_content_type_is_json():
    async with AsyncClient(
        transport=ASGITransport(app=sentinel_app), base_url="http://test"
    ) as client:
        response = await client.get("/health")
    assert "application/json" in response.headers["content-type"]
