"""
pipeline/analyzer.py  End-to-end analysis orchestrator.

Upload -> parse -> window+extract -> build_graph -> sequence -> WorldModel
(binary detection) + LightGBM StageClassifier (MITRE stage) -> AnalysisContext.

The detector is the shipped all-days checkpoint (checkpoints/deploy_all_days/
sentinel_deploy.pt); the stage source is the selected LightGBM model
(checkpoints/stage_classifier_lgbm.pkl), exactly the deployment configuration.
Both are loaded once and cached.

Returns an AnalysisContext that the scenario builder turns into the dashboard's
scenarioData. Nothing here is dashboard-shaped; that mapping lives in
pipeline/scenario_builder.py so this stays a pure analysis step.
"""

from __future__ import annotations

import bisect
import logging
from dataclasses import dataclass, field
from pathlib import Path

import torch

from app import config
from app.schemas import DataSource, MitreStage, NetworkEvent, GraphWindow
from app.features.extractor import window_and_extract
from app.graph.builder import build_graph, NODE_FEATURE_NAMES, EDGE_FEATURE_NAMES
from app.models.world_model import WorldModel
from app.models.seeding import set_seed
from app.ingestion.flexible_parser import parse_flow_csv
from app.ingestion.schema import CoverageReport

logger = logging.getLogger(__name__)

DEPLOY_CKPT = config.CHECKPOINTS_DIR / "deploy_all_days" / "sentinel_deploy.pt"
STAGE_CKPT = config.CHECKPOINTS_DIR / "stage_classifier_lgbm.pkl"
DEFAULT_THRESHOLD = 0.5      # (1) temporal-holdout sweep found 0.5 already optimal
MAX_EVENTS = 60_000          # responsiveness cap for interactive uploads
DEVICE = torch.device("cpu")

_MODEL: WorldModel | None = None
_STAGE = None  # StageClassifier


def _model_args() -> dict:
    return dict(
        node_in_dim=len(NODE_FEATURE_NAMES), edge_in_dim=len(EDGE_FEATURE_NAMES),
        gat_hidden_dim=128, gat_num_heads=4, gat_out_dim=64, gat_dropout=0.1,
        lstm_hidden_dim=128, lstm_num_layers=2, lstm_dropout=0.1,
        num_mitre_stages=config.NUM_MITRE_STAGES, window_feat_dim=config.NUM_FEATURES,
        mitre_arch="mlp",
    )


def load_models() -> tuple[WorldModel, object]:
    """Load and cache the detector + stage classifier. Raises if either is absent."""
    global _MODEL, _STAGE
    if _MODEL is None:
        if not DEPLOY_CKPT.exists():
            raise FileNotFoundError(
                f"Deployment detector not found at {DEPLOY_CKPT}. Run deploy.py first.")
        config.FEATURE_SCALING = "linear"
        set_seed(config.GLOBAL_SEED)
        m = WorldModel(**_model_args()).to(DEVICE)
        m.load_state_dict(torch.load(DEPLOY_CKPT, map_location=DEVICE, weights_only=True))
        m.eval()
        _MODEL = m
        logger.info(f"Loaded detector {DEPLOY_CKPT.name}")
    if _STAGE is None:
        from app.stage_classifier import StageClassifier
        if not STAGE_CKPT.exists():
            raise FileNotFoundError(
                f"Stage classifier not found at {STAGE_CKPT}. Run stage_classifier.py.")
        _STAGE = StageClassifier.load(STAGE_CKPT)
        logger.info(f"Loaded stage classifier {STAGE_CKPT.name}")
    return _MODEL, _STAGE


@dataclass
class WindowResult:
    index: int
    window_id: str
    window_start: object
    window_end: object
    attack_prob: float
    is_attack: bool
    stage_idx: int            # MitreStage index (0=BENIGN); attack windows only, else 0
    stage: str                # MitreStage.value
    flow_count: int


@dataclass
class AnalysisContext:
    events: list[NetworkEvent]
    windows: list[GraphWindow]
    results: list[WindowResult]
    coverage: CoverageReport
    threshold: float
    stage_clf: object
    n_events: int
    truncated: bool = False
    meta: dict = field(default_factory=dict)


def _build_sequences(windows: list[GraphWindow]) -> list[list[GraphWindow]]:
    """For each window i, the sequence windows[max(0,i-SEQ+1) .. i] — the same
    windowing create_sequences uses, without labels (inference needs none)."""
    seq_len = config.SEQUENCE_LENGTH
    return [windows[max(0, i - seq_len + 1): i + 1] for i in range(len(windows))]


def analyze_csv(
    text_or_path,
    threshold: float = DEFAULT_THRESHOLD,
    source: DataSource = DataSource.REAL,
) -> AnalysisContext:
    """Full pipeline on one uploaded flow-log CSV. Raises CoverageError (from the
    parser) if coverage < 18/21; the API turns that into a 422."""
    model, stage_clf = load_models()

    events, coverage = parse_flow_csv(text_or_path, source=source)
    truncated = False
    if len(events) > MAX_EVENTS:
        events = events[:MAX_EVENTS]      # chronological truncation
        truncated = True
    if not events:
        raise ValueError("No valid rows parsed from the uploaded file.")

    feature_records = window_and_extract(events)
    # map events -> their window for graph construction
    events_by_window: dict = {}
    starts = [fr.window_start for fr in feature_records]
    for e in events:
        idx = bisect.bisect_right(starts, e.timestamp) - 1
        if idx >= 0:
            fr = feature_records[idx]
            if fr.window_start <= e.timestamp < fr.window_end:
                events_by_window.setdefault(fr.window_id, []).append(e)

    windows: list[GraphWindow] = []
    for fr in feature_records:
        windows.append(build_graph(
            events_by_window.get(fr.window_id, []),
            fr.window_id, fr.window_start, fr.window_end, fr.source,
            window_features=fr.feature_vector,
        ))

    sequences = _build_sequences(windows)
    stages = list(MitreStage)
    results: list[WindowResult] = []
    with torch.no_grad():
        for i, (w, seq) in enumerate(zip(windows, sequences)):
            pred = model(seq)  # documented single-sequence inference path
            p = float(pred.attack_probability)
            is_attack = p >= threshold
            stage_idx, stage_name = 0, MitreStage.BENIGN.value
            if is_attack and w.window_features:
                stage_idx = int(stage_clf.predict([list(w.window_features)])[0])
                stage_name = stages[stage_idx].value
            results.append(WindowResult(
                index=i, window_id=w.window_id,
                window_start=w.window_start, window_end=w.window_end,
                attack_prob=p, is_attack=is_attack,
                stage_idx=stage_idx, stage=stage_name,
                flow_count=len(events_by_window.get(w.window_id, [])),
            ))

    return AnalysisContext(
        events=events, windows=windows, results=results, coverage=coverage,
        threshold=threshold, stage_clf=stage_clf, n_events=len(events),
        truncated=truncated,
    )
