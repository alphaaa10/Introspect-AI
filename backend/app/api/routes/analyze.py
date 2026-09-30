"""
api/routes/analyze.py  Upload -> analyze endpoint.

POST /api/analyze  (multipart form-data, field 'file': a flow-log CSV)
  200 -> { scenario, coverage, warnings, meta }   dashboard-ready scenarioData
  422 -> { message, coverage }                     coverage < 18/21 (refused)
  400 -> parse/other client errors
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.ingestion.flexible_parser import CoverageError
from app.pipeline.analyzer import analyze_csv, DEFAULT_THRESHOLD
from app.pipeline.scenario_builder import build_scenario

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["analysis"])


def _decode(raw: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    raise HTTPException(status_code=400, detail="Could not decode file (expected UTF-8/CSV text).")


@router.get("/analyze/health")
def analyze_health() -> dict:
    return {"status": "ok", "endpoint": "analyze"}


@router.post("/analyze")
async def analyze(file: UploadFile = File(...)) -> dict:
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Empty file.")
    text = _decode(raw)

    try:
        ctx = analyze_csv(text, threshold=DEFAULT_THRESHOLD)
    except CoverageError as ce:
        # Refusal: below the 18/21 minimum. Hand the report back for the UI.
        raise HTTPException(status_code=422, detail={
            "message": (f"Feature coverage {ce.report.n_covered}/21 is below the required "
                        f"minimum of 18. Cannot analyze without fabricating features."),
            "coverage": ce.report.to_dict(),
        })
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except FileNotFoundError as fe:
        # Missing model checkpoints — a server misconfiguration, not the user's fault.
        logger.error(f"Model checkpoint missing: {fe}")
        raise HTTPException(status_code=503, detail=str(fe))

    scenario = build_scenario(ctx)
    cov = ctx.coverage.to_dict()
    warnings = []
    if not ctx.coverage.full:
        warnings.append(
            f"Proceeding with {cov['n_covered']}/21 features. Missing (not imputed): "
            + ", ".join(cov["missing"]))
    if ctx.truncated:
        warnings.append(f"File truncated to the first {ctx.n_events} flows for responsiveness.")

    return {
        "scenario": scenario,
        "coverage": cov,
        "warnings": warnings,
        "meta": {
            "filename": file.filename,
            "n_events": ctx.n_events,
            "n_windows": len(ctx.windows),
            "n_attack_windows": sum(1 for r in ctx.results if r.is_attack),
            "threshold": ctx.threshold,
        },
    }
