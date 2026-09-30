"""
pipeline/scenario_builder.py  Map an AnalysisContext onto the dashboard's
scenarioData shape (the exact contract src/data/mockScenarios.js defines).

Composes the per-domain assemblers (mitre, correlation, forecasting,
explainability, reconstruction) and fills the remaining overview/detections/
profile keys here. Output drops straight into the React dashboard so every panel
renders from the uploaded file.
"""

from __future__ import annotations

from app.mitre.stages import build_mitre_stages, STAGE_META
from app.correlation.graph_view import build_graph_view
from app.forecasting.forecast import build_infiltration_timeline
from app.explainability.shap_view import build_explainability
from app.reconstruction.narrative import build_narrative

_CAT_CLASS = {1: "recon", 2: "init", 3: "cred", 4: "lateral", 5: "cc", 6: "exfil", 7: "impact"}


def _hhmm(ts):
    try:
        return ts.strftime("%H:%M")
    except Exception:
        return ""


def _hhmmss_ms(ts):
    try:
        return ts.strftime("%H:%M:%S.") + f"{ts.microsecond // 1000:03d}"
    except Exception:
        return ""


def _overview(ctx, stage_names):
    results = ctx.results
    n_windows = len(results)
    attack_windows = [r for r in results if r.is_attack]
    malicious_flows = sum(r.flow_count for r in attack_windows)
    probs = [r.attack_prob for r in results]
    peak = max(probs) if probs else 0.0
    last = results[-1].attack_prob if results else 0.0
    return {
        "totalFlows": ctx.n_events,
        "maliciousFlows": malicious_flows,
        "activeAlerts": len(stage_names),
        "dataset": "Uploaded logs",
        "subset": f"feature coverage {ctx.coverage.n_covered}/21",
        "rows": f"{ctx.n_events:,} flows" + (" (truncated)" if ctx.truncated else ""),
        "features": ctx.coverage.n_covered,
        "duration": f"{n_windows} × 60s windows",
        "attackTypes": stage_names or ["None detected"],
        "worldModelConfidence": round(100 * peak),
        "worldModelTrend": ("Rising" if last >= (probs[max(0, len(probs) - 4)] if probs else 0)
                            else "Easing") + f" — latest {round(100 * last)}%",
        "infiltrationProbability": round(peak, 3),
    }


def _detections(ctx):
    by_stage_first, by_stage_last = {}, {}
    for r in ctx.results:
        if r.is_attack and 1 <= r.stage_idx <= 7:
            by_stage_first.setdefault(r.stage_idx, r)
            by_stage_last[r.stage_idx] = r
    out = []
    for k, idx in enumerate(STAGE_META):
        fr = by_stage_first.get(idx)
        if not fr:
            continue
        lr = by_stage_last[idx]
        out.append({
            "id": f"d{k}", "category": STAGE_META[idx]["name"],
            "categoryClass": _CAT_CLASS.get(idx, "info"),
            "type": f"{STAGE_META[idx]['name']} activity",
            "status": "Active", "statusClass": "active",
            "firstSeen": str(fr.window_start), "lastSeen": str(lr.window_end),
        })
    return out


def _urgency_timeline(ctx, max_points=13):
    results = ctx.results
    if not results:
        return []
    step = max(1, len(results) // max_points)
    pts = []
    for r in results[::step]:
        pts.append({"time": _hhmm(r.window_start), "value": round(100 * r.attack_prob)})
    return pts


def _network_logs(ctx, limit=25):
    # map event -> whether its window was flagged, for severity
    attack_wids = {r.window_id for r in ctx.results if r.is_attack}
    # build window bounds for a quick membership test
    logs = []
    for i, e in enumerate(ctx.events[:limit]):
        benign = e.label.lower() in ("benign", "unknown", "")
        sev = "low" if benign else "critical"
        logs.append({
            "id": i + 1, "ts": _hhmmss_ms(e.timestamp), "src": e.src_ip, "dst": e.dst_ip,
            "proto": e.protocol.value, "port": e.dst_port, "flags": e.tcp_flags or "-",
            "bytes": e.fwd_bytes + e.bwd_bytes, "label": e.label, "severity": sev,
        })
    return logs


def _attack_profile(ctx, stage_names):
    return {
        "classification": "Detected Adversary Activity" if stage_names else "No Attack Detected",
        "description": (
            "Model flagged " + ", ".join(stage_names) + " across the uploaded traffic."
            if stage_names else
            "No windows exceeded the detection threshold in the uploaded traffic."),
        "positiveIndicators": stage_names,
    }


def _build_alerts(ctx, max_alerts=12, top_k=5):
    """Per-alert-window top-K GAT-attended edges (read-only extraction)."""
    attack = [r for r in ctx.results if r.is_attack]
    if not attack or ctx.model is None:
        return []
    strongest = sorted(attack, key=lambda r: r.attack_prob, reverse=True)[:max_alerts]
    seq = [ctx.windows[r.index] for r in strongest]
    att = ctx.model.attention_for_sequence(seq, top_k=top_k)
    alerts = [{
        "window_id": r.window_id,
        "attack_probability": round(r.attack_prob, 4),
        "predicted_stage": r.stage,
        "top_attended_edges": a["top_edges"],
    } for r, a in zip(strongest, att)]
    alerts.sort(key=lambda x: x["window_id"])  # chronological (zero-padded ids)
    return alerts


def build_scenario(ctx) -> dict:
    mitre = build_mitre_stages(ctx)
    gv = build_graph_view(ctx)
    stage_names = [s["name"] for s in mitre if s["status"] in ("confirmed", "current")]

    expl = build_explainability(ctx)
    narr = build_narrative(ctx)
    alerts = _build_alerts(ctx)

    return {
        "name": f"Uploaded analysis — {ctx.n_events:,} flows, "
                f"{sum(1 for r in ctx.results if r.is_attack)} attack window(s)",
        "overviewStats": _overview(ctx, stage_names),
        "hosts": gv["hosts"],
        "attackProfile": _attack_profile(ctx, stage_names),
        "mitreStages": mitre,
        "urgencyTimeline": _urgency_timeline(ctx),
        "detections": _detections(ctx),
        "infiltrationTimeline": build_infiltration_timeline(ctx),
        "shapValues": expl["shapValues"],
        "explainabilityMeta": expl["explainabilityMeta"],
        "networkLogs": _network_logs(ctx),
        "narrativeEntries": narr["narrativeEntries"],
        "rawLogStream": narr["rawLogStream"],
        "graphNodes": gv["graphNodes"],
        "graphEdges": gv["graphEdges"],
        "alerts": alerts,
    }
