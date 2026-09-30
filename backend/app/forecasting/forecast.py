"""
forecasting/forecast.py  Build the infiltration timeline.

Feeds scenarioData.infiltrationTimeline: the observed per-window attack
probability (type 'real') followed by a short K-step extrapolation
(type 'predicted'). The forecast is an explicit linear trend extrapolation of the
recent probabilities, NOT a learned forecaster — labelled 'predicted' so the UI
renders it as the dashed projection and never confuses it with observed data.
"""

from __future__ import annotations

FORECAST_STEPS = 3
OBSERVED_WINDOW = 12  # how many recent real windows to show


def _hhmm(ts) -> str:
    try:
        return ts.strftime("%H:%M")
    except Exception:
        return ""


def build_infiltration_timeline(ctx) -> list[dict]:
    results = ctx.results
    if not results:
        return []

    recent = results[-OBSERVED_WINDOW:]
    n = len(recent)
    points = []
    for k, r in enumerate(recent):
        label = "NOW" if k == n - 1 else f"t-{n - 1 - k}"
        points.append({
            "window": label, "time": _hhmm(r.window_start),
            "probability": round(r.attack_prob, 3),
            "tactic": r.stage if r.is_attack else "Benign",
            "type": "real",
        })

    # Linear trend from the last few observed probabilities.
    tail = [r.attack_prob for r in recent[-4:]]
    if len(tail) >= 2:
        slope = (tail[-1] - tail[0]) / (len(tail) - 1)
    else:
        slope = 0.0
    last_p = recent[-1].attack_prob
    last_tactic = recent[-1].stage if recent[-1].is_attack else "Benign"
    for step in range(1, FORECAST_STEPS + 1):
        proj = max(0.0, min(1.0, last_p + slope * step))
        points.append({
            "window": f"t+{step}", "time": "",
            "probability": round(proj, 3),
            "tactic": last_tactic, "type": "predicted",
        })
    return points
