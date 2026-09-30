"""
mitre/stages.py  Build the dashboard's MITRE stage progression from per-window
LightGBM stage predictions over attack windows.

Feeds scenarioData.mitreStages: the seven attack stages in kill-chain order,
each marked confirmed / current / inactive with a confidence for the current one.
"""

from __future__ import annotations

from app.schemas import MitreStage

# MitreStage index (0=BENIGN, 1..7 attack) -> dashboard stage card metadata.
STAGE_META = {
    1: {"id": "RECON",   "name": "Reconnaissance",     "icon": "\U0001F50D"},
    2: {"id": "INIT",    "name": "Initial Access",      "icon": "\U0001F6AA"},
    3: {"id": "CRED",    "name": "Credential Access",   "icon": "\U0001F511"},
    4: {"id": "LATERAL", "name": "Lateral Movement",    "icon": "⚡"},
    5: {"id": "C2",      "name": "Command & Control",   "icon": "\U0001F4E1"},
    6: {"id": "EXFIL",   "name": "Exfiltration",        "icon": "\U0001F4E4"},
    7: {"id": "IMPACT",  "name": "Impact",              "icon": "\U0001F4A5"},
}
ATTACK_IDXS = list(STAGE_META.keys())  # 1..7 in kill-chain order


def build_mitre_stages(ctx) -> list[dict]:
    attack = [r for r in ctx.results if r.is_attack and 1 <= r.stage_idx <= 7]
    counts: dict[int, int] = {}
    prob_sum: dict[int, float] = {}
    for r in attack:
        counts[r.stage_idx] = counts.get(r.stage_idx, 0) + 1
        prob_sum[r.stage_idx] = prob_sum.get(r.stage_idx, 0.0) + r.attack_prob

    # "current" = stage of the most-recent attack window.
    current_idx = attack[-1].stage_idx if attack else None

    out = []
    for idx in ATTACK_IDXS:
        meta = STAGE_META[idx]
        c = counts.get(idx, 0)
        if idx == current_idx:
            status = "current"
            prob = f"{round(100 * prob_sum[idx] / c)}%" if c else None
            desc = f"Active now — {c} window(s), avg P={prob}"
        elif c > 0:
            status = "confirmed"
            prob = None
            desc = f"Detected in {c} window(s)"
        else:
            status = "inactive"
            prob = None
            desc = "Not detected"
        out.append({
            "id": meta["id"], "name": meta["name"], "icon": meta["icon"],
            "status": status, "desc": desc, "prob": prob,
        })
    return out


def stage_name(idx: int) -> str:
    return list(MitreStage)[idx].value if 0 <= idx < len(list(MitreStage)) else "Unknown"
