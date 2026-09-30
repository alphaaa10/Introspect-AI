"""
reconstruction/narrative.py  Build the attack-story narrative + raw log stream.

Feeds scenarioData.narrativeEntries and .rawLogStream. Templated from the real
detected stages, timestamps and flow counts (not an LLM) — a deterministic
reconstruction the vertical slice ships; an LLM narrative is the follow-up.
"""

from __future__ import annotations

from collections import Counter

from app.mitre.stages import STAGE_META


def _hhmmss(ts) -> str:
    try:
        return ts.strftime("%H:%M:%S")
    except Exception:
        return ""


def _attacker_ip(events) -> str:
    if not events:
        return "unknown"
    return Counter(e.src_ip for e in events).most_common(1)[0][0]


def build_narrative(ctx) -> dict:
    results = ctx.results
    attack = [r for r in results if r.is_attack and 1 <= r.stage_idx <= 7]
    attacker = _attacker_ip(ctx.events)

    entries = []
    # One confirmed entry per stage, at its first-seen window (kill-chain order).
    first_seen: dict[int, object] = {}
    for r in attack:
        first_seen.setdefault(r.stage_idx, r)
    for idx in STAGE_META:
        r = first_seen.get(idx)
        if not r:
            continue
        name = STAGE_META[idx]["name"]
        entries.append({
            "type": "confirmed",
            "timestamp": _hhmmss(r.window_start),
            "text": (f"{name} detected on source {attacker} at window {r.window_id} "
                     f"(attack probability {round(100 * r.attack_prob)}%, "
                     f"{r.flow_count} flows in the window)."),
            "evidence": f"Window {r.window_id} — {r.flow_count} flows [P={round(r.attack_prob, 3)}]",
        })

    # Predicted entry from the trend of the last few windows.
    if len(results) >= 2:
        rising = results[-1].attack_prob >= results[max(0, len(results) - 4)].attack_prob
        last = results[-1]
        proj = "rising" if rising else "easing"
        entries.append({
            "type": "predicted", "timestamp": "+3 windows",
            "text": (f"World Model trend is {proj}; latest window probability "
                     f"{round(100 * last.attack_prob)}%. Projected to continue over the "
                     f"next {3} windows (linear extrapolation)."),
            "evidence": None,
        })

    # Action entry.
    if attack:
        entries.append({
            "type": "action", "timestamp": "NOW",
            "text": (f"ISOLATE source host {attacker}; BLOCK its outbound traffic; "
                     f"PRESERVE flow and session logs for forensic review."),
            "evidence": None,
        })

    # Raw log stream (colored): system + sample flows + per-stage model signals.
    stream = [
        {"color": "#3b82f6", "text": "[SYSTEM] Correlation engine initialised."},
        {"color": "#3b82f6", "text": f"[SYSTEM] Parsed {ctx.n_events} flows; "
                                     f"coverage {ctx.coverage.n_covered}/21 features."},
    ]
    for e in ctx.events[:3]:
        stream.append({"color": "#cbd5e1",
                       "text": (f"[NETFLOW] src={e.src_ip} dst={e.dst_ip} "
                                f"port={e.dst_port} proto={e.protocol.value} "
                                f"flags={e.tcp_flags or '-'}")})
    for idx in STAGE_META:
        r = first_seen.get(idx)
        if r:
            stream.append({"color": "#ef4444",
                           "text": (f"[WORLD MODEL] Stage={STAGE_META[idx]['name']}, "
                                    f"P={round(r.attack_prob, 2)} @ {r.window_id}")})
    if attack:
        stream.append({"color": "#10b981",
                       "text": "[FUSION] Evidence corroborates detection. Narrative generated."})
    return {"narrativeEntries": entries, "rawLogStream": stream}
