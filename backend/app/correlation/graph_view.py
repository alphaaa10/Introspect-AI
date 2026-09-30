"""
correlation/graph_view.py  Build the interactive attack graph (React Flow nodes/
edges) and host entities from the parsed flows + detected stages.

Feeds scenarioData.graphNodes, .graphEdges, .hosts. Topology is model/flow-real
(top talker as attacker, real destination fan-out); node styling matches the
shapes the AttackGraph component already renders for the mock scenarios.
"""

from __future__ import annotations

from collections import defaultdict

from app.mitre.stages import STAGE_META

_RED = {"stroke": "#ef4444", "strokeWidth": 2}
_GREY = {"stroke": "#94a3b8", "strokeWidth": 1.5}


def _talkers(events):
    out_dsts = defaultdict(set)
    in_count = defaultdict(int)
    flow_count = defaultdict(int)
    for e in events:
        out_dsts[e.src_ip].add(e.dst_ip)
        in_count[e.dst_ip] += 1
        flow_count[e.src_ip] += 1
    return out_dsts, in_count, flow_count


def build_graph_view(ctx) -> dict:
    events = ctx.events
    out_dsts, in_count, flow_count = _talkers(events)
    if not out_dsts:
        return {"graphNodes": [], "graphEdges": [], "hosts": {"attacker": None, "targets": []}}

    # Attacker = highest out-degree (distinct destinations), tie-broken by flows.
    attacker_ip = max(out_dsts, key=lambda ip: (len(out_dsts[ip]), flow_count[ip]))
    dsts = sorted(out_dsts[attacker_ip], key=lambda ip: in_count[ip], reverse=True)

    # Detected stages, in kill-chain order, as the "attack type" nodes.
    seen = {r.stage_idx for r in ctx.results if r.is_attack and 1 <= r.stage_idx <= 7}
    stage_idxs = [i for i in STAGE_META if i in seen] or []

    nodes = [{
        "id": "attacker-main", "type": "attackNode", "position": {"x": 420, "y": 270},
        "data": {"label": attacker_ip, "sublabel": f"{flow_count[attacker_ip]} flows",
                 "nodeType": "attacker", "icon": "monitor"},
    }]
    edges = []

    n = max(len(stage_idxs), 1)
    for k, idx in enumerate(stage_idxs):
        y = 80 + k * (380 // n)
        sid = f"atk-{STAGE_META[idx]['id'].lower()}"
        nodes.append({
            "id": sid, "type": "attackTypeNode", "position": {"x": 650, "y": y},
            "data": {"label": STAGE_META[idx]["name"]},
        })
        edges.append({"id": f"e-m-{sid}", "source": "attacker-main", "target": sid,
                      "animated": True, "type": "smoothstep", "style": dict(_RED)})

    # Target fan-out node(s): one group node summarising distinct destinations.
    tg_id = "tg-main"
    nodes.append({
        "id": tg_id, "type": "targetGroupNode", "position": {"x": 880, "y": 250},
        "data": {"count": len(dsts), "label": "internal targets"},
    })
    for k, idx in enumerate(stage_idxs):
        sid = f"atk-{STAGE_META[idx]['id'].lower()}"
        edges.append({"id": f"e-{sid}-tg", "source": sid, "target": tg_id,
                      "type": "smoothstep", "style": dict(_GREY)})
    if not stage_idxs:
        edges.append({"id": "e-m-tg", "source": "attacker-main", "target": tg_id,
                      "animated": True, "type": "smoothstep", "style": dict(_RED)})

    hosts = {
        "attacker": {
            "id": "attacker-1", "ip": attacker_ip, "hostname": "unknown",
            "os": "unknown", "sensor": "upload", "privilege": "unknown",
            "lastSeen": str(events[-1].timestamp), "roles": [],
            "entityImportance": "High" if len(dsts) > 10 else "Medium",
            "attackRating": min(10, 1 + len(seen) + (len(dsts) > 10)),
            "velocity": "High" if flow_count[attacker_ip] > 500 else "Medium",
            "urgencyScore": min(100, 10 * len(seen) + (len(dsts) > 10) * 20),
            "priorityStatus": "Prioritized" if seen else "Monitoring",
        },
        "targets": [
            {"id": f"target-{k}", "ip": ip, "hostname": "unknown",
             "flows": in_count[ip]}
            for k, ip in enumerate(dsts[:5])
        ],
    }
    return {"graphNodes": nodes, "graphEdges": edges, "hosts": hosts}
