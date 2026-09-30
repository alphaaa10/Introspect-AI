"""
explainability/shap_view.py  Feature-attribution view for the Profiling panel.

Feeds scenarioData.shapValues + .explainabilityMeta. These are the LightGBM stage
classifier's GLOBAL feature importances (normalised), not per-window SHAP values
— an honest approximation the vertical slice ships; a true per-instance SHAP/
attention attribution is the follow-up. Importances are non-negative, so all
directions are 'positive'.
"""

from __future__ import annotations

# Prettier labels for the 21 canonical features; unlisted names pass through.
_LABEL = {
    "syn_flag_cnt": "SYN flag count", "ack_flag_cnt": "ACK flag count",
    "psh_flag_cnt": "PSH flag count", "fin_flag_cnt": "FIN flag count",
    "rst_flag_cnt": "RST flag count", "unique_dst_ports": "Unique dst ports",
    "unique_dst_ips": "Unique dst IPs", "flow_pkts_per_s": "Flow packets/s",
    "flow_bytes_per_s": "Flow bytes/s", "fwd_pkt_len_mean": "Fwd pkt length mean",
    "bwd_pkt_len_mean": "Bwd pkt length mean", "iat_mean": "Inter-arrival mean",
    "iat_std": "Inter-arrival std", "dst_port": "Dst port", "src_port": "Src port",
    "protocol_type": "Protocol", "duration": "Flow duration",
    "fwd_packets": "Fwd packets", "bwd_packets": "Bwd packets",
    "fwd_bytes": "Fwd bytes", "bwd_bytes": "Bwd bytes",
}


def build_explainability(ctx, top_n: int = 7) -> dict:
    clf = ctx.stage_clf
    names = list(getattr(clf, "feature_names", []))
    try:
        imp = list(clf.feature_importances_)
    except Exception:
        imp = []

    shap_values = []
    if names and imp and len(names) == len(imp):
        total = float(sum(imp)) or 1.0
        ranked = sorted(zip(names, imp), key=lambda x: x[1], reverse=True)[:top_n]
        for name, val in ranked:
            shap_values.append({
                "feature": _LABEL.get(name, name),
                "value": round(float(val) / total, 3),
                "direction": "positive",
            })

    attack_probs = [r.attack_prob for r in ctx.results if r.is_attack]
    peak = max(attack_probs) if attack_probs else (
        max((r.attack_prob for r in ctx.results), default=0.0))
    conf = "HIGH" if peak >= 0.8 else "MEDIUM" if peak >= 0.5 else "LOW"
    n_stages = len({r.stage_idx for r in ctx.results if r.is_attack and r.stage_idx})

    meta = {
        "calibratedProbability": f"{round(100 * peak)}%",
        "confidenceLevel": conf,
        "evidenceMatch": f"{n_stages}/7 stages",
    }
    return {"shapValues": shap_values, "explainabilityMeta": meta}
