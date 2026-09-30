"""
explainability/shap_view.py  Real SHAP attribution for the LightGBM stage
classifier (exact TreeExplainer).

Feeds scenarioData.shapValues + .explainabilityMeta. For each predicted stage we
take a representative window (the highest-probability attack window for that
stage) and compute exact, SIGNED per-feature SHAP contributions toward that
stage's class:

    {"stage": "Credential Access", "confidence": 0.92,
     "shap_values": [{"feature": "dst_port", "value": 0.0003, "shap": 0.31}, ...]}

Positive shap pushes the window toward that stage; negative pushes away.
TreeExplainer is exact (additivity: expected_value[c] + sum(shap[c]) == raw
margin[c]) and runs in a few ms per window. SHAP is applied ONLY to the LightGBM
stage classifier — never to the GAT+LSTM detector.
"""

from __future__ import annotations

import numpy as np

from app.mitre.stages import STAGE_META

# Prettier labels for the 21 canonical features; the raw name is kept in
# `feature` (matching the requested contract), `label` is for display.
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


def _norm3d(sv) -> np.ndarray:
    """Normalise TreeExplainer output to (n_samples, n_features, n_classes)."""
    if isinstance(sv, list):                       # legacy: per-class list
        return np.stack([np.asarray(a, dtype=float) for a in sv], axis=-1)
    a = np.asarray(sv, dtype=float)
    if a.ndim == 3:                                # shap>=0.45 multiclass
        return a
    if a.ndim == 2:                                # binary
        return a[:, :, None]
    raise ValueError(f"Unexpected SHAP shape {a.shape}")


def _empty_meta(ctx) -> dict:
    probs = [r.attack_prob for r in ctx.results]
    peak = max(probs) if probs else 0.0
    return {
        "method": "SHAP (TreeExplainer, LightGBM)",
        "stage": None, "confidence": 0.0,
        "calibratedProbability": f"{round(100 * peak)}%",
        "confidenceLevel": "LOW",
        "evidenceMatch": "0/7 stages",
        "stageAttributions": [],
    }


def build_explainability(ctx, top_n: int = 10) -> dict:
    import shap  # imported lazily so the rest of the pipeline never needs it

    clf = ctx.stage_clf
    windows = ctx.windows
    names = list(getattr(clf, "feature_names", []))
    le = getattr(clf, "_le", None)

    attack = [r for r in ctx.results
              if r.is_attack and 1 <= r.stage_idx <= 7
              and windows[r.index].window_features]

    if not attack or le is None or not names:
        return {"shapValues": [], "explainabilityMeta": _empty_meta(ctx)}

    le_classes = list(le.classes_)  # column c of shap == original stage le_classes[c]

    # One representative window per predicted stage: its highest-prob window.
    reps: dict[int, object] = {}
    for r in attack:
        if r.stage_idx not in reps or r.attack_prob > reps[r.stage_idx].attack_prob:
            reps[r.stage_idx] = r
    stage_idxs = sorted(reps, key=lambda s: reps[s].attack_prob, reverse=True)

    X = np.array([list(windows[reps[s].index].window_features) for s in stage_idxs],
                 dtype=float)

    explainer = shap.TreeExplainer(clf.model)
    sv = _norm3d(explainer.shap_values(X))                 # (n, feat, nclass)
    ev = np.atleast_1d(np.asarray(explainer.expected_value, dtype=float))
    proba = clf.model.predict_proba(X)
    raw = np.atleast_2d(clf.model.predict(X, raw_score=True))

    stage_attrs = []
    for i, s in enumerate(stage_idxs):
        e = le_classes.index(s)
        shap_row = sv[i, :, e]
        residual = float(abs(ev[e] + float(shap_row.sum()) - float(raw[i, e])))
        feats = sorted(
            ({"feature": names[j], "label": _LABEL.get(names[j], names[j]),
              "value": round(float(X[i, j]), 5), "shap": round(float(shap_row[j]), 5)}
             for j in range(len(names))),
            key=lambda d: abs(d["shap"]), reverse=True,
        )[:top_n]
        stage_attrs.append({
            "stage": STAGE_META[s]["name"], "stageId": STAGE_META[s]["id"],
            "confidence": round(float(proba[i, e]), 4),
            "baseline": round(float(ev[e]), 5),
            "additivityResidual": residual,
            "shap_values": feats,
        })

    primary = stage_attrs[0]
    peak = reps[stage_idxs[0]].attack_prob
    conf_level = "HIGH" if peak >= 0.8 else "MEDIUM" if peak >= 0.5 else "LOW"
    meta = {
        "method": "SHAP (TreeExplainer, LightGBM)",
        "stage": primary["stage"],
        "confidence": primary["confidence"],
        "calibratedProbability": f"{round(100 * peak)}%",
        "confidenceLevel": conf_level,
        "evidenceMatch": f"{len(reps)}/7 stages",
        "additivityResidual": primary["additivityResidual"],
        "stageAttributions": stage_attrs,
    }
    # shapValues (primary stage) is what the panel renders by default.
    return {"shapValues": primary["shap_values"], "explainabilityMeta": meta}
