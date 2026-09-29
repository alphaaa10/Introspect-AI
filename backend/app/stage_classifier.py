"""
app/stage_classifier.py  Random Forest MITRE-stage classifier.

Why this module exists
----------------------
The deep detector (GAT + LSTM) is excellent at the *binary* question — is this
60-second window an attack? — but its MITRE *stage* head is not. On the blocked
5-fold run (checkpoints/full_blocked_2stage_mlp/lodo_results.json) the stage
head scores a macro-F1 around 0.16 and predicts Credential Access with F1 = 0.0
on 97 support, i.e. it never gets that stage right. The stage head is a small
MLP on top of the *binary* LSTM summary, so it only sees what the detector
needed to answer "attack or not", not what separates one attack family from
another.

This module answers "given that a window is an attack, which stage is it?"
directly from the 21 hand-engineered flow features (config.FEATURE_NAMES) with a
Random Forest. Those features — flag counts, unique_dst_ports, IAT stats,
pkts/s, byte rates — are exactly the discriminators that tell a port scan from a
brute force from a DDoS, so a shallow tree ensemble on them is a strong,
interpretable baseline for the stage question and a clean ablation against the
deep head.

Contract with the deep model
-----------------------------
* Trains on ATTACK windows ONLY (is_attack == 1). Benign windows are the binary
  head's job; mixing them in here would let BENIGN dominate exactly as it did in
  the deep head's failure mode.
* One example per sequence, taken from the target (last) window's
  `window_features`, so labels line up with the deep model's per-sequence target.
* Evaluated with train.make_blocked_folds at n_splits=5, block_size=40 — the
  identical, purged fold structure the deep blocked run used, so the numbers are
  comparable and leak-free at the label level (purging drops any training
  sequence whose label window overlaps a held-out block).

Run it (from backend/):
    python -m app.stage_classifier
    python -m app.stage_classifier --no-cache          # force a re-parse
    python -m app.stage_classifier --data-dir data/raw --save checkpoints/stage_classifier.pkl
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import pickle
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_recall_fscore_support
from sklearn.preprocessing import LabelEncoder

from app import config
from app.schemas import DataSource, MitreStage
from app.ingestion.parser import parse_cicids2017_csv
from app.features.extractor import window_and_extract
from app.graph.builder import build_graph
from app.models.seeding import set_seed

# train.py owns the fold generator and the sequence/label builder. Import them —
# never reimplement — so this experiment sees exactly the fold membership and
# window labels the deep model was trained and scored on.
from train import make_blocked_folds, create_sequences

STAGE_NAMES: list[str] = [s.value for s in MitreStage]  # index == mitre_idx
FEATURE_NAMES: list[str] = list(config.FEATURE_NAMES)
# Each model has its own checkpoint path so a comparison run never clobbers
# another model's baseline. LightGBM is the selected deployment stage classifier.
CKPT_BY_MODEL = {
    "rf": Path("checkpoints/stage_classifier_rf.pkl"),
    "xgb": Path("checkpoints/stage_classifier_xgb.pkl"),
    "lgbm": Path("checkpoints/stage_classifier_lgbm.pkl"),
}
DEFAULT_CKPT = CKPT_BY_MODEL["rf"]
MODEL_LABELS = {"rf": "Random Forest", "xgb": "XGBoost", "lgbm": "LightGBM"}
DEFAULT_DEEP_RESULTS = Path("checkpoints/full_blocked_2stage_mlp/lodo_results.json")

DAYS = ["monday", "tuesday", "wednesday", "thursday", "friday"]
BLOCK_SIZE = 40   # matches the deep blocked run ("85 blocks of 40")
N_SPLITS = 5
MIN_SUPPORT = 20  # stages below this support are excluded from the headline macro-F1


# ══════════════════════════════════════════════════════════════
# The classifier
# ══════════════════════════════════════════════════════════════

class _FeatWindow:
    """A one-window stand-in so `seq[-1].window_features` works on the light,
    cached feature pools exactly as it does on the deep model's GraphWindow
    sequences. Lets fold generation and feature extraction share one code path."""
    __slots__ = ("window_features",)

    def __init__(self, features: list[float]):
        self.window_features = features


def _build_estimator(model: str, class_weight: str | dict | None, random_state: int, n_jobs: int):
    """Construct the underlying estimator for a model type.

    Hyperparameters are the spec's, chosen conservative for ~1,200 training
    windows per fold (shallow/limited-leaf trees, modest count, lr 0.1). No
    balanced weighting for any model: the earlier ablation showed the natural
    distribution is the honest baseline, so all three train on it.
    """
    if model == "rf":
        return RandomForestClassifier(
            n_estimators=200, max_depth=None,
            class_weight=class_weight, random_state=random_state, n_jobs=n_jobs,
        )
    if model == "xgb":
        from xgboost import XGBClassifier
        return XGBClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.1, tree_method="hist",
            random_state=random_state, n_jobs=n_jobs, verbosity=0,
        )
    if model == "lgbm":
        from lightgbm import LGBMClassifier
        return LGBMClassifier(
            n_estimators=200, max_depth=-1, num_leaves=31, learning_rate=0.1,
            random_state=random_state, n_jobs=n_jobs, verbose=-1,
        )
    raise ValueError(f"unknown model {model!r}; expected one of rf, xgb, lgbm")


class StageClassifier:
    """Tree-ensemble over the 21 window flow features -> MITRE stage index.

    One interface (fit / predict / predict_proba / feature_importances_ / save /
    load) over three backends selected by `model`:
      * "rf"   Random Forest      (n_estimators=200, max_depth=None)
      * "xgb"  XGBoost            (n_estimators=200, max_depth=6, lr=0.1, hist)
      * "lgbm" LightGBM           (n_estimators=200, num_leaves=31, lr=0.1)

    class_weight applies to RF only (the boosters train on the natural
    distribution, matching the honest-baseline ablation). It defaults to None so
    every backend shares the same natural-distribution setup; pass "balanced"
    to reproduce the earlier weighted RF.

    Label handling: the MITRE stage indices present in attack windows are
    {1,2,3,4,5,7} — non-contiguous and never 0. RF tolerates that, but XGBoost
    (>=2.0) requires 0..K-1 labels, so the boosters get a LabelEncoder and
    predict() maps back to the original stage index. RF keeps its native labels,
    so existing rf pickles load unchanged.
    """

    def __init__(
        self,
        model: str = "rf",
        class_weight: str | dict | None = None,
        random_state: int = config.GLOBAL_SEED,
        n_jobs: int = -1,
    ):
        self.model_type = model
        self.feature_names = list(FEATURE_NAMES)
        self.model = _build_estimator(model, class_weight, random_state, n_jobs)
        self._le: LabelEncoder | None = None  # boosters only
        self.classes_: np.ndarray | None = None

    def fit(self, X, y) -> "StageClassifier":
        X = np.asarray(X, dtype=np.float64)
        y = np.asarray(y)
        if self.model_type == "rf":
            self.model.fit(X, y)
            self.classes_ = self.model.classes_
        else:
            self._le = LabelEncoder().fit(y)
            self.model.fit(X, self._le.transform(y))
            self.classes_ = self._le.classes_  # original stage indices, sorted
        return self

    def predict(self, X) -> np.ndarray:
        X = np.asarray(X, dtype=np.float64)
        pred = self.model.predict(X)
        if self.model_type != "rf":
            pred = self._le.inverse_transform(np.asarray(pred).astype(int))
        return pred

    def predict_proba(self, X) -> np.ndarray:
        # Column order is self.classes_ for every backend (LabelEncoder classes
        # are sorted, matching sklearn's own class ordering).
        return self.model.predict_proba(np.asarray(X, dtype=np.float64))

    @property
    def feature_importances_(self) -> np.ndarray:
        return np.asarray(self.model.feature_importances_, dtype=np.float64)

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(
                {
                    "model": self.model,
                    "model_type": self.model_type,
                    "feature_names": self.feature_names,
                    "classes_": self.classes_,
                    "label_encoder": self._le,
                    "stage_names": STAGE_NAMES,
                },
                f,
            )

    @classmethod
    def load(cls, path: str | Path) -> "StageClassifier":
        with open(path, "rb") as f:
            blob = pickle.load(f)
        obj = cls(model=blob.get("model_type", "rf"))
        obj.model = blob["model"]
        obj.feature_names = blob["feature_names"]
        obj.classes_ = blob.get("classes_")
        obj._le = blob.get("label_encoder")
        return obj


# ══════════════════════════════════════════════════════════════
# Feature/label extraction
# ══════════════════════════════════════════════════════════════

def attack_xy(pairs) -> tuple[np.ndarray, np.ndarray]:
    """(X, y) over ATTACK windows only, from a list of (seq, (is_attack, mitre_idx)).

    Works on both the deep model's GraphWindow sequences and this module's light
    feature pools, because both expose `seq[-1].window_features`. The label is
    the sequence's own mitre_idx (already the target/last window's stage).
    """
    X, y = [], []
    for seq, (is_attack, mitre_idx) in pairs:
        if is_attack != 1:
            continue
        feats = seq[-1].window_features
        if not feats:
            # A real window always carries 21 features; skip defensively rather
            # than feed the forest a wrong-width or empty row.
            continue
        X.append(list(feats))
        y.append(int(mitre_idx))
    if not X:
        return np.empty((0, len(FEATURE_NAMES))), np.empty((0,), dtype=int)
    return np.asarray(X, dtype=np.float64), np.asarray(y, dtype=int)


# ══════════════════════════════════════════════════════════════
# Data loading (mirrors train.run_pipeline / the sibling diagnostic scripts)
# ══════════════════════════════════════════════════════════════

def _cache_key(csv_files: list[Path]) -> str:
    h = hashlib.sha256()
    h.update(config.FEATURE_SCALING.encode())
    h.update(f"win{config.WINDOW_SIZE_SECONDS}".encode())
    for p in csv_files:
        st = p.stat()
        h.update(f"{p.name}:{st.st_size}:{int(st.st_mtime)}".encode())
    return h.hexdigest()[:16]


def build_feature_pools(data_dir: Path, use_cache: bool = True) -> dict[str, list]:
    """Parse the five day files into per-day, ordered lists of (light_seq, target).

    Identical parse -> window+extract -> build_graph -> contiguous-chunk ->
    create_sequences(label_policy="dominant") path as train.run_pipeline and the
    sibling scripts, then reduced to just the target window's 21 features so the
    result is small enough to cache. The per-day ordering is preserved exactly,
    so make_blocked_folds produces the same folds it would on the full sequences.
    """
    csv_files = [data_dir / f"{d}_plus.csv" for d in DAYS]
    missing = [p for p in csv_files if not p.exists()]
    if missing:
        print("STOP: missing data files (run from backend/):", file=sys.stderr)
        for p in missing:
            print(f"  {p.resolve()}", file=sys.stderr)
        sys.exit(1)

    cache_dir = config.BACKEND_ROOT / ".cache"
    cache_path = cache_dir / f"stage_pools_{_cache_key(csv_files)}.pkl"
    if use_cache and cache_path.exists():
        print(f"Loading cached feature pools from {cache_path.name}")
        with open(cache_path, "rb") as f:
            raw = pickle.load(f)
        return {
            day: [([_FeatWindow(feats)], tuple(target)) for feats, target in items]
            for day, items in raw.items()
        }

    day_pools: dict[str, list] = {}
    raw_pools: dict[str, list] = {}  # cache-friendly: (features, target)
    for fp in csv_files:
        print(f"  parsing {fp.name} ...", flush=True)
        events, _ = parse_cicids2017_csv(fp, source=DataSource.REAL)
        if not events:
            print(f"  WARNING: {fp.name} parsed to zero events", file=sys.stderr)
            continue

        feature_records = window_and_extract(events)

        events_by_window: dict = {}
        window_starts = [fr.window_start for fr in feature_records]
        for e in events:
            idx = bisect.bisect_right(window_starts, e.timestamp) - 1
            if idx >= 0:
                fr = feature_records[idx]
                if fr.window_start <= e.timestamp < fr.window_end:
                    events_by_window.setdefault(fr.window_id, []).append(e)

        windows = []
        for fr in feature_records:
            windows.append(build_graph(
                events_by_window.get(fr.window_id, []),
                fr.window_id, fr.window_start, fr.window_end,
                fr.source, window_features=fr.feature_vector,
            ))

        chunks, current = [], []
        for w in windows:
            if not current or w.window_start == current[-1].window_end:
                current.append(w)
            else:
                chunks.append(current)
                current = [w]
        if current:
            chunks.append(current)

        day = fp.stem.split("_")[0]
        day_pools.setdefault(day, [])
        raw_pools.setdefault(day, [])
        for chunk in chunks:
            seqs, targets = create_sequences(chunk, events, label_policy="dominant")
            for seq, target in zip(seqs, targets):
                feats = list(seq[-1].window_features)
                day_pools[day].append(([_FeatWindow(feats)], tuple(target)))
                raw_pools[day].append((feats, tuple(target)))

    if use_cache:
        cache_dir.mkdir(parents=True, exist_ok=True)
        with open(cache_path, "wb") as f:
            pickle.dump(raw_pools, f)
        print(f"Cached feature pools to {cache_path.name}")

    return day_pools


# ══════════════════════════════════════════════════════════════
# Metrics / reporting
# ══════════════════════════════════════════════════════════════

def macro_f1_min_support(y_true, y_pred, min_support: int = MIN_SUPPORT) -> tuple[float, list[int]]:
    """Macro-F1 over stages whose TRUE support >= min_support.

    Rare stages (a handful of Lateral Movement / Initial Access windows that the
    dominant-label policy barely surfaces) make a per-class F1 swing wildly on a
    couple of examples; restricting the headline number to stages with real
    support keeps it stable and honest about what the model actually learned.
    """
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    counts = Counter(int(v) for v in y_true)
    labels = sorted(c for c, n in counts.items() if n >= min_support)
    if not labels:
        return float("nan"), []
    f1 = f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)
    return float(f1), labels


def print_per_stage_report(y_true, y_pred, title: str) -> None:
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    labels = sorted(set(int(v) for v in y_true) | set(int(v) for v in y_pred))
    prec, rec, f1, sup = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, zero_division=0
    )
    print(f"\n{title}")
    print(f"{'stage':<20}{'precision':>11}{'recall':>9}{'f1':>9}{'support':>9}")
    print("-" * 58)
    for lbl, p, r, f, s in zip(labels, prec, rec, f1, sup):
        mark = "" if s >= MIN_SUPPORT else "  (< min-support)"
        print(f"{STAGE_NAMES[lbl]:<20}{p:>11.4f}{r:>9.4f}{f:>9.4f}{s:>9}{mark}")
    print("-" * 58)
    macro_all = f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)
    macro_sup, sup_labels = macro_f1_min_support(y_true, y_pred)
    print(f"{'macro-F1 (all present)':<20}{macro_all:>29.4f}")
    print(f"{'macro-F1 (support>=%d)' % MIN_SUPPORT:<20}{macro_sup:>29.4f}"
          f"   over {[STAGE_NAMES[l] for l in sup_labels]}")


def print_confusion(y_true, y_pred, title: str) -> None:
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    labels = sorted(set(int(v) for v in y_true) | set(int(v) for v in y_pred))
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    col_w = 7
    name_w = 20
    print(f"\n{title}")
    print("rows = true stage   cols = predicted stage")
    hdr = f"{'true \\ pred':<{name_w}}" + "".join(
        f"{STAGE_NAMES[c][:col_w - 1]:>{col_w}}" for c in labels) + f"{'total':>{col_w}}"
    print(hdr)
    print("-" * len(hdr))
    for i, t in enumerate(labels):
        row_total = int(cm[i].sum())
        line = f"{STAGE_NAMES[t]:<{name_w}}" + "".join(
            f"{int(cm[i][j]):>{col_w}}" for j in range(len(labels))) + f"{row_total:>{col_w}}"
        print(line)
    print("-" * len(hdr))
    line = f"{'pred total':<{name_w}}" + "".join(
        f"{int(cm[:, j].sum()):>{col_w}}" for j in range(len(labels)))
    print(line)


def print_feature_importances(clf: StageClassifier, title: str, top_n: int | None = None) -> None:
    imp = clf.feature_importances_
    order = np.argsort(imp)[::-1]
    if top_n is not None:
        order = order[:top_n]
    print(f"\n{title}")
    print(f"{'rank':>4}  {'feature':<20}{'importance':>12}")
    print("-" * 40)
    for rank, i in enumerate(order, 1):
        print(f"{rank:>4}  {clf.feature_names[i]:<20}{imp[i]:>12.4f}")


def _deep_macro_f1(results_path: Path) -> dict:
    """Deep stage-head macro-F1 per fold, as recorded, for a side-by-side.

    Reference only: the recorded number is the present-class macro-F1 the deep
    run logged, not the support>=20 restriction used here, so treat it as the
    order-of-magnitude comparison the ablation is about, not a metric-identical one.
    """
    import json
    if not results_path.exists():
        return {}
    try:
        recorded = json.loads(results_path.read_text())
    except (OSError, ValueError):
        return {}
    out = {}
    for fold, m in recorded.items():
        if fold.endswith("_2stage"):
            continue
        v = m.get("mitre_f1_macro")
        if isinstance(v, (int, float)):
            out[fold] = float(v)
    return out


# ══════════════════════════════════════════════════════════════
# Cross-validation driver
# ══════════════════════════════════════════════════════════════

def evaluate_model_cv(folds, model: str, class_weight=None, verbose: bool = False) -> dict:
    """Run one model over pre-generated blocked folds; attack windows only.

    Returns pooled out-of-fold true/pred (each test window scored exactly once),
    the per-fold macro-F1 (support>=20), and the per-fold fit time in seconds.
    Every model sees the identical folds, so the numbers are directly comparable.
    """
    pooled_true, pooled_pred = [], []
    per_fold_macro, fold_times = [], []

    for name, train, _val, test in folds:
        X_tr, y_tr = attack_xy(train)
        X_te, y_te = attack_xy(test)
        if len(X_tr) == 0 or len(X_te) == 0:
            if verbose:
                print(f"\n[{name}] skipped: {len(X_tr)} train / {len(X_te)} test attack windows")
            continue

        t0 = time.perf_counter()
        clf = StageClassifier(model=model, class_weight=class_weight).fit(X_tr, y_tr)
        fit_s = time.perf_counter() - t0
        y_pred = clf.predict(X_te)

        pooled_true.extend(int(v) for v in y_te)
        pooled_pred.extend(int(v) for v in y_pred)
        macro_sup, sup_labels = macro_f1_min_support(y_te, y_pred)
        per_fold_macro.append(macro_sup)
        fold_times.append(fit_s)

        if verbose:
            train_stages = sorted(set(int(v) for v in y_tr))
            print(f"\n[{name}] train {len(X_tr)} / test {len(X_te)} attack windows | "
                  f"fit {fit_s:.2f}s | train stages: {[STAGE_NAMES[s] for s in train_stages]}")
            print(f"[{name}] macro-F1 (support>=%d): {macro_sup:.4f}   "
                  f"over {[STAGE_NAMES[l] for l in sup_labels]}" % MIN_SUPPORT)
            print_confusion(y_te, y_pred, f"[{name}] confusion matrix")

    pooled_macro, pooled_labels = macro_f1_min_support(pooled_true, pooled_pred)
    valid = [m for m in per_fold_macro if m == m]
    return {
        "model": model,
        "pooled_true": pooled_true,
        "pooled_pred": pooled_pred,
        "per_fold_macro": per_fold_macro,
        "fold_times": fold_times,
        "pooled_macro": pooled_macro,
        "pooled_labels": pooled_labels,
        "mean_fold": float(np.mean(valid)) if valid else float("nan"),
        "std_fold": float(np.std(valid)) if valid else float("nan"),
    }


def run_single_model(day_pools: dict, args) -> None:
    """Detailed single-model CV report (per-fold CMs, pooled per-stage, headline),
    then train on all attack windows, save, and print feature importances."""
    model = args.model
    class_weight = None
    if model == "rf" and not args.no_class_weight:
        # Preserve the original single-run RF behaviour (weighted unless
        # --no-class-weight). The comparison path forces natural distribution.
        class_weight = "balanced"

    folds = list(make_blocked_folds(day_pools, n_splits=args.n_splits, block_size=args.block_size))
    print("\n" + "=" * 70)
    print(f"BLOCKED CV  —  {MODEL_LABELS[model]}  —  {args.n_splits} folds, "
          f"block_size={args.block_size}, attack windows only")
    print("=" * 70)
    res = evaluate_model_cv(folds, model, class_weight=class_weight, verbose=True)

    print("\n" + "=" * 70)
    print("POOLED OVER ALL FOLDS  (each test window scored once, out-of-fold)")
    print("=" * 70)
    print_per_stage_report(res["pooled_true"], res["pooled_pred"], "Per-stage precision / recall / F1")
    print_confusion(res["pooled_true"], res["pooled_pred"], "Pooled confusion matrix")

    deep = _deep_macro_f1(Path(args.deep_results))
    print("\n" + "=" * 70)
    print("HEADLINE  —  MITRE stage macro-F1 (support >= %d)" % MIN_SUPPORT)
    print("=" * 70)
    print(f"  {MODEL_LABELS[model]}, per-fold mean:  {res['mean_fold']:.4f} ± {res['std_fold']:.4f}   "
          f"(folds: " + ", ".join(f"{m:.3f}" for m in res["per_fold_macro"]) + ")")
    print(f"  {MODEL_LABELS[model]}, pooled OOF:     {res['pooled_macro']:.4f}   "
          f"over {[STAGE_NAMES[l] for l in res['pooled_labels']]}")
    if deep:
        deep_vals = list(deep.values())
        print(f"  Deep stage head:    {np.mean(deep_vals):.4f} ± {np.std(deep_vals):.4f}   "
              f"(recorded present-class macro; reference only)")

    all_pairs = [item for items in day_pools.values() for item in items]
    X_all, y_all = attack_xy(all_pairs)
    print("\n" + "=" * 70)
    print(f"FINAL MODEL  —  {MODEL_LABELS[model]} trained on all {len(X_all)} attack windows")
    print("=" * 70)
    dist = Counter(int(v) for v in y_all)
    print("Stage distribution: " + ", ".join(f"{STAGE_NAMES[k]}={dist[k]}" for k in sorted(dist)))
    final = StageClassifier(model=model, class_weight=class_weight).fit(X_all, y_all)
    print_feature_importances(final, "Feature importances (final model)")

    save_path = args.save if args.save else str(CKPT_BY_MODEL[model])
    final.save(save_path)
    print(f"\nSaved final {MODEL_LABELS[model]} to {save_path}")


def _fmt3(x: float) -> str:
    return f"{x:.3f}"


def run_comparison(day_pools: dict, args) -> None:
    """Three-way rf/xgb/lgbm comparison on identical blocked folds, natural
    class distribution for all three (the honest-baseline setting)."""
    models = ["rf", "xgb", "lgbm"]
    folds = list(make_blocked_folds(day_pools, n_splits=args.n_splits, block_size=args.block_size))

    print("\n" + "=" * 70)
    print(f"THREE-WAY COMPARISON  —  {args.n_splits} folds, block_size={args.block_size}, "
          f"attack windows only, natural class distribution")
    print("=" * 70)

    results = {}
    for m in models:
        print(f"  running {MODEL_LABELS[m]} ...", flush=True)
        results[m] = evaluate_model_cv(folds, m, class_weight=None, verbose=False)

    # All three share the same test windows, so support is identical; take the
    # label universe from the pooled truth of any model.
    ref_true = results["rf"]["pooled_true"]
    labels = sorted(set(int(v) for v in ref_true))
    support = Counter(int(v) for v in ref_true)

    # ---- side-by-side per-stage P / R / F1 ----
    per_model_prf = {}
    for m in models:
        p, r, f, _s = precision_recall_fscore_support(
            results[m]["pooled_true"], results[m]["pooled_pred"],
            labels=labels, zero_division=0)
        per_model_prf[m] = (p, r, f)

    print("\n" + "-" * 100)
    print("PER-STAGE (pooled out-of-fold)   P / R / F1 per model   [* = support < %d]" % MIN_SUPPORT)
    print("-" * 100)
    print(f"{'stage':<19}{'sup':>5}   "
          + "".join(f"{MODEL_LABELS[m]:^24}" for m in models))
    print(f"{'':<19}{'':>5}   " + "".join(f"{'P':>7}{'R':>8}{'F1':>8} " for _ in models))
    for i, lbl in enumerate(labels):
        s = support[lbl]
        mark = " " if s >= MIN_SUPPORT else "*"
        row = f"{STAGE_NAMES[lbl]:<18}{mark}{s:>5}   "
        for m in models:
            p, r, f = per_model_prf[m]
            row += f"{_fmt3(p[i]):>7}{_fmt3(r[i]):>8}{_fmt3(f[i]):>8} "
        print(row)

    # ---- macro-F1 summary ----
    print("\n" + "-" * 78)
    print("MACRO-F1 (support >= %d)" % MIN_SUPPORT)
    print("-" * 78)
    print(f"{'model':<14}{'pooled OOF':>12}{'per-fold mean±std':>22}   per-fold")
    for m in models:
        r = results[m]
        folds_str = ", ".join(f"{v:.3f}" for v in r["per_fold_macro"])
        print(f"{MODEL_LABELS[m]:<14}{r['pooled_macro']:>12.4f}"
              f"{r['mean_fold']:>13.4f} ± {r['std_fold']:.4f}   [{folds_str}]")

    # ---- pick best by pooled macro-F1 (support>=20) ----
    best = max(models, key=lambda m: (results[m]["pooled_macro"]
                                      if results[m]["pooled_macro"] == results[m]["pooled_macro"] else -1))
    print(f"\nBest by pooled macro-F1 (support>={MIN_SUPPORT}): {MODEL_LABELS[best]} "
          f"({results[best]['pooled_macro']:.4f})")
    print_confusion(results[best]["pooled_true"], results[best]["pooled_pred"],
                    f"Full confusion matrix — best model ({MODEL_LABELS[best]})")

    # ---- training time per fold ----
    print("\n" + "-" * 78)
    print("TRAINING TIME PER FOLD (seconds)")
    print("-" * 78)
    fold_names = [name for name, *_ in folds]
    print(f"{'model':<14}" + "".join(f"{fn:>10}" for fn in fold_names) + f"{'mean':>10}")
    for m in models:
        ts = results[m]["fold_times"]
        print(f"{MODEL_LABELS[m]:<14}" + "".join(f"{t:>10.3f}" for t in ts)
              + f"{np.mean(ts):>10.3f}")

    # ---- final models on all attack windows: importances + save alt models ----
    all_pairs = [item for items in day_pools.values() for item in items]
    X_all, y_all = attack_xy(all_pairs)
    print("\n" + "=" * 70)
    print(f"FINAL MODELS  —  trained on all {len(X_all)} attack windows (natural distribution)")
    print("=" * 70)
    for m in models:
        final = StageClassifier(model=m, class_weight=None).fit(X_all, y_all)
        print_feature_importances(final, f"Top 10 feature importances — {MODEL_LABELS[m]}", top_n=10)
        # Never overwrite the RF baseline pkl during a comparison run.
        if m == "rf":
            print(f"  (RF final model NOT saved — baseline {CKPT_BY_MODEL['rf']} preserved)")
        else:
            final.save(CKPT_BY_MODEL[m])
            print(f"  Saved {MODEL_LABELS[m]} to {CKPT_BY_MODEL[m]}")

    # ---- interpretation ----
    _print_interpretation(results, best)


def _print_interpretation(results: dict, best: str) -> None:
    rf = results["rf"]["pooled_macro"]
    print("\n" + "=" * 70)
    print("INTERPRETATION")
    print("=" * 70)

    # C2 is the weakest supported stage; compare its pooled F1 across models.
    c2_idx = STAGE_NAMES.index("Command & Control")
    labels = sorted(set(int(v) for v in results["rf"]["pooled_true"]))
    c2_f1 = {}
    for m in ["rf", "xgb", "lgbm"]:
        _p, _r, f, _s = precision_recall_fscore_support(
            results[m]["pooled_true"], results[m]["pooled_pred"], labels=labels, zero_division=0)
        c2_f1[m] = f[labels.index(c2_idx)] if c2_idx in labels else float("nan")

    print(f"  Pooled macro-F1 (support>={MIN_SUPPORT}):  "
          + ", ".join(f"{MODEL_LABELS[m]}={results[m]['pooled_macro']:.4f}" for m in ['rf', 'xgb', 'lgbm']))
    print(f"  Command & Control F1:          "
          + ", ".join(f"{MODEL_LABELS[m]}={c2_f1[m]:.4f}" for m in ['rf', 'xgb', 'lgbm']))

    best_gain = results[best]["pooled_macro"] - rf
    c2_gain = c2_f1[best] - c2_f1["rf"]
    print()
    if best != "rf" and (best_gain >= 0.02 or c2_gain >= 0.02):
        why = []
        if best_gain >= 0.02:
            why.append(f"macro-F1 +{best_gain:.3f}")
        if c2_gain >= 0.02:
            why.append(f"C2 F1 +{c2_gain:.3f}")
        print(f"  RECOMMENDATION: switch to {MODEL_LABELS[best]} "
              f"({', '.join(why)} over RF — clears the >=2% bar).")
    else:
        spread = max(results[m]["pooled_macro"] for m in results) - \
                 min(results[m]["pooled_macro"] for m in results)
        print(f"  RECOMMENDATION: keep Random Forest. All three are within "
              f"{spread:.3f} macro-F1 of each other (< the 2% switching bar), and RF is "
              f"the simplest option with no extra dependency. XGBoost/LightGBM add a "
              f"heavyweight dependency for no measurable gain.")


# ══════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-dir", type=str, default="data/raw")
    parser.add_argument("--model", choices=["rf", "xgb", "lgbm"], default="rf",
                        help="Which model to run for a single-model report (default rf, "
                             "preserves prior behaviour). Ignored when --compare is set.")
    parser.add_argument("--compare", action="store_true",
                        help="Run all three models (rf/xgb/lgbm) on the same folds and print "
                             "the side-by-side comparison. Natural class distribution for all.")
    parser.add_argument("--n-splits", type=int, default=N_SPLITS)
    parser.add_argument("--block-size", type=int, default=BLOCK_SIZE)
    parser.add_argument("--no-class-weight", action="store_true",
                        help="Single-model rf only: disable class_weight='balanced'")
    parser.add_argument("--no-cache", action="store_true",
                        help="Force a re-parse instead of using the cached feature pools")
    parser.add_argument("--save", type=str, default=None,
                        help="Single-model only: where to save the final model "
                             "(default: the model's checkpoint path)")
    parser.add_argument("--deep-results", type=str, default=str(DEFAULT_DEEP_RESULTS),
                        help="Deep blocked-run lodo_results.json, for the ablation comparison")
    args = parser.parse_args()

    if config.FEATURE_SCALING != "linear":
        print(f"STOP: config.FEATURE_SCALING is {config.FEATURE_SCALING!r}, expected "
              f"'linear' to match the deep blocked run. Set SENTINEL_FEATURE_SCALING=linear.",
              file=sys.stderr)
        sys.exit(1)

    set_seed(config.GLOBAL_SEED)
    print(f"Feature scaling: {config.FEATURE_SCALING}   seed: {config.GLOBAL_SEED}")

    day_pools = build_feature_pools(Path(args.data_dir), use_cache=not args.no_cache)
    sizes = {d: len(v) for d, v in day_pools.items()}
    n_attack = {d: sum(1 for _s, (a, _m) in v if a == 1) for d, v in day_pools.items()}
    print(f"Days: {sizes}")
    print(f"Attack windows per day: {n_attack}")

    if args.compare:
        run_comparison(day_pools, args)
    else:
        run_single_model(day_pools, args)


if __name__ == "__main__":
    main()
