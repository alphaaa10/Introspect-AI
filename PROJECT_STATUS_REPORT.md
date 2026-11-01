# Sentinel AI — Full Project Architecture & Status Report
> **Handover document.** Everything your next contributor needs to understand the system, reproduce results, and continue from here.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Repository Layout](#2-repository-layout)
3. [Technology Stack](#3-technology-stack)
4. [Data Pipeline — Phases 1–6](#4-data-pipeline--phases-16)
   - Phase 1 & 2: Ingestion & Parsing
   - Phase 3: Feature Extraction & Windowing
   - Phase 4: Graph Construction
   - Phase 5: World Model Architecture (GAT + LSTM)
   - Phase 6: Determinism & Smoke Testing
5. [Real Data Training & Tuning — Phases 7–8](#5-real-data-training--tuning--phases-78)
   - Dataset & Slice Strategy
   - Mode Collapse & Class Weighting
   - Root Cause Breakthrough — Graph Feature Normalization
   - Architecture Refinements
6. [The 2-Stage Architecture Pivot — Phase 9](#6-the-2-stage-architecture-pivot--phase-9)
7. [LODO Evaluation & Deployment — Phase 10](#7-lodo-evaluation--deployment--phase-10)
8. [FastAPI Backend](#8-fastapi-backend)
9. [Post-Analysis Subsystems](#9-post-analysis-subsystems)
10. [React Frontend Dashboard](#10-react-frontend-dashboard)
11. [Deployed Model & Checkpoints](#11-deployed-model--checkpoints)
12. [Test Suite](#12-test-suite)
13. [Finalized Architecture Parameters](#13-finalized-architecture-parameters)
14. [Open Problems & Next Steps](#14-open-problems--next-steps)
15. [How to Run Everything](#15-how-to-run-everything)

---

## 1. Project Overview

**Sentinel AI** is an end-to-end network intrusion detection system with a full-stack interactive dashboard.

The ML core is a hybrid **Graph Attention Network (GAT) + LSTM "WorldModel"** that processes raw PCAP/CSV network flows and predicts:
1. **Binary:** Is this 60-second time window an active attack? (attack probability 0–1)
2. **Stage:** Which MITRE ATT&CK tactic best describes it? (one of 8 classes)

The system trains on the **CIC-IDS-2017** dataset, exposes a **FastAPI REST API** that accepts any flow-log CSV upload, runs the full ML pipeline, and returns structured dashboard data consumed by a **React + Vite** frontend.

**What has been fully built and is working:**
- Complete data pipeline (ingestion → feature extraction → graph construction → sequence modeling)
- WorldModel detector (GAT + LSTM, binary attack detection), deployed and producing valid ROC-AUC
- Decoupled LightGBM stage classifier, deployed and working per-stage predictions
- FastAPI backend with flexible CSV upload, coverage checking, and SHAP explainability
- React frontend with 15 components: attack graph, MITRE stage panel, timeline, explainability panel, reconstruction narrative, etc.

---

## 2. Repository Layout

```
Introspect-AI/
├── backend/
│   ├── app/
│   │   ├── api/routes/analyze.py      # POST /api/analyze endpoint
│   │   ├── config.py                  # Single source of truth for all params
│   │   ├── schemas.py                 # All Pydantic data contracts (12 models)
│   │   ├── main.py                    # FastAPI app entry point
│   │   ├── stage_classifier.py        # RF / XGBoost / LightGBM stage classifier (745 lines)
│   │   ├── ingestion/
│   │   │   ├── parser.py              # Strict CIC-IDS-2017 parser (training path)
│   │   │   ├── flexible_parser.py     # Alias-normalizing parser (upload/inference path)
│   │   │   └── schema.py             # Column aliases + CoverageReport
│   │   ├── features/extractor.py      # Windowing + 21-feature extraction
│   │   ├── graph/builder.py           # GraphWindow construction
│   │   ├── models/
│   │   │   ├── gat.py                 # Hand-written GATv2 (no PyG dependency)
│   │   │   ├── lstm.py                # LSTM encoder
│   │   │   ├── world_model.py         # GAT+LSTM combined model
│   │   │   └── seeding.py             # Deterministic seed initialisation
│   │   ├── pipeline/
│   │   │   ├── analyzer.py            # Full inference orchestrator
│   │   │   └── scenario_builder.py    # AnalysisContext → dashboard JSON
│   │   ├── mitre/stages.py            # MITRE kill-chain stage progression builder
│   │   ├── correlation/graph_view.py  # Attack graph topology builder (React Flow)
│   │   ├── forecasting/forecast.py    # Rolling probability + 3-step linear forecast
│   │   ├── explainability/shap_view.py # SHAP TreeExplainer on LightGBM
│   │   └── reconstruction/narrative.py # Templated attack-story narrative generator
│   ├── train.py                       # Full training script (72 KB)
│   ├── sweep_thresholds.py            # Detection threshold sweep
│   ├── holdout_sweep.py               # LODO cross-day evaluation
│   ├── diagnose_mitre_cm.py           # MITRE confusion matrix diagnostics
│   ├── deploy.py                      # Checkpoint packaging for deployment
│   ├── checkpoints/                   # All saved model weights
│   └── requirements.txt
├── src/                               # React frontend (Vite)
│   ├── App.jsx
│   ├── components/                    # 15 UI components
│   └── data/mockScenarios.js          # Pre-canned demo scenarios
├── index.html
├── package.json
└── vite.config.js
```

---

## 3. Technology Stack

### Backend
| Layer | Technology |
|---|---|
| Language | Python 3.12 |
| Web framework | FastAPI 0.115 + Uvicorn |
| Data validation | Pydantic v2 |
| Deep learning | PyTorch 2.4.1 (hand-written GAT, no PyTorch Geometric) |
| Stage classifier | LightGBM 4.7, XGBoost 3.4, scikit-learn 1.5 |
| Explainability | SHAP 0.52 (TreeExplainer on LightGBM) |
| Data processing | pandas 2.2, numpy 2.1 |
| Testing | pytest 8.3, pytest-asyncio 0.24, httpx 0.27 |

> **Important:** PyTorch Geometric was **intentionally avoided** due to Windows dependency issues. The entire GAT is hand-written in plain PyTorch (`app/models/gat.py`, 281 lines).

### Frontend
| Layer | Technology |
|---|---|
| Framework | React 18 + Vite |
| Routing/state | React Context (`ScenarioContext`) |
| Graph visualization | React Flow (attack graph component) |
| Styling | Vanilla CSS (`src/index.css`, 33 KB) |
| Icons | Lucide React |

---

## 4. Data Pipeline — Phases 1–6

### Phase 1 & 2 — Ingestion & Parsing (`app/ingestion/parser.py`)

- Strict schema validation via **Pydantic `NetworkEvent`** — skips malformed rows, never fabricates values.
- For CIC-IDS-2017: explicitly maps dataset-specific column names to the internal schema (e.g., `"Total Fwd Packet"`, `"Flow Duration"`).
- Parses TCP flag fields (`SYN`, `ACK`, `PSH`, `FIN`, `RST`, `URG`) into a canonical string representation.
- IPs are derived from the `Flow ID` field (format: `SrcIP-DstIP-SrcPort-DstPort-Proto`) which avoids decimal-encoded IP integer columns.

**Flexible Parser (Upload Path) — `app/ingestion/flexible_parser.py`:**
- Separate parser for user-uploaded CSVs with arbitrary column naming.
- Column aliases defined in `app/ingestion/schema.py` (`ALIASES` dict). Adding a new format = adding one entry there, nothing else changes.
- Computes a `CoverageReport`: how many of the 21 features are derivable from the file's columns.
  - **< 18/21 covered → `CoverageError` (HTTP 422 refusal).** Never fabricates missing features.
  - **18–21 covered → proceed, warn about missing features.**
- Uses a fixed row-order timestamp anchor (`2017-07-07 09:00:00 UTC`, 100 ms cadence) to keep IAT features on the same distribution the model saw during training.

---

### Phase 3 — Feature Extraction & Windowing (`app/features/extractor.py`)

- Raw events are grouped into **60-second half-open `[start, end)` windows** deterministically. Empty windows are skipped.
- **21 window-level features** are extracted per window (canonical list in `app/config.py → FEATURE_NAMES`):

| Feature | Description |
|---|---|
| `duration` | Mean flow duration (s) |
| `protocol_type` | Mode protocol (TCP=6, UDP=17, ICMP=1) |
| `src_port`, `dst_port` | Mean src/dst port across flows |
| `fwd_packets`, `bwd_packets` | Sum of forward/backward packets |
| `fwd_bytes`, `bwd_bytes` | Sum of forward/backward bytes |
| `fwd_pkt_len_mean`, `bwd_pkt_len_mean` | Mean packet lengths |
| `flow_bytes_per_s`, `flow_pkts_per_s` | Throughput rates |
| `syn_flag_cnt`, `ack_flag_cnt`, `psh_flag_cnt`, `fin_flag_cnt`, `rst_flag_cnt` | TCP flag counts |
| `unique_dst_ports`, `unique_dst_ips` | Fan-out metrics |
| `iat_mean`, `iat_std` | Inter-arrival time statistics |

- **Failed Connection Proxy:** `rst_flag_cnt` is used as a proxy for failed connections since the dataset lacks explicit session completion states.
- **Scaling:** All 21 features are normalized to `[0.0, 1.0]` using a **fixed-bounds Min-Max dictionary** (`_SCALE_BOUNDS`). Fixed bounds (not batch statistics) ensure deterministic behavior at inference.
- **Two scaling modes** (set via `config.FEATURE_SCALING` or env var `SENTINEL_FEATURE_SCALING`):
  - `linear` (default): `clip(x, lo, hi) / hi`
  - `log`: `log1p(clip(x, lo, hi) - lo) / log1p(hi - lo)`
  - **Ablation result:** `linear` wins on aggregate (LODO mean ROC-AUC 0.9707 vs 0.8941). `log` wins on low-volume folds (Patator brute force) but loses badly on volumetric DDoS folds, so `linear` is the deployed default.

---

### Phase 4 — Graph Construction (`app/graph/builder.py`)

Each 60-second window becomes a `GraphWindow` (Pydantic model):

- **Nodes (`GraphNode`):** One per unique IP address. Features: `in_bytes`, `out_bytes`, `in_degree`, `out_degree`, `total_flows` — all scaled to `[0, 1]` with fixed bounds.
- **Edges (`GraphEdge`):** One per IP pair (bidirectional flows aggregated). Features: `total_fwd_bytes`, `total_bwd_bytes`, `total_fwd_packets`, `total_bwd_packets`, `flow_count`, `mean_duration_s` — all scaled.
- **Determinism:** Nodes and edges are sorted lexicographically by IP to guarantee stable matrix structure across identical runs.
- **Self-loops:** Traffic where `src_ip == dst_ip` is fully supported.
- **`window_features`:** The 21-dimensional `FeatureRecord.feature_vector` is carried inside `GraphWindow` so the model can consume both the graph structure AND the window statistics in a single pass.

> **Critical lesson learned (Phase 8):** Node and edge features were originally **unscaled**. Feeding raw values in the thousands/millions into the GAT exploded gradients and destroyed the attention mechanism (ROC-AUC inverted to 0.41). Scaling graph features was the breakthrough that finally broke mode collapse.

---

### Phase 5 — World Model Architecture (`app/models/world_model.py`)

```
Input: sequence of up to 20 GraphWindows
         │
         ▼ (per timestep)
    ┌─────────────┐
    │  GATEncoder  │  (app/models/gat.py)
    │  GATv2-style │
    │  4 heads     │
    │  hidden=128  │
    │  out=64      │
    └──────┬───────┘
           │  → mean+max pooled → 128-dim graph embedding
           │  + window_features (21-dim)
           │  = 149-dim LSTM input
           ▼
    ┌─────────────┐
    │   LSTM       │  (app/models/lstm.py)
    │   2 layers   │
    │   hidden=128 │
    │   dropout=0.1│
    └──────┬───────┘
           │  → [1, 128] sequence summary
           ├─────────────────────────────┐
           ▼                             ▼
    ┌──────────────┐            ┌──────────────────┐
    │  attack_head │            │   mitre_head      │
    │  Linear(128,1)│           │  MLP: 128→64→ReLU→│
    │  → sigmoid   │           │   → 8 logits       │
    │  → P(attack) │           │  (DEPRECATED in    │
    └──────────────┘            │   production; see  │
                                │   Phase 9)         │
                                └──────────────────┘
```

**GAT Implementation Details (`app/models/gat.py`):**
- Hand-written **GATv2-style attention** (no PyTorch Geometric) with edge features.
- Attention score: `a^T × LeakyReLU(W_src(h_j) + W_dst(h_i) + W_edge(e_ij))`
- **Volumetric bypass gate:** A learnable `vol_weight` parameter is added as `out += raw_edge_sum × vol_weight`. This surgically injects raw edge magnitudes (not attention-weighted) so DDoS volume signal is never washed out by softmax normalization.
- **GraphSAGE-style self-connection:** Each node's own features are added via `W_self(h_i)`.
- **Readout:** Mean pooling **concatenated with** Max pooling → 128-dim graph embedding. This was an upgrade from pure mean pooling to preserve anomaly spikes.
- Multi-head: 4 heads, outputs concatenated, then projected down.

**MITRE Head Architecture Options (experimental):**
The code supports three `mitre_arch` values:
- `"linear"` — `Linear(128, 8)` — baseline
- `"mlp"` — `Linear(128, 64) → ReLU → Linear(64, 8)` — the architecture trained in the 2-stage experiment
- `"dual_lstm"` — a second dedicated LSTM for MITRE, plus a skip connection from the target window's raw features — ablation only

---

### Phase 6 — Determinism & Smoke Testing (`train.py`)

Before touching real data:
- Built a 3-window mock dataset.
- **Determinism Gate:** Two independent runs must produce identical graphs, model weights, and metrics. This verified the preprocessing and seed initialization were stable.
- **Checkpointing Gate:** A reloaded model must produce identical probabilities to the pre-save model.
- Seeds are set via `app/models/seeding.py → set_seed()` which covers `torch`, `random`, and `numpy`.

---

## 5. Real Data Training & Tuning — Phases 7–8

### Dataset & Slice Strategy

**Dataset:** CIC-IDS-2017 `friday_plus.csv` (547K rows), plus all 5 days for LODO.

**The Degeneracy Problem:** The raw dataset is entirely Benign in the morning, then has a massive afternoon DDoS burst. Standard random splitting causes data leakage; chronological splitting creates degenerate sets (e.g., Test set with 0% Benign).

**The Fix — Non-Contiguous Mixed Slice:**
- Concatenate rows 0–30,000 (morning baseline) + rows 80,000–128,000 (afternoon attack).
- Sequences are generated *within* each chunk independently, so no sequence straddles the 5-hour gap.
- **Interleaved Chronological Split:** Sequences are assigned Train/Val/Test via modulo (`idx % 3`), distributing them evenly while preserving temporal continuity within each sequence.

### Mode Collapse & Class Weighting

**The Problem:** Initial 10-epoch training produced mode collapse — the model predicted "Attack" for every window because Attacks were the majority class (67%).

**The Fix:** Calculated exact inverse class ratio and applied it as `pos_weight` to `BCEWithLogitsLoss`. This mathematically penalizes misclassifying Benign windows more.

### Root Cause Breakthrough — Graph Feature Normalization

**The Problem:** Even with `pos_weight`, the model remained collapsed. ROC-AUC inverted to 0.41.

**Root Cause:** While window-level features in `extractor.py` were properly scaled, the **graph node and edge features fed into the GAT were completely raw** (unscaled values in the thousands to millions). This exploded gradients and destroyed the attention mechanism.

**The Fix:** Implemented fixed-bounds Min-Max scaling for all graph features in `builder.py`, matching the architecture in `extractor.py`. Schemas were updated to store floats instead of ints.

**Result:** Retraining with normalized graph features broke mode collapse on the training set — True Negatives appeared, AUC turned positive — proving gradients were flowing and the architecture was sound.

### Architecture Refinements (Post-Phase 8)

Two additional refinements were made based on analysis of the training dynamics:

1. **Mean+Max Pooling Concatenation:** Replaced pure Global Mean Pooling in the GAT readout with `concat(mean_pool, max_pool)` → 128-dim. This preserves both the average network state AND the peak anomaly signals (critical for DDoS windows where the attack signal is a spike, not the average).

2. **Volumetric Bypass Gate:** Added a learnable bypass of raw edge magnitudes into the GAT output to prevent softmax attention from washing out flood volume (the most discriminative DDoS signal).

3. **Sequence Length:** Increased from 10 → **20** windows (`config.SEQUENCE_LENGTH = 20`).

---

## 6. The 2-Stage Architecture Pivot — Phase 9

### The Problem with the Deep MITRE Head

After the WorldModel was producing valid binary detections, the `mitre_head` (MLP on top of the binary LSTM summary) was evaluated on the 5-fold blocked cross-validation:

- **Macro-F1 ≈ 0.16** (far too low for production use)
- **Credential Access F1 = 0.0** on 97-window support — the head never correctly identified this stage
- **Root cause:** The binary LSTM summary is a compression of information needed to answer "is this an attack?" — it discards information needed to distinguish *which type* of attack. The Credential Access and Impact stages overlap in the binary-trained embedding space.

### The Solution — Decoupled LightGBM Stage Classifier

A completely separate, shallow tree-ensemble classifier was built (`app/stage_classifier.py`, 745 lines):

- **Input:** The 21 raw window-level features (`config.FEATURE_NAMES`) from the last window of each sequence — exactly the flow statistics that discriminate attack types (flag counts, unique ports, IAT, byte rates).
- **Training scope:** ATTACK windows only (is_attack == 1). Benign windows are the binary head's job.
- **Three backends benchmarked:**
  - `rf` — Random Forest (n_estimators=200, max_depth=None)
  - `xgb` — XGBoost (n_estimators=200, max_depth=6, lr=0.1)
  - `lgbm` — LightGBM (n_estimators=200, num_leaves=31, lr=0.1)
- **Evaluation:** Blocked 5-fold CV with block_size=40 (identical fold structure to the deep model run for comparability). Stages with fewer than 20 true support examples are excluded from headline macro-F1 to keep the metric stable.
- **Selected model: LightGBM** → checkpoint `checkpoints/stage_classifier_lgbm.pkl`

### Deployed Pipeline (2-Stage Inference)

```
Upload CSV
    │
    ▼
flexible_parser.py → events[]
    │
    ▼
window_and_extract() → 21 features per window
    │
    ▼
build_graph() → GraphWindow (with window_features attached)
    │
    ▼
WorldModel.forward(sequence)
    │
    ├── attack_head → P(attack) → is_attack?
    │
    └── IF is_attack:
            LightGBM StageClassifier.predict([window_features])
                → MITRE stage index
```

The `mitre_head` in the WorldModel is **still present in the code** but is **not used in production inference**. It is kept for ablation comparisons.

---

## 7. LODO Evaluation & Deployment — Phase 10

### Leave-One-Day-Out (LODO) Evaluation

**Script:** `backend/holdout_sweep.py` (11 KB)

All 5 CIC-IDS-2017 days were used for cross-day generalization testing:
- `monday.csv` — Benign only (baseline)
- `tuesday.csv` — Brute force (Patator / FTP / SSH)
- `wednesday.csv` — DoS/DDoS (Slowloris, Slowhttptest, Hulk, GoldenEye)
- `thursday.csv` — Web attacks (Brute force, XSS, SQL Injection)
- `friday.csv` — DDoS + Infiltration + Botnet

Each day is held out as the test set while the other four are combined for training. Checkpoints saved in `checkpoints/holdout/`.

**Feature Scaling Ablation Results (from LODO):**

| Scaling | Mean ROC-AUC |
|---|---|
| linear | **0.9707** |
| log | 0.8941 |

`log` scaling wins on the low-volume Patator fold (0.9759 → 1.0000) because linear scaling against a 1e8 ceiling compresses ordinary traffic to ~1e-4. But it loses on all volumetric DDoS folds (thursday: 0.9787 → 0.8191; friday: 1.0000 → 0.8796) because it compresses the upper tail where flood magnitude is the signal. `linear` wins on the aggregate.

### Deployment Checkpoint

**Script:** `backend/deploy.py`

After LODO evaluation, the best-performing weights across all days were packaged:
- **WorldModel detector:** `checkpoints/deploy_all_days/sentinel_deploy.pt`
- **LightGBM stage classifier:** `checkpoints/stage_classifier_lgbm.pkl`

These are the two files loaded at runtime by `app/pipeline/analyzer.py`. Both are loaded once at startup and cached in module-level globals (`_MODEL`, `_STAGE`) for request-to-request efficiency.

### Threshold Sweep

**Script:** `backend/sweep_thresholds.py` (13 KB)

A sweep over the binary detection threshold was run on the temporal holdout. The default threshold of `0.5` was found to already be optimal. This is hardcoded in `analyzer.py → DEFAULT_THRESHOLD = 0.5`.

---

## 8. FastAPI Backend

**Entry point:** `backend/app/main.py`
**Server:** Uvicorn, default port 8000, CORS configured for `http://localhost:5173`

### Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Returns `{"status": "ok", "service": "sentinel-backend"}` |
| `GET` | `/api/analyze/health` | Analyze router health check |
| `POST` | `/api/analyze` | **Main endpoint.** Accepts multipart CSV upload, runs full pipeline, returns dashboard JSON |

### POST /api/analyze

**Request:** `multipart/form-data`, field `file` = flow-log CSV file.

**Response (200):**
```json
{
  "scenario": { ... },      // Full dashboard-ready scenarioData
  "coverage": { ... },      // Feature coverage report
  "warnings": [ ... ],      // Non-fatal issues (missing features, truncation)
  "meta": {
    "filename": "...",
    "n_events": 12500,
    "n_windows": 208,
    "n_attack_windows": 45,
    "threshold": 0.5
  }
}
```

**Error Responses:**
- `HTTP 422` — Feature coverage < 18/21. Returns `coverage` dict explaining which features are missing.
- `HTTP 400` — Malformed file or unparseable CSV.
- `HTTP 503` — Model checkpoint files not found (server misconfiguration).

**Truncation:** Files > 60,000 events are truncated to the first 60,000 rows (chronologically) for responsiveness. The `warnings` array will note this.

---

## 9. Post-Analysis Subsystems

After `analyze_csv()` produces an `AnalysisContext`, `scenario_builder.py` calls five domain assemblers to build the full dashboard payload:

### MITRE Stage Progression (`app/mitre/stages.py`)
- Maps per-window LightGBM predictions to 7 kill-chain stages (Reconnaissance → Impact).
- Each stage is marked `confirmed` (seen in past windows), `current` (most recent attack window's stage), or `inactive`.
- Output feeds `scenarioData.mitreStages`.

### Correlation / Attack Graph (`app/correlation/graph_view.py`)
- Builds **React Flow** node/edge topology from parsed events.
- Attacker identification: IP with the highest out-degree (distinct destinations), tie-broken by total flow count.
- Produces `attacker` node → MITRE stage nodes → `targetGroup` node topology.
- Output feeds `scenarioData.graphNodes`, `.graphEdges`, `.hosts`.

### Forecasting (`app/forecasting/forecast.py`)
- Shows the last 12 real windows of attack probability plus a 3-step linear trend extrapolation.
- Extrapolation labeled `type: "predicted"` so the UI renders it as a dashed projection line.
- Output feeds `scenarioData.infiltrationTimeline`.

### SHAP Explainability (`app/explainability/shap_view.py`)
- Uses **SHAP `TreeExplainer`** (exact, not kernel approximation) on the LightGBM stage classifier.
- For each detected stage, picks the highest-probability attack window as a representative sample.
- Computes per-feature signed SHAP contributions toward that stage's class. Positive SHAP = pushes toward this stage.
- Top 10 features by |SHAP| are returned per stage.
- Includes additivity residual check: `|expected_value[c] + sum(shap[c]) - raw_margin[c]|` should be near 0.
- Output feeds `scenarioData.shapValues`, `.explainabilityMeta`.

### Narrative Reconstruction (`app/reconstruction/narrative.py`)
- Deterministic (no LLM) templated narrative from detected stages, timestamps, and flow counts.
- Produces: confirmed entries (one per detected stage in kill-chain order), a predicted trend entry, and an action recommendation.
- Also produces `rawLogStream`: a colored terminal-style log feed shown in the UI.
- Output feeds `scenarioData.narrativeEntries`, `.rawLogStream`.

### Alert Builder (in `scenario_builder.py`)
- For up to 12 highest attack-probability windows, extracts the top-K GAT-attended edges using `model.attention_for_sequence()`.
- Output feeds `scenarioData.alerts`.

---

## 10. React Frontend Dashboard

**Stack:** React 18 + Vite, Vanilla CSS, React Flow, Lucide icons.

**Entry:** `src/App.jsx` — manages global app state via `ScenarioContext`.

**App States:**
1. `setup` / `select-dataset` — Shows `SetupScreen.jsx`. User picks a pre-canned demo scenario or uploads a real CSV.
2. `dashboard` — Full analysis dashboard.

**Pre-canned Scenarios:** Defined in `src/data/mockScenarios.js`. These are complete pre-built `scenarioData` objects that allow the dashboard to run without a backend.

**Upload Flow (live analysis):**
1. User uploads CSV in `SetupScreen`.
2. Frontend `POST /api/analyze` with the file.
3. On success: `setUploadedScenario(response.scenario)` → switches to dashboard view.

**The 15 Components:**

| Component | Purpose |
|---|---|
| `SetupScreen.jsx` | Landing page — dataset picker + file upload |
| `Sidebar.jsx` | Left navigation sidebar |
| `TopBar.jsx` | Header with theme toggle and controls |
| `OverviewDashboard.jsx` | Main overview: stats cards, urgency timeline, alerts table |
| `AttackGraph.jsx` | React Flow interactive attack topology graph |
| `DetectionTimeline.jsx` | Chronological event feed with stage badges |
| `InfiltrationTimeline.jsx` | Rolling probability chart with forecast projection |
| `ExplainabilityPanel.jsx` | SHAP feature attribution bar chart |
| `AttackStoryReconstruction.jsx` | Narrative timeline + raw log stream |
| `HostDetailPanel.jsx` | Per-host entity details (attacker, targets) |
| `MitreStageProgression.jsx` | Kill-chain stage cards (confirmed / current / inactive) |
| `NarrativePanel.jsx` | Compact narrative text panel |
| `PipelineVisualization.jsx` | Visual diagram of the ML pipeline |
| `AnalystActions.jsx` | Recommended analyst actions |
| `Icons.jsx` | Shared icon components |

**Theme:** Light/dark mode toggle with persistence via `localStorage`.

---

## 11. Deployed Model & Checkpoints

### Files Used in Production

| File | Role |
|---|---|
| `checkpoints/deploy_all_days/sentinel_deploy.pt` | WorldModel state dict (binary detector) |
| `checkpoints/stage_classifier_lgbm.pkl` | LightGBM stage classifier |

### Other Notable Checkpoints

| Path | Description |
|---|---|
| `checkpoints/full_blocked_2stage_mlp/` | The blocked-CV run of the deep 2-stage model (with MLP mitre_head). This is where the deep MITRE head's failure (macro-F1 ~0.16) was documented. |
| `checkpoints/holdout/` | Per-fold LODO evaluation checkpoints |
| `checkpoints/sentinel_best_val_auc.pt` | Best validation AUC checkpoint from training |
| `checkpoints/stage_classifier_rf.pkl` | Random Forest stage classifier (not deployed) |
| `checkpoints/stage_classifier_xgb.pkl` | XGBoost stage classifier (not deployed) |

### Model Size

- WorldModel (`sentinel_deploy.pt`): ~1.1 MB
- LightGBM classifier (`stage_classifier_lgbm.pkl`): ~1.8 MB

---

## 12. Test Suite

**Location:** `backend/tests/` (10 test files, ~107 KB total)

| Test File | What It Covers |
|---|---|
| `test_ingestion.py` | Parser robustness, malformed row handling, field validation |
| `test_extractor.py` | Windowing logic, feature extraction, scaling |
| `test_graph_builder.py` | Graph construction, node/edge feature correctness, determinism |
| `test_gat.py` | GAT forward pass shapes, edge cases (empty graphs, self-loops) |
| `test_lstm.py` | LSTM encoder shapes and outputs |
| `test_world_model.py` | End-to-end WorldModel forward pass, checkpoint save/reload determinism |
| `test_batching.py` | Batch collation and padded sequence handling |
| `test_train_protocols.py` | Training loop integration, seed stability, determinism gate |
| `test_pipeline.py` | Full pipeline integration test (parse → extract → graph → predict) |

**Run tests:**
```bash
cd backend
venv\Scripts\pytest tests/ -v
```

---

## 13. Finalized Architecture Parameters

All architectural parameters are locked in `app/config.py`:

| Parameter | Value | Notes |
|---|---|---|
| `WINDOW_SIZE_SECONDS` | 60 | 1-minute windows |
| `NUM_FEATURES` | 21 | Window-level feature vector size |
| `SEQUENCE_LENGTH` | 20 | LSTM lookback (was 10 in early phases) |
| `GAT_HIDDEN_DIM` | 128 | GAT intermediate layer width |
| `NUM_MITRE_STAGES` | 8 | Including Benign (0) + 7 attack stages |
| `GLOBAL_SEED` | 42 | For full determinism |
| `FEATURE_SCALING` | `"linear"` | Default; override with `SENTINEL_FEATURE_SCALING` env var |
| `MODEL_DEVICE` | `"cpu"` | Override with `SENTINEL_DEVICE` env var |
| **At `analyzer.py` level:** | | |
| `gat_num_heads` | 4 | |
| `gat_out_dim` | 64 | Per-head output; × 2 after mean+max concat = 128 |
| `gat_dropout` | 0.1 | |
| `lstm_hidden_dim` | 128 | |
| `lstm_num_layers` | 2 | |
| `lstm_dropout` | 0.1 | |
| `mitre_arch` | `"mlp"` | The architecture the checkpoints were trained with |
| `DEFAULT_THRESHOLD` | 0.5 | Binary detection threshold (found optimal by sweep) |
| `MAX_EVENTS` | 60,000 | Upload truncation limit |

---

## 14. Open Problems & Next Steps

### Known Weaknesses

1. **Lateral Movement & Initial Access** have very low support in the dataset. The LODO evaluation's `macro_f1_min_support` metric excludes stages with < 20 windows to keep the number honest — but this means those stages are effectively untested.

2. **Stage classifier is not temporal.** LightGBM predicts stage from a single window's features. It has no memory of which stages preceded it, so it cannot enforce kill-chain ordering (e.g., it could predict `Impact` before `Reconnaissance`).

3. **Narrative reconstruction is template-based.** The `reconstruction/narrative.py` module generates text from templates. An LLM-based narrative generator is the documented follow-up.

4. **No authentication on the API.** The FastAPI server has no auth layer. It is designed for local/trusted network deployment only.

5. **Frontend uses mock data by default.** The pre-canned scenarios are hardcoded `mockScenarios.js` objects. The live-analysis path only works when the backend is running.

### Immediate Next Steps (High Priority)

- **Kill-chain ordering enforcement:** Post-process LightGBM predictions to flag stage regressions (e.g., jump from Impact back to Reconnaissance) as potential false positives.
- **Expand stage coverage:** Augment the dataset with more Lateral Movement and Initial Access samples (synthetic generation or additional CIC datasets like CIC-IDS-2018).
- **API auth:** Add API key or JWT authentication before any network-accessible deployment.
- **LLM narrative:** Wire an LLM (GPT-4o / Gemini) into `reconstruction/narrative.py` to generate human-readable attack stories from the structured context.

### Research Hypotheses (Open from Phase 8, Partially Addressed)

- **Hypothesis 2 (Learning Rate):** Default `1e-3` may still be too aggressive. A cosine-annealing schedule or a lower fixed LR (e.g., `3e-4`) should be compared against the current LODO baseline.
- **Hypothesis 3 (Pooling):** The mean+max pooling change was implemented, but the Max-only pooling ablation was never run in isolation. This would confirm whether mean+max is better than max-only for DDoS detection.

---

## 15. How to Run Everything

### Prerequisites
- Python 3.12
- Node.js 18+
- The 5 CIC-IDS-2017 day CSV files in `backend/data/raw/` (named `monday_plus.csv` through `friday_plus.csv`)

### Backend Setup
```bash
cd backend
py -3.12 -m venv venv
venv\Scripts\pip install -r requirements.txt
# Note: torch is listed last in requirements.txt — install order matters.
```

### Train the WorldModel (if not using existing checkpoints)
```bash
cd backend
venv\Scripts\python train.py
```

### Train the LightGBM Stage Classifier
```bash
cd backend
venv\Scripts\python -m app.stage_classifier --model lgbm --save checkpoints/stage_classifier_lgbm.pkl
```

### Package for Deployment
```bash
cd backend
venv\Scripts\python deploy.py
# Creates checkpoints/deploy_all_days/sentinel_deploy.pt
```

### Run the Backend API
```bash
cd backend
venv\Scripts\python app/main.py
# Listening on http://0.0.0.0:8000
# Docs at http://localhost:8000/docs
```

### Run the Frontend
```bash
# From the project root (Introspect-AI/)
npm install
npm run dev
# Listening on http://localhost:5173
```

### Run Tests
```bash
cd backend
venv\Scripts\pytest tests/ -v
```

### Quick Diagnostics
```bash
# MITRE confusion matrix (requires trained checkpoints)
cd backend
venv\Scripts\python diagnose_mitre_cm.py

# Threshold sweep
venv\Scripts\python sweep_thresholds.py

# LODO cross-day evaluation
venv\Scripts\python holdout_sweep.py
```

---

*Report generated: 2026-10-30. Reflects codebase state as of that date.*
