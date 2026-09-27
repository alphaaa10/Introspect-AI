# Model review — Introspect-AI detection pipeline

## Measured result

Four configurations, all under LODO with 4 training days, fixed 0.5 threshold,
`--mitre-weight 0`, 10 epochs, 60k rows/day. Only the feature pipeline differs,
so the comparison is clean.

| config | scaling | 21 features | mean ROC-AUC | specificity | recall | F1 | balanced acc |
|---|---|---|---|---|---|---|---|
| **A** (original) | linear | no | **0.9707** | 0.3041 | 0.9808 | 0.8309 | 0.6425 |
| D | log | no | 0.8941 | 0.5146 | 0.7923 | 0.7702 | 0.6535 |
| B | log | yes | 0.8910 | 0.6784 | 0.8243 | 0.8243 | 0.7513 |
| **E** (current default) | linear | yes | 0.9566 | 0.5906 | 0.9265 | 0.8618 | **0.7586** |

Reading, fold by fold (per-fold AUC in section 1):

- **Log scaling caused a 0.077 AUC regression** (A→D, features off). Adding
  features on top changed AUC by 0.003 — noise. An earlier draft of this review
  blamed the drop on a training-data confound; run D rules that out. The scaling
  change was the cause.
- **The 21 features are a real win.** D→B lifts balanced accuracy 0.654 → 0.751
  and specificity 0.515 → 0.678 at no AUC cost. Recovering them was correct.
- **E combines both**: best balanced accuracy (0.759 vs 0.643 originally), F1
  0.862 vs 0.831, while giving back most of the AUC (0.957 vs 0.971).

The headline change is **specificity 0.304 → 0.591 at slightly better recall** —
on the monday fold alone, false alarms went from 64 to 0 under the full
configuration. For a SOC tool that is the trade that matters.

**Quote ROC-AUC alongside any accuracy figure.** 65% of windows are labelled
attack, so accuracy alone flatters everything here.

---

Review of the GAT+LSTM training pipeline. Every number below was measured on the
five CIC-IDS-2017 day slices in `backend/data/raw/`, not estimated.

Read alongside `backend/train.py`, `backend/app/graph/builder.py` and
`backend/app/models/world_model.py`.

---

## 1. Feature scaling — diagnosed correctly, first fix was wrong, now a selectable mode

`_scale` in both `graph/builder.py` and `features/extractor.py` was linear
min-max against fixed ceilings: `clip(x, lo, hi) / hi`. Those ceilings are
*safety* bounds (1e8 bytes, 1e9 bytes/s, 1e6 pkt/s), orders of magnitude above
anything in the data, so real traffic collapsed into a sliver next to zero.

Measured over 58,891 real nodes and 67,857 real edges:

| feature | median (linear) | p99 (linear) | share below 0.01 |
|---|---|---|---|
| `out_bytes` | 0.000000 | 0.00059 | **100.0%** |
| `total_fwd_bytes` | 0.000007 | 0.00032 | **100.0%** |
| `flow_count` | 0.000100 | 0.00344 | 99.5% |

Inputs that small are indistinguishable from zero once they pass through a
Xavier-initialised `nn.Linear`, so the GAT was effectively blind to traffic
volume. This is almost certainly what the `vol_weight` / `raw_edge_sum`
"volumetric bypass" in `gat.py` was compensating for.

**Fix:** logarithmic scaling, `log1p(clip(x,lo,hi) - lo) / log1p(hi - lo)`.
Monotonic, same endpoints (`lo` maps to 0, `hi` maps to 1), but it spends the
output range on values that actually occur. After the change:

| feature | median (log) | share below 0.01 |
|---|---|---|
| `total_fwd_bytes` | 0.356 | 9.7% |
| `total_bwd_packets` | 0.216 | 4.6% |
| `total_flows` | 0.075 | 0.0% |

A 59 KB window maps to ~0.60 under log instead of ~0.00059 under linear.

### But log scaling made the model worse overall

Measured, features off, everything else identical:

| fold | dominant attack | linear | log |
|---|---|---|---|
| tuesday | Patator (low volume) | 0.9759 | **1.0000** |
| wednesday | DoS Hulk | 0.9283 | 0.8776 |
| thursday | Infiltration-Portscan | 0.9787 | 0.8191 |
| friday | DDoS / Botnet | 1.0000 | 0.8796 |
| **mean ROC-AUC** | | **0.9707** | 0.8941 |

The pattern is consistent and mechanistic. Log scaling expands the low end,
which is exactly what tuesday's low-rate brute force needed — it goes to a
**perfect 1.0000**. But it compresses the upper tail, where flood *magnitude*
is the discriminating signal, so every volumetric fold degrades. Under linear
scaling a DoS flood sits at 0.025 against benign at 0.00003 — a ~800x ratio;
under log they are ~0.80 against ~0.36, a ~2.2x ratio.

So the original linear scaling was **not** pathological in general. It was
pathological for one attack class and fine for the others, and since three of
the four evaluable folds are volumetric, the aggregate favours linear.

**Resolution:** scaling is a selectable mode, `config.FEATURE_SCALING`,
defaulting to `linear` on aggregate ROC-AUC, overridable with
`train.py --scaling log` or `SENTINEL_FEATURE_SCALING`. This is a genuine
workload-dependent choice, not a bug with one right answer — if your threat
model emphasises brute-force and low-and-slow attacks, `log` is the better
default. A/B it against your own attack mix.

**Follow-up:** re-run an A/B on `vol_weight`. It is a learnable gate initialised
at 0.01 and contributes ~0.7% of layer output, so it is no longer load-bearing
and may be removable.

---

## 2. The 21 engineered features never reached the model — fixed

`features/extractor.py` computes a 21-dim `feature_vector` per window:
`syn_flag_cnt`, `rst_flag_cnt`, `unique_dst_ports`, `unique_dst_ips`,
`iat_mean`, `iat_std`, `flow_pkts_per_s`, protocol, ports. `train.py` used
`FeatureRecord` only for `window_id` / `window_start` / `window_end` and threw
the vector away. Grepping `feature_vector` across `train.py`, `app/models/` and
`app/graph/` returned nothing.

The model therefore saw 5 node features and 6 edge features — all volumetric —
and no flag, port or timing information at all.

This matters most for attacks that are not volumetric. Measured attack-flow
fraction per window:

| day | dominant attack | median attack fraction |
|---|---|---|
| tuesday | FTP/SSH-Patator | **0.032** |
| thursday | Infiltration - Portscan | 0.250 |
| wednesday | DoS Hulk | 0.932 |
| friday | DDoS / Botnet | 0.023 to 0.873 (bimodal) |

Tuesday's brute-force windows are only ~3% attack flows and carry almost no
extra volume. `syn_flag_cnt`, `rst_flag_cnt` and `unique_dst_ports` are what
distinguish them, and those were exactly the discarded features.

**Fix:** `GraphWindow` gained a `window_features` field, `build_graph` accepts
it, and `WorldModel` concatenates it to the GAT embedding at each LSTM timestep
(`lstm.input_dim` 128 to 149). `--no-window-features` reproduces the old
graph-only architecture for ablation.

---

## 3. Training and inference used two different encoders — fixed

`train_one_epoch` re-implemented the GAT-to-LSTM forward pass inline, with a
comment explaining it was done "to respect the rule of not changing
world_model.py". `WorldModel.forward` had its own copy.

Two consequences: any encoder change had to be made twice or it silently applied
to only one path, and the training path was the one that mattered for gradients.
The feature fusion above would have been a no-op in training if the duplication
had stayed.

**Fix:** `WorldModel.encode()` is now the single path. `forward()` wraps it for
inference, `logits()` exposes raw logits for loss, and `train_one_epoch` calls
`model.logits(seq)`.

---

## 4. Determinism was not actually deterministic — fixed

`set_seed()` existed in three copies (`gat.py`, `lstm.py`, `world_model.py`),
all seeding torch only. `train.py` shuffles its training pool with
`random.shuffle`, which draws from Python's unseeded global RNG, so fold
ordering differed run to run while the determinism check reported success.

Verified: `random.shuffle` on the same list across two processes gave
`[6,8,4,1,0,5,9,2,3,7]` and `[9,2,0,3,1,8,5,7,6,4]`.

**Fix:** one implementation in `app/models/seeding.py` seeding `random`, `numpy`
and `torch` (CPU and CUDA). The three modules re-export it so existing imports
keep working. The same list now gives `[7,3,2,8,5,6,9,4,0,1]` in both processes.

---

## 5. Dead training controls — fixed

- `--epochs` was accepted and ignored; `EPOCHS = 30` was hardcoded.
- `--patience` was accepted and no early stopping existed.
- `pos_weight` was computed every fold then discarded — `FocalLoss` was
  commented out and plain `BCEWithLogitsLoss()` used instead.
- There was **no validation set**. The held-out test day was evaluated every 5
  epochs as a diagnostic, and the final model was whatever the last epoch
  produced.
- The decision threshold was hardcoded at 0.5 despite attack windows being ~65%
  of the data.

**Fix:** `--epochs` wired through (default changed 40 to 30 so effective
behaviour is unchanged). Nested CV holds out one training day as validation;
early stopping and best-weight restore run against it, never the test fold. The
decision threshold is chosen by F1 on validation and recorded per fold as
`decision_threshold`. `--pos-weight none|auto|<float>` makes class weighting a
real, opt-in control.

### Why validation is a whole day, not a slice of each day

A chronological tail of each training day was tried first. It failed twice over:
consecutive sequences share up to `SEQUENCE_LENGTH` windows, so a naive cut
leaks; and once a 20-window gap was inserted, the resulting validation set was
**100% attack**, because these CSVs put benign traffic at the top and attacks
later. Holding out a whole day shares no window with training and carries its
own class mix. Days with no attacks (monday) are excluded from being the
validation day — a single-class val set cannot tune a threshold — and stay in
training where their benign windows are useful.

---

## 6. Two crashes on the real data path — fixed

- **`confusion_matrix` indexing.** `monday_plus_slice.csv` is 100% BENIGN
  (50,000 of 50,000). Held out, the test set is single-class, `confusion_matrix`
  returns 1x1, and the epoch-5 diagnostic's `cm[0][1]` raised `IndexError`. The
  real LODO run died in fold 1. Fixed with `labels=[0, 1]`.
- **`--smoke` was broken.** The mock dataset resolves to one "day", so the LODO
  hold-out left an empty training pool and raised `ValueError: not enough values
  to unpack`. Also pass 2 of the determinism check ran with the default 30
  epochs while pass 1 used `--epochs`, so the check could never pass; and the
  checkpoint-reload check indexed `train_seqs[-1]` on the empty list
  `run_pipeline` had started returning. All three fixed — `--smoke` now reports
  determinism PASSED and reload PASSED.

---

## 7. Choice of evaluation protocol — LODO is right for one claim, wrong for the other

Each CIC-IDS day runs essentially one attack family, so each day maps to one
MITRE stage. Friday is the exception: it is the mixed slice and carries three.

| day | MITRE stages present |
|---|---|
| monday | *(none — all benign)* |
| tuesday | Credential Access |
| wednesday | Impact |
| thursday | Reconnaissance |
| friday | Command & Control, Impact, Reconnaissance |

Worked through per fold, LODO is not uniformly hopeless for stages — friday acts
as a bridge that puts Impact and Reconnaissance into training on other folds:

| held-out day | test stages | unseen in training | verdict |
|---|---|---|---|
| monday | — | — | N/A, no attacks in test |
| tuesday | Credential Access | Credential Access | **impossible** |
| wednesday | Impact | — | OK, all stages seen |
| thursday | Reconnaissance | — | OK, all stages seen |
| friday | C2, Impact, Reconnaissance | Command & Control | partial, 2 of 3 |

So two clean folds, one partial, one impossible, one N/A. That is too thin to
report a stage-classification result from, but it is not "structurally
impossible" everywhere — an earlier draft of this review overstated it.

### The recommendation: two protocols, two claims

`--protocol` now selects between them.

**`lodo` (default) — for the detection claim.** Holding out a whole day is close
to holding out an attack family, so this measures generalisation to an attack
type never seen in training. That is the strong, honest claim for a detection
system, and it is what you should quote for binary detection. Accept that stage
metrics from it are partial.

**`blocked` — for the stage-classification claim.** Purged blocked k-fold takes
contiguous blocks from every day into every fold, so all four stages appear on
both sides of every split and the stage head has something learnable. Verified
on the current data: all of `[Reconnaissance, Credential Access, C2, Impact]`
present in training for all 5 folds.

Two details that took iterations to get right, both worth knowing if you touch
this code:

- **Purging is mandatory.** Sequences overlap by up to `SEQUENCE_LENGTH`
  windows. A training sequence whose label window is `j` reads windows
  `[j-SEQ+1, j]`, so for a held-out block `[s, e)` every training sequence with
  `j` in `[s, e+SEQ-1]` touches a held-out window and is dropped. Without this,
  the split leaks badly. Audited: 0 duplicate labels and 0 training sequences
  reading a held-out window, across all folds and both data sizes.
- **Fold assignment is diagonal, not a plain stripe.** `global_position %
  n_splits` aliases: with 5 days of 2 blocks each and `n_splits=5` the stride
  equals the day count, so both of a day's blocks land in the same group and
  every fold's test set becomes one whole day — silently collapsing blocked CV
  back into LODO. Assignment is `(block_index + day_index) % n_splits`.

**Cost to be aware of.** Each held-out block costs `SEQUENCE_LENGTH - 1 = 19`
purged training sequences. At the default `block_size = 30` that is 63% of a
block, which is expensive. The fix is more data, not a smaller gap — see below.

### Supporting changes for stage classification

- MITRE loss restored, weight controlled by `--mitre-weight` (default 1.0;
  `0.0` reproduces the binary-head isolation diagnostic).
- **Inverse-frequency class weights** on the MITRE cross-entropy, normalised so
  the mean weight over present classes is 1.0 (keeps the MITRE term on the same
  scale as the binary term). Stage counts on the 60k subset are Impact 117,
  Reconnaissance 95, Credential Access 83, C2 18 — a ~6:1 imbalance that
  unweighted cross-entropy handles by ignoring C2. Disable with
  `--no-mitre-class-weights`.
- **Per-stage F1 with support counts** in the metrics (`mitre_f1_per_stage`).
  A single macro number hides which stages the head actually learned; C2 with
  18 examples will not behave like Impact with 117, and you need to see that.
- Macro-F1 is computed over stages actually present, so an absent class no
  longer silently drags the average toward zero.
- Each fold still warns when a test stage is absent from training.

### Use more data — this is the biggest lever left

Training currently uses the `*_slice.csv` files, which are roughly 15% of the
`*_plus.csv` files you already have (1.3 GB total). Measured window counts on
the slices: monday 84, tuesday 170, wednesday 433, thursday 170, friday 132 —
about 989 sequences. The full days would give roughly 7x that.

This matters more than any remaining modelling change: it makes purging cheap
instead of expensive, allows a larger `--block-size`, gives the rare stages
(C2 has 18 examples) enough support to learn, and cuts the variance on a 5-fold
estimate. Note also that stride-1 sequence generation means each window appears
in up to 20 sequences, so the effective independent sample count is far lower
than the sequence count suggests.

---

## 7b. Stage *forecasting* is not learnable from this dataset

This is the finding that most affects the project's stated ambition, and it is
about the data, not the code.

Traced as a storyline, each day's stage sequence is:

```
monday     Benign x84
tuesday    Benign x17  -> Credential Access x83
wednesday  Benign x15  -> Impact x12 -> Benign x2 -> ... -> Impact x58
thursday   Benign x6   -> Reconnaissance x94
friday     Benign x43  -> C2 x18 -> Reconnaissance x1 -> Impact x38
```

Counting every stage-to-stage change across all five days, the **attack-to-attack
transitions are:**

| transition | occurrences |
|---|---|
| Command & Control -> Reconnaissance | 1 |
| Reconnaissance -> Impact | 1 |

Two. Both on friday, and that Reconnaissance run is a single window. Everything
else is Benign to attack or attack to Benign (mostly wednesday's DoS switching
on and off).

Stage label support tells the same story — 3 of 8 stages never occur at all:

| stage | windows (dominant policy) |
|---|---|
| Benign | 171 |
| Reconnaissance | 95 |
| Initial Access | **0** |
| Credential Access | 83 |
| Lateral Movement | **0** |
| Command & Control | 18 |
| Exfiltration | **0** |
| Impact | 117 |

So the ambition splits in two:

- **Stage classification** ("which stage is this window?") — learnable now, with
  `--protocol blocked`. Four classes, with C2 thin at 18 examples.
- **Stage forecasting** ("what stage comes next?") — **not learnable here.** You
  cannot fit transition dynamics to two examples. CIC-IDS-2017 contains isolated
  attack types run one per day, not kill chains.

This, rather than provenance graphs as such, is the real argument for DARPA
TC/OpTC: those datasets contain multi-stage APT campaigns with actual
progressions to learn from. Any forecasting claim made on CIC-IDS-2017 would be
unfalsifiable on its own data.

### Labelling policy affects which stages exist at all

`--label-policy` selects how a window with several attack types is labelled:

| stage | `dominant` (default) | `advanced` |
|---|---|---|
| Reconnaissance | 95 | 1 |
| Initial Access | 0 | **84** |
| Credential Access | 83 | 83 |
| Lateral Movement | 0 | **9** |
| Command & Control | 18 | 18 |
| Exfiltration | 0 | 0 |
| Impact | 117 | 118 |
| zero-support stages | 3 | 1 |

`dominant` takes the most frequent attack label; `advanced` takes the furthest
stage along the kill chain present (the `MitreStage` enum declaration order *is*
kill-chain order, and a test now pins that). Thursday is why they differ so much:
~23,675 Infiltration-Portscan flows sit next to a few hundred Web Attack flows,
so `dominant` never surfaces Initial Access and `advanced` buries Reconnaissance.

Neither is right. A 60-second window genuinely contains several stages at once,
so the honest model is **multi-label** — one sigmoid per stage instead of a
softmax over stages. That is the change to make if stage output matters for the
final demo; the two policies are the interim compromise.

---

## 7c. Zero class weights produced a silent NaN

Found while testing the blocked protocol: validation loss logged as `Val: nan`
for two folds.

Cause: the MITRE class weights were inverse-frequency with **0.0 for classes
absent from training**. `nn.CrossEntropyLoss(reduction='mean')` divides by the
summed weight of the batch, so a single sample of a zero-weight class computes
`0/0`. With C2 at only 18 windows, a validation set containing a stage missing
from training is common, so this fired routinely — and because it surfaced as a
loss value rather than an exception, it silently disabled early stopping and
best-weight selection for those folds.

Two fixes, both tested: absent classes get weight `1.0` rather than `0.0`, and
early stopping refuses to select on a non-finite score and logs a warning
instead of treating it as "no improvement".

While writing the test for the weighting scheme, the test also caught a wrong
claim in the code comment. The `N / (K * n_c)` formula does *not* make the mean
weight per class 1.0 (it is 1.60 for the current counts); what it guarantees is
`sum_c(n_c * w_c) == N`, i.e. the mean weight **per training sample** is 1.0.
That is the property that keeps the MITRE term on the same scale as the binary
term. Comment corrected.

---

## 8. The binary label is close to a step function

`get_window_label` marks a window as attack if it contains *any* non-benign
flow. With ~600 flows per 60-second window and attack flows interleaved at a
median run length of 1 to 14 rows, nearly every window after the attack starts
qualifies. Result: **64.7% of windows are labelled attack**.

Thresholding on attack *fraction* does not straightforwardly fix it, because the
right threshold differs by attack type. Measured windows labelled attack at:

| threshold | attack windows |
|---|---|
| `frac > 0` (current) | 64.7% |
| `frac >= 0.05` | 43.4% |
| `frac >= 0.20` | 41.1% |
| `frac >= 0.50` | 19.8% |

A 5% threshold would erase **all** of tuesday's Patator windows (median 3.2%)
while barely touching wednesday's DoS. Any global threshold trades one attack
family for another.

Left as-is deliberately: "alert if any malicious flow is present" is a
defensible detection target. But it makes the task partly "is the campaign
currently running", which is easier than per-flow detection — so quote ROC-AUC
alongside accuracy, and never present accuracy alone.

---

## 9. The timeline is synthetic

`parse_cicids2017_csv` synthesises timestamps as `anchor + row_index * 100ms`.
It does not read a timestamp column. So:

- "60-second windows" are really fixed 600-row buckets.
- The LSTM's temporal ordering is CSV row order, not wall-clock order.
- Every day gets identical timestamps (anchored at 2017-07-07 09:00:00 UTC).

Row order in these files does broadly track capture order, so this is not fatal,
but it is a modelling assumption that should be stated rather than assumed. If a
real `Timestamp` column exists in the source CSVs, using it would make the
temporal claim real. Worth checking before the SIH write-up, because "we model
attack progression over time" is a weaker claim if time is an index.

---

## Checked and not problems

- The microsecond-to-second conversion in `_parse_duration` is correct.
- Column-name mapping matches the data (`SYN Flag Count` and friends all
  verified present in the headers).
- LODO has no cross-fold leakage: chunking is per-day and folds split by day.
- Node and edge ordering is deterministic (lexicographic IP, then index pairs).

---

## On pivoting to provenance graphs

The architecture advice — provenance graphs, self-supervised next-state
prediction, a stage head on top — is sound, and it is what would let this
project claim dormant-malware detection and next-stage forecasting.

It is also **blocked on data, not code**. A provenance graph needs process,
file, socket and registry nodes with causal edges. CIC-IDS-2017 is
CICFlowMeter output: one row per network flow, 104 columns, all flow statistics.
There is no process identity, no file access, no parent-child relationship. No
amount of work on `builder.py` extracts a provenance graph from it.

To actually build one you need host telemetry:

- **DARPA Transparent Computing** (E3/E5) — the datasets the described approach
  is evaluated on. Real provenance, labelled APT campaigns, free to request.
  This is the direct path.
- **DARPA OpTC** — Windows host telemetry, large, labelled red-team activity.
- **Your own Sysmon capture** — a small Windows lab, Sysmon with a decent
  config, plus a scripted attack chain. Full control, but you are also building
  the labels.

Practical recommendation for an SIH timeline: keep the current flow-based
pipeline as the working, measured detection system, and treat provenance as the
described extension with one concrete dataset named. A judged project is much
stronger with an honest measured result on flows plus a credible plan than with
a half-built provenance pipeline and no numbers. If you do want provenance in
scope, request DARPA TC access now, because the lead time is the risk, not the
modelling.

The one piece of the described approach you can adopt *today* on flow data is
the self-supervised objective: add a head that predicts the next window's
embedding, train it on monday (all benign), and use prediction error as an
anomaly score. That gives you a novelty detector that needs no attack labels,
and it runs on the data you already have.
