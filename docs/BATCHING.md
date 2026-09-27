# Batched training path

Status: **Phase 1 and Phase 2 step 1 complete.**

- **Phase 1** added the batched encoder (`collate_sequences`,
  `WorldModel.encode_batch`, `WorldModel.logits_batch`) and verified it against
  the unbatched path.
- **Phase 2 step 1** routed the default training and evaluation paths through
  `logits_batch` at **B=1**, giving a measured **2.35x faster training epoch**.

There is deliberately **no `--batch-size` CLI flag**. B=1 is the only supported
batch size, so a flag whose only valid value is its default would be dead
config. If B>1 is ever added, the flag arrives with it.

`WorldModel.encode` and `WorldModel.logits` remain callable and unchanged for
diagnostics, and `WorldModel.forward` is still the single-sequence inference
entry point the API and dashboard use.

Branch: `batching-work` (base commit `2ae3b3c`, "checkpoint before batching work").

---

## What changed in Phase 2 step 1

Four functions in `train.py` now build a one-sequence batch and call
`logits_batch` instead of `logits`:

| function | was | now |
|---|---|---|
| `train_one_epoch` | `model.logits(seq)` | `model.logits_batch(collate_sequences([(seq, target)], device))` |
| `evaluate_loss` | `model.logits(seq)` | same, so validation loss uses the path that produced the weights |
| `evaluate` | `model(seq)` → `PredictionResult` | `logits_batch`, then `sigmoid` / `softmax` to reproduce the same two fields |
| `select_threshold` | `model(seq).attack_probability` | `logits_batch` → `sigmoid`, matching `evaluate` |

**`ACCUM_STEPS = 64` semantics are untouched.** Each sequence's loss is still
divided by 64 and the optimizer still steps every 64 sequences. That is the whole
reason B=1 was chosen: the loss sees exactly one sequence, so no normalisation
had to be reconciled.

Nothing else moved. No CLI flag, no optimizer or LR change, no seed handling, no
data loading, no `compute_metrics` format.

---

## Headline result: the speedup is ~3.5x, not ~20x

Measured on real windows from `monday_plus.csv` (first 200,000 rows → 334
sequences, 156 nodes / 174 edges per window, matching the full dataset's 150-node
average), single-threaded, forward + backward, **including collation cost**
because collation recurs every epoch:

| path | ms/sequence | speedup |
|---|---|---|
| unbatched (current default) | 69.92 | 1.00x |
| batched B=1 | 26.88 | **2.60x** |
| batched B=4 | 20.11 | **3.48x** |
| batched B=8 | 20.13 | 3.47x |
| batched B=16 | 21.76 | 3.21x |
| batched B=32 | 23.36 | 2.99x |
| batched B=64 | 25.35 | 2.76x |

**Throughput peaks around B=4–8 and then falls.** At B=32 the disjoint-union
graph reaches ~100,000 nodes and the GAT's scatter operations become
memory-bandwidth bound, which costs more than the dispatch amortisation saves.

### Graph size dominates the result

The same benchmark on a slice with much smaller graphs (24 nodes / 26 edges)
reports very different numbers:

| | 24 nodes/window | 156 nodes/window |
|---|---|---|
| best speedup | **9.96x** (B=32) | **3.48x** (B=4) |
| B=32 | 9.96x | 2.99x |

Any speedup figure for this pipeline is meaningless without the graph size
attached. The full dataset averages 150 nodes, so **3.5x is the number to plan
with**; the ~10x only appears on the atypically sparse slices.

### Most of the win is intra-sequence, not inter-sequence

Look at the B=1 row: **2.60x of the 3.48x total arrives at batch size one.**

That is because `encode_batch` runs the GAT **once** over a sequence's 20 windows
fused into a single disjoint graph, instead of making 20 separate GAT calls.
Batching *across* sequences adds only a further ~1.35x on top of that.

This matters for what to build next, because B=1 requires **no loss or optimizer
reconciliation at all** — one sequence in, one loss out, divided by
`ACCUM_STEPS`, stepping every 64 sequences, exactly as today. All the risk
identified in pre-flight (gradient-scale mismatch, `pos_weight` handling,
weighted-cross-entropy normalisation) belongs solely to B>1, which is worth only
that last 1.35x.

---

## Approach

### Scatter strategy: offset-based, so `GATLayer` is unmodified

`collate_sequences` shifts every graph's node indices by a running offset, so no
two graphs in a batch share a node index. `GATLayer`'s attention softmax is a
scatter over destination node indices (`scatter_reduce_` for the max, then
`scatter_add_` for the normaliser), so disjoint indices make a cross-graph
message arithmetically impossible.

**`GATLayer.forward` therefore received no changes and takes no `batch_index`
argument.** Adding an unused parameter would have implied a safety mechanism that
is not there; the safety comes from the index offsets. This is the approach the
specification named as preferred.

Only `GATEncoder.forward` needed work, because its readout was
`torch.mean(node_embeds, dim=0)` and `torch.max(...)` over *all* nodes, which
would mix graphs. It now takes optional `batch_index` / `num_graphs`:

- `batch_index=None` → the original single-graph code path, byte-for-byte.
- `batch_index` given → per-graph mean via `scatter_add_` divided by per-graph
  node counts, and per-graph max via `scatter_reduce_(..., reduce="amax",
  include_self=False)`.

The max initialises its output to **zeros, not `-inf`**. With
`include_self=False`, graphs that have nodes get their true maximum (the zero
init is excluded from the reduction), while graphs with no nodes are left at
zero — matching `GATEncoder`'s existing empty-graph policy. An `-inf` init would
have left empty graphs at `-inf` and poisoned the LSTM.

### Padding: empty graphs, then packing

Padded timesteps are materialised as **empty graphs** (zero nodes, zero edges),
so a graph's id is exactly `b * T_max + t`. That keeps the reshape to
`[B, T_max, D]` a plain `view` rather than a scatter, and costs nothing since an
empty graph contributes no rows to any concatenated tensor.

Masking before the LSTM uses **`pack_padded_sequence`** (with
`enforce_sorted=False`, so the caller keeps its own batch order). This is the one
reason `app/models/lstm.py` was touched: `LSTMEncoder.forward` gained an optional
`lengths` argument. With `lengths=None` behaviour is unchanged.

Packing is a correctness requirement, not an optimisation. `h_n[-1]` is what both
prediction heads read, so without it a length-5 sequence padded to 10 would
return the hidden state after five further steps of *zero input* — a different
and wrong value. Test 4 asserts this directly.

### `window_features` had to be added to the collated dict

The specification's field list omitted the extractor's 21 features. They are
required: the current architecture fuses them into every timestep
(`window_feat_dim=21`), so leaving them out would have silently disabled the
fusion **in the batched path only**. That is precisely the divergence that the
duplicated encoder inside `train_one_epoch` used to cause, which is why
`encode_batch` also raises if the tensor's shape disagrees with
`self.window_feat_dim` rather than broadcasting past the problem.

### Attention weights on the batched path: unsupported, by design

`GATEncoder.latest_attention_weights` in the batched path holds **every graph's
edges concatenated with no edge→graph mapping**, so it is not per-window
interpretable. It is not broken — it is meaningless at that granularity.

The consumer is the dashboard's explainability panel, which reads
`PredictionResult.attention_weights` from single-sequence inference
(`WorldModel.forward`). That path never takes the batched route and is verified
still populated (`TestAttentionWeightsPhase1`). Making batched attention
per-window would need an edge→graph index; it is not needed by anything today.

---

## Public API added

| symbol | purpose |
|---|---|
| `train.collate_sequences(batch, device) -> dict` | packs `(sequence, target)` pairs into one disjoint-union graph |
| `WorldModel.encode_batch(collated) -> Tensor` | `[B, T_max, D]` per-timestep embeddings |
| `WorldModel.logits_batch(collated) -> (Tensor, Tensor)` | `[B,1]` attack logits, `[B,S]` stage logits |
| `GATEncoder.forward(..., batch_index=None, num_graphs=None)` | optional, default preserves old behaviour |
| `LSTMEncoder.forward(x, lengths=None)` | optional, default preserves old behaviour |

Nothing was removed. No CLI flag changed. No existing test was modified.

---

## Equivalence is exact without dropout, and differs only by dropout RNG with it

This is the one behavioural difference, and it is worth understanding before
reading any before/after loss numbers.

Same initial weights, same RNG state, same 84 real sequences, comparing
`model.logits` against `model.logits_batch`:

| dropout | mode | mean loss difference | max per-sequence difference |
|---|---|---|---|
| 0.0 | eval | **0.000e+00** | 5.96e-08 |
| 0.0 | train | **0.000e+00** | 5.96e-08 |
| 0.1 | eval | **0.000e+00** | 5.96e-08 |
| 0.1 | **train** | **2.313e-04** | 3.527e-03 |

With dropout disabled the two paths agree to **float32 epsilon** (5.96e-08), in
both train and eval mode. The only case that diverges is **training mode with
dropout active**, and the cause is RNG consumption, not arithmetic:

- the unbatched path calls the GAT once per window, so dropout draws a mask for
  each of the ~20 alpha tensors separately;
- the batched path calls the GAT once, so dropout draws **one** mask over the
  concatenated alpha tensor.

Same number of elements, same distribution, different draw. Both are valid
samples; neither is more correct. The effect is equivalent to reseeding, so
training dynamics are statistically identical while any single run's trajectory
differs slightly.

Practical consequences:

- **Final metrics were bit-identical** in both verification runs (see below), so
  this does not move results at the granularity that matters.
- Epoch-level loss values can differ by ~1e-4 on small sequence counts, where
  individual dropout draws are not yet averaged out. On the 60,000-row run
  (300 training sequences) the logged train and validation losses matched to all
  four decimal places printed.
- A run is still reproducible against **itself**: seeding is unchanged, so the
  same command at the same seed gives the same answer. Only comparisons *across*
  the two code paths are affected.
- Set `gat_dropout=0.0` / `lstm_dropout=0.0` if you ever need exact cross-path
  equality, as `tests/test_batching.py` does.

---

## Verification output

### `pytest tests/test_batching.py -v`

```
21 passed, 4 skipped in 3.19s
```

Passing, grouped by the specification's numbering:

- **Test 1** — batch_size=1 equals unbatched: attack and stage logits match
  within 1e-5, across sequence lengths 1, 2, 7 and 20. `WorldModel.forward`
  confirmed unchanged.
- **Test 3** — no cross-sequence leakage: two sequences with disjoint feature
  ranges (0.10 vs 0.80) produce identical embeddings batched and solo; a
  sequence's logits are unchanged by three different batch companions; every
  collated edge provably connects two nodes of the same graph.
- **Test 4** — LSTM masking: a length-5 sequence batched with a length-10 one
  matches its solo result and the unbatched path within 1e-5; `seq_mask` and
  `seq_lengths` agree.
- **Test 6** — empty graphs: an all-empty window, an empty window in the middle
  of a populated sequence, nodes-with-no-edges, and an entirely empty batch all
  stay finite and match the unbatched path.
- **Test 9** — checkpoints: `state_dict` keys and shapes unchanged by batching;
  save/load round-trips to identical output on both paths; a batched forward pass
  adds no state.

Skipped, deferred to the training-loop phase: **Tests 2, 5, 7** (batched loss
equality, determinism, incomplete final batch — all require
`train_one_epoch_batched`) and **Test 8**'s batched half. Test 8's
single-sequence half is asserted now.

`checkpoints/sentinel_best_val_auc.pt` is **not** used by Test 9. It has
`lstm.lstm.weight_ih_l0` of shape `(512, 128)`, i.e. `window_feat_dim=0`, so it
predates the window-feature fusion and cannot load into the current default
architecture (which needs `(512, 149)`). Test 9 builds its own checkpoints.

### `pytest -q` (full existing suite)

```
188 passed, 4 skipped in 3.94s
```

167 pre-existing tests still pass, unchanged. No existing test was edited.

### Phase 2 step 1: before/after equivalence on real runs

Identical command and seed either side of the change,
`--epochs 2 --only-fold monday --mitre-weight 0.0 --scaling linear`:

`--max-rows 3000` (20 training sequences, no validation set at this size):

| key | pre | post | diff |
|---|---|---|---|
| attack_accuracy | 1.0000000000 | 1.0000000000 | 0.00e+00 |
| attack_precision / recall / f1 | 0.0 | 0.0 | 0.00e+00 |
| attack_confusion_matrix | `[[5,0],[0,0]]` | `[[5,0],[0,0]]` | same |
| decision_threshold | 0.5 | 0.5 | 0.00e+00 |

`--max-rows 60000` (300 training sequences, 100 validation sequences — this run
exercises `evaluate_loss` and `select_threshold`, which the 3000-row size cannot
because it produces no validation set):

| key | pre | post | diff |
|---|---|---|---|
| attack_accuracy | 0.0119047619 | 0.0119047619 | 0.00e+00 |
| attack_precision / recall / f1 | 0.0 | 0.0 | 0.00e+00 |
| attack_confusion_matrix | `[[1,83],[0,0]]` | `[[1,83],[0,0]]` | same |
| decision_threshold | 0.5 | 0.5 | 0.00e+00 |

Logged losses, 60,000-row run: train 0.6942 → 0.6942 and 0.6671 → 0.6671;
validation 0.6763 → 0.6763 and 0.6389 → 0.6389. Identical to the four decimals
printed.

On the 3000-row run the epoch losses moved slightly (0.6709 → 0.6707 and
0.6652 → 0.6662, i.e. ~1e-4 to ~1e-3). That is the dropout RNG effect above,
amplified by there being only 20 sequences to average over; final metrics were
still bit-identical.

### Speed

One real training epoch over 334 sequences from `monday_plus.csv`
(156 nodes/window), single-threaded, replicating `train_one_epoch`'s loss and
accumulation logic exactly and switching only the encoder call:

| path | epoch wall | ms/sequence |
|---|---|---|
| old, `model.logits` (per-window GAT) | 24.89 s | 74.51 |
| new, `model.logits_batch` (B=1) | **10.61 s** | **31.77** |

**2.35x faster (57% less wall time).**

A CLI `Measure-Command` on `--epochs 1 --max-rows 3000` reported 26.82 s, but
that figure is not a useful speed test: `--max-rows` truncates *after* parsing,
so ~22 s of it is parsing all 588,000 slice rows regardless of batch path, and
only ~2 s is the 20-sequence training loop. Use the epoch measurement above.

Projection for a 30-epoch full-data monday fold (1,969 training sequences):
~62 s/epoch → roughly **31 min**, against ~58 min before, plus ~106 s of fixed
data loading. Combined with `--only-fold` + `--threads 1` across 5 parallel
folds, a full-dataset LODO run should land near 25–30 min.

---

## If Phase 2 proceeds

**Step 1 is done.** What remains is B>1, which is worth only a further ~1.35x:

**Do not add `--batch-size` until B>1 actually works** - a flag whose only
valid value is its default is dead config.

Adding B>1 means reconciling three separate normalisations, and this is where the
pre-flight traps bite:
   - `ACCUM_STEPS = 64` with per-batch mean loss gives `64/B` times the
     intended gradient scale unless batches are accumulated to 64 sequences.
   - `attack_criterion` is an `nn.BCEWithLogitsLoss` **object** that may carry
     `pos_weight` from `--pos-weight`; a switch to
     `F.binary_cross_entropy_with_logits` must forward it.
   - `mitre_criterion` is `CrossEntropyLoss(weight=...)`, which with
     `reduction='mean'` computes `sum(w_i * l_i) / sum(w_i)`, **not** a plain
     mean. A masked mean will not match it.

Batching does **not** reduce the 2.4 GB per-process data footprint, which is what
currently limits fold-level parallelism. Combining batching with `--only-fold`
`--threads 1` is additive: 5 parallel folds at 3.5x would bring a full-dataset
LODO run from ~60 min to roughly 17–23 min.
