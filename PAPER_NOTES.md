# Paper Notes

## Citation

CD-Fuzzing (working title) — internal research project, 2026.
No published paper yet. These notes describe the method as implemented.

---

## Problem

Coverage-guided fuzzers plateau: after an initial burst of corpus growth they repeatedly exercise
the same code regions without making further progress. The fuzzer is "stuck" in a local optimum.
Existing approaches (energy scheduling, seed selection) do not explicitly detect or respond to
the global stagnation state.

---

## Method Summary

Apply concept drift detection to the fuzzer's corpus growth signal.

**Core idea**: model corpus growth as a time series. Use a two-sample KS test to compare the
growth rate over a recent window against the growth rate over the preceding window. A statistically
significant difference (p < THRESHOLD) indicates the distribution of new edges has shifted — the
fuzzer is experiencing "concept drift" in its coverage signal. When this drift is detected
persistently (CONSECUTIVE consecutive windows) and the corpus is actually stagnating (EMA growth
guard), reset the corpus to a random subset of high-scoring seeds.

**Fuzzer-agnostic module**: the CD logic is a thin wrapper around the fuzzer's main loop, reading
`queued_paths` from shared memory and triggering a soft reset by clearing the queue and replanting
a subset of high-value seeds. No changes to the core mutation or coverage logic are required.

---

## Implementation-Relevant Details

- **Inputs**: live `queued_paths` counter from fuzzer shared memory
- **Outputs**: trigger event → soft corpus reset
- **Data structures**:
  - Sliding window buffer of `queued_paths` samples (size: `WINDOW`)
  - EMA accumulator for stagnation guard
  - Reset counter and cooldown timer
- **Algorithms**:
  - Two-sample KS test: `scipy.stats.ks_2samp` equivalent in C (custom implementation)
  - EMA: `ema = EMA_ALPHA * new_val + (1 - EMA_ALPHA) * ema`
  - Stagnation guard: fire only if `(current_ema - baseline_ema) / baseline_ema < STAGNATION_FACTOR`
- **Hyperparameters** (all exposed as env vars):

  | Env var | seed_4 value | Meaning |
  |---|---|---|
  | AFL_DRIFT_WINDOW | 100 | KS test window size (samples per window) |
  | AFL_DRIFT_THRESHOLD | 0.05 | KS p-value threshold |
  | AFL_DRIFT_CONSECUTIVE | 5 | Consecutive windows below threshold to trigger reset |
  | AFL_DRIFT_STAGNATION_FACTOR | 0.5 | EMA growth guard — only reset if EMA growth < 50% |
  | AFL_DRIFT_COOLDOWN | 10 | Minimum windows between resets |
  | AFL_DRIFT_EMA_ALPHA | 0.1 | EMA smoothing factor |
  | AFL_DRIFT_SOFT_RESET | 2 | Reset mode: 2 = wipe corpus, replant top seeds |
  | AFL_DRIFT_MAX_RESETS | 0 | Max resets per campaign (0 = unlimited) |
  | AFL_DRIFT_HAVOC_BOOST | 2 | Post-reset havoc stage multiplier |
  | AFL_DRIFT_BOOST_CYCLES | 1 | Number of boosted havoc cycles after reset |

- **Metrics**: canary bugs triggered (Magma ground truth), `queued_paths` as corpus size proxy

---

## Explicitly Stated Implementation Details

- KS test applied to corpus growth rate (delta of `queued_paths` per window), not raw `queued_paths`
- EMA guard prevents resets when corpus is still actively growing
- Cooldown prevents resets from firing back-to-back
- Soft reset preserves top-scoring seeds by `exec_us` and `bitmap_size`
- `drift_log.csv` written to output dir for post-hoc analysis

---

## Inferred Details

- KS test window of 100 corresponds to ~100 AFL executions of the coverage bitmap sampling loop
  (exact timing depends on exec speed; typically ~5–30 minutes at 100–500 execs/s)
- "High-scoring seeds" for replanting are selected by AFL's `top_rated[]` array if populated,
  otherwise by shortest execution time

---

## Underspecified Details

- How many seeds to retain after soft reset: currently hardcoded as `min(queue_size/4, 20)`
  in the implementation (implementation choice, not from a paper)
- Whether to boost havoc on just the retained seeds or all new seeds post-reset: currently boosts
  all seeds in the next havoc cycle

---

## Implementation Decisions

- **Coverage metric = queued_paths, not edge bitmap**: bitmap edge count requires afl-showmap post-hoc;
  queued_paths is available live from shared memory. Paper must clarify this distinction.
- **KS test in C**: custom implementation; matches scipy.stats.ks_2samp for n=100 to 3 decimal places
  (verified in `cdfuzzing/prototyping.ipynb`)
- **Drift log format**: CSV with columns `timestamp,window_id,ks_stat,p_value,ema,fired`
  — enables the drift signal plots in `plot_seed4.py`
- **6 fuzzers targeted**: AFL 2.52b, AFL++ 4.x, FairFuzz, MOpt-AFL, AFLFast, honggfuzz
  — chosen to cover AFL-family schedulers; libFuzzer not included (different coverage model)

---

## Deviations From Paper

N/A — this is the primary implementation (no prior paper).

---

## Open Questions

- Is `queued_paths` a sufficient proxy for edge coverage for the KS test input, or should the
  test be applied directly to the bitmap bitmap_cvg percentage?
- Does the EMA stagnation guard interact poorly with MOpt's adaptive mutation (which causes
  queued_paths to burst and stall in cycles)? seed_4 moptaflcd data suggests yes (3.62 resets/program).
- What is the correct CONSECUTIVE threshold for each fuzzer family? seed_4 suggests:
  - AFL: 5 is well-calibrated (0.43 resets/program)
  - AFL++: 5 is slightly high (2.38 resets/program — okay but some programs over-reset)
  - FairFuzz: 5 is too high (0 resets/program)
  - MOpt-AFL: 5 is too low (3.62 resets/program)
- Does the soft reset interact with AFL++'s MOpt table state? The alias table fix addresses
  the crash, but the question of whether replanting seeds from a wiped MOpt table gives optimal
  behavior is open.
- Should the paper claim per-pair improvement or overall improvement? With 4 pairs and 1 seed,
  the per-pair evidence is weak (especially fairfuzz which shows -6.9% coverage).
