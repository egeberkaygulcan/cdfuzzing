# Decisions

## 2026-06-17: Exclude aflfast pair from main results table

Decision:
The aflfast→aflfastcd pair is excluded from the four-pair main result summary because aflfastcd is
missing openssl (6 programs) and php (4 programs) — 10 of 21 programs never ran.
The partial pair shows -47.9% coverage which is an artifact of the missing programs having 0
coverage, not a real regression.

Reason:
Including partial data in aggregate totals gives misleading grand total numbers.
The 4 complete pairs (aflplusplus, fairfuzz, moptafl, afl) are the basis for conclusions.

Alternatives considered:
- Imputing missing programs with baseline values: would require a defensible imputation method;
  avoided to prevent introducing bias.
- Re-running aflfastcd for openssl+php only: `captainrc_rerun_b3` was created for this purpose
  but not used because disk space was marginal (30GB free after honggfuzz failure) and the
  session had already been running for days.

Consequences:
`summary_table.txt` still includes aflfast pair for completeness but with a note.
Grand total in `summary_table.txt` is -5 bugs / -4.5% coverage — this is misleading and should
not be cited without noting the partial aflfastcd data.

---

## 2026-06-17: Do not run honggfuzz in seed_4

Decision:
honggfuzz and honggfuzzcd were not run in seed_4 due to disk space exhaustion during Docker builds.

Reason:
63GB node disk was 81% full (≈ 48GB used) when batch 3 started. honggfuzz preinstall.sh failed
with exit code 100. After freeing 20GB, the decision was made to stop rather than restart because
disk would fill again during the runs (queue/ dirs accumulate at ~1GB/fuzzer/target/day).

Alternatives considered:
- Running honggfuzz on a larger node: valid option for a future seed.
- Pruning queue/ before running honggfuzz: would require interrupting the running aflfastcd batch.

Consequences:
honggfuzz pair is absent from seed_4. A future seed should either use a ≥100GB node or
explicitly prune queue/ dirs after each batch to stay under disk limit.

---

## 2026-06-15: Use NO_ARCHIVE=1 for all batches

Decision:
All captainrc files set `NO_ARCHIVE=1`. Results are stored as raw workdirs under
`~/experiment_results/seed_4/ar/{fuzzer}/{target}/{program}/0/` rather than being tar'd.

Reason:
Archiving adds significant I/O time at the end of a 24h campaign and requires extra disk for the
intermediate archive. Analysis scripts (`plot_seed4.py`) read raw workdirs directly.

Alternatives considered:
- Archiving with ARCHIVE=1: would save disk long-term by compressing queue/, but requires more
  I/O during the campaign end and a different analysis path.

Consequences:
queue/ directories accumulate and consume ~8GB across all runs. If disk is tight, prune queue/
before starting the next batch:
  `find ~/experiment_results/seed_4/ar -type d -name queue -exec rm -rf {} + 2>/dev/null`

---

## 2026-06-13: Coverage metric is queued_paths, not bitmap edge count

Decision:
`plot_seed4.py` reads the `corpus_size` field from `fuzzer_stats`, which corresponds to
`queued_paths` in AFL terminology (number of corpus entries), not bitmap edge coverage.

Reason:
`queued_paths` is present in all AFL-family fuzzer_stats files and is trivially parseable.
Bitmap edge coverage requires either `bitmap_cvg` (a percentage) or running `afl-showmap` on the
entire queue, which is significantly more expensive.

Alternatives considered:
- Using `bitmap_cvg` from fuzzer_stats: this is a percentage (e.g. "7.23%") not an absolute
  count, making cross-fuzzer comparison harder.
- Using `afl-showmap`: accurate but requires re-running instrumented binary on each corpus file;
  too expensive for post-hoc analysis.

Consequences:
Coverage delta numbers in `summary_table.txt` and `parameter_eval.txt` reflect corpus growth, not
edge coverage. The +367% mean delta in the "0 resets" bucket in the parameter eval is dominated
by programs where CD kept the corpus growing longer — not raw edge coverage.
This must be clearly stated in the paper.

---

## 2026-06-12: Fix AFL++CD alias table and splice loop bugs before seed_4

Decision:
Three bugs in the AFL++CD implementation were fixed before seed_4 runs. Fixes are applied via
`sed` in `cdfuzzing/magma/fuzzers/aflpluspluscd/fetch.sh` and `newsrc/` patch files.

Bugs fixed:
1. Alias table not populated on soft reset — caused crash/infinite loop after first reset
2. `top_rated[]` not cleared on soft reset — caused stale entries after corpus wipe
3. Splice loop `->disabled` check missing — caused use-after-free when splicing with cleared corpus

Reason:
These bugs caused AFL++CD to crash or produce corrupted results in earlier seeds (seeds 1–3).
seed_4 is the first seed where AFL++CD is considered correct.

Consequences:
Do not compare seed_4 AFL++CD results to seeds 1–3 for AFL++. Seeds 1–3 AFL++ data is invalid.
The `newsrc/` directory in `fuzzers/aflpluspluscd/` contains the patched source overrides.

---

## 2026-06-10: seed=4 chosen as baseline for first complete evaluation

Decision:
`seed=4` was used for the first complete single-seed evaluation. Seeds 1–3 were invalidated by
the AFL++CD alias table bug. Seed 5 and beyond are reserved for multi-seed validation.

Reason:
Needed a clean seed not contaminated by the AFL++CD bug to produce trustworthy results.

Consequences:
seed_4 results are preliminary (single seed, no confidence intervals).
Paper claims must be framed as "preliminary evaluation" until multi-seed results are available.

---

## 2026-06: CD parameters for seed_4

Decision:
```
AFL_DRIFT_WINDOW=100
AFL_DRIFT_THRESHOLD=0.05
AFL_DRIFT_CONSECUTIVE=5
AFL_DRIFT_STAGNATION_FACTOR=0.5
AFL_DRIFT_COOLDOWN=10
AFL_DRIFT_EMA_ALPHA=0.1
AFL_DRIFT_SOFT_RESET=2
AFL_DRIFT_MAX_RESETS=0   (unlimited)
AFL_DRIFT_HAVOC_BOOST=2
AFL_DRIFT_BOOST_CYCLES=1
```

These are the same parameters as seeds 1–3 to allow future cross-seed comparison once bugs are fixed.

Reason:
Keeping parameters stable across seeds isolates the effect of the bug fix.

Consequences:
The parameter eval (see `parameter_eval.txt`) shows `fairfuzzcd` never fires (CONSECUTIVE=5 too
high for fairfuzz's slow scheduling) and `moptaflcd` over-resets (3.62/program). dist1 tests
alternative parameters per the A/B design below.

---

## 2026-06-17: A/B per-rep parameter design for dist1

Decision:
`dist1` uses different `AFL_DRIFT_CONSECUTIVE` / `AFL_DRIFT_STAGNATION_FACTOR` values for
rep 0 vs rep 1 of each CD fuzzer, rather than running identical repetitions. This makes each
2-node CD pair a single-shot A/B comparison instead of a plain statistical repetition.

Rationale (from seed_4 `parameter_eval.txt`):
- `fairfuzzcd` (C=5): 0 resets fired (stagnation guard filtered 100% of 50 drifts — too conservative)
- `moptaflcd` (C=5): 3.62 resets/program (MOpt's mutation scheduling amplifies KS p-values)
- `aflpluspluscd` (C=5): 2.38 resets/program (moderately high)
- `aflcd` (C=5): 0.43 resets/program (reference — best-calibrated pair)

A/B parameter mapping for dist1:

| CD Fuzzer      | Rep 0 (Config A)       | Rep 1 (Config B)       | Goal                            |
|---|---|---|---|
| aflcd          | C=5, SF=0.5 (seed_4)   | C=3, SF=0.5            | reference vs more aggressive    |
| aflpluspluscd  | C=6, SF=0.5            | C=8, SF=0.5            | mild vs aggressive reduction    |
| fairfuzzcd     | C=3, SF=0.5            | C=2, SF=0.5            | both fix 0-reset (C=5 filtered 100%) |
| moptaflcd      | C=8, SF=0.5            | C=5, SF=0.3            | raise bar vs tighten stagnation guard |
| aflfastcd      | C=5, SF=0.5 (default)  | C=3, SF=0.5            | default vs more aggressive      |
| honggfuzzcd    | C=5, SF=0.5 (default)  | C=3, SF=0.5            | default vs more aggressive      |

Baseline fuzzers (afl, aflplusplus, fairfuzz, moptafl, aflfast, honggfuzz): both reps identical.
The CD environment variables are exported for baselines too (present but inactive — no CD module).

Implementation:
`cloudlab/worker-run.sh` has a `case "$FUZZER"` block that sets `CD_CONSECUTIVE` and
`CD_STAGNATION` before writing the captainrc. These are exported as
`AFL_DRIFT_CONSECUTIVE` and `AFL_DRIFT_STAGNATION_FACTOR` into the fuzzer container environment.

Consequences:
dist1 reps are NOT pure statistical repetitions for CD fuzzers — they test different parameter
regimes. A follow-up run (dist2) with fixed winning parameters on both reps is needed before
computing confidence intervals or statistical tests on CD-vs-baseline comparisons.
A single-seed result per config will be directional only; 3+ reps needed for significance.
