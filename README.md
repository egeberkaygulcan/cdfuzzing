# cdfuzzing

Concept-drift-guided fuzzing: integrates a KS-test-based corpus stagnation detector into
AFL-family fuzzers (AFL, AFL++, FairFuzz, MOpt-AFL, AFLFast, honggfuzz). When persistent
concept drift is detected in the corpus growth signal, the fuzzer performs a soft reset —
wiping the corpus and replanting a subset of high-value seeds — to escape local optima.

Evaluated on the [Magma](https://hexhive.epfl.ch/magma/) benchmark (9 targets, 21 programs,
24h campaigns). See `EXPERIMENTS.md` for the full experiment ledger and `HANDOFF.md` for
current project state.

## Repository Layout

```
cdfuzzing/
  magma/                    Magma benchmark (modified)
    fuzzers/
      afl/                  Baseline AFL
      aflcd/                AFL + CD module
      aflplusplus/          Baseline AFL++
      aflpluspluscd/        AFL++ + CD module  ← also contains alias table / splice loop bug fixes
      fairfuzz/             Baseline FairFuzz
      fairfuzzcd/           FairFuzz + CD module
      moptafl/              Baseline MOpt-AFL
      moptaflcd/            MOpt-AFL + CD module
      aflfast/              Baseline AFLFast
      aflfastcd/            AFLFast + CD module
      honggfuzz/            Baseline honggfuzz
      honggfuzzcd/          honggfuzz + CD module
    targets/                9 Magma targets (libpng, libtiff, libxml2, openssl, php, poppler,
                            sqlite3, lua, libsndfile)
    tools/captain/          Campaign orchestration (captainrc_* files)
  plot_seed4.py             Analysis script for seed_4 results
  plots_seed4/              Generated plots and reports (not committed)
  HANDOFF.md                Current project state and next steps
  TODO.md                   Pending tasks
  DECISIONS.md              Key design and methodology decisions
  EXPERIMENTS.md            Experiment ledger
  DEBUGGING.md              Known issues and fixes
  PAPER_NOTES.md            Method details and open questions
```

## Quick Start

### Reproduce the seed_4 analysis

```bash
# On CloudLab node amd149.utah.cloudlab.us (eldarfin@node-0)
# Results must be present at ~/experiment_results/seed_4/ar/

cd ~/cdfuzzing
rm -rf plots_seed4
python3 plot_seed4.py
# Output: ~/cdfuzzing/plots_seed4/ (52 files)
```

### Run a new experiment batch

```bash
# Fix Docker socket if needed (after node reboot)
sudo chmod 666 /var/run/docker.sock

# Launch a batch
cd ~/cdfuzzing/magma/tools/captain
bash run.sh captainrc_batch2   # or captainrc_batch3, etc.
```

### CD parameters (seed_4)

| Parameter | Value | Effect |
|---|---|---|
| AFL_DRIFT_WINDOW | 100 | KS test window size |
| AFL_DRIFT_THRESHOLD | 0.05 | p-value cutoff |
| AFL_DRIFT_CONSECUTIVE | 5 | Windows below threshold before reset |
| AFL_DRIFT_STAGNATION_FACTOR | 0.5 | EMA growth guard |
| AFL_DRIFT_COOLDOWN | 10 | Min windows between resets |
| AFL_DRIFT_EMA_ALPHA | 0.1 | EMA smoothing |

## seed_4 Results (4 complete pairs)

| Pair | Δbugs | Δcov% | Resets |
|---|---|---|---|
| aflplusplus → aflpluspluscd | +0 | +4.2% | 50 |
| fairfuzz → fairfuzzcd | +1 | -6.9% | 0 |
| moptafl → moptaflcd | -1 | +1.1% | 76 |
| afl → aflcd | **+3** | **+4.7%** | 9 |

Coverage metric is `queued_paths` (corpus size), not bitmap edge count.
Detailed results: `plots_seed4/summary_table.txt`, `plots_seed4/parameter_eval.txt`.
