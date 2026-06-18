# Experiments

---

## seed_4: Batch 1 — fairfuzz + aflplusplus (24h)

Goal:
Establish baseline and CD results for fairfuzz and AFL++ on all 9 Magma targets.

Command:
```bash
cd ~/cdfuzzing/magma/tools/captain && bash run.sh captainrc_batch1
```

Configuration:
- Seed: 4
- Repetitions: 1 per program (21 programs × 2 fuzzers = 42 campaigns)
- Timeout: 24h
- Fuzzers: fairfuzz, fairfuzzcd, aflplusplus, aflpluspluscd
- Targets: all 9 (libpng, libtiff, libxml2, openssl, php, poppler, sqlite3, lua, libsndfile)
- Node: amd149.utah.cloudlab.us (node-0), 32 CPUs, 63GB disk
- Parameters: WINDOW=100, THRESHOLD=0.05, CONSECUTIVE=5, STAGNATION_FACTOR=0.5, COOLDOWN=10, EMA_ALPHA=0.1
- NO_ARCHIVE=1

Output:
- `~/experiment_results/seed_4/ar/{fairfuzz,fairfuzzcd,aflplusplus,aflpluspluscd}/{target}/{program}/0/`

Status:
Completed — 2026-06-13 (fairfuzz: 19/21 programs; libtiff missing both fuzzers; aflplusplus: 21/21)

Summary:
- aflplusplus→aflpluspluscd: 45→45 bugs (+0), +4.2% coverage, 50 resets
- fairfuzz→fairfuzzcd: 20→21 bugs (+1), -6.9% coverage, 0 resets
- Notable: fairfuzzcd never fired a reset (stagnation guard filtered 100% of 50 drifts)
- Notable: fairfuzz libtiff missing — root cause not investigated

Notes:
This was run on a fresh CloudLab node after the previous node expired. Docker required manual
setup (groupadd docker, chmod 666 /var/run/docker.sock). See DEBUGGING.md.

---

## seed_4: Batch 2 — moptafl + afl (24h)

Goal:
Establish baseline and CD results for moptafl and AFL on all 9 Magma targets.

Command:
```bash
cd ~/cdfuzzing/magma/tools/captain && bash run.sh captainrc_batch2
```

Configuration:
- Seed: 4
- Repetitions: 1 per program (21 programs × 2 fuzzers = 42 campaigns)
- Timeout: 24h
- Fuzzers: moptafl, moptaflcd, afl, aflcd
- Targets: all 9
- Node: same as batch 1
- Parameters: same as batch 1
- Config file: `cdfuzzing/magma/tools/captain/captainrc_batch2`

Output:
- `~/experiment_results/seed_4/ar/{moptafl,moptaflcd,afl,aflcd}/{target}/{program}/0/`

Status:
Completed — 2026-06-13 08:42 → 2026-06-15 ~09:30 (21/21 programs for all 4 fuzzers)

Summary:
- moptafl→moptaflcd: 47→46 bugs (-1), +1.1% coverage, 76 resets
- afl→aflcd: 26→29 bugs (+3), +4.7% coverage, 9 resets
- Notable: moptaflcd over-resets (3.62/program avg); MOpt scheduling amplifies KS p-value fluctuations
- Notable: aflcd is best-calibrated pair (0.43 resets/program, net positive bug and coverage delta)
- Notable: sqlite3 consistent winner (+37.4% coverage for moptaflcd, +8.6% for aflcd)

Notes:
First launch silently failed (Docker socket not ready). Logs looked successful but containers
exited immediately. Detected by checking `find .../ar/ -name fuzzer_stats | wc -l == 0`.
Fix: see DEBUGGING.md. Second launch succeeded.

---

## seed_4: Batch 3 — aflfast + honggfuzz (24h, partial)

Goal:
Establish baseline and CD results for aflfast and honggfuzz.

Command:
```bash
cd ~/cdfuzzing/magma/tools/captain && bash run.sh captainrc_batch3
```

Configuration:
- Fuzzers: aflfast, aflfastcd, honggfuzz, honggfuzzcd
- Targets: all 9
- Config file: `cdfuzzing/magma/tools/captain/captainrc_batch3`

Output:
- `~/experiment_results/seed_4/ar/{aflfast,aflfastcd}/{target}/{program}/0/` (honggfuzz dirs empty)

Status:
PARTIAL — 2026-06-15 09:30 → 2026-06-16 17:23
- aflfast: 21/21 programs completed
- aflfastcd: 11/21 programs (missing openssl×6 and php×4 — never started, disk exhaustion)
- honggfuzz: 0/21 (Docker build failed with exit code 100 — preinstall.sh failed due to full disk)
- honggfuzzcd: 0/21 (never attempted after honggfuzz build failure)

Summary:
- aflfast pair: incomplete — exclude from main analysis
- Decision made not to retry honggfuzz or aflfastcd in seed_4 (session already 4 days long)

Notes:
Disk was at 81% (48/63GB) when batch 3 started. Docker build cache (12.8GB) + accumulated images
caused disk exhaustion. Free space was restored to 51% but too late for honggfuzz.
See DEBUGGING.md for full disk recovery steps.

---

## seed_4: Full Analysis

Goal:
Generate all plots and summary tables from seed_4 raw workdir data.

Command:
```bash
cd ~/cdfuzzing && rm -rf plots_seed4 && python3 plot_seed4.py
```

Configuration:
- Script: `cdfuzzing/plot_seed4.py`
- Input: `~/experiment_results/seed_4/ar/`
- Output: `~/cdfuzzing/plots_seed4/` (52 files)
- Python deps: matplotlib, numpy (pip3 installed to ~/.local/)

Output:
- `~/cdfuzzing/plots_seed4/summary_table.txt` — per-program cross-pair results table
- `~/cdfuzzing/plots_seed4/parameter_eval.txt` — stagnation guard + reset distribution analysis
- `~/cdfuzzing/plots_seed4/bug_report.txt` — per-program bug counts
- `~/cdfuzzing/plots_seed4/reset_report.txt` — per-fuzzer drift/reset counts
- Coverage line plots (9 PNGs), bug bar charts (5 PNGs × 2), drift signal plots (21 PNGs), reset plots

Status:
Completed — 2026-06-17

Summary:
4-pair results (excluding partial aflfast):
- Total bugs: 138 base → 141 CD (+3 across 4 pairs)
- afl→aflcd best: +3 bugs, +4.7% coverage
- sqlite3 most consistent beneficiary across all pairs
- fairfuzzcd underperforms due to 0 resets (conservative guard)
- moptaflcd over-resets (76 resets across 21 programs)

Notes:
Coverage metric is `queued_paths` (corpus size), not bitmap edge count. See DECISIONS.md.

---

## distributed (CloudLab): smoke1 — afl+aflcd, sqlite3, 10min (COMPLETE)

Goal:
End-to-end verification of the CloudLab pipeline before launching the full dist1 campaign.

Command:
```bash
cd /local/repository/cloudlab
./orchestrate.sh --run-id smoke1 --timeout 10m --fuzzers "afl aflcd" --targets "sqlite3"
```

Configuration:
- 4 workers (afl-0, afl-1, aflcd-0, aflcd-1), 1 target (sqlite3), 1 program (sqlite3)
- Timeout: 10min
- CD parameters: CONSECUTIVE=5, STAGNATION_FACTOR=0.5 (defaults)

Output:
- `/proj/cdfuzzing-PG0/distributed/smoke1/ar/`
- `/proj/cdfuzzing-PG0/distributed/smoke1/plots/` (15 output files)

Status:
COMPLETE — 2026-06-17. 4/4 workers done, 0 failed.

Summary:
- Pipeline verified end-to-end: Docker build, captain, rsync to NFS, plot_seed4.py analysis
- matplotlib/numpy installed on head via apt (pip ~/.local/ path was insufficient)
- 15 output files confirmed in plots/ dir

---

## distributed (CloudLab): dist1 — all 12 fuzzers, 8h, multi-node (COMPLETE)

Goal:
Replace the single-machine seed-by-seed workflow with one node per
(fuzzer × repetition). Produce multi-rep results for all 12 fuzzers — including
honggfuzz (which seed_4 could not run on a single 63GB node). Additionally,
run an A/B parameter search for all 6 CD fuzzers (see DECISIONS.md).

Command:
```bash
cd /local/repository/cloudlab
./orchestrate.sh --run-id dist1 --timeout 8h --poll 60
# launched in tmux session 'dist1' on head, 2026-06-17 ~20:20 CDT
```

Configuration:
- fuzzerSet=all, nodesPerFuzzer=2 → 24 workers + 1 head = 25 nodes
- Each worker = 1 repetition; per-node `/mydata` blockstore (~87GB free)
- Targets: all 9 Magma targets (21 programs)
- CD parameters: A/B per-rep design — see DECISIONS.md for full mapping
- Baselines: both reps identical (CONSECUTIVE=5, STAGNATION_FACTOR=0.5)
- Worker run log: `/mydata/dist1-<fuzzer>-<rep>.boot.log` on each worker
- Merge target: `/proj/cdfuzzing-PG0/distributed/dist1/`

Output:
- `/proj/cdfuzzing-PG0/distributed/dist1/ar/<fuzzer>/<target>/<program>/<rep>/`
- `/proj/cdfuzzing-PG0/distributed/dist1/plots/` (55 files from `plot_seed4.py`)
- `/proj/cdfuzzing-PG0/distributed/dist1_orch.log`

Status:
COMPLETE — finished 2026-06-18 ~05:20 CDT. All 24 workers done, 0 failed.

Summary:
| Pair | Δbugs | Δcov% | Resets | Notes |
|---|---|---|---|---|
| moptafl→moptaflcd | +3 | +6.3% | 25 | Best. sqlite3 +89%. |
| aflfast→aflfastcd | +1 | +1.0% | 3 | Modest positive. |
| afl→aflcd | +0 | +5.7% | 6 | Good coverage gain. |
| aflplusplus→aflpluspluscd | +0 | -0.2% | 18 | Near neutral. |
| fairfuzz→fairfuzzcd | -5 | -14.4% | 0 | BUG: blacklist trap (fixed). |
| honggfuzz→honggfuzzcd | -3 | +3.3% | 0 | BUG: CD init race (fixed). |

Bugs found and fixed (all in codebase for dist2):
- `plot_seed4.py`: honggfuzz missing from PAIRS; get_final_cov() fallback for output/ layout;
  parse_drift_log() output/ path for honggfuzz family
- `honggfuzzcd/newsrc/honggfuzz.c`: lazy initial_corpus_count in driftCycle() —
  dist1 had 17512 drifts detected, 0 resets fired (all blocked by initial_corpus_count==0)
- `fairfuzzcd/newsrc/afl-fuzz.c` + both fairfuzz*/run.sh: FairFuzz blacklist trap —
  `-q 1` enables vanilla AFL fallback when stuck; perform_corpus_reset() now clears
  hit_bits/blacklist/fuzzed_branches so CD resets don’t re-trigger the stuck state

Notes:
dist1 A/B parameter comparison (per-rep different params) produced winning params
for dist2. Files deployed to workers via scp (git push to GitHub SSH blocked on head node).

---

## distributed (CloudLab): dist2 — all 12 fuzzers, 8h, winning params (RUNNING)

Goal:
Replicate dist1 with winning CD parameters on both reps for each fuzzer.
Both reps are genuine statistical repetitions (not A/B). Also validates the three
bug fixes applied after dist1: honggfuzz.c CD init, FairFuzz blacklist trap,
FairFuzz state reset on corpus reset.

Command:
```bash
cd /local/repository/cloudlab
./orchestrate.sh --run-id dist2 --timeout 8h
# launched in tmux session 'dist2' on head, 2026-06-18 ~06:30 CDT
```

Configuration:
- Same cluster (25 nodes), same targets, same programs as dist1
- Winning params: aflcd C=3/SF=0.5, aflpluspluscd C=8/SF=0.5, fairfuzzcd C=3/SF=0.5,
  moptaflcd C=5/SF=0.3, aflfastcd C=3/SF=0.5, honggfuzzcd C=5/SF=0.5
- Baselines: both reps identical (unchanged)
- Code fixes active: honggfuzz.c lazy init, fairfuzz -q 1, perform_corpus_reset() state reset

Output:
- `/proj/cdfuzzing-PG0/distributed/dist2/ar/<fuzzer>/<target>/<program>/<rep>/`
- `/proj/cdfuzzing-PG0/distributed/dist2/plots/` (from plot_seed4.py)
- `/proj/cdfuzzing-PG0/distributed/dist2_orch.log`

Status:
RUNNING — dispatched 2026-06-18 06:30 CDT; expected finish ~14:30 CDT 2026-06-18.
All 24 workers dispatched (0 skipped).

