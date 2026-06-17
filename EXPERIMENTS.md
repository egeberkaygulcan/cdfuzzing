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
