# TODO

## Active

- [ ] **dist14: still running** — expected done ~June 29 18:00–18:30 CDT. Last batch containers started June 28 ~17:46; 24h timeout fires ~17:46 CDT today. Then analyze: honggfuzz KEEP_RECENT=50 vs 0 on Δbugs and Δcov.
  ```bash
  done=$(ls /proj/CDFuzzing/distributed/dist14/status/*.done 2>/dev/null | wc -l)
  echo "dist14: $done/20 done"
  ```

- [ ] **Analyze dist14** — after all 20 workers done, run plot_seed4.py (or targeted script) comparing honggfuzz KEEP_RECENT=50 vs KEEP_RECENT=0.

## Done (2026-06-29)

- [x] **dist14/dist15 status checked** — dist14: 9/20 done, 11 running (still in progress; expected done ~18:00-18:30 CDT). dist15: fuzzing complete, Utah NFS quota exhausted (100% full); worker data pulled to Wisconsin `/mydata/dist15/ar/` (monitor/ dirs later deleted for inode exhaustion).
- [x] **dist15 analyzed** — `analyze_dist15.py` run; results in HANDOFF.md. CL=60 prevents cascade (aflcd_v2 −47% resets). aflfastcd_v2 C=2 hypothesis failed (sqlite3 0/5 reps). aflfastcd_v2 limited to 5/10 reps (workers .35-.39 inaccessible from Utah head).
- [x] **Δbugs methodology established** — correct metric: per-program union over all 10 reps, summed. Confirmed evaluation.tex table Δbugs column is already correct for 10-rep data.
- [x] **dfcov/dfbug/dfbugdelta analysis** — full 6-pair dataframe analysis (fired-reps-only): coverage delta per program, bug ID union per program, bug delta per fuzzer pair. Results: moptafl best (+6 fired-only, +8 all-reps); others near 0 when restricted to fired reps.
- [x] **All-6-pairs fired-only analysis** — confirmed drift_log paths for all fuzzer families (AFL: `findings/drift_log.csv`; AFL++/honggfuzz: `findings/default/drift_log.csv`). Per-rep reset counts verified.

## Done (2026-06-27)

- [x] **dist13 COMPLETE + MERGED** — 25/25 Utah workers done; data at `/mydata/dist13/ar/` on Wisconsin (local disk); symlinked into `merged/ar/` as reps 8–9 on June 27 ~14:48.
- [x] **10-rep analysis confirmed** — evaluation.tex table numbers correct at 10 reps; guard stats unchanged (3,222 detected / 144 fired / 95.5% suppression).
- [x] **Root cause analysis complete** — AFL-CD cascade reset pattern (CL=10 causes 6 resets in first 3.3h, then vanilla AFL for 86% of campaign); AFLFast-CD C=3 too conservative for sqlite3 (only 1/8 reps fires).
- [x] **dist14 launched** — 20 workers, honggfuzz KEEP_RECENT=50, Wisconsin, expected ~June 27 18:30 MDT.
- [x] **dist15 launched** — 30 workers, aflcd_v2/v3 + aflfastcd_v2, Utah, expected ~June 28 18:00 MDT.

## Done (2026-06-26)

- [x] **dist11 COMPLETE** — 60/60 workers done, all reps 0–4, `/proj/CDFuzzing/distributed/dist11/ar/`
- [x] **dist12 COMPLETE** — 36/36 workers done, reps 5–7 (Utah cluster2), ~07:35 CDT 2026-06-26
- [x] **Transfer dist12 → Wisconsin** — rsync (ar/ without monitor/), thin monitor via Python
- [x] **merged/ar/ symlink tree** — 1,995 symlinks, reps 0–7, `/proj/CDFuzzing/distributed/merged/ar/`
- [x] **8-rep analysis** — plot_seed4.py on merged/, summary at `.../merged/plots/summary_table.txt`
- [x] **Paper updated** — evaluation.tex table updated with 8-rep values, compiles clean (6 pages)
- [x] **CLUSTER2.md created** — Utah cluster documentation (identity, access, dist12, dist13 plan)

## Historical (prior sessions)

: honggfuzz UaF fix (zombie approach), 8×3 manifest,
  rep2 SOFT_RESET=1 sweep — commit a0d951f8; auto-launches via `tmux:dist6_wait`
- [x] **Analyze dist5 results**: honggfuzzcd Δ=+1 with 0 resets confirms UaF was causing the -11
- [x] **Analyze dist6 results**: afl +2 ✅, fairfuzz +1 ✅, aflplusplus -3 ❌, honggfuzz INVALID ⚠
- [x] **Fix worker-run.sh NFS issues** (commit b7077dd7):
  - `--exclude '*.honggfuzz.cov'` added to rsync
  - NFS free-space pre-check added (warn if <10GB)
  - `copied` counter now only increments on rsync success
- [x] **dist7 launched** (2026-06-20 15:29 CDT): 6-rep paired-seed sweep for honggfuzz+aflplusplus
  — `tmux:dist7` fuzzing, `tmux:dist7_followup` auto-analysis, expected done ~20:13 CDT
- [x] **Analyze dist7 results** (2026-06-21):
  - honggfuzzcd: no config effective — resets consistently hurt; +2 rep fired 0 resets (noise)
  - aflpluspluscd: SOFT_RESET=1 is the key variable; best config SR=1,C=10,CL=25 → **+11 bugs**
  - See DECISIONS.md § dist7 outcomes for full interpretation
- [x] **dist8 COMPLETE** (2026-06-21 13:14 CDT): aflpluspluscd confirmed +1.8 avg (C=10); C=12 gave +8 (best); honggfuzz C/CL bug discovered
- [x] **Fix honggfuzz drift-detect.c**: `drift_init()` now reads `AFL_DRIFT_CONSECUTIVE`/`AFL_DRIFT_COOLDOWN`; `drift_check_value()` enforces consecutive/cooldown gate
- [x] **smoke9 PASSED** (2026-06-21 ~16:47 CDT): consecutive_drifts counted 0→1→0 (reset at C=2), cooldown 5→0, corpus reset confirmed (queue 814→105)
- [x] ⚠ **dist9 INVALID** (2026-06-22, post-mortem): only worker .16 had the honggfuzz fix; workers .17–.33 were at c85513f6 (dist7 code). Results cannot be trusted.
- [x] **orchestrate.sh fixed**: now does `git pull --ff-only` on each worker before running worker-run.sh
- [x] **All 24 workers pulled to 65fc953b** (2026-06-22, manually)
- [x] **dist10 LAUNCHED** (2026-06-22 07:43 CDT, `tmux:dist10`): full paper run — 12 fuzzers × 5 reps
  × 24h, all confirmed best params, seeds 1000–1004, commit `1bfa67b2`.
  Expected done: 2026-06-23 ~07:45 CDT.
  Monitor: `tmux attach -t dist10` or `tail -f /proj/cdfuzzing-PG0/distributed/dist10_orch.log`
- [x] **dist10 LOST** (2026-06-23): CloudLab lease expired ~22:36 CDT June 22 (~14h in). Local /mydata wiped on deallocation; rsync never ran. ar/ empty. All prior dist1–dist9 data also gone (were on old cluster NFS).
- [x] **Fix libtiff fetch.sh** (2026-06-23, commit `15974124`): 24/60 workers had libtiff build failures in dist10 due to GitLab rate-limiting concurrent clones. Added 3-attempt retry with 30/60/90s backoff.
- [x] **Launch dist11** (2026-06-23 04:37 CDT, `tmux:dist11`): full redo of dist10 with libtiff fix — 12 fuzzers × 5 reps × 24h, commit `0271863d`, all 60 workers confirmed.
  Expected done: 2026-06-24 ~04:38 CDT.
  Monitor: `tmux attach -t dist11` or `tail -f /proj/CDFuzzing/dist11_orch.log`
- [x] **Analyze dist11+dist12 results** — done via 8-rep merged analysis
- [x] **Update paper draft** — 8-rep values in evaluation.tex; compiles clean

## Medium Priority

- [ ] Re-run dist2 analysis to confirm honggfuzz coverage metric (output/ file count vs edge count):
  the -62.6% coverage loss in honggfuzzcd may be partly an artifact of the get_final_cov()
  fallback counting output/ files at end-of-run (near-empty after last reset). Consider adding
  per-minute peak coverage tracking to plot_seed4.py for honggfuzz.
- [ ] Investigate fairfuzz libtiff programs (both fuzzer+fuzzercd produced no `fuzzer_stats`
  in batch 1 on the previous node — root cause unknown)
- [ ] Replace `queued_paths` coverage metric with bitmap edge count (requires parsing
  `fuzzer_stats` bitmap_cvg field or using `afl-showmap` on queue)
- [ ] Export plots for paper: `scp -r eldarfin@head...:cdfuzzing-pg0/dist2/plots/ ~/paper/figures/`
- [ ] Extend CloudLab lease before it expires (check deadline: `cloudlab.us → experiments → eldarfin-308618`)

## Low Priority

- [ ] Add confidence intervals / Mann-Whitney U test to summary table (10 reps will enable this)
- [ ] Investigate poppler/pdftoppm AFL++CD anomaly: +12.7% coverage but -3 bugs (6→3)
- [ ] Investigate lua/lua AFL++CD anomaly: -29.2% coverage and -1 bug (4 resets may over-reset)
- [ ] Add libsndfile fairfuzz anomaly to DEBUGGING.md: +3 bugs with 0 resets and -43% coverage — possible canary detection timing difference
- [ ] Consider pruning queue/ directories from seed_4 results to save disk (currently ~21GB total; queue/ alone ≈ 8GB) — keep fuzzer_stats, plot_data, drift_log.csv, monitor/
- [ ] Write artifact evaluation README for public release

## Done

- [x] Implement CD module in AFL, AFL++, fairfuzz, moptafl, aflfast, honggfuzz — 2026 (prior session)
- [x] Fix AFL++CD bugs: alias table splice loop, top_rated[] splice loop — 2026-06 (see DEBUGGING.md)
- [x] Run batch 1 (fairfuzz + aflplusplus), 24h — 2026-06-13
- [x] Run batch 2 (moptafl + afl), 24h — 2026-06-13 to 2026-06-15
- [x] Run batch 3 (aflfast partial), 24h — 2026-06-15 to 2026-06-16 (honggfuzz never started due to disk)
- [x] Run full analysis: `plot_seed4.py` — 2026-06-17, 52 output files in `~/cdfuzzing/plots_seed4/`
- [x] Generate cross-pair summary table — `summary_table.txt` — 2026-06-17
- [x] Generate parameter evaluation report — `parameter_eval.txt` — 2026-06-17
- [x] Fix boot_command() quoting bug in profile.py — 2026-06-17
- [x] Fix /users shared-FS assumption in all cloudlab/*.sh — 2026-06-17
- [x] Fix honggfuzzcd cascade loop (peak_corpus metric + 60s time-gate) — commit 7043370d
- [x] Update dist3 parameters (fairfuzzcd C=15, aflcd/aflpluspluscd COOLDOWN=25) — 2026-06-18
- [x] Launch and complete dist3 — 2026-06-18 ~16:15 CDT → 2026-06-19 01:07 CDT
- [x] Implement selective reset for honggfuzzcd — commit 9132d446 (dist4)
- [x] Launch and complete dist4 — 2026-06-19 ~03:29 CDT → 12:22 CDT
- [x] Diagnose dist4 honggfuzzcd crash (UaF in selective reset) — commit ac9eec7f disables reset
- [x] Provision all 25 CloudLab nodes manually (24/24 EXIT=0) — 2026-06-17
- [x] Verify cluster: Docker, /mydata, SSH keypair, manifest, head→worker passwordless SSH — 2026-06-17
- [x] Fix plot_seed4.py hardcoded campaign ID "0" to glob "*" for distributed layout — 2026-06-17
- [x] Run smoke test (smoke1: afl+aflcd, sqlite3, 10min) — 4/4 done, 15 analysis files — 2026-06-17
- [x] Design and implement A/B per-rep CD parameter search for dist1 (worker-run.sh) — 2026-06-17
- [x] Deploy updated worker-run.sh to all 24 workers — 2026-06-17
- [x] Launch dist1 in tmux (8h, all 12 fuzzers × 2 reps, 24 workers) — 2026-06-17 ~20:20 CDT
- [x] dist1 COMPLETE: all 24 workers done, results at /proj/cdfuzzing-PG0/distributed/dist1/ — 2026-06-18 ~05:20 CDT
- [x] Fix plot_seed4.py: add honggfuzz to PAIRS, get_final_cov() fallback, output/drift_log.csv path — 2026-06-18
- [x] Fix honggfuzzcd CD init race (initial_corpus_count sampled before corpus loads → 0 resets) — 2026-06-18
- [x] Fix FairFuzz blacklist trap: -q 1 in run.sh + state reset in perform_corpus_reset() — 2026-06-18
- [x] Select dist2 winning params from dist1 A/B analysis; update worker-run.sh — 2026-06-18
- [x] Deploy 5 fixed files to all 24 workers via scp — 2026-06-18
- [x] Launch dist2 in tmux (8h, all 12 fuzzers × 2 reps, winning params) — 2026-06-18 ~06:30 CDT
- [x] dist2 COMPLETE: all 24 workers done, results at /proj/cdfuzzing-PG0/distributed/dist2/ — 2026-06-18 ~15:24 CDT
- [x] Deep-dive dist2 analysis: honggfuzzcd root cause (cascade loop / non-monotonic metric), fairfuzzcd root cause (rare-branch state recovery), moptaflcd/aflfastcd win analysis — 2026-06-18
- [x] Update EXPERIMENTS.md, DECISIONS.md, HANDOFF.md, TODO.md with dist2 results and dist3 plan — 2026-06-18
