# TODO

## High Priority

- [x] **dist5 deployed and launched** (2026-06-19 12:39 CDT, `tmux:dist5`)
- [x] **dist6 prepared and queued**: honggfuzz UaF fix (zombie approach), 8×3 manifest,
  rep2 SOFT_RESET=1 sweep — commit a0d951f8; auto-launches via `tmux:dist6_wait`
- [ ] **Analyze dist5 results** when done (~21:25 CDT): check honggfuzzcd Δ ≈ 0 (monitoring-only baseline)
- [ ] **Analyze dist6 results** when done (~next day): key questions:
  - honggfuzzcd: does reset fire without crash? Does Δ improve from ~0?
  - fairfuzzcd rep2 (SOFT_RESET=1): does Δ improve from -6?
  - aflcd/aflpluspluscd rep2: do det stages post-reset help?
- [ ] **Push commits to GitHub** — 8+ local commits unpushed (a6b53bb5..a0d951f8).
  `git bundle create /tmp/cdfuzzing.bundle HEAD`, scp to local, push.
- [ ] **Investigate fairfuzzcd `AFL_DRIFT_SOFT_RESET=2`** ✅ (RESOLVED): confirmed SOFT_RESET
  only fires post-reset (not global). Root cause is likely mode 2 blocking det re-run of
  rare-branch mutations. rep2 test with SOFT_RESET=1 will confirm in dist6.

## Medium Priority

## Medium Priority

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

- [ ] Add confidence intervals / Mann-Whitney U test to summary table once multiple seeds available
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
