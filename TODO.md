# TODO

## High Priority

- [ ] **Monitor dist2** — expected finish ~14:30 CDT 2026-06-18. Check:
  `tail -f /proj/cdfuzzing-PG0/distributed/dist2_orch.log`
  or `tmux attach -t dist2` on head. Extend CloudLab lease if needed before campaign ends.
- [ ] **Review dist2 analysis output** at `/proj/cdfuzzing-PG0/distributed/dist2/plots/`.
  Run analysis manually when complete:
  `CDFUZZ_BASE=/proj/cdfuzzing-PG0/distributed/dist2 CDFUZZ_OUTDIR=.../dist2/plots python3 /local/repository/plot_seed4.py`
- [ ] **Push commits to GitHub** — 4 local commits not yet pushed (SSH key not trusted on head).
  Commits: b97ea801 (dist1 complete + infra fixes), 0a60bf3c (FairFuzz blacklist trap fix),
  95b34cc0 (DECISIONS.md), 03cc0915 (worker-run.sh dist2 params).
  Option: `scp` the git bundle to a machine that has GitHub SSH access, then push.
- [ ] **Interpret dist2 results**: both reps same params → compute per-fuzzer mean Δbugs/Δcov%
  and run Mann-Whitney U tests CD vs baseline. Key questions:
  - Did honggfuzzcd resets fire correctly now (lazy init fix)? Check reset_report for dist2.
  - Did fairfuzzcd recover (blacklist trap fix + -q 1)? Check bug counts on libpng/libtiff/php.
  - Do winning params generalize? Compare dist2 vs dist1 rep-0 winning side.

## Medium Priority

- [ ] Investigate fairfuzz libtiff programs (both fuzzer+fuzzercd produced no `fuzzer_stats` in batch 1 on the previous node — root cause unknown)
- [ ] Replace `queued_paths` coverage metric with bitmap edge count (requires parsing `fuzzer_stats` bitmap_cvg field or using `afl-showmap` on queue)
- [ ] Add plot: reset timing distribution per fuzzer (when in 24h campaign do resets occur?)
- [ ] Export plots for paper: `scp -r eldarfin@head...:~/cdfuzzing/plots_seed4/ ~/paper/figures/`

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
