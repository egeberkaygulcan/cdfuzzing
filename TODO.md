# TODO

## High Priority

- [ ] Run seeds 1–3 and 5 for all 4 complete pairs (aflplusplus, fairfuzz, moptafl, afl) — need ≥3 seeds for statistical claims — `cdfuzzing/magma/tools/captain/`
- [ ] Add honggfuzz pair on a node with ≥100GB disk (or prune queue/ dirs before batch runs to stay under 60GB) — see DEBUGGING.md for disk issue
- [ ] Complete aflfast pair: re-run aflfastcd for openssl and php targets only — `captainrc_rerun_b3` exists but was not used

## Medium Priority

- [ ] Tune CD parameters per fuzzer family based on seed_4 findings:
  - fairfuzzcd: lower `CONSECUTIVE` from 5 to 3 (0 resets fired in seed_4)
  - moptaflcd: raise `CONSECUTIVE` to 8 or lower `STAGNATION_FACTOR` to 0.3 (3.62 resets/program)
- [ ] Investigate fairfuzz libtiff programs (both fuzzer+fuzzercd produced no `fuzzer_stats` in batch 1 on the previous node — root cause unknown)
- [ ] Replace `queued_paths` coverage metric with bitmap edge count (requires parsing `fuzzer_stats` bitmap_cvg field or using `afl-showmap` on queue)
- [ ] Add plot: reset timing distribution per fuzzer (when in 24h campaign do resets occur?)
- [ ] Export plots for paper: `scp -r eldarfin@amd149.utah.cloudlab.us:~/cdfuzzing/plots_seed4/ ~/paper/figures/`

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
