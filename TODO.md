# TODO

## High Priority

- [ ] **Run the distributed CloudLab experiment** — create profile from root `profile.py`, instantiate, `./orchestrate.sh --run-id dist1` on head — see CLOUDLAB.md (replaces the seed-by-seed single-machine runs below; honggfuzz now runs on per-node local disk)
- [ ] Verify the CloudLab scripts end-to-end on first instantiation (NFS wait, Docker data-root move to /mydata, inter-node SSH, manifest IPs) — they are syntax-checked but UNVERIFIED
- [ ] (Fallback if not using CloudLab) Run seeds 1–3 and 5 for the 4 complete pairs — `cdfuzzing/magma/tools/captain/`
- [ ] (Covered by distributed run) Add honggfuzz pair — per-node /mydata blockstore removes the disk limit; otherwise needs ≥100GB node
- [ ] (Covered by distributed run) Complete aflfast pair: openssl + php targets

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
