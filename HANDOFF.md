# Handoff

## Current Goal

Evaluate CD-Fuzzing (concept drift detection integrated into AFL-family fuzzers) on the Magma
benchmark. Seed 4 experiments are complete for 4 fuzzer pairs. **Active next step: run the
distributed CloudLab experiment** (one node per fuzzer×repetition, head-dispatched + merged)
to get multi-rep results for all 12 fuzzers — see CLOUDLAB.md. This is the work for the new session.

## Current State

**Seed 4 experiments — COMPLETE (4 of 5 intended pairs)**

| Pair | Status | Bugs (base→CD) | Δbugs | Δcov% | Resets |
|---|---|---|---|---|---|
| aflplusplus → aflpluspluscd | ✅ 21/21 programs | 45 → 45 | +0 | +4.2% | 50 |
| fairfuzz → fairfuzzcd | ✅ 19/21 programs (no libtiff) | 20 → 21 | +1 | -6.9% | 0 |
| moptafl → moptaflcd | ✅ 21/21 programs | 47 → 46 | -1 | +1.1% | 76 |
| afl → aflcd | ✅ 21/21 programs | 26 → 29 | +3 | +4.7% | 9 |
| aflfast → aflfastcd | ⚠️ 11/21 programs (no openssl/php) | — | — | — | 1 |
| honggfuzz → honggfuzzcd | ❌ 0/21 (disk full, not attempted again) | — | — | — | — |

**Analysis — COMPLETE**
- 52 output files in `~/cdfuzzing/plots_seed4/`
- Key outputs: `summary_table.txt`, `parameter_eval.txt`, `bug_report.txt`, `reset_report.txt`
- Coverage line plots, bug bar charts, drift signal plots, reset timing/summary plots

**Distributed CloudLab experiment — SCRIPTS READY, NOT YET RUN**
- Root `profile.py` (geni-lib) + `cloudlab/{setup-node,worker-run,orchestrate,merge-results}.sh`
- All syntax-checked; profile.py moved to repo root so CloudLab git discovery finds it
- `plot_seed4.py` now honors `CDFUZZ_BASE` / `CDFUZZ_OUTDIR` env vars for merged-run analysis
- Full reference: CLOUDLAB.md. First real instantiation/run is the new session's task.

## Important Files

- `cdfuzzing/plot_seed4.py`: main analysis script; reads from `~/experiment_results/seed_4/ar/`; outputs to `~/cdfuzzing/plots_seed4/`- `cdfuzzing/magma/tools/captain/captainrc_batch2`: captainrc for moptafl+moptaflcd+afl+aflcd
- `cdfuzzing/magma/tools/captain/captainrc_batch3`: captainrc for aflfast+aflfastcd+honggfuzz+honggfuzzcd (batch 3 was stopped early due to disk)
- `cdfuzzing/magma/tools/captain/run_batches.sh`: sequential batch runner (batch1→2→3 with Docker cleanup)
- `cdfuzzing/magma/fuzzers/aflpluspluscd/fetch.sh`: contains AFL++ bug fixes (alias table, top_rated[], splice loops — applied via sed)
- `~/experiment_results/seed_4/ar/`: raw workdirs, NO_ARCHIVE=1 (not tar'd)
- `~/cdfuzzing/plots_seed4/summary_table.txt`: per-program cross-pair results
- `~/cdfuzzing/plots_seed4/parameter_eval.txt`: stagnation guard / reset distribution analysis
- `cdfuzzing/profile.py`: CloudLab geni-lib profile (repo root for git discovery)
- `cdfuzzing/cloudlab/`: setup-node.sh, worker-run.sh, orchestrate.sh, merge-results.sh
- `cdfuzzing/CLOUDLAB.md`: full reference for the distributed experiment

## Commands That Worked

```bash
# Reproduce the full analysis (delete plots_seed4 first to get a clean run)
cd ~/cdfuzzing && rm -rf plots_seed4 && python3 plot_seed4.py

# Fix Docker socket permissions after node reboot
sudo chmod 666 /var/run/docker.sock

# Run a batch via captain
cd ~/cdfuzzing/magma/tools/captain && bash run.sh captainrc_batch2

# Run batches in tmux
tmux new-session -d -s cdfuzz \
  "cd /users/eldarfin/cdfuzzing/magma/tools/captain && bash run_batches.sh 2>&1 | tee ~/experiment_results/seed_4/batch_logs/run.log"

# Check disk usage
df -h / && du -sh ~/experiment_results/seed_4/ar/* | sort -rh | head

# Free Docker build cache (done already for seed_4 node)
docker builder prune -af

# Disk info at time of writing
# ~/experiment_results/seed_4/ar/ ≈ 21G (queue/ dirs included)
# Docker images ≈ 21.57GB; build cache ≈ 12.81GB (already pruned once)
```

## Commands That Failed

```bash
# honggfuzz builds failed — preinstall.sh exited with code 100
# Root cause: disk was full (63G node, ~51G used when batch 3 started)
# Fix attempted: docker builder prune -af, rmi completed images — freed ~22GB, too late
# Decision: do not retry honggfuzz

# First batch 2 launch failed silently (Docker socket not reachable)
# captain spawned containers that immediately exited; lock files looked like success
# Fix: groupadd docker + usermod + systemctl start docker + chmod 666 /var/run/docker.sock
```

## Open Issues

- fairfuzz pair is missing libtiff (both fuzzers produced no fuzzer_stats for libtiff in batch 1 on the
  previous node; not investigated further).
- aflfast pair is partial (openssl+php missing for aflfastcd, honggfuzz not run at all).
  Treat aflfast results as preliminary/excluded from main table.
- Coverage metric is `queued_paths` (from fuzzer_stats), NOT bitmap edge count.
  This inflates coverage delta numbers. The parameter eval's mean_Δcov% values should be
  interpreted as corpus size change, not edge coverage change.
- Only 1 seed (seed=4). Results need multiple repetitions for statistical validity.
- moptaflcd resets/program is high (3.62) — MOpt's mutation scheduling amplifies KS fluctuations;
  may need a higher CONSECUTIVE for moptafl.
- fairfuzzcd fired 0 resets out of 50 drifts (stagnation guard too conservative for slow schedulers).

## Next Steps

1. **Run the distributed CloudLab experiment** (CLOUDLAB.md) — gives multi-rep results for all 12
   fuzzers including honggfuzz, on per-node local disk (fixes the seed_4 disk + missing-pair gaps).
2. **Write paper section on seed_4 results** using `summary_table.txt` and `parameter_eval.txt` as ground truth.
3. **Tune parameters per fuzzer family** based on parameter eval findings (see DECISIONS.md).
4. **Export plots** for paper figures from the merged run dir or `plots_seed4/`.

## Assumptions

- CloudLab node `amd149.utah.cloudlab.us` (hostname: `node-0`), user `eldarfin`
- 63GB disk — queue/ directories in results consume ~8GB; prune before running honggfuzz
- Python deps installed to `~/.local/` via `pip3 install matplotlib numpy`
- All CD fuzzers patched and built — do not re-run `fetch.sh` without checking for regressions
- `NO_ARCHIVE=1` was set in all captainrc files — results are raw workdirs, not `.tar.gz`

## Last Updated

2026-06-17
