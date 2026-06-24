# Handoff

## Current Goal

Produce paper-quality results (10 reps × 24h × 12 fuzzers × 21 Magma programs) by merging two runs:

- **`dist11`** (reps 0–4): running on cluster `eldarfin-309063`, **finishing ~June 26 12:00 CEST** (noon Thursday)
- **`dist12`** (reps 5–9): to launch on a NEW CloudLab experiment, **finishing ~June 28 12:00 CEST** (noon Saturday)

After both finish, merge and run analysis. See § Merge and § Analysis below.

---

## dist11 Status (as of 2026-06-24)

**15/60 workers done, 45 running, 0 failed.**

Important: each CloudLab worker node has only **8 CPUs**. With 21 Magma programs, captain
queues them in 3 waves (8 / 8 / 5 programs each, one wave per 24h). Total runtime ≈ 72h.

| Wave | Programs | Started | Finishes |
|---|---|---|---|
| Wave 1 | sqlite3, libpng, lua, libsndfile, libtiff×2, libxml2×2 | June 23 ~04:38 CDT | June 24 ✅ |
| Wave 2 | poppler×3, php×4, openssl×6 (partial) | June 24 ~04:48 CDT | June 25 ~05:35 CDT |
| Wave 3 | remaining programs | June 25 ~04:48 CDT | **June 26 ~05:35 CDT** |

Monitor dist11:
```bash
# from head node of eldarfin-309063 (192.168.1.1):
echo "done: $(ls /proj/CDFuzzing/distributed/dist11/status/*.done 2>/dev/null | wc -l) / 60"
tail -5 /proj/CDFuzzing/dist11_orch.log
```

Results accumulate at `/proj/CDFuzzing/distributed/dist11/ar/` as each worker completes.

---

## dist12 Setup (reps 5–9)

**Create a new CloudLab experiment** using the same profile with these parameters:

| Parameter | Value |
|---|---|
| `nodesPerFuzzer` | `5` |
| `repOffset` | **`5`** ← critical |
| `sharedDir` | `/proj/CDFuzzing` (same NFS as dist11) |
| `fuzzerSet` | `all` |
| `phystype` | leave blank or same as dist11 |

This will create 60 worker nodes named `afl-5` through `honggfuzzcd-9` with the correct rep IDs
in `/local/cdfuzz-role`. The head generates a manifest with reps 5–9 automatically.

Once the experiment is up and workers have finished booting (check `/local/setup.log` on head):
```bash
# SSH to the new head node (192.168.1.1 on the new experiment's LAN)
cd /local/repository/cloudlab
tmux new-session -d -s dist12 \
  "bash orchestrate.sh --run-id dist12 --timeout 24h --poll 60 \
     2>&1 | tee /proj/CDFuzzing/dist12_orch.log"
echo "dist12 launched"
```

Monitor dist12:
```bash
echo "done: $(ls /proj/CDFuzzing/distributed/dist12/status/*.done 2>/dev/null | wc -l) / 60"
tail -5 /proj/CDFuzzing/dist12_orch.log
```

Expected completion: **June 28 ~12:00 CEST** (Saturday noon Amsterdam).

---

## Merge Instructions (after both complete)

```bash
mkdir -p /proj/CDFuzzing/distributed/dist11_merged/{ar,plots}

# Merge dist11 (reps 0-4) + dist12 (reps 5-9) into one ar/ tree
rsync -a /proj/CDFuzzing/distributed/dist11/ar/ \
         /proj/CDFuzzing/distributed/dist11_merged/ar/
rsync -a /proj/CDFuzzing/distributed/dist12/ar/ \
         /proj/CDFuzzing/distributed/dist11_merged/ar/

# Verify: each program dir should have 10 rep subdirs (0-9)
find /proj/CDFuzzing/distributed/dist11_merged/ar/afl/sqlite3 -maxdepth 2 -type d
```

---

## Analysis

Run from either head node (both mount the same `/proj/CDFuzzing` NFS):
```bash
CDFUZZ_BASE=/proj/CDFuzzing/distributed/dist11_merged \
CDFUZZ_OUTDIR=/proj/CDFuzzing/distributed/dist11_merged/plots \
python3 /local/repository/plot_seed4.py
```

---

## Final Fuzzer Configurations (paper-ready)

| Fuzzer | Config | Best observed Δbugs | Evidence |
|---|---|---|---|
| aflcd | SR=1, C=3, CL=10, W=100 | +4 bugs | dist5 |
| aflpluspluscd | **SR=1, C=12, CL=25**, W=100 | +11 bugs (dist7); +6 unique (dist9) | dist7–dist9 |
| fairfuzzcd | SR=1, C=3, CL=10, W=100 | +1 bug | dist6 |
| moptaflcd | SR=1, C=5, CL=10, W=100 | +6 bugs | dist2 |
| aflfastcd | SR=1, C=3, CL=10, W=100 | +5 bugs | dist2/3/5 |
| honggfuzzcd | W=5, C=2, CL=5, SR=2 | +1 bug (only) | dist9 — **negative result** |

---

## Infrastructure Notes

- **Cluster**: `eldarfin-309063` (dist11) / new experiment (dist12)
- **NFS**: `/proj/CDFuzzing` — mounted on all nodes in both experiments
- **SSH key**: `/proj/CDFuzzing/cluster/ssh/id_rsa` (head `~/.ssh/config` routes 192.168.1.* to it)
- **Permanent SSH auth**: cluster pubkey in `/etc/ssh/cdfuzz_authorized_keys` on each worker
  (Emulab keymgmt never touches `/etc/ssh/` so it survives reboots)
- **CPU constraint**: 8 CPUs per node → 3-wave captain execution for 21 programs
- **libtiff fix**: `magma/targets/libtiff/fetch.sh` has 3-attempt retry (commit `15974124`);
  prevents GitLab rate-limit failures when 60 workers clone simultaneously
- **orchestrate.sh**: does `git pull --ff-only` on each worker before dispatch (commit `65fc953b`)
- **Repo**: https://github.com/egeberkaygulcan/cdfuzzing.git — HEAD `442831e6`

---

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

**Distributed CloudLab experiment — `dist1` COMPLETE**
- 24 workers, launched 2026-06-17 20:20 CDT, finished 2026-06-18 ~05:20 CDT
- Results: `/proj/cdfuzzing-PG0/distributed/dist1/ar/` | Plots: `/proj/cdfuzzing-PG0/distributed/dist1/plots/` (55 files)
- A/B per-rep parameter design; analysis complete via plot_seed4.py
- **Bugs found during dist1 analysis (all fixed for dist2):**
  1. `honggfuzzcd` missing from PAIRS in plot_seed4.py → added
  2. `honggfuzzcd` CD init race: `initial_corpus_count=0` → all 17512 drifts detected, 0 resets fired; fixed with lazy init in `honggfuzz.c:driftCycle()`
  3. `fairfuzzcd` blacklist trap: FairFuzz branch blacklist fills → fuzzer spins 21M queue cycles with 0 mutations; fixed with `-q 1` in run.sh + FairFuzz state reset in `perform_corpus_reset()`

**Distributed CloudLab experiment — `dist2` COMPLETE**
- 24 workers, launched 2026-06-18 ~06:30 CDT, finished 2026-06-18 ~15:24 CDT
- Results: `/proj/cdfuzzing-PG0/distributed/dist2/ar/` | Plots: `/proj/cdfuzzing-PG0/distributed/dist2/plots/` (58 files)
- Results: moptaflcd +6 bugs, aflfastcd +5 bugs, aflpluspluscd ±0 (+1.6% cov), aflcd -1 (variance), fairfuzzcd -2, **honggfuzzcd -16 (761 resets — CASCADE LOOP)**
- Root causes documented in DECISIONS.md § dist2 analysis

**`dist4` COMPLETE (crashed honggfuzzcd)**
- 24 workers, launched 2026-06-19 ~03:29 CDT, finished 2026-06-19 ~12:22 CDT
- Results: `/proj/cdfuzzing-PG0/distributed/dist4/ar/` | Plots: `…/dist4/plots/`
- Results: moptaflcd -3, aflfastcd +1 (baseline variance), aflpluspluscd +2, aflcd 0, fairfuzzcd -6, **honggfuzzcd crashed (UaF in selective reset)**
- Root causes documented in DECISIONS.md § dist4 analysis

**`dist5` COMPLETE (honggfuzzcd monitoring-only)**
- 24 workers, launched 2026-06-19 12:39 CDT, finished 2026-06-19 ~21:23 CDT
- Results: afl +4, aflfast +5, moptafl +1, fairfuzz -3, aflplusplus -6, honggfuzz +1 (0 resets → UaF was causing -11)
- Data: `/proj/cdfuzzing-PG0/distributed/dist5/ar/` | Plots: `…/dist5/plots/`

**`dist9` COMPLETE — 6-rep honggfuzz C/CL sweep + AFL++ C=12 confirmation**
- 24/24 workers done 2026-06-22 01:25 CDT; 0 failures
- aflpluspluscd SR=1,C=12,CL=25: **+6 unique bugs** (34→40 across 21 programs); guard 95.2% effective
- honggfuzzcd: **−4 unique bugs** (33→29); no C/CL config helps; negative result accepted
- Data: `/proj/cdfuzzing-PG0/distributed/dist9/ar/` | Plots: `…/dist9/plots/`
- See EXPERIMENTS.md § dist9 and DECISIONS.md § dist9 outcomes for full analysis

**`dist8` COMPLETE — AFL++ confirmation + honggfuzz ultra-conservative sweep**
- 24/24 workers done 2026-06-21 13:14 CDT
- aflpluspluscd: mean +1.8 bugs (C=10, 4 reps); C=12 gave +8 (best single rep)
- honggfuzzcd: C/CL code bug discovered (drift_init never read env vars)
- Data: `/proj/cdfuzzing-PG0/distributed/dist8/ar/` | Plots: `…/dist8/plots/`

**`dist7` COMPLETE — paired-seed 6-rep sweep (honggfuzz + aflplusplus)**
- 24/24 workers done by 20:21 CDT June 20; NFS fix confirmed (no quota errors)
- aflpluspluscd: 3/6 reps positive (best: SR=1,C=10,CL=25 → +11 bugs, 9 resets)
- honggfuzzcd: 0/6 reps positive via CD; only +2 rep fired 0 resets (variance)
- Data: `/proj/cdfuzzing-PG0/distributed/dist7/ar/` | Plots: `…/dist7/plots/`
- See EXPERIMENTS.md § dist7 and DECISIONS.md § dist7 outcomes for full analysis

**`dist6` COMPLETE (honggfuzz UaF fix, 3 reps, rep2 SOFT_RESET=1 sweep)**
- 24 workers, launched 2026-06-19 ~21:25 CDT, finished 2026-06-20 ~06:52 CDT
- Results: afl +2 ✅, fairfuzz +1 ✅, aflplusplus -3 ❌, honggfuzz INVALID ⚠ (NFS data loss)
- ⚠ NFS at 100% capacity: honggfuzzcd rsync failed silently; only 5/21 programs saved
- Data: `/proj/cdfuzzing-PG0/distributed/dist6/ar/` | Plots: `…/dist6/plots/`
- See DECISIONS.md § dist6 outcomes for full analysis

## Important Files

- `cdfuzzing/plot_seed4.py`: main analysis script; reads from `~/experiment_results/seed_4/ar/`; outputs to `~/cdfuzzing/plots_seed4/`
- `cdfuzzing/cloudlab/worker-run.sh`: per-worker captain runner; **dist2: both reps use winning params from dist1 A/B** (see DECISIONS.md); deployed to all 24 workers via scp (GitHub SSH push blocked).
- `cdfuzzing/cloudlab/orchestrate.sh`: head dispatcher; poll interval 60s for dist1
- `cdfuzzing/magma/tools/captain/captainrc_batch2`: captainrc for moptafl+moptaflcd+afl+aflcd
- `cdfuzzing/magma/tools/captain/captainrc_batch3`: captainrc for aflfast+aflfastcd+honggfuzz+honggfuzzcd (batch 3 was stopped early due to disk)
- `cdfuzzing/magma/tools/captain/run_batches.sh`: sequential batch runner (batch1→2→3 with Docker cleanup)
- `cdfuzzing/magma/fuzzers/aflpluspluscd/fetch.sh`: contains AFL++ bug fixes (alias table, top_rated[], splice loops — applied via sed)
- `~/experiment_results/seed_4/ar/`: raw workdirs, NO_ARCHIVE=1 (not tar'd)
- `~/cdfuzzing/plots_seed4/summary_table.txt`: per-program cross-pair results
- `~/cdfuzzing/plots_seed4/parameter_eval.txt`: stagnation guard / reset distribution analysis
- `cdfuzzing/profile.py`: CloudLab geni-lib profile (repo root for git discovery)
- `cdfuzzing/cloudlab/`: setup-node.sh, worker-run.sh, orchestrate.sh, merge-results.sh
- `cdfuzzing/CLOUDLAB.md`: full reference for the distributed experiment
- `/proj/cdfuzzing-PG0/distributed/dist1_orch.log`: orchestrator log for dist1 (complete)
- `/proj/cdfuzzing-PG0/distributed/dist3_orch.log`: orchestrator log for dist3 (complete)
- `/proj/cdfuzzing-PG0/distributed/dist4_orch.log`: orchestrator log for dist4 (complete)
- `/proj/cdfuzzing-PG0/distributed/dist3/`: NFS results dir for dist3
- `/proj/cdfuzzing-PG0/distributed/dist4/`: NFS results dir for dist4

## Commands That Worked

```bash
# Monitor dist2 campaign (running ~06:30 CDT Jun 18 → ~14:30 CDT Jun 18)
tail -f /proj/cdfuzzing-PG0/distributed/dist2_orch.log
# or live: ssh head, then:
tmux attach -t dist2     # detach: Ctrl-B D

# Analyze dist2 when complete
CDFUZZ_BASE=/proj/cdfuzzing-PG0/distributed/dist2 \
CDFUZZ_OUTDIR=/proj/cdfuzzing-PG0/distributed/dist2/plots \
python3 /local/repository/plot_seed4.py

# Sync code changes to workers (GitHub SSH not set up — use scp)
for ip in $(grep -v '^#\|^head' /proj/cdfuzzing-PG0/cluster/manifest.txt | awk '{print $2}'); do
  scp -i /proj/cdfuzzing-PG0/cluster/ssh/id_rsa FILE $ip:/local/repository/FILE &
done; wait

# Re-run analysis manually if auto-merge fails at end
CDFUZZ_BASE=/proj/cdfuzzing-PG0/distributed/dist1 \
CDFUZZ_OUTDIR=/proj/cdfuzzing-PG0/distributed/dist1/plots \
python3 /local/repository/plot_seed4.py

# Reproduce the full seed_4 analysis (delete plots_seed4 first to get a clean run)
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
  dist1 gives 2 reps for each fuzzer but uses A/B parameters for CD variants — not pure
  statistical repetitions. Pure repetitions (fixed params) are needed for confidence intervals.
- moptaflcd resets/program was high (3.62) in seed_4 — dist1 tests C=8/SF=0.5 (rep 0) and
  C=5/SF=0.3 (rep 1) as alternatives.
- fairfuzzcd fired 0 resets in seed_4 (stagnation guard too conservative) — dist1 tests C=3
  (rep 0) and C=2 (rep 1).
- profile.py boot-time auto-provision fix is **unverified on a fresh re-instantiation** — the
  manual procedure in CLOUDLAB.md is the proven path if nodes need to be re-provisioned.
- 6 files in `/local/repository` have uncommitted changes (CLOUDLAB.md, profile.py, 4
  cloudlab/*.sh). Git commit has not been made — if the experiment is re-instantiated, a fresh
  git clone will miss these fixes. Should commit before experiment expires.

## Next Steps

1. **Wait for dist1 to finish** (~06:00 CDT 2026-06-18). Monitor via orchestrator log or tmux.
2. **Review dist1 analysis output** at `/proj/cdfuzzing-PG0/distributed/dist1/plots/`.
   If auto-analysis fails, run manually (see Commands above).
3. **Interpret A/B parameter results**: compare rep 0 vs rep 1 for each CD fuzzer to pick
   the better CONSECUTIVE/STAGNATION_FACTOR setting. Especially watch fairfuzzcd and moptaflcd.
4. **Commit the 6 fixed files** to `/local/repository` on branch main before the CloudLab
   lease expires (so profile.py boot fix is captured for re-instantiation).
5. **Run dist2** (if dist1 shows clear parameter winners) with the best parameters, both reps
   identical per fuzzer — proper 2-rep statistical repetitions for confidence intervals.
6. **Write paper section on seed_4 results** using `summary_table.txt` and `parameter_eval.txt`.
7. **Tune further** if dist1 reveals new pathologies (see DECISIONS.md for A/B rationale).
8. **Extend CloudLab lease** if needed via the web UI (Experiment → Extend).

## Assumptions

- CloudLab experiment `eldarfin-308618` — Wisconsin datacenter, c220g1 nodes, Ubuntu 22.04.2 LTS
- Head: `head.eldarfin-308618.cdfuzzing-pg0.wisc.cloudlab.us` (public IP 128.105.145.221)
- 25 nodes: head (192.168.1.1) + 24 workers (192.168.1.10–.33)
- `/users/eldarfin` is **local per node** (NOT NFS). Repo is `/local/repository` (per-node checkout).
- Only `/proj/cdfuzzing-PG0` (100GB NFS) and `/share` are shared across nodes.
- Workers: ~87GB free per node on `/mydata`; Docker data-root on `/mydata`
- Shared cluster SSH keypair: `/proj/cdfuzzing-PG0/cluster/ssh/id_rsa` — installed to each node's `~/.ssh`
- Python deps (matplotlib, numpy) installed system-wide via apt on head node
- `NO_ARCHIVE=1` was set in all seed_4 captainrc files — results are raw workdirs, not `.tar.gz`
- All CD fuzzers patched and built — do not re-run `fetch.sh` without checking for regressions

## Last Updated

2026-06-17 (session 2: CloudLab provisioning, smoke test, A/B param design, dist1 launched)
