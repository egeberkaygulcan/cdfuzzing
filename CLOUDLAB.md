# CloudLab Distributed Experiment

Reference for the distributed multi-node CD-Fuzzing campaign on CloudLab. This
replaces the single-machine, sequential-batch workflow (seed_4) with one node
per (fuzzer × repetition), dispatched and merged from a central head node.

> Status: scripts written and syntax-checked, **NOT yet executed on CloudLab**.
> First real run is planned for a new session.

## What it provisions

`profile.py` (at the **repo root** so CloudLab git discovery finds it) is a
`geni-lib` profile that requests:

- **1 head node** (orchestrator) — IP `192.168.1.1`
- **(12 fuzzers × `nodesPerFuzzer`) worker nodes** — IPs `192.168.1.10+`

Defaults (`fuzzerSet=all`, `nodesPerFuzzer=2`) → **24 workers + 1 head = 25 nodes**.
Each worker = one repetition (`rep 0`, `rep 1`), giving the multi-rep sample the
seed_4 single-machine run could not produce.

Each node gets a stock **Ubuntu 22.04** image by default; `setup-node.sh`
installs Docker (+rsync) at boot and captain builds the Magma target images on
the node (Magma is not baked into the image). The custom `cdfuzzing-PG0:DedicatedMachine`
snapshot is still selectable from the image dropdown if you prefer to skip the
boot-time install. Each node also gets a `/mydata` blockstore (default 100GB)
and a static IP on a best-effort private LAN.

### Profile parameters

| Parameter | Default | Notes |
|---|---|---|
| `osImage` | `UBUNTU22-64-STD` (stock) | Docker installed at boot; custom snapshot selectable |
| `fuzzerSet` | `all` | `all` / `baselines` / `cd` |
| `nodesPerFuzzer` | `2` | nodes (= reps) per fuzzer |
| `phystype` | (blank) | leave blank to let mapper choose |
| `blockstoreSize` | `100` GB | local `/mydata` disk |
| `blockstoreMax` | `false` | grab whole disk instead |
| `repoPath` | `/users/eldarfin/cdfuzzing` | shared-home checkout path |
| `sharedDir` | `/proj/cdfuzzing-PG0` | project NFS merge target |
| `bestEffort` | `true` | LAN maps even if bandwidth unavailable |

## Files

| File | Runs on | Role |
|---|---|---|
| [profile.py](profile.py) | CloudLab | geni-lib RSpec; head + workers, LAN, blockstores, boot services |
| [cloudlab/setup-node.sh](cloudlab/setup-node.sh) | every node (boot) | mount `/mydata`, install Docker (+rsync), move Docker data-root there, passwordless SSH, write manifest |
| [cloudlab/orchestrate.sh](cloudlab/orchestrate.sh) | head | SSH-dispatch one campaign per worker, poll status, then merge |
| [cloudlab/worker-run.sh](cloudlab/worker-run.sh) | worker | generate single-fuzzer captainrc, run captain, rsync results to NFS (no `queue/`) |
| [cloudlab/merge-results.sh](cloudlab/merge-results.sh) | head | inventory arrivals + run analysis |
| [plot_seed4.py](plot_seed4.py) | head | analysis; `CDFUZZ_BASE` / `CDFUZZ_OUTDIR` env override the hardcoded seed_4 paths |

## How it works

```
head: orchestrate.sh
  ├─ ssh worker afl-0   ──▶ worker-run.sh ─▶ fuzz on /mydata ─▶ rsync to NFS
  ├─ ssh worker afl-1   ──▶ ...
  └─ ssh worker ...     ──▶ ...
  (poll <sharedDir>/distributed/<run-id>/status/*.done|.failed)
  └─ merge-results.sh ─▶ CDFUZZ_BASE=<run dir> python3 plot_seed4.py
```

Workers publish directly into the merged layout, so "merge" is just pointing the
analysis at it:

```
<sharedDir>/distributed/<run-id>/
  ar/<fuzzer>/<target>/<program>/<rep>/   merged per-rep results (no queue/)
  plots/                                  analysis output
  status/                                 .done / .failed / .running markers
  log/                                    analysis + per-worker logs
```

The seed is encoded purely by the run-id/rep directory name — there is no RNG
seed argument; repetitions differ by fuzzer nondeterminism (same as seed_4).

## Prerequisites before instantiating

1. The `cdfuzzing` checkout must exist on the cluster **home FS** at `repoPath`
   (default `/users/eldarfin/cdfuzzing`) — boot scripts are sourced from
   `<repoPath>/cloudlab/`. If `~/cdfuzzing` here is already the mounted CloudLab
   home, this is satisfied; otherwise `git clone`/`rsync` it there first.
2. `sharedDir` (project NFS) must be writable.

## Running (on the head node, after boot)

```bash
cd /users/eldarfin/cdfuzzing/cloudlab
./orchestrate.sh --run-id dist1 --timeout 24h
```

- Re-running the same `--run-id` **resumes**: workers already `.done` are skipped.
- `--dry-run` prints the SSH dispatch plan without launching.
- `--fuzzers "afl aflcd"` restricts to a subset; `--targets "sqlite3 libpng"` restricts targets.
- Merge/analyze alone: `./merge-results.sh --run-id dist1`.

## Scaling / operational notes

- 25 bare-metal nodes is a large allocation. If mapping fails: keep `phystype`
  blank, keep `bestEffort` on, or use `fuzzerSet=baselines` / `nodesPerFuzzer=1` first.
- Docker data-root is moved to `/mydata` at boot — directly mitigates the seed_4
  honggfuzz disk-exhaustion failure (root disk was 63GB).
- `queue/` corpora are excluded from rsync to keep NFS usage small; `fuzzer_stats`,
  `plot_data`, `drift_log.csv`, `monitor/` are kept.
- CloudLab experiments are lease-limited — **extend** the experiment if a 24h
  campaign would outlive the default lease.

## Known unknowns (verify on first run)

- Scripts are unverified end-to-end; the boot-time NFS-wait, Docker data-root
  move, and SSH key exchange have not been exercised on a real instantiation.
- Confirm `/proj/cdfuzzing-PG0` quota is large enough for 24 workers × 9 targets
  of merged (queue-excluded) results.
- Confirm the manifest IP scheme in `setup-node.sh` (`START_IP=10`) matches the
  `ip_index = 10` start in `profile.py` if either is edited.

## Last Updated

2026-06-17
