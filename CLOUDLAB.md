# CloudLab Distributed Experiment

Reference for the distributed multi-node CD-Fuzzing campaign on CloudLab. This
replaces the single-machine, sequential-batch workflow (seed_4) with one node
per (fuzzer × repetition), dispatched and merged from a central head node.

> Status (2026-07-01): **EXPERIMENT EXPIRING** — Wisconsin cluster (eldarfin-309063), 61 nodes.
> dist14 complete (honggfuzz KEEP_RECENT=50, 20 workers, archived to `/mydata/dist14_ar.tar.gz`).
> NFS at ~80% full (21 GB free). dist11/dist12 raw data partially recovered from worker nodes.
> Worker SSH restored via drop-in (`/etc/ssh/cdfuzz_authorized_keys` + `90-cdfuzz.conf`).
> Workers accessible via 192.168.1.10–69 using cluster key at `/proj/CDFuzzing/cluster/ssh/id_rsa`.
> **Important**: workers store local data under `0/` regardless of rep — use tar `--transform` to remap rep dirs when pulling.

## What it provisions

`profile.py` (at the **repo root** so CloudLab git discovery finds it) is a
`geni-lib` profile that requests:

- **1 head node** (orchestrator) — IP `192.168.1.1`
- **(12 fuzzers × `nodesPerFuzzer`) worker nodes** — IPs `192.168.1.10+`

Defaults (`fuzzerSet=all`, `nodesPerFuzzer=2`) → **24 workers + 1 head = 25 nodes**.
Each worker = one repetition (`rep 0`, `rep 1`), giving the multi-rep sample the
seed_4 single-machine run could not produce.

Each node gets a stock **Ubuntu 22.04** image; `setup-node.sh` installs Docker
(+rsync) and captain builds the Magma target images on the node (Magma is not
baked into the image, and no custom snapshot is used). Each node also gets a
`/mydata` blockstore (default 100GB) and a static IP on a best-effort private LAN.

The cdfuzzing repo is **git-cloned per node to `/local/repository`** by CloudLab's
standard git-profile checkout (NOT to a shared home). The home FS (`/users`) is
**local per node**, not NFS-shared; only `/proj/cdfuzzing-PG0` and `/share` are
shared. All scripts therefore source the repo from `/local/repository`.

### Profile parameters

| Parameter | Default | Notes |
|---|---|---|
| `osImage` | `UBUNTU22-64-STD` (stock) | Docker installed at boot; stock Ubuntu only |
| `fuzzerSet` | `all` | `all` / `baselines` / `cd` |
| `nodesPerFuzzer` | `2` | nodes (= reps) per fuzzer |
| `phystype` | (blank) | leave blank to let mapper choose |
| `blockstoreSize` | `100` GB | local `/mydata` disk |
| `blockstoreMax` | `false` | grab whole disk instead |
| `repoPath` | `/local/repository` | per-node git checkout (home is NOT shared) |
| `sharedDir` | `/proj/cdfuzzing-PG0` | project NFS merge target (the only shared FS) |
| `bestEffort` | `true` | LAN maps even if bandwidth unavailable |

## Files

| File | Runs on | Role |
|---|---|---|
| [profile.py](profile.py) | CloudLab | geni-lib RSpec; head + workers, LAN, blockstores, boot services |
| [cloudlab/setup-node.sh](cloudlab/setup-node.sh) | every node | mount `/mydata`, install Docker (+rsync), move Docker data-root there, install the **shared cluster SSH key** from `<sharedDir>/cluster/ssh` into each node's local `~/.ssh`, write manifest (head) |
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

1. The profile is created from the GitHub repo; CloudLab git-clones it to
   `/local/repository` on every node. No shared-home checkout is needed.
2. `sharedDir` (project NFS, `/proj/cdfuzzing-PG0`) must be writable by the
   experiment user's group (`cdfuzzing-PG0`). The merge dir lives here.
3. After boot, confirm every node is provisioned (Docker active, `/mydata`
   moved, `~/.ssh/id_rsa` present). If the boot Execute service did not run
   setup-node.sh, provision manually — see below.

## Provisioning (what actually happened, 2026-06-17)

The boot-time `Execute` service that should run `setup-node.sh` **failed** with
`syntax error near unexpected token` — CloudLab wraps the command in
`/bin/bash -c "..."` and the old `boot_command()` nested double quotes
(`REPO="..."`) plus `$(seq 1 60)` collided with that wrapper. `profile.py` is
fixed, but the **already-running** nodes were provisioned manually from the head:

```bash
# Head uses CloudLab's per-experiment root key (/root/.ssh/id_rsa) to reach
# every node as root. Run head setup first (generates the shared cluster
# SSH key on NFS + writes the manifest), then all workers from the manifest.
sudo bash /local/repository/cloudlab/setup-node.sh head \
  --fuzzers afl,aflplusplus,fairfuzz,moptafl,aflfast,honggfuzz,aflcd,aflpluspluscd,fairfuzzcd,moptaflcd,aflfastcd,honggfuzzcd \
  --nodes-per-fuzzer 2 --repo /local/repository --shared /proj/cdfuzzing-PG0

while read -r name ip fuzzer rep; do
  [ "$name" = head ] && continue
  sudo ssh -n -i /root/.ssh/id_rsa -o StrictHostKeyChecking=no root@"$name" \
    "bash /local/repository/cloudlab/setup-node.sh worker --fuzzer $fuzzer --rep $rep \
     --repo /local/repository --shared /proj/cdfuzzing-PG0 >/local/setup.log 2>&1"
done < <(grep -vE '^#|^head ' /proj/cdfuzzing-PG0/cluster/manifest.txt)
```

Inter-node SSH uses a **single shared cluster keypair** generated once on NFS at
`/proj/cdfuzzing-PG0/cluster/ssh` and installed into every node's local `~/.ssh`
(home is not shared, so one `~/.ssh` cannot propagate by itself).

## Running (on the head node, after provisioning)

```bash
cd /local/repository/cloudlab
./orchestrate.sh --run-id dist1 --timeout 8h
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

## Verified on this instantiation (2026-06-17)

- 25 nodes up; LAN `192.168.1.0/24`; `/etc/hosts` names = `<fuzzer>-<rep>`
  (`afl-0`=.10 … `honggfuzzcd-1`=.33), matching `profile.py` exactly.
- Docker active and usable as `eldarfin` on all 24 workers; data-root on `/mydata`
  (≈87GB free per node).
- Magma target/fuzzer submodules populated under `/local/repository/magma`.
- Passwordless SSH works head→worker AND worker→worker as `eldarfin` via the
  shared cluster key.
- `eldarfin` can create the run dir `/proj/cdfuzzing-PG0/distributed/<run-id>/`.

## Known unknowns / notes from dist1

- The full `orchestrate.sh → worker-run.sh → captain` pipeline was verified via
  smoke test (smoke1: afl+aflcd, sqlite3, 10min, 4/4 done, 15 analysis files) before dist1.
- `/proj/cdfuzzing-PG0` quota is ~100GB; queue/ is excluded from rsync so per-worker
  footprint is small (fuzzer_stats, plot_data, drift_log.csv, monitor/ only).
- `/proj/cdfuzzing-PG0/cluster/` is root-owned; manifest + keys inside are `eldarfin`-owned.
- The boot-time auto-provision fix in `profile.py` is **unverified on a fresh re-instantiation**
  — the manual procedure above is the proven path.
- **6 files in `/local/repository` have uncommitted changes** (CLOUDLAB.md, profile.py,
  cloudlab/{setup-node,worker-run,orchestrate,merge-results}.sh). Commit before the lease
  expires so the next instantiation gets the fixed profile.py automatically.
- `worker-run.sh` contains a per-rep A/B CD parameter selection block. See DECISIONS.md.
- dist1 uses `--poll 60` (1-minute poll interval) and `--timeout 8h` per worker.

## Last Updated

2026-06-17 (session 2: smoke test ✓, dist1 launched)
