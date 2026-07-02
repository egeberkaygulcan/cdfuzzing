# Cluster 2 — Utah CloudLab

Reference for the second CloudLab experiment (Utah datacenter) used to run dist12 (reps 5–7).
Cluster 1 (Wisconsin) is documented in [CLOUDLAB.md](CLOUDLAB.md).

---

## Identity

| Property | Value |
|---|---|
| CloudLab experiment ID | `eldarfin-309225` |
| Datacenter | Utah (`utah.cloudlab.us`) |
| Head node (external) | `amd131.utah.cloudlab.us` (128.110.219.42) |
| Head node (internal) | `192.168.1.1` |
| Workers | 36 (12 fuzzers × 3 reps), IPs `192.168.1.10–.45` |
| Shared NFS | `/proj/cdfuzzing-PG0` — **this IS the real NFS on Utah** |
| Repo (per node) | `/local/repository` |
| cdfuzz-role SHARED | `/proj/cdfuzzing-PG0` |
| Manifest | `/proj/cdfuzzing-PG0/cluster/manifest.txt` |
| Cluster SSH key | `/proj/cdfuzzing-PG0/cluster/ssh/id_rsa` |
| Wisconsin head access | `ssh -i /proj/CDFuzzing/cluster/ssh/id_rsa <fuzzer>-N.eldarfin-309225.cdfuzzing-pg0.utah.cloudlab.us` |
| Wisconsin cluster key installed | ✅ Drop-in at `/etc/ssh/cdfuzz_authorized_keys` + `90-cdfuzz.conf` on all 36 Utah workers (2026-07-01) |

> **NFS naming note**: On Wisconsin, `/proj/cdfuzzing-PG0` is a *local* per-node directory
> (not NFS) — the real NFS there is `/proj/CDFuzzing`. On Utah cluster2, `/proj/cdfuzzing-PG0`
> IS the project NFS. The `SHARED` variable in `/local/cdfuzz-role` on each cluster reflects this.

---

## Access from Wisconsin Head

SSH is now set up from the Wisconsin head to the Utah head:

```bash
ssh eldarfin@amd131.utah.cloudlab.us
```

This works because Wisconsin's `~/.ssh/id_rsa.pub` was added to Utah's
`~/.ssh/authorized_keys` (done 2026-06-26). The reverse is not set up.

To run commands on Utah from Wisconsin without entering a shell:
```bash
ssh eldarfin@amd131.utah.cloudlab.us 'COMMAND'
```

Workers on Utah are reachable **by IP only** (hostname resolution fails from Utah head):
```bash
# From Utah head, use IP:
ssh 192.168.1.10 'hostname'

# From Utah head, use manifest IPs:
WORKER_IP=$(grep -v "^#\|^head" /proj/cdfuzzing-PG0/cluster/manifest.txt | head -1 | awk '{print $2}')
ssh $WORKER_IP 'docker images'
```

---

## What Ran on Cluster 2

### dist12 — 36 workers, reps 5/6/7 (COMPLETE)

| Property | Value |
|---|---|
| Run ID | `dist12` |
| Reps | 5, 6, 7 (FUZZER_SEED = 1005, 1006, 1007) |
| Workers | 36/36 done, 0 failed |
| Completed | ~07:35 CDT 2026-06-26 |
| Results path (Utah NFS) | `/proj/cdfuzzing-PG0/distributed/dist12/ar/` |
| Fuzzers | afl, aflcd, aflfast, aflfastcd, aflplusplus, aflpluspluscd, fairfuzz, fairfuzzcd, honggfuzz, honggfuzzcd, moptafl, moptaflcd |
| Targets | sqlite3, libpng, lua, libsndfile, libtiff, libxml2, poppler, php, openssl (21 programs) |
| ar/ layout | `ar/<fuzzer>/<target>/<program>/<rep>/` e.g. `ar/afl/libpng/libpng_read_fuzzer/5/` |

CD parameters used (same confirmed best from dist10/dist11):

| Fuzzer | W | C | CL | SR | Evidence |
|---|---|---|---|---|---|
| aflcd | 100 | 3 | 10 | 1 | dist2 +3 bugs; dist5 +4 bugs |
| aflpluspluscd | 100 | 12 | 25 | 1 | dist7–dist9: +11/+8/+6 bugs |
| fairfuzzcd | 100 | 3 | 10 | 1 | dist2 corrected; dist6 +1 bug |
| moptaflcd | 100 | 5 | 10 | 1 | dist2 +6 bugs; dist5 +1 bug |
| aflfastcd | 100 | 3 | 10 | 1 | dist2 +5 bugs; dist5 +5 bugs |
| honggfuzzcd | 5 | 2 | 5 | 2 | dist9 rep0: +1 bug, 10 resets |

---

## Current State (2026-06-26)

- dist12 fully complete; results on Utah NFS at `/proj/cdfuzzing-PG0/distributed/dist12/ar/`
- Manifest currently set to reps 5/6/7 (36 workers)
- dist12 `ar/` is being rsynced to Wisconsin: `/proj/CDFuzzing/distributed/dist12/ar/`
- Workers are idle (no containers running); Docker images are still present on all workers
- **Manifest backup**: `/proj/cdfuzzing-PG0/cluster/manifest.dist12.bak` (once dist13 is launched)

---

## dist13 Plan — reps 8/9 (NOT YET LAUNCHED)

dist13 will cover reps 8 and 9 (FUZZER_SEED = 1008, 1009), using 24 of the 36 workers
(reusing the rep-5 and rep-6 worker machines with new rep assignments).

### Step 1 — Update manifest for reps 8/9

```bash
ssh eldarfin@amd131.utah.cloudlab.us '
  cp /proj/cdfuzzing-PG0/cluster/manifest.txt \
     /proj/cdfuzzing-PG0/cluster/manifest.dist12.bak
  {
    echo "# name ip fuzzer rep   (dist13: reps 8-9, $(date +%F\ %T))"
    echo "head 192.168.1.1 - -"
    awk "$4==5{print $3\"-8\", $2, $3, 8}
         $4==6{print $3\"-9\", $2, $3, 9}" \
      /proj/cdfuzzing-PG0/cluster/manifest.dist12.bak
  } > /proj/cdfuzzing-PG0/cluster/manifest.txt
  wc -l /proj/cdfuzzing-PG0/cluster/manifest.txt
'
```

This produces 24 worker entries (12 fuzzers × 2 reps). The rep-7 workers (192.168.1.12,
.15, .18, ...) are not assigned and will be idle.

### Step 2 — Launch dist13

```bash
ssh eldarfin@amd131.utah.cloudlab.us '
  mkdir -p /proj/cdfuzzing-PG0/distributed/dist13/log
  nohup /local/repository/cloudlab/orchestrate.sh \
    --run-id dist13 \
    --repo /local/repository \
    --shared /proj/cdfuzzing-PG0 \
    --no-merge \
    > /proj/cdfuzzing-PG0/distributed/dist13/log/orchestrate.log 2>&1 &
  echo "dist13 launched, PID: $!"
'
```

`--no-merge` is intentional: merging happens on Wisconsin after rsync.

### Step 3 — Monitor dist13

```bash
ssh eldarfin@amd131.utah.cloudlab.us '
  echo "done: $(ls /proj/cdfuzzing-PG0/distributed/dist13/status/*.done 2>/dev/null | wc -l) / 24"
  tail -5 /proj/cdfuzzing-PG0/distributed/dist13/log/orchestrate.log
'
```

### Step 4 — Transfer dist13 to Wisconsin (when complete)

```bash
rsync -avz --progress \
  eldarfin@amd131.utah.cloudlab.us:/proj/cdfuzzing-PG0/distributed/dist13/ar/ \
  /proj/CDFuzzing/distributed/dist13/ar/
```

---

## Differences from Wisconsin (Cluster 1)

| Property | Wisconsin (cluster 1) | Utah (cluster 2) |
|---|---|---|
| Experiment ID | `eldarfin-309063` | `eldarfin-309225` |
| Head (external) | `head.eldarfin-309063.cdfuzzing.emulab.net` | `amd131.utah.cloudlab.us` |
| Shared NFS | `/proj/CDFuzzing` | `/proj/cdfuzzing-PG0` |
| `/proj/cdfuzzing-PG0` | Local per-node (NOT NFS) | **Actual project NFS** |
| Nodes | 61 (1 head + 60 workers) | 37 (1 head + 36 workers) |
| Reps per fuzzer | 5 (dist11) | 3 (dist12) |
| Hostname resolution | Workers reachable by name | Workers reachable by IP only |
| Orch log | `/proj/CDFuzzing/dist11_orch.log` | `/proj/cdfuzzing-PG0/distributed/dist13/log/orchestrate.log` |

---

## Operational Notes

- **Worker reachability**: On cluster2, DNS does not resolve worker short names like `afl-5`.
  Use IPs from the manifest (`$2` column). The cluster SSH key handles auth.

- **Sync code to workers** (if needed before dist13):
  ```bash
  ssh eldarfin@amd131.utah.cloudlab.us '
    for ip in $(grep -v "^#\|^head" /proj/cdfuzzing-PG0/cluster/manifest.txt | awk "{print \$2}"); do
      scp -i /proj/cdfuzzing-PG0/cluster/ssh/id_rsa \
        /local/repository/cloudlab/worker-run.sh \
        eldarfin@$ip:/local/repository/cloudlab/worker-run.sh &
    done; wait
  '
  ```

- **Check Docker images on a worker**:
  ```bash
  ssh eldarfin@amd131.utah.cloudlab.us 'ssh 192.168.1.10 "docker images --format \"{{.Repository}}:{{.Tag}}\" | grep magma | head -5"'
  ```

- **NFS quota on Utah**: `/proj/cdfuzzing-PG0` has been sufficient for dist12 (queue/ and
  `*.honggfuzz.cov` excluded from rsync per worker-run.sh). Monitor if launching multiple runs.

- **orchestrate.sh `--no-merge`**: Always pass this when running on cluster2; merging and
  analysis happen on Wisconsin using `plot_seed4.py` with the combined `merged/ar/` tree.

---

## History of Experiments on Cluster 2

All earlier experiments (dist1–dist11) ran on cluster 1 (Wisconsin). Cluster 2 was created
specifically to run the second half of the paper-quality repetitions in parallel.

| Run | Reps | Workers | Status | Results path (Utah NFS) |
|---|---|---|---|---|
| dist12 | 5, 6, 7 | 36/36 done | **COMPLETE** 2026-06-26 07:35 CDT | `/proj/cdfuzzing-PG0/distributed/dist12/ar/` |
| dist13 | 8, 9 | 24 planned | **NOT YET LAUNCHED** | `/proj/cdfuzzing-PG0/distributed/dist13/ar/` |

---

## Last Updated

2026-06-26 (dist12 complete; dist13 plan ready; SSH from Wisconsin established)
