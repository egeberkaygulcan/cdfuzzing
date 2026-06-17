# Debugging Notes

---

## Issue: Docker socket not available on fresh CloudLab node

Symptoms:
- `docker ps` returns "permission denied" or "Cannot connect to the Docker daemon"
- captain launches containers that immediately exit (no fuzzer_stats produced after 24h)
- `systemctl status docker.socket` shows "Failed to start"

Evidence:
- `docker` group did not exist on the node
- `sudo systemctl status docker.socket` → "Failed"
- `find .../ar/ -name fuzzer_stats | wc -l` returned 0 after batch appeared to complete

Tried:
- [x] `sudo chmod 666 /var/run/docker.sock` — works temporarily but requires docker to be running first
- [x] Full fix (see below) — resolved

Current Best Explanation:
Fresh CloudLab Ubuntu nodes do not have the `docker` group pre-created. Without it,
`docker.socket` activation fails. Systemd failure state also blocks restart.

Fix:
```bash
sudo groupadd docker
sudo usermod -aG docker $USER
sudo systemctl reset-failed docker.socket docker.service
sudo systemctl start docker
sudo chmod 666 /var/run/docker.sock
# log out and back in, or: newgrp docker
```

After node reboot (permission fix is lost):
```bash
sudo chmod 666 /var/run/docker.sock
```

Verification:
```bash
docker ps   # should return empty table, not permission error
docker run hello-world
```

---

## Issue: Disk exhaustion during batch 3 (honggfuzz Docker builds failed)

Symptoms:
- honggfuzz preinstall.sh exited with code 100 during Docker build
- `df -h /` showed 81% used (48/63GB) at batch 3 start
- `docker system df` showed 12.8GB build cache + 21.57GB images

Evidence:
```
ERROR: failed to build: failed to solve: process "/bin/sh -c ${FUZZER}/preinstall.sh"
did not complete successfully: exit code: 100
```
- honggfuzz preinstall installs heavy toolchain (LLVM, ninja, cmake) — requires ~5GB free during build

Tried:
- [x] `docker builder prune -af` — freed 12.8GB build cache
- [x] `docker rmi` on completed batch images (aflfast, moptafl, afl, etc.) — freed ~10GB
- [x] `rm -f ~/seed4_results.tar.gz && rm -rf ~/handoff_extracted` — freed ~1.5GB
- [x] Decision: do not retry honggfuzz in seed_4

Disk state at time of decision (after cleanup):
```
/dev/sda3   63G  30G  30G  51%
```

Root cause:
- Docker build cache grew to 12.8GB across 3 batches (each fuzzer×target image is ~1.5GB built)
- Batch images from batches 1+2 were not pruned before batch 3
- queue/ dirs in results (~8GB across all runs) contribute but were not the primary cause

Prevention for future seeds:
```bash
# Before each batch: prune unused images and build cache
docker builder prune -af
docker images --format "{{.Repository}}:{{.Tag}}" | grep "^magma/" | xargs -r docker rmi

# Or: use a ≥100GB CloudLab node profile
# Or: prune queue/ dirs after each batch completes:
find ~/experiment_results/ -type d -name queue -exec rm -rf {} + 2>/dev/null
```

---

## Issue: AFL++CD alias table / top_rated[] / splice loop bugs (fixed before seed_4)

Symptoms (prior seeds 1–3):
- AFL++CD crashed after first reset (segfault or infinite loop)
- Some seeds showed AFL++CD producing no corpus growth after reset
- Splice stage occasionally triggered use-after-free

Evidence:
- Code inspection of AFL++ soft reset path: alias table (`alias_prob[]`, `alias_table[]`) was not
  rebuilt after corpus wipe
- `top_rated[]` array was not cleared on reset — stale pointers into freed entries
- Splice loop did not check `->disabled` flag — could access wiped queue entries

Tried:
- [x] Rebuild alias table on soft reset — fixed crash
- [x] Clear `top_rated[]` on soft reset — fixed stale pointer deref
- [x] Add `->disabled` check in splice loop — fixed use-after-free

Fix location:
- `cdfuzzing/magma/fuzzers/aflpluspluscd/fetch.sh` — applies sed patches after AFL++ checkout
- `cdfuzzing/magma/fuzzers/aflpluspluscd/newsrc/` — patched source overrides

Verification:
Run AFL++CD for 1h on sqlite3 with CONSECUTIVE=1 (to force a reset early) and confirm:
```bash
docker run --rm magma/aflpluspluscd/sqlite3 bash -c "
  AFL_DRIFT_CONSECUTIVE=1 timeout 3600 afl-fuzz ..."
# Should not crash and should continue fuzzing after reset
```

Remaining uncertainty:
These fixes were applied but not formally unit-tested. seed_4 results (50 resets, no crashes
reported in captain logs) provide indirect confirmation.

---

## Issue: batch 2 ran silently with no results (first attempt)

Symptoms:
- captain `run.sh` appeared to complete successfully
- No `fuzzer_stats` files found under `ar/moptafl/` or `ar/afl/`
- Docker containers were created and immediately exited

Evidence:
- `find ~/experiment_results/seed_4/ar/moptafl -name fuzzer_stats | wc -l` returned 0
- `docker ps -a` showed exited containers with exit code 1
- Root cause: Docker socket was not available (see Docker socket issue above)

Tried:
- [x] Fixed Docker socket permissions
- [x] Cleaned stale captain lock/cache directories and log files
- [x] Re-launched batch 2 — succeeded

Fix:
```bash
# Remove stale captain state before relaunch
rm -f ~/experiment_results/seed_4/batch_logs/batch2.log
# Remove any partial workdirs created by the failed run
rm -rf ~/experiment_results/seed_4/ar/moptafl ~/experiment_results/seed_4/ar/moptaflcd \
        ~/experiment_results/seed_4/ar/afl ~/experiment_results/seed_4/ar/aflcd
# Then relaunch
bash run.sh captainrc_batch2
```

---

## Issue: fairfuzz libtiff programs missing from results

Symptoms:
- `summary_table.txt` shows fairfuzz pair has 19 programs instead of 21 (libtiff missing)
- Both `fairfuzz/libtiff/` and `fairfuzzcd/libtiff/` have no `fuzzer_stats` files

Evidence:
```bash
find ~/experiment_results/seed_4/ar/fairfuzz/libtiff -name fuzzer_stats  # empty
find ~/experiment_results/seed_4/ar/fairfuzzcd/libtiff -name fuzzer_stats  # empty
```

Hypotheses:
1. fairfuzz build for libtiff failed silently — captainrc may have skipped it
2. libtiff-specific instrumentation issue with fairfuzz's custom coverage bitmap
3. Container exited before producing fuzzer_stats (OOM or timeout during startup)

Tried:
- [ ] Check captain logs for libtiff errors during batch 1 — log file may have been deleted
- [ ] Re-run fairfuzz/fairfuzzcd for libtiff only

Current Best Explanation:
Unknown. Batch 1 logs were deleted during cleanup. The libtiff programs are not critical for the
main analysis but should be investigated if fairfuzz results are to be included in a paper.

Next Diagnostic Step:
```bash
# Check if fairfuzz Docker image builds successfully for libtiff
cd ~/cdfuzzing/magma/tools/captain
FUZZER=fairfuzz TARGET=libtiff bash run.sh captainrc_single_test  # create a minimal captainrc
docker logs $(docker ps -lq)  # check last container logs
```
