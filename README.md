# Drift-Aware Fuzzing — Artifact

Artifact for the paper:
> **Drift-Aware Fuzzing: Escaping Coverage Plateaus with Statistical Coverage Tracking**
> ICSE 2027 Research Track

This artifact provides the full implementation of the drift-aware fuzzing module, its integration into six coverage-guided fuzzers, and the scripts needed to reproduce the paper's evaluation on the Magma benchmark.

---

## Overview

Drift-aware fuzzing augments coverage-guided fuzzers with a lightweight statistical monitoring layer. Every W mutation rounds, a two-sample Kolmogorov-Smirnov test is applied to two consecutive windows of the corpus-size history. When the p-value falls below a threshold *and* an EMA-based stagnation guard confirms that growth has genuinely stalled, the fuzzer performs a soft corpus reset and a temporary havoc boost.

**Evaluated fuzzers (baseline → CD variant):**

| Baseline | CD variant |
|---|---|
| AFL | AFLCD |
| AFLFast | AFLFastCD |
| MOpt-AFL | MOptCD |
| AFL++ | AFL++CD |
| FairFuzz | FairFuzzCD |
| honggfuzz | honggfuzzCD |

**Benchmark:** [Magma](https://hexhive.epfl.ch/magma/) — 9 real-world targets, 21 fuzzing programs, 24-hour campaigns, 10 independent repetitions.

---

## Requirements

| Requirement | Notes |
|---|---|
| Linux x86-64 | Ubuntu 20.04 or 22.04 recommended |
| Docker | 20.10 or later; see [docker_setup.sh](docker_setup.sh) |
| bash | 4.0 or later |
| Python 3 | 3.8 or later, with `pandas`, `scipy`, `matplotlib` |
| RAM | >= 8 GB (16 GB recommended for parallel campaigns) |
| Disk | >= 20 GB free for Docker images and campaign output |

Install Python dependencies:

```bash
pip3 install pandas scipy matplotlib
```

Enable Docker for your user (if not already configured):

```bash
sudo bash docker_setup.sh
```

---

## Repository Structure

```
magma/
  fuzzers/
    afl/                  Baseline AFL
    aflcd/                AFL + CD module   <- afl-drift-detect.c / .h
    aflfast/              Baseline AFLFast
    aflfastcd/            AFLFast + CD module
    aflplusplus/          Baseline AFL++
    aflpluspluscd/        AFL++ + CD module
    fairfuzz/             Baseline FairFuzz
    fairfuzzcd/           FairFuzz + CD module
    honggfuzz/            Baseline honggfuzz
    honggfuzzcd/          honggfuzz + CD module
    moptafl/              Baseline MOpt-AFL
    moptaflcd/            MOpt-AFL + CD module
  targets/                9 Magma targets (libpng, libsndfile, libtiff, libxml2,
                           lua, openssl, php, poppler, sqlite3)
  tools/
    captain/              Campaign orchestration engine
      captainrc           Default configuration (edit to customize campaigns)
      run.sh              Launch campaigns from a captainrc
cloudlab/
  setup-node.sh           One-time node setup (Docker relocation, SSH keys)
  orchestrate.sh          Head-node dispatcher for distributed runs
  worker-run.sh           Per-worker campaign launcher with CD parameter tables
  merge-results.sh        Post-run inventory and analysis trigger
run_local.sh              Single-machine evaluation entry point (wraps captain)
smoke_test_all_cd.sh      Quick build-and-run verification (~15 min)
smoke_test_aflpluspluscd.sh  AFL++ CD-specific smoke test
plot_seed4.py             Analysis script: coverage + bug delta tables and plots
```

**CD module source** (the core implementation):
- `magma/fuzzers/aflcd/newsrc/afl-drift-detect.c` — KS test, EMA stagnation guard, soft reset
- `magma/fuzzers/aflcd/newsrc/afl-drift-detect.h` — struct and function declarations
- Honggfuzz uses an equivalent module under `magma/fuzzers/honggfuzzcd/`

---

## Quick Verification (~15 minutes)

Build all six CD fuzzer Docker images and run a 10-minute campaign on `libpng` to confirm that drift detection fires at least once:

```bash
bash smoke_test_all_cd.sh
```

To skip rebuilding (if images are already built):

```bash
bash smoke_test_all_cd.sh --skip-build
```

To test a single fuzzer:

```bash
bash smoke_test_all_cd.sh --only aflcd
```

Expected output per fuzzer:

```
[PASS] aflcd: 3 resets fired, container exited 0
```

---

## Running a Local Evaluation

`run_local.sh` provides a single-command interface for running campaigns on one machine.

### Syntax

```bash
bash run_local.sh [OPTIONS]

Options:
  --fuzzers  "F1 F2 ..."   Fuzzers to run (default: "afl aflcd")
  --targets  "T1 T2 ..."   Magma targets  (default: "sqlite3 libpng")
  --timeout  DURATION      Campaign duration, e.g. 1h, 24h (default: 1h)
  --reps     N             Repetitions per fuzzer-program pair (default: 1)
  --outdir   PATH          Output directory (default: ./workdir)
  --workers  N             Parallel campaigns (default: all CPU cores)
  --seed     N             Base FUZZER_SEED; rep i uses seed+i (default: 1000)
```

### Example: single pair, short run

```bash
bash run_local.sh \
  --fuzzers "afl aflcd" \
  --targets "sqlite3" \
  --timeout 1h \
  --reps 2 \
  --outdir ./results/afl_sqlite3_quick
```

### Example: reproducing the AFL/AFLCD paper pair

```bash
bash run_local.sh \
  --fuzzers "afl aflcd" \
  --targets "sqlite3 libpng lua libsndfile libtiff libxml2 poppler php openssl" \
  --timeout 24h \
  --reps 10 \
  --outdir ./results/afl_pair
```

> **Note:** 10 reps x 21 programs x 2 fuzzers = 420 campaigns. On a single machine this
> requires many cores and will take proportionally longer than 24 h if run sequentially.
> Use the distributed scripts below for parallel execution across multiple machines.

### Analyzing results

```bash
CDFUZZ_BASE=./results/afl_sqlite3_quick \
CDFUZZ_OUTDIR=./results/afl_sqlite3_quick/plots \
  python3 plot_seed4.py
```

---

## Running the Distributed Evaluation

For the full 10-repetition evaluation, the `cloudlab/` scripts implement a head-and-workers architecture. Each worker runs one fuzzer over all Magma targets for one repetition; the head dispatches and collects results via a shared filesystem.

### Architecture

```
head node (orchestrate.sh)
  |-- SSH --> worker (fuzzer=afl,      rep=0, worker-run.sh)
  |-- SSH --> worker (fuzzer=aflcd,    rep=0, worker-run.sh)
  |-- SSH --> worker (fuzzer=afl,      rep=1, worker-run.sh)
  ...
  `-- SSH --> worker (fuzzer=honggfuzz, rep=9, worker-run.sh)

Results written to shared storage:
  $SHARED/distributed/<run-id>/ar/<fuzzer>/<target>/<program>/<rep>/
```

### Step 1: Prepare a manifest

Create `$SHARED/cluster/manifest.txt`:

```
# name          ip              fuzzer       rep
head             192.168.1.1     -            -
afl-0            192.168.1.10    afl          0
aflcd-0          192.168.1.11    aflcd         0
afl-1            192.168.1.12    afl          1
aflcd-1          192.168.1.13    aflcd         1
```

One row per worker. The `name` field is used for status files; `ip` must be SSH-reachable from the head. Each worker runs exactly one fuzzer for one repetition index.

### Step 2: Set up nodes

Run on each node as root (idempotent):

```bash
# On the head node:
sudo bash cloudlab/setup-node.sh head \
  --fuzzers "afl,aflcd,aflfast,aflfastcd,moptafl,moptaflcd,aflplusplus,aflpluspluscd,fairfuzz,fairfuzzcd,honggfuzz,honggfuzzcd" \
  --nodes-per-fuzzer 10 \
  --repo /path/to/cdfuzzing \
  --shared /path/to/shared/nfs

# On each worker node:
sudo bash cloudlab/setup-node.sh worker \
  --fuzzer <FUZZER_NAME> \
  --rep <REP_INDEX> \
  --repo /path/to/cdfuzzing \
  --shared /path/to/shared/nfs
```

`setup-node.sh` installs Docker, moves Docker's data-root to a large local disk (`/mydata` by default, overridable with `--local-disk`), and configures passwordless inter-node SSH.

### Step 3: Launch a run

```bash
cd cloudlab
./orchestrate.sh \
  --run-id run1 \
  --timeout 24h \
  --fuzzers "afl aflcd" \
  --shared /path/to/shared/nfs \
  --repo /path/to/cdfuzzing
```

`orchestrate.sh` polls all workers every 60 seconds and calls `merge-results.sh` automatically when all workers finish.

### Step 4: Check progress

```bash
ls /path/to/shared/nfs/distributed/run1/status/
# afl-0.done  aflcd-0.done  afl-1.running ...
```

### Step 5: Merge and analyze

```bash
./cloudlab/merge-results.sh \
  --run-id run1 \
  --shared /path/to/shared/nfs \
  --repo /path/to/cdfuzzing
```

---

## Analyzing Results

`plot_seed4.py` reads the captain archive layout and produces the summary tables from the paper.

```bash
CDFUZZ_BASE=/path/to/shared/distributed/run1 \
CDFUZZ_OUTDIR=/tmp/run1_plots \
  python3 plot_seed4.py
```

Output in `$CDFUZZ_OUTDIR`:

| File | Contents |
|---|---|
| `summary_table.txt` | Per-program Δcov and Δbugs for each fuzzer pair |
| `bug_report.txt` | Bug IDs found by each CD variant vs. its baseline |
| `parameter_eval.txt` | Guard statistics: drifts detected, resets fired, suppression rate |
| `*.png` | Coverage-over-time plots per target |

---

## CD Parameters Reference

CD parameters are passed as environment variables. Baseline fuzzers ignore them silently.

| Variable | Default | Description |
|---|---|---|
| `AFL_DRIFT_WINDOW` | 100 | Sliding window size W (mutation rounds) |
| `AFL_DRIFT_THRESHOLD` | 0.05 | KS p-value significance cutoff (α) |
| `AFL_DRIFT_CONSECUTIVE` | 3 | Consecutive stagnant windows before reset (C) |
| `AFL_DRIFT_COOLDOWN` | 10 | Min windows between resets (CL) |
| `AFL_DRIFT_STAGNATION_FACTOR` | 0.5 | EMA growth guard factor (γ) |
| `AFL_DRIFT_EMA_ALPHA` | 0.1 | EMA smoothing factor (β) |
| `AFL_DRIFT_SOFT_RESET` | 1 | 1 = soft reset (keep corpus, re-queue); 0 = hard reset |
| `AFL_DRIFT_HAVOC_BOOST` | 1 | Havoc stage multiplier applied after reset |
| `AFL_DRIFT_KEEP_RECENT` | 0 | honggfuzz only: keep N most-recent corpus entries on reset |

**Paper-confirmed parameters by fuzzer pair:**

| Pair | W | C | CL | Notes |
|---|---|---|---|---|
| AFL / AFLCD | 100 | 3 | 10 | Soft reset |
| AFLFast / AFLFastCD | 100 | 3 | 10 | Soft reset |
| MOpt / MOptCD | 100 | 5 | 10 | Soft reset |
| AFL++ / AFL++CD | 100 | 12 | 25 | Higher C prevents cmplog annotation churn |
| FairFuzz / FairFuzzCD | 100 | 3 | 10 | Soft reset |
| honggfuzz / honggfuzzCD | 5 | 2 | 5 | KEEP_RECENT=50 |

---

## Paper Claims → Experiments

| Claim | How to reproduce |
|---|---|
| Δcov improvement in 5/6 pairs (Table 1) | Full 10-rep eval → `summary_table.txt` |
| +13 total unique bugs (RQ2) | Same → `bug_report.txt` |
| 95.5% drift suppression rate (RQ3, Table 2) | Same → `parameter_eval.txt` |
| sqlite3 large coverage gain (+23–57%) | Run any CD pair with `--targets sqlite3` |

---

## Targets Reference

| Target | Programs |
|---|---|
| libpng | `libpng_read_fuzzer` |
| libsndfile | `sndfile_fuzzer` |
| libtiff | `tiff_read_rgba_fuzzer`, `tiffcp` |
| libxml2 | `libxml2_xml_read_memory_fuzzer`, `xmllint` |
| lua | `lua` |
| openssl | `asn1`, `asn1parse`, `bignum`, `client`, `server`, `x509` |
| php | `exif`, `json`, `parser`, `unserialize` |
| poppler | `pdf_fuzzer`, `pdfimages`, `pdftoppm` |
| sqlite3 | `sqlite3_fuzz` |

---

## License

This artifact builds on:
- [AFL](https://github.com/google/AFL) — Apache 2.0
- [AFL++](https://github.com/AFLplusplus/AFLplusplus) — Apache 2.0
- [Magma](https://github.com/HexHive/magma) — Apache 2.0
- [honggfuzz](https://github.com/google/honggfuzz) — Apache 2.0

The drift detection module and all scripts added by this work are released under the Apache 2.0 License.
