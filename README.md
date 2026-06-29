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
| Docker | 20.10 or later |
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
sudo groupadd docker 2>/dev/null; sudo usermod -aG docker $USER
sudo systemctl start docker
newgrp docker
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
run_local.sh              Evaluation entry point (wraps captain)
```

**CD module source** (the core implementation):
- `magma/fuzzers/aflcd/newsrc/afl-drift-detect.c` — KS test, EMA stagnation guard, soft reset
- `magma/fuzzers/aflcd/newsrc/afl-drift-detect.h` — struct and function declarations
- honggfuzz uses an equivalent module under `magma/fuzzers/honggfuzzcd/`

---

## Kick the Tires (~10 minutes)

Verify that the artifact builds and that the drift detection module fires before committing to a full evaluation.

```bash
bash run_local.sh --kick-the-tires
```

This runs AFL (baseline) and AFLCD side-by-side on `libpng` for 10 minutes using deliberately aggressive CD parameters (window=5, consecutive=1, cooldown=1, stagnation guard disabled) so that at least one corpus reset fires within the short window.

On completion the script checks:
1. Both containers exited without error.
2. The CD module produced a drift log for AFLCD.
3. At least one reset is recorded in that log.

Expected output:
```
[OK]   drift_log.csv found: .../ar/aflcd/libpng/libpng_read_fuzzer/0/findings/drift_log.csv
[OK]   4 reset(s) recorded in drift log.

==============================
 KICK-THE-TIRES: PASSED
==============================
```

If this is your first run, Docker will build the `afl` and `aflcd` images first (add ~5–10 minutes).

---

## Running an Evaluation

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

### Quick trial (~1 hour)

Run AFL vs AFLCD on sqlite3 for one hour with two repetitions:

```bash
bash run_local.sh \
  --fuzzers "afl aflcd" \
  --targets "sqlite3" \
  --timeout 1h \
  --reps 2 \
  --outdir ./results/trial
```

### Reproducing a paper fuzzer pair (24 hours, all targets, 10 reps)

```bash
bash run_local.sh \
  --fuzzers "afl aflcd" \
  --targets "sqlite3 libpng lua libsndfile libtiff libxml2 poppler php openssl" \
  --timeout 24h \
  --reps 10 \
  --outdir ./results/afl_pair
```

> **Resource note:** 10 reps x 21 programs x 2 fuzzers = 420 campaigns. Each campaign
> uses one CPU core for 24 hours. On a single machine, campaigns run in parallel up to
> `--workers` (default: all cores), so wall-clock time depends on available hardware.

### Running all six pairs

```bash
bash run_local.sh \
  --fuzzers "afl aflcd aflfast aflfastcd moptafl moptaflcd aflplusplus aflpluspluscd fairfuzz fairfuzzcd honggfuzz honggfuzzcd" \
  --targets "sqlite3 libpng lua libsndfile libtiff libxml2 poppler php openssl" \
  --timeout 24h \
  --reps 10 \
  --outdir ./results/full_eval
```

---

## Analyzing Results

An analysis script for computing per-program coverage deltas, bug-finding deltas, and stagnation guard statistics from the campaign output will be provided separately.

Campaign output is written to `<outdir>/ar/<fuzzer>/<target>/<program>/<rep>/` and contains standard AFL `fuzzer_stats`, plot data, and a `findings/drift_log.csv` for CD variants.

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

`run_local.sh` applies these parameters automatically for each named fuzzer.

---

## Paper Claims → Experiments

| Claim | How to reproduce |
|---|---|
| Δcov improvement in 5/6 pairs (Table 1) | Full 10-rep eval, analyze `ar/` output |
| +13 total unique bugs (RQ2) | Same |
| 95.5% drift suppression rate (RQ3, Table 2) | Same |
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
