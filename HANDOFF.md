# Handoff

## Current State (2026-07-01)

Experiment expiring. Data archived to `/mydata/` on head and partially to local Mac. Worker SSH
restored via drop-in at `/etc/ssh/cdfuzz_authorized_keys` on all 60 Wisconsin + 36 Utah workers.
dist11/dist12 raw data partially recovered from worker `/mydata/` disks to NFS.
NFS at ~80% (21 GB free) — stopped transfers to avoid filling disk.
**Next action: analyze dist14 vs baseline honggfuzz; analyze dist15 vs baseline.**

| Step | Status |
|---|---|
| dist11: reps 0–4 (Wisconsin) | ⚠ PARTIAL — `/proj/CDFuzzing/distributed/dist11/ar/` has rep 0 full + partial reps 1–4 (NFS space limited). Worker nodes accessible at 192.168.1.10–69 with cluster key. |
| dist12: reps 5–7 (Utah) | ⚠ PARTIAL — `/proj/CDFuzzing/distributed/dist12/ar/` has reps 0,5,6,7. Workers at `<fuzzer>-N.eldarfin-309225.cdfuzzing-pg0.utah.cloudlab.us`. |
| dist13: reps 8–9 (Utah) | ✅ COMPLETE — `/mydata/dist13/ar/` on Wisconsin; archived to `/mydata/dist13_ar.tar.gz` (428 MB) |
| merged/ar/ symlink tree | ⚠ PARTIAL — reps 8–9 working (→ dist13); reps 0–7 symlinks broken (dist11/dist12 data was deleted earlier, now partially restored) |
| 10-rep analysis | ✅ COMPLETE — evaluation.tex table confirmed correct; guard stats unchanged (144/3222, 95.5%) |
| Paper (evaluation.tex) | ✅ CURRENT — 10-rep values, compiles clean |
| dfcov/dfbug/dfbugdelta analysis | ✅ COMPLETE (2026-06-29) — see Results section below |
| dist14: honggfuzz KEEP_RECENT=50 (Wisconsin) | ✅ COMPLETE — 20/20 workers done; archived to `/mydata/dist14_ar.tar.gz` (130 MB); analysis pending |
| dist15: aflcd_v2/v3 + aflfastcd_v2 (Utah) | ✅ ANALYZED — data at `/mydata/dist15/ar/`; archived to `/mydata/dist15_ar.tar.gz` (184 MB) |

### Data Archives on Wisconsin `/mydata/` (scp to local machine)

```bash
scp eldarfin@pc536.emulab.net:/mydata/dist13_ar.tar.gz ~/cdfuzzing-data/
scp eldarfin@pc536.emulab.net:/mydata/dist14_ar.tar.gz ~/cdfuzzing-data/
scp eldarfin@pc536.emulab.net:/mydata/dist15_ar.tar.gz ~/cdfuzzing-data/
scp eldarfin@pc536.emulab.net:/mydata/hfuzz_paired_9rep.log ~/cdfuzzing-data/
scp eldarfin@pc536.emulab.net:/mydata/cdfuzzing_repo.zip ~/cdfuzzing-data/
scp eldarfin@pc536.emulab.net:/mydata/paper_repo.zip ~/cdfuzzing-data/
```

### SSH Access to Workers (restored 2026-07-01)

Cluster key: `/proj/CDFuzzing/cluster/ssh/id_rsa` (and pubkey `.pub`)
Drop-in installed at `/etc/ssh/cdfuzz_authorized_keys` + `/etc/ssh/sshd_config.d/90-cdfuzz.conf` on all workers.

- Wisconsin workers: SSH via internal IPs `192.168.1.10–69` (uses cluster key via SSH config)
- Utah workers: `ssh -i /proj/CDFuzzing/cluster/ssh/id_rsa <fuzzer>-N.eldarfin-309225.cdfuzzing-pg0.utah.cloudlab.us`

### Recovering remaining dist11 reps (when NFS has space)

Workers store data locally under `0/` regardless of rep. Use tar transform:
```bash
# For ip X with rep = (X-10)%5:
ssh 192.168.1.X "tar -C /mydata/dist11/ar --transform='s|/0/|/REP/|;s|/0$|/REP|' \
  --exclude='*/queue' --exclude='*/output' -cf - . 2>/dev/null" | \
  tar -C /proj/CDFuzzing/distributed/dist11/ar/ -xf -
```

### 10-Rep Results (correct Δbugs methodology)

**Δbugs** = sum over programs of (|cd_union_bugs| − |base_union_bugs|) where union is over all 10 reps.
This is the metric used in evaluation.tex and confirmed correct on June 29.

| Pair | Δcov | Δbugs (all progs) | Δbugs (fired progs only) | Programs fired | Resets |
|---|---|---|---|---|---|
| afl → aflcd | **+1.0%** | **-3** | **+1** | 7/21 | 19 |
| aflfast → aflfastcd | **+1.6%** | **0** | **0** | 9/21 | 8 |
| moptafl → moptaflcd | **+4.1%** | **+8** | **+6** | 20/21 | 78 |
| aflplusplus → aflpluspluscd | -1.8% | **+1** | **0** | 16/21 | 15 |
| fairfuzz → fairfuzzcd | **+2.4%** | **+6** | **+2** | 8/21 | 10 |
| honggfuzz → honggfuzzcd | -- | **+1** | **0** | 18/21 | 14 |

> **Δbugs (fired only)** restricts the union to reps where that program had ≥1 reset.
> **−3 for AFL** comes entirely from zero-reset programs (variance, not CD-caused).
> **+6 for FairFuzz (all)** is dominated by libsndfile (+4, 0 resets) — variance; fired-only = +2.
> **Δcov values** from evaluation.tex (relative change); honggfuzz uses raw edge counts (incomparable).

---

### Root Cause Analysis (2026-06-27)

**AFL-CD (−3 bugs):** Cascade reset pattern found. Resets fire at minutes 28, 81, 127, 155, 176, 198 — then NONE for ~1,242 remaining min (86% of campaign = vanilla AFL). Root cause: each reset depletes corpus (post-reset exploration shrinks 200→53→46→28→21→22 min). The −3 bug regression comes entirely from programs with 0 resets — pure statistical noise, not a real regression. Fix: longer cooldown (CL=60) prevents cascade by guaranteeing ≥72 min between resets.

**AFLFast-CD (+1 bug):** Only rep7/sqlite3 fired (once, +1 bug, +29% cov). Others never triggered because p-value recovered before consecutive=3. Fix: C=2 (fire on 2 consecutive stagnant windows) makes sqlite3 fire in ~5/10 reps.

### dist15 Results (2026-06-29, analysis complete)

Utah NFS was 100% full at end of run; data pulled directly from workers → Wisconsin `/mydata/dist15/ar/` via `pull_dist15.sh`. aflfastcd_v2 limited to 5/10 reps (workers .35-.39 inaccessible). monitor/ dirs deleted from dist15/ar/ (inode exhaustion). Analysis script: `analyze_dist15.py`.

| Variant | C | CL | Total Resets | vs Baseline | Mean Δcov | Δbugs |
|---|---|---|---|---|---|---|
| aflcd_v2 | 3 | 60 | 105 (10 reps) | aflcd: 200 (−47%) | +1.15% | +2 |
| aflcd_v3 | 5 | 120 | 113 (10 reps) | aflcd: 200 (−43%) | +1.27% | +4 |
| aflfastcd_v2 | 2 | 25 | 39 (5 reps) | aflfastcd: 83 | +0.63% | 0 |

**Key takeaways:**
1. **CL=60 confirmed**: reduces cascade (php/json 64→22, php/unserialize 59→28, libpng 60→40). Per-rep counts now uniform (2-4/rep vs 4-9/rep before).
2. **CL is dominant**: raising C from 3→5 barely changes reset count (v2 ≈ v3).
3. **aflfastcd_v2 C=2 hypothesis failed**: sqlite3 fired 0/5 reps (expected ~5/10). C=2 appears no better than C=3 for sqlite3.

### New Experiments

**dist14** — honggfuzz/honggfuzzcd KEEP_RECENT=50 (Wisconsin, 20 workers, reps 0–9)
- Parameters: W=5, C=2, CL=5, SR=1, KEEP_RECENT=50 (soft reset keeps 50 most recent inputs)
- Baseline honggfuzz reps 0–9 co-running for direct comparison
- Data: `/proj/CDFuzzing/distributed/dist14/ar/`

**dist15** — AFL-CD and AFLFast-CD parameter variants (Utah, 30 workers, reps 0–9)

| Fuzzer | C | CL | Hypothesis |
|---|---|---|---|
| `aflcd_v2` | 3 | 60 | 6× longer cooldown prevents corpus depletion cascade |
| `aflcd_v3` | 5 | 120 | Higher evidence + very long cooldown → 3–4 resets, not 6 |
| `aflfastcd_v2` | 2 | 25 | C=2 fires on 2-window stagnation → sqlite3 triggers in ~5/10 reps |

- Seeds: 1000–1009 (reps 0–9), same as existing baselines → paired comparison valid
- Worker assignments: aflcd_v2 → IPs .10–.19, aflcd_v3 → .20–.29, aflfastcd_v2 → .30–.39
- Data: `/proj/cdfuzzing-PG0/distributed/dist15/ar/` (Utah, then rsync to Wisconsin)

---

## ~~Next: dist13 (reps 8–9, Utah cluster2)~~ COMPLETE

> dist13 is done (25/25 workers). Commands below are kept for reference. Rsync to Wisconsin still needed.

Full procedure is in CLUSTER2.md. Summary:

**Step 1 — Update manifest on cluster2:**
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

**Step 2 — Launch dist13:**
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

**Monitor dist13:**
```bash
ssh eldarfin@amd131.utah.cloudlab.us '
  echo "done: $(ls /proj/cdfuzzing-PG0/distributed/dist13/status/*.done 2>/dev/null | wc -l) / 24"
  tail -5 /proj/cdfuzzing-PG0/distributed/dist13/log/orchestrate.log
'
```

---

## After dist13 — Build 10-rep merged tree and re-run analysis

```bash
# 1. Rsync ar/ (without monitor/)
rsync -avz --progress --exclude='monitor' \
  eldarfin@amd131.utah.cloudlab.us:/proj/cdfuzzing-PG0/distributed/dist13/ar/ \
  /proj/CDFuzzing/distributed/dist13/ar/

# 2. Thin monitor on Utah
ssh eldarfin@amd131.utah.cloudlab.us 'python3 - <<EOF
import os, shutil
AR = "/proj/cdfuzzing-PG0/distributed/dist13/ar"
THIN = "/proj/cdfuzzing-PG0/distributed/dist13_thin_mon"
count = 0
for fuzzer in sorted(os.listdir(AR)):
  for target in sorted(os.listdir(f"{AR}/{fuzzer}")):
    for prog in sorted(os.listdir(f"{AR}/{fuzzer}/{target}")):
      for rep in sorted(os.listdir(f"{AR}/{fuzzer}/{target}/{prog}")):
        mon = f"{AR}/{fuzzer}/{target}/{prog}/{rep}/monitor"
        if not os.path.isdir(mon): continue
        files = sorted([f for f in os.listdir(mon) if f.isdigit()], key=int)
        if not files: continue
        thin = f"{THIN}/{fuzzer}/{target}/{prog}/{rep}/monitor"
        os.makedirs(thin, exist_ok=True)
        for f in ([files[0]] if len(files)==1 else [files[0], files[-1]]):
          shutil.copy2(f"{mon}/{f}", f"{thin}/{f}")
        count += 1
print(f"done: {count} monitor dirs thinned")
EOF'
rsync -avz eldarfin@amd131.utah.cloudlab.us:/proj/cdfuzzing-PG0/distributed/dist13_thin_mon/ \
  /proj/CDFuzzing/distributed/dist13/

# 3. Extend merged/ symlinks to include reps 8-9
python3 -c "
import os
AR13 = '/proj/CDFuzzing/distributed/dist13/ar'
MERGED = '/proj/CDFuzzing/distributed/merged/ar'
created = 0
for fuzzer in os.listdir(AR13):
  for target in os.listdir(f'{AR13}/{fuzzer}'):
    for prog in os.listdir(f'{AR13}/{fuzzer}/{target}'):
      for rep in os.listdir(f'{AR13}/{fuzzer}/{target}/{prog}'):
        src = f'{AR13}/{fuzzer}/{target}/{prog}/{rep}'
        dst = f'{MERGED}/{fuzzer}/{target}/{prog}/{rep}'
        if not os.path.exists(dst):
          os.makedirs(os.path.dirname(dst), exist_ok=True)
          os.symlink(src, dst)
          created += 1
print(f'created {created} symlinks')
"

# 4. Re-run analysis
mkdir -p /proj/CDFuzzing/distributed/merged/plots /proj/CDFuzzing/distributed/merged/log
CDFUZZ_BASE=/proj/CDFuzzing/distributed/merged \
CDFUZZ_OUTDIR=/proj/CDFuzzing/distributed/merged/plots \
  python3 /users/eldarfin/cdfuzzing/plot_seed4.py \
  > /proj/CDFuzzing/distributed/merged/log/analysis.log 2>&1 &
echo "PID: $!"
```

---

## After dist15 completes (~June 28 18:00 MDT)

```bash
# 1. Rsync dist15 results from Utah to Wisconsin
rsync -avz --progress \
  eldarfin@amd131.utah.cloudlab.us:/proj/cdfuzzing-PG0/distributed/dist15/ar/ \
  /proj/CDFuzzing/distributed/dist15/ar/

# 2. Also rsync dist13 (reps 8-9, not yet on Wisconsin)
rsync -avz --progress --exclude='monitor' \
  eldarfin@amd131.utah.cloudlab.us:/proj/cdfuzzing-PG0/distributed/dist13/ar/ \
  /proj/CDFuzzing/distributed/dist13/ar/

# 3. Extend merged/ar/ symlinks for dist13 reps 8-9
python3 -c "
import os
AR13 = '/proj/CDFuzzing/distributed/dist13/ar'
MERGED = '/proj/CDFuzzing/distributed/merged/ar'
created = 0
for fuzzer in os.listdir(AR13):
  for target in os.listdir(f'{AR13}/{fuzzer}'):
    for prog in os.listdir(f'{AR13}/{fuzzer}/{target}'):
      for rep in os.listdir(f'{AR13}/{fuzzer}/{target}/{prog}'):
        src = f'{AR13}/{fuzzer}/{target}/{prog}/{rep}'
        dst = f'{MERGED}/{fuzzer}/{target}/{prog}/{rep}'
        if not os.path.exists(dst):
          os.makedirs(os.path.dirname(dst), exist_ok=True)
          os.symlink(src, dst)
          created += 1
print(f'created {created} symlinks')
"

# 4. Add dist15 variants to merged/ar/ (aflcd_v2, aflcd_v3, aflfastcd_v2)
python3 -c "
import os
AR15 = '/proj/CDFuzzing/distributed/dist15/ar'
MERGED = '/proj/CDFuzzing/distributed/merged/ar'
created = 0
for fuzzer in os.listdir(AR15):
  for target in os.listdir(f'{AR15}/{fuzzer}'):
    for prog in os.listdir(f'{AR15}/{fuzzer}/{target}'):
      for rep in os.listdir(f'{AR15}/{fuzzer}/{target}/{prog}'):
        src = f'{AR15}/{fuzzer}/{target}/{prog}/{rep}'
        dst = f'{MERGED}/{fuzzer}/{target}/{prog}/{rep}'
        if not os.path.exists(dst):
          os.makedirs(os.path.dirname(dst), exist_ok=True)
          os.symlink(src, dst)
          created += 1
print(f'created {created} symlinks')
"

# 5. Re-run analysis (include new variant pairs vs baselines)
mkdir -p /proj/CDFuzzing/distributed/merged/plots
CDFUZZ_BASE=/proj/CDFuzzing/distributed/merged \
CDFUZZ_OUTDIR=/proj/CDFuzzing/distributed/merged/plots \
  python3 /users/eldarfin/cdfuzzing/plot_seed4.py \
  > /proj/CDFuzzing/distributed/merged/log/analysis.log 2>&1 &
echo "PID: $!"
```

Note: `plot_seed4.py` needs to be updated to add the new fuzzer pairs:
- `(aflcd_v2, afl)`, `(aflcd_v3, afl)`, `(aflfastcd_v2, aflfast)`

---

## After 10-rep analysis — Paper

1. Fix `content/evaluation.tex` setup paragraph: current text says "mode 2, 2× boost, stagnation 0.25, cooldown 200" — all wrong. Correct values: SR=1, boost 1×, stagnation factor 0.5, cooldown 10 min (AFL/AFLFast/FairFuzz), 25 min (AFL++), 5 min (honggfuzz).
2. Update `content/evaluation.tex` table with 10-rep values.
3. Write the RQ1/RQ2/RQ3 paragraphs (currently say "TODO" in evaluation.tex).
4. Compile: `cd /users/eldarfin/Drift-Aware-Fuzzing && pdflatex -interaction=nonstopmode main.tex > /dev/null && bibtex main > /dev/null && pdflatex -interaction=nonstopmode main.tex > /dev/null && pdflatex -interaction=nonstopmode main.tex 2>&1 | tail -3`

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

**`dist11` COMPLETE — 12 fuzzers × 5 reps × 24h (reps 0–4, Wisconsin)**
- 60/60 workers done, ~05:35 CDT 2026-06-26
- Data: `/proj/CDFuzzing/distributed/dist11/ar/`

**`dist12` COMPLETE — 12 fuzzers × 3 reps × 24h (reps 5–7, Utah cluster2)**
- 36/36 workers done, ~07:35 CDT 2026-06-26
- Data: `/proj/CDFuzzing/distributed/dist12/ar/` (transferred to Wisconsin; thin monitors)
- Note: aflfast/sqlite3 rep 1 missing (campaign failure on Utah)

**`dist13` COMPLETE — 12 fuzzers × 2 reps × 24h (reps 8–9, Utah cluster2)**
- 25/25 workers done (by 2026-06-27)
- Data: `/proj/cdfuzzing-PG0/distributed/dist13/ar/` (Utah only — NOT yet rsynced to Wisconsin)
- Pending: rsync to Wisconsin, extend merged/ar/ symlinks to reps 8–9, rerun 10-rep analysis

**`dist14` RUNNING — honggfuzz/honggfuzzcd KEEP_RECENT=50 (Wisconsin, 2026-06-27)**
- 20 workers (honggfuzz × 10 reps + honggfuzzcd × 10 reps), launched ~2026-06-27 17:00 MDT
- Parameters: W=5, C=2, CL=5, SR=1, KEEP_RECENT=50
- Expected completion: ~June 27 18:30 MDT
- Data: `/proj/CDFuzzing/distributed/dist14/ar/`

**`dist15` RUNNING — AFL-CD/AFLFast-CD parameter variants (Utah, 2026-06-27)**
- 30 workers: aflcd_v2 (C=3,CL=60) × 10 + aflcd_v3 (C=5,CL=120) × 10 + aflfastcd_v2 (C=2,CL=25) × 10
- Launched 2026-06-27 17:09 MDT; expected completion ~June 28 18:00 MDT
- All 30 workers confirmed building (containers started at 17:18 MDT for early programs)
- Data: `/proj/cdfuzzing-PG0/distributed/dist15/ar/` (Utah)

**`merged` (8-rep) COMPLETE — reps 0–7 via symlink tree**
- 1,995 symlinks at `/proj/CDFuzzing/distributed/merged/ar/`
- Analysis complete: `/proj/CDFuzzing/distributed/merged/plots/summary_table.txt`
- Paper table updated: `Drift-Aware-Fuzzing/content/evaluation.tex` (compiles clean, 6 pages)

**`dist10` LOST — CloudLab lease expired mid-run**
- 12 fuzzers × 5 reps × 24h, launched 2026-06-22, lease expired ~14h in; data wiped

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
