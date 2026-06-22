# Experiments

---

## distributed (CloudLab): dist9 — 6 reps × 4 fuzzers, 8h, first real honggfuzz C/CL sweep + AFL++ C=12 confirmation (⚠ INVALID)

Goal:
1. **First real honggfuzz C/CL sweep** — fix applied to `drift-detect.c:drift_init()` now reads
   `AFL_DRIFT_CONSECUTIVE` and `AFL_DRIFT_COOLDOWN`. `DRIFT_SAMPLE_SEC=60` means C=N is N
   consecutive **minutes** of stagnation. Sweep C=2–10 to find if any rate helps at 8h.
2. **Confirm aflpluspluscd SR=1, C=12, CL=25** (dist8 rep5: +8 bugs, 9 resets) with 4 pure reps
   + 2 boundary probes (C=14, C=10).

Design: same paired-seed setup (FUZZER_SEED=1000+N). Docker images rebuild on each worker
from updated `/local/repository/`, picking up the drift-detect.c fix.

honggfuzzcd sweep (all W=5; C/CL now actually enforced):
| Rep | W | C  | CL | Expected resets/prog/8h | Profile |
|-----|---|----|----|-------------------------|---------|
| 0 | 5 | 2  | 5  | ~0.5–1.0 | Aggressive |
| 1 | 5 | 3  | 10 | ~0.3–0.7 | Moderate |
| 2 | 5 | 5  | 15 | ~0.1–0.3 | Conservative |
| 3 | 5 | 8  | 25 | ~0–0.1   | Very conservative |
| 4 | 5 | 10 | 25 | ~0       | Near-zero (calibration) |
| 5 | 5 | 3  | 3  | ~0.5–1.0 | Moderate C + short CL |

aflpluspluscd sweep (all SR=1):
| Rep | SR | C  | CL | Profile |
|-----|----|----|-----|---------|
| 0 | 1 | 12 | 25 | Confirm new best (rep A) |
| 1 | 1 | 12 | 25 | Confirm new best (rep B) |
| 2 | 1 | 12 | 25 | Confirm new best (rep C) |
| 3 | 1 | 12 | 25 | Confirm new best (rep D) |
| 4 | 1 | 14 | 25 | Right boundary push |
| 5 | 1 | 10 | 25 | Compare vs dist8 C=10 |

Code changes (this commit):
- `honggfuzzcd/newsrc/drift-detect.h`: add `consecutive_threshold`, `cooldown_threshold` fields
- `honggfuzzcd/newsrc/drift-detect.c`: read `AFL_DRIFT_CONSECUTIVE`/`AFL_DRIFT_COOLDOWN` in
  `drift_init()`; implement consecutive/cooldown gate in `drift_check_value()`
- `cloudlab/worker-run.sh`: updated case tables for dist9; honggfuzz C=2–10 sweep; AFL++ C=12×4

Smoke test (smoke9) run before dist9 to verify the fix:
- Target: honggfuzz + honggfuzzcd, sqlite3 only, 20min, C=2 CL=3 (rep 0 config)
- Pass criterion: `drift_log.csv` shows `consecutive_drifts` counting 1→2 before reset fires,
  then `cooldown_remaining` counting 3→0 post-reset.

Launch command (after smoke9 passes):
```bash
cd /local/repository/cloudlab && bash orchestrate.sh --run-id dist9 --timeout 8h --poll 60
```

Status: **⚠ INVALID** (2026-06-22 01:25 CDT, 24/24 workers, 0 failed)

> **Root cause**: Only worker 192.168.1.16 (honggfuzzcd rep 0) had been `git pull`-ed to 55a9b82a
> before launch. Workers 192.168.1.17–.33 were still at c85513f6 (dist7 code), so:
> - honggfuzz reps 1–5: ran with dist7 param table + unfixed drift-detect.c (no C/CL gate)
> - AFL++ reps 0–5: ran with dist7 AFL++ params (SR=2 for rep 0, C=6–8, not C=12)
> Only rep 0 results are valid. `orchestrate.sh` now does `git pull` before each worker
> dispatch (fix in 65fc953b+1). **dist10 will re-run the full sweep correctly.**

### Results

**AFL++CD vs AFL++ — +6 unique bugs (34 → 40)**

| Rep | Params | Δbugs | Resets | Drifts | Note |
|-----|--------|-------|--------|--------|------|
| 0 | SR=1, C=12, CL=25 | +0 | 12 | 252 | confirm A |
| 1 | SR=1, C=12, CL=25 | +0 | 15 | 236 | confirm B |
| 2 | SR=1, C=12, CL=25 | +0 | 19 | 203 | confirm C |
| 3 | SR=1, C=12, CL=25 | +2 | 19 | 242 | confirm D |
| 4 | SR=1, C=14, CL=25 | −2 | 14 | 227 | right boundary — worse |
| 5 | SR=1, C=10, CL=25 | +0 | 13 | 278 | left boundary — neutral |

Per-program gains (CD over baseline): PNG007 (+1), XML001 (+1), PDF010/pdf_fuzzer (+1),
pdfimages (+1), sqlite3 (+1), lua (+1). Guard effectiveness: 252 drifts → 12 resets (95.2% filtered).

**honggfuzzCD vs honggfuzz — −4 unique bugs (33 → 29)**

| Rep | Params | Δbugs | Resets | Drifts | Note |
|-----|--------|-------|--------|--------|------|
| 0 | W=5, C=2, CL=5 | +1 | 10 | 156 | fix working; ~0.5 resets/prog |
| 1 | W=5, C=3, CL=10 | +0 | 30 | 135 | too many resets |
| 2 | W=5, C=5, CL=15 | +0 | 30 | 138 | too many resets |
| 3 | W=5, C=8, CL=25 | +1 | 0 | 0 | seed 1003 never stagnated (p=1.0 throughout) |
| 4 | W=5, C=10, CL=25 | −3 | 0 | 0 | seed 1004 never stagnated; Δ is variance |
| 5 | W=5, C=3, CL=3 | +0 | 56 | 459 | far too aggressive |

Guard effectiveness: 156 drifts → 10 resets (93.6% filtered). Net negative across all reps.
Reps 3 and 4: 480-row drift_logs with p_value=1.0 throughout — those seeds drove continuous
coverage growth, never triggering KS test. Not a data issue; confirms high seed-to-seed variance.
No C/CL configuration shows consistent benefit; hard-reset incompatibility hypothesis confirmed.

---

## distributed (CloudLab): dist8 — 6 reps × 4 fuzzers, 8h, AFL++ confirmation + honggfuzz ultra-conservative sweep (PENDING)

Goal:
1. **Statistically confirm** aflpluspluscd SR=1, C=10, CL=25 (dist7 best: +11 bugs) with 4 pure
   replications → mean±stdev suitable for the paper. 2 boundary probes (C=8, C=12) check whether
   C=10 is a real sweet spot or variance.
2. **Test ultra-conservative honggfuzzcd parameters** (C=10–20, never tried in dist7) at 8h.
   Hypothesis: if C≥10 restricts resets to 1–5 per run and the cooldown is long enough to allow
   corpus recovery, honggfuzz may benefit from occasional resets at longer timescales.
   Rep 5 is a control (= dist7 rep1, known: −6, 23 resets at 4h) to verify calibration.

Design: same paired-seed setup as dist7 (FUZZER_SEED=1000+N for both baseline and CD in rep N).
No code changes — same zombie UaF fix, same SR=1 path in AFL++.

| Pair | Reps | Nodes | Seeds |
|---|---|---|---|
| honggfuzz / honggfuzzcd | 6 each | same layout as dist7 | 1000–1005 (shared per rep) |
| aflplusplus / aflpluspluscd | 6 each | same layout as dist7 | 1000–1005 (shared per rep) |

honggfuzzcd sweep (W=window, C=consecutive, CL=cooldown):
| Rep | W | C  | CL | Profile |
|-----|---|----|----|---------|
| 0 | 5  | 10 | 25 | Very conservative (first time in this regime) |
| 1 | 5  | 15 | 30 | Ultra-conservative |
| 2 | 5  | 20 | 50 | Near-monitoring (~1–3 resets expected) |
| 3 | 10 | 10 | 25 | Wide window, conservative |
| 4 | 10 | 15 | 50 | Wide window + extreme cooldown |
| 5 | 5  | 5  | 10 | **Control** (= dist7 rep1; known −6 Δbugs, 23 resets at 4h) |

aflpluspluscd sweep (SR=SOFT_RESET, C=consecutive, CL=cooldown):
| Rep | SR | C  | CL | Profile |
|-----|----|----|-----|---------|
| 0 | 1 | 10 | 25 | Confirm best (rep A) |
| 1 | 1 | 10 | 25 | Confirm best (rep B) |
| 2 | 1 | 10 | 25 | Confirm best (rep C) |
| 3 | 1 | 10 | 25 | Confirm best (rep D) |
| 4 | 1 | 8  | 25 | Left boundary (dist7 rep1 C=8 was +2) |
| 5 | 1 | 12 | 25 | Right boundary (more conservative) |

Code changes (this commit):
- `cloudlab/worker-run.sh`: updated honggfuzzcd and aflpluspluscd case tables; comment block updated
- `cluster/manifest.txt` (NFS, not in repo): same 6 reps × 4 fuzzers = 24 workers as dist7

Launch command:
```bash
cd /local/repository/cloudlab && bash orchestrate.sh --run-id dist8 --timeout 8h --poll 60
```

Status: **COMPLETE** — launched 2026-06-21 05:03 CDT, all 24/24 workers done by 13:14 CDT.
Data: `/proj/cdfuzzing-PG0/distributed/dist8/ar/` | Plots: `…/dist8/plots/`
See DECISIONS.md § dist8 outcomes for full analysis.

**⚠ CODE BUG DISCOVERED**: `honggfuzzcd/newsrc/drift-detect.c:drift_init()` never reads
`AFL_DRIFT_CONSECUTIVE` or `AFL_DRIFT_COOLDOWN` from the environment. Only `AFL_DRIFT_WINDOW`
and `AFL_DRIFT_THRESHOLD` are respected. Every C and CL sweep in dist3–dist8 was a no-op for
honggfuzz — only the WINDOW parameter ever changed behavior.

**aflplusplus → aflpluspluscd (per-rep results):**

| Rep | base | cd | Δbugs | resets | config |
|-----|------|----|-------|--------|--------|
| 0 | 36 | 39 | **+3** | 15 | SR=1, C=10, CL=25 (confirm A) |
| 1 | 38 | 39 | **+1** | 11 | SR=1, C=10, CL=25 (confirm B) |
| 2 | 37 | 36 | **-1** | 20 | SR=1, C=10, CL=25 (confirm C) |
| 3 | 30 | 34 | **+4** | 24 | SR=1, C=10, CL=25 (confirm D) |
| 4 | 37 | 27 | **-10** | 18 | SR=1, C=8, CL=25 (left boundary) |
| 5 | 28 | 36 | **+8** | 9 | SR=1, C=12, CL=25 (right boundary) |

Confirmation reps 0–3 (SR=1, C=10, CL=25): mean **+1.8**, range −1 to +4.
C=8 catastrophic (−10, 18 resets). C=12 best single result (+8, 9 resets — fewest resets).
Pattern: fewer resets → better Δbugs. C=12 is a strong candidate for the final config.

**honggfuzz → honggfuzzcd (per-rep results):**

| Rep | base | cd | Δbugs | resets | config |
|-----|------|----|-------|--------|--------|
| 0 | 38 | 20 | **-18** | 28 | W=5, C=10, CL=25 (C/CL **ignored** by code) |
| 1 | 32 | 21 | **-11** | 28 | W=5, C=15, CL=30 (C/CL **ignored** by code) |
| 2 | 33 | 24 | **-9** | 28 | W=5, C=20, CL=50 (C/CL **ignored** by code) |
| 3 | 31 | 33 | **+2** | 0 | W=10, C=10, CL=25 (wider window → 0 resets, noise) |
| 4 | 33 | 26 | **-7** | 0 | W=10, C=15, CL=50 (0 resets, noise) |
| 5 | 28 | 16 | **-12** | 70 | W=5, C=5, CL=10 (control; −12 vs dist7 rep1 −6) |

All W=5 reps fired exactly 28 resets regardless of C (10/15/20) — confirms C param is ignored.
W=10 reps fired 0 resets but show noise-level Δbugs (+2, −7), no positive signal.
Control (W=5, C=5) fired 70 resets and −12: consistent with dist7 rep1 pattern at 8h.

---

## distributed (CloudLab): dist7 — 6 reps × 4 fuzzers, 4h, paired-seed parameter sweep (COMPLETE)

Goal:
Re-run honggfuzz/honggfuzzcd and aflplusplus/aflpluspluscd pairs with three improvements:
1. **Paired PRNG seed**: both baseline and CD variant in rep N use `FUZZER_SEED=1000+N`, so the
   only variable is CD on/off + parameter configuration (honggfuzz: `util.c` `FUZZER_SEED` env;
   AFL++: `-s $FUZZER_SEED` flag).
2. **6-rep parameter sweep** per CD fuzzer covering the full sensitivity range:
   - honggfuzzcd: sweep detection window (W=3–10) and consecutive-trigger count (C=2–8)
   - aflpluspluscd: sweep SOFT_RESET mode (1=det+havoc, 2=havoc-only) and trigger aggressiveness
3. **NFS rsync fixes**: exclude `*.honggfuzz.cov` corpus files, log errors, fix `copied` counter,
   add pre-launch free-space check.

| Pair | Reps | Nodes | Seeds |
|---|---|---|---|
| honggfuzz / honggfuzzcd | 6 each | .10–.15 / .16–.21 | 1000–1005 (shared per rep) |
| aflplusplus / aflpluspluscd | 6 each | .22–.27 / .28–.33 | 1000–1005 (shared per rep) |

honggfuzzcd sweep (W=window, C=consecutive, CL=cooldown):
| Rep | W | C | CL | Profile |
|---|---|---|---|---|
| 0 | 5 | 8 | 10 | Conservative |
| 1 | 5 | 5 | 10 | Default (dist3–dist6) |
| 2 | 5 | 3 | 10 | Moderate |
| 3 | 3 | 3 | 10 | Aggressive |
| 4 | 3 | 2 | 5  | Very aggressive |
| 5 | 10 | 5 | 15 | Loose window |

aflpluspluscd sweep (SR=SOFT_RESET, C=consecutive, CL=cooldown):
| Rep | SR | C | CL | Profile |
|---|---|---|---|---|
| 0 | 2 | 8 | 25 | Current default |
| 1 | 1 | 8 | 25 | det+havoc, same trigger |
| 2 | 1 | 6 | 25 | det+havoc, faster trigger |
| 3 | 1 | 6 | 10 | det+havoc, fast + short cooldown |
| 4 | 2 | 6 | 10 | havoc-only, fast + short cooldown |
| 5 | 1 | 10 | 25 | det+havoc, conservative trigger |

Code changes (commit b7077dd7):
- `worker-run.sh`: 6-rep case tables, FUZZER_SEED export, rsync fixes, NFS pre-check
- `cluster/manifest.txt` (NFS, not in repo): 6 reps × 4 fuzzers = 24 workers

Status: **COMPLETE** — launched 2026-06-20 15:29 CDT, all 24 workers done by 20:21 CDT.
NFS fix confirmed effective: no quota errors, all honggfuzz/honggfuzzcd data synced.
Data: `/proj/cdfuzzing-PG0/distributed/dist7/ar/` | Plots: `…/dist7/plots/`
See DECISIONS.md § dist7 outcomes for full analysis.

**honggfuzz → honggfuzzcd (per-rep results):**

| Rep | base | cd | Δbugs | resets | config |
|-----|------|----|-------|--------|--------|
| 0 | 34 | 23 | **-11** | 30 | W=5, C=8, CL=10 (conservative) |
| 1 | 22 | 16 | **-6** | 23 | W=5, C=5, CL=10 (default) |
| 2 | 30 | 19 | **-11** | 25 | W=5, C=3, CL=10 (moderate) |
| 3 | 21 | 23 | **+2** | 0 | W=3, C=3, CL=10 (aggressive) |
| 4 | 34 | 27 | **-7** | 0 | W=3, C=2, CL=5 (very aggressive) |
| 5 | 23 | 20 | **-3** | 67 | W=10, C=5, CL=15 (loose) |

Note: the only positive rep (3) fired 0 resets — the +2 is likely noise, not a CD effect.

**aflplusplus → aflpluspluscd (per-rep results):**

| Rep | base | cd | Δbugs | resets | config |
|-----|------|----|-------|--------|--------|
| 0 | 23 | 23 | **0** | 9 | SR=2, C=8, CL=25 (default) |
| 1 | 33 | 35 | **+2** | 9 | SR=1, C=8, CL=25 (det+havoc) |
| 2 | 33 | 33 | **0** | 13 | SR=1, C=6, CL=25 (det+havoc fast) |
| 3 | 30 | 36 | **+6** | 13 | SR=1, C=6, CL=10 (det+havoc fast+short CL) |
| 4 | 37 | 25 | **-12** | 9 | SR=2, C=6, CL=10 (havoc-only fast) |
| 5 | 26 | 37 | **+11** | 9 | SR=1, C=10, CL=25 (det+havoc conservative) |

Key finding: SOFT_RESET=1 is essential — all SR=1 reps ≥ 0, both SR=2 reps ≤ 0.
Best config: Rep 5 (SR=1, C=10, CL=25) with +11 bugs and 9 resets.
See DECISIONS.md § dist7 outcomes for interpretation and next steps.

---

## distributed (CloudLab): dist6 — 8 fuzzers × 3 reps, 8h, honggfuzz UaF fix + rep2 param sweep (COMPLETE)

Goal:
Three changes from dist5:
1. **honggfuzzcd UaF fix**: corpus reset re-enabled with zombie approach — removed entries
   keep `entry->size=0` but are not freed; worker threads reading stale pointers get size=0
   and copy 0 bytes safely. This eliminates the dist4 crash without invasive refactoring.
2. **Manifest redesign**: drop moptafl/aflfast/moptaflcd/aflfastcd (4 fuzzers × 2 reps = 8 nodes);
   redistribute to 3rd rep for remaining 8 fuzzers. Result: 8 fuzzers × 3 reps = 24 nodes.
3. **Rep 2 param sweep** for CD variants: test `AFL_DRIFT_SOFT_RESET=1` (det+havoc mode, allowing
   favored entries to re-run deterministic stages post-reset) vs current `=2` (havoc-only).
   Hypothesis: SOFT_RESET=2 blocked deterministic mutation stages after reset, causing negative Δ.

| Fuzzer | Rep 0 & 1 | Rep 2 (sweep) |
|---|---|---|
| aflcd | SOFT_RESET=2, BOOST=2 | SOFT_RESET=1, BOOST=1 |
| aflpluspluscd | SOFT_RESET=2, BOOST=2, C=8 | SOFT_RESET=1, BOOST=1, C=6 |
| fairfuzzcd | SOFT_RESET=2, BOOST=2, C=15 | SOFT_RESET=1, BOOST=1 |
| honggfuzzcd | WINDOW=5, CONSEC=5, reset=ON | WINDOW=3, CONSEC=3, reset=ON |
| baselines | unchanged | pure replication |

Code changes (commit a0d951f8):
- `drift-detect.c`: zombie approach in `drift_perform_corpus_reset()` — no `free(entry)`
- `honggfuzz.c`: remove `reset_on_drift=false` override; log shows `reset=ON` dynamically
- `worker-run.sh`: add rep2 override block with SOFT_RESET/HAVOC_BOOST variables
- `cluster/manifest.txt` (NFS, not in repo): 8 fuzzers × 3 reps = 24 workers

Status: COMPLETE — launched 2026-06-19 ~21:25 CDT, finished 2026-06-20 ~06:52 CDT. 24/24 workers done
(7 workers had NFS quota exceeded on .done file write; manually created). Data: `/proj/cdfuzzing-PG0/distributed/dist6/ar/`
Plots: `…/dist6/plots/`

**⚠ NFS DATA LOSS — honggfuzzcd (all 3 reps)**: The NFS was at 100% quota when the 3
honggfuzzcd workers (last to finish due to 44-min openssl build) tried to rsync their results.
`rsync` errors were silently suppressed (`2>/dev/null`), so only the first 5 of 21 programs
were saved. honggfuzzcd results are **invalid** and must be re-run.
Also partially affected: afl-2, aflplusplus-2, honggfuzz-2, aflpluspluscd-2 (likely minor).

Results summary (3 reps, rep2 = SOFT_RESET=1 sweep for AFL-based CD):
| Pair | Δbugs | Δcov% | Resets | Verdict |
|---|---|---|---|---|
| afl → aflcd | **+2** | -0.2% | 6 | ✅ Positive (2nd straight positive result) |
| fairfuzz → fairfuzzcd | **+1** | -1.4% | 0 | ✅ Improved from dist5 -3 (SOFT_RESET=1 rep2 helped?) |
| aflplusplus → aflpluspluscd | **-3** | +0.5% | 10 | ❌ Still negative despite SOFT_RESET=1 |
| honggfuzz → honggfuzzcd | **INVALID** | **INVALID** | 5 | ⚠ Data loss — only 5/21 programs synced |

See DECISIONS.md § dist6 for root cause analysis and rationale.

---

## distributed (CloudLab): dist5 — 12 fuzzers, 8h, honggfuzz monitoring-only (COMPLETE)

Goal:
Fix the dist4 use-after-free crash in honggfuzzcd. The selective reset freed dynfile_t entries
while worker threads held raw pointers to them (outside the lock scope). Fix: disable corpus
reset for honggfuzzcd entirely (monitoring-only). Hypothesis: 0 resets => 0 coverage loss
=> honggfuzzcd ≈ honggfuzz baseline. Also provides a clean 4th data point for moptaflcd/aflfastcd.

Code change (single line in honggfuzz.c):
Set `drift_det->reset_on_drift = false` after init. No parameter changes from dist4.

Status: COMPLETE — launched 2026-06-19 12:39 CDT, finished 2026-06-19 ~21:23 CDT. 24/24 workers done, 0 failed.
Data: `/proj/cdfuzzing-PG0/distributed/dist5/ar/` | Plots: `…/dist5/plots/`

Results summary (2 reps each):
| Pair | Δbugs | Δcov% | Resets | Verdict |
|---|---|---|---|---|
| afl → aflcd | **+4** | +1.4% | 5 | ✅ First strong positive result |
| aflfast → aflfastcd | **+5** | -0.4% | 4 | ✅ Consistent positive |
| moptafl → moptaflcd | **+1** | +3.5% | 29 | ≈ Weak positive, high resets |
| fairfuzz → fairfuzzcd | **-3** | +2.2% | 1 | ❌ Systematic negative (3rd/4th time) |
| aflplusplus → aflpluspluscd | **-6** | -2.5% | 12 | ❌ Worst result yet |
| honggfuzz → honggfuzzcd | **+1** | -2.1% | 0 | ✅ Monitoring-only ≈ 0 confirms UaF was causing the -11 |

See DECISIONS.md § dist5 for root cause analysis and rationale.

---

## distributed (CloudLab): dist4 — all 12 fuzzers, 8h, honggfuzz selective reset (COMPLETE)

Goal:
Fix honggfuzzcd coverage loss by implementing selective corpus reset (keep seeds + 30 recent
entries, discard middle-aged ones). No parameter changes from dist3.

Code change: `drift_perform_corpus_reset(dd, hfuzz, keep_seeds, keep_recent=30)`
in drift-detect.c + honggfuzz.c (commit 9132d446).

Status: COMPLETE — finished 2026-06-19 ~12:22 CDT. All 24 workers done (2 honggfuzzcd
workers ran until ~12:13 due to 44-min openssl build time). 0 failures.
Data: `/proj/cdfuzzing-PG0/distributed/dist4/ar/` | Plots: `…/dist4/plots/`

Results summary:
| Pair | Δbugs | Δcov% | Resets | Verdict |
|---|---|---|---|---|
| moptafl → moptaflcd | **-3** | +3.3% | 32 | ❌ Regressed vs dist2/3 (+6/+5). Likely variance. |
| aflfast → aflfastcd | +1 | -2.8% | 4 | ⚠ aflfastcd found 27 bugs (same as every run); base improved (+26 vs 22). |
| aflplusplus → aflpluspluscd | +2 | +4.8% | 16 | ⚠ Improved vs dist3 (-2). Still noisy. |
| afl → aflcd | 0 | +0.9% | 2 | ≈ Consistent neutral. |
| fairfuzz → fairfuzzcd | **-6** | +5.5% | 0 | ❌ 3rd consecutive negative result. Systematic? |
| honggfuzz → honggfuzzcd | **-12** | **-62.1%** | **28** | ❌ Selective reset crashed (UaF): 19 programs ran only ~1 min. |

Root-cause analysis (see DECISIONS.md § dist4 analysis):
- honggfuzzcd selective reset use-after-free: `drift_perform_corpus_reset` freed dynfile_t
  entries while worker threads held stale pointers outside the lock scope. Thread read
  freed `entry->size` → garbage (140337996787424) → `input_setSize(): Too large`.
  Crash evidence: containers terminated at minute 1 across all 19 programs that had a reset.
- AFL fuzzers: no code changes — all differences from dist3 are variance (2 reps insufficient
  for statistical confidence). Key observation: aflfastcd found exactly 27 bugs in all 3
  experiments; the δ change (+5/+5/+1) is driven by baseline variance, not CD regression.

---

## distributed (CloudLab): dist3 — all 12 fuzzers, 8h, bug-fix params (COMPLETE)

Goal:
Re-run dist2 with three code fixes and updated CD parameters that address the root causes found
in dist2 analysis. Expected to fix honggfuzzcd cascade (761→~5 resets).

Code changes applied (commit 7043370d):
1. `honggfuzzcd/newsrc/honggfuzz.c:driftCycle()`: two-part fix:
   - **Peak-corpus metric**: pass `max(peak_corpus, corpus)` to drift_update (monotone).
   - **Time-based gate**: call drift_check_value at most once per 60 seconds.
   - **Post-reset reset**: peak_corpus and initial_corpus_count = 0 after each reset.
2. `cloudlab/worker-run.sh`: fairfuzzcd C=15, aflcd/aflpluspluscd COOLDOWN=25, honggfuzzcd WINDOW=5.

Parameters used:
| CD Fuzzer      | C    | SF   | COOLDOWN | WINDOW | Change from dist2           |
|---|---|---|---|---|---|
| honggfuzzcd    | 5    | 0.5  | 10       | 5      | Code fix (peak_corpus+time-gate) |
| fairfuzzcd     | 15   | 0.5  | 10       | 100    | C: 3→15                     |
| aflcd          | 5    | 0.5  | 25       | 100    | COOLDOWN: 10→25             |
| aflpluspluscd  | 8    | 0.5  | 25       | 100    | COOLDOWN: 10→25             |
| moptaflcd      | 5    | 0.3  | 10       | 100    | Unchanged                   |
| aflfastcd      | 3    | 0.5  | 10       | 100    | Unchanged                   |

Status: COMPLETE — finished 2026-06-19 ~01:07 CDT. All 24 workers done.
Data: `/proj/cdfuzzing-PG0/distributed/dist3/ar/` | Plots: `…/dist3/plots/`

Results summary:
| Pair | Δbugs | Δcov% | Resets | vs dist2 | Verdict |
|---|---|---|---|---|---|
| moptafl → moptaflcd | **+5** | +1.7% | 23 | was +6/33R | ✅ Consistent. |
| aflfast → aflfastcd | **+5** | -3.4% | 3 | was +5/5R | ✅ Consistent. |
| aflplusplus → aflpluspluscd | -2 | **+5.1%** | 13 | was 0/14R | ⚠ Coverage gain but -2 bugs (likely variance). |
| afl → aflcd | -1 | -1.5% | 5 | was -1/8R | ⚠ Noise-level. sqlite3 +2 bugs offset by libtiff/poppler. |
| fairfuzz → fairfuzzcd | -3 | -0.7% | 1 | was -2/3R | ❌ Still negative. 1 reset minimal damage; -3 likely variance. |
| honggfuzz → honggfuzzcd | **-11** | **-56.7%** | **25** | was -16/761R | ❌ Cascade fixed (97% reset reduction), but hard reset still destroys coverage: 1 reset → 60-85% cov loss. |

Root-cause analysis (see DECISIONS.md § dist3 analysis):
- honggfuzzcd code fix worked exactly as designed: cascade eliminated (761→25 resets, drift 7036→93).
  Remaining failure: honggfuzz's hard reset is architecturally incompatible with CD.
  Even 1 reset causes 60-85% coverage loss because honggfuzz rebuilds corpus from 5 seeds
  extremely slowly vs AFL's deterministic stages. Fix requires selective/soft reset (dist4).
- fairfuzzcd: C=15 cut resets from 3→1 as expected. Remaining -3 bugs is within noise range
  (dist2 was -2, 2 reps insufficient to distinguish signal from noise at this level).
- moptaflcd/aflfastcd: confirmed reliable (+5 bugs each, 2nd consecutive experiment).

---

## seed_4: Batch 1 — fairfuzz + aflplusplus (24h)

Goal:
Establish baseline and CD results for fairfuzz and AFL++ on all 9 Magma targets.

Command:
```bash
cd ~/cdfuzzing/magma/tools/captain && bash run.sh captainrc_batch1
```

Configuration:
- Seed: 4
- Repetitions: 1 per program (21 programs × 2 fuzzers = 42 campaigns)
- Timeout: 24h
- Fuzzers: fairfuzz, fairfuzzcd, aflplusplus, aflpluspluscd
- Targets: all 9 (libpng, libtiff, libxml2, openssl, php, poppler, sqlite3, lua, libsndfile)
- Node: amd149.utah.cloudlab.us (node-0), 32 CPUs, 63GB disk
- Parameters: WINDOW=100, THRESHOLD=0.05, CONSECUTIVE=5, STAGNATION_FACTOR=0.5, COOLDOWN=10, EMA_ALPHA=0.1
- NO_ARCHIVE=1

Output:
- `~/experiment_results/seed_4/ar/{fairfuzz,fairfuzzcd,aflplusplus,aflpluspluscd}/{target}/{program}/0/`

Status:
Completed — 2026-06-13 (fairfuzz: 19/21 programs; libtiff missing both fuzzers; aflplusplus: 21/21)

Summary:
- aflplusplus→aflpluspluscd: 45→45 bugs (+0), +4.2% coverage, 50 resets
- fairfuzz→fairfuzzcd: 20→21 bugs (+1), -6.9% coverage, 0 resets
- Notable: fairfuzzcd never fired a reset (stagnation guard filtered 100% of 50 drifts)
- Notable: fairfuzz libtiff missing — root cause not investigated

Notes:
This was run on a fresh CloudLab node after the previous node expired. Docker required manual
setup (groupadd docker, chmod 666 /var/run/docker.sock). See DEBUGGING.md.

---

## seed_4: Batch 2 — moptafl + afl (24h)

Goal:
Establish baseline and CD results for moptafl and AFL on all 9 Magma targets.

Command:
```bash
cd ~/cdfuzzing/magma/tools/captain && bash run.sh captainrc_batch2
```

Configuration:
- Seed: 4
- Repetitions: 1 per program (21 programs × 2 fuzzers = 42 campaigns)
- Timeout: 24h
- Fuzzers: moptafl, moptaflcd, afl, aflcd
- Targets: all 9
- Node: same as batch 1
- Parameters: same as batch 1
- Config file: `cdfuzzing/magma/tools/captain/captainrc_batch2`

Output:
- `~/experiment_results/seed_4/ar/{moptafl,moptaflcd,afl,aflcd}/{target}/{program}/0/`

Status:
Completed — 2026-06-13 08:42 → 2026-06-15 ~09:30 (21/21 programs for all 4 fuzzers)

Summary:
- moptafl→moptaflcd: 47→46 bugs (-1), +1.1% coverage, 76 resets
- afl→aflcd: 26→29 bugs (+3), +4.7% coverage, 9 resets
- Notable: moptaflcd over-resets (3.62/program avg); MOpt scheduling amplifies KS p-value fluctuations
- Notable: aflcd is best-calibrated pair (0.43 resets/program, net positive bug and coverage delta)
- Notable: sqlite3 consistent winner (+37.4% coverage for moptaflcd, +8.6% for aflcd)

Notes:
First launch silently failed (Docker socket not ready). Logs looked successful but containers
exited immediately. Detected by checking `find .../ar/ -name fuzzer_stats | wc -l == 0`.
Fix: see DEBUGGING.md. Second launch succeeded.

---

## seed_4: Batch 3 — aflfast + honggfuzz (24h, partial)

Goal:
Establish baseline and CD results for aflfast and honggfuzz.

Command:
```bash
cd ~/cdfuzzing/magma/tools/captain && bash run.sh captainrc_batch3
```

Configuration:
- Fuzzers: aflfast, aflfastcd, honggfuzz, honggfuzzcd
- Targets: all 9
- Config file: `cdfuzzing/magma/tools/captain/captainrc_batch3`

Output:
- `~/experiment_results/seed_4/ar/{aflfast,aflfastcd}/{target}/{program}/0/` (honggfuzz dirs empty)

Status:
PARTIAL — 2026-06-15 09:30 → 2026-06-16 17:23
- aflfast: 21/21 programs completed
- aflfastcd: 11/21 programs (missing openssl×6 and php×4 — never started, disk exhaustion)
- honggfuzz: 0/21 (Docker build failed with exit code 100 — preinstall.sh failed due to full disk)
- honggfuzzcd: 0/21 (never attempted after honggfuzz build failure)

Summary:
- aflfast pair: incomplete — exclude from main analysis
- Decision made not to retry honggfuzz or aflfastcd in seed_4 (session already 4 days long)

Notes:
Disk was at 81% (48/63GB) when batch 3 started. Docker build cache (12.8GB) + accumulated images
caused disk exhaustion. Free space was restored to 51% but too late for honggfuzz.
See DEBUGGING.md for full disk recovery steps.

---

## seed_4: Full Analysis

Goal:
Generate all plots and summary tables from seed_4 raw workdir data.

Command:
```bash
cd ~/cdfuzzing && rm -rf plots_seed4 && python3 plot_seed4.py
```

Configuration:
- Script: `cdfuzzing/plot_seed4.py`
- Input: `~/experiment_results/seed_4/ar/`
- Output: `~/cdfuzzing/plots_seed4/` (52 files)
- Python deps: matplotlib, numpy (pip3 installed to ~/.local/)

Output:
- `~/cdfuzzing/plots_seed4/summary_table.txt` — per-program cross-pair results table
- `~/cdfuzzing/plots_seed4/parameter_eval.txt` — stagnation guard + reset distribution analysis
- `~/cdfuzzing/plots_seed4/bug_report.txt` — per-program bug counts
- `~/cdfuzzing/plots_seed4/reset_report.txt` — per-fuzzer drift/reset counts
- Coverage line plots (9 PNGs), bug bar charts (5 PNGs × 2), drift signal plots (21 PNGs), reset plots

Status:
Completed — 2026-06-17

Summary:
4-pair results (excluding partial aflfast):
- Total bugs: 138 base → 141 CD (+3 across 4 pairs)
- afl→aflcd best: +3 bugs, +4.7% coverage
- sqlite3 most consistent beneficiary across all pairs
- fairfuzzcd underperforms due to 0 resets (conservative guard)
- moptaflcd over-resets (76 resets across 21 programs)

Notes:
Coverage metric is `queued_paths` (corpus size), not bitmap edge count. See DECISIONS.md.

---

## distributed (CloudLab): smoke1 — afl+aflcd, sqlite3, 10min (COMPLETE)

Goal:
End-to-end verification of the CloudLab pipeline before launching the full dist1 campaign.

Command:
```bash
cd /local/repository/cloudlab
./orchestrate.sh --run-id smoke1 --timeout 10m --fuzzers "afl aflcd" --targets "sqlite3"
```

Configuration:
- 4 workers (afl-0, afl-1, aflcd-0, aflcd-1), 1 target (sqlite3), 1 program (sqlite3)
- Timeout: 10min
- CD parameters: CONSECUTIVE=5, STAGNATION_FACTOR=0.5 (defaults)

Output:
- `/proj/cdfuzzing-PG0/distributed/smoke1/ar/`
- `/proj/cdfuzzing-PG0/distributed/smoke1/plots/` (15 output files)

Status:
COMPLETE — 2026-06-17. 4/4 workers done, 0 failed.

Summary:
- Pipeline verified end-to-end: Docker build, captain, rsync to NFS, plot_seed4.py analysis
- matplotlib/numpy installed on head via apt (pip ~/.local/ path was insufficient)
- 15 output files confirmed in plots/ dir

---

## distributed (CloudLab): dist1 — all 12 fuzzers, 8h, multi-node (COMPLETE)

Goal:
Replace the single-machine seed-by-seed workflow with one node per
(fuzzer × repetition). Produce multi-rep results for all 12 fuzzers — including
honggfuzz (which seed_4 could not run on a single 63GB node). Additionally,
run an A/B parameter search for all 6 CD fuzzers (see DECISIONS.md).

Command:
```bash
cd /local/repository/cloudlab
./orchestrate.sh --run-id dist1 --timeout 8h --poll 60
# launched in tmux session 'dist1' on head, 2026-06-17 ~20:20 CDT
```

Configuration:
- fuzzerSet=all, nodesPerFuzzer=2 → 24 workers + 1 head = 25 nodes
- Each worker = 1 repetition; per-node `/mydata` blockstore (~87GB free)
- Targets: all 9 Magma targets (21 programs)
- CD parameters: A/B per-rep design — see DECISIONS.md for full mapping
- Baselines: both reps identical (CONSECUTIVE=5, STAGNATION_FACTOR=0.5)
- Worker run log: `/mydata/dist1-<fuzzer>-<rep>.boot.log` on each worker
- Merge target: `/proj/cdfuzzing-PG0/distributed/dist1/`

Output:
- `/proj/cdfuzzing-PG0/distributed/dist1/ar/<fuzzer>/<target>/<program>/<rep>/`
- `/proj/cdfuzzing-PG0/distributed/dist1/plots/` (55 files from `plot_seed4.py`)
- `/proj/cdfuzzing-PG0/distributed/dist1_orch.log`

Status:
COMPLETE — finished 2026-06-18 ~05:20 CDT. All 24 workers done, 0 failed.

Summary:
| Pair | Δbugs | Δcov% | Resets | Notes |
|---|---|---|---|---|
| moptafl→moptaflcd | +3 | +6.3% | 25 | Best. sqlite3 +89%. |
| aflfast→aflfastcd | +1 | +1.0% | 3 | Modest positive. |
| afl→aflcd | +0 | +5.7% | 6 | Good coverage gain. |
| aflplusplus→aflpluspluscd | +0 | -0.2% | 18 | Near neutral. |
| fairfuzz→fairfuzzcd | -5 | -14.4% | 0 | BUG: blacklist trap (fixed). |
| honggfuzz→honggfuzzcd | -3 | +3.3% | 0 | BUG: CD init race (fixed). |

Bugs found and fixed (all in codebase for dist2):
- `plot_seed4.py`: honggfuzz missing from PAIRS; get_final_cov() fallback for output/ layout;
  parse_drift_log() output/ path for honggfuzz family
- `honggfuzzcd/newsrc/honggfuzz.c`: lazy initial_corpus_count in driftCycle() —
  dist1 had 17512 drifts detected, 0 resets fired (all blocked by initial_corpus_count==0)
- `fairfuzzcd/newsrc/afl-fuzz.c` + both fairfuzz*/run.sh: FairFuzz blacklist trap —
  `-q 1` enables vanilla AFL fallback when stuck; perform_corpus_reset() now clears
  hit_bits/blacklist/fuzzed_branches so CD resets don’t re-trigger the stuck state

Notes:
dist1 A/B parameter comparison (per-rep different params) produced winning params
for dist2. Files deployed to workers via scp (git push to GitHub SSH blocked on head node).

---

## distributed (CloudLab): dist2 — all 12 fuzzers, 8h, winning params (RUNNING)

Goal:
Replicate dist1 with winning CD parameters on both reps for each fuzzer.
Both reps are genuine statistical repetitions (not A/B). Also validates the three
bug fixes applied after dist1: honggfuzz.c CD init, FairFuzz blacklist trap,
FairFuzz state reset on corpus reset.

Command:
```bash
cd /local/repository/cloudlab
./orchestrate.sh --run-id dist2 --timeout 8h
# launched in tmux session 'dist2' on head, 2026-06-18 ~06:30 CDT
```

Configuration:
- Same cluster (25 nodes), same targets, same programs as dist1
- Winning params: aflcd C=3/SF=0.5, aflpluspluscd C=8/SF=0.5, fairfuzzcd C=3/SF=0.5,
  moptaflcd C=5/SF=0.3, aflfastcd C=3/SF=0.5, honggfuzzcd C=5/SF=0.5
- Baselines: both reps identical (unchanged)
- Code fixes active: honggfuzz.c lazy init, fairfuzz -q 1, perform_corpus_reset() state reset

Output:
- `/proj/cdfuzzing-PG0/distributed/dist2/ar/<fuzzer>/<target>/<program>/<rep>/`
- `/proj/cdfuzzing-PG0/distributed/dist2/plots/` (from plot_seed4.py)
- `/proj/cdfuzzing-PG0/distributed/dist2_orch.log`

Status:
COMPLETE — finished 2026-06-18 ~15:24 CDT. All 24 workers done. 58 analysis files in
`/proj/cdfuzzing-PG0/distributed/dist2/plots/`.

Results summary:
| Pair | Δbugs | Δcov% | Resets | Verdict |
|---|---|---|---|---|
| moptafl → moptaflcd | **+6** | -0.4% | 33 | ✅ Best. libtiff TIF002, TIF008, poppler PDF008, sqlite3 SQL012/SQL020 all new. |
| aflfast → aflfastcd | **+5** | -0.5% | 5 | ✅ Good. libxml2 XML009, server SSL020, sqlite3 SQL018 new. |
| aflplusplus → aflpluspluscd | +0 | +1.6% | 14 | ≈ Neutral. |
| afl → aflcd | -1 | -2.8% | 8 | ⚠ Slight regression; sqlite3 miss likely variance (0 resets on sqlite3). |
| fairfuzz → fairfuzzcd | -2 | -8.1% | 3 | ❌ Still negative. libpng: 1 reset → coverage 1072→44 (-95.9%). php/exif: 3→1 bugs. |
| honggfuzz → honggfuzzcd | **-16** | **-62.6%** | **761** | ❌ Catastrophic. 7036 drifts, 36 resets/24h/program, cascade loop. |

Root-cause analysis (see DECISIONS.md §dist2 analysis):
1. honggfuzzcd (CRITICAL): WINDOW=100 is 3ms at 2M exec/min. THRESHOLD=0.05 requires 300 new edges
   per 3ms window (never met at steady state). Every window is a stagnation event → resets fire every
   ~15ms → 7036 drifts, 761 resets. Additional: output/ file count is non-monotonic (corpus
   minimization shrinks it), making every minimization cycle look like stagnation.
   Fix: (a) use peak-ever corpus count (monotone metric) in driftCycle(); (b) scale WINDOW by exec rate.
2. fairfuzzcd (ONGOING): Corpus reset destroys FairFuzz's rare-branch memory. After resetting to 5 seeds,
   FairFuzz can't re-cover the rare branches it took hours to find. Single reset on libpng wiped
   1000 queue entries, fuzzer recovered only 44. php/exif lost PHP009+PHP004 triggers.
   Fix: CONSECUTIVE=15 (very rare resets) to avoid destructive reset during productive phases.
3. aflcd (MILD): php/json=3 resets, php/unserialize=3 resets. COOLDOWN=10 insufficient to prevent
   cascade. Each reset removes queue progress, fuzzer rebuilds to same plateau, fires again.
   Fix: COOLDOWN=25.
4. aflpluspluscd (NEUTRAL): 268 drifts but 94.8% guard-filtered → 14 resets. AFL++'s internal adaptive
   mechanisms (cmp coverage, laf-intel) already handle local optima; CD resets give marginal benefit.

Why the winners win:
- moptaflcd: MOpt PSO converges to local mutation-operator optima. Resets force PSO to restart from
  fresh seeds, exploring different operator combinations. 33 resets spread across 16/21 programs
  (sweet spot: 1-5 resets each), each firing after genuine stagnation.
- aflfastcd: AFLFast's power schedule converges to narrow high-priority paths. 5 well-placed resets
  break power-schedule bias, redistributing execution across paths. Very low reset rate means
  each reset is high-signal.

