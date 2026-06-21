# Decisions

## 2026-06-21: dist8 outcomes — AFL++ confirmation + honggfuzz code bug

### aflpluspluscd: confirmed positive, C=12 is the new best candidate
4 pure confirmations of SR=1, C=10, CL=25 (dist7 best) gave +3, +1, −1, +4 → mean **+1.8**.
C=8 boundary: −10 (18 resets — catastrophic, confirms C=8 is over the edge).
C=12 boundary: **+8** (9 resets — fewest of all reps, best single-rep result).

The consistent pattern across dist7 and dist8: **fewer resets = better Δbugs**.
Rep 5 in dist7 (C=10, 9 resets at 4h) gave +11. C=12 in dist8 (9 resets at 8h) gave +8.
The variance at C=10 (−1 to +4) is substantial with only 21 programs — the mean +1.8 is
real but noisy. C=12 may reduce accidental over-triggering while still catching genuine
stagnation, making it a cleaner operating point.

**Recommended final config**: SR=1, C=12, CL=25. Should be tested with ≥4 dedicated reps
before paper submission.

### honggfuzzcd: critical code bug — C and CL parameters were never read
**Root cause**: `drift-detect.c:drift_init()` reads only `AFL_DRIFT_WINDOW` and
`AFL_DRIFT_THRESHOLD` from the environment. There is no `getenv("AFL_DRIFT_CONSECUTIVE")`
or `getenv("AFL_DRIFT_COOLDOWN")` call anywhere in the honggfuzz CD codebase.

Consequence: every honggfuzz experiment from dist3 to dist8 that swept C or CL was a
**no-op** for those parameters. The effective parameter space was only WINDOW vs no-WINDOW:
- W=5 → ~28 resets/run (regardless of C=5/8/10/15/20) at 8h
- W=10 → 0 resets/run (KS test less sensitive with wider windows)
- W=3 (dist7) → 0 resets (too few samples for KS test to reject null)

This also retroactively explains all prior honggfuzz results:
- dist3–dist6 C/CL sweeps for honggfuzz changed nothing
- The "WINDOW=5" experiments all used the same effective config regardless of C=3/5/8

**What was actually tested**: Only the drift detection threshold (WINDOW + THRESHOLD),
not the trigger frequency (CONSECUTIVE) or recovery time (COOLDOWN).

**Whether to fix**: The fix would be adding `getenv()` calls in `drift_init()` and
implementing the consecutive/cooldown gate in `drift_check_value()`. This mirrors what
AFL-based CD fuzzers already do. However, given that honggfuzz's reset is destructive
(hard reset of entire corpus) and all non-zero-reset configs hurt at every WINDOW value
tested, fixing the C/CL reading might not help — the fundamental problem is honggfuzz
rebuilds corpus from scratch far slower than AFL. Decision: **fix the bug for completeness
and run one final honggfuzz sweep** (dist9) with a working C/CL parameter, then accept
the negative result if it persists.

---

## 2026-06-21: dist7 outcomes — parameter sweep analysis

### honggfuzzcd: structurally ineffective
The sweep covered W=3–10 and C=2–8. All reps with resets fired showed negative Δbugs
(-11, -6, -11, -7, -3). The one positive rep (+2, W=3, C=3) fired **0 resets** — the drift
detector never triggered, so the result is pure variance, not a CD effect. More resets
consistently means more harm: rep 5 (W=10, 67 resets) had -3; rep 0 (W=5, 30 resets) had -11.
Conclusion: the corpus-reset strategy does not benefit honggfuzz in a 4h campaign.
Hypothesis: honggfuzz's internal corpus management already handles stagnation adequately;
forced resets discard coverage that honggfuzz would have exploited over time.

### aflpluspluscd: SOFT_RESET mode is the key variable
All SOFT_RESET=1 reps (det+havoc) were ≥ 0: +0, +2, +6, +11.
Both SOFT_RESET=2 reps (havoc-only) were ≤ 0: 0, -12.
With SR=2, AFL++'s deterministic stage (`passed_det=1`) is never re-run post-reset,
so AFL++ cannot fully re-explore the new corpus direction. SR=1 clears `passed_det` on
favored entries, enabling bit-flips and arithmetic to exploit post-reset coverage gains.
Best result: Rep 5 (SR=1, C=10, CL=25): **+11 bugs**, 9 resets. Conservative trigger
(C=10) avoids premature resets while still catching sustained stagnation.

### Auto-verdict script was wrong
The followup script counted "positive Δbugs" by checking the aggregate summary table,
which summed all 6 reps as one pool. Per-rep analysis (the correct method) shows 3/6
aflpluspluscd reps are positive. Verdict script needs to be updated to analyze each
rep's ar/ subdirectory separately.

### Next steps
- **aflpluspluscd**: confirm Rep 5 config (SR=1, C=10, CL=25) in a proper multi-rep
  experiment (dist8) with more reps (≥6) and possibly longer runtime.
- **honggfuzzcd**: deprioritize or drop from paper as primary contribution; can be
  noted as "CD resets hurt honggfuzz" (negative result still publishable).
- **afl/fairfuzz pairs**: still consistently positive across dist5/dist6 — no need
  to re-run unless reviewers ask for more reps.

---

## 2026-06-20: dist7 design — paired-seed 6-rep parameter sweep

### Motivation
dist6 showed positive results for afl (+2) and fairfuzz (+1) but honggfuzzcd data was
lost (NFS quota) and aflpluspluscd remained negative (-3 for 5th time). Two questions:
1. What is honggfuzz's actual Δ with the UaF fix and reset enabled?
2. Which CD parameter configuration gives the best Δ for each fuzzer?

### Paired-seed design
Previous experiments had no seed control: honggfuzz_N and honggfuzzcd_N started with
different PRNG states, so differences could be variance rather than CD effect. With
`FUZZER_SEED=1000+N` for both baseline and CD variant in the same rep, the only variable
is whether CD is active (and which parameter config). This reduces noise substantially.

### Parameter sweep rationale
**honggfuzzcd**: The key question is detection sensitivity. Too conservative (large C) →
  few resets, CD effect minimal. Too aggressive (small C) → frequent resets disrupt the
  corpus before the fuzzer has exploited it. Sweep covers C=2–8 and W=3–10.

**aflpluspluscd**: The key question is reset mode. SOFT_RESET=2 (havoc-only) keeps
  `passed_det=1` so AFL++'s deterministic stages never re-run post-reset. SOFT_RESET=1
  (det+havoc) clears `passed_det` on favored entries, re-running bit-flips/arithmetic.
  Hypothesis: SOFT_RESET=1 should allow AFL++ to exploit post-reset coverage better.
  Secondary: CONSECUTIVE sweep (C=6–10) to find the right trigger threshold.

### NFS rsync fixes
Root cause of dist6 honggfuzzcd data loss: `*.honggfuzz.cov` corpus files (2000+ per
honggfuzz run × 4KB block allocation × 9 programs × 6 reps × NFS latency = GBs of
small-file overhead). Fix: `--exclude '*.honggfuzz.cov'` in rsync. Also: rsync errors
no longer silently discarded, `copied` counter now only increments on success, pre-launch
free-space check warns if <10GB available.

---

## 2026-06-19: dist6 proposed changes — honggfuzz UaF fix + rep2 param sweep

### honggfuzzcd: proper UaF fix (zombie approach)

**Problem**: dist5 disabled corpus reset entirely (monitoring-only) as a workaround. This means
honggfuzzcd ≈ honggfuzz (Δ ≈ 0), wasting the 3rd rep. We want to actually fix the UaF and
re-enable the reset so honggfuzzcd can benefit from drift-triggered corpus refresh.

**Root cause revisited**: The crash site was `input_setSize():51 Too large size`. Tracing the
call stack in `input.c`:
```c
// input_prepareDynamicInput():
for (;;) {
    MX_SCOPED_RWLOCK_WRITE(&run->global->mutex.dynfileq);
    run->current = run->global->io.dynfileqCurrent;
    ...
    break;
}  // ← lock released HERE by 'defer' cleanup attribute

input_setSize(run, run->current->size);     // ← UaF: entry may be freed
memcpy(run->dynfile->data, run->current->data, run->current->size);  // ← UaF
```
Worker threads store `run->current` (a raw `dynfile_t*`) outside the lock scope. When the
main thread's `drift_perform_corpus_reset()` frees entries under the write lock, worker
threads that already hold the pointer dereference freed memory.

**Fix**: Zombie approach in `drift_perform_corpus_reset()` — never free entries.
Instead: `TAILQ_REMOVE` (removes from active corpus) + `entry->size = 0` (marks as expired).
- Worker threads that hold a stale pointer see `size=0` → `input_setSize(run, 0)` → safe
- `memcpy(..., entry->data, 0)` copies 0 bytes → safe (data pointer still valid)
- Memory leak: each removed entry ≈ few KB; 1–5 resets per campaign → negligible

**Why not fix input.c instead?** Moving the `input_setSize`/`memcpy` block inside the
lock scope would require restructuring the `for(;;)` break paths (3 exit points, one reuses
the previous `run->current`). The zombie approach is a 3-line change vs a complex refactor.

**Code change**: `drift-detect.c` in `drift_perform_corpus_reset()`, commit a0d951f8.
**Re-enable**: Remove `drift_det->reset_on_drift = false` override from `honggfuzz.c`.

### Manifest redesign: 8 fuzzers × 3 reps

**Rationale**: moptafl and aflfast/aflfastcd show the clearest single-run variance (+6/+5/-3
for moptaflcd, +5/+5/+1 for aflfastcd from a stable 27). More reps for the remaining 8
fuzzers give better statistical confidence. The 3rd rep also serves as a parameter sweep.

**Rep 2 AFL SOFT_RESET sweep**:

`AFL_DRIFT_SOFT_RESET` is NOT a global setting — it only affects behavior when drift fires.
Mode 2 (current) = havoc-only after reset: `passed_det` stays `1` on most entries → no
re-run of deterministic stages. Mode 1 = det+havoc: clears `passed_det` on favored entries
→ they re-run bit-flips/arithmetic/havoc with post-reset coverage knowledge.

For FairFuzz specifically: mode 2 prevents re-running rare-branch-guided deterministic
mutations after reset (FairFuzz's core advantage). Mode 1 should allow the rare-branch
targeting to fire again.

Hypothesis: switching to SOFT_RESET=1 will make aflcd/aflpluspluscd/fairfuzzcd Δ positive.

| Fuzzer | Rep 0&1 config | Rep 2 sweep | Hypothesis |
|---|---|---|---|
| aflcd | SOFT_RESET=2, BOOST=2 | SOFT_RESET=1, BOOST=1 | Det re-run post-reset → better coverage recovery |
| aflpluspluscd | SOFT_RESET=2, C=8 | SOFT_RESET=1, C=6 | Faster drift response + det stages |
| fairfuzzcd | SOFT_RESET=2 | SOFT_RESET=1, BOOST=1 | Re-run rare-branch det mutations post-reset |
| honggfuzzcd | WINDOW=5, CONSEC=5 | WINDOW=3, CONSEC=3 | Tighter monitoring sensitivity |

---

## 2026-06-20: dist6 outcomes

### Results (8 fuzzers × 3 reps, 8h each)
| Pair | Δbugs | Δcov% | Resets | Verdict |
|---|---|---|---|---|
| afl → aflcd | **+2** | -0.2% | 6 | ✅ 2nd positive run |
| fairfuzz → fairfuzzcd | **+1** | -1.4% | 0 | ✅ Improved from -3 in dist5 |
| aflplusplus → aflpluspluscd | **-3** | +0.5% | 10 | ❌ Still negative |
| honggfuzz → honggfuzzcd | **INVALID** | **INVALID** | 5 | ⚠ Data loss — see below |

### Rep2 SOFT_RESET=1 sweep interpretation
- **aflcd**: Rep 2 SOFT_RESET=1 results are in the +2 aggregate. The total is positive, suggesting
  the sweep didn't hurt and may have helped.
- **fairfuzzcd**: Overall +1 (improved from -3). SOFT_RESET=1 in rep2 is a likely contributor —
  re-running rare-branch deterministic mutations post-reset aligns with FairFuzz's design.
- **aflpluspluscd**: Still -3 even with SOFT_RESET=1 rep2 included. The CD interference with AFL++
  strategies (e.g., CMPLOG, MOpt scheduling) may be fundamental, not a reset-mode issue.

### NFS disk quota data loss — honggfuzzcd invalid
The NFS `/proj/cdfuzzing-PG0` was at 100% capacity when the 3 honggfuzzcd workers tried to
rsync their results (~06:52 CDT June 20). The `rsync` command uses `2>/dev/null`, so quota
errors were silently swallowed. Only the first 5 of 21 programs (libpng, libsndfile, libtiff×2,
libxml2×1 from rep1 only) made it to NFS. The honggfuzzcd -23 bugs / -89.7% coverage result
is an artifact of missing data, NOT a real measurement.

Also partially affected (minor):
- afl rep2, aflplusplus rep2, honggfuzz rep2, aflpluspluscd rep2 (all had quota errors on .done)
  These reps likely had most results saved (they finished earlier and had more NFS headroom).

**Root cause of NFS full**: honggfuzz and dist5/dist6 accumulate `*.honggfuzz.cov` corpus files
in the output directory (not in `corpus/` so not excluded by rsync). Each file is ~500 bytes
but allocates a full 4KB block; 2000+ files per run × many programs × many dists = GBs of
small-file overhead. Compounded by AFL crash files from `findings/crashes/`.

**Fix needed before dist7**:
1. Add `--exclude '*.honggfuzz.cov'` (or `--exclude 'output/'` for honggfuzz) to the rsync in
   `worker-run.sh` — honggfuzz corpus files are seeds, not findings; not needed for analysis.
2. Add NFS space pre-check before captain launch (warn/abort if <10GB free).
3. Consider deleting dist4 ar/ to reclaim space (dist4 has only partial honggfuzzcd data anyway).

---

## 2026-06-19: dist5 proposed change — honggfuzzcd monitoring-only (no reset)

**Problem**: dist4 selective reset crashed with use-after-free in every program that had a reset.

**Root cause**: `drift_perform_corpus_reset()` frees dynfile_t entries while worker threads
hold raw pointers to those entries outside the dynfileq lock scope. honggfuzz's input model:
1. Worker thread acquires read lock, picks `df = dynfileqCurrent`, advances pointer, releases lock.
2. Worker thread USES `df->data` and `df->size` OUTSIDE the lock.
3. Main thread acquires write lock in reset, removes + frees entries including the in-use `df`.
4. Worker thread reads freed `df->size` → garbage → `input_setSize(): Too large size`.

This is unfixable without either (a) adding reference counting to dynfile_t (invasive change to
honggfuzz core), or (b) using deferred free (complex). The write lock does NOT protect threads
that already hold raw pointers.

**Fix for dist5**: Set `drift_det->reset_on_drift = false` after initialization in honggfuzz.c.
Corpus reset is disabled; drift detection runs as monitoring-only.

**Expected outcome**: honggfuzzcd ≈ honggfuzz baseline (0 Δbugs, 0% Δcov). If this holds,
the conclusion for the paper is: "CD framework is not applicable to honggfuzz's multi-threaded
corpus model without significant refactoring; the other 5 fuzzers show a range of effects."

**Code change**: 3 lines in honggfuzz.c, commit ac9eec7f.

---

## 2026-06-19: dist4 results analysis — selective reset use-after-free

### honggfuzzcd: UaF crash in selective reset

Evidence from container log (`honggfuzzcd_libsndfile_sndfile_fuzzer_0_container.log`):
```
Selective corpus reset: keeping 124 seeds + 30 most-recent entries
Corpus reset: kept 154 entries (124 seeds + 30 recent), removed 1788
[F][2959] input_setSize():51 Too large size requested: 140337996787424 > maxSize: 163840
Campaign terminated at 2026-06-19 08:45
```
Every program that triggered a reset had its container terminate at minute 1.
Programs with 0 resets (e.g., openssl/client: +27.7% cov) ran correctly for 8h.

Even when not crashing (programs with 0 resets), the pattern holds: coverage is fine.
The crash itself meant 19/21 honggfuzzcd programs only ran for ~1 minute, making
all dist4 honggfuzzcd results invalid.

### AFL fuzzers: variance analysis across 3 experiments

| Pair | dist2 Δ | dist3 Δ | dist4 Δ | Assessment |
|---|---|---|---|---|
| afl → aflcd | -1 | -1 | 0 | Consistent neutral |
| aflfast → aflfastcd | +5 | +5 | +1 | aflfastcd found 27 bugs in ALL runs; baseline varied |
| aflplusplus → aflpluspluscd | -2 | -2 | +2 | Noisy; likely neutral |
| fairfuzz → fairfuzzcd | -3 | -3 | -6 | Consistently negative — investigate |
| moptafl → moptaflcd | +6 | +5 | -3 | CD count varied (45/44/39); base was stable |

**aflfastcd is the most robust winner**: CD variant found 27 bugs in every single experiment
while the baseline varied from 22→22→26. The delta shrinkage in dist4 is pure baseline luck.

**moptaflcd needs more data**: 3 experiments with Δ = +6/+5/-3. The 95% CI spans both
positive and negative. Need ≥5 experiments for statistical confidence.

**fairfuzzcd systematic negative effect**: 3 experiments all negative (-3/-3/-6) with stable
baseline. Possible cause: `AFL_DRIFT_SOFT_RESET=2` env var may disable AFL's deterministic
stages (bitflip, arithmetic) that FairFuzz relies on for rare-branch targeting. Investigate
whether AFL_DRIFT_SOFT_RESET affects mutation strategy even without a reset firing.

---

## 2026-06-19: dist4 proposed changes — selective reset for honggfuzzcd

### Problem

honggfuzzcd dist3: cascade fixed (761→25 resets) but -56.7% coverage / -11 bugs.
Even 1 hard corpus reset causes 60-85% coverage loss in honggfuzz:

| Program | Δcov% | Resets |
|---|---|---|
| libsndfile | -87.6% | 1 |
| lua | -84.8% | 1 |
| libxml2/xmllint | -76.8% | 1 |
| php/parser | -72.9% | 1 |
| poppler/pdf_fuzzer | -69.1% | 2 |
| poppler/pdfimages | -60.3% | 2 |
| sqlite3 | -62.0% | 1 |
| libxml2/libxml2_xml | -45.8% | 1 |

Programs with 0 resets show near-zero coverage change (control confirms causality).

**Root cause**: honggfuzz's hard reset in `drift_perform_corpus_reset()` reverts the corpus
to the first `initial_corpus_count` files (the original 5 seeds). honggfuzz rebuilds from
seeds slowly because it lacks AFL's deterministic stages (bit/byte flips) and uses
hardware-based coverage feedback that requires many executions to rediscover edges.
Mid-campaign resets at minute 200+ leave insufficient time for full corpus recovery.

### Proposed fix: selective reset in honggfuzz.c

Instead of keeping only the first N seed files, keep the **K most recently added** entries
plus the **original N seeds**, discarding the "middle aged" entries which are superseded by
newer, more refined inputs.

**Implementation in `honggfuzzcd/newsrc/honggfuzz.c`** (not drift-detect.c — keep it
generic; implement in the honggfuzz-specific wrapper):

```c
// After detecting drift, instead of calling drift_perform_corpus_reset(),
// call a new honggfuzz_selective_reset():
static void honggfuzz_selective_reset(honggfuzz_t* hfuzz, struct drift_detector* dd) {
    /* Count queue */
    size_t total = 0;
    struct dynfile* df;
    TAILQ_FOREACH(df, &hfuzz->io.dynfileq, TAILQ_ENTRY_FIELD) { total++; }

    size_t keep_recent = 30;  /* keep 30 most-recently-added entries */
    size_t keep_seeds  = dd->initial_corpus_count;  /* keep original seeds */
    size_t discard_from = keep_seeds;
    size_t discard_to   = (total > keep_seeds + keep_recent)
                          ? total - keep_recent : keep_seeds;

    /* Walk the queue; entries in [keep_seeds, discard_to) are the "middle aged" ones */
    size_t idx = 0;
    TAILQ_FOREACH_SAFE(df, &hfuzz->io.dynfileq, TAILQ_ENTRY_FIELD, tmp) {
        if (idx >= discard_from && idx < discard_to) {
            TAILQ_REMOVE(&hfuzz->io.dynfileq, df, TAILQ_ENTRY_FIELD);
            unlink(df->path);
            free(df->path);
            free(df);
        }
        idx++;
    }
    /* Reset peak state so next epoch starts fresh */
    honggfuzz_peak_corpus = 0;
    dd->initial_corpus_count = 0;
    dd->history_len = 0;
}
```

**Why keep-recent rather than keep-highest-coverage**: honggfuzz does not store per-entry
edge counts in dynfile_t; sorting by coverage would require a full bitmap comparison for
each entry, which is expensive. The most-recently-added entries are a good proxy for
highest-coverage because honggfuzz only adds an entry when it finds a new edge.

### Parameters for dist4

No parameter changes from dist3 — the selective reset code change is the only variable.

| CD Fuzzer      | C    | SF   | COOLDOWN | WINDOW | Change |
|---|---|---|---|---|---|
| honggfuzzcd    | 5    | 0.5  | 10       | 5      | **Code: selective reset** |
| fairfuzzcd     | 15   | 0.5  | 10       | 100    | Unchanged |
| aflcd          | 5    | 0.5  | 25       | 100    | Unchanged |
| aflpluspluscd  | 8    | 0.5  | 25       | 100    | Unchanged |
| moptaflcd      | 5    | 0.3  | 10       | 100    | Unchanged |
| aflfastcd      | 3    | 0.5  | 10       | 100    | Unchanged |

**Expected outcome**: honggfuzzcd moves from -11 bugs/-56.7% cov toward ~0 bugs/~0% cov,
since corpus recovery after a selective reset (keeping seeds + 30 recent) should be
dramatically faster than recovery from 5 seeds alone.

---

## 2026-06-19: dist3 results analysis — hard reset root cause confirmed

### Summary

dist3 completed 2026-06-19 01:07 CDT. Time-gate fix worked; new root cause identified.

| Pair | Δbugs | Δcov% | Resets | dist2 resets | Conclusion |
|---|---|---|---|---|---|
| moptafl → moptaflcd | **+5** | +1.7% | 23 | 33 | ✅ Consistent 2nd time |
| aflfast → aflfastcd | **+5** | -3.4% | 3 | 5 | ✅ Consistent 2nd time |
| aflplusplus → aflpluspluscd | -2 | **+5.1%** | 13 | 14 | ⚠ Coverage gain but -2 bugs; likely variance |
| afl → aflcd | -1 | -1.5% | 5 | 8 | ⚠ Noise-level; 2 reps insufficient |
| fairfuzz → fairfuzzcd | -3 | -0.7% | 1 | 3 | ❌ C=15 reduced resets (3→1), -3 probably noise |
| honggfuzz → honggfuzzcd | **-11** | **-56.7%** | **25** | 761 | ❌ Cascade fixed, hard reset too destructive |

### honggfuzzcd: dist3 fix worked exactly; new root cause = hard reset architecture

**Fix outcome**: peak_corpus metric + 60s time-gate cut resets from 761 to 25 (-97%) and
drifts from 7036 to 93. This is exactly the intended effect. The cascade loop is eliminated.

**New failure mode**: Hard corpus reset is incompatible with honggfuzz's corpus rebuilding
speed. When a reset fires at minute 200+ of an 8h run, honggfuzz only has ~280 minutes
remaining to recover a corpus it took 200+ minutes to build. With AFL, deterministic stages
(bitflip, arithm) rapidly recover coverage after a reset. With honggfuzz, recovery depends
entirely on random mutations finding the same edges, which takes much longer.

Evidence: 8 of 9 programs had ≥1 reset; all show 45-88% coverage loss proportional to reset
count and timing. The 1 program with 0 resets (libpng) showed +0.2% coverage change.

### fairfuzzcd: signal-to-noise too low at current rep count

dist2: -2 bugs. dist3: -3 bugs. With only 2 reps × 9 targets × 2-3 programs = ~36-54
observations per pair, the variance across targets can easily account for ±2 bug difference.
FairFuzz has known target-specific performance (rare-branch discovery depends heavily on
input structure). C=15 achieved its goal (3→1 resets), but the bug delta remains noisy.
Need 3+ reps to separate signal from noise for fairfuzzcd.

### aflpluspluscd: coverage gain does not translate to bugs

dist3: -2 bugs but +5.1% coverage. AFL++'s internal adaptive mechanisms (cmp analysis,
laf-intel, CMPLOG) already handle local optima exploration. The CD resets provide some
coverage benefit but may disrupt AFL++'s in-progress cmp-coverage state. Result: positive
coverage metric but negative bug count. With 2 reps this is inconclusive — could be variance.

---

## 2026-06-18: dist3 proposed CD parameters

Following the dist2 root-cause analysis, proposed parameter changes for dist3:

| CD Fuzzer      | C (dist2) | C (dist3) | SF   | COOLDOWN (dist2) | COOLDOWN (dist3) | Code change? |
|---|---|---|---|---|---|---|
| honggfuzzcd    | 5         | 5         | 0.5  | 10               | 10               | **YES** (peak_corpus metric) |
| fairfuzzcd     | 3         | **15**    | 0.5  | 10               | 10               | No |
| aflcd          | 5         | 5         | 0.5  | 10               | **25**           | No |
| aflpluspluscd  | 8         | 8         | 0.5  | 10               | **25**           | No |
| moptaflcd      | 5         | 5         | 0.3  | 10               | 10               | No |
| aflfastcd      | 3         | 3         | 0.5  | 10               | 10               | No |

**honggfuzzcd code fix (honggfuzz.c):**
Replace raw corpus count with monotone peak metric in `driftCycle()`:
```c
// Before: uses corpus (current output/ file count, non-monotonic)
// After:
static size_t peak_corpus = 0;
if (corpus > peak_corpus) peak_corpus = corpus;
// Then use peak_corpus in place of corpus for the stagnation threshold comparison
```
This makes the coverage signal monotonically non-decreasing, exactly like AFL's `queued_paths`.
corpus minimization (which shrinks output/) no longer registers as stagnation.

**fairfuzzcd C=3→15:**
Each "window" for fairfuzz is ~1 minute of real time. With C=3, a reset fires after 3 minutes
of stagnation, which is too early — FairFuzz's rare-branch re-discovery after a reset takes
10-30 minutes. C=15 requires 15 consecutive stagnant windows (~15 minutes), ensuring resets
only fire after genuine long-term plateau. Expected outcome: 0-1 resets per campaign vs 3 in dist2.

**COOLDOWN 10→25 for afl/aflplusplus:**
With COOLDOWN=10 and C=3-5, programs like php/json and php/unserialize accumulated 3 resets
each. After each reset the fuzzer rebuilds to the same plateau and fires again 10 windows later.
COOLDOWN=25 spaces resets by 25 windows (~25 minutes), giving each reset time to produce
genuine new coverage before the next stagnation check activates.

Consequences:
- These parameters are educated guesses based on 2 experiments; statistical confidence requires
  3+ repetitions per config.
- The honggfuzzcd code change may reveal new issues (e.g., if the stagnation threshold now fires
  too rarely — if peak_corpus never truly stagnates, 0 resets will fire, similar to seed_4 fairfuzz).
  Add a sanity check: log when peak_corpus changes vs when it stays flat.
- If dist3 honggfuzzcd still shows 0 resets, need to lower SF or C for honggfuzz specifically.

---

## 2026-06-18: dist2 results analysis — root causes of good and bad outcomes

### honggfuzzcd: CASCADE LOOP — 761 resets, -16 bugs, -62.6% cov

**Primary root cause: Non-monotonic coverage metric (corpus minimization)**
honggfuzz continuously minimizes its corpus: old inputs are replaced by shorter/more-efficient
ones, causing output/ file count to shrink during minimization bursts. The CD module uses
`queued_paths` = output/ file count as the coverage signal. Unlike AFL's `queued_paths` (strictly
non-decreasing), honggfuzz's count fluctuates (log evidence: 305→265→273→269→254 in first 5
minutes of xmllint run). The EMA-based stagnation detector cannot distinguish minimization-caused
shrinkage from genuine stagnation.

**Secondary cause: Window/threshold mismatch with honggfuzz's execution rate**
honggfuzz runs at ~2M exec/min (log: 2,050,044 iterations in first minute). At WINDOW=100
iterations, each measurement window is ~3ms. Real coverage growth over a 3ms window is <<5%.
The 5% threshold (THRESHOLD=0.05) is calibrated for AFL queue cycles (~minutes each), not
honggfuzz iteration batches (~milliseconds). Result: nearly every window registers as stagnation.

**Evidence:**
- 7036 drifts across 21 programs (335/program avg) vs 1129 for moptaflcd (54/program)
- resets_per_24h = 36.24 (moptaflcd = 1.57; aflfastcd = 0.24)
- 14/21 programs had 6+ resets; only 3 had 0 resets
- xmllint drift log: consecutive_drifts=0 at every minute-log entry (resets fired and cleared counter
  within each 1-minute reporting window)
- Final output/ file count: honggfuzz 1918 files / honggfuzzcd 956 files for libpng (reset
  happened close to end of campaign, dumping accumulated corpus)

**Conclusion:** The CD module is fundamentally mis-calibrated for honggfuzz. corpus resets
destroyed all accumulated coverage: baseline honggfuzz = 130,014 total coverage units,
honggfuzzcd = 48,686 (62.6% loss).

---

### fairfuzzcd: DESTRUCTIVE RESET — -2 bugs, -8.1% cov, 3 resets

**Root cause: FairFuzz rare-branch state cannot survive corpus reset**
FairFuzz builds up `hit_bits[]` (per-branch hit counts) and `blacklist[]` (unreachable branches)
over hours of fuzzing. These guide its rare-branch targeting — the core of FairFuzz's value.
After a corpus reset to original seeds, the `hit_bits` and blacklist were cleared (our fix from
dist2), but the SEEDS don't cover the rare branches that FairFuzz had identified. FairFuzz needs
10-30 minutes to re-discover which branches are rare and begin effective targeting again.

**Evidence:**
- libpng/libpng_read_fuzzer: 1 reset → coverage 1072 → 44 (-95.9%). The single reset erased
  all queue progress; fairfuzzcd recovered only 44/1072 paths in the remaining 7h.
- php/exif: fairfuzz triggers PHP009+PHP004+PHP011 (3 bugs); fairfuzzcd triggers only PHP011
  (1 bug) — the two rarer bugs lost after rare-branch state disruption.
- Total -2 bugs despite the -q 1 bootstrap fix making blacklist-trap much less likely.

**Conclusion:** With C=3, a reset fires after just 3 minutes of stagnation, far too early for
FairFuzz's recovery time. The rare-branch re-discovery overhead means short resets are net-negative.
The `-q 1` fix solved the blacklist-trap but didn't solve the fundamental state-recovery problem.

---

### aflcd: CASCADING RESETS — -1 bug, -2.8% cov, 8 resets

**Root cause: COOLDOWN=10 insufficient to prevent multi-reset cascade on same program**
php/json: 3 resets; php/unserialize: 3 resets; libpng: 2 resets. Pattern: reset fires,
COOLDOWN=10 windows expire, fuzzer reaches same plateau as before, another reset fires.
This is expected behavior but suboptimal: AFL needs 10-20 minutes per reset to re-build
useful coverage; COOLDOWN=10 windows is too short to determine whether a reset helped.

**Evidence:**
- 3 programs with 3+ resets (php/json: 3, php/unserialize: 3, libpng: 2) out of 21
- The -1 bug (sqlite3: afl triggers SQL002, aflcd triggers 0 bugs) is likely variance —
  aflcd had 0 resets on sqlite3, so resets are not the cause; single-rep variance is.

**Conclusion:** Mild parameter issue. COOLDOWN=25 should reduce cascade frequency.

---

### What makes moptaflcd and aflfastcd work

**moptaflcd (+6 bugs, 33 resets, C=5/SF=0.3):**
MOpt-AFL uses Particle Swarm Optimization to select mutation operators. The PSO converges to
a local optimum where a subset of operators dominate — effective for current seeds but missing
code regions reachable only via different mutation strategies. A corpus reset forces PSO to
restart from diverse seeds, effectively re-exploring the operator selection space.
- SF=0.3: corpus only needs 30% growth before reset is considered (lower bar). moptafl's PSO
  finds paths quickly, so genuine stagnation sets in at 30% growth just as effectively as 50%.
- C=5: 5 windows of stagnation needed → well-calibrated for moptafl's fast initial exploration.
- 33 resets spread across 16/21 programs (5 with 0, 11 with 1-2, 5 with 3-5): no cascade.
- New bugs found: TIF002, TIF008 (libtiff), PDF008 (poppler/pdfimages), SQL012+SQL020 (sqlite3)
  — these are unique bugs not in the moptafl baseline.

**aflfastcd (+5 bugs, 5 resets, C=3/SF=0.5):**
AFLFast's exponential power schedule can over-prioritize a narrow set of low-fuzz-count paths,
neglecting harder-to-reach code. 5 well-placed resets (each on a different program) reset the
power schedule, allowing the exponential distribution to re-explore from a different starting point.
Very low reset rate (5 total in 8h across 21 programs) means each reset is high-signal and the
fuzzer spends >99% of time fuzzing, not recovering.
- New bugs found: XML009 (libxml2), SSL020 (openssl/server), SQL018 (sqlite3) — all from resets
  that fired on programs where AFLFast's schedule was genuinely stuck.

---

## 2026-06-18: dist2 winning parameters (carried to dist3 unchanged)

moptaflcd C=5/SF=0.3 and aflfastcd C=3/SF=0.5 produced strong results in dist2.
These are carried forward unchanged to dist3. See dist3 parameter table above.

---

## 2026-06-17: Exclude aflfast pair from main results table

Decision:
The aflfast→aflfastcd pair is excluded from the four-pair main result summary because aflfastcd is
missing openssl (6 programs) and php (4 programs) — 10 of 21 programs never ran.
The partial pair shows -47.9% coverage which is an artifact of the missing programs having 0
coverage, not a real regression.

Reason:
Including partial data in aggregate totals gives misleading grand total numbers.
The 4 complete pairs (aflplusplus, fairfuzz, moptafl, afl) are the basis for conclusions.

Alternatives considered:
- Imputing missing programs with baseline values: would require a defensible imputation method;
  avoided to prevent introducing bias.
- Re-running aflfastcd for openssl+php only: `captainrc_rerun_b3` was created for this purpose
  but not used because disk space was marginal (30GB free after honggfuzz failure) and the
  session had already been running for days.

Consequences:
`summary_table.txt` still includes aflfast pair for completeness but with a note.
Grand total in `summary_table.txt` is -5 bugs / -4.5% coverage — this is misleading and should
not be cited without noting the partial aflfastcd data.

---

## 2026-06-17: Do not run honggfuzz in seed_4

Decision:
honggfuzz and honggfuzzcd were not run in seed_4 due to disk space exhaustion during Docker builds.

Reason:
63GB node disk was 81% full (≈ 48GB used) when batch 3 started. honggfuzz preinstall.sh failed
with exit code 100. After freeing 20GB, the decision was made to stop rather than restart because
disk would fill again during the runs (queue/ dirs accumulate at ~1GB/fuzzer/target/day).

Alternatives considered:
- Running honggfuzz on a larger node: valid option for a future seed.
- Pruning queue/ before running honggfuzz: would require interrupting the running aflfastcd batch.

Consequences:
honggfuzz pair is absent from seed_4. A future seed should either use a ≥100GB node or
explicitly prune queue/ dirs after each batch to stay under disk limit.

---

## 2026-06-15: Use NO_ARCHIVE=1 for all batches

Decision:
All captainrc files set `NO_ARCHIVE=1`. Results are stored as raw workdirs under
`~/experiment_results/seed_4/ar/{fuzzer}/{target}/{program}/0/` rather than being tar'd.

Reason:
Archiving adds significant I/O time at the end of a 24h campaign and requires extra disk for the
intermediate archive. Analysis scripts (`plot_seed4.py`) read raw workdirs directly.

Alternatives considered:
- Archiving with ARCHIVE=1: would save disk long-term by compressing queue/, but requires more
  I/O during the campaign end and a different analysis path.

Consequences:
queue/ directories accumulate and consume ~8GB across all runs. If disk is tight, prune queue/
before starting the next batch:
  `find ~/experiment_results/seed_4/ar -type d -name queue -exec rm -rf {} + 2>/dev/null`

---

## 2026-06-13: Coverage metric is queued_paths, not bitmap edge count

Decision:
`plot_seed4.py` reads the `corpus_size` field from `fuzzer_stats`, which corresponds to
`queued_paths` in AFL terminology (number of corpus entries), not bitmap edge coverage.

Reason:
`queued_paths` is present in all AFL-family fuzzer_stats files and is trivially parseable.
Bitmap edge coverage requires either `bitmap_cvg` (a percentage) or running `afl-showmap` on the
entire queue, which is significantly more expensive.

Alternatives considered:
- Using `bitmap_cvg` from fuzzer_stats: this is a percentage (e.g. "7.23%") not an absolute
  count, making cross-fuzzer comparison harder.
- Using `afl-showmap`: accurate but requires re-running instrumented binary on each corpus file;
  too expensive for post-hoc analysis.

Consequences:
Coverage delta numbers in `summary_table.txt` and `parameter_eval.txt` reflect corpus growth, not
edge coverage. The +367% mean delta in the "0 resets" bucket in the parameter eval is dominated
by programs where CD kept the corpus growing longer — not raw edge coverage.
This must be clearly stated in the paper.

---

## 2026-06-12: Fix AFL++CD alias table and splice loop bugs before seed_4

Decision:
Three bugs in the AFL++CD implementation were fixed before seed_4 runs. Fixes are applied via
`sed` in `cdfuzzing/magma/fuzzers/aflpluspluscd/fetch.sh` and `newsrc/` patch files.

Bugs fixed:
1. Alias table not populated on soft reset — caused crash/infinite loop after first reset
2. `top_rated[]` not cleared on soft reset — caused stale entries after corpus wipe
3. Splice loop `->disabled` check missing — caused use-after-free when splicing with cleared corpus

Reason:
These bugs caused AFL++CD to crash or produce corrupted results in earlier seeds (seeds 1–3).
seed_4 is the first seed where AFL++CD is considered correct.

Consequences:
Do not compare seed_4 AFL++CD results to seeds 1–3 for AFL++. Seeds 1–3 AFL++ data is invalid.
The `newsrc/` directory in `fuzzers/aflpluspluscd/` contains the patched source overrides.

---

## 2026-06-10: seed=4 chosen as baseline for first complete evaluation

Decision:
`seed=4` was used for the first complete single-seed evaluation. Seeds 1–3 were invalidated by
the AFL++CD alias table bug. Seed 5 and beyond are reserved for multi-seed validation.

Reason:
Needed a clean seed not contaminated by the AFL++CD bug to produce trustworthy results.

Consequences:
seed_4 results are preliminary (single seed, no confidence intervals).
Paper claims must be framed as "preliminary evaluation" until multi-seed results are available.

---

## 2026-06: CD parameters for seed_4

Decision:
```
AFL_DRIFT_WINDOW=100
AFL_DRIFT_THRESHOLD=0.05
AFL_DRIFT_CONSECUTIVE=5
AFL_DRIFT_STAGNATION_FACTOR=0.5
AFL_DRIFT_COOLDOWN=10
AFL_DRIFT_EMA_ALPHA=0.1
AFL_DRIFT_SOFT_RESET=2
AFL_DRIFT_MAX_RESETS=0   (unlimited)
AFL_DRIFT_HAVOC_BOOST=2
AFL_DRIFT_BOOST_CYCLES=1
```

These are the same parameters as seeds 1–3 to allow future cross-seed comparison once bugs are fixed.

Reason:
Keeping parameters stable across seeds isolates the effect of the bug fix.

Consequences:
The parameter eval (see `parameter_eval.txt`) shows `fairfuzzcd` never fires (CONSECUTIVE=5 too
high for fairfuzz's slow scheduling) and `moptaflcd` over-resets (3.62/program). dist1 tests
alternative parameters per the A/B design below.

---

## 2026-06-17: A/B per-rep parameter design for dist1

Decision:
`dist1` uses different `AFL_DRIFT_CONSECUTIVE` / `AFL_DRIFT_STAGNATION_FACTOR` values for
rep 0 vs rep 1 of each CD fuzzer, rather than running identical repetitions. This makes each
2-node CD pair a single-shot A/B comparison instead of a plain statistical repetition.

Rationale (from seed_4 `parameter_eval.txt`):
- `fairfuzzcd` (C=5): 0 resets fired (stagnation guard filtered 100% of 50 drifts — too conservative)
- `moptaflcd` (C=5): 3.62 resets/program (MOpt's mutation scheduling amplifies KS p-values)
- `aflpluspluscd` (C=5): 2.38 resets/program (moderately high)
- `aflcd` (C=5): 0.43 resets/program (reference — best-calibrated pair)

A/B parameter mapping for dist1:

| CD Fuzzer      | Rep 0 (Config A)       | Rep 1 (Config B)       | Goal                            |
|---|---|---|---|
| aflcd          | C=5, SF=0.5 (seed_4)   | C=3, SF=0.5            | reference vs more aggressive    |
| aflpluspluscd  | C=6, SF=0.5            | C=8, SF=0.5            | mild vs aggressive reduction    |
| fairfuzzcd     | C=3, SF=0.5            | C=2, SF=0.5            | both fix 0-reset (C=5 filtered 100%) |
| moptaflcd      | C=8, SF=0.5            | C=5, SF=0.3            | raise bar vs tighten stagnation guard |
| aflfastcd      | C=5, SF=0.5 (default)  | C=3, SF=0.5            | default vs more aggressive      |
| honggfuzzcd    | C=5, SF=0.5 (default)  | C=3, SF=0.5            | default vs more aggressive      |

Baseline fuzzers (afl, aflplusplus, fairfuzz, moptafl, aflfast, honggfuzz): both reps identical.
The CD environment variables are exported for baselines too (present but inactive — no CD module).

Implementation:
`cloudlab/worker-run.sh` has a `case "$FUZZER"` block that sets `CD_CONSECUTIVE` and
`CD_STAGNATION` before writing the captainrc. These are exported as
`AFL_DRIFT_CONSECUTIVE` and `AFL_DRIFT_STAGNATION_FACTOR` into the fuzzer container environment.

Consequences:
dist1 reps are NOT pure statistical repetitions for CD fuzzers — they test different parameter
regimes. A follow-up run (dist2) with fixed winning parameters on both reps is needed before
computing confidence intervals or statistical tests on CD-vs-baseline comparisons.
A single-seed result per config will be directional only; 3+ reps needed for significance.

---

## 2026-06-18: Fix FairFuzz blacklist trap

**Problem:**
In dist1, fairfuzzcd showed near-zero coverage on 3 targets: libpng (4 paths),
libtiff/tiff_read_rgba (21 paths), php/json (57 paths). These runs were not stuck
from CD resets (0 resets observed) — the CD module was a non-factor.

**Root cause:**
FairFuzz maintains a `blacklist[]` of branches it can't consistently reach. When
ALL rare branches hit by ALL queue entries are blacklisted, `is_rb_hit_mini()`
returns NULL for every input → `fuzz_one()` returns 1 (skip) → the fuzzer spins
through millions of queue cycles with 0 mutations. Affected run: libpng ran
21.7M queue cycles with only 5M executions (0.24 execs/cycle).

A recovery mechanism exists (checks `prev_cycle_wo_new && bootstrap` in fuzz_one)
that falls back to vanilla AFL mode. But it requires the `-q` flag to enable it
(`bootstrap` defaults to 0).

**Fix 1: Add `-q 1` to fairfuzz and fairfuzzcd run.sh**
When stuck for ≥1 cycle with no new finds, vanilla AFL scheduling is used for
each fuzz_one() call instead of branch targeting. FairFuzz mode resumes when a
new path is found. Applied to both fuzzers for a fair A/B comparison.

**Fix 2: Reset FairFuzz state in `perform_corpus_reset()` (fairfuzzcd only)**
After a CD reset, `hit_bits[]` retains counts from deleted entries, making
formerly rare branches appear "common". The blacklist also persists. After a
reset these stale counts would cause the blacklist to refill immediately. Fixed
by clearing `hit_bits[]`, `blacklist[]`, `rare_branch_exp`, and
`was_fuzzed`/`fuzzed_branches` on surviving entries.

**Commit:** `0a60bf3c`
