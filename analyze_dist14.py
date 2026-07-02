#!/usr/bin/env python3
"""
analyze_dist14.py — honggfuzzcd (KEEP_RECENT=50) vs honggfuzz (KEEP_RECENT=0)

dist14: 10 reps × 24h, all 9 Magma targets.
Compares:
  1. dist14 standalone   : dist14/ar/honggfuzzcd  vs dist14/ar/honggfuzz
  2. Paper baseline      : merged/ar/honggfuzzcd  vs merged/ar/honggfuzz (10 reps, Table 1)
  3. Combined (20 reps)  : merged + dist14 together for each fuzzer

Bug metric : union of triggered bug IDs across all available reps per program
             (monitor/ last snapshot; falls back to canaries.raw if monitor absent)
Coverage   : branch_coverage_percent × guard_nb / 100 from log/current Summary line
"""

import os, glob, re
from collections import defaultdict

DIST14_AR = "/proj/CDFuzzing/distributed/dist14/ar"
MERGED_AR = "/proj/CDFuzzing/distributed/merged/ar"

TARGETS = ["libpng", "libtiff", "libxml2", "openssl", "php", "poppler",
           "sqlite3", "lua", "libsndfile"]

TARGET_SHORT = {
    "libpng": "lpng", "libtiff": "ltif", "libxml2": "lxml",
    "openssl": "ssl",  "php": "php",     "poppler": "popl",
    "sqlite3": "sql",  "lua": "lua",     "libsndfile": "lsnd",
}

# ── Bug readers ───────────────────────────────────────────────────────────────

def read_bugs_monitor(ar, fuzzer, target, program):
    """Union of triggered bug IDs (last monitor snapshot per rep)."""
    union = set()
    found = False
    pattern = os.path.join(ar, fuzzer, target, program, "*", "monitor")
    for mon_dir in sorted(glob.glob(pattern)):
        if not os.path.isdir(mon_dir):
            continue
        try:
            timestamps = sorted([int(f) for f in os.listdir(mon_dir) if f.isdigit()])
        except Exception:
            continue
        if not timestamps:
            continue
        last_file = os.path.join(mon_dir, str(timestamps[-1]))
        try:
            with open(last_file) as f:
                header = f.readline().strip().split(',')
                values = f.readline().strip().split(',')
        except OSError:
            continue
        for i in range(0, len(header), 2):
            bug_id = header[i].replace('_R', '')
            try:
                triggered = int(values[i+1]) if i+1 < len(values) and values[i+1].strip() else 0
            except (ValueError, IndexError):
                triggered = 0
            if triggered > 0:
                union.add(bug_id)
        found = True
    return union if found else None


BUG_RE = re.compile(r'[A-Z]{3}[0-9]+[a-z]?')

def read_bugs_canaries(ar, fuzzer, target, program):
    """Fallback: union of bug IDs from canaries.raw across all rep dirs."""
    union = set()
    pattern = os.path.join(ar, fuzzer, target, program, "*", "canaries.raw")
    for path in glob.glob(pattern):
        try:
            with open(path, 'rb') as f:
                data = f.read().decode('latin-1', errors='replace')
            union |= set(BUG_RE.findall(data))
        except Exception:
            pass
    return union


def read_bugs(ar, fuzzer, target, program):
    result = read_bugs_monitor(ar, fuzzer, target, program)
    if result is not None:
        return result
    return read_bugs_canaries(ar, fuzzer, target, program)


def read_bugs_combined(ar_list, fuzzer, target, program):
    """Union bugs across multiple ar roots (for combined analysis)."""
    union = set()
    for ar in ar_list:
        union |= read_bugs(ar, fuzzer, target, program)
    return union


# ── Coverage readers ──────────────────────────────────────────────────────────

def read_hfuzz_edges_rep(ar, fuzzer, target, program, rep):
    path = os.path.join(ar, fuzzer, target, program, str(rep), "log", "current")
    if not os.path.isfile(path):
        return None
    try:
        with open(path) as f:
            for line in f:
                if "Summary" in line and "guard_nb" in line and "branch_coverage_percent" in line:
                    m_g = re.search(r'guard_nb:(\d+)', line)
                    m_p = re.search(r'branch_coverage_percent:(\d+)', line)
                    if m_g and m_p:
                        return int(m_g.group(1)) * int(m_p.group(1)) / 100.0
    except Exception:
        pass
    return None


def mean_cov(ar, fuzzer, target, program):
    """Mean edge coverage across all available reps."""
    vals = []
    pattern = os.path.join(ar, fuzzer, target, program, "*")
    reps = [os.path.basename(p) for p in glob.glob(pattern)
            if os.path.isdir(p) and os.path.basename(p).isdigit()]
    for rep in reps:
        v = read_hfuzz_edges_rep(ar, fuzzer, target, program, rep)
        if v is not None:
            vals.append(v)
    return sum(vals) / len(vals) if vals else None


def mean_cov_combined(ar_list, fuzzer, target, program):
    vals = []
    for ar in ar_list:
        pattern = os.path.join(ar, fuzzer, target, program, "*")
        reps = [os.path.basename(p) for p in glob.glob(pattern)
                if os.path.isdir(p) and os.path.basename(p).isdigit()]
        for rep in reps:
            v = read_hfuzz_edges_rep(ar, fuzzer, target, program, rep)
            if v is not None:
                vals.append(v)
    return sum(vals) / len(vals) if vals else None


# ── Program discovery ─────────────────────────────────────────────────────────

def find_programs(ar_list, fuzzer, target):
    """Union of program names across all ar roots."""
    progs = set()
    for ar in ar_list:
        pattern = os.path.join(ar, fuzzer, target, "*")
        for p in glob.glob(pattern):
            if os.path.isdir(p):
                progs.add(os.path.basename(p))
    return sorted(progs)


def count_reps(ar, fuzzer, target, program):
    pattern = os.path.join(ar, fuzzer, target, program, "*")
    return len([p for p in glob.glob(pattern)
                if os.path.isdir(p) and os.path.basename(p).isdigit()])


# ── Analysis ──────────────────────────────────────────────────────────────────

def analyze(label, cd_ar_list, base_ar_list, cd="honggfuzzcd", base="honggfuzz"):
    """Compute Δbugs and Δcov per target and print a summary table."""
    print(f"\n{'='*70}")
    print(f"  {label}")
    print(f"{'='*70}")
    print(f"  {'target':<10} {'lpng':>5} {'ltif':>5} {'lxml':>5} {'ssl':>5} "
          f"{'php':>5} {'popl':>5} {'sql':>5} {'lua':>5} {'lsnd':>5} {'TOTAL':>7}")
    print(f"  {'-'*75}")

    total_dbug = 0
    dcov_targets = []
    bug_row = {}
    cov_row = {}

    for target in TARGETS:
        programs = find_programs(cd_ar_list + base_ar_list, cd, target)
        if not programs:
            programs = find_programs(cd_ar_list + base_ar_list, base, target)

        tgt_dbug = 0
        tgt_dcov_vals = []

        for prog in programs:
            cd_bugs   = read_bugs_combined(cd_ar_list,   cd,   target, prog)
            base_bugs = read_bugs_combined(base_ar_list, base, target, prog)
            dbug = len(cd_bugs) - len(base_bugs)
            tgt_dbug += dbug

            cd_cov   = mean_cov_combined(cd_ar_list,   cd,   target, prog)
            base_cov = mean_cov_combined(base_ar_list, base, target, prog)
            if cd_cov is not None and base_cov is not None and base_cov > 0:
                tgt_dcov_vals.append((cd_cov - base_cov) / base_cov * 100)

        bug_row[target] = tgt_dbug
        cov_row[target] = (sum(tgt_dcov_vals) / len(tgt_dcov_vals)) if tgt_dcov_vals else None
        total_dbug += tgt_dbug
        if tgt_dcov_vals:
            dcov_targets.append(sum(tgt_dcov_vals) / len(tgt_dcov_vals))

    # Print Δbugs row
    cells = []
    for t in TARGETS:
        v = bug_row[t]
        cells.append(f"{v:+5d}" if v != 0 else f"{'0':>5}")
    mean_dcov = sum(dcov_targets) / len(dcov_targets) if dcov_targets else 0
    print(f"  {'Δbugs':<10} " + " ".join(cells) + f"  {total_dbug:>+5}")

    # Print Δcov% row
    cells = []
    for t in TARGETS:
        v = cov_row[t]
        cells.append(f"{v:>+5.1f}" if v is not None else f"{'?':>5}")
    print(f"  {'Δcov%':<10} " + " ".join(cells) + f"  {mean_dcov:>+5.1f}%  (mean)")

    # Per-program details for non-zero bug deltas
    print()
    any_diff = False
    for target in TARGETS:
        programs = find_programs(cd_ar_list + base_ar_list, cd, target)
        if not programs:
            programs = find_programs(cd_ar_list + base_ar_list, base, target)
        for prog in programs:
            cd_bugs   = read_bugs_combined(cd_ar_list,   cd,   target, prog)
            base_bugs = read_bugs_combined(base_ar_list, base, target, prog)
            dbug = len(cd_bugs) - len(base_bugs)
            if dbug != 0:
                gained = cd_bugs - base_bugs
                lost   = base_bugs - cd_bugs
                if not any_diff:
                    print(f"  {'program':<35} {'base':>6} {'cd':>6} {'Δ':>4}  details")
                    print(f"  {'-'*70}")
                    any_diff = True
                details = ""
                if gained: details += f"  gained: {sorted(gained)}"
                if lost:   details += f"  lost:   {sorted(lost)}"
                print(f"  {target}/{prog:<28} {len(base_bugs):>6} {len(cd_bugs):>6} {dbug:>+4}{details}")
    if not any_diff:
        print("  (no per-program bug differences)")

    # Rep counts
    print()
    d14_cd_reps   = sum(count_reps(DIST14_AR, cd,   t, p)
                        for t in TARGETS
                        for p in find_programs([DIST14_AR], cd, t))
    d14_base_reps = sum(count_reps(DIST14_AR, base, t, p)
                        for t in TARGETS
                        for p in find_programs([DIST14_AR], base, t))
    print(f"  Reps in dist14: {cd}={d14_cd_reps}  {base}={d14_base_reps}")

    return total_dbug, mean_dcov


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("dist14 Analysis: honggfuzzcd (KEEP_RECENT=50) vs honggfuzz (KEEP_RECENT=0)")
    print("Bug metric: union of triggered IDs across reps (monitor/ last snapshot)")
    print("Coverage : mean branch edges (branch_coverage_percent × guard_nb / 100)")

    # 1. dist14 standalone
    dbug14, dcov14 = analyze(
        "1. dist14 STANDALONE  (10 reps each)",
        cd_ar_list   = [DIST14_AR],
        base_ar_list = [DIST14_AR],
    )

    # 2. Paper result (merged/ar only — Table 1 baseline)
    dbug_paper, dcov_paper = analyze(
        "2. PAPER RESULT  merged/ar  (10 reps, Table 1)",
        cd_ar_list   = [MERGED_AR],
        base_ar_list = [MERGED_AR],
    )

    # 3. Combined merged + dist14 (20 reps)
    dbug_comb, dcov_comb = analyze(
        "3. COMBINED  merged + dist14  (20 reps)",
        cd_ar_list   = [MERGED_AR, DIST14_AR],
        base_ar_list = [MERGED_AR, DIST14_AR],
    )

    print(f"\n{'='*70}")
    print("  SUMMARY")
    print(f"{'='*70}")
    print(f"  {'Analysis':<35} {'Δbugs':>8} {'mean Δcov%':>12}")
    print(f"  {'-'*60}")
    print(f"  {'dist14 standalone (10 reps)':<35} {dbug14:>+8} {dcov14:>+11.1f}%")
    print(f"  {'paper / merged (10 reps)':<35} {dbug_paper:>+8} {dcov_paper:>+11.1f}%")
    print(f"  {'combined merged+dist14 (20 reps)':<35} {dbug_comb:>+8} {dcov_comb:>+11.1f}%")
    print()
    print("  Paper Table 1 honggfuzz result: Δbugs=+1, mean Δcov=+6.0%")
    print("  (from generate_summary_table() in plot_seed4.py)")
