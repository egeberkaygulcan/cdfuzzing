#!/usr/bin/env python3
"""
Delta coverage and delta bug table for all CD vs base fuzzer pairs,
broken down by target (and summed across programs within each target).

Coverage metrics:
  AFL-based fuzzers  : final map_size% from plot_data
                       (tried at findings/plot_data and findings/default/plot_data)
  honggfuzz family   : branch_coverage_percent * guard_nb / 100  from log/current Summary

Bug metric: union of Magma canary IDs across all 10 reps per program,
            summed across programs within each target.
"""

import os, glob, re
from collections import defaultdict

MERGED_AR = "/proj/CDFuzzing/distributed/merged/ar"
DIST15_AR  = "/mydata/dist15/ar"
REPS       = list(range(10))
TARGETS    = ["libpng", "libtiff", "libxml2", "openssl", "php", "poppler",
              "sqlite3", "lua", "libsndfile"]

BUG_RE = re.compile(r'[A-Z]{3}[0-9]+[a-z]?')


# ── Bug readers ───────────────────────────────────────────────────────────────

def read_bugs_monitor(ar, fuzzer, target, program):
    """Union of triggered bug IDs across all reps, reading monitor/ files.
    Mirrors find_monitor_data_union() in plot_seed4.py.
    A bug is counted if triggered > 0 in the LAST monitor snapshot of ANY rep.
    Returns a set, or None if no monitor data found at all.
    """
    union = set()
    found_any = False
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
        found_any = True
    return union if found_any else None


def read_bugs_canaries(ar, fuzzer, target, program):
    """Union of bug IDs across all reps from canaries.raw (fallback when monitor absent)."""
    union = set()
    for rep in REPS:
        path = os.path.join(ar, fuzzer, target, program, str(rep), "canaries.raw")
        try:
            with open(path, 'rb') as f:
                data = f.read().decode('latin-1', errors='replace')
            union |= set(BUG_RE.findall(data))
        except Exception:
            pass
    return union


def read_bugs(ar, fuzzer, target, program):
    """Read bug union: prefer monitor/ files, fall back to canaries.raw."""
    result = read_bugs_monitor(ar, fuzzer, target, program)
    if result is not None:
        return result
    return read_bugs_canaries(ar, fuzzer, target, program)


# (label, cd_fuzzer, base_fuzzer, cd_ar, base_ar, use_monitor)
# use_monitor=False forces canaries.raw for both sides (used when monitor/ was deleted)
PAIRS = [
    ("aflcd vs afl",          "aflcd",        "afl",        MERGED_AR, MERGED_AR, True),
    ("aflfastcd vs aflfast",   "aflfastcd",    "aflfast",    MERGED_AR, MERGED_AR, True),
    ("aflpluspluscd vs afl++", "aflpluspluscd","aflplusplus", MERGED_AR, MERGED_AR, True),
    ("fairfuzzcd vs fairfuzz", "fairfuzzcd",   "fairfuzz",   MERGED_AR, MERGED_AR, True),
    ("honggfuzzcd vs hfuzz",   "honggfuzzcd",  "honggfuzz",  MERGED_AR, MERGED_AR, True),
    ("moptaflcd vs moptafl",   "moptaflcd",    "moptafl",    MERGED_AR, MERGED_AR, True),
    # aflcd_v3 monitor/ deleted from dist15 — use canaries.raw for both sides
    ("aflcd_v3 vs afl",        "aflcd_v3",     "afl",        DIST15_AR, MERGED_AR, False),
]


# ── Coverage readers ────────────────────────────────────────────────────────

def read_map_size(ar, fuzzer, target, program, rep):
    """Final map_size% from AFL plot_data (tries findings/ then findings/default/)."""
    base = os.path.join(ar, fuzzer, target, program, str(rep), "findings")
    for sub in ["plot_data", os.path.join("default", "plot_data")]:
        path = os.path.join(base, sub)
        if not os.path.isfile(path):
            continue
        last_val = None
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('#') or not line:
                        continue
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 7:
                        try:
                            last_val = float(parts[6].rstrip('%'))
                        except ValueError:
                            pass
        except Exception:
            pass
        if last_val is not None:
            return last_val
    return None


def read_hfuzz_edges(ar, fuzzer, target, program, rep):
    """branch_coverage_percent * guard_nb / 100 from honggfuzz log/current Summary."""
    path = os.path.join(ar, fuzzer, target, program, str(rep), "log", "current")
    if not os.path.isfile(path):
        return None
    try:
        with open(path) as f:
            for line in f:
                if "Summary" in line and "guard_nb" in line and "branch_coverage_percent" in line:
                    m_guard = re.search(r'guard_nb:(\d+)', line)
                    m_pct   = re.search(r'branch_coverage_percent:(\d+)', line)
                    if m_guard and m_pct:
                        return int(m_guard.group(1)) * int(m_pct.group(1)) / 100.0
    except Exception:
        pass
    return None


def is_honggfuzz(fuzzer):
    return "honggfuzz" in fuzzer.lower()


def read_cov(ar, fuzzer, target, program, rep):
    if is_honggfuzz(fuzzer):
        return read_hfuzz_edges(ar, fuzzer, target, program, rep)
    return read_map_size(ar, fuzzer, target, program, rep)


# ── Per-pair analysis ────────────────────────────────────────────────────────

def analyze_pair(label, cd, base, cd_ar, base_ar, use_monitor=True):
    """Returns (cov_delta_by_target, bug_delta_by_target) dicts keyed by target."""
    cov_cd_tgt  = defaultdict(list)   # target -> [per-program mean Δ%]
    cov_base_tgt = defaultdict(list)
    bug_cd_tgt   = defaultdict(int)   # target -> Δbugs (sum of per-program deltas)
    bug_base_tgt = defaultdict(int)

    for target in TARGETS:
        # Use CD dir to enumerate programs (variant defines scope)
        pattern = os.path.join(cd_ar, cd, target, "*")
        programs = [os.path.basename(p) for p in sorted(glob.glob(pattern))
                    if os.path.isdir(p)]
        if not programs:
            # Fall back to base dir for this target
            pattern = os.path.join(base_ar, base, target, "*")
            programs = [os.path.basename(p) for p in sorted(glob.glob(pattern))
                        if os.path.isdir(p)]

        for prog in programs:
            # Coverage: mean over reps
            cv_vals = [v for r in REPS if (v := read_cov(cd_ar,   cd,   target, prog, r)) is not None]
            bv_vals = [v for r in REPS if (v := read_cov(base_ar, base, target, prog, r)) is not None]
            if cv_vals:
                cov_cd_tgt[target].append(sum(cv_vals)/len(cv_vals))
            if bv_vals:
                cov_base_tgt[target].append(sum(bv_vals)/len(bv_vals))

            # Bugs: union across reps; use monitor/ unless disabled (e.g. monitor deleted)
            if use_monitor:
                bugs_cd_set   = read_bugs(cd_ar,   cd,   target, prog)
                bugs_base_set = read_bugs(base_ar, base, target, prog)
            else:
                bugs_cd_set   = read_bugs_canaries(cd_ar,   cd,   target, prog)
                bugs_base_set = read_bugs_canaries(base_ar, base, target, prog)
            bug_cd_tgt[target]    += len(bugs_cd_set)
            bug_base_tgt[target]  += len(bugs_base_set)

    # Compute per-target Δcov% (mean of per-program means) and Δbugs
    cov_delta = {}
    for t in TARGETS:
        cv = cov_cd_tgt.get(t, [])
        bv = cov_base_tgt.get(t, [])
        if cv and bv:
            mean_cv = sum(cv) / len(cv)
            mean_bv = sum(bv) / len(bv)
            if mean_bv > 0:
                cov_delta[t] = 100 * (mean_cv - mean_bv) / mean_bv
            else:
                cov_delta[t] = None
        else:
            cov_delta[t] = None

    bug_delta = {t: bug_cd_tgt.get(t, 0) - bug_base_tgt.get(t, 0) for t in TARGETS}
    return cov_delta, bug_delta, bug_cd_tgt, bug_base_tgt


# ── Table printing ───────────────────────────────────────────────────────────

def fmt_cov(v):
    if v is None:
        return "  N/A  "
    return f"{v:+6.1f}%"

def fmt_bug(v):
    if v == 0:
        return "  0 "
    return f"{v:+3d} "

def main():
    tgt_abbr = {
        "libpng":    "lpng",
        "libtiff":   "ltif",
        "libxml2":   "lxml",
        "openssl":   "ssl ",
        "php":       "php ",
        "poppler":   "popl",
        "sqlite3":   "sql ",
        "lua":       "lua ",
        "libsndfile":"lsnd",
    }
    abbrs = [tgt_abbr[t] for t in TARGETS]

    print("\nComputing per-pair results...")
    results = []
    for args in PAIRS:
        label = args[0]
        print(f"  {label}...")
        cov_d, bug_d, bug_cd, bug_b = analyze_pair(*args)  # args includes use_monitor
        results.append((label, cov_d, bug_d, bug_cd, bug_b))

    # ── Δcoverage% table ────────────────────────────────────────────────────
    col = 9
    hdr = " ".join(f"{a:>{col}}" for a in abbrs)
    sep = "-" * (24 + (col+1)*len(TARGETS) + 8)

    print(f"\n{'='*len(sep)}")
    print("  ΔCOVERAGE% (CD - base, mean over programs per target, mean over 10 reps)")
    print(f"{'='*len(sep)}")
    print(f"  {'Pair':<24} {hdr}  {'Mean':>7}")
    print(f"  {sep}")
    for label, cov_d, bug_d, _, _ in results:
        vals = [cov_d.get(t) for t in TARGETS]
        row  = " ".join(fmt_cov(v).rjust(col) for v in vals)
        defined = [v for v in vals if v is not None]
        mean_str = f"{sum(defined)/len(defined):+6.1f}%" if defined else "  N/A  "
        print(f"  {label:<24} {row}  {mean_str:>7}")

    # ── Δbugs table ──────────────────────────────────────────────────────────
    print(f"\n{'='*len(sep)}")
    print("  ΔBUGS (CD union - base union, summed over programs per target, 10 reps)")
    print(f"{'='*len(sep)}")
    print(f"  {'Pair':<24} {hdr}  {'Total':>7}")
    print(f"  {sep}")
    for label, cov_d, bug_d, bug_cd, bug_b in results:
        vals  = [bug_d.get(t, 0) for t in TARGETS]
        row   = " ".join(fmt_bug(v).rjust(col) for v in vals)
        total = sum(vals)
        total_str = f"{total:+3d}" if total != 0 else "  0"
        print(f"  {label:<24} {row}  {total_str:>7}")

    # ── Bug absolute counts (CD / base) ─────────────────────────────────────
    print(f"\n{'='*len(sep)}")
    print("  BUGS ABSOLUTE (CD total unique / base total unique, union over all targets)")
    print(f"{'='*len(sep)}")
    for label, cov_d, bug_d, bug_cd, bug_b in results:
        total_cd  = sum(bug_cd.values())
        total_b   = sum(bug_b.values())
        print(f"  {label:<24}  CD={total_cd:3d}  base={total_b:3d}  Δ={total_cd-total_b:+3d}")

    print()


if __name__ == "__main__":
    main()
