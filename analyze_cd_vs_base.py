#!/usr/bin/env python3
"""
Proper comparison: aflcd_v3 (dist15, 10 reps) vs afl (merged/ar, 10 reps).

Coverage metric: paths_total from fuzzer_stats (available for all AFL variants).
Bug metric: union over all reps per program, from canaries.raw.
"""

import os, glob, re
from pathlib import Path
from collections import defaultdict

MERGED_AR  = "/proj/CDFuzzing/distributed/merged/ar"
DIST15_AR  = "/mydata/dist15/ar"
REPS       = list(range(10))
TARGETS    = ["libpng", "libtiff", "libxml2", "openssl", "php", "poppler",
              "sqlite3", "lua", "libsndfile"]

BUG_RE = re.compile(r'[A-Z]{3}[0-9]+[a-z]?')

VARIANT  = ("aflcd_v3",  DIST15_AR,  "C=5 CL=120")
BASELINE = ("afl",       MERGED_AR,  "no-CD")


def find_programs(ar_root, fuzzer, target):
    pattern = os.path.join(ar_root, fuzzer, target, "*")
    return [os.path.basename(p) for p in sorted(glob.glob(pattern))
            if os.path.isdir(p)]


def read_paths_total(ar_root, fuzzer, target, program, rep):
    path = os.path.join(ar_root, fuzzer, target, program, str(rep),
                        "findings", "fuzzer_stats")
    try:
        with open(path) as f:
            for line in f:
                if line.startswith("paths_total"):
                    return int(line.split(":")[1].strip())
    except Exception:
        pass
    return None


def read_bugs(ar_root, fuzzer, target, program, rep):
    path = os.path.join(ar_root, fuzzer, target, program, str(rep),
                        "canaries.raw")
    try:
        with open(path, 'rb') as f:
            data = f.read().decode('latin-1', errors='replace')
        return set(BUG_RE.findall(data))
    except Exception:
        return set()


def main():
    v_name,  v_ar,  v_label  = VARIANT
    b_name,  b_ar,  b_label  = BASELINE

    print(f"\n{'='*72}")
    print(f"  {v_name} ({v_label})  vs  {b_name} ({b_label})")
    print(f"  Coverage: paths_total from fuzzer_stats | Bugs: canaries.raw union")
    print(f"{'='*72}")

    # --- per-program data ---
    cov_v  = defaultdict(list)
    cov_b  = defaultdict(list)
    bugs_v = defaultdict(set)
    bugs_b = defaultdict(set)

    for target in TARGETS:
        programs = find_programs(v_ar, v_name, target)
        if not programs:
            programs = find_programs(b_ar, b_name, target)

        for prog in programs:
            key = f"{target}/{prog}"
            for rep in REPS:
                pt_v = read_paths_total(v_ar, v_name, target, prog, rep)
                pt_b = read_paths_total(b_ar, b_name, target, prog, rep)
                if pt_v is not None:
                    cov_v[key].append(pt_v)
                if pt_b is not None:
                    cov_b[key].append(pt_b)
                bugs_v[key] |= read_bugs(v_ar, v_name, target, prog, rep)
                bugs_b[key] |= read_bugs(b_ar, b_name, target, prog, rep)

    # --- Coverage table ---
    print(f"\n  COVERAGE (paths_total, mean over 10 reps)")
    print(f"  {'Program':<38} {'Variant':>9} {'Baseline':>9} {'Delta%':>8}  {'n_v':>3}/{' n_b':>3}")
    print(f"  {'-'*38} {'-'*9} {'-'*9} {'-'*8}  {'-'*3}/{'-'*3}")
    total_pct = []
    all_keys = sorted(set(list(cov_v.keys()) + list(cov_b.keys())))
    for key in all_keys:
        v_vals = cov_v.get(key, [])
        b_vals = cov_b.get(key, [])
        mv = sum(v_vals) / len(v_vals) if v_vals else 0
        mb = sum(b_vals) / len(b_vals) if b_vals else 0
        nv, nb = len(v_vals), len(b_vals)
        if mb > 0:
            pct = 100 * (mv - mb) / mb
            total_pct.append(pct)
            flag = " *" if abs(pct) >= 5 else ""
            print(f"  {key:<38} {mv:>9.0f} {mb:>9.0f} {pct:>+7.1f}%{flag}  {nv:>3}/{nb:>3}")
        else:
            print(f"  {key:<38} {mv:>9.0f} {'N/A':>9}  {'N/A':>8}  {nv:>3}/{nb:>3}")
    if total_pct:
        print(f"\n  Mean coverage delta: {sum(total_pct)/len(total_pct):+.2f}%  (over {len(total_pct)} programs)")

    # --- Bug table ---
    print(f"\n  BUG DELTA (union of all 10 reps per program)")
    print(f"  {'Program':<38} {'Variant':>9} {'Baseline':>9} {'Delta':>7}  Variant-only bugs")
    print(f"  {'-'*38} {'-'*9} {'-'*9} {'-'*7}  {'-'*30}")
    total_delta = 0
    total_bv, total_bb = set(), set()
    for key in sorted(bugs_v.keys()):
        bv_set = bugs_v.get(key, set())
        bb_set = bugs_b.get(key, set())
        total_bv |= bv_set
        total_bb |= bb_set
        bv, bb = len(bv_set), len(bb_set)
        d = bv - bb
        total_delta += d
        only_v = sorted(bv_set - bb_set)
        only_b = sorted(bb_set - bv_set)
        extras = ""
        if only_v:
            extras += f"+{only_v}"
        if only_b:
            extras += f"  -{only_b}"
        if d != 0 or only_v or only_b:
            print(f"  {key:<38} {bv:>9} {bb:>9} {d:>+7}  {extras}")

    print(f"\n  Total Δbugs: {total_delta:+d}  (variant union={len(total_bv)}, baseline union={len(total_bb)})")

    # --- Per-rep bug counts for top programs ---
    print(f"\n  PER-REP BUG COUNTS for programs with delta != 0:")
    for key in sorted(bugs_v.keys()):
        bv_set = bugs_v.get(key, set())
        bb_set = bugs_b.get(key, set())
        if len(bv_set) == len(bb_set) and not (bv_set - bb_set) and not (bb_set - bv_set):
            continue
        target, prog = key.split("/", 1)
        print(f"\n  {key}")
        v_per_rep = []
        b_per_rep = []
        for rep in REPS:
            bv = read_bugs(v_ar, v_name, target, prog, rep)
            bb = read_bugs(b_ar, b_name, target, prog, rep)
            v_per_rep.append(sorted(bv))
            b_per_rep.append(sorted(bb))
        print(f"    variant  bugs per rep: {[len(x) for x in v_per_rep]}")
        print(f"    baseline bugs per rep: {[len(x) for x in b_per_rep]}")
        all_bugs = sorted(bv_set | bb_set)
        for bug in all_bugs:
            v_reps = [r for r, bugs in enumerate(v_per_rep) if bug in bugs]
            b_reps = [r for r, bugs in enumerate(b_per_rep) if bug in bugs]
            marker = " <-- variant only" if bug not in bb_set else (" <-- baseline only" if bug not in bv_set else "")
            print(f"      {bug:10s} variant found in reps {v_reps}  baseline found in reps {b_reps}{marker}")


if __name__ == "__main__":
    main()
