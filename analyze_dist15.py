#!/usr/bin/env python3
"""
Analyze dist15 parameter variants vs their baselines.

Pairs:
  aflcd_v2  (C=3  CL=60)  vs  aflcd  (C=3  CL=10)  — longer cooldown
  aflcd_v3  (C=5  CL=120) vs  aflcd  (C=3  CL=10)  — higher gate + very long CL
  aflfastcd_v2 (C=2 CL=25) vs  aflfastcd (C=3 CL=10) — more responsive

Baseline data:   /proj/CDFuzzing/distributed/merged/ar/
Variant data:    /mydata/dist15/ar/
"""

import os, glob, re, csv
from pathlib import Path
from collections import defaultdict

MERGED_AR = "/proj/CDFuzzing/distributed/merged/ar"
DIST15_AR = "/mydata/dist15/ar"
REPS = list(range(10))
TARGETS = ["libpng", "libtiff", "libxml2", "openssl", "php", "poppler",
           "sqlite3", "lua", "libsndfile"]

PAIRS = [
    ("aflcd_v2",    "aflcd",    "C=3 CL=60",   "C=3 CL=10"),
    ("aflcd_v3",    "aflcd",    "C=5 CL=120",  "C=3 CL=10"),
    ("aflfastcd_v2","aflfastcd","C=2 CL=25",   "C=3 CL=10"),
    # CD vs base (fast check)
    ("aflcd_v2",    "afl",      "C=3 CL=60",   "no-CD"),
    ("aflcd_v3",    "afl",      "C=5 CL=120",  "no-CD"),
    ("aflfastcd_v2","aflfast",  "C=2 CL=25",   "no-CD"),
]

BUG_RE = re.compile(r'[A-Z]{3}[0-9]+[a-z]?')


def find_programs(ar_root, fuzzer, target):
    pattern = os.path.join(ar_root, fuzzer, target, "*")
    return [os.path.basename(p) for p in sorted(glob.glob(pattern))
            if os.path.isdir(p)]


def read_drift_log(ar_root, fuzzer, target, program, rep):
    path = os.path.join(ar_root, fuzzer, target, program, str(rep),
                        "findings", "drift_log.csv")
    if not os.path.isfile(path):
        return None
    with open(path) as f:
        rows = list(csv.DictReader(f))
    return rows[-1] if rows else None


def read_bugs(ar_root, fuzzer, target, program, rep):
    path = os.path.join(ar_root, fuzzer, target, program, str(rep),
                        "canaries.raw")
    if not os.path.isfile(path):
        return set()
    try:
        with open(path, 'rb') as f:
            data = f.read().decode('latin-1', errors='replace')
        return set(BUG_RE.findall(data))
    except Exception:
        return set()


def analyze_pair(variant, baseline, variant_label, baseline_label):
    print(f"\n{'='*70}")
    print(f"  {variant} ({variant_label})  vs  {baseline} ({baseline_label})")
    print(f"{'='*70}")

    # Determine which ar root to use for variant vs baseline
    variant_ar  = DIST15_AR
    baseline_ar = MERGED_AR

    total_resets_v = defaultdict(list)   # program -> [resets per rep]
    total_resets_b = defaultdict(list)
    cov_v = defaultdict(list)            # program -> [coverage per rep]
    cov_b = defaultdict(list)
    bugs_v = defaultdict(set)            # program -> union of bug IDs
    bugs_b = defaultdict(set)

    missing_v, missing_b = 0, 0

    for target in TARGETS:
        # Use variant programs as ground truth
        programs = find_programs(variant_ar, variant, target)
        if not programs:
            programs = find_programs(baseline_ar, baseline, target)

        for prog in programs:
            for rep in REPS:
                row_v = read_drift_log(variant_ar,  variant,  target, prog, rep)
                row_b = read_drift_log(baseline_ar, baseline, target, prog, rep)

                key = f"{target}/{prog}"

                # Always read bugs (canaries.raw exists for all fuzzers)
                bugs_v[key] |= read_bugs(variant_ar, variant, target, prog, rep)
                bugs_b[key] |= read_bugs(baseline_ar, baseline, target, prog, rep)

                if row_v:
                    total_resets_v[key].append(int(row_v.get("reset_count", 0)))
                    cov_v[key].append(int(row_v.get("coverage", 0)))
                else:
                    missing_v += 1

                if row_b:
                    total_resets_b[key].append(int(row_b.get("reset_count", 0)))
                    cov_b[key].append(int(row_b.get("coverage", 0)))
                else:
                    missing_b += 1

    if missing_v or missing_b:
        print(f"  [WARN] missing drift_logs: variant={missing_v}, baseline={missing_b}")

    # --- Reset summary ---
    print(f"\n  RESET COUNTS (sum across all 10 reps):")
    print(f"  {'Program':<40} {'Variant':>10} {'Baseline':>10} {'Delta':>8}")
    print(f"  {'-'*40} {'-'*10} {'-'*10} {'-'*8}")

    total_v_resets, total_b_resets = 0, 0
    programs_fired_v = 0
    reset_rows = []
    for key in sorted(total_resets_v.keys()):
        sv = sum(total_resets_v[key])
        sb = sum(total_resets_b.get(key, []))
        total_v_resets += sv
        total_b_resets += sb
        if sv > 0:
            programs_fired_v += 1
        reset_rows.append((key, sv, sb, sv - sb))

    # Show programs where either side fired
    for key, sv, sb, delta in reset_rows:
        if sv > 0 or sb > 0:
            print(f"  {key:<40} {sv:>10} {sb:>10} {delta:>+8}")
    print(f"  {'TOTAL':<40} {total_v_resets:>10} {total_b_resets:>10} {total_v_resets-total_b_resets:>+8}")
    print(f"  Programs where variant fired: {programs_fired_v}")

    # --- Per-rep reset distribution for key programs ---
    print(f"\n  PER-REP RESETS (variant / baseline) for top programs:")
    top = sorted(reset_rows, key=lambda x: x[1] + x[2], reverse=True)[:5]
    for key, sv, sb, _ in top:
        if sv + sb == 0:
            continue
        rv = total_resets_v.get(key, [0]*10)
        rb = total_resets_b.get(key, [0]*10)
        rv_str = " ".join(f"{x}" for x in rv)
        rb_str = " ".join(f"{x}" for x in rb)
        print(f"  {key}")
        print(f"    variant  reps: [{rv_str}]  total={sv}")
        print(f"    baseline reps: [{rb_str}]  total={sb}")

    # Coverage summary
    print(f"\n  COVERAGE DELTA (mean final edge count, variant - baseline):")
    print(f"  {'Program':<40} {'Variant':>10} {'Baseline':>10} {'Delta%':>8}")
    print(f"  {'-'*40} {'-'*10} {'-'*10} {'-'*8}")
    total_delta_pct = []
    for key in sorted(cov_v.keys()):
        mv = sum(cov_v[key]) / len(cov_v[key]) if cov_v[key] else 0
        mb_vals = cov_b.get(key, [])
        mb = sum(mb_vals) / len(mb_vals) if mb_vals else 0
        # Skip if >30% of baseline reps have near-zero coverage (bad data)
        zero_frac = sum(1 for x in mb_vals if x < 100) / len(mb_vals) if mb_vals else 1
        if zero_frac > 0.3:
            print(f"  {key:<40} {'(baseline has ' + str(int(zero_frac*100)) + '% zero reps — skipped)':>42}")
            continue
        if mb > 100:
            pct = 100 * (mv - mb) / mb
            total_delta_pct.append(pct)
            if abs(pct) > 0.5:
                print(f"  {key:<40} {mv:>10.0f} {mb:>10.0f} {pct:>+7.1f}%")
        elif mb <= 100 and mv > 100:
            print(f"  {key:<40} {'(baseline near-zero — skipped)':>30}")
    if total_delta_pct:
        print(f"  Mean coverage delta across all programs: {sum(total_delta_pct)/len(total_delta_pct):+.2f}%")

    # --- Bug summary ---
    print(f"\n  BUG DELTA (union across all 10 reps, variant - baseline):")
    delta_bugs = 0
    for key in sorted(bugs_v.keys()):
        bv = len(bugs_v.get(key, set()))
        bb = len(bugs_b.get(key, set()))
        d = bv - bb
        delta_bugs += d
        if d != 0:
            print(f"  {key:<40} v={bv}  b={bb}  delta={d:+d}")
    print(f"  Total Δbugs: {delta_bugs:+d}")


if __name__ == "__main__":
    for args in PAIRS:
        analyze_pair(*args)
    print("\nDone.")
