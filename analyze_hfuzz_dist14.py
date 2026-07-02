#!/usr/bin/env python3
"""
analyze_hfuzz_dist14.py
Compare honggfuzz (merged/ar, 10 reps 0-9) vs honggfuzzcd (dist14/ar, 9 reps 0-3,5-9).

Bug metric  : union of triggered bug IDs (last monitor snapshot per rep)
Coverage    : mean branch edges = branch_coverage_percent × guard_nb / 100
              (from last Summary line in log/current)
EMA/guard   : Value drifts / Resets from log/current (honggfuzzcd only)

Monitor timestamp format: both use second-based stamps (max ~86400).
  merged/honggfuzz  : ~17K files per dir → probe downward from 90000 step 5
  dist14/honggfuzzcd: ~20  files per dir → os.scandir() (fast)
Log files   : tail-read last 4 KB to find Summary and guard lines.
"""

import os, glob, re, sys
from collections import defaultdict

MERGED  = "/proj/CDFuzzing/distributed/merged/ar"
DIST14  = "/proj/CDFuzzing/distributed/dist14/ar"
TARGETS = ["libpng","libtiff","libxml2","openssl","php","poppler","sqlite3","lua","libsndfile"]
SHORT   = {"libpng":"lpng","libtiff":"ltif","libxml2":"lxml","openssl":"ssl",
           "php":"php","poppler":"popl","sqlite3":"sql","lua":"lua","libsndfile":"lsnd"}

BASE_REPS = {0,1,2,3,5,6,7,8,9}      # honggfuzz  : merged/ar  — skip rep 4 to match CD side
CD_REPS   = {0,1,2,3,5,6,7,8,9}     # honggfuzzcd: dist14/ar  — rep 4 missing

# ── monitor helpers ─────────────────────────────────────────────────────────

def last_monitor_probe(mon_dir, start=90000, step=5):
    """Probe downward for second-based stamps. Fast when run completed near 24h."""
    for t in range(start, 0, -step):
        p = os.path.join(mon_dir, str(t))
        try:
            os.stat(p)
            return p
        except FileNotFoundError:
            pass
    return None

def last_monitor_scandir(mon_dir):
    """Scandir approach — fast for dirs with few files (~20)."""
    try:
        ts = max((int(e.name) for e in os.scandir(mon_dir) if e.name.isdigit()), default=None)
        return os.path.join(mon_dir, str(ts)) if ts else None
    except:
        return None

def bugs_union(ar, fuzzer, tgt, prog, reps, mon_fn):
    union = set()
    found = False
    for rep in reps:
        mon_dir = os.path.join(ar, fuzzer, tgt, prog, str(rep), "monitor")
        if not os.path.isdir(mon_dir):
            continue
        p = mon_fn(mon_dir)
        if not p:
            continue
        try:
            with open(p) as f:
                hdr  = f.readline().strip().split(',')
                vals = f.readline().strip().split(',')
            for i in range(0, len(hdr), 2):
                bid = hdr[i].replace('_R', '')
                try:
                    if int(vals[i+1] if i+1 < len(vals) and vals[i+1].strip() else 0) > 0:
                        union.add(bid)
                except Exception:
                    pass
            found = True
        except Exception:
            pass
    return union if found else set()

# ── log helpers ──────────────────────────────────────────────────────────────

def read_log_tail(path, nbytes=4096):
    try:
        with open(path, 'rb') as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - nbytes))
            return f.read().decode('utf-8', errors='replace')
    except:
        return ""

def cov_branch_edges(log_current):
    tail = read_log_tail(log_current)
    last = None
    for line in tail.splitlines():
        if 'Summary' in line:
            last = line
    if last:
        m_pct = re.search(r'branch_coverage_percent:(\d+)', last)
        m_nb  = re.search(r'guard_nb:(\d+)', last)
        if m_pct and m_nb:
            return int(m_pct.group(1)) * int(m_nb.group(1)) / 100
    return None

def guard_stats(log_current):
    tail = read_log_tail(log_current)
    m = re.search(r'Value drifts:\s*(\d+),\s*Resets:\s*(\d+)', tail)
    if m:
        return int(m.group(1)), int(m.group(2))
    return 0, 0

# ── collect ──────────────────────────────────────────────────────────────────

rows = []
ema_by_tgt = defaultdict(lambda: [0, 0])  # [drifts, resets]

all_progs = sorted(set(
    (tgt, os.path.basename(pd))
    for tgt in TARGETS
    for pd in glob.glob(os.path.join(MERGED, "honggfuzz", tgt, "*"))
))

total = len(all_progs)
for i, (tgt, prog) in enumerate(all_progs):
    print(f"  [{i+1}/{total}] {tgt}/{prog} ...", flush=True)

    bb = bugs_union(MERGED, "honggfuzz",   tgt, prog, BASE_REPS,
                    lambda d: last_monitor_probe(d, start=90000, step=5))
    cb = bugs_union(DIST14, "honggfuzzcd", tgt, prog, CD_REPS,
                    last_monitor_scandir)

    base_covs, cd_covs = [], []
    for rep in BASE_REPS:
        v = cov_branch_edges(os.path.join(MERGED, "honggfuzz",   tgt, prog, str(rep), "log", "current"))
        if v: base_covs.append(v)
    for rep in CD_REPS:
        v = cov_branch_edges(os.path.join(DIST14, "honggfuzzcd", tgt, prog, str(rep), "log", "current"))
        if v: cd_covs.append(v)

    for rep in CD_REPS:
        d, r = guard_stats(os.path.join(DIST14, "honggfuzzcd", tgt, prog, str(rep), "log", "current"))
        ema_by_tgt[tgt][0] += d
        ema_by_tgt[tgt][1] += r

    rows.append((tgt, prog, bb, cb,
                 sum(base_covs)/len(base_covs) if base_covs else None,
                 sum(cd_covs)/len(cd_covs)     if cd_covs   else None))

# ── print results ────────────────────────────────────────────────────────────

W = 92
print("\n" + "="*W)
print(f"  honggfuzz (merged/ar) vs honggfuzzcd (dist14/ar)  —  PAIRED 9 reps {{0,1,2,3,5,6,7,8,9}}  (PRNG seeds 1000-1003, 1005-1009)")
print("="*W)
print(f"\n{'Program':<40} {'Bbugs':>5} {'Cbugs':>5} {'Δbugs':>6}  {'Bcov':>6} {'Ccov':>6} {'Δcov%':>7}  changes")
print("-"*W)

by_tgt_bugs = defaultdict(int)
total_bugs  = 0
cov_deltas  = []

for tgt, prog, bb, cb, bc, cc in rows:
    db = len(cb) - len(bb)
    by_tgt_bugs[tgt] += db
    total_bugs += db
    gained = sorted(cb - bb)
    lost   = sorted(bb - cb)
    detail = ("gained " + str(gained) if gained else "") + (" lost " + str(lost) if lost else "")
    dc_str = bc_str = cc_str = "—"
    if bc and cc:
        dc = (cc - bc) / bc * 100
        cov_deltas.append(dc)
        dc_str = f"{dc:+.1f}%"
        bc_str = f"{bc:.0f}"
        cc_str = f"{cc:.0f}"
    mk = " ◄" if db else ""
    print(f"  {tgt}/{prog:<30}{len(bb):>5} {len(cb):>5} {db:>+6}  {bc_str:>6} {cc_str:>6} {dc_str:>7}{mk}  {detail}")

print("-"*W)
print(f"\nPer-target Δbugs:", end="")
for t in TARGETS:
    print(f"  {SHORT[t]}:{by_tgt_bugs[t]:+d}", end="")
print(f"\nTotal  Δbugs : {total_bugs:+d}")
if cov_deltas:
    print(f"Mean   Δcov  : {sum(cov_deltas)/len(cov_deltas):+.1f}%  ({len(cov_deltas)} programs with coverage data)")

print(f"\n{'='*W}")
print(f"  EMA / GUARD STATISTICS  (honggfuzzcd dist14, 9 paired reps × 21 programs)")
print(f"{'='*W}")
print(f"\n  {'Target':<10} {'Drifts':>8} {'Resets':>8} {'Sup%':>8}  {'D/rep':>8} {'R/rep':>8}")
print(f"  {'-'*56}")
td = tr = 0
for tgt in TARGETS:
    d, r = ema_by_tgt[tgt]
    n_progs = sum(1 for t, _, *__ in rows if t == tgt)
    n = n_progs * 9
    sup = (1 - r/d) * 100 if d > 0 else float('nan')
    d_per = d/n if n else 0
    r_per = r/n if n else 0
    print(f"  {SHORT[tgt]:<10} {d:>8} {r:>8} {sup:>7.1f}%  {d_per:>8.2f} {r_per:>8.2f}")
    td += d
    tr += r
sup_t = (1 - tr/td) * 100 if td > 0 else float('nan')
print(f"  {'TOTAL':<10} {td:>8} {tr:>8} {sup_t:>7.1f}%")
print(f"\n  Drifts = guard fires (EMA crossed threshold)")
print(f"  Resets = corpus pruned (drift confirmed post-hysteresis)")
print(f"  Sup%%   = 1 - Resets/Drifts")
