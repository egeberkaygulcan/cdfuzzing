#!/usr/bin/env python3
"""Generate plots for seed_4 experiment data.
Produces per-target coverage line plots, bar charts, and bug reports.
Each plot is a separate image file.
"""

import os
import glob
import csv
import re
from pathlib import Path
from collections import defaultdict

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

# BASE/OUTDIR default to the seed_4 run but can be overridden so the same
# analysis runs against a distributed/merged run (see cloudlab/merge-results.sh).
BASE = os.environ.get("CDFUZZ_BASE", "/users/eldarfin/experiment_results/seed_4")
AR = os.path.join(BASE, "ar")
CACHE = os.path.join(BASE, "cache")
OUTDIR = os.environ.get("CDFUZZ_OUTDIR", "/users/eldarfin/cdfuzzing/plots_seed4")
os.makedirs(OUTDIR, exist_ok=True)

TARGETS = ["libpng", "libtiff", "libxml2", "openssl", "php", "poppler",
           "sqlite3", "lua", "libsndfile"]

# Fuzzer pairs: baseline -> CD variant (only complete 9/9 pairs)
PAIRS = {
    "aflplusplus": "aflpluspluscd",
    "fairfuzz": "fairfuzzcd",
    "moptafl": "moptaflcd",
    "afl": "aflcd",
    "aflfast": "aflfastcd",
}

COLORS = {
    "fairfuzz": "#1f77b4",
    "fairfuzzcd": "#ff7f0e",
    "aflplusplus": "#2ca02c",
    "aflpluspluscd": "#d62728",
    "afl": "#9467bd",
    "aflcd": "#8c564b",
    "moptafl": "#e377c2",
    "moptaflcd": "#7f7f7f",
    "aflfast": "#bcbd22",
    "aflfastcd": "#17becf",
    "honggfuzz": "#aec7e8",
    "honggfuzzcd": "#ffbb78",
}

LINESTYLES = {}
for base_name in PAIRS:
    LINESTYLES[base_name] = '-'
    LINESTYLES[PAIRS[base_name]] = '--'

# Only analyze these fuzzers (exclude incomplete aflplusplus*, honggfuzz*)
INCLUDED_FUZZERS = set()
for b, c in PAIRS.items():
    INCLUDED_FUZZERS.add(b)
    INCLUDED_FUZZERS.add(c)


def find_plot_data(fuzzer, target):
    """Find plot_data file for a fuzzer/target combination (any program)."""
    results = {}
    for root_dir in [AR, CACHE]:
        pattern = os.path.join(root_dir, fuzzer, target, "*", "*", "findings")
        for findings_dir in sorted(glob.glob(pattern)):
            # Check for plot_data directly or in default/ subdir
            for pd_path in [
                os.path.join(findings_dir, "plot_data"),
                os.path.join(findings_dir, "default", "plot_data"),
            ]:
                if os.path.isfile(pd_path):
                    program = findings_dir.split("/")[-3]
                    results[program] = pd_path
    return results


def parse_plot_data(filepath):
    """Parse AFL plot_data file into time series."""
    times = []
    paths = []
    crashes = []
    map_sizes = []

    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line.startswith('#') or not line:
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) < 8:
                continue
            try:
                t = int(parts[0])
                p = int(parts[3])   # paths_total
                c = int(parts[7])   # unique_crashes
                ms = parts[6].rstrip('%')
                ms = float(ms)
            except (ValueError, IndexError):
                continue
            times.append(t)
            paths.append(p)
            crashes.append(c)
            map_sizes.append(ms)

    if not times:
        return None

    # Normalize time to hours from start
    t0 = times[0]
    hours = [(t - t0) / 3600.0 for t in times]
    return {
        'hours': np.array(hours),
        'paths': np.array(paths),
        'crashes': np.array(crashes),
        'map_size': np.array(map_sizes),
    }


def parse_fuzzer_stats(fuzzer, target):
    """Parse fuzzer_stats for final summary."""
    results = {}
    for root_dir in [AR, CACHE]:
        pattern = os.path.join(root_dir, fuzzer, target, "*", "*", "findings")
        for findings_dir in sorted(glob.glob(pattern)):
            for stats_path in [
                os.path.join(findings_dir, "fuzzer_stats"),
                os.path.join(findings_dir, "default", "fuzzer_stats"),
            ]:
                if os.path.isfile(stats_path):
                    program = findings_dir.split("/")[-3]
                    stats = {}
                    with open(stats_path) as f:
                        for line in f:
                            if ':' in line:
                                k, v = line.split(':', 1)
                                stats[k.strip()] = v.strip()
                    results[program] = stats
    return results


def find_monitor_data(fuzzer, target, program):
    """Parse monitor canary files for bug reaching/triggering."""
    for root_dir in [AR, CACHE]:
        for mon_dir in sorted(glob.glob(
                os.path.join(root_dir, fuzzer, target, program, "*", "monitor"))):
          if os.path.isdir(mon_dir):
            timestamps = sorted([int(f) for f in os.listdir(mon_dir) if f.isdigit()])
            if not timestamps:
                continue
            # Read first and last
            first_file = os.path.join(mon_dir, str(timestamps[0]))
            last_file = os.path.join(mon_dir, str(timestamps[-1]))

            with open(last_file) as f:
                header = f.readline().strip().split(',')
                values = f.readline().strip().split(',')

            bugs = {}
            for i in range(0, len(header), 2):
                bug_id = header[i].replace('_R', '')
                try:
                    reached = int(values[i]) if i < len(values) and values[i].strip() else 0
                except (ValueError, IndexError):
                    reached = 0
                try:
                    triggered = int(values[i+1]) if i+1 < len(values) and values[i+1].strip() else 0
                except (ValueError, IndexError):
                    triggered = 0
                bugs[bug_id] = {'reached': reached, 'triggered': triggered}
            return bugs, timestamps[0], timestamps[-1]
    return None, None, None


def find_all_programs(target):
    """Find all programs for a target across all fuzzers."""
    programs = set()
    for root_dir in [AR, CACHE]:
        for fuzzer_dir in glob.glob(os.path.join(root_dir, "*", target)):
            for prog_dir in glob.glob(os.path.join(fuzzer_dir, "*")):
                if os.path.isdir(prog_dir):
                    programs.add(os.path.basename(prog_dir))
    return sorted(programs)


def find_all_fuzzers():
    """Find all fuzzers with data, filtered to INCLUDED_FUZZERS."""
    fuzzers = set()
    for root_dir in [AR, CACHE]:
        for d in glob.glob(os.path.join(root_dir, "*")):
            if os.path.isdir(d):
                name = os.path.basename(d)
                if name in INCLUDED_FUZZERS:
                    fuzzers.add(name)
    return sorted(fuzzers)


# ─── COVERAGE LINE PLOTS (per target, one program per subplot) ────────────────

def plot_coverage_lines():
    fuzzers = find_all_fuzzers()
    for target in TARGETS:
        programs = find_all_programs(target)
        if not programs:
            continue

        n = len(programs)
        fig, axes = plt.subplots(n, 1, figsize=(12, 4*n), squeeze=False)
        fig.suptitle(f"Coverage Over Time — {target}", fontsize=16, fontweight='bold')
        has_data = False

        for idx, program in enumerate(programs):
            ax = axes[idx, 0]
            for fuzzer in fuzzers:
                pd_files = find_plot_data(fuzzer, target)
                if program not in pd_files:
                    continue
                data = parse_plot_data(pd_files[program])
                if data is None:
                    continue
                has_data = True
                color = COLORS.get(fuzzer, None)
                ls = LINESTYLES.get(fuzzer, '-')
                lw = 2.5 if fuzzer.endswith('cd') else 1.5
                ax.plot(data['hours'], data['paths'],
                        label=fuzzer, color=color, linestyle=ls, linewidth=lw)

            ax.set_title(program, fontsize=12)
            ax.set_xlabel("Time (hours)")
            ax.set_ylabel("Paths (coverage)")
            ax.legend(fontsize=8, ncol=2)
            ax.grid(True, alpha=0.3)

        if has_data:
            plt.tight_layout(rect=[0, 0, 1, 0.96])
            outpath = os.path.join(OUTDIR, f"coverage_line_{target}.png")
            fig.savefig(outpath, dpi=150, bbox_inches='tight')
            print(f"  Saved {outpath}")
        plt.close(fig)


# ─── COVERAGE BAR CHARTS (per pair, final coverage across targets) ────────────

def plot_coverage_bars():
    for base, cd in PAIRS.items():
        fig, ax = plt.subplots(figsize=(14, 6))
        fig.suptitle(f"Final Coverage: {base} vs {cd}", fontsize=14, fontweight='bold')

        labels = []
        base_vals = []
        cd_vals = []

        for target in TARGETS:
            programs = find_all_programs(target)
            for program in programs:
                base_pd = find_plot_data(base, target)
                cd_pd = find_plot_data(cd, target)

                base_data = parse_plot_data(base_pd[program]) if program in base_pd else None
                cd_data = parse_plot_data(cd_pd[program]) if program in cd_pd else None

                if base_data is not None or cd_data is not None:
                    short = program[:20]
                    labels.append(f"{target}\n{short}")
                    base_vals.append(base_data['paths'][-1] if base_data is not None else 0)
                    cd_vals.append(cd_data['paths'][-1] if cd_data is not None else 0)

        if not labels:
            plt.close(fig)
            continue

        x = np.arange(len(labels))
        width = 0.35
        bars1 = ax.bar(x - width/2, base_vals, width, label=base,
                       color=COLORS.get(base, '#1f77b4'), alpha=0.8)
        bars2 = ax.bar(x + width/2, cd_vals, width, label=cd,
                       color=COLORS.get(cd, '#ff7f0e'), alpha=0.8)

        ax.set_ylabel("Final Paths (coverage)")
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=8)
        ax.legend()
        ax.grid(True, alpha=0.3, axis='y')

        # Add value labels
        for bar in bars1:
            h = bar.get_height()
            if h > 0:
                ax.text(bar.get_x() + bar.get_width()/2., h,
                        f'{int(h)}', ha='center', va='bottom', fontsize=6)
        for bar in bars2:
            h = bar.get_height()
            if h > 0:
                ax.text(bar.get_x() + bar.get_width()/2., h,
                        f'{int(h)}', ha='center', va='bottom', fontsize=6)

        plt.tight_layout()
        outpath = os.path.join(OUTDIR, f"coverage_bar_{base}_vs_{cd}.png")
        fig.savefig(outpath, dpi=150, bbox_inches='tight')
        print(f"  Saved {outpath}")
        plt.close(fig)


# ─── BUG REPORT ───────────────────────────────────────────────────────────────

def generate_bug_report():
    fuzzers = find_all_fuzzers()
    report_lines = []
    report_lines.append("=" * 80)
    report_lines.append("BUG REPORT — seed_4 Experiments")
    report_lines.append("=" * 80)
    report_lines.append("")

    # Also build data for a plot
    bug_data = {}  # fuzzer -> {target/program -> {bug: triggered}}

    for target in TARGETS:
        programs = find_all_programs(target)
        if not programs:
            continue

        report_lines.append(f"\n{'─'*60}")
        report_lines.append(f"  TARGET: {target}")
        report_lines.append(f"{'─'*60}")

        for program in programs:
            report_lines.append(f"\n  Program: {program}")
            report_lines.append(f"  {'fuzzer':<20} {'bugs_reached':>14} {'bugs_triggered':>16} {'crashes':>10}")
            report_lines.append(f"  {'-'*64}")

            for fuzzer in fuzzers:
                bugs, t0, t1 = find_monitor_data(fuzzer, target, program)
                stats_all = parse_fuzzer_stats(fuzzer, target)
                stats = stats_all.get(program, {})
                crashes = stats.get('unique_crashes', '?')

                if bugs is None:
                    continue

                reached = sum(1 for b in bugs.values() if b['reached'] > 0)
                triggered = sum(1 for b in bugs.values() if b['triggered'] > 0)
                total_bugs = len(bugs)
                duration_h = (t1 - t0) / 3600.0 if t0 and t1 else 0

                triggered_ids = [k for k, v in bugs.items() if v['triggered'] > 0]
                trig_str = ", ".join(triggered_ids) if triggered_ids else "-"

                report_lines.append(
                    f"  {fuzzer:<20} {reached:>6}/{total_bugs:<7} "
                    f"{triggered:>8}/{total_bugs:<7} {str(crashes):>10}"
                )
                if triggered_ids:
                    report_lines.append(f"    → triggered: {trig_str}")

                # Store for plot
                if fuzzer not in bug_data:
                    bug_data[fuzzer] = {}
                key = f"{target}/{program}"
                bug_data[fuzzer][key] = {
                    'reached': reached,
                    'triggered': triggered,
                    'total': total_bugs,
                    'crashes': int(crashes) if crashes != '?' else 0,
                }

    report_text = "\n".join(report_lines)
    report_path = os.path.join(OUTDIR, "bug_report.txt")
    with open(report_path, 'w') as f:
        f.write(report_text)
    print(f"  Saved {report_path}")
    print(report_text)

    return bug_data


def plot_bugs_triggered(bug_data):
    """Bar chart of bugs triggered per fuzzer."""
    if not bug_data:
        return

    fuzzers = sorted(bug_data.keys())
    triggered_counts = []
    reached_counts = []
    crash_counts = []

    for fz in fuzzers:
        total_trig = sum(v['triggered'] for v in bug_data[fz].values())
        total_reach = sum(v['reached'] for v in bug_data[fz].values())
        total_crash = sum(v['crashes'] for v in bug_data[fz].values())
        triggered_counts.append(total_trig)
        reached_counts.append(total_reach)
        crash_counts.append(total_crash)

    # Bugs triggered bar chart
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle("Bug Summary — seed_4", fontsize=14, fontweight='bold')

    x = np.arange(len(fuzzers))
    colors = [COLORS.get(f, '#333333') for f in fuzzers]

    bars = ax1.bar(x, triggered_counts, color=colors, alpha=0.85)
    ax1.set_xticks(x)
    ax1.set_xticklabels(fuzzers, rotation=45, ha='right', fontsize=9)
    ax1.set_ylabel("Unique Bugs Triggered")
    ax1.set_title("Bugs Triggered (canaries)")
    ax1.grid(True, alpha=0.3, axis='y')
    for bar, val in zip(bars, triggered_counts):
        if val > 0:
            ax1.text(bar.get_x() + bar.get_width()/2., bar.get_height(),
                     str(val), ha='center', va='bottom', fontsize=9, fontweight='bold')

    bars2 = ax2.bar(x, crash_counts, color=colors, alpha=0.85)
    ax2.set_xticks(x)
    ax2.set_xticklabels(fuzzers, rotation=45, ha='right', fontsize=9)
    ax2.set_ylabel("Unique Crashes Found")
    ax2.set_title("Crashes Found")
    ax2.grid(True, alpha=0.3, axis='y')
    for bar, val in zip(bars2, crash_counts):
        if val > 0:
            ax2.text(bar.get_x() + bar.get_width()/2., bar.get_height(),
                     str(val), ha='center', va='bottom', fontsize=9, fontweight='bold')

    plt.tight_layout()
    outpath = os.path.join(OUTDIR, "bugs_summary.png")
    fig.savefig(outpath, dpi=150, bbox_inches='tight')
    print(f"  Saved {outpath}")
    plt.close(fig)

    # Per-target bugs triggered heatmap-style comparison
    for base, cd in PAIRS.items():
        if base not in bug_data or cd not in bug_data:
            continue
        all_keys = sorted(set(list(bug_data.get(base, {}).keys()) +
                              list(bug_data.get(cd, {}).keys())))
        if not all_keys:
            continue

        fig, ax = plt.subplots(figsize=(12, max(4, len(all_keys) * 0.4)))
        y = np.arange(len(all_keys))
        base_trig = [bug_data.get(base, {}).get(k, {}).get('triggered', 0) for k in all_keys]
        cd_trig = [bug_data.get(cd, {}).get(k, {}).get('triggered', 0) for k in all_keys]

        height = 0.35
        ax.barh(y - height/2, base_trig, height, label=base,
                color=COLORS.get(base, '#1f77b4'), alpha=0.8)
        ax.barh(y + height/2, cd_trig, height, label=cd,
                color=COLORS.get(cd, '#ff7f0e'), alpha=0.8)

        ax.set_yticks(y)
        ax.set_yticklabels(all_keys, fontsize=8)
        ax.set_xlabel("Bugs Triggered")
        ax.set_title(f"Bugs Triggered: {base} vs {cd}", fontweight='bold')
        ax.legend()
        ax.grid(True, alpha=0.3, axis='x')

        plt.tight_layout()
        outpath = os.path.join(OUTDIR, f"bugs_{base}_vs_{cd}.png")
        fig.savefig(outpath, dpi=150, bbox_inches='tight')
        print(f"  Saved {outpath}")
        plt.close(fig)


# ─── DRIFT LOG ANALYSIS ──────────────────────────────────────────────────────

def parse_drift_log(fuzzer, target, program):
    """Parse drift_log.csv for a CD fuzzer, return rows list or None."""
    for root_dir in [AR, CACHE]:
        for drift_path in sorted(glob.glob(
                os.path.join(root_dir, fuzzer, target, program, "*",
                             "findings", "drift_log.csv"))) + \
                sorted(glob.glob(
                os.path.join(root_dir, fuzzer, target, program, "*",
                             "findings", "default", "drift_log.csv"))):
            if os.path.isfile(drift_path):
                try:
                    with open(drift_path) as f:
                        reader = csv.DictReader(f)
                        rows = list(reader)
                    if rows:
                        return rows
                except Exception:
                    pass
    return None


def plot_drift_analysis():
    """Plot drift detection metrics for CD fuzzers."""
    cd_fuzzers = [f for f in find_all_fuzzers() if f.endswith('cd')]
    if not cd_fuzzers:
        return

    for target in TARGETS:
        programs = find_all_programs(target)
        if not programs:
            continue

        for program in programs:
            fig_data = {}
            for fuzzer in cd_fuzzers:
                rows = parse_drift_log(fuzzer, target, program)
                if rows:
                    fig_data[fuzzer] = rows

            if not fig_data:
                continue

            fig, axes = plt.subplots(2, 1, figsize=(12, 8), sharex=True)
            fig.suptitle(f"Drift Analysis — {target}/{program}", fontsize=14,
                         fontweight='bold')

            for fuzzer, rows in fig_data.items():
                minutes = [float(r.get('minute', 0)) for r in rows]
                cov = [float(r.get('coverage', 0)) for r in rows]
                resets = [float(r.get('reset_count', 0)) for r in rows]
                drifts = [float(r.get('drift_count', 0)) for r in rows]

                hours = [m/60.0 for m in minutes]
                color = COLORS.get(fuzzer, None)

                axes[0].plot(hours, cov, label=f"{fuzzer} coverage",
                            color=color, linewidth=2)
                axes[1].plot(hours, resets, label=f"{fuzzer} resets",
                            color=color, linewidth=2, linestyle='-')
                axes[1].plot(hours, drifts, label=f"{fuzzer} drifts",
                            color=color, linewidth=1.5, linestyle='--', alpha=0.6)

            axes[0].set_ylabel("Coverage")
            axes[0].legend(fontsize=8)
            axes[0].grid(True, alpha=0.3)
            axes[1].set_ylabel("Count")
            axes[1].set_xlabel("Time (hours)")
            axes[1].legend(fontsize=8, ncol=2)
            axes[1].grid(True, alpha=0.3)

            plt.tight_layout(rect=[0, 0, 1, 0.96])
            safe_prog = program.replace('/', '_')
            outpath = os.path.join(OUTDIR, f"drift_{target}_{safe_prog}.png")
            fig.savefig(outpath, dpi=150, bbox_inches='tight')
            print(f"  Saved {outpath}")
            plt.close(fig)


# ─── RESET ANALYSIS ──────────────────────────────────────────────────────────

def generate_reset_report():
    """Generate comprehensive reset analysis for all CD fuzzers."""
    cd_fuzzers = [f for f in find_all_fuzzers() if f.endswith('cd')]
    if not cd_fuzzers:
        return {}

    report_lines = []
    report_lines.append("=" * 80)
    report_lines.append("RESET & DRIFT REPORT — seed_4 Experiments")
    report_lines.append("=" * 80)
    report_lines.append("")

    # Per-fuzzer per-target summary
    reset_data = {}  # fuzzer -> {target/program -> {resets, drifts, jerk_drifts, final_cov, ...}}

    for fuzzer in cd_fuzzers:
        reset_data[fuzzer] = {}
        for target in TARGETS:
            programs = find_all_programs(target)
            for program in programs:
                rows = parse_drift_log(fuzzer, target, program)
                if not rows:
                    continue
                last = rows[-1]
                total_resets = int(float(last.get('reset_count', 0)))
                total_drifts = int(float(last.get('drift_count', 0)))
                total_jerk = int(float(last.get('jerk_drift_count', 0)))
                final_cov = float(last.get('coverage', 0))

                # Find reset timings (when reset_count increments)
                reset_times = []
                prev_rc = 0
                for r in rows:
                    rc = int(float(r.get('reset_count', 0)))
                    if rc > prev_rc:
                        reset_times.append(float(r.get('minute', 0)) / 60.0)
                    prev_rc = rc

                key = f"{target}/{program}"
                reset_data[fuzzer][key] = {
                    'resets': total_resets,
                    'drifts': total_drifts,
                    'jerk_drifts': total_jerk,
                    'final_cov': final_cov,
                    'reset_times_h': reset_times,
                }

    # Print per-fuzzer summary table
    for fuzzer in cd_fuzzers:
        report_lines.append(f"\n{'─'*60}")
        report_lines.append(f"  FUZZER: {fuzzer}")
        report_lines.append(f"{'─'*60}")
        report_lines.append(f"  {'target/program':<40} {'resets':>7} {'drifts':>7} {'jerk':>7} {'final_cov':>10}")
        report_lines.append(f"  {'-'*75}")

        total_r = total_d = total_j = 0
        for key in sorted(reset_data[fuzzer].keys()):
            d = reset_data[fuzzer][key]
            report_lines.append(
                f"  {key:<40} {d['resets']:>7} {d['drifts']:>7} "
                f"{d['jerk_drifts']:>7} {d['final_cov']:>10.0f}"
            )
            total_r += d['resets']
            total_d += d['drifts']
            total_j += d['jerk_drifts']
        report_lines.append(f"  {'-'*75}")
        report_lines.append(
            f"  {'TOTAL':<40} {total_r:>7} {total_d:>7} {total_j:>7}"
        )

    report_text = "\n".join(report_lines)
    report_path = os.path.join(OUTDIR, "reset_report.txt")
    with open(report_path, 'w') as f:
        f.write(report_text)
    print(f"  Saved {report_path}")
    print(report_text)

    return reset_data


def plot_reset_summary(reset_data):
    """Plot reset summary charts."""
    if not reset_data:
        return

    cd_fuzzers = sorted(reset_data.keys())

    # --- 1. Total resets per fuzzer bar chart ---
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle("Reset & Drift Summary — seed_4", fontsize=14, fontweight='bold')

    total_resets = []
    total_drifts = []
    for fz in cd_fuzzers:
        total_resets.append(sum(v['resets'] for v in reset_data[fz].values()))
        total_drifts.append(sum(v['drifts'] for v in reset_data[fz].values()))

    x = np.arange(len(cd_fuzzers))
    colors = [COLORS.get(f, '#333333') for f in cd_fuzzers]

    bars1 = ax1.bar(x, total_resets, color=colors, alpha=0.85)
    ax1.set_xticks(x)
    ax1.set_xticklabels(cd_fuzzers, rotation=45, ha='right', fontsize=9)
    ax1.set_ylabel("Total Resets")
    ax1.set_title("Total Resets per Fuzzer")
    ax1.grid(True, alpha=0.3, axis='y')
    for bar, val in zip(bars1, total_resets):
        ax1.text(bar.get_x() + bar.get_width()/2., bar.get_height(),
                 str(val), ha='center', va='bottom', fontsize=9, fontweight='bold')

    bars2 = ax2.bar(x, total_drifts, color=colors, alpha=0.85)
    ax2.set_xticks(x)
    ax2.set_xticklabels(cd_fuzzers, rotation=45, ha='right', fontsize=9)
    ax2.set_ylabel("Total Drifts Detected")
    ax2.set_title("Total Drifts Detected per Fuzzer")
    ax2.grid(True, alpha=0.3, axis='y')
    for bar, val in zip(bars2, total_drifts):
        ax2.text(bar.get_x() + bar.get_width()/2., bar.get_height(),
                 str(val), ha='center', va='bottom', fontsize=9, fontweight='bold')

    plt.tight_layout()
    outpath = os.path.join(OUTDIR, "reset_summary.png")
    fig.savefig(outpath, dpi=150, bbox_inches='tight')
    print(f"  Saved {outpath}")
    plt.close(fig)

    # --- 2. Resets per target/program heatmap for each CD fuzzer ---
    for fuzzer in cd_fuzzers:
        data = reset_data[fuzzer]
        if not data:
            continue
        keys = sorted(data.keys())
        resets = [data[k]['resets'] for k in keys]
        drifts = [data[k]['drifts'] for k in keys]

        fig, ax = plt.subplots(figsize=(12, max(4, len(keys) * 0.4)))
        y = np.arange(len(keys))
        height = 0.35
        ax.barh(y - height/2, resets, height, label='Resets',
                color=COLORS.get(fuzzer, '#333'), alpha=0.85)
        ax.barh(y + height/2, drifts, height, label='Drifts',
                color=COLORS.get(fuzzer, '#333'), alpha=0.45, hatch='//')
        ax.set_yticks(y)
        ax.set_yticklabels(keys, fontsize=8)
        ax.set_xlabel("Count")
        ax.set_title(f"Resets & Drifts per Program — {fuzzer}", fontweight='bold')
        ax.legend()
        ax.grid(True, alpha=0.3, axis='x')
        plt.tight_layout()
        outpath = os.path.join(OUTDIR, f"resets_{fuzzer}.png")
        fig.savefig(outpath, dpi=150, bbox_inches='tight')
        print(f"  Saved {outpath}")
        plt.close(fig)

    # --- 3. Reset timing scatter: when do resets happen? ---
    fig, ax = plt.subplots(figsize=(14, 6))
    fig.suptitle("Reset Timing — When Do Resets Occur?", fontsize=14, fontweight='bold')
    for i, fuzzer in enumerate(cd_fuzzers):
        all_times = []
        for key, d in reset_data[fuzzer].items():
            all_times.extend(d['reset_times_h'])
        if all_times:
            ax.scatter(all_times, [i]*len(all_times), label=fuzzer,
                      color=COLORS.get(fuzzer, '#333'), alpha=0.6, s=30)
    ax.set_yticks(range(len(cd_fuzzers)))
    ax.set_yticklabels(cd_fuzzers)
    ax.set_xlabel("Time (hours)")
    ax.set_title("Reset Events Over 24h Campaign")
    ax.grid(True, alpha=0.3)
    ax.legend(loc='upper right')
    plt.tight_layout()
    outpath = os.path.join(OUTDIR, "reset_timing.png")
    fig.savefig(outpath, dpi=150, bbox_inches='tight')
    print(f"  Saved {outpath}")
    plt.close(fig)

    # --- 4. Correlation: resets vs final coverage improvement ---
    fig, ax = plt.subplots(figsize=(10, 7))
    fig.suptitle("Resets vs Coverage (CD Fuzzers)", fontsize=14, fontweight='bold')
    for fuzzer in cd_fuzzers:
        # Get matching baseline name
        base = fuzzer.replace('cd', '')
        for key, d in reset_data[fuzzer].items():
            parts = key.split('/')
            target, program = parts[0], parts[1]
            # Get baseline final coverage
            base_pd = find_plot_data(base, target)
            base_data = parse_plot_data(base_pd[program]) if program in base_pd else None
            base_cov = base_data['paths'][-1] if base_data is not None else 0

            cd_cov = d['final_cov']
            improvement = ((cd_cov - base_cov) / base_cov * 100) if base_cov > 0 else 0

            ax.scatter(d['resets'], improvement,
                      color=COLORS.get(fuzzer, '#333'), alpha=0.6, s=40)

    # Add fuzzer legend manually
    from matplotlib.lines import Line2D
    legend_elements = [Line2D([0], [0], marker='o', color='w',
                              markerfacecolor=COLORS.get(f, '#333'),
                              markersize=8, label=f) for f in cd_fuzzers]
    ax.legend(handles=legend_elements, loc='best')
    ax.axhline(y=0, color='black', linestyle='-', linewidth=0.5, alpha=0.5)
    ax.set_xlabel("Number of Resets")
    ax.set_ylabel("Coverage Improvement over Baseline (%)")
    ax.set_title("Do More Resets Lead to Better Coverage?")
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    outpath = os.path.join(OUTDIR, "resets_vs_coverage.png")
    fig.savefig(outpath, dpi=150, bbox_inches='tight')
    print(f"  Saved {outpath}")
    plt.close(fig)


# ─── CROSS-PAIR SUMMARY TABLE ────────────────────────────────────────────────

def generate_summary_table():
    """Print a cross-pair table: bugs and coverage for baseline vs CD."""
    lines = []
    lines.append("=" * 100)
    lines.append("CROSS-PAIR SUMMARY TABLE — seed_4")
    lines.append(f"Parameters: WINDOW=100  THRESHOLD=0.05  CONSECUTIVE=5  "
                 f"STAGNATION_FACTOR=0.5  COOLDOWN=10  EMA_ALPHA=0.1")
    lines.append("=" * 100)

    grand = {"base_bugs": 0, "cd_bugs": 0, "base_cov": 0, "cd_cov": 0, "resets": 0, "programs": 0}

    for base, cd in PAIRS.items():
        lines.append(f"\n{'─'*100}")
        lines.append(f"  PAIR: {base}  →  {cd}")
        lines.append(f"  {'program':<40} {'base_bugs':>10} {'cd_bugs':>10} "
                     f"{'Δbugs':>7} {'base_cov':>10} {'cd_cov':>10} "
                     f"{'Δcov%':>8} {'resets':>8} {'verdict':>10}")
        lines.append(f"  {'-'*97}")

        pair_totals = {"base_bugs": 0, "cd_bugs": 0,
                       "base_cov": 0.0, "cd_cov": 0.0, "resets": 0, "n": 0}

        for target in TARGETS:
            programs = find_all_programs(target)
            for program in programs:
                # bugs
                base_bugs_d, _, _ = find_monitor_data(base, target, program)
                cd_bugs_d, _, _ = find_monitor_data(cd, target, program)
                bb = sum(1 for v in base_bugs_d.values() if v['triggered'] > 0) if base_bugs_d else 0
                cb = sum(1 for v in cd_bugs_d.values() if v['triggered'] > 0) if cd_bugs_d else 0

                # coverage
                base_pd = find_plot_data(base, target)
                cd_pd = find_plot_data(cd, target)
                base_data = parse_plot_data(base_pd[program]) if program in base_pd else None
                cd_data = parse_plot_data(cd_pd[program]) if program in cd_pd else None
                bc = int(base_data['paths'][-1]) if base_data else 0
                cc = int(cd_data['paths'][-1]) if cd_data else 0
                dcov_pct = ((cc - bc) / bc * 100) if bc > 0 else 0.0

                # resets from drift log
                rows = parse_drift_log(cd, target, program)
                resets = int(float(rows[-1].get('reset_count', 0))) if rows else 0

                if bc == 0 and bb == 0 and cc == 0 and cb == 0:
                    continue  # no data at all

                verdict = "="
                if cb > bb or cc > bc * 1.01:
                    verdict = "CD+" if cb >= bb else "cov+"
                elif bb > cb or bc > cc * 1.01:
                    verdict = "base+" if bb >= cb else "cov-"

                label = f"{target}/{program}"
                lines.append(f"  {label:<40} {bb:>10} {cb:>10} {cb-bb:>+7} "
                              f"{bc:>10} {cc:>10} {dcov_pct:>+8.1f}% {resets:>8}  {verdict:>9}")

                pair_totals["base_bugs"] += bb
                pair_totals["cd_bugs"] += cb
                pair_totals["base_cov"] += bc
                pair_totals["cd_cov"] += cc
                pair_totals["resets"] += resets
                pair_totals["n"] += 1

        n = pair_totals["n"] or 1
        avg_dcov = (pair_totals["cd_cov"] - pair_totals["base_cov"]) / pair_totals["base_cov"] * 100 \
                   if pair_totals["base_cov"] > 0 else 0
        lines.append(f"  {'-'*97}")
        lines.append(f"  {'PAIR TOTAL':<40} {pair_totals['base_bugs']:>10} "
                     f"{pair_totals['cd_bugs']:>10} "
                     f"{pair_totals['cd_bugs']-pair_totals['base_bugs']:>+7} "
                     f"{pair_totals['base_cov']:>10} {pair_totals['cd_cov']:>10} "
                     f"{avg_dcov:>+8.1f}% {pair_totals['resets']:>8}")

        grand["base_bugs"] += pair_totals["base_bugs"]
        grand["cd_bugs"]   += pair_totals["cd_bugs"]
        grand["base_cov"]  += pair_totals["base_cov"]
        grand["cd_cov"]    += pair_totals["cd_cov"]
        grand["resets"]    += pair_totals["resets"]
        grand["programs"]  += n

    grand_dcov = (grand["cd_cov"] - grand["base_cov"]) / grand["base_cov"] * 100 \
                 if grand["base_cov"] > 0 else 0
    lines.append(f"\n{'='*100}")
    lines.append(f"  {'GRAND TOTAL':<40} {grand['base_bugs']:>10} "
                 f"{grand['cd_bugs']:>10} "
                 f"{grand['cd_bugs']-grand['base_bugs']:>+7} "
                 f"{grand['base_cov']:>10} {grand['cd_cov']:>10} "
                 f"{grand_dcov:>+8.1f}% {grand['resets']:>8}")
    lines.append("=" * 100)

    text = "\n".join(lines)
    path = os.path.join(OUTDIR, "summary_table.txt")
    with open(path, 'w') as f:
        f.write(text)
    print(f"  Saved {path}")
    print(text)


# ─── PARAMETER EVALUATION ────────────────────────────────────────────────────

def generate_parameter_eval(reset_data):
    """Evaluate CD parameter effectiveness from drift logs."""
    PARAMS = {
        "WINDOW": 100, "THRESHOLD": 0.05, "CONSECUTIVE": 5,
        "STAGNATION_FACTOR": 0.5, "COOLDOWN": 10, "EMA_ALPHA": 0.1,
    }
    lines = []
    lines.append("=" * 80)
    lines.append("PARAMETER EVALUATION — seed_4")
    lines.append("  Parameters used:")
    for k, v in PARAMS.items():
        lines.append(f"    AFL_DRIFT_{k} = {v}")
    lines.append("=" * 80)

    cd_fuzzers = sorted(reset_data.keys())

    # Per-fuzzer: drifts detected vs resets fired (stagnation guard filter rate)
    lines.append("\n── Stagnation Guard Effectiveness (drifts detected → resets fired) ──")
    lines.append(f"  {'fuzzer':<20} {'drifts':>8} {'resets':>8} {'guard_filtered%':>16} {'resets_per_24h':>16}")
    lines.append(f"  {'-'*72}")
    for fz in cd_fuzzers:
        total_d = sum(v['drifts'] for v in reset_data[fz].values())
        total_r = sum(v['resets'] for v in reset_data[fz].values())
        n_programs = len(reset_data[fz])
        filtered_pct = (1 - total_r / total_d) * 100 if total_d > 0 else 0
        resets_per = total_r / n_programs if n_programs > 0 else 0
        lines.append(f"  {fz:<20} {total_d:>8} {total_r:>8} {filtered_pct:>15.1f}% {resets_per:>15.2f}")

    # Reset count distribution across programs
    lines.append("\n── Reset Count Distribution (programs bucketed by reset count) ──")
    lines.append(f"  {'fuzzer':<20} {'0 resets':>10} {'1-2':>8} {'3-5':>8} {'6+':>8}")
    lines.append(f"  {'-'*56}")
    for fz in cd_fuzzers:
        buckets = {0: 0, "1-2": 0, "3-5": 0, "6+": 0}
        for d in reset_data[fz].values():
            r = d['resets']
            if r == 0:    buckets[0] += 1
            elif r <= 2:  buckets["1-2"] += 1
            elif r <= 5:  buckets["3-5"] += 1
            else:         buckets["6+"] += 1
        lines.append(f"  {fz:<20} {buckets[0]:>10} {buckets['1-2']:>8} "
                     f"{buckets['3-5']:>8} {buckets['6+']:>8}")

    # Coverage delta by reset bucket (averaged across all pairs)
    lines.append("\n── Mean Coverage Delta by Reset Count (CD vs baseline) ──")
    bucket_deltas = {0: [], "1-2": [], "3-5": [], "6+": []}
    for fz in cd_fuzzers:
        base = fz[:-2]  # strip 'cd'
        for key, d in reset_data[fz].items():
            parts = key.split('/')
            target, program = parts[0], parts[1]
            base_pd = find_plot_data(base, target)
            base_data = parse_plot_data(base_pd[program]) if program in base_pd else None
            if base_data is None or d['final_cov'] == 0:
                continue
            delta_pct = (d['final_cov'] - base_data['paths'][-1]) / base_data['paths'][-1] * 100
            r = d['resets']
            if r == 0:    bucket_deltas[0].append(delta_pct)
            elif r <= 2:  bucket_deltas["1-2"].append(delta_pct)
            elif r <= 5:  bucket_deltas["3-5"].append(delta_pct)
            else:         bucket_deltas["6+"].append(delta_pct)

    lines.append(f"  {'bucket':<10} {'n':>5} {'mean_Δcov%':>12} {'median_Δcov%':>14}")
    lines.append(f"  {'-'*44}")
    for bucket in [0, "1-2", "3-5", "6+"]:
        vals = bucket_deltas[bucket]
        if vals:
            mean_v = np.mean(vals)
            median_v = np.median(vals)
            lines.append(f"  {str(bucket):<10} {len(vals):>5} {mean_v:>+11.2f}% {median_v:>+13.2f}%")

    lines.append("\n── Assessment ──")
    for bucket, label in [(0, "0 resets"), ("1-2", "1-2 resets"), ("3-5", "3-5 resets"), ("6+", "6+ resets")]:
        vals = bucket_deltas[bucket]
        if not vals:
            continue
        mean_v = np.mean(vals)
        sign = "positive" if mean_v > 1 else ("negative" if mean_v < -1 else "neutral")
        lines.append(f"  {label}: mean coverage delta {mean_v:+.2f}% → {sign}")

    lines.append("\n── Parameter Recommendations ──")
    # Check if high-reset programs (5+) are consistently negative
    high_vals = bucket_deltas.get("3-5", []) + bucket_deltas.get("6+", [])
    if high_vals and np.mean(high_vals) < -1:
        lines.append("  [!] High-reset programs (3+) show negative coverage on average.")
        lines.append("      → CONSECUTIVE (currently 5) or STAGNATION_FACTOR (currently 0.5)")
        lines.append("        should be increased to reduce false-positive resets on")
        lines.append("        slow-growth targets (parsers, state machines).")
    low_vals = bucket_deltas.get("1-2", [])
    if low_vals and np.mean(low_vals) > 1:
        lines.append("  [+] 1-2 resets per campaign is net positive.")
        lines.append("      → COOLDOWN=10 and current parameters appear well-calibrated")
        lines.append("        for targets that benefit from occasional resets.")
    zero_vals = bucket_deltas.get(0, [])
    if zero_vals:
        lines.append(f"  [i] {len(zero_vals)} programs never triggered a reset — drift "
                     f"signal was too conservative or coverage was already stagnant.")

    text = "\n".join(lines)
    path = os.path.join(OUTDIR, "parameter_eval.txt")
    with open(path, 'w') as f:
        f.write(text)
    print(f"  Saved {path}")
    print(text)

    # Plot: coverage delta distribution by reset bucket
    fig, ax = plt.subplots(figsize=(10, 6))
    bucket_labels = [str(b) for b in [0, "1-2", "3-5", "6+"]]
    data_for_box = [bucket_deltas[b] for b in [0, "1-2", "3-5", "6+"] if bucket_deltas[b]]
    labels_for_box = [str(b) for b in [0, "1-2", "3-5", "6+"] if bucket_deltas[b]]
    if data_for_box:
        bp = ax.boxplot(data_for_box, labels=labels_for_box, patch_artist=True,
                        medianprops=dict(color='red', linewidth=2))
        colors_box = ['#2ca02c', '#ff7f0e', '#d62728', '#9467bd']
        for patch, color in zip(bp['boxes'], colors_box[:len(data_for_box)]):
            patch.set_facecolor(color)
            patch.set_alpha(0.6)
    ax.axhline(y=0, color='black', linestyle='--', linewidth=1, alpha=0.7)
    ax.set_xlabel("Number of Resets (bucket)")
    ax.set_ylabel("Coverage Delta vs Baseline (%)")
    ax.set_title("Coverage Impact by Reset Count\n(+ = CD better, - = baseline better)",
                 fontweight='bold')
    ax.grid(True, alpha=0.3, axis='y')
    plt.tight_layout()
    outpath = os.path.join(OUTDIR, "param_eval_coverage_by_resets.png")
    fig.savefig(outpath, dpi=150, bbox_inches='tight')
    print(f"  Saved {outpath}")
    plt.close(fig)

    # Plot: stagnation guard effectiveness per fuzzer
    fig, ax = plt.subplots(figsize=(10, 5))
    fz_list = cd_fuzzers
    drifts_all = [sum(v['drifts'] for v in reset_data[fz].values()) for fz in fz_list]
    resets_all = [sum(v['resets'] for v in reset_data[fz].values()) for fz in fz_list]
    x = np.arange(len(fz_list))
    ax.bar(x, drifts_all, label='Drifts Detected', color='#aec7e8', alpha=0.9)
    ax.bar(x, resets_all, label='Resets Fired', color='#d62728', alpha=0.85)
    ax.set_xticks(x)
    ax.set_xticklabels(fz_list, rotation=45, ha='right')
    ax.set_ylabel("Count (all programs combined)")
    ax.set_title("Stagnation Guard: Drifts Detected vs Resets Fired", fontweight='bold')
    ax.legend()
    ax.grid(True, alpha=0.3, axis='y')
    for i, (d, r) in enumerate(zip(drifts_all, resets_all)):
        if d > 0:
            ax.text(i, d + 0.5, f"{r}/{d}", ha='center', fontsize=8)
    plt.tight_layout()
    outpath = os.path.join(OUTDIR, "param_eval_guard_effectiveness.png")
    fig.savefig(outpath, dpi=150, bbox_inches='tight')
    print(f"  Saved {outpath}")
    plt.close(fig)


# ─── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("Generating seed_4 plots (4 complete pairs)...\n")

    print("1. Coverage line plots (per target)...")
    plot_coverage_lines()

    print("\n2. Coverage bar charts (base vs CD)...")
    plot_coverage_bars()

    print("\n3. Bug report & plots...")
    bug_data = generate_bug_report()
    plot_bugs_triggered(bug_data)

    print("\n4. Drift analysis plots (per target/program)...")
    plot_drift_analysis()

    print("\n5. Reset & drift report...")
    reset_data = generate_reset_report()

    print("\n6. Reset summary plots...")
    plot_reset_summary(reset_data)

    print("\n7. Cross-pair summary table...")
    generate_summary_table()

    print("\n8. Parameter evaluation...")
    generate_parameter_eval(reset_data)

    print(f"\nAll outputs saved to: {OUTDIR}/")
    print(f"Files: {sorted(os.listdir(OUTDIR))}")
