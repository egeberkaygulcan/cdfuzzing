#!/usr/bin/env python3
"""Generate paper-quality plots for seed_4 experiment data.
- Per-benchmark coverage over time (all 8 fuzzers on each plot)
- Per-benchmark total bugs triggered bar plot (all 8 fuzzers)
- Single summary bar plot: bugs triggered per fuzzer pair
"""

import os
import glob
import numpy as np

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

BASE = "/users/eldarfin/experiment_results/seed_4"
AR = os.path.join(BASE, "ar")
CACHE = os.path.join(BASE, "cache")
OUTDIR = "/users/eldarfin/cdfuzzing/plots_paper"
os.makedirs(OUTDIR, exist_ok=True)

TARGETS = ["libpng", "libtiff", "libxml2", "openssl", "php", "poppler",
           "sqlite3", "lua", "libsndfile"]

# Ordered: base then CD variant for each pair
FUZZERS = ["afl", "aflcd", "moptafl", "moptaflcd"]

COLORS = {
    "afl":        "#9467bd",
    "aflcd":      "#8c564b",
    "aflfast":    "#bcbd22",
    "aflfastcd":  "#17becf",
    "fairfuzz":   "#1f77b4",
    "fairfuzzcd": "#ff7f0e",
    "moptafl":    "#e377c2",
    "moptaflcd":  "#7f7f7f",
}

LINESTYLES = {f: ('--' if f.endswith('cd') else '-') for f in FUZZERS}


# ─── Data parsing ────────────────────────────────────────────────────────────

def find_plot_data(fuzzer, target):
    results = {}
    for root_dir in [AR, CACHE]:
        pattern = os.path.join(root_dir, fuzzer, target, "*", "0", "findings")
        for findings_dir in glob.glob(pattern):
            for pd_path in [
                os.path.join(findings_dir, "plot_data"),
                os.path.join(findings_dir, "default", "plot_data"),
            ]:
                if os.path.isfile(pd_path):
                    program = findings_dir.split("/")[-3]
                    results[program] = pd_path
    return results


def parse_plot_data(filepath):
    times, paths = [], []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line.startswith('#') or not line:
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) < 8:
                continue
            try:
                times.append(int(parts[0]))
                paths.append(int(parts[3]))
            except (ValueError, IndexError):
                continue
    if not times:
        return None
    t0 = times[0]
    return {
        'hours': np.array([(t - t0) / 3600.0 for t in times]),
        'paths': np.array(paths),
    }


def find_all_programs(target):
    programs = set()
    for root_dir in [AR, CACHE]:
        for fuzzer_dir in glob.glob(os.path.join(root_dir, "*", target)):
            for prog_dir in glob.glob(os.path.join(fuzzer_dir, "*")):
                if os.path.isdir(prog_dir):
                    programs.add(os.path.basename(prog_dir))
    return sorted(programs)


def find_monitor_data(fuzzer, target, program):
    for root_dir in [AR, CACHE]:
        mon_dir = os.path.join(root_dir, fuzzer, target, program, "0", "monitor")
        if os.path.isdir(mon_dir):
            timestamps = sorted([int(f) for f in os.listdir(mon_dir) if f.isdigit()])
            if not timestamps:
                continue
            last_file = os.path.join(mon_dir, str(timestamps[-1]))
            with open(last_file) as f:
                header = f.readline().strip().split(',')
                values = f.readline().strip().split(',')
            bugs = {}
            for i in range(0, len(header), 2):
                bug_id = header[i].replace('_R', '')
                try:
                    triggered = int(values[i+1]) if i+1 < len(values) and values[i+1].strip() else 0
                except (ValueError, IndexError):
                    triggered = 0
                bugs[bug_id] = triggered
            return bugs
    return None


# ─── 1. Per-benchmark coverage over time ─────────────────────────────────────

def plot_coverage_per_benchmark():
    print("1. Per-benchmark coverage over time...")
    for target in TARGETS:
        programs = find_all_programs(target)
        if not programs:
            continue

        n = len(programs)
        fig, axes = plt.subplots(1, n, figsize=(5 * n, 4), squeeze=False)
        fig.suptitle(f"Coverage Over Time — {target}", fontsize=14, fontweight='bold')

        for idx, program in enumerate(programs):
            ax = axes[0, idx]
            for fuzzer in FUZZERS:
                pd_files = find_plot_data(fuzzer, target)
                if program not in pd_files:
                    continue
                data = parse_plot_data(pd_files[program])
                if data is None:
                    continue
                lw = 2.0 if fuzzer.endswith('cd') else 1.3
                ax.plot(data['hours'], data['paths'], label=fuzzer,
                        color=COLORS[fuzzer], linestyle=LINESTYLES[fuzzer],
                        linewidth=lw, alpha=0.85)

            ax.set_title(program, fontsize=10)
            ax.set_xlabel("Time (hours)")
            if idx == 0:
                ax.set_ylabel("Paths (coverage)")
            ax.grid(True, alpha=0.3)

        # Single shared legend
        handles, labels = axes[0, 0].get_legend_handles_labels()
        if handles:
            fig.legend(handles, labels, loc='lower center', ncol=len(FUZZERS),
                       fontsize=8, bbox_to_anchor=(0.5, -0.02))

        plt.tight_layout(rect=[0, 0.05, 1, 0.95])
        outpath = os.path.join(OUTDIR, f"coverage_{target}.png")
        fig.savefig(outpath, dpi=150, bbox_inches='tight')
        print(f"  Saved {outpath}")
        plt.close(fig)


# ─── 2. Per-benchmark bugs triggered bar plot ────────────────────────────────

def get_bugs_per_fuzzer_per_target():
    """Returns {target: {fuzzer: total_bugs_triggered}}"""
    result = {}
    for target in TARGETS:
        programs = find_all_programs(target)
        result[target] = {}
        for fuzzer in FUZZERS:
            total = 0
            for program in programs:
                bugs = find_monitor_data(fuzzer, target, program)
                if bugs:
                    total += sum(1 for v in bugs.values() if v > 0)
            result[target][fuzzer] = total
    return result


def plot_bugs_per_benchmark(bug_counts):
    print("\n2. Per-benchmark bugs triggered bar plots...")
    for target in TARGETS:
        counts = bug_counts[target]
        fig, ax = plt.subplots(figsize=(8, 4))

        x = np.arange(len(FUZZERS))
        vals = [counts.get(f, 0) for f in FUZZERS]
        colors = [COLORS[f] for f in FUZZERS]

        bars = ax.bar(x, vals, color=colors, alpha=0.85, edgecolor='white',
                      linewidth=0.5)
        ax.set_xticks(x)
        ax.set_xticklabels(FUZZERS, rotation=45, ha='right', fontsize=9)
        ax.set_ylabel("Unique Bugs Triggered")
        ax.set_title(f"Bugs Triggered — {target}", fontsize=13, fontweight='bold')
        ax.grid(True, alpha=0.3, axis='y')

        for bar, val in zip(bars, vals):
            if val > 0:
                ax.text(bar.get_x() + bar.get_width() / 2., bar.get_height(),
                        str(val), ha='center', va='bottom', fontsize=9,
                        fontweight='bold')

        plt.tight_layout()
        outpath = os.path.join(OUTDIR, f"bugs_{target}.png")
        fig.savefig(outpath, dpi=150, bbox_inches='tight')
        print(f"  Saved {outpath}")
        plt.close(fig)


# ─── 3. Summary bar plot: bugs triggered per fuzzer (grouped pairs) ──────────

def plot_bugs_summary(bug_counts):
    print("\n3. Summary bugs triggered (paired bars)...")

    # Compute totals per fuzzer
    totals = {f: sum(bug_counts[t].get(f, 0) for t in TARGETS) for f in FUZZERS}

    pairs = [("afl", "aflcd"), ("moptafl", "moptaflcd")]

    fig, ax = plt.subplots(figsize=(8, 5))

    x = np.arange(len(pairs))
    width = 0.35

    base_vals = [totals[b] for b, _ in pairs]
    cd_vals = [totals[c] for _, c in pairs]
    base_colors = [COLORS[b] for b, _ in pairs]
    cd_colors = [COLORS[c] for _, c in pairs]

    bars1 = ax.bar(x - width / 2, base_vals, width, color=base_colors,
                   alpha=0.85, edgecolor='white', linewidth=0.5)
    bars2 = ax.bar(x + width / 2, cd_vals, width, color=cd_colors,
                   alpha=0.85, edgecolor='white', linewidth=0.5)

    # X labels: pair names
    pair_labels = [f"{b} / {c}" for b, c in pairs]
    ax.set_xticks(x)
    ax.set_xticklabels(pair_labels, fontsize=10)
    ax.set_ylabel("Total Unique Bugs Triggered", fontsize=11)
    ax.set_title("Bugs Triggered: Baseline vs CD Variant", fontsize=14,
                 fontweight='bold')
    ax.grid(True, alpha=0.3, axis='y')

    # Value labels
    for bar, val in zip(bars1, base_vals):
        ax.text(bar.get_x() + bar.get_width() / 2., bar.get_height(),
                str(val), ha='center', va='bottom', fontsize=10, fontweight='bold')
    for bar, val in zip(bars2, cd_vals):
        ax.text(bar.get_x() + bar.get_width() / 2., bar.get_height(),
                str(val), ha='center', va='bottom', fontsize=10, fontweight='bold')

    plt.tight_layout()
    outpath = os.path.join(OUTDIR, "bugs_summary_pairs.png")
    fig.savefig(outpath, dpi=150, bbox_inches='tight')
    print(f"  Saved {outpath}")
    plt.close(fig)


# ─── 4. Coverage % change: CD vs baseline per benchmark (grouped by pair) ────

def plot_coverage_pct_change():
    print("\n4. Coverage % change per pair per benchmark...")

    pairs = [("afl", "aflcd"), ("moptafl", "moptaflcd")]

    # For each pair, compute total final coverage (sum of all programs) per target
    pair_pcts = {}
    for base, cd in pairs:
        pcts = []
        for target in TARGETS:
            programs = find_all_programs(target)
            base_total = 0
            cd_total = 0
            for program in programs:
                base_pd = find_plot_data(base, target)
                cd_pd = find_plot_data(cd, target)
                if program in base_pd:
                    d = parse_plot_data(base_pd[program])
                    if d is not None:
                        base_total += d['paths'][-1]
                if program in cd_pd:
                    d = parse_plot_data(cd_pd[program])
                    if d is not None:
                        cd_total += d['paths'][-1]
            if base_total > 0:
                pcts.append((cd_total - base_total) / base_total * 100)
            else:
                pcts.append(0)
        pair_pcts[(base, cd)] = pcts

    # Plot: grouped bar chart, one group per target, one bar per pair
    fig, ax = plt.subplots(figsize=(14, 6))

    x = np.arange(len(TARGETS))
    n_pairs = len(pairs)
    width = 0.18
    offsets = np.linspace(-(n_pairs - 1) / 2 * width, (n_pairs - 1) / 2 * width, n_pairs)

    for i, (base, cd) in enumerate(pairs):
        pcts = pair_pcts[(base, cd)]
        colors_pos = [COLORS[cd] if v >= 0 else '#d62728' for v in pcts]
        bars = ax.bar(x + offsets[i], pcts, width, color=colors_pos, alpha=0.85,
                      edgecolor='white', linewidth=0.5, label=f"{base}→{cd}")
        for bar, val in zip(bars, pcts):
            va = 'bottom' if val >= 0 else 'top'
            ax.text(bar.get_x() + bar.get_width() / 2., bar.get_height(),
                    f"{val:+.1f}%", ha='center', va=va, fontsize=7, fontweight='bold')

    ax.axhline(y=0, color='black', linewidth=0.8)
    ax.set_xticks(x)
    ax.set_xticklabels(TARGETS, fontsize=10)
    ax.set_ylabel("Coverage Change (%)")
    ax.set_title("Coverage % Change: CD Variant vs Baseline (per benchmark)",
                 fontsize=14, fontweight='bold')
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3, axis='y')

    plt.tight_layout()
    outpath = os.path.join(OUTDIR, "coverage_pct_change.png")
    fig.savefig(outpath, dpi=150, bbox_inches='tight')
    print(f"  Saved {outpath}")
    plt.close(fig)


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print(f"Generating paper plots → {OUTDIR}/\n")

    plot_coverage_per_benchmark()

    bug_counts = get_bugs_per_fuzzer_per_target()
    plot_bugs_per_benchmark(bug_counts)
    plot_bugs_summary(bug_counts)
    plot_coverage_pct_change()

    print(f"\nDone. All plots in {OUTDIR}/")
