#!/usr/bin/env python3
"""
Analysis script for Magma campaign results.
Compares bugs found, coverage reached, plots coverage over time,
and marks concept-drift resets and early stops on the plot.

Usage:
    python3 analyze.py [workdir]

workdir defaults to ./workdir
"""

import argparse
import csv
import os
import sys
import tarfile
from collections import defaultdict
from io import TextIOWrapper

import matplotlib.pyplot as plt
import pandas as pd


def parse_args():
    parser = argparse.ArgumentParser(description="Analyze Magma campaign results")
    parser.add_argument("workdir", nargs="?", default="./workdir",
                        help="Path to captain workdir (default: ./workdir)")
    parser.add_argument("-o", "--output", default="analysis",
                        help="Output directory for plots (default: ./analysis)")
    return parser.parse_args()


def find_campaigns(workdir):
    """Discover all campaigns under workdir/ar/{fuzzer}/{target}/{program}/{run}/."""
    ar_dir = os.path.join(workdir, "ar")
    if not os.path.isdir(ar_dir):
        print(f"Error: {ar_dir} not found", file=sys.stderr)
        sys.exit(1)

    campaigns = []
    for fuzzer in sorted(os.listdir(ar_dir)):
        fuzzer_dir = os.path.join(ar_dir, fuzzer)
        if not os.path.isdir(fuzzer_dir):
            continue
        for target in sorted(os.listdir(fuzzer_dir)):
            target_dir = os.path.join(fuzzer_dir, target)
            if not os.path.isdir(target_dir):
                continue
            for program in sorted(os.listdir(target_dir)):
                program_dir = os.path.join(target_dir, program)
                if not os.path.isdir(program_dir):
                    continue
                for run in sorted(os.listdir(program_dir)):
                    run_dir = os.path.join(program_dir, run)
                    if not os.path.isdir(run_dir) or not run.isdigit():
                        continue
                    campaigns.append({
                        "fuzzer": fuzzer,
                        "target": target,
                        "program": program,
                        "run": int(run),
                        "path": run_dir,
                    })
    return campaigns


def read_file_from_tar(tar, member_path):
    """Read a file from a tarball, returning its text content or None."""
    # Normalize: member might be ./path or path
    for prefix in [f"./{member_path}", member_path]:
        try:
            member = tar.getmember(prefix)
            f = tar.extractfile(member)
            if f is not None:
                return f.read().decode("utf-8", errors="replace")
        except KeyError:
            continue
    return None


def parse_plot_data(text):
    """Parse AFL's plot_data into a DataFrame with relative time in seconds."""
    lines = [l.strip() for l in text.strip().split("\n") if l.strip() and not l.strip().startswith("#")]
    if not lines:
        return pd.DataFrame()

    rows = []
    for line in lines:
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 7:
            continue
        unix_time = int(parts[0])
        paths_total = int(parts[3])
        map_size_str = parts[6].replace("%", "").strip()
        map_size = float(map_size_str)
        unique_crashes = int(parts[7])
        execs_per_sec = float(parts[10])
        rows.append({
            "unix_time": unix_time,
            "paths_total": paths_total,
            "map_size": map_size,
            "unique_crashes": unique_crashes,
            "execs_per_sec": execs_per_sec,
        })

    df = pd.DataFrame(rows)
    if df.empty:
        return df
    t0 = df["unix_time"].iloc[0]
    df["time_s"] = df["unix_time"] - t0
    df["time_min"] = df["time_s"] / 60.0
    return df


def parse_monitor_files(tar):
    """Parse all monitor/{timestamp} files from tarball into a bug DataFrame."""
    members = [m for m in tar.getmembers()
               if "/monitor/" in m.name and m.isfile()]

    rows = []
    for member in members:
        basename = os.path.basename(member.name)
        if basename == "tmp" or not basename.isdigit():
            continue
        timestamp = int(basename)
        f = tar.extractfile(member)
        if f is None:
            continue
        text = f.read().decode("utf-8", errors="replace").strip()
        if not text:
            continue
        reader = csv.DictReader(text.split("\n"))
        try:
            row = next(reader)
            row["time_s"] = timestamp
            rows.append(row)
        except StopIteration:
            continue

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    df["time_s"] = df["time_s"].astype(int)
    df.sort_values("time_s", inplace=True)
    df.reset_index(drop=True, inplace=True)
    df["time_min"] = df["time_s"] / 60.0

    # Convert numeric columns
    for col in df.columns:
        if col.endswith("_R") or col.endswith("_T"):
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)

    return df


def parse_drift_log(text):
    """Parse drift_log.csv into a DataFrame."""
    if not text or not text.strip():
        return pd.DataFrame()
    df = pd.read_csv(pd.io.common.StringIO(text))
    return df


def extract_campaign_data(campaign):
    """Extract plot_data, monitor data, and drift_log from a campaign tarball."""
    tarball = os.path.join(campaign["path"], "ball.tar")
    if not os.path.isfile(tarball):
        # Try raw directory
        plot_text = None
        plot_path = os.path.join(campaign["path"], "findings", "plot_data")
        if os.path.isfile(plot_path):
            with open(plot_path) as f:
                plot_text = f.read()
        drift_text = None
        drift_path = os.path.join(campaign["path"], "findings", "drift_log.csv")
        if os.path.isfile(drift_path):
            with open(drift_path) as f:
                drift_text = f.read()
        # Monitor from raw dir
        mon_dir = os.path.join(campaign["path"], "monitor")
        monitor_df = pd.DataFrame()
        # Can't parse without tarball context here, skip for now
        return plot_text, monitor_df, drift_text

    with tarfile.open(tarball, "r") as tar:
        # Try multiple possible paths for plot_data and drift_log
        plot_text = None
        for path in ["findings/plot_data", "findings/afl-master/plot_data",
                      "findings/default/plot_data"]:
            plot_text = read_file_from_tar(tar, path)
            if plot_text:
                break

        drift_text = None
        for path in ["findings/drift_log.csv", "findings/afl-master/drift_log.csv",
                      "findings/default/drift_log.csv", "output/drift_log.csv"]:
            drift_text = read_file_from_tar(tar, path)
            if drift_text:
                break

        monitor_df = parse_monitor_files(tar)

    return plot_text, monitor_df, drift_text


def summarize_bugs(monitor_df, fuzzer_name):
    """Summarize bugs reached and triggered from monitor data."""
    if monitor_df.empty:
        return {}

    bug_cols = [c for c in monitor_df.columns if c.endswith("_R")]
    bug_ids = [c[:-2] for c in bug_cols]

    summary = {}
    for bug_id in bug_ids:
        r_col = f"{bug_id}_R"
        t_col = f"{bug_id}_T"

        reached_rows = monitor_df[monitor_df[r_col] > 0]
        triggered_rows = monitor_df[monitor_df[t_col] > 0] if t_col in monitor_df.columns else pd.DataFrame()

        first_reached = reached_rows["time_s"].iloc[0] if not reached_rows.empty else None
        first_triggered = triggered_rows["time_s"].iloc[0] if not triggered_rows.empty else None

        final_reached = int(monitor_df[r_col].iloc[-1]) if not monitor_df.empty else 0
        final_triggered = int(monitor_df[t_col].iloc[-1]) if t_col in monitor_df.columns and not monitor_df.empty else 0

        summary[bug_id] = {
            "first_reached_s": first_reached,
            "first_triggered_s": first_triggered,
            "total_reached": final_reached,
            "total_triggered": final_triggered,
        }

    return summary


def print_bug_comparison(all_bugs):
    """Print a table comparing bugs across fuzzers."""
    # Collect all bug IDs
    all_bug_ids = set()
    for fuzzer_data in all_bugs.values():
        all_bug_ids.update(fuzzer_data.keys())
    all_bug_ids = sorted(all_bug_ids)

    if not all_bug_ids:
        print("No bug data found in monitor files.")
        return

    fuzzers = sorted(all_bugs.keys())

    print("\n" + "=" * 80)
    print("BUG COMPARISON")
    print("=" * 80)

    # Header
    header = f"{'Bug':<10}"
    for fuzzer in fuzzers:
        header += f" | {'Reached':>10} {'Triggered':>10} {'Time(s)':>8}"
    print(header)
    print("-" * len(header))

    for bug_id in all_bug_ids:
        row = f"{bug_id:<10}"
        for fuzzer in fuzzers:
            data = all_bugs.get(fuzzer, {}).get(bug_id, {})
            reached = data.get("total_reached", 0)
            triggered = data.get("total_triggered", 0)
            t_time = data.get("first_triggered_s", None)
            t_str = str(t_time) if t_time is not None else "-"
            row += f" | {reached:>10} {triggered:>10} {t_str:>8}"
        print(row)

    # Summary line
    print("-" * len(header))
    summary_row = f"{'TOTAL':<10}"
    for fuzzer in fuzzers:
        total_reached = sum(1 for b in all_bugs.get(fuzzer, {}).values()
                          if b.get("total_reached", 0) > 0)
        total_triggered = sum(1 for b in all_bugs.get(fuzzer, {}).values()
                             if b.get("total_triggered", 0) > 0)
        summary_row += f" | {total_reached:>10} {total_triggered:>10} {'':>8}"
    print(summary_row)
    print(f"{'':>10}   {'bugs reached':>10} {'triggered':>10}")


def plot_coverage(all_plot_data, all_drift_data, output_dir):
    """Plot coverage over time for all fuzzers, marking resets and early stops."""
    os.makedirs(output_dir, exist_ok=True)

    # Group campaigns by target/program
    groups = defaultdict(list)
    for entry in all_plot_data:
        key = (entry["target"], entry["program"])
        groups[key].append(entry)

    for (target, program), entries in groups.items():
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 10), sharex=True)
        fig.suptitle(f"Coverage Comparison — {target}/{program}", fontsize=14)

        colors = plt.cm.tab10.colors
        fuzzer_colors = {}

        for i, entry in enumerate(sorted(entries, key=lambda e: e["fuzzer"])):
            fuzzer = entry["fuzzer"]
            df = entry["df"]
            drift_df = entry.get("drift_df", pd.DataFrame())
            color = colors[i % len(colors)]
            fuzzer_colors[fuzzer] = color

            if df.empty:
                continue

            # Plot 1: map_size (edge coverage %)
            ax1.plot(df["time_min"], df["map_size"], label=fuzzer,
                    color=color, linewidth=1.5)

            # Plot 2: paths_total (corpus size)
            ax2.plot(df["time_min"], df["paths_total"], label=fuzzer,
                    color=color, linewidth=1.5)

            # Mark resets and early stops from drift_log
            if not drift_df.empty and "reset_flag" in drift_df.columns:
                # Find transitions: reset_flag goes from false to true
                drift_df["reset_flag_bool"] = drift_df["reset_flag"].astype(str).str.lower() == "true"
                drift_df["early_stop_flag_bool"] = drift_df["early_stop_flag"].astype(str).str.lower() == "true"

                # Find first minute where reset_flag becomes true
                reset_minutes = []
                prev_reset = False
                for _, row in drift_df.iterrows():
                    cur_reset = row["reset_flag_bool"]
                    if cur_reset and not prev_reset:
                        reset_minutes.append(row["timestamp"])
                    prev_reset = cur_reset

                # Find first minute where early_stop becomes true
                early_stop_minute = None
                for _, row in drift_df.iterrows():
                    if row["early_stop_flag_bool"]:
                        early_stop_minute = row["timestamp"]
                        break

                for rm in reset_minutes:
                    ax1.axvline(x=rm, color=color, linestyle="--", alpha=0.7, linewidth=1)
                    ax1.annotate("reset", xy=(rm, ax1.get_ylim()[1]),
                                fontsize=8, color=color, alpha=0.8,
                                ha="center", va="bottom")
                    ax2.axvline(x=rm, color=color, linestyle="--", alpha=0.7, linewidth=1)

                if early_stop_minute is not None:
                    ax1.axvline(x=early_stop_minute, color=color,
                               linestyle=":", alpha=0.9, linewidth=2)
                    ax1.annotate("early stop", xy=(early_stop_minute, ax1.get_ylim()[1]),
                                fontsize=8, color=color, alpha=0.8,
                                ha="center", va="bottom",
                                bbox=dict(boxstyle="round,pad=0.2",
                                         facecolor="yellow", alpha=0.5))
                    ax2.axvline(x=early_stop_minute, color=color,
                               linestyle=":", alpha=0.9, linewidth=2)

        ax1.set_ylabel("Edge Coverage (%)")
        ax1.legend(loc="lower right")
        ax1.grid(True, alpha=0.3)

        ax2.set_xlabel("Time (minutes)")
        ax2.set_ylabel("Corpus Size (paths)")
        ax2.legend(loc="lower right")
        ax2.grid(True, alpha=0.3)

        plt.tight_layout()
        fname = os.path.join(output_dir, f"coverage_{target}_{program}.png")
        plt.savefig(fname, dpi=150, bbox_inches="tight")
        plt.close()
        print(f"Saved coverage plot: {fname}")


def main():
    args = parse_args()
    workdir = args.workdir
    output_dir = args.output

    campaigns = find_campaigns(workdir)
    if not campaigns:
        print(f"No campaigns found in {workdir}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(campaigns)} campaign(s):")
    for c in campaigns:
        print(f"  {c['fuzzer']}/{c['target']}/{c['program']} run={c['run']}")

    # Extract data from all campaigns
    all_bugs = {}
    all_plot_entries = []

    for campaign in campaigns:
        fuzzer = campaign["fuzzer"]
        label = f"{fuzzer}/{campaign['target']}/{campaign['program']} run={campaign['run']}"
        print(f"\nProcessing {label}...")

        plot_text, monitor_df, drift_text = extract_campaign_data(campaign)

        # Parse plot_data
        plot_df = parse_plot_data(plot_text) if plot_text else pd.DataFrame()
        if plot_df.empty:
            print(f"  Warning: no plot_data found")
        else:
            print(f"  plot_data: {len(plot_df)} entries, "
                  f"final coverage={plot_df['map_size'].iloc[-1]:.2f}%, "
                  f"final paths={plot_df['paths_total'].iloc[-1]}")

        # Parse drift log
        drift_df = parse_drift_log(drift_text) if drift_text else pd.DataFrame()
        if not drift_df.empty:
            has_reset = drift_df["reset_flag"].astype(str).str.lower().eq("true").any()
            has_early_stop = drift_df["early_stop_flag"].astype(str).str.lower().eq("true").any()
            print(f"  drift_log: {len(drift_df)} entries, "
                  f"resets={'YES' if has_reset else 'no'}, "
                  f"early_stop={'YES' if has_early_stop else 'no'}")

        # Summarize bugs
        if not monitor_df.empty:
            bug_summary = summarize_bugs(monitor_df, fuzzer)
            all_bugs[fuzzer] = bug_summary
            triggered = sum(1 for b in bug_summary.values()
                          if b["total_triggered"] > 0)
            reached = sum(1 for b in bug_summary.values()
                        if b["total_reached"] > 0)
            print(f"  bugs: {reached} reached, {triggered} triggered")
        else:
            print(f"  Warning: no monitor data found")

        all_plot_entries.append({
            "fuzzer": fuzzer,
            "target": campaign["target"],
            "program": campaign["program"],
            "run": campaign["run"],
            "df": plot_df,
            "drift_df": drift_df,
        })

    # Print bug comparison table
    print_bug_comparison(all_bugs)

    # Coverage summary
    print("\n" + "=" * 80)
    print("COVERAGE SUMMARY")
    print("=" * 80)
    for entry in sorted(all_plot_entries, key=lambda e: e["fuzzer"]):
        df = entry["df"]
        if df.empty:
            continue
        print(f"  {entry['fuzzer']}: "
              f"final_coverage={df['map_size'].iloc[-1]:.2f}%, "
              f"final_paths={df['paths_total'].iloc[-1]}, "
              f"duration={df['time_min'].iloc[-1]:.1f}min")

    # Generate plots
    plot_coverage(all_plot_entries, all_drift_data={}, output_dir=output_dir)

    print(f"\nAnalysis complete. Plots saved to {output_dir}/")


if __name__ == "__main__":
    main()
