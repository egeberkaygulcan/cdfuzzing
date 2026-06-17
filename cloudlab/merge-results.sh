#!/bin/bash
##
# Runs on the HEAD node (called by orchestrate.sh, or by hand).
#
# Workers already publish their lightweight results directly into the merged
# layout at $SHARED/distributed/<run-id>/ar/<fuzzer>/<target>/<program>/<rep>/,
# so "merging" is mostly: sanity-check the tree, summarize what arrived, and run
# the existing analysis script against it.
#
# Usage:
#   ./merge-results.sh --run-id dist1 [--repo PATH] [--shared PATH] [--no-analyze]
##
set -uo pipefail

RUN_ID=""
DO_ANALYZE=1

[ -f /local/cdfuzz-role ] && . /local/cdfuzz-role 2>/dev/null
REPO="${REPO:-/users/eldarfin/cdfuzzing}"
SHARED="${SHARED:-/proj/cdfuzzing-PG0}"

while [ $# -gt 0 ]; do
    case "$1" in
        --run-id)     RUN_ID="$2"; shift 2;;
        --repo)       REPO="$2"; shift 2;;
        --shared)     SHARED="$2"; shift 2;;
        --no-analyze) DO_ANALYZE=0; shift;;
        *) echo "unknown arg: $1" >&2; exit 2;;
    esac
done

if [ -z "$RUN_ID" ]; then
    echo "ERROR: --run-id is required" >&2
    exit 2
fi

SHARED_RUN="$SHARED/distributed/$RUN_ID"
AR="$SHARED_RUN/ar"
PLOTS="$SHARED_RUN/plots"

log() { echo "[$(date '+%F %T')] merge: $*"; }

if [ ! -d "$AR" ]; then
    echo "ERROR: no merged ar/ at $AR (did any worker publish results?)" >&2
    exit 1
fi

# --- Inventory: which fuzzer/target/program/rep dirs actually arrived ------
log "inventory for run '$RUN_ID' under $AR"
summary="$SHARED_RUN/merge_inventory.txt"
{
    echo "# merge inventory for run $RUN_ID ($(date '+%F %T'))"
    echo "# fuzzer  programs  repetitions"
    total_progs=0
    for fdir in "$AR"/*/; do
        [ -d "$fdir" ] || continue
        fuzzer="$(basename "$fdir")"
        # count program dirs that contain at least one fuzzer_stats
        nprog=$(find "$fdir" -name fuzzer_stats 2>/dev/null | wc -l)
        reps=$(find "$fdir" -mindepth 3 -maxdepth 3 -type d 2>/dev/null \
                 | sed 's#.*/##' | sort -u | tr '\n' ',' | sed 's/,$//')
        printf "%-16s %-9s %s\n" "$fuzzer" "$nprog" "${reps:-none}"
        total_progs=$((total_progs + nprog))
    done
    echo "# total program-result dirs: $total_progs"
} | tee "$summary"

# --- Run the analysis against the merged tree ------------------------------
if [ "$DO_ANALYZE" -eq 1 ]; then
    mkdir -p "$PLOTS"
    log "running analysis -> $PLOTS"
    if command -v python3 >/dev/null 2>&1; then
        CDFUZZ_BASE="$SHARED_RUN" CDFUZZ_OUTDIR="$PLOTS" \
            python3 "$REPO/plot_seed4.py" \
            > "$SHARED_RUN/log/analysis.log" 2>&1 \
            && log "analysis complete; see $PLOTS and $SHARED_RUN/log/analysis.log" \
            || log "analysis script returned non-zero; check $SHARED_RUN/log/analysis.log"
    else
        log "python3 not found; skipping analysis"
    fi
fi

log "merge complete: $SHARED_RUN"
echo
echo "Merged results : $AR"
echo "Inventory      : $summary"
echo "Plots/tables   : $PLOTS"
echo "Re-run analysis: CDFUZZ_BASE=$SHARED_RUN CDFUZZ_OUTDIR=$PLOTS python3 $REPO/plot_seed4.py"
