#!/usr/bin/env bash
##
# run_local.sh — Single-machine evaluation entry point for drift-aware fuzzing.
#
# Runs one or more fuzzer-target campaigns using the Magma captain orchestrator.
# Generates a captainrc from command-line options and calls captain/run.sh.
#
# Usage:
#   bash run_local.sh [OPTIONS]
#
# Options:
#   --kick-the-tires         Quick sanity check: builds images, runs 10-min campaign,
#                            verifies drift detection fires (see below)
#   --fuzzers  "F1 F2 ..."   Fuzzers to run (default: "afl aflcd")
#   --targets  "T1 T2 ..."   Magma targets  (default: "sqlite3 libpng")
#   --timeout  DURATION      Per-campaign duration: 10m, 1h, 24h (default: 1h)
#   --reps     N             Repetitions per fuzzer-program pair (default: 1)
#   --outdir   PATH          Output directory (default: ./workdir)
#   --workers  N             Max parallel campaigns (default: all CPU cores)
#   --seed     N             Base FUZZER_SEED; rep i uses seed+i (default: 1000)
#   --help                   Show this message
#
# Kick-the-tires mode (--kick-the-tires):
#   Runs AFL (baseline) and AFLCD side-by-side on libpng for 10 minutes using
#   deliberately aggressive CD parameters (W=5, C=1, CL=1, guard disabled) so
#   that at least one corpus reset fires within the short window. On exit it
#   checks that:
#     1. Both campaigns completed without error.
#     2. The CD module produced a drift log for aflcd.
#     3. At least one reset was recorded in that log.
#   Typical runtime: ~10 minutes (image build time on first run: +5-10 minutes).
#
# Example — quick single pair:
#   bash run_local.sh --fuzzers "afl aflcd" --targets "sqlite3" --timeout 1h --reps 2
#
# Example — full AFL pair, all targets, 10 reps:
#   bash run_local.sh \
#     --fuzzers "afl aflcd" \
#     --targets "sqlite3 libpng lua libsndfile libtiff libxml2 poppler php openssl" \
#     --timeout 24h --reps 10 --outdir ./results/afl_pair
##
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAGMA="${MAGMA:-$SCRIPT_DIR/magma}"
CAPTAIN="$MAGMA/tools/captain"

# --- Defaults ---
FUZZERS="afl aflcd"
TARGETS="sqlite3 libpng"
TIMEOUT="1h"
REPS=1
OUTDIR="$SCRIPT_DIR/workdir"
WORKERS=""
BASE_SEED=1000
KICK_THE_TIRES=0

# --- Parse arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --fuzzers)  FUZZERS="$2";  shift 2 ;;
        --targets)  TARGETS="$2";  shift 2 ;;
        --timeout)  TIMEOUT="$2";  shift 2 ;;
        --reps)     REPS="$2";     shift 2 ;;
        --outdir)   OUTDIR="$2";   shift 2 ;;
        --workers)  WORKERS="$2";  shift 2 ;;
        --seed)            BASE_SEED="$2"; shift 2 ;;
        --kick-the-tires)  KICK_THE_TIRES=1; shift ;;
        --help|-h)
            sed -n '/^# Usage/,/^##$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

# --- Kick-the-tires mode overrides -----------------------------------------
if [[ "$KICK_THE_TIRES" -eq 1 ]]; then
    FUZZERS="afl aflcd"
    TARGETS="libpng"
    TIMEOUT="10m"
    REPS=1
    OUTDIR="${OUTDIR:-$SCRIPT_DIR/workdir-ktt}"
    # Aggressive CD parameters so a reset fires within 10 minutes:
    #   W=5    (tiny window — drift detected almost immediately after stagnation)
    #   C=1    (fire on the very first confirmed stagnant window)
    #   CL=1   (minimal cooldown — allow rapid successive resets)
    #   SF=0.0 (disable EMA stagnation guard — never suppress the KS test)
    KTT_CD_OVERRIDE="AFL_DRIFT_WINDOW=5 AFL_DRIFT_CONSECUTIVE=1 AFL_DRIFT_COOLDOWN=1 AFL_DRIFT_STAGNATION_FACTOR=0.0"
fi

# --- Validate ---
if ! command -v docker &>/dev/null; then
    echo "ERROR: docker not found. Install Docker and ensure it is in PATH." >&2
    exit 1
fi

if [[ ! -d "$CAPTAIN" ]]; then
    echo "ERROR: captain not found at $CAPTAIN. Is MAGMA set correctly?" >&2
    exit 1
fi

# --- CD parameter table (paper-confirmed best per fuzzer) ------------------
# These values match the paper evaluation (Section IV, Table II).
# Override by exporting AFL_DRIFT_* variables before calling this script.
cd_params_for() {
    local fuzzer="$1"
    # In kick-the-tires mode, CD fuzzers use aggressive parameters instead.
    if [[ "$KICK_THE_TIRES" -eq 1 ]]; then
        case "$fuzzer" in
            *cd) echo "$KTT_CD_OVERRIDE AFL_DRIFT_SOFT_RESET=1 AFL_DRIFT_HAVOC_BOOST=1"; return ;;
        esac
    fi
    case "$fuzzer" in
        aflcd)
            echo "AFL_DRIFT_WINDOW=100 AFL_DRIFT_CONSECUTIVE=3 AFL_DRIFT_COOLDOWN=10 AFL_DRIFT_SOFT_RESET=1 AFL_DRIFT_HAVOC_BOOST=1"
            ;;
        aflfastcd)
            echo "AFL_DRIFT_WINDOW=100 AFL_DRIFT_CONSECUTIVE=3 AFL_DRIFT_COOLDOWN=10 AFL_DRIFT_SOFT_RESET=1 AFL_DRIFT_HAVOC_BOOST=1"
            ;;
        moptaflcd)
            echo "AFL_DRIFT_WINDOW=100 AFL_DRIFT_CONSECUTIVE=5 AFL_DRIFT_COOLDOWN=10 AFL_DRIFT_SOFT_RESET=1 AFL_DRIFT_HAVOC_BOOST=1"
            ;;
        aflpluspluscd)
            echo "AFL_DRIFT_WINDOW=100 AFL_DRIFT_CONSECUTIVE=12 AFL_DRIFT_COOLDOWN=25 AFL_DRIFT_SOFT_RESET=1 AFL_DRIFT_HAVOC_BOOST=1"
            ;;
        fairfuzzcd)
            echo "AFL_DRIFT_WINDOW=100 AFL_DRIFT_CONSECUTIVE=3 AFL_DRIFT_COOLDOWN=10 AFL_DRIFT_SOFT_RESET=1 AFL_DRIFT_HAVOC_BOOST=1"
            ;;
        honggfuzzcd)
            echo "AFL_DRIFT_WINDOW=5 AFL_DRIFT_CONSECUTIVE=2 AFL_DRIFT_COOLDOWN=5 AFL_DRIFT_KEEP_RECENT=50"
            ;;
        *)
            # Baseline fuzzers: no CD parameters needed (variables are ignored)
            echo ""
            ;;
    esac
}

# --- Build per-rep captainrc files and run them ----------------------------
mkdir -p "$OUTDIR"
FUZZERS_ARRAY=($FUZZERS)
TARGETS_ARRAY=($TARGETS)

echo "=========================================="
if [[ "$KICK_THE_TIRES" -eq 1 ]]; then
    echo " Drift-Aware Fuzzing — Kick the Tires"
else
    echo " Drift-Aware Fuzzing — Local Evaluation"
fi
echo "=========================================="
echo "  Fuzzers:  $FUZZERS"
echo "  Targets:  $TARGETS"
echo "  Timeout:  $TIMEOUT per campaign"
echo "  Reps:     $REPS"
echo "  Outdir:   $OUTDIR"
echo "  Base seed: $BASE_SEED"
[[ -n "$WORKERS" ]] && echo "  Workers:  $WORKERS"
echo "=========================================="

for rep in $(seq 0 $((REPS - 1))); do
    FUZZER_SEED=$(( BASE_SEED + rep ))
    REP_OUTDIR="$OUTDIR/rep${rep}"
    CAPTAINRC="$REP_OUTDIR/captainrc"
    mkdir -p "$REP_OUTDIR"

    # Build captainrc for this repetition
    {
        echo "# Auto-generated by run_local.sh (rep=$rep, seed=$FUZZER_SEED)"
        echo "WORKDIR=$REP_OUTDIR"
        echo "REPEAT=1"
        echo "TIMEOUT=$TIMEOUT"
        echo "POLL=5"
        echo "CACHE_ON_DISK=1"
        echo "NO_ARCHIVE=1"
        echo "MAGMA=$MAGMA"
        [[ -n "$WORKERS" ]] && echo "WORKERS=$WORKERS"
        echo ""
        echo "FUZZERS=(${FUZZERS_ARRAY[*]})"
        echo ""
        for fuzzer in "${FUZZERS_ARRAY[@]}"; do
            echo "${fuzzer}_TARGETS=(${TARGETS_ARRAY[*]})"
        done
        echo ""
        echo "# Paired PRNG seed (baseline and CD variant share the same seed per rep)"
        echo "export FUZZER_SEED=$FUZZER_SEED"
        echo ""
        echo "# CD drift parameters (ignored by baseline fuzzers)"
        echo "export AFL_DRIFT_THRESHOLD=0.05"
        echo "export AFL_DRIFT_EMA_ALPHA=0.1"
        echo "export AFL_DRIFT_STAGNATION_FACTOR=0.5"
        echo "export AFL_DRIFT_MAX_RESETS=0"
        echo "export AFL_DRIFT_BOOST_CYCLES=1"
        echo "export AFL_DRIFT_KEEP_RECENT=0"
        echo ""
        echo "# Per-fuzzer CD parameters"
        for fuzzer in "${FUZZERS_ARRAY[@]}"; do
            params="$(cd_params_for "$fuzzer")"
            if [[ -n "$params" ]]; then
                echo "# $fuzzer"
                for kv in $params; do
                    echo "export $kv"
                done
            fi
        done
    } > "$CAPTAINRC"

    echo ""
    echo "--- Rep $rep (seed=$FUZZER_SEED) ---"
    echo "captainrc: $CAPTAINRC"

    cd "$CAPTAIN"
    bash run.sh "$CAPTAINRC"
    cd "$SCRIPT_DIR"

    # Flatten rep results into the shared ar/ tree:
    #   rep<N>/ar/<fuzzer>/<target>/<program>/0/  ->  ar/<fuzzer>/<target>/<program>/<N>/
    shopt -s nullglob
    for cid_dir in "$REP_OUTDIR"/ar/*/*/0; do
        rel="${cid_dir#"$REP_OUTDIR"/ar/}"   # fuzzer/target/program/0
        base="${rel%/0}"                      # fuzzer/target/program
        dest="$OUTDIR/ar/$base/$rep"
        mkdir -p "$dest"
        rsync -a \
            --exclude 'queue/' \
            --exclude 'corpus/' \
            --exclude 'output/' \
            --exclude '.cur_input' \
            --exclude '.synced/' \
            "$cid_dir"/ "$dest"/
    done
    shopt -u nullglob
done

echo ""
echo "=========================================="
echo " All campaigns complete."
echo " Results: $OUTDIR/ar/"
echo "=========================================="

# --- Kick-the-tires verification -------------------------------------------
if [[ "$KICK_THE_TIRES" -eq 1 ]]; then
    echo ""
    echo "--- Kick-the-tires checks ---"
    KTT_PASS=1

    # 1. Drift log must exist for aflcd (confirms the CD module ran).
    DRIFT_LOG=$(find "$OUTDIR/ar/aflcd" -name "drift_log.csv" 2>/dev/null | head -1)
    if [[ -z "$DRIFT_LOG" ]]; then
        echo "[FAIL] drift_log.csv not found under $OUTDIR/ar/aflcd/"
        echo "       The CD module did not produce output. Check that the aflcd"
        echo "       Docker image built correctly (look for build errors above)."
        KTT_PASS=0
    else
        echo "[OK]   drift_log.csv found: $DRIFT_LOG"

        # 2. At least one reset must have been recorded.
        RESET_COUNT=$(awk -F',' 'NR>1 && $NF=="1" {c++} END {print c+0}' "$DRIFT_LOG" 2>/dev/null)
        # Fallback: count lines containing "reset" (case-insensitive) if column check yields 0.
        if [[ "$RESET_COUNT" -eq 0 ]]; then
            RESET_COUNT=$(grep -ci "reset" "$DRIFT_LOG" 2>/dev/null || true)
        fi

        if [[ "$RESET_COUNT" -gt 0 ]]; then
            echo "[OK]   $RESET_COUNT reset(s) recorded in drift log."
        else
            echo "[WARN] No resets found in drift_log.csv."
            echo "       The CD module ran but did not trigger a reset in 10 minutes."
            echo "       This is unexpected with the aggressive kick-the-tires parameters."
            echo "       Inspect $DRIFT_LOG to see what p-values were recorded."
            KTT_PASS=0
        fi
    fi

    echo ""
    if [[ "$KTT_PASS" -eq 1 ]]; then
        echo "=============================="
        echo " KICK-THE-TIRES: PASSED"
        echo "=============================="
        echo " The drift detection module is working correctly."
        echo " Proceed with a full evaluation using --timeout 24h --reps 10."
    else
        echo "=============================="
        echo " KICK-THE-TIRES: FAILED"
        echo "=============================="
        echo " See [FAIL] / [WARN] messages above for next steps."
        exit 1
    fi
fi
