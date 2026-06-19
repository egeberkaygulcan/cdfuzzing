#!/bin/bash
##
# Runs on a WORKER node (invoked over SSH by orchestrate.sh, or by hand).
#
# It fuzzes ONE fuzzer over the requested Magma targets on the local /mydata
# disk via the existing captain runner, then copies the lightweight results
# (everything except the multi-GB queue/ corpora) into the shared merge
# directory under the repetition id taken from this node's --rep.
#
# Usage:
#   worker-run.sh --fuzzer F --rep N --run-id ID --timeout 8h \
#                 [--targets "sqlite3 libpng ..."] [--repo PATH] [--shared PATH]
#
# Parameter design (dist2 — winning params from dist1 A/B, both reps identical):
#   Both reps of each CD fuzzer now use the same winning parameter set so that
#   the two reps are genuine statistical repetitions for CD-vs-baseline analysis.
#
#   Fuzzer          C   SF    dist1 basis
#   aflcd           3  0.5   rep1 won (+10268 cov, 15 vs 6 resets)
#   aflpluspluscd   8  0.5   rep1 won (+3388 cov, 19 vs 18 resets)
#   fairfuzzcd      3  0.5   rep0 won (+4941 cov); blacklist bug fixed in dist2
#   moptaflcd       5  0.3   rep1 won (+3113 cov, 31 vs 25 resets)
#   aflfastcd       3  0.5   rep1 won (+1995 cov, 3 vs 3 resets)
#   honggfuzzcd     5  0.5   both had 0 CD activity (init bug); default kept
##
set -uo pipefail

FUZZER=""
REP="0"
RUN_ID=""
TIMEOUT="8h"
TARGETS="sqlite3 libpng lua libsndfile libtiff libxml2 poppler php openssl"
REPO="/local/repository"
SHARED="/proj/cdfuzzing-PG0"

# Inherit role defaults written at boot if present.
[ -f /local/cdfuzz-role ] && . /local/cdfuzz-role 2>/dev/null

while [ $# -gt 0 ]; do
    case "$1" in
        --fuzzer)  FUZZER="$2"; shift 2;;
        --rep)     REP="$2"; shift 2;;
        --run-id)  RUN_ID="$2"; shift 2;;
        --timeout) TIMEOUT="$2"; shift 2;;
        --targets) TARGETS="$2"; shift 2;;
        --repo)    REPO="$2"; shift 2;;
        --shared)  SHARED="$2"; shift 2;;
        *) echo "unknown arg: $1" >&2; shift;;
    esac
done

if [ -z "$FUZZER" ] || [ -z "$RUN_ID" ]; then
    echo "ERROR: --fuzzer and --run-id are required" >&2
    exit 2
fi

MAGMA="$REPO/magma"
CAPTAIN="$MAGMA/tools/captain"
LOCALWORK="/mydata/$RUN_ID"
SHARED_RUN="$SHARED/distributed/$RUN_ID"
STATUS_DIR="$SHARED_RUN/status"
NODE_TAG="${FUZZER}-${REP}"

log() { echo "[$(date '+%F %T')] worker($NODE_TAG): $*"; }

mkdir -p "$LOCALWORK" "$STATUS_DIR" "$SHARED_RUN/log"
rm -f "$STATUS_DIR/${NODE_TAG}.done" "$STATUS_DIR/${NODE_TAG}.failed"
echo "$(date '+%F %T') started on $(hostname)" > "$STATUS_DIR/${NODE_TAG}.running"

# --- Per-fuzzer CD parameter selection (dist3: bug-fix params) ----
# honggfuzz: code-fixed (peak_corpus + time-gate in honggfuzz.c); WINDOW=5 means
#            5 time-gated samples (each ~60s) per KS window = 5-min comparison.
# fairfuzz:  C=15 (rare-branch rebuild takes 10-30 min; C=3 was too destructive).
# afl/afl++: COOLDOWN=25 (prevent 3+ resets on same program within one campaign).
# moptafl/aflfast: unchanged (working well in dist2).
CD_CONSECUTIVE=5
CD_STAGNATION=0.5
CD_COOLDOWN=10
CD_WINDOW=100
CD_SOFT_RESET=2   # 0=full-corpus-reset 1=det+havoc 2=havoc-only
CD_HAVOC_BOOST=2  # havoc energy multiplier after reset
if [[ "$FUZZER" == *cd ]]; then
    case "$FUZZER" in
        aflcd)         CD_CONSECUTIVE=5; CD_STAGNATION=0.5; CD_COOLDOWN=25 ;;
        aflpluspluscd) CD_CONSECUTIVE=8; CD_STAGNATION=0.5; CD_COOLDOWN=25 ;;
        fairfuzzcd)    CD_CONSECUTIVE=15; CD_STAGNATION=0.5 ;;
        honggfuzzcd)   CD_CONSECUTIVE=5;  CD_STAGNATION=0.5; CD_WINDOW=5 ;;
    esac
fi

# Rep 2: parameter sweep — test SOFT_RESET=1 (det+havoc) for AFL-based fuzzers
# and tighter drift window for honggfuzzcd.  Non-CD reps 2 are pure replications.
if [[ "$REP" == "2" ]] && [[ "$FUZZER" == *cd ]]; then
    case "$FUZZER" in
        aflcd)         CD_SOFT_RESET=1; CD_HAVOC_BOOST=1 ;;
        aflpluspluscd) CD_SOFT_RESET=1; CD_HAVOC_BOOST=1; CD_CONSECUTIVE=6 ;;
        fairfuzzcd)    CD_SOFT_RESET=1; CD_HAVOC_BOOST=1 ;;
        honggfuzzcd)   CD_WINDOW=3; CD_CONSECUTIVE=3 ;;  # monitoring-only sensitivity test
    esac
    log "REP=2 sweep: SOFT_RESET=$CD_SOFT_RESET HAVOC_BOOST=$CD_HAVOC_BOOST CONSECUTIVE=$CD_CONSECUTIVE WINDOW=$CD_WINDOW"
fi
log "CD params: CONSECUTIVE=$CD_CONSECUTIVE STAGNATION=$CD_STAGNATION COOLDOWN=$CD_COOLDOWN WINDOW=$CD_WINDOW SOFT_RESET=$CD_SOFT_RESET HAVOC_BOOST=$CD_HAVOC_BOOST"

# --- Generate a single-fuzzer captainrc -----------------------------------
CAPTAINRC="$LOCALWORK/captainrc_${NODE_TAG}"
{
    echo "WORKDIR=$LOCALWORK"
    echo "REPEAT=1"
    echo "TIMEOUT=$TIMEOUT"
    echo "POLL=5"
    echo "CACHE_ON_DISK=1"
    echo "NO_ARCHIVE=1"
    echo "MAGMA=$MAGMA"
    echo ""
    echo "FUZZERS=($FUZZER)"
    echo "${FUZZER}_TARGETS=($TARGETS)"
    echo ""
    echo "# CD drift parameters (no effect on baseline fuzzers)"
    echo "export AFL_DRIFT_WINDOW=$CD_WINDOW"
    echo "export AFL_DRIFT_THRESHOLD=0.05"
    echo "export AFL_DRIFT_SOFT_RESET=$CD_SOFT_RESET"
    echo "export AFL_DRIFT_MAX_RESETS=0"
    echo "export AFL_DRIFT_HAVOC_BOOST=$CD_HAVOC_BOOST"
    echo "export AFL_DRIFT_BOOST_CYCLES=1"
    echo "export AFL_DRIFT_COOLDOWN=$CD_COOLDOWN"
    echo "export AFL_DRIFT_CONSECUTIVE=$CD_CONSECUTIVE"
    echo "export AFL_DRIFT_EMA_ALPHA=0.1"
    echo "export AFL_DRIFT_STAGNATION_FACTOR=$CD_STAGNATION"
} > "$CAPTAINRC"
log "captainrc -> $CAPTAINRC"

# --- Run the campaign ------------------------------------------------------
log "launching captain (timeout=$TIMEOUT, targets: $TARGETS)"
cd "$CAPTAIN"
RC=0
bash run.sh "$CAPTAINRC" > "$SHARED_RUN/log/${NODE_TAG}.log" 2>&1 || RC=$?
log "captain finished (rc=$RC)"

# --- Publish lightweight results into the merged layout --------------------
# captain writes ar/<fuzzer>/<target>/<program>/0/ (REPEAT=1 -> cid 0).
# Re-home each program's results under this node's repetition id ($REP) so the
# 2-nodes-per-fuzzer layout becomes 2 repetitions in the merged tree.
copied=0
shopt -s nullglob
for cid_dir in "$LOCALWORK"/ar/"$FUZZER"/*/*/0; do
    rel="${cid_dir#"$LOCALWORK"/ar/}"      # fuzzer/target/program/0
    base="${rel%/0}"                        # fuzzer/target/program
    dest="$SHARED_RUN/ar/$base/$REP"
    mkdir -p "$dest"
    rsync -a \
        --exclude 'queue/' \
        --exclude 'corpus/' \
        --exclude '.cur_input' \
        --exclude '.synced/' \
        "$cid_dir"/ "$dest"/ 2>/dev/null
    copied=$((copied + 1))
done
shopt -u nullglob
log "published $copied program result dirs to $SHARED_RUN/ar"

# --- Mark completion -------------------------------------------------------
rm -f "$STATUS_DIR/${NODE_TAG}.running"
if [ "$RC" -eq 0 ] && [ "$copied" -gt 0 ]; then
    echo "$(date '+%F %T') ok programs=$copied" > "$STATUS_DIR/${NODE_TAG}.done"
    log "DONE"
else
    echo "$(date '+%F %T') rc=$RC programs=$copied" > "$STATUS_DIR/${NODE_TAG}.failed"
    log "FAILED (rc=$RC, programs=$copied) — see $SHARED_RUN/log/${NODE_TAG}.log"
fi
exit "$RC"
