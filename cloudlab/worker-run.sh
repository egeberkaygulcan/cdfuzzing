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
#   worker-run.sh --fuzzer F --rep N --run-id ID --timeout 24h \
#                 [--targets "sqlite3 libpng ..."] [--repo PATH] [--shared PATH]
##
set -uo pipefail

FUZZER=""
REP="0"
RUN_ID=""
TIMEOUT="24h"
TARGETS="sqlite3 libpng lua libsndfile libtiff libxml2 poppler php openssl"
REPO="/users/eldarfin/cdfuzzing"
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
    echo "export AFL_DRIFT_WINDOW=100"
    echo "export AFL_DRIFT_THRESHOLD=0.05"
    echo "export AFL_DRIFT_SOFT_RESET=2"
    echo "export AFL_DRIFT_MAX_RESETS=0"
    echo "export AFL_DRIFT_HAVOC_BOOST=2"
    echo "export AFL_DRIFT_BOOST_CYCLES=1"
    echo "export AFL_DRIFT_COOLDOWN=10"
    echo "export AFL_DRIFT_CONSECUTIVE=5"
    echo "export AFL_DRIFT_EMA_ALPHA=0.1"
    echo "export AFL_DRIFT_STAGNATION_FACTOR=0.5"
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
