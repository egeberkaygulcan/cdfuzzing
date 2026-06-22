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
FUZZER_SEED="" # set below from REP
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

# --- Per-rep paired seed (baseline and CD variant share the same PRNG seed) ---
# Both honggfuzz_N and honggfuzzcd_N use seed 1000+N, so the only variable is
# whether CD is active.  Same for aflplusplus_N / aflpluspluscd_N.
FUZZER_SEED=$(( 1000 + REP ))

# --- CD parameter tables -------------------------------------------------------
#
# All CD fuzzers use confirmed best parameters from dist2–dist9.  All reps are
# identical so each rep is a genuine statistical repetition.
#
# Confirmed best params by fuzzer (AFL-based: W=100, threshold=0.05, SR=1, BOOST=1):
#
#   Fuzzer         W    C   CL   Evidence
#   aflcd         100   3   10   dist2 +3 bugs; dist5 +4 bugs
#   aflpluspluscd 100  12   25   dist7–dist9: +11/+8/+6 bugs; SR=1 essential
#   fairfuzzcd    100   3   10   dist2 corrected; dist6 +1 bug
#   moptaflcd     100   5   10   dist2 +6 bugs; dist5 +1 bug
#   aflfastcd     100   3   10   dist2 +5 bugs; dist5 +5 bugs
#   honggfuzzcd     5   2    5   dist9 rep0: +1 bug, 10 resets (only C/CL-correct run;
#                                overall negative result — see DEBUGGING.md).
#                                W=5 + DRIFT_SAMPLE_SEC=60: C=2 = 2 consecutive stagnation
#                                minutes.  Only config that fired a controlled reset rate
#                                (~10/21 progs over 8h) and showed positive signal.
#                                All higher C values either over-reset (C=3: 30 resets,
#                                Δ=0) or never fired (C≥8: seed never stagnated).

# Defaults (safe fallback for any unrecognised fuzzer / baseline).
CD_CONSECUTIVE=5
CD_STAGNATION=0.5
CD_COOLDOWN=10
CD_WINDOW=100
CD_SOFT_RESET=2
CD_HAVOC_BOOST=2

case "$FUZZER" in
    # --- AFL-based CD fuzzers: confirmed best params, all reps identical --------
    aflcd)
        CD_SOFT_RESET=1; CD_CONSECUTIVE=3; CD_HAVOC_BOOST=1; CD_COOLDOWN=10
        ;;
    fairfuzzcd)
        CD_SOFT_RESET=1; CD_CONSECUTIVE=3; CD_HAVOC_BOOST=1; CD_COOLDOWN=10
        ;;
    moptaflcd)
        CD_SOFT_RESET=1; CD_CONSECUTIVE=5; CD_HAVOC_BOOST=1; CD_COOLDOWN=10
        ;;
    aflfastcd)
        CD_SOFT_RESET=1; CD_CONSECUTIVE=3; CD_HAVOC_BOOST=1; CD_COOLDOWN=10
        ;;
    aflpluspluscd)
        # Confirmed best across dist7–dist9.  All reps use the same config.
        CD_SOFT_RESET=1; CD_CONSECUTIVE=12; CD_HAVOC_BOOST=1; CD_COOLDOWN=25
        ;;
    # --- honggfuzzcd: confirmed best params, all reps identical -------------------
    honggfuzzcd)
        # W=5, DRIFT_SAMPLE_SEC=60 → C=2 = 2 consecutive stagnation minutes.
        # Only config (dist9 rep0) that fired a controlled reset rate and showed
        # positive signal (+1 bug, 10 resets / 21 programs over 8h).
        CD_WINDOW=5; CD_CONSECUTIVE=2; CD_COOLDOWN=5
        ;;
esac
log "seed=$FUZZER_SEED CD params: W=$CD_WINDOW C=$CD_CONSECUTIVE SR=$CD_SOFT_RESET BOOST=$CD_HAVOC_BOOST CL=$CD_COOLDOWN SF=$CD_STAGNATION"

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
    echo "# Paired PRNG seed — baseline and CD variant use the same value per rep"
    echo "export FUZZER_SEED=$FUZZER_SEED"
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
# --- NFS space pre-check ---------------------------------------------------
FREE_GB=$(df --output=avail -BG "$SHARED" 2>/dev/null | tail -1 | tr -d 'G ')
if [[ -n "$FREE_GB" && "$FREE_GB" -lt 10 ]]; then
    log "WARN: NFS has only ${FREE_GB}G free — rsync may fail due to quota exceeded"
fi

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
    if rsync -a \
        --exclude 'queue/' \
        --exclude 'corpus/' \
        --exclude '*.honggfuzz.cov' \
        --exclude '.cur_input' \
        --exclude '.synced/' \
        "$cid_dir"/ "$dest"/ 2>>"$SHARED_RUN/log/${NODE_TAG}.log"; then
        copied=$((copied + 1))
    else
        log "WARN: rsync failed for $cid_dir (NFS quota or I/O error — check log)"
    fi
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
