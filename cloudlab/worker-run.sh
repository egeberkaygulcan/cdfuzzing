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

# --- CD parameter sweep (6 reps × 2 pairs: honggfuzz and aflplusplus) ----------
#
# dist8: 8h, ultra-conservative honggfuzz sweep + AFL++ confirmation
#
# honggfuzzcd sweep — test whether very rare resets (1–3 per 8h) can help.
#   dist7 showed C≤8 always fires enough resets to hurt; C=2–3 with 0 resets
#   is pure noise.  This sweep tests C=10–20 (never tried) plus long cooldowns
#   to space resets far apart.  Rep 5 is a control (= dist7 rep1) to verify
#   the known-negative result holds at 8h.
#
#  rep | WINDOW | CONSEC | COOLDOWN | expected resets (8h) | profile
#  ----+--------+--------+----------+----------------------+---------
#   0  |   5    |   10   |   25     | ~5–10                | very conservative
#   1  |   5    |   15   |   30     | ~2–5                 | ultra-conservative
#   2  |   5    |   20   |   50     | ~1–3                 | near-monitoring
#   3  |  10    |   10   |   25     | ~3–8                 | wide window, conservative
#   4  |  10    |   15   |   50     | ~1–3                 | wide window + extreme cooldown
#   5  |   5    |    5   |   10     | ~40–60               | control (= dist7 rep1; known -6, 23R@4h)
#
# aflpluspluscd — confirm SR=1,C=10,CL=25 as best config (dist7 Rep5: +11 bugs).
#   All reps use SR=1 (det+havoc confirmed essential in dist7).
#   Reps 0–3: pure replication of best config → mean±stdev for the paper.
#   Reps 4–5: boundary probes to verify C=10 is a real sweet spot.
#
#  rep | SR | CONSEC | BOOST | COOLDOWN | profile
#  ----+----+--------+-------+----------+---------
#   0  |  1 |   10   |   1   |   25     | confirm best (rep A)
#   1  |  1 |   10   |   1   |   25     | confirm best (rep B)
#   2  |  1 |   10   |   1   |   25     | confirm best (rep C)
#   3  |  1 |   10   |   1   |   25     | confirm best (rep D)
#   4  |  1 |    8   |   1   |   25     | left boundary  (dist7 rep1 was +2)
#   5  |  1 |   12   |   1   |   25     | right boundary (more conservative)

CD_CONSECUTIVE=5
CD_STAGNATION=0.5
CD_COOLDOWN=10
CD_WINDOW=100
CD_SOFT_RESET=2
CD_HAVOC_BOOST=2

case "$FUZZER" in
    honggfuzzcd)
        case "$REP" in
            0) CD_WINDOW=5;  CD_CONSECUTIVE=10; CD_COOLDOWN=25 ;;
            1) CD_WINDOW=5;  CD_CONSECUTIVE=15; CD_COOLDOWN=30 ;;
            2) CD_WINDOW=5;  CD_CONSECUTIVE=20; CD_COOLDOWN=50 ;;
            3) CD_WINDOW=10; CD_CONSECUTIVE=10; CD_COOLDOWN=25 ;;
            4) CD_WINDOW=10; CD_CONSECUTIVE=15; CD_COOLDOWN=50 ;;
            5) CD_WINDOW=5;  CD_CONSECUTIVE=5;  CD_COOLDOWN=10 ;;  # control = dist7 rep1
        esac
        ;;
    aflpluspluscd)
        case "$REP" in
            0) CD_SOFT_RESET=1; CD_CONSECUTIVE=10; CD_HAVOC_BOOST=1; CD_COOLDOWN=25 ;;  # confirm best
            1) CD_SOFT_RESET=1; CD_CONSECUTIVE=10; CD_HAVOC_BOOST=1; CD_COOLDOWN=25 ;;  # confirm best
            2) CD_SOFT_RESET=1; CD_CONSECUTIVE=10; CD_HAVOC_BOOST=1; CD_COOLDOWN=25 ;;  # confirm best
            3) CD_SOFT_RESET=1; CD_CONSECUTIVE=10; CD_HAVOC_BOOST=1; CD_COOLDOWN=25 ;;  # confirm best
            4) CD_SOFT_RESET=1; CD_CONSECUTIVE=8;  CD_HAVOC_BOOST=1; CD_COOLDOWN=25 ;;  # left boundary
            5) CD_SOFT_RESET=1; CD_CONSECUTIVE=12; CD_HAVOC_BOOST=1; CD_COOLDOWN=25 ;;  # right boundary
        esac
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
