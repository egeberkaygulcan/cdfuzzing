#!/bin/bash
##
# Runs on the HEAD node. Dispatches one fuzzing campaign to every worker over
# SSH, waits for all workers to finish, then merges + analyzes the results.
#
# Workers fuzz on their own local disk and publish lightweight results into
#   $SHARED/distributed/<run-id>/ar/<fuzzer>/<target>/<program>/<rep>/
# so once every worker is done the merge is just "point the analysis at it".
#
# Usage:
#   ./orchestrate.sh --run-id dist1 [--timeout 24h] [--targets "sqlite3 libpng"]
#                    [--fuzzers "afl aflcd"] [--no-merge] [--dry-run]
#
# Re-running with the same --run-id resumes: workers already marked .done are
# skipped, so you can relaunch after a transient SSH/node failure.
##
set -uo pipefail

RUN_ID=""
TIMEOUT="24h"
TARGETS="sqlite3 libpng lua libsndfile libtiff libxml2 poppler php openssl"
ONLY_FUZZERS=""
DO_MERGE=1
DRY_RUN=0
POLL_SECONDS=60

[ -f /local/cdfuzz-role ] && . /local/cdfuzz-role 2>/dev/null
REPO="${REPO:-/local/repository}"
SHARED="${SHARED:-/proj/cdfuzzing-PG0}"
USER_NAME="${USER_NAME:-$(whoami)}"

while [ $# -gt 0 ]; do
    case "$1" in
        --run-id)   RUN_ID="$2"; shift 2;;
        --timeout)  TIMEOUT="$2"; shift 2;;
        --targets)  TARGETS="$2"; shift 2;;
        --fuzzers)  ONLY_FUZZERS="$2"; shift 2;;
        --repo)     REPO="$2"; shift 2;;
        --shared)   SHARED="$2"; shift 2;;
        --no-merge) DO_MERGE=0; shift;;
        --dry-run)  DRY_RUN=1; shift;;
        --poll)     POLL_SECONDS="$2"; shift 2;;
        *) echo "unknown arg: $1" >&2; exit 2;;
    esac
done

if [ -z "$RUN_ID" ]; then
    echo "ERROR: --run-id is required" >&2
    exit 2
fi

MANIFEST="$SHARED/cluster/manifest.txt"
SHARED_RUN="$SHARED/distributed/$RUN_ID"
STATUS_DIR="$SHARED_RUN/status"

log() { echo "[$(date '+%F %T')] orchestrate: $*"; }

if [ ! -f "$MANIFEST" ]; then
    echo "ERROR: manifest not found at $MANIFEST (is this the head node, and did setup run?)" >&2
    exit 1
fi

mkdir -p "$STATUS_DIR" "$SHARED_RUN/ar" "$SHARED_RUN/log"

# Build the worker list from the manifest (skip the head row).
declare -a W_NAME W_IP W_FUZZER W_REP
while read -r name ip fuzzer rep; do
    case "$name" in ''|'#'*|head) continue;; esac
    if [ -n "$ONLY_FUZZERS" ] && ! grep -qw -- "$fuzzer" <<< "$ONLY_FUZZERS"; then
        continue
    fi
    W_NAME+=("$name"); W_IP+=("$ip"); W_FUZZER+=("$fuzzer"); W_REP+=("$rep")
done < "$MANIFEST"

N=${#W_NAME[@]}
if [ "$N" -eq 0 ]; then
    echo "ERROR: no workers selected" >&2
    exit 1
fi
log "run-id=$RUN_ID  workers=$N  timeout=$TIMEOUT"
log "shared run dir: $SHARED_RUN"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -o BatchMode=yes"

# --- Dispatch --------------------------------------------------------------
launched=0
skipped=0
for idx in "${!W_NAME[@]}"; do
    name="${W_NAME[$idx]}"; ip="${W_IP[$idx]}"
    fuzzer="${W_FUZZER[$idx]}"; rep="${W_REP[$idx]}"
    tag="${fuzzer}-${rep}"

    if [ -f "$STATUS_DIR/${tag}.done" ]; then
        log "skip $name (already .done)"
        skipped=$((skipped + 1))
        continue
    fi

    remote_cmd="nohup bash -c 'cd $REPO && git pull --ff-only >> /mydata/${RUN_ID}-${tag}.boot.log 2>&1; bash $REPO/cloudlab/worker-run.sh --fuzzer $fuzzer --rep $rep --run-id $RUN_ID --timeout $TIMEOUT --targets \"$TARGETS\" --repo $REPO --shared $SHARED >> /mydata/${RUN_ID}-${tag}.boot.log 2>&1' &"

    if [ "$DRY_RUN" -eq 1 ]; then
        echo "DRY: ssh $USER_NAME@$ip -- $remote_cmd"
        continue
    fi

    log "dispatch -> $name ($ip): $fuzzer rep=$rep"
    rm -f "$STATUS_DIR/${tag}.failed"
    if ssh $SSH_OPTS "$USER_NAME@$ip" "$remote_cmd" </dev/null; then
        launched=$((launched + 1))
    else
        log "WARNING: failed to start worker on $name ($ip)"
        echo "$(date '+%F %T') ssh-dispatch-failed" > "$STATUS_DIR/${tag}.failed"
    fi
done

if [ "$DRY_RUN" -eq 1 ]; then
    log "dry-run complete ($N workers would be dispatched)"
    exit 0
fi
log "dispatched=$launched skipped=$skipped"

# --- Wait for completion ---------------------------------------------------
log "waiting for $N workers to finish (poll every ${POLL_SECONDS}s)"
while :; do
    done_n=$(ls "$STATUS_DIR"/*.done 2>/dev/null | wc -l)
    fail_n=$(ls "$STATUS_DIR"/*.failed 2>/dev/null | wc -l)
    run_n=$(ls "$STATUS_DIR"/*.running 2>/dev/null | wc -l)
    finished=$((done_n + fail_n))
    log "progress: done=$done_n failed=$fail_n running=$run_n  ($finished/$N)"
    [ "$finished" -ge "$N" ] && break
    sleep "$POLL_SECONDS"
done

done_n=$(ls "$STATUS_DIR"/*.done 2>/dev/null | wc -l)
fail_n=$(ls "$STATUS_DIR"/*.failed 2>/dev/null | wc -l)
log "all workers finished: done=$done_n failed=$fail_n"
if [ "$fail_n" -gt 0 ]; then
    log "failed workers:"
    for f in "$STATUS_DIR"/*.failed; do log "  - $(basename "${f%.failed}")"; done
fi

# --- Merge + analyze -------------------------------------------------------
if [ "$DO_MERGE" -eq 1 ]; then
    log "merging + analyzing"
    bash "$REPO/cloudlab/merge-results.sh" --run-id "$RUN_ID" --repo "$REPO" --shared "$SHARED"
fi

log "orchestration complete: $SHARED_RUN"
