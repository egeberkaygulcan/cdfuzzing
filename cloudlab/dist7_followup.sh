#!/bin/bash
##
# dist7_followup.sh — runs automatically after dist7 finishes.
#
# 1. Polls until all 24 dist7 workers are done.
# 2. Runs merge-results.sh (analysis + plots).
# 3. Checks the summary_table.txt for satisfactory results:
#      "satisfactory" = at least one rep with Δbugs > 0 for BOTH pairs.
# 4. Writes a verdict to /proj/cdfuzzing-PG0/distributed/dist7_verdict.txt.
# 5. If unsatisfactory AND --auto-dist8 is passed, launches dist8 with the
#    escalation parameter set (see bottom of file).
#
# Usage:
#   bash dist7_followup.sh [--auto-dist8]
##
set -uo pipefail

REPO="${REPO:-/local/repository}"
SHARED="${SHARED:-/proj/cdfuzzing-PG0}"
AUTO_DIST8=0
[ "${1:-}" = "--auto-dist8" ] && AUTO_DIST8=1

SHARED_RUN="$SHARED/distributed/dist7"
STATUS_DIR="$SHARED_RUN/status"

log() { echo "[$(date '+%F %T')] followup: $*"; }

# ---------------------------------------------------------------------------
# 1. Wait for all 24 dist7 workers
# ---------------------------------------------------------------------------
EXPECTED=24
log "waiting for dist7 ($EXPECTED workers)..."
while true; do
    done=$(ls "$STATUS_DIR"/*.done  2>/dev/null | wc -l)
    fail=$(ls "$STATUS_DIR"/*.failed 2>/dev/null | wc -l)
    run=$(ls  "$STATUS_DIR"/*.running 2>/dev/null | wc -l)
    log "progress: done=$done failed=$fail running=$run / $EXPECTED"
    [ "$done" -ge "$EXPECTED" ] && break
    [ "$fail" -gt 0 ] && log "WARNING: $fail worker(s) failed"
    sleep 60
done
log "all workers done (done=$done failed=$fail)"

# ---------------------------------------------------------------------------
# 2. Run analysis
# ---------------------------------------------------------------------------
log "running merge-results.sh..."
bash "$REPO/cloudlab/merge-results.sh" \
    --run-id dist7 --repo "$REPO" --shared "$SHARED"
log "analysis complete"

# ---------------------------------------------------------------------------
# 3. Check verdict: is any rep Δbugs > 0 for both pairs?
# ---------------------------------------------------------------------------
SUMMARY="$SHARED_RUN/plots/summary_table.txt"
VERDICT_FILE="$SHARED/distributed/dist7_verdict.txt"

hongg_positive=0
aflpp_positive=0
if [ -f "$SUMMARY" ]; then
    # grep for PAIR TOTAL lines; extract the Δbugs column (field 4 after the pair header)
    # summary_table.txt has a "PAIR TOTAL" line with the aggregate delta.
    # For per-rep breakdown we rely on the parameter_eval or raw summary lines.
    # Simple heuristic: count positive Δbugs entries in honggfuzz and aflplusplus pairs.
    hongg_positive=$(grep -A2 "honggfuzz.*honggfuzzcd" "$SUMMARY" 2>/dev/null | \
        grep "PAIR TOTAL" | awk '{print $NF}' | grep -c "^+[1-9]" || true)
    aflpp_positive=$(grep -A2 "aflplusplus.*aflpluspluscd" "$SUMMARY" 2>/dev/null | \
        grep "PAIR TOTAL" | awk '{print $NF}' | grep -c "^+[1-9]" || true)
fi

{
    echo "dist7 verdict — $(date '+%F %T')"
    echo "honggfuzz->honggfuzzcd: $hongg_positive rep(s) with positive Δbugs"
    echo "aflplusplus->aflpluspluscd: $aflpp_positive rep(s) with positive Δbugs"
    if [ "$hongg_positive" -gt 0 ] && [ "$aflpp_positive" -gt 0 ]; then
        echo "VERDICT: SATISFACTORY — both pairs have at least one positive rep"
    else
        echo "VERDICT: UNSATISFACTORY — one or both pairs are non-positive"
        echo "  → Run: bash $REPO/cloudlab/dist7_followup.sh --auto-dist8"
        echo "  → Or manually: cd $REPO/cloudlab && bash orchestrate.sh --run-id dist8 --timeout 4h --poll 60"
    fi
} | tee "$VERDICT_FILE"
log "verdict written to $VERDICT_FILE"

# ---------------------------------------------------------------------------
# 4. Optionally launch dist8
# ---------------------------------------------------------------------------
if [ "$AUTO_DIST8" -eq 1 ] && \
   { [ "$hongg_positive" -eq 0 ] || [ "$aflpp_positive" -eq 0 ]; }; then
    log "launching dist8 (escalation parameters)..."
    # dist8 reuses the same manifest (6x4 layout).
    # Escalation: honggfuzzcd gets CONSECUTIVE=1 (always reset on first drift);
    #             aflpluspluscd gets SOFT_RESET=0 (full corpus wipe, no det/havoc mode).
    # This is the most aggressive CD configuration — if it doesn't help, CD is
    # fundamentally incompatible with these fuzzers under current conditions.
    # Worker-run.sh reads DIST8_ESCALATION=1 to activate the escalation params.
    export DIST8_ESCALATION=1
    tmux new-session -d -s dist8 \
      "cd $REPO/cloudlab && DIST8_ESCALATION=1 bash orchestrate.sh \
        --run-id dist8 --timeout 4h --poll 60 \
        2>&1 | tee $SHARED/distributed/dist8_orch.log"
    log "dist8 launched in tmux:dist8"
else
    log "dist8 not launched (auto-dist8=$AUTO_DIST8, hongg_pos=$hongg_positive, aflpp_pos=$aflpp_positive)"
fi

log "done"
