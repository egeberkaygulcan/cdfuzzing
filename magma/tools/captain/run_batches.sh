#!/bin/bash
set -e

MAGMA=/users/eldarfin/cdfuzzing/magma
CAPTAIN="$MAGMA/tools/captain"
LOGDIR=/users/eldarfin/experiment_results/seed_4/batch_logs

mkdir -p "$LOGDIR"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGDIR/batches.log"; }

disk_check() {
    local avail=$(df --output=avail / | tail -1)
    local avail_gb=$((avail / 1024 / 1024))
    log "Disk available: ${avail_gb}GB"
    if [ "$avail_gb" -lt 5 ]; then
        log "CRITICAL: Less than 5GB free! Aborting."
        exit 1
    fi
}

docker_cleanup() {
    log "Pruning Docker images and build cache..."
    docker system prune -af --volumes 2>&1 | tail -3
    disk_check
}

run_batch() {
    local batch=$1
    local config="$CAPTAIN/captainrc_batch${batch}"

    if [ ! -f "$config" ]; then
        log "ERROR: $config not found!"
        return 1
    fi

    log "=========================================="
    log "STARTING BATCH $batch"
    log "Config: $config"
    log "=========================================="
    disk_check

    cd "$CAPTAIN"
    bash run.sh "$config" 2>&1 | tee "$LOGDIR/batch${batch}.log"
    local exit_code=${PIPESTATUS[0]}

    log "Batch $batch finished with exit code $exit_code"
    log "Docker images after batch $batch:"
    docker images --format "{{.Repository}}:{{.Tag}} {{.Size}}" 2>&1 | tee -a "$LOGDIR/batches.log"

    return $exit_code
}

# Main execution
log "Starting 24h batch experiments (seed_4)"
log "Batch 1: fairfuzz/fairfuzzcd + aflplusplus/aflpluspluscd (BROKEN)"
log "Batch 2: moptafl/moptaflcd + afl/aflcd (RESET STORMS)"
log "Batch 3: aflfast/aflfastcd + honggfuzz/honggfuzzcd (CLEAN BASELINE)"

# Start from the specified batch (default: 1)
START_BATCH=${1:-1}

for batch in 1 2 3; do
    if [ "$batch" -lt "$START_BATCH" ]; then
        log "Skipping batch $batch (starting from $START_BATCH)"
        continue
    fi

    # Clean Docker before each batch (except first if already clean)
    if [ "$batch" -gt "$START_BATCH" ] || docker images -q 2>/dev/null | grep -q .; then
        docker_cleanup
    fi

    run_batch $batch || {
        log "WARNING: Batch $batch had errors. Continuing to next batch."
    }
done

log "All batches complete!"
log "Results at: /users/eldarfin/experiment_results/seed_4/ar/"
