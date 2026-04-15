#!/bin/bash
# Run remaining fuzzers that failed due to disk space in v5.
# aflplusplus had only 3/21 programs, rest never ran.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAGMA="$(cd "$SCRIPT_DIR/../../" && pwd)"
RESULTS_DIR="${RESULTS_DIR:-/users/eldarfin/experiment_results}"
SEED="${SEED:-1}"

FUZZERS=(aflplusplus aflpluspluscd fairfuzz fairfuzzcd honggfuzz honggfuzzcd)
TARGETS=(sqlite3 libpng lua libsndfile libtiff libxml2 poppler php openssl)

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

free_gb() {
    df --output=avail / | tail -1 | awk '{printf "%.0f", $1/1024/1024}'
}

prune_images() {
    log "Pruning Docker images and build cache..."
    docker image prune -af 2>/dev/null || true
    docker builder prune -af 2>/dev/null || true
    log "Free disk after prune: $(free_gb) GB"
}

mkdir -p "$RESULTS_DIR/seed_${SEED}"
log "=== Remaining Fuzzers Runner ==="
log "Seed: $SEED | Results: $RESULTS_DIR"
log "Fuzzers: ${FUZZERS[*]}"
log "Targets: ${TARGETS[*]}"
log "Free disk: $(free_gb) GB"
echo ""

# Run in 2 batches of 3 fuzzers to manage disk
BATCH1=(aflplusplus aflpluspluscd fairfuzz)
BATCH2=(fairfuzzcd honggfuzz honggfuzzcd)

for batch_num in 1 2; do
    if [ "$batch_num" -eq 1 ]; then
        BATCH_FUZZERS=("${BATCH1[@]}")
    else
        BATCH_FUZZERS=("${BATCH2[@]}")
    fi

    free=$(free_gb)
    log "--- Batch $batch_num: ${BATCH_FUZZERS[*]} (free: ${free} GB) ---"

    captainrc="$SCRIPT_DIR/captainrc_remaining"
    target_list="${TARGETS[*]}"

    cat > "$captainrc" << EOF
WORKDIR=$RESULTS_DIR/seed_${SEED}
REPEAT=1
TIMEOUT=24h
POLL=5
CACHE_ON_DISK=1
NO_ARCHIVE=1
MAGMA=$MAGMA

FUZZERS=(${BATCH_FUZZERS[*]})

EOF

    for f in "${BATCH_FUZZERS[@]}"; do
        echo "${f}_TARGETS=($target_list)" >> "$captainrc"
    done

    cat >> "$captainrc" << 'ENVEOF'

# CD variant parameters
export AFL_DRIFT_WINDOW=100
export AFL_DRIFT_THRESHOLD=0.05
export AFL_DRIFT_SOFT_RESET=2
export AFL_DRIFT_MAX_RESETS=0
export AFL_DRIFT_HAVOC_BOOST=2
export AFL_DRIFT_BOOST_CYCLES=1
ENVEOF

    log "Generated captainrc at $captainrc"
    log "Starting captain for batch $batch_num: ${BATCH_FUZZERS[*]}"

    cd "$SCRIPT_DIR"
    bash run.sh "$captainrc" 2>&1 | tee "$RESULTS_DIR/seed_${SEED}/batch_remaining_${batch_num}.log" || {
        log "WARNING: Captain exited with error for batch $batch_num"
    }

    log "Batch $batch_num complete."
    prune_images
done

log "=== All remaining fuzzers complete for seed $SEED ==="
