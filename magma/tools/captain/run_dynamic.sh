#!/bin/bash
# Dynamic experiment runner: runs all fuzzers × all targets with disk-aware batching.
# Iterates through targets, checks disk space before each, batches what fits,
# runs captain, prunes images after each batch, then continues.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAGMA="$(cd "$SCRIPT_DIR/../../" && pwd)"
RESULTS_DIR="${RESULTS_DIR:-/users/eldarfin/experiment_results}"
SEED="${SEED:-1}"

# Disk thresholds (in GB)
MIN_FREE_TO_START=15    # minimum free GB before starting a new target build
IMAGE_ESTIMATE=3        # estimated GB per target (all 12 fuzzer images, with layer sharing)
RUNTIME_RESERVE=10      # GB reserved for runtime data and archives

FUZZERS=(afl aflcd aflfast aflfastcd moptafl moptaflcd aflplusplus aflpluspluscd fairfuzz fairfuzzcd honggfuzz honggfuzzcd)
TARGETS=(sqlite3 libpng lua libsndfile libtiff libxml2 poppler php openssl)

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

free_gb() {
    df --output=avail / | tail -1 | awk '{printf "%.0f", $1/1024/1024}'
}

disk_used_gb() {
    df --output=used / | tail -1 | awk '{printf "%.0f", $1/1024/1024}'
}

prune_images() {
    log "Pruning Docker images and build cache..."
    docker image prune -af --filter "label!=keep" 2>/dev/null || true
    docker builder prune -af 2>/dev/null || true
    log "Free disk after prune: $(free_gb) GB"
}

mkdir -p "$RESULTS_DIR"
log "=== Dynamic Experiment Runner ==="
log "Seed: $SEED | Results: $RESULTS_DIR"
log "Fuzzers: ${FUZZERS[*]}"
log "Targets: ${TARGETS[*]}"
log "Free disk: $(free_gb) GB"
echo ""

# Track which targets are done
declare -A DONE
remaining=("${TARGETS[@]}")

while [ ${#remaining[@]} -gt 0 ]; do
    batch=()
    free=$(free_gb)
    log "--- Planning next batch (free: ${free} GB) ---"

    # Greedily add targets until we'd drop below threshold
    next_remaining=()
    for t in "${remaining[@]}"; do
        needed=$((IMAGE_ESTIMATE + RUNTIME_RESERVE))
        projected_free=$((free - IMAGE_ESTIMATE * (${#batch[@]} + 1)))
        if [ "$projected_free" -ge "$MIN_FREE_TO_START" ]; then
            batch+=("$t")
        else
            next_remaining+=("$t")
        fi
    done

    # If we couldn't fit any target, force at least one (we'll prune first)
    if [ ${#batch[@]} -eq 0 ]; then
        log "Not enough space for any target. Pruning first..."
        prune_images
        free=$(free_gb)
        if [ "$free" -lt "$MIN_FREE_TO_START" ]; then
            log "ERROR: Only ${free} GB free even after prune. Cannot continue."
            exit 1
        fi
        batch=("${next_remaining[0]}")
        next_remaining=("${next_remaining[@]:1}")
    fi

    remaining=("${next_remaining[@]}")

    log "Batch targets: ${batch[*]}"
    log "Remaining targets: ${remaining[*]:-none}"

    # Generate per-fuzzer target assignments for captainrc
    target_list=$(IFS=' '; echo "${batch[*]}")
    captainrc="$SCRIPT_DIR/captainrc_dynamic"
    cat > "$captainrc" << EOF
WORKDIR=$RESULTS_DIR/seed_${SEED}
REPEAT=1
TIMEOUT=24h
POLL=5
CACHE_ON_DISK=1
NO_ARCHIVE=1
MAGMA=$MAGMA

FUZZERS=(${FUZZERS[*]})

EOF

    # Set per-fuzzer targets
    for f in "${FUZZERS[@]}"; do
        echo "${f}_TARGETS=(${target_list})" >> "$captainrc"
    done

    # Set CD variant environment variables
    cat >> "$captainrc" << 'EOF'

# CD variant parameters (applied via start.sh env passthrough)
export AFL_DRIFT_WINDOW=100
export AFL_DRIFT_THRESHOLD=0.05
export AFL_DRIFT_SOFT_RESET=2
export AFL_DRIFT_MAX_RESETS=0
export AFL_DRIFT_HAVOC_BOOST=2
export AFL_DRIFT_BOOST_CYCLES=1
EOF

    log "Generated captainrc at $captainrc"
    log "Starting captain for batch: ${batch[*]}"

    # Run captain
    cd "$SCRIPT_DIR"
    bash run.sh "$captainrc" 2>&1 | tee "$RESULTS_DIR/seed_${SEED}/batch_$(IFS=_; echo "${batch[*]}").log" || {
        log "WARNING: Captain exited with error for batch ${batch[*]}"
    }

    log "Batch [${batch[*]}] complete."
    log "Pruning images before next batch..."
    prune_images

    for t in "${batch[@]}"; do
        DONE[$t]=1
    done
done

log "=== All targets complete for seed $SEED ==="
log "Results in: $RESULTS_DIR/seed_${SEED}"
