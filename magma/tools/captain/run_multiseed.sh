#!/bin/bash
# Multi-seed runner: backs up previous seed, cleans up, runs next seed.
# Runs seeds 2-10, backing up each to NFS before starting the next.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAGMA="$(cd "$SCRIPT_DIR/../../" && pwd)"
RESULTS_DIR="/users/eldarfin/experiment_results"
NFS_DIR="/proj/cdfuzzing-PG0"
START_SEED="${START_SEED:-2}"
END_SEED="${END_SEED:-10}"

FUZZERS=(afl aflcd aflfast aflfastcd moptafl moptaflcd aflplusplus aflpluspluscd fairfuzz fairfuzzcd honggfuzz honggfuzzcd)
TARGETS=(sqlite3 libpng lua libsndfile libtiff libxml2 poppler php openssl)

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

free_gb() {
    df --output=avail / | tail -1 | awk '{printf "%.0f", $1/1024/1024}'
}

prune_docker() {
    log "Pruning Docker..."
    docker system prune -af --volumes 2>/dev/null || true
    log "Free disk after prune: $(free_gb) GB"
}

backup_seed() {
    local seed=$1
    local src="$RESULTS_DIR/seed_${seed}"
    local dst="$NFS_DIR/seed${seed}_full.tar.gz"

    if [ ! -d "$src/ar" ]; then
        log "No results for seed $seed, skipping backup"
        return
    fi

    log "Backing up seed $seed to $dst ..."
    cd "$RESULTS_DIR"
    tar cf - "seed_${seed}/" | pigz -p 4 > "$dst"
    local size=$(ls -lh "$dst" | awk '{print $5}')
    log "Backup complete: $dst ($size)"
}

run_seed() {
    local seed=$1
    log "=== Starting seed $seed ==="

    # Clean previous seed data from local disk
    if [ -d "$RESULTS_DIR/seed_${seed}" ]; then
        log "Removing existing local seed_${seed} data"
        rm -rf "$RESULTS_DIR/seed_${seed}"
    fi

    # Clean Docker
    prune_docker

    local free=$(free_gb)
    log "Free disk: ${free} GB"

    if [ "$free" -lt 30 ]; then
        log "ERROR: Only ${free} GB free, need at least 30 GB. Aborting."
        exit 1
    fi

    mkdir -p "$RESULTS_DIR/seed_${seed}"

    # Run in 2 batches to manage disk (6 fuzzers each)
    local BATCH1=(afl aflcd aflfast aflfastcd moptafl moptaflcd)
    local BATCH2=(aflplusplus aflpluspluscd fairfuzz fairfuzzcd honggfuzz honggfuzzcd)

    for batch_num in 1 2; do
        if [ "$batch_num" -eq 1 ]; then
            local BATCH_FUZZERS=("${BATCH1[@]}")
        else
            local BATCH_FUZZERS=("${BATCH2[@]}")
        fi

        log "--- Seed $seed, Batch $batch_num: ${BATCH_FUZZERS[*]} ---"

        local captainrc="$SCRIPT_DIR/captainrc_seed${seed}"
        local target_list="${TARGETS[*]}"

        cat > "$captainrc" << EOF
WORKDIR=$RESULTS_DIR/seed_${seed}
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

        cd "$SCRIPT_DIR"
        bash run.sh "$captainrc" 2>&1 | tee "$RESULTS_DIR/seed_${seed}/batch${batch_num}.log" || {
            log "WARNING: Captain batch $batch_num failed for seed $seed"
        }

        log "Batch $batch_num complete for seed $seed"
        prune_docker
    done

    # Verify results
    local total=0
    for f in "${FUZZERS[@]}"; do
        local count=$(find "$RESULTS_DIR/seed_${seed}/ar/$f" -mindepth 3 -maxdepth 3 -name "0" -type d 2>/dev/null | wc -l)
        total=$((total + count))
    done
    log "Seed $seed complete: $total/252 campaigns"
}

# ============================================================
# Main loop
# ============================================================
log "=== Multi-Seed Runner: seeds $START_SEED to $END_SEED ==="

for seed in $(seq "$START_SEED" "$END_SEED"); do
    # Run the seed
    run_seed "$seed"

    # Backup results to NFS
    backup_seed "$seed"

    # Delete local data to free space for next seed
    log "Removing local seed_${seed} data to free disk"
    rm -rf "$RESULTS_DIR/seed_${seed}"
    log "Free disk: $(free_gb) GB"

    log "=== Seed $seed done. Proceeding to next. ==="
done

log "=== All seeds ($START_SEED-$END_SEED) complete! ==="
