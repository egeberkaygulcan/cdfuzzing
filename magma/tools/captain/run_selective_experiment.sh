#!/bin/bash
# EXP5: 12h Validation Run - Unlimited Resets vs Baseline
# Winning config: unlimited soft resets (SOFT_RESET=2, MAX_RESETS=0, BOOST=2, BOOST_CYCLES=1)
# 12h duration, 5 seeds each, 10 containers total
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

DURATION_MIN=720
TIMEOUT="${DURATION_MIN}m"
PROGRAM=libpng_read_fuzzer
POLL=5

EXPDIR="$SCRIPT_DIR/selective_experiment"
rm -rf "$EXPDIR"
mkdir -p "$EXPDIR"

echo "=== EXP5: 12h Validation - Unlimited Resets vs Baseline ==="
echo "Target: libpng/$PROGRAM | Duration: ${DURATION_MIN}m (12h)"
echo "Configs: baseline(5), unlim_b2(5)"
echo "Seeds: 1-5 | Results: $EXPDIR"
echo ""

PIDS=()
LABELS=()

launch() {
    local LABEL="$1" IMAGE="$2" SEED="$3"
    shift 3
    local SHARED="$EXPDIR/${LABEL}"
    mkdir -p "$SHARED" && chmod 777 "$SHARED"
    cid=$(docker run -dt \
        --volume="$SHARED":/magma_shared \
        --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
        --env=PROGRAM="$PROGRAM" --env=ARGS="@@" \
        --env=POLL="$POLL" --env=TIMEOUT="$TIMEOUT" \
        --env=FUZZER_SEED="$SEED" \
        "$@" \
        --network=none \
        "$IMAGE")
    cid=$(cut -c-12 <<< "$cid")
    echo "[$(date +%H:%M:%S)] Started $LABEL -> $cid"
    docker logs -f "$cid" &> "$EXPDIR/${LABEL}.log" &
    (docker wait "$cid" || true) &
    PIDS+=($!)
    LABELS+=("$LABEL")
}

# Baseline afl (no drift detection)
for SEED in 1 2 3 4 5; do
    launch "baseline_s${SEED}" "magma/afl/libpng" "$SEED"
done

# Unlimited resets with temporary boost (WINNING CONFIG from EXP4)
for SEED in 1 2 3 4 5; do
    launch "unlim_b2_s${SEED}" "magma/aflcd/libpng" "$SEED" \
        --env=AFL_DRIFT_WINDOW=100 \
        --env=AFL_DRIFT_THRESHOLD=0.05 \
        --env=AFL_DRIFT_SOFT_RESET=2 \
        --env=AFL_DRIFT_MAX_RESETS=0 \
        --env=AFL_DRIFT_HAVOC_BOOST=2 \
        --env=AFL_DRIFT_BOOST_CYCLES=1
done

echo ""
echo "[$(date +%H:%M:%S)] All ${#PIDS[@]} containers launched. Waiting..."

for i in "${!PIDS[@]}"; do
    wait "${PIDS[$i]}" 2>/dev/null || true
    echo "[$(date +%H:%M:%S)] ${LABELS[$i]} finished."
done

echo ""
echo "=== All experiments complete ==="
ls -la "$EXPDIR"/ | head -40
