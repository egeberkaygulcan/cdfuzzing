#!/bin/bash
# Experiment: Multi-parameter sweep for drift detection on libpng
# Varies: window size, threshold, and always_reset (guard bypass)
# Runs each config for DURATION minutes in parallel with 3 seeds each.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAGMA="$(cd "$SCRIPT_DIR/../.." && pwd)"

DURATION_MIN=180
TIMEOUT="${DURATION_MIN}m"
PROGRAM=libpng_read_fuzzer
POLL=5

EXPDIR="$SCRIPT_DIR/param_experiment"
rm -rf "$EXPDIR"
mkdir -p "$EXPDIR"

echo "=== Multi-Parameter Drift Experiment ==="
echo "Target: libpng/$PROGRAM | Duration: ${DURATION_MIN}m"
echo "Factors: window={50,100}, threshold={0.05,0.2}, always_reset={0,1}"
echo "Seeds: 1 2 3 | Results: $EXPDIR"
echo ""

PIDS=()
LABELS=()

launch() {
    local LABEL="$1" IMAGE="$2" SEED="$3"
    shift 3
    # remaining args are --env flags
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
for SEED in 1 2 3; do
    launch "baseline_s${SEED}" "magma/afl/libpng" "$SEED"
done

# aflcd with guard (default behavior: always_reset=0)
for WINDOW in 50 100; do
    for THRESH in 0.05 0.2; do
        TNAME=$(echo "$THRESH" | tr -d '.')
        for SEED in 1 2 3; do
            launch "g0_w${WINDOW}_t${TNAME}_s${SEED}" "magma/aflcd/libpng" "$SEED" \
                --env=AFL_DRIFT_WINDOW="$WINDOW" \
                --env=AFL_DRIFT_THRESHOLD="$THRESH" \
                --env=AFL_DRIFT_ALWAYS_RESET=0
        done
    done
done

# aflcd without guard (always_reset=1: bypass is_coverage_rate_increasing)
for WINDOW in 50 100; do
    for THRESH in 0.05 0.2; do
        TNAME=$(echo "$THRESH" | tr -d '.')
        for SEED in 1 2 3; do
            launch "g1_w${WINDOW}_t${TNAME}_s${SEED}" "magma/aflcd/libpng" "$SEED" \
                --env=AFL_DRIFT_WINDOW="$WINDOW" \
                --env=AFL_DRIFT_THRESHOLD="$THRESH" \
                --env=AFL_DRIFT_ALWAYS_RESET=1
        done
    done
done

echo ""
echo "[$(date +%H:%M:%S)] All ${#PIDS[@]} containers launched. Waiting..."

for i in "${!PIDS[@]}"; do
    wait "${PIDS[$i]}" 2>/dev/null || true
    echo "[$(date +%H:%M:%S)] ${LABELS[$i]} finished."
done

echo ""
echo "=== All experiments complete ==="
echo "Configs: $(( ${#LABELS[@]} )) containers"
ls -la "$EXPDIR"/ | head -50
