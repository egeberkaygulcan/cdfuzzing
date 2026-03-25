#!/bin/bash
# Experiment: vary AFL_DRIFT_WINDOW for aflcd on libpng
# Runs each window size for DURATION minutes in parallel with 3 seeds each.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAGMA="$(cd "$SCRIPT_DIR/../.." && pwd)"

WINDOW_SIZES=(10 20 50 100 200)
DURATION_MIN=180
TIMEOUT="${DURATION_MIN}m"
PROGRAM=libpng_read_fuzzer
POLL=5

EXPDIR="$SCRIPT_DIR/window_experiment"
rm -rf "$EXPDIR"
mkdir -p "$EXPDIR"

echo "=== Window Size Experiment ==="
echo "Target: libpng/$PROGRAM | Duration: ${DURATION_MIN}m"
echo "Window sizes: ${WINDOW_SIZES[*]}"
echo "Seeds: 1 2 3 | Results: $EXPDIR"
echo ""

PIDS=()
LABELS=()

# Launch baseline afl (3 seeds)
for SEED in 1 2 3; do
    SHARED="$EXPDIR/afl_baseline_s${SEED}"
    mkdir -p "$SHARED" && chmod 777 "$SHARED"
    cid=$(docker run -dt \
        --volume="$SHARED":/magma_shared \
        --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
        --env=PROGRAM="$PROGRAM" --env=ARGS="@@" \
        --env=POLL="$POLL" --env=TIMEOUT="$TIMEOUT" \
        --env=FUZZER_SEED="$SEED" \
        --network=none \
        "magma/afl/libpng")
    cid=$(cut -c-12 <<< "$cid")
    echo "[$(date +%H:%M:%S)] Started afl baseline seed=$SEED -> $cid"
    docker logs -f "$cid" &> "$EXPDIR/afl_baseline_s${SEED}.log" &
    (docker wait "$cid" || true) &
    PIDS+=($!)
    LABELS+=("afl_baseline_s${SEED}")
done

# Launch all window sizes in parallel (3 seeds each)
for WINDOW in "${WINDOW_SIZES[@]}"; do
    for SEED in 1 2 3; do
        SHARED="$EXPDIR/window_${WINDOW}_s${SEED}"
        mkdir -p "$SHARED" && chmod 777 "$SHARED"
        cid=$(docker run -dt \
            --volume="$SHARED":/magma_shared \
            --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
            --env=PROGRAM="$PROGRAM" --env=ARGS="@@" \
            --env=POLL="$POLL" --env=TIMEOUT="$TIMEOUT" \
            --env=FUZZER_SEED="$SEED" \
            --env=AFL_DRIFT_WINDOW="$WINDOW" \
            --network=none \
            "magma/aflcd/libpng")
        cid=$(cut -c-12 <<< "$cid")
        echo "[$(date +%H:%M:%S)] Started aflcd window=$WINDOW seed=$SEED -> $cid"
        docker logs -f "$cid" &> "$EXPDIR/window_${WINDOW}_s${SEED}.log" &
        (docker wait "$cid" || true) &
        PIDS+=($!)
        LABELS+=("window_${WINDOW}_s${SEED}")
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
ls -la "$EXPDIR"/ | head -40
