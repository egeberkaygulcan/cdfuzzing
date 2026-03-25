#!/bin/bash
# Multi-fuzzer, multi-target 12h experiment
# Compares 3 fuzzer baselines against their CD variants on 3 targets
# 3 seeds each → 54 containers total
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

DURATION_MIN=720
TIMEOUT="${DURATION_MIN}m"
POLL=5

EXPDIR="$SCRIPT_DIR/multi_experiment"
rm -rf "$EXPDIR"
mkdir -p "$EXPDIR"

# Target configs: target_name program_name
declare -A TARGET_PROGRAMS
TARGET_PROGRAMS[libtiff]="tiff_read_rgba_fuzzer"
TARGET_PROGRAMS[libxml2]="libxml2_xml_read_memory_fuzzer"
TARGET_PROGRAMS[openssl]="server"

# Fuzzer pairs: baseline cd_variant
FUZZER_PAIRS=(
    "afl aflcd"
    "aflfast aflfastcd"
    "moptafl moptaflcd"
)

SEEDS=(1 2 3)

echo "=== Multi-Fuzzer Multi-Target 12h Experiment ==="
echo "Fuzzer pairs: afl/aflcd, aflfast/aflfastcd, moptafl/moptaflcd"
echo "Targets: libtiff, libxml2, openssl"
echo "Seeds: ${SEEDS[*]} | Duration: ${DURATION_MIN}m (12h)"
echo "Results: $EXPDIR"
echo ""

PIDS=()
LABELS=()

launch() {
    local LABEL="$1" IMAGE="$2" SEED="$3" PROGRAM="$4"
    shift 4
    local SHARED="$EXPDIR/${LABEL}"
    mkdir -p "$SHARED" && chmod 777 "$SHARED"
    cid=$(docker run -dt \
        --volume="$SHARED":/magma_shared \
        --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
        --env=PROGRAM="$PROGRAM" \
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

# Launch all containers
for pair in "${FUZZER_PAIRS[@]}"; do
    BASE=$(echo "$pair" | cut -d' ' -f1)
    CD=$(echo "$pair" | cut -d' ' -f2)

    for TARGET in libtiff libxml2 openssl; do
        PROGRAM="${TARGET_PROGRAMS[$TARGET]}"

        for SEED in "${SEEDS[@]}"; do
            # Baseline
            launch "${BASE}_${TARGET}_s${SEED}" "magma/${BASE}/${TARGET}" "$SEED" "$PROGRAM"

            # CD variant with winning config
            launch "${CD}_${TARGET}_s${SEED}" "magma/${CD}/${TARGET}" "$SEED" "$PROGRAM" \
                --env=AFL_DRIFT_WINDOW=100 \
                --env=AFL_DRIFT_THRESHOLD=0.05 \
                --env=AFL_DRIFT_SOFT_RESET=2 \
                --env=AFL_DRIFT_MAX_RESETS=0 \
                --env=AFL_DRIFT_HAVOC_BOOST=2 \
                --env=AFL_DRIFT_BOOST_CYCLES=1
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
ls -la "$EXPDIR"/ | head -60
