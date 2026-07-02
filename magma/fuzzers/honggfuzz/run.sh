#!/bin/bash

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
# - env TARGET: path to target work dir
# - env OUT: path to directory where artifacts are stored
# - env SHARED: path to directory shared with host (to store results)
# - env PROGRAM: name of program to run (should be found in $OUT)
# - env ARGS: extra arguments to pass to the program
# - env FUZZARGS: extra arguments to pass to the fuzzer
##

mkdir -p "$SHARED/findings" "$SHARED/output"

# replace AFL-style input file parameter with honggfuzz-style one. Use stdin
# fuzzing if an input file parameter is not provided
if [[ ! "$ARGS" =~ " @@" ]]; then
    FUZZARGS="$FUZZARGS -s"
fi
ARGS="${ARGS/@@/___FILE___}"

# Background: write periodic AFL-style plot_data from honggfuzz's log.
# Reads the cumulative edge count (4th field of Cur: lines) every 60 s and
# appends a synthetic plot_data row so the analysis pipeline can track
# coverage over time.
(
  START_TS=$(date +%s)
  PLOT="$SHARED/findings/plot_data"
  echo '# unix_time, cycles_done, cur_path, paths_total, pending_total, pending_favs, map_size, unique_crashes, unique_hangs, max_depth, execs_per_sec' > "$PLOT"
  LOG="$SHARED/log/current"
  while true; do
    sleep 60
    [ ! -f "$LOG" ] && continue
    EDGES=$(grep -oP 'Cur:\d+/\d+/\d+/\K\d+(?=/)' "$LOG" 2>/dev/null | sort -n | tail -1)
    [ -z "$EDGES" ] && continue
    NOW=$(date +%s)
    # Write edge count in map_size column (col 7); other fields are placeholders
    echo "$NOW, 0, 0, 0, 0, 0, $EDGES, 0, 0, 0, 0" >> "$PLOT"
  done
) &
COV_PID=$!
trap "kill \$COV_PID 2>/dev/null" EXIT INT TERM

"$FUZZER/repo/honggfuzz" -n 1 -z --input "$TARGET/corpus/$PROGRAM" \
    --output "$SHARED/output" --workspace "$SHARED/findings" \
    $FUZZARGS -- "$OUT/$PROGRAM" $ARGS 2>&1
