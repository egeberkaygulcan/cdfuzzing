#!/bin/bash
# Analyze param_experiment results
# Usage: bash analyze_param_experiment.sh [EXPDIR]

EXPDIR="${1:-/users/eldarfin/cdfuzzing/magma/tools/captain/param_experiment}"

echo "=== Multi-Parameter Experiment Analysis ==="
echo "Directory: $EXPDIR"
echo ""

# Collect results per config
echo "CONFIG                  | SEED | PATHS  | MAP_SIZE | RESETS | ITERS"
echo "------------------------|------|--------|----------|--------|------"

for d in "$EXPDIR"/*/findings/plot_data; do
    config=$(echo "$d" | sed 's|.*/param_experiment/||;s|/findings/plot_data||')
    
    # Extract seed
    seed=$(echo "$config" | grep -oP 's\K[0-9]+')
    base=$(echo "$config" | sed 's/_s[0-9]*$//')
    
    # Last line of plot_data
    last=$(sudo tail -1 "$d" 2>/dev/null)
    paths=$(echo "$last" | awk -F', ' '{print $4}')
    map=$(echo "$last" | awk -F', ' '{print $7}')
    
    # Drift log info
    dlog="$EXPDIR/$config/findings/drift_log.csv"
    if [[ -f "$dlog" ]]; then
        last_drift=$(sudo tail -1 "$dlog" 2>/dev/null)
        iters=$(echo "$last_drift" | cut -d, -f2)
        # Count reset transitions (first time reset_flag goes true)
        resets=$(sudo awk -F, 'NR>1 && $4=="true" && prev!="true" {count++} {prev=$4}' "$dlog" 2>/dev/null)
        # Actually, reset_flag is cumulative. Count from fuzzer_stats if available
        fstats="$EXPDIR/$config/findings/fuzzer_stats"
        r2=$(sudo grep "corpus_reset_count" "$fstats" 2>/dev/null | awk -F: '{gsub(/ /,"",$2); print $2}')
        if [[ -n "$r2" ]]; then
            resets="$r2"
        else
            # Fallback: check if reset_flag is "true" in last line
            has_reset=$(echo "$last_drift" | cut -d, -f4)
            resets="$has_reset"
        fi
    else
        iters="N/A"
        resets="N/A"
    fi
    
    printf "%-23s | %4s | %6s | %8s | %6s | %s\n" "$base" "$seed" "$paths" "$map" "$resets" "$iters"
done 2>/dev/null | sort

echo ""
echo "=== Aggregated by Config (mean ± std) ==="
echo ""

# Aggregate using awk
for d in "$EXPDIR"/*/findings/plot_data; do
    config=$(echo "$d" | sed 's|.*/param_experiment/||;s|/findings/plot_data||')
    base=$(echo "$config" | sed 's/_s[0-9]*$//')
    
    last=$(sudo tail -1 "$d" 2>/dev/null)
    paths=$(echo "$last" | awk -F', ' '{print $4}')
    map=$(echo "$last" | awk -F', ' '{gsub(/%/,"",$7); print $7}')
    
    fstats="$EXPDIR/$config/findings/fuzzer_stats"
    resets=$(sudo grep "corpus_reset_count" "$fstats" 2>/dev/null | awk -F: '{gsub(/ /,"",$2); print $2}')
    [[ -z "$resets" ]] && resets=0
    
    echo "$base $paths $map $resets"
done 2>/dev/null | sort | awk '
{
    config=$1; paths=$2; map=$3; resets=$4;
    sum_paths[config] += paths;
    sum_map[config] += map;
    sum_resets[config] += resets;
    sumsq_paths[config] += paths*paths;
    sumsq_map[config] += map*map;
    count[config]++;
    all_paths[config] = all_paths[config] " " paths;
    all_map[config] = all_map[config] " " map;
}
END {
    printf "%-23s | %8s | %10s | %8s\n", "CONFIG", "PATHS", "MAP_SIZE%", "RESETS";
    printf "%-23s-|-%8s-|-%10s-|-%8s\n", "-----------------------", "--------", "----------", "--------";
    n = asorti(count, sorted);
    for (i=1; i<=n; i++) {
        c = sorted[i];
        n_c = count[c];
        mean_p = sum_paths[c] / n_c;
        mean_m = sum_map[c] / n_c;
        mean_r = sum_resets[c] / n_c;
        
        var_p = (n_c > 1) ? (sumsq_paths[c]/n_c - mean_p*mean_p) : 0;
        var_m = (n_c > 1) ? (sumsq_map[c]/n_c - mean_m*mean_m) : 0;
        std_p = (var_p > 0) ? sqrt(var_p) : 0;
        std_m = (var_m > 0) ? sqrt(var_m) : 0;
        
        printf "%-23s | %6.1f±%3.0f | %5.2f±%4.2f | %5.1f\n", c, mean_p, std_p, mean_m, std_m, mean_r;
    }
}
'
