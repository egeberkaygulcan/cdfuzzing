/*
 * honggfuzz - concept drift detection header
 * -------------------------------------------
 *
 * Concept drift detection.
 * Matches EarlyStopFuzzer implementation from bits.ipynb.
 *
 * Adapted for honggfuzz (stdint types, LOG_* macros, util_Calloc).
 */

#ifndef _HF_DRIFT_DETECT_H
#define _HF_DRIFT_DETECT_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include "honggfuzz.h"

/* Drift detection state - mirrors EarlyStopFuzzer/MeanJerkFuzzer */
typedef struct {

    /* Configuration */
    uint32_t window_size;          /* Window for value drift (default: 100) */
    double   drift_threshold;      /* P-value threshold (default: 0.05) */
    bool     reset_on_drift;       /* Reset corpus on VALUE drift only */
    uint32_t metrics_window_size;  /* Window for derivative metrics (default: 100) */

    /* History tracking */
    uint64_t* value_history;        /* queued_paths over time */
    double*   coverage_rate_history; /* Coverage rate over time */
    uint32_t  history_len;
    uint32_t  history_capacity;

    /* Statistics */
    uint32_t drift_count;          /* Value distribution drifts */
    uint32_t reset_count;          /* Corpus resets */
    uint32_t consecutive_drifts;   /* Consecutive drift detections */
    uint32_t cooldown_remaining;   /* Cooldown iterations remaining */

    /* Last known state */
    uint64_t last_queued_paths;
    uint64_t last_coverage;        /* For velocity calculation */

    /* CSV logging */
    FILE*    csv_file;
    uint64_t csv_last_update_ms;
    uint32_t csv_minute;

    /* Iteration counter (driven from main thread) */
    uint64_t iteration;

    /* Corpus reset tracking */
    uint32_t corpus_reset_count;
    uint64_t first_corpus_reset_iteration;
    uint64_t first_corpus_reset_time_ms;
    uint64_t last_corpus_reset_iteration;
    uint64_t last_corpus_reset_time_ms;

    /* Initial corpus size (for reset) */
    size_t   initial_corpus_count;

    /* Diagnostics (populated each drift_check_value call for CSV logging) */
    double   last_p_value;
    double   last_growth_rate;

    /* Cached output directory for stats file */
    char     output_dir[PATH_MAX];

} drift_detector_t;

/* Initialize drift detector - returns NULL on failure */
drift_detector_t* drift_init(const char* output_dir);

/* Cleanup drift detector */
void drift_destroy(drift_detector_t* dd);

/* Update history after each iteration */
void drift_update(drift_detector_t* dd, uint64_t current_iter,
                  uint64_t queued_paths, uint64_t coverage);

/* Check for value distribution drift - returns true if reset needed */
bool drift_check_value(drift_detector_t* dd, uint64_t current_iter);

/* Check if coverage rate is increasing */
bool drift_is_coverage_rate_increasing(drift_detector_t* dd);

/* CSV logging: append row if >= 1 minute has elapsed */
void drift_csv_update(drift_detector_t* dd, uint64_t current_iter,
                      uint64_t coverage, uint64_t elapsed_ms,
                      uint64_t corpus);

/* Perform corpus reset on a honggfuzz_t instance.
 * keep_seeds  : number of original seed entries to retain (from queue head).
 * keep_recent : number of most-recently-added entries to retain (from queue tail).
 *               Pass 0 for the original hard-reset behaviour (seeds-only). */
void drift_perform_corpus_reset(drift_detector_t* dd, honggfuzz_t* hfuzz,
                                size_t keep_seeds, size_t keep_recent);

/* Write human-readable diagnostic stats file */
void drift_write_stats_file(drift_detector_t* dd, const char* out_dir,
                            uint64_t queued_paths);

#endif /* _HF_DRIFT_DETECT_H */
