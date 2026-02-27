/*
 * honggfuzz - concept drift detection header
 * -------------------------------------------
 *
 * Concept drift detection with jerk tracking.
 * Matches EarlyStopFuzzer/MeanJerkFuzzer implementation from bits.ipynb.
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
    uint32_t jerk_window_size;     /* Window for jerk calculation (default: 1000) */
    uint32_t mean_jerk_window;     /* Record mean jerk interval (default: 100) */
    bool     stop_on_jerk_drift;   /* Early stop on jerk drift? */

    /* History tracking */
    uint64_t* value_history;        /* queued_paths over time */
    double*   coverage_rate_history; /* Coverage rate over time */
    uint32_t  history_len;
    uint32_t  history_capacity;

    /* Jerk tracking (mirrors MeanJerkFuzzer) */
    double*  sliding_jerk_history;      /* Jerk at each iteration */
    double*  mean_jerk_history;         /* Mean jerk every mean_jerk_window */
    uint32_t jerk_history_len;
    uint32_t jerk_history_capacity;
    uint32_t mean_jerk_len;
    uint32_t mean_jerk_capacity;

    /* Statistics */
    uint32_t drift_count;          /* Value distribution drifts */
    uint32_t reset_count;          /* Corpus resets */
    uint32_t jerk_drift_count;     /* Jerk drifts detected */

    /* Early stop state */
    bool     stopped_early;
    uint64_t stop_iteration;

    /* Last known state */
    uint64_t last_queued_paths;
    uint64_t last_coverage;        /* For velocity calculation */

    /* CSV logging */
    FILE*    csv_file;
    uint64_t csv_last_update_ms;
    uint32_t csv_minute;

    /* Iteration counter (driven from main thread) */
    uint64_t iteration;

    /* Jerk drift detection (one-shot) */
    bool     jerk_drift_detected;
    uint64_t jerk_drift_iteration;
    uint64_t jerk_drift_time_ms;
    uint64_t jerk_drift_coverage;

    /* Corpus reset tracking */
    uint32_t corpus_reset_count;
    uint64_t first_corpus_reset_iteration;
    uint64_t first_corpus_reset_time_ms;
    uint64_t last_corpus_reset_iteration;
    uint64_t last_corpus_reset_time_ms;

    /* Initial corpus size (for reset) */
    size_t   initial_corpus_count;

} drift_detector_t;

/* Initialize drift detector - returns NULL on failure */
drift_detector_t* drift_init(const char* output_dir);

/* Cleanup drift detector */
void drift_destroy(drift_detector_t* dd);

/* Update history after each iteration */
void drift_update(drift_detector_t* dd, uint64_t current_iter,
                  uint64_t queued_paths, uint64_t coverage);

/* Calculate sliding jerk (call when i >= jerk_window_size) */
void drift_calculate_jerk(drift_detector_t* dd, uint64_t current_iter);

/* Record mean jerk (call every mean_jerk_window iterations) */
void drift_record_mean_jerk(drift_detector_t* dd);

/* Check for value distribution drift - returns true if reset needed */
bool drift_check_value(drift_detector_t* dd, uint64_t current_iter);

/* Check for jerk drift - returns true if drift detected */
bool drift_check_jerk(drift_detector_t* dd, uint64_t current_iter);

/* Check if should trigger early stop */
bool drift_should_stop(drift_detector_t* dd);

/* Check if coverage rate is increasing */
bool drift_is_coverage_rate_increasing(drift_detector_t* dd);

/* CSV logging: append row if >= 1 minute has elapsed */
void drift_csv_update(drift_detector_t* dd, uint64_t current_iter,
                      uint64_t coverage, uint64_t elapsed_ms);

/* Perform corpus reset on a honggfuzz_t instance */
void drift_perform_corpus_reset(drift_detector_t* dd, honggfuzz_t* hfuzz);

#endif /* _HF_DRIFT_DETECT_H */
