/*

*/

#ifndef _AFL_DRIFT_DETECT_H
#define _AFL_DRIFT_DETECT_H

#include "types.h"
#include "config.h"

/* Drift detection state - mirrors EarlyStopFuzzer/MeanJerkFuzzer */
struct drift_detector {
  
  /* Configuration */
  u32    window_size;          /* Window for value drift (default: 100) */
  double drift_threshold;      /* P-value threshold (default: 0.05) */
  u8     reset_on_drift;       /* Reset corpus on VALUE drift only */
  u32    metrics_window_size;  /* Window for derivative metrics (default: 100) */
  u32    jerk_window_size;     /* Window for jerk calculation (default: 1000) */
  u32    mean_jerk_window;     /* Record mean jerk interval (default: 100) */
  u8     stop_on_jerk_drift;   /* Early stop on jerk drift? */
  
  /* History tracking */
  u64*   value_history;        /* queued_paths over time */
  double* coverage_rate_history; /* Coverage rate over time */
  u32    history_len;
  u32    history_capacity;
  
  /* Jerk tracking (mirrors MeanJerkFuzzer) */
  double* sliding_jerk_history;      /* Jerk at each iteration */
  double* mean_jerk_history;         /* Mean jerk every mean_jerk_window */
  u32    jerk_history_len;
  u32    jerk_history_capacity;
  u32    mean_jerk_len;
  u32    mean_jerk_capacity;
  
  /* Statistics */
  u32    drift_count;          /* Value distribution drifts */
  u32    reset_count;          /* Corpus resets */
  u32    jerk_drift_count;     /* Jerk drifts detected */
  
  /* Early stop state */
  u8     stopped_early;
  u64    stop_iteration;
  
  /* Last known state */
  u64    last_queued_paths;
  u64    last_coverage;        /* For velocity calculation */
  
};

/* Global drift detector instance */
extern struct drift_detector* drift_state;

/* Initialize drift detector */
struct drift_detector* drift_init(void);

/* Cleanup drift detector */
void drift_destroy(struct drift_detector* dd);

/* Update history after each iteration */
void drift_update(struct drift_detector* dd, u64 current_iter, 
                  u64 queued_paths, u64 coverage);

/* Calculate sliding jerk (call when i >= jerk_window_size) */
void drift_calculate_jerk(struct drift_detector* dd, u64 current_iter);

/* Record mean jerk (call every mean_jerk_window iterations) */
void drift_record_mean_jerk(struct drift_detector* dd);

/* Check for value distribution drift - returns 1 if reset needed */
u8 drift_check_value(struct drift_detector* dd, u64 current_iter);

/* Check for jerk drift - returns 1 if drift detected */
u8 drift_check_jerk(struct drift_detector* dd, u64 current_iter);

/* Check if should trigger early stop */
u8 drift_should_stop(struct drift_detector* dd);

/* Check if coverage rate is increasing */
u8 is_coverage_rate_increasing(struct drift_detector* dd);

#endif /* !_AFL_DRIFT_DETECT_H */
