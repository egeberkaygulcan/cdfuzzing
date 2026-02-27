/*
   american fuzzy lop - drift detection header
   --------------------------------------------

   Concept drift detection with jerk tracking.
   Matches EarlyStopFuzzer implementation from bits.ipynb.

   Licensed under the Apache License, Version 2.0 (the "License");

*/

#ifndef _AFL_DRIFT_DETECT_H
#define _AFL_DRIFT_DETECT_H

#include "types.h"

/* Drift detector state (mirrors EarlyStopFuzzer / MeanJerkFuzzer) */
struct drift_detector {

  /* Configuration */
  u32    window_size;          /* KS test window (AFL_DRIFT_WINDOW, def 100)    */
  double drift_threshold;     /* p-value threshold (AFL_DRIFT_THRESHOLD, 0.05) */
  u8     reset_on_drift;      /* Reset corpus on value drift (always 1)        */
  u32    metrics_window_size;  /* Coverage rate window (AFL_METRICS_WINDOW)     */
  u32    jerk_window_size;     /* Sliding jerk window (AFL_JERK_WINDOW, 1000)   */
  u32    mean_jerk_window;     /* Mean jerk window (AFL_MEAN_JERK_WINDOW, 100)  */
  u8     stop_on_jerk_drift;  /* Early stop on jerk drift (always 0)           */

  /* Value history */
  u64   *value_history;        /* queued_paths history                          */
  double *coverage_rate_history;
  u32    history_len;
  u32    history_capacity;

  /* Jerk tracking */
  double *sliding_jerk_history;
  u32    jerk_history_len;
  u32    jerk_history_capacity;

  /* Mean jerk tracking */
  double *mean_jerk_history;
  u32    mean_jerk_len;
  u32    mean_jerk_capacity;

  /* Statistics */
  u32    drift_count;
  u32    reset_count;
  u32    jerk_drift_count;
  u8     stopped_early;
  u64    stop_iteration;
  u64    last_queued_paths;
  u64    last_coverage;

};

/* API */
struct drift_detector *drift_init(void);
void   drift_destroy(struct drift_detector *dd);
void   drift_update(struct drift_detector *dd, u64 current_iter,
                    u64 queued_paths, u64 coverage);
void   drift_calculate_jerk(struct drift_detector *dd, u64 current_iter);
void   drift_record_mean_jerk(struct drift_detector *dd);
u8     is_coverage_rate_increasing(struct drift_detector *dd);
u8     drift_check_value(struct drift_detector *dd, u64 current_iter);
u8     drift_check_jerk(struct drift_detector *dd, u64 current_iter);
u8     drift_should_stop(struct drift_detector *dd);

#endif /* _AFL_DRIFT_DETECT_H */
