/*
   american fuzzy lop - drift detection implementation
   ---------------------------------------------------

   Concept drift detection with jerk tracking.
   Matches EarlyStopFuzzer implementation from bits.ipynb.

   Licensed under the Apache License, Version 2.0 (the "License");

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <gsl/gsl_sort.h>
#include <gsl/gsl_statistics_double.h>

#include "afl-drift-detect.h"
#include "alloc-inl.h"
#include "debug.h"

/* Two-sample Kolmogorov-Smirnov test using GSL
   Returns p-value (approximation matching scipy.stats.ks_2samp) */
static double ks_test_two_sample(double *data1, u32 n1,
                                 double *data2, u32 n2) {

  if (n1 == 0 || n2 == 0) return 1.0;

  double *sorted1 = ck_alloc(n1 * sizeof(double));
  double *sorted2 = ck_alloc(n2 * sizeof(double));

  memcpy(sorted1, data1, n1 * sizeof(double));
  memcpy(sorted2, data2, n2 * sizeof(double));

  gsl_sort(sorted1, 1, n1);
  gsl_sort(sorted2, 1, n2);

  double d_max = 0.0;
  u32 i = 0, j = 0;

  while (i < n1 && j < n2) {

    double cdf1 = (double)(i + 1) / n1;
    double cdf2 = (double)(j + 1) / n2;
    double diff = fabs(cdf1 - cdf2);
    if (diff > d_max) d_max = diff;

    if (sorted1[i] <= sorted2[j])
      i++;
    if (j < n2 && sorted2[j] <= sorted1[i < n1 ? i : n1 - 1])
      j++;

  }

  ck_free(sorted1);
  ck_free(sorted2);

  double n_eff   = sqrt((n1 * n2) / (double)(n1 + n2));
  double lambda  = (n_eff + 0.12 + 0.11 / n_eff) * d_max;
  double p_value = 2.0 * exp(-2.0 * lambda * lambda);

  if (p_value > 1.0) p_value = 1.0;
  if (p_value < 0.0) p_value = 0.0;

  return p_value;

}

/* Initialize drift detector (mirrors EarlyStopFuzzer/MeanJerkFuzzer.__init__) */
struct drift_detector *drift_init(void) {

  struct drift_detector *dd = ck_alloc(sizeof(struct drift_detector));
  char *env_val;

  env_val = getenv("AFL_DRIFT_WINDOW");
  dd->window_size = env_val ? atoi(env_val) : 100;

  env_val = getenv("AFL_DRIFT_THRESHOLD");
  dd->drift_threshold = env_val ? atof(env_val) : 0.05;

  env_val = getenv("AFL_DRIFT_RESET");
  dd->reset_on_drift = 1;  /* always enabled */

  env_val = getenv("AFL_METRICS_WINDOW");
  dd->metrics_window_size = env_val ? atoi(env_val) : 100;

  env_val = getenv("AFL_JERK_WINDOW");
  dd->jerk_window_size = env_val ? atoi(env_val) : 1000;

  env_val = getenv("AFL_MEAN_JERK_WINDOW");
  dd->mean_jerk_window = env_val ? atoi(env_val) : 100;

  env_val = getenv("AFL_STOP_ON_JERK_DRIFT");
  dd->stop_on_jerk_drift = 0;  /* detect-and-log only */

  dd->history_capacity      = 20000;
  dd->value_history         = ck_alloc(dd->history_capacity * sizeof(u64));
  dd->coverage_rate_history = ck_alloc(dd->history_capacity * sizeof(double));
  dd->history_len           = 0;

  dd->jerk_history_capacity  = 20000;
  dd->sliding_jerk_history   = ck_alloc(dd->jerk_history_capacity * sizeof(double));
  dd->jerk_history_len       = 0;

  dd->mean_jerk_capacity = 1000;
  dd->mean_jerk_history  = ck_alloc(dd->mean_jerk_capacity * sizeof(double));
  dd->mean_jerk_len      = 0;

  dd->drift_count      = 0;
  dd->reset_count      = 0;
  dd->jerk_drift_count = 0;
  dd->stopped_early    = 0;
  dd->stop_iteration   = 0;
  dd->last_queued_paths = 0;
  dd->last_coverage    = 0;

  SAYF(cGRN "[+] " cRST "Drift detection with jerk tracking enabled:\n");
  SAYF("    Value drift: window=%u, threshold=%.3f, reset=%s\n",
       dd->window_size, dd->drift_threshold,
       dd->reset_on_drift ? "ON" : "OFF");
  SAYF("    Jerk tracking: window=%u, mean_jerk_window=%u\n",
       dd->jerk_window_size, dd->mean_jerk_window);
  SAYF("    Early stop on jerk drift: %s\n",
       dd->stop_on_jerk_drift ? "YES" : "NO");

  return dd;

}

/* Cleanup drift detector */
void drift_destroy(struct drift_detector *dd) {

  if (!dd) return;

  SAYF(cGRN "\n[+] " cRST "Drift detection summary:\n");
  SAYF("    Value drifts: %u, Resets: %u\n", dd->drift_count, dd->reset_count);
  SAYF("    Jerk drifts: %u\n", dd->jerk_drift_count);
  if (dd->stopped_early) {

    SAYF("    Early stop at iteration: %llu\n",
         (unsigned long long)dd->stop_iteration);

  }

  ck_free(dd->value_history);
  ck_free(dd->coverage_rate_history);
  ck_free(dd->sliding_jerk_history);
  ck_free(dd->mean_jerk_history);
  ck_free(dd);

}

/* Update history (mirrors tracking in EarlyStopFuzzer.fuzz) */
void drift_update(struct drift_detector *dd, u64 current_iter,
                  u64 queued_paths, u64 coverage) {

  if (!dd) return;

  if (dd->history_len >= dd->history_capacity) {

    dd->history_capacity *= 2;
    dd->value_history = ck_realloc(dd->value_history,
                                   dd->history_capacity * sizeof(u64));
    dd->coverage_rate_history = ck_realloc(dd->coverage_rate_history,
                                           dd->history_capacity * sizeof(double));

  }

  dd->value_history[dd->history_len] = queued_paths;

  double coverage_rate = (current_iter > 0)
                             ? ((double)queued_paths / (double)current_iter)
                             : 0.0;
  dd->coverage_rate_history[dd->history_len] = coverage_rate;

  dd->history_len++;
  dd->last_queued_paths = queued_paths;
  dd->last_coverage     = coverage;

}

/* Calculate sliding jerk (mirrors calculate_sliding_jerk) */
void drift_calculate_jerk(struct drift_detector *dd, u64 current_iter) {

  if (!dd) return;
  if (dd->history_len < dd->jerk_window_size) return;

  if (dd->jerk_history_len >= dd->jerk_history_capacity) {

    dd->jerk_history_capacity *= 2;
    dd->sliding_jerk_history =
        ck_realloc(dd->sliding_jerk_history,
                   dd->jerk_history_capacity * sizeof(double));

  }

  u32 window_start   = dd->history_len - dd->jerk_window_size;
  u64 coverage_start = dd->value_history[window_start];
  u64 coverage_end   = dd->value_history[dd->history_len - 1];
  double velocity    = (double)(coverage_end - coverage_start) /
                       dd->jerk_window_size;

  if (dd->jerk_history_len < 1) {

    dd->sliding_jerk_history[dd->jerk_history_len++] = 0.0;
    return;

  }

  if (dd->history_len > dd->jerk_window_size + 1) {

    u32 prev_window_start = window_start - 1;
    if (prev_window_start >= dd->jerk_window_size) {

      u64 prev_coverage_start =
          dd->value_history[prev_window_start - dd->jerk_window_size];
      u64 prev_coverage_end = dd->value_history[prev_window_start];
      double prev_velocity  = (double)(prev_coverage_end - prev_coverage_start) /
                              dd->jerk_window_size;
      double acceleration = velocity - prev_velocity;

      dd->sliding_jerk_history[dd->jerk_history_len++] = acceleration;

    }

  }

}

/* Record mean jerk (mirrors record_mean_jerk) */
void drift_record_mean_jerk(struct drift_detector *dd) {

  if (!dd) return;
  if (dd->jerk_history_len < dd->mean_jerk_window) return;

  if (dd->mean_jerk_len >= dd->mean_jerk_capacity) {

    dd->mean_jerk_capacity *= 2;
    dd->mean_jerk_history =
        ck_realloc(dd->mean_jerk_history,
                   dd->mean_jerk_capacity * sizeof(double));

  }

  u32 start_idx = dd->jerk_history_len >= dd->mean_jerk_window
                      ? dd->jerk_history_len - dd->mean_jerk_window
                      : 0;
  u32 count = dd->jerk_history_len - start_idx;

  double mean_jerk =
      gsl_stats_mean(dd->sliding_jerk_history + start_idx, 1, count);
  dd->mean_jerk_history[dd->mean_jerk_len++] = mean_jerk;

}

/* Check if coverage rate is increasing (mirrors is_coverage_rate_increasing) */
u8 is_coverage_rate_increasing(struct drift_detector *dd) {

  if (!dd) return 1;
  if (dd->history_len < dd->window_size * 2) return 1;

  u32 current_start  = dd->history_len - dd->window_size;
  u32 previous_start = current_start - dd->window_size;

  double avg_current = gsl_stats_mean(
      dd->coverage_rate_history + current_start, 1, dd->window_size);
  double avg_previous = gsl_stats_mean(
      dd->coverage_rate_history + previous_start, 1, dd->window_size);

  return avg_current > avg_previous;

}

/* Check for value distribution drift (mirrors detect_concept_drift) */
u8 drift_check_value(struct drift_detector *dd, u64 current_iter) {

  if (!dd) return 0;
  if (dd->history_len < dd->window_size * 2) return 0;

  u32 current_start  = dd->history_len - dd->window_size;
  u32 previous_start = current_start - dd->window_size;

  double *current_values  = ck_alloc(dd->window_size * sizeof(double));
  double *previous_values = ck_alloc(dd->window_size * sizeof(double));

  u32 i;
  for (i = 0; i < dd->window_size; i++) {

    current_values[i]  = (double)dd->value_history[current_start + i];
    previous_values[i] = (double)dd->value_history[previous_start + i];

  }

  double p_value = ks_test_two_sample(previous_values, dd->window_size,
                                      current_values, dd->window_size);

  ck_free(current_values);
  ck_free(previous_values);

  if (p_value < dd->drift_threshold) {

    dd->drift_count++;

    SAYF(cYEL "\n[!] " cRST
         "VALUE DRIFT detected at iter %llu | p-value: %.4f\n",
         (unsigned long long)current_iter, p_value);

    u8 is_increasing = is_coverage_rate_increasing(dd);
    SAYF("    Coverage rate increasing: %s\n",
         is_increasing ? "YES" : "NO");

    if (dd->reset_on_drift && !is_increasing) {

      dd->reset_count++;
      SAYF(cLRD "    CORPUS RESET" cRST " - Coverage rate not increasing\n");
      return 1;

    } else if (dd->reset_on_drift && is_increasing) {

      SAYF("    NO RESET - Coverage rate is increasing\n");

    }

  }

  return 0;

}

/* Check for jerk drift (mirrors detect_jerk_drift from MeanJerkFuzzer) */
u8 drift_check_jerk(struct drift_detector *dd, u64 current_iter) {

  if (!dd) return 0;
  if (dd->mean_jerk_len < 20) return 0;

  u32 half_point = dd->mean_jerk_len / 2;
  if (half_point < 2) return 0;

  double *previous_jerks = dd->mean_jerk_history;
  double *current_jerks  = dd->mean_jerk_history + half_point;
  u32 current_len        = dd->mean_jerk_len - half_point;

  double p_value = ks_test_two_sample(previous_jerks, half_point,
                                      current_jerks, current_len);

  if (p_value < dd->drift_threshold) {

    dd->jerk_drift_count++;

    double mean_prev = gsl_stats_mean(previous_jerks, 1, half_point);
    double mean_curr = gsl_stats_mean(current_jerks, 1, current_len);

    SAYF(cYEL "\n[!] " cRST
         "JERK DRIFT detected at iter %llu | p-value: %.4f\n",
         (unsigned long long)current_iter, p_value);
    SAYF("    Mean jerk: %.6f -> %.6f\n", mean_prev, mean_curr);

    if (dd->stop_on_jerk_drift) {

      dd->stopped_early  = 1;
      dd->stop_iteration = current_iter;
      SAYF(cLRD "\n[!] EARLY STOP triggered at iteration %llu\n" cRST,
           (unsigned long long)current_iter);

    }

    return 1;

  }

  return 0;

}

/* Check if should trigger early stop */
u8 drift_should_stop(struct drift_detector *dd) {

  if (!dd || !dd->stop_on_jerk_drift) return 0;
  return dd->stopped_early;

}
