/*
   american fuzzy lop - drift detection implementation
   ---------------------------------------------------

   Concept drift detection.
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

/* Global drift detector instance */
struct drift_detector* drift_state = NULL;

/* Two-sample Kolmogorov-Smirnov test using GSL
   Returns p-value (approximation matching scipy.stats.ks_2samp) */
static double ks_test_two_sample(double* data1, u32 n1, double* data2, u32 n2) {
  
  if (n1 == 0 || n2 == 0) return 1.0;
  
  /* Sort both samples using GSL */
  double* sorted1 = ck_alloc(n1 * sizeof(double));
  double* sorted2 = ck_alloc(n2 * sizeof(double));
  
  memcpy(sorted1, data1, n1 * sizeof(double));
  memcpy(sorted2, data2, n2 * sizeof(double));
  
  gsl_sort(sorted1, 1, n1);
  gsl_sort(sorted2, 1, n2);
  
  /* Calculate KS statistic (max difference between ECDFs) */
  double d_max = 0.0;
  u32 i = 0, j = 0;
  
  while (i < n1 && j < n2) {
    double cdf1 = (double)(i + 1) / n1;
    double cdf2 = (double)(j + 1) / n2;
    double diff = fabs(cdf1 - cdf2);
    if (diff > d_max) d_max = diff;
    
    if (sorted1[i] <= sorted2[j]) i++;
    if (j < n2 && sorted2[j] <= sorted1[i < n1 ? i : n1 - 1]) j++;
  }
  
  ck_free(sorted1);
  ck_free(sorted2);
  
  /* Calculate approximate p-value using asymptotic formula
     This matches scipy.stats.ks_2samp implementation */
  double n_eff = sqrt((n1 * n2) / (double)(n1 + n2));
  double lambda = (n_eff + 0.12 + 0.11 / n_eff) * d_max;
  double p_value = 2.0 * exp(-2.0 * lambda * lambda);
  
  /* Clamp to [0, 1] */
  if (p_value > 1.0) p_value = 1.0;
  if (p_value < 0.0) p_value = 0.0;
  
  return p_value;
}

/* Initialize drift detector (mirrors EarlyStopFuzzer/MeanJerkFuzzer.__init__) */
struct drift_detector* drift_init(void) {
  
  struct drift_detector* dd = ck_alloc(sizeof(struct drift_detector));
  
  char* env_val;
  
  /* Value drift detection parameters (from OperationBasedFuzzer) */
  env_val = getenv("AFL_DRIFT_WINDOW");
  dd->window_size = env_val ? atoi(env_val) : 100;  /* Default: 100 */
  
  env_val = getenv("AFL_DRIFT_THRESHOLD");
  dd->drift_threshold = env_val ? atof(env_val) : 0.05;  /* Default: 0.05 */
  
  env_val = getenv("AFL_DRIFT_RESET");
  dd->reset_on_drift = 1; // env_val ? atoi(env_val) : 0;  /* Default: disabled */
  
  env_val = getenv("AFL_DRIFT_ALWAYS_RESET");
  dd->always_reset = env_val ? atoi(env_val) : 0;  /* Default: 0 (use guard) */
  
  env_val = getenv("AFL_DRIFT_SELECTIVE");
  dd->selective_reset = env_val ? atoi(env_val) : 0;  /* Default: 0 (full reset) */
  
  env_val = getenv("AFL_DRIFT_SOFT_RESET");
  dd->soft_reset = env_val ? atoi(env_val) : 0;  /* Default: 0 */
  
  env_val = getenv("AFL_DRIFT_MAX_RESETS");
  dd->max_resets = env_val ? atoi(env_val) : 0;  /* Default: 0 (unlimited) */
  
  env_val = getenv("AFL_DRIFT_COOLDOWN");
  dd->cooldown = env_val ? atoi(env_val) : 0;  /* Default: 0 (no cooldown) */
  dd->cooldown_remaining = 0;
  
  env_val = getenv("AFL_DRIFT_CONSECUTIVE");
  dd->consecutive_required = env_val ? atoi(env_val) : 1;  /* Default: 1 (first detection triggers) */
  dd->consecutive_drifts = 0;
  
  /* Adaptive stagnation parameters */
  env_val = getenv("AFL_DRIFT_EMA_ALPHA");
  dd->ema_alpha = env_val ? atof(env_val) : 0.1;  /* Default: 0.1 */
  
  env_val = getenv("AFL_DRIFT_STAGNATION_FACTOR");
  dd->stagnation_factor = env_val ? atof(env_val) : 0.25;  /* Default: 0.25 */
  
  dd->growth_ema = 0.0;
  dd->ema_initialized = 0;
  
  /* Allocate history buffers (auto-expand as needed) */
  dd->history_capacity = 20000;
  dd->value_history = ck_alloc(dd->history_capacity * sizeof(u64));
  dd->coverage_rate_history = ck_alloc(dd->history_capacity * sizeof(double));
  dd->history_len = 0;
  
  /* Initialize statistics */
  dd->drift_count = 0;
  dd->reset_count = 0;
  dd->last_queued_paths = 0;
  dd->last_coverage = 0;
  /* Diagnostic state */
  dd->last_p_value = -1.0;
  dd->last_growth_rate = 0.0;
  dd->last_stagnation_thresh = 0.0;
  
  SAYF(cGRN "[+] " cRST "Drift detection enabled:\n");
  SAYF("    Value drift: window=%u, threshold=%.3f, reset=%s\n",
       dd->window_size, dd->drift_threshold, dd->reset_on_drift ? "ON" : "OFF");
  SAYF("    Cooldown: %u iters, consecutive required: %u\n",
       dd->cooldown, dd->consecutive_required);
  SAYF("    Adaptive stagnation: ema_alpha=%.2f, stag_factor=%.2f\n",
       dd->ema_alpha, dd->stagnation_factor);
  return dd;
}

/* Reset drift history buffers (call after corpus reset to prevent false re-triggers) */
void drift_reset_history(struct drift_detector* dd) {
  if (!dd) return;
  dd->history_len = 0;
  dd->consecutive_drifts = 0;
  /* Activate cooldown period after reset */
  dd->cooldown_remaining = dd->cooldown;
}

/* Cleanup drift detector */
void drift_destroy(struct drift_detector* dd) {
  if (!dd) return;
  
  SAYF(cGRN "\n[+] " cRST "Drift detection summary:\n");
  SAYF("    Value drifts: %u, Resets: %u\n", dd->drift_count, dd->reset_count);
  
  ck_free(dd->value_history);
  ck_free(dd->coverage_rate_history);
  ck_free(dd);
}

/* Update history (mirrors tracking in EarlyStopFuzzer.fuzz) */
void drift_update(struct drift_detector* dd, u64 current_iter,
                  u64 queued_paths, u64 coverage) {
  
  if (!dd) return;
  
  /* Expand buffers if needed */
  if (dd->history_len >= dd->history_capacity) {
    dd->history_capacity *= 2;
    dd->value_history = ck_realloc(dd->value_history,
                                    dd->history_capacity * sizeof(u64));
    dd->coverage_rate_history = ck_realloc(dd->coverage_rate_history,
                                            dd->history_capacity * sizeof(double));
  }
  
  /* Track value (queued_paths) - mirrors value_history.append(value) */
  dd->value_history[dd->history_len] = queued_paths;
  
  /* Track coverage rate - mirrors coverage_rate calculation */
  double coverage_rate = (current_iter > 0) ?
                         ((double)queued_paths / (double)current_iter) : 0.0;
  dd->coverage_rate_history[dd->history_len] = coverage_rate;
  
  dd->history_len++;
  dd->last_queued_paths = queued_paths;
  dd->last_coverage = coverage;
}

/* Check if coverage rate is increasing (mirrors is_coverage_rate_increasing) */
u8 is_coverage_rate_increasing(struct drift_detector* dd) {
  
  if (!dd) return 1;
  if (dd->history_len < dd->window_size * 2) return 1;
  
  /* Get current and previous windows */
  u32 current_start = dd->history_len - dd->window_size;
  u32 previous_start = current_start - dd->window_size;
  
  /* Calculate mean of each window using GSL */
  double avg_current = gsl_stats_mean(dd->coverage_rate_history + current_start,
                                       1, dd->window_size);
  double avg_previous = gsl_stats_mean(dd->coverage_rate_history + previous_start,
                                        1, dd->window_size);
  
  return avg_current > avg_previous;
}

/* Check for value distribution drift (mirrors detect_concept_drift) */
u8 drift_check_value(struct drift_detector* dd, u64 current_iter) {
  
  if (!dd) return 0;
  
  /* Cooldown: skip checks after a reset */
  if (dd->cooldown_remaining > 0) {
    dd->cooldown_remaining--;
    return 0;
  }
  
  /* Need at least 2 windows of data */
  if (dd->history_len < dd->window_size * 2) return 0;
  
  /* Adaptive stagnation check using EMA of growth rates.
     Track the fuzzer's own historical growth rate and trigger when
     recent growth drops significantly below its norm. */
  u32 current_end = dd->history_len - 1;
  u32 current_start = dd->history_len - dd->window_size;
  u32 previous_start = current_start - dd->window_size;
  
  u64 recent_growth = dd->value_history[current_end] - dd->value_history[current_start];
  u64 previous_growth = dd->value_history[current_start] - dd->value_history[previous_start];
  double growth_rate = (double)recent_growth;
  
  /* Update EMA of growth rates (persists across resets for baseline calibration) */
  if (!dd->ema_initialized) {
    dd->growth_ema = growth_rate;
    dd->ema_initialized = 1;
  } else {
    dd->growth_ema = dd->ema_alpha * growth_rate + (1.0 - dd->ema_alpha) * dd->growth_ema;
  }
  
  /* If coverage is growing above the adaptive threshold, no stagnation */
  double stagnation_threshold = dd->growth_ema * dd->stagnation_factor;
  
  /* Store diagnostics for CSV logging */
  dd->last_growth_rate = growth_rate;
  dd->last_stagnation_thresh = stagnation_threshold;
  
  if (growth_rate > stagnation_threshold && stagnation_threshold > 0.0) {
    dd->consecutive_drifts = 0;
    dd->last_p_value = -1.0;  /* KS test not run */
    return 0;
  }
  
  /* Get current and previous windows */
  /* Convert u64 to double for KS test */
  double* current_values = ck_alloc(dd->window_size * sizeof(double));
  double* previous_values = ck_alloc(dd->window_size * sizeof(double));
  
  u32 i;
  for (i = 0; i < dd->window_size; i++) {
    current_values[i] = (double)dd->value_history[current_start + i];
    previous_values[i] = (double)dd->value_history[previous_start + i];
  }
  
  /* KS test for value distribution (mirrors: ks_stat_values, p_value_values = stats.ks_2samp(...)) */
  double p_value = ks_test_two_sample(previous_values, dd->window_size,
                                       current_values, dd->window_size);
  
  ck_free(current_values);
  ck_free(previous_values);
  
  /* Store p-value for CSV logging */
  dd->last_p_value = p_value;
  
  /* Detect drift if p-value is below threshold */
  if (p_value < dd->drift_threshold) {
    dd->drift_count++;
    dd->consecutive_drifts++;
    
    SAYF(cYEL "\n[!] " cRST "VALUE DRIFT detected at iter %llu | p-value: %.4f | consecutive: %u/%u\n",
         current_iter, p_value, dd->consecutive_drifts, dd->consecutive_required);
    SAYF("    Growth: recent=%llu prev=%llu ema=%.1f threshold=%.1f\n",
         recent_growth, previous_growth, dd->growth_ema, stagnation_threshold);
    
    /* Require consecutive drift detections before acting */
    if (dd->consecutive_drifts < dd->consecutive_required) {
      SAYF("    WAITING - need %u more consecutive detections\n",
           dd->consecutive_required - dd->consecutive_drifts);
      return 0;
    }
    
    /* Decide on corpus reset */
    if (dd->reset_on_drift) {
      if (dd->max_resets > 0 && dd->reset_count >= dd->max_resets) {
        SAYF("    NO RESET - Max resets reached (%u/%u)\n",
             dd->reset_count, dd->max_resets);
        return 0;
      }
      dd->reset_count++;
      dd->consecutive_drifts = 0;
      SAYF(cLRD "    CORPUS RESET #%u" cRST " - stagnation + drift confirmed\n",
           dd->reset_count);
      return 1;  /* Signal reset needed */
    }
  } else {
    /* No drift — reset consecutive counter */
    dd->consecutive_drifts = 0;
  }
  
  return 0;  /* No reset needed */
}

/* Write human-readable diagnostic stats file (like AFL's fuzzer_stats) */
void drift_write_stats(struct drift_detector* dd, u8* out_dir,
                       u64 queued_paths, u32 corpus_resets) {
  
  if (!dd || !out_dir) return;
  
  u8* fn = alloc_printf("%s/drift_stats", out_dir);
  FILE* f = fopen((char*)fn, "w");
  if (!f) { ck_free(fn); return; }
  
  fprintf(f, "drift_window        : %u\n", dd->window_size);
  fprintf(f, "drift_threshold     : %.4f\n", dd->drift_threshold);
  fprintf(f, "drift_cooldown      : %u\n", dd->cooldown);
  fprintf(f, "drift_consecutive   : %u\n", dd->consecutive_required);
  fprintf(f, "drift_max_resets    : %u\n", dd->max_resets);
  fprintf(f, "ema_alpha           : %.4f\n", dd->ema_alpha);
  fprintf(f, "stagnation_factor   : %.4f\n", dd->stagnation_factor);
  fprintf(f, "history_len         : %u\n", dd->history_len);
  fprintf(f, "queued_paths        : %llu\n", (unsigned long long)queued_paths);
  fprintf(f, "drift_count         : %u\n", dd->drift_count);
  fprintf(f, "reset_count         : %u\n", dd->reset_count);
  fprintf(f, "corpus_resets       : %u\n", corpus_resets);
  fprintf(f, "consecutive_drifts  : %u\n", dd->consecutive_drifts);
  fprintf(f, "cooldown_remaining  : %u\n", dd->cooldown_remaining);
  fprintf(f, "growth_ema          : %.4f\n", dd->growth_ema);
  fprintf(f, "last_p_value        : %.6f\n", dd->last_p_value);
  fprintf(f, "last_growth_rate    : %.4f\n", dd->last_growth_rate);
  fprintf(f, "last_stagnation_thr : %.4f\n", dd->last_stagnation_thresh);
  
  fclose(f);
  ck_free(fn);
}
