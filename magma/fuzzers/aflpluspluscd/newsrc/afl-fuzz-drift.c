/*
   american fuzzy lop++ - drift detection module
   ----------------------------------------------

   Concept drift detection with jerk tracking for AFL++.
   Self-contained module: all drift logic, CSV logging, and corpus reset.

   This file is automatically included via the GNUmakefile wildcard
   pattern: AFL_FUZZ_FILES = $(wildcard src/afl-fuzz*.c)

   All functions are gated behind #ifdef AFL_DRIFT_DETECT.

   Licensed under the Apache License, Version 2.0 (the "License");
*/

#include "afl-fuzz.h"

#ifdef AFL_DRIFT_DETECT

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <gsl/gsl_sort.h>
#include <gsl/gsl_statistics_double.h>
#include "afl-drift-detect.h"

/* ===== File-scope drift state ===== */

static struct drift_detector *drift_det       = NULL;
static u64  drift_iteration                   = 0;
static u8   jerk_drift_detected               = 0;
static u64  jerk_drift_iteration              = 0;
static u64  jerk_drift_time                   = 0;
static u32  jerk_drift_coverage               = 0;
static u32  corpus_reset_count                = 0;
static u64  first_corpus_reset_iteration      = 0;
static u64  first_corpus_reset_time           = 0;
static u64  last_corpus_reset_iteration       = 0;
static u64  last_corpus_reset_time            = 0;
static FILE *drift_csv_file                   = NULL;
static u64   drift_csv_last_update            = 0;
static u32   drift_csv_minute                 = 0;

/* ================================================================
   KS test (two-sample Kolmogorov-Smirnov)
   ================================================================ */

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

/* ================================================================
   drift_init  (mirrors EarlyStopFuzzer/MeanJerkFuzzer.__init__)
   ================================================================ */

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

  dd->history_capacity    = 20000;
  dd->value_history       = ck_alloc(dd->history_capacity * sizeof(u64));
  dd->coverage_rate_history = ck_alloc(dd->history_capacity * sizeof(double));
  dd->history_len         = 0;

  dd->jerk_history_capacity  = 20000;
  dd->sliding_jerk_history   = ck_alloc(dd->jerk_history_capacity * sizeof(double));
  dd->jerk_history_len       = 0;

  dd->mean_jerk_capacity = 1000;
  dd->mean_jerk_history  = ck_alloc(dd->mean_jerk_capacity * sizeof(double));
  dd->mean_jerk_len      = 0;

  dd->drift_count       = 0;
  dd->reset_count        = 0;
  dd->jerk_drift_count   = 0;
  dd->stopped_early      = 0;
  dd->stop_iteration     = 0;
  dd->last_queued_paths  = 0;
  dd->last_coverage      = 0;

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

/* ================================================================
   drift_destroy
   ================================================================ */

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

/* ================================================================
   drift_update  (mirrors tracking in EarlyStopFuzzer.fuzz)
   ================================================================ */

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

/* ================================================================
   drift_calculate_jerk  (mirrors calculate_sliding_jerk)
   ================================================================ */

void drift_calculate_jerk(struct drift_detector *dd, u64 current_iter) {

  if (!dd) return;
  if (dd->history_len < dd->jerk_window_size) return;

  if (dd->jerk_history_len >= dd->jerk_history_capacity) {

    dd->jerk_history_capacity *= 2;
    dd->sliding_jerk_history =
        ck_realloc(dd->sliding_jerk_history,
                   dd->jerk_history_capacity * sizeof(double));

  }

  u32 window_start  = dd->history_len - dd->jerk_window_size;
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

/* ================================================================
   drift_record_mean_jerk  (mirrors record_mean_jerk)
   ================================================================ */

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

/* ================================================================
   is_coverage_rate_increasing
   ================================================================ */

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

/* ================================================================
   drift_check_value  (mirrors detect_concept_drift)
   ================================================================ */

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

/* ================================================================
   drift_check_jerk  (mirrors detect_jerk_drift from MeanJerkFuzzer)
   ================================================================ */

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

      dd->stopped_early    = 1;
      dd->stop_iteration   = current_iter;
      SAYF(cLRD "\n[!] EARLY STOP triggered at iteration %llu\n" cRST,
           (unsigned long long)current_iter);

    }

    return 1;

  }

  return 0;

}

/* ================================================================
   drift_should_stop
   ================================================================ */

u8 drift_should_stop(struct drift_detector *dd) {

  if (!dd || !dd->stop_on_jerk_drift) return 0;
  return dd->stopped_early;

}

/* ================================================================
   AFL++ corpus reset  (uses queue_buf[] + disabled flag)
   ================================================================ */

static void perform_corpus_reset(afl_state_t *afl) {

  u32 removed_count = 0;

  if (!afl->queued_at_start) {

    WARNF("No initial seeds to reset to!");
    return;

  }

  ACTF("Resetting corpus to %u initial seeds...", afl->queued_at_start);

  for (u32 i = afl->queued_at_start; i < afl->queued_paths; i++) {

    struct queue_entry *q = afl->queue_buf[i];
    if (!q || q->disabled) continue;

    unlink((char *)q->fname);

    if (q->trace_mini) {

      ck_free(q->trace_mini);
      q->trace_mini = NULL;

    }

    q->disabled = 1;
    removed_count++;

  }

  afl->current_entry = 0;
  afl->queue_cur     = afl->queue_buf[0];

  corpus_reset_count++;
  u64 reset_time = get_cur_time() - afl->start_time;

  if (corpus_reset_count == 1) {

    first_corpus_reset_iteration = drift_iteration;
    first_corpus_reset_time      = reset_time;

  }

  last_corpus_reset_iteration = drift_iteration;
  last_corpus_reset_time      = reset_time;

  afl->reinit_table   = 1;
  afl->score_changed  = 1;

  ACTF("Corpus reset #%u complete: disabled %u entries, kept %u seeds",
       corpus_reset_count, removed_count, afl->queued_at_start);

}

/* ================================================================
   CSV logging
   ================================================================ */

static void drift_csv_init(afl_state_t *afl) {

  u8 *fn = alloc_printf("%s/drift_log.csv", afl->out_dir);
  drift_csv_file = fopen((char *)fn, "w");
  if (!drift_csv_file) PFATAL("Unable to create '%s'", fn);
  ck_free(fn);

  fprintf(drift_csv_file,
          "timestamp,iterations,coverage,reset_flag,early_stop_flag\n");
  fprintf(drift_csv_file, "0,0,0,false,false\n");
  fflush(drift_csv_file);

  drift_csv_last_update = get_cur_time();
  drift_csv_minute      = 0;

}

static void drift_csv_update(u64 current_iter, u32 current_coverage) {

  if (!drift_csv_file) return;

  u64 now = get_cur_time();
  if (now - drift_csv_last_update < 60000) return;

  drift_csv_minute++;
  drift_csv_last_update = now;

  fprintf(drift_csv_file, "%u,%llu,%u,%s,%s\n",
          drift_csv_minute,
          (unsigned long long)current_iter,
          current_coverage,
          corpus_reset_count > 0 ? "true" : "false",
          jerk_drift_detected ? "true" : "false");
  fflush(drift_csv_file);

}

static void drift_csv_close(void) {

  if (drift_csv_file) {

    fclose(drift_csv_file);
    drift_csv_file = NULL;

  }

}

/* ================================================================
   Public entry points — called from afl-fuzz.c
   ================================================================ */

void drift_setup(afl_state_t *afl) {

  drift_det = drift_init();
  if (!drift_det) FATAL("Failed to initialize drift detector");
  ACTF("Drift detection initialized (window=%u, threshold=%.3f)",
       drift_det->window_size, drift_det->drift_threshold);
  drift_csv_init(afl);

}

void drift_cycle(afl_state_t *afl) {

  if (!drift_det) return;

  drift_iteration++;

  u32 current_coverage = count_non_255_bytes(afl, afl->virgin_bits);
  drift_update(drift_det, drift_iteration, afl->queued_paths,
               current_coverage);

  /* Jerk calculation */
  if (drift_iteration >= drift_det->jerk_window_size &&
      drift_iteration % drift_det->jerk_window_size == 0) {

    drift_calculate_jerk(drift_det, drift_iteration);

  }

  /* Mean jerk recording */
  if (drift_det->jerk_history_len >= drift_det->mean_jerk_window &&
      drift_iteration % drift_det->mean_jerk_window == 0) {

    drift_record_mean_jerk(drift_det);

  }

  /* Value drift check */
  if (drift_iteration >= drift_det->window_size &&
      drift_iteration % drift_det->window_size == 0) {

    if (drift_check_value(drift_det, drift_iteration)) {

      ACTF("Value drift detected at iteration %llu!",
           (unsigned long long)drift_iteration);

      if (drift_det->reset_on_drift &&
          !is_coverage_rate_increasing(drift_det)) {

        WARNF("Coverage not increasing - performing corpus reset...");
        perform_corpus_reset(afl);
        ACTF("Resuming fuzzing from initial seeds...");

      }

    }

  }

  /* Jerk drift check (one-shot) */
  if (!jerk_drift_detected && drift_det->mean_jerk_len >= 20 &&
      drift_iteration % drift_det->mean_jerk_window == 0) {

    if (drift_check_jerk(drift_det, drift_iteration)) {

      jerk_drift_detected  = 1;
      jerk_drift_iteration = drift_iteration;
      jerk_drift_time      = get_cur_time() - afl->start_time;
      jerk_drift_coverage  = current_coverage;
      ACTF("Jerk drift detected at iteration %llu (%.2f sec, coverage: "
           "%u edges)!",
           (unsigned long long)drift_iteration,
           jerk_drift_time / 1000.0, current_coverage);
      ACTF("Continuing fuzzing with jerk drift detection disabled...");

    }

  }

  drift_csv_update(drift_iteration, current_coverage);

}

void drift_teardown(afl_state_t *afl) {

  if (corpus_reset_count > 0 || jerk_drift_detected) {

    u32 final_coverage = count_non_255_bytes(afl, afl->virgin_bits);
    u64 total_time     = get_cur_time() - afl->start_time;

    SAYF("\n" cYEL "[*] Drift Detection Summary" cRST "\n");

    if (corpus_reset_count > 0) {

      SAYF("    Corpus resets performed: %u\n", corpus_reset_count);
      SAYF("    First reset at iteration %llu (%.2f sec / %.2f min)\n",
           (unsigned long long)first_corpus_reset_iteration,
           first_corpus_reset_time / 1000.0,
           first_corpus_reset_time / 60000.0);
      if (corpus_reset_count > 1) {

        SAYF("    Last reset at iteration %llu (%.2f sec / %.2f min)\n",
             (unsigned long long)last_corpus_reset_iteration,
             last_corpus_reset_time / 1000.0,
             last_corpus_reset_time / 60000.0);

      }

    }

    if (jerk_drift_detected) {

      SAYF("    Jerk drift detected at iteration %llu (%.2f sec / %.2f "
           "min)\n",
           (unsigned long long)jerk_drift_iteration,
           jerk_drift_time / 1000.0, jerk_drift_time / 60000.0);
      SAYF("    Coverage at jerk drift: %u edges\n", jerk_drift_coverage);
      SAYF("    Final coverage: %u edges\n", final_coverage);
      SAYF("    Coverage gained after jerk drift: %d edges\n",
           (s32)final_coverage - (s32)jerk_drift_coverage);

    }

    SAYF("    Total runtime: %.2f sec / %.2f min\n", total_time / 1000.0,
         total_time / 60000.0);

  }

  drift_csv_close();
  if (drift_det) {

    drift_destroy(drift_det);
    drift_det = NULL;

  }

}

#endif /* AFL_DRIFT_DETECT */
