/*
   american fuzzy lop++ - drift detection module
   ----------------------------------------------

   Concept drift detection for AFL++.
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

  env_val = getenv("AFL_DRIFT_ALWAYS_RESET");
  dd->always_reset = env_val ? atoi(env_val) : 0;

  env_val = getenv("AFL_DRIFT_SELECTIVE");
  dd->selective_reset = env_val ? atoi(env_val) : 0;

  env_val = getenv("AFL_DRIFT_SOFT_RESET");
  dd->soft_reset = env_val ? atoi(env_val) : 0;

  env_val = getenv("AFL_DRIFT_MAX_RESETS");
  dd->max_resets = env_val ? atoi(env_val) : 0;

  env_val = getenv("AFL_DRIFT_COOLDOWN");
  dd->cooldown = env_val ? atoi(env_val) : 0;
  dd->cooldown_remaining = 0;

  env_val = getenv("AFL_DRIFT_CONSECUTIVE");
  dd->consecutive_required = env_val ? atoi(env_val) : 1;
  dd->consecutive_drifts = 0;

  env_val = getenv("AFL_DRIFT_EMA_ALPHA");
  dd->ema_alpha = env_val ? atof(env_val) : 0.1;

  env_val = getenv("AFL_DRIFT_STAGNATION_FACTOR");
  dd->stagnation_factor = env_val ? atof(env_val) : 0.25;

  dd->growth_ema = 0.0;
  dd->ema_initialized = 0;

  dd->history_capacity    = 20000;
  dd->value_history       = ck_alloc(dd->history_capacity * sizeof(u64));
  dd->coverage_rate_history = ck_alloc(dd->history_capacity * sizeof(double));
  dd->history_len         = 0;

  dd->drift_count       = 0;
  dd->reset_count        = 0;
  dd->last_queued_paths  = 0;
  dd->last_coverage      = 0;
  dd->last_p_value       = -1.0;
  dd->last_growth_rate   = 0.0;
  dd->last_stagnation_thresh = 0.0;

  SAYF(cGRN "[+] " cRST "Drift detection enabled:\n");
  SAYF("    Value drift: window=%u, threshold=%.3f, reset=%s\n",
       dd->window_size, dd->drift_threshold,
       dd->reset_on_drift ? "ON" : "OFF");
  SAYF("    Cooldown: %u iters, consecutive required: %u\n",
       dd->cooldown, dd->consecutive_required);
  SAYF("    Adaptive stagnation: ema_alpha=%.2f, stag_factor=%.2f\n",
       dd->ema_alpha, dd->stagnation_factor);

  return dd;

}

/* ================================================================
   drift_reset_history  (clear buffers after corpus reset)
   ================================================================ */

void drift_reset_history(struct drift_detector *dd) {
  if (!dd) return;
  dd->history_len = 0;
  dd->consecutive_drifts = 0;
  dd->cooldown_remaining = dd->cooldown;
}

/* ================================================================
   drift_destroy
   ================================================================ */

void drift_destroy(struct drift_detector *dd) {

  if (!dd) return;

  SAYF(cGRN "\n[+] " cRST "Drift detection summary:\n");
  SAYF("    Value drifts: %u, Resets: %u\n", dd->drift_count, dd->reset_count);

  ck_free(dd->value_history);
  ck_free(dd->coverage_rate_history);
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

  /* Cooldown: skip checks after a reset */
  if (dd->cooldown_remaining > 0) {
    dd->cooldown_remaining--;
    return 0;
  }

  /* Need at least 2 windows of data */
  if (dd->history_len < dd->window_size * 2) return 0;

  /* Adaptive stagnation check using EMA of growth rates */
  u32 current_end = dd->history_len - 1;
  u32 current_start  = dd->history_len - dd->window_size;
  u32 previous_start = current_start - dd->window_size;

  u64 recent_growth = dd->value_history[current_end] - dd->value_history[current_start];
  u64 previous_growth = dd->value_history[current_start] - dd->value_history[previous_start];
  double growth_rate = (double)recent_growth;

  /* Update EMA of growth rates */
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
    dd->last_p_value = -1.0;
    return 0;
  }

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

  /* Store p-value for CSV logging */
  dd->last_p_value = p_value;

  if (p_value < dd->drift_threshold) {

    dd->drift_count++;
    dd->consecutive_drifts++;

    SAYF(cYEL "\n[!] " cRST
         "VALUE DRIFT detected at iter %llu | p-value: %.4f | consecutive: %u/%u\n",
         (unsigned long long)current_iter, p_value,
         dd->consecutive_drifts, dd->consecutive_required);
    SAYF("    Growth: recent=%llu prev=%llu ema=%.1f threshold=%.1f\n",
         (unsigned long long)recent_growth, (unsigned long long)previous_growth,
         dd->growth_ema, stagnation_threshold);

    /* Require consecutive drift detections before acting */
    if (dd->consecutive_drifts < dd->consecutive_required) {
      SAYF("    WAITING - need %u more consecutive detections\n",
           dd->consecutive_required - dd->consecutive_drifts);
      return 0;
    }

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
      return 1;
    }

  } else {
    dd->consecutive_drifts = 0;
  }

  return 0;

}

/* ================================================================
   drift_write_stats  (human-readable diagnostic file)
   ================================================================ */

void drift_write_stats(struct drift_detector *dd, u8 *out_dir,
                       u64 queued_paths, u32 corpus_resets) {

  if (!dd || !out_dir) return;

  u8 *fn = alloc_printf("%s/drift_stats", out_dir);
  FILE *f = fopen((char *)fn, "w");
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
    q->weight = 0;       /* Bug 1 fix: prevent degenerate alias table */
    q->perf_score = 0;   /* Bug 1 fix: alias table uses raw weight for disabled entries */
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

  /* Bug 2 fix: clear stale top_rated[] pointers to disabled entries.
     cull_queue() (triggered by score_changed=1) dereferences top_rated[i]->trace_mini
     which was freed above; sweep before setting score_changed. */
  for (u32 j = 0; j < afl->fsrv.map_size; j++) {

    if (afl->top_rated[j] && afl->top_rated[j]->disabled) {

      afl->top_rated[j] = NULL;

    }

  }

  afl->score_changed  = 1;

  ACTF("Corpus reset #%u complete: disabled %u entries, kept %u seeds",
       corpus_reset_count, removed_count, afl->queued_at_start);

  /* Clear drift history so detector needs fresh data before re-triggering */
  drift_reset_history(drift_det);

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
          "minute,iterations,queued_paths,coverage,p_value,growth_rate,ema_growth,stagnation_thresh,consecutive_drifts,cooldown_remaining,reset_count,drift_count\n");
  fprintf(drift_csv_file, "0,0,0,0,-1,0,0,0,0,0,0,0\n");
  fflush(drift_csv_file);

  drift_csv_last_update = get_cur_time();
  drift_csv_minute      = 0;

}

static void drift_csv_update(u64 current_iter, u32 current_coverage,
                             u32 cur_queued) {

  if (!drift_csv_file) return;

  u64 now = get_cur_time();
  if (now - drift_csv_last_update < 60000) return;

  drift_csv_minute++;
  drift_csv_last_update = now;

  fprintf(drift_csv_file, "%u,%llu,%u,%u,%.6f,%.4f,%.4f,%.4f,%u,%u,%u,%u,%u\n",
          drift_csv_minute,
          (unsigned long long)current_iter,
          cur_queued,
          current_coverage,
          drift_det ? drift_det->last_p_value : -1.0,
          drift_det ? drift_det->last_growth_rate : 0.0,
          drift_det ? drift_det->growth_ema : 0.0,
          drift_det ? drift_det->last_stagnation_thresh : 0.0,
          drift_det ? drift_det->consecutive_drifts : 0,
          drift_det ? drift_det->cooldown_remaining : 0,
          corpus_reset_count,
          drift_det ? drift_det->drift_count : 0);
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

  /* Value drift check */
  if (drift_iteration >= drift_det->window_size &&
      drift_iteration % drift_det->window_size == 0) {

    if (drift_check_value(drift_det, drift_iteration)) {

      ACTF("Value drift detected at iteration %llu!",
           (unsigned long long)drift_iteration);
      WARNF("Performing corpus reset...");
      perform_corpus_reset(afl);
      ACTF("Resuming fuzzing from initial seeds...");

    }

  }

  drift_csv_update(drift_iteration, current_coverage, afl->queued_paths);

  /* Write human-readable stats file alongside CSV */
  drift_write_stats(drift_det, afl->out_dir, afl->queued_paths,
                    corpus_reset_count);

}

void drift_teardown(afl_state_t *afl) {

  if (corpus_reset_count > 0) {

    u64 total_time     = get_cur_time() - afl->start_time;

    SAYF("\n" cYEL "[*] Drift Detection Summary" cRST "\n");
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
