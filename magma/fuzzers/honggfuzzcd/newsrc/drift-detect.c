/*
 * honggfuzz - concept drift detection implementation
 * ---------------------------------------------------
 *
 * Concept drift detection with jerk tracking.
 * Matches EarlyStopFuzzer/MeanJerkFuzzer implementation from bits.ipynb.
 *
 * Adapted for honggfuzz: uses util_Calloc/util_Realloc/free,
 * LOG_I/LOG_W macros, and honggfuzz_t TAILQ corpus.
 */

#include "drift-detect.h"
#include "libhfcommon/common.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"

#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>
#include <unistd.h>

#include <gsl/gsl_sort.h>
#include <gsl/gsl_statistics_double.h>

/* ---------- Two-sample KS test ---------- */

static double ks_test_two_sample(double* data1, uint32_t n1,
                                  double* data2, uint32_t n2) {
    if (n1 == 0 || n2 == 0) return 1.0;

    double* sorted1 = (double*)util_Calloc(n1 * sizeof(double));
    double* sorted2 = (double*)util_Calloc(n2 * sizeof(double));

    memcpy(sorted1, data1, n1 * sizeof(double));
    memcpy(sorted2, data2, n2 * sizeof(double));

    gsl_sort(sorted1, 1, n1);
    gsl_sort(sorted2, 1, n2);

    double d_max = 0.0;
    uint32_t i = 0, j = 0;

    while (i < n1 && j < n2) {
        double cdf1 = (double)(i + 1) / n1;
        double cdf2 = (double)(j + 1) / n2;
        double diff = fabs(cdf1 - cdf2);
        if (diff > d_max) d_max = diff;
        if (sorted1[i] <= sorted2[j]) i++;
        if (sorted2[j] <= sorted1[i]) j++;
    }

    free(sorted1);
    free(sorted2);

    double n_eff  = sqrt((n1 * n2) / (double)(n1 + n2));
    double lambda = (n_eff + 0.12 + 0.11 / n_eff) * d_max;
    double p_value = 2.0 * exp(-2.0 * lambda * lambda);

    if (p_value > 1.0) p_value = 1.0;
    if (p_value < 0.0) p_value = 0.0;

    return p_value;
}

/* ---------- Initialization ---------- */

drift_detector_t* drift_init(const char* output_dir) {

    drift_detector_t* dd = (drift_detector_t*)util_Calloc(sizeof(drift_detector_t));

    const char* env_val;

    /* Value drift detection parameters */
    env_val = getenv("AFL_DRIFT_WINDOW");
    dd->window_size = env_val ? (uint32_t)atoi(env_val) : 100;

    env_val = getenv("AFL_DRIFT_THRESHOLD");
    dd->drift_threshold = env_val ? atof(env_val) : 0.05;

    dd->reset_on_drift = true;   /* Always on */

    /* Jerk tracking parameters */
    env_val = getenv("AFL_METRICS_WINDOW");
    dd->metrics_window_size = env_val ? (uint32_t)atoi(env_val) : 100;

    env_val = getenv("AFL_JERK_WINDOW");
    dd->jerk_window_size = env_val ? (uint32_t)atoi(env_val) : 1000;

    env_val = getenv("AFL_MEAN_JERK_WINDOW");
    dd->mean_jerk_window = env_val ? (uint32_t)atoi(env_val) : 100;

    dd->stop_on_jerk_drift = false;  /* Always off — detect-and-log only */

    /* Allocate history buffers */
    dd->history_capacity = 20000;
    dd->value_history = (uint64_t*)util_Calloc(dd->history_capacity * sizeof(uint64_t));
    dd->coverage_rate_history = (double*)util_Calloc(dd->history_capacity * sizeof(double));
    dd->history_len = 0;

    /* Jerk tracking buffers */
    dd->jerk_history_capacity = 20000;
    dd->sliding_jerk_history = (double*)util_Calloc(dd->jerk_history_capacity * sizeof(double));
    dd->jerk_history_len = 0;

    dd->mean_jerk_capacity = 1000;
    dd->mean_jerk_history = (double*)util_Calloc(dd->mean_jerk_capacity * sizeof(double));
    dd->mean_jerk_len = 0;

    /* Init statistics */
    dd->drift_count       = 0;
    dd->reset_count       = 0;
    dd->jerk_drift_count  = 0;
    dd->stopped_early     = false;
    dd->stop_iteration    = 0;
    dd->last_queued_paths = 0;
    dd->last_coverage     = 0;
    dd->iteration         = 0;

    dd->jerk_drift_detected   = false;
    dd->jerk_drift_iteration  = 0;
    dd->jerk_drift_time_ms    = 0;
    dd->jerk_drift_coverage   = 0;

    dd->corpus_reset_count            = 0;
    dd->first_corpus_reset_iteration  = 0;
    dd->first_corpus_reset_time_ms    = 0;
    dd->last_corpus_reset_iteration   = 0;
    dd->last_corpus_reset_time_ms     = 0;
    dd->initial_corpus_count          = 0;

    /* CSV logging */
    dd->csv_file = NULL;
    dd->csv_last_update_ms = 0;
    dd->csv_minute = 0;

    if (output_dir) {
        char csv_path[PATH_MAX];
        snprintf(csv_path, sizeof(csv_path), "%s/drift_log.csv", output_dir);
        dd->csv_file = fopen(csv_path, "w");
        if (dd->csv_file) {
            fprintf(dd->csv_file, "timestamp,iterations,coverage,reset_flag,early_stop_flag\n");
            fprintf(dd->csv_file, "0,0,0,false,false\n");
            fflush(dd->csv_file);
        } else {
            LOG_W("Could not create drift CSV at '%s': %s", csv_path, strerror(errno));
        }
    }

    LOG_I("Drift detection with jerk tracking enabled:");
    LOG_I("  Value drift: window=%u, threshold=%.3f, reset=%s",
          dd->window_size, dd->drift_threshold, dd->reset_on_drift ? "ON" : "OFF");
    LOG_I("  Jerk tracking: window=%u, mean_jerk_window=%u",
          dd->jerk_window_size, dd->mean_jerk_window);
    LOG_I("  Early stop on jerk drift: %s", dd->stop_on_jerk_drift ? "YES" : "NO");

    return dd;
}

/* ---------- Cleanup ---------- */

void drift_destroy(drift_detector_t* dd) {
    if (!dd) return;

    LOG_I("Drift detection summary:");
    LOG_I("  Value drifts: %u, Resets: %u", dd->drift_count, dd->reset_count);
    LOG_I("  Jerk drifts: %u", dd->jerk_drift_count);
    if (dd->stopped_early) {
        LOG_I("  Early stop at iteration: %" PRIu64, dd->stop_iteration);
    }

    if (dd->csv_file) {
        fclose(dd->csv_file);
        dd->csv_file = NULL;
    }

    free(dd->value_history);
    free(dd->coverage_rate_history);
    free(dd->sliding_jerk_history);
    free(dd->mean_jerk_history);
    free(dd);
}

/* ---------- Update ---------- */

void drift_update(drift_detector_t* dd, uint64_t current_iter,
                  uint64_t queued_paths, uint64_t coverage) {
    if (!dd) return;

    /* Expand buffers if needed */
    if (dd->history_len >= dd->history_capacity) {
        dd->history_capacity *= 2;
        dd->value_history = (uint64_t*)util_Realloc(
            dd->value_history, dd->history_capacity * sizeof(uint64_t));
        dd->coverage_rate_history = (double*)util_Realloc(
            dd->coverage_rate_history, dd->history_capacity * sizeof(double));
    }

    dd->value_history[dd->history_len] = queued_paths;

    double coverage_rate = (current_iter > 0)
        ? ((double)queued_paths / (double)current_iter) : 0.0;
    dd->coverage_rate_history[dd->history_len] = coverage_rate;

    dd->history_len++;
    dd->last_queued_paths = queued_paths;
    dd->last_coverage     = coverage;
}

/* ---------- Jerk calculation ---------- */

void drift_calculate_jerk(drift_detector_t* dd, uint64_t current_iter) {
    (void)current_iter;
    if (!dd) return;
    if (dd->history_len < dd->jerk_window_size) return;

    if (dd->jerk_history_len >= dd->jerk_history_capacity) {
        dd->jerk_history_capacity *= 2;
        dd->sliding_jerk_history = (double*)util_Realloc(
            dd->sliding_jerk_history, dd->jerk_history_capacity * sizeof(double));
    }

    uint32_t window_start = dd->history_len - dd->jerk_window_size;
    uint64_t coverage_start = dd->value_history[window_start];
    uint64_t coverage_end   = dd->value_history[dd->history_len - 1];
    double velocity = (double)(coverage_end - coverage_start) / dd->jerk_window_size;

    if (dd->jerk_history_len < 1) {
        dd->sliding_jerk_history[dd->jerk_history_len++] = 0.0;
        return;
    }

    if (dd->history_len > dd->jerk_window_size + 1) {
        uint32_t prev_window_start = window_start - 1;
        if (prev_window_start >= dd->jerk_window_size) {
            uint64_t prev_coverage_start = dd->value_history[prev_window_start - dd->jerk_window_size];
            uint64_t prev_coverage_end   = dd->value_history[prev_window_start];
            double prev_velocity = (double)(prev_coverage_end - prev_coverage_start) / dd->jerk_window_size;
            double acceleration = velocity - prev_velocity;
            dd->sliding_jerk_history[dd->jerk_history_len++] = acceleration;
        }
    }
}

/* ---------- Mean jerk recording ---------- */

void drift_record_mean_jerk(drift_detector_t* dd) {
    if (!dd) return;
    if (dd->jerk_history_len < dd->mean_jerk_window) return;

    if (dd->mean_jerk_len >= dd->mean_jerk_capacity) {
        dd->mean_jerk_capacity *= 2;
        dd->mean_jerk_history = (double*)util_Realloc(
            dd->mean_jerk_history, dd->mean_jerk_capacity * sizeof(double));
    }

    uint32_t start_idx = dd->jerk_history_len >= dd->mean_jerk_window
        ? dd->jerk_history_len - dd->mean_jerk_window : 0;
    uint32_t count = dd->jerk_history_len - start_idx;

    double mean_jerk = gsl_stats_mean(dd->sliding_jerk_history + start_idx, 1, count);
    dd->mean_jerk_history[dd->mean_jerk_len++] = mean_jerk;
}

/* ---------- Coverage rate check ---------- */

bool drift_is_coverage_rate_increasing(drift_detector_t* dd) {
    if (!dd) return true;
    if (dd->history_len < dd->window_size * 2) return true;

    uint32_t current_start  = dd->history_len - dd->window_size;
    uint32_t previous_start = current_start - dd->window_size;

    double avg_current  = gsl_stats_mean(dd->coverage_rate_history + current_start,
                                          1, dd->window_size);
    double avg_previous = gsl_stats_mean(dd->coverage_rate_history + previous_start,
                                          1, dd->window_size);

    return avg_current > avg_previous;
}

/* ---------- Value drift check ---------- */

bool drift_check_value(drift_detector_t* dd, uint64_t current_iter) {
    if (!dd) return false;
    if (dd->history_len < dd->window_size * 2) return false;

    uint32_t current_start  = dd->history_len - dd->window_size;
    uint32_t previous_start = current_start - dd->window_size;

    double* current_values  = (double*)util_Calloc(dd->window_size * sizeof(double));
    double* previous_values = (double*)util_Calloc(dd->window_size * sizeof(double));

    for (uint32_t i = 0; i < dd->window_size; i++) {
        current_values[i]  = (double)dd->value_history[current_start + i];
        previous_values[i] = (double)dd->value_history[previous_start + i];
    }

    double p_value = ks_test_two_sample(previous_values, dd->window_size,
                                         current_values, dd->window_size);

    free(current_values);
    free(previous_values);

    if (p_value < dd->drift_threshold) {
        dd->drift_count++;

        LOG_I("VALUE DRIFT detected at iter %" PRIu64 " | p-value: %.4f",
              current_iter, p_value);

        bool is_increasing = drift_is_coverage_rate_increasing(dd);
        LOG_I("  Coverage rate increasing: %s", is_increasing ? "YES" : "NO");

        if (dd->reset_on_drift && !is_increasing) {
            dd->reset_count++;
            LOG_W("  CORPUS RESET - Coverage rate not increasing");
            return true;  /* Signal reset needed */
        } else if (dd->reset_on_drift && is_increasing) {
            LOG_I("  NO RESET - Coverage rate is increasing");
        }
    }

    return false;
}

/* ---------- Jerk drift check ---------- */

bool drift_check_jerk(drift_detector_t* dd, uint64_t current_iter) {
    if (!dd) return false;
    if (dd->mean_jerk_len < 20) return false;

    uint32_t half_point = dd->mean_jerk_len / 2;
    if (half_point < 2) return false;

    double* previous_jerks = dd->mean_jerk_history;
    double* current_jerks  = dd->mean_jerk_history + half_point;
    uint32_t current_len   = dd->mean_jerk_len - half_point;

    double p_value = ks_test_two_sample(previous_jerks, half_point,
                                         current_jerks, current_len);

    if (p_value < dd->drift_threshold) {
        dd->jerk_drift_count++;

        double mean_prev = gsl_stats_mean(previous_jerks, 1, half_point);
        double mean_curr = gsl_stats_mean(current_jerks, 1, current_len);

        LOG_I("JERK DRIFT detected at iter %" PRIu64 " | p-value: %.4f",
              current_iter, p_value);
        LOG_I("  Mean jerk: %.3f -> %.3f", mean_prev, mean_curr);

        if (dd->stop_on_jerk_drift) {
            dd->stopped_early    = true;
            dd->stop_iteration   = current_iter;
            LOG_W("EARLY STOP triggered at iteration %" PRIu64, current_iter);
        }

        return true;
    }

    return false;
}

/* ---------- Early stop check ---------- */

bool drift_should_stop(drift_detector_t* dd) {
    if (!dd || !dd->stop_on_jerk_drift) return false;
    return dd->stopped_early;
}

/* ---------- CSV update ---------- */

void drift_csv_update(drift_detector_t* dd, uint64_t current_iter,
                      uint64_t coverage, uint64_t elapsed_ms) {
    if (!dd || !dd->csv_file) return;

    if (elapsed_ms - dd->csv_last_update_ms < 60000) return;

    dd->csv_minute++;
    dd->csv_last_update_ms = elapsed_ms;

    fprintf(dd->csv_file, "%u,%" PRIu64 ",%" PRIu64 ",%s,%s\n",
            dd->csv_minute,
            current_iter,
            coverage,
            dd->corpus_reset_count > 0 ? "true" : "false",
            dd->jerk_drift_detected ? "true" : "false");
    fflush(dd->csv_file);
}

/* ---------- Corpus reset ---------- */

void drift_perform_corpus_reset(drift_detector_t* dd, honggfuzz_t* hfuzz) {
    if (!dd) return;

    if (dd->initial_corpus_count == 0) {
        LOG_W("No initial corpus size recorded, skipping reset");
        return;
    }

    LOG_I("Resetting corpus to %zu initial seeds...", dd->initial_corpus_count);

    /*
     * Walk the TAILQ and remove entries beyond the initial corpus.
     * We keep the first initial_corpus_count entries and free the rest.
     * Must hold the dynfileq write lock.
     */
    MX_SCOPED_RWLOCK_WRITE(&hfuzz->mutex.dynfileq);

    size_t kept = 0;
    size_t removed = 0;
    dynfile_t* entry;
    dynfile_t* tmp;

    /* We need TAILQ_FOREACH_SAFE equivalent; honggfuzz uses TAILQ_FOREACH_HF
       but that's not safe for removal. Use manual iteration. */
    entry = TAILQ_FIRST(&hfuzz->io.dynfileq);
    while (entry != NULL) {
        tmp = TAILQ_NEXT(entry, pointers);
        if (kept < dd->initial_corpus_count) {
            kept++;
        } else {
            /* Remove this entry */
            TAILQ_REMOVE(&hfuzz->io.dynfileq, entry, pointers);
            if (entry->data) {
                free(entry->data);
            }
            free(entry);
            removed++;
        }
        entry = tmp;
    }

    /* Update corpus count */
    ATOMIC_SET(hfuzz->io.dynfileqCnt, (size_t)kept);

    /* Reset the current pointers so threads pick from the beginning */
    hfuzz->io.dynfileqCurrent  = TAILQ_FIRST(&hfuzz->io.dynfileq);
    hfuzz->io.dynfileq2Current = TAILQ_FIRST(&hfuzz->io.dynfileq);

    /* Track reset events */
    uint64_t elapsed_sec = (uint64_t)(time(NULL) - hfuzz->timing.timeStart);
    uint64_t elapsed_ms  = elapsed_sec * 1000;

    dd->corpus_reset_count++;
    if (dd->corpus_reset_count == 1) {
        dd->first_corpus_reset_iteration = dd->iteration;
        dd->first_corpus_reset_time_ms   = elapsed_ms;
    }
    dd->last_corpus_reset_iteration = dd->iteration;
    dd->last_corpus_reset_time_ms   = elapsed_ms;

    LOG_I("Corpus reset: kept %zu seeds, removed %zu entries", kept, removed);
}
