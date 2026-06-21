/*
 * honggfuzz - concept drift detection implementation
 * ---------------------------------------------------
 *
 * Concept drift detection.
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
        if (j < n2 && sorted2[j] <= sorted1[i < n1 ? i : n1 - 1]) j++;
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

    env_val = getenv("AFL_DRIFT_CONSECUTIVE");
    dd->consecutive_threshold = env_val ? (uint32_t)atoi(env_val) : 5;

    env_val = getenv("AFL_DRIFT_COOLDOWN");
    dd->cooldown_threshold = env_val ? (uint32_t)atoi(env_val) : 10;

    dd->reset_on_drift = true;   /* Always on */

    /* Allocate history buffers */
    dd->history_capacity = 20000;
    dd->value_history = (uint64_t*)util_Calloc(dd->history_capacity * sizeof(uint64_t));
    dd->coverage_rate_history = (double*)util_Calloc(dd->history_capacity * sizeof(double));
    dd->history_len = 0;

    /* Init statistics */
    dd->drift_count       = 0;
    dd->reset_count       = 0;
    dd->last_queued_paths = 0;
    dd->last_coverage     = 0;
    dd->iteration         = 0;

    dd->corpus_reset_count            = 0;
    dd->first_corpus_reset_iteration  = 0;
    dd->first_corpus_reset_time_ms    = 0;
    dd->last_corpus_reset_iteration   = 0;
    dd->last_corpus_reset_time_ms     = 0;
    dd->initial_corpus_count          = 0;
    dd->consecutive_drifts            = 0;
    dd->cooldown_remaining            = 0;

    dd->last_p_value      = -1.0;
    dd->last_growth_rate  = 0.0;

    /* Cache output directory for stats file */
    if (output_dir) {
        snprintf(dd->output_dir, sizeof(dd->output_dir), "%s", output_dir);
    } else {
        dd->output_dir[0] = '\0';
    }

    /* CSV logging */
    dd->csv_file = NULL;
    dd->csv_last_update_ms = 0;
    dd->csv_minute = 0;

    if (output_dir) {
        char csv_path[PATH_MAX];
        snprintf(csv_path, sizeof(csv_path), "%s/drift_log.csv", output_dir);
        dd->csv_file = fopen(csv_path, "w");
        if (dd->csv_file) {
            fprintf(dd->csv_file, "minute,iterations,queued_paths,coverage,p_value,growth_rate,ema_growth,stagnation_thresh,consecutive_drifts,cooldown_remaining,reset_count,drift_count\n");
            fprintf(dd->csv_file, "0,0,0,0,-1,0,0,0,0,0,0,0\n");
            fflush(dd->csv_file);
        } else {
            LOG_W("Could not create drift CSV at '%s': %s", csv_path, strerror(errno));
        }
    }

    LOG_I("Drift detection enabled:");
    LOG_I("  Value drift: window=%u, threshold=%.3f, consecutive=%u, cooldown=%u, reset=%s",
          dd->window_size, dd->drift_threshold,
          dd->consecutive_threshold, dd->cooldown_threshold,
          dd->reset_on_drift ? "ON" : "OFF");

    return dd;
}

/* ---------- Cleanup ---------- */

void drift_destroy(drift_detector_t* dd) {
    if (!dd) return;

    LOG_I("Drift detection summary:");
    LOG_I("  Value drifts: %u, Resets: %u", dd->drift_count, dd->reset_count);

    if (dd->csv_file) {
        fclose(dd->csv_file);
        dd->csv_file = NULL;
    }

    free(dd->value_history);
    free(dd->coverage_rate_history);
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

    /* --- Cooldown gate ---
     * After each reset, skip this many time-gate windows before checking again.
     * This mirrors AFL_DRIFT_COOLDOWN semantics in the AFL-based CD fuzzers. */
    if (dd->cooldown_remaining > 0) {
        dd->cooldown_remaining--;
        return false;
    }

    uint32_t current_start  = dd->history_len - dd->window_size;
    uint32_t previous_start = current_start - dd->window_size;
    uint32_t current_end    = dd->history_len - 1;

    /* Store growth rate diagnostic */
    dd->last_growth_rate = (double)(dd->value_history[current_end] -
                                    dd->value_history[current_start]);

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

    /* Store p-value diagnostic */
    dd->last_p_value = p_value;

    if (p_value < dd->drift_threshold) {
        dd->drift_count++;

        LOG_I("VALUE DRIFT detected at iter %" PRIu64 " | p-value: %.4f | consecutive: %u/%u",
              current_iter, p_value, dd->consecutive_drifts + 1, dd->consecutive_threshold);

        bool is_increasing = drift_is_coverage_rate_increasing(dd);
        LOG_I("  Coverage rate increasing: %s", is_increasing ? "YES" : "NO");

        if (dd->reset_on_drift && !is_increasing) {
            dd->consecutive_drifts++;
            if (dd->consecutive_drifts >= dd->consecutive_threshold) {
                /* Threshold reached — fire reset */
                dd->consecutive_drifts = 0;
                dd->cooldown_remaining = dd->cooldown_threshold;
                dd->reset_count++;
                LOG_W("  CORPUS RESET - %u consecutive drifts reached", dd->consecutive_threshold);
                return true;
            } else {
                LOG_I("  NO RESET yet - %u/%u consecutive drifts",
                      dd->consecutive_drifts, dd->consecutive_threshold);
            }
        } else {
            /* Coverage is increasing — not a stagnation event, reset counter */
            dd->consecutive_drifts = 0;
            LOG_I("  NO RESET - Coverage rate is increasing");
        }
    } else {
        /* No drift this window — reset consecutive counter */
        dd->consecutive_drifts = 0;
    }

    return false;
}

/* ---------- CSV update ---------- */

void drift_csv_update(drift_detector_t* dd, uint64_t current_iter,
                      uint64_t coverage, uint64_t elapsed_ms,
                      uint64_t corpus) {
    if (!dd || !dd->csv_file) return;

    if (elapsed_ms - dd->csv_last_update_ms < 60000) return;

    dd->csv_minute++;
    dd->csv_last_update_ms = elapsed_ms;

    fprintf(dd->csv_file, "%u,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%.6f,%.4f,0,0,%u,%u,%u,%u\n",
            dd->csv_minute,
            current_iter,
            corpus,
            coverage,
            dd->last_p_value,
            dd->last_growth_rate,
            dd->consecutive_drifts,
            dd->cooldown_remaining,
            dd->corpus_reset_count,
            dd->drift_count);
    fflush(dd->csv_file);

    /* Write human-readable stats file alongside CSV */
    drift_write_stats_file(dd, dd->output_dir[0] ? dd->output_dir : NULL, corpus);
}

/* ---------- Corpus reset ---------- */

void drift_perform_corpus_reset(drift_detector_t* dd, honggfuzz_t* hfuzz,
                                size_t keep_seeds, size_t keep_recent) {
    if (!dd) return;

    if (keep_seeds == 0) {
        /* Caller explicitly supplied 0 — fall back to recorded initial count */
        keep_seeds = dd->initial_corpus_count;
    }
    if (keep_seeds == 0) {
        LOG_W("No initial corpus size recorded, skipping reset");
        return;
    }

    LOG_I("Selective corpus reset: keeping %zu seeds + %zu most-recent entries",
          keep_seeds, keep_recent);

    /*
     * Selective reset: keep the first keep_seeds entries (original seeds, at
     * the TAILQ head) and the keep_recent most-recently-added entries (TAILQ
     * tail).  Everything in between — the "middle-aged" entries — is removed.
     *
     * If the corpus is small enough that seeds and recent entries overlap,
     * nothing is removed (the fuzzer hasn't built up a large corpus yet).
     *
     * Must hold the dynfileq write lock.
     */
    MX_SCOPED_RWLOCK_WRITE(&hfuzz->mutex.dynfileq);

    /* --- Pass 1: count total entries --- */
    size_t total = 0;
    {
        dynfile_t* e = TAILQ_FIRST(&hfuzz->io.dynfileq);
        while (e != NULL) { total++; e = TAILQ_NEXT(e, pointers); }
    }

    /* --- Compute removal range [remove_start, remove_end) ---
     * remove_start: first index past the seed block
     * remove_end  : first index of the recent block
     * If remove_end <= remove_start there is nothing to remove. */
    size_t remove_start = keep_seeds;
    size_t remove_end   = (total > keep_seeds + keep_recent)
                          ? total - keep_recent
                          : keep_seeds;

    /* --- Pass 2: walk queue, removing the middle-aged range --- */
    size_t kept = 0;
    size_t removed = 0;
    size_t idx = 0;
    dynfile_t* entry = TAILQ_FIRST(&hfuzz->io.dynfileq);
    while (entry != NULL) {
        dynfile_t* tmp = TAILQ_NEXT(entry, pointers);
        if (idx >= remove_start && idx < remove_end) {
            TAILQ_REMOVE(&hfuzz->io.dynfileq, entry, pointers);
            /* Zombie: do NOT free entry->data or entry.  Worker threads in
             * input_prepareDynamicInput() hold a raw dynfile_t* (run->current)
             * outside the dynfileq lock.  Freeing the struct while a thread
             * holds that pointer causes a use-after-free (observed dist4).
             * Setting size=0 marks the entry as expired: any thread that still
             * holds the pointer will call input_setSize(run,0) and
             * memcpy(...,data,0) — both safe.  The entry's memory is
             * intentionally leaked; resets are rare so the leak is negligible. */
            entry->size = 0;
            removed++;
        } else {
            kept++;
        }
        idx++;
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

    size_t kept_seeds  = (kept < keep_seeds) ? kept : keep_seeds;
    size_t kept_recent = (kept > keep_seeds) ? (kept - keep_seeds) : 0;
    LOG_I("Corpus reset: kept %zu entries (%zu seeds + %zu recent), removed %zu",
          kept, kept_seeds, kept_recent, removed);

    /* Clear drift history so detector needs fresh data before re-triggering */
    dd->history_len = 0;
}

/* Write human-readable diagnostic stats file */
void drift_write_stats_file(drift_detector_t* dd, const char* out_dir,
                            uint64_t queued_paths) {
    if (!dd || !out_dir) return;

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/drift_stats", out_dir);
    FILE* f = fopen(path, "w");
    if (!f) return;

    fprintf(f, "drift_window        : %u\n", dd->window_size);
    fprintf(f, "drift_threshold     : %.4f\n", dd->drift_threshold);
    fprintf(f, "history_len         : %u\n", dd->history_len);
    fprintf(f, "queued_paths        : %" PRIu64 "\n", queued_paths);
    fprintf(f, "drift_count         : %u\n", dd->drift_count);
    fprintf(f, "reset_count         : %u\n", dd->reset_count);
    fprintf(f, "corpus_resets       : %u\n", dd->corpus_reset_count);
    fprintf(f, "last_p_value        : %.6f\n", dd->last_p_value);
    fprintf(f, "last_growth_rate    : %.4f\n", dd->last_growth_rate);
    fprintf(f, "iteration           : %" PRIu64 "\n", dd->iteration);

    fclose(f);
}
