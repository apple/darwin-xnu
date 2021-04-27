#ifndef BENCHMARK_PERF_HELPERS_H
#define BENCHMARK_PERF_HELPERS_H

/*
 * Utility functions and constants used by perf tests.
 */
#include <inttypes.h>
#include <time.h>
#include <stdbool.h>

/*
 * mmap an anonymous chunk of memory.
 */
unsigned char *mmap_buffer(size_t size);
/*
 * Returns a - b in microseconds.
 * NB: a must be >= b
 */
uint64_t timespec_difference_us(const struct timespec* a, const struct timespec* b);
/*
 * Print the message to stdout along with the current time.
 * Also flushes stdout so that the log can help detect hangs. Don't call
 * this function from within the measured portion of the benchmark as it will
 * pollute your measurement.
 *
 * NB: Will only log if verbose == true.
 */
void benchmark_log(bool verbose, const char *restrict fmt, ...) __attribute__((format(printf, 2, 3)));

static const uint64_t kNumMicrosecondsInSecond = 1000UL * 1000;
static const uint64_t kNumNanosecondsInMicrosecond = 1000UL;
static const uint64_t kNumNanosecondsInSecond = kNumNanosecondsInMicrosecond * kNumMicrosecondsInSecond;
/* Get a (wall-time) timestamp in nanoseconds */
#define current_timestamp_ns() (clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW));

int get_ncpu(void);

#endif /* !defined(BENCHMARK_PERF_HELPERS_H) */
