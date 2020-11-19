/*
 * Madvise benchmark.
 * Currently only times various types of madvise frees.
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/sysctl.h>

#include "vm/perf_helpers.h"

typedef enum test_variant {
	VARIANT_MADVISE_FREE
} test_variant_t;

/* Arguments parsed from the command line */
typedef struct test_args {
	uint64_t ta_duration_seconds;
	uint64_t ta_size;
	test_variant_t ta_variant;
	bool ta_verbose;
} test_args_t;

static void print_help(char **argv);
static void parse_arguments(int argc, char** argv, test_args_t *args);
static double madvise_free_test(const test_args_t* args);
/*
 * Allocate a buffer of the given size and fault in all of its pages.
 */
static void *allocate_and_init_buffer(uint64_t size);
/*
 * Fault in the pages in the given buffer.
 */
static void fault_pages(unsigned char *buffer, size_t size, size_t stride);
/*
 * Output the results of the test in pages / CPU second.
 */
static void output_throughput(double throughput);

/* Test Variants */
static const char* kMadviseFreeArgument = "MADV_FREE";
/* The VM page size */
static size_t kPageSize = 0;
static const clockid_t kThreadCPUTimeClock = CLOCK_THREAD_CPUTIME_ID;

int
main(int argc, char** argv)
{
	test_args_t args;
	parse_arguments(argc, argv, &args);
	double throughput = 0.0;
	if (args.ta_variant == VARIANT_MADVISE_FREE) {
		throughput = madvise_free_test(&args);
	} else {
		fprintf(stderr, "Unknown test variant\n");
		exit(2);
	}
	output_throughput(throughput);
	return 0;
}

static double
madvise_free_test(const test_args_t* args)
{
	int ret, ret_end;
	assert(args->ta_variant == VARIANT_MADVISE_FREE);
	benchmark_log(args->ta_verbose, "Running madvise free test\n");
	size_t time_elapsed_us = 0;
	size_t count = 0;
	double throughput = 0;

	while (time_elapsed_us < args->ta_duration_seconds * kNumMicrosecondsInSecond) {
		benchmark_log(args->ta_verbose, "Starting iteration %zu\n", count + 1);
		void* buffer = allocate_and_init_buffer(args->ta_size);
		benchmark_log(args->ta_verbose, "Allocated and faulted in test buffer\n");
		struct timespec start_time, end_time;
		ret = clock_gettime(kThreadCPUTimeClock, &start_time);

		madvise(buffer, args->ta_size, MADV_FREE);

		ret_end = clock_gettime(kThreadCPUTimeClock, &end_time);
		assert(ret == 0);
		assert(ret_end == 0);
		time_elapsed_us += timespec_difference_us(&end_time, &start_time);

		ret = munmap(buffer, args->ta_size);
		assert(ret == 0);
		benchmark_log(args->ta_verbose, "Completed iteration %zu\nMeasured %zu time on CPU so far.\n", count + 1, time_elapsed_us);

		count++;
	}
	assert(kPageSize != 0);
	throughput = (count * args->ta_size) / ((double)time_elapsed_us / kNumMicrosecondsInSecond);
	return throughput;
}

static void *
allocate_and_init_buffer(uint64_t size)
{
	unsigned char *buffer = NULL;
	int ret;
	size_t len;
	if (kPageSize == 0) {
		size_t pagesize_size = sizeof(kPageSize);
		ret = sysctlbyname("vm.pagesize", &kPageSize, &pagesize_size, NULL, 0);
		assert(ret == 0);
		assert(kPageSize > 0);
	}
	len = size;
	buffer = mmap_buffer(len);
	fault_pages(buffer, len, kPageSize);
	return buffer;
}

static void
fault_pages(unsigned char *buffer, size_t size, size_t stride)
{
	volatile unsigned char val;
	for (unsigned char* ptr = buffer; ptr < buffer + size; ptr += stride) {
		val = *ptr;
	}
}

static void
parse_arguments(int argc, char** argv, test_args_t *args)
{
	int current_positional_argument = 0;
	long duration = -1, size_mb = -1;
	memset(args, 0, sizeof(test_args_t));
	for (int current_argument = 1; current_argument < argc; current_argument++) {
		if (argv[current_argument][0] == '-') {
			if (strcmp(argv[current_argument], "-v") == 0) {
				args->ta_verbose = true;
			} else {
				fprintf(stderr, "Unknown argument %s\n", argv[current_argument]);
				print_help(argv);
				exit(1);
			}
			if (current_argument >= argc) {
				print_help(argv);
				exit(1);
			}
		} else {
			if (current_positional_argument == 0) {
				if (strcasecmp(argv[current_argument], kMadviseFreeArgument) == 0) {
					args->ta_variant = VARIANT_MADVISE_FREE;
				} else {
					print_help(argv);
					exit(1);
				}
				current_positional_argument++;
			} else if (current_positional_argument == 1) {
				duration = strtol(argv[current_argument], NULL, 10);
				if (duration <= 0) {
					print_help(argv);
					exit(1);
				}
				current_positional_argument++;
			} else if (current_positional_argument == 2) {
				size_mb = strtol(argv[current_argument], NULL, 10);
				if (size_mb <= 0) {
					print_help(argv);
					exit(1);
				}
				current_positional_argument++;
			} else {
				print_help(argv);
				exit(1);
			}
		}
	}
	if (current_positional_argument != 3) {
		fprintf(stderr, "Expected 3 positional arguments. %d were supplied.\n", current_positional_argument);
		print_help(argv);
		exit(1);
	}
	args->ta_duration_seconds = (uint64_t) duration;
	args->ta_size = ((uint64_t) size_mb * (1UL << 20));
}

static void
print_help(char** argv)
{
	fprintf(stderr, "%s: <test-variant> [-v] duration_seconds size_mb\n", argv[0]);
	fprintf(stderr, "\ntest variants:\n");
	fprintf(stderr, "	%s	Measure MADV_FREE time.\n", kMadviseFreeArgument);
}

static void
output_throughput(double throughput)
{
	printf("-----Results-----\n");
	printf("Throughput (bytes / CPU second)\n");
	printf("%f\n", throughput);
}
