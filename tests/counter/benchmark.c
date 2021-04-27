/* Per-cpu counter microbenchmarks. */

#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/sysctl.h>

#include "benchmark/helpers.h"
#include "counter/common.h"

typedef enum test_variant {
	VARIANT_SCALABLE_COUNTER,
	VARIANT_ATOMIC,
	VARIANT_RACY
} test_variant_t;

static const char* kScalableCounterArgument = "scalable";
static const char* kAtomicCounterArgument = "atomic";
static const char* kRacyCounterArgument = "racy";

static const int64_t kChunkSize = 100000000;

/* Arguments parsed from the command line */
typedef struct test_args {
	size_t n_threads;
	unsigned long long num_writes;
	test_variant_t variant;
	bool verbose;
} test_args_t;

typedef struct {
	char _padding1[128];
	atomic_bool tg_test_start;
	atomic_ullong tg_num_writes_remaining;
	atomic_ullong tg_threads_ready;
	test_args_t tg_args;
	uint64_t tg_start_time;
	uint64_t tg_end_time;
	uint64_t tg_start_value;
	uint64_t tg_end_value;
	char _padding2[128];
} test_globals_t;

static void parse_arguments(int argc, char** argv, test_args_t *args);
static const char *get_sysctl_name_for_test_variant(test_variant_t variant);
static void *writer(void *);
static uint64_t counter_read(test_variant_t);

int
main(int argc, char** argv)
{
	test_globals_t globals = {0};
	pthread_t* threads = NULL;
	int ret;
	int is_development_kernel;
	size_t is_development_kernel_size = sizeof(is_development_kernel);
	pthread_attr_t pthread_attrs;
	uint64_t duration, writes_stored;
	double writes_per_second;
	double loss;

	if (sysctlbyname("kern.development", &is_development_kernel,
	    &is_development_kernel_size, NULL, 0) != 0 || !is_development_kernel) {
		fprintf(stderr, "%s requires the development kernel\n", argv[0]);
		exit(1);
	}

	parse_arguments(argc, argv, &(globals.tg_args));
	atomic_store(&(globals.tg_num_writes_remaining), globals.tg_args.num_writes);

	threads = malloc(sizeof(pthread_t) * globals.tg_args.n_threads);
	assert(threads);
	ret = pthread_attr_init(&pthread_attrs);
	assert(ret == 0);
	ret = init_scalable_counter_test();
	assert(ret == 0);
	globals.tg_start_value = counter_read(globals.tg_args.variant);
	for (size_t i = 0; i < globals.tg_args.n_threads; i++) {
		ret = pthread_create(threads + i, &pthread_attrs, writer, &globals);
		assert(ret == 0);
	}
	for (size_t i = 0; i < globals.tg_args.n_threads; i++) {
		ret = pthread_join(threads[i], NULL);
		assert(ret == 0);
	}
	ret = fini_scalable_counter_test();
	assert(ret == 0);
	globals.tg_end_value = counter_read(globals.tg_args.variant);

	duration = globals.tg_end_time - globals.tg_start_time;
	printf("-----Results-----\n");
	printf("rate,loss\n");
	writes_per_second = globals.tg_args.num_writes / ((double) duration / kNumNanosecondsInSecond);
	writes_stored = globals.tg_end_value - globals.tg_start_value;
	loss = (1.0 - ((double) writes_stored / globals.tg_args.num_writes)) * 100;
	printf("%.4f,%.4f\n", writes_per_second, loss);
	return 0;
}

static void *
writer(void *arg)
{
	int ret;
	const char* sysctl_name;
	test_globals_t *globals = arg;
	int64_t value = kChunkSize;
	//size_t size = sizeof(value);

	sysctl_name = get_sysctl_name_for_test_variant(globals->tg_args.variant);
	assert(sysctl_name != NULL);

	if (atomic_fetch_add(&(globals->tg_threads_ready), 1) == globals->tg_args.n_threads - 1) {
		globals->tg_start_time = current_timestamp_ns();
		atomic_store(&globals->tg_test_start, true);
	}
	while (!atomic_load(&(globals->tg_test_start))) {
		;
	}

	while (true) {
		unsigned long long remaining = atomic_fetch_sub(&(globals->tg_num_writes_remaining), value);
		if (remaining < kChunkSize || remaining > globals->tg_args.num_writes) {
			break;
		}

		ret = sysctlbyname(sysctl_name, NULL, NULL, &value, sizeof(value));
		assert(ret == 0);
		if (remaining == kChunkSize || remaining - kChunkSize > remaining) {
			break;
		}
	}

	if (atomic_fetch_sub(&(globals->tg_threads_ready), 1) == 1) {
		globals->tg_end_time = current_timestamp_ns();
	}

	return NULL;
}

static const char*
get_sysctl_name_for_test_variant(test_variant_t variant)
{
	switch (variant) {
	case VARIANT_SCALABLE_COUNTER:
		return "kern.scalable_counter_write_benchmark";
	case VARIANT_ATOMIC:
		return "kern.scalable_counter_atomic_counter_write_benchmark";
	case VARIANT_RACY:
		return "kern.scalable_counter_racy_counter_benchmark";
	default:
		return NULL;
	}
}

static const char*
get_sysctl_load_name_for_test_variant(test_variant_t variant)
{
	switch (variant) {
	case VARIANT_SCALABLE_COUNTER:
		return "kern.scalable_counter_test_load";
	case VARIANT_ATOMIC:
		return "kern.scalable_counter_atomic_counter_load";
	case VARIANT_RACY:
		return "kern.scalable_counter_racy_counter_load";
	default:
		return NULL;
	}
}

static uint64_t
counter_read(test_variant_t variant)
{
	const char *sysctl_name = get_sysctl_load_name_for_test_variant(variant);
	int result;
	uint64_t value;
	size_t size = sizeof(value);
	result = sysctlbyname(sysctl_name, &value, &size, NULL, 0);
	assert(result == 0);
	return value;
}

static void
print_help(char** argv)
{
	fprintf(stderr, "%s: <test-variant> [-v] num_writes num_threads\n", argv[0]);
	fprintf(stderr, "\ntest variants:\n");
	fprintf(stderr, "	%s	Benchmark scalable counters.\n", kScalableCounterArgument);
	fprintf(stderr, "	%s	Benchmark single atomic counter.\n", kAtomicCounterArgument);
	fprintf(stderr, "	%s	Benchmark racy counter.\n", kRacyCounterArgument);
}

static void
parse_arguments(int argc, char** argv, test_args_t *args)
{
	int current_argument = 1;
	memset(args, 0, sizeof(test_args_t));
	if (argc < 4 || argc > 6) {
		print_help(argv);
		exit(1);
	}
	if (argv[current_argument][0] == '-') {
		if (strcmp(argv[current_argument], "-v") == 0) {
			args->verbose = true;
		} else {
			fprintf(stderr, "Unknown argument %s\n", argv[current_argument]);
			print_help(argv);
			exit(1);
		}
		current_argument++;
	}
	if (strncasecmp(argv[current_argument], kScalableCounterArgument, strlen(kScalableCounterArgument)) == 0) {
		args->variant = VARIANT_SCALABLE_COUNTER;
	} else if (strncasecmp(argv[current_argument], kAtomicCounterArgument, strlen(kAtomicCounterArgument)) == 0) {
		args->variant = VARIANT_ATOMIC;
	} else if (strncasecmp(argv[current_argument], kRacyCounterArgument, strlen(kRacyCounterArgument)) == 0) {
		args->variant = VARIANT_RACY;
	} else {
		print_help(argv);
		exit(1);
	}
	current_argument++;

	long num_writes = strtol(argv[current_argument++], NULL, 10);
	if (num_writes == 0) {
		print_help(argv);
		exit(1);
	}
	long num_cores = strtol(argv[current_argument++], NULL, 10);
	if (num_cores == 0) {
		print_help(argv);
		exit(1);
	}
	assert(num_cores > 0 && num_cores <= get_ncpu());
	args->n_threads = (unsigned int) num_cores;
	args->num_writes = (unsigned long long) num_writes;
}
