/*
 * Benchmark VM fault throughput.
 * This test faults memory for a configurable amount of time across a
 * configurable number of threads. Currently it only measures zero fill faults.
 * Currently it supports two variants:
 * 1. Each thread gets its own vm objects to fault in
 * 2. Threads share vm objects
 *
 * We'll add more fault types as we identify problematic user-facing workloads
 * in macro benchmarks.
 *
 * Throughput is reported as pages / second using both wall time and cpu time.
 * CPU time is a more reliable metric for regression testing, but wall time can
 * highlight blocking in the VM.
 *
 * Running this benchmark directly is not recommended.
 * Use fault_throughput.lua which provides a nicer interface and outputs
 * perfdata.
 */
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/sysctl.h>

/*
 * TODO: Make this benchmark runnable on linux so we can do a perf comparison.
 * We're mostly using POSIX APIs, but we'll need to replace
 * the sysctls with the /proc equivalents, and replace clock_gettime_nsec_np
 * with the linux equivalent.
 */
#include <mach/mach.h>

#include <TargetConditionals.h>

#include <pthread.h>
#include <stdatomic.h>

#include "vm/perf_helpers.h"

#if (TARGET_OS_OSX || TARGET_OS_SIMULATOR)
/*
 * On non-embedded platforms we coalesce vm objects up to 128 MB, so
 * we make the objects 128 MB on that platform to ensure they're not
 * merged with anything else.
 */
const static size_t kVmObjectSize = 128 * (1UL << 20);
#else
/*
 * Embedded platforms don't coalesce vm objects. This number
 * needs to be big enough that faulting it in dwarfs the cost of dequeuing
 * it from the work queue, but can't be too large or else we won't be able
 * to allocate one per thread in the separate-objects benchmark.
 */
const static size_t kVmObjectSize = 4 * (1UL << 20);
#endif /* (TARGET_OS_OSX || TARGET_OS_SIMULATOR) */
static const clockid_t kWallTimeClock = CLOCK_MONOTONIC_RAW;
static const clockid_t kThreadCPUTimeClock = CLOCK_THREAD_CPUTIME_ID;
/* These globals are set dynamically during test setup based on sysctls. */
static uint64_t kCacheLineSize = 0;
/* The VM page size */
static size_t kPageSize = 0;


typedef struct fault_buffer {
	unsigned char* fb_start; /* The start of this buffer. */
	size_t fb_size; /* The size of this buffer in bytes. */
} fault_buffer_t;

typedef enum test_variant {
	VARIANT_SEPARATE_VM_OBJECTS,
	VARIANT_SHARE_VM_OBJECTS
} test_variant_t;

typedef struct test_globals {
	/* This lock protects: tg_cv, tg_running_count, tg_done, tg_current_iteration, and tg_iterations_completed. */
	pthread_mutex_t tg_lock;
	pthread_cond_t tg_cv;
	/* The number of currently running threads */
	unsigned int tg_running_count;
	/* Set during cleanup to indicate that the benchmark is over. */
	bool tg_done;
	size_t tg_current_iteration;
	size_t tg_iterations_completed;
	unsigned int tg_num_threads;
	test_variant_t tg_variant;
	/*
	 * An array of memory objects to fault in.
	 * This is basically a workqueue of
	 * contiguous chunks of memory that the worker threads
	 * will fault in.
	 */
	fault_buffer_t *tg_fault_buffer_arr;
	size_t tg_fault_buffer_arr_length;
	/*
	 * To avoid false sharing, we pad the test globals with an extra cache line and place the atomic
	 * next_fault_buffer_index size_t after the cache line.
	 */
	__unused char padding[];
	/*
	 * This field is directly after the padding buffer.
	 * It is used to synchronize access to tg_fault_buffer_arr.
	 */
	//_Atomic size_t tg_next_fault_buffer_index;
} test_globals_t;

static const char* kSeparateObjectsArgument = "separate-objects";
static const char* kShareObjectsArgument = "share-objects";

/* Arguments parsed from the command line */
typedef struct test_args {
	uint32_t n_threads;
	uint64_t duration_seconds;
	test_variant_t variant;
	bool verbose;
} test_args_t;

/* Get a (wall-time) timestamp in nanoseconds */
static uint64_t get_timestamp_ns(void);
/* Get the number of cpus on this device. */
static unsigned int get_ncpu(void);
/*
 * Fault in the pages in the given buffer.
 */
static void fault_pages(fault_buffer_t *buffer, size_t stride);
/* Get a unique fault buffer from the global work queue. */
static fault_buffer_t *get_fault_buffer(test_globals_t* globals);
/*
 * Grabs buffers from the global test structure and faults them in, using this
 * test variant's stride, until there are no more buffers to grab.
 * Returns the number of microseconds spent on-cpu.
 */
static uint64_t grab_and_fault_pages(test_globals_t* globals);

static bool worker_thread_iteration_setup(size_t current_iteration, test_globals_t *globals);
static void worker_thread_iteration_complete(test_globals_t *globals);

static void parse_arguments(int argc, char **argv, test_args_t *args);
/*
 * Sets up the test globals and spawns the background threads to do the faults.
 * Returns an array of size `num_threads`
 * Containing the thread ids of the forked threads.
 */
static pthread_t* setup_test(test_globals_t *globals, const test_args_t *args, size_t memory_size, bool verbose);
static test_globals_t *allocate_test_globals(void);
/* Initializes variables in the globals array. */
static void init_globals(test_globals_t *globals, const test_args_t *args);
static inline _Atomic size_t *next_fault_buffer_index_ptr(test_globals_t *globals);
/*
 * Called on the main thread.
 * Waits for the background threads to be ready, sets up the memory objects,
 * and then starts a faulting iteration.
 * Returns the start (wall) time.
 */
static uint64_t start_iteration(test_globals_t* globals, test_variant_t variant, bool verbose);
/*
 * Called on the main thread.
 * Waits for the background threads to complete the iteration and cleans up.
 * Returns the total amount of time spent faulting pages in nanoseconds by all threads thus far.
 */
static uint64_t finish_iteration(test_globals_t *globals, uint64_t start_time);
/*
 * Called on the main thread.
 * Maps buffers and places them in the work queue.
 */
static void setup_memory(test_globals_t* globals, test_variant_t variant);
/*
 * Dump test results as a csv to stdout.
 * Use fault_throughput.lua to convert to perfdata.
 */
static void output_results(const test_globals_t *globals, double walltime_elapsed_seconds, double cputime_elapsed_seconds);
static void cleanup_test(test_globals_t *globals);
/*
 * Join the background threads and return the total microseconds
 * of cpu time spent faulting across all of the threads.
 * Takes ownership of the threads array and frees it.
 */
static uint64_t join_background_threads(test_globals_t *globals, pthread_t *threads);
static void unmap_fault_buffers(test_globals_t *globals);
/*
 * Get the stride between each vm object in the fault buffer array.
 */
static size_t fault_buffer_stride(const test_globals_t *globals);

int
main(int argc, char **argv)
{
	/* How much memory should the test consume (per-core on the system)? */
#if (TARGET_OS_OSX || TARGET_OS_SIMULATOR)
	static const size_t memory_per_core = kVmObjectSize;
#else
	static const size_t memory_per_core = 25 * (1UL << 20);
#endif /* (TARGET_OS_OSX || TARGET_OS_SIMULATOR) */
	const size_t kMemSize = memory_per_core * get_ncpu();
	test_globals_t *globals = allocate_test_globals();
	/* Total wall-time spent faulting in pages. */
	uint64_t wall_time_elapsed_ns = 0;
	/* Total cpu-time spent faulting in pages */
	uint64_t cpu_time_faulting_us = 0;
	uint64_t start_time_ns;
	test_args_t args;
	parse_arguments(argc, argv, &args);
	pthread_t* threads = setup_test(globals, &args, kMemSize, args.verbose);

	/* Keep doing more iterations until we've hit our (wall) time budget */
	while (wall_time_elapsed_ns < args.duration_seconds * kNumNanosecondsInSecond) {
		benchmark_log(args.verbose, "----Starting Iteration %lu-----\n", globals->tg_current_iteration + 1);
		start_time_ns = start_iteration(globals, args.variant, args.verbose);
		wall_time_elapsed_ns += finish_iteration(globals, start_time_ns);
		benchmark_log(args.verbose, "----Completed Iteration %lu----\n", globals->tg_current_iteration);
	}

	benchmark_log(args.verbose, "Hit time budget\nJoining worker threads\n");
	cpu_time_faulting_us = join_background_threads(globals, threads);
	benchmark_log(args.verbose, "----End Test Output----\n");
	output_results(globals, (double) wall_time_elapsed_ns / kNumNanosecondsInSecond,
	    (double)cpu_time_faulting_us / kNumMicrosecondsInSecond);
	cleanup_test(globals);

	return 0;
}


/* The main loop for the worker threads. */
static void*
faulting_thread(void* arg)
{
	test_globals_t* globals = arg;
	uint64_t on_cpu_time_faulting = 0;
	size_t current_iteration = 1;
	while (true) {
		bool should_continue = worker_thread_iteration_setup(current_iteration, globals);
		if (!should_continue) {
			break;
		}
		on_cpu_time_faulting += grab_and_fault_pages(globals);
		worker_thread_iteration_complete(globals);
		current_iteration++;
	}
	return (void*)on_cpu_time_faulting;
}

/*
 * Called on the worker threads before each iteration to synchronize this
 * iteration start with the other threads.
 * Returns true if the iteration should continue, and false if the test is over.
 */
static bool
worker_thread_iteration_setup(size_t current_iteration, test_globals_t *globals)
{
	bool should_continue = false;
	int ret = 0;
	// Gate on the other threads being ready to start
	ret = pthread_mutex_lock(&globals->tg_lock);
	assert(ret == 0);
	globals->tg_running_count++;
	if (globals->tg_running_count == globals->tg_num_threads) {
		// All the worker threads are running.
		// Wake up the main thread so that it can ungate the test.
		ret = pthread_cond_broadcast(&globals->tg_cv);
		assert(ret == 0);
	}
	/*
	 * The main thread will start this iteration by incrementing
	 * tg_current_iteration. Block until that happens.
	 * See start_iteration for the wakeup code.
	 */
	while (!globals->tg_done && globals->tg_current_iteration != current_iteration) {
		ret = pthread_cond_wait(&globals->tg_cv, &globals->tg_lock);
		assert(ret == 0);
	}
	should_continue = !globals->tg_done;
	ret = pthread_mutex_unlock(&globals->tg_lock);
	assert(ret == 0);
	return should_continue;
}

/*
 * Called on the worker threads before each iteration finishes to synchronize
 * with the other threads.
 */
static void
worker_thread_iteration_complete(test_globals_t *globals)
{
	int ret;
	// Mark ourselves as done and wait for the other threads to finish
	ret = pthread_mutex_lock(&globals->tg_lock);
	assert(ret == 0);
	globals->tg_running_count--;
	if (globals->tg_running_count == 0) {
		// We're the last one to finish. Mark this iteration as completed and wake everyone up.
		globals->tg_iterations_completed++;
		ret = pthread_cond_broadcast(&globals->tg_cv);
		assert(ret == 0);
	} else {
		// Others are running. Wait for them to finish.
		while (globals->tg_iterations_completed != globals->tg_current_iteration) {
			ret = pthread_cond_wait(&globals->tg_cv, &globals->tg_lock);
			assert(ret == 0);
		}
	}
	ret = pthread_mutex_unlock(&globals->tg_lock);
	assert(ret == 0);
}

static void
fault_pages(fault_buffer_t *buffer, size_t stride)
{
	volatile unsigned char val;
	for (unsigned char* ptr = buffer->fb_start; ptr < buffer->fb_start + buffer->fb_size; ptr += stride) {
		val = *ptr;
	}
}

static fault_buffer_t *
get_fault_buffer(test_globals_t* globals)
{
	size_t index = atomic_fetch_add_explicit(next_fault_buffer_index_ptr(globals), 1UL, memory_order_acq_rel);
	if (index < globals->tg_fault_buffer_arr_length) {
		return &globals->tg_fault_buffer_arr[index];
	}
	return NULL;
}

static uint64_t
grab_and_fault_pages(test_globals_t* globals)
{
	struct timespec start_time, end_time;
	uint64_t nanoseconds_faulting_on_cpu = 0;
	int ret;
	size_t stride = fault_buffer_stride(globals) * kPageSize;
	while (true) {
		fault_buffer_t *object = get_fault_buffer(globals);
		if (object == NULL) {
			break;
		}
		ret = clock_gettime(kThreadCPUTimeClock, &start_time);
		assert(ret == 0);

		fault_pages(object, stride);

		ret = clock_gettime(kThreadCPUTimeClock, &end_time);
		assert(ret == 0);
		nanoseconds_faulting_on_cpu += (unsigned long) timespec_difference_us(&end_time, &start_time);
	}
	return nanoseconds_faulting_on_cpu;
}

static uint64_t
start_iteration(test_globals_t* globals, test_variant_t variant, bool verbose)
{
	int ret;
	uint64_t start_time;
	ret = pthread_mutex_lock(&globals->tg_lock);
	assert(ret == 0);
	benchmark_log(verbose, "Waiting for workers to catch up before starting next iteration.\n");
	/* Wait until all the threads are ready to go to the next iteration */
	while (globals->tg_running_count != globals->tg_num_threads) {
		ret = pthread_cond_wait(&globals->tg_cv, &globals->tg_lock);
	}
	benchmark_log(verbose, "Workers are all caught up\n");
	setup_memory(globals, variant);
	benchmark_log(verbose, "Initialized data structures for iteration. Waking workers.\n");
	/* Grab a timestamp, tick the current iteration, and wake up the worker threads */
	start_time = get_timestamp_ns();
	globals->tg_current_iteration++;
	ret = pthread_mutex_unlock(&globals->tg_lock);
	assert(ret == 0);
	ret = pthread_cond_broadcast(&globals->tg_cv);
	assert(ret == 0);
	return start_time;
}

static uint64_t
finish_iteration(test_globals_t* globals, uint64_t start_time)
{
	int ret;
	uint64_t end_time;
	ret = pthread_mutex_lock(&globals->tg_lock);
	assert(ret == 0);
	while (globals->tg_iterations_completed != globals->tg_current_iteration) {
		ret = pthread_cond_wait(&globals->tg_cv, &globals->tg_lock);
	}
	end_time = get_timestamp_ns();
	ret = pthread_mutex_unlock(&globals->tg_lock);
	unmap_fault_buffers(globals);
	assert(ret == 0);
	return end_time - start_time;
}

static void
setup_memory(test_globals_t* globals, test_variant_t variant)
{
	size_t stride = fault_buffer_stride(globals);
	for (size_t i = 0; i < globals->tg_fault_buffer_arr_length; i += stride) {
		fault_buffer_t *object = &globals->tg_fault_buffer_arr[i];
		object->fb_start = mmap_buffer(kVmObjectSize);
		object->fb_size = kVmObjectSize;
		if (variant == VARIANT_SHARE_VM_OBJECTS) {
			/*
			 * Insert another buffer into the work queue for each thread.
			 * Each buffer starts 1 page past where the previous buffer started into the vm object.
			 * Since each thread strides by the number of threads * the page size they won't fault in the same pages.
			 */
			for (size_t j = 1; j < globals->tg_num_threads; j++) {
				size_t offset = kPageSize * j;
				fault_buffer_t *offset_object = &globals->tg_fault_buffer_arr[i + j];
				offset_object->fb_start = object->fb_start + offset;
				offset_object->fb_size = object->fb_size - offset;
			}
		} else if (variant != VARIANT_SEPARATE_VM_OBJECTS) {
			fprintf(stderr, "Unknown test variant.\n");
			exit(2);
		}
	}
	atomic_store_explicit(next_fault_buffer_index_ptr(globals), 0, memory_order_release);
}

static void
unmap_fault_buffers(test_globals_t* globals)
{
	size_t stride = fault_buffer_stride(globals);
	for (size_t i = 0; i < globals->tg_fault_buffer_arr_length; i += stride) {
		fault_buffer_t *buffer = &globals->tg_fault_buffer_arr[i];
		int res = munmap(buffer->fb_start, buffer->fb_size);
		assert(res == 0);
	}
}

static test_globals_t *
allocate_test_globals()
{
	test_globals_t *globals = NULL;
	int ret;
	if (kCacheLineSize == 0) {
		size_t cachelinesize_size = sizeof(kCacheLineSize);
		ret = sysctlbyname("hw.cachelinesize", &kCacheLineSize, &cachelinesize_size, NULL, 0);
		assert(ret == 0);
		assert(kCacheLineSize > 0);
	}
	if (kPageSize == 0) {
		size_t pagesize_size = sizeof(kPageSize);
		ret = sysctlbyname("vm.pagesize", &kPageSize, &pagesize_size, NULL, 0);
		assert(ret == 0);
		assert(kPageSize > 0);
	}
	size_t test_globals_size = sizeof(test_globals_t) + kCacheLineSize + sizeof(_Atomic size_t);
	globals = malloc(test_globals_size);
	assert(globals != NULL);
	memset(globals, 0, test_globals_size);
	return globals;
}

static void
init_globals(test_globals_t *globals, const test_args_t *args)
{
	pthread_mutexattr_t mutex_attrs;
	pthread_condattr_t cond_attrs;
	int ret;
	memset(globals, 0, sizeof(test_globals_t));

	ret = pthread_mutexattr_init(&mutex_attrs);
	assert(ret == 0);
	ret = pthread_mutex_init(&globals->tg_lock, &mutex_attrs);
	assert(ret == 0);
	ret = pthread_condattr_init(&cond_attrs);
	assert(ret == 0);
	ret = pthread_cond_init(&globals->tg_cv, &cond_attrs);
	assert(ret == 0);
	ret = pthread_mutexattr_destroy(&mutex_attrs);
	assert(ret == 0);
	ret = pthread_condattr_destroy(&cond_attrs);
	assert(ret == 0);

	globals->tg_num_threads = args->n_threads;
	globals->tg_variant = args->variant;
}

static void
init_fault_buffer_arr(test_globals_t *globals, const test_args_t *args, size_t memory_size)
{
	if (args->variant == VARIANT_SEPARATE_VM_OBJECTS) {
		// This variant creates separate vm objects up to memory size bytes total
		globals->tg_fault_buffer_arr_length = memory_size / kVmObjectSize;
	} else if (args->variant == VARIANT_SHARE_VM_OBJECTS) {
		// This variant creates separate vm objects up to memory size bytes total
		// And places a pointer into each vm object for each thread.
		globals->tg_fault_buffer_arr_length = memory_size / kVmObjectSize * globals->tg_num_threads;
	} else {
		fprintf(stderr, "Unsupported test variant.\n");
		exit(2);
	}
	// It doesn't make sense to have more threads than elements in the work queue.
	// NB: Since we scale memory_size by ncpus, this can only happen if the user
	// tries to run the benchmark with many more threads than cores.
	assert(globals->tg_fault_buffer_arr_length >= globals->tg_num_threads);
	globals->tg_fault_buffer_arr = calloc(sizeof(fault_buffer_t), globals->tg_fault_buffer_arr_length);
	assert(globals->tg_fault_buffer_arr);
}

static pthread_t *
spawn_worker_threads(test_globals_t *globals, unsigned int num_threads)
{
	int ret;
	pthread_attr_t pthread_attrs;
	globals->tg_num_threads = num_threads;
	pthread_t* threads = malloc(sizeof(pthread_t) * num_threads);
	assert(threads);
	ret = pthread_attr_init(&pthread_attrs);
	assert(ret == 0);
	// Spawn the background threads
	for (unsigned int i = 0; i < num_threads; i++) {
		ret = pthread_create(threads + i, &pthread_attrs, faulting_thread, globals);
		assert(ret == 0);
	}
	ret = pthread_attr_destroy(&pthread_attrs);
	assert(ret == 0);
	return threads;
}

static pthread_t*
setup_test(test_globals_t *globals, const test_args_t *args, size_t memory_size, bool verbose)
{
	init_globals(globals, args);
	init_fault_buffer_arr(globals, args, memory_size);
	benchmark_log(verbose, "Initialized global data structures.\n");
	pthread_t *workers = spawn_worker_threads(globals, args->n_threads);
	benchmark_log(verbose, "Spawned workers.\n");
	return workers;
}

static uint64_t
join_background_threads(test_globals_t *globals, pthread_t *threads)
{
	// Set the done flag so that the background threads exit
	int ret;
	uint64_t total_cputime_spent_faulting = 0;
	ret = pthread_mutex_lock(&globals->tg_lock);
	assert(ret == 0);
	globals->tg_done = true;
	ret = pthread_cond_broadcast(&globals->tg_cv);
	assert(ret == 0);
	ret = pthread_mutex_unlock(&globals->tg_lock);
	assert(ret == 0);

	// Join the background threads
	for (unsigned int i = 0; i < globals->tg_num_threads; i++) {
		uint64_t cputime_spent_faulting = 0;
		ret = pthread_join(threads[i], (void **)&cputime_spent_faulting);
		assert(ret == 0);
		total_cputime_spent_faulting += cputime_spent_faulting;
	}
	free(threads);
	return total_cputime_spent_faulting;
}

static void
cleanup_test(test_globals_t* globals)
{
	int ret;
	ret = pthread_mutex_destroy(&globals->tg_lock);
	assert(ret == 0);
	ret = pthread_cond_destroy(&globals->tg_cv);
	assert(ret == 0);
	free(globals->tg_fault_buffer_arr);
	free(globals);
}

static void
output_results(const test_globals_t* globals, double walltime_elapsed_seconds, double cputime_elapsed_seconds)
{
	size_t pgsize;
	size_t sysctl_size = sizeof(pgsize);
	int ret = sysctlbyname("vm.pagesize", &pgsize, &sysctl_size, NULL, 0);
	assert(ret == 0);
	size_t num_pages = 0;
	double walltime_throughput, cputime_throughput;
	size_t stride = fault_buffer_stride(globals);
	for (size_t i = 0; i < globals->tg_fault_buffer_arr_length; i += stride) {
		num_pages += globals->tg_fault_buffer_arr[i].fb_size / pgsize;
	}
	num_pages *= globals->tg_iterations_completed;
	walltime_throughput = num_pages / walltime_elapsed_seconds;
	cputime_throughput = num_pages / cputime_elapsed_seconds;
	printf("-----Results-----\n");
	printf("Throughput (pages / wall second), Throughput (pages / CPU second)\n");
	printf("%f,%f\n", walltime_throughput, cputime_throughput);
}

static void
print_help(char** argv)
{
	fprintf(stderr, "%s: <test-variant> [-v] duration num_threads\n", argv[0]);
	fprintf(stderr, "\ntest variants:\n");
	fprintf(stderr, "	%s	Fault in different vm objects in each thread.\n", kSeparateObjectsArgument);
	fprintf(stderr, "	%s		Share vm objects across faulting threads.\n", kShareObjectsArgument);
}

static uint64_t
get_timestamp_ns()
{
	return clock_gettime_nsec_np(kWallTimeClock);
}

static unsigned int
get_ncpu(void)
{
	int ncpu;
	size_t sysctl_size = sizeof(ncpu);
	int ret = sysctlbyname("hw.ncpu", &ncpu, &sysctl_size, NULL, 0);
	assert(ret == 0);
	return (unsigned int) ncpu;
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
	if (strncasecmp(argv[current_argument], kSeparateObjectsArgument, strlen(kSeparateObjectsArgument)) == 0) {
		args->variant = VARIANT_SEPARATE_VM_OBJECTS;
	} else if (strncasecmp(argv[current_argument], kShareObjectsArgument, strlen(kShareObjectsArgument)) == 0) {
		args->variant = VARIANT_SHARE_VM_OBJECTS;
	} else {
		print_help(argv);
		exit(1);
	}
	current_argument++;

	long duration = strtol(argv[current_argument++], NULL, 10);
	if (duration == 0) {
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
	args->duration_seconds = (unsigned long) duration;
}

static inline
_Atomic size_t *
next_fault_buffer_index_ptr(test_globals_t *globals)
{
	return (_Atomic size_t *) (((ptrdiff_t)(globals + 1)) + (int64_t)kCacheLineSize);
}
static size_t
fault_buffer_stride(const test_globals_t *globals)
{
	size_t stride;
	if (globals->tg_variant == VARIANT_SEPARATE_VM_OBJECTS) {
		stride = 1;
	} else if (globals->tg_variant == VARIANT_SHARE_VM_OBJECTS) {
		stride = globals->tg_num_threads;
	} else {
		fprintf(stderr, "Unknown variant\n");
		exit(-1);
	}
	return stride;
}
