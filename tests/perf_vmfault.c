#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <darwintest.h>
#include <TargetConditionals.h>
#include <perfcheck_keys.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm.perf"),
	T_META_CHECK_LEAKS(false),
	T_META_TAG_PERF
);

#ifdef DT_IOSMARK
#define MEMSIZE			(1UL<<29)	/* 512 MB */
#else
#define MEMSIZE			(1UL<<27)	/* 128 MB */
#endif

enum {
	SOFT_FAULT,
	ZERO_FILL,
	NUM_TESTS
};

static int test_type;
static int num_threads;
static int ready_thread_count;
static size_t pgsize;
static size_t num_pages;
static char *memblock;
static char *memblock_share;
static dt_stat_time_t t;
static pthread_cond_t start_cvar;
static pthread_cond_t threads_ready_cvar;
static pthread_mutex_t ready_thread_count_lock;

static void map_mem_regions(void);
static void unmap_mem_regions(void);
static void fault_pages(int thread_id);
static void execute_threads(void);
static void *thread_setup(void *arg);
static void run_test(int test, int threads, int cpus);
static int get_ncpu(void);

static void map_mem_regions(void)
{
	char *ptr;
	volatile char val;
	vm_prot_t curprot, maxprot;

	memblock = (char *)mmap(NULL, MEMSIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
	T_QUIET; T_ASSERT_NE((void *)memblock, MAP_FAILED, "mmap");

	if (test_type == SOFT_FAULT) {

		/* Fault in all the pages of the original region. */
		for(ptr = memblock; ptr < memblock + MEMSIZE; ptr += pgsize) {
			val = *ptr;
		}
		/* Remap the region so that subsequent accesses result in read soft faults. */
		T_QUIET; T_ASSERT_MACH_SUCCESS(vm_remap(mach_task_self(), (vm_address_t *)&memblock_share,
					MEMSIZE, 0, VM_FLAGS_ANYWHERE, mach_task_self(), (vm_address_t)memblock, FALSE,
					&curprot, &maxprot, VM_INHERIT_DEFAULT), "vm_remap");
	}
}

static void unmap_mem_regions(void)
{
	if (test_type == SOFT_FAULT) {
		T_QUIET; T_ASSERT_MACH_SUCCESS(munmap(memblock_share, MEMSIZE), "munmap");
	}
	T_QUIET; T_ASSERT_MACH_SUCCESS(munmap(memblock, MEMSIZE), "munmap");
}

static void fault_pages(int thread_id)
{
	size_t region_len, region_start, region_end;
	char *ptr, *block;
	volatile char val;

	region_len = num_pages / (size_t)num_threads;
	region_start = region_len * (size_t)thread_id;

	if((size_t)thread_id < num_pages % (size_t)num_threads) {
		region_start += (size_t)thread_id;
		region_len++;
	}
	else {
		region_start += num_pages % (size_t)num_threads;
	}

	region_start *= pgsize;
	region_len *= pgsize;
	region_end = region_start + region_len;

	block = (test_type == SOFT_FAULT)? memblock_share: memblock;
	for(ptr = block + region_start; ptr < block + region_end; ptr += pgsize) {
		val = *ptr;
	}
}

static void execute_threads(void)
{
	int thread_index, thread_retval;
	int *thread_indices;
    void *thread_retval_ptr = &thread_retval;
	pthread_t* threads;

	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_cond_init(&threads_ready_cvar, NULL), "pthread_cond_init");
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_cond_init(&start_cvar, NULL), "pthread_cond_init");
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_mutex_init(&ready_thread_count_lock, NULL), "pthread_mutex_init");
	ready_thread_count = 0;

	threads = (pthread_t *)malloc(sizeof(*threads) * (size_t)num_threads);
	thread_indices = (int *)malloc(sizeof(*thread_indices) * (size_t)num_threads);
	for(thread_index = 0; thread_index < num_threads; thread_index++) {
		thread_indices[thread_index] = thread_index;
		T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_create(&threads[thread_index], NULL,
					thread_setup, (void *)&thread_indices[thread_index]), "pthread_create");
	}

	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_mutex_lock(&ready_thread_count_lock), "pthread_mutex_lock");
	if(ready_thread_count != num_threads) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_cond_wait(&threads_ready_cvar, &ready_thread_count_lock),
				"pthread_cond_wait");
	}
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_mutex_unlock(&ready_thread_count_lock), "pthread_mutex_unlock");

	T_STAT_MEASURE(t) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_cond_broadcast(&start_cvar), "pthread_cond_broadcast");
		for(thread_index = 0; thread_index < num_threads; thread_index++) {
			T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_join(threads[thread_index], &thread_retval_ptr),
					"pthread_join");
		}
	};

	free(threads);
	free(thread_indices);
}

static void *thread_setup(void *arg)
{
  int my_index = *((int *)arg);

  T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_mutex_lock(&ready_thread_count_lock), "pthread_mutex_lock");
  ready_thread_count++;
  if(ready_thread_count == num_threads) {
    T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_cond_signal(&threads_ready_cvar), "pthread_cond_signal");
  }
  T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_cond_wait(&start_cvar, &ready_thread_count_lock), "pthread_cond_wait");
  T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_mutex_unlock(&ready_thread_count_lock), "pthread_mutex_unlock");

  fault_pages(my_index);
  return NULL;
}

static void run_test(int test, int threads, int cpus)
{
	size_t sysctl_size = sizeof(pgsize);
	int ret = sysctlbyname("vm.pagesize", &pgsize, &sysctl_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl vm.pagesize failed");

	test_type = test;
	num_threads = threads;
	num_pages = MEMSIZE / pgsize;

	T_QUIET; T_ASSERT_LT(test_type, NUM_TESTS, "invalid test type");
	T_QUIET; T_ASSERT_GT(num_threads, 0, "num_threads <= 0");
	T_QUIET; T_ASSERT_GT((int)num_pages/ num_threads, 0, "num_pages/num_threads <= 0");

	T_LOG("No. of cpus:     %d", cpus);
	T_LOG("No. of threads:  %d", num_threads);
	T_LOG("No. of pages:    %ld", num_pages);
	T_LOG("Pagesize:        %ld", pgsize);

	t = dt_stat_time_create("Runtime");
	// This sets the A/B failure threshold at 50% of baseline for Runtime
	dt_stat_set_variable(t, kPCFailureThresholdPctVar, 50.0);
	while (!dt_stat_stable(t)) {
		map_mem_regions();
		execute_threads();
		unmap_mem_regions();
	}

	dt_stat_finalize(t);
	T_END;
}

static int get_ncpu(void)
{
	int ncpu;
	size_t length = sizeof(ncpu);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctlbyname("hw.ncpu", &ncpu, &length, NULL, 0),
			"failed to query hw.ncpu");
	return ncpu;
}

T_DECL(read_soft_fault,
		"Read soft faults (single thread)")
{
	run_test(SOFT_FAULT, 1, get_ncpu());
}

T_DECL(read_soft_fault_multithreaded,
		"Read soft faults (multi-threaded)")
{
	char *e;
	int nthreads;

	/* iOSMark passes in the no. of threads via an env. variable */
	if ((e = getenv("DT_STAT_NTHREADS"))) {
		nthreads = (int)strtol(e, NULL, 0);
	} else {
		nthreads = get_ncpu();
	}
	run_test(SOFT_FAULT, nthreads, get_ncpu());
}

T_DECL(zero_fill_fault,
		"Zero fill faults (single thread)")
{
	run_test(ZERO_FILL, 1, get_ncpu());
}

T_DECL(zero_fill_fault_multithreaded,
		"Zero fill faults (multi-threaded)")
{
	char *e;
	int nthreads;

	/* iOSMark passes in the no. of threads via an env. variable */
	if ((e = getenv("DT_STAT_NTHREADS"))) {
		nthreads = (int)strtol(e, NULL, 0);
	} else {
		nthreads = get_ncpu();
	}
	run_test(ZERO_FILL, nthreads, get_ncpu());
}
