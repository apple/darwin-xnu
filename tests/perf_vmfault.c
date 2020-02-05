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
#define MEMSIZE                 (1UL<<29)       /* 512 MB */
#else
#define MEMSIZE                 (1UL<<27)       /* 128 MB */
#endif

#define VM_TAG1                 100
#define VM_TAG2                 101

enum {
	SOFT_FAULT,
	ZERO_FILL,
	NUM_FAULT_TYPES
};

enum {
	VARIANT_DEFAULT = 1,
	VARIANT_SINGLE_REGION,
	VARIANT_MULTIPLE_REGIONS,
	NUM_MAPPING_VARIANTS
};

static char *variant_str[] = {
	"none",
	"default",
	"single-region",
	"multiple-regions"
};


typedef struct {
	char *region_addr;
	char *shared_region_addr;
	size_t region_len;
} memregion_config;

static memregion_config *memregion_config_per_thread;

static size_t pgsize;
static int num_threads;
static int ready_thread_count;
static int finished_thread_count;
static dt_stat_time_t runtime;
static pthread_cond_t start_cvar;
static pthread_cond_t threads_ready_cvar;
static pthread_cond_t threads_finished_cvar;
static pthread_mutex_t ready_thread_count_lock;
static pthread_mutex_t finished_thread_count_lock;

static void map_mem_regions_default(int fault_type, size_t memsize);
static void map_mem_regions_single(int fault_type, size_t memsize);
static void map_mem_regions_multiple(int fault_type, size_t memsize);
static void map_mem_regions(int fault_type, int mapping_variant, size_t memsize);
static void unmap_mem_regions(int mapping_variant, size_t memsize);
static void setup_per_thread_regions(char *memblock, char *memblock_share, int fault_type, size_t memsize);
static void fault_pages(int thread_id);
static void execute_threads(void);
static void *thread_setup(void *arg);
static void run_test(int fault_type, int mapping_variant, size_t memsize);
static void setup_and_run_test(int test, int threads);
static int get_ncpu(void);

/* Allocates memory using the default mmap behavior. Each VM region created is capped at 128 MB. */
static void
map_mem_regions_default(int fault_type, size_t memsize)
{
	volatile char val;
	vm_prot_t curprot, maxprot;
	char *ptr, *memblock, *memblock_share = NULL;

	memblock = (char *)mmap(NULL, memsize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
	T_QUIET; T_ASSERT_NE((void *)memblock, MAP_FAILED, "mmap");

	if (fault_type == SOFT_FAULT) {
		/* Fault in all the pages of the original region. */
		for (ptr = memblock; ptr < memblock + memsize; ptr += pgsize) {
			val = *ptr;
		}
		/* Remap the region so that subsequent accesses result in read soft faults. */
		T_QUIET; T_ASSERT_MACH_SUCCESS(vm_remap(mach_task_self(), (vm_address_t *)&memblock_share,
		    memsize, 0, VM_FLAGS_ANYWHERE, mach_task_self(), (vm_address_t)memblock, FALSE,
		    &curprot, &maxprot, VM_INHERIT_DEFAULT), "vm_remap");
	}
	setup_per_thread_regions(memblock, memblock_share, fault_type, memsize);
}

/* Creates a single VM region by mapping in a named memory entry. */
static void
map_mem_regions_single(int fault_type, size_t memsize)
{
	volatile char val;
	vm_prot_t curprot, maxprot;
	char *ptr, *memblock = NULL, *memblock_share = NULL;
	vm_size_t size = memsize;
	vm_offset_t addr1 = 0;
	mach_port_t mem_handle = MACH_PORT_NULL;

	/* Allocate a region and fault in all the pages. */
	T_QUIET; T_ASSERT_MACH_SUCCESS(vm_allocate(mach_task_self(), &addr1, size, VM_FLAGS_ANYWHERE), "vm_allocate");
	for (ptr = (char *)addr1; ptr < (char *)addr1 + memsize; ptr += pgsize) {
		val = *ptr;
	}

	/* Create a named memory entry from the region allocated above, and de-allocate said region. */
	T_QUIET; T_ASSERT_MACH_SUCCESS(mach_make_memory_entry(mach_task_self(), &size, addr1, VM_PROT_ALL | MAP_MEM_NAMED_CREATE,
	    &mem_handle, MACH_PORT_NULL), "mach_make_memory_entry");
	T_QUIET; T_ASSERT_MACH_SUCCESS(vm_deallocate(mach_task_self(), addr1, size), "vm_deallocate");

	/* Map in the named entry and deallocate it. */
	T_QUIET; T_ASSERT_MACH_SUCCESS(vm_map(mach_task_self(), (vm_address_t *)&memblock, size, 0, VM_FLAGS_ANYWHERE, mem_handle, 0,
	    FALSE, VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_NONE), "vm_map");
	T_QUIET; T_ASSERT_MACH_SUCCESS(mach_port_deallocate(mach_task_self(), mem_handle), "mach_port_deallocate");

	if (fault_type == SOFT_FAULT) {
		/* Fault in all the pages of the original region. */
		for (ptr = memblock; ptr < memblock + memsize; ptr += pgsize) {
			val = *ptr;
		}
		/* Remap the region so that subsequent accesses result in read soft faults. */
		T_QUIET; T_ASSERT_MACH_SUCCESS(vm_remap(mach_task_self(), (vm_address_t *)&memblock_share,
		    memsize, 0, VM_FLAGS_ANYWHERE, mach_task_self(), (vm_address_t)memblock, FALSE,
		    &curprot, &maxprot, VM_INHERIT_DEFAULT), "vm_remap");
	}
	setup_per_thread_regions(memblock, memblock_share, fault_type, memsize);
}

/* Allocates a separate VM region for each thread. */
static void
map_mem_regions_multiple(int fault_type, size_t memsize)
{
	int i;
	size_t region_len, num_pages;
	volatile char val;
	char *ptr, *memblock, *memblock_share;
	vm_prot_t curprot, maxprot;

	num_pages = memsize / pgsize;

	for (i = 0; i < num_threads; i++) {
		memblock = NULL;

		region_len = num_pages / (size_t)num_threads;
		if ((size_t)i < num_pages % (size_t)num_threads) {
			region_len++;
		}
		region_len *= pgsize;

		int flags = VM_MAKE_TAG((i % 2)? VM_TAG1 : VM_TAG2) | MAP_ANON | MAP_PRIVATE;

		memblock = (char *)mmap(NULL, region_len, PROT_READ | PROT_WRITE, flags, -1, 0);
		T_QUIET; T_ASSERT_NE((void *)memblock, MAP_FAILED, "mmap");
		memregion_config_per_thread[i].region_addr = memblock;
		memregion_config_per_thread[i].shared_region_addr = 0;
		memregion_config_per_thread[i].region_len = region_len;

		if (fault_type == SOFT_FAULT) {
			/* Fault in all the pages of the original region. */
			for (ptr = memblock; ptr < memblock + region_len; ptr += pgsize) {
				val = *ptr;
			}
			memblock_share = NULL;
			/* Remap the region so that subsequent accesses result in read soft faults. */
			T_QUIET; T_ASSERT_MACH_SUCCESS(vm_remap(mach_task_self(), (vm_address_t *)&memblock_share,
			    region_len, 0, VM_FLAGS_ANYWHERE, mach_task_self(), (vm_address_t)memblock, FALSE,
			    &curprot, &maxprot, VM_INHERIT_DEFAULT), "vm_remap");
			memregion_config_per_thread[i].shared_region_addr = memblock_share;
		}
	}
}

static void
map_mem_regions(int fault_type, int mapping_variant, size_t memsize)
{
	memregion_config_per_thread = (memregion_config *)malloc(sizeof(*memregion_config_per_thread) * (size_t)num_threads);
	switch (mapping_variant) {
	case VARIANT_SINGLE_REGION:
		map_mem_regions_single(fault_type, memsize);
		break;
	case VARIANT_MULTIPLE_REGIONS:
		map_mem_regions_multiple(fault_type, memsize);
		break;
	case VARIANT_DEFAULT:
	default:
		map_mem_regions_default(fault_type, memsize);
	}
}

static void
setup_per_thread_regions(char *memblock, char *memblock_share, int fault_type, size_t memsize)
{
	int i;
	size_t region_len, region_start, num_pages;

	num_pages = memsize / pgsize;
	for (i = 0; i < num_threads; i++) {
		region_len = num_pages / (size_t)num_threads;
		region_start = region_len * (size_t)i;

		if ((size_t)i < num_pages % (size_t)num_threads) {
			region_start += (size_t)i;
			region_len++;
		} else {
			region_start += num_pages % (size_t)num_threads;
		}

		region_start *= pgsize;
		region_len *= pgsize;

		memregion_config_per_thread[i].region_addr = memblock + region_start;
		memregion_config_per_thread[i].shared_region_addr = ((fault_type == SOFT_FAULT) ?
		    memblock_share + region_start : 0);
		memregion_config_per_thread[i].region_len = region_len;
	}
}

static void
unmap_mem_regions(int mapping_variant, size_t memsize)
{
	if (mapping_variant == VARIANT_MULTIPLE_REGIONS) {
		int i;
		for (i = 0; i < num_threads; i++) {
			if (memregion_config_per_thread[i].shared_region_addr != 0) {
				T_QUIET; T_ASSERT_MACH_SUCCESS(munmap(memregion_config_per_thread[i].shared_region_addr,
				    memregion_config_per_thread[i].region_len), "munmap");
			}
			T_QUIET; T_ASSERT_MACH_SUCCESS(munmap(memregion_config_per_thread[i].region_addr,
			    memregion_config_per_thread[i].region_len), "munmap");
		}
	} else {
		if (memregion_config_per_thread[0].shared_region_addr != 0) {
			T_QUIET; T_ASSERT_MACH_SUCCESS(munmap(memregion_config_per_thread[0].shared_region_addr, memsize), "munmap");
		}
		T_QUIET; T_ASSERT_MACH_SUCCESS(munmap(memregion_config_per_thread[0].region_addr, memsize), "munmap");
	}
}

static void
fault_pages(int thread_id)
{
	char *ptr, *block;
	volatile char val;

	block = memregion_config_per_thread[thread_id].shared_region_addr ?
	    memregion_config_per_thread[thread_id].shared_region_addr :
	    memregion_config_per_thread[thread_id].region_addr;
	for (ptr = block; ptr < block + memregion_config_per_thread[thread_id].region_len; ptr += pgsize) {
		val = *ptr;
	}
}

static void *
thread_setup(void *arg)
{
	int my_index = *((int *)arg);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_mutex_lock(&ready_thread_count_lock), "pthread_mutex_lock");
	ready_thread_count++;
	if (ready_thread_count == num_threads) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_cond_signal(&threads_ready_cvar), "pthread_cond_signal");
	}
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_cond_wait(&start_cvar, &ready_thread_count_lock), "pthread_cond_wait");
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_mutex_unlock(&ready_thread_count_lock), "pthread_mutex_unlock");

	fault_pages(my_index);

	/* Up the finished count */
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_mutex_lock(&finished_thread_count_lock), "pthread_mutex_lock");
	finished_thread_count++;
	if (finished_thread_count == num_threads) {
		/* All the threads are done. Wake up the main thread */
		T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_cond_signal(&threads_finished_cvar), "pthread_cond_signal");
	}
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_mutex_unlock(&finished_thread_count_lock), "pthread_mutex_unlock");
	return NULL;
}

static void
execute_threads(void)
{
	int thread_index, thread_retval;
	int *thread_indices;
	void *thread_retval_ptr = &thread_retval;
	pthread_t* threads;

	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_cond_init(&threads_ready_cvar, NULL), "pthread_cond_init");
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_cond_init(&start_cvar, NULL), "pthread_cond_init");
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_mutex_init(&ready_thread_count_lock, NULL), "pthread_mutex_init");
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_cond_init(&threads_finished_cvar, NULL), "pthread_cond_init");
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_mutex_init(&finished_thread_count_lock, NULL), "pthread_mutex_init");
	ready_thread_count = 0;
	finished_thread_count = 0;

	threads = (pthread_t *)malloc(sizeof(*threads) * (size_t)num_threads);
	thread_indices = (int *)malloc(sizeof(*thread_indices) * (size_t)num_threads);
	for (thread_index = 0; thread_index < num_threads; thread_index++) {
		thread_indices[thread_index] = thread_index;
		T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_create(&threads[thread_index], NULL,
		    thread_setup, (void *)&thread_indices[thread_index]), "pthread_create");
	}

	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_mutex_lock(&ready_thread_count_lock), "pthread_mutex_lock");
	while (ready_thread_count != num_threads) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_cond_wait(&threads_ready_cvar, &ready_thread_count_lock),
		    "pthread_cond_wait");
	}
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_mutex_unlock(&ready_thread_count_lock), "pthread_mutex_unlock");

	T_STAT_MEASURE(runtime) {
		/* Ungate the threads */
		T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_cond_broadcast(&start_cvar), "pthread_cond_broadcast");
		/* Wait for the threads to finish */
		T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_mutex_lock(&finished_thread_count_lock), "pthread_mutex_lock");
		while (finished_thread_count != num_threads) {
			T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_cond_wait(&threads_finished_cvar, &finished_thread_count_lock), "pthread_cond_wait");
		}
	};

	/* Join the threads */
	for (thread_index = 0; thread_index < num_threads; thread_index++) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_join(threads[thread_index], &thread_retval_ptr),
		    "pthread_join");
	}

	free(threads);
	free(thread_indices);
}

static void
run_test(int fault_type, int mapping_variant, size_t memsize)
{
	char metric_str[32];
	size_t num_pages;
	size_t sysctl_size = sizeof(pgsize);
	int ret = sysctlbyname("vm.pagesize", &pgsize, &sysctl_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl vm.pagesize failed");

	num_pages = memsize / pgsize;

	T_QUIET; T_ASSERT_LT(fault_type, NUM_FAULT_TYPES, "invalid test type");
	T_QUIET; T_ASSERT_LT(mapping_variant, NUM_MAPPING_VARIANTS, "invalid mapping variant");
	T_QUIET; T_ASSERT_GT(num_threads, 0, "num_threads <= 0");
	T_QUIET; T_ASSERT_GT((int)num_pages / num_threads, 0, "num_pages/num_threads <= 0");

	T_LOG("No. of cpus:     %d", get_ncpu());
	T_LOG("No. of threads:  %d", num_threads);
	T_LOG("No. of pages:    %ld", num_pages);
	T_LOG("Pagesize:        %ld", pgsize);
	T_LOG("Allocation size: %ld MB", memsize / (1024 * 1024));
	T_LOG("Mapping variant: %s", variant_str[mapping_variant]);

	snprintf(metric_str, 32, "Runtime-%s", variant_str[mapping_variant]);
	runtime = dt_stat_time_create(metric_str);

	while (!dt_stat_stable(runtime)) {
		map_mem_regions(fault_type, mapping_variant, memsize);
		execute_threads();
		unmap_mem_regions(mapping_variant, memsize);
	}

	dt_stat_finalize(runtime);
	T_LOG("Throughput-%s (MB/s): %lf\n\n", variant_str[mapping_variant], (double)memsize / (1024 * 1024) / dt_stat_mean((dt_stat_t)runtime));
}

static void
setup_and_run_test(int fault_type, int threads)
{
	int i, mapping_variant;
	size_t memsize;
	char *e;

	mapping_variant = VARIANT_DEFAULT;
	memsize = MEMSIZE;
	num_threads = threads;

	if ((e = getenv("NTHREADS"))) {
		if (threads == 1) {
			T_SKIP("Custom environment variables specified. Skipping single threaded version.");
		}
		num_threads = (int)strtol(e, NULL, 0);
	}

	if ((e = getenv("MEMSIZEMB"))) {
		memsize = (size_t)strtol(e, NULL, 0) * 1024 * 1024;
	}

	if ((e = getenv("VARIANT"))) {
		mapping_variant = (int)strtol(e, NULL, 0);
		run_test(fault_type, mapping_variant, memsize);
	} else {
		for (i = VARIANT_DEFAULT; i < NUM_MAPPING_VARIANTS; i++) {
			run_test(fault_type, i, memsize);
		}
	}

	T_END;
}

static int
get_ncpu(void)
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
	setup_and_run_test(SOFT_FAULT, 1);
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
		if (nthreads == 1) {
			T_SKIP("Skipping multi-threaded test on single core device.");
		}
	}
	setup_and_run_test(SOFT_FAULT, nthreads);
}

T_DECL(zero_fill_fault,
    "Zero fill faults (single thread)")
{
	setup_and_run_test(ZERO_FILL, 1);
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
		if (nthreads == 1) {
			T_SKIP("Skipping multi-threaded test on single core device.");
		}
	}
	setup_and_run_test(ZERO_FILL, nthreads);
}
