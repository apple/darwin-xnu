#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <err.h>
#include <string.h>
#include <assert.h>
#include <sysexits.h>
#include <getopt.h>
#include <spawn.h>
#include <stdbool.h>
#include <sys/sysctl.h>
#include <mach/mach_time.h>
#include <mach/mach.h>
#include <mach/semaphore.h>
#include <TargetConditionals.h>

#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif

#include <darwintest.h>
#include <stdatomic.h>

#define MAX_THREADS         32
#define SPIN_SECS           6
#define THR_SPINNER_PRI     63
#define THR_MANAGER_PRI     62
#define WARMUP_ITERATIONS   100
#define FILE_SIZE           (16384 * 4096)
#define IO_SIZE             4096
#define IO_COUNT            2500

static mach_timebase_info_data_t timebase_info;
static semaphore_t semaphore;
static semaphore_t worker_sem;
static uint32_t g_numcpus;
static _Atomic uint32_t keep_going = 1;
int test_file_fd = 0;
char *data_buf = NULL;
extern char **environ;

static struct {
	pthread_t thread;
} threads[MAX_THREADS];

static uint64_t
nanos_to_abs(uint64_t nanos)
{
	return nanos * timebase_info.denom / timebase_info.numer;
}

static void
io_perf_test_io_init(void)
{
	int spawn_ret, pid;
	char *const mount_args[] = {"/usr/local/sbin/mount_nand.sh", NULL};
	spawn_ret = posix_spawn(&pid, mount_args[0], NULL, NULL, mount_args, environ);
	if (spawn_ret < 0) {
		T_SKIP("NAND mounting in LTE not possible on this device. Skipping test!");
	}
	waitpid(pid, &spawn_ret, 0);
	if (WIFEXITED(spawn_ret) && !WEXITSTATUS(spawn_ret)) {
		T_PASS("NAND mounted successfully");
	} else {
		T_SKIP("Unable to mount NAND. Skipping test!");
	}

	/* Mark the main thread as fixed priority */
	struct sched_param param = {.sched_priority = THR_MANAGER_PRI};
	T_ASSERT_POSIX_ZERO(pthread_setschedparam(pthread_self(), SCHED_FIFO, &param),
	    "pthread_setschedparam");

	/* Set I/O Policy to Tier 0 */
	T_ASSERT_POSIX_ZERO(setiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_PROCESS,
	    IOPOL_IMPORTANT), "setiopolicy");

	/* Create data buffer */
	data_buf = malloc(IO_SIZE * 16);
	T_ASSERT_NOTNULL(data_buf, "Data buffer allocation");

	int rndfd = open("/dev/urandom", O_RDONLY, S_IRUSR);
	T_ASSERT_POSIX_SUCCESS(rndfd, "Open /dev/urandom");
	T_ASSERT_GE_INT((int)read(rndfd, data_buf, IO_SIZE * 16), 0, "read /dev/urandom");
	close(rndfd);

	/* Create test file */
	int fd = open("/mnt2/test", O_CREAT | O_WRONLY, S_IRUSR);
	T_ASSERT_POSIX_SUCCESS(fd, 0, "Open /mnt2/test for writing!");

	T_ASSERT_POSIX_ZERO(fcntl(fd, F_NOCACHE, 1), "fcntl F_NOCACHE enable");
	for (int size = 0; size < FILE_SIZE;) {
		T_QUIET;
		T_ASSERT_GE_INT((int)write(fd, data_buf, IO_SIZE * 16), 0, "write test file");
		size += (IO_SIZE * 16);
	}
	close(fd);
	sync();
}

static pthread_t
create_thread(uint32_t thread_id, uint32_t priority, bool fixpri,
    void *(*start_routine)(void *))
{
	int rv;
	pthread_t new_thread;
	struct sched_param param = { .sched_priority = (int)priority };
	pthread_attr_t attr;

	T_ASSERT_POSIX_ZERO(pthread_attr_init(&attr), "pthread_attr_init");

	T_ASSERT_POSIX_ZERO(pthread_attr_setschedparam(&attr, &param),
	    "pthread_attr_setschedparam");

	if (fixpri) {
		T_ASSERT_POSIX_ZERO(pthread_attr_setschedpolicy(&attr, SCHED_RR),
		    "pthread_attr_setschedpolicy");
	}

	T_ASSERT_POSIX_ZERO(pthread_create(&new_thread, &attr, start_routine,
	    (void*)(uintptr_t)thread_id), "pthread_create");

	T_ASSERT_POSIX_ZERO(pthread_attr_destroy(&attr), "pthread_attr_destroy");

	threads[thread_id].thread = new_thread;

	return new_thread;
}

/* Spin until a specified number of seconds elapses */
static void
spin_for_duration(uint32_t seconds)
{
	uint64_t duration       = nanos_to_abs((uint64_t)seconds * NSEC_PER_SEC);
	uint64_t current_time   = mach_absolute_time();
	uint64_t timeout        = duration + current_time;

	uint64_t spin_count = 0;

	while (mach_absolute_time() < timeout && atomic_load_explicit(&keep_going,
	    memory_order_relaxed)) {
		spin_count++;
	}
}

static void *
spin_thread(void *arg)
{
	uint32_t thread_id = (uint32_t) arg;
	char name[30] = "";

	snprintf(name, sizeof(name), "spin thread %2d", thread_id);
	pthread_setname_np(name);
	T_ASSERT_MACH_SUCCESS(semaphore_wait_signal(semaphore, worker_sem),
	    "semaphore_wait_signal");
	spin_for_duration(SPIN_SECS);
	return NULL;
}

void
perform_io(dt_stat_time_t stat)
{
	/* Open the test data file */
	int test_file_fd = open("/mnt2/test", O_RDONLY);
	T_WITH_ERRNO;
	T_ASSERT_POSIX_SUCCESS(test_file_fd, "Open test data file");

	/* Disable caching and read-ahead for the file */
	T_ASSERT_POSIX_ZERO(fcntl(test_file_fd, F_NOCACHE, 1), "fcntl F_NOCACHE enable");
	T_ASSERT_POSIX_ZERO(fcntl(test_file_fd, F_RDAHEAD, 0), "fcntl F_RDAHEAD disable");

	uint32_t count = 0;
	int ret;

	for (int i = 0; i < WARMUP_ITERATIONS; i++) {
		/* Warmup loop */
		read(test_file_fd, data_buf, IO_SIZE);
	}

	do {
		T_STAT_MEASURE(stat) {
			ret = read(test_file_fd, data_buf, IO_SIZE);
		}
		if (ret == 0) {
			T_QUIET;
			T_ASSERT_POSIX_SUCCESS(lseek(test_file_fd, 0, SEEK_SET), "lseek begin");
		} else if (ret < 0) {
			T_FAIL("read failure");
			T_END;
		}
		count++;
	} while (count < IO_COUNT);
	close(test_file_fd);
}

T_GLOBAL_META(T_META_NAMESPACE("xnu.io"), T_META_TAG_PERF);

/* Disable the test on MacOS for now */
T_DECL(read_perf, "Sequential Uncached Read Performance", T_META_TYPE_PERF, T_META_CHECK_LEAKS(NO), T_META_ASROOT(YES), T_META_LTEPHASE(LTE_POSTINIT))
{
#if !CONFIG_EMBEDDED
	T_SKIP("Not supported on MacOS");
#endif /* !CONFIG_EMBEDDED */

	io_perf_test_io_init();
	pthread_setname_np("main thread");

	T_ASSERT_MACH_SUCCESS(mach_timebase_info(&timebase_info), "mach_timebase_info");

	dt_stat_time_t seq_noload = dt_stat_time_create("sequential read latency (CPU idle)");
	perform_io(seq_noload);
	dt_stat_finalize(seq_noload);

	/*
	 * We create spinner threads for this test so that all other cores are
	 * busy. That way the I/O issue thread has to context switch to the
	 * IOWorkLoop thread and back for the I/O.
	 */
	T_ASSERT_MACH_SUCCESS(semaphore_create(mach_task_self(), &semaphore,
	    SYNC_POLICY_FIFO, 0), "semaphore_create");

	T_ASSERT_MACH_SUCCESS(semaphore_create(mach_task_self(), &worker_sem,
	    SYNC_POLICY_FIFO, 0), "semaphore_create");

	size_t ncpu_size = sizeof(g_numcpus);
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("hw.ncpu", &g_numcpus, &ncpu_size, NULL, 0),
	    "sysctlbyname(hw.ncpu)");

	T_LOG("hw.ncpu: %d\n", g_numcpus);
	uint32_t n_spinners = g_numcpus - 1;

	for (uint32_t thread_id = 0; thread_id < n_spinners; thread_id++) {
		threads[thread_id].thread = create_thread(thread_id, THR_SPINNER_PRI,
		    true, &spin_thread);
	}

	for (uint32_t thread_id = 0; thread_id < n_spinners; thread_id++) {
		T_ASSERT_MACH_SUCCESS(semaphore_wait(worker_sem), "semaphore_wait");
	}

	T_ASSERT_MACH_SUCCESS(semaphore_signal_all(semaphore), "semaphore_signal");

	dt_stat_time_t seq_load = dt_stat_time_create("sequential read latency (Single CPU)");
	perform_io(seq_load);
	dt_stat_finalize(seq_load);

	atomic_store_explicit(&keep_going, 0, memory_order_relaxed);
	for (uint32_t thread_id = 0; thread_id < n_spinners; thread_id++) {
		T_ASSERT_POSIX_ZERO(pthread_join(threads[thread_id].thread, NULL),
		    "pthread_join %d", thread_id);
	}
}
