#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
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

#define MAX_THREADS     32
#define SPIN_SECS       6
#define THR_SPINNER_PRI 63
#define THR_MANAGER_PRI 62
#define WARMUP_ITERATIONS 100
#define POWERCTRL_SUCCESS_STR "Factor1: 1.000000"

static mach_timebase_info_data_t timebase_info;
static semaphore_t semaphore;
static semaphore_t worker_sem;
static uint32_t g_numcpus;
static _Atomic uint32_t keep_going = 1;
static dt_stat_time_t s;

static struct {
	pthread_t thread;
	bool measure_thread;
} threads[MAX_THREADS];

static uint64_t
nanos_to_abs(uint64_t nanos)
{
	return nanos * timebase_info.denom / timebase_info.numer;
}

extern char **environ;

static void
csw_perf_test_init(void)
{
	int spawn_ret, pid;
	char *const clpcctrl_args[] = {"/usr/local/bin/clpcctrl", "-f", "5000", NULL};
	spawn_ret = posix_spawn(&pid, clpcctrl_args[0], NULL, NULL, clpcctrl_args, environ);
	waitpid(pid, &spawn_ret, 0);
}

static void
csw_perf_test_cleanup(void)
{
	int spawn_ret, pid;
	char *const clpcctrl_args[] = {"/usr/local/bin/clpcctrl", "-d", NULL};
	spawn_ret = posix_spawn(&pid, clpcctrl_args[0], NULL, NULL, clpcctrl_args, environ);
	waitpid(pid, &spawn_ret, 0);
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

static void *
thread(void *arg)
{
	uint32_t thread_id = (uint32_t) arg;
	char name[30] = "";

	snprintf(name, sizeof(name), "thread %2d", thread_id);
	pthread_setname_np(name);
	T_ASSERT_MACH_SUCCESS(semaphore_wait_signal(semaphore, worker_sem), "semaphore_wait");

	if (threads[thread_id].measure_thread) {
		for (int i = 0; i < WARMUP_ITERATIONS; i++) {
			thread_switch(THREAD_NULL, SWITCH_OPTION_NONE, 0);
		}
		T_STAT_MEASURE_LOOP(s) {
			if (thread_switch(THREAD_NULL, SWITCH_OPTION_NONE, 0)) {
				T_ASSERT_FAIL("thread_switch");
			}
		}
		atomic_store_explicit(&keep_going, 0, memory_order_relaxed);
	} else {
		while (atomic_load_explicit(&keep_going, memory_order_relaxed)) {
			if (thread_switch(THREAD_NULL, SWITCH_OPTION_NONE, 0)) {
				T_ASSERT_FAIL("thread_switch");
			}
		}
	}
	return NULL;
}

void
check_device_temperature(void)
{
	char buffer[256];
	FILE *pipe = popen("powerctrl Factor1", "r");

	if (pipe == NULL) {
		T_FAIL("Failed to check device temperature");
		T_END;
	}

	fgets(buffer, sizeof(buffer), pipe);

	if (strncmp(POWERCTRL_SUCCESS_STR, buffer, strlen(POWERCTRL_SUCCESS_STR))) {
		T_PERF("temperature", 0.0, "factor", "device temperature");
	} else {
		T_PASS("Device temperature check pass");
		T_PERF("temperature", 1.0, "factor", "device temperature");
	}
	pclose(pipe);
}

void
record_perfcontrol_stats(const char *sysctlname, const char *units, const char *info)
{
	int data = 0;
	size_t data_size = sizeof(data);
	T_ASSERT_POSIX_ZERO(sysctlbyname(sysctlname,
	    &data, &data_size, NULL, 0),
	    "%s", sysctlname);
	T_PERF(info, data, units, info);
}


T_GLOBAL_META(T_META_NAMESPACE("xnu.scheduler"));

/* Disable the test on MacOS for now */
T_DECL(perf_csw, "context switch performance", T_META_TAG_PERF, T_META_CHECK_LEAKS(false), T_META_ASROOT(true))
{
#if !CONFIG_EMBEDDED
	T_SKIP("Not supported on MacOS");
	return;
#endif /* CONFIG_EMBEDDED */
	check_device_temperature();

	T_ATEND(csw_perf_test_cleanup);

	csw_perf_test_init();
	pthread_setname_np("main thread");

	T_ASSERT_MACH_SUCCESS(mach_timebase_info(&timebase_info), "mach_timebase_info");

	struct sched_param param = {.sched_priority = 48};

	T_ASSERT_POSIX_ZERO(pthread_setschedparam(pthread_self(), SCHED_FIFO, &param),
	    "pthread_setschedparam");

	T_ASSERT_MACH_SUCCESS(semaphore_create(mach_task_self(), &semaphore,
	    SYNC_POLICY_FIFO, 0), "semaphore_create");

	T_ASSERT_MACH_SUCCESS(semaphore_create(mach_task_self(), &worker_sem,
	    SYNC_POLICY_FIFO, 0), "semaphore_create");

	size_t ncpu_size = sizeof(g_numcpus);
	T_ASSERT_POSIX_ZERO(sysctlbyname("hw.ncpu", &g_numcpus, &ncpu_size, NULL, 0),
	    "sysctlbyname hw.ncpu");

	printf("hw.ncpu: %d\n", g_numcpus);
	uint32_t n_spinners = g_numcpus - 1;

	int mt_supported = 0;
	size_t mt_supported_size = sizeof(mt_supported);
	T_ASSERT_POSIX_ZERO(sysctlbyname("kern.monotonic.supported", &mt_supported,
	    &mt_supported_size, NULL, 0), "sysctlbyname kern.monotonic.supported");

	for (uint32_t thread_id = 0; thread_id < n_spinners; thread_id++) {
		threads[thread_id].thread = create_thread(thread_id, THR_SPINNER_PRI,
		    true, &spin_thread);
	}

	s = dt_stat_time_create("context switch time");

	create_thread(n_spinners, THR_MANAGER_PRI, true, &thread);
	threads[n_spinners].measure_thread = true;
	create_thread(n_spinners + 1, THR_MANAGER_PRI, true, &thread);

	/* Allow the context switch threads to get into sem_wait() */
	for (uint32_t thread_id = 0; thread_id < n_spinners + 2; thread_id++) {
		T_ASSERT_MACH_SUCCESS(semaphore_wait(worker_sem), "semaphore_wait");
	}

	int enable_callout_stats = 1;
	size_t enable_size = sizeof(enable_callout_stats);

	if (mt_supported) {
		/* Enable callout stat collection */
		T_ASSERT_POSIX_ZERO(sysctlbyname("kern.perfcontrol_callout.stats_enabled",
		    NULL, 0, &enable_callout_stats, enable_size),
		    "sysctlbyname kern.perfcontrol_callout.stats_enabled");
	}

	T_ASSERT_MACH_SUCCESS(semaphore_signal_all(semaphore), "semaphore_signal");


	for (uint32_t thread_id = 0; thread_id < n_spinners + 2; thread_id++) {
		T_ASSERT_POSIX_ZERO(pthread_join(threads[thread_id].thread, NULL),
		    "pthread_join %d", thread_id);
	}

	if (mt_supported) {
		record_perfcontrol_stats("kern.perfcontrol_callout.oncore_instr",
		    "instructions", "oncore.instructions");
		record_perfcontrol_stats("kern.perfcontrol_callout.offcore_instr",
		    "instructions", "offcore.instructions");
		record_perfcontrol_stats("kern.perfcontrol_callout.oncore_cycles",
		    "cycles", "oncore.cycles");
		record_perfcontrol_stats("kern.perfcontrol_callout.offcore_cycles",
		    "cycles", "offcore.cycles");

		/* Disable callout stat collection */
		enable_callout_stats = 0;
		T_ASSERT_POSIX_ZERO(sysctlbyname("kern.perfcontrol_callout.stats_enabled",
		    NULL, 0, &enable_callout_stats, enable_size),
		    "sysctlbyname kern.perfcontrol_callout.stats_enabled");
	}

	check_device_temperature();
	dt_stat_finalize(s);
}
