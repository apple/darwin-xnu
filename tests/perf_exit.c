#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif
#include <darwintest.h>
#include <darwintest_utils.h>

#include <sys/kdebug.h>
#include <ktrace/session.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.perf"),
	T_META_ASROOT(true),
	T_META_LTEPHASE(LTE_SINGLEUSER),
	T_META_TAG_PERF
	);
#if TARGET_OS_WATCH
#define TEST_TIMEOUT 3600 * (NSEC_PER_SEC)
#else
#define TEST_TIMEOUT 1800 * (NSEC_PER_SEC)
#endif
// From bsd/sys/proc_internal.h
#define PID_MAX 99999

#define EXIT_BINARY "perf_exit_proc"
#define EXIT_BINARY_PATH "./" EXIT_BINARY

#define NEXT_CASE_EVENTID (0xfedcbb00)

struct test_case {
	int wired_mem;
	int threads;
};

static struct test_case test_cases[] = {
	{0, 0},
	{0, 10},
	{1000000, 0},
#if !TARGET_OS_WATCH
	{10000000, 0}
#endif
};

#define TEST_CASES_COUNT (sizeof(test_cases) / sizeof(struct test_case))

static _Atomic int producer_i, consumer_i;

static ktrace_session_t session;

static dispatch_queue_t spawn_queue, processing_queue;

static uint64_t *begin_ts;
static dt_stat_time_t s;
static _Atomic bool tracing_on = false;

void run_exit_test(int proc_wired_mem, int nthreads);

static void
cleanup(void)
{
	free(begin_ts);
	dispatch_release(spawn_queue);
	dispatch_release(processing_queue);
	if (tracing_on) {
		ktrace_end(session, 1);
	}
}

static dt_stat_time_t
create_stat(int proc_wired_mem, int nthreads)
{
	dt_stat_time_t dst = dt_stat_time_create("time");
	T_ASSERT_NOTNULL(dst, "created time statistic");

	dt_stat_set_variable((dt_stat_t)dst, "proc_threads", nthreads);
	dt_stat_set_variable((dt_stat_t)dst, "proc_wired_mem", proc_wired_mem);;

	return dst;
}

T_DECL(exit, "exit(2) time from syscall start to end", T_META_TIMEOUT(TEST_TIMEOUT)) {
	s = create_stat(test_cases[consumer_i].wired_mem, test_cases[consumer_i].threads);

	begin_ts = malloc(sizeof(uint64_t) * PID_MAX);
	T_ASSERT_NOTNULL(begin_ts, "created pid array");

	T_ATEND(cleanup);

	session = ktrace_session_create();
	T_ASSERT_NOTNULL(session, "created a trace session");

	spawn_queue = dispatch_queue_create("com.apple.perf_exit.spawn_queue", NULL);
	processing_queue = dispatch_queue_create("com.apple.perf_exit.processing_queue", NULL);

	ktrace_set_completion_handler(session, ^{
		T_ASSERT_EQ(consumer_i, TEST_CASES_COUNT, "ran all the test cases");
		dispatch_sync(spawn_queue, ^(void) {
			tracing_on = false;
		});
		ktrace_session_destroy(session);
		T_END;
	});

	ktrace_set_signal_handler(session);
	ktrace_set_execnames_enabled(session, KTRACE_FEATURE_ENABLED);

	// We are only interested in the processes we launched and ourselves
	ktrace_filter_process(session, EXIT_BINARY);
	ktrace_filter_process(session, "perf_exit");

	ktrace_events_single(session, NEXT_CASE_EVENTID, ^(__unused ktrace_event_t e) {
		consumer_i++;
		dt_stat_finalize(s);
		if (consumer_i >= TEST_CASES_COUNT) {
		        ktrace_end(session, 1);
		} else {
		        s = create_stat(test_cases[consumer_i].wired_mem, test_cases[consumer_i].threads);
		}
	});

	ktrace_events_single(session, (BSDDBG_CODE(DBG_BSD_EXCP_SC, 1) | DBG_FUNC_START), ^(ktrace_event_t e) {
		T_QUIET; T_ASSERT_LE(e->pid, PID_MAX, "pid %d is valid in start tracepoint", e->pid);
		begin_ts[e->pid] = e->timestamp;
	});

	ktrace_events_single(session, (BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXIT) | DBG_FUNC_END), ^(ktrace_event_t e) {
		T_ASSERT_LE(e->pid, PID_MAX, "pid %d is valid in end tracepoint", e->pid);

		if (begin_ts[e->pid] == 0) {
		        return;
		}

		T_QUIET; T_ASSERT_LE(begin_ts[e->pid], e->timestamp, "timestamps are monotonically increasing");
		dt_stat_mach_time_add(s, e->timestamp - begin_ts[e->pid]);


		if (dt_stat_stable(s) && producer_i == consumer_i) {
		        dispatch_sync(spawn_queue, ^(void) {
				producer_i++;
				T_ASSERT_POSIX_ZERO(kdebug_trace(NEXT_CASE_EVENTID, producer_i, 0, 0, 0), "kdebug_trace returns 0");
			});
		}
	});

	int ret = ktrace_start(session, processing_queue);
	T_ASSERT_POSIX_ZERO(ret, "starting trace");
	tracing_on = true;

	// Spawn processes continuously until the test is over

	__block void (^spawn_process)(void) = Block_copy(^(void) {
		char nthreads_buf[32], mem_buf[32];

		if (producer_i >= TEST_CASES_COUNT || !tracing_on) {
		        return;
		}

		snprintf(nthreads_buf, 32, "%d", test_cases[producer_i].threads);
		snprintf(mem_buf, 32, "%d", test_cases[producer_i].wired_mem);

		char *args[] = {EXIT_BINARY_PATH, nthreads_buf, mem_buf, NULL};
		int status;

		pid_t pid;
		int bret = posix_spawn(&pid, args[0], NULL, NULL, args, NULL);
		T_ASSERT_POSIX_ZERO(bret, "spawned process with pid %d (threads=%s mem=%s)", pid, nthreads_buf, mem_buf);

		bret = waitpid(pid, &status, 0);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(bret, "waited for process %d\n", pid);

		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		        T_ASSERT_FAIL("child process failed to run");
		}

		// Avoid saturating the CPU with new processes
		usleep(1000);

		dispatch_async(spawn_queue, spawn_process);
	});

	dispatch_async(spawn_queue, spawn_process);

	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, TEST_TIMEOUT), dispatch_get_main_queue(), ^{
		ktrace_end(session, 0);
	});

	dispatch_main();
}
