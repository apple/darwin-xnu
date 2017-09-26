#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif
#include <darwintest.h>

#include <sys/kdebug.h>
#include <ktrace/session.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.perf.exit"),
	T_META_ASROOT(true),
	T_META_LTEPHASE(LTE_SINGLEUSER)
);

// From osfmk/kern/sched.h
#define BASEPRI_FOREGROUND 47
#define BASEPRI_USER_INITIATED 37
#define BASEPRI_UTILITY 20
#define MAXPRI_THROTTLE 4

// From bsd/sys/proc_internal.h
#define PID_MAX 99999

#define EXIT_BINARY "perf_exit_proc"
#define EXIT_BINARY_PATH "./" EXIT_BINARY

static ktrace_session_t session;
static dispatch_queue_t spawn_queue;
static uint64_t *begin_ts;
static dt_stat_time_t s;
static bool started_tracing = false;

void run_exit_test(int proc_wired_mem, int thread_priority, int nthreads);

static void cleanup(void) {
	free(begin_ts);
	dt_stat_finalize(s);
	dispatch_release(spawn_queue);
	if (started_tracing) {
		ktrace_end(session, 1);
	}
}

void run_exit_test(int proc_wired_mem, int thread_priority, int nthreads) {
	static atomic_bool ended = false;

	s = dt_stat_time_create("time");
	T_QUIET; T_ASSERT_NOTNULL(s, "created time statistic");

	begin_ts = malloc(sizeof(uint64_t) * PID_MAX);
	T_QUIET; T_ASSERT_NOTNULL(begin_ts, "created pid array");

	T_ATEND(cleanup);

	session = ktrace_session_create();
	T_QUIET; T_ASSERT_NOTNULL(session, "created a trace session");

	spawn_queue = dispatch_queue_create("spawn_queue", NULL);

	ktrace_set_completion_handler(session, ^{
		ktrace_session_destroy(session);
		T_END;
	});

	ktrace_set_signal_handler(session);
	ktrace_set_execnames_enabled(session, KTRACE_FEATURE_ENABLED);

	// We are only interested in the process we launched
	ktrace_filter_process(session, EXIT_BINARY);

	ktrace_events_single(session, (BSDDBG_CODE(DBG_BSD_EXCP_SC, 1) | DBG_FUNC_START), ^(ktrace_event_t e) {
		T_QUIET; T_ASSERT_LE(e->pid, PID_MAX, "valid pid for tracepoint");
		begin_ts[e->pid] = e->timestamp;
	});
	ktrace_events_single(session, (BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXIT) | DBG_FUNC_END), ^(ktrace_event_t e) {
		T_QUIET; T_ASSERT_LE(e->pid, PID_MAX, "valid pid for tracepoint");

		if (begin_ts[e->pid] == 0) {
			return;
		}
		T_QUIET; T_ASSERT_LE(begin_ts[e->pid], e->timestamp, "timestamps are monotonically increasing");
		dt_stat_mach_time_add(s, e->timestamp - begin_ts[e->pid]);

		if (dt_stat_stable(s)) {
			ended = true;
			ktrace_end(session, 1);
		}
	});

	int ret = ktrace_start(session, dispatch_get_main_queue());
	T_ASSERT_POSIX_ZERO(ret, "starting trace");
	started_tracing = true;

	// Spawn processes continuously until the test is over
	dispatch_async(spawn_queue, ^(void) {
		char priority_buf[32], nthreads_buf[32], mem_buf[32];

		snprintf(priority_buf, 32, "%d", thread_priority);
		snprintf(nthreads_buf, 32, "%d", nthreads);
		snprintf(mem_buf, 32, "%d", proc_wired_mem);

		char *args[] = {EXIT_BINARY_PATH, priority_buf, nthreads_buf, mem_buf, NULL};
		int status;
		while (!ended) {
			pid_t pid;
			int bret = posix_spawn(&pid, args[0], NULL, NULL, args, NULL);
			T_QUIET; T_ASSERT_POSIX_ZERO(bret, "spawned process '%s'", args[0]);

			bret = waitpid(pid, &status, 0);
			T_QUIET; T_ASSERT_POSIX_SUCCESS(bret, "waited for process %d\n", pid);

			if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
				T_ASSERT_FAIL("child process failed to run");

			// Avoid saturating the CPU with new processes
			usleep(1);
		}
	});

	dispatch_main();
}


T_DECL(exit, "exit(2) time from syscall start to end") {
	run_exit_test(0, BASEPRI_FOREGROUND, 0);
}

T_DECL(exit_pri_4, "exit(2) time at priority 4 (throttled)") {
	run_exit_test(0, MAXPRI_THROTTLE, 0);
}

T_DECL(exit_pri_20, "exit(2) time at priority 20 (utility)") {
	run_exit_test(0, BASEPRI_UTILITY, 0);
}

T_DECL(exit_pri_37, "exit(2) time at priority 37 (user initiated)") {
	run_exit_test(0, BASEPRI_USER_INITIATED, 0);
}

T_DECL(exit_10_threads, "exit(2) time with 10 threads") {
	run_exit_test(0, BASEPRI_FOREGROUND, 10);
}

T_DECL(exit_1mb, "exit(2) time with 1MB of wired memory") {
	run_exit_test(10000000, BASEPRI_FOREGROUND, 0);
}

T_DECL(exit_10mb, "exit(2) time with 10MB of wired memory") {
	run_exit_test(10000000, BASEPRI_FOREGROUND, 0);
}

T_DECL(exit_100_threads, "exit(2) time with 100 threads", T_META_ENABLED(false), T_META_TIMEOUT(1800)) {
	run_exit_test(0, BASEPRI_FOREGROUND, 100);
}

T_DECL(exit_1000_threads, "exit(2) time with 1000 threads", T_META_ENABLED(false), T_META_TIMEOUT(1800)) {
	run_exit_test(0, BASEPRI_FOREGROUND, 1000);
}

T_DECL(exit_100mb, "exit(2) time with 100MB of wired memory", T_META_ENABLED(false), T_META_TIMEOUT(1800)) {
	run_exit_test(100000000, BASEPRI_FOREGROUND, 0);
}
