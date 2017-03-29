#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif
#include <darwintest.h>

#include <sys/kdebug.h>
#include <ktrace.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>

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

void run_exit_test(int proc_wired_mem, int thread_priority, int nthreads);

void run_exit_test(int proc_wired_mem, int thread_priority, int nthreads) {
	_Atomic static int ended = 0;
	dispatch_queue_t spawn_queue;

	dt_stat_time_t s = dt_stat_time_create("time");

	uint64_t *begin_ts = malloc(sizeof(uint64_t) * PID_MAX);
	if (begin_ts == NULL) {
		T_FAIL("Error allocating timestamp array");
	}

	ktrace_session_t session;
	session = ktrace_session_create();
	if (session == NULL) {
		T_FAIL("Error creating ktrace session");
	}

	spawn_queue = dispatch_queue_create("spawn_queue", NULL);

	ktrace_set_completion_handler(session, ^{
		free(begin_ts);
		dt_stat_finalize(s);
		dispatch_release(spawn_queue);
		T_END;
	});

	ktrace_set_signal_handler(session);

	// We are only interested by the process we launched
	ktrace_filter_process(session, EXIT_BINARY);

	ktrace_events_single(session, (BSDDBG_CODE(DBG_BSD_EXCP_SC, 1) | DBG_FUNC_START), ^(ktrace_event_t e) {
		pid_t pid = ktrace_get_pid_for_thread(session, e->threadid);
		if (pid > PID_MAX) {
			T_FAIL("Invalid pid returned by ktrace_get_pid_for_thread: %d\n", pid);
		}
		begin_ts[pid] = e->timestamp;

	});
	ktrace_events_single(session, (BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXIT) | DBG_FUNC_END), ^(ktrace_event_t e) {
		pid_t pid = ktrace_get_pid_for_thread(session, e->threadid);
		if (pid > PID_MAX) {
			T_FAIL("Invalid pid returned by ktrace_get_pid_for_thread: %d\n", pid);
		}
		if (begin_ts[pid] == 0) {
			return;
		}
		uint64_t delta = e->timestamp - begin_ts[pid];
		if (!dt_stat_stable(s)) {
			dt_stat_mach_time_add(s, delta);
		}
		else {
			ended = 1;
			ktrace_end(session, 1);
		}
	});

	int ret = ktrace_start(session, dispatch_get_main_queue());
	if (ret != 0) {
		T_FAIL("Error starting ktrace");
	}

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
			int err = posix_spawn(&pid, args[0], NULL, NULL, args, NULL);
			if (err)
				T_FAIL("posix_spawn returned %d", err);

			waitpid(pid, &status, 0);
			if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
				T_FAIL("Child process of posix_spawn failed to run");

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

/*
T_DECL(exit_100_threads, "exit(2) time with 100 threads", T_META_TIMEOUT(1800)) {
	run_exit_test(0, BASEPRI_FOREGROUND, 100);
}

T_DECL(exit_1000_threads, "exit(2) time with 1000 threads", T_META_TIMEOUT(1800)) {
	run_exit_test(0, BASEPRI_FOREGROUND, 1000);
}

T_DECL(exit_100mb, "exit(2) time with 100MB of wired memory", T_META_TIMEOUT(1800)) {
	run_exit_test(100000000, BASEPRI_FOREGROUND, 0);
}
*/

