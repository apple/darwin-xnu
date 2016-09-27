#include <sys/kdebug.h>
#include <ktrace.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>

#include <darwintest.h>

// From bsd/sys/proc_internal.h
#define PID_MAX 99999

T_DECL(exit, "exit(2) time from syscall start to end", T_META_TYPE_PERF, T_META_CHECK_LEAKS(NO)) {
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
	
	ktrace_set_completion_handler(session, ^{
		free(begin_ts);
		dt_stat_finalize(s);
		T_END;
	});

	ktrace_set_signal_handler(session);

	// We are only interested by the process we launched
	ktrace_filter_process(session, "true");

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
	spawn_queue = dispatch_queue_create("spawn_queue", NULL);
	dispatch_async(spawn_queue, ^(void) {
		while (!ended) {
			pid_t pid;
			int status;
			char *args[] = {"/usr/bin/true", NULL};
			int err = posix_spawn(&pid, args[0], NULL, NULL, args, NULL);
			if (err)
				T_FAIL("posix_spawn returned %d", err);

			waitpid(pid, &status, 0);
			if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
				T_FAIL("Child process of posix_spawn failed to run");
		}
	});

	dispatch_main();
}
