#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif
#include <darwintest.h>

#include <spawn.h>
#include <stdlib.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.perf.fork"),
	T_META_CHECK_LEAKS(false)
);

#define SPAWN_MEASURE_LOOP(s) \
	char *args[] = {"/usr/bin/true", NULL}; \
	int err; \
	pid_t pid; \
	int status; \
	while (!dt_stat_stable(s)) { \
		T_STAT_MEASURE(s) { \
			err = posix_spawn(&pid, args[0], NULL, NULL, args, NULL); \
		} \
		if (err) { \
			T_FAIL("posix_spawn returned %d", err); \
		} \
		waitpid(pid, &status, 0); \
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) { \
			T_FAIL("Child process of posix_spawn failed to run"); \
		} \
	}

T_DECL(posix_spawn_platform_binary_latency, "posix_spawn platform binary latency") {
	{
		dt_stat_time_t s = dt_stat_time_create("time");
		SPAWN_MEASURE_LOOP(s);
		dt_stat_finalize(s);
	}

	{
		dt_stat_thread_cpu_time_t s = dt_stat_thread_cpu_time_create("on-cpu time");
		SPAWN_MEASURE_LOOP(s);
		dt_stat_finalize(s);
	}
}

#define FORK_MEASURE_LOOP(s) \
	pid_t pid; \
	int status; \
	while (!dt_stat_stable(s)) { \
		T_STAT_MEASURE(s) { \
			pid = fork(); \
			if (pid == 0) \
				exit(0); \
			else if (pid == -1) \
				T_FAIL("fork returned -1"); \
		} \
		waitpid(pid, &status, 0); \
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) { \
			T_FAIL("forked process failed to exit properly"); \
		} \
	}

T_DECL(fork, "fork latency") {
	{
		dt_stat_time_t s = dt_stat_time_create("time");
		FORK_MEASURE_LOOP(s);
		dt_stat_finalize(s);
	}
	{
		dt_stat_thread_cpu_time_t s = dt_stat_thread_cpu_time_create("on-cpu time");
		FORK_MEASURE_LOOP(s);
		dt_stat_finalize(s);
	}
}
