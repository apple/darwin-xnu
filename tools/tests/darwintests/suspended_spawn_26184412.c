

#include <darwintest.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <sys/sysctl.h>
#include <stdbool.h>
#include <sysexits.h>
#include <err.h>

/*
 * Test to validate that suspended-spawn DTRTs when a SIGKILL is recieved
 * while the process is waiting for SIGCONT.
 *
 * Also test that suspended-spawn correctly looks like a SIGSTOP while it's suspended.
 *
 * <rdar://problem/26184412> posix_spawn non-exec with POSIX_SPAWN_START_SUSPENDED, then killing instead of SIGCONT-ing causes unkillable hung processes
 */

static void
spawn_and_signal(int signal)
{
	/* do not buffer output to stdout */
	setvbuf(stdout, NULL, _IONBF, 0);

	int ret;
	posix_spawnattr_t attr;

	ret = posix_spawnattr_init(&attr);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_init");

	ret = posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_setflags");

	char * const    prog = "/usr/bin/true";
	char * const    argv_child[] = { prog, NULL };
	pid_t           child_pid;
	extern char   **environ;

	ret = posix_spawn(&child_pid, prog, NULL, &attr, argv_child, environ);
	T_ASSERT_POSIX_SUCCESS(ret, "posix_spawn");

	printf("parent: spawned child with pid %d\n", child_pid);

	ret = posix_spawnattr_destroy(&attr);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_destroy");

	int status = 0;
	int waitpid_result = waitpid(child_pid, &status, WUNTRACED|WNOHANG);
	T_ASSERT_POSIX_SUCCESS(waitpid_result, "waitpid");

	T_ASSERT_EQ(waitpid_result, child_pid, "waitpid should return child we spawned");

	T_ASSERT_EQ(WIFEXITED(status), 0, "before SIGCONT: must not have exited");
	T_ASSERT_EQ(WIFSTOPPED(status), 1, "before SIGCONT: must be stopped");

	printf("parent: continuing child process\n");

	ret = kill(child_pid, signal);
	T_ASSERT_POSIX_SUCCESS(ret, "kill(signal)");

	printf("parent: waiting for child process\n");

	status = 0;
	waitpid_result = waitpid(child_pid, &status, 0);
	T_ASSERT_POSIX_SUCCESS(waitpid_result, "waitpid");

	T_ASSERT_EQ(waitpid_result, child_pid, "waitpid should return child we spawned");

	if (signal == SIGKILL) {
		T_ASSERT_EQ(WIFSIGNALED(status), 1, "child should have exited due to signal");
		T_ASSERT_EQ(WTERMSIG(status), SIGKILL, "child should have exited due to SIGKILL");
	} else {
		T_ASSERT_EQ(WIFEXITED(status), 1, "child should have exited normally");
		T_ASSERT_EQ(WEXITSTATUS(status), EX_OK, "child should have exited with success");
	}

	printf("wait returned with pid %d, status %d\n", ret, status);
}

T_DECL(suspended_spawn_continue, "Tests spawning a suspended process and continuing it", T_META_TIMEOUT(2))
{
	spawn_and_signal(SIGCONT);
}

T_DECL(suspended_spawn_kill, "Tests spawning a suspended process and killing it", T_META_TIMEOUT(2))
{
	spawn_and_signal(SIGKILL);
}

