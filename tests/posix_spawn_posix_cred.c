#include <darwintest.h>

#include <errno.h>
#include <libproc.h>
#include <signal.h>
#include <spawn.h>
#include <spawn_private.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/kauth.h>
#include <sys/proc_info.h>
#include <sys/spawn_internal.h>
#include <sys/sysctl.h>
#include <sysexits.h>
#include <unistd.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

T_DECL(posix_spawn_posix_cred, "Check posix_spawnattr for POSIX creds",
    T_META_ASROOT(true))
{
	posix_spawnattr_t attr;
	int ret;

	ret = posix_spawnattr_init(&attr);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_init");

	ret = posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_setflags");

	ret = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSID);
	T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_setflags(POSIX_SPAWN_SETSID)");

	ret = posix_spawnattr_set_uid_np(&attr, 502);
	T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_set_uid_np");

	ret = posix_spawnattr_set_gid_np(&attr, 501);
	T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_set_gid_np");

	gid_t groups[3] = { 501, 250, 299 };
	ret = posix_spawnattr_set_groups_np(&attr, 3, &groups, KAUTH_UID_NONE);
	T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_set_groups_np");

	ret = posix_spawnattr_set_login_np(&attr, "fake-name");
	T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_set_login_np");

	char * const    prog = "/bin/sh";
	char * const    argv_child[] = { prog,
		                         "-c",
		                         "test $(logname) = \"fake-name\" -a \"$(id -G)\" = \"501 250 299\"",
		                         NULL, };
	pid_t           child_pid;
	extern char   **environ;

	ret = posix_spawn(&child_pid, prog, NULL, &attr, argv_child, environ);
	T_ASSERT_POSIX_SUCCESS(ret, "posix_spawn");

	T_LOG("parent: spawned child with pid %d\n", child_pid);

	ret = posix_spawnattr_destroy(&attr);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_destroy");

	struct proc_bsdinfo info;

	ret = proc_pidinfo(child_pid, PROC_PIDTBSDINFO, 1, &info, sizeof(info));
	T_QUIET;
	T_ASSERT_EQ(ret, (int)sizeof(info), "proc_pidinfo(PROC_PIDTBSDINFO)");

	T_EXPECT_TRUE((bool)(info.pbi_flags & PROC_FLAG_SLEADER),
	    "check setsid happened");
	T_EXPECT_EQ(info.pbi_uid, 502, "UID was set");
	T_EXPECT_EQ(info.pbi_gid, 501, "GID was set");

	ret = kill(child_pid, SIGCONT);
	T_ASSERT_POSIX_SUCCESS(ret, "kill(signal)");

	T_LOG("parent: waiting for child process\n");

	int status = 0;
	int waitpid_result = waitpid(child_pid, &status, 0);
	T_ASSERT_POSIX_SUCCESS(waitpid_result, "waitpid");
	T_ASSERT_EQ(waitpid_result, child_pid, "waitpid should return child we spawned");
	T_ASSERT_EQ(WIFEXITED(status), 1, "child should have exited normally");
	T_ASSERT_EQ(WEXITSTATUS(status), EX_OK, "child should have exited with success");
}
