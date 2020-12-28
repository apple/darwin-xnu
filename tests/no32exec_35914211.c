#include <spawn.h>
#include <sys/wait.h>
#include <darwintest.h>
#include <mach-o/dyld.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

T_DECL(no32exec_bootarg_with_spawn, "make sure we can't posix_spawn 32-bit")
{
	int spawn_ret, pid;
	char path[1024];
	uint32_t size = sizeof(path);

	T_QUIET; T_ASSERT_EQ(_NSGetExecutablePath(path, &size), 0, NULL);
	T_QUIET; T_ASSERT_LT(strlcat(path, "_helper", size), (unsigned long)size, NULL);

	spawn_ret = posix_spawn(&pid, path, NULL, NULL, NULL, NULL);
	if (spawn_ret == 0) {
		int wait_ret = 0;
		waitpid(pid, &wait_ret, 0);
		T_ASSERT_FALSE(WIFEXITED(wait_ret), "i386 helper should not run");
	}
	T_ASSERT_EQ(spawn_ret, EBADARCH, NULL);
}

T_DECL(no32_exec_bootarg_with_exec, "make sure we can't fork and exec 32-bit")
{
	int pid;
	char path[1024];
	uint32_t size = sizeof(path);

	T_QUIET; T_ASSERT_EQ(_NSGetExecutablePath(path, &size), 0, NULL);
	T_QUIET; T_ASSERT_LT(strlcat(path, "_helper", size), (unsigned long)size, NULL);

	pid = fork();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pid, "fork");

	if (pid == 0) { /* child */
		execve(path, NULL, NULL); /* this should fail, resulting in the call to exit below */
		exit(errno);
	} else { /* parent */
		int wait_ret = 0;
		waitpid(pid, &wait_ret, 0);
		T_QUIET; T_ASSERT_TRUE(WIFEXITED(wait_ret), "child should have called exit()");
		T_ASSERT_EQ(WEXITSTATUS(wait_ret), EBADARCH, "execve should set errno = EBADARCH");
	}
}

T_DECL(no32exec_bootarg_with_spawn_binprefs, "make sure we honor no32exec, using posix_spawn with binprefs on a fat i386/x86_64 Mach-O")
{
	int pid, ret;
	posix_spawnattr_t spawnattr;
	cpu_type_t cpuprefs[] = { CPU_TYPE_X86, CPU_TYPE_X86_64 };

	char path[1024];
	uint32_t size = sizeof(path);
	T_QUIET; T_ASSERT_EQ(_NSGetExecutablePath(path, &size), 0, NULL);
	T_QUIET; T_ASSERT_LT(strlcat(path, "_helper_binprefs", size), (unsigned long)size, NULL);

	ret = posix_spawnattr_init(&spawnattr);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_init");

	ret = posix_spawnattr_setbinpref_np(&spawnattr, sizeof(cpuprefs) / sizeof(cpuprefs[0]), cpuprefs, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_setbinpref_np");

	ret = posix_spawn(&pid, path, NULL, &spawnattr, NULL, NULL);
	T_ASSERT_EQ(ret, 0, "posix_spawn should succeed despite 32-bit binpref appearing first");

	int wait_ret = 0;
	ret = waitpid(pid, &wait_ret, 0);
	T_QUIET; T_ASSERT_EQ(ret, pid, "child pid");

	T_QUIET; T_ASSERT_EQ(WIFEXITED(wait_ret), 1, "child process should have called exit()");
	T_ASSERT_EQ(WEXITSTATUS(wait_ret), 8, "child process should be running in 64-bit mode");

	ret = posix_spawnattr_destroy(&spawnattr);
	T_QUIET; T_ASSERT_EQ(ret, 0, "posix_spawnattr_destroy");
}

T_DECL(no32exec_bootarg_with_32only_spawn_binprefs, "make sure we honor no32exec, using posix_spawn with 32-bit only binprefs on a fat i386/x86_64 Mach-O")
{
	int pid, ret, spawn_ret;
	posix_spawnattr_t spawnattr;
	cpu_type_t cpuprefs[] = { CPU_TYPE_X86 };

	char path[1024];
	uint32_t size = sizeof(path);
	T_QUIET; T_ASSERT_EQ(_NSGetExecutablePath(path, &size), 0, NULL);
	T_QUIET; T_ASSERT_LT(strlcat(path, "_helper_binprefs", size), (unsigned long)size, NULL);

	ret = posix_spawnattr_init(&spawnattr);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_init");

	ret = posix_spawnattr_setbinpref_np(&spawnattr, sizeof(cpuprefs) / sizeof(cpuprefs[0]), cpuprefs, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_setbinpref_np");

	spawn_ret = posix_spawn(&pid, path, NULL, &spawnattr, NULL, NULL);
	T_ASSERT_EQ(spawn_ret, EBADARCH, "posix_spawn should return EBADARCH since only 32-bit binpref is requested");

	ret = posix_spawnattr_destroy(&spawnattr);
	T_QUIET; T_ASSERT_EQ(ret, 0, "posix_spawnattr_destroy");
}
