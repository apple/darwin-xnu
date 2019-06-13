#include <spawn.h>
#include <sys/wait.h>
#include <darwintest.h>
#include <mach-o/dyld.h>
#include <errno.h>

T_DECL(no32exec_bootarg, "make sure the no32exec boot-arg is honored", T_META_BOOTARGS_SET("-no32exec"))
{
	int spawn_ret, pid;
	char path[1024];
	uint32_t size = sizeof(path);

	T_ASSERT_EQ(_NSGetExecutablePath(path, &size), 0, NULL);
	T_ASSERT_LT(strlcat(path, "_helper", size), size, NULL);

	spawn_ret = posix_spawn(&pid, path, NULL, NULL, NULL, NULL);
	if (spawn_ret == 0) {
		int wait_ret = 0;
		waitpid(pid, &wait_ret, 0);
		T_ASSERT_FALSE(WIFEXITED(wait_ret), "i386 helper should not run");
	}
	T_ASSERT_EQ(spawn_ret, EBADARCH, NULL);
}
