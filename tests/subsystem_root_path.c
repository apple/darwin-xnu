#include <spawn_private.h>
#include "subsystem_root_path.h"

#include <darwintest.h>
#include <darwintest_utils.h>

#define UNENTITLED_EXECUTABLE_PATH "./subsystem_root_path_helper"
#define ENTITLED_EXECUTABLE_PATH "./subsystem_root_path_helper_entitled"

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

T_DECL(subsystem_root_path,
    "Test the support for setting subsystem_root_path",
    T_META_CHECK_LEAKS(false))
{
	char * args[] = { ENTITLED_EXECUTABLE_PATH, HELPER_BEHAVIOR_NOT_SET, "/main_root/", NULL};
	int pid = 0;
	posix_spawnattr_t attr = NULL;

	T_ASSERT_EQ_INT(_spawn_and_wait(args, NULL), 0, "posix_spawn without attributes");
	T_ASSERT_POSIX_SUCCESS(posix_spawnattr_init(&attr), "posix_spawnattr_init");
	T_ASSERT_EQ_INT(_spawn_and_wait(args, &attr), 0, "posix_spawn with attributes");
	T_ASSERT_POSIX_SUCCESS(posix_spawnattr_set_subsystem_root_path_np(&attr, args[2]), "Set subsystem root path");

	args[1] = HELPER_BEHAVIOR_SET;

	T_ASSERT_EQ_INT(_spawn_and_wait(args, &attr), 0, "posix_spawn with subsystem root path");
	T_ASSERT_POSIX_SUCCESS(posix_spawnattr_set_subsystem_root_path_np(&attr, NULL), "Clear subsystem root path attribute");

	args[1] = HELPER_BEHAVIOR_NOT_SET;

	T_ASSERT_EQ_INT(_spawn_and_wait(args, &attr), 0, "Spawn without subsystem root path");

	T_ASSERT_POSIX_SUCCESS(posix_spawnattr_set_subsystem_root_path_np(&attr, args[2]), "Set subsystem root path (again)");

	args[1] = HELPER_BEHAVIOR_FORK_EXEC;

	T_ASSERT_EQ_INT(_spawn_and_wait(args, &attr), 0, "Subsystem root path inheritence across fork/exec");

	args[1] = HELPER_BEHAVIOR_SPAWN;

	T_ASSERT_EQ_INT(_spawn_and_wait(args, &attr), 0, "Subsystem root path override through posix_spawn");

	args[0] = UNENTITLED_EXECUTABLE_PATH;

	T_ASSERT_NE_INT(_spawn_and_wait(args, &attr), 0, "Entitlement check");
	T_ASSERT_POSIX_SUCCESS(posix_spawnattr_destroy(&attr), "posix_spawnattr_destroy");
}
