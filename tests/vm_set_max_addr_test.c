#include <sys/wait.h>
#include <spawn.h>
#include <spawn_private.h>

#include <mach/mach_init.h>
#include <mach/mach_vm.h>

#include <darwintest.h>
#include <darwintest_utils.h>

extern char * testpath;

T_DECL(set_max_addr,
	"Description",
	T_META_NAMESPACE("xnu.vm"),
	T_META_CHECK_LEAKS(false))
{
#if (defined(__arm64__) && defined(__LP64__))
	int result = 0;
	int code = 0;
	int child_pid = 0;
	int status = 0;
	char * command_path = "./vm_set_max_addr_helper";
	char * command_args[] = { command_path, NULL };
	posix_spawnattr_t attrp;

	result = posix_spawnattr_init(&attrp);
	T_ASSERT_POSIX_SUCCESS(result, "posix_spawnattr_init");

	result = posix_spawn(&child_pid, command_path, NULL, &attrp, command_args, NULL);
	T_ASSERT_POSIX_SUCCESS(result, "posix_spawn");

	result = waitpid(child_pid, &status, 0);
	T_ASSERT_POSIX_SUCCESS(result, "waitpid");

	code = WEXITSTATUS(status);
	T_ASSERT_NE_INT(code, 0, "Child should have failed");

	result = posix_spawnattr_set_max_addr_np(&attrp, ~0ULL);
	T_ASSERT_POSIX_SUCCESS(result, "posix_spawnattr_set_max_addr_np");

	result = posix_spawn(&child_pid, command_path, NULL, &attrp, command_args, NULL);
	T_ASSERT_POSIX_SUCCESS(result, "posix_spawn");

	result = waitpid(child_pid, &status, 0);
	T_ASSERT_POSIX_SUCCESS(result, "waitpid");

	code = WEXITSTATUS(status);
	T_ASSERT_EQ_INT(code, 0, "Child should have succeeded");

	posix_spawnattr_destroy(&attrp);
	T_ASSERT_POSIX_SUCCESS(result, "posix_spawnattr_destroy");
#else /* !defined(__arm64__) || !defined(__LP64__) */
	T_SKIP("Not supported on this architecture");
#endif /* (defined(__arm64__) && defined(__LP64__)) */
}

