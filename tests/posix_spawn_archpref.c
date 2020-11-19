#include <darwintest.h>
#include <mach-o/dyld.h>
#include <spawn.h>
#include <unistd.h>
#include <sys/wait.h>

static void
run_test(const char *name, cpu_type_t type, cpu_subtype_t subtype)
{
	int ret, pid;
	posix_spawnattr_t spawnattr;
	char path[1024];
	uint32_t size = sizeof(path);
	cpu_type_t cpuprefs[] = { type };
	cpu_type_t subcpuprefs[] = { subtype };

	T_QUIET; T_ASSERT_EQ(_NSGetExecutablePath(path, &size), 0, NULL);
	T_QUIET; T_ASSERT_LT(strlcat(path, "_helper", size), (unsigned long)size, NULL);

	ret = posix_spawnattr_init(&spawnattr);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "%s: posix_spawnattr_init", name);

	ret = posix_spawnattr_setarchpref_np(&spawnattr, sizeof(cpuprefs) / sizeof(cpuprefs[0]), cpuprefs, subcpuprefs, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "%s: posix_spawnattr_setarchpref_np", name);

	ret = posix_spawn(&pid, path, NULL, &spawnattr, NULL, NULL);
	T_ASSERT_EQ(ret, 0, "%s: posix_spawn should succeed", name);

	int wait_ret = 0;
	ret = waitpid(pid, &wait_ret, 0);
	T_QUIET; T_ASSERT_EQ(ret, pid, "%s: child pid", name);

	T_QUIET; T_ASSERT_EQ(WIFEXITED(wait_ret), 1, "%s: child process should have called exit()", name);

	if (subtype != CPU_SUBTYPE_ANY) {
		T_ASSERT_EQ(WEXITSTATUS(wait_ret), subtype, "%s: child process should be running with %d subtype", name, subtype);
	}

	ret = posix_spawnattr_destroy(&spawnattr);
	T_QUIET; T_ASSERT_EQ(ret, 0, "%s: posix_spawnattr_destroy", name);
}

T_DECL(posix_spawn_archpref, "verify posix_spawn_setarchpref_np can select slices")
{
#if defined(__x86_64__)
	run_test("x86_64", CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL);
#endif /* defined(__x86_64__) */
#if defined(__arm64__) && defined(__LP64__)
	run_test("arm64", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
#endif /* defined(__arm64__) && defined(__LP64__) */

#if defined(__x86_64__)
	run_test("any (x86_64)", CPU_TYPE_X86_64, CPU_SUBTYPE_ANY);
#elif defined(__arm64__) && defined(__LP64__)
	run_test("any (arm64)", CPU_TYPE_ARM64, CPU_SUBTYPE_ANY);
#elif defined(__arm64__)
	run_test("any (arm64_32)", CPU_TYPE_ARM64_32, CPU_SUBTYPE_ANY);
#elif defined(__arm__)
	run_test("any (arm)", CPU_TYPE_ARM, CPU_SUBTYPE_ANY);
#else
#error unknown architecture
#endif
}
