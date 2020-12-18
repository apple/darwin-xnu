#define PRIVATE
#include <darwintest.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <spawn_private.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/spawn_internal.h>
#include <sys/sysctl.h>
#include <sys/syslimits.h>
#include <sys/reason.h>
#include <sysexits.h>
#include <unistd.h>
#include <signal.h>
#include <libproc.h>
#undef PRIVATE

#include <mach-o/dyld.h>
#include <mach-o/dyld_priv.h>
#include <dlfcn.h>

#define SHARED_CACHE_HELPER "get_shared_cache_address"
#define DO_RUSAGE_CHECK "check_rusage_flag"
#define DO_DUMMY "dummy"
#define ADDRESS_OUTPUT_SIZE     12L

#ifndef _POSIX_SPAWN_RESLIDE
#define _POSIX_SPAWN_RESLIDE    0x0800
#endif

#ifndef OS_REASON_FLAG_SHAREDREGION_FAULT
#define OS_REASON_FLAG_SHAREDREGION_FAULT       0x400
#endif

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

#if     (__arm64e__ && TARGET_OS_IPHONE)
static void *
get_current_slide_address(bool reslide)
{
	pid_t                                           pid;
	int                             pipefd[2];
	posix_spawnattr_t               attr;
	posix_spawn_file_actions_t      action;
	uintptr_t                       addr;

	T_ASSERT_POSIX_SUCCESS(posix_spawnattr_init(&attr), "posix_spawnattr_init");
	/* spawn the helper requesting a reslide */
	if (reslide) {
		T_ASSERT_POSIX_SUCCESS(posix_spawnattr_setflags(&attr, _POSIX_SPAWN_RESLIDE), "posix_spawnattr_setflags");
	}

	T_ASSERT_POSIX_SUCCESS(pipe(pipefd), "pipe");
	T_ASSERT_POSIX_ZERO(posix_spawn_file_actions_init(&action), "posix_spawn_fileactions_init");
	T_ASSERT_POSIX_ZERO(posix_spawn_file_actions_addclose(&action, pipefd[0]), "posix_spawn_file_actions_addclose");
	T_ASSERT_POSIX_ZERO(posix_spawn_file_actions_adddup2(&action, pipefd[1], 1), "posix_spawn_file_actions_addup2");
	T_ASSERT_POSIX_ZERO(posix_spawn_file_actions_addclose(&action, pipefd[1]), "posix_spawn_file_actions_addclose");

	char *argvs[3];
	argvs[0] = SHARED_CACHE_HELPER;
	argvs[1] = reslide ? DO_RUSAGE_CHECK : DO_DUMMY;
	argvs[2] = NULL;
	char *const envps[] = {NULL};

	T_ASSERT_POSIX_ZERO(posix_spawn(&pid, SHARED_CACHE_HELPER, &action, &attr, argvs, envps), "helper posix_spawn");
	T_ASSERT_POSIX_SUCCESS(close(pipefd[1]), "close child end of the pipe");

	char buf[ADDRESS_OUTPUT_SIZE] = {0};

	ssize_t read_bytes = 0;
	do {
		if (read_bytes == -1) {
			T_LOG("reading off get_shared_cache_address got interrupted");
		}
		read_bytes = read(pipefd[0], buf, sizeof(buf));
	} while (read_bytes == -1 && errno == EINTR);

	T_ASSERT_EQ_LONG(ADDRESS_OUTPUT_SIZE, read_bytes, "read helper output");

	int status = 0;
	int waitpid_result = waitpid(pid, &status, 0);
	T_ASSERT_POSIX_SUCCESS(waitpid_result, "waitpid");
	T_ASSERT_EQ(waitpid_result, pid, "waitpid should return child we spawned");
	T_ASSERT_EQ(WIFEXITED(status), 1, "child should have exited normally");
	T_ASSERT_EQ(WEXITSTATUS(status), EX_OK, "child should have exited with success");

	addr = strtoul(buf, NULL, 16);
	T_ASSERT_GE_LONG(addr, 0L, "convert address to uintptr_t");

	return (void *)addr;
}

/*
 * build_faulting_shared_cache_address creates a pointer to an address that is
 * within the shared_cache range but that is guaranteed to not be mapped.
 */
static char *
build_faulting_shared_cache_address(bool tbi)
{
	uintptr_t fault_address;

	// Grab currently mapped shared cache location and size
	size_t shared_cache_len = 0;
	const void *shared_cache_location = _dyld_get_shared_cache_range(&shared_cache_len);
	if (shared_cache_location == NULL || shared_cache_len == 0) {
		return NULL;
	}

	// Locate a mach_header in the shared cache
	Dl_info info;
	if (dladdr((const void *)fork, &info) == 0) {
		return NULL;
	}

	const struct mach_header *mh = info.dli_fbase;
	uintptr_t slide = (uintptr_t)_dyld_get_image_slide(mh);

	if (slide == 0) {
		fault_address = (uintptr_t)shared_cache_location + shared_cache_len + PAGE_SIZE;
	} else {
		fault_address = (uintptr_t)shared_cache_location - PAGE_SIZE;
	}

	if (tbi) {
		fault_address |= 0x2000000000000000;
	}

	return (char *)fault_address;
}

static void
induce_crash(volatile char *ptr)
{
	pid_t child = fork();
	T_ASSERT_POSIX_SUCCESS(child, "fork");

	if (child == 0) {
		ptr[1];
	} else {
		sleep(1);
		struct proc_exitreasonbasicinfo exit_reason = {0};
		T_ASSERT_POSIX_SUCCESS(proc_pidinfo(child, PROC_PIDEXITREASONBASICINFO, 1, &exit_reason, sizeof(exit_reason)), "basic exit reason");

		int status = 0;
		int waitpid_result;
		do {
			waitpid_result = waitpid(child, &status, 0);
		} while (waitpid_result < 0 && errno == EINTR);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(waitpid_result, "waitpid");
		T_ASSERT_EQ(waitpid_result, child, "waitpid should return forked child");
		T_ASSERT_EQ(exit_reason.beri_namespace, OS_REASON_SIGNAL, "child should have exited with a signal");

		if (ptr) {
			T_ASSERT_EQ_ULLONG(exit_reason.beri_code, (unsigned long long)SIGSEGV, "child should have received SIGSEGV");
			T_ASSERT_NE((int)(exit_reason.beri_flags & OS_REASON_FLAG_SHAREDREGION_FAULT), 0, "should detect shared cache fault");
		} else {
			T_ASSERT_EQ((int)(exit_reason.beri_flags & OS_REASON_FLAG_SHAREDREGION_FAULT), 0, "should not detect shared cache fault");
		}
	}
}

static int saved_status;
static void
cleanup_sysctl(void)
{
	int ret;

	if (saved_status == 0) {
		ret = sysctlbyname("vm.vm_shared_region_reslide_aslr", NULL, NULL, &saved_status, sizeof(saved_status));
		T_QUIET; T_EXPECT_POSIX_SUCCESS(ret, "set shared region resliding back off");
	}
}
#endif  /* __arm64e && TARGET_OS_IPHONE */

T_DECL(reslide_sharedcache, "crash induced reslide of the shared cache",
    T_META_CHECK_LEAKS(false), T_META_IGNORECRASHES(".*shared_cache_reslide_test.*"),
    T_META_ASROOT(true))
{
#if (__arm64e__ && TARGET_OS_IOS)
	void *system_address;
	void *reslide_address;
	void *confirm_address;
	char *ptr;
	int  on = 1;
	size_t size;

	/* Force resliding on */
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("vm.vm_shared_region_reslide_aslr", &saved_status, &size, &on, sizeof(on)), "force enable reslide");
	T_ATEND(cleanup_sysctl);

	system_address = get_current_slide_address(false);
	confirm_address = get_current_slide_address(false);
	T_ASSERT_EQ_PTR(system_address, confirm_address, "system and current addresses should not diverge %p %p", system_address, confirm_address);

	reslide_address = get_current_slide_address(true);
	confirm_address = get_current_slide_address(true);
	T_ASSERT_NE_PTR(system_address, reslide_address, "system and reslide addresses should diverge %p %p", system_address, reslide_address);
	T_ASSERT_EQ_PTR(reslide_address, confirm_address, "reslide and another reslide (no crash) shouldn't diverge %p %p", reslide_address, confirm_address);

	/* Crash into the shared cache area */
	ptr = build_faulting_shared_cache_address(false);
	T_ASSERT_NOTNULL(ptr, "faulting on %p in the shared region", (void *)ptr);
	induce_crash(ptr);
	reslide_address = get_current_slide_address(true);
	T_ASSERT_NE_PTR(system_address, reslide_address, "system and reslide should diverge (after crash) %p %p", system_address, reslide_address);
	T_ASSERT_NE_PTR(confirm_address, reslide_address, "reslide and another reslide should diverge (after crash) %p %p", confirm_address, reslide_address);

	confirm_address = get_current_slide_address(true);
	T_ASSERT_EQ_PTR(reslide_address, confirm_address, "reslide and another reslide shouldn't diverge (no crash) %p %p", reslide_address, confirm_address);

	/* Crash somewhere else */
	ptr = NULL;
	induce_crash(ptr);
	confirm_address = get_current_slide_address(true);
	T_ASSERT_EQ_PTR(reslide_address, confirm_address, "reslide and another reslide after a non-tracked crash shouldn't diverge %p %p", reslide_address, confirm_address);

	/* Ensure we still get the system address */
	confirm_address = get_current_slide_address(false);
	T_ASSERT_EQ_PTR(system_address, confirm_address, "system address and new process without resliding shouldn't diverge %p %p", system_address, confirm_address);

	/* Ensure we detect a crash into the shared area with a TBI tagged address */
	ptr = build_faulting_shared_cache_address(true);
	T_ASSERT_NOTNULL(ptr, "faulting on %p in the shared region", (void *)ptr);
	confirm_address = get_current_slide_address(true);
	induce_crash(ptr);
	reslide_address = get_current_slide_address(true);
	T_ASSERT_NE_PTR(system_address, reslide_address, "system and reslide should diverge (after crash, TBI test) %p %p", system_address, reslide_address);
	T_ASSERT_NE_PTR(confirm_address, reslide_address, "reslide and another reslide should diverge (after crash, TBI test) %p %p", confirm_address, reslide_address);
#else   /* __arm64e__ && TARGET_OS_IPHONE */
	T_SKIP("shared cache reslide is currently only supported on arm64e iPhones");
#endif /* __arm64e__ && TARGET_OS_IPHONE */
}
