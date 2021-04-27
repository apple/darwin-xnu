/*
 * Test to validate that we can schedule threads on all hw.ncpus cores according to _os_cpu_number
 *
 * <rdar://problem/29545645>
 * <rdar://problem/30445216>
 *
 *  xcrun -sdk macosx.internal clang -o cpucount cpucount.c -ldarwintest -g -Weverything
 *  xcrun -sdk iphoneos.internal clang -arch arm64 -o cpucount-ios cpucount.c -ldarwintest -g -Weverything
 *  xcrun -sdk macosx.internal clang -o cpucount cpucount.c -ldarwintest -arch arm64e -Weverything
 */

#include <darwintest.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/sysctl.h>
#include <sys/proc_info.h>
#include <libproc.h>

#include <mach/mach.h>
#include <mach/mach_time.h>

#include <os/tsd.h> /* private header for _os_cpu_number */

T_GLOBAL_META(
	T_META_RUN_CONCURRENTLY(false),
	T_META_BOOTARGS_SET("enable_skstb=1"),
	T_META_CHECK_LEAKS(false),
	T_META_ASROOT(true),
	T_META_ALL_VALID_ARCHS(true)
	);

#define KERNEL_BOOTARGS_MAX_SIZE 1024
static char kernel_bootargs[KERNEL_BOOTARGS_MAX_SIZE];

#define KERNEL_VERSION_MAX_SIZE 1024
static char kernel_version[KERNEL_VERSION_MAX_SIZE];

static mach_timebase_info_data_t timebase_info;

static uint64_t
abs_to_nanos(uint64_t abs)
{
	return abs * timebase_info.numer / timebase_info.denom;
}

static int32_t
get_csw_count()
{
	struct proc_taskinfo taskinfo;
	int rv;

	rv = proc_pidinfo(getpid(), PROC_PIDTASKINFO, 0, &taskinfo, sizeof(taskinfo));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "PROC_PIDTASKINFO");

	return taskinfo.pti_csw;
}

// noinline hopefully keeps the optimizer from hoisting it out of the loop
// until rdar://68253516 is fixed.
__attribute__((noinline))
static uint32_t
fixed_os_cpu_number(void)
{
	uint32_t cpu_number = _os_cpu_number();

	return cpu_number;
}


T_DECL(count_cpus, "Tests we can schedule bound threads on all hw.ncpus cores and that _os_cpu_number matches")
{
	int rv;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	/* Validate what kind of kernel we're on */
	size_t kernel_version_size = sizeof(kernel_version);
	rv = sysctlbyname("kern.version", kernel_version, &kernel_version_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "kern.version");

	T_LOG("kern.version: %s\n", kernel_version);

	/* Double check that darwintest set the boot arg we requested */
	size_t kernel_bootargs_size = sizeof(kernel_bootargs);
	rv = sysctlbyname("kern.bootargs", kernel_bootargs, &kernel_bootargs_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "kern.bootargs");

	T_LOG("kern.bootargs: %s\n", kernel_bootargs);

	if (NULL == strstr(kernel_bootargs, "enable_skstb=1")) {
		T_FAIL("enable_skstb=1 boot-arg is missing");
	}

	kern_return_t kr;
	kr = mach_timebase_info(&timebase_info);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_timebase_info");

	int bound_cpu_out = 0;
	size_t bound_cpu_out_size = sizeof(bound_cpu_out);
	rv = sysctlbyname("kern.sched_thread_bind_cpu", &bound_cpu_out, &bound_cpu_out_size, NULL, 0);

	if (rv == -1) {
		if (errno == ENOENT) {
			T_FAIL("kern.sched_thread_bind_cpu doesn't exist, must set enable_skstb=1 boot-arg on development kernel");
		}
		if (errno == EPERM) {
			T_FAIL("must run as root");
		}
	}

	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "read kern.sched_thread_bind_cpu");
	T_QUIET; T_ASSERT_EQ(bound_cpu_out, -1, "kern.sched_thread_bind_cpu should exist, start unbound");

	struct sched_param param = {.sched_priority = 63};

	rv = pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pthread_setschedparam");

	uint32_t sysctl_ncpu = 0;
	size_t ncpu_size = sizeof(sysctl_ncpu);
	rv = sysctlbyname("hw.ncpu", &sysctl_ncpu, &ncpu_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "sysctlbyname(hw.ncpu)");

	T_LOG("hw.ncpu: %2d\n", sysctl_ncpu);

	T_ASSERT_GT(sysctl_ncpu, 0, "at least one CPU exists");

	for (uint32_t cpu_to_bind = 0; cpu_to_bind < sysctl_ncpu; cpu_to_bind++) {
		int32_t before_csw_count = get_csw_count();
		T_LOG("(csw %4d) attempting to bind to cpu %2d\n", before_csw_count, cpu_to_bind);

		uint64_t start =  mach_absolute_time();

		rv = sysctlbyname("kern.sched_thread_bind_cpu", NULL, 0, &cpu_to_bind, sizeof(cpu_to_bind));

		uint64_t end =  mach_absolute_time();

		if (rv == -1 && errno == ENOTSUP) {
			T_SKIP("Binding is available, but this process doesn't support binding (e.g. Rosetta on Aruba)");
		}

		T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "kern.sched_thread_bind_cpu(%u)", cpu_to_bind);

		uint32_t os_cpu_number_reported = fixed_os_cpu_number();

		bound_cpu_out = 0;
		rv = sysctlbyname("kern.sched_thread_bind_cpu", &bound_cpu_out, &bound_cpu_out_size, NULL, 0);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "read kern.sched_thread_bind_cpu");

		T_QUIET; T_EXPECT_EQ((int)cpu_to_bind, bound_cpu_out,
		    "should report bound cpu id matching requested bind target");

		uint64_t delta_abs = end - start;
		uint64_t delta_ns = abs_to_nanos(delta_abs);

		int32_t after_csw_count = get_csw_count();

		T_LOG("(csw %4d) bound to cpu %2d in %f milliseconds\n",
		    after_csw_count, cpu_to_bind,
		    ((double)delta_ns / 1000000.0));

		if (cpu_to_bind > 0) {
			T_QUIET; T_EXPECT_LT(before_csw_count, after_csw_count,
			    "should have had to context switch to execute the bind");
		}

		T_LOG("cpu %2d reported id %2d\n",
		    cpu_to_bind, os_cpu_number_reported);

		T_QUIET;
		T_EXPECT_EQ(cpu_to_bind, os_cpu_number_reported,
		    "should report same CPU number as was bound to");
	}

	int unbind = -1; /* pass -1 in order to unbind the thread */

	rv = sysctlbyname("kern.sched_thread_bind_cpu", NULL, 0, &unbind, sizeof(unbind));

	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "kern.sched_thread_bind_cpu(%u)", unbind);

	rv = sysctlbyname("kern.sched_thread_bind_cpu", &bound_cpu_out, &bound_cpu_out_size, NULL, 0);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "read kern.sched_thread_bind_cpu");
	T_QUIET; T_ASSERT_EQ(bound_cpu_out, -1, "thread should be unbound at the end");

	T_PASS("test has run threads on all CPUS");
}
