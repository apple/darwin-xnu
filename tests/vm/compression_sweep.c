#include <darwintest.h>
#include <errno.h>
#include <TargetConditionals.h>
#include <mach/mach.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/proc.h>

static int orig_age = 0;
static const char *ripe_target_age_sysctl = "vm.vm_ripe_target_age_in_secs";

static void
cleanup_ripe_age(void)
{
	int ret = sysctlbyname(ripe_target_age_sysctl, NULL, NULL, &orig_age,
	    sizeof(orig_age));
	if (ret == -1) {
		T_LOG("non-fatal: failed to reset %s: %s", ripe_target_age_sysctl,
		    strerror(errno));
	}
}

T_DECL(compression_sweep,
    "ensure some pages are compressed due to pid_hibernate",
    T_META_ASROOT(true),
    T_META_ENABLED(!TARGET_OS_OSX && !TARGET_OS_WATCH && !TARGET_OS_TV))
{
	/*
	 * Change the system to sweep out compressed pages that are older than
	 * `compressed_page_target_age_secs` seconds and induce `sweep_count` sweeps
	 * every `sleep_dur_secs` seconds.
	 */

	int compressed_page_target_age_secs = 1;
	const int sweep_period_secs = 10;
	T_QUIET; T_ASSERT_GT(sweep_period_secs, compressed_page_target_age_secs,
	    "should sleep longer than target age");
	const int sweep_count = 3;

	vm_statistics64_data_t vm_stat_before;
	unsigned int count = HOST_VM_INFO64_COUNT;
	kern_return_t kret = host_statistics64(mach_host_self(), HOST_VM_INFO64,
	    (host_info64_t)&vm_stat_before, &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kret, "host_statistics64");

	size_t size = sizeof(orig_age);
	int ret = sysctlbyname(ripe_target_age_sysctl, &orig_age, &size,
	    &compressed_page_target_age_secs,
	    sizeof(compressed_page_target_age_secs));
	T_ASSERT_POSIX_SUCCESS(ret, "temporarily set sysctl(%s) to %d",
	    ripe_target_age_sysctl, compressed_page_target_age_secs);
	T_ATEND(cleanup_ripe_age);

	for (int i = 0; i < sweep_count; i++) {
		const int sweep_out_unused_compressed_command = -2;
		ret = pid_hibernate(sweep_out_unused_compressed_command);
		T_ASSERT_POSIX_SUCCESS(ret, "pid_hibernate(sweep-unused-compressed)");
		sleep(sweep_period_secs);
	}

	vm_statistics64_data_t vm_stat_after;
	count = HOST_VM_INFO64_COUNT;
	kret = host_statistics64(mach_host_self(), HOST_VM_INFO64,
	    (host_info64_t)&vm_stat_after, &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kret, "host_statistics64");

	T_LOG("compressed %llu pages",
	    vm_stat_after.compressions - vm_stat_before.swapouts);
	T_EXPECT_GT(vm_stat_after.compressions, vm_stat_before.compressions,
	    "should have compressed some pages during sweeps");
	// rdar://71454311 (Compression sweep swap outs are flaky, should induce compressions)
	T_MAYFAIL;
	T_EXPECT_GT(vm_stat_after.swapouts, vm_stat_before.swapouts,
	    "should have swapped out some pages during sweeps");
}
