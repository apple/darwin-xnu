#include <darwintest.h>
#include <inttypes.h>
#include <mach/coalition.h>
#include <stdint.h>
#include <sys/coalition.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <unistd.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

static void
skip_if_monotonic_unsupported(void)
{
	int r;
	int supported = 0;
	size_t supported_size = sizeof(supported);

	r = sysctlbyname("kern.monotonic.supported", &supported, &supported_size,
	    NULL, 0);
	if (r < 0) {
		T_WITH_ERRNO;
		T_SKIP("could not find \"kern.monotonic.supported\" sysctl");
	}

	if (!supported) {
		T_SKIP("monotonic is not supported on this platform");
	}
}

T_DECL(coalition_resource_info_counters,
    "ensure that coalition resource info produces valid counter data")
{
	skip_if_monotonic_unsupported();

	struct proc_pidcoalitioninfo idinfo = {};
	int ret = proc_pidinfo(getpid(), PROC_PIDCOALITIONINFO, 0,
	    &idinfo, sizeof(idinfo));
	T_ASSERT_POSIX_SUCCESS(ret, "proc_pidinfo(... PROC_PIDCOALITIONINFO ...)");

	uint64_t resid = idinfo.coalition_id[COALITION_TYPE_RESOURCE];

	struct coalition_resource_usage coalusage[2] = {};
	ret = coalition_info_resource_usage(resid, &coalusage[0],
	    sizeof(coalusage[0]));
	T_ASSERT_POSIX_SUCCESS(ret, "coalition_info_resource_usage()");
	T_EXPECT_GT(coalusage[0].cpu_instructions, UINT64_C(0),
	    "instruction count is non-zero");
	T_EXPECT_GT(coalusage[0].cpu_cycles, UINT64_C(0),
	    "cycle count is non-zero");

	sleep(1);

	ret = coalition_info_resource_usage(resid, &coalusage[1],
	    sizeof(coalusage[1]));
	T_ASSERT_POSIX_SUCCESS(ret, "coalition_info_resource_usage()");

	T_EXPECT_GE(coalusage[1].cpu_instructions, coalusage[0].cpu_instructions,
	    "instruction count is monotonically increasing (+%" PRIu64 ")",
	    coalusage[1].cpu_instructions - coalusage[0].cpu_instructions);
	T_EXPECT_GE(coalusage[1].cpu_cycles, coalusage[0].cpu_cycles,
	    "cycle count is monotonically increasing (+%" PRIu64 ")",
	    coalusage[1].cpu_cycles - coalusage[0].cpu_cycles);
}
