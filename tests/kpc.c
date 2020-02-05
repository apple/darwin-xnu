/* Copyright (c) 2018 Apple Inc.  All rights reserved. */

#include <darwintest.h>
#include <inttypes.h>
#include <stdint.h>
#include <sys/sysctl.h>

#include <kperf/kpc.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ktrace"),
	T_META_ASROOT(true),
	T_META_CHECK_LEAKS(false));

T_DECL(fixed_thread_counters,
    "test that fixed thread counters return monotonically increasing values")
{

	int err;
	uint32_t ctrs_cnt;
	uint64_t *ctrs_a;
	uint64_t *ctrs_b;

	T_SETUPBEGIN;

	ctrs_cnt = kpc_get_counter_count(KPC_CLASS_FIXED_MASK);
	if (ctrs_cnt == 0) {
		T_SKIP("no fixed counters available");
	}
	T_LOG("device has %" PRIu32 " fixed counters", ctrs_cnt);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(kpc_force_all_ctrs_set(1), NULL);
	T_ASSERT_POSIX_SUCCESS(kpc_set_counting(KPC_CLASS_FIXED_MASK),
	    "kpc_set_counting");
	T_ASSERT_POSIX_SUCCESS(kpc_set_thread_counting(KPC_CLASS_FIXED_MASK),
	    "kpc_set_thread_counting");

	T_SETUPEND;

	ctrs_a = malloc(ctrs_cnt * sizeof(uint64_t));
	T_QUIET; T_ASSERT_NOTNULL(ctrs_a, NULL);

	err = kpc_get_thread_counters(0, ctrs_cnt, ctrs_a);
	T_ASSERT_POSIX_SUCCESS(err, "kpc_get_thread_counters");

	for (uint32_t i = 0; i < ctrs_cnt; i++) {
		T_LOG("checking counter %d with value %" PRIu64 " > 0", i, ctrs_a[i]);
		T_QUIET;
		T_EXPECT_GT(ctrs_a[i], UINT64_C(0), "counter %d is non-zero", i);
	}

	ctrs_b = malloc(ctrs_cnt * sizeof(uint64_t));
	T_QUIET; T_ASSERT_NOTNULL(ctrs_b, NULL);

	err = kpc_get_thread_counters(0, ctrs_cnt, ctrs_b);
	T_ASSERT_POSIX_SUCCESS(err, "kpc_get_thread_counters");

	for (uint32_t i = 0; i < ctrs_cnt; i++) {
		T_LOG("checking counter %d with value %" PRIu64
		    " > previous value %" PRIu64, i, ctrs_b[i], ctrs_a[i]);
		T_QUIET;
		T_EXPECT_GT(ctrs_b[i], UINT64_C(0), "counter %d is non-zero", i);
		T_QUIET; T_EXPECT_LT(ctrs_a[i], ctrs_b[i],
		    "counter %d is increasing", i);
	}

	free(ctrs_a);
	free(ctrs_b);
}

#if defined(__arm64__)
/*
 * This policy only applies to arm64 devices.
 */

static int g_prev_disablewl = 0;

static void
whitelist_atend(void)
{
	int ret = sysctlbyname("kpc.disable_whitelist", NULL, NULL,
	    &g_prev_disablewl, sizeof(g_prev_disablewl));
	if (ret < 0) {
		T_LOG("failed to reset whitelist: %d (%s)", errno, strerror(errno));
	}
}

T_DECL(whitelist, "ensure kpc's whitelist is filled out")
{
	/* Start enforcing the whitelist. */
	int set = 0;
	size_t getsz = sizeof(g_prev_disablewl);
	int ret = sysctlbyname("kpc.disable_whitelist", &g_prev_disablewl, &getsz,
	    &set, sizeof(set));
	if (ret < 0 && errno == ENOENT) {
		T_SKIP("kpc not running with a whitelist, or RELEASE kernel");
	}

	T_ASSERT_POSIX_SUCCESS(ret, "started enforcing the event whitelist");
	T_ATEND(whitelist_atend);

	uint32_t nconfigs = kpc_get_config_count(KPC_CLASS_CONFIGURABLE_MASK);
	uint64_t *config = calloc(nconfigs, sizeof(*config));

	/*
	 * Check that events in the whitelist are allowed.  CORE_CYCLE (0x2) is
	 * always present in the whitelist.
	 */
	config[0] = 0x02;
	ret = kpc_set_config(KPC_CLASS_CONFIGURABLE_MASK, config);
	T_ASSERT_POSIX_SUCCESS(ret, "configured kpc to count cycles");

	/* Check that non-event bits are ignored by the whitelist. */
	config[0] = 0x102;
	ret = kpc_set_config(KPC_CLASS_CONFIGURABLE_MASK, config);
	T_ASSERT_POSIX_SUCCESS(ret,
	    "configured kpc to count cycles with non-event bits set");

	/* Check that configurations of non-whitelisted events fail. */
	config[0] = 0xfe;
	ret = kpc_set_config(KPC_CLASS_CONFIGURABLE_MASK, config);
	T_ASSERT_POSIX_FAILURE(ret, EPERM,
	    "shouldn't allow arbitrary events with whitelist enabled");

	/* Clean up the configuration. */
	config[0] = 0;
	(void)kpc_set_config(KPC_CLASS_CONFIGURABLE_MASK, config);

	free(config);
}

#endif /* defined(__arm64__) */
