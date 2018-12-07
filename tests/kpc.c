#include <darwintest.h>
#include <inttypes.h>
#include <stdint.h>

#include <kperf/kpc.h>

T_DECL(fixed_counters,
		"test that fixed counters return monotonically increasing values",
		T_META_ASROOT(YES))
{
	T_SKIP("unimplemented");
}

T_DECL(fixed_thread_counters,
		"test that fixed thread counters return monotonically increasing values",
		T_META_ASROOT(YES))
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
