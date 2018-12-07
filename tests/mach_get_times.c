#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <mach/mach_time.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#define T_LOG_VERBOSE(...)

#define timespec2nanosec(ts) ((uint64_t)((ts)->tv_sec) * NSEC_PER_SEC + (uint64_t)((ts)->tv_nsec))

T_DECL(mach_get_times, "mach_get_times()",
	   T_META_CHECK_LEAKS(false), T_META_ALL_VALID_ARCHS(true))
{
	const int ITERATIONS = 500000 * dt_ncpu();
	struct timespec gtod_ts;

	uint64_t last_absolute, last_continuous, last_gtod;
	T_QUIET; T_ASSERT_EQ(mach_get_times(&last_absolute, &last_continuous, &gtod_ts), KERN_SUCCESS, NULL);
	last_gtod = timespec2nanosec(&gtod_ts);

	for (int i = 0; i < ITERATIONS; i++) {
		uint64_t absolute, continuous, gtod;
		T_QUIET; T_ASSERT_EQ(mach_get_times(&absolute, &continuous, &gtod_ts), KERN_SUCCESS, NULL);
		gtod = timespec2nanosec(&gtod_ts);

		T_LOG_VERBOSE("[%d] abs: %llu.%09llu(+%llu)\tcont: %llu.%09llu(+%llu)\tgtod:%llu.%09llu(+%llu)", i,
				absolute / NSEC_PER_SEC, absolute % NSEC_PER_SEC, absolute - last_absolute,
				continuous / NSEC_PER_SEC, continuous % NSEC_PER_SEC, continuous - last_continuous,
				gtod / NSEC_PER_SEC, gtod % NSEC_PER_SEC, gtod - last_gtod);

		T_QUIET; T_EXPECT_EQ(absolute - last_absolute, continuous - last_continuous, NULL);

		int64_t gtod_diff = (int64_t)gtod - (int64_t)last_gtod;
		T_QUIET; T_ASSERT_LE((uint64_t)llabs(gtod_diff), NSEC_PER_SEC, NULL);

		last_absolute = absolute;
		last_continuous = continuous;
		last_gtod = gtod;

		gtod_ts.tv_sec = 0; gtod_ts.tv_nsec = 0;
	}
}
