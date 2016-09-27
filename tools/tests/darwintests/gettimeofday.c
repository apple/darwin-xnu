#include <unistd.h>
#include <sys/time.h>
#include <mach/mach_time.h>

#include <darwintest.h>

extern int __gettimeofday(struct timeval *, struct timezone *);

T_DECL(gettimeofday, "gettimeofday()",
	   T_META_CHECK_LEAKS(NO), T_META_ALL_VALID_ARCHS(YES))
{
	struct timeval tv_a, tv_b, tv_c;

	T_ASSERT_POSIX_ZERO(gettimeofday(&tv_a, NULL), NULL);
	T_ASSERT_GT(tv_a.tv_sec, 0L, NULL);

	sleep(1);

	T_ASSERT_POSIX_ZERO(__gettimeofday(&tv_b, NULL), NULL);
	T_ASSERT_GE(tv_b.tv_sec, tv_a.tv_sec, NULL);

	sleep(1);

	T_ASSERT_POSIX_ZERO(gettimeofday(&tv_c, NULL), NULL);
	T_ASSERT_GE(tv_c.tv_sec, tv_b.tv_sec, NULL);
}

#if 0 // This symbol isn't exported so we can't test with stock libsyscall
extern int __gettimeofday_with_mach(struct timeval *, struct timezone *, uint64_t *mach_time);

T_DECL(gettimeofday_with_mach, "gettimeofday_with_mach()",
	   T_META_CHECK_LEAKS(NO), T_META_ALL_VALID_ARCHS(YES))
{
	struct timeval gtod_ts;

	uint64_t mach_time_before, mach_time, mach_time_after;

	mach_time_before = mach_absolute_time();

	T_ASSERT_POSIX_ZERO(__gettimeofday_with_mach(&gtod_ts, NULL, &mach_time), NULL);
	T_ASSERT_GT(gtod_ts.tv_sec, 0L, NULL);

	mach_time_after = mach_absolute_time();

	T_LOG("%llx > %llx > %llx", mach_time_before, mach_time, mach_time_after);

	T_ASSERT_LT(mach_time_before, mach_time, NULL);
	T_ASSERT_GT(mach_time_after, mach_time, NULL);
}
#endif // 0
