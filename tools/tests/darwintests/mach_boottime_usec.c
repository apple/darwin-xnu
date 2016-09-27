#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/mach_time.h>

#include <darwintest.h>

T_DECL(mach_boottime_usec, "mach_boottime_usec()",
		T_META_ALL_VALID_ARCHS(YES))
{
	uint64_t bt_usec = mach_boottime_usec();

	struct timeval bt_tv;
	size_t len = sizeof(bt_tv);
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.boottime", &bt_tv, &len, NULL, 0), NULL);

	T_EXPECT_EQ((uint64_t)bt_tv.tv_sec * USEC_PER_SEC + (uint64_t)bt_tv.tv_usec, bt_usec, NULL);
}
