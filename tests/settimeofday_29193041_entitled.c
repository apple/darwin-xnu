#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <mach/clock_types.h>
#include <sys/timex.h>
#include <spawn.h>
#include <darwintest.h>
#include <darwintest_utils.h>

#if CONFIG_EMBEDDED
#include <sys/types.h>
#include <pwd.h>
#include <uuid/uuid.h>
#endif

/*
 * This test expects the entitlement or root privileges for a process to
 * set the time using settimeofday syscall.
 */

#define DAY 86400 //1 day in sec

T_DECL(settime_32089962_entitled_root,
    "Verify that root privileges can allow to change the time",
    T_META_ASROOT(true), T_META_CHECK_LEAKS(false))
{
	struct timeval settimeofdaytime;
	struct timeval adj_time;
	struct timex ntptime;

	if (geteuid() != 0) {
		T_SKIP("settime_32089962_entitled_root test requires root privileges to run.");
	}

	/* test settimeofday */
	T_QUIET; T_ASSERT_POSIX_ZERO(gettimeofday(&settimeofdaytime, NULL), NULL);
	T_ASSERT_POSIX_ZERO(settimeofday(&settimeofdaytime, NULL), NULL);

	/* test adjtime */
	adj_time.tv_sec = 1;
	adj_time.tv_usec = 0;
	T_ASSERT_POSIX_ZERO(adjtime(&adj_time, NULL), NULL);

	/* test ntp_adjtime */
	memset(&ntptime, 0, sizeof(ntptime));
	ntptime.modes |= MOD_STATUS;
	ntptime.status = TIME_OK;

	T_ASSERT_EQ(ntp_adjtime(&ntptime), TIME_OK, NULL);
}

T_DECL(settime_32089962_entitled_not_root,
    "Verify that the \"com.apple.settime\" entitlement can allow to change the time",
    T_META_ASROOT(false), T_META_CHECK_LEAKS(false))
{
	struct timeval settimeofdaytime;
	struct timeval adj_time;
	struct timex ntptime;

	if (geteuid() == 0) {
		T_SKIP("settime_32089962_entitled_root test requires no root privileges to run.");
	}

	/* test settimeofday */
	T_QUIET; T_ASSERT_POSIX_ZERO(gettimeofday(&settimeofdaytime, NULL), NULL);
	T_ASSERT_POSIX_ZERO(settimeofday(&settimeofdaytime, NULL), NULL);

	/* test adjtime */
	adj_time.tv_sec = 1;
	adj_time.tv_usec = 0;
	T_ASSERT_POSIX_ZERO(adjtime(&adj_time, NULL), NULL);

	/* test ntp_adjtime */
	memset(&ntptime, 0, sizeof(ntptime));
	ntptime.modes |= MOD_STATUS;
	ntptime.status = TIME_OK;

	T_ASSERT_EQ(ntp_adjtime(&ntptime), TIME_OK, NULL);
}

T_DECL(settimeofday_29193041_entitled_root,
    "Verify that root privileges can allow to change the time",
    T_META_ASROOT(true), T_META_CHECK_LEAKS(false))
{
	struct timeval time;
	long new_time;

	if (geteuid() != 0) {
		T_SKIP("settimeofday_root_29193041 test requires root privileges to run.");
	}

	T_QUIET; T_ASSERT_POSIX_ZERO(gettimeofday(&time, NULL), NULL);

	/* increment the time of one day */
	new_time = time.tv_sec + DAY;

	time.tv_sec = new_time;
	time.tv_usec = 0;

	T_ASSERT_POSIX_ZERO(settimeofday(&time, NULL), NULL);

	T_QUIET; T_ASSERT_POSIX_ZERO(gettimeofday(&time, NULL), NULL);

	/* expext to be past new_time */
	T_EXPECT_GE_LONG(time.tv_sec, new_time, "Time changed with root and entitlement");

	time.tv_sec -= DAY;
	T_QUIET; T_ASSERT_POSIX_ZERO(settimeofday(&time, NULL), NULL);
}

T_DECL(settimeofday_29193041_entitled_not_root,
    "Verify that the \"com.apple.settime\" entitlement can allow to change the time",
    T_META_ASROOT(false), T_META_CHECK_LEAKS(false))
{
	struct timeval time;
	long new_time;

	if (geteuid() == 0) {
		T_SKIP("settimeofday_29193041 test requires no root privileges to run.");
	}

	T_QUIET; T_ASSERT_POSIX_ZERO(gettimeofday(&time, NULL), NULL);

	/* increment the time of one day */
	new_time = time.tv_sec + DAY;

	time.tv_sec = new_time;
	time.tv_usec = 0;

	T_ASSERT_POSIX_ZERO(settimeofday(&time, NULL), NULL);

	T_QUIET; T_ASSERT_POSIX_ZERO(gettimeofday(&time, NULL), NULL);

	/* expext to be past new_time */
	T_EXPECT_GE_LONG(time.tv_sec, new_time, "Time successfully changed without root and with entitlement");

	time.tv_sec -= DAY;
	T_QUIET; T_ASSERT_POSIX_ZERO(settimeofday(&time, NULL), NULL);
}
