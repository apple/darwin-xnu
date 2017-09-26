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

#define EXIT_FAIL() exit((__LINE__ % 255) + 1)

/*
 * This test expects the entitlement or root privileges for a process to
 * set the time using settimeofday syscall.
 */

#define DAY 86400 //1 day in sec

/*
 * To run without root privileges
 * <rdar://problem/28315048> libdarwintest should run leaks even without root
 */
static void drop_priv(void){
	/* determine the less-privileged UID and GID */

	unsigned long lower_uid = 0;
	unsigned long lower_gid = 0;

#if CONFIG_EMBEDDED
	struct passwd *pw = getpwnam("mobile");
	if (!pw) {
		printf("child: error: get_pwname(\"mobile\") failed %d: %s\n", errno, strerror(errno));
		EXIT_FAIL();
	}

	lower_uid = pw->pw_uid;
	lower_gid = pw->pw_gid;
#else
	char *sudo_gid_str = getenv("SUDO_GID");
	if (!sudo_gid_str) {
		printf("child: error: SUDO_GID environment variable unset (not run under sudo)\n");
		EXIT_FAIL();
	}

	char *sudo_uid_str = getenv("SUDO_UID");
	if (!sudo_uid_str) {
		printf("child: error: SUDO_UID environment variable unset (not run under sudo)\n");
		EXIT_FAIL();
	}

	char *end = sudo_gid_str;
	lower_gid = strtoul(sudo_gid_str, &end, 10);
	if (sudo_gid_str == end && sudo_gid_str[0] != '\0') {
		printf("child: error: SUDO_GID (%s) could not be converted to an integer\n", sudo_gid_str);
		EXIT_FAIL();
	}
	if (lower_gid == 0) {
		printf("child: error: less-privileged GID invalid\n");
		EXIT_FAIL();
	}

	end = sudo_uid_str;
	lower_uid = strtoul(sudo_uid_str, &end, 10);
	if (sudo_uid_str == end && sudo_uid_str[0] != '\0') {
		printf("child: error: SUDO_UID (%s) could not be converted to an integer\n", sudo_uid_str);
		EXIT_FAIL();
	}
	if (lower_gid == 0) {
		printf("child: error: less-privileged UID invalid\n");
		EXIT_FAIL();
	}
#endif

	if (setgid(lower_gid) == -1) {
		printf("child: error: could not change group to %lu\n", lower_gid);
		EXIT_FAIL();
	}
	if (setuid(lower_uid) == -1) {
		printf("child: error: could not change user to %lu\n", lower_uid);
		EXIT_FAIL();
	}
}

T_DECL(settime_32089962_entitled_root,
	"Verify that root privileges can allow to change the time",
	T_META_ASROOT(true), T_META_CHECK_LEAKS(NO))
{
	struct timeval settimeofdaytime;
	struct timeval adj_time;
	struct timex ntptime;

	if (geteuid() != 0){
                T_SKIP("settime_32089962_entitled_root test requires root privileges to run.");
        }

	/* test settimeofday */
	T_QUIET; T_ASSERT_POSIX_ZERO(gettimeofday(&settimeofdaytime, NULL), NULL);
	T_ASSERT_POSIX_ZERO(settimeofday(&settimeofdaytime, NULL), NULL);

	/* test adjtime */
	adj_time.tv_sec = 1;
	adj_time.tv_usec = 0;
	T_ASSERT_POSIX_ZERO(adjtime(&adj_time, NULL),NULL);

	/* test ntp_adjtime */
	memset(&ntptime, 0, sizeof(ntptime));
	ntptime.modes |= MOD_STATUS;
	ntptime.status = TIME_OK;

	T_ASSERT_EQ(ntp_adjtime(&ntptime), TIME_OK, NULL);
}

T_DECL(settime_32089962_entitled_not_root,
	"Verify that the \"com.apple.settime\" entitlement can allow to change the time",
	T_META_ASROOT(false), T_META_CHECK_LEAKS(NO))
{

	struct timeval settimeofdaytime;
	struct timeval adj_time;
	struct timex ntptime;

	drop_priv();

	if (geteuid() == 0){
                T_SKIP("settime_32089962_entitled_root test requires no root privileges to run.");
        }

	/* test settimeofday */
	T_QUIET; T_ASSERT_POSIX_ZERO(gettimeofday(&settimeofdaytime, NULL), NULL);
	T_ASSERT_POSIX_ZERO(settimeofday(&settimeofdaytime, NULL), NULL);

	/* test adjtime */
	adj_time.tv_sec = 1;
	adj_time.tv_usec = 0;
	T_ASSERT_POSIX_ZERO(adjtime(&adj_time, NULL),NULL);

	/* test ntp_adjtime */
	memset(&ntptime, 0, sizeof(ntptime));
	ntptime.modes |= MOD_STATUS;
	ntptime.status = TIME_OK;

	T_ASSERT_EQ(ntp_adjtime(&ntptime), TIME_OK, NULL);

}

T_DECL(settimeofday_29193041_entitled_root,
	"Verify that root privileges can allow to change the time",
	T_META_ASROOT(true), T_META_CHECK_LEAKS(NO))
{
	struct timeval time;
	long new_time;

	if (geteuid() != 0){
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
	T_QUIET;T_ASSERT_POSIX_ZERO(settimeofday(&time, NULL), NULL);
}

T_DECL(settimeofday_29193041_entitled_not_root,
	"Verify that the \"com.apple.settime\" entitlement can allow to change the time",
	T_META_ASROOT(false), T_META_CHECK_LEAKS(NO))
{
	struct timeval time;
	long new_time;

	drop_priv();

	if (geteuid() == 0){
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
