#include <darwintest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/kext/KextManager.h>
#include <mach/mach_time.h>
#include <sys/sysctl.h>
#include <copyfile.h>
#include <removefile.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.iokit"),
    T_META_RUN_CONCURRENTLY(true));

#define DEXT_NAME "com.apple.test_intentionally_crashing_driver_56101852.dext"
#define DEXT_PATH "/Library/DriverExtensions/" DEXT_NAME
#define SYSCTL_NAME "kern.driverkit_checkin_timed_out"
#define MAX_TIMEOUT_SECONDS 120

static int
copyfileCallback(int what __unused, int stage, copyfile_state_t state __unused, const char *src __unused, const char *dst, void *ctx __unused)
{
	if (stage == COPYFILE_FINISH) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(chown(dst, 0, 0), "chown %s to root / wheel", dst);
	}
	return COPYFILE_CONTINUE;
}

static void
cleanup(void)
{
	removefile_state_t state = removefile_state_alloc();
	removefile(DEXT_PATH, state, REMOVEFILE_RECURSIVE);
	removefile_state_free(state);
}

T_DECL(test_dext_launch_56101852,
    "Test launching a crashing dext",
    T_META_ASROOT(true), T_META_IGNORECRASHES("*test_intentionally_crashing_driver_56101852*"))
{
	T_SKIP("skipping test_dext_launch_56101852 due to 62657199");

	CFStringRef path = NULL;
	CFURLRef url = NULL;
	uint64_t startTime = mach_absolute_time();
	uint64_t endTime = 0;
	size_t endTimeSize = sizeof(uint64_t);
	uint64_t elapsedTimeAbs = 0;
	uint64_t elapsedTimeNs = 0;
	mach_timebase_info_data_t timebaseInfo;
	copyfile_state_t copyfileState;

	copyfileState = copyfile_state_alloc();
	copyfile_state_set(copyfileState, COPYFILE_STATE_STATUS_CB, (void *)&copyfileCallback);
	T_ASSERT_POSIX_SUCCESS(copyfile(DEXT_NAME, DEXT_PATH, copyfileState, COPYFILE_RECURSIVE | COPYFILE_ALL), "copied dext " DEXT_NAME " to " DEXT_PATH);
	T_ATEND(cleanup);

	/* set up timebaseInfo */
	T_ASSERT_MACH_SUCCESS(mach_timebase_info(&timebaseInfo), "set up mach_timebase_info");

	/* Set the initial value of kern.driverkit_checkin_timed_out to startTime */
	T_ASSERT_POSIX_SUCCESS(sysctlbyname(SYSCTL_NAME, NULL, NULL, &startTime, sizeof(startTime)), "set sysctl " SYSCTL_NAME " to %llu", startTime);


	/* Convert DEXT_PATH to a CFURL */
	path = CFSTR(DEXT_PATH);
	url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, path, kCFURLPOSIXPathStyle, true);
	T_ASSERT_NOTNULL(url, "created CFURL from CFString");

	/* Ask kextd to load the dext */
	T_ASSERT_EQ(KextManagerLoadKextWithURL(url, NULL), kOSReturnSuccess, "Loaded dext %s with kextd", DEXT_PATH);
	T_LOG("Will sleep for up to %d seconds", MAX_TIMEOUT_SECONDS);

	/* Wait for up to 120 seconds. Each loop iteration sleeps for 1 second and checks
	 * the value of the sysctl to check if it has changed. If the value changed, then
	 * the dext loaded earlier has crashed. If 120 seconds elapses and the value does
	 * not change, then the dext did not crash.
	 */
	for (int i = 0; i < MAX_TIMEOUT_SECONDS; i++) {
		sleep(1);
		T_ASSERT_POSIX_SUCCESS(sysctlbyname(SYSCTL_NAME, &endTime, &endTimeSize, NULL, 0), "using " SYSCTL_NAME " to check if dext has crashed");
		if (endTime != startTime) {
			T_LOG("Detected dext crash");
			break;
		}
		T_LOG("    Slept for %d seconds", i + 1);
	}

	T_LOG("startTime = %llu, endTime = %llu", startTime, endTime);

	T_ASSERT_GT(endTime, startTime, "dext has crashed");

	/* Check how much time has elapsed and see if it is less than 120 seconds. If it
	 * is 120 seconds or greater, then the dext did not check in to the kernel but we
	 * were not able to stop waiting for the dext to check in after it crashed.
	 */
	elapsedTimeAbs = endTime - startTime;
	elapsedTimeNs = elapsedTimeAbs * timebaseInfo.numer / timebaseInfo.denom;
	T_LOG("elapsedTimeAbs = %llu, elapsedTimeNs = %llu", elapsedTimeAbs, elapsedTimeNs);
	T_ASSERT_LT(elapsedTimeNs / NSEC_PER_SEC, (uint64_t)MAX_TIMEOUT_SECONDS, "elapsed time is less than %d seconds", MAX_TIMEOUT_SECONDS);

	copyfile_state_free(copyfileState);
	CFRelease(url);
}
