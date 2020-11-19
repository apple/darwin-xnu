/* Copyright (c) 2018 Apple Inc.  All rights reserved. */

#include <CoreFoundation/CoreFoundation.h>
#include <darwintest.h>
#include <dispatch/dispatch.h>
#include <ktrace/ktrace.h>
#include <kperf/kperf.h>
#include <kern/debug.h>
#include <notify.h>
#include <sys/kdebug.h>
#include <sys/sysctl.h>
#include <TargetConditionals.h>

#include "ktrace_helpers.h"

enum telemetry_pmi {
	TELEMETRY_PMI_NONE,
	TELEMETRY_PMI_INSTRS,
	TELEMETRY_PMI_CYCLES,
};
#define TELEMETRY_CMD_PMI_SETUP 3

T_GLOBAL_META(T_META_NAMESPACE("xnu.debugging.telemetry"),
    T_META_CHECK_LEAKS(false),
    T_META_ASROOT(true));

extern int __telemetry(uint64_t cmd, uint64_t deadline, uint64_t interval,
    uint64_t leeway, uint64_t arg4, uint64_t arg5);

/*
 * Microstackshots based on PMI are only supported on devices with monotonic
 * support.
 */

static void
skip_if_pmi_unsupported(void)
{
	int supported = 0;
	int ret = sysctlbyname("kern.monotonic.supported", &supported,
	    &(size_t){ sizeof(supported), }, NULL, 0);
	if (ret < 0) {
		T_SKIP("monotonic sysctl generated an error: %d (%s)", errno,
		    strerror(errno));
	}
	if (!supported) {
		T_SKIP("monotonic must be supported for microstackshots");
	}
}

/*
 * Data Analytics (da) also has a microstackshot configuration -- set a PMI
 * cycle interval of 0 to force it to disable microstackshot on PMI.
 */

static void
set_da_microstackshot_period(CFNumberRef num)
{
	CFPreferencesSetValue(CFSTR("microstackshotPMICycleInterval"), num,
	    CFSTR("com.apple.da"),
#if TARGET_OS_IPHONE
	    CFSTR("mobile"),
#else // TARGET_OS_IPHONE
	    CFSTR("root"),
#endif // !TARGET_OS_IPHONE
	    kCFPreferencesCurrentHost);

	notify_post("com.apple.da.tasking_changed");
}

static void
disable_da_microstackshots(void)
{
	int64_t zero = 0;
	CFNumberRef num = CFNumberCreate(NULL, kCFNumberSInt64Type, &zero);
	set_da_microstackshot_period(num);
	T_LOG("notified da of tasking change, sleeping");
#if TARGET_OS_WATCH
	sleep(8);
#else /* TARGET_OS_WATCH */
	sleep(3);
#endif /* !TARGET_OS_WATCH */
}

/*
 * Unset the preference to allow da to reset its configuration.
 */
static void
reenable_da_microstackshots(void)
{
	set_da_microstackshot_period(NULL);
}

/*
 * Clean up the test's configuration and allow da to activate again.
 */
static void
telemetry_cleanup(void)
{
	(void)__telemetry(TELEMETRY_CMD_PMI_SETUP, TELEMETRY_PMI_NONE, 0, 0, 0, 0);
	reenable_da_microstackshots();
}

/*
 * Make sure da hasn't configured the microstackshots -- otherwise the PMI
 * setup command will return EBUSY.
 */
static void
telemetry_init(void)
{
	disable_da_microstackshots();
	T_LOG("installing cleanup handler");
	T_ATEND(telemetry_cleanup);
}

volatile static bool spinning = true;

static void *
thread_spin(__unused void *arg)
{
	while (spinning) {
	}
	return NULL;
}

#define MT_MICROSTACKSHOT KDBG_EVENTID(DBG_MONOTONIC, 2, 1)
#define MS_RECORD MACHDBG_CODE(DBG_MACH_STACKSHOT, \
	        MICROSTACKSHOT_RECORD)
#if defined(__arm64__) || defined(__arm__)
#define INSTRS_PERIOD (100ULL * 1000 * 1000)
#else /* defined(__arm64__) || defined(__arm__) */
#define INSTRS_PERIOD (1ULL * 1000 * 1000 * 1000)
#endif /* !defined(__arm64__) && !defined(__arm__) */
#define SLEEP_SECS 10

T_DECL(microstackshot_pmi, "attempt to configure microstackshots on PMI")
{
	skip_if_pmi_unsupported();
	start_controlling_ktrace();

	T_SETUPBEGIN;
	ktrace_session_t s = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "session create");

	__block int pmi_events = 0;
	__block int microstackshot_record_events = 0;
	__block int pmi_records = 0;
	__block int io_records = 0;
	__block int interrupt_records = 0;
	__block int timer_arm_records = 0;
	__block int unknown_records = 0;
	__block int empty_records = 0;

	ktrace_events_single(s, MT_MICROSTACKSHOT, ^(__unused struct trace_point *tp) {
		pmi_events++;
	});
	ktrace_events_single_paired(s, MS_RECORD,
	    ^(struct trace_point *start, __unused struct trace_point *end) {
		if (start->arg1 & kPMIRecord) {
		        pmi_records++;
		}
		if (start->arg1 & kIORecord) {
		        io_records++;
		}
		if (start->arg1 & kInterruptRecord) {
		        interrupt_records++;
		}
		if (start->arg1 & kTimerArmingRecord) {
		        timer_arm_records++;
		}

		if (start->arg2 == end->arg2) {
			/*
			 * The buffer didn't grow for this record -- there was
			 * an error.
			 */
			empty_records++;
		}

		const uint8_t any_record = kPMIRecord | kIORecord | kInterruptRecord |
		kTimerArmingRecord;
		if ((start->arg1 & any_record) == 0) {
		        unknown_records++;
		}

		microstackshot_record_events++;
	});

	ktrace_set_completion_handler(s, ^{
		ktrace_session_destroy(s);
		T_EXPECT_GT(pmi_events, 0,
		"saw non-zero PMIs (%g/sec)", pmi_events / (double)SLEEP_SECS);
		T_EXPECT_GT(pmi_records, 0, "saw non-zero PMI record events (%g/sec)",
		pmi_records / (double)SLEEP_SECS);
		T_EXPECT_EQ(unknown_records, 0, "saw zero unknown record events");
		T_EXPECT_GT(microstackshot_record_events, 0,
		"saw non-zero microstackshot record events (%d -- %g/sec)",
		microstackshot_record_events,
		microstackshot_record_events / (double)SLEEP_SECS);
		T_EXPECT_NE(empty_records, microstackshot_record_events,
		"saw non-empty records (%d empty)", empty_records);

		if (interrupt_records > 0) {
		        T_LOG("saw %g interrupt records per second",
		        interrupt_records / (double)SLEEP_SECS);
		} else {
		        T_LOG("saw no interrupt records");
		}
		if (io_records > 0) {
		        T_LOG("saw %g I/O records per second",
		        io_records / (double)SLEEP_SECS);
		} else {
		        T_LOG("saw no I/O records");
		}
		if (timer_arm_records > 0) {
		        T_LOG("saw %g timer arming records per second",
		        timer_arm_records / (double)SLEEP_SECS);
		} else {
		        T_LOG("saw no timer arming records");
		}

		T_END;
	});

	T_SETUPEND;

	telemetry_init();

	/*
	 * Start sampling via telemetry on the instructions PMI.
	 */
	int ret = __telemetry(TELEMETRY_CMD_PMI_SETUP, TELEMETRY_PMI_INSTRS,
	    INSTRS_PERIOD, 0, 0, 0);
	T_ASSERT_POSIX_SUCCESS(ret,
	    "telemetry syscall succeeded, started microstackshots");

	pthread_t thread;
	int error = pthread_create(&thread, NULL, thread_spin, NULL);
	T_ASSERT_POSIX_ZERO(error, "started thread to spin");

	error = ktrace_start(s, dispatch_get_main_queue());
	T_ASSERT_POSIX_ZERO(error, "started tracing");

	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, SLEEP_SECS * NSEC_PER_SEC),
	    dispatch_get_main_queue(), ^{
		spinning = false;
		ktrace_end(s, 0);
		(void)pthread_join(thread, NULL);
		T_LOG("ending trace session after %d seconds", SLEEP_SECS);
	});

	dispatch_main();
}

T_DECL(error_handling,
    "ensure that error conditions for the telemetry syscall are observed")
{
	skip_if_pmi_unsupported();

	telemetry_init();

	int ret = __telemetry(TELEMETRY_CMD_PMI_SETUP, TELEMETRY_PMI_INSTRS,
	    1, 0, 0, 0);
	T_EXPECT_EQ(ret, -1, "telemetry shouldn't allow PMI every instruction");

	ret = __telemetry(TELEMETRY_CMD_PMI_SETUP, TELEMETRY_PMI_INSTRS,
	    1000 * 1000, 0, 0, 0);
	T_EXPECT_EQ(ret, -1,
	    "telemetry shouldn't allow PMI every million instructions");

	ret = __telemetry(TELEMETRY_CMD_PMI_SETUP, TELEMETRY_PMI_CYCLES,
	    1, 0, 0, 0);
	T_EXPECT_EQ(ret, -1, "telemetry shouldn't allow PMI every cycle");

	ret = __telemetry(TELEMETRY_CMD_PMI_SETUP, TELEMETRY_PMI_CYCLES,
	    1000 * 1000, 0, 0, 0);
	T_EXPECT_EQ(ret, -1,
	    "telemetry shouldn't allow PMI every million cycles");

	ret = __telemetry(TELEMETRY_CMD_PMI_SETUP, TELEMETRY_PMI_CYCLES,
	    UINT64_MAX, 0, 0, 0);
	T_EXPECT_EQ(ret, -1, "telemetry shouldn't allow PMI every UINT64_MAX cycles");

	ret = __telemetry(TELEMETRY_CMD_PMI_SETUP, TELEMETRY_PMI_CYCLES,
	    (1ULL << 55), 0, 0, 0);
	T_EXPECT_EQ(ret, -1, "telemetry shouldn't allow PMI with extremely long periods");
}
