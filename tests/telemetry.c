#include <darwintest.h>
#include <dispatch/dispatch.h>
#include <ktrace/ktrace.h>
#include <kern/debug.h>
#include <sys/kdebug.h>
#include <TargetConditionals.h>

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

static void
telemetry_cleanup(void)
{
	int ret = __telemetry(TELEMETRY_CMD_PMI_SETUP, TELEMETRY_PMI_NONE, 0, 0, 0, 0);
	T_EXPECT_POSIX_SUCCESS(ret, "telemetry(... NONE ...)");
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
#if TARGET_OS_WATCH
	T_SKIP("unsupported platform");
#endif /* TARGET_OS_WATCH */

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
	__block int multi_records = 0;

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

		const uint8_t any_record = kPMIRecord | kIORecord | kInterruptRecord |
				kTimerArmingRecord;
		if ((start->arg1 & any_record) == 0) {
			unknown_records++;
		}
		if (__builtin_popcount(start->arg1 & any_record) != 1) {
			multi_records++;
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
		T_EXPECT_EQ(multi_records, 0, "saw zero multiple record events");
		T_EXPECT_GT(microstackshot_record_events, 0,
				"saw non-zero microstackshot record events (%g/sec)",
				microstackshot_record_events / (double)SLEEP_SECS);

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

	/*
	 * Start sampling via telemetry on the instructions PMI.
	 */
	int ret = __telemetry(TELEMETRY_CMD_PMI_SETUP, TELEMETRY_PMI_INSTRS,
			INSTRS_PERIOD, 0, 0, 0);
	if (ret < 0 && errno == EBUSY) {
		T_PASS("telemetry is busy/active, maybe the events will be seen");
	} else {
		T_ASSERT_POSIX_SUCCESS(ret,
				"telemetry syscall succeeded, started microstackshots");
		T_LOG("installing cleanup handler");
		T_ATEND(telemetry_cleanup);
	}

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
}
