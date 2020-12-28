#include <darwintest.h>
#include <darwintest_utils.h>
#include <dispatch/dispatch.h>
#include <inttypes.h>
#include <ktrace/session.h>
#include <ktrace/private.h>
#include <kperf/kperf.h>
#include <mach/clock_types.h>
#include <mach/dyld_kernel.h>
#include <mach/host_info.h>
#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/task.h>
#include <os/assumes.h>
#include <stdlib.h>
#include <sys/kdebug.h>
#include <sys/kdebug_signpost.h>
#include <sys/sysctl.h>
#include <stdint.h>

#include "ktrace_helpers.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ktrace"),
	T_META_ASROOT(true));

#define KDBG_TEST_MACROS         1
#define KDBG_TEST_OLD_TIMES      2
#define KDBG_TEST_FUTURE_TIMES   3
#define KDBG_TEST_IOP_SYNC_FLUSH 4

static void
assert_kdebug_test(unsigned int flavor)
{
	size_t size = flavor;
	int mib[] = { CTL_KERN, KERN_KDEBUG, KERN_KDTEST };
	T_ASSERT_POSIX_SUCCESS(sysctl(mib, sizeof(mib) / sizeof(mib[0]), NULL,
	    &size, NULL, 0), "KERN_KDTEST sysctl");
}

#pragma mark kdebug syscalls

#define TRACE_DEBUGID (0xfedfed00U)

T_DECL(kdebug_trace_syscall, "test that kdebug_trace(2) emits correct events")
{
	start_controlling_ktrace();

	ktrace_session_t s = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "created session");

	ktrace_events_class(s, DBG_MACH, ^(__unused struct trace_point *tp){});

	__block int events_seen = 0;
	ktrace_events_single(s, TRACE_DEBUGID, ^void (struct trace_point *tp) {
		events_seen++;
		T_PASS("saw traced event");

		if (ktrace_is_kernel_64_bit(s)) {
			T_EXPECT_EQ(tp->arg1, UINT64_C(0xfeedfacefeedface),
					"argument 1 of traced event is correct");
		} else {
			T_EXPECT_EQ(tp->arg1, UINT64_C(0xfeedface),
					"argument 1 of traced event is correct");
		}
		T_EXPECT_EQ(tp->arg2, 2ULL, "argument 2 of traced event is correct");
		T_EXPECT_EQ(tp->arg3, 3ULL, "argument 3 of traced event is correct");
		T_EXPECT_EQ(tp->arg4, 4ULL, "argument 4 of traced event is correct");

		ktrace_end(s, 1);
	});

	ktrace_set_completion_handler(s, ^{
		T_EXPECT_GE(events_seen, 1, NULL);
		ktrace_session_destroy(s);
		T_END;
	});

	ktrace_filter_pid(s, getpid());

	T_ASSERT_POSIX_ZERO(ktrace_start(s, dispatch_get_main_queue()), NULL);
	T_ASSERT_POSIX_SUCCESS(kdebug_trace(TRACE_DEBUGID, 0xfeedfacefeedface, 2,
			3, 4), NULL);
	ktrace_end(s, 0);

	dispatch_main();
}

#define SIGNPOST_SINGLE_CODE (0x10U)
#define SIGNPOST_PAIRED_CODE (0x20U)

T_DECL(kdebug_signpost_syscall,
    "test that kdebug_signpost(2) emits correct events")
{
	start_controlling_ktrace();

	ktrace_session_t s = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "created session");

	__block int single_seen = 0;
	__block int paired_seen = 0;

	/* make sure to get enough events for the KDBUFWAIT to trigger */
	// ktrace_events_class(s, DBG_MACH, ^(__unused struct trace_point *tp){});
	ktrace_events_single(s,
	    APPSDBG_CODE(DBG_APP_SIGNPOST, SIGNPOST_SINGLE_CODE),
	    ^(struct trace_point *tp) {
		single_seen++;
		T_PASS("single signpost is traced");

		T_EXPECT_EQ(tp->arg1, 1ULL, "argument 1 of single signpost is correct");
		T_EXPECT_EQ(tp->arg2, 2ULL, "argument 2 of single signpost is correct");
		T_EXPECT_EQ(tp->arg3, 3ULL, "argument 3 of single signpost is correct");
		T_EXPECT_EQ(tp->arg4, 4ULL, "argument 4 of single signpost is correct");
	});

	ktrace_events_single_paired(s,
	    APPSDBG_CODE(DBG_APP_SIGNPOST, SIGNPOST_PAIRED_CODE),
	    ^(struct trace_point *start, struct trace_point *end) {
		paired_seen++;
		T_PASS("paired signposts are traced");

		T_EXPECT_EQ(start->arg1, 5ULL, "argument 1 of start signpost is correct");
		T_EXPECT_EQ(start->arg2, 6ULL, "argument 2 of start signpost is correct");
		T_EXPECT_EQ(start->arg3, 7ULL, "argument 3 of start signpost is correct");
		T_EXPECT_EQ(start->arg4, 8ULL, "argument 4 of start signpost is correct");

		T_EXPECT_EQ(end->arg1, 9ULL, "argument 1 of end signpost is correct");
		T_EXPECT_EQ(end->arg2, 10ULL, "argument 2 of end signpost is correct");
		T_EXPECT_EQ(end->arg3, 11ULL, "argument 3 of end signpost is correct");
		T_EXPECT_EQ(end->arg4, 12ULL, "argument 4 of end signpost is correct");

		T_EXPECT_EQ(single_seen, 1, "signposts are traced in the correct order");

		ktrace_end(s, 1);
	});

	ktrace_set_completion_handler(s, ^(void) {
		T_QUIET; T_EXPECT_NE(single_seen, 0,
		"did not see single tracepoint before timeout");
		T_QUIET; T_EXPECT_NE(paired_seen, 0,
		"did not see single tracepoint before timeout");
		ktrace_session_destroy(s);
		T_END;
	});

	ktrace_filter_pid(s, getpid());

	T_ASSERT_POSIX_ZERO(ktrace_start(s, dispatch_get_main_queue()),
	    "started tracing");

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	T_EXPECT_POSIX_SUCCESS(kdebug_signpost(SIGNPOST_SINGLE_CODE, 1, 2, 3, 4),
	    "emitted single signpost");
	T_EXPECT_POSIX_SUCCESS(
		kdebug_signpost_start(SIGNPOST_PAIRED_CODE, 5, 6, 7, 8),
		"emitted start signpost");
	T_EXPECT_POSIX_SUCCESS(
		kdebug_signpost_end(SIGNPOST_PAIRED_CODE, 9, 10, 11, 12),
		"emitted end signpost");
#pragma clang diagnostic pop
	ktrace_end(s, 0);

	dispatch_main();
}

T_DECL(syscall_tracing,
		"ensure that syscall arguments are traced propertly")
{
	ktrace_session_t s = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "created session");

	__block bool seen = 0;

	ktrace_filter_pid(s, getpid());

	static const int telemetry_syscall_no = 451;
	static const uint64_t arg1 = 0xfeedfacefeedface;

	ktrace_events_single(s, BSDDBG_CODE(DBG_BSD_EXCP_SC, telemetry_syscall_no),
			^(struct trace_point *evt){
		if (KDBG_EXTRACT_CODE(evt->debugid) != telemetry_syscall_no || seen) {
			return;
		}

		seen = true;
		if (ktrace_is_kernel_64_bit(s)) {
			T_EXPECT_EQ(evt->arg1, arg1,
					"argument 1 of syscall event is correct");
		} else {
			T_EXPECT_EQ(evt->arg1, (uint64_t)(uint32_t)(arg1),
					"argument 1 of syscall event is correct");
		}

		ktrace_end(s, 1);
	});

	ktrace_set_completion_handler(s, ^{
		T_ASSERT_TRUE(seen,
				"should have seen a syscall event for kevent_id(2)");
		ktrace_session_destroy(s);
		T_END;
	});

	int error = ktrace_start(s, dispatch_get_main_queue());
	T_ASSERT_POSIX_ZERO(error, "started tracing");

	/*
	 * telemetry(2) has a 64-bit argument that will definitely be traced, and
	 * is unlikely to be used elsewhere by this process.
	 */
	extern int __telemetry(uint64_t cmd, uint64_t deadline, uint64_t interval,
			uint64_t leeway, uint64_t arg4, uint64_t arg5);
	(void)__telemetry(arg1, 0, 0, 0, 0, 0);

	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC),
			dispatch_get_main_queue(), ^{
		T_LOG("ending test due to timeout");
		ktrace_end(s, 0);
	});

	dispatch_main();
}

#pragma mark kdebug behaviors

#define WRAPPING_EVENTS_COUNT     (150000)
#define TRACE_ITERATIONS          (5000)
#define WRAPPING_EVENTS_THRESHOLD (100)

T_DECL(wrapping,
    "ensure that wrapping traces lost events and no events prior to the wrap",
    T_META_CHECK_LEAKS(false))
{
	kbufinfo_t buf_info;
	int wait_wrapping_secs = (WRAPPING_EVENTS_COUNT / TRACE_ITERATIONS) + 5;
	int current_secs = wait_wrapping_secs;

	start_controlling_ktrace();

	/* use sysctls manually to bypass libktrace assumptions */

	int mib[4] = { CTL_KERN, KERN_KDEBUG };
	mib[2] = KERN_KDSETBUF; mib[3] = WRAPPING_EVENTS_COUNT;
	T_ASSERT_POSIX_SUCCESS(sysctl(mib, 4, NULL, 0, NULL, 0), "KERN_KDSETBUF");

	mib[2] = KERN_KDSETUP; mib[3] = 0;
	size_t needed = 0;
	T_ASSERT_POSIX_SUCCESS(sysctl(mib, 3, NULL, &needed, NULL, 0),
	    "KERN_KDSETUP");

	mib[2] = KERN_KDENABLE; mib[3] = 1;
	T_ASSERT_POSIX_SUCCESS(sysctl(mib, 4, NULL, 0, NULL, 0), "KERN_KDENABLE");

	/* wrapping is on by default */

	/* wait until wrapped */
	T_LOG("waiting for trace to wrap");
	mib[2] = KERN_KDGETBUF;
	needed = sizeof(buf_info);
	do {
		sleep(1);
		for (int i = 0; i < TRACE_ITERATIONS; i++) {
			T_QUIET;
			T_ASSERT_POSIX_SUCCESS(kdebug_trace(0xfefe0000, 0, 0, 0, 0), NULL);
		}
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(sysctl(mib, 3, &buf_info, &needed, NULL, 0),
		    NULL);
	} while (!(buf_info.flags & KDBG_WRAPPED) && --current_secs > 0);

	T_ASSERT_TRUE(buf_info.flags & KDBG_WRAPPED,
	    "trace wrapped (after %d seconds within %d second timeout)",
	    wait_wrapping_secs - current_secs, wait_wrapping_secs);

	ktrace_session_t s = ktrace_session_create();
	T_QUIET; T_ASSERT_NOTNULL(s, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(ktrace_set_use_existing(s), NULL);

	__block int events = 0;

	ktrace_events_all(s, ^(struct trace_point *tp) {
		if (events == 0) {
		        T_EXPECT_EQ(tp->debugid, (unsigned int)TRACE_LOST_EVENTS,
		        "first event's debugid 0x%08x (%s) should be TRACE_LOST_EVENTS",
		        tp->debugid,
		        ktrace_name_for_eventid(s, tp->debugid & KDBG_EVENTID_MASK));
		} else {
		        T_QUIET;
		        T_EXPECT_NE(tp->debugid, (unsigned int)TRACE_LOST_EVENTS,
		        "event debugid 0x%08x (%s) should not be TRACE_LOST_EVENTS",
		        tp->debugid,
		        ktrace_name_for_eventid(s, tp->debugid & KDBG_EVENTID_MASK));
		}

		events++;
		if (events > WRAPPING_EVENTS_THRESHOLD) {
		        ktrace_end(s, 1);
		}
	});

	ktrace_set_completion_handler(s, ^{
		ktrace_session_destroy(s);
		T_END;
	});

	T_ASSERT_POSIX_ZERO(ktrace_start(s, dispatch_get_main_queue()),
	    "started tracing");

	dispatch_main();
}

T_DECL(reject_old_events,
    "ensure that kdebug rejects events from before tracing began",
    T_META_CHECK_LEAKS(false))
{
	__block uint64_t event_horizon_ts;

	start_controlling_ktrace();

	ktrace_session_t s = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "created session");

	__block int events = 0;
	ktrace_events_single(s, KDBG_EVENTID(DBG_BSD, DBG_BSD_KDEBUG_TEST, 1),
	    ^(struct trace_point *tp) {
		events++;
		T_EXPECT_GT(tp->timestamp, event_horizon_ts,
		"events in trace should be from after tracing began");
	});

	ktrace_set_completion_handler(s, ^{
		T_EXPECT_EQ(events, 2, "should see only two events");
		ktrace_session_destroy(s);
		T_END;
	});

	event_horizon_ts = mach_absolute_time();

	T_ASSERT_POSIX_ZERO(ktrace_start(s, dispatch_get_main_queue()), NULL);
	/* first, try an old event at the beginning of trace */
	assert_kdebug_test(KDBG_TEST_OLD_TIMES);
	/* after a good event has been traced, old events should be rejected */
	assert_kdebug_test(KDBG_TEST_OLD_TIMES);
	ktrace_end(s, 0);

	dispatch_main();
}

#define ORDERING_TIMEOUT_SEC 5

T_DECL(ascending_time_order,
    "ensure that kdebug events are in ascending order based on time",
    T_META_CHECK_LEAKS(false))
{
	__block uint64_t prev_ts = 0;
	__block uint32_t prev_debugid = 0;
	__block unsigned int prev_cpu = 0;
	__block bool in_order = true;

	start_controlling_ktrace();

	ktrace_session_t s = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "created session");

	ktrace_events_all(s, ^(struct trace_point *tp) {
		if (tp->timestamp < prev_ts) {
		        in_order = false;
		        T_LOG("%" PRIu64 ": %#" PRIx32 " (cpu %d)",
		        prev_ts, prev_debugid, prev_cpu);
		        T_LOG("%" PRIu64 ": %#" PRIx32 " (cpu %d)",
		        tp->timestamp, tp->debugid, tp->cpuid);
		        ktrace_end(s, 1);
		}
	});

	ktrace_set_completion_handler(s, ^{
		ktrace_session_destroy(s);
		T_EXPECT_TRUE(in_order, "event timestamps were in-order");
		T_END;
	});

	T_ASSERT_POSIX_ZERO(ktrace_start(s, dispatch_get_main_queue()),
	    "started tracing");

	/* try to inject old timestamps into trace */
	assert_kdebug_test(KDBG_TEST_OLD_TIMES);

	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, ORDERING_TIMEOUT_SEC * NSEC_PER_SEC),
	    dispatch_get_main_queue(), ^{
		T_LOG("ending test after timeout");
		ktrace_end(s, 1);
	});

	dispatch_main();
}

#pragma mark dyld tracing

__attribute__((aligned(8)))
static const char map_uuid[16] = "map UUID";

__attribute__((aligned(8)))
static const char unmap_uuid[16] = "unmap UUID";

__attribute__((aligned(8)))
static const char sc_uuid[16] = "shared UUID";

static fsid_t map_fsid = { .val = { 42, 43 } };
static fsid_t unmap_fsid = { .val = { 44, 45 } };
static fsid_t sc_fsid = { .val = { 46, 47 } };

static fsobj_id_t map_fsobjid = { .fid_objno = 42, .fid_generation = 43 };
static fsobj_id_t unmap_fsobjid = { .fid_objno = 44, .fid_generation = 45 };
static fsobj_id_t sc_fsobjid = { .fid_objno = 46, .fid_generation = 47 };

#define MAP_LOAD_ADDR   0xabadcafe
#define UNMAP_LOAD_ADDR 0xfeedface
#define SC_LOAD_ADDR    0xfedfaced

__unused
static void
expect_dyld_image_info(struct trace_point *tp, const uint64_t *exp_uuid,
    uint64_t exp_load_addr, fsid_t *exp_fsid, fsobj_id_t *exp_fsobjid,
    int order)
{
#if defined(__LP64__) || defined(__arm64__)
	if (order == 0) {
		uint64_t uuid[2];
		uint64_t load_addr;
		fsid_t fsid;

		uuid[0] = (uint64_t)tp->arg1;
		uuid[1] = (uint64_t)tp->arg2;
		load_addr = (uint64_t)tp->arg3;
		fsid.val[0] = (int32_t)(tp->arg4 & UINT32_MAX);
		fsid.val[1] = (int32_t)((uint64_t)tp->arg4 >> 32);

		T_QUIET; T_EXPECT_EQ(uuid[0], exp_uuid[0], NULL);
		T_QUIET; T_EXPECT_EQ(uuid[1], exp_uuid[1], NULL);
		T_QUIET; T_EXPECT_EQ(load_addr, exp_load_addr, NULL);
		T_QUIET; T_EXPECT_EQ(fsid.val[0], exp_fsid->val[0], NULL);
		T_QUIET; T_EXPECT_EQ(fsid.val[1], exp_fsid->val[1], NULL);
	} else if (order == 1) {
		fsobj_id_t fsobjid;

		fsobjid.fid_objno = (uint32_t)(tp->arg1 & UINT32_MAX);
		fsobjid.fid_generation = (uint32_t)((uint64_t)tp->arg1 >> 32);

		T_QUIET; T_EXPECT_EQ(fsobjid.fid_objno, exp_fsobjid->fid_objno, NULL);
		T_QUIET; T_EXPECT_EQ(fsobjid.fid_generation,
		    exp_fsobjid->fid_generation, NULL);
	} else {
		T_ASSERT_FAIL("unrecognized order of events %d", order);
	}
#else /* defined(__LP64__) */
	if (order == 0) {
		uint32_t uuid[4];

		uuid[0] = (uint32_t)tp->arg1;
		uuid[1] = (uint32_t)tp->arg2;
		uuid[2] = (uint32_t)tp->arg3;
		uuid[3] = (uint32_t)tp->arg4;

		T_QUIET; T_EXPECT_EQ(uuid[0], (uint32_t)exp_uuid[0], NULL);
		T_QUIET; T_EXPECT_EQ(uuid[1], (uint32_t)(exp_uuid[0] >> 32), NULL);
		T_QUIET; T_EXPECT_EQ(uuid[2], (uint32_t)exp_uuid[1], NULL);
		T_QUIET; T_EXPECT_EQ(uuid[3], (uint32_t)(exp_uuid[1] >> 32), NULL);
	} else if (order == 1) {
		uint32_t load_addr;
		fsid_t fsid;
		fsobj_id_t fsobjid;

		load_addr = (uint32_t)tp->arg1;
		fsid.val[0] = (int32_t)tp->arg2;
		fsid.val[1] = (int32_t)tp->arg3;
		fsobjid.fid_objno = (uint32_t)tp->arg4;

		T_QUIET; T_EXPECT_EQ(load_addr, (uint32_t)exp_load_addr, NULL);
		T_QUIET; T_EXPECT_EQ(fsid.val[0], exp_fsid->val[0], NULL);
		T_QUIET; T_EXPECT_EQ(fsid.val[1], exp_fsid->val[1], NULL);
		T_QUIET; T_EXPECT_EQ(fsobjid.fid_objno, exp_fsobjid->fid_objno, NULL);
	} else if (order == 2) {
		fsobj_id_t fsobjid;

		fsobjid.fid_generation = tp->arg1;

		T_QUIET; T_EXPECT_EQ(fsobjid.fid_generation,
		    exp_fsobjid->fid_generation, NULL);
	} else {
		T_ASSERT_FAIL("unrecognized order of events %d", order);
	}
#endif /* defined(__LP64__) */
}

#if defined(__LP64__) || defined(__arm64__)
#define DYLD_CODE_OFFSET (0)
#define DYLD_EVENTS      (2)
#else
#define DYLD_CODE_OFFSET (2)
#define DYLD_EVENTS      (3)
#endif

static void
expect_dyld_events(ktrace_session_t s, const char *name, uint32_t base_code,
    const char *exp_uuid, uint64_t exp_load_addr, fsid_t *exp_fsid,
    fsobj_id_t *exp_fsobjid, uint8_t *saw_events)
{
	for (int i = 0; i < DYLD_EVENTS; i++) {
		ktrace_events_single(s, KDBG_EVENTID(DBG_DYLD, DBG_DYLD_UUID,
		    base_code + DYLD_CODE_OFFSET + (unsigned int)i),
		    ^(struct trace_point *tp) {
			T_LOG("checking %s event %c", name, 'A' + i);
			expect_dyld_image_info(tp, (const void *)exp_uuid, exp_load_addr,
			exp_fsid, exp_fsobjid, i);
			*saw_events |= (1U << i);
		});
	}
}

T_DECL(dyld_events, "test that dyld registering libraries emits events")
{
	dyld_kernel_image_info_t info;

	/*
	 * Use pointers instead of __block variables in order to use these variables
	 * in the completion block below _and_ pass pointers to them to the
	 * expect_dyld_events function.
	 */
	uint8_t saw_events[3] = { 0 };
	uint8_t *saw_mapping = &(saw_events[0]);
	uint8_t *saw_unmapping = &(saw_events[1]);
	uint8_t *saw_shared_cache = &(saw_events[2]);

	start_controlling_ktrace();

	ktrace_session_t s = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "created session");

	T_QUIET;
	T_ASSERT_POSIX_ZERO(ktrace_filter_pid(s, getpid()),
	    "filtered to current process");

	expect_dyld_events(s, "mapping", DBG_DYLD_UUID_MAP_A, map_uuid,
	    MAP_LOAD_ADDR, &map_fsid, &map_fsobjid, saw_mapping);
	expect_dyld_events(s, "unmapping", DBG_DYLD_UUID_UNMAP_A, unmap_uuid,
	    UNMAP_LOAD_ADDR, &unmap_fsid, &unmap_fsobjid, saw_unmapping);
	expect_dyld_events(s, "shared cache", DBG_DYLD_UUID_SHARED_CACHE_A,
	    sc_uuid, SC_LOAD_ADDR, &sc_fsid, &sc_fsobjid, saw_shared_cache);

	ktrace_set_completion_handler(s, ^{
		ktrace_session_destroy(s);

		T_EXPECT_EQ(__builtin_popcount(*saw_mapping), DYLD_EVENTS, NULL);
		T_EXPECT_EQ(__builtin_popcount(*saw_unmapping), DYLD_EVENTS, NULL);
		T_EXPECT_EQ(__builtin_popcount(*saw_shared_cache), DYLD_EVENTS, NULL);
		T_END;
	});

	T_ASSERT_POSIX_ZERO(ktrace_start(s, dispatch_get_main_queue()), NULL);

	info.load_addr = MAP_LOAD_ADDR;
	memcpy(info.uuid, map_uuid, sizeof(info.uuid));
	info.fsid = map_fsid;
	info.fsobjid = map_fsobjid;
	T_EXPECT_MACH_SUCCESS(task_register_dyld_image_infos(mach_task_self(),
	    &info, 1), "registered dyld image info");

	info.load_addr = UNMAP_LOAD_ADDR;
	memcpy(info.uuid, unmap_uuid, sizeof(info.uuid));
	info.fsid = unmap_fsid;
	info.fsobjid = unmap_fsobjid;
	T_EXPECT_MACH_SUCCESS(task_unregister_dyld_image_infos(mach_task_self(),
	    &info, 1), "unregistered dyld image info");

	info.load_addr = SC_LOAD_ADDR;
	memcpy(info.uuid, sc_uuid, sizeof(info.uuid));
	info.fsid = sc_fsid;
	info.fsobjid = sc_fsobjid;
	T_EXPECT_MACH_SUCCESS(task_register_dyld_shared_cache_image_info(
		    mach_task_self(), info, FALSE, FALSE),
	    "registered dyld shared cache image info");

	ktrace_end(s, 0);

	dispatch_main();
}

#pragma mark kdebug kernel macros

#define EXP_KERNEL_EVENTS 5U

static const uint32_t dev_evts[EXP_KERNEL_EVENTS] = {
	BSDDBG_CODE(DBG_BSD_KDEBUG_TEST, 0),
	BSDDBG_CODE(DBG_BSD_KDEBUG_TEST, 1),
	BSDDBG_CODE(DBG_BSD_KDEBUG_TEST, 2),
	BSDDBG_CODE(DBG_BSD_KDEBUG_TEST, 3),
	BSDDBG_CODE(DBG_BSD_KDEBUG_TEST, 4),
};

static const uint32_t rel_evts[EXP_KERNEL_EVENTS] = {
	BSDDBG_CODE(DBG_BSD_KDEBUG_TEST, 5),
	BSDDBG_CODE(DBG_BSD_KDEBUG_TEST, 6),
	BSDDBG_CODE(DBG_BSD_KDEBUG_TEST, 7),
	BSDDBG_CODE(DBG_BSD_KDEBUG_TEST, 8),
	BSDDBG_CODE(DBG_BSD_KDEBUG_TEST, 9),
};

static const uint32_t filt_evts[EXP_KERNEL_EVENTS] = {
	BSDDBG_CODE(DBG_BSD_KDEBUG_TEST, 10),
	BSDDBG_CODE(DBG_BSD_KDEBUG_TEST, 11),
	BSDDBG_CODE(DBG_BSD_KDEBUG_TEST, 12),
	BSDDBG_CODE(DBG_BSD_KDEBUG_TEST, 13),
	BSDDBG_CODE(DBG_BSD_KDEBUG_TEST, 14),
};

static const uint32_t noprocfilt_evts[EXP_KERNEL_EVENTS] = {
	BSDDBG_CODE(DBG_BSD_KDEBUG_TEST, 15),
	BSDDBG_CODE(DBG_BSD_KDEBUG_TEST, 16),
	BSDDBG_CODE(DBG_BSD_KDEBUG_TEST, 17),
	BSDDBG_CODE(DBG_BSD_KDEBUG_TEST, 18),
	BSDDBG_CODE(DBG_BSD_KDEBUG_TEST, 19),
};

static bool
is_development_kernel(void)
{
	static dispatch_once_t is_development_once;
	static bool is_development;

	dispatch_once(&is_development_once, ^{
		int dev;
		size_t dev_size = sizeof(dev);

		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.development", &dev,
		&dev_size, NULL, 0), NULL);
		is_development = (dev != 0);
	});

	return is_development;
}

static void
expect_event(struct trace_point *tp, const char *name, unsigned int *events,
    const uint32_t *event_ids, size_t event_ids_len)
{
	unsigned int event_idx = *events;
	bool event_found = false;
	size_t i;
	for (i = 0; i < event_ids_len; i++) {
		if (event_ids[i] == (tp->debugid & KDBG_EVENTID_MASK)) {
			T_LOG("found %s event 0x%x", name, tp->debugid);
			event_found = true;
		}
	}

	if (!event_found) {
		return;
	}

	*events += 1;
	for (i = 0; i < event_idx; i++) {
		T_QUIET; T_EXPECT_EQ(((uint64_t *)&tp->arg1)[i], (uint64_t)i + 1,
		    NULL);
	}
	for (; i < 4; i++) {
		T_QUIET; T_EXPECT_EQ(((uint64_t *)&tp->arg1)[i], (uint64_t)0, NULL);
	}
}

static void
expect_release_event(struct trace_point *tp, unsigned int *events)
{
	expect_event(tp, "release", events, rel_evts,
	    sizeof(rel_evts) / sizeof(rel_evts[0]));
}

static void
expect_development_event(struct trace_point *tp, unsigned int *events)
{
	expect_event(tp, "dev", events, dev_evts, sizeof(dev_evts) / sizeof(dev_evts[0]));
}

static void
expect_filtered_event(struct trace_point *tp, unsigned int *events)
{
	expect_event(tp, "filtered", events, filt_evts,
	    sizeof(filt_evts) / sizeof(filt_evts[0]));
}

static void
expect_noprocfilt_event(struct trace_point *tp, unsigned int *events)
{
	expect_event(tp, "noprocfilt", events, noprocfilt_evts,
	    sizeof(noprocfilt_evts) / sizeof(noprocfilt_evts[0]));
}

static void
expect_kdbg_test_events(ktrace_session_t s, bool use_all_callback,
    void (^cb)(unsigned int dev_seen, unsigned int rel_seen,
    unsigned int filt_seen, unsigned int noprocfilt_seen))
{
	__block unsigned int dev_seen = 0;
	__block unsigned int rel_seen = 0;
	__block unsigned int filt_seen = 0;
	__block unsigned int noprocfilt_seen = 0;

	void (^evtcb)(struct trace_point *tp) = ^(struct trace_point *tp) {
		expect_development_event(tp, &dev_seen);
		expect_release_event(tp, &rel_seen);
		expect_filtered_event(tp, &filt_seen);
		expect_noprocfilt_event(tp, &noprocfilt_seen);
	};

	if (use_all_callback) {
		ktrace_events_all(s, evtcb);
	} else {
		ktrace_events_range(s, KDBG_EVENTID(DBG_BSD, DBG_BSD_KDEBUG_TEST, 0),
		    KDBG_EVENTID(DBG_BSD + 1, 0, 0), evtcb);
	}

	ktrace_set_completion_handler(s, ^{
		ktrace_session_destroy(s);
		cb(dev_seen, rel_seen, filt_seen, noprocfilt_seen);
		T_END;
	});

	T_ASSERT_POSIX_ZERO(ktrace_start(s, dispatch_get_main_queue()), NULL);
	assert_kdebug_test(KDBG_TEST_MACROS);

	ktrace_end(s, 0);
}

T_DECL(kernel_events, "ensure kernel macros work")
{
	start_controlling_ktrace();

	ktrace_session_t s = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "created session");

	T_QUIET; T_ASSERT_POSIX_ZERO(ktrace_filter_pid(s, getpid()),
	    "filtered events to current process");

	expect_kdbg_test_events(s, false,
	    ^(unsigned int dev_seen, unsigned int rel_seen,
	    unsigned int filt_seen, unsigned int noprocfilt_seen) {
		/*
		 * Development-only events are only filtered if running on an embedded
		 * OS.
		 */
		unsigned int dev_exp;
#if (TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR)
		dev_exp = is_development_kernel() ? EXP_KERNEL_EVENTS : 0U;
#else
		dev_exp = EXP_KERNEL_EVENTS;
#endif

		T_EXPECT_EQ(rel_seen, EXP_KERNEL_EVENTS,
		"release and development events seen");
		T_EXPECT_EQ(dev_seen, dev_exp, "development-only events %sseen",
		dev_exp ? "" : "not ");
		T_EXPECT_EQ(filt_seen, dev_exp, "filter-only events seen");
		T_EXPECT_EQ(noprocfilt_seen, EXP_KERNEL_EVENTS,
		"process filter-agnostic events seen");
	});

	dispatch_main();
}

T_DECL(kernel_events_filtered, "ensure that the filtered kernel macros work")
{
	start_controlling_ktrace();

	ktrace_session_t s = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "created session");

	T_QUIET; T_ASSERT_POSIX_ZERO(ktrace_filter_pid(s, getpid()),
	    "filtered events to current process");

	expect_kdbg_test_events(s, true,
	    ^(unsigned int dev_seen, unsigned int rel_seen,
	    unsigned int filt_seen, unsigned int noprocfilt_seen) {
		T_EXPECT_EQ(rel_seen, EXP_KERNEL_EVENTS, NULL);
#if defined(__arm__) || defined(__arm64__)
		T_EXPECT_EQ(dev_seen, is_development_kernel() ? EXP_KERNEL_EVENTS : 0U,
		NULL);
#else
		T_EXPECT_EQ(dev_seen, EXP_KERNEL_EVENTS,
		"development-only events seen");
#endif /* defined(__arm__) || defined(__arm64__) */
		T_EXPECT_EQ(filt_seen, 0U, "no filter-only events seen");
		T_EXPECT_EQ(noprocfilt_seen, EXP_KERNEL_EVENTS,
		"process filter-agnostic events seen");
	});

	dispatch_main();
}

T_DECL(kernel_events_noprocfilt,
    "ensure that the no process filter kernel macros work")
{
	start_controlling_ktrace();

	ktrace_session_t s = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "created session");

	/*
	 * Only allow launchd events through.
	 */
	T_ASSERT_POSIX_ZERO(ktrace_filter_pid(s, 1), "filtered events to launchd");
	for (size_t i = 0; i < sizeof(noprocfilt_evts) / sizeof(noprocfilt_evts[0]); i++) {
		T_QUIET;
		T_ASSERT_POSIX_ZERO(ktrace_ignore_process_filter_for_event(s,
		    noprocfilt_evts[i]),
		    "ignored process filter for noprocfilt event");
	}

	expect_kdbg_test_events(s, false,
	    ^(unsigned int dev_seen, unsigned int rel_seen,
	    unsigned int filt_seen, unsigned int noprocfilt_seen) {
		T_EXPECT_EQ(rel_seen, 0U, "release and development events not seen");
		T_EXPECT_EQ(dev_seen, 0U, "development-only events not seen");
		T_EXPECT_EQ(filt_seen, 0U, "filter-only events not seen");

		T_EXPECT_EQ(noprocfilt_seen, EXP_KERNEL_EVENTS,
		"process filter-agnostic events seen");
	});

	dispatch_main();
}

static volatile bool continue_abuse = true;

#define STRESS_DEBUGID (0xfeedfac0)
#define ABUSE_SECS (2)
#define TIMER_NS (100 * NSEC_PER_USEC)
/*
 * Use the quantum as the gap threshold.
 */
#define GAP_THRESHOLD_NS (10 * NSEC_PER_MSEC)

static void *
kdebug_abuser_thread(void *ctx)
{
	unsigned int id = (unsigned int)ctx;
	uint64_t i = 0;
	while (continue_abuse) {
		kdebug_trace(STRESS_DEBUGID, id, i, 0, 0);
		i++;
	}

	return NULL;
}

T_DECL(stress, "emit events on all but one CPU with a small buffer",
    T_META_CHECK_LEAKS(false))
{
	start_controlling_ktrace();

	T_SETUPBEGIN;
	ktrace_session_t s = ktrace_session_create();
	T_WITH_ERRNO; T_QUIET; T_ASSERT_NOTNULL(s, "ktrace_session_create");

	/* Let's not waste any time with pleasantries. */
	ktrace_set_uuid_map_enabled(s, KTRACE_FEATURE_DISABLED);

	/* Ouch. */
	ktrace_events_all(s, ^(__unused struct trace_point *tp) {});
	ktrace_set_vnode_paths_enabled(s, KTRACE_FEATURE_ENABLED);
	(void)atexit_b(^{ kperf_reset(); });
	(void)kperf_action_count_set(1);
	(void)kperf_timer_count_set(1);
	int kperror = kperf_timer_period_set(0, kperf_ns_to_ticks(TIMER_NS));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(kperror, "kperf_timer_period_set %llu ns",
	    TIMER_NS);
	kperror = kperf_timer_action_set(0, 1);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(kperror, "kperf_timer_action_set");
	kperror = kperf_action_samplers_set(1, KPERF_SAMPLER_TINFO |
	    KPERF_SAMPLER_TH_SNAPSHOT | KPERF_SAMPLER_KSTACK |
	    KPERF_SAMPLER_USTACK | KPERF_SAMPLER_MEMINFO |
	    KPERF_SAMPLER_TINFO_SCHED | KPERF_SAMPLER_TH_DISPATCH |
	    KPERF_SAMPLER_TK_SNAPSHOT | KPERF_SAMPLER_SYS_MEM |
	    KPERF_SAMPLER_TH_INSTRS_CYCLES);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(kperror, "kperf_action_samplers_set");
	/* You monster... */

	/* The coup-de-grace. */
	ktrace_set_buffer_size(s, 10);

	char filepath_arr[MAXPATHLEN] = "";
	strlcpy(filepath_arr, dt_tmpdir(), sizeof(filepath_arr));
	strlcat(filepath_arr, "/stress.ktrace", sizeof(filepath_arr));
	char *filepath = filepath_arr;

	int ncpus = 0;
	size_t ncpus_size = sizeof(ncpus);
	int ret = sysctlbyname("hw.logicalcpu_max", &ncpus, &ncpus_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname(\"hw.logicalcpu_max\"");
	T_QUIET; T_ASSERT_GT(ncpus, 0, "realistic number of CPUs");

	pthread_t *threads = calloc((unsigned int)ncpus - 1, sizeof(pthread_t));
	T_WITH_ERRNO; T_QUIET; T_ASSERT_NOTNULL(threads, "calloc(%d threads)",
	    ncpus - 1);

	ktrace_set_completion_handler(s, ^{
		T_SETUPBEGIN;
		ktrace_session_destroy(s);

		T_LOG("trace ended, searching for gaps");

		ktrace_session_t sread = ktrace_session_create();
		T_WITH_ERRNO; T_QUIET; T_ASSERT_NOTNULL(sread, "ktrace_session_create");

		int error = ktrace_set_file(sread, filepath);
		T_QUIET; T_ASSERT_POSIX_ZERO(error, "ktrace_set_file %s", filepath);

		ktrace_file_t f = ktrace_file_open(filepath, false);
		T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(f, "ktrace_file_open %s",
		filepath);
		uint64_t first_timestamp = 0;
		error = ktrace_file_earliest_timestamp(f, &first_timestamp);
		T_QUIET; T_ASSERT_POSIX_ZERO(error, "ktrace_file_earliest_timestamp");

		uint64_t last_timestamp = 0;
		(void)ktrace_file_latest_timestamp(f, &last_timestamp);

		__block uint64_t prev_timestamp = 0;
		__block uint64_t nevents = 0;
		ktrace_events_all(sread, ^(struct trace_point *tp) {
			nevents++;
			uint64_t delta_ns = 0;
			T_QUIET; T_EXPECT_GE(tp->timestamp, prev_timestamp,
			"timestamps are monotonically increasing");
			int converror = ktrace_convert_timestamp_to_nanoseconds(sread,
			tp->timestamp - prev_timestamp, &delta_ns);
			T_QUIET; T_ASSERT_POSIX_ZERO(converror, "convert timestamp to ns");
			if (prev_timestamp && delta_ns > GAP_THRESHOLD_NS) {
			        if (tp->debugname) {
			                T_LOG("gap: %gs at %llu - %llu on %d: %s (%#08x)",
			                (double)delta_ns / 1e9, prev_timestamp,
			                tp->timestamp, tp->cpuid, tp->debugname, tp->debugid);
				} else {
			                T_LOG("gap: %gs at %llu - %llu on %d: %#x",
			                (double)delta_ns / 1e9, prev_timestamp,
			                tp->timestamp, tp->cpuid, tp->debugid);
				}

			        /*
			         * These gaps are ok -- they appear after CPUs are brought back
			         * up.
			         */
#define INTERRUPT (0x1050000)
#define PERF_CPU_IDLE (0x27001000)
#define INTC_HANDLER (0x5000004)
#define DECR_TRAP (0x1090000)
			        uint32_t eventid = tp->debugid & KDBG_EVENTID_MASK;
			        if (eventid != INTERRUPT && eventid != PERF_CPU_IDLE &&
			        eventid != INTC_HANDLER && eventid != DECR_TRAP) {
			                unsigned int lost_events = TRACE_LOST_EVENTS;
			                T_QUIET; T_EXPECT_EQ(tp->debugid, lost_events,
			                "gaps should end with lost events");
				}
			}

			prev_timestamp = tp->timestamp;
		});
		ktrace_events_single(sread, TRACE_LOST_EVENTS, ^(struct trace_point *tp){
			T_LOG("lost: %llu on %d (%llu)", tp->timestamp, tp->cpuid, tp->arg1);
		});

		__block uint64_t last_write = 0;
		ktrace_events_single_paired(sread, TRACE_WRITING_EVENTS,
		^(struct trace_point *start, struct trace_point *end) {
			uint64_t delta_ns;
			int converror = ktrace_convert_timestamp_to_nanoseconds(sread,
			start->timestamp - last_write, &delta_ns);
			T_QUIET; T_ASSERT_POSIX_ZERO(converror, "convert timestamp to ns");

			uint64_t dur_ns;
			converror = ktrace_convert_timestamp_to_nanoseconds(sread,
			end->timestamp - start->timestamp, &dur_ns);
			T_QUIET; T_ASSERT_POSIX_ZERO(converror, "convert timestamp to ns");

			T_LOG("write: %llu (+%gs): %gus on %d: %llu events", start->timestamp,
			(double)delta_ns / 1e9, (double)dur_ns / 1e3, end->cpuid, end->arg1);
			last_write = end->timestamp;
		});
		ktrace_set_completion_handler(sread, ^{
			uint64_t duration_ns = 0;
			if (last_timestamp) {
			        int converror = ktrace_convert_timestamp_to_nanoseconds(sread,
			        last_timestamp - first_timestamp, &duration_ns);
			        T_QUIET; T_ASSERT_POSIX_ZERO(converror,
			        "convert timestamp to ns");
			        T_LOG("file was %gs long, %llu events: %g events/msec/cpu",
			        (double)duration_ns / 1e9, nevents,
			        (double)nevents / ((double)duration_ns / 1e6) / ncpus);
			}
			(void)unlink(filepath);
			ktrace_session_destroy(sread);
			T_END;
		});

		int starterror = ktrace_start(sread, dispatch_get_main_queue());
		T_QUIET; T_ASSERT_POSIX_ZERO(starterror, "ktrace_start read session");

		T_SETUPEND;
	});

/* Just kidding... for now. */
#if 0
	kperror = kperf_sample_set(1);
	T_ASSERT_POSIX_SUCCESS(kperror,
	    "started kperf timer sampling every %llu ns", TIMER_NS);
#endif

	for (int i = 0; i < (ncpus - 1); i++) {
		int error = pthread_create(&threads[i], NULL, kdebug_abuser_thread,
		    (void *)(uintptr_t)i);
		T_QUIET; T_ASSERT_POSIX_ZERO(error,
		    "pthread_create abuser thread %d", i);
	}

	int error = ktrace_start_writing_file(s, filepath,
	    ktrace_compression_none, NULL, NULL);
	T_ASSERT_POSIX_ZERO(error, "started writing ktrace to %s", filepath);

	T_SETUPEND;

	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, ABUSE_SECS * NSEC_PER_SEC),
	    dispatch_get_main_queue(), ^{
		T_LOG("ending trace");
		ktrace_end(s, 1);

		continue_abuse = false;
		for (int i = 0; i < (ncpus - 1); i++) {
		        int joinerror = pthread_join(threads[i], NULL);
		        T_QUIET; T_EXPECT_POSIX_ZERO(joinerror, "pthread_join thread %d",
		        i);
		}
	});

	dispatch_main();
}

#define ROUND_TRIP_PERIOD UINT64_C(10 * 1000)
#define ROUND_TRIPS_THRESHOLD UINT64_C(25)
#define ROUND_TRIPS_TIMEOUT_SECS (2 * 60)
#define COLLECTION_INTERVAL_MS 100

/*
 * Test a sustained tracing session, involving multiple round-trips to the
 * kernel.
 *
 * Trace all events, and every `ROUND_TRIP_PERIOD` events, emit an event that's
 * unlikely to be emitted elsewhere.  Look for this event, too, and make sure we
 * see as many of them as we emitted.
 *
 * After seeing `ROUND_TRIPS_THRESHOLD` of the unlikely events, end tracing.
 * In the failure mode, we won't see any of these, so set a timeout of
 * `ROUND_TRIPS_TIMEOUT_SECS` to prevent hanging, waiting for events that we'll
 * never see.
 */
T_DECL(round_trips,
    "test sustained tracing with multiple round-trips through the kernel")
{
	start_controlling_ktrace();

	ktrace_session_t s = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "created session");

	/*
	 * Set a small buffer and collection interval to increase the number of
	 * round-trips.
	 */
	ktrace_set_buffer_size(s, 50);
	ktrace_set_collection_interval(s, COLLECTION_INTERVAL_MS);

	__block uint64_t events = 0;
	__block uint64_t emitted = 0;
	__block uint64_t seen = 0;
	ktrace_events_all(s, ^(__unused struct trace_point *tp) {
		events++;
		if (events % ROUND_TRIP_PERIOD == 0) {
		        T_LOG("emitting round-trip event %" PRIu64, emitted);
		        kdebug_trace(TRACE_DEBUGID, events, 0, 0, 0);
		        emitted++;
		}
	});

	ktrace_events_single(s, TRACE_DEBUGID, ^(__unused struct trace_point *tp) {
		T_LOG("saw round-trip event after %" PRIu64 " events", events);
		seen++;
		if (seen >= ROUND_TRIPS_THRESHOLD) {
		        T_LOG("ending trace after seeing %" PRIu64 " events, "
		        "emitting %" PRIu64, seen, emitted);
		        ktrace_end(s, 1);
		}
	});

	ktrace_set_completion_handler(s, ^{
		T_EXPECT_GE(emitted, ROUND_TRIPS_THRESHOLD,
		"emitted %" PRIu64 " round-trip events", emitted);
		T_EXPECT_GE(seen, ROUND_TRIPS_THRESHOLD,
		"saw %" PRIu64 " round-trip events", seen);
		ktrace_session_destroy(s);
		T_END;
	});

	int error = ktrace_start(s, dispatch_get_main_queue());
	T_ASSERT_POSIX_ZERO(error, "started tracing");

	dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
	    ROUND_TRIPS_TIMEOUT_SECS * NSEC_PER_SEC), dispatch_get_main_queue(),
	    ^{
		T_LOG("ending trace after %d seconds", ROUND_TRIPS_TIMEOUT_SECS);
		ktrace_end(s, 0);
	});

	dispatch_main();
}

#define HEARTBEAT_INTERVAL_SECS 2
#define HEARTBEAT_COUNT 20

/*
 * Ensure we see events periodically, checking for recent events on a
 * heart-beat.
 */
T_DECL(event_coverage, "ensure events appear up to the end of tracing")
{
	start_controlling_ktrace();

	ktrace_session_t s = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "created session");

	__block uint64_t current_timestamp = 0;
	__block uint64_t events = 0;
	ktrace_events_all(s, ^(struct trace_point *tp) {
		current_timestamp = tp->timestamp;
		events++;
	});

	ktrace_set_buffer_size(s, 20);
	ktrace_set_collection_interval(s, COLLECTION_INTERVAL_MS);

	__block uint64_t last_timestamp = 0;
	__block uint64_t last_events = 0;
	__block unsigned int heartbeats = 0;

	ktrace_set_completion_handler(s, ^{
		ktrace_session_destroy(s);
		T_QUIET; T_EXPECT_GT(events, 0ULL, "should have seen some events");
		T_END;
	});

	dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,
	    0, 0, dispatch_get_main_queue());
	dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW,
	    HEARTBEAT_INTERVAL_SECS * NSEC_PER_SEC),
	    HEARTBEAT_INTERVAL_SECS * NSEC_PER_SEC, 0);
	dispatch_source_set_cancel_handler(timer, ^{
		dispatch_release(timer);
	});

	dispatch_source_set_event_handler(timer, ^{
		heartbeats++;

		T_LOG("heartbeat %u at time %lld, seen %" PRIu64 " events, "
		"current event time %lld", heartbeats, mach_absolute_time(),
		events, current_timestamp);

		if (current_timestamp > 0) {
		        T_EXPECT_GT(current_timestamp, last_timestamp,
		        "event timestamps should be increasing");
		        T_QUIET; T_EXPECT_GT(events, last_events,
		        "number of events should be increasing");
		}

		last_timestamp = current_timestamp;
		last_events = events;

		if (heartbeats >= HEARTBEAT_COUNT) {
		        T_LOG("ending trace after %u heartbeats", HEARTBEAT_COUNT);
		        ktrace_end(s, 0);
		}
	});

	int error = ktrace_start(s, dispatch_get_main_queue());
	T_ASSERT_POSIX_ZERO(error, "started tracing");

	dispatch_activate(timer);

	dispatch_main();
}

static unsigned int
set_nevents(unsigned int nevents)
{
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(sysctl(
		    (int[]){ CTL_KERN, KERN_KDEBUG, KERN_KDSETBUF, (int)nevents }, 4,
		    NULL, 0, NULL, 0), "set kdebug buffer size");

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(sysctl(
		    (int[]){ CTL_KERN, KERN_KDEBUG, KERN_KDSETUP, (int)nevents }, 4,
		    NULL, 0, NULL, 0), "setup kdebug buffers");

	kbufinfo_t bufinfo = { 0 };
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(sysctl(
		    (int[]){ CTL_KERN, KERN_KDEBUG, KERN_KDGETBUF }, 3,
		    &bufinfo, &(size_t){ sizeof(bufinfo) }, NULL, 0),
	    "get kdebug buffer size");

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(sysctl(
		    (int[]){ CTL_KERN, KERN_KDEBUG, KERN_KDREMOVE }, 3,
		    NULL, 0, NULL, 0),
	    "remove kdebug buffers");

	return (unsigned int)bufinfo.nkdbufs;
}

T_DECL(set_buffer_size, "ensure large buffer sizes can be set")
{
	start_controlling_ktrace();

	uint64_t memsize = 0;
	T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctlbyname("hw.memsize", &memsize,
	    &(size_t){ sizeof(memsize) }, NULL, 0), "get memory size");

	/*
	 * Try to allocate up to one-eighth of available memory towards
	 * tracing.
	 */
	uint64_t maxevents_u64 = memsize / 8 / sizeof(kd_buf);
	if (maxevents_u64 > UINT32_MAX) {
		maxevents_u64 = UINT32_MAX;
	}
	unsigned int maxevents = (unsigned int)maxevents_u64;

	unsigned int minevents = set_nevents(0);
	T_ASSERT_GT(minevents, 0, "saw non-zero minimum event count of %u",
	    minevents);

	unsigned int step = ((maxevents - minevents - 1) / 4);
	T_ASSERT_GT(step, 0, "stepping by %u events", step);

	for (unsigned int i = minevents + step; i < maxevents; i += step) {
		unsigned int actualevents = set_nevents(i);
		T_ASSERT_GE(actualevents, i - minevents,
		    "%u events in kernel when %u requested", actualevents, i);
	}
}

static void *
donothing(__unused void *arg)
{
	return NULL;
}

T_DECL(long_names, "ensure long command names are reported")
{
	start_controlling_ktrace();

	char longname[] = "thisisaverylongprocessname!";
	char *longname_ptr = longname;
	static_assert(sizeof(longname) > 16,
	    "the name should be longer than MAXCOMLEN");

	int ret = sysctlbyname("kern.procname", NULL, NULL, longname,
	    sizeof(longname));
	T_ASSERT_POSIX_SUCCESS(ret,
	    "use sysctl kern.procname to lengthen the name");

	ktrace_session_t ktsess = ktrace_session_create();

	/*
	 * 32-bit kernels can only trace 16 bytes of the string in their event
	 * arguments.
	 */
	if (!ktrace_is_kernel_64_bit(ktsess)) {
		longname[16] = '\0';
	}

	ktrace_filter_pid(ktsess, getpid());

	__block bool saw_newthread = false;
	ktrace_events_single(ktsess, TRACE_STRING_NEWTHREAD,
	    ^(struct trace_point *tp) {
		if (ktrace_get_pid_for_thread(ktsess, tp->threadid) ==
		    getpid()) {
			saw_newthread = true;

			char argname[32] = {};
			strncat(argname, (char *)&tp->arg1, sizeof(tp->arg1));
			strncat(argname, (char *)&tp->arg2, sizeof(tp->arg2));
			strncat(argname, (char *)&tp->arg3, sizeof(tp->arg3));
			strncat(argname, (char *)&tp->arg4, sizeof(tp->arg4));

			T_EXPECT_EQ_STR((char *)argname, longname_ptr,
			    "process name of new thread should be long");

			ktrace_end(ktsess, 1);
		}
	});

	ktrace_set_completion_handler(ktsess, ^{
		ktrace_session_destroy(ktsess);
		T_EXPECT_TRUE(saw_newthread,
		    "should have seen the new thread");
		T_END;
	});

	int error = ktrace_start(ktsess, dispatch_get_main_queue());
	T_ASSERT_POSIX_ZERO(error, "started tracing");

	pthread_t thread = NULL;
	error = pthread_create(&thread, NULL, donothing, NULL);
	T_ASSERT_POSIX_ZERO(error, "create new thread");

	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC),
	    dispatch_get_main_queue(), ^{
		ktrace_end(ktsess, 0);
	});

	error = pthread_join(thread, NULL);
	T_ASSERT_POSIX_ZERO(error, "join to thread");

	dispatch_main();
}

T_DECL(continuous_time, "make sure continuous time status can be queried",
	T_META_RUN_CONCURRENTLY(true))
{
	bool cont_time = kdebug_using_continuous_time();
	T_ASSERT_FALSE(cont_time, "should not be using continuous time yet");
}

static const uint32_t frame_eventid = KDBG_EVENTID(DBG_BSD,
    DBG_BSD_KDEBUG_TEST, 1);

static ktrace_session_t
future_events_session(void)
{
	ktrace_session_t ktsess = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(ktsess, "failed to create session");

	ktrace_events_single(ktsess, KDBG_EVENTID(DBG_BSD, DBG_BSD_KDEBUG_TEST, 0),
	    ^(struct trace_point *tp __unused) {
		T_FAIL("saw future test event from IOP");
	});
	ktrace_events_single(ktsess, frame_eventid, ^(struct trace_point *tp) {
		if (tp->debugid & DBG_FUNC_START) {
			T_LOG("saw start event");
		} else {
			T_LOG("saw event traced after trying to trace future event, ending");
			ktrace_end(ktsess, 1);
		}
	});

	ktrace_set_collection_interval(ktsess, 100);
	return ktsess;
}

T_DECL(future_iop_events,
    "make sure IOPs cannot trace events in the future while live tracing")
{
	start_controlling_ktrace();
	ktrace_session_t ktsess = future_events_session();
	ktrace_set_completion_handler(ktsess, ^{
		ktrace_session_destroy(ktsess);
		T_END;
	});

	T_ASSERT_POSIX_ZERO(ktrace_start(ktsess, dispatch_get_main_queue()),
	    "start tracing");
	kdebug_trace(frame_eventid | DBG_FUNC_START, 0, 0, 0, 0);
	assert_kdebug_test(KDBG_TEST_FUTURE_TIMES);
	kdebug_trace(frame_eventid | DBG_FUNC_END, 0, 0, 0, 0);

	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC),
	    dispatch_get_main_queue(), ^{
		T_FAIL("ending tracing after timeout");
		ktrace_end(ktsess, 0);
	});

	dispatch_main();
}

T_DECL(future_iop_events_disabled,
    "make sure IOPs cannot trace events in the future after disabling tracing")
{
	start_controlling_ktrace();
	ktrace_session_t ktsess = future_events_session();
	T_ASSERT_POSIX_ZERO(ktrace_configure(ktsess), "configure tracing");

	kdebug_trace(frame_eventid | DBG_FUNC_START, 0, 0, 0, 0);
	assert_kdebug_test(KDBG_TEST_FUTURE_TIMES);
	kdebug_trace(frame_eventid | DBG_FUNC_END, 0, 0, 0, 0);

	T_ASSERT_POSIX_ZERO(ktrace_disable_configured(ktsess),
	    "disable tracing");
	ktrace_session_destroy(ktsess);

	ktsess = future_events_session();
	T_QUIET;
	T_ASSERT_POSIX_ZERO(ktrace_set_use_existing(ktsess), "use existing trace");
	ktrace_set_completion_handler(ktsess, ^{
		ktrace_session_destroy(ktsess);
		T_END;
	});

	T_ASSERT_POSIX_ZERO(ktrace_start(ktsess, dispatch_get_main_queue()),
	    "start tracing existing session");

	dispatch_main();
}

T_DECL(iop_events_disable,
    "make sure IOP events are flushed before disabling trace")
{
	start_controlling_ktrace();
	ktrace_session_t ktsess = future_events_session();

	assert_kdebug_test(KDBG_TEST_IOP_SYNC_FLUSH);
	T_ASSERT_POSIX_ZERO(ktrace_configure(ktsess), "configure tracing");

	kdebug_trace(frame_eventid | DBG_FUNC_START, 0, 0, 0, 0);

	T_ASSERT_POSIX_ZERO(ktrace_disable_configured(ktsess),
	    "disable tracing");
	ktrace_session_destroy(ktsess);

	ktsess = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO;
	T_ASSERT_NOTNULL(ktsess, "create session");

	ktrace_events_single(ktsess,
	    KDBG_EVENTID(DBG_BSD, DBG_BSD_KDEBUG_TEST, 0xff),
	    ^(struct trace_point *tp __unused) {
		T_PASS("saw IOP event from sync flush");
	});

	T_QUIET;
	T_ASSERT_POSIX_ZERO(ktrace_set_use_existing(ktsess), "use existing trace");
	ktrace_set_completion_handler(ktsess, ^{
		ktrace_session_destroy(ktsess);
		T_END;
	});

	T_ASSERT_POSIX_ZERO(ktrace_start(ktsess, dispatch_get_main_queue()),
	    "start tracing existing session");

	dispatch_main();
}
