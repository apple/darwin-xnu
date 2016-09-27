#include <darwintest.h>
#include <dispatch/dispatch.h>
#include <inttypes.h>
#include <ktrace.h>
#include <ktrace_private.h>
#include <mach/dyld_kernel.h>
#include <mach/host_info.h>
#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/task.h>
#include <os/assumes.h>
#include <sys/kdebug.h>
#include <sys/kdebug_signpost.h>
#include <sys/sysctl.h>

#define KTRACE_WAIT_TIMEOUT_S (10)

#define TRACE_DEBUGID (0xfedfed00U)

T_DECL(kdebug_trace_syscall, "test that kdebug_trace(2) emits correct events",
       T_META_ASROOT(YES))
{
    ktrace_session_t s;
    dispatch_time_t timeout;
    __block int events_seen = 0;

    s = ktrace_session_create();
    os_assert(s != NULL);

    ktrace_events_class(s, DBG_MACH, ^(__unused struct trace_point *tp){});
    ktrace_events_single(s, TRACE_DEBUGID, ^void(struct trace_point *tp) {
        events_seen++;
        T_PASS("saw traced event");

        T_EXPECT_EQ(tp->arg1, 1UL, "argument 1 of traced event is correct");
        T_EXPECT_EQ(tp->arg2, 2UL, "argument 2 of traced event is correct");
        T_EXPECT_EQ(tp->arg3, 3UL, "argument 3 of traced event is correct");
        T_EXPECT_EQ(tp->arg4, 4UL, "argument 4 of traced event is correct");

        ktrace_end(s, 1);
    });

    ktrace_set_completion_handler(s, ^(void) {
        T_EXPECT_GE(events_seen, 1, NULL);
        ktrace_session_destroy(s);
        T_END;
    });

    ktrace_filter_pid(s, getpid());

    T_ASSERT_POSIX_ZERO(ktrace_start(s, dispatch_get_main_queue()), NULL);
    T_ASSERT_POSIX_SUCCESS(kdebug_trace(TRACE_DEBUGID, 1, 2, 3, 4), NULL);
    ktrace_end(s, 0);

    dispatch_main();
}

#define SIGNPOST_SINGLE_CODE  (0x10U)
#define SIGNPOST_PAIRED_CODE  (0x20U)

T_DECL(kdebug_signpost_syscall,
    "test that kdebug_signpost(2) emits correct events",
    T_META_ASROOT(YES))
{
    ktrace_session_t s;
    __block int single_seen = 0;
    __block int paired_seen = 0;
    dispatch_time_t timeout;

    s = ktrace_session_create();
    T_ASSERT_NOTNULL(s, NULL);

    /* make sure to get enough events for the KDBUFWAIT to trigger */
    // ktrace_events_class(s, DBG_MACH, ^(__unused struct trace_point *tp){});
    ktrace_events_single(s,
        APPSDBG_CODE(DBG_APP_SIGNPOST, SIGNPOST_SINGLE_CODE),
        ^void(struct trace_point *tp)
    {
        single_seen++;
        T_PASS("single signpost is traced");

        T_EXPECT_EQ(tp->arg1, 1UL, "argument 1 of single signpost is correct");
        T_EXPECT_EQ(tp->arg2, 2UL, "argument 2 of single signpost is correct");
        T_EXPECT_EQ(tp->arg3, 3UL, "argument 3 of single signpost is correct");
        T_EXPECT_EQ(tp->arg4, 4UL, "argument 4 of single signpost is correct");
    });

    ktrace_events_single_paired(s,
        APPSDBG_CODE(DBG_APP_SIGNPOST, SIGNPOST_PAIRED_CODE),
        ^void(struct trace_point *start, struct trace_point *end)
    {
        paired_seen++;
        T_PASS("paired signposts are traced");

        T_EXPECT_EQ(start->arg1, 5UL, "argument 1 of start signpost is correct");
        T_EXPECT_EQ(start->arg2, 6UL, "argument 2 of start signpost is correct");
        T_EXPECT_EQ(start->arg3, 7UL, "argument 3 of start signpost is correct");
        T_EXPECT_EQ(start->arg4, 8UL, "argument 4 of start signpost is correct");

        T_EXPECT_EQ(end->arg1, 9UL, "argument 1 of end signpost is correct");
        T_EXPECT_EQ(end->arg2, 10UL, "argument 2 of end signpost is correct");
        T_EXPECT_EQ(end->arg3, 11UL, "argument 3 of end signpost is correct");
        T_EXPECT_EQ(end->arg4, 12UL, "argument 4 of end signpost is correct");

        T_EXPECT_EQ(single_seen, 1,
            "signposts are traced in the correct order");

        ktrace_end(s, 1);
    });

    ktrace_set_completion_handler(s, ^(void) {
        if (single_seen == 0) {
            T_FAIL("did not see single tracepoint before timeout");
        }
        if (paired_seen == 0) {
            T_FAIL("did not see paired tracepoints before timeout");
        }
        ktrace_session_destroy(s);
        T_END;
    });

    ktrace_filter_pid(s, getpid());

    T_ASSERT_POSIX_ZERO(ktrace_start(s, dispatch_get_main_queue()), NULL);

    T_EXPECT_POSIX_SUCCESS(kdebug_signpost(
        SIGNPOST_SINGLE_CODE, 1, 2, 3, 4), NULL);
    T_EXPECT_POSIX_SUCCESS(kdebug_signpost_start(
        SIGNPOST_PAIRED_CODE, 5, 6, 7, 8), NULL);
    T_EXPECT_POSIX_SUCCESS(kdebug_signpost_end(
        SIGNPOST_PAIRED_CODE, 9, 10, 11, 12), NULL);
    ktrace_end(s, 0);

    dispatch_main();
}

#define WRAPPING_EVENTS_COUNT     (150000)
#define TRACE_ITERATIONS          (5000)
#define WRAPPING_EVENTS_THRESHOLD (100)

T_DECL(kdebug_wrapping,
    "ensure that wrapping traces lost events and no events prior to the wrap",
    T_META_ASROOT(YES), T_META_CHECK_LEAKS(NO))
{
    ktrace_session_t s;
    __block int events = 0;
    int mib[4];
    size_t needed;
    kbufinfo_t buf_info;
    int wait_wrapping_secs = (WRAPPING_EVENTS_COUNT / TRACE_ITERATIONS) + 5;
    int current_secs = wait_wrapping_secs;

    /* use sysctls manually to bypass libktrace assumptions */

    mib[0] = CTL_KERN; mib[1] = KERN_KDEBUG; mib[2] = KERN_KDSETUP; mib[3] = 0;
    needed = 0;
    T_ASSERT_POSIX_SUCCESS(sysctl(mib, 3, NULL, &needed, NULL, 0),
        "KERN_KDSETUP");

    mib[2] = KERN_KDSETBUF; mib[3] = WRAPPING_EVENTS_COUNT;
    T_ASSERT_POSIX_SUCCESS(sysctl(mib, 4, NULL, 0, NULL, 0), "KERN_KDSETBUF");

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

    s = ktrace_session_create();
    T_QUIET; T_ASSERT_NOTNULL(s, NULL);
    T_QUIET; T_ASSERT_POSIX_ZERO(ktrace_set_use_existing(s), NULL);

    ktrace_events_all(s, ^void(struct trace_point *tp) {
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

    ktrace_set_completion_handler(s, ^(void) {
        ktrace_session_destroy(s);
        T_END;
    });

    T_ASSERT_POSIX_ZERO(ktrace_start(s, dispatch_get_main_queue()), NULL);

    dispatch_main();
}

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
#if defined(__LP64__)
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

#if defined(__LP64__)
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
        ktrace_events_single(s,
            KDBG_EVENTID(DBG_DYLD, DBG_DYLD_UUID,
            base_code + DYLD_CODE_OFFSET + (unsigned int)i),
            ^(struct trace_point *tp)
        {
            T_LOG("checking %s event %c", name, 'A' + i);
            expect_dyld_image_info(tp, (const void *)exp_uuid, exp_load_addr,
                exp_fsid, exp_fsobjid, i);
            *saw_events |= (1U << i);
        });
    }
}

T_DECL(dyld_events, "test that dyld registering libraries emits events",
    T_META_ASROOT(YES))
{
    ktrace_session_t s;
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

    s = ktrace_session_create();
    T_ASSERT_NOTNULL(s, NULL);

    expect_dyld_events(s, "mapping", DBG_DYLD_UUID_MAP_A, map_uuid,
        MAP_LOAD_ADDR, &map_fsid, &map_fsobjid, saw_mapping);
    expect_dyld_events(s, "unmapping", DBG_DYLD_UUID_UNMAP_A, unmap_uuid,
        UNMAP_LOAD_ADDR, &unmap_fsid, &unmap_fsobjid, saw_unmapping);
    expect_dyld_events(s, "shared cache", DBG_DYLD_UUID_SHARED_CACHE_A,
        sc_uuid, SC_LOAD_ADDR, &sc_fsid, &sc_fsobjid, saw_shared_cache);

    ktrace_set_completion_handler(s, ^(void) {
        T_EXPECT_EQ(__builtin_popcount(*saw_mapping), DYLD_EVENTS, NULL);
        T_EXPECT_EQ(__builtin_popcount(*saw_unmapping), DYLD_EVENTS, NULL);
        T_EXPECT_EQ(__builtin_popcount(*saw_shared_cache), DYLD_EVENTS, NULL);
        ktrace_session_destroy(s);
        T_END;
    });

    T_ASSERT_POSIX_ZERO(ktrace_start(s, dispatch_get_main_queue()), NULL);

    info.load_addr = MAP_LOAD_ADDR;
    memcpy(info.uuid, map_uuid, sizeof(info.uuid));
    info.fsid = map_fsid;
    info.fsobjid = map_fsobjid;
    T_EXPECT_MACH_SUCCESS(task_register_dyld_image_infos(mach_task_self(),
        &info, 1), NULL);

    info.load_addr = UNMAP_LOAD_ADDR;
    memcpy(info.uuid, unmap_uuid, sizeof(info.uuid));
    info.fsid = unmap_fsid;
    info.fsobjid = unmap_fsobjid;
    T_EXPECT_MACH_SUCCESS(task_unregister_dyld_image_infos(mach_task_self(),
        &info, 1), NULL);

    info.load_addr = SC_LOAD_ADDR;
    memcpy(info.uuid, sc_uuid, sizeof(info.uuid));
    info.fsid = sc_fsid;
    info.fsobjid = sc_fsobjid;
    T_EXPECT_MACH_SUCCESS(task_register_dyld_shared_cache_image_info(
        mach_task_self(), info, FALSE, FALSE), NULL);

    ktrace_end(s, 0);

    dispatch_main();
}

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

static bool
is_development_kernel(void)
{
    static dispatch_once_t is_development_once;
    static bool is_development;

    dispatch_once(&is_development_once, ^(void) {
        host_debug_info_internal_data_t info;
        mach_msg_type_number_t count = HOST_DEBUG_INFO_INTERNAL_COUNT;
        kern_return_t kr;

        kr = host_info(mach_host_self(), HOST_DEBUG_INFO_INTERNAL,
            (host_info_t)(void *)&info, &count);
        if (kr != KERN_SUCCESS && kr != KERN_NOT_SUPPORTED) {
            T_ASSERT_FAIL("check for development kernel failed %d", kr);
        }

        is_development = (kr == KERN_SUCCESS);
    });

    return is_development;
}

static void
assert_kdebug_test(void)
{
    int mib[] = { CTL_KERN, KERN_KDEBUG, KERN_KDTEST };
    T_ASSERT_POSIX_SUCCESS(
        sysctl(mib, sizeof(mib) / sizeof(mib[0]), NULL, NULL, NULL, 0),
        "KERN_KDTEST");
}

static void
expect_event(struct trace_point *tp, unsigned int *events,
    const uint32_t *event_ids, size_t event_ids_len)
{
    unsigned int event_idx = *events;
    bool event_found = false;
    size_t i;
    for (i = 0; i < event_ids_len; i++) {
        if (event_ids[i] == (tp->debugid & KDBG_EVENTID_MASK)) {
            T_LOG("found event 0x%x", tp->debugid);
            event_found = true;
        }
    }

    if (!event_found) {
        return;
    }

    *events += 1;
    for (i = 0; i < event_idx; i++) {
        T_QUIET; T_EXPECT_EQ(((uintptr_t *)&tp->arg1)[i], (uintptr_t)i + 1,
            NULL);
    }
    for (; i < 4; i++) {
        T_QUIET; T_EXPECT_EQ(((uintptr_t *)&tp->arg1)[i], (uintptr_t)0, NULL);
    }
}

static void
expect_release_event(struct trace_point *tp, unsigned int *events)
{
    expect_event(tp, events, rel_evts,
        sizeof(rel_evts) / sizeof(rel_evts[0]));
}

static void
expect_development_event(struct trace_point *tp, unsigned int *events)
{
    expect_event(tp, events, dev_evts,
        sizeof(dev_evts) / sizeof(dev_evts[0]));
}

static void
expect_filtered_event(struct trace_point *tp, unsigned int *events)
{
    expect_event(tp, events, filt_evts,
        sizeof(filt_evts) / sizeof(filt_evts[0]));
}

T_DECL(kernel_events, "ensure kernel macros work",
    T_META_ASROOT(YES))
{
    ktrace_session_t s;

    s = ktrace_session_create();
    T_QUIET; T_ASSERT_NOTNULL(s, NULL);

    __block unsigned int dev_seen = 0;
    __block unsigned int rel_seen = 0;
    __block unsigned int filt_seen = 0;
    ktrace_events_range(s, KDBG_EVENTID(DBG_BSD, DBG_BSD_KDEBUG_TEST, 0),
        KDBG_EVENTID(DBG_BSD + 1, 0, 0),
        ^(struct trace_point *tp)
    {
        expect_development_event(tp, &dev_seen);
        expect_release_event(tp, &rel_seen);
        expect_filtered_event(tp, &filt_seen);
    });

    ktrace_set_completion_handler(s, ^(void) {
        T_EXPECT_EQ(rel_seen, EXP_KERNEL_EVENTS, NULL);
        T_EXPECT_EQ(dev_seen, is_development_kernel() ? EXP_KERNEL_EVENTS : 0U,
            NULL);
        T_EXPECT_EQ(filt_seen, EXP_KERNEL_EVENTS, NULL);
        ktrace_session_destroy(s);
        T_END;
    });

    ktrace_filter_pid(s, getpid());

    T_ASSERT_POSIX_ZERO(ktrace_start(s, dispatch_get_main_queue()), NULL);
    assert_kdebug_test();

    ktrace_end(s, 0);

    dispatch_main();
}

T_DECL(kernel_events_filtered, "ensure that the filtered kernel macros work",
    T_META_ASROOT(YES))
{
    ktrace_session_t s;

    s = ktrace_session_create();
    T_QUIET; T_ASSERT_NOTNULL(s, NULL);

    __block unsigned int dev_seen = 0;
    __block unsigned int rel_seen = 0;
    __block unsigned int filt_seen = 0;
    ktrace_events_all(s, ^(struct trace_point *tp) {
        expect_development_event(tp, &dev_seen);
        expect_release_event(tp, &rel_seen);
        /* to make sure no filtered events are emitted */
        expect_filtered_event(tp, &filt_seen);
    });

    ktrace_set_completion_handler(s, ^(void) {
        ktrace_session_destroy(s);

        T_EXPECT_EQ(rel_seen, EXP_KERNEL_EVENTS, NULL);
        T_EXPECT_EQ(dev_seen, EXP_KERNEL_EVENTS, NULL);
        T_EXPECT_EQ(filt_seen, 0U, NULL);
        T_END;
    });

    T_ASSERT_POSIX_ZERO(ktrace_start(s, dispatch_get_main_queue()), NULL);
    assert_kdebug_test();

    ktrace_end(s, 0);

    dispatch_main();
}

