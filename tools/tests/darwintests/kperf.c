#include <darwintest.h>
#include <dispatch/dispatch.h>
#include <inttypes.h>
#include <ktrace.h>
#include <ktrace_private.h>
#include <kperf/kperf.h>
#include <kperfdata/kpdecode.h>
#include <os/assumes.h>
#include <stdint.h>
#include <sys/sysctl.h>

#include "kperf_helpers.h"

#define PERF_STK_KHDR  UINT32_C(0x25020014)
#define PERF_STK_UHDR  UINT32_C(0x25020018)

/* KDEBUG TRIGGER */

#define KDEBUG_TRIGGER_TIMEOUT_NS (10 * NSEC_PER_SEC)

#define NON_TRIGGER_CLASS    UINT8_C(0xfd)
#define NON_TRIGGER_SUBCLASS UINT8_C(0xff)
#define NON_TRIGGER_CODE     UINT8_C(0xff)

#define NON_TRIGGER_EVENT \
    (KDBG_EVENTID(NON_TRIGGER_CLASS, NON_TRIGGER_SUBCLASS, NON_TRIGGER_CODE))

static void
expect_kdebug_trigger(const char *filter_desc, const uint32_t *debugids,
    unsigned int n_debugids)
{
    __block int missing_kernel_stacks = 0;
    __block int missing_user_stacks = 0;
    ktrace_session_t s;
    kperf_kdebug_filter_t filter;

    s = ktrace_session_create();
    T_QUIET; T_ASSERT_NOTNULL(s, NULL);

    ktrace_events_single(s, PERF_STK_KHDR, ^(struct trace_point *tp) {
        missing_kernel_stacks--;
        T_LOG("saw kernel stack with %lu frames, flags = %#lx", tp->arg2,
            tp->arg1);
    });
    ktrace_events_single(s, PERF_STK_UHDR, ^(struct trace_point *tp) {
        missing_user_stacks--;
        T_LOG("saw user stack with %lu frames, flags = %#lx", tp->arg2,
            tp->arg1);
    });

    for (unsigned int i = 0; i < n_debugids; i++) {
        ktrace_events_single(s, debugids[i], ^(struct trace_point *tp) {
            missing_kernel_stacks++;
            missing_user_stacks++;
            T_LOG("saw event with debugid 0x%" PRIx32, tp->debugid);
        });
    }

    ktrace_events_single(s, NON_TRIGGER_EVENT,
        ^(__unused struct trace_point *tp)
    {
        ktrace_end(s, 0);
    });

    ktrace_set_completion_handler(s, ^{
        T_EXPECT_LE(missing_kernel_stacks, 0, NULL);
        T_EXPECT_LE(missing_user_stacks, 0, NULL);

        ktrace_session_destroy(s);
        T_END;
    });

    /* configure kperf */

    kperf_reset();

    (void)kperf_action_count_set(1);
    T_ASSERT_POSIX_SUCCESS(kperf_action_samplers_set(1,
        KPERF_SAMPLER_KSTACK | KPERF_SAMPLER_USTACK), NULL);

    filter = kperf_kdebug_filter_create();
    T_ASSERT_NOTNULL(filter, NULL);

    T_ASSERT_POSIX_SUCCESS(kperf_kdebug_action_set(1), NULL);
    T_ASSERT_POSIX_SUCCESS(kperf_kdebug_filter_add_desc(filter, filter_desc),
        NULL);
    T_ASSERT_POSIX_SUCCESS(kperf_kdebug_filter_set(filter), NULL);
    kperf_kdebug_filter_destroy(filter);

    T_ASSERT_POSIX_SUCCESS(kperf_sample_set(1), NULL);

    T_ASSERT_POSIX_ZERO(ktrace_start(s, dispatch_get_main_queue()), NULL);

    /* trace the triggering debugids */

    for (unsigned int i = 0; i < n_debugids; i++) {
        T_ASSERT_POSIX_SUCCESS(kdebug_trace(debugids[i], 0, 0, 0, 0), NULL);
    }

    T_ASSERT_POSIX_SUCCESS(kdebug_trace(NON_TRIGGER_EVENT, 0, 0, 0, 0), NULL);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, KDEBUG_TRIGGER_TIMEOUT_NS),
        dispatch_get_main_queue(), ^(void)
    {
        ktrace_end(s, 1);
    });
}

#define TRIGGER_CLASS     UINT8_C(0xfe)
#define TRIGGER_CLASS_END UINT8_C(0xfd)
#define TRIGGER_SUBCLASS  UINT8_C(0xff)
#define TRIGGER_CODE      UINT8_C(0)
#define TRIGGER_DEBUGID \
    (KDBG_EVENTID(TRIGGER_CLASS, TRIGGER_SUBCLASS, TRIGGER_CODE))

T_DECL(kdebug_trigger_classes, "test that kdebug trigger samples on classes",
    T_META_ASROOT(YES))
{
    const uint32_t class_debugids[] = {
        KDBG_EVENTID(TRIGGER_CLASS, 1, 1),
        KDBG_EVENTID(TRIGGER_CLASS, 2, 1),
        KDBG_EVENTID(TRIGGER_CLASS_END, 1, 1) | DBG_FUNC_END,
        KDBG_EVENTID(TRIGGER_CLASS_END, 2, 1) | DBG_FUNC_END,
    };

    expect_kdebug_trigger("C0xfe,C0xfdr", class_debugids,
        sizeof(class_debugids) / sizeof(class_debugids[0]));
    dispatch_main();
}

T_DECL(kdebug_trigger_subclasses,
    "test that kdebug trigger samples on subclasses",
    T_META_ASROOT(YES))
{
    const uint32_t subclass_debugids[] = {
        KDBG_EVENTID(TRIGGER_CLASS, TRIGGER_SUBCLASS, 0),
        KDBG_EVENTID(TRIGGER_CLASS, TRIGGER_SUBCLASS, 1),
        KDBG_EVENTID(TRIGGER_CLASS_END, TRIGGER_SUBCLASS, 0) | DBG_FUNC_END,
        KDBG_EVENTID(TRIGGER_CLASS_END, TRIGGER_SUBCLASS, 1) | DBG_FUNC_END
    };

    expect_kdebug_trigger("S0xfeff,S0xfdffr", subclass_debugids,
        sizeof(subclass_debugids) / sizeof(subclass_debugids[0]));
    dispatch_main();
}

T_DECL(kdebug_trigger_debugids, "test that kdebug trigger samples on debugids",
    T_META_ASROOT(YES))
{
    const uint32_t debugids[] = {
        TRIGGER_DEBUGID
    };

    expect_kdebug_trigger("D0xfeff0000", debugids,
        sizeof(debugids) / sizeof(debugids[0]));
    dispatch_main();
}

/*
 * TODO Set a single function specifier filter, expect not to trigger of all
 * events from that class.
 */

T_DECL(kdbg_callstacks, "test that the kdbg_callstacks samples on syscalls",
    T_META_ASROOT(YES))
{
    ktrace_session_t s;
    __block bool saw_user_stack = false;

    s = ktrace_session_create();
    T_ASSERT_NOTNULL(s, NULL);

    /*
     * Make sure BSD events are traced in order to trigger samples on syscalls.
     */
    ktrace_events_class(s, DBG_BSD,
        ^void(__unused struct trace_point *tp) {});

    ktrace_events_single(s, PERF_STK_UHDR, ^(__unused struct trace_point *tp) {
        saw_user_stack = true;
        ktrace_end(s, 1);
    });

    ktrace_set_completion_handler(s, ^{
        ktrace_session_destroy(s);

        T_EXPECT_TRUE(saw_user_stack,
            "saw user stack after configuring kdbg_callstacks");

        /*
         * Ensure user stacks are not sampled after resetting kdbg_callstacks.
         */
        ktrace_session_t s_after = ktrace_session_create();
        T_ASSERT_NOTNULL(s_after, NULL);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        T_ASSERT_POSIX_SUCCESS(kperf_kdbg_callstacks_set(0), NULL);
#pragma clang diagnostic pop

        ktrace_events_class(s_after, DBG_BSD,
            ^void(__unused struct trace_point *tp) {});

        __block bool saw_extra_stack = false;

        ktrace_events_single(s_after, PERF_STK_UHDR,
            ^(__unused struct trace_point *tp)
        {
            saw_extra_stack = true;
            ktrace_end(s_after, 1);
        });

        ktrace_set_completion_handler(s_after, ^(void) {
            ktrace_session_destroy(s_after);
            T_EXPECT_FALSE(saw_extra_stack,
                "saw user stack after disabling kdbg_callstacks)");
            kperf_reset();
            T_END;
        });

        T_ASSERT_POSIX_ZERO(ktrace_start(s_after, dispatch_get_main_queue()),
            NULL);

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC),
            dispatch_get_main_queue(), ^(void)
        {
            ktrace_end(s_after, 1);
        });
    });

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    T_ASSERT_POSIX_SUCCESS(kperf_kdbg_callstacks_set(1), NULL);
#pragma clang diagnostic pop

    T_ASSERT_POSIX_ZERO(ktrace_start(s, dispatch_get_main_queue()), NULL);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC),
        dispatch_get_main_queue(), ^(void)
    {
        ktrace_end(s, 1);
    });

    dispatch_main();
}

/*
 * PET mode
 */

#define STACKS_WAIT_DURATION_NS (3 * NSEC_PER_SEC)

static void
expect_stacks_traced(void (^cb)(void))
{
    ktrace_session_t s;

    s = ktrace_session_create();
    T_QUIET; T_ASSERT_NOTNULL(s, "ktrace_session_create");

    __block unsigned int user_stacks = 0;
    __block unsigned int kernel_stacks = 0;

    ktrace_events_single(s, PERF_STK_UHDR, ^(__unused struct trace_point *tp) {
        user_stacks++;
    });
    ktrace_events_single(s, PERF_STK_KHDR, ^(__unused struct trace_point *tp) {
        kernel_stacks++;
    });

    ktrace_set_completion_handler(s, ^(void) {
        ktrace_session_destroy(s);
        T_EXPECT_GT(user_stacks, 0U, NULL);
        T_EXPECT_GT(kernel_stacks, 0U, NULL);
        cb();
    });

    T_QUIET; T_ASSERT_POSIX_SUCCESS(kperf_sample_set(1), NULL);

    T_ASSERT_POSIX_ZERO(ktrace_start(s, dispatch_get_main_queue()), NULL);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, STACKS_WAIT_DURATION_NS),
        dispatch_get_main_queue(), ^(void)
    {
        kperf_reset();
        ktrace_end(s, 0);
    });
}

T_DECL(pet, "test that PET mode samples kernel and user stacks",
    T_META_ASROOT(YES))
{
    configure_kperf_stacks_timer(-1, 10);
    T_ASSERT_POSIX_SUCCESS(kperf_timer_pet_set(0), NULL);

    expect_stacks_traced(^(void) {
        T_END;
    });

    dispatch_main();
}

T_DECL(lightweight_pet,
    "test that lightweight PET mode samples kernel and user stacks",
    T_META_ASROOT(YES))
{
    int set = 1;

    configure_kperf_stacks_timer(-1, 10);
    T_ASSERT_POSIX_SUCCESS(sysctlbyname("kperf.lightweight_pet", NULL, NULL,
        &set, sizeof(set)), NULL);
    T_ASSERT_POSIX_SUCCESS(kperf_timer_pet_set(0), NULL);

    expect_stacks_traced(^(void) {
        T_END;
    });

    dispatch_main();
}
