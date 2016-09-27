#include <CoreSymbolication/CoreSymbolication.h>
#include <darwintest.h>
#include <dispatch/dispatch.h>
#include <kperf/kperf.h>
#include <ktrace.h>
#include <pthread.h>

#include "kperf_helpers.h"

#define PERF_STK_KHDR  UINT32_C(0x25020014)
#define PERF_STK_UHDR  UINT32_C(0x25020018)
#define PERF_STK_KDATA UINT32_C(0x2502000c)
#define PERF_STK_UDATA UINT32_C(0x25020010)

static void
expect_frame(const char **bt, unsigned int bt_len, CSSymbolRef symbol,
    unsigned long addr, unsigned int bt_idx, unsigned int max_frames)
{
    const char *name;
    unsigned int frame_idx = max_frames - bt_idx - 1;

    if (!bt[frame_idx]) {
        T_LOG("frame %2u: skipping system frame", frame_idx);
        return;
    }

    if (CSIsNull(symbol)) {
        T_FAIL("invalid symbol for address %#lx at frame %d", addr, frame_idx);
        return;
    }

    if (frame_idx >= bt_len) {
        T_FAIL("unexpected frame '%s' (%#lx) at index %u",
            CSSymbolGetName(symbol), addr, frame_idx);
        return;
    }

    name = CSSymbolGetName(symbol);
    T_QUIET; T_ASSERT_NOTNULL(name, NULL);
    T_EXPECT_EQ_STR(name, bt[frame_idx],
        "frame %2u: saw '%s', expected '%s'",
        frame_idx, name, bt[frame_idx]);
}

/*
 * Expect to see user and kernel stacks with a known signature.
 */
static void
expect_backtrace(ktrace_session_t s, uint64_t tid, unsigned int *stacks_seen,
    bool kern, const char **bt, unsigned int bt_len)
{
    CSSymbolicatorRef symb;
    uint32_t hdr_debugid;
    uint32_t data_debugid;
    __block unsigned int stacks = 0;
    __block unsigned int frames = 0;
    __block unsigned int hdr_frames = 0;

    if (kern) {
        static CSSymbolicatorRef kern_symb;
        static dispatch_once_t kern_symb_once;

        hdr_debugid = PERF_STK_KHDR;
        data_debugid = PERF_STK_KDATA;

        dispatch_once(&kern_symb_once, ^(void) {
            kern_symb = CSSymbolicatorCreateWithMachKernel();
            T_QUIET; T_ASSERT_FALSE(CSIsNull(kern_symb), NULL);
        });
        symb = kern_symb;
    } else {
        static CSSymbolicatorRef user_symb;
        static dispatch_once_t user_symb_once;

        hdr_debugid = PERF_STK_UHDR;
        data_debugid = PERF_STK_UDATA;

        dispatch_once(&user_symb_once, ^(void) {
            user_symb = CSSymbolicatorCreateWithTask(mach_task_self());
            T_QUIET; T_ASSERT_FALSE(CSIsNull(user_symb), NULL);
            T_QUIET; T_ASSERT_TRUE(CSSymbolicatorIsTaskValid(user_symb), NULL);
        });
        symb = user_symb;
    }

    ktrace_events_single(s, hdr_debugid, ^(struct trace_point *tp) {
        if (tid != 0 && tid != tp->threadid) {
            return;
        }

        stacks++;
        if (!(tp->arg1 & 1)) {
            T_FAIL("invalid %s stack on thread %#lx", kern ? "kernel" : "user",
                tp->threadid);
            return;
        }

        hdr_frames = (unsigned int)tp->arg2;
        /* ignore extra link register or value pointed to by stack pointer */
        hdr_frames -= 1;

        T_QUIET; T_EXPECT_EQ(hdr_frames, bt_len,
            "number of frames in header");

        T_LOG("%s stack seen", kern ? "kernel" : "user");
        frames = 0;
    });

    ktrace_events_single(s, data_debugid, ^(struct trace_point *tp) {
        if (tid != 0 && tid != tp->threadid) {
            return;
        }

        for (int i = 0; i < 4 && frames < hdr_frames; i++, frames++) {
            unsigned long addr = (&tp->arg1)[i];
            CSSymbolRef symbol = CSSymbolicatorGetSymbolWithAddressAtTime(
                symb, addr, kCSNow);

            expect_frame(bt, bt_len, symbol, addr, frames, hdr_frames);
        }

        /* saw the end of the user stack */
        if (hdr_frames == frames) {
            *stacks_seen += 1;
            if (!kern) {
                ktrace_end(s, 1);
            }
        }
    });
}

#define TRIGGERING_DEBUGID (0xfeff0f00)

/*
 * These functions must return an int to avoid the function prologue being
 * hoisted out of the path to the spin (breaking being able to get a good
 * backtrace).
 */
static int __attribute__((noinline,not_tail_called))
recurse_a(bool spin, unsigned int frames);
static int __attribute__((noinline,not_tail_called))
recurse_b(bool spin, unsigned int frames);

static int __attribute__((noinline,not_tail_called))
recurse_a(bool spin, unsigned int frames)
{
    if (frames == 0) {
        if (spin) {
            for (;;);
        } else {
            kdebug_trace(TRIGGERING_DEBUGID, 0, 0, 0, 0);
            return 0;
        }
    }

    return recurse_b(spin, frames - 1) + 1;
}

static int __attribute__((noinline,not_tail_called))
recurse_b(bool spin, unsigned int frames)
{
    if (frames == 0) {
        if (spin) {
            for (;;);
        } else {
            kdebug_trace(TRIGGERING_DEBUGID, 0, 0, 0, 0);
            return 0;
        }
    }

    return recurse_a(spin, frames - 1) + 1;
}

#define USER_FRAMES       (12)

#if defined(__x86_64__)
#define RECURSE_START_OFFSET (4)
#else /* defined(__x86_64__) */
#define RECURSE_START_OFFSET (3)
#endif /* defined(__x86_64__) */

static const char *user_bt[USER_FRAMES] = {
#if defined(__x86_64__)
    NULL,
#endif /* defined(__x86_64__) */
    NULL, NULL,
    "backtrace_thread",
    "recurse_a", "recurse_b", "recurse_a", "recurse_b",
    "recurse_a", "recurse_b", "recurse_a",
#if !defined(__x86_64__)
    "recurse_b",
#endif /* !defined(__x86_64__) */
    NULL
};

#if   defined(__x86_64__)

#define KERNEL_FRAMES (2)
static const char *kernel_bt[KERNEL_FRAMES] = {
    "unix_syscall64", "kdebug_trace64"
};

#else
#error "architecture unsupported"
#endif /* defined(__arm__) */

static dispatch_once_t backtrace_start_once;
static dispatch_semaphore_t backtrace_start;

static void *
backtrace_thread(void *arg)
{
    bool spin;
    unsigned int calls;

    spin = (bool)arg;
    dispatch_semaphore_wait(backtrace_start, DISPATCH_TIME_FOREVER);

    /*
     * backtrace_thread, recurse_a, recurse_b, ...[, __kdebug_trace64]
     *
     * Always make one less call for this frame (backtrace_thread).
     */
    calls = USER_FRAMES - RECURSE_START_OFFSET - 1 /* backtrace_thread */;
    if (spin) {
        /*
         * Spinning doesn't end up calling __kdebug_trace64.
         */
        calls -= 1;
    }

    T_LOG("backtrace thread calling into %d frames (already at %d frames)",
        calls, RECURSE_START_OFFSET);
    (void)recurse_a(spin, calls);
    return NULL;
}

static uint64_t
create_backtrace_thread(bool spin)
{
    pthread_t thread;
    uint64_t tid;

    dispatch_once(&backtrace_start_once, ^(void) {
        backtrace_start = dispatch_semaphore_create(0);
    });

    T_QUIET; T_ASSERT_POSIX_ZERO(pthread_create(&thread, NULL, backtrace_thread,
        (void *)spin), NULL);
    T_QUIET; T_ASSERT_POSIX_ZERO(pthread_threadid_np(thread, &tid), NULL);

    return tid;
}

static void
start_backtrace_thread(void)
{
    T_QUIET; T_ASSERT_NOTNULL(backtrace_start,
        "thread to backtrace created before starting it");
    dispatch_semaphore_signal(backtrace_start);
}

#define TEST_TIMEOUT_NS (5 * NSEC_PER_SEC)

T_DECL(kdebug_trigger_backtraces,
    "test that backtraces from kdebug trigger are correct",
    T_META_ASROOT(YES))
{
    static unsigned int stacks_seen = 0;
    ktrace_session_t s;
    kperf_kdebug_filter_t filter;
    uint64_t tid;

    s = ktrace_session_create();
    T_ASSERT_NOTNULL(s, "ktrace session was created");

    T_ASSERT_POSIX_ZERO(ktrace_filter_pid(s, getpid()), NULL);

    tid = create_backtrace_thread(false);
    expect_backtrace(s, tid, &stacks_seen, false, user_bt, USER_FRAMES);
    expect_backtrace(s, tid, &stacks_seen, true, kernel_bt, KERNEL_FRAMES);

    /*
     * The triggering event must be traced (and thus registered with libktrace)
     * to get backtraces.
     */
    ktrace_events_single(s, TRIGGERING_DEBUGID,
        ^(__unused struct trace_point *tp){ });

    ktrace_set_completion_handler(s, ^(void) {
        T_EXPECT_GE(stacks_seen, 2U, "saw both kernel and user stacks");
        ktrace_session_destroy(s);
        kperf_reset();
        T_END;
    });

    filter = kperf_kdebug_filter_create();
    T_ASSERT_NOTNULL(filter, "kperf kdebug filter was created");

    T_QUIET; T_ASSERT_POSIX_SUCCESS(kperf_kdebug_filter_add_debugid(filter,
        TRIGGERING_DEBUGID), NULL);
    T_QUIET; T_ASSERT_POSIX_SUCCESS(kperf_kdebug_filter_set(filter), NULL);
    (void)kperf_action_count_set(1);
    T_QUIET; T_ASSERT_POSIX_SUCCESS(kperf_action_samplers_set(1,
        KPERF_SAMPLER_USTACK | KPERF_SAMPLER_KSTACK), NULL);
    T_QUIET; T_ASSERT_POSIX_SUCCESS(kperf_kdebug_action_set(1), NULL);
    kperf_kdebug_filter_destroy(filter);

    T_ASSERT_POSIX_SUCCESS(kperf_sample_set(1), NULL);

    T_ASSERT_POSIX_ZERO(ktrace_start(s, dispatch_get_main_queue()), NULL);

    start_backtrace_thread();

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, TEST_TIMEOUT_NS),
        dispatch_get_main_queue(), ^(void)
    {
        ktrace_end(s, 0);
    });

    dispatch_main();
}

T_DECL(user_backtraces_timer,
    "test that user backtraces on a timer are correct",
    T_META_ASROOT(YES))
{
    static unsigned int stacks_seen = 0;
    ktrace_session_t s;
    uint64_t tid;

    s = ktrace_session_create();
    T_QUIET; T_ASSERT_NOTNULL(s, "ktrace_session_create");

    ktrace_filter_pid(s, getpid());

    configure_kperf_stacks_timer(getpid(), 10);

    tid = create_backtrace_thread(true);
    /* not calling kdebug_trace(2) on the last frame */
    expect_backtrace(s, tid, &stacks_seen, false, user_bt, USER_FRAMES - 1);

    ktrace_set_completion_handler(s, ^(void) {
        T_EXPECT_GE(stacks_seen, 1U, "saw at least one stack");
        ktrace_session_destroy(s);
        kperf_reset();
        T_END;
    });

    T_QUIET; T_ASSERT_POSIX_SUCCESS(kperf_sample_set(1), NULL);

    T_ASSERT_POSIX_ZERO(ktrace_start(s, dispatch_get_main_queue()), NULL);

    start_backtrace_thread();

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, TEST_TIMEOUT_NS),
        dispatch_get_main_queue(), ^(void)
    {
        ktrace_end(s, 0);
    });

    dispatch_main();
}

/* TODO test kernel stacks in all modes */
/* TODO PET mode backtracing */
/* TODO test deep stacks, further than 128 frames, make sure they are truncated */
/* TODO test constrained stacks */
