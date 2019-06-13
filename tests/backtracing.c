#include <CoreSymbolication/CoreSymbolication.h>
#include <darwintest.h>
#include <dispatch/dispatch.h>
#include <execinfo.h>
#include <pthread.h>
#include <sys/sysctl.h>

#define USER_FRAMES (12)

#define NON_RECURSE_FRAMES (5)

static const char *user_bt[USER_FRAMES] = {
    NULL, NULL,
    "backtrace_thread",
    "recurse_a", "recurse_b", "recurse_a", "recurse_b",
    "recurse_a", "recurse_b", "recurse_a",
    "expect_stack", NULL
};

static void
expect_frame(const char **bt, unsigned int bt_len, CSSymbolRef symbol,
    unsigned long addr, unsigned int bt_idx, unsigned int max_frames)
{
    const char *name;
    unsigned int frame_idx = max_frames - bt_idx - 1;

    if (bt[frame_idx] == NULL) {
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

static void __attribute__((noinline,not_tail_called))
expect_stack(void)
{
    uint64_t bt[USER_FRAMES] = { 0 };
    unsigned int bt_len = USER_FRAMES;
    int err;
    size_t bt_filled;

    static dispatch_once_t expect_stacks_once;
    static bool k64;
    static CSSymbolicatorRef user_symb;

    dispatch_once(&expect_stacks_once, ^(void) {
        int errb;
        int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 /* kernproc */ };

        struct kinfo_proc kp;
        size_t len;

        len = sizeof(kp);
        errb = sysctl(mib, sizeof(mib) / sizeof(mib[0]), &kp, &len, NULL, 0);
        T_QUIET; T_ASSERT_POSIX_SUCCESS(errb,
            "sysctl({ CTL_KERN, KERN_PROC, KERN_PROC_PID, 0})");

        k64 = kp.kp_proc.p_flag & P_LP64;
        T_LOG("executing with a %s-bit kernel", k64 ? "64" : "32");

        user_symb = CSSymbolicatorCreateWithTask(mach_task_self());
        T_QUIET; T_ASSERT_FALSE(CSIsNull(user_symb), NULL);
        T_QUIET; T_ASSERT_TRUE(CSSymbolicatorIsTaskValid(user_symb), NULL);
    });

    bt_filled = USER_FRAMES;
    err = sysctlbyname("kern.backtrace.user", bt, &bt_filled, NULL, 0);
    if (err == ENOENT) {
        T_SKIP("release kernel: kern.backtrace.user sysctl returned ENOENT");
    }
    T_ASSERT_POSIX_SUCCESS(err, "sysctlbyname(\"kern.backtrace.user\")");

    bt_len = (unsigned int)bt_filled;
    T_EXPECT_EQ(bt_len, (unsigned int)USER_FRAMES,
        "%u frames should be present in backtrace", (unsigned int)USER_FRAMES);

    for (unsigned int i = 0; i < bt_len; i++) {
        uintptr_t addr;
#if !defined(__LP64__)
        /*
         * Backtrace frames come out as kernel words; convert them back to user
         * uintptr_t for 32-bit processes.
         */
        if (k64) {
            addr = (uintptr_t)(bt[i]);
        } else {
            addr = (uintptr_t)(((uint32_t *)bt)[i]);
        }
#else /* defined(__LP32__) */
        addr = (uintptr_t)bt[i];
#endif /* defined(__LP32__) */

        CSSymbolRef symbol = CSSymbolicatorGetSymbolWithAddressAtTime(
            user_symb, addr, kCSNow);
        expect_frame(user_bt, USER_FRAMES, symbol, addr, i, bt_len);
    }
}

static int __attribute__((noinline,not_tail_called))
recurse_a(unsigned int frames);
static int __attribute__((noinline,not_tail_called))
recurse_b(unsigned int frames);

static int __attribute__((noinline,not_tail_called))
recurse_a(unsigned int frames)
{
    if (frames == 1) {
        expect_stack();
        getpid();
        return 0;
    }

    return recurse_b(frames - 1) + 1;
}

static int __attribute__((noinline,not_tail_called))
recurse_b(unsigned int frames)
{
    if (frames == 1) {
        expect_stack();
        getpid();
        return 0;
    }

    return recurse_a(frames - 1) + 1;
}

static void *
backtrace_thread(void *arg)
{
#pragma unused(arg)
    unsigned int calls;

    /*
     * backtrace_thread, recurse_a, recurse_b, ..., __sysctlbyname
     *
     * Always make one less call for this frame (backtrace_thread).
     */
    calls = USER_FRAMES - NON_RECURSE_FRAMES;

    T_LOG("backtrace thread calling into %d frames (already at %d frames)",
       calls, NON_RECURSE_FRAMES);
    (void)recurse_a(calls);
    return NULL;
}

T_DECL(backtrace_user, "test that the kernel can backtrace user stacks",
    T_META_CHECK_LEAKS(false), T_META_ALL_VALID_ARCHS(true))
{
    pthread_t thread;

    T_QUIET; T_ASSERT_POSIX_ZERO(pthread_create(&thread, NULL, backtrace_thread,
        NULL), "create additional thread to backtrace");

    T_QUIET; T_ASSERT_POSIX_ZERO(pthread_join(thread, NULL), NULL);
}
