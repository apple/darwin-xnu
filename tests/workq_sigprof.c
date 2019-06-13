#include <pthread.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <mach/mach_time.h>
#include <dispatch/dispatch.h>

#include <darwintest.h>

#if !TARGET_OS_IPHONE

static pthread_t workq_thread;
static bool signal_received;

static void signal_handler(int sig __unused, siginfo_t *b __unused, void* unused __unused) {
    if (pthread_self() == workq_thread) {
        signal_received = true;
    }
}

static void workq_block(void *unused __unused) {
    workq_thread = pthread_self();

    /*
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPROF);
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);
    */

    uint64_t spin_start = mach_absolute_time();
    while (mach_absolute_time() - spin_start < 30 * NSEC_PER_SEC)
        if (signal_received) {
            T_PASS("Got SIGPROF!");
            T_END;
        }
    }

T_DECL(workq_sigprof, "test that workqueue threads can receive sigprof")
{
    struct sigaction sa = {
        .sa_sigaction = signal_handler
    };
    sigfillset(&sa.sa_mask);
    T_ASSERT_POSIX_ZERO(sigaction(SIGPROF, &sa, NULL), NULL);

    dispatch_queue_t q = dispatch_get_global_queue(0, 0);
    dispatch_async_f(q, NULL, workq_block);

    struct itimerval timerval = {
        .it_interval = {.tv_usec = 10000},
        .it_value = {.tv_usec = 10000}
    };
    T_ASSERT_POSIX_ZERO(setitimer(ITIMER_PROF, &timerval, NULL), NULL);

    dispatch_main();
}

#else //!TARGET_OS_IPHONE

T_DECL(workq_sigprof, "test that workqueue threads can receive sigprof")
{
    T_EXPECTFAIL;
    T_FAIL("<rdar://problem/25864196> setitimer/sigprof doesn't seem to be delivered on embeded platforms");
}

#endif //!TARGET_OS_IPHONE
