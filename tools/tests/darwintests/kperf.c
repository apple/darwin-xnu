#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif /* defined(T_NAMESPACE) */

#include <darwintest.h>
#include <darwintest_utils.h>
#include <dispatch/dispatch.h>
#include <inttypes.h>
#include <ktrace/session.h>
#include <ktrace/private.h>
#include <System/sys/kdebug.h>
#include <kperf/kperf.h>
#include <kperfdata/kpdecode.h>
#include <os/assumes.h>
#include <stdint.h>
#include <sys/sysctl.h>

#include "kperf_helpers.h"

T_GLOBAL_META(
		T_META_NAMESPACE("xnu.kperf"),
		T_META_CHECK_LEAKS(false));

#define MAX_CPUS    64
#define MAX_THREADS 64

volatile static bool running_threads = true;

static void *
spinning_thread(void *semp)
{
	T_QUIET;
	T_ASSERT_NOTNULL(semp, "semaphore passed to thread should not be NULL");
	dispatch_semaphore_signal(*(dispatch_semaphore_t *)semp);

	while (running_threads);
	return NULL;
}

#define PERF_STK_KHDR  UINT32_C(0x25020014)
#define PERF_STK_UHDR  UINT32_C(0x25020018)
#define PERF_TMR_FIRE  KDBG_EVENTID(DBG_PERF, 3, 0)
#define PERF_TMR_HNDLR KDBG_EVENTID(DBG_PERF, 3, 2)
#define PERF_TMR_PEND  KDBG_EVENTID(DBG_PERF, 3, 3)
#define PERF_TMR_SKIP  KDBG_EVENTID(DBG_PERF, 3, 4)

#define SCHED_HANDOFF KDBG_EVENTID(DBG_MACH, DBG_MACH_SCHED, \
		MACH_STACK_HANDOFF)
#define SCHED_SWITCH  KDBG_EVENTID(DBG_MACH, DBG_MACH_SCHED, MACH_SCHED)
#define SCHED_IDLE    KDBG_EVENTID(DBG_MACH, DBG_MACH_SCHED, MACH_IDLE)

#define MP_CPUS_CALL UINT32_C(0x1900004)

#define DISPATCH_AFTER_EVENT UINT32_C(0xfefffffc)
#define TIMEOUT_SECS 10

#define TIMER_PERIOD_NS (1 * NSEC_PER_MSEC)

static void
reset_ktrace(void)
{
	kperf_reset();
}

/*
 * Ensure that kperf is correctly IPIing CPUs that are actively scheduling by
 * bringing up threads and ensuring that threads on-core are sampled by each
 * timer fire.
 */

T_DECL(ipi_active_cpus,
		"make sure that kperf IPIs all active CPUs",
		T_META_ASROOT(true))
{
	int ncpus = dt_ncpu();
	T_QUIET;
	T_ASSERT_LT(ncpus, MAX_CPUS,
			"only supports up to %d CPUs", MAX_CPUS);
	T_LOG("found %d CPUs", ncpus);

	int nthreads = ncpus - 1;
	T_QUIET;
	T_ASSERT_LT(nthreads, MAX_THREADS,
			"only supports up to %d threads", MAX_THREADS);

	static pthread_t threads[MAX_THREADS];

	/*
	 * TODO options to write this to a file and reinterpret a file...
	 */

	/*
	 * Create threads to bring up all of the CPUs.
	 */

	dispatch_semaphore_t thread_spinning = dispatch_semaphore_create(0);

	for (int i = 0; i < nthreads; i++) {
		T_QUIET;
		T_ASSERT_POSIX_ZERO(
				pthread_create(&threads[i], NULL, &spinning_thread,
				&thread_spinning), NULL);
		dispatch_semaphore_wait(thread_spinning, DISPATCH_TIME_FOREVER);
	}

	T_LOG("spun up %d thread%s", nthreads, nthreads == 1 ? "" : "s");

	ktrace_session_t s = ktrace_session_create();
	T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "ktrace_session_create");

	dispatch_queue_t q = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0);

	/*
	 * Only set the timeout after we've seen an event that was traced by us.
	 * This helps set a reasonable timeout after we're guaranteed to get a
	 * few events.
	 */

	ktrace_events_single(s, DISPATCH_AFTER_EVENT,
			^(__unused struct trace_point *tp)
	{
		dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
				TIMEOUT_SECS * NSEC_PER_SEC), q, ^{
			ktrace_end(s, 0);
		});
	});

	__block uint64_t nfires = 0;
	__block uint64_t nsamples = 0;
	static uint64_t idle_tids[MAX_CPUS] = { 0 };
	__block int nidles = 0;

	ktrace_set_completion_handler(s, ^{
		T_LOG("stopping threads");

		running_threads = false;

		for (int i = 0; i < nthreads; i++) {
			T_QUIET;
			T_ASSERT_POSIX_ZERO(pthread_join(threads[i], NULL), NULL);
		}

		for (int i = 0; i < nidles; i++) {
			T_LOG("CPU %d idle thread: %#" PRIx64, i, idle_tids[i]);
		}

		T_LOG("saw %" PRIu64 " timer fires, %" PRIu64 " samples, "
				"%g samples/fire", nfires, nsamples,
				(double)nsamples / (double)nfires);

		T_END;
	});

	/*
	 * Track which threads are running on each CPU.
	 */

	static uint64_t tids_on_cpu[MAX_CPUS] = { 0 };

	void (^switch_cb)(struct trace_point *) = ^(struct trace_point *tp) {
		uint64_t new_thread = tp->arg2;
		// uint64_t old_thread = tp->threadid;

		for (int i = 0; i < nidles; i++) {
			if (idle_tids[i] == new_thread) {
				return;
			}
		}

		tids_on_cpu[tp->cpuid] = new_thread;
	};

	ktrace_events_single(s, SCHED_SWITCH, switch_cb);
	ktrace_events_single(s, SCHED_HANDOFF, switch_cb);

	/*
	 * Determine the thread IDs of the idle threads on each CPU.
	 */

	ktrace_events_single(s, SCHED_IDLE, ^(struct trace_point *tp) {
		uint64_t idle_thread = tp->threadid;

		tids_on_cpu[tp->cpuid] = 0;

		for (int i = 0; i < nidles; i++) {
			if (idle_tids[i] == idle_thread) {
				return;
			}
		}

		idle_tids[nidles++] = idle_thread;
	});

	/*
	 * On each timer fire, go through all the cores and mark any threads
	 * that should be sampled.
	 */

	__block int last_fire_cpu = -1;
	__block uint64_t sample_missing = 0;
	static uint64_t tids_snap[MAX_CPUS] = { 0 };
	__block int nexpected = 0;
#if defined(__x86_64__)
	__block int xcall_from_cpu = -1;
#endif /* defined(__x86_64__) */
	__block uint64_t xcall_mask = 0;

	ktrace_events_single(s, PERF_TMR_FIRE, ^(struct trace_point *tp) {
		int last_expected = nexpected;
		nfires++;

		nexpected = 0;
		for (int i = 0; i < ncpus; i++) {
			uint64_t i_bit = UINT64_C(1) << i;
			if (sample_missing & i_bit) {
				T_LOG("missed sample on CPU %d for thread %#llx from timer on CPU %d (xcall mask = %llx, expected %d samples)",
						tp->cpuid, tids_snap[i], last_fire_cpu,
						xcall_mask, last_expected);
				sample_missing &= ~i_bit;
			}

			if (tids_on_cpu[i] != 0) {
				tids_snap[i] = tids_on_cpu[i];
				sample_missing |= i_bit;
				nexpected++;
			}
		}

		T_QUIET;
		T_ASSERT_LT((int)tp->cpuid, ncpus, "timer fire should not occur on an IOP");
		last_fire_cpu = (int)tp->cpuid;
#if defined(__x86_64__)
		xcall_from_cpu = (int)tp->cpuid;
#endif /* defined(__x86_64__) */
	});

#if defined(__x86_64__)
	/*
	 * Watch for the cross-call on Intel, make sure they match what kperf
	 * should be doing.
	 */

	ktrace_events_single(s, MP_CPUS_CALL, ^(struct trace_point *tp) {
		if (xcall_from_cpu != (int)tp->cpuid) {
			return;
		}

		xcall_mask = tp->arg1;
		xcall_from_cpu = -1;
	});
#endif /* defined(__x86_64__) */

	/*
	 * On the timer handler for each CPU, unset the missing sample bitmap.
	 */

	ktrace_events_single(s, PERF_TMR_HNDLR, ^(struct trace_point *tp) {
		nsamples++;
		if ((int)tp->cpuid > ncpus) {
			/* skip IOPs; they're not scheduling our threads */
			return;
		}

		sample_missing &= ~(UINT64_C(1) << tp->cpuid);
	});

	/*
	 * Configure kperf and ktrace.
	 */

	(void)kperf_action_count_set(1);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(kperf_action_samplers_set(1, KPERF_SAMPLER_KSTACK),
			NULL);
	(void)kperf_timer_count_set(1);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(kperf_timer_period_set(0,
			kperf_ns_to_ticks(TIMER_PERIOD_NS)), NULL);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(kperf_timer_action_set(0, 1), NULL);

	T_ASSERT_POSIX_SUCCESS(kperf_sample_set(1), "start kperf sampling");
	T_ATEND(reset_ktrace);

	T_ASSERT_POSIX_ZERO(ktrace_start(s,
			dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0)),
			"start ktrace");

	kdebug_trace(DISPATCH_AFTER_EVENT, 0, 0, 0, 0);

	dispatch_main();
}

#pragma mark kdebug triggers

#define KDEBUG_TRIGGER_TIMEOUT_NS (10 * NSEC_PER_SEC)

#define NON_TRIGGER_CLASS    UINT8_C(0xfd)
#define NON_TRIGGER_SUBCLASS UINT8_C(0xff)
#define NON_TRIGGER_CODE     UINT8_C(0xff)

#define NON_TRIGGER_EVENT \
		(KDBG_EVENTID(NON_TRIGGER_CLASS, NON_TRIGGER_SUBCLASS, \
		NON_TRIGGER_CODE))

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

T_DECL(kdebug_trigger_classes,
		"test that kdebug trigger samples on classes",
		T_META_ASROOT(true))
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
		T_META_ASROOT(true))
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

T_DECL(kdebug_trigger_debugids,
		"test that kdebug trigger samples on debugids",
		T_META_ASROOT(true))
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

T_DECL(kdbg_callstacks,
		"test that the kdbg_callstacks samples on syscalls",
		T_META_ASROOT(true))
{
	ktrace_session_t s;
	__block bool saw_user_stack = false;

	s = ktrace_session_create();
	T_ASSERT_NOTNULL(s, NULL);

	/*
	 * Make sure BSD events are traced in order to trigger samples on syscalls.
	 */
	ktrace_events_class(s, DBG_BSD, ^void(__unused struct trace_point *tp) {});

	ktrace_events_single(s, PERF_STK_UHDR, ^(__unused struct trace_point *tp) {
		saw_user_stack = true;
		ktrace_end(s, 1);
	});

	ktrace_set_completion_handler(s, ^{
		ktrace_session_destroy(s);

		T_EXPECT_TRUE(saw_user_stack,
				"saw user stack after configuring kdbg_callstacks");
		T_END;
	});

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	T_ASSERT_POSIX_SUCCESS(kperf_kdbg_callstacks_set(1), NULL);
#pragma clang diagnostic pop
	T_ATEND(kperf_reset);

	T_ASSERT_POSIX_ZERO(ktrace_start(s, dispatch_get_main_queue()), NULL);

	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC),
			dispatch_get_main_queue(), ^(void) {
		ktrace_end(s, 1);
	});

	dispatch_main();
}

#pragma mark PET

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
		T_META_ASROOT(true))
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
		T_META_ASROOT(true))
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
