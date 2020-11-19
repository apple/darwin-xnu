// Copyright (c) 2017-2020 Apple Computer, Inc. All rights reserved.

#include <darwintest.h>
#include <darwintest_utils.h>
#include <dispatch/dispatch.h>
#include <inttypes.h>
#include <ktrace/session.h>
#include <ktrace/private.h>
#include <sys/kdebug.h>
#include <sys/syscall.h>
#include <kperf/kpc.h>
#include <kperf/kperf.h>
#include <kperfdata/kpdecode.h>
#include <os/assumes.h>
#include <stdint.h>
#include <sys/sysctl.h>

#include "kperf_helpers.h"
#include "ktrace_helpers.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ktrace"),
	T_META_CHECK_LEAKS(false),
	T_META_ASROOT(true));

#define MAX_CPUS    64
#define MAX_THREADS 64

volatile static bool running_threads = true;

static void *
spinning_thread(void *semp)
{
	T_QUIET;
	T_ASSERT_NOTNULL(semp, "semaphore passed to thread should not be NULL");
	dispatch_semaphore_signal(*(dispatch_semaphore_t *)semp);

	while (running_threads) {
		;
	}
	return NULL;
}

#define PERF_STK_KHDR   UINT32_C(0x25020014)
#define PERF_STK_UHDR   UINT32_C(0x25020018)
#define PERF_TMR_FIRE   KDBG_EVENTID(DBG_PERF, 3, 0)
#define PERF_TMR_HNDLR  KDBG_EVENTID(DBG_PERF, 3, 2)
#define PERF_TMR_PEND   KDBG_EVENTID(DBG_PERF, 3, 3)
#define PERF_TMR_SKIP   KDBG_EVENTID(DBG_PERF, 3, 4)
#define PERF_KPC_CONFIG KDBG_EVENTID(DBG_PERF, 6, 4)
#define PERF_KPC_REG    KDBG_EVENTID(DBG_PERF, 6, 5)
#define PERF_KPC_REG32  KDBG_EVENTID(DBG_PERF, 6, 7)
#define PERF_INSTR_DATA KDBG_EVENTID(DBG_PERF, 1, 17)
#define PERF_EVENT      KDBG_EVENTID(DBG_PERF, 0, 0)

#define SCHED_DISPATCH KDBG_EVENTID(DBG_MACH, DBG_MACH_SCHED, MACH_DISPATCH)
#define SCHED_SWITCH KDBG_EVENTID(DBG_MACH, DBG_MACH_SCHED, MACH_SCHED)
#define SCHED_HANDOFF KDBG_EVENTID(DBG_MACH, DBG_MACH_SCHED, MACH_STACK_HANDOFF)
#define SCHED_IDLE KDBG_EVENTID(DBG_MACH, DBG_MACH_SCHED, MACH_IDLE)

#define MP_CPUS_CALL UINT32_C(0x1900004)

#define DISPATCH_AFTER_EVENT UINT32_C(0xfefffffc)
#define TIMEOUT_SECS 10

#define TIMER_PERIOD_NS (1 * NSEC_PER_MSEC)

static void
start_tracing_with_timeout(ktrace_session_t s, unsigned int timeout_secs)
{
	// Only set the timeout after we've seen an event that was traced by us.
	// This helps set a reasonable timeout after we're guaranteed to get a
	// few events.
	dispatch_queue_t q = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0);

	ktrace_events_single(s, DISPATCH_AFTER_EVENT,
	    ^(__unused struct trace_point *tp)
	{
		T_LOG("arming timer to stop tracing after %d seconds", timeout_secs);
		dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
		    timeout_secs * NSEC_PER_SEC), q, ^{
			T_LOG("ending tracing due to timeout");
			ktrace_end(s, 0);
		});
	});
	ktrace_set_collection_interval(s, 100);

	T_ASSERT_POSIX_ZERO(ktrace_start(s, q), "start ktrace");

	kdebug_trace(DISPATCH_AFTER_EVENT, 0, 0, 0, 0);
	T_LOG("trace point emitted");
}

static void
configure_kperf_timer_samplers(uint64_t period_ns, uint32_t samplers)
{
	T_SETUPBEGIN;

	(void)kperf_action_count_set(1);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(kperf_action_samplers_set(1, samplers),
	    NULL);
	(void)kperf_timer_count_set(1);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(kperf_timer_period_set(0,
	    kperf_ns_to_ticks(period_ns)), NULL);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(kperf_timer_action_set(0, 1), NULL);

	T_ASSERT_POSIX_SUCCESS(kperf_sample_set(1), "start kperf sampling");

	T_SETUPEND;
}

static double
timestamp_secs(ktrace_session_t s, uint64_t timestamp)
{
	uint64_t ns = 0;
	T_QUIET;
	T_ASSERT_POSIX_ZERO(ktrace_convert_timestamp_to_nanoseconds(s, timestamp,
	    &ns), NULL);
	return (double)ns / NSEC_PER_SEC;
}

#pragma mark - timers

// Ensure that kperf is correctly sampling CPUs that are actively scheduling by
// bringing up threads and ensuring that threads on-core are sampled by each
// timer fire.

T_DECL(kperf_sample_active_cpus,
    "make sure that kperf samples all active CPUs")
{
	start_controlling_ktrace();

	T_SETUPBEGIN;

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

	ktrace_session_t s = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "ktrace_session_create");
	ktrace_set_collection_interval(s, 100);

	__block uint64_t nfires = 0;
	__block uint64_t nsamples = 0;
	static uint64_t idle_tids[MAX_CPUS] = { 0 };
	__block double sum_saturation = 0;
	__block uint64_t last_nsamples = 0;

	// As a test debugging aid, take an additonal argument that specifies the
	// number of fires to stop tracing after.  This also turns on additional
	// logging of scheduler trace events.
	int stopafter = 0;
	if (argc > 0) {
		stopafter = atoi(argv[0]);
		if (stopafter < 0) {
			T_ASSERT_FAIL("argument must be positive");
		}
	}

	static uint64_t first_timestamp = 0;
	static uint64_t last_timestamp = 0;
	ktrace_events_any(s, ^(struct trace_point *tp) {
		if (first_timestamp == 0) {
			first_timestamp = tp->timestamp;
		}
		last_timestamp = tp->timestamp;
	});

	ktrace_set_completion_handler(s, ^{
		T_LOG("stopping threads");

		running_threads = false;

		for (int i = 0; i < nthreads; i++) {
		        T_QUIET;
		        T_ASSERT_POSIX_ZERO(pthread_join(threads[i], NULL), NULL);
		}

		double saturation = sum_saturation / nfires * 100;

		T_LOG("over %.1f seconds, saw %" PRIu64 " timer fires, %" PRIu64
			" samples, %g samples/fire, %.2f%% saturation",
			timestamp_secs(s, last_timestamp - first_timestamp), nfires,
			nsamples, (double)nsamples / (double)nfires, saturation);
		T_ASSERT_GT(saturation, 95.0,
		    "saw reasonable percentage of full samples");

		T_END;
	});

	// Track which threads are running on each CPU.
	static uint64_t tids_on_cpu[MAX_CPUS] = { 0 };
	void (^switch_cb)(struct trace_point *, const char *name) =
	    ^(struct trace_point *tp, const char *name) {
		uint64_t new_thread = tp->arg2;

		if (idle_tids[tp->cpuid] != new_thread) {
			tids_on_cpu[tp->cpuid] = new_thread;
		}

		if (stopafter) {
			T_LOG("%.7g: %s on %d: %llx", timestamp_secs(s, tp->timestamp),
			    name, tp->cpuid, tp->arg2);
		}
	};

	ktrace_events_single(s, SCHED_SWITCH, ^(struct trace_point *tp) {
		switch_cb(tp, "switch");
	});
	ktrace_events_single(s, SCHED_HANDOFF, ^(struct trace_point *tp) {
		switch_cb(tp, "hndoff");
	});

	// Determine the thread IDs of the idle threads on each CPU.
	ktrace_events_single(s, SCHED_IDLE, ^(struct trace_point *tp) {
		if (tp->debugid & DBG_FUNC_END) {
			return;
		}
		tids_on_cpu[tp->cpuid] = 0;
		idle_tids[tp->cpuid] = tp->threadid;
		if (stopafter) {
			T_LOG("%.7g: idle on %d: %llx", timestamp_secs(s, tp->timestamp),
			    tp->cpuid, tp->threadid);
		}
	});

	// On each timer fire, go through all the cores and mark any threads
	// that should be sampled.

	__block int last_fire_cpu = -1;
	static bool sample_missing[MAX_CPUS] = { false };
	static uint64_t tids_snap[MAX_CPUS] = { 0 };
	__block int nexpected = 0;
	__block int nextra = 0;
	__block int nidles = 0;

	ktrace_events_single(s, PERF_TMR_FIRE, ^(struct trace_point *tp) {
		T_QUIET; T_ASSERT_EQ((tp->debugid & DBG_FUNC_START), 0,
		    "no timer fire start events are allowed");
		int last_expected = nexpected;
		nfires++;

		nexpected = 0;
		for (int i = 0; i < ncpus; i++) {
			if (sample_missing[i]) {
				T_LOG("missed sample on CPU %d for thread %#llx from "
				    "timer on CPU %d (expected %d samples)",
				    tp->cpuid, tids_snap[i], last_fire_cpu, last_expected);
				sample_missing[i] = false;
			}

			if (tids_on_cpu[i] != 0) {
				tids_snap[i] = tids_on_cpu[i];
				sample_missing[i] = true;
				nexpected++;
			}
		}
		if (stopafter) {
			T_LOG("%.7g: FIRE on %d: %d extra, %d idles",
			    timestamp_secs(s, tp->timestamp), tp->cpuid, nextra, nidles);
		}

		if (nfires == 1) {
			return;
		}

		if (last_expected == 0) {
			sum_saturation += 1;
		} else {
			sum_saturation += (double)(nsamples - last_nsamples) /
			    last_expected;
		}
		last_nsamples = nsamples;
		nextra = 0;
		nidles = 0;

		T_QUIET;
		T_ASSERT_LT((int)tp->cpuid, ncpus, "timer fire should not occur on an IOP");
		last_fire_cpu = (int)tp->cpuid;

		if (stopafter && (uint64_t)stopafter == nfires) {
			ktrace_end(s, 1);
		}
	});

	// On the timer handler for each CPU, unset the missing sample bitmap.

	ktrace_events_single(s, PERF_TMR_HNDLR, ^(struct trace_point *tp) {
		nsamples++;
		if ((int)tp->cpuid > ncpus) {
		        // Skip IOPs; they're not scheduling any relevant threads.
		        return;
		}

		if (!sample_missing[tp->cpuid] && idle_tids[tp->cpuid] != 0) {
			T_LOG("sampled additional thread %llx on CPU %d", tp->threadid,
			    tp->cpuid);
			nextra++;
		}
		if (tp->threadid == idle_tids[tp->cpuid]) {
			T_LOG("sampled idle thread on CPU %d", tp->cpuid);
			nidles++;
		}
		sample_missing[tp->cpuid] = false;
	});

	configure_kperf_timer_samplers(TIMER_PERIOD_NS, KPERF_SAMPLER_KSTACK);

	T_SETUPEND;

	start_tracing_with_timeout(s, TIMEOUT_SECS);

	// Create threads to bring up all of the CPUs.

	dispatch_semaphore_t thread_spinning = dispatch_semaphore_create(0);

	for (int i = 0; i < nthreads; i++) {
		T_QUIET;
		T_ASSERT_POSIX_ZERO(
			pthread_create(&threads[i], NULL, &spinning_thread,
			&thread_spinning), NULL);
		dispatch_semaphore_wait(thread_spinning, DISPATCH_TIME_FOREVER);
	}

	T_LOG("spun up %d thread%s", nthreads, nthreads == 1 ? "" : "s");

	dispatch_main();
}

#define FIRES_THRESHOLD (5000)

T_DECL(kperf_timer_fires_enough_times,
    "ensure the correct number of timers fire in a period of time")
{
	start_controlling_ktrace();

	dispatch_semaphore_t thread_spinning = dispatch_semaphore_create(0);

	ktrace_session_t s = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "ktrace_session_create");
	ktrace_set_collection_interval(s, 100);

	__block uint64_t nfires = 0;
	__block uint64_t first_fire_ns = 0;
	__block uint64_t last_fire_ns = 0;

	int ncpus = dt_ncpu();

	ktrace_events_single(s, PERF_TMR_FIRE, ^(struct trace_point *tp) {
		nfires++;
		if (first_fire_ns == 0) {
			ktrace_convert_timestamp_to_nanoseconds(s, tp->timestamp,
			    &first_fire_ns);
		}
		ktrace_convert_timestamp_to_nanoseconds(s, tp->timestamp,
		    &last_fire_ns);

		T_QUIET; T_ASSERT_LT((int)tp->cpuid, ncpus,
		    "timer fire should not occur on an IOP");
		if (nfires >= FIRES_THRESHOLD) {
			ktrace_end(s, 1);
		}
	});

	configure_kperf_timer_samplers(TIMER_PERIOD_NS, KPERF_SAMPLER_KSTACK);

	pthread_t thread;
 	T_QUIET;
	T_ASSERT_POSIX_ZERO(pthread_create(&thread, NULL, &spinning_thread,
	    &thread_spinning), NULL);
	dispatch_semaphore_wait(thread_spinning, DISPATCH_TIME_FOREVER);

	ktrace_set_completion_handler(s, ^{
		running_threads = false;

		double duration_secs = (double)(last_fire_ns - first_fire_ns) /
		    NSEC_PER_SEC;
		T_LOG("stopping thread after %.2f seconds", duration_secs);

		T_QUIET; T_ASSERT_POSIX_ZERO(pthread_join(thread, NULL), NULL);

		T_LOG("saw %" PRIu64 " timer fires (%g fires/second)", nfires,
		    (double)nfires / (double)duration_secs);
		double expected_nfires = duration_secs * NSEC_PER_SEC / TIMER_PERIOD_NS;
		T_LOG("expecting %g timer fires", expected_nfires);
		double nfires_seen_pct = expected_nfires / nfires * 100;
		T_ASSERT_GT(nfires_seen_pct, 95.0,
		    "saw reasonable number of missed timer fires");
		T_ASSERT_LT(nfires_seen_pct, 105.0,
			"saw reasonable number of extra timer fires");

		T_END;
	});

	start_tracing_with_timeout(s, TIMEOUT_SECS);

	dispatch_main();
}

// kperf_timer_not_oversampling ensures that the profiling timer fires are
// spaced apart by the programmed timer period.  Otherwise, tools that rely on
// sample count as a proxy for CPU usage will over-estimate.

#define FIRE_PERIOD_THRESHOLD_NS \
		(TIMER_PERIOD_NS - (uint64_t)(TIMER_PERIOD_NS * 0.05))

struct cirq {
	unsigned int nslots;
	unsigned int tail_slot;
	unsigned int slot_size;
};

#define CIRQ_INIT(TYPE, NSLOTS) \
	(struct cirq){ \
		.nslots = NSLOTS, .tail_slot = 0, .slot_size = sizeof(TYPE), \
	}

static inline void *
cirq_get(struct cirq *cq, unsigned int i)
{
	return (char *)cq + sizeof(*cq) + (cq->slot_size * i);
}

static void *
cirq_top(void *vcq)
{
	struct cirq *cq = vcq;
	unsigned int tail_slot = cq->tail_slot;
	unsigned int top_slot = (tail_slot > 0 ? tail_slot : cq->nslots) - 1;
	return cirq_get(cq, top_slot);
}

static void *
cirq_push(void *vcq)
{
	struct cirq *cq = vcq;
	unsigned int tail_slot = cq->tail_slot;
	unsigned int next_slot = tail_slot == cq->nslots - 1 ? 0 : tail_slot + 1;
	cq->tail_slot = next_slot;
	return cirq_get(cq, tail_slot);
}

static void
cirq_for(void *vcq, void (^iter)(void *elt))
{
	struct cirq *cq = vcq;
	for (unsigned int i = cq->tail_slot; i < cq->nslots; i++) {
		iter(cirq_get(cq, i));
	}
	for (unsigned int i = 0; i < cq->tail_slot; i++) {
		iter(cirq_get(cq, i));
	}
}

#define HISTORY_LEN 5

struct instval {
	uint64_t iv_instant_ns;
	uint64_t iv_val;
};

struct cirq_instval {
	struct cirq cq;
	struct instval elts[HISTORY_LEN];
};

struct cirq_u64 {
	struct cirq cq;
	uint64_t elts[HISTORY_LEN];
};

struct cpu_oversample {
	struct cirq_instval timer_latencies;
	struct cirq_instval fire_latencies;
};

static void
cpu_oversample_log(struct cpu_oversample *cpu, unsigned int cpuid)
{
	T_LOG("CPU %d timer latencies:", cpuid);
	__block int i = -HISTORY_LEN;
	cirq_for(&cpu->timer_latencies, ^(void *viv) {
		struct instval *iv = viv;
		T_LOG("\t%llu timer latency %d: %llu", iv->iv_instant_ns, i,
		    iv->iv_val);
		i++;
	});

	T_LOG("CPU %d fire latencies:", cpuid);
	i = -HISTORY_LEN;
	cirq_for(&cpu->fire_latencies, ^(void *viv) {
		struct instval *iv = viv;
		T_LOG("\t%llu fire latency %d: %llu", iv->iv_instant_ns, i, iv->iv_val);
		i++;
	});
}

T_DECL(kperf_timer_not_oversampling,
    "ensure that time between fires is long enough")
{
	start_controlling_ktrace();

	ktrace_session_t s = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "ktrace_session_create");
	// Try not to perturb the system with more work.
	ktrace_set_collection_interval(s, 1000);
	__block uint64_t nfires = 0;
	__block uint64_t first_fire_ns = 0;
	__block uint64_t last_fire_ns = 0;
	__block unsigned int last_fire_cpuid = 0;

	int ncpus = dt_ncpu();
	T_QUIET; T_ASSERT_GT(ncpus, 0, "should see positive number of CPUs");

	struct cpu_oversample *per_cpu = calloc((unsigned int)ncpus,
			sizeof(per_cpu[0]));
	T_QUIET; T_WITH_ERRNO;
	T_ASSERT_NOTNULL(per_cpu, "allocated timer latency tracking");
	for (int i = 0; i < ncpus; i++) {
		per_cpu[i].timer_latencies.cq = CIRQ_INIT(struct instval, HISTORY_LEN);
		per_cpu[i].fire_latencies.cq = CIRQ_INIT(struct instval, HISTORY_LEN);
	}

	__block bool in_stackshot = false;
	__block uint64_t last_stackshot_ns = 0;

	// Stackshots are the primary source of interrupt latency on the system.
	ktrace_events_single(s, KDBG_EVENTID(DBG_BSD, DBG_BSD_EXCP_SC,
			SYS_stack_snapshot_with_config), ^(struct trace_point *tp) {
		bool start = tp->debugid & DBG_FUNC_START;
		uint64_t cur_ns = relns_from_abs(s, tp->timestamp);
		T_LOG("%llu: %s stackshot syscall from process %s",
				cur_ns, start ? "start" : "finish", tp->command);
		in_stackshot = start;
		if (!start) {
			last_stackshot_ns = cur_ns;
		}
	});

	struct cirq_u64 *fire_times = calloc(1, sizeof(*fire_times));
	T_ASSERT_NOTNULL(fire_times, "allocated fire time tracking");
	fire_times->cq = CIRQ_INIT(uint64_t, HISTORY_LEN);

	// Track the decrementer's latency values to find any unexpectedly long
	// interrupt latencies that could affect the firing cadence.
	ktrace_events_single(s, MACHDBG_CODE(DBG_MACH_EXCP_DECI, 0),
			^(struct trace_point *tp) {
		uint64_t cur_ns = relns_from_abs(s, tp->timestamp);
		uint64_t latency_ns = ns_from_abs(s, 0 - tp->arg1);
		struct instval *latency = cirq_push(&per_cpu[tp->cpuid].timer_latencies);
		latency->iv_instant_ns = cur_ns;
		latency->iv_val = latency_ns;
	});

	ktrace_events_single(s, PERF_TMR_FIRE, ^(struct trace_point *tp) {
		T_QUIET; T_ASSERT_LT((int)tp->cpuid, ncpus,
				"timer fire should not occur on an IOP");

		nfires++;
		uint64_t cur_ns = relns_from_abs(s, tp->timestamp);
		uint64_t *fire_ns = cirq_push(fire_times);
		*fire_ns = cur_ns;

		struct cpu_oversample *cur_cpu = &per_cpu[tp->cpuid];
		struct instval *last_timer_latency = cirq_top(
				&cur_cpu->timer_latencies);
		uint64_t timer_latency_ns = last_timer_latency->iv_val;

		if (first_fire_ns == 0) {
			first_fire_ns = cur_ns;
		} else {
			struct cpu_oversample *last_cpu = &per_cpu[last_fire_cpuid];
			struct instval *last_latency = cirq_top(&last_cpu->fire_latencies);
			uint64_t last_fire_latency_ns = last_latency->iv_val;

			if (timer_latency_ns > TIMER_PERIOD_NS / 4) {
				T_LOG("%llu: long timer latency at fire: %llu", cur_ns,
						timer_latency_ns);
			}

			// Long interrupt latencies will cause the timer to miss its fire
			// time and report a fire past when it should have, making the next
			// period too short.  Keep track of the latency as a leeway
			// adjustment for the subsequent fire.
			uint64_t fire_period_ns = cur_ns - last_fire_ns;
			uint64_t fire_period_adj_ns = fire_period_ns +
			    last_fire_latency_ns + timer_latency_ns;
			bool too_short = fire_period_adj_ns < FIRE_PERIOD_THRESHOLD_NS;
			if (too_short) {
				T_LOG("%llu: period of timer fire %llu is %llu + %llu + %llu = "
						"%llu < %llu",
						cur_ns, nfires, fire_period_ns, last_fire_latency_ns,
						timer_latency_ns, fire_period_adj_ns,
						FIRE_PERIOD_THRESHOLD_NS);

				T_LOG("short profile timer fired on CPU %d", tp->cpuid);
				cpu_oversample_log(cur_cpu, tp->cpuid);

				if (cur_cpu == last_cpu) {
					T_LOG("fired back-to-back on CPU %d", tp->cpuid);
				} else {
					T_LOG("previous profile timer fired on CPU %d",
							last_fire_cpuid);
					cpu_oversample_log(last_cpu, last_fire_cpuid);
				}

				T_LOG("profile timer fires:");
				cirq_for(fire_times, ^(void *vu64) {
					T_LOG("\tfire: %llu", *(uint64_t *)vu64);
				});
				if (nfires < (unsigned int)ncpus) {
					T_LOG("ignoring timer fire %llu as context may be missing",
							nfires);
				} else {
					if (in_stackshot) {
						T_LOG("skipping assertion because stackshot is "
								"happening");
					} else if (last_stackshot_ns != 0 &&
							cur_ns > last_stackshot_ns &&
							cur_ns - last_stackshot_ns < TIMER_PERIOD_NS) {
						T_LOG("skipping assertion because stackshot happened "
								"%" PRIu64 "ns ago",
								cur_ns - last_stackshot_ns);
					} else {
						T_ASSERT_FAIL("profiling period is shorter than "
								"expected with no stackshot interference");
					}
				}
			}

			struct instval *latency = cirq_push(&cur_cpu->fire_latencies);
			latency->iv_instant_ns = cur_ns;
			latency->iv_val = timer_latency_ns;

			// Snapshot this timer fire's interrupt latency, so the next one
			// can make an adjustment to the period.
			last_fire_latency_ns = timer_latency_ns;
		}
		last_fire_ns = cur_ns;
		last_fire_cpuid = tp->cpuid;

		if (nfires >= FIRES_THRESHOLD) {
			ktrace_end(s, 1);
		}
	});

	configure_kperf_timer_samplers(TIMER_PERIOD_NS, KPERF_SAMPLER_TINFO);

	ktrace_set_completion_handler(s, ^{
		double duration_secs = (double)(last_fire_ns - first_fire_ns) /
		    NSEC_PER_SEC;
		T_LOG("stopping trace after %.2f seconds", duration_secs);

		T_PASS("saw %" PRIu64 " timer fires (%g fires/second) without "
			"oversampling", nfires, (double)nfires / (double)duration_secs);

		T_END;
	});

	start_tracing_with_timeout(s, 5);

	// Get all CPUs out of idle.
	uint64_t *counts = kpc_counterbuf_alloc();
	(void)kpc_get_cpu_counters(true,KPC_CLASS_CONFIGURABLE_MASK, NULL, counts);
	free(counts);

	dispatch_main();
}

T_DECL(kperf_timer_stress, "repeatedly enable and disable timers")
{
	start_controlling_ktrace();

	const int niters = 500;
	for (int i = 0; i < niters; i++) {
		configure_kperf_stacks_timer(-1, 1, true);
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(kperf_sample_set(1), "start kperf sampling");
		usleep(2000);
		kperf_reset();
	}
	T_LOG("configured kperf with a timer %d times", niters);
}

#pragma mark - kdebug triggers

#define KDEBUG_TRIGGER_TIMEOUT_NS (10 * NSEC_PER_SEC)

#define NON_TRIGGER_CLASS    UINT32_C(0xfd)
#define NON_TRIGGER_SUBCLASS UINT32_C(0xff)
#define NON_TRIGGER_CODE     UINT32_C(0xff)

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
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "ktrace_session_create");
	ktrace_set_collection_interval(s, 100);

	ktrace_events_single(s, PERF_STK_KHDR, ^(struct trace_point *tp) {
		missing_kernel_stacks--;
		T_LOG("saw kernel stack with %" PRIu64 " frames, flags = %#"
		PRIx64, tp->arg2, tp->arg1);
	});
	ktrace_events_single(s, PERF_STK_UHDR, ^(struct trace_point *tp) {
		missing_user_stacks--;
		T_LOG("saw user stack with %" PRIu64 " frames, flags = %#"
		PRIx64, tp->arg2, tp->arg1);
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

	// Trace the triggering events.

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

#define TRIGGER_CLASS     UINT32_C(0xfe)
#define TRIGGER_CLASS_END UINT32_C(0xfd)
#define TRIGGER_SUBCLASS  UINT32_C(0xff)
#define TRIGGER_CODE      UINT32_C(0)
#define TRIGGER_DEBUGID \
	        (KDBG_EVENTID(TRIGGER_CLASS, TRIGGER_SUBCLASS, TRIGGER_CODE))

T_DECL(kperf_kdebug_trigger_classes,
    "test that kdebug trigger samples on classes")
{
	start_controlling_ktrace();

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

T_DECL(kperf_kdebug_trigger_subclasses,
    "test that kdebug trigger samples on subclasses")
{
	start_controlling_ktrace();

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

T_DECL(kperf_kdebug_trigger_debugids,
    "test that kdebug trigger samples on debugids")
{
	start_controlling_ktrace();

	const uint32_t debugids[] = {
		TRIGGER_DEBUGID
	};

	expect_kdebug_trigger("D0xfeff0000", debugids,
	    sizeof(debugids) / sizeof(debugids[0]));
	dispatch_main();
}

// TODO Set a single function specifier filter, expect not to trigger of all
// events from that class.

static void
reset_kperf(void)
{
	(void)kperf_reset();
}

T_DECL(kperf_kdbg_callstacks,
    "test that the kdbg_callstacks samples on syscalls")
{
	start_controlling_ktrace();

	ktrace_session_t s;
	__block bool saw_user_stack = false;

	s = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "ktrace_session_create");
	ktrace_set_collection_interval(s, 100);

	// Make sure BSD events are traced in order to trigger samples on syscalls.
	ktrace_events_class(s, DBG_BSD, ^void (__unused struct trace_point *tp) {});

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
	T_ATEND(reset_kperf);

	T_ASSERT_POSIX_ZERO(ktrace_start(s, dispatch_get_main_queue()), NULL);

	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC),
	    dispatch_get_main_queue(), ^(void) {
		ktrace_end(s, 1);
	});

	dispatch_main();
}

#pragma mark - PET

#define STACKS_WAIT_DURATION_NS (3 * NSEC_PER_SEC)

static void
expect_stacks_traced(void (^setup)(ktrace_session_t s), void (^complete)(void))
{
	ktrace_session_t s;

	s = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "ktrace_session_create");
	ktrace_set_collection_interval(s, 100);
	if (setup) {
		setup(s);
	}

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
		complete();
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

T_DECL(kperf_pet, "test that PET mode samples kernel and user stacks")
{
	start_controlling_ktrace();

	configure_kperf_stacks_timer(-1, 10, false);
	T_ASSERT_POSIX_SUCCESS(kperf_timer_pet_set(0), NULL);

	expect_stacks_traced(NULL, ^(void) {
		T_END;
	});

	dispatch_main();
}

T_DECL(kperf_lightweight_pet,
    "test that lightweight PET mode samples kernel and user stacks",
    T_META_ASROOT(true))
{
	start_controlling_ktrace();

	int set = 1;

	configure_kperf_stacks_timer(-1, 10, false);
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kperf.lightweight_pet", NULL, NULL,
	    &set, sizeof(set)), NULL);
	T_ASSERT_POSIX_SUCCESS(kperf_timer_pet_set(0), NULL);

	__block uint64_t nfires = 0;

	expect_stacks_traced(^(ktrace_session_t s) {
		ktrace_events_single(s, PERF_TMR_FIRE, ^(struct trace_point *tp) {
			nfires++;
			T_QUIET;
			T_ASSERT_EQ(tp->arg1, (uint64_t)0,
					"timer fire should have timer ID of 0");
			T_QUIET;
			T_ASSERT_EQ(tp->arg2, (uint64_t)1,
					"timer fire should have PET bit set");
		});
	}, ^(void) {
		T_ASSERT_GT(nfires, (uint64_t)0, "timer fired at least once");
		T_END;
	});

	dispatch_main();
}

T_DECL(kperf_pet_stress, "repeatedly enable and disable PET mode")
{
	start_controlling_ktrace();

	const int niters = 500;
	for (int i = 0; i < niters; i++) {
		configure_kperf_stacks_timer(-1, 1, true);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(kperf_timer_pet_set(0), NULL);
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(kperf_sample_set(1), "start kperf sampling");
		usleep(2000);
		kperf_reset();
	}

	T_PASS("configured kperf PET %d times", niters);
}

#pragma mark - PMCs

T_DECL(kperf_pmc_config_only,
    "shouldn't show PMC config events unless requested")
{
	start_controlling_ktrace();

	__block bool saw_kpc_config = false;
	__block bool saw_kpc_reg = false;

	ktrace_session_t s = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(s, "ktrace_session_create");
	ktrace_set_collection_interval(s, 100);

	ktrace_events_single(s, PERF_KPC_CONFIG,
	    ^(__unused struct trace_point *tp) {
		saw_kpc_config = true;
	});
	ktrace_events_single(s, PERF_KPC_REG,
	    ^(__unused struct trace_point *tp) {
		saw_kpc_reg = true;
	});
	ktrace_events_single(s, PERF_KPC_REG32,
	    ^(__unused struct trace_point *tp) {
		saw_kpc_reg = true;
	});

	ktrace_set_completion_handler(s, ^{
		ktrace_session_destroy(s);
		T_EXPECT_FALSE(saw_kpc_config,
		"should see no KPC configs without sampler enabled");
		T_EXPECT_FALSE(saw_kpc_reg,
		"should see no KPC registers without sampler enabled");
		T_END;
	});

	uint32_t nconfigs = kpc_get_config_count(KPC_CLASS_CONFIGURABLE_MASK);
	uint64_t *config = calloc(nconfigs, sizeof(*config));
	config[0] = 0x02;
	int ret = kpc_set_config(KPC_CLASS_CONFIGURABLE_MASK, config);
	T_ASSERT_POSIX_SUCCESS(ret, "configured kpc");
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(kpc_set_counting(KPC_CLASS_CONFIGURABLE_MASK),
	    "kpc_set_counting");

	(void)kperf_action_count_set(1);
	T_ATEND(reset_kperf);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(kperf_action_samplers_set(1, KPERF_SAMPLER_PMC_CPU),
	    NULL);

	(void)kperf_timer_count_set(1);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(kperf_timer_period_set(0,
	    kperf_ns_to_ticks(TIMER_PERIOD_NS)), NULL);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(kperf_timer_action_set(0, 1), NULL);

	T_ASSERT_POSIX_SUCCESS(kperf_sample_set(1), "start kperf sampling");

	T_ASSERT_POSIX_ZERO(ktrace_start(s, dispatch_get_main_queue()), NULL);

	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC),
	    dispatch_get_main_queue(), ^(void) {
		ktrace_end(s, 1);
	});

	dispatch_main();
}

static void
skip_if_monotonic_unsupported(void)
{
	int r;
	int supported = 0;
	size_t supported_size = sizeof(supported);

	r = sysctlbyname("kern.monotonic.supported", &supported, &supported_size,
	    NULL, 0);
	if (r < 0) {
		T_WITH_ERRNO;
		T_SKIP("could not find \"kern.monotonic.supported\" sysctl");
	}

	if (!supported) {
		T_SKIP("monotonic is not supported on this platform");
	}
}

#define INSTRS_CYCLES_UPPER 500
#define INSTRS_CYCLES_LOWER 50

T_DECL(kperf_sample_instrs_cycles,
    "ensure instructions and cycles are sampled")
{
	skip_if_monotonic_unsupported();

	start_controlling_ktrace();

	ktrace_session_t sess = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(sess, "ktrace_session_create");
	ktrace_set_collection_interval(sess, 100);

	__block uint64_t ninstrs_cycles = 0;
	__block uint64_t nzeroes = 0;
	ktrace_events_single(sess, PERF_INSTR_DATA,
	    ^(__unused struct trace_point *tp) {
		ninstrs_cycles++;
		if (tp->arg1 == 0) {
			T_LOG("%llx (%s)\n", tp->threadid, tp->command);
			nzeroes++;
		}
		if (ninstrs_cycles >= INSTRS_CYCLES_UPPER) {
			ktrace_end(sess, 1);
		}
	});

	ktrace_set_collection_interval(sess, 200);

	ktrace_set_completion_handler(sess, ^{
		T_EXPECT_GE(ninstrs_cycles, (uint64_t)INSTRS_CYCLES_LOWER,
		    "saw enough instructions and cycles events");
		T_EXPECT_EQ(nzeroes, UINT64_C(0),
		    "saw no events with 0 instructions");
		T_END;
	});

	(void)kperf_action_count_set(1);
	T_ATEND(reset_kperf);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(kperf_action_samplers_set(1,
	    KPERF_SAMPLER_TH_INSTRS_CYCLES), NULL);

	(void)kperf_timer_count_set(1);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(kperf_timer_period_set(0,
	    kperf_ns_to_ticks(TIMER_PERIOD_NS)), NULL);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(kperf_timer_action_set(0, 1), NULL);

	T_ASSERT_POSIX_SUCCESS(kperf_sample_set(1), "start kperf sampling");

	T_ASSERT_POSIX_ZERO(ktrace_start(sess, dispatch_get_main_queue()),
	    NULL);

	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC),
	    dispatch_get_main_queue(), ^(void) {
		ktrace_end(sess, 1);
	});

	dispatch_main();
}
