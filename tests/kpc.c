// Copyright (c) 2018-2020 Apple Inc.  All rights reserved.

#include <darwintest.h>
#include <ktrace/config.h>
#include <ktrace/session.h>
#include <inttypes.h>
#include <libproc.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/resource.h>
#include <sys/sysctl.h>

#include <kperf/kpc.h>
#include <kperf/kperf.h>

#include "ktrace_helpers.h"
#include "kperf_helpers.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ktrace"),
	T_META_ASROOT(true),
	T_META_CHECK_LEAKS(false));

struct machine {
	unsigned int ncpus;
	unsigned int nfixed;
	unsigned int nconfig;
};

static void
skip_if_unsupported(void)
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
		T_SKIP("PMCs are not supported on this platform");
	}
}

static struct rusage_info_v4 pre_ru = {};

static void
start_kpc(void)
{
	T_SETUPBEGIN;

	kpc_classmask_t classes = KPC_CLASS_FIXED_MASK |
	    KPC_CLASS_CONFIGURABLE_MASK;
	int ret = kpc_set_counting(classes);
	T_ASSERT_POSIX_SUCCESS(ret, "started counting");

	ret = proc_pid_rusage(getpid(), RUSAGE_INFO_V4, (rusage_info_t *)&pre_ru);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "got rusage information");

	kpc_classmask_t classes_on = kpc_get_counting();
	T_QUIET;
	T_ASSERT_EQ(classes, classes_on, "classes counting is correct");

	T_SETUPEND;
}

static void kpc_reset_atend(void);

#if defined(__arm__) || defined(__arm64__)
#define CYCLES_EVENT 0x02
#else // defined(__arm__) || defined(__arm64__)
#define CYCLES_EVENT (0x10000 | 0x20000 | 0x3c)
#endif // !defined(__arm__) && !defined(__arm64__)

static void
prepare_kpc(struct machine *mch, bool config, bool reset)
{
	T_SETUPBEGIN;

	if (!reset) {
		T_ATEND(kpc_reset_atend);
	}

	size_t ncpus_sz = sizeof(mch->ncpus);
	int ret = sysctlbyname("hw.logicalcpu_max", &mch->ncpus, &ncpus_sz,
	    NULL, 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname(hw.logicalcpu_max)");
	T_QUIET;
	T_ASSERT_GT(mch->ncpus, 0, "must have some number of CPUs");

	ret = kpc_force_all_ctrs_set(1);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kpc_force_all_ctrs_set(1)");

	int forcing = 0;
	ret = kpc_force_all_ctrs_get(&forcing);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kpc_force_all_ctrs_get");
	T_QUIET; T_ASSERT_EQ(forcing, 1, "counters must be forced");

	mch->nfixed = kpc_get_counter_count(KPC_CLASS_FIXED_MASK);
	mch->nconfig = kpc_get_counter_count(KPC_CLASS_CONFIGURABLE_MASK);

	T_LOG("machine: ncpus = %d, nfixed = %d, nconfig = %d", mch->ncpus,
	    mch->nfixed, mch->nconfig);

	if (config) {
		uint32_t nconfigs = kpc_get_config_count(
		    KPC_CLASS_CONFIGURABLE_MASK);
		uint64_t *configs = calloc(nconfigs, sizeof(*configs));
		T_QUIET; T_ASSERT_NOTNULL(configs, "allocated config words");

		for (unsigned int i = 0; i < nconfigs; i++) {
			configs[i] = reset ? 0 : CYCLES_EVENT;
		}

		ret = kpc_set_config(KPC_CLASS_CONFIGURABLE_MASK, configs);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kpc_set_config");
	}

	T_SETUPEND;
}

static void
kpc_reset_atend(void)
{
	struct machine mch = {};
	prepare_kpc(&mch, true, true);
	uint64_t *periods = calloc(mch.nconfig, sizeof(*periods));
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(periods, "allocate periods array");

	int ret = kpc_set_period(KPC_CLASS_CONFIGURABLE_MASK, periods);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kpc_set_period");
	free(periods);
}

static void *
spin(void *arg)
{
	while (*(volatile int *)arg == 0) {
		;
	}

	return NULL;
}

static pthread_t *
start_threads(const struct machine *mch, void *(*func)(void *), void *arg)
{
	T_SETUPBEGIN;

	pthread_t *threads = calloc((unsigned int)mch->ncpus,
	    sizeof(*threads));
	T_QUIET; T_ASSERT_NOTNULL(threads, "allocated array of threads");
	for (unsigned int i = 0; i < mch->ncpus; i++) {
		int error = pthread_create(&threads[i], NULL, func, arg);
		T_QUIET; T_ASSERT_POSIX_ZERO(error, "pthread_create");
	}

	T_SETUPEND;

	return threads;
}

static void
end_threads(const struct machine *mch, pthread_t *threads)
{
	for (unsigned int i = 0; i < mch->ncpus; i++) {
		int error = pthread_join(threads[i], NULL);
		T_QUIET; T_ASSERT_POSIX_ZERO(error, "joined thread %d", i);
	}
	free(threads);
}

struct tally {
	uint64_t firstvalue;
	uint64_t lastvalue;
	uint64_t nchecks;
	uint64_t nzero;
	uint64_t nstuck;
	uint64_t ndecrease;
};

static void
check_counters(unsigned int ncpus, unsigned int nctrs, struct tally *tallies,
		uint64_t *counts)
{
	for (unsigned int i = 0; i < ncpus; i++) {
		for (unsigned int j = 0; j < nctrs; j++) {
			unsigned int ctr = i * nctrs + j;
			struct tally *tly = &tallies[ctr];
			uint64_t count = counts[ctr];

			if (counts[ctr] == 0) {
				tly->nzero++;
			}
			if (tly->lastvalue == count) {
				tly->nstuck++;
			}
			if (tly->lastvalue > count) {
				tly->ndecrease++;
			}
			tly->lastvalue = count;
			if (tly->nchecks == 0) {
				tly->firstvalue = count;
			}
			tly->nchecks++;
		}
	}
}

static void
check_tally(const char *name, unsigned int ncpus, unsigned int nctrs,
		struct tally *tallies)
{
	for (unsigned int i = 0; i < ncpus; i++) {
		for (unsigned int j = 0; j < nctrs; j++) {
			unsigned int ctr = i * nctrs + j;
			struct tally *tly = &tallies[ctr];

			T_LOG("CPU %2u PMC %u: nchecks = %llu, last value = %llx, "
				"delta = %llu, nstuck = %llu", i, j,
			    tly->nchecks, tly->lastvalue, tly->lastvalue - tly->firstvalue,
			    tly->nstuck);
			T_QUIET; T_EXPECT_GT(tly->nchecks, 0ULL,
			    "checked that CPU %d %s counter %d values", i, name, j);
			T_QUIET; T_EXPECT_EQ(tly->nzero, 0ULL,
			    "CPU %d %s counter %d value was zero", i, name, j);
			T_QUIET; T_EXPECT_EQ(tly->nstuck, 0ULL,
			    "CPU %d %s counter %d value was stuck", i, name, j);
			T_QUIET; T_EXPECT_EQ(tly->ndecrease, 0ULL,
			    "CPU %d %s counter %d value decreased", i, name, j);
		}
	}
}

#define TESTDUR_NS (5 * NSEC_PER_SEC)

T_DECL(kpc_cpu_direct_configurable,
    "test that configurable counters return monotonically increasing values")
{
	skip_if_unsupported();

	struct machine mch = {};
	prepare_kpc(&mch, true, false);

	int until = 0;
	pthread_t *threads = start_threads(&mch, spin, &until);
	start_kpc();

	T_SETUPBEGIN;

	uint64_t startns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
	uint64_t *counts = kpc_counterbuf_alloc();
	T_QUIET; T_ASSERT_NOTNULL(counts, "allocated space for counter values");
	memset(counts, 0, sizeof(*counts) * mch.ncpus * (mch.nfixed + mch.nconfig));
	struct tally *tly = calloc(mch.ncpus * mch.nconfig, sizeof(*tly));
	T_QUIET; T_ASSERT_NOTNULL(tly, "allocated space for tallies");

	T_SETUPEND;

	int n = 0;
	while (clock_gettime_nsec_np(CLOCK_MONOTONIC) - startns < TESTDUR_NS) {
		int ret = kpc_get_cpu_counters(true,
		    KPC_CLASS_CONFIGURABLE_MASK, NULL, counts);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kpc_get_cpu_counters");

		check_counters(mch.ncpus, mch.nconfig, tly, counts);

		usleep(10000);
		n++;
		if (n % 100 == 0) {
			T_LOG("checked 100 times");
		}
	}

	check_tally("config", mch.ncpus, mch.nconfig, tly);

	until = 1;
	end_threads(&mch, threads);
}

T_DECL(kpc_thread_direct_instrs_cycles,
    "test that fixed thread counters return monotonically increasing values")
{
	int err;
	uint32_t ctrs_cnt;
	uint64_t *ctrs_a;
	uint64_t *ctrs_b;

	skip_if_unsupported();

	T_SETUPBEGIN;

	ctrs_cnt = kpc_get_counter_count(KPC_CLASS_FIXED_MASK);
	if (ctrs_cnt == 0) {
		T_SKIP("no fixed counters available");
	}
	T_LOG("device has %" PRIu32 " fixed counters", ctrs_cnt);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(kpc_force_all_ctrs_set(1), NULL);
	T_ASSERT_POSIX_SUCCESS(kpc_set_counting(KPC_CLASS_FIXED_MASK),
	    "kpc_set_counting");
	T_ASSERT_POSIX_SUCCESS(kpc_set_thread_counting(KPC_CLASS_FIXED_MASK),
	    "kpc_set_thread_counting");

	T_SETUPEND;

	ctrs_a = malloc(ctrs_cnt * sizeof(uint64_t));
	T_QUIET; T_ASSERT_NOTNULL(ctrs_a, NULL);

	err = kpc_get_thread_counters(0, ctrs_cnt, ctrs_a);
	T_ASSERT_POSIX_SUCCESS(err, "kpc_get_thread_counters");

	for (uint32_t i = 0; i < ctrs_cnt; i++) {
		T_LOG("checking counter %d with value %" PRIu64 " > 0", i, ctrs_a[i]);
		T_QUIET;
		T_EXPECT_GT(ctrs_a[i], UINT64_C(0), "counter %d is non-zero", i);
	}

	ctrs_b = malloc(ctrs_cnt * sizeof(uint64_t));
	T_QUIET; T_ASSERT_NOTNULL(ctrs_b, NULL);

	err = kpc_get_thread_counters(0, ctrs_cnt, ctrs_b);
	T_ASSERT_POSIX_SUCCESS(err, "kpc_get_thread_counters");

	for (uint32_t i = 0; i < ctrs_cnt; i++) {
		T_LOG("checking counter %d with value %" PRIu64
		    " > previous value %" PRIu64, i, ctrs_b[i], ctrs_a[i]);
		T_QUIET;
		T_EXPECT_GT(ctrs_b[i], UINT64_C(0), "counter %d is non-zero", i);
		T_QUIET; T_EXPECT_LT(ctrs_a[i], ctrs_b[i],
		    "counter %d is increasing", i);
	}

	free(ctrs_a);
	free(ctrs_b);
}

#define PMI_TEST_DURATION_NS (15 * NSEC_PER_SEC)
#define PERIODIC_CPU_COUNT_MS (250)
#define NTIMESLICES (72)
#define PMI_PERIOD (50ULL * 1000 * 1000)
#define END_EVENT KDBG_EVENTID(0xfe, 0xfe, 0)

struct cpu {
	uint64_t prev_count, max_skid;
	unsigned int timeslices[NTIMESLICES];
};

T_DECL(kpc_pmi_configurable,
    "test that PMIs don't interfere with sampling counters in kperf")
{
	skip_if_unsupported();

	start_controlling_ktrace();
	struct machine mch = {};
	prepare_kpc(&mch, true, false);

	T_SETUPBEGIN;

	uint64_t *periods = calloc(mch.nconfig, sizeof(*periods));
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(periods, "allocate periods array");
	periods[0] = PMI_PERIOD;

	int ret = kpc_set_period(KPC_CLASS_CONFIGURABLE_MASK, periods);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kpc_set_period");
	free(periods);

	int32_t *actions = calloc(mch.nconfig, sizeof(*actions));
	actions[0] = 1;
	ret = kpc_set_actionid(KPC_CLASS_CONFIGURABLE_MASK, actions);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kpc_set_actionid");
	free(actions);

	(void)kperf_action_count_set(1);
	ret = kperf_action_samplers_set(1, KPERF_SAMPLER_TINFO);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kperf_action_samplers_set");

	ktrace_config_t ktconfig = ktrace_config_create_current();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(ktconfig, "create current config");
	ret = ktrace_config_print_description(ktconfig, stdout);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "print config description");

	struct cpu *cpus = calloc(mch.ncpus, sizeof(*cpus));
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(cpus, "allocate CPUs array");

	__block unsigned int nsamples = 0;
	__block uint64_t first_ns = 0;
	__block uint64_t last_ns = 0;

	ktrace_session_t sess = ktrace_session_create();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(sess, "ktrace_session_create");

	ktrace_events_single(sess, PERF_KPC_PMI, ^(struct trace_point *tp) {
		if (tp->debugid & DBG_FUNC_END) {
			return;
		}

		uint64_t cur_ns = 0;
		int cret = ktrace_convert_timestamp_to_nanoseconds(sess,
		    tp->timestamp, &cur_ns);
		T_QUIET; T_ASSERT_POSIX_ZERO(cret, "convert timestamp");

		uint64_t count = tp->arg2;
		if (first_ns == 0) {
			first_ns = cur_ns;
		}
		struct cpu *cpu = &cpus[tp->cpuid];

		if (cpu->prev_count != 0) {
			uint64_t delta = count - cpu->prev_count;
			T_QUIET; T_EXPECT_GT(delta, PMI_PERIOD,
			    "counter delta should be greater than PMI period");
			uint64_t skid = delta - PMI_PERIOD;
			if (skid > cpu->max_skid) {
				cpu->max_skid = skid;
			}
		}
		cpu->prev_count = count;

		double slice = (double)(cur_ns - first_ns) / PMI_TEST_DURATION_NS *
		    NTIMESLICES;
		if (slice < NTIMESLICES) {
			cpu->timeslices[(unsigned int)slice] += 1;
		}

		nsamples++;
	});

	ktrace_events_single(sess, END_EVENT, ^(struct trace_point *tp __unused) {
		int cret = ktrace_convert_timestamp_to_nanoseconds(sess,
		    tp->timestamp, &last_ns);
		T_QUIET; T_ASSERT_POSIX_ZERO(cret, "convert timestamp");

		ktrace_end(sess, 1);
	});

	uint64_t *counts = kpc_counterbuf_alloc();
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(counts,
			"allocated counter values array");
	memset(counts, 0, sizeof(*counts) * mch.ncpus * (mch.nfixed + mch.nconfig));
	struct tally *tly = calloc(mch.ncpus * (mch.nconfig + mch.nfixed),
			sizeof(*tly));
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(tly, "allocated tallies array");

	dispatch_source_t cpu_count_timer = dispatch_source_create(
			DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
    dispatch_source_set_timer(cpu_count_timer, dispatch_time(DISPATCH_TIME_NOW,
        PERIODIC_CPU_COUNT_MS * NSEC_PER_MSEC),
        PERIODIC_CPU_COUNT_MS * NSEC_PER_MSEC, 0);
    dispatch_source_set_cancel_handler(cpu_count_timer, ^{
        dispatch_release(cpu_count_timer);
    });

    __block uint64_t first_check_ns = 0;
    __block uint64_t last_check_ns = 0;

    dispatch_source_set_event_handler(cpu_count_timer, ^{
		int cret = kpc_get_cpu_counters(true,
		    KPC_CLASS_FIXED_MASK | KPC_CLASS_CONFIGURABLE_MASK, NULL, counts);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(cret, "kpc_get_cpu_counters");

		if (!first_check_ns) {
			first_check_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
		} else {
			last_check_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
		}
		check_counters(mch.ncpus, mch.nfixed + mch.nconfig, tly, counts);
	});

	int stop = 0;
	(void)start_threads(&mch, spin, &stop);

	ktrace_set_completion_handler(sess, ^{
		dispatch_cancel(cpu_count_timer);

		check_tally("config", mch.ncpus, mch.nfixed + mch.nconfig, tly);

		struct rusage_info_v4 post_ru = {};
		int ruret = proc_pid_rusage(getpid(), RUSAGE_INFO_V4,
				(rusage_info_t *)&post_ru);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ruret, "got rusage information");

		T_LOG("saw %llu cycles in process", post_ru.ri_cycles - pre_ru.ri_cycles);
		uint64_t total = 0;

		unsigned int nsamplecpus = 0;
		char sample_slices[NTIMESLICES + 1];
		sample_slices[NTIMESLICES] = '\0';
		for (unsigned int i = 0; i < mch.ncpus; i++) {
			memset(sample_slices, '.', sizeof(sample_slices) - 1);

			struct cpu *cpu = &cpus[i];
			unsigned int nsampleslices = 0, ncpusamples = 0,
					last_contiguous = 0;
			bool seen_empty = false;
			for (unsigned int j = 0; j < NTIMESLICES; j++) {
				unsigned int nslice = cpu->timeslices[j];
				nsamples += nslice;
				ncpusamples += nslice;
				if (nslice > 0) {
					nsampleslices++;
					sample_slices[j] = '*';
				} else {
					seen_empty = true;
				}
				if (!seen_empty) {
					last_contiguous = j;
				}
			}
			unsigned int ctr = i * (mch.nfixed + mch.nconfig) + mch.nfixed;
			uint64_t delta = tly[ctr].lastvalue - tly[ctr].firstvalue;
			T_LOG("%g GHz", (double)delta / (last_check_ns - first_check_ns));
			total += delta;
			T_LOG("CPU %2u: %4u/%u, %6u/%llu, max skid = %llu (%.1f%%), "
					"last contiguous = %u", i,
					nsampleslices, NTIMESLICES, ncpusamples, delta / PMI_PERIOD,
					cpu->max_skid, (double)cpu->max_skid / PMI_PERIOD * 100,
					last_contiguous);
			T_LOG("%s", sample_slices);
			if (nsampleslices > 0) {
				nsamplecpus++;
			}
			T_EXPECT_EQ(last_contiguous, NTIMESLICES - 1,
					"CPU %2u: saw samples in each time slice", i);
		}
		T_LOG("kpc reported %llu total cycles", total);
		T_LOG("saw %u sample events, across %u/%u cpus", nsamples, nsamplecpus,
				mch.ncpus);
		T_END;
	});

	int dbglvl = 3;
	ret = sysctlbyname("kperf.debug_level", NULL, NULL, &dbglvl,
	    sizeof(dbglvl));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "set kperf debug level");
	ret = kperf_sample_set(1);
	T_ASSERT_POSIX_SUCCESS(ret, "kperf_sample_set");

	start_kpc();

	int error = ktrace_start(sess, dispatch_get_main_queue());
	T_ASSERT_POSIX_ZERO(error, "started tracing");

	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, PMI_TEST_DURATION_NS),
			dispatch_get_main_queue(), ^{
		T_LOG("ending tracing after timeout");
		kdebug_trace(END_EVENT, 0, 0, 0, 0);
	});

	dispatch_activate(cpu_count_timer);

	T_SETUPEND;

	dispatch_main();
}

#if defined(__arm64__)
// This policy only applies to arm64 devices.

static int g_prev_disablewl = 0;

static void
whitelist_atend(void)
{
	int ret = sysctlbyname("kpc.disable_whitelist", NULL, NULL,
	    &g_prev_disablewl, sizeof(g_prev_disablewl));
	if (ret < 0) {
		T_LOG("failed to reset whitelist: %d (%s)", errno, strerror(errno));
	}
}

T_DECL(whitelist, "ensure kpc's whitelist is filled out")
{
	// Start enforcing the whitelist.
	int set = 0;
	size_t getsz = sizeof(g_prev_disablewl);
	int ret = sysctlbyname("kpc.disable_whitelist", &g_prev_disablewl, &getsz,
	    &set, sizeof(set));
	if (ret < 0 && errno == ENOENT) {
		T_SKIP("kpc not running with a whitelist, or RELEASE kernel");
	}

	T_ASSERT_POSIX_SUCCESS(ret, "started enforcing the event whitelist");
	T_ATEND(whitelist_atend);

	uint32_t nconfigs = kpc_get_config_count(KPC_CLASS_CONFIGURABLE_MASK);
	uint64_t *config = calloc(nconfigs, sizeof(*config));

	// Check that events in the whitelist are allowed.  CORE_CYCLE (0x2) is
	// always present in the whitelist.
	config[0] = 0x02;
	ret = kpc_set_config(KPC_CLASS_CONFIGURABLE_MASK, config);
	T_ASSERT_POSIX_SUCCESS(ret, "configured kpc to count cycles");

	// Check that non-event bits are ignored by the whitelist.
	config[0] = 0x102;
	ret = kpc_set_config(KPC_CLASS_CONFIGURABLE_MASK, config);
	T_ASSERT_POSIX_SUCCESS(ret,
	    "configured kpc to count cycles with non-event bits set");

	// Check that configurations of non-whitelisted events fail.
	config[0] = 0xfe;
	ret = kpc_set_config(KPC_CLASS_CONFIGURABLE_MASK, config);
	T_ASSERT_POSIX_FAILURE(ret, EPERM,
	    "shouldn't allow arbitrary events with whitelist enabled");

	// Clean up the configuration.
	config[0] = 0;
	(void)kpc_set_config(KPC_CLASS_CONFIGURABLE_MASK, config);

	free(config);
}

#endif // defined(__arm64__)
