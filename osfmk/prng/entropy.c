/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <libkern/crypto/sha2.h>
#include <libkern/crypto/crypto_internal.h>
#include <os/atomic_private.h>
#include <kern/assert.h>
#include <kern/percpu.h>
#include <kern/zalloc.h>
#include <kern/lock_group.h>
#include <kern/locks.h>
#include <kern/misc_protos.h>
#include <pexpert/pexpert.h>
#include <prng/entropy.h>
#include <crypto/entropy/entropy_sysctl.h>
#include <machine/machine_routines.h>
#include <libkern/section_keywords.h>
#include <sys/cdefs.h>

// The number of samples we can hold in an entropy buffer.
#define ENTROPY_MAX_SAMPLE_COUNT (2048)

// The state for a per-CPU entropy buffer.
typedef struct entropy_cpu_data {
	// A buffer to hold entropy samples.
	entropy_sample_t samples[ENTROPY_MAX_SAMPLE_COUNT];

	// A count of samples resident in the buffer. It also functions as
	// an index to the buffer. All entries at indices less than the
	// sample count are considered valid for consumption by the
	// reader. The reader resets this to zero after consuming the
	// available entropy.
	uint32_t _Atomic sample_count;
} entropy_cpu_data_t;

// This structure holds the state for an instance of a FIPS continuous
// health test. In practice, we do not expect these tests to fail.
typedef struct entropy_health_test {
	// The initial sample observed in this test instance. Tests look
	// for some repetition of the sample, either consecutively or
	// within a window.
	entropy_sample_t init_observation;

	// The count of times the initial observation has recurred within
	// the span of the current test.
	uint64_t observation_count;

	// The statistics are only relevant for telemetry and parameter
	// tuning. They do not drive any actual logic in the module.
	entropy_health_stats_t *stats;
} entropy_health_test_t;

typedef enum health_test_result {
	health_test_failure,
	health_test_success
} health_test_result_t;

// Along with various counters and the buffer itself, this includes
// the state for two FIPS continuous health tests.
typedef struct entropy_data {
	// State for a SHA256 computation. This is used to accumulate
	// entropy samples from across all CPUs. It is finalized when
	// entropy is provided to the consumer of this module.
	SHA256_CTX sha256_ctx;

	// Since the corecrypto kext is not loaded when this module is
	// initialized, we cannot initialize the SHA256 state at that
	// time. Instead, we initialize it lazily during entropy
	// consumption. This flag tracks whether initialization is
	// complete.
	bool sha256_ctx_init;

	// A total count of entropy samples that have passed through this
	// structure. It is incremented as new samples are accumulated
	// from the various per-CPU structures. The "current" count of
	// samples is the difference between this field and the "read"
	// sample count below (which see).
	uint64_t total_sample_count;

	// Initially zero, this flag is reset to the current sample count
	// if and when we fail a health test. We consider the startup
	// health tests to be complete when the difference between the
	// total sample count and this field is at least 1024. In other
	// words, we must accumulate 1024 good samples to demonstrate
	// viability. We refuse to provide any entropy before that
	// threshold is reached.
	uint64_t startup_sample_count;

	// The count of samples from the last time we provided entropy to
	// the kernel RNG. We use this to compute how many new samples we
	// have to contribute. This value is also reset to the current
	// sample count in case of health test failure.
	uint64_t read_sample_count;

	// The lock group for this structure; see below.
	lck_grp_t lock_group;

	// This structure accumulates entropy samples from across all CPUs
	// for a single point of consumption protected by a mutex.
	lck_mtx_t mutex;

	// State for the Repetition Count Test.
	entropy_health_test_t repetition_count_test;

	// State for the Adaptive Proportion Test.
	entropy_health_test_t adaptive_proportion_test;
} entropy_data_t;

static entropy_cpu_data_t PERCPU_DATA(entropy_cpu_data);

int entropy_health_startup_done;
entropy_health_stats_t entropy_health_rct_stats;
entropy_health_stats_t entropy_health_apt_stats;

static entropy_data_t entropy_data = {
	.repetition_count_test = {
		.init_observation = -1,
		.stats = &entropy_health_rct_stats,
	},
	.adaptive_proportion_test = {
		.init_observation = -1,
		.stats = &entropy_health_apt_stats,
	},
};

__security_const_late entropy_sample_t *entropy_analysis_buffer;
__security_const_late uint32_t entropy_analysis_buffer_size;
static __security_const_late uint32_t entropy_analysis_max_sample_count;
static uint32_t entropy_analysis_sample_count;

__startup_func
static void
entropy_analysis_init(uint32_t sample_count)
{
	entropy_analysis_max_sample_count = sample_count;
	entropy_analysis_buffer_size = sample_count * sizeof(entropy_sample_t);
	entropy_analysis_buffer = zalloc_permanent(entropy_analysis_buffer_size, ZALIGN(entropy_sample_t));
	entropy_analysis_register_sysctls();
}

__startup_func
void
entropy_init(void)
{
	lck_grp_init(&entropy_data.lock_group, "entropy-data", LCK_GRP_ATTR_NULL);
	lck_mtx_init(&entropy_data.mutex, &entropy_data.lock_group, LCK_ATTR_NULL);

	// The below path is used only for testing. This boot arg is used
	// to collect raw entropy samples for offline analysis. The "ebsz"
	// name is supported only until dependent tools can be updated to
	// use the more descriptive "entropy-analysis-sample-count".
	uint32_t sample_count = 0;
	if (__improbable(PE_parse_boot_argn("entropy-analysis-sample-count", &sample_count, sizeof(sample_count)))) {
		entropy_analysis_init(sample_count);
	} else if (__improbable(PE_parse_boot_argn("ebsz", &sample_count, sizeof(sample_count)))) {
		entropy_analysis_init(sample_count);
	}
}

void
entropy_collect(void)
{
	// This function is called from within the interrupt handler, so
	// we do not need to disable interrupts.

	entropy_cpu_data_t *e = PERCPU_GET(entropy_cpu_data);

	uint32_t sample_count = os_atomic_load(&e->sample_count, relaxed);

	assert(sample_count <= ENTROPY_MAX_SAMPLE_COUNT);

	// If the buffer is full, we return early without collecting
	// entropy.
	if (sample_count == ENTROPY_MAX_SAMPLE_COUNT) {
		return;
	}

	e->samples[sample_count] = (entropy_sample_t)ml_get_timebase_entropy();

	// If the consumer has reset the sample count on us, the only
	// consequence is a dropped sample. We effectively abort the
	// entropy collection in this case.
	(void)os_atomic_cmpxchg(&e->sample_count, sample_count, sample_count + 1, release);
}

// For information on the following tests, see NIST SP 800-90B 4
// Health Tests. These tests are intended to detect catastrophic
// degradations in entropy. As noted in that document:
//
// > Health tests are expected to raise an alarm in three cases:
// > 1. When there is a significant decrease in the entropy of the
// > outputs,
// > 2. When noise source failures occur, or
// > 3. When hardware fails, and implementations do not work
// > correctly.
//
// Each entropy accumulator declines to release entropy until the
// startup tests required by NIST are complete. In the event that a
// health test does fail, all entropy accumulators are reset and
// decline to release further entropy until their startup tests can be
// repeated.

static health_test_result_t
add_observation(entropy_health_test_t *t, uint64_t bound)
{
	t->observation_count += 1;
	t->stats->max_observation_count = MAX(t->stats->max_observation_count, (uint32_t)t->observation_count);
	if (__improbable(t->observation_count >= bound)) {
		t->stats->failure_count += 1;
		return health_test_failure;
	}

	return health_test_success;
}

static void
reset_test(entropy_health_test_t *t, entropy_sample_t observation)
{
	t->stats->reset_count += 1;
	t->init_observation = observation;
	t->observation_count = 1;
	t->stats->max_observation_count = MAX(t->stats->max_observation_count, (uint32_t)t->observation_count);
}

// 4.4.1 Repetition Count Test
//
// Like the name implies, this test counts consecutive occurrences of
// the same value.
//
// We compute the bound C as:
//
// A = 2^-128
// H = 1
// C = 1 + ceil(-log(A, 2) / H) = 129
//
// With A the acceptable chance of false positive and H a conservative
// estimate for the entropy (in bits) of each sample.

#define REPETITION_COUNT_BOUND (129)

static health_test_result_t
repetition_count_test(entropy_sample_t observation)
{
	entropy_health_test_t *t = &entropy_data.repetition_count_test;

	if (t->init_observation == observation) {
		return add_observation(t, REPETITION_COUNT_BOUND);
	} else {
		reset_test(t, observation);
	}

	return health_test_success;
}

// 4.4.2 Adaptive Proportion Test
//
// This test counts occurrences of a value within a window of samples.
//
// We use a non-binary alphabet, giving us a window size of 512. (In
// particular, we consider the least-significant byte of each time
// sample.)
//
// Assuming one bit of entropy, we can compute the binomial cumulative
// distribution function over 512 trials in SageMath as:
//
// k = var('k')
// f(x) = sum(binomial(512, k), k, x, 512) / 2^512
//
// We compute the bound C as the minimal x for which:
//
// f(x) < 2^-128
//
// Is true.
//
// Empirically, we have C = 400.

#define ADAPTIVE_PROPORTION_BOUND (400)
#define ADAPTIVE_PROPORTION_WINDOW (512)

// This mask definition requires the window be a power of two.
static_assert(__builtin_popcount(ADAPTIVE_PROPORTION_WINDOW) == 1);
#define ADAPTIVE_PROPORTION_INDEX_MASK (ADAPTIVE_PROPORTION_WINDOW - 1)

static health_test_result_t
adaptive_proportion_test(entropy_sample_t observation, uint32_t offset)
{
	entropy_health_test_t *t = &entropy_data.adaptive_proportion_test;

	// We work in windows of size ADAPTIVE_PROPORTION_WINDOW, so we
	// can compute our index by taking the entropy buffer's overall
	// sample count plus the offset of this observation modulo the
	// window size.
	uint32_t index = (entropy_data.total_sample_count + offset) & ADAPTIVE_PROPORTION_INDEX_MASK;

	if (index == 0) {
		reset_test(t, observation);
	} else if (t->init_observation == observation) {
		return add_observation(t, ADAPTIVE_PROPORTION_BOUND);
	}

	return health_test_success;
}

static health_test_result_t
entropy_health_test(uint32_t sample_count, entropy_sample_t *samples)
{
	health_test_result_t result = health_test_success;

	for (uint32_t i = 0; i < sample_count; i += 1) {
		// We only consider the low bits of each sample, since that is
		// where we expect the entropy to be concentrated.
		entropy_sample_t observation = samples[i] & 0xff;

		if (__improbable(repetition_count_test(observation) == health_test_failure)) {
			result = health_test_failure;
		}

		if (__improbable(adaptive_proportion_test(observation, i) == health_test_failure)) {
			result = health_test_failure;
		}
	}

	return result;
}

static void
entropy_analysis_store(uint32_t sample_count, entropy_sample_t *samples)
{
	lck_mtx_assert(&entropy_data.mutex, LCK_MTX_ASSERT_OWNED);

	sample_count = MIN(sample_count, (entropy_analysis_max_sample_count - entropy_analysis_sample_count));
	if (sample_count == 0) {
		return;
	}

	size_t size = sample_count * sizeof(samples[0]);
	memcpy(&entropy_analysis_buffer[entropy_analysis_sample_count], samples, size);
	entropy_analysis_sample_count += sample_count;
}

int32_t
entropy_provide(size_t *entropy_size, void *entropy, __unused void *arg)
{
#if (DEVELOPMENT || DEBUG)
	if (*entropy_size < SHA256_DIGEST_LENGTH) {
		panic("[entropy_provide] recipient entropy buffer is too small\n");
	}
#endif

	int32_t sample_count = 0;
	*entropy_size = 0;

	// The first call to this function comes while the corecrypto kext
	// is being loaded. We require SHA256 to accumulate entropy
	// samples.
	if (__improbable(!g_crypto_funcs)) {
		return sample_count;
	}

	// There is only one consumer (the kernel PRNG), but they could
	// try to consume entropy from different threads. We simply fail
	// if a consumption is already in progress.
	if (!lck_mtx_try_lock(&entropy_data.mutex)) {
		return sample_count;
	}

	// This only happens on the first call to this function. We cannot
	// perform this initialization in entropy_init because the
	// corecrypto kext is not loaded yet.
	if (__improbable(!entropy_data.sha256_ctx_init)) {
		SHA256_Init(&entropy_data.sha256_ctx);
		entropy_data.sha256_ctx_init = true;
	}

	health_test_result_t health_test_result = health_test_success;

	// We accumulate entropy from all CPUs.
	percpu_foreach(e, entropy_cpu_data) {
		// On each CPU, the sample count functions as an index into
		// the entropy buffer. All samples before that index are valid
		// for consumption.
		uint32_t cpu_sample_count = os_atomic_load(&e->sample_count, acquire);

		assert(cpu_sample_count <= ENTROPY_MAX_SAMPLE_COUNT);

		// The health test depends in part on the current state of
		// the entropy data, so we test the new sample before
		// accumulating it.
		if (__improbable(entropy_health_test(cpu_sample_count, e->samples) == health_test_failure)) {
			health_test_result = health_test_failure;
		}

		// We accumulate the samples regardless of whether the test
		// failed. It cannot hurt.
		entropy_data.total_sample_count += cpu_sample_count;
		SHA256_Update(&entropy_data.sha256_ctx, e->samples, cpu_sample_count * sizeof(e->samples[0]));

		// This code path is only used for testing. Its use is governed by
		// a boot arg; see its initialization above.
		if (__improbable(entropy_analysis_buffer)) {
			entropy_analysis_store(cpu_sample_count, e->samples);
		}

		// "Drain" the per-CPU buffer by resetting its sample count.
		os_atomic_store(&e->sample_count, 0, relaxed);
	}

	// We expect this never to happen.
	//
	// But if it does happen, we need to return negative to signal the
	// consumer (i.e. the kernel PRNG) that there has been a failure.
	if (__improbable(health_test_result == health_test_failure)) {
		entropy_health_startup_done = 0;
		entropy_data.startup_sample_count = entropy_data.total_sample_count;
		entropy_data.read_sample_count = entropy_data.total_sample_count;
		sample_count = -1;
		goto out;
	}

	// FIPS requires we pass our startup health tests before providing
	// any entropy. This condition is only true during startup and in
	// case of reset due to test failure.
	if (__improbable((entropy_data.total_sample_count - entropy_data.startup_sample_count) < 1024)) {
		goto out;
	}

	entropy_health_startup_done = 1;

	// The count of new samples from the consumer's perspective.
	int32_t n = (int32_t)(entropy_data.total_sample_count - entropy_data.read_sample_count);

	// For performance reasons, we require a small threshold of
	// samples to have built up before we provide any to the PRNG.
	if (n < 32) {
		goto out;
	}

	SHA256_Final(entropy, &entropy_data.sha256_ctx);
	SHA256_Init(&entropy_data.sha256_ctx);
	entropy_data.read_sample_count = entropy_data.total_sample_count;

	sample_count = n;
	*entropy_size = SHA256_DIGEST_LENGTH;

out:
	lck_mtx_unlock(&entropy_data.mutex);

	return sample_count;
}
