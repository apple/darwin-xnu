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

#ifndef _PRNG_ENTROPY_H_
#define _PRNG_ENTROPY_H_

#include <kern/kern_types.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

// This module is used to accumulate entropy from hardware interrupts
// for consumption by a higher-level PRNG.
//
// The raw entropy samples are collected from CPU counters during
// hardware interrupts. We do not perform synchronization before
// reading the counter (unlike ml_get_timebase and similar functions).
//
// This entropy accumulator performs continuous health tests in
// accordance with NIST SP 800-90B. The parameters have been chosen
// with the expectation that test failures should never occur except
// in case of catastrophic hardware failure.

typedef uint32_t entropy_sample_t;

// Called during startup to initialize internal data structures.
void entropy_init(void);

// Called during hardware interrupts to collect entropy in per-CPU
// structures.
void entropy_collect(void);

// Called by the higher-level PRNG. The module performs continuous
// health tests and decides whether to release entropy based on the
// values of various counters. Returns negative in case of error
// (e.g. health test failure).
int32_t entropy_provide(size_t *entropy_size, void *entropy, void *arg);

extern entropy_sample_t *entropy_analysis_buffer;
extern uint32_t entropy_analysis_buffer_size;

typedef struct entropy_health_stats {
	// A total count of times the test has been reset with a new
	// initial observation. This can be thought of as the number of
	// tests, but note that a single "test" can theoretically accrue
	// multiple failures.
	uint32_t reset_count;

	// A total count of failures of this test instance since
	// boot. Since we do not expect any test failures (ever) in
	// practice, this counter should always be zero.
	uint32_t failure_count;

	// The maximum count of times an initial observation has recurred
	// across all instances of this test.
	uint32_t max_observation_count;
} entropy_health_stats_t;

extern int entropy_health_startup_done;
extern entropy_health_stats_t entropy_health_rct_stats;
extern entropy_health_stats_t entropy_health_apt_stats;

__END_DECLS

#endif /* _PRNG_ENTROPY_H_ */
