/* * Copyright (c) 2020 Apple Inc. All rights reserved.
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

/* sysctl interface for testing percpu counters in DEBUG or DEVELOPMENT kernel only. */
#if !(DEVELOPMENT || DEBUG)
#error "Counter testing is not enabled on RELEASE configurations"
#endif

#include <sys/sysctl.h>
#include <kern/counter.h>
#include <machine/atomic.h>
#include <libkern/libkern.h>
#include <machine/machine_routines.h>
#include <kern/cpu_data.h>

#include <os/log.h>

#ifdef CONFIG_XNUPOST
#include <tests/xnupost.h>
#endif /* CONFIG_XNUPOST */

static _Atomic boolean_t scalable_counter_test_running = FALSE;
scalable_counter_t test_scalable_counter;

SCALABLE_COUNTER_DEFINE(test_static_scalable_counter);

#ifdef CONFIG_XNUPOST
kern_return_t counter_tests(void);
/*
 * Sanity test that a counter can be modified before zalloc is initialized.
 */
static void
bump_static_counter(void* arg)
{
	(void) arg;
	counter_inc(&test_static_scalable_counter);
}

STARTUP_ARG(PMAP_STEAL, STARTUP_RANK_MIDDLE, bump_static_counter, NULL);

kern_return_t
counter_tests()
{
	T_ASSERT_EQ_ULLONG(counter_load(&test_static_scalable_counter), 1, "Counter was incremented");
	return KERN_SUCCESS;
}
#endif /* CONFIG_XNUPOST */

static int
sysctl_scalable_counter_test_start SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int ret_val = 1;
	int error = 0;
	boolean_t exclusive;
	error = sysctl_io_number(req, ret_val, sizeof(int), &ret_val, NULL);
	if (error || !req->newptr) {
		return error;
	}
	/* The test doesn't support being run multiple times in parallel. */
	exclusive = os_atomic_cmpxchg(&scalable_counter_test_running, FALSE, TRUE, seq_cst);
	if (!exclusive) {
		os_log(OS_LOG_DEFAULT, "scalable_counter_test: Caught attempt to run the test in parallel.");
		return EINVAL;
	}
	counter_alloc(&test_scalable_counter);
	return 0;
}

static int
sysctl_scalable_counter_test_finish SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	boolean_t exclusive;
	int ret_val = 0;
	int error = 0;
	error = sysctl_io_number(req, ret_val, sizeof(int), &ret_val, NULL);
	if (error || !req->newptr) {
		return error;
	}

	/* The test doesn't support being run multiple times in parallel. */
	exclusive = os_atomic_cmpxchg(&scalable_counter_test_running, TRUE, FALSE, seq_cst);
	if (!exclusive) {
		/* Finish called without start. */
		return EINVAL;
	}
	return 0;
}

static int
sysctl_scalable_counter_add SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int64_t value = 0;
	int error = 0;
	if (!os_atomic_load(&scalable_counter_test_running, seq_cst)) {
		/* Must call start */
		return EINVAL;
	}
	error = sysctl_io_number(req, value, sizeof(int64_t), &value, NULL);
	if (error || !req->newptr) {
		return error;
	}
	counter_add(&test_scalable_counter, value);
	return 0;
}

static int
sysctl_static_scalable_counter_add SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int64_t value = 0;
	int error = 0;
	if (!os_atomic_load(&scalable_counter_test_running, seq_cst)) {
		/* Must call start */
		return EINVAL;
	}
	error = sysctl_io_number(req, value, sizeof(int64_t), &value, NULL);
	if (error || !req->newptr) {
		return error;
	}
	counter_add(&test_static_scalable_counter, value);
	return 0;
}

static int
sysctl_scalable_counter_load SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	uint64_t value;
	if (!os_atomic_load(&scalable_counter_test_running, seq_cst)) {
		/* Must call start */
		return EINVAL;
	}
	value = counter_load(&test_scalable_counter);
	return SYSCTL_OUT(req, &value, sizeof(value));
}

static int
sysctl_scalable_counter_write_benchmark SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error;
	int64_t iterations;
	int ret_val = 0;
	if (!os_atomic_load(&scalable_counter_test_running, seq_cst)) {
		/* Must call start */
		return EINVAL;
	}
	error = sysctl_io_number(req, ret_val, sizeof(int), &iterations, NULL);
	if (error || !req->newptr) {
		return error;
	}
	for (int64_t i = 0; i < iterations; i++) {
		counter_inc(&test_scalable_counter);
	}
	return 0;
}

static volatile uint64_t racy_counter;

static int
sysctl_racy_counter_write_benchmark SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error;
	int64_t iterations;
	int ret_val = 0;
	error = sysctl_io_number(req, ret_val, sizeof(int), &iterations, NULL);
	if (error || !req->newptr) {
		return error;
	}
	for (int64_t i = 0; i < iterations; i++) {
		racy_counter++;
	}
	return 0;
}

static int
sysctl_racy_counter_load SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	uint64_t value = racy_counter;
	return SYSCTL_OUT(req, &value, sizeof(value));
}

static _Atomic uint64_t atomic_counter;

static int
sysctl_atomic_counter_write_benchmark SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error;
	int64_t iterations;
	int ret_val = 0;
	error = sysctl_io_number(req, ret_val, sizeof(int), &iterations, NULL);
	if (error || !req->newptr) {
		return error;
	}
	for (int64_t i = 0; i < iterations; i++) {
		os_atomic_add(&atomic_counter, 1, relaxed);
	}
	return 0;
}

static int
sysctl_atomic_counter_load SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	uint64_t value = os_atomic_load_wide(&atomic_counter, relaxed);
	return SYSCTL_OUT(req, &value, sizeof(value));
}

SYSCTL_PROC(_kern, OID_AUTO, scalable_counter_test_start,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MASKED | CTLFLAG_LOCKED,
    0, 0, sysctl_scalable_counter_test_start, "I", "Setup per-cpu counter test");

SYSCTL_PROC(_kern, OID_AUTO, scalable_counter_test_finish,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MASKED | CTLFLAG_LOCKED,
    0, 0, sysctl_scalable_counter_test_finish, "I", "Finish per-cpu counter test");

SYSCTL_PROC(_kern, OID_AUTO, scalable_counter_test_add,
    CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_MASKED | CTLFLAG_LOCKED,
    0, 0, sysctl_scalable_counter_add, "I", "Perform an add on the per-cpu counter");

SYSCTL_PROC(_kern, OID_AUTO, static_scalable_counter_test_add,
    CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_MASKED | CTLFLAG_LOCKED,
    0, 0, sysctl_static_scalable_counter_add, "I", "Perform an add on the static per-cpu counter");

SYSCTL_PROC(_kern, OID_AUTO, scalable_counter_test_load,
    CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_MASKED | CTLFLAG_LOCKED,
    0, 0, sysctl_scalable_counter_load, "I", "Load the current per-cpu counter value.");

SYSCTL_SCALABLE_COUNTER(_kern, static_scalable_counter_test_load,
    test_static_scalable_counter, "Load the current static per-cpu counter value.");

SYSCTL_PROC(_kern, OID_AUTO, scalable_counter_write_benchmark,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MASKED | CTLFLAG_LOCKED,
    0, 0, sysctl_scalable_counter_write_benchmark, "I", "Per-cpu counter write benchmark");

SYSCTL_PROC(_kern, OID_AUTO, scalable_counter_racy_counter_benchmark,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MASKED | CTLFLAG_LOCKED,
    0, 0, sysctl_racy_counter_write_benchmark, "I", "Global counter racy benchmark");

SYSCTL_PROC(_kern, OID_AUTO, scalable_counter_racy_counter_load,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MASKED | CTLFLAG_LOCKED,
    0, 0, sysctl_racy_counter_load, "I", "Global counter racy load");

SYSCTL_PROC(_kern, OID_AUTO, scalable_counter_atomic_counter_write_benchmark,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MASKED | CTLFLAG_LOCKED,
    0, 0, sysctl_atomic_counter_write_benchmark, "I", "Atomic counter write benchmark");

SYSCTL_PROC(_kern, OID_AUTO, scalable_counter_atomic_counter_load,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MASKED | CTLFLAG_LOCKED,
    0, 0, sysctl_atomic_counter_load, "I", "Atomic counter load");
