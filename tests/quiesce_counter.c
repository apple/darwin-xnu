/*
 * Copyright (c) 2018 Apple Inc. All rights reserved.
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

/*
 * Test to validate that _COMM_PAGE_CPU_QUIESCENT_COUNTER ticks at least once per second
 *
 * <rdar://problem/42433973>
 */

#include <System/machine/cpu_capabilities.h>

#include <darwintest.h>

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/sysctl.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

#ifndef _COMM_PAGE_CPU_QUIESCENT_COUNTER

T_DECL(test_quiescent_counter, "Validate that _COMM_PAGE_CPU_QUIESCENT_COUNTER increments",
    T_META_CHECK_LEAKS(false))
{
	T_SKIP("_COMM_PAGE_CPU_QUIESCENT_COUNTER doesn't exist on this system");
}

#else /* _COMM_PAGE_CPU_QUIESCENT_COUNTER */

T_DECL(test_quiescent_counter, "Validate that _COMM_PAGE_CPU_QUIESCENT_COUNTER increments",
    T_META_CHECK_LEAKS(false))
{
	int rv;

	uint32_t cpu_checkin_min_interval = 0; /* set by sysctl hw.ncpu */

	size_t value_size = sizeof(cpu_checkin_min_interval);
	rv = sysctlbyname("kern.cpu_checkin_interval", &cpu_checkin_min_interval, &value_size, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(rv, "sysctlbyname(kern.cpu_checkin_interval)");

	T_LOG("kern.cpu_checkin_interval is %d", cpu_checkin_min_interval);

	T_ASSERT_GT(cpu_checkin_min_interval, 0, "kern.cpu_checkin_interval should be > 0");

	uint64_t* commpage_addr = (uint64_t *)(uintptr_t)_COMM_PAGE_CPU_QUIESCENT_COUNTER;

	T_LOG("address of _COMM_PAGE_CPU_QUIESCENT_COUNTER is %p", (void*) commpage_addr);

	uint64_t counter = *commpage_addr;
	uint64_t last_counter = counter;
	T_LOG("first value of _COMM_PAGE_CPU_QUIESCENT_COUNTER is %llu", counter);

	for (int i = 0; i < 10; i++) {
		sleep(1);

		last_counter = counter;
		counter = *commpage_addr;

		T_LOG("value of _COMM_PAGE_CPU_QUIESCENT_COUNTER is %llu", counter);

		T_ASSERT_GT(counter, last_counter, "_COMM_PAGE_CPU_QUIESCENT_COUNTER must monotonically increase at least once per second");
	}
}

#endif /* _COMM_PAGE_CPU_QUIESCENT_COUNTER */
