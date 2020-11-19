/*
 * Copyright (c) 2019 Apple Computer, Inc. All rights reserved.
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

#include <darwintest.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/sysctl.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm"),
	T_META_RUN_CONCURRENTLY(true));

T_DECL(x18_preserved,
    "Test that x18 is preserved on hardware that supports it.")
{
#ifndef __arm64__
	T_SKIP("Running on non-arm64 target, skipping...");
#else
	int arm_kernel_protect = 0;
	size_t arm_kernel_protect_size = sizeof(arm_kernel_protect);
	bool preserved = true;

	int err = sysctlbyname("hw.optional.arm_kernel_protect", &arm_kernel_protect, &arm_kernel_protect_size, NULL, 0);
	if (err) {
		T_SKIP("Could not determine state of __ARM_KERNEL_PROTECT__, skipping...");
	}
	if (arm_kernel_protect) {
		preserved = false;
	}

	uint64_t x18_val;
	for (uint64_t i = 0xFEEDB0B000000000ULL; i < 0xFEEDB0B000000000ULL + 10000; ++i) {
		asm volatile ("mov x18, %0" : : "r"(i));
		sched_yield();
		asm volatile ("mov %0, x18" : "=r"(x18_val));
		if (preserved) {
			T_QUIET; T_ASSERT_EQ(x18_val, i, "check that x18 reads back correctly after yield");
		} else {
			T_QUIET; T_ASSERT_EQ(x18_val, 0ULL, "check that x18 is cleared after yield");
		}
	}
#endif
}
