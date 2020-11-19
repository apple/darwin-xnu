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

#include <stdlib.h>
#include <darwintest.h>
#include <mach/mach.h>
#include <mach/thread_status.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm"),
	T_META_RUN_CONCURRENTLY(true)
	);

#define PSR64_USER_MASK (0xFU << 28)

#if __arm64__
__attribute__((noreturn))
static void
phase2()
{
	kern_return_t err;
	arm_thread_state64_t ts;
	mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
	uint32_t nzcv = (uint32_t) __builtin_arm_rsr64("NZCV");

	T_QUIET; T_ASSERT_EQ(nzcv & PSR64_USER_MASK, PSR64_USER_MASK, "All condition flags are set");

	err = thread_get_state(mach_thread_self(), ARM_THREAD_STATE64, (thread_state_t)&ts, &count);
	T_QUIET; T_ASSERT_EQ(err, KERN_SUCCESS, "Got own thread state after corrupting CPSR");

	T_QUIET; T_ASSERT_EQ(ts.__cpsr & ~PSR64_USER_MASK, 0, "No privileged fields in CPSR are set");

	exit(0);
}
#endif

T_DECL(thread_set_state_arm64_cpsr,
    "Test that user mode cannot control privileged fields in CPSR/PSTATE.")
{
#if !__arm64__
	T_SKIP("Running on non-arm64 target, skipping...");
#else
	kern_return_t err;
	mach_msg_type_number_t count;
	arm_thread_state64_t ts;

	count = ARM_THREAD_STATE64_COUNT;
	err = thread_get_state(mach_thread_self(), ARM_THREAD_STATE64, (thread_state_t)&ts, &count);
	T_QUIET; T_ASSERT_EQ(err, KERN_SUCCESS, "Got own thread state");

	/*
	 * jump to the second phase while attempting to set all the bits
	 * in CPSR. If we survive the jump and read back CPSR without any
	 * bits besides condition flags set, the test passes. If kernel
	 * does not mask out the privileged CPSR bits correctly, we can
	 * expect an illegal instruction set panic due to SPSR.IL being
	 * set upon ERET to user mode.
	 */

	void *new_pc = (void *)&phase2;
	arm_thread_state64_set_pc_fptr(ts, new_pc);
	ts.__cpsr = ~0U;

	err = thread_set_state(mach_thread_self(), ARM_THREAD_STATE64, (thread_state_t)&ts, ARM_THREAD_STATE64_COUNT);

	/* NOT REACHED */

	T_ASSERT_FAIL("Thread did not reach expected state. err = %d", err);

#endif
}
