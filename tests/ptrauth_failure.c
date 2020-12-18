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
#include <ptrauth.h>
#include <mach/machine/thread_state.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include "exc_helpers.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm"),
	T_META_RUN_CONCURRENTLY(true)
	);


T_DECL(thread_set_state_corrupted_pc,
    "Test that ptrauth failures in thread_set_state() poison the respective register.")
{
#if !__arm64e__
	T_SKIP("Running on non-arm64e target, skipping...");
#else
	mach_port_t thread;
	kern_return_t err = thread_create(mach_task_self(), &thread);
	T_QUIET; T_ASSERT_EQ(err, KERN_SUCCESS, "Created thread");

	arm_thread_state64_t state;
	mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
	err = thread_get_state(mach_thread_self(), ARM_THREAD_STATE64, (thread_state_t)&state, &count);
	T_QUIET; T_ASSERT_EQ(err, KERN_SUCCESS, "Got own thread state");

	void *corrupted_pc = (void *)((uintptr_t)state.__opaque_pc ^ 0x4);
	state.__opaque_pc = corrupted_pc;
	err = thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, count);
	T_QUIET; T_ASSERT_EQ(err, KERN_SUCCESS, "Set child thread's PC to a corrupted pointer");

	err = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, &count);
	T_QUIET; T_ASSERT_EQ(err, KERN_SUCCESS, "Got child's thread state");
	T_EXPECT_NE(state.__opaque_pc, corrupted_pc, "thread_set_state() with a corrupted PC should poison the PC value");

	err = thread_terminate(thread);
	T_QUIET; T_EXPECT_EQ(err, KERN_SUCCESS, "Terminated thread");
#endif // __arm64e__
}

