/*
 * Copyright (c) 2012 Apple Inc. All rights reserved.
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
#include <debug.h>
#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <mach/thread_status.h>
#include <kern/thread.h>
#include <kern/kalloc.h>
#include <arm/vmparam.h>
#include <arm/cpu_data_internal.h>

/*
 * Copy values from saved_state to ts32.
 */
void
saved_state_to_thread_state32(const arm_saved_state_t *saved_state, arm_thread_state32_t *ts32)
{
	uint32_t i;

	assert(is_saved_state32(saved_state));

	ts32->lr = (uint32_t)get_saved_state_lr(saved_state);
	ts32->sp = (uint32_t)get_saved_state_sp(saved_state);
	ts32->pc = (uint32_t)get_saved_state_pc(saved_state);
	ts32->cpsr = get_saved_state_cpsr(saved_state);
	for (i = 0; i < 13; i++) {
		ts32->r[i] = (uint32_t)get_saved_state_reg(saved_state, i);
	}
}

/*
 * Copy values from ts32 to saved_state.
 */
void
thread_state32_to_saved_state(const arm_thread_state32_t *ts32, arm_saved_state_t *saved_state)
{
	uint32_t i;

	assert(is_saved_state32(saved_state));

	set_saved_state_lr(saved_state, ts32->lr);
	set_saved_state_sp(saved_state, ts32->sp);
	set_saved_state_pc(saved_state, ts32->pc);

#if defined(__arm64__)
	set_saved_state_cpsr(saved_state, (ts32->cpsr & ~PSR64_MODE_MASK) | PSR64_MODE_RW_32);
#elif defined(__arm__)
	set_saved_state_cpsr(saved_state, (ts32->cpsr & ~PSR_USER_MASK) | (ts32->cpsr & PSR_USER_MASK));
#else
#error Unknown architecture.
#endif

	for (i = 0; i < 13; i++) {
		set_saved_state_reg(saved_state, i, ts32->r[i]);
	}
}
