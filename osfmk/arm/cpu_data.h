/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 * 
 */

#ifndef	ARM_CPU_DATA
#define ARM_CPU_DATA

#ifdef  MACH_KERNEL_PRIVATE

#include <mach_assert.h>
#include <kern/assert.h>
#include <kern/kern_types.h>
#include <kern/processor.h>
#include <pexpert/pexpert.h>
#include <arm/thread.h>
#include <arm/proc_reg.h>

#include <mach/mach_types.h>
#include <machine/thread.h>


#define current_thread()	current_thread_fast()

static inline thread_t current_thread_fast(void) 
{
        thread_t        result;
#if defined(__arm64__)
        __asm__ volatile("mrs %0, TPIDR_EL1" : "=r" (result));
#else
	result = (thread_t)__builtin_arm_mrc(15, 0, 13, 0, 4);	// TPIDRPRW
#endif
        return result;
}

#if defined(__arm64__)

static inline vm_offset_t exception_stack_pointer(void)
{
	vm_offset_t result = 0;
	__asm__ volatile(
		"msr		SPSel, #1  \n"
		"mov		%0, sp     \n"
		"msr		SPSel, #0  \n"
		: "=r" (result));

	return result;
}

#endif /* defined(__arm64__) */

#define getCpuDatap()            current_thread()->machine.CpuDatap
#define current_cpu_datap()	 getCpuDatap()

extern int 									get_preemption_level(void);
extern void 								_enable_preemption_no_check(void);

#define enable_preemption_no_check()		_enable_preemption_no_check()
#define mp_disable_preemption()				_disable_preemption()
#define mp_enable_preemption()				_enable_preemption()
#define mp_enable_preemption_no_check()		_enable_preemption_no_check()

#endif  /* MACH_KERNEL_PRIVATE */

#endif	/* ARM_CPU_DATA */
