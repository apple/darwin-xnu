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
 * Copyright (c) 1992 NeXT Computer, Inc.
 *
 * Machine dependent kernel calls.
 *
 * HISTORY
 *
 * 17 June 1992 ? at NeXT
 *	Created.
 */

#include <kern/thread.h>
#include <mach/mach_types.h>
#include <arm/machdep_call.h>
#if __arm64__
#include <arm64/machine_machdep.h>
#endif

extern kern_return_t kern_invalid(void);

uintptr_t
get_tpidrro(void)
{
	uintptr_t       uthread;
#if __arm__
	uthread = __builtin_arm_mrc(15, 0, 13, 0, 3);   // TPIDRURO
#else
	__asm__ volatile ("mrs %0, TPIDRRO_EL0" : "=r" (uthread));
#endif
	return uthread;
}

void
set_tpidrro(uintptr_t uthread)
{
#if __arm__
	__builtin_arm_mcr(15, 0, uthread, 13, 0, 3);    // TPIDRURO
#else
	__asm__ volatile ("msr TPIDRRO_EL0, %0" : : "r" (uthread));
#endif
}

kern_return_t
thread_set_cthread_self(vm_address_t self)
{
	return machine_thread_set_tsd_base(current_thread(), self);
}

vm_address_t
thread_get_cthread_self(void)
{
	uintptr_t       self;

	self = get_tpidrro();
#if __arm__
	self &= ~3;
	assert( self == current_thread()->machine.cthread_self);
	return (kern_return_t) current_thread()->machine.cthread_self;
#else
	self &= MACHDEP_CTHREAD_MASK;
	assert( self == current_thread()->machine.cthread_self);
	return self;
#endif
}
