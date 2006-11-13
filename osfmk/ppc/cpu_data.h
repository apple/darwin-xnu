/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 * 
 */

#ifndef	PPC_CPU_DATA
#define PPC_CPU_DATA

#ifdef	MACH_KERNEL_PRIVATE

#include <mach/mach_types.h>
#include <machine/thread.h>

extern thread_t current_thread(void);
extern __inline__ thread_t current_thread(void) 
{
	thread_t	result;

	__asm__ volatile("mfsprg %0,1" : "=r" (result));

	return (result);
}

#define	getPerProc()		current_thread()->machine.PerProc

extern int 					get_preemption_level(void);
extern void 					_enable_preemption_no_check(void);

#define enable_preemption_no_check()		_enable_preemption_no_check()
#define mp_disable_preemption()			_disable_preemption()
#define mp_enable_preemption()			_enable_preemption()
#define mp_enable_preemption_no_check()		_enable_preemption_no_check()

#endif	/* MACH_KERNEL_PRIVATE */

#endif	/* PPC_CPU_DATA */
