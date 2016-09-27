/*
 * Copyright (c) 2003-2009 Apple Inc. All rights reserved.
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

#include <mach/mach_types.h>
#include <mach/task.h>
#include <mach/thread_act.h>

#include <kern/kern_types.h>
#include <kern/processor.h>
#include <kern/thread.h>
#include <kern/kalloc.h>

#include <chud/chud_xnu.h>
#include <chud/chud_xnu_private.h>
#include <chud/chud_thread.h>

#include <machine/machine_routines.h>

#include <libkern/OSAtomic.h>

#if KPC
#include <kern/kpc.h>
#endif

#if KPERF
#include <kperf/kperf.h>
#endif

// include the correct file to find real_ncpus
#if defined(__i386__) || defined(__x86_64__)
#	include <i386/mp.h>	
#else
// fall back on declaring it extern.  The linker will sort us out.
extern unsigned int real_ncpus;
#endif

// Mask for supported options
#define T_CHUD_BIND_OPT_MASK (-1UL)

#if 0
#pragma mark **** thread binding ****
#endif

/*
 * This method will bind a given thread to the requested CPU starting at the
 * next time quantum.  If the thread is the current thread, this method will
 * force a thread_block().  The result is that if you call this method on the
 * current thread, you will be on the requested CPU when this method returns.
 */
__private_extern__ kern_return_t
chudxnu_bind_thread(thread_t thread, int cpu, __unused int options)
{
    processor_t proc = NULL;

	if(cpu < 0 || (unsigned int)cpu >= real_ncpus) // sanity check
		return KERN_FAILURE;

	// temporary restriction until after phase 2 of the scheduler
	if(thread != current_thread())
		return KERN_FAILURE; 
	
	proc = cpu_to_processor(cpu);

	/* 
	 * Potentially racey, but mainly to prevent bind to shutdown
	 * processor.
	 */
	if(proc && !(proc->state == PROCESSOR_OFF_LINE) &&
			!(proc->state == PROCESSOR_SHUTDOWN)) {
		
		thread_bind(proc);

		/*
		 * If we're trying to bind the current thread, and
		 * we're not on the target cpu, and not at interrupt
		 * context, block the current thread to force a
		 * reschedule on the target CPU.
		 */
		if(thread == current_thread() && 
			!ml_at_interrupt_context() && cpu_number() != cpu) {
			(void)thread_block(THREAD_CONTINUE_NULL);
		}
		return KERN_SUCCESS;
	}
    return KERN_FAILURE;
}

__private_extern__ kern_return_t
chudxnu_unbind_thread(thread_t thread, __unused int options)
{
	if(thread == current_thread())
		thread_bind(PROCESSOR_NULL);
    return KERN_SUCCESS;
}
