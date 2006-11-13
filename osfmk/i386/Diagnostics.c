/*
 * Copyright (c) 2005 Apple Computer, Inc. All rights reserved.
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
 * @OSF_FREE_COPYRIGHT@
 */
/*
 * @APPLE_FREE_COPYRIGHT@
 */

/*
 *	Author: Bill Angell, Apple
 *	Date:	10/auht-five
 *
 *	Random diagnostics
 *
 *	Try to keep the x86 selectors in-sync with the ppc selectors.
 *
 */


#include <kern/machine.h>
#include <kern/processor.h>
#include <mach/machine.h>
#include <mach/processor_info.h>
#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <kern/ipc_kobject.h>
#include <mach/vm_param.h>
#include <ipc/port.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_port.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/pmap.h>
#include <pexpert/pexpert.h>
#include <console/video_console.h>
#include <i386/cpu_data.h>
#include <i386/Diagnostics.h>
#include <i386/mp.h>
#include <i386/pmCPU.h>
#include <i386/tsc.h>
#include <i386/hpet.h>
#include <mach/i386/syscall_sw.h>

extern uint64_t lastNapClear;

diagWork        dgWork;
uint64_t        lastNapClear = 0ULL;
uint64_t        lastRuptClear = 0ULL;

typedef struct pmdata {
	uint64_t        pmNapDur;	/* Time since last query */
	pmStats_t       pmd;	/* Powermanagement statistics */
}               pmdata;



int 
diagCall64(__unused x86_saved_state_t * regs)
{
        panic("diagCall not yet supported for 64 bit tasks\n");
}


int 
diagCall(x86_saved_state_t * state)
{

	uint32_t        stk, curpos, i, j;
	uint32_t        selector, data;
	int             err;
	uint64_t        currNap, durNap;
	x86_saved_state32_t	*regs;

	assert(is_saved_state32(state));
	regs = saved_state32(state);

	if (!(dgWork.dgFlags & enaDiagSCs))
		return 0;	/* If not enabled, cause an exception */

	stk = regs->uesp;	/* Point to the stack */
	err = copyin((user_addr_t) (stk + 4), (char *) &selector, sizeof(uint32_t));	/* Get the selector */
	if (err) {
		return 0;	/* Failed to fetch stack */
	}
	switch (selector) {	/* Select the routine */

	case dgRuptStat:	/* Suck Interruption statistics */

		err = copyin((user_addr_t) (stk + 8), (char *) &data, sizeof(uint32_t));	/* Get the selector */

		if (data == 0) {/* If number of processors is 0, clear all
				 * counts */
			for (i = 0; i < real_ncpus; i++) {	/* Cycle through
								 * processors */
				for (j = 0; j < 256; j++)
					cpu_data_ptr[i]->cpu_hwIntCnt[j] = 0;
			}

			lastRuptClear = mach_absolute_time();	/* Get the time of clear */
			return 1;	/* Normal return */
		}
		err = copyin((user_addr_t) (stk + 8), (char *) &data, sizeof(uint32_t));	/* Get the selector */

		(void) copyout((char *) &real_ncpus, data, sizeof(real_ncpus));	/* Copy out number of
										 * processors */

		currNap = mach_absolute_time();	/* Get the time now */
		durNap = currNap - lastRuptClear;	/* Get the last interval
							 * duration */
		if (durNap == 0)
			durNap = 1;	/* This is a very short time, make it
					 * bigger */

		curpos = data + sizeof(real_ncpus);	/* Point to the next
							 * available spot */

		for (i = 0; i < real_ncpus; i++) {	/* Move 'em all out */
			(void) copyout((char *) &durNap, curpos, 8);	/* Copy out the time
									 * since last clear */
			(void) copyout((char *) &cpu_data_ptr[i]->cpu_hwIntCnt, curpos + 8, 256 * sizeof(uint32_t));	/* Copy out interrupt
															 * data for this
															 * processor */
			curpos = curpos + (256 * sizeof(uint32_t) + 8);	/* Point to next out put
									 * slot */
		}

		break;

	default:		/* Handle invalid ones */
		return 0;	/* Return an exception */

	}

	return 1;		/* Normal non-ast check return */
}
