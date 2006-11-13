/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
 */
/*
 * @APPLE_FREE_COPYRIGHT@
 */
#include <kern/misc_protos.h>
#include <kern/assert.h>
#include <kern/thread.h>
#include <kern/counters.h>
#include <kern/etimer.h>
#include <kern/pms.h>
#include <ppc/misc_protos.h>
#include <ppc/trap.h>
#include <ppc/proc_reg.h>
#include <ppc/exception.h>
#include <ppc/savearea.h>
#include <pexpert/pexpert.h>
#include <sys/kdebug.h>

perfCallback perfIntHook = 0;						/* Pointer to CHUD trap hook routine */

void unresolved_kernel_trap(int trapno,
				   struct savearea *ssp,
				   unsigned int dsisr,
				   addr64_t dar,
				   const char *message);

struct savearea * interrupt(
        int type,
        struct savearea *ssp,
	unsigned int dsisr,
	unsigned int dar)
{
	int	current_cpu;
	struct per_proc_info	*proc_info;
	uint64_t		now;
	thread_t		thread;

	disable_preemption();

	if(perfIntHook) {							/* Is there a hook? */
		if(perfIntHook(type, ssp, dsisr, dar) == KERN_SUCCESS) return ssp;	/* If it succeeds, we are done... */
	}
	
#if 0
	{
		extern void fctx_text(void);
		fctx_test();
	}
#endif


	current_cpu = cpu_number();
	proc_info = getPerProc();

	switch (type) {

		case T_DECREMENTER:
			KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_DECI, 0) | DBG_FUNC_NONE,
				  isync_mfdec(), (unsigned int)ssp->save_srr0, 0, 0, 0);
	
#if 0
			if (pcsample_enable) {
				if (find_user_regs(current_thread()))
				  add_pcsamples (user_pc(current_thread()));
			}
#endif

			now = mach_absolute_time();				/* Find out what time it is */
			
			if(now >= proc_info->pms.pmsPop) {		/* Is it time for power management state change? */
				pmsStep(1);							/* Yes, advance step */
				now = mach_absolute_time();			/* Get the time again since we ran a bit */
			}

			thread = current_thread();					/* Find ourselves */
			if(thread->machine.qactTimer != 0) {	/* Is the timer set? */
				if (thread->machine.qactTimer <= now) {	/* It is set, has it popped? */
					thread->machine.qactTimer = 0;		/* Clear single shot timer */
					if((unsigned int)thread->machine.vmmControl & 0xFFFFFFFE) {	/* Are there any virtual machines? */
						vmm_timer_pop(thread);			/* Yes, check out them out... */
					}
				}
			}

			etimer_intr(USER_MODE(ssp->save_srr1), ssp->save_srr0);	/* Handle event timer */
			break;
	
		case T_INTERRUPT:
			/* Call the platform interrupt routine */
			counter_always(c_incoming_interrupts++);
	
			KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_INTR, 0) | DBG_FUNC_START,
			   current_cpu, (unsigned int)ssp->save_srr0, 0, 0, 0);
	
			proc_info->interrupt_handler(
				proc_info->interrupt_target, 
				proc_info->interrupt_refCon,
				proc_info->interrupt_nub, 
				proc_info->interrupt_source);
	
			KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_INTR, 0) | DBG_FUNC_END,
			   0, 0, 0, 0, 0);
	
			break;
	
		case T_SIGP:
			/* Did the other processor signal us? */ 
			cpu_signal_handler();
			break;
	
		case T_SHUTDOWN:
			cpu_doshutdown();
			panic("returning from cpu_doshutdown()\n");
			break;
	
				
		default:
			if (!Call_Debugger(type, ssp))
				unresolved_kernel_trap(type, ssp, dsisr, dar, NULL);
			break;
	}

	enable_preemption();
	return ssp;
}
