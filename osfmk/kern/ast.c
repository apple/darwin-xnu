/*
 * Copyright (c) 2000-2012 Apple Inc. All rights reserved.
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
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/* 
 */

/*
 *
 *	This file contains routines to check whether an ast is needed.
 *
 *	ast_check() - check whether ast is needed for interrupt or context
 *	switch.  Usually called by clock interrupt handler.
 *
 */

#include <kern/ast.h>
#include <kern/counters.h>
#include <kern/cpu_number.h>
#include <kern/misc_protos.h>
#include <kern/queue.h>
#include <kern/sched_prim.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/spl.h>
#include <kern/sfi.h>
#if CONFIG_TELEMETRY
#include <kern/telemetry.h>
#endif
#include <kern/waitq.h>
#include <kern/ledger.h>
#include <kperf/kperf_kpc.h>
#include <mach/policy.h>
#include <machine/trap.h> // for CHUD AST hook
#include <machine/pal_routines.h>
#include <security/mac_mach_internal.h> // for MACF AST hook

volatile perfASTCallback perfASTHook;


void
ast_init(void)
{
}

#ifdef CONFIG_DTRACE
extern void dtrace_ast(void);
#endif

/*
 * Called at splsched.
 */
void
ast_taken(
	ast_t		reasons,
	boolean_t	enable
)
{
	boolean_t		preempt_trap = (reasons == AST_PREEMPTION);
	ast_t			*myast = ast_pending();
	thread_t		thread = current_thread();
	perfASTCallback	perf_hook = perfASTHook;

	/*
	 * CHUD hook - all threads including idle processor threads
	 */
	if (perf_hook) {
		if (*myast & AST_CHUD_ALL) {
			(*perf_hook)(reasons, myast);
			
			if (*myast == AST_NONE)
				return;
		}
	}
	else
		*myast &= ~AST_CHUD_ALL;

	reasons &= *myast;
	*myast &= ~reasons;

	/*
	 * Handle ASTs for all threads
	 * except idle processor threads.
	 */
	if (!(thread->state & TH_IDLE)) {
		/*
		 * Check for urgent preemption.
		 */
		if (	(reasons & AST_URGENT)				&&
				waitq_wait_possible(thread)		) {
			if (reasons & AST_PREEMPT) {
				counter(c_ast_taken_block++);
				thread_block_reason(THREAD_CONTINUE_NULL, NULL,
										reasons & AST_PREEMPTION);
			}

			reasons &= ~AST_PREEMPTION;
		}

		/*
		 * The kernel preempt traps
		 * skip all other ASTs.
		 */
		if (!preempt_trap) {
			ml_set_interrupts_enabled(enable);

#if CONFIG_DTRACE
			if (reasons & AST_DTRACE) {
				dtrace_ast();
			}
#endif

#ifdef	MACH_BSD
			/*
			 * Handle BSD hook.
			 */
			if (reasons & AST_BSD) {
				thread_ast_clear(thread, AST_BSD);
				bsd_ast(thread);
			}
#endif
#if CONFIG_MACF
			/*
			 * Handle MACF hook.
			 */
			if (reasons & AST_MACF) {
				thread_ast_clear(thread, AST_MACF);
				mac_thread_userret(thread);
			}
#endif
			/* 
			 * Thread APC hook.
			 */
			if (reasons & AST_APC) {
				thread_ast_clear(thread, AST_APC);
				thread_apc_ast(thread);
			}

			if (reasons & AST_GUARD) {
				thread_ast_clear(thread, AST_GUARD);
				guard_ast(thread);
			}

			if (reasons & AST_LEDGER) {
				thread_ast_clear(thread, AST_LEDGER);
				ledger_ast(thread);
			}

			/*
			 * Kernel Profiling Hook
			 */
			if (reasons & AST_KPERF) {
				thread_ast_clear(thread, AST_KPERF);
				kperf_kpc_thread_ast(thread);
			}

#if CONFIG_TELEMETRY
			if (reasons & AST_TELEMETRY_ALL) {
				boolean_t interrupted_userspace = FALSE;
				boolean_t io_telemetry = FALSE;

				assert((reasons & AST_TELEMETRY_ALL) != AST_TELEMETRY_ALL); /* only one is valid at a time */
				interrupted_userspace = (reasons & AST_TELEMETRY_USER) ? TRUE : FALSE;
				io_telemetry = ((reasons & AST_TELEMETRY_IO) ? TRUE : FALSE);
				thread_ast_clear(thread, AST_TELEMETRY_ALL);
				telemetry_ast(thread, interrupted_userspace, io_telemetry);
			}
#endif

			ml_set_interrupts_enabled(FALSE);

#if CONFIG_SCHED_SFI
			if (reasons & AST_SFI) {
				sfi_ast(thread);
			}
#endif

			/*
			 * Check for preemption. Conditions may have changed from when the AST_PREEMPT was originally set.
			 */
			thread_lock(thread);
			if (reasons & AST_PREEMPT)
				reasons = csw_check(current_processor(), reasons & AST_QUANTUM);
			thread_unlock(thread);

			assert(waitq_wait_possible(thread));

			if (reasons & AST_PREEMPT) {
				counter(c_ast_taken_block++);
				thread_block_reason((thread_continue_t)thread_exception_return, NULL, reasons & AST_PREEMPTION);
			}
		}
	}

	ml_set_interrupts_enabled(enable);
}

/*
 * Called at splsched.
 */
void
ast_check(
	processor_t processor)
{
	thread_t thread = processor->active_thread;

	if (processor->state == PROCESSOR_RUNNING ||
	    processor->state == PROCESSOR_SHUTDOWN) {
		ast_t preempt;

		/*
		 *	Propagate thread ast to processor.
		 */
		pal_ast_check(thread);

		ast_propagate(thread->ast);

		/*
		 *	Context switch check.
		 */
		thread_lock(thread);

		processor->current_pri = thread->sched_pri;
		processor->current_thmode = thread->sched_mode;
		processor->current_sfi_class = thread->sfi_class = sfi_thread_classify(thread);

		if ((preempt = csw_check(processor, AST_NONE)) != AST_NONE)
			ast_on(preempt);

		thread_unlock(thread);
	}
}

/*
 * Set AST flags on current processor
 * Called at splsched
 */
void
ast_on(ast_t reasons)
{
	ast_t *pending_ast = ast_pending();

	*pending_ast |= reasons;
}

/*
 * Clear AST flags on current processor
 * Called at splsched
 */
void
ast_off(ast_t reasons)
{
	ast_t *pending_ast = ast_pending();

	*pending_ast &= ~reasons;
}

/*
 * Re-set current processor's per-thread AST flags to those set on thread
 * Called at splsched
 */
void
ast_context(thread_t thread)
{
	ast_t *pending_ast = ast_pending();

	*pending_ast = ((*pending_ast & ~AST_PER_THREAD) | thread->ast);
}

void
ast_dtrace_on(void)
{
	ast_on(AST_DTRACE);
}

