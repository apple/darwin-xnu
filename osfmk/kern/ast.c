/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
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

#include <cputypes.h>
#include <cpus.h>
#include <platforms.h>

#include <kern/ast.h>
#include <kern/counters.h>
#include <kern/cpu_number.h>
#include <kern/misc_protos.h>
#include <kern/queue.h>
#include <kern/sched_prim.h>
#include <kern/thread.h>
#include <kern/thread_act.h>
#include <kern/thread_swap.h>
#include <kern/processor.h>
#include <kern/spl.h>
#include <mach/policy.h>

volatile ast_t need_ast[NCPUS];

void
ast_init(void)
{
#ifndef	MACHINE_AST
	register int i;

	for (i=0; i<NCPUS; i++) {
		need_ast[i] = AST_NONE;
	}
#endif	/* MACHINE_AST */
}

void
ast_taken(
	ast_t			reasons,
	boolean_t		enable
)
{
	register int			mycpu;
	register processor_t	myprocessor;
	register thread_t		self = current_thread();
	boolean_t				preempt_trap = (reasons == AST_PREEMPT);

	disable_preemption();
	mycpu = cpu_number();
	reasons &= need_ast[mycpu];
	need_ast[mycpu] &= ~reasons;
	enable_preemption();

	/*
	 * No ast for an idle thread
	 */
	if (self->state & TH_IDLE)
		goto enable_and_return;

	/*
	 * Check for urgent preemption
	 */
	if ((reasons & AST_URGENT) && wait_queue_assert_possible(self)) {
		if (reasons & AST_BLOCK) {
			counter(c_ast_taken_block++);
			thread_block_reason((void (*)(void))0, AST_BLOCK);
		}

		reasons &= ~AST_PREEMPT;
		if (reasons == 0)
			goto enable_and_return;
	}

	if (preempt_trap)
		goto enable_and_return;

	ml_set_interrupts_enabled(enable);

#ifdef	MACH_BSD
	/*
	 * Check for BSD hook
	 */
	if (reasons & AST_BSD) {
		extern void		bsd_ast(thread_act_t	act);
		thread_act_t	act = self->top_act;

		thread_ast_clear(act, AST_BSD);
		bsd_ast(act);
	}
#endif

	/* 
	 * migration APC hook 
	 */
	if (reasons & AST_APC) {
		act_execute_returnhandlers();
	}

	/* 
	 * Check for normal preemption
	 */
	reasons &= AST_BLOCK;
    if (reasons == 0) {
        disable_preemption();
        myprocessor = current_processor();
        if (csw_needed(self, myprocessor))
            reasons = AST_BLOCK;
        enable_preemption();
    }
	if (	(reasons & AST_BLOCK)				&&
			wait_queue_assert_possible(self)		) {		
		counter(c_ast_taken_block++);
		thread_block_reason(thread_exception_return, AST_BLOCK);
	}

	goto just_return;

enable_and_return:
    ml_set_interrupts_enabled(enable);

just_return:
	return;
}

/*
 * Called at splsched.
 */
void
ast_check(
	processor_t		processor)
{
	register thread_t		self = processor->cpu_data->active_thread;

	processor->current_pri = self->sched_pri;
	if (processor->state == PROCESSOR_RUNNING) {
		register ast_t		preempt;
processor_running:

		/*
		 *	Propagate thread ast to processor.
		 */
		ast_propagate(self->top_act->ast);

		/*
		 *	Context switch check.
		 */
		if ((preempt = csw_check(self, processor)) != AST_NONE)
			ast_on(preempt);
	}
	else
	if (	processor->state == PROCESSOR_DISPATCHING	||
			processor->state == PROCESSOR_IDLE			) {
		return;
	}
	else
	if (processor->state == PROCESSOR_SHUTDOWN)
		goto processor_running;
	else
	if (processor->state == PROCESSOR_ASSIGN)
		ast_on(AST_BLOCK);
}
