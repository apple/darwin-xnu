/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
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
	 * Check for BSD hardcoded hooks 
	 */
	if (reasons & AST_BSD) {
		extern void		bsd_ast(thread_act_t	act);
		thread_act_t	act = self->top_act;

		thread_ast_clear(act, AST_BSD);
		bsd_ast(act);
	}
	if (reasons & AST_BSD_INIT) {
		extern void		bsdinit_task(void);

		thread_ast_clear(self->top_act, AST_BSD_INIT);
		bsdinit_task();
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

void
ast_check(void)
{
	register int			mycpu;
	register processor_t	myprocessor;
	register thread_t		self = current_thread();
	spl_t					s;

	s = splsched();
	mycpu = cpu_number();

	/*
	 *	Check processor state for ast conditions.
	 */
	myprocessor = cpu_to_processor(mycpu);
	switch (myprocessor->state) {

	case PROCESSOR_OFF_LINE:
	case PROCESSOR_IDLE:
	case PROCESSOR_DISPATCHING:
		/*
		 *	No ast.
		 */
		break;

	case PROCESSOR_ASSIGN:
        /*
		 * 	Need ast to force action thread onto processor.
		 */
		ast_on(AST_BLOCK);
		break;

	case PROCESSOR_RUNNING:
	case PROCESSOR_SHUTDOWN:
		/*
		 *	Propagate thread ast to processor.
		 */
		ast_propagate(self->top_act->ast);

		/*
		 *	Context switch check.
		 */
		if (csw_needed(self, myprocessor))
			ast_on(AST_BLOCK);
		break;

	default:
        panic("ast_check: Bad processor state");
	}

	splx(s);
}

/*
 * JMM - Temporary exports to other components
 */
#undef ast_on
#undef ast_off

void
ast_on(ast_t reason)
{
	boolean_t		enable;

	enable = ml_set_interrupts_enabled(FALSE);
	ast_on_fast(reason);
	(void)ml_set_interrupts_enabled(enable);
}

void
ast_off(ast_t reason)
{
	ast_off_fast(reason);
}
