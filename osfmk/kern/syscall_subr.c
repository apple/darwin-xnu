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

#include <cpus.h>

#include <mach/boolean.h>
#include <mach/thread_switch.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>
#include <kern/counters.h>
#include <kern/etap_macros.h>
#include <kern/ipc_kobject.h>
#include <kern/processor.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/spl.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/ast.h>
#include <mach/policy.h>

#include <kern/syscall_subr.h>
#include <mach/mach_host_server.h>
#include <mach/mach_syscalls.h>

#include <kern/sf.h>

/*
 *	swtch and swtch_pri both attempt to context switch (logic in
 *	thread_block no-ops the context switch if nothing would happen).
 *	A boolean is returned that indicates whether there is anything
 *	else runnable.
 *
 *	This boolean can be used by a thread waiting on a
 *	lock or condition:  If FALSE is returned, the thread is justified
 *	in becoming a resource hog by continuing to spin because there's
 *	nothing else useful that the processor could do.  If TRUE is
 *	returned, the thread should make one more check on the
 *	lock and then be a good citizen and really suspend.
 */

#if		0

/* broken..do not enable */

swtch_continue()
{
    boolean_t retval;
	register processor_t myprocessor;

    mp_disable_preemption();
	myprocessor = current_processor();
	retval = (
#if	NCPUS > 1
	       myprocessor->runq.count > 0 ||
#endif	/*NCPUS > 1*/
	       myprocessor->processor_set->runq.count > 0);
	mp_enable_preemption();
	return retval;
}

#endif

boolean_t
swtch(void)
{
	register processor_t	myprocessor;
	boolean_t				result;

	mp_disable_preemption();
	myprocessor = current_processor();
	if (
#if	NCPUS > 1
			myprocessor->runq.count == 0					&&
#endif	/* NCPUS > 1 */
			myprocessor->processor_set->runq.count == 0			) {
		mp_enable_preemption();

		return (FALSE);
	}
	mp_enable_preemption();

	counter(c_swtch_block++);

	thread_block((void (*)(void)) 0);

	mp_disable_preemption();
	myprocessor = current_processor();
	result = 
#if	NCPUS > 1
		myprocessor->runq.count > 0							||
#endif	/*NCPUS > 1*/
		myprocessor->processor_set->runq.count > 0;
	mp_enable_preemption();

	return (result);
}

boolean_t
swtch_pri(
	int				pri)
{
	thread_t				self = current_thread();
	register processor_t	myprocessor;
	boolean_t				result;
	sched_policy_t			*policy;
	spl_t					s;

	s = splsched();
	thread_lock(self);
	myprocessor = current_processor();
	if (
#if	NCPUS > 1
			myprocessor->runq.count == 0					&&
#endif	/* NCPUS > 1 */
			myprocessor->processor_set->runq.count == 0			) {
		thread_unlock(self);
		splx(s);

		return (FALSE);
	}

	policy = &sched_policy[self->policy];
	thread_unlock(self);
	splx(s);

	policy->sp_ops.sp_swtch_pri(policy, pri);

	mp_disable_preemption();
	myprocessor = current_processor();
	result = 
#if	NCPUS > 1
		myprocessor->runq.count > 0							||
#endif	/*NCPUS > 1*/
		myprocessor->processor_set->runq.count > 0;
	mp_enable_preemption();

	return (result);
}

/*
 *	thread_switch:
 *
 *	Context switch.  User may supply thread hint.
 */
kern_return_t
thread_switch(
	mach_port_name_t		thread_name,
	int						option,
	mach_msg_timeout_t		option_time)
{
    register thread_t		self = current_thread();
    register thread_act_t 	hint_act = THR_ACT_NULL;
	sched_policy_t			*policy;
	spl_t					s;

    /*
     *	Process option.
     */
    switch (option) {

	case SWITCH_OPTION_NONE:
	case SWITCH_OPTION_DEPRESS:
	case SWITCH_OPTION_WAIT:
	    break;

	default:
	    return (KERN_INVALID_ARGUMENT);
    }

    if (thread_name != MACH_PORT_NULL) {
		ipc_port_t			port;

		if (ipc_port_translate_send(self->top_act->task->itk_space,
									thread_name, &port) == KERN_SUCCESS) {
			ip_reference(port);
			ip_unlock(port);

			hint_act = convert_port_to_act(port);
			ipc_port_release(port);
		}
	}

	s = splsched();
	thread_lock(self);
	policy = &sched_policy[self->policy];
	thread_unlock(self);
	splx(s);

    /*
     * This is a scheduling policy-dependent operation.
     * Call the routine associated with the thread's
     * scheduling policy.
     */
    return (policy->sp_ops.
				sp_thread_switch(policy, hint_act, option, option_time));
}
