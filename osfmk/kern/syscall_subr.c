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

#include <kern/mk_sp.h>

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

void
swtch_continue(void)
{
	register processor_t	myprocessor;
    boolean_t				result;

    mp_disable_preemption();
	myprocessor = current_processor();
	result =		myprocessor->runq.count > 0					||
				myprocessor->processor_set->runq.count > 0;
	mp_enable_preemption();

	thread_syscall_return(result);
	/*NOTREACHED*/
}

boolean_t
swtch(void)
{
	register processor_t	myprocessor;
	boolean_t				result;

	mp_disable_preemption();
	myprocessor = current_processor();
	if (		myprocessor->runq.count == 0				&&
			myprocessor->processor_set->runq.count == 0			) {
		mp_enable_preemption();

		return (FALSE);
	}
	mp_enable_preemption();

	counter(c_swtch_block++);

	thread_block(swtch_continue);

	mp_disable_preemption();
	myprocessor = current_processor();
	result =		myprocessor->runq.count > 0					||
				myprocessor->processor_set->runq.count > 0;
	mp_enable_preemption();

	return (result);
}

void
swtch_pri_continue(void)
{
	register processor_t	myprocessor;
    boolean_t				result;

	_mk_sp_thread_depress_abort(current_thread(), FALSE);

    mp_disable_preemption();
	myprocessor = current_processor();
	result =		myprocessor->runq.count > 0					||
				myprocessor->processor_set->runq.count > 0;
	mp_enable_preemption();

	thread_syscall_return(result);
	/*NOTREACHED*/
}

boolean_t
swtch_pri(
	int				pri)
{
	register processor_t	myprocessor;
	boolean_t				result;

	mp_disable_preemption();
	myprocessor = current_processor();
	if (	myprocessor->runq.count == 0					&&
			myprocessor->processor_set->runq.count == 0			) {
		mp_enable_preemption();

		return (FALSE);
	}
	mp_enable_preemption();

	counter(c_swtch_pri_block++);

	_mk_sp_thread_depress_abstime(std_quantum);

	thread_block(swtch_pri_continue);

	_mk_sp_thread_depress_abort(current_thread(), FALSE);

	mp_disable_preemption();
	myprocessor = current_processor();
	result =	myprocessor->runq.count > 0						||
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

    return _mk_sp_thread_switch(hint_act, option, option_time);
}
