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

#include <mach_kdb.h>

#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/message.h>
#include <mach/port.h>
#include <mach/mig_errors.h>
#include <mach/thread_status.h>
#include <mach/exception_types.h>
#include <ipc/port.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_notify.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_pset.h>
#include <ipc/ipc_machdep.h>
#include <kern/etap_macros.h>
#include <kern/counters.h>
#include <kern/ipc_tt.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/thread_swap.h>
#include <kern/processor.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/host.h>
#include <kern/misc_protos.h>
#include <string.h>
#include <mach/exc.h>

#if	MACH_KDB
#include <ddb/db_trap.h>
#endif	/* MACH_KDB */

#if	MACH_KDB

#include <ddb/db_output.h>

#if iPSC386 || iPSC860
boolean_t debug_user_with_kdb = TRUE;
#else
boolean_t debug_user_with_kdb = FALSE;
#endif

#endif	/* MACH_KDB */

unsigned long c_thr_exc_raise = 0;
unsigned long c_thr_exc_raise_state = 0;
unsigned long c_thr_exc_raise_state_id = 0;
unsigned long c_tsk_exc_raise = 0;
unsigned long c_tsk_exc_raise_state = 0;
unsigned long c_tsk_exc_raise_state_id = 0;


/*
 *	Routine:	exception_deliver
 *	Purpose:
 *		Make an upcall to the exception server provided.
 *	Conditions:
 *		Nothing locked and no resources held.
 *		Called from an exception context, so
 *		thread_exception_return and thread_kdb_return
 *		are possible.
 *	Returns:
 *		If the exception was not handled by this handler
 */
void
exception_deliver(
	exception_type_t	exception,
	exception_data_t	code,
	mach_msg_type_number_t  codeCnt,
	struct exception_action *excp,
	mutex_t			*mutex)
{
	thread_act_t		a_self = current_act();
	ipc_port_t		exc_port;
	int			behavior;
	int			flavor;
	kern_return_t		kr;

	/*
	 *  Save work if we are terminating.
	 *  Just go back to our AST handler.
	 */
	if (!a_self->active)
		thread_exception_return();

	/*
	 * Snapshot the exception action data under lock for consistency.
	 * Hold a reference to the port over the exception_raise_* calls
	 * so it can't be destroyed.  This seems like overkill, but keeps
	 * the port from disappearing between now and when
	 * ipc_object_copyin_from_kernel is finally called.
	 */
	mutex_lock(mutex);
	exc_port = excp->port;
	if (!IP_VALID(exc_port)) {
		mutex_unlock(mutex);
		return;
	}
	ip_lock(exc_port);
	if (!ip_active(exc_port)) {
		ip_unlock(exc_port);
		mutex_unlock(mutex);
		return;
	}
	ip_reference(exc_port);	
	exc_port->ip_srights++;
	ip_unlock(exc_port);

	flavor = excp->flavor;
	behavior = excp->behavior;
	mutex_unlock(mutex);

	switch (behavior) {
	case EXCEPTION_STATE: {
		mach_msg_type_number_t state_cnt;
		natural_t state[ THREAD_MACHINE_STATE_MAX ];

		c_thr_exc_raise_state++;
		state_cnt = state_count[flavor];
		kr = thread_getstatus(a_self, flavor, 
				      (thread_state_t)state,
				      &state_cnt);
		if (kr == KERN_SUCCESS) {
			kr = exception_raise_state(exc_port, exception,
						   code, codeCnt,
						   &flavor,
						   state, state_cnt,
						   state, &state_cnt);
			if (kr == MACH_MSG_SUCCESS)
				kr = thread_setstatus(a_self, flavor, 
						      (thread_state_t)state,
						      state_cnt);
		}

		if (kr == KERN_SUCCESS || kr == MACH_RCV_PORT_DIED)
			thread_exception_return();
			/*NOTREACHED*/
		return;
	}

	case EXCEPTION_DEFAULT:
		c_thr_exc_raise++;
		kr = exception_raise(exc_port,
				retrieve_act_self_fast(a_self),
				retrieve_task_self_fast(a_self->task),
				exception,
				code, codeCnt);

		if (kr == KERN_SUCCESS || kr == MACH_RCV_PORT_DIED)
			thread_exception_return();
			/*NOTREACHED*/
		return;

	case EXCEPTION_STATE_IDENTITY: {
		mach_msg_type_number_t state_cnt;
		natural_t state[ THREAD_MACHINE_STATE_MAX ];

		c_thr_exc_raise_state_id++;
		state_cnt = state_count[flavor];
		kr = thread_getstatus(a_self, flavor,
				      (thread_state_t)state,
				      &state_cnt);
		if (kr == KERN_SUCCESS) {
		    kr = exception_raise_state_identity(exc_port,
				retrieve_act_self_fast(a_self),
				retrieve_task_self_fast(a_self->task),
				exception,
				code, codeCnt,
				&flavor,
				state, state_cnt,
				state, &state_cnt);
		    if (kr == MACH_MSG_SUCCESS)
			kr = thread_setstatus(a_self, flavor,
					      (thread_state_t)state,
					      state_cnt);
		}

		if (kr == KERN_SUCCESS || kr == MACH_RCV_PORT_DIED)
			thread_exception_return();
			/*NOTREACHED*/
		return;
	}
	
	default:
		panic ("bad exception behavior!");
	}/* switch */
}

/*
 *	Routine:	exception
 *	Purpose:
 *		The current thread caught an exception.
 *		We make an up-call to the thread's exception server.
 *	Conditions:
 *		Nothing locked and no resources held.
 *		Called from an exception context, so
 *		thread_exception_return and thread_kdb_return
 *		are possible.
 *	Returns:
 *		Doesn't return.
 */
void
exception(
	exception_type_t	exception,
	exception_data_t	code,
	mach_msg_type_number_t  codeCnt)
{
	thread_act_t		thr_act;
	task_t			task;
	host_priv_t		host_priv;
	struct exception_action *excp;
	mutex_t			*mutex;

	assert(exception != EXC_RPC_ALERT);

	if (exception == KERN_SUCCESS)
		panic("exception");

	/*
	 * Try to raise the exception at the activation level.
	 */
	thr_act = current_act();
	mutex = mutex_addr(thr_act->lock);
	excp = &thr_act->exc_actions[exception];
	exception_deliver(exception, code, codeCnt, excp, mutex);

	/*
	 * Maybe the task level will handle it.
	 */
	task = current_task();
	mutex = mutex_addr(task->lock);
	excp = &task->exc_actions[exception];
	exception_deliver(exception, code, codeCnt, excp, mutex);

	/*
	 * How about at the host level?
	 */
	host_priv = host_priv_self();
	mutex = mutex_addr(host_priv->lock);
	excp = &host_priv->exc_actions[exception];
	exception_deliver(exception, code, codeCnt, excp, mutex);

	/*
	 * Nobody handled it, terminate the task.
	 */

#if	MACH_KDB
	if (debug_user_with_kdb) {
		/*
		 *	Debug the exception with kdb.
		 *	If kdb handles the exception,
		 *	then thread_kdb_return won't return.
		 */
		db_printf("No exception server, calling kdb...\n");
		thread_kdb_return();
	}
#endif	/* MACH_KDB */

	(void) task_terminate(task);
	thread_exception_return();
	/*NOTREACHED*/
}

kern_return_t
bsd_exception(
	exception_type_t	exception,
	exception_data_t	code,
	mach_msg_type_number_t  codeCnt)
{
	task_t			task;
	host_priv_t		host_priv;
	struct exception_action *excp;
	mutex_t			*mutex;
	thread_act_t		a_self = current_act();
	ipc_port_t		exc_port;
	int			behavior;
	int			flavor;
	kern_return_t		kr;

	/*
	 * Maybe the task level will handle it.
	 */
	task = current_task();
	mutex = mutex_addr(task->lock);
	excp = &task->exc_actions[exception];

	/*
	 *  Save work if we are terminating.
	 *  Just go back to our AST handler.
	 */
	if (!a_self->active) {
		return(KERN_FAILURE);
	}

	/*
	 * Snapshot the exception action data under lock for consistency.
	 * Hold a reference to the port over the exception_raise_* calls
	 * so it can't be destroyed.  This seems like overkill, but keeps
	 * the port from disappearing between now and when
	 * ipc_object_copyin_from_kernel is finally called.
	 */
	mutex_lock(mutex);
	exc_port = excp->port;
	if (!IP_VALID(exc_port)) {
		mutex_unlock(mutex);
		return(KERN_FAILURE);
	}
	ip_lock(exc_port);
	if (!ip_active(exc_port)) {
		ip_unlock(exc_port);
		mutex_unlock(mutex);
		return(KERN_FAILURE);
	}
	ip_reference(exc_port);	
	exc_port->ip_srights++;
	ip_unlock(exc_port);

	flavor = excp->flavor;
	behavior = excp->behavior;
	mutex_unlock(mutex);

	switch (behavior) {
	case EXCEPTION_STATE: {
		mach_msg_type_number_t state_cnt;
		natural_t state[ THREAD_MACHINE_STATE_MAX ];

		c_thr_exc_raise_state++;
		state_cnt = state_count[flavor];
		kr = thread_getstatus(a_self, flavor, 
				      (thread_state_t)state,
				      &state_cnt);
		if (kr == KERN_SUCCESS) {
			kr = exception_raise_state(exc_port, exception,
						   code, codeCnt,
						   &flavor,
						   state, state_cnt,
						   state, &state_cnt);
			if (kr == MACH_MSG_SUCCESS)
				kr = thread_setstatus(a_self, flavor, 
						      (thread_state_t)state,
						      state_cnt);
		}

		if (kr == KERN_SUCCESS || kr == MACH_RCV_PORT_DIED)
			return(KERN_SUCCESS);

		return(KERN_FAILURE);
	}

	case EXCEPTION_DEFAULT:
		c_thr_exc_raise++;
		kr = exception_raise(exc_port,
				retrieve_act_self_fast(a_self),
				retrieve_task_self_fast(a_self->task),
				exception,
				code, codeCnt);

		if (kr == KERN_SUCCESS || kr == MACH_RCV_PORT_DIED)
			return(KERN_SUCCESS);
		return(KERN_FAILURE);

	case EXCEPTION_STATE_IDENTITY: {
		mach_msg_type_number_t state_cnt;
		natural_t state[ THREAD_MACHINE_STATE_MAX ];

		c_thr_exc_raise_state_id++;
		state_cnt = state_count[flavor];
		kr = thread_getstatus(a_self, flavor,
				      (thread_state_t)state,
				      &state_cnt);
		if (kr == KERN_SUCCESS) {
		    kr = exception_raise_state_identity(exc_port,
				retrieve_act_self_fast(a_self),
				retrieve_task_self_fast(a_self->task),
				exception,
				code, codeCnt,
				&flavor,
				state, state_cnt,
				state, &state_cnt);
		    if (kr == MACH_MSG_SUCCESS)
			kr = thread_setstatus(a_self, flavor,
					      (thread_state_t)state,
					      state_cnt);
		}

		if (kr == KERN_SUCCESS || kr == MACH_RCV_PORT_DIED)
			return(KERN_SUCCESS);
		return(KERN_FAILURE);
	}
	
	default:
		
		return(KERN_FAILURE);
	}/* switch */
	return(KERN_FAILURE);
}

