/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
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
 * File:	ipc_tt.c
 * Purpose:
 *	Task and thread related IPC functions.
 */

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach_rt.h>
#include <mach/kern_return.h>
#include <mach/mach_param.h>
#include <mach/task_special_ports.h>
#include <mach/thread_special_ports.h>
#include <mach/thread_status.h>
#include <mach/exception_types.h>
#include <mach/mach_traps.h>
#include <mach/task_server.h>
#include <mach/thread_act_server.h>
#include <mach/mach_host_server.h>
#include <mach/vm_map_server.h>
#include <kern/host.h>
#include <kern/ipc_tt.h>
#include <kern/thread_act.h>
#include <kern/misc_protos.h>
#include <vm/vm_pageout.h>

/*
 *	Routine:	ipc_task_init
 *	Purpose:
 *		Initialize a task's IPC state.
 *
 *		If non-null, some state will be inherited from the parent.
 *		The parent must be appropriately initialized.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_task_init(
	task_t		task,
	task_t		parent)
{
	ipc_space_t space;
	ipc_port_t kport;
	kern_return_t kr;
	int i;


	kr = ipc_space_create(&ipc_table_entries[0], &space);
	if (kr != KERN_SUCCESS)
		panic("ipc_task_init");


	kport = ipc_port_alloc_kernel();
	if (kport == IP_NULL)
		panic("ipc_task_init");

	itk_lock_init(task);
	task->itk_self = kport;
	task->itk_sself = ipc_port_make_send(kport);
	task->itk_space = space;
	space->is_fast = FALSE;

	if (parent == TASK_NULL) {
		ipc_port_t port;

		for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
			task->exc_actions[i].port = IP_NULL;
		}/* for */
		
		kr = host_get_host_port(host_priv_self(), &port);
		assert(kr == KERN_SUCCESS);
		task->itk_host = port;

		task->itk_bootstrap = IP_NULL;

		for (i = 0; i < TASK_PORT_REGISTER_MAX; i++)
			task->itk_registered[i] = IP_NULL;
	} else {
		itk_lock(parent);
		assert(parent->itk_self != IP_NULL);

		/* inherit registered ports */

		for (i = 0; i < TASK_PORT_REGISTER_MAX; i++)
			task->itk_registered[i] =
				ipc_port_copy_send(parent->itk_registered[i]);

		/* inherit exception and bootstrap ports */

		for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		    task->exc_actions[i].port =
		  		ipc_port_copy_send(parent->exc_actions[i].port);
		    task->exc_actions[i].flavor =
				parent->exc_actions[i].flavor;
		    task->exc_actions[i].behavior = 
				parent->exc_actions[i].behavior;
		}/* for */
		task->itk_host =
			ipc_port_copy_send(parent->itk_host);

		task->itk_bootstrap =
			ipc_port_copy_send(parent->itk_bootstrap);

		itk_unlock(parent);
	}
}

/*
 *	Routine:	ipc_task_enable
 *	Purpose:
 *		Enable a task for IPC access.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_task_enable(
	task_t		task)
{
	ipc_port_t kport;

	itk_lock(task);
	kport = task->itk_self;
	if (kport != IP_NULL)
		ipc_kobject_set(kport, (ipc_kobject_t) task, IKOT_TASK);
	itk_unlock(task);
}

/*
 *	Routine:	ipc_task_disable
 *	Purpose:
 *		Disable IPC access to a task.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_task_disable(
	task_t		task)
{
	ipc_port_t kport;

	itk_lock(task);
	kport = task->itk_self;
	if (kport != IP_NULL)
		ipc_kobject_set(kport, IKO_NULL, IKOT_NONE);
	itk_unlock(task);
}

/*
 *	Routine:	ipc_task_terminate
 *	Purpose:
 *		Clean up and destroy a task's IPC state.
 *	Conditions:
 *		Nothing locked.  The task must be suspended.
 *		(Or the current thread must be in the task.)
 */

void
ipc_task_terminate(
	task_t		task)
{
	ipc_port_t kport;
	int i;

	itk_lock(task);
	kport = task->itk_self;

	if (kport == IP_NULL) {
		/* the task is already terminated (can this happen?) */
		itk_unlock(task);
		return;
	}

	task->itk_self = IP_NULL;
	itk_unlock(task);

	/* release the naked send rights */

	if (IP_VALID(task->itk_sself))
		ipc_port_release_send(task->itk_sself);

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		if (IP_VALID(task->exc_actions[i].port)) {
			ipc_port_release_send(task->exc_actions[i].port);
		}
	}/* for */
	if (IP_VALID(task->itk_host))
		ipc_port_release_send(task->itk_host);

	if (IP_VALID(task->itk_bootstrap))
		ipc_port_release_send(task->itk_bootstrap);

	for (i = 0; i < TASK_PORT_REGISTER_MAX; i++)
		if (IP_VALID(task->itk_registered[i]))
			ipc_port_release_send(task->itk_registered[i]);

	ipc_port_release_send(task->wired_ledger_port);
	ipc_port_release_send(task->paged_ledger_port);

	/* destroy the kernel port */
	ipc_port_dealloc_kernel(kport);
}

/*
 *	Routine:	ipc_task_reset
 *	Purpose:
 *		Reset a task's IPC state to protect it when
 *		it enters an elevated security context.
 *	Conditions:
 *		Nothing locked.  The task must be suspended.
 *		(Or the current thread must be in the task.)
 */

void
ipc_task_reset(
	task_t		task)
{
	ipc_port_t old_kport, new_kport;
	ipc_port_t old_sself;
#if 0
	ipc_port_t old_exc_actions[EXC_TYPES_COUNT];
	int i;
#endif

	new_kport = ipc_port_alloc_kernel();
	if (new_kport == IP_NULL)
		panic("ipc_task_reset");

	itk_lock(task);

	old_kport = task->itk_self;

	if (old_kport == IP_NULL) {
		/* the task is already terminated (can this happen?) */
		itk_unlock(task);
		ipc_port_dealloc_kernel(new_kport);
		return;
	}

	task->itk_self = new_kport;
	old_sself = task->itk_sself;
	task->itk_sself = ipc_port_make_send(new_kport);
	ipc_kobject_set(old_kport, IKO_NULL, IKOT_NONE);
	ipc_kobject_set(new_kport, (ipc_kobject_t) task, IKOT_TASK);

#if 0
	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		old_exc_actions[i] = task->exc_action[i].port;
		task->exc_actions[i].port = IP_NULL;
	}/* for */
#endif

	itk_unlock(task);

	/* release the naked send rights */

	if (IP_VALID(old_sself))
		ipc_port_release_send(old_sself);

#if 0
	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		if (IP_VALID(old_exc_actions[i])) {
			ipc_port_release_send(old_exc_actions[i]);
		}
	}/* for */
#endif

	/* destroy the kernel port */
	ipc_port_dealloc_kernel(old_kport);
}

/*
 *	Routine:	ipc_thread_init
 *	Purpose:
 *		Initialize a thread's IPC state.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_thread_init(
	thread_t	thread)
{
	ipc_kmsg_queue_init(&thread->ith_messages);
	thread->ith_mig_reply = MACH_PORT_NULL;
	thread->ith_rpc_reply = IP_NULL;
}

/*
 *	Routine:	ipc_thread_terminate
 *	Purpose:
 *		Clean up and destroy a thread's IPC state.
 *	Conditions:
 *		Nothing locked.  The thread must be suspended.
 *		(Or be the current thread.)
 */

void
ipc_thread_terminate(
	thread_t	thread)
{
	assert(ipc_kmsg_queue_empty(&thread->ith_messages));

        if (thread->ith_rpc_reply != IP_NULL)
            ipc_port_dealloc_reply(thread->ith_rpc_reply);
	thread->ith_rpc_reply = IP_NULL;
}

/*
 *	Routine:	ipc_thr_act_init
 *	Purpose:
 *		Initialize an thr_act's IPC state.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_thr_act_init(task_t task, thread_act_t thr_act)
{
	ipc_port_t kport; int i;

	kport = ipc_port_alloc_kernel();
	if (kport == IP_NULL)
		panic("ipc_thr_act_init");

	thr_act->ith_self = kport;
	thr_act->ith_sself = ipc_port_make_send(kport);

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++)
		thr_act->exc_actions[i].port = IP_NULL;

	ipc_kobject_set(kport, (ipc_kobject_t) thr_act, IKOT_ACT);
}

void
ipc_thr_act_disable(thread_act_t thr_act)
{
	int i;
	ipc_port_t kport;

	kport = thr_act->ith_self;

	if (kport != IP_NULL)
		ipc_kobject_set(kport, IKO_NULL, IKOT_NONE);
}

void
ipc_thr_act_terminate(thread_act_t thr_act)
{
	ipc_port_t kport; int i;

	kport = thr_act->ith_self;

	if (kport == IP_NULL) {
		/* the thread is already terminated (can this happen?) */
		return;
	}

	thr_act->ith_self = IP_NULL;

	/* release the naked send rights */

	if (IP_VALID(thr_act->ith_sself))
		ipc_port_release_send(thr_act->ith_sself);
	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
	    if (IP_VALID(thr_act->exc_actions[i].port))
		ipc_port_release_send(thr_act->exc_actions[i].port);
        }

	/* destroy the kernel port */
	ipc_port_dealloc_kernel(kport);
}

/*
 *	Routine:	retrieve_task_self_fast
 *	Purpose:
 *		Optimized version of retrieve_task_self,
 *		that only works for the current task.
 *
 *		Return a send right (possibly null/dead)
 *		for the task's user-visible self port.
 *	Conditions:
 *		Nothing locked.
 */

ipc_port_t
retrieve_task_self_fast(
	register task_t		task)
{
	register ipc_port_t port;

	assert(task == current_task());

	itk_lock(task);
	assert(task->itk_self != IP_NULL);

	if ((port = task->itk_sself) == task->itk_self) {
		/* no interposing */

		ip_lock(port);
		assert(ip_active(port));
		ip_reference(port);
		port->ip_srights++;
		ip_unlock(port);
	} else
		port = ipc_port_copy_send(port);
	itk_unlock(task);

	return port;
}

/*
 *	Routine:	retrieve_act_self_fast
 *	Purpose:
 *		Optimized version of retrieve_thread_self,
 *		that only works for the current thread.
 *
 *		Return a send right (possibly null/dead)
 *		for the thread's user-visible self port.
 *	Conditions:
 *		Nothing locked.
 */

ipc_port_t
retrieve_act_self_fast(thread_act_t thr_act)
{
	register ipc_port_t port;

	assert(thr_act == current_act());
	act_lock(thr_act);
	assert(thr_act->ith_self != IP_NULL);

	if ((port = thr_act->ith_sself) == thr_act->ith_self) {
		/* no interposing */

		ip_lock(port);
		assert(ip_active(port));
		ip_reference(port);
		port->ip_srights++;
		ip_unlock(port);
	} else
		port = ipc_port_copy_send(port);
	act_unlock(thr_act);

	return port;
}

/*
 *	Routine:	task_self_trap [mach trap]
 *	Purpose:
 *		Give the caller send rights for his own task port.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_PORT_NULL if there are any resource failures
 *		or other errors.
 */

mach_port_name_t
task_self_trap(void)
{
	task_t task = current_task();
	ipc_port_t sright;

	sright = retrieve_task_self_fast(task);
	return ipc_port_copyout_send(sright, task->itk_space);
}

/*
 *	Routine:	thread_self_trap [mach trap]
 *	Purpose:
 *		Give the caller send rights for his own thread port.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_PORT_NULL if there are any resource failures
 *		or other errors.
 */

mach_port_name_t
thread_self_trap(void)
{
	thread_act_t  thr_act  = current_act();
	task_t task = thr_act->task;
	ipc_port_t sright;

	sright = retrieve_act_self_fast(thr_act);
	return ipc_port_copyout_send(sright, task->itk_space);
}

/*
 *	Routine:	mach_reply_port [mach trap]
 *	Purpose:
 *		Allocate a port for the caller.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_PORT_NULL if there are any resource failures
 *		or other errors.
 */

mach_port_name_t
mach_reply_port(void)
{
	ipc_port_t port;
	mach_port_name_t name;
	kern_return_t kr;

	kr = ipc_port_alloc(current_task()->itk_space, &name, &port);
	if (kr == KERN_SUCCESS)
		ip_unlock(port);
	else
		name = MACH_PORT_NULL;

	return name;
}

/*
 *	Routine:	task_get_special_port [kernel call]
 *	Purpose:
 *		Clones a send right for one of the task's
 *		special ports.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Extracted a send right.
 *		KERN_INVALID_ARGUMENT	The task is null.
 *		KERN_FAILURE		The task/space is dead.
 *		KERN_INVALID_ARGUMENT	Invalid special port.
 */

kern_return_t
task_get_special_port(
	task_t		task,
	int		which,
	ipc_port_t	*portp)
{
	ipc_port_t *whichp;
	ipc_port_t port;

	if (task == TASK_NULL)
		return KERN_INVALID_ARGUMENT;

	switch (which) {
	    case TASK_KERNEL_PORT:
		whichp = &task->itk_sself;
		break;

	    case TASK_HOST_PORT:
		whichp = &task->itk_host;
		break;

	    case TASK_BOOTSTRAP_PORT:
		whichp = &task->itk_bootstrap;
		break;

            case TASK_WIRED_LEDGER_PORT:
                whichp = &task->wired_ledger_port;
                break;

            case TASK_PAGED_LEDGER_PORT:
                whichp = &task->paged_ledger_port;
                break;
                    
	    default:
		return KERN_INVALID_ARGUMENT;
	}

	itk_lock(task);
	if (task->itk_self == IP_NULL) {
		itk_unlock(task);
		return KERN_FAILURE;
	}

	port = ipc_port_copy_send(*whichp);
	itk_unlock(task);

	*portp = port;
	return KERN_SUCCESS;
}

/*
 *	Routine:	task_set_special_port [kernel call]
 *	Purpose:
 *		Changes one of the task's special ports,
 *		setting it to the supplied send right.
 *	Conditions:
 *		Nothing locked.  If successful, consumes
 *		the supplied send right.
 *	Returns:
 *		KERN_SUCCESS		Changed the special port.
 *		KERN_INVALID_ARGUMENT	The task is null.
 *		KERN_FAILURE		The task/space is dead.
 *		KERN_INVALID_ARGUMENT	Invalid special port.
 */

kern_return_t
task_set_special_port(
	task_t		task,
	int		which,
	ipc_port_t	port)
{
	ipc_port_t *whichp;
	ipc_port_t old;

	if (task == TASK_NULL)
		return KERN_INVALID_ARGUMENT;

	switch (which) {
	    case TASK_KERNEL_PORT:
		whichp = &task->itk_sself;
		break;

	    case TASK_HOST_PORT:
		whichp = &task->itk_host;
		break;

	    case TASK_BOOTSTRAP_PORT:
		whichp = &task->itk_bootstrap;
		break;

            case TASK_WIRED_LEDGER_PORT:
                whichp = &task->wired_ledger_port;
                break;

            case TASK_PAGED_LEDGER_PORT:
                whichp = &task->paged_ledger_port;
                break;
                    
	    default:
		return KERN_INVALID_ARGUMENT;
	}/* switch */

	itk_lock(task);
	if (task->itk_self == IP_NULL) {
		itk_unlock(task);
		return KERN_FAILURE;
	}

	old = *whichp;
	*whichp = port;
	itk_unlock(task);

	if (IP_VALID(old))
		ipc_port_release_send(old);
	return KERN_SUCCESS;
}


/*
 *	Routine:	mach_ports_register [kernel call]
 *	Purpose:
 *		Stash a handful of port send rights in the task.
 *		Child tasks will inherit these rights, but they
 *		must use mach_ports_lookup to acquire them.
 *
 *		The rights are supplied in a (wired) kalloc'd segment.
 *		Rights which aren't supplied are assumed to be null.
 *	Conditions:
 *		Nothing locked.  If successful, consumes
 *		the supplied rights and memory.
 *	Returns:
 *		KERN_SUCCESS		Stashed the port rights.
 *		KERN_INVALID_ARGUMENT	The task is null.
 *		KERN_INVALID_ARGUMENT	The task is dead.
 *		KERN_INVALID_ARGUMENT	Too many port rights supplied.
 */

kern_return_t
mach_ports_register(
	task_t			task,
	mach_port_array_t	memory,
	mach_msg_type_number_t	portsCnt)
{
	ipc_port_t ports[TASK_PORT_REGISTER_MAX];
	int i;

	if ((task == TASK_NULL) ||
	    (portsCnt > TASK_PORT_REGISTER_MAX))
		return KERN_INVALID_ARGUMENT;

	/*
	 *	Pad the port rights with nulls.
	 */

	for (i = 0; i < portsCnt; i++)
		ports[i] = memory[i];
	for (; i < TASK_PORT_REGISTER_MAX; i++)
		ports[i] = IP_NULL;

	itk_lock(task);
	if (task->itk_self == IP_NULL) {
		itk_unlock(task);
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 *	Replace the old send rights with the new.
	 *	Release the old rights after unlocking.
	 */

	for (i = 0; i < TASK_PORT_REGISTER_MAX; i++) {
		ipc_port_t old;

		old = task->itk_registered[i];
		task->itk_registered[i] = ports[i];
		ports[i] = old;
	}

	itk_unlock(task);

	for (i = 0; i < TASK_PORT_REGISTER_MAX; i++)
		if (IP_VALID(ports[i]))
			ipc_port_release_send(ports[i]);

	/*
	 *	Now that the operation is known to be successful,
	 *	we can free the memory.
	 */

	if (portsCnt != 0)
		kfree((vm_offset_t) memory,
		      (vm_size_t) (portsCnt * sizeof(mach_port_t)));

	return KERN_SUCCESS;
}

/*
 *	Routine:	mach_ports_lookup [kernel call]
 *	Purpose:
 *		Retrieves (clones) the stashed port send rights.
 *	Conditions:
 *		Nothing locked.  If successful, the caller gets
 *		rights and memory.
 *	Returns:
 *		KERN_SUCCESS		Retrieved the send rights.
 *		KERN_INVALID_ARGUMENT	The task is null.
 *		KERN_INVALID_ARGUMENT	The task is dead.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
mach_ports_lookup(
	task_t			task,
	mach_port_array_t	*portsp,
	mach_msg_type_number_t	*portsCnt)
{
	vm_offset_t memory;
	vm_size_t size;
	ipc_port_t *ports;
	int i;

	kern_return_t kr;
	
	if (task == TASK_NULL)
		return KERN_INVALID_ARGUMENT;

	size = (vm_size_t) (TASK_PORT_REGISTER_MAX * sizeof(ipc_port_t));

	memory = kalloc(size);
	if (memory == 0)
		return KERN_RESOURCE_SHORTAGE;

	itk_lock(task);
	if (task->itk_self == IP_NULL) {
		itk_unlock(task);

		kfree(memory, size);
		return KERN_INVALID_ARGUMENT;
	}

	ports = (ipc_port_t *) memory;

	/*
	 *	Clone port rights.  Because kalloc'd memory
	 *	is wired, we won't fault while holding the task lock.
	 */

	for (i = 0; i < TASK_PORT_REGISTER_MAX; i++)
		ports[i] = ipc_port_copy_send(task->itk_registered[i]);

	itk_unlock(task);

	*portsp = (mach_port_array_t) ports;
	*portsCnt = TASK_PORT_REGISTER_MAX;
	return KERN_SUCCESS;
}

/*
 *	Routine: convert_port_to_locked_task
 *	Purpose:
 *		Internal helper routine to convert from a port to a locked
 *		task.  Used by several routines that try to convert from a
 *		task port to a reference on some task related object.
 *	Conditions:
 *		Nothing locked, blocking OK.
 */
task_t
convert_port_to_locked_task(ipc_port_t port)
{
	while (IP_VALID(port)) {
		task_t task;

		ip_lock(port);
		if (!ip_active(port) || (ip_kotype(port) != IKOT_TASK)) {
			ip_unlock(port);
			return TASK_NULL;
		}
		task = (task_t) port->ip_kobject;
		assert(task != TASK_NULL);

		/*
		 * Normal lock ordering puts task_lock() before ip_lock().
		 * Attempt out-of-order locking here.
		 */
		if (task_lock_try(task)) {
			ip_unlock(port);
			return(task);
		}

		ip_unlock(port);
		mutex_pause();
	}
	return TASK_NULL;
}

/*
 *	Routine:	convert_port_to_task
 *	Purpose:
 *		Convert from a port to a task.
 *		Doesn't consume the port ref; produces a task ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */
task_t
convert_port_to_task(
	ipc_port_t	port)
{
	task_t task;

	task = convert_port_to_locked_task(port);
	if (task) {
		task->ref_count++;
		task_unlock(task);
	}
	return task;
}

/*
 *	Routine:	convert_port_to_space
 *	Purpose:
 *		Convert from a port to a space.
 *		Doesn't consume the port ref; produces a space ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */
ipc_space_t
convert_port_to_space(
	ipc_port_t	port)
{
	ipc_space_t space;
	task_t task;

	task = convert_port_to_locked_task(port);

	if (task == TASK_NULL)
		return IPC_SPACE_NULL;

	if (!task->active) {
		task_unlock(task);
		return IPC_SPACE_NULL;
	}
		
	space = task->itk_space;
	is_reference(space);
	task_unlock(task);
	return (space);
}

upl_t
convert_port_to_upl(
	ipc_port_t	port)
{
	upl_t upl;

	ip_lock(port);
	if (!ip_active(port) || (ip_kotype(port) != IKOT_UPL)) {
			ip_unlock(port);
			return (upl_t)NULL;
	}
	upl = (upl_t) port->ip_kobject;
	ip_unlock(port);
	upl_lock(upl);
	upl->ref_count+=1;
	upl_unlock(upl);
	return upl;
}

mach_port_t
convert_upl_to_port(
	upl_t		upl)
{
	return MACH_PORT_NULL;
}

__private_extern__ void
upl_no_senders(
	upl_t			upl,
	mach_port_mscount_t	mscount)
{
	return;
}

/*
 *	Routine:	convert_port_entry_to_map
 *	Purpose:
 *		Convert from a port specifying an entry or a task
 *		to a map. Doesn't consume the port ref; produces a map ref,
 *		which may be null.  Unlike convert_port_to_map, the
 *		port may be task or a named entry backed.
 *	Conditions:
 *		Nothing locked.
 */


vm_map_t
convert_port_entry_to_map(
	ipc_port_t	port)
{
	task_t task;
	vm_map_t map;
	vm_named_entry_t	named_entry;

	if(IP_VALID(port) && (ip_kotype(port) == IKOT_NAMED_ENTRY)) {
		while(TRUE) {
			ip_lock(port);
			if(ip_active(port) && (ip_kotype(port) 
						== IKOT_NAMED_ENTRY)) {
				named_entry =
					 (vm_named_entry_t)port->ip_kobject;
				if (!(mutex_try(&(named_entry)->Lock))) {
                       			ip_unlock(port);
                       			mutex_pause();
                       			continue;
                		}
				named_entry->ref_count++;
				mutex_unlock(&(named_entry)->Lock);
				ip_unlock(port);
				if ((named_entry->is_sub_map) &&
					(named_entry->protection 
					& VM_PROT_WRITE)) {
					map = named_entry->backing.map;
				} else {
					mach_destroy_memory_entry(port);
					return VM_MAP_NULL;
				}
				vm_map_reference_swap(map);
				mach_destroy_memory_entry(port);
				break;
			}
			else 
				return VM_MAP_NULL;
		}
	} else {
		task_t task;

		task = convert_port_to_locked_task(port);
		
		if (task == TASK_NULL)
			return VM_MAP_NULL;

		if (!task->active) {
			task_unlock(task);
			return VM_MAP_NULL;
		}
		
		map = task->map;
		vm_map_reference_swap(map);
		task_unlock(task);
	}

	return map;
}

/*
 *	Routine:	convert_port_entry_to_object
 *	Purpose:
 *		Convert from a port specifying a named entry to an
 *		object. Doesn't consume the port ref; produces a map ref,
 *		which may be null. 
 *	Conditions:
 *		Nothing locked.
 */


vm_object_t
convert_port_entry_to_object(
	ipc_port_t	port)
{
	vm_object_t object;
	vm_named_entry_t	named_entry;

	if(IP_VALID(port) && (ip_kotype(port) == IKOT_NAMED_ENTRY)) {
		while(TRUE) {
			ip_lock(port);
			if(ip_active(port) && (ip_kotype(port) 
						== IKOT_NAMED_ENTRY)) {
				named_entry =
					 (vm_named_entry_t)port->ip_kobject;
				if (!(mutex_try(&(named_entry)->Lock))) {
                       			ip_unlock(port);
                       			mutex_pause();
                       			continue;
                		}
				named_entry->ref_count++;
				mutex_unlock(&(named_entry)->Lock);
				ip_unlock(port);
				if ((!named_entry->is_sub_map) &&
					(named_entry->protection 
					& VM_PROT_WRITE)) {
					object = named_entry->object;
				} else {
					mach_destroy_memory_entry(port);
					return (vm_object_t)NULL;
				}
				vm_object_reference(named_entry->object);
				mach_destroy_memory_entry(port);
				break;
			}
			else 
				return (vm_object_t)NULL;
		}
	} else {
		return (vm_object_t)NULL;
	}

	return object;
}

/*
 *	Routine:	convert_port_to_map
 *	Purpose:
 *		Convert from a port to a map.
 *		Doesn't consume the port ref; produces a map ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */

vm_map_t
convert_port_to_map(
	ipc_port_t	port)
{
	task_t task;
	vm_map_t map;

	task = convert_port_to_locked_task(port);
		
	if (task == TASK_NULL)
		return VM_MAP_NULL;

	if (!task->active) {
		task_unlock(task);
		return VM_MAP_NULL;
	}
		
	map = task->map;
	vm_map_reference_swap(map);
	task_unlock(task);
	return map;
}


/*
 *	Routine:	convert_port_to_act
 *	Purpose:
 *		Convert from a port to a thr_act.
 *		Doesn't consume the port ref; produces an thr_act ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */

thread_act_t
convert_port_to_act( ipc_port_t port )
{
	boolean_t r;
	thread_act_t thr_act = 0;

	r = FALSE;
	while (!r && IP_VALID(port)) {
		ip_lock(port);
		r = ref_act_port_locked(port, &thr_act);
		/* port unlocked */
	}
	return (thr_act);
}

boolean_t
ref_act_port_locked( ipc_port_t port, thread_act_t *pthr_act )
{
	thread_act_t thr_act;

	thr_act = 0;
	if (ip_active(port) &&
		(ip_kotype(port) == IKOT_ACT)) {
		thr_act = (thread_act_t) port->ip_kobject;
		assert(thr_act != THR_ACT_NULL);

		/*
		 * Out of order locking here, normal
		 * ordering is act_lock(), then ip_lock().
		 */
		if (!act_lock_try(thr_act)) {
			ip_unlock(port);
			mutex_pause();
			return (FALSE);
		}
		act_reference_locked(thr_act);
		act_unlock(thr_act);
	}
	*pthr_act = thr_act;
	ip_unlock(port);
	return (TRUE);
}

/*
 *	Routine:	port_name_to_act
 *	Purpose:
 *		Convert from a port name to an act reference
 *		A name of MACH_PORT_NULL is valid for the null act
 *	Conditions:
 *		Nothing locked.
 */
thread_act_t
port_name_to_act(
	mach_port_name_t	name)
{
	thread_act_t thr_act = THR_ACT_NULL;
	ipc_port_t kern_port;
	kern_return_t kr;

	if (MACH_PORT_VALID(name)) {
		kr = ipc_object_copyin(current_space(), name,
				       MACH_MSG_TYPE_COPY_SEND,
				       (ipc_object_t *) &kern_port);
		if (kr != KERN_SUCCESS)
			return THR_ACT_NULL;

		thr_act = convert_port_to_act(kern_port);
		
		if (IP_VALID(kern_port))
			ipc_port_release_send(kern_port);
	}
	return thr_act;
}

task_t
port_name_to_task(
	mach_port_name_t name)
{
	ipc_port_t kern_port;
	kern_return_t kr;
	task_t task = TASK_NULL;

	if (MACH_PORT_VALID(name)) {
		kr = ipc_object_copyin(current_space(), name,
				       MACH_MSG_TYPE_COPY_SEND,
				       (ipc_object_t *) &kern_port);
		if (kr != KERN_SUCCESS)
			return TASK_NULL;

		task = convert_port_to_task(kern_port);

		if (IP_VALID(kern_port))
			ipc_port_release_send(kern_port);
	}
	return task;
}

/*
 *	Routine:	convert_task_to_port
 *	Purpose:
 *		Convert from a task to a port.
 *		Consumes a task ref; produces a naked send right
 *		which may be invalid.  
 *	Conditions:
 *		Nothing locked.
 */

ipc_port_t
convert_task_to_port(
	task_t		task)
{
	ipc_port_t port;

	itk_lock(task);
	if (task->itk_self != IP_NULL)
#if	NORMA_TASK
		if (task->map == VM_MAP_NULL)
			/* norma placeholder task */
			port = ipc_port_copy_send(task->itk_self);
		else
#endif	/* NORMA_TASK */
		port = ipc_port_make_send(task->itk_self);
	else
		port = IP_NULL;
	itk_unlock(task);

	task_deallocate(task);
	return port;
}

/*
 *	Routine:	convert_act_to_port
 *	Purpose:
 *		Convert from a thr_act to a port.
 *		Consumes an thr_act ref; produces a naked send right
 *		which may be invalid.
 *	Conditions:
 *		Nothing locked.
 */

ipc_port_t
convert_act_to_port(thr_act)
	thread_act_t thr_act;
{
	ipc_port_t port;

	act_lock(thr_act);
	if (thr_act->ith_self != IP_NULL)
		port = ipc_port_make_send(thr_act->ith_self);
	else
		port = IP_NULL;
	act_unlock(thr_act);

	act_deallocate(thr_act);
	return port;
}

/*
 *	Routine:	space_deallocate
 *	Purpose:
 *		Deallocate a space ref produced by convert_port_to_space.
 *	Conditions:
 *		Nothing locked.
 */

void
space_deallocate(
	ipc_space_t	space)
{
	if (space != IS_NULL)
		is_release(space);
}

/*
 *	Routine:	thread/task_set_exception_ports [kernel call]
 *	Purpose:
 *			Sets the thread/task exception port, flavor and
 *			behavior for the exception types specified by the mask.
 *			There will be one send right per exception per valid
 *			port.
 *	Conditions:
 *		Nothing locked.  If successful, consumes
 *		the supplied send right.
 *	Returns:
 *		KERN_SUCCESS		Changed the special port.
 *		KERN_INVALID_ARGUMENT	The thread is null,
 *					Illegal mask bit set.
 *					Illegal exception behavior
 *		KERN_FAILURE		The thread is dead.
 */

kern_return_t
thread_set_exception_ports(
	thread_act_t		 	thr_act,
	exception_mask_t		exception_mask,
	ipc_port_t			new_port,
	exception_behavior_t		new_behavior,
	thread_state_flavor_t		new_flavor)
{
	register int	i;
	ipc_port_t	old_port[EXC_TYPES_COUNT];

	if (!thr_act)
		return KERN_INVALID_ARGUMENT;

	if (exception_mask & ~EXC_MASK_ALL)
		return KERN_INVALID_ARGUMENT;

	if (IP_VALID(new_port)) {
		switch (new_behavior) {
		case EXCEPTION_DEFAULT:
		case EXCEPTION_STATE:
		case EXCEPTION_STATE_IDENTITY:
			break;
		default:
			return KERN_INVALID_ARGUMENT;
		}
	}

	/* 
	 * Check the validity of the thread_state_flavor by calling the
	 * VALID_THREAD_STATE_FLAVOR architecture dependent macro defined in
	 * osfmk/mach/ARCHITECTURE/thread_status.h
	 */
	if (!VALID_THREAD_STATE_FLAVOR(new_flavor)) {
		return KERN_INVALID_ARGUMENT;
	}

	act_lock(thr_act);
	if (!thr_act->active) {
		act_unlock(thr_act);
		return KERN_FAILURE;
	}

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		if (exception_mask & (1 << i)) {
			old_port[i] = thr_act->exc_actions[i].port;
			thr_act->exc_actions[i].port =
				ipc_port_copy_send(new_port);
			thr_act->exc_actions[i].behavior = new_behavior;
			thr_act->exc_actions[i].flavor = new_flavor;
		} else
			old_port[i] = IP_NULL;
	}/* for */
	/*
	 * Consume send rights without any lock held.
	 */
	act_unlock(thr_act);
	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++)
		if (IP_VALID(old_port[i]))
			ipc_port_release_send(old_port[i]);
	if (IP_VALID(new_port))		 /* consume send right */
		ipc_port_release_send(new_port);

        return KERN_SUCCESS;
}/* thread_set_exception_port */

kern_return_t
task_set_exception_ports(
	task_t				task,
	exception_mask_t		exception_mask,
	ipc_port_t			new_port,
	exception_behavior_t		new_behavior,
	thread_state_flavor_t		new_flavor)
{
	register int	i;
	ipc_port_t	old_port[EXC_TYPES_COUNT];

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (exception_mask & ~EXC_MASK_ALL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (IP_VALID(new_port)) {
		switch (new_behavior) {
		case EXCEPTION_DEFAULT:
		case EXCEPTION_STATE:
		case EXCEPTION_STATE_IDENTITY:
			break;
		default:
			return KERN_INVALID_ARGUMENT;
		}
	}
	/* Cannot easily check "new_flavor", but that just means that
	 * the flavor in the generated exception message might be garbage:
	 * GIGO */

        itk_lock(task);
        if (task->itk_self == IP_NULL) {
                itk_unlock(task);
                return KERN_FAILURE;
        }

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		if (exception_mask & (1 << i)) {
			old_port[i] = task->exc_actions[i].port;
			task->exc_actions[i].port =
				ipc_port_copy_send(new_port);
			task->exc_actions[i].behavior = new_behavior;
			task->exc_actions[i].flavor = new_flavor;
		} else
			old_port[i] = IP_NULL;
	}/* for */

	/*
	 * Consume send rights without any lock held.
	 */
        itk_unlock(task);
	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++)
		if (IP_VALID(old_port[i]))
			ipc_port_release_send(old_port[i]);
	if (IP_VALID(new_port))		 /* consume send right */
		ipc_port_release_send(new_port);

        return KERN_SUCCESS;
}/* task_set_exception_port */

/*
 *	Routine:	thread/task_swap_exception_ports [kernel call]
 *	Purpose:
 *			Sets the thread/task exception port, flavor and
 *			behavior for the exception types specified by the
 *			mask.
 *
 *			The old ports, behavior and flavors are returned
 *			Count specifies the array sizes on input and
 *			the number of returned ports etc. on output.  The
 *			arrays must be large enough to hold all the returned
 *			data, MIG returnes an error otherwise.  The masks
 *			array specifies the corresponding exception type(s).
 *
 *	Conditions:
 *		Nothing locked.  If successful, consumes
 *		the supplied send right.
 *
 *		Returns upto [in} CountCnt elements.
 *	Returns:
 *		KERN_SUCCESS		Changed the special port.
 *		KERN_INVALID_ARGUMENT	The thread is null,
 *					Illegal mask bit set.
 *					Illegal exception behavior
 *		KERN_FAILURE		The thread is dead.
 */

kern_return_t
thread_swap_exception_ports(
	thread_act_t			thr_act,
	exception_mask_t		exception_mask,
	ipc_port_t			new_port,
	exception_behavior_t		new_behavior,
	thread_state_flavor_t		new_flavor,
	exception_mask_array_t		masks,
	mach_msg_type_number_t		* CountCnt,
	exception_port_array_t		ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors	)
{
	register int	i,
			j,
			count;
	ipc_port_t	old_port[EXC_TYPES_COUNT];

	if (!thr_act)
		return KERN_INVALID_ARGUMENT;

	if (exception_mask & ~EXC_MASK_ALL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (IP_VALID(new_port)) {
		switch (new_behavior) {
		case EXCEPTION_DEFAULT:
		case EXCEPTION_STATE:
		case EXCEPTION_STATE_IDENTITY:
			break;
		default:
			return KERN_INVALID_ARGUMENT;
		}
	}
	/* Cannot easily check "new_flavor", but that just means that
	 * the flavor in the generated exception message might be garbage:
	 * GIGO */

	act_lock(thr_act);
	if (!thr_act->active) {
		act_unlock(thr_act);
		return KERN_FAILURE;
	}

	count = 0;

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		if (exception_mask & (1 << i)) {
			for (j = 0; j < count; j++) {
/*
 *				search for an identical entry, if found
 *				set corresponding mask for this exception.
 */
				if (thr_act->exc_actions[i].port == ports[j] &&
				  thr_act->exc_actions[i].behavior ==behaviors[j]
				  && thr_act->exc_actions[i].flavor ==flavors[j])
				{
					masks[j] |= (1 << i);
					break;
				}
			}/* for */
			if (j == count) {
				masks[j] = (1 << i);
				ports[j] =
				ipc_port_copy_send(thr_act->exc_actions[i].port);

				behaviors[j] = thr_act->exc_actions[i].behavior;
				flavors[j] = thr_act->exc_actions[i].flavor;
				count++;
			}

			old_port[i] = thr_act->exc_actions[i].port;
			thr_act->exc_actions[i].port =
				ipc_port_copy_send(new_port);
			thr_act->exc_actions[i].behavior = new_behavior;
			thr_act->exc_actions[i].flavor = new_flavor;
			if (count > *CountCnt) {
				break;
			}
		} else
			old_port[i] = IP_NULL;
	}/* for */

	/*
	 * Consume send rights without any lock held.
	 */
	act_unlock(thr_act);
	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++)
		if (IP_VALID(old_port[i]))
			ipc_port_release_send(old_port[i]);
	if (IP_VALID(new_port))		 /* consume send right */
		ipc_port_release_send(new_port);
	*CountCnt = count;
	return KERN_SUCCESS;
}/* thread_swap_exception_ports */

kern_return_t
task_swap_exception_ports(
	task_t				task,
	exception_mask_t		exception_mask,
	ipc_port_t			new_port,
	exception_behavior_t		new_behavior,
	thread_state_flavor_t		new_flavor,
	exception_mask_array_t		masks,
	mach_msg_type_number_t		* CountCnt,
	exception_port_array_t		ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors		)
{
	register int	i,
			j,
			count;
	ipc_port_t	old_port[EXC_TYPES_COUNT];

	if (task == TASK_NULL)
		return KERN_INVALID_ARGUMENT;

	if (exception_mask & ~EXC_MASK_ALL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (IP_VALID(new_port)) {
		switch (new_behavior) {
		case EXCEPTION_DEFAULT:
		case EXCEPTION_STATE:
		case EXCEPTION_STATE_IDENTITY:
			break;
		default:
			return KERN_INVALID_ARGUMENT;
		}
	}
	/* Cannot easily check "new_flavor", but that just means that
	 * the flavor in the generated exception message might be garbage:
	 * GIGO */

	itk_lock(task);
	if (task->itk_self == IP_NULL) {
		itk_unlock(task);
		return KERN_FAILURE;
	}

	count = 0;

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		if (exception_mask & (1 << i)) {
			for (j = 0; j < count; j++) {
/*
 *				search for an identical entry, if found
 *				set corresponding mask for this exception.
 */
				if (task->exc_actions[i].port == ports[j] &&
				  task->exc_actions[i].behavior == behaviors[j]
				  && task->exc_actions[i].flavor == flavors[j])
				{
					masks[j] |= (1 << i);
					break;
				}
			}/* for */
			if (j == count) {
				masks[j] = (1 << i);
				ports[j] =
				ipc_port_copy_send(task->exc_actions[i].port);
				behaviors[j] = task->exc_actions[i].behavior;
				flavors[j] = task->exc_actions[i].flavor;
				count++;
			}
			old_port[i] = task->exc_actions[i].port;
			task->exc_actions[i].port =
				ipc_port_copy_send(new_port);
			task->exc_actions[i].behavior = new_behavior;
			task->exc_actions[i].flavor = new_flavor;
			if (count > *CountCnt) {
				break;
			}
		} else
			old_port[i] = IP_NULL;
	}/* for */


	/*
	 * Consume send rights without any lock held.
	 */
	itk_unlock(task);
	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++)
		if (IP_VALID(old_port[i]))
			ipc_port_release_send(old_port[i]);
	if (IP_VALID(new_port))		 /* consume send right */
		ipc_port_release_send(new_port);
	*CountCnt = count;

	return KERN_SUCCESS;
}/* task_swap_exception_ports */

/*
 *	Routine:	thread/task_get_exception_ports [kernel call]
 *	Purpose:
 *		Clones a send right for each of the thread/task's exception
 *		ports specified in the mask and returns the behaviour
 *		and flavor of said port.
 *
 *		Returns upto [in} CountCnt elements.
 *
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Extracted a send right.
 *		KERN_INVALID_ARGUMENT	The thread is null,
 *					Invalid special port,
 *					Illegal mask bit set.
 *		KERN_FAILURE		The thread is dead.
 */

kern_return_t
thread_get_exception_ports(
	thread_act_t			thr_act,
	exception_mask_t                exception_mask,
	exception_mask_array_t		masks,
	mach_msg_type_number_t		* CountCnt,
	exception_port_array_t		ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors		)
{
	register int	i,
			j,
			count;

	if (!thr_act)
		return KERN_INVALID_ARGUMENT;

	if (exception_mask & ~EXC_MASK_ALL) {
		return KERN_INVALID_ARGUMENT;
	}

	act_lock(thr_act);
	if (!thr_act->active) {
		act_unlock(thr_act);
		return KERN_FAILURE;
	}

	count = 0;

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		if (exception_mask & (1 << i)) {
			for (j = 0; j < count; j++) {
/*
 *				search for an identical entry, if found
 *				set corresponding mask for this exception.
 */
				if (thr_act->exc_actions[i].port == ports[j] &&
				  thr_act->exc_actions[i].behavior ==behaviors[j]
				  && thr_act->exc_actions[i].flavor == flavors[j])
				{
					masks[j] |= (1 << i);
					break;
				}
			}/* for */
			if (j == count) {
				masks[j] = (1 << i);
				ports[j] =
				ipc_port_copy_send(thr_act->exc_actions[i].port);
				behaviors[j] = thr_act->exc_actions[i].behavior;
				flavors[j] = thr_act->exc_actions[i].flavor;
				count++;
				if (count >= *CountCnt) {
					break;
				}
			}
		}
	}/* for */

	act_unlock(thr_act);

	*CountCnt = count;
	return KERN_SUCCESS;
}/* thread_get_exception_ports */

kern_return_t
task_get_exception_ports(
	task_t				task,
	exception_mask_t                exception_mask,
	exception_mask_array_t		masks,
	mach_msg_type_number_t		* CountCnt,
	exception_port_array_t		ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors		)
{
	register int	i,
			j,
			count;

	if (task == TASK_NULL)
		return KERN_INVALID_ARGUMENT;

	if (exception_mask & ~EXC_MASK_ALL) {
		return KERN_INVALID_ARGUMENT;
	}

	itk_lock(task);
	if (task->itk_self == IP_NULL) {
		itk_unlock(task);
		return KERN_FAILURE;
	}

	count = 0;

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		if (exception_mask & (1 << i)) {
			for (j = 0; j < count; j++) {
/*
 *				search for an identical entry, if found
 *				set corresponding mask for this exception.
 */
				if (task->exc_actions[i].port == ports[j] &&
				  task->exc_actions[i].behavior == behaviors[j]
				  && task->exc_actions[i].flavor == flavors[j])
				{
					masks[j] |= (1 << i);
					break;
				}
			}/* for */
			if (j == count) {
				masks[j] = (1 << i);
				ports[j] =
				  ipc_port_copy_send(task->exc_actions[i].port);
				behaviors[j] = task->exc_actions[i].behavior;
				flavors[j] = task->exc_actions[i].flavor;
				count++;
				if (count > *CountCnt) {
					break;
				}
			}
		}
	}/* for */

	itk_unlock(task);

	*CountCnt = count;
	return KERN_SUCCESS;
}/* task_get_exception_ports */
