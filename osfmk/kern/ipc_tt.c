/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
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
#include <mach/kern_return.h>
#include <mach/mach_param.h>
#include <mach/task_special_ports.h>
#include <mach/thread_special_ports.h>
#include <mach/thread_status.h>
#include <mach/exception_types.h>
#include <mach/memory_object_types.h>
#include <mach/mach_traps.h>
#include <mach/task_server.h>
#include <mach/thread_act_server.h>
#include <mach/mach_host_server.h>
#include <mach/host_priv_server.h>
#include <mach/vm_map_server.h>

#include <kern/kern_types.h>
#include <kern/host.h>
#include <kern/ipc_kobject.h>
#include <kern/ipc_tt.h>
#include <kern/kalloc.h>
#include <kern/thread.h>
#include <kern/misc_protos.h>

#include <vm/vm_map.h>
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>

#include <security/mac_mach_internal.h>

/* forward declarations */
task_t convert_port_to_locked_task(ipc_port_t port);


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
	ipc_port_t nport;
	kern_return_t kr;
	int i;


	kr = ipc_space_create(&ipc_table_entries[0], &space);
	if (kr != KERN_SUCCESS)
		panic("ipc_task_init");

	space->is_task = task;

	kport = ipc_port_alloc_kernel();
	if (kport == IP_NULL)
		panic("ipc_task_init");

	nport = ipc_port_alloc_kernel();
	if (nport == IP_NULL)
		panic("ipc_task_init");

	itk_lock_init(task);
	task->itk_self = kport;
	task->itk_nself = nport;
	task->itk_sself = ipc_port_make_send(kport);
	task->itk_space = space;
	space->is_fast = FALSE;

#if CONFIG_MACF_MACH
	if (parent)
		mac_task_label_associate(parent, task, &parent->maclabel,
		    &task->maclabel, &kport->ip_label);
	else
		mac_task_label_associate_kernel(task, &task->maclabel, &kport->ip_label);
#endif

	if (parent == TASK_NULL) {
		ipc_port_t port;

		for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
			task->exc_actions[i].port = IP_NULL;
		}/* for */
		
		kr = host_get_host_port(host_priv_self(), &port);
		assert(kr == KERN_SUCCESS);
		task->itk_host = port;

		task->itk_bootstrap = IP_NULL;
		task->itk_seatbelt = IP_NULL;
		task->itk_gssd = IP_NULL;
		task->itk_task_access = IP_NULL;

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
		    task->exc_actions[i].privileged =
				parent->exc_actions[i].privileged;
		}/* for */
		task->itk_host =
			ipc_port_copy_send(parent->itk_host);

		task->itk_bootstrap =
			ipc_port_copy_send(parent->itk_bootstrap);

		task->itk_seatbelt =
			ipc_port_copy_send(parent->itk_seatbelt);

		task->itk_gssd =
			ipc_port_copy_send(parent->itk_gssd);

		task->itk_task_access =
			ipc_port_copy_send(parent->itk_task_access);

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
	ipc_port_t nport;

	itk_lock(task);
	kport = task->itk_self;
	if (kport != IP_NULL)
		ipc_kobject_set(kport, (ipc_kobject_t) task, IKOT_TASK);
	nport = task->itk_nself;
	if (nport != IP_NULL)
		ipc_kobject_set(nport, (ipc_kobject_t) task, IKOT_TASK_NAME);
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
	ipc_port_t nport;

	itk_lock(task);
	kport = task->itk_self;
	if (kport != IP_NULL)
		ipc_kobject_set(kport, IKO_NULL, IKOT_NONE);
	nport = task->itk_nself;
	if (nport != IP_NULL)
		ipc_kobject_set(nport, IKO_NULL, IKOT_NONE);
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
	ipc_port_t nport;
	int i;

	itk_lock(task);
	kport = task->itk_self;

	if (kport == IP_NULL) {
		/* the task is already terminated (can this happen?) */
		itk_unlock(task);
		return;
	}
	task->itk_self = IP_NULL;

	nport = task->itk_nself;
	assert(nport != IP_NULL);
	task->itk_nself = IP_NULL;

	itk_unlock(task);

	/* release the naked send rights */

	if (IP_VALID(task->itk_sself))
		ipc_port_release_send(task->itk_sself);

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		if (IP_VALID(task->exc_actions[i].port)) {
			ipc_port_release_send(task->exc_actions[i].port);
		}
	}

	if (IP_VALID(task->itk_host))
		ipc_port_release_send(task->itk_host);

	if (IP_VALID(task->itk_bootstrap))
		ipc_port_release_send(task->itk_bootstrap);

	if (IP_VALID(task->itk_seatbelt))
		ipc_port_release_send(task->itk_seatbelt);
	
	if (IP_VALID(task->itk_gssd))
		ipc_port_release_send(task->itk_gssd);

	if (IP_VALID(task->itk_task_access))
		ipc_port_release_send(task->itk_task_access);

	for (i = 0; i < TASK_PORT_REGISTER_MAX; i++)
		if (IP_VALID(task->itk_registered[i]))
			ipc_port_release_send(task->itk_registered[i]);

	ipc_port_release_send(task->wired_ledger_port);
	ipc_port_release_send(task->paged_ledger_port);

	/* destroy the kernel ports */
	ipc_port_dealloc_kernel(kport);
	ipc_port_dealloc_kernel(nport);

	itk_lock_destroy(task);
}

/*
 *	Routine:	ipc_task_reset
 *	Purpose:
 *		Reset a task's IPC state to protect it when
 *		it enters an elevated security context. The
 *		task name port can remain the same - since
 *		it represents no specific privilege.
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
	ipc_port_t old_exc_actions[EXC_TYPES_COUNT];
	int i;

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

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		if (!task->exc_actions[i].privileged) {
			old_exc_actions[i] = task->exc_actions[i].port;
			task->exc_actions[i].port = IP_NULL;
		} else {
			old_exc_actions[i] = IP_NULL;
		}
	}/* for */

	itk_unlock(task);

	/* release the naked send rights */

	if (IP_VALID(old_sself))
		ipc_port_release_send(old_sself);

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		if (IP_VALID(old_exc_actions[i])) {
			ipc_port_release_send(old_exc_actions[i]);
		}
	}/* for */

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
	ipc_port_t	kport;
	int			i;

	kport = ipc_port_alloc_kernel();
	if (kport == IP_NULL)
		panic("ipc_thread_init");

	thread->ith_self = kport;
	thread->ith_sself = ipc_port_make_send(kport);

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; ++i)
		thread->exc_actions[i].port = IP_NULL;

	ipc_kobject_set(kport, (ipc_kobject_t)thread, IKOT_THREAD);

	ipc_kmsg_queue_init(&thread->ith_messages);

	thread->ith_rpc_reply = IP_NULL;
}

void
ipc_thread_disable(
	thread_t	thread)
{
	ipc_port_t	kport = thread->ith_self;

	if (kport != IP_NULL)
		ipc_kobject_set(kport, IKO_NULL, IKOT_NONE);
}

/*
 *	Routine:	ipc_thread_terminate
 *	Purpose:
 *		Clean up and destroy a thread's IPC state.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_thread_terminate(
	thread_t	thread)
{
	ipc_port_t	kport = thread->ith_self;

	if (kport != IP_NULL) {
		int			i;

		if (IP_VALID(thread->ith_sself))
			ipc_port_release_send(thread->ith_sself);

		thread->ith_sself = thread->ith_self = IP_NULL;

		for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; ++i) {
			if (IP_VALID(thread->exc_actions[i].port))
				ipc_port_release_send(thread->exc_actions[i].port);
        }

		ipc_port_dealloc_kernel(kport);
	}

	assert(ipc_kmsg_queue_empty(&thread->ith_messages));

	if (thread->ith_rpc_reply != IP_NULL)
		ipc_port_dealloc_reply(thread->ith_rpc_reply);

	thread->ith_rpc_reply = IP_NULL;
}

/*
 *	Routine:	ipc_thread_reset
 *	Purpose:
 *		Reset the IPC state for a given Mach thread when
 *		its task enters an elevated security context.
 * 		Both the thread port and its exception ports have
 *		to be reset.  Its RPC reply port cannot have any
 *		rights outstanding, so it should be fine.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_thread_reset(
	thread_t	thread)
{
	ipc_port_t old_kport, new_kport;
	ipc_port_t old_sself;
	ipc_port_t old_exc_actions[EXC_TYPES_COUNT];
	int i;

	new_kport = ipc_port_alloc_kernel();
	if (new_kport == IP_NULL)
		panic("ipc_task_reset");

	thread_mtx_lock(thread);

	old_kport = thread->ith_self;

	if (old_kport == IP_NULL) {
		/* the  is already terminated (can this happen?) */
		thread_mtx_unlock(thread);
		ipc_port_dealloc_kernel(new_kport);
		return;
	}

	thread->ith_self = new_kport;
	old_sself = thread->ith_sself;
	thread->ith_sself = ipc_port_make_send(new_kport);
	ipc_kobject_set(old_kport, IKO_NULL, IKOT_NONE);
	ipc_kobject_set(new_kport, (ipc_kobject_t) thread, IKOT_THREAD);

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		if (!thread->exc_actions[i].privileged) {
			old_exc_actions[i] = thread->exc_actions[i].port;
			thread->exc_actions[i].port = IP_NULL;
		} else {
			old_exc_actions[i] = IP_NULL;
		}
	}/* for */

	thread_mtx_unlock(thread);

	/* release the naked send rights */

	if (IP_VALID(old_sself))
		ipc_port_release_send(old_sself);

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		if (IP_VALID(old_exc_actions[i])) {
			ipc_port_release_send(old_exc_actions[i]);
		}
	}/* for */

	/* destroy the kernel port */
	ipc_port_dealloc_kernel(old_kport);
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
 *	Routine:	retrieve_thread_self_fast
 *	Purpose:
 *		Return a send right (possibly null/dead)
 *		for the thread's user-visible self port.
 *
 *		Only works for the current thread.
 *
 *	Conditions:
 *		Nothing locked.
 */

ipc_port_t
retrieve_thread_self_fast(
	thread_t		thread)
{
	register ipc_port_t port;

	assert(thread == current_thread());

	thread_mtx_lock(thread);

	assert(thread->ith_self != IP_NULL);

	if ((port = thread->ith_sself) == thread->ith_self) {
		/* no interposing */

		ip_lock(port);
		assert(ip_active(port));
		ip_reference(port);
		port->ip_srights++;
		ip_unlock(port);
	}
	else
		port = ipc_port_copy_send(port);

	thread_mtx_unlock(thread);

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
task_self_trap(
	__unused struct task_self_trap_args *args)
{
	task_t task = current_task();
	ipc_port_t sright;
	mach_port_name_t name;

	sright = retrieve_task_self_fast(task);
	name = ipc_port_copyout_send(sright, task->itk_space);
	return name;
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
thread_self_trap(
	__unused struct thread_self_trap_args *args)
{
	thread_t  thread = current_thread();
	task_t task = thread->task;
	ipc_port_t sright;
	mach_port_name_t name;

	sright = retrieve_thread_self_fast(thread);
	name = ipc_port_copyout_send(sright, task->itk_space);
	return name;

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
mach_reply_port(
	__unused struct mach_reply_port_args *args)
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
 *	Routine:	thread_get_special_port [kernel call]
 *	Purpose:
 *		Clones a send right for one of the thread's
 *		special ports.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Extracted a send right.
 *		KERN_INVALID_ARGUMENT	The thread is null.
 *		KERN_FAILURE		The thread is dead.
 *		KERN_INVALID_ARGUMENT	Invalid special port.
 */

kern_return_t
thread_get_special_port(
	thread_t		thread,
	int				which,
	ipc_port_t		*portp)
{
	kern_return_t	result = KERN_SUCCESS;
	ipc_port_t		*whichp;

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	switch (which) {

	case THREAD_KERNEL_PORT:
		whichp = &thread->ith_sself;
		break;

	default:
		return (KERN_INVALID_ARGUMENT);
	}

 	thread_mtx_lock(thread);

	if (thread->active)
		*portp = ipc_port_copy_send(*whichp);
	else
		result = KERN_FAILURE;

	thread_mtx_unlock(thread);

	return (result);
}

/*
 *	Routine:	thread_set_special_port [kernel call]
 *	Purpose:
 *		Changes one of the thread's special ports,
 *		setting it to the supplied send right.
 *	Conditions:
 *		Nothing locked.  If successful, consumes
 *		the supplied send right.
 *	Returns:
 *		KERN_SUCCESS		Changed the special port.
 *		KERN_INVALID_ARGUMENT	The thread is null.
 *		KERN_FAILURE		The thread is dead.
 *		KERN_INVALID_ARGUMENT	Invalid special port.
 */

kern_return_t
thread_set_special_port(
	thread_t		thread,
	int			which,
	ipc_port_t	port)
{
	kern_return_t	result = KERN_SUCCESS;
	ipc_port_t		*whichp, old = IP_NULL;

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	switch (which) {

	case THREAD_KERNEL_PORT:
		whichp = &thread->ith_sself;
		break;

	default:
		return (KERN_INVALID_ARGUMENT);
	}

	thread_mtx_lock(thread);

	if (thread->active) {
		old = *whichp;
		*whichp = port;
	}
	else
		result = KERN_FAILURE;

	thread_mtx_unlock(thread);

	if (IP_VALID(old))
		ipc_port_release_send(old);

	return (result);
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
	ipc_port_t port;

	if (task == TASK_NULL)
		return KERN_INVALID_ARGUMENT;

	itk_lock(task);
	if (task->itk_self == IP_NULL) {
		itk_unlock(task);
		return KERN_FAILURE;
	}

	switch (which) {
	    case TASK_KERNEL_PORT:
		port = ipc_port_copy_send(task->itk_sself);
		break;

	    case TASK_NAME_PORT:
		port = ipc_port_make_send(task->itk_nself);
		break;

	    case TASK_HOST_PORT:
		port = ipc_port_copy_send(task->itk_host);
		break;

	    case TASK_BOOTSTRAP_PORT:
		port = ipc_port_copy_send(task->itk_bootstrap);
		break;

	    case TASK_WIRED_LEDGER_PORT:
		port = ipc_port_copy_send(task->wired_ledger_port);
		break;

	    case TASK_PAGED_LEDGER_PORT:
		port = ipc_port_copy_send(task->paged_ledger_port);
		break;
                    
	    case TASK_SEATBELT_PORT:
		port = ipc_port_copy_send(task->itk_seatbelt);
		break;

	    case TASK_GSSD_PORT:
		port = ipc_port_copy_send(task->itk_gssd);
		break;
			
	    case TASK_ACCESS_PORT:
		port = ipc_port_copy_send(task->itk_task_access);
		break;
			
	    default:
               itk_unlock(task);
		return KERN_INVALID_ARGUMENT;
	}
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
 * 		KERN_NO_ACCESS		Attempted overwrite of seatbelt port.
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
                    
	    case TASK_SEATBELT_PORT:
		whichp = &task->itk_seatbelt;
		break;

	    case TASK_GSSD_PORT:
		whichp = &task->itk_gssd;
		break;
		
	    case TASK_ACCESS_PORT:
		whichp = &task->itk_task_access;
		break;
		
	    default:
		return KERN_INVALID_ARGUMENT;
	}/* switch */

	itk_lock(task);
	if (task->itk_self == IP_NULL) {
		itk_unlock(task);
		return KERN_FAILURE;
	}

	/* do not allow overwrite of seatbelt or task access ports */
	if ((TASK_SEATBELT_PORT == which  || TASK_ACCESS_PORT == which) 
		&& IP_VALID(*whichp)) {
			itk_unlock(task);
			return KERN_NO_ACCESS;
	}

#if CONFIG_MACF_MACH
       if (mac_task_check_service(current_task(), task, "set_special_port")) {
               itk_unlock(task);
               return KERN_NO_ACCESS;
       }
#endif

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
	unsigned int i;

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
		kfree(memory,
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
	void  *memory;
	vm_size_t size;
	ipc_port_t *ports;
	int i;

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
        int try_failed_count = 0;

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
		try_failed_count++;

		ip_unlock(port);
		mutex_pause(try_failed_count);
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
	ipc_port_t		port)
{
	task_t		task = TASK_NULL;

	if (IP_VALID(port)) {
		ip_lock(port);

		if (	ip_active(port)					&&
				ip_kotype(port) == IKOT_TASK		) {
			task = (task_t)port->ip_kobject;
			assert(task != TASK_NULL);

			task_reference_internal(task);
		}

		ip_unlock(port);
	}

	return (task);
}

/*
 *	Routine:	convert_port_to_task_name
 *	Purpose:
 *		Convert from a port to a task name.
 *		Doesn't consume the port ref; produces a task name ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */
task_name_t
convert_port_to_task_name(
	ipc_port_t		port)
{
	task_name_t		task = TASK_NULL;

	if (IP_VALID(port)) {
		ip_lock(port);

		if (	ip_active(port)					&&
				(ip_kotype(port) == IKOT_TASK	||
				 ip_kotype(port) == IKOT_TASK_NAME)) {
			task = (task_name_t)port->ip_kobject;
			assert(task != TASK_NAME_NULL);

			task_reference_internal(task);
		}

		ip_unlock(port);
	}

	return (task);
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
 *	Routine:	convert_port_to_thread
 *	Purpose:
 *		Convert from a port to a thread.
 *		Doesn't consume the port ref; produces an thread ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */

thread_t
convert_port_to_thread(
	ipc_port_t		port)
{
	thread_t	thread = THREAD_NULL;

	if (IP_VALID(port)) {
		ip_lock(port);

		if (	ip_active(port)					&&
				ip_kotype(port) == IKOT_THREAD		) {
			thread = (thread_t)port->ip_kobject;
			assert(thread != THREAD_NULL);

			thread_reference_internal(thread);
		}

		ip_unlock(port);
	}

	return (thread);
}

/*
 *	Routine:	port_name_to_thread
 *	Purpose:
 *		Convert from a port name to an thread reference
 *		A name of MACH_PORT_NULL is valid for the null thread.
 *	Conditions:
 *		Nothing locked.
 */
thread_t
port_name_to_thread(
	mach_port_name_t	name)
{
	thread_t	thread = THREAD_NULL;
	ipc_port_t	kport;

	if (MACH_PORT_VALID(name)) {
		if (ipc_object_copyin(current_space(), name,
					       MACH_MSG_TYPE_COPY_SEND,
							  (ipc_object_t *)&kport) != KERN_SUCCESS)
			return (THREAD_NULL);

		thread = convert_port_to_thread(kport);
		
		if (IP_VALID(kport))
			ipc_port_release_send(kport);
	}

	return (thread);
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
		port = ipc_port_make_send(task->itk_self);
	else
		port = IP_NULL;
	itk_unlock(task);

	task_deallocate(task);
	return port;
}

/*
 *	Routine:	convert_task_name_to_port
 *	Purpose:
 *		Convert from a task name ref to a port.
 *		Consumes a task name ref; produces a naked send right
 *		which may be invalid.  
 *	Conditions:
 *		Nothing locked.
 */

ipc_port_t
convert_task_name_to_port(
	task_name_t		task_name)
{
	ipc_port_t port;

	itk_lock(task_name);
	if (task_name->itk_nself != IP_NULL)
		port = ipc_port_make_send(task_name->itk_nself);
	else
		port = IP_NULL;
	itk_unlock(task_name);

	task_name_deallocate(task_name);
	return port;
}

/*
 *	Routine:	convert_thread_to_port
 *	Purpose:
 *		Convert from a thread to a port.
 *		Consumes an thread ref; produces a naked send right
 *		which may be invalid.
 *	Conditions:
 *		Nothing locked.
 */

ipc_port_t
convert_thread_to_port(
	thread_t		thread)
{
	ipc_port_t		port;

	thread_mtx_lock(thread);

	if (thread->ith_self != IP_NULL)
		port = ipc_port_make_send(thread->ith_self);
	else
		port = IP_NULL;

	thread_mtx_unlock(thread);

	thread_deallocate(thread);

	return (port);
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
	thread_t		 		thread,
	exception_mask_t		exception_mask,
	ipc_port_t				new_port,
	exception_behavior_t	new_behavior,
	thread_state_flavor_t	new_flavor)
{
	ipc_port_t		old_port[EXC_TYPES_COUNT];
	boolean_t privileged = current_task()->sec_token.val[0] == 0;
	register int	i;

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	if (exception_mask & ~EXC_MASK_VALID)
		return (KERN_INVALID_ARGUMENT);

	if (IP_VALID(new_port)) {
		switch (new_behavior & ~MACH_EXCEPTION_CODES) {

		case EXCEPTION_DEFAULT:
		case EXCEPTION_STATE:
		case EXCEPTION_STATE_IDENTITY:
			break;

		default:
			return (KERN_INVALID_ARGUMENT);
		}
	}

	/* 
	 * Check the validity of the thread_state_flavor by calling the
	 * VALID_THREAD_STATE_FLAVOR architecture dependent macro defined in
	 * osfmk/mach/ARCHITECTURE/thread_status.h
	 */
	if (!VALID_THREAD_STATE_FLAVOR(new_flavor))
		return (KERN_INVALID_ARGUMENT);

	thread_mtx_lock(thread);

	if (!thread->active) {
		thread_mtx_unlock(thread);

		return (KERN_FAILURE);
	}

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; ++i) {
		if (exception_mask & (1 << i)) {
			old_port[i] = thread->exc_actions[i].port;
			thread->exc_actions[i].port = ipc_port_copy_send(new_port);
			thread->exc_actions[i].behavior = new_behavior;
			thread->exc_actions[i].flavor = new_flavor;
			thread->exc_actions[i].privileged = privileged;
		}
		else
			old_port[i] = IP_NULL;
	}

	thread_mtx_unlock(thread);

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; ++i)
		if (IP_VALID(old_port[i]))
			ipc_port_release_send(old_port[i]);

	if (IP_VALID(new_port))		 /* consume send right */
		ipc_port_release_send(new_port);

	return (KERN_SUCCESS);
}

kern_return_t
task_set_exception_ports(
	task_t					task,
	exception_mask_t		exception_mask,
	ipc_port_t				new_port,
	exception_behavior_t	new_behavior,
	thread_state_flavor_t	new_flavor)
{
	ipc_port_t		old_port[EXC_TYPES_COUNT];
	boolean_t privileged = current_task()->sec_token.val[0] == 0;
	register int	i;

	if (task == TASK_NULL)
		return (KERN_INVALID_ARGUMENT);

	if (exception_mask & ~EXC_MASK_VALID)
		return (KERN_INVALID_ARGUMENT);

	if (IP_VALID(new_port)) {
		switch (new_behavior & ~MACH_EXCEPTION_CODES) {

		case EXCEPTION_DEFAULT:
		case EXCEPTION_STATE:
		case EXCEPTION_STATE_IDENTITY:
			break;

		default:
			return (KERN_INVALID_ARGUMENT);
		}
	}

	itk_lock(task);

	if (task->itk_self == IP_NULL) {
		itk_unlock(task);

		return (KERN_FAILURE);
	}

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; ++i) {
		if (exception_mask & (1 << i)) {
			old_port[i] = task->exc_actions[i].port;
			task->exc_actions[i].port =
				ipc_port_copy_send(new_port);
			task->exc_actions[i].behavior = new_behavior;
			task->exc_actions[i].flavor = new_flavor;
			task->exc_actions[i].privileged = privileged;
		}
		else
			old_port[i] = IP_NULL;
	}

	itk_unlock(task);

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; ++i)
		if (IP_VALID(old_port[i]))
			ipc_port_release_send(old_port[i]);

	if (IP_VALID(new_port))		 /* consume send right */
		ipc_port_release_send(new_port);

	return (KERN_SUCCESS);
}

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
	thread_t					thread,
	exception_mask_t			exception_mask,
	ipc_port_t					new_port,
	exception_behavior_t		new_behavior,
	thread_state_flavor_t		new_flavor,
	exception_mask_array_t		masks,
	mach_msg_type_number_t		*CountCnt,
	exception_port_array_t		ports,
	exception_behavior_array_t	behaviors,
	thread_state_flavor_array_t	flavors)
{
	ipc_port_t		old_port[EXC_TYPES_COUNT];
	boolean_t privileged = current_task()->sec_token.val[0] == 0;
	unsigned int	i, j, count;

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	if (exception_mask & ~EXC_MASK_VALID)
		return (KERN_INVALID_ARGUMENT);

	if (IP_VALID(new_port)) {
		switch (new_behavior & ~MACH_EXCEPTION_CODES) {

		case EXCEPTION_DEFAULT:
		case EXCEPTION_STATE:
		case EXCEPTION_STATE_IDENTITY:
			break;

		default:
			return (KERN_INVALID_ARGUMENT);
		}
	}

	thread_mtx_lock(thread);

	if (!thread->active) {
		thread_mtx_unlock(thread);

		return (KERN_FAILURE);
	}

	count = 0;

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; ++i) {
		if (exception_mask & (1 << i)) {
			for (j = 0; j < count; ++j) {
				/*
				 * search for an identical entry, if found
				 * set corresponding mask for this exception.
				 */
				if (	thread->exc_actions[i].port == ports[j]				&&
						thread->exc_actions[i].behavior == behaviors[j]		&&
						thread->exc_actions[i].flavor == flavors[j]			) {
					masks[j] |= (1 << i);
					break;
				}
			}

			if (j == count) {
				masks[j] = (1 << i);
				ports[j] = ipc_port_copy_send(thread->exc_actions[i].port);

				behaviors[j] = thread->exc_actions[i].behavior;
				flavors[j] = thread->exc_actions[i].flavor;
				++count;
			}

			old_port[i] = thread->exc_actions[i].port;
			thread->exc_actions[i].port = ipc_port_copy_send(new_port);
			thread->exc_actions[i].behavior = new_behavior;
			thread->exc_actions[i].flavor = new_flavor;
			thread->exc_actions[i].privileged = privileged;
			if (count > *CountCnt)
				break;
		}
		else
			old_port[i] = IP_NULL;
	}

	thread_mtx_unlock(thread);

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; ++i)
		if (IP_VALID(old_port[i]))
			ipc_port_release_send(old_port[i]);

	if (IP_VALID(new_port))		 /* consume send right */
		ipc_port_release_send(new_port);

	*CountCnt = count;

	return (KERN_SUCCESS);
}

kern_return_t
task_swap_exception_ports(
	task_t						task,
	exception_mask_t			exception_mask,
	ipc_port_t					new_port,
	exception_behavior_t		new_behavior,
	thread_state_flavor_t		new_flavor,
	exception_mask_array_t		masks,
	mach_msg_type_number_t		*CountCnt,
	exception_port_array_t		ports,
	exception_behavior_array_t	behaviors,
	thread_state_flavor_array_t	flavors)
{
	ipc_port_t		old_port[EXC_TYPES_COUNT];
	boolean_t privileged = current_task()->sec_token.val[0] == 0;
	unsigned int	i, j, count;

	if (task == TASK_NULL)
		return (KERN_INVALID_ARGUMENT);

	if (exception_mask & ~EXC_MASK_VALID)
		return (KERN_INVALID_ARGUMENT);

	if (IP_VALID(new_port)) {
		switch (new_behavior & ~MACH_EXCEPTION_CODES) {

		case EXCEPTION_DEFAULT:
		case EXCEPTION_STATE:
		case EXCEPTION_STATE_IDENTITY:
			break;

		default:
			return (KERN_INVALID_ARGUMENT);
		}
	}

	itk_lock(task);

	if (task->itk_self == IP_NULL) {
		itk_unlock(task);

		return (KERN_FAILURE);
	}

	count = 0;

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; ++i) {
		if (exception_mask & (1 << i)) {
			for (j = 0; j < count; j++) {
				/*
				 * search for an identical entry, if found
				 * set corresponding mask for this exception.
				 */
				if (	task->exc_actions[i].port == ports[j]			&&
						task->exc_actions[i].behavior == behaviors[j]	&&
						task->exc_actions[i].flavor == flavors[j]		) {
					masks[j] |= (1 << i);
					break;
				}
			}

			if (j == count) {
				masks[j] = (1 << i);
				ports[j] = ipc_port_copy_send(task->exc_actions[i].port);
				behaviors[j] = task->exc_actions[i].behavior;
				flavors[j] = task->exc_actions[i].flavor;
				++count;
			}

			old_port[i] = task->exc_actions[i].port;
			task->exc_actions[i].port =	ipc_port_copy_send(new_port);
			task->exc_actions[i].behavior = new_behavior;
			task->exc_actions[i].flavor = new_flavor;
			task->exc_actions[i].privileged = privileged;
			if (count > *CountCnt)
				break;
		}
		else
			old_port[i] = IP_NULL;
	}

	itk_unlock(task);

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++)
		if (IP_VALID(old_port[i]))
			ipc_port_release_send(old_port[i]);

	if (IP_VALID(new_port))		 /* consume send right */
		ipc_port_release_send(new_port);

	*CountCnt = count;

	return (KERN_SUCCESS);
}

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
	thread_t					thread,
	exception_mask_t			exception_mask,
	exception_mask_array_t		masks,
	mach_msg_type_number_t		*CountCnt,
	exception_port_array_t		ports,
	exception_behavior_array_t	behaviors,
	thread_state_flavor_array_t	flavors)
{
	unsigned int	i, j, count;

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	if (exception_mask & ~EXC_MASK_VALID)
		return (KERN_INVALID_ARGUMENT);

	thread_mtx_lock(thread);

	if (!thread->active) {
		thread_mtx_unlock(thread);

		return (KERN_FAILURE);
	}

	count = 0;

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; ++i) {
		if (exception_mask & (1 << i)) {
			for (j = 0; j < count; ++j) {
				/*
				 * search for an identical entry, if found
				 * set corresponding mask for this exception.
				 */
				if (	thread->exc_actions[i].port == ports[j]			&&
						thread->exc_actions[i].behavior ==behaviors[j]	&&
						thread->exc_actions[i].flavor == flavors[j]		) {
					masks[j] |= (1 << i);
					break;
				}
			}

			if (j == count) {
				masks[j] = (1 << i);
				ports[j] = ipc_port_copy_send(thread->exc_actions[i].port);
				behaviors[j] = thread->exc_actions[i].behavior;
				flavors[j] = thread->exc_actions[i].flavor;
				++count;
				if (count >= *CountCnt)
					break;
			}
		}
	}

	thread_mtx_unlock(thread);

	*CountCnt = count;

	return (KERN_SUCCESS);
}

kern_return_t
task_get_exception_ports(
	task_t						task,
	exception_mask_t			exception_mask,
	exception_mask_array_t		masks,
	mach_msg_type_number_t		*CountCnt,
	exception_port_array_t		ports,
	exception_behavior_array_t	behaviors,
	thread_state_flavor_array_t	flavors)
{
	unsigned int	i, j, count;

	if (task == TASK_NULL)
		return (KERN_INVALID_ARGUMENT);

	if (exception_mask & ~EXC_MASK_VALID)
		return (KERN_INVALID_ARGUMENT);

	itk_lock(task);

	if (task->itk_self == IP_NULL) {
		itk_unlock(task);

		return (KERN_FAILURE);
	}

	count = 0;

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; ++i) {
		if (exception_mask & (1 << i)) {
			for (j = 0; j < count; ++j) {
				/*
				 * search for an identical entry, if found
				 * set corresponding mask for this exception.
				 */
				if (	task->exc_actions[i].port == ports[j]			&&
						task->exc_actions[i].behavior == behaviors[j]	&&
						task->exc_actions[i].flavor == flavors[j]		) {
					masks[j] |= (1 << i);
					break;
				}
			}

			if (j == count) {
				masks[j] = (1 << i);
				ports[j] = ipc_port_copy_send(task->exc_actions[i].port);
				behaviors[j] = task->exc_actions[i].behavior;
				flavors[j] = task->exc_actions[i].flavor;
				++count;
				if (count > *CountCnt)
					break;
			}
		}
	}

	itk_unlock(task);

	*CountCnt = count;

	return (KERN_SUCCESS);
}
