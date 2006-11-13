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
 * @OSF_FREE_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
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
 *	File:	kern/task.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young, David Golub,
 *		David Black
 *
 *	Task management primitives implementation.
 */
/*
 * Copyright (c) 1993 The University of Utah and
 * the Computer Systems Laboratory (CSL).  All rights reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * THE UNIVERSITY OF UTAH AND CSL ALLOW FREE USE OF THIS SOFTWARE IN ITS "AS
 * IS" CONDITION.  THE UNIVERSITY OF UTAH AND CSL DISCLAIM ANY LIABILITY OF
 * ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * CSL requests users of this software to return to csl-dist@cs.utah.edu any
 * improvements that they make and grant CSL redistribution rights.
 *
 */

#include <mach_kdb.h>
#include <mach_host.h>
#include <mach_prof.h>
#include <fast_tas.h>
#include <platforms.h>

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/host_priv.h>
#include <mach/machine/vm_types.h>
#include <mach/vm_param.h>
#include <mach/semaphore.h>
#include <mach/task_info.h>
#include <mach/task_special_ports.h>

#include <ipc/ipc_types.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_entry.h>

#include <kern/kern_types.h>
#include <kern/mach_param.h>
#include <kern/misc_protos.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <kern/processor.h>
#include <kern/sched_prim.h>	/* for thread_wakeup */
#include <kern/ipc_tt.h>
#include <kern/ledger.h>
#include <kern/host.h>
#include <kern/clock.h>
#include <kern/timer.h>
#include <kern/profile.h>
#include <kern/assert.h>
#include <kern/sync_lock.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>		/* for kernel_map, ipc_kernel_map */
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>	/* for vm_map_remove_commpage64 */

#if	MACH_KDB
#include <ddb/db_sym.h>
#endif	/* MACH_KDB */

#ifdef __ppc__
#include <ppc/exception.h>
#include <ppc/hw_perfmon.h>
#endif

/*
 * Exported interfaces
 */

#include <mach/task_server.h>
#include <mach/mach_host_server.h>
#include <mach/host_security_server.h>
#include <mach/mach_port_server.h>

#include <vm/task_working_set.h>
#include <vm/vm_shared_memory_server.h>

task_t	kernel_task;
zone_t	task_zone;

/* Forwards */

void		task_hold_locked(
			task_t		task);
void		task_wait_locked(
			task_t		task);
void		task_release_locked(
			task_t		task);
void		task_free(
			task_t		task );
void		task_synchronizer_destroy_all(
			task_t		task);

kern_return_t	task_set_ledger(
			task_t		task,
			ledger_t	wired,
			ledger_t	paged);

void
task_backing_store_privileged(
			task_t task)
{
	task_lock(task);
	task->priv_flags |= VM_BACKING_STORE_PRIV;
	task_unlock(task);
	return;
}

void
task_working_set_disable(task_t task)
{
	struct tws_hash *ws;

	task_lock(task);
	ws = task->dynamic_working_set;
	task->dynamic_working_set = NULL;
	task_unlock(task);
	if (ws) {
		tws_hash_ws_flush(ws);
		tws_hash_destroy(ws);
	}
}

void
task_set_64bit(
		task_t task,
		boolean_t is64bit)
{
	if(is64bit) {
		/* LP64todo - no task working set for 64-bit */
		task_set_64BitAddr(task);
		task_working_set_disable(task);
		task->map->max_offset = MACH_VM_MAX_ADDRESS;
	} else {
		/*
		 * Deallocate all memory previously allocated
		 * above the 32-bit address space, since it won't
		 * be accessible anymore.
		 */
		/* LP64todo - make this clean */
#ifdef __ppc__
		vm_map_remove_commpage64(task->map);
		pmap_unmap_sharedpage(task->map->pmap);	/* Unmap commpage */
#endif
		(void) vm_map_remove(task->map,
				     (vm_map_offset_t) VM_MAX_ADDRESS,
				     MACH_VM_MAX_ADDRESS,
				     VM_MAP_NO_FLAGS);
		task_clear_64BitAddr(task);
		task->map->max_offset = (vm_map_offset_t)VM_MAX_ADDRESS;
	}
}

void
task_init(void)
{
	task_zone = zinit(
			sizeof(struct task),
			TASK_MAX * sizeof(struct task),
			TASK_CHUNK * sizeof(struct task),
			"tasks");

	/*
	 * Create the kernel task as the first task.
	 */
	if (task_create_internal(TASK_NULL, FALSE, &kernel_task) != KERN_SUCCESS)
		panic("task_init\n");

	vm_map_deallocate(kernel_task->map);
	kernel_task->map = kernel_map;
}

#if	MACH_HOST

#if 0
static void
task_freeze(
	task_t task)
{
	task_lock(task);
	/*
	 *	If may_assign is false, task is already being assigned,
	 *	wait for that to finish.
	 */
	while (task->may_assign == FALSE) {
		wait_result_t res;

		task->assign_active = TRUE;
		res = thread_sleep_mutex((event_t) &task->assign_active,
					 &task->lock, THREAD_UNINT);
		assert(res == THREAD_AWAKENED);
	}
	task->may_assign = FALSE;
	task_unlock(task);
	return;
}
#else
#define thread_freeze(thread)	assert(task->processor_set == &default_pset)
#endif

#if 0
static void
task_unfreeze(
	task_t task)
{
	task_lock(task);
	assert(task->may_assign == FALSE);
	task->may_assign = TRUE;
	if (task->assign_active == TRUE) {
		task->assign_active = FALSE;
		thread_wakeup((event_t)&task->assign_active);
	}
	task_unlock(task);
	return;
}
#else
#define thread_unfreeze(thread)	assert(task->processor_set == &default_pset)
#endif

#endif	/* MACH_HOST */

/*
 * Create a task running in the kernel address space.  It may
 * have its own map of size mem_size and may have ipc privileges.
 */
kern_return_t
kernel_task_create(
	__unused task_t		parent_task,
	__unused vm_offset_t		map_base,
	__unused vm_size_t		map_size,
	__unused task_t		*child_task)
{
	return (KERN_INVALID_ARGUMENT);
}

kern_return_t
task_create(
	task_t					parent_task,
	__unused ledger_port_array_t	ledger_ports,
	__unused  mach_msg_type_number_t	num_ledger_ports,
	boolean_t				inherit_memory,
	task_t					*child_task)	/* OUT */
{
	if (parent_task == TASK_NULL)
		return(KERN_INVALID_ARGUMENT);

	return task_create_internal(
	    		parent_task, inherit_memory, child_task);
}

kern_return_t
host_security_create_task_token(
	host_security_t			host_security,
	task_t					parent_task,
	security_token_t			sec_token,
	audit_token_t				audit_token,
	host_priv_t				host_priv,
	__unused ledger_port_array_t	ledger_ports,
	__unused mach_msg_type_number_t	num_ledger_ports,
	boolean_t				inherit_memory,
	task_t					*child_task)	/* OUT */
{
        kern_return_t		result;
        
	if (parent_task == TASK_NULL)
		return(KERN_INVALID_ARGUMENT);

	if (host_security == HOST_NULL)
		return(KERN_INVALID_SECURITY);

	result = task_create_internal(
			parent_task, inherit_memory, child_task);

        if (result != KERN_SUCCESS)
                return(result);

	result = host_security_set_task_token(host_security,
					      *child_task,
					      sec_token,
					      audit_token,
					      host_priv);

	if (result != KERN_SUCCESS)
		return(result);

	return(result);
}

kern_return_t
task_create_internal(
	task_t		parent_task,
	boolean_t	inherit_memory,
	task_t		*child_task)		/* OUT */
{
	task_t		new_task;
	processor_set_t	pset;

	new_task = (task_t) zalloc(task_zone);

	if (new_task == TASK_NULL)
		return(KERN_RESOURCE_SHORTAGE);

	/* one ref for just being alive; one for our caller */
	new_task->ref_count = 2;

	if (inherit_memory)
		new_task->map = vm_map_fork(parent_task->map);
	else
		new_task->map = vm_map_create(pmap_create(0),
					(vm_map_offset_t)(VM_MIN_ADDRESS),
					(vm_map_offset_t)(VM_MAX_ADDRESS), TRUE);

	mutex_init(&new_task->lock, 0);
	queue_init(&new_task->threads);
	new_task->suspend_count = 0;
	new_task->thread_count = 0;
	new_task->active_thread_count = 0;
	new_task->user_stop_count = 0;
	new_task->role = TASK_UNSPECIFIED;
	new_task->active = TRUE;
	new_task->user_data = 0;
	new_task->faults = 0;
	new_task->cow_faults = 0;
	new_task->pageins = 0;
	new_task->messages_sent = 0;
	new_task->messages_received = 0;
	new_task->syscalls_mach = 0;
	new_task->priv_flags = 0;
	new_task->syscalls_unix=0;
	new_task->csw=0;
	new_task->taskFeatures[0] = 0;				/* Init task features */
	new_task->taskFeatures[1] = 0;				/* Init task features */
	new_task->dynamic_working_set = 0;

	task_working_set_create(new_task, TWS_SMALL_HASH_LINE_COUNT, 
				0, TWS_HASH_STYLE_DEFAULT);

#ifdef MACH_BSD
	new_task->bsd_info = 0;
#endif /* MACH_BSD */

#ifdef __ppc__
	if(BootProcInfo.pf.Available & pf64Bit) new_task->taskFeatures[0] |= tf64BitData;	/* If 64-bit machine, show we have 64-bit registers at least */
#endif

	queue_init(&new_task->semaphore_list);
	queue_init(&new_task->lock_set_list);
	new_task->semaphores_owned = 0;
	new_task->lock_sets_owned = 0;

#if	MACH_HOST
	new_task->may_assign = TRUE;
	new_task->assign_active = FALSE;
#endif	/* MACH_HOST */

	ipc_task_init(new_task, parent_task);

	new_task->total_user_time = 0;
	new_task->total_system_time = 0;

	task_prof_init(new_task);

	if (parent_task != TASK_NULL) {
#if	MACH_HOST
		/*
		 * Freeze the parent, so that parent_task->processor_set
		 * cannot change.
		 */
		task_freeze(parent_task);
#endif	/* MACH_HOST */
		pset = parent_task->processor_set;
		if (!pset->active)
			pset = &default_pset;

		new_task->sec_token = parent_task->sec_token;
		new_task->audit_token = parent_task->audit_token;

		shared_region_mapping_ref(parent_task->system_shared_region);
		new_task->system_shared_region = parent_task->system_shared_region;

		new_task->wired_ledger_port = ledger_copy(
			convert_port_to_ledger(parent_task->wired_ledger_port));
		new_task->paged_ledger_port = ledger_copy(
			convert_port_to_ledger(parent_task->paged_ledger_port));
		if(task_has_64BitAddr(parent_task))
			task_set_64BitAddr(new_task);
	}
	else {
		pset = &default_pset;

		new_task->sec_token = KERNEL_SECURITY_TOKEN;
		new_task->audit_token = KERNEL_AUDIT_TOKEN;
		new_task->wired_ledger_port = ledger_copy(root_wired_ledger);
		new_task->paged_ledger_port = ledger_copy(root_paged_ledger);
	}

	if (kernel_task == TASK_NULL) {
		new_task->priority = BASEPRI_KERNEL;
		new_task->max_priority = MAXPRI_KERNEL;
	}
	else {
		new_task->priority = BASEPRI_DEFAULT;
		new_task->max_priority = MAXPRI_USER;
	}

	pset_lock(pset);
	pset_add_task(pset, new_task);
	pset_unlock(pset);
#if	MACH_HOST
	if (parent_task != TASK_NULL)
		task_unfreeze(parent_task);
#endif	/* MACH_HOST */

	if (vm_backing_store_low && parent_task != NULL)
		new_task->priv_flags |= (parent_task->priv_flags&VM_BACKING_STORE_PRIV);

	ipc_task_enable(new_task);

	*child_task = new_task;
	return(KERN_SUCCESS);
}

/*
 *	task_deallocate:
 *
 *	Drop a reference on a task.
 */
void
task_deallocate(
	task_t		task)
{
	processor_set_t		pset;

	if (task == TASK_NULL)
	    return;

	if (task_deallocate_internal(task) > 0)
		return;

	pset = task->processor_set;
	pset_deallocate(pset);

	if(task->dynamic_working_set)
		tws_hash_destroy(task->dynamic_working_set);

	ipc_task_terminate(task);

	vm_map_deallocate(task->map);
	is_release(task->itk_space);

	task_prof_deallocate(task);
	zfree(task_zone, task);
}

/*
 *	task_terminate:
 *
 *	Terminate the specified task.  See comments on thread_terminate
 *	(kern/thread.c) about problems with terminating the "current task."
 */

kern_return_t
task_terminate(
	task_t		task)
{
	if (task == TASK_NULL)
		return (KERN_INVALID_ARGUMENT);

	if (task->bsd_info)
		return (KERN_FAILURE);

	return (task_terminate_internal(task));
}

kern_return_t
task_terminate_internal(
	task_t			task)
{
	processor_set_t		pset;
	thread_t			thread, self;
	task_t				self_task;
	boolean_t			interrupt_save;

	assert(task != kernel_task);

	self = current_thread();
	self_task = self->task;

	/*
	 *	Get the task locked and make sure that we are not racing
	 *	with someone else trying to terminate us.
	 */
	if (task == self_task)
		task_lock(task);
	else
	if (task < self_task) {
		task_lock(task);
		task_lock(self_task);
	}
	else {
		task_lock(self_task);
		task_lock(task);
	}

	if (!task->active || !self->active) {
		/*
		 *	Task or current act is already being terminated.
		 *	Just return an error. If we are dying, this will
		 *	just get us to our AST special handler and that
		 *	will get us to finalize the termination of ourselves.
		 */
		task_unlock(task);
		if (self_task != task)
			task_unlock(self_task);

		return (KERN_FAILURE);
	}

	if (self_task != task)
		task_unlock(self_task);

	/*
	 * Make sure the current thread does not get aborted out of
	 * the waits inside these operations.
	 */
	interrupt_save = thread_interrupt_level(THREAD_UNINT);

	/*
	 *	Indicate that we want all the threads to stop executing
	 *	at user space by holding the task (we would have held
	 *	each thread independently in thread_terminate_internal -
	 *	but this way we may be more likely to already find it
	 *	held there).  Mark the task inactive, and prevent
	 *	further task operations via the task port.
	 */
	task_hold_locked(task);
	task->active = FALSE;
	ipc_task_disable(task);

	/*
	 *	Terminate each thread in the task.
	 */
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
			thread_terminate_internal(thread);
	}

	/*
	 *	Give the machine dependent code a chance
	 *	to perform cleanup before ripping apart
	 *	the task.
	 */
	if (self_task == task)
		machine_thread_terminate_self();

	task_unlock(task);

	/*
	 *	Destroy all synchronizers owned by the task.
	 */
	task_synchronizer_destroy_all(task);

	/*
	 *	Destroy the IPC space, leaving just a reference for it.
	 */
	ipc_space_destroy(task->itk_space);

/* LP64todo - make this clean */
#ifdef __ppc__
	vm_map_remove_commpage64(task->map);
	pmap_unmap_sharedpage(task->map->pmap);		/* Unmap commpage */
#endif

	/*
	 * If the current thread is a member of the task
	 * being terminated, then the last reference to
	 * the task will not be dropped until the thread
	 * is finally reaped.  To avoid incurring the
	 * expense of removing the address space regions
	 * at reap time, we do it explictly here.
	 */
	vm_map_remove(task->map, task->map->min_offset,
								task->map->max_offset, VM_MAP_NO_FLAGS);

	shared_region_mapping_dealloc(task->system_shared_region);

	/*
	 * Flush working set here to avoid I/O in reaper thread
	 */
	if (task->dynamic_working_set)
		tws_hash_ws_flush(task->dynamic_working_set);

	pset = task->processor_set;
	pset_lock(pset);
	pset_remove_task(pset,task);
	pset_unlock(pset);

	/*
	 * We no longer need to guard against being aborted, so restore
	 * the previous interruptible state.
	 */
	thread_interrupt_level(interrupt_save);

#if __ppc__
    perfmon_release_facility(task); // notify the perfmon facility
#endif

	/*
	 * Get rid of the task active reference on itself.
	 */
	task_deallocate(task);

	return (KERN_SUCCESS);
}

/*
 * task_halt:
 *
 * 	Shut the current task down (except for the current thread) in
 *	preparation for dramatic changes to the task (probably exec).
 *	We hold the task, terminate all other threads in the task and
 *	wait for them to terminate, clean up the portspace, and when
 *	all done, let the current thread go.
 */
kern_return_t
task_halt(
	task_t		task)
{
	thread_t	thread, self;

	assert(task != kernel_task);

	self = current_thread();

	if (task != self->task)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);

	if (!task->active || !self->active) {
		/*
		 *	Task or current thread is already being terminated.
		 *	Hurry up and return out of the current kernel context
		 *	so that we run our AST special handler to terminate
		 *	ourselves.
		 */
		task_unlock(task);

		return (KERN_FAILURE);
	}

	if (task->thread_count > 1) {
		/*
		 * Mark all the threads to keep them from starting any more
		 * user-level execution.  The thread_terminate_internal code
		 * would do this on a thread by thread basis anyway, but this
		 * gives us a better chance of not having to wait there.
		 */
		task_hold_locked(task);

		/*
		 *	Terminate all the other threads in the task.
		 */
		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			if (thread != self)
				thread_terminate_internal(thread);
		}

		task_release_locked(task);
	}

	/*
	 *	Give the machine dependent code a chance
	 *	to perform cleanup before ripping apart
	 *	the task.
	 */
	machine_thread_terminate_self();

	task_unlock(task);

	/*
	 *	Destroy all synchronizers owned by the task.
	 */
	task_synchronizer_destroy_all(task);

	/*
	 *	Destroy the contents of the IPC space, leaving just
	 *	a reference for it.
	 */
	ipc_space_clean(task->itk_space);

	/*
	 * Clean out the address space, as we are going to be
	 * getting a new one.
	 */
	vm_map_remove(task->map, task->map->min_offset,
		      task->map->max_offset, VM_MAP_NO_FLAGS);

	return (KERN_SUCCESS);
}

/*
 *	task_hold_locked:
 *
 *	Suspend execution of the specified task.
 *	This is a recursive-style suspension of the task, a count of
 *	suspends is maintained.
 *
 * 	CONDITIONS: the task is locked and active.
 */
void
task_hold_locked(
	register task_t		task)
{
	register thread_t	thread;

	assert(task->active);

	if (task->suspend_count++ > 0)
		return;

	/*
	 *	Iterate through all the threads and hold them.
	 */
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		thread_mtx_lock(thread);
		thread_hold(thread);
		thread_mtx_unlock(thread);
	}
}

/*
 *	task_hold:
 *
 *	Same as the internal routine above, except that is must lock
 *	and verify that the task is active.  This differs from task_suspend
 *	in that it places a kernel hold on the task rather than just a 
 *	user-level hold.  This keeps users from over resuming and setting
 *	it running out from under the kernel.
 *
 * 	CONDITIONS: the caller holds a reference on the task
 */
kern_return_t
task_hold(
	register task_t		task)
{
	if (task == TASK_NULL)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);

	if (!task->active) {
		task_unlock(task);

		return (KERN_FAILURE);
	}

	task_hold_locked(task);
	task_unlock(task);

	return (KERN_SUCCESS);
}

/*
 *	task_wait_locked:
 *
 *	Wait for all threads in task to stop.
 *
 * Conditions:
 *	Called with task locked, active, and held.
 */
void
task_wait_locked(
	register task_t		task)
{
	register thread_t	thread, self;

	assert(task->active);
	assert(task->suspend_count > 0);

	self = current_thread();

	/*
	 *	Iterate through all the threads and wait for them to
	 *	stop.  Do not wait for the current thread if it is within
	 *	the task.
	 */
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		if (thread != self)
			thread_wait(thread);
	}
}

/*
 *	task_release_locked:
 *
 *	Release a kernel hold on a task.
 *
 * 	CONDITIONS: the task is locked and active
 */
void
task_release_locked(
	register task_t		task)
{
	register thread_t	thread;

	assert(task->active);
	assert(task->suspend_count > 0);

	if (--task->suspend_count > 0)
		return;

	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		thread_mtx_lock(thread);
		thread_release(thread);
		thread_mtx_unlock(thread);
	}
}

/*
 *	task_release:
 *
 *	Same as the internal routine above, except that it must lock
 *	and verify that the task is active.
 *
 * 	CONDITIONS: The caller holds a reference to the task
 */
kern_return_t
task_release(
	task_t		task)
{
	if (task == TASK_NULL)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);

	if (!task->active) {
		task_unlock(task);

		return (KERN_FAILURE);
	}

	task_release_locked(task);
	task_unlock(task);

	return (KERN_SUCCESS);
}

kern_return_t
task_threads(
	task_t					task,
	thread_act_array_t		*threads_out,
	mach_msg_type_number_t	*count)
{
	mach_msg_type_number_t	actual;
	thread_t				*threads;
	thread_t				thread;
	vm_size_t				size, size_needed;
	void					*addr;
	unsigned int			i, j;

	if (task == TASK_NULL)
		return (KERN_INVALID_ARGUMENT);

	size = 0; addr = 0;

	for (;;) {
		task_lock(task);
		if (!task->active) {
			task_unlock(task);

			if (size != 0)
				kfree(addr, size);

			return (KERN_FAILURE);
		}

		actual = task->thread_count;

		/* do we have the memory we need? */
		size_needed = actual * sizeof (mach_port_t);
		if (size_needed <= size)
			break;

		/* unlock the task and allocate more memory */
		task_unlock(task);

		if (size != 0)
			kfree(addr, size);

		assert(size_needed > 0);
		size = size_needed;

		addr = kalloc(size);
		if (addr == 0)
			return (KERN_RESOURCE_SHORTAGE);
	}

	/* OK, have memory and the task is locked & active */
	threads = (thread_t *)addr;

	i = j = 0;

	for (thread = (thread_t)queue_first(&task->threads); i < actual;
				++i, thread = (thread_t)queue_next(&thread->task_threads)) {
		thread_reference_internal(thread);
		threads[j++] = thread;
	}

	assert(queue_end(&task->threads, (queue_entry_t)thread));

	actual = j;
	size_needed = actual * sizeof (mach_port_t);

	/* can unlock task now that we've got the thread refs */
	task_unlock(task);

	if (actual == 0) {
		/* no threads, so return null pointer and deallocate memory */

		*threads_out = 0;
		*count = 0;

		if (size != 0)
			kfree(addr, size);
	}
	else {
		/* if we allocated too much, must copy */

		if (size_needed < size) {
			void *newaddr;

			newaddr = kalloc(size_needed);
			if (newaddr == 0) {
				for (i = 0; i < actual; ++i)
					thread_deallocate(threads[i]);
				kfree(addr, size);
				return (KERN_RESOURCE_SHORTAGE);
			}

			bcopy(addr, newaddr, size_needed);
			kfree(addr, size);
			threads = (thread_t *)newaddr;
		}

		*threads_out = threads;
		*count = actual;

		/* do the conversion that Mig should handle */

		for (i = 0; i < actual; ++i)
			((ipc_port_t *) threads)[i] = convert_thread_to_port(threads[i]);
	}

	return (KERN_SUCCESS);
}

/*
 *	task_suspend:
 *
 *	Implement a user-level suspension on a task.
 *
 * Conditions:
 * 	The caller holds a reference to the task
 */
kern_return_t
task_suspend(
	register task_t		task)
{
	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);

	if (!task->active) {
		task_unlock(task);

		return (KERN_FAILURE);
	}

	if (task->user_stop_count++ > 0) {
		/*
		 *	If the stop count was positive, the task is
		 *	already stopped and we can exit.
		 */
		task_unlock(task);

		return (KERN_SUCCESS);
	}

	/*
	 * Put a kernel-level hold on the threads in the task (all
	 * user-level task suspensions added together represent a
	 * single kernel-level hold).  We then wait for the threads
	 * to stop executing user code.
	 */
	task_hold_locked(task);
	task_wait_locked(task);

	task_unlock(task);

	return (KERN_SUCCESS);
}

/*
 *	task_resume:
 *		Release a kernel hold on a task.
 *		
 * Conditions:
 *		The caller holds a reference to the task
 */
kern_return_t 
task_resume(
	register task_t	task)
{
	register boolean_t	release = FALSE;

	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);

	if (!task->active) {
		task_unlock(task);

		return (KERN_FAILURE);
	}

	if (task->user_stop_count > 0) {
		if (--task->user_stop_count == 0)
			release = TRUE;
	}
	else {
		task_unlock(task);

		return (KERN_FAILURE);
	}

	/*
	 *	Release the task if necessary.
	 */
	if (release)
		task_release_locked(task);

	task_unlock(task);

	return (KERN_SUCCESS);
}

kern_return_t
host_security_set_task_token(
        host_security_t  host_security,
        task_t		 task,
        security_token_t sec_token,
	audit_token_t	 audit_token,
	host_priv_t	 host_priv)
{
	ipc_port_t	 host_port;
	kern_return_t	 kr;

	if (task == TASK_NULL)
		return(KERN_INVALID_ARGUMENT);

	if (host_security == HOST_NULL)
		return(KERN_INVALID_SECURITY);

        task_lock(task);
        task->sec_token = sec_token;
	task->audit_token = audit_token;
        task_unlock(task);

	if (host_priv != HOST_PRIV_NULL) {
		kr = host_get_host_priv_port(host_priv, &host_port);
	} else {
		kr = host_get_host_port(host_priv_self(), &host_port);
	}
	assert(kr == KERN_SUCCESS);
	kr = task_set_special_port(task, TASK_HOST_PORT, host_port);
        return(kr);
}

/*
 * Utility routine to set a ledger
 */
kern_return_t
task_set_ledger(
        task_t		task,
        ledger_t	wired,
        ledger_t	paged)
{
	if (task == TASK_NULL)
		return(KERN_INVALID_ARGUMENT);

        task_lock(task);
        if (wired) {
                ipc_port_release_send(task->wired_ledger_port);
                task->wired_ledger_port = ledger_copy(wired);
        }                
        if (paged) {
                ipc_port_release_send(task->paged_ledger_port);
                task->paged_ledger_port = ledger_copy(paged);
        }                
        task_unlock(task);

        return(KERN_SUCCESS);
}

/*
 * This routine was added, pretty much exclusively, for registering the
 * RPC glue vector for in-kernel short circuited tasks.  Rather than
 * removing it completely, I have only disabled that feature (which was
 * the only feature at the time).  It just appears that we are going to
 * want to add some user data to tasks in the future (i.e. bsd info,
 * task names, etc...), so I left it in the formal task interface.
 */
kern_return_t
task_set_info(
	task_t		task,
	task_flavor_t	flavor,
	__unused task_info_t	task_info_in,		/* pointer to IN array */
	__unused mach_msg_type_number_t	task_info_count)
{
	if (task == TASK_NULL)
		return(KERN_INVALID_ARGUMENT);

	switch (flavor) {
	    default:
		return (KERN_INVALID_ARGUMENT);
	}
	return (KERN_SUCCESS);
}

kern_return_t
task_info(
	task_t					task,
	task_flavor_t			flavor,
	task_info_t				task_info_out,
	mach_msg_type_number_t	*task_info_count)
{
	if (task == TASK_NULL)
		return (KERN_INVALID_ARGUMENT);

	switch (flavor) {

	case TASK_BASIC_INFO_32:
	{
		task_basic_info_32_t	basic_info;
		vm_map_t			map;

		if (*task_info_count < TASK_BASIC_INFO_32_COUNT)
		    return (KERN_INVALID_ARGUMENT);

		basic_info = (task_basic_info_32_t)task_info_out;

		map = (task == kernel_task)? kernel_map: task->map;
		basic_info->virtual_size  = CAST_DOWN(vm_offset_t,map->size);
		basic_info->resident_size = pmap_resident_count(map->pmap)
						   * PAGE_SIZE;

		task_lock(task);
		basic_info->policy = ((task != kernel_task)?
										  POLICY_TIMESHARE: POLICY_RR);
		basic_info->suspend_count = task->user_stop_count;

		absolutetime_to_microtime(
						task->total_user_time,
								&basic_info->user_time.seconds,
								&basic_info->user_time.microseconds);
		absolutetime_to_microtime(
						task->total_system_time,
								&basic_info->system_time.seconds,
								&basic_info->system_time.microseconds);
		task_unlock(task);

		*task_info_count = TASK_BASIC_INFO_32_COUNT;
		break;
	}

	case TASK_BASIC_INFO_64:
	{
		task_basic_info_64_t	basic_info;
		vm_map_t			map;

		if (*task_info_count < TASK_BASIC_INFO_64_COUNT)
		    return (KERN_INVALID_ARGUMENT);

		basic_info = (task_basic_info_64_t)task_info_out;

		map = (task == kernel_task)? kernel_map: task->map;
		basic_info->virtual_size  = map->size;
		basic_info->resident_size = (mach_vm_size_t)(pmap_resident_count(map->pmap)
						   * PAGE_SIZE);

		task_lock(task);
		basic_info->policy = ((task != kernel_task)?
										  POLICY_TIMESHARE: POLICY_RR);
		basic_info->suspend_count = task->user_stop_count;

		absolutetime_to_microtime(
						task->total_user_time,
								&basic_info->user_time.seconds,
								&basic_info->user_time.microseconds);
		absolutetime_to_microtime(
						task->total_system_time,
								&basic_info->system_time.seconds,
								&basic_info->system_time.microseconds);
		task_unlock(task);

		*task_info_count = TASK_BASIC_INFO_64_COUNT;
		break;
	}

	case TASK_THREAD_TIMES_INFO:
	{
		register task_thread_times_info_t	times_info;
		register thread_t					thread;

		if (*task_info_count < TASK_THREAD_TIMES_INFO_COUNT)
		    return (KERN_INVALID_ARGUMENT);

		times_info = (task_thread_times_info_t) task_info_out;
		times_info->user_time.seconds = 0;
		times_info->user_time.microseconds = 0;
		times_info->system_time.seconds = 0;
		times_info->system_time.microseconds = 0;

		task_lock(task);

		queue_iterate(&task->threads, thread, thread_t, task_threads) {
		    time_value_t	user_time, system_time;

		    thread_read_times(thread, &user_time, &system_time);

		    time_value_add(&times_info->user_time, &user_time);
		    time_value_add(&times_info->system_time, &system_time);
		}

		task_unlock(task);

		*task_info_count = TASK_THREAD_TIMES_INFO_COUNT;
		break;
	}

	case TASK_ABSOLUTETIME_INFO:
	{
		task_absolutetime_info_t	info;
		register thread_t			thread;

		if (*task_info_count < TASK_ABSOLUTETIME_INFO_COUNT)
			return (KERN_INVALID_ARGUMENT);

		info = (task_absolutetime_info_t)task_info_out;
		info->threads_user = info->threads_system = 0;

		task_lock(task);

		info->total_user = task->total_user_time;
		info->total_system = task->total_system_time;

		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			uint64_t	tval;

			tval = timer_grab(&thread->user_timer);
			info->threads_user += tval;
			info->total_user += tval;

			tval = timer_grab(&thread->system_timer);
			info->threads_system += tval;
			info->total_system += tval;
		}

		task_unlock(task);

		*task_info_count = TASK_ABSOLUTETIME_INFO_COUNT;
		break;
	}

	/* OBSOLETE */
	case TASK_SCHED_FIFO_INFO:
	{

		if (*task_info_count < POLICY_FIFO_BASE_COUNT)
			return (KERN_INVALID_ARGUMENT);

		return (KERN_INVALID_POLICY);
	}

	/* OBSOLETE */
	case TASK_SCHED_RR_INFO:
	{
		register policy_rr_base_t	rr_base;

		if (*task_info_count < POLICY_RR_BASE_COUNT)
			return (KERN_INVALID_ARGUMENT);

		rr_base = (policy_rr_base_t) task_info_out;

		task_lock(task);
		if (task != kernel_task) {
			task_unlock(task);
			return (KERN_INVALID_POLICY);
		}

		rr_base->base_priority = task->priority;
		task_unlock(task);

		rr_base->quantum = std_quantum_us / 1000;

		*task_info_count = POLICY_RR_BASE_COUNT;
		break;
	}

	/* OBSOLETE */
	case TASK_SCHED_TIMESHARE_INFO:
	{
		register policy_timeshare_base_t	ts_base;

		if (*task_info_count < POLICY_TIMESHARE_BASE_COUNT)
			return (KERN_INVALID_ARGUMENT);

		ts_base = (policy_timeshare_base_t) task_info_out;

		task_lock(task);
		if (task == kernel_task) {
			task_unlock(task);
			return (KERN_INVALID_POLICY);
		}

		ts_base->base_priority = task->priority;
		task_unlock(task);

		*task_info_count = POLICY_TIMESHARE_BASE_COUNT;
		break;
	}

	case TASK_SECURITY_TOKEN:
	{
		register security_token_t	*sec_token_p;

		if (*task_info_count < TASK_SECURITY_TOKEN_COUNT)
		    return (KERN_INVALID_ARGUMENT);

		sec_token_p = (security_token_t *) task_info_out;

		task_lock(task);
		*sec_token_p = task->sec_token;
		task_unlock(task);

		*task_info_count = TASK_SECURITY_TOKEN_COUNT;
		break;
	}
            
	case TASK_AUDIT_TOKEN:
	{
		register audit_token_t	*audit_token_p;

		if (*task_info_count < TASK_AUDIT_TOKEN_COUNT)
		    return (KERN_INVALID_ARGUMENT);

		audit_token_p = (audit_token_t *) task_info_out;

		task_lock(task);
		*audit_token_p = task->audit_token;
		task_unlock(task);

		*task_info_count = TASK_AUDIT_TOKEN_COUNT;
		break;
	}
            
	case TASK_SCHED_INFO:
		return (KERN_INVALID_ARGUMENT);

	case TASK_EVENTS_INFO:
	{
		register task_events_info_t	events_info;

		if (*task_info_count < TASK_EVENTS_INFO_COUNT)
		    return (KERN_INVALID_ARGUMENT);

		events_info = (task_events_info_t) task_info_out;

		task_lock(task);
		events_info->faults = task->faults;
		events_info->pageins = task->pageins;
		events_info->cow_faults = task->cow_faults;
		events_info->messages_sent = task->messages_sent;
		events_info->messages_received = task->messages_received;
		events_info->syscalls_mach = task->syscalls_mach;
		events_info->syscalls_unix = task->syscalls_unix;
		events_info->csw = task->csw;
		task_unlock(task);

		*task_info_count = TASK_EVENTS_INFO_COUNT;
		break;
	}

	default:
		return (KERN_INVALID_ARGUMENT);
	}

	return (KERN_SUCCESS);
}

/*
 *	task_assign:
 *
 *	Change the assigned processor set for the task
 */
kern_return_t
task_assign(
	__unused task_t		task,
	__unused processor_set_t	new_pset,
	__unused boolean_t	assign_threads)
{
	return(KERN_FAILURE);
}

/*
 *	task_assign_default:
 *
 *	Version of task_assign to assign to default processor set.
 */
kern_return_t
task_assign_default(
	task_t		task,
	boolean_t	assign_threads)
{
    return (task_assign(task, &default_pset, assign_threads));
}

/*
 *	task_get_assignment
 *
 *	Return name of processor set that task is assigned to.
 */
kern_return_t
task_get_assignment(
	task_t		task,
	processor_set_t	*pset)
{
	if (!task->active)
		return(KERN_FAILURE);

	*pset = task->processor_set;
	pset_reference(*pset);
	return(KERN_SUCCESS);
}


/*
 * 	task_policy
 *
 *	Set scheduling policy and parameters, both base and limit, for
 *	the given task. Policy must be a policy which is enabled for the
 *	processor set. Change contained threads if requested. 
 */
kern_return_t
task_policy(
	__unused task_t			task,
	__unused policy_t			policy_id,
	__unused policy_base_t		base,
	__unused mach_msg_type_number_t	count,
	__unused boolean_t			set_limit,
	__unused boolean_t			change)
{
	return(KERN_FAILURE);
}

/*
 *	task_set_policy
 *
 *	Set scheduling policy and parameters, both base and limit, for 
 *	the given task. Policy can be any policy implemented by the
 *	processor set, whether enabled or not. Change contained threads
 *	if requested.
 */
kern_return_t
task_set_policy(
	__unused task_t			task,
	__unused processor_set_t		pset,
	__unused policy_t			policy_id,
	__unused policy_base_t		base,
	__unused mach_msg_type_number_t	base_count,
	__unused policy_limit_t		limit,
	__unused mach_msg_type_number_t	limit_count,
	__unused boolean_t			change)
{
	return(KERN_FAILURE);
}

#if	FAST_TAS
kern_return_t
task_set_ras_pc(
 	task_t		task,
 	vm_offset_t	pc,
 	vm_offset_t	endpc)
{
	extern int fast_tas_debug;
 
	if (fast_tas_debug) {
		printf("task 0x%x: setting fast_tas to [0x%x, 0x%x]\n",
		       task, pc, endpc);
	}
	task_lock(task);
	task->fast_tas_base = pc;
	task->fast_tas_end =  endpc;
	task_unlock(task);
	return KERN_SUCCESS;
} 
#else	/* FAST_TAS */
kern_return_t
task_set_ras_pc(
 	__unused task_t	task,
 	__unused vm_offset_t	pc,
 	__unused vm_offset_t	endpc)
{
	return KERN_FAILURE;
}
#endif	/* FAST_TAS */

void
task_synchronizer_destroy_all(task_t task)
{
	semaphore_t	semaphore;
	lock_set_t	lock_set;

	/*
	 *  Destroy owned semaphores
	 */

	while (!queue_empty(&task->semaphore_list)) {
		semaphore = (semaphore_t) queue_first(&task->semaphore_list);
		(void) semaphore_destroy(task, semaphore);
	}

	/*
	 *  Destroy owned lock sets
	 */

	while (!queue_empty(&task->lock_set_list)) {
		lock_set = (lock_set_t) queue_first(&task->lock_set_list);
		(void) lock_set_destroy(task, lock_set);
	}
}

/*
 * We need to export some functions to other components that
 * are currently implemented in macros within the osfmk
 * component.  Just export them as functions of the same name.
 */
boolean_t is_kerneltask(task_t t)
{
	if (t == kernel_task)
		return (TRUE);

	return (FALSE);
}

#undef current_task
task_t current_task(void);
task_t current_task(void)
{
	return (current_task_fast());
}

#undef task_reference
void task_reference(task_t task);
void
task_reference(
	task_t		task)
{
	if (task != TASK_NULL)
		task_reference_internal(task);
}
