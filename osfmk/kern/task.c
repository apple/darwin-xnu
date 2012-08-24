/*
 * Copyright (c) 2000-2010 Apple Inc. All rights reserved.
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
/*
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 * Copyright (c) 2005 SPARTA, Inc.
 */

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
#include <kern/host.h>
#include <kern/clock.h>
#include <kern/timer.h>
#include <kern/assert.h>
#include <kern/sync_lock.h>
#include <kern/affinity.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>		/* for kernel_map, ipc_kernel_map */
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>

/*
 * Exported interfaces
 */

#include <mach/task_server.h>
#include <mach/mach_host_server.h>
#include <mach/host_security_server.h>
#include <mach/mach_port_server.h>
#include <mach/security_server.h>

#include <vm/vm_shared_region.h>

#if CONFIG_MACF_MACH
#include <security/mac_mach_internal.h>
#endif

#if CONFIG_COUNTERS
#include <pmc/pmc.h>
#endif /* CONFIG_COUNTERS */

task_t			kernel_task;
zone_t			task_zone;
lck_attr_t      task_lck_attr;
lck_grp_t       task_lck_grp;
lck_grp_attr_t  task_lck_grp_attr;
#if CONFIG_EMBEDDED
lck_mtx_t	task_watch_mtx;
#endif /* CONFIG_EMBEDDED */

zinfo_usage_store_t tasks_tkm_private;
zinfo_usage_store_t tasks_tkm_shared;

static ledger_template_t task_ledger_template = NULL;
struct _task_ledger_indices task_ledgers = {-1, -1, -1, -1, -1};
void init_task_ledgers(void);


int task_max = CONFIG_TASK_MAX; /* Max number of tasks */

/* externs for BSD kernel */
extern void proc_getexecutableuuid(void *, unsigned char *, unsigned long);

/* Forwards */

void		task_hold_locked(
			task_t		task);
void		task_wait_locked(
			task_t		task,
			boolean_t	until_not_runnable);
void		task_release_locked(
			task_t		task);
void		task_free(
			task_t		task );
void		task_synchronizer_destroy_all(
			task_t		task);

int check_for_tasksuspend(
			task_t task);

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
task_set_64bit(
		task_t task,
		boolean_t is64bit)
{
#if defined(__i386__) || defined(__x86_64__)
	thread_t thread;
#endif /* __i386__ */
	int	vm_flags = 0;

	if (is64bit) {
		if (task_has_64BitAddr(task))
			return;

		task_set_64BitAddr(task);
	} else {
		if ( !task_has_64BitAddr(task))
			return;

		/*
		 * Deallocate all memory previously allocated
		 * above the 32-bit address space, since it won't
		 * be accessible anymore.
		 */
		/* remove regular VM map entries & pmap mappings */
		(void) vm_map_remove(task->map,
				     (vm_map_offset_t) VM_MAX_ADDRESS,
				     MACH_VM_MAX_ADDRESS,
				     0);
		/* remove the higher VM mappings */
		(void) vm_map_remove(task->map,
				     MACH_VM_MAX_ADDRESS,
				     0xFFFFFFFFFFFFF000ULL,
				     vm_flags);
		task_clear_64BitAddr(task);
	}
	/* FIXME: On x86, the thread save state flavor can diverge from the
	 * task's 64-bit feature flag due to the 32-bit/64-bit register save
	 * state dichotomy. Since we can be pre-empted in this interval,
	 * certain routines may observe the thread as being in an inconsistent
	 * state with respect to its task's 64-bitness.
	 */
#if defined(__i386__) || defined(__x86_64__)
	task_lock(task);
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		thread_mtx_lock(thread);
		machine_thread_switch_addrmode(thread);
		thread_mtx_unlock(thread);
	}
	task_unlock(task);
#endif /* __i386__ */
}


void
task_set_dyld_info(task_t task, mach_vm_address_t addr, mach_vm_size_t size)
{
	task_lock(task);
	task->all_image_info_addr = addr;
	task->all_image_info_size = size;
	task_unlock(task);
}

void
task_init(void)
{

	lck_grp_attr_setdefault(&task_lck_grp_attr);
	lck_grp_init(&task_lck_grp, "task", &task_lck_grp_attr);
	lck_attr_setdefault(&task_lck_attr);
	lck_mtx_init(&tasks_threads_lock, &task_lck_grp, &task_lck_attr);
#if CONFIG_EMBEDDED
	lck_mtx_init(&task_watch_mtx, &task_lck_grp, &task_lck_attr);
#endif /* CONFIG_EMBEDDED */

	task_zone = zinit(
			sizeof(struct task),
			task_max * sizeof(struct task),
			TASK_CHUNK * sizeof(struct task),
			"tasks");

	zone_change(task_zone, Z_NOENCRYPT, TRUE);

	init_task_ledgers();

	/*
	 * Create the kernel task as the first task.
	 */
#ifdef __LP64__
	if (task_create_internal(TASK_NULL, FALSE, TRUE, &kernel_task) != KERN_SUCCESS)
#else
	if (task_create_internal(TASK_NULL, FALSE, FALSE, &kernel_task) != KERN_SUCCESS)
#endif
		panic("task_init\n");

	vm_map_deallocate(kernel_task->map);
	kernel_task->map = kernel_map;

}

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
	task_t				parent_task,
	__unused ledger_port_array_t	ledger_ports,
	__unused mach_msg_type_number_t	num_ledger_ports,
	__unused boolean_t		inherit_memory,
	__unused task_t			*child_task)	/* OUT */
{
	if (parent_task == TASK_NULL)
		return(KERN_INVALID_ARGUMENT);

	/*
	 * No longer supported: too many calls assume that a task has a valid
	 * process attached.
	 */
	return(KERN_FAILURE);
}

kern_return_t
host_security_create_task_token(
	host_security_t			host_security,
	task_t				parent_task,
	__unused security_token_t	sec_token,
	__unused audit_token_t		audit_token,
	__unused host_priv_t		host_priv,
	__unused ledger_port_array_t	ledger_ports,
	__unused mach_msg_type_number_t	num_ledger_ports,
	__unused boolean_t		inherit_memory,
	__unused task_t			*child_task)	/* OUT */
{
	if (parent_task == TASK_NULL)
		return(KERN_INVALID_ARGUMENT);

	if (host_security == HOST_NULL)
		return(KERN_INVALID_SECURITY);

	/*
	 * No longer supported.
	 */
	return(KERN_FAILURE);
}

void
init_task_ledgers(void)
{
	ledger_template_t t;
	
	assert(task_ledger_template == NULL);
	assert(kernel_task == TASK_NULL);

	if ((t = ledger_template_create("Per-task ledger")) == NULL)
		panic("couldn't create task ledger template");

	task_ledgers.cpu_time = ledger_entry_add(t, "cpu_time", "sched", "ns");
	task_ledgers.tkm_private = ledger_entry_add(t, "tkm_private",
	    "physmem", "bytes");
	task_ledgers.tkm_shared = ledger_entry_add(t, "tkm_shared", "physmem",
	    "bytes");
	task_ledgers.phys_mem = ledger_entry_add(t, "phys_mem", "physmem",
	    "bytes");
	task_ledgers.wired_mem = ledger_entry_add(t, "wired_mem", "physmem",
	    "bytes");

	if ((task_ledgers.cpu_time < 0) || (task_ledgers.tkm_private < 0) ||
	    (task_ledgers.tkm_shared < 0) || (task_ledgers.phys_mem < 0) ||
	    (task_ledgers.wired_mem < 0)) {
		panic("couldn't create entries for task ledger template");
	}

	task_ledger_template = t;
}

kern_return_t
task_create_internal(
	task_t		parent_task,
	boolean_t	inherit_memory,
	boolean_t	is_64bit,
	task_t		*child_task)		/* OUT */
{
	task_t			new_task;
	vm_shared_region_t	shared_region;
	ledger_t		ledger = NULL;

	new_task = (task_t) zalloc(task_zone);

	if (new_task == TASK_NULL)
		return(KERN_RESOURCE_SHORTAGE);

	/* one ref for just being alive; one for our caller */
	new_task->ref_count = 2;

	/* allocate with active entries */
	assert(task_ledger_template != NULL);
	if ((ledger = ledger_instantiate(task_ledger_template,
			LEDGER_CREATE_ACTIVE_ENTRIES)) == NULL) {
		zfree(task_zone, new_task);
		return(KERN_RESOURCE_SHORTAGE);
	}
	new_task->ledger = ledger;

	/* if inherit_memory is true, parent_task MUST not be NULL */
	if (inherit_memory)
		new_task->map = vm_map_fork(ledger, parent_task->map);
	else
		new_task->map = vm_map_create(pmap_create(ledger, 0, is_64bit),
				(vm_map_offset_t)(VM_MIN_ADDRESS),
				(vm_map_offset_t)(VM_MAX_ADDRESS), TRUE);

	/* Inherit memlock limit from parent */
	if (parent_task)
		vm_map_set_user_wire_limit(new_task->map, (vm_size_t)parent_task->map->user_wire_limit);

	lck_mtx_init(&new_task->lock, &task_lck_grp, &task_lck_attr);
	queue_init(&new_task->threads);
	new_task->suspend_count = 0;
	new_task->thread_count = 0;
	new_task->active_thread_count = 0;
	new_task->user_stop_count = 0;
	new_task->role = TASK_UNSPECIFIED;
	new_task->active = TRUE;
	new_task->halting = FALSE;
	new_task->user_data = NULL;
	new_task->faults = 0;
	new_task->cow_faults = 0;
	new_task->pageins = 0;
	new_task->messages_sent = 0;
	new_task->messages_received = 0;
	new_task->syscalls_mach = 0;
	new_task->priv_flags = 0;
	new_task->syscalls_unix=0;
	new_task->c_switch = new_task->p_switch = new_task->ps_switch = 0;
	new_task->taskFeatures[0] = 0;				/* Init task features */
	new_task->taskFeatures[1] = 0;				/* Init task features */

	zinfo_task_init(new_task);

#ifdef MACH_BSD
	new_task->bsd_info = NULL;
#endif /* MACH_BSD */

#if defined(__i386__) || defined(__x86_64__)
	new_task->i386_ldt = 0;
	new_task->task_debug = NULL;
#endif


	queue_init(&new_task->semaphore_list);
	queue_init(&new_task->lock_set_list);
	new_task->semaphores_owned = 0;
	new_task->lock_sets_owned = 0;

#if CONFIG_MACF_MACH
	new_task->label = labelh_new(1);
	mac_task_label_init (&new_task->maclabel);
#endif

	ipc_task_init(new_task, parent_task);

	new_task->total_user_time = 0;
	new_task->total_system_time = 0;

	new_task->vtimers = 0;

	new_task->shared_region = NULL;

	new_task->affinity_space = NULL;

#if CONFIG_COUNTERS
	new_task->t_chud = 0U;
#endif

	new_task->pidsuspended = FALSE;
	new_task->frozen = FALSE;
	new_task->rusage_cpu_flags = 0;
	new_task->rusage_cpu_percentage = 0;
	new_task->rusage_cpu_interval = 0;
	new_task->rusage_cpu_deadline = 0;
	new_task->rusage_cpu_callt = NULL;
	new_task->proc_terminate = 0;
#if CONFIG_EMBEDDED
	queue_init(&new_task->task_watchers);
	new_task->appstate = TASK_APPSTATE_ACTIVE;
	new_task->num_taskwatchers  = 0;
	new_task->watchapplying  = 0;
#endif /* CONFIG_EMBEDDED */

	if (parent_task != TASK_NULL) {
		new_task->sec_token = parent_task->sec_token;
		new_task->audit_token = parent_task->audit_token;

		/* inherit the parent's shared region */
		shared_region = vm_shared_region_get(parent_task);
		vm_shared_region_set(new_task, shared_region);

		if(task_has_64BitAddr(parent_task))
			task_set_64BitAddr(new_task);
		new_task->all_image_info_addr = parent_task->all_image_info_addr;
		new_task->all_image_info_size = parent_task->all_image_info_size;

#if defined(__i386__) || defined(__x86_64__)
		if (inherit_memory && parent_task->i386_ldt)
			new_task->i386_ldt = user_ldt_copy(parent_task->i386_ldt);
#endif
		if (inherit_memory && parent_task->affinity_space)
			task_affinity_create(parent_task, new_task);

		new_task->pset_hint = parent_task->pset_hint = task_choose_pset(parent_task);
		new_task->policystate = parent_task->policystate;
		/* inherit the self action state */
		new_task->appliedstate = parent_task->appliedstate;
		new_task->ext_policystate = parent_task->ext_policystate;
#if NOTYET
		/* till the child lifecycle is cleared do not inherit external action */
		new_task->ext_appliedstate = parent_task->ext_appliedstate;
#else
		new_task->ext_appliedstate = default_task_null_policy;
#endif
	}
	else {
		new_task->sec_token = KERNEL_SECURITY_TOKEN;
		new_task->audit_token = KERNEL_AUDIT_TOKEN;
#ifdef __LP64__
		if(is_64bit)
			task_set_64BitAddr(new_task);
#endif
		new_task->all_image_info_addr = (mach_vm_address_t)0;
		new_task->all_image_info_size = (mach_vm_size_t)0;

		new_task->pset_hint = PROCESSOR_SET_NULL;
		new_task->policystate = default_task_proc_policy;
		new_task->ext_policystate = default_task_proc_policy;
		new_task->appliedstate = default_task_null_policy;
		new_task->ext_appliedstate = default_task_null_policy;
	}

	if (kernel_task == TASK_NULL) {
		new_task->priority = BASEPRI_KERNEL;
		new_task->max_priority = MAXPRI_KERNEL;
	}
	else {
		new_task->priority = BASEPRI_DEFAULT;
		new_task->max_priority = MAXPRI_USER;
	}

	bzero(&new_task->extmod_statistics, sizeof(new_task->extmod_statistics));
	
	lck_mtx_lock(&tasks_threads_lock);
	queue_enter(&tasks, new_task, task_t, tasks);
	tasks_count++;
	lck_mtx_unlock(&tasks_threads_lock);

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
	ledger_amount_t credit, debit;

	if (task == TASK_NULL)
	    return;

	if (task_deallocate_internal(task) > 0)
		return;

	lck_mtx_lock(&tasks_threads_lock);
	queue_remove(&terminated_tasks, task, task_t, tasks);
	lck_mtx_unlock(&tasks_threads_lock);

	/*
	 *	Give the machine dependent code a chance
	 *	to perform cleanup before ripping apart
	 *	the task.
	 */
	machine_task_terminate(task);

	ipc_task_terminate(task);

	if (task->affinity_space)
		task_affinity_deallocate(task);

	vm_map_deallocate(task->map);
	is_release(task->itk_space);

	lck_mtx_destroy(&task->lock, &task_lck_grp);

#if CONFIG_MACF_MACH
	labelh_release(task->label);
#endif

	if (!ledger_get_entries(task->ledger, task_ledgers.tkm_private, &credit,
	    &debit)) {
		OSAddAtomic64(credit, (int64_t *)&tasks_tkm_private.alloc);
		OSAddAtomic64(debit, (int64_t *)&tasks_tkm_private.free);
	}
	if (!ledger_get_entries(task->ledger, task_ledgers.tkm_shared, &credit,
	    &debit)) {
		OSAddAtomic64(credit, (int64_t *)&tasks_tkm_shared.alloc);
		OSAddAtomic64(debit, (int64_t *)&tasks_tkm_shared.free);
	}
	ledger_dereference(task->ledger);
	zinfo_task_free(task);
	zfree(task_zone, task);
}

/*
 *	task_name_deallocate:
 *
 *	Drop a reference on a task name.
 */
void
task_name_deallocate(
	task_name_t		task_name)
{
	return(task_deallocate((task_t)task_name));
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

	if (!task->active) {
		/*
		 *	Task is already being terminated.
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

	task_unlock(task);

#if CONFIG_EMBEDDED
	/*
	 * remove all task watchers 
	 */
	task_removewatchers(task);
#endif /* CONFIG_EMBEDDED */

	/*
	 *	Destroy all synchronizers owned by the task.
	 */
	task_synchronizer_destroy_all(task);

	/*
	 *	Destroy the IPC space, leaving just a reference for it.
	 */
	ipc_space_terminate(task->itk_space);

	if (vm_map_has_4GB_pagezero(task->map))
		vm_map_clear_4GB_pagezero(task->map);

	/*
	 * If the current thread is a member of the task
	 * being terminated, then the last reference to
	 * the task will not be dropped until the thread
	 * is finally reaped.  To avoid incurring the
	 * expense of removing the address space regions
	 * at reap time, we do it explictly here.
	 */
	vm_map_remove(task->map,
		      task->map->min_offset,
		      task->map->max_offset,
		      VM_MAP_NO_FLAGS);

	/* release our shared region */
	vm_shared_region_set(task, NULL);

	lck_mtx_lock(&tasks_threads_lock);
	queue_remove(&tasks, task, task_t, tasks);
	queue_enter(&terminated_tasks, task, task_t, tasks);
	tasks_count--;
	lck_mtx_unlock(&tasks_threads_lock);

	/*
	 * We no longer need to guard against being aborted, so restore
	 * the previous interruptible state.
	 */
	thread_interrupt_level(interrupt_save);

	/*
	 * Get rid of the task active reference on itself.
	 */
	task_deallocate(task);

	return (KERN_SUCCESS);
}

/*
 * task_start_halt:
 *
 * 	Shut the current task down (except for the current thread) in
 *	preparation for dramatic changes to the task (probably exec).
 *	We hold the task and mark all other threads in the task for
 *	termination.
 */
kern_return_t
task_start_halt(
	task_t		task)
{
	thread_t	thread, self;

	assert(task != kernel_task);

	self = current_thread();

	if (task != self->task)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);

	if (task->halting || !task->active || !self->active) {
		/*
		 *	Task or current thread is already being terminated.
		 *	Hurry up and return out of the current kernel context
		 *	so that we run our AST special handler to terminate
		 *	ourselves.
		 */
		task_unlock(task);

		return (KERN_FAILURE);
	}

	task->halting = TRUE;

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
	task_unlock(task);
	return KERN_SUCCESS;
}


/*
 * task_complete_halt:
 *
 *	Complete task halt by waiting for threads to terminate, then clean
 *	up task resources (VM, port namespace, etc...) and then let the
 *	current thread go in the (practically empty) task context.
 */
void
task_complete_halt(task_t task)
{
	task_lock(task);
	assert(task->halting);
	assert(task == current_task());

	/*
	 *	Wait for the other threads to get shut down.
	 *      When the last other thread is reaped, we'll be
	 *	woken up.
	 */
	if (task->thread_count > 1) {
		assert_wait((event_t)&task->halting, THREAD_UNINT);
		task_unlock(task);
		thread_block(THREAD_CONTINUE_NULL);
	} else {
		task_unlock(task);
	}

	/*
	 *	Give the machine dependent code a chance
	 *	to perform cleanup of task-level resources
	 *	associated with the current thread before
	 *	ripping apart the task.
	 */
	machine_task_terminate(task);

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

	task->halting = FALSE;
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

kern_return_t
task_wait(
		task_t		task,
		boolean_t	until_not_runnable)
{
	if (task == TASK_NULL)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);

	if (!task->active) {
		task_unlock(task);

		return (KERN_FAILURE);
	}

	task_wait_locked(task, until_not_runnable);
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
	register task_t		task,
	boolean_t		until_not_runnable)
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
			thread_wait(thread, until_not_runnable);
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
	thread_t				*thread_list;
	thread_t				thread;
	vm_size_t				size, size_needed;
	void					*addr;
	unsigned int			i, j;

	if (task == TASK_NULL)
		return (KERN_INVALID_ARGUMENT);

	size = 0; addr = NULL;

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
	thread_list = (thread_t *)addr;

	i = j = 0;

	for (thread = (thread_t)queue_first(&task->threads); i < actual;
				++i, thread = (thread_t)queue_next(&thread->task_threads)) {
		thread_reference_internal(thread);
		thread_list[j++] = thread;
	}

	assert(queue_end(&task->threads, (queue_entry_t)thread));

	actual = j;
	size_needed = actual * sizeof (mach_port_t);

	/* can unlock task now that we've got the thread refs */
	task_unlock(task);

	if (actual == 0) {
		/* no threads, so return null pointer and deallocate memory */

		*threads_out = NULL;
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
					thread_deallocate(thread_list[i]);
				kfree(addr, size);
				return (KERN_RESOURCE_SHORTAGE);
			}

			bcopy(addr, newaddr, size_needed);
			kfree(addr, size);
			thread_list = (thread_t *)newaddr;
		}

		*threads_out = thread_list;
		*count = actual;

		/* do the conversion that Mig should handle */

		for (i = 0; i < actual; ++i)
			((ipc_port_t *) thread_list)[i] = convert_thread_to_port(thread_list[i]);
	}

	return (KERN_SUCCESS);
}

static kern_return_t
place_task_hold    (
	register task_t		task)
{    
	if (!task->active) {
		return (KERN_FAILURE);
	}

	if (task->user_stop_count++ > 0) {
		/*
		 *	If the stop count was positive, the task is
		 *	already stopped and we can exit.
		 */
		return (KERN_SUCCESS);
	}

	/*
	 * Put a kernel-level hold on the threads in the task (all
	 * user-level task suspensions added together represent a
	 * single kernel-level hold).  We then wait for the threads
	 * to stop executing user code.
	 */
	task_hold_locked(task);
	task_wait_locked(task, TRUE);
	
	return (KERN_SUCCESS);
}

static kern_return_t
release_task_hold    (
	register task_t		task,
	boolean_t           pidresume)
{
	register boolean_t release = FALSE;
    
	if (!task->active) {
		return (KERN_FAILURE);
	}
	
	if (pidresume) {
	    if (task->pidsuspended == FALSE) {
            return (KERN_FAILURE);
	    }
	    task->pidsuspended = FALSE;
	}

    if (task->user_stop_count > (task->pidsuspended ? 1 : 0)) {
		if (--task->user_stop_count == 0) {
			release = TRUE;
		}
	}
	else {
		return (KERN_FAILURE);
	}

	/*
	 *	Release the task if necessary.
	 */
	if (release)
		task_release_locked(task);
		
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
	kern_return_t	 kr;
       
	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);

	kr = place_task_hold(task);

	task_unlock(task);

	return (kr);
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
	kern_return_t	 kr;

	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);

	kr = release_task_hold(task, FALSE);

	task_unlock(task);

	return (kr);
}

kern_return_t
task_pidsuspend_locked(task_t task)
{
	kern_return_t kr;

	if (task->pidsuspended) {
		kr = KERN_FAILURE;
		goto out;
	}

	task->pidsuspended = TRUE;

	kr = place_task_hold(task);
	if (kr != KERN_SUCCESS) {
		task->pidsuspended = FALSE;
	}
out:
	return(kr);
}


/*
 *	task_pidsuspend:
 *
 *	Suspends a task by placing a hold on its threads.
 *
 * Conditions:
 * 	The caller holds a reference to the task
 */
kern_return_t
task_pidsuspend(
	register task_t		task)
{
	kern_return_t	 kr;
    
	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);

	kr = task_pidsuspend_locked(task);

	task_unlock(task);

	return (kr);
}

/* If enabled, we bring all the frozen pages back in prior to resumption; otherwise, they're faulted back in on demand */
#define THAW_ON_RESUME 1

/*
 *	task_pidresume:
 *		Resumes a previously suspended task.
 *		
 * Conditions:
 *		The caller holds a reference to the task
 */
kern_return_t 
task_pidresume(
	register task_t	task)
{
	kern_return_t	 kr;
#if (CONFIG_FREEZE && THAW_ON_RESUME)
    boolean_t frozen;
#endif

	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);
	
#if (CONFIG_FREEZE && THAW_ON_RESUME)
    frozen = task->frozen;
    task->frozen = FALSE;
#endif

	kr = release_task_hold(task, TRUE);

	task_unlock(task);

#if (CONFIG_FREEZE && THAW_ON_RESUME)
	if ((kr == KERN_SUCCESS) && (frozen == TRUE)) {
	    kr = vm_map_thaw(task->map);
	}
#endif

	return (kr);
}

#if CONFIG_FREEZE

/*
 *	task_freeze:
 *
 *	Freeze a task.
 *
 * Conditions:
 * 	The caller holds a reference to the task
 */
kern_return_t
task_freeze(
	register task_t    task,
	uint32_t           *purgeable_count,
	uint32_t           *wired_count,
	uint32_t           *clean_count,
	uint32_t           *dirty_count,
	uint32_t           dirty_budget,
	boolean_t          *shared,
	boolean_t          walk_only)
{
	kern_return_t kr;
    
	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);

	if (task->frozen) {
	    task_unlock(task);
	    return (KERN_FAILURE);
	}

    if (walk_only == FALSE) {
	    task->frozen = TRUE;
    }

	task_unlock(task);

	if (walk_only) {
		kr = vm_map_freeze_walk(task->map, purgeable_count, wired_count, clean_count, dirty_count, dirty_budget, shared);		
	} else {
		kr = vm_map_freeze(task->map, purgeable_count, wired_count, clean_count, dirty_count, dirty_budget, shared);
	}

	return (kr);
}

/*
 *	task_thaw:
 *
 *	Thaw a currently frozen task.
 *
 * Conditions:
 * 	The caller holds a reference to the task
 */
kern_return_t
task_thaw(
	register task_t		task)
{
	kern_return_t kr;
    
	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);
	
	if (!task->frozen) {
	    task_unlock(task);
	    return (KERN_FAILURE);
	}

	task->frozen = FALSE;

	task_unlock(task);

	kr = vm_map_thaw(task->map);

	return (kr);
}

#endif /* CONFIG_FREEZE */

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
	kern_return_t error = KERN_SUCCESS;

	if (task == TASK_NULL)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);

	if ((task != current_task()) && (!task->active)) {
		task_unlock(task);
		return (KERN_INVALID_ARGUMENT);
	}

	switch (flavor) {

	case TASK_BASIC_INFO_32:
	case TASK_BASIC2_INFO_32:
	{
		task_basic_info_32_t	basic_info;
		vm_map_t				map;
		clock_sec_t				secs;
		clock_usec_t			usecs;

		if (*task_info_count < TASK_BASIC_INFO_32_COUNT) {
		    error = KERN_INVALID_ARGUMENT;
		    break;
		}

		basic_info = (task_basic_info_32_t)task_info_out;

		map = (task == kernel_task)? kernel_map: task->map;
		basic_info->virtual_size = (typeof(basic_info->virtual_size))map->size;
		if (flavor == TASK_BASIC2_INFO_32) {
			/*
			 * The "BASIC2" flavor gets the maximum resident
			 * size instead of the current resident size...
			 */
			basic_info->resident_size = pmap_resident_max(map->pmap);
		} else {
			basic_info->resident_size = pmap_resident_count(map->pmap);
		}
		basic_info->resident_size *= PAGE_SIZE;

		basic_info->policy = ((task != kernel_task)?
										  POLICY_TIMESHARE: POLICY_RR);
		basic_info->suspend_count = task->user_stop_count;

		absolutetime_to_microtime(task->total_user_time, &secs, &usecs);
		basic_info->user_time.seconds = 
			(typeof(basic_info->user_time.seconds))secs;
		basic_info->user_time.microseconds = usecs;

		absolutetime_to_microtime(task->total_system_time, &secs, &usecs);
		basic_info->system_time.seconds = 
			(typeof(basic_info->system_time.seconds))secs;
		basic_info->system_time.microseconds = usecs;

		*task_info_count = TASK_BASIC_INFO_32_COUNT;
		break;
	}

	case TASK_BASIC_INFO_64:
	{
		task_basic_info_64_t	basic_info;
		vm_map_t				map;
		clock_sec_t				secs;
		clock_usec_t			usecs;

		if (*task_info_count < TASK_BASIC_INFO_64_COUNT) {
		    error = KERN_INVALID_ARGUMENT;
		    break;
		}

		basic_info = (task_basic_info_64_t)task_info_out;

		map = (task == kernel_task)? kernel_map: task->map;
		basic_info->virtual_size  = map->size;
		basic_info->resident_size =
			(mach_vm_size_t)(pmap_resident_count(map->pmap))
			* PAGE_SIZE_64;

		basic_info->policy = ((task != kernel_task)?
										  POLICY_TIMESHARE: POLICY_RR);
		basic_info->suspend_count = task->user_stop_count;

		absolutetime_to_microtime(task->total_user_time, &secs, &usecs);
		basic_info->user_time.seconds = 
			(typeof(basic_info->user_time.seconds))secs;
		basic_info->user_time.microseconds = usecs;

		absolutetime_to_microtime(task->total_system_time, &secs, &usecs);
		basic_info->system_time.seconds =
			(typeof(basic_info->system_time.seconds))secs;
		basic_info->system_time.microseconds = usecs;

		*task_info_count = TASK_BASIC_INFO_64_COUNT;
		break;
	}

	case MACH_TASK_BASIC_INFO:
	{
		mach_task_basic_info_t  basic_info;
		vm_map_t                map;
		clock_sec_t             secs;
		clock_usec_t            usecs;

		if (*task_info_count < MACH_TASK_BASIC_INFO_COUNT) {
		    error = KERN_INVALID_ARGUMENT;
		    break;
		}

		basic_info = (mach_task_basic_info_t)task_info_out;

		map = (task == kernel_task) ? kernel_map : task->map;

		basic_info->virtual_size  = map->size;

		basic_info->resident_size =
		    (mach_vm_size_t)(pmap_resident_count(map->pmap));
		basic_info->resident_size *= PAGE_SIZE_64;

		basic_info->resident_size_max =
		    (mach_vm_size_t)(pmap_resident_max(map->pmap));
		basic_info->resident_size_max *= PAGE_SIZE_64;

		basic_info->policy = ((task != kernel_task) ? 
		                      POLICY_TIMESHARE : POLICY_RR);

		basic_info->suspend_count = task->user_stop_count;

		absolutetime_to_microtime(task->total_user_time, &secs, &usecs);
		basic_info->user_time.seconds = 
		    (typeof(basic_info->user_time.seconds))secs;
		basic_info->user_time.microseconds = usecs;

		absolutetime_to_microtime(task->total_system_time, &secs, &usecs);
		basic_info->system_time.seconds =
		    (typeof(basic_info->system_time.seconds))secs;
		basic_info->system_time.microseconds = usecs;

		*task_info_count = MACH_TASK_BASIC_INFO_COUNT;
		break;
	}

	case TASK_THREAD_TIMES_INFO:
	{
		register task_thread_times_info_t	times_info;
		register thread_t					thread;

		if (*task_info_count < TASK_THREAD_TIMES_INFO_COUNT) {
		    error = KERN_INVALID_ARGUMENT;
		    break;
		}

		times_info = (task_thread_times_info_t) task_info_out;
		times_info->user_time.seconds = 0;
		times_info->user_time.microseconds = 0;
		times_info->system_time.seconds = 0;
		times_info->system_time.microseconds = 0;


		queue_iterate(&task->threads, thread, thread_t, task_threads) {
		    time_value_t	user_time, system_time;

		    thread_read_times(thread, &user_time, &system_time);

		    time_value_add(&times_info->user_time, &user_time);
		    time_value_add(&times_info->system_time, &system_time);
		}


		*task_info_count = TASK_THREAD_TIMES_INFO_COUNT;
		break;
	}

	case TASK_ABSOLUTETIME_INFO:
	{
		task_absolutetime_info_t	info;
		register thread_t			thread;

		if (*task_info_count < TASK_ABSOLUTETIME_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		info = (task_absolutetime_info_t)task_info_out;
		info->threads_user = info->threads_system = 0;


		info->total_user = task->total_user_time;
		info->total_system = task->total_system_time;

		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			uint64_t	tval;
			spl_t 		x;

			x = splsched();
			thread_lock(thread);

			tval = timer_grab(&thread->user_timer);
			info->threads_user += tval;
			info->total_user += tval;

			tval = timer_grab(&thread->system_timer);
			if (thread->precise_user_kernel_time) {
				info->threads_system += tval;
				info->total_system += tval;
			} else {
				/* system_timer may represent either sys or user */
				info->threads_user += tval;
				info->total_user += tval;
			}

			thread_unlock(thread);
			splx(x);
		}


		*task_info_count = TASK_ABSOLUTETIME_INFO_COUNT;
		break;
	}

	case TASK_DYLD_INFO:
	{
		task_dyld_info_t info;

		/*
		 * We added the format field to TASK_DYLD_INFO output.  For
		 * temporary backward compatibility, accept the fact that
		 * clients may ask for the old version - distinquished by the
		 * size of the expected result structure.
		 */
#define TASK_LEGACY_DYLD_INFO_COUNT \
		offsetof(struct task_dyld_info, all_image_info_format)/sizeof(natural_t)

		if (*task_info_count < TASK_LEGACY_DYLD_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		info = (task_dyld_info_t)task_info_out;
		info->all_image_info_addr = task->all_image_info_addr;
		info->all_image_info_size = task->all_image_info_size;

		/* only set format on output for those expecting it */
		if (*task_info_count >= TASK_DYLD_INFO_COUNT) {
			info->all_image_info_format = task_has_64BitAddr(task) ?
				                 TASK_DYLD_ALL_IMAGE_INFO_64 : 
				                 TASK_DYLD_ALL_IMAGE_INFO_32 ;
			*task_info_count = TASK_DYLD_INFO_COUNT;
		} else {
			*task_info_count = TASK_LEGACY_DYLD_INFO_COUNT;
		}
		break;
	}

	case TASK_EXTMOD_INFO:
	{
		task_extmod_info_t info;
		void *p;

		if (*task_info_count < TASK_EXTMOD_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		info = (task_extmod_info_t)task_info_out;

		p = get_bsdtask_info(task);
		if (p) {
			proc_getexecutableuuid(p, info->task_uuid, sizeof(info->task_uuid));
		} else {
			bzero(info->task_uuid, sizeof(info->task_uuid));
		}
		info->extmod_statistics = task->extmod_statistics;
		*task_info_count = TASK_EXTMOD_INFO_COUNT;

		break;
	}

	case TASK_KERNELMEMORY_INFO:
	{
		task_kernelmemory_info_t	tkm_info;
		ledger_amount_t			credit, debit;

		if (*task_info_count < TASK_KERNELMEMORY_INFO_COUNT) {
		   error = KERN_INVALID_ARGUMENT;
		   break;
		}

		tkm_info = (task_kernelmemory_info_t) task_info_out;
		tkm_info->total_palloc = 0;
		tkm_info->total_pfree = 0;
		tkm_info->total_salloc = 0;
		tkm_info->total_sfree = 0;

		if (task == kernel_task) {
			/*
			 * All shared allocs/frees from other tasks count against
			 * the kernel private memory usage.  If we are looking up
			 * info for the kernel task, gather from everywhere.
			 */
			task_unlock(task);

			/* start by accounting for all the terminated tasks against the kernel */
			tkm_info->total_palloc = tasks_tkm_private.alloc + tasks_tkm_shared.alloc;
			tkm_info->total_pfree = tasks_tkm_private.free + tasks_tkm_shared.free;

			/* count all other task/thread shared alloc/free against the kernel */
			lck_mtx_lock(&tasks_threads_lock);

			/* XXX this really shouldn't be using the function parameter 'task' as a local var! */
			queue_iterate(&tasks, task, task_t, tasks) {
				if (task == kernel_task) {
					if (ledger_get_entries(task->ledger,
					    task_ledgers.tkm_private, &credit,
					    &debit) == KERN_SUCCESS) {
						tkm_info->total_palloc += credit;
						tkm_info->total_pfree += debit;
					}
				}
				if (!ledger_get_entries(task->ledger,
				    task_ledgers.tkm_shared, &credit, &debit)) {
					tkm_info->total_palloc += credit;
					tkm_info->total_pfree += debit;
				}
			}
			lck_mtx_unlock(&tasks_threads_lock);
		} else {
			if (!ledger_get_entries(task->ledger,
			    task_ledgers.tkm_private, &credit, &debit)) {
				tkm_info->total_palloc = credit;
				tkm_info->total_pfree = debit;
			}
			if (!ledger_get_entries(task->ledger,
			    task_ledgers.tkm_shared, &credit, &debit)) {
				tkm_info->total_salloc = credit;
				tkm_info->total_sfree = debit;
			}
			task_unlock(task);
		}

		*task_info_count = TASK_KERNELMEMORY_INFO_COUNT;
		return KERN_SUCCESS;
	}

	/* OBSOLETE */
	case TASK_SCHED_FIFO_INFO:
	{

		if (*task_info_count < POLICY_FIFO_BASE_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		error = KERN_INVALID_POLICY;
		break;
	}

	/* OBSOLETE */
	case TASK_SCHED_RR_INFO:
	{
		register policy_rr_base_t	rr_base;
		uint32_t quantum_time;
		uint64_t quantum_ns;

		if (*task_info_count < POLICY_RR_BASE_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		rr_base = (policy_rr_base_t) task_info_out;

		if (task != kernel_task) {
			error = KERN_INVALID_POLICY;
			break;
		}

		rr_base->base_priority = task->priority;

		quantum_time = SCHED(initial_quantum_size)(THREAD_NULL);
		absolutetime_to_nanoseconds(quantum_time, &quantum_ns);
		
		rr_base->quantum = (uint32_t)(quantum_ns / 1000 / 1000);

		*task_info_count = POLICY_RR_BASE_COUNT;
		break;
	}

	/* OBSOLETE */
	case TASK_SCHED_TIMESHARE_INFO:
	{
		register policy_timeshare_base_t	ts_base;

		if (*task_info_count < POLICY_TIMESHARE_BASE_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		ts_base = (policy_timeshare_base_t) task_info_out;

		if (task == kernel_task) {
			error = KERN_INVALID_POLICY;
			break;
		}

		ts_base->base_priority = task->priority;

		*task_info_count = POLICY_TIMESHARE_BASE_COUNT;
		break;
	}

	case TASK_SECURITY_TOKEN:
	{
		register security_token_t	*sec_token_p;

		if (*task_info_count < TASK_SECURITY_TOKEN_COUNT) {
		    error = KERN_INVALID_ARGUMENT;
		    break;
		}

		sec_token_p = (security_token_t *) task_info_out;

		*sec_token_p = task->sec_token;

		*task_info_count = TASK_SECURITY_TOKEN_COUNT;
		break;
	}
            
	case TASK_AUDIT_TOKEN:
	{
		register audit_token_t	*audit_token_p;

		if (*task_info_count < TASK_AUDIT_TOKEN_COUNT) {
		    error = KERN_INVALID_ARGUMENT;
		    break;
		}

		audit_token_p = (audit_token_t *) task_info_out;

		*audit_token_p = task->audit_token;

		*task_info_count = TASK_AUDIT_TOKEN_COUNT;
		break;
	}
            
	case TASK_SCHED_INFO:
		error = KERN_INVALID_ARGUMENT;
		break;

	case TASK_EVENTS_INFO:
	{
		register task_events_info_t	events_info;
		register thread_t			thread;

		if (*task_info_count < TASK_EVENTS_INFO_COUNT) {
		   error = KERN_INVALID_ARGUMENT;
		   break;
		}

		events_info = (task_events_info_t) task_info_out;


		events_info->faults = task->faults;
		events_info->pageins = task->pageins;
		events_info->cow_faults = task->cow_faults;
		events_info->messages_sent = task->messages_sent;
		events_info->messages_received = task->messages_received;
		events_info->syscalls_mach = task->syscalls_mach;
		events_info->syscalls_unix = task->syscalls_unix;

		events_info->csw = task->c_switch;

		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			events_info->csw	   += thread->c_switch;
			events_info->syscalls_mach += thread->syscalls_mach;
			events_info->syscalls_unix += thread->syscalls_unix;
		}


		*task_info_count = TASK_EVENTS_INFO_COUNT;
		break;
	}
	case TASK_AFFINITY_TAG_INFO:
	{
		if (*task_info_count < TASK_AFFINITY_TAG_INFO_COUNT) {
		    error = KERN_INVALID_ARGUMENT;
		    break;
		}

		error = task_affinity_info(task, task_info_out, task_info_count);
		break;
	}
	default:
		error = KERN_INVALID_ARGUMENT;
	}

	task_unlock(task);
	return (error);
}

void
task_vtimer_set(
	task_t		task,
	integer_t	which)
{
	thread_t	thread;
	spl_t		x;

	/* assert(task == current_task()); */ /* bogus assert 4803227 4807483 */

	task_lock(task);

	task->vtimers |= which;

	switch (which) {

	case TASK_VTIMER_USER:
		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			x = splsched();
			thread_lock(thread);
			if (thread->precise_user_kernel_time)
				thread->vtimer_user_save = timer_grab(&thread->user_timer);
			else
				thread->vtimer_user_save = timer_grab(&thread->system_timer);
			thread_unlock(thread);
			splx(x);
		}
		break;

	case TASK_VTIMER_PROF:
		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			x = splsched();
			thread_lock(thread);
			thread->vtimer_prof_save = timer_grab(&thread->user_timer);
			thread->vtimer_prof_save += timer_grab(&thread->system_timer);
			thread_unlock(thread);
			splx(x);
		}
		break;

	case TASK_VTIMER_RLIM:
		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			x = splsched();
			thread_lock(thread);
			thread->vtimer_rlim_save = timer_grab(&thread->user_timer);
			thread->vtimer_rlim_save += timer_grab(&thread->system_timer);
			thread_unlock(thread);
			splx(x);
		}
		break;
	}

	task_unlock(task);
}

void
task_vtimer_clear(
	task_t		task,
	integer_t	which)
{
	assert(task == current_task());

	task_lock(task);

	task->vtimers &= ~which;

	task_unlock(task);
}

void
task_vtimer_update(
__unused
	task_t		task,
	integer_t	which,
	uint32_t	*microsecs)
{
	thread_t	thread = current_thread();
	uint32_t	tdelt;
	clock_sec_t	secs;
	uint64_t	tsum;

	assert(task == current_task());

	assert(task->vtimers & which);

	secs = tdelt = 0;

	switch (which) {

	case TASK_VTIMER_USER:
		if (thread->precise_user_kernel_time) {
			tdelt = (uint32_t)timer_delta(&thread->user_timer,
								&thread->vtimer_user_save);
		} else {
			tdelt = (uint32_t)timer_delta(&thread->system_timer,
								&thread->vtimer_user_save);
		}
		absolutetime_to_microtime(tdelt, &secs, microsecs);
		break;

	case TASK_VTIMER_PROF:
		tsum = timer_grab(&thread->user_timer);
		tsum += timer_grab(&thread->system_timer);
		tdelt = (uint32_t)(tsum - thread->vtimer_prof_save);
		absolutetime_to_microtime(tdelt, &secs, microsecs);
		/* if the time delta is smaller than a usec, ignore */
		if (*microsecs != 0)
			thread->vtimer_prof_save = tsum;
		break;

	case TASK_VTIMER_RLIM:
		tsum = timer_grab(&thread->user_timer);
		tsum += timer_grab(&thread->system_timer);
		tdelt = (uint32_t)(tsum - thread->vtimer_rlim_save);
		thread->vtimer_rlim_save = tsum;
		absolutetime_to_microtime(tdelt, &secs, microsecs);
		break;
	}

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
    return (task_assign(task, &pset0, assign_threads));
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

	*pset = &pset0;

	return (KERN_SUCCESS);
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
 * Install default (machine-dependent) initial thread state 
 * on the task.  Subsequent thread creation will have this initial
 * state set on the thread by machine_thread_inherit_taskwide().
 * Flavors and structures are exactly the same as those to thread_set_state()
 */
kern_return_t 
task_set_state(
	task_t task, 
	int flavor, 
	thread_state_t state, 
	mach_msg_type_number_t state_count)
{
	kern_return_t ret;

	if (task == TASK_NULL) {
		return (KERN_INVALID_ARGUMENT);
	}

	task_lock(task);

	if (!task->active) {
		task_unlock(task);
		return (KERN_FAILURE);
	}

	ret = machine_task_set_state(task, flavor, state, state_count);

	task_unlock(task);
	return ret;
}

/*
 * Examine the default (machine-dependent) initial thread state 
 * on the task, as set by task_set_state().  Flavors and structures
 * are exactly the same as those passed to thread_get_state().
 */
kern_return_t 
task_get_state(
	task_t 	task, 
	int	flavor,
	thread_state_t state,
	mach_msg_type_number_t *state_count)
{
	kern_return_t ret;

	if (task == TASK_NULL) {
		return (KERN_INVALID_ARGUMENT);
	}

	task_lock(task);

	if (!task->active) {
		task_unlock(task);
		return (KERN_FAILURE);
	}

	ret = machine_task_get_state(task, flavor, state, state_count);

	task_unlock(task);
	return ret;
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

int
check_for_tasksuspend(task_t task)
{

	if (task == TASK_NULL)
		return (0);

	return (task->suspend_count > 0);
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

/* 
 * This routine is called always with task lock held.
 * And it returns a thread handle without reference as the caller
 * operates on it under the task lock held.
 */
thread_t
task_findtid(task_t task, uint64_t tid)
{
	thread_t thread= THREAD_NULL;

	queue_iterate(&task->threads, thread, thread_t, task_threads) {
			if (thread->thread_id == tid)
				return(thread);
	}
	return(THREAD_NULL);
}


#if CONFIG_MACF_MACH
/*
 * Protect 2 task labels against modification by adding a reference on
 * both label handles. The locks do not actually have to be held while
 * using the labels as only labels with one reference can be modified
 * in place.
 */

void
tasklabel_lock2(
	task_t a,
	task_t b)
{
	labelh_reference(a->label);
	labelh_reference(b->label);
}

void
tasklabel_unlock2(
	task_t a,
	task_t b)
{
	labelh_release(a->label);
	labelh_release(b->label);
}

void
mac_task_label_update_internal(
	struct label	*pl,
	struct task	*task)
{

	tasklabel_lock(task);
	task->label = labelh_modify(task->label);
	mac_task_label_update(pl, &task->maclabel);
	tasklabel_unlock(task);
	ip_lock(task->itk_self);
	mac_port_label_update_cred(pl, &task->itk_self->ip_label);
	ip_unlock(task->itk_self);
}

void
mac_task_label_modify(
	struct task	*task,
	void		*arg,
	void (*f)	(struct label *l, void *arg))
{

	tasklabel_lock(task);
	task->label = labelh_modify(task->label);
	(*f)(&task->maclabel, arg);
	tasklabel_unlock(task);
}

struct label *
mac_task_get_label(struct task *task)
{
	return (&task->maclabel);
}
#endif
