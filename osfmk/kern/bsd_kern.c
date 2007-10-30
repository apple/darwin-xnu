/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
#include <mach/mach_types.h>

#include <kern/kern_types.h>
#include <kern/processor.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <kern/spl.h>
#include <kern/lock.h>
#include <kern/ast.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_object.h>
#include <vm/vm_map.h>
#include <vm/pmap.h>
#include <vm/vm_protos.h> /* last */

#undef thread_should_halt
#undef ipc_port_release

/* BSD KERN COMPONENT INTERFACE */

task_t	bsd_init_task = TASK_NULL;
char	init_task_failure_data[1024];
extern unsigned int not_in_kdp; /* Skip acquiring locks if we're in kdp */
 
thread_t get_firstthread(task_t);
int get_task_userstop(task_t);
int get_thread_userstop(thread_t);
boolean_t thread_should_abort(thread_t);
boolean_t current_thread_aborted(void);
void task_act_iterate_wth_args(task_t, void(*)(thread_t, void *), void *);
void ipc_port_release(ipc_port_t);
boolean_t is_thread_active(thread_t);
kern_return_t get_signalact(task_t , thread_t *, int);
int get_vmsubmap_entries(vm_map_t, vm_object_offset_t, vm_object_offset_t);

/*
 *
 */
void  *get_bsdtask_info(task_t t)
{
	return(t->bsd_info);
}

/*
 *
 */
void set_bsdtask_info(task_t t,void * v)
{
	t->bsd_info=v;
}

/*
 *
 */
void *get_bsdthread_info(thread_t th)
{
	return(th->uthread);
}

/*
 * XXX: wait for BSD to  fix signal code
 * Until then, we cannot block here.  We know the task
 * can't go away, so we make sure it is still active after
 * retrieving the first thread for extra safety.
 */
thread_t get_firstthread(task_t task)
{
	thread_t	thread = (thread_t)queue_first(&task->threads);

	if (queue_end(&task->threads, (queue_entry_t)thread))
		thread = THREAD_NULL;

	if (!task->active)
		return (THREAD_NULL);

	return (thread);
}

kern_return_t
get_signalact(
	task_t		task,
	thread_t	*result_out,
	int			setast)
{
	kern_return_t	result = KERN_SUCCESS;
	thread_t		inc, thread = THREAD_NULL;

	task_lock(task);

	if (!task->active) {
		task_unlock(task);

		return (KERN_FAILURE);
	}

	for (inc  = (thread_t)queue_first(&task->threads);
			!queue_end(&task->threads, (queue_entry_t)inc); ) {
                thread_mtx_lock(inc);
                if (inc->active  && 
	                    (inc->state & (TH_ABORT|TH_ABORT_SAFELY)) != TH_ABORT) {
                    thread = inc;
					break;
                }
                thread_mtx_unlock(inc);

				inc = (thread_t)queue_next(&inc->task_threads);
	}

	if (result_out) 
		*result_out = thread;

	if (thread) {
		if (setast)
			act_set_astbsd(thread);

		thread_mtx_unlock(thread);
	}
	else
		result = KERN_FAILURE;

	task_unlock(task);

	return (result);
}


kern_return_t
check_actforsig(
	task_t			task,
	thread_t		thread,
	int				setast)
{
	kern_return_t	result = KERN_FAILURE;
	thread_t		inc;

	task_lock(task);

	if (!task->active) {
		task_unlock(task);

		return (KERN_FAILURE);
	}

	for (inc  = (thread_t)queue_first(&task->threads);
			!queue_end(&task->threads, (queue_entry_t)inc); ) {
		if (inc == thread) {
			thread_mtx_lock(inc);

			if (inc->active  && 
				(inc->state & (TH_ABORT|TH_ABORT_SAFELY)) != TH_ABORT) {
				result = KERN_SUCCESS;
				break;
			}

			thread_mtx_unlock(inc);
			break;
		}

		inc = (thread_t)queue_next(&inc->task_threads);
	}

	if (result == KERN_SUCCESS) {
		if (setast)
			act_set_astbsd(thread);

		thread_mtx_unlock(thread);
	}

	task_unlock(task);

	return (result);
}

/*
 * This is only safe to call from a thread executing in
 * in the task's context or if the task is locked  Otherwise,
 * the map could be switched for the task (and freed) before
 * we to return it here.
 */
vm_map_t  get_task_map(task_t t)
{
	return(t->map);
}

vm_map_t  get_task_map_reference(task_t t)
{
	vm_map_t m;

	if (t == NULL)
		return VM_MAP_NULL;

	task_lock(t);
	if (!t->active) {
		task_unlock(t);
		return VM_MAP_NULL;
	}
	m = t->map;
	vm_map_reference_swap(m);
	task_unlock(t);
	return m;
}

/*
 *
 */
ipc_space_t  get_task_ipcspace(task_t t)
{
	return(t->itk_space);
}

int  get_task_numacts(task_t t)
{
	return(t->thread_count);
}

/* does this machine need  64bit register set for signal handler */
int is_64signalregset(void)
{
	task_t t = current_task();
	if(t->taskFeatures[0] & tf64BitData)
		return(1);
	else
		return(0);
}

/*
 * The old map reference is returned.
 */
vm_map_t
swap_task_map(task_t task,vm_map_t map)
{
	thread_t thread = current_thread();
	vm_map_t old_map;

	if (task != thread->task)
		panic("swap_task_map");

	task_lock(task);
	old_map = task->map;
	thread->map = task->map = map;
	task_unlock(task);
	return old_map;
}

/*
 *
 */
pmap_t  get_task_pmap(task_t t)
{
	return(t->map->pmap);
}

/*
 *
 */
pmap_t  get_map_pmap(vm_map_t map)
{
	return(map->pmap);
}
/*
 *
 */
task_t	get_threadtask(thread_t th)
{
	return(th->task);
}


/*
 *
 */
boolean_t is_thread_idle(thread_t th)
{
	return((th->state & TH_IDLE) == TH_IDLE);
}

/*
 *
 */
boolean_t is_thread_running(thread_t th)
{
	return((th->state & TH_RUN) == TH_RUN);
}

/*
 *
 */
thread_t
getshuttle_thread(
	thread_t	th)
{
	return(th);
}

/*
 *
 */
thread_t
getact_thread(
	thread_t	th)
{
	return(th);
}

/*
 *
 */
vm_map_offset_t
get_map_min(
	vm_map_t	map)
{
	return(vm_map_min(map));
}

/*
 *
 */
vm_map_offset_t
get_map_max(
	vm_map_t	map)
{
	return(vm_map_max(map));
}
vm_map_size_t
get_vmmap_size(
	vm_map_t	map)
{
	return(map->size);
}

int
get_vmsubmap_entries(
	vm_map_t	map,
	vm_object_offset_t	start,
	vm_object_offset_t	end)
{
	int	total_entries = 0;
	vm_map_entry_t	entry;

	if (not_in_kdp)
	  vm_map_lock(map);
	entry = vm_map_first_entry(map);
	while((entry != vm_map_to_entry(map)) && (entry->vme_start < start)) {
		entry = entry->vme_next;
	}

	while((entry != vm_map_to_entry(map)) && (entry->vme_start < end)) {
		if(entry->is_sub_map) {
			total_entries += 	
				get_vmsubmap_entries(entry->object.sub_map, 
					entry->offset, 
					entry->offset + 
					(entry->vme_end - entry->vme_start));
		} else {
			total_entries += 1;
		}
		entry = entry->vme_next;
	}
	if (not_in_kdp)
	  vm_map_unlock(map);
	return(total_entries);
}

int
get_vmmap_entries(
	vm_map_t	map)
{
	int	total_entries = 0;
	vm_map_entry_t	entry;

	if (not_in_kdp)
	  vm_map_lock(map);
	entry = vm_map_first_entry(map);

	while(entry != vm_map_to_entry(map)) {
		if(entry->is_sub_map) {
			total_entries += 	
				get_vmsubmap_entries(entry->object.sub_map, 
					entry->offset, 
					entry->offset + 
					(entry->vme_end - entry->vme_start));
		} else {
			total_entries += 1;
		}
		entry = entry->vme_next;
	}
	if (not_in_kdp)
	  vm_map_unlock(map);
	return(total_entries);
}

/*
 *
 */
/*
 *
 */
int
get_task_userstop(
	task_t task)
{
	return(task->user_stop_count);
}

/*
 *
 */
int
get_thread_userstop(
	thread_t th)
{
	return(th->user_stop_count);
}

/*
 *
 */
boolean_t
thread_should_abort(
	thread_t th)
{
	return ((th->state & (TH_ABORT|TH_ABORT_SAFELY)) == TH_ABORT);
}

/*
 * This routine is like thread_should_abort() above.  It checks to
 * see if the current thread is aborted.  But unlike above, it also
 * checks to see if thread is safely aborted.  If so, it returns
 * that fact, and clears the condition (safe aborts only should
 * have a single effect, and a poll of the abort status
 * qualifies.
 */
boolean_t
current_thread_aborted (
		void)
{
	thread_t th = current_thread();
	spl_t s;

	if ((th->state & (TH_ABORT|TH_ABORT_SAFELY)) == TH_ABORT &&
			(th->options & TH_OPT_INTMASK) != THREAD_UNINT)
		return (TRUE);
	if (th->state & TH_ABORT_SAFELY) {
		s = splsched();
		thread_lock(th);
		if (th->state & TH_ABORT_SAFELY)
			th->state &= ~(TH_ABORT|TH_ABORT_SAFELY);
		thread_unlock(th);
		splx(s);
	}
	return FALSE;
}

/*
 *
 */
void
task_act_iterate_wth_args(
	task_t			task,
	void			(*func_callback)(thread_t, void *),
	void			*func_arg)
{
	thread_t	inc;

	task_lock(task);

	for (inc  = (thread_t)queue_first(&task->threads);
			!queue_end(&task->threads, (queue_entry_t)inc); ) {
		(void) (*func_callback)(inc, func_arg);
		inc = (thread_t)queue_next(&inc->task_threads);
	}

	task_unlock(task);
}

void
ipc_port_release(
	ipc_port_t port)
{
	ipc_object_release(&(port)->ip_object);
}

boolean_t
is_thread_active(
	thread_t th)
{
	return(th->active);
}

void
astbsd_on(void)
{
	boolean_t	reenable;

	reenable = ml_set_interrupts_enabled(FALSE);
	ast_on_fast(AST_BSD);
	(void)ml_set_interrupts_enabled(reenable);
}
