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
#include <mach/mach_types.h>
#include <kern/queue.h>
#include <kern/ast.h>
#include <kern/thread.h>
#include <kern/thread_act.h>
#include <kern/task.h>
#include <kern/spl.h>
#include <kern/lock.h>
#include <vm/vm_map.h>
#include <vm/pmap.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_object.h>

#undef thread_should_halt
#undef ipc_port_release
#undef thread_ast_set
#undef thread_ast_clear

decl_simple_lock_data(extern,reaper_lock)
extern queue_head_t           reaper_queue;

/* BSD KERN COMPONENT INTERFACE */

vm_address_t bsd_init_task = 0;
char	init_task_failure_data[1024];
 
thread_act_t get_firstthread(task_t);
vm_map_t  get_task_map(task_t);
ipc_space_t  get_task_ipcspace(task_t);
boolean_t is_kerneltask(task_t);
boolean_t is_thread_idle(thread_t);
boolean_t is_thread_running(thread_t);
thread_shuttle_t getshuttle_thread( thread_act_t);
thread_act_t getact_thread( thread_shuttle_t);
vm_offset_t get_map_min( vm_map_t);
vm_offset_t get_map_max( vm_map_t);
int get_task_userstop(task_t);
int get_thread_userstop(thread_act_t);
int inc_task_userstop(task_t);
boolean_t thread_should_abort(thread_shuttle_t);
boolean_t current_thread_aborted(void);
void task_act_iterate_wth_args(task_t, void(*)(thread_act_t, void *), void *);
void ipc_port_release(ipc_port_t);
void thread_ast_set(thread_act_t, ast_t);
void thread_ast_clear(thread_act_t, ast_t);
boolean_t is_thread_active(thread_t);
event_t get_thread_waitevent(thread_t);
kern_return_t get_thread_waitresult(thread_t);
vm_size_t get_vmmap_size(vm_map_t);
int get_vmmap_entries(vm_map_t);
int  get_task_numacts(task_t);
thread_act_t get_firstthread(task_t task);
kern_return_t get_signalact(task_t , thread_act_t *, thread_t *, int);

kern_return_t bsd_refvm_object(vm_object_t object);


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
void *get_bsdthread_info(thread_act_t th)
{
	return(th->uthread);
}

/*
 * XXX: wait for BSD to  fix signal code
 * Until then, we cannot block here.  We know the task
 * can't go away, so we make sure it is still active after
 * retrieving the first thread for extra safety.
 */
thread_act_t get_firstthread(task_t task)
{
	thread_act_t	thr_act;

	thr_act = (thread_act_t)queue_first(&task->thr_acts);
	if (thr_act == (thread_act_t)&task->thr_acts)
		thr_act = THR_ACT_NULL;
	if (!task->active)
		return(THR_ACT_NULL);
	return(thr_act);
}

kern_return_t get_signalact(task_t task,thread_act_t * thact, thread_t * thshut, int setast)
{

        thread_act_t inc;
        thread_act_t ninc;
        thread_act_t thr_act;
	thread_t	th;

	task_lock(task);
	if (!task->active) {
		task_unlock(task);
		return(KERN_FAILURE);
	}

        thr_act = THR_ACT_NULL;
        for (inc  = (thread_act_t)queue_first(&task->thr_acts);
             inc != (thread_act_t)&task->thr_acts;
             inc  = ninc) {
                th = act_lock_thread(inc);
                if ((inc->active)  && ((th->state & TH_ABORT) != TH_ABORT)) {
                    thr_act = inc;
                   break;
                }
                act_unlock_thread(inc);
                ninc = (thread_act_t)queue_next(&inc->thr_acts);
        }
out:
        if (thact) 
                *thact = thr_act;

        if (thshut)
                *thshut = thr_act? thr_act->thread: THREAD_NULL ;
        if (thr_act) {
                if (setast) {
                    thread_ast_set(thr_act, AST_BSD);
			if (current_act() == thr_act)
				ast_on(AST_BSD);
		}
                act_unlock_thread(thr_act);
        }
	task_unlock(task);

        if (thr_act) 
            return(KERN_SUCCESS);
        else 
            return(KERN_FAILURE);
}

/*
 *
 */
vm_map_t  get_task_map(task_t t)
{
	return(t->map);
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
	return(t->thr_act_count);
}

/*
 * Reset the current task's map by taking a reference
 * on the new map.  The old map reference is returned.
 */
vm_map_t
swap_task_map(task_t task,vm_map_t map)
{
	vm_map_t old_map;

	vm_map_reference(map);
	task_lock(task);
	old_map = task->map;
	task->map = map;
	task_unlock(task);
	return old_map;
}

/*
 * Reset the current act map.
 * The caller donates us a reference to the new map
 * and we donote our reference to the old map to him.
 */
vm_map_t
swap_act_map(thread_act_t thr_act,vm_map_t map)
{
	vm_map_t old_map;

	act_lock(thr_act);
	old_map = thr_act->map;
	thr_act->map = map;
	act_unlock(thr_act);
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
task_t	get_threadtask(thread_act_t th)
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
thread_shuttle_t
getshuttle_thread(
	thread_act_t	th)
{
#ifdef	DEBUG
	assert(th->thread);
#endif
	return(th->thread);
}

/*
 *
 */
thread_act_t
getact_thread(
	thread_shuttle_t	th)
{
#ifdef	DEBUG
	assert(th->top_act);
#endif
	return(th->top_act);
}

/*
 *
 */
vm_offset_t
get_map_min(
	vm_map_t	map)
{
	return(vm_map_min(map));
}

/*
 *
 */
vm_offset_t
get_map_max(
	vm_map_t	map)
{
	return(vm_map_max(map));
}
vm_size_t
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
	vm_map_unlock(map);
	return(total_entries);
}

int
get_vmmap_entries(
	vm_map_t	map)
{
	int	total_entries = 0;
	vm_map_entry_t	entry;

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
	thread_act_t th)
{
	return(th->user_stop_count);
}

/*
 *
 */
int
inc_task_userstop(
	task_t	task)
{
	int i=0;
	i = task->user_stop_count;
	task->user_stop_count++;
	return(i);
}


/*
 *
 */
boolean_t
thread_should_abort(
	thread_shuttle_t th)
{
	return( (!th->top_act || !th->top_act->active || 
        th->state & TH_ABORT)); 
}

/*
 *
 */
boolean_t
current_thread_aborted (
		void)
{
	thread_t th = current_thread();

	return(!th->top_act ||
	       ((th->state & TH_ABORT) && (th->interruptible))); 
}

/*
 *
 */
void
task_act_iterate_wth_args(
	task_t task,
	void (*func_callback)(thread_act_t, void *),
	void *func_arg)
{
        thread_act_t inc, ninc;

	task_lock(task);
        for (inc  = (thread_act_t)queue_first(&task->thr_acts);
             inc != (thread_act_t)&task->thr_acts;
             inc  = ninc) {
                ninc = (thread_act_t)queue_next(&inc->thr_acts);
                (void) (*func_callback)(inc, func_arg);
        }
	task_unlock(task);
}

void
ipc_port_release(
	ipc_port_t port)
{
	ipc_object_release(&(port)->ip_object);
}

void
thread_ast_set(
	thread_act_t act, 
	ast_t reason) 
{
          act->ast |= reason;
}
void
thread_ast_clear(
	thread_act_t act, 
	ast_t reason) 
{
          act->ast &= ~(reason);
}

boolean_t
is_thread_active(
	thread_shuttle_t th)
{
	return(th->active);
}

event_t
get_thread_waitevent(
	thread_shuttle_t th)
{
	return(th->wait_event);
}

kern_return_t
get_thread_waitresult(
	thread_shuttle_t th)
{
	return(th->wait_result);
}

kern_return_t
bsd_refvm_object(vm_object_t object)
{
	vm_object_reference(object);
	return(KERN_SUCCESS);
}

