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
#include <mach/mach_types.h>
#include <mach/machine/vm_param.h>

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
#include <vm/vm_kern.h>
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
kern_return_t get_signalact(task_t , thread_t *, int);
int get_vmsubmap_entries(vm_map_t, vm_object_offset_t, vm_object_offset_t);
void syscall_exit_funnelcheck(void);


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
void *get_bsdthreadtask_info(thread_t th)
{
	return(th->task != TASK_NULL ? th->task->bsd_info : NULL);
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
 * XXX
 */
int get_thread_lock_count(thread_t th);		/* forced forward */
int get_thread_lock_count(thread_t th)
{
 	return(th->mutex_count);
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
		if (inc->active &&
				(inc->sched_flags & TH_SFLAG_ABORTED_MASK) != TH_SFLAG_ABORT) {
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
					(inc->sched_flags & TH_SFLAG_ABORTED_MASK) != TH_SFLAG_ABORT) {
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

int get_task_numactivethreads(task_t task)
{
	thread_t	inc;
	int num_active_thr=0;
	task_lock(task);

	for (inc  = (thread_t)queue_first(&task->threads);
			!queue_end(&task->threads, (queue_entry_t)inc); inc = (thread_t)queue_next(&inc->task_threads)) 
	{
		if(inc->active)
			num_active_thr++;
	}
	task_unlock(task);
	return num_active_thr;
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
 * Swap in a new map for the task/thread pair; the old map reference is
 * returned.
 */
vm_map_t
swap_task_map(task_t task, thread_t thread, vm_map_t map, boolean_t doswitch)
{
	vm_map_t old_map;

	if (task != thread->task)
		panic("swap_task_map");

	task_lock(task);
	mp_disable_preemption();
	old_map = task->map;
	thread->map = task->map = map;
	if (doswitch)
		pmap_switch(map->pmap);
	mp_enable_preemption();
	task_unlock(task);

#if (defined(__i386__) || defined(__x86_64__)) && NCOPY_WINDOWS > 0
	inval_copy_windows(thread);
#endif

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
uint64_t get_task_resident_size(task_t task) 
{
	vm_map_t map;
	
	map = (task == kernel_task) ? kernel_map: task->map;
	return((uint64_t)pmap_resident_count(map->pmap) * PAGE_SIZE_64);
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
	return ((th->sched_flags & TH_SFLAG_ABORTED_MASK) == TH_SFLAG_ABORT);
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

	if ((th->sched_flags & TH_SFLAG_ABORTED_MASK) == TH_SFLAG_ABORT &&
			(th->options & TH_OPT_INTMASK) != THREAD_UNINT)
		return (TRUE);
	if (th->sched_flags & TH_SFLAG_ABORTSAFELY) {
		s = splsched();
		thread_lock(th);
		if (th->sched_flags & TH_SFLAG_ABORTSAFELY)
			th->sched_flags &= ~TH_SFLAG_ABORTED_MASK;
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

void
astbsd_on(void)
{
	boolean_t	reenable;

	reenable = ml_set_interrupts_enabled(FALSE);
	ast_on_fast(AST_BSD);
	(void)ml_set_interrupts_enabled(reenable);
}


#include <sys/bsdtask_info.h>

void
fill_taskprocinfo(task_t task, struct proc_taskinfo_internal * ptinfo)
{
	vm_map_t map;
	task_absolutetime_info_data_t   tinfo;
	thread_t thread;
	uint32_t cswitch = 0, numrunning = 0;
	uint32_t syscalls_unix = 0;
	uint32_t syscalls_mach = 0;
	
	map = (task == kernel_task)? kernel_map: task->map;

	ptinfo->pti_virtual_size  = map->size;
	ptinfo->pti_resident_size =
		(mach_vm_size_t)(pmap_resident_count(map->pmap))
		* PAGE_SIZE_64;

	task_lock(task);

	ptinfo->pti_policy = ((task != kernel_task)?
                                          POLICY_TIMESHARE: POLICY_RR);

	tinfo.threads_user = tinfo.threads_system = 0;
	tinfo.total_user = task->total_user_time;
	tinfo.total_system = task->total_system_time;

	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		uint64_t    tval;

		if ((thread->state & TH_RUN) == TH_RUN)
			numrunning++;
		cswitch += thread->c_switch;
		tval = timer_grab(&thread->user_timer);
		tinfo.threads_user += tval;
		tinfo.total_user += tval;

		tval = timer_grab(&thread->system_timer);
		tinfo.threads_system += tval;
		tinfo.total_system += tval;

		syscalls_unix += thread->syscalls_unix;
		syscalls_mach += thread->syscalls_mach;
	}

	ptinfo->pti_total_system = tinfo.total_system;
	ptinfo->pti_total_user = tinfo.total_user;
	ptinfo->pti_threads_system = tinfo.threads_system;
	ptinfo->pti_threads_user = tinfo.threads_user;
	
	ptinfo->pti_faults = task->faults;
	ptinfo->pti_pageins = task->pageins;
	ptinfo->pti_cow_faults = task->cow_faults;
	ptinfo->pti_messages_sent = task->messages_sent;
	ptinfo->pti_messages_received = task->messages_received;
	ptinfo->pti_syscalls_mach = task->syscalls_mach + syscalls_mach;
	ptinfo->pti_syscalls_unix = task->syscalls_unix + syscalls_unix;
	ptinfo->pti_csw = task->c_switch + cswitch;
	ptinfo->pti_threadnum = task->thread_count;
	ptinfo->pti_numrunning = numrunning;
	ptinfo->pti_priority = task->priority;

	task_unlock(task);
}

int 
fill_taskthreadinfo(task_t task, uint64_t thaddr, struct proc_threadinfo_internal * ptinfo, void * vpp, int *vidp)
{
	thread_t  thact;
	int err=0;
	mach_msg_type_number_t count;
	thread_basic_info_data_t basic_info;
	kern_return_t kret;

	task_lock(task);

	for (thact  = (thread_t)queue_first(&task->threads);
			!queue_end(&task->threads, (queue_entry_t)thact); ) {
		if (thact->machine.cthread_self == thaddr)
		{
		
			count = THREAD_BASIC_INFO_COUNT;
			if ((kret = thread_info_internal(thact, THREAD_BASIC_INFO, (thread_info_t)&basic_info, &count)) != KERN_SUCCESS) {
				err = 1;
				goto out;	
			}
#if 0
			ptinfo->pth_user_time = timer_grab(&basic_info.user_time);
			ptinfo->pth_system_time = timer_grab(&basic_info.system_time);
#else
			ptinfo->pth_user_time = ((basic_info.user_time.seconds * NSEC_PER_SEC) + (basic_info.user_time.microseconds * NSEC_PER_USEC));
			ptinfo->pth_system_time = ((basic_info.system_time.seconds * NSEC_PER_SEC) + (basic_info.system_time.microseconds * NSEC_PER_USEC));

#endif
			ptinfo->pth_cpu_usage = basic_info.cpu_usage;
			ptinfo->pth_policy = basic_info.policy;
			ptinfo->pth_run_state = basic_info.run_state;
			ptinfo->pth_flags = basic_info.flags;
			ptinfo->pth_sleep_time = basic_info.sleep_time;
			ptinfo->pth_curpri = thact->sched_pri;
			ptinfo->pth_priority = thact->priority;
			ptinfo->pth_maxpriority = thact->max_priority;
			
			if ((vpp != NULL) && (thact->uthread != NULL)) 
				bsd_threadcdir(thact->uthread, vpp, vidp);
			bsd_getthreadname(thact->uthread,ptinfo->pth_name);
			err = 0;
			goto out; 
		}
		thact = (thread_t)queue_next(&thact->task_threads);
	}
	err = 1;

out:
	task_unlock(task);
	return(err);
}

int
fill_taskthreadlist(task_t task, void * buffer, int thcount)
{
	int numthr=0;
	thread_t thact;
	uint64_t * uptr;
	uint64_t  thaddr;

	uptr = (uint64_t *)buffer;

	task_lock(task);

	for (thact  = (thread_t)queue_first(&task->threads);
			!queue_end(&task->threads, (queue_entry_t)thact); ) {
		thaddr = thact->machine.cthread_self;
		*uptr++ = thaddr;
		numthr++;
		if (numthr >= thcount)
			goto out;
		thact = (thread_t)queue_next(&thact->task_threads);
	}

out:
	task_unlock(task);
	return (int)(numthr * sizeof(uint64_t));
	
}

int
get_numthreads(task_t task)
{
	return(task->thread_count);
}

void 
syscall_exit_funnelcheck(void)
{
        thread_t thread;

	thread = current_thread();

        if (thread->funnel_lock)
		panic("syscall exit with funnel held\n");
}
