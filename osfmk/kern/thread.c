/*
 * Copyright (c) 2000-2012 Apple Inc. All rights reserved.
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
 *	File:	kern/thread.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young, David Golub
 *	Date:	1986
 *
 *	Thread management primitives implementation.
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

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/policy.h>
#include <mach/thread_info.h>
#include <mach/thread_special_ports.h>
#include <mach/thread_status.h>
#include <mach/time_value.h>
#include <mach/vm_param.h>

#include <machine/thread.h>
#include <machine/pal_routines.h>
#include <machine/limits.h>

#include <kern/kern_types.h>
#include <kern/kalloc.h>
#include <kern/cpu_data.h>
#include <kern/counters.h>
#include <kern/extmod_statistics.h>
#include <kern/ipc_mig.h>
#include <kern/ipc_tt.h>
#include <kern/mach_param.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/processor.h>
#include <kern/queue.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/sync_lock.h>
#include <kern/syscall_subr.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/host.h>
#include <kern/zalloc.h>
#include <kern/assert.h>
#include <kern/exc_resource.h>
#include <kern/telemetry.h>
#if KPC
#include <kern/kpc.h>
#endif

#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_port.h>

#include <vm/vm_kern.h>
#include <vm/vm_pageout.h>

#include <sys/kdebug.h>

#include <mach/sdt.h>

/*
 * Exported interfaces
 */
#include <mach/task_server.h>
#include <mach/thread_act_server.h>
#include <mach/mach_host_server.h>
#include <mach/host_priv_server.h>

static struct zone			*thread_zone;
static lck_grp_attr_t		thread_lck_grp_attr;
lck_attr_t					thread_lck_attr;
lck_grp_t					thread_lck_grp;

decl_simple_lock_data(static,thread_stack_lock)
static queue_head_t		thread_stack_queue;

decl_simple_lock_data(static,thread_terminate_lock)
static queue_head_t		thread_terminate_queue;

static struct thread	thread_template, init_thread;

static void		sched_call_null(
					int			type,
					thread_t	thread);

#ifdef MACH_BSD
extern void proc_exit(void *);
extern uint64_t get_dispatchqueue_offset_from_proc(void *);
extern int      proc_selfpid(void);
extern char *   proc_name_address(void *p);
#endif /* MACH_BSD */

extern int disable_exc_resource;
extern int debug_task;
int thread_max = CONFIG_THREAD_MAX;	/* Max number of threads */
int task_threadmax = CONFIG_THREAD_MAX;

static uint64_t		thread_unique_id = 0;

struct _thread_ledger_indices thread_ledgers = { -1 };
static ledger_template_t thread_ledger_template = NULL;
void init_thread_ledgers(void);
int task_disable_cpumon(task_t task);

/*
 * Level (in terms of percentage of the limit) at which the CPU usage monitor triggers telemetry.
 *
 * (ie when any thread's CPU consumption exceeds 70% of the limit, start taking user
 *  stacktraces, aka micro-stackshots)
 */
#define	CPUMON_USTACKSHOTS_TRIGGER_DEFAULT_PCT 70

int cpumon_ustackshots_trigger_pct; /* Percentage. Level at which we start gathering telemetry. */
void __attribute__((noinline)) THIS_THREAD_IS_CONSUMING_TOO_MUCH_CPU__SENDING_EXC_RESOURCE(void);

/*
 * The smallest interval over which we support limiting CPU consumption is 1ms
 */
#define MINIMUM_CPULIMIT_INTERVAL_MS 1

void
thread_bootstrap(void)
{
	/*
	 *	Fill in a template thread for fast initialization.
	 */

	thread_template.runq = PROCESSOR_NULL;

	thread_template.ref_count = 2;

	thread_template.reason = AST_NONE;
	thread_template.at_safe_point = FALSE;
	thread_template.wait_event = NO_EVENT64;
	thread_template.wait_queue = WAIT_QUEUE_NULL;
	thread_template.wait_result = THREAD_WAITING;
	thread_template.options = THREAD_ABORTSAFE;
	thread_template.state = TH_WAIT | TH_UNINT;
	thread_template.wake_active = FALSE;
	thread_template.continuation = THREAD_CONTINUE_NULL;
	thread_template.parameter = NULL;

	thread_template.importance = 0;
	thread_template.sched_mode = TH_MODE_NONE;
	thread_template.sched_flags = 0;
	thread_template.saved_mode = TH_MODE_NONE;
	thread_template.safe_release = 0;

	thread_template.priority = 0;
	thread_template.sched_pri = 0;
	thread_template.max_priority = 0;
	thread_template.task_priority = 0;
	thread_template.promotions = 0;
	thread_template.pending_promoter_index = 0;
	thread_template.pending_promoter[0] =
	thread_template.pending_promoter[1] = NULL;
	thread_template.rwlock_count = 0;

	thread_template.realtime.deadline = UINT64_MAX;

	thread_template.current_quantum = 0;
	thread_template.last_run_time = 0;
	thread_template.last_quantum_refill_time = 0;

	thread_template.computation_metered = 0;
	thread_template.computation_epoch = 0;

#if defined(CONFIG_SCHED_TRADITIONAL)
	thread_template.sched_stamp = 0;
	thread_template.pri_shift = INT8_MAX;
	thread_template.sched_usage = 0;
	thread_template.cpu_usage = thread_template.cpu_delta = 0;
#endif
	thread_template.c_switch = thread_template.p_switch = thread_template.ps_switch = 0;

	thread_template.bound_processor = PROCESSOR_NULL;
	thread_template.last_processor = PROCESSOR_NULL;

	thread_template.sched_call = sched_call_null;

	timer_init(&thread_template.user_timer);
	timer_init(&thread_template.system_timer);
	thread_template.user_timer_save = 0;
	thread_template.system_timer_save = 0;
	thread_template.vtimer_user_save = 0;
	thread_template.vtimer_prof_save = 0;
	thread_template.vtimer_rlim_save = 0;

	thread_template.wait_timer_is_set = FALSE;
	thread_template.wait_timer_active = 0;

	thread_template.depress_timer_active = 0;

	thread_template.special_handler.handler = special_handler;
	thread_template.special_handler.next = NULL;

	thread_template.funnel_lock = THR_FUNNEL_NULL;
	thread_template.funnel_state = 0;
	thread_template.recover = (vm_offset_t)NULL;
	
	thread_template.map = VM_MAP_NULL;

#if CONFIG_DTRACE
	thread_template.t_dtrace_predcache = 0;
	thread_template.t_dtrace_vtime = 0;
	thread_template.t_dtrace_tracing = 0;
#endif /* CONFIG_DTRACE */

#if KPC
	thread_template.kpc_buf = NULL;
#endif

	thread_template.t_chud = 0;
	thread_template.t_page_creation_count = 0;
	thread_template.t_page_creation_time = 0;

	thread_template.affinity_set = NULL;
	
	thread_template.syscalls_unix = 0;
	thread_template.syscalls_mach = 0;

	thread_template.t_ledger = LEDGER_NULL;
	thread_template.t_threadledger = LEDGER_NULL;

	thread_template.requested_policy = default_task_requested_policy;
	thread_template.effective_policy = default_task_effective_policy;
	thread_template.pended_policy    = default_task_pended_policy;

	thread_template.iotier_override = THROTTLE_LEVEL_NONE;

	thread_template.thread_callout_interrupt_wakeups = thread_template.thread_callout_platform_idle_wakeups = 0;

	thread_template.thread_timer_wakeups_bin_1 = thread_template.thread_timer_wakeups_bin_2 = 0;
	thread_template.callout_woken_from_icontext = thread_template.callout_woken_from_platform_idle = 0;

	thread_template.thread_tag = 0;

	init_thread = thread_template;
	machine_set_current_thread(&init_thread);
}

void
thread_init(void)
{
	thread_zone = zinit(
			sizeof(struct thread),
			thread_max * sizeof(struct thread),
			THREAD_CHUNK * sizeof(struct thread),
			"threads");

	lck_grp_attr_setdefault(&thread_lck_grp_attr);
	lck_grp_init(&thread_lck_grp, "thread", &thread_lck_grp_attr);
	lck_attr_setdefault(&thread_lck_attr);
	
	stack_init();

	/*
	 *	Initialize any machine-dependent
	 *	per-thread structures necessary.
	 */
	machine_thread_init();

	if (!PE_parse_boot_argn("cpumon_ustackshots_trigger_pct", &cpumon_ustackshots_trigger_pct,
		sizeof (cpumon_ustackshots_trigger_pct))) {
		cpumon_ustackshots_trigger_pct = CPUMON_USTACKSHOTS_TRIGGER_DEFAULT_PCT;
	}

	init_thread_ledgers();
}

static void
thread_terminate_continue(void)
{
	panic("thread_terminate_continue");
	/*NOTREACHED*/
}

/*
 *	thread_terminate_self:
 */
void
thread_terminate_self(void)
{
	thread_t		thread = current_thread();

	task_t			task;
	spl_t			s;
	int threadcnt;

	pal_thread_terminate_self(thread);

	DTRACE_PROC(lwp__exit);

	thread_mtx_lock(thread);

	ipc_thread_disable(thread);
	
	thread_mtx_unlock(thread);

	s = splsched();
	thread_lock(thread);

	/*
	 *	Cancel priority depression, wait for concurrent expirations
	 *	on other processors.
	 */
	if (thread->sched_flags & TH_SFLAG_DEPRESSED_MASK) {
		thread->sched_flags &= ~TH_SFLAG_DEPRESSED_MASK;

		if (timer_call_cancel(&thread->depress_timer))
			thread->depress_timer_active--;
	}

	while (thread->depress_timer_active > 0) {
		thread_unlock(thread);
		splx(s);

		delay(1);

		s = splsched();
		thread_lock(thread);
	}

	thread_sched_call(thread, NULL);

	thread_unlock(thread);
	splx(s);

	thread_policy_reset(thread);


	task = thread->task;
	uthread_cleanup(task, thread->uthread, task->bsd_info);
	threadcnt = hw_atomic_sub(&task->active_thread_count, 1);

	/*
	 * If we are the last thread to terminate and the task is
	 * associated with a BSD process, perform BSD process exit.
	 */
	if (threadcnt == 0 && task->bsd_info != NULL)
		proc_exit(task->bsd_info);

	uthread_cred_free(thread->uthread);

	s = splsched();
	thread_lock(thread);

	/*
	 *	Cancel wait timer, and wait for
	 *	concurrent expirations.
	 */
	if (thread->wait_timer_is_set) {
		thread->wait_timer_is_set = FALSE;

		if (timer_call_cancel(&thread->wait_timer))
			thread->wait_timer_active--;
	}

	while (thread->wait_timer_active > 0) {
		thread_unlock(thread);
		splx(s);

		delay(1);

		s = splsched();
		thread_lock(thread);
	}

	/*
	 *	If there is a reserved stack, release it.
	 */
	if (thread->reserved_stack != 0) {
		stack_free_reserved(thread);
		thread->reserved_stack = 0;
	}

	/*
	 *	Mark thread as terminating, and block.
	 */
	thread->state |= TH_TERMINATE;
	thread_mark_wait_locked(thread, THREAD_UNINT);
	assert(thread->promotions == 0);
	assert(thread->rwlock_count == 0);
	thread_unlock(thread);
	/* splsched */

	thread_block((thread_continue_t)thread_terminate_continue);
	/*NOTREACHED*/
}

void
thread_deallocate(
	thread_t			thread)
{
	task_t				task;

	if (thread == THREAD_NULL)
		return;

	if (thread_deallocate_internal(thread) > 0)
		return;

	if(!(thread->state & TH_TERMINATE2))
		panic("thread_deallocate: thread not properly terminated\n");

#if KPC
	kpc_thread_destroy(thread);
#endif


	ipc_thread_terminate(thread);

	task = thread->task;

#ifdef MACH_BSD 
	{
		void *ut = thread->uthread;

		thread->uthread = NULL;
		uthread_zone_free(ut);
	}
#endif  /* MACH_BSD */   

	if (thread->t_ledger)
		ledger_dereference(thread->t_ledger);
	if (thread->t_threadledger)
		ledger_dereference(thread->t_threadledger);

	if (thread->kernel_stack != 0)
		stack_free(thread);

	lck_mtx_destroy(&thread->mutex, &thread_lck_grp);
	machine_thread_destroy(thread);

	task_deallocate(task);

	zfree(thread_zone, thread);
}

/*
 *	thread_terminate_daemon:
 *
 *	Perform final clean up for terminating threads.
 */
static void
thread_terminate_daemon(void)
{
	thread_t	self, thread;
	task_t		task;

	self = current_thread();
	self->options |= TH_OPT_SYSTEM_CRITICAL;

	(void)splsched();
	simple_lock(&thread_terminate_lock);

	while ((thread = (thread_t)dequeue_head(&thread_terminate_queue)) != THREAD_NULL) {
		simple_unlock(&thread_terminate_lock);
		(void)spllo();

		task = thread->task;

		task_lock(task);
		task->total_user_time += timer_grab(&thread->user_timer);
		if (thread->precise_user_kernel_time) {
			task->total_system_time += timer_grab(&thread->system_timer);
		} else {
			task->total_user_time += timer_grab(&thread->system_timer);
		}

		task->c_switch += thread->c_switch;
		task->p_switch += thread->p_switch;
		task->ps_switch += thread->ps_switch;

		task->syscalls_unix += thread->syscalls_unix;
		task->syscalls_mach += thread->syscalls_mach;

		task->task_timer_wakeups_bin_1 += thread->thread_timer_wakeups_bin_1;
		task->task_timer_wakeups_bin_2 += thread->thread_timer_wakeups_bin_2;
		queue_remove(&task->threads, thread, thread_t, task_threads);
		task->thread_count--;

		/* 
		 * If the task is being halted, and there is only one thread
		 * left in the task after this one, then wakeup that thread.
		 */
		if (task->thread_count == 1 && task->halting)
			thread_wakeup((event_t)&task->halting);

		task_unlock(task);

		lck_mtx_lock(&tasks_threads_lock);
		queue_remove(&threads, thread, thread_t, threads);
		threads_count--;
		lck_mtx_unlock(&tasks_threads_lock);

		thread_deallocate(thread);

		(void)splsched();
		simple_lock(&thread_terminate_lock);
	}

	assert_wait((event_t)&thread_terminate_queue, THREAD_UNINT);
	simple_unlock(&thread_terminate_lock);
	/* splsched */

	self->options &= ~TH_OPT_SYSTEM_CRITICAL;
	thread_block((thread_continue_t)thread_terminate_daemon);
	/*NOTREACHED*/
}

/*
 *	thread_terminate_enqueue:
 *
 *	Enqueue a terminating thread for final disposition.
 *
 *	Called at splsched.
 */
void
thread_terminate_enqueue(
	thread_t		thread)
{
	simple_lock(&thread_terminate_lock);
	enqueue_tail(&thread_terminate_queue, (queue_entry_t)thread);
	simple_unlock(&thread_terminate_lock);

	thread_wakeup((event_t)&thread_terminate_queue);
}

/*
 *	thread_stack_daemon:
 *
 *	Perform stack allocation as required due to
 *	invoke failures.
 */
static void
thread_stack_daemon(void)
{
	thread_t		thread;
	spl_t			s;

	s = splsched();
	simple_lock(&thread_stack_lock);

	while ((thread = (thread_t)dequeue_head(&thread_stack_queue)) != THREAD_NULL) {
		simple_unlock(&thread_stack_lock);
		splx(s);

		/* allocate stack with interrupts enabled so that we can call into VM */
		stack_alloc(thread);
		
		s = splsched();
		thread_lock(thread);
		thread_setrun(thread, SCHED_PREEMPT | SCHED_TAILQ);
		thread_unlock(thread);

		simple_lock(&thread_stack_lock);
	}

	assert_wait((event_t)&thread_stack_queue, THREAD_UNINT);
	simple_unlock(&thread_stack_lock);
	splx(s);

	thread_block((thread_continue_t)thread_stack_daemon);
	/*NOTREACHED*/
}

/*
 *	thread_stack_enqueue:
 *
 *	Enqueue a thread for stack allocation.
 *
 *	Called at splsched.
 */
void
thread_stack_enqueue(
	thread_t		thread)
{
	simple_lock(&thread_stack_lock);
	enqueue_tail(&thread_stack_queue, (queue_entry_t)thread);
	simple_unlock(&thread_stack_lock);

	thread_wakeup((event_t)&thread_stack_queue);
}

void
thread_daemon_init(void)
{
	kern_return_t	result;
	thread_t	thread = NULL;

	simple_lock_init(&thread_terminate_lock, 0);
	queue_init(&thread_terminate_queue);

	result = kernel_thread_start_priority((thread_continue_t)thread_terminate_daemon, NULL, MINPRI_KERNEL, &thread);
	if (result != KERN_SUCCESS)
		panic("thread_daemon_init: thread_terminate_daemon");

	thread_deallocate(thread);

	simple_lock_init(&thread_stack_lock, 0);
	queue_init(&thread_stack_queue);

	result = kernel_thread_start_priority((thread_continue_t)thread_stack_daemon, NULL, BASEPRI_PREEMPT, &thread);
	if (result != KERN_SUCCESS)
		panic("thread_daemon_init: thread_stack_daemon");

	thread_deallocate(thread);
}

/*
 * Create a new thread.
 * Doesn't start the thread running.
 */
static kern_return_t
thread_create_internal(
	task_t					parent_task,
	integer_t				priority,
	thread_continue_t		continuation,
	int						options,
#define TH_OPTION_NONE		0x00
#define TH_OPTION_NOCRED	0x01
#define TH_OPTION_NOSUSP	0x02
	thread_t				*out_thread)
{
	thread_t				new_thread;
	static thread_t			first_thread;

	/*
	 *	Allocate a thread and initialize static fields
	 */
	if (first_thread == THREAD_NULL)
		new_thread = first_thread = current_thread();
	else
		new_thread = (thread_t)zalloc(thread_zone);
	if (new_thread == THREAD_NULL)
		return (KERN_RESOURCE_SHORTAGE);

	if (new_thread != first_thread)
		*new_thread = thread_template;

#ifdef MACH_BSD
	new_thread->uthread = uthread_alloc(parent_task, new_thread, (options & TH_OPTION_NOCRED) != 0);
	if (new_thread->uthread == NULL) {
		zfree(thread_zone, new_thread);
		return (KERN_RESOURCE_SHORTAGE);
	}
#endif  /* MACH_BSD */

	if (machine_thread_create(new_thread, parent_task) != KERN_SUCCESS) {
#ifdef MACH_BSD
		void *ut = new_thread->uthread;

		new_thread->uthread = NULL;
		/* cred free may not be necessary */
		uthread_cleanup(parent_task, ut, parent_task->bsd_info);
		uthread_cred_free(ut);
		uthread_zone_free(ut);
#endif  /* MACH_BSD */

		zfree(thread_zone, new_thread);
		return (KERN_FAILURE);
	}

	new_thread->task = parent_task;

	thread_lock_init(new_thread);
	wake_lock_init(new_thread);

	lck_mtx_init(&new_thread->mutex, &thread_lck_grp, &thread_lck_attr);

	ipc_thread_init(new_thread);

	new_thread->continuation = continuation;

	lck_mtx_lock(&tasks_threads_lock);
	task_lock(parent_task);

	if (	!parent_task->active || parent_task->halting ||
			((options & TH_OPTION_NOSUSP) != 0 &&
			 	parent_task->suspend_count > 0)	||
			(parent_task->thread_count >= task_threadmax &&
				parent_task != kernel_task)		) {
		task_unlock(parent_task);
		lck_mtx_unlock(&tasks_threads_lock);

#ifdef MACH_BSD
		{
			void *ut = new_thread->uthread;

			new_thread->uthread = NULL;
			uthread_cleanup(parent_task, ut, parent_task->bsd_info);
			/* cred free may not be necessary */
			uthread_cred_free(ut);
			uthread_zone_free(ut);
		}
#endif  /* MACH_BSD */
		ipc_thread_disable(new_thread);
		ipc_thread_terminate(new_thread);
		lck_mtx_destroy(&new_thread->mutex, &thread_lck_grp);
		machine_thread_destroy(new_thread);
		zfree(thread_zone, new_thread);
		return (KERN_FAILURE);
	}

	/* New threads inherit any default state on the task */
	machine_thread_inherit_taskwide(new_thread, parent_task);

	task_reference_internal(parent_task);

	if (new_thread->task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_PERTHR_LIMIT) {
		/*
		 * This task has a per-thread CPU limit; make sure this new thread
		 * gets its limit set too, before it gets out of the kernel.
		 */
		set_astledger(new_thread);
	}
	new_thread->t_threadledger = LEDGER_NULL;	/* per thread ledger is not inherited */
	new_thread->t_ledger = new_thread->task->ledger;
	if (new_thread->t_ledger)
		ledger_reference(new_thread->t_ledger);

	/* Cache the task's map */
	new_thread->map = parent_task->map;

	/* Chain the thread onto the task's list */
	queue_enter(&parent_task->threads, new_thread, thread_t, task_threads);
	parent_task->thread_count++;
	
	/* So terminating threads don't need to take the task lock to decrement */
	hw_atomic_add(&parent_task->active_thread_count, 1);

	/* Protected by the tasks_threads_lock */
	new_thread->thread_id = ++thread_unique_id;

	queue_enter(&threads, new_thread, thread_t, threads);
	threads_count++;

	timer_call_setup(&new_thread->wait_timer, thread_timer_expire, new_thread);
	timer_call_setup(&new_thread->depress_timer, thread_depress_expire, new_thread);

#if CONFIG_COUNTERS
	/*
	 * If parent task has any reservations, they need to be propagated to this
	 * thread.
	 */
	new_thread->t_chud = (TASK_PMC_FLAG == (parent_task->t_chud & TASK_PMC_FLAG)) ? 
		THREAD_PMC_FLAG : 0U;
#endif
#if KPC
	kpc_thread_create(new_thread);
#endif
	
	/* Only need to update policies pushed from task to thread */
	new_thread->requested_policy.bg_iotier  = parent_task->effective_policy.bg_iotier;
	new_thread->requested_policy.terminated = parent_task->effective_policy.terminated;

	/* Set the thread's scheduling parameters */
	new_thread->sched_mode = SCHED(initial_thread_sched_mode)(parent_task);
	new_thread->sched_flags = 0;
	new_thread->max_priority = parent_task->max_priority;
	new_thread->task_priority = parent_task->priority;
	new_thread->priority = (priority < 0)? parent_task->priority: priority;
	if (new_thread->priority > new_thread->max_priority)
		new_thread->priority = new_thread->max_priority;
	new_thread->importance = new_thread->priority - new_thread->task_priority;
	new_thread->saved_importance = new_thread->importance;

#if defined(CONFIG_SCHED_TRADITIONAL)
	new_thread->sched_stamp = sched_tick;
	new_thread->pri_shift = sched_pri_shift;
#endif
	SCHED(compute_priority)(new_thread, FALSE);

	new_thread->active = TRUE;

	*out_thread = new_thread;

	{
		long	dbg_arg1, dbg_arg2, dbg_arg3, dbg_arg4;

		kdbg_trace_data(parent_task->bsd_info, &dbg_arg2);

		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, 
			TRACEDBG_CODE(DBG_TRACE_DATA, 1) | DBG_FUNC_NONE,
			(vm_address_t)(uintptr_t)thread_tid(new_thread), dbg_arg2, 0, 0, 0);

		kdbg_trace_string(parent_task->bsd_info,
							&dbg_arg1, &dbg_arg2, &dbg_arg3, &dbg_arg4);

		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, 
			TRACEDBG_CODE(DBG_TRACE_STRING, 1) | DBG_FUNC_NONE,
			dbg_arg1, dbg_arg2, dbg_arg3, dbg_arg4, 0);
	}

	DTRACE_PROC1(lwp__create, thread_t, *out_thread);

	return (KERN_SUCCESS);
}

static kern_return_t
thread_create_internal2(
	task_t				task,
	thread_t			*new_thread,
	boolean_t			from_user)
{
	kern_return_t		result;
	thread_t			thread;

	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	result = thread_create_internal(task, -1, (thread_continue_t)thread_bootstrap_return, TH_OPTION_NONE, &thread);
	if (result != KERN_SUCCESS)
		return (result);

	thread->user_stop_count = 1;
	thread_hold(thread);
	if (task->suspend_count > 0)
		thread_hold(thread);

	if (from_user)
		extmod_statistics_incr_thread_create(task);

	task_unlock(task);
	lck_mtx_unlock(&tasks_threads_lock);
	
	*new_thread = thread;

	return (KERN_SUCCESS);
}

/* No prototype, since task_server.h has the _from_user version if KERNEL_SERVER */
kern_return_t
thread_create(
	task_t				task,
	thread_t			*new_thread);

kern_return_t
thread_create(
	task_t				task,
	thread_t			*new_thread)
{
	return thread_create_internal2(task, new_thread, FALSE);
}

kern_return_t
thread_create_from_user(
	task_t				task,
	thread_t			*new_thread)
{
	return thread_create_internal2(task, new_thread, TRUE);
}

static kern_return_t
thread_create_running_internal2(
	register task_t         task,
	int                     flavor,
	thread_state_t          new_state,
	mach_msg_type_number_t  new_state_count,
	thread_t				*new_thread,
	boolean_t				from_user)
{
	register kern_return_t  result;
	thread_t				thread;

	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	result = thread_create_internal(task, -1, (thread_continue_t)thread_bootstrap_return, TH_OPTION_NONE, &thread);
	if (result != KERN_SUCCESS)
		return (result);

	result = machine_thread_set_state(
						thread, flavor, new_state, new_state_count);
	if (result != KERN_SUCCESS) {
		task_unlock(task);
		lck_mtx_unlock(&tasks_threads_lock);

		thread_terminate(thread);
		thread_deallocate(thread);
		return (result);
	}

	thread_mtx_lock(thread);
	thread_start_internal(thread);
	thread_mtx_unlock(thread);

	if (from_user)
		extmod_statistics_incr_thread_create(task);

	task_unlock(task);
	lck_mtx_unlock(&tasks_threads_lock);

	*new_thread = thread;

	return (result);
}

/* Prototype, see justification above */
kern_return_t
thread_create_running(
	register task_t         task,
	int                     flavor,
	thread_state_t          new_state,
	mach_msg_type_number_t  new_state_count,
	thread_t				*new_thread);

kern_return_t
thread_create_running(
	register task_t         task,
	int                     flavor,
	thread_state_t          new_state,
	mach_msg_type_number_t  new_state_count,
	thread_t				*new_thread)
{
	return thread_create_running_internal2(
		task, flavor, new_state, new_state_count,
		new_thread, FALSE);
}

kern_return_t
thread_create_running_from_user(
	register task_t         task,
	int                     flavor,
	thread_state_t          new_state,
	mach_msg_type_number_t  new_state_count,
	thread_t				*new_thread)
{
	return thread_create_running_internal2(
		task, flavor, new_state, new_state_count,
		new_thread, TRUE);
}

kern_return_t
thread_create_workq(
	task_t				task,
	thread_continue_t		thread_return,
	thread_t			*new_thread)
{
	kern_return_t		result;
	thread_t			thread;

	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	result = thread_create_internal(task, -1, thread_return, TH_OPTION_NOCRED | TH_OPTION_NOSUSP, &thread);
	if (result != KERN_SUCCESS)
		return (result);

	thread->user_stop_count = 1;
	thread_hold(thread);
	if (task->suspend_count > 0)
		thread_hold(thread);

	task_unlock(task);
	lck_mtx_unlock(&tasks_threads_lock);
	
	*new_thread = thread;

	return (KERN_SUCCESS);
}

/*
 *	kernel_thread_create:
 *
 *	Create a thread in the kernel task
 *	to execute in kernel context.
 */
kern_return_t
kernel_thread_create(
	thread_continue_t	continuation,
	void				*parameter,
	integer_t			priority,
	thread_t			*new_thread)
{
	kern_return_t		result;
	thread_t			thread;
	task_t				task = kernel_task;

	result = thread_create_internal(task, priority, continuation, TH_OPTION_NONE, &thread);
	if (result != KERN_SUCCESS)
		return (result);

	task_unlock(task);
	lck_mtx_unlock(&tasks_threads_lock);

	stack_alloc(thread);
	assert(thread->kernel_stack != 0);
	thread->reserved_stack = thread->kernel_stack;

	thread->parameter = parameter;

if(debug_task & 1)
	kprintf("kernel_thread_create: thread = %p continuation = %p\n", thread, continuation);
	*new_thread = thread;

	return (result);
}

kern_return_t
kernel_thread_start_priority(
	thread_continue_t	continuation,
	void				*parameter,
	integer_t			priority,
	thread_t			*new_thread)
{
	kern_return_t	result;
	thread_t		thread;

	result = kernel_thread_create(continuation, parameter, priority, &thread);
	if (result != KERN_SUCCESS)
		return (result);

	*new_thread = thread;	

	thread_mtx_lock(thread);
	thread_start_internal(thread);
	thread_mtx_unlock(thread);

	return (result);
}

kern_return_t
kernel_thread_start(
	thread_continue_t	continuation,
	void				*parameter,
	thread_t			*new_thread)
{
	return kernel_thread_start_priority(continuation, parameter, -1, new_thread);
}


kern_return_t
thread_info_internal(
	register thread_t		thread,
	thread_flavor_t			flavor,
	thread_info_t			thread_info_out,	/* ptr to OUT array */
	mach_msg_type_number_t	*thread_info_count)	/*IN/OUT*/
{
	int						state, flags;
	spl_t					s;

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	if (flavor == THREAD_BASIC_INFO) {
	    register thread_basic_info_t	basic_info;

	    if (*thread_info_count < THREAD_BASIC_INFO_COUNT)
			return (KERN_INVALID_ARGUMENT);

	    basic_info = (thread_basic_info_t) thread_info_out;

	    s = splsched();
	    thread_lock(thread);

	    /* fill in info */

	    thread_read_times(thread, &basic_info->user_time,
									&basic_info->system_time);

		/*
		 *	Update lazy-evaluated scheduler info because someone wants it.
		 */
		if (SCHED(can_update_priority)(thread))
			SCHED(update_priority)(thread);

		basic_info->sleep_time = 0;

		/*
		 *	To calculate cpu_usage, first correct for timer rate,
		 *	then for 5/8 ageing.  The correction factor [3/5] is
		 *	(1/(5/8) - 1).
		 */
		basic_info->cpu_usage = 0;
#if defined(CONFIG_SCHED_TRADITIONAL)
		if (sched_tick_interval) {
			basic_info->cpu_usage =	(integer_t)(((uint64_t)thread->cpu_usage
										* TH_USAGE_SCALE) /	sched_tick_interval);
			basic_info->cpu_usage = (basic_info->cpu_usage * 3) / 5;
		}
#endif
		
		if (basic_info->cpu_usage > TH_USAGE_SCALE)
			basic_info->cpu_usage = TH_USAGE_SCALE;

		basic_info->policy = ((thread->sched_mode == TH_MODE_TIMESHARE)?
												POLICY_TIMESHARE: POLICY_RR);

	    flags = 0;
		if (thread->options & TH_OPT_IDLE_THREAD)
			flags |= TH_FLAGS_IDLE;

	    if (!thread->kernel_stack)
			flags |= TH_FLAGS_SWAPPED;

	    state = 0;
	    if (thread->state & TH_TERMINATE)
			state = TH_STATE_HALTED;
	    else
		if (thread->state & TH_RUN)
			state = TH_STATE_RUNNING;
	    else
		if (thread->state & TH_UNINT)
			state = TH_STATE_UNINTERRUPTIBLE;
	    else
		if (thread->state & TH_SUSP)
			state = TH_STATE_STOPPED;
	    else
		if (thread->state & TH_WAIT)
			state = TH_STATE_WAITING;

	    basic_info->run_state = state;
	    basic_info->flags = flags;

	    basic_info->suspend_count = thread->user_stop_count;

	    thread_unlock(thread);
	    splx(s);

	    *thread_info_count = THREAD_BASIC_INFO_COUNT;

	    return (KERN_SUCCESS);
	}
	else
	if (flavor == THREAD_IDENTIFIER_INFO) {
	    register thread_identifier_info_t	identifier_info;

	    if (*thread_info_count < THREAD_IDENTIFIER_INFO_COUNT)
			return (KERN_INVALID_ARGUMENT);

	    identifier_info = (thread_identifier_info_t) thread_info_out;

	    s = splsched();
	    thread_lock(thread);

	    identifier_info->thread_id = thread->thread_id;
	    identifier_info->thread_handle = thread->machine.cthread_self;
	    if(thread->task->bsd_info) {
	    	identifier_info->dispatch_qaddr =  identifier_info->thread_handle + get_dispatchqueue_offset_from_proc(thread->task->bsd_info);
	    } else {
		    thread_unlock(thread);
		    splx(s);
		    return KERN_INVALID_ARGUMENT;
	    }

	    thread_unlock(thread);
	    splx(s);
	    return KERN_SUCCESS;
	}
	else
	if (flavor == THREAD_SCHED_TIMESHARE_INFO) {
		policy_timeshare_info_t		ts_info;

		if (*thread_info_count < POLICY_TIMESHARE_INFO_COUNT)
			return (KERN_INVALID_ARGUMENT);

		ts_info = (policy_timeshare_info_t)thread_info_out;

	    s = splsched();
		thread_lock(thread);

	    if (thread->sched_mode != TH_MODE_TIMESHARE) {
	    	thread_unlock(thread);
			splx(s);

			return (KERN_INVALID_POLICY);
	    }

		ts_info->depressed = (thread->sched_flags & TH_SFLAG_DEPRESSED_MASK) != 0;
		if (ts_info->depressed) {
			ts_info->base_priority = DEPRESSPRI;
			ts_info->depress_priority = thread->priority;
		}
		else {
			ts_info->base_priority = thread->priority;
			ts_info->depress_priority = -1;
		}

		ts_info->cur_priority = thread->sched_pri;
		ts_info->max_priority =	thread->max_priority;

		thread_unlock(thread);
	    splx(s);

		*thread_info_count = POLICY_TIMESHARE_INFO_COUNT;

		return (KERN_SUCCESS);	
	}
	else
	if (flavor == THREAD_SCHED_FIFO_INFO) {
		if (*thread_info_count < POLICY_FIFO_INFO_COUNT)
			return (KERN_INVALID_ARGUMENT);

		return (KERN_INVALID_POLICY);
	}
	else
	if (flavor == THREAD_SCHED_RR_INFO) {
		policy_rr_info_t			rr_info;
		uint32_t quantum_time;
		uint64_t quantum_ns;
		
		if (*thread_info_count < POLICY_RR_INFO_COUNT)
			return (KERN_INVALID_ARGUMENT);

		rr_info = (policy_rr_info_t) thread_info_out;

	    s = splsched();
		thread_lock(thread);

	    if (thread->sched_mode == TH_MODE_TIMESHARE) {
	    	thread_unlock(thread);
			splx(s);

			return (KERN_INVALID_POLICY);
	    }

		rr_info->depressed = (thread->sched_flags & TH_SFLAG_DEPRESSED_MASK) != 0;
		if (rr_info->depressed) {
			rr_info->base_priority = DEPRESSPRI;
			rr_info->depress_priority = thread->priority;
		}
		else {
			rr_info->base_priority = thread->priority;
			rr_info->depress_priority = -1;
		}

		quantum_time = SCHED(initial_quantum_size)(THREAD_NULL);
		absolutetime_to_nanoseconds(quantum_time, &quantum_ns);
		
		rr_info->max_priority = thread->max_priority;
	    rr_info->quantum = (uint32_t)(quantum_ns / 1000 / 1000);

		thread_unlock(thread);
	    splx(s);

		*thread_info_count = POLICY_RR_INFO_COUNT;

		return (KERN_SUCCESS);	
	}

	return (KERN_INVALID_ARGUMENT);
}

void
thread_read_times(
	thread_t		thread,
	time_value_t	*user_time,
	time_value_t	*system_time)
{
	clock_sec_t		secs;
	clock_usec_t	usecs;
	uint64_t		tval_user, tval_system;

	tval_user = timer_grab(&thread->user_timer);
	tval_system = timer_grab(&thread->system_timer);

	if (thread->precise_user_kernel_time) {
		absolutetime_to_microtime(tval_user, &secs, &usecs);
		user_time->seconds = (typeof(user_time->seconds))secs;
		user_time->microseconds = usecs;
		
		absolutetime_to_microtime(tval_system, &secs, &usecs);
		system_time->seconds = (typeof(system_time->seconds))secs;
		system_time->microseconds = usecs;
	} else {
		/* system_timer may represent either sys or user */
		tval_user += tval_system;
		absolutetime_to_microtime(tval_user, &secs, &usecs);
		user_time->seconds = (typeof(user_time->seconds))secs;
		user_time->microseconds = usecs;

		system_time->seconds = 0;
		system_time->microseconds = 0;
	}
}

kern_return_t
thread_assign(
	__unused thread_t			thread,
	__unused processor_set_t	new_pset)
{
	return (KERN_FAILURE);
}

/*
 *	thread_assign_default:
 *
 *	Special version of thread_assign for assigning threads to default
 *	processor set.
 */
kern_return_t
thread_assign_default(
	thread_t		thread)
{
	return (thread_assign(thread, &pset0));
}

/*
 *	thread_get_assignment
 *
 *	Return current assignment for this thread.
 */	    
kern_return_t
thread_get_assignment(
	thread_t		thread,
	processor_set_t	*pset)
{
	if (thread == NULL)
		return (KERN_INVALID_ARGUMENT);

	*pset = &pset0;

	return (KERN_SUCCESS);
}

/*
 *	thread_wire_internal:
 *
 *	Specify that the target thread must always be able
 *	to run and to allocate memory.
 */
kern_return_t
thread_wire_internal(
	host_priv_t		host_priv,
	thread_t		thread,
	boolean_t		wired,
	boolean_t		*prev_state)
{
	if (host_priv == NULL || thread != current_thread())
		return (KERN_INVALID_ARGUMENT);

	assert(host_priv == &realhost);

	if (prev_state)
	    *prev_state = (thread->options & TH_OPT_VMPRIV) != 0;
	
	if (wired) {
	    if (!(thread->options & TH_OPT_VMPRIV)) 
		    vm_page_free_reserve(1);	/* XXX */
	    thread->options |= TH_OPT_VMPRIV;
	}
	else {
	    if (thread->options & TH_OPT_VMPRIV) 
		    vm_page_free_reserve(-1);	/* XXX */
	    thread->options &= ~TH_OPT_VMPRIV;
	}

	return (KERN_SUCCESS);
}


/*
 *	thread_wire:
 *
 *	User-api wrapper for thread_wire_internal()
 */
kern_return_t
thread_wire(
	host_priv_t	host_priv,
	thread_t	thread,
	boolean_t	wired)
{
    return (thread_wire_internal(host_priv, thread, wired, NULL));
}


/*
 * XXX assuming current thread only, for now...
 */
void
thread_guard_violation(thread_t thread, unsigned type)
{
	assert(thread == current_thread());

	spl_t s = splsched();
	/*
	 * Use the saved state area of the thread structure
	 * to store all info required to handle the AST when
	 * returning to userspace
	 */
	thread->guard_exc_info.type = type;
	thread_ast_set(thread, AST_GUARD);
	ast_propagate(thread->ast);

	splx(s);
}

/*
 *	guard_ast:
 *
 *	Handle AST_GUARD for a thread. This routine looks at the
 *	state saved in the thread structure to determine the cause
 *	of this exception. Based on this value, it invokes the 
 *	appropriate routine which determines other exception related
 *	info and raises the exception.
 */
void
guard_ast(thread_t thread)
{
	if (thread->guard_exc_info.type == GUARD_TYPE_MACH_PORT)
		mach_port_guard_ast(thread);
	else
		fd_guard_ast(thread);
}

static void
thread_cputime_callback(int warning, __unused const void *arg0, __unused const void *arg1)
{
	if (warning == LEDGER_WARNING_ROSE_ABOVE) {
#if CONFIG_TELEMETRY		
		/*
		 * This thread is in danger of violating the CPU usage monitor. Enable telemetry
		 * on the entire task so there are micro-stackshots available if and when
		 * EXC_RESOURCE is triggered. We could have chosen to enable micro-stackshots
		 * for this thread only; but now that this task is suspect, knowing what all of
		 * its threads are up to will be useful.
		 */
		telemetry_task_ctl(current_task(), TF_CPUMON_WARNING, 1);
#endif
		return;
	}

#if CONFIG_TELEMETRY
	/*
	 * If the balance has dipped below the warning level (LEDGER_WARNING_DIPPED_BELOW) or
	 * exceeded the limit, turn telemetry off for the task.
	 */
	telemetry_task_ctl(current_task(), TF_CPUMON_WARNING, 0);
#endif

	if (warning == 0) {
		THIS_THREAD_IS_CONSUMING_TOO_MUCH_CPU__SENDING_EXC_RESOURCE();
	}
}

void __attribute__((noinline))
THIS_THREAD_IS_CONSUMING_TOO_MUCH_CPU__SENDING_EXC_RESOURCE(void)
{
	int          pid                = 0;
	task_t		 task				= current_task();
	thread_t     thread             = current_thread();
	uint64_t     tid                = thread->thread_id;
	char         *procname          = (char *) "unknown";
	time_value_t thread_total_time  = {0, 0};
	time_value_t thread_system_time;
	time_value_t thread_user_time;
	int          action;
	uint8_t      percentage;
	uint32_t     limit_percent;
	uint32_t     usage_percent;
	uint32_t     interval_sec;
	uint64_t     interval_ns;
	uint64_t     balance_ns;
	boolean_t	 fatal = FALSE;

	mach_exception_data_type_t	code[EXCEPTION_CODE_MAX];
	struct ledger_entry_info	lei;

	assert(thread->t_threadledger != LEDGER_NULL);

	/*
	 * Now that a thread has tripped the monitor, disable it for the entire task.
	 */
	task_lock(task);
	if ((task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_PERTHR_LIMIT) == 0) {
		/*
		 * The CPU usage monitor has been disabled on our task, so some other
		 * thread must have gotten here first. We only send one exception per
		 * task lifetime, so there's nothing left for us to do here.
		 */
		task_unlock(task);
		return;
	}
	if (task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_FATAL_CPUMON) {
		fatal = TRUE;
	}
	task_disable_cpumon(task);
	task_unlock(task);

#ifdef MACH_BSD
	pid = proc_selfpid();
	if (task->bsd_info != NULL)
		procname = proc_name_address(task->bsd_info);
#endif

	thread_get_cpulimit(&action, &percentage, &interval_ns);

	interval_sec = (uint32_t)(interval_ns / NSEC_PER_SEC);

	thread_read_times(thread, &thread_user_time, &thread_system_time);
	time_value_add(&thread_total_time, &thread_user_time);
	time_value_add(&thread_total_time, &thread_system_time);

	ledger_get_entry_info(thread->t_threadledger, thread_ledgers.cpu_time, &lei);

	absolutetime_to_nanoseconds(lei.lei_balance, &balance_ns);
	usage_percent = (uint32_t) ((balance_ns * 100ULL) / lei.lei_last_refill);

	/* Show refill period in the same units as balance, limit, etc */
	nanoseconds_to_absolutetime(lei.lei_refill_period, &lei.lei_refill_period);

	limit_percent = (uint32_t) ((lei.lei_limit * 100ULL) / lei.lei_refill_period);

	/*  TODO: show task total runtime as well? see TASK_ABSOLUTETIME_INFO */

	if (disable_exc_resource) {
		printf("process %s[%d] thread %llu caught burning CPU!; EXC_RESOURCE "
			"supressed by a boot-arg\n", procname, pid, tid);
		return;
	}

	printf("process %s[%d] thread %llu caught burning CPU! "
	       "It used more than %d%% CPU (Actual recent usage: %d%%) over %d seconds. "
	       "thread lifetime cpu usage %d.%06d seconds, (%d.%06d user, %d.%06d system) "
	       "ledger info: balance: %lld credit: %lld debit: %lld limit: %llu (%d%%) "
	       "period: %llu time since last refill (ns): %llu \n",
	       procname, pid, tid,
	       percentage, usage_percent,  interval_sec,
	       thread_total_time.seconds,  thread_total_time.microseconds,
	       thread_user_time.seconds,   thread_user_time.microseconds,
	       thread_system_time.seconds, thread_system_time.microseconds,
	       lei.lei_balance,
	       lei.lei_credit,             lei.lei_debit,
	       lei.lei_limit,              limit_percent,
	       lei.lei_refill_period,      lei.lei_last_refill);


	code[0] = code[1] = 0;
	EXC_RESOURCE_ENCODE_TYPE(code[0], RESOURCE_TYPE_CPU);
	EXC_RESOURCE_ENCODE_FLAVOR(code[0], FLAVOR_CPU_MONITOR);
	EXC_RESOURCE_CPUMONITOR_ENCODE_INTERVAL(code[0], interval_sec);
	EXC_RESOURCE_CPUMONITOR_ENCODE_PERCENTAGE(code[0], limit_percent);
	EXC_RESOURCE_CPUMONITOR_ENCODE_PERCENTAGE(code[1], usage_percent);
	exception_triage(EXC_RESOURCE, code, EXCEPTION_CODE_MAX);

	if (fatal) {
		task_terminate_internal(task);
	}
}

void
init_thread_ledgers(void) {
	ledger_template_t t;
	int idx;
	
	assert(thread_ledger_template == NULL);

	if ((t = ledger_template_create("Per-thread ledger")) == NULL)
		panic("couldn't create thread ledger template");

	if ((idx = ledger_entry_add(t, "cpu_time", "sched", "ns")) < 0) {
		panic("couldn't create cpu_time entry for thread ledger template");
	}

	if (ledger_set_callback(t, idx, thread_cputime_callback, NULL, NULL) < 0) {
	    	panic("couldn't set thread ledger callback for cpu_time entry");
	}

	thread_ledgers.cpu_time = idx;
	thread_ledger_template = t;
}

/*
 * Returns currently applied CPU usage limit, or 0/0 if none is applied.
 */
int
thread_get_cpulimit(int *action, uint8_t *percentage, uint64_t *interval_ns)
{
	int64_t		abstime = 0;
	uint64_t 	limittime = 0;
	thread_t	thread = current_thread();

	*percentage  = 0;
	*interval_ns = 0;
	*action      = 0;

	if (thread->t_threadledger == LEDGER_NULL) {
		/*
		 * This thread has no per-thread ledger, so it can't possibly
		 * have a CPU limit applied.
		 */
		return (KERN_SUCCESS);
	}

	ledger_get_period(thread->t_threadledger, thread_ledgers.cpu_time, interval_ns);
	ledger_get_limit(thread->t_threadledger, thread_ledgers.cpu_time, &abstime);

	if ((abstime == LEDGER_LIMIT_INFINITY) || (*interval_ns == 0)) {
		/*
		 * This thread's CPU time ledger has no period or limit; so it
		 * doesn't have a CPU limit applied.
		 */
		 return (KERN_SUCCESS);
	}

	/*
	 * This calculation is the converse to the one in thread_set_cpulimit().
	 */
	absolutetime_to_nanoseconds(abstime, &limittime);
	*percentage = (limittime * 100ULL) / *interval_ns;
	assert(*percentage <= 100);

	if (thread->options & TH_OPT_PROC_CPULIMIT) {
		assert((thread->options & TH_OPT_PRVT_CPULIMIT) == 0);

		*action = THREAD_CPULIMIT_BLOCK;
	} else if (thread->options & TH_OPT_PRVT_CPULIMIT) {
		assert((thread->options & TH_OPT_PROC_CPULIMIT) == 0);

		*action = THREAD_CPULIMIT_EXCEPTION;
	} else {
		*action = THREAD_CPULIMIT_DISABLE;
	}

	return (KERN_SUCCESS);
}

/*
 * Set CPU usage limit on a thread.
 *
 * Calling with percentage of 0 will unset the limit for this thread.
 */
int
thread_set_cpulimit(int action, uint8_t percentage, uint64_t interval_ns)
{
	thread_t	thread = current_thread(); 
	ledger_t	l;
	uint64_t 	limittime = 0;
	uint64_t	abstime = 0;

	assert(percentage <= 100);

	if (action == THREAD_CPULIMIT_DISABLE) {
		/*
		 * Remove CPU limit, if any exists.
		 */
		if (thread->t_threadledger != LEDGER_NULL) {
			l = thread->t_threadledger;
			/*
			 * The only way to get a per-thread ledger is via CPU limits.
			 */
			assert(thread->options & (TH_OPT_PROC_CPULIMIT | TH_OPT_PRVT_CPULIMIT));
			thread->t_threadledger = NULL;
			ledger_dereference(l);
			thread->options &= ~(TH_OPT_PROC_CPULIMIT | TH_OPT_PRVT_CPULIMIT);
		}

		return (0);
	}

	if (interval_ns < MINIMUM_CPULIMIT_INTERVAL_MS * NSEC_PER_MSEC) {
		return (KERN_INVALID_ARGUMENT);
	}

 	l = thread->t_threadledger;
	if (l == LEDGER_NULL) {
		/*
		 * This thread doesn't yet have a per-thread ledger; so create one with the CPU time entry active.
		 */
		if ((l = ledger_instantiate(thread_ledger_template, LEDGER_CREATE_INACTIVE_ENTRIES)) == LEDGER_NULL)
			return (KERN_RESOURCE_SHORTAGE);

		/*
		 * We are the first to create this thread's ledger, so only activate our entry.
		 */
		ledger_entry_setactive(l, thread_ledgers.cpu_time);
		thread->t_threadledger = l;
	}

	/*
	 * The limit is specified as a percentage of CPU over an interval in nanoseconds.
	 * Calculate the amount of CPU time that the thread needs to consume in order to hit the limit.
	 */
	limittime = (interval_ns * percentage) / 100;
	nanoseconds_to_absolutetime(limittime, &abstime); 
	ledger_set_limit(l, thread_ledgers.cpu_time, abstime, cpumon_ustackshots_trigger_pct);
	/*
	 * Refill the thread's allotted CPU time every interval_ns nanoseconds.
	 */
	ledger_set_period(l, thread_ledgers.cpu_time, interval_ns);

	if (action == THREAD_CPULIMIT_EXCEPTION) {
		/*
		 * We don't support programming the CPU usage monitor on a task if any of its
		 * threads have a per-thread blocking CPU limit configured.
		 */
		if (thread->options & TH_OPT_PRVT_CPULIMIT) {
			panic("CPU usage monitor activated, but blocking thread limit exists");
		}

		/*
		 * Make a note that this thread's CPU limit is being used for the task-wide CPU
		 * usage monitor. We don't have to arm the callback which will trigger the
		 * exception, because that was done for us in ledger_instantiate (because the
		 * ledger template used has a default callback).
		 */
		thread->options |= TH_OPT_PROC_CPULIMIT;
	} else {
		/*
		 * We deliberately override any CPU limit imposed by a task-wide limit (eg
		 * CPU usage monitor).
		 */
		thread->options &= ~TH_OPT_PROC_CPULIMIT;		

		thread->options |= TH_OPT_PRVT_CPULIMIT;
		/* The per-thread ledger template by default has a callback for CPU time */
		ledger_disable_callback(l, thread_ledgers.cpu_time);
		ledger_set_action(l, thread_ledgers.cpu_time, LEDGER_ACTION_BLOCK);
	}

	return (0);
}

int		split_funnel_off = 0;
lck_grp_t	*funnel_lck_grp = LCK_GRP_NULL;
lck_grp_attr_t	*funnel_lck_grp_attr;
lck_attr_t	*funnel_lck_attr;

funnel_t *
funnel_alloc(
	int type)
{
	lck_mtx_t	*m;
	funnel_t	*fnl;

	if (funnel_lck_grp == LCK_GRP_NULL) {
		funnel_lck_grp_attr = lck_grp_attr_alloc_init();

		funnel_lck_grp = lck_grp_alloc_init("Funnel",  funnel_lck_grp_attr);

		funnel_lck_attr = lck_attr_alloc_init();
	}
	if ((fnl = (funnel_t *)kalloc(sizeof(funnel_t))) != 0){
		bzero((void *)fnl, sizeof(funnel_t));
		if ((m = lck_mtx_alloc_init(funnel_lck_grp, funnel_lck_attr)) == (lck_mtx_t *)NULL) {
			kfree(fnl, sizeof(funnel_t));
			return(THR_FUNNEL_NULL);
		}
		fnl->fnl_mutex = m;
		fnl->fnl_type = type;
	}
	return(fnl);
}

void 
funnel_free(
	funnel_t * fnl)
{
	lck_mtx_free(fnl->fnl_mutex, funnel_lck_grp);
	if (fnl->fnl_oldmutex)
		lck_mtx_free(fnl->fnl_oldmutex, funnel_lck_grp);
	kfree(fnl, sizeof(funnel_t));
}

void 
funnel_lock(
	funnel_t * fnl)
{
	lck_mtx_lock(fnl->fnl_mutex);
	fnl->fnl_mtxholder = current_thread();
}

void 
funnel_unlock(
	funnel_t * fnl)
{
	lck_mtx_unlock(fnl->fnl_mutex);
	fnl->fnl_mtxholder = NULL;
	fnl->fnl_mtxrelease = current_thread();
}

funnel_t *
thread_funnel_get(
	void)
{
	thread_t th = current_thread();

	if (th->funnel_state & TH_FN_OWNED) {
		return(th->funnel_lock);
	}
	return(THR_FUNNEL_NULL);
}

boolean_t
thread_funnel_set(
        funnel_t *	fnl,
	boolean_t	funneled)
{
	thread_t	cur_thread;
	boolean_t	funnel_state_prev;
	boolean_t	intr;
        
	cur_thread = current_thread();
	funnel_state_prev = ((cur_thread->funnel_state & TH_FN_OWNED) == TH_FN_OWNED);

	if (funnel_state_prev != funneled) {
		intr = ml_set_interrupts_enabled(FALSE);

		if (funneled == TRUE) {
			if (cur_thread->funnel_lock)
				panic("Funnel lock called when holding one %p", cur_thread->funnel_lock);
			KERNEL_DEBUG(0x6032428 | DBG_FUNC_NONE,
											fnl, 1, 0, 0, 0);
			funnel_lock(fnl);
			KERNEL_DEBUG(0x6032434 | DBG_FUNC_NONE,
											fnl, 1, 0, 0, 0);
			cur_thread->funnel_state |= TH_FN_OWNED;
			cur_thread->funnel_lock = fnl;
		} else {
			if(cur_thread->funnel_lock->fnl_mutex != fnl->fnl_mutex)
				panic("Funnel unlock  when not holding funnel");
			cur_thread->funnel_state &= ~TH_FN_OWNED;
			KERNEL_DEBUG(0x603242c | DBG_FUNC_NONE,
								fnl, 1, 0, 0, 0);

			cur_thread->funnel_lock = THR_FUNNEL_NULL;
			funnel_unlock(fnl);
		}
		(void)ml_set_interrupts_enabled(intr);
	} else {
		/* if we are trying to acquire funnel recursively
		 * check for funnel to be held already
		 */
		if (funneled && (fnl->fnl_mutex != cur_thread->funnel_lock->fnl_mutex)) {
				panic("thread_funnel_set: already holding a different funnel");
		}
	}
	return(funnel_state_prev);
}

static void
sched_call_null(
__unused	int			type,
__unused	thread_t	thread)
{
	return;
}

void
thread_sched_call(
	thread_t		thread,
	sched_call_t	call)
{
	thread->sched_call = (call != NULL)? call: sched_call_null;
}

void
thread_static_param(
	thread_t		thread,
	boolean_t		state)
{
	thread_mtx_lock(thread);
	thread->static_param = state;
	thread_mtx_unlock(thread);
}

uint64_t
thread_tid(
	thread_t	thread)
{
	return (thread != THREAD_NULL? thread->thread_id: 0);
}

uint16_t	thread_set_tag(thread_t th, uint16_t tag) {
	return thread_set_tag_internal(th, tag);
}
uint16_t	thread_get_tag(thread_t th) {
	return thread_get_tag_internal(th);
}

uint64_t
thread_dispatchqaddr(
	thread_t		thread)
{
	uint64_t	dispatchqueue_addr = 0;
	uint64_t	thread_handle = 0;

	if (thread != THREAD_NULL) {
		thread_handle = thread->machine.cthread_self;

		if (thread->task->bsd_info)
			dispatchqueue_addr = thread_handle + get_dispatchqueue_offset_from_proc(thread->task->bsd_info);
	}

	return (dispatchqueue_addr);
}

/*
 * Export routines to other components for things that are done as macros
 * within the osfmk component.
 */

#undef thread_reference
void thread_reference(thread_t thread);
void
thread_reference(
	thread_t	thread)
{
	if (thread != THREAD_NULL)
		thread_reference_internal(thread);
}

#undef thread_should_halt

boolean_t
thread_should_halt(
	thread_t		th)
{
	return (thread_should_halt_fast(th));
}

#if CONFIG_DTRACE
uint32_t dtrace_get_thread_predcache(thread_t thread)
{
	if (thread != THREAD_NULL)
		return thread->t_dtrace_predcache;
	else
		return 0;
}

int64_t dtrace_get_thread_vtime(thread_t thread)
{
	if (thread != THREAD_NULL)
		return thread->t_dtrace_vtime;
	else
		return 0;
}

int64_t dtrace_get_thread_tracing(thread_t thread)
{
	if (thread != THREAD_NULL)
		return thread->t_dtrace_tracing;
	else
		return 0;
}

boolean_t dtrace_get_thread_reentering(thread_t thread)
{
	if (thread != THREAD_NULL)
		return (thread->options & TH_OPT_DTRACE) ? TRUE : FALSE;
	else
		return 0;
}

vm_offset_t dtrace_get_kernel_stack(thread_t thread)
{
	if (thread != THREAD_NULL)
		return thread->kernel_stack;
	else
		return 0;
}

int64_t dtrace_calc_thread_recent_vtime(thread_t thread)
{
	if (thread != THREAD_NULL) {
		processor_t             processor = current_processor();
		uint64_t 				abstime = mach_absolute_time();
		timer_t					timer;

		timer = PROCESSOR_DATA(processor, thread_timer);

		return timer_grab(&(thread->system_timer)) + timer_grab(&(thread->user_timer)) +
				(abstime - timer->tstamp); /* XXX need interrupts off to prevent missed time? */
	} else
		return 0;
}

void dtrace_set_thread_predcache(thread_t thread, uint32_t predcache)
{
	if (thread != THREAD_NULL)
		thread->t_dtrace_predcache = predcache;
}

void dtrace_set_thread_vtime(thread_t thread, int64_t vtime)
{
	if (thread != THREAD_NULL)
		thread->t_dtrace_vtime = vtime;
}

void dtrace_set_thread_tracing(thread_t thread, int64_t accum)
{
	if (thread != THREAD_NULL)
		thread->t_dtrace_tracing = accum;
}

void dtrace_set_thread_reentering(thread_t thread, boolean_t vbool)
{
	if (thread != THREAD_NULL) {
		if (vbool)
			thread->options |= TH_OPT_DTRACE;
		else
			thread->options &= (~TH_OPT_DTRACE);
	}
}

vm_offset_t dtrace_set_thread_recover(thread_t thread, vm_offset_t recover)
{
	vm_offset_t prev = 0;

	if (thread != THREAD_NULL) {
		prev = thread->recover;
		thread->recover = recover;
	}
	return prev;
}

void dtrace_thread_bootstrap(void)
{
	task_t task = current_task();

	if (task->thread_count == 1) {
		thread_t thread = current_thread();
		if (thread->t_dtrace_flags & TH_DTRACE_EXECSUCCESS) {
			thread->t_dtrace_flags &= ~TH_DTRACE_EXECSUCCESS;
			DTRACE_PROC(exec__success);
		}
		DTRACE_PROC(start);
	}
	DTRACE_PROC(lwp__start);

}

void
dtrace_thread_didexec(thread_t thread)
{
	thread->t_dtrace_flags |= TH_DTRACE_EXECSUCCESS;
}
#endif /* CONFIG_DTRACE */
