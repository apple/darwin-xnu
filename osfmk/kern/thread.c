/*
 * Copyright (c) 2000-2015 Apple Inc. All rights reserved.
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
#include <kern/thread_group.h>
#include <kern/coalition.h>
#include <kern/host.h>
#include <kern/zalloc.h>
#include <kern/assert.h>
#include <kern/exc_resource.h>
#include <kern/exc_guard.h>
#include <kern/telemetry.h>
#include <kern/policy_internal.h>
#include <kern/turnstile.h>

#include <corpses/task_corpse.h>
#if KPC
#include <kern/kpc.h>
#endif

#if MONOTONIC
#include <kern/monotonic.h>
#include <machine/monotonic.h>
#endif /* MONOTONIC */

#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_port.h>
#include <bank/bank_types.h>

#include <vm/vm_kern.h>
#include <vm/vm_pageout.h>

#include <sys/kdebug.h>
#include <sys/bsdtask_info.h>
#include <mach/sdt.h>
#include <san/kasan.h>

#include <stdatomic.h>

/*
 * Exported interfaces
 */
#include <mach/task_server.h>
#include <mach/thread_act_server.h>
#include <mach/mach_host_server.h>
#include <mach/host_priv_server.h>
#include <mach/mach_voucher_server.h>
#include <kern/policy_internal.h>

static struct zone			*thread_zone;
static lck_grp_attr_t		thread_lck_grp_attr;
lck_attr_t					thread_lck_attr;
lck_grp_t					thread_lck_grp;

struct zone					*thread_qos_override_zone;

decl_simple_lock_data(static,thread_stack_lock)
static queue_head_t		thread_stack_queue;

decl_simple_lock_data(static,thread_terminate_lock)
static queue_head_t		thread_terminate_queue;

static queue_head_t		thread_deallocate_queue;

static queue_head_t		turnstile_deallocate_queue;

static queue_head_t		crashed_threads_queue;

static queue_head_t		workq_deallocate_queue;

decl_simple_lock_data(static,thread_exception_lock)
static queue_head_t		thread_exception_queue;

struct thread_exception_elt {
	queue_chain_t		elt;
	exception_type_t	exception_type;
	task_t			exception_task;
	thread_t		exception_thread;
};

static struct thread	thread_template, init_thread;
static void thread_deallocate_enqueue(thread_t thread);
static void thread_deallocate_complete(thread_t thread);

#ifdef MACH_BSD
extern void proc_exit(void *);
extern mach_exception_data_type_t proc_encode_exit_exception_code(void *);
extern uint64_t get_dispatchqueue_offset_from_proc(void *);
extern uint64_t get_return_to_kernel_offset_from_proc(void *p);
extern int      proc_selfpid(void);
extern void     proc_name(int, char*, int);
extern char *   proc_name_address(void *p);
#endif /* MACH_BSD */

extern int disable_exc_resource;
extern int audio_active;
extern int debug_task;
int thread_max = CONFIG_THREAD_MAX;	/* Max number of threads */
int task_threadmax = CONFIG_THREAD_MAX;

static uint64_t		thread_unique_id = 100;

struct _thread_ledger_indices thread_ledgers = { -1 };
static ledger_template_t thread_ledger_template = NULL;
static void init_thread_ledgers(void);

#if CONFIG_JETSAM
void jetsam_on_ledger_cpulimit_exceeded(void);
#endif

extern int task_thread_soft_limit;
extern int exc_via_corpse_forking;

#if DEVELOPMENT || DEBUG
extern int exc_resource_threads_enabled;
#endif /* DEVELOPMENT || DEBUG */

/*
 * Level (in terms of percentage of the limit) at which the CPU usage monitor triggers telemetry.
 *
 * (ie when any thread's CPU consumption exceeds 70% of the limit, start taking user
 *  stacktraces, aka micro-stackshots)
 */
#define	CPUMON_USTACKSHOTS_TRIGGER_DEFAULT_PCT 70

int cpumon_ustackshots_trigger_pct; /* Percentage. Level at which we start gathering telemetry. */
void __attribute__((noinline)) SENDING_NOTIFICATION__THIS_THREAD_IS_CONSUMING_TOO_MUCH_CPU(void);
#if DEVELOPMENT || DEBUG
void __attribute__((noinline)) SENDING_NOTIFICATION__TASK_HAS_TOO_MANY_THREADS(task_t, int);
#endif /* DEVELOPMENT || DEBUG */

/*
 * The smallest interval over which we support limiting CPU consumption is 1ms
 */
#define MINIMUM_CPULIMIT_INTERVAL_MS 1

os_refgrp_decl(static, thread_refgrp, "thread", NULL);

void
thread_bootstrap(void)
{
	/*
	 *	Fill in a template thread for fast initialization.
	 */

#if MACH_ASSERT
	thread_template.thread_magic = THREAD_MAGIC;
#endif /* MACH_ASSERT */

	thread_template.runq = PROCESSOR_NULL;

	thread_template.reason = AST_NONE;
	thread_template.at_safe_point = FALSE;
	thread_template.wait_event = NO_EVENT64;
	thread_template.waitq = NULL;
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
	thread_template.th_sched_bucket = TH_BUCKET_RUN;

	thread_template.sfi_class = SFI_CLASS_UNSPECIFIED;
	thread_template.sfi_wait_class = SFI_CLASS_UNSPECIFIED;

	thread_template.active = 0;
	thread_template.started = 0;
	thread_template.static_param = 0;
	thread_template.policy_reset = 0;

	thread_template.base_pri = BASEPRI_DEFAULT;
	thread_template.sched_pri = 0;
	thread_template.max_priority = 0;
	thread_template.task_priority = 0;
	thread_template.promotions = 0;
	thread_template.rwlock_count = 0;
	thread_template.waiting_for_mutex = NULL;


	thread_template.realtime.deadline = UINT64_MAX;

	thread_template.quantum_remaining = 0;
	thread_template.last_run_time = 0;
	thread_template.last_made_runnable_time = THREAD_NOT_RUNNABLE;
	thread_template.last_basepri_change_time = THREAD_NOT_RUNNABLE;
	thread_template.same_pri_latency = 0;

	thread_template.computation_metered = 0;
	thread_template.computation_epoch = 0;

#if defined(CONFIG_SCHED_TIMESHARE_CORE)
	thread_template.sched_stamp = 0;
	thread_template.pri_shift = INT8_MAX;
	thread_template.sched_usage = 0;
	thread_template.cpu_usage = thread_template.cpu_delta = 0;
#endif
	thread_template.c_switch = thread_template.p_switch = thread_template.ps_switch = 0;

#if MONOTONIC
	memset(&thread_template.t_monotonic, 0,
			sizeof(thread_template.t_monotonic));
#endif /* MONOTONIC */

	thread_template.bound_processor = PROCESSOR_NULL;
	thread_template.last_processor = PROCESSOR_NULL;

	thread_template.sched_call = NULL;

	timer_init(&thread_template.user_timer);
	timer_init(&thread_template.system_timer);
	timer_init(&thread_template.ptime);
	timer_init(&thread_template.runnable_timer);
	thread_template.user_timer_save = 0;
	thread_template.system_timer_save = 0;
	thread_template.vtimer_user_save = 0;
	thread_template.vtimer_prof_save = 0;
	thread_template.vtimer_rlim_save = 0;
	thread_template.vtimer_qos_save  = 0;

#if CONFIG_SCHED_SFI
	thread_template.wait_sfi_begin_time = 0;
#endif

	thread_template.wait_timer_is_set = FALSE;
	thread_template.wait_timer_active = 0;

	thread_template.depress_timer_active = 0;

	thread_template.recover = (vm_offset_t)NULL;
	
	thread_template.map = VM_MAP_NULL;
#if DEVELOPMENT || DEBUG
	thread_template.pmap_footprint_suspended = FALSE;
#endif /* DEVELOPMENT || DEBUG */

#if CONFIG_DTRACE
	thread_template.t_dtrace_predcache = 0;
	thread_template.t_dtrace_vtime = 0;
	thread_template.t_dtrace_tracing = 0;
#endif /* CONFIG_DTRACE */

#if KPERF
	thread_template.kperf_flags = 0;
	thread_template.kperf_pet_gen = 0;
	thread_template.kperf_c_switch = 0;
	thread_template.kperf_pet_cnt = 0;
#endif

#if KPC
	thread_template.kpc_buf = NULL;
#endif

#if HYPERVISOR
	thread_template.hv_thread_target = NULL;
#endif /* HYPERVISOR */

#if (DEVELOPMENT || DEBUG)
	thread_template.t_page_creation_throttled_hard = 0;
	thread_template.t_page_creation_throttled_soft = 0;
#endif /* DEVELOPMENT || DEBUG */
	thread_template.t_page_creation_throttled = 0;
	thread_template.t_page_creation_count = 0;
	thread_template.t_page_creation_time = 0;

	thread_template.affinity_set = NULL;
	
	thread_template.syscalls_unix = 0;
	thread_template.syscalls_mach = 0;

	thread_template.t_ledger = LEDGER_NULL;
	thread_template.t_threadledger = LEDGER_NULL;
	thread_template.t_bankledger = LEDGER_NULL;
	thread_template.t_deduct_bank_ledger_time = 0;

	thread_template.requested_policy = (struct thread_requested_policy) {};
	thread_template.effective_policy = (struct thread_effective_policy) {};

	bzero(&thread_template.overrides, sizeof(thread_template.overrides));
	thread_template.sync_ipc_overrides = 0;

	thread_template.iotier_override = THROTTLE_LEVEL_NONE;
	thread_template.thread_io_stats = NULL;
#if CONFIG_EMBEDDED
	thread_template.taskwatch = NULL;
#endif /* CONFIG_EMBEDDED */
	thread_template.thread_callout_interrupt_wakeups = thread_template.thread_callout_platform_idle_wakeups = 0;

	thread_template.thread_timer_wakeups_bin_1 = thread_template.thread_timer_wakeups_bin_2 = 0;
	thread_template.callout_woken_from_icontext = thread_template.callout_woken_from_platform_idle = 0;

	thread_template.thread_tag = 0;

	thread_template.ith_voucher_name = MACH_PORT_NULL;
	thread_template.ith_voucher = IPC_VOUCHER_NULL;

	thread_template.th_work_interval = NULL;

	init_thread = thread_template;

	machine_set_current_thread(&init_thread);
}

extern boolean_t allow_qos_policy_set;

void
thread_init(void)
{
	thread_zone = zinit(
			sizeof(struct thread),
			thread_max * sizeof(struct thread),
			THREAD_CHUNK * sizeof(struct thread),
			"threads");

	thread_qos_override_zone = zinit(
		sizeof(struct thread_qos_override),
		4 * thread_max * sizeof(struct thread_qos_override),
		PAGE_SIZE,
		"thread qos override");
	zone_change(thread_qos_override_zone, Z_EXPAND, TRUE);
	zone_change(thread_qos_override_zone, Z_COLLECT, TRUE);
	zone_change(thread_qos_override_zone, Z_CALLERACCT, FALSE);
	zone_change(thread_qos_override_zone, Z_NOENCRYPT, TRUE);

	lck_grp_attr_setdefault(&thread_lck_grp_attr);
	lck_grp_init(&thread_lck_grp, "thread", &thread_lck_grp_attr);
	lck_attr_setdefault(&thread_lck_attr);

	stack_init();

	thread_policy_init();

	/*
	 *	Initialize any machine-dependent
	 *	per-thread structures necessary.
	 */
	machine_thread_init();

	if (!PE_parse_boot_argn("cpumon_ustackshots_trigger_pct", &cpumon_ustackshots_trigger_pct,
		sizeof (cpumon_ustackshots_trigger_pct))) {
		cpumon_ustackshots_trigger_pct = CPUMON_USTACKSHOTS_TRIGGER_DEFAULT_PCT;
	}

	PE_parse_boot_argn("-qos-policy-allow", &allow_qos_policy_set, sizeof(allow_qos_policy_set));	

	init_thread_ledgers();
}

boolean_t
thread_is_active(thread_t thread)
{
	return (thread->active);
}

void
thread_corpse_continue(void)
{
	thread_t thread = current_thread();

	thread_terminate_internal(thread);

	/*
	 * Handle the thread termination directly
	 * here instead of returning to userspace.
	 */
	assert(thread->active == FALSE);
	thread_ast_clear(thread, AST_APC);
	thread_apc_ast(thread);

	panic("thread_corpse_continue");
	/*NOTREACHED*/
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
	int threadcnt;

	pal_thread_terminate_self(thread);

	DTRACE_PROC(lwp__exit);

	thread_mtx_lock(thread);

	ipc_thread_disable(thread);

	thread_mtx_unlock(thread);

	thread_sched_call(thread, NULL);

	spl_t s = splsched();
	thread_lock(thread);

	thread_depress_abort_locked(thread);

	thread_unlock(thread);
	splx(s);

#if CONFIG_EMBEDDED
	thead_remove_taskwatch(thread);
#endif /* CONFIG_EMBEDDED */

	work_interval_thread_terminate(thread);

	thread_mtx_lock(thread);

	thread_policy_reset(thread);

	thread_mtx_unlock(thread);

	bank_swap_thread_bank_ledger(thread, NULL);

	if (kdebug_enable && bsd_hasthreadname(thread->uthread)) {
		char threadname[MAXTHREADNAMESIZE];
		bsd_getthreadname(thread->uthread, threadname);
		kernel_debug_string_simple(TRACE_STRING_THREADNAME_PREV, threadname);
	}

	task = thread->task;
	uthread_cleanup(task, thread->uthread, task->bsd_info);

	if (kdebug_enable && task->bsd_info && !task_is_exec_copy(task)) {
		/* trace out pid before we sign off */
		long dbg_arg1 = 0;
		long dbg_arg2 = 0;

		kdbg_trace_data(thread->task->bsd_info, &dbg_arg1, &dbg_arg2);
		KDBG_RELEASE(TRACE_DATA_THREAD_TERMINATE_PID, dbg_arg1, dbg_arg2);
	}

	/*
	 * After this subtraction, this thread should never access
	 * task->bsd_info unless it got 0 back from the hw_atomic_sub.  It
	 * could be racing with other threads to be the last thread in the
	 * process, and the last thread in the process will tear down the proc
	 * structure and zero-out task->bsd_info.
	 */
	threadcnt = hw_atomic_sub(&task->active_thread_count, 1);

	/*
	 * If we are the last thread to terminate and the task is
	 * associated with a BSD process, perform BSD process exit.
	 */
	if (threadcnt == 0 && task->bsd_info != NULL && !task_is_exec_copy(task)) {
		mach_exception_data_type_t subcode = 0;
		if (kdebug_enable) {
			/* since we're the last thread in this process, trace out the command name too */
			long args[4] = {};
			kdbg_trace_string(thread->task->bsd_info, &args[0], &args[1], &args[2], &args[3]);
			KDBG_RELEASE(TRACE_STRING_PROC_EXIT, args[0], args[1], args[2], args[3]);
		}

		/* Get the exit reason before proc_exit */
		subcode = proc_encode_exit_exception_code(task->bsd_info);
		proc_exit(task->bsd_info);
		/*
		 * if there is crash info in task
		 * then do the deliver action since this is
		 * last thread for this task.
		 */
		if (task->corpse_info) {
			task_deliver_crash_notification(task, current_thread(), EXC_RESOURCE, subcode);
		}
	}

	if (threadcnt == 0) {
		task_lock(task);
		if (task_is_a_corpse_fork(task)) {
			thread_wakeup((event_t)&task->active_thread_count);
		}
		task_unlock(task);
	}

	uthread_cred_free(thread->uthread);

	s = splsched();
	thread_lock(thread);

	/*
	 * Ensure that the depress timer is no longer enqueued,
	 * so the timer (stored in the thread) can be safely deallocated
	 *
	 * TODO: build timer_call_cancel_wait
	 */

	assert((thread->sched_flags & TH_SFLAG_DEPRESSED_MASK) == 0);

	uint32_t delay_us = 1;

	while (thread->depress_timer_active > 0) {
		thread_unlock(thread);
		splx(s);

		delay(delay_us++);

		if (delay_us > USEC_PER_SEC)
			panic("depress timer failed to inactivate!"
			      "thread: %p depress_timer_active: %d",
			      thread, thread->depress_timer_active);

		s = splsched();
		thread_lock(thread);
	}

	/*
	 *	Cancel wait timer, and wait for
	 *	concurrent expirations.
	 */
	if (thread->wait_timer_is_set) {
		thread->wait_timer_is_set = FALSE;

		if (timer_call_cancel(&thread->wait_timer))
			thread->wait_timer_active--;
	}

	delay_us = 1;

	while (thread->wait_timer_active > 0) {
		thread_unlock(thread);
		splx(s);

		delay(delay_us++);

		if (delay_us > USEC_PER_SEC)
			panic("wait timer failed to inactivate!"
			      "thread: %p wait_timer_active: %d",
			      thread, thread->wait_timer_active);

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

	assert((thread->sched_flags & TH_SFLAG_WAITQ_PROMOTED) == 0);
	assert((thread->sched_flags & TH_SFLAG_RW_PROMOTED) == 0);
	assert((thread->sched_flags & TH_SFLAG_EXEC_PROMOTED) == 0);
	assert((thread->sched_flags & TH_SFLAG_PROMOTED) == 0);
	assert(thread->promotions == 0);
	assert(thread->was_promoted_on_wakeup == 0);
	assert(thread->waiting_for_mutex == NULL);
	assert(thread->rwlock_count == 0);

	thread_unlock(thread);
	/* splsched */

	thread_block((thread_continue_t)thread_terminate_continue);
	/*NOTREACHED*/
}

static bool
thread_ref_release(thread_t thread)
{
	if (thread == THREAD_NULL) {
		return false;
	}

	assert_thread_magic(thread);

	return os_ref_release(&thread->ref_count) == 0;
}

/* Drop a thread refcount safely without triggering a zfree */
void
thread_deallocate_safe(thread_t thread)
{
	if (__improbable(thread_ref_release(thread))) {
		/* enqueue the thread for thread deallocate deamon to call thread_deallocate_complete */
		thread_deallocate_enqueue(thread);
	}
}

void
thread_deallocate(thread_t thread)
{
	if (__improbable(thread_ref_release(thread))) {
		thread_deallocate_complete(thread);
	}
}

void
thread_deallocate_complete(
	thread_t			thread)
{
	task_t				task;

	assert_thread_magic(thread);

	assert(os_ref_get_count(&thread->ref_count) == 0);

	assert(thread_owned_workloops_count(thread) == 0);

	if (!(thread->state & TH_TERMINATE2))
		panic("thread_deallocate: thread not properly terminated\n");

	assert(thread->runq == PROCESSOR_NULL);

#if KPC
	kpc_thread_destroy(thread);
#endif

	ipc_thread_terminate(thread);

	proc_thread_qos_deallocate(thread);

	task = thread->task;

#ifdef MACH_BSD
	{
		void *ut = thread->uthread;

		thread->uthread = NULL;
		uthread_zone_free(ut);
	}
#endif /* MACH_BSD */

	if (thread->t_ledger)
		ledger_dereference(thread->t_ledger);
	if (thread->t_threadledger)
		ledger_dereference(thread->t_threadledger);

	assert(thread->turnstile != TURNSTILE_NULL);
	if (thread->turnstile)
		turnstile_deallocate(thread->turnstile);

	if (IPC_VOUCHER_NULL != thread->ith_voucher)
		ipc_voucher_release(thread->ith_voucher);

	if (thread->thread_io_stats)
		kfree(thread->thread_io_stats, sizeof(struct io_stat_info));

	if (thread->kernel_stack != 0)
		stack_free(thread);

	lck_mtx_destroy(&thread->mutex, &thread_lck_grp);
	machine_thread_destroy(thread);

	task_deallocate(task);

#if MACH_ASSERT
	assert_thread_magic(thread);
	thread->thread_magic = 0;
#endif /* MACH_ASSERT */

	zfree(thread_zone, thread);
}

void
thread_starts_owning_workloop(thread_t thread)
{
	atomic_fetch_add_explicit(&thread->kqwl_owning_count, 1,
			memory_order_relaxed);
}

void
thread_ends_owning_workloop(thread_t thread)
{
	__assert_only uint32_t count;
	count = atomic_fetch_sub_explicit(&thread->kqwl_owning_count, 1,
			memory_order_relaxed);
	assert(count > 0);
}

uint32_t
thread_owned_workloops_count(thread_t thread)
{
	return atomic_load_explicit(&thread->kqwl_owning_count,
			memory_order_relaxed);
}

/*
 *	thread_inspect_deallocate:
 *
 *	Drop a thread inspection reference.
 */
void
thread_inspect_deallocate(
	thread_inspect_t		thread_inspect)
{
	return(thread_deallocate((thread_t)thread_inspect));
}

/*
 *	thread_exception_daemon:
 *
 *	Deliver EXC_{RESOURCE,GUARD} exception
 */
static void
thread_exception_daemon(void)
{
	struct thread_exception_elt *elt;
	task_t task;
	thread_t thread;
	exception_type_t etype;

	simple_lock(&thread_exception_lock);
	while ((elt = (struct thread_exception_elt *)dequeue_head(&thread_exception_queue)) != NULL) {
		simple_unlock(&thread_exception_lock);

		etype = elt->exception_type;
		task = elt->exception_task;
		thread = elt->exception_thread;
		assert_thread_magic(thread);

		kfree(elt, sizeof (*elt));

		/* wait for all the threads in the task to terminate */
		task_lock(task);
		task_wait_till_threads_terminate_locked(task);
		task_unlock(task);

		/* Consumes the task ref returned by task_generate_corpse_internal */
		task_deallocate(task);
		/* Consumes the thread ref returned by task_generate_corpse_internal */
		thread_deallocate(thread);

		/* Deliver the notification, also clears the corpse. */
		task_deliver_crash_notification(task, thread, etype, 0);

		simple_lock(&thread_exception_lock);
	}

	assert_wait((event_t)&thread_exception_queue, THREAD_UNINT);
	simple_unlock(&thread_exception_lock);

	thread_block((thread_continue_t)thread_exception_daemon);
}

/*
 *	thread_exception_enqueue:
 *
 *	Enqueue a corpse port to be delivered an EXC_{RESOURCE,GUARD}.
 */
void
thread_exception_enqueue(
	task_t		task,
	thread_t	thread,
	exception_type_t etype)
{
	assert(EXC_RESOURCE == etype || EXC_GUARD == etype);
	struct thread_exception_elt *elt = kalloc(sizeof (*elt));
	elt->exception_type = etype;
	elt->exception_task = task;
	elt->exception_thread = thread;

	simple_lock(&thread_exception_lock);
	enqueue_tail(&thread_exception_queue, (queue_entry_t)elt);
	simple_unlock(&thread_exception_lock);

	thread_wakeup((event_t)&thread_exception_queue);
}

/*
 *	thread_copy_resource_info
 *
 *	Copy the resource info counters from source
 *	thread to destination thread.
 */
void
thread_copy_resource_info(
	thread_t dst_thread,
	thread_t src_thread)
{
	dst_thread->c_switch = src_thread->c_switch;
	dst_thread->p_switch = src_thread->p_switch;
	dst_thread->ps_switch = src_thread->ps_switch;
	dst_thread->precise_user_kernel_time = src_thread->precise_user_kernel_time;
	dst_thread->user_timer = src_thread->user_timer;
	dst_thread->user_timer_save = src_thread->user_timer_save;
	dst_thread->system_timer = src_thread->system_timer;
	dst_thread->system_timer_save = src_thread->system_timer_save;
	dst_thread->runnable_timer = src_thread->runnable_timer;
	dst_thread->vtimer_user_save = src_thread->vtimer_user_save;
	dst_thread->vtimer_prof_save = src_thread->vtimer_prof_save;
	dst_thread->vtimer_rlim_save = src_thread->vtimer_rlim_save;
	dst_thread->vtimer_qos_save = src_thread->vtimer_qos_save;
	dst_thread->syscalls_unix = src_thread->syscalls_unix;
	dst_thread->syscalls_mach = src_thread->syscalls_mach;
	ledger_rollup(dst_thread->t_threadledger, src_thread->t_threadledger);
	*dst_thread->thread_io_stats = *src_thread->thread_io_stats;
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

thread_terminate_start:
	while ((thread = qe_dequeue_head(&thread_terminate_queue, struct thread, runq_links)) != THREAD_NULL) {
		assert_thread_magic(thread);

		/* 
		 * if marked for crash reporting, skip reaping. 
		 * The corpse delivery thread will clear bit and enqueue 
		 * for reaping when done
		 */
		if (thread->inspection){
			enqueue_tail(&crashed_threads_queue, &thread->runq_links);
			continue;
		}

		simple_unlock(&thread_terminate_lock);
		(void)spllo();

		task = thread->task;

		task_lock(task);
		task->total_user_time += timer_grab(&thread->user_timer);
		task->total_ptime += timer_grab(&thread->ptime);
		task->total_runnable_time += timer_grab(&thread->runnable_timer);
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
		task->task_gpu_ns += ml_gpu_stat(thread);
		task->task_energy += ml_energy_stat(thread);

#if MONOTONIC
		mt_terminate_update(task, thread);
#endif /* MONOTONIC */

		thread_update_qos_cpu_time(thread);

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

	while ((thread = qe_dequeue_head(&thread_deallocate_queue, struct thread, runq_links)) != THREAD_NULL) {
		assert_thread_magic(thread);

		simple_unlock(&thread_terminate_lock);
		(void)spllo();

		thread_deallocate_complete(thread);

		(void)splsched();
		simple_lock(&thread_terminate_lock);
	}

	struct turnstile *turnstile;
	while ((turnstile = qe_dequeue_head(&turnstile_deallocate_queue, struct turnstile, ts_deallocate_link)) != TURNSTILE_NULL) {

		simple_unlock(&thread_terminate_lock);
		(void)spllo();

		turnstile_destroy(turnstile);

		(void)splsched();
		simple_lock(&thread_terminate_lock);
	}

	queue_entry_t qe;

	/*
	 * see workq_deallocate_enqueue: struct workqueue is opaque to thread.c and
	 * we just link pieces of memory here
	 */
	while ((qe = dequeue_head(&workq_deallocate_queue))) {
		simple_unlock(&thread_terminate_lock);
		(void)spllo();

		workq_destroy((struct workqueue *)qe);

		(void)splsched();
		simple_lock(&thread_terminate_lock);
	}

	/*
	 * Check if something enqueued in thread terminate/deallocate queue
	 * while processing workq deallocate queue
	 */
	if (!queue_empty(&thread_terminate_queue) ||
	    !queue_empty(&thread_deallocate_queue) ||
	    !queue_empty(&turnstile_deallocate_queue))
		goto thread_terminate_start;

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
	KDBG_RELEASE(TRACE_DATA_THREAD_TERMINATE, thread->thread_id);

	simple_lock(&thread_terminate_lock);
	enqueue_tail(&thread_terminate_queue, &thread->runq_links);
	simple_unlock(&thread_terminate_lock);

	thread_wakeup((event_t)&thread_terminate_queue);
}

/*
 *	thread_deallocate_enqueue:
 *
 *	Enqueue a thread for final deallocation.
 */
static void
thread_deallocate_enqueue(
	thread_t		thread)
{
	spl_t s = splsched();

	simple_lock(&thread_terminate_lock);
	enqueue_tail(&thread_deallocate_queue, &thread->runq_links);
	simple_unlock(&thread_terminate_lock);

	thread_wakeup((event_t)&thread_terminate_queue);
	splx(s);
}

/*
 *	turnstile_deallocate_enqueue:
 *
 *	Enqueue a turnstile for final deallocation.
 */
void
turnstile_deallocate_enqueue(
	struct turnstile *turnstile)
{
	spl_t s = splsched();

	simple_lock(&thread_terminate_lock);
	enqueue_tail(&turnstile_deallocate_queue, &turnstile->ts_deallocate_link);
	simple_unlock(&thread_terminate_lock);

	thread_wakeup((event_t)&thread_terminate_queue);
	splx(s);
}

/*
 *	workq_deallocate_enqueue:
 *
 *	Enqueue a workqueue for final deallocation.
 */
void
workq_deallocate_enqueue(
	struct workqueue *wq)
{
	spl_t s = splsched();

	simple_lock(&thread_terminate_lock);
	/*
	 * this is just to delay a zfree(), so we link the memory with no regards
	 * for how the struct looks like.
	 */
	enqueue_tail(&workq_deallocate_queue, (queue_entry_t)wq);
	simple_unlock(&thread_terminate_lock);

	thread_wakeup((event_t)&thread_terminate_queue);
	splx(s);
}

/*
 * thread_terminate_crashed_threads:
 * walk the list of crashed threads and put back set of threads
 * who are no longer being inspected.
 */
void
thread_terminate_crashed_threads()
{
	thread_t th_remove;
	boolean_t should_wake_terminate_queue = FALSE;
	spl_t s = splsched();

	simple_lock(&thread_terminate_lock);
	/*
	 * loop through the crashed threads queue
	 * to put any threads that are not being inspected anymore
	 */

	qe_foreach_element_safe(th_remove, &crashed_threads_queue, runq_links) {
		/* make sure current_thread is never in crashed queue */
		assert(th_remove != current_thread());

		if (th_remove->inspection == FALSE) {
			re_queue_tail(&thread_terminate_queue, &th_remove->runq_links);
			should_wake_terminate_queue = TRUE;
		}
	}

	simple_unlock(&thread_terminate_lock);
	splx(s);
	if (should_wake_terminate_queue == TRUE) {
		thread_wakeup((event_t)&thread_terminate_queue);
	}
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

	while ((thread = qe_dequeue_head(&thread_stack_queue, struct thread, runq_links)) != THREAD_NULL) {
		assert_thread_magic(thread);

		simple_unlock(&thread_stack_lock);
		splx(s);

		/* allocate stack with interrupts enabled so that we can call into VM */
		stack_alloc(thread);

		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED,MACH_STACK_WAIT) | DBG_FUNC_END, thread_tid(thread), 0, 0, 0, 0);
		
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
	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED,MACH_STACK_WAIT) | DBG_FUNC_START, thread_tid(thread), 0, 0, 0, 0);
	assert_thread_magic(thread);

	simple_lock(&thread_stack_lock);
	enqueue_tail(&thread_stack_queue, &thread->runq_links);
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
	queue_init(&thread_deallocate_queue);
	queue_init(&workq_deallocate_queue);
	queue_init(&turnstile_deallocate_queue);
	queue_init(&crashed_threads_queue);

	result = kernel_thread_start_priority((thread_continue_t)thread_terminate_daemon, NULL, MINPRI_KERNEL, &thread);
	if (result != KERN_SUCCESS)
		panic("thread_daemon_init: thread_terminate_daemon");

	thread_deallocate(thread);

	simple_lock_init(&thread_stack_lock, 0);
	queue_init(&thread_stack_queue);

	result = kernel_thread_start_priority((thread_continue_t)thread_stack_daemon, NULL, BASEPRI_PREEMPT_HIGH, &thread);
	if (result != KERN_SUCCESS)
		panic("thread_daemon_init: thread_stack_daemon");

	thread_deallocate(thread);

	simple_lock_init(&thread_exception_lock, 0);
	queue_init(&thread_exception_queue);

	result = kernel_thread_start_priority((thread_continue_t)thread_exception_daemon, NULL, MINPRI_KERNEL, &thread);
	if (result != KERN_SUCCESS)
		panic("thread_daemon_init: thread_exception_daemon");

	thread_deallocate(thread);
}

#define TH_OPTION_NONE		0x00
#define TH_OPTION_NOCRED	0x01
#define TH_OPTION_NOSUSP	0x02
#define TH_OPTION_WORKQ		0x04

/*
 * Create a new thread.
 * Doesn't start the thread running.
 *
 * Task and tasks_threads_lock are returned locked on success.
 */
static kern_return_t
thread_create_internal(
	task_t					parent_task,
	integer_t				priority,
	thread_continue_t		continuation,
	void					*parameter,
	int						options,
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

	os_ref_init_count(&new_thread->ref_count, &thread_refgrp, 2);

#ifdef MACH_BSD
	new_thread->uthread = uthread_alloc(parent_task, new_thread, (options & TH_OPTION_NOCRED) != 0);
	if (new_thread->uthread == NULL) {
#if MACH_ASSERT
		new_thread->thread_magic = 0;
#endif /* MACH_ASSERT */

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

#if MACH_ASSERT
		new_thread->thread_magic = 0;
#endif /* MACH_ASSERT */

		zfree(thread_zone, new_thread);
		return (KERN_FAILURE);
	}

	new_thread->task = parent_task;

	thread_lock_init(new_thread);
	wake_lock_init(new_thread);

	lck_mtx_init(&new_thread->mutex, &thread_lck_grp, &thread_lck_attr);

	ipc_thread_init(new_thread);

	new_thread->continuation = continuation;
	new_thread->parameter = parameter;
	new_thread->inheritor_flags = TURNSTILE_UPDATE_FLAGS_NONE;
	priority_queue_init(&new_thread->inheritor_queue,
			PRIORITY_QUEUE_BUILTIN_MAX_HEAP);

	/* Allocate I/O Statistics structure */
	new_thread->thread_io_stats = (io_stat_info_t)kalloc(sizeof(struct io_stat_info));
	assert(new_thread->thread_io_stats != NULL);
	bzero(new_thread->thread_io_stats, sizeof(struct io_stat_info));
	new_thread->sync_ipc_overrides = 0;

#if KASAN
	kasan_init_thread(&new_thread->kasan_data);
#endif

#if CONFIG_IOSCHED
	/* Clear out the I/O Scheduling info for AppleFSCompression */
	new_thread->decmp_upl = NULL;
#endif /* CONFIG_IOSCHED */ 

#if DEVELOPMENT || DEBUG
	task_lock(parent_task);
	uint16_t thread_limit = parent_task->task_thread_limit;
	if (exc_resource_threads_enabled &&
	    thread_limit > 0 &&
	    parent_task->thread_count >= thread_limit &&
	    !parent_task->task_has_crossed_thread_limit &&
	    !(parent_task->t_flags & TF_CORPSE)) {
		int thread_count = parent_task->thread_count;
		parent_task->task_has_crossed_thread_limit = TRUE;
		task_unlock(parent_task);
		SENDING_NOTIFICATION__TASK_HAS_TOO_MANY_THREADS(parent_task, thread_count);
	}
	else {
		task_unlock(parent_task);
	}
#endif

	lck_mtx_lock(&tasks_threads_lock);
	task_lock(parent_task);

	/*
	 * Fail thread creation if parent task is being torn down or has too many threads
	 * If the caller asked for TH_OPTION_NOSUSP, also fail if the parent task is suspended
	 */
	if (parent_task->active == 0 || parent_task->halting ||
	    (parent_task->suspend_count > 0 && (options & TH_OPTION_NOSUSP) != 0) ||
	    (parent_task->thread_count >= task_threadmax && parent_task != kernel_task)) {
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
		kfree(new_thread->thread_io_stats, sizeof(struct io_stat_info));
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
		act_set_astledger(new_thread);
	}

	/* Instantiate a thread ledger. Do not fail thread creation if ledger creation fails. */
	if ((new_thread->t_threadledger = ledger_instantiate(thread_ledger_template,
				LEDGER_CREATE_INACTIVE_ENTRIES)) != LEDGER_NULL) {

		ledger_entry_setactive(new_thread->t_threadledger, thread_ledgers.cpu_time);
	}

	new_thread->t_bankledger = LEDGER_NULL;
	new_thread->t_deduct_bank_ledger_time = 0;
	new_thread->t_deduct_bank_ledger_energy = 0;

	new_thread->t_ledger = new_thread->task->ledger;
	if (new_thread->t_ledger)
		ledger_reference(new_thread->t_ledger);

#if defined(CONFIG_SCHED_MULTIQ)
	/* Cache the task's sched_group */
	new_thread->sched_group = parent_task->sched_group;
#endif /* defined(CONFIG_SCHED_MULTIQ) */

	/* Cache the task's map */
	new_thread->map = parent_task->map;

	timer_call_setup(&new_thread->wait_timer, thread_timer_expire, new_thread);
	timer_call_setup(&new_thread->depress_timer, thread_depress_expire, new_thread);

#if KPC
	kpc_thread_create(new_thread);
#endif

	/* Set the thread's scheduling parameters */
	new_thread->sched_mode = SCHED(initial_thread_sched_mode)(parent_task);
	new_thread->max_priority = parent_task->max_priority;
	new_thread->task_priority = parent_task->priority;

	int new_priority = (priority < 0) ? parent_task->priority: priority;
	new_priority = (priority < 0)? parent_task->priority: priority;
	if (new_priority > new_thread->max_priority)
		new_priority = new_thread->max_priority;
#if CONFIG_EMBEDDED
	if (new_priority < MAXPRI_THROTTLE) {
		new_priority = MAXPRI_THROTTLE;
	}
#endif /* CONFIG_EMBEDDED */

	new_thread->importance = new_priority - new_thread->task_priority;

	sched_set_thread_base_priority(new_thread, new_priority);

#if defined(CONFIG_SCHED_TIMESHARE_CORE)
	new_thread->sched_stamp = sched_tick;
	new_thread->pri_shift = sched_pri_shifts[new_thread->th_sched_bucket];
#endif /* defined(CONFIG_SCHED_TIMESHARE_CORE) */

#if CONFIG_EMBEDDED
	if (parent_task->max_priority <= MAXPRI_THROTTLE)
		sched_thread_mode_demote(new_thread, TH_SFLAG_THROTTLED);
#endif /* CONFIG_EMBEDDED */

	thread_policy_create(new_thread);

	/* Chain the thread onto the task's list */
	queue_enter(&parent_task->threads, new_thread, thread_t, task_threads);
	parent_task->thread_count++;

	/* So terminating threads don't need to take the task lock to decrement */
	hw_atomic_add(&parent_task->active_thread_count, 1);

	/* Protected by the tasks_threads_lock */
	new_thread->thread_id = ++thread_unique_id;


	queue_enter(&threads, new_thread, thread_t, threads);
	threads_count++;

	new_thread->active = TRUE;
	if (task_is_a_corpse_fork(parent_task)) {
		/* Set the inspection bit if the task is a corpse fork */
		new_thread->inspection = TRUE;
	} else {
		new_thread->inspection = FALSE;
	}
	new_thread->corpse_dup = FALSE;
	new_thread->turnstile = turnstile_alloc();
	*out_thread = new_thread;

	if (kdebug_enable) {
		long args[4] = {};

		kdbg_trace_data(parent_task->bsd_info, &args[1], &args[3]);

		/*
		 * Starting with 26604425, exec'ing creates a new task/thread.
		 *
		 * NEWTHREAD in the current process has two possible meanings:
		 *
		 * 1) Create a new thread for this process.
		 * 2) Create a new thread for the future process this will become in an
		 * exec.
		 *
		 * To disambiguate these, arg3 will be set to TRUE for case #2.
		 *
		 * The value we need to find (TPF_EXEC_COPY) is stable in the case of a
		 * task exec'ing. The read of t_procflags does not take the proc_lock.
		 */
		args[2] = task_is_exec_copy(parent_task) ? 1 : 0;

		KDBG_RELEASE(TRACE_DATA_NEWTHREAD, (uintptr_t)thread_tid(new_thread),
				args[1], args[2], args[3]);

		kdbg_trace_string(parent_task->bsd_info, &args[0], &args[1],
				&args[2], &args[3]);
		KDBG_RELEASE(TRACE_STRING_NEWTHREAD, args[0], args[1], args[2],
				args[3]);
	}

	DTRACE_PROC1(lwp__create, thread_t, *out_thread);

	return (KERN_SUCCESS);
}

static kern_return_t
thread_create_internal2(
	task_t				task,
	thread_t			*new_thread,
	boolean_t			from_user,
	thread_continue_t		continuation)
{
	kern_return_t		result;
	thread_t			thread;

	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	result = thread_create_internal(task, -1, continuation, NULL, TH_OPTION_NONE, &thread);
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
	return thread_create_internal2(task, new_thread, FALSE, (thread_continue_t)thread_bootstrap_return);
}

kern_return_t
thread_create_from_user(
	task_t				task,
	thread_t			*new_thread)
{
	return thread_create_internal2(task, new_thread, TRUE, (thread_continue_t)thread_bootstrap_return);
}

kern_return_t
thread_create_with_continuation(
	task_t				task,
	thread_t			*new_thread,
	thread_continue_t		continuation)
{
	return thread_create_internal2(task, new_thread, FALSE, continuation);
}

/*
 * Create a thread that is already started, but is waiting on an event
 */
static kern_return_t
thread_create_waiting_internal(
	task_t                  task,
	thread_continue_t       continuation,
	event_t                 event,
	block_hint_t            block_hint,
	int                     options,
	thread_t                *new_thread)
{
	kern_return_t result;
	thread_t thread;

	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	result = thread_create_internal(task, -1, continuation, NULL,
			options, &thread);
	if (result != KERN_SUCCESS)
		return (result);

	/* note no user_stop_count or thread_hold here */

	if (task->suspend_count > 0)
		thread_hold(thread);

	thread_mtx_lock(thread);
	thread_set_pending_block_hint(thread, block_hint);
	if (options & TH_OPTION_WORKQ) {
		thread->static_param = true;
		event = workq_thread_init_and_wq_lock(task, thread);
	}
	thread_start_in_assert_wait(thread, event, THREAD_INTERRUPTIBLE);
	thread_mtx_unlock(thread);

	task_unlock(task);
	lck_mtx_unlock(&tasks_threads_lock);

	*new_thread = thread;

	return (KERN_SUCCESS);
}

kern_return_t
thread_create_waiting(
	task_t                  task,
	thread_continue_t       continuation,
	event_t                 event,
	thread_t                *new_thread)
{
	return thread_create_waiting_internal(task, continuation, event,
			kThreadWaitNone, TH_OPTION_NONE, new_thread);
}


static kern_return_t
thread_create_running_internal2(
	task_t         task,
	int                     flavor,
	thread_state_t          new_state,
	mach_msg_type_number_t  new_state_count,
	thread_t				*new_thread,
	boolean_t				from_user)
{
	kern_return_t  result;
	thread_t				thread;

	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	result = thread_create_internal(task, -1,
			(thread_continue_t)thread_bootstrap_return, NULL,
			TH_OPTION_NONE, &thread);
	if (result != KERN_SUCCESS)
		return (result);

	if (task->suspend_count > 0)
		thread_hold(thread);

	if (from_user) {
		result = machine_thread_state_convert_from_user(thread, flavor,
				new_state, new_state_count);
	}
	if (result == KERN_SUCCESS) {
		result = machine_thread_set_state(thread, flavor, new_state,
				new_state_count);
	}
	if (result != KERN_SUCCESS) {
		task_unlock(task);
		lck_mtx_unlock(&tasks_threads_lock);

		thread_terminate(thread);
		thread_deallocate(thread);
		return (result);
	}

	thread_mtx_lock(thread);
	thread_start(thread);
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
	task_t         task,
	int                     flavor,
	thread_state_t          new_state,
	mach_msg_type_number_t  new_state_count,
	thread_t				*new_thread);

kern_return_t
thread_create_running(
	task_t         task,
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
	task_t         task,
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
thread_create_workq_waiting(
	task_t              task,
	thread_continue_t   continuation,
	thread_t            *new_thread)
{
	int options = TH_OPTION_NOCRED | TH_OPTION_NOSUSP | TH_OPTION_WORKQ;
	return thread_create_waiting_internal(task, continuation, NULL,
			kThreadWaitParkedWorkQueue, options, new_thread);
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

	result = thread_create_internal(task, priority, continuation, parameter,
			TH_OPTION_NOCRED | TH_OPTION_NONE, &thread);
	if (result != KERN_SUCCESS)
		return (result);

	task_unlock(task);
	lck_mtx_unlock(&tasks_threads_lock);

	stack_alloc(thread);
	assert(thread->kernel_stack != 0);
#if CONFIG_EMBEDDED
	if (priority > BASEPRI_KERNEL)
#endif
	thread->reserved_stack = thread->kernel_stack;

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
	thread_start(thread);
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

/* Separated into helper function so it can be used by THREAD_BASIC_INFO and THREAD_EXTENDED_INFO */
/* it is assumed that the thread is locked by the caller */
static void
retrieve_thread_basic_info(thread_t thread, thread_basic_info_t basic_info)
{
	int	state, flags;

	/* fill in info */

	thread_read_times(thread, &basic_info->user_time,
			&basic_info->system_time, NULL);

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
#if defined(CONFIG_SCHED_TIMESHARE_CORE)
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

	if (thread->options & TH_OPT_GLOBAL_FORCED_IDLE) {
		flags |= TH_FLAGS_GLOBAL_FORCED_IDLE;
	}

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

	return;
}

kern_return_t
thread_info_internal(
	thread_t		thread,
	thread_flavor_t			flavor,
	thread_info_t			thread_info_out,	/* ptr to OUT array */
	mach_msg_type_number_t	*thread_info_count)	/*IN/OUT*/
{
	spl_t	s;

	if (thread == THREAD_NULL)
		return (KERN_INVALID_ARGUMENT);

	if (flavor == THREAD_BASIC_INFO) {

		if (*thread_info_count < THREAD_BASIC_INFO_COUNT)
			return (KERN_INVALID_ARGUMENT);

		s = splsched();
		thread_lock(thread);

		retrieve_thread_basic_info(thread, (thread_basic_info_t) thread_info_out);

		thread_unlock(thread);
		splx(s);

		*thread_info_count = THREAD_BASIC_INFO_COUNT;

		return (KERN_SUCCESS);
	}
	else
	if (flavor == THREAD_IDENTIFIER_INFO) {
		thread_identifier_info_t	identifier_info;

		if (*thread_info_count < THREAD_IDENTIFIER_INFO_COUNT)
			return (KERN_INVALID_ARGUMENT);

		identifier_info = (thread_identifier_info_t) thread_info_out;

		s = splsched();
		thread_lock(thread);

		identifier_info->thread_id = thread->thread_id;
		identifier_info->thread_handle = thread->machine.cthread_self;
		identifier_info->dispatch_qaddr = thread_dispatchqaddr(thread);

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
			ts_info->depress_priority = thread->base_pri;
		}
		else {
			ts_info->base_priority = thread->base_pri;
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
			rr_info->depress_priority = thread->base_pri;
		}
		else {
			rr_info->base_priority = thread->base_pri;
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
	else
	if (flavor == THREAD_EXTENDED_INFO) {
		thread_basic_info_data_t	basic_info;
		thread_extended_info_t		extended_info = (thread_extended_info_t) thread_info_out;

		if (*thread_info_count < THREAD_EXTENDED_INFO_COUNT) {
			return (KERN_INVALID_ARGUMENT);
		}

		s = splsched();
		thread_lock(thread);

		/* NOTE: This mimics fill_taskthreadinfo(), which is the function used by proc_pidinfo() for
		 * the PROC_PIDTHREADINFO flavor (which can't be used on corpses)
		 */
		retrieve_thread_basic_info(thread, &basic_info);
		extended_info->pth_user_time = ((basic_info.user_time.seconds * (integer_t)NSEC_PER_SEC) + (basic_info.user_time.microseconds * (integer_t)NSEC_PER_USEC));
		extended_info->pth_system_time = ((basic_info.system_time.seconds * (integer_t)NSEC_PER_SEC) + (basic_info.system_time.microseconds * (integer_t)NSEC_PER_USEC));

		extended_info->pth_cpu_usage = basic_info.cpu_usage;
		extended_info->pth_policy = basic_info.policy;
		extended_info->pth_run_state = basic_info.run_state;
		extended_info->pth_flags = basic_info.flags;
		extended_info->pth_sleep_time = basic_info.sleep_time;
		extended_info->pth_curpri = thread->sched_pri;
		extended_info->pth_priority = thread->base_pri;
		extended_info->pth_maxpriority = thread->max_priority;

		bsd_getthreadname(thread->uthread,extended_info->pth_name);

		thread_unlock(thread);
		splx(s);

		*thread_info_count = THREAD_EXTENDED_INFO_COUNT;

		return (KERN_SUCCESS);
	}
	else
	if (flavor == THREAD_DEBUG_INFO_INTERNAL) {
#if DEVELOPMENT || DEBUG
		thread_debug_info_internal_t dbg_info;
		if (*thread_info_count < THREAD_DEBUG_INFO_INTERNAL_COUNT)
			return (KERN_NOT_SUPPORTED);

		if (thread_info_out == NULL)
			return (KERN_INVALID_ARGUMENT);

		dbg_info = (thread_debug_info_internal_t) thread_info_out;
		dbg_info->page_creation_count = thread->t_page_creation_count;

		*thread_info_count = THREAD_DEBUG_INFO_INTERNAL_COUNT;
		return (KERN_SUCCESS);
#endif /* DEVELOPMENT || DEBUG */
		return (KERN_NOT_SUPPORTED);
	}

	return (KERN_INVALID_ARGUMENT);
}

void
thread_read_times(
	thread_t		thread,
	time_value_t	*user_time,
	time_value_t	*system_time,
	time_value_t	*runnable_time)
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

	if (runnable_time) {
		uint64_t tval_runnable = timer_grab(&thread->runnable_timer);
		absolutetime_to_microtime(tval_runnable, &secs, &usecs);
		runnable_time->seconds = (typeof(runnable_time->seconds))secs;
		runnable_time->microseconds = usecs;
	}
}

uint64_t thread_get_runtime_self(void)
{
	boolean_t interrupt_state;
	uint64_t runtime;
	thread_t thread = NULL;
	processor_t processor = NULL;

	thread = current_thread();

	/* Not interrupt safe, as the scheduler may otherwise update timer values underneath us */
	interrupt_state = ml_set_interrupts_enabled(FALSE);
	processor = current_processor();
	timer_update(PROCESSOR_DATA(processor, thread_timer), mach_absolute_time());
	runtime = (timer_grab(&thread->user_timer) + timer_grab(&thread->system_timer));
	ml_set_interrupts_enabled(interrupt_state);

	return runtime;
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


boolean_t
is_vm_privileged(void)
{
	return current_thread()->options & TH_OPT_VMPRIV ? TRUE : FALSE;
}

boolean_t
set_vm_privilege(boolean_t privileged)
{
	boolean_t       was_vmpriv;

	if (current_thread()->options & TH_OPT_VMPRIV)
		was_vmpriv = TRUE;
	else
		was_vmpriv = FALSE;

	if (privileged != FALSE)
		current_thread()->options |= TH_OPT_VMPRIV;
	else
		current_thread()->options &= ~TH_OPT_VMPRIV;

	return (was_vmpriv);
}

void
set_thread_rwlock_boost(void)
{
	current_thread()->rwlock_count++;
}

void
clear_thread_rwlock_boost(void)
{
	thread_t thread = current_thread();

	if ((thread->rwlock_count-- == 1) && (thread->sched_flags & TH_SFLAG_RW_PROMOTED)) {

		lck_rw_clear_promotion(thread, 0);
	}
}


/*
 * XXX assuming current thread only, for now...
 */
void
thread_guard_violation(thread_t thread,
    mach_exception_data_type_t code, mach_exception_data_type_t subcode)
{
	assert(thread == current_thread());

	/* don't set up the AST for kernel threads */
	if (thread->task == kernel_task)
		return;

	spl_t s = splsched();
	/*
	 * Use the saved state area of the thread structure
	 * to store all info required to handle the AST when
	 * returning to userspace
	 */
	assert(EXC_GUARD_DECODE_GUARD_TYPE(code));
	thread->guard_exc_info.code = code;
	thread->guard_exc_info.subcode = subcode;
	thread_ast_set(thread, AST_GUARD);
	ast_propagate(thread);

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
guard_ast(thread_t t)
{
	const mach_exception_data_type_t
		code = t->guard_exc_info.code,
		subcode = t->guard_exc_info.subcode;

	t->guard_exc_info.code = 0;
	t->guard_exc_info.subcode = 0;
	
	switch (EXC_GUARD_DECODE_GUARD_TYPE(code)) {
	case GUARD_TYPE_NONE:
		/* lingering AST_GUARD on the processor? */
		break;
	case GUARD_TYPE_MACH_PORT:
		mach_port_guard_ast(t, code, subcode);
		break;
	case GUARD_TYPE_FD:
		fd_guard_ast(t, code, subcode);
		break;
#if CONFIG_VNGUARD
	case GUARD_TYPE_VN:
		vn_guard_ast(t, code, subcode);
		break;
#endif
	case GUARD_TYPE_VIRT_MEMORY:
		virt_memory_guard_ast(t, code, subcode);
		break;
	default:
		panic("guard_exc_info %llx %llx", code, subcode);
	}
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
		SENDING_NOTIFICATION__THIS_THREAD_IS_CONSUMING_TOO_MUCH_CPU();
	}
}

void __attribute__((noinline))
SENDING_NOTIFICATION__THIS_THREAD_IS_CONSUMING_TOO_MUCH_CPU(void)
{
	int          pid                = 0;
	task_t		 task				= current_task();
	thread_t     thread             = current_thread();
	uint64_t     tid                = thread->thread_id;
	const char	 *procname          = "unknown";
	time_value_t thread_total_time  = {0, 0};
	time_value_t thread_system_time;
	time_value_t thread_user_time;
	int          action;
	uint8_t      percentage;
	uint32_t     usage_percent = 0;
	uint32_t     interval_sec;
	uint64_t     interval_ns;
	uint64_t     balance_ns;
	boolean_t	 fatal = FALSE;
	boolean_t	 send_exc_resource = TRUE; /* in addition to RESOURCE_NOTIFY */
	kern_return_t	kr;

#ifdef EXC_RESOURCE_MONITORS
	mach_exception_data_type_t	code[EXCEPTION_CODE_MAX];
#endif /* EXC_RESOURCE_MONITORS */
	struct ledger_entry_info	lei;

	assert(thread->t_threadledger != LEDGER_NULL);

	/*
	 * Extract the fatal bit and suspend the monitor (which clears the bit).
	 */
	task_lock(task);
	if (task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_FATAL_CPUMON) {
		fatal = TRUE;
		send_exc_resource = TRUE;
	}
	/* Only one thread can be here at a time.  Whichever makes it through
	   first will successfully suspend the monitor and proceed to send the
	   notification.  Other threads will get an error trying to suspend the
	   monitor and give up on sending the notification.  In the first release,
	   the monitor won't be resumed for a number of seconds, but we may
	   eventually need to handle low-latency resume.
	 */
	kr = task_suspend_cpumon(task);
	task_unlock(task);
	if (kr == KERN_INVALID_ARGUMENT)	return;

#ifdef MACH_BSD
	pid = proc_selfpid();
	if (task->bsd_info != NULL) {
		procname = proc_name_address(task->bsd_info);
	}
#endif

	thread_get_cpulimit(&action, &percentage, &interval_ns);

	interval_sec = (uint32_t)(interval_ns / NSEC_PER_SEC);

	thread_read_times(thread, &thread_user_time, &thread_system_time, NULL);
	time_value_add(&thread_total_time, &thread_user_time);
	time_value_add(&thread_total_time, &thread_system_time);
	ledger_get_entry_info(thread->t_threadledger, thread_ledgers.cpu_time, &lei);

	/* credit/debit/balance/limit are in absolute time units;
	   the refill info is in nanoseconds. */
	absolutetime_to_nanoseconds(lei.lei_balance, &balance_ns);
	if (lei.lei_last_refill > 0) {
		usage_percent = (uint32_t)((balance_ns*100ULL) / lei.lei_last_refill);
	}

	/* TODO: show task total runtime (via TASK_ABSOLUTETIME_INFO)? */
	printf("process %s[%d] thread %llu caught burning CPU! "
	       "It used more than %d%% CPU over %u seconds "
	       "(actual recent usage: %d%% over ~%llu seconds).  "
	       "Thread lifetime cpu usage %d.%06ds, (%d.%06d user, %d.%06d sys) "
	       "ledger balance: %lld mabs credit: %lld mabs debit: %lld mabs "
	       "limit: %llu mabs period: %llu ns last refill: %llu ns%s.\n",
	       procname, pid, tid,
	       percentage, interval_sec,
	       usage_percent,
	       (lei.lei_last_refill + NSEC_PER_SEC/2) / NSEC_PER_SEC,
	       thread_total_time.seconds, thread_total_time.microseconds,
	       thread_user_time.seconds, thread_user_time.microseconds,
	       thread_system_time.seconds,thread_system_time.microseconds,
	       lei.lei_balance, lei.lei_credit, lei.lei_debit,
	       lei.lei_limit, lei.lei_refill_period, lei.lei_last_refill,
	       (fatal ? " [fatal violation]" : ""));

	/*
	   For now, send RESOURCE_NOTIFY in parallel with EXC_RESOURCE.  Once
	   we have logging parity, we will stop sending EXC_RESOURCE (24508922).
	 */

	/* RESOURCE_NOTIFY MIG specifies nanoseconds of CPU time */
	lei.lei_balance = balance_ns;
	absolutetime_to_nanoseconds(lei.lei_limit, &lei.lei_limit);
	trace_resource_violation(RMON_CPUUSAGE_VIOLATED, &lei);
	kr = send_resource_violation(send_cpu_usage_violation, task, &lei,
								 fatal ? kRNFatalLimitFlag : 0);
	if (kr) {
		printf("send_resource_violation(CPU usage, ...): error %#x\n", kr);
	}

#ifdef EXC_RESOURCE_MONITORS
	if (send_exc_resource) {
		if (disable_exc_resource) {
			printf("process %s[%d] thread %llu caught burning CPU! "
				   "EXC_RESOURCE%s supressed by a boot-arg\n",
				   procname, pid, tid, fatal ? " (and termination)" : "");
			return;
		}

		if (audio_active) {
			printf("process %s[%d] thread %llu caught burning CPU! "
			   "EXC_RESOURCE & termination supressed due to audio playback\n",
				   procname, pid, tid);
			return;
		}
	}


	if (send_exc_resource) {
		code[0] = code[1] = 0;
		EXC_RESOURCE_ENCODE_TYPE(code[0], RESOURCE_TYPE_CPU);
		if (fatal) {
			EXC_RESOURCE_ENCODE_FLAVOR(code[0], FLAVOR_CPU_MONITOR_FATAL);
		}else {
			EXC_RESOURCE_ENCODE_FLAVOR(code[0], FLAVOR_CPU_MONITOR);
		}
		EXC_RESOURCE_CPUMONITOR_ENCODE_INTERVAL(code[0], interval_sec);
		EXC_RESOURCE_CPUMONITOR_ENCODE_PERCENTAGE(code[0], percentage);
		EXC_RESOURCE_CPUMONITOR_ENCODE_PERCENTAGE(code[1], usage_percent);
		exception_triage(EXC_RESOURCE, code, EXCEPTION_CODE_MAX);
	}
#endif /* EXC_RESOURCE_MONITORS */

	if (fatal) {
#if CONFIG_JETSAM
		jetsam_on_ledger_cpulimit_exceeded();
#else
		task_terminate_internal(task);
#endif
	}
}

#if DEVELOPMENT || DEBUG
void __attribute__((noinline)) SENDING_NOTIFICATION__TASK_HAS_TOO_MANY_THREADS(task_t task, int thread_count)
{
	mach_exception_data_type_t code[EXCEPTION_CODE_MAX] = {0};
	int pid = task_pid(task);
	char procname[MAXCOMLEN+1] = "unknown";

	if (pid == 1) {
		/*
		 * Cannot suspend launchd
		 */
		return;
	}

	proc_name(pid, procname, sizeof(procname));

	if (disable_exc_resource) {
		printf("process %s[%d] crossed thread count high watermark (%d), EXC_RESOURCE "
			"supressed by a boot-arg. \n", procname, pid, thread_count);
		return;
	}

	if (audio_active) {
		printf("process %s[%d] crossed thread count high watermark (%d), EXC_RESOURCE "
			"supressed due to audio playback.\n", procname, pid, thread_count);
		return;
	}

	if (exc_via_corpse_forking == 0) {
		printf("process %s[%d] crossed thread count high watermark (%d), EXC_RESOURCE "
			"supressed due to corpse forking being disabled.\n", procname, pid,
			thread_count);
		return;
	}

	printf("process %s[%d] crossed thread count high watermark (%d), sending "
		"EXC_RESOURCE\n", procname, pid, thread_count);

	EXC_RESOURCE_ENCODE_TYPE(code[0], RESOURCE_TYPE_THREADS);
	EXC_RESOURCE_ENCODE_FLAVOR(code[0], FLAVOR_THREADS_HIGH_WATERMARK);
	EXC_RESOURCE_THREADS_ENCODE_THREADS(code[0], thread_count);

	task_enqueue_exception_with_corpse(task, EXC_RESOURCE, code, EXCEPTION_CODE_MAX, NULL);
}
#endif /* DEVELOPMENT || DEBUG */

void thread_update_io_stats(thread_t thread, int size, int io_flags)
{
	int io_tier;

	if (thread->thread_io_stats == NULL || thread->task->task_io_stats == NULL)
		return;

	if (io_flags & DKIO_READ) {
		UPDATE_IO_STATS(thread->thread_io_stats->disk_reads, size);
		UPDATE_IO_STATS_ATOMIC(thread->task->task_io_stats->disk_reads, size);
	}
	
	if (io_flags & DKIO_META) {
		UPDATE_IO_STATS(thread->thread_io_stats->metadata, size);
		UPDATE_IO_STATS_ATOMIC(thread->task->task_io_stats->metadata, size);
	}
	
	if (io_flags & DKIO_PAGING) {
		UPDATE_IO_STATS(thread->thread_io_stats->paging, size);
		UPDATE_IO_STATS_ATOMIC(thread->task->task_io_stats->paging, size);
	}

	io_tier = ((io_flags & DKIO_TIER_MASK) >> DKIO_TIER_SHIFT);
	assert (io_tier < IO_NUM_PRIORITIES);

	UPDATE_IO_STATS(thread->thread_io_stats->io_priority[io_tier], size);
	UPDATE_IO_STATS_ATOMIC(thread->task->task_io_stats->io_priority[io_tier], size);

	/* Update Total I/O Counts */
	UPDATE_IO_STATS(thread->thread_io_stats->total_io, size);
	UPDATE_IO_STATS_ATOMIC(thread->task->task_io_stats->total_io, size);

	if (!(io_flags & DKIO_READ)) {
		DTRACE_IO3(physical_writes, struct task *, thread->task, uint32_t, size, int, io_flags);
		ledger_credit(thread->task->ledger, task_ledgers.physical_writes, size);
	}
}

static void
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

	ledger_template_complete(t);
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
			ledger_set_limit(l, thread_ledgers.cpu_time, LEDGER_LIMIT_INFINITY, 0);
			ledger_set_action(l, thread_ledgers.cpu_time, LEDGER_ACTION_IGNORE);
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

void
thread_sched_call(
	thread_t		thread,
	sched_call_t	call)
{
	assert((thread->state & TH_WAIT_REPORT) == 0);
	thread->sched_call = call;
}

uint64_t
thread_tid(
	thread_t	thread)
{
	return (thread != THREAD_NULL? thread->thread_id: 0);
}

uint16_t
thread_set_tag(thread_t th, uint16_t tag)
{
	return thread_set_tag_internal(th, tag);
}

uint16_t
thread_get_tag(thread_t th)
{
	return thread_get_tag_internal(th);
}

uint64_t
thread_last_run_time(thread_t th)
{
	return th->last_run_time;
}

uint64_t
thread_dispatchqaddr(
	thread_t		thread)
{
	uint64_t	dispatchqueue_addr;
	uint64_t	thread_handle;

	if (thread == THREAD_NULL)
		return 0;

	thread_handle = thread->machine.cthread_self;
	if (thread_handle == 0)
		return 0;
	
	if (thread->inspection == TRUE)
		dispatchqueue_addr = thread_handle + get_task_dispatchqueue_offset(thread->task);
	else if (thread->task->bsd_info)
		dispatchqueue_addr = thread_handle + get_dispatchqueue_offset_from_proc(thread->task->bsd_info);
	else
		dispatchqueue_addr = 0;

	return dispatchqueue_addr;
}

uint64_t
thread_rettokern_addr(
	thread_t		thread)
{
	uint64_t	rettokern_addr;
	uint64_t	rettokern_offset;
	uint64_t	thread_handle;

	if (thread == THREAD_NULL)
		return 0;

	thread_handle = thread->machine.cthread_self;
	if (thread_handle == 0)
		return 0;

	if (thread->task->bsd_info) {
		rettokern_offset = get_return_to_kernel_offset_from_proc(thread->task->bsd_info);

		/* Return 0 if return to kernel offset is not initialized. */
		if (rettokern_offset == 0) {
			rettokern_addr = 0;
		} else {
			rettokern_addr = thread_handle + rettokern_offset;
		}
	} else {
		rettokern_addr = 0;
	}

	return rettokern_addr;
}

/*
 * Export routines to other components for things that are done as macros
 * within the osfmk component.
 */

#undef thread_mtx_lock
void thread_mtx_lock(thread_t thread);
void
thread_mtx_lock(thread_t thread)
{
	lck_mtx_lock(&thread->mutex);
}

#undef thread_mtx_unlock
void thread_mtx_unlock(thread_t thread);
void
thread_mtx_unlock(thread_t thread)
{
	lck_mtx_unlock(&thread->mutex);
}

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

/*
 * thread_set_voucher_name - reset the voucher port name bound to this thread
 *
 * Conditions:  nothing locked
 *
 *	If we already converted the previous name to a cached voucher
 *	reference, then we discard that reference here.  The next lookup
 *	will cache it again.
 */

kern_return_t
thread_set_voucher_name(mach_port_name_t voucher_name)
{
	thread_t thread = current_thread();
	ipc_voucher_t new_voucher = IPC_VOUCHER_NULL;
	ipc_voucher_t voucher;
	ledger_t bankledger = NULL;
	struct thread_group *banktg = NULL;

	if (MACH_PORT_DEAD == voucher_name)
		return KERN_INVALID_RIGHT;

	/*
	 * agressively convert to voucher reference
	 */
	if (MACH_PORT_VALID(voucher_name)) {
		new_voucher = convert_port_name_to_voucher(voucher_name);
		if (IPC_VOUCHER_NULL == new_voucher)
			return KERN_INVALID_ARGUMENT;
	}
	bank_get_bank_ledger_and_thread_group(new_voucher, &bankledger, &banktg);

	thread_mtx_lock(thread);
	voucher = thread->ith_voucher;
	thread->ith_voucher_name = voucher_name;
	thread->ith_voucher = new_voucher;
	thread_mtx_unlock(thread);

	bank_swap_thread_bank_ledger(thread, bankledger);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				  MACHDBG_CODE(DBG_MACH_IPC,MACH_THREAD_SET_VOUCHER) | DBG_FUNC_NONE,
				  (uintptr_t)thread_tid(thread),
				  (uintptr_t)voucher_name,
				  VM_KERNEL_ADDRPERM((uintptr_t)new_voucher),
				  1, 0);

	if (IPC_VOUCHER_NULL != voucher)
		ipc_voucher_release(voucher);

	return KERN_SUCCESS;
}

/* 
 *  thread_get_mach_voucher - return a voucher reference for the specified thread voucher
 *
 *  Conditions:  nothing locked
 *
 *  A reference to the voucher may be lazily pending, if someone set the voucher name
 *  but nobody has done a lookup yet.  In that case, we'll have to do the equivalent
 *  lookup here.
 *
 *  NOTE:  	At the moment, there is no distinction between the current and effective
 *		vouchers because we only set them at the thread level currently.
 */
kern_return_t 
thread_get_mach_voucher(
	thread_act_t		thread,
	mach_voucher_selector_t __unused which,
	ipc_voucher_t		*voucherp)
{
	ipc_voucher_t	       	voucher;
	mach_port_name_t	voucher_name;

	if (THREAD_NULL == thread)
		return KERN_INVALID_ARGUMENT;

	thread_mtx_lock(thread);
	voucher = thread->ith_voucher;

	/* if already cached, just return a ref */
	if (IPC_VOUCHER_NULL != voucher) {
		ipc_voucher_reference(voucher);
		thread_mtx_unlock(thread);
		*voucherp = voucher;
		return KERN_SUCCESS;
	}

	voucher_name = thread->ith_voucher_name;

	/* convert the name to a port, then voucher reference */
	if (MACH_PORT_VALID(voucher_name)) {
		ipc_port_t port;

		if (KERN_SUCCESS !=
		    ipc_object_copyin(thread->task->itk_space, voucher_name,
				      MACH_MSG_TYPE_COPY_SEND, (ipc_object_t *)&port)) {
			thread->ith_voucher_name = MACH_PORT_NULL;
			thread_mtx_unlock(thread);
			*voucherp = IPC_VOUCHER_NULL;
			return KERN_SUCCESS;
		}

		/* convert to a voucher ref to return, and cache a ref on thread */
		voucher = convert_port_to_voucher(port);
		ipc_voucher_reference(voucher);
		thread->ith_voucher = voucher;
		thread_mtx_unlock(thread);

		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
					  MACHDBG_CODE(DBG_MACH_IPC,MACH_THREAD_SET_VOUCHER) | DBG_FUNC_NONE,
					  (uintptr_t)thread_tid(thread),
					  (uintptr_t)port,
					  VM_KERNEL_ADDRPERM((uintptr_t)voucher),
					  2, 0);


		ipc_port_release_send(port);
	} else
		thread_mtx_unlock(thread);

	*voucherp = voucher;
	return KERN_SUCCESS;
}

/* 
 *  thread_set_mach_voucher - set a voucher reference for the specified thread voucher
 *
 *  Conditions: callers holds a reference on the voucher.
 *		nothing locked.
 *
 *  We grab another reference to the voucher and bind it to the thread.  Any lazy
 *  binding is erased.  The old voucher reference associated with the thread is
 *  discarded.
 */
kern_return_t 
thread_set_mach_voucher(
	thread_t		thread,
	ipc_voucher_t		voucher)
{
	ipc_voucher_t old_voucher;
	ledger_t bankledger = NULL;
	struct thread_group *banktg = NULL;

	if (THREAD_NULL == thread)
		return KERN_INVALID_ARGUMENT;

	if (thread != current_thread() && thread->started)
		return KERN_INVALID_ARGUMENT;

	ipc_voucher_reference(voucher);
	bank_get_bank_ledger_and_thread_group(voucher, &bankledger, &banktg);

	thread_mtx_lock(thread);
	old_voucher = thread->ith_voucher;
	thread->ith_voucher = voucher;
	thread->ith_voucher_name = MACH_PORT_NULL;
	thread_mtx_unlock(thread);

	bank_swap_thread_bank_ledger(thread, bankledger);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				  MACHDBG_CODE(DBG_MACH_IPC,MACH_THREAD_SET_VOUCHER) | DBG_FUNC_NONE,
				  (uintptr_t)thread_tid(thread),
				  (uintptr_t)MACH_PORT_NULL,
				  VM_KERNEL_ADDRPERM((uintptr_t)voucher),
				  3, 0);

	ipc_voucher_release(old_voucher);

	return KERN_SUCCESS;
}

/* 
 *  thread_swap_mach_voucher - swap a voucher reference for the specified thread voucher
 *
 *  Conditions: callers holds a reference on the new and presumed old voucher(s).
 *		nothing locked.
 *
 *  This function is no longer supported.
 */
kern_return_t
thread_swap_mach_voucher(
	__unused thread_t		thread,
	__unused ipc_voucher_t		new_voucher,
	ipc_voucher_t			*in_out_old_voucher)
{
	/*
	 * Currently this function is only called from a MIG generated
	 * routine which doesn't release the reference on the voucher
	 * addressed by in_out_old_voucher. To avoid leaking this reference,
	 * a call to release it has been added here.
	 */
	ipc_voucher_release(*in_out_old_voucher);
	return KERN_NOT_SUPPORTED;
}

/* 
 *  thread_get_current_voucher_origin_pid - get the pid of the originator of the current voucher.
 */
kern_return_t
thread_get_current_voucher_origin_pid(
	int32_t      *pid)
{
	uint32_t buf_size;
	kern_return_t kr;
	thread_t thread = current_thread();
	
	buf_size = sizeof(*pid);
	kr = mach_voucher_attr_command(thread->ith_voucher,
		MACH_VOUCHER_ATTR_KEY_BANK,
		BANK_ORIGINATOR_PID,
		NULL,
		0,
		(mach_voucher_attr_content_t)pid,
		&buf_size);

	return kr;
}


boolean_t
thread_has_thread_name(thread_t th)
{
	if ((th) && (th->uthread)) {
		return bsd_hasthreadname(th->uthread);
	}

	/*
	 * This is an odd case; clients may set the thread name based on the lack of
	 * a name, but in this context there is no uthread to attach the name to.
	 */
	return FALSE;
}

void
thread_set_thread_name(thread_t th, const char* name)
{
	if ((th) && (th->uthread) && name) {
		bsd_setthreadname(th->uthread, name);
	}
}

void
thread_set_honor_qlimit(thread_t thread)
{
	thread->options |= TH_OPT_HONOR_QLIMIT;
}

void
thread_clear_honor_qlimit(thread_t thread)
{
	thread->options &= (~TH_OPT_HONOR_QLIMIT);
}

/*
 * thread_enable_send_importance - set/clear the SEND_IMPORTANCE thread option bit.
 */
void thread_enable_send_importance(thread_t thread, boolean_t enable)
{
	if (enable == TRUE)
		thread->options |= TH_OPT_SEND_IMPORTANCE;
	else
		thread->options &= ~TH_OPT_SEND_IMPORTANCE;
}

/*
 * thread_set_allocation_name - .
 */

kern_allocation_name_t thread_set_allocation_name(kern_allocation_name_t new_name)
{
	kern_allocation_name_t ret;
	thread_kernel_state_t kstate = thread_get_kernel_state(current_thread());
	ret = kstate->allocation_name;
	// fifo
	if (!new_name || !kstate->allocation_name) kstate->allocation_name = new_name;
	return ret;
}

uint64_t
thread_get_last_wait_duration(thread_t thread)
{
	return thread->last_made_runnable_time - thread->last_run_time;
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

int dtrace_get_thread_last_cpu_id(thread_t thread)
{
	if ((thread != THREAD_NULL) && (thread->last_processor != PROCESSOR_NULL)) {
		return thread->last_processor->cpu_id;
	} else {
		return -1;
	}
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

#if KASAN
struct kasan_thread_data *
kasan_get_thread_data(thread_t thread)
{
	return &thread->kasan_data;
}
#endif

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
			KDBG(BSDDBG_CODE(DBG_BSD_PROC,BSD_PROC_EXEC),
			     task_pid(task));
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
