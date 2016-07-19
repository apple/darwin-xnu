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
 *	File:	thread.h
 *	Author:	Avadis Tevanian, Jr.
 *
 *	This file contains the structure definitions for threads.
 *
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

#ifndef	_KERN_THREAD_H_
#define _KERN_THREAD_H_

#include <mach/kern_return.h>
#include <mach/mach_types.h>
#include <mach/message.h>
#include <mach/boolean.h>
#include <mach/vm_param.h>
#include <mach/thread_info.h>
#include <mach/thread_status.h>
#include <mach/exception_types.h>

#include <kern/kern_types.h>

#include <sys/cdefs.h>

#ifdef	MACH_KERNEL_PRIVATE

#include <mach_assert.h>
#include <mach_ldebug.h>

#include <ipc/ipc_types.h>

#include <mach/port.h>
#include <kern/cpu_number.h>
#include <kern/smp.h>
#include <kern/queue.h>
#include <kern/timer.h>
#include <kern/simple_lock.h>
#include <kern/locks.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <mach/sfi_class.h>
#include <kern/thread_call.h>
#include <kern/timer_call.h>
#include <kern/task.h>
#include <kern/exception.h>
#include <kern/affinity.h>

#include <kern/waitq.h>

#include <ipc/ipc_kmsg.h>

#include <machine/cpu_data.h>
#include <machine/thread.h>

struct thread {
	/*
	 *	NOTE:	The runq field in the thread structure has an unusual
	 *	locking protocol.  If its value is PROCESSOR_NULL, then it is
	 *	locked by the thread_lock, but if its value is something else
	 *	then it is locked by the associated run queue lock. It is
	 *	set to PROCESSOR_NULL without holding the thread lock, but the
	 *	transition from PROCESSOR_NULL to non-null must be done
	 *	under the thread lock and the run queue lock.
	 *
	 *	New waitq APIs allow the 'links' and 'runq' fields to be
	 *	anywhere in the thread structure.
	 */
  	/* Items examined often, modified infrequently */
	queue_chain_t	links;				/* run/wait queue links */
	processor_t		runq;				/* run queue assignment */
	event64_t		wait_event;			/* wait queue event */
	struct waitq	*waitq;
	/* Data updated during assert_wait/thread_wakeup */
#if __SMP__
	decl_simple_lock_data(,sched_lock)	/* scheduling lock (thread_lock()) */
	decl_simple_lock_data(,wake_lock)	/* for thread stop / wait (wake_lock()) */
#endif
	integer_t		options;			/* options set by thread itself */
#define TH_OPT_INTMASK		0x0003		/* interrupt / abort level */
#define TH_OPT_VMPRIV		0x0004		/* may allocate reserved memory */
#define TH_OPT_DTRACE		0x0008		/* executing under dtrace_probe */
#define TH_OPT_SYSTEM_CRITICAL	0x0010		/* Thread must always be allowed to run - even under heavy load */
#define TH_OPT_PROC_CPULIMIT	0x0020		/* Thread has a task-wide CPU limit applied to it */
#define TH_OPT_PRVT_CPULIMIT	0x0040		/* Thread has a thread-private CPU limit applied to it */
#define TH_OPT_IDLE_THREAD	0x0080		/* Thread is a per-processor idle thread */
#define TH_OPT_GLOBAL_FORCED_IDLE	0x0100	/* Thread performs forced idle for thermal control */
#define TH_OPT_SCHED_VM_GROUP	0x0200		/* Thread belongs to special scheduler VM group */
#define TH_OPT_HONOR_QLIMIT	0x0400		/* Thread will honor qlimit while sending mach_msg, regardless of MACH_SEND_ALWAYS */
#define TH_OPT_SEND_IMPORTANCE	0x0800		/* Thread will allow importance donation from kernel rpc */

	boolean_t			wake_active;	/* wake event on stop */
	int					at_safe_point;	/* thread_abort_safely allowed */
	ast_t				reason;			/* why we blocked */
	uint32_t 			quantum_remaining;
	wait_result_t 			wait_result; 	/* outcome of wait -
							 * may be examined by this thread
							 * WITHOUT locking */
	thread_continue_t	continuation;	/* continue here next dispatch */
	void				*parameter;		/* continuation parameter */

	/* Data updated/used in thread_invoke */
	vm_offset_t     	kernel_stack;		/* current kernel stack */
	vm_offset_t			reserved_stack;		/* reserved kernel stack */

	/* Thread state: */
	int					state;
/*
 *	Thread states [bits or'ed]
 */
#define TH_WAIT			0x01			/* queued for waiting */
#define TH_SUSP			0x02			/* stopped or requested to stop */
#define TH_RUN			0x04			/* running or on runq */
#define TH_UNINT		0x08			/* waiting uninteruptibly */
#define TH_TERMINATE		0x10			/* halted at termination */
#define TH_TERMINATE2		0x20			/* added to termination queue */

#define TH_IDLE			0x80			/* idling processor */

	/* Scheduling information */
	sched_mode_t			sched_mode;		/* scheduling mode */
	sched_mode_t			saved_mode;		/* saved mode during forced mode demotion */

	sfi_class_id_t			sfi_class;		/* SFI class (XXX Updated on CSW/QE/AST) */
	sfi_class_id_t			sfi_wait_class;	/* Currently in SFI wait for this class, protected by sfi_lock */
	
	uint32_t			sched_flags;		/* current flag bits */
/* TH_SFLAG_FAIRSHARE_TRIPPED (unused)	0x0001 */
#define TH_SFLAG_FAILSAFE		0x0002		/* fail-safe has tripped */
#define TH_SFLAG_THROTTLED		0x0004		/* thread treated as background for scheduler decay purposes */
#define TH_SFLAG_DEMOTED_MASK      (TH_SFLAG_THROTTLE_DEMOTED | TH_SFLAG_FAILSAFE)	/* saved_mode contains previous sched_mode */

#define	TH_SFLAG_PROMOTED		0x0008		/* sched pri has been promoted */
#define TH_SFLAG_ABORT			0x0010		/* abort interruptible waits */
#define TH_SFLAG_ABORTSAFELY		0x0020		/* ... but only those at safe point */
#define TH_SFLAG_ABORTED_MASK		(TH_SFLAG_ABORT | TH_SFLAG_ABORTSAFELY)
#define	TH_SFLAG_DEPRESS		0x0040		/* normal depress yield */
#define TH_SFLAG_POLLDEPRESS		0x0080		/* polled depress yield */
#define TH_SFLAG_DEPRESSED_MASK		(TH_SFLAG_DEPRESS | TH_SFLAG_POLLDEPRESS)
#define TH_SFLAG_PRI_UPDATE		0x0100		/* Updating priority */
#define TH_SFLAG_EAGERPREEMPT		0x0200		/* Any preemption of this thread should be treated as if AST_URGENT applied */
#define TH_SFLAG_RW_PROMOTED		0x0400		/* sched pri has been promoted due to blocking with RW lock held */
#define TH_SFLAG_THROTTLE_DEMOTED	0x0800		/* throttled thread forced to timeshare mode (may be applied in addition to failsafe) */
#define TH_SFLAG_WAITQ_PROMOTED		0x1000		/* sched pri promoted from waitq wakeup (generally for IPC receive) */
#define TH_SFLAG_PROMOTED_MASK		(TH_SFLAG_PROMOTED | TH_SFLAG_RW_PROMOTED | TH_SFLAG_WAITQ_PROMOTED)

#define TH_SFLAG_RW_PROMOTED_BIT	(10)	/* 0x400 */

	int16_t                         sched_pri;              /* scheduled (current) priority */
	int16_t                         base_pri;               /* base priority */
	int16_t                         max_priority;           /* copy of max base priority */
	int16_t                         task_priority;          /* copy of task base priority */

#if defined(CONFIG_SCHED_GRRR)
#if 0
	uint16_t			grrr_deficit;		/* fixed point (1/1000th quantum) fractional deficit */
#endif
#endif
	
	int16_t				promotions;			/* level of promotion */
	int16_t				pending_promoter_index;
	uint32_t			ref_count;		/* number of references to me */
	void				*pending_promoter[2];

	uint32_t			rwlock_count;	/* Number of lck_rw_t locks held by thread */

#if MACH_ASSERT
	uint32_t			SHARE_COUNT, BG_COUNT; /* This thread's contribution to global sched counters (temporary debugging) */
#endif /* MACH_ASSERT */

	integer_t			importance;			/* task-relative importance */
	uint32_t                        was_promoted_on_wakeup;

	/* Priority depression expiration */
	integer_t			depress_timer_active;
	timer_call_data_t	depress_timer;
										/* real-time parameters */
	struct {								/* see mach/thread_policy.h */
		uint32_t			period;
		uint32_t			computation;
		uint32_t			constraint;
		boolean_t			preemptible;
		uint64_t			deadline;
	}					realtime;

	uint64_t			last_run_time;		/* time when thread was switched away from */
	uint64_t			last_made_runnable_time;	/* time when thread was unblocked or preempted */

#if defined(CONFIG_SCHED_MULTIQ)
	sched_group_t			sched_group;
#endif /* defined(CONFIG_SCHED_MULTIQ) */

  /* Data used during setrun/dispatch */
	timer_data_t		system_timer;		/* system mode timer */
	processor_t			bound_processor;	/* bound to a processor? */
	processor_t			last_processor;		/* processor last dispatched on */
	processor_t			chosen_processor;	/* Where we want to run this thread */

	/* Fail-safe computation since last unblock or qualifying yield */
	uint64_t			computation_metered;
	uint64_t			computation_epoch;
	uint64_t			safe_release;	/* when to release fail-safe */

	/* Call out from scheduler */
	void				(*sched_call)(
							int			type,
							thread_t	thread);
#if defined(CONFIG_SCHED_PROTO)
	uint32_t			runqueue_generation;	/* last time runqueue was drained */
#endif
	
	/* Statistics and timesharing calculations */
#if defined(CONFIG_SCHED_TIMESHARE_CORE)
	natural_t			sched_stamp;	/* last scheduler tick */
	natural_t			sched_usage;	/* timesharing cpu usage [sched] */
	natural_t			pri_shift;		/* usage -> priority from pset */
	natural_t			cpu_usage;		/* instrumented cpu usage [%cpu] */
	natural_t			cpu_delta;		/* accumulated cpu_usage delta */
#endif /* CONFIG_SCHED_TIMESHARE_CORE */

	uint32_t			c_switch;		/* total context switches */
	uint32_t			p_switch;		/* total processor switches */
	uint32_t			ps_switch;		/* total pset switches */

	integer_t mutex_count;  /* total count of locks held */
	/* Timing data structures */
	int					precise_user_kernel_time; /* precise user/kernel enabled for this thread */
	timer_data_t		user_timer;			/* user mode timer */
	uint64_t			user_timer_save;	/* saved user timer value */
	uint64_t			system_timer_save;	/* saved system timer value */
	uint64_t			vtimer_user_save;	/* saved values for vtimers */
	uint64_t			vtimer_prof_save;
	uint64_t			vtimer_rlim_save;

#if CONFIG_SCHED_SFI
	/* Timing for wait state */
	uint64_t		wait_sfi_begin_time;    /* start time for thread waiting in SFI */
#endif

	/* Timed wait expiration */
	timer_call_data_t	wait_timer;
	integer_t			wait_timer_active;
	boolean_t			wait_timer_is_set;


	/*
	 * Processor/cache affinity
	 * - affinity_threads links task threads with the same affinity set
	 */
	affinity_set_t			affinity_set;
	queue_chain_t			affinity_threads;

	/* Various bits of stashed state */
	union {
		struct {
		  	mach_msg_return_t	state;		/* receive state */
			mach_port_seqno_t	seqno;		/* seqno of recvd message */
		  	ipc_object_t		object;		/* object received on */
		  	mach_vm_address_t	msg_addr;	/* receive buffer pointer */
			mach_msg_size_t		msize;		/* max size for recvd msg */
		  	mach_msg_option_t	option;		/* options for receive */
			mach_port_name_t	receiver_name;	/* the receive port name */
			struct ipc_kmsg		*kmsg;		/* received message */
			mach_msg_continue_t	continuation;
		} receive;
		struct {
			struct semaphore	*waitsemaphore;  	/* semaphore ref */
			struct semaphore	*signalsemaphore;	/* semaphore ref */
			int					options;			/* semaphore options */
			kern_return_t		result;				/* primary result */
			mach_msg_continue_t continuation;
		} sema;
	  	struct {
			int					option;		/* switch option */
			boolean_t				reenable_workq_callback;	/* on entry, callbacks were suspended */
		} swtch;
		int						misc;		/* catch-all for other state */
	} saved;

	/* Structure to save information about guard exception */
	struct {
		unsigned				type;		/* EXC_GUARD reason/type */
		mach_exception_data_type_t		code;		/* Exception code */
		mach_exception_data_type_t		subcode;	/* Exception sub-code */
	} guard_exc_info;

	/* Kernel holds on this thread  */
	int16_t                                         suspend_count;
	/* User level suspensions */
	int16_t                                         user_stop_count;

	/* IPC data structures */
#if IMPORTANCE_INHERITANCE
	natural_t ith_assertions;			/* assertions pending drop */
#endif
	struct ipc_kmsg_queue ith_messages;		/* messages to reap */
	mach_port_t ith_rpc_reply;			/* reply port for kernel RPCs */

	/* Ast/Halt data structures */
	vm_offset_t					recover;		/* page fault recover(copyin/out) */

	queue_chain_t				threads;		/* global list of all threads */

	/* Activation */
		queue_chain_t			task_threads;

		/* Task membership */
		struct task				*task;
		vm_map_t				map;

		decl_lck_mtx_data(,mutex)


		/* Pending thread ast(s) */
		ast_t					ast;

		/* Miscellaneous bits guarded by mutex */
		uint32_t
			active:1,				/* Thread is active and has not been terminated */
			started:1,				/* Thread has been started after creation */
			static_param:1,			/* Disallow policy parameter changes */
		 	inspection:1,				/* TRUE when task is being inspected by crash reporter */
			policy_reset:1,			/* Disallow policy parameter changes on terminating threads */
			:0;
	
		/* Ports associated with this thread */
		struct ipc_port			*ith_self;		/* not a right, doesn't hold ref */
		struct ipc_port			*ith_sself;		/* a send right */
		struct exception_action	*exc_actions;

#ifdef	MACH_BSD
		void					*uthread;
#endif

#if CONFIG_DTRACE
		uint32_t t_dtrace_flags;	/* DTrace thread states */
#define	TH_DTRACE_EXECSUCCESS	0x01
		uint32_t t_dtrace_predcache;/* DTrace per thread predicate value hint */
		int64_t t_dtrace_tracing;       /* Thread time under dtrace_probe() */
		int64_t t_dtrace_vtime;
#endif

	        clock_sec_t t_page_creation_time;
	        uint32_t    t_page_creation_count;
	        uint32_t    t_page_creation_throttled;
#if (DEVELOPMENT || DEBUG)
	        uint64_t    t_page_creation_throttled_hard;
	        uint64_t    t_page_creation_throttled_soft;
#endif /* DEVELOPMENT || DEBUG */

#define T_CHUD_MARKED           0x01          /* this thread is marked by CHUD */
#define T_IN_CHUD               0x02          /* this thread is already in a CHUD handler */
#define THREAD_PMC_FLAG         0x04          /* Bit in "t_chud" signifying PMC interest */	
#define T_AST_CALLSTACK         0x08          /* Thread scheduled to dump a
					       * callstack on its next
					       * AST */
#define T_AST_NAME              0x10          /* Thread scheduled to dump
					       * its name on its next
					       * AST */
#define T_NAME_DONE             0x20          /* Thread has previously
					       * recorded its name */
#define T_KPC_ALLOC             0x40          /* Thread needs a kpc_buf */

		uint32_t t_chud;	/* CHUD flags, used for Shark */
		uint32_t chud_c_switch; /* last dispatch detection */

#ifdef KPC
	/* accumulated performance counters for this thread */
	uint64_t *kpc_buf;
#endif

#ifdef KPERF
	/* count of how many times a thread has been sampled since it was last scheduled */
	uint64_t kperf_pet_cnt;
#endif

#if HYPERVISOR
	/* hypervisor virtual CPU object associated with this thread */
	void *hv_thread_target;
#endif /* HYPERVISOR */

		uint64_t thread_id;	/*system wide unique thread-id*/

	/* Statistics accumulated per-thread and aggregated per-task */
	uint32_t		syscalls_unix;
	uint32_t		syscalls_mach;
	ledger_t		t_ledger;
	ledger_t		t_threadledger;	/* per thread ledger */
	uint64_t 		cpu_time_last_qos;
#ifdef CONFIG_BANK
	ledger_t		t_bankledger;  		   /* ledger to charge someone */
	uint64_t		t_deduct_bank_ledger_time; /* cpu time to be deducted from bank ledger */
#endif

	/* policy is protected by the task lock */
	struct task_requested_policy     requested_policy;
	struct task_effective_policy     effective_policy;
	struct task_pended_policy        pended_policy;

	/* usynch override is protected by the task lock, eventually will be thread mutex */
	struct thread_qos_override {
		struct thread_qos_override	*override_next;
		uint32_t	override_contended_resource_count;
		int16_t		override_qos;
		int16_t		override_resource_type;
		user_addr_t	override_resource;
	} *overrides;

	int	iotier_override; /* atomic operations to set, cleared on ret to user */
	integer_t               saved_importance;               /* saved task-relative importance */
	io_stat_info_t  		thread_io_stats; /* per-thread I/O statistics */


	uint32_t			thread_callout_interrupt_wakeups;
	uint32_t			thread_callout_platform_idle_wakeups;
	uint32_t			thread_timer_wakeups_bin_1;
	uint32_t			thread_timer_wakeups_bin_2;
	uint16_t			thread_tag;
	uint16_t			callout_woken_from_icontext:1,
					callout_woken_from_platform_idle:1,
					callout_woke_thread:1,
					thread_bitfield_unused:13;

	mach_port_name_t		ith_voucher_name;
	ipc_voucher_t			ith_voucher;
#if CONFIG_IOSCHED
	void 				*decmp_upl;
#endif /* CONFIG_IOSCHED */

	/* work interval ID (if any) associated with the thread. Uses thread mutex */
	uint64_t		work_interval_id;

	/*** Machine-dependent state ***/
	struct machine_thread   machine;
};

#define ith_state		saved.receive.state
#define ith_object		saved.receive.object
#define ith_msg_addr			saved.receive.msg_addr
#define ith_msize		saved.receive.msize
#define	ith_option		saved.receive.option
#define ith_receiver_name	saved.receive.receiver_name
#define ith_continuation	saved.receive.continuation
#define ith_kmsg		saved.receive.kmsg
#define ith_seqno		saved.receive.seqno

#define sth_waitsemaphore	saved.sema.waitsemaphore
#define sth_signalsemaphore	saved.sema.signalsemaphore
#define sth_options		saved.sema.options
#define sth_result		saved.sema.result
#define sth_continuation	saved.sema.continuation

extern void			thread_bootstrap(void);

extern void			thread_init(void);

extern void			thread_daemon_init(void);

#define	thread_reference_internal(thread)	\
			(void)hw_atomic_add(&(thread)->ref_count, 1)

#define thread_reference(thread)					\
MACRO_BEGIN											\
	if ((thread) != THREAD_NULL)					\
		thread_reference_internal(thread);		\
MACRO_END

extern void			thread_deallocate(
						thread_t		thread);

extern void			thread_deallocate_safe(
						thread_t		thread);

extern void			thread_terminate_self(void);

extern kern_return_t	thread_terminate_internal(
							thread_t		thread);

extern void			thread_start_internal(
							thread_t			thread) __attribute__ ((noinline));

extern void			thread_terminate_enqueue(
						thread_t		thread);

extern void			thread_terminate_crashed_threads(void);

extern void			thread_stack_enqueue(
						thread_t		thread);

extern void			thread_hold(
						thread_t	thread);

extern void			thread_release(
						thread_t	thread);

/* Locking for scheduler state, always acquired with interrupts disabled (splsched()) */
#if __SMP__
#define	thread_lock_init(th)	simple_lock_init(&(th)->sched_lock, 0)
#define thread_lock(th)			simple_lock(&(th)->sched_lock)
#define thread_unlock(th)		simple_unlock(&(th)->sched_lock)

#define wake_lock_init(th)		simple_lock_init(&(th)->wake_lock, 0)
#define wake_lock(th)			simple_lock(&(th)->wake_lock)
#define wake_unlock(th)			simple_unlock(&(th)->wake_lock)
#else
#define thread_lock_init(th)	do { (void)th; } while(0)
#define thread_lock(th)			do { (void)th; } while(0)
#define thread_unlock(th)		do { (void)th; } while(0)

#define wake_lock_init(th)		do { (void)th; } while(0)
#define wake_lock(th)			do { (void)th; } while(0)
#define wake_unlock(th)			do { (void)th; } while(0)
#endif

#define thread_should_halt_fast(thread)		(!(thread)->active)

extern void				stack_alloc(
							thread_t		thread);

extern void			stack_handoff(
					      		thread_t		from,
							thread_t		to);

extern void				stack_free(
							thread_t		thread);

extern void				stack_free_reserved(
							thread_t		thread);

extern boolean_t		stack_alloc_try(
							thread_t	    thread);

extern void				stack_collect(void);

extern void				stack_init(void);


extern kern_return_t	thread_info_internal(
							thread_t				thread,
							thread_flavor_t			flavor,
							thread_info_t			thread_info_out,
							mach_msg_type_number_t	*thread_info_count);

extern void				thread_task_priority(
							thread_t		thread,
							integer_t		priority,
							integer_t		max_priority);

extern kern_return_t                    thread_set_mode_and_absolute_pri(
                                                        thread_t       thread,
                                                        integer_t      policy,
                                                        integer_t      priority);

extern void				thread_policy_reset(
							thread_t		thread);

extern kern_return_t	kernel_thread_create(
							thread_continue_t	continuation,
							void				*parameter,
							integer_t			priority,
							thread_t			*new_thread);

extern kern_return_t	kernel_thread_start_priority(
							thread_continue_t	continuation,
							void				*parameter,
							integer_t			priority,
							thread_t			*new_thread);

extern void				machine_stack_attach(
							thread_t		thread,
							vm_offset_t		stack);

extern vm_offset_t		machine_stack_detach(
							thread_t		thread);

extern void				machine_stack_handoff(
							thread_t		old,
							thread_t		new);

extern thread_t			machine_switch_context(
							thread_t			old_thread,
							thread_continue_t	continuation,
							thread_t			new_thread);

extern void				machine_load_context(
							thread_t		thread);

extern kern_return_t	machine_thread_state_initialize(
							thread_t				thread);

extern kern_return_t	machine_thread_neon_state_initialize(
							thread_t				thread);

extern kern_return_t	machine_thread_set_state(
							thread_t				thread,
							thread_flavor_t			flavor,
							thread_state_t			state,
							mach_msg_type_number_t	count);

extern kern_return_t	machine_thread_get_state(
							thread_t				thread,
							thread_flavor_t			flavor,
							thread_state_t			state,
							mach_msg_type_number_t	*count);

extern kern_return_t	machine_thread_dup(
							thread_t		self,
							thread_t		target);

extern void				machine_thread_init(void);

extern kern_return_t	machine_thread_create(
							thread_t		thread,
							task_t			task);
extern void		machine_thread_switch_addrmode(
						       thread_t			thread);

extern void 		    machine_thread_destroy(
							thread_t		thread);

extern void				machine_set_current_thread(
							thread_t			thread);

extern kern_return_t	machine_thread_get_kern_state(
							thread_t				thread,
							thread_flavor_t			flavor,
							thread_state_t			tstate,
							mach_msg_type_number_t	*count);

extern kern_return_t	machine_thread_inherit_taskwide(
							thread_t		thread,
							task_t			parent_task);

extern kern_return_t	machine_thread_set_tsd_base(
							thread_t				thread,
							mach_vm_offset_t		tsd_base);

#define	thread_mtx_lock(thread)			lck_mtx_lock(&(thread)->mutex)
#define	thread_mtx_try(thread)			lck_mtx_try_lock(&(thread)->mutex)
#define	thread_mtx_unlock(thread)		lck_mtx_unlock(&(thread)->mutex)

extern void			install_special_handler(
						thread_t		thread);

extern void			special_handler(
						thread_t		thread);

extern void
thread_update_qos_cpu_time(
			thread_t thread,
			boolean_t lock_needed);

void act_machine_sv_free(thread_t, int);

vm_offset_t			min_valid_stack_address(void);
vm_offset_t			max_valid_stack_address(void);

static inline uint16_t	thread_set_tag_internal(thread_t	thread, uint16_t tag) {
	return __sync_fetch_and_or(&thread->thread_tag, tag);
}

static inline uint16_t	thread_get_tag_internal(thread_t	thread) {
	return thread->thread_tag;
}

typedef struct {
	int             qos_pri[THREAD_QOS_LAST];
	int             qos_iotier[THREAD_QOS_LAST];
	uint32_t        qos_through_qos[THREAD_QOS_LAST];
	uint32_t        qos_latency_qos[THREAD_QOS_LAST];
} qos_policy_params_t;

extern void thread_set_options(uint32_t thopt);

#else	/* MACH_KERNEL_PRIVATE */

__BEGIN_DECLS

extern thread_t		current_thread(void);

extern void			thread_reference(
						thread_t	thread);

extern void			thread_deallocate(
						thread_t	thread);

__END_DECLS

#endif	/* MACH_KERNEL_PRIVATE */

#ifdef	KERNEL_PRIVATE

__BEGIN_DECLS

extern uint64_t	 		thread_dispatchqaddr(
						thread_t thread);

__END_DECLS

#endif	/* KERNEL_PRIVATE */

#ifdef KERNEL
__BEGIN_DECLS

extern uint64_t	 		thread_tid(thread_t thread);

__END_DECLS

#endif  /* KERNEL */

__BEGIN_DECLS

#ifdef	XNU_KERNEL_PRIVATE

/*
 * Thread tags; for easy identification.
 */
#define	THREAD_TAG_MAINTHREAD 0x1
#define	THREAD_TAG_CALLOUT 0x2
#define	THREAD_TAG_IOWORKLOOP 0x4

uint16_t	thread_set_tag(thread_t, uint16_t);
uint16_t	thread_get_tag(thread_t);

/*
 * Allocate/assign a single work interval ID for a thread,
 * and support deallocating it.
 */
extern kern_return_t			thread_policy_create_work_interval(
	thread_t		thread,
	uint64_t		*work_interval_id);

extern kern_return_t			thread_policy_destroy_work_interval(
	thread_t		thread,
	uint64_t		work_interval_id);

extern kern_return_t    thread_state_initialize(
							thread_t				thread);

extern kern_return_t	thread_setstatus(
							thread_t				thread,
							int						flavor,
							thread_state_t			tstate,
							mach_msg_type_number_t	count);

extern kern_return_t	thread_getstatus(
							thread_t				thread,
							int						flavor,
							thread_state_t			tstate,
							mach_msg_type_number_t	*count);

extern kern_return_t	thread_create_with_continuation(
							task_t task,
							thread_t *new_thread,
							thread_continue_t continuation);

extern kern_return_t	thread_create_workq(
							task_t			task,
							thread_continue_t	thread_return,
							thread_t		*new_thread);

extern	void	thread_yield_internal(
	mach_msg_timeout_t	interval);

/*
 * Thread-private CPU limits: apply a private CPU limit to this thread only. Available actions are:
 * 
 * 1) Block. Prevent CPU consumption of the thread from exceeding the limit.
 * 2) Exception. Generate a resource consumption exception when the limit is exceeded.
 * 3) Disable. Remove any existing CPU limit.
 */
#define THREAD_CPULIMIT_BLOCK		0x1
#define THREAD_CPULIMIT_EXCEPTION	0x2
#define	THREAD_CPULIMIT_DISABLE		0x3

struct _thread_ledger_indices {
	int cpu_time;
};

extern struct _thread_ledger_indices thread_ledgers;

extern int thread_get_cpulimit(int *action, uint8_t *percentage, uint64_t *interval_ns);
extern int thread_set_cpulimit(int action, uint8_t percentage, uint64_t interval_ns);

extern void			thread_read_times(
						thread_t 		thread,
						time_value_t	*user_time,
						time_value_t	*system_time);

extern uint64_t		thread_get_runtime_self(void);

extern void			thread_setuserstack(
						thread_t		thread,
						mach_vm_offset_t	user_stack);

extern uint64_t		thread_adjuserstack(
						thread_t		thread,
						int				adjust);

extern void			thread_setentrypoint(
						thread_t		thread,
						mach_vm_offset_t	entry);

extern kern_return_t	thread_set_tsd_base(
							thread_t	thread,
							mach_vm_offset_t tsd_base);

extern kern_return_t	thread_setsinglestep(
						thread_t		thread,
						int			on);

extern kern_return_t	thread_userstack(
						thread_t,
						int,
						thread_state_t,
						unsigned int,
						mach_vm_offset_t *,
						int *);

extern kern_return_t	thread_entrypoint(
						thread_t,
						int,
						thread_state_t,
						unsigned int,
						mach_vm_offset_t *); 

extern kern_return_t	thread_userstackdefault(
						thread_t,
						mach_vm_offset_t *);

extern kern_return_t	thread_wire_internal(
							host_priv_t		host_priv,
							thread_t		thread,
							boolean_t		wired,
							boolean_t		*prev_state);


extern kern_return_t	thread_dup(thread_t);

typedef void	(*sched_call_t)(
					int				type,
					thread_t		thread);

#define SCHED_CALL_BLOCK		0x1
#define SCHED_CALL_UNBLOCK		0x2

extern void		thread_sched_call(
					thread_t		thread,
					sched_call_t	call);

extern void		thread_static_param(
					thread_t		thread,
					boolean_t		state);

extern boolean_t	thread_is_static_param(
					thread_t		thread);

extern kern_return_t	thread_policy_set_internal(
	                                thread_t		thread,
					thread_policy_flavor_t	flavor,
					thread_policy_t		policy_info,
					mach_msg_type_number_t	count);

extern boolean_t thread_has_qos_policy(thread_t thread);

extern kern_return_t thread_remove_qos_policy(thread_t thread);

extern task_t	get_threadtask(thread_t);
#define thread_is_64bit(thd)	\
	task_has_64BitAddr(get_threadtask(thd))


extern void		*get_bsdthread_info(thread_t);
extern void		set_bsdthread_info(thread_t, void *);
extern void		*uthread_alloc(task_t, thread_t, int);
extern void		uthread_cleanup_name(void *uthread);
extern void		uthread_cleanup(task_t, void *, void *, boolean_t);
extern void		uthread_zone_free(void *); 
extern void		uthread_cred_free(void *);

#if PROC_REF_DEBUG
extern int		uthread_get_proc_refcount(void *);
extern void		uthread_reset_proc_refcount(void *);
extern int		proc_ref_tracking_disabled;
#endif

extern boolean_t	thread_should_halt(
						thread_t		thread);

extern boolean_t	thread_should_abort(
						thread_t);

extern int is_64signalregset(void);

extern void act_set_kperf(thread_t);
extern void set_astledger(thread_t thread);

extern uint32_t dtrace_get_thread_predcache(thread_t);
extern int64_t dtrace_get_thread_vtime(thread_t);
extern int64_t dtrace_get_thread_tracing(thread_t);
extern boolean_t dtrace_get_thread_reentering(thread_t);
extern int dtrace_get_thread_last_cpu_id(thread_t);
extern vm_offset_t dtrace_get_kernel_stack(thread_t);
extern void dtrace_set_thread_predcache(thread_t, uint32_t);
extern void dtrace_set_thread_vtime(thread_t, int64_t);
extern void dtrace_set_thread_tracing(thread_t, int64_t);
extern void dtrace_set_thread_reentering(thread_t, boolean_t);
extern vm_offset_t dtrace_set_thread_recover(thread_t, vm_offset_t);
extern void dtrace_thread_bootstrap(void);
extern void dtrace_thread_didexec(thread_t);

extern int64_t dtrace_calc_thread_recent_vtime(thread_t);


extern kern_return_t	thread_set_wq_state32(
					      thread_t          thread,
					      thread_state_t    tstate);

extern kern_return_t	thread_set_wq_state64(
					      thread_t          thread,
					      thread_state_t    tstate);

extern vm_offset_t	kernel_stack_mask;
extern vm_offset_t	kernel_stack_size;
extern vm_offset_t	kernel_stack_depth_max;

void guard_ast(thread_t thread);
extern void fd_guard_ast(thread_t thread);
extern void mach_port_guard_ast(thread_t thread);
extern void thread_guard_violation(thread_t thread, unsigned type);
extern void thread_update_io_stats(thread_t thread, int size, int io_flags);

extern kern_return_t	thread_set_voucher_name(mach_port_name_t name);
extern kern_return_t thread_get_current_voucher_origin_pid(int32_t *pid);

extern void set_thread_rwlock_boost(void);
extern void clear_thread_rwlock_boost(void);

extern void thread_enable_send_importance(thread_t thread, boolean_t enable);

#endif	/* XNU_KERNEL_PRIVATE */


/*! @function kernel_thread_start
    @abstract Create a kernel thread.
    @discussion This function takes three input parameters, namely reference to the function that the thread should execute, caller specified data and a reference which is used to return the newly created kernel thread. The function returns KERN_SUCCESS on success or an appropriate kernel code type indicating the error. It may be noted that the caller is responsible for explicitly releasing the reference to the created thread when no longer needed. This should be done by calling thread_deallocate(new_thread).
    @param continuation A C-function pointer where the thread will begin execution.
    @param parameter Caller specified data to be passed to the new thread.
    @param new_thread Reference to the new thread is returned in this parameter.
    @result Returns KERN_SUCCESS on success or an appropriate kernel code type.
*/

extern kern_return_t	kernel_thread_start(
							thread_continue_t	continuation,
							void				*parameter,
							thread_t			*new_thread);
#ifdef KERNEL_PRIVATE
void thread_set_eager_preempt(thread_t thread);
void thread_clear_eager_preempt(thread_t thread);
extern ipc_port_t convert_thread_to_port(thread_t);
extern boolean_t set_vm_privilege(boolean_t);
#endif /* KERNEL_PRIVATE */

__END_DECLS

#endif	/* _KERN_THREAD_H_ */
