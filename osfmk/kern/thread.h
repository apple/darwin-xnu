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
#include <mach/vm_types.h>
#include <mach/vm_prot.h>
#include <mach/thread_info.h>
#include <mach/thread_status.h>

#include <kern/cpu_data.h>		/* for current_thread */
#include <kern/kern_types.h>

#include <ipc/ipc_types.h>

/*
 * Logically, a thread of control consists of two parts:
 *
 *	a thread_shuttle, which may migrate due to resource contention
 * and
 *	a thread_activation, which remains attached to a task.
 *
 * The thread_shuttle contains scheduling info, accounting info,
 * and links to the thread_activation within which the shuttle is
 * currently operating.
 *
 * It might make sense to have the thread_shuttle be a proper sub-structure
 * of the thread, with the thread containing links to both the shuttle and
 * activation.  In order to reduce the scope and complexity of source
 * changes and the overhead of maintaining these linkages, we have subsumed
 * the shuttle into the thread, calling it a thread_shuttle.
 *
 * User accesses to threads always come in via the user's thread port,
 * which gets translated to a pointer to the target thread_activation.
 */
#include <sys/appleapiopts.h>

#ifdef	__APPLE_API_PRIVATE

#ifdef	MACH_KERNEL_PRIVATE

#include <cpus.h>
#include <hw_footprint.h>
#include <mach_host.h>
#include <mach_prof.h>
#include <mach_lock_mon.h>
#include <mach_ldebug.h>

#include <mach/port.h>
#include <kern/ast.h>
#include <kern/cpu_number.h>
#include <kern/queue.h>
#include <kern/time_out.h>
#include <kern/timer.h>
#include <kern/lock.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/thread_call.h>
#include <kern/timer_call.h>
#include <kern/task.h>
#include <ipc/ipc_kmsg.h>
#include <machine/thread.h>

/*
 * Kernel accesses intended to effect the entire thread, typically use
 * a pointer to the thread_shuttle (current_thread()) as the target of
 * their operations.  This makes sense given that we have subsumed the
 * shuttle into the thread_shuttle, eliminating one set of linkages.
 * Operations effecting only the shuttle may use a thread_shuttle_t
 * to indicate this.
 *
 * The current_act() macro returns a pointer to the current thread_act, while
 * the current_thread() macro returns a pointer to the currently active
 * thread_shuttle (representing the thread in its entirety).
 */
struct thread_shuttle {
	/*
	 *	NOTE:	The runq field in the thread structure has an unusual
	 *	locking protocol.  If its value is RUN_QUEUE_NULL, then it is
	 *	locked by the thread_lock, but if its value is something else
	 *	(i.e. a run_queue) then it is locked by that run_queue's lock.
	 *
	 *	Beginning of thread_shuttle proper.  When the thread is on
	 *	a wait queue, these first three fields are treated as an un-
	 *	official union with a wait_queue_element.  If you change
	 *	these, you must change that definition as well (wait_queue.h).
	 */
  	/* Items examined often, modified infrequently */
	queue_chain_t	links;				/* run/wait queue links */
	run_queue_t		runq;				/* run queue thread is on SEE BELOW */
	wait_queue_t	wait_queue;			/* wait queue we are currently on */
	event64_t		wait_event;			/* wait queue event */
	thread_act_t	top_act;			/* "current" thr_act */
	uint32_t							/* Only set by thread itself */
						interrupt_level:2,	/* interrupts/aborts allowed */
						vm_privilege:1,		/* can use reserved memory? */
						active_callout:1,	/* an active callout */
						:0;


	/* Data updated during assert_wait/thread_wakeup */
	decl_simple_lock_data(,lock)		/* scheduling lock (thread_lock()) */
	decl_simple_lock_data(,wake_lock)	/* covers wake_active (wake_lock())*/
	boolean_t			wake_active;	/* Someone is waiting for this */
	int					at_safe_point;	/* thread_abort_safely allowed */
	ast_t				reason;			/* why we blocked */
	wait_result_t		wait_result;	/* outcome of wait -
										 * may be examined by this thread
										 * WITHOUT locking */
	thread_roust_t 		roust;			/* routine to roust it after wait */
	thread_continue_t	continuation;	/* resume here next dispatch */

	/* Data updated/used in thread_invoke */
    struct funnel_lock	*funnel_lock;		/* Non-reentrancy funnel */
    int				    funnel_state;
#define TH_FN_OWNED			0x1				/* we own the funnel */
#define TH_FN_REFUNNEL		0x2				/* re-acquire funnel on dispatch */

	vm_offset_t     	kernel_stack;		/* current kernel stack */
	vm_offset_t			stack_privilege;	/* reserved kernel stack */

	/* Thread state: */
	int					state;
/*
 *	Thread states [bits or'ed]
 */
#define TH_WAIT			0x01			/* thread is queued for waiting */
#define TH_SUSP			0x02			/* thread has been asked to stop */
#define TH_RUN			0x04			/* thread is running or on runq */
#define TH_UNINT		0x08			/* thread is waiting uninteruptibly */
#define	TH_TERMINATE	0x10			/* thread is halting at termination */

#define TH_ABORT		0x20	/* abort interruptible waits */
#define TH_ABORT_SAFELY	0x40	/* ... but only those at safe point */

#define TH_IDLE			0x80			/* thread is an idle thread */

#define	TH_SCHED_STATE	(TH_WAIT|TH_SUSP|TH_RUN|TH_UNINT)

#define	TH_STACK_HANDOFF	0x0100		/* thread has no kernel stack */
#define	TH_STACK_ALLOC		0x0200		/* waiting for stack allocation */
#define	TH_STACK_STATE	(TH_STACK_HANDOFF | TH_STACK_ALLOC)

	/* Scheduling information */
	integer_t			sched_mode;			/* scheduling mode bits */
#define TH_MODE_REALTIME		0x0001		/* time constraints supplied */
#define TH_MODE_TIMESHARE		0x0002		/* use timesharing algorithm */
#define TH_MODE_PREEMPT			0x0004		/* can preempt kernel contexts */
#define TH_MODE_FAILSAFE		0x0008		/* fail-safe has tripped */
#define	TH_MODE_PROMOTED		0x0010		/* sched pri has been promoted */
#define	TH_MODE_FORCEDPREEMPT	0x0020		/* force setting of mode PREEMPT */
#define	TH_MODE_DEPRESS			0x0040		/* normal depress yield */
#define TH_MODE_POLLDEPRESS		0x0080		/* polled depress yield */
#define TH_MODE_ISDEPRESSED		(TH_MODE_DEPRESS | TH_MODE_POLLDEPRESS)

	integer_t			sched_pri;			/* scheduled (current) priority */
	integer_t			priority;			/* base priority */
	integer_t			max_priority;		/* max base priority */
	integer_t			task_priority;		/* copy of task base priority */

	integer_t			promotions;			/* level of promotion */
	integer_t			pending_promoter_index;
	void				*pending_promoter[2];

	integer_t			importance;			/* task-relative importance */

											/* time constraint parameters */
	struct {								/* see mach/thread_policy.h */
		uint32_t			period;
		uint32_t			computation;
		uint32_t			constraint;
		boolean_t			preemptible;
	}					realtime;

	uint32_t			current_quantum;	/* duration of current quantum */

  /* Data used during setrun/dispatch */
	timer_data_t		system_timer;		/* system mode timer */
	processor_set_t		processor_set;		/* assigned processor set */
	processor_t			bound_processor;	/* bound to a processor? */
	processor_t			last_processor;		/* processor last dispatched on */
	uint64_t			last_switch;		/* time of last context switch */

	/* Fail-safe computation since last unblock or qualifying yield */
	uint64_t			computation_metered;
	uint64_t			computation_epoch;
	integer_t			safe_mode;		/* saved mode during fail-safe */
	natural_t			safe_release;	/* when to release fail-safe */

  /* Used in priority computations */
	natural_t			sched_stamp;	/* when priority was updated */
	natural_t			cpu_usage;		/* exp. decaying cpu usage [%cpu] */
	natural_t			cpu_delta;		/* cpu usage since last update */
	natural_t			sched_usage;	/* load-weighted cpu usage [sched] */
	natural_t			sched_delta;	/* weighted cpu usage since update */
	natural_t			sleep_stamp;	/* when entered TH_WAIT state */

	/* Timing data structures */
	timer_data_t			user_timer;			/* user mode timer */
	timer_save_data_t		system_timer_save;	/* saved system timer value */
	timer_save_data_t		user_timer_save;	/* saved user timer value */

	/* Timed wait expiration */
	timer_call_data_t		wait_timer;
	integer_t				wait_timer_active;
	boolean_t				wait_timer_is_set;

	/* Priority depression expiration */
	timer_call_data_t		depress_timer;
	integer_t				depress_timer_active;

	/* Various bits of stashed state */
	union {
		struct {
		  	mach_msg_return_t	state;		/* receive state */
		  	ipc_object_t		object;		/* object received on */
		  	mach_msg_header_t	*msg;		/* receive buffer pointer */
			mach_msg_size_t		msize;		/* max size for recvd msg */
		  	mach_msg_option_t	option;		/* options for receive */
		  	mach_msg_size_t		slist_size;	/* scatter list size */
			struct ipc_kmsg		*kmsg;		/* received message */
			mach_port_seqno_t	seqno;		/* seqno of recvd message */
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
		} swtch;
		int						misc;		/* catch-all for other state */
	} saved;

	/* IPC data structures */
	struct ipc_kmsg_queue ith_messages;
	mach_port_t ith_mig_reply;			/* reply port for mig */
	mach_port_t ith_rpc_reply;			/* reply port for kernel RPCs */

	/* Ast/Halt data structures */
	boolean_t			active;			/* thread is active */
	vm_offset_t			recover;		/* page fault recover(copyin/out) */
	int					ref_count;		/* number of references to me */

	/* Processor set info */
	queue_chain_t		pset_threads;	/* list of all shuttles in pset */
#if	MACH_HOST
	boolean_t			may_assign;		/* may assignment change? */
	boolean_t			assign_active;	/* waiting for may_assign */
#endif	/* MACH_HOST */

/* BEGIN TRACING/DEBUG */

#if	MACH_LOCK_MON
	unsigned			lock_stack;			/* number of locks held */
#endif  /* MACH_LOCK_MON */

#if	ETAP_EVENT_MONITOR
	int					etap_reason;		/* real reason why we blocked */
	boolean_t			etap_trace;			/* ETAP trace status */
#endif	/* ETAP_EVENT_MONITOR */

#if	MACH_LDEBUG
	/*
	 *	Debugging:  track acquired mutexes and locks.
	 *	Because a thread can block while holding such
	 *	synchronizers, we think of the thread as
	 *	"owning" them.
	 */
#define	MUTEX_STACK_DEPTH	20
#define	LOCK_STACK_DEPTH	20
	mutex_t				*mutex_stack[MUTEX_STACK_DEPTH];
	lock_t				*lock_stack[LOCK_STACK_DEPTH];
	unsigned int		mutex_stack_index;
	unsigned int		lock_stack_index;
	unsigned			mutex_count;		/* XXX to be deleted XXX */
#endif	/* MACH_LDEBUG */
/* END TRACING/DEBUG */

};

#define ith_state		saved.receive.state
#define ith_object		saved.receive.object
#define ith_msg			saved.receive.msg
#define ith_msize		saved.receive.msize
#define	ith_option		saved.receive.option
#define ith_scatter_list_size	saved.receive.slist_size
#define ith_continuation	saved.receive.continuation
#define ith_kmsg		saved.receive.kmsg
#define ith_seqno		saved.receive.seqno

#define sth_waitsemaphore	saved.sema.waitsemaphore
#define sth_signalsemaphore	saved.sema.signalsemaphore
#define sth_options		saved.sema.options
#define sth_result		saved.sema.result
#define sth_continuation	saved.sema.continuation

struct funnel_lock {
	int			fnl_type;			/* funnel type */
	mutex_t		*fnl_mutex;			/* underlying mutex for the funnel */
	void *		fnl_mtxholder;		/* thread (last)holdng mutex */
	void *		fnl_mtxrelease;		/* thread (last)releasing mutex */
	mutex_t		*fnl_oldmutex;		/* Mutex before collapsing split funnel */
};

typedef struct funnel_lock		funnel_t;

extern thread_act_t active_kloaded[NCPUS];	/* "" kernel-loaded acts */
extern vm_offset_t active_stacks[NCPUS];	/* active kernel stacks */
extern vm_offset_t kernel_stack[NCPUS];

extern	struct thread_shuttle	pageout_thread;

#ifndef MACHINE_STACK_STASH
/*
 * MD Macro to fill up global stack state,
 * keeping the MD structure sizes + games private
 */
#define MACHINE_STACK_STASH(stack)								\
MACRO_BEGIN														\
	mp_disable_preemption();									\
	active_stacks[cpu_number()] = (stack);						\
	kernel_stack[cpu_number()] = (stack) + KERNEL_STACK_SIZE;	\
	mp_enable_preemption();										\
MACRO_END
#endif	/* MACHINE_STACK_STASH */

/*
 *	Kernel-only routines
 */

/* Initialize thread module */
extern void		thread_init(void);

/* Take reference on thread (make sure it doesn't go away) */
extern void		thread_reference(
					thread_t		thread);

/* Release reference on thread */
extern void		thread_deallocate(
					thread_t		thread);

/* Set task priority of member thread */
extern void		thread_task_priority(
					thread_t		thread,
					integer_t		priority,
					integer_t		max_priority);

/* Start a thread at specified routine */
#define thread_start(thread, start)						\
					(thread)->continuation = (start)

/* Reaps threads waiting to be destroyed */
extern void		thread_reaper_init(void);


/* Insure thread always has a kernel stack */
extern void		stack_privilege(
					thread_t		thread);

extern void		consider_thread_collect(void);

/*
 *	Arguments to specify aggressiveness to thread halt.
 *	Can't have MUST_HALT and SAFELY at the same time.
 */
#define	THREAD_HALT_NORMAL	0
#define	THREAD_HALT_MUST_HALT	1	/* no deadlock checks */
#define	THREAD_HALT_SAFELY	2	/* result must be restartable */

/*
 *	Macro-defined routines
 */

#define thread_pcb(th)			((th)->pcb)

#define	thread_lock_init(th)	simple_lock_init(&(th)->lock, ETAP_THREAD_LOCK)
#define thread_lock(th)			simple_lock(&(th)->lock)
#define thread_unlock(th)		simple_unlock(&(th)->lock)
#define thread_lock_try(th)		simple_lock_try(&(th)->lock)

#define thread_should_halt_fast(thread)	\
	(!(thread)->top_act || !(thread)->top_act->active)

#define thread_should_halt(thread) thread_should_halt_fast(thread)

#define thread_reference_locked(thread) ((thread)->ref_count++)

/*
 * Lock to cover wake_active only; like thread_lock(), is taken
 * at splsched().  Used to avoid calling into scheduler with a
 * thread_lock() held.  Precedes thread_lock() (and other scheduling-
 * related locks) in the system lock ordering.
 */
#define wake_lock_init(th)					\
			simple_lock_init(&(th)->wake_lock, ETAP_THREAD_WAKE)
#define wake_lock(th)		simple_lock(&(th)->wake_lock)
#define wake_unlock(th)		simple_unlock(&(th)->wake_lock)
#define wake_lock_try(th)		simple_lock_try(&(th)->wake_lock)

static __inline__ vm_offset_t current_stack(void);
static __inline__ vm_offset_t
current_stack(void)
{
	vm_offset_t	ret;

	mp_disable_preemption();
	ret = active_stacks[cpu_number()];
	mp_enable_preemption();
	return ret;
}

extern void		pcb_module_init(void);

extern void		pcb_init(
					thread_act_t	thr_act);

extern void		pcb_terminate(
					thread_act_t	thr_act);

extern void		pcb_collect(
					thread_act_t	thr_act);

extern void		pcb_user_to_kernel(
					thread_act_t	thr_act);

extern kern_return_t	thread_setstatus(
							thread_act_t			thr_act,
							int						flavor,
							thread_state_t			tstate,
							mach_msg_type_number_t	count);

extern kern_return_t	thread_getstatus(
							thread_act_t			thr_act,
							int						flavor,
							thread_state_t			tstate,
							mach_msg_type_number_t	*count);

extern boolean_t		stack_alloc_try(
							thread_t			    thread,
							void					(*start_pos)(thread_t));

/* This routine now used only internally */
extern kern_return_t	thread_info_shuttle(
							thread_act_t			thr_act,
							thread_flavor_t			flavor,
							thread_info_t			thread_info_out,
							mach_msg_type_number_t	*thread_info_count);

/* Machine-dependent routines */
extern void		thread_machine_init(void);

extern void		thread_machine_set_current(
					thread_t		thread );

extern kern_return_t	thread_machine_create(
							thread_t			thread,
							thread_act_t		thr_act,
							void				(*start_pos)(thread_t));

extern void		thread_set_syscall_return(
					thread_t		thread,
					kern_return_t	retval);

extern void		thread_machine_destroy(
					thread_t		thread );

extern void		thread_machine_flush(
				thread_act_t thr_act);

extern thread_t     kernel_thread_with_priority(
                    task_t          task,
					integer_t		priority,
                    void            (*start)(void),
					boolean_t		alloc_stack,
                    boolean_t       start_running);

extern void			thread_terminate_self(void);

extern void 		funnel_lock(funnel_t *);

extern void 		funnel_unlock(funnel_t *);

#else	/* MACH_KERNEL_PRIVATE */

typedef struct funnel_lock		funnel_t;

extern boolean_t thread_should_halt(thread_t);

#endif	/* MACH_KERNEL_PRIVATE */

extern thread_t		kernel_thread(
						task_t		task,
						void		(*start)(void));

extern void         thread_set_cont_arg(int);

extern int          thread_get_cont_arg(void);

/* JMM - These are only temporary */
extern boolean_t	is_thread_running(thread_act_t); /* True is TH_RUN */
extern boolean_t	is_thread_idle(thread_t); /* True is TH_IDLE */
extern kern_return_t	get_thread_waitresult(thread_t);

#endif	/* __APPLE_API_PRIVATE */

#ifdef __APPLE_API_EVOLVING

#define THR_FUNNEL_NULL (funnel_t *)0

extern funnel_t *	funnel_alloc(int);

extern funnel_t *	thread_funnel_get(void);

extern boolean_t	thread_funnel_set(funnel_t * fnl, boolean_t funneled);

extern boolean_t	thread_funnel_merge(funnel_t * fnl, funnel_t * otherfnl);

#endif	/* __APPLE_API_EVOLVING */

#endif	/* _KERN_THREAD_H_ */
