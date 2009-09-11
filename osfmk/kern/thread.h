/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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

#include <cputypes.h>

#include <mach_assert.h>
#include <mach_ldebug.h>

#include <ipc/ipc_types.h>

#include <mach/port.h>
#include <kern/cpu_number.h>
#include <kern/queue.h>
#include <kern/timer.h>
#include <kern/lock.h>
#include <kern/locks.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/thread_call.h>
#include <kern/timer_call.h>
#include <kern/task.h>
#include <kern/exception.h>
#include <kern/affinity.h>

#include <ipc/ipc_kmsg.h>

#include <machine/cpu_data.h>
#include <machine/thread.h>

struct thread {
	/*
	 *	NOTE:	The runq field in the thread structure has an unusual
	 *	locking protocol.  If its value is PROCESSOR_NULL, then it is
	 *	locked by the thread_lock, but if its value is something else
	 *	then it is locked by the associated run queue lock.
	 *
	 *	When the thread is on a wait queue, these first three fields
	 *	are treated as an unofficial union with a wait_queue_element.
	 *	If you change these, you must change that definition as well
	 *	(kern/wait_queue.h).
	 */
  	/* Items examined often, modified infrequently */
	queue_chain_t	links;				/* run/wait queue links */
	processor_t		runq;				/* run queue assignment */
	wait_queue_t	wait_queue;			/* wait queue we are currently on */
	event64_t		wait_event;			/* wait queue event */
	integer_t		options;			/* options set by thread itself */
#define TH_OPT_INTMASK		0x03		/* interrupt / abort level */
#define TH_OPT_VMPRIV		0x04		/* may allocate reserved memory */
#define TH_OPT_DTRACE		0x08		/* executing under dtrace_probe */

	/* Data updated during assert_wait/thread_wakeup */
	decl_simple_lock_data(,sched_lock)	/* scheduling lock (thread_lock()) */
	decl_simple_lock_data(,wake_lock)	/* for thread stop / wait (wake_lock()) */
	boolean_t			wake_active;	/* wake event on stop */
	int					at_safe_point;	/* thread_abort_safely allowed */
	ast_t				reason;			/* why we blocked */
	wait_result_t		wait_result;	/* outcome of wait -
										 * may be examined by this thread
										 * WITHOUT locking */
	thread_continue_t	continuation;	/* continue here next dispatch */
	void				*parameter;		/* continuation parameter */

	/* Data updated/used in thread_invoke */
    struct funnel_lock	*funnel_lock;		/* Non-reentrancy funnel */
    int				    funnel_state;
#define TH_FN_OWNED			0x1				/* we own the funnel */
#define TH_FN_REFUNNEL		0x2				/* re-acquire funnel on dispatch */

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
#define	TH_TERMINATE	0x10			/* halted at termination */

#define TH_IDLE			0x80			/* idling processor */

	/* Scheduling information */
	integer_t			sched_mode;			/* scheduling mode bits */
#define TH_MODE_REALTIME		0x0001		/* time constraints supplied */
#define TH_MODE_TIMESHARE		0x0002		/* use timesharing algorithm */
#define TH_MODE_FAILSAFE		0x0004		/* fail-safe has tripped */
#define	TH_MODE_PROMOTED		0x0008		/* sched pri has been promoted */
#define TH_MODE_ABORT			0x0010		/* abort interruptible waits */
#define TH_MODE_ABORTSAFELY		0x0020		/* ... but only those at safe point */
#define TH_MODE_ISABORTED		(TH_MODE_ABORT | TH_MODE_ABORTSAFELY)
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

											/* real-time parameters */
	struct {								/* see mach/thread_policy.h */
		uint32_t			period;
		uint32_t			computation;
		uint32_t			constraint;
		boolean_t			preemptible;

		uint64_t			deadline;
	}					realtime;

	uint32_t			current_quantum;	/* duration of current quantum */

  /* Data used during setrun/dispatch */
	timer_data_t		system_timer;		/* system mode timer */
	processor_t			bound_processor;	/* bound to a processor? */
	processor_t			last_processor;		/* processor last dispatched on */

	/* Fail-safe computation since last unblock or qualifying yield */
	uint64_t			computation_metered;
	uint64_t			computation_epoch;
	integer_t			safe_mode;		/* saved mode during fail-safe */
	natural_t			safe_release;	/* when to release fail-safe */

	/* Call out from scheduler */
	void				(*sched_call)(
							int			type,
							thread_t	thread);

	/* Statistics and timesharing calculations */
	natural_t			sched_stamp;	/* last scheduler tick */
	natural_t			sched_usage;	/* timesharing cpu usage [sched] */
	natural_t			pri_shift;		/* usage -> priority from pset */
	natural_t			cpu_usage;		/* instrumented cpu usage [%cpu] */
	natural_t			cpu_delta;		/* accumulated cpu_usage delta */
	uint32_t			c_switch;		/* total context switches */
	uint32_t			p_switch;		/* total processor switches */
	uint32_t			ps_switch;		/* total pset switches */

	/* Timing data structures */
	timer_data_t		user_timer;			/* user mode timer */
	uint64_t			user_timer_save;	/* saved user timer value */
	uint64_t			system_timer_save;	/* saved system timer value */
	uint64_t			vtimer_user_save;	/* saved values for vtimers */
	uint64_t			vtimer_prof_save;
	uint64_t			vtimer_rlim_save;

	/* Timed wait expiration */
	timer_call_data_t	wait_timer;
	integer_t			wait_timer_active;
	boolean_t			wait_timer_is_set;

	/* Priority depression expiration */
	timer_call_data_t	depress_timer;
	integer_t			depress_timer_active;

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
		  	ipc_object_t		object;		/* object received on */
		  	mach_vm_address_t	msg_addr;	/* receive buffer pointer */
			mach_msg_size_t		msize;		/* max size for recvd msg */
		  	mach_msg_option_t	option;		/* options for receive */
		  	mach_msg_size_t		slist_size;	/* scatter list size */
			mach_port_name_t	receiver_name;	/* the receive port name */
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
	mach_port_t ith_rpc_reply;			/* reply port for kernel RPCs */

	/* Ast/Halt data structures */
	vm_offset_t					recover;		/* page fault recover(copyin/out) */
	uint32_t					ref_count;		/* number of references to me */

	queue_chain_t				threads;		/* global list of all threads */

	/* Activation */
		queue_chain_t			task_threads;

		/*** Machine-dependent state ***/
		struct machine_thread	machine;

		/* Task membership */
		struct task				*task;
		vm_map_t				map;

		decl_lck_mtx_data(,mutex)

		/* Kernel holds on this thread  */
		int						suspend_count;

		/* User level suspensions */
		int						user_stop_count;

		/* Pending thread ast(s) */
		ast_t					ast;

		/* Miscellaneous bits guarded by mutex */
		uint32_t
			active:1,				/* Thread is active and has not been terminated */
			started:1,				/* Thread has been started after creation */
			static_param:1,			/* Disallow policy parameter changes */
			:0;

		/* Return Handers */
		struct ReturnHandler {
			struct ReturnHandler	*next;
			void		(*handler)(
							struct ReturnHandler		*rh,
							struct thread				*thread);
		} *handlers, special_handler;

		/* Ports associated with this thread */
		struct ipc_port			*ith_self;		/* not a right, doesn't hold ref */
		struct ipc_port			*ith_sself;		/* a send right */
		struct exception_action	exc_actions[EXC_TYPES_COUNT];

		/* Owned ulocks (a lock set element) */
		queue_head_t			held_ulocks;

#ifdef	MACH_BSD
		void					*uthread;
#endif

#if CONFIG_DTRACE
		uint32_t t_dtrace_predcache;/* DTrace per thread predicate value hint */
		int64_t t_dtrace_tracing;       /* Thread time under dtrace_probe() */
		int64_t t_dtrace_vtime;
#endif

#define T_CHUD_MARKED		0x1		/* this thread is marked by CHUD */
#define T_IN_CHUD			0x2		/* this thread is already in a CHUD handler */
#define THREAD_PMC_FLAG		0x4		/* Bit in "t_chud" signifying PMC interest */
	        uint32_t    t_page_creation_count;
	        clock_sec_t t_page_creation_time;

		uint32_t t_chud;	/* CHUD flags, used for Shark */
		uint64_t thread_id;	/*system wide unique thread-id*/
};

#define ith_state		saved.receive.state
#define ith_object		saved.receive.object
#define ith_msg_addr			saved.receive.msg_addr
#define ith_msize		saved.receive.msize
#define	ith_option		saved.receive.option
#define ith_scatter_list_size	saved.receive.slist_size
#define ith_receiver_name	saved.receive.receiver_name
#define ith_continuation	saved.receive.continuation
#define ith_kmsg		saved.receive.kmsg
#define ith_seqno		saved.receive.seqno

#define sth_waitsemaphore	saved.sema.waitsemaphore
#define sth_signalsemaphore	saved.sema.signalsemaphore
#define sth_options		saved.sema.options
#define sth_result		saved.sema.result
#define sth_continuation	saved.sema.continuation

extern void			thread_bootstrap(void) __attribute__((section("__TEXT, initcode")));

extern void			thread_init(void) __attribute__((section("__TEXT, initcode")));

extern void			thread_daemon_init(void);

#define	thread_reference_internal(thread)	\
			(void)hw_atomic_add(&(thread)->ref_count, 1)

#define thread_deallocate_internal(thread)	\
			hw_atomic_sub(&(thread)->ref_count, 1)

#define thread_reference(thread)					\
MACRO_BEGIN											\
	if ((thread) != THREAD_NULL)					\
		thread_reference_internal(thread);		\
MACRO_END

extern void			thread_deallocate(
						thread_t		thread);

extern void			thread_terminate_self(void);

extern kern_return_t	thread_terminate_internal(
							thread_t		thread);

extern void			thread_start_internal(
							thread_t			thread) __attribute__ ((noinline));

extern void			thread_terminate_enqueue(
						thread_t		thread);

extern void			thread_stack_enqueue(
						thread_t		thread);

extern void			thread_hold(
						thread_t	thread);

extern void			thread_release(
						thread_t	thread);


#define	thread_lock_init(th)	simple_lock_init(&(th)->sched_lock, 0)
#define thread_lock(th)			simple_lock(&(th)->sched_lock)
#define thread_unlock(th)		simple_unlock(&(th)->sched_lock)

#define wake_lock_init(th)		simple_lock_init(&(th)->wake_lock, 0)
#define wake_lock(th)			simple_lock(&(th)->wake_lock)
#define wake_unlock(th)			simple_unlock(&(th)->wake_lock)

#define thread_should_halt_fast(thread)		(!(thread)->active)

extern void				stack_alloc(
							thread_t		thread);

extern void				stack_free(
							thread_t		thread);

extern void				stack_free_stack(
							vm_offset_t		stack);

extern boolean_t		stack_alloc_try(
							thread_t	    thread);

extern void				stack_collect(void);

extern void				stack_init(void) __attribute__((section("__TEXT, initcode")));

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

extern kern_return_t	thread_info_internal(
							thread_t				thread,
							thread_flavor_t			flavor,
							thread_info_t			thread_info_out,
							mach_msg_type_number_t	*thread_info_count);

extern void				thread_task_priority(
							thread_t		thread,
							integer_t		priority,
							integer_t		max_priority);

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

extern void			machine_thread_terminate_self(void);

extern kern_return_t	machine_thread_get_kern_state(
							thread_t				thread,
							thread_flavor_t			flavor,
							thread_state_t			tstate,
							mach_msg_type_number_t	*count);

extern kern_return_t	machine_thread_inherit_taskwide(
							thread_t		thread,
							task_t			parent_task);

/*
 * XXX Funnel locks XXX
 */

struct funnel_lock {
	int			fnl_type;			/* funnel type */
	lck_mtx_t	*fnl_mutex;			/* underlying mutex for the funnel */
	void *		fnl_mtxholder;		/* thread (last)holdng mutex */
	void *		fnl_mtxrelease;		/* thread (last)releasing mutex */
	lck_mtx_t	*fnl_oldmutex;		/* Mutex before collapsing split funnel */
};

typedef struct ReturnHandler		ReturnHandler;

#define	thread_mtx_lock(thread)			lck_mtx_lock(&(thread)->mutex)
#define	thread_mtx_try(thread)			lck_mtx_try_lock(&(thread)->mutex)
#define	thread_mtx_unlock(thread)		lck_mtx_unlock(&(thread)->mutex)

extern void			act_execute_returnhandlers(void);

extern void			install_special_handler(
						thread_t		thread);

extern void			special_handler(
						ReturnHandler	*rh,
						thread_t		thread);

void act_machine_sv_free(thread_t, int);

vm_offset_t			min_valid_stack_address(void);
vm_offset_t			max_valid_stack_address(void);

extern void 		funnel_lock(
						struct funnel_lock	*lock);

extern void 		funnel_unlock(
						struct funnel_lock	*lock);

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

#ifndef	__LP64__

extern thread_t		kernel_thread(
						task_t		task,
						void		(*start)(void));

#endif	/* __LP64__ */

extern uint64_t	 		thread_tid(
						thread_t thread);

extern uint64_t	 		thread_dispatchqaddr(
						thread_t thread);

__END_DECLS

#endif	/* KERNEL_PRIVATE */

__BEGIN_DECLS

#ifdef	XNU_KERNEL_PRIVATE

extern kern_return_t	thread_create_workq(
							task_t			task,
							thread_t		*new_thread);

extern	void	thread_yield_internal(
	mach_msg_timeout_t	interval);

typedef struct funnel_lock		funnel_t;

#define THR_FUNNEL_NULL (funnel_t *)0

extern funnel_t		 *funnel_alloc(
						int			type);

extern void			funnel_free(
						funnel_t	*lock);

extern funnel_t		*thread_funnel_get(void);

extern boolean_t	thread_funnel_set(
						funnel_t	*lock,
						boolean_t	 funneled);

extern void			thread_read_times(
						thread_t 		thread,
						time_value_t	*user_time,
						time_value_t	*system_time);

extern void			thread_setuserstack(
						thread_t		thread,
						mach_vm_offset_t	user_stack);

extern uint64_t		thread_adjuserstack(
						thread_t		thread,
						int				adjust);

extern void			thread_setentrypoint(
						thread_t		thread,
						mach_vm_offset_t	entry);

extern kern_return_t	thread_setsinglestep(
						thread_t		thread,
						int			on);

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

extern kern_return_t	thread_policy_set_internal(
	                                thread_t		thread,
					thread_policy_flavor_t	flavor,
					thread_policy_t		policy_info,
					mach_msg_type_number_t	count);


extern task_t	get_threadtask(thread_t);
#define thread_is_64bit(thd)	\
	task_has_64BitAddr(get_threadtask(thd))


extern void		*get_bsdthread_info(thread_t);
extern void		set_bsdthread_info(thread_t, void *);
extern void		*uthread_alloc(task_t, thread_t, int);
extern void		uthread_cleanup(task_t, void *, void *); 
extern void		uthread_zone_free(void *); 
extern void		uthread_cred_free(void *); 

extern boolean_t	thread_should_halt(
						thread_t		thread);

extern int is_64signalregset(void);

void act_set_apc(thread_t);

extern uint32_t dtrace_get_thread_predcache(thread_t);
extern int64_t dtrace_get_thread_vtime(thread_t);
extern int64_t dtrace_get_thread_tracing(thread_t);
extern boolean_t dtrace_get_thread_reentering(thread_t);
extern vm_offset_t dtrace_get_kernel_stack(thread_t);
extern void dtrace_set_thread_predcache(thread_t, uint32_t);
extern void dtrace_set_thread_vtime(thread_t, int64_t);
extern void dtrace_set_thread_tracing(thread_t, int64_t);
extern void dtrace_set_thread_reentering(thread_t, boolean_t);
extern vm_offset_t dtrace_set_thread_recover(thread_t, vm_offset_t);
extern void dtrace_thread_bootstrap(void);

extern int64_t dtrace_calc_thread_recent_vtime(thread_t);


extern void		thread_set_wq_state32(
					      thread_t          thread,
					      thread_state_t    tstate);

extern void		thread_set_wq_state64(
					      thread_t          thread,
					      thread_state_t    tstate);

extern vm_offset_t	kernel_stack_mask;
extern vm_offset_t	kernel_stack_size;
extern vm_offset_t	kernel_stack_depth_max;

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

__END_DECLS

#endif	/* _KERN_THREAD_H_ */
