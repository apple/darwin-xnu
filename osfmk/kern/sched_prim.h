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
 * @OSF_COPYRIGHT@
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
 *	File:	sched_prim.h
 *	Author:	David Golub
 *
 *	Scheduling primitive definitions file
 *
 */

#ifndef	_KERN_SCHED_PRIM_H_
#define _KERN_SCHED_PRIM_H_

#include <mach/boolean.h>
#include <mach/machine/vm_types.h>
#include <mach/kern_return.h>
#include <kern/clock.h>
#include <kern/kern_types.h>
#include <kern/thread.h>
#include <sys/cdefs.h>

#ifdef	MACH_KERNEL_PRIVATE

/* Initialization */
extern void		sched_init(void);

extern void		sched_startup(void);

extern void		sched_timebase_init(void);

/* Force a preemption point for a thread and wait for it to stop running */
extern boolean_t	thread_stop( 
						thread_t	thread,
						boolean_t	until_not_runnable);

/* Release a previous stop request */
extern void			thread_unstop(
						thread_t	thread);

/* Wait for a thread to stop running */
extern void			thread_wait(
						thread_t	thread,
						boolean_t	until_not_runnable);

/* Unblock thread on wake up */
extern boolean_t	thread_unblock(
						thread_t		thread,
						wait_result_t	wresult);

/* Unblock and dispatch thread */
extern kern_return_t	thread_go(
						 	thread_t		thread,
							wait_result_t	wresult);

/* Handle threads at context switch */
extern void			thread_dispatch(
						thread_t		old_thread,
						thread_t		new_thread);

/* Switch directly to a particular thread */
extern int			thread_run(
						thread_t			self,
						thread_continue_t	continuation,
						void				*parameter,
						thread_t			new_thread);

/* Resume thread with new stack */
extern void			thread_continue(
						thread_t		old_thread);

/* Invoke continuation */
extern void		call_continuation(
					thread_continue_t	continuation,
					void				*parameter,
					wait_result_t		wresult);

/* Set the current scheduled priority */
extern void		set_sched_pri(
					thread_t		thread,
					int				priority);

/* Set base priority of the specified thread */
extern void		set_priority(
					thread_t		thread,
					int				priority);

/* Reset scheduled priority of thread */
extern void		compute_priority(
					thread_t		thread,
					boolean_t		override_depress);

/* Adjust scheduled priority of thread during execution */
extern void		compute_my_priority(
					thread_t		thread);

/* Periodic scheduler activity */
extern void		sched_init_thread(void (*)(void));

/* Perform sched_tick housekeeping activities */
extern boolean_t		can_update_priority(
					thread_t		thread);

extern void		update_priority(
											thread_t		thread);

extern void		lightweight_update_priority(
								thread_t		thread);

extern void		sched_traditional_quantum_expire(thread_t	thread);

/* Idle processor thread */
extern void		idle_thread(void);

extern kern_return_t	idle_thread_create(
							processor_t		processor);

/* Continuation return from syscall */
extern void     thread_syscall_return(
                        kern_return_t   ret);

/* Context switch */
extern wait_result_t	thread_block_reason(
							thread_continue_t	continuation,
							void				*parameter,
							ast_t				reason);

/* Reschedule thread for execution */
extern void		thread_setrun(
					thread_t	thread,
					integer_t	options);

#define SCHED_TAILQ		1
#define SCHED_HEADQ		2
#define SCHED_PREEMPT	4

extern processor_set_t	task_choose_pset(
							task_t			task);

/* Bind the current thread to a particular processor */
extern processor_t		thread_bind(
							processor_t		processor);

/* Choose the best processor to run a thread */
extern processor_t	choose_processor(
									 processor_set_t		pset,
									 processor_t			processor,
									 thread_t			thread);

/* Choose a thread from a processor's priority-based runq */
extern thread_t choose_thread(
							  processor_t		processor,
							  run_queue_t		runq,
							  int				priority);


extern void thread_quantum_init(
								thread_t thread);

extern void		run_queue_init(
					run_queue_t		runq);

extern thread_t	run_queue_dequeue(
							  run_queue_t		runq,
							  integer_t		options);

extern boolean_t	run_queue_enqueue(
							  run_queue_t		runq,
							  thread_t			thread,
							  integer_t		options);

extern void	run_queue_remove(
									 run_queue_t		runq,
									 thread_t			thread);
									  
/* Remove thread from its run queue */
extern boolean_t	thread_run_queue_remove(
						thread_t	thread);

extern void		thread_timer_expire(
					void			*thread,
					void			*p1);

extern boolean_t	thread_eager_preemption(
						thread_t thread);

/* Fair Share routines */
#if defined(CONFIG_SCHED_TRADITIONAL) || defined(CONFIG_SCHED_PROTO) || defined(CONFIG_SCHED_FIXEDPRIORITY)
void		sched_traditional_fairshare_init(void);

int			sched_traditional_fairshare_runq_count(void);

uint64_t	sched_traditional_fairshare_runq_stats_count_sum(void);

void		sched_traditional_fairshare_enqueue(thread_t thread);

thread_t	sched_traditional_fairshare_dequeue(void);

boolean_t	sched_traditional_fairshare_queue_remove(thread_t thread);
#endif

#if defined(CONFIG_SCHED_GRRR) || defined(CONFIG_SCHED_FIXEDPRIORITY)
void		sched_grrr_fairshare_init(void);

int			sched_grrr_fairshare_runq_count(void);

uint64_t	sched_grrr_fairshare_runq_stats_count_sum(void);

void		sched_grrr_fairshare_enqueue(thread_t thread);

thread_t	sched_grrr_fairshare_dequeue(void);

boolean_t	sched_grrr_fairshare_queue_remove(thread_t thread);
#endif

extern boolean_t sched_generic_direct_dispatch_to_idle_processors;

/* Set the maximum interrupt level for the thread */
__private_extern__ wait_interrupt_t thread_interrupt_level(
						wait_interrupt_t interruptible);

__private_extern__ wait_result_t thread_mark_wait_locked(
						thread_t		 thread,
						wait_interrupt_t interruptible);

/* Wake up locked thread directly, passing result */
__private_extern__ kern_return_t clear_wait_internal(
						thread_t		thread,
						wait_result_t	result);

extern void sched_stats_handle_csw(
							processor_t processor, 
							int reasons, 
							int selfpri, 
							int otherpri);

extern void sched_stats_handle_runq_change(
									struct runq_stats *stats, 
									int old_count);



#define	SCHED_STATS_CSW(processor, reasons, selfpri, otherpri) 		\
do { 								\
	if (__builtin_expect(sched_stats_active, 0)) { 	\
		sched_stats_handle_csw((processor), 		\
				(reasons), (selfpri), (otherpri)); 	\
	}							\
} while (0) 


#define SCHED_STATS_RUNQ_CHANGE(stats, old_count)		\
do { 								\
	if (__builtin_expect(sched_stats_active, 0)) { 	\
		sched_stats_handle_runq_change((stats), 	\
								(old_count));		\
	}							\
} while (0) 

#define THREAD_URGENCY_NONE		0	/* indicates that there is no currently runnable */
#define THREAD_URGENCY_BACKGROUND	1	/* indicates that the thread is marked as a "background" thread */
#define THREAD_URGENCY_NORMAL		2	/* indicates that the thread is marked as a "normal" thread */
#define THREAD_URGENCY_REAL_TIME	3	/* indicates that the thread is marked as a "real-time" or urgent thread */
#define	THREAD_URGENCY_MAX		4	/* Marker */
/* Returns the "urgency" of a thread (provided by scheduler) */
extern int	thread_get_urgency(
					thread_t	thread,
    				   	uint64_t	*rt_period,
					uint64_t	*rt_deadline);

/* Tells the "urgency" of the just scheduled thread (provided by CPU PM) */
extern void	thread_tell_urgency(
    					int		urgency,
					uint64_t	rt_period,
					uint64_t	rt_deadline,
				    thread_t nthread);

/* Tells if there are "active" RT threads in the system (provided by CPU PM) */
extern void	active_rt_threads(
    					boolean_t	active);

#endif /* MACH_KERNEL_PRIVATE */

__BEGIN_DECLS

#ifdef	XNU_KERNEL_PRIVATE

extern boolean_t		assert_wait_possible(void);

/* Toggles a global override to turn off CPU Throttling */
#define CPU_THROTTLE_DISABLE	0
#define CPU_THROTTLE_ENABLE	1
extern void	sys_override_cpu_throttle(int flag);

/*
 ****************** Only exported until BSD stops using ********************
 */

/* Wake up thread directly, passing result */
extern kern_return_t clear_wait(
						thread_t		thread,
						wait_result_t	result);

/* Start thread running */
extern void		thread_bootstrap_return(void);

/* Return from exception (BSD-visible interface) */
extern void		thread_exception_return(void) __dead2;

#endif	/* XNU_KERNEL_PRIVATE */

/* Context switch */
extern wait_result_t	thread_block(
							thread_continue_t	continuation);

extern wait_result_t	thread_block_parameter(
							thread_continue_t	continuation,
							void				*parameter);

/* Declare thread will wait on a particular event */
extern wait_result_t	assert_wait(
							event_t				event,
							wait_interrupt_t	interruptible);

/* Assert that the thread intends to wait with a timeout */
extern wait_result_t	assert_wait_timeout(
							event_t				event,
							wait_interrupt_t	interruptible,
							uint32_t			interval,
							uint32_t			scale_factor);

/* Assert that the thread intends to wait with an urgency, timeout and leeway */
extern wait_result_t	assert_wait_timeout_with_leeway(
							event_t				event,
							wait_interrupt_t	interruptible,
							wait_timeout_urgency_t	urgency,
							uint32_t			interval,
							uint32_t			leeway,
							uint32_t			scale_factor);

extern wait_result_t	assert_wait_deadline(
							event_t				event,
							wait_interrupt_t	interruptible,
							uint64_t			deadline);

/* Assert that the thread intends to wait with an urgency, deadline, and leeway */
extern wait_result_t	assert_wait_deadline_with_leeway(
							event_t				event,
							wait_interrupt_t	interruptible,
							wait_timeout_urgency_t	urgency,
							uint64_t			deadline,
							uint64_t			leeway);

/* Wake up thread (or threads) waiting on a particular event */
extern kern_return_t	thread_wakeup_prim(
							event_t				event,
							boolean_t			one_thread,
							wait_result_t			result);

extern kern_return_t    thread_wakeup_prim_internal(
	                                                event_t				event,
							boolean_t			one_thread,
							wait_result_t			result,
							int				priority);


#define thread_wakeup(x)					\
			thread_wakeup_prim((x), FALSE, THREAD_AWAKENED)
#define thread_wakeup_with_result(x, z)		\
			thread_wakeup_prim((x), FALSE, (z))
#define thread_wakeup_one(x)				\
			thread_wakeup_prim((x), TRUE, THREAD_AWAKENED)

#ifdef MACH_KERNEL_PRIVATE
#define thread_wakeup_one_with_pri(x, pri)                              \
	                thread_wakeup_prim_internal((x), TRUE, THREAD_AWAKENED, pri)
#endif

extern boolean_t		preemption_enabled(void);

#ifdef MACH_KERNEL_PRIVATE

/*
 * Scheduler algorithm indirection. If only one algorithm is
 * enabled at compile-time, a direction function call is used.
 * If more than one is enabled, calls are dispatched through
 * a function pointer table.
 */

#if   !defined(CONFIG_SCHED_TRADITIONAL) && !defined(CONFIG_SCHED_PROTO) && !defined(CONFIG_SCHED_GRRR) && !defined(CONFIG_SCHED_FIXEDPRIORITY)
#error Enable at least one scheduler algorithm in osfmk/conf/MASTER.XXX
#endif

#define SCHED(f) (sched_current_dispatch->f)

struct sched_dispatch_table {
	void	(*init)(void);				/* Init global state */
	void	(*timebase_init)(void);		/* Timebase-dependent initialization */
	void	(*processor_init)(processor_t processor);	/* Per-processor scheduler init */
	void	(*pset_init)(processor_set_t pset);	/* Per-processor set scheduler init */
	
	void	(*maintenance_continuation)(void);	/* Function called regularly */
	
	/*
	 * Choose a thread of greater or equal priority from the per-processor
	 * runqueue for timeshare/fixed threads
	 */
	thread_t	(*choose_thread)(
								  processor_t		processor,
								  int				priority);
	
	/*
	 * Steal a thread from another processor in the pset so that it can run
	 * immediately
	 */
	thread_t	(*steal_thread)(
								processor_set_t		pset);
	
	/*
	 * Recalculate sched_pri based on base priority, past running time,
	 * and scheduling class.
	 */
	void		(*compute_priority)(
					 thread_t	thread,
					 boolean_t			override_depress);
	
	/*
	 * Pick the best processor for a thread (any kind of thread) to run on.
	 */
	processor_t	(*choose_processor)(
										 processor_set_t		pset,
										 processor_t			processor,
										 thread_t			thread);
	/*
	 * Enqueue a timeshare or fixed priority thread onto the per-processor
	 * runqueue
	 */
	boolean_t (*processor_enqueue)(
								 processor_t			processor,
								 thread_t			thread,
								 integer_t			options);
	
	/* Migrate threads away in preparation for processor shutdown */
	void (*processor_queue_shutdown)(
									 processor_t			processor);
	
	/* Remove the specific thread from the per-processor runqueue */
	boolean_t	(*processor_queue_remove)(
									processor_t			processor,
									thread_t		thread);
	
	/*
	 * Does the per-processor runqueue have any timeshare or fixed priority
	 * threads on it? Called without pset lock held, so should
	 * not assume immutability while executing.
	 */
	boolean_t	(*processor_queue_empty)(processor_t		processor);
	
	/*
	 * Would this priority trigger an urgent preemption if it's sitting
	 * on the per-processor runqueue?
	 */
	boolean_t	(*priority_is_urgent)(int priority);
	
	/*
	 * Does the per-processor runqueue contain runnable threads that
	 * should cause the currently-running thread to be preempted?
	 */
	ast_t		(*processor_csw_check)(processor_t processor);
	
	/*
	 * Does the per-processor runqueue contain a runnable thread
	 * of > or >= priority, as a preflight for choose_thread() or other
	 * thread selection
	 */
	boolean_t	(*processor_queue_has_priority)(processor_t		processor,
												int				priority,
												boolean_t		gte);
	
	/* Quantum size for the specified non-realtime thread. */
	uint32_t	(*initial_quantum_size)(thread_t thread);
	
	/* Scheduler mode for a new thread */
	sched_mode_t	(*initial_thread_sched_mode)(task_t parent_task);
	
	/* Scheduler algorithm supports timeshare (decay) mode */
	boolean_t	(*supports_timeshare_mode)(void);
	
	/*
	 * Is it safe to call update_priority, which may change a thread's
	 * runqueue or other state. This can be used to throttle changes
	 * to dynamic priority.
	 */
	boolean_t	(*can_update_priority)(thread_t thread);

	/*
	 * Update both scheduled priority and other persistent state.
	 * Side effects may including migration to another processor's runqueue.
	 */
	void		(*update_priority)(thread_t thread);
	
	/* Lower overhead update to scheduled priority and state. */
	void		(*lightweight_update_priority)(thread_t thread);
	
	/* Callback for non-realtime threads when the quantum timer fires */
	void		(*quantum_expire)(thread_t thread);
	
	/*
	 * Even though we could continue executing on this processor, does the
	 * topology (SMT, for instance) indicate that a better processor could be
	 * chosen
	 */
	boolean_t	(*should_current_thread_rechoose_processor)(processor_t			processor);
    
	/*
	 * Runnable threads on per-processor runqueue. Should only
	 * be used for relative comparisons of load between processors.
	 */
	int			(*processor_runq_count)(processor_t	processor);
	
	/* Aggregate runcount statistics for per-processor runqueue */
    uint64_t    (*processor_runq_stats_count_sum)(processor_t   processor);
	
	/* Initialize structures to track demoted fairshare threads */
	void		(*fairshare_init)(void);
	
	/* Number of runnable fairshare threads */
	int			(*fairshare_runq_count)(void);
	
	/* Aggregate runcount statistics for fairshare runqueue */
	uint64_t	(*fairshare_runq_stats_count_sum)(void);
	
	void		(*fairshare_enqueue)(thread_t thread);
	
	thread_t	(*fairshare_dequeue)(void);

	boolean_t	(*fairshare_queue_remove)(thread_t thread);
    
	/*
	* Use processor->next_thread to pin a thread to an idle
	* processor. If FALSE, threads are enqueued and can
	* be stolen by other processors.
	*/
	boolean_t   direct_dispatch_to_idle_processors;
};

#if defined(CONFIG_SCHED_TRADITIONAL)
#define kSchedTraditionalString "traditional"
#define kSchedTraditionalWithPsetRunqueueString "traditional_with_pset_runqueue"
extern const struct sched_dispatch_table sched_traditional_dispatch;
extern const struct sched_dispatch_table sched_traditional_with_pset_runqueue_dispatch;
#endif

#if defined(CONFIG_SCHED_PROTO)
#define kSchedProtoString "proto"
extern const struct sched_dispatch_table sched_proto_dispatch;
#endif

#if defined(CONFIG_SCHED_GRRR)
#define kSchedGRRRString "grrr"
extern const struct sched_dispatch_table sched_grrr_dispatch;
#endif

#if defined(CONFIG_SCHED_FIXEDPRIORITY)
#define kSchedFixedPriorityString "fixedpriority"
#define kSchedFixedPriorityWithPsetRunqueueString "fixedpriority_with_pset_runqueue"
extern const struct sched_dispatch_table sched_fixedpriority_dispatch;
extern const struct sched_dispatch_table sched_fixedpriority_with_pset_runqueue_dispatch;
#endif

/*
 * It is an error to invoke any scheduler-related code
 * before this is set up
 */
enum sched_enum {
	sched_enum_unknown = 0,
#if defined(CONFIG_SCHED_TRADITIONAL)
	sched_enum_traditional = 1,
	sched_enum_traditional_with_pset_runqueue = 2,
#endif
#if defined(CONFIG_SCHED_PROTO)
	sched_enum_proto = 3,
#endif
#if defined(CONFIG_SCHED_GRRR)
	sched_enum_grrr = 4,
#endif
#if defined(CONFIG_SCHED_FIXEDPRIORITY)
	sched_enum_fixedpriority = 5,
	sched_enum_fixedpriority_with_pset_runqueue = 6,
#endif
	sched_enum_max = 7
};

extern const struct sched_dispatch_table *sched_current_dispatch;

#endif	/* MACH_KERNEL_PRIVATE */

__END_DECLS

#endif	/* _KERN_SCHED_PRIM_H_ */
