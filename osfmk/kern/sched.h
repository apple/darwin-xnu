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
 *	File:	sched.h
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1985
 *
 *	Header file for scheduler.
 *
 */

#ifndef	_KERN_SCHED_H_
#define _KERN_SCHED_H_

#include <mach/policy.h>
#include <kern/kern_types.h>
#include <kern/queue.h>
#include <kern/lock.h>
#include <kern/macro_help.h>
#include <kern/timer_call.h>
#include <kern/ast.h>

#define	NRQS		128				/* 128 levels per run queue */
#define NRQBM		(NRQS / 32)		/* number of words per bit map */

#define MAXPRI		(NRQS-1)
#define MINPRI		IDLEPRI			/* lowest legal priority schedulable */
#define	IDLEPRI		0				/* idle thread priority */

/*
 *	High-level priority assignments
 *
 *************************************************************************
 * 127		Reserved (real-time)
 *				A
 *				+
 *			(32 levels)
 *				+
 *				V
 * 96		Reserved (real-time)
 * 95		Kernel mode only
 *				A
 *				+
 *			(16 levels)
 *				+
 *				V
 * 80		Kernel mode only
 * 79		System high priority
 *				A
 *				+
 *			(16 levels)
 *				+
 *				V
 * 64		System high priority
 * 63		Elevated priorities
 *				A
 *				+
 *			(12 levels)
 *				+
 *				V
 * 52		Elevated priorities
 * 51		Elevated priorities (incl. BSD +nice)
 *				A
 *				+
 *			(20 levels)
 *				+
 *				V
 * 32		Elevated priorities (incl. BSD +nice)
 * 31		Default (default base for threads)
 * 30		Lowered priorities (incl. BSD -nice)
 *				A
 *				+
 *			(20 levels)
 *				+
 *				V
 * 11		Lowered priorities (incl. BSD -nice)
 * 10		Lowered priorities (aged pri's)
 *				A
 *				+
 *			(11 levels)
 *				+
 *				V
 * 0		Lowered priorities (aged pri's / idle)
 *************************************************************************
 */

#define BASEPRI_RTQUEUES	(BASEPRI_REALTIME + 1)				/* 97 */
#define BASEPRI_REALTIME	(MAXPRI - (NRQS / 4) + 1)			/* 96 */

#define MAXPRI_KERNEL		(BASEPRI_REALTIME - 1)				/* 95 */
#define BASEPRI_PREEMPT		(MAXPRI_KERNEL - 2)					/* 93 */
#define BASEPRI_KERNEL		(MINPRI_KERNEL + 1)					/* 81 */
#define MINPRI_KERNEL		(MAXPRI_KERNEL - (NRQS / 8) + 1)	/* 80 */

#define MAXPRI_RESERVED		(MINPRI_KERNEL - 1)					/* 79 */
#define MINPRI_RESERVED		(MAXPRI_RESERVED - (NRQS / 8) + 1)	/* 64 */

#define MAXPRI_USER			(MINPRI_RESERVED - 1)				/* 63 */
#define BASEPRI_CONTROL		(BASEPRI_DEFAULT + 17)				/* 48 */
#define BASEPRI_FOREGROUND	(BASEPRI_DEFAULT + 16)				/* 47 */
#define BASEPRI_BACKGROUND	(BASEPRI_DEFAULT + 15)				/* 46 */
#define BASEPRI_DEFAULT		(MAXPRI_USER - (NRQS / 4))			/* 31 */
#define MAXPRI_THROTTLE		(MINPRI + 4)						/*  4 */
#define MINPRI_USER			MINPRI								/*  0 */

#ifdef CONFIG_EMBEDDED
#define DEPRESSPRI	MAXPRI_THROTTLE
#else
#define DEPRESSPRI	MINPRI			/* depress priority */
#endif

/* Type used for thread->sched_mode and saved_mode */
typedef enum {
	TH_MODE_NONE = 0,					/* unassigned, usually for saved_mode only */
	TH_MODE_REALTIME,					/* time constraints supplied */
	TH_MODE_FIXED,						/* use fixed priorities, no decay */
	TH_MODE_TIMESHARE,					/* use timesharing algorithm */
	TH_MODE_FAIRSHARE					/* use fair-share scheduling */		
} sched_mode_t;

/*
 *	Macro to check for invalid priorities.
 */
#define invalid_pri(pri) ((pri) < MINPRI || (pri) > MAXPRI)

struct runq_stats {
	uint64_t				count_sum;
	uint64_t				last_change_timestamp;
};

#if defined(CONFIG_SCHED_TRADITIONAL) || defined(CONFIG_SCHED_PROTO) || defined(CONFIG_SCHED_FIXEDPRIORITY)

struct run_queue {
	int					highq;				/* highest runnable queue */
	int					bitmap[NRQBM];		/* run queue bitmap array */
	int					count;				/* # of threads total */
	int					urgency;			/* level of preemption urgency */
	queue_head_t		queues[NRQS];		/* one for each priority */

	struct runq_stats	runq_stats;
};

#endif /* defined(CONFIG_SCHED_TRADITIONAL) || defined(CONFIG_SCHED_PROTO) || defined(CONFIG_SCHED_FIXEDPRIORITY) */

struct rt_queue {
	int					count;				/* # of threads total */
	queue_head_t		queue;				/* all runnable RT threads */

	struct runq_stats	runq_stats;
};

#if defined(CONFIG_SCHED_TRADITIONAL) || defined(CONFIG_SCHED_PROTO) || defined(CONFIG_SCHED_FIXEDPRIORITY)
struct fairshare_queue {
	int					count;				/* # of threads total */
	queue_head_t		queue;				/* all runnable threads demoted to fairshare scheduling */
	
	struct runq_stats	runq_stats;
};
#endif

#if defined(CONFIG_SCHED_GRRR_CORE)

/*
 * We map standard Mach priorities to an abstract scale that more properly
 * indicates how we want processor time allocated under contention.
 */
typedef uint8_t	grrr_proportional_priority_t;
typedef uint8_t grrr_group_index_t;

#define NUM_GRRR_PROPORTIONAL_PRIORITIES	256
#define MAX_GRRR_PROPORTIONAL_PRIORITY ((grrr_proportional_priority_t)255)

#if 0
#define NUM_GRRR_GROUPS 8					/* log(256) */
#endif

#define NUM_GRRR_GROUPS 64					/* 256/4 */

struct grrr_group {
	queue_chain_t			priority_order;				/* next greatest weight group */
	grrr_proportional_priority_t		minpriority;
	grrr_group_index_t		index;

	queue_head_t			clients;
	int						count;
	uint32_t				weight;
#if 0
	uint32_t				deferred_removal_weight;
#endif
	uint32_t				work;
	thread_t				current_client;
};

struct grrr_run_queue {
	int					count;
	uint32_t			last_rescale_tick;
	struct grrr_group	groups[NUM_GRRR_GROUPS];
	queue_head_t		sorted_group_list;
	uint32_t			weight;
	grrr_group_t		current_group;
	
	struct runq_stats   runq_stats;
};

#endif /* defined(CONFIG_SCHED_GRRR_CORE) */

#define first_timeslice(processor)		((processor)->timeslice > 0)

extern struct rt_queue		rt_runq;

/*
 *	Scheduler routines.
 */

/* Handle quantum expiration for an executing thread */
extern void		thread_quantum_expire(
					timer_call_param_t	processor,
					timer_call_param_t	thread);

/* Context switch check for current processor */
extern ast_t	csw_check(processor_t		processor);

#if defined(CONFIG_SCHED_TRADITIONAL)
extern uint32_t	std_quantum, min_std_quantum;
extern uint32_t	std_quantum_us;
#endif

extern uint32_t thread_depress_time;
extern uint32_t default_timeshare_computation;
extern uint32_t default_timeshare_constraint;

extern uint32_t	max_rt_quantum, min_rt_quantum;

extern int default_preemption_rate;
extern int default_bg_preemption_rate;

#if defined(CONFIG_SCHED_TRADITIONAL)

/*
 *	Age usage (1 << SCHED_TICK_SHIFT) times per second.
 */
#define SCHED_TICK_SHIFT	3

extern unsigned		sched_tick;
extern uint32_t		sched_tick_interval;

#endif /* CONFIG_SCHED_TRADITIONAL */

extern uint64_t		sched_one_second_interval;

/* Periodic computation of various averages */
extern void		compute_averages(void);

extern void		compute_averunnable(
					void			*nrun);

extern void		compute_stack_target(
					void			*arg);

extern void		compute_memory_pressure(
					void			*arg);

extern void		compute_zone_gc_throttle(
					void			*arg);

extern void		compute_pageout_gc_throttle(
					void			*arg);

extern void		compute_pmap_gc_throttle(
					void			*arg);

/*
 *	Conversion factor from usage
 *	to priority.
 */
#if defined(CONFIG_SCHED_TRADITIONAL)
extern uint32_t		sched_pri_shift;
extern uint32_t		sched_fixed_shift;
extern int8_t		sched_load_shifts[NRQS];
#endif

extern int32_t		sched_poll_yield_shift;
extern uint64_t		sched_safe_duration;

extern uint32_t		sched_run_count, sched_share_count;
extern uint32_t		sched_load_average, sched_mach_factor;

extern uint32_t		avenrun[3], mach_factor[3];

extern uint64_t		max_unsafe_computation;
extern uint64_t		max_poll_computation;

#define sched_run_incr()			\
MACRO_BEGIN					\
         hw_atomic_add(&sched_run_count, 1);	\
MACRO_END

#define sched_run_decr()			\
MACRO_BEGIN					\
	hw_atomic_sub(&sched_run_count, 1);	\
MACRO_END

#define sched_share_incr()			\
MACRO_BEGIN											\
	(void)hw_atomic_add(&sched_share_count, 1);		\
MACRO_END

#define sched_share_decr()			\
MACRO_BEGIN											\
	(void)hw_atomic_sub(&sched_share_count, 1);		\
MACRO_END

/*
 *	thread_timer_delta macro takes care of both thread timers.
 */
#define thread_timer_delta(thread, delta)					\
MACRO_BEGIN													\
	(delta) = (typeof(delta))timer_delta(&(thread)->system_timer,			\
							&(thread)->system_timer_save);	\
	(delta) += (typeof(delta))timer_delta(&(thread)->user_timer,			\
							&(thread)->user_timer_save);	\
MACRO_END

#endif	/* _KERN_SCHED_H_ */
