/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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

#include <stat_time.h>

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
#define DEPRESSPRI	MINPRI			/* depress priority */

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
#define MINPRI_USER			MINPRI								/*  0 */

/*
 *	Macro to check for invalid priorities.
 */
#define invalid_pri(pri) ((pri) < MINPRI || (pri) > MAXPRI)

struct run_queue {
	int					highq;				/* highest runnable queue */
	int					bitmap[NRQBM];		/* run queue bitmap array */
	int					count;				/* # of threads total */
	int					urgency;			/* level of preemption urgency */
	queue_head_t		queues[NRQS];		/* one for each priority */
};

typedef struct run_queue	*run_queue_t;
#define RUN_QUEUE_NULL		((run_queue_t) 0)

#define first_timeslice(processor)		((processor)->timeslice > 0)

#define	processor_timeslice_setup(processor, thread)			\
MACRO_BEGIN														\
	(processor)->timeslice =									\
		((thread)->sched_mode & TH_MODE_TIMESHARE)?				\
			(processor)->processor_set->timeshare_quanta: 1;	\
MACRO_END

#define thread_quantum_init(thread)							\
MACRO_BEGIN													\
	(thread)->current_quantum = 							\
		((thread)->sched_mode & TH_MODE_REALTIME)?			\
			(thread)->realtime.computation: std_quantum;	\
MACRO_END

/* Invoked at splsched by a thread on itself */
#define csw_needed(thread, processor) (										\
	((thread)->state & TH_SUSP)										||		\
	(first_timeslice(processor)?											\
	 ((processor)->runq.highq > (thread)->sched_pri				||			\
	  (processor)->processor_set->runq.highq > (thread)->sched_pri) :		\
	 ((processor)->runq.highq >= (thread)->sched_pri			||			\
	  (processor)->processor_set->runq.highq >= (thread)->sched_pri))	)

/*
 *	Scheduler routines.
 */

/* Remove thread from its run queue */
extern run_queue_t	run_queue_remove(
						thread_t	thread);

/* Handle quantum expiration for an executing thread */
extern void		thread_quantum_expire(
					timer_call_param_t	processor,
					timer_call_param_t	thread);

/* Called at splsched by a thread on itself */
extern ast_t	csw_check(
					thread_t		thread,
					processor_t		processor);

extern uint32_t	std_quantum, min_std_quantum;
extern uint32_t	std_quantum_us;

extern uint32_t	max_rt_quantum, min_rt_quantum;

extern uint32_t	sched_cswtime;

/*
 *	Age usage (1 << SCHED_TICK_SHIFT) times per second.
 */
#define SCHED_TICK_SHIFT	3

extern unsigned		sched_tick;
extern uint32_t		sched_tick_interval;

/* Periodic computation of various averages */
extern void		compute_averages(void);

extern void		compute_averunnable(
					void			*nrun);

extern void		compute_stack_target(
					void			*arg);

/*
 *	Conversion factor from usage
 *	to priority.
 */
extern uint32_t		sched_pri_shift;

/*
 *	Scaling factor for usage
 *	based on load.
 */
extern int8_t		sched_load_shifts[NRQS];

extern int32_t		sched_poll_yield_shift;
extern uint32_t		sched_safe_duration;

extern uint64_t		max_unsafe_computation;
extern uint64_t		max_poll_computation;

extern uint32_t		avenrun[3], mach_factor[3];

/*
 *	thread_timer_delta macro takes care of both thread timers.
 */
#define thread_timer_delta(thread, delta)					\
MACRO_BEGIN													\
	(delta) = timer_delta(&(thread)->system_timer,			\
							&(thread)->system_timer_save);	\
	(delta) += timer_delta(&(thread)->user_timer,			\
							&(thread)->user_timer_save);	\
MACRO_END

#endif	/* _KERN_SCHED_H_ */
