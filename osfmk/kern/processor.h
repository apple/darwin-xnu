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
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
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
 *	processor.h:	Processor and processor-set definitions.
 */

#ifndef	_KERN_PROCESSOR_H_
#define	_KERN_PROCESSOR_H_

/*
 *	Data structures for managing processors and sets of processors.
 */
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <kern/kern_types.h>

#include <sys/appleapiopts.h>

#ifdef	__APPLE_API_PRIVATE

#ifdef	MACH_KERNEL_PRIVATE

#include <cpus.h>

#include <mach/mach_types.h>
#include <kern/cpu_number.h>
#include <kern/lock.h>
#include <kern/queue.h>
#include <kern/sched.h>

#include <machine/ast_types.h>

struct processor_set {
	queue_head_t		idle_queue;		/* idle processors */
	int					idle_count;		/* how many ? */
	queue_head_t		active_queue;	/* active processors */

	queue_head_t		processors;		/* all processors here */
	int					processor_count;/* how many ? */
	decl_simple_lock_data(,sched_lock)	/* lock for above */

	struct	run_queue	runq;			/* runq for this set */

	queue_head_t		tasks;			/* tasks assigned */
	int					task_count;		/* how many */
	queue_head_t		threads;		/* threads in this set */
	int					thread_count;	/* how many */
	int					ref_count;		/* structure ref count */
	boolean_t			active;			/* is pset in use */
	decl_mutex_data(,	lock)			/* lock for above */

	int					timeshare_quanta;	/* timeshare quantum factor */
	int					quantum_factors[NCPUS+1];

	struct ipc_port	*	pset_self;		/* port for operations */
	struct ipc_port *	pset_name_self;	/* port for information */

	uint32_t			run_count;		/* threads running in set */
	uint32_t			share_count;	/* timeshare threads running in set */

	integer_t			mach_factor;	/* mach_factor */
	integer_t			load_average;	/* load_average */
	uint32_t			sched_load;		/* load avg for scheduler */
};

struct processor {
	queue_chain_t		processor_queue;/* idle/active/action queue link,
										 * MUST remain the first element */
	int					state;			/* See below */
	struct thread
						*active_thread,	/* thread running on processor */
						*next_thread,	/* next thread to run if dispatched */
						*idle_thread;	/* this processor's idle thread. */

	processor_set_t		processor_set;	/* current membership */

	int					current_pri;	/* priority of current thread */

	timer_call_data_t	quantum_timer;	/* timer for quantum expiration */
	uint64_t			quantum_end;	/* time when current quantum ends */
	uint64_t			last_dispatch;	/* time of last dispatch */

	int					timeslice;		/* quanta before timeslice ends */
	uint64_t			deadline;		/* current deadline */

	struct run_queue	runq;			/* local runq for this processor */

	queue_chain_t		processors;		/* all processors in set */
	decl_simple_lock_data(,lock)
	struct ipc_port		*processor_self;/* port for operations */
	int					slot_num;		/* machine-indep slot number */
};

extern struct processor_set	default_pset;
extern processor_t	master_processor;

extern struct processor	processor_array[NCPUS];

/*
 *	NOTE: The processor->processor_set link is needed in one of the
 *	scheduler's critical paths.  [Figure out where to look for another
 *	thread to run on this processor.]  It is accessed without locking.
 *	The following access protocol controls this field.
 *
 *	Read from own processor - just read.
 *	Read from another processor - lock processor structure during read.
 *	Write from own processor - lock processor structure during write.
 *	Write from another processor - NOT PERMITTED.
 *
 */

/*
 *	Processor state locking:
 *
 *	Values for the processor state are defined below.  If the processor
 *	is off-line or being shutdown, then it is only necessary to lock
 *	the processor to change its state.  Otherwise it is only necessary
 *	to lock its processor set's sched_lock.  Scheduler code will
 *	typically lock only the sched_lock, but processor manipulation code
 *	will often lock both.
 */

#define PROCESSOR_OFF_LINE		0	/* Not available */
#define	PROCESSOR_RUNNING		1	/* Normal execution */
#define	PROCESSOR_IDLE			2	/* Idle */
#define PROCESSOR_DISPATCHING	3	/* Dispatching (idle -> running) */
#define PROCESSOR_SHUTDOWN		4	/* Going off-line */
#define PROCESSOR_START			5	/* Being started */

/*
 *	Use processor ptr array to find current processor's data structure.
 *	This replaces a multiplication (index into processor_array) with
 *	an array lookup and a memory reference.  It also allows us to save
 *	space if processor numbering gets too sparse.
 */

extern processor_t	processor_ptr[NCPUS];

#define cpu_to_processor(i)	(processor_ptr[i])

#define current_processor()	(processor_ptr[cpu_number()])

/* Compatibility -- will go away */

#define cpu_state(slot_num)	(processor_ptr[slot_num]->state)
#define cpu_idle(slot_num)	(cpu_state(slot_num) == PROCESSOR_IDLE)

/* Useful lock macros */

#define	pset_lock(pset)		mutex_lock(&(pset)->lock)
#define	pset_lock_try(pset)	mutex_try(&(pset)->lock)
#define pset_unlock(pset)	mutex_unlock(&(pset)->lock)

#define processor_lock(pr)	simple_lock(&(pr)->lock)
#define processor_unlock(pr)	simple_unlock(&(pr)->lock)

extern void		pset_sys_bootstrap(void);

#define timeshare_quanta_update(pset)					\
MACRO_BEGIN												\
	int		proc_count = (pset)->processor_count;		\
	int		runq_count = (pset)->runq.count;			\
														\
	(pset)->timeshare_quanta = (pset)->quantum_factors[	\
					(runq_count > proc_count)?			\
							proc_count: runq_count];	\
MACRO_END

#define pset_run_incr(pset)					\
	hw_atomic_add(&(pset)->run_count, 1)

#define pset_run_decr(pset)					\
	hw_atomic_sub(&(pset)->run_count, 1)

#define pset_share_incr(pset)				\
	hw_atomic_add(&(pset)->share_count, 1)

#define pset_share_decr(pset)				\
	hw_atomic_sub(&(pset)->share_count, 1)

extern void		cpu_up(
					int		cpu);

extern kern_return_t	processor_shutdown(
							processor_t		processor);

extern void		pset_remove_processor(
					processor_set_t		pset,
					processor_t			processor);

extern void		pset_add_processor(
					processor_set_t		pset,
					processor_t			processor);

extern void		pset_remove_task(
					processor_set_t		pset,
					task_t				task);

extern void		pset_add_task(
					processor_set_t		pset,
					task_t				task);

extern void		pset_remove_thread(
					processor_set_t		pset,
					thread_t			thread);

extern void		pset_add_thread(
					processor_set_t		pset,
					thread_t			thread);

extern void		thread_change_psets(
					thread_t			thread,
					processor_set_t		old_pset,
					processor_set_t		new_pset);

extern kern_return_t	processor_assign(
							processor_t			processor,
							processor_set_t		new_pset,
							boolean_t			wait);

extern kern_return_t	processor_info_count(
							processor_flavor_t		flavor,
							mach_msg_type_number_t	*count);

#endif	/* MACH_KERNEL_PRIVATE */

extern kern_return_t	processor_start(
							processor_t		processor);

extern kern_return_t	processor_exit(
							processor_t		processor);

#endif	/* __APPLE_API_PRIVATE */

extern void		pset_deallocate(
					processor_set_t	pset);

extern void		pset_reference(
					processor_set_t	pset);

#endif	/* _KERN_PROCESSOR_H_ */
