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

extern struct processor_set	default_pset;
extern processor_t	master_processor;

#ifdef MACH_KERNEL_PRIVATE

#include <cpus.h>
#include <mach_host.h>

#include <mach/mach_types.h>
#include <kern/cpu_number.h>
#include <kern/lock.h>
#include <kern/queue.h>
#include <kern/sched.h>

#if	NCPUS > 1
#include <machine/ast_types.h>
#endif	/* NCPUS > 1 */

struct processor_set {
	struct	run_queue	runq;			/* runq for this set */
	queue_head_t		idle_queue;		/* idle processors */
	int					idle_count;		/* how many ? */
	decl_simple_lock_data(,idle_lock)	/* lock for above */
	queue_head_t		processors;		/* all processors here */
	int					processor_count;/* how many ? */
	decl_simple_lock_data(,processors_lock)	/* lock for above */
	queue_head_t		tasks;			/* tasks assigned */
	int					task_count;		/* how many */
	queue_head_t		threads;		/* threads in this set */
	int					thread_count;	/* how many */
	int					ref_count;		/* structure ref count */
	boolean_t			active;			/* is pset in use */
	decl_mutex_data(,	lock)			/* lock for everything else */
	struct ipc_port	*	pset_self;		/* port for operations */
	struct ipc_port *	pset_name_self;	/* port for information */
	int					max_priority;	/* maximum priority */
	int					policies;		/* bit vector for policies */
	int					set_quantum;	/* current default quantum */
#if	NCPUS > 1
	int					quantum_adj_index;			/* runtime quantum adj. */
	decl_simple_lock_data(,quantum_adj_lock)		/* lock for above */
	int					machine_quantum[NCPUS+1];	/* ditto */
#endif	/* NCPUS > 1 */
	integer_t			mach_factor;	/* mach_factor */
	integer_t			load_average;	/* load_average */
	long				sched_load;		/* load avg for scheduler */
	policy_t			policy_default;	/* per set default */
	policy_base_data_t	policy_base;	/* base attributes */
	policy_limit_data_t	policy_limit;	/* limit attributes */
};

struct processor {
	struct run_queue	runq;			/* local runq for this processor */
	queue_chain_t		processor_queue;/* idle/assign/shutdown queue link */
	int					state;			/* See below */
	struct thread_shuttle
						*next_thread,	/* next thread to run if dispatched */
						*idle_thread;	/* this processor's idle thread. */
	int					quantum;		/* quantum for current thread */
	boolean_t			first_quantum;	/* first quantum in succession */
	int					last_quantum;	/* last quantum assigned */

	processor_set_t		processor_set;		/* processor set I belong to */
	processor_set_t		processor_set_next;	/* set I will belong to */
	queue_chain_t		processors;			/* all processors in set */
	decl_simple_lock_data(,lock)
	struct ipc_port		*processor_self;/* port for operations */
	int					slot_num;		/* machine-indep slot number */
#if	NCPUS > 1
	ast_check_t			ast_check_data;	/* for remote ast_check invocation */
	queue_chain_t		softclock_queue;/* cpus handling softclocks */
#endif	/* NCPUS > 1 */
	/* punt id data temporarily */
};

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
 *	to lock its processor set's idle_lock.  Scheduler code will
 *	typically lock only the idle_lock, but processor manipulation code
 *	will often lock both.
 */

#define PROCESSOR_OFF_LINE		0	/* Not in system */
#define	PROCESSOR_RUNNING		1	/* Running a normal thread */
#define	PROCESSOR_IDLE			2	/* idle */
#define PROCESSOR_DISPATCHING	3	/* dispatching (idle -> running) */
#define	PROCESSOR_ASSIGN		4	/* Assignment is changing */
#define PROCESSOR_SHUTDOWN		5	/* Being shutdown */
#define PROCESSOR_START			6	/* Being start */

/*
 *	Use processor ptr array to find current processor's data structure.
 *	This replaces a multiplication (index into processor_array) with
 *	an array lookup and a memory reference.  It also allows us to save
 *	space if processor numbering gets too sparse.
 */

extern processor_t	processor_ptr[NCPUS];

#define cpu_to_processor(i)	(processor_ptr[i])

#define current_processor()	(processor_ptr[cpu_number()])
#define current_processor_set()	(current_processor()->processor_set)

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

/* Implemented by MD layer */

extern void		cpu_up(
				int		cpu);

extern kern_return_t	processor_shutdown(
				processor_t	processor);

extern void		pset_remove_processor(
				processor_set_t	pset,
				processor_t	processor);

extern void		pset_add_processor(
				processor_set_t	pset,
				processor_t	processor);

extern void		pset_remove_task(
				processor_set_t	pset,
				task_t		task);

extern void		pset_add_task(
				processor_set_t	pset,
				task_t		task);

extern void		pset_remove_thread(
				processor_set_t	pset,
				thread_t	thread);

extern void		pset_add_thread(
				processor_set_t	pset,
				thread_t	thread);

extern void		thread_change_psets(
				thread_t	thread,
				processor_set_t old_pset,
				processor_set_t new_pset);

extern void		pset_deallocate(
				processor_set_t	pset);

extern void		pset_reference(
				processor_set_t	pset);

extern kern_return_t	processor_assign(
				processor_t	processor,
				processor_set_t	new_pset,
				boolean_t	wait);

extern kern_return_t	processor_info_count(
				processor_flavor_t flavor,
				mach_msg_type_number_t *count);
#endif /* MACH_KERNEL_PRIVATE */

extern kern_return_t	processor_start(
				processor_t	processor);

extern kern_return_t	processor_exit(
				processor_t	processor);

#endif	/* _KERN_PROCESSOR_H_ */
