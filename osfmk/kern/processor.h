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
 *	processor.h:	Processor and processor-related definitions.
 */

#ifndef	_KERN_PROCESSOR_H_
#define	_KERN_PROCESSOR_H_

#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <kern/kern_types.h>

#include <sys/cdefs.h>

#ifdef	MACH_KERNEL_PRIVATE

#include <mach/mach_types.h>
#include <kern/ast.h>
#include <kern/cpu_number.h>
#include <kern/simple_lock.h>
#include <kern/locks.h>
#include <kern/queue.h>
#include <kern/sched.h>
#include <mach/sfi_class.h>
#include <kern/processor_data.h>

#include <machine/ast_types.h>

struct processor_set {
	queue_head_t		active_queue;	/* active processors */
	queue_head_t		idle_queue;		/* idle processors */
	queue_head_t		idle_secondary_queue;		/* idle secondary processors */

	int					online_processor_count;

	int					cpu_set_low, cpu_set_hi;
	int					cpu_set_count;

	decl_simple_lock_data(,sched_lock)	/* lock for above */

#if defined(CONFIG_SCHED_TRADITIONAL) || defined(CONFIG_SCHED_MULTIQ)
	struct run_queue	pset_runq;      /* runq for this processor set */
#endif

#if defined(CONFIG_SCHED_TRADITIONAL)
	int					pset_runq_bound_count;
		/* # of threads in runq bound to any processor in pset */
#endif

	/* CPUs that have been sent an unacknowledged remote AST for scheduling purposes */
	uint32_t			pending_AST_cpu_mask;

	struct ipc_port	*	pset_self;		/* port for operations */
	struct ipc_port *	pset_name_self;	/* port for information */

	processor_set_t		pset_list;		/* chain of associated psets */
	pset_node_t			node;
};

extern struct processor_set	pset0;

struct pset_node {
	processor_set_t		psets;			/* list of associated psets */

	pset_node_t			nodes;			/* list of associated subnodes */
	pset_node_t			node_list;		/* chain of associated nodes */

	pset_node_t			parent;
};

extern struct pset_node	pset_node0;

extern queue_head_t		tasks, terminated_tasks, threads; /* Terminated tasks are ONLY for stackshot */
extern int				tasks_count, terminated_tasks_count, threads_count;
decl_lck_mtx_data(extern,tasks_threads_lock)

struct processor {
	queue_chain_t		processor_queue;/* idle/active queue link,
										 * MUST remain the first element */
	int					state;			/* See below */
	boolean_t		is_SMT;
	struct thread
						*active_thread,	/* thread running on processor */
						*next_thread,	/* next thread when dispatched */
						*idle_thread;	/* this processor's idle thread. */

	processor_set_t		processor_set;	/* assigned set */

	int					current_pri;	/* priority of current thread */
	sched_mode_t		current_thmode;	/* sched mode of current thread */
	sfi_class_id_t		current_sfi_class;	/* SFI class of current thread */
	int					cpu_id;			/* platform numeric id */

	timer_call_data_t	quantum_timer;	/* timer for quantum expiration */
	uint64_t			quantum_end;	/* time when current quantum ends */
	uint64_t			last_dispatch;	/* time of last dispatch */

	uint64_t			deadline;		/* current deadline */
	int					timeslice;		/* quanta before timeslice ends */

#if defined(CONFIG_SCHED_TRADITIONAL) || defined(CONFIG_SCHED_MULTIQ)
	struct run_queue	runq;			/* runq for this processor */
#endif

#if defined(CONFIG_SCHED_TRADITIONAL)
	int					runq_bound_count; /* # of threads bound to this processor */
#endif
#if defined(CONFIG_SCHED_GRRR)
	struct grrr_run_queue	grrr_runq;      /* Group Ratio Round-Robin runq */
#endif

	processor_t			processor_primary;	/* pointer to primary processor for
											 * secondary SMT processors, or a pointer
											 * to ourselves for primaries or non-SMT */
	processor_t		processor_secondary;
	struct ipc_port *	processor_self;	/* port for operations */

	processor_t			processor_list;	/* all existing processors */
	processor_data_t	processor_data;	/* per-processor data */
};

extern processor_t		processor_list;
extern unsigned int		processor_count;
decl_simple_lock_data(extern,processor_list_lock)

extern uint32_t			processor_avail_count;

extern processor_t		master_processor;

extern boolean_t		sched_stats_active;

/*
 *	Processor state is accessed by locking the scheduling lock
 *	for the assigned processor set.
 *
 *           -------------------- SHUTDOWN
 *          /                     ^     ^
 *        _/                      |      \
 *  OFF_LINE ---> START ---> RUNNING ---> IDLE ---> DISPATCHING
 *         \_________________^   ^ ^______/           /
 *                                \__________________/
 *
 *  Most of these state transitions are externally driven as a
 *  a directive (for instance telling an IDLE processor to start
 *  coming out of the idle state to run a thread). However these
 *  are typically paired with a handshake by the processor itself
 *  to indicate that it has completed a transition of indeterminate
 *  length (for example, the DISPATCHING->RUNNING or START->RUNNING
 *  transitions must occur on the processor itself).
 *
 *  The boot processor has some special cases, and skips the START state,
 *  since it has already bootstrapped and is ready to context switch threads.
 *
 *  When a processor is in DISPATCHING or RUNNING state, the current_pri,
 *  current_thmode, and deadline fields should be set, so that other
 *  processors can evaluate if it is an appropriate candidate for preemption.
*/
#define PROCESSOR_OFF_LINE		0	/* Not available */
#define PROCESSOR_SHUTDOWN		1	/* Going off-line */
#define PROCESSOR_START			2	/* Being started */
/*                     			3	   Formerly Inactive (unavailable) */
#define	PROCESSOR_IDLE			4	/* Idle (available) */
#define PROCESSOR_DISPATCHING	5	/* Dispatching (idle -> active) */
#define	PROCESSOR_RUNNING		6	/* Normal execution */

extern processor_t	current_processor(void);

/* Lock macros */

#define pset_lock(p)			simple_lock(&(p)->sched_lock)
#define pset_unlock(p)			simple_unlock(&(p)->sched_lock)
#define pset_lock_init(p)		simple_lock_init(&(p)->sched_lock, 0)

extern void		processor_bootstrap(void);

extern void		processor_init(
					processor_t		processor,
					int				cpu_id,
					processor_set_t	processor_set);

extern void		processor_set_primary(
					processor_t		processor,
					processor_t		primary);

extern kern_return_t	processor_shutdown(
							processor_t		processor);

extern void		processor_queue_shutdown(
					processor_t		processor);

extern processor_set_t	processor_pset(
							processor_t		processor);

extern pset_node_t		pset_node_root(void);

extern processor_set_t	pset_create(
							pset_node_t		node);

extern void		pset_init(
					processor_set_t		pset,
					pset_node_t			node);

extern kern_return_t	processor_info_count(
							processor_flavor_t		flavor,
							mach_msg_type_number_t	*count);

#define pset_deallocate(x)
#define pset_reference(x)

extern void				machine_run_count(
							uint32_t	count);

extern processor_t		machine_choose_processor(
							processor_set_t		pset,
							processor_t			processor);

#define next_pset(p)	(((p)->pset_list != PROCESSOR_SET_NULL)? (p)->pset_list: (p)->node->psets)

#else	/* MACH_KERNEL_PRIVATE */

__BEGIN_DECLS

extern void		pset_deallocate(
					processor_set_t	pset);

extern void		pset_reference(
					processor_set_t	pset);

__END_DECLS

#endif	/* MACH_KERNEL_PRIVATE */

#ifdef KERNEL_PRIVATE
__BEGIN_DECLS
extern processor_t	cpu_to_processor(int cpu);
__END_DECLS

#endif /* KERNEL_PRIVATE */

#endif	/* _KERN_PROCESSOR_H_ */
