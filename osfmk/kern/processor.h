/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
#include <kern/lock.h>
#include <kern/queue.h>
#include <kern/sched.h>
#include <kern/processor_data.h>

#include <machine/ast_types.h>

struct processor_set {
	queue_head_t		active_queue;	/* active processors */
	queue_head_t		idle_queue;		/* idle processors */
	int					idle_count;

	processor_t			low_hint;
	processor_t			high_hint;

	int					processor_count;

	decl_simple_lock_data(,sched_lock)	/* lock for above */

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

extern queue_head_t		tasks, threads;
extern int				tasks_count, threads_count;
decl_mutex_data(extern,tasks_threads_lock)

struct processor {
	queue_chain_t		processor_queue;/* idle/active queue link,
										 * MUST remain the first element */
	int					state;			/* See below */
	struct thread
						*active_thread,	/* thread running on processor */
						*next_thread,	/* next thread when dispatched */
						*idle_thread;	/* this processor's idle thread. */

	processor_set_t		processor_set;	/* assigned set */

	int					current_pri;	/* priority of current thread */

	timer_call_data_t	quantum_timer;	/* timer for quantum expiration */
	uint64_t			quantum_end;	/* time when current quantum ends */
	uint64_t			last_dispatch;	/* time of last dispatch */

	uint64_t			deadline;		/* current deadline */
	int					timeslice;		/* quanta before timeslice ends */

	struct run_queue	runq;			/* runq for this processor */

	struct ipc_port *	processor_self;	/* port for operations */
	decl_simple_lock_data(,lock)

	processor_t			processor_list;	/* all existing processors */
	processor_data_t	processor_data;	/* per-processor data */
};

extern processor_t		processor_list;
extern unsigned int		processor_count;
decl_simple_lock_data(extern,processor_list_lock)

extern processor_t	master_processor;

/*
 *	Processor state is accessed by locking the scheduling lock
 *	for the assigned processor set.
 */
#define PROCESSOR_OFF_LINE		0	/* Not available */
#define PROCESSOR_SHUTDOWN		1	/* Going off-line */
#define PROCESSOR_START			2	/* Being started */
#define	PROCESSOR_IDLE			3	/* Idle */
#define PROCESSOR_DISPATCHING	4	/* Dispatching (idle -> running) */
#define	PROCESSOR_RUNNING		5	/* Normal execution */

extern processor_t	current_processor(void);

extern processor_t	cpu_to_processor(
						int			cpu);

/* Lock macros */

#define pset_lock(p)			simple_lock(&(p)->sched_lock)
#define pset_unlock(p)			simple_unlock(&(p)->sched_lock)
#define pset_lock_init(p)		simple_lock_init(&(p)->sched_lock, 0)

#define processor_lock(p)		simple_lock(&(p)->lock)
#define processor_unlock(p)		simple_unlock(&(p)->lock)
#define processor_lock_init(p)	simple_lock_init(&(p)->lock, 0)

/* Update hints */

#define pset_hint_low(ps, p)	\
MACRO_BEGIN														\
	if ((ps)->low_hint != PROCESSOR_NULL) {						\
		if ((p) != (ps)->low_hint) {							\
			if ((p)->runq.count < (ps)->low_hint->runq.count)	\
				(ps)->low_hint = (p);							\
		}														\
	}															\
	else														\
		(ps)->low_hint = (p);									\
MACRO_END

#define pset_hint_high(ps, p)	\
MACRO_BEGIN														\
	if ((ps)->high_hint != PROCESSOR_NULL) {					\
		if ((p) != (ps)->high_hint) {							\
			if ((p)->runq.count > (ps)->high_hint->runq.count)	\
				(ps)->high_hint = (p);							\
		}														\
	}															\
	else														\
		(ps)->high_hint = (p);									\
MACRO_END

extern void		processor_bootstrap(void) __attribute__((section("__TEXT, initcode")));

extern void		processor_init(
					processor_t		processor,
					int				slot_num,
					processor_set_t	processor_set) __attribute__((section("__TEXT, initcode")));

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
					pset_node_t			node) __attribute__((section("__TEXT, initcode")));

extern kern_return_t	processor_info_count(
							processor_flavor_t		flavor,
							mach_msg_type_number_t	*count);

#define pset_deallocate(x)
#define pset_reference(x)

#else	/* MACH_KERNEL_PRIVATE */

__BEGIN_DECLS

extern void		pset_deallocate(
					processor_set_t	pset);

extern void		pset_reference(
					processor_set_t	pset);

__END_DECLS

#endif	/* MACH_KERNEL_PRIVATE */

#ifdef	XNU_KERNEL_PRIVATE

extern uint32_t		processor_avail_count;

#endif
#endif	/* _KERN_PROCESSOR_H_ */
