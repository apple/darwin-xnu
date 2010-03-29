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
#include <kern/lock.h>
#include <kern/queue.h>
#include <kern/sched.h>
#include <kern/processor_data.h>

#include <machine/ast_types.h>

struct processor_set {
	queue_head_t		active_queue;	/* active processors */
	queue_head_t		idle_queue;		/* idle processors */

	processor_t			low_pri, low_count;

	int					processor_count;

	int					cpu_set_low, cpu_set_hi;
	int					cpu_set_count;

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
decl_lck_mtx_data(extern,tasks_threads_lock)

struct processor_meta {
	queue_head_t		idle_queue;
	processor_t			primary;
};

typedef struct processor_meta	*processor_meta_t;
#define PROCESSOR_META_NULL		((processor_meta_t) 0)

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
	int					cpu_id;			/* platform numeric id */

	timer_call_data_t	quantum_timer;	/* timer for quantum expiration */
	uint64_t			quantum_end;	/* time when current quantum ends */
	uint64_t			last_dispatch;	/* time of last dispatch */

	uint64_t			deadline;		/* current deadline */
	int					timeslice;		/* quanta before timeslice ends */

	struct run_queue	runq;			/* runq for this processor */
	processor_meta_t	processor_meta;

	struct ipc_port *	processor_self;	/* port for operations */

	processor_t			processor_list;	/* all existing processors */
	processor_data_t	processor_data;	/* per-processor data */
};

extern processor_t		processor_list;
extern unsigned int		processor_count;
decl_simple_lock_data(extern,processor_list_lock)

extern uint32_t			processor_avail_count;

extern processor_t		master_processor;

/*
 *	Processor state is accessed by locking the scheduling lock
 *	for the assigned processor set.
 */
#define PROCESSOR_OFF_LINE		0	/* Not available */
#define PROCESSOR_SHUTDOWN		1	/* Going off-line */
#define PROCESSOR_START			2	/* Being started */
#define PROCESSOR_INACTIVE		3	/* Inactive (unavailable) */
#define	PROCESSOR_IDLE			4	/* Idle (available) */
#define PROCESSOR_DISPATCHING	5	/* Dispatching (idle -> active) */
#define	PROCESSOR_RUNNING		6	/* Normal execution */

extern processor_t	current_processor(void);

extern processor_t	cpu_to_processor(
						int			cpu);

/* Lock macros */

#define pset_lock(p)			simple_lock(&(p)->sched_lock)
#define pset_unlock(p)			simple_unlock(&(p)->sched_lock)
#define pset_lock_init(p)		simple_lock_init(&(p)->sched_lock, 0)

/* Update hints */

#define pset_pri_hint(ps, p, pri)		\
MACRO_BEGIN												\
	if ((p) != (ps)->low_pri) {							\
		if ((pri) < (ps)->low_pri->current_pri)			\
			(ps)->low_pri = (p);						\
		else											\
		if ((ps)->low_pri->state < PROCESSOR_IDLE)		\
			(ps)->low_pri = (p);						\
	}													\
MACRO_END

#define pset_count_hint(ps, p, cnt)		\
MACRO_BEGIN												\
	if ((p) != (ps)->low_count) {						\
		if ((cnt) < (ps)->low_count->runq.count)		\
			(ps)->low_count = (p);						\
		else											\
		if ((ps)->low_count->state < PROCESSOR_IDLE)	\
			(ps)->low_count = (p);						\
	}													\
MACRO_END

extern void		processor_bootstrap(void) __attribute__((section("__TEXT, initcode")));

extern void		processor_init(
					processor_t		processor,
					int				cpu_id,
					processor_set_t	processor_set) __attribute__((section("__TEXT, initcode")));

extern void		processor_meta_init(
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
					pset_node_t			node) __attribute__((section("__TEXT, initcode")));

extern kern_return_t	processor_info_count(
							processor_flavor_t		flavor,
							mach_msg_type_number_t	*count);

#define pset_deallocate(x)
#define pset_reference(x)

extern void				machine_run_count(
							uint32_t	count);

extern boolean_t		machine_processor_is_inactive(
							processor_t			processor);

extern processor_t		machine_choose_processor(
							processor_set_t		pset,
							processor_t			processor);

#else	/* MACH_KERNEL_PRIVATE */

__BEGIN_DECLS

extern void		pset_deallocate(
					processor_set_t	pset);

extern void		pset_reference(
					processor_set_t	pset);

__END_DECLS

#endif	/* MACH_KERNEL_PRIVATE */

#endif	/* _KERN_PROCESSOR_H_ */
