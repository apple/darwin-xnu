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
 * Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
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
 *	File:	task.h
 *	Author:	Avadis Tevanian, Jr.
 *
 *	This file contains the structure definitions for tasks.
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

#ifndef	_KERN_TASK_H_
#define _KERN_TASK_H_

#include <kern/kern_types.h>
#include <mach/mach_types.h>
#include <vm/pmap.h>

#ifdef	__APPLE_API_PRIVATE

#ifdef	MACH_KERNEL_PRIVATE

#include <mach/boolean.h>
#include <mach/port.h>
#include <mach/time_value.h>
#include <mach/message.h>
#include <mach/mach_param.h>
#include <mach/task_info.h>
#include <mach/exception_types.h>
#include <mach_prof.h>
#include <machine/task.h>
#include <kern/queue.h>
#include <kern/exception.h>
#include <kern/lock.h>
#include <kern/syscall_emulation.h>
#include <norma_task.h>
#include <mach_host.h>
#include <fast_tas.h>
#include <task_swapper.h>
#include <kern/thread_act.h>

typedef struct task {
	/* Synchronization/destruction information */
	decl_mutex_data(,lock)		/* Task's lock */
	int		ref_count;	/* Number of references to me */
	boolean_t	active;		/* Task has not been terminated */
	boolean_t	kernel_loaded;	/* Created with kernel_task_create() */

	/* Miscellaneous */
	vm_map_t	map;		/* Address space description */
	queue_chain_t	pset_tasks;	/* list of tasks assigned to pset */
	void		*user_data;	/* Arbitrary data settable via IPC */
	int		suspend_count;	/* Internal scheduling only */

#if	TASK_SWAPPER
	/* Task swapper data */
	unsigned short	swap_state;	/* swap state (e.g. IN/OUT) */
	unsigned short	swap_flags;	/* swap flags (e.g. MAKE_UNSWAPP) */
	unsigned int	swap_stamp;	/* when last swapped */
	unsigned long	swap_rss;	/* size (pages) when last swapped */
	int		swap_ast_waiting; /* number of threads that have not */
					  /* reached a clean point and halted */
	int		swap_nswap;	/* number of times this task swapped */
	queue_chain_t	swapped_tasks;	/* list of non-resident tasks */
#endif	/* TASK_SWAPPER */

	/* Activations in this task */
	queue_head_t	thr_acts;	/* list of thread_activations */
	int		thr_act_count;
	int		res_act_count;
	int		active_act_count; /* have not terminate_self yet */

	processor_set_t	processor_set;	/* processor set for new threads */
#if	MACH_HOST
	boolean_t	may_assign;	/* can assigned pset be changed? */
	boolean_t	assign_active;	/* waiting for may_assign */
#endif	/* MACH_HOST */

	/* User-visible scheduling information */
	integer_t		user_stop_count;	/* outstanding stops */

	task_role_t		role;

	integer_t		priority;			/* base priority for threads */
	integer_t		max_priority;		/* maximum priority for threads */

	/* Task security token */
	security_token_t sec_token;
        
	/* Statistics */
	time_value_t	total_user_time;	/* user time for dead threads */
	time_value_t	total_system_time;	/* system time for dead threads */

#if	MACH_PROF
	boolean_t	task_profiled;  /* is task being profiled ? */
	struct prof_data *profil_buffer;/* profile struct if so */
#endif	/* MACH_PROF */

	/* IPC structures */
	decl_mutex_data(,itk_lock_data)
	struct ipc_port *itk_self;	/* not a right, doesn't hold ref */
	struct ipc_port *itk_sself;	/* a send right */
	struct exception_action exc_actions[EXC_TYPES_COUNT];
		 			/* a send right each valid element  */
	struct ipc_port *itk_host;	/* a send right */
	struct ipc_port *itk_bootstrap;	/* a send right */
	struct ipc_port *itk_registered[TASK_PORT_REGISTER_MAX];
					/* all send rights */

	struct ipc_space *itk_space;

	/* Synchronizer ownership information */
	queue_head_t	semaphore_list;		/* list of owned semaphores   */
	queue_head_t	lock_set_list;		/* list of owned lock sets    */
	int		semaphores_owned;	/* number of semaphores owned */
	int 		lock_sets_owned;	/* number of lock sets owned  */

	/* User space system call emulation support */
	struct 	eml_dispatch	*eml_dispatch;

        /* Ledgers */
	struct ipc_port	*wired_ledger_port;
	struct ipc_port *paged_ledger_port;
        
#if	NORMA_TASK
	long		child_node;	/* if != -1, node for new children */
#endif	/* NORMA_TASK */
#if	FAST_TAS
	vm_offset_t	fast_tas_base;
	vm_offset_t	fast_tas_end;
#endif	/* FAST_TAS */
	MACHINE_TASK
	integer_t faults;              /* faults counter */
        integer_t pageins;             /* pageins counter */
        integer_t cow_faults;          /* copy on write fault counter */
        integer_t messages_sent;       /* messages sent counter */
        integer_t messages_received;   /* messages received counter */
        integer_t syscalls_mach;       /* mach system call counter */
        integer_t syscalls_unix;       /* unix system call counter */
        integer_t csw;                 /* context switch counter */
#ifdef  MACH_BSD 
	void *bsd_info;
#endif  
	vm_offset_t	system_shared_region;
	vm_offset_t	dynamic_working_set;
} Task;

#define task_lock(task)		mutex_lock(&(task)->lock)
#define task_lock_try(task)	mutex_try(&(task)->lock)
#define task_unlock(task)	mutex_unlock(&(task)->lock)

#define	itk_lock_init(task)	mutex_init(&(task)->itk_lock_data, \
					   ETAP_THREAD_TASK_ITK)
#define	itk_lock(task)		mutex_lock(&(task)->itk_lock_data)
#define	itk_unlock(task)	mutex_unlock(&(task)->itk_lock_data)

#define task_reference_locked(task) ((task)->ref_count++)

/*
 *	Internal only routines
 */

/* Initialize task module */
extern void		task_init(void);

/* task create */
extern kern_return_t	task_create_local(
				task_t		parent_task,
				boolean_t	inherit_memory,
				boolean_t	kernel_loaded,
				task_t		*child_task);	/* OUT */

extern void		consider_task_collect(void);

#define	current_task_fast()	(current_act_fast()->task)
#define current_task()		current_task_fast()

#endif	/* MACH_KERNEL_PRIVATE */

extern task_t		kernel_task;

/* Temporarily hold all threads in a task */
extern kern_return_t	task_hold(
				task_t	task);

/* Release temporary hold on all threads in a task */
extern kern_return_t	task_release(
				task_t	task);

/* Get a task prepared for major changes */
extern kern_return_t	task_halt(
				task_t	task);

#if defined(MACH_KERNEL_PRIVATE) || defined(BSD_BUILD)
extern kern_return_t	task_importance(
							task_t			task,
							integer_t		importance);
#endif

/* JMM - should just be temporary (implementation in bsd_kern still) */
extern void 	*get_bsdtask_info(task_t);
extern void	set_bsdtask_info(task_t,void *);
extern vm_map_t get_task_map(task_t);
extern vm_map_t	swap_task_map(task_t, vm_map_t);
extern pmap_t	get_task_pmap(task_t);

extern boolean_t	task_reference_try(task_t task);

#endif	/* __APPLE_API_PRIVATE */

#if		!defined(MACH_KERNEL_PRIVATE)

extern task_t	current_task(void);

#endif	/* MACH_KERNEL_TASK */

/* Take reference on task (make sure it doesn't go away) */
extern void		task_reference(task_t	task);

/* Remove reference to task */
extern void		task_deallocate(task_t	task);

#endif	/* _KERN_TASK_H_ */
