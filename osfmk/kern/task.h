/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
#include <sys/cdefs.h>

#ifdef	MACH_KERNEL_PRIVATE

#include <mach/boolean.h>
#include <mach/port.h>
#include <mach/time_value.h>
#include <mach/message.h>
#include <mach/mach_param.h>
#include <mach/task_info.h>
#include <mach/exception_types.h>
#include <machine/task.h>

#include <kern/cpu_data.h>
#include <kern/queue.h>
#include <kern/exception.h>
#include <kern/lock.h>
#include <kern/thread.h>

#include <mach_host.h>
#include <mach_prof.h>

struct task {
	/* Synchronization/destruction information */
	decl_mutex_data(,lock)		/* Task's lock */
	int		ref_count;	/* Number of references to me */
	boolean_t	active;		/* Task has not been terminated */

	/* Miscellaneous */
	vm_map_t	map;		/* Address space description */
	queue_chain_t	pset_tasks;	/* list of tasks assigned to pset */
	void		*user_data;	/* Arbitrary data settable via IPC */
	int		suspend_count;	/* Internal scheduling only */

	/* Threads in this task */
	queue_head_t	threads;
	int				thread_count;
	int				active_thread_count;

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

	/* Task security and audit tokens */
	security_token_t sec_token;
	audit_token_t	audit_token;
        
	/* Statistics */
	uint64_t		total_user_time;	/* terminated threads only */
	uint64_t		total_system_time;

#if	MACH_PROF
	boolean_t	task_profiled;  /* is task being profiled ? */
	struct prof_data *profil_buffer;/* profile struct if so */
#endif	/* MACH_PROF */

	/* IPC structures */
	decl_mutex_data(,itk_lock_data)
	struct ipc_port *itk_self;	/* not a right, doesn't hold ref */
	struct ipc_port *itk_nself;	/* not a right, doesn't hold ref */
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

	/* Ledgers */
	struct ipc_port	*wired_ledger_port;
	struct ipc_port *paged_ledger_port;
	unsigned int	priv_flags;			/* privilege resource flags */
#define VM_BACKING_STORE_PRIV	0x1

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
	struct shared_region_mapping	*system_shared_region;
	struct tws_hash 		*dynamic_working_set;
	uint32_t taskFeatures[2];		/* Special feature for this task */
#define tf64BitAddr	0x80000000		/* Task has 64-bit addressing */
#define tf64BitData	0x40000000		/* Task has 64-bit data registers */
#define task_has_64BitAddr(task)	\
	 (((task)->taskFeatures[0] & tf64BitAddr) != 0)
#define task_set_64BitAddr(task)	\
	 ((task)->taskFeatures[0] |= tf64BitAddr)
#define task_clear_64BitAddr(task)	\
	 ((task)->taskFeatures[0] &= ~tf64BitAddr)

};

#define task_lock(task)		mutex_lock(&(task)->lock)
#define task_lock_try(task)	mutex_try(&(task)->lock)
#define task_unlock(task)	mutex_unlock(&(task)->lock)

#define	itk_lock_init(task)	mutex_init(&(task)->itk_lock_data, 0)
#define	itk_lock(task)		mutex_lock(&(task)->itk_lock_data)
#define	itk_unlock(task)	mutex_unlock(&(task)->itk_lock_data)

#define task_reference_internal(task)		\
			hw_atomic_add(&(task)->ref_count, 1)

#define task_deallocate_internal(task)		\
			hw_atomic_sub(&(task)->ref_count, 1)

#define task_reference(task)					\
MACRO_BEGIN										\
	if ((task) != TASK_NULL)					\
		task_reference_internal(task);			\
MACRO_END

extern kern_return_t	kernel_task_create(
							task_t			task,
							vm_offset_t		map_base,
							vm_size_t		map_size,
							task_t 			*child);

/* Initialize task module */
extern void		task_init(void);

#define	current_task_fast()	(current_thread()->task)
#define current_task()		current_task_fast()

#else	/* MACH_KERNEL_PRIVATE */

__BEGIN_DECLS

extern task_t	current_task(void);

extern void		task_reference(task_t	task);

__END_DECLS

#endif	/* MACH_KERNEL_PRIVATE */

__BEGIN_DECLS

#ifdef	XNU_KERNEL_PRIVATE

/* Hold all threads in a task */
extern kern_return_t	task_hold(
							task_t		task);

/* Release hold on all threads in a task */
extern kern_return_t	task_release(
							task_t		task);

/* Halt all other threads in the current task */
extern kern_return_t	task_halt(
							task_t		task);

extern kern_return_t	task_terminate_internal(
							task_t			task);

extern kern_return_t	task_create_internal(
							task_t		parent_task,
							boolean_t	inherit_memory,
							boolean_t	is_64bit,
							task_t		*child_task);	/* OUT */

extern kern_return_t	task_importance(
							task_t			task,
							integer_t		importance);

extern void		task_set_64bit(
					task_t		task,
					boolean_t	is64bit);

extern void		task_backing_store_privileged(
					task_t		task);

extern void		task_working_set_disable(
					task_t		task);


/* Get number of activations in a task */
extern int		get_task_numacts(
					task_t		task);


/* JMM - should just be temporary (implementation in bsd_kern still) */
extern void	set_bsdtask_info(task_t,void *);
extern vm_map_t get_task_map_reference(task_t);
extern vm_map_t	swap_task_map(task_t, vm_map_t);
extern pmap_t	get_task_pmap(task_t);

extern boolean_t	is_kerneltask(task_t task);

#endif	/* XNU_KERNEL_PRIVATE */

#ifdef	KERNEL_PRIVATE

extern void 	*get_bsdtask_info(task_t);
extern vm_map_t get_task_map(task_t);

#endif	/* KERNEL_PRIVATE */

extern task_t	kernel_task;

extern void		task_deallocate(
					task_t		task);

extern void		task_name_deallocate(
					task_name_t		task_name);
__END_DECLS

#endif	/* _KERN_TASK_H_ */
