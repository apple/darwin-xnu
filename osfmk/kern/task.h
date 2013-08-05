/*
 * Copyright (c) 2000-2010 Apple Inc. All rights reserved.
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
/*
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 * Copyright (c) 2005 SPARTA, Inc.
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
#include <mach/vm_statistics.h>
#include <machine/task.h>

#include <kern/cpu_data.h>
#include <kern/queue.h>
#include <kern/exception.h>
#include <kern/lock.h>
#include <security/_label.h>
#include <ipc/ipc_labelh.h>
#endif /* MACH_KERNEL_PRIVATE */

#ifdef XNU_KERNEL_PRIVATE

/* defns for task->rsu_controldata */
#define TASK_POLICY_CPU_RESOURCE_USAGE		0
#define TASK_POLICY_WIREDMEM_RESOURCE_USAGE	1
#define TASK_POLICY_VIRTUALMEM_RESOURCE_USAGE	2
#define TASK_POLICY_DISK_RESOURCE_USAGE		3
#define TASK_POLICY_NETWORK_RESOURCE_USAGE	4
#define TASK_POLICY_POWER_RESOURCE_USAGE	5

#define TASK_POLICY_RESOURCE_USAGE_COUNT 6

/*
 * Process Action and Policy bit definitions 

The bit defns of the policy states 
64   60    56   52   48   44   40   36   32   28   24   20   16   12   8        0
|----|-----|----|----|----|----|----|----|----|----|----|----|----|----|--------| 
|RFU | RFU | PWR| NET| DSK| CPU| VM | WM | LVM| RFU| CPU| NET| GPU| DSK| BGRND  |
|----|-----|----|----|----|----|----|----|----|----|----|----|----|----|--------| 
|<-----------   RESOURCE USAGE  -------->|< LOWSRC>|<-HARDWARE ACCESS->|BackGrnd|     
|----|-----|----|----|----|----|----|----|----|----|----|----|----|----|--------| 

*
*/

#define TASK_POLICY_BACKGROUND_ATTRIBUTE_NONE		0x00
#define TASK_POLICY_BACKGROUND_ATTRIBUTE_LOWPRI		0x01
#define TASK_POLICY_BACKGROUND_ATTRIBUTE_DISKTHROTTLE	0x02
#define TASK_POLICY_BACKGROUND_ATTRIBUTE_NETTHROTTLE	0x04
#define TASK_POLICY_BACKGROUND_ATTRIBUTE_NOGPU		0x08
#if CONFIG_EMBEDDED
#define TASK_POLICY_BACKGROUND_ATTRIBUTE_ALL		0x0F
#else /* CONFIG_EMBEDDED */
#define TASK_POLICY_BACKGROUND_ATTRIBUTE_ALL		0x07
#endif /* CONFIG_EMBEDDED */
#define TASK_POLICY_BACKGROUND_ATTRIBUTE_DEFAULT	TASK_POLICY_BACKGROUND_ATTRIBUTE_ALL

/* Hardware disk access attributes, bit different as it should reflect IOPOL_XXX */
#define TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_NONE	0x00
#define TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_FULLACCESS	0x01
#define TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_NORMAL	0x01
#define TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_PASSIVE	0x02
#define TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_THROTTLE	0x03
#define TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_UTILITY	0x04
#define TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_DEFAULT	TASK_POLICY_HWACCESS_DISK_ATTRIBUTE_FULLACCESS

/* Hardware GPU access attributes */
#define TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NONE		0x00
#define TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_FULLACCESS	0x00
#define TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_NOACCESS	0x01
#define TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_DEFAULT	TASK_POLICY_HWACCESS_GPU_ATTRIBUTE_FULLACCESS

/* Hardware Network access attributes */
#define TASK_POLICY_HWACCESS_NET_ATTRIBUTE_NONE		0x00
#define TASK_POLICY_HWACCESS_NET_ATTRIBUTE_FULLACCESS	0x00
#define TASK_POLICY_HWACCESS_NET_ATTRIBUTE_THROTTLE	0x01
#define TASK_POLICY_HWACCESS_NET_ATTRIBUTE_DEFAULT	TASK_POLICY_HWACCESS_NET_ATTRIBUTE_FULLACCESS

/* Hardware CPU access attributes */
#define TASK_POLICY_HWACCESS_CPU_ATTRIBUTE_NONE		0x00
#define TASK_POLICY_HWACCESS_CPU_ATTRIBUTE_FULLACCESS	0x00
#define TASK_POLICY_HWACCESS_CPU_ATTRIBUTE_ONE		0x01
#define TASK_POLICY_HWACCESS_CPU_ATTRIBUTE_LLCACHE	0x02
#define TASK_POLICY_HWACCESS_CPU_ATTRIBUTE_DEFAULT	TASK_POLICY_HWACCESS_CPU_ATTRIBUTE_FULLACCESS

/* Resource usage/low resource attributes */
#define TASK_POLICY_RESOURCE_ATTRIBUTE_NONE		0x00
#define TASK_POLICY_RESOURCE_ATTRIBUTE_THROTTLE		0x01
#define TASK_POLICY_RESOURCE_ATTRIBUTE_SUSPEND 		0x02
#define TASK_POLICY_RESOURCE_ATTRIBUTE_TERMINATE	0x03
#define TASK_POLICY_RESOURCE_ATTRIBUTE_NOTIFY_KQ	0x04
#define TASK_POLICY_RESOURCE_ATTRIBUTE_NOTIFY_EXC	0x05
#define TASK_POLICY_RESOURCE_ATTRIBUTE_DEFAULT		TASK_POLICY_RESOURCE_ATTRIBUTE_NONE

#endif /* XNU_KERNEL_PRIVATE */

#ifdef MACH_KERNEL_PRIVATE

typedef struct process_policy {
	uint64_t  apptype:4,
		  rfu1:4,
		  ru_power:4,	/* Resource Usage Power */
		  ru_net:4,	/* Resource Usage Network */
		  ru_disk:4,	/* Resource Usage Disk */
		  ru_cpu:4,	/* Resource Usage CPU */
		  ru_virtmem:4,	/* Resource Usage VM */
		  ru_wiredmem:4,/* Resource Usage Wired Memory */
		  low_vm:4,	/* Low Virtual Memory */
		  rfu2:4,
		  hw_cpu:4,	/* HW Access to CPU */
		  hw_net:4,	/* HW Access to Network */
		  hw_gpu:4,	/* HW Access to GPU */
		  hw_disk:4,	/* HW Access to Disk */
		  hw_bg:8;	/* Darwin Background Policy */
} process_policy_t;

#if CONFIG_EMBEDDED

typedef struct task_watcher {
	queue_chain_t	tw_links;		/* queueing of threads */
	task_t		tw_task;	/* task that is being watched */
	thread_t	tw_thread;	/* thread that is watching the watch_task */
	int		tw_state;	/* the current app state of the thread */
	int		tw_importance;	/* importance prior to backgrounding */
} task_watch_t;

extern lck_mtx_t task_watch_mtx;

#endif /* CONFIG_EMBEDDED */

#include <kern/thread.h>

extern process_policy_t default_task_proc_policy;	/* init value for the process policy attributes */
extern process_policy_t default_task_null_policy;	/* none as the value for the process policy attributes */

struct task {
	/* Synchronization/destruction information */
	decl_lck_mtx_data(,lock)		/* Task's lock */
	uint32_t	ref_count;	/* Number of references to me */
	boolean_t	active;		/* Task has not been terminated */
	boolean_t	halting;	/* Task is being halted */

	/* Miscellaneous */
	vm_map_t	map;		/* Address space description */
	queue_chain_t	tasks;	/* global list of tasks */
	void		*user_data;	/* Arbitrary data settable via IPC */

	/* Threads in this task */
	queue_head_t		threads;

	processor_set_t		pset_hint;
	struct affinity_space	*affinity_space;

	int			thread_count;
	uint32_t		active_thread_count;
	int			suspend_count;	/* Internal scheduling only */

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

	/* Virtual timers */
	uint32_t		vtimers;

	/* IPC structures */
	decl_lck_mtx_data(,itk_lock_data)
	struct ipc_port *itk_self;	/* not a right, doesn't hold ref */
	struct ipc_port *itk_nself;	/* not a right, doesn't hold ref */
	struct ipc_port *itk_sself;	/* a send right */
	struct exception_action exc_actions[EXC_TYPES_COUNT];
		 			/* a send right each valid element  */
	struct ipc_port *itk_host;	/* a send right */
	struct ipc_port *itk_bootstrap;	/* a send right */
	struct ipc_port *itk_seatbelt;	/* a send right */
	struct ipc_port *itk_gssd;	/* yet another send right */
	struct ipc_port *itk_task_access; /* and another send right */ 
	struct ipc_port *itk_registered[TASK_PORT_REGISTER_MAX];
					/* all send rights */

	struct ipc_space *itk_space;

	/* Synchronizer ownership information */
	queue_head_t	semaphore_list;		/* list of owned semaphores   */
	queue_head_t	lock_set_list;		/* list of owned lock sets    */
	int		semaphores_owned;	/* number of semaphores owned */
	int 		lock_sets_owned;	/* number of lock sets owned  */

	ledger_t	ledger;

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
		uint32_t  c_switch;			   /* total context switches */
		uint32_t  p_switch;			   /* total processor switches */
		uint32_t  ps_switch;		   /* total pset switches */

	zinfo_usage_t tkm_zinfo;	/* per-task, per-zone usage statistics */

#ifdef  MACH_BSD 
	void *bsd_info;
#endif  
	struct vm_shared_region		*shared_region;
	uint32_t taskFeatures[2];		/* Special feature for this task */
#define tf64BitAddr	0x80000000		/* Task has 64-bit addressing */
#define tf64BitData	0x40000000		/* Task has 64-bit data registers */
#define task_has_64BitAddr(task)	\
	 (((task)->taskFeatures[0] & tf64BitAddr) != 0)
#define task_set_64BitAddr(task)	\
	 ((task)->taskFeatures[0] |= tf64BitAddr)
#define task_clear_64BitAddr(task)	\
	 ((task)->taskFeatures[0] &= ~tf64BitAddr)

	mach_vm_address_t	all_image_info_addr; /* dyld __all_image_info     */
	mach_vm_size_t		all_image_info_size; /* section location and size */
#if CONFIG_MACF_MACH
	ipc_labelh_t label;
#endif

#if CONFIG_COUNTERS
#define TASK_PMC_FLAG 0x1	/* Bit in "t_chud" signifying PMC interest */
	uint32_t t_chud;		/* CHUD flags, used for Shark */
#endif

	boolean_t pidsuspended; /* pid_suspend called; no threads can execute */
	boolean_t frozen;       /* frozen; private resident pages committed to swap */
	process_policy_t ext_appliedstate;	/* externally applied actions */
	process_policy_t ext_policystate;	/* externally defined process policy states*/
	process_policy_t appliedstate;		/* self applied acions */
	process_policy_t policystate;		/* process wide policy states */
	uint8_t  rusage_cpu_flags;
	uint8_t  rusage_cpu_percentage;		/* Task-wide CPU limit percentage */
	uint64_t rusage_cpu_interval;		/* Task-wide CPU limit interval */
	uint8_t  rusage_cpu_perthr_percentage;  /* Per-thread CPU limit percentage */
	uint64_t rusage_cpu_perthr_interval;    /* Per-thread CPU limit interval */
	uint64_t rusage_cpu_deadline;
	thread_call_t rusage_cpu_callt;
#if CONFIG_EMBEDDED
	uint32_t	appstate;		/* the current appstate */
	queue_head_t	task_watchers;		/* app state watcher threads */
	int	num_taskwatchers;
	int		watchapplying;
#endif /* CONFIG_EMBEDDED */

	vm_extmod_statistics_data_t	extmod_statistics;
	natural_t	proc_terminate;	/* the process is marked for proc_terminate */

	/* Statistics accumulated for terminated threads from this task */
	uint32_t	task_timer_wakeups_bin_1;
	uint32_t	task_timer_wakeups_bin_2;
};

#define task_lock(task)		lck_mtx_lock(&(task)->lock)
#define task_lock_try(task)	lck_mtx_try_lock(&(task)->lock)
#define task_unlock(task)	lck_mtx_unlock(&(task)->lock)

#if CONFIG_MACF_MACH
#define maclabel label->lh_label

#define tasklabel_lock(task)	lh_lock((task)->label)
#define tasklabel_unlock(task)	lh_unlock((task)->label)

extern void tasklabel_lock2(task_t a, task_t b);
extern void tasklabel_unlock2(task_t a, task_t b);
#endif /* MAC_MACH */

#define	itk_lock_init(task)	lck_mtx_init(&(task)->itk_lock_data, &ipc_lck_grp, &ipc_lck_attr)
#define	itk_lock_destroy(task)	lck_mtx_destroy(&(task)->itk_lock_data, &ipc_lck_grp)
#define	itk_lock(task)		lck_mtx_lock(&(task)->itk_lock_data)
#define	itk_unlock(task)	lck_mtx_unlock(&(task)->itk_lock_data)

#define task_reference_internal(task)		\
			(void)hw_atomic_add(&(task)->ref_count, 1)

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
extern void		task_init(void) __attribute__((section("__TEXT, initcode")));

#define	current_task_fast()	(current_thread()->task)
#define current_task()		current_task_fast()

extern lck_attr_t      task_lck_attr;
extern lck_grp_t       task_lck_grp;

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

/* Wait for task to stop running, either just to get off CPU or to cease being runnable */
extern kern_return_t	task_wait(
							task_t		task,
							boolean_t 	until_not_runnable);

/* Release hold on all threads in a task */
extern kern_return_t	task_release(
							task_t		task);

/* Suspends a task by placing a hold on its threads */
extern kern_return_t    task_pidsuspend(
							task_t		task);
extern kern_return_t    task_pidsuspend_locked(
							task_t		task);

/* Resumes a previously paused task */
extern kern_return_t    task_pidresume(
							task_t		task);

#if CONFIG_FREEZE

/* Freeze a task's resident pages */
extern kern_return_t	task_freeze(
							task_t		task,
							uint32_t	*purgeable_count,
							uint32_t	*wired_count,
							uint32_t	*clean_count,
							uint32_t	*dirty_count,
							uint32_t	dirty_budget,
							boolean_t	*shared,
							boolean_t	walk_only);

/* Thaw a currently frozen task */
extern kern_return_t	task_thaw(
							task_t		task);

#endif /* CONFIG_FREEZE */

/* Halt all other threads in the current task */
extern kern_return_t	task_start_halt(
							task_t		task);

/* Wait for other threads to halt and free halting task resources */
extern void		task_complete_halt(
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

extern void		task_vtimer_set(
					task_t		task,
					integer_t	which);

extern void		task_vtimer_clear(
					task_t		task,
					integer_t	which);

extern void		task_vtimer_update(
					task_t		task,
					integer_t	which,
					uint32_t	*microsecs);

#define	TASK_VTIMER_USER		0x01
#define	TASK_VTIMER_PROF		0x02
#define	TASK_VTIMER_RLIM		0x04

extern void		task_set_64bit(
					task_t		task,
					boolean_t	is64bit);

extern void		task_backing_store_privileged(
					task_t		task);

extern void		task_set_dyld_info(
    					task_t		task,
					mach_vm_address_t addr,
					mach_vm_size_t size);

/* Get number of activations in a task */
extern int		get_task_numacts(
					task_t		task);

extern int get_task_numactivethreads(task_t task);

/* JMM - should just be temporary (implementation in bsd_kern still) */
extern void	set_bsdtask_info(task_t,void *);
extern vm_map_t get_task_map_reference(task_t);
extern vm_map_t	swap_task_map(task_t, thread_t, vm_map_t, boolean_t);
extern pmap_t	get_task_pmap(task_t);
extern uint64_t	get_task_resident_size(task_t);

extern boolean_t	is_kerneltask(task_t task);

extern kern_return_t check_actforsig(task_t task, thread_t thread, int setast);

extern kern_return_t machine_task_get_state(
					task_t task, 
					int flavor, 
					thread_state_t state, 
					mach_msg_type_number_t *state_count);

extern kern_return_t machine_task_set_state(
					task_t task, 
					int flavor, 
					thread_state_t state, 
					mach_msg_type_number_t state_count);

extern void machine_task_terminate(task_t task);

struct _task_ledger_indices {
	int cpu_time;
	int tkm_private;
	int tkm_shared;
	int phys_mem;
	int wired_mem;
	int platform_idle_wakeups;
	int interrupt_wakeups;
};
extern struct _task_ledger_indices task_ledgers;

int proc_get_task_bg_policy(task_t task);
int proc_get_thread_bg_policy(task_t task, uint64_t tid);
int proc_get_self_isbackground(void);
int proc_get_selfthread_isbackground(void);

int proc_get_darwinbgstate(task_t, uint32_t *);
int proc_set_bgtaskpolicy(task_t task, int intval);
int proc_set_and_apply_bgtaskpolicy(task_t task, int intval);
int proc_set_bgthreadpolicy(task_t task, uint64_t tid, int val);
int proc_set_and_apply_bgthreadpolicy(task_t task, uint64_t tid, int val);

int proc_add_bgtaskpolicy(task_t task, int val);
int proc_add_bgthreadpolicy(task_t task, uint64_t tid, int val);
int proc_remove_bgtaskpolicy(task_t task, int policy);
int proc_remove_bgthreadpolicy(task_t task, uint64_t tid, int val);

int proc_apply_bgtaskpolicy(task_t task);
int proc_apply_bgtaskpolicy_external(task_t task);
int proc_apply_bgthreadpolicy(task_t task, uint64_t tid);
int proc_apply_bgtask_selfpolicy(void);
int proc_apply_bgthread_selfpolicy(void);
int proc_apply_workq_bgthreadpolicy(thread_t);

int proc_restore_bgtaskpolicy(task_t task);
int proc_restore_bgthreadpolicy(task_t task, uint64_t tid);
int proc_restore_bgthread_selfpolicy(void);
int proc_restore_workq_bgthreadpolicy(thread_t);
void proc_task_remove_throttle(task_t task);

/* hw access routines */
int proc_apply_task_diskacc(task_t task, int policy);
int proc_apply_thread_diskacc(task_t task, uint64_t tid, int policy);
int proc_apply_thread_selfdiskacc(int policy);
int proc_get_task_disacc(task_t task);
int proc_get_task_selfdiskacc(void);
int proc_get_diskacc(thread_t thread);
int proc_get_thread_selfdiskacc(void);
int proc_denyinherit_policy(task_t task);
int proc_denyselfset_policy(task_t task);

int proc_get_task_selfgpuacc_deny(void);
int proc_apply_task_gpuacc(task_t task, int prio);

int proc_get_task_ruse_cpu(task_t task, uint32_t * policyp, uint32_t * percentagep, uint64_t * intervalp, uint64_t * deadlinep);
int proc_set_task_ruse_cpu(task_t task, uint32_t policy, uint32_t percentage, uint64_t interval, uint64_t deadline);
int proc_clear_task_ruse_cpu(task_t task);
thread_t task_findtid(task_t, uint64_t);

#define TASK_RUSECPU_FLAGS_PROC_LIMIT	0x1
#define TASK_RUSECPU_FLAGS_PERTHR_LIMIT	0x2
#define TASK_RUSECPU_FLAGS_DEADLINE		0x4

#define PROC_POLICY_OSX_APPTYPE_NONE		0
#if CONFIG_EMBEDDED
#define PROC_POLICY_IOS_RESV1_APPTYPE		1
#define PROC_POLICY_IOS_APPLE_DAEMON		2
#define PROC_POLICY_IOS_APPTYPE			3
#define PROC_POLICY_IOS_NONUITYPE		4
#else
#define PROC_POLICY_OSX_APPTYPE_TAL		1
#define PROC_POLICY_OSX_APPTYPE_WIDGET		2
#define PROC_POLICY_OSX_APPTYPE_DBCLIENT	2	/* Not a bug, just rename of widget */
#endif

void proc_set_task_apptype(task_t task, int type, thread_t thread);
int proc_disable_task_apptype(task_t task, int policy_subtype);
int proc_enable_task_apptype(task_t task, int policy_subtype);

#if CONFIG_EMBEDDED
extern int proc_setthread_saved_importance(thread_t thread, int importance);
#endif

/* BSD call back functions */
extern int proc_apply_resource_actions(void * p, int type, int action);
extern int proc_restore_resource_actions(void * p, int type, int action);
extern int task_restore_resource_actions(task_t task, int type);

extern void proc_apply_task_networkbg(void * bsd_info);
extern void proc_restore_task_networkbg(void * bsd_info);
extern void proc_set_task_networkbg(void * bsd_info, int setbg);
extern int task_clear_cpuusage(task_t task);

#if CONFIG_EMBEDDED
#define TASK_APPSTATE_NONE              0
#define TASK_APPSTATE_ACTIVE            1
#define TASK_APPSTATE_BACKGROUND        2
#define TASK_APPSTATE_NONUI             3
#define TASK_APPSTATE_INACTIVE          4

extern int proc_lf_getappstate(task_t task);
extern int proc_lf_setappstate(task_t task, int state);
extern int proc_lf_pidbind(task_t curtask, uint64_t tid, task_t target_task, int bind);
extern void thead_remove_taskwatch(thread_t thread);
extern void task_removewatchers(task_t task);
#endif /* CONFIG_EMBEDDED */

#endif	/* XNU_KERNEL_PRIVATE */

#ifdef	KERNEL_PRIVATE

extern void 	*get_bsdtask_info(task_t);
extern void	*get_bsdthreadtask_info(thread_t);
extern vm_map_t get_task_map(task_t);
extern ledger_t	get_task_ledger(task_t);

extern boolean_t get_task_pidsuspended(task_t);
extern boolean_t get_task_frozen(task_t);

/* Convert from a task to a port */
extern ipc_port_t convert_task_to_port(task_t);

/* Convert from a task name to a port */
extern ipc_port_t convert_task_name_to_port(task_name_t);

#endif	/* KERNEL_PRIVATE */

extern task_t	kernel_task;

extern void		task_deallocate(
					task_t		task);

extern void		task_name_deallocate(
					task_name_t		task_name);
__END_DECLS

#endif	/* _KERN_TASK_H_ */
