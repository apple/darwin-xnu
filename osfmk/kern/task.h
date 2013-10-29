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

#define	TASK_POLICY_CPUMON_DISABLE			0xFF
#define	TASK_POLICY_CPUMON_DEFAULTS			0xFE

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


#include <kern/thread.h>

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
	integer_t		legacy_stop_count;	/* outstanding legacy stops */

	integer_t		priority;			/* base priority for threads */
	integer_t		max_priority;		/* maximum priority for threads */

	integer_t		importance;		/* priority offset (BSD 'nice' value) */

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
	struct ipc_port *itk_resume;	/* a receive right to resume this task */
	struct ipc_port *itk_registered[TASK_PORT_REGISTER_MAX];
					/* all send rights */

	struct ipc_space *itk_space;

	/* Synchronizer ownership information */
	queue_head_t	semaphore_list;		/* list of owned semaphores   */
	int		semaphores_owned;	/* number of semaphores owned */

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
	uint32_t t_flags;					/* general-purpose task flags protected by task_lock (TL) */
#define TF_64B_ADDR		0x1				/* task has 64-bit addressing */
#define TF_64B_DATA		0x2				/* task has 64-bit data registers */
#define	TF_CPUMON_WARNING	0x4				/* task has at least one thread in CPU usage warning zone */
#define	TF_WAKEMON_WARNING	0x8				/* task is in wakeups monitor warning zone */
#define TF_TELEMETRY	(TF_CPUMON_WARNING | TF_WAKEMON_WARNING) /* task is a telemetry participant */
#define task_has_64BitAddr(task)	\
	 (((task)->t_flags & TF_64B_ADDR) != 0)
#define task_set_64BitAddr(task)	\
	 ((task)->t_flags |= TF_64B_ADDR)
#define task_clear_64BitAddr(task)	\
	 ((task)->t_flags &= ~TF_64B_ADDR)
#define task_has_64BitData(task)    \
	 (((task)->t_flags & TF_64B_DATA) != 0)

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
	boolean_t changing_freeze_state;	/* in the process of freezing or thawing */
	uint16_t policy_ru_cpu          :4,
	         policy_ru_cpu_ext      :4,
	         applied_ru_cpu         :4,
	         applied_ru_cpu_ext     :4;
	uint8_t  rusage_cpu_flags;
	uint8_t  rusage_cpu_percentage;		/* Task-wide CPU limit percentage */
	uint64_t rusage_cpu_interval;		/* Task-wide CPU limit interval */
	uint8_t  rusage_cpu_perthr_percentage;  /* Per-thread CPU limit percentage */
	uint64_t rusage_cpu_perthr_interval;    /* Per-thread CPU limit interval */
	uint64_t rusage_cpu_deadline;
	thread_call_t rusage_cpu_callt;

#if IMPORTANCE_INHERITANCE
	uint32_t        imp_receiver    :1,     /* the task can receive importance boost */
	                imp_donor       :1,     /* the task always sends boosts regardless of boost status */
	                imp_reserved    :30;    /* reserved for future use */

	uint32_t        task_imp_assertcnt;     /* total number of boost assertions (kernel managed plus userspace managed) */
	uint32_t        task_imp_externcnt;     /* number of boost assertions externalized (userspace managed) */
#endif /* IMPORTANCE_INHERITANCE */

	vm_extmod_statistics_data_t	extmod_statistics;

#if MACH_ASSERT
	int8_t		suspends_outstanding;	/* suspends this task performed in excess of resumes */
#endif

	struct task_requested_policy requested_policy;
	struct task_effective_policy effective_policy;
	struct task_pended_policy    pended_policy;

	/*
	 * Can be merged with imp_donor bits, once the IMPORTANCE_INHERITANCE macro goes away.
	 */
	uint32_t        low_mem_notified_warn     :1,    /* warning low memory notification is sent to the task */
	                low_mem_notified_critical :1,    /* critical low memory notification is sent to the task */
	                purged_memory_warn        :1,    /* purgeable memory of the task is purged for warning level pressure */
	                purged_memory_critical    :1,    /* purgeable memory of the task is purged for critical level pressure */
	                mem_notify_reserved       :28;   /* reserved for future use */

	/* Statistics accumulated for terminated threads from this task */
	uint32_t	task_timer_wakeups_bin_1;
	uint32_t	task_timer_wakeups_bin_2;

	int		task_volatile_objects; /* # of purgeable VM objects made
						* "volatile" by this task */
};

#define task_lock(task)		 	lck_mtx_lock(&(task)->lock)
#define	task_lock_assert_owned(task)	lck_mtx_assert(&(task)->lock, LCK_MTX_ASSERT_OWNED)
#define task_lock_try(task)	 	lck_mtx_try_lock(&(task)->lock)
#define task_unlock(task)	 	lck_mtx_unlock(&(task)->lock)

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

#define TASK_REFERENCE_LEAK_DEBUG 0

#if TASK_REFERENCE_LEAK_DEBUG
extern void task_reference_internal(task_t task);
extern uint32_t task_deallocate_internal(task_t task);
#else
#define task_reference_internal(task)		\
			(void)hw_atomic_add(&(task)->ref_count, 1)

#define task_deallocate_internal(task)		\
			hw_atomic_sub(&(task)->ref_count, 1)
#endif

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

extern void 		task_power_info_locked(
							task_t			task,
							task_power_info_t	info);

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
extern uint64_t	get_task_phys_footprint(task_t);
extern uint64_t	get_task_phys_footprint_max(task_t);

extern kern_return_t task_set_phys_footprint_limit_internal(task_t, int, int *, boolean_t);
extern kern_return_t task_get_phys_footprint_limit(task_t task, int *limit_mb);

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
	int iokit_mem;
	int phys_footprint;
	int phys_compressed;
	int platform_idle_wakeups;
	int interrupt_wakeups;
};
extern struct _task_ledger_indices task_ledgers;

/* Begin task_policy */

/* value */
#define TASK_POLICY_DISABLE             0x0
#define TASK_POLICY_ENABLE              0x1

/* category */
#define TASK_POLICY_INTERNAL            0x0
#define TASK_POLICY_EXTERNAL            0x1
#define TASK_POLICY_ATTRIBUTE           0x2

/* for tracing */
#define TASK_POLICY_TASK                0x4
#define TASK_POLICY_THREAD              0x8

/* flavors (also DBG_IMPORTANCE subclasses  0x20 - 0x3F) */

/* internal or external, thread or task */
#define TASK_POLICY_DARWIN_BG           0x21
#define TASK_POLICY_IOPOL               0x22
#define TASK_POLICY_IO                  0x23
#define TASK_POLICY_PASSIVE_IO          0x24

/* internal or external, task only */
#define TASK_POLICY_DARWIN_BG_AND_GPU   0x25
#define TASK_POLICY_GPU_DENY            0x26

/* internal, task only */
#define TASK_POLICY_DARWIN_BG_IOPOL     0x27

/* task-only attributes */
#define TASK_POLICY_TAL                 0x28
#define TASK_POLICY_BOOST               0x29
#define TASK_POLICY_ROLE                0x2A
#define TASK_POLICY_SUPPRESSED_CPU      0x2B
#define TASK_POLICY_TERMINATED          0x2C
#define TASK_POLICY_NEW_SOCKETS_BG      0x2D
#define TASK_POLICY_LOWPRI_CPU          0x2E
#define TASK_POLICY_LATENCY_QOS         0x2F
#define TASK_POLICY_THROUGH_QOS         0x30
#define TASK_POLICY_WATCHERS_BG         0x31

/* thread-only attributes */
#define TASK_POLICY_PIDBIND_BG          0x32
#define TASK_POLICY_WORKQ_BG            0x33

#define TASK_POLICY_MAX                 0x3F

/* The main entrance to task policy is this function */
extern void proc_set_task_policy(task_t task, thread_t thread, int category, int flavor, int value);
extern int  proc_get_task_policy(task_t task, thread_t thread, int category, int flavor);

/* For use by kernel threads and others who don't hold a reference on the target thread */
extern void proc_set_task_policy_thread(task_t task, uint64_t tid, int category, int flavor, int value);

extern void proc_set_task_apptype(task_t task, int type);

/* IO Throttle tiers */
#define THROTTLE_LEVEL_NONE     -1
#define	THROTTLE_LEVEL_TIER0     0      /* IOPOL_NORMAL, IOPOL_DEFAULT, IOPOL_PASSIVE */

#define THROTTLE_LEVEL_THROTTLED 1
#define THROTTLE_LEVEL_TIER1     1      /* IOPOL_STANDARD */
#define THROTTLE_LEVEL_TIER2     2      /* IOPOL_UTILITY */
#define THROTTLE_LEVEL_TIER3     3      /* IOPOL_THROTTLE */

#define THROTTLE_LEVEL_START     0
#define THROTTLE_LEVEL_END       3

#define THROTTLE_LEVEL_COMPRESSOR_TIER0		THROTTLE_LEVEL_TIER0
#define THROTTLE_LEVEL_COMPRESSOR_TIER1		THROTTLE_LEVEL_TIER1
#define THROTTLE_LEVEL_COMPRESSOR_TIER2		THROTTLE_LEVEL_TIER2

#define THROTTLE_LEVEL_PAGEOUT_THROTTLED        THROTTLE_LEVEL_TIER2
#define THROTTLE_LEVEL_PAGEOUT_UNTHROTTLED      THROTTLE_LEVEL_TIER1

extern int proc_apply_workq_bgthreadpolicy(thread_t thread);
extern int proc_restore_workq_bgthreadpolicy(thread_t thread);

extern int proc_get_darwinbgstate(task_t task, uint32_t *flagsp);
extern boolean_t proc_task_is_tal(task_t task);
extern integer_t task_grab_latency_qos(task_t task);
extern void task_policy_create(task_t task, int parent_boosted);

/*
 * Get effective policy
 * Only for use by relevant subsystem, should never be passed into a setter!
 */

extern int proc_get_effective_task_policy(task_t task, int flavor);
extern int proc_get_effective_thread_policy(thread_t thread, int flavor);

/* temporary compatibility */
int proc_setthread_saved_importance(thread_t thread, int importance);

int proc_get_task_ruse_cpu(task_t task, uint32_t *policyp, uint8_t *percentagep, uint64_t *intervalp, uint64_t *deadlinep);
int proc_set_task_ruse_cpu(task_t task, uint32_t policy, uint8_t percentage, uint64_t interval, uint64_t deadline, int cpumon_entitled);
int proc_clear_task_ruse_cpu(task_t task, int cpumon_entitled);
thread_t task_findtid(task_t, uint64_t);
void set_thread_iotier_override(thread_t, int policy);

#define TASK_RUSECPU_FLAGS_PROC_LIMIT			0x01
#define TASK_RUSECPU_FLAGS_PERTHR_LIMIT			0x02
#define TASK_RUSECPU_FLAGS_DEADLINE			0x04
#define	TASK_RUSECPU_FLAGS_FATAL_CPUMON			0x08	/* CPU usage monitor violations are fatal */
#define	TASK_RUSECPU_FLAGS_FATAL_WAKEUPSMON		0x10	/* wakeups monitor violations are fatal */
#define	TASK_RUSECPU_FLAGS_PHYS_FOOTPRINT_EXCEPTION	0x20	/* exceeding physical footprint generates EXC_RESOURCE */

/* BSD call back functions */
extern int proc_apply_resource_actions(void * p, int type, int action);
extern int proc_restore_resource_actions(void * p, int type, int action);
extern int task_restore_resource_actions(task_t task, int type);

extern int task_clear_cpuusage(task_t task, int cpumon_entitled);

extern kern_return_t task_wakeups_monitor_ctl(task_t task, uint32_t *rate_hz, int32_t *flags);
extern kern_return_t task_cpu_usage_monitor_ctl(task_t task, uint32_t *flags);


void task_importance_mark_donor(task_t task, boolean_t donating);

#if IMPORTANCE_INHERITANCE
extern boolean_t task_is_importance_donor(task_t task);
extern boolean_t task_is_importance_receiver(task_t task);

extern int task_importance_hold_internal_assertion(task_t target_task, uint32_t count);
extern int task_importance_drop_internal_assertion(task_t target_task, uint32_t count);

extern int task_importance_hold_external_assertion(task_t target_task, uint32_t count);
extern int task_importance_drop_external_assertion(task_t target_task, uint32_t count);

extern int task_importance_externalize_assertion(task_t target_task, uint32_t count, int sender_pid);
#endif /* IMPORTANCE_INHERITANCE */

extern void task_hold_multiple_assertion(task_t task, uint32_t count);
extern void task_add_importance_watchport(task_t task, int pid, mach_port_t port, int *boostp);

extern boolean_t task_has_been_notified(task_t task, int pressurelevel);
extern boolean_t task_used_for_purging(task_t task, int pressurelevel);
extern void task_mark_has_been_notified(task_t task, int pressurelevel);
extern void task_mark_used_for_purging(task_t task, int pressurelevel);
extern void task_clear_has_been_notified(task_t task, int pressurelevel);
extern void task_clear_used_for_purging(task_t task);
extern int task_importance_estimate(task_t task);

/*
 * This should only be used for debugging.
 * pid is stored in audit_token by set_security_token().
 */
#define audit_token_pid_from_task(task)  ((task)->audit_token.val[5])

/* End task_policy */

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
extern ipc_port_t convert_task_name_to_port(task_name_t);
extern ipc_port_t convert_task_suspension_token_to_port(task_suspension_token_t task);

/* Convert from a port (in this case, an SO right to a task's resume port) to a task. */
extern task_suspension_token_t convert_port_to_task_suspension_token(ipc_port_t port);

extern boolean_t task_suspension_notify(mach_msg_header_t *);

#endif	/* KERNEL_PRIVATE */

extern task_t	kernel_task;

extern void		task_deallocate(
					task_t		task);

extern void		task_name_deallocate(
					task_name_t		task_name);

extern void		task_suspension_token_deallocate(
					task_suspension_token_t	token);
__END_DECLS

#endif	/* _KERN_TASK_H_ */
