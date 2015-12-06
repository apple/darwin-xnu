/*
 * Copyright (c) 2000-2010, 2015 Apple Inc. All rights reserved.
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
 *	File:	kern/task.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young, David Golub,
 *		David Black
 *
 *	Task management primitives implementation.
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

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/host_priv.h>
#include <mach/machine/vm_types.h>
#include <mach/vm_param.h>
#include <mach/mach_vm.h>
#include <mach/semaphore.h>
#include <mach/task_info.h>
#include <mach/task_special_ports.h>

#include <ipc/ipc_importance.h>
#include <ipc/ipc_types.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_hash.h>

#include <kern/kern_types.h>
#include <kern/mach_param.h>
#include <kern/misc_protos.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/coalition.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <kern/kern_cdata.h>
#include <kern/processor.h>
#include <kern/sched_prim.h>	/* for thread_wakeup */
#include <kern/ipc_tt.h>
#include <kern/host.h>
#include <kern/clock.h>
#include <kern/timer.h>
#include <kern/assert.h>
#include <kern/sync_lock.h>
#include <kern/affinity.h>
#include <kern/exc_resource.h>
#include <kern/machine.h>
#include <corpses/task_corpse.h>
#if CONFIG_TELEMETRY
#include <kern/telemetry.h>
#endif

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>		/* for kernel_map, ipc_kernel_map */
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>
#include <vm/vm_purgeable_internal.h>

#include <sys/resource.h>
#include <sys/signalvar.h> /* for coredump */

/*
 * Exported interfaces
 */

#include <mach/task_server.h>
#include <mach/mach_host_server.h>
#include <mach/host_security_server.h>
#include <mach/mach_port_server.h>

#include <vm/vm_shared_region.h>

#include <libkern/OSDebug.h>
#include <libkern/OSAtomic.h>

#if CONFIG_ATM
#include <atm/atm_internal.h>
#endif

#include <kern/sfi.h>

#if KPERF
extern int kpc_force_all_ctrs(task_t, int);
#endif

uint32_t qos_override_mode;

task_t			kernel_task;
zone_t			task_zone;
lck_attr_t      task_lck_attr;
lck_grp_t       task_lck_grp;
lck_grp_attr_t  task_lck_grp_attr;

/* Flag set by core audio when audio is playing. Used to stifle EXC_RESOURCE generation when active. */
int audio_active = 0;

zinfo_usage_store_t tasks_tkm_private;
zinfo_usage_store_t tasks_tkm_shared;

/* A container to accumulate statistics for expired tasks */
expired_task_statistics_t		dead_task_statistics;
lck_spin_t		dead_task_statistics_lock;

ledger_template_t task_ledger_template = NULL;

struct _task_ledger_indices task_ledgers __attribute__((used)) =
	{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	 { 0 /* initialized at runtime */},
#ifdef CONFIG_BANK
	 -1, -1,
#endif
	};

void init_task_ledgers(void);
void task_footprint_exceeded(int warning, __unused const void *param0, __unused const void *param1);
void task_wakeups_rate_exceeded(int warning, __unused const void *param0, __unused const void *param1);
void __attribute__((noinline)) THIS_PROCESS_IS_CAUSING_TOO_MANY_WAKEUPS__SENDING_EXC_RESOURCE(void);
void __attribute__((noinline)) PROC_CROSSED_HIGH_WATERMARK__SEND_EXC_RESOURCE_AND_SUSPEND(int max_footprint_mb);

kern_return_t task_suspend_internal(task_t);
kern_return_t task_resume_internal(task_t);
static kern_return_t task_start_halt_locked(task_t task, boolean_t should_mark_corpse);


void proc_init_cpumon_params(void);
extern kern_return_t exception_deliver(thread_t, exception_type_t, mach_exception_data_t, mach_msg_type_number_t, struct exception_action *, lck_mtx_t *);

// Warn tasks when they hit 80% of their memory limit.
#define	PHYS_FOOTPRINT_WARNING_LEVEL 80

#define TASK_WAKEUPS_MONITOR_DEFAULT_LIMIT		150 /* wakeups per second */
#define TASK_WAKEUPS_MONITOR_DEFAULT_INTERVAL	300 /* in seconds. */

/*
 * Level (in terms of percentage of the limit) at which the wakeups monitor triggers telemetry.
 *
 * (ie when the task's wakeups rate exceeds 70% of the limit, start taking user
 *  stacktraces, aka micro-stackshots)
 */
#define	TASK_WAKEUPS_MONITOR_DEFAULT_USTACKSHOTS_TRIGGER	70

int task_wakeups_monitor_interval; /* In seconds. Time period over which wakeups rate is observed */
int task_wakeups_monitor_rate;     /* In hz. Maximum allowable wakeups per task before EXC_RESOURCE is sent */

int task_wakeups_monitor_ustackshots_trigger_pct; /* Percentage. Level at which we start gathering telemetry. */

int disable_exc_resource; /* Global override to supress EXC_RESOURCE for resource monitor violations. */

ledger_amount_t max_task_footprint = 0;  /* Per-task limit on physical memory consumption in bytes     */
int max_task_footprint_mb = 0;  /* Per-task limit on physical memory consumption in megabytes */

#if MACH_ASSERT
int pmap_ledgers_panic = 1;
#endif /* MACH_ASSERT */

int task_max = CONFIG_TASK_MAX; /* Max number of tasks */

int hwm_user_cores = 0; /* high watermark violations generate user core files */

#ifdef MACH_BSD
extern void	proc_getexecutableuuid(void *, unsigned char *, unsigned long);
extern int	proc_pid(struct proc *p);
extern int	proc_selfpid(void);
extern char	*proc_name_address(struct proc *p);
extern uint64_t get_dispatchqueue_offset_from_proc(void *);
#if CONFIG_JETSAM
extern void	proc_memstat_terminated(struct proc* p, boolean_t set);
extern void	memorystatus_on_ledger_footprint_exceeded(int warning, const int max_footprint_mb);
#endif
#endif
#if MACH_ASSERT
extern int pmap_ledgers_panic;
#endif /* MACH_ASSERT */

/* Forwards */

void		task_hold_locked(
			task_t		task);
void		task_wait_locked(
			task_t		task,
			boolean_t	until_not_runnable);
void		task_release_locked(
			task_t		task);
void		task_free(
			task_t		task );
void		task_synchronizer_destroy_all(
			task_t		task);

int check_for_tasksuspend(
			task_t task);

void
task_backing_store_privileged(
			task_t task)
{
	task_lock(task);
	task->priv_flags |= VM_BACKING_STORE_PRIV;
	task_unlock(task);
	return;
}


void
task_set_64bit(
		task_t task,
		boolean_t is64bit)
{
#if defined(__i386__) || defined(__x86_64__) || defined(__arm64__)
	thread_t thread;
#endif /* defined(__i386__) || defined(__x86_64__) || defined(__arm64__) */

	task_lock(task);

	if (is64bit) {
		if (task_has_64BitAddr(task))
			goto out;
		task_set_64BitAddr(task);
	} else {
		if ( !task_has_64BitAddr(task))
			goto out;
		task_clear_64BitAddr(task);
	}
	/* FIXME: On x86, the thread save state flavor can diverge from the
	 * task's 64-bit feature flag due to the 32-bit/64-bit register save
	 * state dichotomy. Since we can be pre-empted in this interval,
	 * certain routines may observe the thread as being in an inconsistent
	 * state with respect to its task's 64-bitness.
	 */

#if defined(__i386__) || defined(__x86_64__) || defined(__arm64__)	
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		thread_mtx_lock(thread);
		machine_thread_switch_addrmode(thread);
		thread_mtx_unlock(thread);
	}
#endif /* defined(__i386__) || defined(__x86_64__) || defined(__arm64__) */	

out:
	task_unlock(task);
}


void
task_set_dyld_info(task_t task, mach_vm_address_t addr, mach_vm_size_t size)
{
	task_lock(task);
	task->all_image_info_addr = addr;
	task->all_image_info_size = size;
	task_unlock(task);
}

void
task_atm_reset(__unused task_t task) {

#if CONFIG_ATM
	if (task->atm_context != NULL) {
		 atm_task_descriptor_destroy(task->atm_context);
		 task->atm_context = NULL;
	}
#endif

}

#if TASK_REFERENCE_LEAK_DEBUG
#include <kern/btlog.h>

decl_simple_lock_data(static,task_ref_lock);
static btlog_t *task_ref_btlog;
#define TASK_REF_OP_INCR	0x1
#define TASK_REF_OP_DECR	0x2

#define TASK_REF_BTDEPTH	7

static void
task_ref_lock_lock(void *context)
{
	simple_lock((simple_lock_t)context);
}
static void
task_ref_lock_unlock(void *context)
{
	simple_unlock((simple_lock_t)context);
}

void
task_reference_internal(task_t task)
{
	void *       bt[TASK_REF_BTDEPTH];
	int             numsaved = 0;

	numsaved = OSBacktrace(bt, TASK_REF_BTDEPTH);
	
	(void)hw_atomic_add(&(task)->ref_count, 1);
	btlog_add_entry(task_ref_btlog, task, TASK_REF_OP_INCR,
					bt, numsaved);
}

uint32_t
task_deallocate_internal(task_t task)
{
	void *       bt[TASK_REF_BTDEPTH];
	int             numsaved = 0;

	numsaved = OSBacktrace(bt, TASK_REF_BTDEPTH);

	btlog_add_entry(task_ref_btlog, task, TASK_REF_OP_DECR,
					bt, numsaved);
	return hw_atomic_sub(&(task)->ref_count, 1);
}

#endif /* TASK_REFERENCE_LEAK_DEBUG */

void
task_init(void)
{

	lck_grp_attr_setdefault(&task_lck_grp_attr);
	lck_grp_init(&task_lck_grp, "task", &task_lck_grp_attr);
	lck_attr_setdefault(&task_lck_attr);
	lck_mtx_init(&tasks_threads_lock, &task_lck_grp, &task_lck_attr);

	task_zone = zinit(
			sizeof(struct task),
			task_max * sizeof(struct task),
			TASK_CHUNK * sizeof(struct task),
			"tasks");

	zone_change(task_zone, Z_NOENCRYPT, TRUE);

	/*
	 * Configure per-task memory limit.
	 * The boot-arg is interpreted as Megabytes,
	 * and takes precedence over the device tree.
	 * Setting the boot-arg to 0 disables task limits.
	 */
	if (!PE_parse_boot_argn("max_task_pmem", &max_task_footprint_mb,
			sizeof (max_task_footprint_mb))) {
		/*
		 * No limit was found in boot-args, so go look in the device tree.
		 */
		if (!PE_get_default("kern.max_task_pmem", &max_task_footprint_mb,
				sizeof(max_task_footprint_mb))) {
			/*
			 * No limit was found in device tree.
			 */
			max_task_footprint_mb = 0;
		}
	}

	if (max_task_footprint_mb != 0) {
#if CONFIG_JETSAM
		if (max_task_footprint_mb < 50) {
				printf("Warning: max_task_pmem %d below minimum.\n",
				max_task_footprint_mb);
				max_task_footprint_mb = 50;
		}
		printf("Limiting task physical memory footprint to %d MB\n",
			max_task_footprint_mb);

		max_task_footprint = (ledger_amount_t)max_task_footprint_mb * 1024 * 1024; // Convert MB to bytes
#else
		printf("Warning: max_task_footprint specified, but jetsam not configured; ignoring.\n");
#endif
	}

#if MACH_ASSERT
	PE_parse_boot_argn("pmap_ledgers_panic", &pmap_ledgers_panic,
			  sizeof (pmap_ledgers_panic));
#endif /* MACH_ASSERT */

	if (!PE_parse_boot_argn("hwm_user_cores", &hwm_user_cores,
			sizeof (hwm_user_cores))) {
		hwm_user_cores = 0;
	}

	if (PE_parse_boot_argn("qos_override_mode", &qos_override_mode, sizeof(qos_override_mode))) {
		printf("QOS override mode: 0x%08x\n", qos_override_mode);
	} else {
		qos_override_mode = QOS_OVERRIDE_MODE_FINE_GRAINED_OVERRIDE_BUT_SINGLE_MUTEX_OVERRIDE;
	}

	proc_init_cpumon_params();

	if (!PE_parse_boot_argn("task_wakeups_monitor_rate", &task_wakeups_monitor_rate, sizeof (task_wakeups_monitor_rate))) {
		task_wakeups_monitor_rate = TASK_WAKEUPS_MONITOR_DEFAULT_LIMIT;
	}

	if (!PE_parse_boot_argn("task_wakeups_monitor_interval", &task_wakeups_monitor_interval, sizeof (task_wakeups_monitor_interval))) {
		task_wakeups_monitor_interval = TASK_WAKEUPS_MONITOR_DEFAULT_INTERVAL;
	}

	if (!PE_parse_boot_argn("task_wakeups_monitor_ustackshots_trigger_pct", &task_wakeups_monitor_ustackshots_trigger_pct,
		sizeof (task_wakeups_monitor_ustackshots_trigger_pct))) {
		task_wakeups_monitor_ustackshots_trigger_pct = TASK_WAKEUPS_MONITOR_DEFAULT_USTACKSHOTS_TRIGGER;
	}

	if (!PE_parse_boot_argn("disable_exc_resource", &disable_exc_resource,
		sizeof (disable_exc_resource))) {
		disable_exc_resource = 0;
	}

/*
 * If we have coalitions, coalition_init() will call init_task_ledgers() as it
 * sets up the ledgers for the default coalition. If we don't have coalitions,
 * then we have to call it now.
 */
#if CONFIG_COALITIONS
	assert(task_ledger_template);
#else /* CONFIG_COALITIONS */
	init_task_ledgers();
#endif /* CONFIG_COALITIONS */

#if TASK_REFERENCE_LEAK_DEBUG
	simple_lock_init(&task_ref_lock, 0);
	task_ref_btlog = btlog_create(100000,
								  TASK_REF_BTDEPTH,
								  task_ref_lock_lock,
								  task_ref_lock_unlock,
								  &task_ref_lock);
	assert(task_ref_btlog);
#endif

	/*
	 * Create the kernel task as the first task.
	 */
#ifdef __LP64__
	if (task_create_internal(TASK_NULL, NULL, FALSE, TRUE, &kernel_task) != KERN_SUCCESS)
#else
	if (task_create_internal(TASK_NULL, NULL, FALSE, FALSE, &kernel_task) != KERN_SUCCESS)
#endif
		panic("task_init\n");

	vm_map_deallocate(kernel_task->map);
	kernel_task->map = kernel_map;
	lck_spin_init(&dead_task_statistics_lock, &task_lck_grp, &task_lck_attr);

}

/*
 * Create a task running in the kernel address space.  It may
 * have its own map of size mem_size and may have ipc privileges.
 */
kern_return_t
kernel_task_create(
	__unused task_t		parent_task,
	__unused vm_offset_t		map_base,
	__unused vm_size_t		map_size,
	__unused task_t		*child_task)
{
	return (KERN_INVALID_ARGUMENT);
}

kern_return_t
task_create(
	task_t				parent_task,
	__unused ledger_port_array_t	ledger_ports,
	__unused mach_msg_type_number_t	num_ledger_ports,
	__unused boolean_t		inherit_memory,
	__unused task_t			*child_task)	/* OUT */
{
	if (parent_task == TASK_NULL)
		return(KERN_INVALID_ARGUMENT);

	/*
	 * No longer supported: too many calls assume that a task has a valid
	 * process attached.
	 */
	return(KERN_FAILURE);
}

kern_return_t
host_security_create_task_token(
	host_security_t			host_security,
	task_t				parent_task,
	__unused security_token_t	sec_token,
	__unused audit_token_t		audit_token,
	__unused host_priv_t		host_priv,
	__unused ledger_port_array_t	ledger_ports,
	__unused mach_msg_type_number_t	num_ledger_ports,
	__unused boolean_t		inherit_memory,
	__unused task_t			*child_task)	/* OUT */
{
	if (parent_task == TASK_NULL)
		return(KERN_INVALID_ARGUMENT);

	if (host_security == HOST_NULL)
		return(KERN_INVALID_SECURITY);

	/*
	 * No longer supported.
	 */
	return(KERN_FAILURE);
}

/*
 * Task ledgers
 * ------------
 *
 * phys_footprint
 *   Physical footprint: This is the sum of:
 *     + (internal - alternate_accounting)
 *     + (internal_compressed - alternate_accounting_compressed)
 *     + iokit_mapped
 *     + purgeable_nonvolatile
 *     + purgeable_nonvolatile_compressed
 *
 * internal
 *   The task's anonymous memory, which on iOS is always resident.
 *
 * internal_compressed
 *   Amount of this task's internal memory which is held by the compressor.
 *   Such memory is no longer actually resident for the task [i.e., resident in its pmap],
 *   and could be either decompressed back into memory, or paged out to storage, depending
 *   on our implementation.
 *
 * iokit_mapped
 *   IOKit mappings: The total size of all IOKit mappings in this task, regardless of
     clean/dirty or internal/external state].
 *
 * alternate_accounting
 *   The number of internal dirty pages which are part of IOKit mappings. By definition, these pages
 *   are counted in both internal *and* iokit_mapped, so we must subtract them from the total to avoid
 *   double counting.
 */
void
init_task_ledgers(void)
{
	ledger_template_t t;
	
	assert(task_ledger_template == NULL);
	assert(kernel_task == TASK_NULL);

	if ((t = ledger_template_create("Per-task ledger")) == NULL)
		panic("couldn't create task ledger template");

	task_ledgers.cpu_time = ledger_entry_add(t, "cpu_time", "sched", "ns");
	task_ledgers.tkm_private = ledger_entry_add(t, "tkm_private",
	    "physmem", "bytes");
	task_ledgers.tkm_shared = ledger_entry_add(t, "tkm_shared", "physmem",
	    "bytes");
	task_ledgers.phys_mem = ledger_entry_add(t, "phys_mem", "physmem",
	    "bytes");
	task_ledgers.wired_mem = ledger_entry_add(t, "wired_mem", "physmem",
	    "bytes");
	task_ledgers.internal = ledger_entry_add(t, "internal", "physmem",
	    "bytes");
	task_ledgers.iokit_mapped = ledger_entry_add(t, "iokit_mapped", "mappings",
 	    "bytes");
	task_ledgers.alternate_accounting = ledger_entry_add(t, "alternate_accounting", "physmem",
 	    "bytes");
	task_ledgers.alternate_accounting_compressed = ledger_entry_add(t, "alternate_accounting_compressed", "physmem",
 	    "bytes");
	task_ledgers.phys_footprint = ledger_entry_add(t, "phys_footprint", "physmem",
 	    "bytes");
	task_ledgers.internal_compressed = ledger_entry_add(t, "internal_compressed", "physmem",
 	    "bytes");
	task_ledgers.purgeable_volatile = ledger_entry_add(t, "purgeable_volatile", "physmem", "bytes");
	task_ledgers.purgeable_nonvolatile = ledger_entry_add(t, "purgeable_nonvolatile", "physmem", "bytes");
	task_ledgers.purgeable_volatile_compressed = ledger_entry_add(t, "purgeable_volatile_compress", "physmem", "bytes");
	task_ledgers.purgeable_nonvolatile_compressed = ledger_entry_add(t, "purgeable_nonvolatile_compress", "physmem", "bytes");
	task_ledgers.platform_idle_wakeups = ledger_entry_add(t, "platform_idle_wakeups", "power",
 	    "count");
	task_ledgers.interrupt_wakeups = ledger_entry_add(t, "interrupt_wakeups", "power",
 	    "count");
	
#if CONFIG_SCHED_SFI
	sfi_class_id_t class_id, ledger_alias;
	for (class_id = SFI_CLASS_UNSPECIFIED; class_id < MAX_SFI_CLASS_ID; class_id++) {
		task_ledgers.sfi_wait_times[class_id] = -1;
	}

	/* don't account for UNSPECIFIED */
	for (class_id = SFI_CLASS_UNSPECIFIED + 1; class_id < MAX_SFI_CLASS_ID; class_id++) {
		ledger_alias = sfi_get_ledger_alias_for_class(class_id);
		if (ledger_alias != SFI_CLASS_UNSPECIFIED) {
			/* Check to see if alias has been registered yet */
			if (task_ledgers.sfi_wait_times[ledger_alias] != -1) {
				task_ledgers.sfi_wait_times[class_id] = task_ledgers.sfi_wait_times[ledger_alias];
			} else {
				/* Otherwise, initialize it first */
				task_ledgers.sfi_wait_times[class_id] = task_ledgers.sfi_wait_times[ledger_alias] = sfi_ledger_entry_add(t, ledger_alias);
			}
		} else {
			task_ledgers.sfi_wait_times[class_id] = sfi_ledger_entry_add(t, class_id);
		}

		if (task_ledgers.sfi_wait_times[class_id] < 0) {
			panic("couldn't create entries for task ledger template for SFI class 0x%x", class_id);
		}
	}

	assert(task_ledgers.sfi_wait_times[MAX_SFI_CLASS_ID -1] != -1);
#endif /* CONFIG_SCHED_SFI */

#ifdef CONFIG_BANK
	task_ledgers.cpu_time_billed_to_me = ledger_entry_add(t, "cpu_time_billed_to_me", "sched", "ns");
	task_ledgers.cpu_time_billed_to_others = ledger_entry_add(t, "cpu_time_billed_to_others", "sched", "ns");
#endif
	if ((task_ledgers.cpu_time < 0) ||
	    (task_ledgers.tkm_private < 0) ||
	    (task_ledgers.tkm_shared < 0) ||
	    (task_ledgers.phys_mem < 0) ||
	    (task_ledgers.wired_mem < 0) ||
	    (task_ledgers.internal < 0) ||
	    (task_ledgers.iokit_mapped < 0) ||
	    (task_ledgers.alternate_accounting < 0) ||
	    (task_ledgers.alternate_accounting_compressed < 0) ||
	    (task_ledgers.phys_footprint < 0) ||
	    (task_ledgers.internal_compressed < 0) ||
	    (task_ledgers.purgeable_volatile < 0) ||
	    (task_ledgers.purgeable_nonvolatile < 0) ||
	    (task_ledgers.purgeable_volatile_compressed < 0) ||
	    (task_ledgers.purgeable_nonvolatile_compressed < 0) ||
	    (task_ledgers.platform_idle_wakeups < 0) ||
	    (task_ledgers.interrupt_wakeups < 0)
#ifdef CONFIG_BANK
	    || (task_ledgers.cpu_time_billed_to_me < 0) || (task_ledgers.cpu_time_billed_to_others < 0)
#endif
	    ) {
		panic("couldn't create entries for task ledger template");
	}

	ledger_track_maximum(t, task_ledgers.phys_footprint, 60);
#if MACH_ASSERT
	if (pmap_ledgers_panic) {
		ledger_panic_on_negative(t, task_ledgers.phys_footprint);
		ledger_panic_on_negative(t, task_ledgers.internal);
		ledger_panic_on_negative(t, task_ledgers.internal_compressed);
		ledger_panic_on_negative(t, task_ledgers.iokit_mapped);
		ledger_panic_on_negative(t, task_ledgers.alternate_accounting);
		ledger_panic_on_negative(t, task_ledgers.alternate_accounting_compressed);
		ledger_panic_on_negative(t, task_ledgers.purgeable_volatile);
		ledger_panic_on_negative(t, task_ledgers.purgeable_nonvolatile);
		ledger_panic_on_negative(t, task_ledgers.purgeable_volatile_compressed);
		ledger_panic_on_negative(t, task_ledgers.purgeable_nonvolatile_compressed);
	}
#endif /* MACH_ASSERT */

#if CONFIG_JETSAM
	ledger_set_callback(t, task_ledgers.phys_footprint, task_footprint_exceeded, NULL, NULL);
#endif

	ledger_set_callback(t, task_ledgers.interrupt_wakeups,
		task_wakeups_rate_exceeded, NULL, NULL);
	
	task_ledger_template = t;
}

kern_return_t
task_create_internal(
	task_t		parent_task,
	coalition_t	*parent_coalitions __unused,
	boolean_t	inherit_memory,
	boolean_t	is_64bit,
	task_t		*child_task)		/* OUT */
{
	task_t			new_task;
	vm_shared_region_t	shared_region;
	ledger_t		ledger = NULL;

	new_task = (task_t) zalloc(task_zone);

	if (new_task == TASK_NULL)
		return(KERN_RESOURCE_SHORTAGE);

	/* one ref for just being alive; one for our caller */
	new_task->ref_count = 2;

	/* allocate with active entries */
	assert(task_ledger_template != NULL);
	if ((ledger = ledger_instantiate(task_ledger_template,
			LEDGER_CREATE_ACTIVE_ENTRIES)) == NULL) {
		zfree(task_zone, new_task);
		return(KERN_RESOURCE_SHORTAGE);
	}

	new_task->ledger = ledger;

#if defined(CONFIG_SCHED_MULTIQ)
	new_task->sched_group = sched_group_create();
#endif

	/* if inherit_memory is true, parent_task MUST not be NULL */
	if (inherit_memory)
		new_task->map = vm_map_fork(ledger, parent_task->map);
	else
		new_task->map = vm_map_create(pmap_create(ledger, 0, is_64bit),
				(vm_map_offset_t)(VM_MIN_ADDRESS),
				(vm_map_offset_t)(VM_MAX_ADDRESS), TRUE);

	/* Inherit memlock limit from parent */
	if (parent_task)
		vm_map_set_user_wire_limit(new_task->map, (vm_size_t)parent_task->map->user_wire_limit);

	lck_mtx_init(&new_task->lock, &task_lck_grp, &task_lck_attr);
	queue_init(&new_task->threads);
	new_task->suspend_count = 0;
	new_task->thread_count = 0;
	new_task->active_thread_count = 0;
	new_task->user_stop_count = 0;
	new_task->legacy_stop_count = 0;
	new_task->active = TRUE;
	new_task->halting = FALSE;
	new_task->user_data = NULL;
	new_task->faults = 0;
	new_task->cow_faults = 0;
	new_task->pageins = 0;
	new_task->messages_sent = 0;
	new_task->messages_received = 0;
	new_task->syscalls_mach = 0;
	new_task->priv_flags = 0;
	new_task->syscalls_unix=0;
	new_task->c_switch = new_task->p_switch = new_task->ps_switch = 0;
	new_task->t_flags = 0;
	new_task->importance = 0;

#if CONFIG_ATM
	new_task->atm_context = NULL;
#endif
#if CONFIG_BANK
	new_task->bank_context = NULL;
#endif

	zinfo_task_init(new_task);

#ifdef MACH_BSD
	new_task->bsd_info = NULL;
	new_task->corpse_info = NULL;
#endif /* MACH_BSD */

#if CONFIG_JETSAM
	if (max_task_footprint != 0) {
		ledger_set_limit(ledger, task_ledgers.phys_footprint, max_task_footprint, PHYS_FOOTPRINT_WARNING_LEVEL);
	}
#endif

	if (task_wakeups_monitor_rate != 0) {
		uint32_t flags = WAKEMON_ENABLE | WAKEMON_SET_DEFAULTS;
		int32_t  rate; // Ignored because of WAKEMON_SET_DEFAULTS
		task_wakeups_monitor_ctl(new_task, &flags, &rate);
	}

#if defined(__i386__) || defined(__x86_64__)
	new_task->i386_ldt = 0;
#endif

	new_task->task_debug = NULL;

	queue_init(&new_task->semaphore_list);
	new_task->semaphores_owned = 0;

	ipc_task_init(new_task, parent_task);

	new_task->total_user_time = 0;
	new_task->total_system_time = 0;

	new_task->vtimers = 0;

	new_task->shared_region = NULL;

	new_task->affinity_space = NULL;

	new_task->pidsuspended = FALSE;
	new_task->frozen = FALSE;
	new_task->changing_freeze_state = FALSE;
	new_task->rusage_cpu_flags = 0;
	new_task->rusage_cpu_percentage = 0;
	new_task->rusage_cpu_interval = 0;
	new_task->rusage_cpu_deadline = 0;
	new_task->rusage_cpu_callt = NULL;
#if MACH_ASSERT
	new_task->suspends_outstanding = 0;
#endif

#if HYPERVISOR
	new_task->hv_task_target = NULL;
#endif /* HYPERVISOR */


	new_task->low_mem_notified_warn = 0;
	new_task->low_mem_notified_critical = 0;
	new_task->low_mem_privileged_listener = 0;
	new_task->purged_memory_warn = 0;
	new_task->purged_memory_critical = 0;
	new_task->mem_notify_reserved = 0;
#if IMPORTANCE_INHERITANCE
	new_task->task_imp_base = NULL;
#endif /* IMPORTANCE_INHERITANCE */

#if	defined(__x86_64__)	
	new_task->uexc_range_start = new_task->uexc_range_size = new_task->uexc_handler = 0;
#endif

	new_task->requested_policy = default_task_requested_policy;
	new_task->effective_policy = default_task_effective_policy;
	new_task->pended_policy    = default_task_pended_policy;

	if (parent_task != TASK_NULL) {
		new_task->sec_token = parent_task->sec_token;
		new_task->audit_token = parent_task->audit_token;

		/* inherit the parent's shared region */
		shared_region = vm_shared_region_get(parent_task);
		vm_shared_region_set(new_task, shared_region);

		if(task_has_64BitAddr(parent_task))
			task_set_64BitAddr(new_task);
		new_task->all_image_info_addr = parent_task->all_image_info_addr;
		new_task->all_image_info_size = parent_task->all_image_info_size;

#if defined(__i386__) || defined(__x86_64__)
		if (inherit_memory && parent_task->i386_ldt)
			new_task->i386_ldt = user_ldt_copy(parent_task->i386_ldt);
#endif
		if (inherit_memory && parent_task->affinity_space)
			task_affinity_create(parent_task, new_task);

		new_task->pset_hint = parent_task->pset_hint = task_choose_pset(parent_task);

#if IMPORTANCE_INHERITANCE
		ipc_importance_task_t new_task_imp = IIT_NULL;

		if (task_is_marked_importance_donor(parent_task)) {
			new_task_imp = ipc_importance_for_task(new_task, FALSE);
			assert(IIT_NULL != new_task_imp);
			ipc_importance_task_mark_donor(new_task_imp, TRUE);
		}
		/* Embedded doesn't want this to inherit */
		if (task_is_marked_importance_receiver(parent_task)) {
			if (IIT_NULL == new_task_imp)
				new_task_imp = ipc_importance_for_task(new_task, FALSE);
			assert(IIT_NULL != new_task_imp);
			ipc_importance_task_mark_receiver(new_task_imp, TRUE);
		}
		if (task_is_marked_importance_denap_receiver(parent_task)) {
			if (IIT_NULL == new_task_imp)
				new_task_imp = ipc_importance_for_task(new_task, FALSE);
			assert(IIT_NULL != new_task_imp);
			ipc_importance_task_mark_denap_receiver(new_task_imp, TRUE);
		}
		
		if (IIT_NULL != new_task_imp) {
			assert(new_task->task_imp_base == new_task_imp);
			ipc_importance_task_release(new_task_imp);
		}
#endif /* IMPORTANCE_INHERITANCE */

		new_task->priority = BASEPRI_DEFAULT;
		new_task->max_priority = MAXPRI_USER;

		new_task->requested_policy.t_apptype     = parent_task->requested_policy.t_apptype;

		new_task->requested_policy.int_darwinbg  = parent_task->requested_policy.int_darwinbg;
		new_task->requested_policy.ext_darwinbg  = parent_task->requested_policy.ext_darwinbg;
		new_task->requested_policy.int_iotier    = parent_task->requested_policy.int_iotier;
		new_task->requested_policy.ext_iotier    = parent_task->requested_policy.ext_iotier;
		new_task->requested_policy.int_iopassive = parent_task->requested_policy.int_iopassive;
		new_task->requested_policy.ext_iopassive = parent_task->requested_policy.ext_iopassive;
		new_task->requested_policy.bg_iotier     = parent_task->requested_policy.bg_iotier;
		new_task->requested_policy.terminated    = parent_task->requested_policy.terminated;
		new_task->requested_policy.t_qos_clamp   = parent_task->requested_policy.t_qos_clamp;

		task_policy_create(new_task, parent_task->requested_policy.t_boosted);
	} else {
		new_task->sec_token = KERNEL_SECURITY_TOKEN;
		new_task->audit_token = KERNEL_AUDIT_TOKEN;
#ifdef __LP64__
		if(is_64bit)
			task_set_64BitAddr(new_task);
#endif
		new_task->all_image_info_addr = (mach_vm_address_t)0;
		new_task->all_image_info_size = (mach_vm_size_t)0;

		new_task->pset_hint = PROCESSOR_SET_NULL;

		if (kernel_task == TASK_NULL) {
			new_task->priority = BASEPRI_KERNEL;
			new_task->max_priority = MAXPRI_KERNEL;
		} else {
			new_task->priority = BASEPRI_DEFAULT;
			new_task->max_priority = MAXPRI_USER;
		}
	}

	bzero(new_task->coalition, sizeof(new_task->coalition));
	for (int i = 0; i < COALITION_NUM_TYPES; i++)
		queue_chain_init(new_task->task_coalition[i]);

	/* Allocate I/O Statistics */
	new_task->task_io_stats = (io_stat_info_t)kalloc(sizeof(struct io_stat_info));
	assert(new_task->task_io_stats != NULL);
	bzero(new_task->task_io_stats, sizeof(struct io_stat_info));

	bzero(&(new_task->cpu_time_qos_stats), sizeof(struct _cpu_time_qos_stats));

	bzero(&new_task->extmod_statistics, sizeof(new_task->extmod_statistics));
	new_task->task_timer_wakeups_bin_1 = new_task->task_timer_wakeups_bin_2 = 0;
	new_task->task_gpu_ns = 0;

#if CONFIG_COALITIONS

	/* TODO: there is no graceful failure path here... */
	if (parent_coalitions && parent_coalitions[COALITION_TYPE_RESOURCE]) {
		coalitions_adopt_task(parent_coalitions, new_task);
	} else if (parent_task && parent_task->coalition[COALITION_TYPE_RESOURCE]) {
		/*
		 * all tasks at least have a resource coalition, so
		 * if the parent has one then inherit all coalitions
		 * the parent is a part of
		 */
		coalitions_adopt_task(parent_task->coalition, new_task);
	} else {
		/* TODO: assert that new_task will be PID 1 (launchd) */
		coalitions_adopt_init_task(new_task);
	}

	if (new_task->coalition[COALITION_TYPE_RESOURCE] == COALITION_NULL) {
		panic("created task is not a member of a resource coalition");
	}
#endif /* CONFIG_COALITIONS */

	new_task->dispatchqueue_offset = 0;
	if (parent_task != NULL) {
		new_task->dispatchqueue_offset = parent_task->dispatchqueue_offset;
	}

	if (vm_backing_store_low && parent_task != NULL)
		new_task->priv_flags |= (parent_task->priv_flags&VM_BACKING_STORE_PRIV);

	new_task->task_volatile_objects = 0;
	new_task->task_nonvolatile_objects = 0;
	new_task->task_purgeable_disowning = FALSE;
	new_task->task_purgeable_disowned = FALSE;

	ipc_task_enable(new_task);

	lck_mtx_lock(&tasks_threads_lock);
	queue_enter(&tasks, new_task, task_t, tasks);
	tasks_count++;
	lck_mtx_unlock(&tasks_threads_lock);

	*child_task = new_task;
	return(KERN_SUCCESS);
}

int task_dropped_imp_count = 0;

/*
 *	task_deallocate:
 *
 *	Drop a reference on a task.
 */
void
task_deallocate(
	task_t		task)
{
	ledger_amount_t credit, debit, interrupt_wakeups, platform_idle_wakeups;
	uint32_t refs;

	if (task == TASK_NULL)
	    return;

	refs = task_deallocate_internal(task);

#if IMPORTANCE_INHERITANCE
	if (refs > 1)
		return;
	
	if (refs == 1) {
		/*
		 * If last ref potentially comes from the task's importance,
		 * disconnect it.  But more task refs may be added before
		 * that completes, so wait for the reference to go to zero
		 * naturually (it may happen on a recursive task_deallocate()
		 * from the ipc_importance_disconnect_task() call).
		 */
		if (IIT_NULL != task->task_imp_base)
			ipc_importance_disconnect_task(task);
		return;
	}
#else
	if (refs > 0)
		return;
#endif /* IMPORTANCE_INHERITANCE */

	lck_mtx_lock(&tasks_threads_lock);
	queue_remove(&terminated_tasks, task, task_t, tasks);
	terminated_tasks_count--;
	lck_mtx_unlock(&tasks_threads_lock);

	/*
	 * remove the reference on atm descriptor
	 */
	 task_atm_reset(task);

#if CONFIG_BANK
	/*
	 * remove the reference on bank context
	 */
	if (task->bank_context != NULL) {
		bank_task_destroy(task->bank_context);
		task->bank_context = NULL;
	}
#endif

	if (task->task_io_stats)
		kfree(task->task_io_stats, sizeof(struct io_stat_info));

	/*
	 *	Give the machine dependent code a chance
	 *	to perform cleanup before ripping apart
	 *	the task.
	 */
	machine_task_terminate(task);

	ipc_task_terminate(task);

	if (task->affinity_space)
		task_affinity_deallocate(task);

#if MACH_ASSERT
	if (task->ledger != NULL &&
	    task->map != NULL &&
	    task->map->pmap != NULL &&
	    task->map->pmap->ledger != NULL) {
		assert(task->ledger == task->map->pmap->ledger);
	}
#endif /* MACH_ASSERT */

	vm_purgeable_disown(task);
	assert(task->task_purgeable_disowned);
	if (task->task_volatile_objects != 0 ||
	    task->task_nonvolatile_objects != 0) {
		panic("task_deallocate(%p): "
		      "volatile_objects=%d nonvolatile_objects=%d\n",
		      task,
		      task->task_volatile_objects,
		      task->task_nonvolatile_objects);
	}

	vm_map_deallocate(task->map);
	is_release(task->itk_space);

	ledger_get_entries(task->ledger, task_ledgers.interrupt_wakeups,
	                   &interrupt_wakeups, &debit);
	ledger_get_entries(task->ledger, task_ledgers.platform_idle_wakeups,
	                   &platform_idle_wakeups, &debit);

#if defined(CONFIG_SCHED_MULTIQ)
	sched_group_destroy(task->sched_group);
#endif

	/* Accumulate statistics for dead tasks */
	lck_spin_lock(&dead_task_statistics_lock);
	dead_task_statistics.total_user_time += task->total_user_time;
	dead_task_statistics.total_system_time += task->total_system_time;

	dead_task_statistics.task_interrupt_wakeups += interrupt_wakeups;
	dead_task_statistics.task_platform_idle_wakeups += platform_idle_wakeups;

	dead_task_statistics.task_timer_wakeups_bin_1 += task->task_timer_wakeups_bin_1;
	dead_task_statistics.task_timer_wakeups_bin_2 += task->task_timer_wakeups_bin_2;

	lck_spin_unlock(&dead_task_statistics_lock);
	lck_mtx_destroy(&task->lock, &task_lck_grp);

	if (!ledger_get_entries(task->ledger, task_ledgers.tkm_private, &credit,
	    &debit)) {
		OSAddAtomic64(credit, (int64_t *)&tasks_tkm_private.alloc);
		OSAddAtomic64(debit, (int64_t *)&tasks_tkm_private.free);
	}
	if (!ledger_get_entries(task->ledger, task_ledgers.tkm_shared, &credit,
	    &debit)) {
		OSAddAtomic64(credit, (int64_t *)&tasks_tkm_shared.alloc);
		OSAddAtomic64(debit, (int64_t *)&tasks_tkm_shared.free);
	}
	ledger_dereference(task->ledger);
	zinfo_task_free(task);

#if TASK_REFERENCE_LEAK_DEBUG
	btlog_remove_entries_for_element(task_ref_btlog, task);
#endif

#if CONFIG_COALITIONS
	if (!task->coalition[COALITION_TYPE_RESOURCE])
		panic("deallocating task was not a member of a resource coalition");
	task_release_coalitions(task);
#endif /* CONFIG_COALITIONS */

	bzero(task->coalition, sizeof(task->coalition));

#if MACH_BSD
	/* clean up collected information since last reference to task is gone */
	if (task->corpse_info) {
		task_crashinfo_destroy(task->corpse_info);
		task->corpse_info = NULL;
	}
#endif

	zfree(task_zone, task);
}

/*
 *	task_name_deallocate:
 *
 *	Drop a reference on a task name.
 */
void
task_name_deallocate(
	task_name_t		task_name)
{
	return(task_deallocate((task_t)task_name));
}

/*
 *	task_suspension_token_deallocate:
 *
 *	Drop a reference on a task suspension token.
 */
void
task_suspension_token_deallocate(
	task_suspension_token_t		token)
{
	return(task_deallocate((task_t)token));
}


/*
 * task_collect_crash_info:
 *
 * collect crash info from bsd and mach based data
 */
kern_return_t
task_collect_crash_info(task_t task)
{
	kern_return_t kr = KERN_SUCCESS;

	kcdata_descriptor_t crash_data = NULL;
	kcdata_descriptor_t crash_data_release = NULL;
	mach_msg_type_number_t size = CORPSEINFO_ALLOCATION_SIZE;
	mach_vm_offset_t crash_data_user_ptr = 0;

	if (!corpses_enabled()) {
		return KERN_NOT_SUPPORTED;
	}

	task_lock(task);
	assert(task->bsd_info != NULL);
	if (task->corpse_info == NULL && task->bsd_info != NULL) {
		task_unlock(task);
		/* map crash data memory in task's vm map */
		kr = mach_vm_allocate(task->map, &crash_data_user_ptr, size, (VM_MAKE_TAG(VM_MEMORY_CORPSEINFO) | VM_FLAGS_ANYWHERE));

		if (kr != KERN_SUCCESS)
			goto out_no_lock;

		crash_data = task_crashinfo_alloc_init((mach_vm_address_t)crash_data_user_ptr, size);
		if (crash_data) {
			task_lock(task);
			crash_data_release = task->corpse_info;
			task->corpse_info = crash_data;
			task_unlock(task);
			kr = KERN_SUCCESS;
		} else {
			/* if failed to create corpse info, free the mapping */
			if (KERN_SUCCESS != mach_vm_deallocate(task->map, crash_data_user_ptr, size)) {
				printf("mach_vm_deallocate failed to clear corpse_data for pid %d.\n", task_pid(task));
			}
			kr = KERN_FAILURE;
		}

		if (crash_data_release != NULL) {
			task_crashinfo_destroy(crash_data_release);
		}
	} else {
		task_unlock(task);
	}

out_no_lock:
	return kr;
}

/*
 * task_deliver_crash_notification:
 *
 * Makes outcall to registered host port for a corpse.
 */
kern_return_t
task_deliver_crash_notification(task_t task)
{
	kcdata_descriptor_t crash_info = task->corpse_info;
	thread_t th_iter = NULL;
	kern_return_t kr = KERN_SUCCESS;
	wait_interrupt_t wsave;
	mach_exception_data_type_t code[EXCEPTION_CODE_MAX];

	if (crash_info == NULL)
		return KERN_FAILURE;

	code[0] = crash_info->kcd_addr_begin;
	code[1] = crash_info->kcd_length;

	task_lock(task);
	queue_iterate(&task->threads, th_iter, thread_t, task_threads)
	{
		ipc_thread_reset(th_iter);
	}
	task_unlock(task);

	wsave = thread_interrupt_level(THREAD_UNINT);
	kr = exception_triage(EXC_CORPSE_NOTIFY, code, EXCEPTION_CODE_MAX);
	if (kr != KERN_SUCCESS) {
		printf("Failed to send exception EXC_CORPSE_NOTIFY. error code: %d for pid %d\n", kr, task_pid(task));
	}

	/*
	 * crash reporting is done. Now release threads
	 * for reaping by thread_terminate_daemon
	 */
	task_lock(task);
	assert(task->active_thread_count == 0);
	queue_iterate(&task->threads, th_iter, thread_t, task_threads)
	{
		thread_mtx_lock(th_iter);
		assert(th_iter->inspection == TRUE);
		th_iter->inspection = FALSE;
		/* now that the corpse has been autopsied, dispose of the thread name */
		uthread_cleanup_name(th_iter->uthread);
		thread_mtx_unlock(th_iter);
	}

	thread_terminate_crashed_threads();
	/* remove the pending corpse report flag */
	task_clear_corpse_pending_report(task);

	task_unlock(task);

	(void)thread_interrupt_level(wsave);
	task_terminate_internal(task);

	return kr;
}

/*
 *	task_terminate:
 *
 *	Terminate the specified task.  See comments on thread_terminate
 *	(kern/thread.c) about problems with terminating the "current task."
 */

kern_return_t
task_terminate(
	task_t		task)
{
	if (task == TASK_NULL)
		return (KERN_INVALID_ARGUMENT);

	if (task->bsd_info)
		return (KERN_FAILURE);

	return (task_terminate_internal(task));
}

#if MACH_ASSERT
extern int proc_pid(struct proc *);
extern void proc_name_kdp(task_t t, char *buf, int size);
#endif /* MACH_ASSERT */

#define VM_MAP_PARTIAL_REAP 0x54  /* 0x150 */
static void
__unused task_partial_reap(task_t task, __unused int pid)
{
        unsigned int    reclaimed_resident = 0;
        unsigned int    reclaimed_compressed = 0;
	uint64_t        task_page_count;

	task_page_count = (get_task_phys_footprint(task) / PAGE_SIZE_64);

	KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, VM_MAP_PARTIAL_REAP) | DBG_FUNC_START),
                              pid, task_page_count, 0, 0, 0);

	vm_map_partial_reap(task->map, &reclaimed_resident, &reclaimed_compressed);

        KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, VM_MAP_PARTIAL_REAP) | DBG_FUNC_END),
                              pid, reclaimed_resident, reclaimed_compressed, 0, 0);
}

kern_return_t
task_mark_corpse(task_t task)
{
	kern_return_t kr = KERN_SUCCESS;
	thread_t self_thread;
	(void) self_thread;
	wait_interrupt_t wsave;

	assert(task != kernel_task);
	assert(task == current_task());
	assert(!task_is_a_corpse(task));

	kr = task_collect_crash_info(task);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	self_thread = current_thread();

	wsave = thread_interrupt_level(THREAD_UNINT);
	task_lock(task);

	task_set_corpse_pending_report(task);
	task_set_corpse(task);

	kr = task_start_halt_locked(task, TRUE);
	assert(kr == KERN_SUCCESS);
	ipc_task_reset(task);
	ipc_task_enable(task);

	task_unlock(task);
	/* terminate the ipc space */
	ipc_space_terminate(task->itk_space);
	
	task_start_halt(task);
	thread_terminate_internal(self_thread);
	(void) thread_interrupt_level(wsave);
	assert(task->halting == TRUE);
	return kr;
}

kern_return_t
task_terminate_internal(
	task_t			task)
{
	thread_t			thread, self;
	task_t				self_task;
	boolean_t			interrupt_save;
	int				pid = 0;

	assert(task != kernel_task);

	self = current_thread();
	self_task = self->task;

	/*
	 *	Get the task locked and make sure that we are not racing
	 *	with someone else trying to terminate us.
	 */
	if (task == self_task)
		task_lock(task);
	else
	if (task < self_task) {
		task_lock(task);
		task_lock(self_task);
	}
	else {
		task_lock(self_task);
		task_lock(task);
	}

	if (!task->active) {
		/*
		 *	Task is already being terminated.
		 *	Just return an error. If we are dying, this will
		 *	just get us to our AST special handler and that
		 *	will get us to finalize the termination of ourselves.
		 */
		task_unlock(task);
		if (self_task != task)
			task_unlock(self_task);

		return (KERN_FAILURE);
	}

	if (task_corpse_pending_report(task)) {
		/*
		 *	Task is marked for reporting as corpse.
		 *	Just return an error. This will
		 *	just get us to our AST special handler and that
		 *	will get us to finish the path to death
		 */
		task_unlock(task);
		if (self_task != task)
			task_unlock(self_task);

		return (KERN_FAILURE);
	}

	if (self_task != task)
		task_unlock(self_task);

	/*
	 * Make sure the current thread does not get aborted out of
	 * the waits inside these operations.
	 */
	interrupt_save = thread_interrupt_level(THREAD_UNINT);

	/*
	 *	Indicate that we want all the threads to stop executing
	 *	at user space by holding the task (we would have held
	 *	each thread independently in thread_terminate_internal -
	 *	but this way we may be more likely to already find it
	 *	held there).  Mark the task inactive, and prevent
	 *	further task operations via the task port.
	 */
	task_hold_locked(task);
	task->active = FALSE;
	ipc_task_disable(task);

#if CONFIG_TELEMETRY
	/*
	 * Notify telemetry that this task is going away.
	 */
	telemetry_task_ctl_locked(task, TF_TELEMETRY, 0);
#endif

	/*
	 *	Terminate each thread in the task.
	 */
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
			thread_terminate_internal(thread);
	}

#ifdef MACH_BSD
	if (task->bsd_info != NULL) {
		pid = proc_pid(task->bsd_info);
	}
#endif /* MACH_BSD */

	task_unlock(task);

	proc_set_task_policy(task, THREAD_NULL, TASK_POLICY_ATTRIBUTE,
			     TASK_POLICY_TERMINATED, TASK_POLICY_ENABLE);

        /* Early object reap phase */

// PR-17045188: Revisit implementation
//        task_partial_reap(task, pid);


	/*
	 *	Destroy all synchronizers owned by the task.
	 */
	task_synchronizer_destroy_all(task);

	/*
	 *	Destroy the IPC space, leaving just a reference for it.
	 */
	ipc_space_terminate(task->itk_space);

#if 00
	/* if some ledgers go negative on tear-down again... */
	ledger_disable_panic_on_negative(task->map->pmap->ledger,
					 task_ledgers.phys_footprint);
	ledger_disable_panic_on_negative(task->map->pmap->ledger,
					 task_ledgers.internal);
	ledger_disable_panic_on_negative(task->map->pmap->ledger,
					 task_ledgers.internal_compressed);
	ledger_disable_panic_on_negative(task->map->pmap->ledger,
					 task_ledgers.iokit_mapped);
	ledger_disable_panic_on_negative(task->map->pmap->ledger,
					 task_ledgers.alternate_accounting);
	ledger_disable_panic_on_negative(task->map->pmap->ledger,
					 task_ledgers.alternate_accounting_compressed);
#endif

	/*
	 * If the current thread is a member of the task
	 * being terminated, then the last reference to
	 * the task will not be dropped until the thread
	 * is finally reaped.  To avoid incurring the
	 * expense of removing the address space regions
	 * at reap time, we do it explictly here.
	 */

	vm_map_lock(task->map);
	vm_map_disable_hole_optimization(task->map);
	vm_map_unlock(task->map);

	vm_map_remove(task->map,
		      task->map->min_offset,
		      task->map->max_offset,
		      /* no unnesting on final cleanup: */
		      VM_MAP_REMOVE_NO_UNNESTING);

	/* release our shared region */
	vm_shared_region_set(task, NULL);


#if MACH_ASSERT
	/*
	 * Identify the pmap's process, in case the pmap ledgers drift
	 * and we have to report it.
	 */
	char procname[17];
	if (task->bsd_info) {
		pid = proc_pid(task->bsd_info);
		proc_name_kdp(task, procname, sizeof (procname));
	} else {
		pid = 0;
		strlcpy(procname, "<unknown>", sizeof (procname));
	}
	pmap_set_process(task->map->pmap, pid, procname);
#endif /* MACH_ASSERT */

	lck_mtx_lock(&tasks_threads_lock);
	queue_remove(&tasks, task, task_t, tasks);
	queue_enter(&terminated_tasks, task, task_t, tasks);
	tasks_count--;
	terminated_tasks_count++;
	lck_mtx_unlock(&tasks_threads_lock);

	/*
	 * We no longer need to guard against being aborted, so restore
	 * the previous interruptible state.
	 */
	thread_interrupt_level(interrupt_save);

#if KPERF
	/* force the task to release all ctrs */
	if (task->t_chud & TASK_KPC_FORCED_ALL_CTRS)
		kpc_force_all_ctrs(task, 0);
#endif

#if CONFIG_COALITIONS
	/*
	 * Leave our coalitions. (drop activation but not reference)
	 */
	coalitions_remove_task(task);
#endif

	/*
	 * Get rid of the task active reference on itself.
	 */
	task_deallocate(task);

	return (KERN_SUCCESS);
}

/*
 * task_start_halt:
 *
 * 	Shut the current task down (except for the current thread) in
 *	preparation for dramatic changes to the task (probably exec).
 *	We hold the task and mark all other threads in the task for
 *	termination.
 */
kern_return_t
task_start_halt(task_t task)
{
	kern_return_t kr = KERN_SUCCESS;
	task_lock(task);
	kr = task_start_halt_locked(task, FALSE);
	task_unlock(task);
	return kr;
}

static kern_return_t
task_start_halt_locked(task_t task, boolean_t should_mark_corpse)
{
	thread_t thread, self;
	uint64_t dispatchqueue_offset;

	assert(task != kernel_task);

	self = current_thread();

	if (task != self->task)
		return (KERN_INVALID_ARGUMENT);

	if (task->halting || !task->active || !self->active) {
		/*
		 * Task or current thread is already being terminated.
		 * Hurry up and return out of the current kernel context
		 * so that we run our AST special handler to terminate
		 * ourselves.
		 */
		return (KERN_FAILURE);
	}

	task->halting = TRUE;

	/*
	 * Mark all the threads to keep them from starting any more
	 * user-level execution.  The thread_terminate_internal code
	 * would do this on a thread by thread basis anyway, but this
	 * gives us a better chance of not having to wait there.
	 */
	task_hold_locked(task);
	dispatchqueue_offset = get_dispatchqueue_offset_from_proc(task->bsd_info);

	/*
	 * Terminate all the other threads in the task.
	 */
	queue_iterate(&task->threads, thread, thread_t, task_threads)
	{
		if (should_mark_corpse) {
			thread_mtx_lock(thread);
			thread->inspection = TRUE;
			thread_mtx_unlock(thread);
		}
		if (thread != self)
			thread_terminate_internal(thread);
	}
	task->dispatchqueue_offset = dispatchqueue_offset;

	task_release_locked(task);

	return KERN_SUCCESS;
}


/*
 * task_complete_halt:
 *
 *	Complete task halt by waiting for threads to terminate, then clean
 *	up task resources (VM, port namespace, etc...) and then let the
 *	current thread go in the (practically empty) task context.
 */
void
task_complete_halt(task_t task)
{
	task_lock(task);
	assert(task->halting);
	assert(task == current_task());

	/*
	 *	Wait for the other threads to get shut down.
	 *      When the last other thread is reaped, we'll be
	 *	woken up.
	 */
	if (task->thread_count > 1) {
		assert_wait((event_t)&task->halting, THREAD_UNINT);
		task_unlock(task);
		thread_block(THREAD_CONTINUE_NULL);
	} else {
		task_unlock(task);
	}

	/*
	 *	Give the machine dependent code a chance
	 *	to perform cleanup of task-level resources
	 *	associated with the current thread before
	 *	ripping apart the task.
	 */
	machine_task_terminate(task);

	/*
	 *	Destroy all synchronizers owned by the task.
	 */
	task_synchronizer_destroy_all(task);

	/*
	 *	Destroy the contents of the IPC space, leaving just
	 *	a reference for it.
	 */
	ipc_space_clean(task->itk_space);

	/*
	 * Clean out the address space, as we are going to be
	 * getting a new one.
	 */
	vm_map_remove(task->map, task->map->min_offset,
		      task->map->max_offset,
		      /* no unnesting on final cleanup: */
		      VM_MAP_REMOVE_NO_UNNESTING);

	task->halting = FALSE;
}

/*
 *	task_hold_locked:
 *
 *	Suspend execution of the specified task.
 *	This is a recursive-style suspension of the task, a count of
 *	suspends is maintained.
 *
 * 	CONDITIONS: the task is locked and active.
 */
void
task_hold_locked(
	register task_t		task)
{
	register thread_t	thread;

	assert(task->active);

	if (task->suspend_count++ > 0)
		return;

	/*
	 *	Iterate through all the threads and hold them.
	 */
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		thread_mtx_lock(thread);
		thread_hold(thread);
		thread_mtx_unlock(thread);
	}
}

/*
 *	task_hold:
 *
 *	Same as the internal routine above, except that is must lock
 *	and verify that the task is active.  This differs from task_suspend
 *	in that it places a kernel hold on the task rather than just a 
 *	user-level hold.  This keeps users from over resuming and setting
 *	it running out from under the kernel.
 *
 * 	CONDITIONS: the caller holds a reference on the task
 */
kern_return_t
task_hold(
	register task_t		task)
{
	if (task == TASK_NULL)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);

	if (!task->active) {
		task_unlock(task);

		return (KERN_FAILURE);
	}

	task_hold_locked(task);
	task_unlock(task);

	return (KERN_SUCCESS);
}

kern_return_t
task_wait(
		task_t		task,
		boolean_t	until_not_runnable)
{
	if (task == TASK_NULL)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);

	if (!task->active) {
		task_unlock(task);

		return (KERN_FAILURE);
	}

	task_wait_locked(task, until_not_runnable);
	task_unlock(task);

	return (KERN_SUCCESS);
}

/*
 *	task_wait_locked:
 *
 *	Wait for all threads in task to stop.
 *
 * Conditions:
 *	Called with task locked, active, and held.
 */
void
task_wait_locked(
	register task_t		task,
	boolean_t		until_not_runnable)
{
	register thread_t	thread, self;

	assert(task->active);
	assert(task->suspend_count > 0);

	self = current_thread();

	/*
	 *	Iterate through all the threads and wait for them to
	 *	stop.  Do not wait for the current thread if it is within
	 *	the task.
	 */
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		if (thread != self)
			thread_wait(thread, until_not_runnable);
	}
}

/*
 *	task_release_locked:
 *
 *	Release a kernel hold on a task.
 *
 * 	CONDITIONS: the task is locked and active
 */
void
task_release_locked(
	register task_t		task)
{
	register thread_t	thread;

	assert(task->active);
	assert(task->suspend_count > 0);

	if (--task->suspend_count > 0)
		return;

	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		thread_mtx_lock(thread);
		thread_release(thread);
		thread_mtx_unlock(thread);
	}
}

/*
 *	task_release:
 *
 *	Same as the internal routine above, except that it must lock
 *	and verify that the task is active.
 *
 * 	CONDITIONS: The caller holds a reference to the task
 */
kern_return_t
task_release(
	task_t		task)
{
	if (task == TASK_NULL)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);

	if (!task->active) {
		task_unlock(task);

		return (KERN_FAILURE);
	}

	task_release_locked(task);
	task_unlock(task);

	return (KERN_SUCCESS);
}

kern_return_t
task_threads(
	task_t					task,
	thread_act_array_t		*threads_out,
	mach_msg_type_number_t	*count)
{
	mach_msg_type_number_t	actual;
	thread_t				*thread_list;
	thread_t				thread;
	vm_size_t				size, size_needed;
	void					*addr;
	unsigned int			i, j;

	if (task == TASK_NULL)
		return (KERN_INVALID_ARGUMENT);

	size = 0; addr = NULL;

	for (;;) {
		task_lock(task);
		if (!task->active) {
			task_unlock(task);

			if (size != 0)
				kfree(addr, size);

			return (KERN_FAILURE);
		}

		actual = task->thread_count;

		/* do we have the memory we need? */
		size_needed = actual * sizeof (mach_port_t);
		if (size_needed <= size)
			break;

		/* unlock the task and allocate more memory */
		task_unlock(task);

		if (size != 0)
			kfree(addr, size);

		assert(size_needed > 0);
		size = size_needed;

		addr = kalloc(size);
		if (addr == 0)
			return (KERN_RESOURCE_SHORTAGE);
	}

	/* OK, have memory and the task is locked & active */
	thread_list = (thread_t *)addr;

	i = j = 0;

	for (thread = (thread_t)queue_first(&task->threads); i < actual;
				++i, thread = (thread_t)queue_next(&thread->task_threads)) {
		thread_reference_internal(thread);
		thread_list[j++] = thread;
	}

	assert(queue_end(&task->threads, (queue_entry_t)thread));

	actual = j;
	size_needed = actual * sizeof (mach_port_t);

	/* can unlock task now that we've got the thread refs */
	task_unlock(task);

	if (actual == 0) {
		/* no threads, so return null pointer and deallocate memory */

		*threads_out = NULL;
		*count = 0;

		if (size != 0)
			kfree(addr, size);
	}
	else {
		/* if we allocated too much, must copy */

		if (size_needed < size) {
			void *newaddr;

			newaddr = kalloc(size_needed);
			if (newaddr == 0) {
				for (i = 0; i < actual; ++i)
					thread_deallocate(thread_list[i]);
				kfree(addr, size);
				return (KERN_RESOURCE_SHORTAGE);
			}

			bcopy(addr, newaddr, size_needed);
			kfree(addr, size);
			thread_list = (thread_t *)newaddr;
		}

		*threads_out = thread_list;
		*count = actual;

		/* do the conversion that Mig should handle */

		for (i = 0; i < actual; ++i)
			((ipc_port_t *) thread_list)[i] = convert_thread_to_port(thread_list[i]);
	}

	return (KERN_SUCCESS);
}

#define TASK_HOLD_NORMAL	0
#define TASK_HOLD_PIDSUSPEND	1
#define TASK_HOLD_LEGACY	2
#define TASK_HOLD_LEGACY_ALL	3

static kern_return_t
place_task_hold    (
	register task_t task,
	int mode)
{    
	if (!task->active) {
		return (KERN_FAILURE);
	}

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_IPC,MACH_TASK_SUSPEND) | DBG_FUNC_NONE,
	    task_pid(task), ((thread_t)queue_first(&task->threads))->thread_id,
	    task->user_stop_count, task->user_stop_count + 1, 0);

#if MACH_ASSERT
	current_task()->suspends_outstanding++;
#endif

	if (mode == TASK_HOLD_LEGACY)
		task->legacy_stop_count++;

	if (task->user_stop_count++ > 0) {
		/*
		 *	If the stop count was positive, the task is
		 *	already stopped and we can exit.
		 */
		return (KERN_SUCCESS);
	}

	/*
	 * Put a kernel-level hold on the threads in the task (all
	 * user-level task suspensions added together represent a
	 * single kernel-level hold).  We then wait for the threads
	 * to stop executing user code.
	 */
	task_hold_locked(task);
	task_wait_locked(task, FALSE);
	
	return (KERN_SUCCESS);
}

static kern_return_t
release_task_hold    (
	register task_t		task,
	int           		mode)
{
	register boolean_t release = FALSE;
    
	if (!task->active) {
		return (KERN_FAILURE);
	}
	
	if (mode == TASK_HOLD_PIDSUSPEND) {
	    if (task->pidsuspended == FALSE) {
		    return (KERN_FAILURE);
	    }
	    task->pidsuspended = FALSE;
	}

	if (task->user_stop_count > (task->pidsuspended ? 1 : 0)) {

		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    MACHDBG_CODE(DBG_MACH_IPC,MACH_TASK_RESUME) | DBG_FUNC_NONE,
		    task_pid(task), ((thread_t)queue_first(&task->threads))->thread_id,
		    task->user_stop_count, mode, task->legacy_stop_count);

#if MACH_ASSERT
		/*
		 * This is obviously not robust; if we suspend one task and then resume a different one,
		 * we'll fly under the radar. This is only meant to catch the common case of a crashed
		 * or buggy suspender.
		 */
		current_task()->suspends_outstanding--;
#endif

		if (mode == TASK_HOLD_LEGACY_ALL) {
			if (task->legacy_stop_count >= task->user_stop_count) {
				task->user_stop_count = 0;
				release = TRUE;
			} else {
				task->user_stop_count -= task->legacy_stop_count;
			}
			task->legacy_stop_count = 0;
		} else {
			if (mode == TASK_HOLD_LEGACY && task->legacy_stop_count > 0)
				task->legacy_stop_count--;
			if (--task->user_stop_count == 0)
				release = TRUE;
		}
	}
	else {
		return (KERN_FAILURE);
	}

	/*
	 *	Release the task if necessary.
	 */
	if (release)
		task_release_locked(task);
		
    return (KERN_SUCCESS);
}


/*
 *	task_suspend:
 *
 *	Implement an (old-fashioned) user-level suspension on a task.
 *
 *	Because the user isn't expecting to have to manage a suspension
 *	token, we'll track it for him in the kernel in the form of a naked
 *	send right to the task's resume port.  All such send rights
 *	account for a single suspension against the task (unlike task_suspend2()
 *	where each caller gets a unique suspension count represented by a
 *	unique send-once right).
 *
 * Conditions:
 * 	The caller holds a reference to the task
 */
kern_return_t
task_suspend(
	register task_t		task)
{
	kern_return_t	 		kr;
	mach_port_t			port, send, old_notify;
	mach_port_name_t		name;

	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);

	/* 
	 * Claim a send right on the task resume port, and request a no-senders
	 * notification on that port (if none outstanding). 
	 */
	if (task->itk_resume == IP_NULL) {
		task->itk_resume = ipc_port_alloc_kernel();
		if (!IP_VALID(task->itk_resume))
			panic("failed to create resume port");
		ipc_kobject_set(task->itk_resume, (ipc_kobject_t)task, IKOT_TASK_RESUME);
	}

	port = task->itk_resume;
	ip_lock(port);
	assert(ip_active(port));

	send = ipc_port_make_send_locked(port);
	assert(IP_VALID(send));

	if (port->ip_nsrequest == IP_NULL) {
		ipc_port_nsrequest(port, port->ip_mscount, ipc_port_make_sonce_locked(port), &old_notify);
		assert(old_notify == IP_NULL);
		/* port unlocked */
	} else {
		ip_unlock(port);
	}

	/*
	 * place a legacy hold on the task.
	 */
	kr = place_task_hold(task, TASK_HOLD_LEGACY);
	if (kr != KERN_SUCCESS) {
		task_unlock(task);
		ipc_port_release_send(send);
		return kr;
	}

	task_unlock(task);

	/*
	 * Copyout the send right into the calling task's IPC space.  It won't know it is there,
	 * but we'll look it up when calling a traditional resume.  Any IPC operations that
	 * deallocate the send right will auto-release the suspension.
	 */
	if ((kr = ipc_kmsg_copyout_object(current_task()->itk_space, (ipc_object_t)send,
		MACH_MSG_TYPE_MOVE_SEND, &name)) != KERN_SUCCESS) {
		printf("warning: %s(%d) failed to copyout suspension token for pid %d with error: %d\n",
				proc_name_address(current_task()->bsd_info), proc_pid(current_task()->bsd_info),
				task_pid(task), kr);
		return (kr);
	}

	return (kr);
}

/*
 *	task_resume:
 *		Release a user hold on a task.
 *		
 * Conditions:
 *		The caller holds a reference to the task
 */
kern_return_t 
task_resume(
	register task_t	task)
{
	kern_return_t	 kr;
	mach_port_name_t resume_port_name;
	ipc_entry_t		 resume_port_entry;
	ipc_space_t		 space = current_task()->itk_space;

	if (task == TASK_NULL || task == kernel_task )
		return (KERN_INVALID_ARGUMENT);

	/* release a legacy task hold */
	task_lock(task);
	kr = release_task_hold(task, TASK_HOLD_LEGACY);
	task_unlock(task);

	is_write_lock(space);
	if (is_active(space) && IP_VALID(task->itk_resume) &&
	    ipc_hash_lookup(space, (ipc_object_t)task->itk_resume, &resume_port_name, &resume_port_entry) == TRUE) {
		/*
		 * We found a suspension token in the caller's IPC space. Release a send right to indicate that
		 * we are holding one less legacy hold on the task from this caller.  If the release failed,
		 * go ahead and drop all the rights, as someone either already released our holds or the task
		 * is gone.
		 */
		if (kr == KERN_SUCCESS)
			ipc_right_dealloc(space, resume_port_name, resume_port_entry);
		else
			ipc_right_destroy(space, resume_port_name, resume_port_entry, FALSE, 0);
		/* space unlocked */
	} else {
		is_write_unlock(space);
		if (kr == KERN_SUCCESS)
			printf("warning: %s(%d) performed out-of-band resume on pid %d\n",
			       proc_name_address(current_task()->bsd_info), proc_pid(current_task()->bsd_info),
			       task_pid(task));
	}

	return kr;
}

/*
 * Suspend the target task.
 * Making/holding a token/reference/port is the callers responsibility.
 */
kern_return_t
task_suspend_internal(task_t task)
{
	kern_return_t	 kr;
       
	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);
	kr = place_task_hold(task, TASK_HOLD_NORMAL);
	task_unlock(task);
	return (kr);
}

/*
 * Suspend the target task, and return a suspension token. The token
 * represents a reference on the suspended task.
 */
kern_return_t
task_suspend2(
	register task_t			task,
	task_suspension_token_t *suspend_token)
{
	kern_return_t	 kr;
 
	kr = task_suspend_internal(task);
	if (kr != KERN_SUCCESS) {
		*suspend_token = TASK_NULL;
		return (kr);
	}

	/*
	 * Take a reference on the target task and return that to the caller
	 * as a "suspension token," which can be converted into an SO right to
	 * the now-suspended task's resume port.
	 */
	task_reference_internal(task);
	*suspend_token = task;

	return (KERN_SUCCESS);
}

/*
 * Resume the task
 * (reference/token/port management is caller's responsibility).
 */
kern_return_t
task_resume_internal(
	register task_suspension_token_t		task)
{
	kern_return_t kr;

	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);
	kr = release_task_hold(task, TASK_HOLD_NORMAL);
	task_unlock(task);
	return (kr);
}

/*
 * Resume the task using a suspension token. Consumes the token's ref.
 */
kern_return_t
task_resume2(
	register task_suspension_token_t		task)
{
	kern_return_t kr;

	kr = task_resume_internal(task);
	task_suspension_token_deallocate(task);

	return (kr);
}

boolean_t
task_suspension_notify(mach_msg_header_t *request_header)
{
	ipc_port_t port = (ipc_port_t) request_header->msgh_remote_port;
	task_t task = convert_port_to_task_suspension_token(port);
	mach_msg_type_number_t not_count;

	if (task == TASK_NULL || task == kernel_task)
		return TRUE;  /* nothing to do */

	switch (request_header->msgh_id) {

	case MACH_NOTIFY_SEND_ONCE:
		/* release the hold held by this specific send-once right */
		task_lock(task);
		release_task_hold(task, TASK_HOLD_NORMAL);
		task_unlock(task);
		break;

	case MACH_NOTIFY_NO_SENDERS:
		not_count = ((mach_no_senders_notification_t *)request_header)->not_count;

		task_lock(task);
		ip_lock(port);
		if (port->ip_mscount == not_count) {

			/* release all the [remaining] outstanding legacy holds */
			assert(port->ip_nsrequest == IP_NULL);
			ip_unlock(port);
			release_task_hold(task, TASK_HOLD_LEGACY_ALL);
			task_unlock(task);

		} else if (port->ip_nsrequest == IP_NULL) {
			ipc_port_t old_notify;

			task_unlock(task);
			/* new send rights, re-arm notification at current make-send count */
			ipc_port_nsrequest(port, port->ip_mscount, ipc_port_make_sonce_locked(port), &old_notify);
			assert(old_notify == IP_NULL);
			/* port unlocked */
		} else {
			ip_unlock(port);
			task_unlock(task);
		}
		break;

	default:
		break;
	}

	task_suspension_token_deallocate(task); /* drop token reference */
	return TRUE;
}

kern_return_t
task_pidsuspend_locked(task_t task)
{
	kern_return_t kr;

	if (task->pidsuspended) {
		kr = KERN_FAILURE;
		goto out;
	}

	task->pidsuspended = TRUE;

	kr = place_task_hold(task, TASK_HOLD_PIDSUSPEND);
	if (kr != KERN_SUCCESS) {
		task->pidsuspended = FALSE;
	}
out:
	return(kr);
}


/*
 *	task_pidsuspend:
 *
 *	Suspends a task by placing a hold on its threads.
 *
 * Conditions:
 * 	The caller holds a reference to the task
 */
kern_return_t
task_pidsuspend(
	register task_t		task)
{
	kern_return_t	 kr;
    
	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);

	kr = task_pidsuspend_locked(task);

	task_unlock(task);

	return (kr);
}

/* If enabled, we bring all the frozen pages back in prior to resumption; otherwise, they're faulted back in on demand */
#define THAW_ON_RESUME 1

/*
 *	task_pidresume:
 *		Resumes a previously suspended task.
 *		
 * Conditions:
 *		The caller holds a reference to the task
 */
kern_return_t 
task_pidresume(
	register task_t	task)
{
	kern_return_t	 kr;

	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);
	
#if (CONFIG_FREEZE && THAW_ON_RESUME)

	while (task->changing_freeze_state) {

		assert_wait((event_t)&task->changing_freeze_state, THREAD_UNINT);
		task_unlock(task);
		thread_block(THREAD_CONTINUE_NULL);

		task_lock(task);
	}
	task->changing_freeze_state = TRUE;
#endif

	kr = release_task_hold(task, TASK_HOLD_PIDSUSPEND);

	task_unlock(task);

#if (CONFIG_FREEZE && THAW_ON_RESUME)
	if ((kr == KERN_SUCCESS) && (task->frozen == TRUE)) {

		if (COMPRESSED_PAGER_IS_ACTIVE || DEFAULT_FREEZER_COMPRESSED_PAGER_IS_ACTIVE) {

			kr = KERN_SUCCESS;
		} else {

			kr = vm_map_thaw(task->map);
		}
	}
	task_lock(task);

	if (kr == KERN_SUCCESS)
		task->frozen = FALSE;
	task->changing_freeze_state = FALSE;
	thread_wakeup(&task->changing_freeze_state);
	
	task_unlock(task);
#endif

	return (kr);
}

#if CONFIG_FREEZE

/*
 *	task_freeze:
 *
 *	Freeze a task.
 *
 * Conditions:
 * 	The caller holds a reference to the task
 */
extern void		vm_wake_compactor_swapper();
extern queue_head_t	c_swapout_list_head;

kern_return_t
task_freeze(
	register task_t    task,
	uint32_t           *purgeable_count,
	uint32_t           *wired_count,
	uint32_t           *clean_count,
	uint32_t           *dirty_count,
	uint32_t           dirty_budget,
	boolean_t          *shared,
	boolean_t          walk_only)
{
	kern_return_t kr;
    
	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);

	while (task->changing_freeze_state) {

		assert_wait((event_t)&task->changing_freeze_state, THREAD_UNINT);
		task_unlock(task);
		thread_block(THREAD_CONTINUE_NULL);

		task_lock(task);
	}
	if (task->frozen) {
		task_unlock(task);
		return (KERN_FAILURE);
	}
	task->changing_freeze_state = TRUE;

	task_unlock(task);

	if (walk_only) {
		kr = vm_map_freeze_walk(task->map, purgeable_count, wired_count, clean_count, dirty_count, dirty_budget, shared);		
	} else {
		kr = vm_map_freeze(task->map, purgeable_count, wired_count, clean_count, dirty_count, dirty_budget, shared);
	}

	task_lock(task);

	if (walk_only == FALSE && kr == KERN_SUCCESS)
		task->frozen = TRUE;
	task->changing_freeze_state = FALSE;
	thread_wakeup(&task->changing_freeze_state);
	
	task_unlock(task);

	if (COMPRESSED_PAGER_IS_ACTIVE || DEFAULT_FREEZER_COMPRESSED_PAGER_IS_ACTIVE) {
		vm_wake_compactor_swapper();
		/*
		 * We do an explicit wakeup of the swapout thread here
		 * because the compact_and_swap routines don't have
		 * knowledge about these kind of "per-task packed c_segs"
		 * and so will not be evaluating whether we need to do
		 * a wakeup there.
		 */
		thread_wakeup((event_t)&c_swapout_list_head);
	}

	return (kr);
}

/*
 *	task_thaw:
 *
 *	Thaw a currently frozen task.
 *
 * Conditions:
 * 	The caller holds a reference to the task
 */
kern_return_t
task_thaw(
	register task_t		task)
{
	kern_return_t kr;
    
	if (task == TASK_NULL || task == kernel_task)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);
	
	while (task->changing_freeze_state) {

		assert_wait((event_t)&task->changing_freeze_state, THREAD_UNINT);
		task_unlock(task);
		thread_block(THREAD_CONTINUE_NULL);

		task_lock(task);
	}
	if (!task->frozen) {
		task_unlock(task);
		return (KERN_FAILURE);
	}
	task->changing_freeze_state = TRUE;

	if (DEFAULT_PAGER_IS_ACTIVE || DEFAULT_FREEZER_IS_ACTIVE) {
		task_unlock(task);

		kr = vm_map_thaw(task->map);

		task_lock(task);
	
		if (kr == KERN_SUCCESS)
			task->frozen = FALSE;
	} else {
		task->frozen = FALSE;
		kr = KERN_SUCCESS;
	}

	task->changing_freeze_state = FALSE;
	thread_wakeup(&task->changing_freeze_state);
	
	task_unlock(task);

	if (COMPRESSED_PAGER_IS_ACTIVE || DEFAULT_FREEZER_COMPRESSED_PAGER_IS_ACTIVE) {
		vm_wake_compactor_swapper();
	}

	return (kr);
}

#endif /* CONFIG_FREEZE */

kern_return_t
host_security_set_task_token(
        host_security_t  host_security,
        task_t		 task,
        security_token_t sec_token,
	audit_token_t	 audit_token,
	host_priv_t	 host_priv)
{
	ipc_port_t	 host_port;
	kern_return_t	 kr;

	if (task == TASK_NULL)
		return(KERN_INVALID_ARGUMENT);

	if (host_security == HOST_NULL)
		return(KERN_INVALID_SECURITY);

        task_lock(task);
        task->sec_token = sec_token;
	task->audit_token = audit_token;

	task_unlock(task);

	if (host_priv != HOST_PRIV_NULL) {
		kr = host_get_host_priv_port(host_priv, &host_port);
	} else {
		kr = host_get_host_port(host_priv_self(), &host_port);
	}
	assert(kr == KERN_SUCCESS);
	kr = task_set_special_port(task, TASK_HOST_PORT, host_port);
        return(kr);
}

kern_return_t
task_send_trace_memory(
	task_t        target_task,
	__unused uint32_t pid,
	__unused uint64_t uniqueid)
{
	kern_return_t kr = KERN_INVALID_ARGUMENT;
	if (target_task == TASK_NULL)
		return (KERN_INVALID_ARGUMENT);

#if CONFIG_ATM
	kr = atm_send_proc_inspect_notification(target_task,
				  pid,
				  uniqueid);

#endif
	return (kr);
}
/*
 * This routine was added, pretty much exclusively, for registering the
 * RPC glue vector for in-kernel short circuited tasks.  Rather than
 * removing it completely, I have only disabled that feature (which was
 * the only feature at the time).  It just appears that we are going to
 * want to add some user data to tasks in the future (i.e. bsd info,
 * task names, etc...), so I left it in the formal task interface.
 */
kern_return_t
task_set_info(
	task_t		task,
	task_flavor_t	flavor,
	__unused task_info_t	task_info_in,		/* pointer to IN array */
	__unused mach_msg_type_number_t	task_info_count)
{
	if (task == TASK_NULL)
		return(KERN_INVALID_ARGUMENT);

	switch (flavor) {

#if CONFIG_ATM
		case TASK_TRACE_MEMORY_INFO:
		{
			if (task_info_count != TASK_TRACE_MEMORY_INFO_COUNT)
				return (KERN_INVALID_ARGUMENT);
			
			assert(task_info_in != NULL);
			task_trace_memory_info_t mem_info;
			mem_info = (task_trace_memory_info_t) task_info_in;
			kern_return_t kr = atm_register_trace_memory(task,
						mem_info->user_memory_address,
						mem_info->buffer_size);
			return kr;
			break;
		}

#endif
	    default:
		return (KERN_INVALID_ARGUMENT);
	}
	return (KERN_SUCCESS);
}

int radar_20146450 = 1;
kern_return_t
task_info(
	task_t			task,
	task_flavor_t		flavor,
	task_info_t		task_info_out,
	mach_msg_type_number_t	*task_info_count)
{
	kern_return_t error = KERN_SUCCESS;

	if (task == TASK_NULL)
		return (KERN_INVALID_ARGUMENT);

	task_lock(task);

	if ((task != current_task()) && (!task->active)) {
		task_unlock(task);
		return (KERN_INVALID_ARGUMENT);
	}

	switch (flavor) {

	case TASK_BASIC_INFO_32:
	case TASK_BASIC2_INFO_32:
	{
		task_basic_info_32_t	basic_info;
		vm_map_t				map;
		clock_sec_t				secs;
		clock_usec_t			usecs;

		if (*task_info_count < TASK_BASIC_INFO_32_COUNT) {
		    error = KERN_INVALID_ARGUMENT;
		    break;
		}

		basic_info = (task_basic_info_32_t)task_info_out;

		map = (task == kernel_task)? kernel_map: task->map;
		basic_info->virtual_size = (typeof(basic_info->virtual_size))map->size;
		if (flavor == TASK_BASIC2_INFO_32) {
			/*
			 * The "BASIC2" flavor gets the maximum resident
			 * size instead of the current resident size...
			 */
			basic_info->resident_size = pmap_resident_max(map->pmap);
		} else {
			basic_info->resident_size = pmap_resident_count(map->pmap);
		}
		basic_info->resident_size *= PAGE_SIZE;

		basic_info->policy = ((task != kernel_task)?
										  POLICY_TIMESHARE: POLICY_RR);
		basic_info->suspend_count = task->user_stop_count;

		absolutetime_to_microtime(task->total_user_time, &secs, &usecs);
		basic_info->user_time.seconds = 
			(typeof(basic_info->user_time.seconds))secs;
		basic_info->user_time.microseconds = usecs;

		absolutetime_to_microtime(task->total_system_time, &secs, &usecs);
		basic_info->system_time.seconds = 
			(typeof(basic_info->system_time.seconds))secs;
		basic_info->system_time.microseconds = usecs;

		*task_info_count = TASK_BASIC_INFO_32_COUNT;
		break;
	}

	case TASK_BASIC_INFO_64:
	{
		task_basic_info_64_t	basic_info;
		vm_map_t				map;
		clock_sec_t				secs;
		clock_usec_t			usecs;

		if (*task_info_count < TASK_BASIC_INFO_64_COUNT) {
		    error = KERN_INVALID_ARGUMENT;
		    break;
		}

		basic_info = (task_basic_info_64_t)task_info_out;

		map = (task == kernel_task)? kernel_map: task->map;
		basic_info->virtual_size  = map->size;
		basic_info->resident_size =
			(mach_vm_size_t)(pmap_resident_count(map->pmap))
			* PAGE_SIZE_64;

		basic_info->policy = ((task != kernel_task)?
										  POLICY_TIMESHARE: POLICY_RR);
		basic_info->suspend_count = task->user_stop_count;

		absolutetime_to_microtime(task->total_user_time, &secs, &usecs);
		basic_info->user_time.seconds = 
			(typeof(basic_info->user_time.seconds))secs;
		basic_info->user_time.microseconds = usecs;

		absolutetime_to_microtime(task->total_system_time, &secs, &usecs);
		basic_info->system_time.seconds =
			(typeof(basic_info->system_time.seconds))secs;
		basic_info->system_time.microseconds = usecs;

		*task_info_count = TASK_BASIC_INFO_64_COUNT;
		break;
	}

	case MACH_TASK_BASIC_INFO:
	{
		mach_task_basic_info_t  basic_info;
		vm_map_t                map;
		clock_sec_t             secs;
		clock_usec_t            usecs;

		if (*task_info_count < MACH_TASK_BASIC_INFO_COUNT) {
		    error = KERN_INVALID_ARGUMENT;
		    break;
		}

		basic_info = (mach_task_basic_info_t)task_info_out;

		map = (task == kernel_task) ? kernel_map : task->map;

		basic_info->virtual_size  = map->size;

		basic_info->resident_size =
		    (mach_vm_size_t)(pmap_resident_count(map->pmap));
		basic_info->resident_size *= PAGE_SIZE_64;

		basic_info->resident_size_max =
		    (mach_vm_size_t)(pmap_resident_max(map->pmap));
		basic_info->resident_size_max *= PAGE_SIZE_64;

		basic_info->policy = ((task != kernel_task) ? 
		                      POLICY_TIMESHARE : POLICY_RR);

		basic_info->suspend_count = task->user_stop_count;

		absolutetime_to_microtime(task->total_user_time, &secs, &usecs);
		basic_info->user_time.seconds = 
		    (typeof(basic_info->user_time.seconds))secs;
		basic_info->user_time.microseconds = usecs;

		absolutetime_to_microtime(task->total_system_time, &secs, &usecs);
		basic_info->system_time.seconds =
		    (typeof(basic_info->system_time.seconds))secs;
		basic_info->system_time.microseconds = usecs;

		*task_info_count = MACH_TASK_BASIC_INFO_COUNT;
		break;
	}

	case TASK_THREAD_TIMES_INFO:
	{
		register task_thread_times_info_t	times_info;
		register thread_t					thread;

		if (*task_info_count < TASK_THREAD_TIMES_INFO_COUNT) {
		    error = KERN_INVALID_ARGUMENT;
		    break;
		}

		times_info = (task_thread_times_info_t) task_info_out;
		times_info->user_time.seconds = 0;
		times_info->user_time.microseconds = 0;
		times_info->system_time.seconds = 0;
		times_info->system_time.microseconds = 0;


		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			time_value_t	user_time, system_time;

			if (thread->options & TH_OPT_IDLE_THREAD)
				continue;

			thread_read_times(thread, &user_time, &system_time);

			time_value_add(&times_info->user_time, &user_time);
			time_value_add(&times_info->system_time, &system_time);
		}

		*task_info_count = TASK_THREAD_TIMES_INFO_COUNT;
		break;
	}

	case TASK_ABSOLUTETIME_INFO:
	{
		task_absolutetime_info_t	info;
		register thread_t			thread;

		if (*task_info_count < TASK_ABSOLUTETIME_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		info = (task_absolutetime_info_t)task_info_out;
		info->threads_user = info->threads_system = 0;


		info->total_user = task->total_user_time;
		info->total_system = task->total_system_time;

		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			uint64_t	tval;
			spl_t 		x;

			if (thread->options & TH_OPT_IDLE_THREAD)
				continue;

			x = splsched();
			thread_lock(thread);

			tval = timer_grab(&thread->user_timer);
			info->threads_user += tval;
			info->total_user += tval;

			tval = timer_grab(&thread->system_timer);
			if (thread->precise_user_kernel_time) {
				info->threads_system += tval;
				info->total_system += tval;
			} else {
				/* system_timer may represent either sys or user */
				info->threads_user += tval;
				info->total_user += tval;
			}

			thread_unlock(thread);
			splx(x);
		}


		*task_info_count = TASK_ABSOLUTETIME_INFO_COUNT;
		break;
	}

	case TASK_DYLD_INFO:
	{
		task_dyld_info_t info;

		/*
		 * We added the format field to TASK_DYLD_INFO output.  For
		 * temporary backward compatibility, accept the fact that
		 * clients may ask for the old version - distinquished by the
		 * size of the expected result structure.
		 */
#define TASK_LEGACY_DYLD_INFO_COUNT \
		offsetof(struct task_dyld_info, all_image_info_format)/sizeof(natural_t)

		if (*task_info_count < TASK_LEGACY_DYLD_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		info = (task_dyld_info_t)task_info_out;
		info->all_image_info_addr = task->all_image_info_addr;
		info->all_image_info_size = task->all_image_info_size;

		/* only set format on output for those expecting it */
		if (*task_info_count >= TASK_DYLD_INFO_COUNT) {
			info->all_image_info_format = task_has_64BitAddr(task) ?
				                 TASK_DYLD_ALL_IMAGE_INFO_64 : 
				                 TASK_DYLD_ALL_IMAGE_INFO_32 ;
			*task_info_count = TASK_DYLD_INFO_COUNT;
		} else {
			*task_info_count = TASK_LEGACY_DYLD_INFO_COUNT;
		}
		break;
	}

	case TASK_EXTMOD_INFO:
	{
		task_extmod_info_t info;
		void *p;

		if (*task_info_count < TASK_EXTMOD_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		info = (task_extmod_info_t)task_info_out;

		p = get_bsdtask_info(task);
		if (p) {
			proc_getexecutableuuid(p, info->task_uuid, sizeof(info->task_uuid));
		} else {
			bzero(info->task_uuid, sizeof(info->task_uuid));
		}
		info->extmod_statistics = task->extmod_statistics;
		*task_info_count = TASK_EXTMOD_INFO_COUNT;

		break;
	}

	case TASK_KERNELMEMORY_INFO:
	{
		task_kernelmemory_info_t	tkm_info;
		ledger_amount_t			credit, debit;

		if (*task_info_count < TASK_KERNELMEMORY_INFO_COUNT) {
		   error = KERN_INVALID_ARGUMENT;
		   break;
		}

		tkm_info = (task_kernelmemory_info_t) task_info_out;
		tkm_info->total_palloc = 0;
		tkm_info->total_pfree = 0;
		tkm_info->total_salloc = 0;
		tkm_info->total_sfree = 0;

		if (task == kernel_task) {
			/*
			 * All shared allocs/frees from other tasks count against
			 * the kernel private memory usage.  If we are looking up
			 * info for the kernel task, gather from everywhere.
			 */
			task_unlock(task);

			/* start by accounting for all the terminated tasks against the kernel */
			tkm_info->total_palloc = tasks_tkm_private.alloc + tasks_tkm_shared.alloc;
			tkm_info->total_pfree = tasks_tkm_private.free + tasks_tkm_shared.free;

			/* count all other task/thread shared alloc/free against the kernel */
			lck_mtx_lock(&tasks_threads_lock);

			/* XXX this really shouldn't be using the function parameter 'task' as a local var! */
			queue_iterate(&tasks, task, task_t, tasks) {
				if (task == kernel_task) {
					if (ledger_get_entries(task->ledger,
					    task_ledgers.tkm_private, &credit,
					    &debit) == KERN_SUCCESS) {
						tkm_info->total_palloc += credit;
						tkm_info->total_pfree += debit;
					}
				}
				if (!ledger_get_entries(task->ledger,
				    task_ledgers.tkm_shared, &credit, &debit)) {
					tkm_info->total_palloc += credit;
					tkm_info->total_pfree += debit;
				}
			}
			lck_mtx_unlock(&tasks_threads_lock);
		} else {
			if (!ledger_get_entries(task->ledger,
			    task_ledgers.tkm_private, &credit, &debit)) {
				tkm_info->total_palloc = credit;
				tkm_info->total_pfree = debit;
			}
			if (!ledger_get_entries(task->ledger,
			    task_ledgers.tkm_shared, &credit, &debit)) {
				tkm_info->total_salloc = credit;
				tkm_info->total_sfree = debit;
			}
			task_unlock(task);
		}

		*task_info_count = TASK_KERNELMEMORY_INFO_COUNT;
		return KERN_SUCCESS;
	}

	/* OBSOLETE */
	case TASK_SCHED_FIFO_INFO:
	{

		if (*task_info_count < POLICY_FIFO_BASE_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		error = KERN_INVALID_POLICY;
		break;
	}

	/* OBSOLETE */
	case TASK_SCHED_RR_INFO:
	{
		register policy_rr_base_t	rr_base;
		uint32_t quantum_time;
		uint64_t quantum_ns;

		if (*task_info_count < POLICY_RR_BASE_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		rr_base = (policy_rr_base_t) task_info_out;

		if (task != kernel_task) {
			error = KERN_INVALID_POLICY;
			break;
		}

		rr_base->base_priority = task->priority;

		quantum_time = SCHED(initial_quantum_size)(THREAD_NULL);
		absolutetime_to_nanoseconds(quantum_time, &quantum_ns);
		
		rr_base->quantum = (uint32_t)(quantum_ns / 1000 / 1000);

		*task_info_count = POLICY_RR_BASE_COUNT;
		break;
	}

	/* OBSOLETE */
	case TASK_SCHED_TIMESHARE_INFO:
	{
		register policy_timeshare_base_t	ts_base;

		if (*task_info_count < POLICY_TIMESHARE_BASE_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		ts_base = (policy_timeshare_base_t) task_info_out;

		if (task == kernel_task) {
			error = KERN_INVALID_POLICY;
			break;
		}

		ts_base->base_priority = task->priority;

		*task_info_count = POLICY_TIMESHARE_BASE_COUNT;
		break;
	}

	case TASK_SECURITY_TOKEN:
	{
		register security_token_t	*sec_token_p;

		if (*task_info_count < TASK_SECURITY_TOKEN_COUNT) {
		    error = KERN_INVALID_ARGUMENT;
		    break;
		}

		sec_token_p = (security_token_t *) task_info_out;

		*sec_token_p = task->sec_token;

		*task_info_count = TASK_SECURITY_TOKEN_COUNT;
		break;
	}
            
	case TASK_AUDIT_TOKEN:
	{
		register audit_token_t	*audit_token_p;

		if (*task_info_count < TASK_AUDIT_TOKEN_COUNT) {
		    error = KERN_INVALID_ARGUMENT;
		    break;
		}

		audit_token_p = (audit_token_t *) task_info_out;

		*audit_token_p = task->audit_token;

		*task_info_count = TASK_AUDIT_TOKEN_COUNT;
		break;
	}
            
	case TASK_SCHED_INFO:
		error = KERN_INVALID_ARGUMENT;
		break;

	case TASK_EVENTS_INFO:
	{
		register task_events_info_t	events_info;
		register thread_t			thread;

		if (*task_info_count < TASK_EVENTS_INFO_COUNT) {
		   error = KERN_INVALID_ARGUMENT;
		   break;
		}

		events_info = (task_events_info_t) task_info_out;


		events_info->faults = task->faults;
		events_info->pageins = task->pageins;
		events_info->cow_faults = task->cow_faults;
		events_info->messages_sent = task->messages_sent;
		events_info->messages_received = task->messages_received;
		events_info->syscalls_mach = task->syscalls_mach;
		events_info->syscalls_unix = task->syscalls_unix;

		events_info->csw = task->c_switch;

		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			events_info->csw	   += thread->c_switch;
			events_info->syscalls_mach += thread->syscalls_mach;
			events_info->syscalls_unix += thread->syscalls_unix;
		}


		*task_info_count = TASK_EVENTS_INFO_COUNT;
		break;
	}
	case TASK_AFFINITY_TAG_INFO:
	{
		if (*task_info_count < TASK_AFFINITY_TAG_INFO_COUNT) {
		    error = KERN_INVALID_ARGUMENT;
		    break;
		}

		error = task_affinity_info(task, task_info_out, task_info_count);
		break;
	}
	case TASK_POWER_INFO:
	{
		if (*task_info_count < TASK_POWER_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		task_power_info_locked(task, (task_power_info_t)task_info_out, NULL);
		break;
	}

	case TASK_POWER_INFO_V2:
	{
		if (*task_info_count < TASK_POWER_INFO_V2_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}
		task_power_info_v2_t tpiv2 = (task_power_info_v2_t) task_info_out;
		task_power_info_locked(task, &tpiv2->cpu_energy, &tpiv2->gpu_energy);
		break;
	}

	case TASK_VM_INFO:
	case TASK_VM_INFO_PURGEABLE:
	{
		task_vm_info_t		vm_info;
		vm_map_t		map;

		if (*task_info_count < TASK_VM_INFO_REV0_COUNT) {
		    error = KERN_INVALID_ARGUMENT;
		    break;
		}

		vm_info = (task_vm_info_t)task_info_out;

		if (task == kernel_task) {
			map = kernel_map;
			/* no lock */
		} else {
			map = task->map;
			vm_map_lock_read(map);
		}

		vm_info->virtual_size = (typeof(vm_info->virtual_size))map->size;
		vm_info->region_count = map->hdr.nentries;
		vm_info->page_size = vm_map_page_size(map);

		vm_info->resident_size = pmap_resident_count(map->pmap);
		vm_info->resident_size *= PAGE_SIZE;
		vm_info->resident_size_peak = pmap_resident_max(map->pmap);
		vm_info->resident_size_peak *= PAGE_SIZE;

#define _VM_INFO(_name) \
	vm_info->_name = ((mach_vm_size_t) map->pmap->stats._name) * PAGE_SIZE

		_VM_INFO(device);
		_VM_INFO(device_peak);
		_VM_INFO(external);
		_VM_INFO(external_peak);
		_VM_INFO(internal);
		_VM_INFO(internal_peak);
		_VM_INFO(reusable);
		_VM_INFO(reusable_peak);
		_VM_INFO(compressed);
		_VM_INFO(compressed_peak);
		_VM_INFO(compressed_lifetime);

		vm_info->purgeable_volatile_pmap = 0;
		vm_info->purgeable_volatile_resident = 0;
		vm_info->purgeable_volatile_virtual = 0;
		if (task == kernel_task) {
			/*
			 * We do not maintain the detailed stats for the
			 * kernel_pmap, so just count everything as
			 * "internal"...
			 */
			vm_info->internal = vm_info->resident_size;
			/*
			 * ... but since the memory held by the VM compressor
			 * in the kernel address space ought to be attributed
			 * to user-space tasks, we subtract it from "internal"
			 * to give memory reporting tools a more accurate idea
			 * of what the kernel itself is actually using, instead
			 * of making it look like the kernel is leaking memory
			 * when the system is under memory pressure.
			 */
			vm_info->internal -= (VM_PAGE_COMPRESSOR_COUNT *
					      PAGE_SIZE);
		} else {
			mach_vm_size_t	volatile_virtual_size;
			mach_vm_size_t	volatile_resident_size;
			mach_vm_size_t	volatile_compressed_size;
			mach_vm_size_t	volatile_pmap_size;
			mach_vm_size_t	volatile_compressed_pmap_size;
			kern_return_t	kr;

			if (flavor == TASK_VM_INFO_PURGEABLE) {
				kr = vm_map_query_volatile(
					map,
					&volatile_virtual_size,
					&volatile_resident_size,
					&volatile_compressed_size,
					&volatile_pmap_size,
					&volatile_compressed_pmap_size);
				if (kr == KERN_SUCCESS) {
					vm_info->purgeable_volatile_pmap =
						volatile_pmap_size;
					if (radar_20146450) {
					vm_info->compressed -=
						volatile_compressed_pmap_size;
					}
					vm_info->purgeable_volatile_resident =
						volatile_resident_size;
					vm_info->purgeable_volatile_virtual =
						volatile_virtual_size;
				}
			}
			vm_map_unlock_read(map);
		}

		if (*task_info_count >= TASK_VM_INFO_COUNT) {
			vm_info->phys_footprint = 0;
			*task_info_count = TASK_VM_INFO_COUNT;
		} else {
			*task_info_count = TASK_VM_INFO_REV0_COUNT;
		}

		break;
	}

	case TASK_WAIT_STATE_INFO:
	{
		/* 
		 * Deprecated flavor. Currently allowing some results until all users 
		 * stop calling it. The results may not be accurate.
         */
		task_wait_state_info_t	wait_state_info;
		uint64_t total_sfi_ledger_val = 0;

		if (*task_info_count < TASK_WAIT_STATE_INFO_COUNT) {
		   error = KERN_INVALID_ARGUMENT;
		   break;
		}

		wait_state_info = (task_wait_state_info_t) task_info_out;

		wait_state_info->total_wait_state_time = 0;
		bzero(wait_state_info->_reserved, sizeof(wait_state_info->_reserved));

#if CONFIG_SCHED_SFI
		int i, prev_lentry = -1;
		int64_t  val_credit, val_debit;

		for (i = 0; i < MAX_SFI_CLASS_ID; i++){
			val_credit =0;
			/*
			 * checking with prev_lentry != entry ensures adjacent classes 
			 * which share the same ledger do not add wait times twice.
			 * Note: Use ledger() call to get data for each individual sfi class.
			 */
			if (prev_lentry != task_ledgers.sfi_wait_times[i] &&
				KERN_SUCCESS == ledger_get_entries(task->ledger, 
				                task_ledgers.sfi_wait_times[i], &val_credit, &val_debit)) {
				total_sfi_ledger_val += val_credit;
			}
			prev_lentry = task_ledgers.sfi_wait_times[i];
		}

#endif /* CONFIG_SCHED_SFI */
		wait_state_info->total_wait_sfi_state_time = total_sfi_ledger_val; 
		*task_info_count = TASK_WAIT_STATE_INFO_COUNT;

		break;
	}
	case TASK_VM_INFO_PURGEABLE_ACCOUNT:
	{
#if DEVELOPMENT || DEBUG
		pvm_account_info_t	acnt_info;

		if (*task_info_count < PVM_ACCOUNT_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		if (task_info_out == NULL) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		acnt_info = (pvm_account_info_t) task_info_out;

		error = vm_purgeable_account(task, acnt_info);

		*task_info_count = PVM_ACCOUNT_INFO_COUNT;

		break;
#else /* DEVELOPMENT || DEBUG */
		error = KERN_NOT_SUPPORTED;
		break;
#endif /* DEVELOPMENT || DEBUG */
	}
	case TASK_FLAGS_INFO:
	{
		task_flags_info_t  		flags_info;

		if (*task_info_count < TASK_FLAGS_INFO_COUNT) {
		    error = KERN_INVALID_ARGUMENT;
		    break;
		}

		flags_info = (task_flags_info_t)task_info_out;

		/* only publish the 64-bit flag of the task */
		flags_info->flags = task->t_flags & TF_64B_ADDR;

		*task_info_count = TASK_FLAGS_INFO_COUNT;
		break;
	}

	case TASK_DEBUG_INFO_INTERNAL:
	{
#if DEVELOPMENT || DEBUG
		task_debug_info_internal_t dbg_info;
		if (*task_info_count < TASK_DEBUG_INFO_INTERNAL_COUNT) {
			error = KERN_NOT_SUPPORTED;
			break;
		}

		if (task_info_out == NULL) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}
		dbg_info = (task_debug_info_internal_t) task_info_out;
		dbg_info->ipc_space_size = 0;
		if (task->itk_space){
			dbg_info->ipc_space_size = task->itk_space->is_table_size;
		}

		error = KERN_SUCCESS;
		*task_info_count = TASK_DEBUG_INFO_INTERNAL_COUNT;
		break;
#else /* DEVELOPMENT || DEBUG */
		error = KERN_NOT_SUPPORTED;
		break;
#endif /* DEVELOPMENT || DEBUG */
	}
	default:
		error = KERN_INVALID_ARGUMENT;
	}

	task_unlock(task);
	return (error);
}

/* 
 *	task_power_info
 *
 *	Returns power stats for the task.
 *	Note: Called with task locked.
 */
void
task_power_info_locked(
	task_t			task,
	task_power_info_t	info,
	gpu_energy_data_t	ginfo)
{
	thread_t		thread;
	ledger_amount_t		tmp;

	task_lock_assert_owned(task);

	ledger_get_entries(task->ledger, task_ledgers.interrupt_wakeups,
		(ledger_amount_t *)&info->task_interrupt_wakeups, &tmp);
	ledger_get_entries(task->ledger, task_ledgers.platform_idle_wakeups,
		(ledger_amount_t *)&info->task_platform_idle_wakeups, &tmp);

	info->task_timer_wakeups_bin_1 = task->task_timer_wakeups_bin_1;
	info->task_timer_wakeups_bin_2 = task->task_timer_wakeups_bin_2;

	info->total_user = task->total_user_time;
	info->total_system = task->total_system_time;

	if (ginfo) {
		ginfo->task_gpu_utilisation = task->task_gpu_ns;
	}

	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		uint64_t	tval;
		spl_t 		x;

		if (thread->options & TH_OPT_IDLE_THREAD)
			continue;

		x = splsched();
		thread_lock(thread);

		info->task_timer_wakeups_bin_1 += thread->thread_timer_wakeups_bin_1;
		info->task_timer_wakeups_bin_2 += thread->thread_timer_wakeups_bin_2;

		tval = timer_grab(&thread->user_timer);
		info->total_user += tval;

		tval = timer_grab(&thread->system_timer);
		if (thread->precise_user_kernel_time) {
			info->total_system += tval;
		} else {
			/* system_timer may represent either sys or user */
			info->total_user += tval;
		}

		if (ginfo) {
			ginfo->task_gpu_utilisation += ml_gpu_stat(thread);
		}
		thread_unlock(thread);
		splx(x);
	}
}

/* 
 *	task_gpu_utilisation
 *
 *	Returns the total gpu time used by the all the threads of the task
 *  (both dead and alive)
 */
uint64_t
task_gpu_utilisation(
	task_t	task)
{
	uint64_t gpu_time = 0;
	thread_t thread;

	task_lock(task);
	gpu_time += task->task_gpu_ns;

	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		spl_t x;
		x = splsched();
		thread_lock(thread);
		gpu_time += ml_gpu_stat(thread);
		thread_unlock(thread);
		splx(x);
	}

	task_unlock(task);
	return gpu_time;
}

kern_return_t
task_purgable_info(
	task_t			task,
	task_purgable_info_t	*stats)
{
	if (task == TASK_NULL || stats == NULL)
		return KERN_INVALID_ARGUMENT;
	/* Take task reference */
	task_reference(task);
	vm_purgeable_stats((vm_purgeable_info_t)stats, task);
	/* Drop task reference */
	task_deallocate(task);
	return KERN_SUCCESS;
}

void
task_vtimer_set(
	task_t		task,
	integer_t	which)
{
	thread_t	thread;
	spl_t		x;

	/* assert(task == current_task()); */ /* bogus assert 4803227 4807483 */

	task_lock(task);

	task->vtimers |= which;

	switch (which) {

	case TASK_VTIMER_USER:
		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			x = splsched();
			thread_lock(thread);
			if (thread->precise_user_kernel_time)
				thread->vtimer_user_save = timer_grab(&thread->user_timer);
			else
				thread->vtimer_user_save = timer_grab(&thread->system_timer);
			thread_unlock(thread);
			splx(x);
		}
		break;

	case TASK_VTIMER_PROF:
		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			x = splsched();
			thread_lock(thread);
			thread->vtimer_prof_save = timer_grab(&thread->user_timer);
			thread->vtimer_prof_save += timer_grab(&thread->system_timer);
			thread_unlock(thread);
			splx(x);
		}
		break;

	case TASK_VTIMER_RLIM:
		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			x = splsched();
			thread_lock(thread);
			thread->vtimer_rlim_save = timer_grab(&thread->user_timer);
			thread->vtimer_rlim_save += timer_grab(&thread->system_timer);
			thread_unlock(thread);
			splx(x);
		}
		break;
	}

	task_unlock(task);
}

void
task_vtimer_clear(
	task_t		task,
	integer_t	which)
{
	assert(task == current_task());

	task_lock(task);

	task->vtimers &= ~which;

	task_unlock(task);
}

void
task_vtimer_update(
__unused
	task_t		task,
	integer_t	which,
	uint32_t	*microsecs)
{
	thread_t	thread = current_thread();
	uint32_t	tdelt;
	clock_sec_t	secs;
	uint64_t	tsum;

	assert(task == current_task());

	assert(task->vtimers & which);

	secs = tdelt = 0;

	switch (which) {

	case TASK_VTIMER_USER:
		if (thread->precise_user_kernel_time) {
			tdelt = (uint32_t)timer_delta(&thread->user_timer,
								&thread->vtimer_user_save);
		} else {
			tdelt = (uint32_t)timer_delta(&thread->system_timer,
								&thread->vtimer_user_save);
		}
		absolutetime_to_microtime(tdelt, &secs, microsecs);
		break;

	case TASK_VTIMER_PROF:
		tsum = timer_grab(&thread->user_timer);
		tsum += timer_grab(&thread->system_timer);
		tdelt = (uint32_t)(tsum - thread->vtimer_prof_save);
		absolutetime_to_microtime(tdelt, &secs, microsecs);
		/* if the time delta is smaller than a usec, ignore */
		if (*microsecs != 0)
			thread->vtimer_prof_save = tsum;
		break;

	case TASK_VTIMER_RLIM:
		tsum = timer_grab(&thread->user_timer);
		tsum += timer_grab(&thread->system_timer);
		tdelt = (uint32_t)(tsum - thread->vtimer_rlim_save);
		thread->vtimer_rlim_save = tsum;
		absolutetime_to_microtime(tdelt, &secs, microsecs);
		break;
	}

}

/*
 *	task_assign:
 *
 *	Change the assigned processor set for the task
 */
kern_return_t
task_assign(
	__unused task_t		task,
	__unused processor_set_t	new_pset,
	__unused boolean_t	assign_threads)
{
	return(KERN_FAILURE);
}

/*
 *	task_assign_default:
 *
 *	Version of task_assign to assign to default processor set.
 */
kern_return_t
task_assign_default(
	task_t		task,
	boolean_t	assign_threads)
{
    return (task_assign(task, &pset0, assign_threads));
}

/*
 *	task_get_assignment
 *
 *	Return name of processor set that task is assigned to.
 */
kern_return_t
task_get_assignment(
	task_t		task,
	processor_set_t	*pset)
{
	if (!task->active)
		return(KERN_FAILURE);

	*pset = &pset0;

	return (KERN_SUCCESS);
}

uint64_t
get_task_dispatchqueue_offset(
		task_t 		task)
{
	return task->dispatchqueue_offset;
}

/*
 * 	task_policy
 *
 *	Set scheduling policy and parameters, both base and limit, for
 *	the given task. Policy must be a policy which is enabled for the
 *	processor set. Change contained threads if requested. 
 */
kern_return_t
task_policy(
	__unused task_t			task,
	__unused policy_t			policy_id,
	__unused policy_base_t		base,
	__unused mach_msg_type_number_t	count,
	__unused boolean_t			set_limit,
	__unused boolean_t			change)
{
	return(KERN_FAILURE);
}

/*
 *	task_set_policy
 *
 *	Set scheduling policy and parameters, both base and limit, for 
 *	the given task. Policy can be any policy implemented by the
 *	processor set, whether enabled or not. Change contained threads
 *	if requested.
 */
kern_return_t
task_set_policy(
	__unused task_t			task,
	__unused processor_set_t		pset,
	__unused policy_t			policy_id,
	__unused policy_base_t		base,
	__unused mach_msg_type_number_t	base_count,
	__unused policy_limit_t		limit,
	__unused mach_msg_type_number_t	limit_count,
	__unused boolean_t			change)
{
	return(KERN_FAILURE);
}

kern_return_t
task_set_ras_pc(
 	__unused task_t	task,
 	__unused vm_offset_t	pc,
 	__unused vm_offset_t	endpc)
{
	return KERN_FAILURE;
}

void
task_synchronizer_destroy_all(task_t task)
{
	semaphore_t	semaphore;

	/*
	 *  Destroy owned semaphores
	 */

	while (!queue_empty(&task->semaphore_list)) {
		semaphore = (semaphore_t) queue_first(&task->semaphore_list);
		(void) semaphore_destroy_internal(task, semaphore);
	}
}

/*
 * Install default (machine-dependent) initial thread state 
 * on the task.  Subsequent thread creation will have this initial
 * state set on the thread by machine_thread_inherit_taskwide().
 * Flavors and structures are exactly the same as those to thread_set_state()
 */
kern_return_t 
task_set_state(
	task_t task, 
	int flavor, 
	thread_state_t state, 
	mach_msg_type_number_t state_count)
{
	kern_return_t ret;

	if (task == TASK_NULL) {
		return (KERN_INVALID_ARGUMENT);
	}

	task_lock(task);

	if (!task->active) {
		task_unlock(task);
		return (KERN_FAILURE);
	}

	ret = machine_task_set_state(task, flavor, state, state_count);

	task_unlock(task);
	return ret;
}

/*
 * Examine the default (machine-dependent) initial thread state 
 * on the task, as set by task_set_state().  Flavors and structures
 * are exactly the same as those passed to thread_get_state().
 */
kern_return_t 
task_get_state(
	task_t 	task, 
	int	flavor,
	thread_state_t state,
	mach_msg_type_number_t *state_count)
{
	kern_return_t ret;

	if (task == TASK_NULL) {
		return (KERN_INVALID_ARGUMENT);
	}

	task_lock(task);

	if (!task->active) {
		task_unlock(task);
		return (KERN_FAILURE);
	}

	ret = machine_task_get_state(task, flavor, state, state_count);

	task_unlock(task);
	return ret;
}

#if CONFIG_JETSAM
#define HWM_USERCORE_MINSPACE 250 // free space (in MB) required *after* core file creation

void __attribute__((noinline))
PROC_CROSSED_HIGH_WATERMARK__SEND_EXC_RESOURCE_AND_SUSPEND(int max_footprint_mb)
{
	task_t						task 		= current_task();
	int							pid         = 0;
	const char					*procname 	= "unknown";
	mach_exception_data_type_t	code[EXCEPTION_CODE_MAX];

#ifdef MACH_BSD
	pid = proc_selfpid();

	if (pid == 1) {
		/*
		 * Cannot have ReportCrash analyzing
		 * a suspended initproc.
		 */
		return;
	}

	if (task->bsd_info != NULL)
		procname = proc_name_address(current_task()->bsd_info);
#endif

	if (hwm_user_cores) {
		int				error;
		uint64_t		starttime, end;
		clock_sec_t		secs = 0;
		uint32_t		microsecs = 0;

		starttime = mach_absolute_time();
		/*
		 * Trigger a coredump of this process. Don't proceed unless we know we won't
		 * be filling up the disk; and ignore the core size resource limit for this
		 * core file.
		 */
		if ((error = coredump(current_task()->bsd_info, HWM_USERCORE_MINSPACE, COREDUMP_IGNORE_ULIMIT)) != 0) {
			printf("couldn't take coredump of %s[%d]: %d\n", procname, pid, error);
		}
		/*
		* coredump() leaves the task suspended.
		*/
		task_resume_internal(current_task());

		end = mach_absolute_time();
		absolutetime_to_microtime(end - starttime, &secs, &microsecs);
		printf("coredump of %s[%d] taken in %d secs %d microsecs\n",
		       proc_name_address(current_task()->bsd_info), pid, (int)secs, microsecs);
	}

	if (disable_exc_resource) {
		printf("process %s[%d] crossed memory high watermark (%d MB); EXC_RESOURCE "
			"supressed by a boot-arg.\n", procname, pid, max_footprint_mb);
		return;
	}

	/*
	 * A task that has triggered an EXC_RESOURCE, should not be
	 * jetsammed when the device is under memory pressure.  Here
	 * we set the P_MEMSTAT_TERMINATED flag so that the process
	 * will be skipped if the memorystatus_thread wakes up.
	 */
	proc_memstat_terminated(current_task()->bsd_info, TRUE);

	printf("process %s[%d] crossed memory high watermark (%d MB); sending "
		"EXC_RESOURCE.\n", procname, pid, max_footprint_mb);

	code[0] = code[1] = 0;
	EXC_RESOURCE_ENCODE_TYPE(code[0], RESOURCE_TYPE_MEMORY);
	EXC_RESOURCE_ENCODE_FLAVOR(code[0], FLAVOR_HIGH_WATERMARK);
	EXC_RESOURCE_HWM_ENCODE_LIMIT(code[0], max_footprint_mb);

	/*
	 * Use the _internal_ variant so that no user-space
	 * process can resume our task from under us.
	 */
	task_suspend_internal(task);
	exception_triage(EXC_RESOURCE, code, EXCEPTION_CODE_MAX);
	task_resume_internal(task);

	/*
	 * After the EXC_RESOURCE has been handled, we must clear the
	 * P_MEMSTAT_TERMINATED flag so that the process can again be
	 * considered for jetsam if the memorystatus_thread wakes up.
	 */
	proc_memstat_terminated(current_task()->bsd_info, FALSE);  /* clear the flag */
}

/*
 * Callback invoked when a task exceeds its physical footprint limit.
 */
void
task_footprint_exceeded(int warning, __unused const void *param0, __unused const void *param1)
{
	ledger_amount_t max_footprint, max_footprint_mb;
	ledger_amount_t footprint_after_purge;
	task_t task;

	if (warning == LEDGER_WARNING_DIPPED_BELOW) {
		/*
		 * Task memory limits only provide a warning on the way up.
		 */
		return;
	}

	task = current_task();

	ledger_get_limit(task->ledger, task_ledgers.phys_footprint, &max_footprint);
	max_footprint_mb = max_footprint >> 20;

	/*
	 * Try and purge all "volatile" memory in that task first.
	 */
	(void) task_purge_volatile_memory(task);
	/* are we still over the limit ? */
	ledger_get_balance(task->ledger,
			   task_ledgers.phys_footprint,
			   &footprint_after_purge);
	if ((!warning &&
	     footprint_after_purge <= max_footprint) ||
	    (warning &&
	     footprint_after_purge <= ((max_footprint *
					PHYS_FOOTPRINT_WARNING_LEVEL) / 100))) {
		/* all better now */
		ledger_reset_callback_state(task->ledger,
					    task_ledgers.phys_footprint);
		return;
	}
	/* still over the limit after purging... */

	/*
	 * If this an actual violation (not a warning),
	 * generate a non-fatal high watermark EXC_RESOURCE.
	 */
	if ((warning == 0) && (task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_PHYS_FOOTPRINT_EXCEPTION)) {
		PROC_CROSSED_HIGH_WATERMARK__SEND_EXC_RESOURCE_AND_SUSPEND((int)max_footprint_mb);
	}

	memorystatus_on_ledger_footprint_exceeded((warning == LEDGER_WARNING_ROSE_ABOVE) ? TRUE : FALSE,
		(int)max_footprint_mb);
}

extern int proc_check_footprint_priv(void);

kern_return_t
task_set_phys_footprint_limit(
	task_t task,
	int new_limit_mb,
	int *old_limit_mb)
{
	kern_return_t error;

	if ((error = proc_check_footprint_priv())) {
		return (KERN_NO_ACCESS);
	}

	return task_set_phys_footprint_limit_internal(task, new_limit_mb, old_limit_mb, FALSE);
}

kern_return_t
task_convert_phys_footprint_limit(
	int limit_mb,
	int *converted_limit_mb)
{
	if (limit_mb == -1) {
		/*
		 * No limit
		 */
		if (max_task_footprint != 0) {
			*converted_limit_mb = (int)(max_task_footprint / 1024 / 1024);   /* bytes to MB */
		} else {
			*converted_limit_mb = (int)(LEDGER_LIMIT_INFINITY >> 20);
		}
	} else {
		/* nothing to convert */
		*converted_limit_mb = limit_mb;
	}
	return (KERN_SUCCESS);
}


kern_return_t
task_set_phys_footprint_limit_internal(
	task_t task,
	int new_limit_mb,
	int *old_limit_mb,
	boolean_t trigger_exception)
{
	ledger_amount_t	old;

	ledger_get_limit(task->ledger, task_ledgers.phys_footprint, &old);
	
	if (old_limit_mb) {
		/* 
		 * Check that limit >> 20 will not give an "unexpected" 32-bit
		 * result. There are, however, implicit assumptions that -1 mb limit
		 * equates to LEDGER_LIMIT_INFINITY.
		 */
		assert(((old & 0xFFF0000000000000LL) == 0) || (old == LEDGER_LIMIT_INFINITY));
		*old_limit_mb = (int)(old >> 20);
	}

	if (new_limit_mb == -1) {
		/*
		 * Caller wishes to remove the limit.
		 */
		ledger_set_limit(task->ledger, task_ledgers.phys_footprint,
		                 max_task_footprint ? max_task_footprint : LEDGER_LIMIT_INFINITY,
		                 max_task_footprint ? PHYS_FOOTPRINT_WARNING_LEVEL : 0);
		return (KERN_SUCCESS);
	}

#ifdef CONFIG_NOMONITORS
	return (KERN_SUCCESS);
#endif /* CONFIG_NOMONITORS */

	task_lock(task);

	if (trigger_exception) {
		task->rusage_cpu_flags |= TASK_RUSECPU_FLAGS_PHYS_FOOTPRINT_EXCEPTION;
	} else {
		task->rusage_cpu_flags &= ~TASK_RUSECPU_FLAGS_PHYS_FOOTPRINT_EXCEPTION;
	}

	ledger_set_limit(task->ledger, task_ledgers.phys_footprint,
		(ledger_amount_t)new_limit_mb << 20, PHYS_FOOTPRINT_WARNING_LEVEL);

        if (task == current_task()) {
                ledger_check_new_balance(task->ledger, task_ledgers.phys_footprint);
        }

	task_unlock(task);

	return (KERN_SUCCESS);
}

kern_return_t
task_get_phys_footprint_limit(  	
	task_t task,
	int *limit_mb)
{
	ledger_amount_t	limit;
    
	ledger_get_limit(task->ledger, task_ledgers.phys_footprint, &limit);
	/* 
	 * Check that limit >> 20 will not give an "unexpected" signed, 32-bit
	 * result. There are, however, implicit assumptions that -1 mb limit
	 * equates to LEDGER_LIMIT_INFINITY.
	 */
	assert(((limit & 0xFFF0000000000000LL) == 0) || (limit == LEDGER_LIMIT_INFINITY));
	*limit_mb = (int)(limit >> 20);
	
	return (KERN_SUCCESS);
}
#else /* CONFIG_JETSAM */
kern_return_t
task_set_phys_footprint_limit(
	__unused task_t task,
	__unused int new_limit_mb,
	__unused int *old_limit_mb)
{
	return (KERN_FAILURE);
}

kern_return_t
task_get_phys_footprint_limit(  	
	__unused task_t task,
	__unused int *limit_mb)
{
	return (KERN_FAILURE);
}
#endif /* CONFIG_JETSAM */

/*
 * We need to export some functions to other components that
 * are currently implemented in macros within the osfmk
 * component.  Just export them as functions of the same name.
 */
boolean_t is_kerneltask(task_t t)
{
	if (t == kernel_task)
		return (TRUE);

	return (FALSE);
}

int
check_for_tasksuspend(task_t task)
{

	if (task == TASK_NULL)
		return (0);

	return (task->suspend_count > 0);
}

#undef current_task
task_t current_task(void);
task_t current_task(void)
{
	return (current_task_fast());
}

#undef task_reference
void task_reference(task_t task);
void
task_reference(
	task_t		task)
{
	if (task != TASK_NULL)
		task_reference_internal(task);
}

/* defined in bsd/kern/kern_prot.c */
extern int get_audit_token_pid(audit_token_t *audit_token);

int task_pid(task_t task)
{
	if (task)
		return get_audit_token_pid(&task->audit_token);
	return -1;
}


/* 
 * This routine is called always with task lock held.
 * And it returns a thread handle without reference as the caller
 * operates on it under the task lock held.
 */
thread_t
task_findtid(task_t task, uint64_t tid)
{
	thread_t thread= THREAD_NULL;

	queue_iterate(&task->threads, thread, thread_t, task_threads) {
			if (thread->thread_id == tid)
				return(thread);
	}
	return(THREAD_NULL);
}

/*
 * Control the CPU usage monitor for a task.
 */
kern_return_t
task_cpu_usage_monitor_ctl(task_t task, uint32_t *flags)
{
	int error = KERN_SUCCESS;

	if (*flags & CPUMON_MAKE_FATAL) {
		task->rusage_cpu_flags |= TASK_RUSECPU_FLAGS_FATAL_CPUMON;
	} else {
		error = KERN_INVALID_ARGUMENT;
	}

	return error;
}

/*
 * Control the wakeups monitor for a task.
 */
kern_return_t
task_wakeups_monitor_ctl(task_t task, uint32_t *flags, int32_t *rate_hz)
{
	ledger_t ledger = task->ledger;

	task_lock(task);
	if (*flags & WAKEMON_GET_PARAMS) {
		ledger_amount_t	limit;
		uint64_t		period;

		ledger_get_limit(ledger, task_ledgers.interrupt_wakeups, &limit);
		ledger_get_period(ledger, task_ledgers.interrupt_wakeups, &period);

		if (limit != LEDGER_LIMIT_INFINITY) {
			/*
			 * An active limit means the wakeups monitor is enabled.
			 */
			*rate_hz = (int32_t)(limit / (int64_t)(period / NSEC_PER_SEC));
			*flags = WAKEMON_ENABLE;
			if (task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_FATAL_WAKEUPSMON) {
				*flags |= WAKEMON_MAKE_FATAL;
			}
		} else {
			*flags = WAKEMON_DISABLE;
			*rate_hz = -1;
		}

		/*
		 * If WAKEMON_GET_PARAMS is present in flags, all other flags are ignored.
		 */
 		task_unlock(task);
		return KERN_SUCCESS;
	}

	if (*flags & WAKEMON_ENABLE) {
		if (*flags & WAKEMON_SET_DEFAULTS) {
			*rate_hz = task_wakeups_monitor_rate;
		}

#ifndef CONFIG_NOMONITORS
		if (*flags & WAKEMON_MAKE_FATAL) {
			task->rusage_cpu_flags |= TASK_RUSECPU_FLAGS_FATAL_WAKEUPSMON;
		}
#endif /* CONFIG_NOMONITORS */

		if (*rate_hz < 0) {
			task_unlock(task);
			return KERN_INVALID_ARGUMENT;
		}

#ifndef CONFIG_NOMONITORS
		ledger_set_limit(ledger, task_ledgers.interrupt_wakeups, *rate_hz * task_wakeups_monitor_interval,
			task_wakeups_monitor_ustackshots_trigger_pct);
		ledger_set_period(ledger, task_ledgers.interrupt_wakeups, task_wakeups_monitor_interval * NSEC_PER_SEC);
		ledger_enable_callback(ledger, task_ledgers.interrupt_wakeups);
#endif /* CONFIG_NOMONITORS */
	} else if (*flags & WAKEMON_DISABLE) {
		/*
		 * Caller wishes to disable wakeups monitor on the task.
		 *
		 * Disable telemetry if it was triggered by the wakeups monitor, and
		 * remove the limit & callback on the wakeups ledger entry.
		 */
#if CONFIG_TELEMETRY
		telemetry_task_ctl_locked(current_task(), TF_WAKEMON_WARNING, 0);
#endif
		ledger_disable_refill(ledger, task_ledgers.interrupt_wakeups);
		ledger_disable_callback(ledger, task_ledgers.interrupt_wakeups);
	}

	task_unlock(task);
	return KERN_SUCCESS;
}

void
task_wakeups_rate_exceeded(int warning, __unused const void *param0, __unused const void *param1)
{
	if (warning == LEDGER_WARNING_ROSE_ABOVE) {
#if CONFIG_TELEMETRY		
		/*
		 * This task is in danger of violating the wakeups monitor. Enable telemetry on this task
		 * so there are micro-stackshots available if and when EXC_RESOURCE is triggered.
		 */
		telemetry_task_ctl(current_task(), TF_WAKEMON_WARNING, 1);
#endif
		return;
	}

#if CONFIG_TELEMETRY
	/*
	 * If the balance has dipped below the warning level (LEDGER_WARNING_DIPPED_BELOW) or
	 * exceeded the limit, turn telemetry off for the task.
	 */
	telemetry_task_ctl(current_task(), TF_WAKEMON_WARNING, 0);
#endif

	if (warning == 0) {
		THIS_PROCESS_IS_CAUSING_TOO_MANY_WAKEUPS__SENDING_EXC_RESOURCE();
	}
}

void __attribute__((noinline))
THIS_PROCESS_IS_CAUSING_TOO_MANY_WAKEUPS__SENDING_EXC_RESOURCE(void)
{
	task_t						task 		= current_task();
	int							pid         = 0;
	const char					*procname 	= "unknown";
	uint64_t					observed_wakeups_rate;
	uint64_t					permitted_wakeups_rate;
	uint64_t					observation_interval;
	mach_exception_data_type_t	code[EXCEPTION_CODE_MAX];
	struct ledger_entry_info	lei;

#ifdef MACH_BSD
	pid = proc_selfpid();
	if (task->bsd_info != NULL)
		procname = proc_name_address(current_task()->bsd_info);
#endif

	ledger_get_entry_info(task->ledger, task_ledgers.interrupt_wakeups, &lei);

	/*
	 * Disable the exception notification so we don't overwhelm
	 * the listener with an endless stream of redundant exceptions.
	 */
	uint32_t flags = WAKEMON_DISABLE;
	task_wakeups_monitor_ctl(task, &flags, NULL);

	observed_wakeups_rate = (lei.lei_balance * (int64_t)NSEC_PER_SEC) / lei.lei_last_refill;
	permitted_wakeups_rate = lei.lei_limit / task_wakeups_monitor_interval;
	observation_interval = lei.lei_refill_period / NSEC_PER_SEC;

	if (disable_exc_resource) {
		printf("process %s[%d] caught causing excessive wakeups. EXC_RESOURCE "
			"supressed by a boot-arg\n", procname, pid);
		return;
	}
	if (audio_active) {
		printf("process %s[%d] caught causing excessive wakeups. EXC_RESOURCE "
		       "supressed due to audio playback\n", procname, pid);
		return;
	}
	printf("process %s[%d] caught causing excessive wakeups. Observed wakeups rate "
		"(per sec): %lld; Maximum permitted wakeups rate (per sec): %lld; Observation "
		"period: %lld seconds; Task lifetime number of wakeups: %lld\n",
		procname, pid, observed_wakeups_rate, permitted_wakeups_rate,
		observation_interval, lei.lei_credit);

	code[0] = code[1] = 0;
	EXC_RESOURCE_ENCODE_TYPE(code[0], RESOURCE_TYPE_WAKEUPS);
	EXC_RESOURCE_ENCODE_FLAVOR(code[0], FLAVOR_WAKEUPS_MONITOR);
	EXC_RESOURCE_CPUMONITOR_ENCODE_WAKEUPS_PERMITTED(code[0], task_wakeups_monitor_rate);
	EXC_RESOURCE_CPUMONITOR_ENCODE_OBSERVATION_INTERVAL(code[0], observation_interval);
	EXC_RESOURCE_CPUMONITOR_ENCODE_WAKEUPS_OBSERVED(code[1], lei.lei_balance * (int64_t)NSEC_PER_SEC / lei.lei_last_refill);	
	exception_triage(EXC_RESOURCE, code, EXCEPTION_CODE_MAX);

	if (task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_FATAL_WAKEUPSMON) {
		task_terminate_internal(task);
	}
}

kern_return_t
task_purge_volatile_memory(
	task_t	task)
{
	vm_map_t	map;
	int		num_object_purged;

	if (task == TASK_NULL)
		return KERN_INVALID_TASK;

	task_lock(task);

	if (!task->active) {
		task_unlock(task);
		return KERN_INVALID_TASK;
	}
	map = task->map;
	if (map == VM_MAP_NULL) {
		task_unlock(task);
		return KERN_INVALID_TASK;
	}
	vm_map_reference(task->map);

	task_unlock(task);

	num_object_purged = vm_map_purge(map);
	vm_map_deallocate(map);

	return KERN_SUCCESS;
}

/* Placeholders for the task set/get voucher interfaces */
kern_return_t 
task_get_mach_voucher(
	task_t			task,
	mach_voucher_selector_t __unused which,
	ipc_voucher_t		*voucher)
{
	if (TASK_NULL == task)
		return KERN_INVALID_TASK;

	*voucher = NULL;
	return KERN_SUCCESS;
}

kern_return_t 
task_set_mach_voucher(
	task_t			task,
	ipc_voucher_t		__unused voucher)
{
	if (TASK_NULL == task)
		return KERN_INVALID_TASK;

	return KERN_SUCCESS;
}

kern_return_t
task_swap_mach_voucher(
	task_t			task,
	ipc_voucher_t		new_voucher,
	ipc_voucher_t		*in_out_old_voucher)
{
	if (TASK_NULL == task)
		return KERN_INVALID_TASK;

	*in_out_old_voucher = new_voucher;
	return KERN_SUCCESS;
}

void task_set_gpu_denied(task_t task, boolean_t denied)
{
	task_lock(task);

	if (denied) {
		task->t_flags |= TF_GPU_DENIED;
	} else {
		task->t_flags &= ~TF_GPU_DENIED;
	}

	task_unlock(task);
}

boolean_t task_is_gpu_denied(task_t task)
{
	/* We don't need the lock to read this flag */
	return (task->t_flags & TF_GPU_DENIED) ? TRUE : FALSE;
}
