/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
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
#include <mach/task_inspect.h>
#include <mach/task_special_ports.h>
#include <mach/sdt.h>

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
#include <kern/sched_prim.h>    /* for thread_wakeup */
#include <kern/ipc_tt.h>
#include <kern/host.h>
#include <kern/clock.h>
#include <kern/timer.h>
#include <kern/assert.h>
#include <kern/sync_lock.h>
#include <kern/affinity.h>
#include <kern/exc_resource.h>
#include <kern/machine.h>
#include <kern/policy_internal.h>
#include <kern/restartable.h>

#include <corpses/task_corpse.h>
#if CONFIG_TELEMETRY
#include <kern/telemetry.h>
#endif

#if MONOTONIC
#include <kern/monotonic.h>
#include <machine/monotonic.h>
#endif /* MONOTONIC */

#include <os/log.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>         /* for kernel_map, ipc_kernel_map */
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>
#include <vm/vm_purgeable_internal.h>
#include <vm/vm_compressor_pager.h>

#include <sys/resource.h>
#include <sys/signalvar.h> /* for coredump */
#include <sys/bsdtask_info.h>
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
#include <libkern/section_keywords.h>

#include <mach-o/loader.h>

#if CONFIG_ATM
#include <atm/atm_internal.h>
#endif

#include <kern/sfi.h>           /* picks up ledger.h */

#if CONFIG_MACF
#include <security/mac_mach_internal.h>
#endif

#include <IOKit/IOBSD.h>

#if KPERF
extern int kpc_force_all_ctrs(task_t, int);
#endif

SECURITY_READ_ONLY_LATE(task_t) kernel_task;
SECURITY_READ_ONLY_LATE(zone_t) task_zone;
lck_attr_t      task_lck_attr;
lck_grp_t       task_lck_grp;
lck_grp_attr_t  task_lck_grp_attr;

extern int exc_via_corpse_forking;
extern int corpse_for_fatal_memkill;
extern boolean_t proc_send_synchronous_EXC_RESOURCE(void *p);

/* Flag set by core audio when audio is playing. Used to stifle EXC_RESOURCE generation when active. */
int audio_active = 0;

zinfo_usage_store_t tasks_tkm_private;
zinfo_usage_store_t tasks_tkm_shared;

/* A container to accumulate statistics for expired tasks */
expired_task_statistics_t               dead_task_statistics;
lck_spin_t              dead_task_statistics_lock;

ledger_template_t task_ledger_template = NULL;

SECURITY_READ_ONLY_LATE(struct _task_ledger_indices) task_ledgers __attribute__((used)) =
{.cpu_time = -1,
 .tkm_private = -1,
 .tkm_shared = -1,
 .phys_mem = -1,
 .wired_mem = -1,
 .internal = -1,
 .iokit_mapped = -1,
 .alternate_accounting = -1,
 .alternate_accounting_compressed = -1,
 .page_table = -1,
 .phys_footprint = -1,
 .internal_compressed = -1,
 .purgeable_volatile = -1,
 .purgeable_nonvolatile = -1,
 .purgeable_volatile_compressed = -1,
 .purgeable_nonvolatile_compressed = -1,
 .tagged_nofootprint = -1,
 .tagged_footprint = -1,
 .tagged_nofootprint_compressed = -1,
 .tagged_footprint_compressed = -1,
 .network_volatile = -1,
 .network_nonvolatile = -1,
 .network_volatile_compressed = -1,
 .network_nonvolatile_compressed = -1,
 .media_nofootprint = -1,
 .media_footprint = -1,
 .media_nofootprint_compressed = -1,
 .media_footprint_compressed = -1,
 .graphics_nofootprint = -1,
 .graphics_footprint = -1,
 .graphics_nofootprint_compressed = -1,
 .graphics_footprint_compressed = -1,
 .neural_nofootprint = -1,
 .neural_footprint = -1,
 .neural_nofootprint_compressed = -1,
 .neural_footprint_compressed = -1,
 .platform_idle_wakeups = -1,
 .interrupt_wakeups = -1,
#if !CONFIG_EMBEDDED
 .sfi_wait_times = { 0 /* initialized at runtime */},
#endif /* !CONFIG_EMBEDDED */
 .cpu_time_billed_to_me = -1,
 .cpu_time_billed_to_others = -1,
 .physical_writes = -1,
 .logical_writes = -1,
 .logical_writes_to_external = -1,
#if DEBUG || DEVELOPMENT
 .pages_grabbed = -1,
 .pages_grabbed_kern = -1,
 .pages_grabbed_iopl = -1,
 .pages_grabbed_upl = -1,
#endif
 .energy_billed_to_me = -1,
 .energy_billed_to_others = -1};

/* System sleep state */
boolean_t tasks_suspend_state;


void init_task_ledgers(void);
void task_footprint_exceeded(int warning, __unused const void *param0, __unused const void *param1);
void task_wakeups_rate_exceeded(int warning, __unused const void *param0, __unused const void *param1);
void task_io_rate_exceeded(int warning, const void *param0, __unused const void *param1);
void __attribute__((noinline)) SENDING_NOTIFICATION__THIS_PROCESS_IS_CAUSING_TOO_MANY_WAKEUPS(void);
void __attribute__((noinline)) PROC_CROSSED_HIGH_WATERMARK__SEND_EXC_RESOURCE_AND_SUSPEND(int max_footprint_mb, boolean_t is_fatal);
void __attribute__((noinline)) SENDING_NOTIFICATION__THIS_PROCESS_IS_CAUSING_TOO_MUCH_IO(int flavor);

kern_return_t task_suspend_internal(task_t);
kern_return_t task_resume_internal(task_t);
static kern_return_t task_start_halt_locked(task_t task, boolean_t should_mark_corpse);

extern kern_return_t iokit_task_terminate(task_t task);
extern void          iokit_task_app_suspended_changed(task_t task);

extern kern_return_t exception_deliver(thread_t, exception_type_t, mach_exception_data_t, mach_msg_type_number_t, struct exception_action *, lck_mtx_t *);
extern void bsd_copythreadname(void *dst_uth, void *src_uth);
extern kern_return_t thread_resume(thread_t thread);

// Warn tasks when they hit 80% of their memory limit.
#define PHYS_FOOTPRINT_WARNING_LEVEL 80

#define TASK_WAKEUPS_MONITOR_DEFAULT_LIMIT              150 /* wakeups per second */
#define TASK_WAKEUPS_MONITOR_DEFAULT_INTERVAL   300 /* in seconds. */

/*
 * Level (in terms of percentage of the limit) at which the wakeups monitor triggers telemetry.
 *
 * (ie when the task's wakeups rate exceeds 70% of the limit, start taking user
 *  stacktraces, aka micro-stackshots)
 */
#define TASK_WAKEUPS_MONITOR_DEFAULT_USTACKSHOTS_TRIGGER        70

int task_wakeups_monitor_interval; /* In seconds. Time period over which wakeups rate is observed */
int task_wakeups_monitor_rate;     /* In hz. Maximum allowable wakeups per task before EXC_RESOURCE is sent */

int task_wakeups_monitor_ustackshots_trigger_pct; /* Percentage. Level at which we start gathering telemetry. */

int disable_exc_resource; /* Global override to supress EXC_RESOURCE for resource monitor violations. */

ledger_amount_t max_task_footprint = 0;  /* Per-task limit on physical memory consumption in bytes     */
int max_task_footprint_warning_level = 0;  /* Per-task limit warning percentage */
int max_task_footprint_mb = 0;  /* Per-task limit on physical memory consumption in megabytes */

/* I/O Monitor Limits */
#define IOMON_DEFAULT_LIMIT                     (20480ull)      /* MB of logical/physical I/O */
#define IOMON_DEFAULT_INTERVAL                  (86400ull)      /* in seconds */

uint64_t task_iomon_limit_mb;           /* Per-task I/O monitor limit in MBs */
uint64_t task_iomon_interval_secs;      /* Per-task I/O monitor interval in secs */

#define IO_TELEMETRY_DEFAULT_LIMIT              (10ll * 1024ll * 1024ll)
int64_t io_telemetry_limit;                     /* Threshold to take a microstackshot (0 indicated I/O telemetry is turned off) */
int64_t global_logical_writes_count = 0;        /* Global count for logical writes */
int64_t global_logical_writes_to_external_count = 0;        /* Global count for logical writes to external storage*/
static boolean_t global_update_logical_writes(int64_t, int64_t*);

#define TASK_MAX_THREAD_LIMIT 256

#if MACH_ASSERT
int pmap_ledgers_panic = 1;
int pmap_ledgers_panic_leeway = 3;
#endif /* MACH_ASSERT */

int task_max = CONFIG_TASK_MAX; /* Max number of tasks */

#if CONFIG_COREDUMP
int hwm_user_cores = 0; /* high watermark violations generate user core files */
#endif

#ifdef MACH_BSD
extern uint32_t proc_platform(struct proc *);
extern uint32_t proc_sdk(struct proc *);
extern void     proc_getexecutableuuid(void *, unsigned char *, unsigned long);
extern int      proc_pid(struct proc *p);
extern int      proc_selfpid(void);
extern struct proc *current_proc(void);
extern char     *proc_name_address(struct proc *p);
extern uint64_t get_dispatchqueue_offset_from_proc(void *);
extern int kevent_proc_copy_uptrs(void *proc, uint64_t *buf, int bufsize);
extern void workq_proc_suspended(struct proc *p);
extern void workq_proc_resumed(struct proc *p);

#if CONFIG_MEMORYSTATUS
extern void     proc_memstat_terminated(struct proc* p, boolean_t set);
extern void     memorystatus_on_ledger_footprint_exceeded(int warning, boolean_t memlimit_is_active, boolean_t memlimit_is_fatal);
extern void     memorystatus_log_exception(const int max_footprint_mb, boolean_t memlimit_is_active, boolean_t memlimit_is_fatal);
extern boolean_t memorystatus_allowed_vm_map_fork(task_t task);
extern uint64_t  memorystatus_available_memory_internal(proc_t p);

#if DEVELOPMENT || DEBUG
extern void memorystatus_abort_vm_map_fork(task_t);
#endif

#endif /* CONFIG_MEMORYSTATUS */

#endif /* MACH_BSD */

#if DEVELOPMENT || DEBUG
int exc_resource_threads_enabled;
#endif /* DEVELOPMENT || DEBUG */

#if (DEVELOPMENT || DEBUG)
uint32_t task_exc_guard_default = TASK_EXC_GUARD_MP_DELIVER | TASK_EXC_GUARD_MP_ONCE | TASK_EXC_GUARD_MP_CORPSE |
    TASK_EXC_GUARD_VM_DELIVER | TASK_EXC_GUARD_VM_ONCE | TASK_EXC_GUARD_VM_CORPSE;
#else
uint32_t task_exc_guard_default = 0;
#endif

/* Forwards */

static void task_hold_locked(task_t task);
static void task_wait_locked(task_t task, boolean_t until_not_runnable);
static void task_release_locked(task_t task);

static void task_synchronizer_destroy_all(task_t task);
static os_ref_count_t
task_add_turnstile_watchports_locked(
	task_t                      task,
	struct task_watchports      *watchports,
	struct task_watchport_elem  **previous_elem_array,
	ipc_port_t                  *portwatch_ports,
	uint32_t                    portwatch_count);

static os_ref_count_t
task_remove_turnstile_watchports_locked(
	task_t                 task,
	struct task_watchports *watchports,
	ipc_port_t             *port_freelist);

static struct task_watchports *
task_watchports_alloc_init(
	task_t        task,
	thread_t      thread,
	uint32_t      count);

static void
task_watchports_deallocate(
	struct task_watchports *watchports);

void
task_set_64bit(
	task_t task,
	boolean_t is_64bit,
	boolean_t is_64bit_data)
{
#if defined(__i386__) || defined(__x86_64__) || defined(__arm64__)
	thread_t thread;
#endif /* defined(__i386__) || defined(__x86_64__) || defined(__arm64__) */

	task_lock(task);

	/*
	 * Switching to/from 64-bit address spaces
	 */
	if (is_64bit) {
		if (!task_has_64Bit_addr(task)) {
			task_set_64Bit_addr(task);
		}
	} else {
		if (task_has_64Bit_addr(task)) {
			task_clear_64Bit_addr(task);
		}
	}

	/*
	 * Switching to/from 64-bit register state.
	 */
	if (is_64bit_data) {
		if (task_has_64Bit_data(task)) {
			goto out;
		}

		task_set_64Bit_data(task);
	} else {
		if (!task_has_64Bit_data(task)) {
			goto out;
		}

		task_clear_64Bit_data(task);
	}

	/* FIXME: On x86, the thread save state flavor can diverge from the
	 * task's 64-bit feature flag due to the 32-bit/64-bit register save
	 * state dichotomy. Since we can be pre-empted in this interval,
	 * certain routines may observe the thread as being in an inconsistent
	 * state with respect to its task's 64-bitness.
	 */

#if defined(__x86_64__) || defined(__arm64__)
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		thread_mtx_lock(thread);
		machine_thread_switch_addrmode(thread);
		thread_mtx_unlock(thread);

#if defined(__arm64__)
		/* specifically, if running on H9 */
		if (thread == current_thread()) {
			uint64_t arg1, arg2;
			int urgency;
			spl_t spl = splsched();
			/*
			 * This call tell that the current thread changed it's 32bitness.
			 * Other thread were no more on core when 32bitness was changed,
			 * but current_thread() is on core and the previous call to
			 * machine_thread_going_on_core() gave 32bitness which is now wrong.
			 *
			 * This is needed for bring-up, a different callback should be used
			 * in the future.
			 *
			 * TODO: Remove this callout when we no longer support 32-bit code on H9
			 */
			thread_lock(thread);
			urgency = thread_get_urgency(thread, &arg1, &arg2);
			machine_thread_going_on_core(thread, urgency, 0, 0, mach_approximate_time());
			thread_unlock(thread);
			splx(spl);
		}
#endif /* defined(__arm64__) */
	}
#endif /* defined(__x86_64__) || defined(__arm64__) */

out:
	task_unlock(task);
}

boolean_t
task_get_64bit_data(task_t task)
{
	return task_has_64Bit_data(task);
}

void
task_set_platform_binary(
	task_t task,
	boolean_t is_platform)
{
	task_lock(task);
	if (is_platform) {
		task->t_flags |= TF_PLATFORM;
		/* set exc guard default behavior for first-party code */
		task->task_exc_guard = (task_exc_guard_default & TASK_EXC_GUARD_ALL);
	} else {
		task->t_flags &= ~(TF_PLATFORM);
		/* set exc guard default behavior for third-party code */
		task->task_exc_guard = ((task_exc_guard_default >> TASK_EXC_GUARD_THIRD_PARTY_DEFAULT_SHIFT) & TASK_EXC_GUARD_ALL);
	}
	task_unlock(task);
}

/*
 * Set or clear per-task TF_CA_CLIENT_WI flag according to specified argument.
 * Returns "false" if flag is already set, and "true" in other cases.
 */
bool
task_set_ca_client_wi(
	task_t task,
	boolean_t set_or_clear)
{
	bool ret = true;
	task_lock(task);
	if (set_or_clear) {
		/* Tasks can have only one CA_CLIENT work interval */
		if (task->t_flags & TF_CA_CLIENT_WI) {
			ret = false;
		} else {
			task->t_flags |= TF_CA_CLIENT_WI;
		}
	} else {
		task->t_flags &= ~TF_CA_CLIENT_WI;
	}
	task_unlock(task);
	return ret;
}

void
task_set_dyld_info(
	task_t task,
	mach_vm_address_t addr,
	mach_vm_size_t size)
{
	task_lock(task);
	task->all_image_info_addr = addr;
	task->all_image_info_size = size;
	task_unlock(task);
}

void
task_set_mach_header_address(
	task_t task,
	mach_vm_address_t addr)
{
	task_lock(task);
	task->mach_header_vm_address = addr;
	task_unlock(task);
}

void
task_atm_reset(__unused task_t task)
{
#if CONFIG_ATM
	if (task->atm_context != NULL) {
		atm_task_descriptor_destroy(task->atm_context);
		task->atm_context = NULL;
	}
#endif
}

void
task_bank_reset(__unused task_t task)
{
	if (task->bank_context != NULL) {
		bank_task_destroy(task);
	}
}

/*
 * NOTE: This should only be called when the P_LINTRANSIT
 *	 flag is set (the proc_trans lock is held) on the
 *	 proc associated with the task.
 */
void
task_bank_init(__unused task_t task)
{
	if (task->bank_context != NULL) {
		panic("Task bank init called with non null bank context for task: %p and bank_context: %p", task, task->bank_context);
	}
	bank_task_initialize(task);
}

void
task_set_did_exec_flag(task_t task)
{
	task->t_procflags |= TPF_DID_EXEC;
}

void
task_clear_exec_copy_flag(task_t task)
{
	task->t_procflags &= ~TPF_EXEC_COPY;
}

event_t
task_get_return_wait_event(task_t task)
{
	return (event_t)&task->returnwait_inheritor;
}

void
task_clear_return_wait(task_t task, uint32_t flags)
{
	if (flags & TCRW_CLEAR_INITIAL_WAIT) {
		thread_wakeup(task_get_return_wait_event(task));
	}

	if (flags & TCRW_CLEAR_FINAL_WAIT) {
		is_write_lock(task->itk_space);

		task->t_returnwaitflags &= ~TRW_LRETURNWAIT;
		task->returnwait_inheritor = NULL;

		if (task->t_returnwaitflags & TRW_LRETURNWAITER) {
			struct turnstile *turnstile = turnstile_prepare((uintptr_t) task_get_return_wait_event(task),
			    NULL, TURNSTILE_NULL, TURNSTILE_ULOCK);

			waitq_wakeup64_all(&turnstile->ts_waitq,
			    CAST_EVENT64_T(task_get_return_wait_event(task)),
			    THREAD_AWAKENED, 0);

			turnstile_update_inheritor(turnstile, NULL,
			    TURNSTILE_IMMEDIATE_UPDATE | TURNSTILE_INHERITOR_THREAD);
			turnstile_update_inheritor_complete(turnstile, TURNSTILE_INTERLOCK_HELD);

			turnstile_complete((uintptr_t) task_get_return_wait_event(task), NULL, NULL, TURNSTILE_ULOCK);
			turnstile_cleanup();
			task->t_returnwaitflags &= ~TRW_LRETURNWAITER;
		}
		is_write_unlock(task->itk_space);
	}
}

void __attribute__((noreturn))
task_wait_to_return(void)
{
	task_t task = current_task();

	is_write_lock(task->itk_space);

	if (task->t_returnwaitflags & TRW_LRETURNWAIT) {
		struct turnstile *turnstile = turnstile_prepare((uintptr_t) task_get_return_wait_event(task),
		    NULL, TURNSTILE_NULL, TURNSTILE_ULOCK);

		do {
			task->t_returnwaitflags |= TRW_LRETURNWAITER;
			turnstile_update_inheritor(turnstile, task->returnwait_inheritor,
			    (TURNSTILE_DELAYED_UPDATE | TURNSTILE_INHERITOR_THREAD));

			waitq_assert_wait64(&turnstile->ts_waitq,
			    CAST_EVENT64_T(task_get_return_wait_event(task)),
			    THREAD_UNINT, TIMEOUT_WAIT_FOREVER);

			is_write_unlock(task->itk_space);

			turnstile_update_inheritor_complete(turnstile, TURNSTILE_INTERLOCK_NOT_HELD);

			thread_block(THREAD_CONTINUE_NULL);

			is_write_lock(task->itk_space);
		} while (task->t_returnwaitflags & TRW_LRETURNWAIT);

		turnstile_complete((uintptr_t) task_get_return_wait_event(task), NULL, NULL, TURNSTILE_ULOCK);
	}

	is_write_unlock(task->itk_space);
	turnstile_cleanup();


#if CONFIG_MACF
	/*
	 * Before jumping to userspace and allowing this process to execute any code,
	 * notify any interested parties.
	 */
	mac_proc_notify_exec_complete(current_proc());
#endif

	thread_bootstrap_return();
}

#ifdef CONFIG_32BIT_TELEMETRY
boolean_t
task_consume_32bit_log_flag(task_t task)
{
	if ((task->t_procflags & TPF_LOG_32BIT_TELEMETRY) != 0) {
		task->t_procflags &= ~TPF_LOG_32BIT_TELEMETRY;
		return TRUE;
	} else {
		return FALSE;
	}
}

void
task_set_32bit_log_flag(task_t task)
{
	task->t_procflags |= TPF_LOG_32BIT_TELEMETRY;
}
#endif /* CONFIG_32BIT_TELEMETRY */

boolean_t
task_is_exec_copy(task_t task)
{
	return task_is_exec_copy_internal(task);
}

boolean_t
task_did_exec(task_t task)
{
	return task_did_exec_internal(task);
}

boolean_t
task_is_active(task_t task)
{
	return task->active;
}

boolean_t
task_is_halting(task_t task)
{
	return task->halting;
}

#if TASK_REFERENCE_LEAK_DEBUG
#include <kern/btlog.h>

static btlog_t *task_ref_btlog;
#define TASK_REF_OP_INCR        0x1
#define TASK_REF_OP_DECR        0x2

#define TASK_REF_NUM_RECORDS    100000
#define TASK_REF_BTDEPTH        7

void
task_reference_internal(task_t task)
{
	void *       bt[TASK_REF_BTDEPTH];
	int             numsaved = 0;

	zone_require(task, task_zone);
	os_ref_retain(&task->ref_count);

	numsaved = OSBacktrace(bt, TASK_REF_BTDEPTH);
	btlog_add_entry(task_ref_btlog, task, TASK_REF_OP_INCR,
	    bt, numsaved);
}

os_ref_count_t
task_deallocate_internal(task_t task)
{
	void *       bt[TASK_REF_BTDEPTH];
	int             numsaved = 0;

	numsaved = OSBacktrace(bt, TASK_REF_BTDEPTH);
	btlog_add_entry(task_ref_btlog, task, TASK_REF_OP_DECR,
	    bt, numsaved);

	return os_ref_release(&task->ref_count);
}

#endif /* TASK_REFERENCE_LEAK_DEBUG */

void
task_init(void)
{
	lck_grp_attr_setdefault(&task_lck_grp_attr);
	lck_grp_init(&task_lck_grp, "task", &task_lck_grp_attr);
	lck_attr_setdefault(&task_lck_attr);
	lck_mtx_init(&tasks_threads_lock, &task_lck_grp, &task_lck_attr);
	lck_mtx_init(&tasks_corpse_lock, &task_lck_grp, &task_lck_attr);

	task_zone = zinit(
		sizeof(struct task),
		task_max * sizeof(struct task),
		TASK_CHUNK * sizeof(struct task),
		"tasks");

	zone_change(task_zone, Z_NOENCRYPT, TRUE);

#if CONFIG_EMBEDDED
	task_watch_init();
#endif /* CONFIG_EMBEDDED */

	/*
	 * Configure per-task memory limit.
	 * The boot-arg is interpreted as Megabytes,
	 * and takes precedence over the device tree.
	 * Setting the boot-arg to 0 disables task limits.
	 */
	if (!PE_parse_boot_argn("max_task_pmem", &max_task_footprint_mb,
	    sizeof(max_task_footprint_mb))) {
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
#if CONFIG_MEMORYSTATUS
		if (max_task_footprint_mb < 50) {
			printf("Warning: max_task_pmem %d below minimum.\n",
			    max_task_footprint_mb);
			max_task_footprint_mb = 50;
		}
		printf("Limiting task physical memory footprint to %d MB\n",
		    max_task_footprint_mb);

		max_task_footprint = (ledger_amount_t)max_task_footprint_mb * 1024 * 1024; // Convert MB to bytes

		/*
		 * Configure the per-task memory limit warning level.
		 * This is computed as a percentage.
		 */
		max_task_footprint_warning_level = 0;

		if (max_mem < 0x40000000) {
			/*
			 * On devices with < 1GB of memory:
			 *    -- set warnings to 50MB below the per-task limit.
			 */
			if (max_task_footprint_mb > 50) {
				max_task_footprint_warning_level = ((max_task_footprint_mb - 50) * 100) / max_task_footprint_mb;
			}
		} else {
			/*
			 * On devices with >= 1GB of memory:
			 *    -- set warnings to 100MB below the per-task limit.
			 */
			if (max_task_footprint_mb > 100) {
				max_task_footprint_warning_level = ((max_task_footprint_mb - 100) * 100) / max_task_footprint_mb;
			}
		}

		/*
		 * Never allow warning level to land below the default.
		 */
		if (max_task_footprint_warning_level < PHYS_FOOTPRINT_WARNING_LEVEL) {
			max_task_footprint_warning_level = PHYS_FOOTPRINT_WARNING_LEVEL;
		}

		printf("Limiting task physical memory warning to %d%%\n", max_task_footprint_warning_level);

#else
		printf("Warning: max_task_pmem specified, but jetsam not configured; ignoring.\n");
#endif /* CONFIG_MEMORYSTATUS */
	}

#if DEVELOPMENT || DEBUG
	if (!PE_parse_boot_argn("exc_resource_threads",
	    &exc_resource_threads_enabled,
	    sizeof(exc_resource_threads_enabled))) {
		exc_resource_threads_enabled = 1;
	}
	PE_parse_boot_argn("task_exc_guard_default",
	    &task_exc_guard_default,
	    sizeof(task_exc_guard_default));
#endif /* DEVELOPMENT || DEBUG */

#if CONFIG_COREDUMP
	if (!PE_parse_boot_argn("hwm_user_cores", &hwm_user_cores,
	    sizeof(hwm_user_cores))) {
		hwm_user_cores = 0;
	}
#endif

	proc_init_cpumon_params();

	if (!PE_parse_boot_argn("task_wakeups_monitor_rate", &task_wakeups_monitor_rate, sizeof(task_wakeups_monitor_rate))) {
		task_wakeups_monitor_rate = TASK_WAKEUPS_MONITOR_DEFAULT_LIMIT;
	}

	if (!PE_parse_boot_argn("task_wakeups_monitor_interval", &task_wakeups_monitor_interval, sizeof(task_wakeups_monitor_interval))) {
		task_wakeups_monitor_interval = TASK_WAKEUPS_MONITOR_DEFAULT_INTERVAL;
	}

	if (!PE_parse_boot_argn("task_wakeups_monitor_ustackshots_trigger_pct", &task_wakeups_monitor_ustackshots_trigger_pct,
	    sizeof(task_wakeups_monitor_ustackshots_trigger_pct))) {
		task_wakeups_monitor_ustackshots_trigger_pct = TASK_WAKEUPS_MONITOR_DEFAULT_USTACKSHOTS_TRIGGER;
	}

	if (!PE_parse_boot_argn("disable_exc_resource", &disable_exc_resource,
	    sizeof(disable_exc_resource))) {
		disable_exc_resource = 0;
	}

	if (!PE_parse_boot_argn("task_iomon_limit_mb", &task_iomon_limit_mb, sizeof(task_iomon_limit_mb))) {
		task_iomon_limit_mb = IOMON_DEFAULT_LIMIT;
	}

	if (!PE_parse_boot_argn("task_iomon_interval_secs", &task_iomon_interval_secs, sizeof(task_iomon_interval_secs))) {
		task_iomon_interval_secs = IOMON_DEFAULT_INTERVAL;
	}

	if (!PE_parse_boot_argn("io_telemetry_limit", &io_telemetry_limit, sizeof(io_telemetry_limit))) {
		io_telemetry_limit = IO_TELEMETRY_DEFAULT_LIMIT;
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
	task_ref_btlog = btlog_create(TASK_REF_NUM_RECORDS, TASK_REF_BTDEPTH, TRUE /* caller_will_remove_entries_for_element? */);
	assert(task_ref_btlog);
#endif

	/*
	 * Create the kernel task as the first task.
	 */
#ifdef __LP64__
	if (task_create_internal(TASK_NULL, NULL, FALSE, TRUE, TRUE, TF_NONE, TPF_NONE, TWF_NONE, &kernel_task) != KERN_SUCCESS)
#else
	if (task_create_internal(TASK_NULL, NULL, FALSE, FALSE, FALSE, TF_NONE, TPF_NONE, TWF_NONE, &kernel_task) != KERN_SUCCESS)
#endif
	{ panic("task_init\n");}

#if defined(HAS_APPLE_PAC)
	kernel_task->rop_pid = KERNEL_ROP_ID;
	// kernel_task never runs at EL0, but machine_thread_state_convert_from/to_user() relies on
	// disable_user_jop to be false for kernel threads (e.g. in exception delivery on thread_exception_daemon)
	ml_task_set_disable_user_jop(kernel_task, FALSE);
#endif

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
	__unused task_t         parent_task,
	__unused vm_offset_t            map_base,
	__unused vm_size_t              map_size,
	__unused task_t         *child_task)
{
	return KERN_INVALID_ARGUMENT;
}

kern_return_t
task_create(
	task_t                          parent_task,
	__unused ledger_port_array_t    ledger_ports,
	__unused mach_msg_type_number_t num_ledger_ports,
	__unused boolean_t              inherit_memory,
	__unused task_t                 *child_task)    /* OUT */
{
	if (parent_task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * No longer supported: too many calls assume that a task has a valid
	 * process attached.
	 */
	return KERN_FAILURE;
}

kern_return_t
host_security_create_task_token(
	host_security_t                 host_security,
	task_t                          parent_task,
	__unused security_token_t       sec_token,
	__unused audit_token_t          audit_token,
	__unused host_priv_t            host_priv,
	__unused ledger_port_array_t    ledger_ports,
	__unused mach_msg_type_number_t num_ledger_ports,
	__unused boolean_t              inherit_memory,
	__unused task_t                 *child_task)    /* OUT */
{
	if (parent_task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (host_security == HOST_NULL) {
		return KERN_INVALID_SECURITY;
	}

	/*
	 * No longer supported.
	 */
	return KERN_FAILURE;
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
 *     + page_table
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
 *    clean/dirty or internal/external state].
 *
 * alternate_accounting
 *   The number of internal dirty pages which are part of IOKit mappings. By definition, these pages
 *   are counted in both internal *and* iokit_mapped, so we must subtract them from the total to avoid
 *   double counting.
 *
 * pages_grabbed
 *   pages_grabbed counts all page grabs in a task.  It is also broken out into three subtypes
 *   which track UPL, IOPL and Kernel page grabs.
 */
void
init_task_ledgers(void)
{
	ledger_template_t t;

	assert(task_ledger_template == NULL);
	assert(kernel_task == TASK_NULL);

#if MACH_ASSERT
	PE_parse_boot_argn("pmap_ledgers_panic",
	    &pmap_ledgers_panic,
	    sizeof(pmap_ledgers_panic));
	PE_parse_boot_argn("pmap_ledgers_panic_leeway",
	    &pmap_ledgers_panic_leeway,
	    sizeof(pmap_ledgers_panic_leeway));
#endif /* MACH_ASSERT */

	if ((t = ledger_template_create("Per-task ledger")) == NULL) {
		panic("couldn't create task ledger template");
	}

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
	task_ledgers.page_table = ledger_entry_add(t, "page_table", "physmem",
	    "bytes");
	task_ledgers.phys_footprint = ledger_entry_add(t, "phys_footprint", "physmem",
	    "bytes");
	task_ledgers.internal_compressed = ledger_entry_add(t, "internal_compressed", "physmem",
	    "bytes");
	task_ledgers.purgeable_volatile = ledger_entry_add(t, "purgeable_volatile", "physmem", "bytes");
	task_ledgers.purgeable_nonvolatile = ledger_entry_add(t, "purgeable_nonvolatile", "physmem", "bytes");
	task_ledgers.purgeable_volatile_compressed = ledger_entry_add(t, "purgeable_volatile_compress", "physmem", "bytes");
	task_ledgers.purgeable_nonvolatile_compressed = ledger_entry_add(t, "purgeable_nonvolatile_compress", "physmem", "bytes");
#if DEBUG || DEVELOPMENT
	task_ledgers.pages_grabbed = ledger_entry_add(t, "pages_grabbed", "physmem", "count");
	task_ledgers.pages_grabbed_kern = ledger_entry_add(t, "pages_grabbed_kern", "physmem", "count");
	task_ledgers.pages_grabbed_iopl = ledger_entry_add(t, "pages_grabbed_iopl", "physmem", "count");
	task_ledgers.pages_grabbed_upl = ledger_entry_add(t, "pages_grabbed_upl", "physmem", "count");
#endif
	task_ledgers.tagged_nofootprint = ledger_entry_add(t, "tagged_nofootprint", "physmem", "bytes");
	task_ledgers.tagged_footprint = ledger_entry_add(t, "tagged_footprint", "physmem", "bytes");
	task_ledgers.tagged_nofootprint_compressed = ledger_entry_add(t, "tagged_nofootprint_compressed", "physmem", "bytes");
	task_ledgers.tagged_footprint_compressed = ledger_entry_add(t, "tagged_footprint_compressed", "physmem", "bytes");
	task_ledgers.network_volatile = ledger_entry_add(t, "network_volatile", "physmem", "bytes");
	task_ledgers.network_nonvolatile = ledger_entry_add(t, "network_nonvolatile", "physmem", "bytes");
	task_ledgers.network_volatile_compressed = ledger_entry_add(t, "network_volatile_compressed", "physmem", "bytes");
	task_ledgers.network_nonvolatile_compressed = ledger_entry_add(t, "network_nonvolatile_compressed", "physmem", "bytes");
	task_ledgers.media_nofootprint = ledger_entry_add(t, "media_nofootprint", "physmem", "bytes");
	task_ledgers.media_footprint = ledger_entry_add(t, "media_footprint", "physmem", "bytes");
	task_ledgers.media_nofootprint_compressed = ledger_entry_add(t, "media_nofootprint_compressed", "physmem", "bytes");
	task_ledgers.media_footprint_compressed = ledger_entry_add(t, "media_footprint_compressed", "physmem", "bytes");
	task_ledgers.graphics_nofootprint = ledger_entry_add(t, "graphics_nofootprint", "physmem", "bytes");
	task_ledgers.graphics_footprint = ledger_entry_add(t, "graphics_footprint", "physmem", "bytes");
	task_ledgers.graphics_nofootprint_compressed = ledger_entry_add(t, "graphics_nofootprint_compressed", "physmem", "bytes");
	task_ledgers.graphics_footprint_compressed = ledger_entry_add(t, "graphics_footprint_compressed", "physmem", "bytes");
	task_ledgers.neural_nofootprint = ledger_entry_add(t, "neural_nofootprint", "physmem", "bytes");
	task_ledgers.neural_footprint = ledger_entry_add(t, "neural_footprint", "physmem", "bytes");
	task_ledgers.neural_nofootprint_compressed = ledger_entry_add(t, "neural_nofootprint_compressed", "physmem", "bytes");
	task_ledgers.neural_footprint_compressed = ledger_entry_add(t, "neural_footprint_compressed", "physmem", "bytes");


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

	assert(task_ledgers.sfi_wait_times[MAX_SFI_CLASS_ID - 1] != -1);
#endif /* CONFIG_SCHED_SFI */

	task_ledgers.cpu_time_billed_to_me = ledger_entry_add(t, "cpu_time_billed_to_me", "sched", "ns");
	task_ledgers.cpu_time_billed_to_others = ledger_entry_add(t, "cpu_time_billed_to_others", "sched", "ns");
	task_ledgers.physical_writes = ledger_entry_add(t, "physical_writes", "res", "bytes");
	task_ledgers.logical_writes = ledger_entry_add(t, "logical_writes", "res", "bytes");
	task_ledgers.logical_writes_to_external = ledger_entry_add(t, "logical_writes_to_external", "res", "bytes");
	task_ledgers.energy_billed_to_me = ledger_entry_add(t, "energy_billed_to_me", "power", "nj");
	task_ledgers.energy_billed_to_others = ledger_entry_add(t, "energy_billed_to_others", "power", "nj");

	if ((task_ledgers.cpu_time < 0) ||
	    (task_ledgers.tkm_private < 0) ||
	    (task_ledgers.tkm_shared < 0) ||
	    (task_ledgers.phys_mem < 0) ||
	    (task_ledgers.wired_mem < 0) ||
	    (task_ledgers.internal < 0) ||
	    (task_ledgers.iokit_mapped < 0) ||
	    (task_ledgers.alternate_accounting < 0) ||
	    (task_ledgers.alternate_accounting_compressed < 0) ||
	    (task_ledgers.page_table < 0) ||
	    (task_ledgers.phys_footprint < 0) ||
	    (task_ledgers.internal_compressed < 0) ||
	    (task_ledgers.purgeable_volatile < 0) ||
	    (task_ledgers.purgeable_nonvolatile < 0) ||
	    (task_ledgers.purgeable_volatile_compressed < 0) ||
	    (task_ledgers.purgeable_nonvolatile_compressed < 0) ||
	    (task_ledgers.tagged_nofootprint < 0) ||
	    (task_ledgers.tagged_footprint < 0) ||
	    (task_ledgers.tagged_nofootprint_compressed < 0) ||
	    (task_ledgers.tagged_footprint_compressed < 0) ||
	    (task_ledgers.network_volatile < 0) ||
	    (task_ledgers.network_nonvolatile < 0) ||
	    (task_ledgers.network_volatile_compressed < 0) ||
	    (task_ledgers.network_nonvolatile_compressed < 0) ||
	    (task_ledgers.media_nofootprint < 0) ||
	    (task_ledgers.media_footprint < 0) ||
	    (task_ledgers.media_nofootprint_compressed < 0) ||
	    (task_ledgers.media_footprint_compressed < 0) ||
	    (task_ledgers.graphics_nofootprint < 0) ||
	    (task_ledgers.graphics_footprint < 0) ||
	    (task_ledgers.graphics_nofootprint_compressed < 0) ||
	    (task_ledgers.graphics_footprint_compressed < 0) ||
	    (task_ledgers.neural_nofootprint < 0) ||
	    (task_ledgers.neural_footprint < 0) ||
	    (task_ledgers.neural_nofootprint_compressed < 0) ||
	    (task_ledgers.neural_footprint_compressed < 0) ||
	    (task_ledgers.platform_idle_wakeups < 0) ||
	    (task_ledgers.interrupt_wakeups < 0) ||
	    (task_ledgers.cpu_time_billed_to_me < 0) || (task_ledgers.cpu_time_billed_to_others < 0) ||
	    (task_ledgers.physical_writes < 0) ||
	    (task_ledgers.logical_writes < 0) ||
	    (task_ledgers.logical_writes_to_external < 0) ||
	    (task_ledgers.energy_billed_to_me < 0) ||
	    (task_ledgers.energy_billed_to_others < 0)
	    ) {
		panic("couldn't create entries for task ledger template");
	}

	ledger_track_credit_only(t, task_ledgers.phys_footprint);
	ledger_track_credit_only(t, task_ledgers.page_table);
	ledger_track_credit_only(t, task_ledgers.internal);
	ledger_track_credit_only(t, task_ledgers.internal_compressed);
	ledger_track_credit_only(t, task_ledgers.iokit_mapped);
	ledger_track_credit_only(t, task_ledgers.alternate_accounting);
	ledger_track_credit_only(t, task_ledgers.alternate_accounting_compressed);
	ledger_track_credit_only(t, task_ledgers.purgeable_volatile);
	ledger_track_credit_only(t, task_ledgers.purgeable_nonvolatile);
	ledger_track_credit_only(t, task_ledgers.purgeable_volatile_compressed);
	ledger_track_credit_only(t, task_ledgers.purgeable_nonvolatile_compressed);
#if DEBUG || DEVELOPMENT
	ledger_track_credit_only(t, task_ledgers.pages_grabbed);
	ledger_track_credit_only(t, task_ledgers.pages_grabbed_kern);
	ledger_track_credit_only(t, task_ledgers.pages_grabbed_iopl);
	ledger_track_credit_only(t, task_ledgers.pages_grabbed_upl);
#endif
	ledger_track_credit_only(t, task_ledgers.tagged_nofootprint);
	ledger_track_credit_only(t, task_ledgers.tagged_footprint);
	ledger_track_credit_only(t, task_ledgers.tagged_nofootprint_compressed);
	ledger_track_credit_only(t, task_ledgers.tagged_footprint_compressed);
	ledger_track_credit_only(t, task_ledgers.network_volatile);
	ledger_track_credit_only(t, task_ledgers.network_nonvolatile);
	ledger_track_credit_only(t, task_ledgers.network_volatile_compressed);
	ledger_track_credit_only(t, task_ledgers.network_nonvolatile_compressed);
	ledger_track_credit_only(t, task_ledgers.media_nofootprint);
	ledger_track_credit_only(t, task_ledgers.media_footprint);
	ledger_track_credit_only(t, task_ledgers.media_nofootprint_compressed);
	ledger_track_credit_only(t, task_ledgers.media_footprint_compressed);
	ledger_track_credit_only(t, task_ledgers.graphics_nofootprint);
	ledger_track_credit_only(t, task_ledgers.graphics_footprint);
	ledger_track_credit_only(t, task_ledgers.graphics_nofootprint_compressed);
	ledger_track_credit_only(t, task_ledgers.graphics_footprint_compressed);
	ledger_track_credit_only(t, task_ledgers.neural_nofootprint);
	ledger_track_credit_only(t, task_ledgers.neural_footprint);
	ledger_track_credit_only(t, task_ledgers.neural_nofootprint_compressed);
	ledger_track_credit_only(t, task_ledgers.neural_footprint_compressed);

	ledger_track_maximum(t, task_ledgers.phys_footprint, 60);
#if MACH_ASSERT
	if (pmap_ledgers_panic) {
		ledger_panic_on_negative(t, task_ledgers.phys_footprint);
		ledger_panic_on_negative(t, task_ledgers.page_table);
		ledger_panic_on_negative(t, task_ledgers.internal);
		ledger_panic_on_negative(t, task_ledgers.internal_compressed);
		ledger_panic_on_negative(t, task_ledgers.iokit_mapped);
		ledger_panic_on_negative(t, task_ledgers.alternate_accounting);
		ledger_panic_on_negative(t, task_ledgers.alternate_accounting_compressed);
		ledger_panic_on_negative(t, task_ledgers.purgeable_volatile);
		ledger_panic_on_negative(t, task_ledgers.purgeable_nonvolatile);
		ledger_panic_on_negative(t, task_ledgers.purgeable_volatile_compressed);
		ledger_panic_on_negative(t, task_ledgers.purgeable_nonvolatile_compressed);

		ledger_panic_on_negative(t, task_ledgers.tagged_nofootprint);
		ledger_panic_on_negative(t, task_ledgers.tagged_footprint);
		ledger_panic_on_negative(t, task_ledgers.tagged_nofootprint_compressed);
		ledger_panic_on_negative(t, task_ledgers.tagged_footprint_compressed);
		ledger_panic_on_negative(t, task_ledgers.network_volatile);
		ledger_panic_on_negative(t, task_ledgers.network_nonvolatile);
		ledger_panic_on_negative(t, task_ledgers.network_volatile_compressed);
		ledger_panic_on_negative(t, task_ledgers.network_nonvolatile_compressed);
		ledger_panic_on_negative(t, task_ledgers.media_nofootprint);
		ledger_panic_on_negative(t, task_ledgers.media_footprint);
		ledger_panic_on_negative(t, task_ledgers.media_nofootprint_compressed);
		ledger_panic_on_negative(t, task_ledgers.media_footprint_compressed);
		ledger_panic_on_negative(t, task_ledgers.graphics_nofootprint);
		ledger_panic_on_negative(t, task_ledgers.graphics_footprint);
		ledger_panic_on_negative(t, task_ledgers.graphics_nofootprint_compressed);
		ledger_panic_on_negative(t, task_ledgers.graphics_footprint_compressed);
		ledger_panic_on_negative(t, task_ledgers.neural_nofootprint);
		ledger_panic_on_negative(t, task_ledgers.neural_footprint);
		ledger_panic_on_negative(t, task_ledgers.neural_nofootprint_compressed);
		ledger_panic_on_negative(t, task_ledgers.neural_footprint_compressed);
	}
#endif /* MACH_ASSERT */

#if CONFIG_MEMORYSTATUS
	ledger_set_callback(t, task_ledgers.phys_footprint, task_footprint_exceeded, NULL, NULL);
#endif /* CONFIG_MEMORYSTATUS */

	ledger_set_callback(t, task_ledgers.interrupt_wakeups,
	    task_wakeups_rate_exceeded, NULL, NULL);
	ledger_set_callback(t, task_ledgers.physical_writes, task_io_rate_exceeded, (void *)FLAVOR_IO_PHYSICAL_WRITES, NULL);

#if XNU_MONITOR
	ledger_template_complete_secure_alloc(t);
#else /* XNU_MONITOR */
	ledger_template_complete(t);
#endif /* XNU_MONITOR */
	task_ledger_template = t;
}

os_refgrp_decl(static, task_refgrp, "task", NULL);

kern_return_t
task_create_internal(
	task_t          parent_task,
	coalition_t     *parent_coalitions __unused,
	boolean_t       inherit_memory,
	__unused boolean_t      is_64bit,
	boolean_t is_64bit_data,
	uint32_t        t_flags,
	uint32_t        t_procflags,
	uint8_t         t_returnwaitflags,
	task_t          *child_task)            /* OUT */
{
	task_t                  new_task;
	vm_shared_region_t      shared_region;
	ledger_t                ledger = NULL;

	new_task = (task_t) zalloc(task_zone);

	if (new_task == TASK_NULL) {
		return KERN_RESOURCE_SHORTAGE;
	}

	/* one ref for just being alive; one for our caller */
	os_ref_init_count(&new_task->ref_count, &task_refgrp, 2);

	/* allocate with active entries */
	assert(task_ledger_template != NULL);
	if ((ledger = ledger_instantiate(task_ledger_template,
	    LEDGER_CREATE_ACTIVE_ENTRIES)) == NULL) {
		zfree(task_zone, new_task);
		return KERN_RESOURCE_SHORTAGE;
	}

#if defined(HAS_APPLE_PAC)
	ml_task_set_rop_pid(new_task, parent_task, inherit_memory);
	ml_task_set_disable_user_jop(new_task, inherit_memory ? parent_task->disable_user_jop : FALSE);
#endif

	new_task->ledger = ledger;

#if defined(CONFIG_SCHED_MULTIQ)
	new_task->sched_group = sched_group_create();
#endif

	/* if inherit_memory is true, parent_task MUST not be NULL */
	if (!(t_flags & TF_CORPSE_FORK) && inherit_memory) {
		new_task->map = vm_map_fork(ledger, parent_task->map, 0);
	} else {
		unsigned int pmap_flags = is_64bit ? PMAP_CREATE_64BIT : 0;
		new_task->map = vm_map_create(pmap_create_options(ledger, 0, pmap_flags),
		    (vm_map_offset_t)(VM_MIN_ADDRESS),
		    (vm_map_offset_t)(VM_MAX_ADDRESS), TRUE);
	}

	/* Inherit memlock limit from parent */
	if (parent_task) {
		vm_map_set_user_wire_limit(new_task->map, (vm_size_t)parent_task->map->user_wire_limit);
	}

	lck_mtx_init(&new_task->lock, &task_lck_grp, &task_lck_attr);
	queue_init(&new_task->threads);
	new_task->suspend_count = 0;
	new_task->thread_count = 0;
	new_task->active_thread_count = 0;
	new_task->user_stop_count = 0;
	new_task->legacy_stop_count = 0;
	new_task->active = TRUE;
	new_task->halting = FALSE;
	new_task->priv_flags = 0;
	new_task->t_flags = t_flags;
	new_task->t_procflags = t_procflags;
	new_task->t_returnwaitflags = t_returnwaitflags;
	new_task->returnwait_inheritor = current_thread();
	new_task->importance = 0;
	new_task->crashed_thread_id = 0;
	new_task->exec_token = 0;
	new_task->watchports = NULL;
	new_task->restartable_ranges = NULL;
	new_task->task_exc_guard = 0;

#if CONFIG_ATM
	new_task->atm_context = NULL;
#endif
	new_task->bank_context = NULL;

#ifdef MACH_BSD
	new_task->bsd_info = NULL;
	new_task->corpse_info = NULL;
#endif /* MACH_BSD */

#if CONFIG_MACF
	new_task->crash_label = NULL;
#endif

#if CONFIG_MEMORYSTATUS
	if (max_task_footprint != 0) {
		ledger_set_limit(ledger, task_ledgers.phys_footprint, max_task_footprint, PHYS_FOOTPRINT_WARNING_LEVEL);
	}
#endif /* CONFIG_MEMORYSTATUS */

	if (task_wakeups_monitor_rate != 0) {
		uint32_t flags = WAKEMON_ENABLE | WAKEMON_SET_DEFAULTS;
		int32_t  rate; // Ignored because of WAKEMON_SET_DEFAULTS
		task_wakeups_monitor_ctl(new_task, &flags, &rate);
	}

#if CONFIG_IO_ACCOUNTING
	uint32_t flags = IOMON_ENABLE;
	task_io_monitor_ctl(new_task, &flags);
#endif /* CONFIG_IO_ACCOUNTING */

	machine_task_init(new_task, parent_task, inherit_memory);

	new_task->task_debug = NULL;

#if DEVELOPMENT || DEBUG
	new_task->task_unnested = FALSE;
	new_task->task_disconnected_count = 0;
#endif
	queue_init(&new_task->semaphore_list);
	new_task->semaphores_owned = 0;

	ipc_task_init(new_task, parent_task);

	new_task->vtimers = 0;

	new_task->shared_region = NULL;

	new_task->affinity_space = NULL;

	new_task->t_kpc = 0;

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

#if CONFIG_EMBEDDED
	queue_init(&new_task->task_watchers);
	new_task->num_taskwatchers  = 0;
	new_task->watchapplying  = 0;
#endif /* CONFIG_EMBEDDED */

	new_task->mem_notify_reserved = 0;
	new_task->memlimit_attrs_reserved = 0;

	new_task->requested_policy = default_task_requested_policy;
	new_task->effective_policy = default_task_effective_policy;

	task_importance_init_from_parent(new_task, parent_task);

	if (parent_task != TASK_NULL) {
		new_task->sec_token = parent_task->sec_token;
		new_task->audit_token = parent_task->audit_token;

		/* inherit the parent's shared region */
		shared_region = vm_shared_region_get(parent_task);
		vm_shared_region_set(new_task, shared_region);

		if (task_has_64Bit_addr(parent_task)) {
			task_set_64Bit_addr(new_task);
		}

		if (task_has_64Bit_data(parent_task)) {
			task_set_64Bit_data(new_task);
		}

		new_task->all_image_info_addr = parent_task->all_image_info_addr;
		new_task->all_image_info_size = parent_task->all_image_info_size;
		new_task->mach_header_vm_address = 0;

		if (inherit_memory && parent_task->affinity_space) {
			task_affinity_create(parent_task, new_task);
		}

		new_task->pset_hint = parent_task->pset_hint = task_choose_pset(parent_task);

#if DEBUG || DEVELOPMENT
		if (parent_task->t_flags & TF_NO_SMT) {
			new_task->t_flags |= TF_NO_SMT;
		}
#endif

		new_task->priority = BASEPRI_DEFAULT;
		new_task->max_priority = MAXPRI_USER;

		task_policy_create(new_task, parent_task);
	} else {
		new_task->sec_token = KERNEL_SECURITY_TOKEN;
		new_task->audit_token = KERNEL_AUDIT_TOKEN;
#ifdef __LP64__
		if (is_64bit) {
			task_set_64Bit_addr(new_task);
		}
#endif

		if (is_64bit_data) {
			task_set_64Bit_data(new_task);
		}

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
	for (int i = 0; i < COALITION_NUM_TYPES; i++) {
		queue_chain_init(new_task->task_coalition[i]);
	}

	/* Allocate I/O Statistics */
	new_task->task_io_stats = (io_stat_info_t)kalloc(sizeof(struct io_stat_info));
	assert(new_task->task_io_stats != NULL);
	bzero(new_task->task_io_stats, sizeof(struct io_stat_info));

	bzero(&(new_task->cpu_time_eqos_stats), sizeof(new_task->cpu_time_eqos_stats));
	bzero(&(new_task->cpu_time_rqos_stats), sizeof(new_task->cpu_time_rqos_stats));

	bzero(&new_task->extmod_statistics, sizeof(new_task->extmod_statistics));

	/* Copy resource acc. info from Parent for Corpe Forked task. */
	if (parent_task != NULL && (t_flags & TF_CORPSE_FORK)) {
		task_rollup_accounting_info(new_task, parent_task);
	} else {
		/* Initialize to zero for standard fork/spawn case */
		new_task->total_user_time = 0;
		new_task->total_system_time = 0;
		new_task->total_ptime = 0;
		new_task->total_runnable_time = 0;
		new_task->faults = 0;
		new_task->pageins = 0;
		new_task->cow_faults = 0;
		new_task->messages_sent = 0;
		new_task->messages_received = 0;
		new_task->syscalls_mach = 0;
		new_task->syscalls_unix = 0;
		new_task->c_switch = 0;
		new_task->p_switch = 0;
		new_task->ps_switch = 0;
		new_task->decompressions = 0;
		new_task->low_mem_notified_warn = 0;
		new_task->low_mem_notified_critical = 0;
		new_task->purged_memory_warn = 0;
		new_task->purged_memory_critical = 0;
		new_task->low_mem_privileged_listener = 0;
		new_task->memlimit_is_active = 0;
		new_task->memlimit_is_fatal = 0;
		new_task->memlimit_active_exc_resource = 0;
		new_task->memlimit_inactive_exc_resource = 0;
		new_task->task_timer_wakeups_bin_1 = 0;
		new_task->task_timer_wakeups_bin_2 = 0;
		new_task->task_gpu_ns = 0;
		new_task->task_writes_counters_internal.task_immediate_writes = 0;
		new_task->task_writes_counters_internal.task_deferred_writes = 0;
		new_task->task_writes_counters_internal.task_invalidated_writes = 0;
		new_task->task_writes_counters_internal.task_metadata_writes = 0;
		new_task->task_writes_counters_external.task_immediate_writes = 0;
		new_task->task_writes_counters_external.task_deferred_writes = 0;
		new_task->task_writes_counters_external.task_invalidated_writes = 0;
		new_task->task_writes_counters_external.task_metadata_writes = 0;

		new_task->task_energy = 0;
#if MONOTONIC
		memset(&new_task->task_monotonic, 0, sizeof(new_task->task_monotonic));
#endif /* MONOTONIC */
	}


#if CONFIG_COALITIONS
	if (!(t_flags & TF_CORPSE_FORK)) {
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
		/*
		 * on exec, we need to transfer the coalition roles from the
		 * parent task to the exec copy task.
		 */
		if (parent_task && (t_procflags & TPF_EXEC_COPY)) {
			int coal_roles[COALITION_NUM_TYPES];
			task_coalition_roles(parent_task, coal_roles);
			(void)coalitions_set_roles(new_task->coalition, new_task, coal_roles);
		}
	} else {
		coalitions_adopt_corpse_task(new_task);
	}

	if (new_task->coalition[COALITION_TYPE_RESOURCE] == COALITION_NULL) {
		panic("created task is not a member of a resource coalition");
	}
#endif /* CONFIG_COALITIONS */

	new_task->dispatchqueue_offset = 0;
	if (parent_task != NULL) {
		new_task->dispatchqueue_offset = parent_task->dispatchqueue_offset;
	}

	new_task->task_can_transfer_memory_ownership = FALSE;
	new_task->task_volatile_objects = 0;
	new_task->task_nonvolatile_objects = 0;
	new_task->task_objects_disowning = FALSE;
	new_task->task_objects_disowned = FALSE;
	new_task->task_owned_objects = 0;
	queue_init(&new_task->task_objq);
	task_objq_lock_init(new_task);

#if __arm64__
	new_task->task_legacy_footprint = FALSE;
	new_task->task_extra_footprint_limit = FALSE;
	new_task->task_ios13extended_footprint_limit = FALSE;
#endif /* __arm64__ */
	new_task->task_region_footprint = FALSE;
	new_task->task_has_crossed_thread_limit = FALSE;
	new_task->task_thread_limit = 0;
#if CONFIG_SECLUDED_MEMORY
	new_task->task_can_use_secluded_mem = FALSE;
	new_task->task_could_use_secluded_mem = FALSE;
	new_task->task_could_also_use_secluded_mem = FALSE;
	new_task->task_suppressed_secluded = FALSE;
#endif /* CONFIG_SECLUDED_MEMORY */

	/*
	 * t_flags is set up above. But since we don't
	 * support darkwake mode being set that way
	 * currently, we clear it out here explicitly.
	 */
	new_task->t_flags &= ~(TF_DARKWAKE_MODE);

	queue_init(&new_task->io_user_clients);
	new_task->loadTag = 0;

	ipc_task_enable(new_task);

	lck_mtx_lock(&tasks_threads_lock);
	queue_enter(&tasks, new_task, task_t, tasks);
	tasks_count++;
	if (tasks_suspend_state) {
		task_suspend_internal(new_task);
	}
	lck_mtx_unlock(&tasks_threads_lock);

	*child_task = new_task;
	return KERN_SUCCESS;
}

/*
 *	task_rollup_accounting_info
 *
 *	Roll up accounting stats. Used to rollup stats
 *	for exec copy task and corpse fork.
 */
void
task_rollup_accounting_info(task_t to_task, task_t from_task)
{
	assert(from_task != to_task);

	to_task->total_user_time = from_task->total_user_time;
	to_task->total_system_time = from_task->total_system_time;
	to_task->total_ptime = from_task->total_ptime;
	to_task->total_runnable_time = from_task->total_runnable_time;
	to_task->faults = from_task->faults;
	to_task->pageins = from_task->pageins;
	to_task->cow_faults = from_task->cow_faults;
	to_task->decompressions = from_task->decompressions;
	to_task->messages_sent = from_task->messages_sent;
	to_task->messages_received = from_task->messages_received;
	to_task->syscalls_mach = from_task->syscalls_mach;
	to_task->syscalls_unix = from_task->syscalls_unix;
	to_task->c_switch = from_task->c_switch;
	to_task->p_switch = from_task->p_switch;
	to_task->ps_switch = from_task->ps_switch;
	to_task->extmod_statistics = from_task->extmod_statistics;
	to_task->low_mem_notified_warn = from_task->low_mem_notified_warn;
	to_task->low_mem_notified_critical = from_task->low_mem_notified_critical;
	to_task->purged_memory_warn = from_task->purged_memory_warn;
	to_task->purged_memory_critical = from_task->purged_memory_critical;
	to_task->low_mem_privileged_listener = from_task->low_mem_privileged_listener;
	*to_task->task_io_stats = *from_task->task_io_stats;
	to_task->cpu_time_eqos_stats = from_task->cpu_time_eqos_stats;
	to_task->cpu_time_rqos_stats = from_task->cpu_time_rqos_stats;
	to_task->task_timer_wakeups_bin_1 = from_task->task_timer_wakeups_bin_1;
	to_task->task_timer_wakeups_bin_2 = from_task->task_timer_wakeups_bin_2;
	to_task->task_gpu_ns = from_task->task_gpu_ns;
	to_task->task_writes_counters_internal.task_immediate_writes = from_task->task_writes_counters_internal.task_immediate_writes;
	to_task->task_writes_counters_internal.task_deferred_writes = from_task->task_writes_counters_internal.task_deferred_writes;
	to_task->task_writes_counters_internal.task_invalidated_writes = from_task->task_writes_counters_internal.task_invalidated_writes;
	to_task->task_writes_counters_internal.task_metadata_writes = from_task->task_writes_counters_internal.task_metadata_writes;
	to_task->task_writes_counters_external.task_immediate_writes = from_task->task_writes_counters_external.task_immediate_writes;
	to_task->task_writes_counters_external.task_deferred_writes = from_task->task_writes_counters_external.task_deferred_writes;
	to_task->task_writes_counters_external.task_invalidated_writes = from_task->task_writes_counters_external.task_invalidated_writes;
	to_task->task_writes_counters_external.task_metadata_writes = from_task->task_writes_counters_external.task_metadata_writes;
	to_task->task_energy = from_task->task_energy;

	/* Skip ledger roll up for memory accounting entries */
	ledger_rollup_entry(to_task->ledger, from_task->ledger, task_ledgers.cpu_time);
	ledger_rollup_entry(to_task->ledger, from_task->ledger, task_ledgers.platform_idle_wakeups);
	ledger_rollup_entry(to_task->ledger, from_task->ledger, task_ledgers.interrupt_wakeups);
#if CONFIG_SCHED_SFI
	for (sfi_class_id_t class_id = SFI_CLASS_UNSPECIFIED; class_id < MAX_SFI_CLASS_ID; class_id++) {
		ledger_rollup_entry(to_task->ledger, from_task->ledger, task_ledgers.sfi_wait_times[class_id]);
	}
#endif
	ledger_rollup_entry(to_task->ledger, from_task->ledger, task_ledgers.cpu_time_billed_to_me);
	ledger_rollup_entry(to_task->ledger, from_task->ledger, task_ledgers.cpu_time_billed_to_others);
	ledger_rollup_entry(to_task->ledger, from_task->ledger, task_ledgers.physical_writes);
	ledger_rollup_entry(to_task->ledger, from_task->ledger, task_ledgers.logical_writes);
	ledger_rollup_entry(to_task->ledger, from_task->ledger, task_ledgers.energy_billed_to_me);
	ledger_rollup_entry(to_task->ledger, from_task->ledger, task_ledgers.energy_billed_to_others);
}

int task_dropped_imp_count = 0;

/*
 *	task_deallocate:
 *
 *	Drop a reference on a task.
 */
void
task_deallocate(
	task_t          task)
{
	ledger_amount_t credit, debit, interrupt_wakeups, platform_idle_wakeups;
	os_ref_count_t refs;

	if (task == TASK_NULL) {
		return;
	}

	refs = task_deallocate_internal(task);

#if IMPORTANCE_INHERITANCE
	if (refs == 1) {
		/*
		 * If last ref potentially comes from the task's importance,
		 * disconnect it.  But more task refs may be added before
		 * that completes, so wait for the reference to go to zero
		 * naturally (it may happen on a recursive task_deallocate()
		 * from the ipc_importance_disconnect_task() call).
		 */
		if (IIT_NULL != task->task_imp_base) {
			ipc_importance_disconnect_task(task);
		}
		return;
	}
#endif /* IMPORTANCE_INHERITANCE */

	if (refs > 0) {
		return;
	}

	/*
	 * The task should be dead at this point. Ensure other resources
	 * like threads, are gone before we trash the world.
	 */
	assert(queue_empty(&task->threads));
	assert(task->bsd_info == NULL);
	assert(!is_active(task->itk_space));
	assert(!task->active);
	assert(task->active_thread_count == 0);

	lck_mtx_lock(&tasks_threads_lock);
	assert(terminated_tasks_count > 0);
	queue_remove(&terminated_tasks, task, task_t, tasks);
	terminated_tasks_count--;
	lck_mtx_unlock(&tasks_threads_lock);

	/*
	 * remove the reference on atm descriptor
	 */
	task_atm_reset(task);

	/*
	 * remove the reference on bank context
	 */
	task_bank_reset(task);

	if (task->task_io_stats) {
		kfree(task->task_io_stats, sizeof(struct io_stat_info));
	}

	/*
	 *	Give the machine dependent code a chance
	 *	to perform cleanup before ripping apart
	 *	the task.
	 */
	machine_task_terminate(task);

	ipc_task_terminate(task);

	/* let iokit know */
	iokit_task_terminate(task);

	if (task->affinity_space) {
		task_affinity_deallocate(task);
	}

#if MACH_ASSERT
	if (task->ledger != NULL &&
	    task->map != NULL &&
	    task->map->pmap != NULL &&
	    task->map->pmap->ledger != NULL) {
		assert(task->ledger == task->map->pmap->ledger);
	}
#endif /* MACH_ASSERT */

	vm_owned_objects_disown(task);
	assert(task->task_objects_disowned);
	if (task->task_volatile_objects != 0 ||
	    task->task_nonvolatile_objects != 0 ||
	    task->task_owned_objects != 0) {
		panic("task_deallocate(%p): "
		    "volatile_objects=%d nonvolatile_objects=%d owned=%d\n",
		    task,
		    task->task_volatile_objects,
		    task->task_nonvolatile_objects,
		    task->task_owned_objects);
	}

	vm_map_deallocate(task->map);
	is_release(task->itk_space);
	if (task->restartable_ranges) {
		restartable_ranges_release(task->restartable_ranges);
	}

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
	dead_task_statistics.total_ptime += task->total_ptime;
	dead_task_statistics.total_pset_switches += task->ps_switch;
	dead_task_statistics.task_gpu_ns += task->task_gpu_ns;
	dead_task_statistics.task_energy += task->task_energy;

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

#if TASK_REFERENCE_LEAK_DEBUG
	btlog_remove_entries_for_element(task_ref_btlog, task);
#endif

#if CONFIG_COALITIONS
	task_release_coalitions(task);
#endif /* CONFIG_COALITIONS */

	bzero(task->coalition, sizeof(task->coalition));

#if MACH_BSD
	/* clean up collected information since last reference to task is gone */
	if (task->corpse_info) {
		void *corpse_info_kernel = kcdata_memory_get_begin_addr(task->corpse_info);
		task_crashinfo_destroy(task->corpse_info);
		task->corpse_info = NULL;
		if (corpse_info_kernel) {
			kfree(corpse_info_kernel, CORPSEINFO_ALLOCATION_SIZE);
		}
	}
#endif

#if CONFIG_MACF
	if (task->crash_label) {
		mac_exc_free_label(task->crash_label);
		task->crash_label = NULL;
	}
#endif

	assert(queue_empty(&task->task_objq));

	zfree(task_zone, task);
}

/*
 *	task_name_deallocate:
 *
 *	Drop a reference on a task name.
 */
void
task_name_deallocate(
	task_name_t             task_name)
{
	return task_deallocate((task_t)task_name);
}

/*
 *	task_inspect_deallocate:
 *
 *	Drop a task inspection reference.
 */
void
task_inspect_deallocate(
	task_inspect_t          task_inspect)
{
	return task_deallocate((task_t)task_inspect);
}

/*
 *	task_suspension_token_deallocate:
 *
 *	Drop a reference on a task suspension token.
 */
void
task_suspension_token_deallocate(
	task_suspension_token_t         token)
{
	return task_deallocate((task_t)token);
}


/*
 * task_collect_crash_info:
 *
 * collect crash info from bsd and mach based data
 */
kern_return_t
task_collect_crash_info(
	task_t task,
#ifdef CONFIG_MACF
	struct label *crash_label,
#endif
	int is_corpse_fork)
{
	kern_return_t kr = KERN_SUCCESS;

	kcdata_descriptor_t crash_data = NULL;
	kcdata_descriptor_t crash_data_release = NULL;
	mach_msg_type_number_t size = CORPSEINFO_ALLOCATION_SIZE;
	mach_vm_offset_t crash_data_ptr = 0;
	void *crash_data_kernel = NULL;
	void *crash_data_kernel_release = NULL;
#if CONFIG_MACF
	struct label *label, *free_label;
#endif

	if (!corpses_enabled()) {
		return KERN_NOT_SUPPORTED;
	}

#if CONFIG_MACF
	free_label = label = mac_exc_create_label();
#endif

	task_lock(task);

	assert(is_corpse_fork || task->bsd_info != NULL);
	if (task->corpse_info == NULL && (is_corpse_fork || task->bsd_info != NULL)) {
#if CONFIG_MACF
		/* Set the crash label, used by the exception delivery mac hook */
		free_label = task->crash_label; // Most likely NULL.
		task->crash_label = label;
		mac_exc_update_task_crash_label(task, crash_label);
#endif
		task_unlock(task);

		crash_data_kernel = (void *) kalloc(CORPSEINFO_ALLOCATION_SIZE);
		if (crash_data_kernel == NULL) {
			kr = KERN_RESOURCE_SHORTAGE;
			goto out_no_lock;
		}
		bzero(crash_data_kernel, CORPSEINFO_ALLOCATION_SIZE);
		crash_data_ptr = (mach_vm_offset_t) crash_data_kernel;

		/* Do not get a corpse ref for corpse fork */
		crash_data = task_crashinfo_alloc_init((mach_vm_address_t)crash_data_ptr, size,
		    is_corpse_fork ? 0 : CORPSE_CRASHINFO_HAS_REF,
		    KCFLAG_USE_MEMCOPY);
		if (crash_data) {
			task_lock(task);
			crash_data_release = task->corpse_info;
			crash_data_kernel_release = kcdata_memory_get_begin_addr(crash_data_release);
			task->corpse_info = crash_data;

			task_unlock(task);
			kr = KERN_SUCCESS;
		} else {
			kfree(crash_data_kernel, CORPSEINFO_ALLOCATION_SIZE);
			kr = KERN_FAILURE;
		}

		if (crash_data_release != NULL) {
			task_crashinfo_destroy(crash_data_release);
		}
		if (crash_data_kernel_release != NULL) {
			kfree(crash_data_kernel_release, CORPSEINFO_ALLOCATION_SIZE);
		}
	} else {
		task_unlock(task);
	}

out_no_lock:
#if CONFIG_MACF
	if (free_label != NULL) {
		mac_exc_free_label(free_label);
	}
#endif
	return kr;
}

/*
 * task_deliver_crash_notification:
 *
 * Makes outcall to registered host port for a corpse.
 */
kern_return_t
task_deliver_crash_notification(
	task_t task,
	thread_t thread,
	exception_type_t etype,
	mach_exception_subcode_t subcode)
{
	kcdata_descriptor_t crash_info = task->corpse_info;
	thread_t th_iter = NULL;
	kern_return_t kr = KERN_SUCCESS;
	wait_interrupt_t wsave;
	mach_exception_data_type_t code[EXCEPTION_CODE_MAX];
	ipc_port_t task_port, old_notify;

	if (crash_info == NULL) {
		return KERN_FAILURE;
	}

	task_lock(task);
	if (task_is_a_corpse_fork(task)) {
		/* Populate code with EXC_{RESOURCE,GUARD} for corpse fork */
		code[0] = etype;
		code[1] = subcode;
	} else {
		/* Populate code with EXC_CRASH for corpses */
		code[0] = EXC_CRASH;
		code[1] = 0;
		/* Update the code[1] if the boot-arg corpse_for_fatal_memkill is set */
		if (corpse_for_fatal_memkill) {
			code[1] = subcode;
		}
	}

	queue_iterate(&task->threads, th_iter, thread_t, task_threads)
	{
		if (th_iter->corpse_dup == FALSE) {
			ipc_thread_reset(th_iter);
		}
	}
	task_unlock(task);

	/* Arm the no-sender notification for taskport */
	task_reference(task);
	task_port = convert_task_to_port(task);
	ip_lock(task_port);
	require_ip_active(task_port);
	ipc_port_nsrequest(task_port, task_port->ip_mscount, ipc_port_make_sonce_locked(task_port), &old_notify);
	/* port unlocked */
	assert(IP_NULL == old_notify);

	wsave = thread_interrupt_level(THREAD_UNINT);
	kr = exception_triage_thread(EXC_CORPSE_NOTIFY, code, EXCEPTION_CODE_MAX, thread);
	if (kr != KERN_SUCCESS) {
		printf("Failed to send exception EXC_CORPSE_NOTIFY. error code: %d for pid %d\n", kr, task_pid(task));
	}

	(void)thread_interrupt_level(wsave);

	/*
	 * Drop the send right on task port, will fire the
	 * no-sender notification if exception deliver failed.
	 */
	ipc_port_release_send(task_port);
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
	task_t          task)
{
	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (task->bsd_info) {
		return KERN_FAILURE;
	}

	return task_terminate_internal(task);
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
#if CONFIG_MACF
	struct label *crash_label = NULL;
#endif

	assert(task != kernel_task);
	assert(task == current_task());
	assert(!task_is_a_corpse(task));

#if CONFIG_MACF
	crash_label = mac_exc_create_label_for_proc((struct proc*)task->bsd_info);
#endif

	kr = task_collect_crash_info(task,
#if CONFIG_MACF
	    crash_label,
#endif
	    FALSE);
	if (kr != KERN_SUCCESS) {
		goto out;
	}

	self_thread = current_thread();

	wsave = thread_interrupt_level(THREAD_UNINT);
	task_lock(task);

	task_set_corpse_pending_report(task);
	task_set_corpse(task);
	task->crashed_thread_id = thread_tid(self_thread);

	kr = task_start_halt_locked(task, TRUE);
	assert(kr == KERN_SUCCESS);

	ipc_task_reset(task);
	/* Remove the naked send right for task port, needed to arm no sender notification */
	task_set_special_port_internal(task, TASK_KERNEL_PORT, IPC_PORT_NULL);
	ipc_task_enable(task);

	task_unlock(task);
	/* terminate the ipc space */
	ipc_space_terminate(task->itk_space);

	/* Add it to global corpse task list */
	task_add_to_corpse_task_list(task);

	task_start_halt(task);
	thread_terminate_internal(self_thread);

	(void) thread_interrupt_level(wsave);
	assert(task->halting == TRUE);

out:
#if CONFIG_MACF
	mac_exc_free_label(crash_label);
#endif
	return kr;
}

/*
 *	task_clear_corpse
 *
 *	Clears the corpse pending bit on task.
 *	Removes inspection bit on the threads.
 */
void
task_clear_corpse(task_t task)
{
	thread_t th_iter = NULL;

	task_lock(task);
	queue_iterate(&task->threads, th_iter, thread_t, task_threads)
	{
		thread_mtx_lock(th_iter);
		th_iter->inspection = FALSE;
		thread_mtx_unlock(th_iter);
	}

	thread_terminate_crashed_threads();
	/* remove the pending corpse report flag */
	task_clear_corpse_pending_report(task);

	task_unlock(task);
}

/*
 *	task_port_notify
 *
 *	Called whenever the Mach port system detects no-senders on
 *	the task port of a corpse.
 *	Each notification that comes in should terminate the task (corpse).
 */
void
task_port_notify(mach_msg_header_t *msg)
{
	mach_no_senders_notification_t *notification = (void *)msg;
	ipc_port_t port = notification->not_header.msgh_remote_port;
	task_t task;

	require_ip_active(port);
	assert(IKOT_TASK == ip_kotype(port));
	task = (task_t) ip_get_kobject(port);

	assert(task_is_a_corpse(task));

	/* Remove the task from global corpse task list */
	task_remove_from_corpse_task_list(task);

	task_clear_corpse(task);
	task_terminate_internal(task);
}

/*
 *	task_wait_till_threads_terminate_locked
 *
 *	Wait till all the threads in the task are terminated.
 *	Might release the task lock and re-acquire it.
 */
void
task_wait_till_threads_terminate_locked(task_t task)
{
	/* wait for all the threads in the task to terminate */
	while (task->active_thread_count != 0) {
		assert_wait((event_t)&task->active_thread_count, THREAD_UNINT);
		task_unlock(task);
		thread_block(THREAD_CONTINUE_NULL);

		task_lock(task);
	}
}

/*
 *	task_duplicate_map_and_threads
 *
 *	Copy vmmap of source task.
 *	Copy active threads from source task to destination task.
 *	Source task would be suspended during the copy.
 */
kern_return_t
task_duplicate_map_and_threads(
	task_t task,
	void *p,
	task_t new_task,
	thread_t *thread_ret,
	uint64_t **udata_buffer,
	int *size,
	int *num_udata)
{
	kern_return_t kr = KERN_SUCCESS;
	int active;
	thread_t thread, self, thread_return = THREAD_NULL;
	thread_t new_thread = THREAD_NULL, first_thread = THREAD_NULL;
	thread_t *thread_array;
	uint32_t active_thread_count = 0, array_count = 0, i;
	vm_map_t oldmap;
	uint64_t *buffer = NULL;
	int buf_size = 0;
	int est_knotes = 0, num_knotes = 0;

	self = current_thread();

	/*
	 * Suspend the task to copy thread state, use the internal
	 * variant so that no user-space process can resume
	 * the task from under us
	 */
	kr = task_suspend_internal(task);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	if (task->map->disable_vmentry_reuse == TRUE) {
		/*
		 * Quite likely GuardMalloc (or some debugging tool)
		 * is being used on this task. And it has gone through
		 * its limit. Making a corpse will likely encounter
		 * a lot of VM entries that will need COW.
		 *
		 * Skip it.
		 */
#if DEVELOPMENT || DEBUG
		memorystatus_abort_vm_map_fork(task);
#endif
		task_resume_internal(task);
		return KERN_FAILURE;
	}

	/* Check with VM if vm_map_fork is allowed for this task */
	if (memorystatus_allowed_vm_map_fork(task)) {
		/* Setup new task's vmmap, switch from parent task's map to it COW map */
		oldmap = new_task->map;
		new_task->map = vm_map_fork(new_task->ledger,
		    task->map,
		    (VM_MAP_FORK_SHARE_IF_INHERIT_NONE |
		    VM_MAP_FORK_PRESERVE_PURGEABLE |
		    VM_MAP_FORK_CORPSE_FOOTPRINT));
		vm_map_deallocate(oldmap);

		/* copy ledgers that impact the memory footprint */
		vm_map_copy_footprint_ledgers(task, new_task);

		/* Get all the udata pointers from kqueue */
		est_knotes = kevent_proc_copy_uptrs(p, NULL, 0);
		if (est_knotes > 0) {
			buf_size = (est_knotes + 32) * sizeof(uint64_t);
			buffer = (uint64_t *) kalloc(buf_size);
			num_knotes = kevent_proc_copy_uptrs(p, buffer, buf_size);
			if (num_knotes > est_knotes + 32) {
				num_knotes = est_knotes + 32;
			}
		}
	}

	active_thread_count = task->active_thread_count;
	if (active_thread_count == 0) {
		if (buffer != NULL) {
			kfree(buffer, buf_size);
		}
		task_resume_internal(task);
		return KERN_FAILURE;
	}

	thread_array = (thread_t *) kalloc(sizeof(thread_t) * active_thread_count);

	/* Iterate all the threads and drop the task lock before calling thread_create_with_continuation */
	task_lock(task);
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		/* Skip inactive threads */
		active = thread->active;
		if (!active) {
			continue;
		}

		if (array_count >= active_thread_count) {
			break;
		}

		thread_array[array_count++] = thread;
		thread_reference(thread);
	}
	task_unlock(task);

	for (i = 0; i < array_count; i++) {
		kr = thread_create_with_continuation(new_task, &new_thread, (thread_continue_t)thread_corpse_continue);
		if (kr != KERN_SUCCESS) {
			break;
		}

		/* Equivalent of current thread in corpse */
		if (thread_array[i] == self) {
			thread_return = new_thread;
			new_task->crashed_thread_id = thread_tid(new_thread);
		} else if (first_thread == NULL) {
			first_thread = new_thread;
		} else {
			/* drop the extra ref returned by thread_create_with_continuation */
			thread_deallocate(new_thread);
		}

		kr = thread_dup2(thread_array[i], new_thread);
		if (kr != KERN_SUCCESS) {
			thread_mtx_lock(new_thread);
			new_thread->corpse_dup = TRUE;
			thread_mtx_unlock(new_thread);
			continue;
		}

		/* Copy thread name */
		bsd_copythreadname(new_thread->uthread, thread_array[i]->uthread);
		new_thread->thread_tag = thread_array[i]->thread_tag;
		thread_copy_resource_info(new_thread, thread_array[i]);
	}

	/* return the first thread if we couldn't find the equivalent of current */
	if (thread_return == THREAD_NULL) {
		thread_return = first_thread;
	} else if (first_thread != THREAD_NULL) {
		/* drop the extra ref returned by thread_create_with_continuation */
		thread_deallocate(first_thread);
	}

	task_resume_internal(task);

	for (i = 0; i < array_count; i++) {
		thread_deallocate(thread_array[i]);
	}
	kfree(thread_array, sizeof(thread_t) * active_thread_count);

	if (kr == KERN_SUCCESS) {
		*thread_ret = thread_return;
		*udata_buffer = buffer;
		*size = buf_size;
		*num_udata = num_knotes;
	} else {
		if (thread_return != THREAD_NULL) {
			thread_deallocate(thread_return);
		}
		if (buffer != NULL) {
			kfree(buffer, buf_size);
		}
	}

	return kr;
}

#if CONFIG_SECLUDED_MEMORY
extern void task_set_can_use_secluded_mem_locked(
	task_t          task,
	boolean_t       can_use_secluded_mem);
#endif /* CONFIG_SECLUDED_MEMORY */

kern_return_t
task_terminate_internal(
	task_t                  task)
{
	thread_t                        thread, self;
	task_t                          self_task;
	boolean_t                       interrupt_save;
	int                             pid = 0;

	assert(task != kernel_task);

	self = current_thread();
	self_task = self->task;

	/*
	 *	Get the task locked and make sure that we are not racing
	 *	with someone else trying to terminate us.
	 */
	if (task == self_task) {
		task_lock(task);
	} else if (task < self_task) {
		task_lock(task);
		task_lock(self_task);
	} else {
		task_lock(self_task);
		task_lock(task);
	}

#if CONFIG_SECLUDED_MEMORY
	if (task->task_can_use_secluded_mem) {
		task_set_can_use_secluded_mem_locked(task, FALSE);
	}
	task->task_could_use_secluded_mem = FALSE;
	task->task_could_also_use_secluded_mem = FALSE;

	if (task->task_suppressed_secluded) {
		stop_secluded_suppression(task);
	}
#endif /* CONFIG_SECLUDED_MEMORY */

	if (!task->active) {
		/*
		 *	Task is already being terminated.
		 *	Just return an error. If we are dying, this will
		 *	just get us to our AST special handler and that
		 *	will get us to finalize the termination of ourselves.
		 */
		task_unlock(task);
		if (self_task != task) {
			task_unlock(self_task);
		}

		return KERN_FAILURE;
	}

	if (task_corpse_pending_report(task)) {
		/*
		 *	Task is marked for reporting as corpse.
		 *	Just return an error. This will
		 *	just get us to our AST special handler and that
		 *	will get us to finish the path to death
		 */
		task_unlock(task);
		if (self_task != task) {
			task_unlock(self_task);
		}

		return KERN_FAILURE;
	}

	if (self_task != task) {
		task_unlock(self_task);
	}

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
	if (task->bsd_info != NULL && !task_is_exec_copy(task)) {
		pid = proc_pid(task->bsd_info);
	}
#endif /* MACH_BSD */

	task_unlock(task);

	proc_set_task_policy(task, TASK_POLICY_ATTRIBUTE,
	    TASK_POLICY_TERMINATED, TASK_POLICY_ENABLE);

	/* Early object reap phase */

// PR-17045188: Revisit implementation
//        task_partial_reap(task, pid);

#if CONFIG_EMBEDDED
	/*
	 * remove all task watchers
	 */
	task_removewatchers(task);

#endif /* CONFIG_EMBEDDED */

	/*
	 *	Destroy all synchronizers owned by the task.
	 */
	task_synchronizer_destroy_all(task);

	/*
	 *	Clear the watchport boost on the task.
	 */
	task_remove_turnstile_watchports(task);

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

#if MACH_ASSERT
	/*
	 * Identify the pmap's process, in case the pmap ledgers drift
	 * and we have to report it.
	 */
	char procname[17];
	if (task->bsd_info && !task_is_exec_copy(task)) {
		pid = proc_pid(task->bsd_info);
		proc_name_kdp(task, procname, sizeof(procname));
	} else {
		pid = 0;
		strlcpy(procname, "<unknown>", sizeof(procname));
	}
	pmap_set_process(task->map->pmap, pid, procname);
#endif /* MACH_ASSERT */

	vm_map_terminate(task->map);

	/* release our shared region */
	vm_shared_region_set(task, NULL);


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

#if KPC
	/* force the task to release all ctrs */
	if (task->t_kpc & TASK_KPC_FORCED_ALL_CTRS) {
		kpc_force_all_ctrs(task, 0);
	}
#endif /* KPC */

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

	return KERN_SUCCESS;
}

void
tasks_system_suspend(boolean_t suspend)
{
	task_t task;

	lck_mtx_lock(&tasks_threads_lock);
	assert(tasks_suspend_state != suspend);
	tasks_suspend_state = suspend;
	queue_iterate(&tasks, task, task_t, tasks) {
		if (task == kernel_task) {
			continue;
		}
		suspend ? task_suspend_internal(task) : task_resume_internal(task);
	}
	lck_mtx_unlock(&tasks_threads_lock);
}

/*
 * task_start_halt:
 *
 *      Shut the current task down (except for the current thread) in
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

	if (task != self->task && !task_is_a_corpse_fork(task)) {
		return KERN_INVALID_ARGUMENT;
	}

	if (task->halting || !task->active || !self->active) {
		/*
		 * Task or current thread is already being terminated.
		 * Hurry up and return out of the current kernel context
		 * so that we run our AST special handler to terminate
		 * ourselves.
		 */
		return KERN_FAILURE;
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
		if (thread != self) {
			thread_terminate_internal(thread);
		}
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
 *
 *	Note: task->halting flag is not cleared in order to avoid creation
 *	of new thread in old exec'ed task.
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
	    /*
	     * Final cleanup:
	     * + no unnesting
	     * + remove immutable mappings
	     * + allow gaps in the range
	     */
	    (VM_MAP_REMOVE_NO_UNNESTING |
	    VM_MAP_REMOVE_IMMUTABLE |
	    VM_MAP_REMOVE_GAPS_OK));

	/*
	 * Kick out any IOKitUser handles to the task. At best they're stale,
	 * at worst someone is racing a SUID exec.
	 */
	iokit_task_terminate(task);
}

/*
 *	task_hold_locked:
 *
 *	Suspend execution of the specified task.
 *	This is a recursive-style suspension of the task, a count of
 *	suspends is maintained.
 *
 *	CONDITIONS: the task is locked and active.
 */
void
task_hold_locked(
	task_t          task)
{
	thread_t        thread;

	assert(task->active);

	if (task->suspend_count++ > 0) {
		return;
	}

	if (task->bsd_info) {
		workq_proc_suspended(task->bsd_info);
	}

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
 *      CONDITIONS: the caller holds a reference on the task
 */
kern_return_t
task_hold(
	task_t          task)
{
	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);

	if (!task->active) {
		task_unlock(task);

		return KERN_FAILURE;
	}

	task_hold_locked(task);
	task_unlock(task);

	return KERN_SUCCESS;
}

kern_return_t
task_wait(
	task_t          task,
	boolean_t       until_not_runnable)
{
	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);

	if (!task->active) {
		task_unlock(task);

		return KERN_FAILURE;
	}

	task_wait_locked(task, until_not_runnable);
	task_unlock(task);

	return KERN_SUCCESS;
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
	task_t          task,
	boolean_t               until_not_runnable)
{
	thread_t        thread, self;

	assert(task->active);
	assert(task->suspend_count > 0);

	self = current_thread();

	/*
	 *	Iterate through all the threads and wait for them to
	 *	stop.  Do not wait for the current thread if it is within
	 *	the task.
	 */
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		if (thread != self) {
			thread_wait(thread, until_not_runnable);
		}
	}
}

boolean_t
task_is_app_suspended(task_t task)
{
	return task->pidsuspended;
}

/*
 *	task_release_locked:
 *
 *	Release a kernel hold on a task.
 *
 *      CONDITIONS: the task is locked and active
 */
void
task_release_locked(
	task_t          task)
{
	thread_t        thread;

	assert(task->active);
	assert(task->suspend_count > 0);

	if (--task->suspend_count > 0) {
		return;
	}

	if (task->bsd_info) {
		workq_proc_resumed(task->bsd_info);
	}

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
 *      CONDITIONS: The caller holds a reference to the task
 */
kern_return_t
task_release(
	task_t          task)
{
	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);

	if (!task->active) {
		task_unlock(task);

		return KERN_FAILURE;
	}

	task_release_locked(task);
	task_unlock(task);

	return KERN_SUCCESS;
}

kern_return_t
task_threads(
	task_t                                  task,
	thread_act_array_t              *threads_out,
	mach_msg_type_number_t  *count)
{
	mach_msg_type_number_t  actual;
	thread_t                                *thread_list;
	thread_t                                thread;
	vm_size_t                               size, size_needed;
	void                                    *addr;
	unsigned int                    i, j;

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	size = 0; addr = NULL;

	for (;;) {
		task_lock(task);
		if (!task->active) {
			task_unlock(task);

			if (size != 0) {
				kfree(addr, size);
			}

			return KERN_FAILURE;
		}

		actual = task->thread_count;

		/* do we have the memory we need? */
		size_needed = actual * sizeof(mach_port_t);
		if (size_needed <= size) {
			break;
		}

		/* unlock the task and allocate more memory */
		task_unlock(task);

		if (size != 0) {
			kfree(addr, size);
		}

		assert(size_needed > 0);
		size = size_needed;

		addr = kalloc(size);
		if (addr == 0) {
			return KERN_RESOURCE_SHORTAGE;
		}
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
	size_needed = actual * sizeof(mach_port_t);

	/* can unlock task now that we've got the thread refs */
	task_unlock(task);

	if (actual == 0) {
		/* no threads, so return null pointer and deallocate memory */

		*threads_out = NULL;
		*count = 0;

		if (size != 0) {
			kfree(addr, size);
		}
	} else {
		/* if we allocated too much, must copy */

		if (size_needed < size) {
			void *newaddr;

			newaddr = kalloc(size_needed);
			if (newaddr == 0) {
				for (i = 0; i < actual; ++i) {
					thread_deallocate(thread_list[i]);
				}
				kfree(addr, size);
				return KERN_RESOURCE_SHORTAGE;
			}

			bcopy(addr, newaddr, size_needed);
			kfree(addr, size);
			thread_list = (thread_t *)newaddr;
		}

		*threads_out = thread_list;
		*count = actual;

		/* do the conversion that Mig should handle */

		for (i = 0; i < actual; ++i) {
			((ipc_port_t *) thread_list)[i] = convert_thread_to_port(thread_list[i]);
		}
	}

	return KERN_SUCCESS;
}

#define TASK_HOLD_NORMAL        0
#define TASK_HOLD_PIDSUSPEND    1
#define TASK_HOLD_LEGACY        2
#define TASK_HOLD_LEGACY_ALL    3

static kern_return_t
place_task_hold(
	task_t task,
	int mode)
{
	if (!task->active && !task_is_a_corpse(task)) {
		return KERN_FAILURE;
	}

	/* Return success for corpse task */
	if (task_is_a_corpse(task)) {
		return KERN_SUCCESS;
	}

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_IPC, MACH_TASK_SUSPEND) | DBG_FUNC_NONE,
	    task_pid(task), ((thread_t)queue_first(&task->threads))->thread_id,
	    task->user_stop_count, task->user_stop_count + 1, 0);

#if MACH_ASSERT
	current_task()->suspends_outstanding++;
#endif

	if (mode == TASK_HOLD_LEGACY) {
		task->legacy_stop_count++;
	}

	if (task->user_stop_count++ > 0) {
		/*
		 *	If the stop count was positive, the task is
		 *	already stopped and we can exit.
		 */
		return KERN_SUCCESS;
	}

	/*
	 * Put a kernel-level hold on the threads in the task (all
	 * user-level task suspensions added together represent a
	 * single kernel-level hold).  We then wait for the threads
	 * to stop executing user code.
	 */
	task_hold_locked(task);
	task_wait_locked(task, FALSE);

	return KERN_SUCCESS;
}

static kern_return_t
release_task_hold(
	task_t          task,
	int                     mode)
{
	boolean_t release = FALSE;

	if (!task->active && !task_is_a_corpse(task)) {
		return KERN_FAILURE;
	}

	/* Return success for corpse task */
	if (task_is_a_corpse(task)) {
		return KERN_SUCCESS;
	}

	if (mode == TASK_HOLD_PIDSUSPEND) {
		if (task->pidsuspended == FALSE) {
			return KERN_FAILURE;
		}
		task->pidsuspended = FALSE;
	}

	if (task->user_stop_count > (task->pidsuspended ? 1 : 0)) {
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    MACHDBG_CODE(DBG_MACH_IPC, MACH_TASK_RESUME) | DBG_FUNC_NONE,
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
			if (mode == TASK_HOLD_LEGACY && task->legacy_stop_count > 0) {
				task->legacy_stop_count--;
			}
			if (--task->user_stop_count == 0) {
				release = TRUE;
			}
		}
	} else {
		return KERN_FAILURE;
	}

	/*
	 *	Release the task if necessary.
	 */
	if (release) {
		task_release_locked(task);
	}

	return KERN_SUCCESS;
}

boolean_t
get_task_suspended(task_t task)
{
	return 0 != task->user_stop_count;
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
 *      The caller holds a reference to the task
 */
kern_return_t
task_suspend(
	task_t          task)
{
	kern_return_t                   kr;
	mach_port_t                     port;
	mach_port_name_t                name;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);

	/*
	 * place a legacy hold on the task.
	 */
	kr = place_task_hold(task, TASK_HOLD_LEGACY);
	if (kr != KERN_SUCCESS) {
		task_unlock(task);
		return kr;
	}

	/*
	 * Claim a send right on the task resume port, and request a no-senders
	 * notification on that port (if none outstanding).
	 */
	(void)ipc_kobject_make_send_lazy_alloc_port(&task->itk_resume,
	    (ipc_kobject_t)task, IKOT_TASK_RESUME);
	port = task->itk_resume;

	task_unlock(task);

	/*
	 * Copyout the send right into the calling task's IPC space.  It won't know it is there,
	 * but we'll look it up when calling a traditional resume.  Any IPC operations that
	 * deallocate the send right will auto-release the suspension.
	 */
	if ((kr = ipc_kmsg_copyout_object(current_task()->itk_space, ip_to_object(port),
	    MACH_MSG_TYPE_MOVE_SEND, NULL, NULL, &name)) != KERN_SUCCESS) {
		printf("warning: %s(%d) failed to copyout suspension token for pid %d with error: %d\n",
		    proc_name_address(current_task()->bsd_info), proc_pid(current_task()->bsd_info),
		    task_pid(task), kr);
		return kr;
	}

	return kr;
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
	task_t  task)
{
	kern_return_t    kr;
	mach_port_name_t resume_port_name;
	ipc_entry_t              resume_port_entry;
	ipc_space_t              space = current_task()->itk_space;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	/* release a legacy task hold */
	task_lock(task);
	kr = release_task_hold(task, TASK_HOLD_LEGACY);
	task_unlock(task);

	is_write_lock(space);
	if (is_active(space) && IP_VALID(task->itk_resume) &&
	    ipc_hash_lookup(space, ip_to_object(task->itk_resume), &resume_port_name, &resume_port_entry) == TRUE) {
		/*
		 * We found a suspension token in the caller's IPC space. Release a send right to indicate that
		 * we are holding one less legacy hold on the task from this caller.  If the release failed,
		 * go ahead and drop all the rights, as someone either already released our holds or the task
		 * is gone.
		 */
		if (kr == KERN_SUCCESS) {
			ipc_right_dealloc(space, resume_port_name, resume_port_entry);
		} else {
			ipc_right_destroy(space, resume_port_name, resume_port_entry, FALSE, 0);
		}
		/* space unlocked */
	} else {
		is_write_unlock(space);
		if (kr == KERN_SUCCESS) {
			printf("warning: %s(%d) performed out-of-band resume on pid %d\n",
			    proc_name_address(current_task()->bsd_info), proc_pid(current_task()->bsd_info),
			    task_pid(task));
		}
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
	kern_return_t    kr;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);
	kr = place_task_hold(task, TASK_HOLD_NORMAL);
	task_unlock(task);
	return kr;
}

/*
 * Suspend the target task, and return a suspension token. The token
 * represents a reference on the suspended task.
 */
kern_return_t
task_suspend2(
	task_t                  task,
	task_suspension_token_t *suspend_token)
{
	kern_return_t    kr;

	kr = task_suspend_internal(task);
	if (kr != KERN_SUCCESS) {
		*suspend_token = TASK_NULL;
		return kr;
	}

	/*
	 * Take a reference on the target task and return that to the caller
	 * as a "suspension token," which can be converted into an SO right to
	 * the now-suspended task's resume port.
	 */
	task_reference_internal(task);
	*suspend_token = task;

	return KERN_SUCCESS;
}

/*
 * Resume the task
 * (reference/token/port management is caller's responsibility).
 */
kern_return_t
task_resume_internal(
	task_suspension_token_t         task)
{
	kern_return_t kr;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);
	kr = release_task_hold(task, TASK_HOLD_NORMAL);
	task_unlock(task);
	return kr;
}

/*
 * Resume the task using a suspension token. Consumes the token's ref.
 */
kern_return_t
task_resume2(
	task_suspension_token_t         task)
{
	kern_return_t kr;

	kr = task_resume_internal(task);
	task_suspension_token_deallocate(task);

	return kr;
}

boolean_t
task_suspension_notify(mach_msg_header_t *request_header)
{
	ipc_port_t port = request_header->msgh_remote_port;
	task_t task = convert_port_to_task_suspension_token(port);
	mach_msg_type_number_t not_count;

	if (task == TASK_NULL || task == kernel_task) {
		return TRUE;  /* nothing to do */
	}
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

static kern_return_t
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
	return kr;
}


/*
 *	task_pidsuspend:
 *
 *	Suspends a task by placing a hold on its threads.
 *
 * Conditions:
 *      The caller holds a reference to the task
 */
kern_return_t
task_pidsuspend(
	task_t          task)
{
	kern_return_t    kr;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);

	kr = task_pidsuspend_locked(task);

	task_unlock(task);

	if ((KERN_SUCCESS == kr) && task->message_app_suspended) {
		iokit_task_app_suspended_changed(task);
	}

	return kr;
}

/*
 *	task_pidresume:
 *		Resumes a previously suspended task.
 *
 * Conditions:
 *		The caller holds a reference to the task
 */
kern_return_t
task_pidresume(
	task_t  task)
{
	kern_return_t    kr;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);

#if CONFIG_FREEZE

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

	if ((KERN_SUCCESS == kr) && task->message_app_suspended) {
		iokit_task_app_suspended_changed(task);
	}

#if CONFIG_FREEZE

	task_lock(task);

	if (kr == KERN_SUCCESS) {
		task->frozen = FALSE;
	}
	task->changing_freeze_state = FALSE;
	thread_wakeup(&task->changing_freeze_state);

	task_unlock(task);
#endif

	return kr;
}

os_refgrp_decl(static, task_watchports_refgrp, "task_watchports", NULL);

/*
 *	task_add_turnstile_watchports:
 *		Setup watchports to boost the main thread of the task.
 *
 *	Arguments:
 *		task: task being spawned
 *		thread: main thread of task
 *		portwatch_ports: array of watchports
 *		portwatch_count: number of watchports
 *
 *	Conditions:
 *		Nothing locked.
 */
void
task_add_turnstile_watchports(
	task_t          task,
	thread_t        thread,
	ipc_port_t      *portwatch_ports,
	uint32_t        portwatch_count)
{
	struct task_watchports *watchports = NULL;
	struct task_watchport_elem *previous_elem_array[TASK_MAX_WATCHPORT_COUNT] = {};
	os_ref_count_t refs;

	/* Check if the task has terminated */
	if (!task->active) {
		return;
	}

	assert(portwatch_count <= TASK_MAX_WATCHPORT_COUNT);

	watchports = task_watchports_alloc_init(task, thread, portwatch_count);

	/* Lock the ipc space */
	is_write_lock(task->itk_space);

	/* Setup watchports to boost the main thread */
	refs = task_add_turnstile_watchports_locked(task,
	    watchports, previous_elem_array, portwatch_ports,
	    portwatch_count);

	/* Drop the space lock */
	is_write_unlock(task->itk_space);

	if (refs == 0) {
		task_watchports_deallocate(watchports);
	}

	/* Drop the ref on previous_elem_array */
	for (uint32_t i = 0; i < portwatch_count && previous_elem_array[i] != NULL; i++) {
		task_watchport_elem_deallocate(previous_elem_array[i]);
	}
}

/*
 *	task_remove_turnstile_watchports:
 *		Clear all turnstile boost on the task from watchports.
 *
 *	Arguments:
 *		task: task being terminated
 *
 *	Conditions:
 *		Nothing locked.
 */
void
task_remove_turnstile_watchports(
	task_t          task)
{
	os_ref_count_t refs = TASK_MAX_WATCHPORT_COUNT;
	struct task_watchports *watchports = NULL;
	ipc_port_t port_freelist[TASK_MAX_WATCHPORT_COUNT] = {};
	uint32_t portwatch_count;

	/* Lock the ipc space */
	is_write_lock(task->itk_space);

	/* Check if watchport boost exist */
	if (task->watchports == NULL) {
		is_write_unlock(task->itk_space);
		return;
	}
	watchports = task->watchports;
	portwatch_count = watchports->tw_elem_array_count;

	refs = task_remove_turnstile_watchports_locked(task, watchports,
	    port_freelist);

	is_write_unlock(task->itk_space);

	/* Drop all the port references */
	for (uint32_t i = 0; i < portwatch_count && port_freelist[i] != NULL; i++) {
		ip_release(port_freelist[i]);
	}

	/* Clear the task and thread references for task_watchport */
	if (refs == 0) {
		task_watchports_deallocate(watchports);
	}
}

/*
 *	task_transfer_turnstile_watchports:
 *		Transfer all watchport turnstile boost from old task to new task.
 *
 *	Arguments:
 *		old_task: task calling exec
 *		new_task: new exec'ed task
 *		thread: main thread of new task
 *
 *	Conditions:
 *		Nothing locked.
 */
void
task_transfer_turnstile_watchports(
	task_t   old_task,
	task_t   new_task,
	thread_t new_thread)
{
	struct task_watchports *old_watchports = NULL;
	struct task_watchports *new_watchports = NULL;
	os_ref_count_t old_refs = TASK_MAX_WATCHPORT_COUNT;
	os_ref_count_t new_refs = TASK_MAX_WATCHPORT_COUNT;
	uint32_t portwatch_count;

	if (old_task->watchports == NULL || !new_task->active) {
		return;
	}

	/* Get the watch port count from the old task */
	is_write_lock(old_task->itk_space);
	if (old_task->watchports == NULL) {
		is_write_unlock(old_task->itk_space);
		return;
	}

	portwatch_count = old_task->watchports->tw_elem_array_count;
	is_write_unlock(old_task->itk_space);

	new_watchports = task_watchports_alloc_init(new_task, new_thread, portwatch_count);

	/* Lock the ipc space for old task */
	is_write_lock(old_task->itk_space);

	/* Lock the ipc space for new task */
	is_write_lock(new_task->itk_space);

	/* Check if watchport boost exist */
	if (old_task->watchports == NULL || !new_task->active) {
		is_write_unlock(new_task->itk_space);
		is_write_unlock(old_task->itk_space);
		(void)task_watchports_release(new_watchports);
		task_watchports_deallocate(new_watchports);
		return;
	}

	old_watchports = old_task->watchports;
	assert(portwatch_count == old_task->watchports->tw_elem_array_count);

	/* Setup new task watchports */
	new_task->watchports = new_watchports;

	for (uint32_t i = 0; i < portwatch_count; i++) {
		ipc_port_t port = old_watchports->tw_elem[i].twe_port;

		if (port == NULL) {
			task_watchport_elem_clear(&new_watchports->tw_elem[i]);
			continue;
		}

		/* Lock the port and check if it has the entry */
		ip_lock(port);
		imq_lock(&port->ip_messages);

		task_watchport_elem_init(&new_watchports->tw_elem[i], new_task, port);

		if (ipc_port_replace_watchport_elem_conditional_locked(port,
		    &old_watchports->tw_elem[i], &new_watchports->tw_elem[i]) == KERN_SUCCESS) {
			task_watchport_elem_clear(&old_watchports->tw_elem[i]);

			task_watchports_retain(new_watchports);
			old_refs = task_watchports_release(old_watchports);

			/* Check if all ports are cleaned */
			if (old_refs == 0) {
				old_task->watchports = NULL;
			}
		} else {
			task_watchport_elem_clear(&new_watchports->tw_elem[i]);
		}
		/* mqueue and port unlocked by ipc_port_replace_watchport_elem_conditional_locked */
	}

	/* Drop the reference on new task_watchports struct returned by task_watchports_alloc_init */
	new_refs = task_watchports_release(new_watchports);
	if (new_refs == 0) {
		new_task->watchports = NULL;
	}

	is_write_unlock(new_task->itk_space);
	is_write_unlock(old_task->itk_space);

	/* Clear the task and thread references for old_watchport */
	if (old_refs == 0) {
		task_watchports_deallocate(old_watchports);
	}

	/* Clear the task and thread references for new_watchport */
	if (new_refs == 0) {
		task_watchports_deallocate(new_watchports);
	}
}

/*
 *	task_add_turnstile_watchports_locked:
 *		Setup watchports to boost the main thread of the task.
 *
 *	Arguments:
 *		task: task to boost
 *		watchports: watchport structure to be attached to the task
 *		previous_elem_array: an array of old watchport_elem to be returned to caller
 *		portwatch_ports: array of watchports
 *		portwatch_count: number of watchports
 *
 *	Conditions:
 *		ipc space of the task locked.
 *		returns array of old watchport_elem in previous_elem_array
 */
static os_ref_count_t
task_add_turnstile_watchports_locked(
	task_t                      task,
	struct task_watchports      *watchports,
	struct task_watchport_elem  **previous_elem_array,
	ipc_port_t                  *portwatch_ports,
	uint32_t                    portwatch_count)
{
	os_ref_count_t refs = TASK_MAX_WATCHPORT_COUNT;

	/* Check if the task is still active */
	if (!task->active) {
		refs = task_watchports_release(watchports);
		return refs;
	}

	assert(task->watchports == NULL);
	task->watchports = watchports;

	for (uint32_t i = 0, j = 0; i < portwatch_count; i++) {
		ipc_port_t port = portwatch_ports[i];

		task_watchport_elem_init(&watchports->tw_elem[i], task, port);
		if (port == NULL) {
			task_watchport_elem_clear(&watchports->tw_elem[i]);
			continue;
		}

		ip_lock(port);
		imq_lock(&port->ip_messages);

		/* Check if port is in valid state to be setup as watchport */
		if (ipc_port_add_watchport_elem_locked(port, &watchports->tw_elem[i],
		    &previous_elem_array[j]) != KERN_SUCCESS) {
			task_watchport_elem_clear(&watchports->tw_elem[i]);
			continue;
		}
		/* port and mqueue unlocked on return */

		ip_reference(port);
		task_watchports_retain(watchports);
		if (previous_elem_array[j] != NULL) {
			j++;
		}
	}

	/* Drop the reference on task_watchport struct returned by os_ref_init */
	refs = task_watchports_release(watchports);
	if (refs == 0) {
		task->watchports = NULL;
	}

	return refs;
}

/*
 *	task_remove_turnstile_watchports_locked:
 *		Clear all turnstile boost on the task from watchports.
 *
 *	Arguments:
 *		task: task to remove watchports from
 *		watchports: watchports structure for the task
 *		port_freelist: array of ports returned with ref to caller
 *
 *
 *	Conditions:
 *		ipc space of the task locked.
 *		array of ports with refs are returned in port_freelist
 */
static os_ref_count_t
task_remove_turnstile_watchports_locked(
	task_t                 task,
	struct task_watchports *watchports,
	ipc_port_t             *port_freelist)
{
	os_ref_count_t refs = TASK_MAX_WATCHPORT_COUNT;

	for (uint32_t i = 0, j = 0; i < watchports->tw_elem_array_count; i++) {
		ipc_port_t port = watchports->tw_elem[i].twe_port;
		if (port == NULL) {
			continue;
		}

		/* Lock the port and check if it has the entry */
		ip_lock(port);
		imq_lock(&port->ip_messages);
		if (ipc_port_clear_watchport_elem_internal_conditional_locked(port,
		    &watchports->tw_elem[i]) == KERN_SUCCESS) {
			task_watchport_elem_clear(&watchports->tw_elem[i]);
			port_freelist[j++] = port;
			refs = task_watchports_release(watchports);

			/* Check if all ports are cleaned */
			if (refs == 0) {
				task->watchports = NULL;
				break;
			}
		}
		/* mqueue and port unlocked by ipc_port_clear_watchport_elem_internal_conditional_locked */
	}
	return refs;
}

/*
 *	task_watchports_alloc_init:
 *		Allocate and initialize task watchport struct.
 *
 *	Conditions:
 *		Nothing locked.
 */
static struct task_watchports *
task_watchports_alloc_init(
	task_t        task,
	thread_t      thread,
	uint32_t      count)
{
	struct task_watchports *watchports = kalloc(sizeof(struct task_watchports) +
	    count * sizeof(struct task_watchport_elem));

	task_reference(task);
	thread_reference(thread);
	watchports->tw_task = task;
	watchports->tw_thread = thread;
	watchports->tw_elem_array_count = count;
	os_ref_init(&watchports->tw_refcount, &task_watchports_refgrp);

	return watchports;
}

/*
 *	task_watchports_deallocate:
 *		Deallocate task watchport struct.
 *
 *	Conditions:
 *		Nothing locked.
 */
static void
task_watchports_deallocate(
	struct task_watchports *watchports)
{
	uint32_t portwatch_count = watchports->tw_elem_array_count;

	task_deallocate(watchports->tw_task);
	thread_deallocate(watchports->tw_thread);
	kfree(watchports, sizeof(struct task_watchports) + portwatch_count * sizeof(struct task_watchport_elem));
}

/*
 *	task_watchport_elem_deallocate:
 *		Deallocate task watchport element and release its ref on task_watchport.
 *
 *	Conditions:
 *		Nothing locked.
 */
void
task_watchport_elem_deallocate(
	struct task_watchport_elem *watchport_elem)
{
	os_ref_count_t refs = TASK_MAX_WATCHPORT_COUNT;
	task_t task = watchport_elem->twe_task;
	struct task_watchports *watchports = NULL;
	ipc_port_t port = NULL;

	assert(task != NULL);

	/* Take the space lock to modify the elememt */
	is_write_lock(task->itk_space);

	watchports = task->watchports;
	assert(watchports != NULL);

	port = watchport_elem->twe_port;
	assert(port != NULL);

	task_watchport_elem_clear(watchport_elem);
	refs = task_watchports_release(watchports);

	if (refs == 0) {
		task->watchports = NULL;
	}

	is_write_unlock(task->itk_space);

	ip_release(port);
	if (refs == 0) {
		task_watchports_deallocate(watchports);
	}
}

/*
 *	task_has_watchports:
 *		Return TRUE if task has watchport boosts.
 *
 *	Conditions:
 *		Nothing locked.
 */
boolean_t
task_has_watchports(task_t task)
{
	return task->watchports != NULL;
}

#if DEVELOPMENT || DEBUG

extern void IOSleep(int);

kern_return_t
task_disconnect_page_mappings(task_t task)
{
	int     n;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * this function is used to strip all of the mappings from
	 * the pmap for the specified task to force the task to
	 * re-fault all of the pages it is actively using... this
	 * allows us to approximate the true working set of the
	 * specified task.  We only engage if at least 1 of the
	 * threads in the task is runnable, but we want to continuously
	 * sweep (at least for a while - I've arbitrarily set the limit at
	 * 100 sweeps to be re-looked at as we gain experience) to get a better
	 * view into what areas within a page are being visited (as opposed to only
	 * seeing the first fault of a page after the task becomes
	 * runnable)...  in the future I may
	 * try to block until awakened by a thread in this task
	 * being made runnable, but for now we'll periodically poll from the
	 * user level debug tool driving the sysctl
	 */
	for (n = 0; n < 100; n++) {
		thread_t        thread;
		boolean_t       runnable;
		boolean_t       do_unnest;
		int             page_count;

		runnable = FALSE;
		do_unnest = FALSE;

		task_lock(task);

		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			if (thread->state & TH_RUN) {
				runnable = TRUE;
				break;
			}
		}
		if (n == 0) {
			task->task_disconnected_count++;
		}

		if (task->task_unnested == FALSE) {
			if (runnable == TRUE) {
				task->task_unnested = TRUE;
				do_unnest = TRUE;
			}
		}
		task_unlock(task);

		if (runnable == FALSE) {
			break;
		}

		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (MACHDBG_CODE(DBG_MACH_WORKINGSET, VM_DISCONNECT_TASK_PAGE_MAPPINGS)) | DBG_FUNC_START,
		    task, do_unnest, task->task_disconnected_count, 0, 0);

		page_count = vm_map_disconnect_page_mappings(task->map, do_unnest);

		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (MACHDBG_CODE(DBG_MACH_WORKINGSET, VM_DISCONNECT_TASK_PAGE_MAPPINGS)) | DBG_FUNC_END,
		    task, page_count, 0, 0, 0);

		if ((n % 5) == 4) {
			IOSleep(1);
		}
	}
	return KERN_SUCCESS;
}

#endif


#if CONFIG_FREEZE

/*
 *	task_freeze:
 *
 *	Freeze a task.
 *
 * Conditions:
 *      The caller holds a reference to the task
 */
extern void             vm_wake_compactor_swapper(void);
extern queue_head_t     c_swapout_list_head;

kern_return_t
task_freeze(
	task_t    task,
	uint32_t           *purgeable_count,
	uint32_t           *wired_count,
	uint32_t           *clean_count,
	uint32_t           *dirty_count,
	uint32_t           dirty_budget,
	uint32_t           *shared_count,
	int                *freezer_error_code,
	boolean_t          eval_only)
{
	kern_return_t kr = KERN_SUCCESS;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);

	while (task->changing_freeze_state) {
		assert_wait((event_t)&task->changing_freeze_state, THREAD_UNINT);
		task_unlock(task);
		thread_block(THREAD_CONTINUE_NULL);

		task_lock(task);
	}
	if (task->frozen) {
		task_unlock(task);
		return KERN_FAILURE;
	}
	task->changing_freeze_state = TRUE;

	task_unlock(task);

	kr = vm_map_freeze(task,
	    purgeable_count,
	    wired_count,
	    clean_count,
	    dirty_count,
	    dirty_budget,
	    shared_count,
	    freezer_error_code,
	    eval_only);

	task_lock(task);

	if ((kr == KERN_SUCCESS) && (eval_only == FALSE)) {
		task->frozen = TRUE;
	}

	task->changing_freeze_state = FALSE;
	thread_wakeup(&task->changing_freeze_state);

	task_unlock(task);

	if (VM_CONFIG_COMPRESSOR_IS_PRESENT &&
	    (kr == KERN_SUCCESS) &&
	    (eval_only == FALSE)) {
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

	return kr;
}

/*
 *	task_thaw:
 *
 *	Thaw a currently frozen task.
 *
 * Conditions:
 *      The caller holds a reference to the task
 */
kern_return_t
task_thaw(
	task_t          task)
{
	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);

	while (task->changing_freeze_state) {
		assert_wait((event_t)&task->changing_freeze_state, THREAD_UNINT);
		task_unlock(task);
		thread_block(THREAD_CONTINUE_NULL);

		task_lock(task);
	}
	if (!task->frozen) {
		task_unlock(task);
		return KERN_FAILURE;
	}
	task->frozen = FALSE;

	task_unlock(task);

	return KERN_SUCCESS;
}

#endif /* CONFIG_FREEZE */

kern_return_t
host_security_set_task_token(
	host_security_t  host_security,
	task_t           task,
	security_token_t sec_token,
	audit_token_t    audit_token,
	host_priv_t      host_priv)
{
	ipc_port_t       host_port;
	kern_return_t    kr;

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (host_security == HOST_NULL) {
		return KERN_INVALID_SECURITY;
	}

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

	kr = task_set_special_port_internal(task, TASK_HOST_PORT, host_port);
	return kr;
}

kern_return_t
task_send_trace_memory(
	__unused task_t   target_task,
	__unused uint32_t pid,
	__unused uint64_t uniqueid)
{
	return KERN_INVALID_ARGUMENT;
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
	task_t          task,
	task_flavor_t   flavor,
	__unused task_info_t    task_info_in,           /* pointer to IN array */
	__unused mach_msg_type_number_t task_info_count)
{
	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	switch (flavor) {
#if CONFIG_ATM
	case TASK_TRACE_MEMORY_INFO:
	{
		if (task_info_count != TASK_TRACE_MEMORY_INFO_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		assert(task_info_in != NULL);
		task_trace_memory_info_t mem_info;
		mem_info = (task_trace_memory_info_t) task_info_in;
		kern_return_t kr = atm_register_trace_memory(task,
		    mem_info->user_memory_address,
		    mem_info->buffer_size);
		return kr;
	}

#endif
	default:
		return KERN_INVALID_ARGUMENT;
	}
	return KERN_SUCCESS;
}

int radar_20146450 = 1;
kern_return_t
task_info(
	task_t                  task,
	task_flavor_t           flavor,
	task_info_t             task_info_out,
	mach_msg_type_number_t  *task_info_count)
{
	kern_return_t error = KERN_SUCCESS;
	mach_msg_type_number_t  original_task_info_count;

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	original_task_info_count = *task_info_count;
	task_lock(task);

	if ((task != current_task()) && (!task->active)) {
		task_unlock(task);
		return KERN_INVALID_ARGUMENT;
	}

	switch (flavor) {
	case TASK_BASIC_INFO_32:
	case TASK_BASIC2_INFO_32:
#if defined(__arm__) || defined(__arm64__)
	case TASK_BASIC_INFO_64:
#endif
		{
			task_basic_info_32_t    basic_info;
			vm_map_t                                map;
			clock_sec_t                             secs;
			clock_usec_t                    usecs;

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

#if defined(__arm__) || defined(__arm64__)
	case TASK_BASIC_INFO_64_2:
	{
		task_basic_info_64_2_t  basic_info;
		vm_map_t                                map;
		clock_sec_t                             secs;
		clock_usec_t                    usecs;

		if (*task_info_count < TASK_BASIC_INFO_64_2_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		basic_info = (task_basic_info_64_2_t)task_info_out;

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

		*task_info_count = TASK_BASIC_INFO_64_2_COUNT;
		break;
	}

#else /* defined(__arm__) || defined(__arm64__) */
	case TASK_BASIC_INFO_64:
	{
		task_basic_info_64_t    basic_info;
		vm_map_t                                map;
		clock_sec_t                             secs;
		clock_usec_t                    usecs;

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
#endif /* defined(__arm__) || defined(__arm64__) */

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
		task_thread_times_info_t        times_info;
		thread_t                                        thread;

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
			time_value_t    user_time, system_time;

			if (thread->options & TH_OPT_IDLE_THREAD) {
				continue;
			}

			thread_read_times(thread, &user_time, &system_time, NULL);

			time_value_add(&times_info->user_time, &user_time);
			time_value_add(&times_info->system_time, &system_time);
		}

		*task_info_count = TASK_THREAD_TIMES_INFO_COUNT;
		break;
	}

	case TASK_ABSOLUTETIME_INFO:
	{
		task_absolutetime_info_t        info;
		thread_t                        thread;

		if (*task_info_count < TASK_ABSOLUTETIME_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		info = (task_absolutetime_info_t)task_info_out;
		info->threads_user = info->threads_system = 0;


		info->total_user = task->total_user_time;
		info->total_system = task->total_system_time;

		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			uint64_t        tval;
			spl_t           x;

			if (thread->options & TH_OPT_IDLE_THREAD) {
				continue;
			}

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
			info->all_image_info_format = task_has_64Bit_addr(task) ?
			    TASK_DYLD_ALL_IMAGE_INFO_64 :
			    TASK_DYLD_ALL_IMAGE_INFO_32;
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
		task_kernelmemory_info_t        tkm_info;
		ledger_amount_t                 credit, debit;

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
		policy_rr_base_t        rr_base;
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
		policy_timeshare_base_t ts_base;

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
		security_token_t        *sec_token_p;

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
		audit_token_t   *audit_token_p;

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
		task_events_info_t      events_info;
		thread_t                        thread;

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
			events_info->csw           += thread->c_switch;
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

		task_power_info_locked(task, (task_power_info_t)task_info_out, NULL, NULL, NULL);
		break;
	}

	case TASK_POWER_INFO_V2:
	{
		if (*task_info_count < TASK_POWER_INFO_V2_COUNT_OLD) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}
		task_power_info_v2_t tpiv2 = (task_power_info_v2_t) task_info_out;
		task_power_info_locked(task, &tpiv2->cpu_energy, &tpiv2->gpu_energy, tpiv2, NULL);
		break;
	}

	case TASK_VM_INFO:
	case TASK_VM_INFO_PURGEABLE:
	{
		task_vm_info_t          vm_info;
		vm_map_t                map;

#if __arm64__
		struct proc *p;
		uint32_t platform, sdk;
		p = current_proc();
		platform = proc_platform(p);
		sdk = proc_sdk(p);
		if (original_task_info_count > TASK_VM_INFO_REV2_COUNT &&
		    platform == PLATFORM_IOS &&
		    sdk != 0 &&
		    (sdk >> 16) <= 12) {
			/*
			 * Some iOS apps pass an incorrect value for
			 * task_info_count, expressed in number of bytes
			 * instead of number of "natural_t" elements.
			 * For the sake of backwards binary compatibility
			 * for apps built with an iOS12 or older SDK and using
			 * the "rev2" data structure, let's fix task_info_count
			 * for them, to avoid stomping past the actual end
			 * of their buffer.
			 */
#if DEVELOPMENT || DEBUG
			printf("%s:%d %d[%s] rdar://49484582 task_info_count %d -> %d platform %d sdk %d.%d.%d\n", __FUNCTION__, __LINE__, proc_pid(p), proc_name_address(p), original_task_info_count, TASK_VM_INFO_REV2_COUNT, platform, (sdk >> 16), ((sdk >> 8) & 0xff), (sdk & 0xff));
#endif /* DEVELOPMENT || DEBUG */
			DTRACE_VM4(workaround_task_vm_info_count,
			    mach_msg_type_number_t, original_task_info_count,
			    mach_msg_type_number_t, TASK_VM_INFO_REV2_COUNT,
			    uint32_t, platform,
			    uint32_t, sdk);
			original_task_info_count = TASK_VM_INFO_REV2_COUNT;
			*task_info_count = original_task_info_count;
		}
#endif /* __arm64__ */

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
			mach_vm_size_t  volatile_virtual_size;
			mach_vm_size_t  volatile_resident_size;
			mach_vm_size_t  volatile_compressed_size;
			mach_vm_size_t  volatile_pmap_size;
			mach_vm_size_t  volatile_compressed_pmap_size;
			kern_return_t   kr;

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
		}
		*task_info_count = TASK_VM_INFO_REV0_COUNT;

		if (original_task_info_count >= TASK_VM_INFO_REV1_COUNT) {
			vm_info->phys_footprint =
			    (mach_vm_size_t) get_task_phys_footprint(task);
			*task_info_count = TASK_VM_INFO_REV1_COUNT;
		}
		if (original_task_info_count >= TASK_VM_INFO_REV2_COUNT) {
			vm_info->min_address = map->min_offset;
			vm_info->max_address = map->max_offset;
			*task_info_count = TASK_VM_INFO_REV2_COUNT;
		}
		if (original_task_info_count >= TASK_VM_INFO_REV3_COUNT) {
			ledger_get_lifetime_max(task->ledger,
			    task_ledgers.phys_footprint,
			    &vm_info->ledger_phys_footprint_peak);
			ledger_get_balance(task->ledger,
			    task_ledgers.purgeable_nonvolatile,
			    &vm_info->ledger_purgeable_nonvolatile);
			ledger_get_balance(task->ledger,
			    task_ledgers.purgeable_nonvolatile_compressed,
			    &vm_info->ledger_purgeable_novolatile_compressed);
			ledger_get_balance(task->ledger,
			    task_ledgers.purgeable_volatile,
			    &vm_info->ledger_purgeable_volatile);
			ledger_get_balance(task->ledger,
			    task_ledgers.purgeable_volatile_compressed,
			    &vm_info->ledger_purgeable_volatile_compressed);
			ledger_get_balance(task->ledger,
			    task_ledgers.network_nonvolatile,
			    &vm_info->ledger_tag_network_nonvolatile);
			ledger_get_balance(task->ledger,
			    task_ledgers.network_nonvolatile_compressed,
			    &vm_info->ledger_tag_network_nonvolatile_compressed);
			ledger_get_balance(task->ledger,
			    task_ledgers.network_volatile,
			    &vm_info->ledger_tag_network_volatile);
			ledger_get_balance(task->ledger,
			    task_ledgers.network_volatile_compressed,
			    &vm_info->ledger_tag_network_volatile_compressed);
			ledger_get_balance(task->ledger,
			    task_ledgers.media_footprint,
			    &vm_info->ledger_tag_media_footprint);
			ledger_get_balance(task->ledger,
			    task_ledgers.media_footprint_compressed,
			    &vm_info->ledger_tag_media_footprint_compressed);
			ledger_get_balance(task->ledger,
			    task_ledgers.media_nofootprint,
			    &vm_info->ledger_tag_media_nofootprint);
			ledger_get_balance(task->ledger,
			    task_ledgers.media_nofootprint_compressed,
			    &vm_info->ledger_tag_media_nofootprint_compressed);
			ledger_get_balance(task->ledger,
			    task_ledgers.graphics_footprint,
			    &vm_info->ledger_tag_graphics_footprint);
			ledger_get_balance(task->ledger,
			    task_ledgers.graphics_footprint_compressed,
			    &vm_info->ledger_tag_graphics_footprint_compressed);
			ledger_get_balance(task->ledger,
			    task_ledgers.graphics_nofootprint,
			    &vm_info->ledger_tag_graphics_nofootprint);
			ledger_get_balance(task->ledger,
			    task_ledgers.graphics_nofootprint_compressed,
			    &vm_info->ledger_tag_graphics_nofootprint_compressed);
			ledger_get_balance(task->ledger,
			    task_ledgers.neural_footprint,
			    &vm_info->ledger_tag_neural_footprint);
			ledger_get_balance(task->ledger,
			    task_ledgers.neural_footprint_compressed,
			    &vm_info->ledger_tag_neural_footprint_compressed);
			ledger_get_balance(task->ledger,
			    task_ledgers.neural_nofootprint,
			    &vm_info->ledger_tag_neural_nofootprint);
			ledger_get_balance(task->ledger,
			    task_ledgers.neural_nofootprint_compressed,
			    &vm_info->ledger_tag_neural_nofootprint_compressed);
			*task_info_count = TASK_VM_INFO_REV3_COUNT;
		}
		if (original_task_info_count >= TASK_VM_INFO_REV4_COUNT) {
			if (task->bsd_info) {
				vm_info->limit_bytes_remaining =
				    memorystatus_available_memory_internal(task->bsd_info);
			} else {
				vm_info->limit_bytes_remaining = 0;
			}
			*task_info_count = TASK_VM_INFO_REV4_COUNT;
		}
		if (original_task_info_count >= TASK_VM_INFO_REV5_COUNT) {
			thread_t thread;
			integer_t total = task->decompressions;
			queue_iterate(&task->threads, thread, thread_t, task_threads) {
				total += thread->decompressions;
			}
			vm_info->decompressions = total;
			*task_info_count = TASK_VM_INFO_REV5_COUNT;
		}

		if (task != kernel_task) {
			vm_map_unlock_read(map);
		}

		break;
	}

	case TASK_WAIT_STATE_INFO:
	{
		/*
		 * Deprecated flavor. Currently allowing some results until all users
		 * stop calling it. The results may not be accurate.
		 */
		task_wait_state_info_t  wait_state_info;
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

		for (i = 0; i < MAX_SFI_CLASS_ID; i++) {
			val_credit = 0;
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
		pvm_account_info_t      acnt_info;

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
		task_flags_info_t               flags_info;

		if (*task_info_count < TASK_FLAGS_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		flags_info = (task_flags_info_t)task_info_out;

		/* only publish the 64-bit flag of the task */
		flags_info->flags = task->t_flags & (TF_64B_ADDR | TF_64B_DATA);

		*task_info_count = TASK_FLAGS_INFO_COUNT;
		break;
	}

	case TASK_DEBUG_INFO_INTERNAL:
	{
#if DEVELOPMENT || DEBUG
		task_debug_info_internal_t dbg_info;
		ipc_space_t space = task->itk_space;
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

		if (space) {
			is_read_lock(space);
			dbg_info->ipc_space_size = space->is_table_size;
			is_read_unlock(space);
		}

		dbg_info->suspend_count = task->suspend_count;

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
	return error;
}

/*
 * task_info_from_user
 *
 * When calling task_info from user space,
 * this function will be executed as mig server side
 * instead of calling directly into task_info.
 * This gives the possibility to perform more security
 * checks on task_port.
 *
 * In the case of TASK_DYLD_INFO, we require the more
 * privileged task_port not the less-privileged task_name_port.
 *
 */
kern_return_t
task_info_from_user(
	mach_port_t             task_port,
	task_flavor_t           flavor,
	task_info_t             task_info_out,
	mach_msg_type_number_t  *task_info_count)
{
	task_t task;
	kern_return_t ret;

	if (flavor == TASK_DYLD_INFO) {
		task = convert_port_to_task(task_port);
	} else {
		task = convert_port_to_task_name(task_port);
	}

	ret = task_info(task, flavor, task_info_out, task_info_count);

	task_deallocate(task);

	return ret;
}

/*
 *	task_power_info
 *
 *	Returns power stats for the task.
 *	Note: Called with task locked.
 */
void
task_power_info_locked(
	task_t                  task,
	task_power_info_t       info,
	gpu_energy_data_t       ginfo,
	task_power_info_v2_t    infov2,
	uint64_t                *runnable_time)
{
	thread_t                thread;
	ledger_amount_t         tmp;

	uint64_t                runnable_time_sum = 0;

	task_lock_assert_owned(task);

	ledger_get_entries(task->ledger, task_ledgers.interrupt_wakeups,
	    (ledger_amount_t *)&info->task_interrupt_wakeups, &tmp);
	ledger_get_entries(task->ledger, task_ledgers.platform_idle_wakeups,
	    (ledger_amount_t *)&info->task_platform_idle_wakeups, &tmp);

	info->task_timer_wakeups_bin_1 = task->task_timer_wakeups_bin_1;
	info->task_timer_wakeups_bin_2 = task->task_timer_wakeups_bin_2;

	info->total_user = task->total_user_time;
	info->total_system = task->total_system_time;
	runnable_time_sum = task->total_runnable_time;

#if CONFIG_EMBEDDED
	if (infov2) {
		infov2->task_energy = task->task_energy;
	}
#endif

	if (ginfo) {
		ginfo->task_gpu_utilisation = task->task_gpu_ns;
	}

	if (infov2) {
		infov2->task_ptime = task->total_ptime;
		infov2->task_pset_switches = task->ps_switch;
	}

	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		uint64_t        tval;
		spl_t           x;

		if (thread->options & TH_OPT_IDLE_THREAD) {
			continue;
		}

		x = splsched();
		thread_lock(thread);

		info->task_timer_wakeups_bin_1 += thread->thread_timer_wakeups_bin_1;
		info->task_timer_wakeups_bin_2 += thread->thread_timer_wakeups_bin_2;

#if CONFIG_EMBEDDED
		if (infov2) {
			infov2->task_energy += ml_energy_stat(thread);
		}
#endif

		tval = timer_grab(&thread->user_timer);
		info->total_user += tval;

		if (infov2) {
			tval = timer_grab(&thread->ptime);
			infov2->task_ptime += tval;
			infov2->task_pset_switches += thread->ps_switch;
		}

		tval = timer_grab(&thread->system_timer);
		if (thread->precise_user_kernel_time) {
			info->total_system += tval;
		} else {
			/* system_timer may represent either sys or user */
			info->total_user += tval;
		}

		tval = timer_grab(&thread->runnable_timer);

		runnable_time_sum += tval;

		if (ginfo) {
			ginfo->task_gpu_utilisation += ml_gpu_stat(thread);
		}
		thread_unlock(thread);
		splx(x);
	}

	if (runnable_time) {
		*runnable_time = runnable_time_sum;
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
	task_t  task)
{
	uint64_t gpu_time = 0;
#if !CONFIG_EMBEDDED
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
#else /* CONFIG_EMBEDDED */
	/* silence compiler warning */
	(void)task;
#endif /* !CONFIG_EMBEDDED */
	return gpu_time;
}

/*
 *	task_energy
 *
 *	Returns the total energy used by the all the threads of the task
 *  (both dead and alive)
 */
uint64_t
task_energy(
	task_t  task)
{
	uint64_t energy = 0;
	thread_t thread;

	task_lock(task);
	energy += task->task_energy;

	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		spl_t x;
		x = splsched();
		thread_lock(thread);
		energy += ml_energy_stat(thread);
		thread_unlock(thread);
		splx(x);
	}

	task_unlock(task);
	return energy;
}

#if __AMP__

uint64_t
task_cpu_ptime(
	task_t  task)
{
	uint64_t cpu_ptime = 0;
	thread_t thread;

	task_lock(task);
	cpu_ptime += task->total_ptime;

	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		cpu_ptime += timer_grab(&thread->ptime);
	}

	task_unlock(task);
	return cpu_ptime;
}

#else /* __AMP__ */

uint64_t
task_cpu_ptime(
	__unused task_t  task)
{
	return 0;
}

#endif /* __AMP__ */

/* This function updates the cpu time in the arrays for each
 * effective and requested QoS class
 */
void
task_update_cpu_time_qos_stats(
	task_t  task,
	uint64_t *eqos_stats,
	uint64_t *rqos_stats)
{
	if (!eqos_stats && !rqos_stats) {
		return;
	}

	task_lock(task);
	thread_t thread;
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		if (thread->options & TH_OPT_IDLE_THREAD) {
			continue;
		}

		thread_update_qos_cpu_time(thread);
	}

	if (eqos_stats) {
		eqos_stats[THREAD_QOS_DEFAULT] += task->cpu_time_eqos_stats.cpu_time_qos_default;
		eqos_stats[THREAD_QOS_MAINTENANCE] += task->cpu_time_eqos_stats.cpu_time_qos_maintenance;
		eqos_stats[THREAD_QOS_BACKGROUND] += task->cpu_time_eqos_stats.cpu_time_qos_background;
		eqos_stats[THREAD_QOS_UTILITY] += task->cpu_time_eqos_stats.cpu_time_qos_utility;
		eqos_stats[THREAD_QOS_LEGACY] += task->cpu_time_eqos_stats.cpu_time_qos_legacy;
		eqos_stats[THREAD_QOS_USER_INITIATED] += task->cpu_time_eqos_stats.cpu_time_qos_user_initiated;
		eqos_stats[THREAD_QOS_USER_INTERACTIVE] += task->cpu_time_eqos_stats.cpu_time_qos_user_interactive;
	}

	if (rqos_stats) {
		rqos_stats[THREAD_QOS_DEFAULT] += task->cpu_time_rqos_stats.cpu_time_qos_default;
		rqos_stats[THREAD_QOS_MAINTENANCE] += task->cpu_time_rqos_stats.cpu_time_qos_maintenance;
		rqos_stats[THREAD_QOS_BACKGROUND] += task->cpu_time_rqos_stats.cpu_time_qos_background;
		rqos_stats[THREAD_QOS_UTILITY] += task->cpu_time_rqos_stats.cpu_time_qos_utility;
		rqos_stats[THREAD_QOS_LEGACY] += task->cpu_time_rqos_stats.cpu_time_qos_legacy;
		rqos_stats[THREAD_QOS_USER_INITIATED] += task->cpu_time_rqos_stats.cpu_time_qos_user_initiated;
		rqos_stats[THREAD_QOS_USER_INTERACTIVE] += task->cpu_time_rqos_stats.cpu_time_qos_user_interactive;
	}

	task_unlock(task);
}

kern_return_t
task_purgable_info(
	task_t                  task,
	task_purgable_info_t    *stats)
{
	if (task == TASK_NULL || stats == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	/* Take task reference */
	task_reference(task);
	vm_purgeable_stats((vm_purgeable_info_t)stats, task);
	/* Drop task reference */
	task_deallocate(task);
	return KERN_SUCCESS;
}

void
task_vtimer_set(
	task_t          task,
	integer_t       which)
{
	thread_t        thread;
	spl_t           x;

	task_lock(task);

	task->vtimers |= which;

	switch (which) {
	case TASK_VTIMER_USER:
		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			x = splsched();
			thread_lock(thread);
			if (thread->precise_user_kernel_time) {
				thread->vtimer_user_save = timer_grab(&thread->user_timer);
			} else {
				thread->vtimer_user_save = timer_grab(&thread->system_timer);
			}
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
	task_t          task,
	integer_t       which)
{
	assert(task == current_task());

	task_lock(task);

	task->vtimers &= ~which;

	task_unlock(task);
}

void
task_vtimer_update(
	__unused
	task_t          task,
	integer_t       which,
	uint32_t        *microsecs)
{
	thread_t        thread = current_thread();
	uint32_t        tdelt = 0;
	clock_sec_t     secs = 0;
	uint64_t        tsum;

	assert(task == current_task());

	spl_t s = splsched();
	thread_lock(thread);

	if ((task->vtimers & which) != (uint32_t)which) {
		thread_unlock(thread);
		splx(s);
		return;
	}

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
		if (*microsecs != 0) {
			thread->vtimer_prof_save = tsum;
		}
		break;

	case TASK_VTIMER_RLIM:
		tsum = timer_grab(&thread->user_timer);
		tsum += timer_grab(&thread->system_timer);
		tdelt = (uint32_t)(tsum - thread->vtimer_rlim_save);
		thread->vtimer_rlim_save = tsum;
		absolutetime_to_microtime(tdelt, &secs, microsecs);
		break;
	}

	thread_unlock(thread);
	splx(s);
}

/*
 *	task_assign:
 *
 *	Change the assigned processor set for the task
 */
kern_return_t
task_assign(
	__unused task_t         task,
	__unused processor_set_t        new_pset,
	__unused boolean_t      assign_threads)
{
	return KERN_FAILURE;
}

/*
 *	task_assign_default:
 *
 *	Version of task_assign to assign to default processor set.
 */
kern_return_t
task_assign_default(
	task_t          task,
	boolean_t       assign_threads)
{
	return task_assign(task, &pset0, assign_threads);
}

/*
 *	task_get_assignment
 *
 *	Return name of processor set that task is assigned to.
 */
kern_return_t
task_get_assignment(
	task_t          task,
	processor_set_t *pset)
{
	if (!task || !task->active) {
		return KERN_FAILURE;
	}

	*pset = &pset0;

	return KERN_SUCCESS;
}

uint64_t
get_task_dispatchqueue_offset(
	task_t          task)
{
	return task->dispatchqueue_offset;
}

/*
 *      task_policy
 *
 *	Set scheduling policy and parameters, both base and limit, for
 *	the given task. Policy must be a policy which is enabled for the
 *	processor set. Change contained threads if requested.
 */
kern_return_t
task_policy(
	__unused task_t                 task,
	__unused policy_t                       policy_id,
	__unused policy_base_t          base,
	__unused mach_msg_type_number_t count,
	__unused boolean_t                      set_limit,
	__unused boolean_t                      change)
{
	return KERN_FAILURE;
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
	__unused task_t                 task,
	__unused processor_set_t                pset,
	__unused policy_t                       policy_id,
	__unused policy_base_t          base,
	__unused mach_msg_type_number_t base_count,
	__unused policy_limit_t         limit,
	__unused mach_msg_type_number_t limit_count,
	__unused boolean_t                      change)
{
	return KERN_FAILURE;
}

kern_return_t
task_set_ras_pc(
	__unused task_t task,
	__unused vm_offset_t    pc,
	__unused vm_offset_t    endpc)
{
	return KERN_FAILURE;
}

void
task_synchronizer_destroy_all(task_t task)
{
	/*
	 *  Destroy owned semaphores
	 */
	semaphore_destroy_all(task);
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
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);

	if (!task->active) {
		task_unlock(task);
		return KERN_FAILURE;
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
	task_t  task,
	int     flavor,
	thread_state_t state,
	mach_msg_type_number_t *state_count)
{
	kern_return_t ret;

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);

	if (!task->active) {
		task_unlock(task);
		return KERN_FAILURE;
	}

	ret = machine_task_get_state(task, flavor, state, state_count);

	task_unlock(task);
	return ret;
}


static kern_return_t __attribute__((noinline, not_tail_called))
PROC_VIOLATED_GUARD__SEND_EXC_GUARD_AND_SUSPEND(
	mach_exception_code_t code,
	mach_exception_subcode_t subcode,
	void *reason)
{
#ifdef MACH_BSD
	if (1 == proc_selfpid()) {
		return KERN_NOT_SUPPORTED;              // initproc is immune
	}
#endif
	mach_exception_data_type_t codes[EXCEPTION_CODE_MAX] = {
		[0] = code,
		[1] = subcode,
	};
	task_t task = current_task();
	kern_return_t kr;

	/* (See jetsam-related comments below) */

	proc_memstat_terminated(task->bsd_info, TRUE);
	kr = task_enqueue_exception_with_corpse(task, EXC_GUARD, codes, 2, reason);
	proc_memstat_terminated(task->bsd_info, FALSE);
	return kr;
}

kern_return_t
task_violated_guard(
	mach_exception_code_t code,
	mach_exception_subcode_t subcode,
	void *reason)
{
	return PROC_VIOLATED_GUARD__SEND_EXC_GUARD_AND_SUSPEND(code, subcode, reason);
}


#if CONFIG_MEMORYSTATUS

boolean_t
task_get_memlimit_is_active(task_t task)
{
	assert(task != NULL);

	if (task->memlimit_is_active == 1) {
		return TRUE;
	} else {
		return FALSE;
	}
}

void
task_set_memlimit_is_active(task_t task, boolean_t memlimit_is_active)
{
	assert(task != NULL);

	if (memlimit_is_active) {
		task->memlimit_is_active = 1;
	} else {
		task->memlimit_is_active = 0;
	}
}

boolean_t
task_get_memlimit_is_fatal(task_t task)
{
	assert(task != NULL);

	if (task->memlimit_is_fatal == 1) {
		return TRUE;
	} else {
		return FALSE;
	}
}

void
task_set_memlimit_is_fatal(task_t task, boolean_t memlimit_is_fatal)
{
	assert(task != NULL);

	if (memlimit_is_fatal) {
		task->memlimit_is_fatal = 1;
	} else {
		task->memlimit_is_fatal = 0;
	}
}

boolean_t
task_has_triggered_exc_resource(task_t task, boolean_t memlimit_is_active)
{
	boolean_t triggered = FALSE;

	assert(task == current_task());

	/*
	 * Returns true, if task has already triggered an exc_resource exception.
	 */

	if (memlimit_is_active) {
		triggered = (task->memlimit_active_exc_resource ? TRUE : FALSE);
	} else {
		triggered = (task->memlimit_inactive_exc_resource ? TRUE : FALSE);
	}

	return triggered;
}

void
task_mark_has_triggered_exc_resource(task_t task, boolean_t memlimit_is_active)
{
	assert(task == current_task());

	/*
	 * We allow one exc_resource per process per active/inactive limit.
	 * The limit's fatal attribute does not come into play.
	 */

	if (memlimit_is_active) {
		task->memlimit_active_exc_resource = 1;
	} else {
		task->memlimit_inactive_exc_resource = 1;
	}
}

#define HWM_USERCORE_MINSPACE 250 // free space (in MB) required *after* core file creation

void __attribute__((noinline))
PROC_CROSSED_HIGH_WATERMARK__SEND_EXC_RESOURCE_AND_SUSPEND(int max_footprint_mb, boolean_t is_fatal)
{
	task_t                                          task            = current_task();
	int                                                     pid         = 0;
	const char                                      *procname       = "unknown";
	mach_exception_data_type_t      code[EXCEPTION_CODE_MAX];
	boolean_t send_sync_exc_resource = FALSE;

#ifdef MACH_BSD
	pid = proc_selfpid();

	if (pid == 1) {
		/*
		 * Cannot have ReportCrash analyzing
		 * a suspended initproc.
		 */
		return;
	}

	if (task->bsd_info != NULL) {
		procname = proc_name_address(current_task()->bsd_info);
		send_sync_exc_resource = proc_send_synchronous_EXC_RESOURCE(current_task()->bsd_info);
	}
#endif
#if CONFIG_COREDUMP
	if (hwm_user_cores) {
		int                             error;
		uint64_t                starttime, end;
		clock_sec_t             secs = 0;
		uint32_t                microsecs = 0;

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
#endif /* CONFIG_COREDUMP */

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

	code[0] = code[1] = 0;
	EXC_RESOURCE_ENCODE_TYPE(code[0], RESOURCE_TYPE_MEMORY);
	EXC_RESOURCE_ENCODE_FLAVOR(code[0], FLAVOR_HIGH_WATERMARK);
	EXC_RESOURCE_HWM_ENCODE_LIMIT(code[0], max_footprint_mb);

	/*
	 * Do not generate a corpse fork if the violation is a fatal one
	 * or the process wants synchronous EXC_RESOURCE exceptions.
	 */
	if (is_fatal || send_sync_exc_resource || exc_via_corpse_forking == 0) {
		/* Do not send a EXC_RESOURCE if corpse_for_fatal_memkill is set */
		if (send_sync_exc_resource || corpse_for_fatal_memkill == 0) {
			/*
			 * Use the _internal_ variant so that no user-space
			 * process can resume our task from under us.
			 */
			task_suspend_internal(task);
			exception_triage(EXC_RESOURCE, code, EXCEPTION_CODE_MAX);
			task_resume_internal(task);
		}
	} else {
		if (audio_active) {
			printf("process %s[%d] crossed memory high watermark (%d MB); EXC_RESOURCE "
			    "supressed due to audio playback.\n", procname, pid, max_footprint_mb);
		} else {
			task_enqueue_exception_with_corpse(task, EXC_RESOURCE,
			    code, EXCEPTION_CODE_MAX, NULL);
		}
	}

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
	task_t task;
	boolean_t is_warning;
	boolean_t memlimit_is_active;
	boolean_t memlimit_is_fatal;

	if (warning == LEDGER_WARNING_DIPPED_BELOW) {
		/*
		 * Task memory limits only provide a warning on the way up.
		 */
		return;
	} else if (warning == LEDGER_WARNING_ROSE_ABOVE) {
		/*
		 * This task is in danger of violating a memory limit,
		 * It has exceeded a percentage level of the limit.
		 */
		is_warning = TRUE;
	} else {
		/*
		 * The task has exceeded the physical footprint limit.
		 * This is not a warning but a true limit violation.
		 */
		is_warning = FALSE;
	}

	task = current_task();

	ledger_get_limit(task->ledger, task_ledgers.phys_footprint, &max_footprint);
	max_footprint_mb = max_footprint >> 20;

	memlimit_is_active = task_get_memlimit_is_active(task);
	memlimit_is_fatal = task_get_memlimit_is_fatal(task);

	/*
	 * If this is an actual violation (not a warning), then generate EXC_RESOURCE exception.
	 * We only generate the exception once per process per memlimit (active/inactive limit).
	 * To enforce this, we monitor state based on the  memlimit's active/inactive attribute
	 * and we disable it by marking that memlimit as exception triggered.
	 */
	if ((is_warning == FALSE) && (!task_has_triggered_exc_resource(task, memlimit_is_active))) {
		PROC_CROSSED_HIGH_WATERMARK__SEND_EXC_RESOURCE_AND_SUSPEND((int)max_footprint_mb, memlimit_is_fatal);
		memorystatus_log_exception((int)max_footprint_mb, memlimit_is_active, memlimit_is_fatal);
		task_mark_has_triggered_exc_resource(task, memlimit_is_active);
	}

	memorystatus_on_ledger_footprint_exceeded(is_warning, memlimit_is_active, memlimit_is_fatal);
}

extern int proc_check_footprint_priv(void);

kern_return_t
task_set_phys_footprint_limit(
	task_t task,
	int new_limit_mb,
	int *old_limit_mb)
{
	kern_return_t error;

	boolean_t memlimit_is_active;
	boolean_t memlimit_is_fatal;

	if ((error = proc_check_footprint_priv())) {
		return KERN_NO_ACCESS;
	}

	/*
	 * This call should probably be obsoleted.
	 * But for now, we default to current state.
	 */
	memlimit_is_active = task_get_memlimit_is_active(task);
	memlimit_is_fatal = task_get_memlimit_is_fatal(task);

	return task_set_phys_footprint_limit_internal(task, new_limit_mb, old_limit_mb, memlimit_is_active, memlimit_is_fatal);
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
	return KERN_SUCCESS;
}


kern_return_t
task_set_phys_footprint_limit_internal(
	task_t task,
	int new_limit_mb,
	int *old_limit_mb,
	boolean_t memlimit_is_active,
	boolean_t memlimit_is_fatal)
{
	ledger_amount_t old;
	kern_return_t ret;

	ret = ledger_get_limit(task->ledger, task_ledgers.phys_footprint, &old);

	if (ret != KERN_SUCCESS) {
		return ret;
	}

	/*
	 * Check that limit >> 20 will not give an "unexpected" 32-bit
	 * result. There are, however, implicit assumptions that -1 mb limit
	 * equates to LEDGER_LIMIT_INFINITY.
	 */
	assert(((old & 0xFFF0000000000000LL) == 0) || (old == LEDGER_LIMIT_INFINITY));

	if (old_limit_mb) {
		*old_limit_mb = (int)(old >> 20);
	}

	if (new_limit_mb == -1) {
		/*
		 * Caller wishes to remove the limit.
		 */
		ledger_set_limit(task->ledger, task_ledgers.phys_footprint,
		    max_task_footprint ? max_task_footprint : LEDGER_LIMIT_INFINITY,
		    max_task_footprint ? max_task_footprint_warning_level : 0);

		task_lock(task);
		task_set_memlimit_is_active(task, memlimit_is_active);
		task_set_memlimit_is_fatal(task, memlimit_is_fatal);
		task_unlock(task);

		return KERN_SUCCESS;
	}

#ifdef CONFIG_NOMONITORS
	return KERN_SUCCESS;
#endif /* CONFIG_NOMONITORS */

	task_lock(task);

	if ((memlimit_is_active == task_get_memlimit_is_active(task)) &&
	    (memlimit_is_fatal == task_get_memlimit_is_fatal(task)) &&
	    (((ledger_amount_t)new_limit_mb << 20) == old)) {
		/*
		 * memlimit state is not changing
		 */
		task_unlock(task);
		return KERN_SUCCESS;
	}

	task_set_memlimit_is_active(task, memlimit_is_active);
	task_set_memlimit_is_fatal(task, memlimit_is_fatal);

	ledger_set_limit(task->ledger, task_ledgers.phys_footprint,
	    (ledger_amount_t)new_limit_mb << 20, PHYS_FOOTPRINT_WARNING_LEVEL);

	if (task == current_task()) {
		ledger_check_new_balance(current_thread(), task->ledger,
		    task_ledgers.phys_footprint);
	}

	task_unlock(task);

	return KERN_SUCCESS;
}

kern_return_t
task_get_phys_footprint_limit(
	task_t task,
	int *limit_mb)
{
	ledger_amount_t limit;
	kern_return_t ret;

	ret = ledger_get_limit(task->ledger, task_ledgers.phys_footprint, &limit);
	if (ret != KERN_SUCCESS) {
		return ret;
	}

	/*
	 * Check that limit >> 20 will not give an "unexpected" signed, 32-bit
	 * result. There are, however, implicit assumptions that -1 mb limit
	 * equates to LEDGER_LIMIT_INFINITY.
	 */
	assert(((limit & 0xFFF0000000000000LL) == 0) || (limit == LEDGER_LIMIT_INFINITY));
	*limit_mb = (int)(limit >> 20);

	return KERN_SUCCESS;
}
#else /* CONFIG_MEMORYSTATUS */
kern_return_t
task_set_phys_footprint_limit(
	__unused task_t task,
	__unused int new_limit_mb,
	__unused int *old_limit_mb)
{
	return KERN_FAILURE;
}

kern_return_t
task_get_phys_footprint_limit(
	__unused task_t task,
	__unused int *limit_mb)
{
	return KERN_FAILURE;
}
#endif /* CONFIG_MEMORYSTATUS */

void
task_set_thread_limit(task_t task, uint16_t thread_limit)
{
	assert(task != kernel_task);
	if (thread_limit <= TASK_MAX_THREAD_LIMIT) {
		task_lock(task);
		task->task_thread_limit = thread_limit;
		task_unlock(task);
	}
}

/*
 * We need to export some functions to other components that
 * are currently implemented in macros within the osfmk
 * component.  Just export them as functions of the same name.
 */
boolean_t
is_kerneltask(task_t t)
{
	if (t == kernel_task) {
		return TRUE;
	}

	return FALSE;
}

boolean_t
is_corpsetask(task_t t)
{
	return task_is_a_corpse(t);
}

#undef current_task
task_t current_task(void);
task_t
current_task(void)
{
	return current_task_fast();
}

#undef task_reference
void task_reference(task_t task);
void
task_reference(
	task_t          task)
{
	if (task != TASK_NULL) {
		task_reference_internal(task);
	}
}

/* defined in bsd/kern/kern_prot.c */
extern int get_audit_token_pid(audit_token_t *audit_token);

int
task_pid(task_t task)
{
	if (task) {
		return get_audit_token_pid(&task->audit_token);
	}
	return -1;
}


/*
 * This routine finds a thread in a task by its unique id
 * Returns a referenced thread or THREAD_NULL if the thread was not found
 *
 * TODO: This is super inefficient - it's an O(threads in task) list walk!
 *       We should make a tid hash, or transition all tid clients to thread ports
 *
 * Precondition: No locks held (will take task lock)
 */
thread_t
task_findtid(task_t task, uint64_t tid)
{
	thread_t self           = current_thread();
	thread_t found_thread   = THREAD_NULL;
	thread_t iter_thread    = THREAD_NULL;

	/* Short-circuit the lookup if we're looking up ourselves */
	if (tid == self->thread_id || tid == TID_NULL) {
		assert(self->task == task);

		thread_reference(self);

		return self;
	}

	task_lock(task);

	queue_iterate(&task->threads, iter_thread, thread_t, task_threads) {
		if (iter_thread->thread_id == tid) {
			found_thread = iter_thread;
			thread_reference(found_thread);
			break;
		}
	}

	task_unlock(task);

	return found_thread;
}

int
pid_from_task(task_t task)
{
	int pid = -1;

	if (task->bsd_info) {
		pid = proc_pid(task->bsd_info);
	} else {
		pid = task_pid(task);
	}

	return pid;
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
		ledger_amount_t limit;
		uint64_t                period;

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

		if (*rate_hz <= 0) {
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
		telemetry_task_ctl_locked(task, TF_WAKEMON_WARNING, 0);
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
		SENDING_NOTIFICATION__THIS_PROCESS_IS_CAUSING_TOO_MANY_WAKEUPS();
	}
}

void __attribute__((noinline))
SENDING_NOTIFICATION__THIS_PROCESS_IS_CAUSING_TOO_MANY_WAKEUPS(void)
{
	task_t                      task        = current_task();
	int                         pid         = 0;
	const char                  *procname   = "unknown";
	boolean_t                   fatal;
	kern_return_t               kr;
#ifdef EXC_RESOURCE_MONITORS
	mach_exception_data_type_t  code[EXCEPTION_CODE_MAX];
#endif /* EXC_RESOURCE_MONITORS */
	struct ledger_entry_info    lei;

#ifdef MACH_BSD
	pid = proc_selfpid();
	if (task->bsd_info != NULL) {
		procname = proc_name_address(current_task()->bsd_info);
	}
#endif

	ledger_get_entry_info(task->ledger, task_ledgers.interrupt_wakeups, &lei);

	/*
	 * Disable the exception notification so we don't overwhelm
	 * the listener with an endless stream of redundant exceptions.
	 * TODO: detect whether another thread is already reporting the violation.
	 */
	uint32_t flags = WAKEMON_DISABLE;
	task_wakeups_monitor_ctl(task, &flags, NULL);

	fatal = task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_FATAL_WAKEUPSMON;
	trace_resource_violation(RMON_CPUWAKES_VIOLATED, &lei);
	os_log(OS_LOG_DEFAULT, "process %s[%d] caught waking the CPU %llu times "
	    "over ~%llu seconds, averaging %llu wakes / second and "
	    "violating a %slimit of %llu wakes over %llu seconds.\n",
	    procname, pid,
	    lei.lei_balance, lei.lei_last_refill / NSEC_PER_SEC,
	    lei.lei_last_refill == 0 ? 0 :
	    (NSEC_PER_SEC * lei.lei_balance / lei.lei_last_refill),
	    fatal ? "FATAL " : "",
	    lei.lei_limit, lei.lei_refill_period / NSEC_PER_SEC);

	kr = send_resource_violation(send_cpu_wakes_violation, task, &lei,
	    fatal ? kRNFatalLimitFlag : 0);
	if (kr) {
		printf("send_resource_violation(CPU wakes, ...): error %#x\n", kr);
	}

#ifdef EXC_RESOURCE_MONITORS
	if (disable_exc_resource) {
		printf("process %s[%d] caught causing excessive wakeups. EXC_RESOURCE "
		    "supressed by a boot-arg\n", procname, pid);
		return;
	}
	if (audio_active) {
		os_log(OS_LOG_DEFAULT, "process %s[%d] caught causing excessive wakeups. EXC_RESOURCE "
		    "supressed due to audio playback\n", procname, pid);
		return;
	}
	if (lei.lei_last_refill == 0) {
		os_log(OS_LOG_DEFAULT, "process %s[%d] caught causing excessive wakeups. EXC_RESOURCE "
		    "supressed due to lei.lei_last_refill = 0 \n", procname, pid);
	}

	code[0] = code[1] = 0;
	EXC_RESOURCE_ENCODE_TYPE(code[0], RESOURCE_TYPE_WAKEUPS);
	EXC_RESOURCE_ENCODE_FLAVOR(code[0], FLAVOR_WAKEUPS_MONITOR);
	EXC_RESOURCE_CPUMONITOR_ENCODE_WAKEUPS_PERMITTED(code[0],
	    NSEC_PER_SEC * lei.lei_limit / lei.lei_refill_period);
	EXC_RESOURCE_CPUMONITOR_ENCODE_OBSERVATION_INTERVAL(code[0],
	    lei.lei_last_refill);
	EXC_RESOURCE_CPUMONITOR_ENCODE_WAKEUPS_OBSERVED(code[1],
	    NSEC_PER_SEC * lei.lei_balance / lei.lei_last_refill);
	exception_triage(EXC_RESOURCE, code, EXCEPTION_CODE_MAX);
#endif /* EXC_RESOURCE_MONITORS */

	if (fatal) {
		task_terminate_internal(task);
	}
}

static boolean_t
global_update_logical_writes(int64_t io_delta, int64_t *global_write_count)
{
	int64_t old_count, new_count;
	boolean_t needs_telemetry;

	do {
		new_count = old_count = *global_write_count;
		new_count += io_delta;
		if (new_count >= io_telemetry_limit) {
			new_count = 0;
			needs_telemetry = TRUE;
		} else {
			needs_telemetry = FALSE;
		}
	} while (!OSCompareAndSwap64(old_count, new_count, global_write_count));
	return needs_telemetry;
}

void
task_update_logical_writes(task_t task, uint32_t io_size, int flags, void *vp)
{
	int64_t io_delta = 0;
	int64_t * global_counter_to_update;
	boolean_t needs_telemetry = FALSE;
	boolean_t is_external_device = FALSE;
	int ledger_to_update = 0;
	struct task_writes_counters * writes_counters_to_update;

	if ((!task) || (!io_size) || (!vp)) {
		return;
	}

	KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, VM_DATA_WRITE)) | DBG_FUNC_NONE,
	    task_pid(task), io_size, flags, (uintptr_t)VM_KERNEL_ADDRPERM(vp), 0);
	DTRACE_IO4(logical_writes, struct task *, task, uint32_t, io_size, int, flags, vnode *, vp);

	// Is the drive backing this vnode internal or external to the system?
	if (vnode_isonexternalstorage(vp) == false) {
		global_counter_to_update = &global_logical_writes_count;
		ledger_to_update = task_ledgers.logical_writes;
		writes_counters_to_update = &task->task_writes_counters_internal;
		is_external_device = FALSE;
	} else {
		global_counter_to_update = &global_logical_writes_to_external_count;
		ledger_to_update = task_ledgers.logical_writes_to_external;
		writes_counters_to_update = &task->task_writes_counters_external;
		is_external_device = TRUE;
	}

	switch (flags) {
	case TASK_WRITE_IMMEDIATE:
		OSAddAtomic64(io_size, (SInt64 *)&(writes_counters_to_update->task_immediate_writes));
		ledger_credit(task->ledger, ledger_to_update, io_size);
		if (!is_external_device) {
			coalition_io_ledger_update(task, FLAVOR_IO_LOGICAL_WRITES, TRUE, io_size);
		}
		break;
	case TASK_WRITE_DEFERRED:
		OSAddAtomic64(io_size, (SInt64 *)&(writes_counters_to_update->task_deferred_writes));
		ledger_credit(task->ledger, ledger_to_update, io_size);
		if (!is_external_device) {
			coalition_io_ledger_update(task, FLAVOR_IO_LOGICAL_WRITES, TRUE, io_size);
		}
		break;
	case TASK_WRITE_INVALIDATED:
		OSAddAtomic64(io_size, (SInt64 *)&(writes_counters_to_update->task_invalidated_writes));
		ledger_debit(task->ledger, ledger_to_update, io_size);
		if (!is_external_device) {
			coalition_io_ledger_update(task, FLAVOR_IO_LOGICAL_WRITES, FALSE, io_size);
		}
		break;
	case TASK_WRITE_METADATA:
		OSAddAtomic64(io_size, (SInt64 *)&(writes_counters_to_update->task_metadata_writes));
		ledger_credit(task->ledger, ledger_to_update, io_size);
		if (!is_external_device) {
			coalition_io_ledger_update(task, FLAVOR_IO_LOGICAL_WRITES, TRUE, io_size);
		}
		break;
	}

	io_delta = (flags == TASK_WRITE_INVALIDATED) ? ((int64_t)io_size * -1ll) : ((int64_t)io_size);
	if (io_telemetry_limit != 0) {
		/* If io_telemetry_limit is 0, disable global updates and I/O telemetry */
		needs_telemetry = global_update_logical_writes(io_delta, global_counter_to_update);
		if (needs_telemetry && !is_external_device) {
			act_set_io_telemetry_ast(current_thread());
		}
	}
}

/*
 * Control the I/O monitor for a task.
 */
kern_return_t
task_io_monitor_ctl(task_t task, uint32_t *flags)
{
	ledger_t ledger = task->ledger;

	task_lock(task);
	if (*flags & IOMON_ENABLE) {
		/* Configure the physical I/O ledger */
		ledger_set_limit(ledger, task_ledgers.physical_writes, (task_iomon_limit_mb * 1024 * 1024), 0);
		ledger_set_period(ledger, task_ledgers.physical_writes, (task_iomon_interval_secs * NSEC_PER_SEC));
	} else if (*flags & IOMON_DISABLE) {
		/*
		 * Caller wishes to disable I/O monitor on the task.
		 */
		ledger_disable_refill(ledger, task_ledgers.physical_writes);
		ledger_disable_callback(ledger, task_ledgers.physical_writes);
	}

	task_unlock(task);
	return KERN_SUCCESS;
}

void
task_io_rate_exceeded(int warning, const void *param0, __unused const void *param1)
{
	if (warning == 0) {
		SENDING_NOTIFICATION__THIS_PROCESS_IS_CAUSING_TOO_MUCH_IO((int)param0);
	}
}

void __attribute__((noinline))
SENDING_NOTIFICATION__THIS_PROCESS_IS_CAUSING_TOO_MUCH_IO(int flavor)
{
	int                             pid = 0;
	task_t                          task = current_task();
#ifdef EXC_RESOURCE_MONITORS
	mach_exception_data_type_t      code[EXCEPTION_CODE_MAX];
#endif /* EXC_RESOURCE_MONITORS */
	struct ledger_entry_info        lei;
	kern_return_t                   kr;

#ifdef MACH_BSD
	pid = proc_selfpid();
#endif
	/*
	 * Get the ledger entry info. We need to do this before disabling the exception
	 * to get correct values for all fields.
	 */
	switch (flavor) {
	case FLAVOR_IO_PHYSICAL_WRITES:
		ledger_get_entry_info(task->ledger, task_ledgers.physical_writes, &lei);
		break;
	}


	/*
	 * Disable the exception notification so we don't overwhelm
	 * the listener with an endless stream of redundant exceptions.
	 * TODO: detect whether another thread is already reporting the violation.
	 */
	uint32_t flags = IOMON_DISABLE;
	task_io_monitor_ctl(task, &flags);

	if (flavor == FLAVOR_IO_LOGICAL_WRITES) {
		trace_resource_violation(RMON_LOGWRITES_VIOLATED, &lei);
	}
	os_log(OS_LOG_DEFAULT, "process [%d] caught causing excessive I/O (flavor: %d). Task I/O: %lld MB. [Limit : %lld MB per %lld secs]\n",
	    pid, flavor, (lei.lei_balance / (1024 * 1024)), (lei.lei_limit / (1024 * 1024)), (lei.lei_refill_period / NSEC_PER_SEC));

	kr = send_resource_violation(send_disk_writes_violation, task, &lei, kRNFlagsNone);
	if (kr) {
		printf("send_resource_violation(disk_writes, ...): error %#x\n", kr);
	}

#ifdef EXC_RESOURCE_MONITORS
	code[0] = code[1] = 0;
	EXC_RESOURCE_ENCODE_TYPE(code[0], RESOURCE_TYPE_IO);
	EXC_RESOURCE_ENCODE_FLAVOR(code[0], flavor);
	EXC_RESOURCE_IO_ENCODE_INTERVAL(code[0], (lei.lei_refill_period / NSEC_PER_SEC));
	EXC_RESOURCE_IO_ENCODE_LIMIT(code[0], (lei.lei_limit / (1024 * 1024)));
	EXC_RESOURCE_IO_ENCODE_OBSERVED(code[1], (lei.lei_balance / (1024 * 1024)));
	exception_triage(EXC_RESOURCE, code, EXCEPTION_CODE_MAX);
#endif /* EXC_RESOURCE_MONITORS */
}

/* Placeholders for the task set/get voucher interfaces */
kern_return_t
task_get_mach_voucher(
	task_t                  task,
	mach_voucher_selector_t __unused which,
	ipc_voucher_t           *voucher)
{
	if (TASK_NULL == task) {
		return KERN_INVALID_TASK;
	}

	*voucher = NULL;
	return KERN_SUCCESS;
}

kern_return_t
task_set_mach_voucher(
	task_t                  task,
	ipc_voucher_t           __unused voucher)
{
	if (TASK_NULL == task) {
		return KERN_INVALID_TASK;
	}

	return KERN_SUCCESS;
}

kern_return_t
task_swap_mach_voucher(
	__unused task_t         task,
	__unused ipc_voucher_t  new_voucher,
	ipc_voucher_t          *in_out_old_voucher)
{
	/*
	 * Currently this function is only called from a MIG generated
	 * routine which doesn't release the reference on the voucher
	 * addressed by in_out_old_voucher. To avoid leaking this reference,
	 * a call to release it has been added here.
	 */
	ipc_voucher_release(*in_out_old_voucher);
	return KERN_NOT_SUPPORTED;
}

void
task_set_gpu_denied(task_t task, boolean_t denied)
{
	task_lock(task);

	if (denied) {
		task->t_flags |= TF_GPU_DENIED;
	} else {
		task->t_flags &= ~TF_GPU_DENIED;
	}

	task_unlock(task);
}

boolean_t
task_is_gpu_denied(task_t task)
{
	/* We don't need the lock to read this flag */
	return (task->t_flags & TF_GPU_DENIED) ? TRUE : FALSE;
}


uint64_t
get_task_memory_region_count(task_t task)
{
	vm_map_t map;
	map = (task == kernel_task) ? kernel_map: task->map;
	return (uint64_t)get_map_nentries(map);
}

static void
kdebug_trace_dyld_internal(uint32_t base_code,
    struct dyld_kernel_image_info *info)
{
	static_assert(sizeof(info->uuid) >= 16);

#if defined(__LP64__)
	uint64_t *uuid = (uint64_t *)&(info->uuid);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    KDBG_EVENTID(DBG_DYLD, DBG_DYLD_UUID, base_code), uuid[0],
	    uuid[1], info->load_addr,
	    (uint64_t)info->fsid.val[0] | ((uint64_t)info->fsid.val[1] << 32),
	    0);
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    KDBG_EVENTID(DBG_DYLD, DBG_DYLD_UUID, base_code + 1),
	    (uint64_t)info->fsobjid.fid_objno |
	    ((uint64_t)info->fsobjid.fid_generation << 32),
	    0, 0, 0, 0);
#else /* defined(__LP64__) */
	uint32_t *uuid = (uint32_t *)&(info->uuid);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    KDBG_EVENTID(DBG_DYLD, DBG_DYLD_UUID, base_code + 2), uuid[0],
	    uuid[1], uuid[2], uuid[3], 0);
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    KDBG_EVENTID(DBG_DYLD, DBG_DYLD_UUID, base_code + 3),
	    (uint32_t)info->load_addr, info->fsid.val[0], info->fsid.val[1],
	    info->fsobjid.fid_objno, 0);
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    KDBG_EVENTID(DBG_DYLD, DBG_DYLD_UUID, base_code + 4),
	    info->fsobjid.fid_generation, 0, 0, 0, 0);
#endif /* !defined(__LP64__) */
}

static kern_return_t
kdebug_trace_dyld(task_t task, uint32_t base_code,
    vm_map_copy_t infos_copy, mach_msg_type_number_t infos_len)
{
	kern_return_t kr;
	dyld_kernel_image_info_array_t infos;
	vm_map_offset_t map_data;
	vm_offset_t data;

	if (!infos_copy) {
		return KERN_INVALID_ADDRESS;
	}

	if (!kdebug_enable ||
	    !kdebug_debugid_enabled(KDBG_EVENTID(DBG_DYLD, DBG_DYLD_UUID, 0))) {
		vm_map_copy_discard(infos_copy);
		return KERN_SUCCESS;
	}

	if (task == NULL || task != current_task()) {
		return KERN_INVALID_TASK;
	}

	kr = vm_map_copyout(ipc_kernel_map, &map_data, (vm_map_copy_t)infos_copy);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	infos = CAST_DOWN(dyld_kernel_image_info_array_t, map_data);

	for (mach_msg_type_number_t i = 0; i < infos_len; i++) {
		kdebug_trace_dyld_internal(base_code, &(infos[i]));
	}

	data = CAST_DOWN(vm_offset_t, map_data);
	mach_vm_deallocate(ipc_kernel_map, data, infos_len * sizeof(infos[0]));
	return KERN_SUCCESS;
}

kern_return_t
task_register_dyld_image_infos(task_t task,
    dyld_kernel_image_info_array_t infos_copy,
    mach_msg_type_number_t infos_len)
{
	return kdebug_trace_dyld(task, DBG_DYLD_UUID_MAP_A,
	           (vm_map_copy_t)infos_copy, infos_len);
}

kern_return_t
task_unregister_dyld_image_infos(task_t task,
    dyld_kernel_image_info_array_t infos_copy,
    mach_msg_type_number_t infos_len)
{
	return kdebug_trace_dyld(task, DBG_DYLD_UUID_UNMAP_A,
	           (vm_map_copy_t)infos_copy, infos_len);
}

kern_return_t
task_get_dyld_image_infos(__unused task_t task,
    __unused dyld_kernel_image_info_array_t * dyld_images,
    __unused mach_msg_type_number_t * dyld_imagesCnt)
{
	return KERN_NOT_SUPPORTED;
}

kern_return_t
task_register_dyld_shared_cache_image_info(task_t task,
    dyld_kernel_image_info_t cache_img,
    __unused boolean_t no_cache,
    __unused boolean_t private_cache)
{
	if (task == NULL || task != current_task()) {
		return KERN_INVALID_TASK;
	}

	kdebug_trace_dyld_internal(DBG_DYLD_UUID_SHARED_CACHE_A, &cache_img);
	return KERN_SUCCESS;
}

kern_return_t
task_register_dyld_set_dyld_state(__unused task_t task,
    __unused uint8_t dyld_state)
{
	return KERN_NOT_SUPPORTED;
}

kern_return_t
task_register_dyld_get_process_state(__unused task_t task,
    __unused dyld_kernel_process_info_t * dyld_process_state)
{
	return KERN_NOT_SUPPORTED;
}

kern_return_t
task_inspect(task_inspect_t task_insp, task_inspect_flavor_t flavor,
    task_inspect_info_t info_out, mach_msg_type_number_t *size_in_out)
{
#if MONOTONIC
	task_t task = (task_t)task_insp;
	kern_return_t kr = KERN_SUCCESS;
	mach_msg_type_number_t size;

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	size = *size_in_out;

	switch (flavor) {
	case TASK_INSPECT_BASIC_COUNTS: {
		struct task_inspect_basic_counts *bc;
		uint64_t task_counts[MT_CORE_NFIXED] = { 0 };

		if (size < TASK_INSPECT_BASIC_COUNTS_COUNT) {
			kr = KERN_INVALID_ARGUMENT;
			break;
		}

		mt_fixed_task_counts(task, task_counts);
		bc = (struct task_inspect_basic_counts *)info_out;
#ifdef MT_CORE_INSTRS
		bc->instructions = task_counts[MT_CORE_INSTRS];
#else /* defined(MT_CORE_INSTRS) */
		bc->instructions = 0;
#endif /* !defined(MT_CORE_INSTRS) */
		bc->cycles = task_counts[MT_CORE_CYCLES];
		size = TASK_INSPECT_BASIC_COUNTS_COUNT;
		break;
	}
	default:
		kr = KERN_INVALID_ARGUMENT;
		break;
	}

	if (kr == KERN_SUCCESS) {
		*size_in_out = size;
	}
	return kr;
#else /* MONOTONIC */
#pragma unused(task_insp, flavor, info_out, size_in_out)
	return KERN_NOT_SUPPORTED;
#endif /* !MONOTONIC */
}

#if CONFIG_SECLUDED_MEMORY
int num_tasks_can_use_secluded_mem = 0;

void
task_set_can_use_secluded_mem(
	task_t          task,
	boolean_t       can_use_secluded_mem)
{
	if (!task->task_could_use_secluded_mem) {
		return;
	}
	task_lock(task);
	task_set_can_use_secluded_mem_locked(task, can_use_secluded_mem);
	task_unlock(task);
}

void
task_set_can_use_secluded_mem_locked(
	task_t          task,
	boolean_t       can_use_secluded_mem)
{
	assert(task->task_could_use_secluded_mem);
	if (can_use_secluded_mem &&
	    secluded_for_apps && /* global boot-arg */
	    !task->task_can_use_secluded_mem) {
		assert(num_tasks_can_use_secluded_mem >= 0);
		OSAddAtomic(+1,
		    (volatile SInt32 *)&num_tasks_can_use_secluded_mem);
		task->task_can_use_secluded_mem = TRUE;
	} else if (!can_use_secluded_mem &&
	    task->task_can_use_secluded_mem) {
		assert(num_tasks_can_use_secluded_mem > 0);
		OSAddAtomic(-1,
		    (volatile SInt32 *)&num_tasks_can_use_secluded_mem);
		task->task_can_use_secluded_mem = FALSE;
	}
}

void
task_set_could_use_secluded_mem(
	task_t          task,
	boolean_t       could_use_secluded_mem)
{
	task->task_could_use_secluded_mem = could_use_secluded_mem;
}

void
task_set_could_also_use_secluded_mem(
	task_t          task,
	boolean_t       could_also_use_secluded_mem)
{
	task->task_could_also_use_secluded_mem = could_also_use_secluded_mem;
}

boolean_t
task_can_use_secluded_mem(
	task_t          task,
	boolean_t       is_alloc)
{
	if (task->task_can_use_secluded_mem) {
		assert(task->task_could_use_secluded_mem);
		assert(num_tasks_can_use_secluded_mem > 0);
		return TRUE;
	}
	if (task->task_could_also_use_secluded_mem &&
	    num_tasks_can_use_secluded_mem > 0) {
		assert(num_tasks_can_use_secluded_mem > 0);
		return TRUE;
	}

	/*
	 * If a single task is using more than some amount of
	 * memory, allow it to dip into secluded and also begin
	 * suppression of secluded memory until the tasks exits.
	 */
	if (is_alloc && secluded_shutoff_trigger != 0) {
		uint64_t phys_used = get_task_phys_footprint(task);
		if (phys_used > secluded_shutoff_trigger) {
			start_secluded_suppression(task);
			return TRUE;
		}
	}

	return FALSE;
}

boolean_t
task_could_use_secluded_mem(
	task_t  task)
{
	return task->task_could_use_secluded_mem;
}

boolean_t
task_could_also_use_secluded_mem(
	task_t  task)
{
	return task->task_could_also_use_secluded_mem;
}
#endif /* CONFIG_SECLUDED_MEMORY */

queue_head_t *
task_io_user_clients(task_t task)
{
	return &task->io_user_clients;
}

void
task_set_message_app_suspended(task_t task, boolean_t enable)
{
	task->message_app_suspended = enable;
}

void
task_copy_fields_for_exec(task_t dst_task, task_t src_task)
{
	dst_task->vtimers = src_task->vtimers;
}

#if DEVELOPMENT || DEBUG
int vm_region_footprint = 0;
#endif /* DEVELOPMENT || DEBUG */

boolean_t
task_self_region_footprint(void)
{
#if DEVELOPMENT || DEBUG
	if (vm_region_footprint) {
		/* system-wide override */
		return TRUE;
	}
#endif /* DEVELOPMENT || DEBUG */
	return current_task()->task_region_footprint;
}

void
task_self_region_footprint_set(
	boolean_t newval)
{
	task_t  curtask;

	curtask = current_task();
	task_lock(curtask);
	if (newval) {
		curtask->task_region_footprint = TRUE;
	} else {
		curtask->task_region_footprint = FALSE;
	}
	task_unlock(curtask);
}

void
task_set_darkwake_mode(task_t task, boolean_t set_mode)
{
	assert(task);

	task_lock(task);

	if (set_mode) {
		task->t_flags |= TF_DARKWAKE_MODE;
	} else {
		task->t_flags &= ~(TF_DARKWAKE_MODE);
	}

	task_unlock(task);
}

boolean_t
task_get_darkwake_mode(task_t task)
{
	assert(task);
	return (task->t_flags & TF_DARKWAKE_MODE) != 0;
}

kern_return_t
task_get_exc_guard_behavior(
	task_t task,
	task_exc_guard_behavior_t *behaviorp)
{
	if (task == TASK_NULL) {
		return KERN_INVALID_TASK;
	}
	*behaviorp = task->task_exc_guard;
	return KERN_SUCCESS;
}

#ifndef TASK_EXC_GUARD_ALL
/* Temporary define until two branches are merged */
#define TASK_EXC_GUARD_ALL (TASK_EXC_GUARD_VM_ALL | 0xf0)
#endif

kern_return_t
task_set_exc_guard_behavior(
	task_t task,
	task_exc_guard_behavior_t behavior)
{
	if (task == TASK_NULL) {
		return KERN_INVALID_TASK;
	}
	if (behavior & ~TASK_EXC_GUARD_ALL) {
		return KERN_INVALID_VALUE;
	}
	task->task_exc_guard = behavior;
	return KERN_SUCCESS;
}

#if __arm64__
extern int legacy_footprint_entitlement_mode;
extern void memorystatus_act_on_legacy_footprint_entitlement(proc_t, boolean_t);
extern void memorystatus_act_on_ios13extended_footprint_entitlement(proc_t);

void
task_set_legacy_footprint(
	task_t task)
{
	task_lock(task);
	task->task_legacy_footprint = TRUE;
	task_unlock(task);
}

void
task_set_extra_footprint_limit(
	task_t task)
{
	if (task->task_extra_footprint_limit) {
		return;
	}
	task_lock(task);
	if (task->task_extra_footprint_limit) {
		task_unlock(task);
		return;
	}
	task->task_extra_footprint_limit = TRUE;
	task_unlock(task);
	memorystatus_act_on_legacy_footprint_entitlement(task->bsd_info, TRUE);
}

void
task_set_ios13extended_footprint_limit(
	task_t task)
{
	if (task->task_ios13extended_footprint_limit) {
		return;
	}
	task_lock(task);
	if (task->task_ios13extended_footprint_limit) {
		task_unlock(task);
		return;
	}
	task->task_ios13extended_footprint_limit = TRUE;
	task_unlock(task);
	memorystatus_act_on_ios13extended_footprint_entitlement(task->bsd_info);
}
#endif /* __arm64__ */

static inline ledger_amount_t
task_ledger_get_balance(
	ledger_t        ledger,
	int             ledger_idx)
{
	ledger_amount_t amount;
	amount = 0;
	ledger_get_balance(ledger, ledger_idx, &amount);
	return amount;
}

/*
 * Gather the amount of memory counted in a task's footprint due to
 * being in a specific set of ledgers.
 */
void
task_ledgers_footprint(
	ledger_t        ledger,
	ledger_amount_t *ledger_resident,
	ledger_amount_t *ledger_compressed)
{
	*ledger_resident = 0;
	*ledger_compressed = 0;

	/* purgeable non-volatile memory */
	*ledger_resident += task_ledger_get_balance(ledger, task_ledgers.purgeable_nonvolatile);
	*ledger_compressed += task_ledger_get_balance(ledger, task_ledgers.purgeable_nonvolatile_compressed);

	/* "default" tagged memory */
	*ledger_resident += task_ledger_get_balance(ledger, task_ledgers.tagged_footprint);
	*ledger_compressed += task_ledger_get_balance(ledger, task_ledgers.tagged_footprint_compressed);

	/* "network" currently never counts in the footprint... */

	/* "media" tagged memory */
	*ledger_resident += task_ledger_get_balance(ledger, task_ledgers.media_footprint);
	*ledger_compressed += task_ledger_get_balance(ledger, task_ledgers.media_footprint_compressed);

	/* "graphics" tagged memory */
	*ledger_resident += task_ledger_get_balance(ledger, task_ledgers.graphics_footprint);
	*ledger_compressed += task_ledger_get_balance(ledger, task_ledgers.graphics_footprint_compressed);

	/* "neural" tagged memory */
	*ledger_resident += task_ledger_get_balance(ledger, task_ledgers.neural_footprint);
	*ledger_compressed += task_ledger_get_balance(ledger, task_ledgers.neural_footprint_compressed);
}

void
task_set_memory_ownership_transfer(
	task_t    task,
	boolean_t value)
{
	task_lock(task);
	task->task_can_transfer_memory_ownership = value;
	task_unlock(task);
}

void
task_copy_vmobjects(task_t task, vm_object_query_t query, int len, int64_t* num)
{
	vm_object_t find_vmo;
	unsigned int i = 0;
	unsigned int vmobj_limit = len / sizeof(vm_object_query_data_t);

	task_objq_lock(task);
	if (query != NULL) {
		queue_iterate(&task->task_objq, find_vmo, vm_object_t, task_objq)
		{
			vm_object_query_t p = &query[i];

			/*
			 * Clear the entire vm_object_query_t struct as we are using
			 * only the first 6 bits in the uint64_t bitfield for this
			 * anonymous struct member.
			 */
			bzero(p, sizeof(*p));

			p->object_id = (vm_object_id_t) VM_KERNEL_ADDRPERM(find_vmo);
			p->virtual_size = find_vmo->internal ? find_vmo->vo_size : 0;
			p->resident_size = find_vmo->resident_page_count * PAGE_SIZE;
			p->wired_size = find_vmo->wired_page_count * PAGE_SIZE;
			p->reusable_size = find_vmo->reusable_page_count * PAGE_SIZE;
			p->vo_no_footprint = find_vmo->vo_no_footprint;
			p->vo_ledger_tag = find_vmo->vo_ledger_tag;
			p->purgable = find_vmo->purgable;

			if (find_vmo->internal && find_vmo->pager_created && find_vmo->pager != NULL) {
				p->compressed_size = vm_compressor_pager_get_count(find_vmo->pager) * PAGE_SIZE;
			} else {
				p->compressed_size = 0;
			}

			i++;

			/* Make sure to not overrun */
			if (i == vmobj_limit) {
				break;
			}
		}
	} else {
		i = task->task_owned_objects;
	}
	task_objq_unlock(task);

	*num = i;
}

#if __has_feature(ptrauth_calls)

#define PAC_EXCEPTION_ENTITLEMENT "com.apple.private.pac.exception"

void
task_set_pac_exception_fatal_flag(
	task_t task)
{
	assert(task != TASK_NULL);

	if (!IOTaskHasEntitlement(task, PAC_EXCEPTION_ENTITLEMENT)) {
		return;
	}

	task_lock(task);
	task->t_flags |= TF_PAC_EXC_FATAL;
	task_unlock(task);
}

bool
task_is_pac_exception_fatal(
	task_t task)
{
	uint32_t flags = 0;

	assert(task != TASK_NULL);

	flags = os_atomic_load(&task->t_flags, relaxed);
	return (bool)(flags & TF_PAC_EXC_FATAL);
}
#endif /* __has_feature(ptrauth_calls) */
