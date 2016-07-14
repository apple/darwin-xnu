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
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
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
 *	File:	kern/machine.c
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1987
 *
 *	Support for machine independent machine abstraction.
 */

#include <string.h>

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/machine.h>
#include <mach/host_info.h>
#include <mach/host_reboot.h>
#include <mach/host_priv_server.h>
#include <mach/processor_server.h>

#include <kern/kern_types.h>
#include <kern/counters.h>
#include <kern/cpu_data.h>
#include <kern/ipc_host.h>
#include <kern/host.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/processor.h>
#include <kern/queue.h>
#include <kern/sched.h>
#include <kern/task.h>
#include <kern/thread.h>

#include <machine/commpage.h>

#if HIBERNATION
#include <IOKit/IOHibernatePrivate.h>
#endif
#include <IOKit/IOPlatformExpert.h>

#if CONFIG_DTRACE
extern void (*dtrace_cpu_state_changed_hook)(int, boolean_t);
#endif

/*
 *	Exported variables:
 */

struct machine_info	machine_info;

/* Forwards */
void			processor_doshutdown(
					processor_t			processor);

/*
 *	processor_up:
 *
 *	Flag processor as up and running, and available
 *	for scheduling.
 */
void
processor_up(
	processor_t			processor)
{
	processor_set_t		pset;
	spl_t				s;

	s = splsched();
	init_ast_check(processor);
	pset = processor->processor_set;
	pset_lock(pset);
	++pset->online_processor_count;
	enqueue_tail(&pset->active_queue, (queue_entry_t)processor);
	processor->state = PROCESSOR_RUNNING;
	(void)hw_atomic_add(&processor_avail_count, 1);
	commpage_update_active_cpus();
	pset_unlock(pset);
	ml_cpu_up();
	splx(s);

#if CONFIG_DTRACE
	if (dtrace_cpu_state_changed_hook)
		(*dtrace_cpu_state_changed_hook)(processor->cpu_id, TRUE);
#endif
}
#include <atm/atm_internal.h>

kern_return_t
host_reboot(
	host_priv_t		host_priv,
	int				options)
{
	if (host_priv == HOST_PRIV_NULL)
		return (KERN_INVALID_HOST);

	assert(host_priv == &realhost);

#if DEVELOPMENT || DEBUG
	if (options & HOST_REBOOT_DEBUGGER) {
		Debugger("Debugger");
		return (KERN_SUCCESS);
	}
#endif

    if (options & HOST_REBOOT_UPSDELAY) {
        // UPS power cutoff path
        PEHaltRestart( kPEUPSDelayHaltCPU );
    } else {
       halt_all_cpus(!(options & HOST_REBOOT_HALT));
    }

	return (KERN_SUCCESS);
}

kern_return_t
processor_assign(
	__unused processor_t		processor,
	__unused processor_set_t	new_pset,
	__unused boolean_t		wait)
{
	return (KERN_FAILURE);
}

kern_return_t
processor_shutdown(
	processor_t			processor)
{
	processor_set_t		pset;
	spl_t				s;

	s = splsched();
	pset = processor->processor_set;
	pset_lock(pset);
	if (processor->state == PROCESSOR_OFF_LINE) {
		/*
		 * Success if already shutdown.
		 */
		pset_unlock(pset);
		splx(s);

		return (KERN_SUCCESS);
	}

	if (processor->state == PROCESSOR_START) {
		/*
		 * Failure if currently being started.
		 */
		pset_unlock(pset);
		splx(s);

		return (KERN_FAILURE);
	}

	/*
	 * If the processor is dispatching, let it finish.
	 */
	while (processor->state == PROCESSOR_DISPATCHING) {
		pset_unlock(pset);
		splx(s);
		delay(1);
		s = splsched();
		pset_lock(pset);
	}

	/*
	 * Success if already being shutdown.
	 */
	if (processor->state == PROCESSOR_SHUTDOWN) {
		pset_unlock(pset);
		splx(s);

		return (KERN_SUCCESS);
	}

	if (processor->state == PROCESSOR_IDLE)
		remqueue((queue_entry_t)processor);
	else
	if (processor->state == PROCESSOR_RUNNING)
		remqueue((queue_entry_t)processor);

	processor->state = PROCESSOR_SHUTDOWN;

	pset_unlock(pset);

	processor_doshutdown(processor);
	splx(s);

	cpu_exit_wait(processor->cpu_id);

	return (KERN_SUCCESS);
}

/*
 * Called with interrupts disabled.
 */
void
processor_doshutdown(
	processor_t			processor)
{
	thread_t			old_thread, self = current_thread();
	processor_t			prev;
	processor_set_t			pset;

	/*
	 *	Get onto the processor to shutdown
	 */
	prev = thread_bind(processor);
	thread_block(THREAD_CONTINUE_NULL);

	assert(processor->state == PROCESSOR_SHUTDOWN);

#if CONFIG_DTRACE
	if (dtrace_cpu_state_changed_hook)
		(*dtrace_cpu_state_changed_hook)(processor->cpu_id, FALSE);
#endif

	ml_cpu_down();

#if HIBERNATION
	if (processor_avail_count < 2) {
		hibernate_vm_lock();
		hibernate_vm_unlock();
	}
#endif

	pset = processor->processor_set;
	pset_lock(pset);
	processor->state = PROCESSOR_OFF_LINE;
	--pset->online_processor_count;
	(void)hw_atomic_sub(&processor_avail_count, 1);
	commpage_update_active_cpus();
	SCHED(processor_queue_shutdown)(processor);
	/* pset lock dropped */

	/*
	 * Continue processor shutdown in shutdown context.
	 *
	 * We save the current context in machine_processor_shutdown in such a way
	 * that when this thread is next invoked it will return from here instead of
	 * from the machine_switch_context() in thread_invoke like a normal context switch.
	 *
	 * As such, 'old_thread' is neither the idle thread nor the current thread - it's whatever
	 * thread invoked back to this one. (Usually, it's another processor's idle thread.)
	 *
	 * TODO: Make this a real thread_run of the idle_thread, so we don't have to keep this in sync
	 * with thread_invoke.
	 */
	thread_bind(prev);
	old_thread = machine_processor_shutdown(self, processor_offline, processor);

	thread_dispatch(old_thread, self);
}

/*
 * Complete the shutdown and place the processor offline.
 *
 * Called at splsched in the shutdown context.
 * This performs a minimal thread_invoke() to the idle thread,
 * so it needs to be kept in sync with what thread_invoke() does.
 *
 * The onlining half of this is done in load_context().
 */
void
processor_offline(
	processor_t			processor)
{
	assert(processor == current_processor());
	assert(processor->active_thread == current_thread());

	thread_t old_thread = processor->active_thread;
	thread_t new_thread = processor->idle_thread;

	processor->active_thread = new_thread;
	processor->current_pri = IDLEPRI;
	processor->current_thmode = TH_MODE_NONE;
	processor->deadline = UINT64_MAX;
	new_thread->last_processor = processor;

	uint64_t ctime = mach_absolute_time();

	processor->last_dispatch = ctime;
	old_thread->last_run_time = ctime;

	/* Update processor->thread_timer and ->kernel_timer to point to the new thread */
	thread_timer_event(ctime, &new_thread->system_timer);
	PROCESSOR_DATA(processor, kernel_timer) = &new_thread->system_timer;

	timer_stop(PROCESSOR_DATA(processor, current_state), ctime);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	                          MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED) | DBG_FUNC_NONE,
	                          old_thread->reason, (uintptr_t)thread_tid(new_thread),
	                          old_thread->sched_pri, new_thread->sched_pri, 0);

	machine_set_current_thread(new_thread);

	thread_dispatch(old_thread, new_thread);

	PMAP_DEACTIVATE_KERNEL(processor->cpu_id);

	cpu_sleep();
	panic("zombie processor");
	/*NOTREACHED*/
}

kern_return_t
host_get_boot_info(
        host_priv_t         host_priv,
        kernel_boot_info_t  boot_info)
{
	const char *src = "";
	if (host_priv == HOST_PRIV_NULL)
		return (KERN_INVALID_HOST);

	assert(host_priv == &realhost);

	/*
	 * Copy first operator string terminated by '\0' followed by
	 *	standardized strings generated from boot string.
	 */
	src = machine_boot_info(boot_info, KERNEL_BOOT_INFO_MAX);
	if (src != boot_info)
		(void) strncpy(boot_info, src, KERNEL_BOOT_INFO_MAX);

	return (KERN_SUCCESS);
}
