/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
#include <kern/lock.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/processor.h>
#include <kern/queue.h>
#include <kern/sched.h>
#include <kern/task.h>
#include <kern/thread.h>

#include <IOKit/IOHibernatePrivate.h>

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
	processor_t		processor)
{
	processor_set_t		pset = &default_pset;
	spl_t				s;

	s = splsched();
	processor_lock(processor);
	init_ast_check(processor);
	simple_lock(&pset->sched_lock);
	pset_add_processor(pset, processor);
	enqueue_tail(&pset->active_queue, (queue_entry_t)processor);
	processor->state = PROCESSOR_RUNNING;
	simple_unlock(&pset->sched_lock);
	hw_atomic_add(&machine_info.avail_cpus, 1);
	ml_cpu_up();
	processor_unlock(processor);
	splx(s);
}

kern_return_t
host_reboot(
	host_priv_t		host_priv,
	int				options)
{
	if (host_priv == HOST_PRIV_NULL)
		return (KERN_INVALID_HOST);

	assert(host_priv == &realhost);

	if (options & HOST_REBOOT_DEBUGGER) {
		Debugger("Debugger");
		return (KERN_SUCCESS);
	}

	halt_all_cpus(!(options & HOST_REBOOT_HALT));

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
	processor_lock(processor);
	if (processor->state == PROCESSOR_OFF_LINE) {
		/*
		 * Success if already shutdown.
		 */
		processor_unlock(processor);
		splx(s);

		return (KERN_SUCCESS);
	}

	if (processor->state == PROCESSOR_START) {
		/*
		 * Failure if currently being started.
		 */
		processor_unlock(processor);
		splx(s);

		return (KERN_FAILURE);
	}

	/*
	 * Must lock the scheduling lock
	 * to get at the processor state.
	 */
	pset = processor->processor_set;
	if (pset != PROCESSOR_SET_NULL) {
		simple_lock(&pset->sched_lock);

		/*
		 * If the processor is dispatching, let it finish.
		 */
		while (processor->state == PROCESSOR_DISPATCHING) {
			simple_unlock(&pset->sched_lock);
			delay(1);
			simple_lock(&pset->sched_lock);
		}

		/*
		 * Success if already being shutdown.
		 */
		if (processor->state == PROCESSOR_SHUTDOWN) {
			simple_unlock(&pset->sched_lock);
			processor_unlock(processor);
			splx(s);

			return (KERN_SUCCESS);
		}
	}
	else {
		/*
		 * Success, already being shutdown.
		 */
		processor_unlock(processor);
		splx(s);

		return (KERN_SUCCESS);
	}

	if (processor->state == PROCESSOR_IDLE) {
		remqueue(&pset->idle_queue, (queue_entry_t)processor);
		pset->idle_count--;
	}
	else
	if (processor->state == PROCESSOR_RUNNING)
		remqueue(&pset->active_queue, (queue_entry_t)processor);
	else
		panic("processor_shutdown");

	processor->state = PROCESSOR_SHUTDOWN;

	simple_unlock(&pset->sched_lock);

	processor_unlock(processor);

	processor_doshutdown(processor);
	splx(s);

	cpu_exit_wait(PROCESSOR_DATA(processor, slot_num));

	return (KERN_SUCCESS);
}

/*
 * Called at splsched.
 */
void
processor_doshutdown(
	processor_t			processor)
{
	thread_t			old_thread, self = current_thread();
	processor_set_t		pset;
	processor_t			prev;
	int					pcount;

	/*
	 *	Get onto the processor to shutdown
	 */
	prev = thread_bind(self, processor);
	thread_block(THREAD_CONTINUE_NULL);

	processor_lock(processor);
	pset = processor->processor_set;
	simple_lock(&pset->sched_lock);

	if ((pcount = pset->processor_count) == 1) {
		simple_unlock(&pset->sched_lock);
		processor_unlock(processor);

		hibernate_vm_lock();

		processor_lock(processor);
		simple_lock(&pset->sched_lock);
	}

	assert(processor->state == PROCESSOR_SHUTDOWN);

	pset_remove_processor(pset, processor);
	simple_unlock(&pset->sched_lock);
	processor_unlock(processor);

	if (pcount == 1)
		hibernate_vm_unlock();

	/*
	 *	Continue processor shutdown in shutdown context.
	 */
	thread_bind(self, prev);
	old_thread = machine_processor_shutdown(self, processor_offline, processor);

	thread_begin(self, self->last_processor);

	thread_dispatch(old_thread);

	/*
	 * If we just shutdown another processor, move the
	 * timer call outs to the current processor.
	 */
	if (processor != current_processor()) {
		processor_lock(processor);
		if (	processor->state == PROCESSOR_OFF_LINE	||
				processor->state == PROCESSOR_SHUTDOWN	)
			timer_call_shutdown(processor);
		processor_unlock(processor);
	}
}

/*
 *	Complete the shutdown and place the processor offline.
 *
 *	Called at splsched in the shutdown context.
 */
void
processor_offline(
	processor_t		processor)
{
	thread_t		thread, old_thread = processor->active_thread;

	thread = processor->idle_thread;
	processor->active_thread = thread;
	processor->current_pri = IDLEPRI;

	processor->last_dispatch = mach_absolute_time();
	timer_switch((uint32_t)processor->last_dispatch,
							&PROCESSOR_DATA(processor, offline_timer));

	thread_done(old_thread, thread, processor);

	machine_set_current_thread(thread);

	thread_begin(thread, processor);

	thread_dispatch(old_thread);

	PMAP_DEACTIVATE_KERNEL(PROCESSOR_DATA(processor, slot_num));

	processor_lock(processor);
	processor->state = PROCESSOR_OFF_LINE;
	hw_atomic_sub(&machine_info.avail_cpus, 1);
	ml_cpu_down();
	processor_unlock(processor);

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
