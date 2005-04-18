/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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

#include <cpus.h>

#include <string.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/mach_types.h>
#include <mach/machine.h>
#include <mach/host_info.h>
#include <mach/host_reboot.h>
#include <kern/counters.h>
#include <kern/cpu_data.h>
#include <kern/ipc_host.h>
#include <kern/host.h>
#include <kern/lock.h>
#include <kern/machine.h>
#include <kern/processor.h>
#include <kern/queue.h>
#include <kern/sched.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/thread_swap.h>
#include <kern/misc_protos.h>

#include <kern/mk_sp.h>

/*
 *	Exported variables:
 */

struct machine_info	machine_info;
struct machine_slot	machine_slot[NCPUS];

thread_t		machine_wake_thread;

/* Forwards */
void			processor_doshutdown(
					processor_t			processor);

/*
 *	cpu_up:
 *
 * Flag specified cpu as up and running.  Called when a processor comes
 * online.
 */
void
cpu_up(
	int		cpu)
{
	processor_t				processor = cpu_to_processor(cpu);
	processor_set_t			pset = &default_pset;
	struct machine_slot		*ms;
	spl_t					s;

	s = splsched();
	processor_lock(processor);
	init_ast_check(processor);
	ms = &machine_slot[cpu];
	ms->running = TRUE;
	machine_info.avail_cpus++;
	simple_lock(&pset->sched_lock);
	pset_add_processor(pset, processor);
	enqueue_tail(&pset->active_queue, (queue_entry_t)processor);
	processor->deadline = UINT64_MAX;
	processor->state = PROCESSOR_RUNNING;
	simple_unlock(&pset->sched_lock);
	processor_unlock(processor);
	splx(s);
}

/*
 *	cpu_down:
 *
 *	Flag specified cpu as down.  Called when a processor is about to
 *	go offline.
 */
void
cpu_down(
	int		cpu)
{
	processor_t				processor;
	struct machine_slot		*ms;
	spl_t					s;

	processor = cpu_to_processor(cpu);

	s = splsched();
	processor_lock(processor);
	ms = &machine_slot[cpu];
	ms->running = FALSE;
	machine_info.avail_cpus--;
	/*
	 *	processor has already been removed from pset.
	 */
	processor->state = PROCESSOR_OFF_LINE;
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
	processor_t			processor,
	processor_set_t		new_pset,
	boolean_t			wait)
{
#ifdef	lint
	processor++; new_pset++; wait++;
#endif	/* lint */
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
	if (	processor->state == PROCESSOR_OFF_LINE	||
			processor->state == PROCESSOR_SHUTDOWN	) {
		/*
		 * Success if already shutdown or being shutdown.
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
	 * Processor must be in a processor set.  Must lock the scheduling
	 * lock to get at the processor state.
	 */
	pset = processor->processor_set;
	simple_lock(&pset->sched_lock);

	/*
	 * If the processor is dispatching, let it finish - it will set its
	 * state to running very soon.
	 */
	while (*(volatile int *)&processor->state == PROCESSOR_DISPATCHING) {
		simple_unlock(&pset->sched_lock);
		delay(1);
		simple_lock(&pset->sched_lock);
	}

	if (processor->state == PROCESSOR_IDLE) {
		remqueue(&pset->idle_queue, (queue_entry_t)processor);
		pset->idle_count--;
	}
	else
	if (processor->state == PROCESSOR_RUNNING)
		remqueue(&pset->active_queue, (queue_entry_t)processor);
	else
		panic("processor_request_action");

	processor->state = PROCESSOR_SHUTDOWN;

	simple_unlock(&pset->sched_lock);

	processor_unlock(processor);

	processor_doshutdown(processor);
	splx(s);

#ifdef	__ppc__
	cpu_exit_wait(processor->slot_num);
#endif

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

	/*
	 *	Get onto the processor to shutdown
	 */
	prev = thread_bind(self, processor);
	thread_block(THREAD_CONTINUE_NULL);

	processor_lock(processor);
	pset = processor->processor_set;
	simple_lock(&pset->sched_lock);

	if (pset->processor_count == 1) {
		thread_t		thread;
		extern void		start_cpu_thread(void);

		simple_unlock(&pset->sched_lock);
		processor_unlock(processor);

		/*
		 * Create the thread, and point it at the routine.
		 */
		thread = kernel_thread_create(start_cpu_thread, MAXPRI_KERNEL);

		thread_lock(thread);
		machine_wake_thread = thread;
		thread->state = TH_RUN;
		pset_run_incr(thread->processor_set);
		thread_unlock(thread);

		processor_lock(processor);
		simple_lock(&pset->sched_lock);
	}

	assert(processor->state == PROCESSOR_SHUTDOWN);

	pset_remove_processor(pset, processor);
	simple_unlock(&pset->sched_lock);
	processor_unlock(processor);

	/*
	 *	Clean up.
	 */
	thread_bind(self, prev);
	old_thread = switch_to_shutdown_context(self,
									processor_offline, processor);
	if (processor != current_processor())
		timer_call_shutdown(processor);

	_mk_sp_thread_begin(self, self->last_processor);

	thread_dispatch(old_thread);
}

/*
 *	Actually do the processor shutdown.  This is called at splsched,
 *	running on the processor's shutdown stack.
 */

void
processor_offline(
	processor_t		processor)
{
	register thread_t	old_thread = processor->active_thread;
	register int		cpu = processor->slot_num;

	timer_call_cancel(&processor->quantum_timer);
	timer_switch(&kernel_timer[cpu]);
	processor->active_thread = processor->idle_thread;
	machine_thread_set_current(processor->active_thread);
	thread_dispatch(old_thread);

	/*
	 *	OK, now exit this cpu.
	 */
	PMAP_DEACTIVATE_KERNEL(cpu);
	cpu_down(cpu);
	cpu_sleep();
	panic("zombie processor");
	/*NOTREACHED*/
}

kern_return_t
host_get_boot_info(
        host_priv_t         host_priv,
        kernel_boot_info_t  boot_info)
{
	char *src = "";
	extern char *machine_boot_info(
				kernel_boot_info_t	boot_info,
				vm_size_t			buf_len);

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
