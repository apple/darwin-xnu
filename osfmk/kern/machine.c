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

#include <kern/sf.h>
#include <kern/mk_sp.h> /*** ??? fix so this can be removed ***/

/*
 *	Exported variables:
 */

struct machine_info	machine_info;
struct machine_slot	machine_slot[NCPUS];

static queue_head_t			processor_action_queue;
static boolean_t			processor_action_active;
static thread_call_t		processor_action_call;
static thread_call_data_t	processor_action_call_data;
decl_simple_lock_data(static,processor_action_lock)

thread_t		machine_wake_thread;

/* Forwards */
processor_set_t	processor_request_action(
					processor_t			processor,
					processor_set_t		new_pset);

void			processor_doaction(
					processor_t			processor);

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
	struct machine_slot		*ms;
	spl_t					s;
	
	/*
	 * Just twiddle our thumbs; we've got nothing better to do
	 * yet, anyway.
	 */
	while (!simple_lock_try(&default_pset.processors_lock))
		continue;

	s = splsched();
	processor_lock(processor);
	init_ast_check(processor);
	ms = &machine_slot[cpu];
	ms->running = TRUE;
	machine_info.avail_cpus++;
	pset_add_processor(&default_pset, processor);
	processor->state = PROCESSOR_RUNNING;
	processor_unlock(processor);
	splx(s);

	simple_unlock(&default_pset.processors_lock);
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
	processor->processor_set_next = PROCESSOR_SET_NULL;
	processor->state = PROCESSOR_OFF_LINE;
	processor_unlock(processor);
	splx(s);
}

kern_return_t
host_reboot(
	host_priv_t			host_priv,
	int				options)
{
	if (host_priv == HOST_PRIV_NULL)
		return (KERN_INVALID_HOST);

	assert(host_priv == &realhost);

	if (options & HOST_REBOOT_DEBUGGER) {
		Debugger("Debugger");
	}
	else
		halt_all_cpus(!(options & HOST_REBOOT_HALT));

	return (KERN_SUCCESS);
}

/*
 * processor_request_action: 
 *
 * Common internals of processor_assign and processor_shutdown.  
 * If new_pset is null, this is a shutdown, else it's an assign 
 * and caller must donate a reference.  
 * For assign operations, it returns an old pset that must be deallocated 
 * if it's not NULL.  
 * For shutdown operations, it always returns PROCESSOR_SET_NULL.
 */
processor_set_t
processor_request_action(
	processor_t			processor,
	processor_set_t		new_pset)
{
	processor_set_t pset, old_next_pset;

	/*
	 * Processor must be in a processor set.  Must lock its idle lock to
	 * get at processor state.
	 */
	pset = processor->processor_set;
	simple_lock(&pset->idle_lock);

	/*
	 * If the processor is dispatching, let it finish - it will set its
	 * state to running very soon.
	 */
	while (*(volatile int *)&processor->state == PROCESSOR_DISPATCHING) {
		simple_unlock(&pset->idle_lock);
		simple_lock(&pset->idle_lock);
	}

	/*
	 * Now lock the action queue and do the dirty work.
	 */
	simple_lock(&processor_action_lock);

	switch (processor->state) {

	case PROCESSOR_IDLE:
		/*
		 * Remove from idle queue.
		 */
		queue_remove(&pset->idle_queue, processor, 
						processor_t, processor_queue);
		pset->idle_count--;

		/* fall through ... */
	case PROCESSOR_RUNNING:
		/*
		 * Put it on the action queue.
		 */
		queue_enter(&processor_action_queue, processor, 
						processor_t,processor_queue);

		/* Fall through ... */
	case PROCESSOR_ASSIGN:
		/*
		 * And ask the action_thread to do the work.
		 */

		if (new_pset == PROCESSOR_SET_NULL) {
			processor->state = PROCESSOR_SHUTDOWN;
			old_next_pset = PROCESSOR_SET_NULL;
		} else {
			processor->state = PROCESSOR_ASSIGN;
			old_next_pset = processor->processor_set_next;
			processor->processor_set_next = new_pset;
		}
		break;

	default:
		printf("state: %d\n", processor->state);
		panic("processor_request_action: bad state");
	}

	if (processor_action_active == FALSE) {
		processor_action_active = TRUE;
		simple_unlock(&processor_action_lock);
		simple_unlock(&pset->idle_lock);
		processor_unlock(processor);
		thread_call_enter(processor_action_call);
		processor_lock(processor);
	} else {
		simple_unlock(&processor_action_lock);
    	simple_unlock(&pset->idle_lock);
	}

	return (old_next_pset);
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

/*
 *	processor_shutdown() queues a processor up for shutdown.
 *	Any assignment in progress is overriden.
 */
kern_return_t
processor_shutdown(
	processor_t		processor)
{
	spl_t s;

	s = splsched();
	processor_lock(processor);
	if ((processor->state == PROCESSOR_OFF_LINE) ||
		(processor->state == PROCESSOR_SHUTDOWN)) {
		/*
		 * Already shutdown or being shutdown -- nothing to do.
		 */
		processor_unlock(processor);
		splx(s);

		return (KERN_SUCCESS);
	}

	(void) processor_request_action(processor, PROCESSOR_SET_NULL);

	assert_wait((event_t)processor, THREAD_UNINT);

    processor_unlock(processor);
	splx(s);

	thread_block((void (*)(void)) 0);

	return (KERN_SUCCESS);
}

/*
 *	processor_action() shuts down processors or changes their assignment.
 */
static void
_processor_action(
	thread_call_param_t		p0,
	thread_call_param_t		p1)
{
	register processor_t	processor;
	spl_t s;

	s = splsched();
	simple_lock(&processor_action_lock);

	while (!queue_empty(&processor_action_queue)) {
		processor = (processor_t) queue_first(&processor_action_queue);
		queue_remove(&processor_action_queue, processor, 
						processor_t, processor_queue);
		simple_unlock(&processor_action_lock);
		splx(s);

		processor_doaction(processor);

		s = splsched();
		simple_lock(&processor_action_lock);
	}

	processor_action_active = FALSE;
	simple_unlock(&processor_action_lock);
	splx(s);
}

void
processor_action(void)
{
	queue_init(&processor_action_queue);
	simple_lock_init(&processor_action_lock, ETAP_THREAD_ACTION); 
	processor_action_active = FALSE;

	thread_call_setup(&processor_action_call_data, _processor_action, NULL);
	processor_action_call = &processor_action_call_data;
}

/*
 *	processor_doaction actually does the shutdown.  The trick here
 *	is to schedule ourselves onto a cpu and then save our
 *	context back into the runqs before taking out the cpu.
 */
void
processor_doaction(
	processor_t					processor)
{
	thread_t			self = current_thread();
	processor_set_t		pset;
	thread_t			old_thread;
	spl_t				s;

	/*
	 *	Get onto the processor to shutdown
	 */
	thread_bind(self, processor);
	thread_block((void (*)(void)) 0);

	pset = processor->processor_set;
	simple_lock(&pset->processors_lock);

	if (pset->processor_count == 1) {
		thread_t		thread;
		sched_policy_t	*policy;
		extern void		start_cpu_thread(void);

		simple_unlock(&pset->processors_lock);

		/*
		 * Create the thread, and point it at the routine.
		 */
		thread = kernel_thread_with_priority(kernel_task, MAXPRI_KERNBAND,
										start_cpu_thread, FALSE);

		disable_preemption();

		s = splsched();
		thread_lock(thread);
		thread->state |= TH_RUN;
		policy = &sched_policy[thread->policy];
		(void)policy->sp_ops.sp_thread_unblock(policy, thread);
		(void)rem_runq(thread);
		machine_wake_thread = thread;
		thread_unlock(thread);
		splx(s);

		simple_lock(&pset->processors_lock);
		enable_preemption();
	}

	s = splsched();
	processor_lock(processor);

	/*
	 *	Do shutdown, make sure we live when processor dies.
	 */
	if (processor->state != PROCESSOR_SHUTDOWN) {
		panic("action_thread -- bad processor state");
	}

	pset_remove_processor(pset, processor);
	processor_unlock(processor);
	simple_unlock(&pset->processors_lock);

	/*
	 *	Clean up.
	 */
	thread_bind(self, PROCESSOR_NULL);
	self->continuation = 0;
	old_thread = switch_to_shutdown_context(self,
									processor_doshutdown, processor);
	thread_dispatch(old_thread);
	thread_wakeup((event_t)processor);
	splx(s);
}

/*
 *	Actually do the processor shutdown.  This is called at splsched,
 *	running on the processor's shutdown stack.
 */

void
processor_doshutdown(
	processor_t		processor)
{
	register int	cpu = processor->slot_num;

	thread_dispatch(current_thread());
	timer_switch(&kernel_timer[cpu]);

	/*
	 *	OK, now exit this cpu.
	 */
	PMAP_DEACTIVATE_KERNEL(cpu);
	cpu_data[cpu].active_thread = THREAD_NULL;
	active_kloaded[cpu] = THR_ACT_NULL;
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
