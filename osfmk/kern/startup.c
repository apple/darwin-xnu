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
 *	Mach kernel startup.
 */

#include <debug.h>
#include <xpr_debug.h>
#include <mach_kdp.h>
#include <cpus.h>
#include <mach_host.h>
#include <norma_vm.h>
#include <etap.h>

#include <mach/boolean.h>
#include <mach/machine.h>
#include <mach/task_special_ports.h>
#include <mach/vm_param.h>
#include <ipc/ipc_init.h>
#include <kern/assert.h>
#include <kern/misc_protos.h>
#include <kern/clock.h>
#include <kern/cpu_number.h>
#include <kern/etap_macros.h>
#include <kern/machine.h>
#include <kern/processor.h>
#include <kern/sched_prim.h>
#include <kern/mk_sp.h>
#include <kern/startup.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/timer.h>
#include <kern/timer_call.h>
#include <kern/xpr.h>
#include <kern/zalloc.h>
#include <vm/vm_kern.h>
#include <vm/vm_init.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <machine/pmap.h>
#include <sys/version.h>

#ifdef __ppc__
#include <ppc/Firmware.h>
#include <ppc/mappings.h>
#endif

/* Externs XXX */
extern void	rtclock_reset(void);

/* Forwards */
void		cpu_launch_first_thread(
			thread_t			thread);
void		start_kernel_threads(void);
void        swapin_thread();

/*
 *	Running in virtual memory, on the interrupt stack.
 *	Does not return.  Dispatches initial thread.
 *
 *	Assumes that master_cpu is set.
 */
void
setup_main(void)
{
	thread_t	startup_thread;

	sched_init();
	vm_mem_bootstrap();
	ipc_bootstrap();
	vm_mem_init();
	ipc_init();

	/*
	 * As soon as the virtual memory system is up, we record
	 * that this CPU is using the kernel pmap.
	 */
	PMAP_ACTIVATE_KERNEL(master_cpu);

#ifdef __ppc__
	mapping_free_prime();						/* Load up with temporary mapping blocks */
#endif

	machine_init();
	kmod_init();
	clock_init();

	init_timers();
	timer_call_initialize();

	machine_info.max_cpus = NCPUS;
	machine_info.memory_size = mem_size;
	machine_info.avail_cpus = 0;
	machine_info.major_version = KERNEL_MAJOR_VERSION;
	machine_info.minor_version = KERNEL_MINOR_VERSION;

	/*
	 *	Initialize the IPC, task, and thread subsystems.
	 */
	ledger_init();
	task_init();
	act_init();
	thread_init();

	/*
	 *	Initialize the Event Trace Analysis Package.
	 * 	Dynamic Phase: 2 of 2
	 */
	etap_init_phase2();
	
	/*
	 *	Create a kernel thread to start the other kernel
	 *	threads.
	 */
	startup_thread = kernel_thread_with_priority(
										kernel_task, MAXPRI_KERNEL,
											start_kernel_threads, TRUE, FALSE);
	/*
	 * Pretend it is already running.
	 *
	 * We can do this without locking, because nothing
	 * else is running yet.
	 */
	startup_thread->state = TH_RUN;
	hw_atomic_add(&startup_thread->processor_set->run_count, 1);

	/*
	 * Start the thread.
	 */
	cpu_launch_first_thread(startup_thread);
	/*NOTREACHED*/
	panic("cpu_launch_first_thread returns!");
}

/*
 * Now running in a thread.  Create the rest of the kernel threads
 * and the bootstrap task.
 */
void
start_kernel_threads(void)
{
	register int				i;

	thread_bind(current_thread(), cpu_to_processor(cpu_number()));

	/*
	 *	Create the idle threads and the other
	 *	service threads.
	 */
	for (i = 0; i < NCPUS; i++) {
		processor_t		processor = cpu_to_processor(i);
		thread_t		thread;
		spl_t			s;

		thread = kernel_thread_with_priority(
									kernel_task, MAXPRI_KERNEL,
											idle_thread, TRUE, FALSE);
		s = splsched();
		thread_lock(thread);
		thread_bind_locked(thread, processor);
		processor->idle_thread = thread;
		thread->ref_count++;
		thread->state |= TH_IDLE;
		thread_go_locked(thread, THREAD_AWAKENED);
		thread_unlock(thread);
		splx(s);
	}

	/*
	 * Initialize the thread reaper mechanism.
	 */
	thread_reaper_init();

	/*
	 * Initialize the stack swapin mechanism.
	 */
	swapin_init();

	/*
	 * Initialize the periodic scheduler mechanism.
	 */
	sched_tick_init();

	/*
	 * Initialize the thread callout mechanism.
	 */
	thread_call_initialize();

	/*
	 * Invoke some black magic.
	 */
#if __ppc__
	mapping_adjust();
#endif

	/*
	 *	Create the clock service.
	 */
	clock_service_create();

	/*
	 *	Create the device service.
	 */
	device_service_create();

	shared_file_boot_time_init();

#ifdef	IOKIT
	{
		PE_init_iokit();
	}
#endif

	/*
	 *	Start the user bootstrap.
	 */
	
	(void) spllo();		/* Allow interruptions */
	
#ifdef	MACH_BSD
	{ 
		extern void bsd_init(void);
		bsd_init();
	}
#endif

	thread_bind(current_thread(), PROCESSOR_NULL);

	/*
	 *	Become the pageout daemon.
	 */

	vm_pageout();
	/*NOTREACHED*/
}

void
slave_main(void)
{
	processor_t		myprocessor = current_processor();
	thread_t		thread;

	myprocessor->cpu_data = get_cpu_data();
	thread = myprocessor->next_thread;
	myprocessor->next_thread = THREAD_NULL;
	if (thread == THREAD_NULL) {
		thread = machine_wake_thread;
		machine_wake_thread = THREAD_NULL;
	}
        thread_machine_set_current(thread);
	if (thread == machine_wake_thread)
		thread_bind(thread, myprocessor);

	cpu_launch_first_thread(thread);
	/*NOTREACHED*/
	panic("slave_main");
}

/*
 * Now running in a thread context
 */
void
start_cpu_thread(void)
{
	processor_t	processor;

	processor = cpu_to_processor(cpu_number());

	slave_machine_init();

	if (processor->processor_self == IP_NULL) {
		ipc_processor_init(processor);
		ipc_processor_enable(processor);
	}

	(void) thread_terminate(current_act());
}

/*
 *	Start up the first thread on a CPU.
 */
void
cpu_launch_first_thread(
	thread_t		thread)
{
	register int	mycpu = cpu_number();
	processor_t		processor = cpu_to_processor(mycpu);

	processor->cpu_data->preemption_level = 0;

	cpu_up(mycpu);
	start_timer(&kernel_timer[mycpu]);
	clock_get_uptime(&processor->last_dispatch);

	if (thread == THREAD_NULL || thread == processor->idle_thread)
		panic("cpu_launch_first_thread");

	rtclock_reset();		/* start realtime clock ticking */
	PMAP_ACTIVATE_KERNEL(mycpu);

	thread_machine_set_current(thread);
	thread_lock(thread);
	thread->state &= ~TH_UNINT;
	thread->last_processor = processor;
	processor->current_pri = thread->sched_pri;
	_mk_sp_thread_begin(thread, processor);
	thread_unlock(thread);
	timer_switch(&thread->system_timer);

	PMAP_ACTIVATE_USER(thread->top_act, mycpu);

	/* preemption enabled by load_context */
	load_context(thread);
	/*NOTREACHED*/
}
