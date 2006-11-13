/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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
#include <mach_host.h>
#include <norma_vm.h>

#include <mach/boolean.h>
#include <mach/machine.h>
#include <mach/thread_act.h>
#include <mach/task_special_ports.h>
#include <mach/vm_param.h>
#include <ipc/ipc_init.h>
#include <kern/assert.h>
#include <kern/misc_protos.h>
#include <kern/clock.h>
#include <kern/cpu_number.h>
#include <kern/ledger.h>
#include <kern/machine.h>
#include <kern/processor.h>
#include <kern/sched_prim.h>
#include <kern/startup.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/timer.h>
#include <kern/xpr.h>
#include <kern/zalloc.h>
#include <kern/locks.h>
#include <vm/vm_shared_memory_server.h>
#include <vm/vm_kern.h>
#include <vm/vm_init.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <machine/pmap.h>
#include <machine/commpage.h>
#include <libkern/version.h>

#ifdef __ppc__
#include <ppc/Firmware.h>
#include <ppc/mappings.h>
#include <ppc/serial_io.h>
#endif

static void		kernel_bootstrap_thread(void);

static void		load_context(
					thread_t	thread);

/*
 *	Running in virtual memory, on the interrupt stack.
 */
void
kernel_bootstrap(void)
{
	kern_return_t	result;
	thread_t		thread;

	lck_mod_init();
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

	mapping_free_prime();						/* Load up with temporary mapping blocks */

	machine_init();
	kmod_init();
	clock_init();

	machine_info.memory_size = mem_size;
	machine_info.max_mem = max_mem;
	machine_info.major_version = version_major;
	machine_info.minor_version = version_minor;

	/*
	 *	Initialize the IPC, task, and thread subsystems.
	 */
	ledger_init();
	task_init();
	thread_init();
	
	/*
	 *	Create a kernel thread to execute the kernel bootstrap.
	 */
	result = kernel_thread_create((thread_continue_t)kernel_bootstrap_thread, NULL, MAXPRI_KERNEL, &thread);
	if (result != KERN_SUCCESS)
		panic("kernel_bootstrap");

	thread->state = TH_RUN;
	thread_deallocate(thread);

	load_context(thread);
	/*NOTREACHED*/
}

/*
 * Now running in a thread.  Kick off other services,
 * invoke user bootstrap, enter pageout loop.
 */
static void
kernel_bootstrap_thread(void)
{
	processor_t		processor = current_processor();
	thread_t		self = current_thread();

	/*
	 * Create the idle processor thread.
	 */
	idle_thread_create(processor);

	/*
	 * N.B. Do not stick anything else
	 * before this point.
	 *
	 * Start up the scheduler services.
	 */
	sched_startup();

	/*
	 * Remain on current processor as
	 * additional processors come online.
	 */
	thread_bind(self, processor);

	/*
	 * Kick off memory mapping adjustments.
	 */
	mapping_adjust();

	/*
	 *	Create the clock service.
	 */
	clock_service_create();

	/*
	 *	Create the device service.
	 */
	device_service_create();

	shared_file_boot_time_init(ENV_DEFAULT_ROOT, cpu_type());

#ifdef	IOKIT
	{
		PE_init_iokit();
	}
#endif
	
	(void) spllo();		/* Allow interruptions */

    /*
     *	Fill in the comm area (mapped into every task address space.)
     */
    commpage_populate();

	/*
	 *	Start the user bootstrap.
	 */
#ifdef	MACH_BSD
	{ 
		bsd_init();
	}
#endif

#if __ppc__
	serial_keyboard_init();		/* Start serial keyboard if wanted */
#endif

	thread_bind(self, PROCESSOR_NULL);

	/*
	 *	Become the pageout daemon.
	 */
	vm_pageout();
	/*NOTREACHED*/
}

/*
 *	slave_main:
 *
 *	Load the first thread to start a processor.
 */
void
slave_main(void)
{
	processor_t		processor = current_processor();
	thread_t		thread;

	/*
	 *	Use the idle processor thread if there
	 *	is no dedicated start up thread.
	 */
	if (processor->next_thread == THREAD_NULL) {
		thread = processor->idle_thread;
		thread->continuation = (thread_continue_t)processor_start_thread;
		thread->parameter = NULL;
	}
	else {
		thread = processor->next_thread;
		processor->next_thread = THREAD_NULL;
	}

	load_context(thread);
	/*NOTREACHED*/
}

/*
 *	processor_start_thread:
 *
 *	First thread to execute on a started processor.
 *
 *	Called at splsched.
 */
void
processor_start_thread(void)
{
	processor_t		processor = current_processor();
	thread_t		self = current_thread();

	slave_machine_init();

	/*
	 *	If running the idle processor thread,
	 *	reenter the idle loop, else terminate.
	 */
	if (self == processor->idle_thread)
		thread_block((thread_continue_t)idle_thread);

	thread_terminate(self);
	/*NOTREACHED*/
}

/*
 *	load_context:
 *
 *	Start the first thread on a processor.
 */
static void
load_context(
	thread_t		thread)
{
	processor_t		processor = current_processor();

	machine_set_current_thread(thread);
	processor_up(processor);

	PMAP_ACTIVATE_KERNEL(PROCESSOR_DATA(processor, slot_num));

	/*
	 * Acquire a stack if none attached.  The panic
	 * should never occur since the thread is expected
	 * to have reserved stack.
	 */
	if (!thread->kernel_stack) {
		if (!stack_alloc_try(thread))
			panic("load_context");
	}

	/*
	 * The idle processor threads are not counted as
	 * running for load calculations.
	 */
	if (!(thread->state & TH_IDLE))
		pset_run_incr(thread->processor_set);

	processor->active_thread = thread;
	processor->current_pri = thread->sched_pri;
	processor->deadline = UINT64_MAX;
	thread->last_processor = processor;

	processor->last_dispatch = mach_absolute_time();
	timer_switch((uint32_t)processor->last_dispatch,
							&PROCESSOR_DATA(processor, offline_timer));

	PMAP_ACTIVATE_USER(thread, PROCESSOR_DATA(processor, slot_num));

	machine_load_context(thread);
	/*NOTREACHED*/
}
