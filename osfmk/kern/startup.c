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
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
/*
 */

/*
 *	Mach kernel startup.
 */

#include <debug.h>
#include <xpr_debug.h>
#include <mach_kdp.h>

#include <mach/boolean.h>
#include <mach/machine.h>
#include <mach/thread_act.h>
#include <mach/task_special_ports.h>
#include <mach/vm_param.h>
#include <ipc/ipc_init.h>
#include <kern/assert.h>
#include <kern/mach_param.h>
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
#include <kern/wait_queue.h>
#include <kern/xpr.h>
#include <kern/zalloc.h>
#include <kern/locks.h>
#include <console/serial_protos.h>
#include <vm/vm_kern.h>
#include <vm/vm_init.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_shared_region.h>
#include <machine/pmap.h>
#include <machine/commpage.h>
#include <libkern/version.h>
#include <sys/kdebug.h>

#if MACH_KDP
#include <kdp/kdp.h>
#endif

#if CONFIG_MACF
#include <security/mac_mach_internal.h>
#endif

#if CONFIG_COUNTERS
#include <pmc/pmc.h>
#endif

#include <i386/pmCPU.h>
static void		kernel_bootstrap_thread(void);

static void		load_context(
					thread_t	thread);
#if (defined(__i386__) || defined(__x86_64__)) && NCOPY_WINDOWS > 0
extern void cpu_userwindow_init(int);
extern void cpu_physwindow_init(int);
#endif

// libkern/OSKextLib.cpp
extern void	OSKextRemoveKextBootstrap(void);

void scale_setup(void);
extern void bsd_scale_setup(int);
extern unsigned int semaphore_max;

/*
 *	Running in virtual memory, on the interrupt stack.
 */

extern int serverperfmode;

/* size of kernel trace buffer, disabled by default */
unsigned int new_nkdbufs = 0;
unsigned int wake_nkdbufs = 0;

/* mach leak logging */
int log_leaks = 0;
int turn_on_log_leaks = 0;


void
kernel_early_bootstrap(void)
{

	lck_mod_init();

	/*
	 * Initialize the timer callout world
	 */
	timer_call_initialize();
}


void
kernel_bootstrap(void)
{
	kern_return_t	result;
	thread_t	thread;
	char		namep[16];

	printf("%s\n", version); /* log kernel version */

#define kernel_bootstrap_kprintf(x...) /* kprintf("kernel_bootstrap: " x) */

	if (PE_parse_boot_argn("-l", namep, sizeof (namep))) /* leaks logging */
		turn_on_log_leaks = 1;

	PE_parse_boot_argn("trace", &new_nkdbufs, sizeof (new_nkdbufs));

	PE_parse_boot_argn("trace_wake", &wake_nkdbufs, sizeof (wake_nkdbufs));

	/* i386_vm_init already checks for this ; do it aagin anyway */
        if (PE_parse_boot_argn("serverperfmode", &serverperfmode, sizeof (serverperfmode))) {
                serverperfmode = 1;
        }
	scale_setup();

	kernel_bootstrap_kprintf("calling vm_mem_bootstrap\n");
	vm_mem_bootstrap();

	kernel_bootstrap_kprintf("calling vm_mem_init\n");
	vm_mem_init();

	machine_info.memory_size = (uint32_t)mem_size;
	machine_info.max_mem = max_mem;
	machine_info.major_version = version_major;
	machine_info.minor_version = version_minor;

	kernel_bootstrap_kprintf("calling sched_init\n");
	sched_init();

	kernel_bootstrap_kprintf("calling wait_queue_bootstrap\n");
	wait_queue_bootstrap();

	kernel_bootstrap_kprintf("calling ipc_bootstrap\n");
	ipc_bootstrap();

#if CONFIG_MACF
	mac_policy_init();
#endif
	kernel_bootstrap_kprintf("calling ipc_init\n");
	ipc_init();

	/*
	 * As soon as the virtual memory system is up, we record
	 * that this CPU is using the kernel pmap.
	 */
	kernel_bootstrap_kprintf("calling PMAP_ACTIVATE_KERNEL\n");
	PMAP_ACTIVATE_KERNEL(master_cpu);

	kernel_bootstrap_kprintf("calling mapping_free_prime\n");
	mapping_free_prime();						/* Load up with temporary mapping blocks */

	kernel_bootstrap_kprintf("calling machine_init\n");
	machine_init();

	kernel_bootstrap_kprintf("calling clock_init\n");
	clock_init();

	ledger_init();

	/*
	 *	Initialize the IPC, task, and thread subsystems.
	 */
	kernel_bootstrap_kprintf("calling task_init\n");
	task_init();

	kernel_bootstrap_kprintf("calling thread_init\n");
	thread_init();
	
	/*
	 *	Create a kernel thread to execute the kernel bootstrap.
	 */
	kernel_bootstrap_kprintf("calling kernel_thread_create\n");
	result = kernel_thread_create((thread_continue_t)kernel_bootstrap_thread, NULL, MAXPRI_KERNEL, &thread);

	if (result != KERN_SUCCESS) panic("kernel_bootstrap: result = %08X\n", result);

	thread->state = TH_RUN;
	thread_deallocate(thread);

	kernel_bootstrap_kprintf("calling load_context - done\n");
	load_context(thread);
	/*NOTREACHED*/
}

int kth_started = 0;

vm_offset_t vm_kernel_addrperm;

/*
 * Now running in a thread.  Kick off other services,
 * invoke user bootstrap, enter pageout loop.
 */
static void
kernel_bootstrap_thread(void)
{
	processor_t		processor = current_processor();

#define kernel_bootstrap_thread_kprintf(x...) /* kprintf("kernel_bootstrap_thread: " x) */
	kernel_bootstrap_thread_kprintf("calling idle_thread_create\n");
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
	kernel_bootstrap_thread_kprintf("calling sched_startup\n");
	sched_startup();

	/*
	 * Thread lifecycle maintenance (teardown, stack allocation)
	 */
	kernel_bootstrap_thread_kprintf("calling thread_daemon_init\n");
	thread_daemon_init();
	
	/*
	 * Thread callout service.
	 */
	kernel_bootstrap_thread_kprintf("calling thread_call_initialize\n");
	thread_call_initialize();
	
	/*
	 * Remain on current processor as
	 * additional processors come online.
	 */
	kernel_bootstrap_thread_kprintf("calling thread_bind\n");
	thread_bind(processor);

	/*
	 * Kick off memory mapping adjustments.
	 */
	kernel_bootstrap_thread_kprintf("calling mapping_adjust\n");
	mapping_adjust();

	/*
	 *	Create the clock service.
	 */
	kernel_bootstrap_thread_kprintf("calling clock_service_create\n");
	clock_service_create();

	/*
	 *	Create the device service.
	 */
	device_service_create();

	kth_started = 1;
		
#if (defined(__i386__) || defined(__x86_64__)) && NCOPY_WINDOWS > 0
	/*
	 * Create and initialize the physical copy window for processor 0
	 * This is required before starting kicking off  IOKit.
	 */
	cpu_physwindow_init(0);
#endif

	vm_kernel_reserved_entry_init();
	
#if MACH_KDP
	kernel_bootstrap_kprintf("calling kdp_init\n");
	kdp_init();
#endif

#if CONFIG_COUNTERS
	pmc_bootstrap();
#endif

#if (defined(__i386__) || defined(__x86_64__))
	if (turn_on_log_leaks && !new_nkdbufs)
		new_nkdbufs = 200000;
	start_kern_tracing(new_nkdbufs, FALSE);
	if (turn_on_log_leaks)
		log_leaks = 1;
#endif

#ifdef	IOKIT
	PE_init_iokit();
#endif
	
	(void) spllo();		/* Allow interruptions */

#if (defined(__i386__) || defined(__x86_64__)) && NCOPY_WINDOWS > 0
	/*
	 * Create and initialize the copy window for processor 0
	 * This also allocates window space for all other processors.
	 * However, this is dependent on the number of processors - so this call
	 * must be after IOKit has been started because IOKit performs processor
	 * discovery.
	 */
	cpu_userwindow_init(0);
#endif

#if (!defined(__i386__) && !defined(__x86_64__))
	if (turn_on_log_leaks && !new_nkdbufs)
		new_nkdbufs = 200000;
	start_kern_tracing(new_nkdbufs, FALSE);
	if (turn_on_log_leaks)
		log_leaks = 1;
#endif

	/*
	 *	Initialize the shared region module.
	 */
	vm_shared_region_init();
	vm_commpage_init();
	vm_commpage_text_init();

#if CONFIG_MACF
	mac_policy_initmach();
#endif

	/*
	 * Initialize the global used for permuting kernel
	 * addresses that may be exported to userland as tokens
	 * using VM_KERNEL_ADDRPERM(). Force the random number
	 * to be odd to avoid mapping a non-zero
	 * word-aligned address to zero via addition.
	 */
	vm_kernel_addrperm = (vm_offset_t)early_random() | 1;

	/*
	 *	Start the user bootstrap.
	 */
#ifdef	MACH_BSD
	bsd_init();
#endif

    /*
     * Get rid of segments used to bootstrap kext loading. This removes
     * the KLD, PRELINK symtab, LINKEDIT, and symtab segments/load commands.
     */
	OSKextRemoveKextBootstrap();

	serial_keyboard_init();		/* Start serial keyboard if wanted */

	vm_page_init_local_q();

	thread_bind(PROCESSOR_NULL);

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
slave_main(void *machine_param)
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
		thread->parameter = machine_param;
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
processor_start_thread(void *machine_param)
{
	processor_t		processor = current_processor();
	thread_t		self = current_thread();

	slave_machine_init(machine_param);

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


#define load_context_kprintf(x...) /* kprintf("load_context: " x) */

	load_context_kprintf("calling machine_set_current_thread\n");
	machine_set_current_thread(thread);

	load_context_kprintf("calling processor_up\n");
	processor_up(processor);

	PMAP_ACTIVATE_KERNEL(processor->cpu_id);

	/*
	 * Acquire a stack if none attached.  The panic
	 * should never occur since the thread is expected
	 * to have reserved stack.
	 */
	load_context_kprintf("thread %p, stack %x, stackptr %x\n", thread, 
			     thread->kernel_stack, thread->machine.kstackptr);
	if (!thread->kernel_stack) {
		load_context_kprintf("calling stack_alloc_try\n");
		if (!stack_alloc_try(thread))
			panic("load_context");
	}

	/*
	 * The idle processor threads are not counted as
	 * running for load calculations.
	 */
	if (!(thread->state & TH_IDLE))
		sched_run_incr();

	processor->active_thread = thread;
	processor->current_pri = thread->sched_pri;
	processor->current_thmode = thread->sched_mode;
	processor->deadline = UINT64_MAX;
	thread->last_processor = processor;

	processor->last_dispatch = mach_absolute_time();
	timer_start(&thread->system_timer, processor->last_dispatch);
	PROCESSOR_DATA(processor, thread_timer) = PROCESSOR_DATA(processor, kernel_timer) = &thread->system_timer;

	timer_start(&PROCESSOR_DATA(processor, system_state), processor->last_dispatch);
	PROCESSOR_DATA(processor, current_state) = &PROCESSOR_DATA(processor, system_state);

	PMAP_ACTIVATE_USER(thread, processor->cpu_id);

	load_context_kprintf("calling machine_load_context\n");
	machine_load_context(thread);
	/*NOTREACHED*/
}

void
scale_setup()
{
	int scale = 0;
#if defined(__LP64__)
	typeof(task_max) task_max_base = task_max;

	/* Raise limits for servers with >= 16G */
	if ((serverperfmode != 0) && ((uint64_t)sane_size >= (uint64_t)(16 * 1024 * 1024 *1024ULL))) {
		scale = (int)((uint64_t)sane_size / (uint64_t)(8 * 1024 * 1024 *1024ULL));
		/* limit to 128 G */
		if (scale > 16)
			scale = 16;
		task_max_base = 2500;
	} else if ((uint64_t)sane_size >= (uint64_t)(3 * 1024 * 1024 *1024ULL))
		scale = 2;

	task_max = MAX(task_max, task_max_base * scale);

	if (scale != 0) {
		task_threadmax = task_max;
		thread_max = task_max * 5; 
	}

#endif

	bsd_scale_setup(scale);
	
	ipc_space_max = SPACE_MAX;
	ipc_port_max = PORT_MAX;
	ipc_pset_max = SET_MAX;
	semaphore_max = SEMAPHORE_MAX;
}

