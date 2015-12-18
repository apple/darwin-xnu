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
#include <kern/coalition.h>
#include <kern/cpu_number.h>
#include <kern/ledger.h>
#include <kern/machine.h>
#include <kern/processor.h>
#include <kern/sched_prim.h>
#if CONFIG_SCHED_SFI
#include <kern/sfi.h>
#endif
#include <kern/startup.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/timer.h>
#if CONFIG_TELEMETRY
#include <kern/telemetry.h>
#endif
#include <kern/xpr.h>
#include <kern/zalloc.h>
#include <kern/locks.h>
#include <kern/debug.h>
#include <corpses/task_corpse.h>
#include <prng/random.h>
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
#include <sys/codesign.h>
#include <sys/kdebug.h>
#include <sys/random.h>

#include <kern/waitq.h>


#if CONFIG_ATM
#include <atm/atm_internal.h>
#endif

#if CONFIG_CSR
#include <sys/csr.h>
#endif

#if CONFIG_BANK
#include <bank/bank_internal.h>
#endif

#if ALTERNATE_DEBUGGER
#include <arm64/alternate_debugger.h>
#endif

#if MACH_KDP
#include <kdp/kdp.h>
#endif

#if CONFIG_MACF
#include <security/mac_mach_internal.h>
#endif

#if KPC
#include <kern/kpc.h>
#endif

#if KPERF
#include <kperf/kperf.h>
#endif

#if HYPERVISOR
#include <kern/hv_support.h>
#endif


#include <i386/pmCPU.h>
static void		kernel_bootstrap_thread(void);

static void		load_context(
					thread_t	thread);
#if (defined(__i386__) || defined(__x86_64__)) && NCOPY_WINDOWS > 0
extern void cpu_userwindow_init(int);
extern void cpu_physwindow_init(int);
#endif

#if CONFIG_ECC_LOGGING
#include <kern/ecc.h>
#endif 

#if (defined(__i386__) || defined(__x86_64__)) && CONFIG_VMX
#include <i386/vmx/vmx_cpu.h>
#endif

// libkern/OSKextLib.cpp
extern void	OSKextRemoveKextBootstrap(void);

void scale_setup(void);
extern void bsd_scale_setup(int);
extern unsigned int semaphore_max;
extern void stackshot_lock_init(void);

/*
 *	Running in virtual memory, on the interrupt stack.
 */

extern int serverperfmode;

/* size of kernel trace buffer, disabled by default */
unsigned int new_nkdbufs = 0;
unsigned int wake_nkdbufs = 0;
unsigned int write_trace_on_panic = 0;
unsigned int trace_typefilter = 0;
boolean_t    trace_serial = FALSE;

/* mach leak logging */
int log_leaks = 0;
int turn_on_log_leaks = 0;

static inline void
kernel_bootstrap_log(const char *message)
{
//	kprintf("kernel_bootstrap: %s\n", message);
	kernel_debug_string_simple(message);
}

static inline void
kernel_bootstrap_thread_log(const char *message)
{
//	kprintf("kernel_bootstrap_thread: %s\n", message);
	kernel_debug_string_simple(message);
}

void
kernel_early_bootstrap(void)
{
	/* serverperfmode is needed by timer setup */
        if (PE_parse_boot_argn("serverperfmode", &serverperfmode, sizeof (serverperfmode))) {
                serverperfmode = 1;
        }

	lck_mod_init();

	/*
	 * Initialize the timer callout world
	 */
	timer_call_init();

#if CONFIG_SCHED_SFI
	/*
	 * Configure SFI classes
	 */
	sfi_early_init();
#endif
}

extern boolean_t IORamDiskBSDRoot(void);
extern kern_return_t cpm_preallocate_early(void);

void
kernel_bootstrap(void)
{
	kern_return_t	result;
	thread_t	thread;
	char		namep[16];

	printf("%s\n", version); /* log kernel version */

	if (PE_parse_boot_argn("-l", namep, sizeof (namep))) /* leaks logging */
		turn_on_log_leaks = 1;

	PE_parse_boot_argn("trace", &new_nkdbufs, sizeof (new_nkdbufs));
	PE_parse_boot_argn("trace_wake", &wake_nkdbufs, sizeof (wake_nkdbufs));
	PE_parse_boot_argn("trace_panic", &write_trace_on_panic, sizeof(write_trace_on_panic));
	PE_parse_boot_argn("trace_typefilter", &trace_typefilter, sizeof(trace_typefilter));

	scale_setup();

	kernel_bootstrap_log("vm_mem_bootstrap");
	vm_mem_bootstrap();

	kernel_bootstrap_log("cs_init");
	cs_init();

	kernel_bootstrap_log("vm_mem_init");
	vm_mem_init();

	machine_info.memory_size = (uint32_t)mem_size;
	machine_info.max_mem = max_mem;
	machine_info.major_version = version_major;
	machine_info.minor_version = version_minor;


#if CONFIG_TELEMETRY
	kernel_bootstrap_log("telemetry_init");
	telemetry_init();
#endif

#if CONFIG_CSR
	kernel_bootstrap_log("csr_init");
	csr_init();
#endif

	if (PE_i_can_has_debugger(NULL) &&
	    PE_parse_boot_argn("-show_pointers", &namep, sizeof (namep))) {
		doprnt_hide_pointers = FALSE;
	}

	kernel_bootstrap_log("stackshot_lock_init");	
	stackshot_lock_init();

	kernel_bootstrap_log("sched_init");
	sched_init();

	kernel_bootstrap_log("waitq_bootstrap");
	waitq_bootstrap();

	kernel_bootstrap_log("ipc_bootstrap");
	ipc_bootstrap();

#if CONFIG_MACF
	kernel_bootstrap_log("mac_policy_init");
	mac_policy_init();
#endif

	kernel_bootstrap_log("ipc_init");
	ipc_init();

	/*
	 * As soon as the virtual memory system is up, we record
	 * that this CPU is using the kernel pmap.
	 */
	kernel_bootstrap_log("PMAP_ACTIVATE_KERNEL");
	PMAP_ACTIVATE_KERNEL(master_cpu);

	kernel_bootstrap_log("mapping_free_prime");
	mapping_free_prime();						/* Load up with temporary mapping blocks */

	kernel_bootstrap_log("machine_init");
	machine_init();

	kernel_bootstrap_log("clock_init");
	clock_init();

	ledger_init();

	/*
	 *	Initialize the IPC, task, and thread subsystems.
	 */
#if CONFIG_COALITIONS
	kernel_bootstrap_log("coalitions_init");
	coalitions_init();
#endif

	kernel_bootstrap_log("task_init");
	task_init();

	kernel_bootstrap_log("thread_init");
	thread_init();

#if CONFIG_ATM
	/* Initialize the Activity Trace Resource Manager. */
	kernel_bootstrap_log("atm_init");
	atm_init();
#endif

#if CONFIG_BANK
	/* Initialize the BANK Manager. */
	kernel_bootstrap_log("bank_init");
	bank_init();
#endif
	
	/* initialize the corpse config based on boot-args */
	corpses_init();

	/*
	 *	Create a kernel thread to execute the kernel bootstrap.
	 */
	kernel_bootstrap_log("kernel_thread_create");
	result = kernel_thread_create((thread_continue_t)kernel_bootstrap_thread, NULL, MAXPRI_KERNEL, &thread);

	if (result != KERN_SUCCESS) panic("kernel_bootstrap: result = %08X\n", result);

	thread->state = TH_RUN;
	thread->last_made_runnable_time = mach_absolute_time();
	thread_deallocate(thread);

	kernel_bootstrap_log("load_context - done");
	load_context(thread);
	/*NOTREACHED*/
}

int kth_started = 0;

vm_offset_t vm_kernel_addrperm;
vm_offset_t buf_kernel_addrperm;
vm_offset_t vm_kernel_addrperm_ext;

/*
 * Now running in a thread.  Kick off other services,
 * invoke user bootstrap, enter pageout loop.
 */
static void
kernel_bootstrap_thread(void)
{
	processor_t		processor = current_processor();

#define kernel_bootstrap_thread_kprintf(x...) /* kprintf("kernel_bootstrap_thread: " x) */
	kernel_bootstrap_thread_log("idle_thread_create");
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
	kernel_bootstrap_thread_log("sched_startup");
	sched_startup();

	/*
	 * Thread lifecycle maintenance (teardown, stack allocation)
	 */
	kernel_bootstrap_thread_log("thread_daemon_init");
	thread_daemon_init();

	/* Create kernel map entry reserve */
	vm_kernel_reserved_entry_init();

	/*
	 * Thread callout service.
	 */
	kernel_bootstrap_thread_log("thread_call_initialize");
	thread_call_initialize();

	/*
	 * Remain on current processor as
	 * additional processors come online.
	 */
	kernel_bootstrap_thread_log("thread_bind");
	thread_bind(processor);

	/*
	 * Initialize ipc thread call support.
	 */
	kernel_bootstrap_thread_log("ipc_thread_call_init");
	ipc_thread_call_init();

	/*
	 * Kick off memory mapping adjustments.
	 */
	kernel_bootstrap_thread_log("mapping_adjust");
	mapping_adjust();

	/*
	 *	Create the clock service.
	 */
	kernel_bootstrap_thread_log("clock_service_create");
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


	
#if MACH_KDP 
	kernel_bootstrap_log("kdp_init");
	kdp_init();
#endif

#if ALTERNATE_DEBUGGER
	alternate_debugger_init();
#endif

#if KPC
	kpc_init();
#endif

#if CONFIG_ECC_LOGGING
	ecc_log_init();
#endif 

#if KPERF
	kperf_bootstrap();
#endif

#if HYPERVISOR
	hv_support_init();
#endif

#if CONFIG_TELEMETRY
	kernel_bootstrap_log("bootprofile_init");
	bootprofile_init();
#endif

#if (defined(__i386__) || defined(__x86_64__)) && CONFIG_VMX
	vmx_init();
#endif

#if (defined(__i386__) || defined(__x86_64__))
	if (kdebug_serial) {
		new_nkdbufs = 1;
		if (trace_typefilter == 0)
			trace_typefilter = 1;
	}
	if (turn_on_log_leaks && !new_nkdbufs)
		new_nkdbufs = 200000;
	if (trace_typefilter)
		start_kern_tracing_with_typefilter(new_nkdbufs,
						   FALSE,
						   trace_typefilter);
	else
		start_kern_tracing(new_nkdbufs, FALSE);
	if (turn_on_log_leaks)
		log_leaks = 1;

#endif

	kernel_bootstrap_log("prng_init");
	prng_cpu_init(master_cpu);

#ifdef	IOKIT
	PE_init_iokit();
#endif

	assert(ml_get_interrupts_enabled() == FALSE);
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
	if (trace_typefilter)
		start_kern_tracing_with_typefilter(new_nkdbufs, FALSE, trace_typefilter);
	else
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
	kernel_bootstrap_log("mac_policy_initmach");
	mac_policy_initmach();
#endif


#if CONFIG_SCHED_SFI
	kernel_bootstrap_log("sfi_init");
	sfi_init();
#endif

	/*
	 * Initialize the globals used for permuting kernel
	 * addresses that may be exported to userland as tokens
	 * using VM_KERNEL_ADDRPERM()/VM_KERNEL_ADDRPERM_EXTERNAL().
	 * Force the random number to be odd to avoid mapping a non-zero
	 * word-aligned address to zero via addition.
	 * Note: at this stage we can use the cryptographically secure PRNG
	 * rather than early_random().
	 */
	read_random(&vm_kernel_addrperm, sizeof(vm_kernel_addrperm));
	vm_kernel_addrperm |= 1;
	read_random(&buf_kernel_addrperm, sizeof(buf_kernel_addrperm));
	buf_kernel_addrperm |= 1;
	read_random(&vm_kernel_addrperm_ext, sizeof(vm_kernel_addrperm_ext));
	vm_kernel_addrperm_ext |= 1;

	vm_set_restrictions();



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

	load_context_kprintf("machine_set_current_thread\n");
	machine_set_current_thread(thread);

	load_context_kprintf("processor_up\n");
	processor_up(processor);

	PMAP_ACTIVATE_KERNEL(processor->cpu_id);

	/*
	 * Acquire a stack if none attached.  The panic
	 * should never occur since the thread is expected
	 * to have reserved stack.
	 */
	load_context_kprintf("thread %p, stack %lx, stackptr %lx\n", thread,
			     thread->kernel_stack, thread->machine.kstackptr);
	if (!thread->kernel_stack) {
		load_context_kprintf("stack_alloc_try\n");
		if (!stack_alloc_try(thread))
			panic("load_context");
	}

	/*
	 * The idle processor threads are not counted as
	 * running for load calculations.
	 */
	if (!(thread->state & TH_IDLE))
		sched_run_incr(thread);

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

	load_context_kprintf("machine_load_context\n");
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

