/*
 * Copyright (c) 2000-2012 Apple Inc. All rights reserved.
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

#include <i386/pmap.h>
#include <i386/proc_reg.h>
#include <i386/mp_desc.h>
#include <i386/misc_protos.h>
#include <i386/mp.h>
#include <i386/cpu_data.h>
#if CONFIG_MTRR
#include <i386/mtrr.h>
#endif
#if HYPERVISOR
#include <kern/hv_support.h>
#endif
#if CONFIG_VMX
#include <i386/vmx/vmx_cpu.h>
#endif
#include <i386/ucode.h>
#include <i386/acpi.h>
#include <i386/fpu.h>
#include <i386/lapic.h>
#include <i386/mp.h>
#include <i386/mp_desc.h>
#include <i386/serial_io.h>
#if CONFIG_MCA
#include <i386/machine_check.h>
#endif
#include <i386/pmCPU.h>

#include <i386/tsc.h>

#include <kern/cpu_data.h>
#include <kern/machine.h>
#include <kern/timer_queue.h>
#include <console/serial_protos.h>
#include <machine/pal_routines.h>
#include <vm/vm_page.h>

#if HIBERNATION
#include <IOKit/IOHibernatePrivate.h>
#endif
#include <IOKit/IOPlatformExpert.h>
#include <sys/kdebug.h>

#if MONOTONIC
#include <kern/monotonic.h>
#endif /* MONOTONIC */

#if CONFIG_SLEEP
extern void	acpi_sleep_cpu(acpi_sleep_callback, void * refcon);
extern void	acpi_wake_prot(void);
#endif
extern kern_return_t IOCPURunPlatformQuiesceActions(void);
extern kern_return_t IOCPURunPlatformActiveActions(void);
extern kern_return_t IOCPURunPlatformHaltRestartActions(uint32_t message);

extern void 	fpinit(void);

vm_offset_t
acpi_install_wake_handler(void)
{
#if CONFIG_SLEEP
	install_real_mode_bootstrap(acpi_wake_prot);
	return REAL_MODE_BOOTSTRAP_OFFSET;
#else
	return 0;
#endif
}

#if CONFIG_SLEEP

unsigned int		save_kdebug_enable = 0;
static uint64_t		acpi_sleep_abstime;
static uint64_t		acpi_idle_abstime;
static uint64_t		acpi_wake_abstime, acpi_wake_postrebase_abstime;
boolean_t		deep_idle_rebase = TRUE;

#if HIBERNATION
struct acpi_hibernate_callback_data {
	acpi_sleep_callback func;
	void *refcon;
};
typedef struct acpi_hibernate_callback_data acpi_hibernate_callback_data_t;

static void
acpi_hibernate(void *refcon)
{
	uint32_t mode;

	acpi_hibernate_callback_data_t *data =
		(acpi_hibernate_callback_data_t *)refcon;

	if (current_cpu_datap()->cpu_hibernate) 
	{
		mode = hibernate_write_image();

		if( mode == kIOHibernatePostWriteHalt )
		{
			// off
			HIBLOG("power off\n");
			IOCPURunPlatformHaltRestartActions(kPEHaltCPU);
			if (PE_halt_restart) (*PE_halt_restart)(kPEHaltCPU);
		}
		else if( mode == kIOHibernatePostWriteRestart )
		{
			// restart
			HIBLOG("restart\n");
			IOCPURunPlatformHaltRestartActions(kPERestartCPU);
			if (PE_halt_restart) (*PE_halt_restart)(kPERestartCPU);
		}
		else
		{
			// sleep
			HIBLOG("sleep\n");
	
			// should we come back via regular wake, set the state in memory.
			cpu_datap(0)->cpu_hibernate = 0;			
		}

	}

#if CONFIG_VMX
	vmx_suspend();
#endif
	kdebug_enable = 0;

	IOCPURunPlatformQuiesceActions();

	acpi_sleep_abstime = mach_absolute_time();

	(data->func)(data->refcon);

	/* should never get here! */
}
#endif /* HIBERNATION */
#endif /* CONFIG_SLEEP */

extern void			slave_pstart(void);
extern void			hibernate_rebuild_vm_structs(void);

extern unsigned int wake_nkdbufs;
extern unsigned int trace_wrap;

void
acpi_sleep_kernel(acpi_sleep_callback func, void *refcon)
{
#if HIBERNATION
	acpi_hibernate_callback_data_t data;
#endif
	boolean_t did_hibernate;
	cpu_data_t *cdp = current_cpu_datap();
	unsigned int	cpu;
	kern_return_t	rc;
	unsigned int	my_cpu;
	uint64_t	start;
	uint64_t	elapsed = 0;
	uint64_t	elapsed_trace_start = 0;

	my_cpu = cpu_number();
	kprintf("acpi_sleep_kernel hib=%d, cpu=%d\n", cdp->cpu_hibernate,
			my_cpu);

	/* Get all CPUs to be in the "off" state */
	for (cpu = 0; cpu < real_ncpus; cpu += 1) {
		if (cpu == my_cpu)
			continue;
		rc = pmCPUExitHaltToOff(cpu);
		if (rc != KERN_SUCCESS)
			panic("Error %d trying to transition CPU %d to OFF",
			      rc, cpu);
	}

	/* shutdown local APIC before passing control to firmware */
	lapic_shutdown();

#if HIBERNATION
	data.func = func;
	data.refcon = refcon;
#endif

#if MONOTONIC
	mt_cpu_down(cdp);
#endif /* MONOTONIC */

	/* Save power management timer state */
	pmTimerSave();

#if HYPERVISOR
	/* Notify hypervisor that we are about to sleep */
	hv_suspend();
#endif

	/*
	 * Enable FPU/SIMD unit for potential hibernate acceleration
	 */
	clear_ts(); 

	KDBG(IOKDBG_CODE(DBG_HIBERNATE, 0) | DBG_FUNC_START);

	save_kdebug_enable = kdebug_enable;
	kdebug_enable = 0;

	acpi_sleep_abstime = mach_absolute_time();

#if CONFIG_SLEEP
	/*
	 * Save master CPU state and sleep platform.
	 * Will not return until platform is woken up,
	 * or if sleep failed.
	 */
	uint64_t old_cr3 = x86_64_pre_sleep();
#if HIBERNATION
	acpi_sleep_cpu(acpi_hibernate, &data);
#else
#if CONFIG_VMX
	vmx_suspend();
#endif
	acpi_sleep_cpu(func, refcon);
#endif

	acpi_wake_abstime = mach_absolute_time();
	/* Rebase TSC->absolute time conversion, using timestamp
	 * recorded before sleep.
	 */
	rtc_nanotime_init(acpi_sleep_abstime);
	acpi_wake_postrebase_abstime = start = mach_absolute_time();
	assert(start >= acpi_sleep_abstime);

	x86_64_post_sleep(old_cr3);

#endif /* CONFIG_SLEEP */

	/* Reset UART if kprintf is enabled.
	 * However kprintf should not be used before rtc_sleep_wakeup()
	 * for compatibility with firewire kprintf.
	 */

	if (FALSE == disable_serial_output)
		pal_serial_init();

#if HIBERNATION
	if (current_cpu_datap()->cpu_hibernate) {
		did_hibernate = TRUE;

	} else
#endif 
	{
		did_hibernate = FALSE;
	}

	/* Re-enable fast syscall */
	cpu_syscall_init(current_cpu_datap());

#if CONFIG_MCA
	/* Re-enable machine check handling */
	mca_cpu_init();
#endif

#if CONFIG_MTRR
	/* restore MTRR settings */
	mtrr_update_cpu();
#endif

	/* update CPU microcode */
	ucode_update_wake();

#if CONFIG_MTRR
	/* set up PAT following boot processor power up */
	pat_init();
#endif

#if CONFIG_VMX
	/* 
	 * Restore VT mode
	 */
	vmx_resume(did_hibernate);
#endif

	/*
	 * Go through all of the CPUs and mark them as requiring
	 * a full restart.
	 */
	pmMarkAllCPUsOff();


	/* re-enable and re-init local apic (prior to starting timers) */
	if (lapic_probe())
		lapic_configure();

#if KASAN
	/*
	 * The sleep implementation uses indirect noreturn calls, so we miss stack
	 * unpoisoning. Do it explicitly.
	 */
	kasan_unpoison_curstack(true);
#endif

#if HIBERNATION
	hibernate_rebuild_vm_structs();
#endif

	elapsed += mach_absolute_time() - start;

	rtc_decrementer_configure();
	kdebug_enable = save_kdebug_enable;

	if (kdebug_enable == 0) {
		if (wake_nkdbufs) {
			start = mach_absolute_time();
			kdebug_trace_start(wake_nkdbufs, NULL, trace_wrap != 0, TRUE);
			elapsed_trace_start += mach_absolute_time() - start;
		}
	}
	start = mach_absolute_time();

	/* Reconfigure FP/SIMD unit */
	init_fpu();
	clear_ts();

	IOCPURunPlatformActiveActions();

#if HIBERNATION
	if (did_hibernate) {
		KDBG(IOKDBG_CODE(DBG_HIBERNATE, 2) | DBG_FUNC_START);
		hibernate_machine_init();
		KDBG(IOKDBG_CODE(DBG_HIBERNATE, 2) | DBG_FUNC_END);

		current_cpu_datap()->cpu_hibernate = 0;
	}
#endif /* HIBERNATION */

	KDBG(IOKDBG_CODE(DBG_HIBERNATE, 0) | DBG_FUNC_END, start, elapsed,
			elapsed_trace_start, acpi_wake_abstime);

	/* Restore power management register state */
	pmCPUMarkRunning(current_cpu_datap());

	/* Restore power management timer state */
	pmTimerRestore();

	/* Restart timer interrupts */
	rtc_timer_start();

#if HIBERNATION

	kprintf("ret from acpi_sleep_cpu hib=%d\n", did_hibernate);
#endif

#if CONFIG_SLEEP
	/* Becase we don't save the bootstrap page, and we share it
	 * between sleep and mp slave init, we need to recreate it 
	 * after coming back from sleep or hibernate */
	install_real_mode_bootstrap(slave_pstart);
#endif
}

/*
 * acpi_idle_kernel is called by the ACPI Platform kext to request the kernel
 * to idle the boot processor in the deepest C-state for S0 sleep. All slave
 * processors are expected already to have been offlined in the deepest C-state.
 *
 * The contract with ACPI is that although the kernel is called with interrupts
 * disabled, interrupts may need to be re-enabled to dismiss any pending timer
 * interrupt. However, the callback function will be called once this has
 * occurred and interrupts are guaranteed to be disabled at that time,
 * and to remain disabled during C-state entry, exit (wake) and return
 * from acpi_idle_kernel.
 */
void
acpi_idle_kernel(acpi_sleep_callback func, void *refcon)
{
	boolean_t	istate = ml_get_interrupts_enabled();
	
	kprintf("acpi_idle_kernel, cpu=%d, interrupts %s\n",
		cpu_number(), istate ? "enabled" : "disabled");

	assert(cpu_number() == master_cpu);

	/* Cancel any pending deadline */
	setPop(0);
	while (lapic_is_interrupting(LAPIC_TIMER_VECTOR)) {
		(void) ml_set_interrupts_enabled(TRUE);
		setPop(0);
		ml_set_interrupts_enabled(FALSE);
	}

	if (current_cpu_datap()->cpu_hibernate)  {
        /* Call hibernate_write_image() to put disk to low power state */
        hibernate_write_image();
        cpu_datap(0)->cpu_hibernate = 0;
    }

	/*
	 * Call back to caller to indicate that interrupts will remain
	 * disabled while we deep idle, wake and return.
	 */ 
	IOCPURunPlatformQuiesceActions();

	func(refcon);

	acpi_idle_abstime = mach_absolute_time();

	KERNEL_DEBUG_CONSTANT(
		MACHDBG_CODE(DBG_MACH_SCHED, MACH_DEEP_IDLE) | DBG_FUNC_START,
		acpi_idle_abstime, deep_idle_rebase, 0, 0, 0);

	/*
	 * Disable tracing during S0-sleep
	 * unless overridden by sysctl -w tsc.deep_idle_rebase=0
	 */
	if (deep_idle_rebase) {
		save_kdebug_enable = kdebug_enable;
		kdebug_enable = 0;
	}

	/*
	 * Call into power-management to enter the lowest C-state.
	 * Note when called on the boot processor this routine will
	 * return directly when awoken.
	 */
	pmCPUHalt(PM_HALT_SLEEP);

	/*
	 * Get wakeup time relative to the TSC which has progressed.
	 * Then rebase nanotime to reflect time not progressing over sleep
	 * - unless overriden so that tracing can occur during deep_idle.
	 */ 
	acpi_wake_abstime = mach_absolute_time();
	if (deep_idle_rebase) {
		rtc_sleep_wakeup(acpi_idle_abstime);
		kdebug_enable = save_kdebug_enable;
	}
	acpi_wake_postrebase_abstime = mach_absolute_time();
	assert(mach_absolute_time() >= acpi_idle_abstime);

	KERNEL_DEBUG_CONSTANT(
		MACHDBG_CODE(DBG_MACH_SCHED, MACH_DEEP_IDLE) | DBG_FUNC_END,
		acpi_wake_abstime, acpi_wake_abstime - acpi_idle_abstime, 0, 0, 0);
 
	/* Like S3 sleep, turn on tracing if trace_wake boot-arg is present */ 
	if (kdebug_enable == 0) {
		if (wake_nkdbufs) {
			__kdebug_only uint64_t start = mach_absolute_time();
			kdebug_trace_start(wake_nkdbufs, NULL, trace_wrap != 0, TRUE);
			KDBG(IOKDBG_CODE(DBG_HIBERNATE, 15), start);
		}
	}

	IOCPURunPlatformActiveActions();

	/* Restart timer interrupts */
	rtc_timer_start();
}

extern char real_mode_bootstrap_end[];
extern char real_mode_bootstrap_base[];

void
install_real_mode_bootstrap(void *prot_entry)
{
	/*
	 * Copy the boot entry code to the real-mode vector area REAL_MODE_BOOTSTRAP_OFFSET.
	 * This is in page 1 which has been reserved for this purpose by
	 * machine_startup() from the boot processor.
	 * The slave boot code is responsible for switching to protected
	 * mode and then jumping to the common startup, _start().
	 */
	bcopy_phys(kvtophys((vm_offset_t) real_mode_bootstrap_base),
		   (addr64_t) REAL_MODE_BOOTSTRAP_OFFSET,
		   real_mode_bootstrap_end-real_mode_bootstrap_base);

	/*
	 * Set the location at the base of the stack to point to the
	 * common startup entry.
	 */
	ml_phys_write_word(
		PROT_MODE_START+REAL_MODE_BOOTSTRAP_OFFSET,
		(unsigned int)kvtophys((vm_offset_t)prot_entry));
	
	/* Flush caches */
	__asm__("wbinvd");
}

boolean_t
ml_recent_wake(void) {
	uint64_t ctime = mach_absolute_time();
	assert(ctime > acpi_wake_postrebase_abstime);
	return ((ctime - acpi_wake_postrebase_abstime) < 5 * NSEC_PER_SEC);
}
