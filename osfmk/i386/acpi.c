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

#include <i386/misc_protos.h>
#include <i386/cpu_data.h>
#include <i386/proc_reg.h>
#include <i386/pmap.h>
#include <i386/mtrr.h>
#include <i386/vmx/vmx_cpu.h>
#include <i386/acpi.h>
#include <i386/fpu.h>
#include <i386/lapic.h>
#include <i386/mp.h>
#include <i386/mp_desc.h>
#include <i386/serial_io.h>
#include <i386/machine_check.h>
#include <i386/pmCPU.h>

#include <kern/cpu_data.h>
#include <console/serial_protos.h>

#if HIBERNATION
#include <IOKit/IOHibernatePrivate.h>
#endif
#include <IOKit/IOPlatformExpert.h>

extern void	acpi_sleep_cpu(acpi_sleep_callback, void * refcon);
extern char acpi_wake_start[];
extern char	acpi_wake_end[];

extern void        set_kbd_leds(int leds);

extern void 	fpinit(void);

vm_offset_t
acpi_install_wake_handler(void)
{
	/* copy wake code to ACPI_WAKE_ADDR in low memory */
	bcopy_phys(kvtophys((vm_offset_t)acpi_wake_start),
		   (addr64_t) ACPI_WAKE_ADDR,
		   acpi_wake_end - acpi_wake_start);

	/* flush cache */
	wbinvd();

	/* return physical address of the wakeup code */
	return ACPI_WAKE_ADDR;
}

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
		cpu_IA32e_enable(current_cpu_datap());

		mode = hibernate_write_image();

		if( mode == kIOHibernatePostWriteHalt )
		{
			// off
			HIBLOG("power off\n");
			if (PE_halt_restart) (*PE_halt_restart)(kPEHaltCPU);
		}
		else if( mode == kIOHibernatePostWriteRestart )
		{
			// restart
			HIBLOG("restart\n");
			if (PE_halt_restart) (*PE_halt_restart)(kPERestartCPU);
		}
		else
		{
			// sleep
			HIBLOG("sleep\n");
	
			// should we come back via regular wake, set the state in memory.
			cpu_datap(0)->cpu_hibernate = 0;			
		}

		/*
		 * If we're in 64-bit mode, drop back into legacy mode during sleep.
		 */
		cpu_IA32e_disable(current_cpu_datap());

	}

	(data->func)(data->refcon);

	/* should never get here! */
}
#endif

static uint64_t		acpi_sleep_abstime;

void
acpi_sleep_kernel(acpi_sleep_callback func, void *refcon)
{
#if HIBERNATION
	acpi_hibernate_callback_data_t data;
	boolean_t did_hibernate;
#endif
	unsigned int	cpu;
	kern_return_t	rc;
	unsigned int	my_cpu;

	kprintf("acpi_sleep_kernel hib=%d\n",
			current_cpu_datap()->cpu_hibernate);

	/* Geta ll CPUs to be in the "off" state */
	my_cpu = cpu_number();
	for (cpu = 0; cpu < real_ncpus; cpu += 1) {
	    	if (cpu == my_cpu)
			continue;
		rc = pmCPUExitHaltToOff(cpu);
		if (rc != KERN_SUCCESS)
		    panic("Error %d trying to transition CPU %d to OFF",
			  rc, cpu);
	}

	/* shutdown local APIC before passing control to BIOS */
	lapic_shutdown();

#if HIBERNATION
	data.func = func;
	data.refcon = refcon;
#endif

	/* Save power management timer state */
	pmTimerSave();

	/* 
	 * Turn off VT, otherwise switching to legacy mode will fail
	 */
	vmx_suspend();

	/*
	 * If we're in 64-bit mode, drop back into legacy mode during sleep.
	 */
	cpu_IA32e_disable(current_cpu_datap());

	acpi_sleep_abstime = mach_absolute_time();

	/*
	 * Save master CPU state and sleep platform.
	 * Will not return until platform is woken up,
	 * or if sleep failed.
	 */
#if HIBERNATION
	acpi_sleep_cpu(acpi_hibernate, &data);
#else
	acpi_sleep_cpu(func, refcon);
#endif

	/* Reset UART if kprintf is enabled.
	 * However kprintf should not be used before rtc_sleep_wakeup()
	 * for compatibility with firewire kprintf.
	 */

	if (FALSE == disable_serial_output)
		serial_init();

#if HIBERNATION
	if (current_cpu_datap()->cpu_hibernate) {
		int i;
		for (i = 0; i < PMAP_NWINDOWS; i++)
			*current_cpu_datap()->cpu_pmap->mapwindow[i].prv_CMAP = 0;
		current_cpu_datap()->cpu_hibernate = 0;
		did_hibernate = TRUE;

	} else
#endif 
	{
		did_hibernate = FALSE;
	}

	/* Re-enable mode (including 64-bit if applicable) */
	cpu_mode_init(current_cpu_datap());

	/* Re-enable machine check handling */
	mca_cpu_init();

	/* restore MTRR settings */
	mtrr_update_cpu();

	/* 
	 * Restore VT mode
	 */
	vmx_resume();

	/* set up PAT following boot processor power up */
	pat_init();

	/*
	 * Go through all of the CPUs and mark them as requiring
	 * a full restart.
	 */
	pmMarkAllCPUsOff();

	/* let the realtime clock reset */
	rtc_sleep_wakeup(acpi_sleep_abstime);

	if (did_hibernate)
		hibernate_machine_init();

	/* re-enable and re-init local apic */
	if (lapic_probe())
		lapic_configure();

	/* Restore power management register state */
	pmCPUMarkRunning(current_cpu_datap());

	/* Restore power management timer state */
	pmTimerRestore();

	/* Restart tick interrupts from the LAPIC timer */
	rtc_lapic_start_ticking();

	fpinit();
	clear_fpu();

#if HIBERNATION
	if (did_hibernate)
		enable_preemption();

	kprintf("ret from acpi_sleep_cpu hib=%d\n", did_hibernate);
#endif
}
