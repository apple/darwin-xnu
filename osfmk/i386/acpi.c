/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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

#include <i386/misc_protos.h>
#include <i386/proc_reg.h>
#include <i386/pmap.h>
#include <i386/mtrr.h>
#include <i386/acpi.h>
#include <i386/mp.h>

#include <kern/cpu_data.h>

#include <IOKit/IOHibernatePrivate.h>
#include <IOKit/IOPlatformExpert.h>

extern void	acpi_sleep_cpu(acpi_sleep_callback, void * refcon);
extern char acpi_wake_start[];
extern char	acpi_wake_end[];

extern int	serial_init(void);
extern unsigned int disableSerialOuput;

extern void        set_kbd_leds(int leds);

vm_offset_t
acpi_install_wake_handler(void)
{
	/* copy wake code to ACPI_WAKE_ADDR in low memory */
	bcopy_phys((addr64_t) kvtophys((vm_offset_t)acpi_wake_start),
		   (addr64_t) ACPI_WAKE_ADDR,
		   acpi_wake_end - acpi_wake_start);

	/* flush cache */
	wbinvd();

	/* return physical address of the wakeup code */
	return ACPI_WAKE_ADDR;
}

typedef struct acpi_hibernate_callback_data {
    acpi_sleep_callback func;
    void *refcon;
} acpi_hibernate_callback_data;

static void
acpi_hibernate(void *refcon)
{
    boolean_t hib;

    acpi_hibernate_callback_data *data = (acpi_hibernate_callback_data *)refcon;

    if (current_cpu_datap()->cpu_hibernate) {
        hib = hibernate_write_image();
    }

    (data->func)(data->refcon);

    /* should never get here! */
}

void
acpi_sleep_kernel(acpi_sleep_callback func, void *refcon)
{
    acpi_hibernate_callback_data data;
    boolean_t did_hibernate;

	/* shutdown local APIC before passing control to BIOS */
	lapic_shutdown();

    data.func = func;
    data.refcon = refcon;

	/*
	 * Save master CPU state and sleep platform.
	 * Will not return until platform is woken up,
	 * or if sleep failed.
	 */
    acpi_sleep_cpu(acpi_hibernate, &data);

	/* reset UART if kprintf is enabled */
	if (FALSE == disableSerialOuput)
		serial_init();

    if (current_cpu_datap()->cpu_hibernate) {
        * (int *) CM1 = 0;
        * (int *) CM2 = 0;
        * (int *) CM3 = 0;

        current_cpu_datap()->cpu_hibernate = 0;

        did_hibernate = TRUE;
    } else {
        did_hibernate = FALSE;
    }

	/* restore MTRR settings */
	mtrr_update_cpu();

	/* set up PAT following boot processor power up */
	pat_init();

    if (did_hibernate) {
        hibernate_machine_init();
    }
        
	/* re-enable and re-init local apic */
	if (lapic_probe())
		lapic_init();

	/* let the realtime clock reset */
	rtc_sleep_wakeup();

    if (did_hibernate) {
        enable_preemption();
    }
}
