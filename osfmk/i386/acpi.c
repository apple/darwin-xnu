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

#include <i386/misc_protos.h>
#include <i386/proc_reg.h>
#include <i386/pmap.h>
#include <i386/mtrr.h>
#include <i386/acpi.h>
#include <i386/mp.h>

#include <kern/cpu_data.h>
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

typedef struct acpi_sleep_callback_data {
    acpi_sleep_callback func;
    void *refcon;
} acpi_sleep_callback_data;

static void
acpi_sleep_do_callback(void *refcon)
{
    acpi_sleep_callback_data *data = (acpi_sleep_callback_data *)refcon;


    (data->func)(data->refcon);

    /* should never get here! */
}

void
acpi_sleep_kernel(acpi_sleep_callback func, void *refcon)
{
    acpi_sleep_callback_data data;

	/* shutdown local APIC before passing control to BIOS */
	lapic_shutdown();

    data.func = func;
    data.refcon = refcon;

	/*
	 * Save master CPU state and sleep platform.
	 * Will not return until platform is woken up,
	 * or if sleep failed.
	 */
    acpi_sleep_cpu(acpi_sleep_do_callback, &data);

	/* reset UART if kprintf is enabled */
	if (FALSE == disableSerialOuput)
		serial_init();


	/* restore MTRR settings */
	mtrr_update_cpu();

	/* set up PAT following boot processor power up */
	pat_init();

	/* re-enable and re-init local apic */
	if (lapic_probe())
		lapic_init();

	/* let the realtime clock reset */
	rtc_sleep_wakeup();

}
