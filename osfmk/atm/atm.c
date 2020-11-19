/*
 * Copyright (c) 2012-2013 Apple Inc. All rights reserved.
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

#include <atm/atm_internal.h>
#include <machine/commpage.h>
#include <pexpert/pexpert.h>

/*
 * Global that is set by diagnosticd and readable by userspace
 * via the commpage.
 */
static uint32_t atm_diagnostic_config;
static bool disable_atm;

/*
 * Routine: atm_init
 * Purpose: Initialize the atm subsystem.
 * Returns: None.
 */
void
atm_init(void)
{
	char temp_buf[20];

	/* Disable atm if disable_atm present in device-tree properties or in boot-args */
	if ((PE_get_default("kern.disable_atm", temp_buf, sizeof(temp_buf))) ||
	    (PE_parse_boot_argn("-disable_atm", temp_buf, sizeof(temp_buf)))) {
		disable_atm = true;
	}

	if (!PE_parse_boot_argn("atm_diagnostic_config", &atm_diagnostic_config, sizeof(atm_diagnostic_config))) {
		if (!PE_get_default("kern.atm_diagnostic_config", &atm_diagnostic_config, sizeof(atm_diagnostic_config))) {
			atm_diagnostic_config = 0;
		}
	}

	kprintf("ATM subsystem is initialized\n");
}

/*
 * Routine: atm_reset
 * Purpose: re-initialize the atm subsystem (e.g. for userspace reboot)
 * Returns: None.
 */
void
atm_reset(void)
{
	atm_init();
	commpage_update_atm_diagnostic_config(atm_diagnostic_config);
}

/*
 * Routine: atm_set_diagnostic_config
 * Purpose: Set global atm_diagnostic_config and update the commpage to reflect
 *          the new value.
 * Returns: Error if ATM is disabled.
 */
kern_return_t
atm_set_diagnostic_config(uint32_t diagnostic_config)
{
	if (disable_atm) {
		return KERN_NOT_SUPPORTED;
	}

	atm_diagnostic_config = diagnostic_config;
	commpage_update_atm_diagnostic_config(atm_diagnostic_config);

	return KERN_SUCCESS;
}

/*
 * Routine: atm_get_diagnostic_config
 * Purpose: Get global atm_diagnostic_config.
 * Returns: Diagnostic value
 */
uint32_t
atm_get_diagnostic_config(void)
{
	return atm_diagnostic_config;
}
