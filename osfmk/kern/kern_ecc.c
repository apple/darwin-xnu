/*
* Copyright (c) 2013 Apple Inc. All rights reserved.
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
#include <mach/mach_types.h>
#include <mach/host_info.h>
#include <kern/locks.h>
#include <kern/ecc.h>
#include <kern/spl.h>
#include <pexpert/pexpert.h>
#include <libkern/OSAtomic.h>

/*
 * ECC data.  Not really KPCs, but this still seems like the
 * best home for this code.
 *
 * Circular buffer of events.  When we fill up, drop data.
 */
#define ECC_EVENT_BUFFER_COUNT	5
struct ecc_event		ecc_data[ECC_EVENT_BUFFER_COUNT];
static uint32_t			ecc_data_next_read; 
static uint32_t			ecc_data_next_write; 
static boolean_t		ecc_data_empty = TRUE; // next read == next write : empty or full?
static boolean_t		ecc_prefer_panic = TRUE; 
static lck_grp_t		*ecc_data_lock_group;
static lck_spin_t		ecc_data_lock;
static uint32_t			ecc_correction_count;

void
ecc_log_init()
{
	ecc_prefer_panic = !PE_reboot_on_panic();
	ecc_data_lock_group = lck_grp_alloc_init("ecc-data", NULL);
	lck_spin_init(&ecc_data_lock, ecc_data_lock_group, NULL);
	OSMemoryBarrier();
}

boolean_t 
ecc_log_prefer_panic(void)
{
	OSMemoryBarrier();
	return ecc_prefer_panic;
}

uint32_t
ecc_log_get_correction_count()
{
	return ecc_correction_count;
}

kern_return_t
ecc_log_record_event(const struct ecc_event *ev)
{
	spl_t x;

	if (ev->count > ECC_EVENT_INFO_DATA_ENTRIES) {
		panic("Count of %u on ecc event is too large.", (unsigned)ev->count);
	}

	x = splhigh();
	lck_spin_lock(&ecc_data_lock);

	ecc_correction_count++;

	if (ecc_data_next_read == ecc_data_next_write && !ecc_data_empty)  {
		lck_spin_unlock(&ecc_data_lock);
		splx(x);
		return KERN_FAILURE;
	}

	bcopy(ev, &ecc_data[ecc_data_next_write], sizeof(*ev));
	ecc_data_next_write++;
	ecc_data_next_write %= ECC_EVENT_BUFFER_COUNT;
	ecc_data_empty = FALSE;

	lck_spin_unlock(&ecc_data_lock);
	splx(x);

	return KERN_SUCCESS;
}


kern_return_t
ecc_log_get_next_event(struct ecc_event *ev)
{
	spl_t x;

	x = splhigh();
	lck_spin_lock(&ecc_data_lock);

	if (ecc_data_empty)  {
		assert(ecc_data_next_write == ecc_data_next_read);

		lck_spin_unlock(&ecc_data_lock);
		splx(x);
		return KERN_FAILURE;
	}

	bcopy(&ecc_data[ecc_data_next_read], ev, sizeof(*ev));
	ecc_data_next_read++;
	ecc_data_next_read %= ECC_EVENT_BUFFER_COUNT;

	if (ecc_data_next_read == ecc_data_next_write) {
		ecc_data_empty = TRUE;
	}

	lck_spin_unlock(&ecc_data_lock);
	splx(x);

	return KERN_SUCCESS;
}
