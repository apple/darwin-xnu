/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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
#include <kern/misc_protos.h>
#include <stdatomic.h>
#include <mach/mach_time.h>
#include <mach/clock_types.h>
#include <kern/clock.h>
#include <kern/locks.h>
#include <arm64/machine_remote_time.h>
#include <sys/kdebug.h>
#include <arm/machine_routines.h>

lck_spin_t *bt_spin_lock = NULL;
_Atomic uint32_t bt_init_flag = 0;

extern lck_spin_t *ts_conversion_lock;
extern void mach_bridge_add_timestamp(uint64_t remote_timestamp, uint64_t local_timestamp);
extern void bt_calibration_thread_start(void);

void
mach_bridge_init_timestamp(void)
{
	/* This function should be called only once by the driver
	 *  implementing the interrupt handler for receiving timestamps */
	if (bt_init_flag) {
		assert(!bt_init_flag);
		return;
	}

	/* Initialize the locks */
	static lck_grp_t *bt_lck_grp = NULL;

	bt_lck_grp = lck_grp_alloc_init("bridgetimestamp", LCK_GRP_ATTR_NULL);
	bt_spin_lock = lck_spin_alloc_init(bt_lck_grp, NULL);
	ts_conversion_lock = lck_spin_alloc_init(bt_lck_grp, NULL);

	atomic_store(&bt_init_flag, 1);

	/* Start the kernel thread only after all the locks have been initialized */
	bt_calibration_thread_start();
}

/*
 * Conditions: Should be called from primary interrupt context
 */
void
mach_bridge_recv_timestamps(uint64_t remoteTimestamp, uint64_t localTimestamp)
{
	assert(ml_at_interrupt_context() == TRUE);

	/* Ensure the locks have been initialized */
	if (!bt_init_flag) {
		assert(bt_init_flag != 0);
		return;
	}

	KDBG(MACHDBG_CODE(DBG_MACH_CLOCK, MACH_BRIDGE_RCV_TS), localTimestamp, remoteTimestamp);

	lck_spin_lock(bt_spin_lock);
	mach_bridge_add_timestamp(remoteTimestamp, localTimestamp);
	lck_spin_unlock(bt_spin_lock);

	return;
}
