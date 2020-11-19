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
#include <machine/atomic.h>
#include <mach/mach_time.h>
#include <mach/clock_types.h>
#include <kern/clock.h>
#include <kern/locks.h>
#include <arm64/machine_remote_time.h>
#include <sys/kdebug.h>
#include <arm/machine_routines.h>
#include <kern/remote_time.h>

_Atomic uint32_t bt_init_flag = 0;

extern void mach_bridge_add_timestamp(uint64_t remote_timestamp, uint64_t local_timestamp);
extern void bt_calibration_thread_start(void);
extern void bt_params_add(struct bt_params *params);

void
mach_bridge_init_timestamp(void)
{
	/* This function should be called only once by the driver
	 *  implementing the interrupt handler for receiving timestamps */
	if (os_atomic_load(&bt_init_flag, relaxed)) {
		return;
	}

	os_atomic_store(&bt_init_flag, 1, release);

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
	if (!os_atomic_load(&bt_init_flag, acquire)) {
		panic("%s called before mach_bridge_init_timestamp", __func__);
		return;
	}

	KDBG(MACHDBG_CODE(DBG_MACH_CLOCK, MACH_BRIDGE_RCV_TS), localTimestamp, remoteTimestamp);

	lck_spin_lock(&bt_spin_lock);
	mach_bridge_add_timestamp(remoteTimestamp, localTimestamp);
	lck_spin_unlock(&bt_spin_lock);

	return;
}

/*
 * This function is used to set parameters, calculated externally,
 * needed for mach_bridge_remote_time.
 */
void
mach_bridge_set_params(uint64_t local_timestamp, uint64_t remote_timestamp, double rate)
{
	/* Ensure the locks have been initialized */
	if (!os_atomic_load(&bt_init_flag, acquire)) {
		panic("%s called before mach_bridge_init_timestamp", __func__);
		return;
	}

	struct bt_params params = {};
	params.base_local_ts = local_timestamp;
	params.base_remote_ts = remote_timestamp;
	params.rate = rate;
	lck_spin_lock(&bt_ts_conversion_lock);
	bt_params_add(&params);
	lck_spin_unlock(&bt_ts_conversion_lock);
	KDBG(MACHDBG_CODE(DBG_MACH_CLOCK, MACH_BRIDGE_TS_PARAMS), params.base_local_ts,
	    params.base_remote_ts, *(uint64_t *)((void *)&params.rate));
}
