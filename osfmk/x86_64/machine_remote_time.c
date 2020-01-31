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
#include <x86_64/machine_remote_time.h>
#include <stdatomic.h>
#include <kern/locks.h>
#include <kern/clock.h>

void mach_bridge_send_timestamp(uint64_t timestamp);

extern _Atomic uint32_t bt_init_flag;
extern lck_spin_t *bt_maintenance_lock;
extern void mach_bridge_timer_init(void);
extern uint32_t bt_enable_flag;

/*
 * Delay sending timestamps by certain interval to
 * avoid overwriting sentinel values
 */
#define DELAY_INTERVAL_NS (50 * NSEC_PER_MSEC)
static uint64_t bt_delay_timestamp = 0;
static mach_bridge_regwrite_timestamp_func_t bridge_regwrite_timestamp_callback = NULL;

/*
 * This function should only be called by the kext
 * responsible for sending timestamps across the link
 */
void
mach_bridge_register_regwrite_timestamp_callback(mach_bridge_regwrite_timestamp_func_t func)
{
	static uint64_t delay_amount = 0;

	if (!atomic_load(&bt_init_flag)) {
		mach_bridge_timer_init();
		nanoseconds_to_absolutetime(DELAY_INTERVAL_NS, &delay_amount);
		bt_init_flag = 1;
	}

	lck_spin_lock(bt_maintenance_lock);
	bridge_regwrite_timestamp_callback = func;
	bt_enable_flag = (func != NULL) ? 1 : 0;
	bt_delay_timestamp = mach_absolute_time() + delay_amount;
	lck_spin_unlock(bt_maintenance_lock);
}

void
mach_bridge_send_timestamp(uint64_t timestamp)
{
	LCK_SPIN_ASSERT(bt_maintenance_lock, LCK_ASSERT_OWNED);

	if (bt_delay_timestamp > 0) {
		uint64_t now = mach_absolute_time();
		if (now < bt_delay_timestamp) {
			return;
		}
		bt_delay_timestamp = 0;
	}

	if (bridge_regwrite_timestamp_callback) {
		bridge_regwrite_timestamp_callback(timestamp);
	}
}
