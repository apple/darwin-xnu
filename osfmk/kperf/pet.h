/*
 * Copyright (c) 2011-2018 Apple Computer, Inc. All rights reserved.
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

#include <kern/thread.h>
#include <stdbool.h>

#define KPERF_PET_DEFAULT_IDLE_RATE 15

extern bool kppet_lightweight_active;
extern _Atomic uint32_t kppet_gencount;

/*
 * If `actionid` is non-zero, set up PET to sample the action.  Otherwise,
 * disable PET.
 */
void kppet_config(unsigned int actionid);

/*
 * Reset PET back to its default settings.
 */
void kppet_reset(void);

/*
 * Notify PET that new threads are switching on-CPU.
 */
void kppet_on_cpu(thread_t thread, thread_continue_t continuation,
    uintptr_t *starting_frame);

/*
 * Wake the PET thread from its timer handler.
 */
void kppet_wake_thread(void);

/*
 * For configuring PET from the sysctl interface.
 */
int kppet_get_idle_rate(void);
int kppet_set_idle_rate(int new_idle_rate);
int kppet_get_lightweight_pet(void);
int kppet_set_lightweight_pet(int on);

/*
 * Update whether lightweight PET is active when turning sampling on and off.
 */
void kppet_lightweight_active_update(void);
