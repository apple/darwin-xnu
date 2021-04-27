/* * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#include <kern/assert.h>
#include <kern/cpu_data.h>
#include <kern/counter.h>
#include <kern/zalloc.h>
#include <machine/atomic.h>
#include <machine/machine_routines.h>
#include <machine/cpu_number.h>

OS_OVERLOADABLE
void
counter_add(scalable_counter_t *counter, uint64_t amount)
{
	os_atomic_add(zpercpu_get(*counter), amount, relaxed);
}

OS_OVERLOADABLE
void
counter_inc(scalable_counter_t *counter)
{
	os_atomic_inc(zpercpu_get(*counter), relaxed);
}

OS_OVERLOADABLE
void
counter_dec(scalable_counter_t *counter)
{
	os_atomic_dec(zpercpu_get(*counter), relaxed);
}

/*
 * NB: On arm, the preemption disabled implementation is the same as
 * the normal implementation. Otherwise we would need to enforce that
 * callers never mix the interfaces for the same counter.
 */
OS_OVERLOADABLE
void
counter_add_preemption_disabled(scalable_counter_t *counter, uint64_t amount)
{
	counter_add(counter, amount);
}

OS_OVERLOADABLE
void
counter_inc_preemption_disabled(scalable_counter_t *counter)
{
	counter_inc(counter);
}

OS_OVERLOADABLE
void
counter_dec_preemption_disabled(scalable_counter_t *counter)
{
	counter_dec(counter);
}
