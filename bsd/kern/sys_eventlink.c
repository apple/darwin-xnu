/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
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

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/kernel_types.h>
#include <sys/sysproto.h>
#include <mach/mach_types.h>
#include <mach/mach_eventlink_types.h>

extern uint64_t
mach_eventlink_signal_trap(
	mach_port_name_t port,
	uint64_t         signal_count __unused);

extern uint64_t
mach_eventlink_wait_until_trap(
	mach_port_name_t                    eventlink_port,
	uint64_t                            wait_count,
	mach_eventlink_signal_wait_option_t option,
	kern_clock_id_t                     clock_id,
	uint64_t                            deadline);

extern uint64_t
mach_eventlink_signal_wait_until_trap(
	mach_port_name_t                    eventlink_port,
	uint64_t                            wait_count,
	uint64_t                            signal_count __unused,
	mach_eventlink_signal_wait_option_t option,
	kern_clock_id_t                     clock_id,
	uint64_t                            deadline);

int
mach_eventlink_signal(
	__unused proc_t p,
	struct mach_eventlink_signal_args *uap,
	uint64_t *retval)
{
	*retval = mach_eventlink_signal_trap(uap->eventlink_port, uap->signal_count);
	return 0;
}

int
mach_eventlink_wait_until(
	__unused proc_t p,
	struct mach_eventlink_wait_until_args *uap,
	uint64_t *retval)
{
	*retval = mach_eventlink_wait_until_trap(uap->eventlink_port, uap->wait_count,
	    uap->option, uap->clock_id, uap->deadline);
	return 0;
}

int
mach_eventlink_signal_wait_until(
	__unused proc_t p,
	struct mach_eventlink_signal_wait_until_args *uap,
	uint64_t *retval)
{
	*retval = mach_eventlink_signal_wait_until_trap(uap->eventlink_port, uap->wait_count,
	    uap->signal_count, uap->option, uap->clock_id, uap->deadline);
	return 0;
}
