/*
 * Copyright (c) 2019 Apple Computer, Inc. All rights reserved.
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

#ifndef _MACH_EVENTLINK_TYPES_H_
#define _MACH_EVENTLINK_TYPES_H_

#include <mach/std_types.h>
#include <mach/port.h>

__options_decl(kern_clock_id_t, uint32_t, {
	KERN_CLOCK_MACH_ABSOLUTE_TIME = 1,
});

__options_decl(mach_eventlink_create_option_t, uint32_t, {
	MELC_OPTION_NONE         = 0,
	MELC_OPTION_NO_COPYIN    = 0x1,
	MELC_OPTION_WITH_COPYIN  = 0x2,
});

__options_decl(mach_eventlink_associate_option_t, uint32_t, {
	MELA_OPTION_NONE              = 0,
	MELA_OPTION_ASSOCIATE_ON_WAIT = 0x1,
});

__options_decl(mach_eventlink_disassociate_option_t, uint32_t, {
	MELD_OPTION_NONE = 0,
});

__options_decl(mach_eventlink_signal_wait_option_t, uint32_t, {
	MELSW_OPTION_NONE    = 0,
	MELSW_OPTION_NO_WAIT = 0x1,
});

#define EVENTLINK_SIGNAL_COUNT_MASK 0xffffffffffffff
#define EVENTLINK_SIGNAL_ERROR_MASK 0xff
#define EVENTLINK_SIGNAL_ERROR_SHIFT 56

#define encode_eventlink_count_and_error(count, error) \
	(((count) & EVENTLINK_SIGNAL_COUNT_MASK) | ((((uint64_t)error) & EVENTLINK_SIGNAL_ERROR_MASK) << EVENTLINK_SIGNAL_ERROR_SHIFT))

#define decode_eventlink_count_from_retval(retval) \
	((retval) & EVENTLINK_SIGNAL_COUNT_MASK)

#define decode_eventlink_error_from_retval(retval) \
	((kern_return_t)(((retval) >> EVENTLINK_SIGNAL_ERROR_SHIFT) & EVENTLINK_SIGNAL_ERROR_MASK))

#ifndef KERNEL
kern_return_t
mach_eventlink_signal(
	mach_port_t         eventlink_port,
	uint64_t            signal_count);

kern_return_t
mach_eventlink_wait_until(
	mach_port_t                          eventlink_port,
	uint64_t                             *count_ptr,
	mach_eventlink_signal_wait_option_t  option,
	kern_clock_id_t                      clock_id,
	uint64_t                             deadline);

kern_return_t
mach_eventlink_signal_wait_until(
	mach_port_t                          eventlink_port,
	uint64_t                             *count_ptr,
	uint64_t                             signal_count,
	mach_eventlink_signal_wait_option_t  option,
	kern_clock_id_t                      clock_id,
	uint64_t                             deadline);

#endif

#endif  /* _MACH_EVENTLINK_TYPES_H_ */
