/*
 * Copyright (c) 2003-2008 Apple Inc. All rights reserved.
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
/*
 * Machine independent per processor data.
 */

#include <mach/mach_types.h>

#include <kern/processor.h>
#include <kern/timer.h>
#include <kern/debug.h>

void
processor_data_init(
	processor_t             processor)
{
	(void)memset(&processor->processor_data, 0, sizeof(processor_data_t));

	timer_init(&PROCESSOR_DATA(processor, idle_state));
	timer_init(&PROCESSOR_DATA(processor, system_state));
	timer_init(&PROCESSOR_DATA(processor, user_state));

	PROCESSOR_DATA(processor, debugger_state).db_current_op = DBOP_NONE;
}

boolean_t
processor_in_panic_context(
	processor_t             processor)
{
	return PROCESSOR_DATA(processor, debugger_state).db_entry_count > 0;
}
