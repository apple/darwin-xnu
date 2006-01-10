/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * Machine independent per processor data.
 *
 * HISTORY
 *
 * 16 October 2003 (debo)
 *	Created.
 */

#include <mach/mach_types.h>

#include <kern/processor.h>

void
processor_data_init(
	processor_t		processor)
{
	(void)memset(&processor->processor_data, 0, sizeof (processor_data_t));

	queue_init(&PROCESSOR_DATA(processor, timer_call_queue));
#if	!STAT_TIME
	timer_init(&PROCESSOR_DATA(processor, offline_timer));
#endif	/* STAT_TIME */
}
