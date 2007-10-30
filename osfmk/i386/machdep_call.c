/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1992 NeXT Computer, Inc.
 *
 * Machine dependent kernel calls.
 *
 * HISTORY
 *
 * 17 June 1992 ? at NeXT
 *	Created.
 */
 
#include <mach/mach_types.h>

#include <i386/machdep_call.h>

extern kern_return_t	kern_invalid(void);

machdep_call_t		machdep_call_table[] = {
	MACHDEP_CALL_ROUTINE(thread_get_cthread_self,0),
	MACHDEP_CALL_ROUTINE(thread_set_cthread_self,1),
	MACHDEP_CALL_ROUTINE(kern_invalid,0),
	MACHDEP_CALL_ROUTINE(thread_fast_set_cthread_self,1),
	MACHDEP_CALL_ROUTINE(thread_set_user_ldt,3),
	MACHDEP_BSD_CALL_ROUTINE(i386_set_ldt,3),
	MACHDEP_BSD_CALL_ROUTINE(i386_get_ldt,3),
};
machdep_call_t		machdep_call_table64[] = {
	MACHDEP_CALL_ROUTINE(kern_invalid,0),
	MACHDEP_CALL_ROUTINE(kern_invalid,0),
	MACHDEP_CALL_ROUTINE(kern_invalid,0),
	MACHDEP_CALL_ROUTINE64(thread_fast_set_cthread_self64,1),
	MACHDEP_CALL_ROUTINE(kern_invalid,0),
	MACHDEP_CALL_ROUTINE(kern_invalid,0),
	MACHDEP_CALL_ROUTINE(kern_invalid,0),
};

int	machdep_call_count =
    (sizeof (machdep_call_table) / sizeof (machdep_call_t));

