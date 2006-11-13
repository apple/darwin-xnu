/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 *	Copyright (C) 1992, NeXT, Inc.
 *
 *	File:	kern/mach_loader.h
 *
 *	Mach object file loader API.
 *
 * NOTE:	This header is only used by the kld code for loading 32 bit
 *		kernel modules into a 32 bit mach_kernel.
 *
 * HISTORY
 *  24-Aug-92	Doug Mitchell at NeXT
 *	Created.
 */
 
#ifndef	_BSD_KERN_MACH_LOADER_H_
#define _BSD_KERN_MACH_LOADER_H_

#include <mach/mach_types.h>
 
#include <mach-o/loader.h>

typedef int load_return_t;

typedef struct _load_result {
    vm_offset_t		mach_header;
    vm_offset_t		entry_point;
    vm_offset_t		user_stack;
    int			thread_count;
    unsigned int
    /* boolean_t */	unixproc	:1,
    			dynlinker	:1,
					:0;
} load_result_t;


#define LOAD_SUCCESS		0
#define LOAD_BADARCH		1	/* CPU type/subtype not found */
#define LOAD_BADMACHO		2	/* malformed mach-o file */
#define LOAD_SHLIB		3	/* shlib version mismatch */
#define LOAD_FAILURE		4	/* Miscellaneous error */
#define LOAD_NOSPACE		5	/* No VM available */
#define LOAD_PROTECT		6	/* protection violation */
#define LOAD_RESOURCE		7	/* resource allocation failure */

#endif	/* _BSD_KERN_MACH_LOADER_H_ */
