/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 *	Copyright (C) 1992, NeXT, Inc.
 *
 *	File:	kern/mach_loader.h
 *
 *	Mach object file loader API.
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
    			customstack	:1,
					:0;
} load_result_t;

load_return_t load_machfile(
	struct vnode		*vp,
	struct mach_header	*header,
	unsigned long		file_offset,
	unsigned long		macho_size,
	load_result_t		*result,
	thread_act_t		thr_act,
	vm_map_t			map);

#define LOAD_SUCCESS		0
#define LOAD_BADARCH		1	/* CPU type/subtype not found */
#define LOAD_BADMACHO		2	/* malformed mach-o file */
#define LOAD_SHLIB		3	/* shlib version mismatch */
#define LOAD_FAILURE		4	/* Miscellaneous error */
#define LOAD_NOSPACE		5	/* No VM available */
#define LOAD_PROTECT		6	/* protection violation */
#define LOAD_RESOURCE		7	/* resource allocation failure */

#endif	/* _BSD_KERN_MACH_LOADER_H_ */
