/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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

/*
 * Structure describing the result from calling load_machfile(), if that
 * function returns LOAD_SUCCESS.
 */
typedef struct _load_result {
	user_addr_t		mach_header;
	user_addr_t		entry_point;
	user_addr_t		user_stack;
	mach_vm_size_t		user_stack_size;
	mach_vm_address_t	all_image_info_addr;
	mach_vm_size_t		all_image_info_size;
	int			thread_count;
	unsigned int
		/* boolean_t */	unixproc	:1,
				needs_dynlinker : 1,
				dynlinker	:1,
				prog_allocated_stack	:1,
				prog_stack_size : 1,    
				validentry	:1,
						:0;
	unsigned int		csflags;
	unsigned char	uuid[16];	
	mach_vm_address_t	min_vm_addr;
	mach_vm_address_t	max_vm_addr;
	unsigned int		platform_binary;
} load_result_t;

struct image_params;
load_return_t load_machfile(
	struct image_params	*imgp,
	struct mach_header	*header,
	thread_t		thread,
	vm_map_t		map,
	load_result_t		*result);

#define LOAD_SUCCESS		0
#define LOAD_BADARCH		1	/* CPU type/subtype not found */
#define LOAD_BADMACHO		2	/* malformed mach-o file */
#define LOAD_SHLIB		3	/* shlib version mismatch */
#define LOAD_FAILURE		4	/* Miscellaneous error */
#define LOAD_NOSPACE		5	/* No VM available */
#define LOAD_PROTECT		6	/* protection violation */
#define LOAD_RESOURCE		7	/* resource allocation failure */
#define	LOAD_ENOENT		8	/* resource not found */
#define	LOAD_IOERROR		9	/* IO error */
#define	LOAD_DECRYPTFAIL	10	/* FP decrypt failure */

#endif	/* _BSD_KERN_MACH_LOADER_H_ */
