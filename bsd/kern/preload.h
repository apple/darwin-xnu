/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
#ifndef	_BSD_KERN_PRELOAD_H_
#define _BSD_KERN_PRELOAD_H_

#if KERNEL_PRIVATE

#if PRELOAD

#define PRELOAD_MAGIC 0x1395
#define LC_PRELOAD 0x20

struct preload_command{
	unsigned long 	preload_cmd;	/* LC_PRELOAD */
	unsigned long 	preload_cmdsize;/* includes entries */
	short 		preload_magic;	/* Magic number */
	short 		preload_rev;	/* Rev of preload header */
	int 		preload_hdr_size;/* Size of preload header */
	int		preload_entries;/* Number of preload entries */
};

struct preload_entry{
	vm_offset_t preload_vaddr;	/* Address of page */
	vm_size_t preload_size;		/* size */
};
#endif

#endif


#endif	/* _BSD_KERN_PRELOAD_H_ */
