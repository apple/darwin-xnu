/*
 * Copyright (c) 2003-2004 Apple Computer, Inc. All rights reserved.
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

#ifndef	LIBKERN_OSMALLOC_h
#define LIBKERN_OSMALLOC_h

#include <sys/cdefs.h>

__BEGIN_DECLS

#include <stdint.h>
#ifdef  MACH_KERNEL_PRIVATE     
#include <kern/queue.h>  
#endif

#ifdef	MACH_KERNEL_PRIVATE

#define OSMT_MAX_NAME	64

typedef	struct	_OSMallocTag_ {
	queue_chain_t	OSMT_link;
	uint32_t		OSMT_refcnt;
	uint32_t		OSMT_state;
	uint32_t		OSMT_attr;
	char			OSMT_name[OSMT_MAX_NAME];
} *OSMallocTag;

#define	OSMT_VALID_MASK		0xFFFF0000
#define	OSMT_VALID		0xDEAB0000
#define	OSMT_RELEASED		0x00000001

#define	OSMT_ATTR_PAGEABLE	0x01
#else
typedef struct __OSMallocTag__	*OSMallocTag, *OSMallocTag_t;
#endif

#define	 OSMT_DEFAULT	0x00
#define	 OSMT_PAGEABLE	0x01

extern OSMallocTag		OSMalloc_Tagalloc(const char * str, uint32_t flags);

extern void				OSMalloc_Tagfree(OSMallocTag tag);

extern void *			OSMalloc(uint32_t size, OSMallocTag tag);

extern void *			OSMalloc_nowait(uint32_t size, OSMallocTag tag);

extern void *			OSMalloc_noblock(uint32_t size, OSMallocTag tag);

extern void				OSFree(void * addr, uint32_t size, OSMallocTag tag); 

__END_DECLS

#endif	/* LIBKERN_OSMALLOC_h */
