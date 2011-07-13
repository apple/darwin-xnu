/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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
 * Memory allocation wrappers.
 */

#ifndef _SECURITY_MAC_ALLOC_H_
#define	_SECURITY_MAC_ALLOC_H_

#include <mach/machine/vm_types.h>
#include <kern/kern_types.h>
#include <sys/appleapiopts.h>

/* JMM - should use OSMlloc.h interfaces */

#ifdef __APPLE_API_EVOLVING
/*
 * Kernel Memory allocator
 */
void *	mac_kalloc	(vm_size_t size, int how);
void	mac_kfree	(void *data, vm_size_t size);

/*
 * Mbuf allocator for mbuf labels.
 */
void *	mac_mbuf_alloc	(int len, int wait);
void	mac_mbuf_free	(void *data);

/*
 * 
 */
int	mac_wire	(void *start, void *end);
int	mac_unwire	(void *start, void *end);

/*
 * Zone allocator
 */
zone_t	mac_zinit	(vm_size_t size, vm_size_t maxmem,
			 vm_size_t alloc, const char *name);
void	mac_zone_change	(zone_t zone, unsigned int item, boolean_t value);
void *	mac_zalloc	(zone_t zone, int how);
void	mac_zfree	(zone_t zone, void *elem);

/* Item definitions */
#define Z_EXHAUST       1       /* Make zone exhaustible        */
#define Z_COLLECT       2       /* Make zone collectable        */
#define Z_EXPAND        3       /* Make zone expandable         */
#define Z_FOREIGN       4       /* Allow collectable zone to contain foreign elements */
#define Z_CALLERACCT	5	/* Account alloc/free against the caller */

#endif  /* __APPLE_API_EVOLVING */
#endif	/* _SECURITY_MAC_ALLOC_H_ */
