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
 *
 */

#include <kern/kalloc.h>
#include <kern/zalloc.h>

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/systm.h>
#include <sys/mbuf.h>

#include <vm/vm_map.h>

#include "mac_alloc.h"

/*
 * XXXMAC: We should probably make sure only registered policies can
 * call these, otherwise we're effectively changing Apple's plan wrt
 * exported allocators.
 */

/*
 * Kernel allocator
 */
void *
mac_kalloc(vm_size_t size, int how)
{

	if (how == M_WAITOK)
		return kalloc(size);
	else
		return kalloc_noblock(size);
}

/*
 * for temporary binary compatibility
 */
void *	mac_kalloc_noblock	(vm_size_t size);
void *
mac_kalloc_noblock(vm_size_t size)
{
	return kalloc_noblock(size);
}

void
mac_kfree(void * data, vm_size_t size)
{

	return kfree(data, size);
}

/*
 * MBuf tag allocator.
 */

void *
mac_mbuf_alloc(int len, int wait)
{
	struct m_tag *t;

	t = m_tag_alloc(KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_MAC_POLICY_LABEL,
			len, wait);
	if (t == NULL)
		return (NULL);

	return ((void *)(t + 1));
}

void
mac_mbuf_free(void *data)
{
	struct m_tag *t;

	t = (struct m_tag *)((char *)data - sizeof(struct m_tag));
	m_tag_free(t);
}

/*
 * VM functions
 */

extern vm_map_t kalloc_map;

int
mac_wire(void *start, void *end)
{

	return (vm_map_wire(kalloc_map, CAST_USER_ADDR_T(start),
		CAST_USER_ADDR_T(end), VM_PROT_READ|VM_PROT_WRITE, FALSE));
}

int
mac_unwire(void *start, void *end)
{

	return (vm_map_unwire(kalloc_map, CAST_USER_ADDR_T(start),
		CAST_USER_ADDR_T(end), FALSE));
}

/*
 * Zone allocator
 */
zone_t
mac_zinit(vm_size_t size, vm_size_t maxmem, vm_size_t alloc, const char *name)
{

	return zinit(size, maxmem, alloc, name);
}

void
mac_zone_change(zone_t zone, unsigned int item, boolean_t value)
{

	zone_change(zone, item, value);
}

void *
mac_zalloc(zone_t zone, int how)
{

	if (how == M_WAITOK)
		return zalloc(zone);
	else
		return zalloc_noblock(zone);
}

void
mac_zfree(zone_t zone, void *elem)
{

	zfree(zone, elem);
}
