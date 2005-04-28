/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */

/*
 *	This module maintains information about the presence of
 *	pages not in memory.  Since an external memory object
 *	must maintain a complete knowledge of its contents, this
 *	information takes the form of hints.
 */
#include <string.h>	/* for memcpy()/memset() */

#include <mach/boolean.h>
#include <vm/vm_external.h>
#include <kern/kalloc.h>
#include <mach/vm_param.h>
#include <kern/assert.h>

/*
 *	The implementation uses bit arrays to record whether
 *	a page has been written to external storage.  For
 *	convenience, these bit arrays come in various sizes.
 *	For example, a map N bytes long can record:
 *
 *	  16 bytes =   128 pages = (@ 4KB/page)    512KB
 *	1024 bytes =  8192 pages = (@ 4KB/page)  32MB
 *	4096 bytes = 32768 pages = (@ 4KB/page) 128MB
 *
 *	For a 32-bit machine with 4KB pages, the largest size
 *	would be 128KB = 32 pages. Machines with a larger page
 *	size are more efficient.
 *
 *	This subsystem must be very careful about memory allocation,
 *	since vm_external_create() is almost always called with
 *	vm_privilege set. The largest map to be allocated must be less
 *	than or equal to a single page, and the kalloc subsystem must
 *	never allocate more than a single page in response to a kalloc()
 *	request. Also, vm_external_destroy() must not take any blocking
 *	locks, since it is called with a vm_object lock held. This
 *	implies that kfree() MUST be implemented in terms of zfree()
 *	NOT kmem_free() for all request sizes that this subsystem uses.
 *
 *	For efficiency, this subsystem knows that the kalloc() subsystem
 *	is implemented in terms of power-of-2 allocation, and that the
 *	minimum allocation unit is KALLOC_MINSIZE
 * 
 *	XXXO
 *	Should consider using existence_map to hold bits directly
 *	when existence_size <= 4 bytes (i.e., 32 pages).
 */

#define	SMALL_SIZE	KALLOC_MINSIZE
#define	LARGE_SIZE	PAGE_SIZE

static vm_size_t power_of_2(vm_size_t size);

static vm_size_t
power_of_2(vm_size_t size)
{
	vm_size_t power;

	power = 2 * SMALL_SIZE;
	while (power < size) {
		power <<= 1;
	}
	return(power);
}

vm_external_map_t
vm_external_create(
	vm_offset_t	size)
{
	vm_size_t		bytes;
	vm_external_map_t	result = VM_EXTERNAL_NULL;

	bytes = stob(size);
	if (bytes <= SMALL_SIZE) {
		if ((result = (vm_external_map_t)kalloc(SMALL_SIZE)) != NULL) {
			memset(result, 0, SMALL_SIZE);
		}
	} else if (bytes <= LARGE_SIZE) {
		bytes = power_of_2(bytes);

		if ((result = (vm_external_map_t)kalloc(bytes)) != NULL) {
			memset(result, 0, bytes);
		}
	}
	return(result);
}

void
vm_external_destroy(
	vm_external_map_t	map,
	vm_size_t		size)
{
	vm_size_t bytes;

	if (map == VM_EXTERNAL_NULL)
		return;

	bytes = stob(size);
	if (bytes <= SMALL_SIZE) {
		bytes = SMALL_SIZE;
	} else {
		bytes = power_of_2(bytes);
	}
	kfree(map, bytes);
}

/*
 * Return the number of bytes needed for a vm_external_map given the
 * size of the object to be mapped, i.e. the size of the map that was
 * created by vm_external_create.
 */
vm_size_t
vm_external_map_size(
	vm_offset_t	size)
{
	vm_size_t	bytes;

	bytes = stob(size);
	if (bytes != 0) {
	        if (bytes <= SMALL_SIZE) {
			bytes = SMALL_SIZE;
		} else {
			bytes = power_of_2(bytes);
		}
	}
	return bytes;
}

void
vm_external_copy(
	vm_external_map_t	old_map,
	vm_size_t		old_size,
	vm_external_map_t	new_map)
{
	/*
	 * Cannot copy non-existent maps
	 */
	if ((old_map == VM_EXTERNAL_NULL) || (new_map == VM_EXTERNAL_NULL))
		return;

	/*
	 * Copy old map to new
	 */
	memcpy(new_map, old_map, stob(old_size));
}

boolean_t
vm_external_within(
	vm_size_t	new_size,
	vm_size_t	old_size)
{
	vm_size_t 	new_bytes;
	vm_size_t 	old_bytes;

	assert(new_size >= old_size);

	/*
	 * "old_bytes" is calculated to be the actual amount of space
	 * allocated for a map of size "old_size".
	 */
	old_bytes = stob(old_size);
	if (old_bytes <= SMALL_SIZE) old_bytes = SMALL_SIZE;
	else if (old_bytes <= LARGE_SIZE) old_bytes = power_of_2(old_bytes);

	/*
	 * "new_bytes" is the map size required to map the "new_size" object.
	 * Since the rounding algorithms are the same, we needn't actually
	 * round up new_bytes to get the correct answer
	 */
	new_bytes = stob(new_size);

	return(new_bytes <= old_bytes);
}

vm_external_state_t
_vm_external_state_get(
	vm_external_map_t	map,
	vm_offset_t		offset)
{
	unsigned
	int		bit, byte;

	assert (map != VM_EXTERNAL_NULL);

	bit = atop_32(offset);
	byte = bit >> 3;
	if (map[byte] & (1 << (bit & 07))) {
		return VM_EXTERNAL_STATE_EXISTS;
	} else {
		return VM_EXTERNAL_STATE_ABSENT;
	}
}

void
vm_external_state_set(
	vm_external_map_t	map,
	vm_offset_t		offset)
{
	unsigned
	int		bit, byte;

	if (map == VM_EXTERNAL_NULL)
		return;

	bit = atop_32(offset);
	byte = bit >> 3;
	map[byte] |= (1 << (bit & 07));
}

void
vm_external_state_clr(
	vm_external_map_t	map,
	vm_offset_t		offset)
{
	unsigned
	int		bit, byte;

	if (map == VM_EXTERNAL_NULL)
		return;

	bit = atop_32(offset);
	byte = bit >> 3;
	map[byte] &= ~(1 << (bit & 07));
}

void	
vm_external_module_initialize(void)
{
}
