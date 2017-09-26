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
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright notice
 * and this permission notice appear in all copies of the software,
 * derivative works or modified versions, and any portions thereof, and that
 * both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS" CONDITION.
 * CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR ANY DAMAGES
 * WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 * Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 * School of Computer Science Carnegie Mellon University Pittsburgh PA
 * 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon the
 * rights to redistribute these changes.
 */
/*
 */

#include <mach/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <arm/pmap.h>
#include <arm/io_map_entries.h>
#include <san/kasan.h>

extern vm_offset_t	virtual_space_start;     /* Next available kernel VA */

/*
 * Allocate and map memory for devices that may need to be mapped before
 * Mach VM is running.
 */
vm_offset_t
io_map(vm_map_offset_t phys_addr, vm_size_t size, unsigned int flags)
{
	vm_offset_t     start, start_offset;

	start_offset = phys_addr & PAGE_MASK;
	size += start_offset;
	phys_addr -= start_offset;

	if (kernel_map == VM_MAP_NULL) {
		/*
	         * VM is not initialized.  Grab memory.
	         */
		start = virtual_space_start;
		virtual_space_start += round_page(size);

		assert(flags == VM_WIMG_WCOMB || flags == VM_WIMG_IO);

		if (flags == VM_WIMG_WCOMB) {		
			(void) pmap_map_bd_with_options(start, phys_addr, phys_addr + round_page(size),
				   VM_PROT_READ | VM_PROT_WRITE, PMAP_MAP_BD_WCOMB);
		} else {
			(void) pmap_map_bd(start, phys_addr, phys_addr + round_page(size),
				   VM_PROT_READ | VM_PROT_WRITE);
		}
	} else {
		(void) kmem_alloc_pageable(kernel_map, &start, round_page(size), VM_KERN_MEMORY_IOKIT);
		(void) pmap_map(start, phys_addr, phys_addr + round_page(size),
				VM_PROT_READ | VM_PROT_WRITE, flags);
	}
#if KASAN
	kasan_notify_address(start + start_offset, size);
#endif
	return (start + start_offset);
}

/* just wrap this since io_map handles it */

vm_offset_t 
io_map_spec(vm_map_offset_t phys_addr, vm_size_t size, unsigned int flags)
{
	return (io_map(phys_addr, size, flags));
}
