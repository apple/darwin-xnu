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
 * @OSF_COPYRIGHT@
 * 
 */

#include <debug.h>
#include <mach/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <ppc/pmap.h>
#include <ppc/io_map_entries.h>
#include <ppc/Firmware.h>
#include <ppc/mappings.h>
#include <ppc/proc_reg.h>

extern vm_offset_t	virtual_avail;

/*
 * Allocate and map memory for devices that may need to be mapped 
 * outside the usual physical memory. If phys_addr is NULL then
 * steal the appropriate number of physical pages from the vm
 * system and map them.
 *
 * Note, this will onl
 */
vm_offset_t
io_map(phys_addr, size)
	vm_offset_t	phys_addr;
	vm_size_t	size;
{
	vm_offset_t	start;
	int		i;
	unsigned int j;
	vm_page_t 	m;


#if DEBUG
	assert (kernel_map != VM_MAP_NULL);			/* VM must be initialised */
#endif

	if (phys_addr != 0) {						/* If they supplied a physical address, use it */

		size = round_page(size + (phys_addr & PAGE_MASK));	/* Make sure we map all of it */

		(void) kmem_alloc_pageable(kernel_map, &start, size);	/* Get some virtual addresses to use */
		
		(void)mapping_make(kernel_pmap, (addr64_t)start, (ppnum_t)(phys_addr >> 12), 
			(mmFlgBlock | mmFlgUseAttr | mmFlgCInhib | mmFlgGuarded),	/* Map as I/O page */
			(size >> 12), VM_PROT_READ|VM_PROT_WRITE);

		return (start + (phys_addr & PAGE_MASK));	/* Pass back the physical address */
	
	} else {
	
		(void) kmem_alloc_pageable(kernel_map, &start, size);	/* Get some virtual addresses */

		mapping_prealloc(size);					/* Make sure there are enough free mappings */

		for (i = 0; i < size ; i += PAGE_SIZE) {
			m = VM_PAGE_NULL;
			while ((m = vm_page_grab()) == VM_PAGE_NULL) {	/* Get a physical page */
				VM_PAGE_WAIT();					/* Wait if we didn't have one */
			}
			vm_page_gobble(m);
			
			(void)mapping_make(kernel_pmap, 
				(addr64_t)(start + i), m->phys_page, 
				(mmFlgBlock | mmFlgUseAttr | mmFlgCInhib | mmFlgGuarded),	/* Map as I/O page */
				1, VM_PROT_READ|VM_PROT_WRITE);	
			
		}

		mapping_relpre();						/* Allow mapping release */
		return start;
	}
}


/*
 * Allocate and map memory for devices before the VM system comes alive.
 */

vm_offset_t io_map_spec(vm_offset_t phys_addr, vm_size_t size)
{
	vm_offset_t	start;

	if(kernel_map != VM_MAP_NULL) {				/* If VM system is up, redirect to normal routine */
		
		return io_map(phys_addr, size);			/* Map the address */
	
	}
	
	size = round_page(size + (phys_addr - (phys_addr & -PAGE_SIZE)));	/* Extend the length to include it all */
	start = pmap_boot_map(size);				/* Get me some virtual address */

	(void)mapping_make(kernel_pmap, (addr64_t)start, (ppnum_t)(phys_addr >> 12), 
		(mmFlgBlock | mmFlgUseAttr | mmFlgCInhib | mmFlgGuarded),	/* Map as I/O page */
		(size >> 12), VM_PROT_READ|VM_PROT_WRITE);

	return (start + (phys_addr & PAGE_MASK));
}
