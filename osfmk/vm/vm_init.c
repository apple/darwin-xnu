/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
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
 *	File:	vm/vm_init.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Initialize the Virtual Memory subsystem.
 */

#include <mach/machine/vm_types.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <vm/vm_object.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_kern.h>
#include <vm/memory_object.h>
#include <vm/vm_fault.h>
#include <vm/vm_init.h>

#include <pexpert/pexpert.h>

#include <vm/vm_protos.h>

#define ZONE_MAP_MIN (12 * 1024 * 1024) 
/* Maximum Zone size is 1G */
#define ZONE_MAP_MAX (1024 * 1024 * 1024) 

const vm_offset_t vm_min_kernel_address = VM_MIN_KERNEL_ADDRESS;
const vm_offset_t vm_max_kernel_address = VM_MAX_KERNEL_ADDRESS;

/*
 *	vm_mem_bootstrap initializes the virtual memory system.
 *	This is done only by the first cpu up.
 */

void
vm_mem_bootstrap(void)
{
	vm_offset_t	start, end;
	vm_size_t zsizearg;
	mach_vm_size_t zsize;

	/*
	 *	Initializes resident memory structures.
	 *	From here on, all physical memory is accounted for,
	 *	and we use only virtual addresses.
	 */

	vm_page_bootstrap(&start, &end);

	/*
	 *	Initialize other VM packages
	 */

	zone_bootstrap();
	vm_object_bootstrap();
	vm_map_init();
	kmem_init(start, end);
	pmap_init();
	
	if (PE_parse_boot_arg("zsize", &zsizearg))
		zsize = zsizearg * 1024ULL * 1024ULL;
	else {
		zsize = sane_size >> 2;				/* Get target zone size as 1/4 of physical memory */
	}

	if(zsize < ZONE_MAP_MIN) zsize = ZONE_MAP_MIN;	/* Clamp to min */
	if(zsize > ZONE_MAP_MAX) zsize = ZONE_MAP_MAX;	/* Clamp to max */
	zone_init(zsize);						/* Allocate address space for zones */
	
	kalloc_init();
	vm_fault_init();
	vm_page_module_init();
	memory_manager_default_init();
	memory_object_control_bootstrap();
	device_pager_bootstrap();
}

void
vm_mem_init(void)
{
	vm_object_init();
}
