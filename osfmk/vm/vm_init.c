/*
 * Copyright (c) 2000-2011 Apple Inc. All rights reserved.
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
#include <mach/vm_map.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <kern/kext_alloc.h>
#include <sys/kdebug.h>
#include <vm/vm_object.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_kern.h>
#include <vm/memory_object.h>
#include <vm/vm_fault.h>
#include <vm/vm_init.h>

#include <pexpert/pexpert.h>

#include <vm/vm_protos.h>

#define ZONE_MAP_MIN CONFIG_ZONE_MAP_MIN

/* Maximum zone size is 1.5G */
#define ZONE_MAP_MAX (1024 * 1024 * 1536) 

const vm_offset_t vm_min_kernel_address = VM_MIN_KERNEL_AND_KEXT_ADDRESS;
const vm_offset_t vm_max_kernel_address = VM_MAX_KERNEL_ADDRESS;

boolean_t vm_kernel_ready = FALSE;
boolean_t kmem_ready = FALSE;
boolean_t kmem_alloc_ready = FALSE;
boolean_t zlog_ready = FALSE;

vm_offset_t kmapoff_kaddr;
unsigned int kmapoff_pgcnt;

static inline void
vm_mem_bootstrap_log(const char *message)
{
//	kprintf("vm_mem_bootstrap: %s\n", message);
	kernel_debug_string(message);
}

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
	vm_mem_bootstrap_log("vm_page_bootstrap");
	vm_page_bootstrap(&start, &end);

	/*
	 *	Initialize other VM packages
	 */

	vm_mem_bootstrap_log("zone_bootstrap");
	zone_bootstrap();

	vm_mem_bootstrap_log("vm_object_bootstrap");
	vm_object_bootstrap();

	vm_kernel_ready = TRUE;

	vm_mem_bootstrap_log("vm_map_init");
	vm_map_init();

	vm_mem_bootstrap_log("kmem_init");
	kmem_init(start, end);
	kmem_ready = TRUE;
	/*
	 * Eat a random amount of kernel_map to fuzz subsequent heap, zone and
	 * stack addresses. (With a 4K page and 9 bits of randomness, this
	 * eats at most 2M of VA from the map.)
	 */
	if (!PE_parse_boot_argn("kmapoff", &kmapoff_pgcnt,
	    sizeof (kmapoff_pgcnt)))
		kmapoff_pgcnt = early_random() & 0x1ff;	/* 9 bits */

	if (kmapoff_pgcnt > 0 &&
	    vm_allocate(kernel_map, &kmapoff_kaddr,
	    kmapoff_pgcnt * PAGE_SIZE_64, VM_FLAGS_ANYWHERE) != KERN_SUCCESS)
		panic("cannot vm_allocate %u kernel_map pages", kmapoff_pgcnt);

	vm_mem_bootstrap_log("pmap_init");
	pmap_init();
	
	kmem_alloc_ready = TRUE;

	if (PE_parse_boot_argn("zsize", &zsizearg, sizeof (zsizearg)))
		zsize = zsizearg * 1024ULL * 1024ULL;
	else {
		zsize = sane_size >> 2;				/* Get target zone size as 1/4 of physical memory */
	}

	if (zsize < ZONE_MAP_MIN)
		zsize = ZONE_MAP_MIN;	/* Clamp to min */
#if defined(__LP64__)
	zsize += zsize >> 1;
#endif  /* __LP64__ */
	if (zsize > sane_size >> 1)
		zsize = sane_size >> 1;	/* Clamp to half of RAM max */
#if !__LP64__
	if (zsize > ZONE_MAP_MAX)
		zsize = ZONE_MAP_MAX;	/* Clamp to 1.5GB max for K32 */
#endif /* !__LP64__ */

	vm_mem_bootstrap_log("kext_alloc_init");
	kext_alloc_init();

	vm_mem_bootstrap_log("zone_init");
	assert((vm_size_t) zsize == zsize);
	zone_init((vm_size_t) zsize);	/* Allocate address space for zones */

	/* The vm_page_zone must be created prior to kalloc_init; that
	 * routine can trigger zalloc()s (for e.g. mutex statistic structure
	 * initialization). The vm_page_zone must exist to saisfy fictitious
	 * page allocations (which are used for guard pages by the guard
	 * mode zone allocator).
	 */
	vm_mem_bootstrap_log("vm_page_module_init");
	vm_page_module_init();

	vm_mem_bootstrap_log("kalloc_init");
	kalloc_init();

	vm_mem_bootstrap_log("vm_fault_init");
	vm_fault_init();

	vm_mem_bootstrap_log("memory_manager_default_init");
	memory_manager_default_init();

	vm_mem_bootstrap_log("memory_object_control_bootstrap");
	memory_object_control_bootstrap();

	vm_mem_bootstrap_log("device_pager_bootstrap");
	device_pager_bootstrap();

	vm_paging_map_init();

	vm_mem_bootstrap_log("vm_mem_bootstrap done");
}

void
vm_mem_init(void)
{
	vm_object_init();
}
