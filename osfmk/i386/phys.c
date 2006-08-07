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

#include <mach_rt.h>
#include <mach_debug.h>
#include <mach_ldebug.h>

#include <sys/kdebug.h>

#include <mach/kern_return.h>
#include <mach/thread_status.h>
#include <mach/vm_param.h>

#include <kern/counters.h>
#include <kern/mach_param.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/misc_protos.h>
#include <kern/assert.h>
#include <kern/spl.h>
#include <ipc/ipc_port.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/pmap.h>

#include <i386/cpu_data.h>
#include <i386/cpu_number.h>
#include <i386/thread.h>
#include <i386/eflags.h>
#include <i386/proc_reg.h>
#include <i386/seg.h>
#include <i386/tss.h>
#include <i386/user_ldt.h>
#include <i386/fpu.h>
#include <i386/iopb_entries.h>
#include <i386/misc_protos.h>

/*
 *	pmap_zero_page zeros the specified (machine independent) page.
 */
void
pmap_zero_page(
	       ppnum_t pn)
{
	assert(pn != vm_page_fictitious_addr);
	bzero_phys((addr64_t)i386_ptob(pn), PAGE_SIZE);
}

/*
 *	pmap_zero_part_page
 *	zeros the specified (machine independent) part of a page.
 */
void
pmap_zero_part_page(
        ppnum_t         pn,
	vm_offset_t     offset,
	vm_size_t       len)
{
	assert(pn != vm_page_fictitious_addr);
	assert(offset + len <= PAGE_SIZE);
	bzero_phys((addr64_t)(i386_ptob(pn) + offset), len);
}

/*
 *	pmap_copy_page copies the specified (machine independent) pages.
 */
void
pmap_copy_part_page(
	ppnum_t 	psrc,
	vm_offset_t	src_offset,
	ppnum_t	        pdst,
	vm_offset_t	dst_offset,
	vm_size_t	len)
{
        pmap_paddr_t src, dst;

	assert(psrc != vm_page_fictitious_addr);
	assert(pdst != vm_page_fictitious_addr);

	src = i386_ptob(psrc);
	dst = i386_ptob(pdst);

	assert((((uint32_t)dst & PAGE_MASK) + dst_offset + len) <= PAGE_SIZE);
	assert((((uint32_t)src & PAGE_MASK) + src_offset + len) <= PAGE_SIZE);

	bcopy_phys((addr64_t)src + (src_offset & INTEL_OFFMASK),
		   (addr64_t)dst + (dst_offset & INTEL_OFFMASK),
		   len);
}

/*
 *      pmap_copy_part_lpage copies part of a virtually addressed page 
 *      to a physically addressed page.
 */
void
pmap_copy_part_lpage(
	vm_offset_t 	src,
	ppnum_t 	pdst,
	vm_offset_t	dst_offset,
	vm_size_t	len)
{
        mapwindow_t *map;

	assert(pdst != vm_page_fictitious_addr);
	assert((dst_offset + len) <= PAGE_SIZE);

        mp_disable_preemption();

        map = pmap_get_mapwindow(INTEL_PTE_VALID | INTEL_PTE_RW | (i386_ptob(pdst) & PG_FRAME) | 
                                 INTEL_PTE_REF | INTEL_PTE_MOD);
	if (map == 0) {
	        panic("pmap_copy_part_lpage");
        }
	invlpg((uintptr_t)map->prv_CADDR);

	memcpy((void *) (map->prv_CADDR + (dst_offset & INTEL_OFFMASK)), (void *) src, len);
	*map->prv_CMAP = 0;

	mp_enable_preemption();
}

/*
 *      pmap_copy_part_rpage copies part of a physically addressed page 
 *      to a virtually addressed page.
 */
void
pmap_copy_part_rpage(
	ppnum_t	        psrc,
	vm_offset_t	src_offset,
	vm_offset_t	dst,
	vm_size_t	len)
{
        mapwindow_t *map;

	assert(psrc != vm_page_fictitious_addr);
	assert((src_offset + len) <= PAGE_SIZE);

        mp_disable_preemption();

        map = pmap_get_mapwindow(INTEL_PTE_VALID | INTEL_PTE_RW | (i386_ptob(psrc) & PG_FRAME) | 
                                 INTEL_PTE_REF);
	if (map == 0) {
	        panic("pmap_copy_part_rpage");
        }
	invlpg((uintptr_t) map->prv_CADDR);

	memcpy((void *) dst, (void *) (map->prv_CADDR + (src_offset & INTEL_OFFMASK)), len);
	*map->prv_CMAP = 0;

	mp_enable_preemption();
}

/*
 *	kvtophys(addr)
 *
 *	Convert a kernel virtual address to a physical address
 */
addr64_t
kvtophys(
	vm_offset_t addr)
{
        pt_entry_t *ptep;
	pmap_paddr_t pa;

	if ((ptep = pmap_pte(kernel_pmap, (vm_map_offset_t)addr)) == PT_ENTRY_NULL) {
	        pa = 0;
	} else {
	        pa =  pte_to_pa(*ptep) | (addr & INTEL_OFFMASK);
	}

	return ((addr64_t)pa);
}

