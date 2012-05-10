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
#include <i386/misc_protos.h>

/*
 *	pmap_zero_page zeros the specified (machine independent) page.
 */
void
pmap_zero_page(
       ppnum_t pn)
{
	assert(pn != vm_page_fictitious_addr);
	assert(pn != vm_page_guard_addr);
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
	assert(pn != vm_page_guard_addr);
	assert(offset + len <= PAGE_SIZE);
	bzero_phys((addr64_t)(i386_ptob(pn) + offset), (uint32_t)len);
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
	assert(psrc != vm_page_guard_addr);
	assert(pdst != vm_page_guard_addr);

	src = i386_ptob(psrc);
	dst = i386_ptob(pdst);

	assert((((uintptr_t)dst & PAGE_MASK) + dst_offset + len) <= PAGE_SIZE);
	assert((((uintptr_t)src & PAGE_MASK) + src_offset + len) <= PAGE_SIZE);

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
	__unused vm_offset_t 	src,
	__unused ppnum_t 	pdst,
	__unused vm_offset_t	dst_offset,
	__unused vm_size_t	len)
{
#ifdef __i386__
        mapwindow_t *map;
#endif

	assert(pdst != vm_page_fictitious_addr);
	assert(pdst != vm_page_guard_addr);
	assert((dst_offset + len) <= PAGE_SIZE);

#ifdef __i386__
        mp_disable_preemption();

        map = pmap_get_mapwindow(INTEL_PTE_VALID | INTEL_PTE_RW | (i386_ptob(pdst) & PG_FRAME) | 
                                 INTEL_PTE_REF | INTEL_PTE_MOD);

	memcpy((void *) (map->prv_CADDR + (dst_offset & INTEL_OFFMASK)), (void *) src, len);

	pmap_put_mapwindow(map);

	mp_enable_preemption();
#endif
}

/*
 *      pmap_copy_part_rpage copies part of a physically addressed page 
 *      to a virtually addressed page.
 */
void
pmap_copy_part_rpage(
	__unused ppnum_t	        psrc,
	__unused vm_offset_t	src_offset,
	__unused vm_offset_t	dst,
	__unused vm_size_t	len)
{
#ifdef __i386__
        mapwindow_t *map;
#endif

	assert(psrc != vm_page_fictitious_addr);
	assert(psrc != vm_page_guard_addr);
	assert((src_offset + len) <= PAGE_SIZE);

#ifdef __i386__
        mp_disable_preemption();

        map = pmap_get_mapwindow(INTEL_PTE_VALID | INTEL_PTE_RW | (i386_ptob(psrc) & PG_FRAME) | 
                                 INTEL_PTE_REF);

	memcpy((void *) dst, (void *) (map->prv_CADDR + (src_offset & INTEL_OFFMASK)), len);

	pmap_put_mapwindow(map);

	mp_enable_preemption();
#endif
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
	pmap_paddr_t pa;

	pa = ((pmap_paddr_t)pmap_find_phys(kernel_pmap, addr)) << INTEL_PGSHIFT;
	if (pa)
		pa |= (addr & INTEL_OFFMASK);

	return ((addr64_t)pa);
}

extern pt_entry_t *debugger_ptep;
extern vm_map_offset_t debugger_window_kva;

__private_extern__ void ml_copy_phys(addr64_t src64, addr64_t dst64, vm_size_t bytes) {
	void *src, *dst;

	mp_disable_preemption();
#if NCOPY_WINDOWS > 0
	mapwindow_t *src_map, *dst_map;
	/* We rely on MTRRs here */
	src_map = pmap_get_mapwindow((pt_entry_t)(INTEL_PTE_VALID | ((pmap_paddr_t)src64 & PG_FRAME) | INTEL_PTE_REF));
	dst_map = pmap_get_mapwindow((pt_entry_t)(INTEL_PTE_VALID | INTEL_PTE_RW | ((pmap_paddr_t)dst64 & PG_FRAME) | INTEL_PTE_REF | INTEL_PTE_MOD));
	src = (void *) ((uintptr_t)src_map->prv_CADDR | ((uint32_t)src64 & INTEL_OFFMASK));
	dst = (void *) ((uintptr_t)dst_map->prv_CADDR | ((uint32_t)dst64 & INTEL_OFFMASK));
#elif defined(__x86_64__)
	src = PHYSMAP_PTOV(src64);
	dst = PHYSMAP_PTOV(dst64);

	addr64_t debug_pa = 0;

	/* If either destination or source are outside the
	 * physical map, establish a physical window onto the target frame.
	 */
	assert(physmap_enclosed(src64) || physmap_enclosed(dst64));

	if (physmap_enclosed(src64) == FALSE) {
		src = (void *)(debugger_window_kva | (src64 & INTEL_OFFMASK));
		debug_pa = src64 & PG_FRAME;
	} else if (physmap_enclosed(dst64) == FALSE) {
		dst = (void *)(debugger_window_kva | (dst64 & INTEL_OFFMASK));
		debug_pa = dst64 & PG_FRAME;
	}
	/* DRK: debugger only routine, we don't bother checking for an
	 * identical mapping.
	 */
	if (debug_pa) {
		if (debugger_window_kva == 0)
			panic("%s: invoked in non-debug mode", __FUNCTION__);
		/* Establish a cache-inhibited physical window; some platforms
		 * may not cover arbitrary ranges with MTRRs
		 */
		pmap_store_pte(debugger_ptep, debug_pa | INTEL_PTE_NCACHE | INTEL_PTE_RW | INTEL_PTE_REF| INTEL_PTE_MOD | INTEL_PTE_VALID);
		flush_tlb_raw();
#if	DEBUG
		kprintf("Remapping debugger physical window at %p to 0x%llx\n", (void *)debugger_window_kva, debug_pa);
#endif
	}
#endif
	/* ensure we stay within a page */
	if (((((uint32_t)src64 & (I386_PGBYTES-1)) + bytes) > I386_PGBYTES) || ((((uint32_t)dst64 & (I386_PGBYTES-1)) + bytes) > I386_PGBYTES) ) {
	        panic("ml_copy_phys spans pages, src: 0x%llx, dst: 0x%llx", src64, dst64);
	}

	switch (bytes) {
	case 1:
		*((uint8_t *) dst) = *((volatile uint8_t *) src);
		break;
	case 2:
		*((uint16_t *) dst) = *((volatile uint16_t *) src);
		break;
	case 4:
		*((uint32_t *) dst) = *((volatile uint32_t *) src);
		break;
		/* Should perform two 32-bit reads */
	case 8:
		*((uint64_t *) dst) = *((volatile uint64_t *) src);
		break;
	default:
		bcopy(src, dst, bytes);
		break;
	}
#if NCOPY_WINDOWS > 0
	pmap_put_mapwindow(src_map);
	pmap_put_mapwindow(dst_map);
#endif
	mp_enable_preemption();
}
