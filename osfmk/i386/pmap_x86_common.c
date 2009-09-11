/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <i386/pmap_internal.h>
/*
 * The Intel platform can nest at the PDE level, so NBPDE (i.e. 2MB) at a time,
 * on a NBPDE boundary.
 */

/* These symbols may be referenced directly by VM */
uint64_t pmap_nesting_size_min = NBPDE;
uint64_t pmap_nesting_size_max = 0 - (uint64_t)NBPDE;

/*
 *	kern_return_t pmap_nest(grand, subord, va_start, size)
 *
 *	grand  = the pmap that we will nest subord into
 *	subord = the pmap that goes into the grand
 *	va_start  = start of range in pmap to be inserted
 *	nstart  = start of range in pmap nested pmap
 *	size   = Size of nest area (up to 16TB)
 *
 *	Inserts a pmap into another.  This is used to implement shared segments.
 *
 *	Note that we depend upon higher level VM locks to insure that things don't change while
 *	we are doing this.  For example, VM should not be doing any pmap enters while it is nesting
 *	or do 2 nests at once.
 */

/*
 * This routine can nest subtrees either at the PDPT level (1GiB) or at the
 * PDE level (2MiB). We currently disallow disparate offsets for the "subord"
 * container and the "grand" parent. A minor optimization to consider for the
 * future: make the "subord" truly a container rather than a full-fledged
 * pagetable hierarchy which can be unnecessarily sparse (DRK).
 */

kern_return_t pmap_nest(pmap_t grand, pmap_t subord, addr64_t va_start, addr64_t nstart, uint64_t size) {
	vm_map_offset_t	vaddr, nvaddr;
	pd_entry_t	*pde,*npde;
	unsigned int	i;
	uint64_t	num_pde;

	if ((size & (pmap_nesting_size_min-1)) ||
	    (va_start & (pmap_nesting_size_min-1)) ||
	    (nstart & (pmap_nesting_size_min-1)) ||
	    ((size >> 28) > 65536))	/* Max size we can nest is 16TB */
		return KERN_INVALID_VALUE;

	if(size == 0) {
		panic("pmap_nest: size is invalid - %016llX\n", size);
	}

	if (va_start != nstart)
		panic("pmap_nest: va_start(0x%llx) != nstart(0x%llx)\n", va_start, nstart);

	PMAP_TRACE(PMAP_CODE(PMAP__NEST) | DBG_FUNC_START,
	    (int) grand, (int) subord,
	    (int) (va_start>>32), (int) va_start, 0);

	nvaddr = (vm_map_offset_t)nstart;
	num_pde = size >> PDESHIFT;

	PMAP_LOCK(subord);

	subord->pm_shared = TRUE;

	for (i = 0; i < num_pde;) {
		if (((nvaddr & PDPTMASK) == 0) && (num_pde - i) >= NPDEPG && cpu_64bit) {

			npde = pmap64_pdpt(subord, nvaddr);

			while (0 == npde || ((*npde & INTEL_PTE_VALID) == 0)) {
				PMAP_UNLOCK(subord);
				pmap_expand_pdpt(subord, nvaddr);
				PMAP_LOCK(subord);
				npde = pmap64_pdpt(subord, nvaddr);
			}
			*npde |= INTEL_PDPTE_NESTED;
			nvaddr += NBPDPT;
			i += (uint32_t)NPDEPG;
		}
		else {
			npde = pmap_pde(subord, nvaddr);

			while (0 == npde || ((*npde & INTEL_PTE_VALID) == 0)) {
				PMAP_UNLOCK(subord);
				pmap_expand(subord, nvaddr);
				PMAP_LOCK(subord);
				npde = pmap_pde(subord, nvaddr);
			}
			nvaddr += NBPDE;
			i++;
		}
	}

	PMAP_UNLOCK(subord);

	vaddr = (vm_map_offset_t)va_start;

	PMAP_LOCK(grand);

	for (i = 0;i < num_pde;) {
		pd_entry_t tpde;

		if (((vaddr & PDPTMASK) == 0) && ((num_pde - i) >= NPDEPG) && cpu_64bit) {
			npde = pmap64_pdpt(subord, vaddr);
			if (npde == 0)
				panic("pmap_nest: no PDPT, subord %p nstart 0x%llx", subord, vaddr);
			tpde = *npde;
			pde = pmap64_pdpt(grand, vaddr);
			if (0 == pde) {
				PMAP_UNLOCK(grand);
				pmap_expand_pml4(grand, vaddr);
				PMAP_LOCK(grand);
				pde = pmap64_pdpt(grand, vaddr);
			}
			if (pde == 0)
				panic("pmap_nest: no PDPT, grand  %p vaddr 0x%llx", grand, vaddr);
			pmap_store_pte(pde, tpde);
			vaddr += NBPDPT;
			i += (uint32_t) NPDEPG;
		}
		else {
			npde = pmap_pde(subord, nstart);
			if (npde == 0)
				panic("pmap_nest: no npde, subord %p nstart 0x%llx", subord, nstart);
			tpde = *npde;
			nstart += NBPDE;
			pde = pmap_pde(grand, vaddr);
			if ((0 == pde) && cpu_64bit) {
				PMAP_UNLOCK(grand);
				pmap_expand_pdpt(grand, vaddr);
				PMAP_LOCK(grand);
				pde = pmap_pde(grand, vaddr);
			}

			if (pde == 0)
				panic("pmap_nest: no pde, grand  %p vaddr 0x%llx", grand, vaddr);
			vaddr += NBPDE;
			pmap_store_pte(pde, tpde);
			i++;
		}
	}

	PMAP_UNLOCK(grand);

	PMAP_TRACE(PMAP_CODE(PMAP__NEST) | DBG_FUNC_END, 0, 0, 0, 0, 0);

	return KERN_SUCCESS;
}

/*
 *	kern_return_t pmap_unnest(grand, vaddr)
 *
 *	grand  = the pmap that we will un-nest subord from
 *	vaddr  = start of range in pmap to be unnested
 *
 *	Removes a pmap from another.  This is used to implement shared segments.
 */

kern_return_t pmap_unnest(pmap_t grand, addr64_t vaddr, uint64_t size) {
			
	pd_entry_t *pde;
	unsigned int i;
	uint64_t num_pde;
	addr64_t va_start, va_end;
	uint64_t npdpt = PMAP_INVALID_PDPTNUM;

	PMAP_TRACE(PMAP_CODE(PMAP__UNNEST) | DBG_FUNC_START,
	    (int) grand, 
	    (int) (vaddr>>32), (int) vaddr, 0, 0);

	if ((size & (pmap_nesting_size_min-1)) ||
	    (vaddr & (pmap_nesting_size_min-1))) {
		panic("pmap_unnest(%p,0x%llx,0x%llx): unaligned...\n",
		    grand, vaddr, size);
	}

	/* align everything to PDE boundaries */
	va_start = vaddr & ~(NBPDE-1);
	va_end = (vaddr + size + NBPDE - 1) & ~(NBPDE-1);
	size = va_end - va_start;

	PMAP_LOCK(grand);

	num_pde = size >> PDESHIFT;
	vaddr = va_start;

	for (i = 0; i < num_pde; ) {
		if ((pdptnum(grand, vaddr) != npdpt) && cpu_64bit) {
			npdpt = pdptnum(grand, vaddr);
			pde = pmap64_pdpt(grand, vaddr);
			if (pde && (*pde & INTEL_PDPTE_NESTED)) {
				pmap_store_pte(pde, (pd_entry_t)0);
				i += (uint32_t) NPDEPG;
				vaddr += NBPDPT;
				continue;
			}
		}
		pde = pmap_pde(grand, (vm_map_offset_t)vaddr);
		if (pde == 0)
			panic("pmap_unnest: no pde, grand %p vaddr 0x%llx\n", grand, vaddr);
		pmap_store_pte(pde, (pd_entry_t)0);
		i++;
		vaddr += NBPDE;
	}

	PMAP_UPDATE_TLBS(grand, va_start, va_end);

	PMAP_UNLOCK(grand);
		
	PMAP_TRACE(PMAP_CODE(PMAP__UNNEST) | DBG_FUNC_END, 0, 0, 0, 0, 0);

	return KERN_SUCCESS;
}

/* Invoked by the Mach VM to determine the platform specific unnest region */

boolean_t pmap_adjust_unnest_parameters(pmap_t p, vm_map_offset_t *s, vm_map_offset_t *e) {
	pd_entry_t *pdpte;
	boolean_t rval = FALSE;

	if (!cpu_64bit)
		return rval;

	PMAP_LOCK(p);

	pdpte = pmap64_pdpt(p, *s);
	if (pdpte && (*pdpte & INTEL_PDPTE_NESTED)) {
		*s &= ~(NBPDPT -1);
		rval = TRUE;
	}

	pdpte = pmap64_pdpt(p, *e);
	if (pdpte && (*pdpte & INTEL_PDPTE_NESTED)) {
		*e = ((*e + NBPDPT) & ~(NBPDPT -1));
		rval = TRUE;
	}

	PMAP_UNLOCK(p);

	return rval;
}

/*
 * pmap_find_phys returns the (4K) physical page number containing a
 * given virtual address in a given pmap.
 * Note that pmap_pte may return a pde if this virtual address is
 * mapped by a large page and this is taken into account in order
 * to return the correct page number in this case.
 */
ppnum_t
pmap_find_phys(pmap_t pmap, addr64_t va)
{
	pt_entry_t	*ptp;
	pd_entry_t	*pdep;
	ppnum_t		ppn = 0;
	pd_entry_t	pde;
	pt_entry_t	pte;

	mp_disable_preemption();

	/* This refcount test is a band-aid--several infrastructural changes
	 * are necessary to eliminate invocation of this routine from arbitrary
	 * contexts.
	 */
	
	if (!pmap->ref_count)
		goto pfp_exit;

	pdep = pmap_pde(pmap, va);

	if ((pdep != PD_ENTRY_NULL) && ((pde = *pdep) & INTEL_PTE_VALID)) {
		if (pde & INTEL_PTE_PS) {
			ppn = (ppnum_t) i386_btop(pte_to_pa(pde));
			ppn += (ppnum_t) ptenum(va);
		}
		else {
			ptp = pmap_pte(pmap, va);
			if ((PT_ENTRY_NULL != ptp) && (((pte = *ptp) & INTEL_PTE_VALID) != 0)) {
				ppn = (ppnum_t) i386_btop(pte_to_pa(pte));
			}
		}
	}
pfp_exit:	
	mp_enable_preemption();

        return ppn;
}

