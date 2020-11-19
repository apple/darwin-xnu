/*
 * Copyright (c) 2000-2012 Apple Inc. All rights reserved.
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

#include <mach_assert.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <kern/ledger.h>
#include <i386/pmap_internal.h>

void            pmap_remove_range(
	pmap_t          pmap,
	vm_map_offset_t va,
	pt_entry_t      *spte,
	pt_entry_t      *epte);

static void            pmap_remove_range_options(
	pmap_t          pmap,
	vm_map_offset_t va,
	pt_entry_t      *spte,
	pt_entry_t      *epte,
	int             options);

void            pmap_reusable_range(
	pmap_t          pmap,
	vm_map_offset_t va,
	pt_entry_t      *spte,
	pt_entry_t      *epte,
	boolean_t       reusable);

uint32_t pmap_update_clear_pte_count;

/*
 * The Intel platform can nest at the PDE level, so NBPDE (i.e. 2MB) at a time,
 * on a NBPDE boundary.
 */

uint64_t
pmap_shared_region_size_min(__unused pmap_t pmap)
{
	return NBPDE;
}

uint64_t
pmap_commpage_size_min(__unused pmap_t pmap)
{
	return NBPDE;
}

uint64_t
pmap_nesting_size_max(__unused pmap_t pmap)
{
	return 0llu - (uint64_t)NBPDE;
}

/*
 *	kern_return_t pmap_nest(grand, subord, va_start, size)
 *
 *	grand  = the pmap that we will nest subord into
 *	subord = the pmap that goes into the grand
 *	va_start  = start of range in pmap to be inserted
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

kern_return_t
pmap_nest(pmap_t grand, pmap_t subord, addr64_t va_start, uint64_t size)
{
	vm_map_offset_t vaddr;
	pd_entry_t      *pde, *npde;
	unsigned int    i;
	uint64_t        num_pde;

	assert(!is_ept_pmap(grand));
	assert(!is_ept_pmap(subord));

	if ((size & (pmap_shared_region_size_min(grand) - 1)) ||
	    (va_start & (pmap_shared_region_size_min(grand) - 1)) ||
	    ((size >> 28) > 65536)) {   /* Max size we can nest is 16TB */
		return KERN_INVALID_VALUE;
	}

	if (size == 0) {
		panic("pmap_nest: size is invalid - %016llX\n", size);
	}

	PMAP_TRACE(PMAP_CODE(PMAP__NEST) | DBG_FUNC_START,
	    VM_KERNEL_ADDRHIDE(grand), VM_KERNEL_ADDRHIDE(subord),
	    VM_KERNEL_ADDRHIDE(va_start));

	vaddr = (vm_map_offset_t)va_start;
	num_pde = size >> PDESHIFT;

	PMAP_LOCK_EXCLUSIVE(subord);

	subord->pm_shared = TRUE;

	for (i = 0; i < num_pde;) {
		if (((vaddr & PDPTMASK) == 0) && (num_pde - i) >= NPDEPG) {
			npde = pmap64_pdpt(subord, vaddr);

			while (0 == npde || ((*npde & INTEL_PTE_VALID) == 0)) {
				PMAP_UNLOCK_EXCLUSIVE(subord);
				pmap_expand_pdpt(subord, vaddr, PMAP_EXPAND_OPTIONS_NONE);
				PMAP_LOCK_EXCLUSIVE(subord);
				npde = pmap64_pdpt(subord, vaddr);
			}
			*npde |= INTEL_PDPTE_NESTED;
			vaddr += NBPDPT;
			i += (uint32_t)NPDEPG;
		} else {
			npde = pmap_pde(subord, vaddr);

			while (0 == npde || ((*npde & INTEL_PTE_VALID) == 0)) {
				PMAP_UNLOCK_EXCLUSIVE(subord);
				pmap_expand(subord, vaddr, PMAP_EXPAND_OPTIONS_NONE);
				PMAP_LOCK_EXCLUSIVE(subord);
				npde = pmap_pde(subord, vaddr);
			}
			vaddr += NBPDE;
			i++;
		}
	}

	PMAP_UNLOCK_EXCLUSIVE(subord);

	vaddr = (vm_map_offset_t)va_start;

	PMAP_LOCK_EXCLUSIVE(grand);

	for (i = 0; i < num_pde;) {
		pd_entry_t tpde;

		if (((vaddr & PDPTMASK) == 0) && ((num_pde - i) >= NPDEPG)) {
			npde = pmap64_pdpt(subord, vaddr);
			if (npde == 0) {
				panic("pmap_nest: no PDPT, subord %p nstart 0x%llx", subord, vaddr);
			}
			tpde = *npde;
			pde = pmap64_pdpt(grand, vaddr);
			if (0 == pde) {
				PMAP_UNLOCK_EXCLUSIVE(grand);
				pmap_expand_pml4(grand, vaddr, PMAP_EXPAND_OPTIONS_NONE);
				PMAP_LOCK_EXCLUSIVE(grand);
				pde = pmap64_pdpt(grand, vaddr);
			}
			if (pde == 0) {
				panic("pmap_nest: no PDPT, grand  %p vaddr 0x%llx", grand, vaddr);
			}
			pmap_store_pte(pde, tpde);
			vaddr += NBPDPT;
			i += (uint32_t) NPDEPG;
		} else {
			npde = pmap_pde(subord, vaddr);
			if (npde == 0) {
				panic("pmap_nest: no npde, subord %p vaddr 0x%llx", subord, vaddr);
			}
			tpde = *npde;
			pde = pmap_pde(grand, vaddr);
			if (0 == pde) {
				PMAP_UNLOCK_EXCLUSIVE(grand);
				pmap_expand_pdpt(grand, vaddr, PMAP_EXPAND_OPTIONS_NONE);
				PMAP_LOCK_EXCLUSIVE(grand);
				pde = pmap_pde(grand, vaddr);
			}

			if (pde == 0) {
				panic("pmap_nest: no pde, grand  %p vaddr 0x%llx", grand, vaddr);
			}
			vaddr += NBPDE;
			pmap_store_pte(pde, tpde);
			i++;
		}
	}

	PMAP_UNLOCK_EXCLUSIVE(grand);

	PMAP_TRACE(PMAP_CODE(PMAP__NEST) | DBG_FUNC_END, KERN_SUCCESS);

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

kern_return_t
pmap_unnest(pmap_t grand, addr64_t vaddr, uint64_t size)
{
	pd_entry_t *pde;
	unsigned int i;
	uint64_t num_pde;
	addr64_t va_start, va_end;
	uint64_t npdpt = PMAP_INVALID_PDPTNUM;

	PMAP_TRACE(PMAP_CODE(PMAP__UNNEST) | DBG_FUNC_START,
	    VM_KERNEL_ADDRHIDE(grand), VM_KERNEL_ADDRHIDE(vaddr));

	if ((size & (pmap_shared_region_size_min(grand) - 1)) ||
	    (vaddr & (pmap_shared_region_size_min(grand) - 1))) {
		panic("pmap_unnest(%p,0x%llx,0x%llx): unaligned...\n",
		    grand, vaddr, size);
	}

	assert(!is_ept_pmap(grand));

	/* align everything to PDE boundaries */
	va_start = vaddr & ~(NBPDE - 1);
	va_end = (vaddr + size + NBPDE - 1) & ~(NBPDE - 1);
	size = va_end - va_start;

	PMAP_LOCK_EXCLUSIVE(grand);

	num_pde = size >> PDESHIFT;
	vaddr = va_start;

	for (i = 0; i < num_pde;) {
		if (pdptnum(grand, vaddr) != npdpt) {
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
		if (pde == 0) {
			panic("pmap_unnest: no pde, grand %p vaddr 0x%llx\n", grand, vaddr);
		}
		pmap_store_pte(pde, (pd_entry_t)0);
		i++;
		vaddr += NBPDE;
	}

	PMAP_UPDATE_TLBS(grand, va_start, va_end);

	PMAP_UNLOCK_EXCLUSIVE(grand);

	PMAP_TRACE(PMAP_CODE(PMAP__UNNEST) | DBG_FUNC_END, KERN_SUCCESS);

	return KERN_SUCCESS;
}

kern_return_t
pmap_unnest_options(
	pmap_t grand,
	addr64_t vaddr,
	__unused uint64_t size,
	__unused unsigned int options)
{
	return pmap_unnest(grand, vaddr, size);
}

/* Invoked by the Mach VM to determine the platform specific unnest region */

boolean_t
pmap_adjust_unnest_parameters(pmap_t p, vm_map_offset_t *s, vm_map_offset_t *e)
{
	pd_entry_t *pdpte;
	boolean_t rval = FALSE;

	PMAP_LOCK_EXCLUSIVE(p);

	pdpte = pmap64_pdpt(p, *s);
	if (pdpte && (*pdpte & INTEL_PDPTE_NESTED)) {
		*s &= ~(NBPDPT - 1);
		rval = TRUE;
	}

	pdpte = pmap64_pdpt(p, *e);
	if (pdpte && (*pdpte & INTEL_PDPTE_NESTED)) {
		*e = ((*e + NBPDPT) & ~(NBPDPT - 1));
		rval = TRUE;
	}

	PMAP_UNLOCK_EXCLUSIVE(p);

	return rval;
}

pmap_paddr_t
pmap_find_pa(pmap_t pmap, addr64_t va)
{
	pt_entry_t      *ptp;
	pd_entry_t      *pdep;
	pd_entry_t      pde;
	pt_entry_t      pte;
	boolean_t       is_ept, locked = FALSE;
	pmap_paddr_t    pa = 0;

	is_ept = is_ept_pmap(pmap);

	if ((pmap != kernel_pmap) && not_in_kdp) {
		PMAP_LOCK_EXCLUSIVE(pmap);
		locked = TRUE;
	} else {
		mp_disable_preemption();
	}

	if (os_ref_get_count(&pmap->ref_count) == 0) {
		goto pfp_exit;
	}

	pdep = pmap_pde(pmap, va);

	if ((pdep != PD_ENTRY_NULL) && ((pde = *pdep) & PTE_VALID_MASK(is_ept))) {
		if (pde & PTE_PS) {
			pa = pte_to_pa(pde) + (va & I386_LPGMASK);
		} else {
			ptp = pmap_pte(pmap, va);
			if ((PT_ENTRY_NULL != ptp) && (((pte = *ptp) & PTE_VALID_MASK(is_ept)) != 0)) {
				pa = pte_to_pa(pte) + (va & PAGE_MASK);
			}
		}
	}
pfp_exit:
	if (locked) {
		PMAP_UNLOCK_EXCLUSIVE(pmap);
	} else {
		mp_enable_preemption();
	}

	return pa;
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
	ppnum_t         ppn = 0;
	pmap_paddr_t    pa = 0;

	pa = pmap_find_pa(pmap, va);
	ppn = (ppnum_t) i386_btop(pa);

	return ppn;
}

ppnum_t
pmap_find_phys_nofault(pmap_t pmap, addr64_t va)
{
	if ((pmap == kernel_pmap) ||
	    ((current_thread()->map) && (pmap == vm_map_pmap(current_thread()->map)))) {
		return pmap_find_phys(pmap, va);
	}
	return 0;
}

/*
 *  pmap_get_prot returns the equivalent Vm page protections
 *  set on a given address, 'va'. This function is used in the
 *  ml_static_verify_page_protections() routine which is used
 *  by the kext loading code to validate that the TEXT segment
 *  of a kext is mapped executable.
 */
kern_return_t
pmap_get_prot(pmap_t pmap, addr64_t va, vm_prot_t *protp)
{
	pt_entry_t      *ptp;
	pd_entry_t      *pdep;
	pd_entry_t      pde;
	pt_entry_t      pte;
	boolean_t       is_ept, locked = FALSE;
	kern_return_t   retval = KERN_FAILURE;
	vm_prot_t       prot = 0;

	is_ept = is_ept_pmap(pmap);

	if ((pmap != kernel_pmap) && not_in_kdp) {
		PMAP_LOCK_EXCLUSIVE(pmap);
		locked = TRUE;
	} else {
		mp_disable_preemption();
	}

	if (os_ref_get_count(&pmap->ref_count) == 0) {
		goto pfp_exit;
	}

	pdep = pmap_pde(pmap, va);

	if ((pdep != PD_ENTRY_NULL) && ((pde = *pdep) & PTE_VALID_MASK(is_ept))) {
		if (pde & PTE_PS) {
			prot = VM_PROT_READ;

			if (pde & PTE_WRITE(is_ept)) {
				prot |= VM_PROT_WRITE;
			}
			if (PTE_IS_EXECUTABLE(is_ept, pde)) {
				prot |= VM_PROT_EXECUTE;
			}
			retval = KERN_SUCCESS;
		} else {
			ptp = pmap_pte(pmap, va);
			if ((PT_ENTRY_NULL != ptp) && (((pte = *ptp) & PTE_VALID_MASK(is_ept)) != 0)) {
				prot = VM_PROT_READ;

				if (pte & PTE_WRITE(is_ept)) {
					prot |= VM_PROT_WRITE;
				}
				if (PTE_IS_EXECUTABLE(is_ept, pte)) {
					prot |= VM_PROT_EXECUTE;
				}
				retval = KERN_SUCCESS;
			}
		}
	}

pfp_exit:
	if (locked) {
		PMAP_UNLOCK_EXCLUSIVE(pmap);
	} else {
		mp_enable_preemption();
	}

	if (protp) {
		*protp = prot;
	}

	return retval;
}

/*
 * Update cache attributes for all extant managed mappings.
 * Assumes PV for this page is locked, and that the page
 * is managed. We assume that this physical page may be mapped in
 * both EPT and normal Intel PTEs, so we convert the attributes
 * to the corresponding format for each pmap.
 *
 * We assert that the passed set of attributes is a subset of the
 * PHYS_CACHEABILITY_MASK.
 */
void
pmap_update_cache_attributes_locked(ppnum_t pn, unsigned attributes)
{
	pv_rooted_entry_t       pv_h, pv_e;
	pv_hashed_entry_t       pvh_e, nexth;
	vm_map_offset_t vaddr;
	pmap_t  pmap;
	pt_entry_t      *ptep;
	boolean_t       is_ept;
	unsigned        ept_attributes;

	assert(IS_MANAGED_PAGE(pn));
	assert(((~PHYS_CACHEABILITY_MASK) & attributes) == 0);

	/* We don't support the PAT bit for EPT PTEs */
	if (attributes & INTEL_PTE_NCACHE) {
		ept_attributes = INTEL_EPT_NCACHE;
	} else {
		ept_attributes = INTEL_EPT_WB;
	}

	pv_h = pai_to_pvh(pn);
	/* TODO: translate the PHYS_* bits to PTE bits, while they're
	 * currently identical, they may not remain so
	 * Potential optimization (here and in page_protect),
	 * parallel shootdowns, check for redundant
	 * attribute modifications.
	 */

	/*
	 * Alter attributes on all mappings
	 */
	if (pv_h->pmap != PMAP_NULL) {
		pv_e = pv_h;
		pvh_e = (pv_hashed_entry_t)pv_e;

		do {
			pmap = pv_e->pmap;
			vaddr = PVE_VA(pv_e);
			ptep = pmap_pte(pmap, vaddr);

			if (0 == ptep) {
				panic("pmap_update_cache_attributes_locked: Missing PTE, pmap: %p, pn: 0x%x vaddr: 0x%llx kernel_pmap: %p", pmap, pn, vaddr, kernel_pmap);
			}

			is_ept = is_ept_pmap(pmap);

			nexth = (pv_hashed_entry_t)queue_next(&pvh_e->qlink);
			if (!is_ept) {
				pmap_update_pte(ptep, PHYS_CACHEABILITY_MASK, attributes);
			} else {
				pmap_update_pte(ptep, INTEL_EPT_CACHE_MASK, ept_attributes);
			}
			PMAP_UPDATE_TLBS(pmap, vaddr, vaddr + PAGE_SIZE);
			pvh_e = nexth;
		} while ((pv_e = (pv_rooted_entry_t)nexth) != pv_h);
	}
}

void
x86_filter_TLB_coherency_interrupts(boolean_t dofilter)
{
	assert(ml_get_interrupts_enabled() == 0 || get_preemption_level() != 0);

	if (dofilter) {
		CPU_CR3_MARK_INACTIVE();
	} else {
		CPU_CR3_MARK_ACTIVE();
		mfence();
		pmap_update_interrupt();
	}
}


/*
 *	Insert the given physical page (p) at
 *	the specified virtual address (v) in the
 *	target physical map with the protection requested.
 *
 *	If specified, the page will be wired down, meaning
 *	that the related pte cannot be reclaimed.
 *
 *	NB:  This is the only routine which MAY NOT lazy-evaluate
 *	or lose information.  That is, this routine must actually
 *	insert this page into the given map NOW.
 */

kern_return_t
pmap_enter(
	pmap_t          pmap,
	vm_map_offset_t         vaddr,
	ppnum_t                 pn,
	vm_prot_t               prot,
	vm_prot_t               fault_type,
	unsigned int            flags,
	boolean_t               wired)
{
	return pmap_enter_options(pmap, vaddr, pn, prot, fault_type, flags, wired, PMAP_EXPAND_OPTIONS_NONE, NULL);
}

#define PTE_LOCK(EPT) INTEL_PTE_SWLOCK

static inline void PTE_LOCK_LOCK(pt_entry_t *);
static inline void PTE_LOCK_UNLOCK(pt_entry_t *);

void
PTE_LOCK_LOCK(pt_entry_t *lpte)
{
	pt_entry_t pte;
plretry:
	while ((pte = __c11_atomic_load((_Atomic pt_entry_t *)lpte, memory_order_relaxed)) & PTE_LOCK(0)) {
		__builtin_ia32_pause();
	}
	if (__c11_atomic_compare_exchange_strong((_Atomic pt_entry_t *)lpte, &pte, pte | PTE_LOCK(0), memory_order_acquire_smp, TRUE)) {
		return;
	}

	goto plretry;
}

void
PTE_LOCK_UNLOCK(pt_entry_t *lpte)
{
	__c11_atomic_fetch_and((_Atomic pt_entry_t *)lpte, ~PTE_LOCK(0), memory_order_release_smp);
}

kern_return_t
pmap_enter_options_addr(
	pmap_t pmap,
	vm_map_address_t v,
	pmap_paddr_t pa,
	vm_prot_t prot,
	vm_prot_t fault_type,
	unsigned int flags,
	boolean_t wired,
	unsigned int options,
	__unused void   *arg)
{
	return pmap_enter_options(pmap, v, intel_btop(pa), prot, fault_type, flags, wired, options, arg);
}

kern_return_t
pmap_enter_options(
	pmap_t          pmap,
	vm_map_offset_t         vaddr,
	ppnum_t                 pn,
	vm_prot_t               prot,
	__unused vm_prot_t      fault_type,
	unsigned int            flags,
	boolean_t               wired,
	unsigned int            options,
	void                    *arg)
{
	pt_entry_t              *pte = NULL;
	pv_rooted_entry_t       pv_h;
	ppnum_t                 pai;
	pv_hashed_entry_t       pvh_e;
	pv_hashed_entry_t       pvh_new;
	pt_entry_t              template;
	pmap_paddr_t            old_pa;
	pmap_paddr_t            pa = (pmap_paddr_t) i386_ptob(pn);
	boolean_t               need_tlbflush = FALSE;
	boolean_t               set_NX;
	char                    oattr;
	boolean_t               old_pa_locked;
	/* 2MiB mappings are confined to x86_64 by VM */
	boolean_t               superpage = flags & VM_MEM_SUPERPAGE;
	vm_object_t             delpage_pm_obj = NULL;
	uint64_t                delpage_pde_index = 0;
	pt_entry_t              old_pte;
	kern_return_t           kr = KERN_FAILURE;
	boolean_t               is_ept;
	boolean_t               is_altacct;
	boolean_t               ptelocked = FALSE;

	pmap_intr_assert();

	if (__improbable(pmap == PMAP_NULL)) {
		return KERN_INVALID_ARGUMENT;
	}
	if (__improbable(pn == vm_page_guard_addr)) {
		return KERN_INVALID_ARGUMENT;
	}

	is_ept = is_ept_pmap(pmap);

	/* N.B. We can be supplied a zero page frame in the NOENTER case, it's an
	 * unused value for that scenario.
	 */
	assert(pn != vm_page_fictitious_addr);


	PMAP_TRACE(PMAP_CODE(PMAP__ENTER) | DBG_FUNC_START,
	    VM_KERNEL_ADDRHIDE(pmap), VM_KERNEL_ADDRHIDE(vaddr), pn,
	    prot);

	if ((prot & VM_PROT_EXECUTE)) {
		set_NX = FALSE;
	} else {
		set_NX = TRUE;
	}

#if DEVELOPMENT || DEBUG
	if (__improbable(set_NX && (!nx_enabled || !pmap->nx_enabled))) {
		set_NX = FALSE;
	}

	if (__improbable(set_NX && (pmap == kernel_pmap) &&
	    ((pmap_disable_kstack_nx && (flags & VM_MEM_STACK)) ||
	    (pmap_disable_kheap_nx && !(flags & VM_MEM_STACK))))) {
		set_NX = FALSE;
	}
#endif

	pvh_new = PV_HASHED_ENTRY_NULL;
Retry:
	pvh_e = PV_HASHED_ENTRY_NULL;

	PMAP_LOCK_SHARED(pmap);

	/*
	 *	Expand pmap to include this pte.  Assume that
	 *	pmap is always expanded to include enough hardware
	 *	pages to map one VM page.
	 */
	if (__improbable(superpage)) {
		while ((pte = pmap_pde(pmap, vaddr)) == PD_ENTRY_NULL) {
			/* need room for another pde entry */
			PMAP_UNLOCK_SHARED(pmap);
			kr = pmap_expand_pdpt(pmap, vaddr, options);
			if (kr != KERN_SUCCESS) {
				goto done1;
			}
			PMAP_LOCK_SHARED(pmap);
		}
	} else {
		while ((pte = pmap_pte(pmap, vaddr)) == PT_ENTRY_NULL) {
			/*
			 * Must unlock to expand the pmap
			 * going to grow pde level page(s)
			 */
			PMAP_UNLOCK_SHARED(pmap);
			kr = pmap_expand(pmap, vaddr, options);
			if (kr != KERN_SUCCESS) {
				goto done1;
			}
			PMAP_LOCK_SHARED(pmap);
		}
	}

	if (__improbable(options & PMAP_EXPAND_OPTIONS_NOENTER)) {
		PMAP_UNLOCK_SHARED(pmap);
		kr = KERN_SUCCESS;
		goto done1;
	}

	if (__improbable(superpage && *pte && !(*pte & PTE_PS))) {
		/*
		 * There is still an empty page table mapped that
		 * was used for a previous base page mapping.
		 * Remember the PDE and the PDE index, so that we
		 * can free the page at the end of this function.
		 */
		delpage_pde_index = pdeidx(pmap, vaddr);
		delpage_pm_obj = pmap->pm_obj;
		pmap_store_pte(pte, 0);
	}

	PTE_LOCK_LOCK(pte);
	ptelocked = TRUE;

	old_pa = pte_to_pa(*pte);
	pai = pa_index(old_pa);
	old_pa_locked = FALSE;

	if (old_pa == 0 &&
	    PTE_IS_COMPRESSED(*pte, pte, pmap, vaddr)) {
		/*
		 * "pmap" should be locked at this point, so this should
		 * not race with another pmap_enter() or pmap_remove_range().
		 */
		assert(pmap != kernel_pmap);

		/* one less "compressed" */
		OSAddAtomic64(-1, &pmap->stats.compressed);
		pmap_ledger_debit(pmap, task_ledgers.internal_compressed,
		    PAGE_SIZE);
		if (*pte & PTE_COMPRESSED_ALT) {
			pmap_ledger_debit(
				pmap,
				task_ledgers.alternate_accounting_compressed,
				PAGE_SIZE);
		} else {
			/* was part of the footprint */
			pmap_ledger_debit(pmap, task_ledgers.phys_footprint,
			    PAGE_SIZE);
		}
		/* marker will be cleared below */
	}

	/*
	 * if we have a previous managed page, lock the pv entry now. after
	 * we lock it, check to see if someone beat us to the lock and if so
	 * drop the lock
	 */
	if ((0 != old_pa) && IS_MANAGED_PAGE(pai)) {
		LOCK_PVH(pai);
		old_pa_locked = TRUE;
		old_pa = pte_to_pa(*pte);
		if (0 == old_pa) {
			UNLOCK_PVH(pai);        /* another path beat us to it */
			old_pa_locked = FALSE;
		}
	}

	/*
	 *	Special case if the incoming physical page is already mapped
	 *	at this address.
	 */
	if (old_pa == pa) {
		pt_entry_t old_attributes =
		    *pte & ~(PTE_REF(is_ept) | PTE_MOD(is_ept) | PTE_LOCK(is_ept));

		/*
		 *	May be changing its wired attribute or protection
		 */

		template =  pa_to_pte(pa);

		if (__probable(!is_ept)) {
			template |= INTEL_PTE_VALID;
		} else {
			template |= INTEL_EPT_IPAT;
		}

		template |= pmap_get_cache_attributes(pa_index(pa), is_ept);

		/*
		 * We don't support passing VM_MEM_NOT_CACHEABLE flags for EPT PTEs
		 */
		if (!is_ept && (VM_MEM_NOT_CACHEABLE ==
		    (flags & (VM_MEM_NOT_CACHEABLE | VM_WIMG_USE_DEFAULT)))) {
			if (!(flags & VM_MEM_GUARDED)) {
				template |= INTEL_PTE_PAT;
			}
			template |= INTEL_PTE_NCACHE;
		}
		if (pmap != kernel_pmap && !is_ept) {
			template |= INTEL_PTE_USER;
		}

		if (prot & VM_PROT_READ) {
			template |= PTE_READ(is_ept);
		}

		if (prot & VM_PROT_WRITE) {
			template |= PTE_WRITE(is_ept);
			if (is_ept && !pmap_ept_support_ad) {
				template |= PTE_MOD(is_ept);
				if (old_pa_locked) {
					assert(IS_MANAGED_PAGE(pai));
					pmap_phys_attributes[pai] |= PHYS_MODIFIED;
				}
			}
		}
		if (prot & VM_PROT_EXECUTE) {
			assert(set_NX == 0);
			template = pte_set_ex(template, is_ept);
		}

		if (set_NX) {
			template = pte_remove_ex(template, is_ept);
		}

		if (wired) {
			template |= PTE_WIRED;
			if (!iswired(old_attributes)) {
				OSAddAtomic(+1, &pmap->stats.wired_count);
				pmap_ledger_credit(pmap, task_ledgers.wired_mem, PAGE_SIZE);
			}
		} else {
			if (iswired(old_attributes)) {
				assert(pmap->stats.wired_count >= 1);
				OSAddAtomic(-1, &pmap->stats.wired_count);
				pmap_ledger_debit(pmap, task_ledgers.wired_mem, PAGE_SIZE);
			}
		}

		if (superpage) {        /* this path can not be used */
			template |= PTE_PS;     /* to change the page size! */
		}
		if (old_attributes == template) {
			goto dont_update_pte;
		}

		/* Determine delta, PV locked */
		need_tlbflush =
		    ((old_attributes ^ template) != PTE_WIRED);

		/* Optimisation: avoid TLB flush when adding writability */
		if (need_tlbflush == TRUE && !(old_attributes & PTE_WRITE(is_ept))) {
			if ((old_attributes ^ template) == PTE_WRITE(is_ept)) {
				need_tlbflush = FALSE;
			}
		}

		/* For hardware that doesn't have EPT AD support, we always set REFMOD for EPT PTEs */
		if (__improbable(is_ept && !pmap_ept_support_ad)) {
			template |= PTE_REF(is_ept);
			if (old_pa_locked) {
				assert(IS_MANAGED_PAGE(pai));
				pmap_phys_attributes[pai] |= PHYS_REFERENCED;
			}
		}

		/* store modified PTE and preserve RC bits */
		pt_entry_t npte, opte;

		assert((*pte & PTE_LOCK(is_ept)) != 0);

		do {
			opte = *pte;
			npte = template | (opte & (PTE_REF(is_ept) |
			    PTE_MOD(is_ept))) | PTE_LOCK(is_ept);
		} while (!pmap_cmpx_pte(pte, opte, npte));

dont_update_pte:
		if (old_pa_locked) {
			UNLOCK_PVH(pai);
			old_pa_locked = FALSE;
		}
		goto done2;
	}

	/*
	 *	Outline of code from here:
	 *	   1) If va was mapped, update TLBs, remove the mapping
	 *	      and remove old pvlist entry.
	 *	   2) Add pvlist entry for new mapping
	 *	   3) Enter new mapping.
	 *
	 *	If the old physical page is not managed step 1) is skipped
	 *	(except for updating the TLBs), and the mapping is
	 *	overwritten at step 3).  If the new physical page is not
	 *	managed, step 2) is skipped.
	 */
	/* TODO: add opportunistic refmod collect */
	if (old_pa != (pmap_paddr_t) 0) {
		boolean_t       was_altacct = FALSE;

		/*
		 *	Don't do anything to pages outside valid memory here.
		 *	Instead convince the code that enters a new mapping
		 *	to overwrite the old one.
		 */

		/* invalidate the PTE */
		pmap_update_pte(pte, PTE_VALID_MASK(is_ept), 0);
		/* propagate invalidate everywhere */
		PMAP_UPDATE_TLBS(pmap, vaddr, vaddr + PAGE_SIZE);
		/* remember reference and change */
		old_pte = *pte;
		oattr = (char) (old_pte & (PTE_MOD(is_ept) | PTE_REF(is_ept)));
		/* completely invalidate the PTE */
		pmap_store_pte(pte, PTE_LOCK(is_ept));

		if (IS_MANAGED_PAGE(pai)) {
			/*
			 *	Remove the mapping from the pvlist for
			 *	this physical page.
			 *      We'll end up with either a rooted pv or a
			 *      hashed pv
			 */
			pvh_e = pmap_pv_remove(pmap, vaddr, (ppnum_t *) &pai, &old_pte, &was_altacct);
		}

		if (IS_MANAGED_PAGE(pai)) {
			pmap_assert(old_pa_locked == TRUE);
			pmap_ledger_debit(pmap, task_ledgers.phys_mem, PAGE_SIZE);
			assert(pmap->stats.resident_count >= 1);
			OSAddAtomic(-1, &pmap->stats.resident_count);
			if (pmap != kernel_pmap) {
				/* update pmap stats */
				if (IS_REUSABLE_PAGE(pai)) {
					PMAP_STATS_ASSERTF(
						(pmap->stats.reusable > 0,
						"reusable %d",
						pmap->stats.reusable));
					OSAddAtomic(-1, &pmap->stats.reusable);
				} else if (IS_INTERNAL_PAGE(pai)) {
					PMAP_STATS_ASSERTF(
						(pmap->stats.internal > 0,
						"internal %d",
						pmap->stats.internal));
					OSAddAtomic(-1, &pmap->stats.internal);
				} else {
					PMAP_STATS_ASSERTF(
						(pmap->stats.external > 0,
						"external %d",
						pmap->stats.external));
					OSAddAtomic(-1, &pmap->stats.external);
				}

				/* update ledgers */
				if (was_altacct) {
					assert(IS_INTERNAL_PAGE(pai));
					pmap_ledger_debit(pmap, task_ledgers.internal, PAGE_SIZE);
					pmap_ledger_debit(pmap, task_ledgers.alternate_accounting, PAGE_SIZE);
				} else if (IS_REUSABLE_PAGE(pai)) {
					assert(!was_altacct);
					assert(IS_INTERNAL_PAGE(pai));
					/* was already not in phys_footprint */
				} else if (IS_INTERNAL_PAGE(pai)) {
					assert(!was_altacct);
					assert(!IS_REUSABLE_PAGE(pai));
					pmap_ledger_debit(pmap, task_ledgers.internal, PAGE_SIZE);
					pmap_ledger_debit(pmap, task_ledgers.phys_footprint, PAGE_SIZE);
				} else {
					/* not an internal page */
				}
			}
			if (iswired(*pte)) {
				assert(pmap->stats.wired_count >= 1);
				OSAddAtomic(-1, &pmap->stats.wired_count);
				pmap_ledger_debit(pmap, task_ledgers.wired_mem,
				    PAGE_SIZE);
			}

			if (!is_ept) {
				pmap_phys_attributes[pai] |= oattr;
			} else {
				pmap_phys_attributes[pai] |= ept_refmod_to_physmap(oattr);
			}
		} else {
			/*
			 *	old_pa is not managed.
			 *	Do removal part of accounting.
			 */

			if (pmap != kernel_pmap) {
#if 00
				assert(pmap->stats.device > 0);
				OSAddAtomic(-1, &pmap->stats.device);
#endif
			}
			if (iswired(*pte)) {
				assert(pmap->stats.wired_count >= 1);
				OSAddAtomic(-1, &pmap->stats.wired_count);
				pmap_ledger_debit(pmap, task_ledgers.wired_mem, PAGE_SIZE);
			}
		}
	}

	/*
	 * if we had a previously managed paged locked, unlock it now
	 */
	if (old_pa_locked) {
		UNLOCK_PVH(pai);
		old_pa_locked = FALSE;
	}

	pai = pa_index(pa);     /* now working with new incoming phys page */
	if (IS_MANAGED_PAGE(pai)) {
		/*
		 *	Step 2) Enter the mapping in the PV list for this
		 *	physical page.
		 */
		pv_h = pai_to_pvh(pai);

		LOCK_PVH(pai);

		if (pv_h->pmap == PMAP_NULL) {
			/*
			 *	No mappings yet, use rooted pv
			 */
			pv_h->va_and_flags = vaddr;
			pv_h->pmap = pmap;
			queue_init(&pv_h->qlink);

			if (options & PMAP_OPTIONS_INTERNAL) {
				pmap_phys_attributes[pai] |= PHYS_INTERNAL;
			} else {
				pmap_phys_attributes[pai] &= ~PHYS_INTERNAL;
			}
			if (options & PMAP_OPTIONS_REUSABLE) {
				pmap_phys_attributes[pai] |= PHYS_REUSABLE;
			} else {
				pmap_phys_attributes[pai] &= ~PHYS_REUSABLE;
			}
			if ((options & PMAP_OPTIONS_ALT_ACCT) &&
			    IS_INTERNAL_PAGE(pai)) {
				pv_h->va_and_flags |= PVE_IS_ALTACCT;
				is_altacct = TRUE;
			} else {
				pv_h->va_and_flags &= ~PVE_IS_ALTACCT;
				is_altacct = FALSE;
			}
		} else {
			/*
			 *	Add new pv_hashed_entry after header.
			 */
			if ((PV_HASHED_ENTRY_NULL == pvh_e) && pvh_new) {
				pvh_e = pvh_new;
				pvh_new = PV_HASHED_ENTRY_NULL;
			} else if (PV_HASHED_ENTRY_NULL == pvh_e) {
				PV_HASHED_ALLOC(&pvh_e);
				if (PV_HASHED_ENTRY_NULL == pvh_e) {
					/*
					 * the pv list is empty. if we are on
					 * the kernel pmap we'll use one of
					 * the special private kernel pv_e's,
					 * else, we need to unlock
					 * everything, zalloc a pv_e, and
					 * restart bringing in the pv_e with
					 * us.
					 */
					if (kernel_pmap == pmap) {
						PV_HASHED_KERN_ALLOC(&pvh_e);
					} else {
						UNLOCK_PVH(pai);
						PTE_LOCK_UNLOCK(pte);
						PMAP_UNLOCK_SHARED(pmap);
						pmap_pv_throttle(pmap);
						pvh_new = (pv_hashed_entry_t) zalloc(pv_hashed_list_zone);
						goto Retry;
					}
				}
			}

			if (PV_HASHED_ENTRY_NULL == pvh_e) {
				panic("Mapping alias chain exhaustion, possibly induced by numerous kernel virtual double mappings");
			}

			pvh_e->va_and_flags = vaddr;
			pvh_e->pmap = pmap;
			pvh_e->ppn = pn;
			if ((options & PMAP_OPTIONS_ALT_ACCT) &&
			    IS_INTERNAL_PAGE(pai)) {
				pvh_e->va_and_flags |= PVE_IS_ALTACCT;
				is_altacct = TRUE;
			} else {
				pvh_e->va_and_flags &= ~PVE_IS_ALTACCT;
				is_altacct = FALSE;
			}
			pv_hash_add(pvh_e, pv_h);

			/*
			 *	Remember that we used the pvlist entry.
			 */
			pvh_e = PV_HASHED_ENTRY_NULL;
		}

		/*
		 * only count the mapping
		 * for 'managed memory'
		 */
		pmap_ledger_credit(pmap, task_ledgers.phys_mem, PAGE_SIZE);
		OSAddAtomic(+1, &pmap->stats.resident_count);
		if (pmap->stats.resident_count > pmap->stats.resident_max) {
			pmap->stats.resident_max = pmap->stats.resident_count;
		}
		if (pmap != kernel_pmap) {
			/* update pmap stats */
			if (IS_REUSABLE_PAGE(pai)) {
				OSAddAtomic(+1, &pmap->stats.reusable);
				PMAP_STATS_PEAK(pmap->stats.reusable);
			} else if (IS_INTERNAL_PAGE(pai)) {
				OSAddAtomic(+1, &pmap->stats.internal);
				PMAP_STATS_PEAK(pmap->stats.internal);
			} else {
				OSAddAtomic(+1, &pmap->stats.external);
				PMAP_STATS_PEAK(pmap->stats.external);
			}

			/* update ledgers */
			if (is_altacct) {
				/* internal but also alternate accounting */
				assert(IS_INTERNAL_PAGE(pai));
				pmap_ledger_credit(pmap, task_ledgers.internal, PAGE_SIZE);
				pmap_ledger_credit(pmap, task_ledgers.alternate_accounting, PAGE_SIZE);
				/* alternate accounting, so not in footprint */
			} else if (IS_REUSABLE_PAGE(pai)) {
				assert(!is_altacct);
				assert(IS_INTERNAL_PAGE(pai));
				/* internal but reusable: not in footprint */
			} else if (IS_INTERNAL_PAGE(pai)) {
				assert(!is_altacct);
				assert(!IS_REUSABLE_PAGE(pai));
				/* internal: add to footprint */
				pmap_ledger_credit(pmap, task_ledgers.internal, PAGE_SIZE);
				pmap_ledger_credit(pmap, task_ledgers.phys_footprint, PAGE_SIZE);
			} else {
				/* not internal: not in footprint */
			}
		}
	} else if (last_managed_page == 0) {
		/* Account for early mappings created before "managed pages"
		 * are determined. Consider consulting the available DRAM map.
		 */
		pmap_ledger_credit(pmap, task_ledgers.phys_mem, PAGE_SIZE);
		OSAddAtomic(+1, &pmap->stats.resident_count);
		if (pmap != kernel_pmap) {
#if 00
			OSAddAtomic(+1, &pmap->stats.device);
			PMAP_STATS_PEAK(pmap->stats.device);
#endif
		}
	}
	/*
	 * Step 3) Enter the mapping.
	 *
	 *	Build a template to speed up entering -
	 *	only the pfn changes.
	 */
	template = pa_to_pte(pa);

	if (!is_ept) {
		template |= INTEL_PTE_VALID;
	} else {
		template |= INTEL_EPT_IPAT;
	}


	/*
	 * DRK: It may be worth asserting on cache attribute flags that diverge
	 * from the existing physical page attributes.
	 */

	template |= pmap_get_cache_attributes(pa_index(pa), is_ept);

	/*
	 * We don't support passing VM_MEM_NOT_CACHEABLE flags for EPT PTEs
	 */
	if (!is_ept && (flags & VM_MEM_NOT_CACHEABLE)) {
		if (!(flags & VM_MEM_GUARDED)) {
			template |= INTEL_PTE_PAT;
		}
		template |= INTEL_PTE_NCACHE;
	}
	if (pmap != kernel_pmap && !is_ept) {
		template |= INTEL_PTE_USER;
	}
	if (prot & VM_PROT_READ) {
		template |= PTE_READ(is_ept);
	}
	if (prot & VM_PROT_WRITE) {
		template |= PTE_WRITE(is_ept);
		if (is_ept && !pmap_ept_support_ad) {
			template |= PTE_MOD(is_ept);
			if (IS_MANAGED_PAGE(pai)) {
				pmap_phys_attributes[pai] |= PHYS_MODIFIED;
			}
		}
	}
	if (prot & VM_PROT_EXECUTE) {
		assert(set_NX == 0);
		template = pte_set_ex(template, is_ept);
	}

	if (set_NX) {
		template = pte_remove_ex(template, is_ept);
	}
	if (wired) {
		template |= INTEL_PTE_WIRED;
		OSAddAtomic(+1, &pmap->stats.wired_count);
		pmap_ledger_credit(pmap, task_ledgers.wired_mem, PAGE_SIZE);
	}
	if (__improbable(superpage)) {
		template |= INTEL_PTE_PS;
	}

	/* For hardware that doesn't have EPT AD support, we always set REFMOD for EPT PTEs */
	if (__improbable(is_ept && !pmap_ept_support_ad)) {
		template |= PTE_REF(is_ept);
		if (IS_MANAGED_PAGE(pai)) {
			pmap_phys_attributes[pai] |= PHYS_REFERENCED;
		}
	}
	template |= PTE_LOCK(is_ept);
	pmap_store_pte(pte, template);

	/*
	 * if this was a managed page we delayed unlocking the pv until here
	 * to prevent pmap_page_protect et al from finding it until the pte
	 * has been stored
	 */
	if (IS_MANAGED_PAGE(pai)) {
		UNLOCK_PVH(pai);
	}
done2:
	if (need_tlbflush == TRUE) {
		if (options & PMAP_OPTIONS_NOFLUSH) {
			PMAP_UPDATE_TLBS_DELAYED(pmap, vaddr, vaddr + PAGE_SIZE, (pmap_flush_context *)arg);
		} else {
			PMAP_UPDATE_TLBS(pmap, vaddr, vaddr + PAGE_SIZE);
		}
	}
	if (ptelocked) {
		PTE_LOCK_UNLOCK(pte);
	}
	PMAP_UNLOCK_SHARED(pmap);

	if (pvh_e != PV_HASHED_ENTRY_NULL) {
		PV_HASHED_FREE_LIST(pvh_e, pvh_e, 1);
	}
	if (pvh_new != PV_HASHED_ENTRY_NULL) {
		PV_HASHED_KERN_FREE_LIST(pvh_new, pvh_new, 1);
	}

	if (delpage_pm_obj) {
		vm_page_t m;

		vm_object_lock(delpage_pm_obj);
		m = vm_page_lookup(delpage_pm_obj, (delpage_pde_index * PAGE_SIZE));
		if (m == VM_PAGE_NULL) {
			panic("pmap_enter: pte page not in object");
		}
		VM_PAGE_FREE(m);
		vm_object_unlock(delpage_pm_obj);
		OSAddAtomic(-1, &inuse_ptepages_count);
		PMAP_ZINFO_PFREE(pmap, PAGE_SIZE);
	}

	kr = KERN_SUCCESS;
done1:
	PMAP_TRACE(PMAP_CODE(PMAP__ENTER) | DBG_FUNC_END, kr);
	return kr;
}

/*
 *	Remove a range of hardware page-table entries.
 *	The entries given are the first (inclusive)
 *	and last (exclusive) entries for the VM pages.
 *	The virtual address is the va for the first pte.
 *
 *	The pmap must be locked.
 *	If the pmap is not the kernel pmap, the range must lie
 *	entirely within one pte-page.  This is NOT checked.
 *	Assumes that the pte-page exists.
 */

void
pmap_remove_range(
	pmap_t                  pmap,
	vm_map_offset_t         start_vaddr,
	pt_entry_t              *spte,
	pt_entry_t              *epte)
{
	pmap_remove_range_options(pmap, start_vaddr, spte, epte,
	    PMAP_OPTIONS_REMOVE);
}

static void
pmap_remove_range_options(
	pmap_t                  pmap,
	vm_map_offset_t         start_vaddr,
	pt_entry_t              *spte,
	pt_entry_t              *epte,
	int                     options)
{
	pt_entry_t              *cpte;
	pv_hashed_entry_t       pvh_et = PV_HASHED_ENTRY_NULL;
	pv_hashed_entry_t       pvh_eh = PV_HASHED_ENTRY_NULL;
	pv_hashed_entry_t       pvh_e;
	int                     pvh_cnt = 0;
	int                     num_removed, num_unwired, num_found, num_invalid;
	int                     stats_external, stats_internal, stats_reusable;
	uint64_t                stats_compressed;
	int                     ledgers_internal, ledgers_alt_internal;
	uint64_t                ledgers_compressed, ledgers_alt_compressed;
	ppnum_t                 pai;
	pmap_paddr_t            pa;
	vm_map_offset_t         vaddr;
	boolean_t               is_ept = is_ept_pmap(pmap);
	boolean_t               was_altacct;

	num_removed = 0;
	num_unwired = 0;
	num_found   = 0;
	num_invalid = 0;
	stats_external = 0;
	stats_internal = 0;
	stats_reusable = 0;
	stats_compressed = 0;
	ledgers_internal = 0;
	ledgers_compressed = 0;
	ledgers_alt_internal = 0;
	ledgers_alt_compressed = 0;

	/* invalidate the PTEs first to "freeze" them */
	for (cpte = spte, vaddr = start_vaddr;
	    cpte < epte;
	    cpte++, vaddr += PAGE_SIZE_64) {
		pt_entry_t p = *cpte;

		pa = pte_to_pa(p);
		if (pa == 0) {
			if ((options & PMAP_OPTIONS_REMOVE) &&
			    (PTE_IS_COMPRESSED(p, cpte, pmap, vaddr))) {
				assert(pmap != kernel_pmap);
				/* one less "compressed"... */
				stats_compressed++;
				ledgers_compressed++;
				if (p & PTE_COMPRESSED_ALT) {
					/* ... but it used to be "ALTACCT" */
					ledgers_alt_compressed++;
				}
				/* clear marker(s) */
				/* XXX probably does not need to be atomic! */
				pmap_update_pte(cpte, INTEL_PTE_COMPRESSED_MASK, 0);
			}
			continue;
		}
		num_found++;

		if (iswired(p)) {
			num_unwired++;
		}

		pai = pa_index(pa);

		if (!IS_MANAGED_PAGE(pai)) {
			/*
			 *	Outside range of managed physical memory.
			 *	Just remove the mappings.
			 */
			pmap_store_pte(cpte, 0);
			continue;
		}

		if ((p & PTE_VALID_MASK(is_ept)) == 0) {
			num_invalid++;
		}

		/* invalidate the PTE */
		pmap_update_pte(cpte, PTE_VALID_MASK(is_ept), 0);
	}

	if (num_found == 0) {
		/* nothing was changed: we're done */
		goto update_counts;
	}

	/* propagate the invalidates to other CPUs */

	PMAP_UPDATE_TLBS(pmap, start_vaddr, vaddr);

	for (cpte = spte, vaddr = start_vaddr;
	    cpte < epte;
	    cpte++, vaddr += PAGE_SIZE_64) {
		pa = pte_to_pa(*cpte);
		if (pa == 0) {
check_pte_for_compressed_marker:
			/*
			 * This PTE could have been replaced with a
			 * "compressed" marker after our first "freeze"
			 * loop above, so check again.
			 */
			if ((options & PMAP_OPTIONS_REMOVE) &&
			    (PTE_IS_COMPRESSED(*cpte, cpte, pmap, vaddr))) {
				assert(pmap != kernel_pmap);
				/* one less "compressed"... */
				stats_compressed++;
				ledgers_compressed++;
				if (*cpte & PTE_COMPRESSED_ALT) {
					/* ... but it used to be "ALTACCT" */
					ledgers_alt_compressed++;
				}
				pmap_store_pte(cpte, 0);
			}
			continue;
		}

		pai = pa_index(pa);

		LOCK_PVH(pai);

		pa = pte_to_pa(*cpte);
		if (pa == 0) {
			UNLOCK_PVH(pai);
			goto check_pte_for_compressed_marker;
		}

		/*
		 * Remove the mapping from the pvlist for this physical page.
		 */
		pvh_e = pmap_pv_remove(pmap, vaddr, (ppnum_t *) &pai, cpte, &was_altacct);

		num_removed++;
		/* update pmap stats */
		if (IS_REUSABLE_PAGE(pai)) {
			stats_reusable++;
		} else if (IS_INTERNAL_PAGE(pai)) {
			stats_internal++;
		} else {
			stats_external++;
		}
		/* update ledgers */
		if (was_altacct) {
			/* internal and alternate accounting */
			assert(IS_INTERNAL_PAGE(pai));
			ledgers_internal++;
			ledgers_alt_internal++;
		} else if (IS_REUSABLE_PAGE(pai)) {
			/* internal but reusable */
			assert(!was_altacct);
			assert(IS_INTERNAL_PAGE(pai));
		} else if (IS_INTERNAL_PAGE(pai)) {
			/* internal */
			assert(!was_altacct);
			assert(!IS_REUSABLE_PAGE(pai));
			ledgers_internal++;
		} else {
			/* not internal */
		}

		/*
		 * Get the modify and reference bits, then
		 * nuke the entry in the page table
		 */
		/* remember reference and change */
		if (!is_ept) {
			pmap_phys_attributes[pai] |=
			    *cpte & (PHYS_MODIFIED | PHYS_REFERENCED);
		} else {
			pmap_phys_attributes[pai] |=
			    ept_refmod_to_physmap((*cpte & (INTEL_EPT_REF | INTEL_EPT_MOD))) & (PHYS_MODIFIED | PHYS_REFERENCED);
		}

		/* completely invalidate the PTE */
		pmap_store_pte(cpte, 0);

		UNLOCK_PVH(pai);

		if (pvh_e != PV_HASHED_ENTRY_NULL) {
			pvh_e->qlink.next = (queue_entry_t) pvh_eh;
			pvh_eh = pvh_e;

			if (pvh_et == PV_HASHED_ENTRY_NULL) {
				pvh_et = pvh_e;
			}
			pvh_cnt++;
		}
		/* We can encounter at most 'num_found' PTEs for this level
		 * Fewer may be encountered if some were replaced by
		 * compressed markers. No new valid PTEs can be created
		 * since the pmap lock is held exclusively.
		 */
		if (num_removed == num_found) {
			break;
		}
	} /* for loop */

	if (pvh_eh != PV_HASHED_ENTRY_NULL) {
		PV_HASHED_FREE_LIST(pvh_eh, pvh_et, pvh_cnt);
	}
update_counts:
	/*
	 *	Update the counts
	 */
#if TESTING
	if (pmap->stats.resident_count < num_removed) {
		panic("pmap_remove_range: resident_count");
	}
#endif
	if (num_removed) {
		pmap_ledger_debit(pmap, task_ledgers.phys_mem, machine_ptob(num_removed));
		PMAP_STATS_ASSERTF((pmap->stats.resident_count >= num_removed,
		    "pmap=%p num_removed=%d stats.resident_count=%d",
		    pmap, num_removed, pmap->stats.resident_count));
		OSAddAtomic(-num_removed, &pmap->stats.resident_count);
	}

	if (pmap != kernel_pmap) {
		PMAP_STATS_ASSERTF((pmap->stats.external >= stats_external,
		    "pmap=%p stats_external=%d stats.external=%d",
		    pmap, stats_external, pmap->stats.external));
		PMAP_STATS_ASSERTF((pmap->stats.internal >= stats_internal,
		    "pmap=%p stats_internal=%d stats.internal=%d",
		    pmap, stats_internal, pmap->stats.internal));
		PMAP_STATS_ASSERTF((pmap->stats.reusable >= stats_reusable,
		    "pmap=%p stats_reusable=%d stats.reusable=%d",
		    pmap, stats_reusable, pmap->stats.reusable));
		PMAP_STATS_ASSERTF((pmap->stats.compressed >= stats_compressed,
		    "pmap=%p stats_compressed=%lld, stats.compressed=%lld",
		    pmap, stats_compressed, pmap->stats.compressed));

		/* update pmap stats */
		if (stats_external) {
			OSAddAtomic(-stats_external, &pmap->stats.external);
		}
		if (stats_internal) {
			OSAddAtomic(-stats_internal, &pmap->stats.internal);
		}
		if (stats_reusable) {
			OSAddAtomic(-stats_reusable, &pmap->stats.reusable);
		}
		if (stats_compressed) {
			OSAddAtomic64(-stats_compressed, &pmap->stats.compressed);
		}
		/* update ledgers */

		if (ledgers_internal) {
			pmap_ledger_debit(pmap,
			    task_ledgers.internal,
			    machine_ptob(ledgers_internal));
		}
		if (ledgers_compressed) {
			pmap_ledger_debit(pmap,
			    task_ledgers.internal_compressed,
			    machine_ptob(ledgers_compressed));
		}
		if (ledgers_alt_internal) {
			pmap_ledger_debit(pmap,
			    task_ledgers.alternate_accounting,
			    machine_ptob(ledgers_alt_internal));
		}
		if (ledgers_alt_compressed) {
			pmap_ledger_debit(pmap,
			    task_ledgers.alternate_accounting_compressed,
			    machine_ptob(ledgers_alt_compressed));
		}

		uint64_t net_debit = (ledgers_internal - ledgers_alt_internal) + (ledgers_compressed - ledgers_alt_compressed);
		if (net_debit) {
			pmap_ledger_debit(pmap, task_ledgers.phys_footprint, machine_ptob(net_debit));
		}
	}

#if TESTING
	if (pmap->stats.wired_count < num_unwired) {
		panic("pmap_remove_range: wired_count");
	}
#endif
	PMAP_STATS_ASSERTF((pmap->stats.wired_count >= num_unwired,
	    "pmap=%p num_unwired=%d stats.wired_count=%d",
	    pmap, num_unwired, pmap->stats.wired_count));

	if (num_unwired != 0) {
		OSAddAtomic(-num_unwired, &pmap->stats.wired_count);
		pmap_ledger_debit(pmap, task_ledgers.wired_mem, machine_ptob(num_unwired));
	}
	return;
}


/*
 *	Remove the given range of addresses
 *	from the specified map.
 *
 *	It is assumed that the start and end are properly
 *	rounded to the hardware page size.
 */
void
pmap_remove(
	pmap_t          map,
	addr64_t        s64,
	addr64_t        e64)
{
	pmap_remove_options(map, s64, e64, PMAP_OPTIONS_REMOVE);
}
#define PLCHECK_THRESHOLD (2)

void
pmap_remove_options(
	pmap_t          map,
	addr64_t        s64,
	addr64_t        e64,
	int             options)
{
	pt_entry_t     *pde;
	pt_entry_t     *spte, *epte;
	addr64_t        l64;
	uint64_t        deadline = 0;
	boolean_t       is_ept;

	pmap_intr_assert();

	if (map == PMAP_NULL || s64 == e64) {
		return;
	}

	is_ept = is_ept_pmap(map);

	PMAP_TRACE(PMAP_CODE(PMAP__REMOVE) | DBG_FUNC_START,
	    VM_KERNEL_ADDRHIDE(map), VM_KERNEL_ADDRHIDE(s64),
	    VM_KERNEL_ADDRHIDE(e64));

	PMAP_LOCK_EXCLUSIVE(map);
	uint32_t traverse_count = 0;

	while (s64 < e64) {
		pml4_entry_t *pml4e = pmap64_pml4(map, s64);
		if ((pml4e == NULL) ||
		    ((*pml4e & PTE_VALID_MASK(is_ept)) == 0)) {
			s64 = (s64 + NBPML4) & ~(PML4MASK);
			continue;
		}
		pdpt_entry_t *pdpte = pmap64_pdpt(map, s64);
		if ((pdpte == NULL) ||
		    ((*pdpte & PTE_VALID_MASK(is_ept)) == 0)) {
			s64 = (s64 + NBPDPT) & ~(PDPTMASK);
			continue;
		}

		l64 = (s64 + PDE_MAPPED_SIZE) & ~(PDE_MAPPED_SIZE - 1);

		if (l64 > e64) {
			l64 = e64;
		}

		pde = pmap_pde(map, s64);

		if (pde && (*pde & PTE_VALID_MASK(is_ept))) {
			if (*pde & PTE_PS) {
				/*
				 * If we're removing a superpage, pmap_remove_range()
				 * must work on level 2 instead of level 1; and we're
				 * only passing a single level 2 entry instead of a
				 * level 1 range.
				 */
				spte = pde;
				epte = spte + 1; /* excluded */
			} else {
				spte = pmap_pte(map, (s64 & ~(PDE_MAPPED_SIZE - 1)));
				spte = &spte[ptenum(s64)];
				epte = &spte[intel_btop(l64 - s64)];
			}
			pmap_remove_range_options(map, s64, spte, epte,
			    options);
		}
		s64 = l64;

		if ((s64 < e64) && (traverse_count++ > PLCHECK_THRESHOLD)) {
			if (deadline == 0) {
				deadline = rdtsc64_nofence() + max_preemption_latency_tsc;
			} else {
				if (rdtsc64_nofence() > deadline) {
					PMAP_UNLOCK_EXCLUSIVE(map);
					__builtin_ia32_pause();
					PMAP_LOCK_EXCLUSIVE(map);
					deadline = rdtsc64_nofence() + max_preemption_latency_tsc;
				}
			}
		}
	}

	PMAP_UNLOCK_EXCLUSIVE(map);

	PMAP_TRACE(PMAP_CODE(PMAP__REMOVE) | DBG_FUNC_END);
}

void
pmap_page_protect(
	ppnum_t         pn,
	vm_prot_t       prot)
{
	pmap_page_protect_options(pn, prot, 0, NULL);
}

/*
 *	Routine:	pmap_page_protect_options
 *
 *	Function:
 *		Lower the permission for all mappings to a given
 *		page.
 */
void
pmap_page_protect_options(
	ppnum_t         pn,
	vm_prot_t       prot,
	unsigned int    options,
	void            *arg)
{
	pv_hashed_entry_t       pvh_eh = PV_HASHED_ENTRY_NULL;
	pv_hashed_entry_t       pvh_et = PV_HASHED_ENTRY_NULL;
	pv_hashed_entry_t       nexth;
	int                     pvh_cnt = 0;
	pv_rooted_entry_t       pv_h;
	pv_rooted_entry_t       pv_e;
	pv_hashed_entry_t       pvh_e;
	pt_entry_t              *pte;
	int                     pai;
	pmap_t                  pmap;
	boolean_t               remove;
	pt_entry_t              new_pte_value;
	boolean_t               is_ept;

	pmap_intr_assert();
	assert(pn != vm_page_fictitious_addr);
	if (pn == vm_page_guard_addr) {
		return;
	}

	pai = ppn_to_pai(pn);

	if (!IS_MANAGED_PAGE(pai)) {
		/*
		 *	Not a managed page.
		 */
		return;
	}

	PMAP_TRACE(PMAP_CODE(PMAP__PAGE_PROTECT) | DBG_FUNC_START, pn, prot);

	/*
	 * Determine the new protection.
	 */
	switch (prot) {
	case VM_PROT_READ:
	case VM_PROT_READ | VM_PROT_EXECUTE:
		remove = FALSE;
		break;
	case VM_PROT_ALL:
		return;         /* nothing to do */
	default:
		remove = TRUE;
		break;
	}

	pv_h = pai_to_pvh(pai);

	LOCK_PVH(pai);


	/*
	 * Walk down PV list, if any, changing or removing all mappings.
	 */
	if (pv_h->pmap == PMAP_NULL) {
		goto done;
	}

	pv_e = pv_h;
	pvh_e = (pv_hashed_entry_t) pv_e;       /* cheat */

	do {
		vm_map_offset_t vaddr;

		if ((options & PMAP_OPTIONS_COMPRESSOR_IFF_MODIFIED) &&
		    (pmap_phys_attributes[pai] & PHYS_MODIFIED)) {
			/* page was modified, so it will be compressed */
			options &= ~PMAP_OPTIONS_COMPRESSOR_IFF_MODIFIED;
			options |= PMAP_OPTIONS_COMPRESSOR;
		}

		pmap = pv_e->pmap;
		is_ept = is_ept_pmap(pmap);
		vaddr = PVE_VA(pv_e);
		pte = pmap_pte(pmap, vaddr);

		pmap_assert2((pa_index(pte_to_pa(*pte)) == pn),
		    "pmap_page_protect: PTE mismatch, pn: 0x%x, pmap: %p, vaddr: 0x%llx, pte: 0x%llx", pn, pmap, vaddr, *pte);

		if (0 == pte) {
			panic("pmap_page_protect() "
			    "pmap=%p pn=0x%x vaddr=0x%llx\n",
			    pmap, pn, vaddr);
		}
		nexth = (pv_hashed_entry_t) queue_next(&pvh_e->qlink);

		/*
		 * Remove the mapping if new protection is NONE
		 */
		if (remove) {
			/* Remove per-pmap wired count */
			if (iswired(*pte)) {
				OSAddAtomic(-1, &pmap->stats.wired_count);
				pmap_ledger_debit(pmap, task_ledgers.wired_mem, PAGE_SIZE);
			}

			if (pmap != kernel_pmap &&
			    (options & PMAP_OPTIONS_COMPRESSOR) &&
			    IS_INTERNAL_PAGE(pai)) {
				assert(!PTE_IS_COMPRESSED(*pte, pte, pmap, vaddr));
				/* mark this PTE as having been "compressed" */
				new_pte_value = PTE_COMPRESSED;
				if (IS_ALTACCT_PAGE(pai, pv_e)) {
					new_pte_value |= PTE_COMPRESSED_ALT;
				}
			} else {
				new_pte_value = 0;
			}

			if (options & PMAP_OPTIONS_NOREFMOD) {
				pmap_store_pte(pte, new_pte_value);

				if (options & PMAP_OPTIONS_NOFLUSH) {
					PMAP_UPDATE_TLBS_DELAYED(pmap, vaddr, vaddr + PAGE_SIZE, (pmap_flush_context *)arg);
				} else {
					PMAP_UPDATE_TLBS(pmap, vaddr, vaddr + PAGE_SIZE);
				}
			} else {
				/*
				 * Remove the mapping, collecting dirty bits.
				 */
				pmap_update_pte(pte, PTE_VALID_MASK(is_ept), 0);

				PMAP_UPDATE_TLBS(pmap, vaddr, vaddr + PAGE_SIZE);
				if (!is_ept) {
					pmap_phys_attributes[pai] |=
					    *pte & (PHYS_MODIFIED | PHYS_REFERENCED);
				} else {
					pmap_phys_attributes[pai] |=
					    ept_refmod_to_physmap((*pte & (INTEL_EPT_REF | INTEL_EPT_MOD))) & (PHYS_MODIFIED | PHYS_REFERENCED);
				}
				if ((options &
				    PMAP_OPTIONS_COMPRESSOR_IFF_MODIFIED) &&
				    IS_INTERNAL_PAGE(pai) &&
				    (pmap_phys_attributes[pai] &
				    PHYS_MODIFIED)) {
					/*
					 * Page is actually "modified" and
					 * will be compressed.  Start
					 * accounting for it as "compressed".
					 */
					assert(!(options & PMAP_OPTIONS_COMPRESSOR));
					options &= ~PMAP_OPTIONS_COMPRESSOR_IFF_MODIFIED;
					options |= PMAP_OPTIONS_COMPRESSOR;
					assert(new_pte_value == 0);
					if (pmap != kernel_pmap) {
						new_pte_value = PTE_COMPRESSED;
						if (IS_ALTACCT_PAGE(pai, pv_e)) {
							new_pte_value |= PTE_COMPRESSED_ALT;
						}
					}
				}
				pmap_store_pte(pte, new_pte_value);
			}

#if TESTING
			if (pmap->stats.resident_count < 1) {
				panic("pmap_page_protect: resident_count");
			}
#endif
			pmap_ledger_debit(pmap, task_ledgers.phys_mem, PAGE_SIZE);
			assert(pmap->stats.resident_count >= 1);
			OSAddAtomic(-1, &pmap->stats.resident_count);

			/*
			 * We only ever compress internal pages.
			 */
			if (options & PMAP_OPTIONS_COMPRESSOR) {
				assert(IS_INTERNAL_PAGE(pai));
			}
			if (pmap != kernel_pmap) {
				/* update pmap stats */
				if (IS_REUSABLE_PAGE(pai)) {
					assert(pmap->stats.reusable > 0);
					OSAddAtomic(-1, &pmap->stats.reusable);
				} else if (IS_INTERNAL_PAGE(pai)) {
					assert(pmap->stats.internal > 0);
					OSAddAtomic(-1, &pmap->stats.internal);
				} else {
					assert(pmap->stats.external > 0);
					OSAddAtomic(-1, &pmap->stats.external);
				}
				if ((options & PMAP_OPTIONS_COMPRESSOR) &&
				    IS_INTERNAL_PAGE(pai)) {
					/* adjust "compressed" stats */
					OSAddAtomic64(+1, &pmap->stats.compressed);
					PMAP_STATS_PEAK(pmap->stats.compressed);
					pmap->stats.compressed_lifetime++;
				}

				/* update ledgers */
				if (IS_ALTACCT_PAGE(pai, pv_e)) {
					assert(IS_INTERNAL_PAGE(pai));
					pmap_ledger_debit(pmap, task_ledgers.internal, PAGE_SIZE);
					pmap_ledger_debit(pmap, task_ledgers.alternate_accounting, PAGE_SIZE);
					if (options & PMAP_OPTIONS_COMPRESSOR) {
						pmap_ledger_credit(pmap, task_ledgers.internal_compressed, PAGE_SIZE);
						pmap_ledger_credit(pmap, task_ledgers.alternate_accounting_compressed, PAGE_SIZE);
					}
				} else if (IS_REUSABLE_PAGE(pai)) {
					assert(!IS_ALTACCT_PAGE(pai, pv_e));
					assert(IS_INTERNAL_PAGE(pai));
					if (options & PMAP_OPTIONS_COMPRESSOR) {
						pmap_ledger_credit(pmap, task_ledgers.internal_compressed, PAGE_SIZE);
						/* was not in footprint, but is now */
						pmap_ledger_credit(pmap, task_ledgers.phys_footprint, PAGE_SIZE);
					}
				} else if (IS_INTERNAL_PAGE(pai)) {
					assert(!IS_ALTACCT_PAGE(pai, pv_e));
					assert(!IS_REUSABLE_PAGE(pai));
					pmap_ledger_debit(pmap, task_ledgers.internal, PAGE_SIZE);
					/*
					 * Update all stats related to physical
					 * footprint, which only deals with
					 * internal pages.
					 */
					if (options & PMAP_OPTIONS_COMPRESSOR) {
						/*
						 * This removal is only being
						 * done so we can send this page
						 * to the compressor;  therefore
						 * it mustn't affect total task
						 * footprint.
						 */
						pmap_ledger_credit(pmap, task_ledgers.internal_compressed, PAGE_SIZE);
					} else {
						/*
						 * This internal page isn't
						 * going to the compressor,
						 * so adjust stats to keep
						 * phys_footprint up to date.
						 */
						pmap_ledger_debit(pmap, task_ledgers.phys_footprint, PAGE_SIZE);
					}
				}
			}

			/*
			 * Deal with the pv_rooted_entry.
			 */

			if (pv_e == pv_h) {
				/*
				 * Fix up head later.
				 */
				pv_h->pmap = PMAP_NULL;
			} else {
				/*
				 * Delete this entry.
				 */
				pv_hash_remove(pvh_e);
				pvh_e->qlink.next = (queue_entry_t) pvh_eh;
				pvh_eh = pvh_e;

				if (pvh_et == PV_HASHED_ENTRY_NULL) {
					pvh_et = pvh_e;
				}
				pvh_cnt++;
			}
		} else {
			/*
			 * Write-protect, after opportunistic refmod collect
			 */
			if (!is_ept) {
				pmap_phys_attributes[pai] |=
				    *pte & (PHYS_MODIFIED | PHYS_REFERENCED);
			} else {
				pmap_phys_attributes[pai] |=
				    ept_refmod_to_physmap((*pte & (INTEL_EPT_REF | INTEL_EPT_MOD))) & (PHYS_MODIFIED | PHYS_REFERENCED);
			}
			pmap_update_pte(pte, PTE_WRITE(is_ept), 0);

			if (options & PMAP_OPTIONS_NOFLUSH) {
				PMAP_UPDATE_TLBS_DELAYED(pmap, vaddr, vaddr + PAGE_SIZE, (pmap_flush_context *)arg);
			} else {
				PMAP_UPDATE_TLBS(pmap, vaddr, vaddr + PAGE_SIZE);
			}
		}
		pvh_e = nexth;
	} while ((pv_e = (pv_rooted_entry_t) nexth) != pv_h);


	/*
	 * If pv_head mapping was removed, fix it up.
	 */
	if (pv_h->pmap == PMAP_NULL) {
		pvh_e = (pv_hashed_entry_t) queue_next(&pv_h->qlink);

		if (pvh_e != (pv_hashed_entry_t) pv_h) {
			pv_hash_remove(pvh_e);
			pv_h->pmap = pvh_e->pmap;
			pv_h->va_and_flags = pvh_e->va_and_flags;
			pvh_e->qlink.next = (queue_entry_t) pvh_eh;
			pvh_eh = pvh_e;

			if (pvh_et == PV_HASHED_ENTRY_NULL) {
				pvh_et = pvh_e;
			}
			pvh_cnt++;
		}
	}
	if (pvh_eh != PV_HASHED_ENTRY_NULL) {
		PV_HASHED_FREE_LIST(pvh_eh, pvh_et, pvh_cnt);
	}
done:
	UNLOCK_PVH(pai);

	PMAP_TRACE(PMAP_CODE(PMAP__PAGE_PROTECT) | DBG_FUNC_END);
}


/*
 *	Clear specified attribute bits.
 */
void
phys_attribute_clear(
	ppnum_t         pn,
	int             bits,
	unsigned int    options,
	void            *arg)
{
	pv_rooted_entry_t       pv_h;
	pv_hashed_entry_t       pv_e;
	pt_entry_t              *pte = NULL;
	int                     pai;
	pmap_t                  pmap;
	char                    attributes = 0;
	boolean_t               is_internal, is_reusable, is_altacct, is_ept;
	int                     ept_bits_to_clear;
	boolean_t               ept_keep_global_mod = FALSE;

	if ((bits & PHYS_MODIFIED) &&
	    (options & PMAP_OPTIONS_NOFLUSH) &&
	    arg == NULL) {
		panic("phys_attribute_clear(0x%x,0x%x,0x%x,%p): "
		    "should not clear 'modified' without flushing TLBs\n",
		    pn, bits, options, arg);
	}

	/* We only support converting MOD and REF bits for EPT PTEs in this function */
	assert((bits & ~(PHYS_REFERENCED | PHYS_MODIFIED)) == 0);

	ept_bits_to_clear = (unsigned)physmap_refmod_to_ept(bits & (PHYS_MODIFIED | PHYS_REFERENCED));

	pmap_intr_assert();
	assert(pn != vm_page_fictitious_addr);
	if (pn == vm_page_guard_addr) {
		return;
	}

	pai = ppn_to_pai(pn);

	if (!IS_MANAGED_PAGE(pai)) {
		/*
		 *	Not a managed page.
		 */
		return;
	}

	PMAP_TRACE(PMAP_CODE(PMAP__ATTRIBUTE_CLEAR) | DBG_FUNC_START, pn, bits);

	pv_h = pai_to_pvh(pai);

	LOCK_PVH(pai);


	/*
	 * Walk down PV list, clearing all modify or reference bits.
	 * We do not have to lock the pv_list because we have
	 * the per-pmap lock
	 */
	if (pv_h->pmap != PMAP_NULL) {
		/*
		 * There are some mappings.
		 */

		is_internal = IS_INTERNAL_PAGE(pai);
		is_reusable = IS_REUSABLE_PAGE(pai);

		pv_e = (pv_hashed_entry_t)pv_h;

		do {
			vm_map_offset_t va;
			char pte_bits;

			pmap = pv_e->pmap;
			is_ept = is_ept_pmap(pmap);
			is_altacct = IS_ALTACCT_PAGE(pai, pv_e);
			va = PVE_VA(pv_e);
			pte_bits = 0;

			if (bits) {
				pte = pmap_pte(pmap, va);
				/* grab ref/mod bits from this PTE */
				pte_bits = (*pte & (PTE_REF(is_ept) | PTE_MOD(is_ept)));
				/* propagate to page's global attributes */
				if (!is_ept) {
					attributes |= pte_bits;
				} else {
					attributes |= ept_refmod_to_physmap(pte_bits);
					if (!pmap_ept_support_ad && (pte_bits & INTEL_EPT_MOD)) {
						ept_keep_global_mod = TRUE;
					}
				}
				/* which bits to clear for this PTE? */
				if (!is_ept) {
					pte_bits &= bits;
				} else {
					pte_bits &= ept_bits_to_clear;
				}
			}
			if (options & PMAP_OPTIONS_CLEAR_WRITE) {
				pte_bits |= PTE_WRITE(is_ept);
			}

			/*
			 * Clear modify and/or reference bits.
			 */
			if (pte_bits) {
				pmap_update_pte(pte, pte_bits, 0);

				/* Ensure all processors using this translation
				 * invalidate this TLB entry. The invalidation
				 * *must* follow the PTE update, to ensure that
				 * the TLB shadow of the 'D' bit (in particular)
				 * is synchronized with the updated PTE.
				 */
				if (!(options & PMAP_OPTIONS_NOFLUSH)) {
					/* flush TLBS now */
					PMAP_UPDATE_TLBS(pmap,
					    va,
					    va + PAGE_SIZE);
				} else if (arg) {
					/* delayed TLB flush: add "pmap" info */
					PMAP_UPDATE_TLBS_DELAYED(
						pmap,
						va,
						va + PAGE_SIZE,
						(pmap_flush_context *)arg);
				} else {
					/* no TLB flushing at all */
				}
			}

			/* update pmap "reusable" stats */
			if ((options & PMAP_OPTIONS_CLEAR_REUSABLE) &&
			    is_reusable &&
			    pmap != kernel_pmap) {
				/* one less "reusable" */
				assert(pmap->stats.reusable > 0);
				OSAddAtomic(-1, &pmap->stats.reusable);
				if (is_internal) {
					/* one more "internal" */
					OSAddAtomic(+1, &pmap->stats.internal);
					PMAP_STATS_PEAK(pmap->stats.internal);
					assert(pmap->stats.internal > 0);
					if (is_altacct) {
						/* no impact on ledgers */
					} else {
						pmap_ledger_credit(pmap,
						    task_ledgers.internal,
						    PAGE_SIZE);
						pmap_ledger_credit(
							pmap,
							task_ledgers.phys_footprint,
							PAGE_SIZE);
					}
				} else {
					/* one more "external" */
					OSAddAtomic(+1, &pmap->stats.external);
					PMAP_STATS_PEAK(pmap->stats.external);
					assert(pmap->stats.external > 0);
				}
			} else if ((options & PMAP_OPTIONS_SET_REUSABLE) &&
			    !is_reusable &&
			    pmap != kernel_pmap) {
				/* one more "reusable" */
				OSAddAtomic(+1, &pmap->stats.reusable);
				PMAP_STATS_PEAK(pmap->stats.reusable);
				assert(pmap->stats.reusable > 0);
				if (is_internal) {
					/* one less "internal" */
					assert(pmap->stats.internal > 0);
					OSAddAtomic(-1, &pmap->stats.internal);
					if (is_altacct) {
						/* no impact on footprint */
					} else {
						pmap_ledger_debit(pmap,
						    task_ledgers.internal,
						    PAGE_SIZE);
						pmap_ledger_debit(
							pmap,
							task_ledgers.phys_footprint,
							PAGE_SIZE);
					}
				} else {
					/* one less "external" */
					assert(pmap->stats.external > 0);
					OSAddAtomic(-1, &pmap->stats.external);
				}
			}

			pv_e = (pv_hashed_entry_t)queue_next(&pv_e->qlink);
		} while (pv_e != (pv_hashed_entry_t)pv_h);
	}
	/* Opportunistic refmod collection, annulled
	 * if both REF and MOD are being cleared.
	 */

	pmap_phys_attributes[pai] |= attributes;

	if (ept_keep_global_mod) {
		/*
		 * If the hardware doesn't support AD bits for EPT PTEs and someone is
		 * requesting that we clear the modified bit for a phys page, we need
		 * to ensure that there are no EPT mappings for the page with the
		 * modified bit set. If there are, we cannot clear the global modified bit.
		 */
		bits &= ~PHYS_MODIFIED;
	}
	pmap_phys_attributes[pai] &= ~(bits);

	/* update this page's "reusable" status */
	if (options & PMAP_OPTIONS_CLEAR_REUSABLE) {
		pmap_phys_attributes[pai] &= ~PHYS_REUSABLE;
	} else if (options & PMAP_OPTIONS_SET_REUSABLE) {
		pmap_phys_attributes[pai] |= PHYS_REUSABLE;
	}

	UNLOCK_PVH(pai);

	PMAP_TRACE(PMAP_CODE(PMAP__ATTRIBUTE_CLEAR) | DBG_FUNC_END);
}

/*
 *	Check specified attribute bits.
 */
int
phys_attribute_test(
	ppnum_t         pn,
	int             bits)
{
	pv_rooted_entry_t       pv_h;
	pv_hashed_entry_t       pv_e;
	pt_entry_t              *pte;
	int                     pai;
	pmap_t                  pmap;
	int                     attributes = 0;
	boolean_t               is_ept;

	pmap_intr_assert();
	assert(pn != vm_page_fictitious_addr);
	assert((bits & ~(PHYS_MODIFIED | PHYS_REFERENCED)) == 0);
	if (pn == vm_page_guard_addr) {
		return 0;
	}

	pai = ppn_to_pai(pn);

	if (!IS_MANAGED_PAGE(pai)) {
		/*
		 *	Not a managed page.
		 */
		return 0;
	}

	/*
	 * Fast check...  if bits already collected
	 * no need to take any locks...
	 * if not set, we need to recheck after taking
	 * the lock in case they got pulled in while
	 * we were waiting for the lock
	 */
	if ((pmap_phys_attributes[pai] & bits) == bits) {
		return bits;
	}

	pv_h = pai_to_pvh(pai);

	LOCK_PVH(pai);

	attributes = pmap_phys_attributes[pai] & bits;


	/*
	 * Walk down PV list, checking the mappings until we
	 * reach the end or we've found the desired attributes.
	 */
	if (attributes != bits &&
	    pv_h->pmap != PMAP_NULL) {
		/*
		 * There are some mappings.
		 */
		pv_e = (pv_hashed_entry_t)pv_h;
		do {
			vm_map_offset_t va;

			pmap = pv_e->pmap;
			is_ept = is_ept_pmap(pmap);
			va = PVE_VA(pv_e);
			/*
			 * pick up modify and/or reference bits from mapping
			 */

			pte = pmap_pte(pmap, va);
			if (!is_ept) {
				attributes |= (int)(*pte & bits);
			} else {
				attributes |= (int)(ept_refmod_to_physmap((*pte & (INTEL_EPT_REF | INTEL_EPT_MOD))) & (PHYS_MODIFIED | PHYS_REFERENCED));
			}

			pv_e = (pv_hashed_entry_t)queue_next(&pv_e->qlink);
		} while ((attributes != bits) &&
		    (pv_e != (pv_hashed_entry_t)pv_h));
	}
	pmap_phys_attributes[pai] |= attributes;

	UNLOCK_PVH(pai);
	return attributes;
}

/*
 *	Routine:	pmap_change_wiring
 *	Function:	Change the wiring attribute for a map/virtual-address
 *			pair.
 *	In/out conditions:
 *			The mapping must already exist in the pmap.
 */
void
pmap_change_wiring(
	pmap_t          map,
	vm_map_offset_t vaddr,
	boolean_t       wired)
{
	pt_entry_t      *pte;

	PMAP_LOCK_SHARED(map);

	if ((pte = pmap_pte(map, vaddr)) == PT_ENTRY_NULL) {
		panic("pmap_change_wiring(%p,0x%llx,%d): pte missing",
		    map, vaddr, wired);
	}

	if (wired && !iswired(*pte)) {
		/*
		 * wiring down mapping
		 */
		pmap_ledger_credit(map, task_ledgers.wired_mem, PAGE_SIZE);
		OSAddAtomic(+1, &map->stats.wired_count);
		pmap_update_pte(pte, 0, PTE_WIRED);
	} else if (!wired && iswired(*pte)) {
		/*
		 * unwiring mapping
		 */
		assert(map->stats.wired_count >= 1);
		OSAddAtomic(-1, &map->stats.wired_count);
		pmap_ledger_debit(map, task_ledgers.wired_mem, PAGE_SIZE);
		pmap_update_pte(pte, PTE_WIRED, 0);
	}

	PMAP_UNLOCK_SHARED(map);
}

/*
 *	"Backdoor" direct map routine for early mappings.
 *      Useful for mapping memory outside the range
 *      Sets A, D and NC if requested
 */

vm_offset_t
pmap_map_bd(
	vm_offset_t     virt,
	vm_map_offset_t start_addr,
	vm_map_offset_t end_addr,
	vm_prot_t       prot,
	unsigned int    flags)
{
	pt_entry_t      template;
	pt_entry_t      *ptep;

	vm_offset_t     base = virt;
	boolean_t       doflush = FALSE;

	template = pa_to_pte(start_addr)
	    | INTEL_PTE_REF
	    | INTEL_PTE_MOD
	    | INTEL_PTE_WIRED
	    | INTEL_PTE_VALID;

	if ((flags & (VM_MEM_NOT_CACHEABLE | VM_WIMG_USE_DEFAULT)) == VM_MEM_NOT_CACHEABLE) {
		template |= INTEL_PTE_NCACHE;
		if (!(flags & (VM_MEM_GUARDED))) {
			template |= INTEL_PTE_PAT;
		}
	}

	if ((prot & VM_PROT_EXECUTE) == 0) {
		template |= INTEL_PTE_NX;
	}

	if (prot & VM_PROT_WRITE) {
		template |= INTEL_PTE_WRITE;
	}
	vm_map_offset_t caddr = start_addr;
	while (caddr < end_addr) {
		ptep = pmap_pte(kernel_pmap, (vm_map_offset_t)virt);
		if (ptep == PT_ENTRY_NULL) {
			panic("pmap_map_bd: Invalid kernel address");
		}
		if (pte_to_pa(*ptep)) {
			doflush = TRUE;
		}
		pmap_store_pte(ptep, template);
		pte_increment_pa(template);
		virt += PAGE_SIZE;
		caddr += PAGE_SIZE;
	}
	if (doflush) {
		pmap_tlbi_range(0, ~0ULL, true, 0);
		PMAP_UPDATE_TLBS(kernel_pmap, base, base + end_addr - start_addr);
	}
	return virt;
}

/* Create a virtual alias beginning at 'ava' of the specified kernel virtual
 * range. The aliased pagetable range is expanded if
 * PMAP_EXPAND_OPTIONS_ALIASMAP is specified. Performs no synchronization,
 * assumes caller has stabilized the source and destination ranges. Currently
 * used to populate sections of the trampoline "doublemap" at CPU startup.
 */

void
pmap_alias(
	vm_offset_t     ava,
	vm_map_offset_t start_addr,
	vm_map_offset_t end_addr,
	vm_prot_t       prot,
	unsigned int    eoptions)
{
	pt_entry_t      prot_template, template;
	pt_entry_t      *aptep, *sptep;

	prot_template =  INTEL_PTE_REF | INTEL_PTE_MOD | INTEL_PTE_WIRED | INTEL_PTE_VALID;
	if ((prot & VM_PROT_EXECUTE) == 0) {
		prot_template |= INTEL_PTE_NX;
	}

	if (prot & VM_PROT_WRITE) {
		prot_template |= INTEL_PTE_WRITE;
	}
	assert(((start_addr | end_addr) & PAGE_MASK) == 0);
	while (start_addr < end_addr) {
		aptep = pmap_pte(kernel_pmap, (vm_map_offset_t)ava);
		if (aptep == PT_ENTRY_NULL) {
			if (eoptions & PMAP_EXPAND_OPTIONS_ALIASMAP) {
				pmap_expand(kernel_pmap, ava, PMAP_EXPAND_OPTIONS_ALIASMAP);
				aptep = pmap_pte(kernel_pmap, (vm_map_offset_t)ava);
			} else {
				panic("pmap_alias: Invalid alias address");
			}
		}
		/* The aliased range should not have any active mappings */
		assert(pte_to_pa(*aptep) == 0);

		sptep = pmap_pte(kernel_pmap, start_addr);
		assert(sptep != PT_ENTRY_NULL && (pte_to_pa(*sptep) != 0));
		template = pa_to_pte(pte_to_pa(*sptep)) | prot_template;
		pmap_store_pte(aptep, template);

		ava += PAGE_SIZE;
		start_addr += PAGE_SIZE;
	}
}

mach_vm_size_t
pmap_query_resident(
	pmap_t          pmap,
	addr64_t        s64,
	addr64_t        e64,
	mach_vm_size_t  *compressed_bytes_p)
{
	pt_entry_t     *pde;
	pt_entry_t     *spte, *epte;
	addr64_t        l64;
	uint64_t        deadline = 0;
	mach_vm_size_t  resident_bytes;
	mach_vm_size_t  compressed_bytes;
	boolean_t       is_ept;

	pmap_intr_assert();

	if (pmap == PMAP_NULL || pmap == kernel_pmap || s64 == e64) {
		if (compressed_bytes_p) {
			*compressed_bytes_p = 0;
		}
		return 0;
	}

	is_ept = is_ept_pmap(pmap);

	PMAP_TRACE(PMAP_CODE(PMAP__QUERY_RESIDENT) | DBG_FUNC_START,
	    VM_KERNEL_ADDRHIDE(pmap), VM_KERNEL_ADDRHIDE(s64),
	    VM_KERNEL_ADDRHIDE(e64));

	resident_bytes = 0;
	compressed_bytes = 0;

	PMAP_LOCK_EXCLUSIVE(pmap);
	uint32_t traverse_count = 0;

	while (s64 < e64) {
		l64 = (s64 + PDE_MAPPED_SIZE) & ~(PDE_MAPPED_SIZE - 1);
		if (l64 > e64) {
			l64 = e64;
		}
		pde = pmap_pde(pmap, s64);

		if (pde && (*pde & PTE_VALID_MASK(is_ept))) {
			if (*pde & PTE_PS) {
				/* superpage: not supported */
			} else {
				spte = pmap_pte(pmap,
				    (s64 & ~(PDE_MAPPED_SIZE - 1)));
				spte = &spte[ptenum(s64)];
				epte = &spte[intel_btop(l64 - s64)];

				for (; spte < epte; spte++) {
					if (pte_to_pa(*spte) != 0) {
						resident_bytes += PAGE_SIZE;
					} else if (*spte & PTE_COMPRESSED) {
						compressed_bytes += PAGE_SIZE;
					}
				}
			}
		}
		s64 = l64;

		if ((s64 < e64) && (traverse_count++ > PLCHECK_THRESHOLD)) {
			if (deadline == 0) {
				deadline = rdtsc64() + max_preemption_latency_tsc;
			} else {
				if (rdtsc64() > deadline) {
					PMAP_UNLOCK_EXCLUSIVE(pmap);
					__builtin_ia32_pause();
					PMAP_LOCK_EXCLUSIVE(pmap);
					deadline = rdtsc64() + max_preemption_latency_tsc;
				}
			}
		}
	}

	PMAP_UNLOCK_EXCLUSIVE(pmap);

	PMAP_TRACE(PMAP_CODE(PMAP__QUERY_RESIDENT) | DBG_FUNC_END,
	    resident_bytes);

	if (compressed_bytes_p) {
		*compressed_bytes_p = compressed_bytes;
	}
	return resident_bytes;
}

kern_return_t
pmap_query_page_info(
	pmap_t          pmap,
	vm_map_offset_t va,
	int             *disp_p)
{
	int             disp;
	boolean_t       is_ept;
	pmap_paddr_t    pa;
	ppnum_t         pai;
	pd_entry_t      *pde;
	pt_entry_t      *pte;

	pmap_intr_assert();
	if (pmap == PMAP_NULL || pmap == kernel_pmap) {
		*disp_p = 0;
		return KERN_INVALID_ARGUMENT;
	}

	disp = 0;
	is_ept = is_ept_pmap(pmap);

	PMAP_LOCK_EXCLUSIVE(pmap);

	pde = pmap_pde(pmap, va);
	if (!pde ||
	    !(*pde & PTE_VALID_MASK(is_ept)) ||
	    (*pde & PTE_PS)) {
		goto done;
	}

	pte = pmap_pte(pmap, va);
	if (pte == PT_ENTRY_NULL) {
		goto done;
	}

	pa = pte_to_pa(*pte);
	if (pa == 0) {
		if (PTE_IS_COMPRESSED(*pte, pte, pmap, va)) {
			disp |= PMAP_QUERY_PAGE_COMPRESSED;
			if (*pte & PTE_COMPRESSED_ALT) {
				disp |= PMAP_QUERY_PAGE_COMPRESSED_ALTACCT;
			}
		}
	} else {
		disp |= PMAP_QUERY_PAGE_PRESENT;
		pai = pa_index(pa);
		if (!IS_MANAGED_PAGE(pai)) {
		} else if (pmap_pv_is_altacct(pmap, va, pai)) {
			assert(IS_INTERNAL_PAGE(pai));
			disp |= PMAP_QUERY_PAGE_INTERNAL;
			disp |= PMAP_QUERY_PAGE_ALTACCT;
		} else if (IS_REUSABLE_PAGE(pai)) {
			disp |= PMAP_QUERY_PAGE_REUSABLE;
		} else if (IS_INTERNAL_PAGE(pai)) {
			disp |= PMAP_QUERY_PAGE_INTERNAL;
		}
	}

done:
	PMAP_UNLOCK_EXCLUSIVE(pmap);
	*disp_p = disp;
	return KERN_SUCCESS;
}

void
pmap_set_vm_map_cs_enforced(
	pmap_t pmap,
	bool new_value)
{
	PMAP_LOCK_EXCLUSIVE(pmap);
	pmap->pm_vm_map_cs_enforced = new_value;
	PMAP_UNLOCK_EXCLUSIVE(pmap);
}
extern int cs_process_enforcement_enable;
bool
pmap_get_vm_map_cs_enforced(
	pmap_t pmap)
{
	if (cs_process_enforcement_enable) {
		return true;
	}
	return pmap->pm_vm_map_cs_enforced;
}

void
pmap_set_jit_entitled(__unused pmap_t pmap)
{
	/* The x86 pmap layer does not care if a map has a JIT entry. */
	return;
}

bool
pmap_get_jit_entitled(__unused pmap_t pmap)
{
	/* The x86 pmap layer does not care if a map is using JIT. */
	return false;
}

bool
pmap_has_prot_policy(__unused pmap_t pmap, __unused bool translated_allow_execute, __unused vm_prot_t prot)
{
	/*
	 * The x86 pmap layer does not apply any policy to any protection
	 * types.
	 */
	return false;
}

uint64_t
pmap_release_pages_fast(void)
{
	return 0;
}

void
pmap_trim(__unused pmap_t grand, __unused pmap_t subord, __unused addr64_t vstart, __unused uint64_t size)
{
	return;
}

__dead2
void
pmap_ledger_alloc_init(size_t size)
{
	panic("%s: unsupported, "
	    "size=%lu",
	    __func__, size);
}

__dead2
ledger_t
pmap_ledger_alloc(void)
{
	panic("%s: unsupported",
	    __func__);
}

__dead2
void
pmap_ledger_free(ledger_t ledger)
{
	panic("%s: unsupported, "
	    "ledger=%p",
	    __func__, ledger);
}

kern_return_t
pmap_dump_page_tables(pmap_t pmap __unused, void *bufp __unused, void *buf_end __unused,
    unsigned int level_mask __unused, size_t *bytes_copied __unused)
{
	return KERN_NOT_SUPPORTED;
}

void *
pmap_map_compressor_page(ppnum_t pn)
{
	assertf(IS_MANAGED_PAGE(ppn_to_pai(pn)), "%s called on non-managed page 0x%08x", __func__, pn);
	return PHYSMAP_PTOV((uint64_t)pn << (uint64_t)PAGE_SHIFT);
}

void
pmap_unmap_compressor_page(ppnum_t pn __unused, void *kva __unused)
{
}

bool
pmap_clear_refmod_range_options(
	pmap_t pmap __unused,
	vm_map_address_t start __unused,
	vm_map_address_t end __unused,
	unsigned int mask __unused,
	unsigned int options __unused)
{
	/*
	 * x86 doesn't have ranged tlbi instructions, and we already have
	 * the pmap_flush_context. This operation isn't implemented.
	 */
	return false;
}
