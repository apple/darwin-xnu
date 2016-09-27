/*
 * Copyright (c) 2000-2010 Apple Inc. All rights reserved.
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

#include <i386/proc_reg.h>
#include <i386/cpuid.h>
#include <i386/tsc.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <i386/pmap_internal.h>
#include <i386/pmap_pcid.h>
#include <mach/branch_predicates.h>

/*
 * PCID (Process context identifier) aka tagged TLB support.
 * On processors with this feature, unless disabled via the -pmap_pcid_disable
 * boot-arg, the following algorithm is in effect:
 * Each processor maintains an array of tag refcounts indexed by tag.
 * Each address space maintains an array of tags indexed by CPU number.
 * Each address space maintains a coherency vector, indexed by CPU
 * indicating that the TLB state for that address space has a pending
 * invalidation.
 * On a context switch, a refcounted tag is lazily assigned to the newly
 * dispatched (CPU, address space) tuple.
 * When an inactive address space is invalidated on a remote CPU, it is marked
 * for invalidation upon the next dispatch. Some invalidations are
 * also processed at the user/kernel boundary.
 * Provisions are made for the case where a CPU is overcommmitted, i.e.
 * more active address spaces exist than the number of logical tags
 * provided for by the processor architecture (currently 4096).
 * The algorithm assumes the processor remaps the logical tags
 * to physical TLB context IDs in an LRU fashion for efficiency. (DRK '10)
 */

uint32_t	pmap_pcid_ncpus;
boolean_t 	pmap_pcid_disabled = FALSE;

void	pmap_pcid_configure(void) {
	int ccpu = cpu_number();
	uintptr_t cr4 = get_cr4();
	boolean_t pcid_present = FALSE;

	pmap_pcid_log("PCID configure invoked on CPU %d\n", ccpu);
	pmap_assert(ml_get_interrupts_enabled() == FALSE || get_preemption_level() !=0);
	pmap_assert(cpu_mode_is64bit());

	if (PE_parse_boot_argn("-pmap_pcid_disable", &pmap_pcid_disabled, sizeof (pmap_pcid_disabled))) {
		pmap_pcid_log("PMAP: PCID feature disabled\n");
		printf("PMAP: PCID feature disabled, %u\n", pmap_pcid_disabled);
		kprintf("PMAP: PCID feature disabled %u\n", pmap_pcid_disabled);
	}
	 /* no_shared_cr3+PCID is currently unsupported */
#if	DEBUG
	if (pmap_pcid_disabled == FALSE)
		no_shared_cr3 = FALSE;
	else
		no_shared_cr3 = TRUE;
#else
	if (no_shared_cr3)
		pmap_pcid_disabled = TRUE;
#endif
	if (pmap_pcid_disabled || no_shared_cr3) {
		unsigned i;
		/* Reset PCID status, as we may have picked up
		 * strays if discovered prior to platform
		 * expert initialization.
		 */
		for (i = 0; i < real_ncpus; i++) {
			if (cpu_datap(i)) {
				cpu_datap(i)->cpu_pmap_pcid_enabled = FALSE;
			}
			pmap_pcid_ncpus = 0;
		}
		cpu_datap(ccpu)->cpu_pmap_pcid_enabled = FALSE;
		return;
	}
	/* DRKTODO: assert if features haven't been discovered yet. Redundant
	 * invocation of cpu_mode_init and descendants masks this for now.
	 */
	if ((cpuid_features() & CPUID_FEATURE_PCID))
		pcid_present = TRUE;
	else {
		cpu_datap(ccpu)->cpu_pmap_pcid_enabled = FALSE;
		pmap_pcid_log("PMAP: PCID not detected CPU %d\n", ccpu);
		return;
	}
	if ((cr4 & (CR4_PCIDE | CR4_PGE)) == (CR4_PCIDE|CR4_PGE)) {
		cpu_datap(ccpu)->cpu_pmap_pcid_enabled = TRUE;
		pmap_pcid_log("PMAP: PCID already enabled %d\n", ccpu);
		return;
	}
	if (pcid_present == TRUE) {
		pmap_pcid_log("Pre-PCID:CR0: 0x%lx, CR3: 0x%lx, CR4(CPU %d): 0x%lx\n", get_cr0(), get_cr3_raw(), ccpu, cr4);

		if (cpu_number() >= PMAP_PCID_MAX_CPUS) {
			panic("PMAP_PCID_MAX_CPUS %d\n", cpu_number());
		}
		if ((get_cr4() & CR4_PGE) == 0) {
			set_cr4(get_cr4() | CR4_PGE);
			pmap_pcid_log("Toggled PGE ON (CPU: %d\n", ccpu);
		}
		set_cr4(get_cr4() | CR4_PCIDE);
		pmap_pcid_log("Post PCID: CR0: 0x%lx, CR3: 0x%lx, CR4(CPU %d): 0x%lx\n", get_cr0(), get_cr3_raw(), ccpu, get_cr4());
		tlb_flush_global();
		cpu_datap(ccpu)->cpu_pmap_pcid_enabled = TRUE;

		if (OSIncrementAtomic(&pmap_pcid_ncpus) == machine_info.max_cpus) {
			pmap_pcid_log("All PCIDs enabled: real_ncpus: %d, pmap_pcid_ncpus: %d\n", real_ncpus, pmap_pcid_ncpus);
		}
		cpu_datap(ccpu)->cpu_pmap_pcid_coherentp =
		    cpu_datap(ccpu)->cpu_pmap_pcid_coherentp_kernel =
		    &(kernel_pmap->pmap_pcid_coherency_vector[ccpu]);
		cpu_datap(ccpu)->cpu_pcid_refcounts[0] = 1;
	}
}

void pmap_pcid_initialize(pmap_t p) {
	unsigned i;
	unsigned nc = sizeof(p->pmap_pcid_cpus)/sizeof(pcid_t);

	pmap_assert(nc >= real_ncpus);
	for (i = 0; i < nc; i++) {
		p->pmap_pcid_cpus[i] = PMAP_PCID_INVALID_PCID;
		/* We assume here that the coherency vector is zeroed by
		 * pmap_create
		 */
	}
}

void pmap_pcid_initialize_kernel(pmap_t p) {
	unsigned i;
	unsigned nc = sizeof(p->pmap_pcid_cpus)/sizeof(pcid_t);

	for (i = 0; i < nc; i++) {
		p->pmap_pcid_cpus[i] = 0;
		/* We assume here that the coherency vector is zeroed by
		 * pmap_create
		 */
	}
}

pcid_t	pmap_pcid_allocate_pcid(int ccpu) {
	int i;
	pcid_ref_t 	cur_min = 0xFF;
	uint32_t	cur_min_index = ~1;
	pcid_ref_t	*cpu_pcid_refcounts = &cpu_datap(ccpu)->cpu_pcid_refcounts[0];
	pcid_ref_t	old_count;

	if ((i = cpu_datap(ccpu)->cpu_pcid_free_hint) != 0) {
		if (cpu_pcid_refcounts[i] == 0) {
			(void)__sync_fetch_and_add(&cpu_pcid_refcounts[i], 1);
			cpu_datap(ccpu)->cpu_pcid_free_hint = 0;
			return i;
		}
	}
	/* Linear scan to discover free slot, with hint. Room for optimization
	 * but with intelligent prefetchers this should be
	 * adequately performant, as it is invoked
	 * only on first dispatch of a new address space onto
	 * a given processor. DRKTODO: use larger loads and
	 * zero byte discovery -- any pattern != ~1 should
	 * signify a free slot.
	 */
	for (i = PMAP_PCID_MIN_PCID; i < PMAP_PCID_MAX_PCID; i++) {
		pcid_ref_t cur_refcount = cpu_pcid_refcounts[i];

		pmap_assert(cur_refcount < PMAP_PCID_MAX_REFCOUNT);

		if (cur_refcount == 0) {
			(void)__sync_fetch_and_add(&cpu_pcid_refcounts[i], 1);
			return i;
		}
		else {
			if (cur_refcount < cur_min) {
				cur_min_index = i;
				cur_min = cur_refcount;
			}
		}
	}
	pmap_assert(cur_min_index > 0 && cur_min_index < PMAP_PCID_MAX_PCID);
	/* Consider "rebalancing" tags actively in highly oversubscribed cases
	 * perhaps selecting tags with lower activity.
	 */

	old_count = __sync_fetch_and_add(&cpu_pcid_refcounts[cur_min_index], 1);
	pmap_assert(old_count < PMAP_PCID_MAX_REFCOUNT);
	return cur_min_index;
}

void	pmap_pcid_deallocate_pcid(int ccpu, pmap_t tpmap) {
	pcid_t pcid;
	pmap_t lp;
	pcid_ref_t prior_count;

	pcid = tpmap->pmap_pcid_cpus[ccpu];
	pmap_assert(pcid != PMAP_PCID_INVALID_PCID);
	if (pcid == PMAP_PCID_INVALID_PCID)
		return;

	lp = cpu_datap(ccpu)->cpu_pcid_last_pmap_dispatched[pcid];
	pmap_assert(pcid > 0 && pcid < PMAP_PCID_MAX_PCID);
	pmap_assert(cpu_datap(ccpu)->cpu_pcid_refcounts[pcid] >= 1);

	if (lp == tpmap)
		(void)__sync_bool_compare_and_swap(&cpu_datap(ccpu)->cpu_pcid_last_pmap_dispatched[pcid], tpmap, PMAP_INVALID);

	if ((prior_count = __sync_fetch_and_sub(&cpu_datap(ccpu)->cpu_pcid_refcounts[pcid], 1)) == 1) {
		    cpu_datap(ccpu)->cpu_pcid_free_hint = pcid;
	}
	pmap_assert(prior_count <= PMAP_PCID_MAX_REFCOUNT);
}

void	pmap_destroy_pcid_sync(pmap_t p) {
	int i;
	pmap_assert(ml_get_interrupts_enabled() == FALSE || get_preemption_level() !=0);
	for (i = 0; i < PMAP_PCID_MAX_CPUS; i++)
		if (p->pmap_pcid_cpus[i] != PMAP_PCID_INVALID_PCID)
			pmap_pcid_deallocate_pcid(i, p);
}

pcid_t	pcid_for_pmap_cpu_tuple(pmap_t cpmap, thread_t cthread, int ccpu) {
	pmap_t active_pmap = cpmap;

	if (__improbable(cpmap->pagezero_accessible)) {
		if ((cthread->machine.specFlags & CopyIOActive) == 0) {
			active_pmap = kernel_pmap;
		}
	}

	return active_pmap->pmap_pcid_cpus[ccpu];
}

#if PMAP_ASSERT
#define PCID_RECORD_SIZE 128
uint64_t pcid_record_array[PCID_RECORD_SIZE];
#endif

void	pmap_pcid_activate(pmap_t tpmap, int ccpu, boolean_t nopagezero, boolean_t copyio) {
	pcid_t		new_pcid = tpmap->pmap_pcid_cpus[ccpu];
	pmap_t		last_pmap;
	boolean_t	pcid_conflict = FALSE, pending_flush = FALSE;

	pmap_assert(cpu_datap(ccpu)->cpu_pmap_pcid_enabled);
	if (__improbable(new_pcid == PMAP_PCID_INVALID_PCID)) {
		new_pcid = tpmap->pmap_pcid_cpus[ccpu] = pmap_pcid_allocate_pcid(ccpu);
	}

	pmap_assert(new_pcid != PMAP_PCID_INVALID_PCID);
#ifdef	PCID_ASSERT
	cpu_datap(ccpu)->cpu_last_pcid = cpu_datap(ccpu)->cpu_active_pcid;
#endif
	cpu_datap(ccpu)->cpu_active_pcid = new_pcid;

	pending_flush = (tpmap->pmap_pcid_coherency_vector[ccpu] != 0);
	if (__probable(pending_flush == FALSE)) {
		last_pmap = cpu_datap(ccpu)->cpu_pcid_last_pmap_dispatched[new_pcid];
		pcid_conflict = ((last_pmap != NULL) && (tpmap != last_pmap));
	}
	if (__improbable(pending_flush || pcid_conflict)) {
		pmap_pcid_validate_cpu(tpmap, ccpu);
	}
	/* Consider making this a unique id */
	cpu_datap(ccpu)->cpu_pcid_last_pmap_dispatched[new_pcid] = tpmap;

	pmap_assert(new_pcid < PMAP_PCID_MAX_PCID);
	pmap_assert(((tpmap ==  kernel_pmap) && new_pcid == 0) ||
	    ((new_pcid != PMAP_PCID_INVALID_PCID) && (new_pcid != 0)));
#if	PMAP_ASSERT
	pcid_record_array[ccpu % PCID_RECORD_SIZE] = tpmap->pm_cr3 | new_pcid | (((uint64_t)(!(pending_flush || pcid_conflict))) <<63);
	pml4_entry_t *pml4 = pmap64_pml4(tpmap, 0ULL);
	/* Diagnostic to detect pagetable anchor corruption */
	if (pml4[KERNEL_PML4_INDEX] != kernel_pmap->pm_pml4[KERNEL_PML4_INDEX])
		__asm__ volatile("int3");
#endif	/* PMAP_ASSERT */

	pmap_paddr_t ncr3 = tpmap->pm_cr3;

	if (__improbable(nopagezero)) {
		pending_flush = TRUE;
		if (copyio == FALSE) {
			new_pcid = kernel_pmap->pmap_pcid_cpus[ccpu];
			ncr3 = kernel_pmap->pm_cr3;
		}
		cpu_datap(ccpu)->cpu_kernel_pcid = kernel_pmap->pmap_pcid_cpus[ccpu];
	}

	set_cr3_composed(ncr3, new_pcid, !(pending_flush || pcid_conflict));

	if (!pending_flush) {
		/* We did not previously observe a pending invalidation for this
		 * ASID. However, the load from the coherency vector
		 * could've been reordered ahead of the store to the
		 * active_cr3 field (in the context switch path, our
		 * caller). Re-consult the pending invalidation vector
		 * after the CR3 write. We rely on MOV CR3's documented
		 * serializing property to avoid insertion of an expensive
		 * barrier. (DRK)
		 */
		pending_flush = (tpmap->pmap_pcid_coherency_vector[ccpu] != 0);
		if (__improbable(pending_flush != 0)) {
			pmap_pcid_validate_cpu(tpmap, ccpu);
			set_cr3_composed(ncr3, new_pcid, FALSE);
		}
	}
	cpu_datap(ccpu)->cpu_pmap_pcid_coherentp = &(tpmap->pmap_pcid_coherency_vector[ccpu]);
#if	DEBUG	
	KERNEL_DEBUG_CONSTANT(0x9c1d0000, tpmap, new_pcid, pending_flush, pcid_conflict, 0);
#endif
}
