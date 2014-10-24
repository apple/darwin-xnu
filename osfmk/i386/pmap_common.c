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
#include <vm/pmap.h>
#include <kern/ledger.h>
#include <i386/pmap_internal.h>


/*
 *	Each entry in the pv_head_table is locked by a bit in the
 *	pv_lock_table.  The lock bits are accessed by the physical
 *	address of the page they lock.
 */

char	*pv_lock_table;		/* pointer to array of bits */
char    *pv_hash_lock_table;

pv_rooted_entry_t	pv_head_table;		/* array of entries, one per
						 * page */
uint32_t			pv_hashed_free_count = 0;
uint32_t			pv_hashed_kern_free_count = 0;

pmap_pagetable_corruption_record_t pmap_pagetable_corruption_records[PMAP_PAGETABLE_CORRUPTION_MAX_LOG];
uint32_t pmap_pagetable_corruption_incidents;
uint64_t pmap_pagetable_corruption_last_abstime = (~(0ULL) >> 1);
uint64_t pmap_pagetable_corruption_interval_abstime;
thread_call_t 	pmap_pagetable_corruption_log_call;
static thread_call_data_t 	pmap_pagetable_corruption_log_call_data;
boolean_t pmap_pagetable_corruption_timeout = FALSE;

volatile uint32_t	mappingrecurse = 0;

uint32_t  pv_hashed_low_water_mark, pv_hashed_kern_low_water_mark, pv_hashed_alloc_chunk, pv_hashed_kern_alloc_chunk;

thread_t mapping_replenish_thread;
event_t	mapping_replenish_event, pmap_user_pv_throttle_event;

uint64_t pmap_pv_throttle_stat, pmap_pv_throttled_waiters;

unsigned int pmap_cache_attributes(ppnum_t pn) {
	if (pmap_get_cache_attributes(pn) & INTEL_PTE_NCACHE)
	        return (VM_WIMG_IO);
	else
		return (VM_WIMG_COPYBACK);
}

void	pmap_set_cache_attributes(ppnum_t pn, unsigned int cacheattr) {
	unsigned int current, template = 0;
	int pai;

	if (cacheattr & VM_MEM_NOT_CACHEABLE) {
		if(!(cacheattr & VM_MEM_GUARDED))
			template |= PHYS_PTA;
		template |= PHYS_NCACHE;
	}

	pmap_intr_assert();

	assert((pn != vm_page_fictitious_addr) && (pn != vm_page_guard_addr));

	pai = ppn_to_pai(pn);

	if (!IS_MANAGED_PAGE(pai)) {
		return;
	}

	/* override cache attributes for this phys page
	 * Does not walk through existing mappings to adjust,
	 * assumes page is disconnected
	 */

	LOCK_PVH(pai);

	pmap_update_cache_attributes_locked(pn, template);

	current = pmap_phys_attributes[pai] & PHYS_CACHEABILITY_MASK;
	pmap_phys_attributes[pai] &= ~PHYS_CACHEABILITY_MASK;
	pmap_phys_attributes[pai] |= template;

	UNLOCK_PVH(pai);

	if ((template & PHYS_NCACHE) && !(current & PHYS_NCACHE)) {
		pmap_sync_page_attributes_phys(pn);
	}
}

unsigned	pmap_get_cache_attributes(ppnum_t pn) {
	if (last_managed_page == 0)
		return 0;

	if (!IS_MANAGED_PAGE(ppn_to_pai(pn))) {
	    return INTEL_PTE_NCACHE;
	}

	/*
	 * The cache attributes are read locklessly for efficiency.
	 */
	unsigned int attr = pmap_phys_attributes[ppn_to_pai(pn)];
	unsigned int template = 0;
	
	if (attr & PHYS_PTA)
		template |= INTEL_PTE_PTA;
	if (attr & PHYS_NCACHE)
		template |= INTEL_PTE_NCACHE;
	return template;
}



boolean_t
pmap_is_noencrypt(ppnum_t pn)
{
	int		pai;

	pai = ppn_to_pai(pn);

	if (!IS_MANAGED_PAGE(pai))
		return (FALSE);

	if (pmap_phys_attributes[pai] & PHYS_NOENCRYPT)
		return (TRUE);

	return (FALSE);
}


void
pmap_set_noencrypt(ppnum_t pn)
{
	int		pai;

	pai = ppn_to_pai(pn);

	if (IS_MANAGED_PAGE(pai)) {
		LOCK_PVH(pai);

		pmap_phys_attributes[pai] |= PHYS_NOENCRYPT;

		UNLOCK_PVH(pai);
	}
}


void
pmap_clear_noencrypt(ppnum_t pn)
{
	int		pai;

	pai = ppn_to_pai(pn);

	if (IS_MANAGED_PAGE(pai)) {
		/*
		 * synchronization at VM layer prevents PHYS_NOENCRYPT
		 * from changing state, so we don't need the lock to inspect
		 */
		if (pmap_phys_attributes[pai] & PHYS_NOENCRYPT) {
			LOCK_PVH(pai);

			pmap_phys_attributes[pai] &= ~PHYS_NOENCRYPT;

			UNLOCK_PVH(pai);
		}
	}
}

void
compute_pmap_gc_throttle(void *arg __unused)
{
	
}


void
pmap_lock_phys_page(ppnum_t pn)
{
	int		pai;

	pai = ppn_to_pai(pn);

	if (IS_MANAGED_PAGE(pai)) {
		LOCK_PVH(pai);
	} else
		simple_lock(&phys_backup_lock);
}


void
pmap_unlock_phys_page(ppnum_t pn)
{
	int		pai;

	pai = ppn_to_pai(pn);

	if (IS_MANAGED_PAGE(pai)) {
		UNLOCK_PVH(pai);
	} else
		simple_unlock(&phys_backup_lock);
}



__private_extern__ void
pmap_pagetable_corruption_msg_log(int (*log_func)(const char * fmt, ...)__printflike(1,2)) {
	if (pmap_pagetable_corruption_incidents > 0) {
		int i, e = MIN(pmap_pagetable_corruption_incidents, PMAP_PAGETABLE_CORRUPTION_MAX_LOG);
		(*log_func)("%u pagetable corruption incident(s) detected, timeout: %u\n", pmap_pagetable_corruption_incidents, pmap_pagetable_corruption_timeout);
		for (i = 0; i < e; i++) {
			(*log_func)("Incident 0x%x, reason: 0x%x, action: 0x%x, time: 0x%llx\n", pmap_pagetable_corruption_records[i].incident,  pmap_pagetable_corruption_records[i].reason, pmap_pagetable_corruption_records[i].action, pmap_pagetable_corruption_records[i].abstime);
		}
	}
}

static inline void
pmap_pagetable_corruption_log_setup(void) {
	if (pmap_pagetable_corruption_log_call == NULL) {
		nanotime_to_absolutetime(PMAP_PAGETABLE_CORRUPTION_INTERVAL, 0, &pmap_pagetable_corruption_interval_abstime);
		thread_call_setup(&pmap_pagetable_corruption_log_call_data,
		    (thread_call_func_t) pmap_pagetable_corruption_msg_log,
		    (thread_call_param_t) &printf);
		pmap_pagetable_corruption_log_call = &pmap_pagetable_corruption_log_call_data;
	}
}

void
mapping_free_prime(void)
{
	unsigned		i;
	pv_hashed_entry_t	pvh_e;
	pv_hashed_entry_t	pvh_eh;
	pv_hashed_entry_t	pvh_et;
	int			pv_cnt;

	/* Scale based on DRAM size */
	pv_hashed_low_water_mark = MAX(PV_HASHED_LOW_WATER_MARK_DEFAULT, ((uint32_t)(sane_size >> 30)) * 2000);
	pv_hashed_low_water_mark = MIN(pv_hashed_low_water_mark, 16000);
	/* Alterable via sysctl */
	pv_hashed_kern_low_water_mark = MAX(PV_HASHED_KERN_LOW_WATER_MARK_DEFAULT, ((uint32_t)(sane_size >> 30)) * 1000);
	pv_hashed_kern_low_water_mark = MIN(pv_hashed_kern_low_water_mark, 16000);
	pv_hashed_kern_alloc_chunk = PV_HASHED_KERN_ALLOC_CHUNK_INITIAL;
	pv_hashed_alloc_chunk = PV_HASHED_ALLOC_CHUNK_INITIAL;

	pv_cnt = 0;
	pvh_eh = pvh_et = PV_HASHED_ENTRY_NULL;

	for (i = 0; i < (5 * PV_HASHED_ALLOC_CHUNK_INITIAL); i++) {
		pvh_e = (pv_hashed_entry_t) zalloc(pv_hashed_list_zone);

		pvh_e->qlink.next = (queue_entry_t)pvh_eh;
		pvh_eh = pvh_e;

		if (pvh_et == PV_HASHED_ENTRY_NULL)
		        pvh_et = pvh_e;
		pv_cnt++;
	}
	PV_HASHED_FREE_LIST(pvh_eh, pvh_et, pv_cnt);

	pv_cnt = 0;
	pvh_eh = pvh_et = PV_HASHED_ENTRY_NULL;
	for (i = 0; i < PV_HASHED_KERN_ALLOC_CHUNK_INITIAL; i++) {
		pvh_e = (pv_hashed_entry_t) zalloc(pv_hashed_list_zone);

		pvh_e->qlink.next = (queue_entry_t)pvh_eh;
		pvh_eh = pvh_e;

		if (pvh_et == PV_HASHED_ENTRY_NULL)
		        pvh_et = pvh_e;
		pv_cnt++;
	}
	PV_HASHED_KERN_FREE_LIST(pvh_eh, pvh_et, pv_cnt);
}

void mapping_replenish(void);

void mapping_adjust(void) {
	kern_return_t mres;

	pmap_pagetable_corruption_log_setup();

	mres = kernel_thread_start_priority((thread_continue_t)mapping_replenish, NULL, MAXPRI_KERNEL, &mapping_replenish_thread);
	if (mres != KERN_SUCCESS) {
		panic("pmap: mapping_replenish_thread creation failed");
	}
	thread_deallocate(mapping_replenish_thread);
}

unsigned pmap_mapping_thread_wakeups;	
unsigned pmap_kernel_reserve_replenish_stat;
unsigned pmap_user_reserve_replenish_stat;
unsigned pmap_kern_reserve_alloc_stat;

void mapping_replenish(void)
{
	pv_hashed_entry_t	pvh_e;
	pv_hashed_entry_t	pvh_eh;
	pv_hashed_entry_t	pvh_et;
	int			pv_cnt;
	unsigned             	i;

	/* We qualify for VM privileges...*/
	current_thread()->options |= TH_OPT_VMPRIV;

	for (;;) {

		while (pv_hashed_kern_free_count < pv_hashed_kern_low_water_mark) {
			pv_cnt = 0;
			pvh_eh = pvh_et = PV_HASHED_ENTRY_NULL;

			for (i = 0; i < pv_hashed_kern_alloc_chunk; i++) {
				pvh_e = (pv_hashed_entry_t) zalloc(pv_hashed_list_zone);
				pvh_e->qlink.next = (queue_entry_t)pvh_eh;
				pvh_eh = pvh_e;

				if (pvh_et == PV_HASHED_ENTRY_NULL)
					pvh_et = pvh_e;
				pv_cnt++;
			}
			pmap_kernel_reserve_replenish_stat += pv_cnt;
			PV_HASHED_KERN_FREE_LIST(pvh_eh, pvh_et, pv_cnt);
		}

		pv_cnt = 0;
		pvh_eh = pvh_et = PV_HASHED_ENTRY_NULL;

		if (pv_hashed_free_count < pv_hashed_low_water_mark) {
			for (i = 0; i < pv_hashed_alloc_chunk; i++) {
				pvh_e = (pv_hashed_entry_t) zalloc(pv_hashed_list_zone);

				pvh_e->qlink.next = (queue_entry_t)pvh_eh;
				pvh_eh = pvh_e;

				if (pvh_et == PV_HASHED_ENTRY_NULL)
					pvh_et = pvh_e;
				pv_cnt++;
			}
			pmap_user_reserve_replenish_stat += pv_cnt;
			PV_HASHED_FREE_LIST(pvh_eh, pvh_et, pv_cnt);
		}
/* Wake threads throttled while the kernel reserve was being replenished.
 */
		if (pmap_pv_throttled_waiters) {
			pmap_pv_throttled_waiters = 0;
			thread_wakeup(&pmap_user_pv_throttle_event);
		}
		/* Check if the kernel pool has been depleted since the
		 * first pass, to reduce refill latency.
		 */
		if (pv_hashed_kern_free_count < pv_hashed_kern_low_water_mark)
			continue;
		/* Block sans continuation to avoid yielding kernel stack */
		assert_wait(&mapping_replenish_event, THREAD_UNINT);
		mappingrecurse = 0;
		thread_block(THREAD_CONTINUE_NULL);
		pmap_mapping_thread_wakeups++;
	}
}

/*
 *	Set specified attribute bits.
 */

void
phys_attribute_set(
	ppnum_t		pn,
	int		bits)
{
	int		pai;

	pmap_intr_assert();
	assert(pn != vm_page_fictitious_addr);
	if (pn == vm_page_guard_addr)
		return;

	pai = ppn_to_pai(pn);

	if (!IS_MANAGED_PAGE(pai)) {
		/* Not a managed page.  */
		return;
	}

	LOCK_PVH(pai);
	pmap_phys_attributes[pai] |= bits;
	UNLOCK_PVH(pai);
}

/*
 *	Set the modify bit on the specified physical page.
 */

void
pmap_set_modify(ppnum_t pn)
{
	phys_attribute_set(pn, PHYS_MODIFIED);
}

/*
 *	Clear the modify bits on the specified physical page.
 */

void
pmap_clear_modify(ppnum_t pn)
{
	phys_attribute_clear(pn, PHYS_MODIFIED, 0, NULL);
}

/*
 *	pmap_is_modified:
 *
 *	Return whether or not the specified physical page is modified
 *	by any physical maps.
 */

boolean_t
pmap_is_modified(ppnum_t pn)
{
	if (phys_attribute_test(pn, PHYS_MODIFIED))
		return TRUE;
	return FALSE;
}


/*
 *	pmap_clear_reference:
 *
 *	Clear the reference bit on the specified physical page.
 */

void
pmap_clear_reference(ppnum_t pn)
{
	phys_attribute_clear(pn, PHYS_REFERENCED, 0, NULL);
}

void
pmap_set_reference(ppnum_t pn)
{
	phys_attribute_set(pn, PHYS_REFERENCED);
}

/*
 *	pmap_is_referenced:
 *
 *	Return whether or not the specified physical page is referenced
 *	by any physical maps.
 */

boolean_t
pmap_is_referenced(ppnum_t pn)
{
        if (phys_attribute_test(pn, PHYS_REFERENCED))
		return TRUE;
	return FALSE;
}


/*
 * pmap_get_refmod(phys)
 *  returns the referenced and modified bits of the specified
 *  physical page.
 */
unsigned int
pmap_get_refmod(ppnum_t pn)
{
        int		refmod;
	unsigned int	retval = 0;

	refmod = phys_attribute_test(pn, PHYS_MODIFIED | PHYS_REFERENCED);

	if (refmod & PHYS_MODIFIED)
	        retval |= VM_MEM_MODIFIED;
	if (refmod & PHYS_REFERENCED)
	        retval |= VM_MEM_REFERENCED;

	return (retval);
}


void
pmap_clear_refmod_options(ppnum_t pn, unsigned int mask, unsigned int options, void *arg)
{
        unsigned int  x86Mask;

        x86Mask = (   ((mask &   VM_MEM_MODIFIED)?   PHYS_MODIFIED : 0)
		      | ((mask & VM_MEM_REFERENCED)? PHYS_REFERENCED : 0));

        phys_attribute_clear(pn, x86Mask, options, arg);
}

/*
 * pmap_clear_refmod(phys, mask)
 *  clears the referenced and modified bits as specified by the mask
 *  of the specified physical page.
 */
void
pmap_clear_refmod(ppnum_t pn, unsigned int mask)
{
	unsigned int  x86Mask;

	x86Mask = (   ((mask &   VM_MEM_MODIFIED)?   PHYS_MODIFIED : 0)
	            | ((mask & VM_MEM_REFERENCED)? PHYS_REFERENCED : 0));

	phys_attribute_clear(pn, x86Mask, 0, NULL);
}

unsigned int
pmap_disconnect(ppnum_t pa)
{
	return (pmap_disconnect_options(pa, 0, NULL));
}

/*
 *	Routine:
 *		pmap_disconnect_options
 *
 *	Function:
 *		Disconnect all mappings for this page and return reference and change status
 *		in generic format.
 *
 */
unsigned int
pmap_disconnect_options(ppnum_t pa, unsigned int options, void *arg)
{
	unsigned refmod, vmrefmod = 0;

	pmap_page_protect_options(pa, 0, options, arg);		/* disconnect the page */

	pmap_assert(pa != vm_page_fictitious_addr);
	if ((pa == vm_page_guard_addr) || !IS_MANAGED_PAGE(pa) || (options & PMAP_OPTIONS_NOREFMOD))
		return 0;
	refmod = pmap_phys_attributes[pa] & (PHYS_MODIFIED | PHYS_REFERENCED);
	
	if (refmod & PHYS_MODIFIED)
	        vmrefmod |= VM_MEM_MODIFIED;
	if (refmod & PHYS_REFERENCED)
	        vmrefmod |= VM_MEM_REFERENCED;

	return vmrefmod;
}
