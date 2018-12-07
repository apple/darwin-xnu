/*
 * Copyright (c) 2018 Apple Computer, Inc. All rights reserved.
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

#include <sys/errno.h>

#include <mach/mach_types.h>
#include <mach/mach_traps.h>
#include <mach/host_priv.h>
#include <mach/kern_return.h>
#include <mach/memory_object_control.h>
#include <mach/memory_object_types.h>
#include <mach/port.h>
#include <mach/policy.h>
#include <mach/upl.h>
#include <mach/thread_act.h>
#include <mach/mach_vm.h>

#include <kern/host.h>
#include <kern/kalloc.h>
#include <kern/queue.h>
#include <kern/thread.h>
#include <kern/ipc_kobject.h>

#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>

#include <vm/memory_object.h>
#include <vm/vm_kern.h>
#include <vm/vm_fault.h>
#include <vm/vm_map.h>
#include <vm/vm_pageout.h>
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>
#include <vm/vm_shared_region.h>


/*
 * SHARED REGION MEMORY PAGER
 *
 * This external memory manager (EMM) handles mappings of a dyld shared cache
 * in shared regions, applying any necessary modifications (sliding,
 * pointer signing, ...).
 *
 * It mostly handles page-in requests (from memory_object_data_request()) by
 * getting the original data from its backing VM object, itself backed by
 * the dyld shared cache file, modifying it if needed and providing it to VM.
 *
 * The modified pages will never be dirtied, so the memory manager doesn't
 * need to handle page-out requests (from memory_object_data_return()).  The
 * pages need to be mapped copy-on-write, so that the originals stay clean.
 *
 * We don't expect to have to handle a large number of shared cache files,
 * so the data structures are very simple (simple linked list) for now.
 */

/* forward declarations */
void shared_region_pager_reference(memory_object_t mem_obj);
void shared_region_pager_deallocate(memory_object_t mem_obj);
kern_return_t shared_region_pager_init(memory_object_t mem_obj,
				       memory_object_control_t control,
				       memory_object_cluster_size_t pg_size);
kern_return_t shared_region_pager_terminate(memory_object_t mem_obj);
kern_return_t shared_region_pager_data_request(memory_object_t mem_obj,
					       memory_object_offset_t offset,
					       memory_object_cluster_size_t length,
					       vm_prot_t protection_required,
					       memory_object_fault_info_t fault_info);
kern_return_t shared_region_pager_data_return(memory_object_t mem_obj,
					      memory_object_offset_t offset,
					      memory_object_cluster_size_t	data_cnt,
					      memory_object_offset_t *resid_offset,
					      int *io_error,
					      boolean_t dirty,
					      boolean_t kernel_copy,
					      int upl_flags);
kern_return_t shared_region_pager_data_initialize(memory_object_t mem_obj,
						  memory_object_offset_t offset,
						  memory_object_cluster_size_t data_cnt);
kern_return_t shared_region_pager_data_unlock(memory_object_t mem_obj,
					      memory_object_offset_t offset,
					      memory_object_size_t size,
					      vm_prot_t desired_access);
kern_return_t shared_region_pager_synchronize(memory_object_t mem_obj,
					      memory_object_offset_t offset,
					      memory_object_size_t length,
					      vm_sync_t sync_flags);
kern_return_t shared_region_pager_map(memory_object_t mem_obj,
				      vm_prot_t prot);
kern_return_t shared_region_pager_last_unmap(memory_object_t mem_obj);

/*
 * Vector of VM operations for this EMM.
 * These routines are invoked by VM via the memory_object_*() interfaces.
 */
const struct memory_object_pager_ops shared_region_pager_ops = {
	shared_region_pager_reference,
	shared_region_pager_deallocate,
	shared_region_pager_init,
	shared_region_pager_terminate,
	shared_region_pager_data_request,
	shared_region_pager_data_return,
	shared_region_pager_data_initialize,
	shared_region_pager_data_unlock,
	shared_region_pager_synchronize,
	shared_region_pager_map,
	shared_region_pager_last_unmap,
	NULL, /* data_reclaim */
	"shared_region"
};

/*
 * The "shared_region_pager" describes a memory object backed by
 * the "shared_region" EMM.
 */
typedef struct shared_region_pager {
	/* mandatory generic header */
	struct memory_object sc_pgr_hdr;

	/* pager-specific data */
	queue_chain_t		pager_queue;	/* next & prev pagers */
	unsigned int		ref_count;	/* reference count */
	boolean_t		is_ready;	/* is this pager ready ? */
	boolean_t		is_mapped;	/* is this mem_obj mapped ? */
	vm_object_t		backing_object; /* VM obj for shared cache */
	vm_object_offset_t	backing_offset;
	struct vm_shared_region_slide_info *scp_slide_info;
} *shared_region_pager_t;
#define	SHARED_REGION_PAGER_NULL	((shared_region_pager_t) NULL)

/*
 * List of memory objects managed by this EMM.
 * The list is protected by the "shared_region_pager_lock" lock.
 */
int shared_region_pager_count = 0;		/* number of pagers */
int shared_region_pager_count_mapped = 0;	/* number of unmapped pagers */
queue_head_t shared_region_pager_queue;
decl_lck_mtx_data(,shared_region_pager_lock)

/*
 * Maximum number of unmapped pagers we're willing to keep around.
 */
int shared_region_pager_cache_limit = 0;

/*
 * Statistics & counters.
 */
int shared_region_pager_count_max = 0;
int shared_region_pager_count_unmapped_max = 0;
int shared_region_pager_num_trim_max = 0;
int shared_region_pager_num_trim_total = 0;


lck_grp_t	shared_region_pager_lck_grp;
lck_grp_attr_t	shared_region_pager_lck_grp_attr;
lck_attr_t	shared_region_pager_lck_attr;

uint64_t shared_region_pager_copied = 0;
uint64_t shared_region_pager_slid = 0;
uint64_t shared_region_pager_slid_error = 0;
uint64_t shared_region_pager_reclaimed = 0;

/* internal prototypes */
shared_region_pager_t shared_region_pager_create(
	vm_object_t backing_object,
	vm_object_offset_t backing_offset,
	struct vm_shared_region_slide_info *slide_info);
shared_region_pager_t shared_region_pager_lookup(memory_object_t mem_obj);
void shared_region_pager_dequeue(shared_region_pager_t pager);
void shared_region_pager_deallocate_internal(shared_region_pager_t pager,
					     boolean_t locked);
void shared_region_pager_terminate_internal(shared_region_pager_t pager);
void shared_region_pager_trim(void);


#if DEBUG
int shared_region_pagerdebug = 0;
#define PAGER_ALL		0xffffffff
#define	PAGER_INIT		0x00000001
#define	PAGER_PAGEIN		0x00000002

#define PAGER_DEBUG(LEVEL, A)						\
	MACRO_BEGIN							\
	if ((shared_region_pagerdebug & (LEVEL)) == (LEVEL)) {		\
		printf A;						\
	}								\
	MACRO_END
#else
#define PAGER_DEBUG(LEVEL, A)
#endif


void
shared_region_pager_bootstrap(void)
{
	lck_grp_attr_setdefault(&shared_region_pager_lck_grp_attr);
	lck_grp_init(&shared_region_pager_lck_grp, "shared_region", &shared_region_pager_lck_grp_attr);
	lck_attr_setdefault(&shared_region_pager_lck_attr);
	lck_mtx_init(&shared_region_pager_lock, &shared_region_pager_lck_grp, &shared_region_pager_lck_attr);
	queue_init(&shared_region_pager_queue);
}

/*
 * shared_region_pager_init()
 *
 * Initialize the memory object and makes it ready to be used and mapped.
 */
kern_return_t
shared_region_pager_init(
	memory_object_t		mem_obj,
	memory_object_control_t	control,
#if !DEBUG
	__unused
#endif
	memory_object_cluster_size_t pg_size)
{
	shared_region_pager_t	pager;
	kern_return_t   	kr;
	memory_object_attr_info_data_t  attributes;

	PAGER_DEBUG(PAGER_ALL,
		    ("shared_region_pager_init: %p, %p, %x\n",
		     mem_obj, control, pg_size));

	if (control == MEMORY_OBJECT_CONTROL_NULL)
		return KERN_INVALID_ARGUMENT;

	pager = shared_region_pager_lookup(mem_obj);

	memory_object_control_reference(control);

	pager->sc_pgr_hdr.mo_control = control;

	attributes.copy_strategy = MEMORY_OBJECT_COPY_DELAY;
	/* attributes.cluster_size = (1 << (CLUSTER_SHIFT + PAGE_SHIFT));*/
	attributes.cluster_size = (1 << (PAGE_SHIFT));
	attributes.may_cache_object = FALSE;
	attributes.temporary = TRUE;

	kr = memory_object_change_attributes(
					control,
					MEMORY_OBJECT_ATTRIBUTE_INFO,
					(memory_object_info_t) &attributes,
					MEMORY_OBJECT_ATTR_INFO_COUNT);
	if (kr != KERN_SUCCESS)
		panic("shared_region_pager_init: "
		      "memory_object_change_attributes() failed");

#if CONFIG_SECLUDED_MEMORY
	if (secluded_for_filecache) {
#if 00
		/*
		 * XXX FBDP do we want this in the secluded pool?
		 * Ideally, we'd want the shared region used by Camera to
		 * NOT be in the secluded pool, but all other shared regions
		 * in the secluded pool...
		 */
		memory_object_mark_eligible_for_secluded(control, TRUE);
#endif /* 00 */
	}
#endif /* CONFIG_SECLUDED_MEMORY */

	return KERN_SUCCESS;
}

/*
 * shared_region_data_return()
 *
 * Handles page-out requests from VM.  This should never happen since
 * the pages provided by this EMM are not supposed to be dirty or dirtied
 * and VM should simply discard the contents and reclaim the pages if it
 * needs to.
 */
kern_return_t
shared_region_pager_data_return(
        __unused memory_object_t	mem_obj,
        __unused memory_object_offset_t	offset,
        __unused memory_object_cluster_size_t		data_cnt,
        __unused memory_object_offset_t	*resid_offset,
	__unused int			*io_error,
	__unused boolean_t		dirty,
	__unused boolean_t		kernel_copy,
	__unused int			upl_flags)
{
	panic("shared_region_pager_data_return: should never get called");
	return KERN_FAILURE;
}

kern_return_t
shared_region_pager_data_initialize(
	__unused memory_object_t	mem_obj,
	__unused memory_object_offset_t	offset,
	__unused memory_object_cluster_size_t		data_cnt)
{
	panic("shared_region_pager_data_initialize: should never get called");
	return KERN_FAILURE;
}

kern_return_t
shared_region_pager_data_unlock(
	__unused memory_object_t	mem_obj,
	__unused memory_object_offset_t	offset,
	__unused memory_object_size_t		size,
	__unused vm_prot_t		desired_access)
{
	return KERN_FAILURE;
}

/*
 * shared_region_pager_data_request()
 *
 * Handles page-in requests from VM.
 */
int shared_region_pager_data_request_debug = 0;
kern_return_t
shared_region_pager_data_request(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	memory_object_cluster_size_t		length,
#if !DEBUG
	__unused
#endif
	vm_prot_t		protection_required,
	memory_object_fault_info_t mo_fault_info)
{
	shared_region_pager_t	pager;
	memory_object_control_t	mo_control;
	upl_t			upl;
	int			upl_flags;
	upl_size_t		upl_size;
	upl_page_info_t		*upl_pl;
	unsigned int		pl_count;
	vm_object_t		src_top_object, src_page_object, dst_object;
	kern_return_t		kr, retval;
	vm_offset_t		src_vaddr, dst_vaddr;
	vm_offset_t		cur_offset;
	vm_offset_t		offset_in_page;
	kern_return_t		error_code;
	vm_prot_t		prot;
	vm_page_t		src_page, top_page;
	int			interruptible;
	struct vm_object_fault_info	fault_info;
	mach_vm_offset_t	slide_start_address;

	PAGER_DEBUG(PAGER_ALL, ("shared_region_pager_data_request: %p, %llx, %x, %x\n", mem_obj, offset, length, protection_required));

	retval = KERN_SUCCESS;
	src_top_object = VM_OBJECT_NULL;
	src_page_object = VM_OBJECT_NULL;
	upl = NULL;
	upl_pl = NULL;
	fault_info = *((struct vm_object_fault_info *)(uintptr_t)mo_fault_info);
	fault_info.stealth = TRUE;
	fault_info.io_sync = FALSE;
	fault_info.mark_zf_absent = FALSE;
	fault_info.batch_pmap_op = FALSE;
	interruptible = fault_info.interruptible;

	pager = shared_region_pager_lookup(mem_obj);
	assert(pager->is_ready);
	assert(pager->ref_count > 1); /* pager is alive and mapped */

	PAGER_DEBUG(PAGER_PAGEIN, ("shared_region_pager_data_request: %p, %llx, %x, %x, pager %p\n", mem_obj, offset, length, protection_required, pager));

	/*
	 * Gather in a UPL all the VM pages requested by VM.
	 */
	mo_control = pager->sc_pgr_hdr.mo_control;

	upl_size = length;
	upl_flags =
		UPL_RET_ONLY_ABSENT |
		UPL_SET_LITE |
		UPL_NO_SYNC |
		UPL_CLEAN_IN_PLACE |	/* triggers UPL_CLEAR_DIRTY */
		UPL_SET_INTERNAL;
	pl_count = 0;
	kr = memory_object_upl_request(mo_control,
				       offset, upl_size,
				       &upl, NULL, NULL, upl_flags, VM_KERN_MEMORY_SECURITY);
	if (kr != KERN_SUCCESS) {
		retval = kr;
		goto done;
	}
	dst_object = mo_control->moc_object;
	assert(dst_object != VM_OBJECT_NULL);

	/*
	 * We'll map the original data in the kernel address space from the
	 * backing VM object (itself backed by the shared cache file via
	 * the vnode pager).
	 */
	src_top_object = pager->backing_object;
	assert(src_top_object != VM_OBJECT_NULL);
	vm_object_reference(src_top_object); /* keep the source object alive */

	slide_start_address = pager->scp_slide_info->slid_address;

	fault_info.lo_offset += pager->backing_offset;
	fault_info.hi_offset += pager->backing_offset;

	/*
	 * Fill in the contents of the pages requested by VM.
	 */
	upl_pl = UPL_GET_INTERNAL_PAGE_LIST(upl);
	pl_count = length / PAGE_SIZE;
	for (cur_offset = 0;
	     retval == KERN_SUCCESS && cur_offset < length;
	     cur_offset += PAGE_SIZE) {
		ppnum_t dst_pnum;

		if (!upl_page_present(upl_pl, (int)(cur_offset / PAGE_SIZE))) {
			/* this page is not in the UPL: skip it */
			continue;
		}

		/*
		 * Map the source (dyld shared cache) page in the kernel's
		 * virtual address space.
		 * We already hold a reference on the src_top_object.
		 */
	retry_src_fault:
		vm_object_lock(src_top_object);
		vm_object_paging_begin(src_top_object);
		error_code = 0;
		prot = VM_PROT_READ;
		src_page = VM_PAGE_NULL;
		kr = vm_fault_page(src_top_object,
				   pager->backing_offset + offset + cur_offset,
				   VM_PROT_READ,
				   FALSE,
				   FALSE, /* src_page not looked up */
				   &prot,
				   &src_page,
				   &top_page,
				   NULL,
				   &error_code,
				   FALSE,
				   FALSE,
				   &fault_info);
		switch (kr) {
		case VM_FAULT_SUCCESS:
			break;
		case VM_FAULT_RETRY:
			goto retry_src_fault;
		case VM_FAULT_MEMORY_SHORTAGE:
			if (vm_page_wait(interruptible)) {
				goto retry_src_fault;
			}
			/* fall thru */
		case VM_FAULT_INTERRUPTED:
			retval = MACH_SEND_INTERRUPTED;
			goto done;
		case VM_FAULT_SUCCESS_NO_VM_PAGE:
			/* success but no VM page: fail */
			vm_object_paging_end(src_top_object);
			vm_object_unlock(src_top_object);
			/*FALLTHROUGH*/
		case VM_FAULT_MEMORY_ERROR:
			/* the page is not there ! */
			if (error_code) {
				retval = error_code;
			} else {
				retval = KERN_MEMORY_ERROR;
			}
			goto done;
		default:
			panic("shared_region_pager_data_request: "
			      "vm_fault_page() unexpected error 0x%x\n",
			      kr);
		}
		assert(src_page != VM_PAGE_NULL);
		assert(src_page->vmp_busy);

		if (src_page->vmp_q_state != VM_PAGE_ON_SPECULATIVE_Q) {
			vm_page_lockspin_queues();
			if (src_page->vmp_q_state != VM_PAGE_ON_SPECULATIVE_Q) {
			        vm_page_speculate(src_page, FALSE);
			}
			vm_page_unlock_queues();
		}

		/*
		 * Establish pointers to the source
		 * and destination physical pages.
		 */
		dst_pnum = (ppnum_t)
		        upl_phys_page(upl_pl, (int)(cur_offset / PAGE_SIZE));
                assert(dst_pnum != 0);
#if __x86_64__
		src_vaddr = (vm_map_offset_t)
			PHYSMAP_PTOV((pmap_paddr_t)VM_PAGE_GET_PHYS_PAGE(src_page)
				     << PAGE_SHIFT);
		dst_vaddr = (vm_map_offset_t)
			PHYSMAP_PTOV((pmap_paddr_t)dst_pnum << PAGE_SHIFT);

#elif __arm__ || __arm64__
		src_vaddr = (vm_map_offset_t)
			phystokv((pmap_paddr_t)VM_PAGE_GET_PHYS_PAGE(src_page)
				 << PAGE_SHIFT);
		dst_vaddr = (vm_map_offset_t)
			phystokv((pmap_paddr_t)dst_pnum << PAGE_SHIFT);
#else
#error "vm_paging_map_object: no 1-to-1 kernel mapping of physical memory..."
		src_vaddr = 0;
		dst_vaddr = 0;
#endif
		src_page_object = VM_PAGE_OBJECT(src_page);

		/*
		 * Validate the original page...
		 */
		if (src_page_object->code_signed) {
			vm_page_validate_cs_mapped(
				src_page,
				(const void *) src_vaddr);
		}
		/*
		 * ... and transfer the results to the destination page.
		 */
		UPL_SET_CS_VALIDATED(upl_pl, cur_offset / PAGE_SIZE,
				     src_page->vmp_cs_validated);
		UPL_SET_CS_TAINTED(upl_pl, cur_offset / PAGE_SIZE,
				   src_page->vmp_cs_tainted);
		UPL_SET_CS_NX(upl_pl, cur_offset / PAGE_SIZE,
				   src_page->vmp_cs_nx);

		/*
		 * The page provider might access a mapped file, so let's
		 * release the object lock for the source page to avoid a
		 * potential deadlock.
		 * The source page is kept busy and we have a
		 * "paging_in_progress" reference on its object, so it's safe
		 * to unlock the object here.
		 */
		assert(src_page->vmp_busy);
		assert(src_page_object->paging_in_progress > 0);
		vm_object_unlock(src_page_object);

		/*
		 * Process the original contents of the source page
		 * into the destination page.
		 */
		for (offset_in_page = 0;
		     offset_in_page < PAGE_SIZE;
		     offset_in_page += PAGE_SIZE_FOR_SR_SLIDE) {
			vm_object_offset_t chunk_offset;
			vm_object_offset_t offset_in_backing_object;
			vm_object_offset_t offset_in_sliding_range;

			chunk_offset = offset + cur_offset + offset_in_page;

			bcopy((const char *)(src_vaddr +
					     offset_in_page),
			      (char *)(dst_vaddr + offset_in_page),
			      PAGE_SIZE_FOR_SR_SLIDE);

			offset_in_backing_object = (chunk_offset +
						    pager->backing_offset);
			if ((offset_in_backing_object < pager->scp_slide_info->start) ||
			    (offset_in_backing_object >= pager->scp_slide_info->end)) {
				/* chunk is outside of sliding range: done */
				shared_region_pager_copied++;
				continue;
			}

			offset_in_sliding_range =
				(offset_in_backing_object -
				 pager->scp_slide_info->start);
			kr = vm_shared_region_slide_page(
				pager->scp_slide_info,
				dst_vaddr + offset_in_page,
				(mach_vm_offset_t) (offset_in_sliding_range +
						    slide_start_address),
				(uint32_t) (offset_in_sliding_range /
					    PAGE_SIZE_FOR_SR_SLIDE));
			if (shared_region_pager_data_request_debug) {
				printf("shared_region_data_request"
				       "(%p,0x%llx+0x%llx+0x%04llx): 0x%llx "
				       "in sliding range [0x%llx:0x%llx]: "
				       "SLIDE offset 0x%llx="
				       "(0x%llx+0x%llx+0x%llx+0x%04llx)"
				       "[0x%016llx 0x%016llx] "
				       "code_signed=%d "
				       "cs_validated=%d "
				       "cs_tainted=%d "
				       "cs_nx=%d "
				       "kr=0x%x\n",
				       pager,
				       offset,
				       (uint64_t) cur_offset,
				       (uint64_t) offset_in_page,
				       chunk_offset,
				       pager->scp_slide_info->start,
				       pager->scp_slide_info->end,
				       (pager->backing_offset +
					offset +
					cur_offset +
					offset_in_page),
				       pager->backing_offset,
				       offset,
				       (uint64_t) cur_offset,
				       (uint64_t) offset_in_page,
				       *(uint64_t *)(dst_vaddr+offset_in_page),
				       *(uint64_t *)(dst_vaddr+offset_in_page+8),
				       src_page_object->code_signed,
				       src_page->vmp_cs_validated,
				       src_page->vmp_cs_tainted,
				       src_page->vmp_cs_nx,
				       kr);
			}
			if (kr != KERN_SUCCESS) {
				shared_region_pager_slid_error++;
				break;
			}
			shared_region_pager_slid++;
		}

		assert(VM_PAGE_OBJECT(src_page) == src_page_object);
		assert(src_page->vmp_busy);
		assert(src_page_object->paging_in_progress > 0);
		vm_object_lock(src_page_object);

		/*
		 * Cleanup the result of vm_fault_page() of the source page.
		 */
		PAGE_WAKEUP_DONE(src_page);
		src_page = VM_PAGE_NULL;
		vm_object_paging_end(src_page_object);
		vm_object_unlock(src_page_object);

		if (top_page != VM_PAGE_NULL) {
			assert(VM_PAGE_OBJECT(top_page) == src_top_object);
			vm_object_lock(src_top_object);
			VM_PAGE_FREE(top_page);
			vm_object_paging_end(src_top_object);
			vm_object_unlock(src_top_object);
		}
	}

done:
	if (upl != NULL) {
		/* clean up the UPL */

		/*
		 * The pages are currently dirty because we've just been
		 * writing on them, but as far as we're concerned, they're
		 * clean since they contain their "original" contents as
		 * provided by us, the pager.
		 * Tell the UPL to mark them "clean".
		 */
		upl_clear_dirty(upl, TRUE);

		/* abort or commit the UPL */
		if (retval != KERN_SUCCESS) {
			upl_abort(upl, 0);
		} else {
			boolean_t empty;
			upl_commit_range(upl, 0, upl->size,
					 UPL_COMMIT_CS_VALIDATED | UPL_COMMIT_WRITTEN_BY_KERNEL,
					 upl_pl, pl_count, &empty);
		}

		/* and deallocate the UPL */
		upl_deallocate(upl);
		upl = NULL;
	}
	if (src_top_object != VM_OBJECT_NULL) {
		vm_object_deallocate(src_top_object);
	}
	return retval;
}

/*
 * shared_region_pager_reference()
 *
 * Get a reference on this memory object.
 * For external usage only.  Assumes that the initial reference count is not 0,
 * i.e one should not "revive" a dead pager this way.
 */
void
shared_region_pager_reference(
	memory_object_t		mem_obj)
{
	shared_region_pager_t	pager;

	pager = shared_region_pager_lookup(mem_obj);

	lck_mtx_lock(&shared_region_pager_lock);
	assert(pager->ref_count > 0);
	pager->ref_count++;
	lck_mtx_unlock(&shared_region_pager_lock);
}


/*
 * shared_region_pager_dequeue:
 *
 * Removes a pager from the list of pagers.
 *
 * The caller must hold "shared_region_pager_lock".
 */
void
shared_region_pager_dequeue(
	shared_region_pager_t pager)
{
	assert(!pager->is_mapped);

	queue_remove(&shared_region_pager_queue,
		     pager,
		     shared_region_pager_t,
		     pager_queue);
	pager->pager_queue.next = NULL;
	pager->pager_queue.prev = NULL;

	shared_region_pager_count--;
}

/*
 * shared_region_pager_terminate_internal:
 *
 * Trigger the asynchronous termination of the memory object associated
 * with this pager.
 * When the memory object is terminated, there will be one more call
 * to memory_object_deallocate() (i.e. shared_region_pager_deallocate())
 * to finish the clean up.
 *
 * "shared_region_pager_lock" should not be held by the caller.
 * We don't need the lock because the pager has already been removed from
 * the pagers' list and is now ours exclusively.
 */
void
shared_region_pager_terminate_internal(
	shared_region_pager_t pager)
{
	assert(pager->is_ready);
	assert(!pager->is_mapped);

	if (pager->backing_object != VM_OBJECT_NULL) {
		vm_object_deallocate(pager->backing_object);
		pager->backing_object = VM_OBJECT_NULL;
	}
	/* trigger the destruction of the memory object */
	memory_object_destroy(pager->sc_pgr_hdr.mo_control, 0);
}

/*
 * shared_region_pager_deallocate_internal()
 *
 * Release a reference on this pager and free it when the last
 * reference goes away.
 * Can be called with shared_region_pager_lock held or not but always returns
 * with it unlocked.
 */
void
shared_region_pager_deallocate_internal(
	shared_region_pager_t	pager,
	boolean_t		locked)
{
	boolean_t	needs_trimming;
	int		count_unmapped;

	if (! locked) {
		lck_mtx_lock(&shared_region_pager_lock);
	}

	count_unmapped = (shared_region_pager_count -
			  shared_region_pager_count_mapped);
	if (count_unmapped > shared_region_pager_cache_limit) {
		/* we have too many unmapped pagers:  trim some */
		needs_trimming = TRUE;
	} else {
		needs_trimming = FALSE;
	}

	/* drop a reference on this pager */
	pager->ref_count--;

	if (pager->ref_count == 1) {
		/*
		 * Only the "named" reference is left, which means that
		 * no one is really holding on to this pager anymore.
		 * Terminate it.
		 */
		shared_region_pager_dequeue(pager);
		/* the pager is all ours: no need for the lock now */
		lck_mtx_unlock(&shared_region_pager_lock);
		shared_region_pager_terminate_internal(pager);
	} else if (pager->ref_count == 0) {
		/*
		 * Dropped the existence reference;  the memory object has
		 * been terminated.  Do some final cleanup and release the
		 * pager structure.
		 */
		lck_mtx_unlock(&shared_region_pager_lock);
		if (pager->sc_pgr_hdr.mo_control != MEMORY_OBJECT_CONTROL_NULL) {
			memory_object_control_deallocate(pager->sc_pgr_hdr.mo_control);
			pager->sc_pgr_hdr.mo_control = MEMORY_OBJECT_CONTROL_NULL;
		}
		kfree(pager, sizeof (*pager));
		pager = SHARED_REGION_PAGER_NULL;
	} else {
		/* there are still plenty of references:  keep going... */
		lck_mtx_unlock(&shared_region_pager_lock);
	}

	if (needs_trimming) {
		shared_region_pager_trim();
	}
	/* caution: lock is not held on return... */
}

/*
 * shared_region_pager_deallocate()
 *
 * Release a reference on this pager and free it when the last
 * reference goes away.
 */
void
shared_region_pager_deallocate(
	memory_object_t		mem_obj)
{
	shared_region_pager_t	pager;

	PAGER_DEBUG(PAGER_ALL, ("shared_region_pager_deallocate: %p\n", mem_obj));
	pager = shared_region_pager_lookup(mem_obj);
	shared_region_pager_deallocate_internal(pager, FALSE);
}

/*
 *
 */
kern_return_t
shared_region_pager_terminate(
#if !DEBUG
	__unused
#endif
	memory_object_t	mem_obj)
{
	PAGER_DEBUG(PAGER_ALL, ("shared_region_pager_terminate: %p\n", mem_obj));

	return KERN_SUCCESS;
}

/*
 *
 */
kern_return_t
shared_region_pager_synchronize(
	__unused memory_object_t		mem_obj,
	__unused memory_object_offset_t	offset,
	__unused memory_object_size_t		length,
	__unused vm_sync_t		sync_flags)
{
	panic("shared_region_pager_synchronize: memory_object_synchronize no longer supported\n");
	return KERN_FAILURE;
}

/*
 * shared_region_pager_map()
 *
 * This allows VM to let us, the EMM, know that this memory object
 * is currently mapped one or more times.  This is called by VM each time
 * the memory object gets mapped and we take one extra reference on the
 * memory object to account for all its mappings.
 */
kern_return_t
shared_region_pager_map(
	memory_object_t		mem_obj,
	__unused vm_prot_t	prot)
{
	shared_region_pager_t	pager;

	PAGER_DEBUG(PAGER_ALL, ("shared_region_pager_map: %p\n", mem_obj));

	pager = shared_region_pager_lookup(mem_obj);

	lck_mtx_lock(&shared_region_pager_lock);
	assert(pager->is_ready);
	assert(pager->ref_count > 0); /* pager is alive */
	if (pager->is_mapped == FALSE) {
		/*
		 * First mapping of this pager:  take an extra reference
		 * that will remain until all the mappings of this pager
		 * are removed.
		 */
		pager->is_mapped = TRUE;
		pager->ref_count++;
		shared_region_pager_count_mapped++;
	}
	lck_mtx_unlock(&shared_region_pager_lock);

	return KERN_SUCCESS;
}

/*
 * shared_region_pager_last_unmap()
 *
 * This is called by VM when this memory object is no longer mapped anywhere.
 */
kern_return_t
shared_region_pager_last_unmap(
	memory_object_t		mem_obj)
{
	shared_region_pager_t	pager;
	int			count_unmapped;

	PAGER_DEBUG(PAGER_ALL,
		    ("shared_region_pager_last_unmap: %p\n", mem_obj));

	pager = shared_region_pager_lookup(mem_obj);

	lck_mtx_lock(&shared_region_pager_lock);
	if (pager->is_mapped) {
		/*
		 * All the mappings are gone, so let go of the one extra
		 * reference that represents all the mappings of this pager.
		 */
		shared_region_pager_count_mapped--;
		count_unmapped = (shared_region_pager_count -
				  shared_region_pager_count_mapped);
		if (count_unmapped > shared_region_pager_count_unmapped_max) {
			shared_region_pager_count_unmapped_max = count_unmapped;
		}
		pager->is_mapped = FALSE;
		shared_region_pager_deallocate_internal(pager, TRUE);
		/* caution: deallocate_internal() released the lock ! */
	} else {
		lck_mtx_unlock(&shared_region_pager_lock);
	}

	return KERN_SUCCESS;
}


/*
 *
 */
shared_region_pager_t
shared_region_pager_lookup(
	memory_object_t	 mem_obj)
{
	shared_region_pager_t	pager;

	assert(mem_obj->mo_pager_ops == &shared_region_pager_ops);
	pager = (shared_region_pager_t)(uintptr_t) mem_obj;
	assert(pager->ref_count > 0);
	return pager;
}

shared_region_pager_t
shared_region_pager_create(
	vm_object_t		backing_object,
	vm_object_offset_t	backing_offset,
	struct vm_shared_region_slide_info *slide_info)
{
	shared_region_pager_t	pager;
	memory_object_control_t	control;
	kern_return_t		kr;

	pager = (shared_region_pager_t) kalloc(sizeof (*pager));
	if (pager == SHARED_REGION_PAGER_NULL) {
		return SHARED_REGION_PAGER_NULL;
	}

	/*
	 * The vm_map call takes both named entry ports and raw memory
	 * objects in the same parameter.  We need to make sure that
	 * vm_map does not see this object as a named entry port.  So,
	 * we reserve the first word in the object for a fake ip_kotype
	 * setting - that will tell vm_map to use it as a memory object.
	 */
	pager->sc_pgr_hdr.mo_ikot = IKOT_MEMORY_OBJECT;
	pager->sc_pgr_hdr.mo_pager_ops = &shared_region_pager_ops;
	pager->sc_pgr_hdr.mo_control = MEMORY_OBJECT_CONTROL_NULL;

	pager->is_ready = FALSE;/* not ready until it has a "name" */
	pager->ref_count = 1;	/* existence reference (for the cache) */
	pager->ref_count++;	/* for the caller */
	pager->is_mapped = FALSE;
	pager->backing_object = backing_object;
	pager->backing_offset = backing_offset;
	pager->scp_slide_info = slide_info;

	vm_object_reference(backing_object);

	lck_mtx_lock(&shared_region_pager_lock);
	/* enter new pager at the head of our list of pagers */
	queue_enter_first(&shared_region_pager_queue,
			  pager,
			  shared_region_pager_t,
			  pager_queue);
	shared_region_pager_count++;
	if (shared_region_pager_count > shared_region_pager_count_max) {
		shared_region_pager_count_max = shared_region_pager_count;
	}
	lck_mtx_unlock(&shared_region_pager_lock);

	kr = memory_object_create_named((memory_object_t) pager,
					0,
					&control);
	assert(kr == KERN_SUCCESS);

	lck_mtx_lock(&shared_region_pager_lock);
	/* the new pager is now ready to be used */
	pager->is_ready = TRUE;
	lck_mtx_unlock(&shared_region_pager_lock);

	/* wakeup anyone waiting for this pager to be ready */
	thread_wakeup(&pager->is_ready);

	return pager;
}

/*
 * shared_region_pager_setup()
 *
 * Provide the caller with a memory object backed by the provided
 * "backing_object" VM object.
 */
memory_object_t
shared_region_pager_setup(
	vm_object_t		backing_object,
	vm_object_offset_t	backing_offset,
	struct vm_shared_region_slide_info *slide_info)
{
	shared_region_pager_t	pager;

	/* create new pager */
	pager = shared_region_pager_create(
		backing_object,
		backing_offset,
		slide_info);
	if (pager == SHARED_REGION_PAGER_NULL) {
		/* could not create a new pager */
		return MEMORY_OBJECT_NULL;
	}

	lck_mtx_lock(&shared_region_pager_lock);
	while (!pager->is_ready) {
		lck_mtx_sleep(&shared_region_pager_lock,
			LCK_SLEEP_DEFAULT,
			&pager->is_ready,
			THREAD_UNINT);
	}
	lck_mtx_unlock(&shared_region_pager_lock);

	return (memory_object_t) pager;
}

void
shared_region_pager_trim(void)
{
	shared_region_pager_t	pager, prev_pager;
	queue_head_t		trim_queue;
	int			num_trim;
	int			count_unmapped;

	lck_mtx_lock(&shared_region_pager_lock);

	/*
	 * We have too many pagers, try and trim some unused ones,
	 * starting with the oldest pager at the end of the queue.
	 */
	queue_init(&trim_queue);
	num_trim = 0;

	for (pager = (shared_region_pager_t)
		     queue_last(&shared_region_pager_queue);
	     !queue_end(&shared_region_pager_queue,
			(queue_entry_t) pager);
	     pager = prev_pager) {
		/* get prev elt before we dequeue */
		prev_pager = (shared_region_pager_t)
			queue_prev(&pager->pager_queue);

		if (pager->ref_count == 2 &&
		    pager->is_ready &&
		    !pager->is_mapped) {
			/* this pager can be trimmed */
			num_trim++;
			/* remove this pager from the main list ... */
			shared_region_pager_dequeue(pager);
			/* ... and add it to our trim queue */
			queue_enter_first(&trim_queue,
					  pager,
					  shared_region_pager_t,
					  pager_queue);

			count_unmapped = (shared_region_pager_count -
					  shared_region_pager_count_mapped);
			if (count_unmapped <= shared_region_pager_cache_limit) {
				/* we have enough pagers to trim */
				break;
			}
		}
	}
	if (num_trim > shared_region_pager_num_trim_max) {
		shared_region_pager_num_trim_max = num_trim;
	}
	shared_region_pager_num_trim_total += num_trim;

	lck_mtx_unlock(&shared_region_pager_lock);

	/* terminate the trimmed pagers */
	while (!queue_empty(&trim_queue)) {
		queue_remove_first(&trim_queue,
				   pager,
				   shared_region_pager_t,
				   pager_queue);
		pager->pager_queue.next = NULL;
		pager->pager_queue.prev = NULL;
		assert(pager->ref_count == 2);
		/*
		 * We can't call deallocate_internal() because the pager
		 * has already been dequeued, but we still need to remove
		 * a reference.
		 */
		pager->ref_count--;
		shared_region_pager_terminate_internal(pager);
	}
}
