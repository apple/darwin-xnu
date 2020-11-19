/*
 * Copyright (c) 2008-2020 Apple Inc. All rights reserved.
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

#include <mach/kern_return.h>
#include <mach/memory_object_control.h>
#include <mach/upl.h>

#include <kern/ipc_kobject.h>
#include <kern/kalloc.h>
#include <kern/queue.h>

#include <vm/memory_object.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>


/*
 * APPLE SWAPFILE MEMORY PAGER
 *
 * This external memory manager (EMM) handles mappings of the swap files.
 * Swap files are not regular files and are used solely to store contents of
 * anonymous memory mappings while not resident in memory.
 * There's no valid reason to map a swap file.  This just puts extra burden
 * on the system, is potentially a security issue and is not reliable since
 * the contents can change at any time with pageout operations.
 * Here are some of the issues with mapping a swap file.
 * * PERFORMANCE:
 *   Each page in the swap file belong to an anonymous memory object. Mapping
 *   the swap file makes those pages also accessible via a vnode memory
 *   object and each page can now be resident twice.
 * * SECURITY:
 *   Mapping a swap file allows access to other processes' memory.  Swap files
 *   are only accessible by the "root" super-user, who can already access any
 *   process's memory, so this is not a real issue but if permissions on the
 *   swap file got changed, it could become one.
 *   Swap files are not "zero-filled" on creation, so until their contents are
 *   overwritten with pageout operations, they still contain whatever was on
 *   the disk blocks they were allocated.  The "super-user" could see the
 *   contents of free blocks anyway, so this is not a new security issue but
 *   it may be perceive as one.
 *
 * We can't legitimately prevent a user process with appropriate privileges
 * from mapping a swap file, but we can prevent it from accessing its actual
 * contents.
 * This pager mostly handles page-in request (from memory_object_data_request())
 * for swap file mappings and just returns bogus data.
 * Pageouts are not handled, so mmap() has to make sure it does not allow
 * writable (i.e. MAP_SHARED and PROT_WRITE) mappings of swap files.
 */

/* forward declarations */
void swapfile_pager_reference(memory_object_t mem_obj);
void swapfile_pager_deallocate(memory_object_t mem_obj);
kern_return_t swapfile_pager_init(memory_object_t mem_obj,
    memory_object_control_t control,
    memory_object_cluster_size_t pg_size);
kern_return_t swapfile_pager_terminate(memory_object_t mem_obj);
kern_return_t swapfile_pager_data_request(memory_object_t mem_obj,
    memory_object_offset_t offset,
    memory_object_cluster_size_t length,
    vm_prot_t protection_required,
    memory_object_fault_info_t fault_info);
kern_return_t swapfile_pager_data_return(memory_object_t mem_obj,
    memory_object_offset_t offset,
    memory_object_cluster_size_t      data_cnt,
    memory_object_offset_t *resid_offset,
    int *io_error,
    boolean_t dirty,
    boolean_t kernel_copy,
    int upl_flags);
kern_return_t swapfile_pager_data_initialize(memory_object_t mem_obj,
    memory_object_offset_t offset,
    memory_object_cluster_size_t data_cnt);
kern_return_t swapfile_pager_data_unlock(memory_object_t mem_obj,
    memory_object_offset_t offset,
    memory_object_size_t size,
    vm_prot_t desired_access);
kern_return_t swapfile_pager_synchronize(memory_object_t mem_obj,
    memory_object_offset_t offset,
    memory_object_size_t length,
    vm_sync_t sync_flags);
kern_return_t swapfile_pager_map(memory_object_t mem_obj,
    vm_prot_t prot);
kern_return_t swapfile_pager_last_unmap(memory_object_t mem_obj);

/*
 * Vector of VM operations for this EMM.
 * These routines are invoked by VM via the memory_object_*() interfaces.
 */
const struct memory_object_pager_ops swapfile_pager_ops = {
	.memory_object_reference = swapfile_pager_reference,
	.memory_object_deallocate = swapfile_pager_deallocate,
	.memory_object_init = swapfile_pager_init,
	.memory_object_terminate = swapfile_pager_terminate,
	.memory_object_data_request = swapfile_pager_data_request,
	.memory_object_data_return = swapfile_pager_data_return,
	.memory_object_data_initialize = swapfile_pager_data_initialize,
	.memory_object_data_unlock = swapfile_pager_data_unlock,
	.memory_object_synchronize = swapfile_pager_synchronize,
	.memory_object_map = swapfile_pager_map,
	.memory_object_last_unmap = swapfile_pager_last_unmap,
	.memory_object_data_reclaim = NULL,
	.memory_object_pager_name = "swapfile pager"
};

/*
 * The "swapfile_pager" describes a memory object backed by
 * the "swapfile" EMM.
 */
typedef struct swapfile_pager {
	/* mandatory generic header */
	struct memory_object swp_pgr_hdr;

	/* pager-specific data */
	queue_chain_t           pager_queue;    /* next & prev pagers */
	unsigned int            ref_count;      /* reference count */
	boolean_t               is_ready;       /* is this pager ready ? */
	boolean_t               is_mapped;      /* is this pager mapped ? */
	struct vnode            *swapfile_vnode;/* the swapfile's vnode */
} *swapfile_pager_t;
#define SWAPFILE_PAGER_NULL     ((swapfile_pager_t) NULL)

/*
 * List of memory objects managed by this EMM.
 * The list is protected by the "swapfile_pager_lock" lock.
 */
int swapfile_pager_count = 0;           /* number of pagers */
queue_head_t swapfile_pager_queue = QUEUE_HEAD_INITIALIZER(swapfile_pager_queue);
LCK_GRP_DECLARE(swapfile_pager_lck_grp, "swapfile pager");
LCK_MTX_DECLARE(swapfile_pager_lock, &swapfile_pager_lck_grp);

/*
 * Statistics & counters.
 */
int swapfile_pager_count_max = 0;

/* internal prototypes */
swapfile_pager_t swapfile_pager_create(struct vnode *vp);
swapfile_pager_t swapfile_pager_lookup(memory_object_t mem_obj);
void swapfile_pager_dequeue(swapfile_pager_t pager);
void swapfile_pager_deallocate_internal(swapfile_pager_t pager,
    boolean_t locked);
void swapfile_pager_terminate_internal(swapfile_pager_t pager);


#if DEBUG
int swapfile_pagerdebug = 0;
#define PAGER_ALL               0xffffffff
#define PAGER_INIT              0x00000001
#define PAGER_PAGEIN            0x00000002

#define PAGER_DEBUG(LEVEL, A)                                           \
	MACRO_BEGIN                                                     \
	if ((swapfile_pagerdebug & LEVEL)==LEVEL) {             \
	        printf A;                                               \
	}                                                               \
	MACRO_END
#else
#define PAGER_DEBUG(LEVEL, A)
#endif


/*
 * swapfile_pager_init()
 *
 * Initialize the memory object and makes it ready to be used and mapped.
 */
kern_return_t
swapfile_pager_init(
	memory_object_t         mem_obj,
	memory_object_control_t control,
#if !DEBUG
	__unused
#endif
	memory_object_cluster_size_t pg_size)
{
	swapfile_pager_t        pager;
	kern_return_t           kr;
	memory_object_attr_info_data_t  attributes;

	PAGER_DEBUG(PAGER_ALL,
	    ("swapfile_pager_init: %p, %p, %x\n",
	    mem_obj, control, pg_size));

	if (control == MEMORY_OBJECT_CONTROL_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	pager = swapfile_pager_lookup(mem_obj);

	memory_object_control_reference(control);

	pager->swp_pgr_hdr.mo_control = control;

	attributes.copy_strategy = MEMORY_OBJECT_COPY_DELAY;
	attributes.cluster_size = (1 << (PAGE_SHIFT));
	attributes.may_cache_object = FALSE;
	attributes.temporary = TRUE;

	kr = memory_object_change_attributes(
		control,
		MEMORY_OBJECT_ATTRIBUTE_INFO,
		(memory_object_info_t) &attributes,
		MEMORY_OBJECT_ATTR_INFO_COUNT);
	if (kr != KERN_SUCCESS) {
		panic("swapfile_pager_init: "
		    "memory_object_change_attributes() failed");
	}

	return KERN_SUCCESS;
}

/*
 * swapfile_data_return()
 *
 * Handles page-out requests from VM.  This should never happen since
 * the pages provided by this EMM are not supposed to be dirty or dirtied
 * and VM should simply discard the contents and reclaim the pages if it
 * needs to.
 */
kern_return_t
swapfile_pager_data_return(
	__unused memory_object_t        mem_obj,
	__unused memory_object_offset_t offset,
	__unused memory_object_cluster_size_t           data_cnt,
	__unused memory_object_offset_t *resid_offset,
	__unused int                    *io_error,
	__unused boolean_t              dirty,
	__unused boolean_t              kernel_copy,
	__unused int                    upl_flags)
{
	panic("swapfile_pager_data_return: should never get called");
	return KERN_FAILURE;
}

kern_return_t
swapfile_pager_data_initialize(
	__unused memory_object_t        mem_obj,
	__unused memory_object_offset_t offset,
	__unused memory_object_cluster_size_t           data_cnt)
{
	panic("swapfile_pager_data_initialize: should never get called");
	return KERN_FAILURE;
}

kern_return_t
swapfile_pager_data_unlock(
	__unused memory_object_t        mem_obj,
	__unused memory_object_offset_t offset,
	__unused memory_object_size_t           size,
	__unused vm_prot_t              desired_access)
{
	return KERN_FAILURE;
}

/*
 * swapfile_pager_data_request()
 *
 * Handles page-in requests from VM.
 */
kern_return_t
swapfile_pager_data_request(
	memory_object_t         mem_obj,
	memory_object_offset_t  offset,
	memory_object_cluster_size_t            length,
#if !DEBUG
	__unused
#endif
	vm_prot_t               protection_required,
	__unused memory_object_fault_info_t mo_fault_info)
{
	swapfile_pager_t        pager;
	memory_object_control_t mo_control;
	upl_t                   upl;
	int                     upl_flags;
	upl_size_t              upl_size;
	upl_page_info_t         *upl_pl = NULL;
	unsigned int            pl_count;
	vm_object_t             dst_object;
	kern_return_t           kr, retval;
	vm_map_offset_t         kernel_mapping;
	vm_offset_t             dst_vaddr;
	char                    *dst_ptr;
	vm_offset_t             cur_offset;
	vm_map_entry_t          map_entry;

	PAGER_DEBUG(PAGER_ALL, ("swapfile_pager_data_request: %p, %llx, %x, %x\n", mem_obj, offset, length, protection_required));

	kernel_mapping = 0;
	upl = NULL;
	upl_pl = NULL;

	pager = swapfile_pager_lookup(mem_obj);
	assert(pager->is_ready);
	assert(pager->ref_count > 1); /* pager is alive and mapped */

	PAGER_DEBUG(PAGER_PAGEIN, ("swapfile_pager_data_request: %p, %llx, %x, %x, pager %p\n", mem_obj, offset, length, protection_required, pager));

	/*
	 * Gather in a UPL all the VM pages requested by VM.
	 */
	mo_control = pager->swp_pgr_hdr.mo_control;

	upl_size = length;
	upl_flags =
	    UPL_RET_ONLY_ABSENT |
	    UPL_SET_LITE |
	    UPL_NO_SYNC |
	    UPL_CLEAN_IN_PLACE |        /* triggers UPL_CLEAR_DIRTY */
	    UPL_SET_INTERNAL;
	pl_count = 0;
	kr = memory_object_upl_request(mo_control,
	    offset, upl_size,
	    &upl, NULL, NULL, upl_flags, VM_KERN_MEMORY_OSFMK);
	if (kr != KERN_SUCCESS) {
		retval = kr;
		goto done;
	}
	dst_object = mo_control->moc_object;
	assert(dst_object != VM_OBJECT_NULL);


	/*
	 * Reserve a virtual page in the kernel address space to map each
	 * destination physical page when it's its turn to be processed.
	 */
	vm_object_reference(kernel_object);     /* ref. for mapping */
	kr = vm_map_find_space(kernel_map,
	    &kernel_mapping,
	    PAGE_SIZE_64,
	    0,
	    0,
	    VM_MAP_KERNEL_FLAGS_NONE,
	    VM_KERN_MEMORY_NONE,
	    &map_entry);
	if (kr != KERN_SUCCESS) {
		vm_object_deallocate(kernel_object);
		retval = kr;
		goto done;
	}
	VME_OBJECT_SET(map_entry, kernel_object);
	VME_OFFSET_SET(map_entry, kernel_mapping - VM_MIN_KERNEL_ADDRESS);
	vm_map_unlock(kernel_map);
	dst_vaddr = CAST_DOWN(vm_offset_t, kernel_mapping);
	dst_ptr = (char *) dst_vaddr;

	/*
	 * Fill in the contents of the pages requested by VM.
	 */
	upl_pl = UPL_GET_INTERNAL_PAGE_LIST(upl);
	pl_count = length / PAGE_SIZE;
	for (cur_offset = 0; cur_offset < length; cur_offset += PAGE_SIZE) {
		ppnum_t dst_pnum;

		if (!upl_page_present(upl_pl, (int)(cur_offset / PAGE_SIZE))) {
			/* this page is not in the UPL: skip it */
			continue;
		}

		/*
		 * Establish an explicit pmap mapping of the destination
		 * physical page.
		 * We can't do a regular VM mapping because the VM page
		 * is "busy".
		 */
		dst_pnum = (ppnum_t)
		    upl_phys_page(upl_pl, (int)(cur_offset / PAGE_SIZE));
		assert(dst_pnum != 0);
		retval = pmap_enter(kernel_pmap,
		    kernel_mapping,
		    dst_pnum,
		    VM_PROT_READ | VM_PROT_WRITE,
		    VM_PROT_NONE,
		    0,
		    TRUE);

		assert(retval == KERN_SUCCESS);

		if (retval != KERN_SUCCESS) {
			goto done;
		}

		memset(dst_ptr, '\0', PAGE_SIZE);
		/* add an end-of-line to keep line counters happy */
		dst_ptr[PAGE_SIZE - 1] = '\n';

		/*
		 * Remove the pmap mapping of the destination page
		 * in the kernel.
		 */
		pmap_remove(kernel_pmap,
		    (addr64_t) kernel_mapping,
		    (addr64_t) (kernel_mapping + PAGE_SIZE_64));
	}

	retval = KERN_SUCCESS;
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
			assertf(page_aligned(upl->u_offset) && page_aligned(upl->u_size),
			    "upl %p offset 0x%llx size 0x%x",
			    upl, upl->u_offset, upl->u_size);
			upl_commit_range(upl, 0, upl->u_size,
			    UPL_COMMIT_CS_VALIDATED,
			    upl_pl, pl_count, &empty);
		}

		/* and deallocate the UPL */
		upl_deallocate(upl);
		upl = NULL;
	}
	if (kernel_mapping != 0) {
		/* clean up the mapping of the source and destination pages */
		kr = vm_map_remove(kernel_map,
		    kernel_mapping,
		    kernel_mapping + PAGE_SIZE_64,
		    VM_MAP_REMOVE_NO_FLAGS);
		assert(kr == KERN_SUCCESS);
		kernel_mapping = 0;
		dst_vaddr = 0;
	}

	return retval;
}

/*
 * swapfile_pager_reference()
 *
 * Get a reference on this memory object.
 * For external usage only.  Assumes that the initial reference count is not 0,
 * i.e one should not "revive" a dead pager this way.
 */
void
swapfile_pager_reference(
	memory_object_t         mem_obj)
{
	swapfile_pager_t        pager;

	pager = swapfile_pager_lookup(mem_obj);

	lck_mtx_lock(&swapfile_pager_lock);
	assert(pager->ref_count > 0);
	pager->ref_count++;
	lck_mtx_unlock(&swapfile_pager_lock);
}


/*
 * swapfile_pager_dequeue:
 *
 * Removes a pager from the list of pagers.
 *
 * The caller must hold "swapfile_pager_lock".
 */
void
swapfile_pager_dequeue(
	swapfile_pager_t pager)
{
	assert(!pager->is_mapped);

	queue_remove(&swapfile_pager_queue,
	    pager,
	    swapfile_pager_t,
	    pager_queue);
	pager->pager_queue.next = NULL;
	pager->pager_queue.prev = NULL;

	swapfile_pager_count--;
}

/*
 * swapfile_pager_terminate_internal:
 *
 * Trigger the asynchronous termination of the memory object associated
 * with this pager.
 * When the memory object is terminated, there will be one more call
 * to memory_object_deallocate() (i.e. swapfile_pager_deallocate())
 * to finish the clean up.
 *
 * "swapfile_pager_lock" should not be held by the caller.
 * We don't need the lock because the pager has already been removed from
 * the pagers' list and is now ours exclusively.
 */
void
swapfile_pager_terminate_internal(
	swapfile_pager_t pager)
{
	assert(pager->is_ready);
	assert(!pager->is_mapped);

	if (pager->swapfile_vnode != NULL) {
		pager->swapfile_vnode = NULL;
	}

	/* trigger the destruction of the memory object */
	memory_object_destroy(pager->swp_pgr_hdr.mo_control, 0);
}

/*
 * swapfile_pager_deallocate_internal()
 *
 * Release a reference on this pager and free it when the last
 * reference goes away.
 * Can be called with swapfile_pager_lock held or not but always returns
 * with it unlocked.
 */
void
swapfile_pager_deallocate_internal(
	swapfile_pager_t        pager,
	boolean_t               locked)
{
	if (!locked) {
		lck_mtx_lock(&swapfile_pager_lock);
	}

	/* drop a reference on this pager */
	pager->ref_count--;

	if (pager->ref_count == 1) {
		/*
		 * Only the "named" reference is left, which means that
		 * no one is really holding on to this pager anymore.
		 * Terminate it.
		 */
		swapfile_pager_dequeue(pager);
		/* the pager is all ours: no need for the lock now */
		lck_mtx_unlock(&swapfile_pager_lock);
		swapfile_pager_terminate_internal(pager);
	} else if (pager->ref_count == 0) {
		/*
		 * Dropped the existence reference;  the memory object has
		 * been terminated.  Do some final cleanup and release the
		 * pager structure.
		 */
		lck_mtx_unlock(&swapfile_pager_lock);
		if (pager->swp_pgr_hdr.mo_control != MEMORY_OBJECT_CONTROL_NULL) {
			memory_object_control_deallocate(pager->swp_pgr_hdr.mo_control);
			pager->swp_pgr_hdr.mo_control = MEMORY_OBJECT_CONTROL_NULL;
		}
		kfree(pager, sizeof(*pager));
		pager = SWAPFILE_PAGER_NULL;
	} else {
		/* there are still plenty of references:  keep going... */
		lck_mtx_unlock(&swapfile_pager_lock);
	}

	/* caution: lock is not held on return... */
}

/*
 * swapfile_pager_deallocate()
 *
 * Release a reference on this pager and free it when the last
 * reference goes away.
 */
void
swapfile_pager_deallocate(
	memory_object_t         mem_obj)
{
	swapfile_pager_t        pager;

	PAGER_DEBUG(PAGER_ALL, ("swapfile_pager_deallocate: %p\n", mem_obj));
	pager = swapfile_pager_lookup(mem_obj);
	swapfile_pager_deallocate_internal(pager, FALSE);
}

/*
 *
 */
kern_return_t
swapfile_pager_terminate(
#if !DEBUG
	__unused
#endif
	memory_object_t mem_obj)
{
	PAGER_DEBUG(PAGER_ALL, ("swapfile_pager_terminate: %p\n", mem_obj));

	return KERN_SUCCESS;
}

/*
 *
 */
kern_return_t
swapfile_pager_synchronize(
	__unused memory_object_t        mem_obbj,
	__unused memory_object_offset_t offset,
	__unused memory_object_size_t   length,
	__unused vm_sync_t              sync_flags)
{
	panic("swapfile_pager_synchronize: memory_object_synchronize no longer supported\n");
	return KERN_FAILURE;
}

/*
 * swapfile_pager_map()
 *
 * This allows VM to let us, the EMM, know that this memory object
 * is currently mapped one or more times.  This is called by VM each time
 * the memory object gets mapped and we take one extra reference on the
 * memory object to account for all its mappings.
 */
kern_return_t
swapfile_pager_map(
	memory_object_t         mem_obj,
	__unused vm_prot_t      prot)
{
	swapfile_pager_t        pager;

	PAGER_DEBUG(PAGER_ALL, ("swapfile_pager_map: %p\n", mem_obj));

	pager = swapfile_pager_lookup(mem_obj);

	lck_mtx_lock(&swapfile_pager_lock);
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
	}
	lck_mtx_unlock(&swapfile_pager_lock);

	return KERN_SUCCESS;
}

/*
 * swapfile_pager_last_unmap()
 *
 * This is called by VM when this memory object is no longer mapped anywhere.
 */
kern_return_t
swapfile_pager_last_unmap(
	memory_object_t         mem_obj)
{
	swapfile_pager_t        pager;

	PAGER_DEBUG(PAGER_ALL,
	    ("swapfile_pager_last_unmap: %p\n", mem_obj));

	pager = swapfile_pager_lookup(mem_obj);

	lck_mtx_lock(&swapfile_pager_lock);
	if (pager->is_mapped) {
		/*
		 * All the mappings are gone, so let go of the one extra
		 * reference that represents all the mappings of this pager.
		 */
		pager->is_mapped = FALSE;
		swapfile_pager_deallocate_internal(pager, TRUE);
		/* caution: deallocate_internal() released the lock ! */
	} else {
		lck_mtx_unlock(&swapfile_pager_lock);
	}

	return KERN_SUCCESS;
}


/*
 *
 */
swapfile_pager_t
swapfile_pager_lookup(
	memory_object_t  mem_obj)
{
	swapfile_pager_t        pager;

	assert(mem_obj->mo_pager_ops == &swapfile_pager_ops);
	__IGNORE_WCASTALIGN(pager = (swapfile_pager_t) mem_obj);
	assert(pager->ref_count > 0);
	return pager;
}

swapfile_pager_t
swapfile_pager_create(
	struct vnode            *vp)
{
	swapfile_pager_t        pager, pager2;
	memory_object_control_t control;
	kern_return_t           kr;

	pager = (swapfile_pager_t) kalloc(sizeof(*pager));
	if (pager == SWAPFILE_PAGER_NULL) {
		return SWAPFILE_PAGER_NULL;
	}

	/*
	 * The vm_map call takes both named entry ports and raw memory
	 * objects in the same parameter.  We need to make sure that
	 * vm_map does not see this object as a named entry port.  So,
	 * we reserve the second word in the object for a fake ip_kotype
	 * setting - that will tell vm_map to use it as a memory object.
	 */
	pager->swp_pgr_hdr.mo_ikot = IKOT_MEMORY_OBJECT;
	pager->swp_pgr_hdr.mo_pager_ops = &swapfile_pager_ops;
	pager->swp_pgr_hdr.mo_control = MEMORY_OBJECT_CONTROL_NULL;

	pager->is_ready = FALSE;/* not ready until it has a "name" */
	pager->ref_count = 1;   /* setup reference */
	pager->is_mapped = FALSE;
	pager->swapfile_vnode = vp;

	lck_mtx_lock(&swapfile_pager_lock);
	/* see if anyone raced us to create a pager for the same object */
	queue_iterate(&swapfile_pager_queue,
	    pager2,
	    swapfile_pager_t,
	    pager_queue) {
		if (pager2->swapfile_vnode == vp) {
			break;
		}
	}
	if (!queue_end(&swapfile_pager_queue,
	    (queue_entry_t) pager2)) {
		/* while we hold the lock, transfer our setup ref to winner */
		pager2->ref_count++;
		/* we lost the race, down with the loser... */
		lck_mtx_unlock(&swapfile_pager_lock);
		pager->swapfile_vnode = NULL;
		kfree(pager, sizeof(*pager));
		/* ... and go with the winner */
		pager = pager2;
		/* let the winner make sure the pager gets ready */
		return pager;
	}

	/* enter new pager at the head of our list of pagers */
	queue_enter_first(&swapfile_pager_queue,
	    pager,
	    swapfile_pager_t,
	    pager_queue);
	swapfile_pager_count++;
	if (swapfile_pager_count > swapfile_pager_count_max) {
		swapfile_pager_count_max = swapfile_pager_count;
	}
	lck_mtx_unlock(&swapfile_pager_lock);

	kr = memory_object_create_named((memory_object_t) pager,
	    0,
	    &control);
	assert(kr == KERN_SUCCESS);

	memory_object_mark_trusted(control);

	lck_mtx_lock(&swapfile_pager_lock);
	/* the new pager is now ready to be used */
	pager->is_ready = TRUE;
	lck_mtx_unlock(&swapfile_pager_lock);

	/* wakeup anyone waiting for this pager to be ready */
	thread_wakeup(&pager->is_ready);

	return pager;
}

/*
 * swapfile_pager_setup()
 *
 * Provide the caller with a memory object backed by the provided
 * "backing_object" VM object.  If such a memory object already exists,
 * re-use it, otherwise create a new memory object.
 */
memory_object_t
swapfile_pager_setup(
	struct vnode *vp)
{
	swapfile_pager_t        pager;

	lck_mtx_lock(&swapfile_pager_lock);

	queue_iterate(&swapfile_pager_queue,
	    pager,
	    swapfile_pager_t,
	    pager_queue) {
		if (pager->swapfile_vnode == vp) {
			break;
		}
	}
	if (queue_end(&swapfile_pager_queue,
	    (queue_entry_t) pager)) {
		/* no existing pager for this backing object */
		pager = SWAPFILE_PAGER_NULL;
	} else {
		/* make sure pager doesn't disappear */
		pager->ref_count++;
	}

	lck_mtx_unlock(&swapfile_pager_lock);

	if (pager == SWAPFILE_PAGER_NULL) {
		pager = swapfile_pager_create(vp);
		if (pager == SWAPFILE_PAGER_NULL) {
			return MEMORY_OBJECT_NULL;
		}
	}

	lck_mtx_lock(&swapfile_pager_lock);
	while (!pager->is_ready) {
		lck_mtx_sleep(&swapfile_pager_lock,
		    LCK_SLEEP_DEFAULT,
		    &pager->is_ready,
		    THREAD_UNINT);
	}
	lck_mtx_unlock(&swapfile_pager_lock);

	return (memory_object_t) pager;
}

memory_object_control_t
swapfile_pager_control(
	memory_object_t mem_obj)
{
	swapfile_pager_t        pager;

	if (mem_obj == MEMORY_OBJECT_NULL ||
	    mem_obj->mo_pager_ops != &swapfile_pager_ops) {
		return MEMORY_OBJECT_CONTROL_NULL;
	}
	pager = swapfile_pager_lookup(mem_obj);
	return pager->swp_pgr_hdr.mo_control;
}
