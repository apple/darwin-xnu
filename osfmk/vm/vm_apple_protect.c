/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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
#include <kern/page_decrypt.h>
#include <kern/queue.h>
#include <kern/thread.h>

#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>

#include <default_pager/default_pager_types.h>
#include <default_pager/default_pager_object_server.h>

#include <vm/vm_fault.h>
#include <vm/vm_map.h>
#include <vm/vm_pageout.h>
#include <vm/memory_object.h>
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>


/* 
 * APPLE PROTECT MEMORY PAGER 
 *
 * This external memory manager (EMM) handles memory from the encrypted
 * sections of some executables protected by the DSMOS kernel extension.
 * 
 * It mostly handles page-in requests (from memory_object_data_request()) by
 * getting the encrypted data from its backing VM object, itself backed by
 * the encrypted file, decrypting it and providing it to VM.
 *
 * The decrypted pages will never be dirtied, so the memory manager doesn't
 * need to handle page-out requests (from memory_object_data_return()).  The
 * pages need to be mapped copy-on-write, so that the originals stay clean.
 *
 * We don't expect to have to handle a large number of apple-protected
 * binaries, so the data structures are very simple (simple linked list)
 * for now.
 */

/* forward declarations */
void apple_protect_pager_reference(memory_object_t mem_obj);
void apple_protect_pager_deallocate(memory_object_t mem_obj);
kern_return_t apple_protect_pager_init(memory_object_t mem_obj,
				       memory_object_control_t control,
				       vm_size_t pg_size);
kern_return_t apple_protect_pager_terminate(memory_object_t mem_obj);
kern_return_t apple_protect_pager_data_request(memory_object_t mem_obj,
					       memory_object_offset_t offset,
					       vm_size_t length,
					       vm_prot_t protection_required,
					       memory_object_fault_info_t fault_info);
kern_return_t apple_protect_pager_data_return(memory_object_t mem_obj,
					      memory_object_offset_t offset,
					      vm_size_t	data_cnt,
					      memory_object_offset_t *resid_offset,
					      int *io_error,
					      boolean_t dirty,
					      boolean_t kernel_copy,
					      int upl_flags);
kern_return_t apple_protect_pager_data_initialize(memory_object_t mem_obj,
						  memory_object_offset_t offset,
						  vm_size_t data_cnt);
kern_return_t apple_protect_pager_data_unlock(memory_object_t mem_obj,
					      memory_object_offset_t offset,
					      vm_size_t size,
					      vm_prot_t desired_access);
kern_return_t apple_protect_pager_synchronize(memory_object_t mem_obj,
					      memory_object_offset_t offset,
					      vm_size_t length,
					      vm_sync_t sync_flags);
kern_return_t apple_protect_pager_unmap(memory_object_t mem_obj);

/*
 * Vector of VM operations for this EMM.
 * These routines are invoked by VM via the memory_object_*() interfaces.
 */
const struct memory_object_pager_ops apple_protect_pager_ops = {
	apple_protect_pager_reference,
	apple_protect_pager_deallocate,
	apple_protect_pager_init,
	apple_protect_pager_terminate,
	apple_protect_pager_data_request,
	apple_protect_pager_data_return,
	apple_protect_pager_data_initialize,
	apple_protect_pager_data_unlock,
	apple_protect_pager_synchronize,
	apple_protect_pager_unmap,
	"apple protect pager"
};

/*
 * The "apple_protect_pager" describes a memory object backed by
 * the "apple protect" EMM.
 */
typedef struct apple_protect_pager {
	memory_object_pager_ops_t pager_ops; /* == &apple_protect_pager_ops */
	unsigned int		pager_ikot;	/* JMM: fake ip_kotype() */
	queue_chain_t		pager_queue;	/* next & prev pagers */
	unsigned int		ref_count;	/* reference count */
	boolean_t		is_ready;	/* is this pager ready ? */
	boolean_t		is_mapped;	/* is this mem_obj mapped ? */
	memory_object_control_t pager_control;	/* mem object control handle */
	vm_object_t		backing_object; /* VM obj w/ encrypted data */
} *apple_protect_pager_t;
#define	APPLE_PROTECT_PAGER_NULL	((apple_protect_pager_t) NULL)

/*
 * List of memory objects managed by this EMM.
 * The list is protected by the "apple_protect_pager_lock" lock.
 */
int apple_protect_pager_count = 0;		/* number of pagers */
int apple_protect_pager_count_mapped = 0;	/* number of unmapped pagers */
queue_head_t apple_protect_pager_queue;
decl_mutex_data(,apple_protect_pager_lock)

/*
 * Maximum number of unmapped pagers we're willing to keep around.
 */
int apple_protect_pager_cache_limit = 10;

/*
 * Statistics & counters.
 */
int apple_protect_pager_count_max = 0;
int apple_protect_pager_count_unmapped_max = 0;
int apple_protect_pager_num_trim_max = 0;
int apple_protect_pager_num_trim_total = 0;

/* internal prototypes */
apple_protect_pager_t apple_protect_pager_create(vm_object_t backing_object);
apple_protect_pager_t apple_protect_pager_lookup(memory_object_t mem_obj);
void apple_protect_pager_dequeue(apple_protect_pager_t pager);
void apple_protect_pager_deallocate_internal(apple_protect_pager_t pager,
					     boolean_t locked);
void apple_protect_pager_terminate_internal(apple_protect_pager_t pager);
void apple_protect_pager_trim(void);


#if DEBUG
int apple_protect_pagerdebug = 0;
#define PAGER_ALL		0xffffffff
#define	PAGER_INIT		0x00000001
#define	PAGER_PAGEIN		0x00000002

#define PAGER_DEBUG(LEVEL, A)						\
	MACRO_BEGIN							\
	if ((apple_protect_pagerdebug & LEVEL)==LEVEL) {		\
		printf A;						\
	}								\
	MACRO_END
#else
#define PAGER_DEBUG(LEVEL, A)
#endif


void
apple_protect_pager_bootstrap(void)
{
	mutex_init(&apple_protect_pager_lock, 0);
	queue_init(&apple_protect_pager_queue);
}

/*
 * apple_protect_pager_init()
 *
 * Initialize the memory object and makes it ready to be used and mapped.
 */
kern_return_t
apple_protect_pager_init(
	memory_object_t		mem_obj, 
	memory_object_control_t	control, 
#if !DEBUG
	__unused
#endif
	vm_size_t pg_size)
{
	apple_protect_pager_t	pager;
	kern_return_t   	kr;
	memory_object_attr_info_data_t  attributes;

	PAGER_DEBUG(PAGER_ALL,
		    ("apple_protect_pager_init: %p, %p, %x\n",
		     mem_obj, control, pg_size));

	if (control == MEMORY_OBJECT_CONTROL_NULL)
		return KERN_INVALID_ARGUMENT;

	pager = apple_protect_pager_lookup(mem_obj);

	memory_object_control_reference(control);

	pager->pager_control = control;

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
		panic("apple_protect_pager_init: "
		      "memory_object_change_attributes() failed");

	return KERN_SUCCESS;
}

/*
 * apple_protect_data_return()
 *
 * Handles page-out requests from VM.  This should never happen since
 * the pages provided by this EMM are not supposed to be dirty or dirtied
 * and VM should simply discard the contents and reclaim the pages if it
 * needs to.
 */
kern_return_t
apple_protect_pager_data_return(
        __unused memory_object_t	mem_obj,
        __unused memory_object_offset_t	offset,
        __unused vm_size_t		data_cnt,
        __unused memory_object_offset_t	*resid_offset,
	__unused int			*io_error,
	__unused boolean_t		dirty,
	__unused boolean_t		kernel_copy,
	__unused int			upl_flags)  
{
	panic("apple_protect_pager_data_return: should never get called");
	return KERN_FAILURE;
}

kern_return_t
apple_protect_pager_data_initialize(
	__unused memory_object_t	mem_obj,
	__unused memory_object_offset_t	offset,
	__unused vm_size_t		data_cnt)
{
	panic("apple_protect_pager_data_initialize: should never get called");
	return KERN_FAILURE;
}

kern_return_t
apple_protect_pager_data_unlock(
	__unused memory_object_t	mem_obj,
	__unused memory_object_offset_t	offset,
	__unused vm_size_t		size,
	__unused vm_prot_t		desired_access)
{
	return KERN_FAILURE;
}

/*
 * apple_protect_pager_data_request()
 *
 * Handles page-in requests from VM.
 */
kern_return_t	
apple_protect_pager_data_request(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	vm_size_t		length,
#if !DEBUG
	__unused
#endif
	vm_prot_t		protection_required,
	memory_object_fault_info_t mo_fault_info)
{
	apple_protect_pager_t	pager;
	memory_object_control_t	mo_control;
	upl_t			upl;
	int			upl_flags;
	upl_size_t		upl_size;
	upl_page_info_t		*upl_pl;
	vm_object_t		src_object, dst_object;
	kern_return_t		kr, retval;
	vm_map_offset_t		kernel_mapping;
	vm_offset_t		src_vaddr, dst_vaddr;
	vm_offset_t		cur_offset;
	vm_map_entry_t		map_entry;
	kern_return_t		error_code;
	vm_prot_t		prot;
	vm_page_t		src_page, top_page;
	int			interruptible;
	vm_object_fault_info_t	fault_info;

	PAGER_DEBUG(PAGER_ALL, ("apple_protect_pager_data_request: %p, %llx, %x, %x\n", mem_obj, offset, length, protection_required));

	src_object = VM_OBJECT_NULL;
	kernel_mapping = 0;
	upl = NULL;
	fault_info = (vm_object_fault_info_t) mo_fault_info;
	interruptible = fault_info->interruptible;

	pager = apple_protect_pager_lookup(mem_obj);
	assert(pager->is_ready);
	assert(pager->ref_count > 1); /* pager is alive and mapped */

	PAGER_DEBUG(PAGER_PAGEIN, ("apple_protect_pager_data_request: %p, %llx, %x, %x, pager %p\n", mem_obj, offset, length, protection_required, pager));

	/*
	 * Gather in a UPL all the VM pages requested by VM.
	 */
	mo_control = pager->pager_control;

	upl_size = length;
	upl_flags =
		UPL_RET_ONLY_ABSENT |
		UPL_SET_LITE |
		UPL_NO_SYNC |
		UPL_CLEAN_IN_PLACE |	/* triggers UPL_CLEAR_DIRTY */
		UPL_SET_INTERNAL;
	kr = memory_object_upl_request(mo_control,
				       offset, upl_size,
				       &upl, NULL, NULL, upl_flags);
	if (kr != KERN_SUCCESS) {
		retval = kr;
		goto done;
	}
	dst_object = mo_control->moc_object;
	assert(dst_object != VM_OBJECT_NULL);


	/*
	 * Reserve 2 virtual pages in the kernel address space to map each
	 * source and destination physical pages when it's their turn to
	 * be processed.
	 */
	vm_object_reference(kernel_object);	/* ref. for mapping */
	kr = vm_map_find_space(kernel_map,
			       &kernel_mapping,
			       2 * PAGE_SIZE_64,
			       0,
			       0,
			       &map_entry);
	if (kr != KERN_SUCCESS) {
		vm_object_deallocate(kernel_object);
		retval = kr;
		goto done;
	}
	map_entry->object.vm_object = kernel_object;
	map_entry->offset = kernel_mapping - VM_MIN_KERNEL_ADDRESS;
	vm_map_unlock(kernel_map);
	src_vaddr = CAST_DOWN(vm_offset_t, kernel_mapping);
	dst_vaddr = CAST_DOWN(vm_offset_t, kernel_mapping + PAGE_SIZE_64);

	/*
	 * We'll map the encrypted data in the kernel address space from the 
	 * backing VM object (itself backed by the encrypted file via
	 * the vnode pager).
	 */
	src_object = pager->backing_object;
	assert(src_object != VM_OBJECT_NULL);
	vm_object_reference(src_object); /* to keep the source object alive */

	/*
	 * Fill in the contents of the pages requested by VM.
	 */
	upl_pl = UPL_GET_INTERNAL_PAGE_LIST(upl);
	for (cur_offset = 0; cur_offset < length; cur_offset += PAGE_SIZE) {
		ppnum_t dst_pnum;

		if (!upl_page_present(upl_pl, cur_offset / PAGE_SIZE)) {
			/* this page is not in the UPL: skip it */
			continue;
		}

		/*
		 * Map the source (encrypted) page in the kernel's
		 * virtual address space.
		 * We already hold a reference on the src_object.
		 */
	retry_src_fault:
		vm_object_lock(src_object);
		vm_object_paging_begin(src_object);
		error_code = 0;
		prot = VM_PROT_READ;
		kr = vm_fault_page(src_object,
				   offset + cur_offset,
				   VM_PROT_READ,
				   FALSE,
				   &prot,
				   &src_page,
				   &top_page,
				   NULL,
				   &error_code,
				   FALSE,
				   FALSE,
				   fault_info);
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
		case VM_FAULT_MEMORY_ERROR:
			/* the page is not there ! */
			if (error_code) {
				retval = error_code;
			} else {
				retval = KERN_MEMORY_ERROR;
			}
			goto done;
		default:
			retval = KERN_FAILURE;
			goto done;
		}
		assert(src_page != VM_PAGE_NULL);
		assert(src_page->busy);
		
		/*
		 * Establish an explicit mapping of the source
		 * physical page.
		 */
		pmap_enter(kernel_pmap,
			   kernel_mapping,
			   src_page->phys_page,
			   VM_PROT_READ,
			   src_object->wimg_bits & VM_WIMG_MASK,
			   TRUE);
		/*
		 * Establish an explicit pmap mapping of the destination
		 * physical page.
		 * We can't do a regular VM mapping because the VM page
		 * is "busy".
		 */
		dst_pnum = (addr64_t)
			upl_phys_page(upl_pl, cur_offset / PAGE_SIZE);
		assert(dst_pnum != 0);
		pmap_enter(kernel_pmap,
			   kernel_mapping + PAGE_SIZE_64,
			   dst_pnum,
			   VM_PROT_READ | VM_PROT_WRITE,
			   dst_object->wimg_bits & VM_WIMG_MASK,
			   TRUE);

		/*
		 * Decrypt the encrypted contents of the source page
		 * into the destination page.
		 */
		dsmos_page_transform((const void *) src_vaddr,
				     (void *) dst_vaddr);

		/*
		 * Remove the pmap mapping of the source and destination pages
		 * in the kernel.
		 */
		pmap_remove(kernel_pmap,
			    (addr64_t) kernel_mapping,
			    (addr64_t) (kernel_mapping + (2 * PAGE_SIZE_64)));

		/*
		 * Cleanup the result of vm_fault_page() of the source page.
		 */
		PAGE_WAKEUP_DONE(src_page);
		vm_object_paging_end(src_page->object);
		vm_object_unlock(src_page->object);
		if (top_page != VM_PAGE_NULL) {
			vm_object_t top_object;

			top_object = top_page->object;
			vm_object_lock(top_object);
			VM_PAGE_FREE(top_page);
			vm_object_paging_end(top_object);
			vm_object_unlock(top_object);
		}
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
			upl_commit(upl, NULL, 0);
		}

		/* and deallocate the UPL */
		upl_deallocate(upl);
		upl = NULL;
	}
	if (kernel_mapping != 0) {
		/* clean up the mapping of the source and destination pages */
		kr = vm_map_remove(kernel_map,
				   kernel_mapping,
				   kernel_mapping + (2 * PAGE_SIZE_64),
				   VM_MAP_NO_FLAGS);
		assert(kr == KERN_SUCCESS);
		kernel_mapping = 0;
		src_vaddr = 0;
		dst_vaddr = 0;
	}
	if (src_object != VM_OBJECT_NULL) {
		vm_object_deallocate(src_object);
	}

	return retval;
}

/*
 * apple_protect_pager_reference()
 *
 * Get a reference on this memory object.
 * For external usage only.  Assumes that the initial reference count is not 0,
 * i.e one should not "revive" a dead pager this way.
 */
void
apple_protect_pager_reference(
	memory_object_t		mem_obj)
{	
	apple_protect_pager_t	pager;

	pager = apple_protect_pager_lookup(mem_obj);

	mutex_lock(&apple_protect_pager_lock);
	assert(pager->ref_count > 0);
	pager->ref_count++;
	mutex_unlock(&apple_protect_pager_lock);
}


/*
 * apple_protect_pager_dequeue:
 *
 * Removes a pager from the list of pagers.
 *
 * The caller must hold "apple_protect_pager_lock".
 */
void
apple_protect_pager_dequeue(
	apple_protect_pager_t pager)
{
	assert(!pager->is_mapped);

	queue_remove(&apple_protect_pager_queue,
		     pager,
		     apple_protect_pager_t,
		     pager_queue);
	pager->pager_queue.next = NULL;
	pager->pager_queue.prev = NULL;
	
	apple_protect_pager_count--;
}

/*
 * apple_protect_pager_terminate_internal:
 *
 * Trigger the asynchronous termination of the memory object associated
 * with this pager.
 * When the memory object is terminated, there will be one more call
 * to memory_object_deallocate() (i.e. apple_protect_pager_deallocate())
 * to finish the clean up.
 *
 * "apple_protect_pager_lock" should not be held by the caller.
 * We don't need the lock because the pager has already been removed from
 * the pagers' list and is now ours exclusively.
 */
void
apple_protect_pager_terminate_internal(
	apple_protect_pager_t pager)
{
	assert(pager->is_ready);
	assert(!pager->is_mapped);

	if (pager->backing_object != VM_OBJECT_NULL) {
		vm_object_deallocate(pager->backing_object);
		pager->backing_object = VM_OBJECT_NULL;
	}

	/* trigger the destruction of the memory object */
	memory_object_destroy(pager->pager_control, 0);
}

/*
 * apple_protect_pager_deallocate_internal()
 *
 * Release a reference on this pager and free it when the last
 * reference goes away.
 * Can be called with apple_protect_pager_lock held or not but always returns
 * with it unlocked.
 */
void
apple_protect_pager_deallocate_internal(
	apple_protect_pager_t	pager,
	boolean_t		locked)
{
	boolean_t	needs_trimming;
	int		count_unmapped;

	if (! locked) {
		mutex_lock(&apple_protect_pager_lock);
	}

	count_unmapped = (apple_protect_pager_count - 
			  apple_protect_pager_count_mapped);
	if (count_unmapped > apple_protect_pager_cache_limit) {
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
		apple_protect_pager_dequeue(pager);
		/* the pager is all ours: no need for the lock now */
		mutex_unlock(&apple_protect_pager_lock);
		apple_protect_pager_terminate_internal(pager);
	} else if (pager->ref_count == 0) {
		/*
		 * Dropped the existence reference;  the memory object has
		 * been terminated.  Do some final cleanup and release the
		 * pager structure.
		 */
		mutex_unlock(&apple_protect_pager_lock);
		if (pager->pager_control != MEMORY_OBJECT_CONTROL_NULL) {
			memory_object_control_deallocate(pager->pager_control);
			pager->pager_control = MEMORY_OBJECT_CONTROL_NULL;
		}
		kfree(pager, sizeof (*pager));
		pager = APPLE_PROTECT_PAGER_NULL;
	} else {
		/* there are still plenty of references:  keep going... */
		mutex_unlock(&apple_protect_pager_lock);
	}

	if (needs_trimming) {
		apple_protect_pager_trim();
	}
	/* caution: lock is not held on return... */
}

/*
 * apple_protect_pager_deallocate()
 *
 * Release a reference on this pager and free it when the last
 * reference goes away.
 */
void
apple_protect_pager_deallocate(
	memory_object_t		mem_obj)
{
	apple_protect_pager_t	pager;

	PAGER_DEBUG(PAGER_ALL, ("apple_protect_pager_deallocate: %p\n", mem_obj));
	pager = apple_protect_pager_lookup(mem_obj);
	apple_protect_pager_deallocate_internal(pager, FALSE);
}

/*
 *
 */
kern_return_t
apple_protect_pager_terminate(
#if !DEBUG
	__unused
#endif
	memory_object_t	mem_obj)
{
	PAGER_DEBUG(PAGER_ALL, ("apple_protect_pager_terminate: %p\n", mem_obj));

	return KERN_SUCCESS;
}

/*
 *
 */
kern_return_t
apple_protect_pager_synchronize(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	vm_size_t		length,
	__unused vm_sync_t		sync_flags)
{
	apple_protect_pager_t	pager;

	PAGER_DEBUG(PAGER_ALL, ("apple_protect_pager_synchronize: %p\n", mem_obj));

	pager = apple_protect_pager_lookup(mem_obj);

	memory_object_synchronize_completed(pager->pager_control,
					    offset, length);

	return KERN_SUCCESS;
}

/*
 * apple_protect_pager_map()
 *
 * This allows VM to let us, the EMM, know that this memory object
 * is currently mapped one or more times.  This is called by VM only the first
 * time the memory object gets mapped and we take one extra reference on the
 * memory object to account for all its mappings.
 */
void
apple_protect_pager_map(
	memory_object_t		mem_obj)
{
	apple_protect_pager_t	pager;

	PAGER_DEBUG(PAGER_ALL, ("apple_protect_pager_map: %p\n", mem_obj));

	pager = apple_protect_pager_lookup(mem_obj);

	mutex_lock(&apple_protect_pager_lock);
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
		apple_protect_pager_count_mapped++;
	}
	mutex_unlock(&apple_protect_pager_lock);
}

/*
 * apple_protect_pager_unmap()
 *
 * This is called by VM when this memory object is no longer mapped anywhere.
 */
kern_return_t
apple_protect_pager_unmap(
	memory_object_t		mem_obj)
{
	apple_protect_pager_t	pager;
	int			count_unmapped;

	PAGER_DEBUG(PAGER_ALL, ("apple_protect_pager_unmap: %p\n", mem_obj));

	pager = apple_protect_pager_lookup(mem_obj);

	mutex_lock(&apple_protect_pager_lock);
	if (pager->is_mapped) {
		/*
		 * All the mappings are gone, so let go of the one extra
		 * reference that represents all the mappings of this pager.
		 */
		apple_protect_pager_count_mapped--;
		count_unmapped = (apple_protect_pager_count -
				  apple_protect_pager_count_mapped);
		if (count_unmapped > apple_protect_pager_count_unmapped_max) {
			apple_protect_pager_count_unmapped_max = count_unmapped;
		}
		pager->is_mapped = FALSE;
		apple_protect_pager_deallocate_internal(pager, TRUE);
		/* caution: deallocate_internal() released the lock ! */
	} else {
		mutex_unlock(&apple_protect_pager_lock);
	}
	
	return KERN_SUCCESS;
}


/*
 *
 */
apple_protect_pager_t
apple_protect_pager_lookup(
	memory_object_t	 mem_obj)
{
	apple_protect_pager_t	pager;

	pager = (apple_protect_pager_t) mem_obj;
	assert(pager->pager_ops == &apple_protect_pager_ops);
	assert(pager->ref_count > 0);
	return pager;
}

apple_protect_pager_t
apple_protect_pager_create(
	vm_object_t	backing_object)
{
	apple_protect_pager_t	pager, pager2;
	memory_object_control_t	control;
	kern_return_t		kr;

	pager = (apple_protect_pager_t) kalloc(sizeof (*pager));
	if (pager == APPLE_PROTECT_PAGER_NULL) {
		return APPLE_PROTECT_PAGER_NULL;
	}

	/*
	 * The vm_map call takes both named entry ports and raw memory
	 * objects in the same parameter.  We need to make sure that
	 * vm_map does not see this object as a named entry port.  So,
	 * we reserve the second word in the object for a fake ip_kotype
	 * setting - that will tell vm_map to use it as a memory object.
	 */
	pager->pager_ops = &apple_protect_pager_ops;
	pager->pager_ikot = IKOT_MEMORY_OBJECT;
	pager->is_ready = FALSE;/* not ready until it has a "name" */
	pager->ref_count = 2;	/* existence + setup reference */
	pager->is_mapped = FALSE;
	pager->pager_control = MEMORY_OBJECT_CONTROL_NULL;
	pager->backing_object = backing_object;
	vm_object_reference(backing_object);

	mutex_lock(&apple_protect_pager_lock);
	/* see if anyone raced us to create a pager for the same object */
	queue_iterate(&apple_protect_pager_queue,
		      pager2,
		      apple_protect_pager_t,
		      pager_queue) {
		if (pager2->backing_object == backing_object) {
			break;
		}
	}
	if (! queue_end(&apple_protect_pager_queue,
			(queue_entry_t) pager2)) {
		/* while we hold the lock, transfer our setup ref to winner */
		pager2->ref_count++;
		/* we lost the race, down with the loser... */
		mutex_unlock(&apple_protect_pager_lock);
		vm_object_deallocate(pager->backing_object);
		pager->backing_object = VM_OBJECT_NULL;
		kfree(pager, sizeof (*pager));
		/* ... and go with the winner */
		pager = pager2;
		/* let the winner make sure the pager gets ready */
		return pager;
	}

	/* enter new pager at the head of our list of pagers */
	queue_enter_first(&apple_protect_pager_queue,
			  pager,
			  apple_protect_pager_t,
			  pager_queue);
	apple_protect_pager_count++;
	if (apple_protect_pager_count > apple_protect_pager_count_max) {
		apple_protect_pager_count_max = apple_protect_pager_count;
	}
	mutex_unlock(&apple_protect_pager_lock);

	kr = memory_object_create_named((memory_object_t) pager,
					0,
					&control);
	assert(kr == KERN_SUCCESS);

	mutex_lock(&apple_protect_pager_lock);
	/* the new pager is now ready to be used */
	pager->is_ready = TRUE;
	mutex_unlock(&apple_protect_pager_lock);

	/* wakeup anyone waiting for this pager to be ready */
	thread_wakeup(&pager->is_ready);

	return pager;
}

/*
 * apple_protect_pager_setup()
 *
 * Provide the caller with a memory object backed by the provided
 * "backing_object" VM object.  If such a memory object already exists,
 * re-use it, otherwise create a new memory object.
 */
memory_object_t
apple_protect_pager_setup(
	vm_object_t	backing_object)
{
	apple_protect_pager_t	pager;

	mutex_lock(&apple_protect_pager_lock);

	queue_iterate(&apple_protect_pager_queue,
		      pager,
		      apple_protect_pager_t,
		      pager_queue) {
		if (pager->backing_object == backing_object) {
			break;
		}
	}
	if (queue_end(&apple_protect_pager_queue,
		      (queue_entry_t) pager)) {
		/* no existing pager for this backing object */
		pager = APPLE_PROTECT_PAGER_NULL;
	} else {
		/* make sure pager doesn't disappear */
		pager->ref_count++;
	}

	mutex_unlock(&apple_protect_pager_lock);

	if (pager == APPLE_PROTECT_PAGER_NULL) {
		pager = apple_protect_pager_create(backing_object);
		if (pager == APPLE_PROTECT_PAGER_NULL) {
			return MEMORY_OBJECT_NULL;
		}
	}

	mutex_lock(&apple_protect_pager_lock);
	while (!pager->is_ready) {
		thread_sleep_mutex(&pager->is_ready,
				   &apple_protect_pager_lock,
				   THREAD_UNINT);
	}
	mutex_unlock(&apple_protect_pager_lock);

	return (memory_object_t) pager;
}	

void
apple_protect_pager_trim(void)
{
	apple_protect_pager_t	pager, prev_pager;
	queue_head_t		trim_queue;
	int			num_trim;
	int			count_unmapped;

	mutex_lock(&apple_protect_pager_lock);

	/*
	 * We have too many pagers, try and trim some unused ones,
	 * starting with the oldest pager at the end of the queue.
	 */
	queue_init(&trim_queue);
	num_trim = 0;

	for (pager = (apple_protect_pager_t)
		     queue_last(&apple_protect_pager_queue);
	     !queue_end(&apple_protect_pager_queue,
			(queue_entry_t) pager);
	     pager = prev_pager) {
		/* get prev elt before we dequeue */
		prev_pager = (apple_protect_pager_t)
			queue_prev(&pager->pager_queue);

		if (pager->ref_count == 2 &&
		    pager->is_ready &&
		    !pager->is_mapped) {
			/* this pager can be trimmed */
			num_trim++;
			/* remove this pager from the main list ... */
			apple_protect_pager_dequeue(pager);
			/* ... and add it to our trim queue */
			queue_enter_first(&trim_queue,
					  pager,
					  apple_protect_pager_t,
					  pager_queue);

			count_unmapped = (apple_protect_pager_count -
					  apple_protect_pager_count_mapped);
			if (count_unmapped <= apple_protect_pager_cache_limit) {
				/* we have enough pagers to trim */
				break;
			}
		}
	}
	if (num_trim > apple_protect_pager_num_trim_max) {
		apple_protect_pager_num_trim_max = num_trim;
	}
	apple_protect_pager_num_trim_total += num_trim;

	mutex_unlock(&apple_protect_pager_lock);

	/* terminate the trimmed pagers */
	while (!queue_empty(&trim_queue)) {
		queue_remove_first(&trim_queue,
				   pager,
				   apple_protect_pager_t,
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
		apple_protect_pager_terminate_internal(pager);
	}
}
