/*
 * Copyright (c) 2014 Apple Computer, Inc. All rights reserved.
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
#include <kern/ipc_kobject.h>

#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>

#include <vm/vm_fault.h>
#include <vm/vm_map.h>
#include <vm/vm_pageout.h>
#include <vm/memory_object.h>
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>
#include <vm/vm_kern.h>


/* 
 * 4K MEMORY PAGER 
 *
 * This external memory manager (EMM) handles memory mappings that are
 * 4K-aligned but not page-aligned and can therefore not be mapped directly.
 * 
 * It mostly handles page-in requests (from memory_object_data_request()) by
 * getting the data needed to fill in each 4K-chunk.  That can require
 * getting data from one or two pages from its backing VM object
 * (a file or a "apple-protected" pager backed by an encrypted file), and
 * copies the data to another page so that it is aligned as expected by
 * the mapping.
 *
 * Returned pages can never be dirtied and must always be mapped copy-on-write,
 * so the memory manager does not need to handle page-out requests (from
 * memory_object_data_return()).
 *
 */

/* forward declarations */
void fourk_pager_reference(memory_object_t mem_obj);
void fourk_pager_deallocate(memory_object_t mem_obj);
kern_return_t fourk_pager_init(memory_object_t mem_obj,
				 memory_object_control_t control,
				 memory_object_cluster_size_t pg_size);
kern_return_t fourk_pager_terminate(memory_object_t mem_obj);
kern_return_t fourk_pager_data_request(memory_object_t mem_obj,
					 memory_object_offset_t offset,
					 memory_object_cluster_size_t length,
					 vm_prot_t protection_required,
					 memory_object_fault_info_t fault_info);
kern_return_t fourk_pager_data_return(memory_object_t mem_obj,
					memory_object_offset_t offset,
					memory_object_cluster_size_t	data_cnt,
					memory_object_offset_t *resid_offset,
					int *io_error,
					boolean_t dirty,
					boolean_t kernel_copy,
					int upl_flags);
kern_return_t fourk_pager_data_initialize(memory_object_t mem_obj,
					    memory_object_offset_t offset,
					    memory_object_cluster_size_t data_cnt);
kern_return_t fourk_pager_data_unlock(memory_object_t mem_obj,
					memory_object_offset_t offset,
					memory_object_size_t size,
					vm_prot_t desired_access);
kern_return_t fourk_pager_synchronize(memory_object_t mem_obj,
					memory_object_offset_t offset,
					memory_object_size_t length,
					vm_sync_t sync_flags);
kern_return_t fourk_pager_map(memory_object_t mem_obj,
				vm_prot_t prot);
kern_return_t fourk_pager_last_unmap(memory_object_t mem_obj);

/*
 * Vector of VM operations for this EMM.
 * These routines are invoked by VM via the memory_object_*() interfaces.
 */
const struct memory_object_pager_ops fourk_pager_ops = {
	fourk_pager_reference,
	fourk_pager_deallocate,
	fourk_pager_init,
	fourk_pager_terminate,
	fourk_pager_data_request,
	fourk_pager_data_return,
	fourk_pager_data_initialize,
	fourk_pager_data_unlock,
	fourk_pager_synchronize,
	fourk_pager_map,
	fourk_pager_last_unmap,
	NULL, /* data_reclaim */
	"fourk_pager"
};

/*
 * The "fourk_pager" describes a memory object backed by
 * the "4K" EMM.
 */
#define FOURK_PAGER_SLOTS 4	/* 16K / 4K */
typedef struct fourk_pager_backing {
	vm_object_t		backing_object;
	vm_object_offset_t	backing_offset;
} *fourk_pager_backing_t;
typedef struct fourk_pager {
	struct ipc_object_header	pager_header;	/* fake ip_kotype() */
	memory_object_pager_ops_t pager_ops; /* == &fourk_pager_ops */
	memory_object_control_t pager_control;	/* mem object control handle */
	queue_chain_t		pager_queue;	/* next & prev pagers */
	unsigned int		ref_count;	/* reference count */
	int	is_ready;	/* is this pager ready ? */
	int	is_mapped;	/* is this mem_obj mapped ? */
	struct fourk_pager_backing slots[FOURK_PAGER_SLOTS]; /* backing for each
								4K-chunk */
} *fourk_pager_t;
#define	FOURK_PAGER_NULL	((fourk_pager_t) NULL)
#define pager_ikot pager_header.io_bits

/*
 * List of memory objects managed by this EMM.
 * The list is protected by the "fourk_pager_lock" lock.
 */
int fourk_pager_count = 0;		/* number of pagers */
int fourk_pager_count_mapped = 0;	/* number of unmapped pagers */
queue_head_t fourk_pager_queue;
decl_lck_mtx_data(,fourk_pager_lock)

/*
 * Maximum number of unmapped pagers we're willing to keep around.
 */
int fourk_pager_cache_limit = 0;

/*
 * Statistics & counters.
 */
int fourk_pager_count_max = 0;
int fourk_pager_count_unmapped_max = 0;
int fourk_pager_num_trim_max = 0;
int fourk_pager_num_trim_total = 0;


lck_grp_t	fourk_pager_lck_grp;
lck_grp_attr_t	fourk_pager_lck_grp_attr;
lck_attr_t	fourk_pager_lck_attr;


/* internal prototypes */
fourk_pager_t fourk_pager_lookup(memory_object_t mem_obj);
void fourk_pager_dequeue(fourk_pager_t pager);
void fourk_pager_deallocate_internal(fourk_pager_t pager,
				       boolean_t locked);
void fourk_pager_terminate_internal(fourk_pager_t pager);
void fourk_pager_trim(void);


#if DEBUG
int fourk_pagerdebug = 0;
#define PAGER_ALL		0xffffffff
#define	PAGER_INIT		0x00000001
#define	PAGER_PAGEIN		0x00000002

#define PAGER_DEBUG(LEVEL, A)						\
	MACRO_BEGIN							\
	if ((fourk_pagerdebug & LEVEL)==LEVEL) {		\
		printf A;						\
	}								\
	MACRO_END
#else
#define PAGER_DEBUG(LEVEL, A)
#endif


void
fourk_pager_bootstrap(void)
{
	lck_grp_attr_setdefault(&fourk_pager_lck_grp_attr);
	lck_grp_init(&fourk_pager_lck_grp, "4K-pager", &fourk_pager_lck_grp_attr);
	lck_attr_setdefault(&fourk_pager_lck_attr);
	lck_mtx_init(&fourk_pager_lock, &fourk_pager_lck_grp, &fourk_pager_lck_attr);
	queue_init(&fourk_pager_queue);
}

/*
 * fourk_pager_init()
 *
 * Initialize the memory object and makes it ready to be used and mapped.
 */
kern_return_t
fourk_pager_init(
	memory_object_t		mem_obj, 
	memory_object_control_t	control, 
#if !DEBUG
	__unused
#endif
	memory_object_cluster_size_t pg_size)
{
	fourk_pager_t	pager;
	kern_return_t   	kr;
	memory_object_attr_info_data_t  attributes;

	PAGER_DEBUG(PAGER_ALL,
		    ("fourk_pager_init: %p, %p, %x\n",
		     mem_obj, control, pg_size));

	if (control == MEMORY_OBJECT_CONTROL_NULL)
		return KERN_INVALID_ARGUMENT;

	pager = fourk_pager_lookup(mem_obj);

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
		panic("fourk_pager_init: "
		      "memory_object_change_attributes() failed");

#if CONFIG_SECLUDED_MEMORY
	if (secluded_for_filecache) {
		memory_object_mark_eligible_for_secluded(control, TRUE);
	}
#endif /* CONFIG_SECLUDED_MEMORY */

	return KERN_SUCCESS;
}

/*
 * fourk_pager_data_return()
 *
 * Handles page-out requests from VM.  This should never happen since
 * the pages provided by this EMM are not supposed to be dirty or dirtied
 * and VM should simply discard the contents and reclaim the pages if it
 * needs to.
 */
kern_return_t
fourk_pager_data_return(
        __unused memory_object_t	mem_obj,
        __unused memory_object_offset_t	offset,
        __unused memory_object_cluster_size_t		data_cnt,
        __unused memory_object_offset_t	*resid_offset,
	__unused int			*io_error,
	__unused boolean_t		dirty,
	__unused boolean_t		kernel_copy,
	__unused int			upl_flags)  
{
	panic("fourk_pager_data_return: should never get called");
	return KERN_FAILURE;
}

kern_return_t
fourk_pager_data_initialize(
	__unused memory_object_t	mem_obj,
	__unused memory_object_offset_t	offset,
	__unused memory_object_cluster_size_t		data_cnt)
{
	panic("fourk_pager_data_initialize: should never get called");
	return KERN_FAILURE;
}

kern_return_t
fourk_pager_data_unlock(
	__unused memory_object_t	mem_obj,
	__unused memory_object_offset_t	offset,
	__unused memory_object_size_t		size,
	__unused vm_prot_t		desired_access)
{
	return KERN_FAILURE;
}

/*
 * fourk_pager_reference()
 *
 * Get a reference on this memory object.
 * For external usage only.  Assumes that the initial reference count is not 0,
 * i.e one should not "revive" a dead pager this way.
 */
void
fourk_pager_reference(
	memory_object_t		mem_obj)
{	
	fourk_pager_t	pager;

	pager = fourk_pager_lookup(mem_obj);

	lck_mtx_lock(&fourk_pager_lock);
	assert(pager->ref_count > 0);
	pager->ref_count++;
	lck_mtx_unlock(&fourk_pager_lock);
}


/*
 * fourk_pager_dequeue:
 *
 * Removes a pager from the list of pagers.
 *
 * The caller must hold "fourk_pager_lock".
 */
void
fourk_pager_dequeue(
	fourk_pager_t pager)
{
	assert(!pager->is_mapped);

	queue_remove(&fourk_pager_queue,
		     pager,
		     fourk_pager_t,
		     pager_queue);
	pager->pager_queue.next = NULL;
	pager->pager_queue.prev = NULL;
	
	fourk_pager_count--;
}

/*
 * fourk_pager_terminate_internal:
 *
 * Trigger the asynchronous termination of the memory object associated
 * with this pager.
 * When the memory object is terminated, there will be one more call
 * to memory_object_deallocate() (i.e. fourk_pager_deallocate())
 * to finish the clean up.
 *
 * "fourk_pager_lock" should not be held by the caller.
 * We don't need the lock because the pager has already been removed from
 * the pagers' list and is now ours exclusively.
 */
void
fourk_pager_terminate_internal(
	fourk_pager_t pager)
{
	int i;

	assert(pager->is_ready);
	assert(!pager->is_mapped);

	for (i = 0; i < FOURK_PAGER_SLOTS; i++) {
		if (pager->slots[i].backing_object != VM_OBJECT_NULL &&
		    pager->slots[i].backing_object != (vm_object_t) -1) {
			vm_object_deallocate(pager->slots[i].backing_object);
			pager->slots[i].backing_object = (vm_object_t) -1;
			pager->slots[i].backing_offset = (vm_object_offset_t) -1;
		}
	}
	
	/* trigger the destruction of the memory object */
	memory_object_destroy(pager->pager_control, 0);
}

/*
 * fourk_pager_deallocate_internal()
 *
 * Release a reference on this pager and free it when the last
 * reference goes away.
 * Can be called with fourk_pager_lock held or not but always returns
 * with it unlocked.
 */
void
fourk_pager_deallocate_internal(
	fourk_pager_t	pager,
	boolean_t		locked)
{
	boolean_t	needs_trimming;
	int		count_unmapped;

	if (! locked) {
		lck_mtx_lock(&fourk_pager_lock);
	}

	count_unmapped = (fourk_pager_count - 
			  fourk_pager_count_mapped);
	if (count_unmapped > fourk_pager_cache_limit) {
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
		fourk_pager_dequeue(pager);
		/* the pager is all ours: no need for the lock now */
		lck_mtx_unlock(&fourk_pager_lock);
		fourk_pager_terminate_internal(pager);
	} else if (pager->ref_count == 0) {
		/*
		 * Dropped the existence reference;  the memory object has
		 * been terminated.  Do some final cleanup and release the
		 * pager structure.
		 */
		lck_mtx_unlock(&fourk_pager_lock);
		if (pager->pager_control != MEMORY_OBJECT_CONTROL_NULL) {
			memory_object_control_deallocate(pager->pager_control);
			pager->pager_control = MEMORY_OBJECT_CONTROL_NULL;
		}
		kfree(pager, sizeof (*pager));
		pager = FOURK_PAGER_NULL;
	} else {
		/* there are still plenty of references:  keep going... */
		lck_mtx_unlock(&fourk_pager_lock);
	}

	if (needs_trimming) {
		fourk_pager_trim();
	}
	/* caution: lock is not held on return... */
}

/*
 * fourk_pager_deallocate()
 *
 * Release a reference on this pager and free it when the last
 * reference goes away.
 */
void
fourk_pager_deallocate(
	memory_object_t		mem_obj)
{
	fourk_pager_t	pager;

	PAGER_DEBUG(PAGER_ALL, ("fourk_pager_deallocate: %p\n", mem_obj));
	pager = fourk_pager_lookup(mem_obj);
	fourk_pager_deallocate_internal(pager, FALSE);
}

/*
 *
 */
kern_return_t
fourk_pager_terminate(
#if !DEBUG
	__unused
#endif
	memory_object_t	mem_obj)
{
	PAGER_DEBUG(PAGER_ALL, ("fourk_pager_terminate: %p\n", mem_obj));

	return KERN_SUCCESS;
}

/*
 *
 */
kern_return_t
fourk_pager_synchronize(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	memory_object_size_t		length,
	__unused vm_sync_t		sync_flags)
{
	fourk_pager_t	pager;

	PAGER_DEBUG(PAGER_ALL, ("fourk_pager_synchronize: %p\n", mem_obj));

	pager = fourk_pager_lookup(mem_obj);

	memory_object_synchronize_completed(pager->pager_control,
					    offset, length);

	return KERN_SUCCESS;
}

/*
 * fourk_pager_map()
 *
 * This allows VM to let us, the EMM, know that this memory object
 * is currently mapped one or more times.  This is called by VM each time
 * the memory object gets mapped and we take one extra reference on the
 * memory object to account for all its mappings.
 */
kern_return_t
fourk_pager_map(
	memory_object_t		mem_obj,
	__unused vm_prot_t	prot)
{
	fourk_pager_t	pager;

	PAGER_DEBUG(PAGER_ALL, ("fourk_pager_map: %p\n", mem_obj));

	pager = fourk_pager_lookup(mem_obj);

	lck_mtx_lock(&fourk_pager_lock);
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
		fourk_pager_count_mapped++;
	}
	lck_mtx_unlock(&fourk_pager_lock);

	return KERN_SUCCESS;
}

/*
 * fourk_pager_last_unmap()
 *
 * This is called by VM when this memory object is no longer mapped anywhere.
 */
kern_return_t
fourk_pager_last_unmap(
	memory_object_t		mem_obj)
{
	fourk_pager_t	pager;
	int			count_unmapped;

	PAGER_DEBUG(PAGER_ALL,
		    ("fourk_pager_last_unmap: %p\n", mem_obj));

	pager = fourk_pager_lookup(mem_obj);

	lck_mtx_lock(&fourk_pager_lock);
	if (pager->is_mapped) {
		/*
		 * All the mappings are gone, so let go of the one extra
		 * reference that represents all the mappings of this pager.
		 */
		fourk_pager_count_mapped--;
		count_unmapped = (fourk_pager_count -
				  fourk_pager_count_mapped);
		if (count_unmapped > fourk_pager_count_unmapped_max) {
			fourk_pager_count_unmapped_max = count_unmapped;
		}
		pager->is_mapped = FALSE;
		fourk_pager_deallocate_internal(pager, TRUE);
		/* caution: deallocate_internal() released the lock ! */
	} else {
		lck_mtx_unlock(&fourk_pager_lock);
	}
	
	return KERN_SUCCESS;
}


/*
 *
 */
fourk_pager_t
fourk_pager_lookup(
	memory_object_t	 mem_obj)
{
	fourk_pager_t	pager;

	pager = (fourk_pager_t) mem_obj;
	assert(pager->pager_ops == &fourk_pager_ops);
	assert(pager->ref_count > 0);
	return pager;
}

void
fourk_pager_trim(void)
{
	fourk_pager_t	pager, prev_pager;
	queue_head_t		trim_queue;
	int			num_trim;
	int			count_unmapped;

	lck_mtx_lock(&fourk_pager_lock);

	/*
	 * We have too many pagers, try and trim some unused ones,
	 * starting with the oldest pager at the end of the queue.
	 */
	queue_init(&trim_queue);
	num_trim = 0;

	for (pager = (fourk_pager_t)
		     queue_last(&fourk_pager_queue);
	     !queue_end(&fourk_pager_queue,
			(queue_entry_t) pager);
	     pager = prev_pager) {
		/* get prev elt before we dequeue */
		prev_pager = (fourk_pager_t)
			queue_prev(&pager->pager_queue);

		if (pager->ref_count == 2 &&
		    pager->is_ready &&
		    !pager->is_mapped) {
			/* this pager can be trimmed */
			num_trim++;
			/* remove this pager from the main list ... */
			fourk_pager_dequeue(pager);
			/* ... and add it to our trim queue */
			queue_enter_first(&trim_queue,
					  pager,
					  fourk_pager_t,
					  pager_queue);

			count_unmapped = (fourk_pager_count -
					  fourk_pager_count_mapped);
			if (count_unmapped <= fourk_pager_cache_limit) {
				/* we have enough pagers to trim */
				break;
			}
		}
	}
	if (num_trim > fourk_pager_num_trim_max) {
		fourk_pager_num_trim_max = num_trim;
	}
	fourk_pager_num_trim_total += num_trim;

	lck_mtx_unlock(&fourk_pager_lock);

	/* terminate the trimmed pagers */
	while (!queue_empty(&trim_queue)) {
		queue_remove_first(&trim_queue,
				   pager,
				   fourk_pager_t,
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
		fourk_pager_terminate_internal(pager);
	}
}






vm_object_t
fourk_pager_to_vm_object(
	memory_object_t	mem_obj)
{
	fourk_pager_t	pager;
	vm_object_t	object;

	pager = fourk_pager_lookup(mem_obj);
	if (pager == NULL) {
		return VM_OBJECT_NULL;
	}

	assert(pager->ref_count > 0);
	assert(pager->pager_control != MEMORY_OBJECT_CONTROL_NULL);
	object = memory_object_control_to_vm_object(pager->pager_control);
	assert(object != VM_OBJECT_NULL);
	return object;
}

memory_object_t
fourk_pager_create(void)
{
	fourk_pager_t		pager;
	memory_object_control_t	control;
	kern_return_t		kr;
	int			i;

#if 00
	if (PAGE_SIZE_64 == FOURK_PAGE_SIZE) {
		panic("fourk_pager_create: page size is 4K !?");
	}
#endif

	pager = (fourk_pager_t) kalloc(sizeof (*pager));
	if (pager == FOURK_PAGER_NULL) {
		return MEMORY_OBJECT_NULL;
	}
	bzero(pager, sizeof (*pager));

	/*
	 * The vm_map call takes both named entry ports and raw memory
	 * objects in the same parameter.  We need to make sure that
	 * vm_map does not see this object as a named entry port.  So,
	 * we reserve the first word in the object for a fake ip_kotype
	 * setting - that will tell vm_map to use it as a memory object.
	 */
	pager->pager_ops = &fourk_pager_ops;
	pager->pager_ikot = IKOT_MEMORY_OBJECT;
	pager->pager_control = MEMORY_OBJECT_CONTROL_NULL;
	pager->ref_count = 2;	/* existence + setup reference */
	pager->is_ready = FALSE;/* not ready until it has a "name" */
	pager->is_mapped = FALSE;

	for (i = 0; i < FOURK_PAGER_SLOTS; i++) {
		pager->slots[i].backing_object = (vm_object_t) -1;
		pager->slots[i].backing_offset = (vm_object_offset_t) -1;
	}
	
	lck_mtx_lock(&fourk_pager_lock);

	/* enter new pager at the head of our list of pagers */
	queue_enter_first(&fourk_pager_queue,
			  pager,
			  fourk_pager_t,
			  pager_queue);
	fourk_pager_count++;
	if (fourk_pager_count > fourk_pager_count_max) {
		fourk_pager_count_max = fourk_pager_count;
	}
	lck_mtx_unlock(&fourk_pager_lock);

	kr = memory_object_create_named((memory_object_t) pager,
					0,
					&control);
	assert(kr == KERN_SUCCESS);

	lck_mtx_lock(&fourk_pager_lock);
	/* the new pager is now ready to be used */
	pager->is_ready = TRUE;
	lck_mtx_unlock(&fourk_pager_lock);

	/* wakeup anyone waiting for this pager to be ready */
	thread_wakeup(&pager->is_ready);

	return (memory_object_t) pager;
}

/*
 * fourk_pager_data_request()
 *
 * Handles page-in requests from VM.
 */
int fourk_pager_data_request_debug = 0;
kern_return_t	
fourk_pager_data_request(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	memory_object_cluster_size_t		length,
#if !DEBUG
	__unused
#endif
	vm_prot_t		protection_required,
	memory_object_fault_info_t mo_fault_info)
{
	fourk_pager_t		pager;
	memory_object_control_t	mo_control;
	upl_t			upl;
	int			upl_flags;
	upl_size_t		upl_size;
	upl_page_info_t		*upl_pl;
	unsigned int		pl_count;
	vm_object_t		dst_object;
	kern_return_t		kr, retval;
	vm_map_offset_t		kernel_mapping;
	vm_offset_t		src_vaddr, dst_vaddr;
	vm_offset_t		cur_offset;
	int			sub_page;
	int			sub_page_idx, sub_page_cnt;

	pager = fourk_pager_lookup(mem_obj);
	assert(pager->is_ready);
	assert(pager->ref_count > 1); /* pager is alive and mapped */

	PAGER_DEBUG(PAGER_PAGEIN, ("fourk_pager_data_request: %p, %llx, %x, %x, pager %p\n", mem_obj, offset, length, protection_required, pager));

	retval = KERN_SUCCESS;
	kernel_mapping = 0;

	offset = memory_object_trunc_page(offset);

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
	pl_count = 0;
	kr = memory_object_upl_request(mo_control,
				       offset, upl_size,
				       &upl, NULL, NULL, upl_flags);
	if (kr != KERN_SUCCESS) {
		retval = kr;
		goto done;
	}
	dst_object = mo_control->moc_object;
	assert(dst_object != VM_OBJECT_NULL);

#if __x86_64__ || __arm__ || __arm64__
	/* use the 1-to-1 mapping of physical memory */
#else /* __x86_64__ || __arm__ || __arm64__ */
	/*
	 * Reserve 2 virtual pages in the kernel address space to map the
	 * source and destination physical pages when it's their turn to
	 * be processed.
	 */
	vm_map_entry_t		map_entry;

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
	map_entry->offset = kernel_mapping;
	vm_map_unlock(kernel_map);
	src_vaddr = CAST_DOWN(vm_offset_t, kernel_mapping);
	dst_vaddr = CAST_DOWN(vm_offset_t, kernel_mapping + PAGE_SIZE_64);
#endif /* __x86_64__ || __arm__ || __arm64__ */

	/*
	 * Fill in the contents of the pages requested by VM.
	 */
	upl_pl = UPL_GET_INTERNAL_PAGE_LIST(upl);
	pl_count = length / PAGE_SIZE;
	for (cur_offset = 0;
	     retval == KERN_SUCCESS && cur_offset < length;
	     cur_offset += PAGE_SIZE) {
		ppnum_t dst_pnum;
		int num_subpg_signed, num_subpg_validated;
		int num_subpg_tainted, num_subpg_nx;

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
#if __x86_64__
		dst_vaddr = (vm_map_offset_t)
			PHYSMAP_PTOV((pmap_paddr_t)dst_pnum << PAGE_SHIFT);
#else
		pmap_enter(kernel_pmap,
			   dst_vaddr,
			   dst_pnum,
			   VM_PROT_READ | VM_PROT_WRITE,
			   VM_PROT_NONE,
			   0,
			   TRUE);
#endif

		/* retrieve appropriate data for each 4K-page in this page */
		if (PAGE_SHIFT == FOURK_PAGE_SHIFT &&
		    page_shift_user32 == SIXTEENK_PAGE_SHIFT) {
			/*
			 * Find the slot for the requested 4KB page in
			 * the 16K page...
			 */
			assert(PAGE_SHIFT == FOURK_PAGE_SHIFT);
			assert(page_shift_user32 == SIXTEENK_PAGE_SHIFT);
			sub_page_idx = ((offset & SIXTEENK_PAGE_MASK) /
					PAGE_SIZE);
			/*
			 * ... and provide only that one 4KB page.
			 */
			sub_page_cnt = 1;
		} else {
			/*
			 * Iterate over all slots, i.e. retrieve all four 4KB
			 * pages in the requested 16KB page.
			 */
			assert(PAGE_SHIFT == SIXTEENK_PAGE_SHIFT);
			sub_page_idx = 0;
			sub_page_cnt = FOURK_PAGER_SLOTS;
		}

		num_subpg_signed = 0;
		num_subpg_validated = 0;
		num_subpg_tainted = 0;
		num_subpg_nx = 0;

		/* retrieve appropriate data for each 4K-page in this page */
		for (sub_page = sub_page_idx;
		     sub_page < sub_page_idx + sub_page_cnt;
		     sub_page++) {
			vm_object_t		src_object;
			memory_object_offset_t	src_offset;
			vm_offset_t		offset_in_src_page;
			kern_return_t		error_code;
			vm_object_t		src_page_object;
			vm_page_t		src_page;
			vm_page_t		top_page;
			vm_prot_t		prot;
			int			interruptible;
			struct vm_object_fault_info	fault_info;
			boolean_t	subpg_validated;
			unsigned	subpg_tainted;


			if (offset < SIXTEENK_PAGE_SIZE) {
				/*
				 * The 1st 16K-page can cover multiple
				 * sub-mappings, as described in the 
				 * pager->slots[] array.
				 */
				src_object =
					pager->slots[sub_page].backing_object;
				src_offset =
					pager->slots[sub_page].backing_offset;
			} else {
				fourk_pager_backing_t slot;

				/*
				 * Beyond the 1st 16K-page in the pager is
				 * an extension of the last "sub page" in
				 * the pager->slots[] array.
				 */
				slot = &pager->slots[FOURK_PAGER_SLOTS-1];
				src_object = slot->backing_object;
				src_offset = slot->backing_offset;
				src_offset += FOURK_PAGE_SIZE;
				src_offset +=
					(vm_map_trunc_page(offset,
							   SIXTEENK_PAGE_MASK)
					 - SIXTEENK_PAGE_SIZE);
				src_offset += sub_page * FOURK_PAGE_SIZE;
			}
			offset_in_src_page = src_offset & PAGE_MASK_64;
			src_offset = vm_object_trunc_page(src_offset);
				
			if (src_object == VM_OBJECT_NULL ||
			    src_object == (vm_object_t) -1) {
				/* zero-fill */
				bzero((char *)(dst_vaddr +
					       ((sub_page-sub_page_idx)
						* FOURK_PAGE_SIZE)),
				      FOURK_PAGE_SIZE);
				if (fourk_pager_data_request_debug) {
					printf("fourk_pager_data_request"
					       "(%p,0x%llx+0x%lx+0x%04x): "
					       "ZERO\n",
					       pager,
					       offset,
					       cur_offset,
					       ((sub_page - sub_page_idx)
						* FOURK_PAGE_SIZE));
				}
				continue;
			}

			/* fault in the source page from src_object */
		retry_src_fault:
			src_page = VM_PAGE_NULL;
			top_page = VM_PAGE_NULL;
			fault_info = *((struct vm_object_fault_info *)
				       (uintptr_t)mo_fault_info);
			fault_info.stealth = TRUE;
			fault_info.io_sync = FALSE;
			fault_info.mark_zf_absent = FALSE;
			fault_info.batch_pmap_op = FALSE;
			interruptible = fault_info.interruptible;
			prot = VM_PROT_READ;
			error_code = 0;

			vm_object_lock(src_object);
			vm_object_paging_begin(src_object);
			kr = vm_fault_page(src_object,
					   src_offset,
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
				goto src_fault_done;
			case VM_FAULT_SUCCESS_NO_VM_PAGE:
				/* success but no VM page: fail */
				vm_object_paging_end(src_object);
				vm_object_unlock(src_object);
				/*FALLTHROUGH*/
			case VM_FAULT_MEMORY_ERROR:
				/* the page is not there! */
				if (error_code) {
					retval = error_code;
				} else {
					retval = KERN_MEMORY_ERROR;
				}
				goto src_fault_done;
			default:
				panic("fourk_pager_data_request: "
				      "vm_fault_page() unexpected error 0x%x\n",
				      kr);
			}
			assert(src_page != VM_PAGE_NULL);
			assert(src_page->busy);

			src_page_object = VM_PAGE_OBJECT(src_page);

			if (( !VM_PAGE_PAGEABLE(src_page)) &&
			    !VM_PAGE_WIRED(src_page)) {
				vm_page_lockspin_queues();
				if (( !VM_PAGE_PAGEABLE(src_page)) &&
				    !VM_PAGE_WIRED(src_page)) {
					vm_page_deactivate(src_page);
				}
				vm_page_unlock_queues();
			}

#if __x86_64__
			src_vaddr = (vm_map_offset_t)
				PHYSMAP_PTOV((pmap_paddr_t)VM_PAGE_GET_PHYS_PAGE(src_page)
					     << PAGE_SHIFT);
#else
			/*
			 * Establish an explicit mapping of the source
			 * physical page.
			 */
			pmap_enter(kernel_pmap,
				   src_vaddr,
				   VM_PAGE_GET_PHYS_PAGE(src_page),
				   VM_PROT_READ,
				   VM_PROT_NONE,
				   0,
				   TRUE);
#endif

			/*
			 * Validate the 4K page we want from
			 * this source page...
			 */
			subpg_validated = FALSE;
			subpg_tainted = 0;
			if (src_page_object->code_signed) {
				vm_page_validate_cs_mapped_chunk(
					src_page,
					(const void *) src_vaddr,
					offset_in_src_page,
					FOURK_PAGE_SIZE,
					&subpg_validated,
					&subpg_tainted);
				num_subpg_signed++;
				if (subpg_validated) {
					num_subpg_validated++;
				}
				if (subpg_tainted & CS_VALIDATE_TAINTED) {
					num_subpg_tainted++;
				}
				if (subpg_tainted & CS_VALIDATE_NX) {
					/* subpg should not be executable */
					if (sub_page_cnt > 1) {
						/*
						 * The destination page has
						 * more than 1 subpage and its
						 * other subpages might need
						 * EXEC, so we do not propagate
						 * CS_VALIDATE_NX to the
						 * destination page...
						 */
					} else {
						num_subpg_nx++;
					}
				}
			}

			/*
			 * Copy the relevant portion of the source page
			 * into the appropriate part of the destination page.
			 */
			bcopy((const char *)(src_vaddr + offset_in_src_page),
			      (char *)(dst_vaddr +
				       ((sub_page - sub_page_idx) *
					FOURK_PAGE_SIZE)),
			      FOURK_PAGE_SIZE);
			if (fourk_pager_data_request_debug) {
				printf("fourk_data_request"
				       "(%p,0x%llx+0x%lx+0x%04x): "
				       "backed by [%p:0x%llx]: "
				       "[0x%016llx 0x%016llx] "
				       "code_signed=%d "
				       "cs_valid=%d cs_tainted=%d cs_nx=%d\n",
				       pager,
				       offset, cur_offset,
				       (sub_page-sub_page_idx)*FOURK_PAGE_SIZE,
				       src_page_object,
				       src_page->offset + offset_in_src_page,
				       *(uint64_t *)(dst_vaddr +
						     ((sub_page-sub_page_idx) *
						      FOURK_PAGE_SIZE)),
				       *(uint64_t *)(dst_vaddr +
						     ((sub_page-sub_page_idx) *
						      FOURK_PAGE_SIZE) +
						     8),
				       src_page_object->code_signed,
				       subpg_validated,
				       !!(subpg_tainted & CS_VALIDATE_TAINTED),
				       !!(subpg_tainted & CS_VALIDATE_NX));
			}

#if __x86_64__ || __arm__ || __arm64__
			/* we used the 1-to-1 mapping of physical memory */
			src_vaddr = 0;
#else /* __x86_64__ || __arm__ || __arm64__ */
			/*
			 * Remove the pmap mapping of the source page 
			 * in the kernel.
			 */
			pmap_remove(kernel_pmap,
				    (addr64_t) src_vaddr,
				    (addr64_t) src_vaddr + PAGE_SIZE_64);
#endif /* __x86_64__ || __arm__ || __arm64__ */

		src_fault_done:
			/*
			 * Cleanup the result of vm_fault_page().
			 */
			if (src_page) {
				assert(VM_PAGE_OBJECT(src_page) == src_page_object);

				PAGE_WAKEUP_DONE(src_page);
				src_page = VM_PAGE_NULL;
				vm_object_paging_end(src_page_object);
				vm_object_unlock(src_page_object);
				if (top_page) {
					vm_object_t	top_object;

					top_object = VM_PAGE_OBJECT(top_page);
					vm_object_lock(top_object);
					VM_PAGE_FREE(top_page);
					top_page = VM_PAGE_NULL;
					vm_object_paging_end(top_object);
					vm_object_unlock(top_object);
				}
			}
		}
		if (num_subpg_signed > 0) {
			/* some code-signing involved with this 16K page */
			if (num_subpg_tainted > 0) {
				/* a tainted subpage taints entire 16K page */
				UPL_SET_CS_TAINTED(upl_pl,
						   cur_offset / PAGE_SIZE,
						   TRUE);
				/* also mark as "validated" for consisteny */
				UPL_SET_CS_VALIDATED(upl_pl,
						     cur_offset / PAGE_SIZE,
						     TRUE);
			} else if (num_subpg_validated == num_subpg_signed) {
				/*
				 * All the code-signed 4K subpages of this
				 * 16K page are validated:  our 16K page is
				 * considered validated.
				 */
				UPL_SET_CS_VALIDATED(upl_pl,
						     cur_offset / PAGE_SIZE,
						     TRUE);
			}
			if (num_subpg_nx > 0) {
				UPL_SET_CS_NX(upl_pl,
					      cur_offset / PAGE_SIZE,
					      TRUE);
			}
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
			if (retval == KERN_ABORTED) {
				wait_result_t	wait_result;

				/*
				 * We aborted the fault and did not provide
				 * any contents for the requested pages but
				 * the pages themselves are not invalid, so
				 * let's return success and let the caller
				 * retry the fault, in case it might succeed
				 * later (when the decryption code is up and
				 * running in the kernel, for example).
				 */
				retval = KERN_SUCCESS;
				/*
				 * Wait a little bit first to avoid using
				 * too much CPU time retrying and failing
				 * the same fault over and over again.
				 */
				wait_result = assert_wait_timeout(
					(event_t) fourk_pager_data_request,
					THREAD_UNINT,
					10000,	/* 10ms */
					NSEC_PER_USEC);
				assert(wait_result == THREAD_WAITING);
				wait_result = thread_block(THREAD_CONTINUE_NULL);
				assert(wait_result == THREAD_TIMED_OUT);
			}
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

	return retval;
}



kern_return_t
fourk_pager_populate(
	memory_object_t		mem_obj,
	boolean_t		overwrite,
	int			index,
	vm_object_t		new_backing_object,
	vm_object_offset_t	new_backing_offset,
	vm_object_t		*old_backing_object,
	vm_object_offset_t	*old_backing_offset)
{
	fourk_pager_t	pager;

	pager = fourk_pager_lookup(mem_obj);
	if (pager == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	assert(pager->ref_count > 0);
	assert(pager->pager_control != MEMORY_OBJECT_CONTROL_NULL);

	if (index < 0 || index > FOURK_PAGER_SLOTS) {
		return KERN_INVALID_ARGUMENT;
	}

	if (!overwrite &&
	    (pager->slots[index].backing_object != (vm_object_t) -1 ||
	     pager->slots[index].backing_offset != (vm_object_offset_t) -1)) {
		return KERN_INVALID_ADDRESS;
	}

	*old_backing_object = pager->slots[index].backing_object;
	*old_backing_offset = pager->slots[index].backing_offset;

	pager->slots[index].backing_object = new_backing_object;
	pager->slots[index].backing_offset = new_backing_offset;

	return KERN_SUCCESS;
}

