/*
 * Copyright (c) 2013 Apple Computer, Inc. All rights reserved.
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

/*
 *	Compressor Pager.
 *		Memory Object Management.
 */

#include <kern/host_statistics.h>
#include <kern/kalloc.h>

#include <mach/memory_object_control.h>
#include <mach/memory_object_types.h>
#include <mach/memory_object_server.h>
#include <mach/upl.h>

#include <vm/memory_object.h>
#include <vm/vm_compressor_pager.h>
#include <vm/vm_external.h>
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>

/* memory_object interfaces */
void compressor_memory_object_reference(memory_object_t mem_obj);
void compressor_memory_object_deallocate(memory_object_t mem_obj);
kern_return_t compressor_memory_object_init(
	memory_object_t		mem_obj,
	memory_object_control_t	control,
	memory_object_cluster_size_t pager_page_size);
kern_return_t compressor_memory_object_terminate(memory_object_t mem_obj);
kern_return_t compressor_memory_object_data_request(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	memory_object_cluster_size_t		length,
	__unused vm_prot_t	protection_required,
        memory_object_fault_info_t	fault_info);
kern_return_t compressor_memory_object_data_return(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	memory_object_cluster_size_t			size,
	__unused memory_object_offset_t	*resid_offset,
	__unused int		*io_error,
	__unused boolean_t	dirty,
	__unused boolean_t	kernel_copy,
	__unused int	upl_flags);
kern_return_t compressor_memory_object_data_initialize(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	memory_object_cluster_size_t		size);
kern_return_t compressor_memory_object_data_unlock(
	__unused memory_object_t		mem_obj,
	__unused memory_object_offset_t	offset,
	__unused memory_object_size_t		size,
	__unused vm_prot_t		desired_access);
kern_return_t compressor_memory_object_synchronize(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	memory_object_size_t		length,
	__unused vm_sync_t		flags);
kern_return_t compressor_memory_object_map(
	__unused memory_object_t	mem_obj,
	__unused vm_prot_t		prot);
kern_return_t compressor_memory_object_last_unmap(memory_object_t mem_obj);
kern_return_t compressor_memory_object_data_reclaim(
	__unused memory_object_t	mem_obj,
	__unused boolean_t		reclaim_backing_store);

const struct memory_object_pager_ops compressor_pager_ops = {
	compressor_memory_object_reference,
	compressor_memory_object_deallocate,
	compressor_memory_object_init,
	compressor_memory_object_terminate,
	compressor_memory_object_data_request,
	compressor_memory_object_data_return,
	compressor_memory_object_data_initialize,
	compressor_memory_object_data_unlock,
	compressor_memory_object_synchronize,
	compressor_memory_object_map,
	compressor_memory_object_last_unmap,
	compressor_memory_object_data_reclaim,
	"compressor pager"
};

/* internal data structures */

struct {
	uint64_t	data_returns;
	uint64_t	data_requests;
	uint64_t	put;
	uint64_t	get;
	uint64_t	state_clr;
	uint64_t	state_get;
	uint64_t	transfer;
} compressor_pager_stats;

typedef int compressor_slot_t;

typedef struct compressor_pager {
	struct ipc_object_header	cpgr_pager_header; /* fake ip_kotype */
	memory_object_pager_ops_t	cpgr_pager_ops;	/* == &compressor_pager_ops */
	memory_object_control_t		cpgr_control;
	lck_mtx_t			cpgr_lock;

	unsigned int			cpgr_references;
	unsigned int			cpgr_num_slots;
	unsigned int			cpgr_num_slots_occupied_pager;
	unsigned int			cpgr_num_slots_occupied;
	union {
		compressor_slot_t	*cpgr_dslots;
		compressor_slot_t	**cpgr_islots;
	} cpgr_slots;
} *compressor_pager_t;

#define compressor_pager_lookup(_mem_obj_, _cpgr_)			\
	MACRO_BEGIN							\
	if (_mem_obj_ == NULL ||					\
	    _mem_obj_->mo_pager_ops != &compressor_pager_ops) {		\
		_cpgr_ = NULL;						\
	} else {							\
		_cpgr_ = (compressor_pager_t) _mem_obj_;		\
	}								\
	MACRO_END

zone_t compressor_pager_zone;

lck_grp_t	compressor_pager_lck_grp;
lck_grp_attr_t	compressor_pager_lck_grp_attr;
lck_attr_t	compressor_pager_lck_attr;

#define compressor_pager_lock(_cpgr_) \
	lck_mtx_lock(&(_cpgr_)->cpgr_lock)
#define compressor_pager_unlock(_cpgr_) \
	lck_mtx_unlock(&(_cpgr_)->cpgr_lock)
#define compressor_pager_lock_init(_cpgr_) \
	lck_mtx_init(&(_cpgr_)->cpgr_lock, &compressor_pager_lck_grp, &compressor_pager_lck_attr)
#define compressor_pager_lock_destroy(_cpgr_) \
	lck_mtx_destroy(&(_cpgr_)->cpgr_lock, &compressor_pager_lck_grp)

#define COMPRESSOR_SLOTS_CHUNK_SIZE	(512)
#define COMPRESSOR_SLOTS_PER_CHUNK	(COMPRESSOR_SLOTS_CHUNK_SIZE / sizeof (compressor_slot_t))

/* forward declarations */
unsigned int compressor_pager_slots_chunk_free(compressor_slot_t *chunk,
					       int num_slots,
	                                       int flags,
					       int *failures);
void compressor_pager_slot_lookup(
	compressor_pager_t	pager,
	boolean_t		do_alloc,
	memory_object_offset_t	offset,
	compressor_slot_t	**slot_pp);

kern_return_t
compressor_memory_object_init(
	memory_object_t		mem_obj,
	memory_object_control_t	control,
	__unused memory_object_cluster_size_t pager_page_size)
{
	compressor_pager_t		pager;

	assert(pager_page_size == PAGE_SIZE);

	memory_object_control_reference(control);

	compressor_pager_lookup(mem_obj, pager);
	compressor_pager_lock(pager);

	if (pager->cpgr_control != MEMORY_OBJECT_CONTROL_NULL)
		panic("compressor_memory_object_init: bad request");
	pager->cpgr_control = control;

	compressor_pager_unlock(pager);

	return KERN_SUCCESS;
}

kern_return_t
compressor_memory_object_synchronize(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	memory_object_size_t		length,
	__unused vm_sync_t		flags)
{
	compressor_pager_t	pager;

	compressor_pager_lookup(mem_obj, pager);

	memory_object_synchronize_completed(pager->cpgr_control, offset, length);

	return KERN_SUCCESS;
}

kern_return_t
compressor_memory_object_map(
	__unused memory_object_t	mem_obj,
	__unused vm_prot_t		prot)
{
	panic("compressor_memory_object_map");
	return KERN_FAILURE;
}

kern_return_t
compressor_memory_object_last_unmap(
	__unused memory_object_t	mem_obj)
{
	panic("compressor_memory_object_last_unmap");
	return KERN_FAILURE;
}

kern_return_t
compressor_memory_object_data_reclaim(
	__unused memory_object_t	mem_obj,
	__unused boolean_t		reclaim_backing_store)
{
	panic("compressor_memory_object_data_reclaim");
	return KERN_FAILURE;
}

kern_return_t
compressor_memory_object_terminate(
	memory_object_t		mem_obj)
{
	memory_object_control_t	control;
	compressor_pager_t	pager;

	/* 
	 * control port is a receive right, not a send right.
	 */

	compressor_pager_lookup(mem_obj, pager);
	compressor_pager_lock(pager);

	/*
	 * After memory_object_terminate both memory_object_init
	 * and a no-senders notification are possible, so we need
	 * to clean up our reference to the memory_object_control
	 * to prepare for a new init.
	 */

	control = pager->cpgr_control;
	pager->cpgr_control = MEMORY_OBJECT_CONTROL_NULL;

	compressor_pager_unlock(pager);

	/*
	 * Now we deallocate our reference on the control.
	 */
	memory_object_control_deallocate(control);
	return KERN_SUCCESS;
}

void
compressor_memory_object_reference(
	memory_object_t		mem_obj)
{
	compressor_pager_t	pager;

	compressor_pager_lookup(mem_obj, pager);
	if (pager == NULL)
		return;

	compressor_pager_lock(pager);
	assert(pager->cpgr_references > 0);
	pager->cpgr_references++;
	compressor_pager_unlock(pager);
}

void
compressor_memory_object_deallocate(
	memory_object_t		mem_obj)
{
	compressor_pager_t	pager;
	unsigned int		num_slots_freed;

	/*
	 * Because we don't give out multiple first references
	 * for a memory object, there can't be a race
	 * between getting a deallocate call and creating
	 * a new reference for the object.
	 */

	compressor_pager_lookup(mem_obj, pager);
	if (pager == NULL)
		return;

	compressor_pager_lock(pager);
	if (--pager->cpgr_references > 0) {
		compressor_pager_unlock(pager);
		return;
	}

	/*
	 * We shouldn't get a deallocation call
	 * when the kernel has the object cached.
	 */
	if (pager->cpgr_control != MEMORY_OBJECT_CONTROL_NULL)
		panic("compressor_memory_object_deallocate(): bad request");

	/*
	 * Unlock the pager (though there should be no one
	 * waiting for it).
	 */
	compressor_pager_unlock(pager);

	/* free the compressor slots */
	int num_chunks;
	int i;
	compressor_slot_t *chunk;

	num_chunks = (pager->cpgr_num_slots + COMPRESSOR_SLOTS_PER_CHUNK -1) / COMPRESSOR_SLOTS_PER_CHUNK;
	if (num_chunks > 1) {
		/* we have an array of chunks */
		for (i = 0; i < num_chunks; i++) {
			chunk = pager->cpgr_slots.cpgr_islots[i];
			if (chunk != NULL) {
				num_slots_freed =
					compressor_pager_slots_chunk_free(
						chunk,
						COMPRESSOR_SLOTS_PER_CHUNK,
						0,
						NULL);
				assert(pager->cpgr_num_slots_occupied_pager >=
				       num_slots_freed);
				OSAddAtomic(-num_slots_freed,
					    &pager->cpgr_num_slots_occupied_pager);
				assert(pager->cpgr_num_slots_occupied_pager >= 0);
				pager->cpgr_slots.cpgr_islots[i] = NULL;
				kfree(chunk, COMPRESSOR_SLOTS_CHUNK_SIZE);
			}
		}
		kfree(pager->cpgr_slots.cpgr_islots,
		      num_chunks * sizeof (pager->cpgr_slots.cpgr_islots[0]));
		pager->cpgr_slots.cpgr_islots = NULL;
	} else {
		chunk = pager->cpgr_slots.cpgr_dslots;
		num_slots_freed =
			compressor_pager_slots_chunk_free(
				chunk,
				pager->cpgr_num_slots,
				0,
				NULL);
		assert(pager->cpgr_num_slots_occupied_pager >= num_slots_freed);
		OSAddAtomic(-num_slots_freed, &pager->cpgr_num_slots_occupied_pager);
		assert(pager->cpgr_num_slots_occupied_pager >= 0);
		pager->cpgr_slots.cpgr_dslots = NULL;
		kfree(chunk,
		      (pager->cpgr_num_slots *
		       sizeof (pager->cpgr_slots.cpgr_dslots[0])));
	}
	assert(pager->cpgr_num_slots_occupied_pager == 0);

	compressor_pager_lock_destroy(pager);
	zfree(compressor_pager_zone, pager);
}

kern_return_t
compressor_memory_object_data_request(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	memory_object_cluster_size_t		length,
	__unused vm_prot_t	protection_required,
        __unused memory_object_fault_info_t	fault_info)
{
	compressor_pager_t	pager;
	kern_return_t		kr;
	compressor_slot_t	*slot_p;
	
	compressor_pager_stats.data_requests++;

	/*
	 * Request must be on a page boundary and a multiple of pages.
	 */
	if ((offset & PAGE_MASK) != 0 || (length & PAGE_MASK) != 0)
		panic("compressor_memory_object_data_request(): bad alignment");

	if ((uint32_t)(offset/PAGE_SIZE) != (offset/PAGE_SIZE)) {
		panic("%s: offset 0x%llx overflow\n",
		      __FUNCTION__, (uint64_t) offset);
		return KERN_FAILURE;
	}

	compressor_pager_lookup(mem_obj, pager);

	if (length == 0) {
		/* we're only querying the pager for this page */
	} else {
		panic("compressor: data_request");
	}

	/* find the compressor slot for that page */
	compressor_pager_slot_lookup(pager, FALSE, offset, &slot_p);

	if (offset / PAGE_SIZE > pager->cpgr_num_slots) {
		/* out of range */
		kr = KERN_FAILURE;
	} else if (slot_p == NULL || *slot_p == 0) {
		/* compressor does not have this page */
		kr = KERN_FAILURE;
	} else {
		/* compressor does have this page */
		kr = KERN_SUCCESS;
	}
	return kr;
}

/*
 * memory_object_data_initialize: check whether we already have each page, and
 * write it if we do not.  The implementation is far from optimized, and
 * also assumes that the default_pager is single-threaded.
 */
/*  It is questionable whether or not a pager should decide what is relevant */
/* and what is not in data sent from the kernel.  Data initialize has been */
/* changed to copy back all data sent to it in preparation for its eventual */
/* merge with data return.  It is the kernel that should decide what pages */
/* to write back.  As of the writing of this note, this is indeed the case */
/* the kernel writes back one page at a time through this interface */

kern_return_t
compressor_memory_object_data_initialize(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	memory_object_cluster_size_t		size)
{
	compressor_pager_t	pager;
	memory_object_offset_t	cur_offset;

	compressor_pager_lookup(mem_obj, pager);
	compressor_pager_lock(pager);

	for (cur_offset = offset;
	     cur_offset < offset + size;
	     cur_offset += PAGE_SIZE) {
		panic("do a data_return() if slot for this page is empty");
	}

	compressor_pager_unlock(pager);

	return KERN_SUCCESS;
}

kern_return_t
compressor_memory_object_data_unlock(
	__unused memory_object_t		mem_obj,
	__unused memory_object_offset_t	offset,
	__unused memory_object_size_t		size,
	__unused vm_prot_t		desired_access)
{
	panic("compressor_memory_object_data_unlock()");
	return KERN_FAILURE;
}


/*ARGSUSED*/
kern_return_t
compressor_memory_object_data_return(
	__unused memory_object_t			mem_obj,
	__unused memory_object_offset_t		offset,
	__unused memory_object_cluster_size_t	size,
	__unused memory_object_offset_t	*resid_offset,
	__unused int		*io_error,
	__unused boolean_t	dirty,
	__unused boolean_t	kernel_copy,
	__unused int		upl_flags)
{
	panic("compressor: data_return");
	return KERN_FAILURE;
}

/*
 * Routine:	default_pager_memory_object_create
 * Purpose:
 * 	Handle requests for memory objects from the
 * 	kernel.
 * Notes:
 * 	Because we only give out the default memory
 * 	manager port to the kernel, we don't have to
 * 	be so paranoid about the contents.
 */
kern_return_t
compressor_memory_object_create(
	memory_object_size_t	new_size,
	memory_object_t		*new_mem_obj)
{
	compressor_pager_t	pager;
	int			num_chunks;

	if ((uint32_t)(new_size/PAGE_SIZE) != (new_size/PAGE_SIZE)) {
		/* 32-bit overflow for number of pages */
		panic("%s: size 0x%llx overflow\n",
		      __FUNCTION__, (uint64_t) new_size);
		return KERN_INVALID_ARGUMENT;
	}

	pager = (compressor_pager_t) zalloc(compressor_pager_zone);
	if (pager == NULL) {
		return KERN_RESOURCE_SHORTAGE;
	}

	compressor_pager_lock_init(pager);
	pager->cpgr_control = MEMORY_OBJECT_CONTROL_NULL;
	pager->cpgr_references = 1;
	pager->cpgr_num_slots = (uint32_t)(new_size/PAGE_SIZE);
	pager->cpgr_num_slots_occupied_pager = 0;
	pager->cpgr_num_slots_occupied = 0;

	num_chunks = (pager->cpgr_num_slots + COMPRESSOR_SLOTS_PER_CHUNK - 1) / COMPRESSOR_SLOTS_PER_CHUNK;
	if (num_chunks > 1) {
		pager->cpgr_slots.cpgr_islots = kalloc(num_chunks * sizeof (pager->cpgr_slots.cpgr_islots[0]));
		bzero(pager->cpgr_slots.cpgr_islots, num_chunks * sizeof (pager->cpgr_slots.cpgr_islots[0]));
	} else {
		pager->cpgr_slots.cpgr_dslots = kalloc(pager->cpgr_num_slots * sizeof (pager->cpgr_slots.cpgr_dslots[0]));
		bzero(pager->cpgr_slots.cpgr_dslots, pager->cpgr_num_slots * sizeof (pager->cpgr_slots.cpgr_dslots[0]));
	}

	/*
	 * Set up associations between this memory object
	 * and this compressor_pager structure
	 */

	pager->cpgr_pager_ops = &compressor_pager_ops;
	pager->cpgr_pager_header.io_bits = IKOT_MEMORY_OBJECT;

	*new_mem_obj = (memory_object_t) pager;
	return KERN_SUCCESS;
}


unsigned int
compressor_pager_slots_chunk_free(
	compressor_slot_t	*chunk,
	int			num_slots,
	int			flags,
	int			*failures)
{
	int i;
	unsigned int num_slots_freed;

	if (failures)
		*failures = 0;
	num_slots_freed = 0;
	for (i = 0; i < num_slots; i++) {
		if (chunk[i] != 0) {
			if (vm_compressor_free(&chunk[i], flags) == 0)
				num_slots_freed++;
			else {
				assert(flags & C_DONT_BLOCK);

				if (failures)
					*failures += 1;
			}
		}
	}
	return num_slots_freed;
}

void
compressor_pager_slot_lookup(
	compressor_pager_t	pager,
	boolean_t		do_alloc,
	memory_object_offset_t	offset,
	compressor_slot_t	**slot_pp)
{
	int			num_chunks;
	uint32_t		page_num;
	int			chunk_idx;
	int			slot_idx;
	compressor_slot_t	*chunk;
	compressor_slot_t	*t_chunk;

	page_num = (uint32_t)(offset/PAGE_SIZE);
	if (page_num != (offset/PAGE_SIZE)) {
		/* overflow */
		panic("%s: offset 0x%llx overflow\n",
		      __FUNCTION__, (uint64_t) offset);
		*slot_pp = NULL;
		return;
	}
	if (page_num > pager->cpgr_num_slots) {
		/* out of range */
		*slot_pp = NULL;
		return;
	}
	num_chunks = (pager->cpgr_num_slots + COMPRESSOR_SLOTS_PER_CHUNK - 1) / COMPRESSOR_SLOTS_PER_CHUNK;
	if (num_chunks > 1) {
		/* we have an array of chunks */
		chunk_idx = page_num / COMPRESSOR_SLOTS_PER_CHUNK;
		chunk = pager->cpgr_slots.cpgr_islots[chunk_idx];

		if (chunk == NULL && do_alloc) {
			t_chunk = kalloc(COMPRESSOR_SLOTS_CHUNK_SIZE);
			bzero(t_chunk, COMPRESSOR_SLOTS_CHUNK_SIZE);

			compressor_pager_lock(pager);

			if ((chunk = pager->cpgr_slots.cpgr_islots[chunk_idx]) == NULL) {
				chunk = pager->cpgr_slots.cpgr_islots[chunk_idx] = t_chunk;
				t_chunk = NULL;
			}
			compressor_pager_unlock(pager);
			
			if (t_chunk)
				kfree(t_chunk, COMPRESSOR_SLOTS_CHUNK_SIZE);
		}
		if (chunk == NULL) {
			*slot_pp = NULL;
		} else {
			slot_idx = page_num % COMPRESSOR_SLOTS_PER_CHUNK;
			*slot_pp = &chunk[slot_idx];
		}
	} else {
		slot_idx = page_num;
		*slot_pp = &pager->cpgr_slots.cpgr_dslots[slot_idx];
	}
}

void
vm_compressor_pager_init(void)
{
	lck_grp_attr_setdefault(&compressor_pager_lck_grp_attr);
	lck_grp_init(&compressor_pager_lck_grp, "compressor_pager", &compressor_pager_lck_grp_attr);
	lck_attr_setdefault(&compressor_pager_lck_attr);

	compressor_pager_zone = zinit(sizeof (struct compressor_pager),
				      10000 * sizeof (struct compressor_pager),
				      8192, "compressor_pager");
	zone_change(compressor_pager_zone, Z_CALLERACCT, FALSE);
	zone_change(compressor_pager_zone, Z_NOENCRYPT, TRUE);

	vm_compressor_init();
}

kern_return_t
vm_compressor_pager_put(
	memory_object_t			mem_obj,
	memory_object_offset_t		offset,
	ppnum_t				ppnum,
	void				**current_chead,
	char				*scratch_buf,
	int				*compressed_count_delta_p)
{
	compressor_pager_t	pager;
	compressor_slot_t	*slot_p;

	compressor_pager_stats.put++;

	*compressed_count_delta_p = 0;

	/* This routine is called by the pageout thread.  The pageout thread */
	/* cannot be blocked by read activities unless the read activities   */
	/* Therefore the grant of vs lock must be done on a try versus a      */
	/* blocking basis.  The code below relies on the fact that the       */
	/* interface is synchronous.  Should this interface be again async   */
	/* for some type  of pager in the future the pages will have to be   */
	/* returned through a separate, asynchronous path.		     */

	compressor_pager_lookup(mem_obj, pager);

	if ((uint32_t)(offset/PAGE_SIZE) != (offset/PAGE_SIZE)) {
		/* overflow */
		panic("%s: offset 0x%llx overflow\n",
		      __FUNCTION__, (uint64_t) offset);
		return KERN_RESOURCE_SHORTAGE;
	}

	compressor_pager_slot_lookup(pager, TRUE, offset, &slot_p);

	if (slot_p == NULL) {
		/* out of range ? */
		panic("vm_compressor_pager_put: out of range");
	}
	if (*slot_p != 0) {
		/*
		 * Already compressed: forget about the old one.
		 *
		 * This can happen after a vm_object_do_collapse() when
		 * the "backing_object" had some pages paged out and the
		 * "object" had an equivalent page resident.
		 */
		vm_compressor_free(slot_p, 0);
		assert(pager->cpgr_num_slots_occupied_pager >= 1);
		OSAddAtomic(-1, &pager->cpgr_num_slots_occupied_pager);
		assert(pager->cpgr_num_slots_occupied_pager >= 0);
		*compressed_count_delta_p -= 1;
	}
	if (vm_compressor_put(ppnum, slot_p, current_chead, scratch_buf))
		return (KERN_RESOURCE_SHORTAGE);
	assert(pager->cpgr_num_slots_occupied_pager >= 0);
	OSAddAtomic(+1, &pager->cpgr_num_slots_occupied_pager);
	assert(pager->cpgr_num_slots_occupied_pager > 0);
	*compressed_count_delta_p += 1;

	return (KERN_SUCCESS);
}


kern_return_t
vm_compressor_pager_get(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	ppnum_t			ppnum,
	int			*my_fault_type,
	int			flags,
	int			*compressed_count_delta_p)
{
	compressor_pager_t	pager;
	kern_return_t		kr;
	compressor_slot_t	*slot_p;
	
	compressor_pager_stats.get++;

	*compressed_count_delta_p = 0;

	if ((uint32_t)(offset/PAGE_SIZE) != (offset/PAGE_SIZE)) {
		panic("%s: offset 0x%llx overflow\n",
		      __FUNCTION__, (uint64_t) offset);
		return KERN_MEMORY_ERROR;
	}

	compressor_pager_lookup(mem_obj, pager);

	/* find the compressor slot for that page */
	compressor_pager_slot_lookup(pager, FALSE, offset, &slot_p);

	if (offset / PAGE_SIZE > pager->cpgr_num_slots) {
		/* out of range */
		kr = KERN_MEMORY_FAILURE;
	} else if (slot_p == NULL || *slot_p == 0) {
		/* compressor does not have this page */
		kr = KERN_MEMORY_ERROR;
	} else {
		/* compressor does have this page */
		kr = KERN_SUCCESS;
	}
	*my_fault_type = DBG_COMPRESSOR_FAULT;
		
	if (kr == KERN_SUCCESS) {
		int	retval;

		/* get the page from the compressor */
		retval = vm_compressor_get(ppnum, slot_p, flags);
		if (retval == -1)
			kr = KERN_MEMORY_FAILURE;
		else if (retval == 1)
			*my_fault_type = DBG_COMPRESSOR_SWAPIN_FAULT;
		else if (retval == -2) {
			assert((flags & C_DONT_BLOCK));
			kr = KERN_FAILURE;
		}
	}

	if (kr == KERN_SUCCESS) {
		assert(slot_p != NULL);
		if (*slot_p != 0) {
			/*
			 * We got the page for a copy-on-write fault
			 * and we kept the original in place.  Slot
			 * is still occupied.
			 */
		} else {
			assert(pager->cpgr_num_slots_occupied_pager >= 1);
			OSAddAtomic(-1, &pager->cpgr_num_slots_occupied_pager);
			assert(pager->cpgr_num_slots_occupied_pager >= 0);
			*compressed_count_delta_p -= 1;
		}
	}

	return kr;
}

unsigned int
vm_compressor_pager_state_clr(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset)
{
	compressor_pager_t	pager;
	compressor_slot_t	*slot_p;
	unsigned int		num_slots_freed;
	
	compressor_pager_stats.state_clr++;

	if ((uint32_t)(offset/PAGE_SIZE) != (offset/PAGE_SIZE)) {
		/* overflow */
		panic("%s: offset 0x%llx overflow\n",
		      __FUNCTION__, (uint64_t) offset);
		return 0;
	}

	compressor_pager_lookup(mem_obj, pager);

	/* find the compressor slot for that page */
	compressor_pager_slot_lookup(pager, FALSE, offset, &slot_p);

	num_slots_freed = 0;
	if (slot_p && *slot_p != 0) {
		vm_compressor_free(slot_p, 0);
		num_slots_freed++;
		assert(*slot_p == 0);
		assert(pager->cpgr_num_slots_occupied_pager >= 1);
		OSAddAtomic(-1, &pager->cpgr_num_slots_occupied_pager);
		assert(pager->cpgr_num_slots_occupied_pager >= 0);
	}

	return num_slots_freed;
}

vm_external_state_t
vm_compressor_pager_state_get(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset)
{
	compressor_pager_t	pager;
	compressor_slot_t	*slot_p;
	
	compressor_pager_stats.state_get++;

	if ((uint32_t)(offset/PAGE_SIZE) != (offset/PAGE_SIZE)) {
		/* overflow */
		panic("%s: offset 0x%llx overflow\n",
		      __FUNCTION__, (uint64_t) offset);
		return VM_EXTERNAL_STATE_ABSENT;
	}

	compressor_pager_lookup(mem_obj, pager);

	/* find the compressor slot for that page */
	compressor_pager_slot_lookup(pager, FALSE, offset, &slot_p);

	if (offset / PAGE_SIZE > pager->cpgr_num_slots) {
		/* out of range */
		return VM_EXTERNAL_STATE_ABSENT;
	} else if (slot_p == NULL || *slot_p == 0) {
		/* compressor does not have this page */
		return VM_EXTERNAL_STATE_ABSENT;
	} else {
		/* compressor does have this page */
		return VM_EXTERNAL_STATE_EXISTS;
	}
}

unsigned int
vm_compressor_pager_reap_pages(
	memory_object_t		mem_obj,
	int			flags)
{
	compressor_pager_t	pager;
	int			num_chunks;
	int			failures;
	int			i;
	compressor_slot_t	*chunk;
	unsigned int		num_slots_freed;

	compressor_pager_lookup(mem_obj, pager);
	if (pager == NULL)
		return 0;

	compressor_pager_lock(pager);

	/* reap the compressor slots */
	num_slots_freed = 0;

	num_chunks = (pager->cpgr_num_slots + COMPRESSOR_SLOTS_PER_CHUNK -1) / COMPRESSOR_SLOTS_PER_CHUNK;
	if (num_chunks > 1) {
		/* we have an array of chunks */
		for (i = 0; i < num_chunks; i++) {
			chunk = pager->cpgr_slots.cpgr_islots[i];
			if (chunk != NULL) {
				num_slots_freed +=
					compressor_pager_slots_chunk_free(
						chunk,
						COMPRESSOR_SLOTS_PER_CHUNK,
						flags,
						&failures);
				if (failures == 0) {
					pager->cpgr_slots.cpgr_islots[i] = NULL;
					kfree(chunk, COMPRESSOR_SLOTS_CHUNK_SIZE);
				}
			}
		}
	} else {
		chunk = pager->cpgr_slots.cpgr_dslots;
		num_slots_freed +=
			compressor_pager_slots_chunk_free(
				chunk,
				pager->cpgr_num_slots,
				flags,
				NULL);
	}
	OSAddAtomic(-num_slots_freed, &pager->cpgr_num_slots_occupied_pager);

	compressor_pager_unlock(pager);

	return num_slots_freed;
}

unsigned int
vm_compressor_pager_get_slots_occupied(
	memory_object_t	mem_obj)
{
	compressor_pager_t	pager;

	compressor_pager_lookup(mem_obj, pager);
	if (pager == NULL)
		return 0;

	assert(pager->cpgr_num_slots_occupied_pager >= 0);

	return pager->cpgr_num_slots_occupied_pager;
}

void
vm_compressor_pager_transfer(
	memory_object_t		dst_mem_obj,
	memory_object_offset_t	dst_offset,
	memory_object_t		src_mem_obj,
	memory_object_offset_t	src_offset)
{
	compressor_pager_t	src_pager, dst_pager;
	compressor_slot_t	*src_slot_p, *dst_slot_p;
	
	compressor_pager_stats.transfer++;

	/* find the compressor slot for the destination */
	assert((uint32_t) dst_offset == dst_offset);
	compressor_pager_lookup(dst_mem_obj, dst_pager);
	assert(dst_offset / PAGE_SIZE <= dst_pager->cpgr_num_slots);
	compressor_pager_slot_lookup(dst_pager, TRUE, (uint32_t) dst_offset,
				     &dst_slot_p);
	assert(dst_slot_p != NULL);
	assert(*dst_slot_p == 0);

	/* find the compressor slot for the source */
	assert((uint32_t) src_offset == src_offset);
	compressor_pager_lookup(src_mem_obj, src_pager);
	assert(src_offset / PAGE_SIZE <= src_pager->cpgr_num_slots);
	compressor_pager_slot_lookup(src_pager, FALSE, (uint32_t) src_offset,
				     &src_slot_p);
	assert(src_slot_p != NULL);
	assert(*src_slot_p != 0);

	/* transfer the slot from source to destination */
	vm_compressor_transfer(dst_slot_p, src_slot_p);
	OSAddAtomic(-1, &src_pager->cpgr_num_slots_occupied_pager);
	OSAddAtomic(+1, &dst_pager->cpgr_num_slots_occupied_pager);
	OSAddAtomic(-1, &src_pager->cpgr_num_slots_occupied);
	OSAddAtomic(+1, &dst_pager->cpgr_num_slots_occupied);
}

memory_object_offset_t
vm_compressor_pager_next_compressed(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset)
{
	compressor_pager_t	pager;
	uint32_t		num_chunks;
	uint32_t		page_num;
	uint32_t		chunk_idx;
	uint32_t		slot_idx;
	compressor_slot_t	*chunk;

	compressor_pager_lookup(mem_obj, pager);

	page_num = (uint32_t)(offset / PAGE_SIZE);
	if (page_num != (offset/PAGE_SIZE)) {
		/* overflow */
		return (memory_object_offset_t) -1;
	}
	if (page_num > pager->cpgr_num_slots) {
		/* out of range */
		return (memory_object_offset_t) -1;
	}
	num_chunks = ((pager->cpgr_num_slots + COMPRESSOR_SLOTS_PER_CHUNK - 1) /
		      COMPRESSOR_SLOTS_PER_CHUNK);

	if (num_chunks == 1) {
		chunk = pager->cpgr_slots.cpgr_dslots;
		for (slot_idx = page_num;
		     slot_idx < pager->cpgr_num_slots;
		     slot_idx++) {
			if (chunk[slot_idx] != 0) {
				/* found a non-NULL slot in this chunk */
				return (memory_object_offset_t) (slot_idx *
								 PAGE_SIZE);
			}
		}
		return (memory_object_offset_t) -1;
	}

	/* we have an array of chunks; find the next non-NULL chunk */
	chunk = NULL;
	for (chunk_idx = page_num / COMPRESSOR_SLOTS_PER_CHUNK,
		     slot_idx = page_num % COMPRESSOR_SLOTS_PER_CHUNK;
	     chunk_idx < num_chunks;
	     chunk_idx++,
		     slot_idx = 0) {
		chunk = pager->cpgr_slots.cpgr_islots[chunk_idx];
		if (chunk == NULL) {
			/* no chunk here: try the next one */
			continue;
		}
		/* search for an occupied slot in this chunk */
		for (;
		     slot_idx < COMPRESSOR_SLOTS_PER_CHUNK;
		     slot_idx++) {
			if (chunk[slot_idx] != 0) {
				/* found an occupied slot in this chunk */
				uint32_t next_slot;

				next_slot = ((chunk_idx *
					      COMPRESSOR_SLOTS_PER_CHUNK) +
					     slot_idx);
				if (next_slot > pager->cpgr_num_slots) {
					/* went beyond end of object */
					return (memory_object_offset_t) -1;
				}
				return (memory_object_offset_t) (next_slot *
								 PAGE_SIZE);
			}
		}
	}
	return (memory_object_offset_t) -1;
}

unsigned int
vm_compressor_pager_get_count(
	memory_object_t mem_obj)
{
	compressor_pager_t	pager;

	compressor_pager_lookup(mem_obj, pager);
	if (pager == NULL)
		return 0;

	/*
	 * The caller should have the VM object locked and one
	 * needs that lock to do a page-in or page-out, so no
	 * need to lock the pager here.
	 */
	assert(pager->cpgr_num_slots_occupied >= 0);

	return pager->cpgr_num_slots_occupied;
}

void
vm_compressor_pager_count(
	memory_object_t	mem_obj,
	int		compressed_count_delta,
	boolean_t	shared_lock,
	vm_object_t	object __unused)
{
	compressor_pager_t	pager;

	if (compressed_count_delta == 0) {
		return;
	}

	compressor_pager_lookup(mem_obj, pager);
	if (pager == NULL)
		return;

	if (compressed_count_delta < 0) {
		assert(pager->cpgr_num_slots_occupied >=
		       (unsigned int) -compressed_count_delta);
	}

	/*
	 * The caller should have the VM object locked,
	 * shared or exclusive.
	 */
	if (shared_lock) {
		vm_object_lock_assert_shared(object);
		OSAddAtomic(compressed_count_delta,
			    &pager->cpgr_num_slots_occupied);
	} else {
		vm_object_lock_assert_exclusive(object);
		pager->cpgr_num_slots_occupied += compressed_count_delta;
	}
}
