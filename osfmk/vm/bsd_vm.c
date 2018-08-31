/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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

#include <kern/assert.h>
#include <kern/host.h>
#include <kern/ledger.h>
#include <kern/thread.h>
#include <kern/ipc_kobject.h>

#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>

#include <vm/vm_map.h>
#include <vm/vm_pageout.h>
#include <vm/memory_object.h>
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>
#include <vm/vm_purgeable_internal.h>


/* BSD VM COMPONENT INTERFACES */
int
get_map_nentries(
	vm_map_t);

vm_offset_t
get_map_start(
	vm_map_t);

vm_offset_t
get_map_end(
	vm_map_t);

/*
 * 
 */
int
get_map_nentries(
	vm_map_t map)
{
	return(map->hdr.nentries);
}

mach_vm_offset_t
mach_get_vm_start(vm_map_t map)
{
	return( vm_map_first_entry(map)->vme_start);
}

mach_vm_offset_t
mach_get_vm_end(vm_map_t map)
{
	return( vm_map_last_entry(map)->vme_end);
}

/* 
 * BSD VNODE PAGER 
 */

const struct memory_object_pager_ops vnode_pager_ops = {
	vnode_pager_reference,
	vnode_pager_deallocate,
	vnode_pager_init,
	vnode_pager_terminate,
	vnode_pager_data_request,
	vnode_pager_data_return,
	vnode_pager_data_initialize,
	vnode_pager_data_unlock,
	vnode_pager_synchronize,
	vnode_pager_map,
	vnode_pager_last_unmap,
	NULL, /* data_reclaim */
	"vnode pager"
};

typedef struct vnode_pager {
	/* mandatory generic header */
	struct memory_object vn_pgr_hdr;

	/*  pager-specific */
	unsigned int		ref_count;	/* reference count	     */
	struct vnode		*vnode_handle;	/* vnode handle 	     */
} *vnode_pager_t;


kern_return_t
vnode_pager_cluster_read(		/* forward */
	vnode_pager_t, 
	vm_object_offset_t,
	vm_object_offset_t,
	uint32_t,
	vm_size_t);

void
vnode_pager_cluster_write(		/* forward */
	vnode_pager_t,
	vm_object_offset_t,
	vm_size_t,
	vm_object_offset_t *,
	int *,
	int);


vnode_pager_t
vnode_object_create(			/* forward */
	struct vnode *);

vnode_pager_t
vnode_pager_lookup(			/* forward */
	memory_object_t);

struct vnode *
vnode_pager_lookup_vnode(		/* forward */
	memory_object_t);

zone_t	vnode_pager_zone;


#define	VNODE_PAGER_NULL	((vnode_pager_t) 0)

/* TODO: Should be set dynamically by vnode_pager_init() */
#define CLUSTER_SHIFT 	1

/* TODO: Should be set dynamically by vnode_pager_bootstrap() */
#define	MAX_VNODE		10000


#if DEBUG
int pagerdebug=0;

#define PAGER_ALL		0xffffffff
#define	PAGER_INIT		0x00000001
#define	PAGER_PAGEIN	0x00000002

#define PAGER_DEBUG(LEVEL, A) {if ((pagerdebug & LEVEL)==LEVEL){printf A;}}
#else
#define PAGER_DEBUG(LEVEL, A)
#endif

extern int proc_resetpcontrol(int);

#if DEVELOPMENT || DEBUG
extern unsigned long vm_cs_validated_resets;
#endif


extern int	uiomove64(addr64_t, int, void *);
#define	MAX_RUN	32

int
memory_object_control_uiomove(
	memory_object_control_t	control,
	memory_object_offset_t	offset,
	void		*	uio,
	int			start_offset,
	int			io_requested,
	int			mark_dirty,
	int			take_reference)
{
	vm_object_t		object;
	vm_page_t		dst_page;
	int			xsize;
	int			retval = 0;
	int			cur_run;
	int			cur_needed;
	int			i;
	int			orig_offset;
	vm_page_t		page_run[MAX_RUN];
	int 			dirty_count;	/* keeps track of number of pages dirtied as part of this uiomove */

	object = memory_object_control_to_vm_object(control);
	if (object == VM_OBJECT_NULL) {
		return (0);
	}
	assert(!object->internal);

	vm_object_lock(object);

	if (mark_dirty && object->copy != VM_OBJECT_NULL) {
		/*
		 * We can't modify the pages without honoring
		 * copy-on-write obligations first, so fall off
		 * this optimized path and fall back to the regular
		 * path.
		 */
		vm_object_unlock(object);
		return 0;
	}
	orig_offset = start_offset;

	dirty_count = 0;	
	while (io_requested && retval == 0) {

		cur_needed = (start_offset + io_requested + (PAGE_SIZE - 1)) / PAGE_SIZE;

		if (cur_needed > MAX_RUN)
		        cur_needed = MAX_RUN;
		
		for (cur_run = 0; cur_run < cur_needed; ) {

		        if ((dst_page = vm_page_lookup(object, offset)) == VM_PAGE_NULL)
			        break;


			if (dst_page->busy || dst_page->cleaning) {
				/*
				 * someone else is playing with the page... if we've
				 * already collected pages into this run, go ahead
				 * and process now, we can't block on this
				 * page while holding other pages in the BUSY state
				 * otherwise we will wait
				 */
				if (cur_run)
					break;
				PAGE_SLEEP(object, dst_page, THREAD_UNINT);
				continue;
			}
			if (dst_page->laundry)
				vm_pageout_steal_laundry(dst_page, FALSE);

		        if (mark_dirty) {
				if (dst_page->dirty == FALSE)
					dirty_count++;
				SET_PAGE_DIRTY(dst_page, FALSE);
				if (dst_page->cs_validated && 
				    !dst_page->cs_tainted) {
					/*
					 * CODE SIGNING:
					 * We're modifying a code-signed
					 * page: force revalidate
					 */
					dst_page->cs_validated = FALSE;
#if DEVELOPMENT || DEBUG
                                        vm_cs_validated_resets++;
#endif
					pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(dst_page));
				}
			}
			dst_page->busy = TRUE;

			page_run[cur_run++] = dst_page;

			offset += PAGE_SIZE_64;
		}
		if (cur_run == 0)
		        /*
			 * we hit a 'hole' in the cache or
			 * a page we don't want to try to handle,
			 * so bail at this point
			 * we'll unlock the object below
			 */
		        break;
		vm_object_unlock(object);

		for (i = 0; i < cur_run; i++) {
		  
		        dst_page = page_run[i];

			if ((xsize = PAGE_SIZE - start_offset) > io_requested)
			        xsize = io_requested;

			if ( (retval = uiomove64((addr64_t)(((addr64_t)(VM_PAGE_GET_PHYS_PAGE(dst_page)) << PAGE_SHIFT) + start_offset), xsize, uio)) )
			        break;

			io_requested -= xsize;
			start_offset = 0;
		}
		vm_object_lock(object);

		/*
		 * if we have more than 1 page to work on
		 * in the current run, or the original request
		 * started at offset 0 of the page, or we're
		 * processing multiple batches, we will move
		 * the pages to the tail of the inactive queue
		 * to implement an LRU for read/write accesses
		 *
		 * the check for orig_offset == 0 is there to 
		 * mitigate the cost of small (< page_size) requests
		 * to the same page (this way we only move it once)
		 */
		if (take_reference && (cur_run > 1 || orig_offset == 0)) {

			vm_page_lockspin_queues();

			for (i = 0; i < cur_run; i++)
				vm_page_lru(page_run[i]);

			vm_page_unlock_queues();
		}
		for (i = 0; i < cur_run; i++) {
		        dst_page = page_run[i];

			/*
			 * someone is explicitly referencing this page...
			 * update clustered and speculative state
			 * 
			 */
			if (dst_page->clustered)
				VM_PAGE_CONSUME_CLUSTERED(dst_page);

			PAGE_WAKEUP_DONE(dst_page);
		}
		orig_offset = 0;
	}
	if (object->pager)
		task_update_logical_writes(current_task(), (dirty_count * PAGE_SIZE), TASK_WRITE_DEFERRED, vnode_pager_lookup_vnode(object->pager));
	vm_object_unlock(object);
	return (retval);
}


/*
 *
 */
void
vnode_pager_bootstrap(void)
{
	vm_size_t      size;

	size = (vm_size_t) sizeof(struct vnode_pager);
	vnode_pager_zone = zinit(size, (vm_size_t) MAX_VNODE*size,
				PAGE_SIZE, "vnode pager structures");
	zone_change(vnode_pager_zone, Z_CALLERACCT, FALSE);
	zone_change(vnode_pager_zone, Z_NOENCRYPT, TRUE);


#if CONFIG_CODE_DECRYPTION
	apple_protect_pager_bootstrap();
#endif	/* CONFIG_CODE_DECRYPTION */
	swapfile_pager_bootstrap();
#if __arm64__
	fourk_pager_bootstrap();
#endif /* __arm64__ */
	return;
}

/*
 *
 */
memory_object_t
vnode_pager_setup(
	struct vnode	*vp,
	__unused memory_object_t	pager)
{
	vnode_pager_t	vnode_object;

	vnode_object = vnode_object_create(vp);
	if (vnode_object == VNODE_PAGER_NULL)
		panic("vnode_pager_setup: vnode_object_create() failed");
	return((memory_object_t)vnode_object);
}

/*
 *
 */
kern_return_t
vnode_pager_init(memory_object_t mem_obj, 
		memory_object_control_t control, 
#if !DEBUG
		 __unused
#endif
		 memory_object_cluster_size_t pg_size)
{
	vnode_pager_t   vnode_object;
	kern_return_t   kr;
	memory_object_attr_info_data_t  attributes;


	PAGER_DEBUG(PAGER_ALL, ("vnode_pager_init: %p, %p, %lx\n", mem_obj, control, (unsigned long)pg_size));

	if (control == MEMORY_OBJECT_CONTROL_NULL)
		return KERN_INVALID_ARGUMENT;

	vnode_object = vnode_pager_lookup(mem_obj);

	memory_object_control_reference(control);

	vnode_object->vn_pgr_hdr.mo_control = control;

	attributes.copy_strategy = MEMORY_OBJECT_COPY_DELAY;
	/* attributes.cluster_size = (1 << (CLUSTER_SHIFT + PAGE_SHIFT));*/
	attributes.cluster_size = (1 << (PAGE_SHIFT));
	attributes.may_cache_object = TRUE;
	attributes.temporary = TRUE;

	kr = memory_object_change_attributes(
					control,
					MEMORY_OBJECT_ATTRIBUTE_INFO,
					(memory_object_info_t) &attributes,
					MEMORY_OBJECT_ATTR_INFO_COUNT);
	if (kr != KERN_SUCCESS)
		panic("vnode_pager_init: memory_object_change_attributes() failed");

	return(KERN_SUCCESS);
}

/*
 *
 */
kern_return_t
vnode_pager_data_return(
        memory_object_t		mem_obj,
        memory_object_offset_t	offset,
        memory_object_cluster_size_t		data_cnt,
        memory_object_offset_t	*resid_offset,
	int			*io_error,
	__unused boolean_t		dirty,
	__unused boolean_t		kernel_copy,
	int			upl_flags)  
{
	vnode_pager_t	vnode_object;

	vnode_object = vnode_pager_lookup(mem_obj);

	vnode_pager_cluster_write(vnode_object, offset, data_cnt, resid_offset, io_error, upl_flags);

	return KERN_SUCCESS;
}

kern_return_t
vnode_pager_data_initialize(
	__unused memory_object_t		mem_obj,
	__unused memory_object_offset_t	offset,
	__unused memory_object_cluster_size_t		data_cnt)
{
	panic("vnode_pager_data_initialize");
	return KERN_FAILURE;
}

kern_return_t
vnode_pager_data_unlock(
	__unused memory_object_t		mem_obj,
	__unused memory_object_offset_t	offset,
	__unused memory_object_size_t		size,
	__unused vm_prot_t		desired_access)
{
	return KERN_FAILURE;
}

kern_return_t
vnode_pager_get_isinuse(
	memory_object_t		mem_obj,
	uint32_t		*isinuse)
{
	vnode_pager_t	vnode_object;

	if (mem_obj->mo_pager_ops != &vnode_pager_ops) {
		*isinuse = 1;
		return KERN_INVALID_ARGUMENT;
	}

	vnode_object = vnode_pager_lookup(mem_obj);

	*isinuse = vnode_pager_isinuse(vnode_object->vnode_handle);
	return KERN_SUCCESS;
}

kern_return_t
vnode_pager_get_throttle_io_limit(
	memory_object_t		mem_obj,
	uint32_t		*limit)
{
	vnode_pager_t	vnode_object;

	if (mem_obj->mo_pager_ops != &vnode_pager_ops)
		return KERN_INVALID_ARGUMENT;

	vnode_object = vnode_pager_lookup(mem_obj);

	(void)vnode_pager_return_throttle_io_limit(vnode_object->vnode_handle, limit);
	return KERN_SUCCESS;
}

kern_return_t
vnode_pager_get_isSSD(
	memory_object_t		mem_obj,
	boolean_t		*isSSD)
{
	vnode_pager_t	vnode_object;

	if (mem_obj->mo_pager_ops != &vnode_pager_ops)
		return KERN_INVALID_ARGUMENT;

	vnode_object = vnode_pager_lookup(mem_obj);

	*isSSD = vnode_pager_isSSD(vnode_object->vnode_handle);
	return KERN_SUCCESS;
}

kern_return_t
vnode_pager_get_object_size(
	memory_object_t		mem_obj,
	memory_object_offset_t	*length)
{
	vnode_pager_t	vnode_object;

	if (mem_obj->mo_pager_ops != &vnode_pager_ops) {
		*length = 0;
		return KERN_INVALID_ARGUMENT;
	}

	vnode_object = vnode_pager_lookup(mem_obj);

	*length = vnode_pager_get_filesize(vnode_object->vnode_handle);
	return KERN_SUCCESS;
}

kern_return_t
vnode_pager_get_object_name(
	memory_object_t		mem_obj,
	char			*pathname,
	vm_size_t		pathname_len,
	char			*filename,
	vm_size_t		filename_len,
	boolean_t		*truncated_path_p)
{
	vnode_pager_t	vnode_object;

	if (mem_obj->mo_pager_ops != &vnode_pager_ops) {
		return KERN_INVALID_ARGUMENT;
	}

	vnode_object = vnode_pager_lookup(mem_obj);

	return vnode_pager_get_name(vnode_object->vnode_handle,
				    pathname,
				    pathname_len,
				    filename,
				    filename_len,
				    truncated_path_p);
}

kern_return_t
vnode_pager_get_object_mtime(
	memory_object_t		mem_obj,
	struct timespec		*mtime,
	struct timespec		*cs_mtime)
{
	vnode_pager_t	vnode_object;

	if (mem_obj->mo_pager_ops != &vnode_pager_ops) {
		return KERN_INVALID_ARGUMENT;
	}

	vnode_object = vnode_pager_lookup(mem_obj);

	return vnode_pager_get_mtime(vnode_object->vnode_handle,
				     mtime,
				     cs_mtime);
}

#if CHECK_CS_VALIDATION_BITMAP
kern_return_t
vnode_pager_cs_check_validation_bitmap( 
	memory_object_t	mem_obj, 
	memory_object_offset_t	offset,
        int		optype	)
{
	vnode_pager_t	vnode_object;

	if (mem_obj == MEMORY_OBJECT_NULL ||
	    mem_obj->mo_pager_ops != &vnode_pager_ops) {
		return KERN_INVALID_ARGUMENT;
	}

	vnode_object = vnode_pager_lookup(mem_obj);
	return ubc_cs_check_validation_bitmap( vnode_object->vnode_handle, offset, optype );
}
#endif /* CHECK_CS_VALIDATION_BITMAP */

/*
 *
 */
kern_return_t	
vnode_pager_data_request(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	__unused memory_object_cluster_size_t	length,
	__unused vm_prot_t	desired_access,
	memory_object_fault_info_t	fault_info)
{
	vnode_pager_t		vnode_object;
	memory_object_offset_t	base_offset;
	vm_size_t		size;
	uint32_t		io_streaming = 0;

	vnode_object = vnode_pager_lookup(mem_obj);

	size = MAX_UPL_TRANSFER_BYTES;
	base_offset = offset;

	if (memory_object_cluster_size(vnode_object->vn_pgr_hdr.mo_control,
				       &base_offset, &size, &io_streaming,
				       fault_info) != KERN_SUCCESS)
	        size = PAGE_SIZE;

	assert(offset >= base_offset &&
	       offset < base_offset + size);

	return vnode_pager_cluster_read(vnode_object, base_offset, offset, io_streaming, size);
}

/*
 *
 */
void
vnode_pager_reference(
	memory_object_t		mem_obj)
{	
	vnode_pager_t	vnode_object;
	unsigned int		new_ref_count;

	vnode_object = vnode_pager_lookup(mem_obj);
	new_ref_count = hw_atomic_add(&vnode_object->ref_count, 1);
	assert(new_ref_count > 1);
}

/*
 *
 */
void
vnode_pager_deallocate(
	memory_object_t		mem_obj)
{
	vnode_pager_t	vnode_object;

	PAGER_DEBUG(PAGER_ALL, ("vnode_pager_deallocate: %p\n", mem_obj));

	vnode_object = vnode_pager_lookup(mem_obj);

	if (hw_atomic_sub(&vnode_object->ref_count, 1) == 0) {
		if (vnode_object->vnode_handle != NULL) {
			vnode_pager_vrele(vnode_object->vnode_handle);
		}
		zfree(vnode_pager_zone, vnode_object);
	}
	return;
}

/*
 *
 */
kern_return_t
vnode_pager_terminate(
#if !DEBUG
	__unused
#endif
	memory_object_t	mem_obj)
{
	PAGER_DEBUG(PAGER_ALL, ("vnode_pager_terminate: %p\n", mem_obj));

	return(KERN_SUCCESS);
}

/*
 *
 */
kern_return_t
vnode_pager_synchronize(
	__unused memory_object_t	mem_obj,
	__unused memory_object_offset_t	offset,
	__unused memory_object_size_t	length,
	__unused vm_sync_t		sync_flags)
{
	panic("vnode_pager_synchronize: memory_object_synchronize no longer supported\n");
	return (KERN_FAILURE);
}

/*
 *
 */
kern_return_t
vnode_pager_map(
	memory_object_t		mem_obj,
	vm_prot_t		prot)
{
	vnode_pager_t		vnode_object;
	int			ret;
	kern_return_t		kr;

	PAGER_DEBUG(PAGER_ALL, ("vnode_pager_map: %p %x\n", mem_obj, prot));

	vnode_object = vnode_pager_lookup(mem_obj);

	ret = ubc_map(vnode_object->vnode_handle, prot);

	if (ret != 0) {
		kr = KERN_FAILURE;
	} else {
		kr = KERN_SUCCESS;
	}

	return kr;
}

kern_return_t
vnode_pager_last_unmap(
	memory_object_t		mem_obj)
{
	vnode_pager_t	vnode_object;

	PAGER_DEBUG(PAGER_ALL, ("vnode_pager_last_unmap: %p\n", mem_obj));

	vnode_object = vnode_pager_lookup(mem_obj);

	ubc_unmap(vnode_object->vnode_handle);
	return KERN_SUCCESS;
}



/*
 *
 */
void
vnode_pager_cluster_write(
	vnode_pager_t		vnode_object,
	vm_object_offset_t	offset,
	vm_size_t		cnt,
	vm_object_offset_t   *	resid_offset,
	int		     *  io_error,
	int			upl_flags)
{
	vm_size_t	size;
	int		errno;

	if (upl_flags & UPL_MSYNC) {

	        upl_flags |= UPL_VNODE_PAGER;

		if ( (upl_flags & UPL_IOSYNC) && io_error)
		        upl_flags |= UPL_KEEPCACHED;

	        while (cnt) {
			size = (cnt < MAX_UPL_TRANSFER_BYTES) ? cnt : MAX_UPL_TRANSFER_BYTES; /* effective max */

			assert((upl_size_t) size == size);
			vnode_pageout(vnode_object->vnode_handle, 
				      NULL, (upl_offset_t)0, offset, (upl_size_t)size, upl_flags, &errno);

			if ( (upl_flags & UPL_KEEPCACHED) ) {
			        if ( (*io_error = errno) )
				        break;
			}
			cnt    -= size;
			offset += size;
		}
		if (resid_offset)
			*resid_offset = offset;

	} else {
	        vm_object_offset_t      vnode_size;
	        vm_object_offset_t	base_offset;

	        /*
		 * this is the pageout path
		 */
		vnode_size = vnode_pager_get_filesize(vnode_object->vnode_handle);

		if (vnode_size > (offset + PAGE_SIZE)) {
		        /*
			 * preset the maximum size of the cluster
			 * and put us on a nice cluster boundary...
			 * and then clip the size to insure we
			 * don't request past the end of the underlying file
			 */
		        size = MAX_UPL_TRANSFER_BYTES;
		        base_offset = offset & ~((signed)(size - 1));

			if ((base_offset + size) > vnode_size)
			        size = round_page(((vm_size_t)(vnode_size - base_offset)));
		} else {
		        /*
			 * we've been requested to page out a page beyond the current
			 * end of the 'file'... don't try to cluster in this case...
			 * we still need to send this page through because it might
			 * be marked precious and the underlying filesystem may need
			 * to do something with it (besides page it out)...
			 */
		        base_offset = offset;
			size = PAGE_SIZE;
		}
		assert((upl_size_t) size == size);
	        vnode_pageout(vnode_object->vnode_handle,
			      NULL, (upl_offset_t)(offset - base_offset), base_offset, (upl_size_t) size,
			      (upl_flags & UPL_IOSYNC) | UPL_VNODE_PAGER, NULL);
	}
}


/*
 *
 */
kern_return_t
vnode_pager_cluster_read(
	vnode_pager_t		vnode_object,
	vm_object_offset_t	base_offset,
	vm_object_offset_t	offset,
	uint32_t		io_streaming,
	vm_size_t		cnt)
{
	int		local_error = 0;
	int		kret;
	int		flags = 0;

	assert(! (cnt & PAGE_MASK));

	if (io_streaming)
		flags |= UPL_IOSTREAMING;

	assert((upl_size_t) cnt == cnt);
	kret = vnode_pagein(vnode_object->vnode_handle,
			    (upl_t) NULL,
			    (upl_offset_t) (offset - base_offset),
			    base_offset,
			    (upl_size_t) cnt,
			    flags,
			    &local_error);
/*
	if(kret == PAGER_ABSENT) {
	Need to work out the defs here, 1 corresponds to PAGER_ABSENT 
	defined in bsd/vm/vm_pager.h  However, we should not be including 
	that file here it is a layering violation.
*/
	if (kret == 1) {
		int	uplflags;
		upl_t	upl = NULL;
		unsigned int	count = 0;
		kern_return_t	kr;

		uplflags = (UPL_NO_SYNC |
			    UPL_CLEAN_IN_PLACE |
			    UPL_SET_INTERNAL);
		count = 0;
		assert((upl_size_t) cnt == cnt);
		kr = memory_object_upl_request(vnode_object->vn_pgr_hdr.mo_control,
					       base_offset, (upl_size_t) cnt,
					       &upl, NULL, &count, uplflags, VM_KERN_MEMORY_NONE);
		if (kr == KERN_SUCCESS) {
			upl_abort(upl, 0);
			upl_deallocate(upl);
		} else {
			/*
			 * We couldn't gather the page list, probably
			 * because the memory object doesn't have a link
			 * to a VM object anymore (forced unmount, for
			 * example).  Just return an error to the vm_fault()
			 * path and let it handle it.
			 */
		}

		return KERN_FAILURE;
	}

	return KERN_SUCCESS;

}

/*
 *
 */
vnode_pager_t
vnode_object_create(
        struct vnode *vp)
{
	vnode_pager_t  vnode_object;

	vnode_object = (struct vnode_pager *) zalloc(vnode_pager_zone);
	if (vnode_object == VNODE_PAGER_NULL)
		return(VNODE_PAGER_NULL);

	/*
	 * The vm_map call takes both named entry ports and raw memory
	 * objects in the same parameter.  We need to make sure that
	 * vm_map does not see this object as a named entry port.  So,
	 * we reserve the first word in the object for a fake ip_kotype
	 * setting - that will tell vm_map to use it as a memory object.
	 */
	vnode_object->vn_pgr_hdr.mo_ikot = IKOT_MEMORY_OBJECT;
	vnode_object->vn_pgr_hdr.mo_pager_ops = &vnode_pager_ops;
	vnode_object->vn_pgr_hdr.mo_control = MEMORY_OBJECT_CONTROL_NULL;

	vnode_object->ref_count = 1;
	vnode_object->vnode_handle = vp;

	return(vnode_object);
}

/*
 *
 */
vnode_pager_t
vnode_pager_lookup(
	memory_object_t	 name)
{
	vnode_pager_t	vnode_object;

	vnode_object = (vnode_pager_t)name;
	assert(vnode_object->vn_pgr_hdr.mo_pager_ops == &vnode_pager_ops);
	return (vnode_object);
}


struct vnode *
vnode_pager_lookup_vnode(
	memory_object_t  name)
{
	vnode_pager_t   vnode_object;
	vnode_object = (vnode_pager_t)name;
	if(vnode_object->vn_pgr_hdr.mo_pager_ops == &vnode_pager_ops)
		return (vnode_object->vnode_handle);
	else
		return NULL;
}

/*********************** proc_info implementation *************/

#include <sys/bsdtask_info.h>

static int fill_vnodeinfoforaddr( vm_map_entry_t entry, uintptr_t * vnodeaddr, uint32_t * vid);


int
fill_procregioninfo(task_t task, uint64_t arg, struct proc_regioninfo_internal *pinfo, uintptr_t *vnodeaddr, uint32_t  *vid)
{

	vm_map_t map;
	vm_map_offset_t	address = (vm_map_offset_t )arg;
	vm_map_entry_t		tmp_entry;
	vm_map_entry_t		entry;
	vm_map_offset_t		start;
	vm_region_extended_info_data_t extended;
	vm_region_top_info_data_t top;
	boolean_t do_region_footprint;

	    task_lock(task);
	    map = task->map;
	    if (map == VM_MAP_NULL) 
	    {
			task_unlock(task);
			return(0);
	    }
	    vm_map_reference(map); 
	    task_unlock(task);

	    do_region_footprint = task_self_region_footprint();

	    vm_map_lock_read(map);

	    start = address;

	    if (!vm_map_lookup_entry(map, start, &tmp_entry)) {
		if ((entry = tmp_entry->vme_next) == vm_map_to_entry(map)) {
			if (do_region_footprint &&
			    address == tmp_entry->vme_end) {
				ledger_amount_t nonvol, nonvol_compressed;

				/*
				 * This request is right after the last valid
				 * memory region;  instead of reporting the
				 * end of the address space, report a fake
				 * memory region to account for non-volatile
				 * purgeable memory owned by this task.
				 */

				ledger_get_balance(
					task->ledger,
					task_ledgers.purgeable_nonvolatile,
					&nonvol);
				ledger_get_balance(
					task->ledger,
					task_ledgers.purgeable_nonvolatile_compressed,
					&nonvol_compressed);
				if (nonvol + nonvol_compressed == 0) {
					/* nothing to report */
					vm_map_unlock_read(map);
					vm_map_deallocate(map);
					return 0;
				}
				/* provide fake region for purgeable */
				pinfo->pri_offset = address;
				pinfo->pri_protection = VM_PROT_DEFAULT;
				pinfo->pri_max_protection = VM_PROT_DEFAULT;
				pinfo->pri_inheritance = VM_INHERIT_NONE;
				pinfo->pri_behavior = VM_BEHAVIOR_DEFAULT;
				pinfo->pri_user_wired_count = 0;
				pinfo->pri_user_tag = -1;
				pinfo->pri_pages_resident =
					(uint32_t) (nonvol / PAGE_SIZE);
				pinfo->pri_pages_shared_now_private = 0;
				pinfo->pri_pages_swapped_out =
					(uint32_t) (nonvol_compressed / PAGE_SIZE);
				pinfo->pri_pages_dirtied =
					(uint32_t) (nonvol / PAGE_SIZE);
				pinfo->pri_ref_count = 1;
				pinfo->pri_shadow_depth = 0;
				pinfo->pri_share_mode = SM_PRIVATE;
				pinfo->pri_private_pages_resident =
					(uint32_t) (nonvol / PAGE_SIZE);
				pinfo->pri_shared_pages_resident = 0;
				pinfo->pri_obj_id = INFO_MAKE_FAKE_OBJECT_ID(map, task_ledgers.purgeable_nonvolatile);
				pinfo->pri_address = address;
				pinfo->pri_size =
					(uint64_t) (nonvol + nonvol_compressed);
				pinfo->pri_depth = 0;

				vm_map_unlock_read(map);
				vm_map_deallocate(map);
				return 1;
			}
			vm_map_unlock_read(map);
			vm_map_deallocate(map);
			return 0;
		}
	    } else {
		entry = tmp_entry;
	    }

	    start = entry->vme_start;

	    pinfo->pri_offset = VME_OFFSET(entry);
	    pinfo->pri_protection = entry->protection;
	    pinfo->pri_max_protection = entry->max_protection;
	    pinfo->pri_inheritance = entry->inheritance;
	    pinfo->pri_behavior = entry->behavior;
	    pinfo->pri_user_wired_count = entry->user_wired_count;
	    pinfo->pri_user_tag = VME_ALIAS(entry);

	    if (entry->is_sub_map) {
		pinfo->pri_flags |= PROC_REGION_SUBMAP;
	    } else {
		if (entry->is_shared)
			pinfo->pri_flags |= PROC_REGION_SHARED;
	    }


	    extended.protection = entry->protection;
	    extended.user_tag = VME_ALIAS(entry);
	    extended.pages_resident = 0;
	    extended.pages_swapped_out = 0;
	    extended.pages_shared_now_private = 0;
	    extended.pages_dirtied = 0;
	    extended.external_pager = 0;
	    extended.shadow_depth = 0;

	    vm_map_region_walk(map, start, entry, VME_OFFSET(entry), entry->vme_end - start, &extended, TRUE, VM_REGION_EXTENDED_INFO_COUNT);

	    if (extended.external_pager && extended.ref_count == 2 && extended.share_mode == SM_SHARED)
	            extended.share_mode = SM_PRIVATE;

	    top.private_pages_resident = 0;
	    top.shared_pages_resident = 0;
	    vm_map_region_top_walk(entry, &top);

	
	    pinfo->pri_pages_resident = extended.pages_resident;
	    pinfo->pri_pages_shared_now_private = extended.pages_shared_now_private;
	    pinfo->pri_pages_swapped_out = extended.pages_swapped_out;
	    pinfo->pri_pages_dirtied = extended.pages_dirtied;
	    pinfo->pri_ref_count = extended.ref_count;
	    pinfo->pri_shadow_depth = extended.shadow_depth;
	    pinfo->pri_share_mode = extended.share_mode;

	    pinfo->pri_private_pages_resident = top.private_pages_resident;
	    pinfo->pri_shared_pages_resident = top.shared_pages_resident;
	    pinfo->pri_obj_id = top.obj_id;
		
	    pinfo->pri_address = (uint64_t)start;
	    pinfo->pri_size = (uint64_t)(entry->vme_end - start);
	    pinfo->pri_depth = 0;
	
	    if ((vnodeaddr != 0) && (entry->is_sub_map == 0)) {
		*vnodeaddr = (uintptr_t)0;

		if (fill_vnodeinfoforaddr(entry, vnodeaddr, vid) ==0) {
			vm_map_unlock_read(map);
	    		vm_map_deallocate(map); 
			return(1);
		}
	    }

	    vm_map_unlock_read(map);
	    vm_map_deallocate(map); 
	    return(1);
}

int
fill_procregioninfo_onlymappedvnodes(task_t task, uint64_t arg, struct proc_regioninfo_internal *pinfo, uintptr_t *vnodeaddr, uint32_t  *vid)
{

	vm_map_t map;
	vm_map_offset_t	address = (vm_map_offset_t )arg;
	vm_map_entry_t		tmp_entry;
	vm_map_entry_t		entry;

	task_lock(task);
	map = task->map;
	if (map == VM_MAP_NULL) 
	{
		task_unlock(task);
		return(0);
	}
	vm_map_reference(map); 
	task_unlock(task);
	
	vm_map_lock_read(map);

	if (!vm_map_lookup_entry(map, address, &tmp_entry)) {
		if ((entry = tmp_entry->vme_next) == vm_map_to_entry(map)) {
			vm_map_unlock_read(map);
			vm_map_deallocate(map); 
		   	return(0);
		}
	} else {
		entry = tmp_entry;
	}

	while (entry != vm_map_to_entry(map)) {
		*vnodeaddr = 0;
		*vid = 0;

		if (entry->is_sub_map == 0) {
			if (fill_vnodeinfoforaddr(entry, vnodeaddr, vid)) {

				pinfo->pri_offset = VME_OFFSET(entry);
				pinfo->pri_protection = entry->protection;
				pinfo->pri_max_protection = entry->max_protection;
				pinfo->pri_inheritance = entry->inheritance;
				pinfo->pri_behavior = entry->behavior;
				pinfo->pri_user_wired_count = entry->user_wired_count;
				pinfo->pri_user_tag = VME_ALIAS(entry);
				
				if (entry->is_shared)
					pinfo->pri_flags |= PROC_REGION_SHARED;
				
				pinfo->pri_pages_resident = 0;
				pinfo->pri_pages_shared_now_private = 0;
				pinfo->pri_pages_swapped_out = 0;
				pinfo->pri_pages_dirtied = 0;
				pinfo->pri_ref_count = 0;
				pinfo->pri_shadow_depth = 0;
				pinfo->pri_share_mode = 0;
				
				pinfo->pri_private_pages_resident = 0;
				pinfo->pri_shared_pages_resident = 0;
				pinfo->pri_obj_id = 0;
				
				pinfo->pri_address = (uint64_t)entry->vme_start;
				pinfo->pri_size = (uint64_t)(entry->vme_end - entry->vme_start);
				pinfo->pri_depth = 0;
	
				vm_map_unlock_read(map);
				vm_map_deallocate(map); 
				return(1);
			}
		}

		/* Keep searching for a vnode-backed mapping */
		entry = entry->vme_next;
	}

	vm_map_unlock_read(map);
	vm_map_deallocate(map); 
	return(0);
}

static int
fill_vnodeinfoforaddr(
	vm_map_entry_t			entry,
	uintptr_t * vnodeaddr,
	uint32_t * vid)
{
	vm_object_t	top_object, object;
	memory_object_t memory_object;
	memory_object_pager_ops_t pager_ops;
	kern_return_t	kr;
	int		shadow_depth;


	if (entry->is_sub_map) {
		return(0);
	} else {
		/*
		 * The last object in the shadow chain has the
		 * relevant pager information.
		 */
		top_object = VME_OBJECT(entry);
		if (top_object == VM_OBJECT_NULL) {
			object = VM_OBJECT_NULL;
			shadow_depth = 0;
		} else {
			vm_object_lock(top_object);
			for (object = top_object, shadow_depth = 0;
			     object->shadow != VM_OBJECT_NULL;
			     object = object->shadow, shadow_depth++) {
				vm_object_lock(object->shadow);
				vm_object_unlock(object);
			}
		}
	}

	if (object == VM_OBJECT_NULL) {
		return(0);
	} else if (object->internal) {
		vm_object_unlock(object);
		return(0);
	} else if (! object->pager_ready ||
		   object->terminating ||
		   ! object->alive) {
		vm_object_unlock(object);
		return(0);
	} else {
		memory_object = object->pager;
		pager_ops = memory_object->mo_pager_ops;
		if (pager_ops == &vnode_pager_ops) {
			kr = vnode_pager_get_object_vnode(
				memory_object,
				vnodeaddr, vid);
			if (kr != KERN_SUCCESS) {
				vm_object_unlock(object);
				return(0);
			}
		} else {
			vm_object_unlock(object);
			return(0);
		}
	}
	vm_object_unlock(object);
	return(1);
}

kern_return_t 
vnode_pager_get_object_vnode (
	memory_object_t		mem_obj,
	uintptr_t * vnodeaddr,
	uint32_t * vid)
{
	vnode_pager_t	vnode_object;

	vnode_object = vnode_pager_lookup(mem_obj);
	if (vnode_object->vnode_handle)  {
		*vnodeaddr = (uintptr_t)vnode_object->vnode_handle;
		*vid = (uint32_t)vnode_vid((void *)vnode_object->vnode_handle);	

		return(KERN_SUCCESS);
	}
	
	return(KERN_FAILURE);
}

#if CONFIG_IOSCHED
kern_return_t
vnode_pager_get_object_devvp(
	memory_object_t 	mem_obj,
	uintptr_t 		*devvp)
{
	struct vnode 	*vp;
	uint32_t 	vid;

	if(vnode_pager_get_object_vnode(mem_obj, (uintptr_t *)&vp, (uint32_t *)&vid) != KERN_SUCCESS)
		return (KERN_FAILURE);
	*devvp = (uintptr_t)vnode_mountdevvp(vp);
	if (*devvp)
		return (KERN_SUCCESS);	
	return (KERN_FAILURE);
}
#endif

/*
 * Find the underlying vnode object for the given vm_map_entry.  If found, return with the
 * object locked, otherwise return NULL with nothing locked.
 */

vm_object_t
find_vnode_object(
	vm_map_entry_t	entry
)
{
	vm_object_t			top_object, object;
	memory_object_t 		memory_object;
	memory_object_pager_ops_t	pager_ops;

	if (!entry->is_sub_map) {

		/*
		 * The last object in the shadow chain has the
		 * relevant pager information.
		 */

		top_object = VME_OBJECT(entry);

		if (top_object) {
			vm_object_lock(top_object);

			for (object = top_object; object->shadow != VM_OBJECT_NULL; object = object->shadow) {
				vm_object_lock(object->shadow);
				vm_object_unlock(object);
			}

			if (object && !object->internal && object->pager_ready && !object->terminating &&
			    object->alive) {
				memory_object = object->pager;
				pager_ops = memory_object->mo_pager_ops;

				/*
				 * If this object points to the vnode_pager_ops, then we found what we're
				 * looking for.  Otherwise, this vm_map_entry doesn't have an underlying
				 * vnode and so we fall through to the bottom and return NULL.
				 */

				if (pager_ops == &vnode_pager_ops) 
					return object;		/* we return with the object locked */
			}

			vm_object_unlock(object);
		}

	}

	return(VM_OBJECT_NULL);
}
