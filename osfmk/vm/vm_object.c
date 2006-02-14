/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
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
 */
/*
 *	File:	vm/vm_object.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *
 *	Virtual memory object module.
 */

#include <mach_pagemap.h>
#include <task_swapper.h>

#include <mach/mach_types.h>
#include <mach/memory_object.h>
#include <mach/memory_object_default.h>
#include <mach/memory_object_control_server.h>
#include <mach/vm_param.h>

#include <ipc/ipc_types.h>
#include <ipc/ipc_port.h>

#include <kern/kern_types.h>
#include <kern/assert.h>
#include <kern/lock.h>
#include <kern/queue.h>
#include <kern/xpr.h>
#include <kern/zalloc.h>
#include <kern/host.h>
#include <kern/host_statistics.h>
#include <kern/processor.h>
#include <kern/misc_protos.h>

#include <vm/memory_object.h>
#include <vm/vm_fault.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>

/*
 *	Virtual memory objects maintain the actual data
 *	associated with allocated virtual memory.  A given
 *	page of memory exists within exactly one object.
 *
 *	An object is only deallocated when all "references"
 *	are given up.
 *
 *	Associated with each object is a list of all resident
 *	memory pages belonging to that object; this list is
 *	maintained by the "vm_page" module, but locked by the object's
 *	lock.
 *
 *	Each object also records the memory object reference
 *	that is used by the kernel to request and write
 *	back data (the memory object, field "pager"), etc...
 *
 *	Virtual memory objects are allocated to provide
 *	zero-filled memory (vm_allocate) or map a user-defined
 *	memory object into a virtual address space (vm_map).
 *
 *	Virtual memory objects that refer to a user-defined
 *	memory object are called "permanent", because all changes
 *	made in virtual memory are reflected back to the
 *	memory manager, which may then store it permanently.
 *	Other virtual memory objects are called "temporary",
 *	meaning that changes need be written back only when
 *	necessary to reclaim pages, and that storage associated
 *	with the object can be discarded once it is no longer
 *	mapped.
 *
 *	A permanent memory object may be mapped into more
 *	than one virtual address space.  Moreover, two threads
 *	may attempt to make the first mapping of a memory
 *	object concurrently.  Only one thread is allowed to
 *	complete this mapping; all others wait for the
 *	"pager_initialized" field is asserted, indicating
 *	that the first thread has initialized all of the
 *	necessary fields in the virtual memory object structure.
 *
 *	The kernel relies on a *default memory manager* to
 *	provide backing storage for the zero-filled virtual
 *	memory objects.  The pager memory objects associated
 *	with these temporary virtual memory objects are only
 *	requested from the default memory manager when it
 *	becomes necessary.  Virtual memory objects
 *	that depend on the default memory manager are called
 *	"internal".  The "pager_created" field is provided to
 *	indicate whether these ports have ever been allocated.
 *	
 *	The kernel may also create virtual memory objects to
 *	hold changed pages after a copy-on-write operation.
 *	In this case, the virtual memory object (and its
 *	backing storage -- its memory object) only contain
 *	those pages that have been changed.  The "shadow"
 *	field refers to the virtual memory object that contains
 *	the remainder of the contents.  The "shadow_offset"
 *	field indicates where in the "shadow" these contents begin.
 *	The "copy" field refers to a virtual memory object
 *	to which changed pages must be copied before changing
 *	this object, in order to implement another form
 *	of copy-on-write optimization.
 *
 *	The virtual memory object structure also records
 *	the attributes associated with its memory object.
 *	The "pager_ready", "can_persist" and "copy_strategy"
 *	fields represent those attributes.  The "cached_list"
 *	field is used in the implementation of the persistence
 *	attribute.
 *
 * ZZZ Continue this comment.
 */

/* Forward declarations for internal functions. */
static kern_return_t	vm_object_terminate(
				vm_object_t	object);

extern void		vm_object_remove(
				vm_object_t	object);

static vm_object_t	vm_object_cache_trim(
				boolean_t called_from_vm_object_deallocate);

static void		vm_object_deactivate_all_pages(
				vm_object_t	object);

static kern_return_t	vm_object_copy_call(
				vm_object_t		src_object,
				vm_object_offset_t	src_offset,
				vm_object_size_t	size,
				vm_object_t		*_result_object);

static void		vm_object_do_collapse(
				vm_object_t	object,
				vm_object_t	backing_object);

static void		vm_object_do_bypass(
				vm_object_t	object,
				vm_object_t	backing_object);

static void		vm_object_release_pager(
				memory_object_t	pager);

static zone_t		vm_object_zone;		/* vm backing store zone */

/*
 *	All wired-down kernel memory belongs to a single virtual
 *	memory object (kernel_object) to avoid wasting data structures.
 */
static struct vm_object			kernel_object_store;
__private_extern__ vm_object_t		kernel_object = &kernel_object_store;

/*
 *	The submap object is used as a placeholder for vm_map_submap
 *	operations.  The object is declared in vm_map.c because it
 *	is exported by the vm_map module.  The storage is declared
 *	here because it must be initialized here.
 */
static struct vm_object			vm_submap_object_store;

/*
 *	Virtual memory objects are initialized from
 *	a template (see vm_object_allocate).
 *
 *	When adding a new field to the virtual memory
 *	object structure, be sure to add initialization
 *	(see _vm_object_allocate()).
 */
static struct vm_object			vm_object_template;

/*
 *	Virtual memory objects that are not referenced by
 *	any address maps, but that are allowed to persist
 *	(an attribute specified by the associated memory manager),
 *	are kept in a queue (vm_object_cached_list).
 *
 *	When an object from this queue is referenced again,
 *	for example to make another address space mapping,
 *	it must be removed from the queue.  That is, the
 *	queue contains *only* objects with zero references.
 *
 *	The kernel may choose to terminate objects from this
 *	queue in order to reclaim storage.  The current policy
 *	is to permit a fixed maximum number of unreferenced
 *	objects (vm_object_cached_max).
 *
 *	A spin lock (accessed by routines
 *	vm_object_cache_{lock,lock_try,unlock}) governs the
 *	object cache.  It must be held when objects are
 *	added to or removed from the cache (in vm_object_terminate).
 *	The routines that acquire a reference to a virtual
 *	memory object based on one of the memory object ports
 *	must also lock the cache.
 *
 *	Ideally, the object cache should be more isolated
 *	from the reference mechanism, so that the lock need
 *	not be held to make simple references.
 */
static queue_head_t	vm_object_cached_list;
static int		vm_object_cached_count=0;
static int		vm_object_cached_high;	/* highest # cached objects */
static int		vm_object_cached_max = 512;	/* may be patched*/

static decl_mutex_data(,vm_object_cached_lock_data)

#define vm_object_cache_lock()		\
		mutex_lock(&vm_object_cached_lock_data)
#define vm_object_cache_lock_try()	\
		mutex_try(&vm_object_cached_lock_data)
#define vm_object_cache_unlock()	\
		mutex_unlock(&vm_object_cached_lock_data)

#define	VM_OBJECT_HASH_COUNT		1024
static queue_head_t	vm_object_hashtable[VM_OBJECT_HASH_COUNT];
static struct zone		*vm_object_hash_zone;

struct vm_object_hash_entry {
	queue_chain_t		hash_link;	/* hash chain link */
	memory_object_t	pager;		/* pager we represent */
	vm_object_t		object;		/* corresponding object */
	boolean_t		waiting;	/* someone waiting for
						 * termination */
};

typedef struct vm_object_hash_entry	*vm_object_hash_entry_t;
#define VM_OBJECT_HASH_ENTRY_NULL	((vm_object_hash_entry_t) 0)

#define VM_OBJECT_HASH_SHIFT	8
#define vm_object_hash(pager) \
	((((unsigned)pager) >> VM_OBJECT_HASH_SHIFT) % VM_OBJECT_HASH_COUNT)

void vm_object_hash_entry_free(
	vm_object_hash_entry_t	entry);

/*
 *	vm_object_hash_lookup looks up a pager in the hashtable
 *	and returns the corresponding entry, with optional removal.
 */

static vm_object_hash_entry_t
vm_object_hash_lookup(
	memory_object_t	pager,
	boolean_t	remove_entry)
{
	register queue_t		bucket;
	register vm_object_hash_entry_t	entry;

	bucket = &vm_object_hashtable[vm_object_hash(pager)];

	entry = (vm_object_hash_entry_t)queue_first(bucket);
	while (!queue_end(bucket, (queue_entry_t)entry)) {
		if (entry->pager == pager && !remove_entry)
			return(entry);
		else if (entry->pager == pager) {
			queue_remove(bucket, entry,
					vm_object_hash_entry_t, hash_link);
			return(entry);
		}

		entry = (vm_object_hash_entry_t)queue_next(&entry->hash_link);
	}

	return(VM_OBJECT_HASH_ENTRY_NULL);
}

/*
 *	vm_object_hash_enter enters the specified
 *	pager / cache object association in the hashtable.
 */

static void
vm_object_hash_insert(
	vm_object_hash_entry_t	entry)
{
	register queue_t		bucket;

	bucket = &vm_object_hashtable[vm_object_hash(entry->pager)];

	queue_enter(bucket, entry, vm_object_hash_entry_t, hash_link);
}

static vm_object_hash_entry_t
vm_object_hash_entry_alloc(
	memory_object_t	pager)
{
	vm_object_hash_entry_t	entry;

	entry = (vm_object_hash_entry_t)zalloc(vm_object_hash_zone);
	entry->pager = pager;
	entry->object = VM_OBJECT_NULL;
	entry->waiting = FALSE;

	return(entry);
}

void
vm_object_hash_entry_free(
	vm_object_hash_entry_t	entry)
{
	zfree(vm_object_hash_zone, entry);
}

/*
 *	vm_object_allocate:
 *
 *	Returns a new object with the given size.
 */

__private_extern__ void
_vm_object_allocate(
	vm_object_size_t	size,
	vm_object_t		object)
{
	XPR(XPR_VM_OBJECT,
		"vm_object_allocate, object 0x%X size 0x%X\n",
		(integer_t)object, size, 0,0,0);

	*object = vm_object_template;
	queue_init(&object->memq);
	queue_init(&object->msr_q);
#ifdef UPL_DEBUG
	queue_init(&object->uplq);
#endif /* UPL_DEBUG */
	vm_object_lock_init(object);
	object->size = size;
}

__private_extern__ vm_object_t
vm_object_allocate(
	vm_object_size_t	size)
{
	register vm_object_t object;

	object = (vm_object_t) zalloc(vm_object_zone);
	
//	dbgLog(object, size, 0, 2);			/* (TEST/DEBUG) */

	if (object != VM_OBJECT_NULL)
		_vm_object_allocate(size, object);

	return object;
}

/*
 *	vm_object_bootstrap:
 *
 *	Initialize the VM objects module.
 */
__private_extern__ void
vm_object_bootstrap(void)
{
	register int	i;

	vm_object_zone = zinit((vm_size_t) sizeof(struct vm_object),
				round_page_32(512*1024),
				round_page_32(12*1024),
				"vm objects");

	queue_init(&vm_object_cached_list);
	mutex_init(&vm_object_cached_lock_data, 0);

	vm_object_hash_zone =
			zinit((vm_size_t) sizeof (struct vm_object_hash_entry),
			      round_page_32(512*1024),
			      round_page_32(12*1024),
			      "vm object hash entries");

	for (i = 0; i < VM_OBJECT_HASH_COUNT; i++)
		queue_init(&vm_object_hashtable[i]);

	/*
	 *	Fill in a template object, for quick initialization
	 */

	/* memq; Lock; init after allocation */
	vm_object_template.size = 0;
	vm_object_template.memq_hint = VM_PAGE_NULL;
	vm_object_template.ref_count = 1;
#if	TASK_SWAPPER
	vm_object_template.res_count = 1;
#endif	/* TASK_SWAPPER */
	vm_object_template.resident_page_count = 0;
	vm_object_template.copy = VM_OBJECT_NULL;
	vm_object_template.shadow = VM_OBJECT_NULL;
	vm_object_template.shadow_offset = (vm_object_offset_t) 0;
	vm_object_template.cow_hint = ~(vm_offset_t)0;
	vm_object_template.true_share = FALSE;

	vm_object_template.pager = MEMORY_OBJECT_NULL;
	vm_object_template.paging_offset = 0;
	vm_object_template.pager_control = MEMORY_OBJECT_CONTROL_NULL;
	/* msr_q; init after allocation */

	vm_object_template.copy_strategy = MEMORY_OBJECT_COPY_SYMMETRIC;
	vm_object_template.absent_count = 0;
	vm_object_template.paging_in_progress = 0;

	/* Begin bitfields */
	vm_object_template.all_wanted = 0; /* all bits FALSE */
	vm_object_template.pager_created = FALSE;
	vm_object_template.pager_initialized = FALSE;
	vm_object_template.pager_ready = FALSE;
	vm_object_template.pager_trusted = FALSE;
	vm_object_template.can_persist = FALSE;
	vm_object_template.internal = TRUE;
	vm_object_template.temporary = TRUE;
	vm_object_template.private = FALSE;
	vm_object_template.pageout = FALSE;
	vm_object_template.alive = TRUE;
	vm_object_template.purgable = VM_OBJECT_NONPURGABLE;
	vm_object_template.silent_overwrite = FALSE;
	vm_object_template.advisory_pageout = FALSE;
	vm_object_template.shadowed = FALSE;
	vm_object_template.terminating = FALSE;
	vm_object_template.shadow_severed = FALSE;
	vm_object_template.phys_contiguous = FALSE;
	vm_object_template.nophyscache = FALSE;
	/* End bitfields */

	/* cache bitfields */
	vm_object_template.wimg_bits = VM_WIMG_DEFAULT;

	/* cached_list; init after allocation */
	vm_object_template.last_alloc = (vm_object_offset_t) 0;
	vm_object_template.cluster_size = 0;
#if	MACH_PAGEMAP
	vm_object_template.existence_map = VM_EXTERNAL_NULL;
#endif	/* MACH_PAGEMAP */
#if	MACH_ASSERT
	vm_object_template.paging_object = VM_OBJECT_NULL;
#endif	/* MACH_ASSERT */

	/*
	 *	Initialize the "kernel object"
	 */

	kernel_object = &kernel_object_store;

/*
 *	Note that in the following size specifications, we need to add 1 because 
 *	VM_MAX_KERNEL_ADDRESS (vm_last_addr) is a maximum address, not a size.
 */

#ifdef ppc
	_vm_object_allocate((vm_last_addr - VM_MIN_KERNEL_ADDRESS) + 1,
			kernel_object);
#else
	_vm_object_allocate((VM_MAX_KERNEL_ADDRESS - VM_MIN_KERNEL_ADDRESS) + 1,
			kernel_object);
#endif
	kernel_object->copy_strategy = MEMORY_OBJECT_COPY_NONE;

	/*
	 *	Initialize the "submap object".  Make it as large as the
	 *	kernel object so that no limit is imposed on submap sizes.
	 */

	vm_submap_object = &vm_submap_object_store;
#ifdef ppc
	_vm_object_allocate((vm_last_addr - VM_MIN_KERNEL_ADDRESS) + 1,
			vm_submap_object);
#else
	_vm_object_allocate((VM_MAX_KERNEL_ADDRESS - VM_MIN_KERNEL_ADDRESS) + 1,
			vm_submap_object);
#endif
	vm_submap_object->copy_strategy = MEMORY_OBJECT_COPY_NONE;

	/*
	 * Create an "extra" reference to this object so that we never
	 * try to deallocate it; zfree doesn't like to be called with
	 * non-zone memory.
	 */
	vm_object_reference(vm_submap_object);

#if	MACH_PAGEMAP
	vm_external_module_initialize();
#endif	/* MACH_PAGEMAP */
}

__private_extern__ void
vm_object_init(void)
{
	/*
	 *	Finish initializing the kernel object.
	 */
}

/* remove the typedef below when emergency work-around is taken out */
typedef struct vnode_pager {
	memory_object_t pager;
	memory_object_t pager_handle;	/* pager */
	memory_object_control_t 	control_handle;	/* memory object's control handle */
	void	   	*vnode_handle;  /* vnode handle */
} *vnode_pager_t;

#define	MIGHT_NOT_CACHE_SHADOWS		1
#if	MIGHT_NOT_CACHE_SHADOWS
static int cache_shadows = TRUE;
#endif	/* MIGHT_NOT_CACHE_SHADOWS */

/*
 *	vm_object_deallocate:
 *
 *	Release a reference to the specified object,
 *	gained either through a vm_object_allocate
 *	or a vm_object_reference call.  When all references
 *	are gone, storage associated with this object
 *	may be relinquished.
 *
 *	No object may be locked.
 */
__private_extern__ void
vm_object_deallocate(
	register vm_object_t	object)
{
	boolean_t retry_cache_trim = FALSE;
	vm_object_t shadow = VM_OBJECT_NULL;
	
//	if(object)dbgLog(object, object->ref_count, object->can_persist, 3);	/* (TEST/DEBUG) */
//	else dbgLog(object, 0, 0, 3);	/* (TEST/DEBUG) */


	while (object != VM_OBJECT_NULL) {

		/*
		 *	The cache holds a reference (uncounted) to
		 *	the object; we must lock it before removing
		 *	the object.
		 */
	        for (;;) {
		        vm_object_cache_lock();

			/*
			 * if we try to take a regular lock here
			 * we risk deadlocking against someone
			 * holding a lock on this object while
			 * trying to vm_object_deallocate a different
			 * object
			 */
			if (vm_object_lock_try(object))
			        break;
		        vm_object_cache_unlock();
			mutex_pause();  /* wait a bit */
		}
		assert(object->ref_count > 0);

		/*
		 *	If the object has a named reference, and only
		 *	that reference would remain, inform the pager
		 *	about the last "mapping" reference going away.
		 */
		if ((object->ref_count == 2)  && (object->named)) {
			memory_object_t	pager = object->pager;

			/* Notify the Pager that there are no */
			/* more mappers for this object */

			if (pager != MEMORY_OBJECT_NULL) {
				vm_object_unlock(object);
				vm_object_cache_unlock();
					
				memory_object_unmap(pager);

				for (;;) {
				        vm_object_cache_lock();

					/*
					 * if we try to take a regular lock here
					 * we risk deadlocking against someone
					 * holding a lock on this object while
					 * trying to vm_object_deallocate a different
					 * object
					 */
					if (vm_object_lock_try(object))
					        break;
					vm_object_cache_unlock();
					mutex_pause();  /* wait a bit */
				}
				assert(object->ref_count > 0);
			}
		}

		/*
		 *	Lose the reference. If other references
		 *	remain, then we are done, unless we need
		 *	to retry a cache trim.
		 *	If it is the last reference, then keep it
		 *	until any pending initialization is completed.
		 */

		/* if the object is terminating, it cannot go into */
		/* the cache and we obviously should not call      */
		/* terminate again.  */

		if ((object->ref_count > 1) || object->terminating) {
			object->ref_count--;
			vm_object_res_deallocate(object);
			vm_object_cache_unlock();

			if (object->ref_count == 1 &&
			    object->shadow != VM_OBJECT_NULL) {
				/*
				 * We don't use this VM object anymore.  We
				 * would like to collapse it into its parent(s),
				 * but we don't have any pointers back to these
				 * parent object(s).
				 * But we can try and collapse this object with
				 * its own shadows, in case these are useless
				 * too...
				 */
				vm_object_collapse(object, 0);
			}

			vm_object_unlock(object); 
			if (retry_cache_trim &&
			    ((object = vm_object_cache_trim(TRUE)) !=
			     VM_OBJECT_NULL)) {
				continue;
			}
			return;
		}

		/*
		 *	We have to wait for initialization
		 *	before destroying or caching the object.
		 */
		
		if (object->pager_created && ! object->pager_initialized) {
			assert(! object->can_persist);
			vm_object_assert_wait(object,
					      VM_OBJECT_EVENT_INITIALIZED,
					      THREAD_UNINT);
			vm_object_unlock(object);
			vm_object_cache_unlock();
			thread_block(THREAD_CONTINUE_NULL);
			continue;
		}

		/*
		 *	If this object can persist, then enter it in
		 *	the cache. Otherwise, terminate it.
		 *
		 * 	NOTE:  Only permanent objects are cached, and
		 *	permanent objects cannot have shadows.  This
		 *	affects the residence counting logic in a minor
		 *	way (can do it in-line, mostly).
		 */

		if ((object->can_persist) && (object->alive)) {
			/*
			 *	Now it is safe to decrement reference count,
			 *	and to return if reference count is > 0.
			 */
			if (--object->ref_count > 0) {
				vm_object_res_deallocate(object);
				vm_object_unlock(object);
				vm_object_cache_unlock();
				if (retry_cache_trim &&
				    ((object = vm_object_cache_trim(TRUE)) !=
				     VM_OBJECT_NULL)) {
					continue;
				}
				return;
			}

#if	MIGHT_NOT_CACHE_SHADOWS
			/*
			 *	Remove shadow now if we don't
			 *	want to cache shadows.
			 */
			if (! cache_shadows) {
				shadow = object->shadow;
				object->shadow = VM_OBJECT_NULL;
			}
#endif	/* MIGHT_NOT_CACHE_SHADOWS */

			/*
			 *	Enter the object onto the queue of
			 *	cached objects, and deactivate
			 *	all of its pages.
			 */
			assert(object->shadow == VM_OBJECT_NULL);
			VM_OBJ_RES_DECR(object);
			XPR(XPR_VM_OBJECT,
		      "vm_o_deallocate: adding %x to cache, queue = (%x, %x)\n",
				(integer_t)object,
				(integer_t)vm_object_cached_list.next,
				(integer_t)vm_object_cached_list.prev,0,0);

			vm_object_cached_count++;
			if (vm_object_cached_count > vm_object_cached_high)
				vm_object_cached_high = vm_object_cached_count;
			queue_enter(&vm_object_cached_list, object,
				vm_object_t, cached_list);
			vm_object_cache_unlock();
			vm_object_deactivate_all_pages(object);
			vm_object_unlock(object);

#if	MIGHT_NOT_CACHE_SHADOWS
			/*
			 *	If we have a shadow that we need
			 *	to deallocate, do so now, remembering
			 *	to trim the cache later.
			 */
			if (! cache_shadows && shadow != VM_OBJECT_NULL) {
				object = shadow;
				retry_cache_trim = TRUE;
				continue;
			}
#endif	/* MIGHT_NOT_CACHE_SHADOWS */

			/*
			 *	Trim the cache. If the cache trim
			 *	returns with a shadow for us to deallocate,
			 *	then remember to retry the cache trim
			 *	when we are done deallocating the shadow.
			 *	Otherwise, we are done.
			 */

			object = vm_object_cache_trim(TRUE);
			if (object == VM_OBJECT_NULL) {
				return;
			}
			retry_cache_trim = TRUE;

		} else {
			/*
			 *	This object is not cachable; terminate it.
			 */
			XPR(XPR_VM_OBJECT,
	 "vm_o_deallocate: !cacheable 0x%X res %d paging_ops %d thread 0x%p ref %d\n",
			    (integer_t)object, object->resident_page_count,
			    object->paging_in_progress,
			    (void *)current_thread(),object->ref_count);

			VM_OBJ_RES_DECR(object);	/* XXX ? */
			/*
			 *	Terminate this object. If it had a shadow,
			 *	then deallocate it; otherwise, if we need
			 *	to retry a cache trim, do so now; otherwise,
			 *	we are done. "pageout" objects have a shadow,
			 *	but maintain a "paging reference" rather than
			 *	a normal reference.
			 */
			shadow = object->pageout?VM_OBJECT_NULL:object->shadow;
			if(vm_object_terminate(object) != KERN_SUCCESS) {
				return;
			}
			if (shadow != VM_OBJECT_NULL) {
				object = shadow;
				continue;
			}
			if (retry_cache_trim &&
			    ((object = vm_object_cache_trim(TRUE)) !=
			     VM_OBJECT_NULL)) {
				continue;
			}
			return;
		}
	}
	assert(! retry_cache_trim);
}

/*
 *	Check to see whether we really need to trim
 *	down the cache. If so, remove an object from
 *	the cache, terminate it, and repeat.
 *
 *	Called with, and returns with, cache lock unlocked.
 */
vm_object_t
vm_object_cache_trim(
	boolean_t called_from_vm_object_deallocate)
{
	register vm_object_t object = VM_OBJECT_NULL;
	vm_object_t shadow;

	for (;;) {

		/*
		 *	If we no longer need to trim the cache,
		 *	then we are done.
		 */

		vm_object_cache_lock();
		if (vm_object_cached_count <= vm_object_cached_max) {
			vm_object_cache_unlock();
			return VM_OBJECT_NULL;
		}

		/*
		 *	We must trim down the cache, so remove
		 *	the first object in the cache.
		 */
		XPR(XPR_VM_OBJECT,
		"vm_object_cache_trim: removing from front of cache (%x, %x)\n",
			(integer_t)vm_object_cached_list.next,
			(integer_t)vm_object_cached_list.prev, 0, 0, 0);

		object = (vm_object_t) queue_first(&vm_object_cached_list);
		if(object == (vm_object_t) &vm_object_cached_list) {
			/* something's wrong with the calling parameter or */
			/* the value of vm_object_cached_count, just fix   */
			/* and return */
			if(vm_object_cached_max < 0)
				vm_object_cached_max = 0;
			vm_object_cached_count = 0;
			vm_object_cache_unlock();
			return VM_OBJECT_NULL;
		}
		vm_object_lock(object);
		queue_remove(&vm_object_cached_list, object, vm_object_t,
			     cached_list);
		vm_object_cached_count--;

		/*
		 *	Since this object is in the cache, we know
		 *	that it is initialized and has no references.
		 *	Take a reference to avoid recursive deallocations.
		 */

		assert(object->pager_initialized);
		assert(object->ref_count == 0);
		object->ref_count++;

		/*
		 *	Terminate the object.
		 *	If the object had a shadow, we let vm_object_deallocate
		 *	deallocate it. "pageout" objects have a shadow, but
		 *	maintain a "paging reference" rather than a normal
		 *	reference.
		 *	(We are careful here to limit recursion.)
		 */
		shadow = object->pageout?VM_OBJECT_NULL:object->shadow;
		if(vm_object_terminate(object) != KERN_SUCCESS)
			continue;
		if (shadow != VM_OBJECT_NULL) {
			if (called_from_vm_object_deallocate) {
				return shadow;
			} else {
				vm_object_deallocate(shadow);
			}
		}
	}
}

boolean_t	vm_object_terminate_remove_all = FALSE;

/*
 *	Routine:	vm_object_terminate
 *	Purpose:
 *		Free all resources associated with a vm_object.
 *	In/out conditions:
 *		Upon entry, the object must be locked,
 *		and the object must have exactly one reference.
 *
 *		The shadow object reference is left alone.
 *
 *		The object must be unlocked if its found that pages
 *		must be flushed to a backing object.  If someone
 *		manages to map the object while it is being flushed
 *		the object is returned unlocked and unchanged.  Otherwise,
 *		upon exit, the cache will be unlocked, and the
 *		object will cease to exist.
 */
static kern_return_t
vm_object_terminate(
	register vm_object_t	object)
{
	memory_object_t		pager;
	register vm_page_t	p;
	vm_object_t		shadow_object;

	XPR(XPR_VM_OBJECT, "vm_object_terminate, object 0x%X ref %d\n",
		(integer_t)object, object->ref_count, 0, 0, 0);

	if (!object->pageout && (!object->temporary || object->can_persist)
			&& (object->pager != NULL || object->shadow_severed)) {
	   vm_object_cache_unlock();
	   while (!queue_empty(&object->memq)) {
		/*
		 * Clear pager_trusted bit so that the pages get yanked
		 * out of the object instead of cleaned in place.  This
		 * prevents a deadlock in XMM and makes more sense anyway.
		 */
		object->pager_trusted = FALSE;

		p = (vm_page_t) queue_first(&object->memq);

		VM_PAGE_CHECK(p);

		if (p->busy || p->cleaning) {
			if(p->cleaning || p->absent) {
				vm_object_paging_wait(object, THREAD_UNINT);
				continue;
			} else {
			   panic("vm_object_terminate.3 0x%x 0x%x", object, p);
			}
		}

		vm_page_lock_queues();
		p->busy = TRUE;
		VM_PAGE_QUEUES_REMOVE(p);
		vm_page_unlock_queues();

		if (p->absent || p->private) {

			/*
			 *	For private pages, VM_PAGE_FREE just
			 *	leaves the page structure around for
			 *	its owner to clean up.  For absent
			 *	pages, the structure is returned to
			 *	the appropriate pool.
			 */

			goto free_page;
		}

		if (p->fictitious)
			panic("vm_object_terminate.4 0x%x 0x%x", object, p);

		if (!p->dirty)
			p->dirty = pmap_is_modified(p->phys_page);

		if ((p->dirty || p->precious) && !p->error && object->alive) {
			vm_pageout_cluster(p); /* flush page */
			vm_object_paging_wait(object, THREAD_UNINT);
			XPR(XPR_VM_OBJECT,
			    "vm_object_terminate restart, object 0x%X ref %d\n",
			    (integer_t)object, object->ref_count, 0, 0, 0);
		} else {
		    free_page:
		    	VM_PAGE_FREE(p);
		}
	   }
	   vm_object_unlock(object);
	   vm_object_cache_lock();
	   vm_object_lock(object);
	}

	/*
	 *	Make sure the object isn't already being terminated
	 */
	if(object->terminating) {
		object->ref_count -= 1;
		assert(object->ref_count > 0);
		vm_object_cache_unlock();
		vm_object_unlock(object);
		return KERN_FAILURE;
	}

	/*
	 * Did somebody get a reference to the object while we were
	 * cleaning it?
	 */
	if(object->ref_count != 1) {
		object->ref_count -= 1;
		assert(object->ref_count > 0);
		vm_object_res_deallocate(object);
		vm_object_cache_unlock();
		vm_object_unlock(object);
		return KERN_FAILURE;
	}

	/*
	 *	Make sure no one can look us up now.
	 */

	object->terminating = TRUE;
	object->alive = FALSE;
	vm_object_remove(object);

	/*
	 *	Detach the object from its shadow if we are the shadow's
	 *	copy. The reference we hold on the shadow must be dropped
	 *	by our caller.
	 */
	if (((shadow_object = object->shadow) != VM_OBJECT_NULL) &&
	    !(object->pageout)) {
		vm_object_lock(shadow_object);
		if (shadow_object->copy == object)
			shadow_object->copy = VM_OBJECT_NULL;
		vm_object_unlock(shadow_object);
	}

	/*
	 *	The pageout daemon might be playing with our pages.
	 *	Now that the object is dead, it won't touch any more
	 *	pages, but some pages might already be on their way out.
	 *	Hence, we wait until the active paging activities have ceased
	 *	before we break the association with the pager itself.
	 */
	while (object->paging_in_progress != 0) {
		vm_object_cache_unlock();
		vm_object_wait(object,
			       VM_OBJECT_EVENT_PAGING_IN_PROGRESS,
			       THREAD_UNINT);
		vm_object_cache_lock();
		vm_object_lock(object);
	}

	pager = object->pager;
	object->pager = MEMORY_OBJECT_NULL;

	if (pager != MEMORY_OBJECT_NULL)
		memory_object_control_disable(object->pager_control);
	vm_object_cache_unlock();

	object->ref_count--;
#if	TASK_SWAPPER
	assert(object->res_count == 0);
#endif	/* TASK_SWAPPER */

	assert (object->ref_count == 0);

	/*
	 *	Clean or free the pages, as appropriate.
	 *	It is possible for us to find busy/absent pages,
	 *	if some faults on this object were aborted.
	 */
	if (object->pageout) {
		assert(shadow_object != VM_OBJECT_NULL);
		assert(shadow_object == object->shadow);

		vm_pageout_object_terminate(object);

	} else if ((object->temporary && !object->can_persist) ||
		   (pager == MEMORY_OBJECT_NULL)) {
		while (!queue_empty(&object->memq)) {
			p = (vm_page_t) queue_first(&object->memq);

			VM_PAGE_CHECK(p);
			VM_PAGE_FREE(p);
		}
	} else if (!queue_empty(&object->memq)) {
		panic("vm_object_terminate: queue just emptied isn't");
	}

	assert(object->paging_in_progress == 0);
	assert(object->ref_count == 0);

	/*
	 * If the pager has not already been released by
	 * vm_object_destroy, we need to terminate it and
	 * release our reference to it here.
	 */
	if (pager != MEMORY_OBJECT_NULL) {
		vm_object_unlock(object);
		vm_object_release_pager(pager);
		vm_object_lock(object);
	}

	/* kick off anyone waiting on terminating */
	object->terminating = FALSE;
	vm_object_paging_begin(object);
	vm_object_paging_end(object);
	vm_object_unlock(object);

#if	MACH_PAGEMAP
	vm_external_destroy(object->existence_map, object->size);
#endif	/* MACH_PAGEMAP */

	/*
	 *	Free the space for the object.
	 */
	zfree(vm_object_zone, object);
	return KERN_SUCCESS;
}

/*
 *	Routine:	vm_object_pager_wakeup
 *	Purpose:	Wake up anyone waiting for termination of a pager.
 */

static void
vm_object_pager_wakeup(
	memory_object_t	pager)
{
	vm_object_hash_entry_t	entry;
	boolean_t		waiting = FALSE;

	/*
	 *	If anyone was waiting for the memory_object_terminate
	 *	to be queued, wake them up now.
	 */
	vm_object_cache_lock();
	entry = vm_object_hash_lookup(pager, TRUE);
	if (entry != VM_OBJECT_HASH_ENTRY_NULL)
		waiting = entry->waiting;
	vm_object_cache_unlock();
	if (entry != VM_OBJECT_HASH_ENTRY_NULL) {
		if (waiting)
			thread_wakeup((event_t) pager);
		vm_object_hash_entry_free(entry);
	}
}

/*
 *	Routine:	vm_object_release_pager
 *	Purpose:	Terminate the pager and, upon completion,
 *			release our last reference to it.
 *			just like memory_object_terminate, except
 *			that we wake up anyone blocked in vm_object_enter
 *			waiting for termination message to be queued
 *			before calling memory_object_init.
 */
static void
vm_object_release_pager(
	memory_object_t	pager)
{

	/*
	 *	Terminate the pager.
	 */

	(void) memory_object_terminate(pager);

	/*
	 *	Wakeup anyone waiting for this terminate
	 */
	vm_object_pager_wakeup(pager);

	/*
	 *	Release reference to pager.
	 */
	memory_object_deallocate(pager);
}

/*
 *	Routine:	vm_object_destroy
 *	Purpose:
 *		Shut down a VM object, despite the
 *		presence of address map (or other) references
 *		to the vm_object.
 */
kern_return_t
vm_object_destroy(
	vm_object_t		object,
	__unused kern_return_t		reason)
{
	memory_object_t		old_pager;

	if (object == VM_OBJECT_NULL)
		return(KERN_SUCCESS);

	/*
	 *	Remove the pager association immediately.
	 *
	 *	This will prevent the memory manager from further
	 *	meddling.  [If it wanted to flush data or make
	 *	other changes, it should have done so before performing
	 *	the destroy call.]
	 */

	vm_object_cache_lock();
	vm_object_lock(object);
	object->can_persist = FALSE;
	object->named = FALSE;
	object->alive = FALSE;

	/*
	 *	Rip out the pager from the vm_object now...
	 */

	vm_object_remove(object);
	old_pager = object->pager;
	object->pager = MEMORY_OBJECT_NULL;
	if (old_pager != MEMORY_OBJECT_NULL)
		memory_object_control_disable(object->pager_control);
	vm_object_cache_unlock();

	/*
	 * Wait for the existing paging activity (that got
	 * through before we nulled out the pager) to subside.
	 */

	vm_object_paging_wait(object, THREAD_UNINT);
	vm_object_unlock(object);

	/*
	 *	Terminate the object now.
	 */
	if (old_pager != MEMORY_OBJECT_NULL) {
		vm_object_release_pager(old_pager);

		/* 
		 * JMM - Release the caller's reference.  This assumes the
		 * caller had a reference to release, which is a big (but
		 * currently valid) assumption if this is driven from the
		 * vnode pager (it is holding a named reference when making
		 * this call)..
		 */
		vm_object_deallocate(object);

	}
	return(KERN_SUCCESS);
}

/*
 *	vm_object_deactivate_pages
 *
 *	Deactivate all pages in the specified object.  (Keep its pages
 *	in memory even though it is no longer referenced.)
 *
 *	The object must be locked.
 */
static void
vm_object_deactivate_all_pages(
	register vm_object_t	object)
{
	register vm_page_t	p;

	queue_iterate(&object->memq, p, vm_page_t, listq) {
		vm_page_lock_queues();
		if (!p->busy)
			vm_page_deactivate(p);
		vm_page_unlock_queues();
	}
}

__private_extern__ void
vm_object_deactivate_pages(
	vm_object_t		object,
	vm_object_offset_t	offset,
	vm_object_size_t	size,
	boolean_t               kill_page)
{
	vm_object_t		orig_object;
	int pages_moved = 0;
	int pages_found = 0;

	/*
	 * entered with object lock held, acquire a paging reference to
	 * prevent the memory_object and control ports from
	 * being destroyed.
	 */
	orig_object = object;

	for (;;) {
	        register vm_page_t	m;
	        vm_object_offset_t	toffset;
		vm_object_size_t	tsize;

	        vm_object_paging_begin(object);
		vm_page_lock_queues();

		for (tsize = size, toffset = offset; tsize; tsize -= PAGE_SIZE, toffset += PAGE_SIZE) {

		        if ((m = vm_page_lookup(object, toffset)) != VM_PAGE_NULL) {

			        pages_found++;

				if ((m->wire_count == 0) && (!m->private) && (!m->gobbled) && (!m->busy)) {

					assert(!m->laundry);

					m->reference = FALSE;
					pmap_clear_reference(m->phys_page);

					if ((kill_page) && (object->internal)) {
				        	m->precious = FALSE;
					        m->dirty = FALSE;
						pmap_clear_modify(m->phys_page);
						vm_external_state_clr(object->existence_map, offset);
					}
					VM_PAGE_QUEUES_REMOVE(m);

					assert(!m->laundry);
					assert(m->object != kernel_object);
					assert(m->pageq.next == NULL &&
					       m->pageq.prev == NULL);
					if(m->zero_fill) {
						queue_enter_first(
							&vm_page_queue_zf, 
							m, vm_page_t, pageq);
					} else {
						queue_enter_first(
							&vm_page_queue_inactive, 
							m, vm_page_t, pageq);
					}

					m->inactive = TRUE;
					if (!m->fictitious)  
					        vm_page_inactive_count++;

					pages_moved++;
				}
			}
		}
		vm_page_unlock_queues();
		vm_object_paging_end(object);

		if (object->shadow) {
		        vm_object_t	tmp_object;

			kill_page = 0;

		        offset += object->shadow_offset;

		        tmp_object = object->shadow;
		        vm_object_lock(tmp_object);

			if (object != orig_object)
			        vm_object_unlock(object);
			object = tmp_object;
		} else
		        break;
	}
	if (object != orig_object)
	        vm_object_unlock(object);
}

/*
 *	Routine:	vm_object_pmap_protect
 *
 *	Purpose:
 *		Reduces the permission for all physical
 *		pages in the specified object range.
 *
 *		If removing write permission only, it is
 *		sufficient to protect only the pages in
 *		the top-level object; only those pages may
 *		have write permission.
 *
 *		If removing all access, we must follow the
 *		shadow chain from the top-level object to
 *		remove access to all pages in shadowed objects.
 *
 *		The object must *not* be locked.  The object must
 *		be temporary/internal.  
 *
 *              If pmap is not NULL, this routine assumes that
 *              the only mappings for the pages are in that
 *              pmap.
 */

__private_extern__ void
vm_object_pmap_protect(
	register vm_object_t		object,
	register vm_object_offset_t	offset,
	vm_object_size_t		size,
	pmap_t				pmap,
	vm_map_offset_t			pmap_start,
	vm_prot_t			prot)
{
	if (object == VM_OBJECT_NULL)
	    return;
	size = vm_object_round_page(size);
	offset = vm_object_trunc_page(offset);

	vm_object_lock(object);

	assert(object->internal);

	while (TRUE) {
	   if (ptoa_64(object->resident_page_count) > size/2 && pmap != PMAP_NULL) {
		vm_object_unlock(object);
		pmap_protect(pmap, pmap_start, pmap_start + size, prot);
		return;
	    }

	    /* if we are doing large ranges with respect to resident */
	    /* page count then we should interate over pages otherwise */
	    /* inverse page look-up will be faster */
	    if (ptoa_64(object->resident_page_count / 4) <  size) {
		vm_page_t		p;
		vm_object_offset_t	end;

		end = offset + size;

		if (pmap != PMAP_NULL) {
		  queue_iterate(&object->memq, p, vm_page_t, listq) {
		    if (!p->fictitious &&
			(offset <= p->offset) && (p->offset < end)) {
			vm_map_offset_t start;

			start = pmap_start + p->offset - offset;
			pmap_protect(pmap, start, start + PAGE_SIZE_64, prot);
		    }
		  }
		} else {
		  queue_iterate(&object->memq, p, vm_page_t, listq) {
		    if (!p->fictitious &&
			(offset <= p->offset) && (p->offset < end)) {

			    pmap_page_protect(p->phys_page,
					      prot & ~p->page_lock);
		    }
		  }
		}
	   } else {
		vm_page_t		p;
		vm_object_offset_t	end;
		vm_object_offset_t	target_off;

		end = offset + size;

		if (pmap != PMAP_NULL) {
			for(target_off = offset; 
			    target_off < end;
			    target_off += PAGE_SIZE) {
				p = vm_page_lookup(object, target_off);
				if (p != VM_PAGE_NULL) {
					vm_offset_t start;
					start = pmap_start + 
						(vm_offset_t)(p->offset - offset);
					pmap_protect(pmap, start, 
							start + PAGE_SIZE, prot);
				}
		    	}
		} else {
			for(target_off = offset; 
				target_off < end; target_off += PAGE_SIZE) {
				p = vm_page_lookup(object, target_off);
				if (p != VM_PAGE_NULL) {
		    			pmap_page_protect(p->phys_page,
						      prot & ~p->page_lock);
				}
		    	}
		}
	  }

	    if (prot == VM_PROT_NONE) {
		/*
		 * Must follow shadow chain to remove access
		 * to pages in shadowed objects.
		 */
		register vm_object_t	next_object;

		next_object = object->shadow;
		if (next_object != VM_OBJECT_NULL) {
		    offset += object->shadow_offset;
		    vm_object_lock(next_object);
		    vm_object_unlock(object);
		    object = next_object;
		}
		else {
		    /*
		     * End of chain - we are done.
		     */
		    break;
		}
	    }
	    else {
		/*
		 * Pages in shadowed objects may never have
		 * write permission - we may stop here.
		 */
		break;
	    }
	}

	vm_object_unlock(object);
}

/*
 *	Routine:	vm_object_copy_slowly
 *
 *	Description:
 *		Copy the specified range of the source
 *		virtual memory object without using
 *		protection-based optimizations (such
 *		as copy-on-write).  The pages in the
 *		region are actually copied.
 *
 *	In/out conditions:
 *		The caller must hold a reference and a lock
 *		for the source virtual memory object.  The source
 *		object will be returned *unlocked*.
 *
 *	Results:
 *		If the copy is completed successfully, KERN_SUCCESS is
 *		returned.  If the caller asserted the interruptible
 *		argument, and an interruption occurred while waiting
 *		for a user-generated event, MACH_SEND_INTERRUPTED is
 *		returned.  Other values may be returned to indicate
 *		hard errors during the copy operation.
 *
 *		A new virtual memory object is returned in a
 *		parameter (_result_object).  The contents of this
 *		new object, starting at a zero offset, are a copy
 *		of the source memory region.  In the event of
 *		an error, this parameter will contain the value
 *		VM_OBJECT_NULL.
 */
__private_extern__ kern_return_t
vm_object_copy_slowly(
	register vm_object_t	src_object,
	vm_object_offset_t	src_offset,
	vm_object_size_t	size,
	boolean_t		interruptible,
	vm_object_t		*_result_object)	/* OUT */
{
	vm_object_t		new_object;
	vm_object_offset_t	new_offset;

	vm_object_offset_t	src_lo_offset = src_offset;
	vm_object_offset_t	src_hi_offset = src_offset + size;

	XPR(XPR_VM_OBJECT, "v_o_c_slowly obj 0x%x off 0x%x size 0x%x\n",
	    src_object, src_offset, size, 0, 0);

	if (size == 0) {
		vm_object_unlock(src_object);
		*_result_object = VM_OBJECT_NULL;
		return(KERN_INVALID_ARGUMENT);
	}

	/*
	 *	Prevent destruction of the source object while we copy.
	 */

	assert(src_object->ref_count > 0);
	src_object->ref_count++;
	VM_OBJ_RES_INCR(src_object);
	vm_object_unlock(src_object);

	/*
	 *	Create a new object to hold the copied pages.
	 *	A few notes:
	 *		We fill the new object starting at offset 0,
	 *		 regardless of the input offset.
	 *		We don't bother to lock the new object within
	 *		 this routine, since we have the only reference.
	 */

	new_object = vm_object_allocate(size);
	new_offset = 0;
	vm_object_lock(new_object);

	assert(size == trunc_page_64(size));	/* Will the loop terminate? */

	for ( ;
	    size != 0 ;
	    src_offset += PAGE_SIZE_64, 
			new_offset += PAGE_SIZE_64, size -= PAGE_SIZE_64
	    ) {
		vm_page_t	new_page;
		vm_fault_return_t result;

		while ((new_page = vm_page_alloc(new_object, new_offset))
				== VM_PAGE_NULL) {
			if (!vm_page_wait(interruptible)) {
			        vm_object_unlock(new_object);
				vm_object_deallocate(new_object);
				vm_object_deallocate(src_object);
				*_result_object = VM_OBJECT_NULL;
				return(MACH_SEND_INTERRUPTED);
			}
		}

		do {
			vm_prot_t	prot = VM_PROT_READ;
			vm_page_t	_result_page;
			vm_page_t	top_page;
			register
			vm_page_t	result_page;
			kern_return_t	error_code;

			vm_object_lock(src_object);
			vm_object_paging_begin(src_object);

			XPR(XPR_VM_FAULT,"vm_object_copy_slowly -> vm_fault_page",0,0,0,0,0);
			result = vm_fault_page(src_object, src_offset,
				VM_PROT_READ, FALSE, interruptible,
				src_lo_offset, src_hi_offset,
				VM_BEHAVIOR_SEQUENTIAL,
				&prot, &_result_page, &top_page,
			        (int *)0,
				&error_code, FALSE, FALSE, NULL, 0);

			switch(result) {
				case VM_FAULT_SUCCESS:
					result_page = _result_page;

					/*
					 *	We don't need to hold the object
					 *	lock -- the busy page will be enough.
					 *	[We don't care about picking up any
					 *	new modifications.]
					 *
					 *	Copy the page to the new object.
					 *
					 *	POLICY DECISION:
					 *		If result_page is clean,
					 *		we could steal it instead
					 *		of copying.
					 */

					vm_object_unlock(result_page->object);
					vm_page_copy(result_page, new_page);

					/*
					 *	Let go of both pages (make them
					 *	not busy, perform wakeup, activate).
					 */

					new_page->busy = FALSE;
					new_page->dirty = TRUE;
					vm_object_lock(result_page->object);
					PAGE_WAKEUP_DONE(result_page);

					vm_page_lock_queues();
					if (!result_page->active &&
					    !result_page->inactive)
						vm_page_activate(result_page);
					vm_page_activate(new_page);
					vm_page_unlock_queues();

					/*
					 *	Release paging references and
					 *	top-level placeholder page, if any.
					 */

					vm_fault_cleanup(result_page->object,
							top_page);

					break;
				
				case VM_FAULT_RETRY:
					break;

				case VM_FAULT_FICTITIOUS_SHORTAGE:
					vm_page_more_fictitious();
					break;

				case VM_FAULT_MEMORY_SHORTAGE:
					if (vm_page_wait(interruptible))
						break;
					/* fall thru */

				case VM_FAULT_INTERRUPTED:
					vm_page_free(new_page);
					vm_object_unlock(new_object);
					vm_object_deallocate(new_object);
					vm_object_deallocate(src_object);
					*_result_object = VM_OBJECT_NULL;
					return(MACH_SEND_INTERRUPTED);

				case VM_FAULT_MEMORY_ERROR:
					/*
					 * A policy choice:
					 *	(a) ignore pages that we can't
					 *	    copy
					 *	(b) return the null object if
					 *	    any page fails [chosen]
					 */

					vm_page_lock_queues();
					vm_page_free(new_page);
					vm_page_unlock_queues();
					vm_object_unlock(new_object);
					vm_object_deallocate(new_object);
					vm_object_deallocate(src_object);
					*_result_object = VM_OBJECT_NULL;
					return(error_code ? error_code:
						KERN_MEMORY_ERROR);
			}
		} while (result != VM_FAULT_SUCCESS);
	}

	/*
	 *	Lose the extra reference, and return our object.
	 */

        vm_object_unlock(new_object);
	vm_object_deallocate(src_object);
	*_result_object = new_object;
	return(KERN_SUCCESS);
}

/*
 *	Routine:	vm_object_copy_quickly
 *
 *	Purpose:
 *		Copy the specified range of the source virtual
 *		memory object, if it can be done without waiting
 *		for user-generated events.
 *
 *	Results:
 *		If the copy is successful, the copy is returned in
 *		the arguments; otherwise, the arguments are not
 *		affected.
 *
 *	In/out conditions:
 *		The object should be unlocked on entry and exit.
 */

/*ARGSUSED*/
__private_extern__ boolean_t
vm_object_copy_quickly(
	vm_object_t		*_object,		/* INOUT */
	__unused vm_object_offset_t	offset,	/* IN */
	__unused vm_object_size_t	size,	/* IN */
	boolean_t		*_src_needs_copy,	/* OUT */
	boolean_t		*_dst_needs_copy)	/* OUT */
{
	vm_object_t	object = *_object;
	memory_object_copy_strategy_t copy_strategy;

	XPR(XPR_VM_OBJECT, "v_o_c_quickly obj 0x%x off 0x%x size 0x%x\n",
	    *_object, offset, size, 0, 0);
	if (object == VM_OBJECT_NULL) {
		*_src_needs_copy = FALSE;
		*_dst_needs_copy = FALSE;
		return(TRUE);
	}

	vm_object_lock(object);

	copy_strategy = object->copy_strategy;

	switch (copy_strategy) {
	case MEMORY_OBJECT_COPY_SYMMETRIC:

		/*
		 *	Symmetric copy strategy.
		 *	Make another reference to the object.
		 *	Leave object/offset unchanged.
		 */

		assert(object->ref_count > 0);
		object->ref_count++;
		vm_object_res_reference(object);
		object->shadowed = TRUE;
		vm_object_unlock(object);

		/*
		 *	Both source and destination must make
		 *	shadows, and the source must be made
		 *	read-only if not already.
		 */

		*_src_needs_copy = TRUE;
		*_dst_needs_copy = TRUE;

		break;

	case MEMORY_OBJECT_COPY_DELAY:
		vm_object_unlock(object);
		return(FALSE);

	default:
		vm_object_unlock(object);
		return(FALSE);
	}
	return(TRUE);
}

static int copy_call_count = 0;
static int copy_call_sleep_count = 0;
static int copy_call_restart_count = 0;

/*
 *	Routine:	vm_object_copy_call [internal]
 *
 *	Description:
 *		Copy the source object (src_object), using the
 *		user-managed copy algorithm.
 *
 *	In/out conditions:
 *		The source object must be locked on entry.  It
 *		will be *unlocked* on exit.
 *
 *	Results:
 *		If the copy is successful, KERN_SUCCESS is returned.
 *		A new object that represents the copied virtual
 *		memory is returned in a parameter (*_result_object).
 *		If the return value indicates an error, this parameter
 *		is not valid.
 */
static kern_return_t
vm_object_copy_call(
	vm_object_t		src_object,
	vm_object_offset_t	src_offset,
	vm_object_size_t	size,
	vm_object_t		*_result_object)	/* OUT */
{
	kern_return_t	kr;
	vm_object_t	copy;
	boolean_t	check_ready = FALSE;

	/*
	 *	If a copy is already in progress, wait and retry.
	 *
	 *	XXX
	 *	Consider making this call interruptable, as Mike
	 *	intended it to be.
	 *
	 *	XXXO
	 *	Need a counter or version or something to allow
	 *	us to use the copy that the currently requesting
	 *	thread is obtaining -- is it worth adding to the
	 *	vm object structure? Depends how common this case it.
	 */
	copy_call_count++;
	while (vm_object_wanted(src_object, VM_OBJECT_EVENT_COPY_CALL)) {
		vm_object_sleep(src_object, VM_OBJECT_EVENT_COPY_CALL,
			       THREAD_UNINT);
		copy_call_restart_count++;
	}

	/*
	 *	Indicate (for the benefit of memory_object_create_copy)
	 *	that we want a copy for src_object. (Note that we cannot
	 *	do a real assert_wait before calling memory_object_copy,
	 *	so we simply set the flag.)
	 */

	vm_object_set_wanted(src_object, VM_OBJECT_EVENT_COPY_CALL);
	vm_object_unlock(src_object);

	/*
	 *	Ask the memory manager to give us a memory object
	 *	which represents a copy of the src object.
	 *	The memory manager may give us a memory object
	 *	which we already have, or it may give us a
	 *	new memory object. This memory object will arrive
	 *	via memory_object_create_copy.
	 */

	kr = KERN_FAILURE;	/* XXX need to change memory_object.defs */
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	/*
	 *	Wait for the copy to arrive.
	 */
	vm_object_lock(src_object);
	while (vm_object_wanted(src_object, VM_OBJECT_EVENT_COPY_CALL)) {
		vm_object_sleep(src_object, VM_OBJECT_EVENT_COPY_CALL,
			       THREAD_UNINT);
		copy_call_sleep_count++;
	}
Retry:
	assert(src_object->copy != VM_OBJECT_NULL);
	copy = src_object->copy;
	if (!vm_object_lock_try(copy)) {
		vm_object_unlock(src_object);
		mutex_pause();	/* wait a bit */
		vm_object_lock(src_object);
		goto Retry;
	}
	if (copy->size < src_offset+size)
		copy->size = src_offset+size;

	if (!copy->pager_ready)
		check_ready = TRUE;

	/*
	 *	Return the copy.
	 */
	*_result_object = copy;
	vm_object_unlock(copy);
	vm_object_unlock(src_object);

	/* Wait for the copy to be ready. */
	if (check_ready == TRUE) {
		vm_object_lock(copy);
		while (!copy->pager_ready) {
			vm_object_sleep(copy, VM_OBJECT_EVENT_PAGER_READY, THREAD_UNINT);
		}
		vm_object_unlock(copy);
	}

	return KERN_SUCCESS;
}

static int copy_delayed_lock_collisions = 0;
static int copy_delayed_max_collisions = 0;
static int copy_delayed_lock_contention = 0;
static int copy_delayed_protect_iterate = 0;

/*
 *	Routine:	vm_object_copy_delayed [internal]
 *
 *	Description:
 *		Copy the specified virtual memory object, using
 *		the asymmetric copy-on-write algorithm.
 *
 *	In/out conditions:
 *		The src_object must be locked on entry.  It will be unlocked
 *		on exit - so the caller must also hold a reference to it.
 *
 *		This routine will not block waiting for user-generated
 *		events.  It is not interruptible.
 */
__private_extern__ vm_object_t
vm_object_copy_delayed(
	vm_object_t		src_object,
	vm_object_offset_t	src_offset,
	vm_object_size_t	size)
{
	vm_object_t		new_copy = VM_OBJECT_NULL;
	vm_object_t		old_copy;
	vm_page_t		p;
	vm_object_size_t	copy_size = src_offset + size;

	int collisions = 0;
	/*
	 *	The user-level memory manager wants to see all of the changes
	 *	to this object, but it has promised not to make any changes on
 	 *	its own.
	 *
	 *	Perform an asymmetric copy-on-write, as follows:
	 *		Create a new object, called a "copy object" to hold
	 *		 pages modified by the new mapping  (i.e., the copy,
	 *		 not the original mapping).
	 *		Record the original object as the backing object for
	 *		 the copy object.  If the original mapping does not
	 *		 change a page, it may be used read-only by the copy.
	 *		Record the copy object in the original object.
	 *		 When the original mapping causes a page to be modified,
	 *		 it must be copied to a new page that is "pushed" to
	 *		 the copy object.
	 *		Mark the new mapping (the copy object) copy-on-write.
	 *		 This makes the copy object itself read-only, allowing
	 *		 it to be reused if the original mapping makes no
	 *		 changes, and simplifying the synchronization required
	 *		 in the "push" operation described above.
	 *
	 *	The copy-on-write is said to be assymetric because the original
	 *	object is *not* marked copy-on-write. A copied page is pushed
	 *	to the copy object, regardless which party attempted to modify
	 *	the page.
	 *
	 *	Repeated asymmetric copy operations may be done. If the
	 *	original object has not been changed since the last copy, its
	 *	copy object can be reused. Otherwise, a new copy object can be
	 *	inserted between the original object and its previous copy
	 *	object.  Since any copy object is read-only, this cannot affect
	 *	affect the contents of the previous copy object.
	 *
	 *	Note that a copy object is higher in the object tree than the
	 *	original object; therefore, use of the copy object recorded in
	 *	the original object must be done carefully, to avoid deadlock.
	 */

 Retry:
 
	/*
	 * Wait for paging in progress.
	 */
	if (!src_object->true_share)
		vm_object_paging_wait(src_object, THREAD_UNINT);

	/*
	 *	See whether we can reuse the result of a previous
	 *	copy operation.
	 */

	old_copy = src_object->copy;
	if (old_copy != VM_OBJECT_NULL) {
		/*
		 *	Try to get the locks (out of order)
		 */
		if (!vm_object_lock_try(old_copy)) {
			vm_object_unlock(src_object);
			mutex_pause();

			/* Heisenberg Rules */
			copy_delayed_lock_collisions++;
			if (collisions++ == 0)
				copy_delayed_lock_contention++;

			if (collisions > copy_delayed_max_collisions)
				copy_delayed_max_collisions = collisions;

			vm_object_lock(src_object);
			goto Retry;
		}

		/*
		 *	Determine whether the old copy object has
		 *	been modified.
		 */

		if (old_copy->resident_page_count == 0 &&
		    !old_copy->pager_created) {
			/*
			 *	It has not been modified.
			 *
			 *	Return another reference to
			 *	the existing copy-object if
			 *	we can safely grow it (if
			 *	needed).
			 */

			if (old_copy->size < copy_size) {
				/*
				 * We can't perform a delayed copy if any of the
				 * pages in the extended range are wired (because
				 * we can't safely take write permission away from
				 * wired pages).  If the pages aren't wired, then
				 * go ahead and protect them.
				 */
				copy_delayed_protect_iterate++;
				queue_iterate(&src_object->memq, p, vm_page_t, listq) {
					if (!p->fictitious && 
					    p->offset >= old_copy->size && 
					    p->offset < copy_size) {
						if (p->wire_count > 0) {
							vm_object_unlock(old_copy);
							vm_object_unlock(src_object);

							if (new_copy != VM_OBJECT_NULL) {
								vm_object_unlock(new_copy);
								vm_object_deallocate(new_copy);
							}

							return VM_OBJECT_NULL;
						} else {
							pmap_page_protect(p->phys_page, 
								(VM_PROT_ALL & ~VM_PROT_WRITE &
								 ~p->page_lock));
						}
					}
				}
				old_copy->size = copy_size;
			}
				
			vm_object_reference_locked(old_copy);
			vm_object_unlock(old_copy);
			vm_object_unlock(src_object);

			if (new_copy != VM_OBJECT_NULL) {
				vm_object_unlock(new_copy);
				vm_object_deallocate(new_copy);
			}

			return(old_copy);
		}

		/*
		 * Adjust the size argument so that the newly-created 
		 * copy object will be large enough to back either the
		 * old copy object or the new mapping.
		 */
		if (old_copy->size > copy_size)
			copy_size = old_copy->size;

		if (new_copy == VM_OBJECT_NULL) {
			vm_object_unlock(old_copy);
			vm_object_unlock(src_object);
			new_copy = vm_object_allocate(copy_size);
			vm_object_lock(src_object);
			vm_object_lock(new_copy);
			goto Retry;
		}
		new_copy->size = copy_size;	

		/*
		 *	The copy-object is always made large enough to
		 *	completely shadow the original object, since
		 *	it may have several users who want to shadow
		 *	the original object at different points.
		 */

		assert((old_copy->shadow == src_object) &&
		    (old_copy->shadow_offset == (vm_object_offset_t) 0));

	} else if (new_copy == VM_OBJECT_NULL) {
		vm_object_unlock(src_object);
		new_copy = vm_object_allocate(copy_size);
		vm_object_lock(src_object);
		vm_object_lock(new_copy);
		goto Retry;
	}

	/*
	 * We now have the src object locked, and the new copy object
	 * allocated and locked (and potentially the old copy locked).
	 * Before we go any further, make sure we can still perform
	 * a delayed copy, as the situation may have changed.
	 *
	 * Specifically, we can't perform a delayed copy if any of the
	 * pages in the range are wired (because we can't safely take
	 * write permission away from wired pages).  If the pages aren't
	 * wired, then go ahead and protect them.
	 */
	copy_delayed_protect_iterate++;
	queue_iterate(&src_object->memq, p, vm_page_t, listq) {
		if (!p->fictitious && p->offset < copy_size) {
			if (p->wire_count > 0) {
				if (old_copy)
					vm_object_unlock(old_copy);
				vm_object_unlock(src_object);
				vm_object_unlock(new_copy);
				vm_object_deallocate(new_copy);
				return VM_OBJECT_NULL;
			} else {
				pmap_page_protect(p->phys_page, 
					(VM_PROT_ALL & ~VM_PROT_WRITE &
					 ~p->page_lock));
			}
		}
	}

	if (old_copy != VM_OBJECT_NULL) {
		/*
		 *	Make the old copy-object shadow the new one.
		 *	It will receive no more pages from the original
		 *	object.
		 */

		src_object->ref_count--;	/* remove ref. from old_copy */
		assert(src_object->ref_count > 0);
		old_copy->shadow = new_copy;
		assert(new_copy->ref_count > 0);
		new_copy->ref_count++;		/* for old_copy->shadow ref. */

#if TASK_SWAPPER
		if (old_copy->res_count) {
			VM_OBJ_RES_INCR(new_copy);
			VM_OBJ_RES_DECR(src_object);
		}
#endif

		vm_object_unlock(old_copy);	/* done with old_copy */
	}

	/*
	 *	Point the new copy at the existing object.
	 */
	new_copy->shadow = src_object;
	new_copy->shadow_offset = 0;
	new_copy->shadowed = TRUE;	/* caller must set needs_copy */
	assert(src_object->ref_count > 0);
	src_object->ref_count++;
	VM_OBJ_RES_INCR(src_object);
	src_object->copy = new_copy;
	vm_object_unlock(src_object);
	vm_object_unlock(new_copy);

	XPR(XPR_VM_OBJECT,
		"vm_object_copy_delayed: used copy object %X for source %X\n",
		(integer_t)new_copy, (integer_t)src_object, 0, 0, 0);

	return(new_copy);
}

/*
 *	Routine:	vm_object_copy_strategically
 *
 *	Purpose:
 *		Perform a copy according to the source object's
 *		declared strategy.  This operation may block,
 *		and may be interrupted.
 */
__private_extern__ kern_return_t
vm_object_copy_strategically(
	register vm_object_t	src_object,
	vm_object_offset_t	src_offset,
	vm_object_size_t	size,
	vm_object_t		*dst_object,	/* OUT */
	vm_object_offset_t	*dst_offset,	/* OUT */
	boolean_t		*dst_needs_copy) /* OUT */
{
	boolean_t	result;
	boolean_t	interruptible = THREAD_ABORTSAFE; /* XXX */
	memory_object_copy_strategy_t copy_strategy;

	assert(src_object != VM_OBJECT_NULL);

	vm_object_lock(src_object);

	/*
	 *	The copy strategy is only valid if the memory manager
	 *	is "ready". Internal objects are always ready.
	 */

	while (!src_object->internal && !src_object->pager_ready) {
		wait_result_t wait_result;

		wait_result = vm_object_sleep(	src_object,
						VM_OBJECT_EVENT_PAGER_READY,
						interruptible);
		if (wait_result != THREAD_AWAKENED) {
			vm_object_unlock(src_object);
			*dst_object = VM_OBJECT_NULL;
			*dst_offset = 0;
			*dst_needs_copy = FALSE;
			return(MACH_SEND_INTERRUPTED);
		}
	}

	copy_strategy = src_object->copy_strategy;

	/*
	 *	Use the appropriate copy strategy.
	 */

	switch (copy_strategy) {
	    case MEMORY_OBJECT_COPY_DELAY:
		*dst_object = vm_object_copy_delayed(src_object,
						     src_offset, size);
		if (*dst_object != VM_OBJECT_NULL) {
			*dst_offset = src_offset;
			*dst_needs_copy = TRUE;
			result = KERN_SUCCESS;
			break;
		}
		vm_object_lock(src_object);
		/* fall thru when delayed copy not allowed */

	    case MEMORY_OBJECT_COPY_NONE:
		result = vm_object_copy_slowly(src_object, src_offset, size,
					       interruptible, dst_object);
		if (result == KERN_SUCCESS) {
			*dst_offset = 0;
			*dst_needs_copy = FALSE;
		}
		break;

	    case MEMORY_OBJECT_COPY_CALL:
		result = vm_object_copy_call(src_object, src_offset, size,
				dst_object);
		if (result == KERN_SUCCESS) {
			*dst_offset = src_offset;
			*dst_needs_copy = TRUE;
		}
		break;

	    case MEMORY_OBJECT_COPY_SYMMETRIC:
		XPR(XPR_VM_OBJECT, "v_o_c_strategically obj 0x%x off 0x%x size 0x%x\n",(natural_t)src_object, src_offset, size, 0, 0);
		vm_object_unlock(src_object);
		result = KERN_MEMORY_RESTART_COPY;
		break;

	    default:
		panic("copy_strategically: bad strategy");
		result = KERN_INVALID_ARGUMENT;
	}
	return(result);
}

/*
 *	vm_object_shadow:
 *
 *	Create a new object which is backed by the
 *	specified existing object range.  The source
 *	object reference is deallocated.
 *
 *	The new object and offset into that object
 *	are returned in the source parameters.
 */
boolean_t vm_object_shadow_check = FALSE;

__private_extern__ boolean_t
vm_object_shadow(
	vm_object_t		*object,	/* IN/OUT */
	vm_object_offset_t	*offset,	/* IN/OUT */
	vm_object_size_t	length)
{
	register vm_object_t	source;
	register vm_object_t	result;

	source = *object;
	assert(source->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC);

	/*
	 *	Determine if we really need a shadow.
	 */

	if (vm_object_shadow_check && source->ref_count == 1 &&
	    (source->shadow == VM_OBJECT_NULL ||
	     source->shadow->copy == VM_OBJECT_NULL))
	{
		source->shadowed = FALSE;
		return FALSE;
	}

	/*
	 *	Allocate a new object with the given length
	 */

	if ((result = vm_object_allocate(length)) == VM_OBJECT_NULL)
		panic("vm_object_shadow: no object for shadowing");

	/*
	 *	The new object shadows the source object, adding
	 *	a reference to it.  Our caller changes his reference
	 *	to point to the new object, removing a reference to
	 *	the source object.  Net result: no change of reference
	 *	count.
	 */
	result->shadow = source;
	
	/*
	 *	Store the offset into the source object,
	 *	and fix up the offset into the new object.
	 */

	result->shadow_offset = *offset;

	/*
	 *	Return the new things
	 */

	*offset = 0;
	*object = result;
	return TRUE;
}

/*
 *	The relationship between vm_object structures and
 *	the memory_object requires careful synchronization.
 *
 *	All associations are created by memory_object_create_named
 *  for external pagers and vm_object_pager_create for internal
 *  objects as follows:
 *
 *		pager:	the memory_object itself, supplied by
 *			the user requesting a mapping (or the kernel,
 *			when initializing internal objects); the
 *			kernel simulates holding send rights by keeping
 *			a port reference;
 *
 *		pager_request:
 *			the memory object control port,
 *			created by the kernel; the kernel holds
 *			receive (and ownership) rights to this
 *			port, but no other references.
 *
 *	When initialization is complete, the "initialized" field
 *	is asserted.  Other mappings using a particular memory object,
 *	and any references to the vm_object gained through the
 *	port association must wait for this initialization to occur.
 *
 *	In order to allow the memory manager to set attributes before
 *	requests (notably virtual copy operations, but also data or
 *	unlock requests) are made, a "ready" attribute is made available.
 *	Only the memory manager may affect the value of this attribute.
 *	Its value does not affect critical kernel functions, such as
 *	internal object initialization or destruction.  [Furthermore,
 *	memory objects created by the kernel are assumed to be ready
 *	immediately; the default memory manager need not explicitly
 *	set the "ready" attribute.]
 *
 *	[Both the "initialized" and "ready" attribute wait conditions
 *	use the "pager" field as the wait event.]
 *
 *	The port associations can be broken down by any of the
 *	following routines:
 *		vm_object_terminate:
 *			No references to the vm_object remain, and
 *			the object cannot (or will not) be cached.
 *			This is the normal case, and is done even
 *			though one of the other cases has already been
 *			done.
 *		memory_object_destroy:
 *			The memory manager has requested that the
 *			kernel relinquish references to the memory
 *			object. [The memory manager may not want to
 *			destroy the memory object, but may wish to
 *			refuse or tear down existing memory mappings.]
 *
 *	Each routine that breaks an association must break all of
 *	them at once.  At some later time, that routine must clear
 *	the pager field and release the memory object references.
 *	[Furthermore, each routine must cope with the simultaneous
 *	or previous operations of the others.]
 *
 *	In addition to the lock on the object, the vm_object_cache_lock
 *	governs the associations.  References gained through the
 *	association require use of the cache lock.
 *
 *	Because the pager field may be cleared spontaneously, it
 *	cannot be used to determine whether a memory object has
 *	ever been associated with a particular vm_object.  [This
 *	knowledge is important to the shadow object mechanism.]
 *	For this reason, an additional "created" attribute is
 *	provided.
 *
 *	During various paging operations, the pager reference found in the
 *	vm_object must be valid.  To prevent this from being released,
 *	(other than being removed, i.e., made null), routines may use
 *	the vm_object_paging_begin/end routines [actually, macros].
 *	The implementation uses the "paging_in_progress" and "wanted" fields.
 *	[Operations that alter the validity of the pager values include the
 *	termination routines and vm_object_collapse.]
 */

#if 0
static void		vm_object_abort_activity(
				vm_object_t	object);

/*
 *	Routine:	vm_object_abort_activity [internal use only]
 *	Purpose:
 *		Abort paging requests pending on this object.
 *	In/out conditions:
 *		The object is locked on entry and exit.
 */
static void
vm_object_abort_activity(
	vm_object_t	object)
{
	register
	vm_page_t	p;
	vm_page_t	next;

	XPR(XPR_VM_OBJECT, "vm_object_abort_activity, object 0x%X\n",
		(integer_t)object, 0, 0, 0, 0);

	/*
	 *	Abort all activity that would be waiting
	 *	for a result on this memory object.
	 *
	 *	We could also choose to destroy all pages
	 *	that we have in memory for this object, but
	 *	we don't.
	 */

	p = (vm_page_t) queue_first(&object->memq);
	while (!queue_end(&object->memq, (queue_entry_t) p)) {
		next = (vm_page_t) queue_next(&p->listq);

		/*
		 *	If it's being paged in, destroy it.
		 *	If an unlock has been requested, start it again.
		 */

		if (p->busy && p->absent) {
			VM_PAGE_FREE(p);
		}
		 else {
		 	if (p->unlock_request != VM_PROT_NONE)
			 	p->unlock_request = VM_PROT_NONE;
			PAGE_WAKEUP(p);
		}
		
		p = next;
	}

	/*
	 *	Wake up threads waiting for the memory object to
	 *	become ready.
	 */

	object->pager_ready = TRUE;
	vm_object_wakeup(object, VM_OBJECT_EVENT_PAGER_READY);
}

/*
 *	Routine:	vm_object_pager_dead
 *
 *	Purpose:
 *		A port is being destroy, and the IPC kobject code
 *		can't tell if it represents a pager port or not.
 *		So this function is called each time it sees a port
 *		die.
 *		THIS IS HORRIBLY INEFFICIENT.  We should only call
 *		this routine if we had requested a notification on
 *		the port.
 */

__private_extern__ void
vm_object_pager_dead(
	ipc_port_t	pager)
{
	vm_object_t		object;
	vm_object_hash_entry_t	entry;

	/*
	 *	Perform essentially the same operations as in vm_object_lookup,
	 *	except that this time we look up based on the memory_object
	 *	port, not the control port.
	 */
	vm_object_cache_lock();
	entry = vm_object_hash_lookup(pager, FALSE);
	if (entry == VM_OBJECT_HASH_ENTRY_NULL ||
	    		entry->object == VM_OBJECT_NULL) {
		vm_object_cache_unlock();
		return;
	}

	object = entry->object;
	entry->object = VM_OBJECT_NULL;

	vm_object_lock(object);
	if (object->ref_count == 0) {
		XPR(XPR_VM_OBJECT_CACHE,
		   "vm_object_destroy: removing %x from cache, head (%x, %x)\n",
			(integer_t)object,
			(integer_t)vm_object_cached_list.next,
			(integer_t)vm_object_cached_list.prev, 0,0);

		queue_remove(&vm_object_cached_list, object,
				vm_object_t, cached_list);
		vm_object_cached_count--;
	}
	object->ref_count++;
	vm_object_res_reference(object);

	object->can_persist = FALSE;

	assert(object->pager == pager);

	/*
	 *	Remove the pager association.
	 *
	 *	Note that the memory_object itself is dead, so
	 *	we don't bother with it.
	 */

	object->pager = MEMORY_OBJECT_NULL;

	vm_object_unlock(object);
	vm_object_cache_unlock();

	vm_object_pager_wakeup(pager);

	/*
	 *	Release the pager reference.  Note that there's no
	 *	point in trying the memory_object_terminate call
	 *	because the memory_object itself is dead.  Also
	 *	release the memory_object_control reference, since
	 *	the pager didn't do that either.
	 */

	memory_object_deallocate(pager);
	memory_object_control_deallocate(object->pager_request);
	

	/*
	 *	Restart pending page requests
	 */
	vm_object_lock(object);
	vm_object_abort_activity(object);
	vm_object_unlock(object);

	/*
	 *	Lose the object reference.
	 */

	vm_object_deallocate(object);
}
#endif

/*
 *	Routine:	vm_object_enter
 *	Purpose:
 *		Find a VM object corresponding to the given
 *		pager; if no such object exists, create one,
 *		and initialize the pager.
 */
vm_object_t
vm_object_enter(
	memory_object_t		pager,
	vm_object_size_t	size,
	boolean_t		internal,
	boolean_t		init,
	boolean_t		named)
{
	register vm_object_t	object;
	vm_object_t		new_object;
	boolean_t		must_init;
	vm_object_hash_entry_t	entry, new_entry;

	if (pager == MEMORY_OBJECT_NULL)
		return(vm_object_allocate(size));

	new_object = VM_OBJECT_NULL;
	new_entry = VM_OBJECT_HASH_ENTRY_NULL;
	must_init = init;

	/*
	 *	Look for an object associated with this port.
	 */

	vm_object_cache_lock();
	do {
		entry = vm_object_hash_lookup(pager, FALSE);

		if (entry == VM_OBJECT_HASH_ENTRY_NULL) {
			if (new_object == VM_OBJECT_NULL) {
				/*
				 *	We must unlock to create a new object;
				 *	if we do so, we must try the lookup again.
				 */
				vm_object_cache_unlock();
				assert(new_entry == VM_OBJECT_HASH_ENTRY_NULL);
				new_entry = vm_object_hash_entry_alloc(pager);
				new_object = vm_object_allocate(size);
				vm_object_cache_lock();
			} else {
				/*
				 *	Lookup failed twice, and we have something
				 *	to insert; set the object.
				 */
				vm_object_hash_insert(new_entry);
				entry = new_entry;
				entry->object = new_object;
				new_entry = VM_OBJECT_HASH_ENTRY_NULL;
				new_object = VM_OBJECT_NULL;
				must_init = TRUE;
			}
		} else if (entry->object == VM_OBJECT_NULL) {
			/*
		 	 *	If a previous object is being terminated,
			 *	we must wait for the termination message
			 *	to be queued (and lookup the entry again).
			 */
			entry->waiting = TRUE;
			entry = VM_OBJECT_HASH_ENTRY_NULL;
			assert_wait((event_t) pager, THREAD_UNINT);
			vm_object_cache_unlock();
			thread_block(THREAD_CONTINUE_NULL);
			vm_object_cache_lock();
		}
	} while (entry == VM_OBJECT_HASH_ENTRY_NULL);

	object = entry->object;
	assert(object != VM_OBJECT_NULL);

	if (!must_init) {
		vm_object_lock(object);
		assert(!internal || object->internal);
		if (named) {
			assert(!object->named);
			object->named = TRUE;
		}
		if (object->ref_count == 0) {
			XPR(XPR_VM_OBJECT_CACHE,
		    "vm_object_enter: removing %x from cache, head (%x, %x)\n",
				(integer_t)object,
				(integer_t)vm_object_cached_list.next,
				(integer_t)vm_object_cached_list.prev, 0,0);
			queue_remove(&vm_object_cached_list, object,
				     vm_object_t, cached_list);
			vm_object_cached_count--;
		}
		object->ref_count++;
		vm_object_res_reference(object);
		vm_object_unlock(object);

		VM_STAT(hits++);
	} 
	assert(object->ref_count > 0);

	VM_STAT(lookups++);

	vm_object_cache_unlock();

	XPR(XPR_VM_OBJECT,
		"vm_o_enter: pager 0x%x obj 0x%x must_init %d\n",
		(integer_t)pager, (integer_t)object, must_init, 0, 0);

	/*
	 *	If we raced to create a vm_object but lost, let's
	 *	throw away ours.
	 */

	if (new_object != VM_OBJECT_NULL)
		vm_object_deallocate(new_object);

	if (new_entry != VM_OBJECT_HASH_ENTRY_NULL)
		vm_object_hash_entry_free(new_entry);

	if (must_init) {
		memory_object_control_t control;

		/*
		 *	Allocate request port.
		 */

		control = memory_object_control_allocate(object);
		assert (control != MEMORY_OBJECT_CONTROL_NULL);

		vm_object_lock(object);
		assert(object != kernel_object);

		/*
		 *	Copy the reference we were given.
		 */

		memory_object_reference(pager);
		object->pager_created = TRUE;
		object->pager = pager;
		object->internal = internal;
		object->pager_trusted = internal;
		if (!internal) {
			/* copy strategy invalid until set by memory manager */
			object->copy_strategy = MEMORY_OBJECT_COPY_INVALID;
		}
		object->pager_control = control;
		object->pager_ready = FALSE;

		vm_object_unlock(object);

		/*
		 *	Let the pager know we're using it.
		 */

		(void) memory_object_init(pager,
			object->pager_control,
			PAGE_SIZE);

		vm_object_lock(object);
		if (named)
			object->named = TRUE;
		if (internal) {
			object->pager_ready = TRUE;
			vm_object_wakeup(object, VM_OBJECT_EVENT_PAGER_READY);
		}

		object->pager_initialized = TRUE;
		vm_object_wakeup(object, VM_OBJECT_EVENT_INITIALIZED);
	} else {
		vm_object_lock(object);
	}

	/*
	 *	[At this point, the object must be locked]
	 */

	/*
	 *	Wait for the work above to be done by the first
	 *	thread to map this object.
	 */

	while (!object->pager_initialized) {
		vm_object_sleep(object,
				VM_OBJECT_EVENT_INITIALIZED,
				THREAD_UNINT);
	}
	vm_object_unlock(object);

	XPR(XPR_VM_OBJECT,
	    "vm_object_enter: vm_object %x, memory_object %x, internal %d\n",
	    (integer_t)object, (integer_t)object->pager, internal, 0,0);
	return(object);
}

/*
 *	Routine:	vm_object_pager_create
 *	Purpose:
 *		Create a memory object for an internal object.
 *	In/out conditions:
 *		The object is locked on entry and exit;
 *		it may be unlocked within this call.
 *	Limitations:
 *		Only one thread may be performing a
 *		vm_object_pager_create on an object at
 *		a time.  Presumably, only the pageout
 *		daemon will be using this routine.
 */

void
vm_object_pager_create(
	register vm_object_t	object)
{
	memory_object_t		pager;
	vm_object_hash_entry_t	entry;
#if	MACH_PAGEMAP
	vm_object_size_t	size;
	vm_external_map_t	map;
#endif	/* MACH_PAGEMAP */

	XPR(XPR_VM_OBJECT, "vm_object_pager_create, object 0x%X\n",
		(integer_t)object, 0,0,0,0);

	assert(object != kernel_object);

	if (memory_manager_default_check() != KERN_SUCCESS)
		return;

	/*
	 *	Prevent collapse or termination by holding a paging reference
	 */

	vm_object_paging_begin(object);
	if (object->pager_created) {
		/*
		 *	Someone else got to it first...
		 *	wait for them to finish initializing the ports
		 */
		while (!object->pager_initialized) {
			vm_object_sleep(object,
				        VM_OBJECT_EVENT_INITIALIZED,
				        THREAD_UNINT);
		}
		vm_object_paging_end(object);
		return;
	}

	/*
	 *	Indicate that a memory object has been assigned
	 *	before dropping the lock, to prevent a race.
	 */

	object->pager_created = TRUE;
	object->paging_offset = 0;
		
#if	MACH_PAGEMAP
	size = object->size;
#endif	/* MACH_PAGEMAP */
	vm_object_unlock(object);

#if	MACH_PAGEMAP
	map = vm_external_create(size);
	vm_object_lock(object);
	assert(object->size == size);
	object->existence_map = map;
	vm_object_unlock(object);
#endif	/* MACH_PAGEMAP */

	/*
	 *	Create the [internal] pager, and associate it with this object.
	 *
	 *	We make the association here so that vm_object_enter()
	 * 	can look up the object to complete initializing it.  No
	 *	user will ever map this object.
	 */
	{
		memory_object_default_t		dmm;
		vm_size_t	cluster_size;

		/* acquire a reference for the default memory manager */
		dmm = memory_manager_default_reference(&cluster_size);
		assert(cluster_size >= PAGE_SIZE);

		object->cluster_size = cluster_size; /* XXX ??? */
		assert(object->temporary);

		/* create our new memory object */
		(void) memory_object_create(dmm, object->size, &pager);

		memory_object_default_deallocate(dmm);
       }

	entry = vm_object_hash_entry_alloc(pager);

	vm_object_cache_lock();
	vm_object_hash_insert(entry);

	entry->object = object;
	vm_object_cache_unlock();

	/*
	 *	A reference was returned by
	 *	memory_object_create(), and it is
	 *	copied by vm_object_enter().
	 */

	if (vm_object_enter(pager, object->size, TRUE, TRUE, FALSE) != object)
		panic("vm_object_pager_create: mismatch");

	/*
	 *	Drop the reference we were passed.
	 */
	memory_object_deallocate(pager);

	vm_object_lock(object);

	/*
	 *	Release the paging reference
	 */
	vm_object_paging_end(object);
}

/*
 *	Routine:	vm_object_remove
 *	Purpose:
 *		Eliminate the pager/object association
 *		for this pager.
 *	Conditions:
 *		The object cache must be locked.
 */
__private_extern__ void
vm_object_remove(
	vm_object_t	object)
{
	memory_object_t pager;

	if ((pager = object->pager) != MEMORY_OBJECT_NULL) {
		vm_object_hash_entry_t	entry;

		entry = vm_object_hash_lookup(pager, FALSE);
		if (entry != VM_OBJECT_HASH_ENTRY_NULL)
			entry->object = VM_OBJECT_NULL;
	}

}

/*
 *	Global variables for vm_object_collapse():
 *
 *		Counts for normal collapses and bypasses.
 *		Debugging variables, to watch or disable collapse.
 */
static long	object_collapses = 0;
static long	object_bypasses  = 0;

static boolean_t	vm_object_collapse_allowed = TRUE;
static boolean_t	vm_object_bypass_allowed = TRUE;

static int	vm_external_discarded;
static int	vm_external_collapsed;

unsigned long vm_object_collapse_encrypted = 0;

/*
 *	Routine:	vm_object_do_collapse
 *	Purpose:
 *		Collapse an object with the object backing it.
 *		Pages in the backing object are moved into the
 *		parent, and the backing object is deallocated.
 *	Conditions:
 *		Both objects and the cache are locked; the page
 *		queues are unlocked.
 *
 */
static void
vm_object_do_collapse(
	vm_object_t object,
	vm_object_t backing_object)
{
	vm_page_t p, pp;
	vm_object_offset_t new_offset, backing_offset;
	vm_object_size_t size;

	backing_offset = object->shadow_offset;
	size = object->size;

	/*
	 *	Move all in-memory pages from backing_object
	 *	to the parent.  Pages that have been paged out
	 *	will be overwritten by any of the parent's
	 *	pages that shadow them.
	 */
	
	while (!queue_empty(&backing_object->memq)) {
		
		p = (vm_page_t) queue_first(&backing_object->memq);
		
		new_offset = (p->offset - backing_offset);
		
		assert(!p->busy || p->absent);

		/*
		 *	If the parent has a page here, or if
		 *	this page falls outside the parent,
		 *	dispose of it.
		 *
		 *	Otherwise, move it as planned.
		 */
		
		if (p->offset < backing_offset || new_offset >= size) {
			VM_PAGE_FREE(p);
		} else {
			/*
			 * ENCRYPTED SWAP:
			 * The encryption key includes the "pager" and the
			 * "paging_offset".  These might not be the same in
			 * the new object, so we can't just move an encrypted
			 * page from one object to the other.  We can't just
			 * decrypt the page here either, because that would drop
			 * the object lock.
			 * The caller should check for encrypted pages before
			 * attempting to collapse.
			 */
			ASSERT_PAGE_DECRYPTED(p);

			pp = vm_page_lookup(object, new_offset);
			if (pp == VM_PAGE_NULL) {

				/*
				 *	Parent now has no page.
				 *	Move the backing object's page up.
				 */

				vm_page_rename(p, object, new_offset);
#if	MACH_PAGEMAP
			} else if (pp->absent) {

				/*
				 *	Parent has an absent page...
				 *	it's not being paged in, so
				 *	it must really be missing from
				 *	the parent.
				 *
				 *	Throw out the absent page...
				 *	any faults looking for that
				 *	page will restart with the new
				 *	one.
				 */

				VM_PAGE_FREE(pp);
				vm_page_rename(p, object, new_offset);
#endif	/* MACH_PAGEMAP */
			} else {
				assert(! pp->absent);

				/*
				 *	Parent object has a real page.
				 *	Throw away the backing object's
				 *	page.
				 */
				VM_PAGE_FREE(p);
			}
		}
	}
	
#if	!MACH_PAGEMAP
	assert(!object->pager_created && object->pager == MEMORY_OBJECT_NULL
		|| (!backing_object->pager_created
		&&  backing_object->pager == MEMORY_OBJECT_NULL));
#else 
        assert(!object->pager_created && object->pager == MEMORY_OBJECT_NULL);
#endif	/* !MACH_PAGEMAP */

	if (backing_object->pager != MEMORY_OBJECT_NULL) {
		vm_object_hash_entry_t	entry;

		/*
		 *	Move the pager from backing_object to object.
		 *
		 *	XXX We're only using part of the paging space
		 *	for keeps now... we ought to discard the
		 *	unused portion.
		 */

		assert(!object->paging_in_progress);
		object->pager = backing_object->pager;
		entry = vm_object_hash_lookup(object->pager, FALSE);
		assert(entry != VM_OBJECT_HASH_ENTRY_NULL);
		entry->object = object;
		object->pager_created = backing_object->pager_created;
		object->pager_control = backing_object->pager_control;
		object->pager_ready = backing_object->pager_ready;
		object->pager_initialized = backing_object->pager_initialized;
		object->cluster_size = backing_object->cluster_size;
		object->paging_offset =
		    backing_object->paging_offset + backing_offset;
		if (object->pager_control != MEMORY_OBJECT_CONTROL_NULL) {
			memory_object_control_collapse(object->pager_control,
						       object);
		}
	}

	vm_object_cache_unlock();

#if	MACH_PAGEMAP
	/*
	 *	If the shadow offset is 0, the use the existence map from
	 *	the backing object if there is one. If the shadow offset is
	 *	not zero, toss it.
	 *
	 *	XXX - If the shadow offset is not 0 then a bit copy is needed
	 *	if the map is to be salvaged.  For now, we just just toss the
	 *	old map, giving the collapsed object no map. This means that
	 *	the pager is invoked for zero fill pages.  If analysis shows
	 *	that this happens frequently and is a performance hit, then
	 *	this code should be fixed to salvage the map.
	 */
	assert(object->existence_map == VM_EXTERNAL_NULL);
	if (backing_offset || (size != backing_object->size)) {
		vm_external_discarded++;
		vm_external_destroy(backing_object->existence_map,
			backing_object->size);
	}
	else {
		vm_external_collapsed++;
		object->existence_map = backing_object->existence_map;
	}
	backing_object->existence_map = VM_EXTERNAL_NULL;
#endif	/* MACH_PAGEMAP */

	/*
	 *	Object now shadows whatever backing_object did.
	 *	Note that the reference to backing_object->shadow
	 *	moves from within backing_object to within object.
	 */
	
	assert(!object->phys_contiguous);
	assert(!backing_object->phys_contiguous);
	object->shadow = backing_object->shadow;
	if (object->shadow) {
		object->shadow_offset += backing_object->shadow_offset;
	} else {
		/* no shadow, therefore no shadow offset... */
		object->shadow_offset = 0;
	}
	assert((object->shadow == VM_OBJECT_NULL) ||
	       (object->shadow->copy != backing_object));

	/*
	 *	Discard backing_object.
	 *
	 *	Since the backing object has no pages, no
	 *	pager left, and no object references within it,
	 *	all that is necessary is to dispose of it.
	 */
	
	assert((backing_object->ref_count == 1) &&
	       (backing_object->resident_page_count == 0) &&
	       (backing_object->paging_in_progress == 0));

	backing_object->alive = FALSE;
	vm_object_unlock(backing_object);

	XPR(XPR_VM_OBJECT, "vm_object_collapse, collapsed 0x%X\n",
		(integer_t)backing_object, 0,0,0,0);

	zfree(vm_object_zone, backing_object);
	
	object_collapses++;
}

static void
vm_object_do_bypass(
	vm_object_t object,
	vm_object_t backing_object)
{
	/*
	 *	Make the parent shadow the next object
	 *	in the chain.
	 */
	
#if	TASK_SWAPPER
	/*
	 *	Do object reference in-line to 
	 *	conditionally increment shadow's
	 *	residence count.  If object is not
	 *	resident, leave residence count
	 *	on shadow alone.
	 */
	if (backing_object->shadow != VM_OBJECT_NULL) {
		vm_object_lock(backing_object->shadow);
		backing_object->shadow->ref_count++;
		if (object->res_count != 0)
			vm_object_res_reference(backing_object->shadow);
		vm_object_unlock(backing_object->shadow);
	}
#else	/* TASK_SWAPPER */
	vm_object_reference(backing_object->shadow);
#endif	/* TASK_SWAPPER */

	assert(!object->phys_contiguous);
	assert(!backing_object->phys_contiguous);
	object->shadow = backing_object->shadow;
	if (object->shadow) {
		object->shadow_offset += backing_object->shadow_offset;
	} else {
		/* no shadow, therefore no shadow offset... */
		object->shadow_offset = 0;
	}
	
	/*
	 *	Backing object might have had a copy pointer
	 *	to us.  If it did, clear it. 
	 */
	if (backing_object->copy == object) {
		backing_object->copy = VM_OBJECT_NULL;
	}
	
	/*
	 *	Drop the reference count on backing_object.
#if	TASK_SWAPPER
	 *	Since its ref_count was at least 2, it
	 *	will not vanish; so we don't need to call
	 *	vm_object_deallocate.
	 *	[FBDP: that doesn't seem to be true any more]
	 * 
	 *	The res_count on the backing object is
	 *	conditionally decremented.  It's possible
	 *	(via vm_pageout_scan) to get here with
	 *	a "swapped" object, which has a 0 res_count,
	 *	in which case, the backing object res_count
	 *	is already down by one.
#else
	 *	Don't call vm_object_deallocate unless
	 *	ref_count drops to zero.
	 *
	 *	The ref_count can drop to zero here if the
	 *	backing object could be bypassed but not
	 *	collapsed, such as when the backing object
	 *	is temporary and cachable.
#endif
	 */
	if (backing_object->ref_count > 1) {
		backing_object->ref_count--;
#if	TASK_SWAPPER
		if (object->res_count != 0)
			vm_object_res_deallocate(backing_object);
		assert(backing_object->ref_count > 0);
#endif	/* TASK_SWAPPER */
		vm_object_unlock(backing_object);
	} else {

		/*
		 *	Drop locks so that we can deallocate
		 *	the backing object.
		 */

#if	TASK_SWAPPER
		if (object->res_count == 0) {
			/* XXX get a reference for the deallocate below */
			vm_object_res_reference(backing_object);
		}
#endif	/* TASK_SWAPPER */
		vm_object_unlock(object);
		vm_object_unlock(backing_object);
		vm_object_deallocate(backing_object);

		/*
		 *	Relock object. We don't have to reverify
		 *	its state since vm_object_collapse will
		 *	do that for us as it starts at the
		 *	top of its loop.
		 */

		vm_object_lock(object);
	}
	
	object_bypasses++;
}

		
/*
 *	vm_object_collapse:
 *
 *	Perform an object collapse or an object bypass if appropriate.
 *	The real work of collapsing and bypassing is performed in
 *	the routines vm_object_do_collapse and vm_object_do_bypass.
 *
 *	Requires that the object be locked and the page queues be unlocked.
 *
 */
static unsigned long vm_object_collapse_calls = 0;
static unsigned long vm_object_collapse_objects = 0;
static unsigned long vm_object_collapse_do_collapse = 0;
static unsigned long vm_object_collapse_do_bypass = 0;
__private_extern__ void
vm_object_collapse(
	register vm_object_t			object,
	register vm_object_offset_t		hint_offset)
{
	register vm_object_t			backing_object;
	register unsigned int			rcount;
	register unsigned int			size;
	vm_object_offset_t			collapse_min_offset;
	vm_object_offset_t			collapse_max_offset;
	vm_page_t				page;
	vm_object_t				original_object;

	vm_object_collapse_calls++;

	if (! vm_object_collapse_allowed && ! vm_object_bypass_allowed) {
		return;
	}

	XPR(XPR_VM_OBJECT, "vm_object_collapse, obj 0x%X\n", 
		(integer_t)object, 0,0,0,0);

	if (object == VM_OBJECT_NULL)
		return;

	original_object = object;

	while (TRUE) {
		vm_object_collapse_objects++;
		/*
		 *	Verify that the conditions are right for either
		 *	collapse or bypass:
		 */

		/*
		 *	There is a backing object, and
		 */
	
		backing_object = object->shadow;
		if (backing_object == VM_OBJECT_NULL) {
			if (object != original_object) {
				vm_object_unlock(object);
			}
			return;
		}
	
		/*
		 *	No pages in the object are currently
		 *	being paged out, and
		 */
		if (object->paging_in_progress != 0 ||
		    object->absent_count != 0) {
			/* try and collapse the rest of the shadow chain */
			vm_object_lock(backing_object);
			if (object != original_object) {
				vm_object_unlock(object);
			}
			object = backing_object;
			continue;
		}

		vm_object_lock(backing_object);

		/*
		 *	...
		 *		The backing object is not read_only,
		 *		and no pages in the backing object are
		 *		currently being paged out.
		 *		The backing object is internal.
		 *
		 */
	
		if (!backing_object->internal ||
		    backing_object->paging_in_progress != 0) {
			/* try and collapse the rest of the shadow chain */
			if (object != original_object) {
				vm_object_unlock(object);
			}
			object = backing_object;
			continue;
		}
	
		/*
		 *	The backing object can't be a copy-object:
		 *	the shadow_offset for the copy-object must stay
		 *	as 0.  Furthermore (for the 'we have all the
		 *	pages' case), if we bypass backing_object and
		 *	just shadow the next object in the chain, old
		 *	pages from that object would then have to be copied
		 *	BOTH into the (former) backing_object and into the
		 *	parent object.
		 */
		if (backing_object->shadow != VM_OBJECT_NULL &&
		    backing_object->shadow->copy == backing_object) {
			/* try and collapse the rest of the shadow chain */
			if (object != original_object) {
				vm_object_unlock(object);
			}
			object = backing_object;
			continue;
		}

		/*
		 *	We can now try to either collapse the backing
		 *	object (if the parent is the only reference to
		 *	it) or (perhaps) remove the parent's reference
		 *	to it.
		 *
		 *	If there is exactly one reference to the backing
		 *	object, we may be able to collapse it into the
		 *	parent.
		 *
		 *	If MACH_PAGEMAP is defined:
		 *	The parent must not have a pager created for it,
		 *	since collapsing a backing_object dumps new pages
		 *	into the parent that its pager doesn't know about
		 *	(and the collapse code can't merge the existence
		 *	maps).
		 *	Otherwise:
		 *	As long as one of the objects is still not known
		 *	to the pager, we can collapse them.
		 */
		if (backing_object->ref_count == 1 &&
		    (!object->pager_created 
#if	!MACH_PAGEMAP
		     || !backing_object->pager_created
#endif	/*!MACH_PAGEMAP */
		    ) && vm_object_collapse_allowed) {

			XPR(XPR_VM_OBJECT, 
		   "vm_object_collapse: %x to %x, pager %x, pager_control %x\n",
				(integer_t)backing_object, (integer_t)object,
				(integer_t)backing_object->pager, 
				(integer_t)backing_object->pager_control, 0);

			/*
			 *	We need the cache lock for collapsing,
			 *	but we must not deadlock.
			 */
			
			if (! vm_object_cache_lock_try()) {
				if (object != original_object) {
					vm_object_unlock(object);
				}
				vm_object_unlock(backing_object);
				return;
			}

			/*
			 * ENCRYPTED SWAP
			 * We can't collapse the object if it contains
			 * any encypted page, because the encryption key
			 * includes the <object,offset> info.  We can't
			 * drop the object lock in vm_object_do_collapse()
			 * so we can't decrypt the page there either.
			 */
			if (vm_pages_encrypted) {
				collapse_min_offset = object->shadow_offset;
				collapse_max_offset =
					object->shadow_offset + object->size;
				queue_iterate(&backing_object->memq,
					      page, vm_page_t, listq) {
					if (page->encrypted &&
					    (page->offset >=
					     collapse_min_offset) &&
					    (page->offset <
					     collapse_max_offset)) {
						/*
						 * We found an encrypted page
						 * in the backing object,
						 * within the range covered 
						 * by the parent object: we can
						 * not collapse them.
						 */
						vm_object_collapse_encrypted++;
						vm_object_cache_unlock();
						goto try_bypass;
					}
				}
			}
		       
			/*
			 *	Collapse the object with its backing
			 *	object, and try again with the object's
			 *	new backing object.
			 */

			vm_object_do_collapse(object, backing_object);
			vm_object_collapse_do_collapse++;
			continue;
		}

	try_bypass:
		/*
		 *	Collapsing the backing object was not possible
		 *	or permitted, so let's try bypassing it.
		 */

		if (! vm_object_bypass_allowed) {
			/* try and collapse the rest of the shadow chain */
			if (object != original_object) {
				vm_object_unlock(object);
			}
			object = backing_object;
			continue;
		}


		/*
		 *	If the object doesn't have all its pages present,
		 *	we have to make sure no pages in the backing object
		 *	"show through" before bypassing it.
		 */
		size = atop(object->size);
		rcount = object->resident_page_count;
		if (rcount != size) {
			vm_object_offset_t	offset;
			vm_object_offset_t	backing_offset;
			unsigned int     	backing_rcount;
			unsigned int		lookups = 0;

			/*
			 *	If the backing object has a pager but no pagemap,
			 *	then we cannot bypass it, because we don't know
			 *	what pages it has.
			 */
			if (backing_object->pager_created
#if	MACH_PAGEMAP
				&& (backing_object->existence_map == VM_EXTERNAL_NULL)
#endif	/* MACH_PAGEMAP */
				) {
				/* try and collapse the rest of the shadow chain */
				if (object != original_object) {
					vm_object_unlock(object);
				}
				object = backing_object;
				continue;
			}

			/*
			 *	If the object has a pager but no pagemap,
			 *	then we cannot bypass it, because we don't know
			 *	what pages it has.
			 */
			if (object->pager_created
#if	MACH_PAGEMAP
				&& (object->existence_map == VM_EXTERNAL_NULL)
#endif	/* MACH_PAGEMAP */
				) {
				/* try and collapse the rest of the shadow chain */
				if (object != original_object) {
					vm_object_unlock(object);
				}
				object = backing_object;
				continue;
			}

			/*
			 *	If all of the pages in the backing object are
			 *	shadowed by the parent object, the parent
			 *	object no longer has to shadow the backing
			 *	object; it can shadow the next one in the
			 *	chain.
			 *
			 *	If the backing object has existence info,
			 *	we must check examine its existence info
			 *	as well.
			 *
			 */

			backing_offset = object->shadow_offset;
			backing_rcount = backing_object->resident_page_count;

#define EXISTS_IN_OBJECT(obj, off, rc) \
	(vm_external_state_get((obj)->existence_map, \
	 (vm_offset_t)(off)) == VM_EXTERNAL_STATE_EXISTS || \
	 ((rc) && ++lookups && vm_page_lookup((obj), (off)) != VM_PAGE_NULL && (rc)--))

			/*
			 * Check the hint location first
			 * (since it is often the quickest way out of here).
			 */
			if (object->cow_hint != ~(vm_offset_t)0)
				hint_offset = (vm_object_offset_t)object->cow_hint;
			else
				hint_offset = (hint_offset > 8 * PAGE_SIZE_64) ?
				              (hint_offset - 8 * PAGE_SIZE_64) : 0;

			if (EXISTS_IN_OBJECT(backing_object, hint_offset +
			                     backing_offset, backing_rcount) &&
			    !EXISTS_IN_OBJECT(object, hint_offset, rcount)) {
				/* dependency right at the hint */
				object->cow_hint = (vm_offset_t)hint_offset;
				/* try and collapse the rest of the shadow chain */
				if (object != original_object) {
					vm_object_unlock(object);
				}
				object = backing_object;
				continue;
			}

			/*
			 * If the object's window onto the backing_object
			 * is large compared to the number of resident
			 * pages in the backing object, it makes sense to
			 * walk the backing_object's resident pages first.
			 *
			 * NOTE: Pages may be in both the existence map and 
			 * resident.  So, we can't permanently decrement
			 * the rcount here because the second loop may
			 * find the same pages in the backing object'
			 * existence map that we found here and we would
			 * double-decrement the rcount.  We also may or
			 * may not have found the 
			 */
			if (backing_rcount && size >
			    ((backing_object->existence_map) ?
			     backing_rcount : (backing_rcount >> 1))) {
				unsigned int rc = rcount;
				vm_page_t p;

				backing_rcount = backing_object->resident_page_count;
				p = (vm_page_t)queue_first(&backing_object->memq);
				do {
					/* Until we get more than one lookup lock */
					if (lookups > 256) {
						lookups = 0;
						delay(1);
					}

					offset = (p->offset - backing_offset);
					if (offset < object->size &&
					    offset != hint_offset &&
					    !EXISTS_IN_OBJECT(object, offset, rc)) {
						/* found a dependency */
						object->cow_hint = (vm_offset_t)offset;
						break;
					}
					p = (vm_page_t) queue_next(&p->listq);

				} while (--backing_rcount);
				if (backing_rcount != 0 ) {
					/* try and collapse the rest of the shadow chain */
					if (object != original_object) {
						vm_object_unlock(object);
					}
					object = backing_object;
					continue;
				}
			}

			/*
			 * Walk through the offsets looking for pages in the
			 * backing object that show through to the object.
			 */
			if (backing_rcount || backing_object->existence_map) {
				offset = hint_offset;
				
				while((offset =
				      (offset + PAGE_SIZE_64 < object->size) ?
				      (offset + PAGE_SIZE_64) : 0) != hint_offset) {

					/* Until we get more than one lookup lock */
					if (lookups > 256) {
						lookups = 0;
						delay(1);
					}

					if (EXISTS_IN_OBJECT(backing_object, offset +
				            backing_offset, backing_rcount) &&
					    !EXISTS_IN_OBJECT(object, offset, rcount)) {
						/* found a dependency */
						object->cow_hint = (vm_offset_t)offset;
						break;
					}
				}
				if (offset != hint_offset) {
					/* try and collapse the rest of the shadow chain */
					if (object != original_object) {
						vm_object_unlock(object);
					}
					object = backing_object;
					continue;
				}
			}
		}

		/* reset the offset hint for any objects deeper in the chain */
		object->cow_hint = (vm_offset_t)0;

		/*
		 *	All interesting pages in the backing object
		 *	already live in the parent or its pager.
		 *	Thus we can bypass the backing object.
		 */

		vm_object_do_bypass(object, backing_object);
		vm_object_collapse_do_bypass++;

		/*
		 *	Try again with this object's new backing object.
		 */

		continue;
	}

	if (object != original_object) {
		vm_object_unlock(object);
	}
}

/*
 *	Routine:	vm_object_page_remove: [internal]
 *	Purpose:
 *		Removes all physical pages in the specified
 *		object range from the object's list of pages.
 *
 *	In/out conditions:
 *		The object must be locked.
 *		The object must not have paging_in_progress, usually
 *		guaranteed by not having a pager.
 */
unsigned int vm_object_page_remove_lookup = 0;
unsigned int vm_object_page_remove_iterate = 0;

__private_extern__ void
vm_object_page_remove(
	register vm_object_t		object,
	register vm_object_offset_t	start,
	register vm_object_offset_t	end)
{
	register vm_page_t	p, next;

	/*
	 *	One and two page removals are most popular.
	 *	The factor of 16 here is somewhat arbitrary.
	 *	It balances vm_object_lookup vs iteration.
	 */

	if (atop_64(end - start) < (unsigned)object->resident_page_count/16) {
		vm_object_page_remove_lookup++;

		for (; start < end; start += PAGE_SIZE_64) {
			p = vm_page_lookup(object, start);
			if (p != VM_PAGE_NULL) {
				assert(!p->cleaning && !p->pageout);
				if (!p->fictitious)
				        pmap_disconnect(p->phys_page);
				VM_PAGE_FREE(p);
			}
		}
	} else {
		vm_object_page_remove_iterate++;

		p = (vm_page_t) queue_first(&object->memq);
		while (!queue_end(&object->memq, (queue_entry_t) p)) {
			next = (vm_page_t) queue_next(&p->listq);
			if ((start <= p->offset) && (p->offset < end)) {
				assert(!p->cleaning && !p->pageout);
				if (!p->fictitious)
				        pmap_disconnect(p->phys_page);
				VM_PAGE_FREE(p);
			}
			p = next;
		}
	}
}


/*
 *	Routine:	vm_object_coalesce
 *	Function:	Coalesces two objects backing up adjoining
 *			regions of memory into a single object.
 *
 *	returns TRUE if objects were combined.
 *
 *	NOTE:	Only works at the moment if the second object is NULL -
 *		if it's not, which object do we lock first?
 *
 *	Parameters:
 *		prev_object	First object to coalesce
 *		prev_offset	Offset into prev_object
 *		next_object	Second object into coalesce
 *		next_offset	Offset into next_object
 *
 *		prev_size	Size of reference to prev_object
 *		next_size	Size of reference to next_object
 *
 *	Conditions:
 *	The object(s) must *not* be locked. The map must be locked
 *	to preserve the reference to the object(s).
 */
static int vm_object_coalesce_count = 0;

__private_extern__ boolean_t
vm_object_coalesce(
	register vm_object_t		prev_object,
	vm_object_t			next_object,
	vm_object_offset_t		prev_offset,
	__unused vm_object_offset_t next_offset,
	vm_object_size_t		prev_size,
	vm_object_size_t		next_size)
{
	vm_object_size_t	newsize;

#ifdef	lint
	next_offset++;
#endif	/* lint */

	if (next_object != VM_OBJECT_NULL) {
		return(FALSE);
	}

	if (prev_object == VM_OBJECT_NULL) {
		return(TRUE);
	}

	XPR(XPR_VM_OBJECT,
       "vm_object_coalesce: 0x%X prev_off 0x%X prev_size 0x%X next_size 0x%X\n",
		(integer_t)prev_object, prev_offset, prev_size, next_size, 0);

	vm_object_lock(prev_object);

	/*
	 *	Try to collapse the object first
	 */
	vm_object_collapse(prev_object, prev_offset);

	/*
	 *	Can't coalesce if pages not mapped to
	 *	prev_entry may be in use any way:
	 *	. more than one reference
	 *	. paged out
	 *	. shadows another object
	 *	. has a copy elsewhere
	 *	. is purgable
	 *	. paging references (pages might be in page-list)
	 */

	if ((prev_object->ref_count > 1) ||
	    prev_object->pager_created ||
	    (prev_object->shadow != VM_OBJECT_NULL) ||
	    (prev_object->copy != VM_OBJECT_NULL) ||
	    (prev_object->true_share != FALSE) ||
	    (prev_object->purgable != VM_OBJECT_NONPURGABLE) ||
	    (prev_object->paging_in_progress != 0)) {
		vm_object_unlock(prev_object);
		return(FALSE);
	}

	vm_object_coalesce_count++;

	/*
	 *	Remove any pages that may still be in the object from
	 *	a previous deallocation.
	 */
	vm_object_page_remove(prev_object,
		prev_offset + prev_size,
		prev_offset + prev_size + next_size);

	/*
	 *	Extend the object if necessary.
	 */
	newsize = prev_offset + prev_size + next_size;
	if (newsize > prev_object->size) {
#if	MACH_PAGEMAP
		/*
		 *	We cannot extend an object that has existence info,
		 *	since the existence info might then fail to cover
		 *	the entire object.
		 *
		 *	This assertion must be true because the object
		 *	has no pager, and we only create existence info
		 *	for objects with pagers.
		 */
		assert(prev_object->existence_map == VM_EXTERNAL_NULL);
#endif	/* MACH_PAGEMAP */
		prev_object->size = newsize;
	}

	vm_object_unlock(prev_object);
	return(TRUE);
}

/*
 *	Attach a set of physical pages to an object, so that they can
 *	be mapped by mapping the object.  Typically used to map IO memory.
 *
 *	The mapping function and its private data are used to obtain the
 *	physical addresses for each page to be mapped.
 */
void
vm_object_page_map(
	vm_object_t		object,
	vm_object_offset_t	offset,
	vm_object_size_t	size,
	vm_object_offset_t	(*map_fn)(void *map_fn_data, 
		vm_object_offset_t offset),
		void 		*map_fn_data)	/* private to map_fn */
{
	int	num_pages;
	int	i;
	vm_page_t	m;
	vm_page_t	old_page;
	vm_object_offset_t	addr;

	num_pages = atop_64(size);

	for (i = 0; i < num_pages; i++, offset += PAGE_SIZE_64) {

	    addr = (*map_fn)(map_fn_data, offset);

	    while ((m = vm_page_grab_fictitious()) == VM_PAGE_NULL)
		vm_page_more_fictitious();

	    vm_object_lock(object);
	    if ((old_page = vm_page_lookup(object, offset))
			!= VM_PAGE_NULL)
	    {
		vm_page_lock_queues();
		vm_page_free(old_page);
		vm_page_unlock_queues();
	    }

	    vm_page_init(m, addr);
	    /* private normally requires lock_queues but since we */
	    /* are initializing the page, its not necessary here  */
	    m->private = TRUE;		/* don`t free page */
	    m->wire_count = 1;
	    vm_page_insert(m, object, offset);

	    PAGE_WAKEUP_DONE(m);
	    vm_object_unlock(object);
	}
}

#include <mach_kdb.h>

#if	MACH_KDB
#include <ddb/db_output.h>
#include <vm/vm_print.h>

#define printf	kdbprintf

extern boolean_t	vm_object_cached(
				vm_object_t object);

extern void		print_bitstring(
				char byte);

boolean_t	vm_object_print_pages = FALSE;

void
print_bitstring(
	char byte)
{
	printf("%c%c%c%c%c%c%c%c",
	       ((byte & (1 << 0)) ? '1' : '0'),
	       ((byte & (1 << 1)) ? '1' : '0'),
	       ((byte & (1 << 2)) ? '1' : '0'),
	       ((byte & (1 << 3)) ? '1' : '0'),
	       ((byte & (1 << 4)) ? '1' : '0'),
	       ((byte & (1 << 5)) ? '1' : '0'),
	       ((byte & (1 << 6)) ? '1' : '0'),
	       ((byte & (1 << 7)) ? '1' : '0'));
}

boolean_t
vm_object_cached(
	register vm_object_t object)
{
	register vm_object_t o;

	queue_iterate(&vm_object_cached_list, o, vm_object_t, cached_list) {
		if (object == o) {
			return TRUE;
		}
	}
	return FALSE;
}

#if	MACH_PAGEMAP
/*
 *	vm_external_print:	[ debug ]
 */
void
vm_external_print(
	vm_external_map_t 	emap,
	vm_size_t  		size)
{
	if (emap == VM_EXTERNAL_NULL) {
		printf("0  ");
	} else {
		vm_size_t existence_size = stob(size);
		printf("{ size=%d, map=[", existence_size);
		if (existence_size > 0) {
			print_bitstring(emap[0]);
		}
		if (existence_size > 1) {
			print_bitstring(emap[1]);
		}
		if (existence_size > 2) {
			printf("...");
			print_bitstring(emap[existence_size-1]);
		}
		printf("] }\n");
	}
	return;
}
#endif	/* MACH_PAGEMAP */

int
vm_follow_object(
	vm_object_t object)
{
	int count = 0;
	int orig_db_indent = db_indent;

	while (TRUE) {
		if (object == VM_OBJECT_NULL) {
			db_indent = orig_db_indent;
			return count;
		}

		count += 1;

		iprintf("object 0x%x", object);
		printf(", shadow=0x%x", object->shadow);
		printf(", copy=0x%x", object->copy);
		printf(", pager=0x%x", object->pager);
		printf(", ref=%d\n", object->ref_count);

		db_indent += 2;
		object = object->shadow;
	}

}

/*
 *	vm_object_print:	[ debug ]
 */
void
vm_object_print(
	db_addr_t	db_addr,
	__unused boolean_t	have_addr,
	__unused int		arg_count,
	__unused char		*modif)
{
	vm_object_t	object;
	register vm_page_t p;
	const char *s;

	register int count;

	object = (vm_object_t) (long) db_addr;
	if (object == VM_OBJECT_NULL)
		return;

	iprintf("object 0x%x\n", object);

	db_indent += 2;

	iprintf("size=0x%x", object->size);
	printf(", cluster=0x%x", object->cluster_size);
	printf(", memq_hint=%p", object->memq_hint);
	printf(", ref_count=%d\n", object->ref_count);
	iprintf("");
#if	TASK_SWAPPER
	printf("res_count=%d, ", object->res_count);
#endif	/* TASK_SWAPPER */
	printf("resident_page_count=%d\n", object->resident_page_count);

	iprintf("shadow=0x%x", object->shadow);
	if (object->shadow) {
		register int i = 0;
		vm_object_t shadow = object;
		while((shadow = shadow->shadow))
			i++;
		printf(" (depth %d)", i);
	}
	printf(", copy=0x%x", object->copy);
	printf(", shadow_offset=0x%x", object->shadow_offset);
	printf(", last_alloc=0x%x\n", object->last_alloc);

	iprintf("pager=0x%x", object->pager);
	printf(", paging_offset=0x%x", object->paging_offset);
	printf(", pager_control=0x%x\n", object->pager_control);

	iprintf("copy_strategy=%d[", object->copy_strategy);
	switch (object->copy_strategy) {
		case MEMORY_OBJECT_COPY_NONE:
		printf("copy_none");
		break;

		case MEMORY_OBJECT_COPY_CALL:
		printf("copy_call");
		break;

		case MEMORY_OBJECT_COPY_DELAY:
		printf("copy_delay");
		break;

		case MEMORY_OBJECT_COPY_SYMMETRIC:
		printf("copy_symmetric");
		break;

		case MEMORY_OBJECT_COPY_INVALID:
		printf("copy_invalid");
		break;

		default:
		printf("?");
	}
	printf("]");
	printf(", absent_count=%d\n", object->absent_count);

	iprintf("all_wanted=0x%x<", object->all_wanted);
	s = "";
	if (vm_object_wanted(object, VM_OBJECT_EVENT_INITIALIZED)) {
		printf("%sinit", s);
		s = ",";
	}
	if (vm_object_wanted(object, VM_OBJECT_EVENT_PAGER_READY)) {
		printf("%sready", s);
		s = ",";
	}
	if (vm_object_wanted(object, VM_OBJECT_EVENT_PAGING_IN_PROGRESS)) {
		printf("%spaging", s);
		s = ",";
	}
	if (vm_object_wanted(object, VM_OBJECT_EVENT_ABSENT_COUNT)) {
		printf("%sabsent", s);
		s = ",";
	}
	if (vm_object_wanted(object, VM_OBJECT_EVENT_LOCK_IN_PROGRESS)) {
		printf("%slock", s);
		s = ",";
	}
	if (vm_object_wanted(object, VM_OBJECT_EVENT_UNCACHING)) {
		printf("%suncaching", s);
		s = ",";
	}
	if (vm_object_wanted(object, VM_OBJECT_EVENT_COPY_CALL)) {
		printf("%scopy_call", s);
		s = ",";
	}
	if (vm_object_wanted(object, VM_OBJECT_EVENT_CACHING)) {
		printf("%scaching", s);
		s = ",";
	}
	printf(">");
	printf(", paging_in_progress=%d\n", object->paging_in_progress);

	iprintf("%screated, %sinit, %sready, %spersist, %strusted, %spageout, %s, %s\n",
		(object->pager_created ? "" : "!"),
		(object->pager_initialized ? "" : "!"),
		(object->pager_ready ? "" : "!"),
		(object->can_persist ? "" : "!"),
		(object->pager_trusted ? "" : "!"),
		(object->pageout ? "" : "!"),
		(object->internal ? "internal" : "external"),
		(object->temporary ? "temporary" : "permanent"));
	iprintf("%salive, %spurgable, %spurgable_volatile, %spurgable_empty, %sshadowed, %scached, %sprivate\n",
		(object->alive ? "" : "!"),
		((object->purgable != VM_OBJECT_NONPURGABLE) ? "" : "!"),
		((object->purgable == VM_OBJECT_PURGABLE_VOLATILE) ? "" : "!"),
		((object->purgable == VM_OBJECT_PURGABLE_EMPTY) ? "" : "!"),
		(object->shadowed ? "" : "!"),
		(vm_object_cached(object) ? "" : "!"),
		(object->private ? "" : "!"));
	iprintf("%sadvisory_pageout, %ssilent_overwrite\n",
		(object->advisory_pageout ? "" : "!"),
		(object->silent_overwrite ? "" : "!"));

#if	MACH_PAGEMAP
	iprintf("existence_map=");
	vm_external_print(object->existence_map, object->size);
#endif	/* MACH_PAGEMAP */
#if	MACH_ASSERT
	iprintf("paging_object=0x%x\n", object->paging_object);
#endif	/* MACH_ASSERT */

	if (vm_object_print_pages) {
		count = 0;
		p = (vm_page_t) queue_first(&object->memq);
		while (!queue_end(&object->memq, (queue_entry_t) p)) {
			if (count == 0) {
				iprintf("memory:=");
			} else if (count == 2) {
				printf("\n");
				iprintf(" ...");
				count = 0;
			} else {
				printf(",");
			}
			count++;

			printf("(off=0x%llX,page=%p)", p->offset, p);
			p = (vm_page_t) queue_next(&p->listq);
		}
		if (count != 0) {
			printf("\n");
		}
	}
	db_indent -= 2;
}


/*
 *	vm_object_find		[ debug ]
 *
 *	Find all tasks which reference the given vm_object.
 */

boolean_t vm_object_find(vm_object_t object);
boolean_t vm_object_print_verbose = FALSE;

boolean_t
vm_object_find(
	vm_object_t     object)
{
        task_t task;
	vm_map_t map;
	vm_map_entry_t entry;
	processor_set_t pset = &default_pset;
	boolean_t found = FALSE;

	queue_iterate(&pset->tasks, task, task_t, pset_tasks) {
		map = task->map;
		for (entry = vm_map_first_entry(map);
			 entry && entry != vm_map_to_entry(map);
			 entry = entry->vme_next) {

			vm_object_t obj;

			/* 
			 * For the time being skip submaps,
			 * only the kernel can have submaps,
			 * and unless we are interested in 
			 * kernel objects, we can simply skip 
			 * submaps. See sb/dejan/nmk18b7/src/mach_kernel/vm
			 * for a full solution.
			 */
			if (entry->is_sub_map)
				continue;
			if (entry) 
				obj = entry->object.vm_object;
			else 
				continue;

			while (obj != VM_OBJECT_NULL) {
				if (obj == object) {
					if (!found) {
						printf("TASK\t\tMAP\t\tENTRY\n");
						found = TRUE;
					}
					printf("0x%x\t0x%x\t0x%x\n", 
						   task, map, entry);
				}
				obj = obj->shadow;
			}
		}
	}

	return(found);
}

#endif	/* MACH_KDB */

kern_return_t
vm_object_populate_with_private(
		vm_object_t		object,
		vm_object_offset_t	offset,
		ppnum_t			phys_page,
		vm_size_t		size)
{
	ppnum_t			base_page;
	vm_object_offset_t	base_offset;


	if(!object->private)
		return KERN_FAILURE;

	base_page = phys_page;

	vm_object_lock(object);
	if(!object->phys_contiguous) {
		vm_page_t	m;
		if((base_offset = trunc_page_64(offset)) != offset) {
			vm_object_unlock(object);
			return KERN_FAILURE;
		}
		base_offset += object->paging_offset;
		while(size) {
			m = vm_page_lookup(object, base_offset);
			if(m != VM_PAGE_NULL) {
				if(m->fictitious) {
					vm_page_lock_queues();
					m->fictitious = FALSE;
					m->private = TRUE;
					m->phys_page = base_page;
					if(!m->busy) {
						m->busy = TRUE;
					}
					if(!m->absent) {
						m->absent = TRUE;
						object->absent_count++;
					}
					m->list_req_pending = TRUE;
					vm_page_unlock_queues();
				} else if (m->phys_page != base_page) {
					/* pmap call to clear old mapping */
				        pmap_disconnect(m->phys_page);
					m->phys_page = base_page;
				}

				/*
				 * ENCRYPTED SWAP:
				 * We're not pointing to the same
				 * physical page any longer and the
				 * contents of the new one are not
				 * supposed to be encrypted.
				 * XXX What happens to the original
				 * physical page. Is it lost ?
				 */
				m->encrypted = FALSE;

			} else {
				while ((m = vm_page_grab_fictitious()) 
							 == VM_PAGE_NULL)
                			vm_page_more_fictitious();	
				vm_page_lock_queues();
				m->fictitious = FALSE;
				m->private = TRUE;
				m->phys_page = base_page;
				m->list_req_pending = TRUE;
				m->absent = TRUE;
				m->unusual = TRUE;
				object->absent_count++;
				vm_page_unlock_queues();
	    			vm_page_insert(m, object, base_offset);
			}
			base_page++;									/* Go to the next physical page */
			base_offset += PAGE_SIZE;
			size -= PAGE_SIZE;
		}
	} else {
		/* NOTE: we should check the original settings here */
		/* if we have a size > zero a pmap call should be made */
		/* to disable the range */	

		/* pmap_? */
		
		/* shadows on contiguous memory are not allowed */
		/* we therefore can use the offset field */
		object->shadow_offset = (vm_object_offset_t)(phys_page << 12);
		object->size = size;
	}
	vm_object_unlock(object);
	return KERN_SUCCESS;
}

/*
 *	memory_object_free_from_cache:
 *
 *	Walk the vm_object cache list, removing and freeing vm_objects 
 *	which are backed by the pager identified by the caller, (pager_id).  
 *	Remove up to "count" objects, if there are that may available
 *	in the cache.
 *
 *	Walk the list at most once, return the number of vm_objects
 *	actually freed.
 */

__private_extern__ kern_return_t
memory_object_free_from_cache(
	__unused host_t		host,
	int		*pager_id,
	int		*count)
{

	int	object_released = 0;

	register vm_object_t object = VM_OBJECT_NULL;
	vm_object_t shadow;

/*
	if(host == HOST_NULL)
		return(KERN_INVALID_ARGUMENT);
*/

 try_again:
	vm_object_cache_lock();

	queue_iterate(&vm_object_cached_list, object, 
					vm_object_t, cached_list) {
		if (object->pager && (pager_id == object->pager->pager)) {
			vm_object_lock(object);
			queue_remove(&vm_object_cached_list, object, 
					vm_object_t, cached_list);
			vm_object_cached_count--;

			/*
		 	*	Since this object is in the cache, we know
		 	*	that it is initialized and has only a pager's
			*	(implicit) reference. Take a reference to avoid
			*	recursive deallocations.
		 	*/

			assert(object->pager_initialized);
			assert(object->ref_count == 0);
			object->ref_count++;

			/*
		 	*	Terminate the object.
		 	*	If the object had a shadow, we let 
			*	vm_object_deallocate deallocate it. 
			*	"pageout" objects have a shadow, but
		 	*	maintain a "paging reference" rather 
			*	than a normal reference.
		 	*	(We are careful here to limit recursion.)
		 	*/
			shadow = object->pageout?VM_OBJECT_NULL:object->shadow;
			if ((vm_object_terminate(object) == KERN_SUCCESS)
					&& (shadow != VM_OBJECT_NULL)) {
				vm_object_deallocate(shadow);
			}
		
			if(object_released++ == *count)
				return KERN_SUCCESS;
			goto try_again;
		}
	}
	vm_object_cache_unlock();
	*count  = object_released;
	return KERN_SUCCESS;
}



kern_return_t
memory_object_create_named(
	memory_object_t	pager,
	memory_object_offset_t	size,
	memory_object_control_t		*control)
{
	vm_object_t 		object;
	vm_object_hash_entry_t	entry;

	*control = MEMORY_OBJECT_CONTROL_NULL;
	if (pager == MEMORY_OBJECT_NULL)
		return KERN_INVALID_ARGUMENT;

	vm_object_cache_lock();
	entry = vm_object_hash_lookup(pager, FALSE);
	if ((entry != VM_OBJECT_HASH_ENTRY_NULL) &&
			(entry->object != VM_OBJECT_NULL)) {
		if (entry->object->named == TRUE)
			panic("memory_object_create_named: caller already holds the right");	}

	vm_object_cache_unlock();
	if ((object = vm_object_enter(pager, size, FALSE, FALSE, TRUE))
	    == VM_OBJECT_NULL) {
		return(KERN_INVALID_OBJECT);
	}
	
	/* wait for object (if any) to be ready */
	if (object != VM_OBJECT_NULL) {
		vm_object_lock(object);
		object->named = TRUE;
		while (!object->pager_ready) {
			vm_object_sleep(object,
					VM_OBJECT_EVENT_PAGER_READY,
					THREAD_UNINT);
		}
		*control = object->pager_control;
		vm_object_unlock(object);
	}
	return (KERN_SUCCESS);
}


/*
 *	Routine:	memory_object_recover_named [user interface]
 *	Purpose:
 *		Attempt to recover a named reference for a VM object.
 *		VM will verify that the object has not already started
 *		down the termination path, and if it has, will optionally
 *		wait for that to finish.
 *	Returns:
 *		KERN_SUCCESS - we recovered a named reference on the object
 *		KERN_FAILURE - we could not recover a reference (object dead)
 *		KERN_INVALID_ARGUMENT - bad memory object control
 */
kern_return_t
memory_object_recover_named(
	memory_object_control_t	control,
	boolean_t		wait_on_terminating)
{
	vm_object_t		object;

	vm_object_cache_lock();
	object = memory_object_control_to_vm_object(control);
	if (object == VM_OBJECT_NULL) {
		vm_object_cache_unlock();
		return (KERN_INVALID_ARGUMENT);
	}

restart:
	vm_object_lock(object);

	if (object->terminating && wait_on_terminating) {
		vm_object_cache_unlock();
		vm_object_wait(object, 
			VM_OBJECT_EVENT_PAGING_IN_PROGRESS, 
			THREAD_UNINT);
		vm_object_cache_lock();
		goto restart;
	}

	if (!object->alive) {
		vm_object_cache_unlock();
		vm_object_unlock(object);
		return KERN_FAILURE;
	}

	if (object->named == TRUE) {
		vm_object_cache_unlock();
		vm_object_unlock(object);
		return KERN_SUCCESS;
	}

	if((object->ref_count == 0) && (!object->terminating)){
		queue_remove(&vm_object_cached_list, object,
				     vm_object_t, cached_list);
			vm_object_cached_count--;
			XPR(XPR_VM_OBJECT_CACHE,
		       "memory_object_recover_named: removing %X, head (%X, %X)\n",
			    (integer_t)object, 
			    (integer_t)vm_object_cached_list.next,
			    (integer_t)vm_object_cached_list.prev, 0,0);
	}

	vm_object_cache_unlock();

	object->named = TRUE;
	object->ref_count++;
	vm_object_res_reference(object);
	while (!object->pager_ready) {
		vm_object_sleep(object,
				VM_OBJECT_EVENT_PAGER_READY,
				THREAD_UNINT);
	}
	vm_object_unlock(object);
	return (KERN_SUCCESS);
}


/*
 *	vm_object_release_name:  
 *
 *	Enforces name semantic on memory_object reference count decrement
 *	This routine should not be called unless the caller holds a name
 *	reference gained through the memory_object_create_named.
 *
 *	If the TERMINATE_IDLE flag is set, the call will return if the
 *	reference count is not 1. i.e. idle with the only remaining reference
 *	being the name.
 *	If the decision is made to proceed the name field flag is set to
 *	false and the reference count is decremented.  If the RESPECT_CACHE
 *	flag is set and the reference count has gone to zero, the 
 *	memory_object is checked to see if it is cacheable otherwise when
 *	the reference count is zero, it is simply terminated.
 */

__private_extern__ kern_return_t
vm_object_release_name(
	vm_object_t	object,
	int		flags)
{
	vm_object_t	shadow;
	boolean_t	original_object = TRUE;

	while (object != VM_OBJECT_NULL) {

		/*
		 *	The cache holds a reference (uncounted) to
		 *	the object.  We must locke it before removing
		 *	the object.
		 *
		 */
		
		vm_object_cache_lock();
		vm_object_lock(object);
		assert(object->alive);
		if(original_object)
			assert(object->named);
		assert(object->ref_count > 0);

		/*
		 *	We have to wait for initialization before
		 *	destroying or caching the object.
		 */

		if (object->pager_created && !object->pager_initialized) {
			assert(!object->can_persist);
			vm_object_assert_wait(object,
					VM_OBJECT_EVENT_INITIALIZED,
					THREAD_UNINT);
			vm_object_unlock(object);
			vm_object_cache_unlock();
			thread_block(THREAD_CONTINUE_NULL);
			continue;
		}

		if (((object->ref_count > 1)
			&& (flags & MEMORY_OBJECT_TERMINATE_IDLE))
			|| (object->terminating)) {
			vm_object_unlock(object);
			vm_object_cache_unlock();
			return KERN_FAILURE;
		} else {
			if (flags & MEMORY_OBJECT_RELEASE_NO_OP) {
				vm_object_unlock(object);
				vm_object_cache_unlock();
				return KERN_SUCCESS;
			}
		}
		
		if ((flags & MEMORY_OBJECT_RESPECT_CACHE) &&
					(object->ref_count == 1)) {
			if(original_object)
				object->named = FALSE;
			vm_object_unlock(object);
			vm_object_cache_unlock();
			/* let vm_object_deallocate push this thing into */
			/* the cache, if that it is where it is bound */
			vm_object_deallocate(object);
			return KERN_SUCCESS;
		}
		VM_OBJ_RES_DECR(object);
		shadow = object->pageout?VM_OBJECT_NULL:object->shadow;
		if(object->ref_count == 1) {
			if(vm_object_terminate(object) != KERN_SUCCESS) {
				if(original_object) {
					return KERN_FAILURE;
				} else {
					return KERN_SUCCESS;
				}
			}
			if (shadow != VM_OBJECT_NULL) {
				original_object = FALSE;
				object = shadow;
				continue;
			}
			return KERN_SUCCESS;
		} else {
			object->ref_count--;
			assert(object->ref_count > 0);
			if(original_object)
				object->named = FALSE;
			vm_object_unlock(object);
			vm_object_cache_unlock();
			return KERN_SUCCESS;
		}
	}
	/*NOTREACHED*/
	assert(0);
	return KERN_FAILURE;
}


__private_extern__ kern_return_t
vm_object_lock_request(
	vm_object_t			object,
	vm_object_offset_t		offset,
	vm_object_size_t		size,
	memory_object_return_t		should_return,
	int				flags,
	vm_prot_t			prot)
{
	__unused boolean_t	should_flush;

	should_flush = flags & MEMORY_OBJECT_DATA_FLUSH;

        XPR(XPR_MEMORY_OBJECT,
	    "vm_o_lock_request, obj 0x%X off 0x%X size 0x%X flags %X prot %X\n",
	    (integer_t)object, offset, size, 
 	    (((should_return&1)<<1)|should_flush), prot);

	/*
	 *	Check for bogus arguments.
	 */
	if (object == VM_OBJECT_NULL)
		return (KERN_INVALID_ARGUMENT);

	if ((prot & ~VM_PROT_ALL) != 0 && prot != VM_PROT_NO_CHANGE)
		return (KERN_INVALID_ARGUMENT);

	size = round_page_64(size);

	/*
	 *	Lock the object, and acquire a paging reference to
	 *	prevent the memory_object reference from being released.
	 */
	vm_object_lock(object);
	vm_object_paging_begin(object);

	(void)vm_object_update(object,
		offset, size, NULL, NULL, should_return, flags, prot);

	vm_object_paging_end(object);
	vm_object_unlock(object);

	return (KERN_SUCCESS);
}

/*
 * Empty a purgable object by grabbing the physical pages assigned to it and
 * putting them on the free queue without writing them to backing store, etc.
 * When the pages are next touched they will be demand zero-fill pages.  We
 * skip pages which are busy, being paged in/out, wired, etc.  We do _not_
 * skip referenced/dirty pages, pages on the active queue, etc.  We're more
 * than happy to grab these since this is a purgable object.  We mark the
 * object as "empty" after reaping its pages.
 *
 * On entry the object and page queues are locked, the object must be a
 * purgable object with no delayed copies pending.
 */
unsigned int
vm_object_purge(vm_object_t object)
{
	vm_page_t	p, next;
	unsigned int	num_purged_pages;
	vm_page_t	local_freeq;
	unsigned long	local_freed;
	int		purge_loop_quota;
/* free pages as soon as we gather PURGE_BATCH_FREE_LIMIT pages to free */
#define PURGE_BATCH_FREE_LIMIT	50
/* release page queues lock every PURGE_LOOP_QUOTA iterations */
#define PURGE_LOOP_QUOTA	100

	num_purged_pages = 0;
	if (object->purgable == VM_OBJECT_NONPURGABLE)
		return num_purged_pages;

	object->purgable = VM_OBJECT_PURGABLE_EMPTY;

	assert(object->copy == VM_OBJECT_NULL);
	assert(object->copy_strategy == MEMORY_OBJECT_COPY_NONE);
	purge_loop_quota = PURGE_LOOP_QUOTA;

	local_freeq = VM_PAGE_NULL;
	local_freed = 0;

	/*
	 * Go through the object's resident pages and try and discard them.
	 */
	next = (vm_page_t)queue_first(&object->memq);
	while (!queue_end(&object->memq, (queue_entry_t)next)) {
		p = next;
		next = (vm_page_t)queue_next(&next->listq);

		if (purge_loop_quota-- == 0) {
			/*
			 * Avoid holding the page queues lock for too long.
			 * Let someone else take it for a while if needed.
			 * Keep holding the object's lock to guarantee that
			 * the object's page list doesn't change under us
			 * while we yield.
			 */
			if (local_freeq != VM_PAGE_NULL) {
				/*
				 * Flush our queue of pages to free.
				 */
				vm_page_free_list(local_freeq);
				local_freeq = VM_PAGE_NULL;
				local_freed = 0;
			}
			vm_page_unlock_queues();
			mutex_pause();
			vm_page_lock_queues();

			/* resume with the current page and a new quota */
			purge_loop_quota = PURGE_LOOP_QUOTA;
		}
				
		       
		if (p->busy || p->cleaning || p->laundry ||
		    p->list_req_pending) {
			/* page is being acted upon, so don't mess with it */
			continue;
		}
		if (p->wire_count) {
			/* don't discard a wired page */
			continue;
		}

		if (p->tabled) {
			/* clean up the object/offset table */
			vm_page_remove(p);
		}
		if (p->absent) {
			/* update the object's count of absent pages */
			vm_object_absent_release(object);
		}

		/* we can discard this page */

		/* advertize that this page is in a transition state */
		p->busy = TRUE;

		if (p->no_isync == TRUE) {
			/* the page hasn't been mapped yet */
			/* (optimization to delay the i-cache sync) */
		} else {
			/* unmap the page */
			int refmod_state;

			refmod_state = pmap_disconnect(p->phys_page);
			if (refmod_state & VM_MEM_MODIFIED) {
				p->dirty = TRUE;
			}
		}

		if (p->dirty || p->precious) {
			/* we saved the cost of cleaning this page ! */
			num_purged_pages++;
			vm_page_purged_count++;
		}

		/* remove page from active or inactive queue... */
		VM_PAGE_QUEUES_REMOVE(p);

		/* ... and put it on our queue of pages to free */
		assert(!p->laundry);
		assert(p->object != kernel_object);
		assert(p->pageq.next == NULL &&
		       p->pageq.prev == NULL);
		p->pageq.next = (queue_entry_t) local_freeq;
		local_freeq = p;
		if (++local_freed >= PURGE_BATCH_FREE_LIMIT) {
			/* flush our queue of pages to free */
			vm_page_free_list(local_freeq);
			local_freeq = VM_PAGE_NULL;
			local_freed = 0;
		}
	}

	/* flush our local queue of pages to free one last time */
	if (local_freeq != VM_PAGE_NULL) {
		vm_page_free_list(local_freeq);
		local_freeq = VM_PAGE_NULL;
		local_freed = 0;
	}

	return num_purged_pages;
}

/*
 * vm_object_purgable_control() allows the caller to control and investigate the
 * state of a purgable object.  A purgable object is created via a call to
 * vm_allocate() with VM_FLAGS_PURGABLE specified.  A purgable object will
 * never be coalesced with any other object -- even other purgable objects --
 * and will thus always remain a distinct object.  A purgable object has
 * special semantics when its reference count is exactly 1.  If its reference
 * count is greater than 1, then a purgable object will behave like a normal
 * object and attempts to use this interface will result in an error return
 * of KERN_INVALID_ARGUMENT.
 *
 * A purgable object may be put into a "volatile" state which will make the
 * object's pages elligable for being reclaimed without paging to backing
 * store if the system runs low on memory.  If the pages in a volatile
 * purgable object are reclaimed, the purgable object is said to have been
 * "emptied."  When a purgable object is emptied the system will reclaim as
 * many pages from the object as it can in a convenient manner (pages already
 * en route to backing store or busy for other reasons are left as is).  When
 * a purgable object is made volatile, its pages will generally be reclaimed
 * before other pages in the application's working set.  This semantic is
 * generally used by applications which can recreate the data in the object
 * faster than it can be paged in.  One such example might be media assets
 * which can be reread from a much faster RAID volume.
 *
 * A purgable object may be designated as "non-volatile" which means it will
 * behave like all other objects in the system with pages being written to and
 * read from backing store as needed to satisfy system memory needs.  If the
 * object was emptied before the object was made non-volatile, that fact will
 * be returned as the old state of the purgable object (see
 * VM_PURGABLE_SET_STATE below).  In this case, any pages of the object which
 * were reclaimed as part of emptying the object will be refaulted in as
 * zero-fill on demand.  It is up to the application to note that an object
 * was emptied and recreate the objects contents if necessary.  When a
 * purgable object is made non-volatile, its pages will generally not be paged
 * out to backing store in the immediate future.  A purgable object may also
 * be manually emptied.
 *
 * Finally, the current state (non-volatile, volatile, volatile & empty) of a
 * volatile purgable object may be queried at any time.  This information may
 * be used as a control input to let the application know when the system is
 * experiencing memory pressure and is reclaiming memory.
 *
 * The specified address may be any address within the purgable object.  If
 * the specified address does not represent any object in the target task's
 * virtual address space, then KERN_INVALID_ADDRESS will be returned.  If the
 * object containing the specified address is not a purgable object, then
 * KERN_INVALID_ARGUMENT will be returned.  Otherwise, KERN_SUCCESS will be
 * returned.
 *
 * The control parameter may be any one of VM_PURGABLE_SET_STATE or
 * VM_PURGABLE_GET_STATE.  For VM_PURGABLE_SET_STATE, the in/out parameter
 * state is used to set the new state of the purgable object and return its
 * old state.  For VM_PURGABLE_GET_STATE, the current state of the purgable
 * object is returned in the parameter state.
 *
 * The in/out parameter state may be one of VM_PURGABLE_NONVOLATILE,
 * VM_PURGABLE_VOLATILE or VM_PURGABLE_EMPTY.  These, respectively, represent
 * the non-volatile, volatile and volatile/empty states described above.
 * Setting the state of a purgable object to VM_PURGABLE_EMPTY will
 * immediately reclaim as many pages in the object as can be conveniently
 * collected (some may have already been written to backing store or be
 * otherwise busy).
 *
 * The process of making a purgable object non-volatile and determining its
 * previous state is atomic.  Thus, if a purgable object is made
 * VM_PURGABLE_NONVOLATILE and the old state is returned as
 * VM_PURGABLE_VOLATILE, then the purgable object's previous contents are
 * completely intact and will remain so until the object is made volatile
 * again.  If the old state is returned as VM_PURGABLE_EMPTY then the object
 * was reclaimed while it was in a volatile state and its previous contents
 * have been lost.
 */
/*
 * The object must be locked.
 */
kern_return_t
vm_object_purgable_control(
	vm_object_t	object,
	vm_purgable_t	control,
	int		*state)
{
	int		old_state;
	vm_page_t	p;

	if (object == VM_OBJECT_NULL) {
		/*
		 * Object must already be present or it can't be purgable.
		 */
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * Get current state of the purgable object.
	 */
	switch (object->purgable) {
	    case VM_OBJECT_NONPURGABLE:
		return KERN_INVALID_ARGUMENT;
    
	    case VM_OBJECT_PURGABLE_NONVOLATILE:
		old_state = VM_PURGABLE_NONVOLATILE;
		break;

	    case VM_OBJECT_PURGABLE_VOLATILE:
		old_state = VM_PURGABLE_VOLATILE;
		break;

	    case VM_OBJECT_PURGABLE_EMPTY:
		old_state = VM_PURGABLE_EMPTY;
		break;

	    default:
		old_state = VM_PURGABLE_NONVOLATILE;
		panic("Bad state (%d) for purgable object!\n",
		      object->purgable);
		/*NOTREACHED*/
	}

	/* purgable cant have delayed copies - now or in the future */
	assert(object->copy == VM_OBJECT_NULL); 
	assert(object->copy_strategy == MEMORY_OBJECT_COPY_NONE);

	/*
	 * Execute the desired operation.
	 */
	if (control == VM_PURGABLE_GET_STATE) {
		*state = old_state;
		return KERN_SUCCESS;
	}

	switch (*state) {
	case VM_PURGABLE_NONVOLATILE:
		vm_page_lock_queues();
		if (object->purgable != VM_OBJECT_PURGABLE_NONVOLATILE) {
			assert(vm_page_purgeable_count >=
			       object->resident_page_count);
			vm_page_purgeable_count -= object->resident_page_count;
		}

		object->purgable = VM_OBJECT_PURGABLE_NONVOLATILE;

		/*
		 * If the object wasn't emptied, then mark all pages of the
		 * object as referenced in order to give them a complete turn
		 * of the virtual memory "clock" before becoming candidates
		 * for paging out (if the system is suffering from memory
		 * pressure).  We don't really need to set the pmap reference
		 * bits (which would be expensive) since the software copies
		 * are believed if they're set to true ...
		 */
		if (old_state != VM_PURGABLE_EMPTY) {
			for (p = (vm_page_t)queue_first(&object->memq);
			     !queue_end(&object->memq, (queue_entry_t)p);
			     p = (vm_page_t)queue_next(&p->listq))
				p->reference = TRUE;
		}

		vm_page_unlock_queues();

		break;

	case VM_PURGABLE_VOLATILE:
		vm_page_lock_queues();

		if (object->purgable != VM_OBJECT_PURGABLE_VOLATILE &&
		    object->purgable != VM_OBJECT_PURGABLE_EMPTY) {
			vm_page_purgeable_count += object->resident_page_count;
		}

		object->purgable = VM_OBJECT_PURGABLE_VOLATILE;

		/*
		 * We want the newly volatile purgable object to be a
		 * candidate for the pageout scan before other pages in the
		 * application if the system is suffering from memory
		 * pressure.  To do this, we move a page of the object from
		 * the active queue onto the inactive queue in order to
		 * promote the object for early reclaim.  We only need to move
		 * a single page since the pageout scan will reap the entire
		 * purgable object if it finds a single page in a volatile
		 * state.  Obviously we don't do this if there are no pages
		 * associated with the object or we find a page of the object
		 * already on the inactive queue.
		 */
		for (p = (vm_page_t)queue_first(&object->memq);
		     !queue_end(&object->memq, (queue_entry_t)p);
		     p = (vm_page_t)queue_next(&p->listq)) {
			if (p->inactive) {
				/* already a page on the inactive queue */
				break;
			}
			if (p->active && !p->busy) {
				/* found one we can move */
				vm_page_deactivate(p);
				break;
			}
		}
		vm_page_unlock_queues();

		break;


	case VM_PURGABLE_EMPTY:
		vm_page_lock_queues();
		if (object->purgable != VM_OBJECT_PURGABLE_VOLATILE &&
		    object->purgable != VM_OBJECT_PURGABLE_EMPTY) {
			vm_page_purgeable_count += object->resident_page_count;
		}
		(void) vm_object_purge(object);
		vm_page_unlock_queues();
		break;

	}
	*state = old_state;

	return KERN_SUCCESS;
}

#if	TASK_SWAPPER
/*
 * vm_object_res_deallocate
 *
 * (recursively) decrement residence counts on vm objects and their shadows.
 * Called from vm_object_deallocate and when swapping out an object.
 *
 * The object is locked, and remains locked throughout the function,
 * even as we iterate down the shadow chain.  Locks on intermediate objects
 * will be dropped, but not the original object.
 *
 * NOTE: this function used to use recursion, rather than iteration.
 */

__private_extern__ void
vm_object_res_deallocate(
	vm_object_t	object)
{
	vm_object_t orig_object = object;
	/*
	 * Object is locked so it can be called directly
	 * from vm_object_deallocate.  Original object is never
	 * unlocked.
	 */
	assert(object->res_count > 0);
	while  (--object->res_count == 0) {
		assert(object->ref_count >= object->res_count);
		vm_object_deactivate_all_pages(object);
		/* iterate on shadow, if present */
		if (object->shadow != VM_OBJECT_NULL) {
			vm_object_t tmp_object = object->shadow;
			vm_object_lock(tmp_object);
			if (object != orig_object)
				vm_object_unlock(object);
			object = tmp_object;
			assert(object->res_count > 0);
		} else
			break;
	}
	if (object != orig_object)
		vm_object_unlock(object);
}

/*
 * vm_object_res_reference
 *
 * Internal function to increment residence count on a vm object
 * and its shadows.  It is called only from vm_object_reference, and
 * when swapping in a vm object, via vm_map_swap.
 *
 * The object is locked, and remains locked throughout the function,
 * even as we iterate down the shadow chain.  Locks on intermediate objects
 * will be dropped, but not the original object.
 *
 * NOTE: this function used to use recursion, rather than iteration.
 */

__private_extern__ void
vm_object_res_reference(
	vm_object_t	object)
{
	vm_object_t orig_object = object;
	/* 
	 * Object is locked, so this can be called directly
	 * from vm_object_reference.  This lock is never released.
	 */
	while  ((++object->res_count == 1)  && 
		(object->shadow != VM_OBJECT_NULL)) {
		vm_object_t tmp_object = object->shadow;

		assert(object->ref_count >= object->res_count);
		vm_object_lock(tmp_object);
		if (object != orig_object)
			vm_object_unlock(object);
		object = tmp_object;
	}
	if (object != orig_object)
		vm_object_unlock(object);
	assert(orig_object->ref_count >= orig_object->res_count);
}
#endif	/* TASK_SWAPPER */

/*
 *	vm_object_reference:
 *
 *	Gets another reference to the given object.
 */
#ifdef vm_object_reference
#undef vm_object_reference
#endif
__private_extern__ void
vm_object_reference(
	register vm_object_t	object)
{
	if (object == VM_OBJECT_NULL)
		return;

	vm_object_lock(object);
	assert(object->ref_count > 0);
	vm_object_reference_locked(object);
	vm_object_unlock(object);
}

#ifdef MACH_BSD
/*
 * Scale the vm_object_cache
 * This is required to make sure that the vm_object_cache is big
 * enough to effectively cache the mapped file.
 * This is really important with UBC as all the regular file vnodes
 * have memory object associated with them. Havving this cache too
 * small results in rapid reclaim of vnodes and hurts performance a LOT!
 *
 * This is also needed as number of vnodes can be dynamically scaled.
 */
kern_return_t
adjust_vm_object_cache(
	__unused vm_size_t oval,
	vm_size_t nval)
{
	vm_object_cached_max = nval;
	vm_object_cache_trim(FALSE);
	return (KERN_SUCCESS);
}
#endif /* MACH_BSD */


/*
 * vm_object_transpose
 *
 * This routine takes two VM objects of the same size and exchanges
 * their backing store.
 * The objects should be "quiesced" via a UPL operation with UPL_SET_IO_WIRE
 * and UPL_BLOCK_ACCESS if they are referenced anywhere.
 *
 * The VM objects must not be locked by caller.
 */
kern_return_t
vm_object_transpose(
	vm_object_t		object1,
	vm_object_t		object2,
	vm_object_size_t	transpose_size)
{
	vm_object_t		tmp_object;
	kern_return_t		retval;
	boolean_t		object1_locked, object2_locked;
	boolean_t		object1_paging, object2_paging;
	vm_page_t		page;
	vm_object_offset_t	page_offset;

	tmp_object = VM_OBJECT_NULL;
	object1_locked = FALSE; object2_locked = FALSE;
	object1_paging = FALSE; object2_paging = FALSE;

	if (object1 == object2 ||
	    object1 == VM_OBJECT_NULL ||
	    object2 == VM_OBJECT_NULL) {
		/*
		 * If the 2 VM objects are the same, there's
		 * no point in exchanging their backing store.
		 */
		retval = KERN_INVALID_VALUE;
		goto done;
	}

	vm_object_lock(object1);
	object1_locked = TRUE;
	if (object1->copy || object1->shadow || object1->shadowed ||
	    object1->purgable != VM_OBJECT_NONPURGABLE) {
		/*
		 * We don't deal with copy or shadow objects (yet).
		 */
		retval = KERN_INVALID_VALUE;
		goto done;
	}
	/*
	 * Since we're about to mess with the object's backing store,
	 * mark it as "paging_in_progress".  Note that this is not enough
	 * to prevent any paging activity on this object, so the caller should
	 * have "quiesced" the objects beforehand, via a UPL operation with
	 * UPL_SET_IO_WIRE (to make sure all the pages are there and wired)
	 * and UPL_BLOCK_ACCESS (to mark the pages "busy").
	 */
	vm_object_paging_begin(object1);
	object1_paging = TRUE;
	vm_object_unlock(object1);
	object1_locked = FALSE;

	/*
	 * Same as above for the 2nd object...
	 */
	vm_object_lock(object2);
	object2_locked = TRUE;
	if (object2->copy || object2->shadow || object2->shadowed ||
	    object2->purgable != VM_OBJECT_NONPURGABLE) {
		retval = KERN_INVALID_VALUE;
		goto done;
	}
	vm_object_paging_begin(object2);
	object2_paging = TRUE;
	vm_object_unlock(object2);
	object2_locked = FALSE;

	/*
	 * Allocate a temporary VM object to hold object1's contents
	 * while we copy object2 to object1.
	 */
	tmp_object = vm_object_allocate(transpose_size);
	vm_object_lock(tmp_object);
	vm_object_paging_begin(tmp_object);
	tmp_object->can_persist = FALSE;

	/*
	 * Since we need to lock both objects at the same time,
	 * make sure we always lock them in the same order to
	 * avoid deadlocks.
	 */
	if (object1 < object2) {
		vm_object_lock(object1);
		vm_object_lock(object2);
	} else {
		vm_object_lock(object2);
		vm_object_lock(object1);
	}
	object1_locked = TRUE;
	object2_locked = TRUE;

	if (object1->size != object2->size ||
	    object1->size != transpose_size) {
		/*
		 * If the 2 objects don't have the same size, we can't
		 * exchange their backing stores or one would overflow.
		 * If their size doesn't match the caller's
		 * "transpose_size", we can't do it either because the
		 * transpose operation will affect the entire span of 
		 * the objects.
		 */
		retval = KERN_INVALID_VALUE;
		goto done;
	}


	/*
	 * Transpose the lists of resident pages.
	 */
	if (object1->phys_contiguous || queue_empty(&object1->memq)) {
		/*
		 * No pages in object1, just transfer pages
		 * from object2 to object1.  No need to go through
		 * an intermediate object.
		 */
		while (!queue_empty(&object2->memq)) {
			page = (vm_page_t) queue_first(&object2->memq);
			vm_page_rename(page, object1, page->offset);
		}
		assert(queue_empty(&object2->memq));
	} else if (object2->phys_contiguous || queue_empty(&object2->memq)) {
		/*
		 * No pages in object2, just transfer pages
		 * from object1 to object2.  No need to go through
		 * an intermediate object.
		 */
		while (!queue_empty(&object1->memq)) {
			page = (vm_page_t) queue_first(&object1->memq);
			vm_page_rename(page, object2, page->offset);
		}
		assert(queue_empty(&object1->memq));
	} else {
		/* transfer object1's pages to tmp_object */
		vm_page_lock_queues();
		while (!queue_empty(&object1->memq)) {
			page = (vm_page_t) queue_first(&object1->memq);
			page_offset = page->offset;
			vm_page_remove(page);
			page->offset = page_offset;
			queue_enter(&tmp_object->memq, page, vm_page_t, listq);
		}
		vm_page_unlock_queues();
		assert(queue_empty(&object1->memq));
		/* transfer object2's pages to object1 */
		while (!queue_empty(&object2->memq)) {
			page = (vm_page_t) queue_first(&object2->memq);
			vm_page_rename(page, object1, page->offset);
		}
		assert(queue_empty(&object2->memq));
		/* transfer tmp_object's pages to object1 */
		while (!queue_empty(&tmp_object->memq)) {
			page = (vm_page_t) queue_first(&tmp_object->memq);
			queue_remove(&tmp_object->memq, page,
				     vm_page_t, listq);
			vm_page_insert(page, object2, page->offset);
		}
		assert(queue_empty(&tmp_object->memq));
	}

	/* no need to transpose the size: they should be identical */
	assert(object1->size == object2->size);

#define __TRANSPOSE_FIELD(field)				\
MACRO_BEGIN							\
	tmp_object->field = object1->field;			\
	object1->field = object2->field;			\
	object2->field = tmp_object->field;			\
MACRO_END

	assert(!object1->copy);
	assert(!object2->copy);

	assert(!object1->shadow);
	assert(!object2->shadow);

	__TRANSPOSE_FIELD(shadow_offset); /* used by phys_contiguous objects */
	__TRANSPOSE_FIELD(pager);
	__TRANSPOSE_FIELD(paging_offset);

	__TRANSPOSE_FIELD(pager_control);
	/* update the memory_objects' pointers back to the VM objects */
	if (object1->pager_control != MEMORY_OBJECT_CONTROL_NULL) {
		memory_object_control_collapse(object1->pager_control,
					       object1);
	}
	if (object2->pager_control != MEMORY_OBJECT_CONTROL_NULL) {
		memory_object_control_collapse(object2->pager_control,
					       object2);
	}
		
	__TRANSPOSE_FIELD(absent_count);

	assert(object1->paging_in_progress);
	assert(object2->paging_in_progress);

	__TRANSPOSE_FIELD(pager_created);
	__TRANSPOSE_FIELD(pager_initialized);
	__TRANSPOSE_FIELD(pager_ready);
	__TRANSPOSE_FIELD(pager_trusted);
	__TRANSPOSE_FIELD(internal);
	__TRANSPOSE_FIELD(temporary);
	__TRANSPOSE_FIELD(private);
	__TRANSPOSE_FIELD(pageout);
	__TRANSPOSE_FIELD(true_share);
	__TRANSPOSE_FIELD(phys_contiguous);
	__TRANSPOSE_FIELD(nophyscache);
	__TRANSPOSE_FIELD(last_alloc);
	__TRANSPOSE_FIELD(sequential);
	__TRANSPOSE_FIELD(cluster_size);
	__TRANSPOSE_FIELD(existence_map);
	__TRANSPOSE_FIELD(cow_hint);
	__TRANSPOSE_FIELD(wimg_bits);

#undef __TRANSPOSE_FIELD

	retval = KERN_SUCCESS;

done:
	/*
	 * Cleanup.
	 */
	if (tmp_object != VM_OBJECT_NULL) {
		vm_object_paging_end(tmp_object);
		vm_object_unlock(tmp_object);
		/*
		 * Re-initialize the temporary object to avoid
		 * deallocating a real pager.
		 */
		_vm_object_allocate(transpose_size, tmp_object);
		vm_object_deallocate(tmp_object);
		tmp_object = VM_OBJECT_NULL;
	}

	if (object1_locked) {
		vm_object_unlock(object1);
		object1_locked = FALSE;
	}
	if (object2_locked) {
		vm_object_unlock(object2);
		object2_locked = FALSE;
	}
	if (object1_paging) {
		vm_object_lock(object1);
		vm_object_paging_end(object1);
		vm_object_unlock(object1);
		object1_paging = FALSE;
	}
	if (object2_paging) {
		vm_object_lock(object2);
		vm_object_paging_end(object2);
		vm_object_unlock(object2);
		object2_paging = FALSE;
	}

	return retval;
}
