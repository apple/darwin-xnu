/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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

#include <debug.h>
#include <mach_pagemap.h>
#include <task_swapper.h>

#include <mach/mach_types.h>
#include <mach/memory_object.h>
#include <mach/memory_object_default.h>
#include <mach/memory_object_control_server.h>
#include <mach/vm_param.h>

#include <mach/sdt.h>

#include <ipc/ipc_types.h>
#include <ipc/ipc_port.h>

#include <kern/kern_types.h>
#include <kern/assert.h>
#include <kern/queue.h>
#include <kern/xpr.h>
#include <kern/kalloc.h>
#include <kern/zalloc.h>
#include <kern/host.h>
#include <kern/host_statistics.h>
#include <kern/processor.h>
#include <kern/misc_protos.h>

#include <vm/memory_object.h>
#include <vm/vm_compressor_pager.h>
#include <vm/vm_fault.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>
#include <vm/vm_purgeable_internal.h>

#include <vm/vm_compressor.h>

#if CONFIG_PHANTOM_CACHE
#include <vm/vm_phantom_cache.h>
#endif

boolean_t vm_object_collapse_compressor_allowed = TRUE;

struct vm_counters vm_counters;

#if VM_OBJECT_TRACKING
boolean_t vm_object_tracking_inited = FALSE;
decl_simple_lock_data(static,vm_object_tracking_lock_data);
btlog_t *vm_object_tracking_btlog;
static void
vm_object_tracking_lock(void *context)
{
	simple_lock((simple_lock_t)context);
}
static void
vm_object_tracking_unlock(void *context)
{
	simple_unlock((simple_lock_t)context);
}
void
vm_object_tracking_init(void)
{
	int vm_object_tracking;

	vm_object_tracking = 1;
	PE_parse_boot_argn("vm_object_tracking", &vm_object_tracking, 
			   sizeof (vm_object_tracking));

	if (vm_object_tracking) {
		simple_lock_init(&vm_object_tracking_lock_data, 0);
		vm_object_tracking_btlog = btlog_create(
			50000,
			VM_OBJECT_TRACKING_BTDEPTH,
			vm_object_tracking_lock,
			vm_object_tracking_unlock,
			&vm_object_tracking_lock_data);
		assert(vm_object_tracking_btlog);
		vm_object_tracking_inited = TRUE;
	}
}
#endif /* VM_OBJECT_TRACKING */

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
	                        memory_object_t	pager,
				boolean_t	hashed);

static zone_t		vm_object_zone;		/* vm backing store zone */

/*
 *	All wired-down kernel memory belongs to a single virtual
 *	memory object (kernel_object) to avoid wasting data structures.
 */
static struct vm_object			kernel_object_store;
vm_object_t						kernel_object;

static struct vm_object			compressor_object_store;
vm_object_t				compressor_object = &compressor_object_store;

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

unsigned int vm_page_purged_wired = 0;
unsigned int vm_page_purged_busy = 0;
unsigned int vm_page_purged_others = 0;

#if VM_OBJECT_CACHE
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
static vm_object_t	vm_object_cache_trim(
				boolean_t called_from_vm_object_deallocate);

static void		vm_object_deactivate_all_pages(
				vm_object_t	object);

static int		vm_object_cached_high;	/* highest # cached objects */
static int		vm_object_cached_max = 512;	/* may be patched*/

#define vm_object_cache_lock()		\
		lck_mtx_lock(&vm_object_cached_lock_data)
#define vm_object_cache_lock_try()		\
		lck_mtx_try_lock(&vm_object_cached_lock_data)

#endif	/* VM_OBJECT_CACHE */

static queue_head_t	vm_object_cached_list;
static uint32_t		vm_object_cache_pages_freed = 0;
static uint32_t		vm_object_cache_pages_moved = 0;
static uint32_t		vm_object_cache_pages_skipped = 0;
static uint32_t		vm_object_cache_adds = 0;
static uint32_t		vm_object_cached_count = 0;
static lck_mtx_t	vm_object_cached_lock_data;
static lck_mtx_ext_t	vm_object_cached_lock_data_ext;

static uint32_t		vm_object_page_grab_failed = 0;
static uint32_t		vm_object_page_grab_skipped = 0;
static uint32_t		vm_object_page_grab_returned = 0;
static uint32_t		vm_object_page_grab_pmapped = 0;
static uint32_t		vm_object_page_grab_reactivations = 0;

#define vm_object_cache_lock_spin()		\
		lck_mtx_lock_spin(&vm_object_cached_lock_data)
#define vm_object_cache_unlock()	\
		lck_mtx_unlock(&vm_object_cached_lock_data)

static void	vm_object_cache_remove_locked(vm_object_t);


#define	VM_OBJECT_HASH_COUNT		1024
#define	VM_OBJECT_HASH_LOCK_COUNT	512

static lck_mtx_t	vm_object_hashed_lock_data[VM_OBJECT_HASH_LOCK_COUNT];
static lck_mtx_ext_t	vm_object_hashed_lock_data_ext[VM_OBJECT_HASH_LOCK_COUNT];

static queue_head_t	vm_object_hashtable[VM_OBJECT_HASH_COUNT];
static struct zone	*vm_object_hash_zone;

struct vm_object_hash_entry {
	queue_chain_t		hash_link;	/* hash chain link */
	memory_object_t	pager;		/* pager we represent */
	vm_object_t		object;		/* corresponding object */
	boolean_t		waiting;	/* someone waiting for
						 * termination */
};

typedef struct vm_object_hash_entry	*vm_object_hash_entry_t;
#define VM_OBJECT_HASH_ENTRY_NULL	((vm_object_hash_entry_t) 0)

#define VM_OBJECT_HASH_SHIFT	5
#define vm_object_hash(pager) \
	((int)((((uintptr_t)pager) >> VM_OBJECT_HASH_SHIFT) % VM_OBJECT_HASH_COUNT))

#define vm_object_lock_hash(pager) \
	((int)((((uintptr_t)pager) >> VM_OBJECT_HASH_SHIFT) % VM_OBJECT_HASH_LOCK_COUNT))

void vm_object_hash_entry_free(
	vm_object_hash_entry_t	entry);

static void vm_object_reap(vm_object_t object);
static void vm_object_reap_async(vm_object_t object);
static void vm_object_reaper_thread(void);

static lck_mtx_t	vm_object_reaper_lock_data;
static lck_mtx_ext_t	vm_object_reaper_lock_data_ext;

static queue_head_t vm_object_reaper_queue; /* protected by vm_object_reaper_lock() */
unsigned int vm_object_reap_count = 0;
unsigned int vm_object_reap_count_async = 0;

#define vm_object_reaper_lock()		\
		lck_mtx_lock(&vm_object_reaper_lock_data)
#define vm_object_reaper_lock_spin()		\
		lck_mtx_lock_spin(&vm_object_reaper_lock_data)
#define vm_object_reaper_unlock()	\
		lck_mtx_unlock(&vm_object_reaper_lock_data)

#if CONFIG_IOSCHED
/* I/O Re-prioritization request list */
queue_head_t 	io_reprioritize_list;
lck_spin_t 	io_reprioritize_list_lock;

#define IO_REPRIORITIZE_LIST_LOCK() 	\
		lck_spin_lock(&io_reprioritize_list_lock)
#define IO_REPRIORITIZE_LIST_UNLOCK() 	\
		lck_spin_unlock(&io_reprioritize_list_lock)

#define MAX_IO_REPRIORITIZE_REQS 	8192
zone_t 		io_reprioritize_req_zone;

/* I/O Re-prioritization thread */
int io_reprioritize_wakeup = 0;
static void io_reprioritize_thread(void *param __unused, wait_result_t wr __unused);

#define IO_REPRIO_THREAD_WAKEUP() 	thread_wakeup((event_t)&io_reprioritize_wakeup)
#define IO_REPRIO_THREAD_CONTINUATION() 				\
{ 								\
	assert_wait(&io_reprioritize_wakeup, THREAD_UNINT);	\
	thread_block(io_reprioritize_thread);			\
}

void vm_page_request_reprioritize(vm_object_t, uint64_t, uint32_t, int);
void vm_page_handle_prio_inversion(vm_object_t, vm_page_t);
void vm_decmp_upl_reprioritize(upl_t, int);
#endif

#if 0
#undef KERNEL_DEBUG
#define KERNEL_DEBUG KERNEL_DEBUG_CONSTANT
#endif


static lck_mtx_t *
vm_object_hash_lock_spin(
	memory_object_t	pager)
{
	int	index;

	index = vm_object_lock_hash(pager);

	lck_mtx_lock_spin(&vm_object_hashed_lock_data[index]);

	return (&vm_object_hashed_lock_data[index]);
}

static void
vm_object_hash_unlock(lck_mtx_t *lck)
{
	lck_mtx_unlock(lck);
}


/*
 *	vm_object_hash_lookup looks up a pager in the hashtable
 *	and returns the corresponding entry, with optional removal.
 */
static vm_object_hash_entry_t
vm_object_hash_lookup(
	memory_object_t	pager,
	boolean_t	remove_entry)
{
	queue_t			bucket;
	vm_object_hash_entry_t	entry;

	bucket = &vm_object_hashtable[vm_object_hash(pager)];

	entry = (vm_object_hash_entry_t)queue_first(bucket);
	while (!queue_end(bucket, (queue_entry_t)entry)) {
		if (entry->pager == pager) {
			if (remove_entry) {
				queue_remove(bucket, entry,
					     vm_object_hash_entry_t, hash_link);
			}
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
	vm_object_hash_entry_t	entry,
	vm_object_t		object)
{
	queue_t		bucket;

	vm_object_lock_assert_exclusive(object);

	bucket = &vm_object_hashtable[vm_object_hash(entry->pager)];

	queue_enter(bucket, entry, vm_object_hash_entry_t, hash_link);

	entry->object = object;
	object->hashed = TRUE;
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
		object, size, 0,0,0);

	*object = vm_object_template;
	queue_init(&object->memq);
	queue_init(&object->msr_q);
#if UPL_DEBUG || CONFIG_IOSCHED
	queue_init(&object->uplq);
#endif
	vm_object_lock_init(object);
	object->vo_size = size;

#if VM_OBJECT_TRACKING_OP_CREATED
	if (vm_object_tracking_inited) {
		void	*bt[VM_OBJECT_TRACKING_BTDEPTH];
		int	numsaved = 0;

		numsaved = OSBacktrace(bt, VM_OBJECT_TRACKING_BTDEPTH);
		btlog_add_entry(vm_object_tracking_btlog,
				object,
				VM_OBJECT_TRACKING_OP_CREATED,
				bt,
				numsaved);
	}
#endif /* VM_OBJECT_TRACKING_OP_CREATED */
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


lck_grp_t		vm_object_lck_grp;
lck_grp_t		vm_object_cache_lck_grp;
lck_grp_attr_t		vm_object_lck_grp_attr;
lck_attr_t		vm_object_lck_attr;
lck_attr_t		kernel_object_lck_attr;
lck_attr_t		compressor_object_lck_attr;

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
				round_page(512*1024),
				round_page(12*1024),
				"vm objects");
	zone_change(vm_object_zone, Z_CALLERACCT, FALSE); /* don't charge caller */
	zone_change(vm_object_zone, Z_NOENCRYPT, TRUE);

	vm_object_init_lck_grp();

	queue_init(&vm_object_cached_list);

	lck_mtx_init_ext(&vm_object_cached_lock_data,
		&vm_object_cached_lock_data_ext,
		&vm_object_cache_lck_grp,
		&vm_object_lck_attr);

	queue_init(&vm_object_reaper_queue);

	for (i = 0; i < VM_OBJECT_HASH_LOCK_COUNT; i++) {
		lck_mtx_init_ext(&vm_object_hashed_lock_data[i],
				 &vm_object_hashed_lock_data_ext[i],
				 &vm_object_lck_grp,
				 &vm_object_lck_attr);
	}
	lck_mtx_init_ext(&vm_object_reaper_lock_data,
		&vm_object_reaper_lock_data_ext,
		&vm_object_lck_grp,
		&vm_object_lck_attr);

	vm_object_hash_zone =
			zinit((vm_size_t) sizeof (struct vm_object_hash_entry),
			      round_page(512*1024),
			      round_page(12*1024),
			      "vm object hash entries");
	zone_change(vm_object_hash_zone, Z_CALLERACCT, FALSE);
	zone_change(vm_object_hash_zone, Z_NOENCRYPT, TRUE);

	for (i = 0; i < VM_OBJECT_HASH_COUNT; i++)
		queue_init(&vm_object_hashtable[i]);


	/*
	 *	Fill in a template object, for quick initialization
	 */

	/* memq; Lock; init after allocation */
	vm_object_template.memq.prev = NULL;
	vm_object_template.memq.next = NULL;
#if 0
	/*
	 * We can't call vm_object_lock_init() here because that will
	 * allocate some memory and VM is not fully initialized yet.
	 * The lock will be initialized for each allocated object in
	 * _vm_object_allocate(), so we don't need to initialize it in
	 * the vm_object_template.
	 */
	vm_object_lock_init(&vm_object_template);
#endif
	vm_object_template.vo_size = 0;
	vm_object_template.memq_hint = VM_PAGE_NULL;
	vm_object_template.ref_count = 1;
#if	TASK_SWAPPER
	vm_object_template.res_count = 1;
#endif	/* TASK_SWAPPER */
	vm_object_template.resident_page_count = 0;
	vm_object_template.wired_page_count = 0;
	vm_object_template.reusable_page_count = 0;
	vm_object_template.copy = VM_OBJECT_NULL;
	vm_object_template.shadow = VM_OBJECT_NULL;
	vm_object_template.vo_shadow_offset = (vm_object_offset_t) 0;
	vm_object_template.pager = MEMORY_OBJECT_NULL;
	vm_object_template.paging_offset = 0;
	vm_object_template.pager_control = MEMORY_OBJECT_CONTROL_NULL;
	vm_object_template.copy_strategy = MEMORY_OBJECT_COPY_SYMMETRIC;
	vm_object_template.paging_in_progress = 0;
#if __LP64__
	vm_object_template.__object1_unused_bits = 0;
#endif /* __LP64__ */
	vm_object_template.activity_in_progress = 0;

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
	vm_object_template.purgable = VM_PURGABLE_DENY;
	vm_object_template.purgeable_when_ripe = FALSE;
	vm_object_template.shadowed = FALSE;
	vm_object_template.advisory_pageout = FALSE;
	vm_object_template.true_share = FALSE;
	vm_object_template.terminating = FALSE;
	vm_object_template.named = FALSE;
	vm_object_template.shadow_severed = FALSE;
	vm_object_template.phys_contiguous = FALSE;
	vm_object_template.nophyscache = FALSE;
	/* End bitfields */

	vm_object_template.cached_list.prev = NULL;
	vm_object_template.cached_list.next = NULL;
	vm_object_template.msr_q.prev = NULL;
	vm_object_template.msr_q.next = NULL;
	
	vm_object_template.last_alloc = (vm_object_offset_t) 0;
	vm_object_template.sequential = (vm_object_offset_t) 0;
	vm_object_template.pages_created = 0;
	vm_object_template.pages_used = 0;
	vm_object_template.scan_collisions = 0;
#if CONFIG_PHANTOM_CACHE
	vm_object_template.phantom_object_id = 0;
#endif
#if	MACH_PAGEMAP
	vm_object_template.existence_map = VM_EXTERNAL_NULL;
#endif	/* MACH_PAGEMAP */
	vm_object_template.cow_hint = ~(vm_offset_t)0;
#if	MACH_ASSERT
	vm_object_template.paging_object = VM_OBJECT_NULL;
#endif	/* MACH_ASSERT */

	/* cache bitfields */
	vm_object_template.wimg_bits = VM_WIMG_USE_DEFAULT;
	vm_object_template.set_cache_attr = FALSE;
	vm_object_template.object_slid = FALSE;
	vm_object_template.code_signed = FALSE;
	vm_object_template.hashed = FALSE;
	vm_object_template.transposed = FALSE;
	vm_object_template.mapping_in_progress = FALSE;
	vm_object_template.phantom_isssd = FALSE;
	vm_object_template.volatile_empty = FALSE;
	vm_object_template.volatile_fault = FALSE;
	vm_object_template.all_reusable = FALSE;
	vm_object_template.blocked_access = FALSE;
	vm_object_template.__object2_unused_bits = 0;
#if CONFIG_IOSCHED || UPL_DEBUG
	vm_object_template.uplq.prev = NULL;
	vm_object_template.uplq.next = NULL;
#endif /* UPL_DEBUG */
#ifdef VM_PIP_DEBUG
	bzero(&vm_object_template.pip_holders,
	      sizeof (vm_object_template.pip_holders));
#endif /* VM_PIP_DEBUG */

	vm_object_template.objq.next = NULL;
	vm_object_template.objq.prev = NULL;

	vm_object_template.purgeable_queue_type = PURGEABLE_Q_TYPE_MAX;
	vm_object_template.purgeable_queue_group = 0;

	vm_object_template.vo_cache_ts = 0;
	
#if DEBUG
	bzero(&vm_object_template.purgeable_owner_bt[0],
	      sizeof (vm_object_template.purgeable_owner_bt));
	vm_object_template.vo_purgeable_volatilizer = NULL;
	bzero(&vm_object_template.purgeable_volatilizer_bt[0],
	      sizeof (vm_object_template.purgeable_volatilizer_bt));
#endif /* DEBUG */

	/*
	 *	Initialize the "kernel object"
	 */

	kernel_object = &kernel_object_store;

/*
 *	Note that in the following size specifications, we need to add 1 because 
 *	VM_MAX_KERNEL_ADDRESS (vm_last_addr) is a maximum address, not a size.
 */

#ifdef ppc
	_vm_object_allocate(vm_last_addr + 1,
			    kernel_object);
#else
	_vm_object_allocate(VM_MAX_KERNEL_ADDRESS + 1,
			    kernel_object);

	_vm_object_allocate(VM_MAX_KERNEL_ADDRESS + 1,
			    compressor_object);
#endif
	kernel_object->copy_strategy = MEMORY_OBJECT_COPY_NONE;
	compressor_object->copy_strategy = MEMORY_OBJECT_COPY_NONE;

	/*
	 *	Initialize the "submap object".  Make it as large as the
	 *	kernel object so that no limit is imposed on submap sizes.
	 */

	vm_submap_object = &vm_submap_object_store;
#ifdef ppc
	_vm_object_allocate(vm_last_addr + 1,
			    vm_submap_object);
#else
	_vm_object_allocate(VM_MAX_KERNEL_ADDRESS + 1,
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

#if CONFIG_IOSCHED
void
vm_io_reprioritize_init(void)
{
	kern_return_t 	result;
	thread_t 	thread = THREAD_NULL;

	/* Initialze the I/O reprioritization subsystem */
        lck_spin_init(&io_reprioritize_list_lock, &vm_object_lck_grp, &vm_object_lck_attr);
        queue_init(&io_reprioritize_list);

	io_reprioritize_req_zone = zinit(sizeof(struct io_reprioritize_req),
					 MAX_IO_REPRIORITIZE_REQS * sizeof(struct io_reprioritize_req),
                                      	 4096, "io_reprioritize_req");	

	result = kernel_thread_start_priority(io_reprioritize_thread, NULL, 95 /* MAXPRI_KERNEL */, &thread);
        if (result == KERN_SUCCESS) {
                thread_deallocate(thread);
        } else {
                panic("Could not create io_reprioritize_thread");
        }
}
#endif

void
vm_object_reaper_init(void)
{
	kern_return_t	kr;
	thread_t	thread;

	kr = kernel_thread_start_priority(
		(thread_continue_t) vm_object_reaper_thread,
		NULL,
		BASEPRI_PREEMPT - 1,
		&thread);
	if (kr != KERN_SUCCESS) {
		panic("failed to launch vm_object_reaper_thread kr=0x%x", kr);
	}
	thread_deallocate(thread);
}

__private_extern__ void
vm_object_init(void)
{
	/*
	 *	Finish initializing the kernel object.
	 */
}


__private_extern__ void
vm_object_init_lck_grp(void)
{
	/*
	 * initialze the vm_object lock world
	 */
	lck_grp_attr_setdefault(&vm_object_lck_grp_attr);
	lck_grp_init(&vm_object_lck_grp, "vm_object", &vm_object_lck_grp_attr);
	lck_grp_init(&vm_object_cache_lck_grp, "vm_object_cache", &vm_object_lck_grp_attr);
	lck_attr_setdefault(&vm_object_lck_attr);
	lck_attr_setdefault(&kernel_object_lck_attr);
	lck_attr_cleardebug(&kernel_object_lck_attr);
	lck_attr_setdefault(&compressor_object_lck_attr);
	lck_attr_cleardebug(&compressor_object_lck_attr);
}

#if VM_OBJECT_CACHE
#define	MIGHT_NOT_CACHE_SHADOWS		1
#if	MIGHT_NOT_CACHE_SHADOWS
static int cache_shadows = TRUE;
#endif	/* MIGHT_NOT_CACHE_SHADOWS */
#endif

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
unsigned long vm_object_deallocate_shared_successes = 0;
unsigned long vm_object_deallocate_shared_failures = 0;
unsigned long vm_object_deallocate_shared_swap_failures = 0;
__private_extern__ void
vm_object_deallocate(
	register vm_object_t	object)
{
#if VM_OBJECT_CACHE
	boolean_t	retry_cache_trim = FALSE;
	uint32_t	try_failed_count = 0;
#endif
	vm_object_t	shadow = VM_OBJECT_NULL;
	
//	if(object)dbgLog(object, object->ref_count, object->can_persist, 3);	/* (TEST/DEBUG) */
//	else dbgLog(object, 0, 0, 3);	/* (TEST/DEBUG) */

	if (object == VM_OBJECT_NULL)
	        return;

	if (object == kernel_object || object == compressor_object) {
		vm_object_lock_shared(object);

		OSAddAtomic(-1, &object->ref_count);

		if (object->ref_count == 0) {
			if (object == kernel_object)
				panic("vm_object_deallocate: losing kernel_object\n");
			else
				panic("vm_object_deallocate: losing compressor_object\n");
		}
		vm_object_unlock(object);
		return;
	}

	if (object->ref_count == 2 &&
	    object->named) {
		/*
		 * This "named" object's reference count is about to
		 * drop from 2 to 1:
		 * we'll need to call memory_object_last_unmap().
		 */
	} else if (object->ref_count == 2 &&
		   object->internal &&
		   object->shadow != VM_OBJECT_NULL) {
		/*
		 * This internal object's reference count is about to
		 * drop from 2 to 1 and it has a shadow object:
		 * we'll want to try and collapse this object with its
		 * shadow.
		 */
	} else if (object->ref_count >= 2) { 
		UInt32		original_ref_count;
		volatile UInt32	*ref_count_p;
		Boolean		atomic_swap;

		/*
		 * The object currently looks like it is not being
		 * kept alive solely by the reference we're about to release.
		 * Let's try and release our reference without taking
		 * all the locks we would need if we had to terminate the
		 * object (cache lock + exclusive object lock).
		 * Lock the object "shared" to make sure we don't race with
		 * anyone holding it "exclusive".
		 */
	        vm_object_lock_shared(object);
		ref_count_p = (volatile UInt32 *) &object->ref_count;
		original_ref_count = object->ref_count;
		/*
		 * Test again as "ref_count" could have changed.
		 * "named" shouldn't change.
		 */
		if (original_ref_count == 2 &&
		    object->named) {
			/* need to take slow path for m_o_last_unmap() */
			atomic_swap = FALSE;
		} else if (original_ref_count == 2 &&
			   object->internal &&
			   object->shadow != VM_OBJECT_NULL) {
			/* need to take slow path for vm_object_collapse() */
			atomic_swap = FALSE;
		} else if (original_ref_count < 2) { 
			/* need to take slow path for vm_object_terminate() */
			atomic_swap = FALSE;
		} else {
			/* try an atomic update with the shared lock */
			atomic_swap = OSCompareAndSwap(
				original_ref_count,
				original_ref_count - 1,
				(UInt32 *) &object->ref_count);
			if (atomic_swap == FALSE) {
				vm_object_deallocate_shared_swap_failures++;
				/* fall back to the slow path... */
			}
		}
			
		vm_object_unlock(object);

		if (atomic_swap) {
			/*
			 * ref_count was updated atomically !
			 */
			vm_object_deallocate_shared_successes++;
			return;
		}

		/*
		 * Someone else updated the ref_count at the same
		 * time and we lost the race.  Fall back to the usual
		 * slow but safe path...
		 */
		vm_object_deallocate_shared_failures++;
	}

	while (object != VM_OBJECT_NULL) {

		vm_object_lock(object);

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
				vm_object_mapping_wait(object, THREAD_UNINT);
				vm_object_mapping_begin(object);
				vm_object_unlock(object);

				memory_object_last_unmap(pager);

				vm_object_lock(object);
				vm_object_mapping_end(object);
			}
			assert(object->ref_count > 0);
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
			vm_object_lock_assert_exclusive(object);
			object->ref_count--;
			vm_object_res_deallocate(object);

			if (object->ref_count == 1 &&
			    object->shadow != VM_OBJECT_NULL) {
				/*
				 * There's only one reference left on this
				 * VM object.  We can't tell if it's a valid
				 * one (from a mapping for example) or if this
				 * object is just part of a possibly stale and
				 * useless shadow chain.
				 * We would like to try and collapse it into
				 * its parent, but we don't have any pointers
				 * back to this parent object.
				 * But we can try and collapse this object with
				 * its own shadows, in case these are useless
				 * too...
				 * We can't bypass this object though, since we
				 * don't know if this last reference on it is
				 * meaningful or not.
				 */
				vm_object_collapse(object, 0, FALSE);
			}
			vm_object_unlock(object); 
#if VM_OBJECT_CACHE
			if (retry_cache_trim &&
			    ((object = vm_object_cache_trim(TRUE)) !=
			     VM_OBJECT_NULL)) {
				continue;
			}
#endif
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

			thread_block(THREAD_CONTINUE_NULL);
			continue;
		}

#if VM_OBJECT_CACHE
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

			vm_object_lock_assert_exclusive(object);
			if (--object->ref_count > 0) {
				vm_object_res_deallocate(object);
				vm_object_unlock(object);

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
				object,
				vm_object_cached_list.next,
				vm_object_cached_list.prev,0,0);


			vm_object_unlock(object);

			try_failed_count = 0;
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
				try_failed_count++;

				mutex_pause(try_failed_count);  /* wait a bit */
			}
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
		} else
#endif	/* VM_OBJECT_CACHE */
		{
			/*
			 *	This object is not cachable; terminate it.
			 */
			XPR(XPR_VM_OBJECT,
	 "vm_o_deallocate: !cacheable 0x%X res %d paging_ops %d thread 0x%p ref %d\n",
			    object, object->resident_page_count,
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

			if (vm_object_terminate(object) != KERN_SUCCESS) {
				return;
			}
			if (shadow != VM_OBJECT_NULL) {
				object = shadow;
				continue;
			}
#if VM_OBJECT_CACHE
			if (retry_cache_trim &&
			    ((object = vm_object_cache_trim(TRUE)) !=
			     VM_OBJECT_NULL)) {
				continue;
			}
#endif
			return;
		}
	}
#if VM_OBJECT_CACHE
	assert(! retry_cache_trim);
#endif
}



vm_page_t
vm_object_page_grab(
	vm_object_t	object)
{
	vm_page_t	p, next_p;
	int		p_limit = 0;
	int		p_skipped = 0;

	vm_object_lock_assert_exclusive(object);

	next_p = (vm_page_t)queue_first(&object->memq);
	p_limit = MIN(50, object->resident_page_count);

	while (!queue_end(&object->memq, (queue_entry_t)next_p) && --p_limit > 0) {

		p = next_p;
		next_p = (vm_page_t)queue_next(&next_p->listq);

		if (VM_PAGE_WIRED(p) || p->busy || p->cleaning || p->laundry || p->fictitious)
			goto move_page_in_obj;

		if (p->pmapped || p->dirty || p->precious) {
			vm_page_lockspin_queues();

			if (p->pmapped) {
				int refmod_state;

				vm_object_page_grab_pmapped++;

				if (p->reference == FALSE || p->dirty == FALSE) {

					refmod_state = pmap_get_refmod(p->phys_page);

					if (refmod_state & VM_MEM_REFERENCED)
						p->reference = TRUE;
					if (refmod_state & VM_MEM_MODIFIED) {
						SET_PAGE_DIRTY(p, FALSE);
					}
				}
				if (p->dirty == FALSE && p->precious == FALSE) {

					refmod_state = pmap_disconnect(p->phys_page);

					if (refmod_state & VM_MEM_REFERENCED)
						p->reference = TRUE;
					if (refmod_state & VM_MEM_MODIFIED) {
						SET_PAGE_DIRTY(p, FALSE);
					}

					if (p->dirty == FALSE)
						goto take_page;
				}
			}
			if (p->inactive && p->reference == TRUE) {
				vm_page_activate(p);

				VM_STAT_INCR(reactivations);
				vm_object_page_grab_reactivations++;
			}
			vm_page_unlock_queues();
move_page_in_obj:
			queue_remove(&object->memq, p, vm_page_t, listq);
			queue_enter(&object->memq, p, vm_page_t, listq);

			p_skipped++;
			continue;
		}
		vm_page_lockspin_queues();
take_page:
		vm_page_free_prepare_queues(p);
		vm_object_page_grab_returned++;
		vm_object_page_grab_skipped += p_skipped;

		vm_page_unlock_queues();

		vm_page_free_prepare_object(p, TRUE);
		
		return (p);
	}
	vm_object_page_grab_skipped += p_skipped;
	vm_object_page_grab_failed++;

	return (NULL);
}



#define EVICT_PREPARE_LIMIT	64
#define EVICT_AGE		10

static	clock_sec_t	vm_object_cache_aging_ts = 0;

static void
vm_object_cache_remove_locked(
	vm_object_t	object)
{
	queue_remove(&vm_object_cached_list, object, vm_object_t, objq);
	object->objq.next = NULL;
	object->objq.prev = NULL;

	vm_object_cached_count--;
}

void
vm_object_cache_remove(
	vm_object_t	object)
{
	vm_object_cache_lock_spin();

	if (object->objq.next || object->objq.prev)
		vm_object_cache_remove_locked(object);

	vm_object_cache_unlock();
}

void
vm_object_cache_add(
	vm_object_t	object)
{
	clock_sec_t sec;
	clock_nsec_t nsec;

	if (object->resident_page_count == 0)
		return;
	clock_get_system_nanotime(&sec, &nsec);

	vm_object_cache_lock_spin();

	if (object->objq.next == NULL && object->objq.prev == NULL) {
		queue_enter(&vm_object_cached_list, object, vm_object_t, objq);
		object->vo_cache_ts = sec + EVICT_AGE;
		object->vo_cache_pages_to_scan = object->resident_page_count;

		vm_object_cached_count++;
		vm_object_cache_adds++;
	}
	vm_object_cache_unlock();
}

int
vm_object_cache_evict(
	int	num_to_evict,
	int	max_objects_to_examine)
{
	vm_object_t	object = VM_OBJECT_NULL;
	vm_object_t	next_obj = VM_OBJECT_NULL;
	vm_page_t	local_free_q = VM_PAGE_NULL;
	vm_page_t	p;
	vm_page_t	next_p;
	int		object_cnt = 0;
	vm_page_t	ep_array[EVICT_PREPARE_LIMIT];
	int		ep_count;
	int		ep_limit;
	int		ep_index;
	int		ep_freed = 0;
	int		ep_moved = 0;
	uint32_t	ep_skipped = 0;
	clock_sec_t	sec;
	clock_nsec_t	nsec;

	KERNEL_DEBUG(0x13001ec | DBG_FUNC_START, 0, 0, 0, 0, 0);
	/*
	 * do a couple of quick checks to see if it's 
	 * worthwhile grabbing the lock
	 */
	if (queue_empty(&vm_object_cached_list)) {
		KERNEL_DEBUG(0x13001ec | DBG_FUNC_END, 0, 0, 0, 0, 0);
		return (0);
	}
	clock_get_system_nanotime(&sec, &nsec);

	/*
	 * the object on the head of the queue has not
	 * yet sufficiently aged
	 */
	if (sec < vm_object_cache_aging_ts) {
		KERNEL_DEBUG(0x13001ec | DBG_FUNC_END, 0, 0, 0, 0, 0);
		return (0);
	}
	/*
	 * don't need the queue lock to find 
	 * and lock an object on the cached list
	 */
	vm_page_unlock_queues();

	vm_object_cache_lock_spin();

	for (;;) {
		next_obj = (vm_object_t)queue_first(&vm_object_cached_list);

		while (!queue_end(&vm_object_cached_list, (queue_entry_t)next_obj) && object_cnt++ < max_objects_to_examine) {

			object = next_obj;
			next_obj = (vm_object_t)queue_next(&next_obj->objq);
			
			if (sec < object->vo_cache_ts) {
				KERNEL_DEBUG(0x130020c, object, object->resident_page_count, object->vo_cache_ts, sec, 0);

				vm_object_cache_aging_ts = object->vo_cache_ts;
				object = VM_OBJECT_NULL;
				break;
			}
			if (!vm_object_lock_try_scan(object)) {
				/*
				 * just skip over this guy for now... if we find
				 * an object to steal pages from, we'll revist in a bit...
				 * hopefully, the lock will have cleared
				 */
				KERNEL_DEBUG(0x13001f8, object, object->resident_page_count, 0, 0, 0);

				object = VM_OBJECT_NULL;
				continue;
			}
			if (queue_empty(&object->memq) || object->vo_cache_pages_to_scan == 0) {
				/*
				 * this case really shouldn't happen, but it's not fatal
				 * so deal with it... if we don't remove the object from
				 * the list, we'll never move past it.
				 */
				KERNEL_DEBUG(0x13001fc, object, object->resident_page_count, ep_freed, ep_moved, 0);
				
				vm_object_cache_remove_locked(object);
				vm_object_unlock(object);
				object = VM_OBJECT_NULL;
				continue;
			}
			/*
			 * we have a locked object with pages...
			 * time to start harvesting
			 */
			break;
		}
		vm_object_cache_unlock();

		if (object == VM_OBJECT_NULL)
			break;

		/*
		 * object is locked at this point and
		 * has resident pages
		 */
		next_p = (vm_page_t)queue_first(&object->memq);

		/*
		 * break the page scan into 2 pieces to minimize the time spent
		 * behind the page queue lock...
		 * the list of pages on these unused objects is likely to be cold
		 * w/r to the cpu cache which increases the time to scan the list
		 * tenfold...  and we may have a 'run' of pages we can't utilize that
		 * needs to be skipped over...
		 */
		if ((ep_limit = num_to_evict - (ep_freed + ep_moved)) > EVICT_PREPARE_LIMIT)
			ep_limit = EVICT_PREPARE_LIMIT;
		ep_count = 0;

		while (!queue_end(&object->memq, (queue_entry_t)next_p) && object->vo_cache_pages_to_scan && ep_count < ep_limit) {

			p = next_p;
			next_p = (vm_page_t)queue_next(&next_p->listq);

			object->vo_cache_pages_to_scan--;

			if (VM_PAGE_WIRED(p) || p->busy || p->cleaning || p->laundry) {
				queue_remove(&object->memq, p, vm_page_t, listq);
				queue_enter(&object->memq, p, vm_page_t, listq);

				ep_skipped++;
				continue;
			}
			if (p->wpmapped || p->dirty || p->precious) {
				queue_remove(&object->memq, p, vm_page_t, listq);
				queue_enter(&object->memq, p, vm_page_t, listq);

				pmap_clear_reference(p->phys_page);
			}
			ep_array[ep_count++] = p;
		}
		KERNEL_DEBUG(0x13001f4 | DBG_FUNC_START, object, object->resident_page_count, ep_freed, ep_moved, 0);

		vm_page_lockspin_queues();

		for (ep_index = 0; ep_index < ep_count; ep_index++) {

			p = ep_array[ep_index];

			if (p->wpmapped || p->dirty || p->precious) {
				p->reference = FALSE;
				p->no_cache = FALSE;

				/*
				 * we've already filtered out pages that are in the laundry
				 * so if we get here, this page can't be on the pageout queue
				 */
				assert(!p->pageout_queue);

				VM_PAGE_QUEUES_REMOVE(p);
				VM_PAGE_ENQUEUE_INACTIVE(p, TRUE);

				ep_moved++;
			} else {
#if CONFIG_PHANTOM_CACHE
				vm_phantom_cache_add_ghost(p);
#endif
				vm_page_free_prepare_queues(p);

				assert(p->pageq.next == NULL && p->pageq.prev == NULL);
				/*
				 * Add this page to our list of reclaimed pages,
				 * to be freed later.
				 */
				p->pageq.next = (queue_entry_t) local_free_q;
				local_free_q = p;

				ep_freed++;
			}
		}
		vm_page_unlock_queues();

		KERNEL_DEBUG(0x13001f4 | DBG_FUNC_END, object, object->resident_page_count, ep_freed, ep_moved, 0);

		if (local_free_q) {
			vm_page_free_list(local_free_q, TRUE);
			local_free_q = VM_PAGE_NULL;
		}
		if (object->vo_cache_pages_to_scan == 0) {
			KERNEL_DEBUG(0x1300208, object, object->resident_page_count, ep_freed, ep_moved, 0);

			vm_object_cache_remove(object);

			KERNEL_DEBUG(0x13001fc, object, object->resident_page_count, ep_freed, ep_moved, 0);
		}
		/*
		 * done with this object
		 */
		vm_object_unlock(object);
		object = VM_OBJECT_NULL;

		/*
		 * at this point, we are not holding any locks
		 */
		if ((ep_freed + ep_moved) >= num_to_evict) {
			/*
			 * we've reached our target for the
			 * number of pages to evict
			 */
			break;
		}
		vm_object_cache_lock_spin();
	}
	/*
	 * put the page queues lock back to the caller's
	 * idea of it 
	 */
	vm_page_lock_queues();

	vm_object_cache_pages_freed += ep_freed;
	vm_object_cache_pages_moved += ep_moved;
	vm_object_cache_pages_skipped += ep_skipped;

	KERNEL_DEBUG(0x13001ec | DBG_FUNC_END, ep_freed, 0, 0, 0, 0);
	return (ep_freed);
}


#if VM_OBJECT_CACHE
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
		if (vm_object_cached_count <= vm_object_cached_max)
			return VM_OBJECT_NULL;

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
			vm_object_cached_list.next,
			vm_object_cached_list.prev, 0, 0, 0);

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

		vm_object_cache_unlock();
		/*
		 *	Since this object is in the cache, we know
		 *	that it is initialized and has no references.
		 *	Take a reference to avoid recursive deallocations.
		 */

		assert(object->pager_initialized);
		assert(object->ref_count == 0);
		vm_object_lock_assert_exclusive(object);
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
#endif


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
	vm_object_t	object)
{
	vm_object_t	shadow_object;

	XPR(XPR_VM_OBJECT, "vm_object_terminate, object 0x%X ref %d\n",
		object, object->ref_count, 0, 0, 0);

	if (!object->pageout && (!object->temporary || object->can_persist) &&
	    (object->pager != NULL || object->shadow_severed)) {
		/*
		 * Clear pager_trusted bit so that the pages get yanked
		 * out of the object instead of cleaned in place.  This
		 * prevents a deadlock in XMM and makes more sense anyway.
		 */
		object->pager_trusted = FALSE;

		vm_object_reap_pages(object, REAP_TERMINATE);
	}
	/*
	 *	Make sure the object isn't already being terminated
	 */
	if (object->terminating) {
		vm_object_lock_assert_exclusive(object);
		object->ref_count--;
		assert(object->ref_count > 0);
		vm_object_unlock(object);
		return KERN_FAILURE;
	}

	/*
	 * Did somebody get a reference to the object while we were
	 * cleaning it?
	 */
	if (object->ref_count != 1) {
		vm_object_lock_assert_exclusive(object);
		object->ref_count--;
		assert(object->ref_count > 0);
		vm_object_res_deallocate(object);
		vm_object_unlock(object);
		return KERN_FAILURE;
	}

	/*
	 *	Make sure no one can look us up now.
	 */

	object->terminating = TRUE;
	object->alive = FALSE;

	if ( !object->internal && (object->objq.next || object->objq.prev))
		vm_object_cache_remove(object);

	if (object->hashed) {
		lck_mtx_t	*lck;

		lck = vm_object_hash_lock_spin(object->pager);
		vm_object_remove(object);
		vm_object_hash_unlock(lck);
	}
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

	if (object->paging_in_progress != 0 ||
	    object->activity_in_progress != 0) {
		/*
		 * There are still some paging_in_progress references
		 * on this object, meaning that there are some paging
		 * or other I/O operations in progress for this VM object.
		 * Such operations take some paging_in_progress references
		 * up front to ensure that the object doesn't go away, but
		 * they may also need to acquire a reference on the VM object,
		 * to map it in kernel space, for example.  That means that
		 * they may end up releasing the last reference on the VM
		 * object, triggering its termination, while still holding
		 * paging_in_progress references.  Waiting for these
		 * pending paging_in_progress references to go away here would
		 * deadlock.
		 *
		 * To avoid deadlocking, we'll let the vm_object_reaper_thread
		 * complete the VM object termination if it still holds
		 * paging_in_progress references at this point.
		 *
		 * No new paging_in_progress should appear now that the
		 * VM object is "terminating" and not "alive".
		 */
		vm_object_reap_async(object);
		vm_object_unlock(object);
		/*
		 * Return KERN_FAILURE to let the caller know that we
		 * haven't completed the termination and it can't drop this
		 * object's reference on its shadow object yet.
		 * The reaper thread will take care of that once it has
		 * completed this object's termination.
		 */
		return KERN_FAILURE;
	}
	/*
	 * complete the VM object termination
	 */
	vm_object_reap(object);
	object = VM_OBJECT_NULL;

	/*
	 * the object lock was released by vm_object_reap()
	 *
	 * KERN_SUCCESS means that this object has been terminated
	 * and no longer needs its shadow object but still holds a
	 * reference on it.
	 * The caller is responsible for dropping that reference.
	 * We can't call vm_object_deallocate() here because that
	 * would create a recursion.
	 */
	return KERN_SUCCESS;
}


/*
 * vm_object_reap():
 *
 * Complete the termination of a VM object after it's been marked
 * as "terminating" and "!alive" by vm_object_terminate().
 *
 * The VM object must be locked by caller.
 * The lock will be released on return and the VM object is no longer valid.
 */
void
vm_object_reap(
	vm_object_t object)
{
	memory_object_t		pager;

	vm_object_lock_assert_exclusive(object);
	assert(object->paging_in_progress == 0);
	assert(object->activity_in_progress == 0);

	vm_object_reap_count++;

	/*
	 * Disown this purgeable object to cleanup its owner's purgeable
	 * ledgers.  We need to do this before disconnecting the object
	 * from its pager, to properly account for compressed pages.
	 */
	if (object->internal &&
	    object->purgable != VM_PURGABLE_DENY) {
		vm_purgeable_accounting(object,
					object->purgable,
					TRUE); /* disown */
	}

	pager = object->pager;
	object->pager = MEMORY_OBJECT_NULL;

	if (pager != MEMORY_OBJECT_NULL)
		memory_object_control_disable(object->pager_control);

	object->ref_count--;
#if	TASK_SWAPPER
	assert(object->res_count == 0);
#endif	/* TASK_SWAPPER */

	assert (object->ref_count == 0);

	/*
	 * remove from purgeable queue if it's on
	 */
	if (object->internal) {
		task_t owner;

		owner = object->vo_purgeable_owner;

		if (object->purgable == VM_PURGABLE_DENY) {
			/* not purgeable: nothing to do */
		} else if (object->purgable == VM_PURGABLE_VOLATILE) {
			purgeable_q_t queue;

			assert(object->vo_purgeable_owner == NULL);

			queue = vm_purgeable_object_remove(object);
			assert(queue);

			if (object->purgeable_when_ripe) {
				/*
				 * Must take page lock for this -
				 * using it to protect token queue
				 */
				vm_page_lock_queues();
				vm_purgeable_token_delete_first(queue);
        
				assert(queue->debug_count_objects>=0);
				vm_page_unlock_queues();
			}

			/*
			 * Update "vm_page_purgeable_count" in bulk and mark
			 * object as VM_PURGABLE_EMPTY to avoid updating 
			 * "vm_page_purgeable_count" again in vm_page_remove()
			 * when reaping the pages.
			 */
			unsigned int delta;
			assert(object->resident_page_count >=
			       object->wired_page_count);
			delta = (object->resident_page_count -
				 object->wired_page_count);
			if (delta != 0) {
				assert(vm_page_purgeable_count >= delta);
				OSAddAtomic(-delta,
					    (SInt32 *)&vm_page_purgeable_count);
			}
			if (object->wired_page_count != 0) {
				assert(vm_page_purgeable_wired_count >=
				       object->wired_page_count);
				OSAddAtomic(-object->wired_page_count,
					    (SInt32 *)&vm_page_purgeable_wired_count);
			}
			object->purgable = VM_PURGABLE_EMPTY;
		}
		else if (object->purgable == VM_PURGABLE_NONVOLATILE ||
			 object->purgable == VM_PURGABLE_EMPTY) {
			/* remove from nonvolatile queue */
			assert(object->vo_purgeable_owner == TASK_NULL);
			vm_purgeable_nonvolatile_dequeue(object);
		} else {
			panic("object %p in unexpected purgeable state 0x%x\n",
			      object, object->purgable);
		}
		assert(object->objq.next == NULL);
		assert(object->objq.prev == NULL);
	}
    
	/*
	 *	Clean or free the pages, as appropriate.
	 *	It is possible for us to find busy/absent pages,
	 *	if some faults on this object were aborted.
	 */
	if (object->pageout) {
		assert(object->shadow != VM_OBJECT_NULL);

		vm_pageout_object_terminate(object);

	} else if (((object->temporary && !object->can_persist) || (pager == MEMORY_OBJECT_NULL))) {

		vm_object_reap_pages(object, REAP_REAP);
	}
	assert(queue_empty(&object->memq));
	assert(object->paging_in_progress == 0);
	assert(object->activity_in_progress == 0);
	assert(object->ref_count == 0);

	/*
	 * If the pager has not already been released by
	 * vm_object_destroy, we need to terminate it and
	 * release our reference to it here.
	 */
	if (pager != MEMORY_OBJECT_NULL) {
		vm_object_unlock(object);
		vm_object_release_pager(pager, object->hashed);
		vm_object_lock(object);
	}

	/* kick off anyone waiting on terminating */
	object->terminating = FALSE;
	vm_object_paging_begin(object);
	vm_object_paging_end(object);
	vm_object_unlock(object);

#if	MACH_PAGEMAP
	vm_external_destroy(object->existence_map, object->vo_size);
#endif	/* MACH_PAGEMAP */

	object->shadow = VM_OBJECT_NULL;

#if VM_OBJECT_TRACKING
	if (vm_object_tracking_inited) {
		btlog_remove_entries_for_element(vm_object_tracking_btlog,
						 object);
	}
#endif /* VM_OBJECT_TRACKING */

	vm_object_lock_destroy(object);
	/*
	 *	Free the space for the object.
	 */
	zfree(vm_object_zone, object);
	object = VM_OBJECT_NULL;
}


unsigned int vm_max_batch = 256;

#define V_O_R_MAX_BATCH 128

#define BATCH_LIMIT(max) 	(vm_max_batch >= max ? max : vm_max_batch)


#define VM_OBJ_REAP_FREELIST(_local_free_q, do_disconnect)		\
	MACRO_BEGIN							\
	if (_local_free_q) {						\
		if (do_disconnect) {					\
			vm_page_t m;					\
			for (m = _local_free_q;				\
			     m != VM_PAGE_NULL;				\
			     m = (vm_page_t) m->pageq.next) {		\
				if (m->pmapped) {			\
					pmap_disconnect(m->phys_page);	\
				}					\
			}						\
		}							\
		vm_page_free_list(_local_free_q, TRUE);			\
		_local_free_q = VM_PAGE_NULL;				\
	}								\
	MACRO_END


void
vm_object_reap_pages(
	vm_object_t 	object,
	int		reap_type)
{
	vm_page_t	p;
	vm_page_t	next;
	vm_page_t	local_free_q = VM_PAGE_NULL;
	int		loop_count;
	boolean_t	disconnect_on_release;
	pmap_flush_context	pmap_flush_context_storage;

	if (reap_type == REAP_DATA_FLUSH) {
		/*
		 * We need to disconnect pages from all pmaps before
		 * releasing them to the free list
		 */
		disconnect_on_release = TRUE;
	} else {
		/*
		 * Either the caller has already disconnected the pages
		 * from all pmaps, or we disconnect them here as we add
		 * them to out local list of pages to be released.
		 * No need to re-disconnect them when we release the pages
		 * to the free list.
		 */
		disconnect_on_release = FALSE;
	}
		
restart_after_sleep:
	if (queue_empty(&object->memq))
		return;
	loop_count = BATCH_LIMIT(V_O_R_MAX_BATCH);

	if (reap_type == REAP_PURGEABLE)
		pmap_flush_context_init(&pmap_flush_context_storage);

	vm_page_lockspin_queues();

	next = (vm_page_t)queue_first(&object->memq);

	while (!queue_end(&object->memq, (queue_entry_t)next)) {

		p = next;
		next = (vm_page_t)queue_next(&next->listq);

		if (--loop_count == 0) {
					
			vm_page_unlock_queues();

			if (local_free_q) {

				if (reap_type == REAP_PURGEABLE) {
					pmap_flush(&pmap_flush_context_storage);
					pmap_flush_context_init(&pmap_flush_context_storage);
				}
				/*
				 * Free the pages we reclaimed so far
				 * and take a little break to avoid
				 * hogging the page queue lock too long
				 */
				VM_OBJ_REAP_FREELIST(local_free_q,
						     disconnect_on_release);
			} else
				mutex_pause(0);

			loop_count = BATCH_LIMIT(V_O_R_MAX_BATCH);

			vm_page_lockspin_queues();
		}
		if (reap_type == REAP_DATA_FLUSH || reap_type == REAP_TERMINATE) {

			if (p->busy || p->cleaning) {

				vm_page_unlock_queues();
				/*
				 * free the pages reclaimed so far
				 */
				VM_OBJ_REAP_FREELIST(local_free_q,
						     disconnect_on_release);

				PAGE_SLEEP(object, p, THREAD_UNINT);

				goto restart_after_sleep;
			}
			if (p->laundry) {
				p->pageout = FALSE;

				vm_pageout_steal_laundry(p, TRUE);
			}
		}
		switch (reap_type) {

		case REAP_DATA_FLUSH:
			if (VM_PAGE_WIRED(p)) {
				/*
				 * this is an odd case... perhaps we should
				 * zero-fill this page since we're conceptually
				 * tossing its data at this point, but leaving
				 * it on the object to honor the 'wire' contract
				 */
				continue;
			}
			break;
			
		case REAP_PURGEABLE:
			if (VM_PAGE_WIRED(p)) {
				/*
				 * can't purge a wired page
				 */
				vm_page_purged_wired++;
				continue;
			}
			if (p->laundry && !p->busy && !p->cleaning) {
				p->pageout = FALSE;

				vm_pageout_steal_laundry(p, TRUE);
			}
			if (p->cleaning || p->laundry || p->absent) {
				/*
				 * page is being acted upon,
				 * so don't mess with it
				 */
				vm_page_purged_others++;
				continue;
			}
			if (p->busy) {
				/*
				 * We can't reclaim a busy page but we can
				 * make it more likely to be paged (it's not wired) to make
				 * sure that it gets considered by
				 * vm_pageout_scan() later.
				 */
				vm_page_deactivate(p);
				vm_page_purged_busy++;
				continue;
			}

			assert(p->object != kernel_object);

			/*
			 * we can discard this page...
			 */
			if (p->pmapped == TRUE) {
				/*
				 * unmap the page
				 */
				pmap_disconnect_options(p->phys_page, PMAP_OPTIONS_NOFLUSH | PMAP_OPTIONS_NOREFMOD, (void *)&pmap_flush_context_storage);
			}
			vm_page_purged_count++;

			break;

		case REAP_TERMINATE:
			if (p->absent || p->private) {
				/*
				 *	For private pages, VM_PAGE_FREE just
				 *	leaves the page structure around for
				 *	its owner to clean up.  For absent
				 *	pages, the structure is returned to
				 *	the appropriate pool.
				 */
				break;
			}
			if (p->fictitious) {
				assert (p->phys_page == vm_page_guard_addr);
				break;
			}
			if (!p->dirty && p->wpmapped)
				p->dirty = pmap_is_modified(p->phys_page);

			if ((p->dirty || p->precious) && !p->error && object->alive) {

				if (!p->laundry) {
					VM_PAGE_QUEUES_REMOVE(p);
					/*
					 * flush page... page will be freed
					 * upon completion of I/O
					 */
					vm_pageout_cluster(p, TRUE);
				}
				vm_page_unlock_queues();
				/*
				 * free the pages reclaimed so far
				 */
				VM_OBJ_REAP_FREELIST(local_free_q,
						     disconnect_on_release);

				vm_object_paging_wait(object, THREAD_UNINT);

				goto restart_after_sleep;
			}
			break;

		case REAP_REAP:
			break;
		}
		vm_page_free_prepare_queues(p);
		assert(p->pageq.next == NULL && p->pageq.prev == NULL);
		/*
		 * Add this page to our list of reclaimed pages,
		 * to be freed later.
		 */
		p->pageq.next = (queue_entry_t) local_free_q;
		local_free_q = p;
	}
	vm_page_unlock_queues();

	/*
	 * Free the remaining reclaimed pages
	 */
	if (reap_type == REAP_PURGEABLE)
		pmap_flush(&pmap_flush_context_storage);

	VM_OBJ_REAP_FREELIST(local_free_q,
			     disconnect_on_release);
}


void
vm_object_reap_async(
	vm_object_t	object)
{
	vm_object_lock_assert_exclusive(object);

	vm_object_reaper_lock_spin();

	vm_object_reap_count_async++;

	/* enqueue the VM object... */
	queue_enter(&vm_object_reaper_queue, object,
		    vm_object_t, cached_list);

	vm_object_reaper_unlock();

	/* ... and wake up the reaper thread */
	thread_wakeup((event_t) &vm_object_reaper_queue);
}


void
vm_object_reaper_thread(void)
{
	vm_object_t	object, shadow_object;

	vm_object_reaper_lock_spin();

	while (!queue_empty(&vm_object_reaper_queue)) {
		queue_remove_first(&vm_object_reaper_queue,
				   object,
				   vm_object_t,
				   cached_list);

		vm_object_reaper_unlock();
		vm_object_lock(object);

		assert(object->terminating);
		assert(!object->alive);
		
		/*
		 * The pageout daemon might be playing with our pages.
		 * Now that the object is dead, it won't touch any more
		 * pages, but some pages might already be on their way out.
		 * Hence, we wait until the active paging activities have
		 * ceased before we break the association with the pager
		 * itself.
		 */
		while (object->paging_in_progress != 0 ||
			object->activity_in_progress != 0) {
			vm_object_wait(object,
				       VM_OBJECT_EVENT_PAGING_IN_PROGRESS,
				       THREAD_UNINT);
			vm_object_lock(object);
		}

		shadow_object =
			object->pageout ? VM_OBJECT_NULL : object->shadow;

		vm_object_reap(object);
		/* cache is unlocked and object is no longer valid */
		object = VM_OBJECT_NULL;

		if (shadow_object != VM_OBJECT_NULL) {
			/*
			 * Drop the reference "object" was holding on
			 * its shadow object.
			 */
			vm_object_deallocate(shadow_object);
			shadow_object = VM_OBJECT_NULL;
		}
		vm_object_reaper_lock_spin();
	}

	/* wait for more work... */
	assert_wait((event_t) &vm_object_reaper_queue, THREAD_UNINT);

	vm_object_reaper_unlock();

	thread_block((thread_continue_t) vm_object_reaper_thread);
	/*NOTREACHED*/
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
	lck_mtx_t		*lck;

	/*
	 *	If anyone was waiting for the memory_object_terminate
	 *	to be queued, wake them up now.
	 */
	lck = vm_object_hash_lock_spin(pager);
	entry = vm_object_hash_lookup(pager, TRUE);
	if (entry != VM_OBJECT_HASH_ENTRY_NULL)
		waiting = entry->waiting;
	vm_object_hash_unlock(lck);

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
	memory_object_t	pager,
	boolean_t	hashed)
{

	/*
	 *	Terminate the pager.
	 */

	(void) memory_object_terminate(pager);

	if (hashed == TRUE) {
		/*
		 *	Wakeup anyone waiting for this terminate
		 *      and remove the entry from the hash
		 */
		vm_object_pager_wakeup(pager);
	}
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

	vm_object_lock(object);
	object->can_persist = FALSE;
	object->named = FALSE;
	object->alive = FALSE;

	if (object->hashed) {
		lck_mtx_t	*lck;
		/*
		 *	Rip out the pager from the vm_object now...
		 */
		lck = vm_object_hash_lock_spin(object->pager);
		vm_object_remove(object);
		vm_object_hash_unlock(lck);
	}
	old_pager = object->pager;
	object->pager = MEMORY_OBJECT_NULL;
	if (old_pager != MEMORY_OBJECT_NULL)
		memory_object_control_disable(object->pager_control);

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
		vm_object_release_pager(old_pager, object->hashed);

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


#if VM_OBJECT_CACHE

#define VM_OBJ_DEACT_ALL_STATS DEBUG
#if VM_OBJ_DEACT_ALL_STATS
uint32_t vm_object_deactivate_all_pages_batches = 0;
uint32_t vm_object_deactivate_all_pages_pages = 0;
#endif /* VM_OBJ_DEACT_ALL_STATS */
/*
 *	vm_object_deactivate_all_pages
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
	int			loop_count;
#if VM_OBJ_DEACT_ALL_STATS
	int			pages_count;
#endif /* VM_OBJ_DEACT_ALL_STATS */
#define V_O_D_A_P_MAX_BATCH	256

	loop_count = BATCH_LIMIT(V_O_D_A_P_MAX_BATCH);
#if VM_OBJ_DEACT_ALL_STATS
	pages_count = 0;
#endif /* VM_OBJ_DEACT_ALL_STATS */
	vm_page_lock_queues();
	queue_iterate(&object->memq, p, vm_page_t, listq) {
		if (--loop_count == 0) {
#if VM_OBJ_DEACT_ALL_STATS
			hw_atomic_add(&vm_object_deactivate_all_pages_batches,
				      1);
			hw_atomic_add(&vm_object_deactivate_all_pages_pages,
				      pages_count);
			pages_count = 0;
#endif /* VM_OBJ_DEACT_ALL_STATS */
			lck_mtx_yield(&vm_page_queue_lock);
			loop_count = BATCH_LIMIT(V_O_D_A_P_MAX_BATCH);
		}
		if (!p->busy && !p->throttled) {
#if VM_OBJ_DEACT_ALL_STATS
			pages_count++;
#endif /* VM_OBJ_DEACT_ALL_STATS */
			vm_page_deactivate(p);
		}
	}
#if VM_OBJ_DEACT_ALL_STATS
	if (pages_count) {
		hw_atomic_add(&vm_object_deactivate_all_pages_batches, 1);
		hw_atomic_add(&vm_object_deactivate_all_pages_pages,
			      pages_count);
		pages_count = 0;
	}
#endif /* VM_OBJ_DEACT_ALL_STATS */
	vm_page_unlock_queues();
}
#endif	/* VM_OBJECT_CACHE */



/*
 * The "chunk" macros are used by routines below when looking for pages to deactivate.  These
 * exist because of the need to handle shadow chains.  When deactivating pages, we only
 * want to deactive the ones at the top most level in the object chain.  In order to do
 * this efficiently, the specified address range is divided up into "chunks" and we use
 * a bit map to keep track of which pages have already been processed as we descend down
 * the shadow chain.  These chunk macros hide the details of the bit map implementation
 * as much as we can.
 *
 * For convenience, we use a 64-bit data type as the bit map, and therefore a chunk is
 * set to 64 pages.  The bit map is indexed from the low-order end, so that the lowest
 * order bit represents page 0 in the current range and highest order bit represents
 * page 63.
 *
 * For further convenience, we also use negative logic for the page state in the bit map.
 * The bit is set to 1 to indicate it has not yet been seen, and to 0 to indicate it has
 * been processed.  This way we can simply test the 64-bit long word to see if it's zero
 * to easily tell if the whole range has been processed.  Therefore, the bit map starts
 * out with all the bits set.  The macros below hide all these details from the caller.
 */

#define PAGES_IN_A_CHUNK	64	/* The number of pages in the chunk must */
					/* be the same as the number of bits in  */
					/* the chunk_state_t type. We use 64     */
					/* just for convenience.		 */

#define CHUNK_SIZE	(PAGES_IN_A_CHUNK * PAGE_SIZE_64)	/* Size of a chunk in bytes */

typedef uint64_t	chunk_state_t;

/*
 * The bit map uses negative logic, so we start out with all 64 bits set to indicate
 * that no pages have been processed yet.  Also, if len is less than the full CHUNK_SIZE,
 * then we mark pages beyond the len as having been "processed" so that we don't waste time
 * looking at pages in that range.  This can save us from unnecessarily chasing down the 
 * shadow chain.
 */

#define CHUNK_INIT(c, len) 						\
	MACRO_BEGIN							\
	uint64_t p;							\
									\
	(c) = 0xffffffffffffffffLL; 					\
									\
	for (p = (len) / PAGE_SIZE_64; p < PAGES_IN_A_CHUNK; p++)	\
		MARK_PAGE_HANDLED(c, p);				\
	MACRO_END


/*
 * Return true if all pages in the chunk have not yet been processed.
 */

#define CHUNK_NOT_COMPLETE(c)	((c) != 0)

/*
 * Return true if the page at offset 'p' in the bit map has already been handled
 * while processing a higher level object in the shadow chain.
 */

#define PAGE_ALREADY_HANDLED(c, p)	(((c) & (1LL << (p))) == 0)

/*
 * Mark the page at offset 'p' in the bit map as having been processed.
 */

#define MARK_PAGE_HANDLED(c, p) \
MACRO_BEGIN \
	(c) = (c) & ~(1LL << (p)); \
MACRO_END


/*
 * Return true if the page at the given offset has been paged out.  Object is
 * locked upon entry and returned locked.
 */

static boolean_t
page_is_paged_out(
	vm_object_t		object,
	vm_object_offset_t	offset)
{
	kern_return_t	kr;
	memory_object_t	pager;

	/*
	 * Check the existence map for the page if we have one, otherwise
	 * ask the pager about this page.
	 */

#if MACH_PAGEMAP
	if (object->existence_map) {
		if (vm_external_state_get(object->existence_map, offset)
		    == VM_EXTERNAL_STATE_EXISTS) {
			/*
			 * We found the page
			 */

			return TRUE;
		}
	} else
#endif /* MACH_PAGEMAP */
	if (object->internal &&
	   object->alive &&
	   !object->terminating &&
	   object->pager_ready) {

		if (COMPRESSED_PAGER_IS_ACTIVE || DEFAULT_FREEZER_COMPRESSED_PAGER_IS_ACTIVE) {
			if (VM_COMPRESSOR_PAGER_STATE_GET(object, offset) 
			    == VM_EXTERNAL_STATE_EXISTS) {
				return TRUE;
			} else {
				return FALSE;
			}
		}

		/*
		 * We're already holding a "paging in progress" reference
		 * so the object can't disappear when we release the lock.
		 */

		assert(object->paging_in_progress);
		pager = object->pager;
		vm_object_unlock(object);

		kr = memory_object_data_request(
			pager,
			offset + object->paging_offset,
			0,	/* just poke the pager */
			VM_PROT_READ,
			NULL);

		vm_object_lock(object);

		if (kr == KERN_SUCCESS) {

			/*
			 * We found the page
			 */

			return TRUE;
		}
	}

	return FALSE;
}



/*
 * madvise_free_debug
 *
 * To help debug madvise(MADV_FREE*) mis-usage, this triggers a
 * zero-fill as soon as a page is affected by a madvise(MADV_FREE*), to
 * simulate the loss of the page's contents as if the page had been
 * reclaimed and then re-faulted.
 */
#if DEVELOPMENT || DEBUG
int madvise_free_debug = 1;
#else /* DEBUG */
int madvise_free_debug = 0;
#endif /* DEBUG */

/*
 * Deactivate the pages in the specified object and range.  If kill_page is set, also discard any
 * page modified state from the pmap.  Update the chunk_state as we go along.  The caller must specify
 * a size that is less than or equal to the CHUNK_SIZE.
 */

static void
deactivate_pages_in_object(
	vm_object_t		object,
	vm_object_offset_t	offset,
	vm_object_size_t	size,
	boolean_t               kill_page,
	boolean_t		reusable_page,
	boolean_t		all_reusable,
	chunk_state_t		*chunk_state,
	pmap_flush_context      *pfc)
{
	vm_page_t	m;
	int		p;
	struct vm_page_delayed_work	dw_array[DEFAULT_DELAYED_WORK_LIMIT];
	struct vm_page_delayed_work	*dwp;
	int		dw_count;
	int		dw_limit;
	unsigned int	reusable = 0;

	/*
	 * Examine each page in the chunk.  The variable 'p' is the page number relative to the start of the
	 * chunk.  Since this routine is called once for each level in the shadow chain, the chunk_state may
	 * have pages marked as having been processed already.  We stop the loop early if we find we've handled
	 * all the pages in the chunk.
	 */

	dwp = &dw_array[0];
	dw_count = 0;
	dw_limit = DELAYED_WORK_LIMIT(DEFAULT_DELAYED_WORK_LIMIT);

	for(p = 0; size && CHUNK_NOT_COMPLETE(*chunk_state); p++, size -= PAGE_SIZE_64, offset += PAGE_SIZE_64) {

		/*
		 * If this offset has already been found and handled in a higher level object, then don't
		 * do anything with it in the current shadow object.
		 */

		if (PAGE_ALREADY_HANDLED(*chunk_state, p))
			continue;
	
		/*
		 * See if the page at this offset is around.  First check to see if the page is resident,
		 * then if not, check the existence map or with the pager.
		 */

	        if ((m = vm_page_lookup(object, offset)) != VM_PAGE_NULL) {

			/*
			 * We found a page we were looking for.  Mark it as "handled" now in the chunk_state
			 * so that we won't bother looking for a page at this offset again if there are more
			 * shadow objects.  Then deactivate the page.
			 */

			MARK_PAGE_HANDLED(*chunk_state, p);
	
			if (( !VM_PAGE_WIRED(m)) && (!m->private) && (!m->gobbled) && (!m->busy) && (!m->laundry)) {
				int	clear_refmod;
				int	pmap_options;
	
				dwp->dw_mask = 0;

				pmap_options = 0;
				clear_refmod = VM_MEM_REFERENCED;
				dwp->dw_mask |= DW_clear_reference;

				if ((kill_page) && (object->internal)) {
					if (madvise_free_debug) {
						/*
						 * zero-fill the page now
						 * to simulate it being
						 * reclaimed and re-faulted.
						 */
						pmap_zero_page(m->phys_page);
					}
			        	m->precious = FALSE;
				        m->dirty = FALSE;

					clear_refmod |= VM_MEM_MODIFIED;
					if (m->throttled) {
						/*
						 * This page is now clean and
						 * reclaimable.  Move it out
						 * of the throttled queue, so
						 * that vm_pageout_scan() can
						 * find it.
						 */
						dwp->dw_mask |= DW_move_page;
					}
#if	MACH_PAGEMAP
					vm_external_state_clr(object->existence_map, offset);
#endif	/* MACH_PAGEMAP */
					VM_COMPRESSOR_PAGER_STATE_CLR(object,
								      offset);

					if (reusable_page && !m->reusable) {
						assert(!all_reusable);
						assert(!object->all_reusable);
						m->reusable = TRUE;
						object->reusable_page_count++;
						assert(object->resident_page_count >= object->reusable_page_count);
						reusable++;
						/*
						 * Tell pmap this page is now
						 * "reusable" (to update pmap
						 * stats for all mappings).
						 */
						pmap_options |=	PMAP_OPTIONS_SET_REUSABLE;
					}
				}
				pmap_options |= PMAP_OPTIONS_NOFLUSH;
				pmap_clear_refmod_options(m->phys_page,
							  clear_refmod,
							  pmap_options,
							  (void *)pfc);

				if (!m->throttled && !(reusable_page || all_reusable))
					dwp->dw_mask |= DW_move_page;
				
				if (dwp->dw_mask)
					VM_PAGE_ADD_DELAYED_WORK(dwp, m,
								 dw_count);

				if (dw_count >= dw_limit) {
					if (reusable) {
						OSAddAtomic(reusable,
							    &vm_page_stats_reusable.reusable_count);
						vm_page_stats_reusable.reusable += reusable;
						reusable = 0;
					}
					vm_page_do_delayed_work(object, &dw_array[0], dw_count);

					dwp = &dw_array[0];
					dw_count = 0;
				}
			}

		} else {

			/*
			 * The page at this offset isn't memory resident, check to see if it's
			 * been paged out.  If so, mark it as handled so we don't bother looking
			 * for it in the shadow chain.
			 */

			if (page_is_paged_out(object, offset)) {
				MARK_PAGE_HANDLED(*chunk_state, p);

				/*
				 * If we're killing a non-resident page, then clear the page in the existence 
				 * map so we don't bother paging it back in if it's touched again in the future.
				 */

				if ((kill_page) && (object->internal)) {
#if	MACH_PAGEMAP
					vm_external_state_clr(object->existence_map, offset);
#endif	/* MACH_PAGEMAP */
					VM_COMPRESSOR_PAGER_STATE_CLR(object,
								      offset);
				}
			}
		}
	}

	if (reusable) {
		OSAddAtomic(reusable, &vm_page_stats_reusable.reusable_count);
		vm_page_stats_reusable.reusable += reusable;	
		reusable = 0;
	}
		
	if (dw_count)
		vm_page_do_delayed_work(object, &dw_array[0], dw_count);
}


/*
 * Deactive a "chunk" of the given range of the object starting at offset.  A "chunk"
 * will always be less than or equal to the given size.  The total range is divided up
 * into chunks for efficiency and performance related to the locks and handling the shadow
 * chain.  This routine returns how much of the given "size" it actually processed.  It's
 * up to the caler to loop and keep calling this routine until the entire range they want
 * to process has been done.
 */

static vm_object_size_t
deactivate_a_chunk(
	vm_object_t		orig_object,
	vm_object_offset_t	offset,
	vm_object_size_t	size,
	boolean_t               kill_page,
	boolean_t		reusable_page,
	boolean_t		all_reusable,
	pmap_flush_context      *pfc)
{
	vm_object_t		object;
	vm_object_t		tmp_object;
	vm_object_size_t	length;
	chunk_state_t		chunk_state;


	/*
	 * Get set to do a chunk.  We'll do up to CHUNK_SIZE, but no more than the
	 * remaining size the caller asked for.
	 */

	length = MIN(size, CHUNK_SIZE);

	/*
	 * The chunk_state keeps track of which pages we've already processed if there's
	 * a shadow chain on this object.  At this point, we haven't done anything with this
	 * range of pages yet, so initialize the state to indicate no pages processed yet.
	 */

	CHUNK_INIT(chunk_state, length);
	object = orig_object;

	/*
	 * Start at the top level object and iterate around the loop once for each object
	 * in the shadow chain.  We stop processing early if we've already found all the pages
	 * in the range.  Otherwise we stop when we run out of shadow objects.
	 */

	while (object && CHUNK_NOT_COMPLETE(chunk_state)) {
		vm_object_paging_begin(object);

		deactivate_pages_in_object(object, offset, length, kill_page, reusable_page, all_reusable, &chunk_state, pfc);

		vm_object_paging_end(object);

		/*
		 * We've finished with this object, see if there's a shadow object.  If
		 * there is, update the offset and lock the new object.  We also turn off
		 * kill_page at this point since we only kill pages in the top most object.
		 */

		tmp_object = object->shadow;

		if (tmp_object) {
			kill_page = FALSE;
			reusable_page = FALSE;
			all_reusable = FALSE;
		        offset += object->vo_shadow_offset;
		        vm_object_lock(tmp_object);
		}

		if (object != orig_object)
		        vm_object_unlock(object);

		object = tmp_object;
	}

	if (object && object != orig_object)
	        vm_object_unlock(object);

	return length;
}



/*
 * Move any resident pages in the specified range to the inactive queue.  If kill_page is set,
 * we also clear the modified status of the page and "forget" any changes that have been made
 * to the page.
 */

__private_extern__ void
vm_object_deactivate_pages(
	vm_object_t		object,
	vm_object_offset_t	offset,
	vm_object_size_t	size,
	boolean_t               kill_page,
	boolean_t		reusable_page)
{
	vm_object_size_t	length;
	boolean_t		all_reusable;
	pmap_flush_context	pmap_flush_context_storage;

	/*
	 * We break the range up into chunks and do one chunk at a time.  This is for
	 * efficiency and performance while handling the shadow chains and the locks.	
	 * The deactivate_a_chunk() function returns how much of the range it processed.
	 * We keep calling this routine until the given size is exhausted.
	 */


	all_reusable = FALSE;
#if 11
	/*
	 * For the sake of accurate "reusable" pmap stats, we need 
	 * to tell pmap about each page that is no longer "reusable",
	 * so we can't do the "all_reusable" optimization.
	 */
#else
	if (reusable_page &&
	    object->internal &&
	    object->vo_size != 0 &&
	    object->vo_size == size &&
	    object->reusable_page_count == 0) {
		all_reusable = TRUE;
		reusable_page = FALSE;
	}
#endif

	if ((reusable_page || all_reusable) && object->all_reusable) {
		/* This means MADV_FREE_REUSABLE has been called twice, which 
		 * is probably illegal. */
		return;
	}

	pmap_flush_context_init(&pmap_flush_context_storage);

	while (size) {
		length = deactivate_a_chunk(object, offset, size, kill_page, reusable_page, all_reusable, &pmap_flush_context_storage);

		size -= length;
		offset += length;
	}
	pmap_flush(&pmap_flush_context_storage);

	if (all_reusable) {
		if (!object->all_reusable) {
			unsigned int reusable;

			object->all_reusable = TRUE;
			assert(object->reusable_page_count == 0);
			/* update global stats */
			reusable = object->resident_page_count;
			OSAddAtomic(reusable,
				    &vm_page_stats_reusable.reusable_count);
			vm_page_stats_reusable.reusable += reusable;
			vm_page_stats_reusable.all_reusable_calls++;
		}
	} else if (reusable_page) {
		vm_page_stats_reusable.partial_reusable_calls++;
	}
}

void
vm_object_reuse_pages(
	vm_object_t		object,
	vm_object_offset_t	start_offset,
	vm_object_offset_t	end_offset,
	boolean_t		allow_partial_reuse)
{
	vm_object_offset_t	cur_offset;
	vm_page_t		m;
	unsigned int		reused, reusable;

#define VM_OBJECT_REUSE_PAGE(object, m, reused)				\
	MACRO_BEGIN							\
		if ((m) != VM_PAGE_NULL &&				\
		    (m)->reusable) {					\
			assert((object)->reusable_page_count <=		\
			       (object)->resident_page_count);		\
			assert((object)->reusable_page_count > 0);	\
			(object)->reusable_page_count--;		\
			(m)->reusable = FALSE;				\
			(reused)++;					\
			/*						\
			 * Tell pmap that this page is no longer	\
			 * "reusable", to update the "reusable" stats	\
			 * for all the pmaps that have mapped this	\
			 * page.					\
			 */						\
			pmap_clear_refmod_options((m)->phys_page,	\
						  0, /* refmod */	\
						  (PMAP_OPTIONS_CLEAR_REUSABLE \
						   | PMAP_OPTIONS_NOFLUSH), \
						  NULL);		\
		}							\
	MACRO_END

	reused = 0;
	reusable = 0;

	vm_object_lock_assert_exclusive(object);

	if (object->all_reusable) {
		panic("object %p all_reusable: can't update pmap stats\n",
		      object);
		assert(object->reusable_page_count == 0);
		object->all_reusable = FALSE;
		if (end_offset - start_offset == object->vo_size ||
		    !allow_partial_reuse) {
			vm_page_stats_reusable.all_reuse_calls++;
			reused = object->resident_page_count;
		} else {
			vm_page_stats_reusable.partial_reuse_calls++;
			queue_iterate(&object->memq, m, vm_page_t, listq) {
				if (m->offset < start_offset ||
				    m->offset >= end_offset) {
					m->reusable = TRUE;
					object->reusable_page_count++;
					assert(object->resident_page_count >= object->reusable_page_count);
					continue;
				} else {
					assert(!m->reusable);
					reused++;
				}
			}
		}
	} else if (object->resident_page_count >
		   ((end_offset - start_offset) >> PAGE_SHIFT)) {
		vm_page_stats_reusable.partial_reuse_calls++;
		for (cur_offset = start_offset;
		     cur_offset < end_offset;
		     cur_offset += PAGE_SIZE_64) {
			if (object->reusable_page_count == 0) {
				break;
			}
			m = vm_page_lookup(object, cur_offset);
			VM_OBJECT_REUSE_PAGE(object, m, reused);
		}
	} else {
		vm_page_stats_reusable.partial_reuse_calls++;
		queue_iterate(&object->memq, m, vm_page_t, listq) {
			if (object->reusable_page_count == 0) {
				break;
			}
			if (m->offset < start_offset ||
			    m->offset >= end_offset) {
				continue;
			}
			VM_OBJECT_REUSE_PAGE(object, m, reused);
		}
	}

	/* update global stats */
	OSAddAtomic(reusable-reused, &vm_page_stats_reusable.reusable_count);
	vm_page_stats_reusable.reused += reused;
	vm_page_stats_reusable.reusable += reusable;
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
	vm_object_pmap_protect_options(object, offset, size,
				       pmap, pmap_start, prot, 0);
}

__private_extern__ void
vm_object_pmap_protect_options(
	register vm_object_t		object,
	register vm_object_offset_t	offset,
	vm_object_size_t		size,
	pmap_t				pmap,
	vm_map_offset_t			pmap_start,
	vm_prot_t			prot,
	int				options)
{
	pmap_flush_context	pmap_flush_context_storage;
	boolean_t		delayed_pmap_flush = FALSE;

	if (object == VM_OBJECT_NULL)
		return;
	size = vm_object_round_page(size);
	offset = vm_object_trunc_page(offset);

	vm_object_lock(object);

	if (object->phys_contiguous) {
		if (pmap != NULL) {
			vm_object_unlock(object);
			pmap_protect_options(pmap,
					     pmap_start,
					     pmap_start + size,
					     prot,
					     options & ~PMAP_OPTIONS_NOFLUSH,
					     NULL);
		} else {
			vm_object_offset_t phys_start, phys_end, phys_addr;

			phys_start = object->vo_shadow_offset + offset;
			phys_end = phys_start + size;
			assert(phys_start <= phys_end);
			assert(phys_end <= object->vo_shadow_offset + object->vo_size);
			vm_object_unlock(object);

			pmap_flush_context_init(&pmap_flush_context_storage);
			delayed_pmap_flush = FALSE;

			for (phys_addr = phys_start;
			     phys_addr < phys_end;
			     phys_addr += PAGE_SIZE_64) {
				pmap_page_protect_options(
					(ppnum_t) (phys_addr >> PAGE_SHIFT),
					prot,
					options | PMAP_OPTIONS_NOFLUSH,
					(void *)&pmap_flush_context_storage);
				delayed_pmap_flush = TRUE;
			}
			if (delayed_pmap_flush == TRUE)
				pmap_flush(&pmap_flush_context_storage);
		}
		return;
	}

	assert(object->internal);

	while (TRUE) {
	   if (ptoa_64(object->resident_page_count) > size/2 && pmap != PMAP_NULL) {
		vm_object_unlock(object);
		pmap_protect_options(pmap, pmap_start, pmap_start + size, prot,
				     options & ~PMAP_OPTIONS_NOFLUSH, NULL);
		return;
	    }

	   pmap_flush_context_init(&pmap_flush_context_storage);
	   delayed_pmap_flush = FALSE;

	    /*
	     * if we are doing large ranges with respect to resident
	     * page count then we should interate over pages otherwise
	     * inverse page look-up will be faster
	     */
	    if (ptoa_64(object->resident_page_count / 4) <  size) {
		vm_page_t		p;
		vm_object_offset_t	end;

		end = offset + size;

		queue_iterate(&object->memq, p, vm_page_t, listq) {
			if (!p->fictitious && (offset <= p->offset) && (p->offset < end)) {
				vm_map_offset_t start;

				start = pmap_start + p->offset - offset;

				if (pmap != PMAP_NULL)
					pmap_protect_options(
						pmap,
						start,
						start + PAGE_SIZE_64,
						prot,
						options | PMAP_OPTIONS_NOFLUSH,
						&pmap_flush_context_storage);
				else
					pmap_page_protect_options(
						p->phys_page,
						prot,
						options | PMAP_OPTIONS_NOFLUSH,
						&pmap_flush_context_storage);
					delayed_pmap_flush = TRUE;
			}
		}

	   } else {
		vm_page_t		p;
		vm_object_offset_t	end;
		vm_object_offset_t	target_off;

		end = offset + size;

		for (target_off = offset; 
		     target_off < end; target_off += PAGE_SIZE) {

			p = vm_page_lookup(object, target_off);

			if (p != VM_PAGE_NULL) {
				vm_object_offset_t start;

				start = pmap_start + (p->offset - offset);

				if (pmap != PMAP_NULL)
					pmap_protect_options(
						pmap,
						start,
						start + PAGE_SIZE_64,
						prot,
						options | PMAP_OPTIONS_NOFLUSH,
						&pmap_flush_context_storage);
				else
					pmap_page_protect_options(
						p->phys_page,
						prot,
						options | PMAP_OPTIONS_NOFLUSH,
						&pmap_flush_context_storage);
					delayed_pmap_flush = TRUE;
		    	}
		}
	    }
	    if (delayed_pmap_flush == TRUE)
		    pmap_flush(&pmap_flush_context_storage);

	    if (prot == VM_PROT_NONE) {
		/*
		 * Must follow shadow chain to remove access
		 * to pages in shadowed objects.
		 */
		register vm_object_t	next_object;

		next_object = object->shadow;
		if (next_object != VM_OBJECT_NULL) {
		    offset += object->vo_shadow_offset;
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

	struct vm_object_fault_info fault_info;

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

	vm_object_reference_locked(src_object);
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

	assert(size == trunc_page_64(size));	/* Will the loop terminate? */

	fault_info.interruptible = interruptible;
	fault_info.behavior  = VM_BEHAVIOR_SEQUENTIAL;
	fault_info.user_tag = 0;
	fault_info.pmap_options = 0;
	fault_info.lo_offset = src_offset;
	fault_info.hi_offset = src_offset + size;
	fault_info.no_cache  = FALSE;
	fault_info.stealth = TRUE;
	fault_info.io_sync = FALSE;
	fault_info.cs_bypass = FALSE;
	fault_info.mark_zf_absent = FALSE;
	fault_info.batch_pmap_op = FALSE;

	for ( ;
	    size != 0 ;
	    src_offset += PAGE_SIZE_64, 
			new_offset += PAGE_SIZE_64, size -= PAGE_SIZE_64
	    ) {
		vm_page_t	new_page;
		vm_fault_return_t result;

		vm_object_lock(new_object);

		while ((new_page = vm_page_alloc(new_object, new_offset))
				== VM_PAGE_NULL) {

			vm_object_unlock(new_object);

			if (!vm_page_wait(interruptible)) {
				vm_object_deallocate(new_object);
				vm_object_deallocate(src_object);
				*_result_object = VM_OBJECT_NULL;
				return(MACH_SEND_INTERRUPTED);
			}
			vm_object_lock(new_object);
		}
		vm_object_unlock(new_object);

		do {
			vm_prot_t	prot = VM_PROT_READ;
			vm_page_t	_result_page;
			vm_page_t	top_page;
			register
			vm_page_t	result_page;
			kern_return_t	error_code;

			vm_object_lock(src_object);
			vm_object_paging_begin(src_object);

			if (size > (vm_size_t) -1) {
				/* 32-bit overflow */
				fault_info.cluster_size = (vm_size_t) (0 - PAGE_SIZE);
			} else {
				fault_info.cluster_size = (vm_size_t) size;
				assert(fault_info.cluster_size == size);
			}

			XPR(XPR_VM_FAULT,"vm_object_copy_slowly -> vm_fault_page",0,0,0,0,0);
			_result_page = VM_PAGE_NULL;
			result = vm_fault_page(src_object, src_offset,
				VM_PROT_READ, FALSE,
				FALSE, /* page not looked up */
				&prot, &_result_page, &top_page,
			        (int *)0,
				&error_code, FALSE, FALSE, &fault_info);

			switch(result) {
			case VM_FAULT_SUCCESS:
				result_page = _result_page;

				/*
				 *	Copy the page to the new object.
				 *
				 *	POLICY DECISION:
				 *		If result_page is clean,
				 *		we could steal it instead
				 *		of copying.
				 */

				vm_page_copy(result_page, new_page);
				vm_object_unlock(result_page->object);

				/*
				 *	Let go of both pages (make them
				 *	not busy, perform wakeup, activate).
				 */
				vm_object_lock(new_object);
				SET_PAGE_DIRTY(new_page, FALSE);
				PAGE_WAKEUP_DONE(new_page);
				vm_object_unlock(new_object);

				vm_object_lock(result_page->object);
				PAGE_WAKEUP_DONE(result_page);

				vm_page_lockspin_queues();
				if (!result_page->active &&
				    !result_page->inactive &&
				    !result_page->throttled)
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

			case VM_FAULT_MEMORY_SHORTAGE:
				if (vm_page_wait(interruptible))
					break;
				/* fall thru */

			case VM_FAULT_INTERRUPTED:
				vm_object_lock(new_object);
				VM_PAGE_FREE(new_page);
				vm_object_unlock(new_object);
					
				vm_object_deallocate(new_object);
				vm_object_deallocate(src_object);
				*_result_object = VM_OBJECT_NULL;
				return(MACH_SEND_INTERRUPTED);

			case VM_FAULT_SUCCESS_NO_VM_PAGE:
				/* success but no VM page: fail */
				vm_object_paging_end(src_object);
				vm_object_unlock(src_object);
				/*FALLTHROUGH*/
			case VM_FAULT_MEMORY_ERROR:
				/*
				 * A policy choice:
				 *	(a) ignore pages that we can't
				 *	    copy
				 *	(b) return the null object if
				 *	    any page fails [chosen]
				 */

				vm_object_lock(new_object);
				VM_PAGE_FREE(new_page);
				vm_object_unlock(new_object);

				vm_object_deallocate(new_object);
				vm_object_deallocate(src_object);
				*_result_object = VM_OBJECT_NULL;
				return(error_code ? error_code:
				       KERN_MEMORY_ERROR);

			default:
				panic("vm_object_copy_slowly: unexpected error"
				      " 0x%x from vm_fault_page()\n", result);
			}
		} while (result != VM_FAULT_SUCCESS);
	}

	/*
	 *	Lose the extra reference, and return our object.
	 */
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

		vm_object_reference_locked(object);
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
	uint32_t	try_failed_count = 0;

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

		try_failed_count++;
		mutex_pause(try_failed_count);	/* wait a bit */

		vm_object_lock(src_object);
		goto Retry;
	}
	if (copy->vo_size < src_offset+size)
		copy->vo_size = src_offset+size;

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
	vm_object_size_t	size,
	boolean_t		src_object_shared)
{
	vm_object_t		new_copy = VM_OBJECT_NULL;
	vm_object_t		old_copy;
	vm_page_t		p;
	vm_object_size_t	copy_size = src_offset + size;
	pmap_flush_context	pmap_flush_context_storage;
	boolean_t		delayed_pmap_flush = FALSE;


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
	if (!src_object->true_share &&
	    (src_object->paging_in_progress != 0 ||
	     src_object->activity_in_progress != 0)) {
	        if (src_object_shared == TRUE) {
		        vm_object_unlock(src_object);
			vm_object_lock(src_object);
			src_object_shared = FALSE;
			goto Retry;
		}
		vm_object_paging_wait(src_object, THREAD_UNINT);
	}
	/*
	 *	See whether we can reuse the result of a previous
	 *	copy operation.
	 */

	old_copy = src_object->copy;
	if (old_copy != VM_OBJECT_NULL) {
	        int lock_granted;

		/*
		 *	Try to get the locks (out of order)
		 */
		if (src_object_shared == TRUE)
		        lock_granted = vm_object_lock_try_shared(old_copy);
		else
		        lock_granted = vm_object_lock_try(old_copy);

		if (!lock_granted) {
			vm_object_unlock(src_object);

			if (collisions++ == 0)
				copy_delayed_lock_contention++;
			mutex_pause(collisions);

			/* Heisenberg Rules */
			copy_delayed_lock_collisions++;

			if (collisions > copy_delayed_max_collisions)
				copy_delayed_max_collisions = collisions;

			if (src_object_shared == TRUE)
			        vm_object_lock_shared(src_object);
			else
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

			if (old_copy->vo_size < copy_size) {
			        if (src_object_shared == TRUE) {
				        vm_object_unlock(old_copy);
					vm_object_unlock(src_object);
				
					vm_object_lock(src_object);
					src_object_shared = FALSE;
					goto Retry;
				}
				/*
				 * We can't perform a delayed copy if any of the
				 * pages in the extended range are wired (because
				 * we can't safely take write permission away from
				 * wired pages).  If the pages aren't wired, then
				 * go ahead and protect them.
				 */
				copy_delayed_protect_iterate++;

				pmap_flush_context_init(&pmap_flush_context_storage);
				delayed_pmap_flush = FALSE;

				queue_iterate(&src_object->memq, p, vm_page_t, listq) {
					if (!p->fictitious && 
					    p->offset >= old_copy->vo_size && 
					    p->offset < copy_size) {
						if (VM_PAGE_WIRED(p)) {
							vm_object_unlock(old_copy);
							vm_object_unlock(src_object);

							if (new_copy != VM_OBJECT_NULL) {
								vm_object_unlock(new_copy);
								vm_object_deallocate(new_copy);
							}
							if (delayed_pmap_flush == TRUE)
								pmap_flush(&pmap_flush_context_storage);

							return VM_OBJECT_NULL;
						} else {
							pmap_page_protect_options(p->phys_page, (VM_PROT_ALL & ~VM_PROT_WRITE),
										  PMAP_OPTIONS_NOFLUSH, (void *)&pmap_flush_context_storage);
							delayed_pmap_flush = TRUE;
						}
					}
				}
				if (delayed_pmap_flush == TRUE)
					pmap_flush(&pmap_flush_context_storage);

				old_copy->vo_size = copy_size;
			}
			if (src_object_shared == TRUE)
			        vm_object_reference_shared(old_copy);
			else
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
		if (old_copy->vo_size > copy_size)
			copy_size = old_copy->vo_size;

		if (new_copy == VM_OBJECT_NULL) {
			vm_object_unlock(old_copy);
			vm_object_unlock(src_object);
			new_copy = vm_object_allocate(copy_size);
			vm_object_lock(src_object);
			vm_object_lock(new_copy);

			src_object_shared = FALSE;
			goto Retry;
		}
		new_copy->vo_size = copy_size;	

		/*
		 *	The copy-object is always made large enough to
		 *	completely shadow the original object, since
		 *	it may have several users who want to shadow
		 *	the original object at different points.
		 */

		assert((old_copy->shadow == src_object) &&
		    (old_copy->vo_shadow_offset == (vm_object_offset_t) 0));

	} else if (new_copy == VM_OBJECT_NULL) {
		vm_object_unlock(src_object);
		new_copy = vm_object_allocate(copy_size);
		vm_object_lock(src_object);
		vm_object_lock(new_copy);

		src_object_shared = FALSE;
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

	pmap_flush_context_init(&pmap_flush_context_storage);
	delayed_pmap_flush = FALSE;

	queue_iterate(&src_object->memq, p, vm_page_t, listq) {
		if (!p->fictitious && p->offset < copy_size) {
			if (VM_PAGE_WIRED(p)) {
				if (old_copy)
					vm_object_unlock(old_copy);
				vm_object_unlock(src_object);
				vm_object_unlock(new_copy);
				vm_object_deallocate(new_copy);

				if (delayed_pmap_flush == TRUE)
					pmap_flush(&pmap_flush_context_storage);

				return VM_OBJECT_NULL;
			} else {
				pmap_page_protect_options(p->phys_page, (VM_PROT_ALL & ~VM_PROT_WRITE),
							  PMAP_OPTIONS_NOFLUSH, (void *)&pmap_flush_context_storage);
				delayed_pmap_flush = TRUE;
			}
		}
	}
	if (delayed_pmap_flush == TRUE)
		pmap_flush(&pmap_flush_context_storage);

	if (old_copy != VM_OBJECT_NULL) {
		/*
		 *	Make the old copy-object shadow the new one.
		 *	It will receive no more pages from the original
		 *	object.
		 */

		/* remove ref. from old_copy */
		vm_object_lock_assert_exclusive(src_object);
		src_object->ref_count--;
		assert(src_object->ref_count > 0);
		vm_object_lock_assert_exclusive(old_copy);
		old_copy->shadow = new_copy;
		vm_object_lock_assert_exclusive(new_copy);
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
	vm_object_lock_assert_exclusive(new_copy);
	new_copy->shadow = src_object;
	new_copy->vo_shadow_offset = 0;
	new_copy->shadowed = TRUE;	/* caller must set needs_copy */

	vm_object_lock_assert_exclusive(src_object);
	vm_object_reference_locked(src_object);
	src_object->copy = new_copy;
	vm_object_unlock(src_object);
	vm_object_unlock(new_copy);

	XPR(XPR_VM_OBJECT,
		"vm_object_copy_delayed: used copy object %X for source %X\n",
		new_copy, src_object, 0, 0, 0);

	return new_copy;
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
	boolean_t	object_lock_shared = FALSE;
	memory_object_copy_strategy_t copy_strategy;

	assert(src_object != VM_OBJECT_NULL);

	copy_strategy = src_object->copy_strategy;

	if (copy_strategy == MEMORY_OBJECT_COPY_DELAY) {
	        vm_object_lock_shared(src_object);
		object_lock_shared = TRUE;
	} else
	        vm_object_lock(src_object);

	/*
	 *	The copy strategy is only valid if the memory manager
	 *	is "ready". Internal objects are always ready.
	 */

	while (!src_object->internal && !src_object->pager_ready) {
		wait_result_t wait_result;

		if (object_lock_shared == TRUE) {
		        vm_object_unlock(src_object);
			vm_object_lock(src_object);
			object_lock_shared = FALSE;
			continue;
		}
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

	/*
	 *	Use the appropriate copy strategy.
	 */

	switch (copy_strategy) {
	    case MEMORY_OBJECT_COPY_DELAY:
		*dst_object = vm_object_copy_delayed(src_object,
						     src_offset, size, object_lock_shared);
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
		XPR(XPR_VM_OBJECT, "v_o_c_strategically obj 0x%x off 0x%x size 0x%x\n", src_object, src_offset, size, 0, 0);
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
boolean_t vm_object_shadow_check = TRUE;

__private_extern__ boolean_t
vm_object_shadow(
	vm_object_t		*object,	/* IN/OUT */
	vm_object_offset_t	*offset,	/* IN/OUT */
	vm_object_size_t	length)
{
	register vm_object_t	source;
	register vm_object_t	result;

	source = *object;
	assert(source != VM_OBJECT_NULL);
	if (source == VM_OBJECT_NULL)
		return FALSE;

#if 0
	/*
	 * XXX FBDP
	 * This assertion is valid but it gets triggered by Rosetta for example
	 * due to a combination of vm_remap() that changes a VM object's
	 * copy_strategy from SYMMETRIC to DELAY and vm_protect(VM_PROT_COPY)
	 * that then sets "needs_copy" on its map entry.  This creates a
	 * mapping situation that VM should never see and doesn't know how to
	 * handle.
	 * It's not clear if this can create any real problem but we should
	 * look into fixing this, probably by having vm_protect(VM_PROT_COPY)
	 * do more than just set "needs_copy" to handle the copy-on-write...
	 * In the meantime, let's disable the assertion.
	 */
	assert(source->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC);
#endif

	/*
	 *	Determine if we really need a shadow.
	 *
	 *	If the source object is larger than what we are trying
	 *	to create, then force the shadow creation even if the
	 *	ref count is 1.  This will allow us to [potentially]
	 *	collapse the underlying object away in the future
	 *	(freeing up the extra data it might contain and that
	 *	we don't need).
	 */
	if (vm_object_shadow_check &&
	    source->vo_size == length &&
	    source->ref_count == 1 &&
	    (source->shadow == VM_OBJECT_NULL ||
	     source->shadow->copy == VM_OBJECT_NULL) )
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

	result->vo_shadow_offset = *offset;

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
 *	In addition to the lock on the object, the vm_object_hash_lock
 *	governs the associations.  References gained through the
 *	association require use of the hash lock.
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
	uint32_t        try_failed_count = 0;
	lck_mtx_t	*lck;

	if (pager == MEMORY_OBJECT_NULL)
		return(vm_object_allocate(size));

	new_object = VM_OBJECT_NULL;
	new_entry = VM_OBJECT_HASH_ENTRY_NULL;
	must_init = init;

	/*
	 *	Look for an object associated with this port.
	 */
Retry:
	lck = vm_object_hash_lock_spin(pager);
	do {
		entry = vm_object_hash_lookup(pager, FALSE);

		if (entry == VM_OBJECT_HASH_ENTRY_NULL) {
			if (new_object == VM_OBJECT_NULL) {
				/*
				 *	We must unlock to create a new object;
				 *	if we do so, we must try the lookup again.
				 */
				vm_object_hash_unlock(lck);
				assert(new_entry == VM_OBJECT_HASH_ENTRY_NULL);
				new_entry = vm_object_hash_entry_alloc(pager);
				new_object = vm_object_allocate(size);
				lck = vm_object_hash_lock_spin(pager);
			} else {
				/*
				 *	Lookup failed twice, and we have something
				 *	to insert; set the object.
				 */
				vm_object_lock(new_object);
				vm_object_hash_insert(new_entry, new_object);
				vm_object_unlock(new_object);
				entry = new_entry;
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
			vm_object_hash_unlock(lck);

			thread_block(THREAD_CONTINUE_NULL);
			lck = vm_object_hash_lock_spin(pager);
		}
	} while (entry == VM_OBJECT_HASH_ENTRY_NULL);

	object = entry->object;
	assert(object != VM_OBJECT_NULL);

	if (!must_init) {
	        if ( !vm_object_lock_try(object)) {

		        vm_object_hash_unlock(lck);

		        try_failed_count++;
			mutex_pause(try_failed_count);  /* wait a bit */
			goto Retry;
		}
		assert(!internal || object->internal);
#if VM_OBJECT_CACHE
		if (object->ref_count == 0) {
			if ( !vm_object_cache_lock_try()) {

				vm_object_hash_unlock(lck);
				vm_object_unlock(object);

				try_failed_count++;
				mutex_pause(try_failed_count);  /* wait a bit */
				goto Retry;
			}
			XPR(XPR_VM_OBJECT_CACHE,
			    "vm_object_enter: removing %x from cache, head (%x, %x)\n",
				object,
				vm_object_cached_list.next,
				vm_object_cached_list.prev, 0,0);
			queue_remove(&vm_object_cached_list, object,
				     vm_object_t, cached_list);
			vm_object_cached_count--;

			vm_object_cache_unlock();
		}
#endif
		if (named) {
			assert(!object->named);
			object->named = TRUE;
		}
		vm_object_lock_assert_exclusive(object);
		object->ref_count++;
		vm_object_res_reference(object);

		vm_object_hash_unlock(lck);
		vm_object_unlock(object);

		VM_STAT_INCR(hits);
	} else
		vm_object_hash_unlock(lck);

	assert(object->ref_count > 0);

	VM_STAT_INCR(lookups);

	XPR(XPR_VM_OBJECT,
		"vm_o_enter: pager 0x%x obj 0x%x must_init %d\n",
		pager, object, must_init, 0, 0);

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
	    object, object->pager, internal, 0,0);
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
	lck_mtx_t		*lck;
#if	MACH_PAGEMAP
	vm_object_size_t	size;
	vm_external_map_t	map;
#endif	/* MACH_PAGEMAP */

	XPR(XPR_VM_OBJECT, "vm_object_pager_create, object 0x%X\n",
		object, 0,0,0,0);

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
	size = object->vo_size;
#endif	/* MACH_PAGEMAP */
	vm_object_unlock(object);

#if	MACH_PAGEMAP
	if (DEFAULT_PAGER_IS_ACTIVE) {
		map = vm_external_create(size);
		vm_object_lock(object);
		assert(object->vo_size == size);
		object->existence_map = map;
		vm_object_unlock(object);
	}
#endif	/* MACH_PAGEMAP */

	if ((uint32_t) object->vo_size != object->vo_size) {
		panic("vm_object_pager_create(): object size 0x%llx >= 4GB\n",
		      (uint64_t) object->vo_size);
	}

	/*
	 *	Create the [internal] pager, and associate it with this object.
	 *
	 *	We make the association here so that vm_object_enter()
	 * 	can look up the object to complete initializing it.  No
	 *	user will ever map this object.
	 */
	{
		memory_object_default_t		dmm;

		/* acquire a reference for the default memory manager */
		dmm = memory_manager_default_reference();

		assert(object->temporary);

		/* create our new memory object */
		assert((vm_size_t) object->vo_size == object->vo_size);
		(void) memory_object_create(dmm, (vm_size_t) object->vo_size,
					    &pager);

		memory_object_default_deallocate(dmm);
       }

	entry = vm_object_hash_entry_alloc(pager);

	vm_object_lock(object);
	lck = vm_object_hash_lock_spin(pager);
	vm_object_hash_insert(entry, object);
	vm_object_hash_unlock(lck);
	vm_object_unlock(object);

	/*
	 *	A reference was returned by
	 *	memory_object_create(), and it is
	 *	copied by vm_object_enter().
	 */

	if (vm_object_enter(pager, object->vo_size, TRUE, TRUE, FALSE) != object)
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

void
vm_object_compressor_pager_create(
	register vm_object_t	object)
{
	memory_object_t		pager;
	vm_object_hash_entry_t	entry;
	lck_mtx_t		*lck;
	vm_object_t		pager_object = VM_OBJECT_NULL;

	assert(object != kernel_object);

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
		
	vm_object_unlock(object);

	if ((uint32_t) (object->vo_size/PAGE_SIZE) !=
	    (object->vo_size/PAGE_SIZE)) {
		panic("vm_object_compressor_pager_create(%p): "
		      "object size 0x%llx >= 0x%llx\n",
		      object,
		      (uint64_t) object->vo_size,
		      0x0FFFFFFFFULL*PAGE_SIZE);
	}

	/*
	 *	Create the [internal] pager, and associate it with this object.
	 *
	 *	We make the association here so that vm_object_enter()
	 * 	can look up the object to complete initializing it.  No
	 *	user will ever map this object.
	 */
	{
		assert(object->temporary);

		/* create our new memory object */
		assert((uint32_t) (object->vo_size/PAGE_SIZE) ==
		       (object->vo_size/PAGE_SIZE));
		(void) compressor_memory_object_create(
			(memory_object_size_t) object->vo_size,
			&pager);
		if (pager == NULL) {
			panic("vm_object_compressor_pager_create(): "
			      "no pager for object %p size 0x%llx\n",
			      object, (uint64_t) object->vo_size);
		}
       }

	entry = vm_object_hash_entry_alloc(pager);

	vm_object_lock(object);
	lck = vm_object_hash_lock_spin(pager);
	vm_object_hash_insert(entry, object);
	vm_object_hash_unlock(lck);
	vm_object_unlock(object);

	/*
	 *	A reference was returned by
	 *	memory_object_create(), and it is
	 *	copied by vm_object_enter().
	 */

	pager_object = vm_object_enter(pager, object->vo_size, TRUE, TRUE, FALSE);

	if (pager_object != object) {
		panic("vm_object_compressor_pager_create: mismatch (pager: %p, pager_object: %p, orig_object: %p, orig_object size: 0x%llx)\n", pager, pager_object, object, (uint64_t) object->vo_size);
	}

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

#if MACH_PAGEMAP
static int	vm_external_discarded;
static int	vm_external_collapsed;
#endif

unsigned long vm_object_collapse_encrypted = 0;

void vm_object_do_collapse_compressor(vm_object_t object,
				      vm_object_t backing_object);
void
vm_object_do_collapse_compressor(
	vm_object_t object,
	vm_object_t backing_object)
{
	vm_object_offset_t new_offset, backing_offset;
	vm_object_size_t size;

	vm_counters.do_collapse_compressor++;

	vm_object_lock_assert_exclusive(object);
	vm_object_lock_assert_exclusive(backing_object);

	size = object->vo_size;

	/*
	 *	Move all compressed pages from backing_object
	 *	to the parent.
	 */

	for (backing_offset = object->vo_shadow_offset;
	     backing_offset < object->vo_shadow_offset + object->vo_size;
	     backing_offset += PAGE_SIZE) {
		memory_object_offset_t backing_pager_offset;

		/* find the next compressed page at or after this offset */
		backing_pager_offset = (backing_offset +
					backing_object->paging_offset);
		backing_pager_offset = vm_compressor_pager_next_compressed(
			backing_object->pager,
			backing_pager_offset);
		if (backing_pager_offset == (memory_object_offset_t) -1) {
			/* no more compressed pages */
			break;
		}
		backing_offset = (backing_pager_offset -
				  backing_object->paging_offset);

		new_offset = backing_offset - object->vo_shadow_offset;

		if (new_offset >= object->vo_size) {
			/* we're out of the scope of "object": done */
			break;
		}

		if ((vm_page_lookup(object, new_offset) != VM_PAGE_NULL) ||
		    (vm_compressor_pager_state_get(object->pager,
						   (new_offset +
						    object->paging_offset)) ==
		     VM_EXTERNAL_STATE_EXISTS)) {
			/*
			 * This page already exists in object, resident or
			 * compressed.
			 * We don't need this compressed page in backing_object
			 * and it will be reclaimed when we release
			 * backing_object.
			 */
			continue;
		}

		/*
		 * backing_object has this page in the VM compressor and
		 * we need to transfer it to object.
		 */
		vm_counters.do_collapse_compressor_pages++;
		vm_compressor_pager_transfer(
			/* destination: */
			object->pager,
			(new_offset + object->paging_offset),
			/* source: */
			backing_object->pager,
			(backing_offset + backing_object->paging_offset));
	}
}

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

	vm_object_lock_assert_exclusive(object);
	vm_object_lock_assert_exclusive(backing_object);

	assert(object->purgable == VM_PURGABLE_DENY);
	assert(backing_object->purgable == VM_PURGABLE_DENY);

	backing_offset = object->vo_shadow_offset;
	size = object->vo_size;

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
			 * "paging_offset".  These will not change during the 
			 * object collapse, so we can just move an encrypted
			 * page from one object to the other in this case.
			 * We can't decrypt the page here, since we can't drop
			 * the object lock.
			 */
			if (p->encrypted) {
				vm_object_collapse_encrypted++;
			}
			pp = vm_page_lookup(object, new_offset);
			if (pp == VM_PAGE_NULL) {

				if (VM_COMPRESSOR_PAGER_STATE_GET(object,
								  new_offset)
				    == VM_EXTERNAL_STATE_EXISTS) {
					/*
					 * Parent object has this page
					 * in the VM compressor.
					 * Throw away the backing
					 * object's page.
					 */
					VM_PAGE_FREE(p);
				} else {
					/*
					 *	Parent now has no page.
					 *	Move the backing object's page
					 * 	up.
					 */
					vm_page_rename(p, object, new_offset,
						       TRUE);
				}

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
				vm_page_rename(p, object, new_offset, TRUE);
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

	if (vm_object_collapse_compressor_allowed &&
	    object->pager != MEMORY_OBJECT_NULL &&
	    backing_object->pager != MEMORY_OBJECT_NULL) {

		/* move compressed pages from backing_object to object */
		vm_object_do_collapse_compressor(object, backing_object);

	} else if (backing_object->pager != MEMORY_OBJECT_NULL) {
		vm_object_hash_entry_t	entry;

#if	!MACH_PAGEMAP
		assert((!object->pager_created &&
			(object->pager == MEMORY_OBJECT_NULL)) ||
		       (!backing_object->pager_created &&
			(backing_object->pager == MEMORY_OBJECT_NULL)));
#else 
		assert(!object->pager_created &&
		       object->pager == MEMORY_OBJECT_NULL);
#endif	/* !MACH_PAGEMAP */

		/*
		 *	Move the pager from backing_object to object.
		 *
		 *	XXX We're only using part of the paging space
		 *	for keeps now... we ought to discard the
		 *	unused portion.
		 */

		assert(!object->paging_in_progress);
		assert(!object->activity_in_progress);
		assert(!object->pager_created);
		assert(object->pager == NULL);
		object->pager = backing_object->pager;

		if (backing_object->hashed) {
			lck_mtx_t	*lck;

			lck = vm_object_hash_lock_spin(backing_object->pager);
			entry = vm_object_hash_lookup(object->pager, FALSE);
			assert(entry != VM_OBJECT_HASH_ENTRY_NULL);
			entry->object = object;
			vm_object_hash_unlock(lck);

			object->hashed = TRUE;
		}
		object->pager_created = backing_object->pager_created;
		object->pager_control = backing_object->pager_control;
		object->pager_ready = backing_object->pager_ready;
		object->pager_initialized = backing_object->pager_initialized;
		object->paging_offset =
		    backing_object->paging_offset + backing_offset;
		if (object->pager_control != MEMORY_OBJECT_CONTROL_NULL) {
			memory_object_control_collapse(object->pager_control,
						       object);
		}
		/* the backing_object has lost its pager: reset all fields */
		backing_object->pager_created = FALSE;
		backing_object->pager_control = NULL;
		backing_object->pager_ready = FALSE;
		backing_object->paging_offset = 0;
		backing_object->pager = NULL;
	}

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
	if (backing_offset || (size != backing_object->vo_size)) {
		vm_external_discarded++;
		vm_external_destroy(backing_object->existence_map,
			backing_object->vo_size);
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
		object->vo_shadow_offset += backing_object->vo_shadow_offset;
		/* "backing_object" gave its shadow to "object" */
		backing_object->shadow = VM_OBJECT_NULL;
		backing_object->vo_shadow_offset = 0;
	} else {
		/* no shadow, therefore no shadow offset... */
		object->vo_shadow_offset = 0;
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
	object_collapses++;
	
	assert(backing_object->ref_count == 1);
	assert(backing_object->resident_page_count == 0);
	assert(backing_object->paging_in_progress == 0);
	assert(backing_object->activity_in_progress == 0);
	assert(backing_object->shadow == VM_OBJECT_NULL);
	assert(backing_object->vo_shadow_offset == 0);

	if (backing_object->pager != MEMORY_OBJECT_NULL) {
		/* ... unless it has a pager; need to terminate pager too */
		vm_counters.do_collapse_terminate++;
		if (vm_object_terminate(backing_object) != KERN_SUCCESS) {
			vm_counters.do_collapse_terminate_failure++;
		}
		return;
	}

	assert(backing_object->pager == NULL);

	backing_object->alive = FALSE;
	vm_object_unlock(backing_object);

	XPR(XPR_VM_OBJECT, "vm_object_collapse, collapsed 0x%X\n",
		backing_object, 0,0,0,0);

#if VM_OBJECT_TRACKING
	if (vm_object_tracking_inited) {
		btlog_remove_entries_for_element(vm_object_tracking_btlog,
						 backing_object);
	}
#endif /* VM_OBJECT_TRACKING */

	vm_object_lock_destroy(backing_object);

	zfree(vm_object_zone, backing_object);
	
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
	
	vm_object_lock_assert_exclusive(object);
	vm_object_lock_assert_exclusive(backing_object);

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
		vm_object_lock_assert_exclusive(backing_object->shadow);
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
		object->vo_shadow_offset += backing_object->vo_shadow_offset;
	} else {
		/* no shadow, therefore no shadow offset... */
		object->vo_shadow_offset = 0;
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
	 *	[with a caveat for "named" objects]
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
	if (backing_object->ref_count > 2 ||
	    (!backing_object->named && backing_object->ref_count > 1)) {
		vm_object_lock_assert_exclusive(backing_object);
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
		/*
		 * vm_object_collapse (the caller of this function) is
		 * now called from contexts that may not guarantee that a
		 * valid reference is held on the object... w/o a valid
		 * reference, it is unsafe and unwise (you will definitely
		 * regret it) to unlock the object and then retake the lock
		 * since the object may be terminated and recycled in between.
		 * The "activity_in_progress" reference will keep the object
		 * 'stable'.
		 */
		vm_object_activity_begin(object);
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
		vm_object_activity_end(object);
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
	register vm_object_offset_t		hint_offset,
	boolean_t				can_bypass)
{
	register vm_object_t			backing_object;
	register unsigned int			rcount;
	register unsigned int			size;
	vm_object_t				original_object;
	int					object_lock_type;
	int					backing_object_lock_type;

	vm_object_collapse_calls++;

	if (! vm_object_collapse_allowed &&
	    ! (can_bypass && vm_object_bypass_allowed)) {
		return;
	}

	XPR(XPR_VM_OBJECT, "vm_object_collapse, obj 0x%X\n", 
		object, 0,0,0,0);

	if (object == VM_OBJECT_NULL)
		return;

	original_object = object;

	/*
	 * The top object was locked "exclusive" by the caller.
	 * In the first pass, to determine if we can collapse the shadow chain,
	 * take a "shared" lock on the shadow objects.  If we can collapse,
	 * we'll have to go down the chain again with exclusive locks.
	 */
	object_lock_type = OBJECT_LOCK_EXCLUSIVE;
	backing_object_lock_type = OBJECT_LOCK_SHARED;

retry:
	object = original_object;
	vm_object_lock_assert_exclusive(object);

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
		if (backing_object_lock_type == OBJECT_LOCK_SHARED) {
			vm_object_lock_shared(backing_object);
		} else {
			vm_object_lock(backing_object);
		}

		/*
		 *	No pages in the object are currently
		 *	being paged out, and
		 */
		if (object->paging_in_progress != 0 ||
		    object->activity_in_progress != 0) {
			/* try and collapse the rest of the shadow chain */
			if (object != original_object) {
				vm_object_unlock(object);
			}
			object = backing_object;
			object_lock_type = backing_object_lock_type;
			continue;
		}

		/*
		 *	...
		 *		The backing object is not read_only,
		 *		and no pages in the backing object are
		 *		currently being paged out.
		 *		The backing object is internal.
		 *
		 */
	
		if (!backing_object->internal ||
		    backing_object->paging_in_progress != 0 ||
		    backing_object->activity_in_progress != 0) {
			/* try and collapse the rest of the shadow chain */
			if (object != original_object) {
				vm_object_unlock(object);
			}
			object = backing_object;
			object_lock_type = backing_object_lock_type;
			continue;
		}

		/*
		 * Purgeable objects are not supposed to engage in
		 * copy-on-write activities, so should not have
		 * any shadow objects or be a shadow object to another
		 * object.
		 * Collapsing a purgeable object would require some
		 * updates to the purgeable compressed ledgers.
		 */
		if (object->purgable != VM_PURGABLE_DENY ||
		    backing_object->purgable != VM_PURGABLE_DENY) {
			panic("vm_object_collapse() attempting to collapse "
			      "purgeable object: %p(%d) %p(%d)\n",
			      object, object->purgable,
			      backing_object, backing_object->purgable);
			/* try and collapse the rest of the shadow chain */
			if (object != original_object) {
				vm_object_unlock(object);
			}
			object = backing_object;
			object_lock_type = backing_object_lock_type;
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
			object_lock_type = backing_object_lock_type;
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
		    (vm_object_collapse_compressor_allowed ||
		     !object->pager_created 
#if	!MACH_PAGEMAP
		     || (!backing_object->pager_created)
#endif	/*!MACH_PAGEMAP */
		    ) && vm_object_collapse_allowed) {

			/*
			 * We need the exclusive lock on the VM objects.
			 */
			if (backing_object_lock_type != OBJECT_LOCK_EXCLUSIVE) {
				/*
				 * We have an object and its shadow locked 
				 * "shared".  We can't just upgrade the locks
				 * to "exclusive", as some other thread might
				 * also have these objects locked "shared" and
				 * attempt to upgrade one or the other to 
				 * "exclusive".  The upgrades would block
				 * forever waiting for the other "shared" locks
				 * to get released.
				 * So we have to release the locks and go
				 * down the shadow chain again (since it could
				 * have changed) with "exclusive" locking.
				 */
				vm_object_unlock(backing_object);
				if (object != original_object)
					vm_object_unlock(object);
				object_lock_type = OBJECT_LOCK_EXCLUSIVE;
				backing_object_lock_type = OBJECT_LOCK_EXCLUSIVE;
				goto retry;
			}

			XPR(XPR_VM_OBJECT, 
		   "vm_object_collapse: %x to %x, pager %x, pager_control %x\n",
				backing_object, object,
				backing_object->pager, 
				backing_object->pager_control, 0);

			/*
			 *	Collapse the object with its backing
			 *	object, and try again with the object's
			 *	new backing object.
			 */

			vm_object_do_collapse(object, backing_object);
			vm_object_collapse_do_collapse++;
			continue;
		}

		/*
		 *	Collapsing the backing object was not possible
		 *	or permitted, so let's try bypassing it.
		 */

		if (! (can_bypass && vm_object_bypass_allowed)) {
			/* try and collapse the rest of the shadow chain */
			if (object != original_object) {
				vm_object_unlock(object);
			}
			object = backing_object;
			object_lock_type = backing_object_lock_type;
			continue;
		}


		/*
		 *	If the object doesn't have all its pages present,
		 *	we have to make sure no pages in the backing object
		 *	"show through" before bypassing it.
		 */
		size = (unsigned int)atop(object->vo_size);
		rcount = object->resident_page_count;

		if (rcount != size) {
			vm_object_offset_t	offset;
			vm_object_offset_t	backing_offset;
			unsigned int     	backing_rcount;

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
				object_lock_type = backing_object_lock_type;
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
				object_lock_type = backing_object_lock_type;
				continue;
			}

			backing_offset = object->vo_shadow_offset;
			backing_rcount = backing_object->resident_page_count;

			if ( (int)backing_rcount - (int)(atop(backing_object->vo_size) - size) > (int)rcount) {
                                /*
				 * we have enough pages in the backing object to guarantee that
				 * at least 1 of them must be 'uncovered' by a resident page
				 * in the object we're evaluating, so move on and
				 * try to collapse the rest of the shadow chain
				 */
				if (object != original_object) {
					vm_object_unlock(object);
				}
				object = backing_object;
				object_lock_type = backing_object_lock_type;
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

#if	MACH_PAGEMAP
#define EXISTS_IN_OBJECT(obj, off, rc) \
	((vm_external_state_get((obj)->existence_map,	\
				(vm_offset_t)(off))	\
	  == VM_EXTERNAL_STATE_EXISTS) ||		\
	 (VM_COMPRESSOR_PAGER_STATE_GET((obj), (off))	\
	  == VM_EXTERNAL_STATE_EXISTS) ||		\
	 ((rc) && vm_page_lookup((obj), (off)) != VM_PAGE_NULL && (rc)--))
#else	/* MACH_PAGEMAP */
#define EXISTS_IN_OBJECT(obj, off, rc)			\
	((VM_COMPRESSOR_PAGER_STATE_GET((obj), (off))	\
	  == VM_EXTERNAL_STATE_EXISTS) ||		\
	 ((rc) && vm_page_lookup((obj), (off)) != VM_PAGE_NULL && (rc)--))
#endif	/* MACH_PAGEMAP */

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
				object->cow_hint = (vm_offset_t) hint_offset; /* atomic */
				/* try and collapse the rest of the shadow chain */
				if (object != original_object) {
					vm_object_unlock(object);
				}
				object = backing_object;
				object_lock_type = backing_object_lock_type;
				continue;
			}

			/*
			 * If the object's window onto the backing_object
			 * is large compared to the number of resident
			 * pages in the backing object, it makes sense to
			 * walk the backing_object's resident pages first.
			 *
			 * NOTE: Pages may be in both the existence map and/or
                         * resident, so if we don't find a dependency while
			 * walking the backing object's resident page list
			 * directly, and there is an existence map, we'll have
			 * to run the offset based 2nd pass.  Because we may
			 * have to run both passes, we need to be careful
			 * not to decrement 'rcount' in the 1st pass
			 */
			if (backing_rcount && backing_rcount < (size / 8)) {
				unsigned int rc = rcount;
				vm_page_t p;

				backing_rcount = backing_object->resident_page_count;
				p = (vm_page_t)queue_first(&backing_object->memq);
				do {
					offset = (p->offset - backing_offset);

					if (offset < object->vo_size &&
					    offset != hint_offset &&
					    !EXISTS_IN_OBJECT(object, offset, rc)) {
						/* found a dependency */
						object->cow_hint = (vm_offset_t) offset; /* atomic */
						
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
					object_lock_type = backing_object_lock_type;
					continue;
				}
			}

			/*
			 * Walk through the offsets looking for pages in the
			 * backing object that show through to the object.
			 */
			if (backing_rcount
#if MACH_PAGEMAP
			    || backing_object->existence_map
#endif	/* MACH_PAGEMAP */
				) {
				offset = hint_offset;
				
				while((offset =
				      (offset + PAGE_SIZE_64 < object->vo_size) ?
				      (offset + PAGE_SIZE_64) : 0) != hint_offset) {

					if (EXISTS_IN_OBJECT(backing_object, offset +
				            backing_offset, backing_rcount) &&
					    !EXISTS_IN_OBJECT(object, offset, rcount)) {
						/* found a dependency */
						object->cow_hint = (vm_offset_t) offset; /* atomic */
						break;
					}
				}
				if (offset != hint_offset) {
					/* try and collapse the rest of the shadow chain */
					if (object != original_object) {
						vm_object_unlock(object);
					}
					object = backing_object;
					object_lock_type = backing_object_lock_type;
					continue;
				}
			}
		}

		/*
		 * We need "exclusive" locks on the 2 VM objects.
		 */
		if (backing_object_lock_type != OBJECT_LOCK_EXCLUSIVE) {
			vm_object_unlock(backing_object);
			if (object != original_object)
				vm_object_unlock(object);
			object_lock_type = OBJECT_LOCK_EXCLUSIVE;
			backing_object_lock_type = OBJECT_LOCK_EXCLUSIVE;
			goto retry;
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

	/* NOT REACHED */
	/*
	if (object != original_object) {
		vm_object_unlock(object);
	}
	*/
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
				assert(!p->cleaning && !p->pageout && !p->laundry);
				if (!p->fictitious && p->pmapped)
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
				assert(!p->cleaning && !p->pageout && !p->laundry);
				if (!p->fictitious && p->pmapped)
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
		prev_object, prev_offset, prev_size, next_size, 0);

	vm_object_lock(prev_object);

	/*
	 *	Try to collapse the object first
	 */
	vm_object_collapse(prev_object, prev_offset, TRUE);

	/*
	 *	Can't coalesce if pages not mapped to
	 *	prev_entry may be in use any way:
	 *	. more than one reference
	 *	. paged out
	 *	. shadows another object
	 *	. has a copy elsewhere
	 *	. is purgeable
	 *	. paging references (pages might be in page-list)
	 */

	if ((prev_object->ref_count > 1) ||
	    prev_object->pager_created ||
	    (prev_object->shadow != VM_OBJECT_NULL) ||
	    (prev_object->copy != VM_OBJECT_NULL) ||
	    (prev_object->true_share != FALSE) ||
	    (prev_object->purgable != VM_PURGABLE_DENY) ||
	    (prev_object->paging_in_progress != 0) ||
	    (prev_object->activity_in_progress != 0)) {
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
	if (newsize > prev_object->vo_size) {
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
		prev_object->vo_size = newsize;
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
	int64_t	num_pages;
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
		    VM_PAGE_FREE(old_page);
	    }

	    assert((ppnum_t) addr == addr);
	    vm_page_init(m, (ppnum_t) addr, FALSE);
	    /*
	     * private normally requires lock_queues but since we
	     * are initializing the page, its not necessary here
	     */
	    m->private = TRUE;		/* don`t free page */
	    m->wire_count = 1;
	    vm_page_insert(m, object, offset);

	    PAGE_WAKEUP_DONE(m);
	    vm_object_unlock(object);
	}
}

kern_return_t
vm_object_populate_with_private(
		vm_object_t		object,
		vm_object_offset_t	offset,
		ppnum_t			phys_page,
		vm_size_t		size)
{
	ppnum_t			base_page;
	vm_object_offset_t	base_offset;


	if (!object->private)
		return KERN_FAILURE;

	base_page = phys_page;

	vm_object_lock(object);

	if (!object->phys_contiguous) {
		vm_page_t	m;

		if ((base_offset = trunc_page_64(offset)) != offset) {
			vm_object_unlock(object);
			return KERN_FAILURE;
		}
		base_offset += object->paging_offset;

		while (size) {
			m = vm_page_lookup(object, base_offset);

			if (m != VM_PAGE_NULL) {
				if (m->fictitious) {
					if (m->phys_page != vm_page_guard_addr) {

						vm_page_lockspin_queues();
						m->private = TRUE;
						vm_page_unlock_queues();

						m->fictitious = FALSE;
						m->phys_page = base_page;
					}
				} else if (m->phys_page != base_page) {

				        if ( !m->private) {
						/*
						 * we'd leak a real page... that can't be right
						 */
						panic("vm_object_populate_with_private - %p not private", m);
					}
					if (m->pmapped) {
					        /*
						 * pmap call to clear old mapping
						 */
					        pmap_disconnect(m->phys_page);
					}
					m->phys_page = base_page;
				}
				if (m->encrypted) {
					/*
					 * we should never see this on a ficticious or private page
					 */
					panic("vm_object_populate_with_private - %p encrypted", m);
				}

			} else {
				while ((m = vm_page_grab_fictitious()) == VM_PAGE_NULL)
                			vm_page_more_fictitious();	

				/*
				 * private normally requires lock_queues but since we
				 * are initializing the page, its not necessary here
				 */
				m->private = TRUE;
				m->fictitious = FALSE;
				m->phys_page = base_page;
				m->unusual = TRUE;
				m->busy = FALSE;

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
		object->vo_shadow_offset = (vm_object_offset_t)phys_page << PAGE_SHIFT;
		object->vo_size = size;
	}
	vm_object_unlock(object);

	return KERN_SUCCESS;
}

/*
 *	memory_object_free_from_cache:
 *
 *	Walk the vm_object cache list, removing and freeing vm_objects 
 *	which are backed by the pager identified by the caller, (pager_ops).  
 *	Remove up to "count" objects, if there are that may available
 *	in the cache.
 *
 *	Walk the list at most once, return the number of vm_objects
 *	actually freed.
 */

__private_extern__ kern_return_t
memory_object_free_from_cache(
	__unused host_t		host,
	__unused memory_object_pager_ops_t pager_ops,
	int		*count)
{
#if VM_OBJECT_CACHE
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
		if (object->pager &&
		    (pager_ops == object->pager->mo_pager_ops)) {
			vm_object_lock(object);
			queue_remove(&vm_object_cached_list, object, 
					vm_object_t, cached_list);
			vm_object_cached_count--;

			vm_object_cache_unlock();
			/*
		 	*	Since this object is in the cache, we know
		 	*	that it is initialized and has only a pager's
			*	(implicit) reference. Take a reference to avoid
			*	recursive deallocations.
		 	*/

			assert(object->pager_initialized);
			assert(object->ref_count == 0);
			vm_object_lock_assert_exclusive(object);
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
#else
	*count = 0;
#endif
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
	lck_mtx_t		*lck;

	*control = MEMORY_OBJECT_CONTROL_NULL;
	if (pager == MEMORY_OBJECT_NULL)
		return KERN_INVALID_ARGUMENT;

	lck = vm_object_hash_lock_spin(pager);
	entry = vm_object_hash_lookup(pager, FALSE);

	if ((entry != VM_OBJECT_HASH_ENTRY_NULL) &&
			(entry->object != VM_OBJECT_NULL)) {
		if (entry->object->named == TRUE)
			panic("memory_object_create_named: caller already holds the right");	}
	vm_object_hash_unlock(lck);

	if ((object = vm_object_enter(pager, size, FALSE, FALSE, TRUE)) == VM_OBJECT_NULL) {
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

	object = memory_object_control_to_vm_object(control);
	if (object == VM_OBJECT_NULL) {
		return (KERN_INVALID_ARGUMENT);
	}
restart:
	vm_object_lock(object);

	if (object->terminating && wait_on_terminating) {
		vm_object_wait(object, 
			VM_OBJECT_EVENT_PAGING_IN_PROGRESS, 
			THREAD_UNINT);
		goto restart;
	}

	if (!object->alive) {
		vm_object_unlock(object);
		return KERN_FAILURE;
	}

	if (object->named == TRUE) {
		vm_object_unlock(object);
		return KERN_SUCCESS;
	}
#if VM_OBJECT_CACHE
	if ((object->ref_count == 0) && (!object->terminating)) {
		if (!vm_object_cache_lock_try()) {
			vm_object_unlock(object);
			goto restart;
		}
		queue_remove(&vm_object_cached_list, object,
				     vm_object_t, cached_list);
		vm_object_cached_count--;
		XPR(XPR_VM_OBJECT_CACHE,
		    "memory_object_recover_named: removing %X, head (%X, %X)\n",
		    object, 
		    vm_object_cached_list.next,
		    vm_object_cached_list.prev, 0,0);
		
		vm_object_cache_unlock();
	}
#endif
	object->named = TRUE;
	vm_object_lock_assert_exclusive(object);
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

		vm_object_lock(object);

		assert(object->alive);
		if (original_object)
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
			thread_block(THREAD_CONTINUE_NULL);
			continue;
		}

		if (((object->ref_count > 1)
			&& (flags & MEMORY_OBJECT_TERMINATE_IDLE))
			|| (object->terminating)) {
			vm_object_unlock(object);
			return KERN_FAILURE;
		} else {
			if (flags & MEMORY_OBJECT_RELEASE_NO_OP) {
				vm_object_unlock(object);
				return KERN_SUCCESS;
			}
		}
		
		if ((flags & MEMORY_OBJECT_RESPECT_CACHE) &&
					(object->ref_count == 1)) {
			if (original_object)
				object->named = FALSE;
			vm_object_unlock(object);
			/* let vm_object_deallocate push this thing into */
			/* the cache, if that it is where it is bound */
			vm_object_deallocate(object);
			return KERN_SUCCESS;
		}
		VM_OBJ_RES_DECR(object);
		shadow = object->pageout?VM_OBJECT_NULL:object->shadow;

		if (object->ref_count == 1) {
			if (vm_object_terminate(object) != KERN_SUCCESS) {
				if (original_object) {
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
			vm_object_lock_assert_exclusive(object);
			object->ref_count--;
			assert(object->ref_count > 0);
			if(original_object)
				object->named = FALSE;
			vm_object_unlock(object);
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
	    object, offset, size, 
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
 * Empty a purgeable object by grabbing the physical pages assigned to it and
 * putting them on the free queue without writing them to backing store, etc.
 * When the pages are next touched they will be demand zero-fill pages.  We
 * skip pages which are busy, being paged in/out, wired, etc.  We do _not_
 * skip referenced/dirty pages, pages on the active queue, etc.  We're more
 * than happy to grab these since this is a purgeable object.  We mark the
 * object as "empty" after reaping its pages.
 *
 * On entry the object must be locked and it must be
 * purgeable with no delayed copies pending.
 */
void
vm_object_purge(vm_object_t object, int flags)
{
        vm_object_lock_assert_exclusive(object);

	if (object->purgable == VM_PURGABLE_DENY)
		return;

	assert(object->copy == VM_OBJECT_NULL);
	assert(object->copy_strategy == MEMORY_OBJECT_COPY_NONE);

	/*
	 * We need to set the object's state to VM_PURGABLE_EMPTY *before*
	 * reaping its pages.  We update vm_page_purgeable_count in bulk
	 * and we don't want vm_page_remove() to update it again for each
	 * page we reap later.
	 *
	 * For the purgeable ledgers, pages from VOLATILE and EMPTY objects
	 * are all accounted for in the "volatile" ledgers, so this does not
	 * make any difference.
	 * If we transitioned directly from NONVOLATILE to EMPTY,
	 * vm_page_purgeable_count must have been updated when the object
	 * was dequeued from its volatile queue and the purgeable ledgers
	 * must have also been updated accordingly at that time (in
	 * vm_object_purgable_control()).
	 */
	if (object->purgable == VM_PURGABLE_VOLATILE) {
		unsigned int delta;
		assert(object->resident_page_count >=
		       object->wired_page_count);
		delta = (object->resident_page_count -
			 object->wired_page_count);
		if (delta != 0) {
			assert(vm_page_purgeable_count >=
			       delta);
			OSAddAtomic(-delta,
				    (SInt32 *)&vm_page_purgeable_count);
		}
		if (object->wired_page_count != 0) {
			assert(vm_page_purgeable_wired_count >=
			       object->wired_page_count);
			OSAddAtomic(-object->wired_page_count,
				    (SInt32 *)&vm_page_purgeable_wired_count);
		}
		object->purgable = VM_PURGABLE_EMPTY;
	}
	assert(object->purgable == VM_PURGABLE_EMPTY);
	
	vm_object_reap_pages(object, REAP_PURGEABLE);

	if (object->pager != NULL &&
	    COMPRESSED_PAGER_IS_ACTIVE) {
		unsigned int pgcount;

		if (object->activity_in_progress == 0 &&
		    object->paging_in_progress == 0) {
			/*
			 * Also reap any memory coming from this object
			 * in the VM compressor.
			 *
			 * There are no operations in progress on the VM object
			 * and no operation can start while we're holding the
			 * VM object lock, so it's safe to reap the compressed
			 * pages and update the page counts.
			 */
			pgcount = vm_compressor_pager_get_count(object->pager);
			if (pgcount) {
				pgcount = vm_compressor_pager_reap_pages(object->pager, flags);
				vm_compressor_pager_count(object->pager,
							  -pgcount,
							  FALSE, /* shared */
							  object);
				vm_purgeable_compressed_update(object,
							       -pgcount);
			}
			if ( !(flags & C_DONT_BLOCK)) {
				assert(vm_compressor_pager_get_count(object->pager)
				       == 0);
			}
		} else {
			/*
			 * There's some kind of paging activity in progress
			 * for this object, which could result in a page
			 * being compressed or decompressed, possibly while
			 * the VM object is not locked, so it could race
			 * with us.
			 *
			 * We can't really synchronize this without possibly 
			 * causing a deadlock when the compressor needs to
			 * allocate or free memory while compressing or
			 * decompressing a page from a purgeable object
			 * mapped in the kernel_map...
			 *
			 * So let's not attempt to purge the compressor
			 * pager if there's any kind of operation in
			 * progress on the VM object.
			 */
		}
	}

	vm_object_lock_assert_exclusive(object);
}
				

/*
 * vm_object_purgeable_control() allows the caller to control and investigate the
 * state of a purgeable object.  A purgeable object is created via a call to
 * vm_allocate() with VM_FLAGS_PURGABLE specified.  A purgeable object will
 * never be coalesced with any other object -- even other purgeable objects --
 * and will thus always remain a distinct object.  A purgeable object has
 * special semantics when its reference count is exactly 1.  If its reference
 * count is greater than 1, then a purgeable object will behave like a normal
 * object and attempts to use this interface will result in an error return
 * of KERN_INVALID_ARGUMENT.
 *
 * A purgeable object may be put into a "volatile" state which will make the
 * object's pages elligable for being reclaimed without paging to backing
 * store if the system runs low on memory.  If the pages in a volatile
 * purgeable object are reclaimed, the purgeable object is said to have been
 * "emptied."  When a purgeable object is emptied the system will reclaim as
 * many pages from the object as it can in a convenient manner (pages already
 * en route to backing store or busy for other reasons are left as is).  When
 * a purgeable object is made volatile, its pages will generally be reclaimed
 * before other pages in the application's working set.  This semantic is
 * generally used by applications which can recreate the data in the object
 * faster than it can be paged in.  One such example might be media assets
 * which can be reread from a much faster RAID volume.
 *
 * A purgeable object may be designated as "non-volatile" which means it will
 * behave like all other objects in the system with pages being written to and
 * read from backing store as needed to satisfy system memory needs.  If the
 * object was emptied before the object was made non-volatile, that fact will
 * be returned as the old state of the purgeable object (see
 * VM_PURGABLE_SET_STATE below).  In this case, any pages of the object which
 * were reclaimed as part of emptying the object will be refaulted in as
 * zero-fill on demand.  It is up to the application to note that an object
 * was emptied and recreate the objects contents if necessary.  When a
 * purgeable object is made non-volatile, its pages will generally not be paged
 * out to backing store in the immediate future.  A purgeable object may also
 * be manually emptied.
 *
 * Finally, the current state (non-volatile, volatile, volatile & empty) of a
 * volatile purgeable object may be queried at any time.  This information may
 * be used as a control input to let the application know when the system is
 * experiencing memory pressure and is reclaiming memory.
 *
 * The specified address may be any address within the purgeable object.  If
 * the specified address does not represent any object in the target task's
 * virtual address space, then KERN_INVALID_ADDRESS will be returned.  If the
 * object containing the specified address is not a purgeable object, then
 * KERN_INVALID_ARGUMENT will be returned.  Otherwise, KERN_SUCCESS will be
 * returned.
 *
 * The control parameter may be any one of VM_PURGABLE_SET_STATE or
 * VM_PURGABLE_GET_STATE.  For VM_PURGABLE_SET_STATE, the in/out parameter
 * state is used to set the new state of the purgeable object and return its
 * old state.  For VM_PURGABLE_GET_STATE, the current state of the purgeable
 * object is returned in the parameter state.
 *
 * The in/out parameter state may be one of VM_PURGABLE_NONVOLATILE,
 * VM_PURGABLE_VOLATILE or VM_PURGABLE_EMPTY.  These, respectively, represent
 * the non-volatile, volatile and volatile/empty states described above.
 * Setting the state of a purgeable object to VM_PURGABLE_EMPTY will
 * immediately reclaim as many pages in the object as can be conveniently
 * collected (some may have already been written to backing store or be
 * otherwise busy).
 *
 * The process of making a purgeable object non-volatile and determining its
 * previous state is atomic.  Thus, if a purgeable object is made
 * VM_PURGABLE_NONVOLATILE and the old state is returned as
 * VM_PURGABLE_VOLATILE, then the purgeable object's previous contents are
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
	int		new_state;

	if (object == VM_OBJECT_NULL) {
		/*
		 * Object must already be present or it can't be purgeable.
		 */
		return KERN_INVALID_ARGUMENT;
	}

	vm_object_lock_assert_exclusive(object);

	/*
	 * Get current state of the purgeable object.
	 */
	old_state = object->purgable;
	if (old_state == VM_PURGABLE_DENY)
		return KERN_INVALID_ARGUMENT;
    
	/* purgeable cant have delayed copies - now or in the future */
	assert(object->copy == VM_OBJECT_NULL); 
	assert(object->copy_strategy == MEMORY_OBJECT_COPY_NONE);

	/*
	 * Execute the desired operation.
	 */
	if (control == VM_PURGABLE_GET_STATE) {
		*state = old_state;
		return KERN_SUCCESS;
	}

	if ((*state) & VM_PURGABLE_DEBUG_EMPTY) {
		object->volatile_empty = TRUE;
	}
	if ((*state) & VM_PURGABLE_DEBUG_FAULT) {
		object->volatile_fault = TRUE;
	}

	new_state = *state & VM_PURGABLE_STATE_MASK;
	if (new_state == VM_PURGABLE_VOLATILE &&
	    object->volatile_empty) {
		new_state = VM_PURGABLE_EMPTY;
	}

	switch (new_state) {
	case VM_PURGABLE_DENY:
	case VM_PURGABLE_NONVOLATILE:
		object->purgable = new_state;

		if (old_state == VM_PURGABLE_VOLATILE) {
			unsigned int delta;

			assert(object->resident_page_count >=
			       object->wired_page_count);
			delta = (object->resident_page_count -
				 object->wired_page_count);

			assert(vm_page_purgeable_count >= delta);

			if (delta != 0) {
				OSAddAtomic(-delta,
					    (SInt32 *)&vm_page_purgeable_count);
			}
			if (object->wired_page_count != 0) {
				assert(vm_page_purgeable_wired_count >=
				       object->wired_page_count);
				OSAddAtomic(-object->wired_page_count,
					    (SInt32 *)&vm_page_purgeable_wired_count);
			}

			vm_page_lock_queues();

			/* object should be on a queue */
			assert(object->objq.next != NULL &&
			       object->objq.prev != NULL);
			purgeable_q_t queue;

			/*
			 * Move object from its volatile queue to the
			 * non-volatile queue...
			 */
			queue = vm_purgeable_object_remove(object);
			assert(queue);

			if (object->purgeable_when_ripe) {
				vm_purgeable_token_delete_last(queue);
			}
			assert(queue->debug_count_objects>=0);

			vm_page_unlock_queues();
		}
		if (old_state == VM_PURGABLE_VOLATILE ||
		    old_state == VM_PURGABLE_EMPTY) {
			/*
			 * Transfer the object's pages from the volatile to
			 * non-volatile ledgers.
			 */
			vm_purgeable_accounting(object, VM_PURGABLE_VOLATILE,
						FALSE);
		}

		break;

	case VM_PURGABLE_VOLATILE:
		if (object->volatile_fault) {
			vm_page_t	p;
			int		refmod;

			queue_iterate(&object->memq, p, vm_page_t, listq) {
				if (p->busy ||
				    VM_PAGE_WIRED(p) ||
				    p->fictitious) {
					continue;
				}
				refmod = pmap_disconnect(p->phys_page);
				if ((refmod & VM_MEM_MODIFIED) &&
				    !p->dirty) {
					SET_PAGE_DIRTY(p, FALSE);
				}
			}
		}
					       
		if (old_state == VM_PURGABLE_EMPTY &&
		    object->resident_page_count == 0 &&
		    object->pager == NULL)
			break;

		purgeable_q_t queue;
        
		/* find the correct queue */
		if ((*state&VM_PURGABLE_ORDERING_MASK) == VM_PURGABLE_ORDERING_OBSOLETE)
		        queue = &purgeable_queues[PURGEABLE_Q_TYPE_OBSOLETE];
		else {
		        if ((*state&VM_PURGABLE_BEHAVIOR_MASK) == VM_PURGABLE_BEHAVIOR_FIFO)
			        queue = &purgeable_queues[PURGEABLE_Q_TYPE_FIFO];
			else
			        queue = &purgeable_queues[PURGEABLE_Q_TYPE_LIFO];
		}
        
		if (old_state == VM_PURGABLE_NONVOLATILE ||
		    old_state == VM_PURGABLE_EMPTY) {
			unsigned int delta;

			if ((*state & VM_PURGABLE_NO_AGING_MASK) ==
			    VM_PURGABLE_NO_AGING) {
				object->purgeable_when_ripe = FALSE;
			} else {
				object->purgeable_when_ripe = TRUE;
			}
				
			if (object->purgeable_when_ripe) {
				kern_return_t result;

				/* try to add token... this can fail */
				vm_page_lock_queues();

				result = vm_purgeable_token_add(queue);
				if (result != KERN_SUCCESS) {
					vm_page_unlock_queues();
					return result;
				}
				vm_page_unlock_queues();
			}

			assert(object->resident_page_count >=
			       object->wired_page_count);
			delta = (object->resident_page_count -
				 object->wired_page_count);

			if (delta != 0) {
				OSAddAtomic(delta,
					    &vm_page_purgeable_count);
			}
			if (object->wired_page_count != 0) {
				OSAddAtomic(object->wired_page_count,
					    &vm_page_purgeable_wired_count);
			}

			object->purgable = new_state;

			/* object should be on "non-volatile" queue */
			assert(object->objq.next != NULL);
			assert(object->objq.prev != NULL);
		}
		else if (old_state == VM_PURGABLE_VOLATILE) {
			purgeable_q_t	old_queue;
			boolean_t	purgeable_when_ripe;

		        /*
			 * if reassigning priorities / purgeable groups, we don't change the
			 * token queue. So moving priorities will not make pages stay around longer.
			 * Reasoning is that the algorithm gives most priority to the most important
			 * object. If a new token is added, the most important object' priority is boosted.
			 * This biases the system already for purgeable queues that move a lot.
			 * It doesn't seem more biasing is neccessary in this case, where no new object is added.
			 */
		        assert(object->objq.next != NULL && object->objq.prev != NULL); /* object should be on a queue */
            
			old_queue = vm_purgeable_object_remove(object);
			assert(old_queue);
            
			if ((*state & VM_PURGABLE_NO_AGING_MASK) ==
			    VM_PURGABLE_NO_AGING) {
				purgeable_when_ripe = FALSE;
			} else {
				purgeable_when_ripe = TRUE;
			}
				
			if (old_queue != queue ||
			    (purgeable_when_ripe !=
			     object->purgeable_when_ripe)) {
				kern_return_t result;

			        /* Changing queue. Have to move token. */
			        vm_page_lock_queues();
				if (object->purgeable_when_ripe) {
					vm_purgeable_token_delete_last(old_queue);
				}
				object->purgeable_when_ripe = purgeable_when_ripe;
				if (object->purgeable_when_ripe) {
					result = vm_purgeable_token_add(queue);
					assert(result==KERN_SUCCESS);   /* this should never fail since we just freed a token */
				}
				vm_page_unlock_queues();

			}
		};
		vm_purgeable_object_add(object, queue, (*state&VM_VOLATILE_GROUP_MASK)>>VM_VOLATILE_GROUP_SHIFT );
		if (old_state == VM_PURGABLE_NONVOLATILE) {
			vm_purgeable_accounting(object, VM_PURGABLE_NONVOLATILE,
						FALSE);
		}

		assert(queue->debug_count_objects>=0);
        
		break;


	case VM_PURGABLE_EMPTY:
		if (object->volatile_fault) {
			vm_page_t	p;
			int		refmod;

			queue_iterate(&object->memq, p, vm_page_t, listq) {
				if (p->busy ||
				    VM_PAGE_WIRED(p) ||
				    p->fictitious) {
					continue;
				}
				refmod = pmap_disconnect(p->phys_page);
				if ((refmod & VM_MEM_MODIFIED) &&
				    !p->dirty) {
					SET_PAGE_DIRTY(p, FALSE);
				}
			}
		}

		if (old_state == new_state) {
			/* nothing changes */
			break;
		}

		assert(old_state == VM_PURGABLE_NONVOLATILE ||
		       old_state == VM_PURGABLE_VOLATILE);
		if (old_state == VM_PURGABLE_VOLATILE) {
			purgeable_q_t old_queue;

			/* object should be on a queue */
			assert(object->objq.next != NULL &&
			       object->objq.prev != NULL);

			old_queue = vm_purgeable_object_remove(object);
			assert(old_queue);
			if (object->purgeable_when_ripe) {
				vm_page_lock_queues();
				vm_purgeable_token_delete_first(old_queue);
				vm_page_unlock_queues();
			}
		}

		if (old_state == VM_PURGABLE_NONVOLATILE) {
			/*
			 * This object's pages were previously accounted as
			 * "non-volatile" and now need to be accounted as
			 * "volatile".
			 */
			vm_purgeable_accounting(object, VM_PURGABLE_NONVOLATILE,
						FALSE);
			/*
			 * Set to VM_PURGABLE_EMPTY because the pages are no
			 * longer accounted in the "non-volatile" ledger
			 * and are also not accounted for in
			 * "vm_page_purgeable_count".
			 */
			object->purgable = VM_PURGABLE_EMPTY;
		}

		(void) vm_object_purge(object, 0);
		assert(object->purgable == VM_PURGABLE_EMPTY);

		break;
	}

	*state = old_state;

	vm_object_lock_assert_exclusive(object);

	return KERN_SUCCESS;
}

kern_return_t
vm_object_get_page_counts(
	vm_object_t		object,
	vm_object_offset_t	offset,
	vm_object_size_t	size,
	unsigned int		*resident_page_count,
	unsigned int		*dirty_page_count)
{

	kern_return_t		kr = KERN_SUCCESS;
	boolean_t		count_dirty_pages = FALSE;
	vm_page_t		p = VM_PAGE_NULL;
	unsigned int 		local_resident_count = 0;
	unsigned int		local_dirty_count = 0;
	vm_object_offset_t	cur_offset = 0;
	vm_object_offset_t	end_offset = 0;

	if (object == VM_OBJECT_NULL)
		return KERN_INVALID_ARGUMENT;


	cur_offset = offset;
	
	end_offset = offset + size;

	vm_object_lock_assert_exclusive(object);

	if (dirty_page_count != NULL) {

		count_dirty_pages = TRUE;
	}

	if (resident_page_count != NULL && count_dirty_pages == FALSE) {
		/*
		 * Fast path when:
		 * - we only want the resident page count, and,
		 * - the entire object is exactly covered by the request.
		 */
		if (offset == 0 && (object->vo_size == size)) {

			*resident_page_count = object->resident_page_count;
			goto out;
		}
	}

	if (object->resident_page_count <= (size >> PAGE_SHIFT)) {

		queue_iterate(&object->memq, p, vm_page_t, listq) {
		
			if (p->offset >= cur_offset && p->offset < end_offset) {

				local_resident_count++;

				if (count_dirty_pages) {
					
					if (p->dirty || (p->wpmapped && pmap_is_modified(p->phys_page))) {
						
						local_dirty_count++;
					}
				}
			}
		}
	} else {

		for (cur_offset = offset; cur_offset < end_offset; cur_offset += PAGE_SIZE_64) {
	
			p = vm_page_lookup(object, cur_offset);
		
			if (p != VM_PAGE_NULL) {

				local_resident_count++;

				if (count_dirty_pages) {
					
					if (p->dirty || (p->wpmapped && pmap_is_modified(p->phys_page))) {
				
						local_dirty_count++;
					}
				}
			}
		}

	}

	if (resident_page_count != NULL) {
		*resident_page_count = local_resident_count;
	}

	if (dirty_page_count != NULL) {
		*dirty_page_count = local_dirty_count;
	}

out:
	return kr;
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
	__unused vm_size_t nval)
{
#if VM_OBJECT_CACHE
	vm_object_cached_max = nval;
	vm_object_cache_trim(FALSE);
#endif
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
unsigned int vm_object_transpose_count = 0;
kern_return_t
vm_object_transpose(
	vm_object_t		object1,
	vm_object_t		object2,
	vm_object_size_t	transpose_size)
{
	vm_object_t		tmp_object;
	kern_return_t		retval;
	boolean_t		object1_locked, object2_locked;
	vm_page_t		page;
	vm_object_offset_t	page_offset;
	lck_mtx_t		*hash_lck;
	vm_object_hash_entry_t	hash_entry;

	tmp_object = VM_OBJECT_NULL;
	object1_locked = FALSE; object2_locked = FALSE;

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

	/*
	 * Since we need to lock both objects at the same time,
	 * make sure we always lock them in the same order to
	 * avoid deadlocks.
	 */
	if (object1 >  object2) {
		tmp_object = object1;
		object1 = object2;
		object2 = tmp_object;
	}

	/*
	 * Allocate a temporary VM object to hold object1's contents
	 * while we copy object2 to object1.
	 */
	tmp_object = vm_object_allocate(transpose_size);
	vm_object_lock(tmp_object);
	tmp_object->can_persist = FALSE;


	/*
	 * Grab control of the 1st VM object.
	 */
	vm_object_lock(object1);
	object1_locked = TRUE;
	if (!object1->alive || object1->terminating ||
	    object1->copy || object1->shadow || object1->shadowed ||
	    object1->purgable != VM_PURGABLE_DENY) {
		/*
		 * We don't deal with copy or shadow objects (yet).
		 */
		retval = KERN_INVALID_VALUE;
		goto done;
	}
	/*
	 * We're about to mess with the object's backing store and 
	 * taking a "paging_in_progress" reference wouldn't be enough
	 * to prevent any paging activity on this object, so the caller should
	 * have "quiesced" the objects beforehand, via a UPL operation with
	 * UPL_SET_IO_WIRE (to make sure all the pages are there and wired)
	 * and UPL_BLOCK_ACCESS (to mark the pages "busy").
	 * 
	 * Wait for any paging operation to complete (but only paging, not 
	 * other kind of activities not linked to the pager).  After we're
	 * statisfied that there's no more paging in progress, we keep the
	 * object locked, to guarantee that no one tries to access its pager.
	 */
	vm_object_paging_only_wait(object1, THREAD_UNINT);

	/*
	 * Same as above for the 2nd object...
	 */
	vm_object_lock(object2);
	object2_locked = TRUE;
	if (! object2->alive || object2->terminating ||
	    object2->copy || object2->shadow || object2->shadowed ||
	    object2->purgable != VM_PURGABLE_DENY) {
		retval = KERN_INVALID_VALUE;
		goto done;
	}
	vm_object_paging_only_wait(object2, THREAD_UNINT);


	if (object1->vo_size != object2->vo_size ||
	    object1->vo_size != transpose_size) {
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
	 * This also updates the resident_page_count and the memq_hint.
	 */
	if (object1->phys_contiguous || queue_empty(&object1->memq)) {
		/*
		 * No pages in object1, just transfer pages
		 * from object2 to object1.  No need to go through
		 * an intermediate object.
		 */
		while (!queue_empty(&object2->memq)) {
			page = (vm_page_t) queue_first(&object2->memq);
			vm_page_rename(page, object1, page->offset, FALSE);
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
			vm_page_rename(page, object2, page->offset, FALSE);
		}
		assert(queue_empty(&object1->memq));
	} else {
		/* transfer object1's pages to tmp_object */
		while (!queue_empty(&object1->memq)) {
			page = (vm_page_t) queue_first(&object1->memq);
			page_offset = page->offset;
			vm_page_remove(page, TRUE);
			page->offset = page_offset;
			queue_enter(&tmp_object->memq, page, vm_page_t, listq);
		}
		assert(queue_empty(&object1->memq));
		/* transfer object2's pages to object1 */
		while (!queue_empty(&object2->memq)) {
			page = (vm_page_t) queue_first(&object2->memq);
			vm_page_rename(page, object1, page->offset, FALSE);
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

#define __TRANSPOSE_FIELD(field)				\
MACRO_BEGIN							\
	tmp_object->field = object1->field;			\
	object1->field = object2->field;			\
	object2->field = tmp_object->field;			\
MACRO_END

	/* "Lock" refers to the object not its contents */
	/* "size" should be identical */
	assert(object1->vo_size == object2->vo_size);
	/* "memq_hint" was updated above when transposing pages */
	/* "ref_count" refers to the object not its contents */
#if TASK_SWAPPER
	/* "res_count" refers to the object not its contents */
#endif
	/* "resident_page_count" was updated above when transposing pages */
	/* "wired_page_count" was updated above when transposing pages */
	/* "reusable_page_count" was updated above when transposing pages */
	/* there should be no "copy" */
	assert(!object1->copy);
	assert(!object2->copy);
	/* there should be no "shadow" */
	assert(!object1->shadow);
	assert(!object2->shadow);
	__TRANSPOSE_FIELD(vo_shadow_offset); /* used by phys_contiguous objects */
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
	__TRANSPOSE_FIELD(copy_strategy);
	/* "paging_in_progress" refers to the object not its contents */
	assert(!object1->paging_in_progress);
	assert(!object2->paging_in_progress);
	assert(object1->activity_in_progress);
	assert(object2->activity_in_progress);
	/* "all_wanted" refers to the object not its contents */
	__TRANSPOSE_FIELD(pager_created);
	__TRANSPOSE_FIELD(pager_initialized);
	__TRANSPOSE_FIELD(pager_ready);
	__TRANSPOSE_FIELD(pager_trusted);
	__TRANSPOSE_FIELD(can_persist);
	__TRANSPOSE_FIELD(internal);
	__TRANSPOSE_FIELD(temporary);
	__TRANSPOSE_FIELD(private);
	__TRANSPOSE_FIELD(pageout);
	/* "alive" should be set */
	assert(object1->alive);
	assert(object2->alive);
	/* "purgeable" should be non-purgeable */
	assert(object1->purgable == VM_PURGABLE_DENY);
	assert(object2->purgable == VM_PURGABLE_DENY);
	/* "shadowed" refers to the the object not its contents */
	__TRANSPOSE_FIELD(purgeable_when_ripe);
	__TRANSPOSE_FIELD(advisory_pageout);
	__TRANSPOSE_FIELD(true_share);
	/* "terminating" should not be set */
	assert(!object1->terminating);
	assert(!object2->terminating);
	__TRANSPOSE_FIELD(named);
	/* "shadow_severed" refers to the object not its contents */
	__TRANSPOSE_FIELD(phys_contiguous);
	__TRANSPOSE_FIELD(nophyscache);
	/* "cached_list.next" points to transposed object */
	object1->cached_list.next = (queue_entry_t) object2;
	object2->cached_list.next = (queue_entry_t) object1;
	/* "cached_list.prev" should be NULL */
	assert(object1->cached_list.prev == NULL);
	assert(object2->cached_list.prev == NULL);
	/* "msr_q" is linked to the object not its contents */
	assert(queue_empty(&object1->msr_q));
	assert(queue_empty(&object2->msr_q));
	__TRANSPOSE_FIELD(last_alloc);
	__TRANSPOSE_FIELD(sequential);
	__TRANSPOSE_FIELD(pages_created);
	__TRANSPOSE_FIELD(pages_used);
	__TRANSPOSE_FIELD(scan_collisions);
#if MACH_PAGEMAP
	__TRANSPOSE_FIELD(existence_map);
#endif
	__TRANSPOSE_FIELD(cow_hint);
#if MACH_ASSERT
	__TRANSPOSE_FIELD(paging_object);
#endif
	__TRANSPOSE_FIELD(wimg_bits);
	__TRANSPOSE_FIELD(set_cache_attr);
	__TRANSPOSE_FIELD(code_signed);
	if (object1->hashed) {
		hash_lck = vm_object_hash_lock_spin(object2->pager);
		hash_entry = vm_object_hash_lookup(object2->pager, FALSE);
		assert(hash_entry != VM_OBJECT_HASH_ENTRY_NULL);
		hash_entry->object = object2;
		vm_object_hash_unlock(hash_lck);
	}
	if (object2->hashed) {
		hash_lck = vm_object_hash_lock_spin(object1->pager);
		hash_entry = vm_object_hash_lookup(object1->pager, FALSE);
		assert(hash_entry != VM_OBJECT_HASH_ENTRY_NULL);
		hash_entry->object = object1;
		vm_object_hash_unlock(hash_lck);
	}
	__TRANSPOSE_FIELD(hashed);
	object1->transposed = TRUE;
	object2->transposed = TRUE;
	__TRANSPOSE_FIELD(mapping_in_progress);
	__TRANSPOSE_FIELD(volatile_empty);
	__TRANSPOSE_FIELD(volatile_fault);
	__TRANSPOSE_FIELD(all_reusable);
	assert(object1->blocked_access);
	assert(object2->blocked_access);
	assert(object1->__object2_unused_bits == 0);
	assert(object2->__object2_unused_bits == 0);
#if UPL_DEBUG
	/* "uplq" refers to the object not its contents (see upl_transpose()) */
#endif
	assert(object1->objq.next == NULL);
	assert(object1->objq.prev == NULL);
	assert(object2->objq.next == NULL);
	assert(object2->objq.prev == NULL);

#undef __TRANSPOSE_FIELD

	retval = KERN_SUCCESS;

done:
	/*
	 * Cleanup.
	 */
	if (tmp_object != VM_OBJECT_NULL) {
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

	vm_object_transpose_count++;

	return retval;
}


/*
 *      vm_object_cluster_size
 *
 *      Determine how big a cluster we should issue an I/O for...
 *
 *	Inputs:   *start == offset of page needed
 *		  *length == maximum cluster pager can handle
 *	Outputs:  *start == beginning offset of cluster
 *		  *length == length of cluster to try
 *
 *	The original *start will be encompassed by the cluster
 *
 */
extern int speculative_reads_disabled;
extern int ignore_is_ssd;

unsigned int preheat_max_bytes = MAX_UPL_TRANSFER_BYTES;
unsigned int preheat_min_bytes = (1024 * 32);


__private_extern__ void
vm_object_cluster_size(vm_object_t object, vm_object_offset_t *start,
		       vm_size_t *length, vm_object_fault_info_t fault_info, uint32_t *io_streaming)
{
	vm_size_t		pre_heat_size;
	vm_size_t		tail_size;
	vm_size_t		head_size;
	vm_size_t		max_length;
	vm_size_t		cluster_size;
	vm_object_offset_t	object_size;
	vm_object_offset_t	orig_start;
	vm_object_offset_t	target_start;
	vm_object_offset_t	offset;
	vm_behavior_t		behavior;
	boolean_t		look_behind = TRUE;
	boolean_t		look_ahead  = TRUE;
	boolean_t		isSSD = FALSE;
	uint32_t		throttle_limit;
	int			sequential_run;
	int			sequential_behavior = VM_BEHAVIOR_SEQUENTIAL;
	vm_size_t		max_ph_size;
	vm_size_t		min_ph_size;

	assert( !(*length & PAGE_MASK));
	assert( !(*start & PAGE_MASK_64));

	/*
	 * remember maxiumum length of run requested
	 */
	max_length = *length;
	/*
	 * we'll always return a cluster size of at least
	 * 1 page, since the original fault must always
	 * be processed
	 */
	*length = PAGE_SIZE;
	*io_streaming = 0;

	if (speculative_reads_disabled || fault_info == NULL) {
	        /*
		 * no cluster... just fault the page in
		 */
	        return;
	}
	orig_start = *start;
	target_start = orig_start;
	cluster_size = round_page(fault_info->cluster_size);
	behavior = fault_info->behavior;

	vm_object_lock(object);

	if (object->pager == MEMORY_OBJECT_NULL)
		goto out;	/* pager is gone for this object, nothing more to do */

	if (!ignore_is_ssd)
		vnode_pager_get_isSSD(object->pager, &isSSD);

	min_ph_size = round_page(preheat_min_bytes);
	max_ph_size = round_page(preheat_max_bytes);

	if (isSSD) {
		min_ph_size /= 2;
		max_ph_size /= 8;
	}
	if (min_ph_size < PAGE_SIZE)
		min_ph_size = PAGE_SIZE;

	if (max_ph_size < PAGE_SIZE)
		max_ph_size = PAGE_SIZE;
	else if (max_ph_size > MAX_UPL_TRANSFER_BYTES)
		max_ph_size = MAX_UPL_TRANSFER_BYTES;

	if (max_length > max_ph_size) 
	        max_length = max_ph_size;

	if (max_length <= PAGE_SIZE)
		goto out;

	if (object->internal)
	        object_size = object->vo_size;
	else
	        vnode_pager_get_object_size(object->pager, &object_size);

	object_size = round_page_64(object_size);

	if (orig_start >= object_size) {
	        /*
		 * fault occurred beyond the EOF...
		 * we need to punt w/o changing the
		 * starting offset
		 */
	        goto out;
	}
	if (object->pages_used > object->pages_created) {
	        /*
		 * must have wrapped our 32 bit counters
		 * so reset
		 */
 	        object->pages_used = object->pages_created = 0;
	}
	if ((sequential_run = object->sequential)) {
		  if (sequential_run < 0) {
		          sequential_behavior = VM_BEHAVIOR_RSEQNTL;
			  sequential_run = 0 - sequential_run;
		  } else {
		          sequential_behavior = VM_BEHAVIOR_SEQUENTIAL;
		  }

	}
	switch (behavior) {

	default:
	        behavior = VM_BEHAVIOR_DEFAULT;

	case VM_BEHAVIOR_DEFAULT:
	        if (object->internal && fault_info->user_tag == VM_MEMORY_STACK)
		        goto out;

		if (sequential_run >= (3 * PAGE_SIZE)) {
		        pre_heat_size = sequential_run + PAGE_SIZE;

			if (sequential_behavior == VM_BEHAVIOR_SEQUENTIAL)
			        look_behind = FALSE;
			else
			        look_ahead = FALSE;

			*io_streaming = 1;
		} else {

			if (object->pages_created < (20 * (min_ph_size >> PAGE_SHIFT))) {
			        /*
				 * prime the pump
				 */
			        pre_heat_size = min_ph_size;
			} else {
				/*
				 * Linear growth in PH size: The maximum size is max_length...
				 * this cacluation will result in a size that is neither a 
				 * power of 2 nor a multiple of PAGE_SIZE... so round
				 * it up to the nearest PAGE_SIZE boundary
				 */
				pre_heat_size = (max_length * object->pages_used) / object->pages_created;

				if (pre_heat_size < min_ph_size)
					pre_heat_size = min_ph_size;
				else
					pre_heat_size = round_page(pre_heat_size);
			}
		}
		break;

	case VM_BEHAVIOR_RANDOM:
	        if ((pre_heat_size = cluster_size) <= PAGE_SIZE)
		        goto out;
	        break;

	case VM_BEHAVIOR_SEQUENTIAL:
	        if ((pre_heat_size = cluster_size) == 0)
		        pre_heat_size = sequential_run + PAGE_SIZE;
		look_behind = FALSE;
		*io_streaming = 1;

	        break;

	case VM_BEHAVIOR_RSEQNTL:
	        if ((pre_heat_size = cluster_size) == 0)
		        pre_heat_size = sequential_run + PAGE_SIZE;
		look_ahead = FALSE;
		*io_streaming = 1;

	        break;

	}
	throttle_limit = (uint32_t) max_length;
	assert(throttle_limit == max_length);

	if (vnode_pager_get_throttle_io_limit(object->pager, &throttle_limit) == KERN_SUCCESS) {
		if (max_length > throttle_limit)
			max_length = throttle_limit;
	}
	if (pre_heat_size > max_length)
	        pre_heat_size = max_length;

	if (behavior == VM_BEHAVIOR_DEFAULT && (pre_heat_size > min_ph_size)) {

		unsigned int consider_free = vm_page_free_count + vm_page_cleaned_count;
		
		if (consider_free < vm_page_throttle_limit) {
			pre_heat_size = trunc_page(pre_heat_size / 16);
		} else if (consider_free < vm_page_free_target) {
			pre_heat_size = trunc_page(pre_heat_size / 4);
		}
		
		if (pre_heat_size < min_ph_size)
			pre_heat_size = min_ph_size;
	}
	if (look_ahead == TRUE) {
	        if (look_behind == TRUE) { 
			/*
			 * if we get here its due to a random access... 
			 * so we want to center the original fault address
			 * within the cluster we will issue... make sure
			 * to calculate 'head_size' as a multiple of PAGE_SIZE...
			 * 'pre_heat_size' is a multiple of PAGE_SIZE but not
			 * necessarily an even number of pages so we need to truncate
			 * the result to a PAGE_SIZE boundary
			 */
			head_size = trunc_page(pre_heat_size / 2);

			if (target_start > head_size)
				target_start -= head_size;
			else
				target_start = 0;

			/*
			 * 'target_start' at this point represents the beginning offset
			 * of the cluster we are considering... 'orig_start' will be in
			 * the center of this cluster if we didn't have to clip the start
			 * due to running into the start of the file
			 */
		}
	        if ((target_start + pre_heat_size) > object_size)
		        pre_heat_size = (vm_size_t)(round_page_64(object_size - target_start));
		/*
		 * at this point caclulate the number of pages beyond the original fault
		 * address that we want to consider... this is guaranteed not to extend beyond
		 * the current EOF...
		 */
		assert((vm_size_t)(orig_start - target_start) == (orig_start - target_start));
	        tail_size = pre_heat_size - (vm_size_t)(orig_start - target_start) - PAGE_SIZE;
	} else {
	        if (pre_heat_size > target_start) {
			/*
			 * since pre_heat_size is always smaller then 2^32,
			 * if it is larger then target_start (a 64 bit value)
			 * it is safe to clip target_start to 32 bits
			 */
	                pre_heat_size = (vm_size_t) target_start;
		}
		tail_size = 0;
	}
	assert( !(target_start & PAGE_MASK_64));
	assert( !(pre_heat_size & PAGE_MASK));

	if (pre_heat_size <= PAGE_SIZE)
	        goto out;

	if (look_behind == TRUE) {
	        /*
		 * take a look at the pages before the original
		 * faulting offset... recalculate this in case
		 * we had to clip 'pre_heat_size' above to keep 
		 * from running past the EOF.
		 */
	        head_size = pre_heat_size - tail_size - PAGE_SIZE;

	        for (offset = orig_start - PAGE_SIZE_64; head_size; offset -= PAGE_SIZE_64, head_size -= PAGE_SIZE) {
		        /*
			 * don't poke below the lowest offset 
			 */
		        if (offset < fault_info->lo_offset)
			        break;
		        /*
			 * for external objects and internal objects w/o an existence map
			 * vm_externl_state_get will return VM_EXTERNAL_STATE_UNKNOWN
			 */
#if MACH_PAGEMAP
		        if (vm_external_state_get(object->existence_map, offset) == VM_EXTERNAL_STATE_ABSENT) {
			        /*
				 * we know for a fact that the pager can't provide the page
				 * so don't include it or any pages beyond it in this cluster
				 */
			        break;
			}
#endif /* MACH_PAGEMAP */
			if (VM_COMPRESSOR_PAGER_STATE_GET(object, offset)
			    == VM_EXTERNAL_STATE_ABSENT) {
				break;
			}
			if (vm_page_lookup(object, offset) != VM_PAGE_NULL) {
			        /*
				 * don't bridge resident pages
				 */
			        break;
			}
			*start = offset;
			*length += PAGE_SIZE;
		}
	}
	if (look_ahead == TRUE) {
	        for (offset = orig_start + PAGE_SIZE_64; tail_size; offset += PAGE_SIZE_64, tail_size -= PAGE_SIZE) {
		        /*
			 * don't poke above the highest offset 
			 */
		        if (offset >= fault_info->hi_offset)
			        break;
			assert(offset < object_size);

		        /*
			 * for external objects and internal objects w/o an existence map
			 * vm_externl_state_get will return VM_EXTERNAL_STATE_UNKNOWN
			 */
#if MACH_PAGEMAP
		        if (vm_external_state_get(object->existence_map, offset) == VM_EXTERNAL_STATE_ABSENT) {
			        /*
				 * we know for a fact that the pager can't provide the page
				 * so don't include it or any pages beyond it in this cluster
				 */
			        break;
			}
#endif /* MACH_PAGEMAP */
			if (VM_COMPRESSOR_PAGER_STATE_GET(object, offset) == VM_EXTERNAL_STATE_ABSENT) {
				break;
			}
			if (vm_page_lookup(object, offset) != VM_PAGE_NULL) {
			        /*
				 * don't bridge resident pages
				 */
			        break;
			}
			*length += PAGE_SIZE;
		}
	}
out:
	if (*length > max_length)
		*length = max_length;

	vm_object_unlock(object);
	
	DTRACE_VM1(clustersize, vm_size_t, *length);
}


/*
 * Allow manipulation of individual page state.  This is actually part of
 * the UPL regimen but takes place on the VM object rather than on a UPL
 */

kern_return_t
vm_object_page_op(
	vm_object_t		object,
	vm_object_offset_t	offset,
	int			ops,
	ppnum_t			*phys_entry,
	int			*flags)
{
	vm_page_t		dst_page;

	vm_object_lock(object);

	if(ops & UPL_POP_PHYSICAL) {
		if(object->phys_contiguous) {
			if (phys_entry) {
				*phys_entry = (ppnum_t)
					(object->vo_shadow_offset >> PAGE_SHIFT);
			}
			vm_object_unlock(object);
			return KERN_SUCCESS;
		} else {
			vm_object_unlock(object);
			return KERN_INVALID_OBJECT;
		}
	}
	if(object->phys_contiguous) {
		vm_object_unlock(object);
		return KERN_INVALID_OBJECT;
	}

	while(TRUE) {
		if((dst_page = vm_page_lookup(object,offset)) == VM_PAGE_NULL) {
			vm_object_unlock(object);
			return KERN_FAILURE;
		}

		/* Sync up on getting the busy bit */
		if((dst_page->busy || dst_page->cleaning) && 
			   (((ops & UPL_POP_SET) && 
			   (ops & UPL_POP_BUSY)) || (ops & UPL_POP_DUMP))) {
			/* someone else is playing with the page, we will */
			/* have to wait */
			PAGE_SLEEP(object, dst_page, THREAD_UNINT);
			continue;
		}

		if (ops & UPL_POP_DUMP) {
			if (dst_page->pmapped == TRUE)
			        pmap_disconnect(dst_page->phys_page);

			VM_PAGE_FREE(dst_page);
			break;
		}

		if (flags) {
		        *flags = 0;

			/* Get the condition of flags before requested ops */
			/* are undertaken */

			if(dst_page->dirty) *flags |= UPL_POP_DIRTY;
			if(dst_page->pageout) *flags |= UPL_POP_PAGEOUT;
			if(dst_page->precious) *flags |= UPL_POP_PRECIOUS;
			if(dst_page->absent) *flags |= UPL_POP_ABSENT;
			if(dst_page->busy) *flags |= UPL_POP_BUSY;
		}

		/* The caller should have made a call either contingent with */
		/* or prior to this call to set UPL_POP_BUSY */
		if(ops & UPL_POP_SET) {
			/* The protection granted with this assert will */
			/* not be complete.  If the caller violates the */
			/* convention and attempts to change page state */
			/* without first setting busy we may not see it */
			/* because the page may already be busy.  However */
			/* if such violations occur we will assert sooner */
			/* or later. */
			assert(dst_page->busy || (ops & UPL_POP_BUSY));
			if (ops & UPL_POP_DIRTY) {
				SET_PAGE_DIRTY(dst_page, FALSE);
			}
			if (ops & UPL_POP_PAGEOUT) dst_page->pageout = TRUE;
			if (ops & UPL_POP_PRECIOUS) dst_page->precious = TRUE;
			if (ops & UPL_POP_ABSENT) dst_page->absent = TRUE;
			if (ops & UPL_POP_BUSY) dst_page->busy = TRUE;
		}

		if(ops & UPL_POP_CLR) {
			assert(dst_page->busy);
			if (ops & UPL_POP_DIRTY) dst_page->dirty = FALSE;
			if (ops & UPL_POP_PAGEOUT) dst_page->pageout = FALSE;
			if (ops & UPL_POP_PRECIOUS) dst_page->precious = FALSE;
			if (ops & UPL_POP_ABSENT) dst_page->absent = FALSE;
			if (ops & UPL_POP_BUSY) {
			        dst_page->busy = FALSE;
				PAGE_WAKEUP(dst_page);
			}
		}

		if (dst_page->encrypted) {
			/*
			 * ENCRYPTED SWAP:
			 * We need to decrypt this encrypted page before the
			 * caller can access its contents.
			 * But if the caller really wants to access the page's
			 * contents, they have to keep the page "busy".
			 * Otherwise, the page could get recycled or re-encrypted
			 * at any time.
			 */
			if ((ops & UPL_POP_SET) && (ops & UPL_POP_BUSY) &&
			    dst_page->busy) {
				/*
				 * The page is stable enough to be accessed by
				 * the caller, so make sure its contents are
				 * not encrypted.
				 */
				vm_page_decrypt(dst_page, 0);
			} else {
				/*
				 * The page is not busy, so don't bother
				 * decrypting it, since anything could
				 * happen to it between now and when the
				 * caller wants to access it.
				 * We should not give the caller access
				 * to this page.
				 */
				assert(!phys_entry);
			}
		}

		if (phys_entry) {
			/*
			 * The physical page number will remain valid
			 * only if the page is kept busy.
			 * ENCRYPTED SWAP: make sure we don't let the
			 * caller access an encrypted page.
			 */
			assert(dst_page->busy);
			assert(!dst_page->encrypted);
			*phys_entry = dst_page->phys_page;
		}

		break;
	}

	vm_object_unlock(object);
	return KERN_SUCCESS;
				
}

/*
 * vm_object_range_op offers performance enhancement over 
 * vm_object_page_op for page_op functions which do not require page 
 * level state to be returned from the call.  Page_op was created to provide 
 * a low-cost alternative to page manipulation via UPLs when only a single 
 * page was involved.  The range_op call establishes the ability in the _op 
 * family of functions to work on multiple pages where the lack of page level
 * state handling allows the caller to avoid the overhead of the upl structures.
 */

kern_return_t
vm_object_range_op(
	vm_object_t		object,
	vm_object_offset_t	offset_beg,
	vm_object_offset_t	offset_end,
	int                     ops,
	uint32_t		*range)
{
        vm_object_offset_t	offset;
	vm_page_t		dst_page;

	if (offset_end - offset_beg > (uint32_t) -1) {
		/* range is too big and would overflow "*range" */
		return KERN_INVALID_ARGUMENT;
	} 
	if (object->resident_page_count == 0) {
	        if (range) {
		        if (ops & UPL_ROP_PRESENT) {
			        *range = 0;
			} else {
			        *range = (uint32_t) (offset_end - offset_beg);
				assert(*range == (offset_end - offset_beg));
			}
		}
		return KERN_SUCCESS;
	}
	vm_object_lock(object);

	if (object->phys_contiguous) {
		vm_object_unlock(object);
	        return KERN_INVALID_OBJECT;
	}
	
	offset = offset_beg & ~PAGE_MASK_64;

	while (offset < offset_end) {
		dst_page = vm_page_lookup(object, offset);
		if (dst_page != VM_PAGE_NULL) {
			if (ops & UPL_ROP_DUMP) {
				if (dst_page->busy || dst_page->cleaning) {
					/*
					 * someone else is playing with the 
					 * page, we will have to wait
					 */
				        PAGE_SLEEP(object, dst_page, THREAD_UNINT);
					/*
					 * need to relook the page up since it's
					 * state may have changed while we slept
					 * it might even belong to a different object
					 * at this point
					 */
					continue;
				}
				if (dst_page->laundry) {
					dst_page->pageout = FALSE;
					
					vm_pageout_steal_laundry(dst_page, FALSE);
				}
				if (dst_page->pmapped == TRUE)
				        pmap_disconnect(dst_page->phys_page);

				VM_PAGE_FREE(dst_page);

			} else if ((ops & UPL_ROP_ABSENT) && !dst_page->absent)
			        break;
		} else if (ops & UPL_ROP_PRESENT)
		        break;

		offset += PAGE_SIZE;
	}
	vm_object_unlock(object);

	if (range) {
	        if (offset > offset_end)
		        offset = offset_end;
		if(offset > offset_beg) {
			*range = (uint32_t) (offset - offset_beg);
			assert(*range == (offset - offset_beg));
		} else {
			*range = 0;
		}
	}
	return KERN_SUCCESS;
}

/*
 * Used to point a pager directly to a range of memory (when the pager may be associated
 *   with a non-device vnode).  Takes a virtual address, an offset, and a size.  We currently
 *   expect that the virtual address will denote the start of a range that is physically contiguous.
 */
kern_return_t pager_map_to_phys_contiguous(
	memory_object_control_t	object,
	memory_object_offset_t	offset,
	addr64_t		base_vaddr,
	vm_size_t		size)
{
	ppnum_t page_num;
	boolean_t clobbered_private;
	kern_return_t retval;
	vm_object_t pager_object;

	page_num = pmap_find_phys(kernel_pmap, base_vaddr);

	if (!page_num) {
		retval = KERN_FAILURE;
		goto out;
	}

	pager_object = memory_object_control_to_vm_object(object);

	if (!pager_object) {
		retval = KERN_FAILURE;
		goto out;
	}

	clobbered_private = pager_object->private;
	pager_object->private = TRUE;
	retval = vm_object_populate_with_private(pager_object, offset, page_num, size);

	if (retval != KERN_SUCCESS)
		pager_object->private = clobbered_private;

out:
	return retval;
}

uint32_t scan_object_collision = 0;

void
vm_object_lock(vm_object_t object)
{
        if (object == vm_pageout_scan_wants_object) {
	        scan_object_collision++;
	        mutex_pause(2);
	}
        lck_rw_lock_exclusive(&object->Lock);
}

boolean_t
vm_object_lock_avoid(vm_object_t object)
{
        if (object == vm_pageout_scan_wants_object) {
	        scan_object_collision++;
		return TRUE;
	}
	return FALSE;
}

boolean_t
_vm_object_lock_try(vm_object_t object)
{
	return (lck_rw_try_lock_exclusive(&object->Lock));
}

boolean_t
vm_object_lock_try(vm_object_t object)
{
	/*
	 * Called from hibernate path so check before blocking.
	 */
	if (vm_object_lock_avoid(object) && ml_get_interrupts_enabled() && get_preemption_level()==0) {
		mutex_pause(2);
	}
	return _vm_object_lock_try(object);
}

void
vm_object_lock_shared(vm_object_t object)
{
        if (vm_object_lock_avoid(object)) {
	        mutex_pause(2);
	}
	lck_rw_lock_shared(&object->Lock);
}

boolean_t
vm_object_lock_try_shared(vm_object_t object)
{
        if (vm_object_lock_avoid(object)) {
	        mutex_pause(2);
	}
	return (lck_rw_try_lock_shared(&object->Lock));
}


unsigned int vm_object_change_wimg_mode_count = 0;

/*
 * The object must be locked
 */
void
vm_object_change_wimg_mode(vm_object_t object, unsigned int wimg_mode)
{
	vm_page_t p;

	vm_object_lock_assert_exclusive(object);

	vm_object_paging_wait(object, THREAD_UNINT);

	queue_iterate(&object->memq, p, vm_page_t, listq) {

		if (!p->fictitious)
			pmap_set_cache_attributes(p->phys_page, wimg_mode);
	}
	if (wimg_mode == VM_WIMG_USE_DEFAULT)
		object->set_cache_attr = FALSE;
	else
		object->set_cache_attr = TRUE;

	object->wimg_bits = wimg_mode;

	vm_object_change_wimg_mode_count++;
}

#if CONFIG_FREEZE

kern_return_t vm_object_pack(
	unsigned int	*purgeable_count,
	unsigned int	*wired_count,
	unsigned int	*clean_count,
	unsigned int	*dirty_count,
	unsigned int	dirty_budget,
	boolean_t	*shared,
	vm_object_t	src_object,
	struct default_freezer_handle *df_handle)
{
	kern_return_t	kr = KERN_SUCCESS;
	
	vm_object_lock(src_object);

	*purgeable_count = *wired_count = *clean_count = *dirty_count = 0;
	*shared = FALSE;

	if (!src_object->alive || src_object->terminating){
		kr = KERN_FAILURE;
		goto done;
	}

	if (src_object->purgable == VM_PURGABLE_VOLATILE) {
		*purgeable_count = src_object->resident_page_count;
		
		/* If the default freezer handle is null, we're just walking the pages to discover how many can be hibernated */
		if (df_handle != NULL) {
			purgeable_q_t queue;
			/* object should be on a queue */
			assert(src_object->objq.next != NULL &&
			       src_object->objq.prev != NULL);

			queue = vm_purgeable_object_remove(src_object);
			assert(queue);
			if (src_object->purgeable_when_ripe) {
				vm_page_lock_queues();
				vm_purgeable_token_delete_first(queue);
				vm_page_unlock_queues();
			}

			vm_object_purge(src_object, 0);
			assert(src_object->purgable == VM_PURGABLE_EMPTY);

			/*
			 * This object was "volatile" so its pages must have
			 * already been accounted as "volatile": no change
			 * in accounting now that it's "empty".
			 */
		}
		goto done;
	}

	if (src_object->ref_count == 1) {
		vm_object_pack_pages(wired_count, clean_count, dirty_count, dirty_budget, src_object, df_handle);
	} else {
		if (src_object->internal) {
			*shared = TRUE;
		}
	}
done:
	vm_object_unlock(src_object);
	
	return kr;
}


void
vm_object_pack_pages(
	unsigned int		*wired_count,
	unsigned int		*clean_count,
	unsigned int		*dirty_count,
	unsigned int		dirty_budget,
	vm_object_t		src_object,
	struct default_freezer_handle *df_handle)
{
	vm_page_t p, next;

	next = (vm_page_t)queue_first(&src_object->memq);

	while (!queue_end(&src_object->memq, (queue_entry_t)next)) {
		p = next;
		next = (vm_page_t)queue_next(&next->listq);
		
		/* Finish up if we've hit our pageout limit */
		if (dirty_budget && (dirty_budget == *dirty_count)) {
			break;
		}
		assert(!p->laundry);

		if (p->fictitious || p->busy ) 
			continue;
		
		if (p->absent || p->unusual || p->error)
			continue;
		
		if (VM_PAGE_WIRED(p)) {
			(*wired_count)++;
			continue;
		}
		
		if (df_handle == NULL) {
			if (p->dirty || pmap_is_modified(p->phys_page)) {
				(*dirty_count)++;
			} else {
				(*clean_count)++;				
			}
			continue;
		}
		
		if (p->cleaning) {
			p->pageout = TRUE;
			continue;
		}

		if (p->pmapped == TRUE) {
			int refmod_state;
		 	refmod_state = pmap_disconnect(p->phys_page);
			if (refmod_state & VM_MEM_MODIFIED) {
				SET_PAGE_DIRTY(p, FALSE);
			}
		}
		
		if (p->dirty) {
			default_freezer_pack_page(p, df_handle);	
			(*dirty_count)++;
		}
		else {
			VM_PAGE_FREE(p);
			(*clean_count)++;
		}
	}
}

void
vm_object_pageout(
	vm_object_t object)
{
	vm_page_t 			p, next;
	struct	vm_pageout_queue 	*iq;
	boolean_t			set_pageout_bit = FALSE;

	iq = &vm_pageout_queue_internal;
	
	assert(object != VM_OBJECT_NULL );
	
	vm_object_lock(object);

	if (DEFAULT_PAGER_IS_ACTIVE || DEFAULT_FREEZER_IS_ACTIVE) {
		if (!object->pager_initialized) {
			/*
		 	*   If there is no memory object for the page, create
		 	*   one and hand it to the default pager.
		 	*/
			vm_object_pager_create(object);
		}

		set_pageout_bit = TRUE;
	}
			
	if (COMPRESSED_PAGER_IS_ACTIVE || DEFAULT_FREEZER_COMPRESSED_PAGER_IS_ACTIVE) {

		set_pageout_bit = FALSE;
	}

ReScan:	
	next = (vm_page_t)queue_first(&object->memq);

	while (!queue_end(&object->memq, (queue_entry_t)next)) {
		p = next;
		next = (vm_page_t)queue_next(&next->listq);
		
		/* Throw to the pageout queue */
		vm_page_lockspin_queues();

		/*
		 * see if page is already in the process of
		 * being cleaned... if so, leave it alone
		 */
		if (!p->laundry) {

			if (COMPRESSED_PAGER_IS_ACTIVE || DEFAULT_FREEZER_COMPRESSED_PAGER_IS_ACTIVE) {

				if (VM_PAGE_Q_THROTTLED(iq)) {
					
					iq->pgo_draining = TRUE;
					
					assert_wait((event_t) (&iq->pgo_laundry + 1), THREAD_INTERRUPTIBLE);
					vm_page_unlock_queues();
					vm_object_unlock(object);
					
					thread_block(THREAD_CONTINUE_NULL);

					vm_object_lock(object);
					goto ReScan;
				}

				if (p->fictitious || p->busy ) {
					vm_page_unlock_queues();
					continue;
				}
				
				if (p->absent || p->unusual || p->error || VM_PAGE_WIRED(p)) {
					vm_page_unlock_queues();
					continue;
				}
				
				if (p->cleaning) {
					p->pageout = TRUE;
					vm_page_unlock_queues();
					continue;
				}

				if (p->pmapped == TRUE) {
					int refmod_state;
		        		refmod_state = pmap_disconnect_options(p->phys_page, PMAP_OPTIONS_COMPRESSOR, NULL);
					if (refmod_state & VM_MEM_MODIFIED) {
						SET_PAGE_DIRTY(p, FALSE);
					}
				}
				
				if (p->dirty == FALSE) {
					vm_page_unlock_queues();
					VM_PAGE_FREE(p);
					continue;
				}
			}

			VM_PAGE_QUEUES_REMOVE(p);
			vm_pageout_cluster(p, set_pageout_bit);
		}
		vm_page_unlock_queues();
	}

	vm_object_unlock(object);
}

kern_return_t
vm_object_pagein(
	vm_object_t object)
{
	memory_object_t	pager;
	kern_return_t	kr;

	vm_object_lock(object);

	pager = object->pager;

	if (!object->pager_ready || pager == MEMORY_OBJECT_NULL) {
		vm_object_unlock(object);
		return KERN_FAILURE;
	}
	
	vm_object_paging_wait(object, THREAD_UNINT);
	vm_object_paging_begin(object);

	object->blocked_access = TRUE;
	vm_object_unlock(object);
	
	kr = memory_object_data_reclaim(pager, TRUE);

	vm_object_lock(object);

	object->blocked_access = FALSE;
	vm_object_paging_end(object);

	vm_object_unlock(object);
	
	return kr;
}
#endif /* CONFIG_FREEZE */


#if CONFIG_IOSCHED
void
vm_page_request_reprioritize(vm_object_t o, uint64_t blkno, uint32_t len, int prio)
{
	io_reprioritize_req_t 	req;
	struct vnode 		*devvp = NULL;	

	if(vnode_pager_get_object_devvp(o->pager, (uintptr_t *)&devvp) != KERN_SUCCESS)
		return;
	
	/* Create the request for I/O reprioritization */
	req = (io_reprioritize_req_t)zalloc(io_reprioritize_req_zone);
	assert(req != NULL);
	req->blkno = blkno;
	req->len = len;
	req->priority = prio;
	req->devvp = devvp;

	/* Insert request into the reprioritization list */
	IO_REPRIORITIZE_LIST_LOCK();
	queue_enter(&io_reprioritize_list, req, io_reprioritize_req_t, io_reprioritize_list);
	IO_REPRIORITIZE_LIST_UNLOCK();

	/* Wakeup reprioritize thread */
	IO_REPRIO_THREAD_WAKEUP();	

	return;		
}	

void
vm_decmp_upl_reprioritize(upl_t upl, int prio)
{
	int offset;
	vm_object_t object;
	io_reprioritize_req_t 	req;
	struct vnode            *devvp = NULL;
	uint64_t 		blkno;
	uint32_t 		len;
	upl_t 			io_upl;
	uint64_t 		*io_upl_reprio_info;
	int 			io_upl_size;

	if ((upl->flags & UPL_TRACKED_BY_OBJECT) == 0 || (upl->flags & UPL_EXPEDITE_SUPPORTED) == 0)
		return;

	/* 
	 * We dont want to perform any allocations with the upl lock held since that might 
	 * result in a deadlock. If the system is low on memory, the pageout thread would 
	 * try to pageout stuff and might wait on this lock. If we are waiting for the memory to
	 * be freed up by the pageout thread, it would be a deadlock.
	 */


	/* First step is just to get the size of the upl to find out how big the reprio info is */
	upl_lock(upl);
	if (upl->decmp_io_upl == NULL) {
		/* The real I/O upl was destroyed by the time we came in here. Nothing to do. */
		upl_unlock(upl);
		return;
	}

	io_upl = upl->decmp_io_upl;
	assert((io_upl->flags & UPL_DECMP_REAL_IO) != 0);
	io_upl_size = io_upl->size;
	upl_unlock(upl);
	
	/* Now perform the allocation */
	io_upl_reprio_info = (uint64_t *)kalloc(sizeof(uint64_t) * (io_upl_size / PAGE_SIZE));
	if (io_upl_reprio_info == NULL)
		return;

	/* Now again take the lock, recheck the state and grab out the required info */
	upl_lock(upl);
	if (upl->decmp_io_upl == NULL || upl->decmp_io_upl != io_upl) {
		/* The real I/O upl was destroyed by the time we came in here. Nothing to do. */
		upl_unlock(upl);
		goto out;
	}
	memcpy(io_upl_reprio_info, io_upl->upl_reprio_info, sizeof(uint64_t) * (io_upl_size / PAGE_SIZE));

	/* Get the VM object for this UPL */
	if (io_upl->flags & UPL_SHADOWED) {
		object = io_upl->map_object->shadow;
	} else {
		object = io_upl->map_object;
	}

	/* Get the dev vnode ptr for this object */
	if(!object || !object->pager || 
	   vnode_pager_get_object_devvp(object->pager, (uintptr_t *)&devvp) != KERN_SUCCESS) {
		upl_unlock(upl);
		goto out;
	}

	upl_unlock(upl);

	/* Now we have all the information needed to do the expedite */

	offset = 0;
	while (offset < io_upl_size) {
		blkno 	= io_upl_reprio_info[(offset / PAGE_SIZE)] & UPL_REPRIO_INFO_MASK;
		len 	= (io_upl_reprio_info[(offset / PAGE_SIZE)] >> UPL_REPRIO_INFO_SHIFT) & UPL_REPRIO_INFO_MASK;	

		/*
		 * This implementation may cause some spurious expedites due to the 
		 * fact that we dont cleanup the blkno & len from the upl_reprio_info 
		 * even after the I/O is complete. 
		 */
		
		if (blkno != 0 && len != 0) {
			/* Create the request for I/O reprioritization */
       	 		req = (io_reprioritize_req_t)zalloc(io_reprioritize_req_zone);
        		assert(req != NULL);
        		req->blkno = blkno;
        		req->len = len;
        		req->priority = prio;
        		req->devvp = devvp;

        		/* Insert request into the reprioritization list */
        		IO_REPRIORITIZE_LIST_LOCK();
        		queue_enter(&io_reprioritize_list, req, io_reprioritize_req_t, io_reprioritize_list);
        		IO_REPRIORITIZE_LIST_UNLOCK();		
			
			offset += len;
		} else {
			offset += PAGE_SIZE;
		}
	}

	/* Wakeup reprioritize thread */
        IO_REPRIO_THREAD_WAKEUP();

out:
	kfree(io_upl_reprio_info, sizeof(uint64_t) * (io_upl_size / PAGE_SIZE));
	return;
}

void
vm_page_handle_prio_inversion(vm_object_t o, vm_page_t m)
{
	upl_t upl;
        upl_page_info_t *pl;
        unsigned int i, num_pages;
        int cur_tier;

	cur_tier = proc_get_effective_thread_policy(current_thread(), TASK_POLICY_IO);

	/* 
	Scan through all UPLs associated with the object to find the 
	UPL containing the contended page.
	*/ 
	queue_iterate(&o->uplq, upl, upl_t, uplq) {
		if (((upl->flags & UPL_EXPEDITE_SUPPORTED) == 0) || upl->upl_priority <= cur_tier)
			continue;
		pl = UPL_GET_INTERNAL_PAGE_LIST(upl);
                num_pages = (upl->size / PAGE_SIZE);
                
		/*
		For each page in the UPL page list, see if it matches the contended
		page and was issued as a low prio I/O. 
		*/
		for(i=0; i < num_pages; i++) {
			if(UPL_PAGE_PRESENT(pl,i) && m->phys_page == pl[i].phys_addr) {
				if ((upl->flags & UPL_DECMP_REQ) && upl->decmp_io_upl) {
                        		KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, VM_PAGE_EXPEDITE)) | DBG_FUNC_NONE, upl->upl_creator, m, upl, upl->upl_priority, 0);
					vm_decmp_upl_reprioritize(upl, cur_tier);
					break;
				}
				KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, VM_PAGE_EXPEDITE)) | DBG_FUNC_NONE, upl->upl_creator, m, upl->upl_reprio_info[i], upl->upl_priority, 0);
				if (UPL_REPRIO_INFO_BLKNO(upl, i) != 0 && UPL_REPRIO_INFO_LEN(upl, i) != 0) 
					vm_page_request_reprioritize(o, UPL_REPRIO_INFO_BLKNO(upl, i), UPL_REPRIO_INFO_LEN(upl, i), cur_tier);
                                break;
                         }
		 }
		 /* Check if we found any hits */
                 if (i != num_pages)
			break;
	}
	
	return;
}	

wait_result_t
vm_page_sleep(vm_object_t o, vm_page_t m, int interruptible)
{
	wait_result_t ret;

	KERNEL_DEBUG((MACHDBG_CODE(DBG_MACH_VM, VM_PAGE_SLEEP)) | DBG_FUNC_START, o, m, 0, 0, 0);	
	
	if (o->io_tracking && ((m->busy == TRUE) || (m->cleaning == TRUE) || VM_PAGE_WIRED(m))) {
		/* 
		Indicates page is busy due to an I/O. Issue a reprioritize request if necessary.
		*/
		vm_page_handle_prio_inversion(o,m);
	}
	m->wanted = TRUE;
	ret = thread_sleep_vm_object(o, m, interruptible);
	KERNEL_DEBUG((MACHDBG_CODE(DBG_MACH_VM, VM_PAGE_SLEEP)) | DBG_FUNC_END, o, m, 0, 0, 0);
	return ret;
}

static void
io_reprioritize_thread(void *param __unused, wait_result_t wr __unused)
{
	io_reprioritize_req_t   req = NULL;
	
	while(1) {

		IO_REPRIORITIZE_LIST_LOCK();
		if (queue_empty(&io_reprioritize_list)) {
			IO_REPRIORITIZE_LIST_UNLOCK();
			break;
		}
			
		queue_remove_first(&io_reprioritize_list, req, io_reprioritize_req_t, io_reprioritize_list);   
		IO_REPRIORITIZE_LIST_UNLOCK();
		
		vnode_pager_issue_reprioritize_io(req->devvp, req->blkno, req->len, req->priority);
		zfree(io_reprioritize_req_zone, req);	
	}	
	
	IO_REPRIO_THREAD_CONTINUATION();
}
#endif
