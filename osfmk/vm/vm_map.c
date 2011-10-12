/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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
 *	File:	vm/vm_map.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Virtual memory mapping module.
 */

#include <task_swapper.h>
#include <mach_assert.h>
#include <libkern/OSAtomic.h>

#include <mach/kern_return.h>
#include <mach/port.h>
#include <mach/vm_attributes.h>
#include <mach/vm_param.h>
#include <mach/vm_behavior.h>
#include <mach/vm_statistics.h>
#include <mach/memory_object.h>
#include <mach/mach_vm.h>
#include <machine/cpu_capabilities.h>
#include <mach/sdt.h>

#include <kern/assert.h>
#include <kern/counters.h>
#include <kern/kalloc.h>
#include <kern/zalloc.h>

#include <vm/cpm.h>
#include <vm/vm_init.h>
#include <vm/vm_fault.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_kern.h>
#include <ipc/ipc_port.h>
#include <kern/sched_prim.h>
#include <kern/misc_protos.h>
#include <machine/db_machdep.h>
#include <kern/xpr.h>

#include <mach/vm_map_server.h>
#include <mach/mach_host_server.h>
#include <vm/vm_protos.h>
#include <vm/vm_purgeable_internal.h>

#include <vm/vm_protos.h>
#include <vm/vm_shared_region.h>
#include <vm/vm_map_store.h>

/* Internal prototypes
 */

static void vm_map_simplify_range(
	vm_map_t	map,
	vm_map_offset_t	start,
	vm_map_offset_t	end);	/* forward */

static boolean_t	vm_map_range_check(
	vm_map_t	map,
	vm_map_offset_t	start,
	vm_map_offset_t	end,
	vm_map_entry_t	*entry);

static vm_map_entry_t	_vm_map_entry_create(
	struct vm_map_header	*map_header);

static void		_vm_map_entry_dispose(
	struct vm_map_header	*map_header,
	vm_map_entry_t		entry);

static void		vm_map_pmap_enter(
	vm_map_t		map,
	vm_map_offset_t 	addr,
	vm_map_offset_t		end_addr,
	vm_object_t 		object,
	vm_object_offset_t	offset,
	vm_prot_t		protection);

static void		_vm_map_clip_end(
	struct vm_map_header	*map_header,
	vm_map_entry_t		entry,
	vm_map_offset_t		end);

static void		_vm_map_clip_start(
	struct vm_map_header	*map_header,
	vm_map_entry_t		entry,
	vm_map_offset_t		start);

static void		vm_map_entry_delete(
	vm_map_t	map,
	vm_map_entry_t	entry);

static kern_return_t	vm_map_delete(
	vm_map_t	map,
	vm_map_offset_t	start,
	vm_map_offset_t	end,
	int		flags,
	vm_map_t	zap_map);

static kern_return_t	vm_map_copy_overwrite_unaligned(
	vm_map_t	dst_map,
	vm_map_entry_t	entry,
	vm_map_copy_t	copy,
	vm_map_address_t start);

static kern_return_t	vm_map_copy_overwrite_aligned(
	vm_map_t	dst_map,
	vm_map_entry_t	tmp_entry,
	vm_map_copy_t	copy,
	vm_map_offset_t start,
	pmap_t		pmap);

static kern_return_t	vm_map_copyin_kernel_buffer(
	vm_map_t	src_map,
	vm_map_address_t src_addr,
	vm_map_size_t	len,
	boolean_t	src_destroy,
	vm_map_copy_t	*copy_result);  /* OUT */

static kern_return_t	vm_map_copyout_kernel_buffer(
	vm_map_t	map,
	vm_map_address_t *addr,	/* IN/OUT */
	vm_map_copy_t	copy,
	boolean_t	overwrite);

static void		vm_map_fork_share(
	vm_map_t	old_map,
	vm_map_entry_t	old_entry,
	vm_map_t	new_map);

static boolean_t	vm_map_fork_copy(
	vm_map_t	old_map,
	vm_map_entry_t	*old_entry_p,
	vm_map_t	new_map);

void		vm_map_region_top_walk(
	vm_map_entry_t		   entry,
	vm_region_top_info_t       top);

void		vm_map_region_walk(
	vm_map_t		   map,
	vm_map_offset_t		   va,
	vm_map_entry_t		   entry,
	vm_object_offset_t	   offset,
	vm_object_size_t	   range,
	vm_region_extended_info_t  extended,
	boolean_t		   look_for_pages);

static kern_return_t	vm_map_wire_nested(
	vm_map_t		   map,
	vm_map_offset_t		   start,
	vm_map_offset_t		   end,
	vm_prot_t		   access_type,
	boolean_t		   user_wire,
	pmap_t			   map_pmap, 
	vm_map_offset_t		   pmap_addr);

static kern_return_t	vm_map_unwire_nested(
	vm_map_t		   map,
	vm_map_offset_t		   start,
	vm_map_offset_t		   end,
	boolean_t		   user_wire,
	pmap_t			   map_pmap,
	vm_map_offset_t		   pmap_addr);

static kern_return_t	vm_map_overwrite_submap_recurse(
	vm_map_t		   dst_map,
	vm_map_offset_t		   dst_addr,
	vm_map_size_t		   dst_size);

static kern_return_t	vm_map_copy_overwrite_nested(
	vm_map_t		   dst_map,
	vm_map_offset_t		   dst_addr,
	vm_map_copy_t		   copy,
	boolean_t		   interruptible,
	pmap_t			   pmap,
	boolean_t		   discard_on_success);

static kern_return_t	vm_map_remap_extract(
	vm_map_t		map,
	vm_map_offset_t		addr,
	vm_map_size_t		size,
	boolean_t		copy,
	struct vm_map_header 	*map_header,
	vm_prot_t		*cur_protection,
	vm_prot_t		*max_protection,
	vm_inherit_t		inheritance,
	boolean_t		pageable);

static kern_return_t	vm_map_remap_range_allocate(
	vm_map_t		map,
	vm_map_address_t	*address,
	vm_map_size_t		size,
	vm_map_offset_t		mask,
	int			flags,
	vm_map_entry_t		*map_entry);

static void		vm_map_region_look_for_page(
	vm_map_t		   map,
	vm_map_offset_t            va,
	vm_object_t		   object,
	vm_object_offset_t	   offset,
	int                        max_refcnt,
	int                        depth,
	vm_region_extended_info_t  extended);

static int		vm_map_region_count_obj_refs(
	vm_map_entry_t    	   entry,
	vm_object_t       	   object);


static kern_return_t	vm_map_willneed(
	vm_map_t	map,
	vm_map_offset_t	start,
	vm_map_offset_t	end);

static kern_return_t	vm_map_reuse_pages(
	vm_map_t	map,
	vm_map_offset_t	start,
	vm_map_offset_t	end);

static kern_return_t	vm_map_reusable_pages(
	vm_map_t	map,
	vm_map_offset_t	start,
	vm_map_offset_t	end);

static kern_return_t	vm_map_can_reuse(
	vm_map_t	map,
	vm_map_offset_t	start,
	vm_map_offset_t	end);

#if CONFIG_FREEZE
struct default_freezer_table;
__private_extern__ void* default_freezer_mapping_create(vm_object_t, vm_offset_t);
__private_extern__ void  default_freezer_mapping_free(void**, boolean_t all);	
#endif

/*
 * Macros to copy a vm_map_entry. We must be careful to correctly
 * manage the wired page count. vm_map_entry_copy() creates a new
 * map entry to the same memory - the wired count in the new entry
 * must be set to zero. vm_map_entry_copy_full() creates a new
 * entry that is identical to the old entry.  This preserves the
 * wire count; it's used for map splitting and zone changing in
 * vm_map_copyout.
 */
#define vm_map_entry_copy(NEW,OLD) \
MACRO_BEGIN                                     \
	*(NEW) = *(OLD);                \
	(NEW)->is_shared = FALSE;	\
	(NEW)->needs_wakeup = FALSE;    \
	(NEW)->in_transition = FALSE;   \
	(NEW)->wired_count = 0;         \
	(NEW)->user_wired_count = 0;    \
	(NEW)->permanent = FALSE;	\
MACRO_END

#define vm_map_entry_copy_full(NEW,OLD)        (*(NEW) = *(OLD))

/*
 *	Decide if we want to allow processes to execute from their data or stack areas.
 *	override_nx() returns true if we do.  Data/stack execution can be enabled independently 
 *	for 32 and 64 bit processes.  Set the VM_ABI_32 or VM_ABI_64 flags in allow_data_exec
 *	or allow_stack_exec to enable data execution for that type of data area for that particular
 *	ABI (or both by or'ing the flags together).  These are initialized in the architecture
 *	specific pmap files since the default behavior varies according to architecture.  The 
 *	main reason it varies is because of the need to provide binary compatibility with old 
 *	applications that were written before these restrictions came into being.  In the old 
 *	days, an app could execute anything it could read, but this has slowly been tightened 
 *	up over time.  The default behavior is:
 *
 *	32-bit PPC apps		may execute from both stack and data areas
 *	32-bit Intel apps	may exeucte from data areas but not stack
 *	64-bit PPC/Intel apps	may not execute from either data or stack
 *
 *	An application on any architecture may override these defaults by explicitly
 *	adding PROT_EXEC permission to the page in question with the mprotect(2) 
 *	system call.  This code here just determines what happens when an app tries to
 * 	execute from a page that lacks execute permission.
 *
 *	Note that allow_data_exec or allow_stack_exec may also be modified by sysctl to change the
 *	default behavior for both 32 and 64 bit apps on a system-wide basis. Furthermore,
 *	a Mach-O header flag bit (MH_NO_HEAP_EXECUTION) can be used to forcibly disallow
 *	execution from data areas for a particular binary even if the arch normally permits it. As
 *	a final wrinkle, a posix_spawn attribute flag can be used to negate this opt-in header bit
 *	to support some complicated use cases, notably browsers with out-of-process plugins that
 *	are not all NX-safe.
 */

extern int allow_data_exec, allow_stack_exec;

int
override_nx(vm_map_t map, uint32_t user_tag) /* map unused on arm */
{
	int current_abi;

	/*
	 * Determine if the app is running in 32 or 64 bit mode.
	 */

	if (vm_map_is_64bit(map))
		current_abi = VM_ABI_64;
	else
		current_abi = VM_ABI_32;

	/*
	 * Determine if we should allow the execution based on whether it's a 
	 * stack or data area and the current architecture.
	 */

	if (user_tag == VM_MEMORY_STACK)
		return allow_stack_exec & current_abi;

	return (allow_data_exec & current_abi) && (map->map_disallow_data_exec == FALSE);
}


/*
 *	Virtual memory maps provide for the mapping, protection,
 *	and sharing of virtual memory objects.  In addition,
 *	this module provides for an efficient virtual copy of
 *	memory from one map to another.
 *
 *	Synchronization is required prior to most operations.
 *
 *	Maps consist of an ordered doubly-linked list of simple
 *	entries; a single hint is used to speed up lookups.
 *
 *	Sharing maps have been deleted from this version of Mach.
 *	All shared objects are now mapped directly into the respective
 *	maps.  This requires a change in the copy on write strategy;
 *	the asymmetric (delayed) strategy is used for shared temporary
 *	objects instead of the symmetric (shadow) strategy.  All maps
 *	are now "top level" maps (either task map, kernel map or submap
 *	of the kernel map).  
 *
 *	Since portions of maps are specified by start/end addreses,
 *	which may not align with existing map entries, all
 *	routines merely "clip" entries to these start/end values.
 *	[That is, an entry is split into two, bordering at a
 *	start or end value.]  Note that these clippings may not
 *	always be necessary (as the two resulting entries are then
 *	not changed); however, the clipping is done for convenience.
 *	No attempt is currently made to "glue back together" two
 *	abutting entries.
 *
 *	The symmetric (shadow) copy strategy implements virtual copy
 *	by copying VM object references from one map to
 *	another, and then marking both regions as copy-on-write.
 *	It is important to note that only one writeable reference
 *	to a VM object region exists in any map when this strategy
 *	is used -- this means that shadow object creation can be
 *	delayed until a write operation occurs.  The symmetric (delayed)
 *	strategy allows multiple maps to have writeable references to
 *	the same region of a vm object, and hence cannot delay creating
 *	its copy objects.  See vm_object_copy_quickly() in vm_object.c.
 *	Copying of permanent objects is completely different; see
 *	vm_object_copy_strategically() in vm_object.c.
 */

static zone_t	vm_map_zone;		/* zone for vm_map structures */
static zone_t	vm_map_entry_zone;	/* zone for vm_map_entry structures */
static zone_t	vm_map_kentry_zone;	/* zone for kernel entry structures */
static zone_t	vm_map_copy_zone;	/* zone for vm_map_copy structures */


/*
 *	Placeholder object for submap operations.  This object is dropped
 *	into the range by a call to vm_map_find, and removed when
 *	vm_map_submap creates the submap.
 */

vm_object_t	vm_submap_object;

static void		*map_data;
static vm_size_t	map_data_size;
static void		*kentry_data;
static vm_size_t	kentry_data_size;
static int		kentry_count = 2048;		/* to init kentry_data_size */

#if CONFIG_EMBEDDED
#define		NO_COALESCE_LIMIT  0
#else
#define         NO_COALESCE_LIMIT  ((1024 * 128) - 1)
#endif

/* Skip acquiring locks if we're in the midst of a kernel core dump */
unsigned int not_in_kdp = 1;

unsigned int vm_map_set_cache_attr_count = 0;

kern_return_t
vm_map_set_cache_attr(
	vm_map_t	map,
	vm_map_offset_t	va)
{
	vm_map_entry_t	map_entry;
	vm_object_t	object;
	kern_return_t	kr = KERN_SUCCESS;

	vm_map_lock_read(map);

	if (!vm_map_lookup_entry(map, va, &map_entry) ||
	    map_entry->is_sub_map) {
		/*
		 * that memory is not properly mapped
		 */
		kr = KERN_INVALID_ARGUMENT;
		goto done;
	}
	object = map_entry->object.vm_object;

	if (object == VM_OBJECT_NULL) {
		/*
		 * there should be a VM object here at this point
		 */
		kr = KERN_INVALID_ARGUMENT;
		goto done;
	}
	vm_object_lock(object);
	object->set_cache_attr = TRUE;
	vm_object_unlock(object);

	vm_map_set_cache_attr_count++;
done:
	vm_map_unlock_read(map);

	return kr;
}


#if CONFIG_CODE_DECRYPTION
/*
 * vm_map_apple_protected:
 * This remaps the requested part of the object with an object backed by 
 * the decrypting pager.
 * crypt_info contains entry points and session data for the crypt module.
 * The crypt_info block will be copied by vm_map_apple_protected. The data structures
 * referenced in crypt_info must remain valid until crypt_info->crypt_end() is called.
 */
kern_return_t
vm_map_apple_protected(
	vm_map_t	map,
	vm_map_offset_t	start,
	vm_map_offset_t	end,
	struct pager_crypt_info *crypt_info)
{
	boolean_t	map_locked;
	kern_return_t	kr;
	vm_map_entry_t	map_entry;
	memory_object_t	protected_mem_obj;
	vm_object_t	protected_object;
	vm_map_offset_t	map_addr;

	vm_map_lock_read(map);
	map_locked = TRUE;

	/* lookup the protected VM object */
	if (!vm_map_lookup_entry(map,
				 start,
				 &map_entry) ||
	    map_entry->vme_end < end ||
	    map_entry->is_sub_map) {
		/* that memory is not properly mapped */
		kr = KERN_INVALID_ARGUMENT;
		goto done;
	}
	protected_object = map_entry->object.vm_object;
	if (protected_object == VM_OBJECT_NULL) {
		/* there should be a VM object here at this point */
		kr = KERN_INVALID_ARGUMENT;
		goto done;
	}

	/* make sure protected object stays alive while map is unlocked */
	vm_object_reference(protected_object);

	vm_map_unlock_read(map);
	map_locked = FALSE;

	/*
	 * Lookup (and create if necessary) the protected memory object
	 * matching that VM object.
	 * If successful, this also grabs a reference on the memory object,
	 * to guarantee that it doesn't go away before we get a chance to map
	 * it.
	 */
	protected_mem_obj = apple_protect_pager_setup(protected_object, crypt_info);

	/* release extra ref on protected object */
	vm_object_deallocate(protected_object);

	if (protected_mem_obj == NULL) {
		kr = KERN_FAILURE;
		goto done;
	}

	/* map this memory object in place of the current one */
	map_addr = start;
	kr = vm_map_enter_mem_object(map,
				     &map_addr,
				     end - start,
				     (mach_vm_offset_t) 0,
				     VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
				     (ipc_port_t) protected_mem_obj,
				     (map_entry->offset +
				      (start - map_entry->vme_start)),
				     TRUE,
				     map_entry->protection,
				     map_entry->max_protection,
				     map_entry->inheritance);
	assert(map_addr == start);
	/*
	 * Release the reference obtained by apple_protect_pager_setup().
	 * The mapping (if it succeeded) is now holding a reference on the
	 * memory object.
	 */
	memory_object_deallocate(protected_mem_obj);

done:
	if (map_locked) {
		vm_map_unlock_read(map);
	}
	return kr;
}
#endif	/* CONFIG_CODE_DECRYPTION */


lck_grp_t		vm_map_lck_grp;
lck_grp_attr_t	vm_map_lck_grp_attr;
lck_attr_t		vm_map_lck_attr;


/*
 *	vm_map_init:
 *
 *	Initialize the vm_map module.  Must be called before
 *	any other vm_map routines.
 *
 *	Map and entry structures are allocated from zones -- we must
 *	initialize those zones.
 *
 *	There are three zones of interest:
 *
 *	vm_map_zone:		used to allocate maps.
 *	vm_map_entry_zone:	used to allocate map entries.
 *	vm_map_kentry_zone:	used to allocate map entries for the kernel.
 *
 *	The kernel allocates map entries from a special zone that is initially
 *	"crammed" with memory.  It would be difficult (perhaps impossible) for
 *	the kernel to allocate more memory to a entry zone when it became
 *	empty since the very act of allocating memory implies the creation
 *	of a new entry.
 */
void
vm_map_init(
	void)
{
	vm_map_zone = zinit((vm_map_size_t) sizeof(struct _vm_map), 40*1024,
			    PAGE_SIZE, "maps");
	zone_change(vm_map_zone, Z_NOENCRYPT, TRUE);

	vm_map_entry_zone = zinit((vm_map_size_t) sizeof(struct vm_map_entry),
				  1024*1024, PAGE_SIZE*5,
				  "non-kernel map entries");
	zone_change(vm_map_entry_zone, Z_NOENCRYPT, TRUE);

	vm_map_kentry_zone = zinit((vm_map_size_t) sizeof(struct vm_map_entry),
				   kentry_data_size, kentry_data_size,
				   "kernel map entries");
	zone_change(vm_map_kentry_zone, Z_NOENCRYPT, TRUE);

	vm_map_copy_zone = zinit((vm_map_size_t) sizeof(struct vm_map_copy),
				 16*1024, PAGE_SIZE, "map copies");
	zone_change(vm_map_copy_zone, Z_NOENCRYPT, TRUE);

	/*
	 *	Cram the map and kentry zones with initial data.
	 *	Set kentry_zone non-collectible to aid zone_gc().
	 */
	zone_change(vm_map_zone, Z_COLLECT, FALSE);
	zone_change(vm_map_kentry_zone, Z_COLLECT, FALSE);
	zone_change(vm_map_kentry_zone, Z_EXPAND, FALSE);
	zone_change(vm_map_kentry_zone, Z_FOREIGN, TRUE);
	zone_change(vm_map_kentry_zone, Z_CALLERACCT, FALSE); /* don't charge caller */
	zone_change(vm_map_copy_zone, Z_CALLERACCT, FALSE); /* don't charge caller */

	zcram(vm_map_zone, map_data, map_data_size);
	zcram(vm_map_kentry_zone, kentry_data, kentry_data_size);
	
	lck_grp_attr_setdefault(&vm_map_lck_grp_attr);
	lck_grp_init(&vm_map_lck_grp, "vm_map", &vm_map_lck_grp_attr);
	lck_attr_setdefault(&vm_map_lck_attr);	
}

void
vm_map_steal_memory(
	void)
{
	map_data_size = round_page(10 * sizeof(struct _vm_map));
	map_data = pmap_steal_memory(map_data_size);

#if 0
	/*
	 * Limiting worst case: vm_map_kentry_zone needs to map each "available"
	 * physical page (i.e. that beyond the kernel image and page tables)
	 * individually; we guess at most one entry per eight pages in the
	 * real world. This works out to roughly .1 of 1% of physical memory,
	 * or roughly 1900 entries (64K) for a 64M machine with 4K pages.
	 */
#endif
	kentry_count = pmap_free_pages() / 8;


	kentry_data_size =
		round_page(kentry_count * sizeof(struct vm_map_entry));
	kentry_data = pmap_steal_memory(kentry_data_size);
}

/*
 *	vm_map_create:
 *
 *	Creates and returns a new empty VM map with
 *	the given physical map structure, and having
 *	the given lower and upper address bounds.
 */
vm_map_t
vm_map_create(
	pmap_t			pmap,
	vm_map_offset_t	min,
	vm_map_offset_t	max,
	boolean_t		pageable)
{
	static int		color_seed = 0;
	register vm_map_t	result;

	result = (vm_map_t) zalloc(vm_map_zone);
	if (result == VM_MAP_NULL)
		panic("vm_map_create");

	vm_map_first_entry(result) = vm_map_to_entry(result);
	vm_map_last_entry(result)  = vm_map_to_entry(result);
	result->hdr.nentries = 0;
	result->hdr.entries_pageable = pageable;

	vm_map_store_init( &(result->hdr) );
	
	result->size = 0;
	result->user_wire_limit = MACH_VM_MAX_ADDRESS;	/* default limit is unlimited */
	result->user_wire_size  = 0;
	result->ref_count = 1;
#if	TASK_SWAPPER
	result->res_count = 1;
	result->sw_state = MAP_SW_IN;
#endif	/* TASK_SWAPPER */
	result->pmap = pmap;
	result->min_offset = min;
	result->max_offset = max;
	result->wiring_required = FALSE;
	result->no_zero_fill = FALSE;
	result->mapped = FALSE;
	result->wait_for_space = FALSE;
	result->switch_protect = FALSE;
	result->disable_vmentry_reuse = FALSE;
	result->map_disallow_data_exec = FALSE;
	result->highest_entry_end = 0;
	result->first_free = vm_map_to_entry(result);
	result->hint = vm_map_to_entry(result);
	result->color_rr = (color_seed++) & vm_color_mask;
 	result->jit_entry_exists = FALSE;
#if CONFIG_FREEZE
	result->default_freezer_toc = NULL;
#endif
	vm_map_lock_init(result);
	lck_mtx_init_ext(&result->s_lock, &result->s_lock_ext, &vm_map_lck_grp, &vm_map_lck_attr);
	
	return(result);
}

/*
 *	vm_map_entry_create:	[ internal use only ]
 *
 *	Allocates a VM map entry for insertion in the
 *	given map (or map copy).  No fields are filled.
 */
#define	vm_map_entry_create(map) \
	_vm_map_entry_create(&(map)->hdr)

#define	vm_map_copy_entry_create(copy) \
	_vm_map_entry_create(&(copy)->cpy_hdr)

static vm_map_entry_t
_vm_map_entry_create(
	register struct vm_map_header	*map_header)
{
	register zone_t	zone;
	register vm_map_entry_t	entry;

	if (map_header->entries_pageable)
		zone = vm_map_entry_zone;
	else
		zone = vm_map_kentry_zone;

	entry = (vm_map_entry_t) zalloc(zone);
	if (entry == VM_MAP_ENTRY_NULL)
		panic("vm_map_entry_create");
	vm_map_store_update( (vm_map_t) NULL, entry, VM_MAP_ENTRY_CREATE);

	return(entry);
}

/*
 *	vm_map_entry_dispose:	[ internal use only ]
 *
 *	Inverse of vm_map_entry_create.
 *
 * 	write map lock held so no need to
 *	do anything special to insure correctness
 * 	of the stores
 */
#define	vm_map_entry_dispose(map, entry)			\
	vm_map_store_update( map, entry, VM_MAP_ENTRY_DELETE);	\
	_vm_map_entry_dispose(&(map)->hdr, (entry))

#define	vm_map_copy_entry_dispose(map, entry) \
	_vm_map_entry_dispose(&(copy)->cpy_hdr, (entry))

static void
_vm_map_entry_dispose(
	register struct vm_map_header	*map_header,
	register vm_map_entry_t		entry)
{
	register zone_t		zone;

	if (map_header->entries_pageable)
		zone = vm_map_entry_zone;
	else
		zone = vm_map_kentry_zone;

	zfree(zone, entry);
}

#if MACH_ASSERT
static boolean_t first_free_check = FALSE;
boolean_t
first_free_is_valid(
	vm_map_t	map)
{
	if (!first_free_check)
		return TRUE;
	
	return( first_free_is_valid_store( map ));	
}
#endif /* MACH_ASSERT */


#define vm_map_copy_entry_link(copy, after_where, entry)		\
	_vm_map_store_entry_link(&(copy)->cpy_hdr, after_where, (entry))

#define vm_map_copy_entry_unlink(copy, entry)				\
	_vm_map_store_entry_unlink(&(copy)->cpy_hdr, (entry))

#if	MACH_ASSERT && TASK_SWAPPER
/*
 *	vm_map_res_reference:
 *
 *	Adds another valid residence count to the given map.
 *
 *	Map is locked so this function can be called from
 *	vm_map_swapin.
 *
 */
void vm_map_res_reference(register vm_map_t map)
{
	/* assert map is locked */
	assert(map->res_count >= 0);
	assert(map->ref_count >= map->res_count);
	if (map->res_count == 0) {
		lck_mtx_unlock(&map->s_lock);
		vm_map_lock(map);
		vm_map_swapin(map);
		lck_mtx_lock(&map->s_lock);
		++map->res_count;
		vm_map_unlock(map);
	} else
		++map->res_count;
}

/*
 *	vm_map_reference_swap:
 *
 *	Adds valid reference and residence counts to the given map.
 *
 *	The map may not be in memory (i.e. zero residence count).
 *
 */
void vm_map_reference_swap(register vm_map_t map)
{
	assert(map != VM_MAP_NULL);
	lck_mtx_lock(&map->s_lock);
	assert(map->res_count >= 0);
	assert(map->ref_count >= map->res_count);
	map->ref_count++;
	vm_map_res_reference(map);
	lck_mtx_unlock(&map->s_lock);
}

/*
 *	vm_map_res_deallocate:
 *
 *	Decrement residence count on a map; possibly causing swapout.
 *
 *	The map must be in memory (i.e. non-zero residence count).
 *
 *	The map is locked, so this function is callable from vm_map_deallocate.
 *
 */
void vm_map_res_deallocate(register vm_map_t map)
{
	assert(map->res_count > 0);
	if (--map->res_count == 0) {
		lck_mtx_unlock(&map->s_lock);
		vm_map_lock(map);
		vm_map_swapout(map);
		vm_map_unlock(map);
		lck_mtx_lock(&map->s_lock);
	}
	assert(map->ref_count >= map->res_count);
}
#endif	/* MACH_ASSERT && TASK_SWAPPER */

/*
 *	vm_map_destroy:
 *
 *	Actually destroy a map.
 */
void
vm_map_destroy(
	vm_map_t	map,
	int		flags)
{	
	vm_map_lock(map);

	/* clean up regular map entries */
	(void) vm_map_delete(map, map->min_offset, map->max_offset,
			     flags, VM_MAP_NULL);
	/* clean up leftover special mappings (commpage, etc...) */
	(void) vm_map_delete(map, 0x0, 0xFFFFFFFFFFFFF000ULL,
			     flags, VM_MAP_NULL);

#if CONFIG_FREEZE
	if (map->default_freezer_toc){
		default_freezer_mapping_free( &(map->default_freezer_toc), TRUE);
	}
#endif
	vm_map_unlock(map);

	assert(map->hdr.nentries == 0);
	
	if(map->pmap)
		pmap_destroy(map->pmap);

	zfree(vm_map_zone, map);
}

#if	TASK_SWAPPER
/*
 * vm_map_swapin/vm_map_swapout
 *
 * Swap a map in and out, either referencing or releasing its resources.  
 * These functions are internal use only; however, they must be exported
 * because they may be called from macros, which are exported.
 *
 * In the case of swapout, there could be races on the residence count, 
 * so if the residence count is up, we return, assuming that a 
 * vm_map_deallocate() call in the near future will bring us back.
 *
 * Locking:
 *	-- We use the map write lock for synchronization among races.
 *	-- The map write lock, and not the simple s_lock, protects the
 *	   swap state of the map.
 *	-- If a map entry is a share map, then we hold both locks, in
 *	   hierarchical order.
 *
 * Synchronization Notes:
 *	1) If a vm_map_swapin() call happens while swapout in progress, it
 *	will block on the map lock and proceed when swapout is through.
 *	2) A vm_map_reference() call at this time is illegal, and will
 *	cause a panic.  vm_map_reference() is only allowed on resident
 *	maps, since it refuses to block.
 *	3) A vm_map_swapin() call during a swapin will block, and 
 *	proceeed when the first swapin is done, turning into a nop.
 *	This is the reason the res_count is not incremented until
 *	after the swapin is complete.
 *	4) There is a timing hole after the checks of the res_count, before
 *	the map lock is taken, during which a swapin may get the lock
 *	before a swapout about to happen.  If this happens, the swapin
 *	will detect the state and increment the reference count, causing
 *	the swapout to be a nop, thereby delaying it until a later 
 *	vm_map_deallocate.  If the swapout gets the lock first, then 
 *	the swapin will simply block until the swapout is done, and 
 *	then proceed.
 *
 * Because vm_map_swapin() is potentially an expensive operation, it
 * should be used with caution.
 *
 * Invariants:
 *	1) A map with a residence count of zero is either swapped, or
 *	   being swapped.
 *	2) A map with a non-zero residence count is either resident,
 *	   or being swapped in.
 */

int vm_map_swap_enable = 1;

void vm_map_swapin (vm_map_t map)
{
	register vm_map_entry_t entry;

	if (!vm_map_swap_enable)	/* debug */
		return;

	/*
	 * Map is locked
	 * First deal with various races.
	 */
	if (map->sw_state == MAP_SW_IN)
		/* 
		 * we raced with swapout and won.  Returning will incr.
		 * the res_count, turning the swapout into a nop.
		 */
		return;

	/*
	 * The residence count must be zero.  If we raced with another
	 * swapin, the state would have been IN; if we raced with a
	 * swapout (after another competing swapin), we must have lost
	 * the race to get here (see above comment), in which case
	 * res_count is still 0.
	 */
	assert(map->res_count == 0);

	/*
	 * There are no intermediate states of a map going out or
	 * coming in, since the map is locked during the transition.
	 */
	assert(map->sw_state == MAP_SW_OUT);

	/*
	 * We now operate upon each map entry.  If the entry is a sub- 
	 * or share-map, we call vm_map_res_reference upon it.
	 * If the entry is an object, we call vm_object_res_reference
	 * (this may iterate through the shadow chain).
	 * Note that we hold the map locked the entire time,
	 * even if we get back here via a recursive call in
	 * vm_map_res_reference.
	 */
	entry = vm_map_first_entry(map);

	while (entry != vm_map_to_entry(map)) {
		if (entry->object.vm_object != VM_OBJECT_NULL) {
			if (entry->is_sub_map) {
				vm_map_t lmap = entry->object.sub_map;
				lck_mtx_lock(&lmap->s_lock);
				vm_map_res_reference(lmap);
				lck_mtx_unlock(&lmap->s_lock);
			} else {
				vm_object_t object = entry->object.vm_object;
				vm_object_lock(object);
				/*
				 * This call may iterate through the
				 * shadow chain.
				 */
				vm_object_res_reference(object);
				vm_object_unlock(object);
			}
		}
		entry = entry->vme_next;
	}
	assert(map->sw_state == MAP_SW_OUT);
	map->sw_state = MAP_SW_IN;
}

void vm_map_swapout(vm_map_t map)
{
	register vm_map_entry_t entry;
	
	/*
	 * Map is locked
	 * First deal with various races.
	 * If we raced with a swapin and lost, the residence count
	 * will have been incremented to 1, and we simply return.
	 */
	lck_mtx_lock(&map->s_lock);
	if (map->res_count != 0) {
		lck_mtx_unlock(&map->s_lock);
		return;
	}
	lck_mtx_unlock(&map->s_lock);

	/*
	 * There are no intermediate states of a map going out or
	 * coming in, since the map is locked during the transition.
	 */
	assert(map->sw_state == MAP_SW_IN);

	if (!vm_map_swap_enable)
		return;

	/*
	 * We now operate upon each map entry.  If the entry is a sub- 
	 * or share-map, we call vm_map_res_deallocate upon it.
	 * If the entry is an object, we call vm_object_res_deallocate
	 * (this may iterate through the shadow chain).
	 * Note that we hold the map locked the entire time,
	 * even if we get back here via a recursive call in
	 * vm_map_res_deallocate.
	 */
	entry = vm_map_first_entry(map);

	while (entry != vm_map_to_entry(map)) {
		if (entry->object.vm_object != VM_OBJECT_NULL) {
			if (entry->is_sub_map) {
				vm_map_t lmap = entry->object.sub_map;
				lck_mtx_lock(&lmap->s_lock);
				vm_map_res_deallocate(lmap);
				lck_mtx_unlock(&lmap->s_lock);
			} else {
				vm_object_t object = entry->object.vm_object;
				vm_object_lock(object);
				/*
				 * This call may take a long time, 
				 * since it could actively push 
				 * out pages (if we implement it 
				 * that way).
				 */
				vm_object_res_deallocate(object);
				vm_object_unlock(object);
			}
		}
		entry = entry->vme_next;
	}
	assert(map->sw_state == MAP_SW_IN);
	map->sw_state = MAP_SW_OUT;
}

#endif	/* TASK_SWAPPER */

/*
 *	vm_map_lookup_entry:	[ internal use only ]
 *
 *	Calls into the vm map store layer to find the map 
 *	entry containing (or immediately preceding) the 
 *	specified address in the given map; the entry is returned
 *	in the "entry" parameter.  The boolean
 *	result indicates whether the address is
 *	actually contained in the map.
 */
boolean_t
vm_map_lookup_entry(
	register vm_map_t		map,
	register vm_map_offset_t	address,
	vm_map_entry_t		*entry)		/* OUT */
{
	return ( vm_map_store_lookup_entry( map, address, entry ));
}

/*
 *	Routine:	vm_map_find_space
 *	Purpose:
 *		Allocate a range in the specified virtual address map,
 *		returning the entry allocated for that range.
 *		Used by kmem_alloc, etc.
 *
 *		The map must be NOT be locked. It will be returned locked
 *		on KERN_SUCCESS, unlocked on failure.
 *
 *		If an entry is allocated, the object/offset fields
 *		are initialized to zero.
 */
kern_return_t
vm_map_find_space(
	register vm_map_t	map,
	vm_map_offset_t		*address,	/* OUT */
	vm_map_size_t		size,
	vm_map_offset_t		mask,
	int			flags,
	vm_map_entry_t		*o_entry)	/* OUT */
{
	register vm_map_entry_t	entry, new_entry;
	register vm_map_offset_t	start;
	register vm_map_offset_t	end;

	if (size == 0) {
		*address = 0;
		return KERN_INVALID_ARGUMENT;
	}

	if (flags & VM_FLAGS_GUARD_AFTER) {
		/* account for the back guard page in the size */
		size += PAGE_SIZE_64;
	}

	new_entry = vm_map_entry_create(map);

	/*
	 *	Look for the first possible address; if there's already
	 *	something at this address, we have to start after it.
	 */

	vm_map_lock(map);

	if( map->disable_vmentry_reuse == TRUE) {
		VM_MAP_HIGHEST_ENTRY(map, entry, start);
	} else {
		assert(first_free_is_valid(map));
		if ((entry = map->first_free) == vm_map_to_entry(map))
			start = map->min_offset;
		else
			start = entry->vme_end;
	}

	/*
	 *	In any case, the "entry" always precedes
	 *	the proposed new region throughout the loop:
	 */

	while (TRUE) {
		register vm_map_entry_t	next;

		/*
		 *	Find the end of the proposed new region.
		 *	Be sure we didn't go beyond the end, or
		 *	wrap around the address.
		 */

		if (flags & VM_FLAGS_GUARD_BEFORE) {
			/* reserve space for the front guard page */
			start += PAGE_SIZE_64;
		}
		end = ((start + mask) & ~mask);
			
		if (end < start) {
			vm_map_entry_dispose(map, new_entry);
			vm_map_unlock(map);
			return(KERN_NO_SPACE);
		}
		start = end;
		end += size;

		if ((end > map->max_offset) || (end < start)) {
			vm_map_entry_dispose(map, new_entry);
			vm_map_unlock(map);
			return(KERN_NO_SPACE);
		}

		/*
		 *	If there are no more entries, we must win.
		 */

		next = entry->vme_next;
		if (next == vm_map_to_entry(map))
			break;

		/*
		 *	If there is another entry, it must be
		 *	after the end of the potential new region.
		 */

		if (next->vme_start >= end)
			break;

		/*
		 *	Didn't fit -- move to the next entry.
		 */

		entry = next;
		start = entry->vme_end;
	}

	/*
	 *	At this point,
	 *		"start" and "end" should define the endpoints of the
	 *			available new range, and
	 *		"entry" should refer to the region before the new
	 *			range, and
	 *
	 *		the map should be locked.
	 */

	if (flags & VM_FLAGS_GUARD_BEFORE) {
		/* go back for the front guard page */
		start -= PAGE_SIZE_64;
	}
	*address = start;

	new_entry->vme_start = start;
	new_entry->vme_end = end;
	assert(page_aligned(new_entry->vme_start));
	assert(page_aligned(new_entry->vme_end));

	new_entry->is_shared = FALSE;
	new_entry->is_sub_map = FALSE;
	new_entry->use_pmap = FALSE;
	new_entry->object.vm_object = VM_OBJECT_NULL;
	new_entry->offset = (vm_object_offset_t) 0;

	new_entry->needs_copy = FALSE;

	new_entry->inheritance = VM_INHERIT_DEFAULT;
	new_entry->protection = VM_PROT_DEFAULT;
	new_entry->max_protection = VM_PROT_ALL;
	new_entry->behavior = VM_BEHAVIOR_DEFAULT;
	new_entry->wired_count = 0;
	new_entry->user_wired_count = 0;

	new_entry->in_transition = FALSE;
	new_entry->needs_wakeup = FALSE;
	new_entry->no_cache = FALSE;
	new_entry->permanent = FALSE;
	new_entry->superpage_size = 0;

	new_entry->alias = 0;
	new_entry->zero_wired_pages = FALSE;

	VM_GET_FLAGS_ALIAS(flags, new_entry->alias);

	/*
	 *	Insert the new entry into the list
	 */

	vm_map_store_entry_link(map, entry, new_entry);

	map->size += size;

	/*
	 *	Update the lookup hint
	 */
	SAVE_HINT_MAP_WRITE(map, new_entry);

	*o_entry = new_entry;
	return(KERN_SUCCESS);
}

int vm_map_pmap_enter_print = FALSE;
int vm_map_pmap_enter_enable = FALSE;

/*
 *	Routine:	vm_map_pmap_enter [internal only]
 *
 *	Description:
 *		Force pages from the specified object to be entered into
 *		the pmap at the specified address if they are present.
 *		As soon as a page not found in the object the scan ends.
 *
 *	Returns:
 *		Nothing.  
 *
 *	In/out conditions:
 *		The source map should not be locked on entry.
 */
static void
vm_map_pmap_enter(
	vm_map_t		map,
	register vm_map_offset_t 	addr,
	register vm_map_offset_t	end_addr,
	register vm_object_t 	object,
	vm_object_offset_t	offset,
	vm_prot_t		protection)
{
	int			type_of_fault;
	kern_return_t		kr;

	if(map->pmap == 0)
		return;

	while (addr < end_addr) {
		register vm_page_t	m;

		vm_object_lock(object);

		m = vm_page_lookup(object, offset);
		/*
		 * ENCRYPTED SWAP:
		 * The user should never see encrypted data, so do not
		 * enter an encrypted page in the page table.
		 */
		if (m == VM_PAGE_NULL || m->busy || m->encrypted ||
		    m->fictitious ||
		    (m->unusual && ( m->error || m->restart || m->absent))) {
			vm_object_unlock(object);
			return;
		}

		if (vm_map_pmap_enter_print) {
			printf("vm_map_pmap_enter:");
			printf("map: %p, addr: %llx, object: %p, offset: %llx\n",
			       map, (unsigned long long)addr, object, (unsigned long long)offset);
		}
		type_of_fault = DBG_CACHE_HIT_FAULT;
		kr = vm_fault_enter(m, map->pmap, addr, protection, protection,
				    VM_PAGE_WIRED(m), FALSE, FALSE, FALSE,
				    &type_of_fault);

		vm_object_unlock(object);

		offset += PAGE_SIZE_64;
		addr += PAGE_SIZE;
	}
}

boolean_t vm_map_pmap_is_empty(
	vm_map_t	map,
	vm_map_offset_t	start,
	vm_map_offset_t end);
boolean_t vm_map_pmap_is_empty(
	vm_map_t	map,
	vm_map_offset_t	start,
	vm_map_offset_t	end)
{
#ifdef MACHINE_PMAP_IS_EMPTY
	return pmap_is_empty(map->pmap, start, end);
#else 	/* MACHINE_PMAP_IS_EMPTY */
	vm_map_offset_t	offset;
	ppnum_t		phys_page;

	if (map->pmap == NULL) {
		return TRUE;
	}

	for (offset = start;
	     offset < end;
	     offset += PAGE_SIZE) {
		phys_page = pmap_find_phys(map->pmap, offset);
		if (phys_page) {
			kprintf("vm_map_pmap_is_empty(%p,0x%llx,0x%llx): "
				"page %d at 0x%llx\n",
				map, (long long)start, (long long)end,
				phys_page, (long long)offset);
			return FALSE;
		}
	}
	return TRUE;
#endif	/* MACHINE_PMAP_IS_EMPTY */
}

/*
 *	Routine:	vm_map_enter
 *
 *	Description:
 *		Allocate a range in the specified virtual address map.
 *		The resulting range will refer to memory defined by
 *		the given memory object and offset into that object.
 *
 *		Arguments are as defined in the vm_map call.
 */
int _map_enter_debug = 0;
static unsigned int vm_map_enter_restore_successes = 0;
static unsigned int vm_map_enter_restore_failures = 0;
kern_return_t
vm_map_enter(
	vm_map_t		map,
	vm_map_offset_t		*address,	/* IN/OUT */
	vm_map_size_t		size,
	vm_map_offset_t		mask,
	int			flags,
	vm_object_t		object,
	vm_object_offset_t	offset,
	boolean_t		needs_copy,
	vm_prot_t		cur_protection,
	vm_prot_t		max_protection,
	vm_inherit_t		inheritance)
{
	vm_map_entry_t		entry, new_entry;
	vm_map_offset_t		start, tmp_start, tmp_offset;
	vm_map_offset_t		end, tmp_end;
	vm_map_offset_t		tmp2_start, tmp2_end;
	vm_map_offset_t		step;
	kern_return_t		result = KERN_SUCCESS;
	vm_map_t		zap_old_map = VM_MAP_NULL;
	vm_map_t		zap_new_map = VM_MAP_NULL;
	boolean_t		map_locked = FALSE;
	boolean_t		pmap_empty = TRUE;
	boolean_t		new_mapping_established = FALSE;
	boolean_t		anywhere = ((flags & VM_FLAGS_ANYWHERE) != 0);
	boolean_t		purgable = ((flags & VM_FLAGS_PURGABLE) != 0);
	boolean_t		overwrite = ((flags & VM_FLAGS_OVERWRITE) != 0);
	boolean_t		no_cache = ((flags & VM_FLAGS_NO_CACHE) != 0);
	boolean_t		is_submap = ((flags & VM_FLAGS_SUBMAP) != 0);
	boolean_t		permanent = ((flags & VM_FLAGS_PERMANENT) != 0);
	unsigned int		superpage_size = ((flags & VM_FLAGS_SUPERPAGE_MASK) >> VM_FLAGS_SUPERPAGE_SHIFT);
	char			alias;
	vm_map_offset_t		effective_min_offset, effective_max_offset;
	kern_return_t		kr;

	if (superpage_size) {
		switch (superpage_size) {
			/*
			 * Note that the current implementation only supports
			 * a single size for superpages, SUPERPAGE_SIZE, per
			 * architecture. As soon as more sizes are supposed
			 * to be supported, SUPERPAGE_SIZE has to be replaced
			 * with a lookup of the size depending on superpage_size.
			 */
#ifdef __x86_64__
			case SUPERPAGE_SIZE_ANY:
				/* handle it like 2 MB and round up to page size */
				size = (size + 2*1024*1024 - 1) & ~(2*1024*1024 - 1);
			case SUPERPAGE_SIZE_2MB:
				break;
#endif
			default:
				return KERN_INVALID_ARGUMENT;
		}
		mask = SUPERPAGE_SIZE-1;
		if (size & (SUPERPAGE_SIZE-1))
			return KERN_INVALID_ARGUMENT;
		inheritance = VM_INHERIT_NONE;	/* fork() children won't inherit superpages */
	}


#if CONFIG_EMBEDDED
	if (cur_protection & VM_PROT_WRITE){
		if ((cur_protection & VM_PROT_EXECUTE) && !(flags & VM_FLAGS_MAP_JIT)){
			printf("EMBEDDED: %s curprot cannot be write+execute. turning off execute\n", __PRETTY_FUNCTION__);
			cur_protection &= ~VM_PROT_EXECUTE;
		}
	}
#endif /* CONFIG_EMBEDDED */

	if (is_submap) {
		if (purgable) {
			/* submaps can not be purgeable */
			return KERN_INVALID_ARGUMENT;
		}
		if (object == VM_OBJECT_NULL) {
			/* submaps can not be created lazily */
			return KERN_INVALID_ARGUMENT;
		}
	}
	if (flags & VM_FLAGS_ALREADY) {
		/*
		 * VM_FLAGS_ALREADY says that it's OK if the same mapping
		 * is already present.  For it to be meaningul, the requested
		 * mapping has to be at a fixed address (!VM_FLAGS_ANYWHERE) and
		 * we shouldn't try and remove what was mapped there first
		 * (!VM_FLAGS_OVERWRITE).
		 */
		if ((flags & VM_FLAGS_ANYWHERE) ||
		    (flags & VM_FLAGS_OVERWRITE)) {
			return KERN_INVALID_ARGUMENT;
		}
	}

	effective_min_offset = map->min_offset;

	if (flags & VM_FLAGS_BEYOND_MAX) {
		/*
		 * Allow an insertion beyond the map's max offset.
		 */
		if (vm_map_is_64bit(map))
			effective_max_offset = 0xFFFFFFFFFFFFF000ULL;
		else
			effective_max_offset = 0x00000000FFFFF000ULL;
	} else {
		effective_max_offset = map->max_offset;
	}

	if (size == 0 ||
	    (offset & PAGE_MASK_64) != 0) {
		*address = 0;
		return KERN_INVALID_ARGUMENT;
	}

	VM_GET_FLAGS_ALIAS(flags, alias);

#define	RETURN(value)	{ result = value; goto BailOut; }

	assert(page_aligned(*address));
	assert(page_aligned(size));

	/*
	 * Only zero-fill objects are allowed to be purgable.
	 * LP64todo - limit purgable objects to 32-bits for now
	 */
	if (purgable &&
	    (offset != 0 ||
	     (object != VM_OBJECT_NULL &&
	      (object->vo_size != size ||
	       object->purgable == VM_PURGABLE_DENY))
	     || size > ANON_MAX_SIZE)) /* LP64todo: remove when dp capable */
		return KERN_INVALID_ARGUMENT;

	if (!anywhere && overwrite) {
		/*
		 * Create a temporary VM map to hold the old mappings in the
		 * affected area while we create the new one.
		 * This avoids releasing the VM map lock in
		 * vm_map_entry_delete() and allows atomicity
		 * when we want to replace some mappings with a new one.
		 * It also allows us to restore the old VM mappings if the
		 * new mapping fails.
		 */
		zap_old_map = vm_map_create(PMAP_NULL,
					    *address,
					    *address + size,
					    map->hdr.entries_pageable);
	}

StartAgain: ;

	start = *address;

	if (anywhere) {
		vm_map_lock(map);
		map_locked = TRUE;
		
		if ((flags & VM_FLAGS_MAP_JIT) && (map->jit_entry_exists)){
			result = KERN_INVALID_ARGUMENT;
			goto BailOut;
		}

		/*
		 *	Calculate the first possible address.
		 */

		if (start < effective_min_offset)
			start = effective_min_offset;
		if (start > effective_max_offset)
			RETURN(KERN_NO_SPACE);

		/*
		 *	Look for the first possible address;
		 *	if there's already something at this
		 *	address, we have to start after it.
		 */

		if( map->disable_vmentry_reuse == TRUE) {
			VM_MAP_HIGHEST_ENTRY(map, entry, start);
		} else {
			assert(first_free_is_valid(map));

			entry = map->first_free;

			if (entry == vm_map_to_entry(map)) {
				entry = NULL;
			} else {
			       if (entry->vme_next == vm_map_to_entry(map)){
				       /*
					* Hole at the end of the map.
					*/
					entry = NULL;
			       } else {
					if (start < (entry->vme_next)->vme_start ) {
						start = entry->vme_end;
					} else {
						/*
						 * Need to do a lookup.
						 */
						entry = NULL;
					}
			       }
			}

			if (entry == NULL) {
				vm_map_entry_t	tmp_entry;
				if (vm_map_lookup_entry(map, start, &tmp_entry))
					start = tmp_entry->vme_end;
				entry = tmp_entry;
			}
		}

		/*
		 *	In any case, the "entry" always precedes
		 *	the proposed new region throughout the
		 *	loop:
		 */

		while (TRUE) {
			register vm_map_entry_t	next;

			/*
			 *	Find the end of the proposed new region.
			 *	Be sure we didn't go beyond the end, or
			 *	wrap around the address.
			 */

			end = ((start + mask) & ~mask);
			if (end < start)
				RETURN(KERN_NO_SPACE);
			start = end;
			end += size;

			if ((end > effective_max_offset) || (end < start)) {
				if (map->wait_for_space) {
					if (size <= (effective_max_offset -
						     effective_min_offset)) {
						assert_wait((event_t)map,
							    THREAD_ABORTSAFE);
						vm_map_unlock(map);
						map_locked = FALSE;
						thread_block(THREAD_CONTINUE_NULL);
						goto StartAgain;
					}
				}
				RETURN(KERN_NO_SPACE);
			}

			/*
			 *	If there are no more entries, we must win.
			 */

			next = entry->vme_next;
			if (next == vm_map_to_entry(map))
				break;

			/*
			 *	If there is another entry, it must be
			 *	after the end of the potential new region.
			 */

			if (next->vme_start >= end)
				break;

			/*
			 *	Didn't fit -- move to the next entry.
			 */

			entry = next;
			start = entry->vme_end;
		}
		*address = start;
	} else {
		/*
		 *	Verify that:
		 *		the address doesn't itself violate
		 *		the mask requirement.
		 */

		vm_map_lock(map);
		map_locked = TRUE;
		if ((start & mask) != 0)
			RETURN(KERN_NO_SPACE);

		/*
		 *	...	the address is within bounds
		 */

		end = start + size;

		if ((start < effective_min_offset) ||
		    (end > effective_max_offset) ||
		    (start >= end)) {
			RETURN(KERN_INVALID_ADDRESS);
		}

		if (overwrite && zap_old_map != VM_MAP_NULL) {
			/*
			 * Fixed mapping and "overwrite" flag: attempt to
			 * remove all existing mappings in the specified
			 * address range, saving them in our "zap_old_map".
			 */
			(void) vm_map_delete(map, start, end,
					     VM_MAP_REMOVE_SAVE_ENTRIES,
					     zap_old_map);
		}

		/*
		 *	...	the starting address isn't allocated
		 */

		if (vm_map_lookup_entry(map, start, &entry)) {
			if (! (flags & VM_FLAGS_ALREADY)) {
				RETURN(KERN_NO_SPACE);
			}
			/*
			 * Check if what's already there is what we want.
			 */
			tmp_start = start;
			tmp_offset = offset;
			if (entry->vme_start < start) {
				tmp_start -= start - entry->vme_start;
				tmp_offset -= start - entry->vme_start;
				
			}
			for (; entry->vme_start < end;
			     entry = entry->vme_next) {
				/*
				 * Check if the mapping's attributes
				 * match the existing map entry.
				 */
				if (entry == vm_map_to_entry(map) ||
				    entry->vme_start != tmp_start ||
				    entry->is_sub_map != is_submap ||
				    entry->offset != tmp_offset ||
				    entry->needs_copy != needs_copy ||
				    entry->protection != cur_protection ||
				    entry->max_protection != max_protection ||
				    entry->inheritance != inheritance ||
				    entry->alias != alias) {
					/* not the same mapping ! */
					RETURN(KERN_NO_SPACE);
				}
				/*
				 * Check if the same object is being mapped.
				 */
				if (is_submap) {
					if (entry->object.sub_map !=
					    (vm_map_t) object) {
						/* not the same submap */
						RETURN(KERN_NO_SPACE);
					}
				} else {
					if (entry->object.vm_object != object) {
						/* not the same VM object... */
						vm_object_t obj2;

						obj2 = entry->object.vm_object;
						if ((obj2 == VM_OBJECT_NULL ||
						     obj2->internal) &&
						    (object == VM_OBJECT_NULL ||
						     object->internal)) {
							/*
							 * ... but both are
							 * anonymous memory,
							 * so equivalent.
							 */
						} else {
							RETURN(KERN_NO_SPACE);
						}
					}
				}

				tmp_offset += entry->vme_end - entry->vme_start;
				tmp_start += entry->vme_end - entry->vme_start;
				if (entry->vme_end >= end) {
					/* reached the end of our mapping */
					break;
				}
			}
			/* it all matches:  let's use what's already there ! */
			RETURN(KERN_MEMORY_PRESENT);
		}

		/*
		 *	...	the next region doesn't overlap the
		 *		end point.
		 */

		if ((entry->vme_next != vm_map_to_entry(map)) &&
		    (entry->vme_next->vme_start < end))
			RETURN(KERN_NO_SPACE);
	}

	/*
	 *	At this point,
	 *		"start" and "end" should define the endpoints of the
	 *			available new range, and
	 *		"entry" should refer to the region before the new
	 *			range, and
	 *
	 *		the map should be locked.
	 */

	/*
	 *	See whether we can avoid creating a new entry (and object) by
	 *	extending one of our neighbors.  [So far, we only attempt to
	 *	extend from below.]  Note that we can never extend/join
	 *	purgable objects because they need to remain distinct
	 *	entities in order to implement their "volatile object"
	 *	semantics.
	 */

	if (purgable) {
		if (object == VM_OBJECT_NULL) {
			object = vm_object_allocate(size);
			object->copy_strategy = MEMORY_OBJECT_COPY_NONE;
			object->purgable = VM_PURGABLE_NONVOLATILE;
			offset = (vm_object_offset_t)0;
		}
	} else if ((is_submap == FALSE) &&
		   (object == VM_OBJECT_NULL) &&
		   (entry != vm_map_to_entry(map)) &&
		   (entry->vme_end == start) &&
		   (!entry->is_shared) &&
		   (!entry->is_sub_map) &&
		   ((alias == VM_MEMORY_REALLOC) || (entry->alias == alias)) &&
		   (entry->inheritance == inheritance) &&
		   (entry->protection == cur_protection) &&
		   (entry->max_protection == max_protection) &&
		   (entry->behavior == VM_BEHAVIOR_DEFAULT) &&
		   (entry->in_transition == 0) &&
		   (entry->no_cache == no_cache) &&
		   ((entry->vme_end - entry->vme_start) + size <=
		    (alias == VM_MEMORY_REALLOC ?
		     ANON_CHUNK_SIZE :
		     NO_COALESCE_LIMIT)) &&
		   (entry->wired_count == 0)) { /* implies user_wired_count == 0 */
		if (vm_object_coalesce(entry->object.vm_object,
				       VM_OBJECT_NULL,
				       entry->offset,
				       (vm_object_offset_t) 0,
				       (vm_map_size_t)(entry->vme_end - entry->vme_start),
				       (vm_map_size_t)(end - entry->vme_end))) {

			/*
			 *	Coalesced the two objects - can extend
			 *	the previous map entry to include the
			 *	new range.
			 */
			map->size += (end - entry->vme_end);
			entry->vme_end = end;
			vm_map_store_update_first_free(map, map->first_free);
			RETURN(KERN_SUCCESS);
		}
	}

	step = superpage_size ? SUPERPAGE_SIZE : (end - start);
	new_entry = NULL;

	for (tmp2_start = start; tmp2_start<end; tmp2_start += step) {
		tmp2_end = tmp2_start + step;
		/*
		 *	Create a new entry
		 *	LP64todo - for now, we can only allocate 4GB internal objects
		 *	because the default pager can't page bigger ones.  Remove this
		 *	when it can.
		 *
		 * XXX FBDP
		 * The reserved "page zero" in each process's address space can
		 * be arbitrarily large.  Splitting it into separate 4GB objects and
		 * therefore different VM map entries serves no purpose and just
		 * slows down operations on the VM map, so let's not split the
		 * allocation into 4GB chunks if the max protection is NONE.  That
		 * memory should never be accessible, so it will never get to the
		 * default pager.
		 */
		tmp_start = tmp2_start;
		if (object == VM_OBJECT_NULL &&
		    size > (vm_map_size_t)ANON_CHUNK_SIZE &&
		    max_protection != VM_PROT_NONE &&
		    superpage_size == 0) 
			tmp_end = tmp_start + (vm_map_size_t)ANON_CHUNK_SIZE;
		else
			tmp_end = tmp2_end;
		do {
			new_entry = vm_map_entry_insert(map, entry, tmp_start, tmp_end,
							object,	offset, needs_copy,
							FALSE, FALSE,
							cur_protection, max_protection,
							VM_BEHAVIOR_DEFAULT,
							(flags & VM_FLAGS_MAP_JIT)? VM_INHERIT_NONE: inheritance, 
							0, no_cache,
							permanent, superpage_size);
			new_entry->alias = alias;
			if (flags & VM_FLAGS_MAP_JIT){
				if (!(map->jit_entry_exists)){
					new_entry->used_for_jit = TRUE;
					map->jit_entry_exists = TRUE;
				}
			}

			if (is_submap) {
				vm_map_t	submap;
				boolean_t	submap_is_64bit;
				boolean_t	use_pmap;

				new_entry->is_sub_map = TRUE;
				submap = (vm_map_t) object;
				submap_is_64bit = vm_map_is_64bit(submap);
				use_pmap = (alias == VM_MEMORY_SHARED_PMAP);
	#ifndef NO_NESTED_PMAP 
				if (use_pmap && submap->pmap == NULL) {
					/* we need a sub pmap to nest... */
					submap->pmap = pmap_create(0, submap_is_64bit);
					if (submap->pmap == NULL) {
						/* let's proceed without nesting... */
					}
				}
				if (use_pmap && submap->pmap != NULL) {
					kr = pmap_nest(map->pmap,
						       submap->pmap,
						       tmp_start,
						       tmp_start,
						       tmp_end - tmp_start);
					if (kr != KERN_SUCCESS) {
						printf("vm_map_enter: "
						       "pmap_nest(0x%llx,0x%llx) "
						       "error 0x%x\n",
						       (long long)tmp_start,
						       (long long)tmp_end,
						       kr);
					} else {
						/* we're now nested ! */
						new_entry->use_pmap = TRUE;
						pmap_empty = FALSE;
					}
				}
	#endif /* NO_NESTED_PMAP */
			}
			entry = new_entry;

			if (superpage_size) {
				vm_page_t pages, m;
				vm_object_t sp_object;

				entry->offset = 0;

				/* allocate one superpage */
				kr = cpm_allocate(SUPERPAGE_SIZE, &pages, 0, SUPERPAGE_NBASEPAGES-1, TRUE, 0);
				if (kr != KERN_SUCCESS) {
					new_mapping_established = TRUE; /* will cause deallocation of whole range */
					RETURN(kr);
				}

				/* create one vm_object per superpage */
				sp_object = vm_object_allocate((vm_map_size_t)(entry->vme_end - entry->vme_start));
				sp_object->phys_contiguous = TRUE;
				sp_object->vo_shadow_offset = (vm_object_offset_t)pages->phys_page*PAGE_SIZE;
				entry->object.vm_object = sp_object;

				/* enter the base pages into the object */
				vm_object_lock(sp_object);
				for (offset = 0; offset < SUPERPAGE_SIZE; offset += PAGE_SIZE) {
					m = pages;
					pmap_zero_page(m->phys_page);
					pages = NEXT_PAGE(m);
					*(NEXT_PAGE_PTR(m)) = VM_PAGE_NULL;
					vm_page_insert(m, sp_object, offset);
				}
				vm_object_unlock(sp_object);
			}
		} while (tmp_end != tmp2_end && 
			 (tmp_start = tmp_end) &&
			 (tmp_end = (tmp2_end - tmp_end > (vm_map_size_t)ANON_CHUNK_SIZE) ? 
			  tmp_end + (vm_map_size_t)ANON_CHUNK_SIZE : tmp2_end));
	}

	vm_map_unlock(map);
	map_locked = FALSE;

	new_mapping_established = TRUE;

	/*	Wire down the new entry if the user
	 *	requested all new map entries be wired.
	 */
	if ((map->wiring_required)||(superpage_size)) {
		pmap_empty = FALSE; /* pmap won't be empty */
		result = vm_map_wire(map, start, end,
				     new_entry->protection, TRUE);
		RETURN(result);
	}

	if ((object != VM_OBJECT_NULL) &&
	    (vm_map_pmap_enter_enable) &&
	    (!anywhere)	 &&
	    (!needs_copy) && 
	    (size < (128*1024))) {
		pmap_empty = FALSE; /* pmap won't be empty */

		if (override_nx(map, alias) && cur_protection)
		        cur_protection |= VM_PROT_EXECUTE;

		vm_map_pmap_enter(map, start, end, 
				  object, offset, cur_protection);
	}

BailOut: ;
	if (result == KERN_SUCCESS) {
		vm_prot_t pager_prot;
		memory_object_t pager;

		if (pmap_empty &&
		    !(flags & VM_FLAGS_NO_PMAP_CHECK)) {
			assert(vm_map_pmap_is_empty(map,
						    *address,
						    *address+size));
		}

		/*
		 * For "named" VM objects, let the pager know that the
		 * memory object is being mapped.  Some pagers need to keep
		 * track of this, to know when they can reclaim the memory
		 * object, for example.
		 * VM calls memory_object_map() for each mapping (specifying
		 * the protection of each mapping) and calls
		 * memory_object_last_unmap() when all the mappings are gone.
		 */
		pager_prot = max_protection;
		if (needs_copy) {
			/*
			 * Copy-On-Write mapping: won't modify
			 * the memory object.
			 */
			pager_prot &= ~VM_PROT_WRITE;
		}
		if (!is_submap &&
		    object != VM_OBJECT_NULL &&
		    object->named &&
		    object->pager != MEMORY_OBJECT_NULL) {
			vm_object_lock(object);
			pager = object->pager;
			if (object->named &&
			    pager != MEMORY_OBJECT_NULL) {
				assert(object->pager_ready);
				vm_object_mapping_wait(object, THREAD_UNINT);
				vm_object_mapping_begin(object);
				vm_object_unlock(object);

				kr = memory_object_map(pager, pager_prot);
				assert(kr == KERN_SUCCESS);

				vm_object_lock(object);
				vm_object_mapping_end(object);
			}
			vm_object_unlock(object);
		}
	} else {
		if (new_mapping_established) {
			/*
			 * We have to get rid of the new mappings since we
			 * won't make them available to the user.
			 * Try and do that atomically, to minimize the risk
			 * that someone else create new mappings that range.
			 */
			zap_new_map = vm_map_create(PMAP_NULL,
						    *address,
						    *address + size,
						    map->hdr.entries_pageable);
			if (!map_locked) {
				vm_map_lock(map);
				map_locked = TRUE;
			}
			(void) vm_map_delete(map, *address, *address+size,
					     VM_MAP_REMOVE_SAVE_ENTRIES,
					     zap_new_map);
		}
		if (zap_old_map != VM_MAP_NULL &&
		    zap_old_map->hdr.nentries != 0) {
			vm_map_entry_t	entry1, entry2;

			/*
			 * The new mapping failed.  Attempt to restore
			 * the old mappings, saved in the "zap_old_map".
			 */
			if (!map_locked) {
				vm_map_lock(map);
				map_locked = TRUE;
			}

			/* first check if the coast is still clear */
			start = vm_map_first_entry(zap_old_map)->vme_start;
			end = vm_map_last_entry(zap_old_map)->vme_end;
			if (vm_map_lookup_entry(map, start, &entry1) ||
			    vm_map_lookup_entry(map, end, &entry2) ||
			    entry1 != entry2) {
				/*
				 * Part of that range has already been
				 * re-mapped:  we can't restore the old
				 * mappings...
				 */
				vm_map_enter_restore_failures++;
			} else {
				/*
				 * Transfer the saved map entries from
				 * "zap_old_map" to the original "map",
				 * inserting them all after "entry1".
				 */
				for (entry2 = vm_map_first_entry(zap_old_map);
				     entry2 != vm_map_to_entry(zap_old_map);
				     entry2 = vm_map_first_entry(zap_old_map)) {
					vm_map_size_t entry_size;

					entry_size = (entry2->vme_end -
						      entry2->vme_start);
					vm_map_store_entry_unlink(zap_old_map,
							    entry2);
					zap_old_map->size -= entry_size;
					vm_map_store_entry_link(map, entry1, entry2);
					map->size += entry_size;
					entry1 = entry2;
				}
				if (map->wiring_required) {
					/*
					 * XXX TODO: we should rewire the
					 * old pages here...
					 */
				}
				vm_map_enter_restore_successes++;
			}
		}
	}

	if (map_locked) {
		vm_map_unlock(map);
	}

	/*
	 * Get rid of the "zap_maps" and all the map entries that
	 * they may still contain.
	 */
	if (zap_old_map != VM_MAP_NULL) {
		vm_map_destroy(zap_old_map, VM_MAP_REMOVE_NO_PMAP_CLEANUP);
		zap_old_map = VM_MAP_NULL;
	}
	if (zap_new_map != VM_MAP_NULL) {
		vm_map_destroy(zap_new_map, VM_MAP_REMOVE_NO_PMAP_CLEANUP);
		zap_new_map = VM_MAP_NULL;
	}

	return result;

#undef	RETURN
}

kern_return_t
vm_map_enter_mem_object(
	vm_map_t		target_map,
	vm_map_offset_t		*address,
	vm_map_size_t		initial_size,
	vm_map_offset_t		mask,
	int			flags,
	ipc_port_t		port,
	vm_object_offset_t	offset,
	boolean_t		copy,
	vm_prot_t		cur_protection,
	vm_prot_t		max_protection,
	vm_inherit_t		inheritance)
{
	vm_map_address_t	map_addr;
	vm_map_size_t		map_size;
	vm_object_t		object;
	vm_object_size_t	size;
	kern_return_t		result;
	boolean_t		mask_cur_protection, mask_max_protection;

	mask_cur_protection = cur_protection & VM_PROT_IS_MASK;
	mask_max_protection = max_protection & VM_PROT_IS_MASK;
	cur_protection &= ~VM_PROT_IS_MASK;
	max_protection &= ~VM_PROT_IS_MASK;

	/*
	 * Check arguments for validity
	 */
	if ((target_map == VM_MAP_NULL) ||
	    (cur_protection & ~VM_PROT_ALL) ||
	    (max_protection & ~VM_PROT_ALL) ||
	    (inheritance > VM_INHERIT_LAST_VALID) ||
	    initial_size == 0)
		return KERN_INVALID_ARGUMENT;
	
	map_addr = vm_map_trunc_page(*address);
	map_size = vm_map_round_page(initial_size);
	size = vm_object_round_page(initial_size);	

	/*
	 * Find the vm object (if any) corresponding to this port.
	 */
	if (!IP_VALID(port)) {
		object = VM_OBJECT_NULL;
		offset = 0;
		copy = FALSE;
	} else if (ip_kotype(port) == IKOT_NAMED_ENTRY) {
		vm_named_entry_t	named_entry;

		named_entry = (vm_named_entry_t) port->ip_kobject;
		/* a few checks to make sure user is obeying rules */
		if (size == 0) {
			if (offset >= named_entry->size)
				return KERN_INVALID_RIGHT;
			size = named_entry->size - offset;
		}
		if (mask_max_protection) {
			max_protection &= named_entry->protection;
		}
		if (mask_cur_protection) {
			cur_protection &= named_entry->protection;
		}
		if ((named_entry->protection & max_protection) !=
		    max_protection)
			return KERN_INVALID_RIGHT;
		if ((named_entry->protection & cur_protection) !=
		    cur_protection)
			return KERN_INVALID_RIGHT;
		if (named_entry->size < (offset + size))
			return KERN_INVALID_ARGUMENT;

		/* the callers parameter offset is defined to be the */
		/* offset from beginning of named entry offset in object */
		offset = offset + named_entry->offset;
		
		named_entry_lock(named_entry);
		if (named_entry->is_sub_map) {
			vm_map_t		submap;

			submap = named_entry->backing.map;
			vm_map_lock(submap);
			vm_map_reference(submap);
			vm_map_unlock(submap);
			named_entry_unlock(named_entry);

			result = vm_map_enter(target_map,
					      &map_addr,
					      map_size,
					      mask,
					      flags | VM_FLAGS_SUBMAP,
					      (vm_object_t) submap,
					      offset,
					      copy,
					      cur_protection,
					      max_protection,
					      inheritance);
			if (result != KERN_SUCCESS) {
				vm_map_deallocate(submap);
			} else {
				/*
				 * No need to lock "submap" just to check its
				 * "mapped" flag: that flag is never reset
				 * once it's been set and if we race, we'll
				 * just end up setting it twice, which is OK.
				 */
				if (submap->mapped == FALSE) {
					/*
					 * This submap has never been mapped.
					 * Set its "mapped" flag now that it
					 * has been mapped.
					 * This happens only for the first ever
					 * mapping of a "submap".
					 */
					vm_map_lock(submap);
					submap->mapped = TRUE;
					vm_map_unlock(submap);
				}
				*address = map_addr;
			}
			return result;

		} else if (named_entry->is_pager) {
			unsigned int	access;
			vm_prot_t	protections;
			unsigned int	wimg_mode;

			protections = named_entry->protection & VM_PROT_ALL;
			access = GET_MAP_MEM(named_entry->protection);

			object = vm_object_enter(named_entry->backing.pager, 
						 named_entry->size, 
						 named_entry->internal, 
						 FALSE,
						 FALSE);
			if (object == VM_OBJECT_NULL) {
				named_entry_unlock(named_entry);
				return KERN_INVALID_OBJECT;
			}

			/* JMM - drop reference on pager here */

			/* create an extra ref for the named entry */
			vm_object_lock(object);
			vm_object_reference_locked(object);
			named_entry->backing.object = object;
			named_entry->is_pager = FALSE;
			named_entry_unlock(named_entry);

			wimg_mode = object->wimg_bits;

			if (access == MAP_MEM_IO) {
				wimg_mode = VM_WIMG_IO;
			} else if (access == MAP_MEM_COPYBACK) {
				wimg_mode = VM_WIMG_USE_DEFAULT;
			} else if (access == MAP_MEM_WTHRU) {
				wimg_mode = VM_WIMG_WTHRU;
			} else if (access == MAP_MEM_WCOMB) {
				wimg_mode = VM_WIMG_WCOMB;
			}

			/* wait for object (if any) to be ready */
			if (!named_entry->internal) {
				while (!object->pager_ready) {
					vm_object_wait(
						object,
						VM_OBJECT_EVENT_PAGER_READY,
						THREAD_UNINT);
					vm_object_lock(object);
				}
			}

			if (object->wimg_bits != wimg_mode)
				vm_object_change_wimg_mode(object, wimg_mode);

			object->true_share = TRUE;

			if (object->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC)
				object->copy_strategy = MEMORY_OBJECT_COPY_DELAY;
			vm_object_unlock(object);
		} else {
			/* This is the case where we are going to map */
			/* an already mapped object.  If the object is */
			/* not ready it is internal.  An external     */
			/* object cannot be mapped until it is ready  */
			/* we can therefore avoid the ready check     */
			/* in this case.  */
			object = named_entry->backing.object;
			assert(object != VM_OBJECT_NULL);
			named_entry_unlock(named_entry);
			vm_object_reference(object);
		}
	} else if (ip_kotype(port) == IKOT_MEMORY_OBJECT) {
		/*
		 * JMM - This is temporary until we unify named entries
		 * and raw memory objects.
		 *
		 * Detected fake ip_kotype for a memory object.  In
		 * this case, the port isn't really a port at all, but
		 * instead is just a raw memory object.
		 */
		 
		object = vm_object_enter((memory_object_t)port,
					 size, FALSE, FALSE, FALSE);
		if (object == VM_OBJECT_NULL)
			return KERN_INVALID_OBJECT;

		/* wait for object (if any) to be ready */
		if (object != VM_OBJECT_NULL) {
			if (object == kernel_object) {
				printf("Warning: Attempt to map kernel object"
					" by a non-private kernel entity\n");
				return KERN_INVALID_OBJECT;
			}
			if (!object->pager_ready) {
				vm_object_lock(object);

				while (!object->pager_ready) {
					vm_object_wait(object,
						       VM_OBJECT_EVENT_PAGER_READY,
						       THREAD_UNINT);
					vm_object_lock(object);
				}
				vm_object_unlock(object);
			}
		}
	} else {
		return KERN_INVALID_OBJECT;
	}

	if (object != VM_OBJECT_NULL &&
	    object->named &&
	    object->pager != MEMORY_OBJECT_NULL &&
	    object->copy_strategy != MEMORY_OBJECT_COPY_NONE) {
		memory_object_t pager;
		vm_prot_t	pager_prot;
		kern_return_t	kr;

		/*
		 * For "named" VM objects, let the pager know that the
		 * memory object is being mapped.  Some pagers need to keep
		 * track of this, to know when they can reclaim the memory
		 * object, for example.
		 * VM calls memory_object_map() for each mapping (specifying
		 * the protection of each mapping) and calls
		 * memory_object_last_unmap() when all the mappings are gone.
		 */
		pager_prot = max_protection;
		if (copy) {
			/*
			 * Copy-On-Write mapping: won't modify the
			 * memory object.
			 */
			pager_prot &= ~VM_PROT_WRITE;
		}
		vm_object_lock(object);
		pager = object->pager;
		if (object->named &&
		    pager != MEMORY_OBJECT_NULL &&
		    object->copy_strategy != MEMORY_OBJECT_COPY_NONE) {
			assert(object->pager_ready);
			vm_object_mapping_wait(object, THREAD_UNINT);
			vm_object_mapping_begin(object);
			vm_object_unlock(object);

			kr = memory_object_map(pager, pager_prot);
			assert(kr == KERN_SUCCESS);

			vm_object_lock(object);
			vm_object_mapping_end(object);
		}
		vm_object_unlock(object);
	}

	/*
	 *	Perform the copy if requested
	 */

	if (copy) {
		vm_object_t		new_object;
		vm_object_offset_t	new_offset;

		result = vm_object_copy_strategically(object, offset, size,
						      &new_object, &new_offset,
						      &copy);


		if (result == KERN_MEMORY_RESTART_COPY) {
			boolean_t success;
			boolean_t src_needs_copy;

			/*
			 * XXX
			 * We currently ignore src_needs_copy.
			 * This really is the issue of how to make
			 * MEMORY_OBJECT_COPY_SYMMETRIC safe for
			 * non-kernel users to use. Solution forthcoming.
			 * In the meantime, since we don't allow non-kernel
			 * memory managers to specify symmetric copy,
			 * we won't run into problems here.
			 */
			new_object = object;
			new_offset = offset;
			success = vm_object_copy_quickly(&new_object,
							 new_offset, size,
							 &src_needs_copy,
							 &copy);
			assert(success);
			result = KERN_SUCCESS;
		}
		/*
		 *	Throw away the reference to the
		 *	original object, as it won't be mapped.
		 */

		vm_object_deallocate(object);

		if (result != KERN_SUCCESS)
			return result;

		object = new_object;
		offset = new_offset;
	}

	result = vm_map_enter(target_map,
			      &map_addr, map_size,
			      (vm_map_offset_t)mask,
			      flags,
			      object, offset,
			      copy,
			      cur_protection, max_protection, inheritance);
	if (result != KERN_SUCCESS)
		vm_object_deallocate(object);
	*address = map_addr;
	return result;
}




kern_return_t
vm_map_enter_mem_object_control(
	vm_map_t		target_map,
	vm_map_offset_t		*address,
	vm_map_size_t		initial_size,
	vm_map_offset_t		mask,
	int			flags,
	memory_object_control_t	control,
	vm_object_offset_t	offset,
	boolean_t		copy,
	vm_prot_t		cur_protection,
	vm_prot_t		max_protection,
	vm_inherit_t		inheritance)
{
	vm_map_address_t	map_addr;
	vm_map_size_t		map_size;
	vm_object_t		object;
	vm_object_size_t	size;
	kern_return_t		result;
	memory_object_t		pager;
	vm_prot_t		pager_prot;
	kern_return_t		kr;

	/*
	 * Check arguments for validity
	 */
	if ((target_map == VM_MAP_NULL) ||
	    (cur_protection & ~VM_PROT_ALL) ||
	    (max_protection & ~VM_PROT_ALL) ||
	    (inheritance > VM_INHERIT_LAST_VALID) ||
	    initial_size == 0)
		return KERN_INVALID_ARGUMENT;

	map_addr = vm_map_trunc_page(*address);
	map_size = vm_map_round_page(initial_size);
	size = vm_object_round_page(initial_size);	

	object = memory_object_control_to_vm_object(control);

	if (object == VM_OBJECT_NULL)
		return KERN_INVALID_OBJECT;

	if (object == kernel_object) {
		printf("Warning: Attempt to map kernel object"
		       " by a non-private kernel entity\n");
		return KERN_INVALID_OBJECT;
	}

	vm_object_lock(object);
	object->ref_count++;
	vm_object_res_reference(object);

	/*
	 * For "named" VM objects, let the pager know that the
	 * memory object is being mapped.  Some pagers need to keep
	 * track of this, to know when they can reclaim the memory
	 * object, for example.
	 * VM calls memory_object_map() for each mapping (specifying
	 * the protection of each mapping) and calls
	 * memory_object_last_unmap() when all the mappings are gone.
	 */
	pager_prot = max_protection;
	if (copy) {
		pager_prot &= ~VM_PROT_WRITE;
	}
	pager = object->pager;
	if (object->named &&
	    pager != MEMORY_OBJECT_NULL &&
	    object->copy_strategy != MEMORY_OBJECT_COPY_NONE) {
		assert(object->pager_ready);
		vm_object_mapping_wait(object, THREAD_UNINT);
		vm_object_mapping_begin(object);
		vm_object_unlock(object);

		kr = memory_object_map(pager, pager_prot);
		assert(kr == KERN_SUCCESS);

		vm_object_lock(object);
		vm_object_mapping_end(object);
	}
	vm_object_unlock(object);

	/*
	 *	Perform the copy if requested
	 */

	if (copy) {
		vm_object_t		new_object;
		vm_object_offset_t	new_offset;

		result = vm_object_copy_strategically(object, offset, size,
						      &new_object, &new_offset,
						      &copy);


		if (result == KERN_MEMORY_RESTART_COPY) {
			boolean_t success;
			boolean_t src_needs_copy;

			/*
			 * XXX
			 * We currently ignore src_needs_copy.
			 * This really is the issue of how to make
			 * MEMORY_OBJECT_COPY_SYMMETRIC safe for
			 * non-kernel users to use. Solution forthcoming.
			 * In the meantime, since we don't allow non-kernel
			 * memory managers to specify symmetric copy,
			 * we won't run into problems here.
			 */
			new_object = object;
			new_offset = offset;
			success = vm_object_copy_quickly(&new_object,
							 new_offset, size,
							 &src_needs_copy,
							 &copy);
			assert(success);
			result = KERN_SUCCESS;
		}
		/*
		 *	Throw away the reference to the
		 *	original object, as it won't be mapped.
		 */

		vm_object_deallocate(object);

		if (result != KERN_SUCCESS)
			return result;

		object = new_object;
		offset = new_offset;
	}

	result = vm_map_enter(target_map,
			      &map_addr, map_size,
			      (vm_map_offset_t)mask,
			      flags,
			      object, offset,
			      copy,
			      cur_protection, max_protection, inheritance);
	if (result != KERN_SUCCESS)
		vm_object_deallocate(object);
	*address = map_addr;

	return result;
}


#if	VM_CPM

#ifdef MACH_ASSERT
extern pmap_paddr_t	avail_start, avail_end;
#endif

/*
 *	Allocate memory in the specified map, with the caveat that
 *	the memory is physically contiguous.  This call may fail
 *	if the system can't find sufficient contiguous memory.
 *	This call may cause or lead to heart-stopping amounts of
 *	paging activity.
 *
 *	Memory obtained from this call should be freed in the
 *	normal way, viz., via vm_deallocate.
 */
kern_return_t
vm_map_enter_cpm(
	vm_map_t		map,
	vm_map_offset_t	*addr,
	vm_map_size_t		size,
	int			flags)
{
	vm_object_t		cpm_obj;
	pmap_t			pmap;
	vm_page_t		m, pages;
	kern_return_t		kr;
	vm_map_offset_t		va, start, end, offset;
#if	MACH_ASSERT
	vm_map_offset_t		prev_addr;
#endif	/* MACH_ASSERT */

	boolean_t		anywhere = ((VM_FLAGS_ANYWHERE & flags) != 0);

	if (!vm_allocate_cpm_enabled)
		return KERN_FAILURE;

	if (size == 0) {
		*addr = 0;
		return KERN_SUCCESS;
	}
	if (anywhere)
		*addr = vm_map_min(map);
	else
		*addr = vm_map_trunc_page(*addr);
	size = vm_map_round_page(size);

	/*
	 * LP64todo - cpm_allocate should probably allow
	 * allocations of >4GB, but not with the current
	 * algorithm, so just cast down the size for now.
	 */
	if (size > VM_MAX_ADDRESS)
		return KERN_RESOURCE_SHORTAGE;
	if ((kr = cpm_allocate(CAST_DOWN(vm_size_t, size),
			       &pages, 0, 0, TRUE, flags)) != KERN_SUCCESS)
		return kr;

	cpm_obj = vm_object_allocate((vm_object_size_t)size);
	assert(cpm_obj != VM_OBJECT_NULL);
	assert(cpm_obj->internal);
	assert(cpm_obj->size == (vm_object_size_t)size);
	assert(cpm_obj->can_persist == FALSE);
	assert(cpm_obj->pager_created == FALSE);
	assert(cpm_obj->pageout == FALSE);
	assert(cpm_obj->shadow == VM_OBJECT_NULL);

	/*
	 *	Insert pages into object.
	 */

	vm_object_lock(cpm_obj);
	for (offset = 0; offset < size; offset += PAGE_SIZE) {
		m = pages;
		pages = NEXT_PAGE(m);
		*(NEXT_PAGE_PTR(m)) = VM_PAGE_NULL;

		assert(!m->gobbled);
		assert(!m->wanted);
		assert(!m->pageout);
		assert(!m->tabled);
		assert(VM_PAGE_WIRED(m));
		/*
		 * ENCRYPTED SWAP:
		 * "m" is not supposed to be pageable, so it
		 * should not be encrypted.  It wouldn't be safe
		 * to enter it in a new VM object while encrypted.
		 */
		ASSERT_PAGE_DECRYPTED(m);
		assert(m->busy);
		assert(m->phys_page>=(avail_start>>PAGE_SHIFT) && m->phys_page<=(avail_end>>PAGE_SHIFT));

		m->busy = FALSE;
		vm_page_insert(m, cpm_obj, offset);
	}
	assert(cpm_obj->resident_page_count == size / PAGE_SIZE);
	vm_object_unlock(cpm_obj);

	/*
	 *	Hang onto a reference on the object in case a
	 *	multi-threaded application for some reason decides
	 *	to deallocate the portion of the address space into
	 *	which we will insert this object.
	 *
	 *	Unfortunately, we must insert the object now before
	 *	we can talk to the pmap module about which addresses
	 *	must be wired down.  Hence, the race with a multi-
	 *	threaded app.
	 */
	vm_object_reference(cpm_obj);

	/*
	 *	Insert object into map.
	 */

	kr = vm_map_enter(
		map,
		addr,
		size,
		(vm_map_offset_t)0,
		flags,
		cpm_obj,
		(vm_object_offset_t)0,
		FALSE,
		VM_PROT_ALL,
		VM_PROT_ALL,
		VM_INHERIT_DEFAULT);

	if (kr != KERN_SUCCESS) {
		/*
		 *	A CPM object doesn't have can_persist set,
		 *	so all we have to do is deallocate it to
		 *	free up these pages.
		 */
		assert(cpm_obj->pager_created == FALSE);
		assert(cpm_obj->can_persist == FALSE);
		assert(cpm_obj->pageout == FALSE);
		assert(cpm_obj->shadow == VM_OBJECT_NULL);
		vm_object_deallocate(cpm_obj); /* kill acquired ref */
		vm_object_deallocate(cpm_obj); /* kill creation ref */
	}

	/*
	 *	Inform the physical mapping system that the
	 *	range of addresses may not fault, so that
	 *	page tables and such can be locked down as well.
	 */
	start = *addr;
	end = start + size;
	pmap = vm_map_pmap(map);
	pmap_pageable(pmap, start, end, FALSE);

	/*
	 *	Enter each page into the pmap, to avoid faults.
	 *	Note that this loop could be coded more efficiently,
	 *	if the need arose, rather than looking up each page
	 *	again.
	 */
	for (offset = 0, va = start; offset < size;
	     va += PAGE_SIZE, offset += PAGE_SIZE) {
	        int type_of_fault;

		vm_object_lock(cpm_obj);
		m = vm_page_lookup(cpm_obj, (vm_object_offset_t)offset);
		assert(m != VM_PAGE_NULL);

		vm_page_zero_fill(m);

		type_of_fault = DBG_ZERO_FILL_FAULT;

		vm_fault_enter(m, pmap, va, VM_PROT_ALL, VM_PROT_WRITE,
			       VM_PAGE_WIRED(m), FALSE, FALSE, FALSE,
			       &type_of_fault);

		vm_object_unlock(cpm_obj);
	}

#if	MACH_ASSERT
	/*
	 *	Verify ordering in address space.
	 */
	for (offset = 0; offset < size; offset += PAGE_SIZE) {
		vm_object_lock(cpm_obj);
		m = vm_page_lookup(cpm_obj, (vm_object_offset_t)offset);
		vm_object_unlock(cpm_obj);
		if (m == VM_PAGE_NULL)
			panic("vm_allocate_cpm:  obj 0x%x off 0x%x no page",
			      cpm_obj, offset);
		assert(m->tabled);
		assert(!m->busy);
		assert(!m->wanted);
		assert(!m->fictitious);
		assert(!m->private);
		assert(!m->absent);
		assert(!m->error);
		assert(!m->cleaning);
		assert(!m->precious);
		assert(!m->clustered);
		if (offset != 0) {
			if (m->phys_page != prev_addr + 1) {
				printf("start 0x%x end 0x%x va 0x%x\n",
				       start, end, va);
				printf("obj 0x%x off 0x%x\n", cpm_obj, offset);
				printf("m 0x%x prev_address 0x%x\n", m,
				       prev_addr);
				panic("vm_allocate_cpm:  pages not contig!");
			}
		}
		prev_addr = m->phys_page;
	}
#endif	/* MACH_ASSERT */

	vm_object_deallocate(cpm_obj); /* kill extra ref */

	return kr;
}


#else	/* VM_CPM */

/*
 *	Interface is defined in all cases, but unless the kernel
 *	is built explicitly for this option, the interface does
 *	nothing.
 */

kern_return_t
vm_map_enter_cpm(
	__unused vm_map_t	map,
	__unused vm_map_offset_t	*addr,
	__unused vm_map_size_t	size,
	__unused int		flags)
{
	return KERN_FAILURE;
}
#endif /* VM_CPM */

/* Not used without nested pmaps */
#ifndef NO_NESTED_PMAP
/*
 * Clip and unnest a portion of a nested submap mapping.
 */


static void
vm_map_clip_unnest(
	vm_map_t	map,
	vm_map_entry_t	entry,
	vm_map_offset_t	start_unnest,
	vm_map_offset_t	end_unnest)
{
	vm_map_offset_t old_start_unnest = start_unnest;
	vm_map_offset_t old_end_unnest = end_unnest;

	assert(entry->is_sub_map);
	assert(entry->object.sub_map != NULL);

	/*
	 * Query the platform for the optimal unnest range.
	 * DRK: There's some duplication of effort here, since
	 * callers may have adjusted the range to some extent. This
	 * routine was introduced to support 1GiB subtree nesting
	 * for x86 platforms, which can also nest on 2MiB boundaries
	 * depending on size/alignment.
	 */
	if (pmap_adjust_unnest_parameters(map->pmap, &start_unnest, &end_unnest)) {
		log_unnest_badness(map, old_start_unnest, old_end_unnest);
	}

	if (entry->vme_start > start_unnest ||
	    entry->vme_end < end_unnest) {
		panic("vm_map_clip_unnest(0x%llx,0x%llx): "
		      "bad nested entry: start=0x%llx end=0x%llx\n",
		      (long long)start_unnest, (long long)end_unnest,
		      (long long)entry->vme_start, (long long)entry->vme_end);
	}

	if (start_unnest > entry->vme_start) {
		_vm_map_clip_start(&map->hdr,
				   entry,
				   start_unnest);
		vm_map_store_update_first_free(map, map->first_free);
	}
	if (entry->vme_end > end_unnest) {
		_vm_map_clip_end(&map->hdr,
				 entry,
				 end_unnest);
		vm_map_store_update_first_free(map, map->first_free);
	}

	pmap_unnest(map->pmap,
		    entry->vme_start,
		    entry->vme_end - entry->vme_start);
	if ((map->mapped) && (map->ref_count)) {
		/* clean up parent map/maps */
		vm_map_submap_pmap_clean(
			map, entry->vme_start,
			entry->vme_end,
			entry->object.sub_map,
			entry->offset);
	}
	entry->use_pmap = FALSE;
}
#endif	/* NO_NESTED_PMAP */

/*
 *	vm_map_clip_start:	[ internal use only ]
 *
 *	Asserts that the given entry begins at or after
 *	the specified address; if necessary,
 *	it splits the entry into two.
 */
static void
vm_map_clip_start(
	vm_map_t	map,
	vm_map_entry_t	entry,
	vm_map_offset_t	startaddr)
{
#ifndef NO_NESTED_PMAP
	if (entry->use_pmap &&
	    startaddr >= entry->vme_start) {
		vm_map_offset_t	start_unnest, end_unnest;

		/*
		 * Make sure "startaddr" is no longer in a nested range
		 * before we clip.  Unnest only the minimum range the platform
		 * can handle.
		 * vm_map_clip_unnest may perform additional adjustments to
		 * the unnest range.
		 */
		start_unnest = startaddr & ~(pmap_nesting_size_min - 1);
		end_unnest = start_unnest + pmap_nesting_size_min;
		vm_map_clip_unnest(map, entry, start_unnest, end_unnest);
	}
#endif /* NO_NESTED_PMAP */
	if (startaddr > entry->vme_start) {
		if (entry->object.vm_object &&
		    !entry->is_sub_map &&
		    entry->object.vm_object->phys_contiguous) {
			pmap_remove(map->pmap,
				    (addr64_t)(entry->vme_start),
				    (addr64_t)(entry->vme_end));
		}
		_vm_map_clip_start(&map->hdr, entry, startaddr);
		vm_map_store_update_first_free(map, map->first_free);
	}
}


#define vm_map_copy_clip_start(copy, entry, startaddr) \
	MACRO_BEGIN \
	if ((startaddr) > (entry)->vme_start) \
		_vm_map_clip_start(&(copy)->cpy_hdr,(entry),(startaddr)); \
	MACRO_END

/*
 *	This routine is called only when it is known that
 *	the entry must be split.
 */
static void
_vm_map_clip_start(
	register struct vm_map_header	*map_header,
	register vm_map_entry_t		entry,
	register vm_map_offset_t		start)
{
	register vm_map_entry_t	new_entry;

	/*
	 *	Split off the front portion --
	 *	note that we must insert the new
	 *	entry BEFORE this one, so that
	 *	this entry has the specified starting
	 *	address.
	 */

	new_entry = _vm_map_entry_create(map_header);
	vm_map_entry_copy_full(new_entry, entry);

	new_entry->vme_end = start;
	entry->offset += (start - entry->vme_start);
	entry->vme_start = start;

	_vm_map_store_entry_link(map_header, entry->vme_prev, new_entry);

	if (entry->is_sub_map)
		vm_map_reference(new_entry->object.sub_map);
	else
		vm_object_reference(new_entry->object.vm_object);
}


/*
 *	vm_map_clip_end:	[ internal use only ]
 *
 *	Asserts that the given entry ends at or before
 *	the specified address; if necessary,
 *	it splits the entry into two.
 */
static void
vm_map_clip_end(
	vm_map_t	map,
	vm_map_entry_t	entry,
	vm_map_offset_t	endaddr)
{
	if (endaddr > entry->vme_end) {
		/*
		 * Within the scope of this clipping, limit "endaddr" to
		 * the end of this map entry...
		 */
		endaddr = entry->vme_end;
	}
#ifndef NO_NESTED_PMAP
	if (entry->use_pmap) {
		vm_map_offset_t	start_unnest, end_unnest;

		/*
		 * Make sure the range between the start of this entry and
		 * the new "endaddr" is no longer nested before we clip.
		 * Unnest only the minimum range the platform can handle.
		 * vm_map_clip_unnest may perform additional adjustments to
		 * the unnest range.
		 */
		start_unnest = entry->vme_start;
		end_unnest =
			(endaddr + pmap_nesting_size_min - 1) &
			~(pmap_nesting_size_min - 1);
		vm_map_clip_unnest(map, entry, start_unnest, end_unnest);
	}
#endif /* NO_NESTED_PMAP */
	if (endaddr < entry->vme_end) {
		if (entry->object.vm_object &&
		    !entry->is_sub_map &&
		    entry->object.vm_object->phys_contiguous) {
			pmap_remove(map->pmap,
				    (addr64_t)(entry->vme_start),
				    (addr64_t)(entry->vme_end));
		}
		_vm_map_clip_end(&map->hdr, entry, endaddr);
		vm_map_store_update_first_free(map, map->first_free);
	}
}


#define vm_map_copy_clip_end(copy, entry, endaddr) \
	MACRO_BEGIN \
	if ((endaddr) < (entry)->vme_end) \
		_vm_map_clip_end(&(copy)->cpy_hdr,(entry),(endaddr)); \
	MACRO_END

/*
 *	This routine is called only when it is known that
 *	the entry must be split.
 */
static void
_vm_map_clip_end(
	register struct vm_map_header	*map_header,
	register vm_map_entry_t		entry,
	register vm_map_offset_t	end)
{
	register vm_map_entry_t	new_entry;

	/*
	 *	Create a new entry and insert it
	 *	AFTER the specified entry
	 */

	new_entry = _vm_map_entry_create(map_header);
	vm_map_entry_copy_full(new_entry, entry);

	new_entry->vme_start = entry->vme_end = end;
	new_entry->offset += (end - entry->vme_start);

	_vm_map_store_entry_link(map_header, entry, new_entry);

	if (entry->is_sub_map)
		vm_map_reference(new_entry->object.sub_map);
	else
		vm_object_reference(new_entry->object.vm_object);
}


/*
 *	VM_MAP_RANGE_CHECK:	[ internal use only ]
 *
 *	Asserts that the starting and ending region
 *	addresses fall within the valid range of the map.
 */
#define	VM_MAP_RANGE_CHECK(map, start, end)	\
	MACRO_BEGIN				\
	if (start < vm_map_min(map))		\
		start = vm_map_min(map);	\
	if (end > vm_map_max(map))		\
		end = vm_map_max(map);		\
	if (start > end)			\
		start = end;			\
	MACRO_END

/*
 *	vm_map_range_check:	[ internal use only ]
 *	
 *	Check that the region defined by the specified start and
 *	end addresses are wholly contained within a single map
 *	entry or set of adjacent map entries of the spacified map,
 *	i.e. the specified region contains no unmapped space.
 *	If any or all of the region is unmapped, FALSE is returned.
 *	Otherwise, TRUE is returned and if the output argument 'entry'
 *	is not NULL it points to the map entry containing the start
 *	of the region.
 *
 *	The map is locked for reading on entry and is left locked.
 */
static boolean_t
vm_map_range_check(
	register vm_map_t	map,
	register vm_map_offset_t	start,
	register vm_map_offset_t	end,
	vm_map_entry_t		*entry)
{
	vm_map_entry_t		cur;
	register vm_map_offset_t	prev;

	/*
	 * 	Basic sanity checks first
	 */
	if (start < vm_map_min(map) || end > vm_map_max(map) || start > end)
		return (FALSE);

	/*
	 * 	Check first if the region starts within a valid
	 *	mapping for the map.
	 */
	if (!vm_map_lookup_entry(map, start, &cur))
		return (FALSE);

	/*
	 *	Optimize for the case that the region is contained 
	 *	in a single map entry.
	 */
	if (entry != (vm_map_entry_t *) NULL)
		*entry = cur;
	if (end <= cur->vme_end)
		return (TRUE);

	/*
	 * 	If the region is not wholly contained within a
	 * 	single entry, walk the entries looking for holes.
	 */
	prev = cur->vme_end;
	cur = cur->vme_next;
	while ((cur != vm_map_to_entry(map)) && (prev == cur->vme_start)) {
		if (end <= cur->vme_end)
			return (TRUE);
		prev = cur->vme_end;
		cur = cur->vme_next;
	}
	return (FALSE);
}

/*
 *	vm_map_submap:		[ kernel use only ]
 *
 *	Mark the given range as handled by a subordinate map.
 *
 *	This range must have been created with vm_map_find using
 *	the vm_submap_object, and no other operations may have been
 *	performed on this range prior to calling vm_map_submap.
 *
 *	Only a limited number of operations can be performed
 *	within this rage after calling vm_map_submap:
 *		vm_fault
 *	[Don't try vm_map_copyin!]
 *
 *	To remove a submapping, one must first remove the
 *	range from the superior map, and then destroy the
 *	submap (if desired).  [Better yet, don't try it.]
 */
kern_return_t
vm_map_submap(
	vm_map_t		map,
	vm_map_offset_t	start,
	vm_map_offset_t	end,
	vm_map_t		submap,
	vm_map_offset_t	offset,
#ifdef NO_NESTED_PMAP
	__unused
#endif	/* NO_NESTED_PMAP */
	boolean_t		use_pmap)
{
	vm_map_entry_t		entry;
	register kern_return_t	result = KERN_INVALID_ARGUMENT;
	register vm_object_t	object;

	vm_map_lock(map);

	if (! vm_map_lookup_entry(map, start, &entry)) {
		entry = entry->vme_next;
	}

	if (entry == vm_map_to_entry(map) ||
	    entry->is_sub_map) {
		vm_map_unlock(map);
		return KERN_INVALID_ARGUMENT;
	}

	assert(!entry->use_pmap); /* we don't want to unnest anything here */
	vm_map_clip_start(map, entry, start);
	vm_map_clip_end(map, entry, end);

	if ((entry->vme_start == start) && (entry->vme_end == end) &&
	    (!entry->is_sub_map) &&
	    ((object = entry->object.vm_object) == vm_submap_object) &&
	    (object->resident_page_count == 0) &&
	    (object->copy == VM_OBJECT_NULL) &&
	    (object->shadow == VM_OBJECT_NULL) &&
	    (!object->pager_created)) {
		entry->offset = (vm_object_offset_t)offset;
		entry->object.vm_object = VM_OBJECT_NULL;
		vm_object_deallocate(object);
		entry->is_sub_map = TRUE;
		entry->object.sub_map = submap;
		vm_map_reference(submap);
		submap->mapped = TRUE;

#ifndef NO_NESTED_PMAP
		if (use_pmap) {
			/* nest if platform code will allow */
			if(submap->pmap == NULL) {
				submap->pmap = pmap_create((vm_map_size_t) 0, FALSE);
				if(submap->pmap == PMAP_NULL) {
					vm_map_unlock(map);
					return(KERN_NO_SPACE);
				}
			}
			result = pmap_nest(map->pmap,
					   (entry->object.sub_map)->pmap, 
					   (addr64_t)start,
					   (addr64_t)start,
					   (uint64_t)(end - start));
			if(result)
				panic("vm_map_submap: pmap_nest failed, rc = %08X\n", result);
			entry->use_pmap = TRUE;
		}
#else	/* NO_NESTED_PMAP */
		pmap_remove(map->pmap, (addr64_t)start, (addr64_t)end);
#endif	/* NO_NESTED_PMAP */
		result = KERN_SUCCESS;
	}
	vm_map_unlock(map);

	return(result);
}

/*
 *	vm_map_protect:
 *
 *	Sets the protection of the specified address
 *	region in the target map.  If "set_max" is
 *	specified, the maximum protection is to be set;
 *	otherwise, only the current protection is affected.
 */
kern_return_t
vm_map_protect(
	register vm_map_t	map,
	register vm_map_offset_t	start,
	register vm_map_offset_t	end,
	register vm_prot_t	new_prot,
	register boolean_t	set_max)
{
	register vm_map_entry_t		current;
	register vm_map_offset_t	prev;
	vm_map_entry_t			entry;
	vm_prot_t			new_max;

	XPR(XPR_VM_MAP,
	    "vm_map_protect, 0x%X start 0x%X end 0x%X, new 0x%X %d",
	    map, start, end, new_prot, set_max);

	vm_map_lock(map);

	/* LP64todo - remove this check when vm_map_commpage64()
	 * no longer has to stuff in a map_entry for the commpage
	 * above the map's max_offset.
	 */
	if (start >= map->max_offset) {
		vm_map_unlock(map);
		return(KERN_INVALID_ADDRESS);
	}

	while(1) {
		/*
		 * 	Lookup the entry.  If it doesn't start in a valid
		 *	entry, return an error.
		 */
		if (! vm_map_lookup_entry(map, start, &entry)) {
			vm_map_unlock(map);
			return(KERN_INVALID_ADDRESS);
		}

		if (entry->superpage_size && (start & (SUPERPAGE_SIZE-1))) { /* extend request to whole entry */
			start = SUPERPAGE_ROUND_DOWN(start);
			continue;
		}
		break;
 	}
	if (entry->superpage_size)
 		end = SUPERPAGE_ROUND_UP(end);

	/*
	 *	Make a first pass to check for protection and address
	 *	violations.
	 */

	current = entry;
	prev = current->vme_start;
	while ((current != vm_map_to_entry(map)) &&
	       (current->vme_start < end)) {

		/*
		 * If there is a hole, return an error.
		 */
		if (current->vme_start != prev) {
			vm_map_unlock(map);
			return(KERN_INVALID_ADDRESS);
		}

		new_max = current->max_protection;
		if(new_prot & VM_PROT_COPY) {
			new_max |= VM_PROT_WRITE;
			if ((new_prot & (new_max | VM_PROT_COPY)) != new_prot) {
				vm_map_unlock(map);
				return(KERN_PROTECTION_FAILURE);
			}
		} else {
			if ((new_prot & new_max) != new_prot) {
				vm_map_unlock(map);
				return(KERN_PROTECTION_FAILURE);
			}
		}

#if CONFIG_EMBEDDED
		if (new_prot & VM_PROT_WRITE) {
			if ((new_prot & VM_PROT_EXECUTE) && !(current->used_for_jit)) {
				printf("EMBEDDED: %s can't have both write and exec at the same time\n", __FUNCTION__);
				new_prot &= ~VM_PROT_EXECUTE;
			}
		}
#endif

		prev = current->vme_end;
		current = current->vme_next;
	}
	if (end > prev) {
		vm_map_unlock(map);
		return(KERN_INVALID_ADDRESS);
	}

	/*
	 *	Go back and fix up protections.
	 *	Clip to start here if the range starts within
	 *	the entry.
	 */

	current = entry;
	if (current != vm_map_to_entry(map)) {
		/* clip and unnest if necessary */
		vm_map_clip_start(map, current, start);
	}

	while ((current != vm_map_to_entry(map)) &&
	       (current->vme_start < end)) {

		vm_prot_t	old_prot;

		vm_map_clip_end(map, current, end);

		assert(!current->use_pmap); /* clipping did unnest if needed */

		old_prot = current->protection;

		if(new_prot & VM_PROT_COPY) {
			/* caller is asking specifically to copy the      */
			/* mapped data, this implies that max protection  */
			/* will include write.  Caller must be prepared   */
			/* for loss of shared memory communication in the */
			/* target area after taking this step */

			if (current->is_sub_map == FALSE && current->object.vm_object == VM_OBJECT_NULL){
				current->object.vm_object = vm_object_allocate((vm_map_size_t)(current->vme_end - current->vme_start));
				current->offset = 0;
			}
			current->needs_copy = TRUE;
			current->max_protection |= VM_PROT_WRITE;
		}

		if (set_max)
			current->protection =
				(current->max_protection = 
				 new_prot & ~VM_PROT_COPY) &
				old_prot;
		else
			current->protection = new_prot & ~VM_PROT_COPY;

		/*
		 *	Update physical map if necessary.
		 *	If the request is to turn off write protection, 
		 *	we won't do it for real (in pmap). This is because 
		 *	it would cause copy-on-write to fail.  We've already 
		 *	set, the new protection in the map, so if a 
		 *	write-protect fault occurred, it will be fixed up 
		 *	properly, COW or not.
		 */
		if (current->protection != old_prot) {
			/* Look one level in we support nested pmaps */
			/* from mapped submaps which are direct entries */
			/* in our map */

			vm_prot_t prot;

			prot = current->protection & ~VM_PROT_WRITE;

			if (override_nx(map, current->alias) && prot)
			        prot |= VM_PROT_EXECUTE;

			if (current->is_sub_map && current->use_pmap) {
				pmap_protect(current->object.sub_map->pmap, 
					     current->vme_start,
					     current->vme_end,
					     prot);
			} else {
				pmap_protect(map->pmap,
					     current->vme_start,
					     current->vme_end,
					     prot);
			}
		}
		current = current->vme_next;
	}

	current = entry;
	while ((current != vm_map_to_entry(map)) &&
	       (current->vme_start <= end)) {
		vm_map_simplify_entry(map, current);
		current = current->vme_next;
	}

	vm_map_unlock(map);
	return(KERN_SUCCESS);
}

/*
 *	vm_map_inherit:
 *
 *	Sets the inheritance of the specified address
 *	range in the target map.  Inheritance
 *	affects how the map will be shared with
 *	child maps at the time of vm_map_fork.
 */
kern_return_t
vm_map_inherit(
	register vm_map_t	map,
	register vm_map_offset_t	start,
	register vm_map_offset_t	end,
	register vm_inherit_t	new_inheritance)
{
	register vm_map_entry_t	entry;
	vm_map_entry_t	temp_entry;

	vm_map_lock(map);

	VM_MAP_RANGE_CHECK(map, start, end);

	if (vm_map_lookup_entry(map, start, &temp_entry)) {
		entry = temp_entry;
	}
	else {
		temp_entry = temp_entry->vme_next;
		entry = temp_entry;
	}

	/* first check entire range for submaps which can't support the */
	/* given inheritance. */
	while ((entry != vm_map_to_entry(map)) && (entry->vme_start < end)) {
		if(entry->is_sub_map) {
			if(new_inheritance == VM_INHERIT_COPY) {
				vm_map_unlock(map);
				return(KERN_INVALID_ARGUMENT);
			}
		}

		entry = entry->vme_next;
	}

	entry = temp_entry;
	if (entry != vm_map_to_entry(map)) {
		/* clip and unnest if necessary */
		vm_map_clip_start(map, entry, start);
	}

	while ((entry != vm_map_to_entry(map)) && (entry->vme_start < end)) {
		vm_map_clip_end(map, entry, end);
		assert(!entry->use_pmap); /* clip did unnest if needed */

		entry->inheritance = new_inheritance;

		entry = entry->vme_next;
	}

	vm_map_unlock(map);
	return(KERN_SUCCESS);
}

/*
 * Update the accounting for the amount of wired memory in this map.  If the user has
 * exceeded the defined limits, then we fail.  Wiring on behalf of the kernel never fails.
 */

static kern_return_t
add_wire_counts(
	vm_map_t	map,
	vm_map_entry_t	entry, 
	boolean_t	user_wire)
{ 
	vm_map_size_t	size;

	if (user_wire) {
		unsigned int total_wire_count =  vm_page_wire_count + vm_lopage_free_count;

		/*
		 * We're wiring memory at the request of the user.  Check if this is the first time the user is wiring
		 * this map entry.
		 */

		if (entry->user_wired_count == 0) {
			size = entry->vme_end - entry->vme_start;
 
			/*
			 * Since this is the first time the user is wiring this map entry, check to see if we're
			 * exceeding the user wire limits.  There is a per map limit which is the smaller of either
			 * the process's rlimit or the global vm_user_wire_limit which caps this value.  There is also
			 * a system-wide limit on the amount of memory all users can wire.  If the user is over either
			 * limit, then we fail.
			 */

			if(size + map->user_wire_size > MIN(map->user_wire_limit, vm_user_wire_limit) ||
			   size + ptoa_64(total_wire_count) > vm_global_user_wire_limit ||
		    	   size + ptoa_64(total_wire_count) > max_mem - vm_global_no_user_wire_amount)
				return KERN_RESOURCE_SHORTAGE;

			/*
			 * The first time the user wires an entry, we also increment the wired_count and add this to
			 * the total that has been wired in the map.
			 */

			if (entry->wired_count >= MAX_WIRE_COUNT)
				return KERN_FAILURE;

			entry->wired_count++;
			map->user_wire_size += size;
		}

		if (entry->user_wired_count >= MAX_WIRE_COUNT)
			return KERN_FAILURE;

		entry->user_wired_count++;

	} else {

		/*
		 * The kernel's wiring the memory.  Just bump the count and continue.
		 */

		if (entry->wired_count >= MAX_WIRE_COUNT)
			panic("vm_map_wire: too many wirings");

		entry->wired_count++;
	}

	return KERN_SUCCESS;
}

/*
 * Update the memory wiring accounting now that the given map entry is being unwired.
 */

static void
subtract_wire_counts(
	vm_map_t	map,
	vm_map_entry_t	entry, 
	boolean_t	user_wire)
{ 

	if (user_wire) {

		/*
		 * We're unwiring memory at the request of the user.  See if we're removing the last user wire reference.
		 */

		if (entry->user_wired_count == 1) {

			/*
			 * We're removing the last user wire reference.  Decrement the wired_count and the total
			 * user wired memory for this map.
			 */

			assert(entry->wired_count >= 1);
			entry->wired_count--;
			map->user_wire_size -= entry->vme_end - entry->vme_start;
		}

		assert(entry->user_wired_count >= 1);
		entry->user_wired_count--;

	} else {

		/*
		 * The kernel is unwiring the memory.   Just update the count.
		 */

		assert(entry->wired_count >= 1);
		entry->wired_count--;
	}
}

/*
 *	vm_map_wire:
 *
 *	Sets the pageability of the specified address range in the
 *	target map as wired.  Regions specified as not pageable require
 *	locked-down physical memory and physical page maps.  The
 *	access_type variable indicates types of accesses that must not
 *	generate page faults.  This is checked against protection of
 *	memory being locked-down.
 *
 *	The map must not be locked, but a reference must remain to the
 *	map throughout the call.
 */
static kern_return_t
vm_map_wire_nested(
	register vm_map_t	map,
	register vm_map_offset_t	start,
	register vm_map_offset_t	end,
	register vm_prot_t	access_type,
	boolean_t		user_wire,
	pmap_t			map_pmap, 
	vm_map_offset_t		pmap_addr)
{
	register vm_map_entry_t	entry;
	struct vm_map_entry	*first_entry, tmp_entry;
	vm_map_t		real_map;
	register vm_map_offset_t	s,e;
	kern_return_t		rc;
	boolean_t		need_wakeup;
	boolean_t		main_map = FALSE;
	wait_interrupt_t	interruptible_state;
	thread_t		cur_thread;
	unsigned int		last_timestamp;
	vm_map_size_t		size;

	vm_map_lock(map);
	if(map_pmap == NULL)
		main_map = TRUE;
	last_timestamp = map->timestamp;

	VM_MAP_RANGE_CHECK(map, start, end);
	assert(page_aligned(start));
	assert(page_aligned(end));
	if (start == end) {
		/* We wired what the caller asked for, zero pages */
		vm_map_unlock(map);
		return KERN_SUCCESS;
	}

	need_wakeup = FALSE;
	cur_thread = current_thread();

	s = start;
	rc = KERN_SUCCESS;

	if (vm_map_lookup_entry(map, s, &first_entry)) {
		entry = first_entry;
		/*
		 * vm_map_clip_start will be done later.
		 * We don't want to unnest any nested submaps here !
		 */
	} else {
		/* Start address is not in map */
		rc = KERN_INVALID_ADDRESS;
		goto done;
	}

	while ((entry != vm_map_to_entry(map)) && (s < end)) {
		/*
		 * At this point, we have wired from "start" to "s".
		 * We still need to wire from "s" to "end".
		 *
		 * "entry" hasn't been clipped, so it could start before "s"
		 * and/or end after "end".
		 */

		/* "e" is how far we want to wire in this entry */
		e = entry->vme_end;
		if (e > end)
			e = end;

		/*
		 * If another thread is wiring/unwiring this entry then
		 * block after informing other thread to wake us up.
		 */
		if (entry->in_transition) {
			wait_result_t wait_result;

			/*
			 * We have not clipped the entry.  Make sure that
			 * the start address is in range so that the lookup
			 * below will succeed.
			 * "s" is the current starting point: we've already
			 * wired from "start" to "s" and we still have
			 * to wire from "s" to "end".
			 */

			entry->needs_wakeup = TRUE;

			/*
			 * wake up anybody waiting on entries that we have
			 * already wired.
			 */
			if (need_wakeup) {
				vm_map_entry_wakeup(map);
				need_wakeup = FALSE;
			}
			/*
			 * User wiring is interruptible
			 */
			wait_result = vm_map_entry_wait(map, 
							(user_wire) ? THREAD_ABORTSAFE :
							THREAD_UNINT);
			if (user_wire && wait_result ==	THREAD_INTERRUPTED) {
				/*
				 * undo the wirings we have done so far
				 * We do not clear the needs_wakeup flag,
				 * because we cannot tell if we were the
				 * only one waiting.
				 */
				rc = KERN_FAILURE;
				goto done;
			}

			/*
			 * Cannot avoid a lookup here. reset timestamp.
			 */
			last_timestamp = map->timestamp;

			/*
			 * The entry could have been clipped, look it up again.
			 * Worse that can happen is, it may not exist anymore.
			 */
			if (!vm_map_lookup_entry(map, s, &first_entry)) {
				/*
				 * User: undo everything upto the previous
				 * entry.  let vm_map_unwire worry about
				 * checking the validity of the range.
				 */
				rc = KERN_FAILURE;
				goto done;
			}
			entry = first_entry;
			continue;
		}
	
		if (entry->is_sub_map) {
			vm_map_offset_t	sub_start;
			vm_map_offset_t	sub_end;
			vm_map_offset_t	local_start;
			vm_map_offset_t	local_end;
			pmap_t		pmap;

			vm_map_clip_start(map, entry, s);
			vm_map_clip_end(map, entry, end);

			sub_start = entry->offset;
			sub_end = entry->vme_end;
			sub_end += entry->offset - entry->vme_start;
		
			local_end = entry->vme_end;
			if(map_pmap == NULL) {
				vm_object_t		object;
				vm_object_offset_t	offset;
				vm_prot_t		prot;
				boolean_t		wired;
				vm_map_entry_t		local_entry;
				vm_map_version_t	 version;
				vm_map_t		lookup_map;

				if(entry->use_pmap) {
					pmap = entry->object.sub_map->pmap;
					/* ppc implementation requires that */
					/* submaps pmap address ranges line */
					/* up with parent map */
#ifdef notdef
					pmap_addr = sub_start;
#endif
					pmap_addr = s;
				} else {
					pmap = map->pmap;
					pmap_addr = s;
				}

				if (entry->wired_count) {
					if ((rc = add_wire_counts(map, entry, user_wire)) != KERN_SUCCESS)
						goto done;

					/*
					 * The map was not unlocked:
					 * no need to goto re-lookup.
					 * Just go directly to next entry.
					 */
					entry = entry->vme_next;
					s = entry->vme_start;
					continue;

				}

				/* call vm_map_lookup_locked to */
				/* cause any needs copy to be   */
				/* evaluated */
				local_start = entry->vme_start;
				lookup_map = map;
				vm_map_lock_write_to_read(map);
				if(vm_map_lookup_locked(
					   &lookup_map, local_start, 
					   access_type,
					   OBJECT_LOCK_EXCLUSIVE,
					   &version, &object,
					   &offset, &prot, &wired,
					   NULL,
					   &real_map)) {

					vm_map_unlock_read(lookup_map);
					vm_map_unwire(map, start,
						      s, user_wire);
					return(KERN_FAILURE);
				}
				if(real_map != lookup_map)
					vm_map_unlock(real_map);
				vm_map_unlock_read(lookup_map);
				vm_map_lock(map);
				vm_object_unlock(object);

				/* we unlocked, so must re-lookup */
				if (!vm_map_lookup_entry(map, 
							 local_start,
							 &local_entry)) {
					rc = KERN_FAILURE;
					goto done;
				}

				/*
				 * entry could have been "simplified",
				 * so re-clip
				 */
				entry = local_entry;
				assert(s == local_start);
				vm_map_clip_start(map, entry, s);
				vm_map_clip_end(map, entry, end);
				/* re-compute "e" */
				e = entry->vme_end;
				if (e > end)
					e = end;

				/* did we have a change of type? */
				if (!entry->is_sub_map) {
					last_timestamp = map->timestamp;
					continue;
				}
			} else {
				local_start = entry->vme_start;
				pmap = map_pmap;
			}

			if ((rc = add_wire_counts(map, entry, user_wire)) != KERN_SUCCESS)
				goto done;

			entry->in_transition = TRUE;

			vm_map_unlock(map);
			rc = vm_map_wire_nested(entry->object.sub_map, 
						sub_start, sub_end,
						access_type, 
						user_wire, pmap, pmap_addr);
			vm_map_lock(map);

			/*
			 * Find the entry again.  It could have been clipped
			 * after we unlocked the map.
			 */
			if (!vm_map_lookup_entry(map, local_start,
						 &first_entry))
				panic("vm_map_wire: re-lookup failed");
			entry = first_entry;

			assert(local_start == s);
			/* re-compute "e" */
			e = entry->vme_end;
			if (e > end)
				e = end;

			last_timestamp = map->timestamp;
			while ((entry != vm_map_to_entry(map)) &&
			       (entry->vme_start < e)) {
				assert(entry->in_transition);
				entry->in_transition = FALSE;
				if (entry->needs_wakeup) {
					entry->needs_wakeup = FALSE;
					need_wakeup = TRUE;
				}
				if (rc != KERN_SUCCESS) {/* from vm_*_wire */
					subtract_wire_counts(map, entry, user_wire);
				}
				entry = entry->vme_next;
			}
			if (rc != KERN_SUCCESS) {	/* from vm_*_wire */
				goto done;
			}

			/* no need to relookup again */
			s = entry->vme_start;
			continue;
		}

		/*
		 * If this entry is already wired then increment
		 * the appropriate wire reference count.
		 */
		if (entry->wired_count) {
			/*
			 * entry is already wired down, get our reference
			 * after clipping to our range.
			 */
			vm_map_clip_start(map, entry, s);
			vm_map_clip_end(map, entry, end);

			if ((rc = add_wire_counts(map, entry, user_wire)) != KERN_SUCCESS)
				goto done;

			/* map was not unlocked: no need to relookup */
			entry = entry->vme_next;
			s = entry->vme_start;
			continue;
		}

		/*
		 * Unwired entry or wire request transmitted via submap
		 */


		/*
		 * Perform actions of vm_map_lookup that need the write
		 * lock on the map: create a shadow object for a
		 * copy-on-write region, or an object for a zero-fill
		 * region.
		 */
		size = entry->vme_end - entry->vme_start;
		/*
		 * If wiring a copy-on-write page, we need to copy it now
		 * even if we're only (currently) requesting read access.
		 * This is aggressive, but once it's wired we can't move it.
		 */
		if (entry->needs_copy) {
			vm_object_shadow(&entry->object.vm_object,
					 &entry->offset, size);
			entry->needs_copy = FALSE;
		} else if (entry->object.vm_object == VM_OBJECT_NULL) {
			entry->object.vm_object = vm_object_allocate(size);
			entry->offset = (vm_object_offset_t)0;
		}

		vm_map_clip_start(map, entry, s);
		vm_map_clip_end(map, entry, end);

		/* re-compute "e" */
		e = entry->vme_end;
		if (e > end)
			e = end;

		/*
		 * Check for holes and protection mismatch.
		 * Holes: Next entry should be contiguous unless this
		 *	  is the end of the region.
		 * Protection: Access requested must be allowed, unless
		 *	wiring is by protection class
		 */
		if ((entry->vme_end < end) &&
		    ((entry->vme_next == vm_map_to_entry(map)) ||
		     (entry->vme_next->vme_start > entry->vme_end))) {
			/* found a hole */
			rc = KERN_INVALID_ADDRESS;
			goto done;
		}
		if ((entry->protection & access_type) != access_type) {
			/* found a protection problem */
			rc = KERN_PROTECTION_FAILURE;
			goto done;
		}

		assert(entry->wired_count == 0 && entry->user_wired_count == 0);

		if ((rc = add_wire_counts(map, entry, user_wire)) != KERN_SUCCESS)
			goto done;

		entry->in_transition = TRUE;

		/*
		 * This entry might get split once we unlock the map.
		 * In vm_fault_wire(), we need the current range as
		 * defined by this entry.  In order for this to work
		 * along with a simultaneous clip operation, we make a
		 * temporary copy of this entry and use that for the
		 * wiring.  Note that the underlying objects do not
		 * change during a clip.
		 */
		tmp_entry = *entry;

		/*
		 * The in_transition state guarentees that the entry
		 * (or entries for this range, if split occured) will be
		 * there when the map lock is acquired for the second time.
		 */
		vm_map_unlock(map);

		if (!user_wire && cur_thread != THREAD_NULL)
			interruptible_state = thread_interrupt_level(THREAD_UNINT);
		else
			interruptible_state = THREAD_UNINT;

		if(map_pmap)
			rc = vm_fault_wire(map, 
					   &tmp_entry, map_pmap, pmap_addr);
		else
			rc = vm_fault_wire(map, 
					   &tmp_entry, map->pmap, 
					   tmp_entry.vme_start);

		if (!user_wire && cur_thread != THREAD_NULL)
			thread_interrupt_level(interruptible_state);

		vm_map_lock(map);

		if (last_timestamp+1 != map->timestamp) {
			/*
			 * Find the entry again.  It could have been clipped
			 * after we unlocked the map.
			 */
			if (!vm_map_lookup_entry(map, tmp_entry.vme_start,
						 &first_entry))
				panic("vm_map_wire: re-lookup failed");

			entry = first_entry;
		}

		last_timestamp = map->timestamp;

		while ((entry != vm_map_to_entry(map)) &&
		       (entry->vme_start < tmp_entry.vme_end)) {
			assert(entry->in_transition);
			entry->in_transition = FALSE;
			if (entry->needs_wakeup) {
				entry->needs_wakeup = FALSE;
				need_wakeup = TRUE;
			}
			if (rc != KERN_SUCCESS) {	/* from vm_*_wire */
				subtract_wire_counts(map, entry, user_wire);
			}
			entry = entry->vme_next;
		}

		if (rc != KERN_SUCCESS) {		/* from vm_*_wire */
			goto done;
		}

		s = entry->vme_start;
	} /* end while loop through map entries */

done:
	if (rc == KERN_SUCCESS) {
		/* repair any damage we may have made to the VM map */
		vm_map_simplify_range(map, start, end);
	}

	vm_map_unlock(map);

	/*
	 * wake up anybody waiting on entries we wired.
	 */
	if (need_wakeup)
		vm_map_entry_wakeup(map);

	if (rc != KERN_SUCCESS) {
		/* undo what has been wired so far */
		vm_map_unwire(map, start, s, user_wire);
	}

	return rc;

}

kern_return_t
vm_map_wire(
	register vm_map_t	map,
	register vm_map_offset_t	start,
	register vm_map_offset_t	end,
	register vm_prot_t	access_type,
	boolean_t		user_wire)
{

	kern_return_t	kret;

	kret = vm_map_wire_nested(map, start, end, access_type, 
				  user_wire, (pmap_t)NULL, 0);
	return kret;
}

/*
 *	vm_map_unwire:
 *
 *	Sets the pageability of the specified address range in the target
 *	as pageable.  Regions specified must have been wired previously.
 *
 *	The map must not be locked, but a reference must remain to the map
 *	throughout the call.
 *
 *	Kernel will panic on failures.  User unwire ignores holes and
 *	unwired and intransition entries to avoid losing memory by leaving
 *	it unwired.
 */
static kern_return_t
vm_map_unwire_nested(
	register vm_map_t	map,
	register vm_map_offset_t	start,
	register vm_map_offset_t	end,
	boolean_t		user_wire,
	pmap_t			map_pmap,
	vm_map_offset_t		pmap_addr)
{
	register vm_map_entry_t	entry;
	struct vm_map_entry	*first_entry, tmp_entry;
	boolean_t		need_wakeup;
	boolean_t		main_map = FALSE;
	unsigned int		last_timestamp;

	vm_map_lock(map);
	if(map_pmap == NULL)
		main_map = TRUE;
	last_timestamp = map->timestamp;

	VM_MAP_RANGE_CHECK(map, start, end);
	assert(page_aligned(start));
	assert(page_aligned(end));

	if (start == end) {
		/* We unwired what the caller asked for: zero pages */
		vm_map_unlock(map);
		return KERN_SUCCESS;
	}

	if (vm_map_lookup_entry(map, start, &first_entry)) {
		entry = first_entry;
		/*
		 * vm_map_clip_start will be done later.
		 * We don't want to unnest any nested sub maps here !
		 */
	}
	else {
		if (!user_wire) {
			panic("vm_map_unwire: start not found");
		}
		/*	Start address is not in map. */
		vm_map_unlock(map);
		return(KERN_INVALID_ADDRESS);
	}

	if (entry->superpage_size) {
		/* superpages are always wired */
		vm_map_unlock(map);
		return KERN_INVALID_ADDRESS;
	}

	need_wakeup = FALSE;
	while ((entry != vm_map_to_entry(map)) && (entry->vme_start < end)) {
		if (entry->in_transition) {
			/*
			 * 1)
			 * Another thread is wiring down this entry. Note
			 * that if it is not for the other thread we would
			 * be unwiring an unwired entry.  This is not
			 * permitted.  If we wait, we will be unwiring memory
			 * we did not wire.
			 *
			 * 2)
			 * Another thread is unwiring this entry.  We did not
			 * have a reference to it, because if we did, this
			 * entry will not be getting unwired now.
			 */
			if (!user_wire) {
				/*
				 * XXX FBDP
				 * This could happen:  there could be some
				 * overlapping vslock/vsunlock operations
				 * going on.
				 * We should probably just wait and retry,
				 * but then we have to be careful that this
				 * entry could get "simplified" after 
				 * "in_transition" gets unset and before
				 * we re-lookup the entry, so we would
				 * have to re-clip the entry to avoid
				 * re-unwiring what we have already unwired...
				 * See vm_map_wire_nested().
				 *
				 * Or we could just ignore "in_transition"
				 * here and proceed to decement the wired
				 * count(s) on this entry.  That should be fine
				 * as long as "wired_count" doesn't drop all
				 * the way to 0 (and we should panic if THAT
				 * happens).
				 */
				panic("vm_map_unwire: in_transition entry");
			}

			entry = entry->vme_next;
			continue;
		}

		if (entry->is_sub_map) {
			vm_map_offset_t	sub_start;
			vm_map_offset_t	sub_end;
			vm_map_offset_t	local_end;
			pmap_t		pmap;
		
			vm_map_clip_start(map, entry, start);
			vm_map_clip_end(map, entry, end);

			sub_start = entry->offset;
			sub_end = entry->vme_end - entry->vme_start;
			sub_end += entry->offset;
			local_end = entry->vme_end;
			if(map_pmap == NULL) {
				if(entry->use_pmap) {
					pmap = entry->object.sub_map->pmap;
					pmap_addr = sub_start;
				} else {
					pmap = map->pmap;
					pmap_addr = start;
				}
				if (entry->wired_count == 0 ||
				    (user_wire && entry->user_wired_count == 0)) {
					if (!user_wire)
						panic("vm_map_unwire: entry is unwired");
					entry = entry->vme_next;
					continue;
				}

				/*
				 * Check for holes
				 * Holes: Next entry should be contiguous unless
				 * this is the end of the region.
				 */
				if (((entry->vme_end < end) && 
				     ((entry->vme_next == vm_map_to_entry(map)) ||
				      (entry->vme_next->vme_start 
				       > entry->vme_end)))) {
					if (!user_wire)
						panic("vm_map_unwire: non-contiguous region");
/*
					entry = entry->vme_next;
					continue;
*/
				}

				subtract_wire_counts(map, entry, user_wire);

				if (entry->wired_count != 0) {
					entry = entry->vme_next;
					continue;
				}

				entry->in_transition = TRUE;
				tmp_entry = *entry;/* see comment in vm_map_wire() */

				/*
				 * We can unlock the map now. The in_transition state
				 * guarantees existance of the entry.
				 */
				vm_map_unlock(map);
				vm_map_unwire_nested(entry->object.sub_map, 
						     sub_start, sub_end, user_wire, pmap, pmap_addr);
				vm_map_lock(map);

				if (last_timestamp+1 != map->timestamp) {
					/*
					 * Find the entry again.  It could have been 
					 * clipped or deleted after we unlocked the map.
					 */
					if (!vm_map_lookup_entry(map, 
								 tmp_entry.vme_start,
								 &first_entry)) {
						if (!user_wire)
							panic("vm_map_unwire: re-lookup failed");
						entry = first_entry->vme_next;
					} else
						entry = first_entry;
				}
				last_timestamp = map->timestamp;

				/*
				 * clear transition bit for all constituent entries
				 * that were in the original entry (saved in 
				 * tmp_entry).  Also check for waiters.
				 */
				while ((entry != vm_map_to_entry(map)) &&
				       (entry->vme_start < tmp_entry.vme_end)) {
					assert(entry->in_transition);
					entry->in_transition = FALSE;
					if (entry->needs_wakeup) {
						entry->needs_wakeup = FALSE;
						need_wakeup = TRUE;
					}
					entry = entry->vme_next;
				}
				continue;
			} else {
				vm_map_unlock(map);
				vm_map_unwire_nested(entry->object.sub_map,
						     sub_start, sub_end, user_wire, map_pmap,
						     pmap_addr);
				vm_map_lock(map);

				if (last_timestamp+1 != map->timestamp) {
					/*
					 * Find the entry again.  It could have been 
					 * clipped or deleted after we unlocked the map.
					 */
					if (!vm_map_lookup_entry(map, 
								 tmp_entry.vme_start,
								 &first_entry)) {
						if (!user_wire)
							panic("vm_map_unwire: re-lookup failed");
						entry = first_entry->vme_next;
					} else
						entry = first_entry;
				}
				last_timestamp = map->timestamp;
			}
		}


		if ((entry->wired_count == 0) ||
		    (user_wire && entry->user_wired_count == 0)) {
			if (!user_wire)
				panic("vm_map_unwire: entry is unwired");

			entry = entry->vme_next;
			continue;
		}
	
		assert(entry->wired_count > 0 &&
		       (!user_wire || entry->user_wired_count > 0));

		vm_map_clip_start(map, entry, start);
		vm_map_clip_end(map, entry, end);

		/*
		 * Check for holes
		 * Holes: Next entry should be contiguous unless
		 *	  this is the end of the region.
		 */
		if (((entry->vme_end < end) && 
		     ((entry->vme_next == vm_map_to_entry(map)) ||
		      (entry->vme_next->vme_start > entry->vme_end)))) {

			if (!user_wire)
				panic("vm_map_unwire: non-contiguous region");
			entry = entry->vme_next;
			continue;
		}

		subtract_wire_counts(map, entry, user_wire);

		if (entry->wired_count != 0) {
			entry = entry->vme_next;
			continue;
		}

		if(entry->zero_wired_pages) {
			entry->zero_wired_pages = FALSE;
		}

		entry->in_transition = TRUE;
		tmp_entry = *entry;	/* see comment in vm_map_wire() */

		/*
		 * We can unlock the map now. The in_transition state
		 * guarantees existance of the entry.
		 */
		vm_map_unlock(map);
		if(map_pmap) {
			vm_fault_unwire(map, 
					&tmp_entry, FALSE, map_pmap, pmap_addr);
		} else {
			vm_fault_unwire(map, 
					&tmp_entry, FALSE, map->pmap, 
					tmp_entry.vme_start);
		}
		vm_map_lock(map);

		if (last_timestamp+1 != map->timestamp) {
			/*
			 * Find the entry again.  It could have been clipped
			 * or deleted after we unlocked the map.
			 */
			if (!vm_map_lookup_entry(map, tmp_entry.vme_start,
						 &first_entry)) {
				if (!user_wire)
					panic("vm_map_unwire: re-lookup failed");
				entry = first_entry->vme_next;
			} else
				entry = first_entry;
		}
		last_timestamp = map->timestamp;

		/*
		 * clear transition bit for all constituent entries that
		 * were in the original entry (saved in tmp_entry).  Also
		 * check for waiters.
		 */
		while ((entry != vm_map_to_entry(map)) &&
		       (entry->vme_start < tmp_entry.vme_end)) {
			assert(entry->in_transition);
			entry->in_transition = FALSE;
			if (entry->needs_wakeup) {
				entry->needs_wakeup = FALSE;
				need_wakeup = TRUE;
			}
			entry = entry->vme_next;
		}
	}

	/*
	 * We might have fragmented the address space when we wired this
	 * range of addresses.  Attempt to re-coalesce these VM map entries
	 * with their neighbors now that they're no longer wired.
	 * Under some circumstances, address space fragmentation can
	 * prevent VM object shadow chain collapsing, which can cause
	 * swap space leaks.
	 */
	vm_map_simplify_range(map, start, end);

	vm_map_unlock(map);
	/*
	 * wake up anybody waiting on entries that we have unwired.
	 */
	if (need_wakeup)
		vm_map_entry_wakeup(map);
	return(KERN_SUCCESS);

}

kern_return_t
vm_map_unwire(
	register vm_map_t	map,
	register vm_map_offset_t	start,
	register vm_map_offset_t	end,
	boolean_t		user_wire)
{
	return vm_map_unwire_nested(map, start, end, 
				    user_wire, (pmap_t)NULL, 0);
}


/*
 *	vm_map_entry_delete:	[ internal use only ]
 *
 *	Deallocate the given entry from the target map.
 */		
static void
vm_map_entry_delete(
	register vm_map_t	map,
	register vm_map_entry_t	entry)
{
	register vm_map_offset_t	s, e;
	register vm_object_t	object;
	register vm_map_t	submap;

	s = entry->vme_start;
	e = entry->vme_end;
	assert(page_aligned(s));
	assert(page_aligned(e));
	assert(entry->wired_count == 0);
	assert(entry->user_wired_count == 0);
	assert(!entry->permanent);

	if (entry->is_sub_map) {
		object = NULL;
		submap = entry->object.sub_map;
	} else {
		submap = NULL;
		object = entry->object.vm_object;
	}

	vm_map_store_entry_unlink(map, entry);
	map->size -= e - s;

	vm_map_entry_dispose(map, entry);

	vm_map_unlock(map);
	/*
	 *	Deallocate the object only after removing all
	 *	pmap entries pointing to its pages.
	 */
	if (submap)
		vm_map_deallocate(submap);
	else
		vm_object_deallocate(object);

}

void
vm_map_submap_pmap_clean(
	vm_map_t	map,
	vm_map_offset_t	start,
	vm_map_offset_t	end,
	vm_map_t	sub_map,
	vm_map_offset_t	offset)
{
	vm_map_offset_t	submap_start;
	vm_map_offset_t	submap_end;
	vm_map_size_t	remove_size;
	vm_map_entry_t	entry;

	submap_end = offset + (end - start);
	submap_start = offset;

	vm_map_lock_read(sub_map);
	if(vm_map_lookup_entry(sub_map, offset, &entry)) {
		
		remove_size = (entry->vme_end - entry->vme_start);
		if(offset > entry->vme_start)
			remove_size -= offset - entry->vme_start;
		

		if(submap_end < entry->vme_end) {
			remove_size -=
				entry->vme_end - submap_end;
		}
		if(entry->is_sub_map) {
			vm_map_submap_pmap_clean(
				sub_map,
				start,
				start + remove_size,
				entry->object.sub_map,
				entry->offset);
		} else {

			if((map->mapped) && (map->ref_count)
			   && (entry->object.vm_object != NULL)) {
				vm_object_pmap_protect(
					entry->object.vm_object,
					entry->offset+(offset-entry->vme_start),
					remove_size,
					PMAP_NULL,
					entry->vme_start,
					VM_PROT_NONE);
			} else {
				pmap_remove(map->pmap, 
					    (addr64_t)start, 
					    (addr64_t)(start + remove_size));
			}
		}
	}

	entry = entry->vme_next;

	while((entry != vm_map_to_entry(sub_map)) 
	      && (entry->vme_start < submap_end)) {
		remove_size = (entry->vme_end - entry->vme_start); 
		if(submap_end < entry->vme_end) {
			remove_size -= entry->vme_end - submap_end;
		}
		if(entry->is_sub_map) {
			vm_map_submap_pmap_clean(
				sub_map,
				(start + entry->vme_start) - offset,
				((start + entry->vme_start) - offset) + remove_size,
				entry->object.sub_map,
				entry->offset);
		} else {
			if((map->mapped) && (map->ref_count)
			   && (entry->object.vm_object != NULL)) {
				vm_object_pmap_protect(
					entry->object.vm_object,
					entry->offset,
					remove_size,
					PMAP_NULL,
					entry->vme_start,
					VM_PROT_NONE);
			} else {
				pmap_remove(map->pmap, 
					    (addr64_t)((start + entry->vme_start) 
						       - offset),
					    (addr64_t)(((start + entry->vme_start) 
							- offset) + remove_size));
			}
		}
		entry = entry->vme_next;
	}
	vm_map_unlock_read(sub_map);
	return;
}

/*
 *	vm_map_delete:	[ internal use only ]
 *
 *	Deallocates the given address range from the target map.
 *	Removes all user wirings. Unwires one kernel wiring if
 *	VM_MAP_REMOVE_KUNWIRE is set.  Waits for kernel wirings to go
 *	away if VM_MAP_REMOVE_WAIT_FOR_KWIRE is set.  Sleeps
 *	interruptibly if VM_MAP_REMOVE_INTERRUPTIBLE is set.
 *
 *	This routine is called with map locked and leaves map locked.
 */
static kern_return_t
vm_map_delete(
	vm_map_t		map,
	vm_map_offset_t		start,
	vm_map_offset_t		end,
	int			flags,
	vm_map_t		zap_map)
{
	vm_map_entry_t		entry, next;
	struct	 vm_map_entry	*first_entry, tmp_entry;
	register vm_map_offset_t s;
	register vm_object_t	object;
	boolean_t		need_wakeup;
	unsigned int		last_timestamp = ~0; /* unlikely value */
	int			interruptible;

	interruptible = (flags & VM_MAP_REMOVE_INTERRUPTIBLE) ? 
		THREAD_ABORTSAFE : THREAD_UNINT;

	/*
	 * All our DMA I/O operations in IOKit are currently done by
	 * wiring through the map entries of the task requesting the I/O.
	 * Because of this, we must always wait for kernel wirings
	 * to go away on the entries before deleting them.
	 *
	 * Any caller who wants to actually remove a kernel wiring
	 * should explicitly set the VM_MAP_REMOVE_KUNWIRE flag to
	 * properly remove one wiring instead of blasting through
	 * them all.
	 */
	flags |= VM_MAP_REMOVE_WAIT_FOR_KWIRE;

	while(1) {
		/*
		 *	Find the start of the region, and clip it
		 */
		if (vm_map_lookup_entry(map, start, &first_entry)) {
			entry = first_entry;
			if (entry->superpage_size && (start & ~SUPERPAGE_MASK)) { /* extend request to whole entry */				start = SUPERPAGE_ROUND_DOWN(start);
				start = SUPERPAGE_ROUND_DOWN(start);
				continue;
			}
			if (start == entry->vme_start) {
				/*
				 * No need to clip.  We don't want to cause
				 * any unnecessary unnesting in this case...
				 */
			} else {
				vm_map_clip_start(map, entry, start);
			}

			/*
			 *	Fix the lookup hint now, rather than each
			 *	time through the loop.
			 */
			SAVE_HINT_MAP_WRITE(map, entry->vme_prev);
		} else {
			entry = first_entry->vme_next;
		}
		break;
	}
	if (entry->superpage_size)
		end = SUPERPAGE_ROUND_UP(end);

	need_wakeup = FALSE;
	/*
	 *	Step through all entries in this region
	 */
	s = entry->vme_start;
	while ((entry != vm_map_to_entry(map)) && (s < end)) {
		/*
		 * At this point, we have deleted all the memory entries
		 * between "start" and "s".  We still need to delete
		 * all memory entries between "s" and "end".
		 * While we were blocked and the map was unlocked, some
		 * new memory entries could have been re-allocated between
		 * "start" and "s" and we don't want to mess with those.
		 * Some of those entries could even have been re-assembled
		 * with an entry after "s" (in vm_map_simplify_entry()), so
		 * we may have to vm_map_clip_start() again.
		 */

		if (entry->vme_start >= s) {
			/*
			 * This entry starts on or after "s"
			 * so no need to clip its start.
			 */
		} else {
			/*
			 * This entry has been re-assembled by a
			 * vm_map_simplify_entry().  We need to
			 * re-clip its start.
			 */
			vm_map_clip_start(map, entry, s);
		}
		if (entry->vme_end <= end) {
			/*
			 * This entry is going away completely, so no need
			 * to clip and possibly cause an unnecessary unnesting.
			 */
		} else {
			vm_map_clip_end(map, entry, end);
		}

		if (entry->permanent) {
			panic("attempt to remove permanent VM map entry "
			      "%p [0x%llx:0x%llx]\n",
			      entry, (uint64_t) s, (uint64_t) end);
		}


		if (entry->in_transition) {
			wait_result_t wait_result;

			/*
			 * Another thread is wiring/unwiring this entry.
			 * Let the other thread know we are waiting.
			 */
			assert(s == entry->vme_start);
			entry->needs_wakeup = TRUE;

			/*
			 * wake up anybody waiting on entries that we have
			 * already unwired/deleted.
			 */
			if (need_wakeup) {
				vm_map_entry_wakeup(map);
				need_wakeup = FALSE;
			}

			wait_result = vm_map_entry_wait(map, interruptible);

			if (interruptible &&
			    wait_result == THREAD_INTERRUPTED) {
				/*
				 * We do not clear the needs_wakeup flag,
				 * since we cannot tell if we were the only one.
				 */
				vm_map_unlock(map);
				return KERN_ABORTED;
			}

			/*
			 * The entry could have been clipped or it
			 * may not exist anymore.  Look it up again.
			 */
			if (!vm_map_lookup_entry(map, s, &first_entry)) {
				assert((map != kernel_map) && 
				       (!entry->is_sub_map));
				/*
				 * User: use the next entry
				 */
				entry = first_entry->vme_next;
				s = entry->vme_start;
			} else {
				entry = first_entry;
				SAVE_HINT_MAP_WRITE(map, entry->vme_prev);
			}
			last_timestamp = map->timestamp;
			continue;
		} /* end in_transition */

		if (entry->wired_count) {
			boolean_t	user_wire;

			user_wire = entry->user_wired_count > 0;

			/*
			 * 	Remove a kernel wiring if requested
			 */
			if (flags & VM_MAP_REMOVE_KUNWIRE) {
				entry->wired_count--;
			}
			
			/*
			 *	Remove all user wirings for proper accounting
			 */
			if (entry->user_wired_count > 0) {
				while (entry->user_wired_count)
					subtract_wire_counts(map, entry, user_wire);
			}

			if (entry->wired_count != 0) {
				assert(map != kernel_map);
				/*
				 * Cannot continue.  Typical case is when
				 * a user thread has physical io pending on
				 * on this page.  Either wait for the
				 * kernel wiring to go away or return an
				 * error.
				 */
				if (flags & VM_MAP_REMOVE_WAIT_FOR_KWIRE) {
					wait_result_t wait_result;

					assert(s == entry->vme_start);
					entry->needs_wakeup = TRUE;
					wait_result = vm_map_entry_wait(map,
									interruptible);

					if (interruptible &&
					    wait_result == THREAD_INTERRUPTED) {
						/*
						 * We do not clear the 
						 * needs_wakeup flag, since we 
						 * cannot tell if we were the 
						 * only one.
						 */
						vm_map_unlock(map);
						return KERN_ABORTED;
					}

					/*
					 * The entry could have been clipped or
					 * it may not exist anymore.  Look it
					 * up again.
					 */
					if (!vm_map_lookup_entry(map, s, 
								 &first_entry)) {
						assert(map != kernel_map);
						/*
						 * User: use the next entry
						 */
						entry = first_entry->vme_next;
						s = entry->vme_start;
					} else {
						entry = first_entry;
						SAVE_HINT_MAP_WRITE(map, entry->vme_prev);
					}
					last_timestamp = map->timestamp;
					continue;
				}
				else {
					return KERN_FAILURE;
				}
			}

			entry->in_transition = TRUE;
			/*
			 * copy current entry.  see comment in vm_map_wire()
			 */
			tmp_entry = *entry;
			assert(s == entry->vme_start);

			/*
			 * We can unlock the map now. The in_transition
			 * state guarentees existance of the entry.
			 */
			vm_map_unlock(map);

			if (tmp_entry.is_sub_map) {
				vm_map_t sub_map;
				vm_map_offset_t sub_start, sub_end;
				pmap_t pmap;
				vm_map_offset_t pmap_addr;
				

				sub_map = tmp_entry.object.sub_map;
				sub_start = tmp_entry.offset;
				sub_end = sub_start + (tmp_entry.vme_end -
						       tmp_entry.vme_start);
				if (tmp_entry.use_pmap) {
					pmap = sub_map->pmap;
					pmap_addr = tmp_entry.vme_start;
				} else {
					pmap = map->pmap;
					pmap_addr = tmp_entry.vme_start;
				}
				(void) vm_map_unwire_nested(sub_map,
							    sub_start, sub_end,
							    user_wire,
							    pmap, pmap_addr);
			} else {

				vm_fault_unwire(map, &tmp_entry,
						tmp_entry.object.vm_object == kernel_object,
						map->pmap, tmp_entry.vme_start);
			}

			vm_map_lock(map);

			if (last_timestamp+1 != map->timestamp) {
				/*
				 * Find the entry again.  It could have
				 * been clipped after we unlocked the map.
				 */
				if (!vm_map_lookup_entry(map, s, &first_entry)){
					assert((map != kernel_map) && 
					       (!entry->is_sub_map));
					first_entry = first_entry->vme_next;
					s = first_entry->vme_start;
				} else {
					SAVE_HINT_MAP_WRITE(map, entry->vme_prev);
				}
			} else {
				SAVE_HINT_MAP_WRITE(map, entry->vme_prev);
				first_entry = entry;
			}

			last_timestamp = map->timestamp;

			entry = first_entry;
			while ((entry != vm_map_to_entry(map)) &&
			       (entry->vme_start < tmp_entry.vme_end)) {
				assert(entry->in_transition);
				entry->in_transition = FALSE;
				if (entry->needs_wakeup) {
					entry->needs_wakeup = FALSE;
					need_wakeup = TRUE;
				}
				entry = entry->vme_next;
			}
			/*
			 * We have unwired the entry(s).  Go back and
			 * delete them.
			 */
			entry = first_entry;
			continue;
		}

		/* entry is unwired */
		assert(entry->wired_count == 0);
		assert(entry->user_wired_count == 0);

		assert(s == entry->vme_start);

		if (flags & VM_MAP_REMOVE_NO_PMAP_CLEANUP) {
			/*
			 * XXX with the VM_MAP_REMOVE_SAVE_ENTRIES flag to
			 * vm_map_delete(), some map entries might have been
			 * transferred to a "zap_map", which doesn't have a
			 * pmap.  The original pmap has already been flushed
			 * in the vm_map_delete() call targeting the original
			 * map, but when we get to destroying the "zap_map",
			 * we don't have any pmap to flush, so let's just skip
			 * all this.
			 */
		} else if (entry->is_sub_map) {
			if (entry->use_pmap) {
#ifndef NO_NESTED_PMAP
				pmap_unnest(map->pmap,
					    (addr64_t)entry->vme_start,
					    entry->vme_end - entry->vme_start);
#endif	/* NO_NESTED_PMAP */
				if ((map->mapped) && (map->ref_count)) {
					/* clean up parent map/maps */
					vm_map_submap_pmap_clean(
						map, entry->vme_start,
						entry->vme_end,
						entry->object.sub_map,
						entry->offset);
				}
			} else {
				vm_map_submap_pmap_clean(
					map, entry->vme_start, entry->vme_end,
					entry->object.sub_map,
					entry->offset);
			}
		} else if (entry->object.vm_object != kernel_object) {
			object = entry->object.vm_object;
			if((map->mapped) && (map->ref_count)) {
				vm_object_pmap_protect(
					object, entry->offset,
					entry->vme_end - entry->vme_start,
					PMAP_NULL,
					entry->vme_start,
					VM_PROT_NONE);
			} else {
				pmap_remove(map->pmap,
					    (addr64_t)entry->vme_start,
					    (addr64_t)entry->vme_end);
			}
		}

		/*
		 * All pmap mappings for this map entry must have been
		 * cleared by now.
		 */
		assert(vm_map_pmap_is_empty(map,
					    entry->vme_start,
					    entry->vme_end));

		next = entry->vme_next;
		s = next->vme_start;
		last_timestamp = map->timestamp;

		if ((flags & VM_MAP_REMOVE_SAVE_ENTRIES) &&
		    zap_map != VM_MAP_NULL) {
			vm_map_size_t entry_size;
			/*
			 * The caller wants to save the affected VM map entries
			 * into the "zap_map".  The caller will take care of
			 * these entries.
			 */
			/* unlink the entry from "map" ... */
			vm_map_store_entry_unlink(map, entry);
			/* ... and add it to the end of the "zap_map" */
			vm_map_store_entry_link(zap_map,
					  vm_map_last_entry(zap_map),
					  entry);
			entry_size = entry->vme_end - entry->vme_start;
			map->size -= entry_size;
			zap_map->size += entry_size;
			/* we didn't unlock the map, so no timestamp increase */
			last_timestamp--;
		} else {
			vm_map_entry_delete(map, entry);
			/* vm_map_entry_delete unlocks the map */
			vm_map_lock(map);
		}

		entry = next;

		if(entry == vm_map_to_entry(map)) {
			break;
		}
		if (last_timestamp+1 != map->timestamp) {
			/*
			 * we are responsible for deleting everything
			 * from the give space, if someone has interfered
			 * we pick up where we left off, back fills should
			 * be all right for anyone except map_delete and
			 * we have to assume that the task has been fully
			 * disabled before we get here
			 */
        		if (!vm_map_lookup_entry(map, s, &entry)){
	               		entry = entry->vme_next;
				s = entry->vme_start;
        		} else {
				SAVE_HINT_MAP_WRITE(map, entry->vme_prev);
       		 	}
			/* 
			 * others can not only allocate behind us, we can 
			 * also see coalesce while we don't have the map lock 
			 */
			if(entry == vm_map_to_entry(map)) {
				break;
			}
		}
		last_timestamp = map->timestamp;
	}

	if (map->wait_for_space)
		thread_wakeup((event_t) map);
	/*
	 * wake up anybody waiting on entries that we have already deleted.
	 */
	if (need_wakeup)
		vm_map_entry_wakeup(map);

	return KERN_SUCCESS;
}

/*
 *	vm_map_remove:
 *
 *	Remove the given address range from the target map.
 *	This is the exported form of vm_map_delete.
 */
kern_return_t
vm_map_remove(
	register vm_map_t	map,
	register vm_map_offset_t	start,
	register vm_map_offset_t	end,
	register boolean_t	flags)
{
	register kern_return_t	result;

	vm_map_lock(map);
	VM_MAP_RANGE_CHECK(map, start, end);
	result = vm_map_delete(map, start, end, flags, VM_MAP_NULL);
	vm_map_unlock(map);

	return(result);
}


/*
 *	Routine:	vm_map_copy_discard
 *
 *	Description:
 *		Dispose of a map copy object (returned by
 *		vm_map_copyin).
 */
void
vm_map_copy_discard(
	vm_map_copy_t	copy)
{
	if (copy == VM_MAP_COPY_NULL)
		return;

	switch (copy->type) {
	case VM_MAP_COPY_ENTRY_LIST:
		while (vm_map_copy_first_entry(copy) !=
		       vm_map_copy_to_entry(copy)) {
			vm_map_entry_t	entry = vm_map_copy_first_entry(copy);

			vm_map_copy_entry_unlink(copy, entry);
			vm_object_deallocate(entry->object.vm_object);
			vm_map_copy_entry_dispose(copy, entry);
		}
		break;
        case VM_MAP_COPY_OBJECT:
		vm_object_deallocate(copy->cpy_object);
		break;
	case VM_MAP_COPY_KERNEL_BUFFER:

		/*
		 * The vm_map_copy_t and possibly the data buffer were
		 * allocated by a single call to kalloc(), i.e. the
		 * vm_map_copy_t was not allocated out of the zone.
		 */
		kfree(copy, copy->cpy_kalloc_size);
		return;
	}
	zfree(vm_map_copy_zone, copy);
}

/*
 *	Routine:	vm_map_copy_copy
 *
 *	Description:
 *			Move the information in a map copy object to
 *			a new map copy object, leaving the old one
 *			empty.
 *
 *			This is used by kernel routines that need
 *			to look at out-of-line data (in copyin form)
 *			before deciding whether to return SUCCESS.
 *			If the routine returns FAILURE, the original
 *			copy object will be deallocated; therefore,
 *			these routines must make a copy of the copy
 *			object and leave the original empty so that
 *			deallocation will not fail.
 */
vm_map_copy_t
vm_map_copy_copy(
	vm_map_copy_t	copy)
{
	vm_map_copy_t	new_copy;

	if (copy == VM_MAP_COPY_NULL)
		return VM_MAP_COPY_NULL;

	/*
	 * Allocate a new copy object, and copy the information
	 * from the old one into it.
	 */

	new_copy = (vm_map_copy_t) zalloc(vm_map_copy_zone);
	*new_copy = *copy;

	if (copy->type == VM_MAP_COPY_ENTRY_LIST) {
		/*
		 * The links in the entry chain must be
		 * changed to point to the new copy object.
		 */
		vm_map_copy_first_entry(copy)->vme_prev
			= vm_map_copy_to_entry(new_copy);
		vm_map_copy_last_entry(copy)->vme_next
			= vm_map_copy_to_entry(new_copy);
	}

	/*
	 * Change the old copy object into one that contains
	 * nothing to be deallocated.
	 */
	copy->type = VM_MAP_COPY_OBJECT;
	copy->cpy_object = VM_OBJECT_NULL;

	/*
	 * Return the new object.
	 */
	return new_copy;
}

static kern_return_t
vm_map_overwrite_submap_recurse(
	vm_map_t	dst_map,
	vm_map_offset_t	dst_addr,
	vm_map_size_t	dst_size)
{
	vm_map_offset_t	dst_end;
	vm_map_entry_t	tmp_entry;
	vm_map_entry_t	entry;
	kern_return_t	result;
	boolean_t	encountered_sub_map = FALSE;



	/*
	 *	Verify that the destination is all writeable
	 *	initially.  We have to trunc the destination
	 *	address and round the copy size or we'll end up
	 *	splitting entries in strange ways.
	 */

	dst_end = vm_map_round_page(dst_addr + dst_size);
	vm_map_lock(dst_map);

start_pass_1:
	if (!vm_map_lookup_entry(dst_map, dst_addr, &tmp_entry)) {
		vm_map_unlock(dst_map);
		return(KERN_INVALID_ADDRESS);
	}

	vm_map_clip_start(dst_map, tmp_entry, vm_map_trunc_page(dst_addr));
	assert(!tmp_entry->use_pmap); /* clipping did unnest if needed */

	for (entry = tmp_entry;;) {
		vm_map_entry_t	next;

		next = entry->vme_next;
		while(entry->is_sub_map) {
			vm_map_offset_t	sub_start;
			vm_map_offset_t	sub_end;
			vm_map_offset_t	local_end;

			if (entry->in_transition) {
				/*
				 * Say that we are waiting, and wait for entry.
				 */
                        	entry->needs_wakeup = TRUE;
                        	vm_map_entry_wait(dst_map, THREAD_UNINT);

				goto start_pass_1;
			}

			encountered_sub_map = TRUE;
			sub_start = entry->offset;

			if(entry->vme_end < dst_end)
				sub_end = entry->vme_end;
			else 
				sub_end = dst_end;
			sub_end -= entry->vme_start;
			sub_end += entry->offset;
			local_end = entry->vme_end;
			vm_map_unlock(dst_map);
			
			result = vm_map_overwrite_submap_recurse(
				entry->object.sub_map,
				sub_start,
				sub_end - sub_start);

			if(result != KERN_SUCCESS)
				return result;
			if (dst_end <= entry->vme_end)
				return KERN_SUCCESS;
			vm_map_lock(dst_map);
			if(!vm_map_lookup_entry(dst_map, local_end, 
						&tmp_entry)) {
				vm_map_unlock(dst_map);
				return(KERN_INVALID_ADDRESS);
			}
			entry = tmp_entry;
			next = entry->vme_next;
		}

		if ( ! (entry->protection & VM_PROT_WRITE)) {
			vm_map_unlock(dst_map);
			return(KERN_PROTECTION_FAILURE);
		}

		/*
		 *	If the entry is in transition, we must wait
		 *	for it to exit that state.  Anything could happen
		 *	when we unlock the map, so start over.
		 */
                if (entry->in_transition) {

                        /*
                         * Say that we are waiting, and wait for entry.
                         */
                        entry->needs_wakeup = TRUE;
                        vm_map_entry_wait(dst_map, THREAD_UNINT);

			goto start_pass_1;
		}

/*
 *		our range is contained completely within this map entry
 */
		if (dst_end <= entry->vme_end) {
			vm_map_unlock(dst_map);
			return KERN_SUCCESS;
		}
/*
 *		check that range specified is contiguous region
 */
		if ((next == vm_map_to_entry(dst_map)) ||
		    (next->vme_start != entry->vme_end)) {
			vm_map_unlock(dst_map);
			return(KERN_INVALID_ADDRESS);
		}

		/*
		 *	Check for permanent objects in the destination.
		 */
		if ((entry->object.vm_object != VM_OBJECT_NULL) &&
		    ((!entry->object.vm_object->internal) ||
		     (entry->object.vm_object->true_share))) {
			if(encountered_sub_map) {
				vm_map_unlock(dst_map);
				return(KERN_FAILURE);
			}
		}


		entry = next;
	}/* for */
	vm_map_unlock(dst_map);
	return(KERN_SUCCESS);
}

/*
 *	Routine:	vm_map_copy_overwrite
 *
 *	Description:
 *		Copy the memory described by the map copy
 *		object (copy; returned by vm_map_copyin) onto
 *		the specified destination region (dst_map, dst_addr).
 *		The destination must be writeable.
 *
 *		Unlike vm_map_copyout, this routine actually
 *		writes over previously-mapped memory.  If the
 *		previous mapping was to a permanent (user-supplied)
 *		memory object, it is preserved.
 *
 *		The attributes (protection and inheritance) of the
 *		destination region are preserved.
 *
 *		If successful, consumes the copy object.
 *		Otherwise, the caller is responsible for it.
 *
 *	Implementation notes:
 *		To overwrite aligned temporary virtual memory, it is
 *		sufficient to remove the previous mapping and insert
 *		the new copy.  This replacement is done either on
 *		the whole region (if no permanent virtual memory
 *		objects are embedded in the destination region) or
 *		in individual map entries.
 *
 *		To overwrite permanent virtual memory , it is necessary
 *		to copy each page, as the external memory management
 *		interface currently does not provide any optimizations.
 *
 *		Unaligned memory also has to be copied.  It is possible
 *		to use 'vm_trickery' to copy the aligned data.  This is
 *		not done but not hard to implement.
 *
 *		Once a page of permanent memory has been overwritten,
 *		it is impossible to interrupt this function; otherwise,
 *		the call would be neither atomic nor location-independent.
 *		The kernel-state portion of a user thread must be
 *		interruptible.
 *
 *		It may be expensive to forward all requests that might
 *		overwrite permanent memory (vm_write, vm_copy) to
 *		uninterruptible kernel threads.  This routine may be
 *		called by interruptible threads; however, success is
 *		not guaranteed -- if the request cannot be performed
 *		atomically and interruptibly, an error indication is
 *		returned.
 */

static kern_return_t
vm_map_copy_overwrite_nested(
	vm_map_t		dst_map,
	vm_map_address_t	dst_addr,
	vm_map_copy_t		copy,
	boolean_t		interruptible,
	pmap_t			pmap,
	boolean_t		discard_on_success)
{
	vm_map_offset_t		dst_end;
	vm_map_entry_t		tmp_entry;
	vm_map_entry_t		entry;
	kern_return_t		kr;
	boolean_t		aligned = TRUE;
	boolean_t		contains_permanent_objects = FALSE;
	boolean_t		encountered_sub_map = FALSE;
	vm_map_offset_t		base_addr;
	vm_map_size_t		copy_size;
	vm_map_size_t		total_size;


	/*
	 *	Check for null copy object.
	 */

	if (copy == VM_MAP_COPY_NULL)
		return(KERN_SUCCESS);

	/*
	 *	Check for special kernel buffer allocated
	 *	by new_ipc_kmsg_copyin.
	 */

	if (copy->type == VM_MAP_COPY_KERNEL_BUFFER) {
		return(vm_map_copyout_kernel_buffer(
			       dst_map, &dst_addr, 
			       copy, TRUE));
	}

	/*
	 *      Only works for entry lists at the moment.  Will
	 *	support page lists later.
	 */

	assert(copy->type == VM_MAP_COPY_ENTRY_LIST);

	if (copy->size == 0) {
		if (discard_on_success)
			vm_map_copy_discard(copy);
		return(KERN_SUCCESS);
	}

	/*
	 *	Verify that the destination is all writeable
	 *	initially.  We have to trunc the destination
	 *	address and round the copy size or we'll end up
	 *	splitting entries in strange ways.
	 */

	if (!page_aligned(copy->size) ||
	    !page_aligned (copy->offset) ||
	    !page_aligned (dst_addr))
	{
		aligned = FALSE;
		dst_end = vm_map_round_page(dst_addr + copy->size);
	} else {
		dst_end = dst_addr + copy->size;
	}

	vm_map_lock(dst_map);

	/* LP64todo - remove this check when vm_map_commpage64()
	 * no longer has to stuff in a map_entry for the commpage
	 * above the map's max_offset.
	 */
	if (dst_addr >= dst_map->max_offset) {
		vm_map_unlock(dst_map);
		return(KERN_INVALID_ADDRESS);
	}
	 
start_pass_1:
	if (!vm_map_lookup_entry(dst_map, dst_addr, &tmp_entry)) {
		vm_map_unlock(dst_map);
		return(KERN_INVALID_ADDRESS);
	}
	vm_map_clip_start(dst_map, tmp_entry, vm_map_trunc_page(dst_addr));
	for (entry = tmp_entry;;) {
		vm_map_entry_t	next = entry->vme_next;

		while(entry->is_sub_map) {
			vm_map_offset_t	sub_start;
			vm_map_offset_t	sub_end;
			vm_map_offset_t	local_end;

                	if (entry->in_transition) {

				/*
				 * Say that we are waiting, and wait for entry.
				 */
                        	entry->needs_wakeup = TRUE;
                        	vm_map_entry_wait(dst_map, THREAD_UNINT);

				goto start_pass_1;
			}

			local_end = entry->vme_end;
		        if (!(entry->needs_copy)) {
				/* if needs_copy we are a COW submap */
				/* in such a case we just replace so */
				/* there is no need for the follow-  */
				/* ing check.                        */
				encountered_sub_map = TRUE;
				sub_start = entry->offset;

				if(entry->vme_end < dst_end)
					sub_end = entry->vme_end;
				else 
					sub_end = dst_end;
				sub_end -= entry->vme_start;
				sub_end += entry->offset;
				vm_map_unlock(dst_map);
			
				kr = vm_map_overwrite_submap_recurse(
					entry->object.sub_map,
					sub_start,
					sub_end - sub_start);
				if(kr != KERN_SUCCESS)
					return kr;
				vm_map_lock(dst_map);
			}

			if (dst_end <= entry->vme_end)
				goto start_overwrite;
			if(!vm_map_lookup_entry(dst_map, local_end, 
						&entry)) {
				vm_map_unlock(dst_map);
				return(KERN_INVALID_ADDRESS);
			}
			next = entry->vme_next;
		}

		if ( ! (entry->protection & VM_PROT_WRITE)) {
			vm_map_unlock(dst_map);
			return(KERN_PROTECTION_FAILURE);
		}

		/*
		 *	If the entry is in transition, we must wait
		 *	for it to exit that state.  Anything could happen
		 *	when we unlock the map, so start over.
		 */
                if (entry->in_transition) {

                        /*
                         * Say that we are waiting, and wait for entry.
                         */
                        entry->needs_wakeup = TRUE;
                        vm_map_entry_wait(dst_map, THREAD_UNINT);

			goto start_pass_1;
		}

/*
 *		our range is contained completely within this map entry
 */
		if (dst_end <= entry->vme_end)
			break;
/*
 *		check that range specified is contiguous region
 */
		if ((next == vm_map_to_entry(dst_map)) ||
		    (next->vme_start != entry->vme_end)) {
			vm_map_unlock(dst_map);
			return(KERN_INVALID_ADDRESS);
		}


		/*
		 *	Check for permanent objects in the destination.
		 */
		if ((entry->object.vm_object != VM_OBJECT_NULL) &&
		    ((!entry->object.vm_object->internal) ||
		     (entry->object.vm_object->true_share))) {
			contains_permanent_objects = TRUE;
		}

		entry = next;
	}/* for */

start_overwrite:
	/*
	 *	If there are permanent objects in the destination, then
	 *	the copy cannot be interrupted.
	 */

	if (interruptible && contains_permanent_objects) {
		vm_map_unlock(dst_map);
		return(KERN_FAILURE);	/* XXX */
	}

	/*
 	 *
	 *	Make a second pass, overwriting the data
	 *	At the beginning of each loop iteration,
	 *	the next entry to be overwritten is "tmp_entry"
	 *	(initially, the value returned from the lookup above),
	 *	and the starting address expected in that entry
	 *	is "start".
	 */

	total_size = copy->size;
	if(encountered_sub_map) {
		copy_size = 0;
		/* re-calculate tmp_entry since we've had the map */
		/* unlocked */
		if (!vm_map_lookup_entry( dst_map, dst_addr, &tmp_entry)) {
			vm_map_unlock(dst_map);
			return(KERN_INVALID_ADDRESS);
		}
	} else {
		copy_size = copy->size;
	}
	
	base_addr = dst_addr;
	while(TRUE) {
		/* deconstruct the copy object and do in parts */
		/* only in sub_map, interruptable case */
		vm_map_entry_t	copy_entry;
		vm_map_entry_t	previous_prev = VM_MAP_ENTRY_NULL;
		vm_map_entry_t	next_copy = VM_MAP_ENTRY_NULL;
		int		nentries;
		int		remaining_entries = 0;
		vm_map_offset_t	new_offset = 0;
	
		for (entry = tmp_entry; copy_size == 0;) {
			vm_map_entry_t	next;

			next = entry->vme_next;

			/* tmp_entry and base address are moved along */
			/* each time we encounter a sub-map.  Otherwise */
			/* entry can outpase tmp_entry, and the copy_size */
			/* may reflect the distance between them */
			/* if the current entry is found to be in transition */
			/* we will start over at the beginning or the last */
			/* encounter of a submap as dictated by base_addr */
			/* we will zero copy_size accordingly. */
			if (entry->in_transition) {
                       		/*
                       		 * Say that we are waiting, and wait for entry.
                       		 */
                       		entry->needs_wakeup = TRUE;
                       		vm_map_entry_wait(dst_map, THREAD_UNINT);

				if(!vm_map_lookup_entry(dst_map, base_addr, 
							&tmp_entry)) {
					vm_map_unlock(dst_map);
					return(KERN_INVALID_ADDRESS);
				}
				copy_size = 0;
				entry = tmp_entry;
				continue;
			}
			if(entry->is_sub_map) {
				vm_map_offset_t	sub_start;
				vm_map_offset_t	sub_end;
				vm_map_offset_t	local_end;

		        	if (entry->needs_copy) {
					/* if this is a COW submap */
					/* just back the range with a */
					/* anonymous entry */
					if(entry->vme_end < dst_end)
						sub_end = entry->vme_end;
					else 
						sub_end = dst_end;
					if(entry->vme_start < base_addr)
						sub_start = base_addr;
					else 
						sub_start = entry->vme_start;
					vm_map_clip_end(
						dst_map, entry, sub_end);
					vm_map_clip_start(
						dst_map, entry, sub_start);
					assert(!entry->use_pmap);
					entry->is_sub_map = FALSE;
					vm_map_deallocate(
						entry->object.sub_map);
					entry->object.sub_map = NULL;
					entry->is_shared = FALSE;
					entry->needs_copy = FALSE;
					entry->offset = 0;
					/*
					 * XXX FBDP
					 * We should propagate the protections
					 * of the submap entry here instead
					 * of forcing them to VM_PROT_ALL...
					 * Or better yet, we should inherit
					 * the protection of the copy_entry.
					 */
					entry->protection = VM_PROT_ALL;
					entry->max_protection = VM_PROT_ALL;
					entry->wired_count = 0;
					entry->user_wired_count = 0;
					if(entry->inheritance 
					   == VM_INHERIT_SHARE) 
						entry->inheritance = VM_INHERIT_COPY;
					continue;
				}
				/* first take care of any non-sub_map */
				/* entries to send */
				if(base_addr < entry->vme_start) {
					/* stuff to send */
					copy_size = 
						entry->vme_start - base_addr;
					break;
				}
				sub_start = entry->offset;

				if(entry->vme_end < dst_end)
					sub_end = entry->vme_end;
				else 
					sub_end = dst_end;
				sub_end -= entry->vme_start;
				sub_end += entry->offset;
				local_end = entry->vme_end;
				vm_map_unlock(dst_map);
				copy_size = sub_end - sub_start;

				/* adjust the copy object */
				if (total_size > copy_size) {
					vm_map_size_t	local_size = 0;
					vm_map_size_t	entry_size;

					nentries = 1;
					new_offset = copy->offset;
					copy_entry = vm_map_copy_first_entry(copy);
					while(copy_entry != 
					      vm_map_copy_to_entry(copy)){
						entry_size = copy_entry->vme_end - 
							copy_entry->vme_start;
						if((local_size < copy_size) &&
						   ((local_size + entry_size) 
						    >= copy_size)) {
							vm_map_copy_clip_end(copy, 
									     copy_entry, 
									     copy_entry->vme_start +
									     (copy_size - local_size));
							entry_size = copy_entry->vme_end - 
								copy_entry->vme_start;
							local_size += entry_size;
							new_offset += entry_size;
						}
						if(local_size >= copy_size) {
							next_copy = copy_entry->vme_next;
							copy_entry->vme_next = 
								vm_map_copy_to_entry(copy);
							previous_prev = 
								copy->cpy_hdr.links.prev;
							copy->cpy_hdr.links.prev = copy_entry;
							copy->size = copy_size;
							remaining_entries = 
								copy->cpy_hdr.nentries;
							remaining_entries -= nentries;
							copy->cpy_hdr.nentries = nentries;
							break;
						} else {
							local_size += entry_size;
							new_offset += entry_size;
							nentries++;
						}
						copy_entry = copy_entry->vme_next;
					}
				}
			
				if((entry->use_pmap) && (pmap == NULL)) {
					kr = vm_map_copy_overwrite_nested(
						entry->object.sub_map,
						sub_start,
						copy,
						interruptible, 
						entry->object.sub_map->pmap,
						TRUE);
				} else if (pmap != NULL) {
					kr = vm_map_copy_overwrite_nested(
						entry->object.sub_map,
						sub_start,
						copy,
						interruptible, pmap,
						TRUE);
				} else {
					kr = vm_map_copy_overwrite_nested(
						entry->object.sub_map,
						sub_start,
						copy,
						interruptible,
						dst_map->pmap,
						TRUE);
				}
				if(kr != KERN_SUCCESS) {
					if(next_copy != NULL) {
						copy->cpy_hdr.nentries += 
							remaining_entries;
						copy->cpy_hdr.links.prev->vme_next = 
							next_copy;
						copy->cpy_hdr.links.prev 
							= previous_prev;
						copy->size = total_size;
					}
					return kr;
				}
				if (dst_end <= local_end) {
					return(KERN_SUCCESS);
				}
				/* otherwise copy no longer exists, it was */
				/* destroyed after successful copy_overwrite */
			        copy = (vm_map_copy_t) 
					zalloc(vm_map_copy_zone);
				vm_map_copy_first_entry(copy) =
					vm_map_copy_last_entry(copy) =
					vm_map_copy_to_entry(copy);
				copy->type = VM_MAP_COPY_ENTRY_LIST;
				copy->offset = new_offset;

				total_size -= copy_size;
				copy_size = 0;
				/* put back remainder of copy in container */
				if(next_copy != NULL) {
					copy->cpy_hdr.nentries = remaining_entries;
					copy->cpy_hdr.links.next = next_copy;
					copy->cpy_hdr.links.prev = previous_prev;
					copy->size = total_size;
					next_copy->vme_prev = 
						vm_map_copy_to_entry(copy);
					next_copy = NULL;
				}
				base_addr = local_end;
				vm_map_lock(dst_map);
				if(!vm_map_lookup_entry(dst_map, 
							local_end, &tmp_entry)) {
					vm_map_unlock(dst_map);
					return(KERN_INVALID_ADDRESS);
				}
				entry = tmp_entry;
				continue;
			} 
			if (dst_end <= entry->vme_end) {
				copy_size = dst_end - base_addr;
				break;
			}

			if ((next == vm_map_to_entry(dst_map)) ||
			    (next->vme_start != entry->vme_end)) {
				vm_map_unlock(dst_map);
				return(KERN_INVALID_ADDRESS);
			}

			entry = next;
		}/* for */

		next_copy = NULL;
		nentries = 1;

		/* adjust the copy object */
		if (total_size > copy_size) {
			vm_map_size_t	local_size = 0;
			vm_map_size_t	entry_size;

			new_offset = copy->offset;
			copy_entry = vm_map_copy_first_entry(copy);
			while(copy_entry != vm_map_copy_to_entry(copy)) {
				entry_size = copy_entry->vme_end - 
					copy_entry->vme_start;
				if((local_size < copy_size) &&
				   ((local_size + entry_size) 
				    >= copy_size)) {
					vm_map_copy_clip_end(copy, copy_entry, 
							     copy_entry->vme_start +
							     (copy_size - local_size));
					entry_size = copy_entry->vme_end - 
						copy_entry->vme_start;
					local_size += entry_size;
					new_offset += entry_size;
				}
				if(local_size >= copy_size) {
					next_copy = copy_entry->vme_next;
					copy_entry->vme_next = 
						vm_map_copy_to_entry(copy);
					previous_prev = 
						copy->cpy_hdr.links.prev;
					copy->cpy_hdr.links.prev = copy_entry;
					copy->size = copy_size;
					remaining_entries = 
						copy->cpy_hdr.nentries;
					remaining_entries -= nentries;
					copy->cpy_hdr.nentries = nentries;
					break;
				} else {
					local_size += entry_size;
					new_offset += entry_size;
					nentries++;
				}
				copy_entry = copy_entry->vme_next;
			}
		}

		if (aligned) {
			pmap_t	local_pmap;

			if(pmap)
				local_pmap = pmap;
			else
				local_pmap = dst_map->pmap;

			if ((kr =  vm_map_copy_overwrite_aligned( 
				     dst_map, tmp_entry, copy,
				     base_addr, local_pmap)) != KERN_SUCCESS) {
				if(next_copy != NULL) {
					copy->cpy_hdr.nentries += 
						remaining_entries;
				        copy->cpy_hdr.links.prev->vme_next = 
						next_copy;
			       		copy->cpy_hdr.links.prev = 
						previous_prev;
					copy->size += copy_size;
				}
				return kr;
			}
			vm_map_unlock(dst_map);
		} else {
			/*
			 * Performance gain:
			 *
			 * if the copy and dst address are misaligned but the same
			 * offset within the page we can copy_not_aligned the
			 * misaligned parts and copy aligned the rest.  If they are
			 * aligned but len is unaligned we simply need to copy
			 * the end bit unaligned.  We'll need to split the misaligned
			 * bits of the region in this case !
			 */
			/* ALWAYS UNLOCKS THE dst_map MAP */
			if ((kr =  vm_map_copy_overwrite_unaligned( dst_map,
								    tmp_entry, copy, base_addr)) != KERN_SUCCESS) {
				if(next_copy != NULL) {
					copy->cpy_hdr.nentries +=
						remaining_entries;
			       		copy->cpy_hdr.links.prev->vme_next = 
						next_copy;
			       		copy->cpy_hdr.links.prev = 
						previous_prev;
					copy->size += copy_size;
				}
				return kr;
			}
		}
		total_size -= copy_size;
		if(total_size == 0)
			break;
		base_addr += copy_size;
		copy_size = 0;
		copy->offset = new_offset;
		if(next_copy != NULL) {
			copy->cpy_hdr.nentries = remaining_entries;
			copy->cpy_hdr.links.next = next_copy;
			copy->cpy_hdr.links.prev = previous_prev;
			next_copy->vme_prev = vm_map_copy_to_entry(copy);
			copy->size = total_size;
		}
		vm_map_lock(dst_map);
		while(TRUE) {
			if (!vm_map_lookup_entry(dst_map, 
						 base_addr, &tmp_entry)) {
				vm_map_unlock(dst_map);
				return(KERN_INVALID_ADDRESS);
			}
                	if (tmp_entry->in_transition) {
                       		entry->needs_wakeup = TRUE;
                       		vm_map_entry_wait(dst_map, THREAD_UNINT);
			} else {
				break;
			}
		}
		vm_map_clip_start(dst_map, tmp_entry, vm_map_trunc_page(base_addr));

		entry = tmp_entry;
	} /* while */

	/*
	 *	Throw away the vm_map_copy object
	 */
	if (discard_on_success)
		vm_map_copy_discard(copy);

	return(KERN_SUCCESS);
}/* vm_map_copy_overwrite */

kern_return_t
vm_map_copy_overwrite(
	vm_map_t	dst_map,
	vm_map_offset_t	dst_addr,
	vm_map_copy_t	copy,
	boolean_t	interruptible)
{
	vm_map_size_t	head_size, tail_size;
	vm_map_copy_t	head_copy, tail_copy;
	vm_map_offset_t	head_addr, tail_addr;
	vm_map_entry_t	entry;
	kern_return_t	kr;

	head_size = 0;
	tail_size = 0;
	head_copy = NULL;
	tail_copy = NULL;
	head_addr = 0;
	tail_addr = 0;

	if (interruptible ||
	    copy == VM_MAP_COPY_NULL ||
	    copy->type != VM_MAP_COPY_ENTRY_LIST) {
		/*
		 * We can't split the "copy" map if we're interruptible
		 * or if we don't have a "copy" map...
		 */
	blunt_copy:
		return vm_map_copy_overwrite_nested(dst_map,
						    dst_addr,
						    copy,
						    interruptible,
						    (pmap_t) NULL,
						    TRUE);
	}

	if (copy->size < 3 * PAGE_SIZE) {
		/*
		 * Too small to bother with optimizing...
		 */
		goto blunt_copy;
	}

	if ((dst_addr & PAGE_MASK) != (copy->offset & PAGE_MASK)) {
		/*
		 * Incompatible mis-alignment of source and destination...
		 */
		goto blunt_copy;
	}

	/*
	 * Proper alignment or identical mis-alignment at the beginning.
	 * Let's try and do a small unaligned copy first (if needed)
	 * and then an aligned copy for the rest.
	 */
	if (!page_aligned(dst_addr)) {
		head_addr = dst_addr;
		head_size = PAGE_SIZE - (copy->offset & PAGE_MASK);
	}
	if (!page_aligned(copy->offset + copy->size)) {
		/*
		 * Mis-alignment at the end.
		 * Do an aligned copy up to the last page and
		 * then an unaligned copy for the remaining bytes.
		 */
		tail_size = (copy->offset + copy->size) & PAGE_MASK;
		tail_addr = dst_addr + copy->size - tail_size;
	}

	if (head_size + tail_size == copy->size) {
		/*
		 * It's all unaligned, no optimization possible...
		 */
		goto blunt_copy;
	}

	/*
	 * Can't optimize if there are any submaps in the
	 * destination due to the way we free the "copy" map
	 * progressively in vm_map_copy_overwrite_nested()
	 * in that case.
	 */
	vm_map_lock_read(dst_map);
	if (! vm_map_lookup_entry(dst_map, dst_addr, &entry)) {
		vm_map_unlock_read(dst_map);
		goto blunt_copy;
	}
	for (;
	     (entry != vm_map_copy_to_entry(copy) &&
	      entry->vme_start < dst_addr + copy->size);
	     entry = entry->vme_next) {
		if (entry->is_sub_map) {
			vm_map_unlock_read(dst_map);
			goto blunt_copy;
		}
	}
	vm_map_unlock_read(dst_map);

	if (head_size) {
		/*
		 * Unaligned copy of the first "head_size" bytes, to reach
		 * a page boundary.
		 */
		
		/*
		 * Extract "head_copy" out of "copy".
		 */
		head_copy = (vm_map_copy_t) zalloc(vm_map_copy_zone);
		vm_map_copy_first_entry(head_copy) =
			vm_map_copy_to_entry(head_copy);
		vm_map_copy_last_entry(head_copy) =
			vm_map_copy_to_entry(head_copy);
		head_copy->type = VM_MAP_COPY_ENTRY_LIST;
		head_copy->cpy_hdr.nentries = 0;
		head_copy->cpy_hdr.entries_pageable =
			copy->cpy_hdr.entries_pageable;
		vm_map_store_init(&head_copy->cpy_hdr);

		head_copy->offset = copy->offset;
		head_copy->size = head_size;

		copy->offset += head_size;
		copy->size -= head_size;

		entry = vm_map_copy_first_entry(copy);
		vm_map_copy_clip_end(copy, entry, copy->offset);
		vm_map_copy_entry_unlink(copy, entry);
		vm_map_copy_entry_link(head_copy,
				       vm_map_copy_to_entry(head_copy),
				       entry);

		/*
		 * Do the unaligned copy.
		 */
		kr = vm_map_copy_overwrite_nested(dst_map,
						  head_addr,
						  head_copy,
						  interruptible,
						  (pmap_t) NULL,
						  FALSE);
		if (kr != KERN_SUCCESS)
			goto done;
	}

	if (tail_size) {
		/*
		 * Extract "tail_copy" out of "copy".
		 */
		tail_copy = (vm_map_copy_t) zalloc(vm_map_copy_zone);
		vm_map_copy_first_entry(tail_copy) =
			vm_map_copy_to_entry(tail_copy);
		vm_map_copy_last_entry(tail_copy) =
			vm_map_copy_to_entry(tail_copy);
		tail_copy->type = VM_MAP_COPY_ENTRY_LIST;
		tail_copy->cpy_hdr.nentries = 0;
		tail_copy->cpy_hdr.entries_pageable =
			copy->cpy_hdr.entries_pageable;
		vm_map_store_init(&tail_copy->cpy_hdr);

		tail_copy->offset = copy->offset + copy->size - tail_size;
		tail_copy->size = tail_size;

		copy->size -= tail_size;

		entry = vm_map_copy_last_entry(copy);
		vm_map_copy_clip_start(copy, entry, tail_copy->offset);
		entry = vm_map_copy_last_entry(copy);
		vm_map_copy_entry_unlink(copy, entry);
		vm_map_copy_entry_link(tail_copy,
				       vm_map_copy_last_entry(tail_copy),
				       entry);
	}

	/*
	 * Copy most (or possibly all) of the data.
	 */
	kr = vm_map_copy_overwrite_nested(dst_map,
					  dst_addr + head_size,
					  copy,
					  interruptible,
					  (pmap_t) NULL,
					  FALSE);
	if (kr != KERN_SUCCESS) {
		goto done;
	}

	if (tail_size) {
		kr = vm_map_copy_overwrite_nested(dst_map,
						  tail_addr,
						  tail_copy,
						  interruptible,
						  (pmap_t) NULL,
						  FALSE);
	}

done:
	assert(copy->type == VM_MAP_COPY_ENTRY_LIST);
	if (kr == KERN_SUCCESS) {
		/*
		 * Discard all the copy maps.
		 */
		if (head_copy) {
			vm_map_copy_discard(head_copy);
			head_copy = NULL;
		}
		vm_map_copy_discard(copy);
		if (tail_copy) {
			vm_map_copy_discard(tail_copy);
			tail_copy = NULL;
		}
	} else {
		/*
		 * Re-assemble the original copy map.
		 */
		if (head_copy) {
			entry = vm_map_copy_first_entry(head_copy);
			vm_map_copy_entry_unlink(head_copy, entry);
			vm_map_copy_entry_link(copy,
					       vm_map_copy_to_entry(copy),
					       entry);
			copy->offset -= head_size;
			copy->size += head_size;
			vm_map_copy_discard(head_copy);
			head_copy = NULL;
		}
		if (tail_copy) {
			entry = vm_map_copy_last_entry(tail_copy);
			vm_map_copy_entry_unlink(tail_copy, entry);
			vm_map_copy_entry_link(copy,
					       vm_map_copy_last_entry(copy),
					       entry);
			copy->size += tail_size;
			vm_map_copy_discard(tail_copy);
			tail_copy = NULL;
		}
	}
	return kr;
}


/*
 *	Routine: vm_map_copy_overwrite_unaligned	[internal use only]
 *
 *	Decription:
 *	Physically copy unaligned data
 *
 *	Implementation:
 *	Unaligned parts of pages have to be physically copied.  We use
 *	a modified form of vm_fault_copy (which understands none-aligned
 *	page offsets and sizes) to do the copy.  We attempt to copy as
 *	much memory in one go as possibly, however vm_fault_copy copies
 *	within 1 memory object so we have to find the smaller of "amount left"
 *	"source object data size" and "target object data size".  With
 *	unaligned data we don't need to split regions, therefore the source
 *	(copy) object should be one map entry, the target range may be split
 *	over multiple map entries however.  In any event we are pessimistic
 *	about these assumptions.
 *
 *	Assumptions:
 *	dst_map is locked on entry and is return locked on success,
 *	unlocked on error.
 */

static kern_return_t
vm_map_copy_overwrite_unaligned(
	vm_map_t	dst_map,
	vm_map_entry_t	entry,
	vm_map_copy_t	copy,
	vm_map_offset_t	start)
{
	vm_map_entry_t		copy_entry = vm_map_copy_first_entry(copy);
	vm_map_version_t	version;
	vm_object_t		dst_object;
	vm_object_offset_t	dst_offset;
	vm_object_offset_t	src_offset;
	vm_object_offset_t	entry_offset;
	vm_map_offset_t		entry_end;
	vm_map_size_t		src_size,
				dst_size,
				copy_size,
				amount_left;
	kern_return_t		kr = KERN_SUCCESS;

	vm_map_lock_write_to_read(dst_map);

	src_offset = copy->offset - vm_object_trunc_page(copy->offset);
	amount_left = copy->size;
/*
 *	unaligned so we never clipped this entry, we need the offset into
 *	the vm_object not just the data.
 */	
	while (amount_left > 0) {

		if (entry == vm_map_to_entry(dst_map)) {
			vm_map_unlock_read(dst_map);
			return KERN_INVALID_ADDRESS;
		}

		/* "start" must be within the current map entry */
		assert ((start>=entry->vme_start) && (start<entry->vme_end));

		dst_offset = start - entry->vme_start;

		dst_size = entry->vme_end - start;

		src_size = copy_entry->vme_end -
			(copy_entry->vme_start + src_offset);

		if (dst_size < src_size) {
/*
 *			we can only copy dst_size bytes before
 *			we have to get the next destination entry
 */
			copy_size = dst_size;
		} else {
/*
 *			we can only copy src_size bytes before
 *			we have to get the next source copy entry
 */
			copy_size = src_size;
		}

		if (copy_size > amount_left) {
			copy_size = amount_left;
		}
/*
 *		Entry needs copy, create a shadow shadow object for
 *		Copy on write region.
 */
		if (entry->needs_copy &&
		    ((entry->protection & VM_PROT_WRITE) != 0))
		{
			if (vm_map_lock_read_to_write(dst_map)) {
				vm_map_lock_read(dst_map);
				goto RetryLookup;
			}
			vm_object_shadow(&entry->object.vm_object,
					 &entry->offset,
					 (vm_map_size_t)(entry->vme_end
							 - entry->vme_start));
			entry->needs_copy = FALSE;
			vm_map_lock_write_to_read(dst_map);
		}
		dst_object = entry->object.vm_object;
/*
 *		unlike with the virtual (aligned) copy we're going
 *		to fault on it therefore we need a target object.
 */
                if (dst_object == VM_OBJECT_NULL) {
			if (vm_map_lock_read_to_write(dst_map)) {
				vm_map_lock_read(dst_map);
				goto RetryLookup;
			}
			dst_object = vm_object_allocate((vm_map_size_t)
							entry->vme_end - entry->vme_start);
			entry->object.vm_object = dst_object;
			entry->offset = 0;
			vm_map_lock_write_to_read(dst_map);
		}
/*
 *		Take an object reference and unlock map. The "entry" may
 *		disappear or change when the map is unlocked.
 */
		vm_object_reference(dst_object);
		version.main_timestamp = dst_map->timestamp;
		entry_offset = entry->offset;
		entry_end = entry->vme_end;
		vm_map_unlock_read(dst_map);
/*
 *		Copy as much as possible in one pass
 */
		kr = vm_fault_copy(
			copy_entry->object.vm_object,
			copy_entry->offset + src_offset,
			&copy_size,
			dst_object,
			entry_offset + dst_offset,
			dst_map,
			&version,
			THREAD_UNINT );

		start += copy_size;
		src_offset += copy_size;
		amount_left -= copy_size;
/*
 *		Release the object reference
 */
		vm_object_deallocate(dst_object);
/*
 *		If a hard error occurred, return it now
 */
		if (kr != KERN_SUCCESS)
			return kr;

		if ((copy_entry->vme_start + src_offset) == copy_entry->vme_end
		    || amount_left == 0)
		{
/*
 *			all done with this copy entry, dispose.
 */
			vm_map_copy_entry_unlink(copy, copy_entry);
			vm_object_deallocate(copy_entry->object.vm_object);
			vm_map_copy_entry_dispose(copy, copy_entry);

			if ((copy_entry = vm_map_copy_first_entry(copy))
			    == vm_map_copy_to_entry(copy) && amount_left) {
/*
 *				not finished copying but run out of source
 */
				return KERN_INVALID_ADDRESS;
			}
			src_offset = 0;
		}

		if (amount_left == 0)
			return KERN_SUCCESS;

		vm_map_lock_read(dst_map);
		if (version.main_timestamp == dst_map->timestamp) {
			if (start == entry_end) {
/*
 *				destination region is split.  Use the version
 *				information to avoid a lookup in the normal
 *				case.
 */
				entry = entry->vme_next;
/*
 *				should be contiguous. Fail if we encounter
 *				a hole in the destination.
 */
				if (start != entry->vme_start) {
					vm_map_unlock_read(dst_map);
					return KERN_INVALID_ADDRESS ;
				}
			}
		} else {
/*
 *			Map version check failed.
 *			we must lookup the entry because somebody
 *			might have changed the map behind our backs.
 */
		RetryLookup:
			if (!vm_map_lookup_entry(dst_map, start, &entry))
			{
				vm_map_unlock_read(dst_map);
				return KERN_INVALID_ADDRESS ;
			}
		}
	}/* while */

	return KERN_SUCCESS;
}/* vm_map_copy_overwrite_unaligned */

/*
 *	Routine: vm_map_copy_overwrite_aligned	[internal use only]
 *
 *	Description:
 *	Does all the vm_trickery possible for whole pages.
 *
 *	Implementation:
 *
 *	If there are no permanent objects in the destination,
 *	and the source and destination map entry zones match,
 *	and the destination map entry is not shared,
 *	then the map entries can be deleted and replaced
 *	with those from the copy.  The following code is the
 *	basic idea of what to do, but there are lots of annoying
 *	little details about getting protection and inheritance
 *	right.  Should add protection, inheritance, and sharing checks
 *	to the above pass and make sure that no wiring is involved.
 */

static kern_return_t
vm_map_copy_overwrite_aligned(
	vm_map_t	dst_map,
	vm_map_entry_t	tmp_entry,
	vm_map_copy_t	copy,
	vm_map_offset_t	start,
	__unused pmap_t	pmap)
{
	vm_object_t	object;
	vm_map_entry_t	copy_entry;
	vm_map_size_t	copy_size;
	vm_map_size_t	size;
	vm_map_entry_t	entry;
		
	while ((copy_entry = vm_map_copy_first_entry(copy))
	       != vm_map_copy_to_entry(copy))
	{
		copy_size = (copy_entry->vme_end - copy_entry->vme_start);
		
		entry = tmp_entry;
		assert(!entry->use_pmap); /* unnested when clipped earlier */
		if (entry == vm_map_to_entry(dst_map)) {
			vm_map_unlock(dst_map);
			return KERN_INVALID_ADDRESS;
		}
		size = (entry->vme_end - entry->vme_start);
		/*
		 *	Make sure that no holes popped up in the
		 *	address map, and that the protection is
		 *	still valid, in case the map was unlocked
		 *	earlier.
		 */

		if ((entry->vme_start != start) || ((entry->is_sub_map)
						    && !entry->needs_copy)) {
			vm_map_unlock(dst_map);
			return(KERN_INVALID_ADDRESS);
		}
		assert(entry != vm_map_to_entry(dst_map));

		/*
		 *	Check protection again
		 */

		if ( ! (entry->protection & VM_PROT_WRITE)) {
			vm_map_unlock(dst_map);
			return(KERN_PROTECTION_FAILURE);
		}

		/*
		 *	Adjust to source size first
		 */

		if (copy_size < size) {
			vm_map_clip_end(dst_map, entry, entry->vme_start + copy_size);
			size = copy_size;
		}

		/*
		 *	Adjust to destination size
		 */

		if (size < copy_size) {
			vm_map_copy_clip_end(copy, copy_entry,
					     copy_entry->vme_start + size);
			copy_size = size;
		}

		assert((entry->vme_end - entry->vme_start) == size);
		assert((tmp_entry->vme_end - tmp_entry->vme_start) == size);
		assert((copy_entry->vme_end - copy_entry->vme_start) == size);

		/*
		 *	If the destination contains temporary unshared memory,
		 *	we can perform the copy by throwing it away and
		 *	installing the source data.
		 */

		object = entry->object.vm_object;
		if ((!entry->is_shared && 
		     ((object == VM_OBJECT_NULL) || 
		      (object->internal && !object->true_share))) ||
		    entry->needs_copy) {
			vm_object_t	old_object = entry->object.vm_object;
			vm_object_offset_t	old_offset = entry->offset;
			vm_object_offset_t	offset;

			/*
			 * Ensure that the source and destination aren't
			 * identical
			 */
			if (old_object == copy_entry->object.vm_object &&
			    old_offset == copy_entry->offset) {
				vm_map_copy_entry_unlink(copy, copy_entry);
				vm_map_copy_entry_dispose(copy, copy_entry);

				if (old_object != VM_OBJECT_NULL)
					vm_object_deallocate(old_object);

				start = tmp_entry->vme_end;
				tmp_entry = tmp_entry->vme_next;
				continue;
			}

			if (entry->alias >= VM_MEMORY_MALLOC &&
			    entry->alias <= VM_MEMORY_MALLOC_LARGE_REUSED) {
				vm_object_t new_object, new_shadow;

				/*
				 * We're about to map something over a mapping
				 * established by malloc()...
				 */
				new_object = copy_entry->object.vm_object;
				if (new_object != VM_OBJECT_NULL) {
					vm_object_lock_shared(new_object);
				}
				while (new_object != VM_OBJECT_NULL &&
				       new_object->internal) {
					new_shadow = new_object->shadow;
					if (new_shadow == VM_OBJECT_NULL) {
						break;
					}
					vm_object_lock_shared(new_shadow);
					vm_object_unlock(new_object);
					new_object = new_shadow;
				}
				if (new_object != VM_OBJECT_NULL) {
					if (!new_object->internal) {
						/*
						 * The new mapping is backed
						 * by an external object.  We
						 * don't want malloc'ed memory
						 * to be replaced with such a
						 * non-anonymous mapping, so
						 * let's go off the optimized
						 * path...
						 */
						vm_object_unlock(new_object);
						goto slow_copy;
					}
					vm_object_unlock(new_object);
				}
				/*
				 * The new mapping is still backed by
				 * anonymous (internal) memory, so it's
				 * OK to substitute it for the original
				 * malloc() mapping.
				 */
			}

			if (old_object != VM_OBJECT_NULL) {
				if(entry->is_sub_map) {
					if(entry->use_pmap) {
#ifndef NO_NESTED_PMAP
						pmap_unnest(dst_map->pmap, 
							    (addr64_t)entry->vme_start,
							    entry->vme_end - entry->vme_start);
#endif	/* NO_NESTED_PMAP */
						if(dst_map->mapped) {
							/* clean up parent */
							/* map/maps */
							vm_map_submap_pmap_clean(
								dst_map, entry->vme_start,
								entry->vme_end,
								entry->object.sub_map,
								entry->offset);
						}
					} else {
						vm_map_submap_pmap_clean(
							dst_map, entry->vme_start, 
							entry->vme_end,
							entry->object.sub_map,
							entry->offset);
					}
				   	vm_map_deallocate(
						entry->object.sub_map);
			   	} else {
					if(dst_map->mapped) {
						vm_object_pmap_protect(
							entry->object.vm_object,
							entry->offset,
							entry->vme_end 
							- entry->vme_start,
							PMAP_NULL,
							entry->vme_start,
							VM_PROT_NONE);
					} else {
						pmap_remove(dst_map->pmap, 
							    (addr64_t)(entry->vme_start), 
							    (addr64_t)(entry->vme_end));
					}
					vm_object_deallocate(old_object);
			   	}
			}

			entry->is_sub_map = FALSE;
			entry->object = copy_entry->object;
			object = entry->object.vm_object;
			entry->needs_copy = copy_entry->needs_copy;
			entry->wired_count = 0;
			entry->user_wired_count = 0;
			offset = entry->offset = copy_entry->offset;

			vm_map_copy_entry_unlink(copy, copy_entry);
			vm_map_copy_entry_dispose(copy, copy_entry);

			/*
			 * we could try to push pages into the pmap at this point, BUT
			 * this optimization only saved on average 2 us per page if ALL
			 * the pages in the source were currently mapped
			 * and ALL the pages in the dest were touched, if there were fewer
			 * than 2/3 of the pages touched, this optimization actually cost more cycles
			 * it also puts a lot of pressure on the pmap layer w/r to mapping structures
			 */

			/*
			 *	Set up for the next iteration.  The map
			 *	has not been unlocked, so the next
			 *	address should be at the end of this
			 *	entry, and the next map entry should be
			 *	the one following it.
			 */

			start = tmp_entry->vme_end;
			tmp_entry = tmp_entry->vme_next;
		} else {
			vm_map_version_t	version;
			vm_object_t		dst_object;
			vm_object_offset_t	dst_offset;
			kern_return_t		r;

		slow_copy:
			dst_object = entry->object.vm_object;
			dst_offset = entry->offset;

			/*
			 *	Take an object reference, and record
			 *	the map version information so that the
			 *	map can be safely unlocked.
			 */

			if (dst_object == VM_OBJECT_NULL) {
				/*
				 * We would usually have just taken the
				 * optimized path above if the destination
				 * object has not been allocated yet.  But we
				 * now disable that optimization if the copy
				 * entry's object is not backed by anonymous
				 * memory to avoid replacing malloc'ed
				 * (i.e. re-usable) anonymous memory with a
				 * not-so-anonymous mapping.
				 * So we have to handle this case here and
				 * allocate a new VM object for this map entry.
				 */
				dst_object = vm_object_allocate(
					entry->vme_end - entry->vme_start);
				dst_offset = 0;
				entry->object.vm_object = dst_object;
				entry->offset = dst_offset;
				
			}

			vm_object_reference(dst_object);

			/* account for unlock bumping up timestamp */
			version.main_timestamp = dst_map->timestamp + 1;

			vm_map_unlock(dst_map);

			/*
			 *	Copy as much as possible in one pass
			 */

			copy_size = size;
			r = vm_fault_copy(
				copy_entry->object.vm_object,
				copy_entry->offset,
				&copy_size,
				dst_object,
				dst_offset,
				dst_map,
				&version,
				THREAD_UNINT );

			/*
			 *	Release the object reference
			 */

			vm_object_deallocate(dst_object);

			/*
			 *	If a hard error occurred, return it now
			 */

			if (r != KERN_SUCCESS)
				return(r);

			if (copy_size != 0) {
				/*
				 *	Dispose of the copied region
				 */

				vm_map_copy_clip_end(copy, copy_entry,
						     copy_entry->vme_start + copy_size);
				vm_map_copy_entry_unlink(copy, copy_entry);
				vm_object_deallocate(copy_entry->object.vm_object);
				vm_map_copy_entry_dispose(copy, copy_entry);
			}

			/*
			 *	Pick up in the destination map where we left off.
			 *
			 *	Use the version information to avoid a lookup
			 *	in the normal case.
			 */

			start += copy_size;
			vm_map_lock(dst_map);
			if (version.main_timestamp == dst_map->timestamp) {
				/* We can safely use saved tmp_entry value */

				vm_map_clip_end(dst_map, tmp_entry, start);
				tmp_entry = tmp_entry->vme_next;
			} else {
				/* Must do lookup of tmp_entry */

				if (!vm_map_lookup_entry(dst_map, start, &tmp_entry)) {
					vm_map_unlock(dst_map);
					return(KERN_INVALID_ADDRESS);
				}
				vm_map_clip_start(dst_map, tmp_entry, start);
			}
		}
	}/* while */

	return(KERN_SUCCESS);
}/* vm_map_copy_overwrite_aligned */

/*
 *	Routine: vm_map_copyin_kernel_buffer [internal use only]
 *
 *	Description:
 *		Copy in data to a kernel buffer from space in the
 *		source map. The original space may be optionally
 *		deallocated.
 *
 *		If successful, returns a new copy object.
 */
static kern_return_t
vm_map_copyin_kernel_buffer(
	vm_map_t	src_map,
	vm_map_offset_t	src_addr,
	vm_map_size_t	len,
	boolean_t	src_destroy,
	vm_map_copy_t	*copy_result)
{
	kern_return_t kr;
	vm_map_copy_t copy;
	vm_size_t kalloc_size;

	if ((vm_size_t) len != len) {
		/* "len" is too big and doesn't fit in a "vm_size_t" */
		return KERN_RESOURCE_SHORTAGE;
	}
	kalloc_size = (vm_size_t) (sizeof(struct vm_map_copy) + len);
	assert((vm_map_size_t) kalloc_size == sizeof (struct vm_map_copy) + len);

	copy = (vm_map_copy_t) kalloc(kalloc_size);
	if (copy == VM_MAP_COPY_NULL) {
		return KERN_RESOURCE_SHORTAGE;
	}
	copy->type = VM_MAP_COPY_KERNEL_BUFFER;
	copy->size = len;
	copy->offset = 0;
	copy->cpy_kdata = (void *) (copy + 1);
	copy->cpy_kalloc_size = kalloc_size;

	kr = copyinmap(src_map, src_addr, copy->cpy_kdata, (vm_size_t) len);
	if (kr != KERN_SUCCESS) {
		kfree(copy, kalloc_size);
		return kr;
	}
	if (src_destroy) {
		(void) vm_map_remove(src_map, vm_map_trunc_page(src_addr), 
				     vm_map_round_page(src_addr + len),
				     VM_MAP_REMOVE_INTERRUPTIBLE |
				     VM_MAP_REMOVE_WAIT_FOR_KWIRE |
				     (src_map == kernel_map) ?
				     VM_MAP_REMOVE_KUNWIRE : 0);
	}
	*copy_result = copy;
	return KERN_SUCCESS;
}

/*
 *	Routine: vm_map_copyout_kernel_buffer	[internal use only]
 *
 *	Description:
 *		Copy out data from a kernel buffer into space in the
 *		destination map. The space may be otpionally dynamically
 *		allocated.
 *
 *		If successful, consumes the copy object.
 *		Otherwise, the caller is responsible for it.
 */
static int vm_map_copyout_kernel_buffer_failures = 0;
static kern_return_t
vm_map_copyout_kernel_buffer(
	vm_map_t		map,
	vm_map_address_t	*addr,	/* IN/OUT */
	vm_map_copy_t		copy,
	boolean_t		overwrite)
{
	kern_return_t kr = KERN_SUCCESS;
	thread_t thread = current_thread();

	if (!overwrite) {

		/*
		 * Allocate space in the target map for the data
		 */
		*addr = 0;
		kr = vm_map_enter(map, 
				  addr, 
				  vm_map_round_page(copy->size),
				  (vm_map_offset_t) 0, 
				  VM_FLAGS_ANYWHERE,
				  VM_OBJECT_NULL, 
				  (vm_object_offset_t) 0, 
				  FALSE,
				  VM_PROT_DEFAULT, 
				  VM_PROT_ALL,
				  VM_INHERIT_DEFAULT);
		if (kr != KERN_SUCCESS)
			return kr;
	}

	/*
	 * Copyout the data from the kernel buffer to the target map.
	 */	
	if (thread->map == map) {
	
		/*
		 * If the target map is the current map, just do
		 * the copy.
		 */
		assert((vm_size_t) copy->size == copy->size);
		if (copyout(copy->cpy_kdata, *addr, (vm_size_t) copy->size)) {
			kr = KERN_INVALID_ADDRESS;
		}
	}
	else {
		vm_map_t oldmap;

		/*
		 * If the target map is another map, assume the
		 * target's address space identity for the duration
		 * of the copy.
		 */
		vm_map_reference(map);
		oldmap = vm_map_switch(map);

		assert((vm_size_t) copy->size == copy->size);
		if (copyout(copy->cpy_kdata, *addr, (vm_size_t) copy->size)) {
			vm_map_copyout_kernel_buffer_failures++;
			kr = KERN_INVALID_ADDRESS;
		}
	
		(void) vm_map_switch(oldmap);
		vm_map_deallocate(map);
	}

	if (kr != KERN_SUCCESS) {
		/* the copy failed, clean up */
		if (!overwrite) {
			/*
			 * Deallocate the space we allocated in the target map.
			 */
			(void) vm_map_remove(map,
					     vm_map_trunc_page(*addr),
					     vm_map_round_page(*addr +
							       vm_map_round_page(copy->size)),
					     VM_MAP_NO_FLAGS);
			*addr = 0;
		}
	} else {
		/* copy was successful, dicard the copy structure */
		kfree(copy, copy->cpy_kalloc_size);
	}

	return kr;
}
		
/*
 *	Macro:		vm_map_copy_insert
 *	
 *	Description:
 *		Link a copy chain ("copy") into a map at the
 *		specified location (after "where").
 *	Side effects:
 *		The copy chain is destroyed.
 *	Warning:
 *		The arguments are evaluated multiple times.
 */
#define	vm_map_copy_insert(map, where, copy)				\
MACRO_BEGIN								\
	vm_map_store_copy_insert(map, where, copy);	  \
	zfree(vm_map_copy_zone, copy);		\
MACRO_END

/*
 *	Routine:	vm_map_copyout
 *
 *	Description:
 *		Copy out a copy chain ("copy") into newly-allocated
 *		space in the destination map.
 *
 *		If successful, consumes the copy object.
 *		Otherwise, the caller is responsible for it.
 */
kern_return_t
vm_map_copyout(
	vm_map_t		dst_map,
	vm_map_address_t	*dst_addr,	/* OUT */
	vm_map_copy_t		copy)
{
	vm_map_size_t		size;
	vm_map_size_t		adjustment;
	vm_map_offset_t		start;
	vm_object_offset_t	vm_copy_start;
	vm_map_entry_t		last;
	register
	vm_map_entry_t		entry;

	/*
	 *	Check for null copy object.
	 */

	if (copy == VM_MAP_COPY_NULL) {
		*dst_addr = 0;
		return(KERN_SUCCESS);
	}

	/*
	 *	Check for special copy object, created
	 *	by vm_map_copyin_object.
	 */

	if (copy->type == VM_MAP_COPY_OBJECT) {
		vm_object_t 		object = copy->cpy_object;
		kern_return_t 		kr;
		vm_object_offset_t	offset;

		offset = vm_object_trunc_page(copy->offset);
		size = vm_map_round_page(copy->size + 
					 (vm_map_size_t)(copy->offset - offset));
		*dst_addr = 0;
		kr = vm_map_enter(dst_map, dst_addr, size,
				  (vm_map_offset_t) 0, VM_FLAGS_ANYWHERE,
				  object, offset, FALSE,
				  VM_PROT_DEFAULT, VM_PROT_ALL,
				  VM_INHERIT_DEFAULT);
		if (kr != KERN_SUCCESS)
			return(kr);
		/* Account for non-pagealigned copy object */
		*dst_addr += (vm_map_offset_t)(copy->offset - offset);
		zfree(vm_map_copy_zone, copy);
		return(KERN_SUCCESS);
	}

	/*
	 *	Check for special kernel buffer allocated
	 *	by new_ipc_kmsg_copyin.
	 */

	if (copy->type == VM_MAP_COPY_KERNEL_BUFFER) {
		return(vm_map_copyout_kernel_buffer(dst_map, dst_addr, 
						    copy, FALSE));
	}

	/*
	 *	Find space for the data
	 */

	vm_copy_start = vm_object_trunc_page(copy->offset);
	size =	vm_map_round_page((vm_map_size_t)copy->offset + copy->size) 
		- vm_copy_start;

StartAgain: ;

	vm_map_lock(dst_map);
	if( dst_map->disable_vmentry_reuse == TRUE) {
		VM_MAP_HIGHEST_ENTRY(dst_map, entry, start);
		last = entry;
	} else {
		assert(first_free_is_valid(dst_map));
		start = ((last = dst_map->first_free) == vm_map_to_entry(dst_map)) ?
		vm_map_min(dst_map) : last->vme_end;
	}

	while (TRUE) {
		vm_map_entry_t	next = last->vme_next;
		vm_map_offset_t	end = start + size;

		if ((end > dst_map->max_offset) || (end < start)) {
			if (dst_map->wait_for_space) {
				if (size <= (dst_map->max_offset - dst_map->min_offset)) {
					assert_wait((event_t) dst_map,
						    THREAD_INTERRUPTIBLE);
					vm_map_unlock(dst_map);
					thread_block(THREAD_CONTINUE_NULL);
					goto StartAgain;
				}
			}
			vm_map_unlock(dst_map);
			return(KERN_NO_SPACE);
		}

		if ((next == vm_map_to_entry(dst_map)) ||
		    (next->vme_start >= end))
			break;

		last = next;
		start = last->vme_end;
	}

	/*
	 *	Since we're going to just drop the map
	 *	entries from the copy into the destination
	 *	map, they must come from the same pool.
	 */

	if (copy->cpy_hdr.entries_pageable != dst_map->hdr.entries_pageable) {
		/*
		 * Mismatches occur when dealing with the default
		 * pager.
		 */
		zone_t		old_zone;
		vm_map_entry_t	next, new;

		/*
		 * Find the zone that the copies were allocated from
		 */
		old_zone = (copy->cpy_hdr.entries_pageable)
			? vm_map_entry_zone
			: vm_map_kentry_zone;
		entry = vm_map_copy_first_entry(copy);

		/*
		 * Reinitialize the copy so that vm_map_copy_entry_link
		 * will work.
		 */
		vm_map_store_copy_reset(copy, entry);
		copy->cpy_hdr.entries_pageable = dst_map->hdr.entries_pageable;

		/*
		 * Copy each entry.
		 */
		while (entry != vm_map_copy_to_entry(copy)) {
			new = vm_map_copy_entry_create(copy);
			vm_map_entry_copy_full(new, entry);
			new->use_pmap = FALSE;	/* clr address space specifics */
			vm_map_copy_entry_link(copy,
					       vm_map_copy_last_entry(copy),
					       new);
			next = entry->vme_next;
			zfree(old_zone, entry);
			entry = next;
		}
	}

	/*
	 *	Adjust the addresses in the copy chain, and
	 *	reset the region attributes.
	 */

	adjustment = start - vm_copy_start;
	for (entry = vm_map_copy_first_entry(copy);
	     entry != vm_map_copy_to_entry(copy);
	     entry = entry->vme_next) {
		entry->vme_start += adjustment;
		entry->vme_end += adjustment;

		entry->inheritance = VM_INHERIT_DEFAULT;
		entry->protection = VM_PROT_DEFAULT;
		entry->max_protection = VM_PROT_ALL;
		entry->behavior = VM_BEHAVIOR_DEFAULT;

		/*
		 * If the entry is now wired,
		 * map the pages into the destination map.
		 */
		if (entry->wired_count != 0) {
			register vm_map_offset_t va;
			vm_object_offset_t	 offset;
			register vm_object_t object;
			vm_prot_t prot;
			int	type_of_fault;

			object = entry->object.vm_object;
			offset = entry->offset;
			va = entry->vme_start;

			pmap_pageable(dst_map->pmap,
				      entry->vme_start,
				      entry->vme_end,
				      TRUE);

			while (va < entry->vme_end) {
				register vm_page_t	m;

				/*
				 * Look up the page in the object.
				 * Assert that the page will be found in the
				 * top object:
				 * either
				 *	the object was newly created by
				 *	vm_object_copy_slowly, and has
				 *	copies of all of the pages from
				 *	the source object
				 * or
				 *	the object was moved from the old
				 *	map entry; because the old map
				 *	entry was wired, all of the pages
				 *	were in the top-level object.
				 *	(XXX not true if we wire pages for
				 *	 reading)
				 */
				vm_object_lock(object);

				m = vm_page_lookup(object, offset);
				if (m == VM_PAGE_NULL || !VM_PAGE_WIRED(m) ||
				    m->absent)
					panic("vm_map_copyout: wiring %p", m);

				/*
				 * ENCRYPTED SWAP:
				 * The page is assumed to be wired here, so it
				 * shouldn't be encrypted.  Otherwise, we
				 * couldn't enter it in the page table, since
				 * we don't want the user to see the encrypted
				 * data.
				 */
				ASSERT_PAGE_DECRYPTED(m);

				prot = entry->protection;

				if (override_nx(dst_map, entry->alias) && prot)
				        prot |= VM_PROT_EXECUTE;

				type_of_fault = DBG_CACHE_HIT_FAULT;

				vm_fault_enter(m, dst_map->pmap, va, prot, prot,
					       VM_PAGE_WIRED(m), FALSE, FALSE, FALSE,
					       &type_of_fault);

				vm_object_unlock(object);

				offset += PAGE_SIZE_64;
				va += PAGE_SIZE;
			}
		}
	}

	/*
	 *	Correct the page alignment for the result
	 */

	*dst_addr = start + (copy->offset - vm_copy_start);

	/*
	 *	Update the hints and the map size
	 */

	SAVE_HINT_MAP_WRITE(dst_map, vm_map_copy_last_entry(copy));

	dst_map->size += size;

	/*
	 *	Link in the copy
	 */

	vm_map_copy_insert(dst_map, last, copy);

	vm_map_unlock(dst_map);

	/*
	 * XXX	If wiring_required, call vm_map_pageable
	 */

	return(KERN_SUCCESS);
}

/*
 *	Routine:	vm_map_copyin
 *
 *	Description:
 *		see vm_map_copyin_common.  Exported via Unsupported.exports.
 *
 */

#undef vm_map_copyin

kern_return_t
vm_map_copyin(
	vm_map_t			src_map,
	vm_map_address_t	src_addr,
	vm_map_size_t		len,
	boolean_t			src_destroy,
	vm_map_copy_t		*copy_result)	/* OUT */
{
	return(vm_map_copyin_common(src_map, src_addr, len, src_destroy,
					FALSE, copy_result, FALSE));
}

/*
 *	Routine:	vm_map_copyin_common
 *
 *	Description:
 *		Copy the specified region (src_addr, len) from the
 *		source address space (src_map), possibly removing
 *		the region from the source address space (src_destroy).
 *
 *	Returns:
 *		A vm_map_copy_t object (copy_result), suitable for
 *		insertion into another address space (using vm_map_copyout),
 *		copying over another address space region (using
 *		vm_map_copy_overwrite).  If the copy is unused, it
 *		should be destroyed (using vm_map_copy_discard).
 *
 *	In/out conditions:
 *		The source map should not be locked on entry.
 */

typedef struct submap_map {
	vm_map_t	parent_map;
	vm_map_offset_t	base_start;
	vm_map_offset_t	base_end;
	vm_map_size_t	base_len;
	struct submap_map *next;
} submap_map_t;

kern_return_t
vm_map_copyin_common(
	vm_map_t	src_map,
	vm_map_address_t src_addr,
	vm_map_size_t	len,
	boolean_t	src_destroy,
	__unused boolean_t	src_volatile,
	vm_map_copy_t	*copy_result,	/* OUT */
	boolean_t	use_maxprot)
{
	vm_map_entry_t	tmp_entry;	/* Result of last map lookup --
					 * in multi-level lookup, this
					 * entry contains the actual
					 * vm_object/offset.
					 */
	register
	vm_map_entry_t	new_entry = VM_MAP_ENTRY_NULL;	/* Map entry for copy */

	vm_map_offset_t	src_start;	/* Start of current entry --
					 * where copy is taking place now
					 */
	vm_map_offset_t	src_end;	/* End of entire region to be
					 * copied */
	vm_map_offset_t src_base;
	vm_map_t	base_map = src_map;
	boolean_t	map_share=FALSE;
	submap_map_t	*parent_maps = NULL;

	register
	vm_map_copy_t	copy;		/* Resulting copy */
	vm_map_address_t	copy_addr;

	/*
	 *	Check for copies of zero bytes.
	 */

	if (len == 0) {
		*copy_result = VM_MAP_COPY_NULL;
		return(KERN_SUCCESS);
	}

	/*
	 *	Check that the end address doesn't overflow
	 */
	src_end = src_addr + len;
	if (src_end < src_addr)
		return KERN_INVALID_ADDRESS;

	/*
	 * If the copy is sufficiently small, use a kernel buffer instead
	 * of making a virtual copy.  The theory being that the cost of
	 * setting up VM (and taking C-O-W faults) dominates the copy costs
	 * for small regions.
	 */
	if ((len < msg_ool_size_small) && !use_maxprot)
		return vm_map_copyin_kernel_buffer(src_map, src_addr, len,
						   src_destroy, copy_result);

	/*
	 *	Compute (page aligned) start and end of region
	 */
	src_start = vm_map_trunc_page(src_addr);
	src_end = vm_map_round_page(src_end);

	XPR(XPR_VM_MAP, "vm_map_copyin_common map 0x%x addr 0x%x len 0x%x dest %d\n", src_map, src_addr, len, src_destroy, 0);

	/*
	 *	Allocate a header element for the list.
	 *
	 *	Use the start and end in the header to 
	 *	remember the endpoints prior to rounding.
	 */

	copy = (vm_map_copy_t) zalloc(vm_map_copy_zone);
	vm_map_copy_first_entry(copy) =
		vm_map_copy_last_entry(copy) = vm_map_copy_to_entry(copy);
	copy->type = VM_MAP_COPY_ENTRY_LIST;
	copy->cpy_hdr.nentries = 0;
	copy->cpy_hdr.entries_pageable = TRUE;

	vm_map_store_init( &(copy->cpy_hdr) );

	copy->offset = src_addr;
	copy->size = len;
	
	new_entry = vm_map_copy_entry_create(copy);

#define	RETURN(x)						\
	MACRO_BEGIN						\
	vm_map_unlock(src_map);					\
	if(src_map != base_map)					\
		vm_map_deallocate(src_map);			\
	if (new_entry != VM_MAP_ENTRY_NULL)			\
		vm_map_copy_entry_dispose(copy,new_entry);	\
	vm_map_copy_discard(copy);				\
	{							\
		submap_map_t	*_ptr;				\
								\
		for(_ptr = parent_maps; _ptr != NULL; _ptr = parent_maps) { \
			parent_maps=parent_maps->next;		\
			if (_ptr->parent_map != base_map)	\
				vm_map_deallocate(_ptr->parent_map);	\
			kfree(_ptr, sizeof(submap_map_t));	\
		}						\
	}							\
	MACRO_RETURN(x);					\
	MACRO_END

	/*
	 *	Find the beginning of the region.
	 */

 	vm_map_lock(src_map);

	if (!vm_map_lookup_entry(src_map, src_start, &tmp_entry))
		RETURN(KERN_INVALID_ADDRESS);
	if(!tmp_entry->is_sub_map) {
		vm_map_clip_start(src_map, tmp_entry, src_start);
	}
	/* set for later submap fix-up */
	copy_addr = src_start;

	/*
	 *	Go through entries until we get to the end.
	 */

	while (TRUE) {
		register
		vm_map_entry_t	src_entry = tmp_entry;	/* Top-level entry */
		vm_map_size_t	src_size;		/* Size of source
							 * map entry (in both
							 * maps)
							 */

		register
		vm_object_t		src_object;	/* Object to copy */
		vm_object_offset_t	src_offset;

		boolean_t	src_needs_copy;		/* Should source map
							 * be made read-only
							 * for copy-on-write?
							 */

		boolean_t	new_entry_needs_copy;	/* Will new entry be COW? */

		boolean_t	was_wired;		/* Was source wired? */
		vm_map_version_t version;		/* Version before locks
							 * dropped to make copy
							 */
		kern_return_t	result;			/* Return value from
							 * copy_strategically.
							 */
		while(tmp_entry->is_sub_map) {
			vm_map_size_t submap_len;
			submap_map_t *ptr;

			ptr = (submap_map_t *)kalloc(sizeof(submap_map_t));
			ptr->next = parent_maps;
			parent_maps = ptr;
			ptr->parent_map = src_map;
			ptr->base_start = src_start;
			ptr->base_end = src_end;
			submap_len = tmp_entry->vme_end - src_start;
			if(submap_len > (src_end-src_start))
				submap_len = src_end-src_start;
			ptr->base_len = submap_len;
	
			src_start -= tmp_entry->vme_start;
			src_start += tmp_entry->offset;
			src_end = src_start + submap_len;
			src_map = tmp_entry->object.sub_map;
			vm_map_lock(src_map);
			/* keep an outstanding reference for all maps in */
			/* the parents tree except the base map */
			vm_map_reference(src_map);
			vm_map_unlock(ptr->parent_map);
			if (!vm_map_lookup_entry(
				    src_map, src_start, &tmp_entry))
				RETURN(KERN_INVALID_ADDRESS);
			map_share = TRUE;
			if(!tmp_entry->is_sub_map)
				vm_map_clip_start(src_map, tmp_entry, src_start);
			src_entry = tmp_entry;
		}
		/* we are now in the lowest level submap... */

		if ((tmp_entry->object.vm_object != VM_OBJECT_NULL) && 
		    (tmp_entry->object.vm_object->phys_contiguous)) {
			/* This is not, supported for now.In future */
			/* we will need to detect the phys_contig   */
			/* condition and then upgrade copy_slowly   */
			/* to do physical copy from the device mem  */
			/* based object. We can piggy-back off of   */
			/* the was wired boolean to set-up the      */
			/* proper handling */
			RETURN(KERN_PROTECTION_FAILURE);
		}
		/*
		 *	Create a new address map entry to hold the result. 
		 *	Fill in the fields from the appropriate source entries.
		 *	We must unlock the source map to do this if we need
		 *	to allocate a map entry.
		 */
		if (new_entry == VM_MAP_ENTRY_NULL) {
			version.main_timestamp = src_map->timestamp;
			vm_map_unlock(src_map);

			new_entry = vm_map_copy_entry_create(copy);

			vm_map_lock(src_map);
			if ((version.main_timestamp + 1) != src_map->timestamp) {
				if (!vm_map_lookup_entry(src_map, src_start,
							 &tmp_entry)) {
					RETURN(KERN_INVALID_ADDRESS);
				}
				if (!tmp_entry->is_sub_map)
					vm_map_clip_start(src_map, tmp_entry, src_start);
				continue; /* restart w/ new tmp_entry */
			}
		}

		/*
		 *	Verify that the region can be read.
		 */
		if (((src_entry->protection & VM_PROT_READ) == VM_PROT_NONE &&
		     !use_maxprot) ||
		    (src_entry->max_protection & VM_PROT_READ) == 0)
			RETURN(KERN_PROTECTION_FAILURE);

		/*
		 *	Clip against the endpoints of the entire region.
		 */

		vm_map_clip_end(src_map, src_entry, src_end);

		src_size = src_entry->vme_end - src_start;
		src_object = src_entry->object.vm_object;
		src_offset = src_entry->offset;
		was_wired = (src_entry->wired_count != 0);

		vm_map_entry_copy(new_entry, src_entry);
		new_entry->use_pmap = FALSE; /* clr address space specifics */

		/*
		 *	Attempt non-blocking copy-on-write optimizations.
		 */

		if (src_destroy && 
		    (src_object == VM_OBJECT_NULL || 
		     (src_object->internal && !src_object->true_share
		      && !map_share))) {
			/*
			 * If we are destroying the source, and the object
			 * is internal, we can move the object reference
			 * from the source to the copy.  The copy is
			 * copy-on-write only if the source is.
			 * We make another reference to the object, because
			 * destroying the source entry will deallocate it.
			 */
			vm_object_reference(src_object);

			/*
			 * Copy is always unwired.  vm_map_copy_entry
			 * set its wired count to zero.
			 */

			goto CopySuccessful;
		}


	RestartCopy:
		XPR(XPR_VM_MAP, "vm_map_copyin_common src_obj 0x%x ent 0x%x obj 0x%x was_wired %d\n",
		    src_object, new_entry, new_entry->object.vm_object,
		    was_wired, 0);
		if ((src_object == VM_OBJECT_NULL ||
		     (!was_wired && !map_share && !tmp_entry->is_shared)) &&
		    vm_object_copy_quickly(
			    &new_entry->object.vm_object,
			    src_offset,
			    src_size,
			    &src_needs_copy,
			    &new_entry_needs_copy)) {

			new_entry->needs_copy = new_entry_needs_copy;

			/*
			 *	Handle copy-on-write obligations
			 */

			if (src_needs_copy && !tmp_entry->needs_copy) {
			        vm_prot_t prot;

				prot = src_entry->protection & ~VM_PROT_WRITE;

				if (override_nx(src_map, src_entry->alias) && prot)
				        prot |= VM_PROT_EXECUTE;

				vm_object_pmap_protect(
					src_object,
					src_offset,
					src_size,
			      		(src_entry->is_shared ? 
					 PMAP_NULL
					 : src_map->pmap),
					src_entry->vme_start,
					prot);

				tmp_entry->needs_copy = TRUE;
			}

			/*
			 *	The map has never been unlocked, so it's safe
			 *	to move to the next entry rather than doing
			 *	another lookup.
			 */

			goto CopySuccessful;
		}

		/*
		 *	Take an object reference, so that we may
		 *	release the map lock(s).
		 */

		assert(src_object != VM_OBJECT_NULL);
		vm_object_reference(src_object);

		/*
		 *	Record the timestamp for later verification.
		 *	Unlock the map.
		 */

		version.main_timestamp = src_map->timestamp;
		vm_map_unlock(src_map);	/* Increments timestamp once! */

		/*
		 *	Perform the copy
		 */

		if (was_wired) {
		CopySlowly:
			vm_object_lock(src_object);
			result = vm_object_copy_slowly(
				src_object,
				src_offset,
				src_size,
				THREAD_UNINT,
				&new_entry->object.vm_object);
			new_entry->offset = 0;
			new_entry->needs_copy = FALSE;

		}
		else if (src_object->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC &&
			 (tmp_entry->is_shared  || map_share)) {
		  	vm_object_t new_object;

			vm_object_lock_shared(src_object);
			new_object = vm_object_copy_delayed(
				src_object,
				src_offset,	
				src_size,
				TRUE);
			if (new_object == VM_OBJECT_NULL)
			  	goto CopySlowly;

			new_entry->object.vm_object = new_object;
			new_entry->needs_copy = TRUE;
			result = KERN_SUCCESS;

		} else {
			result = vm_object_copy_strategically(src_object,
							      src_offset,
							      src_size,
							      &new_entry->object.vm_object,
							      &new_entry->offset,
							      &new_entry_needs_copy);

			new_entry->needs_copy = new_entry_needs_copy;
		}

		if (result != KERN_SUCCESS &&
		    result != KERN_MEMORY_RESTART_COPY) {
			vm_map_lock(src_map);
			RETURN(result);
		}

		/*
		 *	Throw away the extra reference
		 */

		vm_object_deallocate(src_object);

		/*
		 *	Verify that the map has not substantially
		 *	changed while the copy was being made.
		 */

		vm_map_lock(src_map);

		if ((version.main_timestamp + 1) == src_map->timestamp)
			goto VerificationSuccessful;

		/*
		 *	Simple version comparison failed.
		 *
		 *	Retry the lookup and verify that the
		 *	same object/offset are still present.
		 *
		 *	[Note: a memory manager that colludes with
		 *	the calling task can detect that we have
		 *	cheated.  While the map was unlocked, the
		 *	mapping could have been changed and restored.]
		 */

		if (!vm_map_lookup_entry(src_map, src_start, &tmp_entry)) {
			RETURN(KERN_INVALID_ADDRESS);
		}

		src_entry = tmp_entry;
		vm_map_clip_start(src_map, src_entry, src_start);

		if ((((src_entry->protection & VM_PROT_READ) == VM_PROT_NONE) &&
		     !use_maxprot) ||
		    ((src_entry->max_protection & VM_PROT_READ) == 0))
			goto VerificationFailed;

		if (src_entry->vme_end < new_entry->vme_end)
			src_size = (new_entry->vme_end = src_entry->vme_end) - src_start;

		if ((src_entry->object.vm_object != src_object) ||
		    (src_entry->offset != src_offset) ) {

			/*
			 *	Verification failed.
			 *
			 *	Start over with this top-level entry.
			 */

		VerificationFailed: ;

			vm_object_deallocate(new_entry->object.vm_object);
			tmp_entry = src_entry;
			continue;
		}

		/*
		 *	Verification succeeded.
		 */

	VerificationSuccessful: ;

		if (result == KERN_MEMORY_RESTART_COPY)
			goto RestartCopy;

		/*
		 *	Copy succeeded.
		 */

	CopySuccessful: ;

		/*
		 *	Link in the new copy entry.
		 */

		vm_map_copy_entry_link(copy, vm_map_copy_last_entry(copy),
				       new_entry);
		
		/*
		 *	Determine whether the entire region
		 *	has been copied.
		 */
		src_base = src_start;
		src_start = new_entry->vme_end;
		new_entry = VM_MAP_ENTRY_NULL;
		while ((src_start >= src_end) && (src_end != 0)) {
			if (src_map != base_map) {
				submap_map_t	*ptr;

				ptr = parent_maps;
				assert(ptr != NULL);
				parent_maps = parent_maps->next;

				/* fix up the damage we did in that submap */
				vm_map_simplify_range(src_map,
						      src_base,
						      src_end);

				vm_map_unlock(src_map);
				vm_map_deallocate(src_map);
				vm_map_lock(ptr->parent_map);
				src_map = ptr->parent_map;
				src_base = ptr->base_start;
				src_start = ptr->base_start + ptr->base_len;
				src_end = ptr->base_end;
				if ((src_end > src_start) &&
				    !vm_map_lookup_entry(
					    src_map, src_start, &tmp_entry))
					RETURN(KERN_INVALID_ADDRESS);
				kfree(ptr, sizeof(submap_map_t));
				if(parent_maps == NULL)
					map_share = FALSE;
				src_entry = tmp_entry->vme_prev;
			} else
				break;
		}
		if ((src_start >= src_end) && (src_end != 0))
			break;

		/*
		 *	Verify that there are no gaps in the region
		 */

		tmp_entry = src_entry->vme_next;
		if ((tmp_entry->vme_start != src_start) || 
		    (tmp_entry == vm_map_to_entry(src_map)))
			RETURN(KERN_INVALID_ADDRESS);
	}

	/*
	 * If the source should be destroyed, do it now, since the
	 * copy was successful. 
	 */
	if (src_destroy) {
		(void) vm_map_delete(src_map,
				     vm_map_trunc_page(src_addr),
				     src_end,
				     (src_map == kernel_map) ?
				     VM_MAP_REMOVE_KUNWIRE :
				     VM_MAP_NO_FLAGS,
				     VM_MAP_NULL);
	} else {
		/* fix up the damage we did in the base map */
		vm_map_simplify_range(src_map,
				      vm_map_trunc_page(src_addr), 
				      vm_map_round_page(src_end));
	}

	vm_map_unlock(src_map);

	/* Fix-up start and end points in copy.  This is necessary */
	/* when the various entries in the copy object were picked */
	/* up from different sub-maps */

	tmp_entry = vm_map_copy_first_entry(copy);
	while (tmp_entry != vm_map_copy_to_entry(copy)) {
		tmp_entry->vme_end = copy_addr + 
			(tmp_entry->vme_end - tmp_entry->vme_start);
		tmp_entry->vme_start = copy_addr;
		copy_addr += tmp_entry->vme_end - tmp_entry->vme_start;
		tmp_entry = (struct vm_map_entry *)tmp_entry->vme_next;
	}

	*copy_result = copy;
	return(KERN_SUCCESS);

#undef	RETURN
}

/*
 *	vm_map_copyin_object:
 *
 *	Create a copy object from an object.
 *	Our caller donates an object reference.
 */

kern_return_t
vm_map_copyin_object(
	vm_object_t		object,
	vm_object_offset_t	offset,	/* offset of region in object */
	vm_object_size_t	size,	/* size of region in object */
	vm_map_copy_t	*copy_result)	/* OUT */
{
	vm_map_copy_t	copy;		/* Resulting copy */

	/*
	 *	We drop the object into a special copy object
	 *	that contains the object directly.
	 */

	copy = (vm_map_copy_t) zalloc(vm_map_copy_zone);
	copy->type = VM_MAP_COPY_OBJECT;
	copy->cpy_object = object;
	copy->offset = offset;
	copy->size = size;

	*copy_result = copy;
	return(KERN_SUCCESS);
}

static void
vm_map_fork_share(
	vm_map_t	old_map,
	vm_map_entry_t	old_entry,
	vm_map_t	new_map)
{
	vm_object_t 	object;
	vm_map_entry_t 	new_entry;

	/*
	 *	New sharing code.  New map entry
	 *	references original object.  Internal
	 *	objects use asynchronous copy algorithm for
	 *	future copies.  First make sure we have
	 *	the right object.  If we need a shadow,
	 *	or someone else already has one, then
	 *	make a new shadow and share it.
	 */
	
	object = old_entry->object.vm_object;
	if (old_entry->is_sub_map) {
		assert(old_entry->wired_count == 0);
#ifndef NO_NESTED_PMAP
		if(old_entry->use_pmap) {
			kern_return_t	result;

			result = pmap_nest(new_map->pmap, 
					   (old_entry->object.sub_map)->pmap, 
					   (addr64_t)old_entry->vme_start,
					   (addr64_t)old_entry->vme_start,
					   (uint64_t)(old_entry->vme_end - old_entry->vme_start));
			if(result)
				panic("vm_map_fork_share: pmap_nest failed!");
		}
#endif	/* NO_NESTED_PMAP */
	} else if (object == VM_OBJECT_NULL) {
		object = vm_object_allocate((vm_map_size_t)(old_entry->vme_end -
							    old_entry->vme_start));
		old_entry->offset = 0;
		old_entry->object.vm_object = object;
		assert(!old_entry->needs_copy);
	} else if (object->copy_strategy !=
		   MEMORY_OBJECT_COPY_SYMMETRIC) {
		
		/*
		 *	We are already using an asymmetric
		 *	copy, and therefore we already have
		 *	the right object.
		 */
		
		assert(! old_entry->needs_copy);
	}
	else if (old_entry->needs_copy ||	/* case 1 */
		 object->shadowed ||		/* case 2 */
		 (!object->true_share && 	/* case 3 */
		  !old_entry->is_shared &&
		  (object->vo_size >
		   (vm_map_size_t)(old_entry->vme_end -
				   old_entry->vme_start)))) {
		
		/*
		 *	We need to create a shadow.
		 *	There are three cases here.
		 *	In the first case, we need to
		 *	complete a deferred symmetrical
		 *	copy that we participated in.
		 *	In the second and third cases,
		 *	we need to create the shadow so
		 *	that changes that we make to the
		 *	object do not interfere with
		 *	any symmetrical copies which
		 *	have occured (case 2) or which
		 *	might occur (case 3).
		 *
		 *	The first case is when we had
		 *	deferred shadow object creation
		 *	via the entry->needs_copy mechanism.
		 *	This mechanism only works when
		 *	only one entry points to the source
		 *	object, and we are about to create
		 *	a second entry pointing to the
		 *	same object. The problem is that
		 *	there is no way of mapping from
		 *	an object to the entries pointing
		 *	to it. (Deferred shadow creation
		 *	works with one entry because occurs
		 *	at fault time, and we walk from the
		 *	entry to the object when handling
		 *	the fault.)
		 *
		 *	The second case is when the object
		 *	to be shared has already been copied
		 *	with a symmetric copy, but we point
		 *	directly to the object without
		 *	needs_copy set in our entry. (This
		 *	can happen because different ranges
		 *	of an object can be pointed to by
		 *	different entries. In particular,
		 *	a single entry pointing to an object
		 *	can be split by a call to vm_inherit,
		 *	which, combined with task_create, can
		 *	result in the different entries
		 *	having different needs_copy values.)
		 *	The shadowed flag in the object allows
		 *	us to detect this case. The problem
		 *	with this case is that if this object
		 *	has or will have shadows, then we
		 *	must not perform an asymmetric copy
		 *	of this object, since such a copy
		 *	allows the object to be changed, which
		 *	will break the previous symmetrical
		 *	copies (which rely upon the object
		 *	not changing). In a sense, the shadowed
		 *	flag says "don't change this object".
		 *	We fix this by creating a shadow
		 *	object for this object, and sharing
		 *	that. This works because we are free
		 *	to change the shadow object (and thus
		 *	to use an asymmetric copy strategy);
		 *	this is also semantically correct,
		 *	since this object is temporary, and
		 *	therefore a copy of the object is
		 *	as good as the object itself. (This
		 *	is not true for permanent objects,
		 *	since the pager needs to see changes,
		 *	which won't happen if the changes
		 *	are made to a copy.)
		 *
		 *	The third case is when the object
		 *	to be shared has parts sticking
		 *	outside of the entry we're working
		 *	with, and thus may in the future
		 *	be subject to a symmetrical copy.
		 *	(This is a preemptive version of
		 *	case 2.)
		 */
		vm_object_shadow(&old_entry->object.vm_object,
				 &old_entry->offset,
				 (vm_map_size_t) (old_entry->vme_end -
						  old_entry->vme_start));
		
		/*
		 *	If we're making a shadow for other than
		 *	copy on write reasons, then we have
		 *	to remove write permission.
		 */

		if (!old_entry->needs_copy &&
		    (old_entry->protection & VM_PROT_WRITE)) {
		        vm_prot_t prot;

			prot = old_entry->protection & ~VM_PROT_WRITE;

			if (override_nx(old_map, old_entry->alias) && prot)
			        prot |= VM_PROT_EXECUTE;

			if (old_map->mapped) {
				vm_object_pmap_protect(
					old_entry->object.vm_object,
					old_entry->offset,
					(old_entry->vme_end -
					 old_entry->vme_start),
					PMAP_NULL,
					old_entry->vme_start,
					prot);
			} else {
				pmap_protect(old_map->pmap,
					     old_entry->vme_start,
					     old_entry->vme_end,
					     prot);
			}
		}
		
		old_entry->needs_copy = FALSE;
		object = old_entry->object.vm_object;
	}

	
	/*
	 *	If object was using a symmetric copy strategy,
	 *	change its copy strategy to the default
	 *	asymmetric copy strategy, which is copy_delay
	 *	in the non-norma case and copy_call in the
	 *	norma case. Bump the reference count for the
	 *	new entry.
	 */
	
	if(old_entry->is_sub_map) {
		vm_map_lock(old_entry->object.sub_map);
		vm_map_reference(old_entry->object.sub_map);
		vm_map_unlock(old_entry->object.sub_map);
	} else {
		vm_object_lock(object);
		vm_object_reference_locked(object);
		if (object->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC) {
			object->copy_strategy = MEMORY_OBJECT_COPY_DELAY;
		}
		vm_object_unlock(object);
	}
	
	/*
	 *	Clone the entry, using object ref from above.
	 *	Mark both entries as shared.
	 */
	
	new_entry = vm_map_entry_create(new_map);
	vm_map_entry_copy(new_entry, old_entry);
	old_entry->is_shared = TRUE;
	new_entry->is_shared = TRUE;
	
	/*
	 *	Insert the entry into the new map -- we
	 *	know we're inserting at the end of the new
	 *	map.
	 */
	
	vm_map_store_entry_link(new_map, vm_map_last_entry(new_map), new_entry);
	
	/*
	 *	Update the physical map
	 */
	
	if (old_entry->is_sub_map) {
		/* Bill Angell pmap support goes here */
	} else {
		pmap_copy(new_map->pmap, old_map->pmap, new_entry->vme_start,
			  old_entry->vme_end - old_entry->vme_start,
			  old_entry->vme_start);
	}
}

static boolean_t
vm_map_fork_copy(
	vm_map_t	old_map,
	vm_map_entry_t	*old_entry_p,
	vm_map_t	new_map)
{
	vm_map_entry_t old_entry = *old_entry_p;
	vm_map_size_t entry_size = old_entry->vme_end - old_entry->vme_start;
	vm_map_offset_t start = old_entry->vme_start;
	vm_map_copy_t copy;
	vm_map_entry_t last = vm_map_last_entry(new_map);

	vm_map_unlock(old_map);
	/*
	 *	Use maxprot version of copyin because we
	 *	care about whether this memory can ever
	 *	be accessed, not just whether it's accessible
	 *	right now.
	 */
	if (vm_map_copyin_maxprot(old_map, start, entry_size, FALSE, &copy)
	    != KERN_SUCCESS) {
		/*
		 *	The map might have changed while it
		 *	was unlocked, check it again.  Skip
		 *	any blank space or permanently
		 *	unreadable region.
		 */
		vm_map_lock(old_map);
		if (!vm_map_lookup_entry(old_map, start, &last) ||
		    (last->max_protection & VM_PROT_READ) == VM_PROT_NONE) {
			last = last->vme_next;
		}
		*old_entry_p = last;

		/*
		 * XXX	For some error returns, want to
		 * XXX	skip to the next element.  Note
		 *	that INVALID_ADDRESS and
		 *	PROTECTION_FAILURE are handled above.
		 */
		
		return FALSE;
	}
	
	/*
	 *	Insert the copy into the new map
	 */
	
	vm_map_copy_insert(new_map, last, copy);
	
	/*
	 *	Pick up the traversal at the end of
	 *	the copied region.
	 */
	
	vm_map_lock(old_map);
	start += entry_size;
	if (! vm_map_lookup_entry(old_map, start, &last)) {
		last = last->vme_next;
	} else {
		if (last->vme_start == start) {
			/*
			 * No need to clip here and we don't
			 * want to cause any unnecessary
			 * unnesting...
			 */
		} else {
			vm_map_clip_start(old_map, last, start);
		}
	}
	*old_entry_p = last;

	return TRUE;
}

/*
 *	vm_map_fork:
 *
 *	Create and return a new map based on the old
 *	map, according to the inheritance values on the
 *	regions in that map.
 *
 *	The source map must not be locked.
 */
vm_map_t
vm_map_fork(
	vm_map_t	old_map)
{
	pmap_t		new_pmap;
	vm_map_t	new_map;
	vm_map_entry_t	old_entry;
	vm_map_size_t	new_size = 0, entry_size;
	vm_map_entry_t	new_entry;
	boolean_t	src_needs_copy;
	boolean_t	new_entry_needs_copy;

	new_pmap = pmap_create((vm_map_size_t) 0,
#if defined(__i386__) || defined(__x86_64__)
			       old_map->pmap->pm_task_map != TASK_MAP_32BIT
#else
			       0
#endif
			       );
#if defined(__i386__)
	if (old_map->pmap->pm_task_map == TASK_MAP_64BIT_SHARED)
		pmap_set_4GB_pagezero(new_pmap);
#endif

	vm_map_reference_swap(old_map);
	vm_map_lock(old_map);

	new_map = vm_map_create(new_pmap,
				old_map->min_offset,
				old_map->max_offset,
				old_map->hdr.entries_pageable);
	for (
		old_entry = vm_map_first_entry(old_map);
		old_entry != vm_map_to_entry(old_map);
		) {

		entry_size = old_entry->vme_end - old_entry->vme_start;

		switch (old_entry->inheritance) {
		case VM_INHERIT_NONE:
			break;

		case VM_INHERIT_SHARE:
			vm_map_fork_share(old_map, old_entry, new_map);
			new_size += entry_size;
			break;

		case VM_INHERIT_COPY:

			/*
			 *	Inline the copy_quickly case;
			 *	upon failure, fall back on call
			 *	to vm_map_fork_copy.
			 */

			if(old_entry->is_sub_map)
				break;
			if ((old_entry->wired_count != 0) ||
			    ((old_entry->object.vm_object != NULL) &&
			     (old_entry->object.vm_object->true_share))) {
				goto slow_vm_map_fork_copy;
			}

			new_entry = vm_map_entry_create(new_map);
			vm_map_entry_copy(new_entry, old_entry);
			/* clear address space specifics */
			new_entry->use_pmap = FALSE;

			if (! vm_object_copy_quickly(
				    &new_entry->object.vm_object,
				    old_entry->offset,
				    (old_entry->vme_end -
				     old_entry->vme_start),
				    &src_needs_copy,
				    &new_entry_needs_copy)) {
				vm_map_entry_dispose(new_map, new_entry);
				goto slow_vm_map_fork_copy;
			}

			/*
			 *	Handle copy-on-write obligations
			 */
			
			if (src_needs_copy && !old_entry->needs_copy) {
			        vm_prot_t prot;

				prot = old_entry->protection & ~VM_PROT_WRITE;

				if (override_nx(old_map, old_entry->alias) && prot)
				        prot |= VM_PROT_EXECUTE;

				vm_object_pmap_protect(
					old_entry->object.vm_object,
					old_entry->offset,
					(old_entry->vme_end -
					 old_entry->vme_start),
					((old_entry->is_shared 
					  || old_map->mapped)
					 ? PMAP_NULL :
					 old_map->pmap),
					old_entry->vme_start,
					prot);

				old_entry->needs_copy = TRUE;
			}
			new_entry->needs_copy = new_entry_needs_copy;
			
			/*
			 *	Insert the entry at the end
			 *	of the map.
			 */
			
			vm_map_store_entry_link(new_map, vm_map_last_entry(new_map),
					  new_entry);
			new_size += entry_size;
			break;

		slow_vm_map_fork_copy:
			if (vm_map_fork_copy(old_map, &old_entry, new_map)) {
				new_size += entry_size;
			}
			continue;
		}
		old_entry = old_entry->vme_next;
	}

	new_map->size = new_size;
	vm_map_unlock(old_map);
	vm_map_deallocate(old_map);

	return(new_map);
}

/*
 * vm_map_exec:
 *
 * 	Setup the "new_map" with the proper execution environment according
 *	to the type of executable (platform, 64bit, chroot environment).
 *	Map the comm page and shared region, etc...
 */
kern_return_t
vm_map_exec(
	vm_map_t	new_map,
	task_t		task,
	void		*fsroot,
	cpu_type_t	cpu)
{
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: task %p: vm_map_exec(%p,%p,%p,0x%x): ->\n",
		 current_task(), new_map, task, fsroot, cpu));
	(void) vm_commpage_enter(new_map, task);
	(void) vm_shared_region_enter(new_map, task, fsroot, cpu);
	SHARED_REGION_TRACE_DEBUG(
		("shared_region: task %p: vm_map_exec(%p,%p,%p,0x%x): <-\n",
		 current_task(), new_map, task, fsroot, cpu));
	return KERN_SUCCESS;
}

/*
 *	vm_map_lookup_locked:
 *
 *	Finds the VM object, offset, and
 *	protection for a given virtual address in the
 *	specified map, assuming a page fault of the
 *	type specified.
 *
 *	Returns the (object, offset, protection) for
 *	this address, whether it is wired down, and whether
 *	this map has the only reference to the data in question.
 *	In order to later verify this lookup, a "version"
 *	is returned.
 *
 *	The map MUST be locked by the caller and WILL be
 *	locked on exit.  In order to guarantee the
 *	existence of the returned object, it is returned
 *	locked.
 *
 *	If a lookup is requested with "write protection"
 *	specified, the map may be changed to perform virtual
 *	copying operations, although the data referenced will
 *	remain the same.
 */
kern_return_t
vm_map_lookup_locked(
	vm_map_t		*var_map,	/* IN/OUT */
	vm_map_offset_t		vaddr,
	vm_prot_t		fault_type,
	int			object_lock_type,
	vm_map_version_t	*out_version,	/* OUT */
	vm_object_t		*object,	/* OUT */
	vm_object_offset_t	*offset,	/* OUT */
	vm_prot_t		*out_prot,	/* OUT */
	boolean_t		*wired,		/* OUT */
	vm_object_fault_info_t	fault_info,	/* OUT */
	vm_map_t		*real_map)
{
	vm_map_entry_t			entry;
	register vm_map_t		map = *var_map;
	vm_map_t			old_map = *var_map;
	vm_map_t			cow_sub_map_parent = VM_MAP_NULL;
	vm_map_offset_t			cow_parent_vaddr = 0;
	vm_map_offset_t			old_start = 0;
	vm_map_offset_t			old_end = 0;
	register vm_prot_t		prot;
	boolean_t			mask_protections;
	vm_prot_t			original_fault_type;

	/*
	 * VM_PROT_MASK means that the caller wants us to use "fault_type"
	 * as a mask against the mapping's actual protections, not as an
	 * absolute value.
	 */
	mask_protections = (fault_type & VM_PROT_IS_MASK) ? TRUE : FALSE;
	fault_type &= ~VM_PROT_IS_MASK;
	original_fault_type = fault_type;

	*real_map = map;

RetryLookup:
	fault_type = original_fault_type;

	/*
	 *	If the map has an interesting hint, try it before calling
	 *	full blown lookup routine.
	 */
	entry = map->hint;

	if ((entry == vm_map_to_entry(map)) ||
	    (vaddr < entry->vme_start) || (vaddr >= entry->vme_end)) {
		vm_map_entry_t	tmp_entry;

		/*
		 *	Entry was either not a valid hint, or the vaddr
		 *	was not contained in the entry, so do a full lookup.
		 */
		if (!vm_map_lookup_entry(map, vaddr, &tmp_entry)) {
			if((cow_sub_map_parent) && (cow_sub_map_parent != map))
				vm_map_unlock(cow_sub_map_parent);
			if((*real_map != map) 
			   && (*real_map != cow_sub_map_parent))
				vm_map_unlock(*real_map);
			return KERN_INVALID_ADDRESS;
		}

		entry = tmp_entry;
	}
	if(map == old_map) {
		old_start = entry->vme_start;
		old_end = entry->vme_end;
	}

	/*
	 *	Handle submaps.  Drop lock on upper map, submap is
	 *	returned locked.
	 */

submap_recurse:
	if (entry->is_sub_map) {
		vm_map_offset_t		local_vaddr;
		vm_map_offset_t		end_delta;
		vm_map_offset_t		start_delta; 
		vm_map_entry_t		submap_entry;
		boolean_t		mapped_needs_copy=FALSE;

		local_vaddr = vaddr;

		if ((entry->use_pmap && !(fault_type & VM_PROT_WRITE))) {
			/* if real_map equals map we unlock below */
			if ((*real_map != map) && 
			    (*real_map != cow_sub_map_parent))
				vm_map_unlock(*real_map);
			*real_map = entry->object.sub_map;
		}

		if(entry->needs_copy && (fault_type & VM_PROT_WRITE)) {
			if (!mapped_needs_copy) {
				if (vm_map_lock_read_to_write(map)) {
					vm_map_lock_read(map);
					/* XXX FBDP: entry still valid ? */
					if(*real_map == entry->object.sub_map)
						*real_map = map;
					goto RetryLookup;
				}
				vm_map_lock_read(entry->object.sub_map);
				cow_sub_map_parent = map;
				/* reset base to map before cow object */
				/* this is the map which will accept   */
				/* the new cow object */
				old_start = entry->vme_start;
				old_end = entry->vme_end;
				cow_parent_vaddr = vaddr;
				mapped_needs_copy = TRUE;
			} else {
				vm_map_lock_read(entry->object.sub_map);
				if((cow_sub_map_parent != map) &&
				   (*real_map != map))
					vm_map_unlock(map);
			}
		} else {
			vm_map_lock_read(entry->object.sub_map);
			/* leave map locked if it is a target */
			/* cow sub_map above otherwise, just  */
			/* follow the maps down to the object */
			/* here we unlock knowing we are not  */
			/* revisiting the map.  */
			if((*real_map != map) && (map != cow_sub_map_parent))
				vm_map_unlock_read(map);
		}

		/* XXX FBDP: map has been unlocked, what protects "entry" !? */
		*var_map = map = entry->object.sub_map;

		/* calculate the offset in the submap for vaddr */
		local_vaddr = (local_vaddr - entry->vme_start) + entry->offset;

	RetrySubMap:
		if(!vm_map_lookup_entry(map, local_vaddr, &submap_entry)) {
			if((cow_sub_map_parent) && (cow_sub_map_parent != map)){
				vm_map_unlock(cow_sub_map_parent);
			}
			if((*real_map != map) 
			   && (*real_map != cow_sub_map_parent)) {
				vm_map_unlock(*real_map);
			}
			*real_map = map;
			return KERN_INVALID_ADDRESS;
		}

		/* find the attenuated shadow of the underlying object */
		/* on our target map */

		/* in english the submap object may extend beyond the     */
		/* region mapped by the entry or, may only fill a portion */
		/* of it.  For our purposes, we only care if the object   */
		/* doesn't fill.  In this case the area which will        */
		/* ultimately be clipped in the top map will only need    */
		/* to be as big as the portion of the underlying entry    */
		/* which is mapped */
		start_delta = submap_entry->vme_start > entry->offset ?
			submap_entry->vme_start - entry->offset : 0;

		end_delta = 
			(entry->offset + start_delta + (old_end - old_start)) <=
			submap_entry->vme_end ?
			0 : (entry->offset + 
			     (old_end - old_start))
			- submap_entry->vme_end; 

		old_start += start_delta;
		old_end -= end_delta;

		if(submap_entry->is_sub_map) {
			entry = submap_entry;
			vaddr = local_vaddr;
			goto submap_recurse;
		}

		if(((fault_type & VM_PROT_WRITE) && cow_sub_map_parent)) {

			vm_object_t	sub_object, copy_object;
			vm_object_offset_t copy_offset;
			vm_map_offset_t	local_start;
			vm_map_offset_t	local_end;
			boolean_t		copied_slowly = FALSE;

			if (vm_map_lock_read_to_write(map)) {
				vm_map_lock_read(map);
				old_start -= start_delta;
				old_end += end_delta;
				goto RetrySubMap;
			}


			sub_object = submap_entry->object.vm_object;
			if (sub_object == VM_OBJECT_NULL) {
				sub_object =
					vm_object_allocate(
						(vm_map_size_t)
						(submap_entry->vme_end -
						 submap_entry->vme_start));
				submap_entry->object.vm_object = sub_object;
				submap_entry->offset = 0;
			}
			local_start =  local_vaddr - 
				(cow_parent_vaddr - old_start);
			local_end = local_vaddr + 
				(old_end - cow_parent_vaddr);
			vm_map_clip_start(map, submap_entry, local_start);
			vm_map_clip_end(map, submap_entry, local_end);
			/* unnesting was done in vm_map_clip_start/end() */
			assert(!submap_entry->use_pmap);

			/* This is the COW case, lets connect */
			/* an entry in our space to the underlying */
			/* object in the submap, bypassing the  */
			/* submap. */


			if(submap_entry->wired_count != 0 ||
			   (sub_object->copy_strategy ==
			    MEMORY_OBJECT_COPY_NONE)) {
				vm_object_lock(sub_object);
				vm_object_copy_slowly(sub_object,
						      submap_entry->offset,
						      (submap_entry->vme_end -
						       submap_entry->vme_start),
						      FALSE,
						      &copy_object);
				copied_slowly = TRUE;
			} else {
				
				/* set up shadow object */
				copy_object = sub_object;
				vm_object_reference(copy_object);
				sub_object->shadowed = TRUE;
				submap_entry->needs_copy = TRUE;

				prot = submap_entry->protection & ~VM_PROT_WRITE;

				if (override_nx(map, submap_entry->alias) && prot)
				        prot |= VM_PROT_EXECUTE;

				vm_object_pmap_protect(
					sub_object,
					submap_entry->offset,
					submap_entry->vme_end - 
					submap_entry->vme_start,
					(submap_entry->is_shared 
					 || map->mapped) ?
					PMAP_NULL : map->pmap,
					submap_entry->vme_start,
					prot);
			}
			
			/*
			 * Adjust the fault offset to the submap entry.
			 */
			copy_offset = (local_vaddr -
				       submap_entry->vme_start +
				       submap_entry->offset);

			/* This works diffently than the   */
			/* normal submap case. We go back  */
			/* to the parent of the cow map and*/
			/* clip out the target portion of  */
			/* the sub_map, substituting the   */
			/* new copy object,                */

			vm_map_unlock(map);
			local_start = old_start;
			local_end = old_end;
			map = cow_sub_map_parent;
			*var_map = cow_sub_map_parent;
			vaddr = cow_parent_vaddr;
			cow_sub_map_parent = NULL;

			if(!vm_map_lookup_entry(map, 
						vaddr, &entry)) {
				vm_object_deallocate(
					copy_object);
				vm_map_lock_write_to_read(map);
				return KERN_INVALID_ADDRESS;
			}
					
			/* clip out the portion of space */
			/* mapped by the sub map which   */
			/* corresponds to the underlying */
			/* object */

			/*
			 * Clip (and unnest) the smallest nested chunk
			 * possible around the faulting address...
			 */
			local_start = vaddr & ~(pmap_nesting_size_min - 1);
			local_end = local_start + pmap_nesting_size_min;
			/*
			 * ... but don't go beyond the "old_start" to "old_end"
			 * range, to avoid spanning over another VM region
			 * with a possibly different VM object and/or offset.
			 */
			if (local_start < old_start) {
				local_start = old_start;
			}
			if (local_end > old_end) {
				local_end = old_end;
			}
			/*
			 * Adjust copy_offset to the start of the range.
			 */
			copy_offset -= (vaddr - local_start);

			vm_map_clip_start(map, entry, local_start);
			vm_map_clip_end(map, entry, local_end);
			/* unnesting was done in vm_map_clip_start/end() */
			assert(!entry->use_pmap);

			/* substitute copy object for */
			/* shared map entry           */
			vm_map_deallocate(entry->object.sub_map);
			entry->is_sub_map = FALSE;
			entry->object.vm_object = copy_object;

			/* propagate the submap entry's protections */
			entry->protection |= submap_entry->protection;
			entry->max_protection |= submap_entry->max_protection;

			if(copied_slowly) {
				entry->offset = local_start - old_start;
				entry->needs_copy = FALSE;
				entry->is_shared = FALSE;
			} else {
				entry->offset = copy_offset;
				entry->needs_copy = TRUE;
				if(entry->inheritance == VM_INHERIT_SHARE) 
					entry->inheritance = VM_INHERIT_COPY;
				if (map != old_map)
					entry->is_shared = TRUE;
			}
			if(entry->inheritance == VM_INHERIT_SHARE) 
				entry->inheritance = VM_INHERIT_COPY;

			vm_map_lock_write_to_read(map);
		} else {
			if((cow_sub_map_parent)
			   && (cow_sub_map_parent != *real_map)
			   && (cow_sub_map_parent != map)) {
				vm_map_unlock(cow_sub_map_parent);
			}
			entry = submap_entry;
			vaddr = local_vaddr;
		}
	}
		
	/*
	 *	Check whether this task is allowed to have
	 *	this page.
	 */

	prot = entry->protection;

	if (override_nx(map, entry->alias) && prot) {
	        /*
		 * HACK -- if not a stack, then allow execution
		 */
	        prot |= VM_PROT_EXECUTE;
	}

	if (mask_protections) {
		fault_type &= prot;
		if (fault_type == VM_PROT_NONE) {
			goto protection_failure;
		}
	}
	if ((fault_type & (prot)) != fault_type) {
	protection_failure:
		if (*real_map != map) {
			vm_map_unlock(*real_map);
		}
		*real_map = map;

		if ((fault_type & VM_PROT_EXECUTE) && prot)
		        log_stack_execution_failure((addr64_t)vaddr, prot);

		DTRACE_VM2(prot_fault, int, 1, (uint64_t *), NULL);
		return KERN_PROTECTION_FAILURE;
	}

	/*
	 *	If this page is not pageable, we have to get
	 *	it for all possible accesses.
	 */

	*wired = (entry->wired_count != 0);
	if (*wired)
	        fault_type = prot;

	/*
	 *	If the entry was copy-on-write, we either ...
	 */

	if (entry->needs_copy) {
	    	/*
		 *	If we want to write the page, we may as well
		 *	handle that now since we've got the map locked.
		 *
		 *	If we don't need to write the page, we just
		 *	demote the permissions allowed.
		 */

		if ((fault_type & VM_PROT_WRITE) || *wired) {
			/*
			 *	Make a new object, and place it in the
			 *	object chain.  Note that no new references
			 *	have appeared -- one just moved from the
			 *	map to the new object.
			 */

			if (vm_map_lock_read_to_write(map)) {
				vm_map_lock_read(map);
				goto RetryLookup;
			}
			vm_object_shadow(&entry->object.vm_object,
					 &entry->offset,
					 (vm_map_size_t) (entry->vme_end -
							  entry->vme_start));

			entry->object.vm_object->shadowed = TRUE;
			entry->needs_copy = FALSE;
			vm_map_lock_write_to_read(map);
		}
		else {
			/*
			 *	We're attempting to read a copy-on-write
			 *	page -- don't allow writes.
			 */

			prot &= (~VM_PROT_WRITE);
		}
	}

	/*
	 *	Create an object if necessary.
	 */
	if (entry->object.vm_object == VM_OBJECT_NULL) {

		if (vm_map_lock_read_to_write(map)) {
			vm_map_lock_read(map);
			goto RetryLookup;
		}

		entry->object.vm_object = vm_object_allocate(
			(vm_map_size_t)(entry->vme_end - entry->vme_start));
		entry->offset = 0;
		vm_map_lock_write_to_read(map);
	}

	/*
	 *	Return the object/offset from this entry.  If the entry
	 *	was copy-on-write or empty, it has been fixed up.  Also
	 *	return the protection.
	 */

        *offset = (vaddr - entry->vme_start) + entry->offset;
        *object = entry->object.vm_object;
	*out_prot = prot;

	if (fault_info) {
		fault_info->interruptible = THREAD_UNINT; /* for now... */
		/* ... the caller will change "interruptible" if needed */
	        fault_info->cluster_size = 0;
		fault_info->user_tag = entry->alias;
	        fault_info->behavior = entry->behavior;
		fault_info->lo_offset = entry->offset;
		fault_info->hi_offset = (entry->vme_end - entry->vme_start) + entry->offset;
		fault_info->no_cache  = entry->no_cache;
		fault_info->stealth = FALSE;
		fault_info->io_sync = FALSE;
		fault_info->cs_bypass = (entry->used_for_jit)? TRUE : FALSE;
		fault_info->mark_zf_absent = FALSE;
	}

	/*
	 *	Lock the object to prevent it from disappearing
	 */
	if (object_lock_type == OBJECT_LOCK_EXCLUSIVE)
	        vm_object_lock(*object);
	else
	        vm_object_lock_shared(*object);
	
	/*
	 *	Save the version number
	 */

	out_version->main_timestamp = map->timestamp;

	return KERN_SUCCESS;
}


/*
 *	vm_map_verify:
 *
 *	Verifies that the map in question has not changed
 *	since the given version.  If successful, the map
 *	will not change until vm_map_verify_done() is called.
 */
boolean_t
vm_map_verify(
	register vm_map_t		map,
	register vm_map_version_t	*version)	/* REF */
{
	boolean_t	result;

	vm_map_lock_read(map);
	result = (map->timestamp == version->main_timestamp);

	if (!result)
		vm_map_unlock_read(map);

	return(result);
}

/*
 *	vm_map_verify_done:
 *
 *	Releases locks acquired by a vm_map_verify.
 *
 *	This is now a macro in vm/vm_map.h.  It does a
 *	vm_map_unlock_read on the map.
 */


/*
 *	TEMPORARYTEMPORARYTEMPORARYTEMPORARYTEMPORARYTEMPORARY
 *	Goes away after regular vm_region_recurse function migrates to
 *	64 bits
 *	vm_region_recurse: A form of vm_region which follows the
 *	submaps in a target map
 *
 */

kern_return_t
vm_map_region_recurse_64(
	vm_map_t		 map,
	vm_map_offset_t	*address,		/* IN/OUT */
	vm_map_size_t		*size,			/* OUT */
	natural_t	 	*nesting_depth,	/* IN/OUT */
	vm_region_submap_info_64_t	submap_info,	/* IN/OUT */
	mach_msg_type_number_t	*count)	/* IN/OUT */
{
	vm_region_extended_info_data_t	extended;
	vm_map_entry_t			tmp_entry;
	vm_map_offset_t			user_address;
	unsigned int			user_max_depth;

	/*
	 * "curr_entry" is the VM map entry preceding or including the
	 * address we're looking for.
	 * "curr_map" is the map or sub-map containing "curr_entry".
	 * "curr_address" is the equivalent of the top map's "user_address" 
	 * in the current map.
	 * "curr_offset" is the cumulated offset of "curr_map" in the
	 * target task's address space.
	 * "curr_depth" is the depth of "curr_map" in the chain of
	 * sub-maps.
	 * 
	 * "curr_max_below" and "curr_max_above" limit the range (around
	 * "curr_address") we should take into account in the current (sub)map.
	 * They limit the range to what's visible through the map entries
	 * we've traversed from the top map to the current map.

	 */
	vm_map_entry_t			curr_entry;
	vm_map_address_t		curr_address;
	vm_map_offset_t			curr_offset;
	vm_map_t			curr_map;
	unsigned int			curr_depth;
	vm_map_offset_t			curr_max_below, curr_max_above;
	vm_map_offset_t			curr_skip;

	/*
	 * "next_" is the same as "curr_" but for the VM region immediately
	 * after the address we're looking for.  We need to keep track of this
	 * too because we want to return info about that region if the
	 * address we're looking for is not mapped.
	 */
	vm_map_entry_t			next_entry;
	vm_map_offset_t			next_offset;
	vm_map_offset_t			next_address;
	vm_map_t			next_map;
	unsigned int			next_depth;
	vm_map_offset_t			next_max_below, next_max_above;
	vm_map_offset_t			next_skip;

	boolean_t			look_for_pages;
	vm_region_submap_short_info_64_t short_info;

	if (map == VM_MAP_NULL) {
		/* no address space to work on */
		return KERN_INVALID_ARGUMENT;
	}

	if (*count < VM_REGION_SUBMAP_INFO_COUNT_64) {
		if (*count < VM_REGION_SUBMAP_SHORT_INFO_COUNT_64) {
			/*
			 * "info" structure is not big enough and
			 * would overflow
			 */
			return KERN_INVALID_ARGUMENT;
		} else {
			look_for_pages = FALSE;
			*count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
			short_info = (vm_region_submap_short_info_64_t) submap_info;
			submap_info = NULL;
		}
	} else {
		look_for_pages = TRUE;
		*count = VM_REGION_SUBMAP_INFO_COUNT_64;
		short_info = NULL;
	}


	user_address = *address;
	user_max_depth = *nesting_depth;
	
	curr_entry = NULL;
	curr_map = map;
	curr_address = user_address;
	curr_offset = 0;
	curr_skip = 0;
	curr_depth = 0;
	curr_max_above = ((vm_map_offset_t) -1) - curr_address;
	curr_max_below = curr_address;

	next_entry = NULL;
	next_map = NULL;
	next_address = 0;
	next_offset = 0;
	next_skip = 0;
	next_depth = 0;
	next_max_above = (vm_map_offset_t) -1;
	next_max_below = (vm_map_offset_t) -1;

	if (not_in_kdp) {
		vm_map_lock_read(curr_map);
	}

	for (;;) {
		if (vm_map_lookup_entry(curr_map,
					curr_address,
					&tmp_entry)) {
			/* tmp_entry contains the address we're looking for */
			curr_entry = tmp_entry;
		} else {
			vm_map_offset_t skip;
			/*
			 * The address is not mapped.  "tmp_entry" is the
			 * map entry preceding the address.  We want the next
			 * one, if it exists.
			 */
			curr_entry = tmp_entry->vme_next;

			if (curr_entry == vm_map_to_entry(curr_map) ||
			    (curr_entry->vme_start >=
			     curr_address + curr_max_above)) {
				/* no next entry at this level: stop looking */
				if (not_in_kdp) {
					vm_map_unlock_read(curr_map);
				}
				curr_entry = NULL;
				curr_map = NULL;
				curr_offset = 0;
				curr_depth = 0;
				curr_max_above = 0;
				curr_max_below = 0;
				break;
			}

			/* adjust current address and offset */
			skip = curr_entry->vme_start - curr_address;
			curr_address = curr_entry->vme_start;
			curr_skip = skip;
			curr_offset += skip;
			curr_max_above -= skip;
			curr_max_below = 0;
		}

		/*
		 * Is the next entry at this level closer to the address (or
		 * deeper in the submap chain) than the one we had
		 * so far ?
		 */
		tmp_entry = curr_entry->vme_next;
		if (tmp_entry == vm_map_to_entry(curr_map)) {
			/* no next entry at this level */
		} else if (tmp_entry->vme_start >=
			   curr_address + curr_max_above) {
			/*
			 * tmp_entry is beyond the scope of what we mapped of
			 * this submap in the upper level: ignore it.
			 */
		} else if ((next_entry == NULL) ||
			   (tmp_entry->vme_start + curr_offset <=
			    next_entry->vme_start + next_offset)) {
			/*
			 * We didn't have a "next_entry" or this one is
			 * closer to the address we're looking for:
			 * use this "tmp_entry" as the new "next_entry".
			 */
			if (next_entry != NULL) {
				/* unlock the last "next_map" */
				if (next_map != curr_map && not_in_kdp) {
					vm_map_unlock_read(next_map);
				}
			}
			next_entry = tmp_entry;
			next_map = curr_map;
			next_depth = curr_depth;
			next_address = next_entry->vme_start;
			next_skip = curr_skip;
			next_offset = curr_offset;
			next_offset += (next_address - curr_address);
			next_max_above = MIN(next_max_above, curr_max_above);
			next_max_above = MIN(next_max_above,
					     next_entry->vme_end - next_address);
			next_max_below = MIN(next_max_below, curr_max_below);
			next_max_below = MIN(next_max_below,
					     next_address - next_entry->vme_start);
		}

		/*
		 * "curr_max_{above,below}" allow us to keep track of the
		 * portion of the submap that is actually mapped at this level:
		 * the rest of that submap is irrelevant to us, since it's not
		 * mapped here.
		 * The relevant portion of the map starts at
		 * "curr_entry->offset" up to the size of "curr_entry".
		 */
		curr_max_above = MIN(curr_max_above,
				     curr_entry->vme_end - curr_address);
		curr_max_below = MIN(curr_max_below,
				     curr_address - curr_entry->vme_start);

		if (!curr_entry->is_sub_map ||
		    curr_depth >= user_max_depth) {
			/*
			 * We hit a leaf map or we reached the maximum depth
			 * we could, so stop looking.  Keep the current map
			 * locked.
			 */
			break;
		}

		/*
		 * Get down to the next submap level.
		 */

		/*
		 * Lock the next level and unlock the current level,
		 * unless we need to keep it locked to access the "next_entry"
		 * later.
		 */
		if (not_in_kdp) {
			vm_map_lock_read(curr_entry->object.sub_map);
		}
		if (curr_map == next_map) {
			/* keep "next_map" locked in case we need it */
		} else {
			/* release this map */
			if (not_in_kdp)
				vm_map_unlock_read(curr_map);
		}

		/*
		 * Adjust the offset.  "curr_entry" maps the submap
		 * at relative address "curr_entry->vme_start" in the
		 * curr_map but skips the first "curr_entry->offset"
		 * bytes of the submap.
		 * "curr_offset" always represents the offset of a virtual
		 * address in the curr_map relative to the absolute address
		 * space (i.e. the top-level VM map).
		 */
		curr_offset +=
			(curr_entry->offset - curr_entry->vme_start);
		curr_address = user_address + curr_offset;
		/* switch to the submap */
		curr_map = curr_entry->object.sub_map;
		curr_depth++;
		curr_entry = NULL;
	}

	if (curr_entry == NULL) {
		/* no VM region contains the address... */
		if (next_entry == NULL) {
			/* ... and no VM region follows it either */
			return KERN_INVALID_ADDRESS;
		}
		/* ... gather info about the next VM region */
		curr_entry = next_entry;
		curr_map = next_map;	/* still locked ... */
		curr_address = next_address;
		curr_skip = next_skip;
		curr_offset = next_offset;
		curr_depth = next_depth;
		curr_max_above = next_max_above;
		curr_max_below = next_max_below;
		if (curr_map == map) {
			user_address = curr_address;
		}
	} else {
		/* we won't need "next_entry" after all */
		if (next_entry != NULL) {
			/* release "next_map" */
			if (next_map != curr_map && not_in_kdp) {
				vm_map_unlock_read(next_map);
			}
		}
	}
	next_entry = NULL;
	next_map = NULL;
	next_offset = 0;
	next_skip = 0;
	next_depth = 0;
	next_max_below = -1;
	next_max_above = -1;

	*nesting_depth = curr_depth;
	*size = curr_max_above + curr_max_below;
	*address = user_address + curr_skip - curr_max_below;

// LP64todo: all the current tools are 32bit, obviously never worked for 64b
// so probably should be a real 32b ID vs. ptr.
// Current users just check for equality
#define INFO_MAKE_OBJECT_ID(p)	((uint32_t)(uintptr_t)p)

	if (look_for_pages) {
		submap_info->user_tag = curr_entry->alias;
		submap_info->offset = curr_entry->offset; 
		submap_info->protection = curr_entry->protection;
		submap_info->inheritance = curr_entry->inheritance;
		submap_info->max_protection = curr_entry->max_protection;
		submap_info->behavior = curr_entry->behavior;
		submap_info->user_wired_count = curr_entry->user_wired_count;
		submap_info->is_submap = curr_entry->is_sub_map;
		submap_info->object_id = INFO_MAKE_OBJECT_ID(curr_entry->object.vm_object);
	} else {
		short_info->user_tag = curr_entry->alias;
		short_info->offset = curr_entry->offset; 
		short_info->protection = curr_entry->protection;
		short_info->inheritance = curr_entry->inheritance;
		short_info->max_protection = curr_entry->max_protection;
		short_info->behavior = curr_entry->behavior;
		short_info->user_wired_count = curr_entry->user_wired_count;
		short_info->is_submap = curr_entry->is_sub_map;
		short_info->object_id = INFO_MAKE_OBJECT_ID(curr_entry->object.vm_object);
	}

	extended.pages_resident = 0;
	extended.pages_swapped_out = 0;
	extended.pages_shared_now_private = 0;
	extended.pages_dirtied = 0;
	extended.external_pager = 0;
	extended.shadow_depth = 0;

	if (not_in_kdp) {
		if (!curr_entry->is_sub_map) {
			vm_map_offset_t range_start, range_end;
			range_start = MAX((curr_address - curr_max_below),
					  curr_entry->vme_start);
			range_end = MIN((curr_address + curr_max_above),
					curr_entry->vme_end);
			vm_map_region_walk(curr_map,
					   range_start,
					   curr_entry,
					   (curr_entry->offset +
					    (range_start -
					     curr_entry->vme_start)),
					   range_end - range_start,
					   &extended,
					   look_for_pages);
			if (extended.external_pager &&
			    extended.ref_count == 2 &&
			    extended.share_mode == SM_SHARED) {
				extended.share_mode = SM_PRIVATE;
			}
		} else {
			if (curr_entry->use_pmap) {
				extended.share_mode = SM_TRUESHARED;
			} else {
				extended.share_mode = SM_PRIVATE;
			}
			extended.ref_count =
				curr_entry->object.sub_map->ref_count;
		}
	}

	if (look_for_pages) {
		submap_info->pages_resident = extended.pages_resident;
		submap_info->pages_swapped_out = extended.pages_swapped_out;
		submap_info->pages_shared_now_private =
			extended.pages_shared_now_private;
		submap_info->pages_dirtied = extended.pages_dirtied;
		submap_info->external_pager = extended.external_pager;
		submap_info->shadow_depth = extended.shadow_depth;
		submap_info->share_mode = extended.share_mode;
		submap_info->ref_count = extended.ref_count;
	} else {
		short_info->external_pager = extended.external_pager;
		short_info->shadow_depth = extended.shadow_depth;
		short_info->share_mode = extended.share_mode;
		short_info->ref_count = extended.ref_count;
	}

	if (not_in_kdp) {
		vm_map_unlock_read(curr_map);
	}

	return KERN_SUCCESS;
}

/*
 *	vm_region:
 *
 *	User call to obtain information about a region in
 *	a task's address map. Currently, only one flavor is
 *	supported.
 *
 *	XXX The reserved and behavior fields cannot be filled
 *	    in until the vm merge from the IK is completed, and
 *	    vm_reserve is implemented.
 */

kern_return_t
vm_map_region(
	vm_map_t		 map,
	vm_map_offset_t	*address,		/* IN/OUT */
	vm_map_size_t		*size,			/* OUT */
	vm_region_flavor_t	 flavor,		/* IN */
	vm_region_info_t	 info,			/* OUT */
	mach_msg_type_number_t	*count,	/* IN/OUT */
	mach_port_t		*object_name)		/* OUT */
{
	vm_map_entry_t		tmp_entry;
	vm_map_entry_t		entry;
	vm_map_offset_t		start;

	if (map == VM_MAP_NULL) 
		return(KERN_INVALID_ARGUMENT);

	switch (flavor) {

	case VM_REGION_BASIC_INFO:
		/* legacy for old 32-bit objects info */
	{
		vm_region_basic_info_t	basic;

		if (*count < VM_REGION_BASIC_INFO_COUNT)
			return(KERN_INVALID_ARGUMENT);

		basic = (vm_region_basic_info_t) info;
		*count = VM_REGION_BASIC_INFO_COUNT;

		vm_map_lock_read(map);

		start = *address;
		if (!vm_map_lookup_entry(map, start, &tmp_entry)) {
			if ((entry = tmp_entry->vme_next) == vm_map_to_entry(map)) {
				vm_map_unlock_read(map);
				return(KERN_INVALID_ADDRESS);
			}
		} else {
			entry = tmp_entry;
		}

		start = entry->vme_start;

		basic->offset = (uint32_t)entry->offset;
		basic->protection = entry->protection;
		basic->inheritance = entry->inheritance;
		basic->max_protection = entry->max_protection;
		basic->behavior = entry->behavior;
		basic->user_wired_count = entry->user_wired_count;
		basic->reserved = entry->is_sub_map;
		*address = start;
		*size = (entry->vme_end - start);

		if (object_name) *object_name = IP_NULL;
		if (entry->is_sub_map) {
			basic->shared = FALSE;
		} else {
			basic->shared = entry->is_shared;
		}

		vm_map_unlock_read(map);
		return(KERN_SUCCESS);
	}

	case VM_REGION_BASIC_INFO_64:
	{
		vm_region_basic_info_64_t	basic;

		if (*count < VM_REGION_BASIC_INFO_COUNT_64)
			return(KERN_INVALID_ARGUMENT);

		basic = (vm_region_basic_info_64_t) info;
		*count = VM_REGION_BASIC_INFO_COUNT_64;

		vm_map_lock_read(map);

		start = *address;
		if (!vm_map_lookup_entry(map, start, &tmp_entry)) {
			if ((entry = tmp_entry->vme_next) == vm_map_to_entry(map)) {
				vm_map_unlock_read(map);
				return(KERN_INVALID_ADDRESS);
			}
		} else {
			entry = tmp_entry;
		}

		start = entry->vme_start;

		basic->offset = entry->offset;
		basic->protection = entry->protection;
		basic->inheritance = entry->inheritance;
		basic->max_protection = entry->max_protection;
		basic->behavior = entry->behavior;
		basic->user_wired_count = entry->user_wired_count;
		basic->reserved = entry->is_sub_map;
		*address = start;
		*size = (entry->vme_end - start);

		if (object_name) *object_name = IP_NULL;
		if (entry->is_sub_map) {
			basic->shared = FALSE;
		} else {
			basic->shared = entry->is_shared;
		}

		vm_map_unlock_read(map);
		return(KERN_SUCCESS);
	}
	case VM_REGION_EXTENDED_INFO:
	{
		vm_region_extended_info_t	extended;

		if (*count < VM_REGION_EXTENDED_INFO_COUNT)
			return(KERN_INVALID_ARGUMENT);

		extended = (vm_region_extended_info_t) info;
		*count = VM_REGION_EXTENDED_INFO_COUNT;

		vm_map_lock_read(map);

		start = *address;
		if (!vm_map_lookup_entry(map, start, &tmp_entry)) {
			if ((entry = tmp_entry->vme_next) == vm_map_to_entry(map)) {
				vm_map_unlock_read(map);
				return(KERN_INVALID_ADDRESS);
			}
		} else {
			entry = tmp_entry;
		}
		start = entry->vme_start;

		extended->protection = entry->protection;
		extended->user_tag = entry->alias;
		extended->pages_resident = 0;
		extended->pages_swapped_out = 0;
		extended->pages_shared_now_private = 0;
		extended->pages_dirtied = 0;
		extended->external_pager = 0;
		extended->shadow_depth = 0;

		vm_map_region_walk(map, start, entry, entry->offset, entry->vme_end - start, extended, TRUE);

		if (extended->external_pager && extended->ref_count == 2 && extended->share_mode == SM_SHARED)
			extended->share_mode = SM_PRIVATE;

		if (object_name)
			*object_name = IP_NULL;
		*address = start;
		*size = (entry->vme_end - start);

		vm_map_unlock_read(map);
		return(KERN_SUCCESS);
	}
	case VM_REGION_TOP_INFO:
	{   
		vm_region_top_info_t	top;

		if (*count < VM_REGION_TOP_INFO_COUNT)
			return(KERN_INVALID_ARGUMENT);

		top = (vm_region_top_info_t) info;
		*count = VM_REGION_TOP_INFO_COUNT;

		vm_map_lock_read(map);

		start = *address;
		if (!vm_map_lookup_entry(map, start, &tmp_entry)) {
			if ((entry = tmp_entry->vme_next) == vm_map_to_entry(map)) {
				vm_map_unlock_read(map);
				return(KERN_INVALID_ADDRESS);
			}
		} else {
			entry = tmp_entry;

		}
		start = entry->vme_start;

		top->private_pages_resident = 0;
		top->shared_pages_resident = 0;

		vm_map_region_top_walk(entry, top);

		if (object_name)
			*object_name = IP_NULL;
		*address = start;
		*size = (entry->vme_end - start);

		vm_map_unlock_read(map);
		return(KERN_SUCCESS);
	}
	default:
		return(KERN_INVALID_ARGUMENT);
	}
}

#define OBJ_RESIDENT_COUNT(obj, entry_size)				\
	MIN((entry_size),						\
	    ((obj)->all_reusable ?					\
	     (obj)->wired_page_count :					\
	     (obj)->resident_page_count - (obj)->reusable_page_count))

void
vm_map_region_top_walk(
        vm_map_entry_t		   entry,
	vm_region_top_info_t       top)
{

	if (entry->object.vm_object == 0 || entry->is_sub_map) {
		top->share_mode = SM_EMPTY;
		top->ref_count = 0;
		top->obj_id = 0;
		return;
	}

	{
	        struct	vm_object *obj, *tmp_obj;
		int		ref_count;
		uint32_t	entry_size;

		entry_size = (uint32_t) ((entry->vme_end - entry->vme_start) / PAGE_SIZE_64);

		obj = entry->object.vm_object;

		vm_object_lock(obj);

		if ((ref_count = obj->ref_count) > 1 && obj->paging_in_progress)
			ref_count--;

		assert(obj->reusable_page_count <= obj->resident_page_count);
		if (obj->shadow) {
			if (ref_count == 1)
				top->private_pages_resident =
					OBJ_RESIDENT_COUNT(obj, entry_size);
			else
				top->shared_pages_resident =
					OBJ_RESIDENT_COUNT(obj, entry_size);
			top->ref_count  = ref_count;
			top->share_mode = SM_COW;
	    
			while ((tmp_obj = obj->shadow)) {
				vm_object_lock(tmp_obj);
				vm_object_unlock(obj);
				obj = tmp_obj;

				if ((ref_count = obj->ref_count) > 1 && obj->paging_in_progress)
					ref_count--;

				assert(obj->reusable_page_count <= obj->resident_page_count);
				top->shared_pages_resident +=
					OBJ_RESIDENT_COUNT(obj, entry_size);
				top->ref_count += ref_count - 1;
			}
		} else {
			if (entry->superpage_size) {
				top->share_mode = SM_LARGE_PAGE;
				top->shared_pages_resident = 0;
				top->private_pages_resident = entry_size;
			} else if (entry->needs_copy) {
				top->share_mode = SM_COW;
				top->shared_pages_resident =
					OBJ_RESIDENT_COUNT(obj, entry_size);
			} else {
				if (ref_count == 1 ||
				    (ref_count == 2 && !(obj->pager_trusted) && !(obj->internal))) {
					top->share_mode = SM_PRIVATE;
					top->private_pages_resident =
						OBJ_RESIDENT_COUNT(obj,
								   entry_size);
				} else {
					top->share_mode = SM_SHARED;
					top->shared_pages_resident =
						OBJ_RESIDENT_COUNT(obj,
								  entry_size);
				}
			}
			top->ref_count = ref_count;
		}
		/* XXX K64: obj_id will be truncated */
		top->obj_id = (unsigned int) (uintptr_t)obj;

		vm_object_unlock(obj);
	}
}

void
vm_map_region_walk(
	vm_map_t		   	map,
	vm_map_offset_t			va,
	vm_map_entry_t			entry,
	vm_object_offset_t		offset,
	vm_object_size_t		range,
	vm_region_extended_info_t	extended,
	boolean_t			look_for_pages)
{
        register struct vm_object *obj, *tmp_obj;
	register vm_map_offset_t       last_offset;
	register int               i;
	register int               ref_count;
	struct vm_object	*shadow_object;
	int			shadow_depth;

	if ((entry->object.vm_object == 0) ||
	    (entry->is_sub_map) ||
	    (entry->object.vm_object->phys_contiguous &&
	     !entry->superpage_size)) {
		extended->share_mode = SM_EMPTY;
		extended->ref_count = 0;
		return;
	}

	if (entry->superpage_size) {
		extended->shadow_depth = 0;
		extended->share_mode = SM_LARGE_PAGE;
		extended->ref_count = 1;
		extended->external_pager = 0;
		extended->pages_resident = (unsigned int)(range >> PAGE_SHIFT);
		extended->shadow_depth = 0;
		return;
	}

	{
		obj = entry->object.vm_object;

		vm_object_lock(obj);

		if ((ref_count = obj->ref_count) > 1 && obj->paging_in_progress)
			ref_count--;

		if (look_for_pages) {
			for (last_offset = offset + range;
			     offset < last_offset;
			     offset += PAGE_SIZE_64, va += PAGE_SIZE)
				vm_map_region_look_for_page(map, va, obj,
							    offset, ref_count,
							    0, extended);
		} else {
			shadow_object = obj->shadow;
			shadow_depth = 0;

			if ( !(obj->pager_trusted) && !(obj->internal))
				extended->external_pager = 1;

			if (shadow_object != VM_OBJECT_NULL) {
				vm_object_lock(shadow_object);
				for (;
				     shadow_object != VM_OBJECT_NULL;
				     shadow_depth++) {
					vm_object_t	next_shadow;

					if ( !(shadow_object->pager_trusted) &&
					     !(shadow_object->internal))
						extended->external_pager = 1;

					next_shadow = shadow_object->shadow;
					if (next_shadow) {
						vm_object_lock(next_shadow);
					}
					vm_object_unlock(shadow_object);
					shadow_object = next_shadow;
				}
			}
			extended->shadow_depth = shadow_depth;
		}

		if (extended->shadow_depth || entry->needs_copy)
			extended->share_mode = SM_COW;
		else {
			if (ref_count == 1)
				extended->share_mode = SM_PRIVATE;
			else {
				if (obj->true_share)
					extended->share_mode = SM_TRUESHARED;
				else
					extended->share_mode = SM_SHARED;
			}
		}
		extended->ref_count = ref_count - extended->shadow_depth;
	    
		for (i = 0; i < extended->shadow_depth; i++) {
			if ((tmp_obj = obj->shadow) == 0)
				break;
			vm_object_lock(tmp_obj);
			vm_object_unlock(obj);

			if ((ref_count = tmp_obj->ref_count) > 1 && tmp_obj->paging_in_progress)
				ref_count--;

			extended->ref_count += ref_count;
			obj = tmp_obj;
		}
		vm_object_unlock(obj);

		if (extended->share_mode == SM_SHARED) {
			register vm_map_entry_t	     cur;
			register vm_map_entry_t	     last;
			int      my_refs;

			obj = entry->object.vm_object;
			last = vm_map_to_entry(map);
			my_refs = 0;

			if ((ref_count = obj->ref_count) > 1 && obj->paging_in_progress)
				ref_count--;
			for (cur = vm_map_first_entry(map); cur != last; cur = cur->vme_next)
				my_refs += vm_map_region_count_obj_refs(cur, obj);

			if (my_refs == ref_count)
				extended->share_mode = SM_PRIVATE_ALIASED;
			else if (my_refs > 1)
				extended->share_mode = SM_SHARED_ALIASED;
		}
	}
}


/* object is locked on entry and locked on return */


static void
vm_map_region_look_for_page(
	__unused vm_map_t		map,
	__unused vm_map_offset_t	va,
	vm_object_t			object,
	vm_object_offset_t		offset,
	int				max_refcnt,
	int				depth,
	vm_region_extended_info_t	extended)
{
        register vm_page_t	p;
        register vm_object_t	shadow;
	register int            ref_count;
	vm_object_t		caller_object;
#if	MACH_PAGEMAP
	kern_return_t		kr;
#endif
	shadow = object->shadow;
	caller_object = object;

	
	while (TRUE) {

		if ( !(object->pager_trusted) && !(object->internal))
			extended->external_pager = 1;

		if ((p = vm_page_lookup(object, offset)) != VM_PAGE_NULL) {
	        	if (shadow && (max_refcnt == 1))
		    		extended->pages_shared_now_private++;

			if (!p->fictitious && 
			    (p->dirty || pmap_is_modified(p->phys_page)))
		    		extended->pages_dirtied++;

	        	extended->pages_resident++;

			if(object != caller_object)
				vm_object_unlock(object);

			return;
		}
#if	MACH_PAGEMAP
		if (object->existence_map) {
	    		if (vm_external_state_get(object->existence_map, offset) == VM_EXTERNAL_STATE_EXISTS) {

	        		extended->pages_swapped_out++;

				if(object != caller_object)
					vm_object_unlock(object);

				return;
	    		}
		} else if (object->internal &&
			   object->alive &&
			   !object->terminating &&
			   object->pager_ready) {

			memory_object_t pager;

			vm_object_paging_begin(object);
			pager = object->pager;
			vm_object_unlock(object);

			kr = memory_object_data_request(
				pager,
				offset + object->paging_offset,
				0, /* just poke the pager */
				VM_PROT_READ,
				NULL);

			vm_object_lock(object);
			vm_object_paging_end(object);

			if (kr == KERN_SUCCESS) {
				/* the pager has that page */
				extended->pages_swapped_out++;
				if (object != caller_object)
					vm_object_unlock(object);
				return;
			}
		}
#endif /* MACH_PAGEMAP */

		if (shadow) {
			vm_object_lock(shadow);

			if ((ref_count = shadow->ref_count) > 1 && shadow->paging_in_progress)
			        ref_count--;

	    		if (++depth > extended->shadow_depth)
	        		extended->shadow_depth = depth;

	    		if (ref_count > max_refcnt)
	        		max_refcnt = ref_count;
			
			if(object != caller_object)
				vm_object_unlock(object);

			offset = offset + object->vo_shadow_offset;
			object = shadow;
			shadow = object->shadow;
			continue;
		}
		if(object != caller_object)
			vm_object_unlock(object);
		break;
	}
}

static int
vm_map_region_count_obj_refs(
        vm_map_entry_t    entry,
	vm_object_t       object)
{
        register int ref_count;
	register vm_object_t chk_obj;
	register vm_object_t tmp_obj;

	if (entry->object.vm_object == 0)
		return(0);

        if (entry->is_sub_map)
		return(0);
	else {
		ref_count = 0;

		chk_obj = entry->object.vm_object;
		vm_object_lock(chk_obj);

		while (chk_obj) {
			if (chk_obj == object)
				ref_count++;
			tmp_obj = chk_obj->shadow;
			if (tmp_obj)
				vm_object_lock(tmp_obj);
			vm_object_unlock(chk_obj);

			chk_obj = tmp_obj;
		}
	}
	return(ref_count);
}


/*
 *	Routine:	vm_map_simplify
 *
 *	Description:
 *		Attempt to simplify the map representation in
 *		the vicinity of the given starting address.
 *	Note:
 *		This routine is intended primarily to keep the
 *		kernel maps more compact -- they generally don't
 *		benefit from the "expand a map entry" technology
 *		at allocation time because the adjacent entry
 *		is often wired down.
 */
void
vm_map_simplify_entry(
	vm_map_t	map,
	vm_map_entry_t	this_entry)
{
	vm_map_entry_t	prev_entry;

	counter(c_vm_map_simplify_entry_called++);

	prev_entry = this_entry->vme_prev;

	if ((this_entry != vm_map_to_entry(map)) &&
	    (prev_entry != vm_map_to_entry(map)) &&

	    (prev_entry->vme_end == this_entry->vme_start) &&

	    (prev_entry->is_sub_map == this_entry->is_sub_map) &&

	    (prev_entry->object.vm_object == this_entry->object.vm_object) &&
	    ((prev_entry->offset + (prev_entry->vme_end -
				    prev_entry->vme_start))
	     == this_entry->offset) &&

	    (prev_entry->inheritance == this_entry->inheritance) &&
	    (prev_entry->protection == this_entry->protection) &&
	    (prev_entry->max_protection == this_entry->max_protection) &&
	    (prev_entry->behavior == this_entry->behavior) &&
	    (prev_entry->alias == this_entry->alias) &&
	    (prev_entry->zero_wired_pages == this_entry->zero_wired_pages) &&
	    (prev_entry->no_cache == this_entry->no_cache) &&
	    (prev_entry->wired_count == this_entry->wired_count) &&
	    (prev_entry->user_wired_count == this_entry->user_wired_count) &&

	    (prev_entry->needs_copy == this_entry->needs_copy) &&
	    (prev_entry->permanent == this_entry->permanent) &&

	    (prev_entry->use_pmap == FALSE) &&
	    (this_entry->use_pmap == FALSE) &&
	    (prev_entry->in_transition == FALSE) &&
	    (this_entry->in_transition == FALSE) &&
	    (prev_entry->needs_wakeup == FALSE) &&
	    (this_entry->needs_wakeup == FALSE) &&
	    (prev_entry->is_shared == FALSE) &&
	    (this_entry->is_shared == FALSE)
		) {
		_vm_map_store_entry_unlink(&map->hdr, prev_entry);
		this_entry->vme_start = prev_entry->vme_start;
		this_entry->offset = prev_entry->offset;
		if (prev_entry->is_sub_map) {
			vm_map_deallocate(prev_entry->object.sub_map);
		} else {
			vm_object_deallocate(prev_entry->object.vm_object);
		}
		vm_map_entry_dispose(map, prev_entry);
		SAVE_HINT_MAP_WRITE(map, this_entry);
		counter(c_vm_map_simplified++);
	}
}

void
vm_map_simplify(
	vm_map_t	map,
	vm_map_offset_t	start)
{
	vm_map_entry_t	this_entry;

	vm_map_lock(map);
	if (vm_map_lookup_entry(map, start, &this_entry)) {
		vm_map_simplify_entry(map, this_entry);
		vm_map_simplify_entry(map, this_entry->vme_next);
	}
	counter(c_vm_map_simplify_called++);
	vm_map_unlock(map);
}

static void
vm_map_simplify_range(
	vm_map_t	map,
	vm_map_offset_t	start,
	vm_map_offset_t	end)
{
	vm_map_entry_t	entry;

	/*
	 * The map should be locked (for "write") by the caller.
	 */

	if (start >= end) {
		/* invalid address range */
		return;
	}

	start = vm_map_trunc_page(start);
	end = vm_map_round_page(end);

	if (!vm_map_lookup_entry(map, start, &entry)) {
		/* "start" is not mapped and "entry" ends before "start" */
		if (entry == vm_map_to_entry(map)) {
			/* start with first entry in the map */
			entry = vm_map_first_entry(map);
		} else {
			/* start with next entry */
			entry = entry->vme_next;
		}
	}
		
	while (entry != vm_map_to_entry(map) &&
	       entry->vme_start <= end) {
		/* try and coalesce "entry" with its previous entry */
		vm_map_simplify_entry(map, entry);
		entry = entry->vme_next;
	}
}


/*
 *	Routine:	vm_map_machine_attribute
 *	Purpose:
 *		Provide machine-specific attributes to mappings,
 *		such as cachability etc. for machines that provide
 *		them.  NUMA architectures and machines with big/strange
 *		caches will use this.
 *	Note:
 *		Responsibilities for locking and checking are handled here,
 *		everything else in the pmap module. If any non-volatile
 *		information must be kept, the pmap module should handle
 *		it itself. [This assumes that attributes do not
 *		need to be inherited, which seems ok to me]
 */
kern_return_t
vm_map_machine_attribute(
	vm_map_t			map,
	vm_map_offset_t		start,
	vm_map_offset_t		end,
	vm_machine_attribute_t	attribute,
	vm_machine_attribute_val_t* value)		/* IN/OUT */
{
	kern_return_t	ret;
	vm_map_size_t sync_size;
	vm_map_entry_t entry;
	
	if (start < vm_map_min(map) || end > vm_map_max(map))
		return KERN_INVALID_ADDRESS;

	/* Figure how much memory we need to flush (in page increments) */
	sync_size = end - start;

	vm_map_lock(map);
	
	if (attribute != MATTR_CACHE) {	
		/* If we don't have to find physical addresses, we */
		/* don't have to do an explicit traversal here.    */
		ret = pmap_attribute(map->pmap, start, end-start,
				     attribute, value);
		vm_map_unlock(map);
		return ret;
	}

	ret = KERN_SUCCESS;										/* Assume it all worked */

	while(sync_size) {
		if (vm_map_lookup_entry(map, start, &entry)) {
			vm_map_size_t	sub_size;
			if((entry->vme_end - start) > sync_size) {
				sub_size = sync_size;
				sync_size = 0;
			} else {
				sub_size = entry->vme_end - start;
				sync_size -= sub_size;
			}
			if(entry->is_sub_map) {
				vm_map_offset_t sub_start;
				vm_map_offset_t sub_end;

				sub_start = (start - entry->vme_start) 
					+ entry->offset;
				sub_end = sub_start + sub_size;
				vm_map_machine_attribute(
					entry->object.sub_map, 
					sub_start,
					sub_end,
					attribute, value);
			} else {
				if(entry->object.vm_object) {
					vm_page_t		m;
					vm_object_t		object;
					vm_object_t		base_object;
					vm_object_t		last_object;
					vm_object_offset_t	offset;
					vm_object_offset_t	base_offset;
					vm_map_size_t		range;
					range = sub_size;
					offset = (start - entry->vme_start)
						+ entry->offset;
					base_offset = offset;
					object = entry->object.vm_object;
					base_object = object;
					last_object = NULL;

					vm_object_lock(object);

					while (range) {
						m = vm_page_lookup(
							object, offset);

						if (m && !m->fictitious) {
						        ret = 
								pmap_attribute_cache_sync(
									m->phys_page, 	
									PAGE_SIZE, 
									attribute, value);
							
						} else if (object->shadow) {
						        offset = offset + object->vo_shadow_offset;
							last_object = object;
							object = object->shadow;
							vm_object_lock(last_object->shadow);
							vm_object_unlock(last_object);
							continue;
						}
						range -= PAGE_SIZE;

						if (base_object != object) {
						        vm_object_unlock(object);
							vm_object_lock(base_object);
							object = base_object;
						}
						/* Bump to the next page */
						base_offset += PAGE_SIZE;
						offset = base_offset;
					}
					vm_object_unlock(object);
				}
			}
			start += sub_size;
		} else {
			vm_map_unlock(map);
			return KERN_FAILURE;
		}
		
	}

	vm_map_unlock(map);

	return ret;
}

/*
 *	vm_map_behavior_set:
 *
 *	Sets the paging reference behavior of the specified address
 *	range in the target map.  Paging reference behavior affects
 *	how pagein operations resulting from faults on the map will be 
 *	clustered.
 */
kern_return_t 
vm_map_behavior_set(
	vm_map_t	map,
	vm_map_offset_t	start,
	vm_map_offset_t	end,
	vm_behavior_t	new_behavior)
{
	register vm_map_entry_t	entry;
	vm_map_entry_t	temp_entry;

	XPR(XPR_VM_MAP,
	    "vm_map_behavior_set, 0x%X start 0x%X end 0x%X behavior %d",
	    map, start, end, new_behavior, 0);

	if (start > end ||
	    start < vm_map_min(map) ||
	    end > vm_map_max(map)) {
		return KERN_NO_SPACE;
	}

	switch (new_behavior) {

	/*
	 * This first block of behaviors all set a persistent state on the specified
	 * memory range.  All we have to do here is to record the desired behavior
	 * in the vm_map_entry_t's.
	 */

	case VM_BEHAVIOR_DEFAULT:
	case VM_BEHAVIOR_RANDOM:
	case VM_BEHAVIOR_SEQUENTIAL:
	case VM_BEHAVIOR_RSEQNTL:
	case VM_BEHAVIOR_ZERO_WIRED_PAGES:
		vm_map_lock(map);
	
		/*
		 *	The entire address range must be valid for the map.
		 * 	Note that vm_map_range_check() does a 
		 *	vm_map_lookup_entry() internally and returns the
		 *	entry containing the start of the address range if
		 *	the entire range is valid.
		 */
		if (vm_map_range_check(map, start, end, &temp_entry)) {
			entry = temp_entry;
			vm_map_clip_start(map, entry, start);
		}
		else {
			vm_map_unlock(map);
			return(KERN_INVALID_ADDRESS);
		}
	
		while ((entry != vm_map_to_entry(map)) && (entry->vme_start < end)) {
			vm_map_clip_end(map, entry, end);
			assert(!entry->use_pmap);
	
			if( new_behavior == VM_BEHAVIOR_ZERO_WIRED_PAGES ) {
				entry->zero_wired_pages = TRUE;
			} else {
				entry->behavior = new_behavior;
			}
			entry = entry->vme_next;
		}
	
		vm_map_unlock(map);
		break;

	/*
	 * The rest of these are different from the above in that they cause
	 * an immediate action to take place as opposed to setting a behavior that 
	 * affects future actions.
	 */

	case VM_BEHAVIOR_WILLNEED:
		return vm_map_willneed(map, start, end);

	case VM_BEHAVIOR_DONTNEED:
		return vm_map_msync(map, start, end - start, VM_SYNC_DEACTIVATE | VM_SYNC_CONTIGUOUS);

	case VM_BEHAVIOR_FREE:
		return vm_map_msync(map, start, end - start, VM_SYNC_KILLPAGES | VM_SYNC_CONTIGUOUS);

	case VM_BEHAVIOR_REUSABLE:
		return vm_map_reusable_pages(map, start, end);

	case VM_BEHAVIOR_REUSE:
		return vm_map_reuse_pages(map, start, end);

	case VM_BEHAVIOR_CAN_REUSE:
		return vm_map_can_reuse(map, start, end);

	default:
		return(KERN_INVALID_ARGUMENT);
	}

	return(KERN_SUCCESS);
}


/*
 * Internals for madvise(MADV_WILLNEED) system call.
 *
 * The present implementation is to do a read-ahead if the mapping corresponds
 * to a mapped regular file.  If it's an anonymous mapping, then we do nothing
 * and basically ignore the "advice" (which we are always free to do).
 */


static kern_return_t
vm_map_willneed(
	vm_map_t	map,
	vm_map_offset_t	start,
	vm_map_offset_t	end
)
{
	vm_map_entry_t 			entry;
	vm_object_t			object;
	memory_object_t			pager;
	struct vm_object_fault_info	fault_info;
	kern_return_t			kr;
	vm_object_size_t		len;
	vm_object_offset_t		offset;

	/*
	 * Fill in static values in fault_info.  Several fields get ignored by the code
	 * we call, but we'll fill them in anyway since uninitialized fields are bad
	 * when it comes to future backwards compatibility.
	 */

	fault_info.interruptible = THREAD_UNINT;		/* ignored value */
	fault_info.behavior      = VM_BEHAVIOR_SEQUENTIAL;
	fault_info.no_cache      = FALSE;			/* ignored value */
	fault_info.stealth	 = TRUE;
	fault_info.io_sync = FALSE;
	fault_info.cs_bypass = FALSE;
	fault_info.mark_zf_absent = FALSE;

	/*
	 * The MADV_WILLNEED operation doesn't require any changes to the
	 * vm_map_entry_t's, so the read lock is sufficient.
	 */

	vm_map_lock_read(map);

	/*
	 * The madvise semantics require that the address range be fully
	 * allocated with no holes.  Otherwise, we're required to return
	 * an error.
	 */

	if (! vm_map_range_check(map, start, end, &entry)) {
		vm_map_unlock_read(map);
		return KERN_INVALID_ADDRESS;
	}

	/*
	 * Examine each vm_map_entry_t in the range.
	 */
	for (; entry != vm_map_to_entry(map) && start < end; ) {
		
		/*
		 * The first time through, the start address could be anywhere
		 * within the vm_map_entry we found.  So adjust the offset to
		 * correspond.  After that, the offset will always be zero to
		 * correspond to the beginning of the current vm_map_entry.
		 */
		offset = (start - entry->vme_start) + entry->offset;

		/*
		 * Set the length so we don't go beyond the end of the
		 * map_entry or beyond the end of the range we were given.
		 * This range could span also multiple map entries all of which
		 * map different files, so make sure we only do the right amount
		 * of I/O for each object.  Note that it's possible for there
		 * to be multiple map entries all referring to the same object
		 * but with different page permissions, but it's not worth
		 * trying to optimize that case.
		 */
		len = MIN(entry->vme_end - start, end - start);

		if ((vm_size_t) len != len) {
			/* 32-bit overflow */
			len = (vm_size_t) (0 - PAGE_SIZE);
		}
		fault_info.cluster_size = (vm_size_t) len;
		fault_info.lo_offset    = offset; 
		fault_info.hi_offset    = offset + len;
		fault_info.user_tag     = entry->alias;

		/*
		 * If there's no read permission to this mapping, then just
		 * skip it.
		 */
		if ((entry->protection & VM_PROT_READ) == 0) {
			entry = entry->vme_next;
			start = entry->vme_start;
			continue;
		}

		/*
		 * Find the file object backing this map entry.  If there is
		 * none, then we simply ignore the "will need" advice for this
		 * entry and go on to the next one.
		 */
		if ((object = find_vnode_object(entry)) == VM_OBJECT_NULL) {
			entry = entry->vme_next;
			start = entry->vme_start;
			continue;
		}

		/*
		 * The data_request() could take a long time, so let's
		 * release the map lock to avoid blocking other threads.
		 */
		vm_map_unlock_read(map);

		vm_object_paging_begin(object);
		pager = object->pager;
		vm_object_unlock(object);

		/*
		 * Get the data from the object asynchronously.
		 *
		 * Note that memory_object_data_request() places limits on the
		 * amount of I/O it will do.  Regardless of the len we
		 * specified, it won't do more than MAX_UPL_TRANSFER and it
		 * silently truncates the len to that size.  This isn't
		 * necessarily bad since madvise shouldn't really be used to
		 * page in unlimited amounts of data.  Other Unix variants
		 * limit the willneed case as well.  If this turns out to be an
		 * issue for developers, then we can always adjust the policy
		 * here and still be backwards compatible since this is all
		 * just "advice".
		 */
		kr = memory_object_data_request(
			pager,
			offset + object->paging_offset,
			0,	/* ignored */
			VM_PROT_READ,
			(memory_object_fault_info_t)&fault_info);

		vm_object_lock(object);
		vm_object_paging_end(object);
		vm_object_unlock(object);

		/*
		 * If we couldn't do the I/O for some reason, just give up on
		 * the madvise.  We still return success to the user since
		 * madvise isn't supposed to fail when the advice can't be
		 * taken.
		 */
		if (kr != KERN_SUCCESS) {
			return KERN_SUCCESS;
		}

		start += len;
		if (start >= end) {
			/* done */
			return KERN_SUCCESS;
		}

		/* look up next entry */
		vm_map_lock_read(map);
		if (! vm_map_lookup_entry(map, start, &entry)) {
			/*
			 * There's a new hole in the address range.
			 */
			vm_map_unlock_read(map);
			return KERN_INVALID_ADDRESS;
		}
	}

	vm_map_unlock_read(map);
	return KERN_SUCCESS;
}

static boolean_t
vm_map_entry_is_reusable(
	vm_map_entry_t entry)
{
	vm_object_t object;

	if (entry->is_shared ||
	    entry->is_sub_map ||
	    entry->in_transition ||
	    entry->protection != VM_PROT_DEFAULT ||
	    entry->max_protection != VM_PROT_ALL ||
	    entry->inheritance != VM_INHERIT_DEFAULT ||
	    entry->no_cache ||
	    entry->permanent ||
	    entry->superpage_size != 0 ||
	    entry->zero_wired_pages ||
	    entry->wired_count != 0 ||
	    entry->user_wired_count != 0) {
		return FALSE;
	}

	object = entry->object.vm_object;
	if (object == VM_OBJECT_NULL) {
		return TRUE;
	}
	if (object->ref_count == 1 &&
	    object->wired_page_count == 0 &&
	    object->copy == VM_OBJECT_NULL &&
	    object->shadow == VM_OBJECT_NULL &&
	    object->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC &&
	    object->internal &&
	    !object->true_share &&
	    object->wimg_bits == VM_WIMG_USE_DEFAULT &&
	    !object->code_signed) {
		return TRUE;
	}
	return FALSE;
	    
	    
}

static kern_return_t
vm_map_reuse_pages(
	vm_map_t	map,
	vm_map_offset_t	start,
	vm_map_offset_t	end)
{
	vm_map_entry_t 			entry;
	vm_object_t			object;
	vm_object_offset_t		start_offset, end_offset;

	/*
	 * The MADV_REUSE operation doesn't require any changes to the
	 * vm_map_entry_t's, so the read lock is sufficient.
	 */

	vm_map_lock_read(map);

	/*
	 * The madvise semantics require that the address range be fully
	 * allocated with no holes.  Otherwise, we're required to return
	 * an error.
	 */

	if (!vm_map_range_check(map, start, end, &entry)) {
		vm_map_unlock_read(map);
		vm_page_stats_reusable.reuse_pages_failure++;
		return KERN_INVALID_ADDRESS;
	}

	/*
	 * Examine each vm_map_entry_t in the range.
	 */
	for (; entry != vm_map_to_entry(map) && entry->vme_start < end;
	     entry = entry->vme_next) {
		/*
		 * Sanity check on the VM map entry.
		 */
		if (! vm_map_entry_is_reusable(entry)) {
			vm_map_unlock_read(map);
			vm_page_stats_reusable.reuse_pages_failure++;
			return KERN_INVALID_ADDRESS;
		}

		/*
		 * The first time through, the start address could be anywhere
		 * within the vm_map_entry we found.  So adjust the offset to
		 * correspond.
		 */
		if (entry->vme_start < start) {
			start_offset = start - entry->vme_start;
		} else {
			start_offset = 0;
		}
		end_offset = MIN(end, entry->vme_end) - entry->vme_start;
		start_offset += entry->offset;
		end_offset += entry->offset;

		object = entry->object.vm_object;
		if (object != VM_OBJECT_NULL) {
			vm_object_lock(object);
			vm_object_reuse_pages(object, start_offset, end_offset,
					      TRUE);
			vm_object_unlock(object);
		}

		if (entry->alias == VM_MEMORY_MALLOC_LARGE_REUSABLE) {
			/*
			 * XXX
			 * We do not hold the VM map exclusively here.
			 * The "alias" field is not that critical, so it's
			 * safe to update it here, as long as it is the only
			 * one that can be modified while holding the VM map
			 * "shared".
			 */
			entry->alias = VM_MEMORY_MALLOC_LARGE_REUSED;
		}
	}
	
	vm_map_unlock_read(map);
	vm_page_stats_reusable.reuse_pages_success++;
	return KERN_SUCCESS;
}


static kern_return_t
vm_map_reusable_pages(
	vm_map_t	map,
	vm_map_offset_t	start,
	vm_map_offset_t	end)
{
	vm_map_entry_t 			entry;
	vm_object_t			object;
	vm_object_offset_t		start_offset, end_offset;

	/*
	 * The MADV_REUSABLE operation doesn't require any changes to the
	 * vm_map_entry_t's, so the read lock is sufficient.
	 */

	vm_map_lock_read(map);

	/*
	 * The madvise semantics require that the address range be fully
	 * allocated with no holes.  Otherwise, we're required to return
	 * an error.
	 */

	if (!vm_map_range_check(map, start, end, &entry)) {
		vm_map_unlock_read(map);
		vm_page_stats_reusable.reusable_pages_failure++;
		return KERN_INVALID_ADDRESS;
	}

	/*
	 * Examine each vm_map_entry_t in the range.
	 */
	for (; entry != vm_map_to_entry(map) && entry->vme_start < end;
	     entry = entry->vme_next) {
		int kill_pages = 0;

		/*
		 * Sanity check on the VM map entry.
		 */
		if (! vm_map_entry_is_reusable(entry)) {
			vm_map_unlock_read(map);
			vm_page_stats_reusable.reusable_pages_failure++;
			return KERN_INVALID_ADDRESS;
		}

		/*
		 * The first time through, the start address could be anywhere
		 * within the vm_map_entry we found.  So adjust the offset to
		 * correspond.
		 */
		if (entry->vme_start < start) {
			start_offset = start - entry->vme_start;
		} else {
			start_offset = 0;
		}
		end_offset = MIN(end, entry->vme_end) - entry->vme_start;
		start_offset += entry->offset;
		end_offset += entry->offset;

		object = entry->object.vm_object;
		if (object == VM_OBJECT_NULL)
			continue;


		vm_object_lock(object);
		if (object->ref_count == 1 && !object->shadow)
			kill_pages = 1;
		else
			kill_pages = -1;
		if (kill_pages != -1) {
			vm_object_deactivate_pages(object,
						   start_offset,
						   end_offset - start_offset,
						   kill_pages,
						   TRUE /*reusable_pages*/);
		} else {
			vm_page_stats_reusable.reusable_pages_shared++;
		}
		vm_object_unlock(object);

		if (entry->alias == VM_MEMORY_MALLOC_LARGE ||
		    entry->alias == VM_MEMORY_MALLOC_LARGE_REUSED) {
			/*
			 * XXX
			 * We do not hold the VM map exclusively here.
			 * The "alias" field is not that critical, so it's
			 * safe to update it here, as long as it is the only
			 * one that can be modified while holding the VM map
			 * "shared".
			 */
			entry->alias = VM_MEMORY_MALLOC_LARGE_REUSABLE;
		}
	}
	
	vm_map_unlock_read(map);
	vm_page_stats_reusable.reusable_pages_success++;
	return KERN_SUCCESS;
}


static kern_return_t
vm_map_can_reuse(
	vm_map_t	map,
	vm_map_offset_t	start,
	vm_map_offset_t	end)
{
	vm_map_entry_t 			entry;

	/*
	 * The MADV_REUSABLE operation doesn't require any changes to the
	 * vm_map_entry_t's, so the read lock is sufficient.
	 */

	vm_map_lock_read(map);

	/*
	 * The madvise semantics require that the address range be fully
	 * allocated with no holes.  Otherwise, we're required to return
	 * an error.
	 */

	if (!vm_map_range_check(map, start, end, &entry)) {
		vm_map_unlock_read(map);
		vm_page_stats_reusable.can_reuse_failure++;
		return KERN_INVALID_ADDRESS;
	}

	/*
	 * Examine each vm_map_entry_t in the range.
	 */
	for (; entry != vm_map_to_entry(map) && entry->vme_start < end;
	     entry = entry->vme_next) {
		/*
		 * Sanity check on the VM map entry.
		 */
		if (! vm_map_entry_is_reusable(entry)) {
			vm_map_unlock_read(map);
			vm_page_stats_reusable.can_reuse_failure++;
			return KERN_INVALID_ADDRESS;
		}
	}
	
	vm_map_unlock_read(map);
	vm_page_stats_reusable.can_reuse_success++;
	return KERN_SUCCESS;
}



#include <mach_kdb.h>
#if	MACH_KDB
#include <ddb/db_output.h>
#include <vm/vm_print.h>

#define	printf	db_printf

/*
 * Forward declarations for internal functions.
 */
extern void vm_map_links_print(
	struct vm_map_links	*links);

extern void vm_map_header_print(
	struct vm_map_header	*header);

extern void vm_map_entry_print(
	vm_map_entry_t		entry);

extern void vm_follow_entry(
	vm_map_entry_t		entry);

extern void vm_follow_map(
	vm_map_t		map);

/*
 *	vm_map_links_print:	[ debug ]
 */
void
vm_map_links_print(
	struct vm_map_links	*links)
{
	iprintf("prev = %08X  next = %08X  start = %016llX  end = %016llX\n",
		links->prev,
		links->next,
		(unsigned long long)links->start,
		(unsigned long long)links->end);
}

/*
 *	vm_map_header_print:	[ debug ]
 */
void
vm_map_header_print(
	struct vm_map_header	*header)
{
	vm_map_links_print(&header->links);
	iprintf("nentries = %08X, %sentries_pageable\n",
		header->nentries,
		(header->entries_pageable ? "" : "!"));
}

/*
 *	vm_follow_entry:	[ debug ]
 */
void
vm_follow_entry(
	vm_map_entry_t entry)
{
	int shadows;

	iprintf("map entry %08X\n", entry);

	db_indent += 2;

	shadows = vm_follow_object(entry->object.vm_object);
	iprintf("Total objects : %d\n",shadows);

	db_indent -= 2;
}

/*
 *	vm_map_entry_print:	[ debug ]
 */
void
vm_map_entry_print(
	register vm_map_entry_t	entry)
{
	static const char *inheritance_name[4] =
		{ "share", "copy", "none", "?"};
	static const char *behavior_name[4] =
		{ "dflt", "rand", "seqtl", "rseqntl" };
	
	iprintf("map entry %08X - prev = %08X  next = %08X\n", entry, entry->vme_prev, entry->vme_next);

	db_indent += 2;

	vm_map_links_print(&entry->links);

	iprintf("start = %016llX  end = %016llX - prot=%x/%x/%s\n",
		(unsigned long long)entry->vme_start,
		(unsigned long long)entry->vme_end,
		entry->protection,
		entry->max_protection,
		inheritance_name[(entry->inheritance & 0x3)]);

	iprintf("behavior = %s, wired_count = %d, user_wired_count = %d\n",
		behavior_name[(entry->behavior & 0x3)],
		entry->wired_count,
		entry->user_wired_count);
	iprintf("%sin_transition, %sneeds_wakeup\n",
		(entry->in_transition ? "" : "!"),
		(entry->needs_wakeup ? "" : "!"));

	if (entry->is_sub_map) {
		iprintf("submap = %08X - offset = %016llX\n",
			entry->object.sub_map,
			(unsigned long long)entry->offset);
	} else {
		iprintf("object = %08X  offset = %016llX - ",
			entry->object.vm_object,
			(unsigned long long)entry->offset);
		printf("%sis_shared, %sneeds_copy\n",
		       (entry->is_shared ? "" : "!"),
		       (entry->needs_copy ? "" : "!"));
	}

	db_indent -= 2;
}

/*
 *	vm_follow_map:	[ debug ]
 */
void
vm_follow_map(
	vm_map_t map)
{
	register vm_map_entry_t	entry;

	iprintf("task map %08X\n", map);

	db_indent += 2;

	for (entry = vm_map_first_entry(map);
	     entry && entry != vm_map_to_entry(map);
	     entry = entry->vme_next) {
		vm_follow_entry(entry);
	}

	db_indent -= 2;
}

/*
 *	vm_map_print:	[ debug ]
 */
void
vm_map_print(
	db_addr_t inmap)
{
	register vm_map_entry_t	entry;
	vm_map_t map;
#if TASK_SWAPPER
	char *swstate;
#endif /* TASK_SWAPPER */

	map = (vm_map_t)(long)
		inmap;	/* Make sure we have the right type */

	iprintf("task map %08X\n", map);

	db_indent += 2;

	vm_map_header_print(&map->hdr);

	iprintf("pmap = %08X  size = %08X  ref = %d  hint = %08X  first_free = %08X\n",
		map->pmap,
		map->size,
		map->ref_count,
		map->hint,
		map->first_free);

	iprintf("%swait_for_space, %swiring_required, timestamp = %d\n",
		(map->wait_for_space ? "" : "!"),
		(map->wiring_required ? "" : "!"),
		map->timestamp);

#if	TASK_SWAPPER
	switch (map->sw_state) {
	case MAP_SW_IN:
		swstate = "SW_IN";
		break;
	case MAP_SW_OUT:
		swstate = "SW_OUT";
		break;
	default:
		swstate = "????";
		break;
	}
	iprintf("res = %d, sw_state = %s\n", map->res_count, swstate);
#endif	/* TASK_SWAPPER */

	for (entry = vm_map_first_entry(map);
	     entry && entry != vm_map_to_entry(map);
	     entry = entry->vme_next) {
		vm_map_entry_print(entry);
	}

	db_indent -= 2;
}

/*
 *	Routine:	vm_map_copy_print
 *	Purpose:
 *		Pretty-print a copy object for ddb.
 */

void
vm_map_copy_print(
	db_addr_t	incopy)
{
	vm_map_copy_t copy;
	vm_map_entry_t entry;

	copy = (vm_map_copy_t)(long)
		incopy;	/* Make sure we have the right type */

	printf("copy object 0x%x\n", copy);

	db_indent += 2;

	iprintf("type=%d", copy->type);
	switch (copy->type) {
	case VM_MAP_COPY_ENTRY_LIST:
		printf("[entry_list]");
		break;
		
	case VM_MAP_COPY_OBJECT:
		printf("[object]");
		break;
		
	case VM_MAP_COPY_KERNEL_BUFFER:
		printf("[kernel_buffer]");
		break;

	default:
		printf("[bad type]");
		break;
	}
	printf(", offset=0x%llx", (unsigned long long)copy->offset);
	printf(", size=0x%x\n", copy->size);

	switch (copy->type) {
	case VM_MAP_COPY_ENTRY_LIST:
		vm_map_header_print(&copy->cpy_hdr);
		for (entry = vm_map_copy_first_entry(copy);
		     entry && entry != vm_map_copy_to_entry(copy);
		     entry = entry->vme_next) {
			vm_map_entry_print(entry);
		}
		break;

	case VM_MAP_COPY_OBJECT:
		iprintf("object=0x%x\n", copy->cpy_object);
		break;

	case VM_MAP_COPY_KERNEL_BUFFER:
		iprintf("kernel buffer=0x%x", copy->cpy_kdata);
		printf(", kalloc_size=0x%x\n", copy->cpy_kalloc_size);
		break;

	}

	db_indent -=2;
}

/*
 *	db_vm_map_total_size(map)	[ debug ]
 *
 *	return the total virtual size (in bytes) of the map
 */
vm_map_size_t
db_vm_map_total_size(
	db_addr_t	inmap)
{
	vm_map_entry_t	entry;
	vm_map_size_t	total;
	vm_map_t map;

	map = (vm_map_t)(long)
		inmap;	/* Make sure we have the right type */

	total = 0;
	for (entry = vm_map_first_entry(map);
	     entry != vm_map_to_entry(map);
	     entry = entry->vme_next) {
		total += entry->vme_end - entry->vme_start;
	}

	return total;
}

#endif	/* MACH_KDB */

/*
 *	Routine:	vm_map_entry_insert
 *
 *	Descritpion:	This routine inserts a new vm_entry in a locked map.
 */
vm_map_entry_t
vm_map_entry_insert(
	vm_map_t		map,
	vm_map_entry_t		insp_entry,
	vm_map_offset_t		start,
	vm_map_offset_t		end,
	vm_object_t		object,
	vm_object_offset_t	offset,
	boolean_t		needs_copy,
	boolean_t		is_shared,
	boolean_t		in_transition,
	vm_prot_t		cur_protection,
	vm_prot_t		max_protection,
	vm_behavior_t		behavior,
	vm_inherit_t		inheritance,
	unsigned		wired_count,
	boolean_t		no_cache,
	boolean_t		permanent,
	unsigned int		superpage_size)
{
	vm_map_entry_t	new_entry;

	assert(insp_entry != (vm_map_entry_t)0);

	new_entry = vm_map_entry_create(map);

	new_entry->vme_start = start;
	new_entry->vme_end = end;
	assert(page_aligned(new_entry->vme_start));
	assert(page_aligned(new_entry->vme_end));

	new_entry->object.vm_object = object;
	new_entry->offset = offset;
	new_entry->is_shared = is_shared;
	new_entry->is_sub_map = FALSE;
	new_entry->needs_copy = needs_copy;
	new_entry->in_transition = in_transition;
	new_entry->needs_wakeup = FALSE;
	new_entry->inheritance = inheritance;
	new_entry->protection = cur_protection;
	new_entry->max_protection = max_protection;
	new_entry->behavior = behavior;
	new_entry->wired_count = wired_count;
	new_entry->user_wired_count = 0;
	new_entry->use_pmap = FALSE;
	new_entry->alias = 0;
	new_entry->zero_wired_pages = FALSE;
	new_entry->no_cache = no_cache;
	new_entry->permanent = permanent;
	new_entry->superpage_size = superpage_size;
	new_entry->used_for_jit = FALSE;

	/*
	 *	Insert the new entry into the list.
	 */

	vm_map_store_entry_link(map, insp_entry, new_entry);
	map->size += end - start;

	/*
	 *	Update the free space hint and the lookup hint.
	 */

	SAVE_HINT_MAP_WRITE(map, new_entry);
	return new_entry;
}

/*
 *	Routine:	vm_map_remap_extract
 *
 *	Descritpion:	This routine returns a vm_entry list from a map.
 */
static kern_return_t
vm_map_remap_extract(
	vm_map_t		map,
	vm_map_offset_t		addr,
	vm_map_size_t		size,
	boolean_t		copy,
	struct vm_map_header	*map_header,
	vm_prot_t		*cur_protection,
	vm_prot_t		*max_protection,
	/* What, no behavior? */
	vm_inherit_t		inheritance,
	boolean_t		pageable)
{
	kern_return_t		result;
	vm_map_size_t		mapped_size;
	vm_map_size_t		tmp_size;
	vm_map_entry_t		src_entry;     /* result of last map lookup */
	vm_map_entry_t		new_entry;
	vm_object_offset_t	offset;
	vm_map_offset_t		map_address;
	vm_map_offset_t		src_start;     /* start of entry to map */
	vm_map_offset_t		src_end;       /* end of region to be mapped */
	vm_object_t		object;    
	vm_map_version_t	version;
	boolean_t		src_needs_copy;
	boolean_t		new_entry_needs_copy;

	assert(map != VM_MAP_NULL);
	assert(size != 0 && size == vm_map_round_page(size));
	assert(inheritance == VM_INHERIT_NONE ||
	       inheritance == VM_INHERIT_COPY ||
	       inheritance == VM_INHERIT_SHARE);

	/*
	 *	Compute start and end of region.
	 */
	src_start = vm_map_trunc_page(addr);
	src_end = vm_map_round_page(src_start + size);

	/*
	 *	Initialize map_header.
	 */
	map_header->links.next = (struct vm_map_entry *)&map_header->links;
	map_header->links.prev = (struct vm_map_entry *)&map_header->links;
	map_header->nentries = 0;
	map_header->entries_pageable = pageable;

	vm_map_store_init( map_header );

	*cur_protection = VM_PROT_ALL;
	*max_protection = VM_PROT_ALL;

	map_address = 0;
	mapped_size = 0;
	result = KERN_SUCCESS;

	/*  
	 *	The specified source virtual space might correspond to
	 *	multiple map entries, need to loop on them.
	 */
	vm_map_lock(map);
	while (mapped_size != size) {
		vm_map_size_t	entry_size;

		/*
		 *	Find the beginning of the region.
		 */ 
		if (! vm_map_lookup_entry(map, src_start, &src_entry)) {
			result = KERN_INVALID_ADDRESS;
			break;
		}

		if (src_start < src_entry->vme_start ||
		    (mapped_size && src_start != src_entry->vme_start)) {
			result = KERN_INVALID_ADDRESS;
			break;
		}

		tmp_size = size - mapped_size;
		if (src_end > src_entry->vme_end)
			tmp_size -= (src_end - src_entry->vme_end);

		entry_size = (vm_map_size_t)(src_entry->vme_end -
					     src_entry->vme_start);

		if(src_entry->is_sub_map) {
			vm_map_reference(src_entry->object.sub_map);
			object = VM_OBJECT_NULL;
		} else {
			object = src_entry->object.vm_object;

			if (object == VM_OBJECT_NULL) {
				object = vm_object_allocate(entry_size);
				src_entry->offset = 0;
				src_entry->object.vm_object = object;
			} else if (object->copy_strategy !=
				   MEMORY_OBJECT_COPY_SYMMETRIC) {
				/*
				 *	We are already using an asymmetric
				 *	copy, and therefore we already have
				 *	the right object.
				 */
				assert(!src_entry->needs_copy);
			} else if (src_entry->needs_copy || object->shadowed ||
				   (object->internal && !object->true_share &&
				    !src_entry->is_shared &&
				    object->vo_size > entry_size)) {

				vm_object_shadow(&src_entry->object.vm_object,
						 &src_entry->offset,
						 entry_size);

				if (!src_entry->needs_copy &&
				    (src_entry->protection & VM_PROT_WRITE)) {
				        vm_prot_t prot;

				        prot = src_entry->protection & ~VM_PROT_WRITE;

					if (override_nx(map, src_entry->alias) && prot)
					        prot |= VM_PROT_EXECUTE;

					if(map->mapped) {
						vm_object_pmap_protect(
							src_entry->object.vm_object,
							src_entry->offset,
							entry_size,
							PMAP_NULL,
							src_entry->vme_start,
							prot);
					} else {
						pmap_protect(vm_map_pmap(map),
							     src_entry->vme_start,
							     src_entry->vme_end,
							     prot);
					}
				}

				object = src_entry->object.vm_object;
				src_entry->needs_copy = FALSE;
			}


			vm_object_lock(object);
			vm_object_reference_locked(object); /* object ref. for new entry */
			if (object->copy_strategy == 
			    MEMORY_OBJECT_COPY_SYMMETRIC) {
				object->copy_strategy = 
					MEMORY_OBJECT_COPY_DELAY;
			}
			vm_object_unlock(object);
		}

		offset = src_entry->offset + (src_start - src_entry->vme_start);

		new_entry = _vm_map_entry_create(map_header);
		vm_map_entry_copy(new_entry, src_entry);
		new_entry->use_pmap = FALSE; /* clr address space specifics */

		new_entry->vme_start = map_address;
		new_entry->vme_end = map_address + tmp_size;
		new_entry->inheritance = inheritance;
		new_entry->offset = offset;

		/*
		 * The new region has to be copied now if required.
		 */
	RestartCopy:
		if (!copy) {
			src_entry->is_shared = TRUE;
			new_entry->is_shared = TRUE;
			if (!(new_entry->is_sub_map)) 
				new_entry->needs_copy = FALSE;

		} else if (src_entry->is_sub_map) {
			/* make this a COW sub_map if not already */
			new_entry->needs_copy = TRUE;
			object = VM_OBJECT_NULL;
		} else if (src_entry->wired_count == 0 &&
			   vm_object_copy_quickly(&new_entry->object.vm_object,
						  new_entry->offset,
						  (new_entry->vme_end -
						   new_entry->vme_start),
						  &src_needs_copy,
						  &new_entry_needs_copy)) {

			new_entry->needs_copy = new_entry_needs_copy;
			new_entry->is_shared = FALSE;

			/*
			 * Handle copy_on_write semantics.
			 */
			if (src_needs_copy && !src_entry->needs_copy) {
			        vm_prot_t prot;

				prot = src_entry->protection & ~VM_PROT_WRITE;

				if (override_nx(map, src_entry->alias) && prot)
				        prot |= VM_PROT_EXECUTE;

				vm_object_pmap_protect(object,
						       offset,
						       entry_size,
						       ((src_entry->is_shared 
							 || map->mapped) ?
							PMAP_NULL : map->pmap),
						       src_entry->vme_start,
						       prot);

				src_entry->needs_copy = TRUE;
			}
			/*
			 * Throw away the old object reference of the new entry.
			 */
			vm_object_deallocate(object);

		} else {
			new_entry->is_shared = FALSE;

			/*
			 * The map can be safely unlocked since we
			 * already hold a reference on the object.
			 *
			 * Record the timestamp of the map for later
			 * verification, and unlock the map.
			 */
			version.main_timestamp = map->timestamp;
			vm_map_unlock(map); 	/* Increments timestamp once! */

			/*
			 * Perform the copy.
			 */
			if (src_entry->wired_count > 0) {
				vm_object_lock(object);
				result = vm_object_copy_slowly(
					object,
					offset,
					entry_size,
					THREAD_UNINT,
					&new_entry->object.vm_object);

				new_entry->offset = 0;
				new_entry->needs_copy = FALSE;
			} else {
				result = vm_object_copy_strategically(
					object,
					offset,
					entry_size,
					&new_entry->object.vm_object,
					&new_entry->offset,
					&new_entry_needs_copy);

				new_entry->needs_copy = new_entry_needs_copy;
			}

			/*
			 * Throw away the old object reference of the new entry.
			 */
			vm_object_deallocate(object);

			if (result != KERN_SUCCESS &&
			    result != KERN_MEMORY_RESTART_COPY) {
				_vm_map_entry_dispose(map_header, new_entry);
				break;
			}

			/*
			 * Verify that the map has not substantially
			 * changed while the copy was being made.
			 */

			vm_map_lock(map);
			if (version.main_timestamp + 1 != map->timestamp) {
				/*
				 * Simple version comparison failed.
				 *
				 * Retry the lookup and verify that the
				 * same object/offset are still present.
				 */
				vm_object_deallocate(new_entry->
						     object.vm_object);
				_vm_map_entry_dispose(map_header, new_entry);
				if (result == KERN_MEMORY_RESTART_COPY)
					result = KERN_SUCCESS;
				continue;
			}

			if (result == KERN_MEMORY_RESTART_COPY) {
				vm_object_reference(object);
				goto RestartCopy;
			}
		}

		_vm_map_store_entry_link(map_header,
				   map_header->links.prev, new_entry);

		/*Protections for submap mapping are irrelevant here*/
		if( !src_entry->is_sub_map ) {
			*cur_protection &= src_entry->protection;
			*max_protection &= src_entry->max_protection;
		}
		map_address += tmp_size;
		mapped_size += tmp_size;
		src_start += tmp_size;

	} /* end while */

	vm_map_unlock(map);
	if (result != KERN_SUCCESS) {
		/*
		 * Free all allocated elements.
		 */
		for (src_entry = map_header->links.next;
		     src_entry != (struct vm_map_entry *)&map_header->links;
		     src_entry = new_entry) {
			new_entry = src_entry->vme_next;
			_vm_map_store_entry_unlink(map_header, src_entry);
			vm_object_deallocate(src_entry->object.vm_object);
			_vm_map_entry_dispose(map_header, src_entry);
		}
	}
	return result;
}

/*
 *	Routine:	vm_remap
 *
 *			Map portion of a task's address space.
 *			Mapped region must not overlap more than
 *			one vm memory object. Protections and
 *			inheritance attributes remain the same
 *			as in the original task and are	out parameters.
 *			Source and Target task can be identical
 *			Other attributes are identical as for vm_map()
 */
kern_return_t
vm_map_remap(
	vm_map_t		target_map,
	vm_map_address_t	*address,
	vm_map_size_t		size,
	vm_map_offset_t		mask,
	int			flags,
	vm_map_t		src_map,
	vm_map_offset_t		memory_address,
	boolean_t		copy,
	vm_prot_t		*cur_protection,
	vm_prot_t		*max_protection,
	vm_inherit_t		inheritance)
{
	kern_return_t		result;
	vm_map_entry_t		entry;
	vm_map_entry_t		insp_entry = VM_MAP_ENTRY_NULL;
	vm_map_entry_t		new_entry;
	struct vm_map_header	map_header;

	if (target_map == VM_MAP_NULL)
		return KERN_INVALID_ARGUMENT;

	switch (inheritance) {
	case VM_INHERIT_NONE:
	case VM_INHERIT_COPY:
	case VM_INHERIT_SHARE:
		if (size != 0 && src_map != VM_MAP_NULL)
			break;
		/*FALL THRU*/
	default:
		return KERN_INVALID_ARGUMENT;
	}

	size = vm_map_round_page(size);

	result = vm_map_remap_extract(src_map, memory_address,
				      size, copy, &map_header,
				      cur_protection,
				      max_protection,
				      inheritance,
				      target_map->hdr.
				      entries_pageable);

	if (result != KERN_SUCCESS) {
		return result;
	}

	/*
	 * Allocate/check a range of free virtual address
	 * space for the target
	 */
	*address = vm_map_trunc_page(*address);
	vm_map_lock(target_map);
	result = vm_map_remap_range_allocate(target_map, address, size,
					     mask, flags, &insp_entry);

	for (entry = map_header.links.next;
	     entry != (struct vm_map_entry *)&map_header.links;
	     entry = new_entry) {
		new_entry = entry->vme_next;
		_vm_map_store_entry_unlink(&map_header, entry);
		if (result == KERN_SUCCESS) {
			entry->vme_start += *address;
			entry->vme_end += *address;
			vm_map_store_entry_link(target_map, insp_entry, entry);
			insp_entry = entry;
		} else {
			if (!entry->is_sub_map) {
				vm_object_deallocate(entry->object.vm_object);
			} else {
				vm_map_deallocate(entry->object.sub_map);
			}
			_vm_map_entry_dispose(&map_header, entry);
		}
	}

	if( target_map->disable_vmentry_reuse == TRUE) {
		if( target_map->highest_entry_end < insp_entry->vme_end ){
			target_map->highest_entry_end = insp_entry->vme_end;
		}
	}

	if (result == KERN_SUCCESS) {
		target_map->size += size;
		SAVE_HINT_MAP_WRITE(target_map, insp_entry);
	}
	vm_map_unlock(target_map);

	if (result == KERN_SUCCESS && target_map->wiring_required)
		result = vm_map_wire(target_map, *address,
				     *address + size, *cur_protection, TRUE);
	return result;
}

/*
 *	Routine:	vm_map_remap_range_allocate
 *
 *	Description:
 *		Allocate a range in the specified virtual address map.
 *		returns the address and the map entry just before the allocated
 *		range
 *
 *	Map must be locked.
 */

static kern_return_t
vm_map_remap_range_allocate(
	vm_map_t		map,
	vm_map_address_t	*address,	/* IN/OUT */
	vm_map_size_t		size,
	vm_map_offset_t		mask,
	int			flags,
	vm_map_entry_t		*map_entry)	/* OUT */
{
	vm_map_entry_t	entry;
	vm_map_offset_t	start;
	vm_map_offset_t	end;
	kern_return_t	kr;

StartAgain: ;

	start = *address;

	if (flags & VM_FLAGS_ANYWHERE)
	{
		/*
		 *	Calculate the first possible address.
		 */

		if (start < map->min_offset)
			start = map->min_offset;
		if (start > map->max_offset)
			return(KERN_NO_SPACE);
		
		/*
		 *	Look for the first possible address;
		 *	if there's already something at this
		 *	address, we have to start after it.
		 */

		if( map->disable_vmentry_reuse == TRUE) {
			VM_MAP_HIGHEST_ENTRY(map, entry, start);
		} else {
			assert(first_free_is_valid(map));
			if (start == map->min_offset) {
				if ((entry = map->first_free) != vm_map_to_entry(map))
					start = entry->vme_end;
			} else {
				vm_map_entry_t	tmp_entry;
				if (vm_map_lookup_entry(map, start, &tmp_entry))
					start = tmp_entry->vme_end;
				entry = tmp_entry;
			}
		}
		
		/*
		 *	In any case, the "entry" always precedes
		 *	the proposed new region throughout the
		 *	loop:
		 */

		while (TRUE) {
			register vm_map_entry_t	next;

			/*
			 *	Find the end of the proposed new region.
			 *	Be sure we didn't go beyond the end, or
			 *	wrap around the address.
			 */

			end = ((start + mask) & ~mask);
			if (end < start)
				return(KERN_NO_SPACE);
			start = end;
			end += size;

			if ((end > map->max_offset) || (end < start)) {
				if (map->wait_for_space) {
					if (size <= (map->max_offset -
						     map->min_offset)) {
						assert_wait((event_t) map, THREAD_INTERRUPTIBLE);
						vm_map_unlock(map);
						thread_block(THREAD_CONTINUE_NULL);
						vm_map_lock(map);
						goto StartAgain;
					}
				}
		
				return(KERN_NO_SPACE);
			}

			/*
			 *	If there are no more entries, we must win.
			 */

			next = entry->vme_next;
			if (next == vm_map_to_entry(map))
				break;

			/*
			 *	If there is another entry, it must be
			 *	after the end of the potential new region.
			 */

			if (next->vme_start >= end)
				break;

			/*
			 *	Didn't fit -- move to the next entry.
			 */

			entry = next;
			start = entry->vme_end;
		}
		*address = start;
	} else {
		vm_map_entry_t		temp_entry;
	
		/*
		 *	Verify that:
		 *		the address doesn't itself violate
		 *		the mask requirement.
		 */

		if ((start & mask) != 0)
			return(KERN_NO_SPACE);


		/*
		 *	...	the address is within bounds
		 */

		end = start + size;

		if ((start < map->min_offset) ||
		    (end > map->max_offset) ||
		    (start >= end)) {
			return(KERN_INVALID_ADDRESS);
		}

		/*
		 * If we're asked to overwrite whatever was mapped in that
		 * range, first deallocate that range.
		 */
		if (flags & VM_FLAGS_OVERWRITE) {
			vm_map_t zap_map;

			/*
			 * We use a "zap_map" to avoid having to unlock
			 * the "map" in vm_map_delete(), which would compromise
			 * the atomicity of the "deallocate" and then "remap"
			 * combination.
			 */
			zap_map = vm_map_create(PMAP_NULL,
						start,
						end - start,
						map->hdr.entries_pageable);
			if (zap_map == VM_MAP_NULL) {
				return KERN_RESOURCE_SHORTAGE;
			}

			kr = vm_map_delete(map, start, end,
					   VM_MAP_REMOVE_SAVE_ENTRIES,
					   zap_map);
			if (kr == KERN_SUCCESS) {
				vm_map_destroy(zap_map,
					       VM_MAP_REMOVE_NO_PMAP_CLEANUP);
				zap_map = VM_MAP_NULL;
			}
		}

		/*
		 *	...	the starting address isn't allocated
		 */

		if (vm_map_lookup_entry(map, start, &temp_entry))
			return(KERN_NO_SPACE);

		entry = temp_entry;

		/*
		 *	...	the next region doesn't overlap the
		 *		end point.
		 */

		if ((entry->vme_next != vm_map_to_entry(map)) &&
		    (entry->vme_next->vme_start < end))
			return(KERN_NO_SPACE);
	}
	*map_entry = entry;
	return(KERN_SUCCESS);
}

/*
 *	vm_map_switch:
 *
 *	Set the address map for the current thread to the specified map
 */

vm_map_t
vm_map_switch(
	vm_map_t	map)
{
	int		mycpu;
	thread_t	thread = current_thread();
	vm_map_t	oldmap = thread->map;

	mp_disable_preemption();
	mycpu = cpu_number();

	/*
	 *	Deactivate the current map and activate the requested map
	 */
	PMAP_SWITCH_USER(thread, map, mycpu);

	mp_enable_preemption();
	return(oldmap);
}


/*
 *	Routine:	vm_map_write_user
 *
 *	Description:
 *		Copy out data from a kernel space into space in the
 *		destination map. The space must already exist in the
 *		destination map.
 *		NOTE:  This routine should only be called by threads
 *		which can block on a page fault. i.e. kernel mode user
 *		threads.
 *
 */
kern_return_t
vm_map_write_user(
	vm_map_t		map,
	void			*src_p,
	vm_map_address_t	dst_addr,
	vm_size_t		size)
{
	kern_return_t	kr = KERN_SUCCESS;

	if(current_map() == map) {
		if (copyout(src_p, dst_addr, size)) {
			kr = KERN_INVALID_ADDRESS;
		}
	} else {
		vm_map_t	oldmap;

		/* take on the identity of the target map while doing */
		/* the transfer */

		vm_map_reference(map);
		oldmap = vm_map_switch(map);
		if (copyout(src_p, dst_addr, size)) {
			kr = KERN_INVALID_ADDRESS;
		}
		vm_map_switch(oldmap);
		vm_map_deallocate(map);
	}
	return kr;
}

/*
 *	Routine:	vm_map_read_user
 *
 *	Description:
 *		Copy in data from a user space source map into the
 *		kernel map. The space must already exist in the
 *		kernel map.
 *		NOTE:  This routine should only be called by threads
 *		which can block on a page fault. i.e. kernel mode user
 *		threads.
 *
 */
kern_return_t
vm_map_read_user(
	vm_map_t		map,
	vm_map_address_t	src_addr,
	void			*dst_p,
	vm_size_t		size)
{
	kern_return_t	kr = KERN_SUCCESS;

	if(current_map() == map) {
		if (copyin(src_addr, dst_p, size)) {
			kr = KERN_INVALID_ADDRESS;
		}
	} else {
		vm_map_t	oldmap;

		/* take on the identity of the target map while doing */
		/* the transfer */

		vm_map_reference(map);
		oldmap = vm_map_switch(map);
		if (copyin(src_addr, dst_p, size)) {
			kr = KERN_INVALID_ADDRESS;
		}
		vm_map_switch(oldmap);
		vm_map_deallocate(map);
	}
	return kr;
}


/*
 *	vm_map_check_protection:
 *
 *	Assert that the target map allows the specified
 *	privilege on the entire address region given.
 *	The entire region must be allocated.
 */
boolean_t
vm_map_check_protection(vm_map_t map, vm_map_offset_t start,
			vm_map_offset_t end, vm_prot_t protection)
{
	vm_map_entry_t entry;
	vm_map_entry_t tmp_entry;

	vm_map_lock(map);

	if (start < vm_map_min(map) || end > vm_map_max(map) || start > end)
	{
		vm_map_unlock(map);
		return (FALSE);
	}

	if (!vm_map_lookup_entry(map, start, &tmp_entry)) {
		vm_map_unlock(map);
		return(FALSE);
	}

	entry = tmp_entry;

	while (start < end) {
		if (entry == vm_map_to_entry(map)) {
			vm_map_unlock(map);
			return(FALSE);
		}

		/*
		 *	No holes allowed!
		 */

		if (start < entry->vme_start) {
			vm_map_unlock(map);
			return(FALSE);
		}

		/*
		 * Check protection associated with entry.
		 */

		if ((entry->protection & protection) != protection) {
			vm_map_unlock(map);
			return(FALSE);
		}

		/* go to next entry */

		start = entry->vme_end;
		entry = entry->vme_next;
	}
	vm_map_unlock(map);
	return(TRUE);
}

kern_return_t
vm_map_purgable_control(
	vm_map_t		map,
	vm_map_offset_t		address,
	vm_purgable_t		control,
	int			*state)
{
	vm_map_entry_t		entry;
	vm_object_t		object;
	kern_return_t		kr;

	/*
	 * Vet all the input parameters and current type and state of the
	 * underlaying object.  Return with an error if anything is amiss.
	 */
	if (map == VM_MAP_NULL)
		return(KERN_INVALID_ARGUMENT);

	if (control != VM_PURGABLE_SET_STATE &&
	    control != VM_PURGABLE_GET_STATE &&
	    control != VM_PURGABLE_PURGE_ALL)
		return(KERN_INVALID_ARGUMENT);

	if (control == VM_PURGABLE_PURGE_ALL) {
		vm_purgeable_object_purge_all();
		return KERN_SUCCESS;
	}

	if (control == VM_PURGABLE_SET_STATE &&
	    (((*state & ~(VM_PURGABLE_ALL_MASKS)) != 0) ||
	     ((*state & VM_PURGABLE_STATE_MASK) > VM_PURGABLE_STATE_MASK)))
		return(KERN_INVALID_ARGUMENT);

	vm_map_lock_read(map);

	if (!vm_map_lookup_entry(map, address, &entry) || entry->is_sub_map) {

		/*
		 * Must pass a valid non-submap address.
		 */
		vm_map_unlock_read(map);
		return(KERN_INVALID_ADDRESS);
	}

	if ((entry->protection & VM_PROT_WRITE) == 0) {
		/*
		 * Can't apply purgable controls to something you can't write.
		 */
		vm_map_unlock_read(map);
		return(KERN_PROTECTION_FAILURE);
	}

	object = entry->object.vm_object;
	if (object == VM_OBJECT_NULL) {
		/*
		 * Object must already be present or it can't be purgable.
		 */
		vm_map_unlock_read(map);
		return KERN_INVALID_ARGUMENT;
	}
		     
	vm_object_lock(object);

	if (entry->offset != 0 || 
	    entry->vme_end - entry->vme_start != object->vo_size) {
		/*
		 * Can only apply purgable controls to the whole (existing)
		 * object at once.
		 */
		vm_map_unlock_read(map);
		vm_object_unlock(object);
		return KERN_INVALID_ARGUMENT;
	}
		
	vm_map_unlock_read(map);

	kr = vm_object_purgable_control(object, control, state);

	vm_object_unlock(object);

	return kr;
}

kern_return_t
vm_map_page_query_internal(
	vm_map_t	target_map,
	vm_map_offset_t	offset,
	int		*disposition,
	int		*ref_count)
{
	kern_return_t			kr;
	vm_page_info_basic_data_t	info;
	mach_msg_type_number_t		count;

	count = VM_PAGE_INFO_BASIC_COUNT;
	kr = vm_map_page_info(target_map,
			      offset,
			      VM_PAGE_INFO_BASIC,
			      (vm_page_info_t) &info,
			      &count);
	if (kr == KERN_SUCCESS) {
		*disposition = info.disposition;
		*ref_count = info.ref_count;
	} else {
		*disposition = 0;
		*ref_count = 0;
	}

	return kr;
}
		
kern_return_t
vm_map_page_info(
	vm_map_t		map,
	vm_map_offset_t		offset,
	vm_page_info_flavor_t	flavor,
	vm_page_info_t		info,
	mach_msg_type_number_t	*count)
{
	vm_map_entry_t		map_entry;
	vm_object_t		object;
	vm_page_t		m;
	kern_return_t		kr;
	kern_return_t		retval = KERN_SUCCESS;
	boolean_t		top_object;
	int			disposition;
	int 			ref_count;
	vm_object_id_t		object_id;
	vm_page_info_basic_t	basic_info;
	int			depth;
	vm_map_offset_t		offset_in_page;

	switch (flavor) {
	case VM_PAGE_INFO_BASIC:
		if (*count != VM_PAGE_INFO_BASIC_COUNT) {
			/*
			 * The "vm_page_info_basic_data" structure was not
			 * properly padded, so allow the size to be off by
			 * one to maintain backwards binary compatibility...
			 */
			if (*count != VM_PAGE_INFO_BASIC_COUNT - 1)
				return KERN_INVALID_ARGUMENT;
		}
		break;
	default:
		return KERN_INVALID_ARGUMENT;
	}

	disposition = 0;
	ref_count = 0;
	object_id = 0;
	top_object = TRUE;
	depth = 0;

	retval = KERN_SUCCESS;
	offset_in_page = offset & PAGE_MASK;
	offset = vm_map_trunc_page(offset);

	vm_map_lock_read(map);

	/*
	 * First, find the map entry covering "offset", going down
	 * submaps if necessary.
	 */
	for (;;) {
		if (!vm_map_lookup_entry(map, offset, &map_entry)) {
			vm_map_unlock_read(map);
			return KERN_INVALID_ADDRESS;
		}
		/* compute offset from this map entry's start */
		offset -= map_entry->vme_start;
		/* compute offset into this map entry's object (or submap) */
		offset += map_entry->offset;

		if (map_entry->is_sub_map) {
			vm_map_t sub_map;

			sub_map = map_entry->object.sub_map;
			vm_map_lock_read(sub_map);
			vm_map_unlock_read(map);

			map = sub_map;

			ref_count = MAX(ref_count, map->ref_count);
			continue;
		}
		break;
	}

	object = map_entry->object.vm_object;
	if (object == VM_OBJECT_NULL) {
		/* no object -> no page */
		vm_map_unlock_read(map);
		goto done;
	}

	vm_object_lock(object);
	vm_map_unlock_read(map);

	/*
	 * Go down the VM object shadow chain until we find the page
	 * we're looking for.
	 */
	for (;;) {
		ref_count = MAX(ref_count, object->ref_count);

		m = vm_page_lookup(object, offset);

		if (m != VM_PAGE_NULL) {
			disposition |= VM_PAGE_QUERY_PAGE_PRESENT;
			break;
		} else {
#if MACH_PAGEMAP
			if (object->existence_map) {
				if (vm_external_state_get(object->existence_map,
							  offset) ==
				    VM_EXTERNAL_STATE_EXISTS) {
					/*
					 * this page has been paged out
					 */
				        disposition |= VM_PAGE_QUERY_PAGE_PAGED_OUT;
					break;
				}
			} else
#endif
			{
				if (object->internal &&
				    object->alive &&
				    !object->terminating &&
				    object->pager_ready) {

					memory_object_t pager;

					vm_object_paging_begin(object);
					pager = object->pager;
					vm_object_unlock(object);

					/*
					 * Ask the default pager if
					 * it has this page.
					 */
					kr = memory_object_data_request(
						pager,
						offset + object->paging_offset,
						0, /* just poke the pager */
						VM_PROT_READ,
						NULL);

					vm_object_lock(object);
					vm_object_paging_end(object);

					if (kr == KERN_SUCCESS) {
						/* the default pager has it */
						disposition |= VM_PAGE_QUERY_PAGE_PAGED_OUT;
						break;
					}
				}
			}

			if (object->shadow != VM_OBJECT_NULL) {
			        vm_object_t shadow;

				offset += object->vo_shadow_offset;
				shadow = object->shadow;
				
				vm_object_lock(shadow);
				vm_object_unlock(object);

				object = shadow;
				top_object = FALSE;
				depth++;
			} else {
//			        if (!object->internal)
//				        break;
//				retval = KERN_FAILURE;
//				goto done_with_object;
				break;
			}
		}
	}
	/* The ref_count is not strictly accurate, it measures the number   */
	/* of entities holding a ref on the object, they may not be mapping */
	/* the object or may not be mapping the section holding the         */
	/* target page but its still a ball park number and though an over- */
	/* count, it picks up the copy-on-write cases                       */

	/* We could also get a picture of page sharing from pmap_attributes */
	/* but this would under count as only faulted-in mappings would     */
	/* show up.							    */

	if (top_object == TRUE && object->shadow)
		disposition |= VM_PAGE_QUERY_PAGE_COPIED;

	if (! object->internal)
		disposition |= VM_PAGE_QUERY_PAGE_EXTERNAL;

	if (m == VM_PAGE_NULL)
	        goto done_with_object;

	if (m->fictitious) {
		disposition |= VM_PAGE_QUERY_PAGE_FICTITIOUS;
		goto done_with_object;
	}
	if (m->dirty || pmap_is_modified(m->phys_page))
		disposition |= VM_PAGE_QUERY_PAGE_DIRTY;

	if (m->reference || pmap_is_referenced(m->phys_page))
		disposition |= VM_PAGE_QUERY_PAGE_REF;

	if (m->speculative)
		disposition |= VM_PAGE_QUERY_PAGE_SPECULATIVE;

	if (m->cs_validated)
		disposition |= VM_PAGE_QUERY_PAGE_CS_VALIDATED;
	if (m->cs_tainted)
		disposition |= VM_PAGE_QUERY_PAGE_CS_TAINTED;

done_with_object:
	vm_object_unlock(object);
done:

	switch (flavor) {
	case VM_PAGE_INFO_BASIC:
		basic_info = (vm_page_info_basic_t) info;
		basic_info->disposition = disposition;
		basic_info->ref_count = ref_count;
		basic_info->object_id = (vm_object_id_t) (uintptr_t) object;
		basic_info->offset =
			(memory_object_offset_t) offset + offset_in_page;
		basic_info->depth = depth;
		break;
	}

	return retval;
}

/*
 *	vm_map_msync
 *
 *	Synchronises the memory range specified with its backing store
 *	image by either flushing or cleaning the contents to the appropriate
 *	memory manager engaging in a memory object synchronize dialog with
 *	the manager.  The client doesn't return until the manager issues
 *	m_o_s_completed message.  MIG Magically converts user task parameter
 *	to the task's address map.
 *
 *	interpretation of sync_flags
 *	VM_SYNC_INVALIDATE	- discard pages, only return precious
 *				  pages to manager.
 *
 *	VM_SYNC_INVALIDATE & (VM_SYNC_SYNCHRONOUS | VM_SYNC_ASYNCHRONOUS)
 *				- discard pages, write dirty or precious
 *				  pages back to memory manager.
 *
 *	VM_SYNC_SYNCHRONOUS | VM_SYNC_ASYNCHRONOUS
 *				- write dirty or precious pages back to
 *				  the memory manager.
 *
 *	VM_SYNC_CONTIGUOUS	- does everything normally, but if there
 *				  is a hole in the region, and we would
 *				  have returned KERN_SUCCESS, return
 *				  KERN_INVALID_ADDRESS instead.
 *
 *	NOTE
 *	The memory object attributes have not yet been implemented, this
 *	function will have to deal with the invalidate attribute
 *
 *	RETURNS
 *	KERN_INVALID_TASK		Bad task parameter
 *	KERN_INVALID_ARGUMENT		both sync and async were specified.
 *	KERN_SUCCESS			The usual.
 *	KERN_INVALID_ADDRESS		There was a hole in the region.
 */

kern_return_t
vm_map_msync(
	vm_map_t		map,
	vm_map_address_t	address,
	vm_map_size_t		size,
	vm_sync_t		sync_flags)
{
	msync_req_t		msr;
	msync_req_t		new_msr;
	queue_chain_t		req_q;	/* queue of requests for this msync */
	vm_map_entry_t		entry;
	vm_map_size_t		amount_left;
	vm_object_offset_t	offset;
	boolean_t		do_sync_req;
	boolean_t		had_hole = FALSE;
	memory_object_t		pager;
	
	if ((sync_flags & VM_SYNC_ASYNCHRONOUS) &&
	    (sync_flags & VM_SYNC_SYNCHRONOUS))
		return(KERN_INVALID_ARGUMENT);

	/*
	 * align address and size on page boundaries
	 */
	size = vm_map_round_page(address + size) - vm_map_trunc_page(address);
	address = vm_map_trunc_page(address);

        if (map == VM_MAP_NULL)
                return(KERN_INVALID_TASK);

	if (size == 0)
		return(KERN_SUCCESS);

	queue_init(&req_q);
	amount_left = size;

	while (amount_left > 0) {
		vm_object_size_t	flush_size;
		vm_object_t		object;

		vm_map_lock(map);
		if (!vm_map_lookup_entry(map,
					 vm_map_trunc_page(address), &entry)) {

			vm_map_size_t	skip;

			/*
			 * hole in the address map.
			 */
			had_hole = TRUE;

			/*
			 * Check for empty map.
			 */
			if (entry == vm_map_to_entry(map) &&
			    entry->vme_next == entry) {
				vm_map_unlock(map);
				break;
			}
			/*
			 * Check that we don't wrap and that
			 * we have at least one real map entry.
			 */
			if ((map->hdr.nentries == 0) ||
			    (entry->vme_next->vme_start < address)) {
				vm_map_unlock(map);
				break;
			}
			/*
			 * Move up to the next entry if needed
			 */
			skip = (entry->vme_next->vme_start - address);
			if (skip >= amount_left)
				amount_left = 0;
			else
				amount_left -= skip;
			address = entry->vme_next->vme_start;
			vm_map_unlock(map);
			continue;
		}

		offset = address - entry->vme_start;

		/*
		 * do we have more to flush than is contained in this
		 * entry ?
		 */
		if (amount_left + entry->vme_start + offset > entry->vme_end) {
			flush_size = entry->vme_end -
				(entry->vme_start + offset);
		} else {
			flush_size = amount_left;
		}
		amount_left -= flush_size;
		address += flush_size;

		if (entry->is_sub_map == TRUE) {
			vm_map_t	local_map;
			vm_map_offset_t	local_offset;

			local_map = entry->object.sub_map;
			local_offset = entry->offset;
			vm_map_unlock(map);
			if (vm_map_msync(
				    local_map,
				    local_offset,
				    flush_size,
				    sync_flags) == KERN_INVALID_ADDRESS) {
				had_hole = TRUE;
			}
			continue;
		}
		object = entry->object.vm_object;

		/*
		 * We can't sync this object if the object has not been
		 * created yet
		 */
		if (object == VM_OBJECT_NULL) {
			vm_map_unlock(map);
			continue;
		}
		offset += entry->offset;

                vm_object_lock(object);

		if (sync_flags & (VM_SYNC_KILLPAGES | VM_SYNC_DEACTIVATE)) {
		        int kill_pages = 0;
			boolean_t reusable_pages = FALSE;

			if (sync_flags & VM_SYNC_KILLPAGES) {
			        if (object->ref_count == 1 && !object->shadow)
				        kill_pages = 1;
				else
				        kill_pages = -1;
			}
			if (kill_pages != -1)
			        vm_object_deactivate_pages(object, offset, 
							   (vm_object_size_t)flush_size, kill_pages, reusable_pages);
			vm_object_unlock(object);
			vm_map_unlock(map);
			continue;
		}
		/*
		 * We can't sync this object if there isn't a pager.
		 * Don't bother to sync internal objects, since there can't
		 * be any "permanent" storage for these objects anyway.
		 */
		if ((object->pager == MEMORY_OBJECT_NULL) ||
		    (object->internal) || (object->private)) {
			vm_object_unlock(object);
			vm_map_unlock(map);
			continue;
		}
		/*
		 * keep reference on the object until syncing is done
		 */
		vm_object_reference_locked(object);
		vm_object_unlock(object);

		vm_map_unlock(map);

		do_sync_req = vm_object_sync(object,
					     offset,
					     flush_size,
					     sync_flags & VM_SYNC_INVALIDATE,
					     ((sync_flags & VM_SYNC_SYNCHRONOUS) ||
					      (sync_flags & VM_SYNC_ASYNCHRONOUS)),
					     sync_flags & VM_SYNC_SYNCHRONOUS);
		/*
		 * only send a m_o_s if we returned pages or if the entry
		 * is writable (ie dirty pages may have already been sent back)
		 */
		if (!do_sync_req) {
			if ((sync_flags & VM_SYNC_INVALIDATE) && object->resident_page_count == 0) {
				/*
				 * clear out the clustering and read-ahead hints
				 */
				vm_object_lock(object);

				object->pages_created = 0;
				object->pages_used = 0;
				object->sequential = 0;
				object->last_alloc = 0;

				vm_object_unlock(object);
			}
			vm_object_deallocate(object);
			continue;
		}
		msync_req_alloc(new_msr);

                vm_object_lock(object);
		offset += object->paging_offset;

		new_msr->offset = offset;
		new_msr->length = flush_size;
		new_msr->object = object;
		new_msr->flag = VM_MSYNC_SYNCHRONIZING;
	re_iterate:

		/*
		 * We can't sync this object if there isn't a pager.  The
		 * pager can disappear anytime we're not holding the object
		 * lock.  So this has to be checked anytime we goto re_iterate.
		 */

		pager = object->pager;

		if (pager == MEMORY_OBJECT_NULL) {
			vm_object_unlock(object);
			vm_object_deallocate(object);
			continue;
		}

		queue_iterate(&object->msr_q, msr, msync_req_t, msr_q) {
			/*
			 * need to check for overlapping entry, if found, wait
			 * on overlapping msr to be done, then reiterate
			 */
			msr_lock(msr);
			if (msr->flag == VM_MSYNC_SYNCHRONIZING &&
			    ((offset >= msr->offset && 
			      offset < (msr->offset + msr->length)) ||
			     (msr->offset >= offset &&
			      msr->offset < (offset + flush_size))))
			{
				assert_wait((event_t) msr,THREAD_INTERRUPTIBLE);
				msr_unlock(msr);
				vm_object_unlock(object);
				thread_block(THREAD_CONTINUE_NULL);
				vm_object_lock(object);
				goto re_iterate;
			}
			msr_unlock(msr);
		}/* queue_iterate */

		queue_enter(&object->msr_q, new_msr, msync_req_t, msr_q);

		vm_object_paging_begin(object);
		vm_object_unlock(object);

		queue_enter(&req_q, new_msr, msync_req_t, req_q);

		(void) memory_object_synchronize(
			pager,
			offset,
			flush_size,
			sync_flags & ~VM_SYNC_CONTIGUOUS);

		vm_object_lock(object);
		vm_object_paging_end(object);
		vm_object_unlock(object);
	}/* while */

	/*
	 * wait for memory_object_sychronize_completed messages from pager(s)
	 */

	while (!queue_empty(&req_q)) {
		msr = (msync_req_t)queue_first(&req_q);
		msr_lock(msr);
		while(msr->flag != VM_MSYNC_DONE) {
			assert_wait((event_t) msr, THREAD_INTERRUPTIBLE);
			msr_unlock(msr);
			thread_block(THREAD_CONTINUE_NULL);
			msr_lock(msr);
		}/* while */
		queue_remove(&req_q, msr, msync_req_t, req_q);
		msr_unlock(msr);
		vm_object_deallocate(msr->object);
		msync_req_free(msr);
	}/* queue_iterate */

	/* for proper msync() behaviour */
	if (had_hole == TRUE && (sync_flags & VM_SYNC_CONTIGUOUS))
		return(KERN_INVALID_ADDRESS);

	return(KERN_SUCCESS);
}/* vm_msync */

/*
 *	Routine:	convert_port_entry_to_map
 *	Purpose:
 *		Convert from a port specifying an entry or a task
 *		to a map. Doesn't consume the port ref; produces a map ref,
 *		which may be null.  Unlike convert_port_to_map, the
 *		port may be task or a named entry backed.
 *	Conditions:
 *		Nothing locked.
 */


vm_map_t
convert_port_entry_to_map(
	ipc_port_t	port)
{
	vm_map_t map;
	vm_named_entry_t	named_entry;
	uint32_t	try_failed_count = 0;

	if(IP_VALID(port) && (ip_kotype(port) == IKOT_NAMED_ENTRY)) {
		while(TRUE) {
			ip_lock(port);
			if(ip_active(port) && (ip_kotype(port) 
					       == IKOT_NAMED_ENTRY)) {
				named_entry =
					(vm_named_entry_t)port->ip_kobject;
				if (!(lck_mtx_try_lock(&(named_entry)->Lock))) {
                       			ip_unlock(port);

					try_failed_count++;
                       			mutex_pause(try_failed_count);
                       			continue;
                		}
				named_entry->ref_count++;
				lck_mtx_unlock(&(named_entry)->Lock);
				ip_unlock(port);
				if ((named_entry->is_sub_map) &&
				    (named_entry->protection 
				     & VM_PROT_WRITE)) {
					map = named_entry->backing.map;
				} else {
					mach_destroy_memory_entry(port);
					return VM_MAP_NULL;
				}
				vm_map_reference_swap(map);
				mach_destroy_memory_entry(port);
				break;
			}
			else 
				return VM_MAP_NULL;
		}
	}
	else
		map = convert_port_to_map(port);

	return map;
}

/*
 *	Routine:	convert_port_entry_to_object
 *	Purpose:
 *		Convert from a port specifying a named entry to an
 *		object. Doesn't consume the port ref; produces a map ref,
 *		which may be null. 
 *	Conditions:
 *		Nothing locked.
 */


vm_object_t
convert_port_entry_to_object(
	ipc_port_t	port)
{
	vm_object_t object;
	vm_named_entry_t	named_entry;
	uint32_t	try_failed_count = 0;

	if(IP_VALID(port) && (ip_kotype(port) == IKOT_NAMED_ENTRY)) {
		while(TRUE) {
			ip_lock(port);
			if(ip_active(port) && (ip_kotype(port) 
					       == IKOT_NAMED_ENTRY)) {
				named_entry =
					(vm_named_entry_t)port->ip_kobject;
				if (!(lck_mtx_try_lock(&(named_entry)->Lock))) {
                       			ip_unlock(port);

					try_failed_count++;
                       			mutex_pause(try_failed_count);
                       			continue;
                		}
				named_entry->ref_count++;
				lck_mtx_unlock(&(named_entry)->Lock);
				ip_unlock(port);
				if ((!named_entry->is_sub_map) &&
				    (!named_entry->is_pager) &&
				    (named_entry->protection 
				     & VM_PROT_WRITE)) {
					object = named_entry->backing.object;
				} else {
					mach_destroy_memory_entry(port);
					return (vm_object_t)NULL;
				}
				vm_object_reference(named_entry->backing.object);
				mach_destroy_memory_entry(port);
				break;
			}
			else 
				return (vm_object_t)NULL;
		}
	} else {
		return (vm_object_t)NULL;
	}

	return object;
}

/*
 * Export routines to other components for the things we access locally through
 * macros.
 */
#undef current_map
vm_map_t
current_map(void)
{
	return (current_map_fast());
}

/*
 *	vm_map_reference:
 *
 *	Most code internal to the osfmk will go through a
 *	macro defining this.  This is always here for the
 *	use of other kernel components.
 */
#undef vm_map_reference
void
vm_map_reference(
	register vm_map_t	map)
{
	if (map == VM_MAP_NULL)
		return;

	lck_mtx_lock(&map->s_lock);
#if	TASK_SWAPPER
	assert(map->res_count > 0);
	assert(map->ref_count >= map->res_count);
	map->res_count++;
#endif
	map->ref_count++;
	lck_mtx_unlock(&map->s_lock);
}

/*
 *	vm_map_deallocate:
 *
 *	Removes a reference from the specified map,
 *	destroying it if no references remain.
 *	The map should not be locked.
 */
void
vm_map_deallocate(
	register vm_map_t	map)
{
	unsigned int		ref;

	if (map == VM_MAP_NULL)
		return;

	lck_mtx_lock(&map->s_lock);
	ref = --map->ref_count;
	if (ref > 0) {
		vm_map_res_deallocate(map);
		lck_mtx_unlock(&map->s_lock);
		return;
	}
	assert(map->ref_count == 0);
	lck_mtx_unlock(&map->s_lock);

#if	TASK_SWAPPER
	/*
	 * The map residence count isn't decremented here because
	 * the vm_map_delete below will traverse the entire map, 
	 * deleting entries, and the residence counts on objects
	 * and sharing maps will go away then.
	 */
#endif

	vm_map_destroy(map, VM_MAP_NO_FLAGS);
}


void
vm_map_disable_NX(vm_map_t map)
{
        if (map == NULL)
	        return;
        if (map->pmap == NULL)
	        return;

        pmap_disable_NX(map->pmap);
}

void
vm_map_disallow_data_exec(vm_map_t map)
{
    if (map == NULL)
        return;

    map->map_disallow_data_exec = TRUE;
}

/* XXX Consider making these constants (VM_MAX_ADDRESS and MACH_VM_MAX_ADDRESS)
 * more descriptive.
 */
void
vm_map_set_32bit(vm_map_t map)
{
	map->max_offset = (vm_map_offset_t)VM_MAX_ADDRESS;
}


void
vm_map_set_64bit(vm_map_t map)
{
	map->max_offset = (vm_map_offset_t)MACH_VM_MAX_ADDRESS;
}

vm_map_offset_t
vm_compute_max_offset(unsigned is64)
{
	return (is64 ? (vm_map_offset_t)MACH_VM_MAX_ADDRESS : (vm_map_offset_t)VM_MAX_ADDRESS);
}

boolean_t
vm_map_is_64bit(
		vm_map_t map)
{
	return map->max_offset > ((vm_map_offset_t)VM_MAX_ADDRESS);
}

boolean_t
vm_map_has_4GB_pagezero(
		vm_map_t map)
{
	/*
	 * XXX FBDP
	 * We should lock the VM map (for read) here but we can get away
	 * with it for now because there can't really be any race condition:
	 * the VM map's min_offset is changed only when the VM map is created
	 * and when the zero page is established (when the binary gets loaded),
	 * and this routine gets called only when the task terminates and the
	 * VM map is being torn down, and when a new map is created via
	 * load_machfile()/execve().
	 */
	return (map->min_offset >= 0x100000000ULL);
}

void
vm_map_set_4GB_pagezero(vm_map_t map)
{
#if defined(__i386__)
	pmap_set_4GB_pagezero(map->pmap);
#else
#pragma unused(map)
#endif

}

void
vm_map_clear_4GB_pagezero(vm_map_t map)
{
#if defined(__i386__)
	pmap_clear_4GB_pagezero(map->pmap);
#else
#pragma unused(map)
#endif
}

/*
 * Raise a VM map's minimum offset.
 * To strictly enforce "page zero" reservation.
 */
kern_return_t
vm_map_raise_min_offset(
	vm_map_t	map,
	vm_map_offset_t	new_min_offset)
{
	vm_map_entry_t	first_entry;

	new_min_offset = vm_map_round_page(new_min_offset);

	vm_map_lock(map);

	if (new_min_offset < map->min_offset) {
		/*
		 * Can't move min_offset backwards, as that would expose
		 * a part of the address space that was previously, and for
		 * possibly good reasons, inaccessible.
		 */
		vm_map_unlock(map);
		return KERN_INVALID_ADDRESS;
	}

	first_entry = vm_map_first_entry(map);
	if (first_entry != vm_map_to_entry(map) &&
	    first_entry->vme_start < new_min_offset) {
		/*
		 * Some memory was already allocated below the new
		 * minimun offset.  It's too late to change it now...
		 */
		vm_map_unlock(map);
		return KERN_NO_SPACE;
	}

	map->min_offset = new_min_offset;

	vm_map_unlock(map);

	return KERN_SUCCESS;
}

/*
 * Set the limit on the maximum amount of user wired memory allowed for this map.
 * This is basically a copy of the MEMLOCK rlimit value maintained by the BSD side of
 * the kernel.  The limits are checked in the mach VM side, so we keep a copy so we
 * don't have to reach over to the BSD data structures.
 */

void
vm_map_set_user_wire_limit(vm_map_t 	map,
			   vm_size_t	limit)
{
	map->user_wire_limit = limit;
}


void vm_map_switch_protect(vm_map_t	map, 
			   boolean_t	val) 
{
	vm_map_lock(map);
	map->switch_protect=val;
	vm_map_unlock(map);
}

/* Add (generate) code signature for memory range */
#if CONFIG_DYNAMIC_CODE_SIGNING
kern_return_t vm_map_sign(vm_map_t map, 
		 vm_map_offset_t start, 
		 vm_map_offset_t end)
{
	vm_map_entry_t entry;
	vm_page_t m;
	vm_object_t object;
	
	/*
	 * Vet all the input parameters and current type and state of the
	 * underlaying object.  Return with an error if anything is amiss.
	 */
	if (map == VM_MAP_NULL)
		return(KERN_INVALID_ARGUMENT);
		
	vm_map_lock_read(map);
	
	if (!vm_map_lookup_entry(map, start, &entry) || entry->is_sub_map) {
		/*
		 * Must pass a valid non-submap address.
		 */
		vm_map_unlock_read(map);
		return(KERN_INVALID_ADDRESS);
	}
	
	if((entry->vme_start > start) || (entry->vme_end < end)) {
		/*
		 * Map entry doesn't cover the requested range. Not handling
		 * this situation currently.
		 */
		vm_map_unlock_read(map);
		return(KERN_INVALID_ARGUMENT);
	}
	
	object = entry->object.vm_object;
	if (object == VM_OBJECT_NULL) {
		/*
		 * Object must already be present or we can't sign.
		 */
		vm_map_unlock_read(map);
		return KERN_INVALID_ARGUMENT;
	}
	
	vm_object_lock(object);
	vm_map_unlock_read(map);
	
	while(start < end) {
		uint32_t refmod;
		
		m = vm_page_lookup(object, start - entry->vme_start + entry->offset );
		if (m==VM_PAGE_NULL) {
			/* shoud we try to fault a page here? we can probably 
			 * demand it exists and is locked for this request */
			vm_object_unlock(object);
			return KERN_FAILURE;
		}
		/* deal with special page status */
		if (m->busy || 
		    (m->unusual && (m->error || m->restart || m->private || m->absent))) {
			vm_object_unlock(object);
			return KERN_FAILURE;
		}
		
		/* Page is OK... now "validate" it */
		/* This is the place where we'll call out to create a code 
		 * directory, later */
		m->cs_validated = TRUE;

		/* The page is now "clean" for codesigning purposes. That means
		 * we don't consider it as modified (wpmapped) anymore. But 
		 * we'll disconnect the page so we note any future modification
		 * attempts. */
		m->wpmapped = FALSE;
		refmod = pmap_disconnect(m->phys_page);
		
		/* Pull the dirty status from the pmap, since we cleared the 
		 * wpmapped bit */
		if ((refmod & VM_MEM_MODIFIED) && !m->dirty) {
			m->dirty = TRUE;
		}
		
		/* On to the next page */
		start += PAGE_SIZE;
	}
	vm_object_unlock(object);
	
	return KERN_SUCCESS;
}
#endif

#if CONFIG_FREEZE

kern_return_t vm_map_freeze_walk(
             	vm_map_t map,
             	unsigned int *purgeable_count,
             	unsigned int *wired_count,
             	unsigned int *clean_count,
             	unsigned int *dirty_count,
             	boolean_t *has_shared)
{
	vm_map_entry_t entry;
	
	vm_map_lock_read(map);
	
	*purgeable_count = *wired_count = *clean_count = *dirty_count = 0;
	*has_shared = FALSE;
	
	for (entry = vm_map_first_entry(map);
	     entry != vm_map_to_entry(map);
	     entry = entry->vme_next) {
		unsigned int purgeable, clean, dirty, wired;
		boolean_t shared;

		if ((entry->object.vm_object == 0) ||
		    (entry->is_sub_map) ||
		    (entry->object.vm_object->phys_contiguous)) {
			continue;
		}

		vm_object_pack(&purgeable, &wired, &clean, &dirty, &shared, entry->object.vm_object, VM_OBJECT_NULL, NULL, NULL);
		
		*purgeable_count += purgeable;
		*wired_count += wired;
		*clean_count += clean;
		*dirty_count += dirty;
		
		if (shared) {
			*has_shared = TRUE;
		}
	}

	vm_map_unlock_read(map);

	return KERN_SUCCESS;
}

kern_return_t vm_map_freeze(
             	vm_map_t map,
             	unsigned int *purgeable_count,
             	unsigned int *wired_count,
             	unsigned int *clean_count,
             	unsigned int *dirty_count,
             	boolean_t *has_shared)
{	
	vm_map_entry_t entry2 = VM_MAP_ENTRY_NULL;
	vm_object_t compact_object = VM_OBJECT_NULL;
	vm_object_offset_t offset = 0x0;
	kern_return_t kr = KERN_SUCCESS;
	void *default_freezer_toc = NULL;
	boolean_t cleanup = FALSE;

	*purgeable_count = *wired_count = *clean_count = *dirty_count = 0;
	*has_shared = FALSE;

	/* Create our compact object */
	compact_object = vm_object_allocate((vm_map_offset_t)(VM_MAX_ADDRESS) - (vm_map_offset_t)(VM_MIN_ADDRESS));
	if (!compact_object) {
		kr = KERN_FAILURE;
		goto done;
	}
	
	default_freezer_toc = default_freezer_mapping_create(compact_object, offset);
	if (!default_freezer_toc) {
		kr = KERN_FAILURE;
		goto done;
	}

	/*
	 * We need the exclusive lock here so that we can
	 * block any page faults or lookups while we are
	 * in the middle of freezing this vm map.
	 */
	vm_map_lock(map);

	if (map->default_freezer_toc != NULL){
		/*
		 * This map has already been frozen.
		 */
		cleanup = TRUE;
		kr = KERN_SUCCESS;
		goto done;
	}

	/* Get a mapping in place for the freezing about to commence */
	map->default_freezer_toc = default_freezer_toc;

	vm_object_lock(compact_object);

	for (entry2 = vm_map_first_entry(map);
	     entry2 != vm_map_to_entry(map);
	     entry2 = entry2->vme_next) {
	
		vm_object_t	src_object = entry2->object.vm_object;

		/* If eligible, scan the entry, moving eligible pages over to our parent object */
		if (entry2->object.vm_object && !entry2->is_sub_map && !entry2->object.vm_object->phys_contiguous) {
			unsigned int purgeable, clean, dirty, wired;
			boolean_t shared;
    		
			vm_object_pack(&purgeable, &wired, &clean, &dirty, &shared,
							src_object, compact_object, &default_freezer_toc, &offset);
									 
			*purgeable_count += purgeable;
			*wired_count += wired;
			*clean_count += clean;
			*dirty_count += dirty;

			if (shared) {
				*has_shared = TRUE;
			}
		}
	}

	vm_object_unlock(compact_object);	
	
	/* Finally, throw out the pages to swap */
	vm_object_pageout(compact_object);

done:
	vm_map_unlock(map);

	/* Unwind if there was a failure */
	if ((cleanup) || (KERN_SUCCESS != kr)) {
		if (default_freezer_toc){
			default_freezer_mapping_free(&map->default_freezer_toc, TRUE);
		}
		if (compact_object){
			vm_object_deallocate(compact_object);
		}
	}
	
	return kr;
}

__private_extern__ vm_object_t	default_freezer_get_compact_vm_object( void** );

void
vm_map_thaw(
	vm_map_t map)
{
	void **default_freezer_toc;
	vm_object_t compact_object;

	vm_map_lock(map);

	if (map->default_freezer_toc == NULL){
		/*
		 * This map is not in a frozen state.
		 */
		goto out;
	}
	
	default_freezer_toc = &(map->default_freezer_toc);
	
	compact_object = default_freezer_get_compact_vm_object(default_freezer_toc);
	
	/* Bring the pages back in */
	vm_object_pagein(compact_object);
	
	/* Shift pages back to their original objects */
	vm_object_unpack(compact_object, default_freezer_toc);

	vm_object_deallocate(compact_object);

	map->default_freezer_toc = NULL;
	
out:
	vm_map_unlock(map);
}
#endif
