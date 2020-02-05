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
 *	File:	vm/vm_kern.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Kernel memory management.
 */

#include <mach/kern_return.h>
#include <mach/vm_param.h>
#include <kern/assert.h>
#include <kern/thread.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_compressor.h>
#include <vm/vm_pageout.h>
#include <kern/misc_protos.h>
#include <vm/cpm.h>
#include <kern/ledger.h>

#include <string.h>

#include <libkern/OSDebug.h>
#include <libkern/crypto/sha2.h>
#include <libkern/section_keywords.h>
#include <sys/kdebug.h>

#include <san/kasan.h>

/*
 *	Variables exported by this module.
 */

SECURITY_READ_ONLY_LATE(vm_map_t) kernel_map;
vm_map_t         kernel_pageable_map;

extern boolean_t vm_kernel_ready;

/*
 * Forward declarations for internal functions.
 */
extern kern_return_t kmem_alloc_pages(
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_object_size_t        size);

kern_return_t
kmem_alloc_contig(
	vm_map_t                map,
	vm_offset_t             *addrp,
	vm_size_t               size,
	vm_offset_t             mask,
	ppnum_t                 max_pnum,
	ppnum_t                 pnum_mask,
	int                     flags,
	vm_tag_t                tag)
{
	vm_object_t             object;
	vm_object_offset_t      offset;
	vm_map_offset_t         map_addr;
	vm_map_offset_t         map_mask;
	vm_map_size_t           map_size, i;
	vm_map_entry_t          entry;
	vm_page_t               m, pages;
	kern_return_t           kr;

	assert(VM_KERN_MEMORY_NONE != tag);

	if (map == VM_MAP_NULL || (flags & ~(KMA_KOBJECT | KMA_LOMEM | KMA_NOPAGEWAIT))) {
		return KERN_INVALID_ARGUMENT;
	}

	map_size = vm_map_round_page(size,
	    VM_MAP_PAGE_MASK(map));
	map_mask = (vm_map_offset_t)mask;

	/* Check for zero allocation size (either directly or via overflow) */
	if (map_size == 0) {
		*addrp = 0;
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 *	Allocate a new object (if necessary) and the reference we
	 *	will be donating to the map entry.  We must do this before
	 *	locking the map, or risk deadlock with the default pager.
	 */
	if ((flags & KMA_KOBJECT) != 0) {
		object = kernel_object;
		vm_object_reference(object);
	} else {
		object = vm_object_allocate(map_size);
	}

	kr = vm_map_find_space(map, &map_addr, map_size, map_mask, 0,
	    VM_MAP_KERNEL_FLAGS_NONE, tag, &entry);
	if (KERN_SUCCESS != kr) {
		vm_object_deallocate(object);
		return kr;
	}

	if (object == kernel_object) {
		offset = map_addr;
	} else {
		offset = 0;
	}
	VME_OBJECT_SET(entry, object);
	VME_OFFSET_SET(entry, offset);

	/* Take an extra object ref in case the map entry gets deleted */
	vm_object_reference(object);
	vm_map_unlock(map);

	kr = cpm_allocate(CAST_DOWN(vm_size_t, map_size), &pages, max_pnum, pnum_mask, FALSE, flags);

	if (kr != KERN_SUCCESS) {
		vm_map_remove(map,
		    vm_map_trunc_page(map_addr,
		    VM_MAP_PAGE_MASK(map)),
		    vm_map_round_page(map_addr + map_size,
		    VM_MAP_PAGE_MASK(map)),
		    VM_MAP_REMOVE_NO_FLAGS);
		vm_object_deallocate(object);
		*addrp = 0;
		return kr;
	}

	vm_object_lock(object);
	for (i = 0; i < map_size; i += PAGE_SIZE) {
		m = pages;
		pages = NEXT_PAGE(m);
		*(NEXT_PAGE_PTR(m)) = VM_PAGE_NULL;
		m->vmp_busy = FALSE;
		vm_page_insert(m, object, offset + i);
	}
	vm_object_unlock(object);

	kr = vm_map_wire_kernel(map,
	    vm_map_trunc_page(map_addr,
	    VM_MAP_PAGE_MASK(map)),
	    vm_map_round_page(map_addr + map_size,
	    VM_MAP_PAGE_MASK(map)),
	    VM_PROT_DEFAULT, tag,
	    FALSE);

	if (kr != KERN_SUCCESS) {
		if (object == kernel_object) {
			vm_object_lock(object);
			vm_object_page_remove(object, offset, offset + map_size);
			vm_object_unlock(object);
		}
		vm_map_remove(map,
		    vm_map_trunc_page(map_addr,
		    VM_MAP_PAGE_MASK(map)),
		    vm_map_round_page(map_addr + map_size,
		    VM_MAP_PAGE_MASK(map)),
		    VM_MAP_REMOVE_NO_FLAGS);
		vm_object_deallocate(object);
		return kr;
	}
	vm_object_deallocate(object);

	if (object == kernel_object) {
		vm_map_simplify(map, map_addr);
		vm_tag_update_size(tag, map_size);
	}
	*addrp = (vm_offset_t) map_addr;
	assert((vm_map_offset_t) *addrp == map_addr);

	return KERN_SUCCESS;
}

/*
 * Master entry point for allocating kernel memory.
 * NOTE: this routine is _never_ interrupt safe.
 *
 * map		: map to allocate into
 * addrp	: pointer to start address of new memory
 * size		: size of memory requested
 * flags	: options
 *		  KMA_HERE		*addrp is base address, else "anywhere"
 *		  KMA_NOPAGEWAIT	don't wait for pages if unavailable
 *		  KMA_KOBJECT		use kernel_object
 *		  KMA_LOMEM		support for 32 bit devices in a 64 bit world
 *					if set and a lomemory pool is available
 *					grab pages from it... this also implies
 *					KMA_NOPAGEWAIT
 */

kern_return_t
kernel_memory_allocate(
	vm_map_t        map,
	vm_offset_t     *addrp,
	vm_size_t       size,
	vm_offset_t     mask,
	int                     flags,
	vm_tag_t                tag)
{
	vm_object_t             object;
	vm_object_offset_t      offset;
	vm_object_offset_t      pg_offset;
	vm_map_entry_t          entry = NULL;
	vm_map_offset_t         map_addr, fill_start;
	vm_map_offset_t         map_mask;
	vm_map_size_t           map_size, fill_size;
	kern_return_t           kr, pe_result;
	vm_page_t               mem;
	vm_page_t               guard_page_list = NULL;
	vm_page_t               wired_page_list = NULL;
	int                     guard_page_count = 0;
	int                     wired_page_count = 0;
	int                     page_grab_count = 0;
	int                     i;
	int                     vm_alloc_flags;
	vm_map_kernel_flags_t   vmk_flags;
	vm_prot_t               kma_prot;
#if DEVELOPMENT || DEBUG
	task_t                                  task = current_task();
#endif /* DEVELOPMENT || DEBUG */

	if (!vm_kernel_ready) {
		panic("kernel_memory_allocate: VM is not ready");
	}

	map_size = vm_map_round_page(size,
	    VM_MAP_PAGE_MASK(map));
	map_mask = (vm_map_offset_t) mask;

	vm_alloc_flags = 0; //VM_MAKE_TAG(tag);
	vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;

	/* Check for zero allocation size (either directly or via overflow) */
	if (map_size == 0) {
		*addrp = 0;
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * limit the size of a single extent of wired memory
	 * to try and limit the damage to the system if
	 * too many pages get wired down
	 * limit raised to 2GB with 128GB max physical limit,
	 * but scaled by installed memory above this
	 */
	if (!(flags & (KMA_VAONLY | KMA_PAGEABLE)) &&
	    map_size > MAX(1ULL << 31, sane_size / 64)) {
		return KERN_RESOURCE_SHORTAGE;
	}

	/*
	 * Guard pages:
	 *
	 * Guard pages are implemented as ficticious pages.  By placing guard pages
	 * on either end of a stack, they can help detect cases where a thread walks
	 * off either end of its stack.  They are allocated and set up here and attempts
	 * to access those pages are trapped in vm_fault_page().
	 *
	 * The map_size we were passed may include extra space for
	 * guard pages.  If those were requested, then back it out of fill_size
	 * since vm_map_find_space() takes just the actual size not including
	 * guard pages.  Similarly, fill_start indicates where the actual pages
	 * will begin in the range.
	 */

	fill_start = 0;
	fill_size = map_size;

	if (flags & KMA_GUARD_FIRST) {
		vmk_flags.vmkf_guard_before = TRUE;
		fill_start += PAGE_SIZE_64;
		fill_size -= PAGE_SIZE_64;
		if (map_size < fill_start + fill_size) {
			/* no space for a guard page */
			*addrp = 0;
			return KERN_INVALID_ARGUMENT;
		}
		guard_page_count++;
	}
	if (flags & KMA_GUARD_LAST) {
		vmk_flags.vmkf_guard_after = TRUE;
		fill_size -= PAGE_SIZE_64;
		if (map_size <= fill_start + fill_size) {
			/* no space for a guard page */
			*addrp = 0;
			return KERN_INVALID_ARGUMENT;
		}
		guard_page_count++;
	}
	wired_page_count = (int) (fill_size / PAGE_SIZE_64);
	assert(wired_page_count * PAGE_SIZE_64 == fill_size);

#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, VM_KERN_REQUEST, DBG_FUNC_START, size, 0, 0, 0);
#endif

	for (i = 0; i < guard_page_count; i++) {
		for (;;) {
			mem = vm_page_grab_guard();

			if (mem != VM_PAGE_NULL) {
				break;
			}
			if (flags & KMA_NOPAGEWAIT) {
				kr = KERN_RESOURCE_SHORTAGE;
				goto out;
			}
			vm_page_more_fictitious();
		}
		mem->vmp_snext = guard_page_list;
		guard_page_list = mem;
	}

	if (!(flags & (KMA_VAONLY | KMA_PAGEABLE))) {
		for (i = 0; i < wired_page_count; i++) {
			for (;;) {
				if (flags & KMA_LOMEM) {
					mem = vm_page_grablo();
				} else {
					mem = vm_page_grab();
				}

				if (mem != VM_PAGE_NULL) {
					break;
				}

				if (flags & KMA_NOPAGEWAIT) {
					kr = KERN_RESOURCE_SHORTAGE;
					goto out;
				}
				if ((flags & KMA_LOMEM) && (vm_lopage_needed == TRUE)) {
					kr = KERN_RESOURCE_SHORTAGE;
					goto out;
				}

				/* VM privileged threads should have waited in vm_page_grab() and not get here. */
				assert(!(current_thread()->options & TH_OPT_VMPRIV));

				uint64_t unavailable = (vm_page_wire_count + vm_page_free_target) * PAGE_SIZE;
				if (unavailable > max_mem || map_size > (max_mem - unavailable)) {
					kr = KERN_RESOURCE_SHORTAGE;
					goto out;
				}
				VM_PAGE_WAIT();
			}
			page_grab_count++;
			if (KMA_ZERO & flags) {
				vm_page_zero_fill(mem);
			}
			mem->vmp_snext = wired_page_list;
			wired_page_list = mem;
		}
	}

	/*
	 *	Allocate a new object (if necessary).  We must do this before
	 *	locking the map, or risk deadlock with the default pager.
	 */
	if ((flags & KMA_KOBJECT) != 0) {
		object = kernel_object;
		vm_object_reference(object);
	} else if ((flags & KMA_COMPRESSOR) != 0) {
		object = compressor_object;
		vm_object_reference(object);
	} else {
		object = vm_object_allocate(map_size);
	}

	if (flags & KMA_ATOMIC) {
		vmk_flags.vmkf_atomic_entry = TRUE;
	}

	kr = vm_map_find_space(map, &map_addr,
	    fill_size, map_mask,
	    vm_alloc_flags, vmk_flags, tag, &entry);
	if (KERN_SUCCESS != kr) {
		vm_object_deallocate(object);
		goto out;
	}

	if (object == kernel_object || object == compressor_object) {
		offset = map_addr;
	} else {
		offset = 0;
	}
	VME_OBJECT_SET(entry, object);
	VME_OFFSET_SET(entry, offset);

	if (!(flags & (KMA_COMPRESSOR | KMA_PAGEABLE))) {
		entry->wired_count++;
	}

	if (flags & KMA_PERMANENT) {
		entry->permanent = TRUE;
	}

	if (object != kernel_object && object != compressor_object) {
		vm_object_reference(object);
	}

	vm_object_lock(object);
	vm_map_unlock(map);

	pg_offset = 0;

	if (fill_start) {
		if (guard_page_list == NULL) {
			panic("kernel_memory_allocate: guard_page_list == NULL");
		}

		mem = guard_page_list;
		guard_page_list = mem->vmp_snext;
		mem->vmp_snext = NULL;

		vm_page_insert(mem, object, offset + pg_offset);

		mem->vmp_busy = FALSE;
		pg_offset += PAGE_SIZE_64;
	}

	kma_prot = VM_PROT_READ | VM_PROT_WRITE;

#if KASAN
	if (!(flags & KMA_VAONLY)) {
		/* for VAONLY mappings we notify in populate only */
		kasan_notify_address(map_addr, size);
	}
#endif

	if (flags & (KMA_VAONLY | KMA_PAGEABLE)) {
		pg_offset = fill_start + fill_size;
	} else {
		for (pg_offset = fill_start; pg_offset < fill_start + fill_size; pg_offset += PAGE_SIZE_64) {
			if (wired_page_list == NULL) {
				panic("kernel_memory_allocate: wired_page_list == NULL");
			}

			mem = wired_page_list;
			wired_page_list = mem->vmp_snext;
			mem->vmp_snext = NULL;

			assert(mem->vmp_wire_count == 0);
			assert(mem->vmp_q_state == VM_PAGE_NOT_ON_Q);

			mem->vmp_q_state = VM_PAGE_IS_WIRED;
			mem->vmp_wire_count++;
			if (__improbable(mem->vmp_wire_count == 0)) {
				panic("kernel_memory_allocate(%p): wire_count overflow",
				    mem);
			}

			vm_page_insert_wired(mem, object, offset + pg_offset, tag);

			mem->vmp_busy = FALSE;
			mem->vmp_pmapped = TRUE;
			mem->vmp_wpmapped = TRUE;

			PMAP_ENTER_OPTIONS(kernel_pmap, map_addr + pg_offset, mem,
			    kma_prot, VM_PROT_NONE, ((flags & KMA_KSTACK) ? VM_MEM_STACK : 0), TRUE,
			    PMAP_OPTIONS_NOWAIT, pe_result);

			if (pe_result == KERN_RESOURCE_SHORTAGE) {
				vm_object_unlock(object);

				PMAP_ENTER(kernel_pmap, map_addr + pg_offset, mem,
				    kma_prot, VM_PROT_NONE, ((flags & KMA_KSTACK) ? VM_MEM_STACK : 0), TRUE,
				    pe_result);

				vm_object_lock(object);
			}

			assert(pe_result == KERN_SUCCESS);

			if (flags & KMA_NOENCRYPT) {
				bzero(CAST_DOWN(void *, (map_addr + pg_offset)), PAGE_SIZE);

				pmap_set_noencrypt(VM_PAGE_GET_PHYS_PAGE(mem));
			}
		}
		if (kernel_object == object) {
			vm_tag_update_size(tag, fill_size);
		}
	}
	if ((fill_start + fill_size) < map_size) {
		if (guard_page_list == NULL) {
			panic("kernel_memory_allocate: guard_page_list == NULL");
		}

		mem = guard_page_list;
		guard_page_list = mem->vmp_snext;
		mem->vmp_snext = NULL;

		vm_page_insert(mem, object, offset + pg_offset);

		mem->vmp_busy = FALSE;
	}
	if (guard_page_list || wired_page_list) {
		panic("kernel_memory_allocate: non empty list\n");
	}

	if (!(flags & (KMA_VAONLY | KMA_PAGEABLE))) {
		vm_page_lockspin_queues();
		vm_page_wire_count += wired_page_count;
		vm_page_unlock_queues();
	}

	vm_object_unlock(object);

	/*
	 * now that the pages are wired, we no longer have to fear coalesce
	 */
	if (object == kernel_object || object == compressor_object) {
		vm_map_simplify(map, map_addr);
	} else {
		vm_object_deallocate(object);
	}

#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, VM_KERN_REQUEST, DBG_FUNC_END, page_grab_count, 0, 0, 0);
	if (task != NULL) {
		ledger_credit(task->ledger, task_ledgers.pages_grabbed_kern, page_grab_count);
	}
#endif

	/*
	 *	Return the memory, not zeroed.
	 */
	*addrp = CAST_DOWN(vm_offset_t, map_addr);
	return KERN_SUCCESS;

out:
	if (guard_page_list) {
		vm_page_free_list(guard_page_list, FALSE);
	}

	if (wired_page_list) {
		vm_page_free_list(wired_page_list, FALSE);
	}

#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, VM_KERN_REQUEST, DBG_FUNC_END, page_grab_count, 0, 0, 0);
	if (task != NULL && kr == KERN_SUCCESS) {
		ledger_credit(task->ledger, task_ledgers.pages_grabbed_kern, page_grab_count);
	}
#endif

	return kr;
}

kern_return_t
kernel_memory_populate(
	vm_map_t        map,
	vm_offset_t     addr,
	vm_size_t       size,
	int             flags,
	vm_tag_t        tag)
{
	vm_object_t             object;
	vm_object_offset_t      offset, pg_offset;
	kern_return_t           kr, pe_result;
	vm_page_t               mem;
	vm_page_t               page_list = NULL;
	int                     page_count = 0;
	int                     page_grab_count = 0;
	int                     i;

#if DEBUG || DEVELOPMENT
	task_t                                  task = current_task();
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, VM_KERN_REQUEST, DBG_FUNC_START, size, 0, 0, 0);
#endif

	page_count = (int) (size / PAGE_SIZE_64);

	assert((flags & (KMA_COMPRESSOR | KMA_KOBJECT)) != (KMA_COMPRESSOR | KMA_KOBJECT));

	if (flags & KMA_COMPRESSOR) {
		pg_offset = page_count * PAGE_SIZE_64;

		do {
			for (;;) {
				mem = vm_page_grab();

				if (mem != VM_PAGE_NULL) {
					break;
				}

				VM_PAGE_WAIT();
			}
			page_grab_count++;
			if (KMA_ZERO & flags) {
				vm_page_zero_fill(mem);
			}
			mem->vmp_snext = page_list;
			page_list = mem;

			pg_offset -= PAGE_SIZE_64;

			kr = pmap_enter_options(kernel_pmap,
			    addr + pg_offset, VM_PAGE_GET_PHYS_PAGE(mem),
			    VM_PROT_READ | VM_PROT_WRITE, VM_PROT_NONE, 0, TRUE,
			    PMAP_OPTIONS_INTERNAL, NULL);
			assert(kr == KERN_SUCCESS);
		} while (pg_offset);

		offset = addr;
		object = compressor_object;

		vm_object_lock(object);

		for (pg_offset = 0;
		    pg_offset < size;
		    pg_offset += PAGE_SIZE_64) {
			mem = page_list;
			page_list = mem->vmp_snext;
			mem->vmp_snext = NULL;

			vm_page_insert(mem, object, offset + pg_offset);
			assert(mem->vmp_busy);

			mem->vmp_busy = FALSE;
			mem->vmp_pmapped = TRUE;
			mem->vmp_wpmapped = TRUE;
			mem->vmp_q_state = VM_PAGE_USED_BY_COMPRESSOR;
		}
		vm_object_unlock(object);

#if KASAN
		if (map == compressor_map) {
			kasan_notify_address_nopoison(addr, size);
		} else {
			kasan_notify_address(addr, size);
		}
#endif

#if DEBUG || DEVELOPMENT
		VM_DEBUG_CONSTANT_EVENT(vm_kern_request, VM_KERN_REQUEST, DBG_FUNC_END, page_grab_count, 0, 0, 0);
		if (task != NULL) {
			ledger_credit(task->ledger, task_ledgers.pages_grabbed_kern, page_grab_count);
		}
#endif
		return KERN_SUCCESS;
	}

	for (i = 0; i < page_count; i++) {
		for (;;) {
			if (flags & KMA_LOMEM) {
				mem = vm_page_grablo();
			} else {
				mem = vm_page_grab();
			}

			if (mem != VM_PAGE_NULL) {
				break;
			}

			if (flags & KMA_NOPAGEWAIT) {
				kr = KERN_RESOURCE_SHORTAGE;
				goto out;
			}
			if ((flags & KMA_LOMEM) &&
			    (vm_lopage_needed == TRUE)) {
				kr = KERN_RESOURCE_SHORTAGE;
				goto out;
			}
			VM_PAGE_WAIT();
		}
		page_grab_count++;
		if (KMA_ZERO & flags) {
			vm_page_zero_fill(mem);
		}
		mem->vmp_snext = page_list;
		page_list = mem;
	}
	if (flags & KMA_KOBJECT) {
		offset = addr;
		object = kernel_object;

		vm_object_lock(object);
	} else {
		/*
		 * If it's not the kernel object, we need to:
		 *      lock map;
		 *      lookup entry;
		 *      lock object;
		 *	take reference on object;
		 *      unlock map;
		 */
		panic("kernel_memory_populate(%p,0x%llx,0x%llx,0x%x): "
		    "!KMA_KOBJECT",
		    map, (uint64_t) addr, (uint64_t) size, flags);
	}

	for (pg_offset = 0;
	    pg_offset < size;
	    pg_offset += PAGE_SIZE_64) {
		if (page_list == NULL) {
			panic("kernel_memory_populate: page_list == NULL");
		}

		mem = page_list;
		page_list = mem->vmp_snext;
		mem->vmp_snext = NULL;

		assert(mem->vmp_q_state == VM_PAGE_NOT_ON_Q);
		mem->vmp_q_state = VM_PAGE_IS_WIRED;
		mem->vmp_wire_count++;
		if (__improbable(mem->vmp_wire_count == 0)) {
			panic("kernel_memory_populate(%p): wire_count overflow", mem);
		}

		vm_page_insert_wired(mem, object, offset + pg_offset, tag);

		mem->vmp_busy = FALSE;
		mem->vmp_pmapped = TRUE;
		mem->vmp_wpmapped = TRUE;

		PMAP_ENTER_OPTIONS(kernel_pmap, addr + pg_offset, mem,
		    VM_PROT_READ | VM_PROT_WRITE, VM_PROT_NONE,
		    ((flags & KMA_KSTACK) ? VM_MEM_STACK : 0), TRUE,
		    PMAP_OPTIONS_NOWAIT, pe_result);

		if (pe_result == KERN_RESOURCE_SHORTAGE) {
			vm_object_unlock(object);

			PMAP_ENTER(kernel_pmap, addr + pg_offset, mem,
			    VM_PROT_READ | VM_PROT_WRITE, VM_PROT_NONE,
			    ((flags & KMA_KSTACK) ? VM_MEM_STACK : 0), TRUE,
			    pe_result);

			vm_object_lock(object);
		}

		assert(pe_result == KERN_SUCCESS);

		if (flags & KMA_NOENCRYPT) {
			bzero(CAST_DOWN(void *, (addr + pg_offset)), PAGE_SIZE);
			pmap_set_noencrypt(VM_PAGE_GET_PHYS_PAGE(mem));
		}
	}
	vm_page_lockspin_queues();
	vm_page_wire_count += page_count;
	vm_page_unlock_queues();

#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, VM_KERN_REQUEST, DBG_FUNC_END, page_grab_count, 0, 0, 0);
	if (task != NULL) {
		ledger_credit(task->ledger, task_ledgers.pages_grabbed_kern, page_grab_count);
	}
#endif

	if (kernel_object == object) {
		vm_tag_update_size(tag, size);
	}

	vm_object_unlock(object);

#if KASAN
	if (map == compressor_map) {
		kasan_notify_address_nopoison(addr, size);
	} else {
		kasan_notify_address(addr, size);
	}
#endif
	return KERN_SUCCESS;

out:
	if (page_list) {
		vm_page_free_list(page_list, FALSE);
	}

#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, VM_KERN_REQUEST, DBG_FUNC_END, page_grab_count, 0, 0, 0);
	if (task != NULL && kr == KERN_SUCCESS) {
		ledger_credit(task->ledger, task_ledgers.pages_grabbed_kern, page_grab_count);
	}
#endif

	return kr;
}


void
kernel_memory_depopulate(
	vm_map_t        map,
	vm_offset_t     addr,
	vm_size_t       size,
	int             flags)
{
	vm_object_t             object;
	vm_object_offset_t      offset, pg_offset;
	vm_page_t               mem;
	vm_page_t               local_freeq = NULL;

	assert((flags & (KMA_COMPRESSOR | KMA_KOBJECT)) != (KMA_COMPRESSOR | KMA_KOBJECT));

	if (flags & KMA_COMPRESSOR) {
		offset = addr;
		object = compressor_object;

		vm_object_lock(object);
	} else if (flags & KMA_KOBJECT) {
		offset = addr;
		object = kernel_object;
		vm_object_lock(object);
	} else {
		offset = 0;
		object = NULL;
		/*
		 * If it's not the kernel object, we need to:
		 *      lock map;
		 *      lookup entry;
		 *      lock object;
		 *      unlock map;
		 */
		panic("kernel_memory_depopulate(%p,0x%llx,0x%llx,0x%x): "
		    "!KMA_KOBJECT",
		    map, (uint64_t) addr, (uint64_t) size, flags);
	}
	pmap_protect(kernel_map->pmap, offset, offset + size, VM_PROT_NONE);

	for (pg_offset = 0;
	    pg_offset < size;
	    pg_offset += PAGE_SIZE_64) {
		mem = vm_page_lookup(object, offset + pg_offset);

		assert(mem);

		if (mem->vmp_q_state != VM_PAGE_USED_BY_COMPRESSOR) {
			pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(mem));
		}

		mem->vmp_busy = TRUE;

		assert(mem->vmp_tabled);
		vm_page_remove(mem, TRUE);
		assert(mem->vmp_busy);

		assert(mem->vmp_pageq.next == 0 && mem->vmp_pageq.prev == 0);
		assert((mem->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR) ||
		    (mem->vmp_q_state == VM_PAGE_NOT_ON_Q));

		mem->vmp_q_state = VM_PAGE_NOT_ON_Q;
		mem->vmp_snext = local_freeq;
		local_freeq = mem;
	}
	vm_object_unlock(object);

	if (local_freeq) {
		vm_page_free_list(local_freeq, TRUE);
	}
}

/*
 *	kmem_alloc:
 *
 *	Allocate wired-down memory in the kernel's address map
 *	or a submap.  The memory is not zero-filled.
 */

kern_return_t
kmem_alloc_external(
	vm_map_t        map,
	vm_offset_t     *addrp,
	vm_size_t       size)
{
	return kmem_alloc(map, addrp, size, vm_tag_bt());
}


kern_return_t
kmem_alloc(
	vm_map_t        map,
	vm_offset_t     *addrp,
	vm_size_t       size,
	vm_tag_t        tag)
{
	return kmem_alloc_flags(map, addrp, size, tag, 0);
}

kern_return_t
kmem_alloc_flags(
	vm_map_t        map,
	vm_offset_t     *addrp,
	vm_size_t       size,
	vm_tag_t        tag,
	int             flags)
{
	kern_return_t kr = kernel_memory_allocate(map, addrp, size, 0, flags, tag);
	TRACE_MACHLEAKS(KMEM_ALLOC_CODE, KMEM_ALLOC_CODE_2, size, *addrp);
	return kr;
}

/*
 *	kmem_realloc:
 *
 *	Reallocate wired-down memory in the kernel's address map
 *	or a submap.  Newly allocated pages are not zeroed.
 *	This can only be used on regions allocated with kmem_alloc.
 *
 *	If successful, the pages in the old region are mapped twice.
 *	The old region is unchanged.  Use kmem_free to get rid of it.
 */
kern_return_t
kmem_realloc(
	vm_map_t                map,
	vm_offset_t             oldaddr,
	vm_size_t               oldsize,
	vm_offset_t             *newaddrp,
	vm_size_t               newsize,
	vm_tag_t                tag)
{
	vm_object_t             object;
	vm_object_offset_t      offset;
	vm_map_offset_t         oldmapmin;
	vm_map_offset_t         oldmapmax;
	vm_map_offset_t         newmapaddr;
	vm_map_size_t           oldmapsize;
	vm_map_size_t           newmapsize;
	vm_map_entry_t          oldentry;
	vm_map_entry_t          newentry;
	vm_page_t               mem;
	kern_return_t           kr;

	oldmapmin = vm_map_trunc_page(oldaddr,
	    VM_MAP_PAGE_MASK(map));
	oldmapmax = vm_map_round_page(oldaddr + oldsize,
	    VM_MAP_PAGE_MASK(map));
	oldmapsize = oldmapmax - oldmapmin;
	newmapsize = vm_map_round_page(newsize,
	    VM_MAP_PAGE_MASK(map));
	if (newmapsize < newsize) {
		/* overflow */
		*newaddrp = 0;
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 *	Find the VM object backing the old region.
	 */

	vm_map_lock(map);

	if (!vm_map_lookup_entry(map, oldmapmin, &oldentry)) {
		panic("kmem_realloc");
	}
	object = VME_OBJECT(oldentry);

	/*
	 *	Increase the size of the object and
	 *	fill in the new region.
	 */

	vm_object_reference(object);
	/* by grabbing the object lock before unlocking the map */
	/* we guarantee that we will panic if more than one     */
	/* attempt is made to realloc a kmem_alloc'd area       */
	vm_object_lock(object);
	vm_map_unlock(map);
	if (object->vo_size != oldmapsize) {
		panic("kmem_realloc");
	}
	object->vo_size = newmapsize;
	vm_object_unlock(object);

	/* allocate the new pages while expanded portion of the */
	/* object is still not mapped */
	kmem_alloc_pages(object, vm_object_round_page(oldmapsize),
	    vm_object_round_page(newmapsize - oldmapsize));

	/*
	 *	Find space for the new region.
	 */

	kr = vm_map_find_space(map, &newmapaddr, newmapsize,
	    (vm_map_offset_t) 0, 0,
	    VM_MAP_KERNEL_FLAGS_NONE,
	    tag,
	    &newentry);
	if (kr != KERN_SUCCESS) {
		vm_object_lock(object);
		for (offset = oldmapsize;
		    offset < newmapsize; offset += PAGE_SIZE) {
			if ((mem = vm_page_lookup(object, offset)) != VM_PAGE_NULL) {
				VM_PAGE_FREE(mem);
			}
		}
		object->vo_size = oldmapsize;
		vm_object_unlock(object);
		vm_object_deallocate(object);
		return kr;
	}
	VME_OBJECT_SET(newentry, object);
	VME_OFFSET_SET(newentry, 0);
	assert(newentry->wired_count == 0);


	/* add an extra reference in case we have someone doing an */
	/* unexpected deallocate */
	vm_object_reference(object);
	vm_map_unlock(map);

	kr = vm_map_wire_kernel(map, newmapaddr, newmapaddr + newmapsize,
	    VM_PROT_DEFAULT, tag, FALSE);
	if (KERN_SUCCESS != kr) {
		vm_map_remove(map, newmapaddr, newmapaddr + newmapsize, VM_MAP_REMOVE_NO_FLAGS);
		vm_object_lock(object);
		for (offset = oldsize; offset < newmapsize; offset += PAGE_SIZE) {
			if ((mem = vm_page_lookup(object, offset)) != VM_PAGE_NULL) {
				VM_PAGE_FREE(mem);
			}
		}
		object->vo_size = oldmapsize;
		vm_object_unlock(object);
		vm_object_deallocate(object);
		return kr;
	}
	vm_object_deallocate(object);

	if (kernel_object == object) {
		vm_tag_update_size(tag, newmapsize);
	}

	*newaddrp = CAST_DOWN(vm_offset_t, newmapaddr);
	return KERN_SUCCESS;
}

/*
 *	kmem_alloc_kobject:
 *
 *	Allocate wired-down memory in the kernel's address map
 *	or a submap.  The memory is not zero-filled.
 *
 *	The memory is allocated in the kernel_object.
 *	It may not be copied with vm_map_copy, and
 *	it may not be reallocated with kmem_realloc.
 */

kern_return_t
kmem_alloc_kobject_external(
	vm_map_t        map,
	vm_offset_t     *addrp,
	vm_size_t       size)
{
	return kmem_alloc_kobject(map, addrp, size, vm_tag_bt());
}

kern_return_t
kmem_alloc_kobject(
	vm_map_t        map,
	vm_offset_t     *addrp,
	vm_size_t       size,
	vm_tag_t        tag)
{
	return kernel_memory_allocate(map, addrp, size, 0, KMA_KOBJECT, tag);
}

/*
 *	kmem_alloc_aligned:
 *
 *	Like kmem_alloc_kobject, except that the memory is aligned.
 *	The size should be a power-of-2.
 */

kern_return_t
kmem_alloc_aligned(
	vm_map_t        map,
	vm_offset_t     *addrp,
	vm_size_t       size,
	vm_tag_t        tag)
{
	if ((size & (size - 1)) != 0) {
		panic("kmem_alloc_aligned: size not aligned");
	}
	return kernel_memory_allocate(map, addrp, size, size - 1, KMA_KOBJECT, tag);
}

/*
 *	kmem_alloc_pageable:
 *
 *	Allocate pageable memory in the kernel's address map.
 */

kern_return_t
kmem_alloc_pageable_external(
	vm_map_t        map,
	vm_offset_t     *addrp,
	vm_size_t       size)
{
	return kmem_alloc_pageable(map, addrp, size, vm_tag_bt());
}

kern_return_t
kmem_alloc_pageable(
	vm_map_t        map,
	vm_offset_t     *addrp,
	vm_size_t       size,
	vm_tag_t        tag)
{
	vm_map_offset_t map_addr;
	vm_map_size_t   map_size;
	kern_return_t kr;

#ifndef normal
	map_addr = (vm_map_min(map)) + PAGE_SIZE;
#else
	map_addr = vm_map_min(map);
#endif
	map_size = vm_map_round_page(size,
	    VM_MAP_PAGE_MASK(map));
	if (map_size < size) {
		/* overflow */
		*addrp = 0;
		return KERN_INVALID_ARGUMENT;
	}

	kr = vm_map_enter(map, &map_addr, map_size,
	    (vm_map_offset_t) 0,
	    VM_FLAGS_ANYWHERE,
	    VM_MAP_KERNEL_FLAGS_NONE,
	    tag,
	    VM_OBJECT_NULL, (vm_object_offset_t) 0, FALSE,
	    VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);

	if (kr != KERN_SUCCESS) {
		return kr;
	}

#if KASAN
	kasan_notify_address(map_addr, map_size);
#endif
	*addrp = CAST_DOWN(vm_offset_t, map_addr);
	return KERN_SUCCESS;
}

/*
 *	kmem_free:
 *
 *	Release a region of kernel virtual memory allocated
 *	with kmem_alloc, kmem_alloc_kobject, or kmem_alloc_pageable,
 *	and return the physical pages associated with that region.
 */

void
kmem_free(
	vm_map_t        map,
	vm_offset_t     addr,
	vm_size_t       size)
{
	kern_return_t kr;

	assert(addr >= VM_MIN_KERNEL_AND_KEXT_ADDRESS);

	TRACE_MACHLEAKS(KMEM_FREE_CODE, KMEM_FREE_CODE_2, size, addr);

	if (size == 0) {
#if MACH_ASSERT
		printf("kmem_free called with size==0 for map: %p with addr: 0x%llx\n", map, (uint64_t)addr);
#endif
		return;
	}

	kr = vm_map_remove(map,
	    vm_map_trunc_page(addr,
	    VM_MAP_PAGE_MASK(map)),
	    vm_map_round_page(addr + size,
	    VM_MAP_PAGE_MASK(map)),
	    VM_MAP_REMOVE_KUNWIRE);
	if (kr != KERN_SUCCESS) {
		panic("kmem_free");
	}
}

/*
 *	Allocate new pages in an object.
 */

kern_return_t
kmem_alloc_pages(
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_object_size_t        size)
{
	vm_object_size_t                alloc_size;

	alloc_size = vm_object_round_page(size);
	vm_object_lock(object);
	while (alloc_size) {
		vm_page_t   mem;


		/*
		 *	Allocate a page
		 */
		while (VM_PAGE_NULL ==
		    (mem = vm_page_alloc(object, offset))) {
			vm_object_unlock(object);
			VM_PAGE_WAIT();
			vm_object_lock(object);
		}
		mem->vmp_busy = FALSE;

		alloc_size -= PAGE_SIZE;
		offset += PAGE_SIZE;
	}
	vm_object_unlock(object);
	return KERN_SUCCESS;
}

/*
 *	kmem_suballoc:
 *
 *	Allocates a map to manage a subrange
 *	of the kernel virtual address space.
 *
 *	Arguments are as follows:
 *
 *	parent		Map to take range from
 *	addr		Address of start of range (IN/OUT)
 *	size		Size of range to find
 *	pageable	Can region be paged
 *	anywhere	Can region be located anywhere in map
 *	new_map		Pointer to new submap
 */
kern_return_t
kmem_suballoc(
	vm_map_t        parent,
	vm_offset_t     *addr,
	vm_size_t       size,
	boolean_t       pageable,
	int             flags,
	vm_map_kernel_flags_t vmk_flags,
	vm_tag_t    tag,
	vm_map_t        *new_map)
{
	vm_map_t        map;
	vm_map_offset_t map_addr;
	vm_map_size_t   map_size;
	kern_return_t   kr;

	map_size = vm_map_round_page(size,
	    VM_MAP_PAGE_MASK(parent));
	if (map_size < size) {
		/* overflow */
		*addr = 0;
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 *	Need reference on submap object because it is internal
	 *	to the vm_system.  vm_object_enter will never be called
	 *	on it (usual source of reference for vm_map_enter).
	 */
	vm_object_reference(vm_submap_object);

	map_addr = ((flags & VM_FLAGS_ANYWHERE)
	    ? vm_map_min(parent)
	    : vm_map_trunc_page(*addr,
	    VM_MAP_PAGE_MASK(parent)));

	kr = vm_map_enter(parent, &map_addr, map_size,
	    (vm_map_offset_t) 0, flags, vmk_flags, tag,
	    vm_submap_object, (vm_object_offset_t) 0, FALSE,
	    VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);
	if (kr != KERN_SUCCESS) {
		vm_object_deallocate(vm_submap_object);
		return kr;
	}

	pmap_reference(vm_map_pmap(parent));
	map = vm_map_create(vm_map_pmap(parent), map_addr, map_addr + map_size, pageable);
	if (map == VM_MAP_NULL) {
		panic("kmem_suballoc: vm_map_create failed");   /* "can't happen" */
	}
	/* inherit the parent map's page size */
	vm_map_set_page_shift(map, VM_MAP_PAGE_SHIFT(parent));

	kr = vm_map_submap(parent, map_addr, map_addr + map_size, map, map_addr, FALSE);
	if (kr != KERN_SUCCESS) {
		/*
		 * See comment preceding vm_map_submap().
		 */
		vm_map_remove(parent, map_addr, map_addr + map_size,
		    VM_MAP_REMOVE_NO_FLAGS);
		vm_map_deallocate(map); /* also removes ref to pmap */
		vm_object_deallocate(vm_submap_object);
		return kr;
	}
	*addr = CAST_DOWN(vm_offset_t, map_addr);
	*new_map = map;
	return KERN_SUCCESS;
}

/*
 *	kmem_init:
 *
 *	Initialize the kernel's virtual memory map, taking
 *	into account all memory allocated up to this time.
 */
void
kmem_init(
	vm_offset_t     start,
	vm_offset_t     end)
{
	vm_map_offset_t map_start;
	vm_map_offset_t map_end;
	vm_map_kernel_flags_t vmk_flags;

	vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
	vmk_flags.vmkf_permanent = TRUE;
	vmk_flags.vmkf_no_pmap_check = TRUE;

	map_start = vm_map_trunc_page(start,
	    VM_MAP_PAGE_MASK(kernel_map));
	map_end = vm_map_round_page(end,
	    VM_MAP_PAGE_MASK(kernel_map));

#if     defined(__arm__) || defined(__arm64__)
	kernel_map = vm_map_create(pmap_kernel(), VM_MIN_KERNEL_AND_KEXT_ADDRESS,
	    VM_MAX_KERNEL_ADDRESS, FALSE);
	/*
	 *	Reserve virtual memory allocated up to this time.
	 */
	{
		unsigned int    region_select = 0;
		vm_map_offset_t region_start;
		vm_map_size_t   region_size;
		vm_map_offset_t map_addr;
		kern_return_t kr;

		while (pmap_virtual_region(region_select, &region_start, &region_size)) {
			map_addr = region_start;
			kr = vm_map_enter(kernel_map, &map_addr,
			    vm_map_round_page(region_size,
			    VM_MAP_PAGE_MASK(kernel_map)),
			    (vm_map_offset_t) 0,
			    VM_FLAGS_FIXED,
			    vmk_flags,
			    VM_KERN_MEMORY_NONE,
			    VM_OBJECT_NULL,
			    (vm_object_offset_t) 0, FALSE, VM_PROT_NONE, VM_PROT_NONE,
			    VM_INHERIT_DEFAULT);

			if (kr != KERN_SUCCESS) {
				panic("kmem_init(0x%llx,0x%llx): vm_map_enter(0x%llx,0x%llx) error 0x%x\n",
				    (uint64_t) start, (uint64_t) end, (uint64_t) region_start,
				    (uint64_t) region_size, kr);
			}

			region_select++;
		}
	}
#else
	kernel_map = vm_map_create(pmap_kernel(), VM_MIN_KERNEL_AND_KEXT_ADDRESS,
	    map_end, FALSE);
	/*
	 *	Reserve virtual memory allocated up to this time.
	 */
	if (start != VM_MIN_KERNEL_AND_KEXT_ADDRESS) {
		vm_map_offset_t map_addr;
		kern_return_t kr;

		vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
		vmk_flags.vmkf_no_pmap_check = TRUE;

		map_addr = VM_MIN_KERNEL_AND_KEXT_ADDRESS;
		kr = vm_map_enter(kernel_map,
		    &map_addr,
		    (vm_map_size_t)(map_start - VM_MIN_KERNEL_AND_KEXT_ADDRESS),
		    (vm_map_offset_t) 0,
		    VM_FLAGS_FIXED,
		    vmk_flags,
		    VM_KERN_MEMORY_NONE,
		    VM_OBJECT_NULL,
		    (vm_object_offset_t) 0, FALSE,
		    VM_PROT_NONE, VM_PROT_NONE,
		    VM_INHERIT_DEFAULT);

		if (kr != KERN_SUCCESS) {
			panic("kmem_init(0x%llx,0x%llx): vm_map_enter(0x%llx,0x%llx) error 0x%x\n",
			    (uint64_t) start, (uint64_t) end,
			    (uint64_t) VM_MIN_KERNEL_AND_KEXT_ADDRESS,
			    (uint64_t) (map_start - VM_MIN_KERNEL_AND_KEXT_ADDRESS),
			    kr);
		}
	}
#endif

	/*
	 * Set the default global user wire limit which limits the amount of
	 * memory that can be locked via mlock().  We set this to the total
	 * amount of memory that are potentially usable by a user app (max_mem)
	 * minus a certain amount.  This can be overridden via a sysctl.
	 */
	vm_global_no_user_wire_amount = MIN(max_mem * 20 / 100,
	    VM_NOT_USER_WIREABLE);
	vm_global_user_wire_limit = max_mem - vm_global_no_user_wire_amount;

	/* the default per user limit is the same as the global limit */
	vm_user_wire_limit = vm_global_user_wire_limit;
}


/*
 *	Routine:	copyinmap
 *	Purpose:
 *		Like copyin, except that fromaddr is an address
 *		in the specified VM map.  This implementation
 *		is incomplete; it handles the current user map
 *		and the kernel map/submaps.
 */
kern_return_t
copyinmap(
	vm_map_t                map,
	vm_map_offset_t         fromaddr,
	void                    *todata,
	vm_size_t               length)
{
	kern_return_t   kr = KERN_SUCCESS;
	vm_map_t oldmap;

	if (vm_map_pmap(map) == pmap_kernel()) {
		/* assume a correct copy */
		memcpy(todata, CAST_DOWN(void *, fromaddr), length);
	} else if (current_map() == map) {
		if (copyin(fromaddr, todata, length) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
	} else {
		vm_map_reference(map);
		oldmap = vm_map_switch(map);
		if (copyin(fromaddr, todata, length) != 0) {
			kr = KERN_INVALID_ADDRESS;
		}
		vm_map_switch(oldmap);
		vm_map_deallocate(map);
	}
	return kr;
}

/*
 *	Routine:	copyoutmap
 *	Purpose:
 *		Like copyout, except that toaddr is an address
 *		in the specified VM map.  This implementation
 *		is incomplete; it handles the current user map
 *		and the kernel map/submaps.
 */
kern_return_t
copyoutmap(
	vm_map_t                map,
	void                    *fromdata,
	vm_map_address_t        toaddr,
	vm_size_t               length)
{
	if (vm_map_pmap(map) == pmap_kernel()) {
		/* assume a correct copy */
		memcpy(CAST_DOWN(void *, toaddr), fromdata, length);
		return KERN_SUCCESS;
	}

	if (current_map() != map) {
		return KERN_NOT_SUPPORTED;
	}

	if (copyout(fromdata, toaddr, length) != 0) {
		return KERN_INVALID_ADDRESS;
	}

	return KERN_SUCCESS;
}

/*
 *
 *	The following two functions are to be used when exposing kernel
 *	addresses to userspace via any of the various debug or info
 *	facilities that exist. These are basically the same as VM_KERNEL_ADDRPERM()
 *	and VM_KERNEL_UNSLIDE_OR_PERM() except they use a different random seed and
 *	are exported to KEXTs.
 *
 *	NOTE: USE THE MACRO VERSIONS OF THESE FUNCTIONS (in vm_param.h) FROM WITHIN THE KERNEL
 */

static void
vm_kernel_addrhash_internal(
	vm_offset_t addr,
	vm_offset_t *hash_addr,
	uint64_t salt)
{
	assert(salt != 0);

	if (addr == 0) {
		*hash_addr = 0;
		return;
	}

	if (VM_KERNEL_IS_SLID(addr)) {
		*hash_addr = VM_KERNEL_UNSLIDE(addr);
		return;
	}

	vm_offset_t sha_digest[SHA256_DIGEST_LENGTH / sizeof(vm_offset_t)];
	SHA256_CTX sha_ctx;

	SHA256_Init(&sha_ctx);
	SHA256_Update(&sha_ctx, &salt, sizeof(salt));
	SHA256_Update(&sha_ctx, &addr, sizeof(addr));
	SHA256_Final(sha_digest, &sha_ctx);

	*hash_addr = sha_digest[0];
}

void
vm_kernel_addrhash_external(
	vm_offset_t addr,
	vm_offset_t *hash_addr)
{
	return vm_kernel_addrhash_internal(addr, hash_addr, vm_kernel_addrhash_salt_ext);
}

vm_offset_t
vm_kernel_addrhash(vm_offset_t addr)
{
	vm_offset_t hash_addr;
	vm_kernel_addrhash_internal(addr, &hash_addr, vm_kernel_addrhash_salt);
	return hash_addr;
}

void
vm_kernel_addrhide(
	vm_offset_t addr,
	vm_offset_t *hide_addr)
{
	*hide_addr = VM_KERNEL_ADDRHIDE(addr);
}

/*
 *	vm_kernel_addrperm_external:
 *	vm_kernel_unslide_or_perm_external:
 *
 *	Use these macros when exposing an address to userspace that could come from
 *	either kernel text/data *or* the heap.
 */
void
vm_kernel_addrperm_external(
	vm_offset_t addr,
	vm_offset_t *perm_addr)
{
	if (VM_KERNEL_IS_SLID(addr)) {
		*perm_addr = VM_KERNEL_UNSLIDE(addr);
	} else if (VM_KERNEL_ADDRESS(addr)) {
		*perm_addr = addr + vm_kernel_addrperm_ext;
	} else {
		*perm_addr = addr;
	}
}

void
vm_kernel_unslide_or_perm_external(
	vm_offset_t addr,
	vm_offset_t *up_addr)
{
	vm_kernel_addrperm_external(addr, up_addr);
}
