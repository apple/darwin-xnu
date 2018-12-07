/*
 * Copyright (c) 2000-2011 Apple Computer, Inc. All rights reserved.
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
 *	File:	kern/kalloc.c
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1985
 *
 *	General kernel memory allocator.  This allocator is designed
 *	to be used by the kernel to manage dynamic memory fast.
 */

#include <zone_debug.h>

#include <mach/boolean.h>
#include <mach/sdt.h>
#include <mach/machine/vm_types.h>
#include <mach/vm_param.h>
#include <kern/misc_protos.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <kern/ledger.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_map.h>
#include <libkern/OSMalloc.h>
#include <sys/kdebug.h>

#include <san/kasan.h>

#ifdef MACH_BSD
zone_t kalloc_zone(vm_size_t);
#endif

#define KALLOC_MAP_SIZE_MIN  (16 * 1024 * 1024)
#define KALLOC_MAP_SIZE_MAX  (128 * 1024 * 1024)
vm_map_t kalloc_map;
vm_size_t kalloc_max;
vm_size_t kalloc_max_prerounded;
vm_size_t kalloc_kernmap_size;	/* size of kallocs that can come from kernel map */

/* how many times we couldn't allocate out of kalloc_map and fell back to kernel_map */
unsigned long kalloc_fallback_count;

unsigned int kalloc_large_inuse;
vm_size_t    kalloc_large_total;
vm_size_t    kalloc_large_max;
vm_size_t    kalloc_largest_allocated = 0;
uint64_t    kalloc_large_sum;

int	kalloc_fake_zone_index = -1; /* index of our fake zone in statistics arrays */

vm_offset_t	kalloc_map_min;
vm_offset_t	kalloc_map_max;

#ifdef	MUTEX_ZONE
/*
 * Diagnostic code to track mutexes separately rather than via the 2^ zones
 */
	zone_t		lck_mtx_zone;
#endif

static void
KALLOC_ZINFO_SALLOC(vm_size_t bytes)
{
	thread_t thr = current_thread();
	ledger_debit(thr->t_ledger, task_ledgers.tkm_shared, bytes);
}

static void
KALLOC_ZINFO_SFREE(vm_size_t bytes)
{
	thread_t thr = current_thread();
	ledger_credit(thr->t_ledger, task_ledgers.tkm_shared, bytes);
}

/*
 * All allocations of size less than kalloc_max are rounded to the next nearest
 * sized zone.  This allocator is built on top of the zone allocator.  A zone
 * is created for each potential size that we are willing to get in small
 * blocks.
 *
 * We assume that kalloc_max is not greater than 64K;
 *
 * Note that kalloc_max is somewhat confusingly named.	It represents the first
 * power of two for which no zone exists.  kalloc_max_prerounded is the
 * smallest allocation size, before rounding, for which no zone exists.
 *
 * Also if the allocation size is more than kalloc_kernmap_size then allocate
 * from kernel map rather than kalloc_map.
 */

#define KALLOC_MINALIGN (1 << KALLOC_LOG2_MINALIGN)
#define KiB(x) (1024 * (x))

static const struct kalloc_zone_config {
	int kzc_size;
	const char *kzc_name;
} k_zone_config[] = {
#define KZC_ENTRY(SIZE) { .kzc_size = (SIZE), .kzc_name = "kalloc." #SIZE }

#if KALLOC_MINSIZE == 16 && KALLOC_LOG2_MINALIGN == 4
	/* 64-bit targets, generally */
	KZC_ENTRY(16),
	KZC_ENTRY(32),
	KZC_ENTRY(48),
	KZC_ENTRY(64),
	KZC_ENTRY(80),
	KZC_ENTRY(96),
	KZC_ENTRY(128),
	KZC_ENTRY(160),
	KZC_ENTRY(192),
	KZC_ENTRY(224),
	KZC_ENTRY(256),
	KZC_ENTRY(288),
	KZC_ENTRY(368),
	KZC_ENTRY(400),
	KZC_ENTRY(512),
	KZC_ENTRY(576),
	KZC_ENTRY(768),
	KZC_ENTRY(1024),
	KZC_ENTRY(1152),
	KZC_ENTRY(1280),
	KZC_ENTRY(1664),
	KZC_ENTRY(2048),
#elif KALLOC_MINSIZE == 8 && KALLOC_LOG2_MINALIGN == 3
	/* 32-bit targets, generally */
	KZC_ENTRY(8),
	KZC_ENTRY(16),
	KZC_ENTRY(24),
	KZC_ENTRY(32),
	KZC_ENTRY(40),
	KZC_ENTRY(48),
	KZC_ENTRY(64),
	KZC_ENTRY(72),
	KZC_ENTRY(88),
	KZC_ENTRY(112),
	KZC_ENTRY(128),
	KZC_ENTRY(192),
	KZC_ENTRY(256),
	KZC_ENTRY(288),
	KZC_ENTRY(384),
	KZC_ENTRY(440),
	KZC_ENTRY(512),
	KZC_ENTRY(576),
	KZC_ENTRY(768),
	KZC_ENTRY(1024),
	KZC_ENTRY(1152),
	KZC_ENTRY(1536),
	KZC_ENTRY(2048),
	KZC_ENTRY(2128),
	KZC_ENTRY(3072),
#else
#error missing or invalid zone size parameters for kalloc
#endif

	/* all configurations get these zones */
	KZC_ENTRY(4096),
	KZC_ENTRY(6144),
	KZC_ENTRY(8192),
	KZC_ENTRY(16384),
	KZC_ENTRY(32768),
#undef KZC_ENTRY
};

#define MAX_K_ZONE (int)(sizeof(k_zone_config) / sizeof(k_zone_config[0]))

/*
 * Many kalloc() allocations are for small structures containing a few
 * pointers and longs - the k_zone_dlut[] direct lookup table, indexed by
 * size normalized to the minimum alignment, finds the right zone index
 * for them in one dereference.
 */

#define INDEX_ZDLUT(size)	\
			(((size) + KALLOC_MINALIGN - 1) / KALLOC_MINALIGN)
#define N_K_ZDLUT	(2048 / KALLOC_MINALIGN)
				/* covers sizes [0 .. 2048 - KALLOC_MINALIGN] */
#define MAX_SIZE_ZDLUT	((N_K_ZDLUT - 1) * KALLOC_MINALIGN)

static int8_t k_zone_dlut[N_K_ZDLUT];	/* table of indices into k_zone[] */

/*
 * If there's no hit in the DLUT, then start searching from k_zindex_start.
 */
static int k_zindex_start;

static zone_t k_zone[MAX_K_ZONE];

/* #define KALLOC_DEBUG		1 */

/* forward declarations */

lck_grp_t kalloc_lck_grp;
lck_mtx_t kalloc_lock;

#define kalloc_spin_lock()	lck_mtx_lock_spin(&kalloc_lock)
#define kalloc_unlock()		lck_mtx_unlock(&kalloc_lock)


/* OSMalloc local data declarations */
static
queue_head_t    OSMalloc_tag_list;

lck_grp_t *OSMalloc_tag_lck_grp;
lck_mtx_t OSMalloc_tag_lock;

#define OSMalloc_tag_spin_lock()	lck_mtx_lock_spin(&OSMalloc_tag_lock)
#define OSMalloc_tag_unlock()		lck_mtx_unlock(&OSMalloc_tag_lock)


/* OSMalloc forward declarations */
void OSMalloc_init(void);
void OSMalloc_Tagref(OSMallocTag	tag);
void OSMalloc_Tagrele(OSMallocTag	tag);

/*
 *	Initialize the memory allocator.  This should be called only
 *	once on a system wide basis (i.e. first processor to get here
 *	does the initialization).
 *
 *	This initializes all of the zones.
 */

void
kalloc_init(
	void)
{
	kern_return_t retval;
	vm_offset_t min;
	vm_size_t size, kalloc_map_size;
	vm_map_kernel_flags_t vmk_flags;

	/* 
	 * Scale the kalloc_map_size to physical memory size: stay below 
	 * 1/8th the total zone map size, or 128 MB (for a 32-bit kernel).
	 */
	kalloc_map_size = (vm_size_t)(sane_size >> 5);
#if !__LP64__
	if (kalloc_map_size > KALLOC_MAP_SIZE_MAX)
		kalloc_map_size = KALLOC_MAP_SIZE_MAX;
#endif /* !__LP64__ */
	if (kalloc_map_size < KALLOC_MAP_SIZE_MIN)
		kalloc_map_size = KALLOC_MAP_SIZE_MIN;

	vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
	vmk_flags.vmkf_permanent = TRUE;

	retval = kmem_suballoc(kernel_map, &min, kalloc_map_size,
			       FALSE,
			       (VM_FLAGS_ANYWHERE),
			       vmk_flags,
			       VM_KERN_MEMORY_KALLOC,
			       &kalloc_map);

	if (retval != KERN_SUCCESS)
		panic("kalloc_init: kmem_suballoc failed");

	kalloc_map_min = min;
	kalloc_map_max = min + kalloc_map_size - 1;

	/*
	 * Create zones up to a least 4 pages because small page-multiples are
	 * common allocations.  Also ensure that zones up to size 16KB bytes exist.
	 * This is desirable because messages are allocated with kalloc(), and
	 * messages up through size 8192 are common.
	 */
	kalloc_max = PAGE_SIZE << 2;
	if (kalloc_max < KiB(16)) {
	    kalloc_max = KiB(16);
	}
	assert(kalloc_max <= KiB(64)); /* assumption made in size arrays */

	kalloc_max_prerounded = kalloc_max / 2 + 1;
	/* allocations larger than 16 times kalloc_max go directly to kernel map */
	kalloc_kernmap_size = (kalloc_max * 16) + 1;
	kalloc_largest_allocated = kalloc_kernmap_size;

	/*
	 * Allocate a zone for each size we are going to handle.
	 */
	for (int i = 0; i < MAX_K_ZONE && (size = k_zone_config[i].kzc_size) < kalloc_max; i++) {
		k_zone[i] = zinit(size, size, size, k_zone_config[i].kzc_name);

		/*
		 * Don't charge the caller for the allocation, as we aren't sure how
		 * the memory will be handled.
		 */
		zone_change(k_zone[i], Z_CALLERACCT, FALSE);
#if VM_MAX_TAG_ZONES
		if (zone_tagging_on) zone_change(k_zone[i], Z_TAGS_ENABLED, TRUE);
#endif
		zone_change(k_zone[i], Z_KASAN_QUARANTINE, FALSE);
	}

	/*
	 * Build the Direct LookUp Table for small allocations
	 */
	size = 0;
	for (int i = 0; i <= N_K_ZDLUT; i++, size += KALLOC_MINALIGN) {
		int zindex = 0;

		while ((vm_size_t)k_zone_config[zindex].kzc_size < size)
			zindex++;

		if (i == N_K_ZDLUT) {
			k_zindex_start = zindex;
			break;
		}
		k_zone_dlut[i] = (int8_t)zindex;
	}

#ifdef KALLOC_DEBUG
	printf("kalloc_init: k_zindex_start %d\n", k_zindex_start);

	/*
	 * Do a quick synthesis to see how well/badly we can
	 * find-a-zone for a given size.
	 * Useful when debugging/tweaking the array of zone sizes.
	 * Cache misses probably more critical than compare-branches!
	 */
	for (int i = 0; i < MAX_K_ZONE; i++) {
		vm_size_t testsize = (vm_size_t)k_zone_config[i].kzc_size - 1;
		int compare = 0;
		int zindex;

		if (testsize < MAX_SIZE_ZDLUT) {
			compare += 1;	/* 'if' (T) */

			long dindex = INDEX_ZDLUT(testsize);
			zindex = (int)k_zone_dlut[dindex];

		} else if (testsize < kalloc_max_prerounded) {

			compare += 2;	/* 'if' (F), 'if' (T) */

			zindex = k_zindex_start;
			while ((vm_size_t)k_zone_config[zindex].kzc_size < testsize) {
				zindex++;
				compare++;	/* 'while' (T) */
			}
			compare++;	/* 'while' (F) */
		} else
			break;	/* not zone-backed */

		zone_t z = k_zone[zindex];
		printf("kalloc_init: req size %4lu: %11s took %d compare%s\n",
		    (unsigned long)testsize, z->zone_name, compare,
		    compare == 1 ? "" : "s");
	}
#endif

	lck_grp_init(&kalloc_lck_grp, "kalloc.large", LCK_GRP_ATTR_NULL);
	lck_mtx_init(&kalloc_lock, &kalloc_lck_grp, LCK_ATTR_NULL);
	OSMalloc_init();
#ifdef	MUTEX_ZONE
	lck_mtx_zone = zinit(sizeof(struct _lck_mtx_), 1024*256, 4096, "lck_mtx");
#endif
}

/*
 * Given an allocation size, return the kalloc zone it belongs to.
 * Direct LookUp Table variant.
 */
static __inline zone_t
get_zone_dlut(vm_size_t size)
{
	long dindex = INDEX_ZDLUT(size);
	int zindex = (int)k_zone_dlut[dindex];
	return (k_zone[zindex]);
}

/* As above, but linear search k_zone_config[] for the next zone that fits. */

static __inline zone_t
get_zone_search(vm_size_t size, int zindex)
{
	assert(size < kalloc_max_prerounded);

	while ((vm_size_t)k_zone_config[zindex].kzc_size < size)
		zindex++;

	assert(zindex < MAX_K_ZONE &&
	    (vm_size_t)k_zone_config[zindex].kzc_size < kalloc_max);

	return (k_zone[zindex]);
}

static vm_size_t
vm_map_lookup_kalloc_entry_locked(
		vm_map_t 	map,
		void 		*addr)
{
	boolean_t       ret;
	vm_map_entry_t  vm_entry = NULL;
	
	ret = vm_map_lookup_entry(map, (vm_map_offset_t)addr, &vm_entry);
	if (!ret) {
		panic("Attempting to lookup/free an address not allocated via kalloc! (vm_map_lookup_entry() failed map: %p, addr: %p)\n", 
			map, addr);
	}
	if (vm_entry->vme_start != (vm_map_offset_t)addr) {
		panic("Attempting to lookup/free the middle of a kalloc'ed element! (map: %p, addr: %p, entry: %p)\n",
			map, addr, vm_entry);
	}
	if (!vm_entry->vme_atomic) {
		panic("Attempting to lookup/free an address not managed by kalloc! (map: %p, addr: %p, entry: %p)\n",
			map, addr, vm_entry); 
	}
	return (vm_entry->vme_end - vm_entry->vme_start);
}

#if KASAN_KALLOC
/*
 * KASAN kalloc stashes the original user-requested size away in the poisoned
 * area. Return that directly.
 */
vm_size_t
kalloc_size(void *addr)
{
	(void)vm_map_lookup_kalloc_entry_locked; /* silence warning */
	return kasan_user_size((vm_offset_t)addr);
}
#else
vm_size_t
kalloc_size(
		void 		*addr)
{
	vm_map_t 		map;
	vm_size_t 		size;

	size = zone_element_size(addr, NULL);
	if (size) {
		return size;
	}
	if (((vm_offset_t)addr >= kalloc_map_min) && ((vm_offset_t)addr < kalloc_map_max)) {
		map = kalloc_map;
	} else {
		map = kernel_map;
	}
	vm_map_lock_read(map);
	size = vm_map_lookup_kalloc_entry_locked(map, addr);
	vm_map_unlock_read(map);
	return size;
}
#endif

vm_size_t
kalloc_bucket_size(
		vm_size_t 	size)
{
	zone_t 		z;
	vm_map_t 	map;
	
	if (size < MAX_SIZE_ZDLUT) {
		z = get_zone_dlut(size);
		return z->elem_size;
	} 
	
	if (size < kalloc_max_prerounded) {
		z = get_zone_search(size, k_zindex_start);
		return z->elem_size;
	}

	if (size >= kalloc_kernmap_size) 
		map = kernel_map;
	else
		map = kalloc_map;
	
	return vm_map_round_page(size, VM_MAP_PAGE_MASK(map));
}

#if KASAN_KALLOC
vm_size_t
kfree_addr(void *addr)
{
	vm_size_t origsz = kalloc_size(addr);
	kfree(addr, origsz);
	return origsz;
}
#else
vm_size_t
kfree_addr(
	void 		*addr)
{
	vm_map_t        map;
	vm_size_t       size = 0;
	kern_return_t 	ret;
	zone_t 			z;

	size = zone_element_size(addr, &z);
	if (size) {
		DTRACE_VM3(kfree, vm_size_t, -1, vm_size_t, z->elem_size, void*, addr);
		zfree(z, addr);
		return size;
	}

	if (((vm_offset_t)addr >= kalloc_map_min) && ((vm_offset_t)addr < kalloc_map_max)) {
		map = kalloc_map;
	} else {
		map = kernel_map;
	}
	if ((vm_offset_t)addr < VM_MIN_KERNEL_AND_KEXT_ADDRESS) {
		panic("kfree on an address not in the kernel & kext address range! addr: %p\n", addr);
	}

	vm_map_lock(map);
	size = vm_map_lookup_kalloc_entry_locked(map, addr);
	ret = vm_map_remove_locked(map,
							vm_map_trunc_page((vm_map_offset_t)addr,
								VM_MAP_PAGE_MASK(map)),
							vm_map_round_page((vm_map_offset_t)addr + size,
								VM_MAP_PAGE_MASK(map)),
							VM_MAP_REMOVE_KUNWIRE);
	if (ret != KERN_SUCCESS) {
		panic("vm_map_remove_locked() failed for kalloc vm_entry! addr: %p, map: %p ret: %d\n",
				addr, map, ret);
	}
	vm_map_unlock(map);
	DTRACE_VM3(kfree, vm_size_t, -1, vm_size_t, size, void*, addr);
	
	kalloc_spin_lock();
	kalloc_large_total -= size;
	kalloc_large_inuse--;
	kalloc_unlock();

	KALLOC_ZINFO_SFREE(size);
	return size;
}
#endif

void *
kalloc_canblock(
		vm_size_t	       * psize,
		boolean_t              canblock,
		vm_allocation_site_t * site)
{
	zone_t z;
	vm_size_t size;
	void *addr;
	vm_tag_t tag;

	tag = VM_KERN_MEMORY_KALLOC;
	size = *psize;

#if KASAN_KALLOC
	/* expand the allocation to accomodate redzones */
	vm_size_t req_size = size;
	size = kasan_alloc_resize(req_size);
#endif

	if (size < MAX_SIZE_ZDLUT)
		z = get_zone_dlut(size);
	else if (size < kalloc_max_prerounded)
		z = get_zone_search(size, k_zindex_start);
	else {
		/*
		 * If size is too large for a zone, then use kmem_alloc.
		 * (We use kmem_alloc instead of kmem_alloc_kobject so that
		 * krealloc can use kmem_realloc.)
		 */
		vm_map_t alloc_map;

		/* kmem_alloc could block so we return if noblock */
		if (!canblock) {
			return(NULL);
		}

#if KASAN_KALLOC
		/* large allocation - use guard pages instead of small redzones */
		size = round_page(req_size + 2 * PAGE_SIZE);
		assert(size >= MAX_SIZE_ZDLUT && size >= kalloc_max_prerounded);
#endif

		if (size >= kalloc_kernmap_size)
		        alloc_map = kernel_map;
		else
			alloc_map = kalloc_map;

		if (site) tag = vm_tag_alloc(site);

		if (kmem_alloc_flags(alloc_map, (vm_offset_t *)&addr, size, tag, KMA_ATOMIC) != KERN_SUCCESS) {
			if (alloc_map != kernel_map) {
				if (kalloc_fallback_count++ == 0) {
					printf("%s: falling back to kernel_map\n", __func__);
				}
				if (kmem_alloc_flags(kernel_map, (vm_offset_t *)&addr, size, tag, KMA_ATOMIC) != KERN_SUCCESS)
					addr = NULL;
			}
			else
				addr = NULL;
		}

		if (addr != NULL) {
			kalloc_spin_lock();
			/*
			 * Thread-safe version of the workaround for 4740071
			 * (a double FREE())
			 */
			if (size > kalloc_largest_allocated)
				kalloc_largest_allocated = size;

		        kalloc_large_inuse++;
		        kalloc_large_total += size;
			kalloc_large_sum += size;

			if (kalloc_large_total > kalloc_large_max)
			        kalloc_large_max = kalloc_large_total;

			kalloc_unlock();

			KALLOC_ZINFO_SALLOC(size);
		}
#if KASAN_KALLOC
		/* fixup the return address to skip the redzone */
		addr = (void *)kasan_alloc((vm_offset_t)addr, size, req_size, PAGE_SIZE);
#else
		*psize = round_page(size);
#endif
		DTRACE_VM3(kalloc, vm_size_t, size, vm_size_t, *psize, void*, addr);
		return(addr);
	}
#ifdef KALLOC_DEBUG
	if (size > z->elem_size)
		panic("%s: z %p (%s) but requested size %lu", __func__,
		    z, z->zone_name, (unsigned long)size);
#endif

	assert(size <= z->elem_size);

#if VM_MAX_TAG_ZONES
    if (z->tags && site)
    {
		tag = vm_tag_alloc(site);
		if (!canblock && !vm_allocation_zone_totals[tag]) tag = VM_KERN_MEMORY_KALLOC;
    }
#endif

	addr =  zalloc_canblock_tag(z, canblock, size, tag);

#if KASAN_KALLOC
	/* fixup the return address to skip the redzone */
	addr = (void *)kasan_alloc((vm_offset_t)addr, z->elem_size, req_size, KASAN_GUARD_SIZE);

	/* For KASan, the redzone lives in any additional space, so don't
	 * expand the allocation. */
#else
	*psize = z->elem_size;
#endif

	DTRACE_VM3(kalloc, vm_size_t, size, vm_size_t, *psize, void*, addr);
	return addr;
}

void *
kalloc_external(
       vm_size_t size);
void *
kalloc_external(
       vm_size_t size)
{
	return( kalloc_tag_bt(size, VM_KERN_MEMORY_KALLOC) );
}

void
kfree(
	void 		*data,
	vm_size_t	size)
{
	zone_t z;

#if KASAN_KALLOC
	/*
	 * Resize back to the real allocation size and hand off to the KASan
	 * quarantine. `data` may then point to a different allocation.
	 */
	vm_size_t user_size = size;
	kasan_check_free((vm_address_t)data, size, KASAN_HEAP_KALLOC);
	data = (void *)kasan_dealloc((vm_address_t)data, &size);
	kasan_free(&data, &size, KASAN_HEAP_KALLOC, NULL, user_size, true);
	if (!data) {
		return;
	}
#endif

	if (size < MAX_SIZE_ZDLUT)
		z = get_zone_dlut(size);
	else if (size < kalloc_max_prerounded)
		z = get_zone_search(size, k_zindex_start);
	else {
		/* if size was too large for a zone, then use kmem_free */

		vm_map_t alloc_map = kernel_map;

		if ((((vm_offset_t) data) >= kalloc_map_min) && (((vm_offset_t) data) <= kalloc_map_max))
			alloc_map = kalloc_map;
		if (size > kalloc_largest_allocated) {
			panic("kfree: size %lu > kalloc_largest_allocated %lu", (unsigned long)size, (unsigned long)kalloc_largest_allocated);
		}
		kmem_free(alloc_map, (vm_offset_t)data, size);
		kalloc_spin_lock();

		kalloc_large_total -= size;
		kalloc_large_inuse--;

		kalloc_unlock();

#if !KASAN_KALLOC
		DTRACE_VM3(kfree, vm_size_t, size, vm_size_t, size, void*, data);
#endif

		KALLOC_ZINFO_SFREE(size);
		return;
	}

	/* free to the appropriate zone */
#ifdef KALLOC_DEBUG
	if (size > z->elem_size)
		panic("%s: z %p (%s) but requested size %lu", __func__,
		    z, z->zone_name, (unsigned long)size);
#endif
	assert(size <= z->elem_size);
#if !KASAN_KALLOC
	DTRACE_VM3(kfree, vm_size_t, size, vm_size_t, z->elem_size, void*, data);
#endif
	zfree(z, data);
}

#ifdef MACH_BSD
zone_t
kalloc_zone(
	vm_size_t       size)
{
	if (size < MAX_SIZE_ZDLUT)
		return (get_zone_dlut(size));
	if (size <= kalloc_max)
		return (get_zone_search(size, k_zindex_start));
	return (ZONE_NULL);
}
#endif

void
OSMalloc_init(
	void)
{
	queue_init(&OSMalloc_tag_list);

	OSMalloc_tag_lck_grp = lck_grp_alloc_init("OSMalloc_tag", LCK_GRP_ATTR_NULL);
	lck_mtx_init(&OSMalloc_tag_lock, OSMalloc_tag_lck_grp, LCK_ATTR_NULL);
}

OSMallocTag
OSMalloc_Tagalloc(
	const char			*str,
	uint32_t			flags)
{
	OSMallocTag       OSMTag;

	OSMTag = (OSMallocTag)kalloc(sizeof(*OSMTag));

	bzero((void *)OSMTag, sizeof(*OSMTag));

	if (flags & OSMT_PAGEABLE)
		OSMTag->OSMT_attr = OSMT_ATTR_PAGEABLE;

	OSMTag->OSMT_refcnt = 1;

	strlcpy(OSMTag->OSMT_name, str, OSMT_MAX_NAME);

	OSMalloc_tag_spin_lock();
	enqueue_tail(&OSMalloc_tag_list, (queue_entry_t)OSMTag);
	OSMalloc_tag_unlock();
	OSMTag->OSMT_state = OSMT_VALID;
	return(OSMTag);
}

void
OSMalloc_Tagref(
	 OSMallocTag		tag)
{
	if (!((tag->OSMT_state & OSMT_VALID_MASK) == OSMT_VALID)) 
		panic("OSMalloc_Tagref():'%s' has bad state 0x%08X\n", tag->OSMT_name, tag->OSMT_state);

	(void)hw_atomic_add(&tag->OSMT_refcnt, 1);
}

void
OSMalloc_Tagrele(
	 OSMallocTag		tag)
{
	if (!((tag->OSMT_state & OSMT_VALID_MASK) == OSMT_VALID))
		panic("OSMalloc_Tagref():'%s' has bad state 0x%08X\n", tag->OSMT_name, tag->OSMT_state);

	if (hw_atomic_sub(&tag->OSMT_refcnt, 1) == 0) {
		if (hw_compare_and_store(OSMT_VALID|OSMT_RELEASED, OSMT_VALID|OSMT_RELEASED, &tag->OSMT_state)) {
			OSMalloc_tag_spin_lock();
			(void)remque((queue_entry_t)tag);
			OSMalloc_tag_unlock();
			kfree((void*)tag, sizeof(*tag));
		} else
			panic("OSMalloc_Tagrele():'%s' has refcnt 0\n", tag->OSMT_name);
	}
}

void
OSMalloc_Tagfree(
	 OSMallocTag		tag)
{
	if (!hw_compare_and_store(OSMT_VALID, OSMT_VALID|OSMT_RELEASED, &tag->OSMT_state))
		panic("OSMalloc_Tagfree():'%s' has bad state 0x%08X \n", tag->OSMT_name, tag->OSMT_state);

	if (hw_atomic_sub(&tag->OSMT_refcnt, 1) == 0) {
		OSMalloc_tag_spin_lock();
		(void)remque((queue_entry_t)tag);
		OSMalloc_tag_unlock();
		kfree((void*)tag, sizeof(*tag));
	}
}

void *
OSMalloc(
	uint32_t			size,
	OSMallocTag			tag)
{
	void			*addr=NULL;
	kern_return_t	kr;

	OSMalloc_Tagref(tag);
	if ((tag->OSMT_attr & OSMT_PAGEABLE)
	    && (size & ~PAGE_MASK)) {
		if ((kr = kmem_alloc_pageable_external(kernel_map, (vm_offset_t *)&addr, size)) != KERN_SUCCESS)
			addr = NULL;
	} else 
		addr = kalloc_tag_bt((vm_size_t)size, VM_KERN_MEMORY_KALLOC);

	if (!addr)
		OSMalloc_Tagrele(tag);

	return(addr);
}

void *
OSMalloc_nowait(
	uint32_t			size,
	OSMallocTag			tag)
{
	void	*addr=NULL;

	if (tag->OSMT_attr & OSMT_PAGEABLE)
		return(NULL);

	OSMalloc_Tagref(tag);
	/* XXX: use non-blocking kalloc for now */
	addr = kalloc_noblock_tag_bt((vm_size_t)size, VM_KERN_MEMORY_KALLOC);
	if (addr == NULL)
		OSMalloc_Tagrele(tag);

	return(addr);
}

void *
OSMalloc_noblock(
	uint32_t			size,
	OSMallocTag			tag)
{
	void	*addr=NULL;

	if (tag->OSMT_attr & OSMT_PAGEABLE)
		return(NULL);

	OSMalloc_Tagref(tag);
	addr = kalloc_noblock_tag_bt((vm_size_t)size, VM_KERN_MEMORY_KALLOC);
	if (addr == NULL)
		OSMalloc_Tagrele(tag);

	return(addr);
}

void
OSFree(
	void				*addr,
	uint32_t			size,
	OSMallocTag			tag) 
{
	if ((tag->OSMT_attr & OSMT_PAGEABLE)
	    && (size & ~PAGE_MASK)) {
		kmem_free(kernel_map, (vm_offset_t)addr, size);
	} else
		kfree((void *)addr, size);

	OSMalloc_Tagrele(tag);
}

uint32_t
OSMalloc_size(
	void 				*addr)
{
	return (uint32_t)kalloc_size(addr);
}

