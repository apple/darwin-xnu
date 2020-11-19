/*
 * Copyright (c) 2000-2020 Apple Computer, Inc. All rights reserved.
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

#include <mach/boolean.h>
#include <mach/sdt.h>
#include <mach/machine/vm_types.h>
#include <mach/vm_param.h>
#include <kern/misc_protos.h>
#include <kern/zalloc_internal.h>
#include <kern/kalloc.h>
#include <kern/ledger.h>
#include <kern/backtrace.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_map.h>
#include <sys/kdebug.h>

#include <san/kasan.h>
#include <libkern/section_keywords.h>

/* #define KALLOC_DEBUG            1 */

#define KALLOC_MAP_SIZE_MIN  (16 * 1024 * 1024)
#define KALLOC_MAP_SIZE_MAX  (128 * 1024 * 1024)

static SECURITY_READ_ONLY_LATE(vm_offset_t) kalloc_map_min;
static SECURITY_READ_ONLY_LATE(vm_offset_t) kalloc_map_max;
static SECURITY_READ_ONLY_LATE(vm_size_t) kalloc_max;
SECURITY_READ_ONLY_LATE(vm_size_t) kalloc_max_prerounded;
/* size of kallocs that can come from kernel map */
SECURITY_READ_ONLY_LATE(vm_size_t) kalloc_kernmap_size;
SECURITY_READ_ONLY_LATE(vm_map_t)  kalloc_map;
#if DEBUG || DEVELOPMENT
static TUNABLE(bool, kheap_temp_debug, "kheap_temp_debug", false);

#define KHT_BT_COUNT 14
struct kheap_temp_header {
	queue_chain_t kht_hdr_link;
	uintptr_t     kht_hdr_pcs[KHT_BT_COUNT];
};
#endif

/* how many times we couldn't allocate out of kalloc_map and fell back to kernel_map */
unsigned long kalloc_fallback_count;

uint_t     kalloc_large_inuse;
vm_size_t  kalloc_large_total;
vm_size_t  kalloc_large_max;
vm_size_t  kalloc_largest_allocated = 0;
uint64_t   kalloc_large_sum;

LCK_GRP_DECLARE(kalloc_lck_grp, "kalloc.large");
LCK_SPIN_DECLARE(kalloc_lock, &kalloc_lck_grp);

#define kalloc_spin_lock()      lck_spin_lock(&kalloc_lock)
#define kalloc_unlock()         lck_spin_unlock(&kalloc_lock)

#pragma mark initialization

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

#define KiB(x) (1024 * (x))

/*
 * The k_zone_cfg table defines the configuration of zones on various platforms.
 * The currently defined list of zones and their per-CPU caching behavior are as
 * follows
 *
 *     X:zone not present
 *     N:zone present no cpu-caching
 *     Y:zone present with cpu-caching
 *
 * Size       macOS(64-bit)       embedded(32-bit)    embedded(64-bit)
 *--------    ----------------    ----------------    ----------------
 *
 * 8          X                    Y                   X
 * 16         Y                    Y                   Y
 * 24         X                    Y                   X
 * 32         Y                    Y                   Y
 * 40         X                    Y                   X
 * 48         Y                    Y                   Y
 * 64         Y                    Y                   Y
 * 72         X                    Y                   X
 * 80         Y                    X                   Y
 * 88         X                    Y                   X
 * 96         Y                    X                   Y
 * 112        X                    Y                   X
 * 128        Y                    Y                   Y
 * 160        Y                    X                   Y
 * 192        Y                    Y                   Y
 * 224        Y                    X                   Y
 * 256        Y                    Y                   Y
 * 288        Y                    Y                   Y
 * 368        Y                    X                   Y
 * 384        X                    Y                   X
 * 400        Y                    X                   Y
 * 440        X                    Y                   X
 * 512        Y                    Y                   Y
 * 576        Y                    N                   N
 * 768        Y                    N                   N
 * 1024       Y                    Y                   Y
 * 1152       N                    N                   N
 * 1280       N                    N                   N
 * 1536       X                    N                   X
 * 1664       N                    X                   N
 * 2048       Y                    N                   N
 * 2128       X                    N                   X
 * 3072       X                    N                   X
 * 4096       Y                    N                   N
 * 6144       N                    N                   N
 * 8192       Y                    N                   N
 * 12288      N                    X                   X
 * 16384      N                    X                   N
 * 32768      X                    X                   N
 *
 */
struct kalloc_zone_cfg {
	bool kzc_caching;
	uint32_t kzc_size;
	const char *kzc_name;
};
static SECURITY_READ_ONLY_LATE(struct kalloc_zone_cfg) k_zone_cfg[] = {
#define KZC_ENTRY(SIZE, caching) { \
	.kzc_caching = (caching), \
	.kzc_size = (SIZE), \
	.kzc_name = "kalloc." #SIZE \
}

#if !defined(XNU_TARGET_OS_OSX)

#if KALLOC_MINSIZE == 16 && KALLOC_LOG2_MINALIGN == 4
	/* Zone config for embedded 64-bit platforms */
	KZC_ENTRY(16, true),
	KZC_ENTRY(32, true),
	KZC_ENTRY(48, true),
	KZC_ENTRY(64, true),
	KZC_ENTRY(80, true),
	KZC_ENTRY(96, true),
	KZC_ENTRY(128, true),
	KZC_ENTRY(160, true),
	KZC_ENTRY(192, true),
	KZC_ENTRY(224, true),
	KZC_ENTRY(256, true),
	KZC_ENTRY(288, true),
	KZC_ENTRY(368, true),
	KZC_ENTRY(400, true),
	KZC_ENTRY(512, true),
	KZC_ENTRY(576, false),
	KZC_ENTRY(768, false),
	KZC_ENTRY(1024, true),
	KZC_ENTRY(1152, false),
	KZC_ENTRY(1280, false),
	KZC_ENTRY(1664, false),
	KZC_ENTRY(2048, false),
	KZC_ENTRY(4096, false),
	KZC_ENTRY(6144, false),
	KZC_ENTRY(8192, false),
	KZC_ENTRY(16384, false),
	KZC_ENTRY(32768, false),

#elif KALLOC_MINSIZE == 8 && KALLOC_LOG2_MINALIGN == 3
	/* Zone config for embedded 32-bit platforms */
	KZC_ENTRY(8, true),
	KZC_ENTRY(16, true),
	KZC_ENTRY(24, true),
	KZC_ENTRY(32, true),
	KZC_ENTRY(40, true),
	KZC_ENTRY(48, true),
	KZC_ENTRY(64, true),
	KZC_ENTRY(72, true),
	KZC_ENTRY(88, true),
	KZC_ENTRY(112, true),
	KZC_ENTRY(128, true),
	KZC_ENTRY(192, true),
	KZC_ENTRY(256, true),
	KZC_ENTRY(288, true),
	KZC_ENTRY(384, true),
	KZC_ENTRY(440, true),
	KZC_ENTRY(512, true),
	KZC_ENTRY(576, false),
	KZC_ENTRY(768, false),
	KZC_ENTRY(1024, true),
	KZC_ENTRY(1152, false),
	KZC_ENTRY(1280, false),
	KZC_ENTRY(1536, false),
	KZC_ENTRY(2048, false),
	KZC_ENTRY(2128, false),
	KZC_ENTRY(3072, false),
	KZC_ENTRY(4096, false),
	KZC_ENTRY(6144, false),
	KZC_ENTRY(8192, false),
	/* To limit internal fragmentation, only add the following zones if the
	 * page size is greater than 4K.
	 * Note that we use ARM_PGBYTES here (instead of one of the VM macros)
	 * since it's guaranteed to be a compile time constant.
	 */
#if ARM_PGBYTES > 4096
	KZC_ENTRY(16384, false),
	KZC_ENTRY(32768, false),
#endif /* ARM_PGBYTES > 4096 */

#else
#error missing or invalid zone size parameters for kalloc
#endif

#else /* !defined(XNU_TARGET_OS_OSX) */

	/* Zone config for macOS 64-bit platforms */
	KZC_ENTRY(16, true),
	KZC_ENTRY(32, true),
	KZC_ENTRY(48, true),
	KZC_ENTRY(64, true),
	KZC_ENTRY(80, true),
	KZC_ENTRY(96, true),
	KZC_ENTRY(128, true),
	KZC_ENTRY(160, true),
	KZC_ENTRY(192, true),
	KZC_ENTRY(224, true),
	KZC_ENTRY(256, true),
	KZC_ENTRY(288, true),
	KZC_ENTRY(368, true),
	KZC_ENTRY(400, true),
	KZC_ENTRY(512, true),
	KZC_ENTRY(576, true),
	KZC_ENTRY(768, true),
	KZC_ENTRY(1024, true),
	KZC_ENTRY(1152, false),
	KZC_ENTRY(1280, false),
	KZC_ENTRY(1664, false),
	KZC_ENTRY(2048, true),
	KZC_ENTRY(4096, true),
	KZC_ENTRY(6144, false),
	KZC_ENTRY(8192, true),
	KZC_ENTRY(12288, false),
	KZC_ENTRY(16384, false)

#endif /* !defined(XNU_TARGET_OS_OSX) */

#undef KZC_ENTRY
};

#define MAX_K_ZONE(kzc) (uint32_t)(sizeof(kzc) / sizeof(kzc[0]))

/*
 * Many kalloc() allocations are for small structures containing a few
 * pointers and longs - the dlut[] direct lookup table, indexed by
 * size normalized to the minimum alignment, finds the right zone index
 * for them in one dereference.
 */

#define INDEX_ZDLUT(size)  (((size) + KALLOC_MINALIGN - 1) / KALLOC_MINALIGN)
#define MAX_SIZE_ZDLUT     ((KALLOC_DLUT_SIZE - 1) * KALLOC_MINALIGN)

static SECURITY_READ_ONLY_LATE(zone_t) k_zone_default[MAX_K_ZONE(k_zone_cfg)];
static SECURITY_READ_ONLY_LATE(zone_t) k_zone_data_buffers[MAX_K_ZONE(k_zone_cfg)];
static SECURITY_READ_ONLY_LATE(zone_t) k_zone_kext[MAX_K_ZONE(k_zone_cfg)];

#if VM_MAX_TAG_ZONES
#if __LP64__
static_assert(VM_MAX_TAG_ZONES >=
    MAX_K_ZONE(k_zone_cfg) + MAX_K_ZONE(k_zone_cfg) + MAX_K_ZONE(k_zone_cfg));
#else
static_assert(VM_MAX_TAG_ZONES >= MAX_K_ZONE(k_zone_cfg));
#endif
#endif

const char * const kalloc_heap_names[] = {
	[KHEAP_ID_NONE]          = "",
	[KHEAP_ID_DEFAULT]       = "default.",
	[KHEAP_ID_DATA_BUFFERS]  = "data.",
	[KHEAP_ID_KEXT]          = "kext.",
};

/*
 * Default kalloc heap configuration
 */
static SECURITY_READ_ONLY_LATE(struct kheap_zones) kalloc_zones_default = {
	.cfg         = k_zone_cfg,
	.heap_id     = KHEAP_ID_DEFAULT,
	.k_zone      = k_zone_default,
	.max_k_zone  = MAX_K_ZONE(k_zone_cfg)
};
SECURITY_READ_ONLY_LATE(struct kalloc_heap) KHEAP_DEFAULT[1] = {
	{
		.kh_zones    = &kalloc_zones_default,
		.kh_name     = "default.",
		.kh_heap_id  = KHEAP_ID_DEFAULT,
	}
};

KALLOC_HEAP_DEFINE(KHEAP_TEMP, "temp allocations", KHEAP_ID_DEFAULT);


/*
 * Bag of bytes heap configuration
 */
static SECURITY_READ_ONLY_LATE(struct kheap_zones) kalloc_zones_data_buffers = {
	.cfg         = k_zone_cfg,
	.heap_id     = KHEAP_ID_DATA_BUFFERS,
	.k_zone      = k_zone_data_buffers,
	.max_k_zone  = MAX_K_ZONE(k_zone_cfg)
};
SECURITY_READ_ONLY_LATE(struct kalloc_heap) KHEAP_DATA_BUFFERS[1] = {
	{
		.kh_zones    = &kalloc_zones_data_buffers,
		.kh_name     = "data.",
		.kh_heap_id  = KHEAP_ID_DATA_BUFFERS,
	}
};


/*
 * Kext heap configuration
 */
static SECURITY_READ_ONLY_LATE(struct kheap_zones) kalloc_zones_kext = {
	.cfg         = k_zone_cfg,
	.heap_id     = KHEAP_ID_KEXT,
	.k_zone      = k_zone_kext,
	.max_k_zone  = MAX_K_ZONE(k_zone_cfg)
};
SECURITY_READ_ONLY_LATE(struct kalloc_heap) KHEAP_KEXT[1] = {
	{
		.kh_zones    = &kalloc_zones_kext,
		.kh_name     = "kext.",
		.kh_heap_id  = KHEAP_ID_KEXT,
	}
};

KALLOC_HEAP_DEFINE(KERN_OS_MALLOC, "kern_os_malloc", KHEAP_ID_KEXT);

/*
 * Initialize kalloc heap: Create zones, generate direct lookup table and
 * do a quick test on lookups
 */
__startup_func
static void
kalloc_zones_init(struct kheap_zones *zones)
{
	struct kalloc_zone_cfg *cfg = zones->cfg;
	zone_t *k_zone = zones->k_zone;
	vm_size_t size;

	/*
	 * Allocate a zone for each size we are going to handle.
	 */
	for (uint32_t i = 0; i < zones->max_k_zone &&
	    (size = cfg[i].kzc_size) < kalloc_max; i++) {
		zone_create_flags_t flags = ZC_KASAN_NOREDZONE |
		    ZC_KASAN_NOQUARANTINE | ZC_KALLOC_HEAP;
		if (cfg[i].kzc_caching) {
			flags |= ZC_CACHING;
		}

		k_zone[i] = zone_create_ext(cfg[i].kzc_name, size, flags,
		    ZONE_ID_ANY, ^(zone_t z){
			z->kalloc_heap = zones->heap_id;
		});
		/*
		 * Set the updated elem size back to the config
		 */
		cfg[i].kzc_size = k_zone[i]->z_elem_size;
	}

	/*
	 * Count all the "raw" views for zones in the heap.
	 */
	zone_view_count += zones->max_k_zone;

	/*
	 * Build the Direct LookUp Table for small allocations
	 * As k_zone_cfg is shared between the heaps the
	 * Direct LookUp Table is also shared and doesn't need to
	 * be rebuilt per heap.
	 */
	size = 0;
	for (int i = 0; i <= KALLOC_DLUT_SIZE; i++, size += KALLOC_MINALIGN) {
		uint8_t zindex = 0;

		while ((vm_size_t)(cfg[zindex].kzc_size) < size) {
			zindex++;
		}

		if (i == KALLOC_DLUT_SIZE) {
			zones->k_zindex_start = zindex;
			break;
		}
		zones->dlut[i] = zindex;
	}

#ifdef KALLOC_DEBUG
	printf("kalloc_init: k_zindex_start %d\n", zones->k_zindex_start);

	/*
	 * Do a quick synthesis to see how well/badly we can
	 * find-a-zone for a given size.
	 * Useful when debugging/tweaking the array of zone sizes.
	 * Cache misses probably more critical than compare-branches!
	 */
	for (uint32_t i = 0; i < zones->max_k_zone; i++) {
		vm_size_t testsize = (vm_size_t)(cfg[i].kzc_size - 1);
		int compare = 0;
		uint8_t zindex;

		if (testsize < MAX_SIZE_ZDLUT) {
			compare += 1;   /* 'if' (T) */

			long dindex = INDEX_ZDLUT(testsize);
			zindex = (int)zones->dlut[dindex];
		} else if (testsize < kalloc_max_prerounded) {
			compare += 2;   /* 'if' (F), 'if' (T) */

			zindex = zones->k_zindex_start;
			while ((vm_size_t)(cfg[zindex].kzc_size) < testsize) {
				zindex++;
				compare++;      /* 'while' (T) */
			}
			compare++;      /* 'while' (F) */
		} else {
			break;  /* not zone-backed */
		}
		zone_t z = k_zone[zindex];
		printf("kalloc_init: req size %4lu: %8s.%16s took %d compare%s\n",
		    (unsigned long)testsize, kalloc_heap_names[zones->heap_id],
		    z->z_name, compare, compare == 1 ? "" : "s");
	}
#endif
}

/*
 *	Initialize the memory allocator.  This should be called only
 *	once on a system wide basis (i.e. first processor to get here
 *	does the initialization).
 *
 *	This initializes all of the zones.
 */

__startup_func
static void
kalloc_init(void)
{
	kern_return_t retval;
	vm_offset_t min;
	vm_size_t kalloc_map_size;
	vm_map_kernel_flags_t vmk_flags;

	/*
	 * Scale the kalloc_map_size to physical memory size: stay below
	 * 1/8th the total zone map size, or 128 MB (for a 32-bit kernel).
	 */
	kalloc_map_size = (vm_size_t)(sane_size >> 5);
#if !__LP64__
	if (kalloc_map_size > KALLOC_MAP_SIZE_MAX) {
		kalloc_map_size = KALLOC_MAP_SIZE_MAX;
	}
#endif /* !__LP64__ */
	if (kalloc_map_size < KALLOC_MAP_SIZE_MIN) {
		kalloc_map_size = KALLOC_MAP_SIZE_MIN;
	}

	vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
	vmk_flags.vmkf_permanent = TRUE;

	retval = kmem_suballoc(kernel_map, &min, kalloc_map_size,
	    FALSE, VM_FLAGS_ANYWHERE, vmk_flags,
	    VM_KERN_MEMORY_KALLOC, &kalloc_map);

	if (retval != KERN_SUCCESS) {
		panic("kalloc_init: kmem_suballoc failed");
	}

	kalloc_map_min = min;
	kalloc_map_max = min + kalloc_map_size - 1;

	struct kheap_zones *khz_default = &kalloc_zones_default;
	kalloc_max = (khz_default->cfg[khz_default->max_k_zone - 1].kzc_size << 1);
	if (kalloc_max < KiB(16)) {
		kalloc_max = KiB(16);
	}
	assert(kalloc_max <= KiB(64)); /* assumption made in size arrays */

	kalloc_max_prerounded = kalloc_max / 2 + 1;
	/* allocations larger than 16 times kalloc_max go directly to kernel map */
	kalloc_kernmap_size = (kalloc_max * 16) + 1;
	kalloc_largest_allocated = kalloc_kernmap_size;

	/* Initialize kalloc default heap */
	kalloc_zones_init(&kalloc_zones_default);

	/* Initialize kalloc data buffers heap */
	if (ZSECURITY_OPTIONS_SUBMAP_USER_DATA & zsecurity_options) {
		kalloc_zones_init(&kalloc_zones_data_buffers);
	} else {
		*KHEAP_DATA_BUFFERS = *KHEAP_DEFAULT;
	}

	/* Initialize kalloc kext heap */
	if (ZSECURITY_OPTIONS_SEQUESTER_KEXT_KALLOC & zsecurity_options) {
		kalloc_zones_init(&kalloc_zones_kext);
	} else {
		*KHEAP_KEXT = *KHEAP_DEFAULT;
	}
}
STARTUP(ZALLOC, STARTUP_RANK_THIRD, kalloc_init);


#pragma mark accessors

static void
KALLOC_ZINFO_SALLOC(vm_size_t bytes)
{
	thread_t thr = current_thread();
	ledger_debit_thread(thr, thr->t_ledger, task_ledgers.tkm_shared, bytes);
}

static void
KALLOC_ZINFO_SFREE(vm_size_t bytes)
{
	thread_t thr = current_thread();
	ledger_credit_thread(thr, thr->t_ledger, task_ledgers.tkm_shared, bytes);
}

static inline vm_map_t
kalloc_map_for_addr(vm_address_t addr)
{
	if (addr >= kalloc_map_min && addr < kalloc_map_max) {
		return kalloc_map;
	}
	return kernel_map;
}

static inline vm_map_t
kalloc_map_for_size(vm_size_t size)
{
	if (size < kalloc_kernmap_size) {
		return kalloc_map;
	}
	return kernel_map;
}

zone_t
kalloc_heap_zone_for_size(kalloc_heap_t kheap, vm_size_t size)
{
	struct kheap_zones *khz = kheap->kh_zones;

	if (size < MAX_SIZE_ZDLUT) {
		uint32_t zindex = khz->dlut[INDEX_ZDLUT(size)];
		return khz->k_zone[zindex];
	}

	if (size < kalloc_max_prerounded) {
		uint32_t zindex = khz->k_zindex_start;
		while (khz->cfg[zindex].kzc_size < size) {
			zindex++;
		}
		assert(zindex < khz->max_k_zone);
		return khz->k_zone[zindex];
	}

	return ZONE_NULL;
}

static vm_size_t
vm_map_lookup_kalloc_entry_locked(vm_map_t map, void *addr)
{
	vm_map_entry_t vm_entry = NULL;

	if (!vm_map_lookup_entry(map, (vm_map_offset_t)addr, &vm_entry)) {
		panic("address %p not allocated via kalloc, map %p",
		    addr, map);
	}
	if (vm_entry->vme_start != (vm_map_offset_t)addr) {
		panic("address %p inside vm entry %p [%p:%p), map %p",
		    addr, vm_entry, (void *)vm_entry->vme_start,
		    (void *)vm_entry->vme_end, map);
	}
	if (!vm_entry->vme_atomic) {
		panic("address %p not managed by kalloc (entry %p, map %p)",
		    addr, vm_entry, map);
	}
	return vm_entry->vme_end - vm_entry->vme_start;
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
kalloc_size(void *addr)
{
	vm_map_t  map;
	vm_size_t size;

	size = zone_element_size(addr, NULL);
	if (size) {
		return size;
	}

	map = kalloc_map_for_addr((vm_offset_t)addr);
	vm_map_lock_read(map);
	size = vm_map_lookup_kalloc_entry_locked(map, addr);
	vm_map_unlock_read(map);
	return size;
}
#endif

vm_size_t
kalloc_bucket_size(vm_size_t size)
{
	zone_t   z   = kalloc_heap_zone_for_size(KHEAP_DEFAULT, size);
	vm_map_t map = kalloc_map_for_size(size);

	if (z) {
		return zone_elem_size(z);
	}
	return vm_map_round_page(size, VM_MAP_PAGE_MASK(map));
}

#pragma mark kalloc

void
kheap_temp_leak_panic(thread_t self)
{
#if DEBUG || DEVELOPMENT
	if (__improbable(kheap_temp_debug)) {
		struct kheap_temp_header *hdr = qe_dequeue_head(&self->t_temp_alloc_list,
		    struct kheap_temp_header, kht_hdr_link);

		panic_plain("KHEAP_TEMP leak on thread %p (%d), allocated at:\n"
		    "  %#016lx\n" "  %#016lx\n" "  %#016lx\n" "  %#016lx\n"
		    "  %#016lx\n" "  %#016lx\n" "  %#016lx\n" "  %#016lx\n"
		    "  %#016lx\n" "  %#016lx\n" "  %#016lx\n" "  %#016lx\n"
		    "  %#016lx\n" "  %#016lx\n",
		    self, self->t_temp_alloc_count,
		    hdr->kht_hdr_pcs[0], hdr->kht_hdr_pcs[1],
		    hdr->kht_hdr_pcs[2], hdr->kht_hdr_pcs[3],
		    hdr->kht_hdr_pcs[4], hdr->kht_hdr_pcs[5],
		    hdr->kht_hdr_pcs[6], hdr->kht_hdr_pcs[7],
		    hdr->kht_hdr_pcs[8], hdr->kht_hdr_pcs[9],
		    hdr->kht_hdr_pcs[10], hdr->kht_hdr_pcs[11],
		    hdr->kht_hdr_pcs[12], hdr->kht_hdr_pcs[13]);
	}
	panic("KHEAP_TEMP leak on thread %p (%d) "
	    "(boot with kheap_temp_debug=1 to debug)",
	    self, self->t_temp_alloc_count);
#else /* !DEBUG && !DEVELOPMENT */
	panic("KHEAP_TEMP leak on thread %p (%d)",
	    self, self->t_temp_alloc_count);
#endif /* !DEBUG && !DEVELOPMENT */
}

__abortlike
static void
kheap_temp_overuse_panic(thread_t self)
{
	panic("too many KHEAP_TEMP allocations in flight: %d",
	    self->t_temp_alloc_count);
}

__attribute__((noinline))
static struct kalloc_result
kalloc_large(
	kalloc_heap_t         kheap,
	vm_size_t             req_size,
	vm_size_t             size,
	zalloc_flags_t        flags,
	vm_allocation_site_t  *site)
{
	int kma_flags = KMA_ATOMIC | KMA_KOBJECT;
	vm_tag_t tag = VM_KERN_MEMORY_KALLOC;
	vm_map_t alloc_map;
	vm_offset_t addr;

	if (flags & Z_NOFAIL) {
		panic("trying to kalloc(Z_NOFAIL) with a large size (%zd)",
		    (size_t)size);
	}
	/* kmem_alloc could block so we return if noblock */
	if (flags & Z_NOWAIT) {
		return (struct kalloc_result){ };
	}

	if (flags & Z_NOPAGEWAIT) {
		kma_flags |= KMA_NOPAGEWAIT;
	}
	if (flags & Z_ZERO) {
		kma_flags |= KMA_ZERO;
	}

#if KASAN_KALLOC
	/* large allocation - use guard pages instead of small redzones */
	size = round_page(req_size + 2 * PAGE_SIZE);
	assert(size >= MAX_SIZE_ZDLUT && size >= kalloc_max_prerounded);
#else
	size = round_page(size);
#endif

	alloc_map = kalloc_map_for_size(size);

	if (site) {
		tag = vm_tag_alloc(site);
	}

	if (kmem_alloc_flags(alloc_map, &addr, size, tag, kma_flags) != KERN_SUCCESS) {
		if (alloc_map != kernel_map) {
			if (kalloc_fallback_count++ == 0) {
				printf("%s: falling back to kernel_map\n", __func__);
			}
			if (kmem_alloc_flags(kernel_map, &addr, size, tag, kma_flags) != KERN_SUCCESS) {
				addr = 0;
			}
		} else {
			addr = 0;
		}
	}

	if (addr != 0) {
		kalloc_spin_lock();
		/*
		 * Thread-safe version of the workaround for 4740071
		 * (a double FREE())
		 */
		if (size > kalloc_largest_allocated) {
			kalloc_largest_allocated = size;
		}

		kalloc_large_inuse++;
		assert(kalloc_large_total + size >= kalloc_large_total); /* no wrap around */
		kalloc_large_total += size;
		kalloc_large_sum += size;

		if (kalloc_large_total > kalloc_large_max) {
			kalloc_large_max = kalloc_large_total;
		}

		kalloc_unlock();

		KALLOC_ZINFO_SALLOC(size);
	}
#if KASAN_KALLOC
	/* fixup the return address to skip the redzone */
	addr = kasan_alloc(addr, size, req_size, PAGE_SIZE);
	/*
	 * Initialize buffer with unique pattern only if memory
	 * wasn't expected to be zeroed.
	 */
	if (!(flags & Z_ZERO)) {
		kasan_leak_init(addr, req_size);
	}
#else
	req_size = size;
#endif

	if (addr && kheap == KHEAP_TEMP) {
		thread_t self = current_thread();

		if (self->t_temp_alloc_count++ > UINT16_MAX) {
			kheap_temp_overuse_panic(self);
		}
#if DEBUG || DEVELOPMENT
		if (__improbable(kheap_temp_debug)) {
			struct kheap_temp_header *hdr = (void *)addr;
			enqueue_head(&self->t_temp_alloc_list,
			    &hdr->kht_hdr_link);
			backtrace(hdr->kht_hdr_pcs, KHT_BT_COUNT, NULL);
			req_size -= sizeof(struct kheap_temp_header);
			addr     += sizeof(struct kheap_temp_header);
		}
#endif /* DEBUG || DEVELOPMENT */
	}

	DTRACE_VM3(kalloc, vm_size_t, size, vm_size_t, req_size, void*, addr);
	return (struct kalloc_result){ .addr = (void *)addr, .size = req_size };
}

struct kalloc_result
kalloc_ext(
	kalloc_heap_t         kheap,
	vm_size_t             req_size,
	zalloc_flags_t        flags,
	vm_allocation_site_t  *site)
{
	vm_tag_t tag = VM_KERN_MEMORY_KALLOC;
	vm_size_t size;
	void *addr;
	zone_t z;

#if DEBUG || DEVELOPMENT
	if (__improbable(kheap_temp_debug)) {
		if (kheap == KHEAP_TEMP) {
			req_size += sizeof(struct kheap_temp_header);
		}
	}
#endif /* DEBUG || DEVELOPMENT */

	/*
	 * Kasan for kalloc heaps will put the redzones *inside*
	 * the allocation, and hence augment its size.
	 *
	 * kalloc heaps do not use zone_t::kasan_redzone.
	 */
#if KASAN_KALLOC
	size = kasan_alloc_resize(req_size);
#else
	size = req_size;
#endif
	z = kalloc_heap_zone_for_size(kheap, size);
	if (__improbable(z == ZONE_NULL)) {
		return kalloc_large(kheap, req_size, size, flags, site);
	}

#ifdef KALLOC_DEBUG
	if (size > zone_elem_size(z)) {
		panic("%s: z %p (%s%s) but requested size %lu", __func__, z,
		    kalloc_heap_names[kheap->kh_zones->heap_id], z->z_name,
		    (unsigned long)size);
	}
#endif
	assert(size <= zone_elem_size(z));

#if VM_MAX_TAG_ZONES
	if (z->tags && site) {
		tag = vm_tag_alloc(site);
		if ((flags & (Z_NOWAIT | Z_NOPAGEWAIT)) && !vm_allocation_zone_totals[tag]) {
			tag = VM_KERN_MEMORY_KALLOC;
		}
	}
#endif
	addr = zalloc_ext(z, kheap->kh_stats ?: z->z_stats,
	    flags | Z_VM_TAG(tag), zone_elem_size(z) - size);

#if KASAN_KALLOC
	addr = (void *)kasan_alloc((vm_offset_t)addr, zone_elem_size(z),
	    req_size, KASAN_GUARD_SIZE);
#else
	req_size = zone_elem_size(z);
#endif

	if (addr && kheap == KHEAP_TEMP) {
		thread_t self = current_thread();

		if (self->t_temp_alloc_count++ > UINT16_MAX) {
			kheap_temp_overuse_panic(self);
		}
#if DEBUG || DEVELOPMENT
		if (__improbable(kheap_temp_debug)) {
			struct kheap_temp_header *hdr = (void *)addr;
			enqueue_head(&self->t_temp_alloc_list,
			    &hdr->kht_hdr_link);
			backtrace(hdr->kht_hdr_pcs, KHT_BT_COUNT, NULL);
			req_size -= sizeof(struct kheap_temp_header);
			addr     += sizeof(struct kheap_temp_header);
		}
#endif /* DEBUG || DEVELOPMENT */
	}

	DTRACE_VM3(kalloc, vm_size_t, size, vm_size_t, req_size, void*, addr);
	return (struct kalloc_result){ .addr = addr, .size = req_size };
}

void *
kalloc_external(vm_size_t size);
void *
kalloc_external(vm_size_t size)
{
	return kheap_alloc_tag_bt(KHEAP_KEXT, size, Z_WAITOK, VM_KERN_MEMORY_KALLOC);
}


#pragma mark kfree

__attribute__((noinline))
static void
kfree_large(vm_offset_t addr, vm_size_t size)
{
	vm_map_t map = kalloc_map_for_addr(addr);
	kern_return_t ret;
	vm_offset_t end;

	if (addr < VM_MIN_KERNEL_AND_KEXT_ADDRESS ||
	    os_add_overflow(addr, size, &end) ||
	    end > VM_MAX_KERNEL_ADDRESS) {
		panic("kfree: address range (%p, %ld) doesn't belong to the kernel",
		    (void *)addr, (uintptr_t)size);
	}

	if (size == 0) {
		vm_map_lock(map);
		size = vm_map_lookup_kalloc_entry_locked(map, (void *)addr);
		ret = vm_map_remove_locked(map,
		    vm_map_trunc_page(addr, VM_MAP_PAGE_MASK(map)),
		    vm_map_round_page(addr + size, VM_MAP_PAGE_MASK(map)),
		    VM_MAP_REMOVE_KUNWIRE);
		if (ret != KERN_SUCCESS) {
			panic("kfree: vm_map_remove_locked() failed for "
			    "addr: %p, map: %p ret: %d", (void *)addr, map, ret);
		}
		vm_map_unlock(map);
	} else {
		size = round_page(size);

		if (size > kalloc_largest_allocated) {
			panic("kfree: size %lu > kalloc_largest_allocated %lu",
			    (uintptr_t)size, (uintptr_t)kalloc_largest_allocated);
		}
		kmem_free(map, addr, size);
	}

	kalloc_spin_lock();

	assert(kalloc_large_total >= size);
	kalloc_large_total -= size;
	kalloc_large_inuse--;

	kalloc_unlock();

#if !KASAN_KALLOC
	DTRACE_VM3(kfree, vm_size_t, size, vm_size_t, size, void*, addr);
#endif

	KALLOC_ZINFO_SFREE(size);
	return;
}

__abortlike
static void
kfree_heap_confusion_panic(kalloc_heap_t kheap, void *data, size_t size, zone_t z)
{
	if (z->kalloc_heap == KHEAP_ID_NONE) {
		panic("kfree: addr %p, size %zd found in regular zone '%s%s'",
		    data, size, zone_heap_name(z), z->z_name);
	} else {
		panic("kfree: addr %p, size %zd found in heap %s* instead of %s*",
		    data, size, zone_heap_name(z),
		    kalloc_heap_names[kheap->kh_heap_id]);
	}
}

__abortlike
static void
kfree_size_confusion_panic(zone_t z, void *data, size_t size, size_t zsize)
{
	if (z) {
		panic("kfree: addr %p, size %zd found in zone '%s%s' "
		    "with elem_size %zd",
		    data, size, zone_heap_name(z), z->z_name, zsize);
	} else {
		panic("kfree: addr %p, size %zd not found in any zone",
		    data, size);
	}
}

__abortlike
static void
kfree_size_invalid_panic(void *data, size_t size)
{
	panic("kfree: addr %p trying to free with nonsensical size %zd",
	    data, size);
}

__abortlike
static void
krealloc_size_invalid_panic(void *data, size_t size)
{
	panic("krealloc: addr %p trying to free with nonsensical size %zd",
	    data, size);
}

__abortlike
static void
kfree_temp_imbalance_panic(void *data, size_t size)
{
	panic("kfree: KHEAP_TEMP allocation imbalance freeing addr %p, size %zd",
	    data, size);
}

/* used to implement kheap_free_addr() */
#define KFREE_UNKNOWN_SIZE  ((vm_size_t)~0)
#define KFREE_ABSURD_SIZE \
	((VM_MAX_KERNEL_ADDRESS - VM_MIN_KERNEL_AND_KEXT_ADDRESS) / 2)

static void
kfree_ext(kalloc_heap_t kheap, void *data, vm_size_t size)
{
	zone_stats_t zs = NULL;
	zone_t z;
	vm_size_t zsize;

	if (__improbable(data == NULL)) {
		return;
	}

	if (kheap == KHEAP_TEMP) {
		assert(size != KFREE_UNKNOWN_SIZE);
		if (current_thread()->t_temp_alloc_count-- == 0) {
			kfree_temp_imbalance_panic(data, size);
		}
#if DEBUG || DEVELOPMENT
		if (__improbable(kheap_temp_debug)) {
			size += sizeof(struct kheap_temp_header);
			data -= sizeof(struct kheap_temp_header);
			remqueue(&((struct kheap_temp_header *)data)->kht_hdr_link);
		}
#endif /* DEBUG || DEVELOPMENT */
	}

#if KASAN_KALLOC
	/*
	 * Resize back to the real allocation size and hand off to the KASan
	 * quarantine. `data` may then point to a different allocation.
	 */
	vm_size_t user_size = size;
	if (size == KFREE_UNKNOWN_SIZE) {
		user_size = size = kalloc_size(data);
	}
	kasan_check_free((vm_address_t)data, size, KASAN_HEAP_KALLOC);
	data = (void *)kasan_dealloc((vm_address_t)data, &size);
	kasan_free(&data, &size, KASAN_HEAP_KALLOC, NULL, user_size, true);
	if (!data) {
		return;
	}
#endif

	if (size >= kalloc_max_prerounded && size != KFREE_UNKNOWN_SIZE) {
		return kfree_large((vm_offset_t)data, size);
	}

	zsize = zone_element_size(data, &z);
	if (size == KFREE_UNKNOWN_SIZE) {
		if (zsize == 0) {
			return kfree_large((vm_offset_t)data, 0);
		}
		size = zsize;
	} else if (size > zsize) {
		kfree_size_confusion_panic(z, data, size, zsize);
	}

	if (kheap != KHEAP_ANY) {
		if (kheap->kh_heap_id != z->kalloc_heap) {
			kfree_heap_confusion_panic(kheap, data, size, z);
		}
		zs = kheap->kh_stats;
	} else if (z->kalloc_heap != KHEAP_ID_DEFAULT &&
	    z->kalloc_heap != KHEAP_ID_KEXT) {
		kfree_heap_confusion_panic(kheap, data, size, z);
	}

#if !KASAN_KALLOC
	DTRACE_VM3(kfree, vm_size_t, size, vm_size_t, zsize, void*, data);
#endif
	zfree_ext(z, zs ?: z->z_stats, data);
}

void
(kfree)(void *addr, vm_size_t size)
{
	if (size > KFREE_ABSURD_SIZE) {
		kfree_size_invalid_panic(addr, size);
	}
	kfree_ext(KHEAP_ANY, addr, size);
}

void
(kheap_free)(kalloc_heap_t kheap, void *addr, vm_size_t size)
{
	if (size > KFREE_ABSURD_SIZE) {
		kfree_size_invalid_panic(addr, size);
	}
	kfree_ext(kheap, addr, size);
}

void
(kheap_free_addr)(kalloc_heap_t kheap, void *addr)
{
	kfree_ext(kheap, addr, KFREE_UNKNOWN_SIZE);
}

static struct kalloc_result
_krealloc_ext(
	kalloc_heap_t           kheap,
	void                   *addr,
	vm_size_t               old_size,
	vm_size_t               new_size,
	zalloc_flags_t          flags,
	vm_allocation_site_t   *site)
{
	vm_size_t old_bucket_size, new_bucket_size, min_size;
	struct kalloc_result kr;

	if (new_size == 0) {
		kfree_ext(kheap, addr, old_size);
		return (struct kalloc_result){ };
	}

	if (addr == NULL) {
		return kalloc_ext(kheap, new_size, flags, site);
	}

	/*
	 * Find out the size of the bucket in which the new sized allocation
	 * would land. If it matches the bucket of the original allocation,
	 * simply return the same address.
	 */
	new_bucket_size = kalloc_bucket_size(new_size);
	if (old_size == KFREE_UNKNOWN_SIZE) {
		old_size = old_bucket_size = kalloc_size(addr);
	} else {
		old_bucket_size = kalloc_bucket_size(old_size);
	}
	min_size = MIN(old_size, new_size);

	if (old_bucket_size == new_bucket_size) {
		kr.addr = addr;
#if KASAN_KALLOC
		kr.size = new_size;
#else
		kr.size = new_bucket_size;
#endif
	} else {
		kr = kalloc_ext(kheap, new_size, flags & ~Z_ZERO, site);
		if (kr.addr == NULL) {
			return kr;
		}

		memcpy(kr.addr, addr, min_size);
		kfree_ext(kheap, addr, old_size);
	}
	if ((flags & Z_ZERO) && kr.size > min_size) {
		bzero(kr.addr + min_size, kr.size - min_size);
	}
	return kr;
}

struct kalloc_result
krealloc_ext(
	kalloc_heap_t           kheap,
	void                   *addr,
	vm_size_t               old_size,
	vm_size_t               new_size,
	zalloc_flags_t          flags,
	vm_allocation_site_t   *site)
{
	if (old_size > KFREE_ABSURD_SIZE) {
		krealloc_size_invalid_panic(addr, old_size);
	}
	return _krealloc_ext(kheap, addr, old_size, new_size, flags, site);
}

struct kalloc_result
kheap_realloc_addr(
	kalloc_heap_t           kheap,
	void                   *addr,
	vm_size_t               size,
	zalloc_flags_t          flags,
	vm_allocation_site_t   *site)
{
	return _krealloc_ext(kheap, addr, KFREE_UNKNOWN_SIZE, size, flags, site);
}

__startup_func
void
kheap_startup_init(kalloc_heap_t kheap)
{
	struct kheap_zones *zones;

	switch (kheap->kh_heap_id) {
	case KHEAP_ID_DEFAULT:
		zones = KHEAP_DEFAULT->kh_zones;
		break;
	case KHEAP_ID_DATA_BUFFERS:
		zones = KHEAP_DATA_BUFFERS->kh_zones;
		break;
	case KHEAP_ID_KEXT:
		zones = KHEAP_KEXT->kh_zones;
		break;
	default:
		panic("kalloc_heap_startup_init: invalid KHEAP_ID: %d",
		    kheap->kh_heap_id);
	}

	kheap->kh_heap_id = zones->heap_id;
	kheap->kh_zones = zones;
	kheap->kh_stats = zalloc_percpu_permanent_type(struct zone_stats);
	kheap->kh_next = zones->views;
	zones->views = kheap;

	zone_view_count += 1;
}

#pragma mark OSMalloc
/*
 * This is a deprecated interface, here only for legacy reasons.
 * There is no internal variant of any of these symbols on purpose.
 */
#define OSMallocDeprecated
#include <libkern/OSMalloc.h>

static KALLOC_HEAP_DEFINE(OSMALLOC, "osmalloc", KHEAP_ID_KEXT);
static queue_head_t OSMalloc_tag_list = QUEUE_HEAD_INITIALIZER(OSMalloc_tag_list);
static LCK_GRP_DECLARE(OSMalloc_tag_lck_grp, "OSMalloc_tag");
static LCK_SPIN_DECLARE(OSMalloc_tag_lock, &OSMalloc_tag_lck_grp);

#define OSMalloc_tag_spin_lock()        lck_spin_lock(&OSMalloc_tag_lock)
#define OSMalloc_tag_unlock()           lck_spin_unlock(&OSMalloc_tag_lock)

extern typeof(OSMalloc_Tagalloc) OSMalloc_Tagalloc_external;
OSMallocTag
OSMalloc_Tagalloc_external(const char *str, uint32_t flags)
{
	OSMallocTag OSMTag;

	OSMTag = kheap_alloc(OSMALLOC, sizeof(*OSMTag), Z_WAITOK | Z_ZERO);

	if (flags & OSMT_PAGEABLE) {
		OSMTag->OSMT_attr = OSMT_ATTR_PAGEABLE;
	}

	OSMTag->OSMT_refcnt = 1;

	strlcpy(OSMTag->OSMT_name, str, OSMT_MAX_NAME);

	OSMalloc_tag_spin_lock();
	enqueue_tail(&OSMalloc_tag_list, (queue_entry_t)OSMTag);
	OSMalloc_tag_unlock();
	OSMTag->OSMT_state = OSMT_VALID;
	return OSMTag;
}

static void
OSMalloc_Tagref(OSMallocTag tag)
{
	if (!((tag->OSMT_state & OSMT_VALID_MASK) == OSMT_VALID)) {
		panic("OSMalloc_Tagref():'%s' has bad state 0x%08X\n",
		    tag->OSMT_name, tag->OSMT_state);
	}

	os_atomic_inc(&tag->OSMT_refcnt, relaxed);
}

static void
OSMalloc_Tagrele(OSMallocTag tag)
{
	if (!((tag->OSMT_state & OSMT_VALID_MASK) == OSMT_VALID)) {
		panic("OSMalloc_Tagref():'%s' has bad state 0x%08X\n",
		    tag->OSMT_name, tag->OSMT_state);
	}

	if (os_atomic_dec(&tag->OSMT_refcnt, relaxed) != 0) {
		return;
	}

	if (os_atomic_cmpxchg(&tag->OSMT_state,
	    OSMT_VALID | OSMT_RELEASED, OSMT_VALID | OSMT_RELEASED, acq_rel)) {
		OSMalloc_tag_spin_lock();
		(void)remque((queue_entry_t)tag);
		OSMalloc_tag_unlock();
		kheap_free(OSMALLOC, tag, sizeof(*tag));
	} else {
		panic("OSMalloc_Tagrele():'%s' has refcnt 0\n", tag->OSMT_name);
	}
}

extern typeof(OSMalloc_Tagfree) OSMalloc_Tagfree_external;
void
OSMalloc_Tagfree_external(OSMallocTag tag)
{
	if (!os_atomic_cmpxchg(&tag->OSMT_state,
	    OSMT_VALID, OSMT_VALID | OSMT_RELEASED, acq_rel)) {
		panic("OSMalloc_Tagfree():'%s' has bad state 0x%08X \n",
		    tag->OSMT_name, tag->OSMT_state);
	}

	if (os_atomic_dec(&tag->OSMT_refcnt, relaxed) == 0) {
		OSMalloc_tag_spin_lock();
		(void)remque((queue_entry_t)tag);
		OSMalloc_tag_unlock();
		kheap_free(OSMALLOC, tag, sizeof(*tag));
	}
}

extern typeof(OSMalloc) OSMalloc_external;
void *
OSMalloc_external(
	uint32_t size, OSMallocTag tag)
{
	void           *addr = NULL;
	kern_return_t   kr;

	OSMalloc_Tagref(tag);
	if ((tag->OSMT_attr & OSMT_PAGEABLE) && (size & ~PAGE_MASK)) {
		if ((kr = kmem_alloc_pageable_external(kernel_map,
		    (vm_offset_t *)&addr, size)) != KERN_SUCCESS) {
			addr = NULL;
		}
	} else {
		addr = kheap_alloc_tag_bt(OSMALLOC, size,
		    Z_WAITOK, VM_KERN_MEMORY_KALLOC);
	}

	if (!addr) {
		OSMalloc_Tagrele(tag);
	}

	return addr;
}

extern typeof(OSMalloc_nowait) OSMalloc_nowait_external;
void *
OSMalloc_nowait_external(uint32_t size, OSMallocTag tag)
{
	void    *addr = NULL;

	if (tag->OSMT_attr & OSMT_PAGEABLE) {
		return NULL;
	}

	OSMalloc_Tagref(tag);
	/* XXX: use non-blocking kalloc for now */
	addr = kheap_alloc_tag_bt(OSMALLOC, (vm_size_t)size,
	    Z_NOWAIT, VM_KERN_MEMORY_KALLOC);
	if (addr == NULL) {
		OSMalloc_Tagrele(tag);
	}

	return addr;
}

extern typeof(OSMalloc_noblock) OSMalloc_noblock_external;
void *
OSMalloc_noblock_external(uint32_t size, OSMallocTag tag)
{
	void    *addr = NULL;

	if (tag->OSMT_attr & OSMT_PAGEABLE) {
		return NULL;
	}

	OSMalloc_Tagref(tag);
	addr = kheap_alloc_tag_bt(OSMALLOC, (vm_size_t)size,
	    Z_NOWAIT, VM_KERN_MEMORY_KALLOC);
	if (addr == NULL) {
		OSMalloc_Tagrele(tag);
	}

	return addr;
}

extern typeof(OSFree) OSFree_external;
void
OSFree_external(void *addr, uint32_t size, OSMallocTag tag)
{
	if ((tag->OSMT_attr & OSMT_PAGEABLE)
	    && (size & ~PAGE_MASK)) {
		kmem_free(kernel_map, (vm_offset_t)addr, size);
	} else {
		kheap_free(OSMALLOC, addr, size);
	}

	OSMalloc_Tagrele(tag);
}

#pragma mark kern_os_malloc

void *
kern_os_malloc_external(size_t size);
void *
kern_os_malloc_external(size_t size)
{
	if (size == 0) {
		return NULL;
	}

	return kheap_alloc_tag_bt(KERN_OS_MALLOC, size, Z_WAITOK | Z_ZERO,
	           VM_KERN_MEMORY_LIBKERN);
}

void
kern_os_free_external(void *addr);
void
kern_os_free_external(void *addr)
{
	kheap_free_addr(KERN_OS_MALLOC, addr);
}

void *
kern_os_realloc_external(void *addr, size_t nsize);
void *
kern_os_realloc_external(void *addr, size_t nsize)
{
	VM_ALLOC_SITE_STATIC(VM_TAG_BT, VM_KERN_MEMORY_LIBKERN);

	return kheap_realloc_addr(KERN_OS_MALLOC, addr, nsize,
	           Z_WAITOK | Z_ZERO, &site).addr;
}

void
kern_os_zfree(zone_t zone, void *addr, vm_size_t size)
{
	if (zsecurity_options & ZSECURITY_OPTIONS_STRICT_IOKIT_FREE
	    || zone_owns(zone, addr)) {
		zfree(zone, addr);
	} else {
		/*
		 * Third party kexts might not know about the operator new
		 * and be allocated from the KEXT heap
		 */
		printf("kern_os_zfree: kheap_free called for object from zone %s\n",
		    zone->z_name);
		kheap_free(KHEAP_KEXT, addr, size);
	}
}

void
kern_os_kfree(void *addr, vm_size_t size)
{
	if (zsecurity_options & ZSECURITY_OPTIONS_STRICT_IOKIT_FREE) {
		kheap_free(KHEAP_DEFAULT, addr, size);
	} else {
		/*
		 * Third party kexts may not know about newly added operator
		 * default new/delete. If they call new for any iokit object
		 * it will end up coming from the KEXT heap. If these objects
		 * are freed by calling release() or free(), the internal
		 * version of operator delete is called and the kernel ends
		 * up freeing the object to the DEFAULT heap.
		 */
		kheap_free(KHEAP_ANY, addr, size);
	}
}
