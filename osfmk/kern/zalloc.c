/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
 *	File:	kern/zalloc.c
 *	Author:	Avadis Tevanian, Jr.
 *
 *	Zone-based memory allocator.  A zone is a collection of fixed size
 *	data blocks for which quick allocation/deallocation is possible.
 */

#define ZALLOC_ALLOW_DEPRECATED 1
#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <mach/kern_return.h>
#include <mach/mach_host_server.h>
#include <mach/task_server.h>
#include <mach/machine/vm_types.h>
#include <mach/vm_map.h>
#include <mach/sdt.h>

#include <kern/bits.h>
#include <kern/startup.h>
#include <kern/kern_types.h>
#include <kern/assert.h>
#include <kern/backtrace.h>
#include <kern/host.h>
#include <kern/macro_help.h>
#include <kern/sched.h>
#include <kern/locks.h>
#include <kern/sched_prim.h>
#include <kern/misc_protos.h>
#include <kern/thread_call.h>
#include <kern/zalloc_internal.h>
#include <kern/kalloc.h>

#include <prng/random.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_compressor.h> /* C_SLOT_PACKED_PTR* */

#include <pexpert/pexpert.h>

#include <machine/machparam.h>
#include <machine/machine_routines.h>  /* ml_cpu_get_info */

#include <os/atomic.h>

#include <libkern/OSDebug.h>
#include <libkern/OSAtomic.h>
#include <libkern/section_keywords.h>
#include <sys/kdebug.h>

#include <san/kasan.h>

#if KASAN_ZALLOC
#define ZONE_ENABLE_LOGGING 0
#elif DEBUG || DEVELOPMENT
#define ZONE_ENABLE_LOGGING 1
#else
#define ZONE_ENABLE_LOGGING 0
#endif

extern void vm_pageout_garbage_collect(int collect);

/* Returns pid of the task with the largest number of VM map entries.  */
extern pid_t find_largest_process_vm_map_entries(void);

/*
 * Callout to jetsam. If pid is -1, we wake up the memorystatus thread to do asynchronous kills.
 * For any other pid we try to kill that process synchronously.
 */
extern boolean_t memorystatus_kill_on_zone_map_exhaustion(pid_t pid);

extern zone_t vm_map_entry_zone;
extern zone_t vm_object_zone;
extern vm_offset_t kmapoff_kaddr;
extern unsigned int kmapoff_pgcnt;
extern unsigned int stack_total;
extern unsigned long long stack_allocs;

/*
 * The max # of elements in a chunk should fit into
 * zone_page_metadata.free_count (uint16_t).
 *
 * Update this if the type of free_count changes.
 */
#define ZONE_CHUNK_MAXELEMENTS  (UINT16_MAX)

#define ZONE_PAGECOUNT_BITS     14

/* Zone elements must fit both a next pointer and a backup pointer */
#define ZONE_MIN_ELEM_SIZE      (2 * sizeof(vm_offset_t))
#define ZONE_MAX_ALLOC_SIZE     (32 * 1024)

/* per-cpu zones are special because of counters */
#define ZONE_MIN_PCPU_ELEM_SIZE (1 * sizeof(vm_offset_t))

struct zone_map_range {
	vm_offset_t min_address;
	vm_offset_t max_address;
};

struct zone_page_metadata {
	/* The index of the zone this metadata page belongs to */
	zone_id_t       zm_index;

	/*
	 * zm_secondary_page == 0: number of pages in this run
	 * zm_secondary_page == 1: offset to the chunk start
	 */
	uint16_t        zm_page_count : ZONE_PAGECOUNT_BITS;

	/* Whether this page is part of a chunk run */
	uint16_t        zm_percpu : 1;
	uint16_t        zm_secondary_page : 1;

	/*
	 * The start of the freelist can be maintained as a 16-bit
	 * offset instead of a pointer because the free elements would
	 * be at max ZONE_MAX_ALLOC_SIZE bytes away from the start
	 * of the allocation chunk.
	 *
	 * Offset from start of the allocation chunk to free element
	 * list head.
	 */
	uint16_t        zm_freelist_offs;

	/*
	 * zm_secondary_page == 0: number of allocated elements in the chunk
	 * zm_secondary_page == 1: unused
	 *
	 * PAGE_METADATA_EMPTY_FREELIST indicates an empty freelist
	 */
	uint16_t        zm_alloc_count;
#define PAGE_METADATA_EMPTY_FREELIST  UINT16_MAX

	zone_pva_t      zm_page_next;
	zone_pva_t      zm_page_prev;

	/*
	 * This is only for the sake of debuggers
	 */
#define ZONE_FOREIGN_COOKIE           0x123456789abcdef
	uint64_t        zm_foreign_cookie[];
};


/* Align elements that use the zone page list to 32 byte boundaries. */
#define ZONE_PAGE_FIRST_OFFSET(kind)  ((kind) == ZONE_ADDR_NATIVE ? 0 : 32)

static_assert(sizeof(struct zone_page_metadata) == 16, "validate packing");

static __security_const_late struct {
	struct zone_map_range      zi_map_range;
	struct zone_map_range      zi_general_range;
	struct zone_map_range      zi_meta_range;
	struct zone_map_range      zi_foreign_range;

	/*
	 * The metadata lives within the zi_meta_range address range.
	 *
	 * The correct formula to find a metadata index is:
	 *     absolute_page_index - page_index(zi_meta_range.min_address)
	 *
	 * And then this index is used to dereference zi_meta_range.min_address
	 * as a `struct zone_page_metadata` array.
	 *
	 * To avoid doing that substraction all the time in the various fast-paths,
	 * zi_array_base is offset by `page_index(zi_meta_range.min_address)`
	 * to avoid redoing that math all the time.
	 */
	struct zone_page_metadata *zi_array_base;
} zone_info;

/*
 *	The zone_locks_grp allows for collecting lock statistics.
 *	All locks are associated to this group in zinit.
 *	Look at tools/lockstat for debugging lock contention.
 */
LCK_GRP_DECLARE(zone_locks_grp, "zone_locks");
LCK_MTX_EARLY_DECLARE(zone_metadata_region_lck, &zone_locks_grp);

/*
 *	Exclude more than one concurrent garbage collection
 */
LCK_GRP_DECLARE(zone_gc_lck_grp, "zone_gc");
LCK_MTX_EARLY_DECLARE(zone_gc_lock, &zone_gc_lck_grp);

boolean_t panic_include_zprint = FALSE;
mach_memory_info_t *panic_kext_memory_info = NULL;
vm_size_t panic_kext_memory_size = 0;

/*
 *      Protects zone_array, num_zones, num_zones_in_use, and
 *      zone_destroyed_bitmap
 */
static SIMPLE_LOCK_DECLARE(all_zones_lock, 0);
static unsigned int     num_zones_in_use;
unsigned int _Atomic    num_zones;
SECURITY_READ_ONLY_LATE(unsigned int) zone_view_count;

#if KASAN_ZALLOC
#define MAX_ZONES       566
#else /* !KASAN_ZALLOC */
#define MAX_ZONES       402
#endif/* !KASAN_ZALLOC */
struct zone             zone_array[MAX_ZONES];

/* Initialized in zone_bootstrap(), how many "copies" the per-cpu system does */
static SECURITY_READ_ONLY_LATE(unsigned) zpercpu_early_count;

/* Used to keep track of destroyed slots in the zone_array */
static bitmap_t zone_destroyed_bitmap[BITMAP_LEN(MAX_ZONES)];

/* number of pages used by all zones */
static long _Atomic zones_phys_page_count;

/* number of zone mapped pages used by all zones */
static long _Atomic zones_phys_page_mapped_count;

#if CONFIG_ZALLOC_SEQUESTER
#define ZSECURITY_OPTIONS_SEQUESTER_DEFAULT ZSECURITY_OPTIONS_SEQUESTER
#else
#define ZSECURITY_OPTIONS_SEQUESTER_DEFAULT 0
#endif
/*
 * Turn ZSECURITY_OPTIONS_STRICT_IOKIT_FREE off on x86 so as not
 * not break third party kexts that haven't yet been recompiled
 * to use the new iokit macros.
 */
#if XNU_TARGET_OS_OSX && __x86_64__
#define ZSECURITY_OPTIONS_STRICT_IOKIT_FREE_DEFAULT 0
#else
#define ZSECURITY_OPTIONS_STRICT_IOKIT_FREE_DEFAULT \
  ZSECURITY_OPTIONS_STRICT_IOKIT_FREE
#endif

#define ZSECURITY_DEFAULT ( \
	        ZSECURITY_OPTIONS_SEQUESTER_DEFAULT | \
	        ZSECURITY_OPTIONS_SUBMAP_USER_DATA | \
	        ZSECURITY_OPTIONS_SEQUESTER_KEXT_KALLOC | \
	        ZSECURITY_OPTIONS_STRICT_IOKIT_FREE_DEFAULT | \
	        0)
TUNABLE(zone_security_options_t, zsecurity_options, "zs", ZSECURITY_DEFAULT);

#if VM_MAX_TAG_ZONES
/* enable tags for zones that ask for it */
TUNABLE(bool, zone_tagging_on, "-zt", false);
#endif /* VM_MAX_TAG_ZONES */

#if DEBUG || DEVELOPMENT
TUNABLE(bool, zalloc_disable_copyio_check, "-no-copyio-zalloc-check", false);
__options_decl(zalloc_debug_t, uint32_t, {
	ZALLOC_DEBUG_ZONEGC     = 0x00000001,
	ZALLOC_DEBUG_ZCRAM      = 0x00000002,
});

TUNABLE(zalloc_debug_t, zalloc_debug, "zalloc_debug", 0);
#endif /* DEBUG || DEVELOPMENT */
#if CONFIG_ZLEAKS
/* Making pointer scanning leaks detection possible for all zones */
TUNABLE(bool, zone_leaks_scan_enable, "-zl", false);
#else
#define zone_leaks_scan_enable false
#endif

/*
 * Async allocation of zones
 * This mechanism allows for bootstrapping an empty zone which is setup with
 * non-blocking flags. The first call to zalloc_noblock() will kick off a thread_call
 * to zalloc_async. We perform a zalloc() (which may block) and then an immediate free.
 * This will prime the zone for the next use.
 *
 * Currently the thread_callout function (zalloc_async) will loop through all zones
 * looking for any zone with async_pending set and do the work for it.
 *
 * NOTE: If the calling thread for zalloc_noblock is lower priority than thread_call,
 * then zalloc_noblock to an empty zone may succeed.
 */
static void zalloc_async(thread_call_param_t p0, thread_call_param_t p1);
static thread_call_data_t call_async_alloc;
static void zcram_and_lock(zone_t zone, vm_offset_t newmem, vm_size_t size);

/*
 * Zone Corruption Debugging
 *
 * We use four techniques to detect modification of a zone element
 * after it's been freed.
 *
 * (1) Check the freelist next pointer for sanity.
 * (2) Store a backup of the next pointer at the end of the element,
 *     and compare it to the primary next pointer when the element is allocated
 *     to detect corruption of the freelist due to use-after-free bugs.
 *     The backup pointer is also XORed with a per-boot random cookie.
 * (3) Poison the freed element by overwriting it with 0xdeadbeef,
 *     and check for that value when the element is being reused to make sure
 *     no part of the element has been modified while it was on the freelist.
 *     This will also help catch read-after-frees, as code will now dereference
 *     0xdeadbeef instead of a valid but freed pointer.
 * (4) If the zfree_clear_mem flag is set clear the element on free and
 *     assert that it is still clear when alloc-ed.
 *
 * (1) and (2) occur for every allocation and free to a zone.
 * This is done to make it slightly more difficult for an attacker to
 * manipulate the freelist to behave in a specific way.
 *
 * Poisoning (3) occurs periodically for every N frees (counted per-zone).
 * If -zp is passed as a boot arg, poisoning occurs for every free.
 *
 * Zeroing (4) is done for those zones that pass the ZC_ZFREE_CLEARMEM
 * flag on creation or if the element size is less than one cacheline.
 *
 * Performance slowdown is inversely proportional to the frequency of poisoning,
 * with a 4-5% hit around N=1, down to ~0.3% at N=16 and just "noise" at N=32
 * and higher. You can expect to find a 100% reproducible bug in an average of
 * N tries, with a standard deviation of about N, but you will want to set
 * "-zp" to always poison every free if you are attempting to reproduce
 * a known bug.
 *
 * For a more heavyweight, but finer-grained method of detecting misuse
 * of zone memory, look up the "Guard mode" zone allocator in gzalloc.c.
 *
 * Zone Corruption Logging
 *
 * You can also track where corruptions come from by using the boot-arguments
 * "zlog=<zone name to log> -zc". Search for "Zone corruption logging" later
 * in this document for more implementation and usage information.
 *
 * Zone Leak Detection
 *
 * To debug leaks of zone memory, use the zone leak detection tool 'zleaks'
 * found later in this file via the showtopztrace and showz* macros in kgmacros,
 * or use zlog without the -zc argument.
 *
 */

#define ZP_DEFAULT_SAMPLING_FACTOR 16
#define ZP_DEFAULT_SCALE_FACTOR 4

/*
 * set by zp-factor=N boot arg
 *
 * A zp_factor of 0 indicates zone poisoning is disabled and can also be set by
 * passing the -no-zp boot-arg.
 *
 * A zp_factor of 1 indicates zone poisoning is on for all elements and can be
 * set by passing the -zp boot-arg.
 */
static TUNABLE(uint32_t, zp_factor, "zp-factor", ZP_DEFAULT_SAMPLING_FACTOR);

/* set by zp-scale=N boot arg, scales zp_factor by zone size */
static TUNABLE(uint32_t, zp_scale, "zp-scale", ZP_DEFAULT_SCALE_FACTOR);

/* initialized to a per-boot random value in zp_bootstrap */
static SECURITY_READ_ONLY_LATE(uintptr_t) zp_poisoned_cookie;
static SECURITY_READ_ONLY_LATE(uintptr_t) zp_nopoison_cookie;
static SECURITY_READ_ONLY_LATE(uintptr_t) zp_min_size;
static SECURITY_READ_ONLY_LATE(uint64_t) zone_phys_mapped_max;

static SECURITY_READ_ONLY_LATE(vm_map_t) zone_submaps[Z_SUBMAP_IDX_COUNT];
static SECURITY_READ_ONLY_LATE(uint32_t) zone_last_submap_idx;

static struct bool_gen zone_bool_gen;
static zone_t          zone_find_largest(void);
static void            zone_drop_free_elements(zone_t z);

#define submap_for_zone(z) zone_submaps[(z)->submap_idx]
#define MAX_SUBMAP_NAME                16

/* Globals for random boolean generator for elements in free list */
#define MAX_ENTROPY_PER_ZCRAM           4

#if CONFIG_ZCACHE
/*
 * Specifies a single zone to enable CPU caching for.
 * Can be set using boot-args: zcc_enable_for_zone_name=<zone>
 */
static char cache_zone_name[MAX_ZONE_NAME];
static TUNABLE(bool, zcc_kalloc, "zcc_kalloc", false);

__header_always_inline bool
zone_caching_enabled(zone_t z)
{
	return z->zcache.zcc_depot != NULL;
}
#else
__header_always_inline bool
zone_caching_enabled(zone_t z __unused)
{
	return false;
}
#endif /* CONFIG_ZCACHE */

#pragma mark Zone metadata

__enum_closed_decl(zone_addr_kind_t, bool, {
	ZONE_ADDR_NATIVE,
	ZONE_ADDR_FOREIGN,
});

static inline zone_id_t
zone_index(zone_t z)
{
	return (zone_id_t)(z - zone_array);
}

static inline bool
zone_has_index(zone_t z, zone_id_t zid)
{
	return zone_array + zid == z;
}

static inline vm_size_t
zone_elem_count(zone_t zone, vm_size_t alloc_size, zone_addr_kind_t kind)
{
	if (kind == ZONE_ADDR_NATIVE) {
		if (zone->percpu) {
			return PAGE_SIZE / zone_elem_size(zone);
		}
		return alloc_size / zone_elem_size(zone);
	} else {
		assert(alloc_size == PAGE_SIZE);
		return (PAGE_SIZE - ZONE_PAGE_FIRST_OFFSET(kind)) / zone_elem_size(zone);
	}
}

__abortlike
static void
zone_metadata_corruption(zone_t zone, struct zone_page_metadata *meta,
    const char *kind)
{
	panic("zone metadata corruption: %s (meta %p, zone %s%s)",
	    kind, meta, zone_heap_name(zone), zone->z_name);
}

__abortlike
static void
zone_invalid_element_addr_panic(zone_t zone, vm_offset_t addr)
{
	panic("zone element pointer validation failed (addr: %p, zone %s%s)",
	    (void *)addr, zone_heap_name(zone), zone->z_name);
}

__abortlike
static void
zone_page_metadata_index_confusion_panic(zone_t zone, vm_offset_t addr,
    struct zone_page_metadata *meta)
{
	panic("%p not in the expected zone %s%s (%d != %d)",
	    (void *)addr, zone_heap_name(zone), zone->z_name,
	    meta->zm_index, zone_index(zone));
}

__abortlike
static void
zone_page_metadata_native_queue_corruption(zone_t zone, zone_pva_t *queue)
{
	panic("foreign metadata index %d enqueued in native head %p from zone %s%s",
	    queue->packed_address, queue, zone_heap_name(zone),
	    zone->z_name);
}

__abortlike
static void
zone_page_metadata_list_corruption(zone_t zone, struct zone_page_metadata *meta)
{
	panic("metadata list corruption through element %p detected in zone %s%s",
	    meta, zone_heap_name(zone), zone->z_name);
}

__abortlike
static void
zone_page_metadata_foreign_queue_corruption(zone_t zone, zone_pva_t *queue)
{
	panic("native metadata index %d enqueued in foreign head %p from zone %s%s",
	    queue->packed_address, queue, zone_heap_name(zone), zone->z_name);
}

__abortlike
static void
zone_page_metadata_foreign_confusion_panic(zone_t zone, vm_offset_t addr)
{
	panic("manipulating foreign address %p in a native-only zone %s%s",
	    (void *)addr, zone_heap_name(zone), zone->z_name);
}

__abortlike __unused
static void
zone_invalid_foreign_addr_panic(zone_t zone, vm_offset_t addr)
{
	panic("addr %p being freed to foreign zone %s%s not from foreign range",
	    (void *)addr, zone_heap_name(zone), zone->z_name);
}

__abortlike
static void
zone_page_meta_accounting_panic(zone_t zone, struct zone_page_metadata *meta,
    const char *kind)
{
	panic("accounting mismatch (%s) for zone %s%s, meta %p", kind,
	    zone_heap_name(zone), zone->z_name, meta);
}

__abortlike
static void
zone_accounting_panic(zone_t zone, const char *kind)
{
	panic("accounting mismatch (%s) for zone %s%s", kind,
	    zone_heap_name(zone), zone->z_name);
}

__abortlike
static void
zone_nofail_panic(zone_t zone)
{
	panic("zalloc(Z_NOFAIL) can't be satisfied for zone %s%s (potential leak)",
	    zone_heap_name(zone), zone->z_name);
}

#if __arm64__
// <rdar://problem/48304934> arm64 doesn't use ldp when I'd expect it to
#define zone_range_load(r, rmin, rmax) \
	asm("ldp %[rmin], %[rmax], [%[range]]" \
	    : [rmin] "=r"(rmin), [rmax] "=r"(rmax) \
	    : [range] "r"(r))
#else
#define zone_range_load(r, rmin, rmax) \
	({ rmin = (r)->min_address; rmax = (r)->max_address; })
#endif

__header_always_inline bool
zone_range_contains(const struct zone_map_range *r, vm_offset_t addr, vm_offset_t size)
{
	vm_offset_t rmin, rmax;

	/*
	 * The `&` is not a typo: we really expect the check to pass,
	 * so encourage the compiler to eagerly load and test without branches
	 */
	zone_range_load(r, rmin, rmax);
	return (addr >= rmin) & (addr + size >= rmin) & (addr + size <= rmax);
}

__header_always_inline vm_size_t
zone_range_size(const struct zone_map_range *r)
{
	vm_offset_t rmin, rmax;

	zone_range_load(r, rmin, rmax);
	return rmax - rmin;
}

#define from_zone_map(addr, size) \
	zone_range_contains(&zone_info.zi_map_range, (vm_offset_t)(addr), size)

#define from_general_submap(addr, size) \
	zone_range_contains(&zone_info.zi_general_range, (vm_offset_t)(addr), size)

#define from_foreign_range(addr, size) \
	zone_range_contains(&zone_info.zi_foreign_range, (vm_offset_t)(addr), size)

#define from_native_meta_map(addr) \
	zone_range_contains(&zone_info.zi_meta_range, (vm_offset_t)(addr), \
	    sizeof(struct zone_page_metadata))

#define zone_addr_kind(addr, size) \
	(from_zone_map(addr, size) ? ZONE_ADDR_NATIVE : ZONE_ADDR_FOREIGN)

__header_always_inline bool
zone_pva_is_null(zone_pva_t page)
{
	return page.packed_address == 0;
}

__header_always_inline bool
zone_pva_is_queue(zone_pva_t page)
{
	// actual kernel pages have the top bit set
	return (int32_t)page.packed_address > 0;
}

__header_always_inline bool
zone_pva_is_equal(zone_pva_t pva1, zone_pva_t pva2)
{
	return pva1.packed_address == pva2.packed_address;
}

__header_always_inline void
zone_queue_set_head(zone_t z, zone_pva_t queue, zone_pva_t oldv,
    struct zone_page_metadata *meta)
{
	zone_pva_t *queue_head = &((zone_pva_t *)zone_array)[queue.packed_address];

	if (!zone_pva_is_equal(*queue_head, oldv)) {
		zone_page_metadata_list_corruption(z, meta);
	}
	*queue_head = meta->zm_page_next;
}

__header_always_inline zone_pva_t
zone_queue_encode(zone_pva_t *headp)
{
	return (zone_pva_t){ (uint32_t)(headp - (zone_pva_t *)zone_array) };
}

__header_always_inline zone_pva_t
zone_pva_from_addr(vm_address_t addr)
{
	// cannot use atop() because we want to maintain the sign bit
	return (zone_pva_t){ (uint32_t)((intptr_t)addr >> PAGE_SHIFT) };
}

__header_always_inline vm_address_t
zone_pva_to_addr(zone_pva_t page)
{
	// cause sign extension so that we end up with the right address
	return (vm_offset_t)(int32_t)page.packed_address << PAGE_SHIFT;
}

__header_always_inline struct zone_page_metadata *
zone_pva_to_meta(zone_pva_t page, zone_addr_kind_t kind)
{
	if (kind == ZONE_ADDR_NATIVE) {
		return &zone_info.zi_array_base[page.packed_address];
	} else {
		return (struct zone_page_metadata *)zone_pva_to_addr(page);
	}
}

__header_always_inline zone_pva_t
zone_pva_from_meta(struct zone_page_metadata *meta, zone_addr_kind_t kind)
{
	if (kind == ZONE_ADDR_NATIVE) {
		uint32_t index = (uint32_t)(meta - zone_info.zi_array_base);
		return (zone_pva_t){ index };
	} else {
		return zone_pva_from_addr((vm_address_t)meta);
	}
}

__header_always_inline struct zone_page_metadata *
zone_meta_from_addr(vm_offset_t addr, zone_addr_kind_t kind)
{
	if (kind == ZONE_ADDR_NATIVE) {
		return zone_pva_to_meta(zone_pva_from_addr(addr), kind);
	} else {
		return (struct zone_page_metadata *)trunc_page(addr);
	}
}

#define zone_native_meta_from_addr(addr) \
	zone_meta_from_addr((vm_offset_t)(addr), ZONE_ADDR_NATIVE)

__header_always_inline vm_offset_t
zone_meta_to_addr(struct zone_page_metadata *meta, zone_addr_kind_t kind)
{
	if (kind == ZONE_ADDR_NATIVE) {
		return ptoa((int)(meta - zone_info.zi_array_base));
	} else {
		return (vm_offset_t)meta;
	}
}

__header_always_inline void
zone_meta_queue_push(zone_t z, zone_pva_t *headp,
    struct zone_page_metadata *meta, zone_addr_kind_t kind)
{
	zone_pva_t head = *headp;
	zone_pva_t queue_pva = zone_queue_encode(headp);
	struct zone_page_metadata *tmp;

	meta->zm_page_next = head;
	if (!zone_pva_is_null(head)) {
		tmp = zone_pva_to_meta(head, kind);
		if (!zone_pva_is_equal(tmp->zm_page_prev, queue_pva)) {
			zone_page_metadata_list_corruption(z, meta);
		}
		tmp->zm_page_prev = zone_pva_from_meta(meta, kind);
	}
	meta->zm_page_prev = queue_pva;
	*headp = zone_pva_from_meta(meta, kind);
}

__header_always_inline struct zone_page_metadata *
zone_meta_queue_pop(zone_t z, zone_pva_t *headp, zone_addr_kind_t kind,
    vm_offset_t *page_addrp)
{
	zone_pva_t head = *headp;
	struct zone_page_metadata *meta = zone_pva_to_meta(head, kind);
	vm_offset_t page_addr = zone_pva_to_addr(head);
	struct zone_page_metadata *tmp;

	if (kind == ZONE_ADDR_NATIVE && !from_native_meta_map(meta)) {
		zone_page_metadata_native_queue_corruption(z, headp);
	}
	if (kind == ZONE_ADDR_FOREIGN && from_zone_map(meta, sizeof(*meta))) {
		zone_page_metadata_foreign_queue_corruption(z, headp);
	}

	if (!zone_pva_is_null(meta->zm_page_next)) {
		tmp = zone_pva_to_meta(meta->zm_page_next, kind);
		if (!zone_pva_is_equal(tmp->zm_page_prev, head)) {
			zone_page_metadata_list_corruption(z, meta);
		}
		tmp->zm_page_prev = meta->zm_page_prev;
	}
	*headp = meta->zm_page_next;

	*page_addrp = page_addr;
	return meta;
}

__header_always_inline void
zone_meta_requeue(zone_t z, zone_pva_t *headp,
    struct zone_page_metadata *meta, zone_addr_kind_t kind)
{
	zone_pva_t meta_pva = zone_pva_from_meta(meta, kind);
	struct zone_page_metadata *tmp;

	if (!zone_pva_is_null(meta->zm_page_next)) {
		tmp = zone_pva_to_meta(meta->zm_page_next, kind);
		if (!zone_pva_is_equal(tmp->zm_page_prev, meta_pva)) {
			zone_page_metadata_list_corruption(z, meta);
		}
		tmp->zm_page_prev = meta->zm_page_prev;
	}
	if (zone_pva_is_queue(meta->zm_page_prev)) {
		zone_queue_set_head(z, meta->zm_page_prev, meta_pva, meta);
	} else {
		tmp = zone_pva_to_meta(meta->zm_page_prev, kind);
		if (!zone_pva_is_equal(tmp->zm_page_next, meta_pva)) {
			zone_page_metadata_list_corruption(z, meta);
		}
		tmp->zm_page_next = meta->zm_page_next;
	}

	zone_meta_queue_push(z, headp, meta, kind);
}

/*
 * Routine to populate a page backing metadata in the zone_metadata_region.
 * Must be called without the zone lock held as it might potentially block.
 */
static void
zone_meta_populate(struct zone_page_metadata *from, struct zone_page_metadata *to)
{
	vm_offset_t page_addr = trunc_page(from);

	for (; page_addr < (vm_offset_t)to; page_addr += PAGE_SIZE) {
#if !KASAN_ZALLOC
		/*
		 * This can race with another thread doing a populate on the same metadata
		 * page, where we see an updated pmap but unmapped KASan shadow, causing a
		 * fault in the shadow when we first access the metadata page. Avoid this
		 * by always synchronizing on the zone_metadata_region lock with KASan.
		 */
		if (pmap_find_phys(kernel_pmap, page_addr)) {
			continue;
		}
#endif

		for (;;) {
			kern_return_t ret = KERN_SUCCESS;

			/* All updates to the zone_metadata_region are done under the zone_metadata_region_lck */
			lck_mtx_lock(&zone_metadata_region_lck);
			if (0 == pmap_find_phys(kernel_pmap, page_addr)) {
				ret = kernel_memory_populate(kernel_map, page_addr,
				    PAGE_SIZE, KMA_NOPAGEWAIT | KMA_KOBJECT | KMA_ZERO,
				    VM_KERN_MEMORY_OSFMK);
			}
			lck_mtx_unlock(&zone_metadata_region_lck);

			if (ret == KERN_SUCCESS) {
				break;
			}

			/*
			 * We can't pass KMA_NOPAGEWAIT under a global lock as it leads
			 * to bad system deadlocks, so if the allocation failed,
			 * we need to do the VM_PAGE_WAIT() outside of the lock.
			 */
			VM_PAGE_WAIT();
		}
	}
}

static inline bool
zone_allocated_element_offset_is_valid(zone_t zone, vm_offset_t addr,
    vm_offset_t page, zone_addr_kind_t kind)
{
	vm_offset_t offs = addr - page - ZONE_PAGE_FIRST_OFFSET(kind);
	vm_offset_t esize = zone_elem_size(zone);

	if (esize & (esize - 1)) { /* not a power of 2 */
		return (offs % esize) == 0;
	} else {
		return (offs & (esize - 1)) == 0;
	}
}

__attribute__((always_inline))
static struct zone_page_metadata *
zone_allocated_element_resolve(zone_t zone, vm_offset_t addr,
    vm_offset_t *pagep, zone_addr_kind_t *kindp)
{
	struct zone_page_metadata *meta;
	zone_addr_kind_t kind;
	vm_offset_t page;
	vm_offset_t esize = zone_elem_size(zone);

	kind = zone_addr_kind(addr, esize);
	page = trunc_page(addr);
	meta = zone_meta_from_addr(addr, kind);

	if (kind == ZONE_ADDR_NATIVE) {
		if (meta->zm_secondary_page) {
			if (meta->zm_percpu) {
				zone_invalid_element_addr_panic(zone, addr);
			}
			page -= ptoa(meta->zm_page_count);
			meta -= meta->zm_page_count;
		}
	} else if (!zone->allows_foreign) {
		zone_page_metadata_foreign_confusion_panic(zone, addr);
#if __LP64__
	} else if (!from_foreign_range(addr, esize)) {
		zone_invalid_foreign_addr_panic(zone, addr);
#else
	} else if (!pmap_kernel_va(addr)) {
		zone_invalid_element_addr_panic(zone, addr);
#endif
	}

	if (!zone_allocated_element_offset_is_valid(zone, addr, page, kind)) {
		zone_invalid_element_addr_panic(zone, addr);
	}

	if (!zone_has_index(zone, meta->zm_index)) {
		zone_page_metadata_index_confusion_panic(zone, addr, meta);
	}

	if (kindp) {
		*kindp = kind;
	}
	if (pagep) {
		*pagep = page;
	}
	return meta;
}

__attribute__((always_inline))
void
zone_allocated_element_validate(zone_t zone, vm_offset_t addr)
{
	zone_allocated_element_resolve(zone, addr, NULL, NULL);
}

__header_always_inline vm_offset_t
zone_page_meta_get_freelist(zone_t zone, struct zone_page_metadata *meta,
    vm_offset_t page)
{
	assert(!meta->zm_secondary_page);
	if (meta->zm_freelist_offs == PAGE_METADATA_EMPTY_FREELIST) {
		return 0;
	}

	vm_size_t size = ptoa(meta->zm_percpu ? 1 : meta->zm_page_count);
	if (meta->zm_freelist_offs + zone_elem_size(zone) > size) {
		zone_metadata_corruption(zone, meta, "freelist corruption");
	}

	return page + meta->zm_freelist_offs;
}

__header_always_inline void
zone_page_meta_set_freelist(struct zone_page_metadata *meta,
    vm_offset_t page, vm_offset_t addr)
{
	assert(!meta->zm_secondary_page);
	if (addr) {
		meta->zm_freelist_offs = (uint16_t)(addr - page);
	} else {
		meta->zm_freelist_offs = PAGE_METADATA_EMPTY_FREELIST;
	}
}

static bool
zone_page_meta_is_sane_element(zone_t zone, struct zone_page_metadata *meta,
    vm_offset_t page, vm_offset_t element, zone_addr_kind_t kind)
{
	if (element == 0) {
		/* ends of the freelist are NULL */
		return true;
	}
	if (element < page + ZONE_PAGE_FIRST_OFFSET(kind)) {
		return false;
	}
	vm_size_t size = ptoa(meta->zm_percpu ? 1 : meta->zm_page_count);
	if (element > page + size - zone_elem_size(zone)) {
		return false;
	}
	return true;
}

/* Routine to get the size of a zone allocated address.
 * If the address doesnt belong to the zone maps, returns 0.
 */
vm_size_t
zone_element_size(void *addr, zone_t *z)
{
	struct zone_page_metadata *meta;
	struct zone *src_zone;

	if (from_zone_map(addr, sizeof(void *))) {
		meta = zone_native_meta_from_addr(addr);
		src_zone = &zone_array[meta->zm_index];
		if (z) {
			*z = src_zone;
		}
		return zone_elem_size(src_zone);
	}
#if CONFIG_GZALLOC
	if (__improbable(gzalloc_enabled())) {
		vm_size_t gzsize;
		if (gzalloc_element_size(addr, z, &gzsize)) {
			return gzsize;
		}
	}
#endif /* CONFIG_GZALLOC */

	return 0;
}

/* This function just formats the reason for the panics by redoing the checks */
__abortlike
static void
zone_require_panic(zone_t zone, void *addr)
{
	uint32_t zindex;
	zone_t other;

	if (!from_zone_map(addr, zone_elem_size(zone))) {
		panic("zone_require failed: address not in a zone (addr: %p)", addr);
	}

	zindex = zone_native_meta_from_addr(addr)->zm_index;
	other = &zone_array[zindex];
	if (zindex >= os_atomic_load(&num_zones, relaxed) || !other->z_self) {
		panic("zone_require failed: invalid zone index %d "
		    "(addr: %p, expected: %s%s)", zindex,
		    addr, zone_heap_name(zone), zone->z_name);
	} else {
		panic("zone_require failed: address in unexpected zone id %d (%s%s) "
		    "(addr: %p, expected: %s%s)",
		    zindex, zone_heap_name(other), other->z_name,
		    addr, zone_heap_name(zone), zone->z_name);
	}
}

__abortlike
static void
zone_id_require_panic(zone_id_t zid, void *addr)
{
	zone_require_panic(&zone_array[zid], addr);
}

/*
 * Routines to panic if a pointer is not mapped to an expected zone.
 * This can be used as a means of pinning an object to the zone it is expected
 * to be a part of.  Causes a panic if the address does not belong to any
 * specified zone, does not belong to any zone, has been freed and therefore
 * unmapped from the zone, or the pointer contains an uninitialized value that
 * does not belong to any zone.
 *
 * Note that this can only work with collectable zones without foreign pages.
 */
void
zone_require(zone_t zone, void *addr)
{
	if (__probable(from_general_submap(addr, zone_elem_size(zone)) &&
	    (zone_has_index(zone, zone_native_meta_from_addr(addr)->zm_index)))) {
		return;
	}
#if CONFIG_GZALLOC
	if (__probable(gzalloc_enabled())) {
		return;
	}
#endif
	zone_require_panic(zone, addr);
}

void
zone_id_require(zone_id_t zid, vm_size_t esize, void *addr)
{
	if (__probable(from_general_submap(addr, esize) &&
	    (zid == zone_native_meta_from_addr(addr)->zm_index))) {
		return;
	}
#if CONFIG_GZALLOC
	if (__probable(gzalloc_enabled())) {
		return;
	}
#endif
	zone_id_require_panic(zid, addr);
}

bool
zone_owns(zone_t zone, void *addr)
{
	if (__probable(from_general_submap(addr, zone_elem_size(zone)) &&
	    (zone_has_index(zone, zone_native_meta_from_addr(addr)->zm_index)))) {
		return true;
	}
#if CONFIG_GZALLOC
	if (__probable(gzalloc_enabled())) {
		return true;
	}
#endif
	return false;
}

#pragma mark ZTAGS
#if VM_MAX_TAG_ZONES

// for zones with tagging enabled:

// calculate a pointer to the tag base entry,
// holding either a uint32_t the first tag offset for a page in the zone map,
// or two uint16_t tags if the page can only hold one or two elements

#define ZTAGBASE(zone, element) \
    (&((uint32_t *)zone_tagbase_min)[atop((element) - zone_info.zi_map_range.min_address)])

// pointer to the tag for an element
#define ZTAG(zone, element)                                     \
    ({                                                          \
	vm_tag_t * result;                                      \
	if ((zone)->tags_inline) {                              \
	    result = (vm_tag_t *) ZTAGBASE((zone), (element));  \
	    if ((page_mask & element) >= zone_elem_size(zone)) result++;    \
	} else {                                                \
	    result =  &((vm_tag_t *)zone_tags_min)[ZTAGBASE((zone), (element))[0] + ((element) & page_mask) / zone_elem_size((zone))];   \
	}                                                       \
	result;                                                 \
    })


static vm_offset_t  zone_tagbase_min;
static vm_offset_t  zone_tagbase_max;
static vm_offset_t  zone_tagbase_map_size;
static vm_map_t     zone_tagbase_map;

static vm_offset_t  zone_tags_min;
static vm_offset_t  zone_tags_max;
static vm_offset_t  zone_tags_map_size;
static vm_map_t     zone_tags_map;

// simple heap allocator for allocating the tags for new memory

LCK_MTX_EARLY_DECLARE(ztLock, &zone_locks_grp); /* heap lock */

enum{
	ztFreeIndexCount = 8,
	ztFreeIndexMax   = (ztFreeIndexCount - 1),
	ztTagsPerBlock   = 4
};

struct ztBlock {
#if __LITTLE_ENDIAN__
	uint64_t free:1,
	    next:21,
	    prev:21,
	    size:21;
#else
// ztBlock needs free bit least significant
#error !__LITTLE_ENDIAN__
#endif
};
typedef struct ztBlock ztBlock;

static ztBlock * ztBlocks;
static uint32_t  ztBlocksCount;
static uint32_t  ztBlocksFree;

static uint32_t
ztLog2up(uint32_t size)
{
	if (1 == size) {
		size = 0;
	} else {
		size = 32 - __builtin_clz(size - 1);
	}
	return size;
}

static uint32_t
ztLog2down(uint32_t size)
{
	size = 31 - __builtin_clz(size);
	return size;
}

static void
ztFault(vm_map_t map, const void * address, size_t size, uint32_t flags)
{
	vm_map_offset_t addr = (vm_map_offset_t) address;
	vm_map_offset_t page, end;

	page = trunc_page(addr);
	end  = round_page(addr + size);

	for (; page < end; page += page_size) {
		if (!pmap_find_phys(kernel_pmap, page)) {
			kern_return_t __unused
			ret = kernel_memory_populate(map, page, PAGE_SIZE,
			    KMA_KOBJECT | flags, VM_KERN_MEMORY_DIAG);
			assert(ret == KERN_SUCCESS);
		}
	}
}

static boolean_t
ztPresent(const void * address, size_t size)
{
	vm_map_offset_t addr = (vm_map_offset_t) address;
	vm_map_offset_t page, end;
	boolean_t       result;

	page = trunc_page(addr);
	end  = round_page(addr + size);
	for (result = TRUE; (page < end); page += page_size) {
		result = pmap_find_phys(kernel_pmap, page);
		if (!result) {
			break;
		}
	}
	return result;
}


void __unused
ztDump(boolean_t sanity);
void __unused
ztDump(boolean_t sanity)
{
	uint32_t q, cq, p;

	for (q = 0; q <= ztFreeIndexMax; q++) {
		p = q;
		do{
			if (sanity) {
				cq = ztLog2down(ztBlocks[p].size);
				if (cq > ztFreeIndexMax) {
					cq = ztFreeIndexMax;
				}
				if (!ztBlocks[p].free
				    || ((p != q) && (q != cq))
				    || (ztBlocks[ztBlocks[p].next].prev != p)
				    || (ztBlocks[ztBlocks[p].prev].next != p)) {
					kprintf("zterror at %d", p);
					ztDump(FALSE);
					kprintf("zterror at %d", p);
					assert(FALSE);
				}
				continue;
			}
			kprintf("zt[%03d]%c %d, %d, %d\n",
			    p, ztBlocks[p].free ? 'F' : 'A',
			    ztBlocks[p].next, ztBlocks[p].prev,
			    ztBlocks[p].size);
			p = ztBlocks[p].next;
			if (p == q) {
				break;
			}
		}while (p != q);
		if (!sanity) {
			printf("\n");
		}
	}
	if (!sanity) {
		printf("-----------------------\n");
	}
}



#define ZTBDEQ(idx)                                                 \
    ztBlocks[ztBlocks[(idx)].prev].next = ztBlocks[(idx)].next;     \
    ztBlocks[ztBlocks[(idx)].next].prev = ztBlocks[(idx)].prev;

static void
ztFree(zone_t zone __unused, uint32_t index, uint32_t count)
{
	uint32_t q, w, p, size, merge;

	assert(count);
	ztBlocksFree += count;

	// merge with preceding
	merge = (index + count);
	if ((merge < ztBlocksCount)
	    && ztPresent(&ztBlocks[merge], sizeof(ztBlocks[merge]))
	    && ztBlocks[merge].free) {
		ZTBDEQ(merge);
		count += ztBlocks[merge].size;
	}

	// merge with following
	merge = (index - 1);
	if ((merge > ztFreeIndexMax)
	    && ztPresent(&ztBlocks[merge], sizeof(ztBlocks[merge]))
	    && ztBlocks[merge].free) {
		size = ztBlocks[merge].size;
		count += size;
		index -= size;
		ZTBDEQ(index);
	}

	q = ztLog2down(count);
	if (q > ztFreeIndexMax) {
		q = ztFreeIndexMax;
	}
	w = q;
	// queue in order of size
	while (TRUE) {
		p = ztBlocks[w].next;
		if (p == q) {
			break;
		}
		if (ztBlocks[p].size >= count) {
			break;
		}
		w = p;
	}
	ztBlocks[p].prev = index;
	ztBlocks[w].next = index;

	// fault in first
	ztFault(zone_tags_map, &ztBlocks[index], sizeof(ztBlocks[index]), 0);

	// mark first & last with free flag and size
	ztBlocks[index].free = TRUE;
	ztBlocks[index].size = count;
	ztBlocks[index].prev = w;
	ztBlocks[index].next = p;
	if (count > 1) {
		index += (count - 1);
		// fault in last
		ztFault(zone_tags_map, &ztBlocks[index], sizeof(ztBlocks[index]), 0);
		ztBlocks[index].free = TRUE;
		ztBlocks[index].size = count;
	}
}

static uint32_t
ztAlloc(zone_t zone, uint32_t count)
{
	uint32_t q, w, p, leftover;

	assert(count);

	q = ztLog2up(count);
	if (q > ztFreeIndexMax) {
		q = ztFreeIndexMax;
	}
	do{
		w = q;
		while (TRUE) {
			p = ztBlocks[w].next;
			if (p == q) {
				break;
			}
			if (ztBlocks[p].size >= count) {
				// dequeue, mark both ends allocated
				ztBlocks[w].next = ztBlocks[p].next;
				ztBlocks[ztBlocks[p].next].prev = w;
				ztBlocks[p].free = FALSE;
				ztBlocksFree -= ztBlocks[p].size;
				if (ztBlocks[p].size > 1) {
					ztBlocks[p + ztBlocks[p].size - 1].free = FALSE;
				}

				// fault all the allocation
				ztFault(zone_tags_map, &ztBlocks[p], count * sizeof(ztBlocks[p]), 0);
				// mark last as allocated
				if (count > 1) {
					ztBlocks[p + count - 1].free = FALSE;
				}
				// free remainder
				leftover = ztBlocks[p].size - count;
				if (leftover) {
					ztFree(zone, p + ztBlocks[p].size - leftover, leftover);
				}

				return p;
			}
			w = p;
		}
		q++;
	}while (q <= ztFreeIndexMax);

	return -1U;
}

__startup_func
static void
zone_tagging_init(vm_size_t max_zonemap_size)
{
	kern_return_t         ret;
	vm_map_kernel_flags_t vmk_flags;
	uint32_t              idx;

	// allocate submaps VM_KERN_MEMORY_DIAG

	zone_tagbase_map_size = atop(max_zonemap_size) * sizeof(uint32_t);
	vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
	vmk_flags.vmkf_permanent = TRUE;
	ret = kmem_suballoc(kernel_map, &zone_tagbase_min, zone_tagbase_map_size,
	    FALSE, VM_FLAGS_ANYWHERE, vmk_flags, VM_KERN_MEMORY_DIAG,
	    &zone_tagbase_map);

	if (ret != KERN_SUCCESS) {
		panic("zone_init: kmem_suballoc failed");
	}
	zone_tagbase_max = zone_tagbase_min + round_page(zone_tagbase_map_size);

	zone_tags_map_size = 2048 * 1024 * sizeof(vm_tag_t);
	vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
	vmk_flags.vmkf_permanent = TRUE;
	ret = kmem_suballoc(kernel_map, &zone_tags_min, zone_tags_map_size,
	    FALSE, VM_FLAGS_ANYWHERE, vmk_flags, VM_KERN_MEMORY_DIAG,
	    &zone_tags_map);

	if (ret != KERN_SUCCESS) {
		panic("zone_init: kmem_suballoc failed");
	}
	zone_tags_max = zone_tags_min + round_page(zone_tags_map_size);

	ztBlocks = (ztBlock *) zone_tags_min;
	ztBlocksCount = (uint32_t)(zone_tags_map_size / sizeof(ztBlock));

	// initialize the qheads
	lck_mtx_lock(&ztLock);

	ztFault(zone_tags_map, &ztBlocks[0], sizeof(ztBlocks[0]), 0);
	for (idx = 0; idx < ztFreeIndexCount; idx++) {
		ztBlocks[idx].free = TRUE;
		ztBlocks[idx].next = idx;
		ztBlocks[idx].prev = idx;
		ztBlocks[idx].size = 0;
	}
	// free remaining space
	ztFree(NULL, ztFreeIndexCount, ztBlocksCount - ztFreeIndexCount);

	lck_mtx_unlock(&ztLock);
}

static void
ztMemoryAdd(zone_t zone, vm_offset_t mem, vm_size_t size)
{
	uint32_t * tagbase;
	uint32_t   count, block, blocks, idx;
	size_t     pages;

	pages = atop(size);
	tagbase = ZTAGBASE(zone, mem);

	lck_mtx_lock(&ztLock);

	// fault tagbase
	ztFault(zone_tagbase_map, tagbase, pages * sizeof(uint32_t), 0);

	if (!zone->tags_inline) {
		// allocate tags
		count = (uint32_t)(size / zone_elem_size(zone));
		blocks = ((count + ztTagsPerBlock - 1) / ztTagsPerBlock);
		block = ztAlloc(zone, blocks);
		if (-1U == block) {
			ztDump(false);
		}
		assert(-1U != block);
	}

	lck_mtx_unlock(&ztLock);

	if (!zone->tags_inline) {
		// set tag base for each page
		block *= ztTagsPerBlock;
		for (idx = 0; idx < pages; idx++) {
			vm_offset_t esize = zone_elem_size(zone);
			tagbase[idx] = block + (uint32_t)((ptoa(idx) + esize - 1) / esize);
		}
	}
}

static void
ztMemoryRemove(zone_t zone, vm_offset_t mem, vm_size_t size)
{
	uint32_t * tagbase;
	uint32_t   count, block, blocks, idx;
	size_t     pages;

	// set tag base for each page
	pages = atop(size);
	tagbase = ZTAGBASE(zone, mem);
	block = tagbase[0];
	for (idx = 0; idx < pages; idx++) {
		tagbase[idx] = 0xFFFFFFFF;
	}

	lck_mtx_lock(&ztLock);
	if (!zone->tags_inline) {
		count = (uint32_t)(size / zone_elem_size(zone));
		blocks = ((count + ztTagsPerBlock - 1) / ztTagsPerBlock);
		assert(block != 0xFFFFFFFF);
		block /= ztTagsPerBlock;
		ztFree(NULL /* zone is unlocked */, block, blocks);
	}

	lck_mtx_unlock(&ztLock);
}

uint32_t
zone_index_from_tag_index(uint32_t tag_zone_index, vm_size_t * elem_size)
{
	simple_lock(&all_zones_lock, &zone_locks_grp);

	zone_index_foreach(idx) {
		zone_t z = &zone_array[idx];
		if (!z->tags) {
			continue;
		}
		if (tag_zone_index != z->tag_zone_index) {
			continue;
		}

		*elem_size = zone_elem_size(z);
		simple_unlock(&all_zones_lock);
		return idx;
	}

	simple_unlock(&all_zones_lock);

	return -1U;
}

#endif /* VM_MAX_TAG_ZONES */
#pragma mark zalloc helpers

const char *
zone_name(zone_t z)
{
	return z->z_name;
}

const char *
zone_heap_name(zone_t z)
{
	if (__probable(z->kalloc_heap < KHEAP_ID_COUNT)) {
		return kalloc_heap_names[z->kalloc_heap];
	}
	return "invalid";
}

static inline vm_size_t
zone_submaps_approx_size(void)
{
	vm_size_t size = 0;

	for (unsigned idx = 0; idx <= zone_last_submap_idx; idx++) {
		size += zone_submaps[idx]->size;
	}

	return size;
}

bool
zone_maps_owned(vm_address_t addr, vm_size_t size)
{
	return from_zone_map(addr, size);
}

void
zone_map_sizes(
	vm_map_size_t    *psize,
	vm_map_size_t    *pfree,
	vm_map_size_t    *plargest_free)
{
	vm_map_sizes(zone_submaps[Z_SUBMAP_IDX_GENERAL_MAP], psize, pfree, plargest_free);
}

vm_map_t
zone_submap(zone_t zone)
{
	return submap_for_zone(zone);
}

unsigned
zpercpu_count(void)
{
	return zpercpu_early_count;
}

int
track_this_zone(const char *zonename, const char *logname)
{
	unsigned int len;
	const char *zc = zonename;
	const char *lc = logname;

	/*
	 * Compare the strings.  We bound the compare by MAX_ZONE_NAME.
	 */

	for (len = 1; len <= MAX_ZONE_NAME; zc++, lc++, len++) {
		/*
		 * If the current characters don't match, check for a space in
		 * in the zone name and a corresponding period in the log name.
		 * If that's not there, then the strings don't match.
		 */

		if (*zc != *lc && !(*zc == ' ' && *lc == '.')) {
			break;
		}

		/*
		 * The strings are equal so far.  If we're at the end, then it's a match.
		 */

		if (*zc == '\0') {
			return TRUE;
		}
	}

	return FALSE;
}

#if DEBUG || DEVELOPMENT

vm_size_t
zone_element_info(void *addr, vm_tag_t * ptag)
{
	vm_size_t     size = 0;
	vm_tag_t      tag = VM_KERN_MEMORY_NONE;
	struct zone_page_metadata *meta;
	struct zone *src_zone;

	if (from_zone_map(addr, sizeof(void *))) {
		meta = zone_native_meta_from_addr(addr);
		src_zone = &zone_array[meta->zm_index];
#if VM_MAX_TAG_ZONES
		if (__improbable(src_zone->tags)) {
			tag = (ZTAG(src_zone, (vm_offset_t) addr)[0] >> 1);
		}
#endif /* VM_MAX_TAG_ZONES */
		size = zone_elem_size(src_zone);
	} else {
#if CONFIG_GZALLOC
		gzalloc_element_size(addr, NULL, &size);
#endif /* CONFIG_GZALLOC */
	}
	*ptag = tag;
	return size;
}

#endif /* DEBUG || DEVELOPMENT */

/* Someone wrote to freed memory. */
__abortlike
static void
zone_element_was_modified_panic(
	zone_t        zone,
	vm_offset_t   element,
	vm_offset_t   found,
	vm_offset_t   expected,
	vm_offset_t   offset)
{
	panic("a freed zone element has been modified in zone %s%s: "
	    "expected %p but found %p, bits changed %p, "
	    "at offset %d of %d in element %p, cookies %p %p",
	    zone_heap_name(zone),
	    zone->z_name,
	    (void *)   expected,
	    (void *)   found,
	    (void *)   (expected ^ found),
	    (uint32_t) offset,
	    (uint32_t) zone_elem_size(zone),
	    (void *)   element,
	    (void *)   zp_nopoison_cookie,
	    (void *)   zp_poisoned_cookie);
}

/* The backup pointer is stored in the last pointer-sized location in an element. */
__header_always_inline vm_offset_t *
get_backup_ptr(vm_size_t elem_size, vm_offset_t *element)
{
	return (vm_offset_t *)((vm_offset_t)element + elem_size - sizeof(vm_offset_t));
}

/*
 * The primary and backup pointers don't match.
 * Determine which one was likely the corrupted pointer, find out what it
 * probably should have been, and panic.
 */
__abortlike
static void
backup_ptr_mismatch_panic(
	zone_t        zone,
	struct zone_page_metadata *page_meta,
	vm_offset_t   page,
	vm_offset_t   element)
{
	vm_offset_t primary = *(vm_offset_t *)element;
	vm_offset_t backup  = *get_backup_ptr(zone_elem_size(zone), &element);
	vm_offset_t likely_backup;
	vm_offset_t likely_primary;
	zone_addr_kind_t kind = zone_addr_kind(page, zone_elem_size(zone));

	likely_primary = primary ^ zp_nopoison_cookie;
	boolean_t   sane_backup;
	boolean_t   sane_primary = zone_page_meta_is_sane_element(zone, page_meta,
	    page, likely_primary, kind);
	boolean_t   element_was_poisoned = (backup & 0x1);

#if defined(__LP64__)
	/* We can inspect the tag in the upper bits for additional confirmation */
	if ((backup & 0xFFFFFF0000000000) == 0xFACADE0000000000) {
		element_was_poisoned = TRUE;
	} else if ((backup & 0xFFFFFF0000000000) == 0xC0FFEE0000000000) {
		element_was_poisoned = FALSE;
	}
#endif

	if (element_was_poisoned) {
		likely_backup = backup ^ zp_poisoned_cookie;
	} else {
		likely_backup = backup ^ zp_nopoison_cookie;
	}
	sane_backup = zone_page_meta_is_sane_element(zone, page_meta,
	    page, likely_backup, kind);

	/* The primary is definitely the corrupted one */
	if (!sane_primary && sane_backup) {
		zone_element_was_modified_panic(zone, element, primary, (likely_backup ^ zp_nopoison_cookie), 0);
	}

	/* The backup is definitely the corrupted one */
	if (sane_primary && !sane_backup) {
		zone_element_was_modified_panic(zone, element, backup,
		    (likely_primary ^ (element_was_poisoned ? zp_poisoned_cookie : zp_nopoison_cookie)),
		    zone_elem_size(zone) - sizeof(vm_offset_t));
	}

	/*
	 * Not sure which is the corrupted one.
	 * It's less likely that the backup pointer was overwritten with
	 * ( (sane address) ^ (valid cookie) ), so we'll guess that the
	 * primary pointer has been overwritten with a sane but incorrect address.
	 */
	if (sane_primary && sane_backup) {
		zone_element_was_modified_panic(zone, element, primary, (likely_backup ^ zp_nopoison_cookie), 0);
	}

	/* Neither are sane, so just guess. */
	zone_element_was_modified_panic(zone, element, primary, (likely_backup ^ zp_nopoison_cookie), 0);
}

/*
 * zone_sequestered_page_get
 * z is locked
 */
static struct zone_page_metadata *
zone_sequestered_page_get(zone_t z, vm_offset_t *page)
{
	const zone_addr_kind_t kind = ZONE_ADDR_NATIVE;

	if (!zone_pva_is_null(z->pages_sequester)) {
		if (os_sub_overflow(z->sequester_page_count, z->alloc_pages,
		    &z->sequester_page_count)) {
			zone_accounting_panic(z, "sequester_page_count wrap-around");
		}
		return zone_meta_queue_pop(z, &z->pages_sequester, kind, page);
	}

	return NULL;
}

/*
 * zone_sequestered_page_populate
 * z is unlocked
 * page_meta is invalid on failure
 */
static kern_return_t
zone_sequestered_page_populate(zone_t z, struct zone_page_metadata *page_meta,
    vm_offset_t space, vm_size_t alloc_size, int zflags)
{
	kern_return_t retval;

	assert(alloc_size == ptoa(z->alloc_pages));
	retval = kernel_memory_populate(submap_for_zone(z), space, alloc_size,
	    zflags, VM_KERN_MEMORY_ZONE);
	if (retval != KERN_SUCCESS) {
		lock_zone(z);
		zone_meta_queue_push(z, &z->pages_sequester, page_meta, ZONE_ADDR_NATIVE);
		z->sequester_page_count += z->alloc_pages;
		unlock_zone(z);
	}
	return retval;
}

#pragma mark Zone poisoning/zeroing

/*
 * Initialize zone poisoning
 * called from zone_bootstrap before any allocations are made from zalloc
 */
__startup_func
static void
zp_bootstrap(void)
{
	char temp_buf[16];

	/*
	 * Initialize backup pointer random cookie for poisoned elements
	 * Try not to call early_random() back to back, it may return
	 * the same value if mach_absolute_time doesn't have sufficient time
	 * to tick over between calls.  <rdar://problem/11597395>
	 * (This is only a problem on embedded devices)
	 */
	zp_poisoned_cookie = (uintptr_t) early_random();

	/* -zp: enable poisoning for every alloc and free */
	if (PE_parse_boot_argn("-zp", temp_buf, sizeof(temp_buf))) {
		zp_factor = 1;
	}

	/* -no-zp: disable poisoning */
	if (PE_parse_boot_argn("-no-zp", temp_buf, sizeof(temp_buf))) {
		zp_factor = 0;
		printf("Zone poisoning disabled\n");
	}

	/* Initialize backup pointer random cookie for unpoisoned elements */
	zp_nopoison_cookie = (uintptr_t) early_random();

#if MACH_ASSERT
	if (zp_poisoned_cookie == zp_nopoison_cookie) {
		panic("early_random() is broken: %p and %p are not random\n",
		    (void *) zp_poisoned_cookie, (void *) zp_nopoison_cookie);
	}
#endif

	/*
	 * Use the last bit in the backup pointer to hint poisoning state
	 * to backup_ptr_mismatch_panic. Valid zone pointers are aligned, so
	 * the low bits are zero.
	 */
	zp_poisoned_cookie |=   (uintptr_t)0x1ULL;
	zp_nopoison_cookie &= ~((uintptr_t)0x1ULL);

#if defined(__LP64__)
	/*
	 * Make backup pointers more obvious in GDB for 64 bit
	 * by making OxFFFFFF... ^ cookie = 0xFACADE...
	 * (0xFACADE = 0xFFFFFF ^ 0x053521)
	 * (0xC0FFEE = 0xFFFFFF ^ 0x3f0011)
	 * The high 3 bytes of a zone pointer are always 0xFFFFFF, and are checked
	 * by the sanity check, so it's OK for that part of the cookie to be predictable.
	 *
	 * TODO: Use #defines, xors, and shifts
	 */

	zp_poisoned_cookie &= 0x000000FFFFFFFFFF;
	zp_poisoned_cookie |= 0x0535210000000000; /* 0xFACADE */

	zp_nopoison_cookie &= 0x000000FFFFFFFFFF;
	zp_nopoison_cookie |= 0x3f00110000000000; /* 0xC0FFEE */
#endif

	/*
	 * Initialize zp_min_size to two cachelines. Elements smaller than this will
	 * be zero-ed.
	 */
	ml_cpu_info_t cpu_info;
	ml_cpu_get_info(&cpu_info);
	zp_min_size = 2 * cpu_info.cache_line_size;
}

inline uint32_t
zone_poison_count_init(zone_t zone)
{
	return zp_factor + (((uint32_t)zone_elem_size(zone)) >> zp_scale) ^
	       (mach_absolute_time() & 0x7);
}

#if ZALLOC_ENABLE_POISONING
static bool
zfree_poison_element(zone_t zone, uint32_t *zp_count, vm_offset_t elem)
{
	bool poison = false;
	uint32_t zp_count_local;

	assert(!zone->percpu);
	if (zp_factor != 0) {
		/*
		 * Poison the memory of every zp_count-th element before it ends up
		 * on the freelist to catch use-after-free and use of uninitialized
		 * memory.
		 *
		 * Every element is poisoned when zp_factor is set to 1.
		 *
		 */
		zp_count_local = os_atomic_load(zp_count, relaxed);
		if (__improbable(zp_count_local == 0 || zp_factor == 1)) {
			poison = true;

			os_atomic_store(zp_count, zone_poison_count_init(zone), relaxed);

			/* memset_pattern{4|8} could help make this faster: <rdar://problem/4662004> */
			vm_offset_t *element_cursor  = ((vm_offset_t *) elem);
			vm_offset_t *end_cursor      = (vm_offset_t *)(elem + zone_elem_size(zone));

			for (; element_cursor < end_cursor; element_cursor++) {
				*element_cursor = ZONE_POISON;
			}
		} else {
			os_atomic_store(zp_count, zp_count_local - 1, relaxed);
			/*
			 * Zero first zp_min_size bytes of elements that aren't being poisoned.
			 * Element size is larger than zp_min_size in this path as elements
			 * that are smaller will always be zero-ed.
			 */
			bzero((void *) elem, zp_min_size);
		}
	}
	return poison;
}
#else
static bool
zfree_poison_element(zone_t zone, uint32_t *zp_count, vm_offset_t elem)
{
#pragma unused(zone, zp_count, elem)
	assert(!zone->percpu);
	return false;
}
#endif

__attribute__((always_inline))
static bool
zfree_clear(zone_t zone, vm_offset_t addr, vm_size_t elem_size)
{
	assert(zone->zfree_clear_mem);
	if (zone->percpu) {
		zpercpu_foreach_cpu(i) {
			bzero((void *)(addr + ptoa(i)), elem_size);
		}
	} else {
		bzero((void *)addr, elem_size);
	}

	return true;
}

/*
 * Zero the element if zone has zfree_clear_mem flag set else poison
 * the element if zp_count hits 0.
 */
__attribute__((always_inline))
bool
zfree_clear_or_poison(zone_t zone, uint32_t *zp_count, vm_offset_t addr)
{
	vm_size_t elem_size = zone_elem_size(zone);

	if (zone->zfree_clear_mem) {
		return zfree_clear(zone, addr, elem_size);
	}

	return zfree_poison_element(zone, zp_count, (vm_offset_t)addr);
}

/*
 * Clear out the old next pointer and backup to avoid leaking the zone
 * poisoning cookie and so that only values on the freelist have a valid
 * cookie.
 */
void
zone_clear_freelist_pointers(zone_t zone, vm_offset_t addr)
{
	vm_offset_t perm_value = 0;

	if (!zone->zfree_clear_mem) {
		perm_value = ZONE_POISON;
	}

	vm_offset_t *primary  = (vm_offset_t *) addr;
	vm_offset_t *backup   = get_backup_ptr(zone_elem_size(zone), primary);

	*primary = perm_value;
	*backup  = perm_value;
}

#if ZALLOC_ENABLE_POISONING
__abortlike
static void
zone_element_not_clear_panic(zone_t zone, void *addr)
{
	panic("Zone element %p was modified after free for zone %s%s: "
	    "Expected element to be cleared", addr, zone_heap_name(zone),
	    zone->z_name);
}

/*
 * Validate that the element was not tampered with while it was in the
 * freelist.
 */
void
zalloc_validate_element(zone_t zone, vm_offset_t addr, vm_size_t size, bool validate)
{
	if (zone->percpu) {
		assert(zone->zfree_clear_mem);
		zpercpu_foreach_cpu(i) {
			if (memcmp_zero_ptr_aligned((void *)(addr + ptoa(i)), size)) {
				zone_element_not_clear_panic(zone, (void *)(addr + ptoa(i)));
			}
		}
	} else if (zone->zfree_clear_mem) {
		if (memcmp_zero_ptr_aligned((void *)addr, size)) {
			zone_element_not_clear_panic(zone, (void *)addr);
		}
	} else if (__improbable(validate)) {
		const vm_offset_t *p   = (vm_offset_t *)addr;
		const vm_offset_t *end = (vm_offset_t *)(addr + size);

		for (; p < end; p++) {
			if (*p != ZONE_POISON) {
				zone_element_was_modified_panic(zone, addr,
				    *p, ZONE_POISON, (vm_offset_t)p - addr);
			}
		}
	} else {
		/*
		 * If element wasn't poisoned or entirely cleared, validate that the
		 * minimum bytes that were cleared on free haven't been corrupted.
		 * addr is advanced by ptr size as we have already validated and cleared
		 * the freelist pointer/zcache canary.
		 */
		if (memcmp_zero_ptr_aligned((void *) (addr + sizeof(vm_offset_t)),
		    zp_min_size - sizeof(vm_offset_t))) {
			zone_element_not_clear_panic(zone, (void *)addr);
		}
	}
}
#endif /* ZALLOC_ENABLE_POISONING */

#pragma mark Zone Leak Detection

/*
 * Zone leak debugging code
 *
 * When enabled, this code keeps a log to track allocations to a particular zone that have not
 * yet been freed.  Examining this log will reveal the source of a zone leak.  The log is allocated
 * only when logging is enabled, so there is no effect on the system when it's turned off.  Logging is
 * off by default.
 *
 * Enable the logging via the boot-args. Add the parameter "zlog=<zone>" to boot-args where <zone>
 * is the name of the zone you wish to log.
 *
 * This code only tracks one zone, so you need to identify which one is leaking first.
 * Generally, you'll know you have a leak when you get a "zalloc retry failed 3" panic from the zone
 * garbage collector.  Note that the zone name printed in the panic message is not necessarily the one
 * containing the leak.  So do a zprint from gdb and locate the zone with the bloated size.  This
 * is most likely the problem zone, so set zlog in boot-args to this zone name, reboot and re-run the test.  The
 * next time it panics with this message, examine the log using the kgmacros zstack, findoldest and countpcs.
 * See the help in the kgmacros for usage info.
 *
 *
 * Zone corruption logging
 *
 * Logging can also be used to help identify the source of a zone corruption.  First, identify the zone
 * that is being corrupted, then add "-zc zlog=<zone name>" to the boot-args.  When -zc is used in conjunction
 * with zlog, it changes the logging style to track both allocations and frees to the zone.  So when the
 * corruption is detected, examining the log will show you the stack traces of the callers who last allocated
 * and freed any particular element in the zone.  Use the findelem kgmacro with the address of the element that's been
 * corrupted to examine its history.  This should lead to the source of the corruption.
 */

/* Returns TRUE if we rolled over the counter at factor */
__header_always_inline bool
sample_counter(volatile uint32_t *count_p, uint32_t factor)
{
	uint32_t old_count, new_count = 0;
	if (count_p != NULL) {
		os_atomic_rmw_loop(count_p, old_count, new_count, relaxed, {
			new_count = old_count + 1;
			if (new_count >= factor) {
			        new_count = 0;
			}
		});
	}

	return new_count == 0;
}

#if ZONE_ENABLE_LOGGING
/* Log allocations and frees to help debug a zone element corruption */
TUNABLE(bool, corruption_debug_flag, "-zc", false);

#define MAX_NUM_ZONES_ALLOWED_LOGGING   10 /* Maximum 10 zones can be logged at once */

static int  max_num_zones_to_log = MAX_NUM_ZONES_ALLOWED_LOGGING;
static int  num_zones_logged = 0;

/*
 * The number of records in the log is configurable via the zrecs parameter in boot-args.  Set this to
 * the number of records you want in the log.  For example, "zrecs=10" sets it to 10 records. Since this
 * is the number of stacks suspected of leaking, we don't need many records.
 */

#if defined(__LP64__)
#define ZRECORDS_MAX            2560            /* Max records allowed in the log */
#else
#define ZRECORDS_MAX            1536            /* Max records allowed in the log */
#endif
#define ZRECORDS_DEFAULT        1024            /* default records in log if zrecs is not specificed in boot-args */

static TUNABLE(uint32_t, log_records, "zrecs", ZRECORDS_DEFAULT);

static void
zone_enable_logging(zone_t z)
{
	z->zlog_btlog = btlog_create(log_records, MAX_ZTRACE_DEPTH,
	    (corruption_debug_flag == FALSE) /* caller_will_remove_entries_for_element? */);

	if (z->zlog_btlog) {
		printf("zone: logging started for zone %s%s\n",
		    zone_heap_name(z), z->z_name);
	} else {
		printf("zone: couldn't allocate memory for zrecords, turning off zleak logging\n");
		z->zone_logging = false;
	}
}

/**
 * @function zone_setup_logging
 *
 * @abstract
 * Optionally sets up a zone for logging.
 *
 * @discussion
 * We recognized two boot-args:
 *
 *	zlog=<zone_to_log>
 *	zrecs=<num_records_in_log>
 *
 * The zlog arg is used to specify the zone name that should be logged,
 * and zrecs is used to control the size of the log.
 *
 * If zrecs is not specified, a default value is used.
 */
static void
zone_setup_logging(zone_t z)
{
	char zone_name[MAX_ZONE_NAME]; /* Temp. buffer for the zone name */
	char zlog_name[MAX_ZONE_NAME]; /* Temp. buffer to create the strings zlog1, zlog2 etc... */
	char zlog_val[MAX_ZONE_NAME];  /* the zone name we're logging, if any */

	/*
	 * Don't allow more than ZRECORDS_MAX records even if the user asked for more.
	 *
	 * This prevents accidentally hogging too much kernel memory
	 * and making the system unusable.
	 */
	if (log_records > ZRECORDS_MAX) {
		log_records = ZRECORDS_MAX;
	}

	/*
	 * Append kalloc heap name to zone name (if zone is used by kalloc)
	 */
	snprintf(zone_name, MAX_ZONE_NAME, "%s%s", zone_heap_name(z), z->z_name);

	/* zlog0 isn't allowed. */
	for (int i = 1; i <= max_num_zones_to_log; i++) {
		snprintf(zlog_name, MAX_ZONE_NAME, "zlog%d", i);

		if (PE_parse_boot_argn(zlog_name, zlog_val, sizeof(zlog_val)) &&
		    track_this_zone(zone_name, zlog_val)) {
			z->zone_logging = true;
			num_zones_logged++;
			break;
		}
	}

	/*
	 * Backwards compat. with the old boot-arg used to specify single zone
	 * logging i.e. zlog Needs to happen after the newer zlogn checks
	 * because the prefix will match all the zlogn
	 * boot-args.
	 */
	if (!z->zone_logging &&
	    PE_parse_boot_argn("zlog", zlog_val, sizeof(zlog_val)) &&
	    track_this_zone(zone_name, zlog_val)) {
		z->zone_logging = true;
		num_zones_logged++;
	}


	/*
	 * If we want to log a zone, see if we need to allocate buffer space for
	 * the log.
	 *
	 * Some vm related zones are zinit'ed before we can do a kmem_alloc, so
	 * we have to defer allocation in that case.
	 *
	 * zone_init() will finish the job.
	 *
	 * If we want to log one of the VM related zones that's set up early on,
	 * we will skip allocation of the log until zinit is called again later
	 * on some other zone.
	 */
	if (z->zone_logging && startup_phase >= STARTUP_SUB_KMEM_ALLOC) {
		zone_enable_logging(z);
	}
}

/*
 * Each record in the log contains a pointer to the zone element it refers to,
 * and a small array to hold the pc's from the stack trace.  A
 * record is added to the log each time a zalloc() is done in the zone_of_interest.  For leak debugging,
 * the record is cleared when a zfree() is done.  For corruption debugging, the log tracks both allocs and frees.
 * If the log fills, old records are replaced as if it were a circular buffer.
 */


/*
 * Decide if we want to log this zone by doing a string compare between a zone name and the name
 * of the zone to log. Return true if the strings are equal, false otherwise.  Because it's not
 * possible to include spaces in strings passed in via the boot-args, a period in the logname will
 * match a space in the zone name.
 */

/*
 * Test if we want to log this zalloc/zfree event.  We log if this is the zone we're interested in and
 * the buffer for the records has been allocated.
 */

#define DO_LOGGING(z)           (z->zlog_btlog != NULL)
#else /* !ZONE_ENABLE_LOGGING */
#define DO_LOGGING(z)           0
#endif /* !ZONE_ENABLE_LOGGING */

#if CONFIG_ZLEAKS

/*
 * The zone leak detector, abbreviated 'zleak', keeps track of a subset of the currently outstanding
 * allocations made by the zone allocator.  Every zleak_sample_factor allocations in each zone, we capture a
 * backtrace.  Every free, we examine the table and determine if the allocation was being tracked,
 * and stop tracking it if it was being tracked.
 *
 * We track the allocations in the zallocations hash table, which stores the address that was returned from
 * the zone allocator.  Each stored entry in the zallocations table points to an entry in the ztraces table, which
 * stores the backtrace associated with that allocation.  This provides uniquing for the relatively large
 * backtraces - we don't store them more than once.
 *
 * Data collection begins when the zone map is 50% full, and only occurs for zones that are taking up
 * a large amount of virtual space.
 */
#define ZLEAK_STATE_ENABLED             0x01    /* Zone leak monitoring should be turned on if zone_map fills up. */
#define ZLEAK_STATE_ACTIVE              0x02    /* We are actively collecting traces. */
#define ZLEAK_STATE_ACTIVATING          0x04    /* Some thread is doing setup; others should move along. */
#define ZLEAK_STATE_FAILED              0x08    /* Attempt to allocate tables failed.  We will not try again. */
uint32_t        zleak_state = 0;                /* State of collection, as above */

boolean_t       panic_include_ztrace    = FALSE;        /* Enable zleak logging on panic */
vm_size_t       zleak_global_tracking_threshold;        /* Size of zone map at which to start collecting data */
vm_size_t       zleak_per_zone_tracking_threshold;      /* Size a zone will have before we will collect data on it */
unsigned int    zleak_sample_factor     = 1000;         /* Allocations per sample attempt */

/*
 * Counters for allocation statistics.
 */

/* Times two active records want to occupy the same spot */
unsigned int z_alloc_collisions = 0;
unsigned int z_trace_collisions = 0;

/* Times a new record lands on a spot previously occupied by a freed allocation */
unsigned int z_alloc_overwrites = 0;
unsigned int z_trace_overwrites = 0;

/* Times a new alloc or trace is put into the hash table */
unsigned int z_alloc_recorded   = 0;
unsigned int z_trace_recorded   = 0;

/* Times zleak_log returned false due to not being able to acquire the lock */
unsigned int z_total_conflicts  = 0;

/*
 * Structure for keeping track of an allocation
 * An allocation bucket is in use if its element is not NULL
 */
struct zallocation {
	uintptr_t               za_element;             /* the element that was zalloc'ed or zfree'ed, NULL if bucket unused */
	vm_size_t               za_size;                        /* how much memory did this allocation take up? */
	uint32_t                za_trace_index; /* index into ztraces for backtrace associated with allocation */
	/* TODO: #if this out */
	uint32_t                za_hit_count;           /* for determining effectiveness of hash function */
};

/* Size must be a power of two for the zhash to be able to just mask off bits instead of mod */
uint32_t zleak_alloc_buckets = CONFIG_ZLEAK_ALLOCATION_MAP_NUM;
uint32_t zleak_trace_buckets = CONFIG_ZLEAK_TRACE_MAP_NUM;

vm_size_t zleak_max_zonemap_size;

/* Hashmaps of allocations and their corresponding traces */
static struct zallocation*      zallocations;
static struct ztrace*           ztraces;

/* not static so that panic can see this, see kern/debug.c */
struct ztrace*                          top_ztrace;

/* Lock to protect zallocations, ztraces, and top_ztrace from concurrent modification. */
LCK_GRP_DECLARE(zleak_lock_grp, "zleak_lock");
LCK_SPIN_DECLARE(zleak_lock, &zleak_lock_grp);

/*
 * Initializes the zone leak monitor.  Called from zone_init()
 */
__startup_func
static void
zleak_init(vm_size_t max_zonemap_size)
{
	char                    scratch_buf[16];
	boolean_t               zleak_enable_flag = FALSE;

	zleak_max_zonemap_size = max_zonemap_size;
	zleak_global_tracking_threshold = max_zonemap_size / 2;
	zleak_per_zone_tracking_threshold = zleak_global_tracking_threshold / 8;

#if CONFIG_EMBEDDED
	if (PE_parse_boot_argn("-zleakon", scratch_buf, sizeof(scratch_buf))) {
		zleak_enable_flag = TRUE;
		printf("zone leak detection enabled\n");
	} else {
		zleak_enable_flag = FALSE;
		printf("zone leak detection disabled\n");
	}
#else /* CONFIG_EMBEDDED */
	/* -zleakoff (flag to disable zone leak monitor) */
	if (PE_parse_boot_argn("-zleakoff", scratch_buf, sizeof(scratch_buf))) {
		zleak_enable_flag = FALSE;
		printf("zone leak detection disabled\n");
	} else {
		zleak_enable_flag = TRUE;
		printf("zone leak detection enabled\n");
	}
#endif /* CONFIG_EMBEDDED */

	/* zfactor=XXXX (override how often to sample the zone allocator) */
	if (PE_parse_boot_argn("zfactor", &zleak_sample_factor, sizeof(zleak_sample_factor))) {
		printf("Zone leak factor override: %u\n", zleak_sample_factor);
	}

	/* zleak-allocs=XXXX (override number of buckets in zallocations) */
	if (PE_parse_boot_argn("zleak-allocs", &zleak_alloc_buckets, sizeof(zleak_alloc_buckets))) {
		printf("Zone leak alloc buckets override: %u\n", zleak_alloc_buckets);
		/* uses 'is power of 2' trick: (0x01000 & 0x00FFF == 0) */
		if (zleak_alloc_buckets == 0 || (zleak_alloc_buckets & (zleak_alloc_buckets - 1))) {
			printf("Override isn't a power of two, bad things might happen!\n");
		}
	}

	/* zleak-traces=XXXX (override number of buckets in ztraces) */
	if (PE_parse_boot_argn("zleak-traces", &zleak_trace_buckets, sizeof(zleak_trace_buckets))) {
		printf("Zone leak trace buckets override: %u\n", zleak_trace_buckets);
		/* uses 'is power of 2' trick: (0x01000 & 0x00FFF == 0) */
		if (zleak_trace_buckets == 0 || (zleak_trace_buckets & (zleak_trace_buckets - 1))) {
			printf("Override isn't a power of two, bad things might happen!\n");
		}
	}

	if (zleak_enable_flag) {
		zleak_state = ZLEAK_STATE_ENABLED;
	}
}

/*
 * Support for kern.zleak.active sysctl - a simplified
 * version of the zleak_state variable.
 */
int
get_zleak_state(void)
{
	if (zleak_state & ZLEAK_STATE_FAILED) {
		return -1;
	}
	if (zleak_state & ZLEAK_STATE_ACTIVE) {
		return 1;
	}
	return 0;
}

kern_return_t
zleak_activate(void)
{
	kern_return_t retval;
	vm_size_t z_alloc_size = zleak_alloc_buckets * sizeof(struct zallocation);
	vm_size_t z_trace_size = zleak_trace_buckets * sizeof(struct ztrace);
	void *allocations_ptr = NULL;
	void *traces_ptr = NULL;

	/* Only one thread attempts to activate at a time */
	if (zleak_state & (ZLEAK_STATE_ACTIVE | ZLEAK_STATE_ACTIVATING | ZLEAK_STATE_FAILED)) {
		return KERN_SUCCESS;
	}

	/* Indicate that we're doing the setup */
	lck_spin_lock(&zleak_lock);
	if (zleak_state & (ZLEAK_STATE_ACTIVE | ZLEAK_STATE_ACTIVATING | ZLEAK_STATE_FAILED)) {
		lck_spin_unlock(&zleak_lock);
		return KERN_SUCCESS;
	}

	zleak_state |= ZLEAK_STATE_ACTIVATING;
	lck_spin_unlock(&zleak_lock);

	/* Allocate and zero tables */
	retval = kmem_alloc_kobject(kernel_map, (vm_offset_t*)&allocations_ptr, z_alloc_size, VM_KERN_MEMORY_OSFMK);
	if (retval != KERN_SUCCESS) {
		goto fail;
	}

	retval = kmem_alloc_kobject(kernel_map, (vm_offset_t*)&traces_ptr, z_trace_size, VM_KERN_MEMORY_OSFMK);
	if (retval != KERN_SUCCESS) {
		goto fail;
	}

	bzero(allocations_ptr, z_alloc_size);
	bzero(traces_ptr, z_trace_size);

	/* Everything's set.  Install tables, mark active. */
	zallocations = allocations_ptr;
	ztraces = traces_ptr;

	/*
	 * Initialize the top_ztrace to the first entry in ztraces,
	 * so we don't have to check for null in zleak_log
	 */
	top_ztrace = &ztraces[0];

	/*
	 * Note that we do need a barrier between installing
	 * the tables and setting the active flag, because the zfree()
	 * path accesses the table without a lock if we're active.
	 */
	lck_spin_lock(&zleak_lock);
	zleak_state |= ZLEAK_STATE_ACTIVE;
	zleak_state &= ~ZLEAK_STATE_ACTIVATING;
	lck_spin_unlock(&zleak_lock);

	return 0;

fail:
	/*
	 * If we fail to allocate memory, don't further tax
	 * the system by trying again.
	 */
	lck_spin_lock(&zleak_lock);
	zleak_state |= ZLEAK_STATE_FAILED;
	zleak_state &= ~ZLEAK_STATE_ACTIVATING;
	lck_spin_unlock(&zleak_lock);

	if (allocations_ptr != NULL) {
		kmem_free(kernel_map, (vm_offset_t)allocations_ptr, z_alloc_size);
	}

	if (traces_ptr != NULL) {
		kmem_free(kernel_map, (vm_offset_t)traces_ptr, z_trace_size);
	}

	return retval;
}

/*
 * TODO: What about allocations that never get deallocated,
 * especially ones with unique backtraces? Should we wait to record
 * until after boot has completed?
 * (How many persistent zallocs are there?)
 */

/*
 * This function records the allocation in the allocations table,
 * and stores the associated backtrace in the traces table
 * (or just increments the refcount if the trace is already recorded)
 * If the allocation slot is in use, the old allocation is replaced with the new allocation, and
 * the associated trace's refcount is decremented.
 * If the trace slot is in use, it returns.
 * The refcount is incremented by the amount of memory the allocation consumes.
 * The return value indicates whether to try again next time.
 */
static boolean_t
zleak_log(uintptr_t* bt,
    uintptr_t addr,
    uint32_t depth,
    vm_size_t allocation_size)
{
	/* Quit if there's someone else modifying the hash tables */
	if (!lck_spin_try_lock(&zleak_lock)) {
		z_total_conflicts++;
		return FALSE;
	}

	struct zallocation* allocation  = &zallocations[hashaddr(addr, zleak_alloc_buckets)];

	uint32_t trace_index = hashbacktrace(bt, depth, zleak_trace_buckets);
	struct ztrace* trace = &ztraces[trace_index];

	allocation->za_hit_count++;
	trace->zt_hit_count++;

	/*
	 * If the allocation bucket we want to be in is occupied, and if the occupier
	 * has the same trace as us, just bail.
	 */
	if (allocation->za_element != (uintptr_t) 0 && trace_index == allocation->za_trace_index) {
		z_alloc_collisions++;

		lck_spin_unlock(&zleak_lock);
		return TRUE;
	}

	/* STEP 1: Store the backtrace in the traces array. */
	/* A size of zero indicates that the trace bucket is free. */

	if (trace->zt_size > 0 && bcmp(trace->zt_stack, bt, (depth * sizeof(uintptr_t))) != 0) {
		/*
		 * Different unique trace with same hash!
		 * Just bail - if we're trying to record the leaker, hopefully the other trace will be deallocated
		 * and get out of the way for later chances
		 */
		trace->zt_collisions++;
		z_trace_collisions++;

		lck_spin_unlock(&zleak_lock);
		return TRUE;
	} else if (trace->zt_size > 0) {
		/* Same trace, already added, so increment refcount */
		trace->zt_size += allocation_size;
	} else {
		/* Found an unused trace bucket, record the trace here! */
		if (trace->zt_depth != 0) { /* if this slot was previously used but not currently in use */
			z_trace_overwrites++;
		}

		z_trace_recorded++;
		trace->zt_size                  = allocation_size;
		memcpy(trace->zt_stack, bt, (depth * sizeof(uintptr_t)));

		trace->zt_depth         = depth;
		trace->zt_collisions    = 0;
	}

	/* STEP 2: Store the allocation record in the allocations array. */

	if (allocation->za_element != (uintptr_t) 0) {
		/*
		 * Straight up replace any allocation record that was there.  We don't want to do the work
		 * to preserve the allocation entries that were there, because we only record a subset of the
		 * allocations anyways.
		 */

		z_alloc_collisions++;

		struct ztrace* associated_trace = &ztraces[allocation->za_trace_index];
		/* Knock off old allocation's size, not the new allocation */
		associated_trace->zt_size -= allocation->za_size;
	} else if (allocation->za_trace_index != 0) {
		/* Slot previously used but not currently in use */
		z_alloc_overwrites++;
	}

	allocation->za_element          = addr;
	allocation->za_trace_index      = trace_index;
	allocation->za_size             = allocation_size;

	z_alloc_recorded++;

	if (top_ztrace->zt_size < trace->zt_size) {
		top_ztrace = trace;
	}

	lck_spin_unlock(&zleak_lock);
	return TRUE;
}

/*
 * Free the allocation record and release the stacktrace.
 * This should be as fast as possible because it will be called for every free.
 */
__attribute__((noinline))
static void
zleak_free(uintptr_t addr,
    vm_size_t allocation_size)
{
	if (addr == (uintptr_t) 0) {
		return;
	}

	struct zallocation* allocation = &zallocations[hashaddr(addr, zleak_alloc_buckets)];

	/* Double-checked locking: check to find out if we're interested, lock, check to make
	 * sure it hasn't changed, then modify it, and release the lock.
	 */

	if (allocation->za_element == addr && allocation->za_trace_index < zleak_trace_buckets) {
		/* if the allocation was the one, grab the lock, check again, then delete it */
		lck_spin_lock(&zleak_lock);

		if (allocation->za_element == addr && allocation->za_trace_index < zleak_trace_buckets) {
			struct ztrace *trace;

			/* allocation_size had better match what was passed into zleak_log - otherwise someone is freeing into the wrong zone! */
			if (allocation->za_size != allocation_size) {
				panic("Freeing as size %lu memory that was allocated with size %lu\n",
				    (uintptr_t)allocation_size, (uintptr_t)allocation->za_size);
			}

			trace = &ztraces[allocation->za_trace_index];

			/* size of 0 indicates trace bucket is unused */
			if (trace->zt_size > 0) {
				trace->zt_size -= allocation_size;
			}

			/* A NULL element means the allocation bucket is unused */
			allocation->za_element = 0;
		}
		lck_spin_unlock(&zleak_lock);
	}
}

#endif /* CONFIG_ZLEAKS */

/*  These functions outside of CONFIG_ZLEAKS because they are also used in
 *  mbuf.c for mbuf leak-detection.  This is why they lack the z_ prefix.
 */

/* "Thomas Wang's 32/64 bit mix functions."  http://www.concentric.net/~Ttwang/tech/inthash.htm */
uintptr_t
hash_mix(uintptr_t x)
{
#ifndef __LP64__
	x += ~(x << 15);
	x ^=  (x >> 10);
	x +=  (x << 3);
	x ^=  (x >> 6);
	x += ~(x << 11);
	x ^=  (x >> 16);
#else
	x += ~(x << 32);
	x ^=  (x >> 22);
	x += ~(x << 13);
	x ^=  (x >> 8);
	x +=  (x << 3);
	x ^=  (x >> 15);
	x += ~(x << 27);
	x ^=  (x >> 31);
#endif
	return x;
}

uint32_t
hashbacktrace(uintptr_t* bt, uint32_t depth, uint32_t max_size)
{
	uintptr_t hash = 0;
	uintptr_t mask = max_size - 1;

	while (depth) {
		hash += bt[--depth];
	}

	hash = hash_mix(hash) & mask;

	assert(hash < max_size);

	return (uint32_t) hash;
}

/*
 *  TODO: Determine how well distributed this is
 *      max_size must be a power of 2. i.e 0x10000 because 0x10000-1 is 0x0FFFF which is a great bitmask
 */
uint32_t
hashaddr(uintptr_t pt, uint32_t max_size)
{
	uintptr_t hash = 0;
	uintptr_t mask = max_size - 1;

	hash = hash_mix(pt) & mask;

	assert(hash < max_size);

	return (uint32_t) hash;
}

/* End of all leak-detection code */
#pragma mark zone creation, configuration, destruction

static zone_t
zone_init_defaults(zone_id_t zid)
{
	zone_t z = &zone_array[zid];

	z->page_count_max = ~0u;
	z->collectable = true;
	z->expandable = true;
	z->submap_idx = Z_SUBMAP_IDX_GENERAL_MAP;

	simple_lock_init(&z->lock, 0);

	return z;
}

static bool
zone_is_initializing(zone_t z)
{
	return !z->z_self && !z->destroyed;
}

static void
zone_set_max(zone_t z, vm_size_t max)
{
#if KASAN_ZALLOC
	if (z->kasan_redzone) {
		/*
		 * Adjust the max memory for the kasan redzones
		 */
		max += (max / z->pcpu_elem_size) * z->kasan_redzone * 2;
	}
#endif
	if (max < z->percpu ? 1 : z->alloc_pages) {
		max = z->percpu ? 1 : z->alloc_pages;
	} else {
		max = atop(round_page(max));
	}
	z->page_count_max = max;
}

void
zone_set_submap_idx(zone_t zone, unsigned int sub_map_idx)
{
	if (!zone_is_initializing(zone)) {
		panic("%s: called after zone_create()", __func__);
	}
	if (sub_map_idx > zone_last_submap_idx) {
		panic("zone_set_submap_idx(%d) > %d", sub_map_idx, zone_last_submap_idx);
	}
	zone->submap_idx = sub_map_idx;
}

void
zone_set_noexpand(
	zone_t          zone,
	vm_size_t       max)
{
	if (!zone_is_initializing(zone)) {
		panic("%s: called after zone_create()", __func__);
	}
	zone->expandable = false;
	zone_set_max(zone, max);
}

void
zone_set_exhaustible(
	zone_t          zone,
	vm_size_t       max)
{
	if (!zone_is_initializing(zone)) {
		panic("%s: called after zone_create()", __func__);
	}
	zone->expandable = false;
	zone->exhaustible = true;
	zone_set_max(zone, max);
}

/**
 * @function zone_create_find
 *
 * @abstract
 * Finds an unused zone for the given name and element size.
 *
 * @param name          the zone name
 * @param size          the element size (including redzones, ...)
 * @param flags         the flags passed to @c zone_create*
 * @param zid           the desired zone ID or ZONE_ID_ANY
 *
 * @returns             a zone to initialize further.
 */
static zone_t
zone_create_find(
	const char             *name,
	vm_size_t               size,
	zone_create_flags_t     flags,
	zone_id_t               zid)
{
	zone_id_t nzones;
	zone_t z;

	simple_lock(&all_zones_lock, &zone_locks_grp);

	nzones = (zone_id_t)os_atomic_load(&num_zones, relaxed);
	assert(num_zones_in_use <= nzones && nzones < MAX_ZONES);

	if (__improbable(nzones < ZONE_ID__FIRST_DYNAMIC)) {
		/*
		 * The first time around, make sure the reserved zone IDs
		 * have an initialized lock as zone_index_foreach() will
		 * enumerate them.
		 */
		while (nzones < ZONE_ID__FIRST_DYNAMIC) {
			zone_init_defaults(nzones++);
		}

		os_atomic_store(&num_zones, nzones, release);
	}

	if (zid != ZONE_ID_ANY) {
		if (zid >= ZONE_ID__FIRST_DYNAMIC) {
			panic("zone_create: invalid desired zone ID %d for %s",
			    zid, name);
		}
		if (flags & ZC_DESTRUCTIBLE) {
			panic("zone_create: ID %d (%s) must be permanent", zid, name);
		}
		if (zone_array[zid].z_self) {
			panic("zone_create: creating zone ID %d (%s) twice", zid, name);
		}
		z = &zone_array[zid];
	} else {
		if (flags & ZC_DESTRUCTIBLE) {
			/*
			 * If possible, find a previously zdestroy'ed zone in the
			 * zone_array that we can reuse.
			 */
			for (int i = bitmap_first(zone_destroyed_bitmap, MAX_ZONES);
			    i >= 0; i = bitmap_next(zone_destroyed_bitmap, i)) {
				z = &zone_array[i];

				/*
				 * If the zone name and the element size are the
				 * same, we can just reuse the old zone struct.
				 */
				if (strcmp(z->z_name, name) || zone_elem_size(z) != size) {
					continue;
				}
				bitmap_clear(zone_destroyed_bitmap, i);
				z->destroyed = false;
				z->z_self = z;
				zid = (zone_id_t)i;
				goto out;
			}
		}

		zid = nzones++;
		z = zone_init_defaults(zid);

		/*
		 * The release barrier pairs with the acquire in
		 * zone_index_foreach() and makes sure that enumeration loops
		 * always see an initialized zone lock.
		 */
		os_atomic_store(&num_zones, nzones, release);
	}

out:
	num_zones_in_use++;
	simple_unlock(&all_zones_lock);

	return z;
}

__abortlike
static void
zone_create_panic(const char *name, const char *f1, const char *f2)
{
	panic("zone_create: creating zone %s: flag %s and %s are incompatible",
	    name, f1, f2);
}
#define zone_create_assert_not_both(name, flags, current_flag, forbidden_flag) \
	if ((flags) & forbidden_flag) { \
	        zone_create_panic(name, #current_flag, #forbidden_flag); \
	}

/*
 * Adjusts the size of the element based on minimum size, alignment
 * and kasan redzones
 */
static vm_size_t
zone_elem_adjust_size(
	const char             *name __unused,
	vm_size_t               elem_size,
	zone_create_flags_t     flags,
	vm_size_t              *redzone __unused)
{
	vm_size_t size;
	/*
	 * Adjust element size for minimum size and pointer alignment
	 */
	size = (elem_size + sizeof(vm_offset_t) - 1) & -sizeof(vm_offset_t);
	if (((flags & ZC_PERCPU) == 0) && size < ZONE_MIN_ELEM_SIZE) {
		size = ZONE_MIN_ELEM_SIZE;
	}

#if KASAN_ZALLOC
	/*
	 * Expand the zone allocation size to include the redzones.
	 *
	 * For page-multiple zones add a full guard page because they
	 * likely require alignment.
	 */
	vm_size_t redzone_tmp;
	if (flags & (ZC_KASAN_NOREDZONE | ZC_PERCPU)) {
		redzone_tmp = 0;
	} else if ((size & PAGE_MASK) == 0) {
		if (size != PAGE_SIZE && (flags & ZC_ALIGNMENT_REQUIRED)) {
			panic("zone_create: zone %s can't provide more than PAGE_SIZE"
			    "alignment", name);
		}
		redzone_tmp = PAGE_SIZE;
	} else if (flags & ZC_ALIGNMENT_REQUIRED) {
		redzone_tmp = 0;
	} else {
		redzone_tmp = KASAN_GUARD_SIZE;
	}
	size += redzone_tmp * 2;
	if (redzone) {
		*redzone = redzone_tmp;
	}
#endif
	return size;
}

/*
 * Returns the allocation chunk size that has least framentation
 */
static vm_size_t
zone_get_min_alloc_granule(
	vm_size_t               elem_size,
	zone_create_flags_t     flags)
{
	vm_size_t alloc_granule = PAGE_SIZE;
	if (flags & ZC_PERCPU) {
		alloc_granule = PAGE_SIZE * zpercpu_count();
		if (PAGE_SIZE % elem_size > 256) {
			panic("zone_create: per-cpu zone has too much fragmentation");
		}
	} else if ((elem_size & PAGE_MASK) == 0) {
		/* zero fragmentation by definition */
		alloc_granule = elem_size;
	} else if (alloc_granule % elem_size == 0) {
		/* zero fragmentation by definition */
	} else {
		vm_size_t frag = (alloc_granule % elem_size) * 100 / alloc_granule;
		vm_size_t alloc_tmp = PAGE_SIZE;
		while ((alloc_tmp += PAGE_SIZE) <= ZONE_MAX_ALLOC_SIZE) {
			vm_size_t frag_tmp = (alloc_tmp % elem_size) * 100 / alloc_tmp;
			if (frag_tmp < frag) {
				frag = frag_tmp;
				alloc_granule = alloc_tmp;
			}
		}
	}
	return alloc_granule;
}

vm_size_t
zone_get_foreign_alloc_size(
	const char             *name __unused,
	vm_size_t               elem_size,
	zone_create_flags_t     flags,
	uint16_t                min_pages)
{
	vm_size_t adjusted_size = zone_elem_adjust_size(name, elem_size, flags,
	    NULL);
	vm_size_t alloc_granule = zone_get_min_alloc_granule(adjusted_size,
	    flags);
	vm_size_t min_size = min_pages * PAGE_SIZE;
	/*
	 * Round up min_size to a multiple of alloc_granule
	 */
	return ((min_size + alloc_granule - 1) / alloc_granule)
	       * alloc_granule;
}

zone_t
zone_create_ext(
	const char             *name,
	vm_size_t               size,
	zone_create_flags_t     flags,
	zone_id_t               desired_zid,
	void                  (^extra_setup)(zone_t))
{
	vm_size_t alloc;
	vm_size_t redzone;
	zone_t z;

	if (size > ZONE_MAX_ALLOC_SIZE) {
		panic("zone_create: element size too large: %zd", (size_t)size);
	}

	size = zone_elem_adjust_size(name, size, flags, &redzone);
	/*
	 * Allocate the zone slot, return early if we found an older match.
	 */
	z = zone_create_find(name, size, flags, desired_zid);
	if (__improbable(z->z_self)) {
		/* We found a zone to reuse */
		return z;
	}

	/*
	 * Initialize the zone properly.
	 */

	/*
	 * If the kernel is post lockdown, copy the zone name passed in.
	 * Else simply maintain a pointer to the name string as it can only
	 * be a core XNU zone (no unloadable kext exists before lockdown).
	 */
	if (startup_phase >= STARTUP_SUB_LOCKDOWN) {
		size_t nsz = MIN(strlen(name) + 1, MACH_ZONE_NAME_MAX_LEN);
		char *buf = zalloc_permanent(nsz, ZALIGN_NONE);
		strlcpy(buf, name, nsz);
		z->z_name = buf;
	} else {
		z->z_name = name;
	}
	/*
	 * If zone_init() hasn't run yet, the permanent zones do not exist.
	 * We can limp along without properly initialized stats for a while,
	 * zone_init() will rebuild the missing stats when it runs.
	 */
	if (__probable(zone_array[ZONE_ID_PERCPU_PERMANENT].z_self)) {
		z->z_stats = zalloc_percpu_permanent_type(struct zone_stats);
	}

	alloc = zone_get_min_alloc_granule(size, flags);

	if (flags & ZC_KALLOC_HEAP) {
		size_t rem = (alloc % size) / (alloc / size);

		/*
		 * Try to grow the elements size and spread them more if the remaining
		 * space is large enough.
		 */
		size += rem & ~(KALLOC_MINALIGN - 1);
	}

	z->pcpu_elem_size = z->z_elem_size = (uint16_t)size;
	z->alloc_pages = (uint16_t)atop(alloc);
#if KASAN_ZALLOC
	z->kasan_redzone = redzone;
	if (strncmp(name, "fakestack.", sizeof("fakestack.") - 1) == 0) {
		z->kasan_fakestacks = true;
	}
#endif

	/*
	 * Handle KPI flags
	 */
#if __LP64__
	if (flags & ZC_SEQUESTER) {
		z->va_sequester = true;
	}
#endif
	/* ZC_CACHING applied after all configuration is done */

	if (flags & ZC_PERCPU) {
		/*
		 * ZC_CACHING is disallowed because it uses per-cpu zones for its
		 * implementation and it would be circular. These allocations are
		 * also quite expensive, so caching feels dangerous memory wise too.
		 *
		 * ZC_ZFREE_CLEARMEM is forced because per-cpu zones allow for
		 * pointer-sized allocations which poisoning doesn't support.
		 */
		zone_create_assert_not_both(name, flags, ZC_PERCPU, ZC_CACHING);
		zone_create_assert_not_both(name, flags, ZC_PERCPU, ZC_ALLOW_FOREIGN);
		z->percpu = true;
		z->gzalloc_exempt = true;
		z->zfree_clear_mem = true;
		z->pcpu_elem_size *= zpercpu_count();
	}
	if (flags & ZC_ZFREE_CLEARMEM) {
		z->zfree_clear_mem = true;
	}
	if (flags & ZC_NOGC) {
		z->collectable = false;
	}
	if (flags & ZC_NOENCRYPT) {
		z->noencrypt = true;
	}
	if (flags & ZC_ALIGNMENT_REQUIRED) {
		z->alignment_required = true;
	}
	if (flags & ZC_NOGZALLOC) {
		z->gzalloc_exempt = true;
	}
	if (flags & ZC_NOCALLOUT) {
		z->no_callout = true;
	}
	if (flags & ZC_DESTRUCTIBLE) {
		zone_create_assert_not_both(name, flags, ZC_DESTRUCTIBLE, ZC_CACHING);
		zone_create_assert_not_both(name, flags, ZC_DESTRUCTIBLE, ZC_ALLOW_FOREIGN);
		z->destructible = true;
	}

	/*
	 * Handle Internal flags
	 */
	if (flags & ZC_ALLOW_FOREIGN) {
		z->allows_foreign = true;
	}
	if ((ZSECURITY_OPTIONS_SUBMAP_USER_DATA & zsecurity_options) &&
	    (flags & ZC_DATA_BUFFERS)) {
		z->submap_idx = Z_SUBMAP_IDX_BAG_OF_BYTES_MAP;
	}
	if (flags & ZC_KASAN_NOQUARANTINE) {
		z->kasan_noquarantine = true;
	}
	/* ZC_KASAN_NOREDZONE already handled */

	/*
	 * Then if there's extra tuning, do it
	 */
	if (extra_setup) {
		extra_setup(z);
	}

	/*
	 * Configure debugging features
	 */
#if CONFIG_GZALLOC
	gzalloc_zone_init(z); /* might set z->gzalloc_tracked */
#endif
#if ZONE_ENABLE_LOGGING
	if (!z->gzalloc_tracked && num_zones_logged < max_num_zones_to_log) {
		/*
		 * Check for and set up zone leak detection if requested via boot-args.
		 * might set z->zone_logging
		 */
		zone_setup_logging(z);
	}
#endif /* ZONE_ENABLE_LOGGING */
#if VM_MAX_TAG_ZONES
	if (!z->gzalloc_tracked && z->kalloc_heap && zone_tagging_on) {
		static int tag_zone_index;
		vm_offset_t esize = zone_elem_size(z);
		z->tags = true;
		z->tags_inline = (((page_size + esize - 1) / esize) <=
		    (sizeof(uint32_t) / sizeof(uint16_t)));
		z->tag_zone_index = os_atomic_inc_orig(&tag_zone_index, relaxed);
		assert(z->tag_zone_index < VM_MAX_TAG_ZONES);
	}
#endif

	/*
	 * Finally, fixup properties based on security policies, boot-args, ...
	 */
	if ((ZSECURITY_OPTIONS_SUBMAP_USER_DATA & zsecurity_options) &&
	    z->kalloc_heap == KHEAP_ID_DATA_BUFFERS) {
		z->submap_idx = Z_SUBMAP_IDX_BAG_OF_BYTES_MAP;
	}
#if __LP64__
	if ((ZSECURITY_OPTIONS_SEQUESTER & zsecurity_options) &&
	    (flags & ZC_NOSEQUESTER) == 0 &&
	    z->submap_idx == Z_SUBMAP_IDX_GENERAL_MAP) {
		z->va_sequester = true;
	}
#endif
	/*
	 * Always clear zone elements smaller than a cacheline,
	 * because it's pretty close to free.
	 */
	if (size <= zp_min_size) {
		z->zfree_clear_mem = true;
	}
	if (zp_factor != 0 && !z->zfree_clear_mem) {
		z->zp_count = zone_poison_count_init(z);
	}

#if CONFIG_ZCACHE
	if ((flags & ZC_NOCACHING) == 0) {
		/*
		 * Append kalloc heap name to zone name (if zone is used by kalloc)
		 */
		char temp_zone_name[MAX_ZONE_NAME] = "";
		snprintf(temp_zone_name, MAX_ZONE_NAME, "%s%s", zone_heap_name(z), z->z_name);

		/* Check if boot-arg specified it should have a cache */
		if (track_this_zone(temp_zone_name, cache_zone_name)) {
			flags |= ZC_CACHING;
		} else if (zcc_kalloc && z->kalloc_heap) {
			flags |= ZC_CACHING;
		}
	}
	if ((flags & ZC_CACHING) &&
	    !z->tags && !z->zone_logging && !z->gzalloc_tracked) {
		zcache_init(z);
	}
#endif /* CONFIG_ZCACHE */

	lock_zone(z);
	z->z_self = z;
	unlock_zone(z);

	return z;
}

__startup_func
void
zone_create_startup(struct zone_create_startup_spec *spec)
{
	*spec->z_var = zone_create_ext(spec->z_name, spec->z_size,
	    spec->z_flags, spec->z_zid, spec->z_setup);
}

/*
 * The 4 first field of a zone_view and a zone alias, so that the zone_or_view_t
 * union works. trust but verify.
 */
#define zalloc_check_zov_alias(f1, f2) \
    static_assert(offsetof(struct zone, f1) == offsetof(struct zone_view, f2))
zalloc_check_zov_alias(z_self, zv_zone);
zalloc_check_zov_alias(z_stats, zv_stats);
zalloc_check_zov_alias(z_name, zv_name);
zalloc_check_zov_alias(z_views, zv_next);
#undef zalloc_check_zov_alias

__startup_func
void
zone_view_startup_init(struct zone_view_startup_spec *spec)
{
	struct kalloc_heap *heap = NULL;
	zone_view_t zv = spec->zv_view;
	zone_t z;

	switch (spec->zv_heapid) {
	case KHEAP_ID_DEFAULT:
		heap = KHEAP_DEFAULT;
		break;
	case KHEAP_ID_DATA_BUFFERS:
		heap = KHEAP_DATA_BUFFERS;
		break;
	case KHEAP_ID_KEXT:
		heap = KHEAP_KEXT;
		break;
	default:
		heap = NULL;
	}

	if (heap) {
		z = kalloc_heap_zone_for_size(heap, spec->zv_size);
		assert(z);
	} else {
		z = spec->zv_zone;
		assert(spec->zv_size <= zone_elem_size(z));
	}

	zv->zv_zone  = z;
	zv->zv_stats = zalloc_percpu_permanent_type(struct zone_stats);
	zv->zv_next  = z->z_views;
	if (z->z_views == NULL && z->kalloc_heap == KHEAP_ID_NONE) {
		/*
		 * count the raw view for zones not in a heap,
		 * kalloc_heap_init() already counts it for its members.
		 */
		zone_view_count += 2;
	} else {
		zone_view_count += 1;
	}
	z->z_views = zv;
}

zone_t
zone_create(
	const char             *name,
	vm_size_t               size,
	zone_create_flags_t     flags)
{
	return zone_create_ext(name, size, flags, ZONE_ID_ANY, NULL);
}

zone_t
zinit(
	vm_size_t       size,           /* the size of an element */
	vm_size_t       max,            /* maximum memory to use */
	vm_size_t       alloc __unused, /* allocation size */
	const char      *name)          /* a name for the zone */
{
	zone_t z = zone_create(name, size, ZC_DESTRUCTIBLE);
	zone_set_max(z, max);
	return z;
}

void
zdestroy(zone_t z)
{
	unsigned int zindex = zone_index(z);

	lock_zone(z);

	if (!z->destructible || zone_caching_enabled(z) || z->allows_foreign) {
		panic("zdestroy: Zone %s%s isn't destructible",
		    zone_heap_name(z), z->z_name);
	}

	if (!z->z_self || z->expanding_no_vm_priv || z->expanding_vm_priv ||
	    z->async_pending || z->waiting) {
		panic("zdestroy: Zone %s%s in an invalid state for destruction",
		    zone_heap_name(z), z->z_name);
	}

#if !KASAN_ZALLOC
	/*
	 * Unset the valid bit. We'll hit an assert failure on further operations
	 * on this zone, until zinit() is called again.
	 *
	 * Leave the zone valid for KASan as we will see zfree's on quarantined free
	 * elements even after the zone is destroyed.
	 */
	z->z_self = NULL;
#endif
	z->destroyed = true;
	unlock_zone(z);

	/* Dump all the free elements */
	zone_drop_free_elements(z);

#if CONFIG_GZALLOC
	if (__improbable(z->gzalloc_tracked)) {
		/* If the zone is gzalloc managed dump all the elements in the free cache */
		gzalloc_empty_free_cache(z);
	}
#endif

	lock_zone(z);

	while (!zone_pva_is_null(z->pages_sequester)) {
		struct zone_page_metadata *page_meta;
		vm_offset_t                free_addr;

		page_meta = zone_sequestered_page_get(z, &free_addr);
		unlock_zone(z);
		kmem_free(submap_for_zone(z), free_addr, ptoa(z->alloc_pages));
		lock_zone(z);
	}

#if !KASAN_ZALLOC
	/* Assert that all counts are zero */
	if (z->countavail || z->countfree || zone_size_wired(z) ||
	    z->allfree_page_count || z->sequester_page_count) {
		panic("zdestroy: Zone %s%s isn't empty at zdestroy() time",
		    zone_heap_name(z), z->z_name);
	}

	/* consistency check: make sure everything is indeed empty */
	assert(zone_pva_is_null(z->pages_any_free_foreign));
	assert(zone_pva_is_null(z->pages_all_used_foreign));
	assert(zone_pva_is_null(z->pages_all_free));
	assert(zone_pva_is_null(z->pages_intermediate));
	assert(zone_pva_is_null(z->pages_all_used));
	assert(zone_pva_is_null(z->pages_sequester));
#endif

	unlock_zone(z);

	simple_lock(&all_zones_lock, &zone_locks_grp);

	assert(!bitmap_test(zone_destroyed_bitmap, zindex));
	/* Mark the zone as empty in the bitmap */
	bitmap_set(zone_destroyed_bitmap, zindex);
	num_zones_in_use--;
	assert(num_zones_in_use > 0);

	simple_unlock(&all_zones_lock);
}

#pragma mark zone (re)fill, jetsam

/*
 * Dealing with zone allocations from the mach VM code.
 *
 * The implementation of the mach VM itself uses the zone allocator
 * for things like the vm_map_entry data structure. In order to prevent
 * an infinite recursion problem when adding more pages to a zone, zalloc
 * uses a replenish thread to refill the VM layer's zones before they have
 * too few remaining free entries. The reserved remaining free entries
 * guarantee that the VM routines can get entries from already mapped pages.
 *
 * In order for that to work, the amount of allocations in the nested
 * case have to be bounded. There are currently 2 replenish zones, and
 * if each needs 1 element of each zone to add a new page to itself, that
 * gives us a minumum reserve of 2 elements.
 *
 * There is also a deadlock issue with the zone garbage collection thread,
 * or any thread that is trying to free zone pages. While holding
 * the kernel's map lock they may need to allocate new VM map entries, hence
 * we need enough reserve to allow them to get past the point of holding the
 * map lock. After freeing that page, the GC thread will wait in drop_free_elements()
 * until the replenish threads can finish. Since there's only 1 GC thread at a time,
 * that adds a minimum of 1 to the reserve size.
 *
 * Since the minumum amount you can add to a zone is 1 page, we'll use 16K (from ARM)
 * as the refill size on all platforms.
 *
 * When a refill zone drops to half that available, i.e. REFILL_SIZE / 2,
 * zalloc_ext() will wake the replenish thread. The replenish thread runs
 * until at least REFILL_SIZE worth of free elements exist, before sleeping again.
 * In the meantime threads may continue to use the reserve until there are only REFILL_SIZE / 4
 * elements left. Below that point only the replenish threads themselves and the GC
 * thread may continue to use from the reserve.
 */
static unsigned zone_replenish_loops;
static unsigned zone_replenish_wakeups;
static unsigned zone_replenish_wakeups_initiated;
static unsigned zone_replenish_throttle_count;

#define ZONE_REPLENISH_TARGET (16 * 1024)
static unsigned zone_replenish_active = 0; /* count of zones currently replenishing */
static unsigned zone_replenish_max_threads = 0;

LCK_GRP_DECLARE(zone_replenish_lock_grp, "zone_replenish_lock");
LCK_SPIN_DECLARE(zone_replenish_lock, &zone_replenish_lock_grp);

__abortlike
static void
zone_replenish_panic(zone_t zone, kern_return_t kr)
{
	panic_include_zprint = TRUE;
#if CONFIG_ZLEAKS
	if ((zleak_state & ZLEAK_STATE_ACTIVE)) {
		panic_include_ztrace = TRUE;
	}
#endif /* CONFIG_ZLEAKS */
	if (kr == KERN_NO_SPACE) {
		zone_t zone_largest = zone_find_largest();
		panic("zalloc: zone map exhausted while allocating from zone %s%s, "
		    "likely due to memory leak in zone %s%s "
		    "(%lu total bytes, %d elements allocated)",
		    zone_heap_name(zone), zone->z_name,
		    zone_heap_name(zone_largest), zone_largest->z_name,
		    (unsigned long)zone_size_wired(zone_largest),
		    zone_count_allocated(zone_largest));
	}
	panic("zalloc: %s%s (%d elements) retry fail %d",
	    zone_heap_name(zone), zone->z_name,
	    zone_count_allocated(zone), kr);
}

static void
zone_replenish_locked(zone_t z, zalloc_flags_t flags, bool asynchronously)
{
	int kmaflags = KMA_KOBJECT | KMA_ZERO;
	vm_offset_t space, alloc_size;
	uint32_t retry = 0;
	kern_return_t kr;

	if (z->noencrypt) {
		kmaflags |= KMA_NOENCRYPT;
	}
	if (flags & Z_NOPAGEWAIT) {
		kmaflags |= KMA_NOPAGEWAIT;
	}
	if (z->permanent) {
		kmaflags |= KMA_PERMANENT;
	}

	for (;;) {
		struct zone_page_metadata *page_meta = NULL;

		/*
		 * Try to allocate our regular chunk of pages,
		 * unless the system is under massive pressure
		 * and we're looking for more than 2 pages.
		 */
		if (!z->percpu && z->alloc_pages > 2 && (vm_pool_low() || retry > 0)) {
			alloc_size = round_page(zone_elem_size(z));
		} else {
			alloc_size = ptoa(z->alloc_pages);
			page_meta = zone_sequestered_page_get(z, &space);
		}

		unlock_zone(z);

#if CONFIG_ZLEAKS
		/*
		 * Do the zone leak activation here because zleak_activate()
		 * may block, and can't be done on the way out.
		 */
		if (__improbable(zleak_state & ZLEAK_STATE_ENABLED)) {
			if (!(zleak_state & ZLEAK_STATE_ACTIVE) &&
			    zone_submaps_approx_size() >= zleak_global_tracking_threshold) {
				kr = zleak_activate();
				if (kr != KERN_SUCCESS) {
					printf("Failed to activate live zone leak debugging (%d).\n", kr);
				}
			}
		}
#endif /* CONFIG_ZLEAKS */

		/*
		 * Trigger jetsams via the vm_pageout_garbage_collect thread if
		 * we're running out of zone memory
		 */
		if (is_zone_map_nearing_exhaustion()) {
			thread_wakeup((event_t) &vm_pageout_garbage_collect);
		}

		if (page_meta) {
			kr = zone_sequestered_page_populate(z, page_meta, space,
			    alloc_size, kmaflags);
		} else {
			if (z->submap_idx == Z_SUBMAP_IDX_GENERAL_MAP && z->kalloc_heap != KHEAP_ID_NONE) {
				kmaflags |= KMA_KHEAP;
			}
			kr = kernel_memory_allocate(submap_for_zone(z),
			    &space, alloc_size, 0, kmaflags, VM_KERN_MEMORY_ZONE);
		}

#if !__LP64__
		if (kr == KERN_NO_SPACE && z->allows_foreign) {
			/*
			 * For zones allowing foreign pages, fallback to the kernel map
			 */
			kr = kernel_memory_allocate(kernel_map, &space,
			    alloc_size, 0, kmaflags, VM_KERN_MEMORY_ZONE);
		}
#endif

		if (kr == KERN_SUCCESS) {
			break;
		}

		if (flags & Z_NOPAGEWAIT) {
			lock_zone(z);
			return;
		}

		if (asynchronously) {
			assert_wait_timeout(&z->prio_refill_count,
			    THREAD_UNINT, 1, 100 * NSEC_PER_USEC);
			thread_block(THREAD_CONTINUE_NULL);
		} else if (++retry == 3) {
			zone_replenish_panic(z, kr);
		}

		lock_zone(z);
	}

	zcram_and_lock(z, space, alloc_size);

#if CONFIG_ZLEAKS
	if (__improbable(zleak_state & ZLEAK_STATE_ACTIVE)) {
		if (!z->zleak_on &&
		    zone_size_wired(z) >= zleak_per_zone_tracking_threshold) {
			z->zleak_on = true;
		}
	}
#endif /* CONFIG_ZLEAKS */
}

/*
 * High priority VM privileged thread used to asynchronously refill a given zone.
 * These are needed for data structures used by the lower level VM itself. The
 * replenish thread maintains a reserve of elements, so that the VM will never
 * block in the zone allocator.
 */
__dead2
static void
zone_replenish_thread(void *_z, wait_result_t __unused wr)
{
	zone_t z = _z;

	current_thread()->options |= (TH_OPT_VMPRIV | TH_OPT_ZONE_PRIV);

	for (;;) {
		lock_zone(z);
		assert(z->z_self == z);
		assert(z->zone_replenishing);
		assert(z->prio_refill_count != 0);

		while (z->countfree < z->prio_refill_count) {
			assert(!z->expanding_no_vm_priv);
			assert(!z->expanding_vm_priv);

			zone_replenish_locked(z, Z_WAITOK, true);

			assert(z->z_self == z);
			zone_replenish_loops++;
		}

		/* Wakeup any potentially throttled allocations. */
		thread_wakeup(z);

		assert_wait(&z->prio_refill_count, THREAD_UNINT);

		/*
		 * We finished refilling the zone, so decrement the active count
		 * and wake up any waiting GC threads.
		 */
		lck_spin_lock(&zone_replenish_lock);
		assert(zone_replenish_active > 0);
		if (--zone_replenish_active == 0) {
			thread_wakeup((event_t)&zone_replenish_active);
		}
		lck_spin_unlock(&zone_replenish_lock);

		z->zone_replenishing = false;
		unlock_zone(z);

		thread_block(THREAD_CONTINUE_NULL);
		zone_replenish_wakeups++;
	}
}

void
zone_prio_refill_configure(zone_t z)
{
	thread_t th;
	kern_return_t tres;

	lock_zone(z);
	assert(!z->prio_refill_count && !z->destructible);
	z->prio_refill_count = (uint16_t)(ZONE_REPLENISH_TARGET / zone_elem_size(z));
	z->zone_replenishing = true;
	unlock_zone(z);

	lck_spin_lock(&zone_replenish_lock);
	++zone_replenish_max_threads;
	++zone_replenish_active;
	lck_spin_unlock(&zone_replenish_lock);
	OSMemoryBarrier();

	tres = kernel_thread_start_priority(zone_replenish_thread, z,
	    MAXPRI_KERNEL, &th);
	if (tres != KERN_SUCCESS) {
		panic("zone_prio_refill_configure, thread create: 0x%x", tres);
	}

	thread_deallocate(th);
}

static void
zone_randomize_freelist(zone_t zone, struct zone_page_metadata *meta,
    vm_offset_t size, zone_addr_kind_t kind, unsigned int *entropy_buffer)
{
	const vm_size_t elem_size = zone_elem_size(zone);
	vm_offset_t     left, right, head, base;
	vm_offset_t     element;

	left  = ZONE_PAGE_FIRST_OFFSET(kind);
	right = size - ((size - left) % elem_size);
	head  = 0;
	base  = zone_meta_to_addr(meta, kind);

	while (left < right) {
		if (zone_leaks_scan_enable || __improbable(zone->tags) ||
		    random_bool_gen_bits(&zone_bool_gen, entropy_buffer, MAX_ENTROPY_PER_ZCRAM, 1)) {
			element = base + left;
			left += elem_size;
		} else {
			right -= elem_size;
			element = base + right;
		}

		vm_offset_t *primary  = (vm_offset_t *)element;
		vm_offset_t *backup   = get_backup_ptr(elem_size, primary);

		*primary = *backup = head ^ zp_nopoison_cookie;
		head = element;
	}

	meta->zm_freelist_offs = (uint16_t)(head - base);
}

/*
 *	Cram the given memory into the specified zone. Update the zone page count accordingly.
 */
static void
zcram_and_lock(zone_t zone, vm_offset_t newmem, vm_size_t size)
{
	unsigned int entropy_buffer[MAX_ENTROPY_PER_ZCRAM] = { 0 };
	struct zone_page_metadata *meta;
	zone_addr_kind_t kind;
	uint32_t pg_count = (uint32_t)atop(size);
	uint32_t zindex = zone_index(zone);
	uint32_t free_count;
	uint16_t empty_freelist_offs = PAGE_METADATA_EMPTY_FREELIST;

	/* Basic sanity checks */
	assert(zone != ZONE_NULL && newmem != (vm_offset_t)0);
	assert((newmem & PAGE_MASK) == 0);
	assert((size & PAGE_MASK) == 0);

	KDBG(MACHDBG_CODE(DBG_MACH_ZALLOC, ZALLOC_ZCRAM) | DBG_FUNC_START,
	    zindex, size);

	kind = zone_addr_kind(newmem, size);
#if DEBUG || DEVELOPMENT
	if (zalloc_debug & ZALLOC_DEBUG_ZCRAM) {
		kprintf("zcram(%p[%s%s], 0x%lx%s, 0x%lx)\n", zone,
		    zone_heap_name(zone), zone->z_name, (uintptr_t)newmem,
		    kind == ZONE_ADDR_FOREIGN ? "[F]" : "", (uintptr_t)size);
	}
#endif /* DEBUG || DEVELOPMENT */

	/*
	 * Initialize the metadata for all pages. We dont need the zone lock
	 * here because we are not manipulating any zone related state yet.
	 *
	 * This includes randomizing the freelists as the metadata isn't
	 * published yet.
	 */

	if (kind == ZONE_ADDR_NATIVE) {
		/*
		 * We're being called by zfill,
		 * zone_replenish_thread or vm_page_more_fictitious,
		 *
		 * which will only either allocate a single page, or `alloc_pages`
		 * worth.
		 */
		assert(pg_count <= zone->alloc_pages);

		/*
		 * Make sure the range of metadata entries we're about to init
		 * have proper physical backing, then initialize them.
		 */
		meta = zone_meta_from_addr(newmem, kind);
		zone_meta_populate(meta, meta + pg_count);

		if (zone->permanent) {
			empty_freelist_offs = 0;
		}

		meta[0] = (struct zone_page_metadata){
			.zm_index         = zindex,
			.zm_page_count    = pg_count,
			.zm_percpu        = zone->percpu,
			.zm_freelist_offs = empty_freelist_offs,
		};

		for (uint32_t i = 1; i < pg_count; i++) {
			meta[i] = (struct zone_page_metadata){
				.zm_index          = zindex,
				.zm_page_count     = i,
				.zm_percpu         = zone->percpu,
				.zm_secondary_page = true,
				.zm_freelist_offs  = empty_freelist_offs,
			};
		}

		if (!zone->permanent) {
			zone_randomize_freelist(zone, meta,
			    zone->percpu ? PAGE_SIZE : size, kind, entropy_buffer);
		}
	} else {
		if (!zone->allows_foreign || !from_foreign_range(newmem, size)) {
			panic("zcram_and_lock: foreign memory [%lx] being crammed is "
			    "outside of foreign range", (uintptr_t)newmem);
		}

		/*
		 * We cannot support elements larger than page size for foreign
		 * memory because we put metadata on the page itself for each
		 * page of foreign memory.
		 *
		 * We need to do this in order to be able to reach the metadata
		 * when any element is freed.
		 */
		assert(!zone->percpu && !zone->permanent);
		assert(zone_elem_size(zone) <= PAGE_SIZE - sizeof(struct zone_page_metadata));

		bzero((void *)newmem, size);

		for (vm_offset_t offs = 0; offs < size; offs += PAGE_SIZE) {
			meta = (struct zone_page_metadata *)(newmem + offs);
			*meta = (struct zone_page_metadata){
				.zm_index         = zindex,
				.zm_page_count    = 1,
				.zm_freelist_offs = empty_freelist_offs,
			};
			meta->zm_foreign_cookie[0] = ZONE_FOREIGN_COOKIE;
			zone_randomize_freelist(zone, meta, PAGE_SIZE, kind,
			    entropy_buffer);
		}
	}

#if VM_MAX_TAG_ZONES
	if (__improbable(zone->tags)) {
		assert(kind == ZONE_ADDR_NATIVE && !zone->percpu);
		ztMemoryAdd(zone, newmem, size);
	}
#endif /* VM_MAX_TAG_ZONES */

	/*
	 * Insert the initialized pages / metadatas into the right lists.
	 */

	lock_zone(zone);
	assert(zone->z_self == zone);

	zone->page_count += pg_count;
	if (zone->page_count_hwm < zone->page_count) {
		zone->page_count_hwm = zone->page_count;
	}
	os_atomic_add(&zones_phys_page_count, pg_count, relaxed);

	if (kind == ZONE_ADDR_NATIVE) {
		os_atomic_add(&zones_phys_page_mapped_count, pg_count, relaxed);
		if (zone->permanent) {
			zone_meta_queue_push(zone, &zone->pages_intermediate, meta, kind);
		} else {
			zone_meta_queue_push(zone, &zone->pages_all_free, meta, kind);
			zone->allfree_page_count += meta->zm_page_count;
		}
		free_count = zone_elem_count(zone, size, kind);
		zone->countfree  += free_count;
		zone->countavail += free_count;
	} else {
		free_count = zone_elem_count(zone, PAGE_SIZE, kind);
		for (vm_offset_t offs = 0; offs < size; offs += PAGE_SIZE) {
			meta = (struct zone_page_metadata *)(newmem + offs);
			zone_meta_queue_push(zone, &zone->pages_any_free_foreign, meta, kind);
			zone->countfree  += free_count;
			zone->countavail += free_count;
		}
	}

	KDBG(MACHDBG_CODE(DBG_MACH_ZALLOC, ZALLOC_ZCRAM) | DBG_FUNC_END, zindex);
}

void
zcram(zone_t zone, vm_offset_t newmem, vm_size_t size)
{
	zcram_and_lock(zone, newmem, size);
	unlock_zone(zone);
}

/*
 * Fill a zone with enough memory to contain at least nelem elements.
 * Return the number of elements actually put into the zone, which may
 * be more than the caller asked for since the memory allocation is
 * rounded up to the next zone allocation size.
 */
int
zfill(
	zone_t  zone,
	int     nelem)
{
	kern_return_t kr;
	vm_offset_t   memory;

	vm_size_t alloc_size = ptoa(zone->alloc_pages);
	vm_size_t nalloc_inc = zone_elem_count(zone, alloc_size, ZONE_ADDR_NATIVE);
	vm_size_t nalloc = 0, goal = MAX(0, nelem);
	int kmaflags = KMA_KOBJECT | KMA_ZERO;

	if (zone->noencrypt) {
		kmaflags |= KMA_NOENCRYPT;
	}

	assert(!zone->allows_foreign && !zone->permanent);

	/*
	 * Trigger jetsams via the vm_pageout_garbage_collect thread if we're
	 * running out of zone memory
	 */
	if (is_zone_map_nearing_exhaustion()) {
		thread_wakeup((event_t) &vm_pageout_garbage_collect);
	}

	if (zone->va_sequester) {
		lock_zone(zone);

		do {
			struct zone_page_metadata *page_meta;
			page_meta = zone_sequestered_page_get(zone, &memory);
			if (NULL == page_meta) {
				break;
			}
			unlock_zone(zone);

			kr = zone_sequestered_page_populate(zone, page_meta,
			    memory, alloc_size, kmaflags);
			if (KERN_SUCCESS != kr) {
				goto out_nolock;
			}

			zcram_and_lock(zone, memory, alloc_size);
			nalloc += nalloc_inc;
		} while (nalloc < goal);

		unlock_zone(zone);
	}

out_nolock:
	while (nalloc < goal) {
		kr = kernel_memory_allocate(submap_for_zone(zone), &memory,
		    alloc_size, 0, kmaflags, VM_KERN_MEMORY_ZONE);
		if (kr != KERN_SUCCESS) {
			printf("%s: kernel_memory_allocate() of %lu bytes failed\n",
			    __func__, (unsigned long)(nalloc * alloc_size));
			break;
		}

		zcram(zone, memory, alloc_size);
		nalloc += nalloc_inc;
	}

	return (int)nalloc;
}

/*
 * We're being very conservative here and picking a value of 95%. We might need to lower this if
 * we find that we're not catching the problem and are still hitting zone map exhaustion panics.
 */
#define ZONE_MAP_JETSAM_LIMIT_DEFAULT 95

/*
 * Trigger zone-map-exhaustion jetsams if the zone map is X% full, where X=zone_map_jetsam_limit.
 * Can be set via boot-arg "zone_map_jetsam_limit". Set to 95% by default.
 */
TUNABLE_WRITEABLE(unsigned int, zone_map_jetsam_limit, "zone_map_jetsam_limit",
    ZONE_MAP_JETSAM_LIMIT_DEFAULT);

void
get_zone_map_size(uint64_t *current_size, uint64_t *capacity)
{
	vm_offset_t phys_pages = os_atomic_load(&zones_phys_page_mapped_count, relaxed);
	*current_size = ptoa_64(phys_pages);
	*capacity = zone_phys_mapped_max;
}

void
get_largest_zone_info(char *zone_name, size_t zone_name_len, uint64_t *zone_size)
{
	zone_t largest_zone = zone_find_largest();

	/*
	 * Append kalloc heap name to zone name (if zone is used by kalloc)
	 */
	snprintf(zone_name, zone_name_len, "%s%s",
	    zone_heap_name(largest_zone), largest_zone->z_name);

	*zone_size = zone_size_wired(largest_zone);
}

boolean_t
is_zone_map_nearing_exhaustion(void)
{
	vm_offset_t phys_pages = os_atomic_load(&zones_phys_page_mapped_count, relaxed);
	return ptoa_64(phys_pages) > (zone_phys_mapped_max * zone_map_jetsam_limit) / 100;
}


#define VMENTRY_TO_VMOBJECT_COMPARISON_RATIO 98

/*
 * Tries to kill a single process if it can attribute one to the largest zone. If not, wakes up the memorystatus thread
 * to walk through the jetsam priority bands and kill processes.
 */
static void
kill_process_in_largest_zone(void)
{
	pid_t pid = -1;
	zone_t largest_zone = zone_find_largest();

	printf("zone_map_exhaustion: Zone mapped %lld of %lld, used %lld, map size %lld, capacity %lld [jetsam limit %d%%]\n",
	    ptoa_64(os_atomic_load(&zones_phys_page_mapped_count, relaxed)), ptoa_64(zone_phys_mapped_max),
	    ptoa_64(os_atomic_load(&zones_phys_page_count, relaxed)),
	    (uint64_t)zone_submaps_approx_size(),
	    (uint64_t)zone_range_size(&zone_info.zi_map_range),
	    zone_map_jetsam_limit);
	printf("zone_map_exhaustion: Largest zone %s%s, size %lu\n", zone_heap_name(largest_zone),
	    largest_zone->z_name, (uintptr_t)zone_size_wired(largest_zone));

	/*
	 * We want to make sure we don't call this function from userspace.
	 * Or we could end up trying to synchronously kill the process
	 * whose context we're in, causing the system to hang.
	 */
	assert(current_task() == kernel_task);

	/*
	 * If vm_object_zone is the largest, check to see if the number of
	 * elements in vm_map_entry_zone is comparable.
	 *
	 * If so, consider vm_map_entry_zone as the largest. This lets us target
	 * a specific process to jetsam to quickly recover from the zone map
	 * bloat.
	 */
	if (largest_zone == vm_object_zone) {
		unsigned int vm_object_zone_count = zone_count_allocated(vm_object_zone);
		unsigned int vm_map_entry_zone_count = zone_count_allocated(vm_map_entry_zone);
		/* Is the VM map entries zone count >= 98% of the VM objects zone count? */
		if (vm_map_entry_zone_count >= ((vm_object_zone_count * VMENTRY_TO_VMOBJECT_COMPARISON_RATIO) / 100)) {
			largest_zone = vm_map_entry_zone;
			printf("zone_map_exhaustion: Picking VM map entries as the zone to target, size %lu\n",
			    (uintptr_t)zone_size_wired(largest_zone));
		}
	}

	/* TODO: Extend this to check for the largest process in other zones as well. */
	if (largest_zone == vm_map_entry_zone) {
		pid = find_largest_process_vm_map_entries();
	} else {
		printf("zone_map_exhaustion: Nothing to do for the largest zone [%s%s]. "
		    "Waking up memorystatus thread.\n", zone_heap_name(largest_zone),
		    largest_zone->z_name);
	}
	if (!memorystatus_kill_on_zone_map_exhaustion(pid)) {
		printf("zone_map_exhaustion: Call to memorystatus failed, victim pid: %d\n", pid);
	}
}

#pragma mark zalloc module init

/*
 *	Initialize the "zone of zones" which uses fixed memory allocated
 *	earlier in memory initialization.  zone_bootstrap is called
 *	before zone_init.
 */
__startup_func
void
zone_bootstrap(void)
{
	/* Validate struct zone_page_metadata expectations */
	if ((1U << ZONE_PAGECOUNT_BITS) <
	    atop(ZONE_MAX_ALLOC_SIZE) * sizeof(struct zone_page_metadata)) {
		panic("ZONE_PAGECOUNT_BITS is not large enough to hold page counts");
	}

	/* Validate struct zone_packed_virtual_address expectations */
	static_assert((intptr_t)VM_MIN_KERNEL_ADDRESS < 0, "the top bit must be 1");
	if (VM_KERNEL_POINTER_SIGNIFICANT_BITS - PAGE_SHIFT > 31) {
		panic("zone_pva_t can't pack a kernel page address in 31 bits");
	}

	zpercpu_early_count = ml_early_cpu_max_number() + 1;

	/* Set up zone element poisoning */
	zp_bootstrap();

	random_bool_init(&zone_bool_gen);

	/*
	 * the KASAN quarantine for kalloc doesn't understand heaps
	 * and trips the heap confusion panics. At the end of the day,
	 * all these security measures are double duty with KASAN.
	 *
	 * On 32bit kernels, these protections are just too expensive.
	 */
#if !defined(__LP64__) || KASAN_ZALLOC
	zsecurity_options &= ~ZSECURITY_OPTIONS_SEQUESTER;
	zsecurity_options &= ~ZSECURITY_OPTIONS_SUBMAP_USER_DATA;
	zsecurity_options &= ~ZSECURITY_OPTIONS_SEQUESTER_KEXT_KALLOC;
#endif

	thread_call_setup(&call_async_alloc, zalloc_async, NULL);

#if CONFIG_ZCACHE
	/* zcc_enable_for_zone_name=<zone>: enable per-cpu zone caching for <zone>. */
	if (PE_parse_boot_arg_str("zcc_enable_for_zone_name", cache_zone_name, sizeof(cache_zone_name))) {
		printf("zcache: caching enabled for zone %s\n", cache_zone_name);
	}
#endif /* CONFIG_ZCACHE */
}

#if __LP64__
#if CONFIG_EMBEDDED
#define ZONE_MAP_VIRTUAL_SIZE_LP64      (32ULL * 1024ULL * 1024 * 1024)
#else
#define ZONE_MAP_VIRTUAL_SIZE_LP64      (128ULL * 1024ULL * 1024 * 1024)
#endif
#endif /* __LP64__ */

#define SINGLE_GUARD                    16384
#define MULTI_GUARD                     (3 * SINGLE_GUARD)

#if __LP64__
static inline vm_offset_t
zone_restricted_va_max(void)
{
	vm_offset_t compressor_max = VM_PACKING_MAX_PACKABLE(C_SLOT_PACKED_PTR);
	vm_offset_t vm_page_max    = VM_PACKING_MAX_PACKABLE(VM_PAGE_PACKED_PTR);

	return trunc_page(MIN(compressor_max, vm_page_max));
}
#endif

__startup_func
static void
zone_tunables_fixup(void)
{
	if (zone_map_jetsam_limit == 0 || zone_map_jetsam_limit > 100) {
		zone_map_jetsam_limit = ZONE_MAP_JETSAM_LIMIT_DEFAULT;
	}
}
STARTUP(TUNABLES, STARTUP_RANK_MIDDLE, zone_tunables_fixup);

__startup_func
static vm_size_t
zone_phys_size_max(void)
{
	mach_vm_size_t zsize;
	vm_size_t zsizearg;

	if (PE_parse_boot_argn("zsize", &zsizearg, sizeof(zsizearg))) {
		zsize = zsizearg * (1024ULL * 1024);
	} else {
		zsize = sane_size >> 2;         /* Set target zone size as 1/4 of physical memory */
#if defined(__LP64__)
		zsize += zsize >> 1;
#endif /* __LP64__ */
	}

	if (zsize < CONFIG_ZONE_MAP_MIN) {
		zsize = CONFIG_ZONE_MAP_MIN;   /* Clamp to min */
	}
	if (zsize > sane_size >> 1) {
		zsize = sane_size >> 1; /* Clamp to half of RAM max */
	}
	if (zsizearg == 0 && zsize > ZONE_MAP_MAX) {
		/* if zsize boot-arg not present and zsize exceeds platform maximum, clip zsize */
		vm_size_t orig_zsize = zsize;
		zsize = ZONE_MAP_MAX;
		printf("NOTE: zonemap size reduced from 0x%lx to 0x%lx\n",
		    (uintptr_t)orig_zsize, (uintptr_t)zsize);
	}

	assert((vm_size_t) zsize == zsize);
	return (vm_size_t)trunc_page(zsize);
}

__startup_func
static struct zone_map_range
zone_init_allocate_va(vm_offset_t *submap_min, vm_size_t size, bool guard)
{
	struct zone_map_range r;
	kern_return_t kr;

	if (guard) {
		vm_map_offset_t addr = *submap_min;
		vm_map_kernel_flags_t vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;

		vmk_flags.vmkf_permanent = TRUE;
		kr = vm_map_enter(kernel_map, &addr, size, 0,
		    VM_FLAGS_FIXED, vmk_flags, VM_KERN_MEMORY_ZONE, kernel_object,
		    0, FALSE, VM_PROT_NONE, VM_PROT_NONE, VM_INHERIT_DEFAULT);
		*submap_min = (vm_offset_t)addr;
	} else {
		kr = kernel_memory_allocate(kernel_map, submap_min, size,
		    0, KMA_KOBJECT | KMA_PAGEABLE | KMA_VAONLY, VM_KERN_MEMORY_ZONE);
	}
	if (kr != KERN_SUCCESS) {
		panic("zone_init_allocate_va(0x%lx:0x%zx) failed: %d",
		    (uintptr_t)*submap_min, (size_t)size, kr);
	}

	r.min_address = *submap_min;
	*submap_min  += size;
	r.max_address = *submap_min;

	return r;
}

__startup_func
static void
zone_submap_init(
	vm_offset_t *submap_min,
	unsigned    idx,
	uint64_t    zone_sub_map_numer,
	uint64_t    *remaining_denom,
	vm_offset_t *remaining_size,
	vm_size_t   guard_size)
{
	vm_offset_t submap_start, submap_end;
	vm_size_t submap_size;
	vm_map_t  submap;
	kern_return_t kr;

	submap_size = trunc_page(zone_sub_map_numer * *remaining_size /
	    *remaining_denom);
	submap_start = *submap_min;
	submap_end = submap_start + submap_size;

#if defined(__LP64__)
	if (idx == Z_SUBMAP_IDX_VA_RESTRICTED_MAP) {
		vm_offset_t restricted_va_max = zone_restricted_va_max();
		if (submap_end > restricted_va_max) {
#if DEBUG || DEVELOPMENT
			printf("zone_init: submap[%d] clipped to %zdM of %zdM\n", idx,
			    (size_t)(restricted_va_max - submap_start) >> 20,
			    (size_t)submap_size >> 20);
#endif /* DEBUG || DEVELOPMENT */
			guard_size += submap_end - restricted_va_max;
			*remaining_size -= submap_end - restricted_va_max;
			submap_end  = restricted_va_max;
			submap_size = restricted_va_max - submap_start;
		}

		vm_packing_verify_range("vm_compressor",
		    submap_start, submap_end, VM_PACKING_PARAMS(C_SLOT_PACKED_PTR));
		vm_packing_verify_range("vm_page",
		    submap_start, submap_end, VM_PACKING_PARAMS(VM_PAGE_PACKED_PTR));
	}
#endif /* defined(__LP64__) */

	vm_map_kernel_flags_t vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
	vmk_flags.vmkf_permanent = TRUE;
	kr = kmem_suballoc(kernel_map, submap_min, submap_size,
	    FALSE, VM_FLAGS_FIXED, vmk_flags,
	    VM_KERN_MEMORY_ZONE, &submap);
	if (kr != KERN_SUCCESS) {
		panic("kmem_suballoc(kernel_map[%d] %p:%p) failed: %d",
		    idx, (void *)submap_start, (void *)submap_end, kr);
	}

#if DEBUG || DEVELOPMENT
	printf("zone_init: submap[%d] %p:%p (%zuM)\n",
	    idx, (void *)submap_start, (void *)submap_end,
	    (size_t)submap_size >> 20);
#endif /* DEBUG || DEVELOPMENT */

	zone_submaps[idx] = submap;
	*submap_min       = submap_end;
	*remaining_size  -= submap_size;
	*remaining_denom -= zone_sub_map_numer;

	zone_init_allocate_va(submap_min, guard_size, true);
}

/* Global initialization of Zone Allocator.
 * Runs after zone_bootstrap.
 */
__startup_func
static void
zone_init(void)
{
	vm_size_t       zone_meta_size;
	vm_size_t       zone_map_size;
	vm_size_t       remaining_size;
	vm_offset_t     submap_min = 0;

	if (ZSECURITY_OPTIONS_SUBMAP_USER_DATA & zsecurity_options) {
		zone_last_submap_idx = Z_SUBMAP_IDX_BAG_OF_BYTES_MAP;
	} else {
		zone_last_submap_idx = Z_SUBMAP_IDX_GENERAL_MAP;
	}
	zone_phys_mapped_max  = zone_phys_size_max();

#if __LP64__
	zone_map_size = ZONE_MAP_VIRTUAL_SIZE_LP64;
#else
	zone_map_size = zone_phys_mapped_max;
#endif
	zone_meta_size = round_page(atop(zone_map_size) *
	    sizeof(struct zone_page_metadata));

	/*
	 * Zone "map" setup:
	 *
	 * [  VA_RESTRICTED  ] <-- LP64 only
	 * [  SINGLE_GUARD   ] <-- LP64 only
	 * [  meta           ]
	 * [  SINGLE_GUARD   ]
	 * [  map<i>         ] \ for each extra map
	 * [  MULTI_GUARD    ] /
	 */
	remaining_size = zone_map_size;
#if defined(__LP64__)
	remaining_size -= SINGLE_GUARD;
#endif
	remaining_size -= zone_meta_size + SINGLE_GUARD;
	remaining_size -= MULTI_GUARD * (zone_last_submap_idx -
	    Z_SUBMAP_IDX_GENERAL_MAP + 1);

#if VM_MAX_TAG_ZONES
	if (zone_tagging_on) {
		zone_tagging_init(zone_map_size);
	}
#endif

	uint64_t remaining_denom = 0;
	uint64_t zone_sub_map_numer[Z_SUBMAP_IDX_COUNT] = {
#ifdef __LP64__
		[Z_SUBMAP_IDX_VA_RESTRICTED_MAP] = 20,
#endif /* defined(__LP64__) */
		[Z_SUBMAP_IDX_GENERAL_MAP]       = 40,
		[Z_SUBMAP_IDX_BAG_OF_BYTES_MAP]  = 40,
	};

	for (unsigned idx = 0; idx <= zone_last_submap_idx; idx++) {
#if DEBUG || DEVELOPMENT
		char submap_name[MAX_SUBMAP_NAME];
		snprintf(submap_name, MAX_SUBMAP_NAME, "submap%d", idx);
		PE_parse_boot_argn(submap_name, &zone_sub_map_numer[idx], sizeof(uint64_t));
#endif
		remaining_denom += zone_sub_map_numer[idx];
	}

	/*
	 * And now allocate the various pieces of VA and submaps.
	 *
	 * Make a first allocation of contiguous VA, that we'll deallocate,
	 * and we'll carve-out memory in that range again linearly.
	 * The kernel is stil single threaded at this stage.
	 */

	struct zone_map_range *map_range = &zone_info.zi_map_range;

	*map_range = zone_init_allocate_va(&submap_min, zone_map_size, false);
	submap_min = map_range->min_address;
	kmem_free(kernel_map, submap_min, zone_map_size);

#if defined(__LP64__)
	/*
	 * Allocate `Z_SUBMAP_IDX_VA_RESTRICTED_MAP` first because its VA range
	 * can't go beyond RESTRICTED_VA_MAX for the vm_page_t packing to work.
	 */
	zone_submap_init(&submap_min, Z_SUBMAP_IDX_VA_RESTRICTED_MAP,
	    zone_sub_map_numer[Z_SUBMAP_IDX_VA_RESTRICTED_MAP], &remaining_denom,
	    &remaining_size, SINGLE_GUARD);
#endif /* defined(__LP64__) */

	/*
	 * Allocate metadata array
	 */
	zone_info.zi_meta_range =
	    zone_init_allocate_va(&submap_min, zone_meta_size, true);
	zone_init_allocate_va(&submap_min, SINGLE_GUARD, true);

	zone_info.zi_array_base =
	    (struct zone_page_metadata *)zone_info.zi_meta_range.min_address -
	    zone_pva_from_addr(map_range->min_address).packed_address;

	/*
	 * Allocate other submaps
	 */
	for (unsigned idx = Z_SUBMAP_IDX_GENERAL_MAP; idx <= zone_last_submap_idx; idx++) {
		zone_submap_init(&submap_min, idx, zone_sub_map_numer[idx],
		    &remaining_denom, &remaining_size, MULTI_GUARD);
	}

	vm_map_t general_map = zone_submaps[Z_SUBMAP_IDX_GENERAL_MAP];
	zone_info.zi_general_range.min_address = vm_map_min(general_map);
	zone_info.zi_general_range.max_address = vm_map_max(general_map);

	assert(submap_min == map_range->max_address);

#if CONFIG_GZALLOC
	gzalloc_init(zone_map_size);
#endif

	zone_create_flags_t kma_flags = ZC_NOCACHING |
	    ZC_NOGC | ZC_NOENCRYPT | ZC_NOGZALLOC | ZC_NOCALLOUT |
	    ZC_KASAN_NOQUARANTINE | ZC_KASAN_NOREDZONE;

	(void)zone_create_ext("vm.permanent", 1, kma_flags,
	    ZONE_ID_PERMANENT, ^(zone_t z){
		z->permanent = true;
		z->z_elem_size = 1;
		z->pcpu_elem_size = 1;
#if defined(__LP64__)
		z->submap_idx = Z_SUBMAP_IDX_VA_RESTRICTED_MAP;
#endif
	});
	(void)zone_create_ext("vm.permanent.percpu", 1, kma_flags | ZC_PERCPU,
	    ZONE_ID_PERCPU_PERMANENT, ^(zone_t z){
		z->permanent = true;
		z->z_elem_size = 1;
		z->pcpu_elem_size = zpercpu_count();
#if defined(__LP64__)
		z->submap_idx = Z_SUBMAP_IDX_VA_RESTRICTED_MAP;
#endif
	});

	/*
	 * Now fix the zones that are missing their zone stats
	 * we don't really know if zfree()s happened so our stats
	 * are slightly off for early boot. ¯\_(ツ)_/¯
	 */
	zone_index_foreach(idx) {
		zone_t tz = &zone_array[idx];

		if (tz->z_self) {
			zone_stats_t zs = zalloc_percpu_permanent_type(struct zone_stats);

			zpercpu_get_cpu(zs, 0)->zs_mem_allocated +=
			    (tz->countavail - tz->countfree) *
			    zone_elem_size(tz);
			assert(tz->z_stats == NULL);
			tz->z_stats = zs;
#if ZONE_ENABLE_LOGGING
			if (tz->zone_logging && !tz->zlog_btlog) {
				zone_enable_logging(tz);
			}
#endif
		}
	}

#if CONFIG_ZLEAKS
	/*
	 * Initialize the zone leak monitor
	 */
	zleak_init(zone_map_size);
#endif /* CONFIG_ZLEAKS */

#if VM_MAX_TAG_ZONES
	if (zone_tagging_on) {
		vm_allocation_zones_init();
	}
#endif
}
STARTUP(ZALLOC, STARTUP_RANK_FIRST, zone_init);

__startup_func
static void
zone_set_foreign_range(
	vm_offset_t range_min,
	vm_offset_t range_max)
{
	zone_info.zi_foreign_range.min_address = range_min;
	zone_info.zi_foreign_range.max_address = range_max;
}

__startup_func
vm_offset_t
zone_foreign_mem_init(vm_size_t size)
{
	vm_offset_t mem = (vm_offset_t) pmap_steal_memory(size);
	zone_set_foreign_range(mem, mem + size);
	return mem;
}

#pragma mark zalloc

#if KASAN_ZALLOC
/*
 * Called from zfree() to add the element being freed to the KASan quarantine.
 *
 * Returns true if the newly-freed element made it into the quarantine without
 * displacing another, false otherwise. In the latter case, addrp points to the
 * address of the displaced element, which will be freed by the zone.
 */
static bool
kasan_quarantine_freed_element(
	zone_t          *zonep,         /* the zone the element is being freed to */
	void            **addrp)        /* address of the element being freed */
{
	zone_t zone = *zonep;
	void *addr = *addrp;

	/*
	 * Resize back to the real allocation size and hand off to the KASan
	 * quarantine. `addr` may then point to a different allocation, if the
	 * current element replaced another in the quarantine. The zone then
	 * takes ownership of the swapped out free element.
	 */
	vm_size_t usersz = zone_elem_size(zone) - 2 * zone->kasan_redzone;
	vm_size_t sz = usersz;

	if (addr && zone->kasan_redzone) {
		kasan_check_free((vm_address_t)addr, usersz, KASAN_HEAP_ZALLOC);
		addr = (void *)kasan_dealloc((vm_address_t)addr, &sz);
		assert(sz == zone_elem_size(zone));
	}
	if (addr && !zone->kasan_noquarantine) {
		kasan_free(&addr, &sz, KASAN_HEAP_ZALLOC, zonep, usersz, true);
		if (!addr) {
			return TRUE;
		}
	}
	if (addr && zone->kasan_noquarantine) {
		kasan_unpoison(addr, zone_elem_size(zone));
	}
	*addrp = addr;
	return FALSE;
}

#endif /* KASAN_ZALLOC */

static inline bool
zone_needs_async_refill(zone_t zone)
{
	if (zone->countfree != 0 || zone->async_pending || zone->no_callout) {
		return false;
	}

	return zone->expandable || zone->page_count < zone->page_count_max;
}

__attribute__((noinline))
static void
zone_refill_synchronously_locked(
	zone_t         zone,
	zalloc_flags_t flags)
{
	thread_t thr = current_thread();
	bool     set_expanding_vm_priv = false;
	zone_pva_t orig = zone->pages_intermediate;

	while ((flags & Z_NOWAIT) == 0 && (zone->permanent
	    ? zone_pva_is_equal(zone->pages_intermediate, orig)
	    : zone->countfree == 0)) {
		/*
		 * zone is empty, try to expand it
		 *
		 * Note that we now allow up to 2 threads (1 vm_privliged and
		 * 1 non-vm_privliged) to expand the zone concurrently...
		 *
		 * this is necessary to avoid stalling vm_privileged threads
		 * running critical code necessary to continue
		 * compressing/swapping pages (i.e. making new free pages) from
		 * stalling behind non-vm_privileged threads waiting to acquire
		 * free pages when the vm_page_free_count is below the
		 * vm_page_free_reserved limit.
		 */
		if ((zone->expanding_no_vm_priv || zone->expanding_vm_priv) &&
		    (((thr->options & TH_OPT_VMPRIV) == 0) || zone->expanding_vm_priv)) {
			/*
			 * This is a non-vm_privileged thread and a non-vm_privileged or
			 * a vm_privileged thread is already expanding the zone...
			 *    OR
			 * this is a vm_privileged thread and a vm_privileged thread is
			 * already expanding the zone...
			 *
			 * In either case wait for a thread to finish, then try again.
			 */
			zone->waiting = true;
			assert_wait(zone, THREAD_UNINT);
			unlock_zone(zone);
			thread_block(THREAD_CONTINUE_NULL);
			lock_zone(zone);
			continue;
		}

		if (zone->page_count >= zone->page_count_max) {
			if (zone->exhaustible) {
				break;
			}
			if (zone->expandable) {
				/*
				 * If we're expandable, just don't go through this again.
				 */
				zone->page_count_max = ~0u;
			} else {
				unlock_zone(zone);

				panic_include_zprint = true;
#if CONFIG_ZLEAKS
				if (zleak_state & ZLEAK_STATE_ACTIVE) {
					panic_include_ztrace = true;
				}
#endif /* CONFIG_ZLEAKS */
				panic("zalloc: zone \"%s\" empty.", zone->z_name);
			}
		}

		/*
		 * It is possible that a BG thread is refilling/expanding the zone
		 * and gets pre-empted during that operation. That blocks all other
		 * threads from making progress leading to a watchdog timeout. To
		 * avoid that, boost the thread priority using the rwlock boost
		 */
		set_thread_rwlock_boost();

		if ((thr->options & TH_OPT_VMPRIV)) {
			zone->expanding_vm_priv = true;
			set_expanding_vm_priv = true;
		} else {
			zone->expanding_no_vm_priv = true;
		}

		zone_replenish_locked(zone, flags, false);

		if (set_expanding_vm_priv == true) {
			zone->expanding_vm_priv = false;
		} else {
			zone->expanding_no_vm_priv = false;
		}

		if (zone->waiting) {
			zone->waiting = false;
			thread_wakeup(zone);
		}
		clear_thread_rwlock_boost();

		if (zone->countfree == 0) {
			assert(flags & Z_NOPAGEWAIT);
			break;
		}
	}

	if ((flags & (Z_NOWAIT | Z_NOPAGEWAIT)) &&
	    zone_needs_async_refill(zone) && !vm_pool_low()) {
		zone->async_pending = true;
		unlock_zone(zone);
		thread_call_enter(&call_async_alloc);
		lock_zone(zone);
		assert(zone->z_self == zone);
	}
}

__attribute__((noinline))
static void
zone_refill_asynchronously_locked(zone_t zone)
{
	uint32_t min_free = zone->prio_refill_count / 2;
	uint32_t resv_free = zone->prio_refill_count / 4;
	thread_t thr = current_thread();

	/*
	 * Nothing to do if there are plenty of elements.
	 */
	while (zone->countfree <= min_free) {
		/*
		 * Wakeup the replenish thread if not running.
		 */
		if (!zone->zone_replenishing) {
			lck_spin_lock(&zone_replenish_lock);
			assert(zone_replenish_active < zone_replenish_max_threads);
			++zone_replenish_active;
			lck_spin_unlock(&zone_replenish_lock);
			zone->zone_replenishing = true;
			zone_replenish_wakeups_initiated++;
			thread_wakeup(&zone->prio_refill_count);
		}

		/*
		 * We'll let VM_PRIV threads to continue to allocate until the
		 * reserve drops to 25%. After that only TH_OPT_ZONE_PRIV threads
		 * may continue.
		 *
		 * TH_OPT_ZONE_PRIV threads are the GC thread and a replenish thread itself.
		 * Replenish threads *need* to use the reserve. GC threads need to
		 * get through the current allocation, but then will wait at a higher
		 * level after they've dropped any locks which would deadlock the
		 * replenish thread.
		 */
		if ((zone->countfree > resv_free && (thr->options & TH_OPT_VMPRIV)) ||
		    (thr->options & TH_OPT_ZONE_PRIV)) {
			break;
		}

		/*
		 * Wait for the replenish threads to add more elements for us to allocate from.
		 */
		zone_replenish_throttle_count++;
		unlock_zone(zone);
		assert_wait_timeout(zone, THREAD_UNINT, 1, NSEC_PER_MSEC);
		thread_block(THREAD_CONTINUE_NULL);
		lock_zone(zone);

		assert(zone->z_self == zone);
	}

	/*
	 * If we're here because of zone_gc(), we didn't wait for
	 * zone_replenish_thread to finish.  So we need to ensure that
	 * we will successfully grab an element.
	 *
	 * zones that have a replenish thread configured.
	 * The value of (refill_level / 2) in the previous bit of code should have
	 * given us headroom even though this thread didn't wait.
	 */
	if (thr->options & TH_OPT_ZONE_PRIV) {
		assert(zone->countfree != 0);
	}
}

#if ZONE_ENABLE_LOGGING || CONFIG_ZLEAKS
__attribute__((noinline))
static void
zalloc_log_or_trace_leaks(zone_t zone, vm_offset_t addr)
{
	uintptr_t       zbt[MAX_ZTRACE_DEPTH];  /* used in zone leak logging and zone leak detection */
	unsigned int    numsaved = 0;

#if ZONE_ENABLE_LOGGING
	if (DO_LOGGING(zone)) {
		numsaved = backtrace(zbt, MAX_ZTRACE_DEPTH, NULL);
		btlog_add_entry(zone->zlog_btlog, (void *)addr,
		    ZOP_ALLOC, (void **)zbt, numsaved);
	}
#endif

#if CONFIG_ZLEAKS
	/*
	 * Zone leak detection: capture a backtrace every zleak_sample_factor
	 * allocations in this zone.
	 */
	if (__improbable(zone->zleak_on)) {
		if (sample_counter(&zone->zleak_capture, zleak_sample_factor)) {
			/* Avoid backtracing twice if zone logging is on */
			if (numsaved == 0) {
				numsaved = backtrace(zbt, MAX_ZTRACE_DEPTH, NULL);
			}
			/* Sampling can fail if another sample is happening at the same time in a different zone. */
			if (!zleak_log(zbt, addr, numsaved, zone_elem_size(zone))) {
				/* If it failed, roll back the counter so we sample the next allocation instead. */
				zone->zleak_capture = zleak_sample_factor;
			}
		}
	}

	if (__improbable(zone_leaks_scan_enable &&
	    !(zone_elem_size(zone) & (sizeof(uintptr_t) - 1)))) {
		unsigned int count, idx;
		/* Fill element, from tail, with backtrace in reverse order */
		if (numsaved == 0) {
			numsaved = backtrace(zbt, MAX_ZTRACE_DEPTH, NULL);
		}
		count = (unsigned int)(zone_elem_size(zone) / sizeof(uintptr_t));
		if (count >= numsaved) {
			count = numsaved - 1;
		}
		for (idx = 0; idx < count; idx++) {
			((uintptr_t *)addr)[count - 1 - idx] = zbt[idx + 1];
		}
	}
#endif /* CONFIG_ZLEAKS */
}

static inline bool
zalloc_should_log_or_trace_leaks(zone_t zone, vm_size_t elem_size)
{
#if ZONE_ENABLE_LOGGING
	if (DO_LOGGING(zone)) {
		return true;
	}
#endif
#if CONFIG_ZLEAKS
	/*
	 * Zone leak detection: capture a backtrace every zleak_sample_factor
	 * allocations in this zone.
	 */
	if (zone->zleak_on) {
		return true;
	}
	if (zone_leaks_scan_enable && !(elem_size & (sizeof(uintptr_t) - 1))) {
		return true;
	}
#endif /* CONFIG_ZLEAKS */
	return false;
}
#endif /* ZONE_ENABLE_LOGGING || CONFIG_ZLEAKS */
#if ZONE_ENABLE_LOGGING

__attribute__((noinline))
static void
zfree_log_trace(zone_t zone, vm_offset_t addr)
{
	/*
	 * See if we're doing logging on this zone.
	 *
	 * There are two styles of logging used depending on
	 * whether we're trying to catch a leak or corruption.
	 */
	if (__improbable(DO_LOGGING(zone))) {
		if (corruption_debug_flag) {
			uintptr_t       zbt[MAX_ZTRACE_DEPTH];
			unsigned int    numsaved;
			/*
			 * We're logging to catch a corruption.
			 *
			 * Add a record of this zfree operation to log.
			 */
			numsaved = backtrace(zbt, MAX_ZTRACE_DEPTH, NULL);
			btlog_add_entry(zone->zlog_btlog, (void *)addr, ZOP_FREE,
			    (void **)zbt, numsaved);
		} else {
			/*
			 * We're logging to catch a leak.
			 *
			 * Remove any record we might have for this element
			 * since it's being freed.  Note that we may not find it
			 * if the buffer overflowed and that's OK.
			 *
			 * Since the log is of a limited size, old records get
			 * overwritten if there are more zallocs than zfrees.
			 */
			btlog_remove_entries_for_element(zone->zlog_btlog, (void *)addr);
		}
	}
}
#endif /* ZONE_ENABLE_LOGGING */

/*
 * Removes an element from the zone's free list, returning 0 if the free list is empty.
 * Verifies that the next-pointer and backup next-pointer are intact,
 * and verifies that a poisoned element hasn't been modified.
 */
vm_offset_t
zalloc_direct_locked(
	zone_t              zone,
	zalloc_flags_t      flags __unused,
	vm_size_t           waste __unused)
{
	struct zone_page_metadata *page_meta;
	zone_addr_kind_t kind = ZONE_ADDR_NATIVE;
	vm_offset_t element, page, validate_bit = 0;

	/* if zone is empty, bail */
	if (!zone_pva_is_null(zone->pages_any_free_foreign)) {
		kind = ZONE_ADDR_FOREIGN;
		page_meta = zone_pva_to_meta(zone->pages_any_free_foreign, kind);
		page = (vm_offset_t)page_meta;
	} else if (!zone_pva_is_null(zone->pages_intermediate)) {
		page_meta = zone_pva_to_meta(zone->pages_intermediate, kind);
		page = zone_pva_to_addr(zone->pages_intermediate);
	} else if (!zone_pva_is_null(zone->pages_all_free)) {
		page_meta = zone_pva_to_meta(zone->pages_all_free, kind);
		page = zone_pva_to_addr(zone->pages_all_free);
		if (os_sub_overflow(zone->allfree_page_count,
		    page_meta->zm_page_count, &zone->allfree_page_count)) {
			zone_accounting_panic(zone, "allfree_page_count wrap-around");
		}
	} else {
		zone_accounting_panic(zone, "countfree corruption");
	}

	if (!zone_has_index(zone, page_meta->zm_index)) {
		zone_page_metadata_index_confusion_panic(zone, page, page_meta);
	}

	element = zone_page_meta_get_freelist(zone, page_meta, page);

	vm_offset_t *primary = (vm_offset_t *) element;
	vm_offset_t *backup  = get_backup_ptr(zone_elem_size(zone), primary);

	/*
	 * since the primary next pointer is xor'ed with zp_nopoison_cookie
	 * for obfuscation, retrieve the original value back
	 */
	vm_offset_t  next_element          = *primary ^ zp_nopoison_cookie;
	vm_offset_t  next_element_primary  = *primary;
	vm_offset_t  next_element_backup   = *backup;

	/*
	 * backup_ptr_mismatch_panic will determine what next_element
	 * should have been, and print it appropriately
	 */
	if (!zone_page_meta_is_sane_element(zone, page_meta, page, next_element, kind)) {
		backup_ptr_mismatch_panic(zone, page_meta, page, element);
	}

	/* Check the backup pointer for the regular cookie */
	if (__improbable(next_element_primary != next_element_backup)) {
		/* Check for the poisoned cookie instead */
		if (__improbable(next_element != (next_element_backup ^ zp_poisoned_cookie))) {
			/* Neither cookie is valid, corruption has occurred */
			backup_ptr_mismatch_panic(zone, page_meta, page, element);
		}

		/*
		 * Element was marked as poisoned, so check its integrity before using it.
		 */
		validate_bit = ZALLOC_ELEMENT_NEEDS_VALIDATION;
	} else if (zone->zfree_clear_mem) {
		validate_bit = ZALLOC_ELEMENT_NEEDS_VALIDATION;
	}

	/* Remove this element from the free list */
	zone_page_meta_set_freelist(page_meta, page, next_element);

	if (kind == ZONE_ADDR_FOREIGN) {
		if (next_element == 0) {
			/* last foreign element allocated on page, move to all_used_foreign */
			zone_meta_requeue(zone, &zone->pages_all_used_foreign, page_meta, kind);
		}
	} else if (next_element == 0) {
		zone_meta_requeue(zone, &zone->pages_all_used, page_meta, kind);
	} else if (page_meta->zm_alloc_count == 0) {
		/* remove from free, move to intermediate */
		zone_meta_requeue(zone, &zone->pages_intermediate, page_meta, kind);
	}

	if (os_add_overflow(page_meta->zm_alloc_count, 1,
	    &page_meta->zm_alloc_count)) {
		/*
		 * This will not catch a lot of errors, the proper check
		 * would be against the number of elements this run should
		 * have which is expensive to count.
		 *
		 * But zm_alloc_count is a 16 bit number which could
		 * theoretically be valuable to cause to wrap around,
		 * so catch this.
		 */
		zone_page_meta_accounting_panic(zone, page_meta,
		    "zm_alloc_count overflow");
	}
	if (os_sub_overflow(zone->countfree, 1, &zone->countfree)) {
		zone_accounting_panic(zone, "countfree wrap-around");
	}

#if VM_MAX_TAG_ZONES
	if (__improbable(zone->tags)) {
		vm_tag_t tag = zalloc_flags_get_tag(flags);
		// set the tag with b0 clear so the block remains inuse
		ZTAG(zone, element)[0] = (vm_tag_t)(tag << 1);
		vm_tag_update_zone_size(tag, zone->tag_zone_index,
		    zone_elem_size(zone), waste);
	}
#endif /* VM_MAX_TAG_ZONES */
#if KASAN_ZALLOC
	if (zone->percpu) {
		zpercpu_foreach_cpu(i) {
			kasan_poison_range(element + ptoa(i),
			    zone_elem_size(zone), ASAN_VALID);
		}
	} else {
		kasan_poison_range(element, zone_elem_size(zone), ASAN_VALID);
	}
#endif

	return element | validate_bit;
}

/*
 *	zalloc returns an element from the specified zone.
 */
void *
zalloc_ext(
	zone_t          zone,
	zone_stats_t    zstats,
	zalloc_flags_t  flags,
	vm_size_t       waste)
{
	vm_offset_t     addr = 0;
	vm_size_t       elem_size = zone_elem_size(zone);

	/*
	 * KASan uses zalloc() for fakestack, which can be called anywhere.
	 * However, we make sure these calls can never block.
	 */
	assert(zone->kasan_fakestacks ||
	    ml_get_interrupts_enabled() ||
	    ml_is_quiescing() ||
	    debug_mode_active() ||
	    startup_phase < STARTUP_SUB_EARLY_BOOT);

	/*
	 * Make sure Z_NOFAIL was not obviously misused
	 */
	if ((flags & Z_NOFAIL) && !zone->prio_refill_count) {
		assert(!zone->exhaustible && (flags & (Z_NOWAIT | Z_NOPAGEWAIT)) == 0);
	}

#if CONFIG_ZCACHE
	/*
	 * Note: if zone caching is on, gzalloc and tags aren't used
	 *       so we can always check this first
	 */
	if (zone_caching_enabled(zone)) {
		addr = zcache_alloc_from_cpu_cache(zone, zstats, waste);
		if (__probable(addr)) {
			goto allocated_from_cache;
		}
	}
#endif /* CONFIG_ZCACHE */

#if CONFIG_GZALLOC
	if (__improbable(zone->gzalloc_tracked)) {
		addr = gzalloc_alloc(zone, zstats, flags);
		goto allocated_from_gzalloc;
	}
#endif /* CONFIG_GZALLOC */
#if VM_MAX_TAG_ZONES
	if (__improbable(zone->tags)) {
		vm_tag_t tag = zalloc_flags_get_tag(flags);
		if (tag == VM_KERN_MEMORY_NONE) {
			/*
			 * zone views into heaps can lead to a site-less call
			 * and we fallback to KALLOC as a tag for those.
			 */
			tag = VM_KERN_MEMORY_KALLOC;
			flags |= Z_VM_TAG(tag);
		}
		vm_tag_will_update_zone(tag, zone->tag_zone_index);
	}
#endif /* VM_MAX_TAG_ZONES */

	lock_zone(zone);
	assert(zone->z_self == zone);

	/*
	 * Check if we need another thread to replenish the zone or
	 * if we have to wait for a replenish thread to finish.
	 * This is used for elements, like vm_map_entry, which are
	 * needed themselves to implement zalloc().
	 */
	if (__improbable(zone->prio_refill_count &&
	    zone->countfree <= zone->prio_refill_count / 2)) {
		zone_refill_asynchronously_locked(zone);
	} else if (__improbable(zone->countfree == 0)) {
		zone_refill_synchronously_locked(zone, flags);
		if (__improbable(zone->countfree == 0)) {
			unlock_zone(zone);
			if (__improbable(flags & Z_NOFAIL)) {
				zone_nofail_panic(zone);
			}
			goto out_nomem;
		}
	}

	addr = zalloc_direct_locked(zone, flags, waste);
	if (__probable(zstats != NULL)) {
		/*
		 * The few vm zones used before zone_init() runs do not have
		 * per-cpu stats yet
		 */
		int cpu = cpu_number();
		zpercpu_get_cpu(zstats, cpu)->zs_mem_allocated += elem_size;
#if ZALLOC_DETAILED_STATS
		if (waste) {
			zpercpu_get_cpu(zstats, cpu)->zs_mem_wasted += waste;
		}
#endif /* ZALLOC_DETAILED_STATS */
	}

	unlock_zone(zone);

#if ZALLOC_ENABLE_POISONING
	bool validate = addr & ZALLOC_ELEMENT_NEEDS_VALIDATION;
#endif
	addr &= ~ZALLOC_ELEMENT_NEEDS_VALIDATION;
	zone_clear_freelist_pointers(zone, addr);
#if ZALLOC_ENABLE_POISONING
	/*
	 * Note: percpu zones do not respect ZONE_MIN_ELEM_SIZE,
	 *       so we will check the first word even if we just
	 *       cleared it.
	 */
	zalloc_validate_element(zone, addr, elem_size - sizeof(vm_offset_t),
	    validate);
#endif /* ZALLOC_ENABLE_POISONING */

allocated_from_cache:
#if ZONE_ENABLE_LOGGING || CONFIG_ZLEAKS
	if (__improbable(zalloc_should_log_or_trace_leaks(zone, elem_size))) {
		zalloc_log_or_trace_leaks(zone, addr);
	}
#endif /* ZONE_ENABLE_LOGGING || CONFIG_ZLEAKS */

#if CONFIG_GZALLOC
allocated_from_gzalloc:
#endif
#if KASAN_ZALLOC
	if (zone->kasan_redzone) {
		addr = kasan_alloc(addr, elem_size,
		    elem_size - 2 * zone->kasan_redzone, zone->kasan_redzone);
		elem_size -= 2 * zone->kasan_redzone;
	}
	/*
	 * Initialize buffer with unique pattern only if memory
	 * wasn't expected to be zeroed.
	 */
	if (!zone->zfree_clear_mem && !(flags & Z_ZERO)) {
		kasan_leak_init(addr, elem_size);
	}
#endif /* KASAN_ZALLOC */
	if ((flags & Z_ZERO) && !zone->zfree_clear_mem) {
		bzero((void *)addr, elem_size);
	}

	TRACE_MACHLEAKS(ZALLOC_CODE, ZALLOC_CODE_2, elem_size, addr);

out_nomem:
	DTRACE_VM2(zalloc, zone_t, zone, void*, addr);
	return (void *)addr;
}

void *
zalloc(union zone_or_view zov)
{
	return zalloc_flags(zov, Z_WAITOK);
}

void *
zalloc_noblock(union zone_or_view zov)
{
	return zalloc_flags(zov, Z_NOWAIT);
}

void *
zalloc_flags(union zone_or_view zov, zalloc_flags_t flags)
{
	zone_t zone = zov.zov_view->zv_zone;
	zone_stats_t zstats = zov.zov_view->zv_stats;
	assert(!zone->percpu);
	return zalloc_ext(zone, zstats, flags, 0);
}

void *
zalloc_percpu(union zone_or_view zov, zalloc_flags_t flags)
{
	zone_t zone = zov.zov_view->zv_zone;
	zone_stats_t zstats = zov.zov_view->zv_stats;
	assert(zone->percpu);
	return (void *)__zpcpu_mangle(zalloc_ext(zone, zstats, flags, 0));
}

static void *
_zalloc_permanent(zone_t zone, vm_size_t size, vm_offset_t mask)
{
	const zone_addr_kind_t kind = ZONE_ADDR_NATIVE;
	struct zone_page_metadata *page_meta;
	vm_offset_t offs, addr;
	zone_pva_t pva;

	assert(ml_get_interrupts_enabled() ||
	    ml_is_quiescing() ||
	    debug_mode_active() ||
	    startup_phase < STARTUP_SUB_EARLY_BOOT);

	size = (size + mask) & ~mask;
	assert(size <= PAGE_SIZE);

	lock_zone(zone);
	assert(zone->z_self == zone);

	for (;;) {
		pva = zone->pages_intermediate;
		while (!zone_pva_is_null(pva)) {
			page_meta = zone_pva_to_meta(pva, kind);
			if (page_meta->zm_freelist_offs + size <= PAGE_SIZE) {
				goto found;
			}
			pva = page_meta->zm_page_next;
		}

		zone_refill_synchronously_locked(zone, Z_WAITOK);
	}

found:
	offs = (page_meta->zm_freelist_offs + mask) & ~mask;
	page_meta->zm_freelist_offs = offs + size;
	page_meta->zm_alloc_count += size;
	zone->countfree -= size;
	if (__probable(zone->z_stats)) {
		zpercpu_get(zone->z_stats)->zs_mem_allocated += size;
	}

	if (page_meta->zm_alloc_count >= PAGE_SIZE - sizeof(vm_offset_t)) {
		zone_meta_requeue(zone, &zone->pages_all_used, page_meta, kind);
	}

	unlock_zone(zone);

	addr = offs + zone_pva_to_addr(pva);

	DTRACE_VM2(zalloc, zone_t, zone, void*, addr);
	return (void *)addr;
}

static void *
_zalloc_permanent_large(size_t size, vm_offset_t mask)
{
	kern_return_t kr;
	vm_offset_t addr;

	kr = kernel_memory_allocate(kernel_map, &addr, size, mask,
	    KMA_KOBJECT | KMA_PERMANENT | KMA_ZERO,
	    VM_KERN_MEMORY_KALLOC);
	if (kr != 0) {
		panic("zalloc_permanent: unable to allocate %zd bytes (%d)",
		    size, kr);
	}
	return (void *)addr;
}

void *
zalloc_permanent(vm_size_t size, vm_offset_t mask)
{
	if (size <= PAGE_SIZE) {
		zone_t zone = &zone_array[ZONE_ID_PERMANENT];
		return _zalloc_permanent(zone, size, mask);
	}
	return _zalloc_permanent_large(size, mask);
}

void *
zalloc_percpu_permanent(vm_size_t size, vm_offset_t mask)
{
	zone_t zone = &zone_array[ZONE_ID_PERCPU_PERMANENT];
	return (void *)__zpcpu_mangle(_zalloc_permanent(zone, size, mask));
}

void
zalloc_async(__unused thread_call_param_t p0, __unused thread_call_param_t p1)
{
	zone_index_foreach(i) {
		zone_t z = &zone_array[i];

		if (z->no_callout) {
			/* async_pending will never be set */
			continue;
		}

		lock_zone(z);
		if (z->z_self && z->async_pending) {
			z->async_pending = false;
			zone_refill_synchronously_locked(z, Z_WAITOK);
		}
		unlock_zone(z);
	}
}

/*
 * Adds the element to the head of the zone's free list
 * Keeps a backup next-pointer at the end of the element
 */
void
zfree_direct_locked(zone_t zone, vm_offset_t element, bool poison)
{
	struct zone_page_metadata *page_meta;
	vm_offset_t page, old_head;
	zone_addr_kind_t kind;
	vm_size_t elem_size = zone_elem_size(zone);

	vm_offset_t *primary  = (vm_offset_t *) element;
	vm_offset_t *backup   = get_backup_ptr(elem_size, primary);

	page_meta = zone_allocated_element_resolve(zone, element, &page, &kind);
	old_head = zone_page_meta_get_freelist(zone, page_meta, page);

	if (__improbable(old_head == element)) {
		panic("zfree: double free of %p to zone %s%s\n",
		    (void *) element, zone_heap_name(zone), zone->z_name);
	}

#if ZALLOC_ENABLE_POISONING
	if (poison && elem_size < ZONE_MIN_ELEM_SIZE) {
		assert(zone->percpu);
		poison = false;
	}
#else
	poison = false;
#endif

	/*
	 * Always write a redundant next pointer
	 * So that it is more difficult to forge, xor it with a random cookie
	 * A poisoned element is indicated by using zp_poisoned_cookie
	 * instead of zp_nopoison_cookie
	 */

	*backup = old_head ^ (poison ? zp_poisoned_cookie : zp_nopoison_cookie);

	/*
	 * Insert this element at the head of the free list. We also xor the
	 * primary pointer with the zp_nopoison_cookie to make sure a free
	 * element does not provide the location of the next free element directly.
	 */
	*primary = old_head ^ zp_nopoison_cookie;

#if VM_MAX_TAG_ZONES
	if (__improbable(zone->tags)) {
		vm_tag_t tag = (ZTAG(zone, element)[0] >> 1);
		// set the tag with b0 clear so the block remains inuse
		ZTAG(zone, element)[0] = 0xFFFE;
		vm_tag_update_zone_size(tag, zone->tag_zone_index,
		    -((int64_t)elem_size), 0);
	}
#endif /* VM_MAX_TAG_ZONES */

	zone_page_meta_set_freelist(page_meta, page, element);
	if (os_sub_overflow(page_meta->zm_alloc_count, 1,
	    &page_meta->zm_alloc_count)) {
		zone_page_meta_accounting_panic(zone, page_meta,
		    "alloc_count wrap-around");
	}
	zone->countfree++;

	if (kind == ZONE_ADDR_FOREIGN) {
		if (old_head == 0) {
			/* first foreign element freed on page, move from all_used_foreign */
			zone_meta_requeue(zone, &zone->pages_any_free_foreign, page_meta, kind);
		}
	} else if (page_meta->zm_alloc_count == 0) {
		/* whether the page was on the intermediate or all_used, queue, move it to free */
		zone_meta_requeue(zone, &zone->pages_all_free, page_meta, kind);
		zone->allfree_page_count += page_meta->zm_page_count;
	} else if (old_head == 0) {
		/* first free element on page, move from all_used */
		zone_meta_requeue(zone, &zone->pages_intermediate, page_meta, kind);
	}

#if KASAN_ZALLOC
	if (zone->percpu) {
		zpercpu_foreach_cpu(i) {
			kasan_poison_range(element + ptoa(i), elem_size,
			    ASAN_HEAP_FREED);
		}
	} else {
		kasan_poison_range(element, elem_size, ASAN_HEAP_FREED);
	}
#endif
}

void
zfree_ext(zone_t zone, zone_stats_t zstats, void *addr)
{
	vm_offset_t     elem = (vm_offset_t)addr;
	vm_size_t       elem_size = zone_elem_size(zone);
	bool            poison = false;

	DTRACE_VM2(zfree, zone_t, zone, void*, addr);
	TRACE_MACHLEAKS(ZFREE_CODE, ZFREE_CODE_2, elem_size, elem);

#if KASAN_ZALLOC
	if (kasan_quarantine_freed_element(&zone, &addr)) {
		return;
	}
	/*
	 * kasan_quarantine_freed_element() might return a different
	 * {zone, addr} than the one being freed for kalloc heaps.
	 *
	 * Make sure we reload everything.
	 */
	elem = (vm_offset_t)addr;
	elem_size = zone_elem_size(zone);
#endif

#if CONFIG_ZLEAKS
	/*
	 * Zone leak detection: un-track the allocation
	 */
	if (__improbable(zone->zleak_on)) {
		zleak_free(elem, elem_size);
	}
#endif /* CONFIG_ZLEAKS */

#if CONFIG_ZCACHE
	/*
	 * Note: if zone caching is on, gzalloc and tags aren't used
	 *       so we can always check this first
	 */
	if (zone_caching_enabled(zone)) {
		return zcache_free_to_cpu_cache(zone, zstats, (vm_offset_t)addr);
	}
#endif /* CONFIG_ZCACHE */

#if CONFIG_GZALLOC
	if (__improbable(zone->gzalloc_tracked)) {
		return gzalloc_free(zone, zstats, addr);
	}
#endif /* CONFIG_GZALLOC */

#if ZONE_ENABLE_LOGGING
	if (__improbable(DO_LOGGING(zone))) {
		zfree_log_trace(zone, elem);
	}
#endif /* ZONE_ENABLE_LOGGING */

	if (zone->zfree_clear_mem) {
		poison = zfree_clear(zone, elem, elem_size);
	}

	lock_zone(zone);
	assert(zone->z_self == zone);

	if (!poison) {
		poison = zfree_poison_element(zone, &zone->zp_count, elem);
	}

	if (__probable(zstats != NULL)) {
		/*
		 * The few vm zones used before zone_init() runs do not have
		 * per-cpu stats yet
		 */
		zpercpu_get(zstats)->zs_mem_freed += elem_size;
	}

	zfree_direct_locked(zone, elem, poison);

	unlock_zone(zone);
}

void
(zfree)(union zone_or_view zov, void *addr)
{
	zone_t zone = zov.zov_view->zv_zone;
	zone_stats_t zstats = zov.zov_view->zv_stats;
	assert(!zone->percpu);
	zfree_ext(zone, zstats, addr);
}

void
zfree_percpu(union zone_or_view zov, void *addr)
{
	zone_t zone = zov.zov_view->zv_zone;
	zone_stats_t zstats = zov.zov_view->zv_stats;
	assert(zone->percpu);
	zfree_ext(zone, zstats, (void *)__zpcpu_demangle(addr));
}

#pragma mark vm integration, MIG routines

/*
 * Drops (i.e. frees) the elements in the all free pages queue of a zone.
 * Called by zone_gc() on each zone and when a zone is zdestroy()ed.
 */
static void
zone_drop_free_elements(zone_t z)
{
	const zone_addr_kind_t    kind = ZONE_ADDR_NATIVE;
	unsigned int              total_freed_pages = 0;
	struct zone_page_metadata *page_meta, *seq_meta;
	vm_address_t              page_addr;
	vm_size_t                 size_to_free;
	vm_size_t                 free_count;
	uint32_t                  page_count;

	current_thread()->options |= TH_OPT_ZONE_PRIV;
	lock_zone(z);

	while (!zone_pva_is_null(z->pages_all_free)) {
		/*
		 * If any replenishment threads are running, defer to them,
		 * so that we don't deplete reserved zones.
		 *
		 * The timing of the check isn't super important, as there are
		 * enough reserves to allow freeing an extra page_meta.
		 *
		 * Hence, we can check without grabbing the lock every time
		 * through the loop.  We do need the lock however to avoid
		 * missing a wakeup when we decide to block.
		 */
		if (zone_replenish_active > 0) {
			lck_spin_lock(&zone_replenish_lock);
			if (zone_replenish_active > 0) {
				assert_wait(&zone_replenish_active, THREAD_UNINT);
				lck_spin_unlock(&zone_replenish_lock);
				unlock_zone(z);
				thread_block(THREAD_CONTINUE_NULL);
				lock_zone(z);
				continue;
			}
			lck_spin_unlock(&zone_replenish_lock);
		}

		page_meta = zone_pva_to_meta(z->pages_all_free, kind);
		page_count = page_meta->zm_page_count;
		free_count = zone_elem_count(z, ptoa(page_count), kind);

		/*
		 * Don't drain zones with async refill to below the refill
		 * threshold, as they need some reserve to function properly.
		 */
		if (!z->destroyed && z->prio_refill_count &&
		    (vm_size_t)(z->countfree - free_count) < z->prio_refill_count) {
			break;
		}

		zone_meta_queue_pop(z, &z->pages_all_free, kind, &page_addr);

		if (os_sub_overflow(z->countfree, free_count, &z->countfree)) {
			zone_accounting_panic(z, "countfree wrap-around");
		}
		if (os_sub_overflow(z->countavail, free_count, &z->countavail)) {
			zone_accounting_panic(z, "countavail wrap-around");
		}
		if (os_sub_overflow(z->allfree_page_count, page_count,
		    &z->allfree_page_count)) {
			zone_accounting_panic(z, "allfree_page_count wrap-around");
		}
		if (os_sub_overflow(z->page_count, page_count, &z->page_count)) {
			zone_accounting_panic(z, "page_count wrap-around");
		}

		os_atomic_sub(&zones_phys_page_count, page_count, relaxed);
		os_atomic_sub(&zones_phys_page_mapped_count, page_count, relaxed);

		bzero(page_meta, sizeof(*page_meta) * page_count);
		seq_meta = page_meta;
		page_meta = NULL; /* page_meta fields are zeroed, prevent reuse */

		unlock_zone(z);

		/* Free the pages for metadata and account for them */
		total_freed_pages += page_count;
		size_to_free = ptoa(page_count);
#if KASAN_ZALLOC
		kasan_poison_range(page_addr, size_to_free, ASAN_VALID);
#endif
#if VM_MAX_TAG_ZONES
		if (z->tags) {
			ztMemoryRemove(z, page_addr, size_to_free);
		}
#endif /* VM_MAX_TAG_ZONES */

		if (z->va_sequester && z->alloc_pages == page_count) {
			kernel_memory_depopulate(submap_for_zone(z), page_addr,
			    size_to_free, KMA_KOBJECT, VM_KERN_MEMORY_ZONE);
		} else {
			kmem_free(submap_for_zone(z), page_addr, size_to_free);
			seq_meta = NULL;
		}
		thread_yield_to_preemption();

		lock_zone(z);

		if (seq_meta) {
			zone_meta_queue_push(z, &z->pages_sequester, seq_meta, kind);
			z->sequester_page_count += page_count;
		}
	}
	if (z->destroyed) {
		assert(zone_pva_is_null(z->pages_all_free));
		assert(z->allfree_page_count == 0);
	}
	unlock_zone(z);
	current_thread()->options &= ~TH_OPT_ZONE_PRIV;

#if DEBUG || DEVELOPMENT
	if (zalloc_debug & ZALLOC_DEBUG_ZONEGC) {
		kprintf("zone_gc() of zone %s%s freed %lu elements, %d pages\n",
		    zone_heap_name(z), z->z_name,
		    (unsigned long)(ptoa(total_freed_pages) / z->pcpu_elem_size),
		    total_freed_pages);
	}
#endif /* DEBUG || DEVELOPMENT */
}

/*	Zone garbage collection
 *
 *	zone_gc will walk through all the free elements in all the
 *	zones that are marked collectable looking for reclaimable
 *	pages.  zone_gc is called by consider_zone_gc when the system
 *	begins to run out of memory.
 *
 *	We should ensure that zone_gc never blocks.
 */
void
zone_gc(boolean_t consider_jetsams)
{
	if (consider_jetsams) {
		kill_process_in_largest_zone();
		/*
		 * If we do end up jetsamming something, we need to do a zone_gc so that
		 * we can reclaim free zone elements and update the zone map size.
		 * Fall through.
		 */
	}

	lck_mtx_lock(&zone_gc_lock);

#if DEBUG || DEVELOPMENT
	if (zalloc_debug & ZALLOC_DEBUG_ZONEGC) {
		kprintf("zone_gc() starting...\n");
	}
#endif /* DEBUG || DEVELOPMENT */

	zone_index_foreach(i) {
		zone_t z = &zone_array[i];

		if (!z->collectable) {
			continue;
		}
#if CONFIG_ZCACHE
		if (zone_caching_enabled(z)) {
			zcache_drain_depot(z);
		}
#endif /* CONFIG_ZCACHE */
		if (zone_pva_is_null(z->pages_all_free)) {
			continue;
		}

		zone_drop_free_elements(z);
	}

	lck_mtx_unlock(&zone_gc_lock);
}

/*
 *	consider_zone_gc:
 *
 *	Called by the pageout daemon when the system needs more free pages.
 */

void
consider_zone_gc(boolean_t consider_jetsams)
{
	/*
	 * One-time reclaim of kernel_map resources we allocated in
	 * early boot.
	 *
	 * Use atomic exchange in case multiple threads race into here.
	 */
	vm_offset_t deallocate_kaddr;
	if (kmapoff_kaddr != 0 &&
	    (deallocate_kaddr = os_atomic_xchg(&kmapoff_kaddr, 0, relaxed)) != 0) {
		vm_deallocate(kernel_map, deallocate_kaddr, ptoa_64(kmapoff_pgcnt));
	}

	zone_gc(consider_jetsams);
}

/*
 * Creates a vm_map_copy_t to return to the caller of mach_* MIG calls
 * requesting zone information.
 * Frees unused pages towards the end of the region, and zero'es out unused
 * space on the last page.
 */
static vm_map_copy_t
create_vm_map_copy(
	vm_offset_t             start_addr,
	vm_size_t               total_size,
	vm_size_t               used_size)
{
	kern_return_t   kr;
	vm_offset_t             end_addr;
	vm_size_t               free_size;
	vm_map_copy_t   copy;

	if (used_size != total_size) {
		end_addr = start_addr + used_size;
		free_size = total_size - (round_page(end_addr) - start_addr);

		if (free_size >= PAGE_SIZE) {
			kmem_free(ipc_kernel_map,
			    round_page(end_addr), free_size);
		}
		bzero((char *) end_addr, round_page(end_addr) - end_addr);
	}

	kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)start_addr,
	    (vm_map_size_t)used_size, TRUE, &copy);
	assert(kr == KERN_SUCCESS);

	return copy;
}

static boolean_t
get_zone_info(
	zone_t                   z,
	mach_zone_name_t        *zn,
	mach_zone_info_t        *zi)
{
	struct zone zcopy;

	assert(z != ZONE_NULL);
	lock_zone(z);
	if (!z->z_self) {
		unlock_zone(z);
		return FALSE;
	}
	zcopy = *z;
	unlock_zone(z);

	if (zn != NULL) {
		/*
		 * Append kalloc heap name to zone name (if zone is used by kalloc)
		 */
		char temp_zone_name[MAX_ZONE_NAME] = "";
		snprintf(temp_zone_name, MAX_ZONE_NAME, "%s%s",
		    zone_heap_name(z), z->z_name);

		/* assuming here the name data is static */
		(void) __nosan_strlcpy(zn->mzn_name, temp_zone_name,
		    strlen(temp_zone_name) + 1);
	}

	if (zi != NULL) {
		*zi = (mach_zone_info_t) {
			.mzi_count = zone_count_allocated(&zcopy),
			.mzi_cur_size = ptoa_64(zcopy.page_count),
			// max_size for zprint is now high-watermark of pages used
			.mzi_max_size = ptoa_64(zcopy.page_count_hwm),
			.mzi_elem_size = zcopy.pcpu_elem_size,
			.mzi_alloc_size = ptoa_64(zcopy.alloc_pages),
			.mzi_exhaustible = (uint64_t)zcopy.exhaustible,
		};
		zpercpu_foreach(zs, zcopy.z_stats) {
			zi->mzi_sum_size += zs->zs_mem_allocated;
		}
		if (zcopy.collectable) {
			SET_MZI_COLLECTABLE_BYTES(zi->mzi_collectable,
			    ptoa_64(zcopy.allfree_page_count));
			SET_MZI_COLLECTABLE_FLAG(zi->mzi_collectable, TRUE);
		}
	}

	return TRUE;
}

kern_return_t
task_zone_info(
	__unused task_t                                 task,
	__unused mach_zone_name_array_t *namesp,
	__unused mach_msg_type_number_t *namesCntp,
	__unused task_zone_info_array_t *infop,
	__unused mach_msg_type_number_t *infoCntp)
{
	return KERN_FAILURE;
}

kern_return_t
mach_zone_info(
	host_priv_t             host,
	mach_zone_name_array_t  *namesp,
	mach_msg_type_number_t  *namesCntp,
	mach_zone_info_array_t  *infop,
	mach_msg_type_number_t  *infoCntp)
{
	return mach_memory_info(host, namesp, namesCntp, infop, infoCntp, NULL, NULL);
}


kern_return_t
mach_memory_info(
	host_priv_t             host,
	mach_zone_name_array_t  *namesp,
	mach_msg_type_number_t  *namesCntp,
	mach_zone_info_array_t  *infop,
	mach_msg_type_number_t  *infoCntp,
	mach_memory_info_array_t *memoryInfop,
	mach_msg_type_number_t   *memoryInfoCntp)
{
	mach_zone_name_t        *names;
	vm_offset_t             names_addr;
	vm_size_t               names_size;

	mach_zone_info_t        *info;
	vm_offset_t             info_addr;
	vm_size_t               info_size;

	mach_memory_info_t      *memory_info;
	vm_offset_t             memory_info_addr;
	vm_size_t               memory_info_size;
	vm_size_t               memory_info_vmsize;
	unsigned int            num_info;

	unsigned int            max_zones, used_zones, i;
	mach_zone_name_t        *zn;
	mach_zone_info_t        *zi;
	kern_return_t           kr;

	uint64_t                zones_collectable_bytes = 0;

	if (host == HOST_NULL) {
		return KERN_INVALID_HOST;
	}
#if CONFIG_DEBUGGER_FOR_ZONE_INFO
	if (!PE_i_can_has_debugger(NULL)) {
		return KERN_INVALID_HOST;
	}
#endif

	/*
	 *	We assume that zones aren't freed once allocated.
	 *	We won't pick up any zones that are allocated later.
	 */

	max_zones = os_atomic_load(&num_zones, relaxed);

	names_size = round_page(max_zones * sizeof *names);
	kr = kmem_alloc_pageable(ipc_kernel_map,
	    &names_addr, names_size, VM_KERN_MEMORY_IPC);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	names = (mach_zone_name_t *) names_addr;

	info_size = round_page(max_zones * sizeof *info);
	kr = kmem_alloc_pageable(ipc_kernel_map,
	    &info_addr, info_size, VM_KERN_MEMORY_IPC);
	if (kr != KERN_SUCCESS) {
		kmem_free(ipc_kernel_map,
		    names_addr, names_size);
		return kr;
	}
	info = (mach_zone_info_t *) info_addr;

	zn = &names[0];
	zi = &info[0];

	used_zones = max_zones;
	for (i = 0; i < max_zones; i++) {
		if (!get_zone_info(&(zone_array[i]), zn, zi)) {
			used_zones--;
			continue;
		}
		zones_collectable_bytes += GET_MZI_COLLECTABLE_BYTES(zi->mzi_collectable);
		zn++;
		zi++;
	}

	*namesp = (mach_zone_name_t *) create_vm_map_copy(names_addr, names_size, used_zones * sizeof *names);
	*namesCntp = used_zones;

	*infop = (mach_zone_info_t *) create_vm_map_copy(info_addr, info_size, used_zones * sizeof *info);
	*infoCntp = used_zones;

	num_info = 0;
	memory_info_addr = 0;

	if (memoryInfop && memoryInfoCntp) {
		vm_map_copy_t           copy;
		num_info = vm_page_diagnose_estimate();
		memory_info_size = num_info * sizeof(*memory_info);
		memory_info_vmsize = round_page(memory_info_size);
		kr = kmem_alloc_pageable(ipc_kernel_map,
		    &memory_info_addr, memory_info_vmsize, VM_KERN_MEMORY_IPC);
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		kr = vm_map_wire_kernel(ipc_kernel_map, memory_info_addr, memory_info_addr + memory_info_vmsize,
		    VM_PROT_READ | VM_PROT_WRITE, VM_KERN_MEMORY_IPC, FALSE);
		assert(kr == KERN_SUCCESS);

		memory_info = (mach_memory_info_t *) memory_info_addr;
		vm_page_diagnose(memory_info, num_info, zones_collectable_bytes);

		kr = vm_map_unwire(ipc_kernel_map, memory_info_addr, memory_info_addr + memory_info_vmsize, FALSE);
		assert(kr == KERN_SUCCESS);

		kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)memory_info_addr,
		    (vm_map_size_t)memory_info_size, TRUE, &copy);
		assert(kr == KERN_SUCCESS);

		*memoryInfop = (mach_memory_info_t *) copy;
		*memoryInfoCntp = num_info;
	}

	return KERN_SUCCESS;
}

kern_return_t
mach_zone_info_for_zone(
	host_priv_t                     host,
	mach_zone_name_t        name,
	mach_zone_info_t        *infop)
{
	zone_t zone_ptr;

	if (host == HOST_NULL) {
		return KERN_INVALID_HOST;
	}
#if CONFIG_DEBUGGER_FOR_ZONE_INFO
	if (!PE_i_can_has_debugger(NULL)) {
		return KERN_INVALID_HOST;
	}
#endif

	if (infop == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	zone_ptr = ZONE_NULL;
	zone_index_foreach(i) {
		zone_t z = &(zone_array[i]);
		assert(z != ZONE_NULL);

		/*
		 * Append kalloc heap name to zone name (if zone is used by kalloc)
		 */
		char temp_zone_name[MAX_ZONE_NAME] = "";
		snprintf(temp_zone_name, MAX_ZONE_NAME, "%s%s",
		    zone_heap_name(z), z->z_name);

		/* Find the requested zone by name */
		if (track_this_zone(temp_zone_name, name.mzn_name)) {
			zone_ptr = z;
			break;
		}
	}

	/* No zones found with the requested zone name */
	if (zone_ptr == ZONE_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (get_zone_info(zone_ptr, NULL, infop)) {
		return KERN_SUCCESS;
	}
	return KERN_FAILURE;
}

kern_return_t
mach_zone_info_for_largest_zone(
	host_priv_t                     host,
	mach_zone_name_t        *namep,
	mach_zone_info_t        *infop)
{
	if (host == HOST_NULL) {
		return KERN_INVALID_HOST;
	}
#if CONFIG_DEBUGGER_FOR_ZONE_INFO
	if (!PE_i_can_has_debugger(NULL)) {
		return KERN_INVALID_HOST;
	}
#endif

	if (namep == NULL || infop == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (get_zone_info(zone_find_largest(), namep, infop)) {
		return KERN_SUCCESS;
	}
	return KERN_FAILURE;
}

uint64_t
get_zones_collectable_bytes(void)
{
	uint64_t zones_collectable_bytes = 0;
	mach_zone_info_t zi;

	zone_index_foreach(i) {
		if (get_zone_info(&zone_array[i], NULL, &zi)) {
			zones_collectable_bytes +=
			    GET_MZI_COLLECTABLE_BYTES(zi.mzi_collectable);
		}
	}

	return zones_collectable_bytes;
}

kern_return_t
mach_zone_get_zlog_zones(
	host_priv_t                             host,
	mach_zone_name_array_t  *namesp,
	mach_msg_type_number_t  *namesCntp)
{
#if ZONE_ENABLE_LOGGING
	unsigned int max_zones, logged_zones, i;
	kern_return_t kr;
	zone_t zone_ptr;
	mach_zone_name_t *names;
	vm_offset_t names_addr;
	vm_size_t names_size;

	if (host == HOST_NULL) {
		return KERN_INVALID_HOST;
	}

	if (namesp == NULL || namesCntp == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	max_zones = os_atomic_load(&num_zones, relaxed);

	names_size = round_page(max_zones * sizeof *names);
	kr = kmem_alloc_pageable(ipc_kernel_map,
	    &names_addr, names_size, VM_KERN_MEMORY_IPC);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	names = (mach_zone_name_t *) names_addr;

	zone_ptr = ZONE_NULL;
	logged_zones = 0;
	for (i = 0; i < max_zones; i++) {
		zone_t z = &(zone_array[i]);
		assert(z != ZONE_NULL);

		/* Copy out the zone name if zone logging is enabled */
		if (z->zlog_btlog) {
			get_zone_info(z, &names[logged_zones], NULL);
			logged_zones++;
		}
	}

	*namesp = (mach_zone_name_t *) create_vm_map_copy(names_addr, names_size, logged_zones * sizeof *names);
	*namesCntp = logged_zones;

	return KERN_SUCCESS;

#else /* ZONE_ENABLE_LOGGING */
#pragma unused(host, namesp, namesCntp)
	return KERN_FAILURE;
#endif /* ZONE_ENABLE_LOGGING */
}

kern_return_t
mach_zone_get_btlog_records(
	host_priv_t                             host,
	mach_zone_name_t                name,
	zone_btrecord_array_t   *recsp,
	mach_msg_type_number_t  *recsCntp)
{
#if DEBUG || DEVELOPMENT
	unsigned int numrecs = 0;
	zone_btrecord_t *recs;
	kern_return_t kr;
	zone_t zone_ptr;
	vm_offset_t recs_addr;
	vm_size_t recs_size;

	if (host == HOST_NULL) {
		return KERN_INVALID_HOST;
	}

	if (recsp == NULL || recsCntp == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	zone_ptr = ZONE_NULL;
	zone_index_foreach(i) {
		zone_t z = &zone_array[i];

		/*
		 * Append kalloc heap name to zone name (if zone is used by kalloc)
		 */
		char temp_zone_name[MAX_ZONE_NAME] = "";
		snprintf(temp_zone_name, MAX_ZONE_NAME, "%s%s",
		    zone_heap_name(z), z->z_name);

		/* Find the requested zone by name */
		if (track_this_zone(temp_zone_name, name.mzn_name)) {
			zone_ptr = z;
			break;
		}
	}

	/* No zones found with the requested zone name */
	if (zone_ptr == ZONE_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	/* Logging not turned on for the requested zone */
	if (!DO_LOGGING(zone_ptr)) {
		return KERN_FAILURE;
	}

	/* Allocate memory for btlog records */
	numrecs = (unsigned int)(get_btlog_records_count(zone_ptr->zlog_btlog));
	recs_size = round_page(numrecs * sizeof *recs);

	kr = kmem_alloc_pageable(ipc_kernel_map, &recs_addr, recs_size, VM_KERN_MEMORY_IPC);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	/*
	 * We will call get_btlog_records() below which populates this region while holding a spinlock
	 * (the btlog lock). So these pages need to be wired.
	 */
	kr = vm_map_wire_kernel(ipc_kernel_map, recs_addr, recs_addr + recs_size,
	    VM_PROT_READ | VM_PROT_WRITE, VM_KERN_MEMORY_IPC, FALSE);
	assert(kr == KERN_SUCCESS);

	recs = (zone_btrecord_t *)recs_addr;
	get_btlog_records(zone_ptr->zlog_btlog, recs, &numrecs);

	kr = vm_map_unwire(ipc_kernel_map, recs_addr, recs_addr + recs_size, FALSE);
	assert(kr == KERN_SUCCESS);

	*recsp = (zone_btrecord_t *) create_vm_map_copy(recs_addr, recs_size, numrecs * sizeof *recs);
	*recsCntp = numrecs;

	return KERN_SUCCESS;

#else /* DEBUG || DEVELOPMENT */
#pragma unused(host, name, recsp, recsCntp)
	return KERN_FAILURE;
#endif /* DEBUG || DEVELOPMENT */
}


#if DEBUG || DEVELOPMENT

kern_return_t
mach_memory_info_check(void)
{
	mach_memory_info_t * memory_info;
	mach_memory_info_t * info;
	unsigned int         num_info;
	vm_offset_t          memory_info_addr;
	kern_return_t        kr;
	size_t               memory_info_size, memory_info_vmsize;
	uint64_t             top_wired, zonestotal, total;

	num_info = vm_page_diagnose_estimate();
	memory_info_size = num_info * sizeof(*memory_info);
	memory_info_vmsize = round_page(memory_info_size);
	kr = kmem_alloc(kernel_map, &memory_info_addr, memory_info_vmsize, VM_KERN_MEMORY_DIAG);
	assert(kr == KERN_SUCCESS);

	memory_info = (mach_memory_info_t *) memory_info_addr;
	vm_page_diagnose(memory_info, num_info, 0);

	top_wired = total = zonestotal = 0;
	zone_index_foreach(idx) {
		zonestotal += zone_size_wired(&zone_array[idx]);
	}

	for (uint32_t idx = 0; idx < num_info; idx++) {
		info = &memory_info[idx];
		if (!info->size) {
			continue;
		}
		if (VM_KERN_COUNT_WIRED == info->site) {
			top_wired = info->size;
		}
		if (VM_KERN_SITE_HIDE & info->flags) {
			continue;
		}
		if (!(VM_KERN_SITE_WIRED & info->flags)) {
			continue;
		}
		total += info->size;
	}
	total += zonestotal;

	printf("vm_page_diagnose_check %qd of %qd, zones %qd, short 0x%qx\n",
	    total, top_wired, zonestotal, top_wired - total);

	kmem_free(kernel_map, memory_info_addr, memory_info_vmsize);

	return kr;
}

extern boolean_t(*volatile consider_buffer_cache_collect)(int);

#endif /* DEBUG || DEVELOPMENT */

kern_return_t
mach_zone_force_gc(
	host_t host)
{
	if (host == HOST_NULL) {
		return KERN_INVALID_HOST;
	}

#if DEBUG || DEVELOPMENT
	/* Callout to buffer cache GC to drop elements in the apfs zones */
	if (consider_buffer_cache_collect != NULL) {
		(void)(*consider_buffer_cache_collect)(0);
	}
	consider_zone_gc(FALSE);
#endif /* DEBUG || DEVELOPMENT */
	return KERN_SUCCESS;
}

zone_t
zone_find_largest(void)
{
	uint32_t    largest_idx  = 0;
	vm_offset_t largest_size = zone_size_wired(&zone_array[0]);

	zone_index_foreach(i) {
		vm_offset_t size = zone_size_wired(&zone_array[i]);
		if (size > largest_size) {
			largest_idx = i;
			largest_size = size;
		}
	}

	return &zone_array[largest_idx];
}

#pragma mark - tests
#if DEBUG || DEVELOPMENT

/*
 * Used for sysctl kern.run_zone_test which is not thread-safe. Ensure only one
 * thread goes through at a time.  Or we can end up with multiple test zones (if
 * a second zinit() comes through before zdestroy()),  which could lead us to
 * run out of zones.
 */
SIMPLE_LOCK_DECLARE(zone_test_lock, 0);
static boolean_t zone_test_running = FALSE;
static zone_t test_zone_ptr = NULL;

static uintptr_t *
zone_copy_allocations(zone_t z, uintptr_t *elems, bitmap_t *bits,
    zone_pva_t page_index, zone_addr_kind_t kind)
{
	vm_offset_t free, first, end, page;
	struct zone_page_metadata *meta;

	while (!zone_pva_is_null(page_index)) {
		page  = zone_pva_to_addr(page_index);
		meta  = zone_pva_to_meta(page_index, kind);
		end   = page + ptoa(meta->zm_percpu ? 1 : meta->zm_page_count);
		first = page + ZONE_PAGE_FIRST_OFFSET(kind);

		bitmap_clear(bits, (uint32_t)((end - first) / zone_elem_size(z)));

		// construct bitmap of all freed elements
		free = zone_page_meta_get_freelist(z, meta, page);
		while (free) {
			bitmap_set(bits, (uint32_t)((free - first) / zone_elem_size(z)));

			// next free element
			free = *(vm_offset_t *)free ^ zp_nopoison_cookie;
		}

		for (unsigned i = 0; first < end; i++, first += zone_elem_size(z)) {
			if (!bitmap_test(bits, i)) {
				*elems++ = INSTANCE_PUT(first);
			}
		}

		page_index = meta->zm_page_next;
	}
	return elems;
}

kern_return_t
zone_leaks(const char * zoneName, uint32_t nameLen, leak_site_proc proc, void * refCon)
{
	uintptr_t     zbt[MAX_ZTRACE_DEPTH];
	zone_t        zone = NULL;
	uintptr_t *   array;
	uintptr_t *   next;
	uintptr_t     element, bt;
	uint32_t      idx, count, found;
	uint32_t      btidx, btcount, nobtcount, btfound;
	uint32_t      elemSize;
	uint64_t      maxElems;
	kern_return_t kr;
	bitmap_t     *bits;

	zone_index_foreach(i) {
		if (!strncmp(zoneName, zone_array[i].z_name, nameLen)) {
			zone = &zone_array[i];
			break;
		}
	}
	if (zone == NULL) {
		return KERN_INVALID_NAME;
	}

	elemSize = zone_elem_size(zone);
	maxElems = (zone->countavail + 1) & ~1ul;

	if ((ptoa(zone->percpu ? 1 : zone->alloc_pages) % elemSize) &&
	    !zone_leaks_scan_enable) {
		return KERN_INVALID_CAPABILITY;
	}

	kr = kmem_alloc_kobject(kernel_map, (vm_offset_t *) &array,
	    maxElems * sizeof(uintptr_t) + BITMAP_LEN(ZONE_CHUNK_MAXELEMENTS),
	    VM_KERN_MEMORY_DIAG);
	if (KERN_SUCCESS != kr) {
		return kr;
	}

	/* maxElems is a 2-multiple so we're always aligned */
	bits = CAST_DOWN_EXPLICIT(bitmap_t *, array + maxElems);

	lock_zone(zone);

	next = array;
	next = zone_copy_allocations(zone, next, bits,
	    zone->pages_any_free_foreign, ZONE_ADDR_FOREIGN);
	next = zone_copy_allocations(zone, next, bits,
	    zone->pages_all_used_foreign, ZONE_ADDR_FOREIGN);
	next = zone_copy_allocations(zone, next, bits,
	    zone->pages_intermediate, ZONE_ADDR_NATIVE);
	next = zone_copy_allocations(zone, next, bits,
	    zone->pages_all_used, ZONE_ADDR_NATIVE);
	count = (uint32_t)(next - array);

	unlock_zone(zone);

	zone_leaks_scan(array, count, zone_elem_size(zone), &found);
	assert(found <= count);

	for (idx = 0; idx < count; idx++) {
		element = array[idx];
		if (kInstanceFlagReferenced & element) {
			continue;
		}
		element = INSTANCE_PUT(element) & ~kInstanceFlags;
	}

#if ZONE_ENABLE_LOGGING
	if (zone->zlog_btlog && !corruption_debug_flag) {
		// btlog_copy_backtraces_for_elements will set kInstanceFlagReferenced on elements it found
		btlog_copy_backtraces_for_elements(zone->zlog_btlog, array, &count, elemSize, proc, refCon);
	}
#endif /* ZONE_ENABLE_LOGGING */

	for (nobtcount = idx = 0; idx < count; idx++) {
		element = array[idx];
		if (!element) {
			continue;
		}
		if (kInstanceFlagReferenced & element) {
			continue;
		}
		element = INSTANCE_PUT(element) & ~kInstanceFlags;

		// see if we can find any backtrace left in the element
		btcount = (typeof(btcount))(zone_elem_size(zone) / sizeof(uintptr_t));
		if (btcount >= MAX_ZTRACE_DEPTH) {
			btcount = MAX_ZTRACE_DEPTH - 1;
		}
		for (btfound = btidx = 0; btidx < btcount; btidx++) {
			bt = ((uintptr_t *)element)[btcount - 1 - btidx];
			if (!VM_KERNEL_IS_SLID(bt)) {
				break;
			}
			zbt[btfound++] = bt;
		}
		if (btfound) {
			(*proc)(refCon, 1, elemSize, &zbt[0], btfound);
		} else {
			nobtcount++;
		}
	}
	if (nobtcount) {
		// fake backtrace when we found nothing
		zbt[0] = (uintptr_t) &zalloc;
		(*proc)(refCon, nobtcount, elemSize, &zbt[0], 1);
	}

	kmem_free(kernel_map, (vm_offset_t) array, maxElems * sizeof(uintptr_t));

	return KERN_SUCCESS;
}

boolean_t
run_zone_test(void)
{
	unsigned int i = 0, max_iter = 5;
	void * test_ptr;
	zone_t test_zone;

	simple_lock(&zone_test_lock, &zone_locks_grp);
	if (!zone_test_running) {
		zone_test_running = TRUE;
	} else {
		simple_unlock(&zone_test_lock);
		printf("run_zone_test: Test already running.\n");
		return FALSE;
	}
	simple_unlock(&zone_test_lock);

	printf("run_zone_test: Testing zinit(), zalloc(), zfree() and zdestroy() on zone \"test_zone_sysctl\"\n");

	/* zinit() and zdestroy() a zone with the same name a bunch of times, verify that we get back the same zone each time */
	do {
		test_zone = zinit(sizeof(uint64_t), 100 * sizeof(uint64_t), sizeof(uint64_t), "test_zone_sysctl");
		if (test_zone == NULL) {
			printf("run_zone_test: zinit() failed\n");
			return FALSE;
		}

#if KASAN_ZALLOC
		if (test_zone_ptr == NULL && test_zone->countfree != 0) {
#else
		if (test_zone->countfree != 0) {
#endif
			printf("run_zone_test: free count is not zero\n");
			return FALSE;
		}

		if (test_zone_ptr == NULL) {
			/* Stash the zone pointer returned on the fist zinit */
			printf("run_zone_test: zone created for the first time\n");
			test_zone_ptr = test_zone;
		} else if (test_zone != test_zone_ptr) {
			printf("run_zone_test: old zone pointer and new zone pointer don't match\n");
			return FALSE;
		}

		test_ptr = zalloc(test_zone);
		if (test_ptr == NULL) {
			printf("run_zone_test: zalloc() failed\n");
			return FALSE;
		}
		zfree(test_zone, test_ptr);

		zdestroy(test_zone);
		i++;

		printf("run_zone_test: Iteration %d successful\n", i);
	} while (i < max_iter);

	/* test Z_VA_SEQUESTER */
	if (zsecurity_options & ZSECURITY_OPTIONS_SEQUESTER) {
		int idx, num_allocs = 8;
		vm_size_t elem_size = 2 * PAGE_SIZE / num_allocs;
		void *allocs[num_allocs];
		vm_offset_t phys_pages = os_atomic_load(&zones_phys_page_count, relaxed);
		vm_size_t zone_map_size = zone_range_size(&zone_info.zi_map_range);

		test_zone = zone_create("test_zone_sysctl", elem_size,
		    ZC_DESTRUCTIBLE | ZC_SEQUESTER);
		if (test_zone == NULL) {
			printf("run_zone_test: zinit() failed\n");
			return FALSE;
		}

		for (idx = 0; idx < num_allocs; idx++) {
			allocs[idx] = zalloc(test_zone);
			assert(NULL != allocs[idx]);
			printf("alloc[%d] %p\n", idx, allocs[idx]);
		}
		for (idx = 0; idx < num_allocs; idx++) {
			zfree(test_zone, allocs[idx]);
		}
		assert(!zone_pva_is_null(test_zone->pages_all_free));

		printf("vm_page_wire_count %d, vm_page_free_count %d, p to v %qd%%\n",
		    vm_page_wire_count, vm_page_free_count,
		    (100ULL * ptoa_64(phys_pages)) / zone_map_size);
		zone_gc(FALSE);
		printf("vm_page_wire_count %d, vm_page_free_count %d, p to v %qd%%\n",
		    vm_page_wire_count, vm_page_free_count,
		    (100ULL * ptoa_64(phys_pages)) / zone_map_size);
		unsigned int allva = 0;
		zone_index_foreach(zidx) {
			zone_t z = &zone_array[zidx];
			lock_zone(z);
			allva += z->page_count;
			if (!z->sequester_page_count) {
				unlock_zone(z);
				continue;
			}
			unsigned count = 0;
			uint64_t size;
			zone_pva_t pg = z->pages_sequester;
			struct zone_page_metadata *page_meta;
			while (pg.packed_address) {
				page_meta = zone_pva_to_meta(pg, ZONE_ADDR_NATIVE);
				count += z->alloc_pages;
				pg = page_meta->zm_page_next;
			}
			assert(count == z->sequester_page_count);
			size = zone_size_wired(z);
			if (!size) {
				size = 1;
			}
			printf("%s%s: seq %d, res %d, %qd %%\n",
			    zone_heap_name(z), z->z_name, z->sequester_page_count,
			    z->page_count, zone_size_allocated(z) * 100ULL / size);
			unlock_zone(z);
		}

		printf("total va: %d\n", allva);

		assert(zone_pva_is_null(test_zone->pages_all_free));
		assert(!zone_pva_is_null(test_zone->pages_sequester));
		assert(2 == test_zone->sequester_page_count);
		for (idx = 0; idx < num_allocs; idx++) {
			assert(0 == pmap_find_phys(kernel_pmap, (addr64_t)(uintptr_t) allocs[idx]));
		}
		for (idx = 0; idx < num_allocs; idx++) {
			allocs[idx] = zalloc(test_zone);
			assert(allocs[idx]);
			printf("alloc[%d] %p\n", idx, allocs[idx]);
		}
		assert(zone_pva_is_null(test_zone->pages_sequester));
		assert(0 == test_zone->sequester_page_count);
		for (idx = 0; idx < num_allocs; idx++) {
			zfree(test_zone, allocs[idx]);
		}
		zdestroy(test_zone);
	} else {
		printf("run_zone_test: skipping sequester test (not enabled)\n");
	}

	printf("run_zone_test: Test passed\n");

	simple_lock(&zone_test_lock, &zone_locks_grp);
	zone_test_running = FALSE;
	simple_unlock(&zone_test_lock);

	return TRUE;
}

/*
 * Routines to test that zone garbage collection and zone replenish threads
 * running at the same time don't cause problems.
 */

void
zone_gc_replenish_test(void)
{
	zone_gc(FALSE);
}


void
zone_alloc_replenish_test(void)
{
	zone_t z = NULL;
	struct data { struct data *next; } *node, *list = NULL;

	/*
	 * Find a zone that has a replenish thread
	 */
	zone_index_foreach(i) {
		z = &zone_array[i];
		if (z->prio_refill_count &&
		    zone_elem_size(z) >= sizeof(struct data)) {
			z = &zone_array[i];
			break;
		}
	}
	if (z == NULL) {
		printf("Couldn't find a replenish zone\n");
		return;
	}

	for (uint32_t i = 0; i < 2000; ++i) {      /* something big enough to go past replenishment */
		node = zalloc(z);
		node->next = list;
		list = node;
	}

	/*
	 * release the memory we allocated
	 */
	while (list != NULL) {
		node = list;
		list = list->next;
		zfree(z, node);
	}
}

#endif /* DEBUG || DEVELOPMENT */
