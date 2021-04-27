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
#if !ZALLOC_TEST
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
#include <vm/vm_pageout.h>
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
/*
 * Set to 0 to debug poisoning and ZC_ZFREE_CLEARMEM validation under kasan.
 * Otherwise they are double-duty with what kasan already does.
 */
#define ZALLOC_ENABLE_POISONING 0
#define ZONE_ENABLE_LOGGING 0
#elif DEBUG || DEVELOPMENT
#define ZALLOC_ENABLE_POISONING 1
#define ZONE_ENABLE_LOGGING 1
#else
#define ZALLOC_ENABLE_POISONING 1
#define ZONE_ENABLE_LOGGING 0
#endif

#if __LP64__
#define ZALLOC_EARLY_GAPS 1
#else
#define ZALLOC_EARLY_GAPS 0
#endif

#if DEBUG
#define z_debug_assert(expr)  assert(expr)
#else
#define z_debug_assert(expr)  (void)(expr)
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

#define ZONE_MIN_ELEM_SIZE      sizeof(uint64_t)
#define ZONE_MAX_ALLOC_SIZE     (32 * 1024)

struct zone_page_metadata {
	/* The index of the zone this metadata page belongs to */
	zone_id_t       zm_index : 11;

	/* Whether `zm_bitmap` is an inline bitmap or a packed bitmap reference */
	uint16_t        zm_inline_bitmap : 1;

	/*
	 * Zones allocate in "chunks" of zone_t::z_chunk_pages consecutive
	 * pages, or zpercpu_count() pages if the zone is percpu.
	 *
	 * The first page of it has its metadata set with:
	 * - 0 if none of the pages are currently wired
	 * - the number of wired pages in the chunk (not scaled for percpu).
	 *
	 * Other pages in the chunk have their zm_chunk_len set to
	 * ZM_SECONDARY_PAGE or ZM_SECONDARY_PCPU_PAGE depending on whether
	 * the zone is percpu or not. For those, zm_page_index holds the
	 * index of that page in the run.
	 */
	uint16_t        zm_chunk_len : 4;
#define ZM_CHUNK_LEN_MAX        0x8
#define ZM_SECONDARY_PAGE       0xe
#define ZM_SECONDARY_PCPU_PAGE  0xf

	union {
#define ZM_ALLOC_SIZE_LOCK      1u
		uint16_t zm_alloc_size; /* first page only */
		uint16_t zm_page_index; /* secondary pages only */
	};
	union {
		uint32_t zm_bitmap;     /* most zones */
		uint32_t zm_bump;       /* permanent zones */
	};

	zone_pva_t      zm_page_next;
	zone_pva_t      zm_page_prev;
};
static_assert(sizeof(struct zone_page_metadata) == 16, "validate packing");

__enum_closed_decl(zone_addr_kind_t, bool, {
	ZONE_ADDR_FOREIGN,
	ZONE_ADDR_NATIVE,
});
#define ZONE_ADDR_KIND_COUNT 2

/*!
 * @typedef zone_element_t
 *
 * @brief
 * Type that represents a "resolved" zone element.
 *
 * @description
 * This type encodes an element pointer as a tuple of:
 * { chunk base, element index, element protection }.
 *
 * The chunk base is extracted with @c trunc_page()
 * as it is always page aligned, and occupies the bits above @c PAGE_SHIFT.
 *
 * The low two bits encode the protection mode (see @c zprot_mode_t).
 *
 * The other bits encode the element index in the chunk rather than its address.
 */
typedef struct zone_element {
	vm_offset_t                 ze_value;
} zone_element_t;

/*!
 * @typedef zone_magazine_t
 *
 * @brief
 * Magazine of cached allocations.
 *
 * @field zm_cur        how many elements this magazine holds (unused while loaded).
 * @field zm_link       linkage used by magazine depots.
 * @field zm_elems      an array of @c zc_mag_size() elements.
 */
typedef struct zone_magazine {
	uint16_t                    zm_cur;
	STAILQ_ENTRY(zone_magazine) zm_link;
	zone_element_t              zm_elems[0];
} *zone_magazine_t;

/*!
 * @typedef zone_cache_t
 *
 * @brief
 * Magazine of cached allocations.
 *
 * @discussion
 * Below is a diagram of the caching system. This design is inspired by the
 * paper "Magazines and Vmem: Extending the Slab Allocator to Many CPUs and
 * Arbitrary Resources" by Jeff Bonwick and Jonathan Adams and the FreeBSD UMA
 * zone allocator (itself derived from this seminal work).
 *
 * It is divided into 3 layers:
 * - the per-cpu layer,
 * - the recirculation depot layer,
 * - the Zone Allocator.
 *
 * The per-cpu and recirculation depot layer use magazines (@c zone_magazine_t),
 * which are stacks of up to @c zc_mag_size() elements.
 *
 * <h2>CPU layer</h2>
 *
 * The CPU layer (@c zone_cache_t) looks like this:
 *
 *      ╭─ a ─ f ─┬───────── zm_depot ──────────╮
 *      │ ╭─╮ ╭─╮ │ ╭─╮ ╭─╮ ╭─╮ ╭─╮ ╭─╮         │
 *      │ │#│ │#│ │ │#│ │#│ │#│ │#│ │#│         │
 *      │ │#│ │ │ │ │#│ │#│ │#│ │#│ │#│         │
 *      │ │ │ │ │ │ │#│ │#│ │#│ │#│ │#│         │
 *      │ ╰─╯ ╰─╯ │ ╰─╯ ╰─╯ ╰─╯ ╰─╯ ╰─╯         │
 *      ╰─────────┴─────────────────────────────╯
 *
 * It has two pre-loaded magazines (a)lloc and (f)ree which we allocate from,
 * or free to. Serialization is achieved through disabling preemption, and only
 * the current CPU can acces those allocations. This is represented on the left
 * hand side of the diagram above.
 *
 * The right hand side is the per-cpu depot. It consists of @c zm_depot_count
 * full magazines, and is protected by the @c zm_depot_lock for access.
 * The lock is expected to absolutely never be contended, as only the local CPU
 * tends to access the local per-cpu depot in regular operation mode.
 *
 * However unlike UMA, our implementation allows for the zone GC to reclaim
 * per-CPU magazines aggresively, which is serialized with the @c zm_depot_lock.
 *
 *
 * <h2>Recirculation Depot</h2>
 *
 * The recirculation depot layer is a list similar to the per-cpu depot,
 * however it is different in two fundamental ways:
 *
 * - it is protected by the regular zone lock,
 * - elements referenced by the magazines in that layer appear free
 *   to the zone layer.
 *
 *
 * <h2>Magazine circulation and sizing</h2>
 *
 * The caching system sizes itself dynamically. Operations that allocate/free
 * a single element call @c zone_lock_nopreempt_check_contention() which records
 * contention on the lock by doing a trylock and recording its success.
 *
 * This information is stored in the @c z_contention_cur field of the zone,
 * and a windoed moving average is maintained in @c z_contention_wma.
 * Each time a CPU registers any contention, it will also allow its own per-cpu
 * cache to grow, incrementing @c zc_depot_max, which is how the per-cpu layer
 * might grow into using its local depot.
 *
 * Note that @c zc_depot_max assume that the (a) and (f) pre-loaded magazines
 * on average contain @c zc_mag_size() elements.
 *
 * When a per-cpu layer cannot hold more full magazines in its depot,
 * then it will overflow about 1/3 of its depot into the recirculation depot
 * (see @c zfree_cached_slow().  Conversely, when a depot is empty, then it will
 * refill its per-cpu depot to about 1/3 of its size from the recirculation
 * depot (see @c zalloc_cached_slow()).
 *
 * Lastly, the zone layer keeps track of the high and low watermark of how many
 * elements have been free per period of time (including being part of the
 * recirculation depot) in the @c z_elems_free_min and @c z_elems_free_max
 * fields. A weighted moving average of the amplitude of this is maintained in
 * the @c z_elems_free_wss which informs the zone GC on how to gently trim
 * zones without hurting performance.
 *
 *
 * <h2>Security considerations</h2>
 *
 * The zone caching layer has been designed to avoid returning elements in
 * a strict LIFO behavior: @c zalloc() will allocate from the (a) magazine,
 * and @c zfree() free to the (f) magazine, and only swap them when the
 * requested operation cannot be fulfilled.
 *
 * The per-cpu overflow depot or the recirculation depots are similarly used
 * in FIFO order.
 *
 * More importantly, when magazines flow through the recirculation depot,
 * the elements they contain are marked as "free" in the zone layer bitmaps.
 * Because allocations out of per-cpu caches verify the bitmaps at allocation
 * time, this acts as a poor man's double-free quarantine. The magazines
 * allow to avoid the cost of the bit-scanning involved in the zone-level
 * @c zalloc_item() codepath.
 *
 *
 * @field zc_alloc_cur      denormalized number of elements in the (a) magazine
 * @field zc_free_cur       denormalized number of elements in the (f) magazine
 * @field zc_alloc_elems    a pointer to the array of elements in (a)
 * @field zc_free_elems     a pointer to the array of elements in (f)
 *
 * @field zc_depot_lock     a lock to access @c zc_depot, @c zc_depot_cur.
 * @field zc_depot          a list of @c zc_depot_cur full magazines
 * @field zc_depot_cur      number of magazines in @c zc_depot
 * @field zc_depot_max      the maximum number of elements in @c zc_depot,
 *                          protected by the zone lock.
 */
typedef struct zone_cache {
	uint16_t                   zc_alloc_cur;
	uint16_t                   zc_free_cur;
	uint16_t                   zc_depot_cur;
	uint16_t                   __zc_padding;
	zone_element_t            *zc_alloc_elems;
	zone_element_t            *zc_free_elems;
	hw_lock_bit_t              zc_depot_lock;
	uint32_t                   zc_depot_max;
	struct zone_depot          zc_depot;
} *zone_cache_t;

static __security_const_late struct {
	struct zone_map_range      zi_map_range[ZONE_ADDR_KIND_COUNT];
	struct zone_map_range      zi_meta_range; /* debugging only */
	struct zone_map_range      zi_bits_range; /* bits buddy allocator */

	/*
	 * The metadata lives within the zi_meta_range address range.
	 *
	 * The correct formula to find a metadata index is:
	 *     absolute_page_index - page_index(MIN(zi_map_range[*].min_address))
	 *
	 * And then this index is used to dereference zi_meta_range.min_address
	 * as a `struct zone_page_metadata` array.
	 *
	 * To avoid doing that substraction all the time in the various fast-paths,
	 * zi_meta_base are pre-offset with that minimum page index to avoid redoing
	 * that math all the time.
	 *
	 * Do note that the array might have a hole punched in the middle,
	 * see zone_metadata_init().
	 */
	struct zone_page_metadata *zi_meta_base;
} zone_info;

/*
 * Initial array of metadata for stolen memory.
 *
 * The numbers here have to be kept in sync with vm_map_steal_memory()
 * so that we have reserved enough metadata.
 *
 * After zone_init() has run (which happens while the kernel is still single
 * threaded), the metadata is moved to its final dynamic location, and
 * this array is unmapped with the rest of __startup_data at lockdown.
 */
#if CONFIG_GZALLOC
#define ZONE_FOREIGN_META_INLINE_COUNT    20032
#else
#define ZONE_FOREIGN_META_INLINE_COUNT    64
#endif
__startup_data
static struct zone_page_metadata
    zone_foreign_meta_array_startup[ZONE_FOREIGN_META_INLINE_COUNT];

/*
 *	The zone_locks_grp allows for collecting lock statistics.
 *	All locks are associated to this group in zinit.
 *	Look at tools/lockstat for debugging lock contention.
 */
static LCK_GRP_DECLARE(zone_locks_grp, "zone_locks");
static LCK_MTX_EARLY_DECLARE(zone_metadata_region_lck, &zone_locks_grp);

/*
 *	Exclude more than one concurrent garbage collection
 */
static LCK_GRP_DECLARE(zone_gc_lck_grp, "zone_gc");
static LCK_MTX_EARLY_DECLARE(zone_gc_lock, &zone_gc_lck_grp);

bool panic_include_zprint = FALSE;
mach_memory_info_t *panic_kext_memory_info = NULL;
vm_size_t panic_kext_memory_size = 0;

/*
 *      Protects zone_array, num_zones, num_zones_in_use, and
 *      zone_destroyed_bitmap
 */
static SIMPLE_LOCK_DECLARE(all_zones_lock, 0);
static zone_id_t        num_zones_in_use;
zone_id_t _Atomic       num_zones;
SECURITY_READ_ONLY_LATE(unsigned int) zone_view_count;

#if KASAN_ZALLOC
#define MAX_ZONES       566
#else /* !KASAN_ZALLOC */
#define MAX_ZONES       402
#endif/* !KASAN_ZALLOC */

/*
 * Initial globals for zone stats until we can allocate the real ones.
 * Those get migrated inside the per-CPU ones during zone_init() and
 * this array is unmapped with the rest of __startup_data at lockdown.
 */

/* zone to allocate zone_magazine structs from */
static SECURITY_READ_ONLY_LATE(zone_t) zc_magazine_zone;
/*
 * Until pid1 is made, zone caching is off,
 * until compute_zone_working_set_size() runs for the firt time.
 *
 * -1 represents the "never enabled yet" value.
 */
static int8_t zone_caching_disabled = -1;

__startup_data
static struct zone_cache zone_cache_startup[MAX_ZONES];
__startup_data
static struct zone_stats zone_stats_startup[MAX_ZONES];
struct zone              zone_array[MAX_ZONES];

/* Initialized in zone_bootstrap(), how many "copies" the per-cpu system does */
static SECURITY_READ_ONLY_LATE(unsigned) zpercpu_early_count;

/* Used to keep track of destroyed slots in the zone_array */
static bitmap_t zone_destroyed_bitmap[BITMAP_LEN(MAX_ZONES)];

/* number of zone mapped pages used by all zones */
static long _Atomic zones_phys_page_mapped_count;

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
	        ZSECURITY_OPTIONS_SEQUESTER | \
	        ZSECURITY_OPTIONS_SUBMAP_USER_DATA | \
	        ZSECURITY_OPTIONS_SEQUESTER_KEXT_KALLOC | \
	        ZSECURITY_OPTIONS_STRICT_IOKIT_FREE_DEFAULT | \
	        0)
TUNABLE(zone_security_options_t, zsecurity_options, "zs", ZSECURITY_DEFAULT);

#if VM_MAX_TAG_ZONES
/* enable tags for zones that ask for it */
static TUNABLE(bool, zone_tagging_on, "-zt", false);
#endif /* VM_MAX_TAG_ZONES */

#if DEBUG || DEVELOPMENT
TUNABLE(bool, zalloc_disable_copyio_check, "-no-copyio-zalloc-check", false);
#endif /* DEBUG || DEVELOPMENT */
#if CONFIG_ZLEAKS
/* Making pointer scanning leaks detection possible for all zones */
static TUNABLE(bool, zone_leaks_scan_enable, "-zl", false);
#else
#define zone_leaks_scan_enable false
#endif

/*! @enum zprot_mode_t
 *
 * @brief
 * Zone element corruption detection mode.
 *
 * @discussion
 * We use four techniques to detect modification of a zone element
 * after it's been freed.
 *
 * Elements that are in zones can be in 3 possible states:
 * - zeroed out (@c ZPM_ZERO)
 * - poisoned (@c ZPM_POISON) with the @c ZONE_POISON pattern
 * - with a left and right canary (@c ZPM_CANARY).
 *
 * @c ZPM_AUTO is used when the actual protection for the element is unknown,
 * and will be detected looking at the last word of the allocation at validation
 * time.
 *
 * The mode of an element in zones is discovered by looking at its last
 * pointer-sized value:
 * - 0 means that it is zeroed out
 * - @c ZONE_POISON means it is poisoned
 * - any other value means it is using canaries.
 *
 * Elements are zeroed if:
 * - the element size is smaller than @c zp_min_size,
 * - the owning zone has the @c z_free_zeroes flag set,
 * - the chunk backing store is fresh (and was just allocated).
 *
 * Elements are poisoned periodically for every N frees (counted per-zone),
 * if the elements aren't otherwise zeroed out.
 * If -zp is passed as a boot arg, poisoning occurs for every free.
 *
 * Else elements use canaries. When canaries are used, the first and last
 * pointer sized values in the allocation are set to values derived from the
 * element address and the @c zp_canary nonce. The first @c zp_min_size
 * bytes of the elment are also cleared.
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
 */
__enum_closed_decl(zprot_mode_t, vm_offset_t, {
	ZPM_AUTO,       /* element is indeterminate          */
	ZPM_ZERO,       /* element is zeroed                 */
	ZPM_POISON,     /* element is poisoned               */
	ZPM_CANARY,     /* element extremities have a canary */
});
#define ZPM_MASK ((zprot_mode_t)0x3)


/*
 * set by zp-factor=N boot arg
 *
 * A zp_factor of 0 indicates zone poisoning is disabled and can also be set by
 * passing the -no-zp boot-arg.
 *
 * A zp_factor of 1 indicates zone poisoning is on for all elements and can be
 * set by passing the -zp boot-arg.
 */
static TUNABLE(uint32_t, zp_factor, "zp-factor", 16);

/* set by zp-scale=N boot arg, scales zp_factor by zone size */
static TUNABLE(uint32_t, zp_scale, "zp-scale", 4);

/*
 * Zone caching tunables
 *
 * zc_mag_size():
 *   size of magazines, larger to reduce contention at the expense of memory
 *
 * zc_auto_enable_threshold
 *   number of contentions per second after which zone caching engages
 *   automatically.
 *
 *   0 to disable.
 *
 * zc_grow_threshold
 *   numer of contentions per second after which the per-cpu depot layer
 *   grows at each newly observed contention without restriction.
 *
 *   0 to disable.
 *
 * zc_recirc_denom
 *   denominator of the fraction of per-cpu depot to migrate to/from
 *   the recirculation depot layer at a time. Default 3 (1/3).
 *
 * zc_defrag_ratio
 *   percentage of the working set to recirc size below which
 *   the zone is defragmented. Default is 50%.
 *
 * zc_free_batch_size
 *   The size of batches of frees/reclaim that can be done keeping
 *   the zone lock held (and preemption disabled).
 */
static TUNABLE(uint16_t, zc_magazine_size, "zc_mag_size()", 8);
static TUNABLE(uint32_t, zc_auto_threshold, "zc_auto_enable_threshold", 20);
static TUNABLE(uint32_t, zc_grow_threshold, "zc_grow_threshold", 8);
static TUNABLE(uint32_t, zc_recirc_denom, "zc_recirc_denom", 3);
static TUNABLE(uint32_t, zc_defrag_ratio, "zc_defrag_ratio", 50);
static TUNABLE(uint32_t, zc_free_batch_size, "zc_free_batch_size", 1024);

static SECURITY_READ_ONLY_LATE(uintptr_t) zp_canary;
/*
 * Perf results for zeroing all non data zones and 2K of data zones
 * showed little regression, therefore setting zp_min_size to 2048
 */
static TUNABLE(uint32_t, zp_min_size, "zclear_size", 2048);
static SECURITY_READ_ONLY_LATE(uint32_t)  zone_phys_mapped_max_pages;
static SECURITY_READ_ONLY_LATE(vm_map_t)  zone_submaps[Z_SUBMAP_IDX_COUNT];
static SECURITY_READ_ONLY_LATE(uint32_t)  zone_last_submap_idx;

static zone_t zone_find_largest(void);

#endif /* !ZALLOC_TEST */
#pragma mark Zone metadata
#if !ZALLOC_TEST

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

static zone_element_t
zone_element_encode(vm_offset_t base, vm_offset_t eidx, zprot_mode_t zpm)
{
	return (zone_element_t){ .ze_value = base | (eidx << 2) | zpm };
}

static vm_offset_t
zone_element_base(zone_element_t ze)
{
	return trunc_page(ze.ze_value);
}

static vm_offset_t
zone_element_idx(zone_element_t ze)
{
	return (ze.ze_value & PAGE_MASK) >> 2;
}

#if ZALLOC_ENABLE_POISONING
static zprot_mode_t
zone_element_prot(zone_element_t ze)
{
	return (zprot_mode_t)(ze.ze_value & ZPM_MASK);
}
#endif

static vm_offset_t
zone_element_addr(zone_element_t ze, vm_offset_t esize)
{
	return zone_element_base(ze) + esize * zone_element_idx(ze);
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
zone_invalid_element_panic(zone_t zone, zone_element_t ze)
{
	panic("zone element pointer validation failed (elem: %p,%d, zone %s%s)",
	    (void *)zone_element_base(ze), (int)zone_element_idx(ze),
	    zone_heap_name(zone), zone->z_name);
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
zone_meta_double_free_panic(zone_t zone, zone_element_t ze, const char *caller)
{
	panic("%s: double free of %p to zone %s%s", caller,
	    (void *)zone_element_addr(ze, zone_elem_size(zone)),
	    zone_heap_name(zone), zone->z_name);
}

__abortlike
static void
zone_accounting_panic(zone_t zone, const char *kind)
{
	panic("accounting mismatch (%s) for zone %s%s", kind,
	    zone_heap_name(zone), zone->z_name);
}

#define zone_counter_sub(z, stat, value)  ({ \
	if (os_sub_overflow((z)->stat, value, &(z)->stat)) { \
	    zone_accounting_panic(z, #stat " wrap-around"); \
	} \
	(z)->stat; \
})

static inline void
zone_elems_free_add(zone_t z, uint32_t count)
{
	uint32_t n = (z->z_elems_free += count);
	if (z->z_elems_free_max < n) {
		z->z_elems_free_max = n;
	}
}

static inline void
zone_elems_free_sub(zone_t z, uint32_t count)
{
	uint32_t n = zone_counter_sub(z, z_elems_free, count);

	if (z->z_elems_free_min > n) {
		z->z_elems_free_min = n;
	}
}

static inline uint16_t
zone_meta_alloc_size_add(zone_t z, struct zone_page_metadata *m,
    vm_offset_t esize)
{
	if (os_add_overflow(m->zm_alloc_size, (uint16_t)esize, &m->zm_alloc_size)) {
		zone_page_meta_accounting_panic(z, m, "alloc_size wrap-around");
	}
	return m->zm_alloc_size;
}

static inline uint16_t
zone_meta_alloc_size_sub(zone_t z, struct zone_page_metadata *m,
    vm_offset_t esize)
{
	if (os_sub_overflow(m->zm_alloc_size, esize, &m->zm_alloc_size)) {
		zone_page_meta_accounting_panic(z, m, "alloc_size wrap-around");
	}
	return m->zm_alloc_size;
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

#define from_zone_map(addr, size, kind) \
	zone_range_contains(&zone_info.zi_map_range[kind], \
	    (vm_offset_t)(addr), size)

#define zone_native_size() \
	zone_range_size(&zone_info.zi_map_range[ZONE_ADDR_NATIVE])

#define zone_foreign_size() \
	zone_range_size(&zone_info.zi_map_range[ZONE_ADDR_FOREIGN])

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

__header_always_inline zone_pva_t
zone_pva_from_element(zone_element_t ze)
{
	return zone_pva_from_addr(ze.ze_value);
}

__header_always_inline vm_address_t
zone_pva_to_addr(zone_pva_t page)
{
	// cause sign extension so that we end up with the right address
	return (vm_offset_t)(int32_t)page.packed_address << PAGE_SHIFT;
}

__header_always_inline struct zone_page_metadata *
zone_pva_to_meta(zone_pva_t page)
{
	return &zone_info.zi_meta_base[page.packed_address];
}

__header_always_inline zone_pva_t
zone_pva_from_meta(struct zone_page_metadata *meta)
{
	return (zone_pva_t){ (uint32_t)(meta - zone_info.zi_meta_base) };
}

__header_always_inline struct zone_page_metadata *
zone_meta_from_addr(vm_offset_t addr)
{
	return zone_pva_to_meta(zone_pva_from_addr(addr));
}

__header_always_inline struct zone_page_metadata *
zone_meta_from_element(zone_element_t ze)
{
	return zone_pva_to_meta(zone_pva_from_element(ze));
}

__header_always_inline zone_id_t
zone_index_from_ptr(const void *ptr)
{
	return zone_pva_to_meta(zone_pva_from_addr((vm_offset_t)ptr))->zm_index;
}

__header_always_inline vm_offset_t
zone_meta_to_addr(struct zone_page_metadata *meta)
{
	return ptoa((int32_t)(meta - zone_info.zi_meta_base));
}

__header_always_inline void
zone_meta_queue_push(zone_t z, zone_pva_t *headp,
    struct zone_page_metadata *meta)
{
	zone_pva_t head = *headp;
	zone_pva_t queue_pva = zone_queue_encode(headp);
	struct zone_page_metadata *tmp;

	meta->zm_page_next = head;
	if (!zone_pva_is_null(head)) {
		tmp = zone_pva_to_meta(head);
		if (!zone_pva_is_equal(tmp->zm_page_prev, queue_pva)) {
			zone_page_metadata_list_corruption(z, meta);
		}
		tmp->zm_page_prev = zone_pva_from_meta(meta);
	}
	meta->zm_page_prev = queue_pva;
	*headp = zone_pva_from_meta(meta);
}

__header_always_inline struct zone_page_metadata *
zone_meta_queue_pop_native(zone_t z, zone_pva_t *headp, vm_offset_t *page_addrp)
{
	zone_pva_t head = *headp;
	struct zone_page_metadata *meta = zone_pva_to_meta(head);
	vm_offset_t page_addr = zone_pva_to_addr(head);
	struct zone_page_metadata *tmp;

	if (!from_zone_map(page_addr, 1, ZONE_ADDR_NATIVE)) {
		zone_page_metadata_native_queue_corruption(z, headp);
	}

	if (!zone_pva_is_null(meta->zm_page_next)) {
		tmp = zone_pva_to_meta(meta->zm_page_next);
		if (!zone_pva_is_equal(tmp->zm_page_prev, head)) {
			zone_page_metadata_list_corruption(z, meta);
		}
		tmp->zm_page_prev = meta->zm_page_prev;
	}
	*headp = meta->zm_page_next;

	meta->zm_page_next = meta->zm_page_prev = (zone_pva_t){ 0 };
	*page_addrp = page_addr;

	if (!zone_has_index(z, meta->zm_index)) {
		zone_page_metadata_index_confusion_panic(z,
		    zone_meta_to_addr(meta), meta);
	}
	return meta;
}

__header_always_inline void
zone_meta_remqueue(zone_t z, struct zone_page_metadata *meta)
{
	zone_pva_t meta_pva = zone_pva_from_meta(meta);
	struct zone_page_metadata *tmp;

	if (!zone_pva_is_null(meta->zm_page_next)) {
		tmp = zone_pva_to_meta(meta->zm_page_next);
		if (!zone_pva_is_equal(tmp->zm_page_prev, meta_pva)) {
			zone_page_metadata_list_corruption(z, meta);
		}
		tmp->zm_page_prev = meta->zm_page_prev;
	}
	if (zone_pva_is_queue(meta->zm_page_prev)) {
		zone_queue_set_head(z, meta->zm_page_prev, meta_pva, meta);
	} else {
		tmp = zone_pva_to_meta(meta->zm_page_prev);
		if (!zone_pva_is_equal(tmp->zm_page_next, meta_pva)) {
			zone_page_metadata_list_corruption(z, meta);
		}
		tmp->zm_page_next = meta->zm_page_next;
	}

	meta->zm_page_next = meta->zm_page_prev = (zone_pva_t){ 0 };
}

__header_always_inline void
zone_meta_requeue(zone_t z, zone_pva_t *headp,
    struct zone_page_metadata *meta)
{
	zone_meta_remqueue(z, meta);
	zone_meta_queue_push(z, headp, meta);
}

/* prevents a given metadata from ever reaching the z_pageq_empty queue */
static inline void
zone_meta_lock_in_partial(zone_t z, struct zone_page_metadata *m, uint32_t len)
{
	uint16_t new_size = zone_meta_alloc_size_add(z, m, ZM_ALLOC_SIZE_LOCK);

	assert(new_size % sizeof(vm_offset_t) == ZM_ALLOC_SIZE_LOCK);
	if (new_size == ZM_ALLOC_SIZE_LOCK) {
		zone_meta_requeue(z, &z->z_pageq_partial, m);
		zone_counter_sub(z, z_wired_empty, len);
	}
}

/* allows a given metadata to reach the z_pageq_empty queue again */
static inline void
zone_meta_unlock_from_partial(zone_t z, struct zone_page_metadata *m, uint32_t len)
{
	uint16_t new_size = zone_meta_alloc_size_sub(z, m, ZM_ALLOC_SIZE_LOCK);

	assert(new_size % sizeof(vm_offset_t) == 0);
	if (new_size == 0) {
		zone_meta_requeue(z, &z->z_pageq_empty, m);
		z->z_wired_empty += len;
	}
}

/*
 * Routine to populate a page backing metadata in the zone_metadata_region.
 * Must be called without the zone lock held as it might potentially block.
 */
static void
zone_meta_populate(vm_offset_t base, vm_size_t size)
{
	struct zone_page_metadata *from = zone_meta_from_addr(base);
	struct zone_page_metadata *to   = from + atop(size);
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

__header_always_inline
struct zone_page_metadata *
zone_element_validate(zone_t zone, zone_element_t ze)
{
	struct zone_page_metadata *meta;
	vm_offset_t page = zone_element_base(ze);

	if (!from_zone_map(page, 1, ZONE_ADDR_NATIVE) &&
	    !from_zone_map(page, 1, ZONE_ADDR_FOREIGN)) {
		zone_invalid_element_panic(zone, ze);
	}
	meta = zone_meta_from_addr(page);

	if (meta->zm_chunk_len > ZM_CHUNK_LEN_MAX) {
		zone_invalid_element_panic(zone, ze);
	}
	if (zone_element_idx(ze) >= zone->z_chunk_elems) {
		zone_invalid_element_panic(zone, ze);
	}

	if (!zone_has_index(zone, meta->zm_index)) {
		vm_offset_t addr = zone_element_addr(ze, zone_elem_size(zone));
		zone_page_metadata_index_confusion_panic(zone, addr, meta);
	}

	return meta;
}

__attribute__((always_inline))
static struct zone_page_metadata *
zone_element_resolve(zone_t zone, vm_offset_t addr, vm_offset_t esize,
    zone_element_t *ze)
{
	struct zone_page_metadata *meta;
	vm_offset_t page, eidx;

	if (!from_zone_map(addr, esize, ZONE_ADDR_NATIVE) &&
	    !from_zone_map(addr, esize, ZONE_ADDR_FOREIGN)) {
		zone_invalid_element_addr_panic(zone, addr);
	}
	page = trunc_page(addr);
	meta = zone_meta_from_addr(addr);

	if (meta->zm_chunk_len == ZM_SECONDARY_PCPU_PAGE) {
		zone_invalid_element_addr_panic(zone, addr);
	}
	if (meta->zm_chunk_len == ZM_SECONDARY_PAGE) {
		page -= ptoa(meta->zm_page_index);
		meta -= meta->zm_page_index;
	}

	eidx = (addr - page) / esize;
	if ((addr - page) % esize) {
		zone_invalid_element_addr_panic(zone, addr);
	}

	if (!zone_has_index(zone, meta->zm_index)) {
		zone_page_metadata_index_confusion_panic(zone, addr, meta);
	}

	*ze = zone_element_encode(page, eidx, ZPM_AUTO);
	return meta;
}

/* Routine to get the size of a zone allocated address.
 * If the address doesnt belong to the zone maps, returns 0.
 */
vm_size_t
zone_element_size(void *addr, zone_t *z)
{
	struct zone *src_zone;

	if (from_zone_map(addr, sizeof(void *), ZONE_ADDR_NATIVE) ||
	    from_zone_map(addr, sizeof(void *), ZONE_ADDR_FOREIGN)) {
		src_zone = &zone_array[zone_index_from_ptr(addr)];
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

	if (!from_zone_map(addr, zone_elem_size(zone), ZONE_ADDR_NATIVE)) {
		panic("zone_require failed: address not in a zone (addr: %p)", addr);
	}

	zindex = zone_index_from_ptr(addr);
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
	vm_size_t esize = zone_elem_size(zone);

	if (__probable(from_zone_map(addr, esize, ZONE_ADDR_NATIVE))) {
		if (zone_has_index(zone, zone_index_from_ptr(addr))) {
			return;
		}
#if CONFIG_GZALLOC
	} else if (__probable(zone->gzalloc_tracked)) {
		return;
#endif
	}
	zone_require_panic(zone, addr);
}

void
zone_id_require(zone_id_t zid, vm_size_t esize, void *addr)
{
	if (__probable(from_zone_map(addr, esize, ZONE_ADDR_NATIVE))) {
		if (zid == zone_index_from_ptr(addr)) {
			return;
		}
#if CONFIG_GZALLOC
	} else if (__probable(zone_array[zid].gzalloc_tracked)) {
		return;
#endif
	}
	zone_id_require_panic(zid, addr);
}

void
zone_id_require_allow_foreign(zone_id_t zid, vm_size_t esize, void *addr)
{
	if (__probable(from_zone_map(addr, esize, ZONE_ADDR_NATIVE) ||
	    from_zone_map(addr, esize, ZONE_ADDR_FOREIGN))) {
		if (zid == zone_index_from_ptr(addr)) {
			return;
		}
#if CONFIG_GZALLOC
	} else if (__probable(zone_array[zid].gzalloc_tracked)) {
		return;
#endif
	}
	zone_id_require_panic(zid, addr);
}

bool
zone_owns(zone_t zone, void *addr)
{
	vm_size_t esize = zone_elem_size(zone);

	if (__probable(from_zone_map(addr, esize, ZONE_ADDR_NATIVE))) {
		return zone_has_index(zone, zone_index_from_ptr(addr));
#if CONFIG_GZALLOC
	} else if (__probable(zone->gzalloc_tracked)) {
		return true;
#endif
	}
	return false;
}

#endif /* !ZALLOC_TEST */
#pragma mark Zone bits allocator

/*!
 * @defgroup Zone Bitmap allocator
 * @{
 *
 * @brief
 * Functions implementing the zone bitmap allocator
 *
 * @discussion
 * The zone allocator maintains which elements are allocated or free in bitmaps.
 *
 * When the number of elements per page is smaller than 32, it is stored inline
 * on the @c zone_page_metadata structure (@c zm_inline_bitmap is set,
 * and @c zm_bitmap used for storage).
 *
 * When the number of elements is larger, then a bitmap is allocated from
 * a buddy allocator (impelemented under the @c zba_* namespace). Pointers
 * to bitmaps are implemented as a packed 32 bit bitmap reference, stored in
 * @c zm_bitmap. The low 3 bits encode the scale (order) of the allocation in
 * @c ZBA_GRANULE units, and hence actual allocations encoded with that scheme
 * cannot be larger than 1024 bytes (8192 bits).
 *
 * This buddy allocator can actually accomodate allocations as large
 * as 8k on 16k systems and 2k on 4k systems.
 *
 * Note: @c zba_* functions are implementation details not meant to be used
 * outside of the allocation of the allocator itself. Interfaces to the rest of
 * the zone allocator are documented and not @c zba_* prefixed.
 */

#define ZBA_CHUNK_SIZE          PAGE_MAX_SIZE
#define ZBA_GRANULE             sizeof(uint64_t)
#define ZBA_GRANULE_BITS        (8 * sizeof(uint64_t))
#define ZBA_MAX_ORDER           (PAGE_MAX_SHIFT - 4)
#define ZBA_MAX_ALLOC_ORDER     7
#define ZBA_SLOTS               (ZBA_CHUNK_SIZE / ZBA_GRANULE)
static_assert(2ul * ZBA_GRANULE << ZBA_MAX_ORDER == ZBA_CHUNK_SIZE, "chunk sizes");
static_assert(ZBA_MAX_ALLOC_ORDER <= ZBA_MAX_ORDER, "ZBA_MAX_ORDER is enough");

struct zone_bits_chain {
	uint32_t zbc_next;
	uint32_t zbc_prev;
} __attribute__((aligned(ZBA_GRANULE)));

struct zone_bits_head {
	uint32_t zbh_next;
	uint32_t zbh_unused;
} __attribute__((aligned(ZBA_GRANULE)));

static_assert(sizeof(struct zone_bits_chain) == ZBA_GRANULE, "zbc size");
static_assert(sizeof(struct zone_bits_head) == ZBA_GRANULE, "zbh size");

struct zone_bits_allocator_meta {
	uint32_t zbam_chunks;
	uint32_t __zbam_padding;
	struct zone_bits_head zbam_lists[ZBA_MAX_ORDER + 1];
};

struct zone_bits_allocator_header {
	uint64_t zbah_bits[ZBA_SLOTS / (8 * sizeof(uint64_t))];
};

#if ZALLOC_TEST
static struct zalloc_bits_allocator_test_setup {
	vm_offset_t zbats_base;
	void      (*zbats_populate)(vm_address_t addr, vm_size_t size);
} zba_test_info;

static struct zone_bits_allocator_header *
zba_base_header(void)
{
	return (struct zone_bits_allocator_header *)zba_test_info.zbats_base;
}

static void
zba_populate(uint32_t n)
{
	vm_address_t base = zba_test_info.zbats_base;
	zba_test_info.zbats_populate(base + n * ZBA_CHUNK_SIZE, ZBA_CHUNK_SIZE);
}
#else
__startup_data
static uint8_t zba_chunk_startup[ZBA_CHUNK_SIZE]
__attribute__((aligned(ZBA_CHUNK_SIZE)));
static LCK_MTX_EARLY_DECLARE(zba_mtx, &zone_locks_grp);

static struct zone_bits_allocator_header *
zba_base_header(void)
{
	return (struct zone_bits_allocator_header *)zone_info.zi_bits_range.min_address;
}

static void
zba_lock(void)
{
	lck_mtx_lock(&zba_mtx);
}

static void
zba_unlock(void)
{
	lck_mtx_unlock(&zba_mtx);
}

static void
zba_populate(uint32_t n)
{
	vm_size_t size = ZBA_CHUNK_SIZE;
	vm_address_t addr;

	addr = zone_info.zi_bits_range.min_address + n * size;
	if (addr >= zone_info.zi_bits_range.max_address) {
		zone_t z = zone_find_largest();
		panic("zba_populate: out of bitmap space, "
		    "likely due to memory leak in zone [%s%s] "
		    "(%luM, %d elements allocated)",
		    zone_heap_name(z), zone_name(z),
		    (unsigned long)zone_size_wired(z) >> 20,
		    zone_count_allocated(z));
	}

	for (;;) {
		kern_return_t kr = KERN_SUCCESS;

		if (0 == pmap_find_phys(kernel_pmap, addr)) {
			kr = kernel_memory_populate(kernel_map, addr, size,
			    KMA_NOPAGEWAIT | KMA_KOBJECT | KMA_ZERO,
			    VM_KERN_MEMORY_OSFMK);
		}

		if (kr == KERN_SUCCESS) {
			return;
		}

		zba_unlock();
		VM_PAGE_WAIT();
		zba_lock();
	}
}
#endif

__pure2
static struct zone_bits_allocator_meta *
zba_meta(void)
{
	return (struct zone_bits_allocator_meta *)&zba_base_header()[1];
}

__pure2
static uint64_t *
zba_slot_base(void)
{
	return (uint64_t *)zba_base_header();
}

__pure2
static vm_address_t
zba_page_addr(uint32_t n)
{
	return (vm_address_t)zba_base_header() + n * ZBA_CHUNK_SIZE;
}

__pure2
static struct zone_bits_head *
zba_head(uint32_t order)
{
	return &zba_meta()->zbam_lists[order];
}

__pure2
static uint32_t
zba_head_index(uint32_t order)
{
	uint32_t hdr_size = sizeof(struct zone_bits_allocator_header) +
	    offsetof(struct zone_bits_allocator_meta, zbam_lists);
	return (hdr_size / ZBA_GRANULE) + order;
}

__pure2
static struct zone_bits_chain *
zba_chain_for_index(uint32_t index)
{
	return (struct zone_bits_chain *)(zba_slot_base() + index);
}

__pure2
static uint32_t
zba_chain_to_index(const struct zone_bits_chain *zbc)
{
	return (uint32_t)((const uint64_t *)zbc - zba_slot_base());
}

__abortlike
static void
zba_head_corruption_panic(uint32_t order)
{
	panic("zone bits allocator head[%d:%p] is corrupt", order,
	    zba_head(order));
}

__abortlike
static void
zba_chain_corruption_panic(struct zone_bits_chain *a, struct zone_bits_chain *b)
{
	panic("zone bits allocator freelist is corrupt (%p <-> %p)", a, b);
}

static void
zba_push_block(struct zone_bits_chain *zbc, uint32_t order)
{
	struct zone_bits_head *hd = zba_head(order);
	uint32_t hd_index = zba_head_index(order);
	uint32_t index = zba_chain_to_index(zbc);
	struct zone_bits_chain *next;

	if (hd->zbh_next) {
		next = zba_chain_for_index(hd->zbh_next);
		if (next->zbc_prev != hd_index) {
			zba_head_corruption_panic(order);
		}
		next->zbc_prev = index;
	}
	zbc->zbc_next = hd->zbh_next;
	zbc->zbc_prev = hd_index;
	hd->zbh_next = index;
}

static void
zba_remove_block(struct zone_bits_chain *zbc)
{
	struct zone_bits_chain *prev = zba_chain_for_index(zbc->zbc_prev);
	uint32_t index = zba_chain_to_index(zbc);

	if (prev->zbc_next != index) {
		zba_chain_corruption_panic(prev, zbc);
	}
	if ((prev->zbc_next = zbc->zbc_next)) {
		struct zone_bits_chain *next = zba_chain_for_index(zbc->zbc_next);
		if (next->zbc_prev != index) {
			zba_chain_corruption_panic(zbc, next);
		}
		next->zbc_prev = zbc->zbc_prev;
	}
}

static vm_address_t
zba_try_pop_block(uint32_t order)
{
	struct zone_bits_head *hd = zba_head(order);
	struct zone_bits_chain *zbc;

	if (hd->zbh_next == 0) {
		return 0;
	}

	zbc = zba_chain_for_index(hd->zbh_next);
	zba_remove_block(zbc);
	return (vm_address_t)zbc;
}

static struct zone_bits_allocator_header *
zba_header(vm_offset_t addr)
{
	addr &= -(vm_offset_t)ZBA_CHUNK_SIZE;
	return (struct zone_bits_allocator_header *)addr;
}

static size_t
zba_node_parent(size_t node)
{
	return (node - 1) / 2;
}

static size_t
zba_node_left_child(size_t node)
{
	return node * 2 + 1;
}

static size_t
zba_node_buddy(size_t node)
{
	return ((node - 1) ^ 1) + 1;
}

static size_t
zba_node(vm_offset_t addr, uint32_t order)
{
	vm_offset_t offs = (addr % ZBA_CHUNK_SIZE) / ZBA_GRANULE;
	return (offs >> order) + (1 << (ZBA_MAX_ORDER - order + 1)) - 1;
}

static struct zone_bits_chain *
zba_chain_for_node(struct zone_bits_allocator_header *zbah, size_t node, uint32_t order)
{
	vm_offset_t offs = (node - (1 << (ZBA_MAX_ORDER - order + 1)) + 1) << order;
	return (struct zone_bits_chain *)((vm_offset_t)zbah + offs * ZBA_GRANULE);
}

static void
zba_node_flip_split(struct zone_bits_allocator_header *zbah, size_t node)
{
	zbah->zbah_bits[node / 64] ^= 1ull << (node % 64);
}

static bool
zba_node_is_split(struct zone_bits_allocator_header *zbah, size_t node)
{
	return zbah->zbah_bits[node / 64] & (1ull << (node % 64));
}

static void
zba_free(vm_offset_t addr, uint32_t order)
{
	struct zone_bits_allocator_header *zbah = zba_header(addr);
	struct zone_bits_chain *zbc;
	size_t node = zba_node(addr, order);

	while (node) {
		size_t parent = zba_node_parent(node);

		zba_node_flip_split(zbah, parent);
		if (zba_node_is_split(zbah, parent)) {
			break;
		}

		zbc = zba_chain_for_node(zbah, zba_node_buddy(node), order);
		zba_remove_block(zbc);
		order++;
		node = parent;
	}

	zba_push_block(zba_chain_for_node(zbah, node, order), order);
}

static vm_size_t
zba_chunk_header_size(uint32_t n)
{
	vm_size_t hdr_size = sizeof(struct zone_bits_allocator_header);
	if (n == 0) {
		hdr_size += sizeof(struct zone_bits_allocator_meta);
	}
	return hdr_size;
}

static void
zba_init_chunk(uint32_t n)
{
	vm_size_t hdr_size = zba_chunk_header_size(n);
	vm_offset_t page = zba_page_addr(n);
	struct zone_bits_allocator_header *zbah = zba_header(page);
	vm_size_t size = ZBA_CHUNK_SIZE;
	size_t node;

	for (uint32_t o = ZBA_MAX_ORDER + 1; o-- > 0;) {
		if (size < hdr_size + (ZBA_GRANULE << o)) {
			continue;
		}
		size -= ZBA_GRANULE << o;
		node = zba_node(page + size, o);
		zba_node_flip_split(zbah, zba_node_parent(node));
		zba_push_block(zba_chain_for_node(zbah, node, o), o);
	}

	zba_meta()->zbam_chunks = n + 1;
}

__attribute__((noinline))
static void
zba_grow(void)
{
	uint32_t chunk = zba_meta()->zbam_chunks;

	zba_populate(chunk);
	if (zba_meta()->zbam_chunks == chunk) {
		zba_init_chunk(chunk);
	}
}

static vm_offset_t
zba_alloc(uint32_t order)
{
	struct zone_bits_allocator_header *zbah;
	uint32_t cur = order;
	vm_address_t addr;
	size_t node;

	while ((addr = zba_try_pop_block(cur)) == 0) {
		if (cur++ >= ZBA_MAX_ORDER) {
			zba_grow();
			cur = order;
		}
	}

	zbah = zba_header(addr);
	node = zba_node(addr, cur);
	zba_node_flip_split(zbah, zba_node_parent(node));
	while (cur > order) {
		cur--;
		zba_node_flip_split(zbah, node);
		node = zba_node_left_child(node);
		zba_push_block(zba_chain_for_node(zbah, node + 1, cur), cur);
	}

	return addr;
}

#define zba_map_index(type, n)    (n / (8 * sizeof(type)))
#define zba_map_bit(type, n)      ((type)1 << (n % (8 * sizeof(type))))
#define zba_map_mask_lt(type, n)  (zba_map_bit(type, n) - 1)
#define zba_map_mask_ge(type, n)  ((type)-zba_map_bit(type, n))

#if !ZALLOC_TEST
static uint32_t
zba_bits_ref_order(uint32_t bref)
{
	return bref & 0x7;
}

static bitmap_t *
zba_bits_ref_ptr(uint32_t bref)
{
	return zba_slot_base() + (bref >> 3);
}

static vm_offset_t
zba_scan_bitmap_inline(zone_t zone, struct zone_page_metadata *meta,
    vm_offset_t eidx)
{
	size_t i = eidx / 32;
	uint32_t map;

	if (eidx % 32) {
		map = meta[i].zm_bitmap & zba_map_mask_ge(uint32_t, eidx);
		if (map) {
			eidx = __builtin_ctz(map);
			meta[i].zm_bitmap ^= 1u << eidx;
			return i * 32 + eidx;
		}
		i++;
	}

	uint32_t chunk_len = meta->zm_chunk_len;
	if (chunk_len == 1 && zone->z_percpu) {
		chunk_len = zpercpu_count();
	}
	for (int j = 0; j < chunk_len; j++, i++) {
		if (i >= chunk_len) {
			i = 0;
		}
		if (__probable(map = meta[i].zm_bitmap)) {
			meta[i].zm_bitmap &= map - 1;
			return i * 32 + __builtin_ctz(map);
		}
	}

	zone_page_meta_accounting_panic(zone, meta, "zm_bitmap");
}

static vm_offset_t
zba_scan_bitmap_ref(zone_t zone, struct zone_page_metadata *meta,
    vm_offset_t eidx)
{
	uint32_t bits_size = 1 << zba_bits_ref_order(meta->zm_bitmap);
	bitmap_t *bits = zba_bits_ref_ptr(meta->zm_bitmap);
	size_t i = eidx / 64;
	uint64_t map;

	if (eidx % 64) {
		map = bits[i] & zba_map_mask_ge(uint64_t, eidx);
		if (map) {
			eidx = __builtin_ctzll(map);
			bits[i] ^= 1ull << eidx;
			return i * 64 + eidx;
		}
		i++;
	}

	for (int j = 0; j < bits_size; i++, j++) {
		if (i >= bits_size) {
			i = 0;
		}
		if (__probable(map = bits[i])) {
			bits[i] &= map - 1;
			return i * 64 + __builtin_ctzll(map);
		}
	}

	zone_page_meta_accounting_panic(zone, meta, "zm_bitmap");
}

/*!
 * @function zone_meta_find_and_clear_bit
 *
 * @brief
 * The core of the bitmap allocator: find a bit set in the bitmaps.
 *
 * @discussion
 * This method will round robin through available allocations,
 * with a per-core memory of the last allocated element index allocated.
 *
 * This is done in order to avoid a fully LIFO behavior which makes exploiting
 * double-free bugs way too practical.
 *
 * @param zone          The zone we're allocating from.
 * @param meta          The main metadata for the chunk being allocated from.
 */
static vm_offset_t
zone_meta_find_and_clear_bit(zone_t zone, struct zone_page_metadata *meta)
{
	zone_stats_t zs = zpercpu_get(zone->z_stats);
	vm_offset_t eidx = zs->zs_alloc_rr + 1;

	if (meta->zm_inline_bitmap) {
		eidx = zba_scan_bitmap_inline(zone, meta, eidx);
	} else {
		eidx = zba_scan_bitmap_ref(zone, meta, eidx);
	}
	zs->zs_alloc_rr = (uint16_t)eidx;
	return eidx;
}

/*!
 * @function zone_meta_bits_init
 *
 * @brief
 * Initializes the zm_bitmap field(s) for a newly assigned chunk.
 *
 * @param meta          The main metadata for the initialized chunk.
 * @param count         The number of elements the chunk can hold
 *                      (which might be partial for partially populated chunks).
 * @param nbits         The maximum nuber of bits that will be used.
 */
static void
zone_meta_bits_init(struct zone_page_metadata *meta,
    uint32_t count, uint32_t nbits)
{
	static_assert(ZONE_MAX_ALLOC_SIZE / ZONE_MIN_ELEM_SIZE <=
	    ZBA_GRANULE_BITS << ZBA_MAX_ORDER, "bitmaps will be large enough");

	if (meta->zm_inline_bitmap) {
		/*
		 * We're called with the metadata zm_bitmap fields already
		 * zeroed out.
		 */
		for (size_t i = 0; 32 * i < count; i++) {
			if (32 * i + 32 <= count) {
				meta[i].zm_bitmap = ~0u;
			} else {
				meta[i].zm_bitmap = zba_map_mask_lt(uint32_t, count);
			}
		}
	} else {
		uint32_t order = flsll((nbits - 1) / ZBA_GRANULE_BITS);
		uint64_t *bits;

		assert(order <= ZBA_MAX_ALLOC_ORDER);
		assert(count <= ZBA_GRANULE_BITS << order);

		zba_lock();
		bits = (uint64_t *)zba_alloc(order);
		zba_unlock();

		for (size_t i = 0; i < 1u << order; i++) {
			if (64 * i + 64 <= count) {
				bits[i] = ~0ull;
			} else if (64 * i < count) {
				bits[i] = zba_map_mask_lt(uint64_t, count);
			} else {
				bits[i] = 0ull;
			}
		}

		meta->zm_bitmap = (uint32_t)((vm_offset_t)bits -
		    (vm_offset_t)zba_slot_base()) + order;
	}
}

/*!
 * @function zone_meta_bits_merge
 *
 * @brief
 * Adds elements <code>[start, end)</code> to a chunk being extended.
 *
 * @param meta          The main metadata for the extended chunk.
 * @param start         The index of the first element to add to the chunk.
 * @param end           The index of the last (exclusive) element to add.
 */
static void
zone_meta_bits_merge(struct zone_page_metadata *meta,
    uint32_t start, uint32_t end)
{
	if (meta->zm_inline_bitmap) {
		while (start < end) {
			size_t s_i = start / 32;
			size_t s_e = end / 32;

			if (s_i == s_e) {
				meta[s_i].zm_bitmap |= zba_map_mask_lt(uint32_t, end) &
				    zba_map_mask_ge(uint32_t, start);
				break;
			}

			meta[s_i].zm_bitmap |= zba_map_mask_ge(uint32_t, start);
			start += 32 - (start % 32);
		}
	} else {
		uint64_t *bits = zba_bits_ref_ptr(meta->zm_bitmap);

		while (start < end) {
			size_t s_i = start / 64;
			size_t s_e = end / 64;

			if (s_i == s_e) {
				bits[s_i] |= zba_map_mask_lt(uint64_t, end) &
				    zba_map_mask_ge(uint64_t, start);
				break;
			}
			bits[s_i] |= zba_map_mask_ge(uint64_t, start);
			start += 64 - (start % 64);
		}
	}
}

/*!
 * @function zone_bits_free
 *
 * @brief
 * Frees a bitmap to the zone bitmap allocator.
 *
 * @param bref
 * A bitmap reference set by @c zone_meta_bits_init() in a @c zm_bitmap field.
 */
static void
zone_bits_free(uint32_t bref)
{
	zba_lock();
	zba_free((vm_offset_t)zba_bits_ref_ptr(bref), zba_bits_ref_order(bref));
	zba_unlock();
}

/*!
 * @function zone_meta_is_free
 *
 * @brief
 * Returns whether a given element appears free.
 */
static bool
zone_meta_is_free(struct zone_page_metadata *meta, zone_element_t ze)
{
	vm_offset_t eidx = zone_element_idx(ze);
	if (meta->zm_inline_bitmap) {
		uint32_t bit = zba_map_bit(uint32_t, eidx);
		return meta[zba_map_index(uint32_t, eidx)].zm_bitmap & bit;
	} else {
		bitmap_t *bits = zba_bits_ref_ptr(meta->zm_bitmap);
		uint64_t bit = zba_map_bit(uint64_t, eidx);
		return bits[zba_map_index(uint64_t, eidx)] & bit;
	}
}

/*!
 * @function zone_meta_mark_free
 *
 * @brief
 * Marks an element as free and returns whether it was marked as used.
 */
static bool
zone_meta_mark_free(struct zone_page_metadata *meta, zone_element_t ze)
{
	vm_offset_t eidx = zone_element_idx(ze);

	if (meta->zm_inline_bitmap) {
		uint32_t bit = zba_map_bit(uint32_t, eidx);
		if (meta[zba_map_index(uint32_t, eidx)].zm_bitmap & bit) {
			return false;
		}
		meta[zba_map_index(uint32_t, eidx)].zm_bitmap ^= bit;
	} else {
		bitmap_t *bits = zba_bits_ref_ptr(meta->zm_bitmap);
		uint64_t bit = zba_map_bit(uint64_t, eidx);
		if (bits[zba_map_index(uint64_t, eidx)] & bit) {
			return false;
		}
		bits[zba_map_index(uint64_t, eidx)] ^= bit;
	}
	return true;
}

/*!
 * @function zone_meta_mark_used
 *
 * @brief
 * Marks an element as used and returns whether it was marked as free
 */
static bool
zone_meta_mark_used(struct zone_page_metadata *meta, zone_element_t ze)
{
	vm_offset_t eidx = zone_element_idx(ze);

	if (meta->zm_inline_bitmap) {
		uint32_t bit = zba_map_bit(uint32_t, eidx);
		if (meta[zba_map_index(uint32_t, eidx)].zm_bitmap & bit) {
			meta[zba_map_index(uint32_t, eidx)].zm_bitmap ^= bit;
			return true;
		}
	} else {
		bitmap_t *bits = zba_bits_ref_ptr(meta->zm_bitmap);
		uint64_t bit = zba_map_bit(uint64_t, eidx);
		if (bits[zba_map_index(uint64_t, eidx)] & bit) {
			bits[zba_map_index(uint64_t, eidx)] ^= bit;
			return true;
		}
	}
	return false;
}

#endif /* !ZALLOC_TEST */
/*! @} */
#pragma mark ZTAGS
#if !ZALLOC_TEST
#if VM_MAX_TAG_ZONES
/*
 * Zone tagging allows for per "tag" accounting of allocations for the kalloc
 * zones only.
 *
 * There are 3 kinds of tags that can be used:
 * - pre-registered VM_KERN_MEMORY_*
 * - dynamic tags allocated per call sites in core-kernel (using vm_tag_alloc())
 * - per-kext tags computed by IOKit (using the magic VM_TAG_BT marker).
 *
 * The VM tracks the statistics in lazily allocated structures.
 * See vm_tag_will_update_zone(), vm_tag_update_zone_size().
 *
 * If for some reason the requested tag cannot be accounted for,
 * the tag is forced to VM_KERN_MEMORY_KALLOC which is pre-allocated.
 *
 * Each allocated element also remembers the tag it was assigned,
 * in its ztSlot() which lets zalloc/zfree update statistics correctly.
 */

// for zones with tagging enabled:

// calculate a pointer to the tag base entry,
// holding either a uint32_t the first tag offset for a page in the zone map,
// or two uint16_t tags if the page can only hold one or two elements

#define ZTAGBASE(zone, element) \
	(&((uint32_t *)zone_tagbase_min)[atop((element) - \
	    zone_info.zi_map_range[ZONE_ADDR_NATIVE].min_address)])

static vm_offset_t  zone_tagbase_min;
static vm_offset_t  zone_tagbase_max;
static vm_offset_t  zone_tagbase_map_size;
static vm_map_t     zone_tagbase_map;

static vm_offset_t  zone_tags_min;
static vm_offset_t  zone_tags_max;
static vm_offset_t  zone_tags_map_size;
static vm_map_t     zone_tags_map;

// simple heap allocator for allocating the tags for new memory

static LCK_MTX_EARLY_DECLARE(ztLock, &zone_locks_grp); /* heap lock */

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

// pointer to the tag for an element
static vm_tag_t *
ztSlot(zone_t zone, vm_offset_t element)
{
	vm_tag_t *result;
	if (zone->tags_inline) {
		result = (vm_tag_t *)ZTAGBASE(zone, element);
		if ((PAGE_MASK & element) >= zone_elem_size(zone)) {
			result++;
		}
	} else {
		result = &((vm_tag_t *)zone_tags_min)[ZTAGBASE(zone, element)[0] +
		    (element & PAGE_MASK) / zone_elem_size(zone)];
	}
	return result;
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
#endif /* !ZALLOC_TEST */
#pragma mark zalloc helpers
#if !ZALLOC_TEST

__pure2
static inline uint16_t
zc_mag_size(void)
{
	return zc_magazine_size;
}

__attribute__((noinline, cold))
static void
zone_lock_was_contended(zone_t zone, zone_cache_t zc)
{
	lck_spin_lock_nopreempt(&zone->z_lock);

	/*
	 * If zone caching has been disabled due to memory pressure,
	 * then recording contention is not useful, give the system
	 * time to recover.
	 */
	if (__improbable(zone_caching_disabled)) {
		return;
	}

	zone->z_contention_cur++;

	if (zc == NULL || zc->zc_depot_max >= INT16_MAX * zc_mag_size()) {
		return;
	}

	/*
	 * Let the depot grow based on how bad the contention is,
	 * and how populated the zone is.
	 */
	if (zone->z_contention_wma < 2 * Z_CONTENTION_WMA_UNIT) {
		if (zc->zc_depot_max * zpercpu_count() * 20u >=
		    zone->z_elems_avail) {
			return;
		}
	}
	if (zone->z_contention_wma < 4 * Z_CONTENTION_WMA_UNIT) {
		if (zc->zc_depot_max * zpercpu_count() * 10u >=
		    zone->z_elems_avail) {
			return;
		}
	}
	if (!zc_grow_threshold || zone->z_contention_wma <
	    zc_grow_threshold * Z_CONTENTION_WMA_UNIT) {
		return;
	}

	zc->zc_depot_max++;
}

static inline void
zone_lock_nopreempt_check_contention(zone_t zone, zone_cache_t zc)
{
	if (lck_spin_try_lock_nopreempt(&zone->z_lock)) {
		return;
	}

	zone_lock_was_contended(zone, zc);
}

static inline void
zone_lock_check_contention(zone_t zone, zone_cache_t zc)
{
	disable_preemption();
	zone_lock_nopreempt_check_contention(zone, zc);
}

static inline void
zone_unlock_nopreempt(zone_t zone)
{
	lck_spin_unlock_nopreempt(&zone->z_lock);
}

static inline void
zone_depot_lock_nopreempt(zone_cache_t zc)
{
	hw_lock_bit_nopreempt(&zc->zc_depot_lock, 0, &zone_locks_grp);
}

static inline void
zone_depot_unlock_nopreempt(zone_cache_t zc)
{
	hw_unlock_bit_nopreempt(&zc->zc_depot_lock, 0);
}

static inline void
zone_depot_lock(zone_cache_t zc)
{
	hw_lock_bit(&zc->zc_depot_lock, 0, &zone_locks_grp);
}

static inline void
zone_depot_unlock(zone_cache_t zc)
{
	hw_unlock_bit(&zc->zc_depot_lock, 0);
}

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

static uint32_t
zone_alloc_pages_for_nelems(zone_t z, vm_size_t max_elems)
{
	vm_size_t elem_count, chunks;

	elem_count = ptoa(z->z_percpu ? 1 : z->z_chunk_pages) / zone_elem_size(z);
	chunks = (max_elems + elem_count - 1) / elem_count;

	return (uint32_t)MIN(UINT32_MAX, chunks * z->z_chunk_pages);
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

static void
zone_cache_swap_magazines(zone_cache_t cache)
{
	uint16_t count_a = cache->zc_alloc_cur;
	uint16_t count_f = cache->zc_free_cur;
	zone_element_t *elems_a = cache->zc_alloc_elems;
	zone_element_t *elems_f = cache->zc_free_elems;

	z_debug_assert(count_a <= zc_mag_size());
	z_debug_assert(count_f <= zc_mag_size());

	cache->zc_alloc_cur = count_f;
	cache->zc_free_cur = count_a;
	cache->zc_alloc_elems = elems_f;
	cache->zc_free_elems = elems_a;
}

/*!
 * @function zone_magazine_load
 *
 * @brief
 * Cache the value of @c zm_cur on the cache to avoid a dependent load
 * on the allocation fastpath.
 */
static void
zone_magazine_load(uint16_t *count, zone_element_t **elems, zone_magazine_t mag)
{
	z_debug_assert(mag->zm_cur <= zc_mag_size());
	*count = mag->zm_cur;
	*elems = mag->zm_elems;
}

/*!
 * @function zone_magazine_replace
 *
 * @brief
 * Unlod a magazine and load a new one instead.
 */
static zone_magazine_t
zone_magazine_replace(uint16_t *count, zone_element_t **elems,
    zone_magazine_t mag)
{
	zone_magazine_t old;

	old = (zone_magazine_t)((uintptr_t)*elems -
	    offsetof(struct zone_magazine, zm_elems));
	old->zm_cur = *count;
	z_debug_assert(old->zm_cur <= zc_mag_size());
	zone_magazine_load(count, elems, mag);

	return old;
}

static zone_magazine_t
zone_magazine_alloc(zalloc_flags_t flags)
{
	return zalloc_ext(zc_magazine_zone, zc_magazine_zone->z_stats,
	           flags | Z_ZERO);
}

static void
zone_magazine_free(zone_magazine_t mag)
{
	zfree_ext(zc_magazine_zone, zc_magazine_zone->z_stats, mag);
}

static void
zone_enable_caching(zone_t zone)
{
	zone_cache_t caches;

	caches = zalloc_percpu_permanent_type(struct zone_cache);
	zpercpu_foreach(zc, caches) {
		zone_magazine_load(&zc->zc_alloc_cur, &zc->zc_alloc_elems,
		    zone_magazine_alloc(Z_WAITOK | Z_NOFAIL));
		zone_magazine_load(&zc->zc_free_cur, &zc->zc_free_elems,
		    zone_magazine_alloc(Z_WAITOK | Z_NOFAIL));
		STAILQ_INIT(&zc->zc_depot);
	}

	if (os_atomic_xchg(&zone->z_pcpu_cache, caches, release)) {
		panic("allocating caches for zone %s twice", zone->z_name);
	}
}

bool
zone_maps_owned(vm_address_t addr, vm_size_t size)
{
	return from_zone_map(addr, size, ZONE_ADDR_NATIVE);
}

void
zone_map_sizes(
	vm_map_size_t    *psize,
	vm_map_size_t    *pfree,
	vm_map_size_t    *plargest_free)
{
	vm_map_size_t size, free, largest;

	vm_map_sizes(zone_submaps[0], psize, pfree, plargest_free);

	for (uint32_t i = 1; i <= zone_last_submap_idx; i++) {
		vm_map_sizes(zone_submaps[i], &size, &free, &largest);
		*psize += size;
		*pfree += free;
		*plargest_free = MAX(*plargest_free, largest);
	}
}

__attribute__((always_inline))
vm_map_t
zone_submap(zone_t zone)
{
	return zone_submaps[zone->z_submap_idx];
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
	struct zone *src_zone;

	if (from_zone_map(addr, sizeof(void *), ZONE_ADDR_NATIVE) ||
	    from_zone_map(addr, sizeof(void *), ZONE_ADDR_FOREIGN)) {
		src_zone = &zone_array[zone_index_from_ptr(addr)];
#if VM_MAX_TAG_ZONES
		if (__improbable(src_zone->tags)) {
			tag = *ztSlot(src_zone, (vm_offset_t)addr) >> 1;
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

/* The backup pointer is stored in the last pointer-sized location in an element. */
__header_always_inline vm_offset_t *
get_primary_ptr(vm_offset_t elem)
{
	return (vm_offset_t *)elem;
}

__header_always_inline vm_offset_t *
get_backup_ptr(vm_offset_t elem, vm_size_t elem_size)
{
	return (vm_offset_t *)(elem + elem_size - sizeof(vm_offset_t));
}

#endif /* !ZALLOC_TEST */
#pragma mark Zone poisoning/zeroing and early random
#if !ZALLOC_TEST

#define ZONE_ENTROPY_CNT 2
static struct zone_bool_gen {
	struct bool_gen zbg_bg;
	uint32_t zbg_entropy[ZONE_ENTROPY_CNT];
} zone_bool_gen[MAX_CPUS];

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
	 * Initialize canary random cookie.
	 *
	 * Make sure that (zp_canary ^ pointer) have non zero low bits (01)
	 * different from ZONE_POISON (11).
	 *
	 * On LP64, have (zp_canary ^ pointer) have the high bits equal 0xC0FFEE...
	 */
	static_assert(ZONE_POISON % 4 == 3);
	zp_canary = (uintptr_t)early_random();
#if __LP64__
	zp_canary &= 0x000000fffffffffc;
	zp_canary |= 0xc0ffee0000000001 ^ 0xffffff0000000000;
#else
	zp_canary &= 0xfffffffc;
	zp_canary |= 0x00000001;
#endif

	/* -zp: enable poisoning for every alloc and free */
	if (PE_parse_boot_argn("-zp", temp_buf, sizeof(temp_buf))) {
		zp_factor = 1;
	}

	/* -no-zp: disable poisoning */
	if (PE_parse_boot_argn("-no-zp", temp_buf, sizeof(temp_buf))) {
		zp_factor = 0;
		printf("Zone poisoning disabled\n");
	}

	zpercpu_foreach_cpu(cpu) {
		random_bool_init(&zone_bool_gen[cpu].zbg_bg);
	}
}

static inline uint32_t
zone_poison_count_init(zone_t zone)
{
	return zp_factor + (((uint32_t)zone_elem_size(zone)) >> zp_scale) ^
	       (mach_absolute_time() & 0x7);
}

/*
 * Zero the element if zone has z_free_zeroes flag set else poison
 * the element if zs_poison_seqno hits 0.
 */
static zprot_mode_t
zfree_clear_or_poison(zone_t zone, vm_offset_t addr, vm_offset_t elem_size)
{
	if (zone->z_free_zeroes) {
		if (zone->z_percpu) {
			zpercpu_foreach_cpu(i) {
				bzero((void *)(addr + ptoa(i)), elem_size);
			}
		} else {
			bzero((void *)addr, elem_size);
		}
		return ZPM_ZERO;
	}

	zprot_mode_t poison = ZPM_AUTO;
#if ZALLOC_ENABLE_POISONING
	if (__improbable(zp_factor == 1)) {
		poison = ZPM_POISON;
	} else if (__probable(zp_factor != 0)) {
		uint32_t *seqnop = &zpercpu_get(zone->z_stats)->zs_poison_seqno;
		uint32_t seqno = os_atomic_load(seqnop, relaxed);
		if (seqno == 0) {
			os_atomic_store(seqnop, zone_poison_count_init(zone), relaxed);
			poison = ZPM_POISON;
		} else {
			os_atomic_store(seqnop, seqno - 1, relaxed);
		}
	}
	if (poison == ZPM_POISON) {
		/* memset_pattern{4|8} could help make this faster: <rdar://problem/4662004> */
		for (size_t i = 0; i < elem_size / sizeof(vm_offset_t); i++) {
			((vm_offset_t *)addr)[i] = ZONE_POISON;
		}
	} else {
		/*
		 * Set a canary at the extremities.
		 *
		 * Zero first zp_min_size bytes of elements that aren't being
		 * poisoned.
		 *
		 * Element size is larger than zp_min_size in this path,
		 * zones with smaller elements have z_free_zeroes set.
		 */
		*get_primary_ptr(addr) = zp_canary ^ (uintptr_t)addr;
		bzero((void *)addr + sizeof(vm_offset_t),
		    zp_min_size - sizeof(vm_offset_t));
		*get_backup_ptr(addr, elem_size) = zp_canary ^ (uintptr_t)addr;

		poison = ZPM_CANARY;
	}
#endif /* ZALLOC_ENABLE_POISONING */

	return poison;
}

#if ZALLOC_ENABLE_POISONING

__abortlike
static void
zalloc_uaf_panic(zone_t z, uintptr_t elem, size_t size, zprot_mode_t zpm)
{
	uint32_t esize = (uint32_t)zone_elem_size(z);
	uint32_t first_offs = ~0u;
	uintptr_t first_bits = 0, v;
	char buf[1024];
	int pos = 0;
	const char *how;

#if __LP64__
#define ZPF  "0x%016lx"
#else
#define ZPF  "0x%08lx"
#endif

	buf[0] = '\0';

	if (zpm == ZPM_CANARY) {
		how = "canaries";

		v = *get_primary_ptr(elem);
		if (v != (elem ^ zp_canary)) {
			pos += scnprintf(buf + pos, sizeof(buf) - pos, "\n"
			    "%5d: got "ZPF", want "ZPF" (xor: "ZPF")",
			    0, v, (elem ^ zp_canary), (v ^ elem ^ zp_canary));
			if (first_offs > 0) {
				first_offs = 0;
				first_bits = v;
			}
		}

		v = *get_backup_ptr(elem, esize);
		if (v != (elem ^ zp_canary)) {
			pos += scnprintf(buf + pos, sizeof(buf) - pos, "\n"
			    "%5d: got "ZPF", want "ZPF" (xor: "ZPF")",
			    esize - (int)sizeof(v), v, (elem ^ zp_canary),
			    (v ^ elem ^ zp_canary));
			if (first_offs > esize - sizeof(v)) {
				first_offs = esize - sizeof(v);
				first_bits = v;
			}
		}

		for (uint32_t o = sizeof(v); o < zp_min_size; o += sizeof(v)) {
			if ((v = *(uintptr_t *)(elem + o)) == 0) {
				continue;
			}
			pos += scnprintf(buf + pos, sizeof(buf) - pos, "\n"
			    "%5d: "ZPF, o, v);
			if (first_offs > o) {
				first_offs = o;
				first_bits = v;
			}
		}
	} else if (zpm == ZPM_ZERO) {
		how = "zero";

		for (uint32_t o = 0; o < size; o += sizeof(v)) {
			if ((v = *(uintptr_t *)(elem + o)) == 0) {
				continue;
			}
			pos += scnprintf(buf + pos, sizeof(buf) - pos, "\n"
			    "%5d: "ZPF, o, v);
			if (first_offs > o) {
				first_offs = o;
				first_bits = v;
			}
		}
	} else {
		how = "poison";

		for (uint32_t o = 0; o < size; o += sizeof(v)) {
			if ((v = *(uintptr_t *)(elem + o)) == ZONE_POISON) {
				continue;
			}
			pos += scnprintf(buf + pos, sizeof(buf) - pos, "\n"
			    "%5d: "ZPF" (xor: "ZPF")",
			    o, v, (v ^ ZONE_POISON));
			if (first_offs > o) {
				first_offs = o;
				first_bits = v;
			}
		}
	}

	(panic)("[%s%s]: element modified after free "
	"(off:%d, val:"ZPF", sz:%d, ptr:%p, prot:%s)%s",
	zone_heap_name(z), zone_name(z),
	first_offs, first_bits, esize, (void *)elem, how, buf);

#undef ZPF
}

static void
zalloc_validate_element_zero(zone_t zone, vm_offset_t elem, vm_size_t size)
{
	if (memcmp_zero_ptr_aligned((void *)elem, size)) {
		zalloc_uaf_panic(zone, elem, size, ZPM_ZERO);
	}
	if (!zone->z_percpu) {
		return;
	}
	for (size_t i = zpercpu_count(); --i > 0;) {
		elem += PAGE_SIZE;
		if (memcmp_zero_ptr_aligned((void *)elem, size)) {
			zalloc_uaf_panic(zone, elem, size, ZPM_ZERO);
		}
	}
}

#if __arm64__ || __arm__
typedef __attribute__((ext_vector_type(2))) vm_offset_t zpair_t;
#else
typedef struct {
	vm_offset_t x;
	vm_offset_t y;
} zpair_t;
#endif


__attribute__((noinline))
static void
zalloc_validate_element_poison(zone_t zone, vm_offset_t elem, vm_size_t size)
{
	vm_offset_t p = elem;
	vm_offset_t end = elem + size;

	const zpair_t poison = { ZONE_POISON, ZONE_POISON };
	zpair_t a, b;

	a.x = *(const vm_offset_t *)p;
	a.y = *(const vm_offset_t *)(end - sizeof(vm_offset_t));

	a.x ^= poison.x;
	a.y ^= poison.y;

	/*
	 * align p to the next double-wide boundary
	 * align end to the previous double-wide boundary
	 */
	p = (p + sizeof(zpair_t) - 1) & -sizeof(zpair_t);
	end &= -sizeof(zpair_t);

	if ((end - p) % (2 * sizeof(zpair_t)) == 0) {
		b.y = 0;
		b.y = 0;
	} else {
		end -= sizeof(zpair_t);
		b.x = ((zpair_t *)end)[0].x ^ poison.x;
		b.y = ((zpair_t *)end)[0].y ^ poison.y;
	}

	for (; p < end; p += 2 * sizeof(zpair_t)) {
		a.x |= ((zpair_t *)p)[0].x ^ poison.x;
		a.y |= ((zpair_t *)p)[0].y ^ poison.y;
		b.x |= ((zpair_t *)p)[1].x ^ poison.x;
		b.y |= ((zpair_t *)p)[1].y ^ poison.y;
	}

	a.x |= b.x;
	a.y |= b.y;

	if (a.x || a.y) {
		zalloc_uaf_panic(zone, elem, size, ZPM_POISON);
	}
}

static void
zalloc_validate_element(zone_t zone, vm_offset_t elem, vm_size_t size,
    zprot_mode_t zpm)
{
	vm_offset_t *primary = get_primary_ptr(elem);
	vm_offset_t *backup  = get_backup_ptr(elem, size);

#if CONFIG_GZALLOC
	if (zone->gzalloc_tracked) {
		return;
	}
#endif /* CONFIG_GZALLOC */

	if (zone->z_free_zeroes) {
		return zalloc_validate_element_zero(zone, elem, size);
	}

	switch (zpm) {
	case ZPM_AUTO:
		if (*backup == 0) {
			size -= sizeof(vm_size_t);
			return zalloc_validate_element_zero(zone, elem, size);
		}
		if (*backup == ZONE_POISON) {
			size -= sizeof(vm_size_t);
			return zalloc_validate_element_poison(zone, elem, size);
		}
		OS_FALLTHROUGH;

	case ZPM_CANARY:
		if ((*primary ^ zp_canary) != elem || (*backup ^ zp_canary) != elem) {
			zalloc_uaf_panic(zone, elem, size, ZPM_CANARY);
		}
		*primary = *backup = 0;
		size = zp_min_size;
		OS_FALLTHROUGH;

	case ZPM_ZERO:
		return zalloc_validate_element_zero(zone, elem, size);

	case ZPM_POISON:
		return zalloc_validate_element_poison(zone, elem, size);
	}
}

#endif /* ZALLOC_ENABLE_POISONING */
#if ZALLOC_EARLY_GAPS

__attribute__((noinline))
static void
zone_early_gap_drop(int n)
{
	while (n-- > 0) {
		zone_t zone0 = &zone_array[0];
		struct zone_page_metadata *meta = NULL;
		vm_offset_t addr;
		uint16_t pages;
		vm_map_t map;

		lck_mtx_lock(&zone_metadata_region_lck);

		if (!zone_pva_is_null(zone0->z_pageq_va)) {
			meta = zone_meta_queue_pop_native(zone0,
			    &zone0->z_pageq_va, &addr);
			map = zone_submaps[meta->zm_chunk_len];
			pages = meta->zm_alloc_size;
			__builtin_bzero(meta, sizeof(struct zone_page_metadata));
		}

		lck_mtx_unlock(&zone_metadata_region_lck);

		if (!meta) {
			break;
		}

		kmem_free(map, addr, ptoa(pages));
	}
}

static void
zone_early_gap_add(zone_t z, uint16_t pages)
{
	struct zone_page_metadata *meta = NULL;
	zone_t zone0 = &zone_array[0];
	kern_return_t kr;
	vm_offset_t addr;

	kma_flags_t kmaflags = KMA_KOBJECT | KMA_ZERO | KMA_VAONLY;
	if (z->z_submap_idx == Z_SUBMAP_IDX_GENERAL &&
	    z->kalloc_heap != KHEAP_ID_NONE) {
		kmaflags |= KMA_KHEAP;
	}

	kr = kernel_memory_allocate(zone_submap(z), &addr, ptoa(pages), 0,
	    kmaflags, VM_KERN_MEMORY_ZONE);

	if (kr != KERN_SUCCESS) {
		panic("unable to allocate early gap (%d pages): %d", pages, kr);
	}

	zone_meta_populate(addr, ptoa(pages));

	meta = zone_meta_from_addr(addr);
	meta->zm_alloc_size = pages;
	meta->zm_chunk_len = z->z_submap_idx;

	lck_mtx_lock(&zone_metadata_region_lck);
	zone_meta_queue_push(zone0, &zone0->z_pageq_va, meta);
	lck_mtx_unlock(&zone_metadata_region_lck);
}

/*
 * Roughly until pd1 is made, introduce random gaps
 * between allocated pages.
 *
 * This way the early boot allocations are not in a completely
 * predictible order and relative position.
 *
 * Those gaps are returned to the maps afterwards.
 *
 * We abuse the zone 0 (which is unused) "va" pageq to remember
 * those ranges.
 */
__attribute__((noinline))
static void
zone_allocate_random_early_gap(zone_t z)
{
	int16_t pages = early_random() % 16;

	/*
	 * 6%  of the time: drop 2 gaps
	 * 25% of the time: drop 1 gap
	 * 37% of the time: do nothing
	 * 18% of the time: add 1 gap
	 * 12% of the time: add 2 gaps
	 */
	if (pages > 10) {
		zone_early_gap_drop(pages == 15 ? 2 : 1);
	}
	if (pages < 5) {
		/* values are 6 through 16 */
		zone_early_gap_add(z, 6 + 2 * pages);
	}
	if (pages < 2) {
		zone_early_gap_add(z, 6 + early_random() % 16);
	}
}

static inline void
zone_cleanup_early_gaps_if_needed(void)
{
	if (__improbable(!zone_pva_is_null(zone_array[0].z_pageq_va))) {
		zone_early_gap_drop(10);
	}
}

#endif /* ZALLOC_EARLY_GAPS */

static void
zone_early_scramble_rr(zone_t zone, zone_stats_t zstats)
{
	int cpu = cpu_number();
	zone_stats_t zs = zpercpu_get_cpu(zstats, cpu);
	uint32_t bits;

	bits = random_bool_gen_bits(&zone_bool_gen[cpu].zbg_bg,
	    zone_bool_gen[cpu].zbg_entropy, ZONE_ENTROPY_CNT, 8);

	zs->zs_alloc_rr += bits;
	zs->zs_alloc_rr %= zone->z_chunk_elems;
}

#endif /* !ZALLOC_TEST */
#pragma mark Zone Leak Detection
#if !ZALLOC_TEST

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
static TUNABLE(bool, corruption_debug_flag, "-zc", false);

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
static uint32_t        zleak_state = 0;                 /* State of collection, as above */
static unsigned int    zleak_sample_factor = 1000;      /* Allocations per sample attempt */

bool            panic_include_ztrace    = FALSE;        /* Enable zleak logging on panic */
vm_size_t       zleak_global_tracking_threshold;        /* Size of zone map at which to start collecting data */
vm_size_t       zleak_per_zone_tracking_threshold;      /* Size a zone will have before we will collect data on it */

/*
 * Counters for allocation statistics.
 */

/* Times two active records want to occupy the same spot */
static unsigned int z_alloc_collisions = 0;
static unsigned int z_trace_collisions = 0;

/* Times a new record lands on a spot previously occupied by a freed allocation */
static unsigned int z_alloc_overwrites = 0;
static unsigned int z_trace_overwrites = 0;

/* Times a new alloc or trace is put into the hash table */
static unsigned int z_alloc_recorded   = 0;
static unsigned int z_trace_recorded   = 0;

/* Times zleak_log returned false due to not being able to acquire the lock */
static unsigned int z_total_conflicts  = 0;

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
static uint32_t zleak_alloc_buckets = CONFIG_ZLEAK_ALLOCATION_MAP_NUM;
static uint32_t zleak_trace_buckets = CONFIG_ZLEAK_TRACE_MAP_NUM;

vm_size_t zleak_max_zonemap_size;

/* Hashmaps of allocations and their corresponding traces */
static struct zallocation*      zallocations;
static struct ztrace*           ztraces;

/* not static so that panic can see this, see kern/debug.c */
struct ztrace*                          top_ztrace;

/* Lock to protect zallocations, ztraces, and top_ztrace from concurrent modification. */
static LCK_GRP_DECLARE(zleak_lock_grp, "zleak_lock");
static LCK_SPIN_DECLARE(zleak_lock, &zleak_lock_grp);

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
	retval = kmem_alloc_kobject(kernel_map, (vm_offset_t*)&allocations_ptr, z_alloc_size, VM_KERN_MEMORY_DIAG);
	if (retval != KERN_SUCCESS) {
		goto fail;
	}

	retval = kmem_alloc_kobject(kernel_map, (vm_offset_t*)&traces_ptr, z_trace_size, VM_KERN_MEMORY_DIAG);
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

static inline void
zleak_activate_if_needed(void)
{
	if (__probable((zleak_state & ZLEAK_STATE_ENABLED) == 0)) {
		return;
	}
	if (zleak_state & ZLEAK_STATE_ACTIVE) {
		return;
	}
	if (zone_submaps_approx_size() < zleak_global_tracking_threshold) {
		return;
	}

	kern_return_t kr = zleak_activate();
	if (kr != KERN_SUCCESS) {
		printf("Failed to activate live zone leak debugging (%d).\n", kr);
	}
}

static inline void
zleak_track_if_needed(zone_t z)
{
	if (__improbable(zleak_state & ZLEAK_STATE_ACTIVE)) {
		if (!z->zleak_on &&
		    zone_size_wired(z) >= zleak_per_zone_tracking_threshold) {
			z->zleak_on = true;
		}
	}
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

#else
static inline void
zleak_activate_if_needed(void)
{
}

static inline void
zleak_track_if_needed(__unused zone_t z)
{
}
#endif /* CONFIG_ZLEAKS */
#if ZONE_ENABLE_LOGGING || CONFIG_ZLEAKS

__attribute__((noinline))
static void
zalloc_log_or_trace_leaks(zone_t zone, vm_offset_t addr, void *fp)
{
	uintptr_t       zbt[MAX_ZTRACE_DEPTH];  /* used in zone leak logging and zone leak detection */
	unsigned int    numsaved = 0;

#if ZONE_ENABLE_LOGGING
	if (DO_LOGGING(zone)) {
		numsaved = backtrace(zbt, MAX_ZTRACE_DEPTH, NULL);
		btlog_add_entry(zone->zlog_btlog, (void *)addr,
		    ZOP_ALLOC, (void **)zbt, numsaved);
	}
#endif /* ZONE_ENABLE_LOGGING */

#if CONFIG_ZLEAKS
	/*
	 * Zone leak detection: capture a backtrace every zleak_sample_factor
	 * allocations in this zone.
	 */
	if (__improbable(zone->zleak_on)) {
		if (sample_counter(&zone->zleak_capture, zleak_sample_factor)) {
			/* Avoid backtracing twice if zone logging is on */
			if (numsaved == 0) {
				numsaved = backtrace_frame(zbt, MAX_ZTRACE_DEPTH, fp, NULL);
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
			numsaved = backtrace_frame(zbt, MAX_ZTRACE_DEPTH, fp, NULL);
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
#endif /* ZONE_ENABLE_LOGGING */
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
zfree_log_trace(zone_t zone, vm_offset_t addr, void *fp)
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
			numsaved = backtrace_frame(zbt, MAX_ZTRACE_DEPTH, fp, NULL);
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

#endif /* !ZALLOC_TEST */
#pragma mark zone (re)fill
#if !ZALLOC_TEST

/*!
 * @defgroup Zone Refill
 * @{
 *
 * @brief
 * Functions handling The zone refill machinery.
 *
 * @discussion
 * Zones are refilled based on 3 mechanisms: direct expansion, async expansion,
 * VM-specific replenishment. Zones using VM-specific replenishment are marked
 * with the @c z_replenishes property set.
 *
 * @c zalloc_ext() is the codepath that kicks the zone refill when the zone is
 * dropping below half of its @c z_elems_rsv (0 for most zones) and will:
 *
 * - call @c zone_expand_locked() directly if the caller is allowed to block,
 *
 * - wakeup the asynchroous expansion thread call if the caller is not allowed
 *   to block.
 *
 * - call @c zone_replenish_locked() to kick the replenish state machine.
 *
 *
 * <h2>Synchronous expansion</h2>
 *
 * This mechanism is actually the only one that may refill a zone, and all the
 * other ones funnel through this one eventually.
 *
 * @c zone_expand_locked() implements the core of the expansion mechanism,
 * and will do so while a caller specified predicate is true.
 *
 * Zone expansion allows for up to 2 threads to concurrently refill the zone:
 * - one VM privileged thread,
 * - one regular thread.
 *
 * Regular threads that refill will put down their identity in @c z_expander,
 * so that priority inversion avoidance can be implemented.
 *
 * However, VM privileged threads are allowed to use VM page reserves,
 * which allows for the system to recover from extreme memory pressure
 * situations, allowing for the few allocations that @c zone_gc() or
 * killing processes require.
 *
 * When a VM privileged thread is also expanding, the @c z_expander_vm_priv bit
 * is set. @c z_expander is not necessarily the identity of this VM privileged
 * thread (it is if the VM privileged thread came in first, but wouldn't be, and
 * could even be @c THREAD_NULL otherwise).
 *
 * Note that the pageout-scan daemon might be BG and is VM privileged. To avoid
 * spending a whole pointer on priority inheritance for VM privileged threads
 * (and other issues related to having two owners), we use the rwlock boost as
 * a stop gap to avoid priority inversions.
 *
 *
 * <h2>Chunk wiring policies</h2>
 *
 * Zones allocate memory in chunks of @c zone_t::z_chunk_pages pages at a time
 * to try to minimize fragmentation relative to element sizes not aligning with
 * a chunk size well.  However, this can grow large and be hard to fulfill on
 * a system under a lot of memory pressure (chunks can be as long as 8 pages on
 * 4k page systems).
 *
 * This is why, when under memory pressure the system allows chunks to be
 * partially populated. The metadata of the first page in the chunk maintains
 * the count of actually populated pages.
 *
 * The metadata for addresses assigned to a zone are found of 4 queues:
 * - @c z_pageq_empty has chunk heads with populated pages and no allocated
 *   elements (those can be targeted by @c zone_gc()),
 * - @c z_pageq_partial has chunk heads with populated pages that are partially
 *   used,
 * - @c z_pageq_full has chunk heads with populated pages with no free elements
 *   left,
 * - @c z_pageq_va has either chunk heads for sequestered VA space assigned to
 *   the zone forever (if @c z_va_sequester is enabled), or the first secondary
 *   metadata for a chunk whose corresponding page is not populated in the
 *   chunk.
 *
 * When new pages need to be wired/populated, chunks from the @c z_pageq_va
 * queues are preferred.
 *
 *
 * <h2>Asynchronous expansion</h2>
 *
 * This mechanism allows for refilling zones used mostly with non blocking
 * callers. It relies on a thread call (@c zone_expand_callout) which will
 * iterate all zones and refill the ones marked with @c z_async_refilling.
 *
 * NOTE: If the calling thread for zalloc_noblock is lower priority than
 *       the thread_call, then zalloc_noblock to an empty zone may succeed.
 *
 *
 * <h2>Dealing with zone allocations from the mach VM code</h2>
 *
 * The implementation of the mach VM itself uses the zone allocator
 * for things like the vm_map_entry data structure. In order to prevent
 * an infinite recursion problem when adding more pages to a zone, @c zalloc
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
 * map lock. After freeing that page, the GC thread will wait in
 * @c zone_reclaim() until the replenish threads can finish.
 * Since there's only 1 GC thread at a time, that adds a minimum of 1 to the
 * reserve size.
 *
 * Since the minumum amount you can add to a zone is 1 page,
 * we'll use 16K (from ARM) as the refill size on all platforms.
 *
 * When a refill zone drops to half that available, i.e. REFILL_SIZE / 2,
 * @c zalloc_ext() will wake the replenish thread. The replenish thread runs
 * until at least REFILL_SIZE worth of free elements exist, before sleeping again.
 * In the meantime threads may continue to use the reserve until there are only
 * REFILL_SIZE / 4 elements left. Below that point only the replenish threads
 * themselves and the GC thread may continue to use from the reserve.
 */

static thread_call_data_t zone_expand_callout;

static inline kma_flags_t
zone_kma_flags(zone_t z, zalloc_flags_t flags)
{
	kma_flags_t kmaflags = KMA_KOBJECT | KMA_ZERO;

	if (z->z_noencrypt) {
		kmaflags |= KMA_NOENCRYPT;
	}
	if (flags & Z_NOPAGEWAIT) {
		kmaflags |= KMA_NOPAGEWAIT;
	}
	if (z->z_permanent || (!z->z_destructible && z->z_va_sequester)) {
		kmaflags |= KMA_PERMANENT;
	}
	if (z->z_submap_idx == Z_SUBMAP_IDX_GENERAL &&
	    z->kalloc_heap != KHEAP_ID_NONE) {
		kmaflags |= KMA_KHEAP;
	}

	return kmaflags;
}

/*!
 * @function zcram_and_lock()
 *
 * @brief
 * Prepare some memory for being usable for allocation purposes.
 *
 * @discussion
 * Prepare memory in <code>[addr + ptoa(pg_start), addr + ptoa(pg_end))</code>
 * to be usable in the zone.
 *
 * This function assumes the metadata is already populated for the range.
 *
 * Calling this function with @c pg_start being 0 means that the memory
 * is either a partial chunk, or a full chunk, that isn't published anywhere
 * and the initialization can happen without locks held.
 *
 * Calling this function with a non zero @c pg_start means that we are extending
 * an existing chunk: the memory in <code>[addr, addr + ptoa(pg_start))</code>,
 * is already usable and published in the zone, so extending it requires holding
 * the zone lock.
 *
 * @param zone          The zone to cram new populated pages into
 * @param addr          The base address for the chunk(s)
 * @param pg_va_new     The number of virtual pages newly assigned to the zone
 * @param pg_start      The first newly populated page relative to @a addr.
 * @param pg_end        The after-last newly populated page relative to @a addr.
 * @param kind          The kind of memory assigned to the zone.
 */
static void
zcram_and_lock(zone_t zone, vm_offset_t addr, uint32_t pg_va_new,
    uint32_t pg_start, uint32_t pg_end, zone_addr_kind_t kind)
{
	zone_id_t zindex = zone_index(zone);
	vm_offset_t elem_size = zone_elem_size(zone);
	uint32_t free_start = 0, free_end = 0;

	struct zone_page_metadata *meta = zone_meta_from_addr(addr);
	uint32_t chunk_pages = zone->z_chunk_pages;

	assert(pg_start < pg_end && pg_end <= chunk_pages);

	if (pg_start == 0) {
		uint16_t chunk_len = (uint16_t)pg_end;
		uint16_t secondary_len = ZM_SECONDARY_PAGE;
		bool inline_bitmap = false;

		if (zone->z_percpu) {
			chunk_len = 1;
			secondary_len = ZM_SECONDARY_PCPU_PAGE;
			assert(pg_end == zpercpu_count());
		}
		if (!zone->z_permanent) {
			inline_bitmap = zone->z_chunk_elems <= 32 * chunk_pages;
		}

		meta[0] = (struct zone_page_metadata){
			.zm_index         = zindex,
			.zm_inline_bitmap = inline_bitmap,
			.zm_chunk_len     = chunk_len,
		};
		if (kind == ZONE_ADDR_FOREIGN) {
			/* Never hit z_pageq_empty */
			meta[0].zm_alloc_size = ZM_ALLOC_SIZE_LOCK;
		}

		for (uint16_t i = 1; i < chunk_pages; i++) {
			meta[i] = (struct zone_page_metadata){
				.zm_index          = zindex,
				.zm_inline_bitmap  = inline_bitmap,
				.zm_chunk_len      = secondary_len,
				.zm_page_index     = i,
			};
		}

		free_end = (uint32_t)ptoa(chunk_len) / elem_size;
		if (!zone->z_permanent) {
			zone_meta_bits_init(meta, free_end, zone->z_chunk_elems);
		}
	} else {
		assert(!zone->z_percpu && !zone->z_permanent);

		free_end = (uint32_t)ptoa(pg_end) / elem_size;
		free_start = (uint32_t)ptoa(pg_start) / elem_size;
	}

#if VM_MAX_TAG_ZONES
	if (__improbable(zone->tags)) {
		assert(kind == ZONE_ADDR_NATIVE && !zone->z_percpu);
		ztMemoryAdd(zone, addr + ptoa(pg_start),
		    ptoa(pg_end - pg_start));
	}
#endif /* VM_MAX_TAG_ZONES */

	/*
	 * Insert the initialized pages / metadatas into the right lists.
	 */

	zone_lock(zone);
	assert(zone->z_self == zone);

	if (pg_start != 0) {
		assert(meta->zm_chunk_len == pg_start);

		zone_meta_bits_merge(meta, free_start, free_end);
		meta->zm_chunk_len = (uint16_t)pg_end;

		/*
		 * consume the zone_meta_lock_in_partial()
		 * done in zone_expand_locked()
		 */
		zone_meta_alloc_size_sub(zone, meta, ZM_ALLOC_SIZE_LOCK);
		zone_meta_remqueue(zone, meta);
	}

	if (zone->z_permanent || meta->zm_alloc_size) {
		zone_meta_queue_push(zone, &zone->z_pageq_partial, meta);
	} else {
		zone_meta_queue_push(zone, &zone->z_pageq_empty, meta);
		zone->z_wired_empty += zone->z_percpu ? 1 : pg_end;
	}
	if (pg_end < chunk_pages) {
		/* push any non populated residual VA on z_pageq_va */
		zone_meta_queue_push(zone, &zone->z_pageq_va, meta + pg_end);
	}

	zone_elems_free_add(zone, free_end - free_start);
	zone->z_elems_avail += free_end - free_start;
	zone->z_wired_cur   += zone->z_percpu ? 1 : pg_end - pg_start;
	if (pg_va_new) {
		zone->z_va_cur += zone->z_percpu ? 1 : pg_va_new;
	}
	if (zone->z_wired_hwm < zone->z_wired_cur) {
		zone->z_wired_hwm = zone->z_wired_cur;
	}

	os_atomic_add(&zones_phys_page_mapped_count, pg_end - pg_start, relaxed);
}

static void
zcram(zone_t zone, vm_offset_t addr, uint32_t pages, zone_addr_kind_t kind)
{
	uint32_t chunk_pages = zone->z_chunk_pages;

	assert(pages % chunk_pages == 0);
	for (; pages > 0; pages -= chunk_pages, addr += ptoa(chunk_pages)) {
		zcram_and_lock(zone, addr, chunk_pages, 0, chunk_pages, kind);
		zone_unlock(zone);
	}
}

void
zone_cram_foreign(zone_t zone, vm_offset_t newmem, vm_size_t size)
{
	uint32_t pages = (uint32_t)atop(size);

	if (!from_zone_map(newmem, size, ZONE_ADDR_FOREIGN)) {
		panic("zone_cram_foreign: foreign memory [%p] being crammed is "
		    "outside of expected range", (void *)newmem);
	}
	if (!zone->z_allows_foreign) {
		panic("zone_cram_foreign: foreign memory [%p] being crammed in "
		    "zone '%s%s' not expecting it", (void *)newmem,
		    zone_heap_name(zone), zone_name(zone));
	}
	if (size % ptoa(zone->z_chunk_pages)) {
		panic("zone_cram_foreign: foreign memory [%p] being crammed has "
		    "invalid size %zx", (void *)newmem, (size_t)size);
	}
	if (startup_phase >= STARTUP_SUB_ZALLOC) {
		panic("zone_cram_foreign: foreign memory [%p] being crammed "
		    "after zalloc is initialized", (void *)newmem);
	}

	bzero((void *)newmem, size);
	zcram(zone, newmem, pages, ZONE_ADDR_FOREIGN);
}

void
zone_fill_initially(zone_t zone, vm_size_t nelems)
{
	kma_flags_t kmaflags;
	kern_return_t kr;
	vm_offset_t addr;
	uint32_t pages;

	assert(!zone->z_permanent && !zone->collectable && !zone->z_destructible);
	assert(zone->z_elems_avail == 0);

	kmaflags = zone_kma_flags(zone, Z_WAITOK) | KMA_PERMANENT;
	pages = zone_alloc_pages_for_nelems(zone, nelems);
	kr = kernel_memory_allocate(zone_submap(zone), &addr, ptoa(pages),
	    0, kmaflags, VM_KERN_MEMORY_ZONE);
	if (kr != KERN_SUCCESS) {
		panic("kernel_memory_allocate() of %u pages failed", pages);
	}

	zone_meta_populate(addr, ptoa(pages));
	zcram(zone, addr, pages, ZONE_ADDR_NATIVE);
}

static vm_offset_t
zone_allocate_va(zone_t z, zalloc_flags_t flags)
{
	kma_flags_t kmaflags = zone_kma_flags(z, flags) | KMA_VAONLY;
	vm_size_t size = ptoa(z->z_chunk_pages);
	kern_return_t kr;
	vm_offset_t addr;

	kr = kernel_memory_allocate(zone_submap(z), &addr, size, 0,
	    kmaflags, VM_KERN_MEMORY_ZONE);

#if !__LP64__
	if (kr == KERN_NO_SPACE && z->z_replenishes) {
		/*
		 * On 32bit the zone submaps do not have as much VA
		 * available, so use the VA reserved map for this
		 * purpose.
		 */
		vm_map_t map = zone_submaps[Z_SUBMAP_IDX_VA_RESERVE];
		kr = kernel_memory_allocate(map, &addr, size, 0,
		    kmaflags, VM_KERN_MEMORY_ZONE);
	}
#endif

	if (kr == KERN_SUCCESS) {
#if ZALLOC_EARLY_GAPS
		if (__improbable(zone_caching_disabled < 0)) {
			zone_allocate_random_early_gap(z);
		}
#endif /* ZALLOC_EARLY_GAPS */
		zone_meta_populate(addr, size);
		return addr;
	}

	panic_include_zprint = TRUE;
#if CONFIG_ZLEAKS
	if ((zleak_state & ZLEAK_STATE_ACTIVE)) {
		panic_include_ztrace = TRUE;
	}
#endif /* CONFIG_ZLEAKS */
	zone_t zone_largest = zone_find_largest();
	panic("zalloc: zone map exhausted while allocating from zone [%s%s], "
	    "likely due to memory leak in zone [%s%s] "
	    "(%luM, %d elements allocated)",
	    zone_heap_name(z), zone_name(z),
	    zone_heap_name(zone_largest), zone_name(zone_largest),
	    (unsigned long)zone_size_wired(zone_largest) >> 20,
	    zone_count_allocated(zone_largest));
}

static bool
zone_expand_pred_nope(__unused zone_t z)
{
	return false;
}

static inline void
ZONE_TRACE_VM_KERN_REQUEST_START(vm_size_t size)
{
#if DEBUG || DEVELOPMENT
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, VM_KERN_REQUEST, DBG_FUNC_START,
	    size, 0, 0, 0);
#else
	(void)size;
#endif
}

static inline void
ZONE_TRACE_VM_KERN_REQUEST_END(uint32_t pages)
{
#if DEBUG || DEVELOPMENT
	task_t task = current_task();
	if (pages && task) {
		ledger_credit(task->ledger, task_ledgers.pages_grabbed_kern, pages);
	}
	VM_DEBUG_CONSTANT_EVENT(vm_kern_request, VM_KERN_REQUEST, DBG_FUNC_END,
	    pages, 0, 0, 0);
#else
	(void)pages;
#endif
}

static void
zone_expand_locked(zone_t z, zalloc_flags_t flags, bool (*pred)(zone_t))
{
	thread_t self = current_thread();
	bool vm_priv = (self->options & TH_OPT_VMPRIV);
	bool clear_vm_priv;

	for (;;) {
		if (!pred) {
			/* NULL pred means "try just once" */
			pred = zone_expand_pred_nope;
		} else if (!pred(z)) {
			return;
		}

		if (vm_priv && !z->z_expander_vm_priv) {
			/*
			 * Claim the vm priv overcommit slot
			 *
			 * We do not track exact ownership for VM privileged
			 * threads, so use the rwlock boost as a stop-gap
			 * just in case.
			 */
			set_thread_rwlock_boost();
			z->z_expander_vm_priv = true;
			clear_vm_priv = true;
		} else {
			clear_vm_priv = false;
		}

		if (z->z_expander == NULL) {
			z->z_expander = self;
			break;
		}
		if (clear_vm_priv) {
			break;
		}

		if (flags & Z_NOPAGEWAIT) {
			return;
		}

		z->z_expanding_wait = true;
		lck_spin_sleep_with_inheritor(&z->z_lock, LCK_SLEEP_DEFAULT,
		    &z->z_expander, z->z_expander,
		    TH_UNINT, TIMEOUT_WAIT_FOREVER);
	}

	do {
		struct zone_page_metadata *meta = NULL;
		uint32_t new_va = 0, cur_pages = 0, min_pages = 0, pages = 0;
		vm_page_t page_list = NULL;
		vm_offset_t addr = 0;
		int waited = 0;

		/*
		 * While we hold the zone lock, look if there's VA we can:
		 * - complete from partial pages,
		 * - reuse from the sequester list.
		 *
		 * When the page is being populated we pretend we allocated
		 * an extra element so that zone_gc() can't attempt to free
		 * the chunk (as it could become empty while we wait for pages).
		 */
		if (!zone_pva_is_null(z->z_pageq_va)) {
			meta = zone_meta_queue_pop_native(z,
			    &z->z_pageq_va, &addr);
			if (meta->zm_chunk_len == ZM_SECONDARY_PAGE) {
				cur_pages = meta->zm_page_index;
				meta -= cur_pages;
				addr -= ptoa(cur_pages);
				zone_meta_lock_in_partial(z, meta, cur_pages);
			}
		}
		zone_unlock(z);

		/*
		 * Do the zone leak activation here because zleak_activate()
		 * may block, and can't be done on the way out.
		 *
		 * Trigger jetsams via the vm_pageout_garbage_collect thread if
		 * we're running out of zone memory
		 */
		zleak_activate_if_needed();
		if (zone_map_nearing_exhaustion()) {
			thread_wakeup((event_t)&vm_pageout_garbage_collect);
		}

		/*
		 * And now allocate pages to populate our VA.
		 */
		if (z->z_percpu) {
			min_pages = z->z_chunk_pages;
		} else {
			min_pages = (uint32_t)atop(round_page(zone_elem_size(z)));
		}

		ZONE_TRACE_VM_KERN_REQUEST_START(ptoa(z->z_chunk_pages - cur_pages));

		while (pages < z->z_chunk_pages - cur_pages) {
			vm_page_t m = vm_page_grab();

			if (m) {
				pages++;
				m->vmp_snext = page_list;
				page_list = m;
				vm_page_zero_fill(m);
				continue;
			}

			if (pages >= min_pages && (vm_pool_low() || waited)) {
				break;
			}

			if ((flags & Z_NOPAGEWAIT) == 0) {
				waited++;
				VM_PAGE_WAIT();
				continue;
			}

			/*
			 * Undo everything and bail out:
			 *
			 * - free pages
			 * - undo the fake allocation if any
			 * - put the VA back on the VA page queue.
			 */
			vm_page_free_list(page_list, FALSE);
			ZONE_TRACE_VM_KERN_REQUEST_END(pages);

			zone_lock(z);

			if (cur_pages) {
				zone_meta_unlock_from_partial(z, meta, cur_pages);
			}
			if (meta) {
				zone_meta_queue_push(z, &z->z_pageq_va,
				    meta + cur_pages);
			}
			goto page_shortage;
		}

		/*
		 * If we didn't find pre-allocated VA, then allocate a chunk
		 * of VA here.
		 */
		if (addr == 0) {
			addr = zone_allocate_va(z, flags);
			meta = zone_meta_from_addr(addr);
			new_va = z->z_chunk_pages;
		}

		kernel_memory_populate_with_pages(zone_submap(z),
		    addr + ptoa(cur_pages), ptoa(pages), page_list,
		    zone_kma_flags(z, flags), VM_KERN_MEMORY_ZONE);

		ZONE_TRACE_VM_KERN_REQUEST_END(pages);

		zcram_and_lock(z, addr, new_va, cur_pages, cur_pages + pages,
		    ZONE_ADDR_NATIVE);
	} while (pred(z));

page_shortage:
	zleak_track_if_needed(z);

	if (clear_vm_priv) {
		z->z_expander_vm_priv = false;
		clear_thread_rwlock_boost();
	}
	if (z->z_expander == self) {
		z->z_expander = THREAD_NULL;
	}
	if (z->z_expanding_wait) {
		z->z_expanding_wait = false;
		wakeup_all_with_inheritor(&z->z_expander, THREAD_AWAKENED);
	}
}

static bool
zalloc_needs_refill(zone_t zone)
{
	if (zone->z_elems_free > zone->z_elems_rsv) {
		return false;
	}
	if (zone->z_wired_cur < zone->z_wired_max) {
		return true;
	}
	if (zone->exhaustible) {
		return false;
	}
	if (zone->expandable) {
		/*
		 * If we're expandable, just don't go through this again.
		 */
		zone->z_wired_max = ~0u;
		return true;
	}
	zone_unlock(zone);

	panic_include_zprint = true;
#if CONFIG_ZLEAKS
	if (zleak_state & ZLEAK_STATE_ACTIVE) {
		panic_include_ztrace = true;
	}
#endif /* CONFIG_ZLEAKS */
	panic("zone '%s%s' exhausted", zone_heap_name(zone), zone_name(zone));
}

static void
zone_expand_async(__unused thread_call_param_t p0, __unused thread_call_param_t p1)
{
	zone_foreach(z) {
		if (z->no_callout) {
			/* z_async_refilling will never be set */
			continue;
		}

		if (z->z_replenishes) {
			/* those use the zone_replenish_thread */
			continue;
		}

		zone_lock(z);
		if (z->z_self && z->z_async_refilling) {
			z->z_async_refilling = false;
			zone_expand_locked(z, Z_WAITOK, zalloc_needs_refill);
		}
		zone_unlock(z);
	}
}

static inline void
zone_expand_async_schedule_if_needed(zone_t zone)
{
	if (zone->z_elems_free > zone->z_elems_rsv || zone->z_async_refilling ||
	    zone->no_callout) {
		return;
	}

	if (!zone->expandable && zone->z_wired_cur >= zone->z_wired_max) {
		return;
	}

	if (zone->z_elems_free == 0 || !vm_pool_low()) {
		zone->z_async_refilling = true;
		thread_call_enter(&zone_expand_callout);
	}
}

#endif /* !ZALLOC_TEST */
#pragma mark zone replenishing (VM allocations)
#if !ZALLOC_TEST

/*
 * Tracks how many zone_replenish threads are active, because zone_gc() wants
 * for those to be finished before it proceeds.
 *
 * This counts how many replenish threads are active in
 * ZONE_REPLENISH_ACTIVE_INC increments,
 * and uses the low bit to track if there are any waiters.
 */
#define ZONE_REPLENISH_ACTIVE_NONE        0u
#define ZONE_REPLENISH_ACTIVE_WAITER_BIT  1u
#define ZONE_REPLENISH_ACTIVE_INC         2u
#define ZONE_REPLENISH_ACTIVE_MASK        (~ZONE_REPLENISH_ACTIVE_WAITER_BIT)
static unsigned _Atomic zone_replenish_active;
static unsigned zone_replenish_wakeups;
static unsigned zone_replenish_wakeups_initiated;
static unsigned zone_replenish_throttle_count;

#define ZONE_REPLENISH_TARGET (16 * 1024)

static void
zone_replenish_wait_if_needed(void)
{
	/*
	 * This check can be racy, the reserves ought to be enough
	 * to compensate for a little race
	 */
	while (os_atomic_load(&zone_replenish_active, relaxed) !=
	    ZONE_REPLENISH_ACTIVE_NONE) {
		unsigned o_active, n_active;

		assert_wait(&zone_replenish_active, THREAD_UNINT);

		os_atomic_rmw_loop(&zone_replenish_active, o_active, n_active, relaxed, {
			if (o_active == ZONE_REPLENISH_ACTIVE_NONE) {
			        os_atomic_rmw_loop_give_up({
					clear_wait(current_thread(), THREAD_AWAKENED);
					return;
				});
			}
			if (o_active & ZONE_REPLENISH_ACTIVE_WAITER_BIT) {
			        os_atomic_rmw_loop_give_up(break);
			}
			n_active = o_active | ZONE_REPLENISH_ACTIVE_WAITER_BIT;
		});
		thread_block(THREAD_CONTINUE_NULL);
	}
}

__attribute__((noinline))
static void
zone_replenish_locked(zone_t zone)
{
	thread_t thr = current_thread();
	uint32_t min_free;

	zone_replenish_wakeups++;

	/*
	 * We'll let threads continue to allocate under the reserve:
	 * - until it depleted to 50% for regular threads,
	 * - until it depleted to 25% for VM_PRIV threads.
	 *
	 * After that only TH_OPT_ZONE_PRIV threads may continue.
	 */
	if (thr->options & TH_OPT_VMPRIV) {
		min_free = zone->z_elems_rsv / 4;
	} else {
		min_free = zone->z_elems_rsv / 2;
	}

	while (zone->z_elems_free <= zone->z_elems_rsv) {
		/*
		 * Wakeup the replenish thread if not running.
		 */
		if (!zone->z_async_refilling) {
			os_atomic_add(&zone_replenish_active,
			    ZONE_REPLENISH_ACTIVE_INC, relaxed);
			zone->z_async_refilling = true;
			zone_replenish_wakeups_initiated++;
			thread_wakeup(&zone->z_elems_rsv);
		}

		if (zone->z_elems_free > min_free) {
			break;
		}

		/*
		 * TH_OPT_ZONE_PRIV threads are the GC thread and a replenish
		 * thread itself.
		 *
		 * Replenish threads *need* to use the reserve. GC threads need
		 * to get through the current allocation, but then will wait at
		 * a higher level after they've dropped any locks which would
		 * deadlock the replenish thread.
		 *
		 * The value of (refill_level / 2) in the previous bit of code
		 * should have given us headroom even though this thread didn't
		 * wait.
		 */
		if (thr->options & TH_OPT_ZONE_PRIV) {
			assert(zone->z_elems_free != 0);
			break;
		}

		if (startup_phase < STARTUP_SUB_MACH_IPC) {
			panic("vm_map_steal_memory didn't steal enough memory: "
			    "trying to grow [%s%s] before the scheduler has started",
			    zone_heap_name(zone), zone_name(zone));
		}

		/*
		 * Wait for the replenish threads to add more elements
		 * for us to allocate from.
		 */
		zone_replenish_throttle_count++;
		zone->z_replenish_wait = true;
		assert_wait_timeout(zone, THREAD_UNINT, 1, NSEC_PER_MSEC);
		zone_unlock(zone);
		thread_block(THREAD_CONTINUE_NULL);
		zone_lock(zone);
		zone->z_replenish_wait = false;

		assert(zone->z_self == zone);
	}
}

static bool
zone_replenish_needed(zone_t z)
{
	return z->z_elems_free <= z->z_elems_rsv;
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
	unsigned o_active, n_active;
	zone_t z = _z;

	zone_lock(z);
	assert(z->z_self == z);
	assert(z->z_async_refilling && z->z_replenishes);

	zone_expand_locked(z, Z_WAITOK, zone_replenish_needed);

	if (z->z_replenish_wait) {
		/* Wakeup any potentially throttled allocations */
		z->z_replenish_wait = false;
		thread_wakeup(z);
	}

	/* wakeup zone_reclaim() callers that were possibly waiting */
	os_atomic_rmw_loop(&zone_replenish_active, o_active, n_active, relaxed, {
		if (os_sub_overflow(o_active, ZONE_REPLENISH_ACTIVE_INC, &n_active)) {
		        panic("zone_replenish_active corrupt: %d", o_active);
		}
		if ((n_active & ZONE_REPLENISH_ACTIVE_MASK) == 0) {
		        n_active = ZONE_REPLENISH_ACTIVE_NONE;
		}
	});

	if (n_active == ZONE_REPLENISH_ACTIVE_NONE &&
	    (o_active & ZONE_REPLENISH_ACTIVE_WAITER_BIT)) {
		thread_wakeup(&zone_replenish_active);
	}

	z->z_async_refilling = false;
	assert_wait(&z->z_elems_rsv, THREAD_UNINT);

	zone_unlock(z);

	thread_block_parameter(zone_replenish_thread, z);
	__builtin_unreachable();
}

void
zone_replenish_configure(zone_t z)
{
	thread_t th;
	kern_return_t kr;
	char name[MAXTHREADNAMESIZE];

	zone_lock(z);
	assert(!z->z_replenishes && !z->z_destructible);
	z->z_elems_rsv = (uint16_t)(ZONE_REPLENISH_TARGET / zone_elem_size(z));
	z->z_replenishes = true;
	os_atomic_add(&zone_replenish_active, ZONE_REPLENISH_ACTIVE_INC, relaxed);
	z->z_async_refilling = true;
	zone_unlock(z);

	kr = kernel_thread_create(zone_replenish_thread, z, MAXPRI_KERNEL, &th);
	if (kr != KERN_SUCCESS) {
		panic("zone_replenish_configure, thread create: 0x%x", kr);
	}
	/* make sure this thread can't lose its stack */
	assert(th->reserved_stack == th->kernel_stack);

	snprintf(name, sizeof(name), "z_replenish(%s)", zone_name(z));
	thread_set_thread_name(th, name);

	thread_mtx_lock(th);
	th->options |= TH_OPT_VMPRIV | TH_OPT_ZONE_PRIV;
	thread_start(th);
	thread_mtx_unlock(th);

	thread_deallocate(th);
}

/*! @} */
#endif /* !ZALLOC_TEST */
#pragma mark zone jetsam integration
#if !ZALLOC_TEST

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
	*capacity = ptoa_64(zone_phys_mapped_max_pages);
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

bool
zone_map_nearing_exhaustion(void)
{
	uint64_t phys_pages = os_atomic_load(&zones_phys_page_mapped_count, relaxed);
	return phys_pages * 100 > zone_phys_mapped_max_pages * zone_map_jetsam_limit;
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

	printf("zone_map_exhaustion: Zone mapped %lld of %lld, used %lld, capacity %lld [jetsam limit %d%%]\n",
	    ptoa_64(os_atomic_load(&zones_phys_page_mapped_count, relaxed)),
	    ptoa_64(zone_phys_mapped_max_pages),
	    (uint64_t)zone_submaps_approx_size(),
	    (uint64_t)(zone_foreign_size() + zone_native_size()),
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

#endif /* !ZALLOC_TEST */
#pragma mark zfree
#if !ZALLOC_TEST
#if KASAN_ZALLOC

/*!
 * @defgroup zfree
 * @{
 *
 * @brief
 * The codepath for zone frees.
 *
 * @discussion
 * There are 4 major ways to allocate memory that end up in the zone allocator:
 * - @c zfree()
 * - @c zfree_percpu()
 * - @c kfree*()
 * - @c zfree_permanent()
 *
 * While permanent zones have their own allocation scheme, all other codepaths
 * will eventually go through the @c zfree_ext() choking point.
 *
 * Ignoring the @c gzalloc_free() codepath, the decision tree looks like this:
 * <code>
 * zfree_ext()
 *      ├───> zfree_cached() ────────────────╮
 *      │       │                            │
 *      │       │                            │
 *      │       ├───> zfree_cached_slow() ───┤
 *      │       │            │               │
 *      │       │            v               │
 *      ╰───────┴───> zfree_item() ──────────┴───>
 * </code>
 *
 * @c zfree_ext() takes care of all the generic work to perform on an element
 * before it is freed (zeroing, logging, tagging, ...) then will hand it off to:
 * - @c zfree_item() if zone caching is off
 * - @c zfree_cached() if zone caching is on.
 *
 * @c zfree_cached can take a number of decisions:
 * - a fast path if the (f) or (a) magazines have space (preemption disabled),
 * - using the cpu local or recirculation depot calling @c zfree_cached_slow(),
 * - falling back to @c zfree_item() when CPU caching has been disabled.
 */

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
	vm_size_t usersz = zone_elem_size(zone) - 2 * zone->z_kasan_redzone;
	vm_size_t sz = usersz;

	if (addr && zone->z_kasan_redzone) {
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

__header_always_inline void
zfree_drop(zone_t zone, struct zone_page_metadata *meta, zone_element_t ze,
    bool recirc)
{
	vm_offset_t esize = zone_elem_size(zone);

	if (zone_meta_mark_free(meta, ze) == recirc) {
		zone_meta_double_free_panic(zone, ze, __func__);
	}

	vm_offset_t old_size = meta->zm_alloc_size;
	vm_offset_t max_size = ptoa(meta->zm_chunk_len) + ZM_ALLOC_SIZE_LOCK;
	vm_offset_t new_size = zone_meta_alloc_size_sub(zone, meta, esize);

	if (new_size == 0) {
		/* whether the page was on the intermediate or all_used, queue, move it to free */
		zone_meta_requeue(zone, &zone->z_pageq_empty, meta);
		zone->z_wired_empty += meta->zm_chunk_len;
	} else if (old_size + esize > max_size) {
		/* first free element on page, move from all_used */
		zone_meta_requeue(zone, &zone->z_pageq_partial, meta);
	}
}

static void
zfree_item(zone_t zone, struct zone_page_metadata *meta, zone_element_t ze)
{
	/* transfer preemption count to lock */
	zone_lock_nopreempt_check_contention(zone, NULL);

	zfree_drop(zone, meta, ze, false);
	zone_elems_free_add(zone, 1);

	zone_unlock(zone);
}

__attribute__((noinline))
static void
zfree_cached_slow(zone_t zone, struct zone_page_metadata *meta,
    zone_element_t ze, zone_cache_t cache)
{
	struct zone_depot mags = STAILQ_HEAD_INITIALIZER(mags);
	zone_magazine_t mag = NULL;
	uint16_t n = 0;

	if (zone_meta_is_free(meta, ze)) {
		zone_meta_double_free_panic(zone, ze, __func__);
	}

	if (zone == zc_magazine_zone) {
		mag = (zone_magazine_t)zone_element_addr(ze,
		    zone_elem_size(zone));
#if KASAN_ZALLOC
		kasan_poison_range((vm_offset_t)mag, zone_elem_size(zone),
		    ASAN_VALID);
#endif
	} else {
		mag = zone_magazine_alloc(Z_NOWAIT);
		if (__improbable(mag == NULL)) {
			return zfree_item(zone, meta, ze);
		}
		mag->zm_cur = 1;
		mag->zm_elems[0] = ze;
	}

	mag = zone_magazine_replace(&cache->zc_free_cur,
	    &cache->zc_free_elems, mag);

	z_debug_assert(cache->zc_free_cur <= 1);
	z_debug_assert(mag->zm_cur == zc_mag_size());

	STAILQ_INSERT_HEAD(&mags, mag, zm_link);
	n = 1;

	if (cache->zc_depot_max >= 2 * zc_mag_size()) {
		/*
		 * If we can use the local depot (zc_depot_max allows for
		 * 2 magazines worth of elements) then:
		 *
		 * 1. if we have space for an extra depot locally,
		 *    push it, and leave.
		 *
		 * 2. if we overflow, then take (1 / zc_recirc_denom)
		 *    of the depot out, in order to migrate it to the
		 *    recirculation depot.
		 */
		zone_depot_lock_nopreempt(cache);

		if ((cache->zc_depot_cur + 2) * zc_mag_size() <=
		    cache->zc_depot_max) {
			cache->zc_depot_cur++;
			STAILQ_INSERT_TAIL(&cache->zc_depot, mag, zm_link);
			return zone_depot_unlock(cache);
		}

		while (zc_recirc_denom * cache->zc_depot_cur * zc_mag_size() >=
		    (zc_recirc_denom - 1) * cache->zc_depot_max) {
			mag = STAILQ_FIRST(&cache->zc_depot);
			STAILQ_REMOVE_HEAD(&cache->zc_depot, zm_link);
			STAILQ_INSERT_TAIL(&mags, mag, zm_link);
			cache->zc_depot_cur--;
			n++;
		}

		zone_depot_unlock(cache);
	} else {
		enable_preemption();
	}

	/*
	 * Preflight validity of all the elements before we touch the zone
	 * metadata, and then insert them into the recirculation depot.
	 */
	STAILQ_FOREACH(mag, &mags, zm_link) {
		for (uint16_t i = 0; i < zc_mag_size(); i++) {
			zone_element_validate(zone, mag->zm_elems[i]);
		}
	}

	zone_lock_check_contention(zone, cache);

	STAILQ_FOREACH(mag, &mags, zm_link) {
		for (uint16_t i = 0; i < zc_mag_size(); i++) {
			zone_element_t e = mag->zm_elems[i];

			if (!zone_meta_mark_free(zone_meta_from_element(e), e)) {
				zone_meta_double_free_panic(zone, e, __func__);
			}
		}
	}
	STAILQ_CONCAT(&zone->z_recirc, &mags);
	zone->z_recirc_cur += n;

	zone_elems_free_add(zone, n * zc_mag_size());

	zone_unlock(zone);
}

static void
zfree_cached(zone_t zone, struct zone_page_metadata *meta, zone_element_t ze)
{
	zone_cache_t cache = zpercpu_get(zone->z_pcpu_cache);

	if (cache->zc_free_cur >= zc_mag_size()) {
		if (cache->zc_alloc_cur >= zc_mag_size()) {
			return zfree_cached_slow(zone, meta, ze, cache);
		}
		zone_cache_swap_magazines(cache);
	}

	if (__improbable(cache->zc_alloc_elems == NULL)) {
		return zfree_item(zone, meta, ze);
	}

	if (zone_meta_is_free(meta, ze)) {
		zone_meta_double_free_panic(zone, ze, __func__);
	}

	uint16_t idx = cache->zc_free_cur++;
	if (idx >= zc_mag_size()) {
		zone_accounting_panic(zone, "zc_free_cur overflow");
	}
	cache->zc_free_elems[idx] = ze;

	enable_preemption();
}

/*
 *     The function is noinline when zlog can be used so that the backtracing can
 *     reliably skip the zfree_ext() and zfree_log_trace()
 *     boring frames.
 */
#if ZONE_ENABLE_LOGGING
__attribute__((noinline))
#endif /* ZONE_ENABLE_LOGGING */
void
zfree_ext(zone_t zone, zone_stats_t zstats, void *addr)
{
	struct zone_page_metadata *page_meta;
	vm_offset_t     elem = (vm_offset_t)addr;
	vm_size_t       elem_size = zone_elem_size(zone);
	zone_element_t  ze;

	DTRACE_VM2(zfree, zone_t, zone, void*, addr);
	TRACE_MACHLEAKS(ZFREE_CODE, ZFREE_CODE_2, elem_size, elem);
#if VM_MAX_TAG_ZONES
	if (__improbable(zone->tags)) {
		vm_tag_t tag = *ztSlot(zone, elem) >> 1;
		// set the tag with b0 clear so the block remains inuse
		*ztSlot(zone, elem) = 0xFFFE;
		vm_tag_update_zone_size(tag, zone->tag_zone_index,
		    -(long)elem_size);
	}
#endif /* VM_MAX_TAG_ZONES */

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
#if ZONE_ENABLE_LOGGING
	if (__improbable(DO_LOGGING(zone))) {
		zfree_log_trace(zone, elem, __builtin_frame_address(0));
	}
#endif /* ZONE_ENABLE_LOGGING */
#if CONFIG_GZALLOC
	if (__improbable(zone->gzalloc_tracked)) {
		return gzalloc_free(zone, zstats, addr);
	}
#endif /* CONFIG_GZALLOC */

	page_meta = zone_element_resolve(zone, elem, elem_size, &ze);
	ze.ze_value |= zfree_clear_or_poison(zone, elem, elem_size);
#if KASAN_ZALLOC
	if (zone->z_percpu) {
		zpercpu_foreach_cpu(i) {
			kasan_poison_range(elem + ptoa(i), elem_size,
			    ASAN_HEAP_FREED);
		}
	} else {
		kasan_poison_range(elem, elem_size, ASAN_HEAP_FREED);
	}
#endif

	disable_preemption();
	zpercpu_get(zstats)->zs_mem_freed += elem_size;

	if (zone->z_pcpu_cache) {
		return zfree_cached(zone, page_meta, ze);
	}

	return zfree_item(zone, page_meta, ze);
}

void
(zfree)(union zone_or_view zov, void *addr)
{
	zone_t zone = zov.zov_view->zv_zone;
	zone_stats_t zstats = zov.zov_view->zv_stats;
	assert(!zone->z_percpu);
	zfree_ext(zone, zstats, addr);
}

void
zfree_percpu(union zone_or_view zov, void *addr)
{
	zone_t zone = zov.zov_view->zv_zone;
	zone_stats_t zstats = zov.zov_view->zv_stats;
	assert(zone->z_percpu);
	zfree_ext(zone, zstats, (void *)__zpcpu_demangle(addr));
}

/*! @} */
#endif /* !ZALLOC_TEST */
#pragma mark zalloc
#if !ZALLOC_TEST

/*!
 * @defgroup zalloc
 * @{
 *
 * @brief
 * The codepath for zone allocations.
 *
 * @discussion
 * There are 4 major ways to allocate memory that end up in the zone allocator:
 * - @c zalloc(), @c zalloc_flags(), ...
 * - @c zalloc_percpu()
 * - @c kalloc*()
 * - @c zalloc_permanent()
 *
 * While permanent zones have their own allocation scheme, all other codepaths
 * will eventually go through the @c zalloc_ext() choking point.
 *
 * Ignoring the @c zalloc_gz() codepath, the decision tree looks like this:
 * <code>
 * zalloc_ext()
 *      │
 *      ├───> zalloc_cached() ──────> zalloc_cached_fast() ───╮
 *      │         │                             ^             │
 *      │         │                             │             │
 *      │         ╰───> zalloc_cached_slow() ───╯             │
 *      │                         │                           │
 *      │<─────────────────╮      ├─────────────╮             │
 *      │                  │      │             │             │
 *      │                  │      v             │             │
 *      │<───────╮  ╭──> zalloc_item_slow() ────┤             │
 *      │        │  │                           │             │
 *      │        │  │                           v             │
 *      ╰───> zalloc_item() ──────────> zalloc_item_fast() ───┤
 *                                                            │
 *                                                            v
 *                                                     zalloc_return()
 * </code>
 *
 *
 * The @c zalloc_item() track is used when zone caching is off:
 * - @c zalloc_item_fast() is used when there are enough elements available,
 * - @c zalloc_item_slow() is used when a refill is needed, which can cause
 *   the zone to grow. This is the only codepath that refills.
 *
 * This track uses the zone lock for serialization:
 * - taken in @c zalloc_item(),
 * - maintained during @c zalloc_item_slow() (possibly dropped and re-taken),
 * - dropped in @c zalloc_item_fast().
 *
 *
 * The @c zalloc_cached() track is used when zone caching is on:
 * - @c zalloc_cached_fast() is taken when the cache has elements,
 * - @c zalloc_cached_slow() is taken if a cache refill is needed.
 *   It can chose many strategies:
 *    ~ @c zalloc_cached_from_depot() to try to reuse cpu stashed magazines,
 *    ~ using the global recirculation depot @c z_recirc,
 *    ~ using zalloc_import() if the zone has enough elements,
 *    ~ falling back to the @c zalloc_item() track if zone caching is disabled
 *      due to VM pressure or the zone has no available elements.
 *
 * This track disables preemption for serialization:
 * - preemption is disabled in @c zalloc_cached(),
 * - kept disabled during @c zalloc_cached_slow(), converted into a zone lock
 *   if switching to @c zalloc_item_slow(),
 * - preemption is reenabled in @c zalloc_cached_fast().
 *
 * @c zalloc_cached_from_depot() also takes depot locks (taken by the caller,
 * released by @c zalloc_cached_from_depot().
 *
 * In general the @c zalloc_*_slow() codepaths deal with refilling and will
 * tail call into the @c zalloc_*_fast() code to perform the actual allocation.
 *
 * @c zalloc_return() is the final function everyone tail calls into,
 * which prepares the element for consumption by the caller and deals with
 * common treatment (zone logging, tags, kasan, validation, ...).
 */

/*!
 * @function zalloc_import
 *
 * @brief
 * Import @c n elements in the specified array, opposite of @c zfree_drop().
 *
 * @param zone          The zone to import elements from
 * @param elems         The array to import into
 * @param n             The number of elements to import. Must be non zero,
 *                      and smaller than @c zone->z_elems_free.
 */
__header_always_inline void
zalloc_import(zone_t zone, zone_element_t *elems, uint32_t n)
{
	vm_size_t esize = zone_elem_size(zone);
	uint32_t i = 0;

	assertf(STAILQ_EMPTY(&zone->z_recirc),
	    "Trying to import from zone %p [%s%s] with non empty recirc",
	    zone, zone_heap_name(zone), zone_name(zone));

	do {
		vm_offset_t page, eidx, size = 0;
		struct zone_page_metadata *meta;

		if (!zone_pva_is_null(zone->z_pageq_partial)) {
			meta = zone_pva_to_meta(zone->z_pageq_partial);
			page = zone_pva_to_addr(zone->z_pageq_partial);
		} else if (!zone_pva_is_null(zone->z_pageq_empty)) {
			meta = zone_pva_to_meta(zone->z_pageq_empty);
			page = zone_pva_to_addr(zone->z_pageq_empty);
			zone_counter_sub(zone, z_wired_empty, meta->zm_chunk_len);
		} else {
			zone_accounting_panic(zone, "z_elems_free corruption");
		}

		if (!zone_has_index(zone, meta->zm_index)) {
			zone_page_metadata_index_confusion_panic(zone, page, meta);
		}

		vm_offset_t old_size = meta->zm_alloc_size;
		vm_offset_t max_size = ptoa(meta->zm_chunk_len) + ZM_ALLOC_SIZE_LOCK;

		do {
			eidx = zone_meta_find_and_clear_bit(zone, meta);
			elems[i++] = zone_element_encode(page, eidx, ZPM_AUTO);
			size += esize;
		} while (i < n && old_size + size + esize <= max_size);

		vm_offset_t new_size = zone_meta_alloc_size_add(zone, meta, size);

		if (new_size + esize > max_size) {
			zone_meta_requeue(zone, &zone->z_pageq_full, meta);
		} else if (old_size == 0) {
			/* remove from free, move to intermediate */
			zone_meta_requeue(zone, &zone->z_pageq_partial, meta);
		}
	} while (i < n);
}

/*!
 * @function zalloc_return
 *
 * @brief
 * Performs the tail-end of the work required on allocations before the caller
 * uses them.
 *
 * @discussion
 * This function is called without any zone lock held,
 * and preemption back to the state it had when @c zalloc_ext() was called.
 *
 * @param zone          The zone we're allocating from.
 * @param ze            The encoded element we just allocated.
 * @param flags         The flags passed to @c zalloc_ext() (for Z_ZERO).
 * @param elem_size     The element size for this zone.
 * @param freemag       An optional magazine that needs to be freed.
 */
__attribute__((noinline))
static void *
zalloc_return(zone_t zone, zone_element_t ze, zalloc_flags_t flags,
    vm_offset_t elem_size, zone_magazine_t freemag)
{
	vm_offset_t addr = zone_element_addr(ze, elem_size);

#if KASAN_ZALLOC
	if (zone->z_percpu) {
		zpercpu_foreach_cpu(i) {
			kasan_poison_range(addr + ptoa(i), elem_size,
			    ASAN_VALID);
		}
	} else {
		kasan_poison_range(addr, elem_size, ASAN_VALID);
	}
#endif
#if ZALLOC_ENABLE_POISONING
	zalloc_validate_element(zone, addr, elem_size, zone_element_prot(ze));
#endif /* ZALLOC_ENABLE_POISONING */
#if ZONE_ENABLE_LOGGING || CONFIG_ZLEAKS
	if (__improbable(zalloc_should_log_or_trace_leaks(zone, elem_size))) {
		zalloc_log_or_trace_leaks(zone, addr, __builtin_frame_address(0));
	}
#endif /* ZONE_ENABLE_LOGGING || CONFIG_ZLEAKS */
#if KASAN_ZALLOC
	if (zone->z_kasan_redzone) {
		addr = kasan_alloc(addr, elem_size,
		    elem_size - 2 * zone->z_kasan_redzone,
		    zone->z_kasan_redzone);
		elem_size -= 2 * zone->z_kasan_redzone;
	}
	/*
	 * Initialize buffer with unique pattern only if memory
	 * wasn't expected to be zeroed.
	 */
	if (!zone->z_free_zeroes && !(flags & Z_ZERO)) {
		kasan_leak_init(addr, elem_size);
	}
#endif /* KASAN_ZALLOC */
	if ((flags & Z_ZERO) && !zone->z_free_zeroes) {
		bzero((void *)addr, elem_size);
	}

#if VM_MAX_TAG_ZONES
	if (__improbable(zone->tags)) {
		vm_tag_t tag = zalloc_flags_get_tag(flags);
		if (tag == VM_KERN_MEMORY_NONE) {
			tag = VM_KERN_MEMORY_KALLOC;
		}
		// set the tag with b0 clear so the block remains inuse
		*ztSlot(zone, addr) = (vm_tag_t)(tag << 1);
		vm_tag_update_zone_size(tag, zone->tag_zone_index,
		    (long)elem_size);
	}
#endif /* VM_MAX_TAG_ZONES */

	TRACE_MACHLEAKS(ZALLOC_CODE, ZALLOC_CODE_2, elem_size, addr);
	DTRACE_VM2(zalloc, zone_t, zone, void*, addr);
	if (freemag) {
		zone_magazine_free(freemag);
	}
	return (void *)addr;
}

#if CONFIG_GZALLOC
/*!
 * @function zalloc_gz
 *
 * @brief
 * Performs allocations for zones using gzalloc.
 *
 * @discussion
 * This function is noinline so that it doesn't affect the codegen
 * of the fastpath.
 */
__attribute__((noinline))
static void *
zalloc_gz(zone_t zone, zone_stats_t zstats, zalloc_flags_t flags)
{
	vm_offset_t addr = gzalloc_alloc(zone, zstats, flags);
	return zalloc_return(zone, zone_element_encode(addr, 0, ZPM_AUTO),
	           flags, zone_elem_size(zone), NULL);
}
#endif /* CONFIG_GZALLOC */

static void *
zalloc_item_fast(zone_t zone, zone_stats_t zstats, zalloc_flags_t flags)
{
	vm_size_t esize = zone_elem_size(zone);
	zone_element_t ze;

	zalloc_import(zone, &ze, 1);
	zone_elems_free_sub(zone, 1);
	zpercpu_get(zstats)->zs_mem_allocated += esize;
	zone_unlock(zone);

	return zalloc_return(zone, ze, flags, esize, NULL);
}

/*!
 * @function zalloc_item_slow
 *
 * @brief
 * Performs allocations when the zone is out of elements.
 *
 * @discussion
 * This function might drop the lock and reenable preemption,
 * which means the per-CPU caching layer or recirculation depot
 * might have received elements.
 */
__attribute__((noinline))
static void *
zalloc_item_slow(zone_t zone, zone_stats_t zstats, zalloc_flags_t flags)
{
	if (zone->z_replenishes) {
		zone_replenish_locked(zone);
	} else {
		if ((flags & Z_NOWAIT) == 0) {
			zone_expand_locked(zone, flags, zalloc_needs_refill);
		}
		if (flags & (Z_NOWAIT | Z_NOPAGEWAIT)) {
			zone_expand_async_schedule_if_needed(zone);
		}
		if (__improbable(zone->z_elems_free == 0)) {
			zone_unlock(zone);
			if (__improbable(flags & Z_NOFAIL)) {
				zone_nofail_panic(zone);
			}
			DTRACE_VM2(zalloc, zone_t, zone, void*, NULL);
			return NULL;
		}
	}

	/*
	 * We might have changed core or got preempted/blocked while expanding
	 * the zone. Allocating from the zone when the recirculation depot
	 * is not empty is not allowed.
	 *
	 * It will be rare but possible for the depot to refill while we were
	 * waiting for pages. If that happens we need to start over.
	 */
	if (!STAILQ_EMPTY(&zone->z_recirc)) {
		zone_unlock(zone);
		return zalloc_ext(zone, zstats, flags);
	}

	return zalloc_item_fast(zone, zstats, flags);
}

/*!
 * @function zalloc_item
 *
 * @brief
 * Performs allocations when zone caching is off.
 *
 * @discussion
 * This function calls @c zalloc_item_slow() when refilling the zone
 * is needed, or @c zalloc_item_fast() if the zone has enough free elements.
 */
static void *
zalloc_item(zone_t zone, zone_stats_t zstats, zalloc_flags_t flags)
{
	zone_lock_check_contention(zone, NULL);

	/*
	 * When we commited to the zalloc_item() path,
	 * zone caching might have been flipped/enabled.
	 *
	 * If we got preempted for long enough, the recirculation layer
	 * can have been populated, and allocating from the zone would be
	 * incorrect.
	 *
	 * So double check for this extremely rare race here.
	 */
	if (__improbable(!STAILQ_EMPTY(&zone->z_recirc))) {
		zone_unlock(zone);
		return zalloc_ext(zone, zstats, flags);
	}

	if (__improbable(zone->z_elems_free <= zone->z_elems_rsv)) {
		return zalloc_item_slow(zone, zstats, flags);
	}

	return zalloc_item_fast(zone, zstats, flags);
}

static void *
zalloc_cached_fast(zone_t zone, zone_stats_t zstats, zalloc_flags_t flags,
    zone_cache_t cache, zone_magazine_t freemag)
{
	vm_offset_t esize = zone_elem_size(zone);
	zone_element_t ze;
	uint32_t index;

	index = --cache->zc_alloc_cur;
	if (index >= zc_mag_size()) {
		zone_accounting_panic(zone, "zc_alloc_cur wrap around");
	}
	ze = cache->zc_alloc_elems[index];
	cache->zc_alloc_elems[index].ze_value = 0;

	zpercpu_get(zstats)->zs_mem_allocated += esize;
	enable_preemption();

	if (zone_meta_is_free(zone_meta_from_element(ze), ze)) {
		zone_meta_double_free_panic(zone, ze, __func__);
	}

	return zalloc_return(zone, ze, flags, esize, freemag);
}

static void *
zalloc_cached_from_depot(zone_t zone, zone_stats_t zstats, zalloc_flags_t flags,
    zone_cache_t cache, zone_cache_t depot, zone_magazine_t mag)
{
	STAILQ_REMOVE_HEAD(&depot->zc_depot, zm_link);
	if (depot->zc_depot_cur-- == 0) {
		zone_accounting_panic(zone, "zc_depot_cur wrap-around");
	}
	zone_depot_unlock_nopreempt(depot);

	mag = zone_magazine_replace(&cache->zc_alloc_cur,
	    &cache->zc_alloc_elems, mag);

	z_debug_assert(cache->zc_alloc_cur == zc_mag_size());
	z_debug_assert(mag->zm_cur == 0);

	if (zone == zc_magazine_zone) {
		enable_preemption();
		bzero(mag, zone_elem_size(zone));
		return mag;
	}

	return zalloc_cached_fast(zone, zstats, flags, cache, mag);
}

__attribute__((noinline))
static void *
zalloc_cached_slow(zone_t zone, zone_stats_t zstats, zalloc_flags_t flags,
    zone_cache_t cache)
{
	zone_magazine_t mag = NULL;
	struct zone_depot mags = STAILQ_HEAD_INITIALIZER(mags);

	/*
	 * Try to allocate from our local depot, if there's one.
	 */
	if (STAILQ_FIRST(&cache->zc_depot)) {
		zone_depot_lock_nopreempt(cache);

		if ((mag = STAILQ_FIRST(&cache->zc_depot)) != NULL) {
			return zalloc_cached_from_depot(zone, zstats, flags,
			           cache, cache, mag);
		}

		zone_depot_unlock_nopreempt(cache);
	}

	zone_lock_nopreempt_check_contention(zone, cache);

	/*
	 * If the recirculation depot is empty, we'll need to import.
	 * The system is tuned for this to be extremely rare.
	 */
	if (__improbable(STAILQ_EMPTY(&zone->z_recirc))) {
		uint16_t n_elems = zc_mag_size();

		if (zone->z_elems_free < n_elems + zone->z_elems_rsv / 2 &&
		    os_sub_overflow(zone->z_elems_free,
		    zone->z_elems_rsv / 2, &n_elems)) {
			n_elems = 0;
		}

		z_debug_assert(n_elems <= zc_mag_size());

		if (__improbable(n_elems == 0)) {
			/*
			 * If importing elements would deplete the zone,
			 * call zalloc_item_slow()
			 */
			return zalloc_item_slow(zone, zstats, flags);
		}

		if (__improbable(zone_caching_disabled)) {
			if (__improbable(zone_caching_disabled < 0)) {
				/*
				 * In the first 10s after boot, mess with
				 * the scan position in order to make early
				 * allocations patterns less predictible.
				 */
				zone_early_scramble_rr(zone, zstats);
			}
			return zalloc_item_fast(zone, zstats, flags);
		}

		zalloc_import(zone, cache->zc_alloc_elems, n_elems);

		cache->zc_alloc_cur = n_elems;
		zone_elems_free_sub(zone, n_elems);

		zone_unlock_nopreempt(zone);

		return zalloc_cached_fast(zone, zstats, flags, cache, NULL);
	}

	uint16_t n_mags = 0;

	/*
	 * If the recirculation depot has elements, then try to fill
	 * the local per-cpu depot to (1 / zc_recirc_denom)
	 */
	do {
		mag = STAILQ_FIRST(&zone->z_recirc);
		STAILQ_REMOVE_HEAD(&zone->z_recirc, zm_link);
		STAILQ_INSERT_TAIL(&mags, mag, zm_link);
		n_mags++;

		for (uint16_t i = 0; i < zc_mag_size(); i++) {
			zone_element_t e = mag->zm_elems[i];

			if (!zone_meta_mark_used(zone_meta_from_element(e), e)) {
				zone_meta_double_free_panic(zone, e, __func__);
			}
		}
	} while (!STAILQ_EMPTY(&zone->z_recirc) &&
	    zc_recirc_denom * n_mags * zc_mag_size() <= cache->zc_depot_max);

	zone_elems_free_sub(zone, n_mags * zc_mag_size());
	zone_counter_sub(zone, z_recirc_cur, n_mags);

	zone_unlock_nopreempt(zone);

	/*
	 * And then incorporate everything into our per-cpu layer.
	 */
	mag = STAILQ_FIRST(&mags);
	STAILQ_REMOVE_HEAD(&mags, zm_link);
	mag = zone_magazine_replace(&cache->zc_alloc_cur,
	    &cache->zc_alloc_elems, mag);
	z_debug_assert(cache->zc_alloc_cur == zc_mag_size());
	z_debug_assert(mag->zm_cur == 0);

	if (--n_mags > 0) {
		zone_depot_lock_nopreempt(cache);
		cache->zc_depot_cur += n_mags;
		STAILQ_CONCAT(&cache->zc_depot, &mags);
		zone_depot_unlock_nopreempt(cache);
	}

	return zalloc_cached_fast(zone, zstats, flags, cache, mag);
}

/*!
 * @function zalloc_cached
 *
 * @brief
 * Performs allocations when zone caching is on.
 *
 * @discussion
 * This function calls @c zalloc_cached_fast() when the caches have elements
 * ready.
 *
 * Else it will call @c zalloc_cached_slow() so that the cache is refilled,
 * which might switch to the @c zalloc_item_slow() track when the backing zone
 * needs to be refilled.
 */
static void *
zalloc_cached(zone_t zone, zone_stats_t zstats, zalloc_flags_t flags)
{
	zone_cache_t cache;

	disable_preemption();
	cache = zpercpu_get(zone->z_pcpu_cache);

	if (cache->zc_alloc_cur == 0) {
		if (__improbable(cache->zc_free_cur == 0)) {
			return zalloc_cached_slow(zone, zstats, flags, cache);
		}
		zone_cache_swap_magazines(cache);
	}

	return zalloc_cached_fast(zone, zstats, flags, cache, NULL);
}

/*!
 * @function zalloc_ext
 *
 * @brief
 * The core implementation of @c zalloc(), @c zalloc_flags(), @c zalloc_percpu().
 */
void *
zalloc_ext(zone_t zone, zone_stats_t zstats, zalloc_flags_t flags)
{
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
	if (zone->z_replenishes) {
		assert((flags & (Z_NOWAIT | Z_NOPAGEWAIT)) == 0);
	} else if (flags & Z_NOFAIL) {
		assert(!zone->exhaustible &&
		    (flags & (Z_NOWAIT | Z_NOPAGEWAIT)) == 0);
	}

#if CONFIG_GZALLOC
	if (__improbable(zone->gzalloc_tracked)) {
		return zalloc_gz(zone, zstats, flags);
	}
#endif /* CONFIG_GZALLOC */

	if (zone->z_pcpu_cache) {
		return zalloc_cached(zone, zstats, flags);
	}

	return zalloc_item(zone, zstats, flags);
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
	assert(!zone->z_percpu);
	return zalloc_ext(zone, zstats, flags);
}

void *
zalloc_percpu(union zone_or_view zov, zalloc_flags_t flags)
{
	zone_t zone = zov.zov_view->zv_zone;
	zone_stats_t zstats = zov.zov_view->zv_stats;
	assert(zone->z_percpu);
	return (void *)__zpcpu_mangle(zalloc_ext(zone, zstats, flags));
}

static void *
_zalloc_permanent(zone_t zone, vm_size_t size, vm_offset_t mask)
{
	struct zone_page_metadata *page_meta;
	vm_offset_t offs, addr;
	zone_pva_t pva;

	assert(ml_get_interrupts_enabled() ||
	    ml_is_quiescing() ||
	    debug_mode_active() ||
	    startup_phase < STARTUP_SUB_EARLY_BOOT);

	size = (size + mask) & ~mask;
	assert(size <= PAGE_SIZE);

	zone_lock(zone);
	assert(zone->z_self == zone);

	for (;;) {
		pva = zone->z_pageq_partial;
		while (!zone_pva_is_null(pva)) {
			page_meta = zone_pva_to_meta(pva);
			if (page_meta->zm_bump + size <= PAGE_SIZE) {
				goto found;
			}
			pva = page_meta->zm_page_next;
		}

		zone_expand_locked(zone, Z_WAITOK, NULL);
	}

found:
	offs = (uint16_t)((page_meta->zm_bump + mask) & ~mask);
	page_meta->zm_bump = (uint16_t)(offs + size);
	page_meta->zm_alloc_size += size;
	zone->z_elems_free -= size;
	zpercpu_get(zone->z_stats)->zs_mem_allocated += size;

	if (page_meta->zm_alloc_size >= PAGE_SIZE - sizeof(vm_offset_t)) {
		zone_meta_requeue(zone, &zone->z_pageq_full, page_meta);
	}

	zone_unlock(zone);

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

/*! @} */
#endif /* !ZALLOC_TEST */
#pragma mark zone GC / trimming
#if !ZALLOC_TEST

static thread_call_data_t zone_defrag_callout;

static void
zone_reclaim_chunk(zone_t z, struct zone_page_metadata *meta, uint32_t free_count)
{
	vm_address_t page_addr;
	vm_size_t    size_to_free;
	uint32_t     bitmap_ref;
	uint32_t     page_count;
	bool         sequester = z->z_va_sequester && !z->z_destroyed;

	zone_meta_queue_pop_native(z, &z->z_pageq_empty, &page_addr);

	page_count = meta->zm_chunk_len;

	if (meta->zm_alloc_size) {
		zone_metadata_corruption(z, meta, "alloc_size");
	}
	if (z->z_percpu) {
		if (page_count != 1) {
			zone_metadata_corruption(z, meta, "page_count");
		}
		size_to_free = ptoa(z->z_chunk_pages);
		os_atomic_sub(&zones_phys_page_mapped_count,
		    z->z_chunk_pages, relaxed);
	} else {
		if (page_count > z->z_chunk_pages) {
			zone_metadata_corruption(z, meta, "page_count");
		}
		if (page_count < z->z_chunk_pages) {
			/* Dequeue non populated VA from z_pageq_va */
			zone_meta_remqueue(z, meta + page_count);
		}
		size_to_free = ptoa(page_count);
		os_atomic_sub(&zones_phys_page_mapped_count, page_count, relaxed);
	}

	zone_counter_sub(z, z_elems_free, free_count);
	zone_counter_sub(z, z_elems_avail, free_count);
	zone_counter_sub(z, z_wired_empty, page_count);
	zone_counter_sub(z, z_wired_cur, page_count);
	if (z->z_elems_free_min < free_count) {
		z->z_elems_free_min = 0;
	} else {
		z->z_elems_free_min -= free_count;
	}
	if (z->z_elems_free_max < free_count) {
		z->z_elems_free_max = 0;
	} else {
		z->z_elems_free_max -= free_count;
	}

	bitmap_ref = 0;
	if (sequester) {
		if (meta->zm_inline_bitmap) {
			for (int i = 0; i < meta->zm_chunk_len; i++) {
				meta[i].zm_bitmap = 0;
			}
		} else {
			bitmap_ref = meta->zm_bitmap;
			meta->zm_bitmap = 0;
		}
		meta->zm_chunk_len = 0;
	} else {
		if (!meta->zm_inline_bitmap) {
			bitmap_ref = meta->zm_bitmap;
		}
		zone_counter_sub(z, z_va_cur, z->z_percpu ? 1 : z->z_chunk_pages);
		bzero(meta, sizeof(*meta) * z->z_chunk_pages);
	}

	zone_unlock(z);

	if (bitmap_ref) {
		zone_bits_free(bitmap_ref);
	}

	/* Free the pages for metadata and account for them */
#if KASAN_ZALLOC
	kasan_poison_range(page_addr, size_to_free, ASAN_VALID);
#endif
#if VM_MAX_TAG_ZONES
	if (z->tags) {
		ztMemoryRemove(z, page_addr, size_to_free);
	}
#endif /* VM_MAX_TAG_ZONES */

	if (sequester) {
		kernel_memory_depopulate(zone_submap(z), page_addr,
		    size_to_free, KMA_KOBJECT, VM_KERN_MEMORY_ZONE);
	} else {
		kmem_free(zone_submap(z), page_addr, ptoa(z->z_chunk_pages));
	}

	/*
	 * Freeing memory sometimes needs some (for example vm map entries
	 * to represent holes).
	 *
	 * If there are any active replenish threads, we need to let them work
	 * while we hold no locks. Only do so right after we just freed memory
	 * once however to give them even more chances to find fresh pages.
	 */
	zone_replenish_wait_if_needed();

	thread_yield_to_preemption();

	zone_lock(z);

	if (sequester) {
		zone_meta_queue_push(z, &z->z_pageq_va, meta);
	}
}

static uint16_t
zone_reclaim_elements(zone_t z, uint16_t *count, zone_element_t *elems)
{
	uint16_t n = *count;

	z_debug_assert(n <= zc_mag_size());

	for (uint16_t i = 0; i < n; i++) {
		zone_element_t ze = elems[i];
		elems[i].ze_value = 0;
		zfree_drop(z, zone_element_validate(z, ze), ze, false);
	}

	*count = 0;
	return n;
}

static uint16_t
zone_reclaim_recirc_magazine(zone_t z, struct zone_depot *mags)
{
	zone_magazine_t mag = STAILQ_FIRST(&z->z_recirc);

	STAILQ_REMOVE_HEAD(&z->z_recirc, zm_link);
	STAILQ_INSERT_TAIL(mags, mag, zm_link);
	zone_counter_sub(z, z_recirc_cur, 1);

	z_debug_assert(mag->zm_cur == zc_mag_size());

	for (uint16_t i = 0; i < zc_mag_size(); i++) {
		zone_element_t ze = mag->zm_elems[i];
		mag->zm_elems[i].ze_value = 0;
		zfree_drop(z, zone_element_validate(z, ze), ze, true);
	}

	mag->zm_cur = 0;

	return zc_mag_size();
}

static void
zone_depot_trim(zone_cache_t zc, struct zone_depot *head)
{
	zone_magazine_t mag;

	if (zc->zc_depot_cur == 0 ||
	    2 * (zc->zc_depot_cur + 1) * zc_mag_size() <= zc->zc_depot_max) {
		return;
	}

	zone_depot_lock(zc);

	while (zc->zc_depot_cur &&
	    2 * (zc->zc_depot_cur + 1) * zc_mag_size() > zc->zc_depot_max) {
		mag = STAILQ_FIRST(&zc->zc_depot);
		STAILQ_REMOVE_HEAD(&zc->zc_depot, zm_link);
		STAILQ_INSERT_TAIL(head, mag, zm_link);
		zc->zc_depot_cur--;
	}

	zone_depot_unlock(zc);
}

__enum_decl(zone_reclaim_mode_t, uint32_t, {
	ZONE_RECLAIM_TRIM,
	ZONE_RECLAIM_DRAIN,
	ZONE_RECLAIM_DESTROY,
});

/*!
 * @function zone_reclaim
 *
 * @brief
 * Drains or trim the zone.
 *
 * @discussion
 * Draining the zone will free it from all its elements.
 *
 * Trimming the zone tries to respect the working set size, and avoids draining
 * the depot when it's not necessary.
 *
 * @param z             The zone to reclaim from
 * @param mode          The purpose of this reclaim.
 */
static void
zone_reclaim(zone_t z, zone_reclaim_mode_t mode)
{
	struct zone_depot mags = STAILQ_HEAD_INITIALIZER(mags);
	zone_magazine_t mag, tmp;

	zone_lock(z);

	if (mode == ZONE_RECLAIM_DESTROY) {
		if (!z->z_destructible || z->z_pcpu_cache ||
		    z->z_elems_rsv || z->z_allows_foreign) {
			panic("zdestroy: Zone %s%s isn't destructible",
			    zone_heap_name(z), z->z_name);
		}

		if (!z->z_self || z->z_expander || z->z_expander_vm_priv ||
		    z->z_async_refilling || z->z_expanding_wait) {
			panic("zdestroy: Zone %s%s in an invalid state for destruction",
			    zone_heap_name(z), z->z_name);
		}

#if !KASAN_ZALLOC
		/*
		 * Unset the valid bit. We'll hit an assert failure on further
		 * operations on this zone, until zinit() is called again.
		 *
		 * Leave the zone valid for KASan as we will see zfree's on
		 * quarantined free elements even after the zone is destroyed.
		 */
		z->z_self = NULL;
#endif
		z->z_destroyed = true;
	} else if (z->z_destroyed) {
		return zone_unlock(z);
	} else if (z->z_replenishes && z->z_async_refilling) {
		/*
		 * If the zone is replenishing, leave it alone.
		 */
		return zone_unlock(z);
	}

	if (z->z_pcpu_cache) {
		if (mode != ZONE_RECLAIM_TRIM) {
			zpercpu_foreach(zc, z->z_pcpu_cache) {
				zc->zc_depot_max /= 2;
			}
		} else {
			zpercpu_foreach(zc, z->z_pcpu_cache) {
				if (zc->zc_depot_max > 0) {
					zc->zc_depot_max--;
				}
			}
		}

		zone_unlock(z);

		if (mode == ZONE_RECLAIM_TRIM) {
			zpercpu_foreach(zc, z->z_pcpu_cache) {
				zone_depot_trim(zc, &mags);
			}
		} else {
			zpercpu_foreach(zc, z->z_pcpu_cache) {
				zone_depot_lock(zc);
				STAILQ_CONCAT(&mags, &zc->zc_depot);
				zc->zc_depot_cur = 0;
				zone_depot_unlock(zc);
			}
		}

		zone_lock(z);

		uint32_t freed = 0;

		STAILQ_FOREACH(mag, &mags, zm_link) {
			freed += zone_reclaim_elements(z,
			    &mag->zm_cur, mag->zm_elems);

			if (freed >= zc_free_batch_size) {
				z->z_elems_free_min += freed;
				z->z_elems_free_max += freed;
				z->z_elems_free += freed;
				zone_unlock(z);
				thread_yield_to_preemption();
				zone_lock(z);
				freed = 0;
			}
		}

		if (mode == ZONE_RECLAIM_DESTROY) {
			zpercpu_foreach(zc, z->z_pcpu_cache) {
				freed += zone_reclaim_elements(z,
				    &zc->zc_alloc_cur, zc->zc_alloc_elems);
				freed += zone_reclaim_elements(z,
				    &zc->zc_free_cur, zc->zc_free_elems);
			}

			z->z_elems_free_wss = 0;
			z->z_elems_free_min = 0;
			z->z_elems_free_max = 0;
			z->z_contention_cur = 0;
			z->z_contention_wma = 0;
		} else {
			z->z_elems_free_min += freed;
			z->z_elems_free_max += freed;
		}
		z->z_elems_free += freed;
	}

	for (;;) {
		struct zone_page_metadata *meta;
		uint32_t count, goal, freed = 0;

		goal = z->z_elems_rsv;
		if (mode == ZONE_RECLAIM_TRIM) {
			/*
			 * When trimming, only free elements in excess
			 * of the working set estimate.
			 *
			 * However if we are in a situation where the working
			 * set estimate is clearly growing, ignore the estimate
			 * as the next working set update will grow it and
			 * we want to avoid churn.
			 */
			goal = MAX(goal, MAX(z->z_elems_free_wss,
			    z->z_elems_free - z->z_elems_free_min));

			/*
			 * Add some slop to account for "the last partial chunk in flight"
			 * so that we do not deplete the recirculation depot too harshly.
			 */
			goal += z->z_chunk_elems / 2;
		}

		if (z->z_elems_free <= goal) {
			break;
		}

		/*
		 * If we're above target, but we have no free page, then drain
		 * the recirculation depot until we get a free chunk or exhaust
		 * the depot.
		 *
		 * This is rather abrupt but also somehow will reduce
		 * fragmentation anyway, and the zone code will import
		 * over time anyway.
		 */
		while (z->z_recirc_cur) {
			if (z->z_recirc_cur * zc_mag_size() <= goal &&
			    !zone_pva_is_null(z->z_pageq_empty)) {
				break;
			}
			if (freed >= zc_free_batch_size) {
				zone_unlock(z);
				thread_yield_to_preemption();
				zone_lock(z);
				freed = 0;
				/* we dropped the lock, needs to reassess */
				continue;
			}
			freed += zone_reclaim_recirc_magazine(z, &mags);
		}

		if (zone_pva_is_null(z->z_pageq_empty)) {
			break;
		}

		meta  = zone_pva_to_meta(z->z_pageq_empty);
		count = (uint32_t)ptoa(meta->zm_chunk_len) / zone_elem_size(z);

		if (z->z_elems_free - count < goal) {
			break;
		}

		zone_reclaim_chunk(z, meta, count);
	}

	zone_unlock(z);

	STAILQ_FOREACH_SAFE(mag, &mags, zm_link, tmp) {
		zone_magazine_free(mag);
	}
}

static void
zone_reclam_all(zone_reclaim_mode_t mode)
{
	/*
	 * Start with zones with VA sequester since depopulating
	 * pages will not need to allocate vm map entries for holes,
	 * which will give memory back to the system faster.
	 */
	zone_foreach(z) {
		if (z == zc_magazine_zone) {
			continue;
		}
		if (z->z_va_sequester && z->collectable) {
			zone_reclaim(z, mode);
		}
	}

	zone_foreach(z) {
		if (z == zc_magazine_zone) {
			continue;
		}
		if (!z->z_va_sequester && z->collectable) {
			zone_reclaim(z, mode);
		}
	}

	zone_reclaim(zc_magazine_zone, mode);
}

void
zone_gc(zone_gc_level_t level)
{
	zone_reclaim_mode_t mode;

	switch (level) {
	case ZONE_GC_TRIM:
		mode = ZONE_RECLAIM_TRIM;
		break;
	case ZONE_GC_DRAIN:
		mode = ZONE_RECLAIM_DRAIN;
		break;
	case ZONE_GC_JETSAM:
		kill_process_in_largest_zone();
		mode = ZONE_RECLAIM_TRIM;
		break;
	}

	current_thread()->options |= TH_OPT_ZONE_PRIV;
	lck_mtx_lock(&zone_gc_lock);

	zone_reclam_all(mode);

	if (level == ZONE_GC_JETSAM && zone_map_nearing_exhaustion()) {
		/*
		 * If we possibly killed a process, but we're still critical,
		 * we need to drain harder.
		 */
		zone_reclam_all(ZONE_RECLAIM_DRAIN);
	}

	lck_mtx_unlock(&zone_gc_lock);
	current_thread()->options &= ~TH_OPT_ZONE_PRIV;
}

void
zone_gc_trim(void)
{
	zone_gc(ZONE_GC_TRIM);
}

void
zone_gc_drain(void)
{
	zone_gc(ZONE_GC_DRAIN);
}

static bool
zone_defrag_needed(zone_t z)
{
	uint32_t recirc_size = z->z_recirc_cur * zc_mag_size();

	if (recirc_size <= z->z_chunk_elems / 2) {
		return false;
	}
	return recirc_size * zc_defrag_ratio > z->z_elems_free_wss * 100;
}

/*!
 * @function zone_defrag_async
 *
 * @brief
 * Resize the recirculation depot to match the working set size.
 *
 * @discussion
 * When zones grow very large due to a spike in usage, and then some of those
 * elements get freed, the elements in magazines in the recirculation depot
 * are in no particular order.
 *
 * In order to control fragmentation, we need to detect "empty" pages so that
 * they get onto the @c z_pageq_empty freelist, so that allocations re-pack
 * naturally.
 *
 * This is done very gently, never in excess of the working set and some slop.
 */
static void
zone_defrag_async(__unused thread_call_param_t p0, __unused thread_call_param_t p1)
{
	zone_foreach(z) {
		struct zone_depot mags = STAILQ_HEAD_INITIALIZER(mags);
		zone_magazine_t mag, tmp;
		uint32_t freed = 0, goal = 0;

		if (!z->collectable || !zone_defrag_needed(z)) {
			continue;
		}

		zone_lock(z);

		goal = z->z_elems_free_wss + z->z_chunk_elems / 2 +
		    zc_mag_size() - 1;

		while (z->z_recirc_cur * zc_mag_size() > goal) {
			if (freed >= zc_free_batch_size) {
				zone_unlock(z);
				thread_yield_to_preemption();
				zone_lock(z);
				freed = 0;
				/* we dropped the lock, needs to reassess */
				continue;
			}
			freed += zone_reclaim_recirc_magazine(z, &mags);
		}

		zone_unlock(z);

		STAILQ_FOREACH_SAFE(mag, &mags, zm_link, tmp) {
			zone_magazine_free(mag);
		}
	}
}

void
compute_zone_working_set_size(__unused void *param)
{
	uint32_t zc_auto = zc_auto_threshold;
	bool kick_defrag = false;

	/*
	 * Keep zone caching disabled until the first proc is made.
	 */
	if (__improbable(zone_caching_disabled < 0)) {
		return;
	}

	zone_caching_disabled = vm_pool_low();
#if ZALLOC_EARLY_GAPS
	zone_cleanup_early_gaps_if_needed();
#endif

	if (os_mul_overflow(zc_auto, Z_CONTENTION_WMA_UNIT, &zc_auto)) {
		zc_auto = 0;
	}

	zone_foreach(z) {
		uint32_t wma;
		bool needs_caching = false;

		if (z->z_self != z) {
			continue;
		}

		zone_lock(z);

		wma = z->z_elems_free_max - z->z_elems_free_min;
		wma = (3 * wma + z->z_elems_free_wss) / 4;
		z->z_elems_free_max = z->z_elems_free_min = z->z_elems_free;
		z->z_elems_free_wss = wma;

		if (!kick_defrag && zone_defrag_needed(z)) {
			kick_defrag = true;
		}

		/* fixed point decimal of contentions per second */
		wma = z->z_contention_cur * Z_CONTENTION_WMA_UNIT /
		    ZONE_WSS_UPDATE_PERIOD;
		z->z_contention_cur = 0;
		z->z_contention_wma = (3 * wma + z->z_contention_wma) / 4;

		/*
		 * If the zone seems to be very quiet,
		 * gently lower its cpu-local depot size.
		 */
		if (z->z_pcpu_cache && wma < Z_CONTENTION_WMA_UNIT / 2 &&
		    z->z_contention_wma < Z_CONTENTION_WMA_UNIT / 2) {
			zpercpu_foreach(zc, z->z_pcpu_cache) {
				if (zc->zc_depot_max > zc_mag_size()) {
					zc->zc_depot_max--;
				}
			}
		}

		/*
		 * If the zone has been contending like crazy for two periods,
		 * and is eligible, maybe it's time to enable caching.
		 */
		if (!z->z_nocaching && !z->z_pcpu_cache && !z->exhaustible &&
		    zc_auto && z->z_contention_wma >= zc_auto && wma >= zc_auto) {
			needs_caching = true;
		}

		zone_unlock(z);

		if (needs_caching) {
			zone_enable_caching(z);
		}
	}

	if (kick_defrag) {
		thread_call_enter(&zone_defrag_callout);
	}
}

#endif /* !ZALLOC_TEST */
#pragma mark vm integration, MIG routines
#if !ZALLOC_TEST

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
	vm_size_t cached = 0;

	assert(z != ZONE_NULL);
	zone_lock(z);
	if (!z->z_self) {
		zone_unlock(z);
		return FALSE;
	}
	zcopy = *z;
	if (z->z_pcpu_cache) {
		zpercpu_foreach(zc, z->z_pcpu_cache) {
			cached += zc->zc_alloc_cur + zc->zc_free_cur;
			cached += zc->zc_depot_cur * zc_mag_size();
		}
	}
	zone_unlock(z);

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
			.mzi_count = zone_count_allocated(&zcopy) - cached,
			.mzi_cur_size = ptoa_64(zone_scale_for_percpu(&zcopy, zcopy.z_wired_cur)),
			// max_size for zprint is now high-watermark of pages used
			.mzi_max_size = ptoa_64(zone_scale_for_percpu(&zcopy, zcopy.z_wired_hwm)),
			.mzi_elem_size = zone_scale_for_percpu(&zcopy, zcopy.z_elem_size),
			.mzi_alloc_size = ptoa_64(zcopy.z_chunk_pages),
			.mzi_exhaustible = (uint64_t)zcopy.exhaustible,
		};
		zpercpu_foreach(zs, zcopy.z_stats) {
			zi->mzi_sum_size += zs->zs_mem_allocated;
		}
		if (zcopy.collectable) {
			SET_MZI_COLLECTABLE_BYTES(zi->mzi_collectable,
			    ptoa_64(zone_scale_for_percpu(&zcopy, zcopy.z_wired_empty)));
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
	zone_foreach(z) {
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

	zone_foreach(z) {
		if (get_zone_info(z, NULL, &zi)) {
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
	zone_foreach(z) {
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
	zone_foreach(z) {
		zonestotal += zone_size_wired(z);
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
	zone_gc(ZONE_GC_DRAIN);
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

#endif /* !ZALLOC_TEST */
#pragma mark zone creation, configuration, destruction
#if !ZALLOC_TEST

static zone_t
zone_init_defaults(zone_id_t zid)
{
	zone_t z = &zone_array[zid];

	z->z_wired_max = ~0u;
	z->collectable = true;
	z->expandable = true;
	z->z_submap_idx = Z_SUBMAP_IDX_GENERAL;

	lck_spin_init(&z->z_lock, &zone_locks_grp, LCK_ATTR_NULL);
	STAILQ_INIT(&z->z_recirc);
	return z;
}

static bool
zone_is_initializing(zone_t z)
{
	return !z->z_self && !z->z_destroyed;
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
	zone->z_submap_idx = sub_map_idx;
}

void
zone_set_noexpand(zone_t zone, vm_size_t nelems)
{
	if (!zone_is_initializing(zone)) {
		panic("%s: called after zone_create()", __func__);
	}
	zone->expandable = false;
	zone->z_wired_max = zone_alloc_pages_for_nelems(zone, nelems);
}

void
zone_set_exhaustible(zone_t zone, vm_size_t nelems)
{
	if (!zone_is_initializing(zone)) {
		panic("%s: called after zone_create()", __func__);
	}
	zone->expandable = false;
	zone->exhaustible = true;
	zone->z_wired_max = zone_alloc_pages_for_nelems(zone, nelems);
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
 * @param zid_inout     the desired zone ID or ZONE_ID_ANY
 *
 * @returns             a zone to initialize further.
 */
static zone_t
zone_create_find(
	const char             *name,
	vm_size_t               size,
	zone_create_flags_t     flags,
	zone_id_t              *zid_inout)
{
	zone_id_t nzones, zid = *zid_inout;
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
				z->z_destroyed = false;
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

	*zid_inout = zid;
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
	zone_create_flags_t     flags __unused,
	uint32_t               *redzone __unused)
{
	vm_size_t size;
	/*
	 * Adjust element size for minimum size and pointer alignment
	 */
	size = (elem_size + sizeof(vm_offset_t) - 1) & -sizeof(vm_offset_t);
	if (size < ZONE_MIN_ELEM_SIZE) {
		size = ZONE_MIN_ELEM_SIZE;
	}

#if KASAN_ZALLOC
	/*
	 * Expand the zone allocation size to include the redzones.
	 *
	 * For page-multiple zones add a full guard page because they
	 * likely require alignment.
	 */
	uint32_t redzone_tmp;
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
	zone_id_t               zid,
	void                  (^extra_setup)(zone_t))
{
	vm_size_t alloc;
	uint32_t redzone;
	zone_t z;

	if (size > ZONE_MAX_ALLOC_SIZE) {
		panic("zone_create: element size too large: %zd", (size_t)size);
	}

	if (size < 2 * sizeof(vm_size_t)) {
		/* Elements are too small for kasan. */
		flags |= ZC_KASAN_NOQUARANTINE | ZC_KASAN_NOREDZONE;
	}

	size = zone_elem_adjust_size(name, size, flags, &redzone);
	/*
	 * Allocate the zone slot, return early if we found an older match.
	 */
	z = zone_create_find(name, size, flags, &zid);
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
	if (__probable(zone_array[ZONE_ID_PERCPU_PERMANENT].z_self)) {
		z->z_stats = zalloc_percpu_permanent_type(struct zone_stats);
	} else {
		/*
		 * zone_init() hasn't run yet, use the storage provided by
		 * zone_stats_startup(), and zone_init() will replace it
		 * with the final value once the PERCPU zone exists.
		 */
		z->z_stats = __zpcpu_mangle_for_boot(&zone_stats_startup[zone_index(z)]);
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

	z->z_elem_size = (uint16_t)size;
	z->z_chunk_pages = (uint16_t)atop(alloc);
	if (flags & ZC_PERCPU) {
		z->z_chunk_elems = (uint16_t)(PAGE_SIZE / z->z_elem_size);
	} else {
		z->z_chunk_elems = (uint16_t)(alloc / z->z_elem_size);
	}
	if (zone_element_idx(zone_element_encode(0,
	    z->z_chunk_elems - 1, ZPM_AUTO)) != z->z_chunk_elems - 1) {
		panic("zone_element_encode doesn't work for zone [%s]", name);
	}

#if KASAN_ZALLOC
	z->z_kasan_redzone = redzone;
	if (strncmp(name, "fakestack.", sizeof("fakestack.") - 1) == 0) {
		z->kasan_fakestacks = true;
	}
#endif

	/*
	 * Handle KPI flags
	 */
#if __LP64__
	if (flags & ZC_SEQUESTER) {
		z->z_va_sequester = true;
	}
#endif
	/* ZC_CACHING applied after all configuration is done */
	if (flags & ZC_NOCACHING) {
		z->z_nocaching = true;
	}

	if (flags & ZC_PERCPU) {
		/*
		 * ZC_ZFREE_CLEARMEM is forced because per-cpu zones allow for
		 * pointer-sized allocations which poisoning doesn't support.
		 */
		zone_create_assert_not_both(name, flags, ZC_PERCPU, ZC_ALLOW_FOREIGN);
		z->z_percpu = true;
		z->gzalloc_exempt = true;
		z->z_free_zeroes = true;
	}
	if (flags & ZC_ZFREE_CLEARMEM) {
		z->z_free_zeroes = true;
	}
	if (flags & ZC_NOGC) {
		z->collectable = false;
	}
	if (flags & ZC_NOENCRYPT) {
		z->z_noencrypt = true;
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
		zone_create_assert_not_both(name, flags, ZC_DESTRUCTIBLE, ZC_ALLOW_FOREIGN);
		z->z_destructible = true;
	}

	/*
	 * Handle Internal flags
	 */
	if (flags & ZC_ALLOW_FOREIGN) {
		z->z_allows_foreign = true;
	}
	if ((ZSECURITY_OPTIONS_SUBMAP_USER_DATA & zsecurity_options) &&
	    (flags & ZC_DATA_BUFFERS)) {
		z->z_submap_idx = Z_SUBMAP_IDX_BAG_OF_BYTES;
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
	if (z->gzalloc_tracked) {
		z->z_nocaching = true;
	}
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
		z->z_submap_idx = Z_SUBMAP_IDX_BAG_OF_BYTES;
	}
#if __LP64__
	if ((ZSECURITY_OPTIONS_SEQUESTER & zsecurity_options) &&
	    (flags & ZC_NOSEQUESTER) == 0 &&
	    z->z_submap_idx == Z_SUBMAP_IDX_GENERAL) {
		z->z_va_sequester = true;
	}
#endif
	/*
	 * Clear entire element for non data zones and upto zp_min_size for
	 * data zones.
	 */
	if (z->z_submap_idx != Z_SUBMAP_IDX_BAG_OF_BYTES) {
		z->z_free_zeroes = true;
	} else if (size <= zp_min_size) {
		z->z_free_zeroes = true;
	}

	if ((flags & ZC_CACHING) && !z->z_nocaching) {
		/*
		 * If zcache hasn't been initialized yet, remember our decision,
		 *
		 * zone_enable_caching() will be called again by
		 * zcache_bootstrap(), while the system is still single
		 * threaded, to build the missing caches.
		 */
		if (__probable(zc_magazine_zone)) {
			zone_enable_caching(z);
		} else {
			z->z_pcpu_cache =
			    __zpcpu_mangle_for_boot(&zone_cache_startup[zid]);
		}
	}

	if (zp_factor != 0 && !z->z_free_zeroes) {
		if (__probable(zone_array[ZONE_ID_PERCPU_PERMANENT].z_self)) {
			zpercpu_foreach(zs, z->z_stats) {
				zs->zs_poison_seqno = zone_poison_count_init(z);
			}
		} else {
			zone_stats_startup[zid].zs_poison_seqno =
			    zone_poison_count_init(z);
		}
	}

	zone_lock(z);
	z->z_self = z;
	zone_unlock(z);

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
	z->z_wired_max = zone_alloc_pages_for_nelems(z, max / size);
	return z;
}

void
zdestroy(zone_t z)
{
	unsigned int zindex = zone_index(z);

	current_thread()->options |= TH_OPT_ZONE_PRIV;
	lck_mtx_lock(&zone_gc_lock);

	zone_reclaim(z, ZONE_RECLAIM_DESTROY);

	lck_mtx_unlock(&zone_gc_lock);
	current_thread()->options &= ~TH_OPT_ZONE_PRIV;

#if CONFIG_GZALLOC
	if (__improbable(z->gzalloc_tracked)) {
		/* If the zone is gzalloc managed dump all the elements in the free cache */
		gzalloc_empty_free_cache(z);
	}
#endif

	zone_lock(z);

	while (!zone_pva_is_null(z->z_pageq_va)) {
		struct zone_page_metadata *meta;
		vm_offset_t free_addr;

		zone_counter_sub(z, z_va_cur, z->z_percpu ? 1 : z->z_chunk_pages);
		meta = zone_meta_queue_pop_native(z, &z->z_pageq_va, &free_addr);
		assert(meta->zm_chunk_len <= ZM_CHUNK_LEN_MAX);
		bzero(meta, sizeof(*meta) * z->z_chunk_pages);
		zone_unlock(z);
		kmem_free(zone_submap(z), free_addr, ptoa(z->z_chunk_pages));
		zone_lock(z);
	}

#if !KASAN_ZALLOC
	/* Assert that all counts are zero */
	if (z->z_elems_avail || z->z_elems_free ||
	    zone_size_wired(z) || z->z_va_cur) {
		panic("zdestroy: Zone %s%s isn't empty at zdestroy() time",
		    zone_heap_name(z), z->z_name);
	}

	/* consistency check: make sure everything is indeed empty */
	assert(zone_pva_is_null(z->z_pageq_empty));
	assert(zone_pva_is_null(z->z_pageq_partial));
	assert(zone_pva_is_null(z->z_pageq_full));
	assert(zone_pva_is_null(z->z_pageq_va));
#endif

	zone_unlock(z);

	simple_lock(&all_zones_lock, &zone_locks_grp);

	assert(!bitmap_test(zone_destroyed_bitmap, zindex));
	/* Mark the zone as empty in the bitmap */
	bitmap_set(zone_destroyed_bitmap, zindex);
	num_zones_in_use--;
	assert(num_zones_in_use > 0);

	simple_unlock(&all_zones_lock);
}

#endif /* !ZALLOC_TEST */
#pragma mark zalloc module init
#if !ZALLOC_TEST

/*
 *	Initialize the "zone of zones" which uses fixed memory allocated
 *	earlier in memory initialization.  zone_bootstrap is called
 *	before zone_init.
 */
__startup_func
void
zone_bootstrap(void)
{
	/* Validate struct zone_packed_virtual_address expectations */
	static_assert((intptr_t)VM_MIN_KERNEL_ADDRESS < 0, "the top bit must be 1");
	if (VM_KERNEL_POINTER_SIGNIFICANT_BITS - PAGE_SHIFT > 31) {
		panic("zone_pva_t can't pack a kernel page address in 31 bits");
	}

	zpercpu_early_count = ml_early_cpu_max_number() + 1;

	/* Set up zone element poisoning */
	zp_bootstrap();

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

	thread_call_setup_with_options(&zone_expand_callout,
	    zone_expand_async, NULL, THREAD_CALL_PRIORITY_HIGH,
	    THREAD_CALL_OPTIONS_ONCE);

	thread_call_setup_with_options(&zone_defrag_callout,
	    zone_defrag_async, NULL, THREAD_CALL_PRIORITY_USER,
	    THREAD_CALL_OPTIONS_ONCE);
}

#if __LP64__
#if ARM_LARGE_MEMORY || __x86_64__
#define ZONE_MAP_VIRTUAL_SIZE_LP64      (128ULL * 1024ULL * 1024 * 1024)
#else
#define ZONE_MAP_VIRTUAL_SIZE_LP64      (32ULL * 1024ULL * 1024 * 1024)
#endif
#endif /* __LP64__ */

#define ZONE_GUARD_SIZE                 (64UL << 10)

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
	if (zc_magazine_size > PAGE_SIZE / ZONE_MIN_ELEM_SIZE) {
		zc_magazine_size = (uint16_t)(PAGE_SIZE / ZONE_MIN_ELEM_SIZE);
	}
}
STARTUP(TUNABLES, STARTUP_RANK_MIDDLE, zone_tunables_fixup);

__startup_func
static vm_size_t
zone_phys_size_max(void)
{
	vm_size_t zsize;
	vm_size_t zsizearg;

	if (PE_parse_boot_argn("zsize", &zsizearg, sizeof(zsizearg))) {
		zsize = zsizearg * (1024ULL * 1024);
	} else {
		/* Set target zone size as 1/4 of physical memory */
		zsize = (vm_size_t)(sane_size >> 2);
#if defined(__LP64__)
		zsize += zsize >> 1;
#endif /* __LP64__ */
	}

	if (zsize < CONFIG_ZONE_MAP_MIN) {
		zsize = CONFIG_ZONE_MAP_MIN;   /* Clamp to min */
	}
	if (zsize > sane_size >> 1) {
		zsize = (vm_size_t)(sane_size >> 1); /* Clamp to half of RAM max */
	}
	if (zsizearg == 0 && zsize > ZONE_MAP_MAX) {
		/* if zsize boot-arg not present and zsize exceeds platform maximum, clip zsize */
		printf("NOTE: zonemap size reduced from 0x%lx to 0x%lx\n",
		    (uintptr_t)zsize, (uintptr_t)ZONE_MAP_MAX);
		zsize = ZONE_MAP_MAX;
	}

	return (vm_size_t)trunc_page(zsize);
}

__options_decl(zone_init_allocate_flags_t, unsigned, {
	ZIA_NONE      = 0x00000000,
	ZIA_REPLACE   = 0x00000001, /* replace a previous non permanent range */
	ZIA_RANDOM    = 0x00000002, /* place at a random address              */
	ZIA_PERMANENT = 0x00000004, /* permanent allocation                   */
	ZIA_GUARD     = 0x00000008, /* will be used as a guard                */
});

__startup_func
static struct zone_map_range
zone_init_allocate_va(vm_map_address_t addr, vm_size_t size,
    zone_init_allocate_flags_t flags)
{
	vm_map_kernel_flags_t vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
	int vm_alloc_flags = 0;
	struct zone_map_range r;
	kern_return_t kr;

	if (flags & ZIA_REPLACE) {
		vm_alloc_flags |= VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE;
	} else {
		vm_alloc_flags |= VM_FLAGS_ANYWHERE;
	}
	if (flags & ZIA_RANDOM) {
		vm_alloc_flags |= VM_FLAGS_RANDOM_ADDR;
	}
	if (flags & ZIA_PERMANENT) {
		vmk_flags.vmkf_permanent = true;
	}

	vm_object_reference(kernel_object);

	kr = vm_map_enter(kernel_map, &addr, size, 0,
	    vm_alloc_flags, vmk_flags, VM_KERN_MEMORY_ZONE,
	    kernel_object, 0, FALSE,
	    (flags & ZIA_GUARD) ? VM_PROT_NONE : VM_PROT_DEFAULT,
	    (flags & ZIA_GUARD) ? VM_PROT_NONE : VM_PROT_DEFAULT,
	    VM_INHERIT_NONE);

	if (KERN_SUCCESS != kr) {
		panic("vm_map_enter(0x%zx) failed: %d", (size_t)size, kr);
	}

	r.min_address = (vm_offset_t)addr;
	r.max_address = (vm_offset_t)addr + size;
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
	if (idx == Z_SUBMAP_IDX_VA_RESTRICTED) {
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
	    FALSE, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, vmk_flags,
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

	zone_init_allocate_va(submap_end, guard_size,
	    ZIA_PERMANENT | ZIA_GUARD | ZIA_REPLACE);

	zone_submaps[idx] = submap;
	*submap_min       = submap_end + guard_size;
	*remaining_size  -= submap_size;
	*remaining_denom -= zone_sub_map_numer;
}

/*
 * Allocate metadata array and migrate foreign initial metadata.
 *
 * So that foreign pages and native pages have the same scheme,
 * we allocate VA space that covers both foreign and native pages.
 */
__startup_func
static void
zone_metadata_init(void)
{
	struct zone_map_range r0 = zone_info.zi_map_range[0];
	struct zone_map_range r1 = zone_info.zi_map_range[1];
	struct zone_map_range mr, br;
	vm_size_t meta_size, bits_size, foreign_base;
	vm_offset_t hstart, hend;

	if (r0.min_address > r1.min_address) {
		r0 = zone_info.zi_map_range[1];
		r1 = zone_info.zi_map_range[0];
	}

	meta_size = round_page(atop(r1.max_address - r0.min_address) *
	    sizeof(struct zone_page_metadata)) + ZONE_GUARD_SIZE * 2;

	/*
	 * Allocations can't be smaller than 8 bytes, which is 128b / 16B per 1k
	 * of physical memory (16M per 1G).
	 *
	 * Let's preallocate for the worst to avoid weird panics.
	 */
	bits_size = round_page(16 * (ptoa(zone_phys_mapped_max_pages) >> 10));

	/*
	 * Compute the size of the "hole" in the middle of the range.
	 *
	 * If it is smaller than 256k, just leave it be, with this layout:
	 *
	 *   [G][ r0 meta ][ hole ][ r1 meta ][ bits ][G]
	 *
	 * else punch a hole with guard pages around the hole, and place the
	 * bits in the hole if it fits, or after r1 otherwise, yielding either
	 * of the following layouts:
	 *
	 *      |__________________hend____________|
	 *      |__hstart_|                        |
	 *   [G][ r0 meta ][ bits ][G]..........[G][ r1 meta ][G]
	 *   [G][ r0 meta ][G]..................[G][ r1 meta ][ bits ][G]
	 */
	hstart = round_page(atop(r0.max_address - r0.min_address) *
	    sizeof(struct zone_page_metadata));
	hend = trunc_page(atop(r1.min_address - r0.min_address) *
	    sizeof(struct zone_page_metadata));

	if (hstart >= hend || hend - hstart < (256ul << 10)) {
		mr = zone_init_allocate_va(0, meta_size + bits_size,
		    ZIA_PERMANENT | ZIA_RANDOM);
		mr.min_address += ZONE_GUARD_SIZE;
		mr.max_address -= ZONE_GUARD_SIZE;
		br.max_address  = mr.max_address;
		mr.max_address -= bits_size;
		br.min_address  = mr.max_address;

#if DEBUG || DEVELOPMENT
		printf("zone_init: metadata  %p:%p (%zuK)\n",
		    (void *)mr.min_address, (void *)mr.max_address,
		    (size_t)zone_range_size(&mr) >> 10);
		printf("zone_init: metabits  %p:%p (%zuK)\n",
		    (void *)br.min_address, (void *)br.max_address,
		    (size_t)zone_range_size(&br) >> 10);
#endif /* DEBUG || DEVELOPMENT */
	} else {
		vm_size_t size, alloc_size = meta_size;
		vm_offset_t base;
		bool bits_in_middle = true;

		if (hend - hstart - 2 * ZONE_GUARD_SIZE < bits_size) {
			alloc_size += bits_size;
			bits_in_middle = false;
		}

		mr = zone_init_allocate_va(0, alloc_size, ZIA_RANDOM);

		base = mr.min_address;
		size = ZONE_GUARD_SIZE + hstart + ZONE_GUARD_SIZE;
		if (bits_in_middle) {
			size += bits_size;
			br.min_address = base + ZONE_GUARD_SIZE + hstart;
			br.max_address = br.min_address + bits_size;
		}
		zone_init_allocate_va(base, size, ZIA_PERMANENT | ZIA_REPLACE);

		base += size;
		size = mr.min_address + hend - base;
		kmem_free(kernel_map, base, size);

		base = mr.min_address + hend;
		size = mr.max_address - base;
		zone_init_allocate_va(base, size, ZIA_PERMANENT | ZIA_REPLACE);

		mr.min_address += ZONE_GUARD_SIZE;
		mr.max_address -= ZONE_GUARD_SIZE;
		if (!bits_in_middle) {
			br.max_address  = mr.max_address;
			mr.max_address -= bits_size;
			br.min_address  = mr.max_address;
		}

#if DEBUG || DEVELOPMENT
		printf("zone_init: metadata0 %p:%p (%zuK)\n",
		    (void *)mr.min_address, (void *)(mr.min_address + hstart),
		    (size_t)hstart >> 10);
		printf("zone_init: metadata1 %p:%p (%zuK)\n",
		    (void *)(mr.min_address + hend), (void *)mr.max_address,
		    (size_t)(zone_range_size(&mr) - hend) >> 10);
		printf("zone_init: metabits  %p:%p (%zuK)\n",
		    (void *)br.min_address, (void *)br.max_address,
		    (size_t)zone_range_size(&br) >> 10);
#endif /* DEBUG || DEVELOPMENT */
	}

	br.min_address = (br.min_address + ZBA_CHUNK_SIZE - 1) & -ZBA_CHUNK_SIZE;
	br.max_address = br.max_address & -ZBA_CHUNK_SIZE;

	zone_info.zi_meta_range = mr;
	zone_info.zi_bits_range = br;

	/*
	 * Migrate the original static metadata into its new location.
	 */
	zone_info.zi_meta_base = (struct zone_page_metadata *)mr.min_address -
	    zone_pva_from_addr(r0.min_address).packed_address;
	foreign_base = zone_info.zi_map_range[ZONE_ADDR_FOREIGN].min_address;
	zone_meta_populate(foreign_base, zone_foreign_size());
	memcpy(zone_meta_from_addr(foreign_base),
	    zone_foreign_meta_array_startup,
	    atop(zone_foreign_size()) * sizeof(struct zone_page_metadata));

	zba_populate(0);
	memcpy(zba_base_header(), zba_chunk_startup,
	    sizeof(zba_chunk_startup));
}

/* Global initialization of Zone Allocator.
 * Runs after zone_bootstrap.
 */
__startup_func
static void
zone_init(void)
{
	vm_size_t       zone_map_size;
	vm_size_t       remaining_size;
	vm_offset_t     submap_min = 0;
	uint64_t        denom = 0;
	uint64_t        submap_ratios[Z_SUBMAP_IDX_COUNT] = {
#ifdef __LP64__
		[Z_SUBMAP_IDX_VA_RESTRICTED] = 20,
#else
		[Z_SUBMAP_IDX_VA_RESERVE]    = 10,
#endif /* defined(__LP64__) */
		[Z_SUBMAP_IDX_GENERAL]       = 40,
		[Z_SUBMAP_IDX_BAG_OF_BYTES]  = 40,
	};

	if (ZSECURITY_OPTIONS_SUBMAP_USER_DATA & zsecurity_options) {
		zone_last_submap_idx = Z_SUBMAP_IDX_BAG_OF_BYTES;
	} else {
		zone_last_submap_idx = Z_SUBMAP_IDX_GENERAL;
	}
	zone_phys_mapped_max_pages = (uint32_t)atop(zone_phys_size_max());

	for (unsigned idx = 0; idx <= zone_last_submap_idx; idx++) {
#if DEBUG || DEVELOPMENT
		char submap_name[1 + sizeof("submap")];
		snprintf(submap_name, sizeof(submap_name), "submap%d", idx);
		PE_parse_boot_argn(submap_name, &submap_ratios[idx], sizeof(uint64_t));
#endif
		denom += submap_ratios[idx];
	}

#if __LP64__
	zone_map_size = ZONE_MAP_VIRTUAL_SIZE_LP64;
#else
	zone_map_size = ptoa(zone_phys_mapped_max_pages *
	    (denom + submap_ratios[Z_SUBMAP_IDX_VA_RESERVE]) / denom);
#endif

	remaining_size = zone_map_size -
	    ZONE_GUARD_SIZE * (zone_last_submap_idx + 1);

	/*
	 * And now allocate the various pieces of VA and submaps.
	 *
	 * Make a first allocation of contiguous VA, that we'll deallocate,
	 * and we'll carve-out memory in that range again linearly.
	 * The kernel is stil single threaded at this stage.
	 */

	struct zone_map_range *map_range =
	    &zone_info.zi_map_range[ZONE_ADDR_NATIVE];

	*map_range = zone_init_allocate_va(0, zone_map_size, ZIA_NONE);
	submap_min = map_range->min_address;

	/*
	 * Allocate the submaps
	 */
	for (unsigned idx = 0; idx <= zone_last_submap_idx; idx++) {
		zone_submap_init(&submap_min, idx, submap_ratios[idx],
		    &denom, &remaining_size, ZONE_GUARD_SIZE);
	}

	assert(submap_min == map_range->max_address);

	zone_metadata_init();

#if VM_MAX_TAG_ZONES
	if (zone_tagging_on) {
		zone_tagging_init(zone_map_size);
	}
#endif
#if CONFIG_GZALLOC
	gzalloc_init(zone_map_size);
#endif

	zone_create_flags_t kma_flags = ZC_NOCACHING |
	    ZC_NOGC | ZC_NOENCRYPT | ZC_NOGZALLOC | ZC_NOCALLOUT |
	    ZC_KASAN_NOQUARANTINE | ZC_KASAN_NOREDZONE;

	(void)zone_create_ext("vm.permanent", 1, kma_flags,
	    ZONE_ID_PERMANENT, ^(zone_t z){
		z->z_permanent = true;
		z->z_elem_size = 1;
#if defined(__LP64__)
		z->z_submap_idx = Z_SUBMAP_IDX_VA_RESTRICTED;
#endif
	});
	(void)zone_create_ext("vm.permanent.percpu", 1, kma_flags | ZC_PERCPU,
	    ZONE_ID_PERCPU_PERMANENT, ^(zone_t z){
		z->z_permanent = true;
		z->z_elem_size = 1;
#if defined(__LP64__)
		z->z_submap_idx = Z_SUBMAP_IDX_VA_RESTRICTED;
#endif
	});

	/*
	 * Now migrate the startup statistics into their final storage.
	 */
	int cpu = cpu_number();
	zone_index_foreach(idx) {
		zone_t tz = &zone_array[idx];

		if (tz->z_stats == __zpcpu_mangle_for_boot(&zone_stats_startup[idx])) {
			zone_stats_t zs = zalloc_percpu_permanent_type(struct zone_stats);

			*zpercpu_get_cpu(zs, cpu) = *zpercpu_get_cpu(tz->z_stats, cpu);
			tz->z_stats = zs;
#if ZONE_ENABLE_LOGGING
			if (tz->zone_logging && !tz->zlog_btlog) {
				zone_enable_logging(tz);
			}
#endif /* ZONE_ENABLE_LOGGING */
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
zone_cache_bootstrap(void)
{
	zone_t magzone;

	magzone = zone_create("zcc_magazine_zone", sizeof(struct zone_magazine) +
	    zc_mag_size() * sizeof(zone_element_t),
	    ZC_NOGZALLOC | ZC_KASAN_NOREDZONE | ZC_KASAN_NOQUARANTINE |
	    ZC_SEQUESTER | ZC_CACHING | ZC_ZFREE_CLEARMEM);
	magzone->z_elems_rsv = (uint16_t)(2 * zpercpu_count());

	os_atomic_store(&zc_magazine_zone, magzone, compiler_acq_rel);

	/*
	 * Now that we are initialized, we can enable zone caching for zones that
	 * were made before zcache_bootstrap() was called.
	 *
	 * The system is still single threaded so we don't need to take the lock.
	 */
	zone_index_foreach(i) {
		zone_t z = &zone_array[i];
		if (z->z_pcpu_cache) {
			z->z_pcpu_cache = NULL;
			zone_enable_caching(z);
		}
	}
}
STARTUP(ZALLOC, STARTUP_RANK_FOURTH, zone_cache_bootstrap);

void
zalloc_first_proc_made(void)
{
	zone_caching_disabled = 0;
}

__startup_func
vm_offset_t
zone_foreign_mem_init(vm_size_t size)
{
	vm_offset_t mem;

	if (atop(size) > ZONE_FOREIGN_META_INLINE_COUNT) {
		panic("ZONE_FOREIGN_META_INLINE_COUNT has become too small: "
		    "%d > %d", (int)atop(size), ZONE_FOREIGN_META_INLINE_COUNT);
	}

	mem = (vm_offset_t)pmap_steal_memory(size);

	zone_info.zi_meta_base = zone_foreign_meta_array_startup -
	    zone_pva_from_addr(mem).packed_address;
	zone_info.zi_map_range[ZONE_ADDR_FOREIGN].min_address = mem;
	zone_info.zi_map_range[ZONE_ADDR_FOREIGN].max_address = mem + size;

	zone_info.zi_bits_range = (struct zone_map_range){
		.min_address = (vm_offset_t)zba_chunk_startup,
		.max_address = (vm_offset_t)zba_chunk_startup +
	    sizeof(zba_chunk_startup),
	};
	zba_init_chunk(0);

	return mem;
}

#endif /* !ZALLOC_TEST */
#pragma mark - tests
#if DEBUG || DEVELOPMENT

/*
 * Used for sysctl kern.run_zone_test which is not thread-safe. Ensure only one
 * thread goes through at a time.  Or we can end up with multiple test zones (if
 * a second zinit() comes through before zdestroy()),  which could lead us to
 * run out of zones.
 */
static SIMPLE_LOCK_DECLARE(zone_test_lock, 0);
static boolean_t zone_test_running = FALSE;
static zone_t test_zone_ptr = NULL;

static uintptr_t *
zone_copy_allocations(zone_t z, uintptr_t *elems, zone_pva_t page_index)
{
	vm_offset_t elem_size = zone_elem_size(z);
	vm_offset_t base;
	struct zone_page_metadata *meta;

	while (!zone_pva_is_null(page_index)) {
		base  = zone_pva_to_addr(page_index);
		meta  = zone_pva_to_meta(page_index);

		if (meta->zm_inline_bitmap) {
			for (size_t i = 0; i < meta->zm_chunk_len; i++) {
				uint32_t map = meta[i].zm_bitmap;

				for (; map; map &= map - 1) {
					*elems++ = INSTANCE_PUT(base +
					    elem_size * __builtin_clz(map));
				}
				base += elem_size * 32;
			}
		} else {
			uint32_t order = zba_bits_ref_order(meta->zm_bitmap);
			bitmap_t *bits = zba_bits_ref_ptr(meta->zm_bitmap);
			for (size_t i = 0; i < (1u << order); i++) {
				uint64_t map = bits[i];

				for (; map; map &= map - 1) {
					*elems++ = INSTANCE_PUT(base +
					    elem_size * __builtin_clzll(map));
				}
				base += elem_size * 64;
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
	size_t        maxElems;
	kern_return_t kr;

	zone_foreach(z) {
		if (!strncmp(zoneName, z->z_name, nameLen)) {
			zone = z;
			break;
		}
	}
	if (zone == NULL) {
		return KERN_INVALID_NAME;
	}

	elemSize = (uint32_t)zone_elem_size(zone);
	maxElems = (zone->z_elems_avail + 1) & ~1ul;

	if ((ptoa(zone->z_percpu ? 1 : zone->z_chunk_pages) % elemSize) &&
	    !zone_leaks_scan_enable) {
		return KERN_INVALID_CAPABILITY;
	}

	kr = kmem_alloc_kobject(kernel_map, (vm_offset_t *) &array,
	    maxElems * sizeof(uintptr_t), VM_KERN_MEMORY_DIAG);
	if (KERN_SUCCESS != kr) {
		return kr;
	}

	zone_lock(zone);

	next = array;
	next = zone_copy_allocations(zone, next, zone->z_pageq_partial);
	next = zone_copy_allocations(zone, next, zone->z_pageq_full);
	count = (uint32_t)(next - array);

	zone_unlock(zone);

	zone_leaks_scan(array, count, (uint32_t)zone_elem_size(zone), &found);
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
	zone_t test_pcpu_zone;
	kern_return_t kr;

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
		if (test_zone_ptr == NULL && test_zone->z_elems_free != 0) {
#else
		if (test_zone->z_elems_free != 0) {
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
		void **allocs_pcpu;
		vm_offset_t phys_pages = os_atomic_load(&zones_phys_page_mapped_count, relaxed);

		test_zone = zone_create("test_zone_sysctl", elem_size,
		    ZC_DESTRUCTIBLE | ZC_SEQUESTER);
		assert(test_zone);

		test_pcpu_zone = zone_create("test_zone_sysctl.pcpu", sizeof(uint64_t),
		    ZC_DESTRUCTIBLE | ZC_SEQUESTER | ZC_PERCPU);
		assert(test_pcpu_zone);

		for (idx = 0; idx < num_allocs; idx++) {
			allocs[idx] = zalloc(test_zone);
			assert(NULL != allocs[idx]);
			printf("alloc[%d] %p\n", idx, allocs[idx]);
		}
		for (idx = 0; idx < num_allocs; idx++) {
			zfree(test_zone, allocs[idx]);
		}
		assert(!zone_pva_is_null(test_zone->z_pageq_empty));

		kr = kernel_memory_allocate(kernel_map,
		    (vm_address_t *)&allocs_pcpu, PAGE_SIZE,
		    0, KMA_ZERO | KMA_KOBJECT, VM_KERN_MEMORY_DIAG);
		assert(kr == KERN_SUCCESS);

		for (idx = 0; idx < PAGE_SIZE / sizeof(uint64_t); idx++) {
			allocs_pcpu[idx] = zalloc_percpu(test_pcpu_zone,
			    Z_WAITOK | Z_ZERO);
			assert(NULL != allocs_pcpu[idx]);
		}
		for (idx = 0; idx < PAGE_SIZE / sizeof(uint64_t); idx++) {
			zfree_percpu(test_pcpu_zone, allocs_pcpu[idx]);
		}
		assert(!zone_pva_is_null(test_pcpu_zone->z_pageq_empty));

		printf("vm_page_wire_count %d, vm_page_free_count %d, p to v %ld%%\n",
		    vm_page_wire_count, vm_page_free_count,
		    100L * phys_pages / zone_phys_mapped_max_pages);
		zone_gc(ZONE_GC_DRAIN);
		printf("vm_page_wire_count %d, vm_page_free_count %d, p to v %ld%%\n",
		    vm_page_wire_count, vm_page_free_count,
		    100L * phys_pages / zone_phys_mapped_max_pages);

		unsigned int allva = 0;

		zone_foreach(z) {
			zone_lock(z);
			allva += z->z_wired_cur;
			if (zone_pva_is_null(z->z_pageq_va)) {
				zone_unlock(z);
				continue;
			}
			unsigned count = 0;
			uint64_t size;
			zone_pva_t pg = z->z_pageq_va;
			struct zone_page_metadata *page_meta;
			while (pg.packed_address) {
				page_meta = zone_pva_to_meta(pg);
				count += z->z_percpu ? 1 : z->z_chunk_pages;
				if (page_meta->zm_chunk_len == ZM_SECONDARY_PAGE) {
					count -= page_meta->zm_page_index;
				}
				pg = page_meta->zm_page_next;
			}
			assert(z->z_wired_cur + count == z->z_va_cur);
			size = zone_size_wired(z);
			if (!size) {
				size = 1;
			}
			printf("%s%s: seq %d, res %d, %qd %%\n",
			    zone_heap_name(z), z->z_name, z->z_va_cur - z->z_wired_cur,
			    z->z_wired_cur, zone_size_allocated(z) * 100ULL / size);
			zone_unlock(z);
		}

		printf("total va: %d\n", allva);

		assert(zone_pva_is_null(test_zone->z_pageq_empty));
		assert(zone_pva_is_null(test_zone->z_pageq_partial));
		assert(!zone_pva_is_null(test_zone->z_pageq_va));
		assert(zone_pva_is_null(test_pcpu_zone->z_pageq_empty));
		assert(zone_pva_is_null(test_pcpu_zone->z_pageq_partial));
		assert(!zone_pva_is_null(test_pcpu_zone->z_pageq_va));

		for (idx = 0; idx < num_allocs; idx++) {
			assert(0 == pmap_find_phys(kernel_pmap, (addr64_t)(uintptr_t) allocs[idx]));
		}

		/* make sure the zone is still usable after a GC */

		for (idx = 0; idx < num_allocs; idx++) {
			allocs[idx] = zalloc(test_zone);
			assert(allocs[idx]);
			printf("alloc[%d] %p\n", idx, allocs[idx]);
		}
		assert(zone_pva_is_null(test_zone->z_pageq_va));
		assert(test_zone->z_wired_cur == test_zone->z_va_cur);
		for (idx = 0; idx < num_allocs; idx++) {
			zfree(test_zone, allocs[idx]);
		}

		for (idx = 0; idx < PAGE_SIZE / sizeof(uint64_t); idx++) {
			allocs_pcpu[idx] = zalloc_percpu(test_pcpu_zone,
			    Z_WAITOK | Z_ZERO);
			assert(NULL != allocs_pcpu[idx]);
		}
		for (idx = 0; idx < PAGE_SIZE / sizeof(uint64_t); idx++) {
			zfree_percpu(test_pcpu_zone, allocs_pcpu[idx]);
		}

		assert(!zone_pva_is_null(test_pcpu_zone->z_pageq_empty));
		assert(zone_pva_is_null(test_pcpu_zone->z_pageq_va));

		kmem_free(kernel_map, (vm_address_t)allocs_pcpu, PAGE_SIZE);

		zdestroy(test_zone);
		zdestroy(test_pcpu_zone);
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
	zone_gc(ZONE_GC_DRAIN);
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
		if (z->z_replenishes && zone_elem_size(z) >= sizeof(struct data)) {
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
