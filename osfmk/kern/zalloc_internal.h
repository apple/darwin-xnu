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

#ifndef _KERN_ZALLOC_INTERNAL_H_
#define _KERN_ZALLOC_INTERNAL_H_

#include <kern/zalloc.h>
#include <kern/locks.h>
#include <kern/btlog.h>
#include <kern/simple_lock.h>

#include <os/atomic_private.h>
#include <sys/queue.h>

#if KASAN
#include <san/kasan.h>
#include <kern/spl.h>
#endif /* !KASAN */

/*!
 * @file <kern/zalloc_internal.h>
 *
 * @abstract
 * Exposes some guts of zalloc to interact with the VM, debugging, copyio and
 * kalloc subsystems.
 */

__BEGIN_DECLS

#pragma GCC visibility push(hidden)

#if CONFIG_GZALLOC
typedef struct gzalloc_data {
	uint32_t        gzfc_index;
	vm_offset_t     *gzfc;
} gzalloc_data_t;
#endif

/*
 *	A zone is a collection of fixed size blocks for which there
 *	is fast allocation/deallocation access.  Kernel routines can
 *	use zones to manage data structures dynamically, creating a zone
 *	for each type of data structure to be managed.
 *
 */

/*!
 * @typedef zone_pva_t
 *
 * @brief
 * Type used to point to a page virtual address in the zone allocator.
 *
 * @description
 * - Valid pages have the top bit set.
 * - 0 represents the "NULL" page
 * - non 0 values with the top bit cleared do not represent any valid page.
 *   the zone freelists use this space to encode "queue" addresses.
 */
typedef struct zone_packed_virtual_address {
	uint32_t packed_address;
} zone_pva_t;

/*!
 * @struct zone_stats
 *
 * @abstract
 * Per-cpu structure used for basic zone stats.
 *
 * @discussion
 * The values aren't scaled for per-cpu zones.
 */
struct zone_stats {
	uint64_t            zs_mem_allocated;
	uint64_t            zs_mem_freed;
	uint32_t            zs_poison_seqno; /* counter for poisoning every N frees */
	uint32_t            zs_alloc_rr;     /* allocation rr bias */
};

STAILQ_HEAD(zone_depot, zone_magazine);

struct zone {
	/*
	 * Readonly / rarely written fields
	 */

	/*
	 * The first 4 fields match a zone_view.
	 *
	 * z_self points back to the zone when the zone is initialized,
	 * or is NULL else.
	 */
	struct zone        *z_self;
	zone_stats_t        z_stats;
	const char         *z_name;
	struct zone_view   *z_views;

	struct thread      *z_expander;
	struct zone_cache  *__zpercpu z_pcpu_cache;

	uint16_t            z_chunk_pages;  /* size used for more memory in pages  */
	uint16_t            z_chunk_elems;  /* count of allocations per chunk */
	uint16_t            z_elems_rsv;    /* maintain a free reserve of elements */
	uint16_t            z_elem_size;    /* size of an element                  */

	uint64_t
	/*
	 * Lifecycle state (Mutable after creation)
	 */
	    z_destroyed        :1,  /* zone is (being) destroyed */
	    z_async_refilling  :1,  /* asynchronous allocation pending? */
	    z_replenish_wait   :1,  /* someone is waiting on the replenish thread */
	    z_expanding_wait   :1,  /* is thread waiting for expansion? */
	    z_expander_vm_priv :1,  /* a vm privileged thread is expanding */

	/*
	 * Security sensitive configuration bits
	 */
	    z_allows_foreign   :1,  /* allow non-zalloc space  */
	    z_destructible     :1,  /* zone can be zdestroy()ed  */
	    kalloc_heap        :2,  /* zone_kheap_id_t when part of a kalloc heap */
	    z_noencrypt        :1,  /* do not encrypt pages when hibernating */
	    z_submap_idx       :2,  /* a Z_SUBMAP_IDX_* value */
	    z_va_sequester     :1,  /* page sequester: no VA reuse with other zones */
	    z_free_zeroes      :1,  /* clear memory of elements on free and assert on alloc */

	/*
	 * Behavior configuration bits
	 */
	    z_percpu           :1,  /* the zone is percpu */
	    z_permanent        :1,  /* the zone allocations are permanent */
	    z_replenishes      :1,  /* uses the async replenish mechanism for VM */
	    z_nocaching        :1,  /* disallow zone caching for this zone */
	    collectable        :1,  /* garbage collect empty pages */
	    exhaustible        :1,  /* merely return if empty? */
	    expandable         :1,  /* expand zone (with message)? */
	    no_callout         :1,

	    _reserved          :26,

	/*
	 * Debugging features
	 */
	    alignment_required :1,  /* element alignment needs to be preserved */
	    gzalloc_tracked    :1,  /* this zone is tracked by gzalloc */
	    gzalloc_exempt     :1,  /* this zone doesn't participate with gzalloc */
	    kasan_fakestacks   :1,
	    kasan_noquarantine :1,  /* whether to use the kasan quarantine */
	    tag_zone_index     :7,
	    tags               :1,
	    tags_inline        :1,
	    zleak_on           :1,  /* Are we collecting allocation information? */
	    zone_logging       :1;  /* Enable zone logging for this zone. */

	/*
	 * often mutated fields
	 */

	lck_spin_t          z_lock;
	struct zone_depot   z_recirc;

	/*
	 * Page accounting (wired / VA)
	 *
	 * Those numbers are unscaled for z_percpu zones
	 * (zone_scale_for_percpu() needs to be used to find the true value).
	 */
	uint32_t            z_wired_max;    /* how large can this zone grow        */
	uint32_t            z_wired_hwm;    /* z_wired_cur high watermark          */
	uint32_t            z_wired_cur;    /* number of pages used by this zone   */
	uint32_t            z_wired_empty;  /* pages collectable by GC             */
	uint32_t            z_va_cur;       /* amount of VA used by this zone      */

	/*
	 * list of metadata structs, which maintain per-page free element lists
	 *
	 * Note: Due to the index packing in page metadata,
	 *       these pointers can't be at the beginning of the zone struct.
	 */
	zone_pva_t          z_pageq_empty;  /* populated, completely empty pages   */
	zone_pva_t          z_pageq_partial;/* populated, partially filled pages   */
	zone_pva_t          z_pageq_full;   /* populated, completely full pages    */
	zone_pva_t          z_pageq_va;     /* non-populated VA pages              */

	/*
	 * Zone statistics
	 *
	 * z_contention_wma:
	 *   weighted moving average of the number of contentions per second,
	 *   in Z_CONTENTION_WMA_UNIT units (fixed point decimal).
	 *
	 * z_contention_cur:
	 *   count of recorded contentions that will be fused in z_contention_wma
	 *   at the next period.
	 *
	 * z_recirc_cur:
	 *   number of magazines in the recirculation depot.
	 *
	 * z_elems_free:
	 *   number of free elements in the zone.
	 *
	 * z_elems_{min,max}:
	 *   tracks the low/high watermark of z_elems_free for the current
	 *   weighted moving average period.
	 *
	 * z_elems_free_wss:
	 *   weighted moving average of the (z_elems_free_max - z_elems_free_min)
	 *   amplited which is used by the GC for trim operations.
	 *
	 * z_elems_avail:
	 *   number of elements in the zone (at all).
	 */
#define Z_CONTENTION_WMA_UNIT (1u << 8)
	uint32_t            z_contention_wma;
	uint32_t            z_contention_cur;
	uint32_t            z_recirc_cur;
	uint32_t            z_elems_free_max;
	uint32_t            z_elems_free_wss;
	uint32_t            z_elems_free_min;
	uint32_t            z_elems_free;   /* Number of free elements             */
	uint32_t            z_elems_avail;  /* Number of elements available        */

#if CONFIG_ZLEAKS
	uint32_t            zleak_capture;  /* per-zone counter for capturing every N allocations */
#endif
#if CONFIG_GZALLOC
	gzalloc_data_t      gz;
#endif
#if KASAN_ZALLOC
	uint32_t            z_kasan_redzone;
	spl_t               z_kasan_spl;
#endif
#if DEBUG || DEVELOPMENT || CONFIG_ZLEAKS
	/* zone logging structure to hold stacks and element references to those stacks. */
	btlog_t            *zlog_btlog;
#endif
};


__options_decl(zone_security_options_t, uint64_t, {
	/*
	 * Zsecurity option to enable sequestering VA of zones
	 */
	ZSECURITY_OPTIONS_SEQUESTER             = 0x00000001,
	/*
	 * Zsecurity option to enable creating separate kalloc zones for
	 * bags of bytes
	 */
	ZSECURITY_OPTIONS_SUBMAP_USER_DATA      = 0x00000004,
	/*
	 * Zsecurity option to enable sequestering of kalloc zones used by
	 * kexts (KHEAP_KEXT heap)
	 */
	ZSECURITY_OPTIONS_SEQUESTER_KEXT_KALLOC = 0x00000008,
	/*
	 * Zsecurity option to enable strict free of iokit objects to zone
	 * or heap they were allocated from.
	 */
	ZSECURITY_OPTIONS_STRICT_IOKIT_FREE     = 0x00000010,
});

#define KALLOC_MINALIGN     (1 << KALLOC_LOG2_MINALIGN)
#define KALLOC_DLUT_SIZE    (2048 / KALLOC_MINALIGN)

struct kheap_zones {
	struct kalloc_zone_cfg         *cfg;
	struct kalloc_heap             *views;
	zone_kheap_id_t                 heap_id;
	uint16_t                        max_k_zone;
	uint8_t                         dlut[KALLOC_DLUT_SIZE];   /* table of indices into k_zone[] */
	uint8_t                         k_zindex_start;
	/* If there's no hit in the DLUT, then start searching from k_zindex_start. */
	zone_t                         *k_zone;
};

extern zone_security_options_t zsecurity_options;
extern zone_id_t _Atomic       num_zones;
extern uint32_t                zone_view_count;
extern struct zone             zone_array[];
extern const char * const      kalloc_heap_names[KHEAP_ID_COUNT];
extern bool                    panic_include_zprint;
#if CONFIG_ZLEAKS
extern bool                    panic_include_ztrace;
extern struct ztrace          *top_ztrace;
#endif
extern mach_memory_info_t     *panic_kext_memory_info;
extern vm_size_t               panic_kext_memory_size;
extern unsigned int            zone_map_jetsam_limit;

#define zone_index_foreach(i) \
	for (zone_id_t i = 1, num_zones_##i = os_atomic_load(&num_zones, acquire); \
	    i < num_zones_##i; i++)

#define zone_foreach(z) \
	for (zone_t z = &zone_array[1], \
	    last_zone_##z = &zone_array[os_atomic_load(&num_zones, acquire)]; \
	    z < last_zone_##z; z++)

struct zone_map_range {
	vm_offset_t min_address;
	vm_offset_t max_address;
} __attribute__((aligned(2 * sizeof(vm_offset_t))));

__pure2
static inline vm_offset_t
zone_elem_size(zone_t zone)
{
	return zone->z_elem_size;
}

static inline uint32_t
zone_count_allocated(zone_t zone)
{
	return zone->z_elems_avail - zone->z_elems_free;
}

static inline vm_size_t
zone_scale_for_percpu(zone_t zone, vm_size_t size)
{
	if (zone->z_percpu) {
		size *= zpercpu_count();
	}
	return size;
}

static inline vm_size_t
zone_size_wired(zone_t zone)
{
	/*
	 * this either require the zone lock,
	 * or to be used for statistics purposes only.
	 */
	vm_size_t size = ptoa(os_atomic_load(&zone->z_wired_cur, relaxed));
	return zone_scale_for_percpu(zone, size);
}

static inline vm_size_t
zone_size_free(zone_t zone)
{
	return zone_scale_for_percpu(zone,
	           (vm_size_t)zone->z_elem_size * zone->z_elems_free);
}

static inline vm_size_t
zone_size_allocated(zone_t zone)
{
	return zone_scale_for_percpu(zone,
	           (vm_size_t)zone->z_elem_size * zone_count_allocated(zone));
}

static inline vm_size_t
zone_size_wasted(zone_t zone)
{
	return zone_size_wired(zone) - zone_scale_for_percpu(zone,
	           (vm_size_t)zone->z_elem_size * zone->z_elems_avail);
}

/*
 * For sysctl kern.zones_collectable_bytes used by memory_maintenance to check if a
 * userspace reboot is needed. The only other way to query for this information
 * is via mach_memory_info() which is unavailable on release kernels.
 */
extern uint64_t get_zones_collectable_bytes(void);

/*!
 * @enum zone_gc_level_t
 *
 * @const ZONE_GC_TRIM
 * Request a trimming GC: it will trim allocations in excess
 * of the working set size estimate only.
 *
 * @const ZONE_GC_DRAIN
 * Request a draining GC: this is an aggressive mode that will
 * cause all caches to be drained and all free pages returned to the system.
 *
 * @const ZONE_GC_JETSAM
 * Request to consider a jetsam, and then fallback to @c ZONE_GC_TRIM or
 * @c ZONE_GC_DRAIN depending on the state of the zone map.
 * To avoid deadlocks, only @c vm_pageout_garbage_collect() should ever
 * request a @c ZONE_GC_JETSAM level.
 */
__enum_closed_decl(zone_gc_level_t, uint32_t, {
	ZONE_GC_TRIM,
	ZONE_GC_DRAIN,
	ZONE_GC_JETSAM,
});

/*!
 * @function zone_gc
 *
 * @brief
 * Reduces memory used by zones by trimming caches and freelists.
 *
 * @discussion
 * @c zone_gc() is called:
 * - by the pageout daemon when the system needs more free pages.
 * - by the VM when contiguous page allocation requests get stuck
 *   (see vm_page_find_contiguous()).
 *
 * @param level         The zone GC level requested.
 */
extern void     zone_gc(zone_gc_level_t level);

extern void     zone_gc_trim(void);
extern void     zone_gc_drain(void);

#define ZONE_WSS_UPDATE_PERIOD  10
/*!
 * @function compute_zone_working_set_size
 *
 * @brief
 * Recomputes the working set size for every zone
 *
 * @discussion
 * This runs about every @c ZONE_WSS_UPDATE_PERIOD seconds (10),
 * computing an exponential moving average with a weight of 75%,
 * so that the history of the last minute is the dominating factor.
 */
extern void     compute_zone_working_set_size(void *);

/* Debug logging for zone-map-exhaustion jetsams. */
extern void     get_zone_map_size(uint64_t *current_size, uint64_t *capacity);
extern void     get_largest_zone_info(char *zone_name, size_t zone_name_len, uint64_t *zone_size);

/* Bootstrap zone module (create zone zone) */
extern void     zone_bootstrap(void);

/*!
 * @function zone_foreign_mem_init
 *
 * @brief
 * Steal memory from pmap (prior to initialization of zalloc)
 * for the special vm zones that allow foreign memory and store
 * the range so as to facilitate range checking in zfree.
 */
__startup_func
extern vm_offset_t zone_foreign_mem_init(
	vm_size_t       size);

/*!
 * @function zone_get_foreign_alloc_size
 *
 * @brief
 * Compute the correct size (greater than @c ptoa(min_pages)) that is a multiple
 * of the allocation granule for the zone with the given creation flags and
 * element size.
 */
__startup_func
extern vm_size_t zone_get_foreign_alloc_size(
	const char          *name __unused,
	vm_size_t            elem_size,
	zone_create_flags_t  flags,
	uint16_t             min_pages);

/*!
 * @function zone_cram_foreign
 *
 * @brief
 * Cram memory allocated with @c zone_foreign_mem_init() into a zone.
 *
 * @param zone          The zone to cram memory into.
 * @param newmem        The base address for the memory to cram.
 * @param size          The size of the memory to cram into the zone.
 */
__startup_func
extern void     zone_cram_foreign(
	zone_t          zone,
	vm_offset_t     newmem,
	vm_size_t       size);

extern bool     zone_maps_owned(
	vm_address_t    addr,
	vm_size_t       size);

extern void     zone_map_sizes(
	vm_map_size_t  *psize,
	vm_map_size_t  *pfree,
	vm_map_size_t  *plargest_free);

extern bool
zone_map_nearing_exhaustion(void);

#if defined(__LP64__)
#define ZONE_POISON       0xdeadbeefdeadbeef
#else
#define ZONE_POISON       0xdeadbeef
#endif

static inline vm_tag_t
zalloc_flags_get_tag(zalloc_flags_t flags)
{
	return (vm_tag_t)((flags & Z_VM_TAG_MASK) >> Z_VM_TAG_SHIFT);
}

extern void    *zalloc_ext(
	zone_t          zone,
	zone_stats_t    zstats,
	zalloc_flags_t  flags);

extern void     zfree_ext(
	zone_t          zone,
	zone_stats_t    zstats,
	void           *addr);

/*!
 * @function zone_replenish_configure
 *
 * @brief
 * Used by zones backing the VM to maintain a reserve of free elements.
 *
 * @discussion
 * This function should not be used by anyone else than the VM.
 */
extern void     zone_replenish_configure(
	zone_t          zone);

extern vm_size_t zone_element_size(
	void           *addr,
	zone_t         *z);

/*!
 * @function zone_owns
 *
 * @abstract
 * This function is a soft version of zone_require that checks if a given
 * pointer belongs to the specified zone and should not be used outside
 * allocator code.
 *
 * @discussion
 * Note that zone_owns() can only work with:
 * - zones not allowing foreign memory
 * - zones in the general submap.
 *
 * @param zone          the zone the address needs to belong to.
 * @param addr          the element address to check.
 */
extern bool     zone_owns(
	zone_t          zone,
	void           *addr);

/*
 *  Structure for keeping track of a backtrace, used for leak detection.
 *  This is in the .h file because it is used during panic, see kern/debug.c
 *  A non-zero size indicates that the trace is in use.
 */
struct ztrace {
	vm_size_t               zt_size;                        /* How much memory are all the allocations referring to this trace taking up? */
	uint32_t                zt_depth;                       /* depth of stack (0 to MAX_ZTRACE_DEPTH) */
	void*                   zt_stack[MAX_ZTRACE_DEPTH];     /* series of return addresses from OSBacktrace */
	uint32_t                zt_collisions;                  /* How many times did a different stack land here while it was occupied? */
	uint32_t                zt_hit_count;                   /* for determining effectiveness of hash function */
};

#ifndef VM_MAX_TAG_ZONES
#error MAX_TAG_ZONES
#endif
#if VM_MAX_TAG_ZONES

extern uint32_t zone_index_from_tag_index(
	uint32_t        tag_zone_index,
	vm_size_t      *elem_size);

#endif /* VM_MAX_TAG_ZONES */

static inline void
zone_lock(zone_t zone)
{
#if KASAN_ZALLOC
	spl_t s = 0;
	if (zone->kasan_fakestacks) {
		s = splsched();
	}
#endif /* KASAN_ZALLOC */
	lck_spin_lock(&zone->z_lock);
#if KASAN_ZALLOC
	zone->z_kasan_spl = s;
#endif /* KASAN_ZALLOC */
}

static inline void
zone_unlock(zone_t zone)
{
#if KASAN_ZALLOC
	spl_t s = zone->z_kasan_spl;
	zone->z_kasan_spl = 0;
#endif /* KASAN_ZALLOC */
	lck_spin_unlock(&zone->z_lock);
#if KASAN_ZALLOC
	if (zone->kasan_fakestacks) {
		splx(s);
	}
#endif /* KASAN_ZALLOC */
}

#if CONFIG_GZALLOC
void gzalloc_init(vm_size_t);
void gzalloc_zone_init(zone_t);
void gzalloc_empty_free_cache(zone_t);
boolean_t gzalloc_enabled(void);

vm_offset_t gzalloc_alloc(zone_t, zone_stats_t zstats, zalloc_flags_t flags);
void gzalloc_free(zone_t, zone_stats_t zstats, void *);
boolean_t gzalloc_element_size(void *, zone_t *, vm_size_t *);
#endif /* CONFIG_GZALLOC */

#define MAX_ZONE_NAME   32      /* max length of a zone name we can take from the boot-args */
int track_this_zone(const char *zonename, const char *logname);

#if DEBUG || DEVELOPMENT
extern boolean_t run_zone_test(void);
extern void zone_gc_replenish_test(void);
extern void zone_alloc_replenish_test(void);
extern vm_size_t zone_element_info(void *addr, vm_tag_t * ptag);
extern bool zalloc_disable_copyio_check;
#else
#define zalloc_disable_copyio_check false
#endif /* DEBUG || DEVELOPMENT */

#pragma GCC visibility pop

__END_DECLS

#endif  /* _KERN_ZALLOC_INTERNAL_H_ */
