/*
 * Copyright (c) 2017-2020 Apple Inc. All rights reserved.
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

#include <kern/assert.h>
#include <kern/cpu_data.h>
#include <mach/mach_host.h>
#include <vm/vm_kern.h>
#include <kern/startup.h>
#include <kern/zalloc_internal.h>

/* Size of array in magazine determined by boot-arg or default */
TUNABLE(uint16_t, magazine_element_count, "zcc_magazine_element_count", 8);

/* Size of depot lists determined by boot-arg or default */
TUNABLE(uint16_t, depot_element_count, "zcc_depot_element_count", 8);

SECURITY_READ_ONLY_LATE(zone_t)    magazine_zone;       /* zone to allocate zcc_magazine structs from */
SECURITY_READ_ONLY_LATE(uintptr_t) zcache_canary;       /* Canary used for the caching layer to prevent UaF attacks */

/*
 *	The zcc_magazine is used as a stack to store cached zone elements. These
 *	sets of elements can be moved around to perform bulk operations.
 */
struct zcc_magazine {
	uint32_t zcc_magazine_index;            /* Used as a stack pointer to acess elements in the array */
	uint32_t zcc_magazine_capacity;         /* Number of pointers able to be stored in the zcc_elements array */
	vm_offset_t zcc_elements[0];            /* Array of pointers to objects */
};


/*
 * Each CPU will use one of these to store its elements
 */
struct zcc_per_cpu_cache {
	/* Magazine from which we will always try to allocate from and free to first */
	struct zcc_magazine *current;
	/* Dedicated magazine for a quick reload and to prevent thrashing wen we swap with the depot */
	struct zcc_magazine *previous;
	/* Zcache poisoning count */
	uint32_t zp_count;
#if ZALLOC_DETAILED_STATS
	uint64_t zcc_allocs;
	uint64_t zcc_frees;
#endif /* ZALLOC_DETAILED_STATS */
};


/*	This is the basic struct to take care of cahing and is included within
 *      the zone.
 */
struct zcc_depot {
	/* marks the point in the array where empty magazines begin */
	int zcc_depot_index;

#if ZALLOC_DETAILED_STATS
	uint64_t zcc_swap;
	uint64_t zcc_fill;
	uint64_t zcc_drain;
	uint64_t zcc_fail;
	uint64_t zcc_gc;
#endif /* ZALLOC_DETAILED_STATS */

	/* Stores full and empty magazines in the depot layer */
	struct zcc_magazine *zcc_depot_list[0];
};

static bool zcache_mag_fill_locked(zone_t zone, struct zcc_magazine *mag);
static void zcache_mag_drain_locked(zone_t zone, struct zcc_magazine *mag);
static bool zcache_mag_has_space(struct zcc_magazine *mag);
static bool zcache_mag_has_elements(struct zcc_magazine *mag);
static void zcache_swap_magazines(struct zcc_magazine **a, struct zcc_magazine **b);
static void zcache_mag_depot_swap_for_alloc(struct zcc_depot *depot, struct zcc_per_cpu_cache *cache);
static void zcache_mag_depot_swap_for_free(struct zcc_depot *depot, struct zcc_per_cpu_cache *cache);
static void zcache_canary_add(zone_t zone, vm_offset_t addr);
#if ZALLOC_ENABLE_POISONING
static void zcache_validate_element(zone_t zone, vm_offset_t *addr, bool poison);
static void zcache_validate_and_clear_canary(zone_t zone, vm_offset_t *primary, vm_offset_t *backup);
#endif

/*
 * zcache_ready
 *
 * Returns whether or not the zone caches are ready to use
 *
 */
static bool
zcache_ready(void)
{
	return magazine_zone != NULL;
}

/*
 * zcache_bootstrap
 *
 * Initializes zone to allocate magazines from and sets
 * magazine_element_count and depot_element_count from
 * boot-args or default values
 *
 */
__startup_func
static void
zcache_bootstrap(void)
{
	int magazine_size = sizeof(struct zcc_magazine) + magazine_element_count * sizeof(void *);
	zone_t magzone;

	/* Generate the canary value for zone caches */
	zcache_canary = (uintptr_t) early_random();

	magzone = zone_create("zcc_magazine_zone", magazine_size,
	    ZC_NOCACHING | ZC_ZFREE_CLEARMEM);

	/*
	 * This causes zcache_ready() to return true.
	 */
	os_atomic_store(&magazine_zone, magzone, compiler_acq_rel);

	/*
	 * Now that we are initialized, we can enable zone caching for zones that
	 * were made before zcache_bootstrap() was called.
	 *
	 * The system is still single threaded so we don't need to take the lock.
	 */
	zone_index_foreach(i) {
		if (zone_array[i].cpu_cache_enabled) {
			zcache_init(&zone_array[i]);
		}
	}
}
STARTUP(ZALLOC, STARTUP_RANK_FOURTH, zcache_bootstrap);

static struct zcc_magazine *
zcache_mag_alloc(void)
{
	struct zcc_magazine *mag = zalloc_flags(magazine_zone, Z_WAITOK);
	mag->zcc_magazine_capacity = magazine_element_count;
	return mag;
}


/*
 * zcache_init
 *
 * Initializes all parts of the per-cpu caches for a given zone
 *
 * Parameters:
 * zone    pointer to zone on which to iniitalize caching
 *
 */
void
zcache_init(zone_t zone)
{
	struct zcc_per_cpu_cache *pcpu_caches;
	struct zcc_depot         *depot;
	vm_size_t size;

	/*
	 * If zcache hasn't been initialized yet, remember our decision,
	 *
	 * zcache_init() will be called again by zcache_bootstrap(),
	 * while the system is still single threaded, to build the missing caches.
	 */
	if (!zcache_ready()) {
		zone->cpu_cache_enabled = true;
		return;
	}

	/* Allocate chunk of memory for all structs */
	size        = sizeof(struct zcc_depot) + (depot_element_count * sizeof(void *));
	depot       = zalloc_permanent(size, ZALIGN_PTR);

	size        = sizeof(struct zcc_per_cpu_cache);
	pcpu_caches = zalloc_percpu_permanent(size, ZALIGN_PTR);

	/* Initialize a cache for every CPU */
	zpercpu_foreach(cache, pcpu_caches) {
		cache->current = zcache_mag_alloc();
		cache->previous = zcache_mag_alloc();
		cache->zp_count = zone_poison_count_init(zone);
	}

	/* Initialize empty magazines in the depot list */
	for (int i = 0; i < depot_element_count; i++) {
		depot->zcc_depot_list[i] = zcache_mag_alloc();
	}

	lock_zone(zone);
	if (zone->zcache.zcc_depot) {
		panic("allocating caches for zone %s twice", zone->z_name);
	}

	/* Make the initialization of the per-cpu magazines visible. */
	os_atomic_thread_fence(release);

	zone->zcache.zcc_depot = depot;
	zone->zcache.zcc_pcpu = pcpu_caches;
	zone->cpu_cache_enabled = true;
	unlock_zone(zone);
}

/*
 * zcache_drain_depot
 *
 * Frees all the full magazines from the depot layer to the zone allocator as part
 * of zone_gc(). The routine assumes that only one zone_gc() is in progress (zone_gc_lock
 * ensures that)
 *
 * Parameters:
 * zone    pointer to zone for which the depot layer needs to be drained
 *
 * Returns: None
 *
 */
void
zcache_drain_depot(zone_t zone)
{
	struct zcc_depot *depot;
	int drain_depot_index = 0;

	lock_zone(zone);
	depot = zone->zcache.zcc_depot;
	drain_depot_index = depot->zcc_depot_index;
	for (int i = 0; i < drain_depot_index; i++) {
		zcache_mag_drain_locked(zone, depot->zcc_depot_list[i]);
	}
#if ZALLOC_DETAILED_STATS
	depot->zcc_gc += drain_depot_index;
#endif /* ZALLOC_DETAILED_STATS */
	depot->zcc_depot_index = 0;
	unlock_zone(zone);
}

__attribute__((noinline))
static void
zcache_free_to_cpu_cache_slow(zone_t zone, struct zcc_per_cpu_cache *per_cpu_cache)
{
	struct zcc_depot *depot;

	lock_zone(zone);
	depot = zone->zcache.zcc_depot;
	if (depot->zcc_depot_index < depot_element_count) {
		/* If able, rotate in a new empty magazine from the depot and retry */
		zcache_mag_depot_swap_for_free(depot, per_cpu_cache);
	} else {
		/* Free an entire magazine of elements */
		zcache_mag_drain_locked(zone, per_cpu_cache->current);
#if ZALLOC_DETAILED_STATS
		depot->zcc_drain++;
#endif /* ZALLOC_DETAILED_STATS */
	}
	unlock_zone(zone);
}


void
zcache_free_to_cpu_cache(zone_t zone, zone_stats_t zstats, vm_offset_t addr)
{
	struct zcc_per_cpu_cache *per_cpu_cache;
	vm_offset_t elem = addr;
	int cpu;

	zone_allocated_element_validate(zone, elem);

	/*
	 * This is racy but we don't need zp_count to be accurate.
	 * This allows us to do the poisoning with preemption enabled.
	 */
	per_cpu_cache = zpercpu_get(zone->zcache.zcc_pcpu);
	if (zfree_clear_or_poison(zone, &per_cpu_cache->zp_count, elem)) {
		addr |= ZALLOC_ELEMENT_NEEDS_VALIDATION;
	} else {
		zcache_canary_add(zone, elem);
	}

#if KASAN_ZALLOC
	kasan_poison_range(elem, zone_elem_size(zone), ASAN_HEAP_FREED);
#endif

	disable_preemption();
	cpu = cpu_number();
	per_cpu_cache = zpercpu_get_cpu(zone->zcache.zcc_pcpu, cpu);

	if (zcache_mag_has_space(per_cpu_cache->current)) {
		/* If able, free into current magazine */
	} else if (zcache_mag_has_space(per_cpu_cache->previous)) {
		/* If able, swap current and previous magazine and retry */
		zcache_swap_magazines(&per_cpu_cache->previous, &per_cpu_cache->current);
	} else {
		zcache_free_to_cpu_cache_slow(zone, per_cpu_cache);
	}

	struct zcc_magazine *mag = per_cpu_cache->current;
	mag->zcc_elements[mag->zcc_magazine_index++] = addr;
	zpercpu_get_cpu(zstats, cpu)->zs_mem_freed += zone_elem_size(zone);
#if ZALLOC_DETAILED_STATS
	per_cpu_cache->zcc_frees++;
#endif /* ZALLOC_DETAILED_STATS */

	enable_preemption();
}

__attribute__((noinline))
static bool
zcache_alloc_from_cpu_cache_slow(zone_t zone, struct zcc_per_cpu_cache *per_cpu_cache)
{
	struct zcc_depot *depot;

	lock_zone(zone);
	depot = zone->zcache.zcc_depot;
	if (depot->zcc_depot_index > 0) {
		/* If able, rotate in a full magazine from the depot */
		zcache_mag_depot_swap_for_alloc(depot, per_cpu_cache);
	} else if (zcache_mag_fill_locked(zone, per_cpu_cache->current)) {
#if ZALLOC_DETAILED_STATS
		depot->zcc_fill++;
#endif /* ZALLOC_DETAILED_STATS */
	} else {
#if ZALLOC_DETAILED_STATS
		depot->zcc_fail++;
#endif /* ZALLOC_DETAILED_STATS */
		/* If unable to allocate from cache return NULL and fall through to zalloc */
		unlock_zone(zone);
		enable_preemption();
		return false;
	}
	unlock_zone(zone);

	return true;
}

vm_offset_t
zcache_alloc_from_cpu_cache(zone_t zone, zone_stats_t zstats, vm_size_t waste)
{
	struct zcc_per_cpu_cache *per_cpu_cache;
	int cpu;

	disable_preemption();
	cpu = cpu_number();
	per_cpu_cache = zpercpu_get_cpu(zone->zcache.zcc_pcpu, cpu);

	if (zcache_mag_has_elements(per_cpu_cache->current)) {
		/* If able, allocate from current magazine */
	} else if (zcache_mag_has_elements(per_cpu_cache->previous)) {
		/* If able, swap current and previous magazine and retry */
		zcache_swap_magazines(&per_cpu_cache->previous, &per_cpu_cache->current);
	} else if (!zcache_alloc_from_cpu_cache_slow(zone, per_cpu_cache)) {
		return (vm_offset_t)NULL;
	}

	struct zcc_magazine *mag = per_cpu_cache->current;
	vm_offset_t elem_size = zone_elem_size(zone);
	uint32_t index = --mag->zcc_magazine_index;
	vm_offset_t addr = mag->zcc_elements[index];
	mag->zcc_elements[index] = 0;
	zpercpu_get_cpu(zstats, cpu)->zs_mem_allocated += elem_size;
#if ZALLOC_DETAILED_STATS
	if (waste) {
		zpercpu_get_cpu(zstats, cpu)->zs_mem_wasted += waste;
	}
	per_cpu_cache->zcc_allocs++;
#else
	(void)waste;
#endif /* ZALLOC_DETAILED_STATS */

	enable_preemption();

#if ZALLOC_ENABLE_POISONING
	bool validate = addr & ZALLOC_ELEMENT_NEEDS_VALIDATION;
#endif /* ZALLOC_ENABLE_POISONING */

	addr &= ~ZALLOC_ELEMENT_NEEDS_VALIDATION;

#if KASAN_ZALLOC
	kasan_poison_range(addr, elem_size, ASAN_VALID);
#endif
#if ZALLOC_ENABLE_POISONING
	if (!validate) {
		vm_offset_t backup = addr + elem_size - sizeof(vm_offset_t);
		zcache_validate_and_clear_canary(zone, (vm_offset_t *)addr,
		    (vm_offset_t *)backup);
	}
	zalloc_validate_element(zone, addr, elem_size, validate);
#endif /* ZALLOC_ENABLE_POISONING */

	return addr;
}


/*
 * zcache_mag_fill_locked
 *
 * Fills a magazine with as many elements as the zone can give
 * without blocking to carve out more memory
 *
 * Parameters:
 * zone    zone from which to allocate
 * mag     pointer to magazine to fill
 *
 * Return:	True if able to allocate elements, false is mag is still empty
 */
static bool
zcache_mag_fill_locked(zone_t zone, struct zcc_magazine *mag)
{
	uint32_t i = mag->zcc_magazine_index;
	uint32_t end = mag->zcc_magazine_capacity;
	vm_offset_t elem, addr;

	while (i < end && zone->countfree) {
		addr = zalloc_direct_locked(zone, Z_NOWAIT, 0);
		elem = addr & ~ZALLOC_ELEMENT_NEEDS_VALIDATION;
		if (addr & ZALLOC_ELEMENT_NEEDS_VALIDATION) {
			zone_clear_freelist_pointers(zone, elem);
		} else {
			zcache_canary_add(zone, elem);
		}
#if KASAN_ZALLOC
		kasan_poison_range(elem, zone_elem_size(zone), ASAN_HEAP_FREED);
#endif
		mag->zcc_elements[i++] = addr;
	}

	mag->zcc_magazine_index = i;

	return i != 0;
}

/*
 * zcache_mag_drain_locked
 *
 * Frees all elements in a magazine
 *
 * Parameters:
 * zone   zone to which elements will be freed
 * mag    pointer to magazine to empty
 *
 */
static void
zcache_mag_drain_locked(zone_t zone, struct zcc_magazine *mag)
{
	vm_offset_t elem, addr;
	bool poison;

	for (uint32_t i = 0, end = mag->zcc_magazine_index; i < end; i++) {
		addr   = mag->zcc_elements[i];
		poison = addr & ZALLOC_ELEMENT_NEEDS_VALIDATION;
		elem   = addr & ~ZALLOC_ELEMENT_NEEDS_VALIDATION;

#if ZALLOC_ENABLE_POISONING
		zcache_validate_element(zone, (vm_offset_t *)elem, poison);
#endif /* ZALLOC_ENABLE_POISONING */
		zfree_direct_locked(zone, elem, poison);
		mag->zcc_elements[i] = 0;
	}
	mag->zcc_magazine_index = 0;
}


/*
 * zcache_mag_has_space
 *
 * Checks if magazine still has capacity
 *
 * Parameters:
 * mag    pointer to magazine to check
 *
 * Returns: true if magazine is full
 *
 */
static bool
zcache_mag_has_space(struct zcc_magazine *mag)
{
	return mag->zcc_magazine_index < mag->zcc_magazine_capacity;
}


/*
 * zcache_mag_has_elements
 *
 * Checks if magazine is empty
 *
 * Parameters:
 * mag    pointer to magazine to check
 *
 * Returns: true if magazine has no elements
 *
 */
static bool
zcache_mag_has_elements(struct zcc_magazine *mag)
{
	return mag->zcc_magazine_index > 0;
}


/*
 * zcache_swap_magazines
 *
 * Function which swaps two pointers of any type
 *
 * Parameters:
 * a		pointer to first pointer
 * b		pointer to second pointer
 */
static void
zcache_swap_magazines(struct zcc_magazine **a, struct zcc_magazine **b)
{
	struct zcc_magazine *temp = *a;
	*a = *b;
	*b = temp;
}


/*
 * zcache_mag_depot_swap_for_alloc
 *
 * Swaps a full magazine into the current position
 *
 * Parameters:
 * depot     pointer to the depot
 * cache     pointer to the current per-cpu cache
 *
 * Precondition: Check that the depot list has full elements
 */
static void
zcache_mag_depot_swap_for_alloc(struct zcc_depot *depot, struct zcc_per_cpu_cache *cache)
{
	/* Loads a full magazine from which we can allocate */
	assert(depot->zcc_depot_index > 0);
	depot->zcc_depot_index--;
#if ZALLOC_DETAILED_STATS
	depot->zcc_swap++;
#endif /* ZALLOC_DETAILED_STATS */
	zcache_swap_magazines(&cache->current, &depot->zcc_depot_list[depot->zcc_depot_index]);
}


/*
 * zcache_mag_depot_swap_for_free
 *
 * Swaps an empty magazine into the current position
 *
 * Parameters:
 * depot     pointer to the depot
 * cache     pointer to the current per-cpu cache
 *
 * Precondition: Check that the depot list has empty elements
 */
static void
zcache_mag_depot_swap_for_free(struct zcc_depot *depot, struct zcc_per_cpu_cache *cache)
{
	/* Loads an empty magazine into which we can free */
	assert(depot->zcc_depot_index < depot_element_count);
	zcache_swap_magazines(&cache->current, &depot->zcc_depot_list[depot->zcc_depot_index]);
#if ZALLOC_DETAILED_STATS
	depot->zcc_swap++;
#endif /* ZALLOC_DETAILED_STATS */
	depot->zcc_depot_index++;
}

/*
 * zcache_canary_add
 *
 * Adds a canary to an element by putting zcache_canary at the first
 * and last location of the element
 *
 * Parameters:
 * zone    zone for the element
 * addr    element address to add canary to
 */
static void
zcache_canary_add(zone_t zone, vm_offset_t element)
{
#if ZALLOC_ENABLE_POISONING
	vm_offset_t *primary = (vm_offset_t *)element;
	vm_offset_t *backup = (vm_offset_t *)((vm_offset_t)primary +
	    zone_elem_size(zone) - sizeof(vm_offset_t));
	*primary = *backup = (zcache_canary ^ (uintptr_t)element);
#else
#pragma unused(zone, element)
#endif
}

#if ZALLOC_ENABLE_POISONING
__abortlike static void
zcache_validation_panic(zone_t zone, vm_offset_t *primary, vm_offset_t *backup,
    vm_offset_t permutation)
{
	vm_offset_t primary_value = 0;
	vm_offset_t backup_value = 0;

	if (permutation == zcache_canary) {
		primary_value = *primary ^ (vm_offset_t)primary;
		backup_value = *backup ^ (vm_offset_t)primary;
		permutation = permutation ^ (vm_offset_t)primary;
	} else {
		primary_value = *primary;
		backup_value = *backup;
	}
	if (primary_value != permutation) {
		panic("Zone cache element was used after free! Element %p was corrupted at "
		    "beginning; Expected 0x%lx but found 0x%lx; canary 0x%lx; zone %p (%s%s)",
		    primary, (uintptr_t) permutation, (uintptr_t) *primary, zcache_canary, zone,
		    zone_heap_name(zone), zone->z_name);
	} else {
		panic("Zone cache element was used after free! Element %p was corrupted at end; "
		    "Expected 0x%lx but found 0x%lx; canary 0x%lx; zone %p (%s%s)",
		    primary, (uintptr_t) permutation, (uintptr_t) *backup, zcache_canary, zone,
		    zone_heap_name(zone), zone->z_name);
	}
}

/*
 * zcache_validate_and_clear_canary
 *
 * Validates an element of the zone cache to make sure it still contains the zone
 * caching canary and clears it.
 *
 * Parameters:
 * zone    zone for the element
 * primary addr of canary placed in front
 * backup	 addr of canary placed at the back
 */
static void
zcache_validate_and_clear_canary(zone_t zone, vm_offset_t *primary, vm_offset_t *backup)
{
	vm_offset_t primary_value = (*primary ^ (uintptr_t)primary);
	vm_offset_t backup_value = (*backup ^ (uintptr_t)primary);

	if (primary_value == zcache_canary && backup_value == zcache_canary) {
		*primary = *backup = ZONE_POISON;
	} else {
		zcache_validation_panic(zone, primary, backup, zcache_canary);
	}
}

/*
 * zcache_validate_element
 *
 * Validates the first and last pointer size of the element to ensure
 * that they haven't been altered. This function is used when an
 * element moves from cache to zone, therefore only validing the
 * first and last pointer size (location of future freelist pointers).
 *
 * Parameters:
 * zone    zone for the element
 * element addr of element to validate
 * poison  has the element been poisoned
 */
static void
zcache_validate_element(zone_t zone, vm_offset_t *element, bool poison)
{
	vm_offset_t *primary = (vm_offset_t *)element;
	vm_offset_t *backup = (vm_offset_t *)((vm_offset_t)primary +
	    zone_elem_size(zone) - sizeof(vm_offset_t));

	if (zone->zfree_clear_mem) {
		if (*primary == 0 && *backup == 0) {
			return;
		} else {
			zcache_validation_panic(zone, primary, backup, 0);
		}
	}

	if (__probable(!poison)) {
		zcache_validate_and_clear_canary(zone, primary, backup);
	} else {
		if (*primary == ZONE_POISON && *backup == ZONE_POISON) {
			return;
		} else {
			zcache_validation_panic(zone, primary, backup, ZONE_POISON);
		}
	}
}
#endif /* ZALLOC_ENABLE_POISONING */
