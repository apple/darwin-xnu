/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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


#if defined(__i386__) || defined(__x86_64__)
#include <i386/mp.h>
#endif

#if defined (__arm__) || defined (__arm64__)
#include <arm/cpu_data_internal.h>
#endif

#define DEFAULT_MAGAZINE_SIZE	8		/* Default number of elements for all magazines allocated from the magazine_zone */
#define DEFAULT_DEPOT_SIZE	8		/* Default number of elements for the array zcc_depot_list */
#define ZCC_MAX_CPU_CACHE_LINE_SIZE	64	/* We should use a platform specific macro for this in the future, right now this is the max cache line size for all platforms*/

lck_grp_t	zcache_locks_grp;			/* lock group for depot_lock */
zone_t 		magazine_zone;				/* zone to allocate zcc_magazine structs from */
uint16_t 	magazine_element_count = 0;		/* Size of array in magazine determined by boot-arg or default */
uint16_t 	depot_element_count = 0;		/* Size of depot lists determined by boot-arg or default */
bool 		zone_cache_ready = FALSE;		/* Flag to check if zone caching has been set up by zcache_bootstrap */
uintptr_t	zcache_canary = 0; 			/* Canary used for the caching layer to prevent UaF attacks */

/*	The zcc_magazine is used as a stack to store cached zone elements. These
 *	sets of elements can be moved around to perform bulk operations.
*/
struct zcc_magazine {
	uint32_t zcc_magazine_index;		/* Used as a stack pointer to acess elements in the array */
	uint32_t zcc_magazine_capacity;		/* Number of pointers able to be stored in the zcc_elements array */
	void *zcc_elements[0];			/* Array of pointers to objects */
};


/* 	Each CPU will use one of these to store its elements
*/
struct zcc_per_cpu_cache {
	struct zcc_magazine *current; 		/* Magazine from which we will always try to allocate from and free to first */
	struct zcc_magazine *previous;		/* Dedicated magazine for a quick reload and to prevent thrashing wen we swap with the depot */
} __attribute__(( aligned(ZCC_MAX_CPU_CACHE_LINE_SIZE) ));	/* we want to align this to a cache line size so it does not thrash when multiple cpus want to access their caches in paralell */


/*
 * The depot layer can be invalid while zone_gc() is draining it out.
 * During that time, the CPU caches are active. For CPU magazine allocs and 
 * frees, the caching layer reaches directly into the zone allocator.
 */
#define ZCACHE_DEPOT_INVALID			-1
#define zcache_depot_available(zcache)		(zcache->zcc_depot_index != ZCACHE_DEPOT_INVALID)

/*	This is the basic struct to take care of cahing and is included within
 * 	the zone.
*/
struct zone_cache {
	lck_mtx_t zcc_depot_lock; 				/* Lock for the depot layer of caching */
	struct zcc_per_cpu_cache zcc_per_cpu_caches[MAX_CPUS]; 	/* An array of caches, one for each CPU */
	int zcc_depot_index;					/* marks the point in the array where empty magazines begin */
	struct zcc_magazine *zcc_depot_list[0]; 		/* Stores full and empty magazines in the depot layer */
};


void zcache_init_marked_zones(void);
bool zcache_mag_fill(zone_t zone, struct zcc_magazine *mag);
void zcache_mag_drain(zone_t zone, struct zcc_magazine *mag);
void zcache_mag_init(struct zcc_magazine *mag, int count);
void *zcache_mag_pop(struct zcc_magazine *mag);
void zcache_mag_push(struct zcc_magazine *mag, void *elem);
bool zcache_mag_has_space(struct zcc_magazine *mag);
bool zcache_mag_has_elements(struct zcc_magazine *mag);
void zcache_swap_magazines(struct zcc_magazine **a, struct zcc_magazine **b);
void zcache_mag_depot_swap_for_alloc(struct zone_cache *depot, struct zcc_per_cpu_cache *cache);
void zcache_mag_depot_swap_for_free(struct zone_cache *depot, struct zcc_per_cpu_cache *cache);
void zcache_mag_depot_swap(struct zone_cache *depot, struct zcc_per_cpu_cache *cache, boolean_t load_full);
void zcache_canary_add(zone_t zone, void *addr);
void zcache_canary_validate(zone_t zone, void *addr);

/*
 * zcache_ready
 *
 * Description: returns whether or not the zone caches are ready to use
 *
 */
bool zcache_ready(void){
	return zone_cache_ready;
}

/*
 * zcache_init_marked_zones
 *
 * Description: Initializes all parts of the per-cpu caches for the list of
 *		marked zones once we are able to initalize caches. This should
 *		only be called once, and will be called during the time that the
 *		system is single threaded so we don't have to take the lock.
 *
 */
void zcache_init_marked_zones(void){
	unsigned int i;
	for(i = 0; i < num_zones; i ++){
		if(zone_array[i].cpu_cache_enable_when_ready){
			zcache_init(&zone_array[i]);
			zone_array[i].cpu_cache_enable_when_ready = FALSE;
		}
	}
}

/*
 * zcache_bootstrap
 *
 * Description: initializes zone to allocate magazines from and sets
 *		magazine_element_count and depot_element_count from
 *		boot-args or default values
 *
 */
void zcache_bootstrap(void)
{
	/* use boot-arg for custom magazine size*/
	if (! PE_parse_boot_argn("zcc_magazine_element_count", &magazine_element_count, sizeof (uint16_t)))
		magazine_element_count = DEFAULT_MAGAZINE_SIZE;

	int magazine_size = sizeof(struct zcc_magazine) + magazine_element_count * sizeof(void *);

	magazine_zone = zinit(magazine_size, 100000 * magazine_size , magazine_size, "zcc_magazine_zone");

	assert(magazine_zone != NULL);

	/* use boot-arg for custom depot size*/
	if (! PE_parse_boot_argn("zcc_depot_element_count", &depot_element_count, sizeof (uint16_t)))
		depot_element_count = DEFAULT_DEPOT_SIZE;

	lck_grp_init(&zcache_locks_grp, "zcc_depot_lock", LCK_GRP_ATTR_NULL);

	/* Generate the canary value for zone caches */
	zcache_canary = (uintptr_t) early_random();

	zone_cache_ready = TRUE;

	zcache_init_marked_zones();
}


/*
 * zcache_init
 *
 * Description: Initializes all parts of the per-cpu caches for a given zone
 *
 * Parameters:	zone	pointer to zone on which to iniitalize caching
 *
 */
 void zcache_init(zone_t zone)
 {
 	int 	i;			/* used as index in for loops */
	vm_size_t	total_size;		/* Used for allocating the zone_cache struct with the proper size of depot list */
	struct zone_cache *temp_cache;	/* Temporary variable to initialize a zone_cache before assigning to the specified zone */

	/* Allocate chunk of memory for all structs */
	total_size = sizeof(struct zone_cache) + (depot_element_count * sizeof(void *));
	
	temp_cache = (struct zone_cache *) kalloc(total_size);


 	/* Initialize a cache for every CPU */
 	for (i = 0; i < MAX_CPUS; i++) {
 		temp_cache->zcc_per_cpu_caches[i].current = (struct zcc_magazine *)zalloc(magazine_zone);
 		temp_cache->zcc_per_cpu_caches[i].previous = (struct zcc_magazine *)zalloc(magazine_zone);

 		assert(temp_cache->zcc_per_cpu_caches[i].current != NULL && temp_cache->zcc_per_cpu_caches[i].previous != NULL);

 		zcache_mag_init(temp_cache->zcc_per_cpu_caches[i].current, magazine_element_count);
 		zcache_mag_init(temp_cache->zcc_per_cpu_caches[i].previous, magazine_element_count);
 	}

 	/* Initialize the lock on the depot layer */
 	lck_mtx_init(&(temp_cache->zcc_depot_lock), &zcache_locks_grp, LCK_ATTR_NULL);

	/* Initialize empty magazines in the depot list */
	for (i = 0; i < depot_element_count; i++) {
		temp_cache->zcc_depot_list[i] = (struct zcc_magazine *)zalloc(magazine_zone);

		assert(temp_cache->zcc_depot_list[i] != NULL);

		zcache_mag_init(temp_cache->zcc_depot_list[i], magazine_element_count);
	}

	temp_cache->zcc_depot_index = 0;

 	lock_zone(zone);
	zone->zcache = temp_cache;
 	/* Set flag to know caching is enabled */
 	zone->cpu_cache_enabled = TRUE;
 	unlock_zone(zone);
 	return;
 }

/*
 * zcache_drain_depot
 *
 * Description: Frees all the full magazines from the depot layer to the zone allocator as part
 *              of zone_gc(). The routine assumes that only one zone_gc() is in progress (zone_gc_lock
 *              ensures that)
 *
 * Parameters:	zone	pointer to zone for which the depot layer needs to be drained
 *
 * Returns: None
 *
 */
void zcache_drain_depot(zone_t zone)
{
	struct zone_cache *zcache = zone->zcache;
	int drain_depot_index = 0;

	/*
	 * Grab the current depot list from the zone cache. If it has full magazines, 
	 * mark the depot as invalid and drain it.
	 */
	lck_mtx_lock_spin_always(&(zcache->zcc_depot_lock));
	if (!zcache_depot_available(zcache) || (zcache->zcc_depot_index == 0)) {
		/* no full magazines in the depot or depot unavailable; nothing to drain here */
		lck_mtx_unlock(&(zcache->zcc_depot_lock));
		return;
	}
	drain_depot_index = zcache->zcc_depot_index;
	/* Mark the depot as unavailable */
	zcache->zcc_depot_index = ZCACHE_DEPOT_INVALID;
	lck_mtx_unlock(&(zcache->zcc_depot_lock));

	/* Now drain the full magazines in the depot */
	for (int i = 0; i < drain_depot_index; i++)
		zcache_mag_drain(zone, zcache->zcc_depot_list[i]);

	lck_mtx_lock_spin_always(&(zcache->zcc_depot_lock));
	/* Mark the depot as available again */
	zcache->zcc_depot_index = 0;
	lck_mtx_unlock(&(zcache->zcc_depot_lock));
}


/*
 * zcache_free_to_cpu_cache
 *
 * Description: Checks per-cpu caches to free element there if possible
 *
 * Parameters:	zone	pointer to zone for which element comes from
 *		addr	pointer to element to free
 *
 * Returns: TRUE if successfull, FALSE otherwise
 *
 * Precondition: check that caching is enabled for zone
 */
bool zcache_free_to_cpu_cache(zone_t zone, void *addr)
{
	int	curcpu;					/* Current cpu is used to index into array of zcc_per_cpu_cache structs */
	struct	zone_cache *zcache;			/* local storage of the zone's cache */
	struct zcc_per_cpu_cache *per_cpu_cache;	/* locally store the current per_cpu_cache */

	disable_preemption();
	curcpu = current_processor()->cpu_id;
	zcache = zone->zcache;
	per_cpu_cache = &zcache->zcc_per_cpu_caches[curcpu];

	if (zcache_mag_has_space(per_cpu_cache->current)) {
		/* If able, free into current magazine */
		goto free_to_current;
	} else if (zcache_mag_has_space(per_cpu_cache->previous)) {
		/* If able, swap current and previous magazine and retry */
		zcache_swap_magazines(&per_cpu_cache->previous, &per_cpu_cache->current);
		goto free_to_current;
	} else{
		lck_mtx_lock_spin_always(&(zcache->zcc_depot_lock));
		if (zcache_depot_available(zcache) && (zcache->zcc_depot_index < depot_element_count)) {
			/* If able, rotate in a new empty magazine from the depot and retry */
			zcache_mag_depot_swap_for_free(zcache, per_cpu_cache);
			lck_mtx_unlock(&(zcache->zcc_depot_lock));
			goto free_to_current;
		}
		lck_mtx_unlock(&(zcache->zcc_depot_lock));
		/* Attempt to free an entire magazine of elements */
		zcache_mag_drain(zone, per_cpu_cache->current);
		if(zcache_mag_has_space(per_cpu_cache->current)){
			goto free_to_current;
		}
	}

	/* If not able to use cache return FALSE and fall through to zfree */
	enable_preemption();
	return FALSE;

free_to_current:
	assert(zcache_mag_has_space(per_cpu_cache->current));
	zcache_canary_add(zone, addr);
	zcache_mag_push(per_cpu_cache->current, addr);

#if KASAN_ZALLOC
	kasan_poison_range((vm_offset_t)addr, zone->elem_size, ASAN_HEAP_FREED);
#endif

	enable_preemption();
	return TRUE;
}


/*
 * zcache_alloc_from_cpu_cache
 *
 * Description: Checks per-cpu caches to allocate element from there if possible
 *
 * Parameters:	zone	pointer to zone for which element will come from
 *
 * Returns: pointer to usable element
 *
 * Precondition: check that caching is enabled for zone
 */
vm_offset_t zcache_alloc_from_cpu_cache(zone_t zone)
{
	int curcpu;					/* Current cpu is used to index into array of zcc_per_cpu_cache structs */
	void *ret = NULL;				/* Points to the element which will be returned */
	struct	zone_cache *zcache;			/* local storage of the zone's cache */
	struct zcc_per_cpu_cache *per_cpu_cache; 	/* locally store the current per_cpu_cache */

	disable_preemption();
	curcpu = current_processor()->cpu_id;
	zcache = zone->zcache;
	per_cpu_cache = &zcache->zcc_per_cpu_caches[curcpu];

	if (zcache_mag_has_elements(per_cpu_cache->current)) {
		/* If able, allocate from current magazine */
		goto allocate_from_current;
	} else if (zcache_mag_has_elements(per_cpu_cache->previous)) {
		/* If able, swap current and previous magazine and retry */
		zcache_swap_magazines(&per_cpu_cache->previous, &per_cpu_cache->current);
		goto allocate_from_current;
	} else {
		lck_mtx_lock_spin_always(&(zcache->zcc_depot_lock));
		if (zcache_depot_available(zcache) && (zcache->zcc_depot_index > 0)) {
			/* If able, rotate in a full magazine from the depot */
			zcache_mag_depot_swap_for_alloc(zcache, per_cpu_cache);
			lck_mtx_unlock(&(zcache->zcc_depot_lock));
			goto allocate_from_current;
		}
		lck_mtx_unlock(&(zcache->zcc_depot_lock));
		/* Attempt to allocate an entire magazine of elements */
		if(zcache_mag_fill(zone, per_cpu_cache->current)){
			goto allocate_from_current;
		}
	}

	/* If unable to allocate from cache return NULL and fall through to zalloc */
	enable_preemption();
	return (vm_offset_t) NULL;

allocate_from_current:
	ret = zcache_mag_pop(per_cpu_cache->current);
	assert(ret != NULL);
	zcache_canary_validate(zone, ret);

#if KASAN_ZALLOC
	kasan_poison_range((vm_offset_t)ret, zone->elem_size, ASAN_VALID);
#endif

	enable_preemption();
	return (vm_offset_t) ret;
}


/*
 * zcache_mag_init
 *
 * Description: initializes fields in a zcc_magazine struct
 *
 * Parameters:	mag	pointer to magazine to initialize
 *
 */
void zcache_mag_init(struct zcc_magazine *mag, int count)
{
	mag->zcc_magazine_index = 0;
	mag->zcc_magazine_capacity = count;
}


/*
 * zcache_mag_fill
 *
 * Description: fills a magazine with as many elements as the zone can give
 * 		without blocking to carve out more memory
 *
 * Parameters:	zone	zone from which to allocate
 *		mag	pointer to magazine to fill
 *
 * Return:	True if able to allocate elements, false is mag is still empty
 */
bool zcache_mag_fill(zone_t zone, struct zcc_magazine *mag)
{
	assert(mag->zcc_magazine_index == 0);
	void* elem = NULL;
	uint32_t i;
	lock_zone(zone);
	for(i = mag->zcc_magazine_index; i < mag->zcc_magazine_capacity; i ++){
		elem = zalloc_attempt(zone);
		if(elem) {
			zcache_canary_add(zone, elem);
			zcache_mag_push(mag, elem);
#if KASAN_ZALLOC
			kasan_poison_range((vm_offset_t)elem, zone->elem_size, ASAN_HEAP_FREED);
#endif
		} else {
			break;
		}
	}
	unlock_zone(zone);
	if (i == 0){
		return FALSE;
	}
	return TRUE;
}

/*
 * zcache_mag_drain
 *
 * Description: frees all elements in a magazine
 *
 * Parameters:	zone	zone to which elements will be freed
 *		mag	pointer to magazine to empty
 *
 */
void zcache_mag_drain(zone_t zone, struct zcc_magazine *mag)
{
	assert(mag->zcc_magazine_index == mag->zcc_magazine_capacity);
	lock_zone(zone);
	while(mag->zcc_magazine_index > 0){
		uint32_t index = --mag->zcc_magazine_index;
		zcache_canary_validate(zone, mag->zcc_elements[index]);
		zfree_direct(zone,(vm_offset_t)mag->zcc_elements[index]);
		mag->zcc_elements[mag->zcc_magazine_index] = 0;
	}
	unlock_zone(zone);
}

/*
 * zcache_mag_pop
 *
 * Description: removes last element from magazine in a stack pop fashion
 *		zcc_magazine_index represents the number of elements on the
 *		stack, so it the index of where to save the next element, when
 *		full, it will be 1 past the last index of the array
 *
 * Parameters:	mag	pointer to magazine from which to remove element
 *
 * Returns: pointer to element removed from magazine
 *
 * Precondition: must check that magazine is not empty before calling
 */
void *zcache_mag_pop(struct zcc_magazine *mag)
{
	void	*elem;
	assert(zcache_mag_has_elements(mag));
	elem =  mag->zcc_elements[--mag->zcc_magazine_index];
	/* Ensure pointer to element cannot be accessed after we pop it */
	mag->zcc_elements[mag->zcc_magazine_index] = NULL;
	assert(elem != NULL);
	return elem;
}


/*
 * zcache_mag_push
 *
 * Description: adds element to magazine and increments zcc_magazine_index
 *		zcc_magazine_index represents the number of elements on the
 *		stack, so it the index of where to save the next element, when
 *		full, it will be 1 past the last index of the array
 *
 * Parameters:	mag	pointer to magazine from which to remove element
 *		elem	pointer to element to add
 *
 * Precondition: must check that magazine is not full before calling
 */
void zcache_mag_push(struct zcc_magazine *mag, void *elem)
{
	assert(zcache_mag_has_space(mag));
	mag->zcc_elements[mag->zcc_magazine_index ++] = elem;
}


/*
 * zcache_mag_has_space
 *
 * Description: checks if magazine still has capacity
 *
 * Parameters:	mag	pointer to magazine to check
 *
 * Returns: true if magazine is full
 *
 */
bool zcache_mag_has_space(struct zcc_magazine *mag)
{
	return (mag->zcc_magazine_index < mag->zcc_magazine_capacity);
}


/*
 * zcache_mag_has_elements
 *
 * Description: checks if magazine is empty
 *
 * Parameters:	mag	pointer to magazine to check
 *
 * Returns: true if magazine has no elements
 *
 */
bool zcache_mag_has_elements(struct zcc_magazine *mag)
{
	return (mag->zcc_magazine_index > 0);
}


/*
 * zcache_swap_magazines
 *
 * Description: Function which swaps two pointers of any type
 *
 * Parameters:	a		pointer to first pointer
 *		b		pointer to second pointer
 */
void zcache_swap_magazines(struct zcc_magazine **a, struct zcc_magazine **b)
{
	struct zcc_magazine *temp = *a;
	*a = *b;
	*b = temp;
}


/*
 * zcache_mag_depot_swap_for_alloc
 *
 * Description: Swaps a full magazine into the current position
 *
 * Parameters:	zcache			pointer to the zone_cache to access the depot
 *		cache			pointer to the current per-cpu cache
 *
 * Precondition: Check that the depot list has full elements
 */
void zcache_mag_depot_swap_for_alloc(struct zone_cache *zcache, struct zcc_per_cpu_cache *cache)
{
	/* Loads a full magazine from which we can allocate */
	assert(zcache_depot_available(zcache));
	assert(zcache->zcc_depot_index > 0);
	zcache->zcc_depot_index --;
	zcache_swap_magazines(&cache->current, &zcache->zcc_depot_list[zcache->zcc_depot_index]);
}


/*
 * zcache_mag_depot_swap_for_free
 *
 * Description: Swaps an empty magazine into the current position
 *
 * Parameters:	zcache			pointer to the zone_cache to access the depot
 *		cache			pointer to the current per-cpu cache
 *
 * Precondition: Check that the depot list has empty elements
 */
void zcache_mag_depot_swap_for_free(struct zone_cache *zcache, struct zcc_per_cpu_cache *cache)
{
	/* Loads an empty magazine into which we can free */
	assert(zcache_depot_available(zcache));
	assert(zcache->zcc_depot_index < depot_element_count);
	zcache_swap_magazines(&cache->current, &zcache->zcc_depot_list[zcache->zcc_depot_index]);
	zcache->zcc_depot_index ++;
}

/*
 * zcache_canary_add
 *
 * Description: Adds a canary to an element by putting zcache_canary at the first 
 * 		and last location of the element
 *
 * Parameters:	zone	zone for the element
 * 		addr	element address to add canary to
 *
 */
void zcache_canary_add(zone_t zone, void *element)
{
	vm_offset_t *primary = (vm_offset_t *)element;
	vm_offset_t *backup = (vm_offset_t *)((vm_offset_t)primary + zone->elem_size - sizeof(vm_offset_t));
	*primary = *backup = (zcache_canary ^ (uintptr_t)element);
}

/*
 * zcache_canary_validate
 *
 * Description: Validates an element of the zone cache to make sure it still contains the zone 
 * 		caching canary.
 *
 * Parameters:	zone	zone for the element
 * 		addr	element address to validate
 *
 */
void zcache_canary_validate(zone_t zone, void *element)
{
	vm_offset_t *primary = (vm_offset_t *)element;
	vm_offset_t *backup = (vm_offset_t *)((vm_offset_t)primary + zone->elem_size - sizeof(vm_offset_t));

	vm_offset_t primary_value = (*primary ^ (uintptr_t)element);
	if (primary_value != zcache_canary) {
		panic("Zone cache element was used after free! Element %p was corrupted at beginning; Expected %p but found %p; canary %p",
			element, (void *)(zcache_canary ^ (uintptr_t)element) , (void *)(*primary), (void *)zcache_canary);
	}
	
	vm_offset_t backup_value = (*backup ^ (uintptr_t)element);
	if (backup_value != zcache_canary) {
		panic("Zone cache element was used after free! Element %p was corrupted at end; Expected %p but found %p; canary %p",
			element, (void *)(zcache_canary ^ (uintptr_t)element), (void *)(*backup), (void *)zcache_canary);
	}
}
