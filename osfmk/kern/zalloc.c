/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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
#include <zone_debug.h>
#include <norma_vm.h>
#include <mach_kdb.h>
#include <kern/ast.h>
#include <kern/assert.h>
#include <kern/macro_help.h>
#include <kern/sched.h>
#include <kern/lock.h>
#include <kern/sched_prim.h>
#include <kern/misc_protos.h>
#include <kern/thread_call.h>
#include <kern/zalloc.h>
#include <mach/vm_param.h>
#include <vm/vm_kern.h>
#include <machine/machparam.h>


#if	MACH_ASSERT
/* Detect use of zone elt after freeing it by two methods:
 * (1) Range-check the free-list "next" ptr for sanity.
 * (2) Store the ptr in two different words, and compare them against
 *     each other when re-using the zone elt, to detect modifications;
 */

#if defined(__alpha)

#define is_kernel_data_addr(a)						\
		(!(a) || IS_SYS_VA(a) && !((a) & (sizeof(long)-1)))

#else /* !defined(__alpha) */

#define is_kernel_data_addr(a)						\
		(!(a) || (a) >= VM_MIN_KERNEL_ADDRESS && !((a) & 0x3))

#endif /* defined(__alpha) */

/* Should we set all words of the zone element to an illegal address
 * when it is freed, to help catch usage after freeing?  The down-side
 * is that this obscures the identity of the freed element.
 */
boolean_t zfree_clear = FALSE;

#define ADD_TO_ZONE(zone, element)					\
MACRO_BEGIN								\
		if (zfree_clear)					\
		{   int i;						\
		    for (i=1;						\
			 i < zone->elem_size/sizeof(vm_offset_t) - 1;	\
			 i++)						\
		    ((vm_offset_t *)(element))[i] = 0xdeadbeef;		\
		}							\
		((vm_offset_t *)(element))[0] = (zone)->free_elements;	\
		(zone)->free_elements = (vm_offset_t) (element);	\
		(zone)->count--;					\
MACRO_END

#define REMOVE_FROM_ZONE(zone, ret, type)				\
MACRO_BEGIN								\
	(ret) = (type) (zone)->free_elements;				\
	if ((ret) != (type) 0) {					\
	    if (!is_kernel_data_addr(((vm_offset_t *)(ret))[0])) {	\
		panic("A freed zone element has been modified.\n");	\
	    }								\
	    (zone)->count++;						\
	    (zone)->free_elements = *((vm_offset_t *)(ret));		\
	}								\
MACRO_END
#else	/* MACH_ASSERT */

#define ADD_TO_ZONE(zone, element)					\
MACRO_BEGIN								\
		*((vm_offset_t *)(element)) = (zone)->free_elements;	\
		(zone)->free_elements = (vm_offset_t) (element);	\
		(zone)->count--;					\
MACRO_END

#define REMOVE_FROM_ZONE(zone, ret, type)				\
MACRO_BEGIN								\
	(ret) = (type) (zone)->free_elements;				\
	if ((ret) != (type) 0) {					\
		(zone)->count++;					\
		(zone)->free_elements = *((vm_offset_t *)(ret));	\
	}								\
MACRO_END

#endif	/* MACH_ASSERT */

#if	ZONE_DEBUG
#define zone_debug_enabled(z) z->active_zones.next
#endif	/* ZONE_DEBUG */

/*
 * Support for garbage collection of unused zone pages:
 */

struct zone_page_table_entry {
	struct	zone_page_table_entry	*next;
	short 	in_free_list;
	short	alloc_count;
};

extern struct zone_page_table_entry * zone_page_table;

#define lock_zone_page_table() simple_lock(&zone_page_table_lock)
#define unlock_zone_page_table() simple_unlock(&zone_page_table_lock)

#define	zone_page(addr) \
    (&(zone_page_table[(atop(((vm_offset_t)addr) - zone_map_min_address))]))

/* Forwards */
void		zone_page_init(
				vm_offset_t	addr,
				vm_size_t	size,
				int		value);

void		zone_page_alloc(
				vm_offset_t	addr,
				vm_size_t	size);

void		zone_add_free_page_list(
				struct zone_page_table_entry	**free_list,
				vm_offset_t	addr,
				vm_size_t	size);
void		zone_page_dealloc(
				vm_offset_t	addr,
				vm_size_t	size);

void		zone_page_in_use(
				vm_offset_t	addr,
				vm_size_t	size);

void		zone_page_free(
				vm_offset_t	addr,
				vm_size_t	size);

boolean_t	zone_page_collectable(
				vm_offset_t	addr,
				vm_size_t	size);

void		zone_page_keep(
				vm_offset_t	addr,
				vm_size_t	size);

void		zalloc_async(
				thread_call_param_t	p0,  
				thread_call_param_t	p1);


#if	ZONE_DEBUG && MACH_KDB
int		zone_count(
				zone_t		z,
				int		tail);
#endif	/* ZONE_DEBUG && MACH_KDB */

vm_map_t	zone_map = VM_MAP_NULL;

zone_t		zone_zone = ZONE_NULL;	/* the zone containing other zones */

/*
 *	The VM system gives us an initial chunk of memory.
 *	It has to be big enough to allocate the zone_zone
 */

vm_offset_t	zdata;
vm_size_t	zdata_size;

#define lock_zone(zone)					\
MACRO_BEGIN						\
	simple_lock(&(zone)->lock);			\
MACRO_END

#define unlock_zone(zone)				\
MACRO_BEGIN						\
	simple_unlock(&(zone)->lock);			\
MACRO_END

#define zone_wakeup(zone) thread_wakeup((event_t)(zone))
#define zone_sleep(zone)				\
	thread_sleep_simple_lock((event_t)(zone),	\
				&(zone)->lock,		\
				THREAD_UNINT)

#define lock_zone_init(zone)				\
MACRO_BEGIN						\
	simple_lock_init(&zone->lock, ETAP_MISC_ZONE);	\
MACRO_END

#define lock_try_zone(zone)	simple_lock_try(&zone->lock)

kern_return_t		zget_space(
				vm_offset_t size,
				vm_offset_t *result);

decl_simple_lock_data(,zget_space_lock)
vm_offset_t	zalloc_next_space;
vm_offset_t	zalloc_end_of_space;
vm_size_t	zalloc_wasted_space;

/*
 *	Garbage collection map information
 */
decl_simple_lock_data(,		zone_page_table_lock)
struct zone_page_table_entry *	zone_page_table;
vm_offset_t			zone_map_min_address;
vm_offset_t			zone_map_max_address;
integer_t			zone_pages;

/*
 *	Exclude more than one concurrent garbage collection
 */
decl_mutex_data(,		zone_gc_lock)

#define from_zone_map(addr) \
	((vm_offset_t)(addr) >= zone_map_min_address && \
	 (vm_offset_t)(addr) <  zone_map_max_address)

#define	ZONE_PAGE_USED  0
#define ZONE_PAGE_UNUSED -1


/*
 *	Protects first_zone, last_zone, num_zones,
 *	and the next_zone field of zones.
 */
decl_simple_lock_data(,	all_zones_lock)
zone_t			first_zone;
zone_t			*last_zone;
int			num_zones;

boolean_t zone_gc_allowed = TRUE;
boolean_t zone_gc_forced = FALSE;
unsigned zone_gc_last_tick = 0;
unsigned zone_gc_max_rate = 0;		/* in ticks */


/*
 *	zinit initializes a new zone.  The zone data structures themselves
 *	are stored in a zone, which is initially a static structure that
 *	is initialized by zone_init.
 */
zone_t
zinit(
	vm_size_t	size,		/* the size of an element */
	vm_size_t	max,		/* maximum memory to use */
	vm_size_t	alloc,		/* allocation size */
	char		*name)		/* a name for the zone */
{
	zone_t		z;

	if (zone_zone == ZONE_NULL) {
		if (zget_space(sizeof(struct zone), (vm_offset_t *)&z)
		    != KERN_SUCCESS)
			return(ZONE_NULL);
	} else
		z = (zone_t) zalloc(zone_zone);
	if (z == ZONE_NULL)
		return(ZONE_NULL);

	/*
	 *	Round off all the parameters appropriately.
	 */
	if (size < sizeof(z->free_elements))
		size = sizeof(z->free_elements);
	size = ((size-1)  + sizeof(z->free_elements)) -
		((size-1) % sizeof(z->free_elements));
 	if (alloc == 0)
		alloc = PAGE_SIZE;
	alloc = round_page(alloc);
	max   = round_page(max);
	/*
	 * We look for an allocation size with least fragmentation
	 * in the range of 1 - 5 pages.  This size will be used unless
	 * the user suggestion is larger AND has less fragmentation
	 */
	{	vm_size_t best, waste; unsigned int i;
		best  = PAGE_SIZE;
		waste = best % size;
		for (i = 2; i <= 5; i++){	vm_size_t tsize, twaste;
			tsize  = i * PAGE_SIZE;
			twaste = tsize % size;
			if (twaste < waste)
				best = tsize, waste = twaste;
		}
		if (alloc <= best || (alloc % size >= waste))
			alloc = best;
	}
	if (max && (max < alloc))
		max = alloc;

	z->free_elements = 0;
	z->cur_size = 0;
	z->max_size = max;
	z->elem_size = size;
	z->alloc_size = alloc;
	z->zone_name = name;
	z->count = 0;
	z->doing_alloc = FALSE;
	z->exhaustible = FALSE;
	z->collectable = TRUE;
	z->allows_foreign = FALSE;
	z->expandable  = TRUE;
	z->waiting = FALSE;
	z->async_pending = FALSE;

#if	ZONE_DEBUG
	z->active_zones.next = z->active_zones.prev = 0;	
	zone_debug_enable(z);
#endif	/* ZONE_DEBUG */
	lock_zone_init(z);

	/*
	 *	Add the zone to the all-zones list.
	 */

	z->next_zone = ZONE_NULL;
	thread_call_setup(&z->call_async_alloc, zalloc_async, z);
	simple_lock(&all_zones_lock);
	*last_zone = z;
	last_zone = &z->next_zone;
	num_zones++;
	simple_unlock(&all_zones_lock);

	return(z);
}

/*
 *	Cram the given memory into the specified zone.
 */
void
zcram(
	register zone_t		zone,
	vm_offset_t		newmem,
	vm_size_t		size)
{
	register vm_size_t	elem_size;

	/* Basic sanity checks */
	assert(zone != ZONE_NULL && newmem != (vm_offset_t)0);
	assert(!zone->collectable || zone->allows_foreign
		|| (from_zone_map(newmem) && from_zone_map(newmem+size-1)));

	elem_size = zone->elem_size;

	lock_zone(zone);
	while (size >= elem_size) {
		ADD_TO_ZONE(zone, newmem);
		if (from_zone_map(newmem))
			zone_page_alloc(newmem, elem_size);
		zone->count++;	/* compensate for ADD_TO_ZONE */
		size -= elem_size;
		newmem += elem_size;
		zone->cur_size += elem_size;
	}
	unlock_zone(zone);
}

/*
 * Contiguous space allocator for non-paged zones. Allocates "size" amount
 * of memory from zone_map.
 */

kern_return_t
zget_space(
	vm_offset_t size,
	vm_offset_t *result)
{
	vm_offset_t	new_space = 0;
	vm_size_t	space_to_add;

	simple_lock(&zget_space_lock);
	while ((zalloc_next_space + size) > zalloc_end_of_space) {
		/*
		 *	Add at least one page to allocation area.
		 */

		space_to_add = round_page(size);

		if (new_space == 0) {
			kern_return_t retval;
			/*
			 *	Memory cannot be wired down while holding
			 *	any locks that the pageout daemon might
			 *	need to free up pages.  [Making the zget_space
			 *	lock a complex lock does not help in this
			 *	regard.]
			 *
			 *	Unlock and allocate memory.  Because several
			 *	threads might try to do this at once, don't
			 *	use the memory before checking for available
			 *	space again.
			 */

			simple_unlock(&zget_space_lock);

			retval = kernel_memory_allocate(zone_map, &new_space,
				space_to_add, 0, KMA_KOBJECT|KMA_NOPAGEWAIT);
			if (retval != KERN_SUCCESS)
				return(retval);
			zone_page_init(new_space, space_to_add,
							ZONE_PAGE_USED);
			simple_lock(&zget_space_lock);
			continue;
		}

		
		/*
	  	 *	Memory was allocated in a previous iteration.
		 *
		 *	Check whether the new region is contiguous
		 *	with the old one.
		 */

		if (new_space != zalloc_end_of_space) {
			/*
			 *	Throw away the remainder of the
			 *	old space, and start a new one.
			 */
			zalloc_wasted_space +=
				zalloc_end_of_space - zalloc_next_space;
			zalloc_next_space = new_space;
		}

		zalloc_end_of_space = new_space + space_to_add;

		new_space = 0;
	}
	*result = zalloc_next_space;
	zalloc_next_space += size;		
	simple_unlock(&zget_space_lock);

	if (new_space != 0)
		kmem_free(zone_map, new_space, space_to_add);

	return(KERN_SUCCESS);
}


/*
 *	Steal memory for the zone package.  Called from
 *	vm_page_bootstrap().
 */
void
zone_steal_memory(void)
{
	zdata_size = round_page(128*sizeof(struct zone));
	zdata = pmap_steal_memory(zdata_size);
}


/*
 * Fill a zone with enough memory to contain at least nelem elements.
 * Memory is obtained with kmem_alloc_wired from the kernel_map.
 * Return the number of elements actually put into the zone, which may
 * be more than the caller asked for since the memory allocation is
 * rounded up to a full page.
 */
int
zfill(
	zone_t	zone,
	int	nelem)
{
	kern_return_t	kr;
	vm_size_t	size;
	vm_offset_t	memory;
	int		nalloc;

	assert(nelem > 0);
	if (nelem <= 0)
		return 0;
	size = nelem * zone->elem_size;
	size = round_page(size);
	kr = kmem_alloc_wired(kernel_map, &memory, size);
	if (kr != KERN_SUCCESS)
		return 0;

	zone_change(zone, Z_FOREIGN, TRUE);
	zcram(zone, memory, size);
	nalloc = size / zone->elem_size;
	assert(nalloc >= nelem);

	return nalloc;
}

/*
 *	Initialize the "zone of zones" which uses fixed memory allocated
 *	earlier in memory initialization.  zone_bootstrap is called
 *	before zone_init.
 */
void
zone_bootstrap(void)
{
	vm_size_t zone_zone_size;
	vm_offset_t zone_zone_space;

	simple_lock_init(&all_zones_lock, ETAP_MISC_ZONE_ALL);

	first_zone = ZONE_NULL;
	last_zone = &first_zone;
	num_zones = 0;

	simple_lock_init(&zget_space_lock, ETAP_MISC_ZONE_GET);
	zalloc_next_space = zdata;
	zalloc_end_of_space = zdata + zdata_size;
	zalloc_wasted_space = 0;

	/* assertion: nobody else called zinit before us */
	assert(zone_zone == ZONE_NULL);
	zone_zone = zinit(sizeof(struct zone), 128 * sizeof(struct zone),
			  sizeof(struct zone), "zones");
	zone_change(zone_zone, Z_COLLECT, FALSE);
	zone_zone_size = zalloc_end_of_space - zalloc_next_space;
	zget_space(zone_zone_size, &zone_zone_space);
	zcram(zone_zone, zone_zone_space, zone_zone_size);
}

void
zone_init(
	vm_size_t max_zonemap_size)
{
	kern_return_t	retval;
	vm_offset_t	zone_min;
	vm_offset_t	zone_max;
	vm_size_t	zone_table_size;

	retval = kmem_suballoc(kernel_map, &zone_min, max_zonemap_size,
						FALSE, TRUE, &zone_map);
	if (retval != KERN_SUCCESS)
		panic("zone_init: kmem_suballoc failed");
	zone_max = zone_min + round_page(max_zonemap_size);
	/*
	 * Setup garbage collection information:
	 */
	zone_table_size = atop(zone_max - zone_min) * 
				sizeof(struct zone_page_table_entry);
	if (kmem_alloc_wired(zone_map, (vm_offset_t *) &zone_page_table,
			     zone_table_size) != KERN_SUCCESS)
		panic("zone_init");
	zone_min = (vm_offset_t)zone_page_table + round_page(zone_table_size);
	zone_pages = atop(zone_max - zone_min);
	zone_map_min_address = zone_min;
	zone_map_max_address = zone_max;
	simple_lock_init(&zone_page_table_lock, ETAP_MISC_ZONE_PTABLE);
	mutex_init(&zone_gc_lock, ETAP_NO_TRACE);
	zone_page_init(zone_min, zone_max - zone_min, ZONE_PAGE_UNUSED);
}


/*
 *	zalloc returns an element from the specified zone.
 */
vm_offset_t
zalloc_canblock(
	register zone_t	zone,
	boolean_t canblock)
{
	vm_offset_t	addr;
	kern_return_t retval;

	assert(zone != ZONE_NULL);
	check_simple_locks();

	lock_zone(zone);

	REMOVE_FROM_ZONE(zone, addr, vm_offset_t);

	while ((addr == 0) && canblock) {
		/*
 		 *	If nothing was there, try to get more
		 */
		if (zone->doing_alloc) {
			/*
			 *	Someone is allocating memory for this zone.
			 *	Wait for it to show up, then try again.
			 */
			zone->waiting = TRUE;
			zone_sleep(zone);
		}
		else {
			if ((zone->cur_size + zone->elem_size) >
			    zone->max_size) {
				if (zone->exhaustible)
					break;
				if (zone->expandable) {
					/*
					 * We're willing to overflow certain
					 * zones, but not without complaining.
					 *
					 * This is best used in conjunction
					 * with the collectable flag. What we
					 * want is an assurance we can get the
					 * memory back, assuming there's no
					 * leak. 
					 */
					zone->max_size += (zone->max_size >> 1);
				} else {
					unlock_zone(zone);

					panic("zalloc: zone \"%s\" empty.", zone->zone_name);
				}
			}
			zone->doing_alloc = TRUE;
			unlock_zone(zone);

			if (zone->collectable) {
				vm_offset_t space;
				vm_size_t alloc_size;

				if (vm_pool_low())
					alloc_size = 
					  round_page(zone->elem_size);
				else
					alloc_size = zone->alloc_size;

				retval = kernel_memory_allocate(zone_map,
					&space, alloc_size, 0,
					KMA_KOBJECT|KMA_NOPAGEWAIT);
				if (retval == KERN_SUCCESS) {
					zone_page_init(space, alloc_size,
						ZONE_PAGE_USED);
					zcram(zone, space, alloc_size);
				} else if (retval != KERN_RESOURCE_SHORTAGE) {
					/* would like to cause a zone_gc() */

					panic("zalloc");
				}
				lock_zone(zone);
				zone->doing_alloc = FALSE; 
				if (zone->waiting) {
					zone->waiting = FALSE;
					zone_wakeup(zone);
				}
				REMOVE_FROM_ZONE(zone, addr, vm_offset_t);
				if (addr == 0 &&
					retval == KERN_RESOURCE_SHORTAGE) {
					unlock_zone(zone);
					
					VM_PAGE_WAIT();
					lock_zone(zone);
				}
			} else {
				vm_offset_t space;
				retval = zget_space(zone->elem_size, &space);

				lock_zone(zone);
				zone->doing_alloc = FALSE; 
				if (zone->waiting) {
					zone->waiting = FALSE;
					thread_wakeup((event_t)zone);
				}
				if (retval == KERN_SUCCESS) {
					zone->count++;
					zone->cur_size += zone->elem_size;
#if	ZONE_DEBUG
					if (zone_debug_enabled(zone)) {
					    enqueue_tail(&zone->active_zones, (queue_entry_t)space);
					}
#endif
					unlock_zone(zone);
					zone_page_alloc(space, zone->elem_size);
#if	ZONE_DEBUG
					if (zone_debug_enabled(zone))
						space += sizeof(queue_chain_t);
#endif
					return(space);
				}
				if (retval == KERN_RESOURCE_SHORTAGE) {
					unlock_zone(zone);
					
					VM_PAGE_WAIT();
					lock_zone(zone);
				} else {
					panic("zalloc");
				}
			}
		}
		if (addr == 0)
			REMOVE_FROM_ZONE(zone, addr, vm_offset_t);
	}

	if ((addr == 0) && !canblock && (zone->async_pending == FALSE) && (!vm_pool_low())) {
		zone->async_pending = TRUE;
		unlock_zone(zone);
		thread_call_enter(&zone->call_async_alloc);
		lock_zone(zone);
		REMOVE_FROM_ZONE(zone, addr, vm_offset_t);
	}

#if	ZONE_DEBUG
	if (addr && zone_debug_enabled(zone)) {
		enqueue_tail(&zone->active_zones, (queue_entry_t)addr);
		addr += sizeof(queue_chain_t);
	}
#endif

	unlock_zone(zone);

	return(addr);
}


vm_offset_t
zalloc(
       register zone_t zone)
{
  return( zalloc_canblock(zone, TRUE) );
}

vm_offset_t
zalloc_noblock(
	       register zone_t zone)
{
  return( zalloc_canblock(zone, FALSE) );
}

void
zalloc_async(
	thread_call_param_t	p0,
	thread_call_param_t	p1)
{
	vm_offset_t	elt;

	elt = zalloc_canblock((zone_t)p0, TRUE);
	zfree((zone_t)p0, elt);
	lock_zone(((zone_t)p0));
	((zone_t)p0)->async_pending = FALSE;
	unlock_zone(((zone_t)p0));
}


/*
 *	zget returns an element from the specified zone
 *	and immediately returns nothing if there is nothing there.
 *
 *	This form should be used when you can not block (like when
 *	processing an interrupt).
 */
vm_offset_t
zget(
	register zone_t	zone)
{
	register vm_offset_t	addr;

	assert( zone != ZONE_NULL );

	if (!lock_try_zone(zone))
	    return ((vm_offset_t)0);

	REMOVE_FROM_ZONE(zone, addr, vm_offset_t);
#if	ZONE_DEBUG
	if (addr && zone_debug_enabled(zone)) {
		enqueue_tail(&zone->active_zones, (queue_entry_t)addr);
		addr += sizeof(queue_chain_t);
	}
#endif	/* ZONE_DEBUG */
	unlock_zone(zone);

	return(addr);
}

/* Keep this FALSE by default.  Large memory machine run orders of magnitude
   slower in debug mode when true.  Use debugger to enable if needed */
boolean_t zone_check = FALSE;

void
zfree(
	register zone_t	zone,
	vm_offset_t	elem)
{

#if MACH_ASSERT
	/* Basic sanity checks */
	if (zone == ZONE_NULL || elem == (vm_offset_t)0)
		panic("zfree: NULL");
	/* zone_gc assumes zones are never freed */
	if (zone == zone_zone)
		panic("zfree: freeing to zone_zone breaks zone_gc!");
	if (zone->collectable && !zone->allows_foreign &&
	    (!from_zone_map(elem) || !from_zone_map(elem+zone->elem_size-1)))
		panic("zfree: non-allocated memory in collectable zone!");
#endif

	lock_zone(zone);
#if	ZONE_DEBUG
	if (zone_debug_enabled(zone)) {
		queue_t tmp_elem;

		elem -= sizeof(queue_chain_t);
		if (zone_check) {
			/* check the zone's consistency */

			for (tmp_elem = queue_first(&zone->active_zones);
			     !queue_end(tmp_elem, &zone->active_zones);
			     tmp_elem = queue_next(tmp_elem))
				if (elem == (vm_offset_t)tmp_elem)
					break;
			if (elem != (vm_offset_t)tmp_elem)
				panic("zfree()ing element from wrong zone");
		}
		remqueue(&zone->active_zones, (queue_t) elem);
	}
#endif	/* ZONE_DEBUG */
	if (zone_check) {
		vm_offset_t this;

		/* check the zone's consistency */

		for (this = zone->free_elements;
		     this != 0;
		     this = * (vm_offset_t *) this)
			if (!pmap_kernel_va(this) || this == elem)
				panic("zfree");
	}
	ADD_TO_ZONE(zone, elem);

	/*
	 * If elements have one or more pages, and memory is low,
	 * request to run the garbage collection in the zone  the next 
	 * time the pageout thread runs.
	 */
	if (zone->elem_size >= PAGE_SIZE && 
	    vm_pool_low()){
		zone_gc_forced = TRUE;
	}
	unlock_zone(zone);
}


/*	Change a zone's flags.
 *	This routine must be called immediately after zinit.
 */
void
zone_change(
	zone_t		zone,
	unsigned int	item,
	boolean_t	value)
{
	assert( zone != ZONE_NULL );
	assert( value == TRUE || value == FALSE );

	switch(item){
		case Z_EXHAUST:
			zone->exhaustible = value;
			break;
		case Z_COLLECT:
			zone->collectable = value;
			break;
		case Z_EXPAND:
			zone->expandable = value;
			break;
		case Z_FOREIGN:
			zone->allows_foreign = value;
			break;
#if MACH_ASSERT
		default:
			panic("Zone_change: Wrong Item Type!");
			/* break; */
#endif
	}
	lock_zone_init(zone);
}

/*
 * Return the expected number of free elements in the zone.
 * This calculation will be incorrect if items are zfree'd that
 * were never zalloc'd/zget'd. The correct way to stuff memory
 * into a zone is by zcram.
 */

integer_t
zone_free_count(zone_t zone)
{
	integer_t free_count;

	lock_zone(zone);
	free_count = zone->cur_size/zone->elem_size - zone->count;
	unlock_zone(zone);

	assert(free_count >= 0);

	return(free_count);
}

/*
 *	zprealloc preallocates wired memory, exanding the specified
 *      zone to the specified size
 */
void
zprealloc(
	zone_t	zone,
	vm_size_t size)
{
        vm_offset_t addr;

	if (size != 0) {
		if (kmem_alloc_wired(zone_map, &addr, size) != KERN_SUCCESS)
		  panic("zprealloc");
		zone_page_init(addr, size, ZONE_PAGE_USED);
		zcram(zone, addr, size);
	}
}

/*
 *  Zone garbage collection subroutines
 *
 *  These routines have in common the modification of entries in the
 *  zone_page_table.  The latter contains one entry for every page
 *  in the zone_map.  
 *
 *  For each page table entry in the given range:
 *
 *	zone_page_collectable	- test if one (in_free_list == alloc_count)
 *	zone_page_keep		- reset in_free_list
 *	zone_page_in_use        - decrements in_free_list
 *	zone_page_free          - increments in_free_list
 *	zone_page_init          - initializes in_free_list and alloc_count
 *	zone_page_alloc         - increments alloc_count
 *	zone_page_dealloc       - decrements alloc_count
 *	zone_add_free_page_list - adds the page to the free list
 *   
 *  Two counts are maintained for each page, the in_free_list count and
 *  alloc_count.  The alloc_count is how many zone elements have been
 *  allocated from a page.  (Note that the page could contain elements
 *  that span page boundaries.  The count includes these elements so
 *  one element may be counted in two pages.) In_free_list is a count
 *  of how many zone elements are currently free.  If in_free_list is
 *  equal to alloc_count then the page is eligible for garbage
 *  collection.
 *
 *  Alloc_count and in_free_list are initialized to the correct values
 *  for a particular zone when a page is zcram'ed into a zone.  Subsequent
 *  gets and frees of zone elements will call zone_page_in_use and 
 *  zone_page_free which modify the in_free_list count.  When the zones
 *  garbage collector runs it will walk through a zones free element list,
 *  remove the elements that reside on collectable pages, and use 
 *  zone_add_free_page_list to create a list of pages to be collected.
 */
boolean_t
zone_page_collectable(
	vm_offset_t	addr,
	vm_size_t	size)
{
	natural_t i, j;

#if MACH_ASSERT
	if (!from_zone_map(addr) || !from_zone_map(addr+size-1))
		panic("zone_page_collectable");
#endif

	i = atop(addr-zone_map_min_address);
	j = atop((addr+size-1) - zone_map_min_address);
	lock_zone_page_table();
	for (; i <= j; i++) {
		if (zone_page_table[i].in_free_list ==
		    zone_page_table[i].alloc_count) {
			unlock_zone_page_table();
			return (TRUE);
		}
	}
	unlock_zone_page_table();
	return (FALSE);
}

void
zone_page_keep(
	vm_offset_t	addr,
	vm_size_t	size)
{
	natural_t i, j;

#if MACH_ASSERT
	if (!from_zone_map(addr) || !from_zone_map(addr+size-1))
		panic("zone_page_keep");
#endif

	i = atop(addr-zone_map_min_address);
	j = atop((addr+size-1) - zone_map_min_address);
	lock_zone_page_table();
	for (; i <= j; i++) {
		zone_page_table[i].in_free_list = 0;
	}
	unlock_zone_page_table();
}

void
zone_page_in_use(
	vm_offset_t	addr,
	vm_size_t	size)
{
	natural_t i, j;

#if MACH_ASSERT
	if (!from_zone_map(addr) || !from_zone_map(addr+size-1))
		panic("zone_page_in_use");
#endif

	i = atop(addr-zone_map_min_address);
	j = atop((addr+size-1) - zone_map_min_address);
	lock_zone_page_table();
	for (; i <= j; i++) {
		if (zone_page_table[i].in_free_list > 0)
			zone_page_table[i].in_free_list--;
	}
	unlock_zone_page_table();
}

void
zone_page_free(
	vm_offset_t	addr,
	vm_size_t	size)
{
	natural_t i, j;

#if MACH_ASSERT
	if (!from_zone_map(addr) || !from_zone_map(addr+size-1))
		panic("zone_page_free");
#endif

	i = atop(addr-zone_map_min_address);
	j = atop((addr+size-1) - zone_map_min_address);
	lock_zone_page_table();
	for (; i <= j; i++) {
		assert(zone_page_table[i].in_free_list >= 0);
		zone_page_table[i].in_free_list++;
	}
	unlock_zone_page_table();
}

void
zone_page_init(
	vm_offset_t	addr,
	vm_size_t	size,
	int		value)
{
	natural_t i, j;

#if MACH_ASSERT
	if (!from_zone_map(addr) || !from_zone_map(addr+size-1))
		panic("zone_page_init");
#endif

	i = atop(addr-zone_map_min_address);
	j = atop((addr+size-1) - zone_map_min_address);
	lock_zone_page_table();
	for (; i <= j; i++) {
		zone_page_table[i].alloc_count = value;
		zone_page_table[i].in_free_list = 0;
	}
	unlock_zone_page_table();
}

void
zone_page_alloc(
	vm_offset_t	addr,
	vm_size_t	size)
{
	natural_t i, j;

#if MACH_ASSERT
	if (!from_zone_map(addr) || !from_zone_map(addr+size-1))
		panic("zone_page_alloc");
#endif

	i = atop(addr-zone_map_min_address);
	j = atop((addr+size-1) - zone_map_min_address);
	lock_zone_page_table();
	for (; i <= j; i++) {
		/* Set alloc_count to (ZONE_PAGE_USED + 1) if
		 * it was previously set to ZONE_PAGE_UNUSED.
		 */
		if (zone_page_table[i].alloc_count == ZONE_PAGE_UNUSED) {
			zone_page_table[i].alloc_count = 1;
		} else {
			zone_page_table[i].alloc_count++;
		}
	}
	unlock_zone_page_table();
}

void
zone_page_dealloc(
	vm_offset_t	addr,
	vm_size_t	size)
{
	natural_t i, j;

#if MACH_ASSERT
	if (!from_zone_map(addr) || !from_zone_map(addr+size-1))
		panic("zone_page_dealloc");
#endif

	i = atop(addr-zone_map_min_address);
	j = atop((addr+size-1) - zone_map_min_address);
	lock_zone_page_table();
	for (; i <= j; i++) {
		zone_page_table[i].alloc_count--;
	}
	unlock_zone_page_table();
}

void
zone_add_free_page_list(
	struct zone_page_table_entry	**free_list,
	vm_offset_t	addr,
	vm_size_t	size)
{
	natural_t i, j;

#if MACH_ASSERT
	if (!from_zone_map(addr) || !from_zone_map(addr+size-1))
		panic("zone_add_free_page_list");
#endif

	i = atop(addr-zone_map_min_address);
	j = atop((addr+size-1) - zone_map_min_address);
	lock_zone_page_table();
	for (; i <= j; i++) {
		if (zone_page_table[i].alloc_count == 0) {
			zone_page_table[i].next = *free_list;
			*free_list = &zone_page_table[i];
			zone_page_table[i].alloc_count  = ZONE_PAGE_UNUSED;
			zone_page_table[i].in_free_list = 0;
		}
	}
	unlock_zone_page_table();
}


/* This is used for walking through a zone's free element list.
 */
struct zone_free_entry {
	struct zone_free_entry * next;
};

int reclaim_page_count = 0;

/*	Zone garbage collection
 *
 *	zone_gc will walk through all the free elements in all the
 *	zones that are marked collectable looking for reclaimable
 *	pages.  zone_gc is called by consider_zone_gc when the system
 *	begins to run out of memory.
 */
void
zone_gc(void)
{
	unsigned int	max_zones;
	zone_t		z;
	unsigned int	i;
	struct zone_page_table_entry	*freep;
	struct zone_page_table_entry	*zone_free_page_list;

	mutex_lock(&zone_gc_lock);

	/*
	 * Note that this scheme of locking only to walk the zone list
	 * assumes that zones are never freed (checked by zfree)
	 */ 
	simple_lock(&all_zones_lock);
	max_zones = num_zones;
	z = first_zone;
	simple_unlock(&all_zones_lock);

#if MACH_ASSERT
	lock_zone_page_table();
	for (i = 0; i < zone_pages; i++)
		assert(zone_page_table[i].in_free_list == 0);
	unlock_zone_page_table();
#endif /* MACH_ASSERT */

	zone_free_page_list = (struct zone_page_table_entry *) 0;

	for (i = 0; i < max_zones; i++, z = z->next_zone) {
		struct zone_free_entry * prev;
		struct zone_free_entry * elt;
		struct zone_free_entry * end;

		assert(z != ZONE_NULL);

		if (!z->collectable)
			continue;

		lock_zone(z);

		/*
		 * Do a quick feasability check before we scan the zone: 
		 * skip unless there is likelihood of getting 1+ pages back.
		 */
		if ((z->cur_size - z->count * z->elem_size) <= (2*PAGE_SIZE)){
			unlock_zone(z);		
			continue;
		}

		/* Count the free elements in each page.  This loop
		 * requires that all in_free_list entries are zero.
		 *
		 * Exit the loop early if we need to hurry up and drop
		 * the lock to allow preemption - but we must fully process
		 * all elements we looked at so far.
		 */
		elt = (struct zone_free_entry *)(z->free_elements);
		while (!ast_urgency() && (elt != (struct zone_free_entry *)0)) {
			if (from_zone_map(elt))
				zone_page_free((vm_offset_t)elt, z->elem_size);
			elt = elt->next;
		}
		end = elt;

		/* Now determine which elements should be removed
		 * from the free list and, after all the elements
		 * on a page have been removed, add the element's
		 * page to a list of pages to be freed.
		 */
		prev = elt = (struct zone_free_entry *)(z->free_elements);
		while (elt != end) {
			if (!from_zone_map(elt)) {
				prev = elt;
				elt = elt->next;
				continue;
			}
			if (zone_page_collectable((vm_offset_t)elt,
						  z->elem_size)) {
				z->cur_size -= z->elem_size;
				zone_page_in_use((vm_offset_t)elt,
						 z->elem_size);
				zone_page_dealloc((vm_offset_t)elt,
						  z->elem_size);
				zone_add_free_page_list(&zone_free_page_list, 
							(vm_offset_t)elt,
							z->elem_size);
				if (elt == prev) {
					elt = elt->next;
					z->free_elements =(vm_offset_t)elt;
					prev = elt;
				} else {
					prev->next = elt->next;
					elt = elt->next;
				}
			} else {
				/* This element is not eligible for collection
				 * so clear in_free_list in preparation for a
				 * subsequent garbage collection pass.
				 */
				zone_page_keep((vm_offset_t)elt, z->elem_size);
				prev = elt;
				elt = elt->next;
			}
		} /* end while(elt != end) */

		unlock_zone(z);
	}

	for (freep = zone_free_page_list; freep != 0; freep = freep->next) {
		vm_offset_t	free_addr;

		free_addr = zone_map_min_address + 
			    PAGE_SIZE * (freep - zone_page_table);
		kmem_free(zone_map, free_addr, PAGE_SIZE);
		reclaim_page_count++;
	}
	mutex_unlock(&zone_gc_lock);
}

/*
 *	consider_zone_gc:
 *
 *	Called by the pageout daemon when the system needs more free pages.
 */

void
consider_zone_gc(void)
{
	/*
	 *	By default, don't attempt zone GC more frequently
	 *	than once a second.
	 */

	if (zone_gc_max_rate == 0)
		zone_gc_max_rate = (1 << SCHED_TICK_SHIFT) + 1;

	if (zone_gc_allowed &&
	    ((sched_tick > (zone_gc_last_tick + zone_gc_max_rate)) ||
	     zone_gc_forced)) {
		zone_gc_forced = FALSE;
		zone_gc_last_tick = sched_tick;
		zone_gc();
	}
}

#include <mach/kern_return.h>
#include <mach/machine/vm_types.h>
#include <mach_debug/zone_info.h>
#include <kern/host.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>

#include <mach/mach_host_server.h>

kern_return_t
host_zone_info(
	host_t			host,
	zone_name_array_t	*namesp,
	mach_msg_type_number_t  *namesCntp,
	zone_info_array_t	*infop,
	mach_msg_type_number_t  *infoCntp)
{
	zone_name_t	*names;
	vm_offset_t	names_addr;
	vm_size_t	names_size;
	zone_info_t	*info;
	vm_offset_t	info_addr;
	vm_size_t	info_size;
	unsigned int	max_zones, i;
	zone_t		z;
	zone_name_t    *zn;
	zone_info_t    *zi;
	kern_return_t	kr;

	if (host == HOST_NULL)
		return KERN_INVALID_HOST;

	/*
	 *	We assume that zones aren't freed once allocated.
	 *	We won't pick up any zones that are allocated later.
	 */

	simple_lock(&all_zones_lock);
#ifdef ppc
	max_zones = num_zones + 4;
#else
	max_zones = num_zones + 2;
#endif
	z = first_zone;
	simple_unlock(&all_zones_lock);

	if (max_zones <= *namesCntp) {
		/* use in-line memory */

		names = *namesp;
	} else {
		names_size = round_page(max_zones * sizeof *names);
		kr = kmem_alloc_pageable(ipc_kernel_map,
					 &names_addr, names_size);
		if (kr != KERN_SUCCESS)
			return kr;
		names = (zone_name_t *) names_addr;
	}

	if (max_zones <= *infoCntp) {
		/* use in-line memory */

		info = *infop;
	} else {
		info_size = round_page(max_zones * sizeof *info);
		kr = kmem_alloc_pageable(ipc_kernel_map,
					 &info_addr, info_size);
		if (kr != KERN_SUCCESS) {
			if (names != *namesp)
				kmem_free(ipc_kernel_map,
					  names_addr, names_size);
			return kr;
		}

		info = (zone_info_t *) info_addr;
	}
	zn = &names[0];
	zi = &info[0];

	for (i = 0; i < num_zones; i++) {
		struct zone zcopy;

		assert(z != ZONE_NULL);

		lock_zone(z);
		zcopy = *z;
		unlock_zone(z);

		simple_lock(&all_zones_lock);
		z = z->next_zone;
		simple_unlock(&all_zones_lock);

		/* assuming here the name data is static */
		(void) strncpy(zn->zn_name, zcopy.zone_name,
			       sizeof zn->zn_name);

		zi->zi_count = zcopy.count;
		zi->zi_cur_size = zcopy.cur_size;
		zi->zi_max_size = zcopy.max_size;
		zi->zi_elem_size = zcopy.elem_size;
		zi->zi_alloc_size = zcopy.alloc_size;
		zi->zi_exhaustible = zcopy.exhaustible;
		zi->zi_collectable = zcopy.collectable;

		zn++;
		zi++;
	}
	strcpy(zn->zn_name, "kernel_stacks");
	stack_fake_zone_info(&zi->zi_count, &zi->zi_cur_size, &zi->zi_max_size, &zi->zi_elem_size,
			     &zi->zi_alloc_size, &zi->zi_collectable, &zi->zi_exhaustible);
	zn++;
	zi++;
#ifdef ppc
	strcpy(zn->zn_name, "save_areas");
	save_fake_zone_info(&zi->zi_count, &zi->zi_cur_size, &zi->zi_max_size, &zi->zi_elem_size,
			    &zi->zi_alloc_size, &zi->zi_collectable, &zi->zi_exhaustible);
	zn++;
	zi++;

	strcpy(zn->zn_name, "pmap_mappings");
	mapping_fake_zone_info(&zi->zi_count, &zi->zi_cur_size, &zi->zi_max_size, &zi->zi_elem_size,
			       &zi->zi_alloc_size, &zi->zi_collectable, &zi->zi_exhaustible);
	zn++;
	zi++;
#endif
	strcpy(zn->zn_name, "kalloc.large");
	kalloc_fake_zone_info(&zi->zi_count, &zi->zi_cur_size, &zi->zi_max_size, &zi->zi_elem_size,
			       &zi->zi_alloc_size, &zi->zi_collectable, &zi->zi_exhaustible);

	if (names != *namesp) {
		vm_size_t used;
		vm_map_copy_t copy;

		used = max_zones * sizeof *names;

		if (used != names_size)
			bzero((char *) (names_addr + used), names_size - used);

		kr = vm_map_copyin(ipc_kernel_map, names_addr, names_size,
				   TRUE, &copy);
		assert(kr == KERN_SUCCESS);

		*namesp = (zone_name_t *) copy;
	}
	*namesCntp = max_zones;

	if (info != *infop) {
		vm_size_t used;
		vm_map_copy_t copy;

		used = max_zones * sizeof *info;

		if (used != info_size)
			bzero((char *) (info_addr + used), info_size - used);

		kr = vm_map_copyin(ipc_kernel_map, info_addr, info_size,
				   TRUE, &copy);
		assert(kr == KERN_SUCCESS);

		*infop = (zone_info_t *) copy;
	}
	*infoCntp = max_zones;

	return KERN_SUCCESS;
}

#if	MACH_KDB
#include <ddb/db_command.h>
#include <ddb/db_output.h>
#include <kern/kern_print.h>

const char *zone_labels =
"ENTRY       COUNT   TOT_SZ   MAX_SZ ELT_SZ ALLOC_SZ NAME";

/* Forwards */
void	db_print_zone(
		zone_t		addr);

#if	ZONE_DEBUG
void	db_zone_check_active(
		zone_t		zone);
void	db_zone_print_active(
		zone_t		zone);
#endif	/* ZONE_DEBUG */
void	db_zone_print_free(
		zone_t		zone);
void
db_print_zone(
	zone_t		addr)
{
	struct zone zcopy;

	zcopy = *addr;

	db_printf("%8x %8x %8x %8x %6x %8x %s ",
		  addr, zcopy.count, zcopy.cur_size,
		  zcopy.max_size, zcopy.elem_size,
		  zcopy.alloc_size, zcopy.zone_name);
	if (zcopy.exhaustible)
	  	db_printf("H");
	if (zcopy.collectable)
	  	db_printf("C");
	if (zcopy.expandable)
	  	db_printf("X");
	db_printf("\n");
}

/*ARGSUSED*/
void
db_show_one_zone(
        db_expr_t       addr,
        int		have_addr,
        db_expr_t	count,
        char *          modif)
{
	struct zone *z = (zone_t)addr;

	if (z == ZONE_NULL || !have_addr){
		db_error("No Zone\n");
		/*NOTREACHED*/
	}

	db_printf("%s\n", zone_labels);
	db_print_zone(z);
}

/*ARGSUSED*/
void
db_show_all_zones(
        db_expr_t	addr,
        int		have_addr,
        db_expr_t	count,
        char *		modif)
{
	zone_t		z;
	unsigned total = 0;

	/*
	 * Don't risk hanging by unconditionally locking,
	 * risk of incoherent data is small (zones aren't freed).
	 */
	have_addr = simple_lock_try(&all_zones_lock);
	count = num_zones;
	z = first_zone;
	if (have_addr) {
		simple_unlock(&all_zones_lock);
	}

	db_printf("%s\n", zone_labels);
	for (  ; count > 0; count--) {
		if (!z) {
			db_error("Mangled Zone List\n");
			/*NOTREACHED*/
		}
		db_print_zone(z);
		total += z->cur_size,

		have_addr = simple_lock_try(&all_zones_lock);
		z = z->next_zone;
		if (have_addr) {
			simple_unlock(&all_zones_lock);
		}
	}
	db_printf("\nTotal              %8x", total);
	db_printf("\n\nzone_gc() has reclaimed %d pages\n",
		  reclaim_page_count);
}

#if	ZONE_DEBUG
void
db_zone_check_active(
	zone_t	zone)
{
	int count = 0;
	queue_t	tmp_elem;

	if (!zone_debug_enabled(zone) || !zone_check)
		return;
	tmp_elem = queue_first(&zone->active_zones);
	while (count < zone->count) {
		count++;
		if (tmp_elem == 0) {
			printf("unexpected zero element, zone=0x%x, count=%d\n",
				zone, count);
			assert(FALSE);
			break;
		}
		if (queue_end(tmp_elem, &zone->active_zones)) {
			printf("unexpected queue_end, zone=0x%x, count=%d\n",
				zone, count);
			assert(FALSE);
			break;
		}
		tmp_elem = queue_next(tmp_elem);
	}
	if (!queue_end(tmp_elem, &zone->active_zones)) {
		printf("not at queue_end, zone=0x%x, tmp_elem=0x%x\n",
			zone, tmp_elem);
		assert(FALSE);
	}
}

void
db_zone_print_active(
	zone_t	zone)
{
	int count = 0;
	queue_t	tmp_elem;

	if (!zone_debug_enabled(zone)) {
		printf("zone 0x%x debug not enabled\n", zone);
		return;
	}
	if (!zone_check) {
		printf("zone_check FALSE\n");
		return;
	}

	printf("zone 0x%x, active elements %d\n", zone, zone->count);
	printf("active list:\n");
	tmp_elem = queue_first(&zone->active_zones);
	while (count < zone->count) {
		printf("  0x%x", tmp_elem);
		count++;
		if ((count % 6) == 0)
			printf("\n");
		if (tmp_elem == 0) {
			printf("\nunexpected zero element, count=%d\n", count);
			break;
		}
		if (queue_end(tmp_elem, &zone->active_zones)) {
			printf("\nunexpected queue_end, count=%d\n", count);
			break;
		}
		tmp_elem = queue_next(tmp_elem);
	}
	if (!queue_end(tmp_elem, &zone->active_zones))
		printf("\nnot at queue_end, tmp_elem=0x%x\n", tmp_elem);
	else
		printf("\n");
}
#endif	/* ZONE_DEBUG */

void
db_zone_print_free(
	zone_t	zone)
{
	int count = 0;
	int freecount;
	vm_offset_t elem;

	freecount = zone_free_count(zone);
	printf("zone 0x%x, free elements %d\n", zone, freecount);
	printf("free list:\n");
	elem = zone->free_elements;
	while (count < freecount) {
		printf("  0x%x", elem);
		count++;
		if ((count % 6) == 0)
			printf("\n");
		if (elem == 0) {
			printf("\nunexpected zero element, count=%d\n", count);
			break;
		}
		elem = *((vm_offset_t *)elem);
	}
	if (elem != 0)
		printf("\nnot at end of free list, elem=0x%x\n", elem);
	else
		printf("\n");
}

#endif /* MACH_KDB */


#if	ZONE_DEBUG

/* should we care about locks here ? */

#if	MACH_KDB
vm_offset_t
next_element(
	zone_t		z,
	vm_offset_t	elt)
{
	if (!zone_debug_enabled(z))
		return(0);
	elt -= sizeof(queue_chain_t);
	elt = (vm_offset_t) queue_next((queue_t) elt);
	if ((queue_t) elt == &z->active_zones)
		return(0);
	elt += sizeof(queue_chain_t);
	return(elt);
}

vm_offset_t
first_element(
	zone_t		z)
{
	vm_offset_t	elt;

	if (!zone_debug_enabled(z))
		return(0);
	if (queue_empty(&z->active_zones))
		return(0);
	elt = (vm_offset_t) queue_first(&z->active_zones);
	elt += sizeof(queue_chain_t);
	return(elt);
}

/*
 * Second arg controls how many zone elements are printed:
 *   0 => none
 *   n, n < 0 => all
 *   n, n > 0 => last n on active list
 */
int
zone_count(
	zone_t		z,
	int		tail)
{
	vm_offset_t	elt;
	int		count = 0;
	boolean_t	print = (tail != 0);

	if (tail < 0)
		tail = z->count;
	if (z->count < tail)
		tail = 0;
	tail = z->count - tail;
	for (elt = first_element(z); elt; elt = next_element(z, elt)) {
		if (print && tail <= count)
			db_printf("%8x\n", elt);
		count++;
	}
	assert(count == z->count);
	return(count);
}
#endif /* MACH_KDB */

#define zone_in_use(z) 	( z->count || z->free_elements )

void
zone_debug_enable(
	zone_t		z)
{
	if (zone_debug_enabled(z) || zone_in_use(z) ||
	    z->alloc_size < (z->elem_size + sizeof(queue_chain_t)))
		return;
	queue_init(&z->active_zones);
	z->elem_size += sizeof(queue_chain_t);
}

void
zone_debug_disable(
	zone_t		z)
{
	if (!zone_debug_enabled(z) || zone_in_use(z))
		return;
	z->elem_size -= sizeof(queue_chain_t);
	z->active_zones.next = z->active_zones.prev = 0;	
}
#endif	/* ZONE_DEBUG */
