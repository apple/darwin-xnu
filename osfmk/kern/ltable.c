/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
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
#include <kern/cpu_data.h>
#include <kern/kern_types.h>
#include <kern/locks.h>
#include <kern/ltable.h>
#include <kern/zalloc.h>
#include <libkern/OSAtomic.h>
#include <pexpert/pexpert.h>
#include <vm/vm_kern.h>


#define	P2ROUNDUP(x, align) (-(-((uint32_t)(x)) & -(align)))
#define ROUNDDOWN(x,y)	(((x)/(y))*(y))

/* ----------------------------------------------------------------------
 *
 * Lockless Link Table Interface
 *
 * ---------------------------------------------------------------------- */

vm_size_t         g_lt_max_tbl_size;
static lck_grp_t  g_lt_lck_grp;

/* default VA space for link tables (zone allocated) */
#define DEFAULT_MAX_TABLE_SIZE  P2ROUNDUP(8 * 1024 * 1024, PAGE_SIZE)

#if defined(DEVELOPMENT) || defined(DEBUG)
/* global for lldb macros */
uint64_t g_lt_idx_max = LT_IDX_MAX;
#endif


/* construct a link table element from an offset and mask into a slab */
#define lt_elem_ofst_slab(slab, slab_msk, ofst) \
	/* cast through 'void *' to avoid compiler alignment warning messages */ \
	((struct lt_elem *)((void *)((uintptr_t)(slab) + ((ofst) & (slab_msk)))))

#if defined(CONFIG_LTABLE_STATS)
/* version that makes no assumption on waste within a slab */
static inline struct lt_elem *
lt_elem_idx(struct link_table *table, uint32_t idx)
{
	int slab_idx = idx / table->slab_elem;
	struct lt_elem *slab = table->table[slab_idx];
	if (!slab)
		panic("Invalid index:%d slab:%d (NULL) for table:%p\n",
		      idx, slab_idx, table);
	assert(slab->lt_id.idx <= idx && (slab->lt_id.idx + table->slab_elem) > idx);
	return lt_elem_ofst_slab(slab, table->slab_msk, (idx - slab->lt_id.idx) * table->elem_sz);
}
#else /* !CONFIG_LTABLE_STATS */
/* verion that assumes 100% ultilization of slabs (no waste) */
static inline struct lt_elem *
lt_elem_idx(struct link_table *table, uint32_t idx)
{
	uint32_t ofst = idx * table->elem_sz;
	struct lt_elem *slab = table->table[ofst >> table->slab_shift];
	if (!slab)
		panic("Invalid index:%d slab:%d (NULL) for table:%p\n",
		      idx, (ofst >> table->slab_shift), table);
	assert(slab->lt_id.idx <= idx && (slab->lt_id.idx + table->slab_elem) > idx);
	return lt_elem_ofst_slab(slab, table->slab_msk, ofst);
}
#endif /* !CONFIG_LTABLE_STATS */

static int __assert_only
lt_elem_in_range(struct lt_elem *elem, struct link_table *table)
{
	struct lt_elem **base = table->table;
	uintptr_t e = (uintptr_t)elem;
	assert(base != NULL);
	while (*base != NULL) {
		uintptr_t b = (uintptr_t)(*base);
		if (e >= b && e < b + table->slab_sz)
			return 1;
		base++;
		if ((uintptr_t)base >= (uintptr_t)table->table + PAGE_SIZE)
			return 0;
	}
	return 0;
}


/**
 * lt_elem_invalidate: mark 'elem' as invalid
 *
 * NOTE: this does _not_ get or put a reference on 'elem'
 */
void lt_elem_invalidate(struct lt_elem *elem)
{
	uint32_t __assert_only old = OSBitAndAtomic(~LT_BITS_VALID, &elem->lt_bits);
	OSMemoryBarrier();
	assert(((lt_bits_type(old) != LT_RESERVED) && (old & LT_BITS_VALID)) ||
	       ((lt_bits_type(old) == LT_RESERVED) && !(old & LT_BITS_VALID)));
}

/**
 * lt_elem_mkvalid: mark 'elem' as valid
 *
 * NOTE: this does _not_ get or put a reference on 'elem'
 */
void lt_elem_mkvalid(struct lt_elem *elem)
{
	uint32_t __assert_only old = OSBitOrAtomic(LT_BITS_VALID, &elem->lt_bits);
	OSMemoryBarrier();
	assert(!(old & LT_BITS_VALID));
}

static void lt_elem_set_type(struct lt_elem *elem, int type)
{
	uint32_t old_bits, new_bits;
	do {
		old_bits = elem->lt_bits;
		new_bits = (old_bits & ~LT_BITS_TYPE) |
			   ((type & LT_BITS_TYPE_MASK) << LT_BITS_TYPE_SHIFT);
	} while (OSCompareAndSwap(old_bits, new_bits, &elem->lt_bits) == FALSE);
	OSMemoryBarrier();
}


/**
 * ltable_bootstrap: bootstrap a link table
 *
 * Called once at system boot
 */
void ltable_bootstrap(void)
{
	static int s_is_bootstrapped = 0;

	uint32_t tmp32 = 0;

	if (s_is_bootstrapped)
		return;
	s_is_bootstrapped = 1;

	g_lt_max_tbl_size = DEFAULT_MAX_TABLE_SIZE;
	if (PE_parse_boot_argn("lt_tbl_size", &tmp32, sizeof(tmp32)) == TRUE)
		g_lt_max_tbl_size = (vm_size_t)P2ROUNDUP(tmp32, PAGE_SIZE);

	lck_grp_init(&g_lt_lck_grp, "link_table_locks", LCK_GRP_ATTR_NULL);
}

/**
 * ltable_init: initialize a link table with given parameters
 *
 */
void ltable_init(struct link_table *table, const char *name,
                 uint32_t max_tbl_elem, uint32_t elem_sz,
                 ltable_poison_func poison)
{
	kern_return_t kr;
	uint32_t slab_sz, slab_shift, slab_msk, slab_elem;
	zone_t slab_zone;
	size_t max_tbl_sz;
	struct lt_elem *e, **base;

#ifndef CONFIG_LTABLE_STATS
	/* the element size _must_ be a power of two! */
	if ((elem_sz & (elem_sz - 1)) != 0)
		panic("elem_sz:%d for table:'%s' must be a power of two!",
		      elem_sz, name);
#endif

	/*
	 * First, allocate a single page of memory to act as the base
	 * for the table's element slabs
	 */
	kr = kernel_memory_allocate(kernel_map, (vm_offset_t *)&base,
				    PAGE_SIZE, 0, KMA_NOPAGEWAIT, VM_KERN_MEMORY_LTABLE);
	if (kr != KERN_SUCCESS)
		panic("Cannot initialize %s table: "
		      "kernel_memory_allocate failed:%d\n", name, kr);
	memset(base, 0, PAGE_SIZE);

	/*
	 * Based on the maximum table size, calculate the slab size:
	 * we allocate 1 page of slab pointers for the table, and we need to
	 * index elements of 'elem_sz', this gives us the slab size based on
	 * the maximum size the table should grow.
	 */
	max_tbl_sz = (max_tbl_elem * elem_sz);
	max_tbl_sz = P2ROUNDUP(max_tbl_sz, PAGE_SIZE);

	/* system maximum table size divided by number of slots in a page */
	slab_sz = (uint32_t)(max_tbl_sz / (PAGE_SIZE / (sizeof(void *))));
	if (slab_sz < PAGE_SIZE)
		slab_sz = PAGE_SIZE;

	/* make sure the slab size is a power of two */
	slab_shift = 0;
	slab_msk = ~0;
	for (uint32_t i = 0; i < 31; i++) {
		uint32_t bit = (1 << i);
		if ((slab_sz & bit) == slab_sz) {
			slab_shift = i;
			slab_msk = 0;
			for (uint32_t j = 0; j < i; j++)
				slab_msk |= (1 << j);
			break;
		}
		slab_sz &= ~bit;
	}
	slab_elem = slab_sz / elem_sz;

	/* initialize the table's slab zone (for table growth) */
	ltdbg("Initializing %s zone: slab:%d (%d,0x%x) max:%ld",
	      name, slab_sz, slab_shift, slab_msk, max_tbl_sz);
	slab_zone = zinit(slab_sz, max_tbl_sz, slab_sz, name);
	assert(slab_zone != ZONE_NULL);

	/* allocate the first slab and populate it */
	base[0] = (struct lt_elem *)zalloc(slab_zone);
	if (base[0] == NULL)
		panic("Can't allocate a %s table slab from zone:%p",
		      name, slab_zone);

	memset(base[0], 0, slab_sz);

	/* setup the initial freelist */
	ltdbg("initializing %d links (%d bytes each)...", slab_elem, elem_sz);
	for (unsigned l = 0; l < slab_elem; l++) {
		e = lt_elem_ofst_slab(base[0], slab_msk, l * elem_sz);
		e->lt_id.idx = l;
		/*
		 * setting generation to 0 ensures that a setid of 0 is
		 * invalid because the generation will be incremented before
		 * each element's allocation.
		 */
		e->lt_id.generation = 0;
		e->lt_next_idx = l + 1;
	}

	/* make sure the last free element points to a never-valid idx */
	e = lt_elem_ofst_slab(base[0], slab_msk, (slab_elem - 1) * elem_sz);
	e->lt_next_idx = LT_IDX_MAX;

	lck_mtx_init(&table->lock, &g_lt_lck_grp, LCK_ATTR_NULL);

	table->slab_sz = slab_sz;
	table->slab_shift = slab_shift;
	table->slab_msk = slab_msk;
	table->slab_elem = slab_elem;
	table->slab_zone = slab_zone;

	table->elem_sz = elem_sz;
	table->nelem = slab_elem;
	table->used_elem = 0;
	table->elem_sz = elem_sz;
	table->poison = poison;

	table->table = base;
	table->next_free_slab = &base[1];
	table->free_list.id = base[0]->lt_id.id;

#if CONFIG_LTABLE_STATS
	table->nslabs = 1;
	table->nallocs = 0;
	table->nreallocs = 0;
	table->npreposts = 0;
	table->nreservations = 0;
	table->nreserved_releases = 0;

	table->max_used = 0;
	table->avg_used = 0;
	table->max_reservations = 0;
	table->avg_reservations = 0;
#endif
}


/**
 * ltable_grow: grow a link table by adding another 'slab' of table elements
 *
 * Conditions:
 *	table mutex is unlocked
 *	calling thread can block
 */
void ltable_grow(struct link_table *table, uint32_t min_free)
{
	struct lt_elem *slab, **slot;
	struct lt_elem *e = NULL, *first_new_elem, *last_new_elem;
	struct ltable_id free_id;
	uint32_t free_elem;

	assert(get_preemption_level() == 0);
	assert(table && table->slab_zone);

	lck_mtx_lock(&table->lock);

	free_elem = table->nelem - table->used_elem;

	/*
	 * If the caller just wanted to ensure a minimum number of elements,
	 * do that (and don't just blindly grow the table). Also, don't grow
	 * the table unnecessarily - we could have been beaten by a higher
	 * priority thread who acquired the lock and grew the table before we
	 * got here.
	 */
	if (free_elem > min_free) {
		lck_mtx_unlock(&table->lock);
		return;
	}

	/* we are now committed to table growth */
	ltdbg_v("BEGIN");

	if (table->next_free_slab == NULL) {
		/*
		 * before we panic, check one more time to see if any other
		 * threads have free'd from space in the table.
		 */
		if ((table->nelem - table->used_elem) > 0) {
			/* there's at least 1 free element: don't panic yet */
			lck_mtx_unlock(&table->lock);
			return;
		}
		panic("No more room to grow table: %p (nelem: %d, used: %d)",
		      table, table->nelem, table->used_elem);
	}
	slot = table->next_free_slab;
	table->next_free_slab++;
	if ((uintptr_t)table->next_free_slab >= (uintptr_t)table->table + PAGE_SIZE)
		table->next_free_slab = NULL;

	assert(*slot == NULL);

	/* allocate another slab */
	slab = (struct lt_elem *)zalloc(table->slab_zone);
	if (slab == NULL)
		panic("Can't allocate a %s table (%p) slab from zone:%p",
		      table->slab_zone->zone_name, table, table->slab_zone);

	memset(slab, 0, table->slab_sz);

	/* put the new elements into a freelist */
	ltdbg_v("    init %d new links...", table->slab_elem);
	for (unsigned l = 0; l < table->slab_elem; l++) {
		uint32_t idx = l + table->nelem;
		if (idx >= (LT_IDX_MAX - 1))
			break; /* the last element of the last slab */
		e = lt_elem_ofst_slab(slab, table->slab_msk, l * table->elem_sz);
		e->lt_id.idx = idx;
		e->lt_next_idx = idx + 1;
	}
	last_new_elem = e;
	assert(last_new_elem != NULL);

	first_new_elem = lt_elem_ofst_slab(slab, table->slab_msk, 0);

	/* update table book keeping, and atomically swap the freelist head */
	*slot = slab;
	if (table->nelem + table->slab_elem >= LT_IDX_MAX)
		table->nelem = LT_IDX_MAX - 1;
	else
		table->nelem += table->slab_elem;

#if CONFIG_LTABLE_STATS
	table->nslabs += 1;
#endif

	/*
	 * The atomic swap of the free list head marks the end of table
	 * growth. Incoming requests may now use the newly allocated slab
	 * of table elements
	 */
	free_id = table->free_list;
	/* connect the existing free list to the end of the new free list */
	last_new_elem->lt_next_idx = free_id.idx;
	while (OSCompareAndSwap64(free_id.id, first_new_elem->lt_id.id,
				  &table->free_list.id) == FALSE) {
		OSMemoryBarrier();
		free_id = table->free_list;
		last_new_elem->lt_next_idx = free_id.idx;
	}
	OSMemoryBarrier();

	lck_mtx_unlock(&table->lock);

	return;
}


/**
 * ltable_alloc_elem: allocate one or more elements from a given table
 *
 * The returned element(s) will be of type 'type', but will remain invalid.
 *
 * If the caller has disabled preemption, then this function may (rarely) spin
 * waiting either for another thread to either release 'nelem' table elements,
 * or grow the table.
 *
 * If the caller can block, then this function may (rarely) block while
 * the table grows to meet the demand for 'nelem' element(s).
 */
__attribute__((noinline))
struct lt_elem *ltable_alloc_elem(struct link_table *table, int type,
				  int nelem, int nattempts)
{
	int nspins = 0, ntries = 0, nalloc = 0;
	uint32_t table_size;
	struct lt_elem *elem = NULL;
	struct ltable_id free_id, next_id;

	static const int max_retries = 500;

	if (type != LT_ELEM && type != LT_LINK && type != LT_RESERVED)
		panic("link_table_aloc of invalid elem type:%d from table @%p",
		      type, table);

	assert(nelem > 0);

	/*
	 * If the callers only wants to try a certain number of times, make it
	 * look like we've already made (MAX - nattempts) tries at allocation
	 */
	if (nattempts > 0 && nattempts <= max_retries) {
		ntries = max_retries - nattempts;
	}

try_again:
	elem = NULL;
	if (ntries++ > max_retries) {
		struct lt_elem *tmp;
		if (nattempts > 0) {
			/*
			 * The caller specified a particular number of
			 * attempts before failure, so it's expected that
			 * they're prepared to handle a NULL return.
			 */
			return NULL;
		}

		if (table->used_elem + nelem >= table_size)
			panic("No more room to grow table: 0x%p size:%d, used:%d, requested elem:%d",
			      table, table_size, table->used_elem, nelem);
		if (nelem == 1)
			panic("Too many alloc retries: %d, table:%p, type:%d, nelem:%d",
			      ntries, table, type, nelem);
		/* don't panic: try allocating one-at-a-time */
		while (nelem > 0) {
			tmp = ltable_alloc_elem(table, type, 1, nattempts);
			if (elem)
				lt_elem_list_link(table, tmp, elem);
			elem = tmp;
			--nelem;
		}
		assert(elem != NULL);
		return elem;
	}

	nalloc = 0;
	table_size = table->nelem;

	if (table->used_elem + nelem >= table_size) {
		if (get_preemption_level() != 0) {
#if CONFIG_LTABLE_STATS
			table->nspins += 1;
#endif
			/*
			 * We may have just raced with table growth: check
			 * again to make sure there really isn't any space.
			 */
			if (++nspins > 4)
				panic("Can't grow table %p with preemption"
				      " disabled!", table);
			delay(1);
			goto try_again;
		}
		ltable_grow(table, nelem);
		goto try_again;
	}

	/* read this value only once before the CAS */
	free_id = table->free_list;
	if (free_id.idx >= table_size)
		goto try_again;

	/*
	 * Find the item on the free list which will become the new free list
	 * head, but be careful not to modify any memory (read only)!  Other
	 * threads can alter table state at any time up until the CAS.  We
	 * don't modify any memory until we've successfully swapped out the
	 * free list head with the one we've investigated.
	 */
	for (struct lt_elem *next_elem = lt_elem_idx(table, free_id.idx);
	     nalloc < nelem;
	     nalloc++) {
		elem = next_elem;
		next_id.generation = 0;
		next_id.idx = next_elem->lt_next_idx;
		if (next_id.idx < table->nelem) {
			next_elem = lt_elem_idx(table, next_id.idx);
			next_id.id = next_elem->lt_id.id;
		} else {
			goto try_again;
		}
	}
	/* 'elem' points to the last element being allocated */

	if (OSCompareAndSwap64(free_id.id, next_id.id,
			       &table->free_list.id) == FALSE)
		goto try_again;

	/* load barrier */
	OSMemoryBarrier();

	/*
	 * After the CAS, we know that we own free_id, and it points to a
	 * valid table entry (checked above). Grab the table pointer and
	 * reset some values.
	 */
	OSAddAtomic(nelem, &table->used_elem);

	/* end the list of allocated elements */
	elem->lt_next_idx = LT_IDX_MAX;
	/* reset 'elem' to point to the first allocated element */
	elem = lt_elem_idx(table, free_id.idx);

	/*
	 * Update the generation count, and return the element(s)
	 * with a single reference (and no valid bit). If the
	 * caller immediately calls _put() on any element, then
	 * it will be released back to the free list. If the caller
	 * subsequently marks the element as valid, then the put
	 * will simply drop the reference.
	 */
	for (struct lt_elem *tmp = elem; ; ) {
		assert(!lt_bits_valid(tmp->lt_bits) &&
		       (lt_bits_refcnt(tmp->lt_bits) == 0));
		--nalloc;
		tmp->lt_id.generation += 1;
		tmp->lt_bits = 1;
		lt_elem_set_type(tmp, type);
		if (tmp->lt_next_idx == LT_IDX_MAX)
			break;
		assert(tmp->lt_next_idx != LT_IDX_MAX);
		tmp = lt_elem_idx(table, tmp->lt_next_idx);
	}
	assert(nalloc == 0);

#if CONFIG_LTABLE_STATS
	uint64_t nreservations;
	table->nallocs += nelem;
	if (type == LT_RESERVED)
		OSIncrementAtomic64(&table->nreservations);
	nreservations = table->nreservations;
	if (table->used_elem > table->max_used)
		table->max_used = table->used_elem;
	if (nreservations > table->max_reservations)
		table->max_reservations = nreservations;
	table->avg_used = (table->avg_used + table->used_elem) / 2;
	table->avg_reservations = (table->avg_reservations + nreservations) / 2;
#endif

	return elem;
}


/**
 * ltable_realloc_elem: convert a reserved element to a particular type
 *
 * This funciton is used to convert reserved elements (not yet marked valid)
 * to the given 'type'. The generation of 'elem' is incremented, the element
 * is disconnected from any list to which it belongs, and its type is set to
 * 'type'.
 */
void ltable_realloc_elem(struct link_table *table, struct lt_elem *elem, int type)
{
	(void)table;
	assert(lt_elem_in_range(elem, table) &&
	       !lt_bits_valid(elem->lt_bits));

#if CONFIG_LTABLE_STATS
	table->nreallocs += 1;
	if (lt_bits_type(elem->lt_bits) == LT_RESERVED && type != LT_RESERVED) {
		/*
		 * This isn't under any lock, so we'll clamp it.
		 * the stats are meant to be informative, not perfectly
		 * accurate
		 */
		OSDecrementAtomic64(&table->nreservations);
	}
	table->avg_reservations = (table->avg_reservations + table->nreservations) / 2;
#endif

	/*
	 * Return the same element with a new generation count, and a
	 * (potentially) new type. Don't touch the refcount: the caller
	 * is responsible for getting that (and the valid bit) correct.
	 */
	elem->lt_id.generation += 1;
	elem->lt_next_idx = LT_IDX_MAX;
	lt_elem_set_type(elem, type);

	return;
}


/**
 * ltable_free_elem: release an element back to a link table
 *
 * Do not call this function directly: use ltable_[get|put]_elem!
 *
 * Conditions:
 *     'elem' was originally allocated from 'table'
 *     'elem' is _not_ marked valid
 *     'elem' has a reference count of 0
 */
static void ltable_free_elem(struct link_table *table, struct lt_elem *elem)
{
	struct ltable_id next_id;

	assert(lt_elem_in_range(elem, table) &&
	       !lt_bits_valid(elem->lt_bits) &&
	       (lt_bits_refcnt(elem->lt_bits) == 0));

	OSDecrementAtomic(&table->used_elem);

#if CONFIG_LTABLE_STATS
	table->avg_used = (table->avg_used + table->used_elem) / 2;
	if (lt_bits_type(elem->lt_bits) == LT_RESERVED)
		OSDecrementAtomic64(&table->nreservations);
	table->avg_reservations = (table->avg_reservations + table->nreservations) / 2;
#endif

	elem->lt_bits = 0;

	if (table->poison)
		(table->poison)(table, elem);

again:
	next_id = table->free_list;
	if (next_id.idx >= table->nelem)
		elem->lt_next_idx = LT_IDX_MAX;
	else
		elem->lt_next_idx = next_id.idx;

	/* store barrier */
	OSMemoryBarrier();
	if (OSCompareAndSwap64(next_id.id, elem->lt_id.id,
			       &table->free_list.id) == FALSE)
		goto again;
}


/**
 * ltable_get_elem: get a reference to a table element identified by 'id'
 *
 * Returns a reference to the table element associated with the given 'id', or
 * NULL if the 'id' was invalid or does not exist in 'table'. The caller is
 * responsible to release the reference using ltable_put_elem().
 *
 * NOTE: if the table element pointed to by 'id' is marked as invalid,
 *       this function will return NULL.
 */
struct lt_elem *ltable_get_elem(struct link_table *table, uint64_t id)
{
	struct lt_elem *elem;
	uint32_t idx, bits, new_bits;

	/*
	 * Here we have a reference to the table which is guaranteed to remain
	 * valid until we drop the reference
	 */

	idx = ((struct ltable_id *)&id)->idx;

	if (idx >= table->nelem)
		panic("id:0x%llx : idx:%d > %d", id, idx, table->nelem);

	elem = lt_elem_idx(table, idx);

	/* verify the validity by taking a reference on the table object */
	bits = elem->lt_bits;
	if (!lt_bits_valid(bits))
		return NULL;

	/*
	 * do a pre-verify on the element ID to potentially
	 * avoid 2 compare-and-swaps
	 */
	if (elem->lt_id.id != id)
		return NULL;

	new_bits = bits + 1;

	/* check for overflow */
	assert(lt_bits_refcnt(new_bits) > 0);

	while (OSCompareAndSwap(bits, new_bits, &elem->lt_bits) == FALSE) {
		/*
		 * either the element became invalid,
		 * or someone else grabbed/removed a reference.
		 */
		bits = elem->lt_bits;
		if (!lt_bits_valid(bits)) {
			/* don't return invalid elements */
			return NULL;
		}
		new_bits = bits + 1;
		assert(lt_bits_refcnt(new_bits) > 0);
	}

	/* load barrier */
	OSMemoryBarrier();

	/* check to see that our reference is to the same generation! */
	if (elem->lt_id.id != id) {
		/*
		ltdbg("ID:0x%llx table generation (%d) != %d",
		      id, elem->lt_id.generation,
		      ((struct ltable_id *)&id)->generation);
		 */
		ltable_put_elem(table, elem);
		return NULL;
	}

	/* We now have a reference on a valid object */
	return elem;
}

/**
 * ltable_put_elem: release a reference to table element
 *
 * This function releases a reference taken on a table element via
 * ltable_get_elem(). This function will release the element back to 'table'
 * when the reference count goes to 0 AND the element has been marked as
 * invalid.
 */
void ltable_put_elem(struct link_table *table, struct lt_elem *elem)
{
	uint32_t bits, new_bits;

	assert(lt_elem_in_range(elem, table));

	bits = elem->lt_bits;
	new_bits = bits - 1;

	/* check for underflow */
	assert(lt_bits_refcnt(new_bits) < LT_BITS_REFCNT_MASK);

	while (OSCompareAndSwap(bits, new_bits, &elem->lt_bits) == FALSE) {
		bits = elem->lt_bits;
		new_bits = bits - 1;
		/* catch underflow */
		assert(lt_bits_refcnt(new_bits) < LT_BITS_REFCNT_MASK);
	}

	/* load barrier */
	OSMemoryBarrier();

	/*
	 * if this was the last reference, and it was marked as invalid,
	 * then we can add this link object back to the free list
	 */
	if (!lt_bits_valid(new_bits) && (lt_bits_refcnt(new_bits) == 0))
		ltable_free_elem(table, elem);

	return;
}


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
 *
 * API: lt_elem_list_...
 *
 * Reuse the free list linkage member, 'lt_next_idx' of a table element
 * in a slightly more generic singly-linked list. All members of this
 * list have been allocated from a table, but have not been made valid.
 *
 * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*/

/**
 * lt_elem_list_link: link a child onto a parent
 *
 * Note that if 'parent' is the head of a list, this function will follow that
 * list and attach 'child' to the end of it. In the simplest case, this
 * results in: parent->child
 * however this could also result in: parent->...->child
 */
int lt_elem_list_link(struct link_table *table, struct lt_elem *parent, struct lt_elem *child)
{
	int nelem = 1;

	assert(lt_elem_in_range(parent, table));

	/* find the end of the parent's list */
	while (parent->lt_next_idx != LT_IDX_MAX) {
		assert(parent->lt_next_idx < table->nelem);
		parent = lt_elem_idx(table, parent->lt_next_idx);
		nelem++;
	}

	if (child) {
		assert(lt_elem_in_range(child, table));
		parent->lt_next_idx = child->lt_id.idx;
	}

	return nelem;
}


/**
 * lt_elem_list_first: obtain a pointer to the first element of a list.
 *
 * This function converts the head of a singly-linked list, 'id', into a real
 * lt_elem object and returns a pointer to the object.
 *
 * It does _not_ take an extra reference on the object: the list implicitly
 * holds that reference.
 */
struct lt_elem *lt_elem_list_first(struct link_table *table, uint64_t id)
{
	uint32_t idx;
	struct lt_elem *elem = NULL;

	if (id == 0)
		return NULL;

	idx = ((struct ltable_id *)&id)->idx;

	if (idx > table->nelem)
		panic("Invalid element for id:0x%llx", id);
	elem = lt_elem_idx(table, idx);

	/* invalid element: reserved ID was probably already reallocated */
	if (elem->lt_id.id != id)
		return NULL;

	/* the returned element should _not_ be marked valid! */
	if (lt_bits_valid(elem->lt_bits) ||
	    lt_bits_type(elem->lt_bits) != LT_RESERVED ||
	    lt_bits_refcnt(elem->lt_bits) != 1) {
		panic("Valid/unreserved element %p (0x%x) in reserved list",
		      elem, elem->lt_bits);
	}

	return elem;
}


/**
 * lt_elem_list_next: return the item subsequent to 'elem' in a list
 *
 * Note that this will return NULL if 'elem' is actually the end of the list.
 */
struct lt_elem *lt_elem_list_next(struct link_table *table, struct lt_elem *head)
{
	struct lt_elem *elem;

	if (!head)
		return NULL;
	if (head->lt_next_idx >= table->nelem)
		return NULL;

	elem = lt_elem_idx(table, head->lt_next_idx);
	assert(lt_elem_in_range(elem, table));

	return elem;
}


/**
 * lt_elem_list_break: break a list in two around 'elem'
 *
 * This function will reset the next_idx field of 'elem' (making it the end of
 * the list), and return the element subsequent to 'elem' in the list
 * (which could be NULL)
 */
struct lt_elem *lt_elem_list_break(struct link_table *table, struct lt_elem *elem)
{
	struct lt_elem *next;

	if (!elem)
		return NULL;
	next = lt_elem_list_next(table, elem);
	elem->lt_next_idx = LT_IDX_MAX;

	return next;
}


/**
 * lt_elem_list_pop: pop an item off the head of a list
 *
 * The list head is pointed to by '*id', the element corresponding to '*id' is
 * returned by this function, and the new list head is returned in the in/out
 * parameter, '*id'.  The caller is responsible for the reference on the
 * returned object.  A realloc is done to reset the type of the object, but it
 * is still left invalid.
 */
struct lt_elem *lt_elem_list_pop(struct link_table *table, uint64_t *id, int type)
{
	struct lt_elem *first, *next;

	if (!id || *id == 0)
		return NULL;

	/* pop an item off the reserved stack */

	first = lt_elem_list_first(table, *id);
	if (!first) {
		*id = 0;
		return NULL;
	}

	next = lt_elem_list_next(table, first);
	if (next)
		*id = next->lt_id.id;
	else
		*id = 0;

	ltable_realloc_elem(table, first, type);

	return first;
}

/**
 * lt_elem_list_release: free an entire list of reserved elements
 *
 * All elements in the list whose first member is 'head' will be released back
 * to 'table' as free elements. The 'type' parameter is used in development
 * kernels to assert that all elements on the list are of the given type.
 */
int lt_elem_list_release(struct link_table *table, struct lt_elem *head,
                         int __assert_only type)
{
	struct lt_elem *elem;
	struct ltable_id free_id;
	int nelem = 0;

	if (!head)
		return 0;

	for (elem = head; ; ) {
		assert(lt_elem_in_range(elem, table));
		assert(!lt_bits_valid(elem->lt_bits) && (lt_bits_refcnt(elem->lt_bits) == 1));
		assert(lt_bits_type(elem->lt_bits) == type);

		nelem++;
		elem->lt_bits = 0;
		if (table->poison)
			(table->poison)(table, elem);

		if (elem->lt_next_idx == LT_IDX_MAX)
			break;
		assert(elem->lt_next_idx < table->nelem);
		elem = lt_elem_idx(table, elem->lt_next_idx);
	}

	/*
	 * 'elem' now points to the end of our list, and 'head' points to the
	 * beginning. We want to atomically swap the free list pointer with
	 * the 'head' and ensure that 'elem' points to the previous free list
	 * head.
	 */

again:
	free_id = table->free_list;
	if (free_id.idx >= table->nelem)
		elem->lt_next_idx = LT_IDX_MAX;
	else
		elem->lt_next_idx = free_id.idx;

	/* store barrier */
	OSMemoryBarrier();
	if (OSCompareAndSwap64(free_id.id, head->lt_id.id,
			       &table->free_list.id) == FALSE)
		goto again;

	OSAddAtomic(-nelem, &table->used_elem);
	return nelem;
}
