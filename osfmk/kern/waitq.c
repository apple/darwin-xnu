/*
 * Copyright (c) 2015 Apple Inc. All rights reserved.
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
 * @OSF_FREE_COPYRIGHT@
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
#include <kern/ast.h>
#include <kern/kern_types.h>
#include <kern/mach_param.h>
#include <kern/queue.h>
#include <kern/sched_prim.h>
#include <kern/simple_lock.h>
#include <kern/spl.h>
#include <kern/waitq.h>
#include <kern/zalloc.h>
#include <libkern/OSAtomic.h>
#include <mach/sync_policy.h>
#include <vm/vm_kern.h>

#include <sys/kdebug.h>

#if CONFIG_WAITQ_DEBUG
#define wqdbg(fmt,...) \
	printf("WQ[%s]:  " fmt "\n", __func__, ## __VA_ARGS__)
#else
#define wqdbg(fmt,...) do { } while (0)
#endif

#ifdef WAITQ_VERBOSE_DEBUG
#define wqdbg_v(fmt,...) \
	printf("WQ[v:%s]:  " fmt "\n", __func__, ## __VA_ARGS__)
#else
#define wqdbg_v(fmt,...) do { } while (0)
#endif

#define wqinfo(fmt,...) \
	printf("WQ[%s]: " fmt "\n", __func__,  ## __VA_ARGS__)

#define wqerr(fmt,...) \
	printf("WQ[%s] ERROR: " fmt "\n", __func__, ## __VA_ARGS__)


/*
 * un-comment the following lines to debug the link/prepost tables
 * NOTE: this expands each element by ~40 bytes
 */
//#define CONFIG_WAITQ_LINK_STATS
//#define CONFIG_WAITQ_PREPOST_STATS

/*
 * file-static functions / data
 */
static thread_t waitq_select_one_locked(struct waitq *waitq, event64_t event,
					uint64_t *reserved_preposts,
					int priority, spl_t *spl);

static kern_return_t waitq_select_thread_locked(struct waitq *waitq,
						event64_t event,
						thread_t thread, spl_t *spl);

#define WAITQ_SET_MAX (task_max * 3)
static zone_t waitq_set_zone;


#define	P2ROUNDUP(x, align) (-(-((uint32_t)(x)) & -(align)))
#define ROUNDDOWN(x,y)	(((x)/(y))*(y))


#ifdef CONFIG_WAITQ_STATS
static __inline__ void waitq_grab_backtrace(uintptr_t bt[NWAITQ_BTFRAMES], int skip);
#endif


/* ----------------------------------------------------------------------
 *
 * Wait Queue Link/Prepost Table Implementation
 *
 * ---------------------------------------------------------------------- */
#define DEFAULT_MIN_FREE_TABLE_ELEM    100
static uint32_t g_min_free_table_elem;
static uint32_t g_min_free_cache;

static vm_size_t   g_wqt_max_tbl_size;
static lck_grp_t   g_wqt_lck_grp;

/* 1 prepost table, 1 setid link table */
#define NUM_WQ_TABLES 2

/* default VA space for waitq tables (zone allocated) */
#define DEFAULT_MAX_TABLE_SIZE  P2ROUNDUP(8 * 1024 * 1024, PAGE_SIZE)

struct wq_id {
	union {
		uint64_t id;
		struct {
			/*
			 * this bitfied is OK because we don't need to
			 * enforce a particular memory layout
			 */
			uint64_t idx:18, /* allows indexing up to 8MB of 32byte link objects */
				 generation:46;
		};
	};
};

enum wqt_elem_type {
	WQT_FREE     = 0,
	WQT_ELEM     = 1,
	WQT_LINK     = 2,
	WQT_RESERVED = 3,
};

struct wqt_elem {
	uint32_t wqt_bits;

	uint32_t wqt_next_idx;

	struct wq_id wqt_id;
};

/* this _must_ match the idx bitfield definition in struct wq_id */
#define WQT_IDX_MAX           (0x3ffff)
#if defined(DEVELOPMENT) || defined(DEBUG)
/* global for lldb macros */
uint64_t g_wqt_idx_max = WQT_IDX_MAX;
#endif

/* reference count bits should _always_ be the low-order bits */
#define WQT_BITS_REFCNT_MASK  (0x1FFFFFFF)
#define WQT_BITS_REFCNT_SHIFT (0)
#define WQT_BITS_REFCNT       (WQT_BITS_REFCNT_MASK << WQT_BITS_REFCNT_SHIFT)

#define WQT_BITS_TYPE_MASK    (0x3)
#define WQT_BITS_TYPE_SHIFT   (29)
#define WQT_BITS_TYPE         (WQT_BITS_TYPE_MASK << WQT_BITS_TYPE_SHIFT)

#define WQT_BITS_VALID_MASK   (0x1)
#define WQT_BITS_VALID_SHIFT  (31)
#define WQT_BITS_VALID        (WQT_BITS_VALID_MASK << WQT_BITS_VALID_SHIFT)

#define wqt_bits_refcnt(bits) \
	(((bits) >> WQT_BITS_REFCNT_SHIFT) & WQT_BITS_REFCNT_MASK)

#define wqt_bits_type(bits) \
	(((bits) >> WQT_BITS_TYPE_SHIFT) & WQT_BITS_TYPE_MASK)

#define wqt_bits_valid(bits) \
	((bits) & WQT_BITS_VALID)

struct wq_table;
typedef void (*wq_table_poison_func)(struct wq_table *, struct wqt_elem *);

/*
 * A table is a container for slabs of elements. Each slab is 'slab_sz' bytes
 * and contains 'slab_sz/elem_sz' elements (of 'elem_sz' bytes each). These
 * slabs allow the table to be broken up into potentially dis-contiguous VA
 * space. On 32-bit platforms with large amounts of physical RAM, this is
 * quite important. Keeping slabs like this slightly complicates retrieval of
 * table elements, but not by much.
 */
struct wq_table {
	struct wqt_elem **table;   /* an array of 'slabs' of elements */
	struct wqt_elem **next_free_slab;
	struct wq_id     free_list __attribute__((aligned(8)));

	uint32_t         nelem;
	uint32_t         used_elem;
	uint32_t         elem_sz;  /* size of a table element (bytes) */

	uint32_t         slab_sz;  /* size of a table 'slab' object (bytes) */
	uint32_t         slab_shift;
	uint32_t         slab_msk;
	uint32_t         slab_elem;
	zone_t           slab_zone;

	wq_table_poison_func poison;

	lck_mtx_t        lock;
	uint32_t         state;

#if CONFIG_WAITQ_STATS
	uint32_t         nslabs;

	uint64_t         nallocs;
	uint64_t         nreallocs;
	uint64_t         npreposts;
	int64_t          nreservations;
	uint64_t         nreserved_releases;
	uint64_t         nspins;

	uint64_t         max_used;
	uint64_t         avg_used;
	uint64_t         max_reservations;
	uint64_t         avg_reservations;
#endif
} __attribute__((aligned(8)));

#define wqt_elem_ofst_slab(slab, slab_msk, ofst) \
	/* cast through 'void *' to avoid compiler alignment warning messages */ \
	((struct wqt_elem *)((void *)((uintptr_t)(slab) + ((ofst) & (slab_msk)))))

#if defined(CONFIG_WAITQ_LINK_STATS) || defined(CONFIG_WAITQ_PREPOST_STATS)
/* version that makes no assumption on waste within a slab */
static inline struct wqt_elem *
wqt_elem_idx(struct wq_table *table, uint32_t idx)
{
	int slab_idx = idx / table->slab_elem;
	struct wqt_elem *slab = table->table[slab_idx];
	if (!slab)
		panic("Invalid index:%d slab:%d (NULL) for table:%p\n",
		      idx, slab_idx, table);
	assert(slab->wqt_id.idx <= idx && (slab->wqt_id.idx + table->slab_elem) > idx);
	return wqt_elem_ofst_slab(slab, table->slab_msk, (idx - slab->wqt_id.idx) * table->elem_sz);
}
#else /* !CONFIG_WAITQ_[LINK|PREPOST]_STATS */
/* verion that assumes 100% ultilization of slabs (no waste) */
static inline struct wqt_elem *
wqt_elem_idx(struct wq_table *table, uint32_t idx)
{
	uint32_t ofst = idx * table->elem_sz;
	struct wqt_elem *slab = table->table[ofst >> table->slab_shift];
	if (!slab)
		panic("Invalid index:%d slab:%d (NULL) for table:%p\n",
		      idx, (ofst >> table->slab_shift), table);
	assert(slab->wqt_id.idx <= idx && (slab->wqt_id.idx + table->slab_elem) > idx);
	return wqt_elem_ofst_slab(slab, table->slab_msk, ofst);
}
#endif /* !CONFIG_WAITQ_[LINK|PREPOST]_STATS */

static int __assert_only wqt_elem_in_range(struct wqt_elem *elem,
					   struct wq_table *table)
{
	struct wqt_elem **base = table->table;
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

static struct wqt_elem *wq_table_get_elem(struct wq_table *table, uint64_t id);
static void wq_table_put_elem(struct wq_table *table, struct wqt_elem *elem);
static int wqt_elem_list_link(struct wq_table *table, struct wqt_elem *parent,
			      struct wqt_elem *child);

static void wqt_elem_invalidate(struct wqt_elem *elem)
{
	uint32_t __assert_only old = OSBitAndAtomic(~WQT_BITS_VALID, &elem->wqt_bits);
	OSMemoryBarrier();
	assert(((wqt_bits_type(old) != WQT_RESERVED) && (old & WQT_BITS_VALID)) ||
	       ((wqt_bits_type(old) == WQT_RESERVED) && !(old & WQT_BITS_VALID)));
}

static void wqt_elem_mkvalid(struct wqt_elem *elem)
{
	uint32_t __assert_only old = OSBitOrAtomic(WQT_BITS_VALID, &elem->wqt_bits);
	OSMemoryBarrier();
	assert(!(old & WQT_BITS_VALID));
}

static void wqt_elem_set_type(struct wqt_elem *elem, int type)
{
	uint32_t old_bits, new_bits;
	do {
		old_bits = elem->wqt_bits;
		new_bits = (old_bits & ~WQT_BITS_TYPE) |
			   ((type & WQT_BITS_TYPE_MASK) << WQT_BITS_TYPE_SHIFT);
	} while (OSCompareAndSwap(old_bits, new_bits, &elem->wqt_bits) == FALSE);
	OSMemoryBarrier();
}


static void wq_table_bootstrap(void)
{
	uint32_t      tmp32 = 0;

	g_min_free_cache = 0;
	g_min_free_table_elem = DEFAULT_MIN_FREE_TABLE_ELEM;
	if (PE_parse_boot_argn("wqt_min_free", &tmp32, sizeof(tmp32)) == TRUE)
		g_min_free_table_elem = tmp32;
	wqdbg("Minimum free table elements: %d", tmp32);

	g_wqt_max_tbl_size = DEFAULT_MAX_TABLE_SIZE;
	if (PE_parse_boot_argn("wqt_tbl_size", &tmp32, sizeof(tmp32)) == TRUE)
		g_wqt_max_tbl_size = (vm_size_t)P2ROUNDUP(tmp32, PAGE_SIZE);

	lck_grp_init(&g_wqt_lck_grp, "waitq_table_locks", LCK_GRP_ATTR_NULL);
}

static void wq_table_init(struct wq_table *table, const char *name,
			  uint32_t max_tbl_elem, uint32_t elem_sz,
			  wq_table_poison_func poison)
{
	kern_return_t kr;
	uint32_t slab_sz, slab_shift, slab_msk, slab_elem;
	zone_t slab_zone;
	size_t max_tbl_sz;
	struct wqt_elem *e, **base;

	/*
	 * First, allocate a single page of memory to act as the base
	 * for the table's element slabs
	 */
	kr = kernel_memory_allocate(kernel_map, (vm_offset_t *)&base,
				    PAGE_SIZE, 0, KMA_NOPAGEWAIT, VM_KERN_MEMORY_WAITQ);
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
	wqdbg("Initializing %s zone: slab:%d (%d,0x%x) max:%ld",
	      name, slab_sz, slab_shift, slab_msk, max_tbl_sz);
	slab_zone = zinit(slab_sz, max_tbl_sz, slab_sz, name);
	assert(slab_zone != ZONE_NULL);

	/* allocate the first slab and populate it */
	base[0] = (struct wqt_elem *)zalloc(slab_zone);
	if (base[0] == NULL)
		panic("Can't allocate a %s table slab from zone:%p",
		      name, slab_zone);

	memset(base[0], 0, slab_sz);

	/* setup the initial freelist */
	wqdbg("initializing %d links (%d bytes each)...", slab_elem, elem_sz);
	for (unsigned l = 0; l < slab_elem; l++) {
		e = wqt_elem_ofst_slab(base[0], slab_msk, l * elem_sz);
		e->wqt_id.idx = l;
		/*
		 * setting generation to 0 ensures that a setid of 0 is
		 * invalid because the generation will be incremented before
		 * each element's allocation.
		 */
		e->wqt_id.generation = 0;
		e->wqt_next_idx = l + 1;
	}

	/* make sure the last free element points to a never-valid idx */
	e = wqt_elem_ofst_slab(base[0], slab_msk, (slab_elem - 1) * elem_sz);
	e->wqt_next_idx = WQT_IDX_MAX;

	lck_mtx_init(&table->lock, &g_wqt_lck_grp, LCK_ATTR_NULL);

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
	table->free_list.id = base[0]->wqt_id.id;

#if CONFIG_WAITQ_STATS
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
 * grow a waitq table by adding another 'slab' of table elements
 *
 * Conditions:
 *	table mutex is unlocked
 *	calling thread can block
 */
static void wq_table_grow(struct wq_table *table, uint32_t min_free)
{
	struct wqt_elem *slab, **slot;
	struct wqt_elem *e = NULL, *first_new_elem, *last_new_elem;
	struct wq_id free_id;
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
	wqdbg_v("BEGIN");

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
	slab = (struct wqt_elem *)zalloc(table->slab_zone);
	if (slab == NULL)
		panic("Can't allocate a %s table (%p) slab from zone:%p",
		      table->slab_zone->zone_name, table, table->slab_zone);

	memset(slab, 0, table->slab_sz);

	/* put the new elements into a freelist */
	wqdbg_v("    init %d new links...", table->slab_elem);
	for (unsigned l = 0; l < table->slab_elem; l++) {
		uint32_t idx = l + table->nelem;
		if (idx >= (WQT_IDX_MAX - 1))
			break; /* the last element of the last slab */
		e = wqt_elem_ofst_slab(slab, table->slab_msk, l * table->elem_sz);
		e->wqt_id.idx = idx;
		e->wqt_next_idx = idx + 1;
	}
	last_new_elem = e;
	assert(last_new_elem != NULL);

	first_new_elem = wqt_elem_ofst_slab(slab, table->slab_msk, 0);

	/* update table book keeping, and atomically swap the freelist head */
	*slot = slab;
	if (table->nelem + table->slab_elem >= WQT_IDX_MAX)
		table->nelem = WQT_IDX_MAX - 1;
	else
		table->nelem += table->slab_elem;

#if CONFIG_WAITQ_STATS
	table->nslabs += 1;
#endif

	/*
	 * The atomic swap of the free list head marks the end of table
	 * growth. Incoming requests may now use the newly allocated slab
	 * of table elements
	 */
	free_id = table->free_list;
	/* connect the existing free list to the end of the new free list */
	last_new_elem->wqt_next_idx = free_id.idx;
	while (OSCompareAndSwap64(free_id.id, first_new_elem->wqt_id.id,
				  &table->free_list.id) == FALSE) {
		OSMemoryBarrier();
		free_id = table->free_list;
		last_new_elem->wqt_next_idx = free_id.idx;
	}
	OSMemoryBarrier();

	lck_mtx_unlock(&table->lock);

	return;
}

static __attribute__((noinline))
struct wqt_elem *wq_table_alloc_elem(struct wq_table *table, int type, int nelem)
{
	int nspins = 0, ntries = 0, nalloc = 0;
	uint32_t table_size;
	struct wqt_elem *elem = NULL;
	struct wq_id free_id, next_id;

	static const int max_retries = 500;

	if (type != WQT_ELEM && type != WQT_LINK && type != WQT_RESERVED)
		panic("wq_table_aloc of invalid elem type:%d from table @%p",
		      type, table);

	assert(nelem > 0);

try_again:
	elem = NULL;
	if (ntries++ > max_retries) {
		struct wqt_elem *tmp;
		if (table->used_elem + nelem >= table_size)
			panic("No more room to grow table: 0x%p size:%d, used:%d, requested elem:%d",
			      table, table_size, table->used_elem, nelem);
		if (nelem == 1)
			panic("Too many alloc retries: %d, table:%p, type:%d, nelem:%d",
			      ntries, table, type, nelem);
		/* don't panic: try allocating one-at-a-time */
		while (nelem > 0) {
			tmp = wq_table_alloc_elem(table, type, 1);
			if (elem)
				wqt_elem_list_link(table, tmp, elem);
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
#if CONFIG_WAITQ_STATS
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
		wq_table_grow(table, nelem);
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
	for (struct wqt_elem *next_elem = wqt_elem_idx(table, free_id.idx);
	     nalloc < nelem;
	     nalloc++) {
		elem = next_elem;
		next_id.generation = 0;
		next_id.idx = next_elem->wqt_next_idx;
		if (next_id.idx < table->nelem) {
			next_elem = wqt_elem_idx(table, next_id.idx);
			next_id.id = next_elem->wqt_id.id;
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
	elem->wqt_next_idx = WQT_IDX_MAX;
	/* reset 'elem' to point to the first allocated element */
	elem = wqt_elem_idx(table, free_id.idx);

	/*
	 * Update the generation count, and return the element(s)
	 * with a single reference (and no valid bit). If the
	 * caller immediately calls _put() on any element, then
	 * it will be released back to the free list. If the caller
	 * subsequently marks the element as valid, then the put
	 * will simply drop the reference.
	 */
	for (struct wqt_elem *tmp = elem; ; ) {
		assert(!wqt_bits_valid(tmp->wqt_bits) &&
		       (wqt_bits_refcnt(tmp->wqt_bits) == 0));
		--nalloc;
		tmp->wqt_id.generation += 1;
		tmp->wqt_bits = 1;
		wqt_elem_set_type(tmp, type);
		if (tmp->wqt_next_idx == WQT_IDX_MAX)
			break;
		assert(tmp->wqt_next_idx != WQT_IDX_MAX);
		tmp = wqt_elem_idx(table, tmp->wqt_next_idx);
	}
	assert(nalloc == 0);

#if CONFIG_WAITQ_STATS
	uint64_t nreservations;
	table->nallocs += nelem;
	if (type == WQT_RESERVED)
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

static void wq_table_realloc_elem(struct wq_table *table, struct wqt_elem *elem, int type)
{
	(void)table;
	assert(wqt_elem_in_range(elem, table) &&
	       !wqt_bits_valid(elem->wqt_bits));

#if CONFIG_WAITQ_STATS
	table->nreallocs += 1;
	if (wqt_bits_type(elem->wqt_bits) == WQT_RESERVED && type != WQT_RESERVED) {
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
	elem->wqt_id.generation += 1;
	elem->wqt_next_idx = WQT_IDX_MAX;
	wqt_elem_set_type(elem, type);

	return;
}

static void wq_table_free_elem(struct wq_table *table, struct wqt_elem *elem)
{
	struct wq_id next_id;

	assert(wqt_elem_in_range(elem, table) &&
	       !wqt_bits_valid(elem->wqt_bits) &&
	       (wqt_bits_refcnt(elem->wqt_bits) == 0));

	OSDecrementAtomic(&table->used_elem);

#if CONFIG_WAITQ_STATS
	table->avg_used = (table->avg_used + table->used_elem) / 2;
	if (wqt_bits_type(elem->wqt_bits) == WQT_RESERVED)
		OSDecrementAtomic64(&table->nreservations);
	table->avg_reservations = (table->avg_reservations + table->nreservations) / 2;
#endif

	elem->wqt_bits = 0;

	if (table->poison)
		(table->poison)(table, elem);

again:
	next_id = table->free_list;
	if (next_id.idx >= table->nelem)
		elem->wqt_next_idx = WQT_IDX_MAX;
	else
		elem->wqt_next_idx = next_id.idx;

	/* store barrier */
	OSMemoryBarrier();
	if (OSCompareAndSwap64(next_id.id, elem->wqt_id.id,
			       &table->free_list.id) == FALSE)
		goto again;
}

/* get a reference to a table element identified by 'id' */
static struct wqt_elem *wq_table_get_elem(struct wq_table *table, uint64_t id)
{
	struct wqt_elem *elem;
	uint32_t idx, bits, new_bits;

	/*
	 * Here we have a reference to the table which is guaranteed to remain
	 * valid until we drop the reference
	 */

	idx = ((struct wq_id *)&id)->idx;

	if (idx >= table->nelem)
		panic("id:0x%llx : idx:%d > %d", id, idx, table->nelem);

	elem = wqt_elem_idx(table, idx);

	/* verify the validity by taking a reference on the table object */
	bits = elem->wqt_bits;
	if (!wqt_bits_valid(bits))
		return NULL;

	/*
	 * do a pre-verify on the element ID to potentially
	 * avoid 2 compare-and-swaps
	 */
	if (elem->wqt_id.id != id)
		return NULL;

	new_bits = bits + 1;

	/* check for overflow */
	assert(wqt_bits_refcnt(new_bits) > 0);

	while (OSCompareAndSwap(bits, new_bits, &elem->wqt_bits) == FALSE) {
		/*
		 * either the element became invalid,
		 * or someone else grabbed/removed a reference.
		 */
		bits = elem->wqt_bits;
		if (!wqt_bits_valid(bits)) {
			/* don't return invalid elements */
			return NULL;
		}
		new_bits = bits + 1;
		assert(wqt_bits_refcnt(new_bits) > 0);
	}

	/* load barrier */
	OSMemoryBarrier();

	/* check to see that our reference is to the same generation! */
	if (elem->wqt_id.id != id) {
		/*
		wqdbg("ID:0x%llx table generation (%d) != %d",
		      id, elem->wqt_id.generation,
		      ((struct wq_id *)&id)->generation);
		 */
		wq_table_put_elem(table, elem);
		return NULL;
	}

	/* We now have a reference on a valid object */
	return elem;
}

/* release a ref to table element - puts it back on free list as appropriate */
static void wq_table_put_elem(struct wq_table *table, struct wqt_elem *elem)
{
	uint32_t bits, new_bits;

	assert(wqt_elem_in_range(elem, table));

	bits = elem->wqt_bits;
	new_bits = bits - 1;

	/* check for underflow */
	assert(wqt_bits_refcnt(new_bits) < WQT_BITS_REFCNT_MASK);

	while (OSCompareAndSwap(bits, new_bits, &elem->wqt_bits) == FALSE) {
		bits = elem->wqt_bits;
		new_bits = bits - 1;
		/* catch underflow */
		assert(wqt_bits_refcnt(new_bits) < WQT_BITS_REFCNT_MASK);
	}

	/* load barrier */
	OSMemoryBarrier();

	/*
	 * if this was the last reference, and it was marked as invalid,
	 * then we can add this link object back to the free list
	 */
	if (!wqt_bits_valid(new_bits) && (wqt_bits_refcnt(new_bits) == 0))
		wq_table_free_elem(table, elem);

	return;
}


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
 *
 * API: wqt_elem_list_...
 *
 * Reuse the free list linkage member, 'wqt_next_idx' of a table element
 * in a slightly more generic singly-linked list. All members of this
 * list have been allocated from a table, but have not been made valid.
 *
 * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*/

/* link parent->child */
static int wqt_elem_list_link(struct wq_table *table, struct wqt_elem *parent, struct wqt_elem *child)
{
	int nelem = 1;

	assert(wqt_elem_in_range(parent, table));

	/* find the end of the parent's list */
	while (parent->wqt_next_idx != WQT_IDX_MAX) {
		assert(parent->wqt_next_idx < table->nelem);
		parent = wqt_elem_idx(table, parent->wqt_next_idx);
		nelem++;
	}

	if (child) {
		assert(wqt_elem_in_range(child, table));
		parent->wqt_next_idx = child->wqt_id.idx;
	}

	return nelem;
}

static struct wqt_elem *wqt_elem_list_next(struct wq_table *table, struct wqt_elem *head)
{
	struct wqt_elem *elem;

	if (!head)
		return NULL;
	if (head->wqt_next_idx >= table->nelem)
		return NULL;

	elem = wqt_elem_idx(table, head->wqt_next_idx);
	assert(wqt_elem_in_range(elem, table));

	return elem;
}

/*
 * Obtain a pointer to the first element of a list.  Don't take an extra
 * reference on the object - the list implicitly holds that reference.
 *
 * This function is used to convert the head of a singly-linked list
 * to a real wqt_elem object.
 */
static struct wqt_elem *wqt_elem_list_first(struct wq_table *table, uint64_t id)
{
	uint32_t idx;
	struct wqt_elem *elem = NULL;

	if (id == 0)
		return NULL;

	idx = ((struct wq_id *)&id)->idx;

	if (idx > table->nelem)
		panic("Invalid element for id:0x%llx", id);
	elem = wqt_elem_idx(table, idx);

	/* invalid element: reserved ID was probably already reallocated */
	if (elem->wqt_id.id != id)
		return NULL;

	/* the returned element should _not_ be marked valid! */
	if (wqt_bits_valid(elem->wqt_bits) ||
	    wqt_bits_type(elem->wqt_bits) != WQT_RESERVED ||
	    wqt_bits_refcnt(elem->wqt_bits) != 1) {
		panic("Valid/unreserved element %p (0x%x) in reserved list",
		      elem, elem->wqt_bits);
	}

	return elem;
}

static void wqt_elem_reset_next(struct wq_table *table, struct wqt_elem *wqp)
{
	(void)table;

	if (!wqp)
		return;
	assert(wqt_elem_in_range(wqp, table));

	wqp->wqt_next_idx = WQT_IDX_MAX;
}

/*
 * Pop an item off the list.
 * New list head returned in *id, caller responsible for reference on returned
 * object. We do a realloc here to reset the type of the object, but still
 * leave it invalid.
 */
static struct wqt_elem *wqt_elem_list_pop(struct wq_table *table, uint64_t *id, int type)
{
	struct wqt_elem *first, *next;

	if (!id || *id == 0)
		return NULL;

	/* pop an item off the reserved stack */

	first = wqt_elem_list_first(table, *id);
	if (!first) {
		*id = 0;
		return NULL;
	}

	next = wqt_elem_list_next(table, first);
	if (next)
		*id = next->wqt_id.id;
	else
		*id = 0;

	wq_table_realloc_elem(table, first, type);

	return first;
}

/*
 * Free an entire list of linked/reserved elements
 */
static int wqt_elem_list_release(struct wq_table *table,
				 struct wqt_elem *head,
				 int __assert_only type)
{
	struct wqt_elem *elem;
	struct wq_id free_id;
	int nelem = 0;

	if (!head)
		return 0;

	for (elem = head; ; ) {
		assert(wqt_elem_in_range(elem, table));
		assert(!wqt_bits_valid(elem->wqt_bits) && (wqt_bits_refcnt(elem->wqt_bits) == 1));
		assert(wqt_bits_type(elem->wqt_bits) == type);

		nelem++;
		elem->wqt_bits = 0;
		if (table->poison)
			(table->poison)(table, elem);

		if (elem->wqt_next_idx == WQT_IDX_MAX)
			break;
		assert(elem->wqt_next_idx < table->nelem);
		elem = wqt_elem_idx(table, elem->wqt_next_idx);
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
		elem->wqt_next_idx = WQT_IDX_MAX;
	else
		elem->wqt_next_idx = free_id.idx;

	/* store barrier */
	OSMemoryBarrier();
	if (OSCompareAndSwap64(free_id.id, head->wqt_id.id,
			       &table->free_list.id) == FALSE)
		goto again;

	OSAddAtomic(-nelem, &table->used_elem);
	return nelem;
}


/* ----------------------------------------------------------------------
 *
 * SetID Link Table Implementation
 *
 * ---------------------------------------------------------------------- */
static struct wq_table g_linktable;

enum setid_link_type {
	SLT_ALL     = -1,
	SLT_FREE    = WQT_FREE,
	SLT_WQS     = WQT_ELEM,
	SLT_LINK    = WQT_LINK,
};

struct setid_link {
	struct wqt_elem wqte;

	union {
		/* wqt_type == SLT_WQS (WQT_ELEM) */
		struct {
			struct waitq_set *sl_set;
			/* uint64_t          sl_prepost_id; */
		} sl_wqs;

		/* wqt_type == SLT_LINK (WQT_LINK) */
		struct {
			uint64_t          sl_left_setid;
			uint64_t          sl_right_setid;
		} sl_link;
	};
#ifdef CONFIG_WAITQ_LINK_STATS
	thread_t  sl_alloc_th;
	task_t    sl_alloc_task;
	uintptr_t sl_alloc_bt[NWAITQ_BTFRAMES];
	uint64_t  sl_alloc_ts;
	uintptr_t sl_invalidate_bt[NWAITQ_BTFRAMES];
	uint64_t  sl_invalidate_ts;
	uintptr_t sl_mkvalid_bt[NWAITQ_BTFRAMES];
	uint64_t  sl_mkvalid_ts;
	uint64_t  sl_free_ts;
#endif
};
#if !defined(CONFIG_WAITQ_LINK_STATS)
_Static_assert((sizeof(struct setid_link) & (sizeof(struct setid_link) - 1)) == 0,
	       "setid_link struct must be a power of two!");
#endif

#define sl_refcnt(link) \
	(wqt_bits_refcnt((link)->wqte.wqt_bits))

#define sl_type(link) \
	(wqt_bits_type((link)->wqte.wqt_bits))

#define sl_set_valid(link) \
	do { \
		wqt_elem_mkvalid(&(link)->wqte); \
		lt_do_mkvalid_stats(&(link)->wqte); \
	} while (0)

#define sl_is_valid(link) \
	wqt_bits_valid((link)->wqte.wqt_bits)

#define sl_set_id wqte.wqt_id

#define SLT_WQS_POISON         ((void *)(0xf00df00d))
#define SLT_LINK_POISON        (0x0bad0badffffffffull)

static void lt_poison(struct wq_table *table, struct wqt_elem *elem)
{
	struct setid_link *sl_link = (struct setid_link *)elem;
	(void)table;

	switch (sl_type(sl_link)) {
	case SLT_WQS:
		sl_link->sl_wqs.sl_set = SLT_WQS_POISON;
		break;
	case SLT_LINK:
		sl_link->sl_link.sl_left_setid = SLT_LINK_POISON;
		sl_link->sl_link.sl_right_setid = SLT_LINK_POISON;
		break;
	default:
		break;
	}
#ifdef CONFIG_WAITQ_LINK_STATS
	memset(sl_link->sl_alloc_bt, 0, sizeof(sl_link->sl_alloc_bt));
	sl_link->sl_alloc_ts = 0;
	memset(sl_link->sl_mkvalid_bt, 0, sizeof(sl_link->sl_mkvalid_bt));
	sl_link->sl_mkvalid_ts = 0;

	sl_link->sl_alloc_th = THREAD_NULL;
	/* leave the sl_alloc_task in place for debugging */

	sl_link->sl_free_ts = mach_absolute_time();
#endif
}

#ifdef CONFIG_WAITQ_LINK_STATS
static __inline__ void lt_do_alloc_stats(struct wqt_elem *elem)
{
	if (elem) {
		struct setid_link *link = (struct setid_link *)elem;
		memset(link->sl_alloc_bt, 0, sizeof(link->sl_alloc_bt));
		waitq_grab_backtrace(link->sl_alloc_bt, 0);
		link->sl_alloc_th = current_thread();
		link->sl_alloc_task = current_task();

		assert(link->sl_alloc_ts == 0);
		link->sl_alloc_ts = mach_absolute_time();

		memset(link->sl_invalidate_bt, 0, sizeof(link->sl_invalidate_bt));
		link->sl_invalidate_ts = 0;
	}
}

static __inline__ void lt_do_invalidate_stats(struct wqt_elem *elem)
{
	struct setid_link *link = (struct setid_link *)elem;

	if (!elem)
		return;

	assert(link->sl_mkvalid_ts > 0);

	memset(link->sl_invalidate_bt, 0, sizeof(link->sl_invalidate_bt));
	link->sl_invalidate_ts = mach_absolute_time();
	waitq_grab_backtrace(link->sl_invalidate_bt, 0);
}

static __inline__ void lt_do_mkvalid_stats(struct wqt_elem *elem)
{
	struct setid_link *link = (struct setid_link *)elem;

	if (!elem)
		return;

	memset(link->sl_mkvalid_bt, 0, sizeof(link->sl_mkvalid_bt));
	link->sl_mkvalid_ts = mach_absolute_time();
	waitq_grab_backtrace(link->sl_mkvalid_bt, 0);
}
#else
#define lt_do_alloc_stats(e)
#define lt_do_invalidate_stats(e)
#define lt_do_mkvalid_stats(e)
#endif /* CONFIG_WAITQ_LINK_STATS */

static void lt_init(void)
{
	uint32_t tablesz = 0, max_links = 0;

	if (PE_parse_boot_argn("wql_tsize", &tablesz, sizeof(tablesz)) != TRUE)
		tablesz = (uint32_t)g_wqt_max_tbl_size;

	tablesz = P2ROUNDUP(tablesz, PAGE_SIZE);
	max_links = tablesz / sizeof(struct setid_link);
	assert(max_links > 0 && tablesz > 0);

	/* we have a restricted index range */
	if (max_links > (WQT_IDX_MAX + 1))
		max_links = WQT_IDX_MAX + 1;

	wqinfo("init linktable with max:%d elements (%d bytes)",
	       max_links, tablesz);
	wq_table_init(&g_linktable, "wqslab.links", max_links,
		      sizeof(struct setid_link), lt_poison);
}

static void lt_ensure_free_space(void)
{
	if (g_linktable.nelem - g_linktable.used_elem < g_min_free_table_elem) {
		/*
		 * we don't hold locks on these values, so check for underflow
		 */
		if (g_linktable.used_elem <= g_linktable.nelem) {
			wqdbg_v("Forcing table growth: nelem=%d, used=%d, min_free=%d",
				g_linktable.nelem, g_linktable.used_elem,
				g_min_free_table_elem);
			wq_table_grow(&g_linktable, g_min_free_table_elem);
		}
	}
}

static struct setid_link *lt_alloc_link(int type)
{
	struct wqt_elem *elem;

	elem = wq_table_alloc_elem(&g_linktable, type, 1);
	lt_do_alloc_stats(elem);
	return (struct setid_link *)elem;
}

static void lt_realloc_link(struct setid_link *link, int type)
{
	wq_table_realloc_elem(&g_linktable, &link->wqte, type);
#ifdef CONFIG_WAITQ_LINK_STATS
	memset(link->sl_alloc_bt, 0, sizeof(link->sl_alloc_bt));
	link->sl_alloc_ts = 0;
	lt_do_alloc_stats(&link->wqte);

	memset(link->sl_invalidate_bt, 0, sizeof(link->sl_invalidate_bt));
	link->sl_invalidate_ts = 0;
#endif
}

static void lt_invalidate(struct setid_link *link)
{
	wqt_elem_invalidate(&link->wqte);
	lt_do_invalidate_stats(&link->wqte);
}

static struct setid_link *lt_get_link(uint64_t setid)
{
	struct wqt_elem *elem;

	elem = wq_table_get_elem(&g_linktable, setid);
	return (struct setid_link *)elem;
}

static void lt_put_link(struct setid_link *link)
{
	if (!link)
		return;
	wq_table_put_elem(&g_linktable, (struct wqt_elem *)link);
}

static struct setid_link *lt_get_reserved(uint64_t setid, int type)
{
	struct wqt_elem *elem;

	elem = wqt_elem_list_first(&g_linktable, setid);
	if (!elem)
		return NULL;
	wq_table_realloc_elem(&g_linktable, elem, type);
	return (struct setid_link *)elem;
}


static inline int waitq_maybe_remove_link(struct waitq *waitq,
					  uint64_t setid,
					  struct setid_link *parent,
					  struct setid_link *left,
					  struct setid_link *right);

enum {
	LINK_WALK_ONE_LEVEL = 0,
	LINK_WALK_FULL_DAG  = 1,
	LINK_WALK_FULL_DAG_UNLOCKED = 2,
};

typedef int (*lt_callback_func)(struct waitq *waitq, void *ctx,
				struct setid_link *link);

/**
 * walk all table elements (of type 'link_type') pointed to by 'setid'
 *
 * Conditions:
 *	waitq is locked (or NULL)
 *	'setid' is managed by 'waitq'
 *		this could be direct (waitq->waitq_set_id == setid)
 *		OR indirect (setid is the left/right ID in a LINK chain,
 *		             whose root is waitq->waitq_set_id)
 *
 * Notes:
 *	This function uses recursion to walk the set of table elements
 *	pointed to by 'setid'. For each element encountered, 'cb' will be
 *	called. If non-zero, the return value of this callback function can
 *	early-out of the table walk.
 *
 *	For each link element encountered, the function takes a reference to
 *	it. The reference is dropped only after the callback and any recursion
 *	has completed.
 *
 *	The assumed table/link/tree structure:
 *                   'setid'
 *                   /    \
 *                  /      \
 *              L(LINK)     R(LINK)
 *               /\             /\
 *              /  \           /  \
 *             /    \       Rl(*)  Rr(*)
 *         Ll(*)  Lr(*)      /\    /\
 *           /\     /\    ... ... ... ...
 *        ...  ... ... ...
 *                    \
 *                    WQS(wqset_q.waitq_setid == Sx)
 *                    [waitq set is a membet of setid, 'Sx')
 *
 *                    'Sx'
 *                   /    \
 *                  /      \
 *              L(LINK)     R(LINK)
 *               /\             /\
 *             ... ...        ... ...
 *
 *	The basic algorithm is as follows:
 *	*) take a reference to the table object pointed to by 'setid'
 *	*) if appropriate, call 'cb' (potentially early-out on non-zero return)
 *	*) if the link object points to a waitq set, and the walk type
 *	   is 'FULL_DAG' (full directed-acyclic-graph), then try to lock
 *	   the associated waitq set object and recursively walk all sets to
 *	   which that set belongs. This is a DFS of the tree structure.
 *	*) recurse down the left side of the tree (following the
 *	   'sl_left_setid' pointer in the link object
 *	*) recurse down the right side of the tree (following the
 *	   'sl_right_setid' pointer in the link object
 */
static __attribute__((noinline))
int walk_setid_links(int walk_type, struct waitq *waitq,
		     uint64_t setid, int link_type,
		     void *ctx, lt_callback_func cb)
{
	struct setid_link *link;
	uint64_t nextid;
	int sl_type;

	link = lt_get_link(setid);

	/* invalid link */
	if (!link)
		return WQ_ITERATE_CONTINUE;

	setid = nextid = 0;
	sl_type = sl_type(link);
	if (sl_type == SLT_LINK) {
		setid  = link->sl_link.sl_left_setid;
		nextid = link->sl_link.sl_right_setid;
	}

	/*
	 * Make the callback only on specified link_type (or all links)
	 * Note that after the callback, the link object may be
	 * invalid. The only valid thing we can do is put our
	 * reference to it (which may put it back on the free list)
	 */
	if (link_type == SLT_ALL || link_type == sl_type) {
		/* allow the callback to early-out */
		int ret = cb(waitq, ctx, link);
		if (ret != WQ_ITERATE_CONTINUE) {
			lt_put_link(link);
			return ret;
		}
	}

	if (sl_type == SLT_WQS &&
	    (walk_type == LINK_WALK_FULL_DAG ||
	     walk_type == LINK_WALK_FULL_DAG_UNLOCKED)) {
		/*
		 * Recurse down any sets to which this wait queue set was
		 * added.  We do this just before we put our reference to
		 * the link object (which may free it).
		 */
		struct waitq_set *wqset = link->sl_wqs.sl_set;
		int ret = WQ_ITERATE_CONTINUE;
		int get_spl = 0;
		int should_unlock = 0;
		uint64_t wqset_setid = 0;
		spl_t set_spl;

		if (waitq_set_is_valid(wqset) && walk_type == LINK_WALK_FULL_DAG) {
			if ((!waitq || !waitq_irq_safe(waitq)) &&
			    waitq_irq_safe(&wqset->wqset_q)) {
				get_spl = 1;
				set_spl = splsched();
			}
			waitq_set_lock(wqset);
			should_unlock = 1;
		}

		/*
		 * verify the linked waitq set as it could have been
		 * invalidated before we grabbed the lock!
		 */
		if (wqset->wqset_id != link->sl_set_id.id) {
			/*This is the bottom of the tree: just get out */
			if (should_unlock) {
				waitq_set_unlock(wqset);
				if (get_spl)
					splx(set_spl);
			}
			lt_put_link(link);
			return WQ_ITERATE_CONTINUE;
		}

		wqset_setid = wqset->wqset_q.waitq_set_id;

		if (wqset_setid > 0)
			ret = walk_setid_links(walk_type, &wqset->wqset_q,
					       wqset_setid, link_type, ctx, cb);
		if (should_unlock) {
			waitq_set_unlock(wqset);
			if (get_spl)
				splx(set_spl);
		}
		if (ret != WQ_ITERATE_CONTINUE) {
			lt_put_link(link);
			return ret;
		}
	}

	lt_put_link(link);

	/* recurse down left side of the tree */
	if (setid) {
		int ret = walk_setid_links(walk_type, waitq, setid, link_type, ctx, cb);
		if (ret != WQ_ITERATE_CONTINUE)
			return ret;
	}

	/* recurse down right side of the tree */
	if (nextid)
		return walk_setid_links(walk_type, waitq, nextid, link_type, ctx, cb);

	return WQ_ITERATE_CONTINUE;
}

/* ----------------------------------------------------------------------
 *
 * Prepost Link Table Implementation
 *
 * ---------------------------------------------------------------------- */
static struct wq_table g_prepost_table;

enum wq_prepost_type {
	WQP_FREE  = WQT_FREE,
	WQP_WQ    = WQT_ELEM,
	WQP_POST  = WQT_LINK,
};

struct wq_prepost {
	struct wqt_elem wqte;

	union {
		/* wqt_type == WQP_WQ (WQT_ELEM) */
		struct {
			struct waitq *wqp_wq_ptr;
		} wqp_wq;
		/* wqt_type == WQP_POST (WQT_LINK) */
		struct {
			uint64_t      wqp_next_id;
			uint64_t      wqp_wq_id;
		} wqp_post;
	};
#ifdef CONFIG_WAITQ_PREPOST_STATS
	thread_t  wqp_alloc_th;
	task_t    wqp_alloc_task;
	uintptr_t wqp_alloc_bt[NWAITQ_BTFRAMES];
#endif
};
#if !defined(CONFIG_WAITQ_PREPOST_STATS)
_Static_assert((sizeof(struct wq_prepost) & (sizeof(struct wq_prepost) - 1)) == 0,
	       "wq_prepost struct must be a power of two!");
#endif

#define wqp_refcnt(wqp) \
	(wqt_bits_refcnt((wqp)->wqte.wqt_bits))

#define wqp_type(wqp) \
	(wqt_bits_type((wqp)->wqte.wqt_bits))

#define wqp_set_valid(wqp) \
	wqt_elem_mkvalid(&(wqp)->wqte)

#define wqp_is_valid(wqp) \
	wqt_bits_valid((wqp)->wqte.wqt_bits)

#define wqp_prepostid wqte.wqt_id

#define WQP_WQ_POISON              (0x0bad0badffffffffull)
#define WQP_POST_POISON            (0xf00df00df00df00d)

static void wqp_poison(struct wq_table *table, struct wqt_elem *elem)
{
	struct wq_prepost *wqp = (struct wq_prepost *)elem;
	(void)table;

	switch (wqp_type(wqp)) {
	case WQP_WQ:
		break;
	case WQP_POST:
		wqp->wqp_post.wqp_next_id = WQP_POST_POISON;
		wqp->wqp_post.wqp_wq_id = WQP_POST_POISON;
		break;
	default:
		break;
	}
}

#ifdef CONFIG_WAITQ_PREPOST_STATS
static __inline__ void wqp_do_alloc_stats(struct wqt_elem *elem)
{
	if (elem) {
		struct wq_prepost *wqp = (struct wq_prepost *)elem;

		/* be sure the take stats for _all_ allocated objects */
		for (;;) {
			uint32_t next_idx;

			memset(wqp->wqp_alloc_bt, 0, sizeof(wqp->wqp_alloc_bt));
			waitq_grab_backtrace(wqp->wqp_alloc_bt, 4);
			wqp->wqp_alloc_th = current_thread();
			wqp->wqp_alloc_task = current_task();
			next_idx = wqp->wqte.wqt_next_idx;

			if (next_idx == WQT_IDX_MAX)
				break;
			assert(next_idx < g_prepost_table.nelem);

			wqp = (struct wq_prepost *)wqt_elem_idx(&g_prepost_table,
								next_idx);
		}
	}
}
#else
#define wqp_do_alloc_stats(e)
#endif /* CONFIG_WAITQ_LINK_STATS */

static void wqp_init(void)
{
	uint32_t tablesz = 0, max_wqp = 0;

	if (PE_parse_boot_argn("wqp_tsize", &tablesz, sizeof(tablesz)) != TRUE)
		tablesz = (uint32_t)g_wqt_max_tbl_size;

	tablesz = P2ROUNDUP(tablesz, PAGE_SIZE);
	max_wqp = tablesz / sizeof(struct wq_prepost);
	assert(max_wqp > 0 && tablesz > 0);

	/* we have a restricted index range */
	if (max_wqp > (WQT_IDX_MAX + 1))
		max_wqp = WQT_IDX_MAX + 1;

	wqinfo("init prepost table with max:%d elements (%d bytes)",
	       max_wqp, tablesz);
	wq_table_init(&g_prepost_table, "wqslab.prepost", max_wqp,
		      sizeof(struct wq_prepost), wqp_poison);
}

/*
 * Refill the per-CPU cache.
 */
static void wq_prepost_refill_cpu_cache(uint32_t nalloc)
{
	struct wqt_elem *new_head, *old_head;
	struct wqp_cache *cache;

	/* require preemption enabled to allocate elements */
	if (get_preemption_level() != 0)
		return;

	new_head = wq_table_alloc_elem(&g_prepost_table,
				       WQT_RESERVED, nalloc);
	if (new_head == NULL)
		return;

	disable_preemption();
	cache = &PROCESSOR_DATA(current_processor(), wqp_cache);
	cache->avail += nalloc;
	if (cache->head == 0 || cache->head == WQT_IDX_MAX) {
		cache->head = new_head->wqt_id.id;
		goto out;
	}

	old_head = wqt_elem_list_first(&g_prepost_table, cache->head);
	(void)wqt_elem_list_link(&g_prepost_table, new_head, old_head);
	cache->head = new_head->wqt_id.id;

out:
	enable_preemption();
	return;
}

static void wq_prepost_ensure_free_space(void)
{
	uint32_t free_elem;
	uint32_t min_free;
	struct wqp_cache *cache;

	if (g_min_free_cache == 0)
		g_min_free_cache = (WQP_CACHE_MAX * ml_get_max_cpus());

	/*
	 * Ensure that we always have a pool of per-CPU prepost elements
	 */
	disable_preemption();
	cache = &PROCESSOR_DATA(current_processor(), wqp_cache);
	free_elem = cache->avail;
	enable_preemption();

	if (free_elem < (WQP_CACHE_MAX / 3))
		wq_prepost_refill_cpu_cache(WQP_CACHE_MAX - free_elem);

	/*
	 * Now ensure that we have a sufficient amount of free table space
	 */
	free_elem = g_prepost_table.nelem - g_prepost_table.used_elem;
	min_free = g_min_free_table_elem + g_min_free_cache;
	if (free_elem < min_free) {
		/*
		 * we don't hold locks on these values, so check for underflow
		 */
		if (g_prepost_table.used_elem <= g_prepost_table.nelem) {
			wqdbg_v("Forcing table growth: nelem=%d, used=%d, min_free=%d+%d",
				g_prepost_table.nelem, g_prepost_table.used_elem,
				g_min_free_table_elem, g_min_free_cache);
			wq_table_grow(&g_prepost_table, min_free);
		}
	}
}

static struct wq_prepost *wq_prepost_alloc(int type, int nelem)
{
	struct wqt_elem *elem;
	struct wq_prepost *wqp;
	struct wqp_cache *cache;

	if (type != WQT_RESERVED)
		goto do_alloc;
	if (nelem == 0)
		return NULL;

	/*
	 * First try to grab the elements from the per-CPU cache if we are
	 * allocating RESERVED elements
	 */
	disable_preemption();
	cache = &PROCESSOR_DATA(current_processor(), wqp_cache);
	if (nelem <= (int)cache->avail) {
		struct wqt_elem *first, *next = NULL;
		int nalloc = nelem;

		cache->avail -= nelem;

		/* grab the first element */
		first = wqt_elem_list_first(&g_prepost_table, cache->head);

		/* find the last element and re-adjust the cache head */
		for (elem = first; elem != NULL && nalloc > 0; elem = next) {
			next = wqt_elem_list_next(&g_prepost_table, elem);
			if (--nalloc == 0) {
				/* terminate the allocated list */
				elem->wqt_next_idx = WQT_IDX_MAX;
				break;
			}
		}
		assert(nalloc == 0);
		if (!next)
			cache->head = WQT_IDX_MAX;
		else
			cache->head = next->wqt_id.id;
		/* assert that we don't have mis-matched book keeping */
		assert(!(cache->head == WQT_IDX_MAX && cache->avail > 0));
		enable_preemption();
		elem = first;
		goto out;
	}
	enable_preemption();

do_alloc:
	/* fall-back to standard table allocation */
	elem = wq_table_alloc_elem(&g_prepost_table, type, nelem);
	if (!elem)
		return NULL;

out:
	wqp = (struct wq_prepost *)elem;
	wqp_do_alloc_stats(elem);
	return wqp;
}

/*
static void wq_prepost_realloc(struct wq_prepost *wqp, int type)
{
	wq_table_realloc_elem(&g_prepost_table, &wqp->wqte, type);
}
*/

static void wq_prepost_invalidate(struct wq_prepost *wqp)
{
	wqt_elem_invalidate(&wqp->wqte);
}

static struct wq_prepost *wq_prepost_get(uint64_t wqp_id)
{
	struct wqt_elem *elem;

	elem = wq_table_get_elem(&g_prepost_table, wqp_id);
	return (struct wq_prepost *)elem;
}

static void wq_prepost_put(struct wq_prepost *wqp)
{
	wq_table_put_elem(&g_prepost_table, (struct wqt_elem *)wqp);
}

static int wq_prepost_rlink(struct wq_prepost *parent, struct wq_prepost *child)
{
	return wqt_elem_list_link(&g_prepost_table, &parent->wqte, &child->wqte);
}

static struct wq_prepost *wq_prepost_get_rnext(struct wq_prepost *head)
{
	struct wqt_elem *elem;
	struct wq_prepost *wqp;
	uint64_t id;

	elem = wqt_elem_list_next(&g_prepost_table, &head->wqte);
	if (!elem)
		return NULL;
	id = elem->wqt_id.id;
	elem = wq_table_get_elem(&g_prepost_table, id);

	if (!elem)
		return NULL;
	wqp = (struct wq_prepost *)elem;
	if (elem->wqt_id.id != id ||
	    wqp_type(wqp) != WQP_POST ||
	    wqp->wqp_post.wqp_next_id != head->wqp_prepostid.id) {
		wq_table_put_elem(&g_prepost_table, elem);
		return NULL;
	}

	return wqp;
}

static void wq_prepost_reset_rnext(struct wq_prepost *wqp)
{
	wqt_elem_reset_next(&g_prepost_table, &wqp->wqte);
}


/**
 * remove 'wqp' from the prepost list on 'wqset'
 *
 * Conditions:
 *	wqset is locked
 *	caller holds a reference on wqp (and is responsible to release it)
 *
 * Result:
 *	wqp is invalidated, wqset is potentially updated with a new
 *	prepost ID, and the next element of the prepost list may be
 *	consumed as well (if the list contained only 2 objects)
 */
static int wq_prepost_remove(struct waitq_set *wqset,
			     struct wq_prepost *wqp)
{
	int more_posts = 1;
	uint64_t next_id = wqp->wqp_post.wqp_next_id;
	uint64_t wqp_id = wqp->wqp_prepostid.id;
	struct wq_prepost *prev_wqp, *next_wqp;

	assert(wqp_type(wqp) == WQP_POST);

	if (next_id == wqp_id) {
		/* the list is singular and becoming empty */
		wqset->wqset_prepost_id = 0;
		more_posts = 0;
		goto out;
	}

	prev_wqp = wq_prepost_get_rnext(wqp);
	assert(prev_wqp != NULL);
	assert(prev_wqp->wqp_post.wqp_next_id == wqp_id);
	assert(prev_wqp->wqp_prepostid.id != wqp_id);
	assert(wqp_type(prev_wqp) == WQP_POST);

	if (prev_wqp->wqp_prepostid.id == next_id) {
		/*
		 * There are two items in the list, and we're removing one. We
		 * only need to keep the WQP_WQ pointer from 'prev_wqp'
		 */
		wqset->wqset_prepost_id = prev_wqp->wqp_post.wqp_wq_id;
		wq_prepost_invalidate(prev_wqp);
		wq_prepost_put(prev_wqp);
		more_posts = 0;
		goto out;
	}

	/* prev->next = next */
	prev_wqp->wqp_post.wqp_next_id = next_id;

	/* next->prev = prev */
	next_wqp = wq_prepost_get(next_id);
	assert(next_wqp != NULL);
	assert(next_wqp != wqp);
	assert(next_wqp != prev_wqp);
	assert(wqp_type(next_wqp) == WQP_POST);

	wq_prepost_reset_rnext(next_wqp);
	wq_prepost_rlink(next_wqp, prev_wqp);

	/* If we remove the head of the list, update the wqset */
	if (wqp_id == wqset->wqset_prepost_id)
		wqset->wqset_prepost_id = next_id;

	wq_prepost_put(prev_wqp);
	wq_prepost_put(next_wqp);

out:
	wq_prepost_reset_rnext(wqp);
	wq_prepost_invalidate(wqp);
	return more_posts;
}

static struct wq_prepost *wq_prepost_rfirst(uint64_t id)
{
	struct wqt_elem *elem;
	elem = wqt_elem_list_first(&g_prepost_table, id);
	wqp_do_alloc_stats(elem);
	return (struct wq_prepost *)(void *)elem;
}

static struct wq_prepost *wq_prepost_rpop(uint64_t *id, int type)
{
	struct wqt_elem *elem;
	elem = wqt_elem_list_pop(&g_prepost_table, id, type);
	wqp_do_alloc_stats(elem);
	return (struct wq_prepost *)(void *)elem;
}

static void wq_prepost_release_rlist(struct wq_prepost *wqp)
{
	int nelem = 0;
	struct wqp_cache *cache;
	struct wqt_elem *elem;

	if (!wqp)
		return;

	elem = &wqp->wqte;

	/*
	 * These are reserved elements: release them back to the per-cpu pool
	 * if our cache is running low.
	 */
	disable_preemption();
	cache = &PROCESSOR_DATA(current_processor(), wqp_cache);
	if (cache->avail < WQP_CACHE_MAX) {
		struct wqt_elem *tmp = NULL;
		if (cache->head != WQT_IDX_MAX)
			tmp = wqt_elem_list_first(&g_prepost_table, cache->head);
		nelem = wqt_elem_list_link(&g_prepost_table, elem, tmp);
		cache->head = elem->wqt_id.id;
		cache->avail += nelem;
		enable_preemption();
		return;
	}
	enable_preemption();

	/* release these elements back to the main table */
	nelem = wqt_elem_list_release(&g_prepost_table, elem, WQT_RESERVED);

#if CONFIG_WAITQ_STATS
	g_prepost_table.nreserved_releases += 1;
	OSDecrementAtomic64(&g_prepost_table.nreservations);
#endif
}

typedef int (*wqp_callback_func)(struct waitq_set *wqset,
				 void *ctx,
				 struct wq_prepost *wqp,
				 struct waitq *waitq);

/**
 * iterate over a chain of preposts associated with a waitq set.
 *
 * Conditions:
 *	wqset is locked
 *
 * Notes:
 *	This loop performs automatic prepost chain management / culling, and
 *	may reset or adjust the waitq set's prepost ID pointer. If you don't
 *	want this extra processing, you can use wq_prepost_iterate().
 */
static int wq_prepost_foreach_locked(struct waitq_set *wqset,
				     void *ctx, wqp_callback_func cb)
{
	int ret;
	struct wq_prepost *wqp, *tmp_wqp;

	if (!wqset || !wqset->wqset_prepost_id)
		return WQ_ITERATE_SUCCESS;

restart:
	wqp = wq_prepost_get(wqset->wqset_prepost_id);
	if (!wqp) {
		/*
		 * The prepost object is no longer valid, reset the waitq
		 * set's prepost id.
		 */
		wqset->wqset_prepost_id = 0;
		return WQ_ITERATE_SUCCESS;
	}

	if (wqp_type(wqp) == WQP_WQ) {
		uint64_t __assert_only wqp_id = wqp->wqp_prepostid.id;
		if (cb)
			ret = cb(wqset, ctx, wqp, wqp->wqp_wq.wqp_wq_ptr);

		switch (ret) {
		case WQ_ITERATE_INVALIDATE_CONTINUE:
			/* the caller wants to remove the only prepost here */
			assert(wqp_id == wqset->wqset_prepost_id);
			wqset->wqset_prepost_id = 0;
			/* fall through */
		case WQ_ITERATE_CONTINUE:
			wq_prepost_put(wqp);
			ret = WQ_ITERATE_SUCCESS;
			break;
		case WQ_ITERATE_RESTART:
			wq_prepost_put(wqp);
			/* fall through */
		case WQ_ITERATE_DROPPED:
			goto restart;
		default:
			wq_prepost_put(wqp);
			break;
		}
		return ret;
	}

	assert(wqp->wqp_prepostid.id == wqset->wqset_prepost_id);
	assert(wqp_type(wqp) == WQP_POST);

	/*
	 * At this point we know we have a list of POST objects.
	 * Grab a handle to the last element in the list and start
	 * the iteration.
	 */
	tmp_wqp = wq_prepost_get_rnext(wqp);
	assert(tmp_wqp != NULL && wqp_type(tmp_wqp) == WQP_POST);

	uint64_t last_id = tmp_wqp->wqp_prepostid.id;
	wq_prepost_put(tmp_wqp);

	ret = WQ_ITERATE_SUCCESS;
	for (;;) {
		uint64_t wqp_id, first_id, next_id;

		wqp_id = wqp->wqp_prepostid.id;
		first_id = wqset->wqset_prepost_id;
		next_id = wqp->wqp_post.wqp_next_id;

		/* grab the WQP_WQ object this _POST points to */
		tmp_wqp = wq_prepost_get(wqp->wqp_post.wqp_wq_id);
		if (!tmp_wqp) {
			/*
			 * This WQP_POST object points to an invalid
			 * WQP_WQ object - remove the POST object from
			 * the list.
			 */
			if (wq_prepost_remove(wqset, wqp) == 0) {
				wq_prepost_put(wqp);
				goto restart;
			}
			goto next_prepost;
		}
		assert(wqp_type(tmp_wqp) == WQP_WQ);
		/*
		 * make the callback: note that this could remove 'wqp' or
		 * drop the lock on our waitq set. We need to re-validate
		 * our state when this function returns.
		 */
		if (cb)
			ret = cb(wqset, ctx, wqp,
				 tmp_wqp->wqp_wq.wqp_wq_ptr);
		wq_prepost_put(tmp_wqp);

		switch (ret) {
		case WQ_ITERATE_CONTINUE:
			/* continue iteration */
			break;
		case WQ_ITERATE_INVALIDATE_CONTINUE:
			assert(next_id == wqp->wqp_post.wqp_next_id);
			if (wq_prepost_remove(wqset, wqp) == 0) {
				wq_prepost_put(wqp);
				goto restart;
			}
			goto next_prepost;
		case WQ_ITERATE_RESTART:
			wq_prepost_put(wqp);
			/* fall-through */
		case WQ_ITERATE_DROPPED:
			/* the callback dropped the ref to wqp: just restart */
			goto restart;
		default:
			/* break out of the iteration for some other reason */
			goto finish_prepost_foreach;
		}

		/*
		 * the set lock may have been dropped during callback,
		 * if something looks different, restart the prepost iteration
		 */
		if (!wqp_is_valid(wqp) ||
		    (wqp->wqp_post.wqp_next_id != next_id) ||
		    wqset->wqset_prepost_id != first_id) {
			wq_prepost_put(wqp);
			goto restart;
		}

next_prepost:
		/* this was the last object in the list */
		if (wqp_id == last_id)
			break;

		/* get the next object */
		tmp_wqp = wq_prepost_get(next_id);
		if (!tmp_wqp) {
			/*
			 * At this point we've already checked our state
			 * after the callback (which may have dropped the set
			 * lock). If we find an invalid member of the list
			 * then something is wrong.
			 */
			panic("Invalid WQP_POST member 0x%llx in waitq set "
			      "0x%llx prepost list (first:%llx, "
			      "wqp:%p)",
			      next_id, wqset->wqset_id, first_id, wqp);
		}
		wq_prepost_put(wqp);
		wqp = tmp_wqp;

		assert(wqp_type(wqp) == WQP_POST);
	}

finish_prepost_foreach:
	wq_prepost_put(wqp);
	if (ret == WQ_ITERATE_CONTINUE)
		ret = WQ_ITERATE_SUCCESS;

	return ret;
}

/**
 * Perform a simple loop over a chain of prepost objects
 *
 * Conditions:
 *	If 'prepost_id' is associated with a waitq (set) then that object must
 *	be locked before calling this function.
 *	Callback function, 'cb', must be able to handle a NULL wqset pointer
 *	and a NULL waitq pointer!
 *
 * Notes:
 *	This prepost chain iteration will _not_ automatically adjust any chain
 *	element or linkage. This is the responsibility of the caller! If you
 *	want automatic prepost chain management (at a cost of extra CPU time),
 *	you can use: wq_prepost_foreach_locked().
 */
static int wq_prepost_iterate(uint64_t prepost_id,
			      void *ctx, wqp_callback_func cb)
{
	int ret;
	struct wq_prepost *wqp;

	if (!prepost_id)
		return WQ_ITERATE_SUCCESS;

	wqp = wq_prepost_get(prepost_id);
	if (!wqp)
		return WQ_ITERATE_SUCCESS;

	if (wqp_type(wqp) == WQP_WQ) {
		ret = WQ_ITERATE_SUCCESS;
		if (cb)
			ret = cb(NULL, ctx, wqp, wqp->wqp_wq.wqp_wq_ptr);

		if (ret != WQ_ITERATE_DROPPED)
			wq_prepost_put(wqp);
		return ret;
	}

	assert(wqp->wqp_prepostid.id == prepost_id);
	assert(wqp_type(wqp) == WQP_POST);

	/* at this point we know we have a list of POST objects */
	uint64_t next_id;

	ret = WQ_ITERATE_CONTINUE;
	do {
		struct wq_prepost *tmp_wqp;
		struct waitq *wq = NULL;

		next_id = wqp->wqp_post.wqp_next_id;

		/* grab the WQP_WQ object this _POST points to */
		tmp_wqp = wq_prepost_get(wqp->wqp_post.wqp_wq_id);
		if (tmp_wqp) {
			assert(wqp_type(tmp_wqp) == WQP_WQ);
			wq = tmp_wqp->wqp_wq.wqp_wq_ptr;
		}

		if (cb)
			ret = cb(NULL, ctx, wqp, wq);
		if (tmp_wqp)
			wq_prepost_put(tmp_wqp);

		if (ret != WQ_ITERATE_CONTINUE)
			break;

		tmp_wqp = wq_prepost_get(next_id);
		if (!tmp_wqp) {
			/*
			 * the chain is broken: nothing we can do here besides
			 * bail from the iteration.
			 */
			ret = WQ_ITERATE_ABORTED;
			break;
		}

		wq_prepost_put(wqp);
		wqp = tmp_wqp;

		assert(wqp_type(wqp) == WQP_POST);
	} while (next_id != prepost_id);

	if (ret != WQ_ITERATE_DROPPED)
		wq_prepost_put(wqp);

	if (ret == WQ_ITERATE_CONTINUE)
		ret = WQ_ITERATE_SUCCESS;
	return ret;
}


struct _is_posted_ctx {
	struct waitq *posting_wq;
	int did_prepost;
};

static int wq_is_preposted_on_set_cb(struct waitq_set *wqset, void *ctx,
				     struct wq_prepost *wqp, struct waitq *waitq)
{
	struct _is_posted_ctx *pctx = (struct _is_posted_ctx *)ctx;

	(void)wqset;
	(void)wqp;

	/*
	 * Don't early-out, run through the _entire_ list:
	 * This ensures that we retain a minimum number of invalid elements.
	 */
	if (pctx->posting_wq == waitq)
		pctx->did_prepost = 1;

	return WQ_ITERATE_CONTINUE;
}


/**
 * checks if 'waitq' has already preposted on 'wqset'
 *
 * Parameters:
 *	waitq    The waitq that's preposting
 *	wqset    The set onto which waitq may be preposted
 *
 * Conditions:
 *	both waitq and wqset are locked
 *
 * Returns non-zero if 'waitq' has already preposted to 'wqset'
 */
static int wq_is_preposted_on_set(struct waitq *waitq, struct waitq_set *wqset)
{
	int ret;
	struct _is_posted_ctx pctx;

	/*
	 * If the set's only prepost matches the waitq's prepost ID,
	 * then it obviously already preposted to the set.
	 */
	if (waitq->waitq_prepost_id != 0 &&
	    wqset->wqset_prepost_id == waitq->waitq_prepost_id)
		return 1;

	/* use full prepost iteration: always trim the list */
	pctx.posting_wq = waitq;
	pctx.did_prepost = 0;
	ret = wq_prepost_foreach_locked(wqset, (void *)&pctx,
					wq_is_preposted_on_set_cb);
	return pctx.did_prepost;
}

static struct wq_prepost *wq_get_prepost_obj(uint64_t *reserved, int type)
{
	struct wq_prepost *wqp = NULL;
	/*
	 * don't fail just because the caller doesn't have enough
	 * reservations, we've kept a low-water mark on the prepost table,
	 * so there should be some available for us.
	 */
	if (reserved && *reserved) {
		wqp = wq_prepost_rpop(reserved, type);
	} else {
		/*
		 * TODO: if in interrupt context, grab from a special
		 *       region / reserved list!
		 */
		wqp = wq_prepost_alloc(type, 1);
	}

	if (wqp == NULL)
		panic("Couldn't allocate prepost object!");
	return wqp;
}


/**
 * prepost a waitq onto a waitq set
 *
 * Parameters:
 *	wqset    The set onto which waitq will be preposted
 *	waitq    The waitq that's preposting
 *	reserved List (wqt_elem_list_ style) of pre-allocated prepost elements
 *	         Could be NULL
 *
 * Conditions:
 *	both wqset and waitq are locked
 *
 * Notes:
 *	If reserved is NULL, this may block on prepost table growth.
 */
static void wq_prepost_do_post_locked(struct waitq_set *wqset,
				      struct waitq *waitq,
				      uint64_t *reserved)
{
	struct wq_prepost *wqp_post, *wqp_head, *wqp_tail;

	assert(waitq_held(waitq) && waitq_held(&wqset->wqset_q));

	/*
	 * nothing to do if it's already preposted:
	 * note that this also culls any invalid prepost objects
	 */
	if (wq_is_preposted_on_set(waitq, wqset))
		return;

	/*
	 * This function is called because an event is being posted to 'waitq'.
	 * We need a prepost object associated with this queue. Allocate one
	 * now if the waitq isn't already associated with one.
	 */
	if (waitq->waitq_prepost_id == 0) {
		struct wq_prepost *wqp;
		wqp = wq_get_prepost_obj(reserved, WQP_WQ);
		wqp->wqp_wq.wqp_wq_ptr = waitq;
		wqp_set_valid(wqp);
		waitq->waitq_prepost_id = wqp->wqp_prepostid.id;
		wq_prepost_put(wqp);
	}

#if CONFIG_WAITQ_STATS
	g_prepost_table.npreposts += 1;
#endif

	wqdbg_v("preposting waitq %p (0x%llx) to set 0x%llx",
		(void *)VM_KERNEL_UNSLIDE_OR_PERM(waitq),
		waitq->waitq_prepost_id, wqset->wqset_id);

	if (wqset->wqset_prepost_id == 0) {
		/* the set has no previous preposts */
		wqset->wqset_prepost_id = waitq->waitq_prepost_id;
		return;
	}

	wqp_head = wq_prepost_get(wqset->wqset_prepost_id);
	if (!wqp_head) {
		/* the previous prepost has become invalid */
		wqset->wqset_prepost_id = waitq->waitq_prepost_id;
		return;
	}

	assert(wqp_head->wqp_prepostid.id == wqset->wqset_prepost_id);

	/*
	 * If we get here, we're going to need at least one new wq_prepost
	 * object. If the previous wqset_prepost_id points to a WQP_WQ, we
	 * actually need to allocate 2 wq_prepost objects because the WQP_WQ
	 * is tied to the waitq and shared across all sets.
	 */
	wqp_post = wq_get_prepost_obj(reserved, WQP_POST);

	wqp_post->wqp_post.wqp_wq_id = waitq->waitq_prepost_id;
	wqdbg_v("POST 0x%llx :: WQ 0x%llx", wqp_post->wqp_prepostid.id,
		waitq->waitq_prepost_id);

	if (wqp_type(wqp_head) == WQP_WQ) {
		/*
		 * We must replace the wqset_prepost_id with a pointer
		 * to two new WQP_POST objects
		 */
		uint64_t wqp_id = wqp_head->wqp_prepostid.id;
		wqdbg_v("set 0x%llx previous had 1 WQ prepost (0x%llx): "
			"replacing with two POST preposts",
			wqset->wqset_id, wqp_id);

		/* drop the old reference */
		wq_prepost_put(wqp_head);

		/* grab another new object (the 2nd of two) */
		wqp_head = wq_get_prepost_obj(reserved, WQP_POST);

		/* point this one to the original WQP_WQ object */
		wqp_head->wqp_post.wqp_wq_id = wqp_id;
		wqdbg_v("POST 0x%llx :: WQ 0x%llx",
			wqp_head->wqp_prepostid.id, wqp_id);
	
		/* link it to the new wqp_post object allocated earlier */
		wqp_head->wqp_post.wqp_next_id = wqp_post->wqp_prepostid.id;
		/* make the list a double-linked and circular */
		wq_prepost_rlink(wqp_head, wqp_post);

		/*
		 * Finish setting up the new prepost: point it back to the
		 * POST object we allocated to replace the original wqset
		 * WQ prepost object
		 */
		wqp_post->wqp_post.wqp_next_id = wqp_head->wqp_prepostid.id;
		wq_prepost_rlink(wqp_post, wqp_head);

		/* mark objects valid, and reset the wqset prepost list head */
		wqp_set_valid(wqp_head);
		wqp_set_valid(wqp_post);
		wqset->wqset_prepost_id = wqp_head->wqp_prepostid.id;

		/* release both references */
		wq_prepost_put(wqp_head);
		wq_prepost_put(wqp_post);

		wqdbg_v("set 0x%llx: 0x%llx/0x%llx -> 0x%llx/0x%llx -> 0x%llx",
			wqset->wqset_id, wqset->wqset_prepost_id,
			wqp_head->wqp_prepostid.id, wqp_head->wqp_post.wqp_next_id,
			wqp_post->wqp_prepostid.id,
			wqp_post->wqp_post.wqp_next_id);
		return;
	}

	assert(wqp_type(wqp_head) == WQP_POST);

	/*
	 * Add the new prepost to the end of the prepost list
	 */
	wqp_tail = wq_prepost_get_rnext(wqp_head);
	assert(wqp_tail != NULL);
	assert(wqp_tail->wqp_post.wqp_next_id == wqset->wqset_prepost_id);

	/*
	 * link the head to the new tail
	 * NOTE: this needs to happen first in case wqp_tail == wqp_head
	 */
	wq_prepost_reset_rnext(wqp_head);
	wq_prepost_rlink(wqp_head, wqp_post);

	/* point the new object to the list head, and list tail */
	wqp_post->wqp_post.wqp_next_id = wqp_head->wqp_prepostid.id;
	wq_prepost_rlink(wqp_post, wqp_tail);

	/* point the last item in the waitq set's list to the new object */
	wqp_tail->wqp_post.wqp_next_id = wqp_post->wqp_prepostid.id;

	wqp_set_valid(wqp_post);

	wq_prepost_put(wqp_head);
	wq_prepost_put(wqp_tail);
	wq_prepost_put(wqp_post);

	wqdbg_v("set 0x%llx (wqp:0x%llx) last_prepost:0x%llx, "
		"new_prepost:0x%llx->0x%llx", wqset->wqset_id,
		wqset->wqset_prepost_id, wqp_head->wqp_prepostid.id,
		wqp_post->wqp_prepostid.id, wqp_post->wqp_post.wqp_next_id);

	return;
}


/* ----------------------------------------------------------------------
 *
 * Stats collection / reporting
 *
 * ---------------------------------------------------------------------- */
#if CONFIG_WAITQ_STATS
static void wq_table_stats(struct wq_table *table, struct wq_table_stats *stats)
{
	stats->version = WAITQ_STATS_VERSION;
	stats->table_elements = table->nelem;
	stats->table_used_elems = table->used_elem;
	stats->table_elem_sz = table->elem_sz;
	stats->table_slabs = table->nslabs;
	stats->table_slab_sz = table->slab_sz;

	stats->table_num_allocs = table->nallocs;
	stats->table_num_preposts = table->npreposts;
	stats->table_num_reservations = table->nreservations;

	stats->table_max_used = table->max_used;
	stats->table_avg_used = table->avg_used;
	stats->table_max_reservations = table->max_reservations;
	stats->table_avg_reservations = table->avg_reservations;
}

void waitq_link_stats(struct wq_table_stats *stats)
{
	if (!stats)
		return;
	wq_table_stats(&g_linktable, stats);
}

void waitq_prepost_stats(struct wq_table_stats *stats)
{
	wq_table_stats(&g_prepost_table, stats);
}
#endif


/* ----------------------------------------------------------------------
 *
 * Global Wait Queues
 *
 * ---------------------------------------------------------------------- */

static struct waitq g_boot_waitq;
static struct waitq *global_waitqs = &g_boot_waitq;
static uint32_t g_num_waitqs = 1;

/*
 * Zero out the used MSBs of the event.
 */
#define _CAST_TO_EVENT_MASK(event)   ((uintptr_t)(event) & ((1ul << _EVENT_MASK_BITS) - 1ul))

/*
 * The Jenkins "one at a time" hash.
 * TBD: There may be some value to unrolling here,
 * depending on the architecture.
 */
static __inline__ uint32_t waitq_hash(char *key, size_t length)
{
	uint32_t hash = 0;
	size_t i;

	for (i = 0; i < length; i++) {
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	hash &= (g_num_waitqs - 1);
	return hash;
}

/* return a global waitq pointer corresponding to the given event */
struct waitq *_global_eventq(char *event, size_t event_length)
{
	return &global_waitqs[waitq_hash(event, event_length)];
}

/* return an indexed global waitq pointer */
struct waitq *global_waitq(int index)
{
	return &global_waitqs[index % g_num_waitqs];
}


#if CONFIG_WAITQ_STATS
/* this global is for lldb */
const uint32_t g_nwaitq_btframes = NWAITQ_BTFRAMES;
struct wq_stats g_boot_stats;
struct wq_stats *g_waitq_stats = &g_boot_stats;

static __inline__ void waitq_grab_backtrace(uintptr_t bt[NWAITQ_BTFRAMES], int skip)
{
	uintptr_t buf[NWAITQ_BTFRAMES + skip];
	if (skip < 0)
		skip = 0;
	memset(buf, 0, (NWAITQ_BTFRAMES + skip) * sizeof(uintptr_t));
	fastbacktrace(buf, g_nwaitq_btframes + skip);
	memcpy(&bt[0], &buf[skip], NWAITQ_BTFRAMES * sizeof(uintptr_t));
}

static __inline__ struct wq_stats *waitq_global_stats(struct waitq *waitq) {
	struct wq_stats *wqs;
	uint32_t idx;

	if (!waitq_is_global(waitq))
		return NULL;

	idx = (uint32_t)(((uintptr_t)waitq - (uintptr_t)global_waitqs) / sizeof(*waitq));
	assert(idx < g_num_waitqs);
	wqs = &g_waitq_stats[idx];
	return wqs;
}

static __inline__ void waitq_stats_count_wait(struct waitq *waitq)
{
	struct wq_stats *wqs = waitq_global_stats(waitq);
	if (wqs != NULL) {
		wqs->waits++;
		waitq_grab_backtrace(wqs->last_wait, 2);
	}
}

static __inline__ void waitq_stats_count_wakeup(struct waitq *waitq)
{
	struct wq_stats *wqs = waitq_global_stats(waitq);
	if (wqs != NULL) {
		wqs->wakeups++;
		waitq_grab_backtrace(wqs->last_wakeup, 2);
	}
}

static __inline__ void waitq_stats_count_clear_wakeup(struct waitq *waitq)
{
	struct wq_stats *wqs = waitq_global_stats(waitq);
	if (wqs != NULL) {
		wqs->wakeups++;
		wqs->clears++;
		waitq_grab_backtrace(wqs->last_wakeup, 2);
	}
}

static __inline__ void waitq_stats_count_fail(struct waitq *waitq)
{
	struct wq_stats *wqs = waitq_global_stats(waitq);
	if (wqs != NULL) {
		wqs->failed_wakeups++;
		waitq_grab_backtrace(wqs->last_failed_wakeup, 2);
	}
}
#else
#define waitq_stats_count_wait(q)         do { } while (0)
#define waitq_stats_count_wakeup(q)       do { } while (0)
#define waitq_stats_count_clear_wakeup(q) do { } while (0)
#define waitq_stats_count_fail(q)         do { } while (0)
#endif

int waitq_is_valid(struct waitq *waitq)
{
	return (waitq != NULL) && ((waitq->waitq_type & ~1) == WQT_QUEUE);
}

int waitq_set_is_valid(struct waitq_set *wqset)
{
	return (wqset != NULL) && waitqs_is_set(wqset);
}

int waitq_is_global(struct waitq *waitq)
{
	if (waitq >= global_waitqs && waitq < global_waitqs + g_num_waitqs)
		return 1;
	return 0;
}

int waitq_irq_safe(struct waitq *waitq)
{
	/* global wait queues have this bit set on initialization */
	return waitq->waitq_irq;
}

static uint32_t waitq_hash_size(void)
{
	uint32_t hsize, queues;
	
	if (PE_parse_boot_argn("wqsize", &hsize, sizeof(hsize)))
		return (hsize);

	queues = thread_max / 11;
	hsize = P2ROUNDUP(queues * sizeof(struct waitq), PAGE_SIZE);

	return hsize;
}

void waitq_bootstrap(void)
{
	kern_return_t kret;
	uint32_t whsize, qsz;

	wq_table_bootstrap();
	lt_init();
	wqp_init();

	/*
	 * Determine the amount of memory we're willing to reserve for
	 * the waitqueue hash table
	 */
	whsize = waitq_hash_size();

	/* Determine the number of waitqueues we can fit. */
	qsz = sizeof(struct waitq);
	whsize = ROUNDDOWN(whsize, qsz);
	g_num_waitqs = whsize / qsz;

	/*
	 * The hash algorithm requires that this be a power of 2, so we
	 * just mask off all the low-order bits.
	 */
	for (uint32_t i = 0; i < 31; i++) {
		uint32_t bit = (1 << i);
		if ((g_num_waitqs & bit) == g_num_waitqs)
			break;
		g_num_waitqs &= ~bit;
	}
	assert(g_num_waitqs > 0);

	/* Now determine how much memory we really need. */
	whsize = P2ROUNDUP(g_num_waitqs * qsz, PAGE_SIZE);

	wqdbg("allocating %d global queues  (%d bytes)", g_num_waitqs, whsize);
	kret = kernel_memory_allocate(kernel_map, (vm_offset_t *)&global_waitqs,
				      whsize, 0, KMA_KOBJECT|KMA_NOPAGEWAIT, VM_KERN_MEMORY_WAITQ);
	if (kret != KERN_SUCCESS || global_waitqs == NULL)
		panic("kernel_memory_allocate() failed to alloc global_waitqs"
		      ", error: %d, whsize: 0x%x", kret, whsize);

#if CONFIG_WAITQ_STATS
	whsize = P2ROUNDUP(g_num_waitqs * sizeof(struct wq_stats), PAGE_SIZE);
	kret = kernel_memory_allocate(kernel_map, (vm_offset_t *)&g_waitq_stats,
				      whsize, 0, KMA_KOBJECT|KMA_NOPAGEWAIT, VM_KERN_MEMORY_WAITQ);
	if (kret != KERN_SUCCESS || global_waitqs == NULL)
		panic("kernel_memory_allocate() failed to alloc g_waitq_stats"
		      ", error: %d, whsize: 0x%x", kret, whsize);
	memset(g_waitq_stats, 0, whsize);
#endif

	for (uint32_t i = 0; i < g_num_waitqs; i++) {
		waitq_init(&global_waitqs[i], SYNC_POLICY_FIFO|SYNC_POLICY_DISABLE_IRQ);
	}


	waitq_set_zone = zinit(sizeof(struct waitq_set),
			       WAITQ_SET_MAX * sizeof(struct waitq_set),
			       sizeof(struct waitq_set),
			       "waitq sets");
	zone_change(waitq_set_zone, Z_NOENCRYPT, TRUE);
}


/* ----------------------------------------------------------------------
 *
 * Wait Queue Implementation
 *
 * ---------------------------------------------------------------------- */

/*
 * Double the standard lock timeout, because wait queues tend
 * to iterate over a number of threads - locking each.  If there is
 * a problem with a thread lock, it normally times out at the wait
 * queue level first, hiding the real problem.
 */
/* For x86, the hardware timeout is in TSC units. */
#if defined(__i386__) || defined(__x86_64__)
#define	hwLockTimeOut LockTimeOutTSC
#else
#define	hwLockTimeOut LockTimeOut
#endif

void waitq_lock(struct waitq *wq)
{
	if (__improbable(hw_lock_to(&(wq)->waitq_interlock,
				    hwLockTimeOut * 2) == 0)) {
		boolean_t wql_acquired = FALSE;

		while (machine_timeout_suspended()) {
#if defined(__i386__) || defined(__x86_64__)
			/*
			 * i386/x86_64 return with preemption disabled on a
			 * timeout for diagnostic purposes.
			 */
			mp_enable_preemption();
#endif
			wql_acquired = hw_lock_to(&(wq)->waitq_interlock,
						  hwLockTimeOut * 2);
			if (wql_acquired)
				break;
		}
		if (wql_acquired == FALSE)
			panic("waitq deadlock - waitq=%p, cpu=%d\n",
			      wq, cpu_number());
	}
	assert(waitq_held(wq));
}

void waitq_unlock(struct waitq *wq)
{
	assert(waitq_held(wq));
	hw_lock_unlock(&(wq)->waitq_interlock);
}


/**
 * clear the thread-related waitq state
 *
 * Conditions:
 *	'thread' is locked
 */
static inline void thread_clear_waitq_state(thread_t thread)
{
	thread->waitq = NULL;
	thread->wait_event = NO_EVENT64;
	thread->at_safe_point = FALSE;
}


typedef thread_t (*waitq_select_cb)(void *ctx, struct waitq *waitq,
				    int is_global, thread_t thread);

struct waitq_select_args {
	/* input parameters */
	struct waitq    *posted_waitq;
	struct waitq    *waitq;
	event64_t        event;
	waitq_select_cb  select_cb;
	void            *select_ctx;

	uint64_t        *reserved_preposts;

	/* output parameters */
	queue_t       threadq;
	int           max_threads;
	int          *nthreads;
	spl_t        *spl;
};

static void do_waitq_select_n_locked(struct waitq_select_args *args);

/**
 * callback invoked once for every waitq set to which a waitq belongs
 *
 * Conditions:
 *	ctx->posted_waitq is locked
 *	'link' points to a valid waitq set
 *
 * Notes:
 *	Takes the waitq set lock on the set pointed to by 'link'
 *	Calls do_waitq_select_n_locked() which could recurse back into
 *	this function if the waitq set is a member of other sets.
 *	If no threads were selected, it preposts the input waitq
 *	onto the waitq set pointed to by 'link'.
 */
static int waitq_select_walk_cb(struct waitq *waitq, void *ctx,
				struct setid_link *link)
{
	int ret = WQ_ITERATE_CONTINUE;
	struct waitq_select_args args = *((struct waitq_select_args *)ctx);
	struct waitq_set *wqset;
	int get_spl = 0;
	spl_t set_spl;

	(void)waitq;
	assert(sl_type(link) == SLT_WQS);

	wqset = link->sl_wqs.sl_set;
	args.waitq = &wqset->wqset_q;

	if (!waitq_irq_safe(waitq) && waitq_irq_safe(&wqset->wqset_q)) {
		get_spl = 1;
		set_spl = splsched();
	}
	waitq_set_lock(wqset);
	/*
	 * verify that the link wasn't invalidated just before
	 * we were able to take the lock.
	 */
	if (wqset->wqset_id != link->sl_set_id.id)
		goto out_unlock;

	/*
	 * Find any threads waiting on this wait queue set,
	 * and recurse into any waitq set to which this set belongs.
	 */
	do_waitq_select_n_locked(&args);

	if (*(args.nthreads) > 0 ||
	    (args.threadq && !queue_empty(args.threadq))) {
		/* at least 1 thread was selected and returned: don't prepost */
		if (args.max_threads > 0 &&
		    *(args.nthreads) >= args.max_threads) {
			/* break out of the setid walk */
			ret = WQ_ITERATE_FOUND;
		}
		goto out_unlock;
	} else {
		/*
		 * No thread selected: prepost 'waitq' to 'wqset'
		 * if wqset can handle preposts and the event is set to 0.
		 * We also make sure to not post waitq sets to other sets.
		 *
		 * In the future, we may consider an optimization to prepost
		 * 'args.posted_waitq' directly to 'wqset' to avoid
		 * unnecessary data structure manipulations in the kqueue path
		 */
		if (args.event == NO_EVENT64 && waitq_set_can_prepost(wqset)) {
			wq_prepost_do_post_locked(wqset, waitq,
						  args.reserved_preposts);
		}
	}

out_unlock:
	waitq_set_unlock(wqset);
	if (get_spl)
		splx(set_spl);
	return ret;
}

/**
 * generic thread selection from a waitq (and sets to which the waitq belongs)
 *
 * Conditions:
 *	args->waitq (and args->posted_waitq) is locked
 *
 * Notes:
 *	Uses the optional select callback function to refine the selection
 *	of one or more threads from a waitq and any set to which the waitq
 *	belongs. The select callback is invoked once for every thread that
 *	is found to be waiting on the input args->waitq.
 *
 *	If one or more threads are selected, this may disable interrupts.
 *	The previous interrupt state is returned in args->spl and should
 *	be used in a call to splx() if threads are returned to the caller.
 */
static void do_waitq_select_n_locked(struct waitq_select_args *args)
{
	struct waitq *waitq = args->waitq;
	int max_threads = args->max_threads;
	thread_t thread = THREAD_NULL, first_thread = THREAD_NULL;
	int global_q = 0;
	unsigned long eventmask = 0;
	int *nthreads = args->nthreads;

	assert(max_threads != 0);

	global_q = waitq_is_global(waitq);
	if (global_q) {
		eventmask = _CAST_TO_EVENT_MASK(args->event);
		/* make sure this waitq accepts this event mask */
		if ((waitq->waitq_eventmask & eventmask) != eventmask)
			return;
		eventmask = 0;
	}

	/* look through each thread waiting directly on the waitq */
	qe_foreach_element_safe(thread, &waitq->waitq_queue, links) {
		thread_t t = THREAD_NULL;
		assert(thread->waitq == waitq);
		if (thread->wait_event == args->event) {
			t = thread;
			if (first_thread == THREAD_NULL)
				first_thread = thread;

			/* allow the caller to futher refine the selection */
			if (args->select_cb)
				t = args->select_cb(args->select_ctx, waitq,
						    global_q, thread);
			if (t != THREAD_NULL) {
				*nthreads += 1;
				if (args->threadq) {
					if (*nthreads == 1)
						*(args->spl) = splsched();
					thread_lock(t);
					thread_clear_waitq_state(t);
					/* put locked thread on output queue */
					re_queue_tail(args->threadq, &t->links);
				}
				/* only enqueue up to 'max' threads */
				if (*nthreads >= max_threads && max_threads > 0)
					break;
			}
		}
		/* thread wasn't selected, and the waitq is global */
		if (t == THREAD_NULL && global_q)
			eventmask |= _CAST_TO_EVENT_MASK(thread->wait_event);
	}

	/*
	 * Update the eventmask of global queues:
	 * - If we selected all the threads in the queue, or we selected zero
	 *   threads on the queue, set the eventmask to the calculated value
	 *   (potentially 0 if we selected them all)
	 * - If we just pulled out a subset of threads from the queue, then we
	 *   can't assume the calculated mask is complete (because we may not
	 *   have made it through all the threads in the queue), so we have to
	 *   leave it alone.
	 */
	if (global_q && (queue_empty(&waitq->waitq_queue) || *nthreads == 0))
		waitq->waitq_eventmask = (typeof(waitq->waitq_eventmask))eventmask;

	/*
	 * Grab the first thread in the queue if no other thread was selected.
	 * We can guarantee that no one has manipulated this thread because
	 * it's waiting on the given waitq, and we have that waitq locked.
	 */
	if (*nthreads == 0 && first_thread != THREAD_NULL && args->threadq) {
		/* we know this is the first (and only) thread */
		++(*nthreads);
		*(args->spl) = splsched();
		thread_lock(first_thread);
		thread_clear_waitq_state(first_thread);
		re_queue_tail(args->threadq, &first_thread->links);

		/* update the eventmask on global queues */
		if (global_q && queue_empty(&waitq->waitq_queue))
			waitq->waitq_eventmask = 0;
	}

	if (max_threads > 0 && *nthreads >= max_threads)
		return;

	/*
	 * wait queues that are not in any sets
	 * are the bottom of the recursion
	 */
	if (!waitq->waitq_set_id)
		return;

	/* check to see if the set ID for this wait queue is valid */
	struct setid_link *link = lt_get_link(waitq->waitq_set_id);
	if (!link) {
		/* the waitq set to which this waitq belonged, has been invalidated */
		waitq->waitq_set_id = 0;
		return;
	}

	lt_put_link(link);

	/*
	 * If this waitq is a member of any wait queue sets, we need to look
	 * for waiting thread(s) in any of those sets, and prepost all sets that
	 * don't have active waiters.
	 *
	 * Note that we do a local walk of this waitq's links - we manually
	 * recurse down wait queue set's with non-zero wqset_q.waitq_set_id
	 */
	(void)walk_setid_links(LINK_WALK_ONE_LEVEL, waitq, waitq->waitq_set_id,
			       SLT_WQS, (void *)args, waitq_select_walk_cb);
}

/**
 * main entry point for thread selection from a waitq
 *
 * Conditions:
 *	waitq is locked
 *
 * Returns:
 *	The number of threads waiting on 'waitq' for 'event' which have
 *	been placed onto the input 'threadq'
 *
 * Notes:
 *	The 'select_cb' function is invoked for every thread found waiting
 *	on 'waitq' for 'event'. The thread is _not_ locked upon callback
 *	invocation. This parameter may be NULL.
 *
 *	If one or more threads are returned in 'threadq' then the caller is
 *	responsible to call splx() using the returned 'spl' value. Each
 *	returned thread is locked.
 */
static __inline__ int waitq_select_n_locked(struct waitq *waitq,
					    event64_t event,
					    waitq_select_cb select_cb,
					    void *select_ctx,
					    uint64_t *reserved_preposts,
					    queue_t threadq,
					    int max_threads, spl_t *spl)
{
	int nthreads = 0;

	struct waitq_select_args args = {
		.posted_waitq = waitq,
		.waitq = waitq,
		.event = event,
		.select_cb = select_cb,
		.select_ctx = select_ctx,
		.reserved_preposts = reserved_preposts,
		.threadq = threadq,
		.max_threads = max_threads,
		.nthreads = &nthreads,
		.spl = spl,
	};

	do_waitq_select_n_locked(&args);
	return nthreads;
}


/**
 * callback function that uses thread parameters to determine wakeup eligibility
 *
 * Conditions:
 *	'waitq' is locked
 *	'thread' is not locked
 */
static thread_t waitq_select_one_cb(void *ctx, struct waitq *waitq,
				    int is_global, thread_t thread)
{
	int fifo_q, realtime;
	boolean_t thread_imp_donor = FALSE;

	(void)ctx;
	(void)waitq;
	(void)is_global;
	realtime = 0;

	fifo_q = 1; /* default to FIFO for all queues for now */
#if IMPORTANCE_INHERITANCE
	if (is_global)
		fifo_q = 0; /* 'thread_imp_donor' takes the place of FIFO checking */
#endif

	if (thread->sched_pri >= BASEPRI_REALTIME)
		realtime = 1;

#if IMPORTANCE_INHERITANCE
	/* 
	 * Checking imp donor bit does not need thread lock or
	 * or task lock since we have the wait queue lock and
	 * thread can not be removed from it without acquiring
	 * wait queue lock. The imp donor bit may change
	 * once we read its value, but it is ok to wake
	 * a thread while someone drops importance assertion
	 * on the that thread.
	 */
	thread_imp_donor = task_is_importance_donor(thread->task);
#endif /* IMPORTANCE_INHERITANCE */

	if (fifo_q || thread_imp_donor == TRUE
	    || realtime || (thread->options & TH_OPT_VMPRIV)) {
		/*
		 * If this thread's task is an importance donor,
		 * or it's a realtime thread, or it's a VM privileged
		 * thread, OR the queue is marked as FIFO:
		 *     select the thread
		 */
		return thread;
	}

	/* by default, _don't_ select the thread */
	return THREAD_NULL;
}

/**
 * select a single thread from a waitq that's waiting for a given event
 *
 * Conditions:
 *	'waitq' is locked
 *
 * Returns:
 *	A locked thread that's been removed from the waitq, but has not
 *	yet been put on a run queue. Caller is responsible to call splx
 *	with the '*spl' value.
 */
static thread_t waitq_select_one_locked(struct waitq *waitq, event64_t event,
					uint64_t *reserved_preposts,
					int priority, spl_t *spl)
{
	int nthreads;
	queue_head_t threadq;

	(void)priority;

	queue_init(&threadq);

	nthreads = waitq_select_n_locked(waitq, event, waitq_select_one_cb, NULL,
					 reserved_preposts, &threadq, 1, spl);

	/* if we selected a thread, return it (still locked) */
	if (!queue_empty(&threadq)) {
		thread_t t;
		queue_entry_t qe = dequeue_head(&threadq);
		t = qe_element(qe, struct thread, links);
		assert(queue_empty(&threadq)); /* there should be 1 entry */
		/* t has been locked and removed from all queues */
		return t;
	}

	return THREAD_NULL;
}


struct select_thread_ctx {
	thread_t      thread;
	event64_t     event;
	spl_t        *spl;
};

/**
 * link walk callback invoked once for each set to which a waitq belongs
 *
 * Conditions:
 *	initial waitq is locked
 *	ctx->thread is unlocked
 *
 * Notes:
 *	This may disable interrupts and early-out of the full DAG link walk by
 *	returning KERN_ALREADY_IN_SET. In this case, the returned thread has
 *	been removed from the waitq, it's waitq state has been reset, and the
 *	caller is responsible to call splx() with the returned interrupt state
 *	in ctx->spl.
 */
static int waitq_select_thread_cb(struct waitq *waitq, void *ctx,
				  struct setid_link *link)
{
	struct select_thread_ctx *stctx = (struct select_thread_ctx *)ctx;
	struct waitq_set *wqset;

	(void)waitq;

	thread_t thread = stctx->thread;
	event64_t event = stctx->event;

	if (sl_type(link) != SLT_WQS)
		return WQ_ITERATE_CONTINUE;

	wqset = link->sl_wqs.sl_set;

	if (!waitq_irq_safe(waitq) && waitq_irq_safe(&wqset->wqset_q)) {
		*(stctx->spl) = splsched();
		waitq_set_lock(wqset);
		thread_lock(thread);
	} else {
		waitq_set_lock(wqset);
		*(stctx->spl) = splsched();
		thread_lock(thread);
	}

	if ((thread->waitq == &wqset->wqset_q)
	    && (thread->wait_event == event)) {
		remqueue(&thread->links);
		thread_clear_waitq_state(thread);
		/*
		 * thread still locked,
		 * return non-zero to break out of WQS walk
		 */
		waitq_set_unlock(wqset);
		return WQ_ITERATE_FOUND;
	}

	thread_unlock(thread);
	waitq_set_unlock(wqset);
	splx(*(stctx->spl));

	return WQ_ITERATE_CONTINUE;
}

/**
 * returns KERN_SUCCESS and locks 'thread' if-and-only-if 'thread' is waiting
 * on 'waitq' (or any set to which waitq belongs) for 'event'
 *
 * Conditions:
 *	'waitq' is locked
 *	'thread' is unlocked
 */
static kern_return_t waitq_select_thread_locked(struct waitq *waitq,
						event64_t event,
						thread_t thread, spl_t *spl)
{
	struct setid_link *link;
	struct select_thread_ctx ctx;
	kern_return_t kr;

	*spl = splsched();
	thread_lock(thread);

	if ((thread->waitq == waitq) && (thread->wait_event == event)) {
		remqueue(&thread->links);
		thread_clear_waitq_state(thread);
		/* thread still locked */
		return KERN_SUCCESS;
	}

	thread_unlock(thread);
	splx(*spl);

	if (!waitq->waitq_set_id)
		return KERN_NOT_WAITING;

	/* check to see if the set ID for this wait queue is valid */
	link = lt_get_link(waitq->waitq_set_id);
	if (!link) {
		/* the waitq to which this set belonged, has been invalidated */
		waitq->waitq_set_id = 0;
		return KERN_NOT_WAITING;
	}

	/*
	 * The thread may be waiting on a wait queue set to which
	 * the input 'waitq' belongs. Go look for the thread in
	 * all wait queue sets. If it's there, we'll remove it
	 * because it's equivalent to waiting directly on the input waitq.
	 */
	ctx.thread = thread;
	ctx.event = event;
	ctx.spl = spl;
	kr = walk_setid_links(LINK_WALK_FULL_DAG, waitq, waitq->waitq_set_id,
			      SLT_WQS, (void *)&ctx, waitq_select_thread_cb);

	lt_put_link(link);

	/* we found a thread, return success */
	if (kr == WQ_ITERATE_FOUND)
		return KERN_SUCCESS;

	return KERN_NOT_WAITING;
}

static int prepost_exists_cb(struct waitq_set __unused *wqset,
			     void __unused *ctx,
			     struct wq_prepost __unused *wqp,
			     struct waitq __unused *waitq)
{
	/* if we get here, then we know that there is a valid prepost object! */
	return WQ_ITERATE_FOUND;
}

/**
 * declare a thread's intent to wait on 'waitq' for 'wait_event'
 *
 * Conditions:
 *	'waitq' is locked
 *	'thread' is locked
 */
wait_result_t waitq_assert_wait64_locked(struct waitq *waitq,
					  event64_t wait_event,
					  wait_interrupt_t interruptible,
					  wait_timeout_urgency_t urgency,
					  uint64_t deadline,
					  uint64_t leeway,
					  thread_t thread)
{
	wait_result_t wait_result;
	int realtime = 0;

	/*
	 * Warning: Do _not_ place debugging print statements here.
	 *          The thread is locked!
	 */

	if (thread->waitq != NULL)
		panic("thread already waiting on %p", thread->waitq);

	if (waitq_is_set(waitq)) {
		struct waitq_set *wqset = (struct waitq_set *)waitq;
		/*
		 * early-out if the thread is waiting on a wait queue set
		 * that has already been pre-posted.
		 */
		if (wait_event == NO_EVENT64 && waitq_set_maybe_preposted(wqset)) {
			int ret;
			/*
			 * Run through the list of potential preposts. Because
			 * this is a hot path, we short-circuit the iteration
			 * if we find just one prepost object.
			 */
			ret = wq_prepost_foreach_locked(wqset, NULL,
							prepost_exists_cb);
			if (ret == WQ_ITERATE_FOUND) {
				thread->wait_result = THREAD_AWAKENED;
				return THREAD_AWAKENED;
			}
		}
	}

	/*
	 * Realtime threads get priority for wait queue placements.
	 * This allows wait_queue_wakeup_one to prefer a waiting
	 * realtime thread, similar in principle to performing
	 * a wait_queue_wakeup_all and allowing scheduler prioritization
	 * to run the realtime thread, but without causing the
	 * lock contention of that scenario.
	 */
	if (thread->sched_pri >= BASEPRI_REALTIME)
		realtime = 1;

	/*
	 * This is the extent to which we currently take scheduling attributes
	 * into account.  If the thread is vm priviledged, we stick it at
	 * the front of the queue.  Later, these queues will honor the policy
	 * value set at waitq_init time.
	 */
	wait_result = thread_mark_wait_locked(thread, interruptible);
	/* thread->wait_result has been set */
	if (wait_result == THREAD_WAITING) {
		if (!waitq->waitq_fifo
		    || (thread->options & TH_OPT_VMPRIV) || realtime)
			enqueue_head(&waitq->waitq_queue, &thread->links);
		else
			enqueue_tail(&waitq->waitq_queue, &thread->links);

		thread->wait_event = wait_event;
		thread->waitq = waitq;

		if (deadline != 0) {
			boolean_t act;
			act = timer_call_enter_with_leeway(&thread->wait_timer,
							   NULL,
							   deadline, leeway,
							   urgency, FALSE);
			if (!act)
				thread->wait_timer_active++;
			thread->wait_timer_is_set = TRUE;
		}

		if (waitq_is_global(waitq))
			waitq->waitq_eventmask = waitq->waitq_eventmask
						| _CAST_TO_EVENT_MASK(wait_event);

		waitq_stats_count_wait(waitq);
	}

	return wait_result;
}

/**
 * remove 'thread' from its current blocking state on 'waitq'
 *
 * Conditions:
 *	'waitq' is locked
 *	'thread' is locked
 *
 * Notes:
 *	This function is primarily used by clear_wait_internal in
 *	sched_prim.c from the thread timer wakeup path
 *	(i.e. the thread was waiting on 'waitq' with a timeout that expired)
 */
void waitq_pull_thread_locked(struct waitq *waitq, thread_t thread)
{
	(void)waitq;
	assert(thread->waitq == waitq);

	remqueue(&thread->links);
	thread_clear_waitq_state(thread);
	waitq_stats_count_clear_wakeup(waitq);

	/* clear the global event mask if this was the last thread there! */
	if (waitq_is_global(waitq) && queue_empty(&waitq->waitq_queue))
		waitq->waitq_eventmask = 0;
}


static __inline__
void maybe_adjust_thread_pri(thread_t thread, int priority) {
	if (thread->sched_pri < priority) {
		if (priority <= MAXPRI) {
			set_sched_pri(thread, priority);

			thread->was_promoted_on_wakeup = 1;
			thread->sched_flags |= TH_SFLAG_PROMOTED;
		}
		return;
	}

	/*
	 * If the caller is requesting the waitq subsystem to promote the
	 * priority of the awoken thread, then boost the thread's priority to
	 * the default WAITQ_BOOST_PRIORITY (if it's not already equal or
	 * higher priority).  This boost must be removed via a call to
	 * waitq_clear_promotion_locked.
	 */
	if (priority == WAITQ_PROMOTE_PRIORITY &&
	    (thread->sched_pri < WAITQ_BOOST_PRIORITY ||
	     !(thread->sched_flags & TH_SFLAG_WAITQ_PROMOTED))) {

		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAITQ_PROMOTE) | DBG_FUNC_NONE,
				      (uintptr_t)thread_tid(thread),
				      thread->sched_pri, thread->base_pri,
				      WAITQ_BOOST_PRIORITY, 0);
		thread->sched_flags |= TH_SFLAG_WAITQ_PROMOTED;
		if (thread->sched_pri < WAITQ_BOOST_PRIORITY)
			set_sched_pri(thread, WAITQ_BOOST_PRIORITY);
	}
}

/**
 * Clear a thread's waitq priority promotion state and the waitq's boost flag
 *
 * This function will always clear the waitq's 'waitq_boost' flag. If the
 * 'thread' parameter is non-null, the this function will also check the
 * priority promotion (boost) state of that thread. If this thread was boosted
 * (by having been awoken from a boosting waitq), then this boost state is
 * cleared. This function is to be paired with waitq_enable_promote_locked.
 */
void waitq_clear_promotion_locked(struct waitq *waitq, thread_t thread)
{
	spl_t s;

	assert(waitq_held(waitq));
	if (thread == THREAD_NULL)
		return;

	if (!waitq_irq_safe(waitq))
		s = splsched();
	thread_lock(thread);

	if (thread->sched_flags & TH_SFLAG_WAITQ_PROMOTED) {
		thread->sched_flags &= ~TH_SFLAG_WAITQ_PROMOTED;

		if (thread->sched_flags & TH_SFLAG_PROMOTED_MASK) {
			/* it still has other promotions (mutex/rw_lock) */
		} else if (thread->sched_flags & TH_SFLAG_DEPRESSED_MASK) {
			KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAITQ_DEMOTE) | DBG_FUNC_NONE,
					      (uintptr_t)thread_tid(thread),
					      thread->sched_pri,
					      thread->base_pri,
					      DEPRESSPRI, 0);
			set_sched_pri(thread, DEPRESSPRI);
		} else {
			KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAITQ_DEMOTE) | DBG_FUNC_NONE,
					      (uintptr_t)thread_tid(thread),
					      thread->sched_pri,
					      thread->base_pri,
					      thread->base_pri, 0);
			thread_recompute_sched_pri(thread, FALSE);
		}
	}

	thread_unlock(thread);
	if (!waitq_irq_safe(waitq))
		splx(s);
}

/**
 * wakeup all threads waiting on 'waitq' for 'wake_event'
 *
 * Conditions:
 *	'waitq' is locked
 *
 * Notes:
 *	May temporarily disable and re-enable interrupts
 *	and re-adjust thread priority of each awoken thread.
 *
 *	If the input 'lock_state' == WAITQ_UNLOCK then the waitq will have
 *	been unlocked before calling thread_go() on any returned threads, and
 *	is guaranteed to be unlocked upon function return.
 */
kern_return_t waitq_wakeup64_all_locked(struct waitq *waitq,
					event64_t wake_event,
					wait_result_t result,
					uint64_t *reserved_preposts,
					int priority,
					waitq_lock_state_t lock_state)
{
	kern_return_t ret;
	thread_t thread;
	spl_t th_spl;
	int nthreads;
	queue_head_t wakeup_queue;

	assert(waitq_held(waitq));
	queue_init(&wakeup_queue);

	nthreads = waitq_select_n_locked(waitq, wake_event, NULL, NULL,
					 reserved_preposts,
					 &wakeup_queue, -1, &th_spl);

	/* set each thread running */
	ret = KERN_NOT_WAITING;

#if CONFIG_WAITQ_STATS
	qe_foreach_element(thread, &wakeup_queue, links)
		waitq_stats_count_wakeup(waitq);
#endif
	if (lock_state == WAITQ_UNLOCK)
		waitq_unlock(waitq);

	qe_foreach_element_safe(thread, &wakeup_queue, links) {
		remqueue(&thread->links);
		maybe_adjust_thread_pri(thread, priority);
		ret = thread_go(thread, result);
		assert(ret == KERN_SUCCESS);
		thread_unlock(thread);
	}
	if (nthreads > 0)
		splx(th_spl);
	else
		waitq_stats_count_fail(waitq);

	return ret;
}

/**
 * wakeup one thread waiting on 'waitq' for 'wake_event'
 *
 * Conditions:
 *	'waitq' is locked
 *
 * Notes:
 *	May temporarily disable and re-enable interrupts.
 */
kern_return_t waitq_wakeup64_one_locked(struct waitq *waitq,
					event64_t wake_event,
					wait_result_t result,
					uint64_t *reserved_preposts,
					int priority,
					waitq_lock_state_t lock_state)
{
	thread_t thread;
	spl_t th_spl;

	assert(waitq_held(waitq));

	thread = waitq_select_one_locked(waitq, wake_event,
					 reserved_preposts,
					 priority, &th_spl);

	if (thread != THREAD_NULL)
		waitq_stats_count_wakeup(waitq);
	else
		waitq_stats_count_fail(waitq);

	if (lock_state == WAITQ_UNLOCK)
		waitq_unlock(waitq);

	if (thread != THREAD_NULL) {
		maybe_adjust_thread_pri(thread, priority);
		kern_return_t ret = thread_go(thread, result);
		assert(ret == KERN_SUCCESS);
		thread_unlock(thread);
		splx(th_spl);
		return ret;
	}

	return KERN_NOT_WAITING;
}

/**
 * wakeup one thread waiting on 'waitq' for 'wake_event'
 *
 * Conditions:
 *	'waitq' is locked
 *
 * Returns:
 *	A locked, runnable thread.
 *	If return value is non-NULL, interrupts have also
 *	been disabled, and the caller is responsible to call
 *	splx() with the returned '*spl' value.
 */
thread_t waitq_wakeup64_identity_locked(struct waitq *waitq,
					event64_t wake_event,
					wait_result_t result,
					spl_t *spl,
					uint64_t *reserved_preposts,
					waitq_lock_state_t lock_state)
{
	thread_t thread;

	assert(waitq_held(waitq));

	thread = waitq_select_one_locked(waitq, wake_event,
					 reserved_preposts,
					 WAITQ_ALL_PRIORITIES, spl);

	if (thread != THREAD_NULL)
		waitq_stats_count_wakeup(waitq);
	else
		waitq_stats_count_fail(waitq);

	if (lock_state == WAITQ_UNLOCK)
		waitq_unlock(waitq);

	if (thread != THREAD_NULL) {
		kern_return_t __assert_only ret;
		ret = thread_go(thread, result);
		assert(ret == KERN_SUCCESS);
	}

	return thread; /* locked if not NULL (caller responsible for spl) */
}

/**
 * wakeup a specific thread iff it's waiting on 'waitq' for 'wake_event'
 *
 * Conditions:
 *	'waitq' is locked
 *	'thread' is unlocked
 *
 * Notes:
 *	May temporarily disable and re-enable interrupts
 *
 *	If the input lock_state == WAITQ_UNLOCK then the waitq will have been
 *	unlocked before calling thread_go() if 'thread' is to be awoken, and
 *	is guaranteed to be unlocked upon function return.
 */
kern_return_t waitq_wakeup64_thread_locked(struct waitq *waitq,
					   event64_t wake_event,
					   thread_t thread,
					   wait_result_t result,
					   waitq_lock_state_t lock_state)
{
	kern_return_t ret;
	spl_t th_spl;

	assert(waitq_held(waitq));

	/*
	 * See if the thread was still waiting there.  If so, it got
	 * dequeued and returned locked.
	 */
	ret = waitq_select_thread_locked(waitq, wake_event, thread, &th_spl);

	if (ret == KERN_SUCCESS)
		waitq_stats_count_wakeup(waitq);
	else
		waitq_stats_count_fail(waitq);

	if (lock_state == WAITQ_UNLOCK)
		waitq_unlock(waitq);

	if (ret != KERN_SUCCESS)
		return KERN_NOT_WAITING;

	ret = thread_go(thread, result);
	assert(ret == KERN_SUCCESS);
	thread_unlock(thread);
	splx(th_spl);

	return ret;
}



/* ----------------------------------------------------------------------
 *
 * In-Kernel API
 *
 * ---------------------------------------------------------------------- */

/**
 * initialize a waitq object
 */
kern_return_t waitq_init(struct waitq *waitq, int policy)
{
	assert(waitq != NULL);

	/* only FIFO and LIFO for now */
	if ((policy & SYNC_POLICY_FIXED_PRIORITY) != 0)
		return KERN_INVALID_ARGUMENT;

	waitq->waitq_fifo = ((policy & SYNC_POLICY_REVERSED) == 0);
	waitq->waitq_irq = !!(policy & SYNC_POLICY_DISABLE_IRQ);
	waitq->waitq_prepost = 0;
	waitq->waitq_type = WQT_QUEUE;
	waitq->waitq_eventmask = 0;

	waitq->waitq_set_id = 0;
	waitq->waitq_prepost_id = 0;

	hw_lock_init(&waitq->waitq_interlock);
	queue_init(&waitq->waitq_queue);

	return KERN_SUCCESS;
}

struct wq_unlink_ctx {
	struct waitq *unlink_wq;
	struct waitq_set *unlink_wqset;
};

static int waitq_unlink_prepost_cb(struct waitq_set __unused *wqset, void *ctx,
				   struct wq_prepost *wqp, struct waitq *waitq);

/**
 * walk_setid_links callback to invalidate 'link' parameter
 *
 * Conditions:
 *	Called from walk_setid_links.
 *	Note that unlink other callbacks, this one make no assumptions about
 *	the 'waitq' parameter, specifically it does not have to be locked or
 *	even valid.
 */
static int waitq_unlink_all_cb(struct waitq *waitq, void *ctx,
			       struct setid_link *link)
{
	(void)waitq;
	(void)ctx;
	if (sl_type(link) == SLT_LINK && sl_is_valid(link))
		lt_invalidate(link);

	if (sl_type(link) == SLT_WQS) {
		struct waitq_set *wqset;
		int do_spl = 0;
		spl_t spl;
		struct wq_unlink_ctx ulctx;

		/*
		 * When destroying the waitq, take the time to clear out any
		 * preposts it may have made. This could potentially save time
		 * on the IPC send path which would otherwise have to iterate
		 * over lots of dead port preposts.
		 */
		if (waitq->waitq_prepost_id == 0)
			goto out;

		wqset = link->sl_wqs.sl_set;
		assert(wqset != NULL);

		if (waitq_set_is_valid(wqset) &&
		    waitq_irq_safe(&wqset->wqset_q)) {
			spl = splsched();
			do_spl = 1;
		}
		waitq_set_lock(wqset);

		if (!waitq_set_is_valid(wqset)) {
			/* someone raced us to teardown */
			goto out_unlock;
		}
		if (!waitq_set_maybe_preposted(wqset))
			goto out_unlock;

		ulctx.unlink_wq = waitq;
		ulctx.unlink_wqset = wqset;
		(void)wq_prepost_iterate(wqset->wqset_prepost_id, &ulctx,
					 waitq_unlink_prepost_cb);
out_unlock:
		waitq_set_unlock(wqset);
		if (do_spl)
			splx(spl);
	}

out:
	return WQ_ITERATE_CONTINUE;
}


/**
 * cleanup any link/prepost table resources associated with a waitq
 */
void waitq_deinit(struct waitq *waitq)
{
	uint64_t setid = 0;
	spl_t s;

	if (!waitq_valid(waitq))
		return;

	if (waitq_irq_safe(waitq))
		s = splsched();
	waitq_lock(waitq);
	if (!waitq_valid(waitq))
		goto out;

	waitq_unlink_all_locked(waitq, &setid, &s, NULL);
	waitq->waitq_type = WQT_INVALID;
	assert(queue_empty(&waitq->waitq_queue));

out:
	waitq_unlock(waitq);
	if (waitq_irq_safe(waitq))
		splx(s);

	if (setid)
		(void)walk_setid_links(LINK_WALK_ONE_LEVEL, waitq, setid,
				       SLT_ALL, NULL, waitq_unlink_all_cb);
}


/**
 * invalidate the given wq_prepost object
 *
 * Conditions:
 *	Called from wq_prepost_iterate (_not_ from wq_prepost_foreach_locked!)
 */
static int wqset_clear_prepost_chain_cb(struct waitq_set __unused *wqset,
					void __unused *ctx,
					struct wq_prepost *wqp,
					struct waitq __unused *waitq)
{
	if (wqp_type(wqp) == WQP_POST)
		wq_prepost_invalidate(wqp);
	return WQ_ITERATE_CONTINUE;
}


/**
 * allocate and initialize a waitq set object
 *
 * Conditions:
 *	may block
 *
 * Returns:
 *	allocated / initialized waitq_set object
 *	NULL on failure
 */
struct waitq_set *waitq_set_alloc(int policy)
{
	struct waitq_set *wqset;

	wqset = (struct waitq_set *)zalloc(waitq_set_zone);
	if (!wqset)
		panic("Can't allocate a new waitq set from zone %p", waitq_set_zone);

	kern_return_t ret;
	ret = waitq_set_init(wqset, policy, NULL);
	if (ret != KERN_SUCCESS) {
		zfree(waitq_set_zone, wqset);
		wqset = NULL;
	}

	return wqset;
}

/**
 * initialize a waitq set object
 *
 * Conditions:
 *	may (rarely) block if link table needs to grow, and
 *	no 'reserved_link' object is passed.
 */
kern_return_t waitq_set_init(struct waitq_set *wqset,
			     int policy, uint64_t *reserved_link)
{
	struct setid_link *link;
	kern_return_t ret;

	memset(wqset, 0, sizeof(*wqset));

	ret = waitq_init(&wqset->wqset_q, policy);
	if (ret != KERN_SUCCESS)
		return ret;

	wqset->wqset_q.waitq_type = WQT_SET;
	if (policy & SYNC_POLICY_PREPOST)
		wqset->wqset_q.waitq_prepost = 1;
	else
		wqset->wqset_q.waitq_prepost = 0;

	if (reserved_link && *reserved_link != 0) {
		link = lt_get_reserved(*reserved_link, SLT_WQS);
		/* always consume the caller's reference */
		*reserved_link = 0;
	} else {
		link = lt_alloc_link(SLT_WQS);
	}
	if (!link)
		panic("Can't allocate link object for waitq set: %p", wqset);

	link->sl_wqs.sl_set = wqset;
	sl_set_valid(link);

	wqset->wqset_id = link->sl_set_id.id;
	wqset->wqset_prepost_id = 0;
	lt_put_link(link);

	return KERN_SUCCESS;
}

/**
 * clear out / release any resources associated with a waitq set
 *
 * Conditions:
 *	may block
 * Note:
 *	This will render the waitq set invalid, and it must
 *	be re-initialized with waitq_set_init before it can be used again
 */
void waitq_set_deinit(struct waitq_set *wqset)
{
	struct setid_link *link = NULL;
	uint64_t set_id, set_links_id, prepost_id;
	int do_spl = 0;
	spl_t s;

	if (!waitqs_is_set(wqset))
		panic("trying to de-initialize an invalid wqset @%p", wqset);

	if (waitq_irq_safe(&wqset->wqset_q)) {
		s = splsched();
		do_spl = 1;
	}
	waitq_set_lock(wqset);

	set_id = wqset->wqset_id;

	/* grab the set's link object */
	link = lt_get_link(set_id);
	if (link)
		lt_invalidate(link);

	/* someone raced us to deinit */
	if (!link || wqset->wqset_id != set_id || set_id != link->sl_set_id.id) {
		if (link)
			lt_put_link(link);
		waitq_set_unlock(wqset);
		if (do_spl)
			splx(s);
		return;
	}

	/* every wait queue set should have a valid link object */
	assert(link != NULL && sl_type(link) == SLT_WQS);

	wqset->wqset_id = 0;

	wqset->wqset_q.waitq_type = WQT_INVALID;
	wqset->wqset_q.waitq_fifo = 0;
	wqset->wqset_q.waitq_prepost = 0;
	/* don't clear the 'waitq_irq' bit: it's used in locking! */
	wqset->wqset_q.waitq_eventmask = 0;

	/*
	 * This set may have a lot of preposts, or may have been a member of
	 * many other sets. To minimize spinlock hold times, we clear out the
	 * waitq set data structure under the lock-hold, but don't clear any
	 * table objects. We keep handles to the prepost and set linkage
	 * objects and free those outside the critical section.
	 */
	prepost_id = wqset->wqset_prepost_id;
	wqset->wqset_prepost_id = 0;

	set_links_id = 0;
	waitq_unlink_all_locked(&wqset->wqset_q, &set_links_id, &s, NULL);

	waitq_set_unlock(wqset);
	if (do_spl)
		splx(s);

	/*
	 * walk_setid_links may race with us for access to the waitq set.
	 * If walk_setid_links has a reference to the set, then we should wait
	 * until the link's refcount goes to 1 (our reference) before we exit
	 * this function. That way we ensure that the waitq set memory will
	 * remain valid even though it's been cleared out.
	 */
	while (sl_refcnt(link) > 1)
		delay(1);
	lt_put_link(link);

	/*
	 * release all the set link objects
	 * (links to other sets to which this set was previously added)
	 */
	if (set_links_id)
		(void)walk_setid_links(LINK_WALK_ONE_LEVEL, NULL, set_links_id,
				       SLT_ALL, NULL, waitq_unlink_all_cb);

	/* drop / unlink all the prepost table objects */
	(void)wq_prepost_iterate(prepost_id, NULL, wqset_clear_prepost_chain_cb);
}

/**
 * de-initialize and free an allocated waitq set object
 *
 * Conditions:
 *	may block
 */
kern_return_t waitq_set_free(struct waitq_set *wqset)
{
	waitq_set_deinit(wqset);

	memset(wqset, 0, sizeof(*wqset));
	zfree(waitq_set_zone, wqset);

	return KERN_SUCCESS;
}

#if defined(DEVLEOPMENT) || defined(DEBUG)
#if CONFIG_WAITQ_DEBUG
/**
 * return the set ID of 'wqset'
 */
uint64_t wqset_id(struct waitq_set *wqset)
{
	if (!wqset)
		return 0;

	assert(waitqs_is_set(wqset));
	return wqset->wqset_id;
}

/**
 * returns a pointer to the waitq object embedded in 'wqset'
 */
struct waitq *wqset_waitq(struct waitq_set *wqset)
{
	if (!wqset)
		return NULL;

	assert(waitqs_is_set(wqset));

	return &wqset->wqset_q;
}
#endif /* CONFIG_WAITQ_DEBUG */
#endif /* DEVELOPMENT || DEBUG */


/**
 * clear all preposts originating from 'waitq'
 *
 * Conditions:
 *	'waitq' locked
 *	may (rarely) spin waiting for another on-core thread to
 *	release the last reference to the waitq's prepost link object
 *
 * NOTE:
 *	If this function needs to spin, it will drop the waitq lock!
 *	The return value of the function indicates whether or not this
 *	happened: 1 == lock was dropped, 0 == lock held
 */
int waitq_clear_prepost_locked(struct waitq *waitq, spl_t *s)
{
	struct wq_prepost *wqp;
	int dropped_lock = 0;

	if (waitq->waitq_prepost_id == 0)
		return 0;

	wqp = wq_prepost_get(waitq->waitq_prepost_id);
	waitq->waitq_prepost_id = 0;
	if (wqp) {
		uint64_t wqp_id = wqp->wqp_prepostid.id;
		wqdbg_v("invalidate prepost 0x%llx (refcnt:%d)",
			wqp->wqp_prepostid.id, wqp_refcnt(wqp));
		wq_prepost_invalidate(wqp);
		while (wqp_refcnt(wqp) > 1) {
			int do_spl = waitq_irq_safe(waitq);

			/*
			 * Some other thread must have raced us to grab a link
			 * object reference before we invalidated it. This
			 * means that they are probably trying to access the
			 * waitq to which the prepost object points. We need
			 * to wait here until the other thread drops their
			 * reference. We know that no one else can get a
			 * reference (the object has been invalidated), and
			 * that prepost references are short-lived (dropped on
			 * a call to wq_prepost_put). We also know that no one
			 * blocks while holding a reference therefore the
			 * other reference holder must be on-core. We'll just
			 * sit and wait for the other reference to be dropped.
			 */
			disable_preemption();

			waitq_unlock(waitq);
			if (s && do_spl)
				splx(*s);
			dropped_lock = 1;
			/*
			 * don't yield here, just spin and assume the other
			 * consumer is already on core...
			 */
			delay(1);
			if (s && do_spl)
				*s = splsched();
			waitq_lock(waitq);

			enable_preemption();
		}
		if (wqp_refcnt(wqp) > 0 && wqp->wqp_prepostid.id == wqp_id)
			wq_prepost_put(wqp);
	}

	return dropped_lock;
}

/**
 * clear all preposts originating from 'waitq'
 *
 * Conditions:
 *	'waitq' is not locked
 *	may disable and re-enable interrupts
 */
void waitq_clear_prepost(struct waitq *waitq)
{
	spl_t s;
	int do_spl = waitq_irq_safe(waitq);

	assert(waitq_valid(waitq));

	if (do_spl)
		s = splsched();
	waitq_lock(waitq);
	/* it doesn't matter to us if the lock is dropped here */
	(void)waitq_clear_prepost_locked(waitq, &s);
	waitq_unlock(waitq);
	if (do_spl)
		splx(s);
}

/**
 * return a the waitq's prepost object ID (allocate if necessary)
 *
 * Conditions:
 *	'waitq' is unlocked
 */
uint64_t waitq_get_prepost_id(struct waitq *waitq)
{
	struct wq_prepost *wqp;
	uint64_t wqp_id = 0;
	spl_t s;

	if (!waitq_valid(waitq))
		return 0;

	if (waitq_irq_safe(waitq))
		s = splsched();
	waitq_lock(waitq);

	if (!waitq_valid(waitq))
		goto out_unlock;

	if (waitq->waitq_prepost_id) {
		wqp_id = waitq->waitq_prepost_id;
		goto out_unlock;
	}

	/* don't hold a spinlock while allocating a prepost object */
	waitq_unlock(waitq);
	if (waitq_irq_safe(waitq))
		splx(s);

	wqp = wq_prepost_alloc(WQP_WQ, 1);
	if (!wqp)
		return 0;

	/* re-acquire the waitq lock */
	if (waitq_irq_safe(waitq))
		s = splsched();
	waitq_lock(waitq);

	if (!waitq_valid(waitq)) {
		wq_prepost_put(wqp);
		wqp_id = 0;
		goto out_unlock;
	}

	if (waitq->waitq_prepost_id) {
		/* we were beat by someone else */
		wq_prepost_put(wqp);
		wqp_id = waitq->waitq_prepost_id;
		goto out_unlock;
	}

	wqp->wqp_wq.wqp_wq_ptr = waitq;

	wqp_set_valid(wqp);
	wqp_id = wqp->wqp_prepostid.id;
	waitq->waitq_prepost_id = wqp_id;

	wq_prepost_put(wqp);

out_unlock:
	waitq_unlock(waitq);
	if (waitq_irq_safe(waitq))
		splx(s);

	return wqp_id;
}


static int waitq_inset_cb(struct waitq *waitq, void *ctx, struct setid_link *link)
{
	uint64_t setid = *(uint64_t *)ctx;
	int ltype = sl_type(link);
	(void)waitq;
	if (ltype == SLT_WQS && link->sl_set_id.id == setid) {
		wqdbg_v("  waitq already in set 0x%llx", setid);
		return WQ_ITERATE_FOUND;
	} else if (ltype == SLT_LINK) {
		/*
		 * break out early if we see a link that points to the setid
		 * in question. This saves us a step in the
		 * iteration/recursion
		 */
		wqdbg_v("  waitq already in set 0x%llx (SLT_LINK)", setid);
		if (link->sl_link.sl_left_setid == setid ||
		    link->sl_link.sl_right_setid == setid)
			return WQ_ITERATE_FOUND;
	}

	return WQ_ITERATE_CONTINUE;
}

/**
 * determine if 'waitq' is a member of 'wqset'
 *
 * Conditions:
 *	neither 'waitq' nor 'wqset' is not locked
 *	may disable and re-enable interrupts while locking 'waitq'
 */
boolean_t waitq_member(struct waitq *waitq, struct waitq_set *wqset)
{
	kern_return_t kr = WQ_ITERATE_SUCCESS;
	uint64_t setid;
	spl_t s;

	if (!waitq_valid(waitq))
		panic("Invalid waitq: %p", waitq);

	if (!waitqs_is_set(wqset))
		return FALSE;

	if (waitq_irq_safe(waitq))
		s = splsched();
	waitq_lock(waitq);

	setid = wqset->wqset_id;
	if (!setid)
		goto out_unlock;

	/* fast path: most waitqs are members of only 1 set */
	if (waitq->waitq_set_id == setid) {
		waitq_unlock(waitq);
		if (waitq_irq_safe(waitq))
			splx(s);
		return TRUE;
	}

	/* walk the link table and look for the Set ID of wqset */
	kr = walk_setid_links(LINK_WALK_ONE_LEVEL, waitq, waitq->waitq_set_id,
			      SLT_ALL, (void *)&setid, waitq_inset_cb);

out_unlock:
	waitq_unlock(waitq);
	if (waitq_irq_safe(waitq))
		splx(s);

	if (kr == WQ_ITERATE_FOUND)
		return TRUE;
	return FALSE;
}

/**
 * Returns true is the given waitq is a member of at least 1 set
 */
boolean_t waitq_in_set(struct waitq *waitq)
{
	struct setid_link *link;
	boolean_t inset = FALSE;
	spl_t s;

	if (waitq_irq_safe(waitq))
		s = splsched();
	waitq_lock(waitq);

	if (!waitq->waitq_set_id)
		goto out_unlock;

	link = lt_get_link(waitq->waitq_set_id);
	if (link) {
		/* if we get here, the waitq is in _at_least_one_ set */
		inset = TRUE;
		lt_put_link(link);
	} else {
		/* we can just optimize this for next time */
		waitq->waitq_set_id = 0;
	}

out_unlock:
	waitq_unlock(waitq);
	if (waitq_irq_safe(waitq))
		splx(s);
	return inset;
}


/**
 * pre-allocate a waitq link structure from the link table
 *
 * Conditions:
 *	'waitq' is not locked
 *	may (rarely) block if link table needs to grow
 */
uint64_t waitq_link_reserve(struct waitq *waitq)
{
	struct setid_link *link;
	uint64_t reserved_id = 0;

	assert(get_preemption_level() == 0 && waitq_wait_possible(current_thread()));

	/*
	 * We've asserted that the caller can block, so we enforce a
	 * minimum-free table element policy here.
	 */
	lt_ensure_free_space();

	(void)waitq;
	link = lt_alloc_link(WQT_RESERVED);
	if (!link)
		return 0;

	reserved_id = link->sl_set_id.id;

	return reserved_id;
}

/**
 * release a pre-allocated waitq link structure
 */
void waitq_link_release(uint64_t id)
{
	struct setid_link *link;

	if (id == 0)
		return;

	link = lt_get_reserved(id, SLT_LINK);
	if (!link)
		return;

	/*
	 * if we successfully got a link object, then we know
	 * it's not been marked valid, and can be released with
	 * a standard lt_put_link() which should free the element.
	 */
	lt_put_link(link);
#if CONFIG_WAITQ_STATS
	g_linktable.nreserved_releases += 1;
#endif
}

/**
 * link 'waitq' to the set identified by 'setid' using the 'link' structure
 *
 * Conditions:
 *	'waitq' is locked
 *	caller should have a reference to the 'link' object
 */
static kern_return_t waitq_link_internal(struct waitq *waitq,
					 uint64_t setid, struct setid_link *link)
{
	struct setid_link *qlink;
	kern_return_t kr;

	assert(waitq_held(waitq));

	/*
	 * If the waitq_set_id field is empty, then this waitq is not
	 * a member of any other set. All we have to do is update the
	 * field.
	 */
	if (!waitq->waitq_set_id) {
		waitq->waitq_set_id = setid;
		return KERN_SUCCESS;
	}

	qlink = lt_get_link(waitq->waitq_set_id);
	if (!qlink) {
		/*
		 * The set to which this wait queue belonged has been
		 * destroyed / invalidated. We can re-use the waitq field.
		 */
		waitq->waitq_set_id = setid;
		return KERN_SUCCESS;
	}
	lt_put_link(qlink);

	/*
	 * Check to see if it's already a member of the set.
	 *
	 * TODO: check for cycles!
	 */
	kr = walk_setid_links(LINK_WALK_ONE_LEVEL, waitq, waitq->waitq_set_id,
			      SLT_ALL, (void *)&setid, waitq_inset_cb);
	if (kr == WQ_ITERATE_FOUND)
		return kr;

	/*
	 * This wait queue is a member of at least one set already,
	 * and _not_ a member of the given set. Use our previously
	 * allocated link object, and hook it up to the wait queue.
	 * Note that it's possible that one or more of the wait queue sets to
	 * which the wait queue belongs was invalidated before we allocated
	 * this link object. That's OK because the next time we use that
	 * object we'll just ignore it.
	 */
	link->sl_link.sl_left_setid = setid;
	link->sl_link.sl_right_setid = waitq->waitq_set_id;
	sl_set_valid(link);

	waitq->waitq_set_id = link->sl_set_id.id;

	return KERN_SUCCESS;
}

/**
 * link 'waitq' to 'wqset'
 *
 * Conditions:
 *	if 'lock_state' contains WAITQ_SHOULD_LOCK, 'waitq' must be unlocked.
 *	Otherwise, 'waitq' must be locked.
 *
 *	may (rarely) block on link table allocation if the table has to grow,
 *	and no 'reserved_link' object is passed.
 *
 * Notes:
 *	The caller can guarantee that this function will never block by
 *	pre-allocating a link table object and passing its ID in 'reserved_link'
 */
kern_return_t waitq_link(struct waitq *waitq, struct waitq_set *wqset,
			 waitq_lock_state_t lock_state, uint64_t *reserved_link)
{
	kern_return_t kr;
	struct setid_link *link;
	int should_lock = (lock_state == WAITQ_SHOULD_LOCK);
	spl_t s;

	if (!waitq_valid(waitq))
		panic("Invalid waitq: %p", waitq);

	if (!waitqs_is_set(wqset))
		return KERN_INVALID_ARGUMENT;

	wqdbg_v("Link waitq %p to wqset 0x%llx",
		(void *)VM_KERNEL_UNSLIDE_OR_PERM(waitq), wqset->wqset_id);

	if (waitq_irq_safe(waitq) && (!reserved_link || *reserved_link == 0)) {
		/*
		 * wait queues that need IRQs disabled cannot block waiting
		 * for table growth to complete. Even though this is rare,
		 * we require all these waitqs to pass in a reserved link
		 * object to avoid the potential to block.
		 */
		panic("Global/IRQ-safe waitq %p cannot link to %p without"
		      "reserved object!", waitq, wqset);
	}

	/*
	 * We _might_ need a new link object here, so we'll grab outside
	 * the lock because the alloc call _might_ block.
	 *
	 * If the caller reserved a link beforehand, then lt_get_link
	 * is guaranteed not to block because the caller holds an extra
	 * reference to the link which, in turn, hold a reference to the
	 * link table.
	 */
	if (reserved_link && *reserved_link != 0) {
		link = lt_get_reserved(*reserved_link, SLT_LINK);
		/* always consume the caller's reference */
		*reserved_link = 0;
	} else {
		link = lt_alloc_link(SLT_LINK);
	}
	if (!link)
		return KERN_NO_SPACE;

	if (should_lock) {
		if (waitq_irq_safe(waitq))
			s = splsched();
		waitq_lock(waitq);
	}

	kr = waitq_link_internal(waitq, wqset->wqset_id, link);

	if (should_lock) {
		waitq_unlock(waitq);
		if (waitq_irq_safe(waitq))
			splx(s);
	}

	lt_put_link(link);

	return kr;
}

/**
 * helper: unlink 'waitq' from waitq set identified by 'setid'
 *         this function also prunes invalid objects from the tree
 *
 * Conditions:
 *	MUST be called from walk_setid_links link table walk
 *	'waitq' is locked
 *
 * Notes:
 *	This is a helper function which compresses the link table by culling
 *	unused or unnecessary links. See comments below for different
 *	scenarios.
 */
static inline int waitq_maybe_remove_link(struct waitq *waitq,
					  uint64_t setid,
					  struct setid_link *parent,
					  struct setid_link *left,
					  struct setid_link *right)
{
	uint64_t *wq_setid = &waitq->waitq_set_id;

	/*
	 * There are two scenarios:
	 *
	 * Scenario 1:
	 * --------------------------------------------------------------------
	 * waitq->waitq_set_id == parent
	 *
	 *         parent(LINK)
	 *           /    \
	 *          /      \
	 *         /        \
	 *  L(LINK/WQS_l)   R(LINK/WQS_r)
	 *
	 * In this scenario, we assert that the original waitq points to the
	 * parent link we were passed in.  If WQS_l (or WQS_r) is the waitq
	 * set we're looking for, we can set the corresponding parent
	 * link id (left or right) to 0.  To compress the tree, we can reset the
	 * waitq_set_id of the original waitq to point to the side of the
	 * parent that is still valid. We then discard the parent link object.
	 */
	if (*wq_setid == parent->sl_set_id.id) {
		if (!left && !right) {
			/* completely invalid children */
			lt_invalidate(parent);
			wqdbg_v("S1, L+R");
			*wq_setid = 0;
			return WQ_ITERATE_INVALID;
		} else if (!left || left->sl_set_id.id == setid) {
			/*
			 * left side matches we know it points either to the
			 * WQS we're unlinking, or to an invalid object:
			 * no need to invalidate it
			 */
			*wq_setid = right ? right->sl_set_id.id : 0;
			lt_invalidate(parent);
			wqdbg_v("S1, L");
			return left ? WQ_ITERATE_UNLINKED : WQ_ITERATE_INVALID;
		} else if (!right || right->sl_set_id.id == setid) {
			/*
			 * if right side matches we know it points either to the
			 * WQS we're unlinking, or to an invalid object:
			 * no need to invalidate it
			 */
			*wq_setid = left ? left->sl_set_id.id : 0;
			lt_invalidate(parent);
			wqdbg_v("S1, R");
			return right ? WQ_ITERATE_UNLINKED : WQ_ITERATE_INVALID;
		}
	}

	/*
	 * the tree walk starts at the top-of-tree and moves down,
	 * so these are safe asserts.
	 */
	assert(left || right); /* one of them has to be valid at this point */

	/*
	 * Scenario 2:
	 * --------------------------------------------------------------------
	 * waitq->waitq_set_id == ... (OR parent)
	 *
	 *                    ...
	 *                     |
	 *                   parent
	 *                   /    \
	 *                  /      \
	 *              L(LINK)     R(LINK)
	 *               /\             /\
	 *              /  \           /  \
	 *             /    \       Rl(*)  Rr(*)
	 *         Ll(WQS)  Lr(WQS)
	 *
	 * In this scenario, a leaf node of either the left or right side
	 * could be the wait queue set we're looking to unlink. We also handle
	 * the case where one of these links is invalid.  If a leaf node is
	 * invalid or it's the set we're looking for, we can safely remove the
	 * middle link (left or right) and point the parent link directly to
	 * the remaining leaf node.
	 */
	if (left && sl_type(left) == SLT_LINK) {
		uint64_t Ll, Lr;
		struct setid_link *linkLl, *linkLr;
		assert(left->sl_set_id.id != setid);
		Ll = left->sl_link.sl_left_setid;
		Lr = left->sl_link.sl_right_setid;
		linkLl = lt_get_link(Ll);
		linkLr = lt_get_link(Lr);
		if (!linkLl && !linkLr) {
			/*
			 * The left object points to two invalid objects!
			 * We can invalidate the left w/o touching the parent.
			 */
			lt_invalidate(left);
			wqdbg_v("S2, Ll+Lr");
			return WQ_ITERATE_INVALID;
		} else if (!linkLl || Ll == setid) {
			/* Ll is invalid and/or the wait queue set we're looking for */
			parent->sl_link.sl_left_setid = Lr;
			lt_invalidate(left);
			lt_put_link(linkLl);
			lt_put_link(linkLr);
			wqdbg_v("S2, Ll");
			return linkLl ? WQ_ITERATE_UNLINKED : WQ_ITERATE_INVALID;
		} else if (!linkLr || Lr == setid) {
			/* Lr is invalid and/or the wait queue set we're looking for */
			parent->sl_link.sl_left_setid = Ll;
			lt_invalidate(left);
			lt_put_link(linkLr);
			lt_put_link(linkLl);
			wqdbg_v("S2, Lr");
			return linkLr ? WQ_ITERATE_UNLINKED : WQ_ITERATE_INVALID;
		}
		lt_put_link(linkLl);
		lt_put_link(linkLr);
	}

	if (right && sl_type(right) == SLT_LINK) {
		uint64_t Rl, Rr;
		struct setid_link *linkRl, *linkRr;
		assert(right->sl_set_id.id != setid);
		Rl = right->sl_link.sl_left_setid;
		Rr = right->sl_link.sl_right_setid;
		linkRl = lt_get_link(Rl);
		linkRr = lt_get_link(Rr);
		if (!linkRl && !linkRr) {
			/*
			 * The right object points to two invalid objects!
			 * We can invalidate the right w/o touching the parent.
			 */
			lt_invalidate(right);
			wqdbg_v("S2, Rl+Rr");
			return WQ_ITERATE_INVALID;
		} else if (!linkRl || Rl == setid) {
			/* Rl is invalid and/or the wait queue set we're looking for */
			parent->sl_link.sl_right_setid = Rr;
			lt_invalidate(right);
			lt_put_link(linkRl);
			lt_put_link(linkRr);
			wqdbg_v("S2, Rl");
			return linkRl ? WQ_ITERATE_UNLINKED : WQ_ITERATE_INVALID;
		} else if (!linkRr || Rr == setid) {
			/* Rr is invalid and/or the wait queue set we're looking for */
			parent->sl_link.sl_right_setid = Rl;
			lt_invalidate(right);
			lt_put_link(linkRl);
			lt_put_link(linkRr);
			wqdbg_v("S2, Rr");
			return linkRr ? WQ_ITERATE_UNLINKED : WQ_ITERATE_INVALID;
		}
		lt_put_link(linkRl);
		lt_put_link(linkRr);
	}

	return WQ_ITERATE_CONTINUE;
}

/**
 * link table walk callback that unlinks 'waitq' from 'ctx->setid'
 *
 * Conditions:
 *	called from walk_setid_links
 *	'waitq' is locked
 *
 * Notes:
 *	uses waitq_maybe_remove_link() to compress the linktable and
 *	perform the actual unlinking
 */
static int waitq_unlink_cb(struct waitq *waitq, void *ctx,
			   struct setid_link *link)
{
	uint64_t setid = *((uint64_t *)ctx);
	struct setid_link *right, *left;
	int ret = 0;

	if (sl_type(link) != SLT_LINK)
		return WQ_ITERATE_CONTINUE;

	do  {
		left  = lt_get_link(link->sl_link.sl_left_setid);
		right = lt_get_link(link->sl_link.sl_right_setid);

		ret = waitq_maybe_remove_link(waitq, setid, link, left, right);

		lt_put_link(left);
		lt_put_link(right);

		if (!sl_is_valid(link))
			return WQ_ITERATE_INVALID;
		/* A ret value of UNLINKED will break us out of table walk */
	} while (ret == WQ_ITERATE_INVALID);

	return ret;
}


/**
 * undo/remove a prepost from 'ctx' (waitq) to 'wqset'
 *
 * Conditions:
 *	Called from wq_prepost_foreach_locked OR wq_prepost_iterate
 *	'wqset' may be NULL
 *	(ctx)->unlink_wqset is locked
 */
static int waitq_unlink_prepost_cb(struct waitq_set __unused *wqset, void *ctx,
				   struct wq_prepost *wqp, struct waitq *waitq)
{
	struct wq_unlink_ctx *ulctx = (struct wq_unlink_ctx *)ctx;

	if (waitq != ulctx->unlink_wq)
		return WQ_ITERATE_CONTINUE;

	if (wqp_type(wqp) == WQP_WQ &&
	    wqp->wqp_prepostid.id == ulctx->unlink_wqset->wqset_prepost_id) {
		/* this is the only prepost on this wait queue set */
		wqdbg_v("unlink wqp (WQ) 0x%llx", wqp->wqp_prepostid.id);
		ulctx->unlink_wqset->wqset_prepost_id = 0;
		return WQ_ITERATE_BREAK;
	}

	assert(wqp_type(wqp) == WQP_POST);

	/*
	 * The prepost object 'wqp' points to a waitq which should no longer
	 * be preposted to 'ulctx->unlink_wqset'. We can remove the prepost
	 * object from the list and break out of the iteration. Using the
	 * context object in this way allows this same callback function to be
	 * used from both wq_prepost_foreach_locked and wq_prepost_iterate.
	 */
	wq_prepost_remove(ulctx->unlink_wqset, wqp);
	return WQ_ITERATE_BREAK;
}

/**
 * unlink 'waitq' from 'wqset'
 *
 * Conditions:
 *	'waitq' is locked
 *	'wqset' is _not_ locked
 *	may (rarely) spin in prepost clear and drop/re-acquire 'waitq' lock
 *	(see waitq_clear_prepost_locked)
 */
static kern_return_t waitq_unlink_locked(struct waitq *waitq,
					 struct waitq_set *wqset,
					 spl_t *s)
{
	uint64_t setid;
	kern_return_t kr;

	setid = wqset->wqset_id;

	if (waitq->waitq_set_id == 0) {
		/*
		 * TODO:
		 * it doesn't belong to anyone, and it has a prepost object?
		 * This is an artifact of not cleaning up after kqueues when
		 * they prepost into select sets...
		 */
		if (waitq->waitq_prepost_id != 0)
			(void)waitq_clear_prepost_locked(waitq, s);
		return KERN_NOT_IN_SET;
	}

	if (waitq->waitq_set_id == setid) {
		waitq->waitq_set_id = 0;
		/*
		 * This was the only set to which the waitq belonged: we can
		 * safely release the waitq's prepost object. It doesn't
		 * matter if this function drops and re-acquires the lock
		 * because we're not manipulating waitq state any more.
		 */
		(void)waitq_clear_prepost_locked(waitq, s);
		return KERN_SUCCESS;
	}

	/*
	 * The waitq was a member of more that 1 set, so we need to
	 * handle potentially compressing the link table, and
	 * adjusting the waitq->waitq_set_id value.
	 *
	 * Note: we can't free the waitq's associated prepost object (if any)
	 *       because it may be in use by the one or more _other_ sets to
	 *       which this queue belongs.
	 *
	 * Note: This function only handles a single level of the queue linkage.
	 *       Removing a waitq from a set to which it does not directly
	 *       belong is undefined. For example, if a waitq belonged to set
	 *       A, and set A belonged to set B. You can't remove the waitq
	 *       from set B.
	 */
	kr = walk_setid_links(LINK_WALK_ONE_LEVEL, waitq, waitq->waitq_set_id,
			      SLT_LINK, (void *)&setid, waitq_unlink_cb);

	if (kr == WQ_ITERATE_UNLINKED) {
		struct wq_unlink_ctx ulctx;
		int do_spl = 0;

		kr = KERN_SUCCESS; /* found it and dis-associated it */

		if (!waitq_irq_safe(waitq) && waitq_irq_safe(&wqset->wqset_q)) {
			*s = splsched();
			do_spl = 1;
		}
		waitq_set_lock(wqset);
		/*
		 * clear out any prepost from waitq into wqset
		 * TODO: this could be more efficient than a linear search of
		 *       the waitq set's prepost list.
		 */
		ulctx.unlink_wq = waitq;
		ulctx.unlink_wqset = wqset;
		(void)wq_prepost_iterate(wqset->wqset_prepost_id, (void *)&ulctx,
					 waitq_unlink_prepost_cb);
		waitq_set_unlock(wqset);
		if (do_spl)
			splx(*s);
	} else {
		kr = KERN_NOT_IN_SET; /* waitq is _not_ associated with wqset */
	}

	return kr;
}

/**
 * unlink 'waitq' from 'wqset'
 *
 * Conditions:
 *	neither 'waitq' nor 'wqset' is locked
 *	may disable and re-enable interrupts
 *	may (rarely) spin in prepost clear
 *	(see waitq_clear_prepost_locked)
 */
kern_return_t waitq_unlink(struct waitq *waitq, struct waitq_set *wqset)
{
	kern_return_t kr = KERN_SUCCESS;
	spl_t s;

	assert(waitqs_is_set(wqset));

	/*
	 * we allow the waitq to be invalid because the caller may be trying
	 * to clear out old/dirty state
	 */
	if (!waitq_valid(waitq))
		return KERN_INVALID_ARGUMENT;

	wqdbg_v("unlink waitq %p from set 0x%llx",
		(void *)VM_KERNEL_UNSLIDE_OR_PERM(waitq), wqset->wqset_id);

	if (waitq_irq_safe(waitq))
		s = splsched();
	waitq_lock(waitq);

	kr = waitq_unlink_locked(waitq, wqset, &s);

	waitq_unlock(waitq);
	if (waitq_irq_safe(waitq))
		splx(s);

	return kr;
}

/**
 * unlink a waitq from a waitq set, but reference the waitq by its prepost ID
 *
 * Conditions:
 *	'wqset' is unlocked
 *	wqp_id may be valid or invalid
 */
void waitq_unlink_by_prepost_id(uint64_t wqp_id, struct waitq_set *wqset)
{
	struct wq_prepost *wqp;

	disable_preemption();
	wqp = wq_prepost_get(wqp_id);
	if (wqp) {
		struct waitq *wq;
		spl_t s;

		wq = wqp->wqp_wq.wqp_wq_ptr;

		/*
		 * lock the waitq, then release our prepost ID reference, then
		 * unlink the waitq from the wqset: this ensures that we don't
		 * hold a prepost ID reference during the unlink, but we also
		 * complete the unlink operation atomically to avoid a race
		 * with waitq_unlink[_all].
		 */
		if (waitq_irq_safe(wq))
			s = splsched();
		waitq_lock(wq);
		wq_prepost_put(wqp);

		if (!waitq_valid(wq)) {
			/* someone already tore down this waitq! */
			waitq_unlock(wq);
			if (waitq_irq_safe(wq))
				splx(s);
			enable_preemption();
			return;
		}

		/* this _may_ drop the wq lock, but that's OK */
		waitq_unlink_locked(wq, wqset, &s);

		waitq_unlock(wq);
		if (waitq_irq_safe(wq))
			splx(s);
	}
	enable_preemption();
	return;
}


/**
 * unlink 'waitq' from all sets to which it belongs
 *
 * Conditions:
 *	'waitq' is locked
 *
 * Notes:
 *	may drop and re-acquire the waitq lock
 *	may (rarely) spin (see waitq_clear_prepost_locked)
 */
kern_return_t waitq_unlink_all_locked(struct waitq *waitq, uint64_t *old_set_id,
				      spl_t *s, int *dropped_lock)
{
	wqdbg_v("unlink waitq %p from all sets",
		(void *)VM_KERNEL_UNSLIDE_OR_PERM(waitq));

	*old_set_id = 0;

	/* it's not a member of any sets */
	if (waitq->waitq_set_id == 0)
		return KERN_SUCCESS;

	*old_set_id = waitq->waitq_set_id;
	waitq->waitq_set_id = 0;

	/*
	 * invalidate the prepost entry for this waitq.
	 * This may drop and re-acquire the waitq lock, but that's OK because
	 * if it was added to another set and preposted to that set in the
	 * time we drop the lock, the state will remain consistent.
	 */
	int dropped = waitq_clear_prepost_locked(waitq, s);
	if (dropped_lock)
		*dropped_lock = dropped;

	return KERN_SUCCESS;
}

/**
 * unlink 'waitq' from all sets to which it belongs
 *
 * Conditions:
 *	'waitq' is not locked
 *	may disable and re-enable interrupts
 *	may (rarely) spin
 *	(see waitq_unlink_all_locked, waitq_clear_prepost_locked)
 */
kern_return_t waitq_unlink_all(struct waitq *waitq)
{
	kern_return_t kr = KERN_SUCCESS;
	uint64_t setid = 0;
	spl_t s;

	if (!waitq_valid(waitq))
		panic("Invalid waitq: %p", waitq);

	if (waitq_irq_safe(waitq))
		s = splsched();
	waitq_lock(waitq);
	if (waitq_valid(waitq))
		kr = waitq_unlink_all_locked(waitq, &setid, &s, NULL);
	waitq_unlock(waitq);
	if (waitq_irq_safe(waitq))
		splx(s);

	if (setid) {
		/*
		 * Walk the link table and invalidate each LINK object that
		 * used to connect this waitq to one or more sets: this works
		 * because SLT_LINK objects are private to each wait queue
		 */
		(void)walk_setid_links(LINK_WALK_ONE_LEVEL, waitq, setid,
				       SLT_LINK, NULL, waitq_unlink_all_cb);
	}

	return kr;
}


/**
 * unlink all waitqs from 'wqset'
 *
 * Conditions:
 *	'wqset' is not locked
 *	may (rarely) spin/block (see waitq_clear_prepost_locked)
 */
kern_return_t waitq_set_unlink_all(struct waitq_set *wqset)
{
	struct setid_link *link;
	uint64_t prepost_id, set_links_id = 0;
	spl_t spl;

	assert(waitqs_is_set(wqset));

	wqdbg_v("unlink all queues from set 0x%llx", wqset->wqset_id);

	/*
	 * This operation does not require interaction with any of the set's
	 * constituent wait queues. All we have to do is invalidate the SetID
	 */
	if (waitq_irq_safe(&wqset->wqset_q))
		spl = splsched();
	waitq_set_lock(wqset);

	/* invalidate and re-alloc the link object first */
	link = lt_get_link(wqset->wqset_id);

	/* we may have raced with a waitq_set_deinit: handle this */
	if (!link) {
		waitq_set_unlock(wqset);
		return KERN_SUCCESS;
	}

	lt_invalidate(link);

	/* re-alloc the object to get a new generation ID */
	lt_realloc_link(link, SLT_WQS);
	link->sl_wqs.sl_set = wqset;

	wqset->wqset_id = link->sl_set_id.id;
	sl_set_valid(link);
	lt_put_link(link);

	/* clear any preposts attached to this set */
	prepost_id = wqset->wqset_prepost_id;
	wqset->wqset_prepost_id = 0;

	/*
	 * clear set linkage and prepost object associated with this set:
	 * waitq sets may prepost to other sets if, for example, they are
	 * associated with a kqueue which is in a select set.
	 *
	 * This may drop and re-acquire the set lock, but that's OK because
	 * the resulting state will remain consistent.
	 */
	waitq_unlink_all_locked(&wqset->wqset_q, &set_links_id, &spl, NULL);

	waitq_set_unlock(wqset);
	if (waitq_irq_safe(&wqset->wqset_q))
		splx(spl);

	/*
	 * release all the set link objects
	 * (links to other sets to which this set was previously added)
	 */
	if (set_links_id)
		(void)walk_setid_links(LINK_WALK_ONE_LEVEL, &wqset->wqset_q,
				       set_links_id, SLT_LINK, NULL,
				       waitq_unlink_all_cb);

	/* drop / unlink all the prepost table objects */
	if (prepost_id)
		(void)wq_prepost_iterate(prepost_id, NULL,
					 wqset_clear_prepost_chain_cb);

	return KERN_SUCCESS;
}


static int waitq_prepost_reserve_cb(struct waitq *waitq, void *ctx,
				    struct setid_link *link)
{
	uint32_t *num = (uint32_t *)ctx;
	(void)waitq;

	/*
	 * In the worst case, we'll have to allocate 2 prepost objects
	 * per waitq set (if the set was already preposted by another
	 * waitq).
	 */
	if (sl_type(link) == SLT_WQS) {
		/*
		 * check to see if the associated waitq actually supports
		 * preposting
		 */
		if (waitq_set_can_prepost(link->sl_wqs.sl_set))
			*num += 2;
	}
	return WQ_ITERATE_CONTINUE;
}

static int waitq_alloc_prepost_reservation(int nalloc, struct waitq *waitq,
					   spl_t *s, int *did_unlock,
					   struct wq_prepost **wqp)
{
	struct wq_prepost *tmp;
	struct wqp_cache *cache;

	*did_unlock = 0;

	/*
	 * Before we unlock the waitq, check the per-processor prepost object
	 * cache to see if there's enough there for us. If so, do the
	 * allocation, keep the lock and save an entire iteration over the set
	 * linkage!
	 */
	if (waitq) {
		disable_preemption();
		cache = &PROCESSOR_DATA(current_processor(), wqp_cache);
		if (nalloc <= (int)cache->avail)
			goto do_alloc;
		enable_preemption();

		/* unlock the waitq to perform the allocation */
		*did_unlock = 1;
		waitq_unlock(waitq);
		if (waitq_irq_safe(waitq))
			splx(*s);
	}

do_alloc:
	tmp = wq_prepost_alloc(WQT_RESERVED, nalloc);
	if (!tmp)
		panic("Couldn't reserve %d preposts for waitq @%p (wqp@%p)",
		      nalloc, waitq, *wqp);
	if (*wqp) {
		/* link the two lists */
		int __assert_only rc;
		rc = wq_prepost_rlink(tmp, *wqp);
		assert(rc == nalloc);
	}
	*wqp = tmp;

	/*
	 * If the caller can block, then enforce a minimum-free table element
	 * policy here. This helps ensure that we will have enough prepost
	 * objects for callers such as selwakeup() that can be called with
	 * spin locks held.
	 */
	if (get_preemption_level() == 0)
		wq_prepost_ensure_free_space();

	if (waitq) {
		if (*did_unlock == 0) {
			/* decrement the preemption count if alloc from cache */
			enable_preemption();
		} else {
			/* otherwise: re-lock the waitq */
			if (waitq_irq_safe(waitq))
				*s = splsched();
			waitq_lock(waitq);
		}
	}

	return nalloc;
}

static int waitq_count_prepost_reservation(struct waitq *waitq, int extra, int keep_locked)
{
	int npreposts = 0;

	/*
	 * If the waitq is not currently part of a set, and we're not asked to
	 * keep the waitq locked then we'll want to have 3 in reserve
	 * just-in-case it becomes part of a set while we unlock and reserve.
	 * We may need up to 1 object for the waitq, and 2 for the set.
	 */
	if (waitq->waitq_set_id == 0) {
		npreposts = 3;
	} else {
		/* this queue has never been preposted before */
		if (waitq->waitq_prepost_id == 0)
			npreposts = 3;

		/*
		 * Walk the set of table linkages associated with this waitq
		 * and count the worst-case number of prepost objects that
		 * may be needed during a wakeup_all. We can walk this without
		 * locking each set along the way because the table-based IDs
		 * disconnect us from the set pointers themselves, and the
		 * table walking is careful to read the setid values only once.
		 * Locking each set up the chain also doesn't guarantee that
		 * their membership won't change between the time we unlock
		 * that set and when we actually go to prepost, so our
		 * situation is no worse than before and we've alleviated lock
		 * contention on any sets to which this waitq belongs.
		 */
		(void)walk_setid_links(LINK_WALK_FULL_DAG_UNLOCKED,
				       waitq, waitq->waitq_set_id,
				       SLT_WQS, (void *)&npreposts,
				       waitq_prepost_reserve_cb);
	}

	if (extra > 0)
		npreposts += extra;

	if (npreposts == 0 && !keep_locked) {
		/*
		 * If we get here, we were asked to reserve some prepost
		 * objects for a waitq that's previously preposted, and is not
		 * currently a member of any sets. We have also been
		 * instructed to unlock the waitq when we're done. In this
		 * case, we pre-allocated enough reserved objects to handle
		 * the case where the waitq gets added to a single set when
		 * the lock is released.
		 */
		npreposts = 3;
	}

	return npreposts;
}


/**
 * pre-allocate prepost objects for 'waitq'
 *
 * Conditions:
 *	'waitq' is not locked
 *
 * Returns:
 *	panic on error
 *
 *	0 on success, '*reserved' is set to the head of a singly-linked
 *	list of pre-allocated prepost objects.
 *
 * Notes:
 *	If 'lock_state' is WAITQ_KEEP_LOCKED, this function performs the pre-allocation
 *	atomically and returns 'waitq' locked. If the waitq requires
 *	interrupts to be disabled, then the output parameter 's' is set to the
 *	previous interrupt state (from splsched), and the caller is
 *	responsible to call splx().
 *
 *	This function attempts to pre-allocate precisely enough prepost
 *	objects based on the current set membership of 'waitq'. If the
 *	operation is performed atomically, then the caller
 *	is guaranteed to have enough pre-allocated prepost object to avoid
 *	any (rare) blocking in the wakeup path.
 */
uint64_t waitq_prepost_reserve(struct waitq *waitq, int extra,
			       waitq_lock_state_t lock_state, spl_t *s)
{
	uint64_t reserved = 0;
	uint64_t prev_setid = 0, prev_prepostid = 0;
	struct wq_prepost *wqp = NULL;
	int nalloc = 0, npreposts = 0;
	int keep_locked = (lock_state == WAITQ_KEEP_LOCKED);
	int unlocked = 0;

	if (s)
		*s = 0;

	wqdbg_v("Attempting to reserve prepost linkages for waitq %p (extra:%d)",
		(void *)VM_KERNEL_UNSLIDE_OR_PERM(waitq), extra);

	if (waitq == NULL && extra > 0) {
		/*
		 * Simple prepost object allocation:
		 * we'll add 2 more because the waitq might need an object,
		 * and the set itself may need a new POST object in addition
		 * to the number of preposts requested by the caller
		 */
		nalloc = waitq_alloc_prepost_reservation(extra + 2, NULL, NULL,
							 &unlocked, &wqp);
		assert(nalloc == extra + 2);
		return wqp->wqp_prepostid.id;
	}

	assert(lock_state == WAITQ_KEEP_LOCKED || lock_state == WAITQ_UNLOCK);

	if (waitq_irq_safe(waitq))
		*s = splsched();
	waitq_lock(waitq);

	/* global queues are never part of any sets */
	if (waitq_is_global(waitq)) {
		if (keep_locked)
			goto out;
		goto out_unlock;
	}

	/* remember the set ID that we started with */
	prev_setid = waitq->waitq_set_id;
	prev_prepostid = waitq->waitq_prepost_id;

	/*
	 * If the waitq is not part of a set, and we're asked to
	 * keep the set locked, then we don't have to reserve
	 * anything!
	 */
	if (prev_setid == 0 && keep_locked)
		goto out;

	npreposts = waitq_count_prepost_reservation(waitq, extra, keep_locked);

	/* nothing for us to do! */
	if (npreposts == 0) {
		if (keep_locked)
			goto out;
		goto out_unlock;
	}

try_alloc:
	/* this _may_ unlock and relock the waitq! */
	nalloc = waitq_alloc_prepost_reservation(npreposts, waitq, s,
						 &unlocked, &wqp);

	if (!unlocked) {
		/* allocation held the waitq lock: we'd done! */
		if (keep_locked)
			goto out;
		goto out_unlock;
	}

	/*
	 * Before we return, if the allocation had to unlock the waitq, we
	 * must check one more time to see if we have enough. If not, we'll
	 * try to allocate the difference. If the caller requests it, we'll
	 * also leave the waitq locked so that the use of the pre-allocated
	 * prepost objects can be guaranteed to be enough if a wakeup_all is
	 * performed before unlocking the waitq.
	 */

	/*
	 * If the waitq is no longer associated with a set, or if the waitq's
	 * set/prepostid has not changed since we first walked its linkage,
	 * we're done.
	 */
	if ((waitq->waitq_set_id == 0) ||
	    (waitq->waitq_set_id == prev_setid &&
	     waitq->waitq_prepost_id == prev_prepostid)) {
		if (keep_locked)
			goto out;
		goto out_unlock;
	}

	npreposts = waitq_count_prepost_reservation(waitq, extra, keep_locked);

	if (npreposts > nalloc) {
		prev_setid = waitq->waitq_set_id;
		prev_prepostid = waitq->waitq_prepost_id;
		npreposts = npreposts - nalloc; /* only allocate the diff */
		goto try_alloc;
	}

	if (keep_locked)
		goto out;

out_unlock:
	waitq_unlock(waitq);
	if (waitq_irq_safe(waitq))
		splx(*s);
out:
	if (wqp)
		reserved = wqp->wqp_prepostid.id;

	return reserved;
}

/**
 * release a linked list of prepost objects allocated via _prepost_reserve
 *
 * Conditions:
 *	may (rarely) spin waiting for prepost table growth memcpy
 */
void waitq_prepost_release_reserve(uint64_t id)
{
	struct wq_prepost *wqp;

	wqdbg_v("releasing reserved preposts starting at: 0x%llx", id);

	wqp = wq_prepost_rfirst(id);
	if (!wqp)
		return;

	wq_prepost_release_rlist(wqp);
}


/**
 * clear all preposts from 'wqset'
 *
 * Conditions:
 *	'wqset' is not locked
 */
void waitq_set_clear_preposts(struct waitq_set *wqset)
{
	uint64_t prepost_id;
	spl_t spl;

	assert(waitqs_is_set(wqset));

	wqdbg_v("Clearing all preposted queues on waitq_set: 0x%llx",
		wqset->wqset_id);

	if (waitq_irq_safe(&wqset->wqset_q))
		spl = splsched();
	waitq_set_lock(wqset);
	prepost_id = wqset->wqset_prepost_id;
	wqset->wqset_prepost_id = 0;
	waitq_set_unlock(wqset);
	if (waitq_irq_safe(&wqset->wqset_q))
		splx(spl);

	/* drop / unlink all the prepost table objects */
	if (prepost_id)
		(void)wq_prepost_iterate(prepost_id, NULL,
					 wqset_clear_prepost_chain_cb);
}


/* ----------------------------------------------------------------------
 *
 * Iteration: waitq -> sets / waitq_set -> preposts
 *
 * ---------------------------------------------------------------------- */

struct wq_it_ctx {
	void *input;
	void *ctx;
	waitq_iterator_t it;

	spl_t *spl;
};

static int waitq_iterate_sets_cb(struct waitq *waitq, void *ctx,
				 struct setid_link *link)
{
	struct wq_it_ctx *wctx = (struct wq_it_ctx *)(ctx);
	struct waitq_set *wqset;
	int ret;
	spl_t spl;

	(void)waitq;
	assert(sl_type(link) == SLT_WQS);

	/*
	 * the waitq is locked, so we can just take the set lock
	 * and call the iterator function
	 */
	wqset = link->sl_wqs.sl_set;
	assert(wqset != NULL);

	if (!waitq_irq_safe(waitq) && waitq_irq_safe(&wqset->wqset_q))
		spl = splsched();
	waitq_set_lock(wqset);

	ret = wctx->it(wctx->ctx, (struct waitq *)wctx->input, wqset);

	waitq_set_unlock(wqset);
	if (!waitq_irq_safe(waitq) && waitq_irq_safe(&wqset->wqset_q))
		splx(spl);

	return ret;
}

/**
 * call external iterator function for each prepost object in wqset
 *
 * Conditions:
 *	Called from wq_prepost_foreach_locked
 *	(wqset locked, waitq _not_ locked)
 */
static int wqset_iterate_prepost_cb(struct waitq_set *wqset, void *ctx,
				    struct wq_prepost *wqp, struct waitq *waitq)
{
	struct wq_it_ctx *wctx = (struct wq_it_ctx *)(ctx);
	uint64_t wqp_id;
	int ret;
	spl_t s;

	(void)wqp;

	/*
	 * This is a bit tricky. The 'wqset' is locked, but the 'waitq' is not.
	 * Taking the 'waitq' lock is a lock order violation, so we need to be
	 * careful. We also must realize that we may have taken a reference to
	 * the 'wqp' just as the associated waitq was being torn down (or
	 * clearing all its preposts) - see waitq_clear_prepost_locked(). If
	 * the 'wqp' is valid and we can get the waitq lock, then we are good
	 * to go. If not, we need to back off, check that the 'wqp' hasn't
	 * been invalidated, and try to re-take the locks.
	 */
	if (waitq_irq_safe(waitq))
		s = splsched();
	if (waitq_lock_try(waitq))
		goto call_iterator;

	if (waitq_irq_safe(waitq))
		splx(s);

	if (!wqp_is_valid(wqp))
		return WQ_ITERATE_RESTART;

	/* We are passed a prepost object with a reference on it. If neither
	 * the waitq set nor the waitq require interrupts disabled, then we
	 * may block on the delay(1) call below. We can't hold a prepost
	 * object reference while blocking, so we have to give that up as well
	 * and re-acquire it when we come back.
	 */
	wqp_id = wqp->wqp_prepostid.id;
	wq_prepost_put(wqp);
	waitq_set_unlock(wqset);
	wqdbg_v("dropped set:%p lock waiting for wqp:%p (0x%llx -> wq:%p)",
		wqset, wqp, wqp->wqp_prepostid.id, waitq);
	delay(1);
	waitq_set_lock(wqset);
	wqp = wq_prepost_get(wqp_id);
	if (!wqp)
		/* someone cleared preposts while we slept! */
		return WQ_ITERATE_DROPPED;

	/*
	 * TODO:
	 * This differs slightly from the logic in ipc_mqueue.c:
	 * ipc_mqueue_receive_on_thread(). There, if the waitq lock
	 * can't be obtained, the prepost link is placed on the back of
	 * the chain, and the iteration starts from the beginning. Here,
	 * we just restart from the beginning.
	 */
	return WQ_ITERATE_RESTART;

call_iterator:
	if (!wqp_is_valid(wqp)) {
		ret = WQ_ITERATE_RESTART;
		goto out_unlock;
	}

	/* call the external callback */
	ret = wctx->it(wctx->ctx, waitq, wqset);

	if (ret == WQ_ITERATE_BREAK_KEEP_LOCKED) {
		ret = WQ_ITERATE_BREAK;
		if (wctx->spl)
			*(wctx->spl) = s;
		goto out;
	}

out_unlock:
	waitq_unlock(waitq);
	if (waitq_irq_safe(waitq))
		splx(s);

out:
	return ret;
}

/**
 * iterator over all sets to which the given waitq has been linked
 *
 * Conditions:
 * 	'waitq' is locked
 */
int waitq_iterate_sets(struct waitq *waitq, void *ctx, waitq_iterator_t it)
{
	int ret;
	struct wq_it_ctx wctx = {
		.input = (void *)waitq,
		.ctx = ctx,
		.it = it,
	};
	if (!it || !waitq)
		return KERN_INVALID_ARGUMENT;

	ret = walk_setid_links(LINK_WALK_ONE_LEVEL, waitq, waitq->waitq_set_id,
			       SLT_WQS, (void *)&wctx, waitq_iterate_sets_cb);
	if (ret == WQ_ITERATE_CONTINUE)
		ret = WQ_ITERATE_SUCCESS;
	return ret;
}

/**
 * iterator over all preposts in the given wqset
 *
 * Conditions:
 * 	'wqset' is locked
 */
int waitq_set_iterate_preposts(struct waitq_set *wqset,
			       void *ctx, waitq_iterator_t it, spl_t *s)
{
	struct wq_it_ctx wctx = {
		.input = (void *)wqset,
		.ctx = ctx,
		.it = it,
		.spl = s,
	};
	if (!it || !wqset)
		return WQ_ITERATE_INVALID;

	assert(waitq_held(&wqset->wqset_q));

	return wq_prepost_foreach_locked(wqset, (void *)&wctx,
					 wqset_iterate_prepost_cb);
}


/* ----------------------------------------------------------------------
 *
 * Higher-level APIs
 *
 * ---------------------------------------------------------------------- */

/**
 * declare a thread's intent to wait on 'waitq' for 'wait_event'
 *
 * Conditions:
 *	'waitq' is not locked
 *	will disable and re-enable interrupts while locking current_thread()
 */
wait_result_t waitq_assert_wait64(struct waitq *waitq,
				  event64_t wait_event,
				  wait_interrupt_t interruptible,
				  uint64_t deadline)
{
	wait_result_t ret;
	thread_t thread = current_thread();
	spl_t s;

	if (!waitq_valid(waitq))
		panic("Invalid waitq: %p", waitq);

	if (waitq_irq_safe(waitq))
		s = splsched();
	waitq_lock(waitq);

	if (!waitq_irq_safe(waitq))
		s = splsched();
	thread_lock(thread);

	ret = waitq_assert_wait64_locked(waitq, wait_event, interruptible,
					 TIMEOUT_URGENCY_SYS_NORMAL,
					 deadline, TIMEOUT_NO_LEEWAY, thread);

	thread_unlock(thread);
	waitq_unlock(waitq);

	splx(s);

	return ret;
}

/**
 * declare a thread's intent to wait on 'waitq' for 'wait_event'
 *
 * Conditions:
 *	'waitq' is not locked
 *	will disable and re-enable interrupts while locking current_thread()
 */
wait_result_t waitq_assert_wait64_leeway(struct waitq *waitq,
					 event64_t wait_event,
					 wait_interrupt_t interruptible,
					 wait_timeout_urgency_t urgency,
					 uint64_t deadline,
					 uint64_t leeway)
{
	wait_result_t ret;
	thread_t thread = current_thread();
	spl_t s;

	if (!waitq_valid(waitq))
		panic("Invalid waitq: %p", waitq);

	if (waitq_irq_safe(waitq))
		s = splsched();
	waitq_lock(waitq);

	if (!waitq_irq_safe(waitq))
		s = splsched();
	thread_lock(thread);

	ret = waitq_assert_wait64_locked(waitq, wait_event, interruptible,
					 urgency, deadline, leeway, thread);

	thread_unlock(thread);
	waitq_unlock(waitq);

	splx(s);

	return ret;
}

/**
 * wakeup a single thread from a waitq that's waiting for a given event
 *
 * Conditions:
 *	'waitq' is not locked
 *	may (rarely) block if 'waitq' is non-global and a member of 1 or more sets
 *	may disable and re-enable interrupts
 *
 * Notes:
 *	will _not_ block if waitq is global (or not a member of any set)
 */
kern_return_t waitq_wakeup64_one(struct waitq *waitq, event64_t wake_event,
				 wait_result_t result, int priority)
{
	kern_return_t kr;
	uint64_t reserved_preposts = 0;
	spl_t spl;

	if (!waitq_valid(waitq))
		panic("Invalid waitq: %p", waitq);

	/* NOTE: this will _not_ reserve anything if waitq is global */
	reserved_preposts = waitq_prepost_reserve(waitq, 0,
						  WAITQ_KEEP_LOCKED, &spl);

	/* waitq is locked upon return */
	kr = waitq_wakeup64_one_locked(waitq, wake_event, result,
				       &reserved_preposts, priority, WAITQ_UNLOCK);

	if (waitq_irq_safe(waitq))
		splx(spl);

	/* release any left-over prepost object (won't block/lock anything) */
	waitq_prepost_release_reserve(reserved_preposts);

	return kr;
}

/**
 * wakeup all threads from a waitq that are waiting for a given event
 *
 * Conditions:
 *	'waitq' is not locked
 *	may (rarely) block if 'waitq' is non-global and a member of 1 or more sets
 *	may disable and re-enable interrupts
 *
 * Notes:
 *	will _not_ block if waitq is global (or not a member of any set)
 */
kern_return_t waitq_wakeup64_all(struct waitq *waitq,
				 event64_t wake_event,
				 wait_result_t result,
				 int priority)
{
	kern_return_t ret;
	uint64_t reserved_preposts = 0;
	spl_t s;

	if (!waitq_valid(waitq))
		panic("Invalid waitq: %p", waitq);

	/* keep waitq locked upon return */
	/* NOTE: this will _not_ reserve anything if waitq is global */
	reserved_preposts = waitq_prepost_reserve(waitq, 0,
						  WAITQ_KEEP_LOCKED, &s);

	/* waitq is locked */

	ret = waitq_wakeup64_all_locked(waitq, wake_event, result,
					&reserved_preposts, priority,
					WAITQ_UNLOCK);

	if (waitq_irq_safe(waitq))
		splx(s);

	waitq_prepost_release_reserve(reserved_preposts);

	return ret;

}

/**
 * wakeup a specific thread iff it's waiting on 'waitq' for 'wake_event'
 *
 * Conditions:
 *	'waitq' is not locked
 *
 * Notes:
 *	May temporarily disable and re-enable interrupts
 */
kern_return_t waitq_wakeup64_thread(struct waitq *waitq,
				    event64_t wake_event,
				    thread_t thread,
				    wait_result_t result)
{
	kern_return_t ret;
	spl_t s, th_spl;

	if (!waitq_valid(waitq))
		panic("Invalid waitq: %p", waitq);

	if (waitq_irq_safe(waitq))
		s = splsched();
	waitq_lock(waitq);

	ret = waitq_select_thread_locked(waitq, wake_event, thread, &th_spl);
	/* on success, returns 'thread' locked */

	waitq_unlock(waitq);

	if (ret == KERN_SUCCESS) {
		ret = thread_go(thread, result);
		assert(ret == KERN_SUCCESS);
		thread_unlock(thread);
		splx(th_spl);
		waitq_stats_count_wakeup(waitq);
	} else {
		ret = KERN_NOT_WAITING;
		waitq_stats_count_fail(waitq);
	}

	if (waitq_irq_safe(waitq))
		splx(s);

	return ret;
}
