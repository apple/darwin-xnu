/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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
 *	File:	vm/vm_page.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *
 *	Resident memory management module.
 */

#include <debug.h>
#include <libkern/OSAtomic.h>
#include <libkern/OSDebug.h>

#include <mach/clock_types.h>
#include <mach/vm_prot.h>
#include <mach/vm_statistics.h>
#include <mach/sdt.h>
#include <kern/counters.h>
#include <kern/sched_prim.h>
#include <kern/policy_internal.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/kalloc.h>
#include <kern/zalloc.h>
#include <kern/xpr.h>
#include <kern/ledger.h>
#include <vm/pmap.h>
#include <vm/vm_init.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_kern.h>			/* kernel_memory_allocate() */
#include <kern/misc_protos.h>
#include <zone_debug.h>
#include <mach_debug/zone_info.h>
#include <vm/cpm.h>
#include <pexpert/pexpert.h>

#include <vm/vm_protos.h>
#include <vm/memory_object.h>
#include <vm/vm_purgeable_internal.h>
#include <vm/vm_compressor.h>

#if CONFIG_PHANTOM_CACHE
#include <vm/vm_phantom_cache.h>
#endif

#include <IOKit/IOHibernatePrivate.h>

#include <sys/kdebug.h>


char	vm_page_inactive_states[VM_PAGE_Q_STATE_ARRAY_SIZE];
char	vm_page_pageable_states[VM_PAGE_Q_STATE_ARRAY_SIZE];
char	vm_page_non_speculative_pageable_states[VM_PAGE_Q_STATE_ARRAY_SIZE];
char	vm_page_active_or_inactive_states[VM_PAGE_Q_STATE_ARRAY_SIZE];

#if CONFIG_SECLUDED_MEMORY
struct vm_page_secluded_data vm_page_secluded;
#endif /* CONFIG_SECLUDED_MEMORY */

boolean_t	hibernate_cleaning_in_progress = FALSE;
boolean_t	vm_page_free_verify = TRUE;

uint32_t	vm_lopage_free_count = 0;
uint32_t	vm_lopage_free_limit = 0;
uint32_t	vm_lopage_lowater    = 0;
boolean_t	vm_lopage_refill = FALSE;
boolean_t	vm_lopage_needed = FALSE;

lck_mtx_ext_t	vm_page_queue_lock_ext;
lck_mtx_ext_t	vm_page_queue_free_lock_ext;
lck_mtx_ext_t	vm_purgeable_queue_lock_ext;

int		speculative_age_index = 0;
int		speculative_steal_index = 0;
struct vm_speculative_age_q vm_page_queue_speculative[VM_PAGE_MAX_SPECULATIVE_AGE_Q + 1];


__private_extern__ void		vm_page_init_lck_grp(void);

static void		vm_page_free_prepare(vm_page_t	page);
static vm_page_t	vm_page_grab_fictitious_common(ppnum_t phys_addr);

static void vm_tag_init(void);

uint64_t	vm_min_kernel_and_kext_address = VM_MIN_KERNEL_AND_KEXT_ADDRESS;
uint32_t	vm_packed_from_vm_pages_array_mask = VM_PACKED_FROM_VM_PAGES_ARRAY;
uint32_t	vm_packed_pointer_shift = VM_PACKED_POINTER_SHIFT;

/*
 *	Associated with page of user-allocatable memory is a
 *	page structure.
 */

/*
 *	These variables record the values returned by vm_page_bootstrap,
 *	for debugging purposes.  The implementation of pmap_steal_memory
 *	and pmap_startup here also uses them internally.
 */

vm_offset_t virtual_space_start;
vm_offset_t virtual_space_end;
uint32_t	vm_page_pages;

/*
 *	The vm_page_lookup() routine, which provides for fast
 *	(virtual memory object, offset) to page lookup, employs
 *	the following hash table.  The vm_page_{insert,remove}
 *	routines install and remove associations in the table.
 *	[This table is often called the virtual-to-physical,
 *	or VP, table.]
 */
typedef struct {
	vm_page_packed_t page_list;
#if	MACH_PAGE_HASH_STATS
	int		cur_count;		/* current count */
	int		hi_count;		/* high water mark */
#endif /* MACH_PAGE_HASH_STATS */
} vm_page_bucket_t;


#define BUCKETS_PER_LOCK	16

vm_page_bucket_t *vm_page_buckets;		/* Array of buckets */
unsigned int	vm_page_bucket_count = 0;	/* How big is array? */
unsigned int	vm_page_hash_mask;		/* Mask for hash function */
unsigned int	vm_page_hash_shift;		/* Shift for hash function */
uint32_t	vm_page_bucket_hash;		/* Basic bucket hash */
unsigned int	vm_page_bucket_lock_count = 0;		/* How big is array of locks? */

lck_spin_t	*vm_page_bucket_locks;
lck_spin_t	vm_objects_wired_lock;
lck_spin_t	vm_allocation_sites_lock;

#if VM_PAGE_BUCKETS_CHECK
boolean_t vm_page_buckets_check_ready = FALSE;
#if VM_PAGE_FAKE_BUCKETS
vm_page_bucket_t *vm_page_fake_buckets;	/* decoy buckets */
vm_map_offset_t vm_page_fake_buckets_start, vm_page_fake_buckets_end;
#endif /* VM_PAGE_FAKE_BUCKETS */
#endif /* VM_PAGE_BUCKETS_CHECK */



#if	MACH_PAGE_HASH_STATS
/* This routine is only for debug.  It is intended to be called by
 * hand by a developer using a kernel debugger.  This routine prints
 * out vm_page_hash table statistics to the kernel debug console.
 */
void
hash_debug(void)
{
	int	i;
	int	numbuckets = 0;
	int	highsum = 0;
	int	maxdepth = 0;

	for (i = 0; i < vm_page_bucket_count; i++) {
		if (vm_page_buckets[i].hi_count) {
			numbuckets++;
			highsum += vm_page_buckets[i].hi_count;
			if (vm_page_buckets[i].hi_count > maxdepth)
				maxdepth = vm_page_buckets[i].hi_count;
		}
	}
	printf("Total number of buckets: %d\n", vm_page_bucket_count);
	printf("Number used buckets:     %d = %d%%\n",
		numbuckets, 100*numbuckets/vm_page_bucket_count);
	printf("Number unused buckets:   %d = %d%%\n",
		vm_page_bucket_count - numbuckets,
		100*(vm_page_bucket_count-numbuckets)/vm_page_bucket_count);
	printf("Sum of bucket max depth: %d\n", highsum);
	printf("Average bucket depth:    %d.%2d\n",
		highsum/vm_page_bucket_count,
		highsum%vm_page_bucket_count);
	printf("Maximum bucket depth:    %d\n", maxdepth);
}
#endif /* MACH_PAGE_HASH_STATS */

/*
 *	The virtual page size is currently implemented as a runtime
 *	variable, but is constant once initialized using vm_set_page_size.
 *	This initialization must be done in the machine-dependent
 *	bootstrap sequence, before calling other machine-independent
 *	initializations.
 *
 *	All references to the virtual page size outside this
 *	module must use the PAGE_SIZE, PAGE_MASK and PAGE_SHIFT
 *	constants.
 */
vm_size_t	page_size  = PAGE_SIZE;
vm_size_t	page_mask  = PAGE_MASK;
int		page_shift = PAGE_SHIFT;

/*
 *	Resident page structures are initialized from
 *	a template (see vm_page_alloc).
 *
 *	When adding a new field to the virtual memory
 *	object structure, be sure to add initialization
 *	(see vm_page_bootstrap).
 */
struct vm_page	vm_page_template;

vm_page_t	vm_pages = VM_PAGE_NULL;
vm_page_t	vm_page_array_beginning_addr;
vm_page_t	vm_page_array_ending_addr;

unsigned int	vm_pages_count = 0;
ppnum_t		vm_page_lowest = 0;

/*
 *	Resident pages that represent real memory
 *	are allocated from a set of free lists,
 *	one per color.
 */
unsigned int	vm_colors;
unsigned int    vm_color_mask;			/* mask is == (vm_colors-1) */
unsigned int	vm_cache_geometry_colors = 0;	/* set by hw dependent code during startup */
unsigned int	vm_free_magazine_refill_limit = 0;


struct vm_page_queue_free_head {
	vm_page_queue_head_t	qhead;
} __attribute__((aligned(VM_PACKED_POINTER_ALIGNMENT)));

struct vm_page_queue_free_head	vm_page_queue_free[MAX_COLORS];


unsigned int	vm_page_free_wanted;
unsigned int	vm_page_free_wanted_privileged;
#if CONFIG_SECLUDED_MEMORY
unsigned int	vm_page_free_wanted_secluded;
#endif /* CONFIG_SECLUDED_MEMORY */
unsigned int	vm_page_free_count;

/*
 *	Occasionally, the virtual memory system uses
 *	resident page structures that do not refer to
 *	real pages, for example to leave a page with
 *	important state information in the VP table.
 *
 *	These page structures are allocated the way
 *	most other kernel structures are.
 */
zone_t	vm_page_array_zone;
zone_t	vm_page_zone;
vm_locks_array_t vm_page_locks;
decl_lck_mtx_data(,vm_page_alloc_lock)
lck_mtx_ext_t vm_page_alloc_lock_ext;

unsigned int io_throttle_zero_fill;

unsigned int	vm_page_local_q_count = 0;
unsigned int	vm_page_local_q_soft_limit = 250;
unsigned int	vm_page_local_q_hard_limit = 500;
struct vplq     *vm_page_local_q = NULL;

/* N.B. Guard and fictitious pages must not
 * be assigned a zero phys_page value.
 */
/*
 *	Fictitious pages don't have a physical address,
 *	but we must initialize phys_page to something.
 *	For debugging, this should be a strange value
 *	that the pmap module can recognize in assertions.
 */
ppnum_t vm_page_fictitious_addr = (ppnum_t) -1;

/*
 *	Guard pages are not accessible so they don't
 * 	need a physical address, but we need to enter
 *	one in the pmap.
 *	Let's make it recognizable and make sure that
 *	we don't use a real physical page with that
 *	physical address.
 */
ppnum_t vm_page_guard_addr = (ppnum_t) -2;

/*
 *	Resident page structures are also chained on
 *	queues that are used by the page replacement
 *	system (pageout daemon).  These queues are
 *	defined here, but are shared by the pageout
 *	module.  The inactive queue is broken into 
 *	file backed and anonymous for convenience as the 
 *	pageout daemon often assignes a higher 
 *	importance to anonymous pages (less likely to pick)
 */
vm_page_queue_head_t	vm_page_queue_active __attribute__((aligned(VM_PACKED_POINTER_ALIGNMENT)));
vm_page_queue_head_t	vm_page_queue_inactive __attribute__((aligned(VM_PACKED_POINTER_ALIGNMENT)));
#if CONFIG_SECLUDED_MEMORY
vm_page_queue_head_t	vm_page_queue_secluded __attribute__((aligned(VM_PACKED_POINTER_ALIGNMENT)));
#endif /* CONFIG_SECLUDED_MEMORY */
vm_page_queue_head_t	vm_page_queue_anonymous __attribute__((aligned(VM_PACKED_POINTER_ALIGNMENT)));	/* inactive memory queue for anonymous pages */
vm_page_queue_head_t	vm_page_queue_throttled __attribute__((aligned(VM_PACKED_POINTER_ALIGNMENT)));

queue_head_t	vm_objects_wired;

#if CONFIG_BACKGROUND_QUEUE
vm_page_queue_head_t	vm_page_queue_background __attribute__((aligned(VM_PACKED_POINTER_ALIGNMENT)));
uint32_t	vm_page_background_limit;
uint32_t	vm_page_background_target;
uint32_t	vm_page_background_count;
uint64_t	vm_page_background_promoted_count;

uint32_t	vm_page_background_internal_count;
uint32_t	vm_page_background_external_count;

uint32_t	vm_page_background_mode;
uint32_t	vm_page_background_exclude_external;
#endif

unsigned int	vm_page_active_count;
unsigned int	vm_page_inactive_count;
#if CONFIG_SECLUDED_MEMORY
unsigned int	vm_page_secluded_count;
unsigned int	vm_page_secluded_count_free;
unsigned int	vm_page_secluded_count_inuse;
#endif /* CONFIG_SECLUDED_MEMORY */
unsigned int	vm_page_anonymous_count;
unsigned int	vm_page_throttled_count;
unsigned int	vm_page_speculative_count;

unsigned int	vm_page_wire_count;
unsigned int	vm_page_stolen_count;
unsigned int	vm_page_wire_count_initial;
unsigned int	vm_page_pages_initial;
unsigned int	vm_page_gobble_count = 0;

#define	VM_PAGE_WIRE_COUNT_WARNING	0
#define VM_PAGE_GOBBLE_COUNT_WARNING	0

unsigned int	vm_page_purgeable_count = 0; /* # of pages purgeable now */
unsigned int	vm_page_purgeable_wired_count = 0; /* # of purgeable pages that are wired now */
uint64_t	vm_page_purged_count = 0;    /* total count of purged pages */

unsigned int	vm_page_xpmapped_external_count = 0;
unsigned int	vm_page_external_count = 0;
unsigned int	vm_page_internal_count = 0;
unsigned int	vm_page_pageable_external_count = 0;
unsigned int	vm_page_pageable_internal_count = 0;

#if DEVELOPMENT || DEBUG
unsigned int	vm_page_speculative_recreated = 0;
unsigned int	vm_page_speculative_created = 0;
unsigned int	vm_page_speculative_used = 0;
#endif

vm_page_queue_head_t    vm_page_queue_cleaned __attribute__((aligned(VM_PACKED_POINTER_ALIGNMENT)));

unsigned int	vm_page_cleaned_count = 0;
unsigned int	vm_pageout_enqueued_cleaned = 0;

uint64_t	max_valid_dma_address = 0xffffffffffffffffULL;
ppnum_t		max_valid_low_ppnum = 0xffffffff;


/*
 *	Several page replacement parameters are also
 *	shared with this module, so that page allocation
 *	(done here in vm_page_alloc) can trigger the
 *	pageout daemon.
 */
unsigned int	vm_page_free_target = 0;
unsigned int	vm_page_free_min = 0;
unsigned int	vm_page_throttle_limit = 0;
unsigned int	vm_page_inactive_target = 0;
#if CONFIG_SECLUDED_MEMORY
unsigned int	vm_page_secluded_target = 0;
#endif /* CONFIG_SECLUDED_MEMORY */
unsigned int	vm_page_anonymous_min = 0;
unsigned int	vm_page_inactive_min = 0;
unsigned int	vm_page_free_reserved = 0;
unsigned int	vm_page_throttle_count = 0;


/*
 *	The VM system has a couple of heuristics for deciding
 *	that pages are "uninteresting" and should be placed
 *	on the inactive queue as likely candidates for replacement.
 *	These variables let the heuristics be controlled at run-time
 *	to make experimentation easier.
 */

boolean_t vm_page_deactivate_hint = TRUE;

struct vm_page_stats_reusable vm_page_stats_reusable;
	
/*
 *	vm_set_page_size:
 *
 *	Sets the page size, perhaps based upon the memory
 *	size.  Must be called before any use of page-size
 *	dependent functions.
 *
 *	Sets page_shift and page_mask from page_size.
 */
void
vm_set_page_size(void)
{
	page_size  = PAGE_SIZE;
	page_mask  = PAGE_MASK;
	page_shift = PAGE_SHIFT;

	if ((page_mask & page_size) != 0)
		panic("vm_set_page_size: page size not a power of two");

	for (page_shift = 0; ; page_shift++)
		if ((1U << page_shift) == page_size)
			break;
}

#define COLOR_GROUPS_TO_STEAL	4


/* Called once during statup, once the cache geometry is known.
 */
static void
vm_page_set_colors( void )
{
	unsigned int	n, override;
	
	if ( PE_parse_boot_argn("colors", &override, sizeof (override)) )		/* colors specified as a boot-arg? */
		n = override;	
	else if ( vm_cache_geometry_colors )			/* do we know what the cache geometry is? */
		n = vm_cache_geometry_colors;
	else	n = DEFAULT_COLORS;				/* use default if all else fails */

	if ( n == 0 )
		n = 1;
	if ( n > MAX_COLORS )
		n = MAX_COLORS;
		
	/* the count must be a power of 2  */
	if ( ( n & (n - 1)) != 0  )
		panic("vm_page_set_colors");
	
	vm_colors = n;
	vm_color_mask = n - 1;

	vm_free_magazine_refill_limit = vm_colors * COLOR_GROUPS_TO_STEAL;
}


lck_grp_t		vm_page_lck_grp_free;
lck_grp_t		vm_page_lck_grp_queue;
lck_grp_t		vm_page_lck_grp_local;
lck_grp_t		vm_page_lck_grp_purge;
lck_grp_t		vm_page_lck_grp_alloc;
lck_grp_t		vm_page_lck_grp_bucket;
lck_grp_attr_t		vm_page_lck_grp_attr;
lck_attr_t		vm_page_lck_attr;


__private_extern__ void
vm_page_init_lck_grp(void)
{
	/*
	 * initialze the vm_page lock world
	 */
	lck_grp_attr_setdefault(&vm_page_lck_grp_attr);
	lck_grp_init(&vm_page_lck_grp_free, "vm_page_free", &vm_page_lck_grp_attr);
	lck_grp_init(&vm_page_lck_grp_queue, "vm_page_queue", &vm_page_lck_grp_attr);
	lck_grp_init(&vm_page_lck_grp_local, "vm_page_queue_local", &vm_page_lck_grp_attr);
	lck_grp_init(&vm_page_lck_grp_purge, "vm_page_purge", &vm_page_lck_grp_attr);
	lck_grp_init(&vm_page_lck_grp_alloc, "vm_page_alloc", &vm_page_lck_grp_attr);
	lck_grp_init(&vm_page_lck_grp_bucket, "vm_page_bucket", &vm_page_lck_grp_attr);
	lck_attr_setdefault(&vm_page_lck_attr);
	lck_mtx_init_ext(&vm_page_alloc_lock, &vm_page_alloc_lock_ext, &vm_page_lck_grp_alloc, &vm_page_lck_attr);

	vm_compressor_init_locks();
}

void
vm_page_init_local_q()
{
	unsigned int		num_cpus;
	unsigned int		i;
	struct vplq     	*t_local_q;

	num_cpus = ml_get_max_cpus();

	/*
	 * no point in this for a uni-processor system
	 */
	if (num_cpus >= 2) {
		t_local_q = (struct vplq *)kalloc(num_cpus * sizeof(struct vplq));

		for (i = 0; i < num_cpus; i++) {
			struct vpl	*lq;

			lq = &t_local_q[i].vpl_un.vpl;
			VPL_LOCK_INIT(lq, &vm_page_lck_grp_local, &vm_page_lck_attr);
			vm_page_queue_init(&lq->vpl_queue);
			lq->vpl_count = 0;
			lq->vpl_internal_count = 0;
			lq->vpl_external_count = 0;
		}
		vm_page_local_q_count = num_cpus;

		vm_page_local_q = (struct vplq *)t_local_q;
	}
}


/*
 *	vm_page_bootstrap:
 *
 *	Initializes the resident memory module.
 *
 *	Allocates memory for the page cells, and
 *	for the object/offset-to-page hash table headers.
 *	Each page cell is initialized and placed on the free list.
 *	Returns the range of available kernel virtual memory.
 */

void
vm_page_bootstrap(
	vm_offset_t		*startp,
	vm_offset_t		*endp)
{
	vm_page_t		m;
	unsigned int		i;
	unsigned int		log1;
	unsigned int		log2;
	unsigned int		size;

	/*
	 *	Initialize the vm_page template.
	 */

	m = &vm_page_template;
	bzero(m, sizeof (*m));

#if CONFIG_BACKGROUND_QUEUE
	m->vm_page_backgroundq.next = 0;
	m->vm_page_backgroundq.prev = 0;
	m->vm_page_in_background = FALSE;
	m->vm_page_on_backgroundq = FALSE;
#endif

	VM_PAGE_ZERO_PAGEQ_ENTRY(m);
	m->listq.next = 0;
	m->listq.prev = 0;
	m->next_m = 0;

	m->vm_page_object = 0;			/* reset later */
	m->offset = (vm_object_offset_t) -1;	/* reset later */

	m->wire_count = 0;
	m->vm_page_q_state = VM_PAGE_NOT_ON_Q;
	m->laundry = FALSE;
	m->reference = FALSE;
	m->gobbled = FALSE;
	m->private = FALSE;
	m->__unused_pageq_bits = 0;

	VM_PAGE_SET_PHYS_PAGE(m, 0);		/* reset later */
	m->busy = TRUE;
	m->wanted = FALSE;
	m->tabled = FALSE;
	m->hashed = FALSE;
	m->fictitious = FALSE;
	m->pmapped = FALSE;
	m->wpmapped = FALSE;
	m->free_when_done = FALSE;
	m->absent = FALSE;
	m->error = FALSE;
	m->dirty = FALSE;
	m->cleaning = FALSE;
	m->precious = FALSE;
	m->clustered = FALSE;
	m->overwriting = FALSE;
	m->restart = FALSE;
	m->unusual = FALSE;
	m->encrypted = FALSE;
	m->encrypted_cleaning = FALSE;
	m->cs_validated = FALSE;
	m->cs_tainted = FALSE;
	m->cs_nx = FALSE;
	m->no_cache = FALSE;
	m->reusable = FALSE;
	m->slid = FALSE;
	m->xpmapped = FALSE;
	m->written_by_kernel = FALSE;
	m->__unused_object_bits = 0;

	/*
	 *	Initialize the page queues.
	 */
	vm_page_init_lck_grp();
	
	lck_mtx_init_ext(&vm_page_queue_free_lock, &vm_page_queue_free_lock_ext, &vm_page_lck_grp_free, &vm_page_lck_attr);
	lck_mtx_init_ext(&vm_page_queue_lock, &vm_page_queue_lock_ext, &vm_page_lck_grp_queue, &vm_page_lck_attr);
	lck_mtx_init_ext(&vm_purgeable_queue_lock, &vm_purgeable_queue_lock_ext, &vm_page_lck_grp_purge, &vm_page_lck_attr);
    
	for (i = 0; i < PURGEABLE_Q_TYPE_MAX; i++) {
		int group;

		purgeable_queues[i].token_q_head = 0;
		purgeable_queues[i].token_q_tail = 0;
		for (group = 0; group < NUM_VOLATILE_GROUPS; group++)
		        queue_init(&purgeable_queues[i].objq[group]);

		purgeable_queues[i].type = i;
		purgeable_queues[i].new_pages = 0;
#if MACH_ASSERT
		purgeable_queues[i].debug_count_tokens = 0;
		purgeable_queues[i].debug_count_objects = 0;
#endif
	};
	purgeable_nonvolatile_count = 0;
	queue_init(&purgeable_nonvolatile_queue);
    
	for (i = 0; i < MAX_COLORS; i++ )
		vm_page_queue_init(&vm_page_queue_free[i].qhead);

	vm_page_queue_init(&vm_lopage_queue_free);
	vm_page_queue_init(&vm_page_queue_active);
	vm_page_queue_init(&vm_page_queue_inactive);
#if CONFIG_SECLUDED_MEMORY
	vm_page_queue_init(&vm_page_queue_secluded);
#endif /* CONFIG_SECLUDED_MEMORY */
	vm_page_queue_init(&vm_page_queue_cleaned);
	vm_page_queue_init(&vm_page_queue_throttled);
	vm_page_queue_init(&vm_page_queue_anonymous);
	queue_init(&vm_objects_wired);

	for ( i = 0; i <= VM_PAGE_MAX_SPECULATIVE_AGE_Q; i++ ) {
		vm_page_queue_init(&vm_page_queue_speculative[i].age_q);

		vm_page_queue_speculative[i].age_ts.tv_sec = 0;
		vm_page_queue_speculative[i].age_ts.tv_nsec = 0;
	}
#if CONFIG_BACKGROUND_QUEUE
	vm_page_queue_init(&vm_page_queue_background);

	vm_page_background_count = 0;
	vm_page_background_internal_count = 0;
	vm_page_background_external_count = 0;
	vm_page_background_promoted_count = 0;

	vm_page_background_target = (unsigned int)(atop_64(max_mem) / 25);

	if (vm_page_background_target > VM_PAGE_BACKGROUND_TARGET_MAX)
		vm_page_background_target = VM_PAGE_BACKGROUND_TARGET_MAX;
	vm_page_background_limit = vm_page_background_target + 256;

	vm_page_background_mode = VM_PAGE_BG_LEVEL_1;
	vm_page_background_exclude_external = 0;

	PE_parse_boot_argn("vm_page_bg_mode", &vm_page_background_mode, sizeof(vm_page_background_mode));
	PE_parse_boot_argn("vm_page_bg_exclude_external", &vm_page_background_exclude_external, sizeof(vm_page_background_exclude_external));
	PE_parse_boot_argn("vm_page_bg_target", &vm_page_background_target, sizeof(vm_page_background_target));
	PE_parse_boot_argn("vm_page_bg_limit", &vm_page_background_limit, sizeof(vm_page_background_limit));

	if (vm_page_background_mode > VM_PAGE_BG_LEVEL_3)
		vm_page_background_mode = VM_PAGE_BG_LEVEL_1;

	if (vm_page_background_limit <= vm_page_background_target)
		vm_page_background_limit = vm_page_background_target + 256;
#endif
	vm_page_free_wanted = 0;
	vm_page_free_wanted_privileged = 0;
#if CONFIG_SECLUDED_MEMORY
	vm_page_free_wanted_secluded = 0;
#endif /* CONFIG_SECLUDED_MEMORY */
	
	vm_page_set_colors();

	bzero(vm_page_inactive_states, sizeof(vm_page_inactive_states));
	vm_page_inactive_states[VM_PAGE_ON_INACTIVE_INTERNAL_Q] = 1;
	vm_page_inactive_states[VM_PAGE_ON_INACTIVE_EXTERNAL_Q] = 1;
	vm_page_inactive_states[VM_PAGE_ON_INACTIVE_CLEANED_Q] = 1;

	bzero(vm_page_pageable_states, sizeof(vm_page_pageable_states));
	vm_page_pageable_states[VM_PAGE_ON_INACTIVE_INTERNAL_Q] = 1;
	vm_page_pageable_states[VM_PAGE_ON_INACTIVE_EXTERNAL_Q] = 1;
	vm_page_pageable_states[VM_PAGE_ON_INACTIVE_CLEANED_Q] = 1;
	vm_page_pageable_states[VM_PAGE_ON_ACTIVE_Q] = 1;
	vm_page_pageable_states[VM_PAGE_ON_SPECULATIVE_Q] = 1;
	vm_page_pageable_states[VM_PAGE_ON_THROTTLED_Q] = 1;
#if CONFIG_SECLUDED_MEMORY
	vm_page_pageable_states[VM_PAGE_ON_SECLUDED_Q] = 1;
#endif /* CONFIG_SECLUDED_MEMORY */

	bzero(vm_page_non_speculative_pageable_states, sizeof(vm_page_non_speculative_pageable_states));
	vm_page_non_speculative_pageable_states[VM_PAGE_ON_INACTIVE_INTERNAL_Q] = 1;
	vm_page_non_speculative_pageable_states[VM_PAGE_ON_INACTIVE_EXTERNAL_Q] = 1;
	vm_page_non_speculative_pageable_states[VM_PAGE_ON_INACTIVE_CLEANED_Q] = 1;
	vm_page_non_speculative_pageable_states[VM_PAGE_ON_ACTIVE_Q] = 1;
	vm_page_non_speculative_pageable_states[VM_PAGE_ON_THROTTLED_Q] = 1;
#if CONFIG_SECLUDED_MEMORY
	vm_page_non_speculative_pageable_states[VM_PAGE_ON_SECLUDED_Q] = 1;
#endif /* CONFIG_SECLUDED_MEMORY */
	
	bzero(vm_page_active_or_inactive_states, sizeof(vm_page_active_or_inactive_states));
	vm_page_active_or_inactive_states[VM_PAGE_ON_INACTIVE_INTERNAL_Q] = 1;
	vm_page_active_or_inactive_states[VM_PAGE_ON_INACTIVE_EXTERNAL_Q] = 1;
	vm_page_active_or_inactive_states[VM_PAGE_ON_INACTIVE_CLEANED_Q] = 1;
	vm_page_active_or_inactive_states[VM_PAGE_ON_ACTIVE_Q] = 1;
#if CONFIG_SECLUDED_MEMORY
	vm_page_active_or_inactive_states[VM_PAGE_ON_SECLUDED_Q] = 1;
#endif /* CONFIG_SECLUDED_MEMORY */


	/*
	 *	Steal memory for the map and zone subsystems.
	 */
#if CONFIG_GZALLOC
	gzalloc_configure();
#endif
	kernel_debug_string_early("vm_map_steal_memory");
	vm_map_steal_memory();

	/*
	 *	Allocate (and initialize) the virtual-to-physical
	 *	table hash buckets.
	 *
	 *	The number of buckets should be a power of two to
	 *	get a good hash function.  The following computation
	 *	chooses the first power of two that is greater
	 *	than the number of physical pages in the system.
	 */

	if (vm_page_bucket_count == 0) {
		unsigned int npages = pmap_free_pages();

		vm_page_bucket_count = 1;
		while (vm_page_bucket_count < npages)
			vm_page_bucket_count <<= 1;
	}
	vm_page_bucket_lock_count = (vm_page_bucket_count + BUCKETS_PER_LOCK - 1) / BUCKETS_PER_LOCK;

	vm_page_hash_mask = vm_page_bucket_count - 1;

	/*
	 *	Calculate object shift value for hashing algorithm:
	 *		O = log2(sizeof(struct vm_object))
	 *		B = log2(vm_page_bucket_count)
	 *	        hash shifts the object left by
	 *		B/2 - O
	 */
	size = vm_page_bucket_count;
	for (log1 = 0; size > 1; log1++) 
		size /= 2;
	size = sizeof(struct vm_object);
	for (log2 = 0; size > 1; log2++) 
		size /= 2;
	vm_page_hash_shift = log1/2 - log2 + 1;
	
	vm_page_bucket_hash = 1 << ((log1 + 1) >> 1);		/* Get (ceiling of sqrt of table size) */
	vm_page_bucket_hash |= 1 << ((log1 + 1) >> 2);		/* Get (ceiling of quadroot of table size) */
	vm_page_bucket_hash |= 1;							/* Set bit and add 1 - always must be 1 to insure unique series */

	if (vm_page_hash_mask & vm_page_bucket_count)
		printf("vm_page_bootstrap: WARNING -- strange page hash\n");

#if VM_PAGE_BUCKETS_CHECK
#if VM_PAGE_FAKE_BUCKETS
	/*
	 * Allocate a decoy set of page buckets, to detect
	 * any stomping there.
	 */
	vm_page_fake_buckets = (vm_page_bucket_t *)
		pmap_steal_memory(vm_page_bucket_count *
				  sizeof(vm_page_bucket_t));
	vm_page_fake_buckets_start = (vm_map_offset_t) vm_page_fake_buckets;
	vm_page_fake_buckets_end =
		vm_map_round_page((vm_page_fake_buckets_start +
				   (vm_page_bucket_count *
				    sizeof (vm_page_bucket_t))),
				  PAGE_MASK);
	char *cp;
	for (cp = (char *)vm_page_fake_buckets_start;
	     cp < (char *)vm_page_fake_buckets_end;
	     cp++) {
		*cp = 0x5a;
	}
#endif /* VM_PAGE_FAKE_BUCKETS */
#endif /* VM_PAGE_BUCKETS_CHECK */

	kernel_debug_string_early("vm_page_buckets");
	vm_page_buckets = (vm_page_bucket_t *)
		pmap_steal_memory(vm_page_bucket_count *
				  sizeof(vm_page_bucket_t));

	kernel_debug_string_early("vm_page_bucket_locks");
	vm_page_bucket_locks = (lck_spin_t *)
		pmap_steal_memory(vm_page_bucket_lock_count *
				  sizeof(lck_spin_t));

	for (i = 0; i < vm_page_bucket_count; i++) {
		vm_page_bucket_t *bucket = &vm_page_buckets[i];

		bucket->page_list = VM_PAGE_PACK_PTR(VM_PAGE_NULL);
#if     MACH_PAGE_HASH_STATS
		bucket->cur_count = 0;
		bucket->hi_count = 0;
#endif /* MACH_PAGE_HASH_STATS */
	}

	for (i = 0; i < vm_page_bucket_lock_count; i++)
	        lck_spin_init(&vm_page_bucket_locks[i], &vm_page_lck_grp_bucket, &vm_page_lck_attr);

	lck_spin_init(&vm_objects_wired_lock, &vm_page_lck_grp_bucket, &vm_page_lck_attr);
	lck_spin_init(&vm_allocation_sites_lock, &vm_page_lck_grp_bucket, &vm_page_lck_attr);
	vm_tag_init();

#if VM_PAGE_BUCKETS_CHECK
	vm_page_buckets_check_ready = TRUE;
#endif /* VM_PAGE_BUCKETS_CHECK */

	/*
	 *	Machine-dependent code allocates the resident page table.
	 *	It uses vm_page_init to initialize the page frames.
	 *	The code also returns to us the virtual space available
	 *	to the kernel.  We don't trust the pmap module
	 *	to get the alignment right.
	 */

	kernel_debug_string_early("pmap_startup");
	pmap_startup(&virtual_space_start, &virtual_space_end);
	virtual_space_start = round_page(virtual_space_start);
	virtual_space_end = trunc_page(virtual_space_end);

	*startp = virtual_space_start;
	*endp = virtual_space_end;

	/*
	 *	Compute the initial "wire" count.
	 *	Up until now, the pages which have been set aside are not under 
	 *	the VM system's control, so although they aren't explicitly
	 *	wired, they nonetheless can't be moved. At this moment,
	 *	all VM managed pages are "free", courtesy of pmap_startup.
	 */
	assert((unsigned int) atop_64(max_mem) == atop_64(max_mem));
	vm_page_wire_count = ((unsigned int) atop_64(max_mem)) - vm_page_free_count - vm_lopage_free_count;	/* initial value */
#if CONFIG_SECLUDED_MEMORY
	vm_page_wire_count -= vm_page_secluded_count;
#endif
	vm_page_wire_count_initial = vm_page_wire_count;
	vm_page_pages_initial = vm_page_pages;

	printf("vm_page_bootstrap: %d free pages and %d wired pages\n",
	       vm_page_free_count, vm_page_wire_count);

	kernel_debug_string_early("vm_page_bootstrap complete");
	simple_lock_init(&vm_paging_lock, 0);
}

#ifndef	MACHINE_PAGES
/*
 *	We implement pmap_steal_memory and pmap_startup with the help
 *	of two simpler functions, pmap_virtual_space and pmap_next_page.
 */

void *
pmap_steal_memory(
	vm_size_t size)
{
	vm_offset_t addr, vaddr;
	ppnum_t	phys_page;

	/*
	 *	We round the size to a round multiple.
	 */

	size = (size + sizeof (void *) - 1) &~ (sizeof (void *) - 1);

	/*
	 *	If this is the first call to pmap_steal_memory,
	 *	we have to initialize ourself.
	 */

	if (virtual_space_start == virtual_space_end) {
		pmap_virtual_space(&virtual_space_start, &virtual_space_end);

		/*
		 *	The initial values must be aligned properly, and
		 *	we don't trust the pmap module to do it right.
		 */

		virtual_space_start = round_page(virtual_space_start);
		virtual_space_end = trunc_page(virtual_space_end);
	}

	/*
	 *	Allocate virtual memory for this request.
	 */

	addr = virtual_space_start;
	virtual_space_start += size;

	//kprintf("pmap_steal_memory: %08lX - %08lX; size=%08lX\n", (long)addr, (long)virtual_space_start, (long)size);	/* (TEST/DEBUG) */

	/*
	 *	Allocate and map physical pages to back new virtual pages.
	 */

	for (vaddr = round_page(addr);
	     vaddr < addr + size;
	     vaddr += PAGE_SIZE) {

		if (!pmap_next_page_hi(&phys_page))
			panic("pmap_steal_memory() size: 0x%llx\n", (uint64_t)size);

		/*
		 *	XXX Logically, these mappings should be wired,
		 *	but some pmap modules barf if they are.
		 */
#if defined(__LP64__)
		pmap_pre_expand(kernel_pmap, vaddr);
#endif

		pmap_enter(kernel_pmap, vaddr, phys_page,
			   VM_PROT_READ|VM_PROT_WRITE, VM_PROT_NONE,
				VM_WIMG_USE_DEFAULT, FALSE);
		/*
		 * Account for newly stolen memory
		 */
		vm_page_wire_count++;
		vm_page_stolen_count++;
	}

	return (void *) addr;
}

#if CONFIG_SECLUDED_MEMORY
/* boot-args to control secluded memory */
unsigned int secluded_mem_mb = 0;	/* # of MBs of RAM to seclude */
int secluded_for_iokit = 1;		/* IOKit can use secluded memory */
int secluded_for_apps = 1;		/* apps can use secluded memory */
int secluded_for_filecache = 2;		/* filecache can use seclude memory */
#if 11
int secluded_for_fbdp = 0;
#endif
int secluded_aging_policy = SECLUDED_AGING_BEFORE_ACTIVE;
#endif /* CONFIG_SECLUDED_MEMORY */




void vm_page_release_startup(vm_page_t mem);
void
pmap_startup(
	vm_offset_t *startp,
	vm_offset_t *endp)
{
	unsigned int i, npages, pages_initialized, fill, fillval;
	ppnum_t		phys_page;
	addr64_t	tmpaddr;

#if    defined(__LP64__)
	/*
	 * make sure we are aligned on a 64 byte boundary
	 * for VM_PAGE_PACK_PTR (it clips off the low-order
	 * 6 bits of the pointer)
	 */
	if (virtual_space_start != virtual_space_end)
		virtual_space_start = round_page(virtual_space_start);
#endif

	/*
	 *	We calculate how many page frames we will have
	 *	and then allocate the page structures in one chunk.
	 */

	tmpaddr = (addr64_t)pmap_free_pages() * (addr64_t)PAGE_SIZE;	/* Get the amount of memory left */
	tmpaddr = tmpaddr + (addr64_t)(round_page(virtual_space_start) - virtual_space_start);	/* Account for any slop */
	npages = (unsigned int)(tmpaddr / (addr64_t)(PAGE_SIZE + sizeof(*vm_pages)));	/* Figure size of all vm_page_ts, including enough to hold the vm_page_ts */

	vm_pages = (vm_page_t) pmap_steal_memory(npages * sizeof *vm_pages);

	/*
	 *	Initialize the page frames.
	 */
	kernel_debug_string_early("Initialize the page frames");

	vm_page_array_beginning_addr = &vm_pages[0];
	vm_page_array_ending_addr = &vm_pages[npages];


	for (i = 0, pages_initialized = 0; i < npages; i++) {
		if (!pmap_next_page(&phys_page))
			break;
		if (pages_initialized == 0 || phys_page < vm_page_lowest)
			vm_page_lowest = phys_page;

		vm_page_init(&vm_pages[i], phys_page, FALSE);
		vm_page_pages++;
		pages_initialized++;
	}
	vm_pages_count = pages_initialized;

#if    defined(__LP64__)

	if ((vm_page_t)(VM_PAGE_UNPACK_PTR(VM_PAGE_PACK_PTR(&vm_pages[0]))) != &vm_pages[0])
		panic("VM_PAGE_PACK_PTR failed on &vm_pages[0] - %p", (void *)&vm_pages[0]);

	if ((vm_page_t)(VM_PAGE_UNPACK_PTR(VM_PAGE_PACK_PTR(&vm_pages[vm_pages_count-1]))) != &vm_pages[vm_pages_count-1])
		panic("VM_PAGE_PACK_PTR failed on &vm_pages[vm_pages_count-1] - %p", (void *)&vm_pages[vm_pages_count-1]);
#endif
	kernel_debug_string_early("page fill/release");
	/*
	 * Check if we want to initialize pages to a known value
	 */
	fill = 0;								/* Assume no fill */
	if (PE_parse_boot_argn("fill", &fillval, sizeof (fillval))) fill = 1;			/* Set fill */
#if	DEBUG
	/* This slows down booting the DEBUG kernel, particularly on
	 * large memory systems, but is worthwhile in deterministically
	 * trapping uninitialized memory usage.
	 */
	if (fill == 0) {
		fill = 1;
		fillval = 0xDEB8F177;
	}
#endif
	if (fill)
		kprintf("Filling vm_pages with pattern: 0x%x\n", fillval);

#if CONFIG_SECLUDED_MEMORY
	/* default: no secluded mem */
	secluded_mem_mb = 0;
	if (max_mem > 1*1024*1024*1024) {
		/* default to 90MB for devices with > 1GB of RAM */
		secluded_mem_mb = 90;
	}
	/* override with value from device tree, if provided */
	PE_get_default("kern.secluded_mem_mb",
		       &secluded_mem_mb, sizeof(secluded_mem_mb));
	/* override with value from boot-args, if provided */
	PE_parse_boot_argn("secluded_mem_mb",
			   &secluded_mem_mb,
			   sizeof (secluded_mem_mb));

	vm_page_secluded_target = (unsigned int)
		((secluded_mem_mb * 1024ULL * 1024ULL) / PAGE_SIZE);
	PE_parse_boot_argn("secluded_for_iokit",
			   &secluded_for_iokit,
			   sizeof (secluded_for_iokit));
	PE_parse_boot_argn("secluded_for_apps",
			   &secluded_for_apps,
			   sizeof (secluded_for_apps));
	PE_parse_boot_argn("secluded_for_filecache",
			   &secluded_for_filecache,
			   sizeof (secluded_for_filecache));
#if 11
	PE_parse_boot_argn("secluded_for_fbdp",
			   &secluded_for_fbdp,
			   sizeof (secluded_for_fbdp));
#endif
	PE_parse_boot_argn("secluded_aging_policy",
			   &secluded_aging_policy,
			   sizeof (secluded_aging_policy));
#endif /* CONFIG_SECLUDED_MEMORY */

	// -debug code remove
	if (2 == vm_himemory_mode) {
		// free low -> high so high is preferred
		for (i = 1; i <= pages_initialized; i++) {
			if(fill) fillPage(VM_PAGE_GET_PHYS_PAGE(&vm_pages[i - 1]), fillval);		/* Fill the page with a know value if requested at boot */
			vm_page_release_startup(&vm_pages[i - 1]);
		}
	}
	else
	// debug code remove-

	/*
	 * Release pages in reverse order so that physical pages
	 * initially get allocated in ascending addresses. This keeps
	 * the devices (which must address physical memory) happy if
	 * they require several consecutive pages.
	 */
	for (i = pages_initialized; i > 0; i--) {
		if(fill) fillPage(VM_PAGE_GET_PHYS_PAGE(&vm_pages[i - 1]), fillval);		/* Fill the page with a know value if requested at boot */			
		vm_page_release_startup(&vm_pages[i - 1]);
	}

	VM_CHECK_MEMORYSTATUS;
	
#if 0
	{
		vm_page_t xx, xxo, xxl;
		int i, j, k, l;
	
		j = 0;													/* (BRINGUP) */
		xxl = 0;
		
		for( i = 0; i < vm_colors; i++ ) {
			queue_iterate(&vm_page_queue_free[i].qhead,
				      xx,
				      vm_page_t,
				      pageq) {	/* BRINGUP */
				j++;												/* (BRINGUP) */
				if(j > vm_page_free_count) {						/* (BRINGUP) */
					panic("pmap_startup: too many pages, xx = %08X, xxl = %08X\n", xx, xxl);
				}
				
				l = vm_page_free_count - j;							/* (BRINGUP) */
				k = 0;												/* (BRINGUP) */
				
				if(((j - 1) & 0xFFFF) == 0) kprintf("checking number %d of %d\n", j, vm_page_free_count);

				for(xxo = xx->pageq.next; xxo != &vm_page_queue_free[i].qhead; xxo = xxo->pageq.next) {	/* (BRINGUP) */
					k++;
					if(k > l) panic("pmap_startup: too many in secondary check %d %d\n", k, l);
					if((xx->phys_page & 0xFFFFFFFF) == (xxo->phys_page & 0xFFFFFFFF)) {	/* (BRINGUP) */
						panic("pmap_startup: duplicate physaddr, xx = %08X, xxo = %08X\n", xx, xxo);
					}
				}

				xxl = xx;
			}
		}
		
		if(j != vm_page_free_count) {						/* (BRINGUP) */
			panic("pmap_startup: vm_page_free_count does not match, calc =  %d, vm_page_free_count = %08X\n", j, vm_page_free_count);
		}
	}
#endif


	/*
	 *	We have to re-align virtual_space_start,
	 *	because pmap_steal_memory has been using it.
	 */

	virtual_space_start = round_page(virtual_space_start);

	*startp = virtual_space_start;
	*endp = virtual_space_end;
}
#endif	/* MACHINE_PAGES */

/*
 *	Routine:	vm_page_module_init
 *	Purpose:
 *		Second initialization pass, to be done after
 *		the basic VM system is ready.
 */
void
vm_page_module_init(void)
{
	uint64_t vm_page_zone_pages, vm_page_array_zone_data_size;
	vm_size_t	vm_page_with_ppnum_size;

	vm_page_array_zone = zinit((vm_size_t) sizeof(struct vm_page),
			     0, PAGE_SIZE, "vm pages array");

	zone_change(vm_page_array_zone, Z_CALLERACCT, FALSE);
	zone_change(vm_page_array_zone, Z_EXPAND, FALSE);
	zone_change(vm_page_array_zone, Z_EXHAUST, TRUE);
	zone_change(vm_page_array_zone, Z_FOREIGN, TRUE);
	zone_change(vm_page_array_zone, Z_GZALLOC_EXEMPT, TRUE);
	/*
	 * Adjust zone statistics to account for the real pages allocated
	 * in vm_page_create(). [Q: is this really what we want?]
	 */
	vm_page_array_zone->count += vm_page_pages;
	vm_page_array_zone->sum_count += vm_page_pages;
	vm_page_array_zone_data_size = vm_page_pages * vm_page_array_zone->elem_size;
	vm_page_array_zone->cur_size += vm_page_array_zone_data_size;
	vm_page_zone_pages = ((round_page(vm_page_array_zone_data_size)) / PAGE_SIZE);
	OSAddAtomic64(vm_page_zone_pages, &(vm_page_array_zone->page_count));
	/* since zone accounts for these, take them out of stolen */
	VM_PAGE_MOVE_STOLEN(vm_page_zone_pages);

	vm_page_with_ppnum_size = (sizeof(struct vm_page_with_ppnum) + (VM_PACKED_POINTER_ALIGNMENT-1)) & ~(VM_PACKED_POINTER_ALIGNMENT - 1);

	vm_page_zone = zinit(vm_page_with_ppnum_size,
			     0, PAGE_SIZE, "vm pages");

	zone_change(vm_page_zone, Z_CALLERACCT, FALSE);
	zone_change(vm_page_zone, Z_EXPAND, FALSE);
	zone_change(vm_page_zone, Z_EXHAUST, TRUE);
	zone_change(vm_page_zone, Z_FOREIGN, TRUE);
	zone_change(vm_page_zone, Z_GZALLOC_EXEMPT, TRUE);
}

/*
 *	Routine:	vm_page_create
 *	Purpose:
 *		After the VM system is up, machine-dependent code
 *		may stumble across more physical memory.  For example,
 *		memory that it was reserving for a frame buffer.
 *		vm_page_create turns this memory into available pages.
 */

void
vm_page_create(
	ppnum_t start,
	ppnum_t end)
{
	ppnum_t		phys_page;
	vm_page_t 	m;

	for (phys_page = start;
	     phys_page < end;
	     phys_page++) {
		while ((m = (vm_page_t) vm_page_grab_fictitious_common(phys_page))
			== VM_PAGE_NULL)
			vm_page_more_fictitious();

		m->fictitious = FALSE;
		pmap_clear_noencrypt(phys_page);

		vm_page_pages++;
		vm_page_release(m, FALSE);
	}
}

/*
 *	vm_page_hash:
 *
 *	Distributes the object/offset key pair among hash buckets.
 *
 *	NOTE:	The bucket count must be a power of 2
 */
#define vm_page_hash(object, offset) (\
	( (natural_t)((uintptr_t)object * vm_page_bucket_hash) + ((uint32_t)atop_64(offset) ^ vm_page_bucket_hash))\
	 & vm_page_hash_mask)


/*
 *	vm_page_insert:		[ internal use only ]
 *
 *	Inserts the given mem entry into the object/object-page
 *	table and object list.
 *
 *	The object must be locked.
 */
void
vm_page_insert(
	vm_page_t		mem,
	vm_object_t		object,
	vm_object_offset_t	offset)
{
	vm_page_insert_internal(mem, object, offset, VM_KERN_MEMORY_NONE, FALSE, TRUE, FALSE, FALSE, NULL);
}

void
vm_page_insert_wired(
	vm_page_t		mem,
	vm_object_t		object,
	vm_object_offset_t	offset,
	vm_tag_t                tag)
{
	vm_page_insert_internal(mem, object, offset, tag, FALSE, TRUE, FALSE, FALSE, NULL);
}

void
vm_page_insert_internal(
	vm_page_t		mem,
	vm_object_t		object,
	vm_object_offset_t	offset,
	vm_tag_t                tag,
	boolean_t		queues_lock_held,
	boolean_t		insert_in_hash,
	boolean_t		batch_pmap_op,
        boolean_t               batch_accounting,
	uint64_t		*delayed_ledger_update)
{
	vm_page_bucket_t	*bucket;
	lck_spin_t		*bucket_lock;
	int			hash_id;
	task_t			owner;

        XPR(XPR_VM_PAGE,
                "vm_page_insert, object 0x%X offset 0x%X page 0x%X\n",
                object, offset, mem, 0,0);
#if 0
	/*
	 * we may not hold the page queue lock
	 * so this check isn't safe to make
	 */
	VM_PAGE_CHECK(mem);
#endif

	assert(page_aligned(offset));

	assert(!VM_PAGE_WIRED(mem) || mem->private || mem->fictitious || (tag != VM_KERN_MEMORY_NONE));

	/* the vm_submap_object is only a placeholder for submaps */
	assert(object != vm_submap_object);

	vm_object_lock_assert_exclusive(object);
	LCK_MTX_ASSERT(&vm_page_queue_lock,
		       queues_lock_held ? LCK_MTX_ASSERT_OWNED
		       			: LCK_MTX_ASSERT_NOTOWNED);
	if (queues_lock_held == FALSE)
		assert(!VM_PAGE_PAGEABLE(mem));

	if (insert_in_hash == TRUE) {
#if DEBUG || VM_PAGE_CHECK_BUCKETS
		if (mem->tabled || mem->vm_page_object)
			panic("vm_page_insert: page %p for (obj=%p,off=0x%llx) "
			      "already in (obj=%p,off=0x%llx)",
			      mem, object, offset, VM_PAGE_OBJECT(mem), mem->offset);
#endif
		assert(!object->internal || offset < object->vo_size);
		assert(vm_page_lookup(object, offset) == VM_PAGE_NULL);
		
		/*
		 *	Record the object/offset pair in this page
		 */

		mem->vm_page_object = VM_PAGE_PACK_OBJECT(object);
		mem->offset = offset;

#if CONFIG_SECLUDED_MEMORY
		if (object->eligible_for_secluded) {
			vm_page_secluded.eligible_for_secluded++;
		}
#endif /* CONFIG_SECLUDED_MEMORY */

		/*
		 *	Insert it into the object_object/offset hash table
		 */
		hash_id = vm_page_hash(object, offset);
		bucket = &vm_page_buckets[hash_id];
		bucket_lock = &vm_page_bucket_locks[hash_id / BUCKETS_PER_LOCK];
	
		lck_spin_lock(bucket_lock);

		mem->next_m = bucket->page_list;
		bucket->page_list = VM_PAGE_PACK_PTR(mem);
		assert(mem == (vm_page_t)(VM_PAGE_UNPACK_PTR(bucket->page_list)));

#if     MACH_PAGE_HASH_STATS
		if (++bucket->cur_count > bucket->hi_count)
			bucket->hi_count = bucket->cur_count;
#endif /* MACH_PAGE_HASH_STATS */
		mem->hashed = TRUE;
		lck_spin_unlock(bucket_lock);
	}

	{	
		unsigned int    cache_attr;

		cache_attr = object->wimg_bits & VM_WIMG_MASK;

		if (cache_attr != VM_WIMG_USE_DEFAULT) {
			PMAP_SET_CACHE_ATTR(mem, object, cache_attr, batch_pmap_op);
		}
	}
	/*
	 *	Now link into the object's list of backed pages.
	 */
	vm_page_queue_enter(&object->memq, mem, vm_page_t, listq);
	object->memq_hint = mem;
	mem->tabled = TRUE;

	/*
	 *	Show that the object has one more resident page.
	 */

	object->resident_page_count++;
	if (VM_PAGE_WIRED(mem)) {
	    assert(mem->wire_count > 0);

	    if (!mem->private && !mem->fictitious) 
	    {
		if (!object->wired_page_count)
		{
		    assert(VM_KERN_MEMORY_NONE != tag);
		    object->wire_tag = tag;
		    VM_OBJECT_WIRED(object);
		}
	    }
	    object->wired_page_count++;
	}
	assert(object->resident_page_count >= object->wired_page_count);

        if (batch_accounting == FALSE) {
		if (object->internal) {
			OSAddAtomic(1, &vm_page_internal_count);
		} else {
			OSAddAtomic(1, &vm_page_external_count);
		}
	}

	/*
	 * It wouldn't make sense to insert a "reusable" page in
	 * an object (the page would have been marked "reusable" only
	 * at the time of a madvise(MADV_FREE_REUSABLE) if it was already
	 * in the object at that time).
	 * But a page could be inserted in a "all_reusable" object, if
	 * something faults it in (a vm_read() from another task or a
	 * "use-after-free" issue in user space, for example).  It can
	 * also happen if we're relocating a page from that object to
	 * a different physical page during a physically-contiguous
	 * allocation.
	 */
	assert(!mem->reusable);
	if (object->all_reusable) {
		OSAddAtomic(+1, &vm_page_stats_reusable.reusable_count);
	}

	if (object->purgable == VM_PURGABLE_DENY) {
		owner = TASK_NULL;
	} else {
		owner = object->vo_purgeable_owner;
	}
	if (owner &&
	    (object->purgable == VM_PURGABLE_NONVOLATILE ||
	     VM_PAGE_WIRED(mem))) {

		if (delayed_ledger_update)
			*delayed_ledger_update += PAGE_SIZE;
		else {
			/* more non-volatile bytes */
			ledger_credit(owner->ledger,
				      task_ledgers.purgeable_nonvolatile,
				      PAGE_SIZE);
			/* more footprint */
			ledger_credit(owner->ledger,
				      task_ledgers.phys_footprint,
				      PAGE_SIZE);
		}

	} else if (owner &&
		   (object->purgable == VM_PURGABLE_VOLATILE ||
		    object->purgable == VM_PURGABLE_EMPTY)) {
		assert(! VM_PAGE_WIRED(mem));
		/* more volatile bytes */
		ledger_credit(owner->ledger,
			      task_ledgers.purgeable_volatile,
			      PAGE_SIZE);
	}

	if (object->purgable == VM_PURGABLE_VOLATILE) {
		if (VM_PAGE_WIRED(mem)) {
			OSAddAtomic(+1, &vm_page_purgeable_wired_count);
		} else {
			OSAddAtomic(+1, &vm_page_purgeable_count);
		}
	} else if (object->purgable == VM_PURGABLE_EMPTY &&
		   mem->vm_page_q_state == VM_PAGE_ON_THROTTLED_Q) {
		/*
		 * This page belongs to a purged VM object but hasn't
		 * been purged (because it was "busy").
		 * It's in the "throttled" queue and hence not
		 * visible to vm_pageout_scan().  Move it to a pageable
		 * queue, so that it can eventually be reclaimed, instead
		 * of lingering in the "empty" object.
		 */
		if (queues_lock_held == FALSE)
			vm_page_lockspin_queues();
		vm_page_deactivate(mem);
		if (queues_lock_held == FALSE)
			vm_page_unlock_queues();
	}

#if VM_OBJECT_TRACKING_OP_MODIFIED
	if (vm_object_tracking_inited &&
	    object->internal &&
	    object->resident_page_count == 0 &&
	    object->pager == NULL &&
	    object->shadow != NULL &&
	    object->shadow->copy == object) {
		void *bt[VM_OBJECT_TRACKING_BTDEPTH];
		int numsaved = 0;

		numsaved =OSBacktrace(bt, VM_OBJECT_TRACKING_BTDEPTH);
		btlog_add_entry(vm_object_tracking_btlog,
				object,
				VM_OBJECT_TRACKING_OP_MODIFIED,
				bt,
				numsaved);
	}
#endif /* VM_OBJECT_TRACKING_OP_MODIFIED */
}

/*
 *	vm_page_replace:
 *
 *	Exactly like vm_page_insert, except that we first
 *	remove any existing page at the given offset in object.
 *
 *	The object must be locked.
 */
void
vm_page_replace(
	vm_page_t		mem,
	vm_object_t		object,
	vm_object_offset_t	offset)
{
	vm_page_bucket_t *bucket;
	vm_page_t	 found_m = VM_PAGE_NULL;
	lck_spin_t	*bucket_lock;
	int		hash_id;

#if 0
	/*
	 * we don't hold the page queue lock
	 * so this check isn't safe to make
	 */
	VM_PAGE_CHECK(mem);
#endif
	vm_object_lock_assert_exclusive(object);
#if DEBUG || VM_PAGE_CHECK_BUCKETS
	if (mem->tabled || mem->vm_page_object)
		panic("vm_page_replace: page %p for (obj=%p,off=0x%llx) "
		      "already in (obj=%p,off=0x%llx)",
		      mem, object, offset, VM_PAGE_OBJECT(mem), mem->offset);
#endif
	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_NOTOWNED);

	assert(!VM_PAGE_PAGEABLE(mem));

	/*
	 *	Record the object/offset pair in this page
	 */
	mem->vm_page_object = VM_PAGE_PACK_OBJECT(object);
	mem->offset = offset;

	/*
	 *	Insert it into the object_object/offset hash table,
	 *	replacing any page that might have been there.
	 */

	hash_id = vm_page_hash(object, offset);
	bucket = &vm_page_buckets[hash_id];
	bucket_lock = &vm_page_bucket_locks[hash_id / BUCKETS_PER_LOCK];

	lck_spin_lock(bucket_lock);

	if (bucket->page_list) {
		vm_page_packed_t *mp = &bucket->page_list;
		vm_page_t m = (vm_page_t)(VM_PAGE_UNPACK_PTR(*mp));

		do {
			/*
			 * compare packed object pointers
			 */
			if (m->vm_page_object == mem->vm_page_object && m->offset == offset) {
				/*
				 * Remove old page from hash list
				 */
				*mp = m->next_m;
				m->hashed = FALSE;
				m->next_m = VM_PAGE_PACK_PTR(NULL);

				found_m = m;
				break;
			}
			mp = &m->next_m;
		} while ((m = (vm_page_t)(VM_PAGE_UNPACK_PTR(*mp))));

		mem->next_m = bucket->page_list;
	} else {
		mem->next_m = VM_PAGE_PACK_PTR(NULL);
	}
	/*
	 * insert new page at head of hash list
	 */
	bucket->page_list = VM_PAGE_PACK_PTR(mem);
	mem->hashed = TRUE;

	lck_spin_unlock(bucket_lock);

	if (found_m) {
	        /*
		 * there was already a page at the specified
		 * offset for this object... remove it from
		 * the object and free it back to the free list
		 */
		vm_page_free_unlocked(found_m, FALSE);
	}
	vm_page_insert_internal(mem, object, offset, VM_KERN_MEMORY_NONE, FALSE, FALSE, FALSE, FALSE, NULL);
}

/*
 *	vm_page_remove:		[ internal use only ]
 *
 *	Removes the given mem entry from the object/offset-page
 *	table and the object page list.
 *
 *	The object must be locked.
 */

void
vm_page_remove(
	vm_page_t	mem,
	boolean_t	remove_from_hash)
{
	vm_page_bucket_t *bucket;
	vm_page_t	this;
	lck_spin_t	*bucket_lock;
	int		hash_id;
	task_t		owner;
	vm_object_t	m_object;

	m_object = VM_PAGE_OBJECT(mem);

        XPR(XPR_VM_PAGE,
                "vm_page_remove, object 0x%X offset 0x%X page 0x%X\n",
                m_object, mem->offset, 
		mem, 0,0);

	vm_object_lock_assert_exclusive(m_object);
	assert(mem->tabled);
	assert(!mem->cleaning);
	assert(!mem->laundry);

	if (VM_PAGE_PAGEABLE(mem)) {
		LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	}
#if 0
	/*
	 * we don't hold the page queue lock
	 * so this check isn't safe to make
	 */
	VM_PAGE_CHECK(mem);
#endif
	if (remove_from_hash == TRUE) {
		/*
		 *	Remove from the object_object/offset hash table
		 */
		hash_id = vm_page_hash(m_object, mem->offset);
		bucket = &vm_page_buckets[hash_id];
		bucket_lock = &vm_page_bucket_locks[hash_id / BUCKETS_PER_LOCK];

		lck_spin_lock(bucket_lock);

		if ((this = (vm_page_t)(VM_PAGE_UNPACK_PTR(bucket->page_list))) == mem) {
			/* optimize for common case */

			bucket->page_list = mem->next_m;
		} else {
			vm_page_packed_t	*prev;

			for (prev = &this->next_m;
			     (this = (vm_page_t)(VM_PAGE_UNPACK_PTR(*prev))) != mem;
			     prev = &this->next_m)
				continue;
			*prev = this->next_m;
		}
#if     MACH_PAGE_HASH_STATS
		bucket->cur_count--;
#endif /* MACH_PAGE_HASH_STATS */
		mem->hashed = FALSE;
		this->next_m = VM_PAGE_PACK_PTR(NULL);
		lck_spin_unlock(bucket_lock);
	}
	/*
	 *	Now remove from the object's list of backed pages.
	 */

	vm_page_remove_internal(mem);

	/*
	 *	And show that the object has one fewer resident
	 *	page.
	 */

	assert(m_object->resident_page_count > 0);
	m_object->resident_page_count--;

	if (m_object->internal) {
#if DEBUG
		assert(vm_page_internal_count);
#endif /* DEBUG */

		OSAddAtomic(-1, &vm_page_internal_count);
	} else {
		assert(vm_page_external_count);
		OSAddAtomic(-1, &vm_page_external_count);

		if (mem->xpmapped) {
			assert(vm_page_xpmapped_external_count);
			OSAddAtomic(-1, &vm_page_xpmapped_external_count);
		}
	}
	if (!m_object->internal && (m_object->objq.next || m_object->objq.prev)) {
		if (m_object->resident_page_count == 0)
			vm_object_cache_remove(m_object);
	}

	if (VM_PAGE_WIRED(mem)) {
		assert(mem->wire_count > 0);
		assert(m_object->wired_page_count > 0);
		m_object->wired_page_count--;
		if (!m_object->wired_page_count) {
		    VM_OBJECT_UNWIRED(m_object);
		}
	}
	assert(m_object->resident_page_count >=
	       m_object->wired_page_count);
	if (mem->reusable) {
		assert(m_object->reusable_page_count > 0);
		m_object->reusable_page_count--;
		assert(m_object->reusable_page_count <=
		       m_object->resident_page_count);
		mem->reusable = FALSE;
		OSAddAtomic(-1, &vm_page_stats_reusable.reusable_count);
		vm_page_stats_reusable.reused_remove++;
	} else if (m_object->all_reusable) {
		OSAddAtomic(-1, &vm_page_stats_reusable.reusable_count);
		vm_page_stats_reusable.reused_remove++;
	}

	if (m_object->purgable == VM_PURGABLE_DENY) {
		owner = TASK_NULL;
	} else {
		owner = m_object->vo_purgeable_owner;
	}
	if (owner &&
	    (m_object->purgable == VM_PURGABLE_NONVOLATILE ||
	     VM_PAGE_WIRED(mem))) {
		/* less non-volatile bytes */
		ledger_debit(owner->ledger,
			     task_ledgers.purgeable_nonvolatile,
			     PAGE_SIZE);
		/* less footprint */
		ledger_debit(owner->ledger,
			     task_ledgers.phys_footprint,
			     PAGE_SIZE);
	} else if (owner &&
		   (m_object->purgable == VM_PURGABLE_VOLATILE ||
		    m_object->purgable == VM_PURGABLE_EMPTY)) {
		assert(! VM_PAGE_WIRED(mem));
		/* less volatile bytes */
		ledger_debit(owner->ledger,
			     task_ledgers.purgeable_volatile,
			     PAGE_SIZE);
	}
	if (m_object->purgable == VM_PURGABLE_VOLATILE) {
		if (VM_PAGE_WIRED(mem)) {
			assert(vm_page_purgeable_wired_count > 0);
			OSAddAtomic(-1, &vm_page_purgeable_wired_count);
		} else {
			assert(vm_page_purgeable_count > 0);
			OSAddAtomic(-1, &vm_page_purgeable_count);
		}
	}
	if (m_object->set_cache_attr == TRUE)
		pmap_set_cache_attributes(VM_PAGE_GET_PHYS_PAGE(mem), 0);

	mem->tabled = FALSE;
	mem->vm_page_object = 0;
	mem->offset = (vm_object_offset_t) -1;
}


/*
 *	vm_page_lookup:
 *
 *	Returns the page associated with the object/offset
 *	pair specified; if none is found, VM_PAGE_NULL is returned.
 *
 *	The object must be locked.  No side effects.
 */

#define	VM_PAGE_HASH_LOOKUP_THRESHOLD	10

#if DEBUG_VM_PAGE_LOOKUP

struct {
	uint64_t	vpl_total;
	uint64_t	vpl_empty_obj;
	uint64_t	vpl_bucket_NULL;
	uint64_t	vpl_hit_hint;
	uint64_t	vpl_hit_hint_next;
	uint64_t	vpl_hit_hint_prev;
	uint64_t	vpl_fast;
	uint64_t	vpl_slow;
	uint64_t	vpl_hit;
	uint64_t	vpl_miss;

	uint64_t	vpl_fast_elapsed;
	uint64_t	vpl_slow_elapsed;
} vm_page_lookup_stats __attribute__((aligned(8)));

#endif

#define	KDP_VM_PAGE_WALK_MAX	1000

vm_page_t
kdp_vm_page_lookup(
	vm_object_t		object,
	vm_object_offset_t	offset)
{
	vm_page_t cur_page;
	int num_traversed = 0;

	if (not_in_kdp) {
		panic("panic: kdp_vm_page_lookup done outside of kernel debugger");
	}

	vm_page_queue_iterate(&object->memq, cur_page, vm_page_t, listq) {
		if (cur_page->offset == offset) {
			return cur_page;
		}
		num_traversed++;

		if (num_traversed >= KDP_VM_PAGE_WALK_MAX) {
			return VM_PAGE_NULL;
		}
	}

	return VM_PAGE_NULL;
}

vm_page_t
vm_page_lookup(
	vm_object_t		object,
	vm_object_offset_t	offset)
{
	vm_page_t	mem;
	vm_page_bucket_t *bucket;
	vm_page_queue_entry_t	qe;
	lck_spin_t	*bucket_lock = NULL;
	int		hash_id;
#if DEBUG_VM_PAGE_LOOKUP
	uint64_t	start, elapsed;

	OSAddAtomic64(1, &vm_page_lookup_stats.vpl_total);
#endif
	vm_object_lock_assert_held(object);

	if (object->resident_page_count == 0) {
#if DEBUG_VM_PAGE_LOOKUP
		OSAddAtomic64(1, &vm_page_lookup_stats.vpl_empty_obj);
#endif
		return (VM_PAGE_NULL);
	}

	mem = object->memq_hint;

	if (mem != VM_PAGE_NULL) {
		assert(VM_PAGE_OBJECT(mem) == object);

		if (mem->offset == offset) {
#if DEBUG_VM_PAGE_LOOKUP
			OSAddAtomic64(1, &vm_page_lookup_stats.vpl_hit_hint);
#endif
			return (mem);
		}
		qe = (vm_page_queue_entry_t)vm_page_queue_next(&mem->listq);

		if (! vm_page_queue_end(&object->memq, qe)) {
			vm_page_t	next_page;

			next_page = (vm_page_t)((uintptr_t)qe);
			assert(VM_PAGE_OBJECT(next_page) == object);

			if (next_page->offset == offset) {
				object->memq_hint = next_page; /* new hint */
#if DEBUG_VM_PAGE_LOOKUP
				OSAddAtomic64(1, &vm_page_lookup_stats.vpl_hit_hint_next);
#endif
				return (next_page);
			}
		}
		qe = (vm_page_queue_entry_t)vm_page_queue_prev(&mem->listq);

		if (! vm_page_queue_end(&object->memq, qe)) {
			vm_page_t prev_page;

			prev_page = (vm_page_t)((uintptr_t)qe);
			assert(VM_PAGE_OBJECT(prev_page) == object);

			if (prev_page->offset == offset) {
				object->memq_hint = prev_page; /* new hint */
#if DEBUG_VM_PAGE_LOOKUP
				OSAddAtomic64(1, &vm_page_lookup_stats.vpl_hit_hint_prev);
#endif
				return (prev_page);
			}
		}
	}
	/*
	 * Search the hash table for this object/offset pair
	 */
	hash_id = vm_page_hash(object, offset);
	bucket = &vm_page_buckets[hash_id];

	/*
	 * since we hold the object lock, we are guaranteed that no
	 * new pages can be inserted into this object... this in turn
	 * guarantess that the page we're looking for can't exist
	 * if the bucket it hashes to is currently NULL even when looked
	 * at outside the scope of the hash bucket lock... this is a 
	 * really cheap optimiztion to avoid taking the lock
	 */
	if (!bucket->page_list) {
#if DEBUG_VM_PAGE_LOOKUP
		OSAddAtomic64(1, &vm_page_lookup_stats.vpl_bucket_NULL);
#endif
	        return (VM_PAGE_NULL);
	}

#if DEBUG_VM_PAGE_LOOKUP
	start = mach_absolute_time();
#endif
	if (object->resident_page_count <= VM_PAGE_HASH_LOOKUP_THRESHOLD) {
		/*
		 * on average, it's roughly 3 times faster to run a short memq list
		 * than to take the spin lock and go through the hash list
		 */
		mem = (vm_page_t)vm_page_queue_first(&object->memq);

		while (!vm_page_queue_end(&object->memq, (vm_page_queue_entry_t)mem)) {

			if (mem->offset == offset)
				break;

			mem = (vm_page_t)vm_page_queue_next(&mem->listq);
		}
		if (vm_page_queue_end(&object->memq, (vm_page_queue_entry_t)mem))
			mem = NULL;
	} else {
		vm_page_object_t	packed_object;

		packed_object = VM_PAGE_PACK_OBJECT(object);

		bucket_lock = &vm_page_bucket_locks[hash_id / BUCKETS_PER_LOCK];

		lck_spin_lock(bucket_lock);

		for (mem = (vm_page_t)(VM_PAGE_UNPACK_PTR(bucket->page_list));
		     mem != VM_PAGE_NULL;
		     mem = (vm_page_t)(VM_PAGE_UNPACK_PTR(mem->next_m))) {
#if 0
			/*
			 * we don't hold the page queue lock
			 * so this check isn't safe to make
			 */
			VM_PAGE_CHECK(mem);
#endif
			if ((mem->vm_page_object == packed_object) && (mem->offset == offset))
				break;
		}
		lck_spin_unlock(bucket_lock);
	}

#if DEBUG_VM_PAGE_LOOKUP
	elapsed = mach_absolute_time() - start;

	if (bucket_lock) {
		OSAddAtomic64(1, &vm_page_lookup_stats.vpl_slow);
		OSAddAtomic64(elapsed, &vm_page_lookup_stats.vpl_slow_elapsed);
	} else {
		OSAddAtomic64(1, &vm_page_lookup_stats.vpl_fast);
		OSAddAtomic64(elapsed, &vm_page_lookup_stats.vpl_fast_elapsed);
	}
	if (mem != VM_PAGE_NULL)
		OSAddAtomic64(1, &vm_page_lookup_stats.vpl_hit);
	else
	        OSAddAtomic64(1, &vm_page_lookup_stats.vpl_miss);
#endif
	if (mem != VM_PAGE_NULL) {
		assert(VM_PAGE_OBJECT(mem) == object);

		object->memq_hint = mem;
	}
	return (mem);
}


/*
 *	vm_page_rename:
 *
 *	Move the given memory entry from its
 *	current object to the specified target object/offset.
 *
 *	The object must be locked.
 */
void
vm_page_rename(
	vm_page_t		mem,
	vm_object_t		new_object,
	vm_object_offset_t	new_offset,
	boolean_t		encrypted_ok)
{
	boolean_t	internal_to_external, external_to_internal;
	vm_tag_t  	tag;
	vm_object_t	m_object;

	m_object = VM_PAGE_OBJECT(mem);

	assert(m_object != new_object);
        assert(m_object);

	/*
	 * ENCRYPTED SWAP:
	 * The encryption key is based on the page's memory object
	 * (aka "pager") and paging offset.  Moving the page to
	 * another VM object changes its "pager" and "paging_offset"
	 * so it has to be decrypted first, or we would lose the key.
	 *
	 * One exception is VM object collapsing, where we transfer pages
	 * from one backing object to its parent object.  This operation also
	 * transfers the paging information, so the <pager,paging_offset> info
	 * should remain consistent.  The caller (vm_object_do_collapse())
	 * sets "encrypted_ok" in this case.
	 */
	if (!encrypted_ok && mem->encrypted) {
		panic("vm_page_rename: page %p is encrypted\n", mem);
	}

        XPR(XPR_VM_PAGE,
                "vm_page_rename, new object 0x%X, offset 0x%X page 0x%X\n",
                new_object, new_offset, 
		mem, 0,0);

	/*
	 *	Changes to mem->object require the page lock because
	 *	the pageout daemon uses that lock to get the object.
	 */
	vm_page_lockspin_queues();

	internal_to_external = FALSE;
	external_to_internal = FALSE;

	if (mem->vm_page_q_state == VM_PAGE_ON_ACTIVE_LOCAL_Q) {
		/*
		 * it's much easier to get the vm_page_pageable_xxx accounting correct
		 * if we first move the page to the active queue... it's going to end
		 * up there anyway, and we don't do vm_page_rename's frequently enough
		 * for this to matter.
		 */
		vm_page_queues_remove(mem, FALSE);
		vm_page_activate(mem);
	}
	if (VM_PAGE_PAGEABLE(mem)) {
		if (m_object->internal && !new_object->internal) {
			internal_to_external = TRUE;
		}
		if (!m_object->internal && new_object->internal) {
			external_to_internal = TRUE;
		}
	}

	tag = m_object->wire_tag;
    	vm_page_remove(mem, TRUE);
	vm_page_insert_internal(mem, new_object, new_offset, tag, TRUE, TRUE, FALSE, FALSE, NULL);

	if (internal_to_external) {
		vm_page_pageable_internal_count--;
		vm_page_pageable_external_count++;
	} else if (external_to_internal) {
		vm_page_pageable_external_count--;
		vm_page_pageable_internal_count++;
	}

	vm_page_unlock_queues();
}

/*
 *	vm_page_init:
 *
 *	Initialize the fields in a new page.
 *	This takes a structure with random values and initializes it
 *	so that it can be given to vm_page_release or vm_page_insert.
 */
void
vm_page_init(
	vm_page_t	mem,
	ppnum_t		phys_page,
	boolean_t	lopage)
{
	assert(phys_page);

#if	DEBUG
	if ((phys_page != vm_page_fictitious_addr) && (phys_page != vm_page_guard_addr)) {
		if (!(pmap_valid_page(phys_page))) {
			panic("vm_page_init: non-DRAM phys_page 0x%x\n", phys_page);
		}
	}
#endif
	*mem = vm_page_template;

	VM_PAGE_SET_PHYS_PAGE(mem, phys_page);
#if 0
	/*
	 * we're leaving this turned off for now... currently pages
	 * come off the free list and are either immediately dirtied/referenced
	 * due to zero-fill or COW faults, or are used to read or write files...
	 * in the file I/O case, the UPL mechanism takes care of clearing
	 * the state of the HW ref/mod bits in a somewhat fragile way.
	 * Since we may change the way this works in the future (to toughen it up),
	 * I'm leaving this as a reminder of where these bits could get cleared
	 */

	/*
	 * make sure both the h/w referenced and modified bits are
	 * clear at this point... we are especially dependent on 
	 * not finding a 'stale' h/w modified in a number of spots
	 * once this page goes back into use
	 */
	pmap_clear_refmod(phys_page, VM_MEM_MODIFIED | VM_MEM_REFERENCED);
#endif
	mem->lopage = lopage;
}

/*
 *	vm_page_grab_fictitious:
 *
 *	Remove a fictitious page from the free list.
 *	Returns VM_PAGE_NULL if there are no free pages.
 */
int	c_vm_page_grab_fictitious = 0;
int	c_vm_page_grab_fictitious_failed = 0;
int	c_vm_page_release_fictitious = 0;
int	c_vm_page_more_fictitious = 0;

vm_page_t
vm_page_grab_fictitious_common(
	ppnum_t phys_addr)
{
	vm_page_t	m;

	if ((m = (vm_page_t)zget(vm_page_zone))) {

		vm_page_init(m, phys_addr, FALSE);
		m->fictitious = TRUE;

		c_vm_page_grab_fictitious++;
	} else
		c_vm_page_grab_fictitious_failed++;

	return m;
}

vm_page_t
vm_page_grab_fictitious(void)
{
	return vm_page_grab_fictitious_common(vm_page_fictitious_addr);
}

vm_page_t
vm_page_grab_guard(void)
{
	return vm_page_grab_fictitious_common(vm_page_guard_addr);
}


/*
 *	vm_page_release_fictitious:
 *
 *	Release a fictitious page to the zone pool
 */
void
vm_page_release_fictitious(
	vm_page_t m)
{
	assert((m->vm_page_q_state == VM_PAGE_NOT_ON_Q) || (m->vm_page_q_state == VM_PAGE_IS_WIRED));
	assert(m->fictitious);
	assert(VM_PAGE_GET_PHYS_PAGE(m) == vm_page_fictitious_addr ||
	       VM_PAGE_GET_PHYS_PAGE(m) == vm_page_guard_addr);

	c_vm_page_release_fictitious++;

	zfree(vm_page_zone, m);
}

/*
 *	vm_page_more_fictitious:
 *
 *	Add more fictitious pages to the zone.
 *	Allowed to block. This routine is way intimate
 *	with the zones code, for several reasons:
 *	1. we need to carve some page structures out of physical
 *	   memory before zones work, so they _cannot_ come from
 *	   the zone_map.
 *	2. the zone needs to be collectable in order to prevent
 *	   growth without bound. These structures are used by
 *	   the device pager (by the hundreds and thousands), as
 *	   private pages for pageout, and as blocking pages for
 *	   pagein. Temporary bursts in demand should not result in
 *	   permanent allocation of a resource.
 *	3. To smooth allocation humps, we allocate single pages
 *	   with kernel_memory_allocate(), and cram them into the
 *	   zone.
 */

void vm_page_more_fictitious(void)
{
	vm_offset_t	addr;
	kern_return_t	retval;

	c_vm_page_more_fictitious++;

	/*
	 * Allocate a single page from the zone_map. Do not wait if no physical
	 * pages are immediately available, and do not zero the space. We need
	 * our own blocking lock here to prevent having multiple,
	 * simultaneous requests from piling up on the zone_map lock. Exactly
	 * one (of our) threads should be potentially waiting on the map lock.
	 * If winner is not vm-privileged, then the page allocation will fail,
	 * and it will temporarily block here in the vm_page_wait().
	 */
	lck_mtx_lock(&vm_page_alloc_lock);
	/*
	 * If another thread allocated space, just bail out now.
	 */
	if (zone_free_count(vm_page_zone) > 5) {
		/*
		 * The number "5" is a small number that is larger than the
		 * number of fictitious pages that any single caller will
		 * attempt to allocate. Otherwise, a thread will attempt to
		 * acquire a fictitious page (vm_page_grab_fictitious), fail,
		 * release all of the resources and locks already acquired,
		 * and then call this routine. This routine finds the pages
		 * that the caller released, so fails to allocate new space.
		 * The process repeats infinitely. The largest known number
		 * of fictitious pages required in this manner is 2. 5 is
		 * simply a somewhat larger number.
		 */
		lck_mtx_unlock(&vm_page_alloc_lock);
		return;
	}

	retval = kernel_memory_allocate(zone_map,
					&addr, PAGE_SIZE, VM_PROT_ALL,
					KMA_KOBJECT|KMA_NOPAGEWAIT, VM_KERN_MEMORY_ZONE);
	if (retval != KERN_SUCCESS) { 
		/*
		 * No page was available. Drop the
		 * lock to give another thread a chance at it, and
		 * wait for the pageout daemon to make progress.
		 */
		lck_mtx_unlock(&vm_page_alloc_lock);
		vm_page_wait(THREAD_UNINT);
		return;
	}

	zcram(vm_page_zone, addr, PAGE_SIZE);

	lck_mtx_unlock(&vm_page_alloc_lock);
}


/*
 *	vm_pool_low():
 *
 *	Return true if it is not likely that a non-vm_privileged thread
 *	can get memory without blocking.  Advisory only, since the
 *	situation may change under us.
 */
int
vm_pool_low(void)
{
	/* No locking, at worst we will fib. */
	return( vm_page_free_count <= vm_page_free_reserved );
}


#if CONFIG_BACKGROUND_QUEUE

void
vm_page_update_background_state(vm_page_t mem)
{
	if (vm_page_background_mode == VM_PAGE_BG_DISABLED)
		return;

	if (mem->vm_page_in_background == FALSE)
		return;

#if BACKGROUNDQ_BASED_ON_QOS
        if (proc_get_effective_thread_policy(current_thread(), TASK_POLICY_QOS) <= THREAD_QOS_LEGACY)
		return;
#else
	task_t	my_task;

	my_task = current_task();
	
	if (my_task) {
		if (proc_get_effective_task_policy(my_task, TASK_POLICY_DARWIN_BG))
			return;
	}
#endif
	vm_page_lockspin_queues();

	mem->vm_page_in_background = FALSE;
	vm_page_background_promoted_count++;

	vm_page_remove_from_backgroundq(mem);

	vm_page_unlock_queues();
}


void
vm_page_assign_background_state(vm_page_t mem)
{
	if (vm_page_background_mode == VM_PAGE_BG_DISABLED)
		return;

#if BACKGROUNDQ_BASED_ON_QOS
        if (proc_get_effective_thread_policy(current_thread(), TASK_POLICY_QOS) <= THREAD_QOS_LEGACY)
                mem->vm_page_in_background = TRUE;
	else
                mem->vm_page_in_background = FALSE;
#else
	task_t	my_task;

	my_task = current_task();

	if (my_task)
		mem->vm_page_in_background = proc_get_effective_task_policy(my_task, TASK_POLICY_DARWIN_BG);
#endif
}


void
vm_page_remove_from_backgroundq(
	vm_page_t	mem)
{
	vm_object_t	m_object;

	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);

	if (mem->vm_page_on_backgroundq) {
		vm_page_queue_remove(&vm_page_queue_background, mem, vm_page_t, vm_page_backgroundq);

		mem->vm_page_backgroundq.next = 0;
		mem->vm_page_backgroundq.prev = 0;
		mem->vm_page_on_backgroundq = FALSE;
		
		vm_page_background_count--;

		m_object = VM_PAGE_OBJECT(mem);

		if (m_object->internal)
			vm_page_background_internal_count--;
		else
			vm_page_background_external_count--;
	} else {
		assert(VM_PAGE_UNPACK_PTR(mem->vm_page_backgroundq.next) == (uintptr_t)NULL &&
		       VM_PAGE_UNPACK_PTR(mem->vm_page_backgroundq.prev) == (uintptr_t)NULL);
	}
}


void
vm_page_add_to_backgroundq(
	vm_page_t	mem,
	boolean_t	first)
{				
	vm_object_t	m_object;

	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);

	if (vm_page_background_mode == VM_PAGE_BG_DISABLED)
		return;

	if (mem->vm_page_on_backgroundq == FALSE) {

		m_object = VM_PAGE_OBJECT(mem);

		if (vm_page_background_exclude_external && !m_object->internal)
			return;

		if (first == TRUE)
			vm_page_queue_enter_first(&vm_page_queue_background, mem, vm_page_t, vm_page_backgroundq);
		else
			vm_page_queue_enter(&vm_page_queue_background, mem, vm_page_t, vm_page_backgroundq);
		mem->vm_page_on_backgroundq = TRUE;
		
		vm_page_background_count++;

		if (m_object->internal)
			vm_page_background_internal_count++;
		else
			vm_page_background_external_count++;
	}
}

#endif

/*
 * this is an interface to support bring-up of drivers
 * on platforms with physical memory > 4G...
 */
int		vm_himemory_mode = 2;


/*
 * this interface exists to support hardware controllers
 * incapable of generating DMAs with more than 32 bits
 * of address on platforms with physical memory > 4G...
 */
unsigned int	vm_lopages_allocated_q = 0;
unsigned int	vm_lopages_allocated_cpm_success = 0;
unsigned int	vm_lopages_allocated_cpm_failed = 0;
vm_page_queue_head_t	vm_lopage_queue_free __attribute__((aligned(VM_PACKED_POINTER_ALIGNMENT)));

vm_page_t
vm_page_grablo(void)
{
	vm_page_t	mem;

	if (vm_lopage_needed == FALSE)
	        return (vm_page_grab());

	lck_mtx_lock_spin(&vm_page_queue_free_lock);

        if ( !vm_page_queue_empty(&vm_lopage_queue_free)) {
                vm_page_queue_remove_first(&vm_lopage_queue_free,
                                   mem,
                                   vm_page_t,
                                   pageq);
		assert(vm_lopage_free_count);
		assert(mem->vm_page_q_state == VM_PAGE_ON_FREE_LOPAGE_Q);
		mem->vm_page_q_state = VM_PAGE_NOT_ON_Q;

                vm_lopage_free_count--;
		vm_lopages_allocated_q++;

		if (vm_lopage_free_count < vm_lopage_lowater)
			vm_lopage_refill = TRUE;

		lck_mtx_unlock(&vm_page_queue_free_lock);

#if CONFIG_BACKGROUND_QUEUE
		vm_page_assign_background_state(mem);
#endif
	} else {
		lck_mtx_unlock(&vm_page_queue_free_lock);

		if (cpm_allocate(PAGE_SIZE, &mem, atop(0xffffffff), 0, FALSE, KMA_LOMEM) != KERN_SUCCESS) {

			lck_mtx_lock_spin(&vm_page_queue_free_lock);
			vm_lopages_allocated_cpm_failed++;
			lck_mtx_unlock(&vm_page_queue_free_lock);

			return (VM_PAGE_NULL);
		}
		assert(mem->vm_page_q_state == VM_PAGE_NOT_ON_Q);

		mem->busy = TRUE;

		vm_page_lockspin_queues();
		
		mem->gobbled = FALSE;
		vm_page_gobble_count--;
		vm_page_wire_count--;

		vm_lopages_allocated_cpm_success++;
		vm_page_unlock_queues();
	}
	assert(mem->busy);
	assert(!mem->pmapped);
	assert(!mem->wpmapped);
	assert(!pmap_is_noencrypt(VM_PAGE_GET_PHYS_PAGE(mem)));

	VM_PAGE_ZERO_PAGEQ_ENTRY(mem);

	return (mem);
}


/*
 *	vm_page_grab:
 *
 *	first try to grab a page from the per-cpu free list...
 *	this must be done while pre-emption is disabled... if
 * 	a page is available, we're done... 
 *	if no page is available, grab the vm_page_queue_free_lock
 *	and see if current number of free pages would allow us
 * 	to grab at least 1... if not, return VM_PAGE_NULL as before... 
 *	if there are pages available, disable preemption and
 * 	recheck the state of the per-cpu free list... we could
 *	have been preempted and moved to a different cpu, or
 * 	some other thread could have re-filled it... if still
 *	empty, figure out how many pages we can steal from the
 *	global free queue and move to the per-cpu queue...
 *	return 1 of these pages when done... only wakeup the
 * 	pageout_scan thread if we moved pages from the global
 *	list... no need for the wakeup if we've satisfied the
 *	request from the per-cpu queue.
 */

#if CONFIG_SECLUDED_MEMORY
vm_page_t vm_page_grab_secluded(void);
#endif /* CONFIG_SECLUDED_MEMORY */

vm_page_t
vm_page_grab(void)
{
	return vm_page_grab_options(0);
}

vm_page_t
vm_page_grab_options(
	int grab_options)
{
	vm_page_t	mem;

	disable_preemption();

	if ((mem = PROCESSOR_DATA(current_processor(), free_pages))) {
return_page_from_cpu_list:
		assert(mem->vm_page_q_state == VM_PAGE_ON_FREE_LOCAL_Q);

	        PROCESSOR_DATA(current_processor(), page_grab_count) += 1;
	        PROCESSOR_DATA(current_processor(), free_pages) = mem->snext;

	        enable_preemption();
		VM_PAGE_ZERO_PAGEQ_ENTRY(mem);
		mem->vm_page_q_state = VM_PAGE_NOT_ON_Q;

		assert(mem->listq.next == 0 && mem->listq.prev == 0);
		assert(mem->tabled == FALSE);
		assert(mem->vm_page_object == 0);
		assert(!mem->laundry);
		assert(pmap_verify_free(VM_PAGE_GET_PHYS_PAGE(mem)));
		assert(mem->busy);
		assert(!mem->encrypted);
		assert(!mem->pmapped);
		assert(!mem->wpmapped);
		assert(!pmap_is_noencrypt(VM_PAGE_GET_PHYS_PAGE(mem)));

#if CONFIG_BACKGROUND_QUEUE
		vm_page_assign_background_state(mem);
#endif
		return mem;
	}
	enable_preemption();


	/*
	 *	Optionally produce warnings if the wire or gobble
	 *	counts exceed some threshold.
	 */
#if VM_PAGE_WIRE_COUNT_WARNING
	if (vm_page_wire_count >= VM_PAGE_WIRE_COUNT_WARNING) {
		printf("mk: vm_page_grab(): high wired page count of %d\n",
			vm_page_wire_count);
	}
#endif
#if VM_PAGE_GOBBLE_COUNT_WARNING
	if (vm_page_gobble_count >= VM_PAGE_GOBBLE_COUNT_WARNING) {
		printf("mk: vm_page_grab(): high gobbled page count of %d\n",
			vm_page_gobble_count);
	}
#endif

	lck_mtx_lock_spin(&vm_page_queue_free_lock);

	/*
	 *	Only let privileged threads (involved in pageout)
	 *	dip into the reserved pool.
	 */
	if ((vm_page_free_count < vm_page_free_reserved) &&
	    !(current_thread()->options & TH_OPT_VMPRIV)) {
		/* no page for us in the free queue... */
		lck_mtx_unlock(&vm_page_queue_free_lock);
		mem = VM_PAGE_NULL;

#if CONFIG_SECLUDED_MEMORY
		/* ... but can we try and grab from the secluded queue? */
		if (vm_page_secluded_count > 0 &&
		    ((grab_options & VM_PAGE_GRAB_SECLUDED) ||
		     task_can_use_secluded_mem(current_task()))) {
			mem = vm_page_grab_secluded();
			if (grab_options & VM_PAGE_GRAB_SECLUDED) {
				vm_page_secluded.grab_for_iokit++;
				if (mem) {
					vm_page_secluded.grab_for_iokit_success++;
				}
			}
			if (mem) {
				VM_CHECK_MEMORYSTATUS;
				return mem;
			}
		}
#else /* CONFIG_SECLUDED_MEMORY */
		(void) grab_options;
#endif /* CONFIG_SECLUDED_MEMORY */
	}
	else {
	       vm_page_t	head;
	       vm_page_t	tail;
	       unsigned int	pages_to_steal;
	       unsigned int	color;

	       while ( vm_page_free_count == 0 ) {

			lck_mtx_unlock(&vm_page_queue_free_lock);
			/*
			 * must be a privileged thread to be
			 * in this state since a non-privileged 
			 * thread would have bailed if we were
			 * under the vm_page_free_reserved mark
			 */
			VM_PAGE_WAIT();
			lck_mtx_lock_spin(&vm_page_queue_free_lock);
		}

		disable_preemption();

		if ((mem = PROCESSOR_DATA(current_processor(), free_pages))) {
			lck_mtx_unlock(&vm_page_queue_free_lock);

		        /*
			 * we got preempted and moved to another processor
			 * or we got preempted and someone else ran and filled the cache
			 */
			goto return_page_from_cpu_list;
		}
		if (vm_page_free_count <= vm_page_free_reserved)
		        pages_to_steal = 1;
		else {
			if (vm_free_magazine_refill_limit <= (vm_page_free_count - vm_page_free_reserved))
				pages_to_steal = vm_free_magazine_refill_limit;
			else
			        pages_to_steal = (vm_page_free_count - vm_page_free_reserved);
		}
		color = PROCESSOR_DATA(current_processor(), start_color);
		head = tail = NULL;

		vm_page_free_count -= pages_to_steal;

		while (pages_to_steal--) {

			while (vm_page_queue_empty(&vm_page_queue_free[color].qhead))
			        color = (color + 1) & vm_color_mask;
		
			vm_page_queue_remove_first(&vm_page_queue_free[color].qhead,
					   mem,
					   vm_page_t,
					   pageq);
			assert(mem->vm_page_q_state == VM_PAGE_ON_FREE_Q);

			VM_PAGE_ZERO_PAGEQ_ENTRY(mem);
			
			color = (color + 1) & vm_color_mask;

			if (head == NULL)
				head = mem;
			else
			        tail->snext = mem;
		        tail = mem;

			assert(mem->listq.next == 0 && mem->listq.prev == 0);
			assert(mem->tabled == FALSE);
			assert(mem->vm_page_object == 0);
			assert(!mem->laundry);

			mem->vm_page_q_state = VM_PAGE_ON_FREE_LOCAL_Q;

			assert(pmap_verify_free(VM_PAGE_GET_PHYS_PAGE(mem)));
			assert(mem->busy);
			assert(!mem->encrypted);
			assert(!mem->pmapped);
			assert(!mem->wpmapped);
			assert(!pmap_is_noencrypt(VM_PAGE_GET_PHYS_PAGE(mem)));
		}
		lck_mtx_unlock(&vm_page_queue_free_lock);

		PROCESSOR_DATA(current_processor(), free_pages) = head->snext;
		PROCESSOR_DATA(current_processor(), start_color) = color;

		/*
		 * satisfy this request
		 */
	        PROCESSOR_DATA(current_processor(), page_grab_count) += 1;
		mem = head;
		assert(mem->vm_page_q_state == VM_PAGE_ON_FREE_LOCAL_Q);

		VM_PAGE_ZERO_PAGEQ_ENTRY(mem);
		mem->vm_page_q_state = VM_PAGE_NOT_ON_Q;

		enable_preemption();
	}
	/*
	 *	Decide if we should poke the pageout daemon.
	 *	We do this if the free count is less than the low
	 *	water mark, or if the free count is less than the high
	 *	water mark (but above the low water mark) and the inactive
	 *	count is less than its target.
	 *
	 *	We don't have the counts locked ... if they change a little,
	 *	it doesn't really matter.
	 */
	if ((vm_page_free_count < vm_page_free_min) ||
	     ((vm_page_free_count < vm_page_free_target) &&
	      ((vm_page_inactive_count + vm_page_speculative_count) < vm_page_inactive_min)))
	         thread_wakeup((event_t) &vm_page_free_wanted);
#if CONFIG_BACKGROUND_QUEUE
	if (vm_page_background_mode == VM_PAGE_BG_LEVEL_3 && (vm_page_background_count > vm_page_background_limit))
	         thread_wakeup((event_t) &vm_page_free_wanted);
#endif

	VM_CHECK_MEMORYSTATUS;

	if (mem) {
//		dbgLog(VM_PAGE_GET_PHYS_PAGE(mem), vm_page_free_count, vm_page_wire_count, 4);	/* (TEST/DEBUG) */

#if CONFIG_BACKGROUND_QUEUE
		vm_page_assign_background_state(mem);
#endif
	}
	return mem;
}

#if CONFIG_SECLUDED_MEMORY
vm_page_t
vm_page_grab_secluded(void)
{
	vm_page_t	mem;
	vm_object_t	object;
	int		refmod_state;

	if (vm_page_secluded_count == 0) {
		/* no secluded pages to grab... */
		return VM_PAGE_NULL;
	}

	/* secluded queue is protected by the VM page queue lock */
	vm_page_lock_queues();

	if (vm_page_secluded_count == 0) {
		/* no secluded pages to grab... */
		vm_page_unlock_queues();
		return VM_PAGE_NULL;
	}

#if 00
	/* can we grab from the secluded queue? */
	if (vm_page_secluded_count > vm_page_secluded_target ||
	    (vm_page_secluded_count > 0 &&
	     task_can_use_secluded_mem(current_task()))) {
		/* OK */
	} else {
		/* can't grab from secluded queue... */
		vm_page_unlock_queues();
		return VM_PAGE_NULL;
	}
#endif

	/* we can grab a page from secluded queue! */
	assert((vm_page_secluded_count_free +
		vm_page_secluded_count_inuse) ==
	       vm_page_secluded_count);
	if (current_task()->task_can_use_secluded_mem) {
		assert(num_tasks_can_use_secluded_mem > 0);
	}
	assert(!vm_page_queue_empty(&vm_page_queue_secluded));
	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	mem = vm_page_queue_first(&vm_page_queue_secluded);
	assert(mem->vm_page_q_state == VM_PAGE_ON_SECLUDED_Q);
	vm_page_queues_remove(mem, TRUE);

	object = VM_PAGE_OBJECT(mem);

	assert(!mem->fictitious);
	assert(!VM_PAGE_WIRED(mem));
	if (object == VM_OBJECT_NULL) {
		/* free for grab! */
		vm_page_unlock_queues();
		vm_page_secluded.grab_success_free++;

		assert(mem->busy);
		assert(mem->vm_page_q_state == VM_PAGE_NOT_ON_Q);
		assert(VM_PAGE_OBJECT(mem) == VM_OBJECT_NULL);
		assert(mem->pageq.next == 0);
		assert(mem->pageq.prev == 0);
		assert(mem->listq.next == 0);
		assert(mem->listq.prev == 0);
#if CONFIG_BACKGROUND_QUEUE
		assert(mem->vm_page_on_backgroundq == 0);
		assert(mem->vm_page_backgroundq.next == 0);
		assert(mem->vm_page_backgroundq.prev == 0);
#endif /* CONFIG_BACKGROUND_QUEUE */
		return mem;
	}

	assert(!object->internal);
//	vm_page_pageable_external_count--;

	if (!vm_object_lock_try(object)) {
//		printf("SECLUDED: page %p: object %p locked\n", mem, object);
		vm_page_secluded.grab_failure_locked++;
	reactivate_secluded_page:
		vm_page_activate(mem);
		vm_page_unlock_queues();
		return VM_PAGE_NULL;
	}
	if (mem->busy ||
	    mem->cleaning ||
	    mem->laundry) {
		/* can't steal page in this state... */
		vm_object_unlock(object);
		vm_page_secluded.grab_failure_state++;
		goto reactivate_secluded_page;
	}

	mem->busy = TRUE;
	refmod_state = pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(mem));
	if (refmod_state & VM_MEM_REFERENCED) {
		mem->reference = TRUE;
	}
	if (refmod_state & VM_MEM_MODIFIED) {
		SET_PAGE_DIRTY(mem, FALSE);
	}
	if (mem->dirty || mem->precious) {
		/* can't grab a dirty page; re-activate */
//		printf("SECLUDED: dirty page %p\n", mem);
		PAGE_WAKEUP_DONE(mem);
		vm_page_secluded.grab_failure_dirty++;
		vm_object_unlock(object);
		goto reactivate_secluded_page;
	}
	if (mem->reference) {
		/* it's been used but we do need to grab a page... */
	}

	vm_page_unlock_queues();

	/* finish what vm_page_free() would have done... */
	vm_page_free_prepare_object(mem, TRUE);
	vm_object_unlock(object);
	object = VM_OBJECT_NULL;
	if (vm_page_free_verify) {
		assert(pmap_verify_free(VM_PAGE_GET_PHYS_PAGE(mem)));
	}
	pmap_clear_noencrypt(VM_PAGE_GET_PHYS_PAGE(mem));
	vm_page_secluded.grab_success_other++;

	assert(mem->busy);
	assert(mem->vm_page_q_state == VM_PAGE_NOT_ON_Q);
	assert(VM_PAGE_OBJECT(mem) == VM_OBJECT_NULL);
	assert(mem->pageq.next == 0);
	assert(mem->pageq.prev == 0);
	assert(mem->listq.next == 0);
	assert(mem->listq.prev == 0);
#if CONFIG_BACKGROUND_QUEUE
	assert(mem->vm_page_on_backgroundq == 0);
	assert(mem->vm_page_backgroundq.next == 0);
	assert(mem->vm_page_backgroundq.prev == 0);
#endif /* CONFIG_BACKGROUND_QUEUE */

	return mem;
}
#endif /* CONFIG_SECLUDED_MEMORY */

/*
 *	vm_page_release:
 *
 *	Return a page to the free list.
 */

void
vm_page_release(
	vm_page_t	mem,
	boolean_t	page_queues_locked)
{
	unsigned int	color;
	int	need_wakeup = 0;
	int	need_priv_wakeup = 0;
#if CONFIG_SECLUDED_MEMORY
	int	need_secluded_wakeup = 0;
#endif /* CONFIG_SECLUDED_MEMORY */

	if (page_queues_locked) {
		LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	} else {
		LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_NOTOWNED);
	}

	assert(!mem->private && !mem->fictitious);
	if (vm_page_free_verify) {
		assert(pmap_verify_free(VM_PAGE_GET_PHYS_PAGE(mem)));
	}
//	dbgLog(VM_PAGE_GET_PHYS_PAGE(mem), vm_page_free_count, vm_page_wire_count, 5);	/* (TEST/DEBUG) */

	pmap_clear_noencrypt(VM_PAGE_GET_PHYS_PAGE(mem));

	lck_mtx_lock_spin(&vm_page_queue_free_lock);

	assert(mem->vm_page_q_state == VM_PAGE_NOT_ON_Q);
	assert(mem->busy);
	assert(!mem->laundry);
	assert(mem->vm_page_object == 0);
	assert(mem->pageq.next == 0 && mem->pageq.prev == 0);
	assert(mem->listq.next == 0 && mem->listq.prev == 0);
#if CONFIG_BACKGROUND_QUEUE
	assert(mem->vm_page_backgroundq.next == 0 &&
	       mem->vm_page_backgroundq.prev == 0 &&
	       mem->vm_page_on_backgroundq == FALSE);
#endif	
	if ((mem->lopage == TRUE || vm_lopage_refill == TRUE) &&
	    vm_lopage_free_count < vm_lopage_free_limit &&
	    VM_PAGE_GET_PHYS_PAGE(mem) < max_valid_low_ppnum) {
	        /*
		 * this exists to support hardware controllers
		 * incapable of generating DMAs with more than 32 bits
		 * of address on platforms with physical memory > 4G...
		 */
		vm_page_queue_enter_first(&vm_lopage_queue_free,
					  mem,
					  vm_page_t,
					  pageq);
		vm_lopage_free_count++;

		if (vm_lopage_free_count >= vm_lopage_free_limit)
			vm_lopage_refill = FALSE;

		mem->vm_page_q_state = VM_PAGE_ON_FREE_LOPAGE_Q;
		mem->lopage = TRUE;
#if CONFIG_SECLUDED_MEMORY
	} else if (vm_page_free_count > vm_page_free_reserved &&
		   vm_page_secluded_count < vm_page_secluded_target &&
		   num_tasks_can_use_secluded_mem == 0) {
		/*
		 * XXX FBDP TODO: also avoid refilling secluded queue
		 * when some IOKit objects are already grabbing from it...
		 */
		if (!page_queues_locked) {
			if (!vm_page_trylock_queues()) {
				/* take locks in right order */
				lck_mtx_unlock(&vm_page_queue_free_lock);
				vm_page_lock_queues();
				lck_mtx_lock_spin(&vm_page_queue_free_lock);
			}
		}
		mem->lopage = FALSE;
		LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
		vm_page_queue_enter_first(&vm_page_queue_secluded,
					  mem,
					  vm_page_t,
					  pageq);
		mem->vm_page_q_state = VM_PAGE_ON_SECLUDED_Q;
		vm_page_secluded_count++;
		vm_page_secluded_count_free++;
		if (!page_queues_locked) {
			vm_page_unlock_queues();
		}
		LCK_MTX_ASSERT(&vm_page_queue_free_lock, LCK_MTX_ASSERT_OWNED);
		if (vm_page_free_wanted_secluded > 0) {
		        vm_page_free_wanted_secluded--;
			need_secluded_wakeup = 1;
		}
#endif /* CONFIG_SECLUDED_MEMORY */
	} else {
		mem->lopage = FALSE;
		mem->vm_page_q_state = VM_PAGE_ON_FREE_Q;

	        color = VM_PAGE_GET_PHYS_PAGE(mem) & vm_color_mask;
		vm_page_queue_enter_first(&vm_page_queue_free[color].qhead,
					  mem,
					  vm_page_t,
					  pageq);
		vm_page_free_count++;
		/*
		 *	Check if we should wake up someone waiting for page.
		 *	But don't bother waking them unless they can allocate.
		 *
		 *	We wakeup only one thread, to prevent starvation.
		 *	Because the scheduling system handles wait queues FIFO,
		 *	if we wakeup all waiting threads, one greedy thread
		 *	can starve multiple niceguy threads.  When the threads
		 *	all wakeup, the greedy threads runs first, grabs the page,
		 *	and waits for another page.  It will be the first to run
		 *	when the next page is freed.
		 *
		 *	However, there is a slight danger here.
		 *	The thread we wake might not use the free page.
		 *	Then the other threads could wait indefinitely
		 *	while the page goes unused.  To forestall this,
		 *	the pageout daemon will keep making free pages
		 *	as long as vm_page_free_wanted is non-zero.
		 */

		assert(vm_page_free_count > 0);
		if (vm_page_free_wanted_privileged > 0) {
		        vm_page_free_wanted_privileged--;
			need_priv_wakeup = 1;
#if CONFIG_SECLUDED_MEMORY
		} else if (vm_page_free_wanted_secluded > 0 &&
			   vm_page_free_count > vm_page_free_reserved) {
			vm_page_free_wanted_secluded--;
			need_secluded_wakeup = 1;
#endif /* CONFIG_SECLUDED_MEMORY */
		} else if (vm_page_free_wanted > 0 &&
			   vm_page_free_count > vm_page_free_reserved) {
		        vm_page_free_wanted--;
			need_wakeup = 1;
		}
	}
	lck_mtx_unlock(&vm_page_queue_free_lock);

	if (need_priv_wakeup)
		thread_wakeup_one((event_t) &vm_page_free_wanted_privileged);
#if CONFIG_SECLUDED_MEMORY
	else if (need_secluded_wakeup)
		thread_wakeup_one((event_t) &vm_page_free_wanted_secluded);
#endif /* CONFIG_SECLUDED_MEMORY */
	else if (need_wakeup)
		thread_wakeup_one((event_t) &vm_page_free_count);

	VM_CHECK_MEMORYSTATUS;
}

/*
 * This version of vm_page_release() is used only at startup
 * when we are single-threaded and pages are being released 
 * for the first time. Hence, no locking or unnecessary checks are made.
 * Note: VM_CHECK_MEMORYSTATUS invoked by the caller.
 */
void
vm_page_release_startup(
	vm_page_t	mem)
{
	vm_page_queue_t	queue_free;

	if (vm_lopage_free_count < vm_lopage_free_limit &&
	    VM_PAGE_GET_PHYS_PAGE(mem) < max_valid_low_ppnum) {
		mem->lopage = TRUE;
		mem->vm_page_q_state = VM_PAGE_ON_FREE_LOPAGE_Q;
		vm_lopage_free_count++;
		queue_free = &vm_lopage_queue_free;
#if CONFIG_SECLUDED_MEMORY
	} else if (vm_page_secluded_count < vm_page_secluded_target) {
		mem->lopage = FALSE;
		mem->vm_page_q_state = VM_PAGE_ON_SECLUDED_Q;
		vm_page_secluded_count++;
		vm_page_secluded_count_free++;
		queue_free = &vm_page_queue_secluded;
#endif /* CONFIG_SECLUDED_MEMORY */
	} else {
		mem->lopage = FALSE;
		mem->vm_page_q_state = VM_PAGE_ON_FREE_Q;
		vm_page_free_count++;
		queue_free = &vm_page_queue_free[VM_PAGE_GET_PHYS_PAGE(mem) & vm_color_mask].qhead;
	}
	vm_page_queue_enter_first(queue_free, mem, vm_page_t, pageq);
}

/*
 *	vm_page_wait:
 *
 *	Wait for a page to become available.
 *	If there are plenty of free pages, then we don't sleep.
 *
 *	Returns:
 *		TRUE:  There may be another page, try again
 *		FALSE: We were interrupted out of our wait, don't try again
 */

boolean_t
vm_page_wait(
	int	interruptible )
{
	/*
	 *	We can't use vm_page_free_reserved to make this
	 *	determination.  Consider: some thread might
	 *	need to allocate two pages.  The first allocation
	 *	succeeds, the second fails.  After the first page is freed,
	 *	a call to vm_page_wait must really block.
	 */
	kern_return_t	wait_result;
	int          	need_wakeup = 0;
	int		is_privileged = current_thread()->options & TH_OPT_VMPRIV;

	lck_mtx_lock_spin(&vm_page_queue_free_lock);

	if (is_privileged && vm_page_free_count) {
		lck_mtx_unlock(&vm_page_queue_free_lock);
		return TRUE;
	}

	if (vm_page_free_count >= vm_page_free_target) {
		lck_mtx_unlock(&vm_page_queue_free_lock);
		return TRUE;
	}

	if (is_privileged) {
		if (vm_page_free_wanted_privileged++ == 0)
			need_wakeup = 1;
		wait_result = assert_wait((event_t)&vm_page_free_wanted_privileged, interruptible);
#if CONFIG_SECLUDED_MEMORY
	} else if (secluded_for_apps &&
		   task_can_use_secluded_mem(current_task())) {
#if 00
		/* XXX FBDP: need pageq lock for this... */
		/* XXX FBDP: might wait even if pages available, */
		/* XXX FBDP: hopefully not for too long... */
		if (vm_page_secluded_count > 0) {
			lck_mtx_unlock(&vm_page_queue_free_lock);
			return TRUE;
		}
#endif
		if (vm_page_free_wanted_secluded++ == 0) {
			need_wakeup = 1;
		}
		wait_result = assert_wait(
			(event_t)&vm_page_free_wanted_secluded,
			interruptible);
#endif /* CONFIG_SECLUDED_MEMORY */
	} else {
		if (vm_page_free_wanted++ == 0)
			need_wakeup = 1;
		wait_result = assert_wait((event_t)&vm_page_free_count,
					  interruptible);
	}
	lck_mtx_unlock(&vm_page_queue_free_lock);
	counter(c_vm_page_wait_block++);

	if (need_wakeup)
		thread_wakeup((event_t)&vm_page_free_wanted);

	if (wait_result == THREAD_WAITING) {
		VM_DEBUG_EVENT(vm_page_wait_block, VM_PAGE_WAIT_BLOCK, DBG_FUNC_START,
			       vm_page_free_wanted_privileged,
			       vm_page_free_wanted,
#if CONFIG_SECLUDED_MEMORY
			       vm_page_free_wanted_secluded,
#else /* CONFIG_SECLUDED_MEMORY */
			       0,
#endif /* CONFIG_SECLUDED_MEMORY */
			       0);
		wait_result = thread_block(THREAD_CONTINUE_NULL);
		VM_DEBUG_EVENT(vm_page_wait_block,
			       VM_PAGE_WAIT_BLOCK, DBG_FUNC_END, 0, 0, 0, 0);
	}

	return (wait_result == THREAD_AWAKENED);
}

/*
 *	vm_page_alloc:
 *
 *	Allocate and return a memory cell associated
 *	with this VM object/offset pair.
 *
 *	Object must be locked.
 */

vm_page_t
vm_page_alloc(
	vm_object_t		object,
	vm_object_offset_t	offset)
{
	vm_page_t	mem;
	int		grab_options;

	vm_object_lock_assert_exclusive(object);
	grab_options = 0;
#if CONFIG_SECLUDED_MEMORY
	if (object->can_grab_secluded) {
		grab_options |= VM_PAGE_GRAB_SECLUDED;
	}
#endif /* CONFIG_SECLUDED_MEMORY */
	mem = vm_page_grab_options(grab_options);
	if (mem == VM_PAGE_NULL)
		return VM_PAGE_NULL;

	vm_page_insert(mem, object, offset);

	return(mem);
}

/*
 *	vm_page_alloc_guard:
 *	
 * 	Allocate a fictitious page which will be used
 *	as a guard page.  The page will be inserted into
 *	the object and returned to the caller.
 */

vm_page_t
vm_page_alloc_guard(
	vm_object_t		object,
	vm_object_offset_t	offset)
{
	vm_page_t	mem;

	vm_object_lock_assert_exclusive(object);
	mem = vm_page_grab_guard();
	if (mem == VM_PAGE_NULL)
		return VM_PAGE_NULL;

	vm_page_insert(mem, object, offset);

	return(mem);
}


counter(unsigned int c_laundry_pages_freed = 0;)

/*
 *	vm_page_free_prepare:
 *
 *	Removes page from any queue it may be on
 *	and disassociates it from its VM object.
 *
 *	Object and page queues must be locked prior to entry.
 */
static void
vm_page_free_prepare(
	vm_page_t	mem)
{
	vm_page_free_prepare_queues(mem);
	vm_page_free_prepare_object(mem, TRUE);
}


void
vm_page_free_prepare_queues(
	vm_page_t	mem)
{
	vm_object_t	m_object;

	VM_PAGE_CHECK(mem);

	assert(mem->vm_page_q_state != VM_PAGE_ON_FREE_Q);
	assert(!mem->cleaning);
	m_object = VM_PAGE_OBJECT(mem);

	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	if (m_object) {
		vm_object_lock_assert_exclusive(m_object);
	}
	if (mem->laundry) {
		/*
		 * We may have to free a page while it's being laundered
		 * if we lost its pager (due to a forced unmount, for example).
		 * We need to call vm_pageout_steal_laundry() before removing
		 * the page from its VM object, so that we can remove it
		 * from its pageout queue and adjust the laundry accounting
		 */
		vm_pageout_steal_laundry(mem, TRUE);
		counter(++c_laundry_pages_freed);
	}
	
	vm_page_queues_remove(mem, TRUE);

	if (VM_PAGE_WIRED(mem)) {
		assert(mem->wire_count > 0);

		if (m_object) {
			assert(m_object->wired_page_count > 0);
			m_object->wired_page_count--;
			if (!m_object->wired_page_count) {
			    VM_OBJECT_UNWIRED(m_object);
			}

			assert(m_object->resident_page_count >=
			       m_object->wired_page_count);

			if (m_object->purgable == VM_PURGABLE_VOLATILE) {
				OSAddAtomic(+1, &vm_page_purgeable_count);
				assert(vm_page_purgeable_wired_count > 0);
				OSAddAtomic(-1, &vm_page_purgeable_wired_count);
			}
			if ((m_object->purgable == VM_PURGABLE_VOLATILE ||
			     m_object->purgable == VM_PURGABLE_EMPTY) &&
			    m_object->vo_purgeable_owner != TASK_NULL) {
				task_t owner;

				owner = m_object->vo_purgeable_owner;
				/*
				 * While wired, this page was accounted
				 * as "non-volatile" but it should now
				 * be accounted as "volatile".
				 */
				/* one less "non-volatile"... */
				ledger_debit(owner->ledger,
					     task_ledgers.purgeable_nonvolatile,
					     PAGE_SIZE);
				/* ... and "phys_footprint" */
				ledger_debit(owner->ledger,
					     task_ledgers.phys_footprint,
					     PAGE_SIZE);
				/* one more "volatile" */
				ledger_credit(owner->ledger,
					      task_ledgers.purgeable_volatile,
					      PAGE_SIZE);
			}
		}
		if (!mem->private && !mem->fictitious)
			vm_page_wire_count--;

		mem->vm_page_q_state = VM_PAGE_NOT_ON_Q;
		mem->wire_count = 0;
		assert(!mem->gobbled);
	} else if (mem->gobbled) {
		if (!mem->private && !mem->fictitious)
			vm_page_wire_count--;
		vm_page_gobble_count--;
	}
}


void
vm_page_free_prepare_object(
	vm_page_t	mem,
	boolean_t	remove_from_hash)
{
	if (mem->tabled)
		vm_page_remove(mem, remove_from_hash);	/* clears tabled, object, offset */

	PAGE_WAKEUP(mem);		/* clears wanted */

	if (mem->private) {
		mem->private = FALSE;
		mem->fictitious = TRUE;
		VM_PAGE_SET_PHYS_PAGE(mem, vm_page_fictitious_addr);
	}
	if ( !mem->fictitious) {
		assert(mem->pageq.next == 0);
		assert(mem->pageq.prev == 0);
		assert(mem->listq.next == 0);
		assert(mem->listq.prev == 0);
#if CONFIG_BACKGROUND_QUEUE
		assert(mem->vm_page_backgroundq.next == 0);
		assert(mem->vm_page_backgroundq.prev == 0);
#endif /* CONFIG_BACKGROUND_QUEUE */
		assert(mem->next_m == 0);
		vm_page_init(mem, VM_PAGE_GET_PHYS_PAGE(mem), mem->lopage);
	}
}


/*
 *	vm_page_free:
 *
 *	Returns the given page to the free list,
 *	disassociating it with any VM object.
 *
 *	Object and page queues must be locked prior to entry.
 */
void
vm_page_free(
	vm_page_t	mem)
{
	vm_page_free_prepare(mem);

	if (mem->fictitious) {
		vm_page_release_fictitious(mem);
	} else {
		vm_page_release(mem,
				TRUE); /* page queues are locked */
	}
}


void
vm_page_free_unlocked(
	vm_page_t	mem,
	boolean_t	remove_from_hash)
{
	vm_page_lockspin_queues();
	vm_page_free_prepare_queues(mem);
	vm_page_unlock_queues();

	vm_page_free_prepare_object(mem, remove_from_hash);

	if (mem->fictitious) {
		vm_page_release_fictitious(mem);
	} else {
		vm_page_release(mem, FALSE); /* page queues are not locked */
	}
}


/*
 * Free a list of pages.  The list can be up to several hundred pages,
 * as blocked up by vm_pageout_scan().
 * The big win is not having to take the free list lock once
 * per page.
 *
 * The VM page queues lock (vm_page_queue_lock) should NOT be held.
 * The VM page free queues lock (vm_page_queue_free_lock) should NOT be held.
 */
void
vm_page_free_list(
	vm_page_t	freeq,
	boolean_t	prepare_object)
{
        vm_page_t	mem;
        vm_page_t	nxt;
	vm_page_t	local_freeq;
	int		pg_count;

	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_NOTOWNED);
	LCK_MTX_ASSERT(&vm_page_queue_free_lock, LCK_MTX_ASSERT_NOTOWNED);

	while (freeq) {

		pg_count = 0;
		local_freeq = VM_PAGE_NULL;
		mem = freeq;

		/*
		 * break up the processing into smaller chunks so
		 * that we can 'pipeline' the pages onto the
		 * free list w/o introducing too much
		 * contention on the global free queue lock
		 */
		while (mem && pg_count < 64) {

			assert(mem->vm_page_q_state == VM_PAGE_NOT_ON_Q);
#if CONFIG_BACKGROUND_QUEUE
			assert(mem->vm_page_backgroundq.next == 0 &&
			       mem->vm_page_backgroundq.prev == 0 &&
			       mem->vm_page_on_backgroundq == FALSE);
#endif
			nxt = mem->snext;
			mem->snext = NULL;
			assert(mem->pageq.prev == 0);

			if (vm_page_free_verify && !mem->fictitious && !mem->private) {
				assert(pmap_verify_free(VM_PAGE_GET_PHYS_PAGE(mem)));
			}
			if (prepare_object == TRUE)
				vm_page_free_prepare_object(mem, TRUE);

			if (!mem->fictitious) {
				assert(mem->busy);

				if ((mem->lopage == TRUE || vm_lopage_refill == TRUE) &&
				    vm_lopage_free_count < vm_lopage_free_limit &&
				    VM_PAGE_GET_PHYS_PAGE(mem) < max_valid_low_ppnum) {
					vm_page_release(mem, FALSE); /* page queues are not locked */
#if CONFIG_SECLUDED_MEMORY
				} else if (vm_page_secluded_count < vm_page_secluded_target &&
					   num_tasks_can_use_secluded_mem == 0) {
					vm_page_release(mem,
							FALSE); /* page queues are not locked */
#endif /* CONFIG_SECLUDED_MEMORY */
				} else {
					/*
					 * IMPORTANT: we can't set the page "free" here
					 * because that would make the page eligible for
					 * a physically-contiguous allocation (see
					 * vm_page_find_contiguous()) right away (we don't
					 * hold the vm_page_queue_free lock).  That would
					 * cause trouble because the page is not actually
					 * in the free queue yet...
					 */
					mem->snext = local_freeq;
					local_freeq = mem;
					pg_count++;

					pmap_clear_noencrypt(VM_PAGE_GET_PHYS_PAGE(mem));
				}
			} else {
				assert(VM_PAGE_GET_PHYS_PAGE(mem) == vm_page_fictitious_addr ||
				       VM_PAGE_GET_PHYS_PAGE(mem) == vm_page_guard_addr);
				vm_page_release_fictitious(mem);
			}
			mem = nxt;
		}
		freeq = mem;

		if ( (mem = local_freeq) ) {
			unsigned int	avail_free_count;
			unsigned int	need_wakeup = 0;
			unsigned int	need_priv_wakeup = 0;
#if CONFIG_SECLUDED_MEMORY
			unsigned int	need_wakeup_secluded = 0;
#endif /* CONFIG_SECLUDED_MEMORY */
	  
			lck_mtx_lock_spin(&vm_page_queue_free_lock);

			while (mem) {
				int	color;

				nxt = mem->snext;

				assert(mem->vm_page_q_state == VM_PAGE_NOT_ON_Q);
				assert(mem->busy);
				mem->lopage = FALSE;
				mem->vm_page_q_state = VM_PAGE_ON_FREE_Q;

				color = VM_PAGE_GET_PHYS_PAGE(mem) & vm_color_mask;
				vm_page_queue_enter_first(&vm_page_queue_free[color].qhead,
							  mem,
							  vm_page_t,
							  pageq);
				mem = nxt;
			}
			vm_page_free_count += pg_count;
			avail_free_count = vm_page_free_count;

			if (vm_page_free_wanted_privileged > 0 && avail_free_count > 0) {

				if (avail_free_count < vm_page_free_wanted_privileged) {
					need_priv_wakeup = avail_free_count;
					vm_page_free_wanted_privileged -= avail_free_count;
					avail_free_count = 0;
				} else {
					need_priv_wakeup = vm_page_free_wanted_privileged;
					avail_free_count -= vm_page_free_wanted_privileged;
					vm_page_free_wanted_privileged = 0;
				}
			}
#if CONFIG_SECLUDED_MEMORY
			if (vm_page_free_wanted_secluded > 0 &&
			    avail_free_count > vm_page_free_reserved) {
				unsigned int available_pages;
				available_pages = (avail_free_count -
						   vm_page_free_reserved);
				if (available_pages <
				    vm_page_free_wanted_secluded) {
					need_wakeup_secluded = available_pages;
					vm_page_free_wanted_secluded -=
						available_pages;
					avail_free_count -= available_pages;
				} else {
					need_wakeup_secluded =
						vm_page_free_wanted_secluded;
					avail_free_count -=
						vm_page_free_wanted_secluded;
					vm_page_free_wanted_secluded = 0;
				}
			}
#endif /* CONFIG_SECLUDED_MEMORY */
			if (vm_page_free_wanted > 0 && avail_free_count > vm_page_free_reserved) {
				unsigned int  available_pages;

				available_pages = avail_free_count - vm_page_free_reserved;

				if (available_pages >= vm_page_free_wanted) {
					need_wakeup = vm_page_free_wanted;
					vm_page_free_wanted = 0;
				} else {
					need_wakeup = available_pages;
					vm_page_free_wanted -= available_pages;
				}
			}
			lck_mtx_unlock(&vm_page_queue_free_lock);

			if (need_priv_wakeup != 0) {
				/*
				 * There shouldn't be that many VM-privileged threads,
				 * so let's wake them all up, even if we don't quite
				 * have enough pages to satisfy them all.
				 */
				thread_wakeup((event_t)&vm_page_free_wanted_privileged);
			}
#if CONFIG_SECLUDED_MEMORY
			if (need_wakeup_secluded != 0 &&
			    vm_page_free_wanted_secluded == 0) {
				thread_wakeup((event_t)
					      &vm_page_free_wanted_secluded);
			} else {
				for (;
				     need_wakeup_secluded != 0;
				     need_wakeup_secluded--) {
					thread_wakeup_one(
						(event_t)
						&vm_page_free_wanted_secluded);
				}
			}
#endif /* CONFIG_SECLUDED_MEMORY */
			if (need_wakeup != 0 && vm_page_free_wanted == 0) {
				/*
				 * We don't expect to have any more waiters
				 * after this, so let's wake them all up at
				 * once.
				 */
				thread_wakeup((event_t) &vm_page_free_count);
			} else for (; need_wakeup != 0; need_wakeup--) {
				/*
				 * Wake up one waiter per page we just released.
				 */
				thread_wakeup_one((event_t) &vm_page_free_count);
			}

			VM_CHECK_MEMORYSTATUS;
		}
	}
}


/*
 *	vm_page_wire:
 *
 *	Mark this page as wired down by yet
 *	another map, removing it from paging queues
 *	as necessary.
 *
 *	The page's object and the page queues must be locked.
 */


void
vm_page_wire(
	vm_page_t mem,
	vm_tag_t           tag,
	boolean_t	   check_memorystatus)
{
	vm_object_t	m_object;

	m_object = VM_PAGE_OBJECT(mem);

//	dbgLog(current_thread(), mem->offset, m_object, 1);	/* (TEST/DEBUG) */

	VM_PAGE_CHECK(mem);
	if (m_object) {
		vm_object_lock_assert_exclusive(m_object);
	} else {
		/*
		 * In theory, the page should be in an object before it
		 * gets wired, since we need to hold the object lock
		 * to update some fields in the page structure.
		 * However, some code (i386 pmap, for example) might want
		 * to wire a page before it gets inserted into an object.
		 * That's somewhat OK, as long as nobody else can get to
		 * that page and update it at the same time.
		 */
	}
	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	if ( !VM_PAGE_WIRED(mem)) {

		if (mem->laundry)
			vm_pageout_steal_laundry(mem, TRUE);

		vm_page_queues_remove(mem, TRUE);

		assert(mem->wire_count == 0);
		mem->vm_page_q_state = VM_PAGE_IS_WIRED;

		if (m_object) {

			if (!mem->private && !mem->fictitious) 
			{
			    if (!m_object->wired_page_count)
			    {
				assert(VM_KERN_MEMORY_NONE != tag);
				m_object->wire_tag = tag;
				VM_OBJECT_WIRED(m_object);
			    }
			}
			m_object->wired_page_count++;

			assert(m_object->resident_page_count >=
			       m_object->wired_page_count);
			if (m_object->purgable == VM_PURGABLE_VOLATILE) {
				assert(vm_page_purgeable_count > 0);
				OSAddAtomic(-1, &vm_page_purgeable_count);
				OSAddAtomic(1, &vm_page_purgeable_wired_count);
			}
			if ((m_object->purgable == VM_PURGABLE_VOLATILE ||
			     m_object->purgable == VM_PURGABLE_EMPTY) &&
			    m_object->vo_purgeable_owner != TASK_NULL) {
				task_t owner;

				owner = m_object->vo_purgeable_owner;
				/* less volatile bytes */
				ledger_debit(owner->ledger,
					     task_ledgers.purgeable_volatile,
					     PAGE_SIZE);
				/* more not-quite-volatile bytes */
				ledger_credit(owner->ledger,
					      task_ledgers.purgeable_nonvolatile,
					      PAGE_SIZE);
				/* more footprint */
				ledger_credit(owner->ledger,
					      task_ledgers.phys_footprint,
					      PAGE_SIZE);
			}
			if (m_object->all_reusable) {
				/*
				 * Wired pages are not counted as "re-usable"
				 * in "all_reusable" VM objects, so nothing
				 * to do here.
				 */
			} else if (mem->reusable) {
				/*
				 * This page is not "re-usable" when it's
				 * wired, so adjust its state and the
				 * accounting.
				 */
				vm_object_reuse_pages(m_object,
						      mem->offset,
						      mem->offset+PAGE_SIZE_64,
						      FALSE);
			}
		}
		assert(!mem->reusable);

		if (!mem->private && !mem->fictitious && !mem->gobbled)
			vm_page_wire_count++;
		if (mem->gobbled)
			vm_page_gobble_count--;
		mem->gobbled = FALSE;

		if (check_memorystatus == TRUE) {
			VM_CHECK_MEMORYSTATUS;
		}
		/* 
		 * ENCRYPTED SWAP:
		 * The page could be encrypted, but
		 * We don't have to decrypt it here
		 * because we don't guarantee that the
		 * data is actually valid at this point.
		 * The page will get decrypted in
		 * vm_fault_wire() if needed.
		 */
	}
	assert(!mem->gobbled);
	assert(mem->vm_page_q_state == VM_PAGE_IS_WIRED);
	mem->wire_count++;
	if (__improbable(mem->wire_count == 0)) {
		panic("vm_page_wire(%p): wire_count overflow", mem);
	}
	VM_PAGE_CHECK(mem);
}

/*
 *	vm_page_unwire:
 *
 *	Release one wiring of this page, potentially
 *	enabling it to be paged again.
 *
 *	The page's object and the page queues must be locked.
 */
void
vm_page_unwire(
	vm_page_t	mem,
	boolean_t	queueit)
{
	vm_object_t	m_object;

	m_object = VM_PAGE_OBJECT(mem);

//	dbgLog(current_thread(), mem->offset, m_object, 0);	/* (TEST/DEBUG) */

	VM_PAGE_CHECK(mem);
	assert(VM_PAGE_WIRED(mem));
	assert(mem->wire_count > 0);
	assert(!mem->gobbled);
	assert(m_object != VM_OBJECT_NULL);
	vm_object_lock_assert_exclusive(m_object);
	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	if (--mem->wire_count == 0) {
		mem->vm_page_q_state = VM_PAGE_NOT_ON_Q;

		if (!mem->private && !mem->fictitious) {
			vm_page_wire_count--;
		}
		assert(m_object->wired_page_count > 0);
		m_object->wired_page_count--;
		if (!m_object->wired_page_count) {
		    VM_OBJECT_UNWIRED(m_object);
		}
		assert(m_object->resident_page_count >=
		       m_object->wired_page_count);
		if (m_object->purgable == VM_PURGABLE_VOLATILE) {
			OSAddAtomic(+1, &vm_page_purgeable_count);
			assert(vm_page_purgeable_wired_count > 0);
			OSAddAtomic(-1, &vm_page_purgeable_wired_count);
		}
		if ((m_object->purgable == VM_PURGABLE_VOLATILE ||
		     m_object->purgable == VM_PURGABLE_EMPTY) &&
		    m_object->vo_purgeable_owner != TASK_NULL) {
			task_t owner;

			owner = m_object->vo_purgeable_owner;
			/* more volatile bytes */
			ledger_credit(owner->ledger,
				      task_ledgers.purgeable_volatile,
				      PAGE_SIZE);
			/* less not-quite-volatile bytes */
			ledger_debit(owner->ledger,
				     task_ledgers.purgeable_nonvolatile,
				     PAGE_SIZE);
			/* less footprint */
			ledger_debit(owner->ledger,
				     task_ledgers.phys_footprint,
				     PAGE_SIZE);
		}
		assert(m_object != kernel_object);
		assert(mem->pageq.next == 0 && mem->pageq.prev == 0);

		if (queueit == TRUE) {
			if (m_object->purgable == VM_PURGABLE_EMPTY) {
				vm_page_deactivate(mem);
			} else {
				vm_page_activate(mem);
			}
		}

		VM_CHECK_MEMORYSTATUS;
		
	}
	VM_PAGE_CHECK(mem);
}

/*
 *	vm_page_deactivate:
 *
 *	Returns the given page to the inactive list,
 *	indicating that no physical maps have access
 *	to this page.  [Used by the physical mapping system.]
 *
 *	The page queues must be locked.
 */
void
vm_page_deactivate(
	vm_page_t	m)
{
	vm_page_deactivate_internal(m, TRUE);
}


void
vm_page_deactivate_internal(
	vm_page_t	m,
	boolean_t	clear_hw_reference)
{
	vm_object_t	m_object;

	m_object = VM_PAGE_OBJECT(m);

	VM_PAGE_CHECK(m);
	assert(m_object != kernel_object);
	assert(VM_PAGE_GET_PHYS_PAGE(m) != vm_page_guard_addr);

//	dbgLog(VM_PAGE_GET_PHYS_PAGE(m), vm_page_free_count, vm_page_wire_count, 6);	/* (TEST/DEBUG) */
	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	/*
	 *	This page is no longer very interesting.  If it was
	 *	interesting (active or inactive/referenced), then we
	 *	clear the reference bit and (re)enter it in the
	 *	inactive queue.  Note wired pages should not have
	 *	their reference bit cleared.
	 */
	assert ( !(m->absent && !m->unusual));

	if (m->gobbled) {		/* can this happen? */
		assert( !VM_PAGE_WIRED(m));

		if (!m->private && !m->fictitious)
			vm_page_wire_count--;
		vm_page_gobble_count--;
		m->gobbled = FALSE;
	}
	/*
	 * if this page is currently on the pageout queue, we can't do the
	 * vm_page_queues_remove (which doesn't handle the pageout queue case)
	 * and we can't remove it manually since we would need the object lock
	 * (which is not required here) to decrement the activity_in_progress
	 * reference which is held on the object while the page is in the pageout queue...
	 * just let the normal laundry processing proceed
	 */
	if (m->laundry || m->private || m->fictitious ||
	    (m->vm_page_q_state == VM_PAGE_USED_BY_COMPRESSOR) ||
	    (m->vm_page_q_state == VM_PAGE_ON_PAGEOUT_Q) ||
	    VM_PAGE_WIRED(m)) {
 		return;
	}
	if (!m->absent && clear_hw_reference == TRUE)
		pmap_clear_reference(VM_PAGE_GET_PHYS_PAGE(m));

	m->reference = FALSE;
	m->no_cache = FALSE;

	if ( !VM_PAGE_INACTIVE(m)) {
		vm_page_queues_remove(m, FALSE);

		if (!VM_DYNAMIC_PAGING_ENABLED() &&
		    m->dirty && m_object->internal &&
		    (m_object->purgable == VM_PURGABLE_DENY ||
		     m_object->purgable == VM_PURGABLE_NONVOLATILE ||
		     m_object->purgable == VM_PURGABLE_VOLATILE)) {
			vm_page_check_pageable_safe(m);
			vm_page_queue_enter(&vm_page_queue_throttled, m, vm_page_t, pageq);
			m->vm_page_q_state = VM_PAGE_ON_THROTTLED_Q;
			vm_page_throttled_count++;
		} else {
			if (m_object->named && m_object->ref_count == 1) {
			        vm_page_speculate(m, FALSE);
#if DEVELOPMENT || DEBUG
				vm_page_speculative_recreated++;
#endif
			} else {
				vm_page_enqueue_inactive(m, FALSE);
			}
		}
	}
}

/*
 * vm_page_enqueue_cleaned
 *
 * Put the page on the cleaned queue, mark it cleaned, etc.
 * Being on the cleaned queue (and having m->clean_queue set)
 * does ** NOT ** guarantee that the page is clean!
 *
 * Call with the queues lock held.
 */

void vm_page_enqueue_cleaned(vm_page_t m)
{
	vm_object_t	m_object;

	m_object = VM_PAGE_OBJECT(m);

	assert(VM_PAGE_GET_PHYS_PAGE(m) != vm_page_guard_addr);
	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	assert( !(m->absent && !m->unusual));
	assert( !VM_PAGE_WIRED(m));

	if (m->gobbled) {
		if (!m->private && !m->fictitious)
			vm_page_wire_count--;
		vm_page_gobble_count--;
		m->gobbled = FALSE;
	}
	/*
	 * if this page is currently on the pageout queue, we can't do the
	 * vm_page_queues_remove (which doesn't handle the pageout queue case)
	 * and we can't remove it manually since we would need the object lock
	 * (which is not required here) to decrement the activity_in_progress
	 * reference which is held on the object while the page is in the pageout queue...
	 * just let the normal laundry processing proceed
	 */
	if (m->laundry || m->private || m->fictitious ||
	    (m->vm_page_q_state == VM_PAGE_ON_INACTIVE_CLEANED_Q) ||
	    (m->vm_page_q_state == VM_PAGE_ON_PAGEOUT_Q)) {
		    return;
	}
	vm_page_queues_remove(m, FALSE);

	vm_page_check_pageable_safe(m);
	vm_page_queue_enter(&vm_page_queue_cleaned, m, vm_page_t, pageq);
	m->vm_page_q_state = VM_PAGE_ON_INACTIVE_CLEANED_Q;
	vm_page_cleaned_count++;

	vm_page_inactive_count++;
	if (m_object->internal) {
		vm_page_pageable_internal_count++;
	} else {
		vm_page_pageable_external_count++;
	}
#if CONFIG_BACKGROUND_QUEUE
	if (m->vm_page_in_background)
		vm_page_add_to_backgroundq(m, TRUE);
#endif
	vm_pageout_enqueued_cleaned++;
}

/*
 *	vm_page_activate:
 *
 *	Put the specified page on the active list (if appropriate).
 *
 *	The page queues must be locked.
 */

void
vm_page_activate(
	vm_page_t	m)
{
	vm_object_t	m_object;

	m_object = VM_PAGE_OBJECT(m);

	VM_PAGE_CHECK(m);
#ifdef	FIXME_4778297
	assert(m_object != kernel_object);
#endif
	assert(VM_PAGE_GET_PHYS_PAGE(m) != vm_page_guard_addr);
	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	assert( !(m->absent && !m->unusual));

	if (m->gobbled) {
		assert( !VM_PAGE_WIRED(m));
		if (!m->private && !m->fictitious)
			vm_page_wire_count--;
		vm_page_gobble_count--;
		m->gobbled = FALSE;
	}
	/*
	 * if this page is currently on the pageout queue, we can't do the
	 * vm_page_queues_remove (which doesn't handle the pageout queue case)
	 * and we can't remove it manually since we would need the object lock
	 * (which is not required here) to decrement the activity_in_progress
	 * reference which is held on the object while the page is in the pageout queue...
	 * just let the normal laundry processing proceed
	 */
	if (m->laundry || m->private || m->fictitious ||
	    (m->vm_page_q_state == VM_PAGE_USED_BY_COMPRESSOR) ||
	    (m->vm_page_q_state == VM_PAGE_ON_PAGEOUT_Q))
		return;

#if DEBUG
	if (m->vm_page_q_state == VM_PAGE_ON_ACTIVE_Q)
	        panic("vm_page_activate: already active");
#endif

	if (m->vm_page_q_state == VM_PAGE_ON_SPECULATIVE_Q) {
		DTRACE_VM2(pgrec, int, 1, (uint64_t *), NULL);
		DTRACE_VM2(pgfrec, int, 1, (uint64_t *), NULL);
	}
	
	vm_page_queues_remove(m, FALSE);

	if ( !VM_PAGE_WIRED(m)) {
		vm_page_check_pageable_safe(m);
		if (!VM_DYNAMIC_PAGING_ENABLED() && 
		    m->dirty && m_object->internal && 
		    (m_object->purgable == VM_PURGABLE_DENY ||
		     m_object->purgable == VM_PURGABLE_NONVOLATILE ||
		     m_object->purgable == VM_PURGABLE_VOLATILE)) {
			vm_page_queue_enter(&vm_page_queue_throttled, m, vm_page_t, pageq);
			m->vm_page_q_state = VM_PAGE_ON_THROTTLED_Q;
			vm_page_throttled_count++;
		} else {
#if CONFIG_SECLUDED_MEMORY
			if (secluded_for_filecache &&
			    vm_page_secluded_target != 0 &&
			    num_tasks_can_use_secluded_mem == 0 &&
			    m_object->eligible_for_secluded &&
			    ((secluded_aging_policy == SECLUDED_AGING_FIFO) ||
			     (secluded_aging_policy ==
			      SECLUDED_AGING_ALONG_ACTIVE) ||
			     (secluded_aging_policy ==
			      SECLUDED_AGING_BEFORE_ACTIVE))) {
				vm_page_queue_enter(&vm_page_queue_secluded, m,
						    vm_page_t, pageq);
				m->vm_page_q_state = VM_PAGE_ON_SECLUDED_Q;
				vm_page_secluded_count++;
				vm_page_secluded_count_inuse++;
				assert(!m_object->internal);
//				vm_page_pageable_external_count++;
			} else
#endif /* CONFIG_SECLUDED_MEMORY */
			vm_page_enqueue_active(m, FALSE);
		}
		m->reference = TRUE;
		m->no_cache = FALSE;
	}
	VM_PAGE_CHECK(m);
}


/*
 *      vm_page_speculate:
 *
 *      Put the specified page on the speculative list (if appropriate).
 *
 *      The page queues must be locked.
 */
void
vm_page_speculate(
	vm_page_t	m,
	boolean_t	new)
{
        struct vm_speculative_age_q	*aq;
	vm_object_t	m_object;

	m_object = VM_PAGE_OBJECT(m);

	VM_PAGE_CHECK(m);
	vm_page_check_pageable_safe(m);

	assert(VM_PAGE_GET_PHYS_PAGE(m) != vm_page_guard_addr);
	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	assert( !(m->absent && !m->unusual));
	assert(m_object->internal == FALSE);

	/*
	 * if this page is currently on the pageout queue, we can't do the
	 * vm_page_queues_remove (which doesn't handle the pageout queue case)
	 * and we can't remove it manually since we would need the object lock
	 * (which is not required here) to decrement the activity_in_progress
	 * reference which is held on the object while the page is in the pageout queue...
	 * just let the normal laundry processing proceed
	 */
	if (m->laundry || m->private || m->fictitious ||
	    (m->vm_page_q_state == VM_PAGE_USED_BY_COMPRESSOR) ||
	    (m->vm_page_q_state == VM_PAGE_ON_PAGEOUT_Q))
		return;

	vm_page_queues_remove(m, FALSE);

	if ( !VM_PAGE_WIRED(m)) {
	        mach_timespec_t		ts;
		clock_sec_t sec;
		clock_nsec_t nsec;

	        clock_get_system_nanotime(&sec, &nsec);
		ts.tv_sec = (unsigned int) sec;
		ts.tv_nsec = nsec;

		if (vm_page_speculative_count == 0) {

			speculative_age_index = VM_PAGE_MIN_SPECULATIVE_AGE_Q;
			speculative_steal_index = VM_PAGE_MIN_SPECULATIVE_AGE_Q;

			aq = &vm_page_queue_speculative[speculative_age_index];

		        /*
			 * set the timer to begin a new group
			 */
			aq->age_ts.tv_sec = vm_page_speculative_q_age_ms / 1000;
			aq->age_ts.tv_nsec = (vm_page_speculative_q_age_ms % 1000) * 1000 * NSEC_PER_USEC;

			ADD_MACH_TIMESPEC(&aq->age_ts, &ts);
		} else {
			aq = &vm_page_queue_speculative[speculative_age_index];

			if (CMP_MACH_TIMESPEC(&ts, &aq->age_ts) >= 0) {

			        speculative_age_index++;

				if (speculative_age_index > VM_PAGE_MAX_SPECULATIVE_AGE_Q)
				        speculative_age_index = VM_PAGE_MIN_SPECULATIVE_AGE_Q;
				if (speculative_age_index == speculative_steal_index) {
				        speculative_steal_index = speculative_age_index + 1;

					if (speculative_steal_index > VM_PAGE_MAX_SPECULATIVE_AGE_Q)
					        speculative_steal_index = VM_PAGE_MIN_SPECULATIVE_AGE_Q;
				}
				aq = &vm_page_queue_speculative[speculative_age_index];

				if (!vm_page_queue_empty(&aq->age_q))
				        vm_page_speculate_ageit(aq);

				aq->age_ts.tv_sec = vm_page_speculative_q_age_ms / 1000;
				aq->age_ts.tv_nsec = (vm_page_speculative_q_age_ms % 1000) * 1000 * NSEC_PER_USEC;

				ADD_MACH_TIMESPEC(&aq->age_ts, &ts);
			}
		}
		vm_page_enqueue_tail(&aq->age_q, &m->pageq);
		m->vm_page_q_state = VM_PAGE_ON_SPECULATIVE_Q;
		vm_page_speculative_count++;
		vm_page_pageable_external_count++;

		if (new == TRUE) {
			vm_object_lock_assert_exclusive(m_object);

		        m_object->pages_created++;
#if DEVELOPMENT || DEBUG
			vm_page_speculative_created++;
#endif
		}
	}
	VM_PAGE_CHECK(m);
}


/*
 * move pages from the specified aging bin to
 * the speculative bin that pageout_scan claims from
 *
 *      The page queues must be locked.
 */
void
vm_page_speculate_ageit(struct vm_speculative_age_q *aq)
{
        struct vm_speculative_age_q	*sq;
	vm_page_t	t;

	sq = &vm_page_queue_speculative[VM_PAGE_SPECULATIVE_AGED_Q];

	if (vm_page_queue_empty(&sq->age_q)) {
	        sq->age_q.next = aq->age_q.next;
		sq->age_q.prev = aq->age_q.prev;
		
		t = (vm_page_t)VM_PAGE_UNPACK_PTR(sq->age_q.next);
		t->pageq.prev = VM_PAGE_PACK_PTR(&sq->age_q);

		t = (vm_page_t)VM_PAGE_UNPACK_PTR(sq->age_q.prev);
		t->pageq.next = VM_PAGE_PACK_PTR(&sq->age_q);
	} else {
	        t = (vm_page_t)VM_PAGE_UNPACK_PTR(sq->age_q.prev);
		t->pageq.next = aq->age_q.next;
						
		t = (vm_page_t)VM_PAGE_UNPACK_PTR(aq->age_q.next);
		t->pageq.prev = sq->age_q.prev;

		t = (vm_page_t)VM_PAGE_UNPACK_PTR(aq->age_q.prev);
		t->pageq.next = VM_PAGE_PACK_PTR(&sq->age_q);

		sq->age_q.prev = aq->age_q.prev;
	}
	vm_page_queue_init(&aq->age_q);
}


void
vm_page_lru(
	vm_page_t	m)
{
	VM_PAGE_CHECK(m);
	assert(VM_PAGE_OBJECT(m) != kernel_object);
	assert(VM_PAGE_GET_PHYS_PAGE(m) != vm_page_guard_addr);

	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	/*
	 * if this page is currently on the pageout queue, we can't do the
	 * vm_page_queues_remove (which doesn't handle the pageout queue case)
	 * and we can't remove it manually since we would need the object lock
	 * (which is not required here) to decrement the activity_in_progress
	 * reference which is held on the object while the page is in the pageout queue...
	 * just let the normal laundry processing proceed
	 */
	if (m->laundry || m->private ||
	    (m->vm_page_q_state == VM_PAGE_USED_BY_COMPRESSOR) ||
	    (m->vm_page_q_state == VM_PAGE_ON_PAGEOUT_Q) ||
	    VM_PAGE_WIRED(m))
		return;

	m->no_cache = FALSE;

	vm_page_queues_remove(m, FALSE);

	vm_page_enqueue_inactive(m, FALSE);
}


void
vm_page_reactivate_all_throttled(void)
{
	vm_page_t	first_throttled, last_throttled;
	vm_page_t	first_active;
	vm_page_t	m;
	int		extra_active_count;
	int		extra_internal_count, extra_external_count;
	vm_object_t	m_object;

	if (!VM_DYNAMIC_PAGING_ENABLED())
		return;

	extra_active_count = 0;
	extra_internal_count = 0;
	extra_external_count = 0;
	vm_page_lock_queues();
	if (! vm_page_queue_empty(&vm_page_queue_throttled)) {
		/*
		 * Switch "throttled" pages to "active".
		 */
		vm_page_queue_iterate(&vm_page_queue_throttled, m, vm_page_t, pageq) {
			VM_PAGE_CHECK(m);
			assert(m->vm_page_q_state == VM_PAGE_ON_THROTTLED_Q);

			m_object = VM_PAGE_OBJECT(m);

			extra_active_count++;
			if (m_object->internal) {
				extra_internal_count++;
			} else {
				extra_external_count++;
			}

			m->vm_page_q_state = VM_PAGE_ON_ACTIVE_Q;
			VM_PAGE_CHECK(m);
#if CONFIG_BACKGROUND_QUEUE
			if (m->vm_page_in_background)
				vm_page_add_to_backgroundq(m, FALSE);
#endif
		}

		/*
		 * Transfer the entire throttled queue to a regular LRU page queues.
		 * We insert it at the head of the active queue, so that these pages
		 * get re-evaluated by the LRU algorithm first, since they've been
		 * completely out of it until now.
		 */
		first_throttled = (vm_page_t) vm_page_queue_first(&vm_page_queue_throttled);
		last_throttled = (vm_page_t) vm_page_queue_last(&vm_page_queue_throttled);
		first_active = (vm_page_t) vm_page_queue_first(&vm_page_queue_active);
		if (vm_page_queue_empty(&vm_page_queue_active)) {
			vm_page_queue_active.prev = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(last_throttled);
		} else {
			first_active->pageq.prev = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(last_throttled);
		}
		vm_page_queue_active.next = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(first_throttled);
		first_throttled->pageq.prev = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(&vm_page_queue_active);
		last_throttled->pageq.next = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(first_active);

#if DEBUG
		printf("reactivated %d throttled pages\n", vm_page_throttled_count);
#endif
		vm_page_queue_init(&vm_page_queue_throttled);
		/*
		 * Adjust the global page counts.
		 */
		vm_page_active_count += extra_active_count;
		vm_page_pageable_internal_count += extra_internal_count;
		vm_page_pageable_external_count += extra_external_count;
		vm_page_throttled_count = 0;
	}
	assert(vm_page_throttled_count == 0);
	assert(vm_page_queue_empty(&vm_page_queue_throttled));
	vm_page_unlock_queues();
}


/*
 * move pages from the indicated local queue to the global active queue
 * its ok to fail if we're below the hard limit and force == FALSE
 * the nolocks == TRUE case is to allow this function to be run on
 * the hibernate path
 */

void
vm_page_reactivate_local(uint32_t lid, boolean_t force, boolean_t nolocks)
{
	struct vpl	*lq;
	vm_page_t	first_local, last_local;
	vm_page_t	first_active;
	vm_page_t	m;
	uint32_t	count = 0;

	if (vm_page_local_q == NULL)
		return;

	lq = &vm_page_local_q[lid].vpl_un.vpl;

	if (nolocks == FALSE) {
		if (lq->vpl_count < vm_page_local_q_hard_limit && force == FALSE) {
			if ( !vm_page_trylockspin_queues())
				return;
		} else
			vm_page_lockspin_queues();

		VPL_LOCK(&lq->vpl_lock);
	}
	if (lq->vpl_count) {
		/*
		 * Switch "local" pages to "active".
		 */
		assert(!vm_page_queue_empty(&lq->vpl_queue));

		vm_page_queue_iterate(&lq->vpl_queue, m, vm_page_t, pageq) {
			VM_PAGE_CHECK(m);
			vm_page_check_pageable_safe(m);
			assert(m->vm_page_q_state == VM_PAGE_ON_ACTIVE_LOCAL_Q);
			assert(!m->fictitious);

			if (m->local_id != lid)
				panic("vm_page_reactivate_local: found vm_page_t(%p) with wrong cpuid", m);
			
			m->local_id = 0;
			m->vm_page_q_state = VM_PAGE_ON_ACTIVE_Q;
			VM_PAGE_CHECK(m);
#if CONFIG_BACKGROUND_QUEUE
			if (m->vm_page_in_background)
				vm_page_add_to_backgroundq(m, FALSE);
#endif
			count++;
		}
		if (count != lq->vpl_count)
			panic("vm_page_reactivate_local: count = %d, vm_page_local_count = %d\n", count, lq->vpl_count);

		/*
		 * Transfer the entire local queue to a regular LRU page queues.
		 */
		first_local = (vm_page_t) vm_page_queue_first(&lq->vpl_queue);
		last_local = (vm_page_t) vm_page_queue_last(&lq->vpl_queue);
		first_active = (vm_page_t) vm_page_queue_first(&vm_page_queue_active);

		if (vm_page_queue_empty(&vm_page_queue_active)) {
			vm_page_queue_active.prev = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(last_local);
		} else {
			first_active->pageq.prev = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(last_local);
		}
		vm_page_queue_active.next = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(first_local);
		first_local->pageq.prev = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(&vm_page_queue_active);
		last_local->pageq.next = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(first_active);

		vm_page_queue_init(&lq->vpl_queue);
		/*
		 * Adjust the global page counts.
		 */
		vm_page_active_count += lq->vpl_count;
		vm_page_pageable_internal_count += lq->vpl_internal_count;
		vm_page_pageable_external_count += lq->vpl_external_count;
		lq->vpl_count = 0;
		lq->vpl_internal_count = 0;
		lq->vpl_external_count = 0;
	}
	assert(vm_page_queue_empty(&lq->vpl_queue));

	if (nolocks == FALSE) {
		VPL_UNLOCK(&lq->vpl_lock);
		vm_page_unlock_queues();
	}
}

/*
 *	vm_page_part_zero_fill:
 *
 *	Zero-fill a part of the page.
 */
#define PMAP_ZERO_PART_PAGE_IMPLEMENTED
void
vm_page_part_zero_fill(
	vm_page_t	m,
	vm_offset_t	m_pa,
	vm_size_t	len)
{

#if 0
	/*
	 * we don't hold the page queue lock
	 * so this check isn't safe to make
	 */
	VM_PAGE_CHECK(m);
#endif

#ifdef PMAP_ZERO_PART_PAGE_IMPLEMENTED
	pmap_zero_part_page(VM_PAGE_GET_PHYS_PAGE(m), m_pa, len);
#else
	vm_page_t	tmp;
	while (1) {
       		tmp = vm_page_grab();
		if (tmp == VM_PAGE_NULL) {
			vm_page_wait(THREAD_UNINT);
			continue;
		}
		break;  
	}
	vm_page_zero_fill(tmp);
	if(m_pa != 0) {
		vm_page_part_copy(m, 0, tmp, 0, m_pa);
	}
	if((m_pa + len) <  PAGE_SIZE) {
		vm_page_part_copy(m, m_pa + len, tmp, 
				m_pa + len, PAGE_SIZE - (m_pa + len));
	}
	vm_page_copy(tmp,m);
	VM_PAGE_FREE(tmp); 
#endif

}

/*
 *	vm_page_zero_fill:
 *
 *	Zero-fill the specified page.
 */
void
vm_page_zero_fill(
	vm_page_t	m)
{
        XPR(XPR_VM_PAGE,
	    "vm_page_zero_fill, object 0x%X offset 0x%X page 0x%X\n",
	    VM_PAGE_OBJECT(m), m->offset, m, 0,0);
#if 0
	/*
	 * we don't hold the page queue lock
	 * so this check isn't safe to make
	 */
	VM_PAGE_CHECK(m);
#endif

//	dbgTrace(0xAEAEAEAE, VM_PAGE_GET_PHYS_PAGE(m), 0);		/* (BRINGUP) */
	pmap_zero_page(VM_PAGE_GET_PHYS_PAGE(m));
}

/*
 *	vm_page_part_copy:
 *
 *	copy part of one page to another
 */

void
vm_page_part_copy(
	vm_page_t	src_m,
	vm_offset_t	src_pa,
	vm_page_t	dst_m,
	vm_offset_t	dst_pa,
	vm_size_t	len)
{
#if 0
	/*
	 * we don't hold the page queue lock
	 * so this check isn't safe to make
	 */
	VM_PAGE_CHECK(src_m);
	VM_PAGE_CHECK(dst_m);
#endif
	pmap_copy_part_page(VM_PAGE_GET_PHYS_PAGE(src_m), src_pa,
			    VM_PAGE_GET_PHYS_PAGE(dst_m), dst_pa, len);
}

/*
 *	vm_page_copy:
 *
 *	Copy one page to another
 *
 * ENCRYPTED SWAP:
 * The source page should not be encrypted.  The caller should
 * make sure the page is decrypted first, if necessary.
 */

int vm_page_copy_cs_validations = 0;
int vm_page_copy_cs_tainted = 0;

void
vm_page_copy(
	vm_page_t	src_m,
	vm_page_t	dest_m)
{
	vm_object_t	src_m_object;

	src_m_object = VM_PAGE_OBJECT(src_m);

        XPR(XPR_VM_PAGE,
	    "vm_page_copy, object 0x%X offset 0x%X to object 0x%X offset 0x%X\n",
	    src_m_object, src_m->offset, 
	    VM_PAGE_OBJECT(dest_m), dest_m->offset,
	    0);
#if 0
	/*
	 * we don't hold the page queue lock
	 * so this check isn't safe to make
	 */
	VM_PAGE_CHECK(src_m);
	VM_PAGE_CHECK(dest_m);
#endif
	vm_object_lock_assert_held(src_m_object);

	/*
	 * ENCRYPTED SWAP:
	 * The source page should not be encrypted at this point.
	 * The destination page will therefore not contain encrypted
	 * data after the copy.
	 */
	if (src_m->encrypted) {
		panic("vm_page_copy: source page %p is encrypted\n", src_m);
	}
	dest_m->encrypted = FALSE;

	if (src_m_object != VM_OBJECT_NULL &&
	    src_m_object->code_signed) {
		/*
		 * We're copying a page from a code-signed object.
		 * Whoever ends up mapping the copy page might care about
		 * the original page's integrity, so let's validate the
		 * source page now.
		 */
		vm_page_copy_cs_validations++;
		vm_page_validate_cs(src_m);
#if DEVELOPMENT || DEBUG
		DTRACE_VM4(codesigned_copy,
			   vm_object_t, src_m_object,
			   vm_object_offset_t, src_m->offset,
			   int, src_m->cs_validated,
			   int, src_m->cs_tainted);
#endif /* DEVELOPMENT || DEBUG */

	}

	if (vm_page_is_slideable(src_m)) {
		boolean_t was_busy = src_m->busy;
		src_m->busy = TRUE;
		(void) vm_page_slide(src_m, 0);
		assert(src_m->busy);
		if (!was_busy) {
			PAGE_WAKEUP_DONE(src_m);
		}
	}

	/*
	 * Propagate the cs_tainted bit to the copy page. Do not propagate
	 * the cs_validated bit.
	 */
	dest_m->cs_tainted = src_m->cs_tainted;
	if (dest_m->cs_tainted) {
		vm_page_copy_cs_tainted++;
	}
	dest_m->slid = src_m->slid;
	dest_m->error = src_m->error; /* sliding src_m might have failed... */
	pmap_copy_page(VM_PAGE_GET_PHYS_PAGE(src_m), VM_PAGE_GET_PHYS_PAGE(dest_m));
}

#if MACH_ASSERT
static void
_vm_page_print(
	vm_page_t	p)
{
	printf("vm_page %p: \n", p);
	printf("  pageq: next=%p prev=%p\n",
	       (vm_page_t)VM_PAGE_UNPACK_PTR(p->pageq.next),
	       (vm_page_t)VM_PAGE_UNPACK_PTR(p->pageq.prev));
	printf("  listq: next=%p prev=%p\n",
	       (vm_page_t)(VM_PAGE_UNPACK_PTR(p->listq.next)),
	       (vm_page_t)(VM_PAGE_UNPACK_PTR(p->listq.prev)));
	printf("  next=%p\n", (vm_page_t)(VM_PAGE_UNPACK_PTR(p->next_m)));
	printf("  object=%p offset=0x%llx\n",VM_PAGE_OBJECT(p), p->offset);
	printf("  wire_count=%u\n", p->wire_count);
	printf("  q_state=%u\n", p->vm_page_q_state);

	printf("  %slaundry, %sref, %sgobbled, %sprivate\n",
	       (p->laundry ? "" : "!"),
	       (p->reference ? "" : "!"),
	       (p->gobbled ? "" : "!"),
	       (p->private ? "" : "!"));
	printf("  %sbusy, %swanted, %stabled, %sfictitious, %spmapped, %swpmapped\n",
	       (p->busy ? "" : "!"),
	       (p->wanted ? "" : "!"),
	       (p->tabled ? "" : "!"),
	       (p->fictitious ? "" : "!"),
	       (p->pmapped ? "" : "!"),
	       (p->wpmapped ? "" : "!"));
	printf("  %sfree_when_done, %sabsent, %serror, %sdirty, %scleaning, %sprecious, %sclustered\n",
	       (p->free_when_done ? "" : "!"),
	       (p->absent ? "" : "!"),
	       (p->error ? "" : "!"),
	       (p->dirty ? "" : "!"),
	       (p->cleaning ? "" : "!"),
	       (p->precious ? "" : "!"),
	       (p->clustered ? "" : "!"));
	printf("  %soverwriting, %srestart, %sunusual, %sencrypted, %sencrypted_cleaning\n",
	       (p->overwriting ? "" : "!"),
	       (p->restart ? "" : "!"),
	       (p->unusual ? "" : "!"),
	       (p->encrypted ? "" : "!"),
	       (p->encrypted_cleaning ? "" : "!"));
	printf("  %scs_validated, %scs_tainted, %scs_nx, %sno_cache\n",
	       (p->cs_validated ? "" : "!"),
	       (p->cs_tainted ? "" : "!"),
	       (p->cs_nx ? "" : "!"),
	       (p->no_cache ? "" : "!"));

	printf("phys_page=0x%x\n", VM_PAGE_GET_PHYS_PAGE(p));
}

/*
 *	Check that the list of pages is ordered by
 *	ascending physical address and has no holes.
 */
static int
vm_page_verify_contiguous(
	vm_page_t	pages,
	unsigned int	npages)
{
	vm_page_t		m;
	unsigned int		page_count;
	vm_offset_t		prev_addr;

	prev_addr = VM_PAGE_GET_PHYS_PAGE(pages);
	page_count = 1;
	for (m = NEXT_PAGE(pages); m != VM_PAGE_NULL; m = NEXT_PAGE(m)) {
		if (VM_PAGE_GET_PHYS_PAGE(m) != prev_addr + 1) {
			printf("m %p prev_addr 0x%lx, current addr 0x%x\n",
			       m, (long)prev_addr, VM_PAGE_GET_PHYS_PAGE(m));
			printf("pages %p page_count %d npages %d\n", pages, page_count, npages);
			panic("vm_page_verify_contiguous:  not contiguous!");
		}
		prev_addr = VM_PAGE_GET_PHYS_PAGE(m);
		++page_count;
	}
	if (page_count != npages) {
		printf("pages %p actual count 0x%x but requested 0x%x\n",
		       pages, page_count, npages);
		panic("vm_page_verify_contiguous:  count error");
	}
	return 1;
}


/*
 *	Check the free lists for proper length etc.
 */
static boolean_t vm_page_verify_this_free_list_enabled = FALSE;
static unsigned int
vm_page_verify_free_list(
	vm_page_queue_head_t	*vm_page_queue,
	unsigned int	color,
	vm_page_t	look_for_page,
	boolean_t	expect_page)
{
	unsigned int 	npages;
	vm_page_t	m;
	vm_page_t	prev_m;
	boolean_t	found_page;

	if (! vm_page_verify_this_free_list_enabled)
		return 0;

	found_page = FALSE;
	npages = 0;
	prev_m = (vm_page_t)((uintptr_t)vm_page_queue);

	vm_page_queue_iterate(vm_page_queue,
			      m,
			      vm_page_t,
			      pageq) {

		if (m == look_for_page) {
			found_page = TRUE;
		}
		if ((vm_page_t)VM_PAGE_UNPACK_PTR(m->pageq.prev) != prev_m)
			panic("vm_page_verify_free_list(color=%u, npages=%u): page %p corrupted prev ptr %p instead of %p\n",
			      color, npages, m, (vm_page_t)VM_PAGE_UNPACK_PTR(m->pageq.prev), prev_m);
		if ( ! m->busy )
			panic("vm_page_verify_free_list(color=%u, npages=%u): page %p not busy\n",
			      color, npages, m);
		if (color != (unsigned int) -1) {
			if ((VM_PAGE_GET_PHYS_PAGE(m) & vm_color_mask) != color)
				panic("vm_page_verify_free_list(color=%u, npages=%u): page %p wrong color %u instead of %u\n",
				      color, npages, m, VM_PAGE_GET_PHYS_PAGE(m) & vm_color_mask, color);
			if (m->vm_page_q_state != VM_PAGE_ON_FREE_Q)
				panic("vm_page_verify_free_list(color=%u, npages=%u): page %p - expecting q_state == VM_PAGE_ON_FREE_Q, found %d\n",
				      color, npages, m, m->vm_page_q_state);
		} else {
			if (m->vm_page_q_state != VM_PAGE_ON_FREE_LOCAL_Q)
				panic("vm_page_verify_free_list(npages=%u): local page %p - expecting q_state == VM_PAGE_ON_FREE_LOCAL_Q, found %d\n",
				      npages, m, m->vm_page_q_state);
		}
		++npages;
		prev_m = m;
	}
	if (look_for_page != VM_PAGE_NULL) {
		unsigned int other_color;

		if (expect_page && !found_page) {
			printf("vm_page_verify_free_list(color=%u, npages=%u): page %p not found phys=%u\n",
			       color, npages, look_for_page, VM_PAGE_GET_PHYS_PAGE(look_for_page));
			_vm_page_print(look_for_page);
			for (other_color = 0;
			     other_color < vm_colors;
			     other_color++) {
				if (other_color == color)
					continue;
				vm_page_verify_free_list(&vm_page_queue_free[other_color].qhead,
							 other_color, look_for_page, FALSE);
			}
			if (color == (unsigned int) -1) {
				vm_page_verify_free_list(&vm_lopage_queue_free,
							 (unsigned int) -1, look_for_page, FALSE);
			}
			panic("vm_page_verify_free_list(color=%u)\n", color);
		}
		if (!expect_page && found_page) {
			printf("vm_page_verify_free_list(color=%u, npages=%u): page %p found phys=%u\n",
			       color, npages, look_for_page, VM_PAGE_GET_PHYS_PAGE(look_for_page));
		}
	}
	return npages;
}

static boolean_t vm_page_verify_all_free_lists_enabled = FALSE;
static void
vm_page_verify_free_lists( void )
{
	unsigned int	color, npages, nlopages;
	boolean_t	toggle = TRUE;

	if (! vm_page_verify_all_free_lists_enabled)
		return;

	npages = 0;

	lck_mtx_lock(&vm_page_queue_free_lock);
	
	if (vm_page_verify_this_free_list_enabled == TRUE) {
		/*
		 * This variable has been set globally for extra checking of
		 * each free list Q. Since we didn't set it, we don't own it
		 * and we shouldn't toggle it.
		 */
		toggle = FALSE;
	}

	if (toggle == TRUE) {
		vm_page_verify_this_free_list_enabled = TRUE;
	}

	for( color = 0; color < vm_colors; color++ ) {
		npages += vm_page_verify_free_list(&vm_page_queue_free[color].qhead,
						   color, VM_PAGE_NULL, FALSE);
	}
	nlopages = vm_page_verify_free_list(&vm_lopage_queue_free,
					    (unsigned int) -1,
					    VM_PAGE_NULL, FALSE);
	if (npages != vm_page_free_count || nlopages != vm_lopage_free_count)
		panic("vm_page_verify_free_lists:  "
		      "npages %u free_count %d nlopages %u lo_free_count %u",
		      npages, vm_page_free_count, nlopages, vm_lopage_free_count);

	if (toggle == TRUE) {
		vm_page_verify_this_free_list_enabled = FALSE;
	}

	lck_mtx_unlock(&vm_page_queue_free_lock);
}

#endif	/* MACH_ASSERT */





extern boolean_t (* volatile consider_buffer_cache_collect)(int);

/*
 *	CONTIGUOUS PAGE ALLOCATION
 *
 *	Find a region large enough to contain at least n pages
 *	of contiguous physical memory.
 *
 *	This is done by traversing the vm_page_t array in a linear fashion
 *	we assume that the vm_page_t array has the avaiable physical pages in an
 *	ordered, ascending list... this is currently true of all our implementations
 * 	and must remain so... there can be 'holes' in the array...  we also can
 *	no longer tolerate the vm_page_t's in the list being 'freed' and reclaimed
 * 	which use to happen via 'vm_page_convert'... that function was no longer
 * 	being called and was removed...
 *	
 *	The basic flow consists of stabilizing some of the interesting state of 
 *	a vm_page_t behind the vm_page_queue and vm_page_free locks... we start our
 *	sweep at the beginning of the array looking for pages that meet our criterea
 *	for a 'stealable' page... currently we are pretty conservative... if the page
 *	meets this criterea and is physically contiguous to the previous page in the 'run'
 * 	we keep developing it.  If we hit a page that doesn't fit, we reset our state
 *	and start to develop a new run... if at this point we've already considered
 * 	at least MAX_CONSIDERED_BEFORE_YIELD pages, we'll drop the 2 locks we hold,
 *	and mutex_pause (which will yield the processor), to keep the latency low w/r 
 *	to other threads trying to acquire free pages (or move pages from q to q),
 *	and then continue from the spot we left off... we only make 1 pass through the
 *	array.  Once we have a 'run' that is long enough, we'll go into the loop which
 * 	which steals the pages from the queues they're currently on... pages on the free
 *	queue can be stolen directly... pages that are on any of the other queues
 *	must be removed from the object they are tabled on... this requires taking the
 * 	object lock... we do this as a 'try' to prevent deadlocks... if the 'try' fails
 *	or if the state of the page behind the vm_object lock is no longer viable, we'll
 *	dump the pages we've currently stolen back to the free list, and pick up our
 *	scan from the point where we aborted the 'current' run.
 *
 *
 *	Requirements:
 *		- neither vm_page_queue nor vm_free_list lock can be held on entry
 *
 *	Returns a pointer to a list of gobbled/wired pages or VM_PAGE_NULL.
 *
 * Algorithm:
 */

#define	MAX_CONSIDERED_BEFORE_YIELD	1000


#define RESET_STATE_OF_RUN()	\
	MACRO_BEGIN		\
	prevcontaddr = -2;	\
	start_pnum = -1;	\
	free_considered = 0;	\
	substitute_needed = 0;	\
	npages = 0;		\
	MACRO_END			

/*
 * Can we steal in-use (i.e. not free) pages when searching for
 * physically-contiguous pages ?
 */
#define VM_PAGE_FIND_CONTIGUOUS_CAN_STEAL 1

static unsigned int vm_page_find_contiguous_last_idx = 0,  vm_page_lomem_find_contiguous_last_idx = 0;
#if DEBUG
int vm_page_find_contig_debug = 0;
#endif

static vm_page_t
vm_page_find_contiguous(
	unsigned int	contig_pages,
	ppnum_t		max_pnum,
	ppnum_t     pnum_mask,
	boolean_t	wire,
	int		flags)
{
	vm_page_t	m = NULL;
	ppnum_t		prevcontaddr;
	ppnum_t		start_pnum;
	unsigned int	npages, considered, scanned;
	unsigned int	page_idx, start_idx, last_idx, orig_last_idx;
	unsigned int	idx_last_contig_page_found = 0;
	int		free_considered, free_available;
	int		substitute_needed;
	boolean_t	wrapped, zone_gc_called = FALSE;
#if DEBUG
	clock_sec_t	tv_start_sec, tv_end_sec;
	clock_usec_t	tv_start_usec, tv_end_usec;
#endif

	int		yielded = 0;
	int		dumped_run = 0;
	int		stolen_pages = 0;
	int		compressed_pages = 0;


	if (contig_pages == 0)
		return VM_PAGE_NULL;

full_scan_again:

#if MACH_ASSERT
	vm_page_verify_free_lists();
#endif
#if DEBUG
	clock_get_system_microtime(&tv_start_sec, &tv_start_usec);
#endif
	PAGE_REPLACEMENT_ALLOWED(TRUE);

	vm_page_lock_queues();


	lck_mtx_lock(&vm_page_queue_free_lock);

	RESET_STATE_OF_RUN();

	scanned = 0;
	considered = 0;
	free_available = vm_page_free_count - vm_page_free_reserved;

	wrapped = FALSE;
	
	if(flags & KMA_LOMEM) 
		idx_last_contig_page_found = vm_page_lomem_find_contiguous_last_idx;
	else
		idx_last_contig_page_found =  vm_page_find_contiguous_last_idx;

	orig_last_idx = idx_last_contig_page_found;
	last_idx = orig_last_idx;

	for (page_idx = last_idx, start_idx = last_idx;
	     npages < contig_pages && page_idx < vm_pages_count;
	     page_idx++) {
retry:
		if (wrapped &&
		    npages == 0 &&
		    page_idx >= orig_last_idx) {
			/*
			 * We're back where we started and we haven't
			 * found any suitable contiguous range.  Let's
			 * give up.
			 */
			break;
		}
		scanned++;
		m = &vm_pages[page_idx];

		assert(!m->fictitious);
		assert(!m->private);

		if (max_pnum && VM_PAGE_GET_PHYS_PAGE(m) > max_pnum) {
			/* no more low pages... */
			break;
		}
		if (!npages & ((VM_PAGE_GET_PHYS_PAGE(m) & pnum_mask) != 0)) {
			/*
			 * not aligned
			 */
			RESET_STATE_OF_RUN();

		} else if (VM_PAGE_WIRED(m) || m->gobbled ||
			   m->encrypted_cleaning || m->laundry || m->wanted ||
			   m->cleaning || m->overwriting || m->free_when_done) {
			/*
			 * page is in a transient state
			 * or a state we don't want to deal
			 * with, so don't consider it which
			 * means starting a new run
			 */
			RESET_STATE_OF_RUN();

		} else if ((m->vm_page_q_state == VM_PAGE_NOT_ON_Q) ||
			   (m->vm_page_q_state == VM_PAGE_ON_FREE_LOCAL_Q) ||
			   (m->vm_page_q_state == VM_PAGE_ON_FREE_LOPAGE_Q) ||
			   (m->vm_page_q_state == VM_PAGE_ON_PAGEOUT_Q)) {
			/*
			 * page needs to be on one of our queues (other then the pageout or special free queues)
			 * or it needs to belong to the compressor pool (which is now indicated
			 * by vm_page_q_state == VM_PAGE_USED_BY_COMPRESSOR and falls out
			 * from the check for VM_PAGE_NOT_ON_Q)
			 * in order for it to be stable behind the
			 * locks we hold at this point...
			 * if not, don't consider it which
			 * means starting a new run
			 */
			RESET_STATE_OF_RUN();

		} else if ((m->vm_page_q_state != VM_PAGE_ON_FREE_Q) && (!m->tabled || m->busy)) {
			/*
			 * pages on the free list are always 'busy'
			 * so we couldn't test for 'busy' in the check
			 * for the transient states... pages that are
			 * 'free' are never 'tabled', so we also couldn't
			 * test for 'tabled'.  So we check here to make
			 * sure that a non-free page is not busy and is
			 * tabled on an object... 
			 * if not, don't consider it which
			 * means starting a new run
			 */
			RESET_STATE_OF_RUN();

		} else {
			if (VM_PAGE_GET_PHYS_PAGE(m) != prevcontaddr + 1) {
				if ((VM_PAGE_GET_PHYS_PAGE(m) & pnum_mask) != 0) {
					RESET_STATE_OF_RUN();
					goto did_consider;
				} else {
					npages = 1;
					start_idx = page_idx;
					start_pnum = VM_PAGE_GET_PHYS_PAGE(m);
				}
			} else {
				npages++;
			}
			prevcontaddr = VM_PAGE_GET_PHYS_PAGE(m);
			
			VM_PAGE_CHECK(m);
			if (m->vm_page_q_state == VM_PAGE_ON_FREE_Q) {
				free_considered++;
			} else {
				/*
				 * This page is not free.
				 * If we can't steal used pages,
				 * we have to give up this run
				 * and keep looking.
				 * Otherwise, we might need to
				 * move the contents of this page
				 * into a substitute page.
				 */
#if VM_PAGE_FIND_CONTIGUOUS_CAN_STEAL
				if (m->pmapped || m->dirty || m->precious) {
					substitute_needed++;
				}
#else
				RESET_STATE_OF_RUN();
#endif
			}

			if ((free_considered + substitute_needed) > free_available) {	
				/*
				 * if we let this run continue
				 * we will end up dropping the vm_page_free_count
				 * below the reserve limit... we need to abort
				 * this run, but we can at least re-consider this
				 * page... thus the jump back to 'retry'
				 */
				RESET_STATE_OF_RUN();

				if (free_available && considered <= MAX_CONSIDERED_BEFORE_YIELD) {
					considered++;
					goto retry;
				}
				/*
				 * free_available == 0
				 * so can't consider any free pages... if
				 * we went to retry in this case, we'd
				 * get stuck looking at the same page
				 * w/o making any forward progress
				 * we also want to take this path if we've already
				 * reached our limit that controls the lock latency
				 */
			}
		}
did_consider:
		if (considered > MAX_CONSIDERED_BEFORE_YIELD && npages <= 1) {

			PAGE_REPLACEMENT_ALLOWED(FALSE);

			lck_mtx_unlock(&vm_page_queue_free_lock);
			vm_page_unlock_queues();

			mutex_pause(0);

			PAGE_REPLACEMENT_ALLOWED(TRUE);

			vm_page_lock_queues();
			lck_mtx_lock(&vm_page_queue_free_lock);

			RESET_STATE_OF_RUN();
			/*
			 * reset our free page limit since we
			 * dropped the lock protecting the vm_page_free_queue
			 */
			free_available = vm_page_free_count - vm_page_free_reserved;
			considered = 0;

			yielded++;

			goto retry;
		}
		considered++;
	}
	m = VM_PAGE_NULL;

	if (npages != contig_pages) {
		if (!wrapped) {
			/*
			 * We didn't find a contiguous range but we didn't
			 * start from the very first page.
			 * Start again from the very first page.
			 */
			RESET_STATE_OF_RUN();
			if( flags & KMA_LOMEM)
				idx_last_contig_page_found  = vm_page_lomem_find_contiguous_last_idx = 0;
			else
				idx_last_contig_page_found = vm_page_find_contiguous_last_idx = 0;
			last_idx = 0;
			page_idx = last_idx;
			wrapped = TRUE;
			goto retry;
		}
		lck_mtx_unlock(&vm_page_queue_free_lock);
	} else {
		vm_page_t	m1;
		vm_page_t	m2;
		unsigned int	cur_idx;
		unsigned int	tmp_start_idx;
		vm_object_t	locked_object = VM_OBJECT_NULL;
		boolean_t	abort_run = FALSE;
		
		assert(page_idx - start_idx == contig_pages);

		tmp_start_idx = start_idx;

		/*
		 * first pass through to pull the free pages
		 * off of the free queue so that in case we
		 * need substitute pages, we won't grab any 
		 * of the free pages in the run... we'll clear
		 * the 'free' bit in the 2nd pass, and even in
		 * an abort_run case, we'll collect all of the
		 * free pages in this run and return them to the free list
		 */
		while (start_idx < page_idx) {

			m1 = &vm_pages[start_idx++];

#if !VM_PAGE_FIND_CONTIGUOUS_CAN_STEAL
			assert(m1->vm_page_q_state == VM_PAGE_ON_FREE_Q);
#endif

			if (m1->vm_page_q_state == VM_PAGE_ON_FREE_Q) {
				unsigned int color;

				color = VM_PAGE_GET_PHYS_PAGE(m1) & vm_color_mask;
#if MACH_ASSERT
				vm_page_verify_free_list(&vm_page_queue_free[color].qhead, color, m1, TRUE);
#endif
				vm_page_queue_remove(&vm_page_queue_free[color].qhead,
						     m1,
						     vm_page_t,
						     pageq);

				VM_PAGE_ZERO_PAGEQ_ENTRY(m1);
#if MACH_ASSERT
				vm_page_verify_free_list(&vm_page_queue_free[color].qhead, color, VM_PAGE_NULL, FALSE);
#endif
				/*
				 * Clear the "free" bit so that this page
				 * does not get considered for another
				 * concurrent physically-contiguous allocation.
				 */
				m1->vm_page_q_state = VM_PAGE_NOT_ON_Q;
				assert(m1->busy);

				vm_page_free_count--;
			}
		}
		if( flags & KMA_LOMEM)
			vm_page_lomem_find_contiguous_last_idx = page_idx;
		else 
			vm_page_find_contiguous_last_idx = page_idx;
		
		/*
		 * we can drop the free queue lock at this point since
		 * we've pulled any 'free' candidates off of the list
		 * we need it dropped so that we can do a vm_page_grab
		 * when substituing for pmapped/dirty pages
		 */
		lck_mtx_unlock(&vm_page_queue_free_lock);

		start_idx = tmp_start_idx;
		cur_idx = page_idx - 1;

		while (start_idx++ < page_idx) {
			/*
			 * must go through the list from back to front
			 * so that the page list is created in the
			 * correct order - low -> high phys addresses
			 */
			m1 = &vm_pages[cur_idx--];

			if (m1->vm_page_object == 0) {
				/*
				 * page has already been removed from
				 * the free list in the 1st pass
				 */
				assert(m1->vm_page_q_state == VM_PAGE_NOT_ON_Q);
				assert(m1->offset == (vm_object_offset_t) -1);
				assert(m1->busy);
				assert(!m1->wanted);
				assert(!m1->laundry);
			} else {
				vm_object_t object;
				int refmod;
				boolean_t disconnected, reusable;

				if (abort_run == TRUE)
					continue;

				assert(m1->vm_page_q_state != VM_PAGE_NOT_ON_Q);

				object = VM_PAGE_OBJECT(m1);

				if (object != locked_object) {
					if (locked_object) {
						vm_object_unlock(locked_object);
						locked_object = VM_OBJECT_NULL;
					}
					if (vm_object_lock_try(object))
						locked_object = object;
				}
				if (locked_object == VM_OBJECT_NULL || 
				    (VM_PAGE_WIRED(m1) || m1->gobbled ||
				     m1->encrypted_cleaning || m1->laundry || m1->wanted ||
				     m1->cleaning || m1->overwriting || m1->free_when_done || m1->busy) ||
				    (m1->vm_page_q_state == VM_PAGE_ON_PAGEOUT_Q)) {

					if (locked_object) {
						vm_object_unlock(locked_object);
						locked_object = VM_OBJECT_NULL;
					}
					tmp_start_idx = cur_idx;
					abort_run = TRUE;
					continue;
				}

				disconnected = FALSE;
				reusable = FALSE;

				if ((m1->reusable ||
				     object->all_reusable) &&
				    (m1->vm_page_q_state == VM_PAGE_ON_INACTIVE_INTERNAL_Q) &&
				    !m1->dirty &&
				    !m1->reference) {
					/* reusable page... */
					refmod = pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(m1));
					disconnected = TRUE;
					if (refmod == 0) {
						/*
						 * ... not reused: can steal
						 * without relocating contents.
						 */
						reusable = TRUE;
					}
				}

				if ((m1->pmapped &&
				     ! reusable) ||
				    m1->dirty ||
				    m1->precious) {
					vm_object_offset_t offset;

					m2 = vm_page_grab();

					if (m2 == VM_PAGE_NULL) {
						if (locked_object) {
							vm_object_unlock(locked_object);
							locked_object = VM_OBJECT_NULL;
						}
						tmp_start_idx = cur_idx;
						abort_run = TRUE;
						continue;
					}
					if (! disconnected) {
						if (m1->pmapped)
							refmod = pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(m1));
						else
							refmod = 0;
					}

					/* copy the page's contents */
					pmap_copy_page(VM_PAGE_GET_PHYS_PAGE(m1), VM_PAGE_GET_PHYS_PAGE(m2));
					/* copy the page's state */
					assert(!VM_PAGE_WIRED(m1));
					assert(m1->vm_page_q_state != VM_PAGE_ON_FREE_Q);
					assert(m1->vm_page_q_state != VM_PAGE_ON_PAGEOUT_Q);
					assert(!m1->laundry);
					m2->reference	= m1->reference;
					assert(!m1->gobbled);
					assert(!m1->private);
					m2->no_cache	= m1->no_cache;
					m2->xpmapped	= 0;
					assert(!m1->busy);
					assert(!m1->wanted);
					assert(!m1->fictitious);
					m2->pmapped	= m1->pmapped; /* should flush cache ? */
					m2->wpmapped	= m1->wpmapped;
					assert(!m1->free_when_done);
					m2->absent	= m1->absent;
					m2->error	= m1->error;
					m2->dirty	= m1->dirty;
					assert(!m1->cleaning);
					m2->precious	= m1->precious;
					m2->clustered	= m1->clustered;
					assert(!m1->overwriting);
					m2->restart	= m1->restart;
					m2->unusual	= m1->unusual;
					m2->encrypted	= m1->encrypted;
					assert(!m1->encrypted_cleaning);
					m2->cs_validated = m1->cs_validated;
					m2->cs_tainted	= m1->cs_tainted;
					m2->cs_nx	= m1->cs_nx;

					/*
					 * If m1 had really been reusable,
					 * we would have just stolen it, so
					 * let's not propagate it's "reusable"
					 * bit and assert that m2 is not
					 * marked as "reusable".
					 */
					// m2->reusable	= m1->reusable;
					assert(!m2->reusable);

					// assert(!m1->lopage);
					m2->slid	= m1->slid;

					if (m1->vm_page_q_state == VM_PAGE_USED_BY_COMPRESSOR)
						m2->vm_page_q_state = VM_PAGE_USED_BY_COMPRESSOR;

					/*
					 * page may need to be flushed if
					 * it is marshalled into a UPL
					 * that is going to be used by a device
					 * that doesn't support coherency
					 */
					m2->written_by_kernel = TRUE;

					/*
					 * make sure we clear the ref/mod state
					 * from the pmap layer... else we risk
					 * inheriting state from the last time
					 * this page was used...
					 */
					pmap_clear_refmod(VM_PAGE_GET_PHYS_PAGE(m2), VM_MEM_MODIFIED | VM_MEM_REFERENCED);

					if (refmod & VM_MEM_REFERENCED)
						m2->reference = TRUE;
					if (refmod & VM_MEM_MODIFIED) {
						SET_PAGE_DIRTY(m2, TRUE);
					}
					offset = m1->offset;

					/*
					 * completely cleans up the state
					 * of the page so that it is ready
					 * to be put onto the free list, or
					 * for this purpose it looks like it
					 * just came off of the free list
					 */
					vm_page_free_prepare(m1);

					/*
					 * now put the substitute page
					 * on the object
					 */
					vm_page_insert_internal(m2, locked_object, offset, VM_KERN_MEMORY_NONE, TRUE, TRUE, FALSE, FALSE, NULL);

					if (m2->vm_page_q_state == VM_PAGE_USED_BY_COMPRESSOR) {
						m2->pmapped = TRUE;
						m2->wpmapped = TRUE;

						PMAP_ENTER(kernel_pmap, m2->offset, m2,
							   VM_PROT_READ | VM_PROT_WRITE, VM_PROT_NONE, 0, TRUE);

						compressed_pages++;

					} else {
						if (m2->reference)
							vm_page_activate(m2);
						else
							vm_page_deactivate(m2);
					}
					PAGE_WAKEUP_DONE(m2);

				} else {
					assert(m1->vm_page_q_state != VM_PAGE_USED_BY_COMPRESSOR);

					/*
					 * completely cleans up the state
					 * of the page so that it is ready
					 * to be put onto the free list, or
					 * for this purpose it looks like it
					 * just came off of the free list
					 */
					vm_page_free_prepare(m1);
				}

				stolen_pages++;

			}
#if CONFIG_BACKGROUND_QUEUE
			vm_page_assign_background_state(m1);
#endif
			VM_PAGE_ZERO_PAGEQ_ENTRY(m1);
			m1->snext = m;
			m = m1;
		}
		if (locked_object) {
			vm_object_unlock(locked_object);
			locked_object = VM_OBJECT_NULL;
		}

		if (abort_run == TRUE) {
			/*
			 * want the index of the last
			 * page in this run that was
			 * successfully 'stolen', so back
			 * it up 1 for the auto-decrement on use
			 * and 1 more to bump back over this page
			 */
			page_idx = tmp_start_idx + 2;
			if (page_idx >= vm_pages_count) {
				if (wrapped) {
					if (m != VM_PAGE_NULL) {
						vm_page_unlock_queues();
						vm_page_free_list(m, FALSE);
						vm_page_lock_queues();
						m = VM_PAGE_NULL;
					}
					dumped_run++;
					goto done_scanning;
				}
				page_idx = last_idx = 0;
				wrapped = TRUE;
			}
			abort_run = FALSE;
		
			/*
			 * We didn't find a contiguous range but we didn't
			 * start from the very first page.
			 * Start again from the very first page.
			 */
			RESET_STATE_OF_RUN();
			
			if( flags & KMA_LOMEM)
				idx_last_contig_page_found  = vm_page_lomem_find_contiguous_last_idx = page_idx;
			else
				idx_last_contig_page_found = vm_page_find_contiguous_last_idx = page_idx;
			
			last_idx = page_idx;
			
			if (m != VM_PAGE_NULL) {
				vm_page_unlock_queues();
				vm_page_free_list(m, FALSE);
				vm_page_lock_queues();
				m = VM_PAGE_NULL;
			}
			dumped_run++;

			lck_mtx_lock(&vm_page_queue_free_lock);
			/*
			* reset our free page limit since we
			* dropped the lock protecting the vm_page_free_queue
			*/
			free_available = vm_page_free_count - vm_page_free_reserved;
			goto retry;
		}

		for (m1 = m; m1 != VM_PAGE_NULL; m1 = NEXT_PAGE(m1)) {

			assert(m1->vm_page_q_state == VM_PAGE_NOT_ON_Q);
			assert(m1->wire_count == 0);

			if (wire == TRUE) {
				m1->wire_count++;
				m1->vm_page_q_state = VM_PAGE_IS_WIRED;
			} else
				m1->gobbled = TRUE;
		}
		if (wire == FALSE)
			vm_page_gobble_count += npages;

		/*
		 * gobbled pages are also counted as wired pages
		 */
		vm_page_wire_count += npages;

 		assert(vm_page_verify_contiguous(m, npages));
	}
done_scanning:
	PAGE_REPLACEMENT_ALLOWED(FALSE);

	vm_page_unlock_queues();

#if DEBUG
	clock_get_system_microtime(&tv_end_sec, &tv_end_usec);

	tv_end_sec -= tv_start_sec;
	if (tv_end_usec < tv_start_usec) {
		tv_end_sec--;
		tv_end_usec += 1000000;
	}
	tv_end_usec -= tv_start_usec;
	if (tv_end_usec >= 1000000) {
		tv_end_sec++;
		tv_end_sec -= 1000000;
	}
	if (vm_page_find_contig_debug) {
		printf("%s(num=%d,low=%d): found %d pages at 0x%llx in %ld.%06ds...  started at %d...  scanned %d pages...  yielded %d times...  dumped run %d times... stole %d pages... stole %d compressed pages\n",
		       __func__, contig_pages, max_pnum, npages, (vm_object_offset_t)start_pnum << PAGE_SHIFT,
		       (long)tv_end_sec, tv_end_usec, orig_last_idx,
		       scanned, yielded, dumped_run, stolen_pages, compressed_pages);
	}

#endif
#if MACH_ASSERT
	vm_page_verify_free_lists();
#endif
	if (m == NULL && zone_gc_called == FALSE) {
		printf("%s(num=%d,low=%d): found %d pages at 0x%llx...scanned %d pages...  yielded %d times...  dumped run %d times... stole %d pages... stole %d compressed pages... wired count is %d\n",
		       __func__, contig_pages, max_pnum, npages, (vm_object_offset_t)start_pnum << PAGE_SHIFT,
		       scanned, yielded, dumped_run, stolen_pages, compressed_pages, vm_page_wire_count);

		if (consider_buffer_cache_collect != NULL) {
			(void)(*consider_buffer_cache_collect)(1);
		}

		consider_zone_gc();

		zone_gc_called = TRUE;

		printf("vm_page_find_contiguous: zone_gc called... wired count is %d\n", vm_page_wire_count);
		goto full_scan_again;
	}

	return m;
}

/*
 *	Allocate a list of contiguous, wired pages.
 */
kern_return_t
cpm_allocate(
	vm_size_t	size,
	vm_page_t	*list,
	ppnum_t		max_pnum,
	ppnum_t		pnum_mask,
	boolean_t	wire,
	int		flags)
{
	vm_page_t		pages;
	unsigned int		npages;

	if (size % PAGE_SIZE != 0)
		return KERN_INVALID_ARGUMENT;

	npages = (unsigned int) (size / PAGE_SIZE);
	if (npages != size / PAGE_SIZE) {
		/* 32-bit overflow */
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 *	Obtain a pointer to a subset of the free
	 *	list large enough to satisfy the request;
	 *	the region will be physically contiguous.
	 */
	pages = vm_page_find_contiguous(npages, max_pnum, pnum_mask, wire, flags);

	if (pages == VM_PAGE_NULL)
		return KERN_NO_SPACE;
	/*
	 * determine need for wakeups
	 */
	if ((vm_page_free_count < vm_page_free_min) ||
	     ((vm_page_free_count < vm_page_free_target) &&
	      ((vm_page_inactive_count + vm_page_speculative_count) < vm_page_inactive_min)))
	         thread_wakeup((event_t) &vm_page_free_wanted);
		
	VM_CHECK_MEMORYSTATUS;
	
	/*
	 *	The CPM pages should now be available and
	 *	ordered by ascending physical address.
	 */
	assert(vm_page_verify_contiguous(pages, npages));

	*list = pages;
	return KERN_SUCCESS;
}


unsigned int vm_max_delayed_work_limit = DEFAULT_DELAYED_WORK_LIMIT;

/*
 * when working on a 'run' of pages, it is necessary to hold 
 * the vm_page_queue_lock (a hot global lock) for certain operations
 * on the page... however, the majority of the work can be done
 * while merely holding the object lock... in fact there are certain
 * collections of pages that don't require any work brokered by the
 * vm_page_queue_lock... to mitigate the time spent behind the global
 * lock, go to a 2 pass algorithm... collect pages up to DELAYED_WORK_LIMIT
 * while doing all of the work that doesn't require the vm_page_queue_lock...
 * then call vm_page_do_delayed_work to acquire the vm_page_queue_lock and do the
 * necessary work for each page... we will grab the busy bit on the page
 * if it's not already held so that vm_page_do_delayed_work can drop the object lock
 * if it can't immediately take the vm_page_queue_lock in order to compete
 * for the locks in the same order that vm_pageout_scan takes them.
 * the operation names are modeled after the names of the routines that
 * need to be called in order to make the changes very obvious in the
 * original loop
 */

void
vm_page_do_delayed_work(
	vm_object_t 	object,
	vm_tag_t        tag,
	struct vm_page_delayed_work *dwp,
	int		dw_count)
{
	int		j;
	vm_page_t	m;
        vm_page_t       local_free_q = VM_PAGE_NULL;

	/*
	 * pageout_scan takes the vm_page_lock_queues first
	 * then tries for the object lock... to avoid what
	 * is effectively a lock inversion, we'll go to the
	 * trouble of taking them in that same order... otherwise
	 * if this object contains the majority of the pages resident
	 * in the UBC (or a small set of large objects actively being
	 * worked on contain the majority of the pages), we could
	 * cause the pageout_scan thread to 'starve' in its attempt
	 * to find pages to move to the free queue, since it has to
	 * successfully acquire the object lock of any candidate page
	 * before it can steal/clean it.
	 */
	if (!vm_page_trylockspin_queues()) {
		vm_object_unlock(object);

		vm_page_lockspin_queues();

		for (j = 0; ; j++) {
			if (!vm_object_lock_avoid(object) &&
			    _vm_object_lock_try(object))
				break;
			vm_page_unlock_queues();
			mutex_pause(j);
			vm_page_lockspin_queues();
		}
	}
	for (j = 0; j < dw_count; j++, dwp++) {

		m = dwp->dw_m;

		if (dwp->dw_mask & DW_vm_pageout_throttle_up)
			vm_pageout_throttle_up(m);
#if CONFIG_PHANTOM_CACHE
		if (dwp->dw_mask & DW_vm_phantom_cache_update)
			vm_phantom_cache_update(m);
#endif
		if (dwp->dw_mask & DW_vm_page_wire)
			vm_page_wire(m, tag, FALSE);
		else if (dwp->dw_mask & DW_vm_page_unwire) {
			boolean_t	queueit;

			queueit = (dwp->dw_mask & (DW_vm_page_free | DW_vm_page_deactivate_internal)) ? FALSE : TRUE;

			vm_page_unwire(m, queueit);
		}
		if (dwp->dw_mask & DW_vm_page_free) {
			vm_page_free_prepare_queues(m);

			assert(m->pageq.next == 0 && m->pageq.prev == 0);
			/*
			 * Add this page to our list of reclaimed pages,
			 * to be freed later.
			 */
			m->snext = local_free_q;
			local_free_q = m;
		} else {
			if (dwp->dw_mask & DW_vm_page_deactivate_internal)
				vm_page_deactivate_internal(m, FALSE);
			else if (dwp->dw_mask & DW_vm_page_activate) {
				if (m->vm_page_q_state != VM_PAGE_ON_ACTIVE_Q) {
					vm_page_activate(m);
				}
			}
			else if (dwp->dw_mask & DW_vm_page_speculate)
				vm_page_speculate(m, TRUE);
			else if (dwp->dw_mask & DW_enqueue_cleaned) {
				/*
				 * if we didn't hold the object lock and did this,
				 * we might disconnect the page, then someone might
				 * soft fault it back in, then we would put it on the
				 * cleaned queue, and so we would have a referenced (maybe even dirty)
				 * page on that queue, which we don't want
				 */
				int refmod_state = pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(m));

				if ((refmod_state & VM_MEM_REFERENCED)) {
					/*
					 * this page has been touched since it got cleaned; let's activate it
					 * if it hasn't already been
					 */
					vm_pageout_enqueued_cleaned++;
					vm_pageout_cleaned_reactivated++;
					vm_pageout_cleaned_commit_reactivated++;

					if (m->vm_page_q_state != VM_PAGE_ON_ACTIVE_Q)
						vm_page_activate(m);
				} else {
					m->reference = FALSE;
					vm_page_enqueue_cleaned(m);
				}
			}
			else if (dwp->dw_mask & DW_vm_page_lru)
				vm_page_lru(m);
			else if (dwp->dw_mask & DW_VM_PAGE_QUEUES_REMOVE) {
				if (m->vm_page_q_state != VM_PAGE_ON_PAGEOUT_Q)
					vm_page_queues_remove(m, TRUE);
			}
			if (dwp->dw_mask & DW_set_reference)
				m->reference = TRUE;
			else if (dwp->dw_mask & DW_clear_reference)
				m->reference = FALSE;

			if (dwp->dw_mask & DW_move_page) {
				if (m->vm_page_q_state != VM_PAGE_ON_PAGEOUT_Q) {
					vm_page_queues_remove(m, FALSE);

					assert(VM_PAGE_OBJECT(m) != kernel_object);

					vm_page_enqueue_inactive(m, FALSE);
				}
			}
			if (dwp->dw_mask & DW_clear_busy)
				m->busy = FALSE;

			if (dwp->dw_mask & DW_PAGE_WAKEUP)
				PAGE_WAKEUP(m);
		}
	}
	vm_page_unlock_queues();

	if (local_free_q)
		vm_page_free_list(local_free_q, TRUE);
	
	VM_CHECK_MEMORYSTATUS;

}

kern_return_t
vm_page_alloc_list(
	int	page_count,
	int	flags,
	vm_page_t *list)
{
	vm_page_t	lo_page_list = VM_PAGE_NULL;
	vm_page_t	mem;
	int		i;

	if ( !(flags & KMA_LOMEM))
		panic("vm_page_alloc_list: called w/o KMA_LOMEM");

	for (i = 0; i < page_count; i++) {

		mem = vm_page_grablo();

		if (mem == VM_PAGE_NULL) {
			if (lo_page_list)
				vm_page_free_list(lo_page_list, FALSE);

			*list = VM_PAGE_NULL;

			return (KERN_RESOURCE_SHORTAGE);
		}
		mem->snext = lo_page_list;
		lo_page_list = mem;
	}
	*list = lo_page_list;

	return (KERN_SUCCESS);
}

void
vm_page_set_offset(vm_page_t page, vm_object_offset_t offset)
{
	page->offset = offset;
}

vm_page_t
vm_page_get_next(vm_page_t page)
{
	return (page->snext);
}

vm_object_offset_t
vm_page_get_offset(vm_page_t page)
{
	return (page->offset);
}

ppnum_t
vm_page_get_phys_page(vm_page_t page)
{
	return (VM_PAGE_GET_PHYS_PAGE(page));
}
	
	
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if HIBERNATION

static vm_page_t hibernate_gobble_queue;

static int  hibernate_drain_pageout_queue(struct vm_pageout_queue *);
static int  hibernate_flush_dirty_pages(int);
static int  hibernate_flush_queue(vm_page_queue_head_t *, int);

void hibernate_flush_wait(void);
void hibernate_mark_in_progress(void);
void hibernate_clear_in_progress(void);

void		hibernate_free_range(int, int);
void		hibernate_hash_insert_page(vm_page_t);
uint32_t	hibernate_mark_as_unneeded(addr64_t, addr64_t, hibernate_page_list_t *, hibernate_page_list_t *);
void		hibernate_rebuild_vm_structs(void);
uint32_t	hibernate_teardown_vm_structs(hibernate_page_list_t *, hibernate_page_list_t *);
ppnum_t		hibernate_lookup_paddr(unsigned int);

struct hibernate_statistics {
	int hibernate_considered;
	int hibernate_reentered_on_q;
	int hibernate_found_dirty;
	int hibernate_skipped_cleaning;
	int hibernate_skipped_transient;
	int hibernate_skipped_precious;
	int hibernate_skipped_external;
	int hibernate_queue_nolock;
	int hibernate_queue_paused;
	int hibernate_throttled;
	int hibernate_throttle_timeout;
	int hibernate_drained;
	int hibernate_drain_timeout;
	int cd_lock_failed;
	int cd_found_precious;
	int cd_found_wired;
	int cd_found_busy;
	int cd_found_unusual;
	int cd_found_cleaning;
	int cd_found_laundry;
	int cd_found_dirty;
	int cd_found_xpmapped;
	int cd_skipped_xpmapped;
	int cd_local_free;
	int cd_total_free;
	int cd_vm_page_wire_count;
	int cd_vm_struct_pages_unneeded;
	int cd_pages;
	int cd_discarded;
	int cd_count_wire;
} hibernate_stats;


/*
 * clamp the number of 'xpmapped' pages we'll sweep into the hibernation image
 * so that we don't overrun the estimated image size, which would
 * result in a hibernation failure.
 */
#define	HIBERNATE_XPMAPPED_LIMIT	40000


static int
hibernate_drain_pageout_queue(struct vm_pageout_queue *q)
{
	wait_result_t	wait_result;

	vm_page_lock_queues();

	while ( !vm_page_queue_empty(&q->pgo_pending) ) {

		q->pgo_draining = TRUE;

		assert_wait_timeout((event_t) (&q->pgo_laundry+1), THREAD_INTERRUPTIBLE, 5000, 1000*NSEC_PER_USEC);

		vm_page_unlock_queues();

		wait_result = thread_block(THREAD_CONTINUE_NULL);

		if (wait_result == THREAD_TIMED_OUT && !vm_page_queue_empty(&q->pgo_pending)) {
			hibernate_stats.hibernate_drain_timeout++;
			
			if (q == &vm_pageout_queue_external)
				return (0);
			
			return (1);
		}
		vm_page_lock_queues();

		hibernate_stats.hibernate_drained++;
	}
	vm_page_unlock_queues();

	return (0);
}


boolean_t hibernate_skip_external = FALSE;

static int
hibernate_flush_queue(vm_page_queue_head_t *q, int qcount)
{
	vm_page_t	m;
	vm_object_t	l_object = NULL;
	vm_object_t	m_object = NULL;
	int		refmod_state = 0;
	int		try_failed_count = 0;
	int		retval = 0;
	int		current_run = 0;
	struct	vm_pageout_queue *iq;
	struct	vm_pageout_queue *eq;
	struct	vm_pageout_queue *tq;


	KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 4) | DBG_FUNC_START, q, qcount, 0, 0, 0);
	
	iq = &vm_pageout_queue_internal;
	eq = &vm_pageout_queue_external;

	vm_page_lock_queues();

	while (qcount && !vm_page_queue_empty(q)) {

		if (current_run++ == 1000) {
			if (hibernate_should_abort()) {
				retval = 1;
				break;
			}
			current_run = 0;
		}

		m = (vm_page_t) vm_page_queue_first(q);
		m_object = VM_PAGE_OBJECT(m);

		/*
		 * check to see if we currently are working
		 * with the same object... if so, we've
		 * already got the lock
		 */
		if (m_object != l_object) {
		        /*
			 * the object associated with candidate page is 
			 * different from the one we were just working
			 * with... dump the lock if we still own it
			 */
		        if (l_object != NULL) {
			        vm_object_unlock(l_object);
				l_object = NULL;
			}
			/*
			 * Try to lock object; since we've alread got the
			 * page queues lock, we can only 'try' for this one.
			 * if the 'try' fails, we need to do a mutex_pause
			 * to allow the owner of the object lock a chance to
			 * run... 
			 */
			if ( !vm_object_lock_try_scan(m_object)) {

				if (try_failed_count > 20) {
					hibernate_stats.hibernate_queue_nolock++;

					goto reenter_pg_on_q;
				}

				vm_page_unlock_queues();
				mutex_pause(try_failed_count++);
				vm_page_lock_queues();

				hibernate_stats.hibernate_queue_paused++;
				continue;
			} else {
				l_object = m_object;
			}
		}
		if ( !m_object->alive || m->encrypted_cleaning || m->cleaning || m->laundry || m->busy || m->absent || m->error) {
			/*
			 * page is not to be cleaned
			 * put it back on the head of its queue
			 */
			if (m->cleaning)
				hibernate_stats.hibernate_skipped_cleaning++;
			else
				hibernate_stats.hibernate_skipped_transient++;

			goto reenter_pg_on_q;
		}
		if (m_object->copy == VM_OBJECT_NULL) {
			if (m_object->purgable == VM_PURGABLE_VOLATILE || m_object->purgable == VM_PURGABLE_EMPTY) {
				/*
				 * let the normal hibernate image path
				 * deal with these
				 */
				goto reenter_pg_on_q;
			}
		}
		if ( !m->dirty && m->pmapped) {
		        refmod_state = pmap_get_refmod(VM_PAGE_GET_PHYS_PAGE(m));

			if ((refmod_state & VM_MEM_MODIFIED)) {
				SET_PAGE_DIRTY(m, FALSE);
			}
		} else
			refmod_state = 0;

		if ( !m->dirty) {
			/*
			 * page is not to be cleaned
			 * put it back on the head of its queue
			 */
			if (m->precious)
				hibernate_stats.hibernate_skipped_precious++;

			goto reenter_pg_on_q;
		}

		if (hibernate_skip_external == TRUE && !m_object->internal) {

			hibernate_stats.hibernate_skipped_external++;
			
			goto reenter_pg_on_q;
		}
		tq = NULL;

		if (m_object->internal) {
			if (VM_PAGE_Q_THROTTLED(iq))
				tq = iq;
		} else if (VM_PAGE_Q_THROTTLED(eq))
			tq = eq;

		if (tq != NULL) {
			wait_result_t	wait_result;
			int		wait_count = 5;

		        if (l_object != NULL) {
			        vm_object_unlock(l_object);
				l_object = NULL;
			}

			while (retval == 0) {

				tq->pgo_throttled = TRUE;

				assert_wait_timeout((event_t) &tq->pgo_laundry, THREAD_INTERRUPTIBLE, 1000, 1000*NSEC_PER_USEC);

				vm_page_unlock_queues();

				wait_result = thread_block(THREAD_CONTINUE_NULL);

				vm_page_lock_queues();

				if (wait_result != THREAD_TIMED_OUT)
					break;
                                if (!VM_PAGE_Q_THROTTLED(tq))
                                        break;

				if (hibernate_should_abort())
					retval = 1;

				if (--wait_count == 0) {

					hibernate_stats.hibernate_throttle_timeout++;

					if (tq == eq) {
						hibernate_skip_external = TRUE;
						break;
					}
					retval = 1;
				}
			}
			if (retval)
				break;

			hibernate_stats.hibernate_throttled++;

			continue;
		}
		/*
		 * we've already factored out pages in the laundry which
		 * means this page can't be on the pageout queue so it's
		 * safe to do the vm_page_queues_remove
		 */
		vm_page_queues_remove(m, TRUE);

		if (m_object->internal == TRUE)
			pmap_disconnect_options(VM_PAGE_GET_PHYS_PAGE(m), PMAP_OPTIONS_COMPRESSOR, NULL);

		(void)vm_pageout_cluster(m, FALSE, FALSE);

		hibernate_stats.hibernate_found_dirty++;

		goto next_pg;

reenter_pg_on_q:
		vm_page_queue_remove(q, m, vm_page_t, pageq);
		vm_page_queue_enter(q, m, vm_page_t, pageq);

		hibernate_stats.hibernate_reentered_on_q++;
next_pg:
		hibernate_stats.hibernate_considered++;

		qcount--;
		try_failed_count = 0;
	}
	if (l_object != NULL) {
		vm_object_unlock(l_object);
		l_object = NULL;
	}

	vm_page_unlock_queues();

	KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 4) | DBG_FUNC_END, hibernate_stats.hibernate_found_dirty, retval, 0, 0, 0);

	return (retval);
}


static int
hibernate_flush_dirty_pages(int pass)
{
	struct vm_speculative_age_q	*aq;
	uint32_t	i;

	if (vm_page_local_q) {
		for (i = 0; i < vm_page_local_q_count; i++)
			vm_page_reactivate_local(i, TRUE, FALSE);
	}

	for (i = 0; i <= VM_PAGE_MAX_SPECULATIVE_AGE_Q; i++) {
		int		qcount;
		vm_page_t	m;

		aq = &vm_page_queue_speculative[i];

		if (vm_page_queue_empty(&aq->age_q))
			continue;
		qcount = 0;

		vm_page_lockspin_queues();

		vm_page_queue_iterate(&aq->age_q,
			      m,
			      vm_page_t,
			      pageq)
		{
			qcount++;
		}
		vm_page_unlock_queues();

		if (qcount) {
			if (hibernate_flush_queue(&aq->age_q, qcount))
				return (1);
		}
	}
	if (hibernate_flush_queue(&vm_page_queue_inactive, vm_page_inactive_count - vm_page_anonymous_count - vm_page_cleaned_count))
		return (1);
	/* XXX FBDP TODO: flush secluded queue */
	if (hibernate_flush_queue(&vm_page_queue_anonymous, vm_page_anonymous_count))
		return (1);
	if (hibernate_flush_queue(&vm_page_queue_cleaned, vm_page_cleaned_count))
		return (1);
	if (hibernate_drain_pageout_queue(&vm_pageout_queue_internal))
		return (1);

	if (pass == 1)
		vm_compressor_record_warmup_start();

	if (hibernate_flush_queue(&vm_page_queue_active, vm_page_active_count)) {
		if (pass == 1)
			vm_compressor_record_warmup_end();
		return (1);
	}
	if (hibernate_drain_pageout_queue(&vm_pageout_queue_internal)) {
		if (pass == 1)
			vm_compressor_record_warmup_end();
		return (1);
	}
	if (pass == 1)
		vm_compressor_record_warmup_end();

	if (hibernate_skip_external == FALSE && hibernate_drain_pageout_queue(&vm_pageout_queue_external))
		return (1);

	return (0);
}


void
hibernate_reset_stats()
{
	bzero(&hibernate_stats, sizeof(struct hibernate_statistics));
}


int
hibernate_flush_memory()
{
	int	retval;

	assert(VM_CONFIG_COMPRESSOR_IS_PRESENT);

	KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 3) | DBG_FUNC_START, vm_page_free_count, 0, 0, 0, 0);

	hibernate_cleaning_in_progress = TRUE;
	hibernate_skip_external = FALSE;

	if ((retval = hibernate_flush_dirty_pages(1)) == 0) {

		KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 10) | DBG_FUNC_START, VM_PAGE_COMPRESSOR_COUNT, 0, 0, 0, 0);

		vm_compressor_flush();

		KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 10) | DBG_FUNC_END, VM_PAGE_COMPRESSOR_COUNT, 0, 0, 0, 0);

		if (consider_buffer_cache_collect != NULL) {
			unsigned int orig_wire_count;

			KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 7) | DBG_FUNC_START, 0, 0, 0, 0, 0);
			orig_wire_count = vm_page_wire_count;
			
			(void)(*consider_buffer_cache_collect)(1);
			consider_zone_gc();

			HIBLOG("hibernate_flush_memory: buffer_cache_gc freed up %d wired pages\n", orig_wire_count - vm_page_wire_count);

			KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 7) | DBG_FUNC_END, orig_wire_count - vm_page_wire_count, 0, 0, 0, 0);
		}
	}
	hibernate_cleaning_in_progress = FALSE;

	KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 3) | DBG_FUNC_END, vm_page_free_count, hibernate_stats.hibernate_found_dirty, retval, 0, 0);

	if (retval)
		HIBLOG("hibernate_flush_memory() failed to finish - vm_page_compressor_count(%d)\n", VM_PAGE_COMPRESSOR_COUNT);


    HIBPRINT("hibernate_flush_memory() considered(%d) reentered_on_q(%d) found_dirty(%d)\n",
                hibernate_stats.hibernate_considered,
                hibernate_stats.hibernate_reentered_on_q,
                hibernate_stats.hibernate_found_dirty);
    HIBPRINT("   skipped_cleaning(%d) skipped_transient(%d) skipped_precious(%d) skipped_external(%d) queue_nolock(%d)\n",
                hibernate_stats.hibernate_skipped_cleaning,
                hibernate_stats.hibernate_skipped_transient,
                hibernate_stats.hibernate_skipped_precious,
                hibernate_stats.hibernate_skipped_external,
                hibernate_stats.hibernate_queue_nolock);
    HIBPRINT("   queue_paused(%d) throttled(%d) throttle_timeout(%d) drained(%d) drain_timeout(%d)\n",
                hibernate_stats.hibernate_queue_paused,
                hibernate_stats.hibernate_throttled,
                hibernate_stats.hibernate_throttle_timeout,
                hibernate_stats.hibernate_drained,
                hibernate_stats.hibernate_drain_timeout);

	return (retval);
}


static void
hibernate_page_list_zero(hibernate_page_list_t *list)
{
    uint32_t             bank;
    hibernate_bitmap_t * bitmap;

    bitmap = &list->bank_bitmap[0];
    for (bank = 0; bank < list->bank_count; bank++)
    {
        uint32_t last_bit;

	bzero((void *) &bitmap->bitmap[0], bitmap->bitmapwords << 2); 
        // set out-of-bound bits at end of bitmap.
        last_bit = ((bitmap->last_page - bitmap->first_page + 1) & 31);
	if (last_bit)
	    bitmap->bitmap[bitmap->bitmapwords - 1] = (0xFFFFFFFF >> last_bit);

	bitmap = (hibernate_bitmap_t *) &bitmap->bitmap[bitmap->bitmapwords];
    }
}

void
hibernate_free_gobble_pages(void)
{
    vm_page_t m, next;
    uint32_t  count = 0;

    m = (vm_page_t) hibernate_gobble_queue;
    while(m)
    {
        next = m->snext;
        vm_page_free(m);
        count++;
        m = next;
    }
    hibernate_gobble_queue = VM_PAGE_NULL;
    
    if (count)
        HIBLOG("Freed %d pages\n", count);
}

static boolean_t 
hibernate_consider_discard(vm_page_t m, boolean_t preflight)
{
    vm_object_t object = NULL;
    int                  refmod_state;
    boolean_t            discard = FALSE;

    do
    {
        if (m->private)
            panic("hibernate_consider_discard: private");

	object = VM_PAGE_OBJECT(m);

        if (!vm_object_lock_try(object)) {
	    object = NULL;
	    if (!preflight) hibernate_stats.cd_lock_failed++;
            break;
	}
	if (VM_PAGE_WIRED(m)) {
	    if (!preflight) hibernate_stats.cd_found_wired++;
            break;
	}
        if (m->precious) {
	    if (!preflight) hibernate_stats.cd_found_precious++;
            break;
	}
        if (m->busy || !object->alive) {
           /*
            *	Somebody is playing with this page.
            */
	    if (!preflight) hibernate_stats.cd_found_busy++;
            break;
	}
        if (m->absent || m->unusual || m->error) {
           /*
            * If it's unusual in anyway, ignore it
            */
	    if (!preflight) hibernate_stats.cd_found_unusual++;
            break;
	}
        if (m->cleaning) {
	    if (!preflight) hibernate_stats.cd_found_cleaning++;
            break;
	}
	if (m->laundry) {
	    if (!preflight) hibernate_stats.cd_found_laundry++;
            break;
	}
        if (!m->dirty)
        {
		refmod_state = pmap_get_refmod(VM_PAGE_GET_PHYS_PAGE(m));
        
            if (refmod_state & VM_MEM_REFERENCED)
                m->reference = TRUE;
            if (refmod_state & VM_MEM_MODIFIED) {
              	SET_PAGE_DIRTY(m, FALSE);
	    }
        }
   
        /*
         * If it's clean or purgeable we can discard the page on wakeup.
         */
        discard = (!m->dirty) 
		    || (VM_PURGABLE_VOLATILE == object->purgable)
		    || (VM_PURGABLE_EMPTY    == object->purgable);


        if (discard == FALSE) {
		if (!preflight)
			hibernate_stats.cd_found_dirty++;
        } else if (m->xpmapped && m->reference && !object->internal) {
		if (hibernate_stats.cd_found_xpmapped < HIBERNATE_XPMAPPED_LIMIT) {
			if (!preflight)
				hibernate_stats.cd_found_xpmapped++;
			discard = FALSE;
		} else {
			if (!preflight)
				hibernate_stats.cd_skipped_xpmapped++;
		}
        }
    }
    while (FALSE);

    if (object)
        vm_object_unlock(object);

    return (discard);
}


static void
hibernate_discard_page(vm_page_t m)
{
    vm_object_t	m_object;

    if (m->absent || m->unusual || m->error)
       /*
        * If it's unusual in anyway, ignore
        */
        return;

    m_object = VM_PAGE_OBJECT(m);

#if MACH_ASSERT || DEBUG
    if (!vm_object_lock_try(m_object))
	panic("hibernate_discard_page(%p) !vm_object_lock_try", m);
#else
    /* No need to lock page queue for token delete, hibernate_vm_unlock() 
       makes sure these locks are uncontended before sleep */
#endif /* MACH_ASSERT || DEBUG */

    if (m->pmapped == TRUE) 
    {
	__unused int refmod_state = pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(m));
    }

    if (m->laundry)
        panic("hibernate_discard_page(%p) laundry", m);
    if (m->private)
        panic("hibernate_discard_page(%p) private", m);
    if (m->fictitious)
        panic("hibernate_discard_page(%p) fictitious", m);

    if (VM_PURGABLE_VOLATILE == m_object->purgable)
    {
	/* object should be on a queue */
        assert((m_object->objq.next != NULL) && (m_object->objq.prev != NULL));
        purgeable_q_t old_queue = vm_purgeable_object_remove(m_object);
        assert(old_queue);
	if (m_object->purgeable_when_ripe) {
		vm_purgeable_token_delete_first(old_queue);
	}
	vm_object_lock_assert_exclusive(m_object);
        m_object->purgable = VM_PURGABLE_EMPTY;

	/*
	 * Purgeable ledgers:  pages of VOLATILE and EMPTY objects are
	 * accounted in the "volatile" ledger, so no change here.
	 * We have to update vm_page_purgeable_count, though, since we're
	 * effectively purging this object.
	 */
	unsigned int delta;
	assert(m_object->resident_page_count >= m_object->wired_page_count);
	delta = (m_object->resident_page_count - m_object->wired_page_count);
	assert(vm_page_purgeable_count >= delta);
	assert(delta > 0);
	OSAddAtomic(-delta, (SInt32 *)&vm_page_purgeable_count);
    }
	
    vm_page_free(m);

#if MACH_ASSERT || DEBUG
    vm_object_unlock(m_object);
#endif	/* MACH_ASSERT || DEBUG */
}

/*
 Grab locks for hibernate_page_list_setall()
*/
void
hibernate_vm_lock_queues(void)
{
    vm_object_lock(compressor_object);
    vm_page_lock_queues();
    lck_mtx_lock(&vm_page_queue_free_lock);
    lck_mtx_lock(&vm_purgeable_queue_lock);

    if (vm_page_local_q) {
	uint32_t  i;
	for (i = 0; i < vm_page_local_q_count; i++) {
	    struct vpl	*lq;
	    lq = &vm_page_local_q[i].vpl_un.vpl;
	    VPL_LOCK(&lq->vpl_lock);
	}
    }
}

void
hibernate_vm_unlock_queues(void)
{
    if (vm_page_local_q) {
	uint32_t  i;
	for (i = 0; i < vm_page_local_q_count; i++) {
	    struct vpl	*lq;
	    lq = &vm_page_local_q[i].vpl_un.vpl;
	    VPL_UNLOCK(&lq->vpl_lock);
	}
    }
    lck_mtx_unlock(&vm_purgeable_queue_lock);
    lck_mtx_unlock(&vm_page_queue_free_lock);
    vm_page_unlock_queues();
    vm_object_unlock(compressor_object);
}

/*
 Bits zero in the bitmaps => page needs to be saved. All pages default to be saved,
 pages known to VM to not need saving are subtracted.
 Wired pages to be saved are present in page_list_wired, pageable in page_list.
*/

void
hibernate_page_list_setall(hibernate_page_list_t * page_list,
			   hibernate_page_list_t * page_list_wired,
			   hibernate_page_list_t * page_list_pal,
			   boolean_t preflight, 
			   boolean_t will_discard,
			   uint32_t * pagesOut)
{
    uint64_t start, end, nsec;
    vm_page_t m;
    vm_page_t next;
    uint32_t pages = page_list->page_count;
    uint32_t count_anonymous = 0, count_throttled = 0, count_compressor = 0;
    uint32_t count_inactive = 0, count_active = 0, count_speculative = 0, count_cleaned = 0;
    uint32_t count_wire = pages;
    uint32_t count_discard_active    = 0;
    uint32_t count_discard_inactive  = 0;
    uint32_t count_discard_cleaned   = 0;
    uint32_t count_discard_purgeable = 0;
    uint32_t count_discard_speculative = 0;
    uint32_t count_discard_vm_struct_pages = 0;
    uint32_t i;
    uint32_t             bank;
    hibernate_bitmap_t * bitmap;
    hibernate_bitmap_t * bitmap_wired;
    boolean_t			 discard_all;
    boolean_t            discard;

    HIBLOG("hibernate_page_list_setall(preflight %d) start\n", preflight);

    if (preflight) {
        page_list       = NULL;
        page_list_wired = NULL;
        page_list_pal   = NULL;
		discard_all     = FALSE;
    } else {
		discard_all     = will_discard;
    }

#if MACH_ASSERT || DEBUG
    if (!preflight)
    {
        vm_page_lock_queues();
	if (vm_page_local_q) {
	    for (i = 0; i < vm_page_local_q_count; i++) {
		struct vpl	*lq;
		lq = &vm_page_local_q[i].vpl_un.vpl;
		VPL_LOCK(&lq->vpl_lock);
	    }
	}
    }
#endif  /* MACH_ASSERT || DEBUG */


    KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 8) | DBG_FUNC_START, count_wire, 0, 0, 0, 0);

    clock_get_uptime(&start);

    if (!preflight) {
	hibernate_page_list_zero(page_list);
	hibernate_page_list_zero(page_list_wired);
	hibernate_page_list_zero(page_list_pal);
    
	hibernate_stats.cd_vm_page_wire_count = vm_page_wire_count;
	hibernate_stats.cd_pages = pages;
    }

    if (vm_page_local_q) {
	    for (i = 0; i < vm_page_local_q_count; i++)
		    vm_page_reactivate_local(i, TRUE, !preflight);
    }

    if (preflight) {
	vm_object_lock(compressor_object);
	vm_page_lock_queues();
	lck_mtx_lock(&vm_page_queue_free_lock);
    }

    m = (vm_page_t) hibernate_gobble_queue;
    while (m)
    {
	pages--;
	count_wire--;
	if (!preflight) {
	    hibernate_page_bitset(page_list,       TRUE, VM_PAGE_GET_PHYS_PAGE(m));
	    hibernate_page_bitset(page_list_wired, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
	}
	m = m->snext;
    }

    if (!preflight) for( i = 0; i < real_ncpus; i++ )
    {
	if (cpu_data_ptr[i] && cpu_data_ptr[i]->cpu_processor)
	{
	for (m = PROCESSOR_DATA(cpu_data_ptr[i]->cpu_processor, free_pages); m; m = m->snext)
	    {
		assert(m->vm_page_q_state == VM_PAGE_ON_FREE_LOCAL_Q);

		pages--;
		count_wire--;
		hibernate_page_bitset(page_list,       TRUE, VM_PAGE_GET_PHYS_PAGE(m));
		hibernate_page_bitset(page_list_wired, TRUE, VM_PAGE_GET_PHYS_PAGE(m));

		hibernate_stats.cd_local_free++;
		hibernate_stats.cd_total_free++;
	    }
	}
    }

    for( i = 0; i < vm_colors; i++ )
    {
	vm_page_queue_iterate(&vm_page_queue_free[i].qhead,
			      m,
			      vm_page_t,
			      pageq)
	{
	    assert(m->vm_page_q_state == VM_PAGE_ON_FREE_Q);

	    pages--;
	    count_wire--;
	    if (!preflight) {
		hibernate_page_bitset(page_list,       TRUE, VM_PAGE_GET_PHYS_PAGE(m));
		hibernate_page_bitset(page_list_wired, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
    
		hibernate_stats.cd_total_free++;
	    }
	}
    }

    vm_page_queue_iterate(&vm_lopage_queue_free,
			  m,
			  vm_page_t,
			  pageq)
    {
	assert(m->vm_page_q_state == VM_PAGE_ON_FREE_LOPAGE_Q);

	pages--;
	count_wire--;
	if (!preflight) {
	    hibernate_page_bitset(page_list,       TRUE, VM_PAGE_GET_PHYS_PAGE(m));
	    hibernate_page_bitset(page_list_wired, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
    
	    hibernate_stats.cd_total_free++;
	}
    }

    m = (vm_page_t) vm_page_queue_first(&vm_page_queue_throttled);
    while (m && !vm_page_queue_end(&vm_page_queue_throttled, (vm_page_queue_entry_t)m))
    {
	assert(m->vm_page_q_state == VM_PAGE_ON_THROTTLED_Q);

        next = (vm_page_t)VM_PAGE_UNPACK_PTR(m->pageq.next);
	discard = FALSE;
        if ((kIOHibernateModeDiscardCleanInactive & gIOHibernateMode) 
         && hibernate_consider_discard(m, preflight))
        {
	    if (!preflight) hibernate_page_bitset(page_list, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
            count_discard_inactive++;
            discard = discard_all;
        }
        else
            count_throttled++;
	count_wire--;
	if (!preflight) hibernate_page_bitset(page_list_wired, TRUE, VM_PAGE_GET_PHYS_PAGE(m));

        if (discard) hibernate_discard_page(m);
	m = next;
    }

    m = (vm_page_t) vm_page_queue_first(&vm_page_queue_anonymous);
    while (m && !vm_page_queue_end(&vm_page_queue_anonymous, (vm_page_queue_entry_t)m))
    {
	assert(m->vm_page_q_state == VM_PAGE_ON_INACTIVE_INTERNAL_Q);

        next = (vm_page_t)VM_PAGE_UNPACK_PTR(m->pageq.next);
	discard = FALSE;
        if ((kIOHibernateModeDiscardCleanInactive & gIOHibernateMode) 
         && hibernate_consider_discard(m, preflight))
        {
	    if (!preflight) hibernate_page_bitset(page_list, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
	    if (m->dirty)
		count_discard_purgeable++;
	    else
		count_discard_inactive++;
            discard = discard_all;
        }
        else
            count_anonymous++;
	count_wire--;
	if (!preflight) hibernate_page_bitset(page_list_wired, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
        if (discard)    hibernate_discard_page(m);
	m = next;
    }

    m = (vm_page_t) vm_page_queue_first(&vm_page_queue_cleaned);
    while (m && !vm_page_queue_end(&vm_page_queue_cleaned, (vm_page_queue_entry_t)m))
    {
	assert(m->vm_page_q_state == VM_PAGE_ON_INACTIVE_CLEANED_Q);

        next = (vm_page_t)VM_PAGE_UNPACK_PTR(m->pageq.next);
	discard = FALSE;
        if ((kIOHibernateModeDiscardCleanInactive & gIOHibernateMode) 
         && hibernate_consider_discard(m, preflight))
        {
	    if (!preflight) hibernate_page_bitset(page_list, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
	    if (m->dirty)
		count_discard_purgeable++;
	    else
		count_discard_cleaned++;
            discard = discard_all;
        }
        else
            count_cleaned++;
	count_wire--;
	if (!preflight) hibernate_page_bitset(page_list_wired, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
        if (discard)    hibernate_discard_page(m);
	m = next;
    }

    m = (vm_page_t) vm_page_queue_first(&vm_page_queue_active);
    while (m && !vm_page_queue_end(&vm_page_queue_active, (vm_page_queue_entry_t)m))
    {
	assert(m->vm_page_q_state == VM_PAGE_ON_ACTIVE_Q);

        next = (vm_page_t)VM_PAGE_UNPACK_PTR(m->pageq.next);
	discard = FALSE;
        if ((kIOHibernateModeDiscardCleanActive & gIOHibernateMode) 
         && hibernate_consider_discard(m, preflight))
        {
	    if (!preflight) hibernate_page_bitset(page_list, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
	    if (m->dirty)
		count_discard_purgeable++;
	    else
		count_discard_active++;
            discard = discard_all;
        }
        else
            count_active++;
	count_wire--;
	if (!preflight) hibernate_page_bitset(page_list_wired, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
        if (discard)    hibernate_discard_page(m);
	m = next;
    }

    m = (vm_page_t) vm_page_queue_first(&vm_page_queue_inactive);
    while (m && !vm_page_queue_end(&vm_page_queue_inactive, (vm_page_queue_entry_t)m))
    {
	assert(m->vm_page_q_state == VM_PAGE_ON_INACTIVE_EXTERNAL_Q);

        next = (vm_page_t)VM_PAGE_UNPACK_PTR(m->pageq.next);
	discard = FALSE;
        if ((kIOHibernateModeDiscardCleanInactive & gIOHibernateMode) 
         && hibernate_consider_discard(m, preflight))
        {
	    if (!preflight) hibernate_page_bitset(page_list, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
	    if (m->dirty)
		count_discard_purgeable++;
	    else
		count_discard_inactive++;
            discard = discard_all;
        }
        else
            count_inactive++;
	count_wire--;
	if (!preflight) hibernate_page_bitset(page_list_wired, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
        if (discard)    hibernate_discard_page(m);
	m = next;
    }
    /* XXX FBDP TODO: secluded queue */

    for( i = 0; i <= VM_PAGE_MAX_SPECULATIVE_AGE_Q; i++ )
    {
	m = (vm_page_t) vm_page_queue_first(&vm_page_queue_speculative[i].age_q);
	while (m && !vm_page_queue_end(&vm_page_queue_speculative[i].age_q, (vm_page_queue_entry_t)m))
	{
	    assert(m->vm_page_q_state == VM_PAGE_ON_SPECULATIVE_Q);

	    next = (vm_page_t)VM_PAGE_UNPACK_PTR(m->pageq.next);
	    discard = FALSE;
	    if ((kIOHibernateModeDiscardCleanInactive & gIOHibernateMode) 
	     && hibernate_consider_discard(m, preflight))
	    {
		if (!preflight) hibernate_page_bitset(page_list, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
		count_discard_speculative++;
		discard = discard_all;
	    }
	    else
		count_speculative++;
	    count_wire--;
	    if (!preflight) hibernate_page_bitset(page_list_wired, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
	    if (discard)    hibernate_discard_page(m);
	    m = next;
	}
    }

    vm_page_queue_iterate(&compressor_object->memq, m, vm_page_t, listq)
    {
	assert(m->vm_page_q_state == VM_PAGE_USED_BY_COMPRESSOR);

        count_compressor++;
	count_wire--;
	if (!preflight) hibernate_page_bitset(page_list_wired, TRUE, VM_PAGE_GET_PHYS_PAGE(m));
    }

    if (preflight == FALSE && discard_all == TRUE) {
	    KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 12) | DBG_FUNC_START, 0, 0, 0, 0, 0);

	    HIBLOG("hibernate_teardown started\n");
	    count_discard_vm_struct_pages = hibernate_teardown_vm_structs(page_list, page_list_wired);
	    HIBLOG("hibernate_teardown completed - discarded %d\n", count_discard_vm_struct_pages);

	    pages -= count_discard_vm_struct_pages;
	    count_wire -= count_discard_vm_struct_pages;

	    hibernate_stats.cd_vm_struct_pages_unneeded = count_discard_vm_struct_pages;

	    KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 13) | DBG_FUNC_END, 0, 0, 0, 0, 0);
    }

    if (!preflight) {
	// pull wired from hibernate_bitmap
	bitmap = &page_list->bank_bitmap[0];
	bitmap_wired = &page_list_wired->bank_bitmap[0];
	for (bank = 0; bank < page_list->bank_count; bank++)
	{
	    for (i = 0; i < bitmap->bitmapwords; i++)
		bitmap->bitmap[i] = bitmap->bitmap[i] | ~bitmap_wired->bitmap[i];
	    bitmap       = (hibernate_bitmap_t *) &bitmap->bitmap      [bitmap->bitmapwords];
	    bitmap_wired = (hibernate_bitmap_t *) &bitmap_wired->bitmap[bitmap_wired->bitmapwords];
	}
    }

    // machine dependent adjustments
    hibernate_page_list_setall_machine(page_list, page_list_wired, preflight, &pages);

    if (!preflight) {
	hibernate_stats.cd_count_wire = count_wire;
	hibernate_stats.cd_discarded = count_discard_active + count_discard_inactive + count_discard_purgeable +
		count_discard_speculative + count_discard_cleaned + count_discard_vm_struct_pages;
    }

    clock_get_uptime(&end);
    absolutetime_to_nanoseconds(end - start, &nsec);
    HIBLOG("hibernate_page_list_setall time: %qd ms\n", nsec / 1000000ULL);

    HIBLOG("pages %d, wire %d, act %d, inact %d, cleaned %d spec %d, zf %d, throt %d, compr %d, xpmapped %d\n  %s discard act %d inact %d purgeable %d spec %d cleaned %d\n", 
	   pages, count_wire, count_active, count_inactive, count_cleaned, count_speculative, count_anonymous, count_throttled, count_compressor, hibernate_stats.cd_found_xpmapped,
	        discard_all ? "did" : "could",
	        count_discard_active, count_discard_inactive, count_discard_purgeable, count_discard_speculative, count_discard_cleaned);

    if (hibernate_stats.cd_skipped_xpmapped)
	    HIBLOG("WARNING: hibernate_page_list_setall skipped %d xpmapped pages\n", hibernate_stats.cd_skipped_xpmapped);

    *pagesOut = pages - count_discard_active - count_discard_inactive - count_discard_purgeable - count_discard_speculative - count_discard_cleaned;

    if (preflight && will_discard) *pagesOut -= count_compressor + count_throttled + count_anonymous + count_inactive + count_cleaned + count_speculative + count_active;

#if MACH_ASSERT || DEBUG
    if (!preflight)
    {
	if (vm_page_local_q) {
	    for (i = 0; i < vm_page_local_q_count; i++) {
		struct vpl	*lq;
		lq = &vm_page_local_q[i].vpl_un.vpl;
		VPL_UNLOCK(&lq->vpl_lock);
	    }
	}
        vm_page_unlock_queues();
    }
#endif  /* MACH_ASSERT || DEBUG */

    if (preflight) {
	lck_mtx_unlock(&vm_page_queue_free_lock);
	vm_page_unlock_queues();
	vm_object_unlock(compressor_object);
    }

    KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 8) | DBG_FUNC_END, count_wire, *pagesOut, 0, 0, 0);
}

void
hibernate_page_list_discard(hibernate_page_list_t * page_list)
{
    uint64_t  start, end, nsec;
    vm_page_t m;
    vm_page_t next;
    uint32_t  i;
    uint32_t  count_discard_active    = 0;
    uint32_t  count_discard_inactive  = 0;
    uint32_t  count_discard_purgeable = 0;
    uint32_t  count_discard_cleaned   = 0;
    uint32_t  count_discard_speculative = 0;


#if MACH_ASSERT || DEBUG
        vm_page_lock_queues();
	if (vm_page_local_q) {
	    for (i = 0; i < vm_page_local_q_count; i++) {
		struct vpl	*lq;
		lq = &vm_page_local_q[i].vpl_un.vpl;
		VPL_LOCK(&lq->vpl_lock);
	    }
	}
#endif  /* MACH_ASSERT || DEBUG */

    clock_get_uptime(&start);

    m = (vm_page_t) vm_page_queue_first(&vm_page_queue_anonymous);
    while (m && !vm_page_queue_end(&vm_page_queue_anonymous, (vm_page_queue_entry_t)m))
    {
	assert(m->vm_page_q_state == VM_PAGE_ON_INACTIVE_INTERNAL_Q);

        next = (vm_page_t) VM_PAGE_UNPACK_PTR(m->pageq.next);
        if (hibernate_page_bittst(page_list, VM_PAGE_GET_PHYS_PAGE(m)))
        {
	    if (m->dirty)
		count_discard_purgeable++;
	    else
		count_discard_inactive++;
            hibernate_discard_page(m);
        }
        m = next;
    }

    for( i = 0; i <= VM_PAGE_MAX_SPECULATIVE_AGE_Q; i++ )
    {
       m = (vm_page_t) vm_page_queue_first(&vm_page_queue_speculative[i].age_q);
       while (m && !vm_page_queue_end(&vm_page_queue_speculative[i].age_q, (vm_page_queue_entry_t)m))
       {
	   assert(m->vm_page_q_state == VM_PAGE_ON_SPECULATIVE_Q);

           next = (vm_page_t) VM_PAGE_UNPACK_PTR(m->pageq.next);
           if (hibernate_page_bittst(page_list, VM_PAGE_GET_PHYS_PAGE(m)))
           {
               count_discard_speculative++;
               hibernate_discard_page(m);
           }
           m = next;
       }
    }

    m = (vm_page_t) vm_page_queue_first(&vm_page_queue_inactive);
    while (m && !vm_page_queue_end(&vm_page_queue_inactive, (vm_page_queue_entry_t)m))
    {
	assert(m->vm_page_q_state == VM_PAGE_ON_INACTIVE_EXTERNAL_Q);

        next = (vm_page_t) VM_PAGE_UNPACK_PTR(m->pageq.next);
        if (hibernate_page_bittst(page_list, VM_PAGE_GET_PHYS_PAGE(m)))
        {
	    if (m->dirty)
		count_discard_purgeable++;
	    else
		count_discard_inactive++;
            hibernate_discard_page(m);
        }
        m = next;
    }
    /* XXX FBDP TODO: secluded queue */

    m = (vm_page_t) vm_page_queue_first(&vm_page_queue_active);
    while (m && !vm_page_queue_end(&vm_page_queue_active, (vm_page_queue_entry_t)m))
    {
	assert(m->vm_page_q_state == VM_PAGE_ON_ACTIVE_Q);

        next = (vm_page_t) VM_PAGE_UNPACK_PTR(m->pageq.next);
        if (hibernate_page_bittst(page_list, VM_PAGE_GET_PHYS_PAGE(m)))
        {
	    if (m->dirty)
		count_discard_purgeable++;
	    else
		count_discard_active++;
            hibernate_discard_page(m);
        }
        m = next;
    }

    m = (vm_page_t) vm_page_queue_first(&vm_page_queue_cleaned);
    while (m && !vm_page_queue_end(&vm_page_queue_cleaned, (vm_page_queue_entry_t)m))
    {
	assert(m->vm_page_q_state == VM_PAGE_ON_INACTIVE_CLEANED_Q);

        next = (vm_page_t) VM_PAGE_UNPACK_PTR(m->pageq.next);
        if (hibernate_page_bittst(page_list, VM_PAGE_GET_PHYS_PAGE(m)))
        {
	    if (m->dirty)
		count_discard_purgeable++;
	    else
		count_discard_cleaned++;
            hibernate_discard_page(m);
        }
        m = next;
    }

#if MACH_ASSERT || DEBUG
	if (vm_page_local_q) {
	    for (i = 0; i < vm_page_local_q_count; i++) {
		struct vpl	*lq;
		lq = &vm_page_local_q[i].vpl_un.vpl;
		VPL_UNLOCK(&lq->vpl_lock);
	    }
	}
        vm_page_unlock_queues();
#endif  /* MACH_ASSERT || DEBUG */

    clock_get_uptime(&end);
    absolutetime_to_nanoseconds(end - start, &nsec);
    HIBLOG("hibernate_page_list_discard time: %qd ms, discarded act %d inact %d purgeable %d spec %d cleaned %d\n",
                nsec / 1000000ULL,
	        count_discard_active, count_discard_inactive, count_discard_purgeable, count_discard_speculative, count_discard_cleaned);
}

boolean_t       hibernate_paddr_map_inited = FALSE;
boolean_t       hibernate_rebuild_needed = FALSE;
unsigned int	hibernate_teardown_last_valid_compact_indx = -1;
vm_page_t	hibernate_rebuild_hash_list = NULL;

unsigned int	hibernate_teardown_found_tabled_pages = 0;
unsigned int	hibernate_teardown_found_created_pages = 0;
unsigned int	hibernate_teardown_found_free_pages = 0;
unsigned int	hibernate_teardown_vm_page_free_count;


struct ppnum_mapping {
	struct ppnum_mapping	*ppnm_next;
	ppnum_t			ppnm_base_paddr;
	unsigned int		ppnm_sindx;
	unsigned int		ppnm_eindx;
};

struct ppnum_mapping	*ppnm_head;
struct ppnum_mapping	*ppnm_last_found = NULL;


void
hibernate_create_paddr_map() 
{
	unsigned int	i;
	ppnum_t		next_ppnum_in_run = 0;
	struct ppnum_mapping *ppnm = NULL;

	if (hibernate_paddr_map_inited == FALSE) {

		for (i = 0; i < vm_pages_count; i++) {

			if (ppnm)
				ppnm->ppnm_eindx = i;

			if (ppnm == NULL || VM_PAGE_GET_PHYS_PAGE(&vm_pages[i]) != next_ppnum_in_run) {

				ppnm = kalloc(sizeof(struct ppnum_mapping));

				ppnm->ppnm_next = ppnm_head;
				ppnm_head = ppnm;

				ppnm->ppnm_sindx = i;
				ppnm->ppnm_base_paddr = VM_PAGE_GET_PHYS_PAGE(&vm_pages[i]);
			}
			next_ppnum_in_run = VM_PAGE_GET_PHYS_PAGE(&vm_pages[i]) + 1;
		}
		ppnm->ppnm_eindx++;

		hibernate_paddr_map_inited = TRUE;
	}
}

ppnum_t
hibernate_lookup_paddr(unsigned int indx)
{
	struct ppnum_mapping *ppnm = NULL;
	
	ppnm = ppnm_last_found;

	if (ppnm) {
		if (indx >= ppnm->ppnm_sindx && indx < ppnm->ppnm_eindx)
			goto done;
	}
	for (ppnm = ppnm_head; ppnm; ppnm = ppnm->ppnm_next) {

		if (indx >= ppnm->ppnm_sindx && indx < ppnm->ppnm_eindx) {
			ppnm_last_found = ppnm;
			break;
		}
	}
	if (ppnm == NULL)
		panic("hibernate_lookup_paddr of %d failed\n", indx);
done:
	return (ppnm->ppnm_base_paddr + (indx - ppnm->ppnm_sindx));
}


uint32_t
hibernate_mark_as_unneeded(addr64_t saddr, addr64_t eaddr, hibernate_page_list_t *page_list, hibernate_page_list_t *page_list_wired)
{
	addr64_t	saddr_aligned;
	addr64_t	eaddr_aligned;
	addr64_t	addr;
	ppnum_t		paddr;
	unsigned int	mark_as_unneeded_pages = 0;

	saddr_aligned = (saddr + PAGE_MASK_64) & ~PAGE_MASK_64;
	eaddr_aligned = eaddr & ~PAGE_MASK_64;

	for (addr = saddr_aligned; addr < eaddr_aligned; addr += PAGE_SIZE_64) {

		paddr = pmap_find_phys(kernel_pmap, addr);

		assert(paddr);

		hibernate_page_bitset(page_list,       TRUE, paddr);
		hibernate_page_bitset(page_list_wired, TRUE, paddr);

		mark_as_unneeded_pages++;
	}
	return (mark_as_unneeded_pages);
}


void
hibernate_hash_insert_page(vm_page_t mem)
{
	vm_page_bucket_t *bucket;
	int		hash_id;
	vm_object_t	m_object;

	m_object = VM_PAGE_OBJECT(mem);

	assert(mem->hashed);
	assert(m_object);
	assert(mem->offset != (vm_object_offset_t) -1);

	/*
	 *	Insert it into the object_object/offset hash table
	 */
	hash_id = vm_page_hash(m_object, mem->offset);
	bucket = &vm_page_buckets[hash_id];

	mem->next_m = bucket->page_list;
	bucket->page_list = VM_PAGE_PACK_PTR(mem);
}


void
hibernate_free_range(int sindx, int eindx)
{
	vm_page_t	mem;
	unsigned int	color;

	while (sindx < eindx) {
		mem = &vm_pages[sindx];

		vm_page_init(mem, hibernate_lookup_paddr(sindx), FALSE);

		mem->lopage = FALSE;
		mem->vm_page_q_state = VM_PAGE_ON_FREE_Q;

	        color = VM_PAGE_GET_PHYS_PAGE(mem) & vm_color_mask;
		vm_page_queue_enter_first(&vm_page_queue_free[color].qhead,
					  mem,
					  vm_page_t,
					  pageq);
		vm_page_free_count++;

		sindx++;
	}
}


extern void hibernate_rebuild_pmap_structs(void);

void
hibernate_rebuild_vm_structs(void)
{
	int		cindx, sindx, eindx;
	vm_page_t	mem, tmem, mem_next;
	AbsoluteTime	startTime, endTime;
	uint64_t	nsec;

	if (hibernate_rebuild_needed == FALSE)
		return;

	KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 13) | DBG_FUNC_START, 0, 0, 0, 0, 0);
	HIBLOG("hibernate_rebuild started\n");

	clock_get_uptime(&startTime);

	hibernate_rebuild_pmap_structs();

	bzero(&vm_page_buckets[0], vm_page_bucket_count * sizeof(vm_page_bucket_t));
	eindx = vm_pages_count;

	for (cindx = hibernate_teardown_last_valid_compact_indx; cindx >= 0; cindx--) {
		
		mem = &vm_pages[cindx];
		/*
		 * hibernate_teardown_vm_structs leaves the location where
		 * this vm_page_t must be located in "next".
		 */
		tmem = (vm_page_t)(VM_PAGE_UNPACK_PTR(mem->next_m));
		mem->next_m = VM_PAGE_PACK_PTR(NULL);

		sindx = (int)(tmem - &vm_pages[0]);

		if (mem != tmem) {
			/*
			 * this vm_page_t was moved by hibernate_teardown_vm_structs,
			 * so move it back to its real location
			 */
			*tmem = *mem;
			mem = tmem;
		}
		if (mem->hashed)
			hibernate_hash_insert_page(mem);
		/*
		 * the 'hole' between this vm_page_t and the previous
		 * vm_page_t we moved needs to be initialized as 
		 * a range of free vm_page_t's
		 */
		hibernate_free_range(sindx + 1, eindx);

		eindx = sindx;
	}
	if (sindx)
		hibernate_free_range(0, sindx);

	assert(vm_page_free_count == hibernate_teardown_vm_page_free_count);

	/*
	 * process the list of vm_page_t's that were entered in the hash,
	 * but were not located in the vm_pages arrary... these are 
	 * vm_page_t's that were created on the fly (i.e. fictitious)
	 */
	for (mem = hibernate_rebuild_hash_list; mem; mem = mem_next) {
		mem_next = (vm_page_t)(VM_PAGE_UNPACK_PTR(mem->next_m));

		mem->next_m = 0;
		hibernate_hash_insert_page(mem);
	}
	hibernate_rebuild_hash_list = NULL;

        clock_get_uptime(&endTime);
        SUB_ABSOLUTETIME(&endTime, &startTime);
        absolutetime_to_nanoseconds(endTime, &nsec);

	HIBLOG("hibernate_rebuild completed - took %qd msecs\n", nsec / 1000000ULL);

	hibernate_rebuild_needed = FALSE;

	KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 13) | DBG_FUNC_END, 0, 0, 0, 0, 0);
}


extern void hibernate_teardown_pmap_structs(addr64_t *, addr64_t *);

uint32_t
hibernate_teardown_vm_structs(hibernate_page_list_t *page_list, hibernate_page_list_t *page_list_wired)
{
	unsigned int	i;
	unsigned int	compact_target_indx;
	vm_page_t	mem, mem_next;
	vm_page_bucket_t *bucket;
	unsigned int	mark_as_unneeded_pages = 0;
	unsigned int	unneeded_vm_page_bucket_pages = 0;
	unsigned int	unneeded_vm_pages_pages = 0;
	unsigned int	unneeded_pmap_pages = 0;
	addr64_t	start_of_unneeded = 0;
	addr64_t	end_of_unneeded = 0;

	
	if (hibernate_should_abort())
		return (0);

	HIBLOG("hibernate_teardown: wired_pages %d, free_pages %d, active_pages %d, inactive_pages %d, speculative_pages %d, cleaned_pages %d, compressor_pages %d\n",
	       vm_page_wire_count, vm_page_free_count, vm_page_active_count, vm_page_inactive_count, vm_page_speculative_count,
	       vm_page_cleaned_count, compressor_object->resident_page_count);

	for (i = 0; i < vm_page_bucket_count; i++) {

		bucket = &vm_page_buckets[i];

		for (mem = (vm_page_t)(VM_PAGE_UNPACK_PTR(bucket->page_list)); mem != VM_PAGE_NULL; mem = mem_next) {
			assert(mem->hashed);

			mem_next = (vm_page_t)(VM_PAGE_UNPACK_PTR(mem->next_m));

			if (mem < &vm_pages[0] || mem >= &vm_pages[vm_pages_count]) {
				mem->next_m = VM_PAGE_PACK_PTR(hibernate_rebuild_hash_list);
				hibernate_rebuild_hash_list = mem;
			}
		}
	}
	unneeded_vm_page_bucket_pages = hibernate_mark_as_unneeded((addr64_t)&vm_page_buckets[0], (addr64_t)&vm_page_buckets[vm_page_bucket_count], page_list, page_list_wired);
	mark_as_unneeded_pages += unneeded_vm_page_bucket_pages;

	hibernate_teardown_vm_page_free_count = vm_page_free_count;

	compact_target_indx = 0;

	for (i = 0; i < vm_pages_count; i++) {

		mem = &vm_pages[i];

		if (mem->vm_page_q_state == VM_PAGE_ON_FREE_Q) {
			unsigned int color;

			assert(mem->busy);
			assert(!mem->lopage);

			color = VM_PAGE_GET_PHYS_PAGE(mem) & vm_color_mask;

			vm_page_queue_remove(&vm_page_queue_free[color].qhead,
					     mem,
					     vm_page_t,
					     pageq);

			VM_PAGE_ZERO_PAGEQ_ENTRY(mem);

			vm_page_free_count--;

			hibernate_teardown_found_free_pages++;

			if (vm_pages[compact_target_indx].vm_page_q_state != VM_PAGE_ON_FREE_Q)
				compact_target_indx = i;
		} else {
			/*
			 * record this vm_page_t's original location
			 * we need this even if it doesn't get moved
			 * as an indicator to the rebuild function that
			 * we don't have to move it
			 */
			mem->next_m = VM_PAGE_PACK_PTR(mem);

			if (vm_pages[compact_target_indx].vm_page_q_state == VM_PAGE_ON_FREE_Q) {
				/*
				 * we've got a hole to fill, so
				 * move this vm_page_t to it's new home
				 */
				vm_pages[compact_target_indx] = *mem;
				mem->vm_page_q_state = VM_PAGE_ON_FREE_Q;

				hibernate_teardown_last_valid_compact_indx = compact_target_indx;
				compact_target_indx++;
			} else
				hibernate_teardown_last_valid_compact_indx = i;
		}
	}
	unneeded_vm_pages_pages = hibernate_mark_as_unneeded((addr64_t)&vm_pages[hibernate_teardown_last_valid_compact_indx+1],
							     (addr64_t)&vm_pages[vm_pages_count-1], page_list, page_list_wired);
	mark_as_unneeded_pages += unneeded_vm_pages_pages;

	hibernate_teardown_pmap_structs(&start_of_unneeded, &end_of_unneeded);

	if (start_of_unneeded) {
		unneeded_pmap_pages = hibernate_mark_as_unneeded(start_of_unneeded, end_of_unneeded, page_list, page_list_wired);
		mark_as_unneeded_pages += unneeded_pmap_pages;
	}
	HIBLOG("hibernate_teardown: mark_as_unneeded_pages %d, %d, %d\n", unneeded_vm_page_bucket_pages, unneeded_vm_pages_pages, unneeded_pmap_pages);

	hibernate_rebuild_needed = TRUE;

	return (mark_as_unneeded_pages);
}


#endif /* HIBERNATION */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <mach_vm_debug.h>
#if	MACH_VM_DEBUG

#include <mach_debug/hash_info.h>
#include <vm/vm_debug.h>

/*
 *	Routine:	vm_page_info
 *	Purpose:
 *		Return information about the global VP table.
 *		Fills the buffer with as much information as possible
 *		and returns the desired size of the buffer.
 *	Conditions:
 *		Nothing locked.  The caller should provide
 *		possibly-pageable memory.
 */

unsigned int
vm_page_info(
	hash_info_bucket_t *info,
	unsigned int count)
{
	unsigned int i;
	lck_spin_t	*bucket_lock;

	if (vm_page_bucket_count < count)
		count = vm_page_bucket_count;

	for (i = 0; i < count; i++) {
		vm_page_bucket_t *bucket = &vm_page_buckets[i];
		unsigned int bucket_count = 0;
		vm_page_t m;

		bucket_lock = &vm_page_bucket_locks[i / BUCKETS_PER_LOCK];
		lck_spin_lock(bucket_lock);

		for (m = (vm_page_t)(VM_PAGE_UNPACK_PTR(bucket->page_list));
		     m != VM_PAGE_NULL;
		     m = (vm_page_t)(VM_PAGE_UNPACK_PTR(m->next_m)))
			bucket_count++;

		lck_spin_unlock(bucket_lock);

		/* don't touch pageable memory while holding locks */
		info[i].hib_count = bucket_count;
	}

	return vm_page_bucket_count;
}
#endif	/* MACH_VM_DEBUG */

#if VM_PAGE_BUCKETS_CHECK
void
vm_page_buckets_check(void)
{
	unsigned int i;
	vm_page_t p;
	unsigned int p_hash;
	vm_page_bucket_t *bucket;
	lck_spin_t	*bucket_lock;

	if (!vm_page_buckets_check_ready) {
		return;
	}

#if HIBERNATION
	if (hibernate_rebuild_needed ||
	    hibernate_rebuild_hash_list) {
		panic("BUCKET_CHECK: hibernation in progress: "
		      "rebuild_needed=%d rebuild_hash_list=%p\n",
		      hibernate_rebuild_needed,
		      hibernate_rebuild_hash_list);
	}
#endif /* HIBERNATION */

#if VM_PAGE_FAKE_BUCKETS
	char *cp;
	for (cp = (char *) vm_page_fake_buckets_start;
	     cp < (char *) vm_page_fake_buckets_end;
	     cp++) {
		if (*cp != 0x5a) {
			panic("BUCKET_CHECK: corruption at %p in fake buckets "
			      "[0x%llx:0x%llx]\n",
			      cp,
			      (uint64_t) vm_page_fake_buckets_start,
			      (uint64_t) vm_page_fake_buckets_end);
		}
	}
#endif /* VM_PAGE_FAKE_BUCKETS */

	for (i = 0; i < vm_page_bucket_count; i++) {
		vm_object_t	p_object;

		bucket = &vm_page_buckets[i];
		if (!bucket->page_list) {
			continue;
		}

		bucket_lock = &vm_page_bucket_locks[i / BUCKETS_PER_LOCK];
		lck_spin_lock(bucket_lock);
		p = (vm_page_t)(VM_PAGE_UNPACK_PTR(bucket->page_list));

		while (p != VM_PAGE_NULL) {
			p_object = VM_PAGE_OBJECT(p);

			if (!p->hashed) {
				panic("BUCKET_CHECK: page %p (%p,0x%llx) "
				      "hash %d in bucket %d at %p "
				      "is not hashed\n",
				      p, p_object, p->offset,
				      p_hash, i, bucket);
			}
			p_hash = vm_page_hash(p_object, p->offset);
			if (p_hash != i) {
				panic("BUCKET_CHECK: corruption in bucket %d "
				      "at %p: page %p object %p offset 0x%llx "
				      "hash %d\n",
				      i, bucket, p, p_object, p->offset,
				      p_hash);
			}
			p = (vm_page_t)(VM_PAGE_UNPACK_PTR(p->next_m));
		}
		lck_spin_unlock(bucket_lock);
	}

//	printf("BUCKET_CHECK: checked buckets\n");
}
#endif /* VM_PAGE_BUCKETS_CHECK */

/*
 * 'vm_fault_enter' will place newly created pages (zero-fill and COW) onto the
 * local queues if they exist... its the only spot in the system where we add pages
 * to those queues...  once on those queues, those pages can only move to one of the
 * global page queues or the free queues... they NEVER move from local q to local q.
 * the 'local' state is stable when vm_page_queues_remove is called since we're behind
 * the global vm_page_queue_lock at this point...  we still need to take the local lock
 * in case this operation is being run on a different CPU then the local queue's identity,
 * but we don't have to worry about the page moving to a global queue or becoming wired
 * while we're grabbing the local lock since those operations would require the global
 * vm_page_queue_lock to be held, and we already own it.
 *
 * this is why its safe to utilze the wire_count field in the vm_page_t as the local_id...
 * 'wired' and local are ALWAYS mutually exclusive conditions.
 */

#if CONFIG_BACKGROUND_QUEUE
void
vm_page_queues_remove(vm_page_t mem, boolean_t remove_from_backgroundq)
#else
void
vm_page_queues_remove(vm_page_t mem, boolean_t __unused remove_from_backgroundq)
#endif
{
	boolean_t	was_pageable = TRUE;
	vm_object_t	m_object;

	m_object = VM_PAGE_OBJECT(mem);

	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);

	if (mem->vm_page_q_state == VM_PAGE_NOT_ON_Q)
	{
		assert(mem->pageq.next == 0 && mem->pageq.prev == 0);
#if CONFIG_BACKGROUND_QUEUE
		if (remove_from_backgroundq == TRUE) {
			vm_page_remove_from_backgroundq(mem);
		}
		if (mem->vm_page_on_backgroundq) {
			assert(mem->vm_page_backgroundq.next != 0);
			assert(mem->vm_page_backgroundq.prev != 0);
		} else {
			assert(mem->vm_page_backgroundq.next == 0);
			assert(mem->vm_page_backgroundq.prev == 0);
		}
#endif /* CONFIG_BACKGROUND_QUEUE */
		return;
	}

	if (mem->vm_page_q_state == VM_PAGE_USED_BY_COMPRESSOR)
	{
		assert(mem->pageq.next == 0 && mem->pageq.prev == 0);
#if CONFIG_BACKGROUND_QUEUE
		assert(mem->vm_page_backgroundq.next == 0 &&
		       mem->vm_page_backgroundq.prev == 0 &&
		       mem->vm_page_on_backgroundq == FALSE);
#endif
		return;
	}
	if (mem->vm_page_q_state == VM_PAGE_IS_WIRED) {
		/*
		 * might put these guys on a list for debugging purposes
		 * if we do, we'll need to remove this assert
		 */
		assert(mem->pageq.next == 0 && mem->pageq.prev == 0);
#if CONFIG_BACKGROUND_QUEUE
		assert(mem->vm_page_backgroundq.next == 0 &&
		       mem->vm_page_backgroundq.prev == 0 &&
		       mem->vm_page_on_backgroundq == FALSE);
#endif
		return;
	}

	assert(m_object != compressor_object);
	assert(m_object != kernel_object);
	assert(m_object != vm_submap_object);
	assert(!mem->fictitious);

	switch(mem->vm_page_q_state) {
		
	case VM_PAGE_ON_ACTIVE_LOCAL_Q:
	{
		struct vpl	*lq;

		lq = &vm_page_local_q[mem->local_id].vpl_un.vpl;
		VPL_LOCK(&lq->vpl_lock);
		vm_page_queue_remove(&lq->vpl_queue,
				     mem, vm_page_t, pageq);
		mem->local_id = 0;
		lq->vpl_count--;
		if (m_object->internal) {
			lq->vpl_internal_count--;
		} else {
			lq->vpl_external_count--;
		}
		VPL_UNLOCK(&lq->vpl_lock);
		was_pageable = FALSE;
		break;
	}
	case VM_PAGE_ON_ACTIVE_Q:
	{
		vm_page_queue_remove(&vm_page_queue_active,
				     mem, vm_page_t, pageq);
		vm_page_active_count--;
		break;
	}

	case VM_PAGE_ON_INACTIVE_INTERNAL_Q:
	{
		assert(m_object->internal == TRUE);

		vm_page_inactive_count--;
		vm_page_queue_remove(&vm_page_queue_anonymous,
				     mem, vm_page_t, pageq);
		vm_page_anonymous_count--;
		vm_purgeable_q_advance_all();
		break;
	}

	case VM_PAGE_ON_INACTIVE_EXTERNAL_Q:
	{
		assert(m_object->internal == FALSE);

		vm_page_inactive_count--;
		vm_page_queue_remove(&vm_page_queue_inactive,
				     mem, vm_page_t, pageq);
		vm_purgeable_q_advance_all();
		break;
	}

	case VM_PAGE_ON_INACTIVE_CLEANED_Q:
	{
		assert(m_object->internal == FALSE);

		vm_page_inactive_count--;
		vm_page_queue_remove(&vm_page_queue_cleaned,
				     mem, vm_page_t, pageq);
		vm_page_cleaned_count--;
		break;
	}

	case VM_PAGE_ON_THROTTLED_Q:
	{
		assert(m_object->internal == TRUE);

		vm_page_queue_remove(&vm_page_queue_throttled,
				     mem, vm_page_t, pageq);
		vm_page_throttled_count--;
		was_pageable = FALSE;
		break;
	}

	case VM_PAGE_ON_SPECULATIVE_Q:
	{
		assert(m_object->internal == FALSE);

                vm_page_remque(&mem->pageq);
		vm_page_speculative_count--;
		break;
	}

#if CONFIG_SECLUDED_MEMORY
	case VM_PAGE_ON_SECLUDED_Q:
	{
		vm_page_queue_remove(&vm_page_queue_secluded,
				     mem, vm_page_t, pageq);
		vm_page_secluded_count--;
		if (m_object == VM_OBJECT_NULL) {
			vm_page_secluded_count_free--;
			was_pageable = FALSE;
		} else {
			assert(!m_object->internal);
			vm_page_secluded_count_inuse--;
			was_pageable = FALSE;
//			was_pageable = TRUE;
		}
		break;
	}
#endif /* CONFIG_SECLUDED_MEMORY */

	default:
	{
		/*
		 *	if (mem->vm_page_q_state == VM_PAGE_ON_PAGEOUT_Q)
		 * 		NOTE: vm_page_queues_remove does not deal with removing pages from the pageout queue...
		 * 		the caller is responsible for determing if the page is on that queue, and if so, must
		 * 		either first remove it (it needs both the page queues lock and the object lock to do
		 * 		this via vm_pageout_steal_laundry), or avoid the call to vm_page_queues_remove
		 *
		 *	we also don't expect to encounter VM_PAGE_ON_FREE_Q, VM_PAGE_ON_FREE_LOCAL_Q, VM_PAGE_ON_FREE_LOPAGE_Q
		 *	or any of the undefined states
		 */
		panic("vm_page_queues_remove - bad page q_state (%p, %d)\n", mem, mem->vm_page_q_state);
		break;
	}

	}
	VM_PAGE_ZERO_PAGEQ_ENTRY(mem);
	mem->vm_page_q_state = VM_PAGE_NOT_ON_Q;

#if CONFIG_BACKGROUND_QUEUE
	if (remove_from_backgroundq == TRUE)
		vm_page_remove_from_backgroundq(mem);
#endif
	if (was_pageable) {
		if (m_object->internal) {
			vm_page_pageable_internal_count--;
		} else {
			vm_page_pageable_external_count--;
		}
	}
}

void
vm_page_remove_internal(vm_page_t page)
{
	vm_object_t __object = VM_PAGE_OBJECT(page);
	if (page == __object->memq_hint) {
		vm_page_t	__new_hint;
		vm_page_queue_entry_t	__qe;
		__qe = (vm_page_queue_entry_t)vm_page_queue_next(&page->listq);
		if (vm_page_queue_end(&__object->memq, __qe)) {
			__qe = (vm_page_queue_entry_t)vm_page_queue_prev(&page->listq);
			if (vm_page_queue_end(&__object->memq, __qe)) {
				__qe = NULL;
			}
		}
		__new_hint = (vm_page_t)((uintptr_t) __qe);
		__object->memq_hint = __new_hint;
	}
	vm_page_queue_remove(&__object->memq, page, vm_page_t, listq);
#if CONFIG_SECLUDED_MEMORY
	if (__object->eligible_for_secluded) {
		vm_page_secluded.eligible_for_secluded--;
	}
#endif /* CONFIG_SECLUDED_MEMORY */
}

void
vm_page_enqueue_inactive(vm_page_t mem, boolean_t first)
{
	vm_object_t	m_object;

	m_object = VM_PAGE_OBJECT(mem);

	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	assert(!mem->fictitious);
	assert(!mem->laundry);
	assert(mem->vm_page_q_state == VM_PAGE_NOT_ON_Q);
	vm_page_check_pageable_safe(mem);

#if CONFIG_SECLUDED_MEMORY
	if (secluded_for_filecache &&
	    vm_page_secluded_target != 0 &&
	    num_tasks_can_use_secluded_mem == 0 &&
	    m_object->eligible_for_secluded &&
	    secluded_aging_policy == SECLUDED_AGING_FIFO) {
		mem->vm_page_q_state = VM_PAGE_ON_SECLUDED_Q;
		vm_page_queue_enter(&vm_page_queue_secluded, mem,
				    vm_page_t, pageq);
		vm_page_secluded_count++;
		vm_page_secluded_count_inuse++;
		assert(!m_object->internal);
//		vm_page_pageable_external_count++;
		return;
	}
#endif /* CONFIG_SECLUDED_MEMORY */

	if (m_object->internal) {
		mem->vm_page_q_state = VM_PAGE_ON_INACTIVE_INTERNAL_Q;

		if (first == TRUE)
			vm_page_queue_enter_first(&vm_page_queue_anonymous, mem, vm_page_t, pageq);
		else
			vm_page_queue_enter(&vm_page_queue_anonymous, mem, vm_page_t, pageq);

		vm_page_anonymous_count++;
		vm_page_pageable_internal_count++;
	} else {
		mem->vm_page_q_state = VM_PAGE_ON_INACTIVE_EXTERNAL_Q;

		if (first == TRUE)
			vm_page_queue_enter_first(&vm_page_queue_inactive, mem, vm_page_t, pageq);
		else
			vm_page_queue_enter(&vm_page_queue_inactive, mem, vm_page_t, pageq);

		vm_page_pageable_external_count++;
	}
	vm_page_inactive_count++;
	token_new_pagecount++;

#if CONFIG_BACKGROUND_QUEUE
	if (mem->vm_page_in_background)
		vm_page_add_to_backgroundq(mem, FALSE);
#endif
}

void
vm_page_enqueue_active(vm_page_t mem, boolean_t first)
{
	vm_object_t	m_object;

	m_object = VM_PAGE_OBJECT(mem);

	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	assert(!mem->fictitious);
	assert(!mem->laundry);
	assert(mem->vm_page_q_state == VM_PAGE_NOT_ON_Q);
	vm_page_check_pageable_safe(mem);

	mem->vm_page_q_state = VM_PAGE_ON_ACTIVE_Q;
	if (first == TRUE)
		vm_page_queue_enter_first(&vm_page_queue_active, mem, vm_page_t, pageq);
	else
		vm_page_queue_enter(&vm_page_queue_active, mem, vm_page_t, pageq);
	vm_page_active_count++;

	if (m_object->internal) {
		vm_page_pageable_internal_count++;
	} else {
		vm_page_pageable_external_count++;
	}

#if CONFIG_BACKGROUND_QUEUE
	if (mem->vm_page_in_background)
		vm_page_add_to_backgroundq(mem, FALSE);
#endif
}

/*
 * Pages from special kernel objects shouldn't
 * be placed on pageable queues.
 */
void
vm_page_check_pageable_safe(vm_page_t page)
{
	vm_object_t	page_object;

	page_object = VM_PAGE_OBJECT(page);

	if (page_object == kernel_object) {
		panic("vm_page_check_pageable_safe: trying to add page" \
			 "from kernel object (%p) to pageable queue", kernel_object);
	}

	if (page_object == compressor_object) {
		panic("vm_page_check_pageable_safe: trying to add page" \
			 "from compressor object (%p) to pageable queue", compressor_object);
	}

	if (page_object == vm_submap_object) {
		panic("vm_page_check_pageable_safe: trying to add page" \
			"from submap object (%p) to pageable queue", vm_submap_object);
	}
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * wired page diagnose
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <libkern/OSKextLibPrivate.h>

vm_allocation_site_t * 
vm_allocation_sites[VM_KERN_MEMORY_COUNT];

vm_tag_t 
vm_tag_bt(void)
{
    uintptr_t* frameptr;
    uintptr_t* frameptr_next;
    uintptr_t retaddr;
    uintptr_t kstackb, kstackt;
    const vm_allocation_site_t * site;
    thread_t cthread;
    
    cthread = current_thread();
    if (__improbable(cthread == NULL)) return VM_KERN_MEMORY_OSFMK;

    kstackb = cthread->kernel_stack;
    kstackt = kstackb + kernel_stack_size;

    /* Load stack frame pointer (EBP on x86) into frameptr */
    frameptr = __builtin_frame_address(0);
    site = NULL;
    while (frameptr != NULL) 
    {
	/* Verify thread stack bounds */
	if (((uintptr_t)(frameptr + 2) > kstackt) || ((uintptr_t)frameptr < kstackb)) break;

	/* Next frame pointer is pointed to by the previous one */
	frameptr_next = (uintptr_t*) *frameptr;

	/* Pull return address from one spot above the frame pointer */
	retaddr = *(frameptr + 1);

	if ((retaddr < vm_kernel_stext) || (retaddr > vm_kernel_top))
	{
	    site = OSKextGetAllocationSiteForCaller(retaddr);
	    break;
	}

	frameptr = frameptr_next;
    }
    return (site ? site->tag : VM_KERN_MEMORY_NONE);
}

static uint64_t free_tag_bits[256/64];

void
vm_tag_alloc_locked(vm_allocation_site_t * site)
{
    vm_tag_t tag;
    uint64_t avail;
    uint64_t idx;

    if (site->tag) return;

    idx = 0;
    while (TRUE)
    {
	avail = free_tag_bits[idx];
	if (avail)
	{
	    tag = __builtin_clzll(avail);
	    avail &= ~(1ULL << (63 - tag));
	    free_tag_bits[idx] = avail;
	    tag += (idx << 6);
	    break;
	}
	idx++;
	if (idx >= (sizeof(free_tag_bits) / sizeof(free_tag_bits[0])))
	{
	     tag = VM_KERN_MEMORY_ANY;
	     break;
	}
    }
    site->tag = tag;
    if (VM_KERN_MEMORY_ANY != tag)
    {
	assert(!vm_allocation_sites[tag]);
	vm_allocation_sites[tag] = site;
    }
}

static void
vm_tag_free_locked(vm_tag_t tag)
{
    uint64_t avail;
    uint32_t idx;
    uint64_t bit;

    if (VM_KERN_MEMORY_ANY == tag) return;

    idx = (tag >> 6);
    avail = free_tag_bits[idx];
    tag &= 63;
    bit = (1ULL << (63 - tag));
    assert(!(avail & bit));
    free_tag_bits[idx] = (avail | bit);
}

static void
vm_tag_init(void)
{
    vm_tag_t tag;
    for (tag = VM_KERN_MEMORY_FIRST_DYNAMIC; tag < VM_KERN_MEMORY_ANY; tag++)
    {
        vm_tag_free_locked(tag);
    }
}

vm_tag_t
vm_tag_alloc(vm_allocation_site_t * site)
{
    vm_tag_t tag;

    if (VM_TAG_BT & site->flags)
    {
	tag = vm_tag_bt();
	if (VM_KERN_MEMORY_NONE != tag) return (tag);
    }

    if (!site->tag) 
    {
	lck_spin_lock(&vm_allocation_sites_lock);
	vm_tag_alloc_locked(site);
	lck_spin_unlock(&vm_allocation_sites_lock);
    }

    return (site->tag);
}

static void 
vm_page_count_object(mach_memory_info_t * sites, unsigned int __unused num_sites, vm_object_t object)
{
    if (!object->wired_page_count) return;
    if (object != kernel_object)
    {
	assert(object->wire_tag < num_sites);
	sites[object->wire_tag].size += ptoa_64(object->wired_page_count);
    }
}

typedef void (*vm_page_iterate_proc)(mach_memory_info_t * sites, 
				     unsigned int num_sites, vm_object_t object);

static void 
vm_page_iterate_purgeable_objects(mach_memory_info_t * sites, unsigned int num_sites,
				  vm_page_iterate_proc proc, purgeable_q_t queue, 
				  int group)
{
    vm_object_t object;

    for (object = (vm_object_t) queue_first(&queue->objq[group]);
	!queue_end(&queue->objq[group], (queue_entry_t) object);
	object = (vm_object_t) queue_next(&object->objq))
    {
	proc(sites, num_sites, object);
    }
}

static void 
vm_page_iterate_objects(mach_memory_info_t * sites, unsigned int num_sites,
			vm_page_iterate_proc proc)
{
    purgeable_q_t   volatile_q;
    queue_head_t  * nonvolatile_q;
    vm_object_t     object;
    int             group;

    lck_spin_lock(&vm_objects_wired_lock);
    queue_iterate(&vm_objects_wired,
		  object,
		  vm_object_t,
		  objq)
    {
	proc(sites, num_sites, object);
    }
    lck_spin_unlock(&vm_objects_wired_lock);

    lck_mtx_lock(&vm_purgeable_queue_lock);
    nonvolatile_q = &purgeable_nonvolatile_queue;
    for (object = (vm_object_t) queue_first(nonvolatile_q);
	 !queue_end(nonvolatile_q, (queue_entry_t) object);
	 object = (vm_object_t) queue_next(&object->objq))
    {
	proc(sites, num_sites, object);
    }

    volatile_q = &purgeable_queues[PURGEABLE_Q_TYPE_OBSOLETE];
    vm_page_iterate_purgeable_objects(sites, num_sites, proc, volatile_q, 0);

    volatile_q = &purgeable_queues[PURGEABLE_Q_TYPE_FIFO];
    for (group = 0; group < NUM_VOLATILE_GROUPS; group++)
    {
	vm_page_iterate_purgeable_objects(sites, num_sites, proc, volatile_q, group);
    }

    volatile_q = &purgeable_queues[PURGEABLE_Q_TYPE_LIFO];
    for (group = 0; group < NUM_VOLATILE_GROUPS; group++)
    {
	vm_page_iterate_purgeable_objects(sites, num_sites, proc, volatile_q, group);
    }
    lck_mtx_unlock(&vm_purgeable_queue_lock);
}

static uint64_t
process_account(mach_memory_info_t * sites, unsigned int __unused num_sites, uint64_t zones_collectable_bytes)
{
    uint64_t found;
    unsigned int idx;
    vm_allocation_site_t * site;

    assert(num_sites >= VM_KERN_MEMORY_COUNT);
    found = 0;
    for (idx = 0; idx < VM_KERN_MEMORY_COUNT; idx++) 
    {
	found += sites[idx].size;
	if (idx < VM_KERN_MEMORY_FIRST_DYNAMIC)
	{
	    sites[idx].site   = idx;
	    sites[idx].flags |= VM_KERN_SITE_TAG;
	    if (VM_KERN_MEMORY_ZONE == idx)
	    {
                sites[idx].flags |= VM_KERN_SITE_HIDE;
                sites[idx].collectable_bytes = zones_collectable_bytes;
            } else sites[idx].flags |= VM_KERN_SITE_WIRED;
            continue;
	}
	lck_spin_lock(&vm_allocation_sites_lock);
	if ((site = vm_allocation_sites[idx]))
	{
	    if (sites[idx].size)
	    {
		sites[idx].flags |= VM_KERN_SITE_WIRED;
		if (VM_TAG_KMOD == (VM_KERN_SITE_TYPE & site->flags))
		{
		    sites[idx].site   = OSKextGetKmodIDForSite(site, NULL, 0);
		    sites[idx].flags |= VM_KERN_SITE_KMOD;
		}
		else
		{
		    sites[idx].site   = VM_KERNEL_UNSLIDE(site);
		    sites[idx].flags |= VM_KERN_SITE_KERNEL;
		}
		site = NULL;
	    }
	    else
	    {
#if 1
		site = NULL;
#else
		/* this code would free a site with no allocations but can race a new
		 * allocation being made */
		vm_tag_free_locked(site->tag);
	        site->tag = VM_KERN_MEMORY_NONE;
	        vm_allocation_sites[idx] = NULL;
		if (!(VM_TAG_UNLOAD & site->flags)) site = NULL;
#endif
	    }
	}
	lck_spin_unlock(&vm_allocation_sites_lock);
        if (site) OSKextFreeSite(site);
    }

    return (found);
}

kern_return_t 
vm_page_diagnose(mach_memory_info_t * sites, unsigned int num_sites, uint64_t zones_collectable_bytes)
{
    enum             	   { kMaxKernelDepth = 1 };
    vm_map_t           	     maps   [kMaxKernelDepth];
    vm_map_entry_t     	     entries[kMaxKernelDepth];
    vm_map_t           	     map;
    vm_map_entry_t     	     entry;
    vm_object_offset_t 	     offset;
    vm_page_t          	     page;
    int                	     stackIdx, count;
    uint64_t	       	     wired_size;
    uint64_t	       	     wired_managed_size;
    uint64_t	       	     wired_reserved_size;
    mach_memory_info_t     * counts;

    bzero(sites, num_sites * sizeof(mach_memory_info_t));

    if (!vm_page_wire_count_initial) return (KERN_ABORTED);

    vm_page_iterate_objects(sites, num_sites, &vm_page_count_object);

    wired_size          = ptoa_64(vm_page_wire_count + vm_lopage_free_count + vm_page_throttled_count);
    wired_reserved_size = ptoa_64(vm_page_wire_count_initial - vm_page_stolen_count + vm_page_throttled_count);
    wired_managed_size  = ptoa_64(vm_page_wire_count - vm_page_wire_count_initial);

    assert(num_sites >= (VM_KERN_MEMORY_COUNT + VM_KERN_COUNTER_COUNT));
    counts = &sites[VM_KERN_MEMORY_COUNT];

#define SET_COUNT(xcount, xsize, xflags)			\
    counts[xcount].site  = (xcount);			\
    counts[xcount].size  = (xsize);			\
    counts[xcount].flags = VM_KERN_SITE_COUNTER | xflags;

    SET_COUNT(VM_KERN_COUNT_MANAGED,		  ptoa_64(vm_page_pages),        0);
    SET_COUNT(VM_KERN_COUNT_WIRED,		  wired_size,                    0);
    SET_COUNT(VM_KERN_COUNT_WIRED_MANAGED,	  wired_managed_size,            0);
    SET_COUNT(VM_KERN_COUNT_RESERVED,	  	  wired_reserved_size, 		 VM_KERN_SITE_WIRED);
    SET_COUNT(VM_KERN_COUNT_STOLEN,	          ptoa_64(vm_page_stolen_count), VM_KERN_SITE_WIRED);
    SET_COUNT(VM_KERN_COUNT_LOPAGE,	          ptoa_64(vm_lopage_free_count), VM_KERN_SITE_WIRED);

#define SET_MAP(xcount, xsize, xfree, xlargest)		\
    counts[xcount].site    = (xcount);			\
    counts[xcount].size    = (xsize);			\
    counts[xcount].free    = (xfree);			\
    counts[xcount].largest = (xlargest);		\
    counts[xcount].flags   = VM_KERN_SITE_COUNTER;

    vm_map_size_t map_size, map_free, map_largest;

    vm_map_sizes(kernel_map, &map_size, &map_free, &map_largest);
    SET_MAP(VM_KERN_COUNT_MAP_KERNEL, map_size, map_free, map_largest);

    vm_map_sizes(zone_map, &map_size, &map_free, &map_largest);
    SET_MAP(VM_KERN_COUNT_MAP_ZONE, map_size, map_free, map_largest);

    vm_map_sizes(kalloc_map, &map_size, &map_free, &map_largest);
    SET_MAP(VM_KERN_COUNT_MAP_KALLOC, map_size, map_free, map_largest);

    map = kernel_map;
    stackIdx = 0;
    while (map)
    {
	vm_map_lock(map);
	for (entry = map->hdr.links.next; map; entry = entry->links.next)
	{
	    if (entry->is_sub_map)
	    {
	    	assert(stackIdx < kMaxKernelDepth);
		maps[stackIdx] = map;
		entries[stackIdx] = entry;
		stackIdx++;
		map = VME_SUBMAP(entry);
		entry = NULL;
		break;
	    }
	    if (VME_OBJECT(entry) == kernel_object)
	    {
		count = 0;
		vm_object_lock(VME_OBJECT(entry));
		for (offset = entry->links.start; offset < entry->links.end; offset += page_size)
		{
			page = vm_page_lookup(VME_OBJECT(entry), offset);
			if (page && VM_PAGE_WIRED(page)) count++;
		}
		vm_object_unlock(VME_OBJECT(entry));

		if (count)
		{
		    assert(VME_ALIAS(entry) < num_sites);
		    sites[VME_ALIAS(entry)].size += ptoa_64(count);
		}
	    }
	    while (map && (entry == vm_map_last_entry(map)))
	    {
		vm_map_unlock(map);
		if (!stackIdx) map = NULL;
		else
		{
		    --stackIdx;
		    map = maps[stackIdx];
		    entry = entries[stackIdx];
		}
	    }
	}
    }

    process_account(sites, num_sites, zones_collectable_bytes);
    
    return (KERN_SUCCESS);
}

uint32_t
vm_tag_get_kext(vm_tag_t tag, char * name, vm_size_t namelen)
{
    vm_allocation_site_t * site;
    uint32_t               kmodId;

    kmodId = 0;
    lck_spin_lock(&vm_allocation_sites_lock);
    if ((site = vm_allocation_sites[tag]))
    {
        if (VM_TAG_KMOD == (VM_KERN_SITE_TYPE & site->flags))
        {
            kmodId = OSKextGetKmodIDForSite(site, name, namelen);
        }
    }
    lck_spin_unlock(&vm_allocation_sites_lock);

    return (kmodId);
}

#if DEBUG || DEVELOPMENT

#define vm_tag_set_lock(set)    lck_spin_lock(&set->lock)
#define vm_tag_set_unlock(set)  lck_spin_unlock(&set->lock)

void
vm_tag_set_init(vm_tag_set_t set, uint32_t count)
{
    lck_spin_init(&set->lock, &vm_page_lck_grp_bucket, &vm_page_lck_attr);
    bzero(&set->entries, count * sizeof(struct vm_tag_set_entry));
}

kern_return_t
vm_tag_set_enter(vm_tag_set_t set, uint32_t count, vm_tag_t tag)
{
    kern_return_t kr;
    uint32_t      idx, free;

    vm_tag_set_lock(set);

    assert(tag != VM_KERN_MEMORY_NONE);

    kr = KERN_NO_SPACE;
    free = -1U;
    for (idx = 0; idx < count; idx++)
    {
        if (tag == set->entries[idx].tag)
        {
            set->entries[idx].count++;
            kr = KERN_SUCCESS;
            break;
        }
        if ((free == -1U) && !set->entries[idx].count) free = idx;
    }

    if ((KERN_SUCCESS != kr) && (free != -1U))
    {
        set->entries[free].tag = tag;
        set->entries[free].count = 1;
        kr = KERN_SUCCESS;
    }

    vm_tag_set_unlock(set);

    return (kr);
}

kern_return_t
vm_tag_set_remove(vm_tag_set_t set, uint32_t count, vm_tag_t tag, vm_tag_t * new_tagp)
{
    kern_return_t kr;
    uint32_t      idx;
    vm_tag_t      new_tag;

    assert(tag != VM_KERN_MEMORY_NONE);
    new_tag = VM_KERN_MEMORY_NONE;
    vm_tag_set_lock(set);

    kr = KERN_NOT_IN_SET;
    for (idx = 0; idx < count; idx++)
    {
        if ((tag != VM_KERN_MEMORY_NONE)
          && (tag == set->entries[idx].tag)
          && set->entries[idx].count)
        {
            set->entries[idx].count--;
            kr = KERN_SUCCESS;
            if (set->entries[idx].count)
            {
                new_tag = tag;
                break;
            }
            if (!new_tagp) break;
            tag = VM_KERN_MEMORY_NONE;
        }

        if (set->entries[idx].count && (VM_KERN_MEMORY_NONE == new_tag))
        {
            new_tag = set->entries[idx].tag;
            if (VM_KERN_MEMORY_NONE == tag) break;
        }
    }

    vm_tag_set_unlock(set);
    if (new_tagp) *new_tagp = new_tag;

    return (kr);
}

#endif /* DEBUG || DEVELOPMENT */
