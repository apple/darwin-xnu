/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
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
 *	File:	vm/vm_page.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *
 *	Resident memory management module.
 */

#include <debug.h>

#include <mach/clock_types.h>
#include <mach/vm_prot.h>
#include <mach/vm_statistics.h>
#include <kern/counters.h>
#include <kern/sched_prim.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/zalloc.h>
#include <kern/xpr.h>
#include <vm/pmap.h>
#include <vm/vm_init.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_kern.h>			/* kernel_memory_allocate() */
#include <kern/misc_protos.h>
#include <zone_debug.h>
#include <vm/cpm.h>
#include <ppc/mappings.h>		/* (BRINGUP) */
#include <pexpert/pexpert.h>	/* (BRINGUP) */

#include <vm/vm_protos.h>

/*	Variables used to indicate the relative age of pages in the
 *	inactive list
 */

unsigned int	vm_page_ticket_roll = 0;
unsigned int	vm_page_ticket = 0;
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
int	vm_page_pages;

/*
 *	The vm_page_lookup() routine, which provides for fast
 *	(virtual memory object, offset) to page lookup, employs
 *	the following hash table.  The vm_page_{insert,remove}
 *	routines install and remove associations in the table.
 *	[This table is often called the virtual-to-physical,
 *	or VP, table.]
 */
typedef struct {
	vm_page_t	pages;
#if	MACH_PAGE_HASH_STATS
	int		cur_count;		/* current count */
	int		hi_count;		/* high water mark */
#endif /* MACH_PAGE_HASH_STATS */
} vm_page_bucket_t;

vm_page_bucket_t *vm_page_buckets;		/* Array of buckets */
unsigned int	vm_page_bucket_count = 0;	/* How big is array? */
unsigned int	vm_page_hash_mask;		/* Mask for hash function */
unsigned int	vm_page_hash_shift;		/* Shift for hash function */
uint32_t		vm_page_bucket_hash;	/* Basic bucket hash */
decl_simple_lock_data(,vm_page_bucket_lock)

vm_page_t
vm_page_lookup_nohint(vm_object_t object, vm_object_offset_t offset);


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
int			page_shift = PAGE_SHIFT;

/*
 *	Resident page structures are initialized from
 *	a template (see vm_page_alloc).
 *
 *	When adding a new field to the virtual memory
 *	object structure, be sure to add initialization
 *	(see vm_page_bootstrap).
 */
struct vm_page	vm_page_template;

/*
 *	Resident pages that represent real memory
 *	are allocated from a free list.
 */
vm_page_t	vm_page_queue_free;
vm_page_t       vm_page_queue_fictitious;
unsigned int	vm_page_free_wanted;
unsigned int	vm_page_free_count;
unsigned int	vm_page_fictitious_count;

unsigned int	vm_page_free_count_minimum;	/* debugging */

/*
 *	Occasionally, the virtual memory system uses
 *	resident page structures that do not refer to
 *	real pages, for example to leave a page with
 *	important state information in the VP table.
 *
 *	These page structures are allocated the way
 *	most other kernel structures are.
 */
zone_t	vm_page_zone;
decl_mutex_data(,vm_page_alloc_lock)
unsigned int io_throttle_zero_fill;

/*
 *	Fictitious pages don't have a physical address,
 *	but we must initialize phys_page to something.
 *	For debugging, this should be a strange value
 *	that the pmap module can recognize in assertions.
 */
vm_offset_t vm_page_fictitious_addr = (vm_offset_t) -1;

/*
 *	Resident page structures are also chained on
 *	queues that are used by the page replacement
 *	system (pageout daemon).  These queues are
 *	defined here, but are shared by the pageout
 *	module.  The inactive queue is broken into 
 *	inactive and zf for convenience as the 
 *	pageout daemon often assignes a higher 
 *	affinity to zf pages
 */
queue_head_t	vm_page_queue_active;
queue_head_t	vm_page_queue_inactive;
unsigned int	vm_page_active_count;
unsigned int	vm_page_inactive_count;
unsigned int	vm_page_wire_count;
unsigned int	vm_page_gobble_count = 0;
unsigned int	vm_page_wire_count_warning = 0;
unsigned int	vm_page_gobble_count_warning = 0;

unsigned int	vm_page_purgeable_count = 0; /* # of pages purgeable now */
uint64_t	vm_page_purged_count = 0;    /* total count of purged pages */

/*
 *	Several page replacement parameters are also
 *	shared with this module, so that page allocation
 *	(done here in vm_page_alloc) can trigger the
 *	pageout daemon.
 */
unsigned int	vm_page_free_target = 0;
unsigned int	vm_page_free_min = 0;
unsigned int	vm_page_inactive_target = 0;
unsigned int	vm_page_free_reserved = 0;
unsigned int	vm_page_throttled_count = 0;

/*
 *	The VM system has a couple of heuristics for deciding
 *	that pages are "uninteresting" and should be placed
 *	on the inactive queue as likely candidates for replacement.
 *	These variables let the heuristics be controlled at run-time
 *	to make experimentation easier.
 */

boolean_t vm_page_deactivate_hint = TRUE;

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
	page_mask = page_size - 1;

	if ((page_mask & page_size) != 0)
		panic("vm_set_page_size: page size not a power of two");

	for (page_shift = 0; ; page_shift++)
		if ((1U << page_shift) == page_size)
			break;
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
	register vm_page_t	m;
	unsigned int		i;
	unsigned int		log1;
	unsigned int		log2;
	unsigned int		size;

	/*
	 *	Initialize the vm_page template.
	 */

	m = &vm_page_template;
	m->object = VM_OBJECT_NULL;		/* reset later */
	m->offset = (vm_object_offset_t) -1;	/* reset later */
	m->wire_count = 0;

	m->pageq.next = NULL;
	m->pageq.prev = NULL;
	m->listq.next = NULL;
	m->listq.prev = NULL;

	m->inactive = FALSE;
	m->active = FALSE;
	m->laundry = FALSE;
	m->free = FALSE;
	m->no_isync = TRUE;
	m->reference = FALSE;
	m->pageout = FALSE;
	m->dump_cleaning = FALSE;
	m->list_req_pending = FALSE;

	m->busy = TRUE;
	m->wanted = FALSE;
	m->tabled = FALSE;
	m->fictitious = FALSE;
	m->private = FALSE;
	m->absent = FALSE;
	m->error = FALSE;
	m->dirty = FALSE;
	m->cleaning = FALSE;
	m->precious = FALSE;
	m->clustered = FALSE;
	m->lock_supplied = FALSE;
	m->unusual = FALSE;
	m->restart = FALSE;
	m->zero_fill = FALSE;
	m->encrypted = FALSE;

	m->phys_page = 0;		/* reset later */

	m->page_lock = VM_PROT_NONE;
	m->unlock_request = VM_PROT_NONE;
	m->page_error = KERN_SUCCESS;

	/*
	 *	Initialize the page queues.
	 */

	mutex_init(&vm_page_queue_free_lock, 0);
	mutex_init(&vm_page_queue_lock, 0);

	vm_page_queue_free = VM_PAGE_NULL;
	vm_page_queue_fictitious = VM_PAGE_NULL;
	queue_init(&vm_page_queue_active);
	queue_init(&vm_page_queue_inactive);
	queue_init(&vm_page_queue_zf);

	vm_page_free_wanted = 0;

	/*
	 *	Steal memory for the map and zone subsystems.
	 */

	vm_map_steal_memory();
	zone_steal_memory();

	/*
	 *	Allocate (and initialize) the virtual-to-physical
	 *	table hash buckets.
	 *
	 *	The number of buckets should be a power of two to
	 *	get a good hash function.  The following computation
	 *	chooses the first power of two that is greater
	 *	than the number of physical pages in the system.
	 */

	simple_lock_init(&vm_page_bucket_lock, 0);
	
	if (vm_page_bucket_count == 0) {
		unsigned int npages = pmap_free_pages();

		vm_page_bucket_count = 1;
		while (vm_page_bucket_count < npages)
			vm_page_bucket_count <<= 1;
	}

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

	vm_page_buckets = (vm_page_bucket_t *)
		pmap_steal_memory(vm_page_bucket_count *
				  sizeof(vm_page_bucket_t));

	for (i = 0; i < vm_page_bucket_count; i++) {
		register vm_page_bucket_t *bucket = &vm_page_buckets[i];

		bucket->pages = VM_PAGE_NULL;
#if     MACH_PAGE_HASH_STATS
		bucket->cur_count = 0;
		bucket->hi_count = 0;
#endif /* MACH_PAGE_HASH_STATS */
	}

	/*
	 *	Machine-dependent code allocates the resident page table.
	 *	It uses vm_page_init to initialize the page frames.
	 *	The code also returns to us the virtual space available
	 *	to the kernel.  We don't trust the pmap module
	 *	to get the alignment right.
	 */

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
	vm_page_wire_count = atop_64(max_mem) - vm_page_free_count;	/* initial value */

	printf("vm_page_bootstrap: %d free pages\n", vm_page_free_count);
	vm_page_free_count_minimum = vm_page_free_count;

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

	kprintf("pmap_steal_memory: %08X - %08X; size=%08X\n", addr, virtual_space_start, size);	/* (TEST/DEBUG) */

	/*
	 *	Allocate and map physical pages to back new virtual pages.
	 */

	for (vaddr = round_page(addr);
	     vaddr < addr + size;
	     vaddr += PAGE_SIZE) {
		if (!pmap_next_page(&phys_page))
			panic("pmap_steal_memory");

		/*
		 *	XXX Logically, these mappings should be wired,
		 *	but some pmap modules barf if they are.
		 */

		pmap_enter(kernel_pmap, vaddr, phys_page,
			   VM_PROT_READ|VM_PROT_WRITE, 
				VM_WIMG_USE_DEFAULT, FALSE);
		/*
		 * Account for newly stolen memory
		 */
		vm_page_wire_count++;

	}

	return (void *) addr;
}

void
pmap_startup(
	vm_offset_t *startp,
	vm_offset_t *endp)
{
	unsigned int i, npages, pages_initialized, fill, fillval;
	vm_page_t	pages;
	ppnum_t		phys_page;
	addr64_t	tmpaddr;

	/*
	 *	We calculate how many page frames we will have
	 *	and then allocate the page structures in one chunk.
	 */

	tmpaddr = (addr64_t)pmap_free_pages() * (addr64_t)PAGE_SIZE;	/* Get the amount of memory left */
	tmpaddr = tmpaddr + (addr64_t)(round_page_32(virtual_space_start) - virtual_space_start);	/* Account for any slop */
	npages = (unsigned int)(tmpaddr / (addr64_t)(PAGE_SIZE + sizeof(*pages)));	/* Figure size of all vm_page_ts, including enough to hold the vm_page_ts */

	pages = (vm_page_t) pmap_steal_memory(npages * sizeof *pages);

	/*
	 *	Initialize the page frames.
	 */

	for (i = 0, pages_initialized = 0; i < npages; i++) {
		if (!pmap_next_page(&phys_page))
			break;

		vm_page_init(&pages[i], phys_page);
		vm_page_pages++;
		pages_initialized++;
	}

	/*
	 * Release pages in reverse order so that physical pages
	 * initially get allocated in ascending addresses. This keeps
	 * the devices (which must address physical memory) happy if
	 * they require several consecutive pages.
	 */

/*
 *		Check if we want to initialize pages to a known value
 */
	
	fill = 0;													/* Assume no fill */
	if (PE_parse_boot_arg("fill", &fillval)) fill = 1;			/* Set fill */
	
	for (i = pages_initialized; i > 0; i--) {
		if(fill) fillPage(pages[i - 1].phys_page, fillval);		/* Fill the page with a know value if requested at boot */			
		vm_page_release(&pages[i - 1]);
	}

#if 0
	{
		vm_page_t xx, xxo, xxl;
		int j, k, l;
	
		j = 0;													/* (BRINGUP) */
		xxl = 0;
		
		for(xx = vm_page_queue_free; xx; xxl = xx, xx = xx->pageq.next) {	/* (BRINGUP) */
			j++;												/* (BRINGUP) */
			if(j > vm_page_free_count) {						/* (BRINGUP) */
				panic("pmap_startup: too many pages, xx = %08X, xxl = %08X\n", xx, xxl);
			}
			
			l = vm_page_free_count - j;							/* (BRINGUP) */
			k = 0;												/* (BRINGUP) */
			
			if(((j - 1) & 0xFFFF) == 0) kprintf("checking number %d of %d\n", j, vm_page_free_count);

			for(xxo = xx->pageq.next; xxo; xxo = xxo->pageq.next) {	/* (BRINGUP) */
				k++;
				if(k > l) panic("pmap_startup: too many in secondary check %d %d\n", k, l);
				if((xx->phys_page & 0xFFFFFFFF) == (xxo->phys_page & 0xFFFFFFFF)) {	/* (BRINGUP) */
					panic("pmap_startup: duplicate physaddr, xx = %08X, xxo = %08X\n", xx, xxo);
				}
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

	virtual_space_start = round_page_32(virtual_space_start);

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
	vm_page_zone = zinit((vm_size_t) sizeof(struct vm_page),
			     0, PAGE_SIZE, "vm pages");

#if	ZONE_DEBUG
	zone_debug_disable(vm_page_zone);
#endif	/* ZONE_DEBUG */

	zone_change(vm_page_zone, Z_EXPAND, FALSE);
	zone_change(vm_page_zone, Z_EXHAUST, TRUE);
	zone_change(vm_page_zone, Z_FOREIGN, TRUE);

        /*
         * Adjust zone statistics to account for the real pages allocated
         * in vm_page_create(). [Q: is this really what we want?]
         */
        vm_page_zone->count += vm_page_pages;
        vm_page_zone->cur_size += vm_page_pages * vm_page_zone->elem_size;

	mutex_init(&vm_page_alloc_lock, 0);
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
		while ((m = (vm_page_t) vm_page_grab_fictitious())
			== VM_PAGE_NULL)
			vm_page_more_fictitious();

		vm_page_init(m, phys_page);
		vm_page_pages++;
		vm_page_release(m);
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
	( (natural_t)((uint32_t)object * vm_page_bucket_hash) + ((uint32_t)atop_64(offset) ^ vm_page_bucket_hash))\
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
	register vm_page_t		mem,
	register vm_object_t		object,
	register vm_object_offset_t	offset)
{
	register vm_page_bucket_t *bucket;

        XPR(XPR_VM_PAGE,
                "vm_page_insert, object 0x%X offset 0x%X page 0x%X\n",
                (integer_t)object, (integer_t)offset, (integer_t)mem, 0,0);

	VM_PAGE_CHECK(mem);
#if DEBUG
	_mutex_assert(&object->Lock, MA_OWNED);

	if (mem->tabled || mem->object != VM_OBJECT_NULL)
		panic("vm_page_insert: page %p for (obj=%p,off=0x%llx) "
		      "already in (obj=%p,off=0x%llx)",
		      mem, object, offset, mem->object, mem->offset);
#endif
	assert(!object->internal || offset < object->size);

	/* only insert "pageout" pages into "pageout" objects,
	 * and normal pages into normal objects */
	assert(object->pageout == mem->pageout);

	assert(vm_page_lookup(object, offset) == VM_PAGE_NULL);

	/*
	 *	Record the object/offset pair in this page
	 */

	mem->object = object;
	mem->offset = offset;

	/*
	 *	Insert it into the object_object/offset hash table
	 */

	bucket = &vm_page_buckets[vm_page_hash(object, offset)];
	simple_lock(&vm_page_bucket_lock);
	mem->next = bucket->pages;
	bucket->pages = mem;
#if     MACH_PAGE_HASH_STATS
	if (++bucket->cur_count > bucket->hi_count)
		bucket->hi_count = bucket->cur_count;
#endif /* MACH_PAGE_HASH_STATS */
	simple_unlock(&vm_page_bucket_lock);

	/*
	 *	Now link into the object's list of backed pages.
	 */

	VM_PAGE_INSERT(mem, object);
	mem->tabled = TRUE;

	/*
	 *	Show that the object has one more resident page.
	 */

	object->resident_page_count++;

	if (object->purgable == VM_OBJECT_PURGABLE_VOLATILE ||
	    object->purgable == VM_OBJECT_PURGABLE_EMPTY) {
		vm_page_lock_queues();
		vm_page_purgeable_count++;
		vm_page_unlock_queues();
	}
}

/*
 *	vm_page_replace:
 *
 *	Exactly like vm_page_insert, except that we first
 *	remove any existing page at the given offset in object.
 *
 *	The object and page queues must be locked.
 */

void
vm_page_replace(
	register vm_page_t		mem,
	register vm_object_t		object,
	register vm_object_offset_t	offset)
{
	register vm_page_bucket_t *bucket;

	VM_PAGE_CHECK(mem);
#if DEBUG
	_mutex_assert(&object->Lock, MA_OWNED);
	_mutex_assert(&vm_page_queue_lock, MA_OWNED);

	if (mem->tabled || mem->object != VM_OBJECT_NULL)
		panic("vm_page_replace: page %p for (obj=%p,off=0x%llx) "
		      "already in (obj=%p,off=0x%llx)",
		      mem, object, offset, mem->object, mem->offset);
#endif
	/*
	 *	Record the object/offset pair in this page
	 */

	mem->object = object;
	mem->offset = offset;

	/*
	 *	Insert it into the object_object/offset hash table,
	 *	replacing any page that might have been there.
	 */

	bucket = &vm_page_buckets[vm_page_hash(object, offset)];
	simple_lock(&vm_page_bucket_lock);
	if (bucket->pages) {
		vm_page_t *mp = &bucket->pages;
		register vm_page_t m = *mp;
		do {
			if (m->object == object && m->offset == offset) {
				/*
				 * Remove page from bucket and from object,
				 * and return it to the free list.
				 */
				*mp = m->next;
				VM_PAGE_REMOVE(m);
				m->tabled = FALSE;
				m->object = VM_OBJECT_NULL;
				m->offset = (vm_object_offset_t) -1;
				object->resident_page_count--;

				if (object->purgable == VM_OBJECT_PURGABLE_VOLATILE ||
				    object->purgable == VM_OBJECT_PURGABLE_EMPTY) {
					assert(vm_page_purgeable_count > 0);
					vm_page_purgeable_count--;
				}
					
				/*
				 * Return page to the free list.
				 * Note the page is not tabled now, so this
				 * won't self-deadlock on the bucket lock.
				 */

				vm_page_free(m);
				break;
			}
			mp = &m->next;
		} while ((m = *mp));
		mem->next = bucket->pages;
	} else {
		mem->next = VM_PAGE_NULL;
	}
	bucket->pages = mem;
	simple_unlock(&vm_page_bucket_lock);

	/*
	 *	Now link into the object's list of backed pages.
	 */

	VM_PAGE_INSERT(mem, object);
	mem->tabled = TRUE;

	/*
	 *	And show that the object has one more resident
	 *	page.
	 */

	object->resident_page_count++;

	if (object->purgable == VM_OBJECT_PURGABLE_VOLATILE ||
	    object->purgable == VM_OBJECT_PURGABLE_EMPTY) {
		vm_page_purgeable_count++;
	}
}

/*
 *	vm_page_remove:		[ internal use only ]
 *
 *	Removes the given mem entry from the object/offset-page
 *	table and the object page list.
 *
 *	The object and page queues must be locked.
 */

void
vm_page_remove(
	register vm_page_t	mem)
{
	register vm_page_bucket_t	*bucket;
	register vm_page_t	this;

        XPR(XPR_VM_PAGE,
                "vm_page_remove, object 0x%X offset 0x%X page 0x%X\n",
                (integer_t)mem->object, (integer_t)mem->offset, 
		(integer_t)mem, 0,0);
#if DEBUG
	_mutex_assert(&vm_page_queue_lock, MA_OWNED);
	_mutex_assert(&mem->object->Lock, MA_OWNED);
#endif
	assert(mem->tabled);
	assert(!mem->cleaning);
	VM_PAGE_CHECK(mem);


	/*
	 *	Remove from the object_object/offset hash table
	 */

	bucket = &vm_page_buckets[vm_page_hash(mem->object, mem->offset)];
	simple_lock(&vm_page_bucket_lock);
	if ((this = bucket->pages) == mem) {
		/* optimize for common case */

		bucket->pages = mem->next;
	} else {
		register vm_page_t	*prev;

		for (prev = &this->next;
		     (this = *prev) != mem;
		     prev = &this->next)
			continue;
		*prev = this->next;
	}
#if     MACH_PAGE_HASH_STATS
	bucket->cur_count--;
#endif /* MACH_PAGE_HASH_STATS */
	simple_unlock(&vm_page_bucket_lock);

	/*
	 *	Now remove from the object's list of backed pages.
	 */

	VM_PAGE_REMOVE(mem);

	/*
	 *	And show that the object has one fewer resident
	 *	page.
	 */

	mem->object->resident_page_count--;

	if (mem->object->purgable == VM_OBJECT_PURGABLE_VOLATILE ||
	    mem->object->purgable == VM_OBJECT_PURGABLE_EMPTY) {
		assert(vm_page_purgeable_count > 0);
		vm_page_purgeable_count--;
	}

	mem->tabled = FALSE;
	mem->object = VM_OBJECT_NULL;
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

unsigned long vm_page_lookup_hint = 0;
unsigned long vm_page_lookup_hint_next = 0;
unsigned long vm_page_lookup_hint_prev = 0;
unsigned long vm_page_lookup_hint_miss = 0;

vm_page_t
vm_page_lookup(
	register vm_object_t		object,
	register vm_object_offset_t	offset)
{
	register vm_page_t	mem;
	register vm_page_bucket_t *bucket;
	queue_entry_t		qe;
#if 0
	_mutex_assert(&object->Lock, MA_OWNED);
#endif

	mem = object->memq_hint;
	if (mem != VM_PAGE_NULL) {
		assert(mem->object == object);
		if (mem->offset == offset) {
			vm_page_lookup_hint++;
			return mem;
		}
		qe = queue_next(&mem->listq);
		if (! queue_end(&object->memq, qe)) {
			vm_page_t	next_page;

			next_page = (vm_page_t) qe;
			assert(next_page->object == object);
			if (next_page->offset == offset) {
				vm_page_lookup_hint_next++;
				object->memq_hint = next_page; /* new hint */
				return next_page;
			}
		}
		qe = queue_prev(&mem->listq);
		if (! queue_end(&object->memq, qe)) {
			vm_page_t prev_page;

			prev_page = (vm_page_t) qe;
			assert(prev_page->object == object);
			if (prev_page->offset == offset) {
				vm_page_lookup_hint_prev++;
				object->memq_hint = prev_page; /* new hint */
				return prev_page;
			}
		}
	}

	/*
	 *	Search the hash table for this object/offset pair
	 */

	bucket = &vm_page_buckets[vm_page_hash(object, offset)];

	simple_lock(&vm_page_bucket_lock);
	for (mem = bucket->pages; mem != VM_PAGE_NULL; mem = mem->next) {
		VM_PAGE_CHECK(mem);
		if ((mem->object == object) && (mem->offset == offset))
			break;
	}
	simple_unlock(&vm_page_bucket_lock);

	if (mem != VM_PAGE_NULL) {
		if (object->memq_hint != VM_PAGE_NULL) {
			vm_page_lookup_hint_miss++;
		}
		assert(mem->object == object);
		object->memq_hint = mem;
	}

	return(mem);
}


vm_page_t
vm_page_lookup_nohint(
	vm_object_t		object,
	vm_object_offset_t	offset)
{
	register vm_page_t	mem;
	register vm_page_bucket_t *bucket;

#if 0
	_mutex_assert(&object->Lock, MA_OWNED);
#endif
	/*
	 *	Search the hash table for this object/offset pair
	 */

	bucket = &vm_page_buckets[vm_page_hash(object, offset)];

	simple_lock(&vm_page_bucket_lock);
	for (mem = bucket->pages; mem != VM_PAGE_NULL; mem = mem->next) {
		VM_PAGE_CHECK(mem);
		if ((mem->object == object) && (mem->offset == offset))
			break;
	}
	simple_unlock(&vm_page_bucket_lock);

	return(mem);
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
	register vm_page_t		mem,
	register vm_object_t		new_object,
	vm_object_offset_t		new_offset)
{
	assert(mem->object != new_object);
	/*
	 * ENCRYPTED SWAP:
	 * The encryption key is based on the page's memory object
	 * (aka "pager") and paging offset.  Moving the page to
	 * another VM object changes its "pager" and "paging_offset"
	 * so it has to be decrypted first.
	 */
	if (mem->encrypted) {
		panic("vm_page_rename: page %p is encrypted\n", mem);
	}
	/*
	 *	Changes to mem->object require the page lock because
	 *	the pageout daemon uses that lock to get the object.
	 */

        XPR(XPR_VM_PAGE,
                "vm_page_rename, new object 0x%X, offset 0x%X page 0x%X\n",
                (integer_t)new_object, (integer_t)new_offset, 
		(integer_t)mem, 0,0);

	vm_page_lock_queues();
    	vm_page_remove(mem);
	vm_page_insert(mem, new_object, new_offset);
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
	ppnum_t	phys_page)
{
	assert(phys_page);
	*mem = vm_page_template;
	mem->phys_page = phys_page;
}

/*
 *	vm_page_grab_fictitious:
 *
 *	Remove a fictitious page from the free list.
 *	Returns VM_PAGE_NULL if there are no free pages.
 */
int	c_vm_page_grab_fictitious = 0;
int	c_vm_page_release_fictitious = 0;
int	c_vm_page_more_fictitious = 0;

vm_page_t
vm_page_grab_fictitious(void)
{
	register vm_page_t m;

	m = (vm_page_t)zget(vm_page_zone);
	if (m) {
		vm_page_init(m, vm_page_fictitious_addr);
		m->fictitious = TRUE;
	}

	c_vm_page_grab_fictitious++;
	return m;
}

/*
 *	vm_page_release_fictitious:
 *
 *	Release a fictitious page to the free list.
 */

void
vm_page_release_fictitious(
	register vm_page_t m)
{
	assert(!m->free);
	assert(m->busy);
	assert(m->fictitious);
	assert(m->phys_page == vm_page_fictitious_addr);

	c_vm_page_release_fictitious++;
#if DEBUG
	if (m->free)
		panic("vm_page_release_fictitious");
#endif
	m->free = TRUE;
	zfree(vm_page_zone, m);
}

/*
 *	vm_page_more_fictitious:
 *
 *	Add more fictitious pages to the free list.
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
 *	   zone. This also allows us to initialize the vm_page_t's
 *	   on the way into the zone, so that zget() always returns
 *	   an initialized structure. The zone free element pointer
 *	   and the free page pointer are both the first item in the
 *	   vm_page_t.
 *	4. By having the pages in the zone pre-initialized, we need
 *	   not keep 2 levels of lists. The garbage collector simply
 *	   scans our list, and reduces physical memory usage as it
 *	   sees fit.
 */

void vm_page_more_fictitious(void)
{
	register vm_page_t m;
	vm_offset_t addr;
	kern_return_t retval;
	int i;

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
	mutex_lock(&vm_page_alloc_lock);
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
		mutex_unlock(&vm_page_alloc_lock);
		return;
	}

	retval = kernel_memory_allocate(zone_map,
					&addr, PAGE_SIZE, VM_PROT_ALL,
					KMA_KOBJECT|KMA_NOPAGEWAIT);
	if (retval != KERN_SUCCESS) { 
		/*
		 * No page was available. Tell the pageout daemon, drop the
		 * lock to give another thread a chance at it, and
		 * wait for the pageout daemon to make progress.
		 */
		mutex_unlock(&vm_page_alloc_lock);
		vm_page_wait(THREAD_UNINT);
		return;
	}
	/*
	 * Initialize as many vm_page_t's as will fit on this page. This
	 * depends on the zone code disturbing ONLY the first item of
	 * each zone element.
	 */
	m = (vm_page_t)addr;
	for (i = PAGE_SIZE/sizeof(struct vm_page); i > 0; i--) {
		vm_page_init(m, vm_page_fictitious_addr);
		m->fictitious = TRUE;
		m++;
	}
	zcram(vm_page_zone, (void *) addr, PAGE_SIZE);
	mutex_unlock(&vm_page_alloc_lock);
}

/*
 *	vm_page_convert:
 *
 *	Attempt to convert a fictitious page into a real page.
 */

boolean_t
vm_page_convert(
	register vm_page_t m)
{
	register vm_page_t real_m;

	assert(m->busy);
	assert(m->fictitious);
	assert(!m->dirty);

	real_m = vm_page_grab();
	if (real_m == VM_PAGE_NULL)
		return FALSE;

	m->phys_page = real_m->phys_page;
	m->fictitious = FALSE;
	m->no_isync = TRUE;

	vm_page_lock_queues();
	if (m->active)
		vm_page_active_count++;
	else if (m->inactive)
		vm_page_inactive_count++;
	vm_page_unlock_queues();

	real_m->phys_page = vm_page_fictitious_addr;
	real_m->fictitious = TRUE;

	vm_page_release_fictitious(real_m);
	return TRUE;
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
	return( vm_page_free_count < vm_page_free_reserved );
}

/*
 *	vm_page_grab:
 *
 *	Remove a page from the free list.
 *	Returns VM_PAGE_NULL if the free list is too small.
 */

unsigned long	vm_page_grab_count = 0;	/* measure demand */

vm_page_t
vm_page_grab(void)
{
	register vm_page_t	mem;

	mutex_lock(&vm_page_queue_free_lock);
	vm_page_grab_count++;

	/*
	 *	Optionally produce warnings if the wire or gobble
	 *	counts exceed some threshold.
	 */
	if (vm_page_wire_count_warning > 0
	    && vm_page_wire_count >= vm_page_wire_count_warning) {
		printf("mk: vm_page_grab(): high wired page count of %d\n",
			vm_page_wire_count);
		assert(vm_page_wire_count < vm_page_wire_count_warning);
	}
	if (vm_page_gobble_count_warning > 0
	    && vm_page_gobble_count >= vm_page_gobble_count_warning) {
		printf("mk: vm_page_grab(): high gobbled page count of %d\n",
			vm_page_gobble_count);
		assert(vm_page_gobble_count < vm_page_gobble_count_warning);
	}

	/*
	 *	Only let privileged threads (involved in pageout)
	 *	dip into the reserved pool.
	 */

	if ((vm_page_free_count < vm_page_free_reserved) &&
	    !(current_thread()->options & TH_OPT_VMPRIV)) {
		mutex_unlock(&vm_page_queue_free_lock);
		mem = VM_PAGE_NULL;
		goto wakeup_pageout;
	}

	while (vm_page_queue_free == VM_PAGE_NULL) {
		mutex_unlock(&vm_page_queue_free_lock);
		VM_PAGE_WAIT();
		mutex_lock(&vm_page_queue_free_lock);
	}

	if (--vm_page_free_count < vm_page_free_count_minimum)
		vm_page_free_count_minimum = vm_page_free_count;
	mem = vm_page_queue_free;
	vm_page_queue_free = (vm_page_t) mem->pageq.next;
	mem->pageq.next = NULL;
	mem->pageq.prev = NULL;
	assert(mem->listq.next == NULL && mem->listq.prev == NULL);
	assert(mem->tabled == FALSE);
	assert(mem->object == VM_OBJECT_NULL);
	assert(!mem->laundry);
	mem->free = FALSE;
	mem->no_isync = TRUE;
	mutex_unlock(&vm_page_queue_free_lock);

	assert(pmap_verify_free(mem->phys_page));

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

wakeup_pageout:
	if ((vm_page_free_count < vm_page_free_min) ||
	    ((vm_page_free_count < vm_page_free_target) &&
	     (vm_page_inactive_count < vm_page_inactive_target)))
		thread_wakeup((event_t) &vm_page_free_wanted);

//	dbgLog(mem->phys_page, vm_page_free_count, vm_page_wire_count, 4);	/* (TEST/DEBUG) */

	return mem;
}

/*
 *	vm_page_release:
 *
 *	Return a page to the free list.
 */

void
vm_page_release(
	register vm_page_t	mem)
{

#if 0
	unsigned int pindex;
	phys_entry *physent;

	physent = mapping_phys_lookup(mem->phys_page, &pindex);		/* (BRINGUP) */
	if(physent->ppLink & ppN) {											/* (BRINGUP) */
		panic("vm_page_release: already released - %08X %08X\n", mem, mem->phys_page);
	}
	physent->ppLink = physent->ppLink | ppN;							/* (BRINGUP) */
#endif
	assert(!mem->private && !mem->fictitious);

//	dbgLog(mem->phys_page, vm_page_free_count, vm_page_wire_count, 5);	/* (TEST/DEBUG) */

	mutex_lock(&vm_page_queue_free_lock);
#if DEBUG
	if (mem->free)
		panic("vm_page_release");
#endif
	mem->free = TRUE;
	assert(!mem->laundry);
	assert(mem->object == VM_OBJECT_NULL);
	assert(mem->pageq.next == NULL &&
	       mem->pageq.prev == NULL);
	mem->pageq.next = (queue_entry_t) vm_page_queue_free;
	vm_page_queue_free = mem;
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

	if ((vm_page_free_wanted > 0) &&
	    (vm_page_free_count >= vm_page_free_reserved)) {
		vm_page_free_wanted--;
		thread_wakeup_one((event_t) &vm_page_free_count);
	}

	mutex_unlock(&vm_page_queue_free_lock);
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

	mutex_lock(&vm_page_queue_free_lock);
	if (vm_page_free_count < vm_page_free_target) {
		if (vm_page_free_wanted++ == 0)
		        need_wakeup = 1;
		wait_result = assert_wait((event_t)&vm_page_free_count, interruptible);
		mutex_unlock(&vm_page_queue_free_lock);
		counter(c_vm_page_wait_block++);

		if (need_wakeup)
			thread_wakeup((event_t)&vm_page_free_wanted);

		if (wait_result == THREAD_WAITING)
			wait_result = thread_block(THREAD_CONTINUE_NULL);

		return(wait_result == THREAD_AWAKENED);
	} else {
		mutex_unlock(&vm_page_queue_free_lock);
		return TRUE;
	}
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
	register vm_page_t	mem;

#if DEBUG
	_mutex_assert(&object->Lock, MA_OWNED);
#endif
	mem = vm_page_grab();
	if (mem == VM_PAGE_NULL)
		return VM_PAGE_NULL;

	vm_page_insert(mem, object, offset);

	return(mem);
}

counter(unsigned int c_laundry_pages_freed = 0;)

int vm_pagein_cluster_unused = 0;
boolean_t	vm_page_free_verify = TRUE;
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
	register vm_page_t	mem)
{
	vm_object_t	object = mem->object;

	assert(!mem->free);
	assert(!mem->cleaning);
	assert(!mem->pageout);
	if (vm_page_free_verify && !mem->fictitious && !mem->private) {
		assert(pmap_verify_free(mem->phys_page));
	}

#if DEBUG
	if (mem->object)
	        _mutex_assert(&mem->object->Lock, MA_OWNED);
	_mutex_assert(&vm_page_queue_lock, MA_OWNED);

	if (mem->free)
	       panic("vm_page_free: freeing page on free list\n");
#endif
	if (mem->tabled)
		vm_page_remove(mem);	/* clears tabled, object, offset */
	VM_PAGE_QUEUES_REMOVE(mem);	/* clears active or inactive */

	if (mem->clustered) {
		mem->clustered = FALSE;
		vm_pagein_cluster_unused++;
	}

	if (mem->wire_count) {
		if (!mem->private && !mem->fictitious)
			vm_page_wire_count--;
		mem->wire_count = 0;
		assert(!mem->gobbled);
	} else if (mem->gobbled) {
		if (!mem->private && !mem->fictitious)
			vm_page_wire_count--;
		vm_page_gobble_count--;
	}
	mem->gobbled = FALSE;

	if (mem->laundry) {
		vm_pageout_throttle_up(mem);
		counter(++c_laundry_pages_freed);
	}

	PAGE_WAKEUP(mem);	/* clears wanted */

	if (mem->absent)
		vm_object_absent_release(object);

	/* Some of these may be unnecessary */
	mem->page_lock = 0;
	mem->unlock_request = 0;
	mem->busy = TRUE;
	mem->absent = FALSE;
	mem->error = FALSE;
	mem->dirty = FALSE;
	mem->precious = FALSE;
	mem->reference = FALSE;
	mem->encrypted = FALSE;

	mem->page_error = KERN_SUCCESS;

	if (mem->private) {
		mem->private = FALSE;
		mem->fictitious = TRUE;
		mem->phys_page = vm_page_fictitious_addr;
	}
	if (mem->fictitious) {
		vm_page_release_fictitious(mem);
	} else {
		/* depends on the queues lock */
		if(mem->zero_fill) {
			vm_zf_count-=1;
			mem->zero_fill = FALSE;
		}
		vm_page_init(mem, mem->phys_page);
		vm_page_release(mem);
	}
}


void
vm_page_free_list(
	register vm_page_t	mem)
{
        register vm_page_t	nxt;
	register vm_page_t      first = NULL;
	register vm_page_t      last = VM_PAGE_NULL;
	register int            pg_count = 0;

#if DEBUG
	_mutex_assert(&vm_page_queue_lock, MA_OWNED);
#endif
	while (mem) {
#if DEBUG
		if (mem->tabled || mem->object)
		        panic("vm_page_free_list: freeing tabled page\n");
		if (mem->inactive || mem->active || mem->free)
		        panic("vm_page_free_list: freeing page on list\n");
#endif
		assert(mem->pageq.prev == NULL);
		nxt = (vm_page_t)(mem->pageq.next);

	        if (mem->clustered)
			vm_pagein_cluster_unused++;

		if (mem->laundry) {
			vm_pageout_throttle_up(mem);
			counter(++c_laundry_pages_freed);
		}
		mem->busy = TRUE;

		PAGE_WAKEUP(mem);	/* clears wanted */

		if (mem->private)
			mem->fictitious = TRUE;

		if (!mem->fictitious) {
		        /* depends on the queues lock */
		        if (mem->zero_fill)
			        vm_zf_count -= 1;
			assert(!mem->laundry);
			vm_page_init(mem, mem->phys_page);

			mem->free = TRUE;

			if (first == NULL)
			        last = mem;
			mem->pageq.next = (queue_t) first;
			first = mem;

			pg_count++;
		} else {
			mem->phys_page = vm_page_fictitious_addr;
		        vm_page_release_fictitious(mem);
		}
		mem = nxt;
	}
	if (first) {
	      
	        mutex_lock(&vm_page_queue_free_lock);

		last->pageq.next = (queue_entry_t) vm_page_queue_free;
		vm_page_queue_free = first;

		vm_page_free_count += pg_count;

		if ((vm_page_free_wanted > 0) &&
		    (vm_page_free_count >= vm_page_free_reserved)) {
		        unsigned int  available_pages;

			if (vm_page_free_count >= vm_page_free_reserved) {
				available_pages = (vm_page_free_count
						   - vm_page_free_reserved);
			} else {
				available_pages = 0;
			}

			if (available_pages >= vm_page_free_wanted) {
			        vm_page_free_wanted = 0;
				thread_wakeup((event_t) &vm_page_free_count);
			} else {
			        while (available_pages--) {
				        vm_page_free_wanted--;
					thread_wakeup_one((event_t) &vm_page_free_count);
				}
			}
		}
		mutex_unlock(&vm_page_queue_free_lock);
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
	register vm_page_t	mem)
{

//	dbgLog(current_thread(), mem->offset, mem->object, 1);	/* (TEST/DEBUG) */

	VM_PAGE_CHECK(mem);
#if DEBUG
	if (mem->object)
	        _mutex_assert(&mem->object->Lock, MA_OWNED);
	_mutex_assert(&vm_page_queue_lock, MA_OWNED);
#endif
	if (mem->wire_count == 0) {
		VM_PAGE_QUEUES_REMOVE(mem);
		if (!mem->private && !mem->fictitious && !mem->gobbled)
			vm_page_wire_count++;
		if (mem->gobbled)
			vm_page_gobble_count--;
		mem->gobbled = FALSE;
		if(mem->zero_fill) {
			/* depends on the queues lock */
			vm_zf_count-=1;
			mem->zero_fill = FALSE;
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
	mem->wire_count++;
}

/*
 *      vm_page_gobble:
 *
 *      Mark this page as consumed by the vm/ipc/xmm subsystems.
 *
 *      Called only for freshly vm_page_grab()ed pages - w/ nothing locked.
 */
void
vm_page_gobble(
        register vm_page_t      mem)
{
        vm_page_lock_queues();
        VM_PAGE_CHECK(mem);

	assert(!mem->gobbled);
	assert(mem->wire_count == 0);

        if (!mem->gobbled && mem->wire_count == 0) {
                if (!mem->private && !mem->fictitious)
                        vm_page_wire_count++;
        }
	vm_page_gobble_count++;
        mem->gobbled = TRUE;
        vm_page_unlock_queues();
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
	register vm_page_t	mem)
{

//	dbgLog(current_thread(), mem->offset, mem->object, 0);	/* (TEST/DEBUG) */

	VM_PAGE_CHECK(mem);
	assert(mem->wire_count > 0);
#if DEBUG
	if (mem->object)
	        _mutex_assert(&mem->object->Lock, MA_OWNED);
	_mutex_assert(&vm_page_queue_lock, MA_OWNED);
#endif
	if (--mem->wire_count == 0) {
		assert(!mem->private && !mem->fictitious);
		vm_page_wire_count--;
		assert(!mem->laundry);
		assert(mem->object != kernel_object);
		assert(mem->pageq.next == NULL && mem->pageq.prev == NULL);
		queue_enter(&vm_page_queue_active, mem, vm_page_t, pageq);
		vm_page_active_count++;
		mem->active = TRUE;
		mem->reference = TRUE;
	}
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
	register vm_page_t	m)
{
	VM_PAGE_CHECK(m);
	assert(m->object != kernel_object);

//	dbgLog(m->phys_page, vm_page_free_count, vm_page_wire_count, 6);	/* (TEST/DEBUG) */
#if DEBUG
	_mutex_assert(&vm_page_queue_lock, MA_OWNED);
#endif
	/*
	 *	This page is no longer very interesting.  If it was
	 *	interesting (active or inactive/referenced), then we
	 *	clear the reference bit and (re)enter it in the
	 *	inactive queue.  Note wired pages should not have
	 *	their reference bit cleared.
	 */
	if (m->gobbled) {		/* can this happen? */
		assert(m->wire_count == 0);
		if (!m->private && !m->fictitious)
			vm_page_wire_count--;
		vm_page_gobble_count--;
		m->gobbled = FALSE;
	}
	if (m->private || (m->wire_count != 0))
		return;
	if (m->active || (m->inactive && m->reference)) {
		if (!m->fictitious && !m->absent)
			pmap_clear_reference(m->phys_page);
		m->reference = FALSE;
		VM_PAGE_QUEUES_REMOVE(m);
	}
	if (m->wire_count == 0 && !m->inactive) {
		m->page_ticket = vm_page_ticket;
		vm_page_ticket_roll++;

		if(vm_page_ticket_roll == VM_PAGE_TICKETS_IN_ROLL) {
			vm_page_ticket_roll = 0;
			if(vm_page_ticket == VM_PAGE_TICKET_ROLL_IDS)
				vm_page_ticket= 0;
			else
				vm_page_ticket++;
		}
		
		assert(!m->laundry);
		assert(m->pageq.next == NULL && m->pageq.prev == NULL);
		if(m->zero_fill) {
			queue_enter(&vm_page_queue_zf, m, vm_page_t, pageq);
		} else {
			queue_enter(&vm_page_queue_inactive,
							m, vm_page_t, pageq);
		}

		m->inactive = TRUE;
		if (!m->fictitious)
			vm_page_inactive_count++;
	}
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
	register vm_page_t	m)
{
	VM_PAGE_CHECK(m);
	assert(m->object != kernel_object);
#if DEBUG
	_mutex_assert(&vm_page_queue_lock, MA_OWNED);
#endif
	if (m->gobbled) {
		assert(m->wire_count == 0);
		if (!m->private && !m->fictitious)
			vm_page_wire_count--;
		vm_page_gobble_count--;
		m->gobbled = FALSE;
	}
	if (m->private)
		return;

	if (m->inactive) {
		assert(!m->laundry);
		if (m->zero_fill) {
			queue_remove(&vm_page_queue_zf, m, vm_page_t, pageq);
		} else {
			queue_remove(&vm_page_queue_inactive, 
						m, vm_page_t, pageq);
		}
		m->pageq.next = NULL;
		m->pageq.prev = NULL;
		if (!m->fictitious)
			vm_page_inactive_count--;
		m->inactive = FALSE;
	}
	if (m->wire_count == 0) {
#if DEBUG
		if (m->active)
			panic("vm_page_activate: already active");
#endif
		assert(!m->laundry);
		assert(m->pageq.next == NULL && m->pageq.prev == NULL);
		queue_enter(&vm_page_queue_active, m, vm_page_t, pageq);
		m->active = TRUE;
		m->reference = TRUE;
		if (!m->fictitious)
			vm_page_active_count++;
	}
}

/*
 *	vm_page_part_zero_fill:
 *
 *	Zero-fill a part of the page.
 */
void
vm_page_part_zero_fill(
	vm_page_t	m,
	vm_offset_t	m_pa,
	vm_size_t	len)
{
	vm_page_t	tmp;

	VM_PAGE_CHECK(m);
#ifdef PMAP_ZERO_PART_PAGE_IMPLEMENTED
	pmap_zero_part_page(m->phys_page, m_pa, len);
#else
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
	vm_page_lock_queues();
	vm_page_free(tmp); 
	vm_page_unlock_queues();
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
                (integer_t)m->object, (integer_t)m->offset, (integer_t)m, 0,0);

	VM_PAGE_CHECK(m);

//	dbgTrace(0xAEAEAEAE, m->phys_page, 0);		/* (BRINGUP) */
	pmap_zero_page(m->phys_page);
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
	VM_PAGE_CHECK(src_m);
	VM_PAGE_CHECK(dst_m);

	pmap_copy_part_page(src_m->phys_page, src_pa,
			dst_m->phys_page, dst_pa, len);
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

void
vm_page_copy(
	vm_page_t	src_m,
	vm_page_t	dest_m)
{
        XPR(XPR_VM_PAGE,
        "vm_page_copy, object 0x%X offset 0x%X to object 0x%X offset 0x%X\n",
        (integer_t)src_m->object, src_m->offset, 
	(integer_t)dest_m->object, dest_m->offset,
	0);

	VM_PAGE_CHECK(src_m);
	VM_PAGE_CHECK(dest_m);

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

	pmap_copy_page(src_m->phys_page, dest_m->phys_page);
}

/*
 *	Currently, this is a primitive allocator that grabs
 *	free pages from the system, sorts them by physical
 *	address, then searches for a region large enough to
 *	satisfy the user's request.
 *
 *	Additional levels of effort:
 *		+ steal clean active/inactive pages
 *		+ force pageouts of dirty pages
 *		+ maintain a map of available physical
 *		memory
 */

#if	MACH_ASSERT
/*
 *	Check that the list of pages is ordered by
 *	ascending physical address and has no holes.
 */
int	vm_page_verify_contiguous(
	vm_page_t	pages,
	unsigned int	npages);

int
vm_page_verify_contiguous(
	vm_page_t	pages,
	unsigned int	npages)
{
	register vm_page_t	m;
	unsigned int		page_count;
	vm_offset_t		prev_addr;

	prev_addr = pages->phys_page;
	page_count = 1;
	for (m = NEXT_PAGE(pages); m != VM_PAGE_NULL; m = NEXT_PAGE(m)) {
		if (m->phys_page != prev_addr + 1) {
			printf("m 0x%x prev_addr 0x%x, current addr 0x%x\n",
			       m, prev_addr, m->phys_page);
			printf("pages 0x%x page_count %d\n", pages, page_count);
			panic("vm_page_verify_contiguous:  not contiguous!");
		}
		prev_addr = m->phys_page;
		++page_count;
	}
	if (page_count != npages) {
		printf("pages 0x%x actual count 0x%x but requested 0x%x\n",
		       pages, page_count, npages);
		panic("vm_page_verify_contiguous:  count error");
	}
	return 1;
}
#endif	/* MACH_ASSERT */


cpm_counter(unsigned int	vpfls_pages_handled = 0;)
cpm_counter(unsigned int	vpfls_head_insertions = 0;)
cpm_counter(unsigned int	vpfls_tail_insertions = 0;)
cpm_counter(unsigned int	vpfls_general_insertions = 0;)
cpm_counter(unsigned int	vpfc_failed = 0;)
cpm_counter(unsigned int	vpfc_satisfied = 0;)

/*
 *	Find a region large enough to contain at least npages
 *	of contiguous physical memory.
 *
 *	Requirements:
 *		- Called while holding vm_page_queue_free_lock.
 *		- Doesn't respect vm_page_free_reserved; caller
 *		must not ask for more pages than are legal to grab.
 *
 *	Returns a pointer to a list of gobbled pages or	VM_PAGE_NULL.
 *
 * Algorithm:
 *	Loop over the free list, extracting one page at a time and
 *	inserting those into a sorted sub-list.  We stop as soon as
 *	there's a contiguous range within the sorted list that can
 *	satisfy the contiguous memory request.  This contiguous sub-
 *	list is chopped out of the sorted sub-list and the remainder
 *	of the sorted sub-list is put back onto the beginning of the
 *	free list.
 */
static vm_page_t
vm_page_find_contiguous(
	unsigned int	contig_pages)
{
	vm_page_t	sort_list;
	vm_page_t	*contfirstprev, contlast;
	vm_page_t	m, m1;
	ppnum_t		prevcontaddr;
	ppnum_t		nextcontaddr;
	unsigned int	npages;

	m = NULL;
#if DEBUG
	_mutex_assert(&vm_page_queue_free_lock, MA_OWNED);
#endif
#if	MACH_ASSERT
	/*
	 *	Verify pages in the free list..
	 */
	npages = 0;
	for (m = vm_page_queue_free; m != VM_PAGE_NULL; m = NEXT_PAGE(m))
		++npages;
	if (npages != vm_page_free_count)
		panic("vm_sort_free_list:  prelim:  npages %u free_count %d",
		      npages, vm_page_free_count);
#endif	/* MACH_ASSERT */

	if (contig_pages == 0 || vm_page_queue_free == VM_PAGE_NULL)
		return VM_PAGE_NULL;

#define PPNUM_PREV(x)	(((x) > 0) ? ((x) - 1) : 0)
#define PPNUM_NEXT(x)	(((x) < PPNUM_MAX) ? ((x) + 1) : PPNUM_MAX)
#define SET_NEXT_PAGE(m,n)	((m)->pageq.next = (struct queue_entry *) (n))

	npages = 1;
	contfirstprev = &sort_list;
	contlast = sort_list = vm_page_queue_free;
	vm_page_queue_free = NEXT_PAGE(sort_list);
	SET_NEXT_PAGE(sort_list, VM_PAGE_NULL);
	prevcontaddr = PPNUM_PREV(sort_list->phys_page);
	nextcontaddr = PPNUM_NEXT(sort_list->phys_page);

 	while (npages < contig_pages && 
	       (m = vm_page_queue_free) != VM_PAGE_NULL)
	{
		cpm_counter(++vpfls_pages_handled);

		/* prepend to existing run? */
		if (m->phys_page == prevcontaddr)
		{
			vm_page_queue_free = NEXT_PAGE(m);
			cpm_counter(++vpfls_head_insertions);
			prevcontaddr = PPNUM_PREV(prevcontaddr);
			SET_NEXT_PAGE(m, *contfirstprev);
			*contfirstprev = m;
			npages++;
			continue; /* no tail expansion check needed */
		} 

		/* append to tail of existing run? */
		else if (m->phys_page == nextcontaddr)
		{
			vm_page_queue_free = NEXT_PAGE(m);
			cpm_counter(++vpfls_tail_insertions);
			nextcontaddr = PPNUM_NEXT(nextcontaddr);
			SET_NEXT_PAGE(m, NEXT_PAGE(contlast));
			SET_NEXT_PAGE(contlast, m);
			contlast = m;
			npages++;
		}

		/* prepend to the very front of sorted list? */
		else if (m->phys_page < sort_list->phys_page)
		{
			vm_page_queue_free = NEXT_PAGE(m);
			cpm_counter(++vpfls_general_insertions);
			prevcontaddr = PPNUM_PREV(m->phys_page);
			nextcontaddr = PPNUM_NEXT(m->phys_page);
			SET_NEXT_PAGE(m, sort_list);
			contfirstprev = &sort_list;
			contlast = sort_list = m;
			npages = 1;
		}

		else /* get to proper place for insertion */
		{
			if (m->phys_page < nextcontaddr)
			{
				prevcontaddr = PPNUM_PREV(sort_list->phys_page);
				nextcontaddr = PPNUM_NEXT(sort_list->phys_page);
				contfirstprev = &sort_list;
				contlast = sort_list;
				npages = 1;
			}
			for (m1 = NEXT_PAGE(contlast);
			     npages < contig_pages &&
			     m1 != VM_PAGE_NULL && m1->phys_page < m->phys_page;
			     m1 = NEXT_PAGE(m1))
			{
				if (m1->phys_page != nextcontaddr) {
					prevcontaddr = PPNUM_PREV(m1->phys_page);
					contfirstprev = NEXT_PAGE_PTR(contlast);
					npages = 1;
				} else {
					npages++;
				}
				nextcontaddr = PPNUM_NEXT(m1->phys_page);
				contlast = m1;
			}

			/*
			 * We may actually already have enough.
			 * This could happen if a previous prepend
			 * joined up two runs to meet our needs.
			 * If so, bail before we take the current
			 * page off the free queue.
			 */
			if (npages == contig_pages)
				break;

			if (m->phys_page != nextcontaddr) 
			{
				contfirstprev = NEXT_PAGE_PTR(contlast);
				prevcontaddr = PPNUM_PREV(m->phys_page);
				nextcontaddr = PPNUM_NEXT(m->phys_page);
				npages = 1;
			} else {
				nextcontaddr = PPNUM_NEXT(nextcontaddr);
				npages++;
			}
			vm_page_queue_free = NEXT_PAGE(m);
			cpm_counter(++vpfls_general_insertions);
			SET_NEXT_PAGE(m, NEXT_PAGE(contlast));
			SET_NEXT_PAGE(contlast, m);
			contlast = m;
		}
		
		/* See how many pages are now contiguous after the insertion */
		for (m1 = NEXT_PAGE(m);
		     npages < contig_pages &&
		     m1 != VM_PAGE_NULL && m1->phys_page == nextcontaddr;
		     m1 = NEXT_PAGE(m1))
		{
			nextcontaddr = PPNUM_NEXT(nextcontaddr);
			contlast = m1;
			npages++;
		}
	}

	/* how did we do? */
	if (npages == contig_pages)
	{
		cpm_counter(++vpfc_satisfied);

		/* remove the contiguous range from the sorted list */
		m = *contfirstprev;
		*contfirstprev = NEXT_PAGE(contlast);
		SET_NEXT_PAGE(contlast, VM_PAGE_NULL);
		assert(vm_page_verify_contiguous(m, npages));

		/* inline vm_page_gobble() for each returned page */
		for (m1 = m; m1 != VM_PAGE_NULL; m1 = NEXT_PAGE(m1)) {
			assert(m1->free);
			assert(!m1->wanted);
			assert(!m1->laundry);
			m1->free = FALSE;
			m1->no_isync = TRUE;
			m1->gobbled = TRUE;
		}
		vm_page_wire_count += npages;
		vm_page_gobble_count += npages;
		vm_page_free_count -= npages;

		/* stick free list at the tail of the sorted list  */
		while ((m1 = *contfirstprev) != VM_PAGE_NULL)
			contfirstprev = (vm_page_t *)&m1->pageq.next;
		*contfirstprev = vm_page_queue_free;
	}

	vm_page_queue_free = sort_list;
	return m;
}

/*
 *	Allocate a list of contiguous, wired pages.
 */
kern_return_t
cpm_allocate(
	vm_size_t	size,
	vm_page_t	*list,
	boolean_t	wire)
{
	register vm_page_t	m;
	vm_page_t		pages;
	unsigned int		npages;
	unsigned int		vm_pages_available;
	boolean_t		wakeup;

	if (size % page_size != 0)
		return KERN_INVALID_ARGUMENT;

	vm_page_lock_queues();
	mutex_lock(&vm_page_queue_free_lock);

	/*
	 *	Should also take active and inactive pages
	 *	into account...  One day...
	 */
	npages = size / page_size;
	vm_pages_available = vm_page_free_count - vm_page_free_reserved;

	if (npages > vm_pages_available) {
		mutex_unlock(&vm_page_queue_free_lock);
		vm_page_unlock_queues();
		return KERN_RESOURCE_SHORTAGE;
	}

	/*
	 *	Obtain a pointer to a subset of the free
	 *	list large enough to satisfy the request;
	 *	the region will be physically contiguous.
	 */
	pages = vm_page_find_contiguous(npages);

	/* adjust global freelist counts and determine need for wakeups */
	if (vm_page_free_count < vm_page_free_count_minimum)
		vm_page_free_count_minimum = vm_page_free_count;

	wakeup = ((vm_page_free_count < vm_page_free_min) ||
		  ((vm_page_free_count < vm_page_free_target) &&
		   (vm_page_inactive_count < vm_page_inactive_target)));
		
	mutex_unlock(&vm_page_queue_free_lock);

	if (pages == VM_PAGE_NULL) {
		vm_page_unlock_queues();
		return KERN_NO_SPACE;
	}

	/*
	 *	Walk the returned list, wiring the pages.
	 */
	if (wire == TRUE)
		for (m = pages; m != VM_PAGE_NULL; m = NEXT_PAGE(m)) {
			/*
			 *	Essentially inlined vm_page_wire.
			 */
			assert(!m->active);
			assert(!m->inactive);
			assert(!m->private);
			assert(!m->fictitious);
			assert(m->wire_count == 0);
			assert(m->gobbled);
			m->gobbled = FALSE;
			m->wire_count++;
			--vm_page_gobble_count;
		}
	vm_page_unlock_queues();

	if (wakeup)
		thread_wakeup((event_t) &vm_page_free_wanted);

	/*
	 *	The CPM pages should now be available and
	 *	ordered by ascending physical address.
	 */
	assert(vm_page_verify_contiguous(pages, npages));

	*list = pages;
	return KERN_SUCCESS;
}


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

	if (vm_page_bucket_count < count)
		count = vm_page_bucket_count;

	for (i = 0; i < count; i++) {
		vm_page_bucket_t *bucket = &vm_page_buckets[i];
		unsigned int bucket_count = 0;
		vm_page_t m;

		simple_lock(&vm_page_bucket_lock);
		for (m = bucket->pages; m != VM_PAGE_NULL; m = m->next)
			bucket_count++;
		simple_unlock(&vm_page_bucket_lock);

		/* don't touch pageable memory while holding locks */
		info[i].hib_count = bucket_count;
	}

	return vm_page_bucket_count;
}
#endif	/* MACH_VM_DEBUG */

#include <mach_kdb.h>
#if	MACH_KDB

#include <ddb/db_output.h>
#include <vm/vm_print.h>
#define	printf	kdbprintf

/*
 *	Routine:	vm_page_print [exported]
 */
void
vm_page_print(
	db_addr_t	db_addr)
{
	vm_page_t	p;

	p = (vm_page_t) (long) db_addr;

	iprintf("page 0x%x\n", p);

	db_indent += 2;

	iprintf("object=0x%x", p->object);
	printf(", offset=0x%x", p->offset);
	printf(", wire_count=%d", p->wire_count);

	iprintf("%sinactive, %sactive, %sgobbled, %slaundry, %sfree, %sref, %sencrypted\n",
		(p->inactive ? "" : "!"),
		(p->active ? "" : "!"),
		(p->gobbled ? "" : "!"),
		(p->laundry ? "" : "!"),
		(p->free ? "" : "!"),
		(p->reference ? "" : "!"),
		(p->encrypted ? "" : "!"));
	iprintf("%sbusy, %swanted, %stabled, %sfictitious, %sprivate, %sprecious\n",
		(p->busy ? "" : "!"),
		(p->wanted ? "" : "!"),
		(p->tabled ? "" : "!"),
		(p->fictitious ? "" : "!"),
		(p->private ? "" : "!"),
		(p->precious ? "" : "!"));
	iprintf("%sabsent, %serror, %sdirty, %scleaning, %spageout, %sclustered\n",
		(p->absent ? "" : "!"),
		(p->error ? "" : "!"),
		(p->dirty ? "" : "!"),
		(p->cleaning ? "" : "!"),
		(p->pageout ? "" : "!"),
		(p->clustered ? "" : "!"));
	iprintf("%slock_supplied, %soverwriting, %srestart, %sunusual\n",
		(p->lock_supplied ? "" : "!"),
		(p->overwriting ? "" : "!"),
		(p->restart ? "" : "!"),
		(p->unusual ? "" : "!"));

	iprintf("phys_page=0x%x", p->phys_page);
	printf(", page_error=0x%x", p->page_error);
	printf(", page_lock=0x%x", p->page_lock);
	printf(", unlock_request=%d\n", p->unlock_request);

	db_indent -= 2;
}
#endif	/* MACH_KDB */
