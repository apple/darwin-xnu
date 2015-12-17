/*
 * Copyright (c) 2000-2014 Apple Inc. All rights reserved.
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
#include <zone_debug.h>
#include <zone_alias_addr.h>

#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <mach/kern_return.h>
#include <mach/mach_host_server.h>
#include <mach/task_server.h>
#include <mach/machine/vm_types.h>
#include <mach_debug/zone_info.h>
#include <mach/vm_map.h>

#include <kern/kern_types.h>
#include <kern/assert.h>
#include <kern/host.h>
#include <kern/macro_help.h>
#include <kern/sched.h>
#include <kern/locks.h>
#include <kern/sched_prim.h>
#include <kern/misc_protos.h>
#include <kern/thread_call.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <kern/btlog.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>

#include <pexpert/pexpert.h>

#include <machine/machparam.h>
#include <machine/machine_routines.h>  /* ml_cpu_get_info */

#include <libkern/OSDebug.h>
#include <libkern/OSAtomic.h>
#include <sys/kdebug.h>

/*
 *  ZONE_ALIAS_ADDR
 *
 * With this option enabled, zones with alloc_size <= PAGE_SIZE allocate
 * a virtual page from the zone_map, but before zcram-ing the allocated memory
 * into the zone, the page is translated to use the alias address of the page
 * in the static kernel region. zone_gc reverses that translation when
 * scanning the freelist to collect free pages so that it can look up the page
 * in the zone_page_table, and free it to kmem_free.
 *
 * The static kernel region is a flat 1:1 mapping of physical memory passed
 * to xnu by the booter. It is mapped to the range:
 * [gVirtBase, gVirtBase + gPhysSize]
 *
 * Accessing memory via the static kernel region is faster due to the
 * entire region being mapped via large pages, cutting down
 * on TLB misses.
 *
 * zinit favors using PAGE_SIZE backing allocations for a zone unless it would
 * waste more than 10% space to use a single page, in order to take advantage
 * of the speed benefit for as many zones as possible.
 *
 * Zones with > PAGE_SIZE allocations can't take advantage of this
 * because kernel_memory_allocate doesn't give out physically contiguous pages.
 *
 * zone_virtual_addr()
 *  - translates an address from the static kernel region to the zone_map
 *  - returns the same address if it's not from the static kernel region
 * It relies on the fact that a physical page mapped to the
 * zone_map is not mapped anywhere else (except the static kernel region).
 *
 * zone_alias_addr()
 *  - translates a virtual memory address from the zone_map to the
 *    corresponding address in the static kernel region
 *
 */

#if     !ZONE_ALIAS_ADDR
#define from_zone_map(addr, size) \
        ((vm_offset_t)(addr)             >= zone_map_min_address && \
        ((vm_offset_t)(addr) + size - 1) <  zone_map_max_address )
#else
#define from_zone_map(addr, size) \
        ((vm_offset_t)(zone_virtual_addr((vm_map_address_t)(uintptr_t)addr))            >= zone_map_min_address && \
        ((vm_offset_t)(zone_virtual_addr((vm_map_address_t)(uintptr_t)addr)) + size -1) <  zone_map_max_address )
#endif

/*
 * Zone Corruption Debugging
 *
 * We use three techniques to detect modification of a zone element
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
 *
 * (1) and (2) occur for every allocation and free to a zone.
 * This is done to make it slightly more difficult for an attacker to
 * manipulate the freelist to behave in a specific way.
 *
 * Poisoning (3) occurs periodically for every N frees (counted per-zone)
 * and on every free for zones smaller than a cacheline.  If -zp
 * is passed as a boot arg, poisoning occurs for every free.
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

/* Returns TRUE if we rolled over the counter at factor */
static inline boolean_t
sample_counter(volatile uint32_t * count_p, uint32_t factor)
{
	uint32_t old_count, new_count;
	boolean_t rolled_over;

	do {
		new_count = old_count = *count_p;

		if (++new_count >= factor) {
			rolled_over = TRUE;
			new_count = 0;
		} else {
			rolled_over = FALSE;
		}

	} while (!OSCompareAndSwap(old_count, new_count, count_p));

	return rolled_over;
}

#if defined(__LP64__)
#define ZP_POISON       0xdeadbeefdeadbeef
#else
#define ZP_POISON       0xdeadbeef
#endif

#define ZP_DEFAULT_SAMPLING_FACTOR 16
#define ZP_DEFAULT_SCALE_FACTOR 4

/*
 *  A zp_factor of 0 indicates zone poisoning is disabled,
 *  however, we still poison zones smaller than zp_tiny_zone_limit (a cacheline).
 *  Passing the -no-zp boot-arg disables even this behavior.
 *  In all cases, we record and check the integrity of a backup pointer.
 */

/* set by zp-factor=N boot arg, zero indicates non-tiny poisoning disabled */
uint32_t        zp_factor               = 0;

/* set by zp-scale=N boot arg, scales zp_factor by zone size */
uint32_t        zp_scale                = 0;

/* set in zp_init, zero indicates -no-zp boot-arg */
vm_size_t       zp_tiny_zone_limit      = 0;

/* initialized to a per-boot random value in zp_init */
uintptr_t       zp_poisoned_cookie      = 0;
uintptr_t       zp_nopoison_cookie      = 0;


/*
 * initialize zone poisoning
 * called from zone_bootstrap before any allocations are made from zalloc
 */
static inline void
zp_init(void)
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

	/*
	 * Always poison zones smaller than a cacheline,
	 * because it's pretty close to free
	 */
	ml_cpu_info_t cpu_info;
	ml_cpu_get_info(&cpu_info);
	zp_tiny_zone_limit = (vm_size_t) cpu_info.cache_line_size;

	zp_factor = ZP_DEFAULT_SAMPLING_FACTOR;
	zp_scale  = ZP_DEFAULT_SCALE_FACTOR;

	//TODO: Bigger permutation?
	/*
	 * Permute the default factor +/- 1 to make it less predictable
	 * This adds or subtracts ~4 poisoned objects per 1000 frees.
	 */
	if (zp_factor != 0) {
		uint32_t rand_bits = early_random() & 0x3;

		if (rand_bits == 0x1)
			zp_factor += 1;
		else if (rand_bits == 0x2)
			zp_factor -= 1;
		/* if 0x0 or 0x3, leave it alone */
	}

	/* -zp: enable poisoning for every alloc and free */
	if (PE_parse_boot_argn("-zp", temp_buf, sizeof(temp_buf))) {
		zp_factor = 1;
	}

	/* -no-zp: disable poisoning completely even for tiny zones */
	if (PE_parse_boot_argn("-no-zp", temp_buf, sizeof(temp_buf))) {
		zp_factor          = 0;
		zp_tiny_zone_limit = 0;
		printf("Zone poisoning disabled\n");
	}

	/* zp-factor=XXXX: override how often to poison freed zone elements */
	if (PE_parse_boot_argn("zp-factor", &zp_factor, sizeof(zp_factor))) {
		printf("Zone poisoning factor override: %u\n", zp_factor);
	}

	/* zp-scale=XXXX: override how much zone size scales zp-factor by */
	if (PE_parse_boot_argn("zp-scale", &zp_scale, sizeof(zp_scale))) {
		printf("Zone poisoning scale factor override: %u\n", zp_scale);
	}

	/* Initialize backup pointer random cookie for unpoisoned elements */
	zp_nopoison_cookie = (uintptr_t) early_random();

#if MACH_ASSERT
	if (zp_poisoned_cookie == zp_nopoison_cookie)
		panic("early_random() is broken: %p and %p are not random\n",
		      (void *) zp_poisoned_cookie, (void *) zp_nopoison_cookie);
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
}

/* zone_map page count for page table structure */
uint64_t zone_map_table_page_count = 0;

/*
 * These macros are used to keep track of the number
 * of pages being used by the zone currently. The
 * z->page_count is protected by the zone lock.
 */
#define ZONE_PAGE_COUNT_INCR(z, count)		\
{						\
	OSAddAtomic64(count, &(z->page_count));	\
}

#define ZONE_PAGE_COUNT_DECR(z, count)			\
{							\
	OSAddAtomic64(-count, &(z->page_count));	\
}

/* for is_sane_zone_element and garbage collection */

vm_offset_t     zone_map_min_address = 0;  /* initialized in zone_init */
vm_offset_t     zone_map_max_address = 0;

/* Helpful for walking through a zone's free element list. */
struct zone_free_element {
	struct zone_free_element *next;
	/* ... */
	/* void *backup_ptr; */
};

struct zone_page_metadata {
	queue_chain_t				pages;
	struct zone_free_element	*elements;
	zone_t						zone;
	uint16_t					alloc_count;
	uint16_t					free_count;
};

/* The backup pointer is stored in the last pointer-sized location in an element. */
static inline vm_offset_t *
get_backup_ptr(vm_size_t  elem_size,
               vm_offset_t *element)
{
	return (vm_offset_t *) ((vm_offset_t)element + elem_size - sizeof(vm_offset_t));
}

static inline struct zone_page_metadata *
get_zone_page_metadata(struct zone_free_element *element)
{
	return (struct zone_page_metadata *)(trunc_page((vm_offset_t)element));
}

/*
 * Zone checking helper function.
 * A pointer that satisfies these conditions is OK to be a freelist next pointer
 * A pointer that doesn't satisfy these conditions indicates corruption
 */
static inline boolean_t
is_sane_zone_ptr(zone_t		zone,
                 vm_offset_t	addr,
		 size_t		obj_size)
{
	/*  Must be aligned to pointer boundary */
	if (__improbable((addr & (sizeof(vm_offset_t) - 1)) != 0))
		return FALSE;

	/*  Must be a kernel address */
	if (__improbable(!pmap_kernel_va(addr)))
		return FALSE;

	/*  Must be from zone map if the zone only uses memory from the zone_map */
	/*
	 *  TODO: Remove the zone->collectable check when every
	 *  zone using foreign memory is properly tagged with allows_foreign
	 */
	if (zone->collectable && !zone->allows_foreign) {
#if ZONE_ALIAS_ADDR
		/*
		 * If this address is in the static kernel region, it might be
		 * the alias address of a valid zone element.
		 * If we tried to find the zone_virtual_addr() of an invalid
		 * address in the static kernel region, it will panic, so don't 
		 * check addresses in this region.
		 *
		 * TODO: Use a safe variant of zone_virtual_addr to
		 *  make this check more accurate
		 *
		 * The static kernel region is mapped at:
		 * [gVirtBase, gVirtBase + gPhysSize]
		 */
		if ((addr - gVirtBase) < gPhysSize)
			return TRUE;
#endif
		/*  check if addr is from zone map */
		if (addr                 >= zone_map_min_address &&
		   (addr + obj_size - 1) <  zone_map_max_address )
			return TRUE;

		return FALSE;
	}

	return TRUE;
}

static inline boolean_t
is_sane_zone_page_metadata(zone_t 	zone,
			   vm_offset_t 	page_meta)
{
	/* NULL page metadata structures are invalid */
	if (page_meta == 0)
		return FALSE;
	return is_sane_zone_ptr(zone, page_meta, sizeof(struct zone_page_metadata));
}

static inline boolean_t
is_sane_zone_element(zone_t      zone,
                     vm_offset_t addr)
{
	/*  NULL is OK because it indicates the tail of the list */
	if (addr == 0)
		return TRUE;
	return is_sane_zone_ptr(zone, addr, zone->elem_size);
}
	
/* Someone wrote to freed memory. */
static inline void /* noreturn */
zone_element_was_modified_panic(zone_t        zone,
                                vm_offset_t   element,
                                vm_offset_t   found,
                                vm_offset_t   expected,
                                vm_offset_t   offset)
{
	panic("a freed zone element has been modified in zone %s: expected %p but found %p, bits changed %p, at offset %d of %d in element %p, cookies %p %p",
	                 zone->zone_name,
	      (void *)   expected,
	      (void *)   found,
	      (void *)   (expected ^ found),
	      (uint32_t) offset,
	      (uint32_t) zone->elem_size,
	      (void *)   element,
	      (void *)   zp_nopoison_cookie,
	      (void *)   zp_poisoned_cookie);
}

/*
 * The primary and backup pointers don't match.
 * Determine which one was likely the corrupted pointer, find out what it
 * probably should have been, and panic.
 * I would like to mark this as noreturn, but panic() isn't marked noreturn.
 */
static void /* noreturn */
backup_ptr_mismatch_panic(zone_t        zone,
                          vm_offset_t   element,
                          vm_offset_t   primary,
                          vm_offset_t   backup)
{
	vm_offset_t likely_backup;

	boolean_t   sane_backup;
	boolean_t   sane_primary = is_sane_zone_element(zone, primary);
	boolean_t   element_was_poisoned = (backup & 0x1) ? TRUE : FALSE;

#if defined(__LP64__)
	/* We can inspect the tag in the upper bits for additional confirmation */
	if ((backup & 0xFFFFFF0000000000) == 0xFACADE0000000000)
		element_was_poisoned = TRUE;
	else if ((backup & 0xFFFFFF0000000000) == 0xC0FFEE0000000000)
		element_was_poisoned = FALSE;
#endif

	if (element_was_poisoned) {
		likely_backup = backup ^ zp_poisoned_cookie;
		sane_backup = is_sane_zone_element(zone, likely_backup);
	} else {
		likely_backup = backup ^ zp_nopoison_cookie;
		sane_backup = is_sane_zone_element(zone, likely_backup);
	}

	/* The primary is definitely the corrupted one */
	if (!sane_primary && sane_backup)
		zone_element_was_modified_panic(zone, element, primary, likely_backup, 0);

	/* The backup is definitely the corrupted one */
	if (sane_primary && !sane_backup)
		zone_element_was_modified_panic(zone, element, backup,
		                                (primary ^ (element_was_poisoned ? zp_poisoned_cookie : zp_nopoison_cookie)),
		                                zone->elem_size - sizeof(vm_offset_t));

	/*
	 * Not sure which is the corrupted one.
	 * It's less likely that the backup pointer was overwritten with
	 * ( (sane address) ^ (valid cookie) ), so we'll guess that the
	 * primary pointer has been overwritten with a sane but incorrect address.
	 */
	if (sane_primary && sane_backup)
		zone_element_was_modified_panic(zone, element, primary, likely_backup, 0);

	/* Neither are sane, so just guess. */
	zone_element_was_modified_panic(zone, element, primary, likely_backup, 0);
}

/*
 * Sets the next element of tail to elem.
 * elem can be NULL.
 * Preserves the poisoning state of the element.
 */
static inline void
append_zone_element(zone_t                    zone,
                    struct zone_free_element *tail,
                    struct zone_free_element *elem)
{
	vm_offset_t *backup = get_backup_ptr(zone->elem_size, (vm_offset_t *) tail);

	vm_offset_t old_backup = *backup;

	vm_offset_t old_next = (vm_offset_t) tail->next;
	vm_offset_t new_next = (vm_offset_t) elem;

	if      (old_next == (old_backup ^ zp_nopoison_cookie))
		*backup = new_next ^ zp_nopoison_cookie;
	else if (old_next == (old_backup ^ zp_poisoned_cookie))
		*backup = new_next ^ zp_poisoned_cookie;
	else
		backup_ptr_mismatch_panic(zone,
		                          (vm_offset_t) tail,
		                          old_next,
		                          old_backup);

	tail->next = elem;
}


/*
 * Insert a linked list of elements (delineated by head and tail) at the head of
 * the zone free list. Every element in the list being added has already gone
 * through append_zone_element, so their backup pointers are already
 * set properly.
 * Precondition: There should be no elements after tail
 */
static inline void
add_list_to_zone(zone_t                    zone,
                 struct zone_free_element *head,
                 struct zone_free_element *tail)
{
	assert(tail->next == NULL);
	assert(!zone->use_page_list);

	append_zone_element(zone, tail, zone->free_elements);

	zone->free_elements = head;
}


/*
 * Adds the element to the head of the zone's free list
 * Keeps a backup next-pointer at the end of the element
 */
static inline void
free_to_zone(zone_t      zone,
             vm_offset_t element,
             boolean_t   poison)
{
	vm_offset_t old_head;
	struct zone_page_metadata *page_meta;

	vm_offset_t *primary  = (vm_offset_t *) element;
	vm_offset_t *backup   = get_backup_ptr(zone->elem_size, primary);

	if (zone->use_page_list) {
		page_meta = get_zone_page_metadata((struct zone_free_element *)element);
		assert(page_meta->zone == zone);
		old_head = (vm_offset_t)page_meta->elements;
	} else {
		old_head = (vm_offset_t)zone->free_elements;
	}

#if MACH_ASSERT
	if (__improbable(!is_sane_zone_element(zone, old_head)))
		panic("zfree: invalid head pointer %p for freelist of zone %s\n",
		      (void *) old_head, zone->zone_name);
#endif

	if (__improbable(!is_sane_zone_element(zone, element)))
		panic("zfree: freeing invalid pointer %p to zone %s\n",
		      (void *) element, zone->zone_name);

	/*
	 * Always write a redundant next pointer
	 * So that it is more difficult to forge, xor it with a random cookie
	 * A poisoned element is indicated by using zp_poisoned_cookie
	 * instead of zp_nopoison_cookie
	 */

	*backup = old_head ^ (poison ? zp_poisoned_cookie : zp_nopoison_cookie);

	/* Insert this element at the head of the free list */
	*primary             = old_head;
	if (zone->use_page_list) {
		page_meta->elements = (struct zone_free_element *)element;
		page_meta->free_count++;
		if (zone->allows_foreign && !from_zone_map(element, zone->elem_size)) {
			if (page_meta->free_count == 1) {
				/* first foreign element freed on page, move from all_used */
				remqueue((queue_entry_t)page_meta);
				enqueue_tail(&zone->pages.any_free_foreign, (queue_entry_t)page_meta);
			} else {
				/* no other list transitions */
			}
		} else if (page_meta->free_count == page_meta->alloc_count) {
			/* whether the page was on the intermediate or all_used, queue, move it to free */
			remqueue((queue_entry_t)page_meta);
			enqueue_tail(&zone->pages.all_free, (queue_entry_t)page_meta);
		} else if (page_meta->free_count == 1) {
			/* first free element on page, move from all_used */
			remqueue((queue_entry_t)page_meta);
			enqueue_tail(&zone->pages.intermediate, (queue_entry_t)page_meta);
		}
	} else {
		zone->free_elements = (struct zone_free_element *)element;
	}
	zone->count--;
	zone->countfree++;
}


/*
 * Removes an element from the zone's free list, returning 0 if the free list is empty.
 * Verifies that the next-pointer and backup next-pointer are intact,
 * and verifies that a poisoned element hasn't been modified.
 */
static inline vm_offset_t
try_alloc_from_zone(zone_t zone,
                    boolean_t* check_poison)
{
	vm_offset_t  element;
	struct zone_page_metadata *page_meta;

	*check_poison = FALSE;

	/* if zone is empty, bail */
	if (zone->use_page_list) {
		if (zone->allows_foreign && !queue_empty(&zone->pages.any_free_foreign))
			page_meta = (struct zone_page_metadata *)queue_first(&zone->pages.any_free_foreign);
		else if (!queue_empty(&zone->pages.intermediate))
			page_meta = (struct zone_page_metadata *)queue_first(&zone->pages.intermediate);
		else if (!queue_empty(&zone->pages.all_free))
			page_meta = (struct zone_page_metadata *)queue_first(&zone->pages.all_free);
		else {
			return 0;
		}

		/* Check if page_meta passes is_sane_zone_element */
		if (__improbable(!is_sane_zone_page_metadata(zone, (vm_offset_t)page_meta)))
			panic("zalloc: invalid metadata structure %p for freelist of zone %s\n",
				(void *) page_meta, zone->zone_name);
		assert(page_meta->zone == zone);
		element = (vm_offset_t)page_meta->elements;
	} else {
		if (zone->free_elements == NULL)
			return 0;

		element = (vm_offset_t)zone->free_elements;
	}

#if MACH_ASSERT
	if (__improbable(!is_sane_zone_element(zone, element)))
		panic("zfree: invalid head pointer %p for freelist of zone %s\n",
		      (void *) element, zone->zone_name);
#endif

	vm_offset_t *primary = (vm_offset_t *) element;
	vm_offset_t *backup  = get_backup_ptr(zone->elem_size, primary);

	vm_offset_t  next_element          = *primary;
	vm_offset_t  next_element_backup   = *backup;

	/*
	 * backup_ptr_mismatch_panic will determine what next_element
	 * should have been, and print it appropriately
	 */
	if (__improbable(!is_sane_zone_element(zone, next_element)))
		backup_ptr_mismatch_panic(zone, element, next_element, next_element_backup);

	/* Check the backup pointer for the regular cookie */
	if (__improbable(next_element != (next_element_backup ^ zp_nopoison_cookie))) {

		/* Check for the poisoned cookie instead */
		if (__improbable(next_element != (next_element_backup ^ zp_poisoned_cookie)))
			/* Neither cookie is valid, corruption has occurred */
			backup_ptr_mismatch_panic(zone, element, next_element, next_element_backup);

		/*
		 * Element was marked as poisoned, so check its integrity before using it.
		 */
		*check_poison = TRUE;
	}

	if (zone->use_page_list) {
			
		/* Make sure the page_meta is at the correct offset from the start of page */
		if (__improbable(page_meta != get_zone_page_metadata((struct zone_free_element *)element)))
			panic("zalloc: metadata located at incorrect location on page of zone %s\n",
				zone->zone_name);

		/* Make sure next_element belongs to the same page as page_meta */
		if (next_element) {
			if (__improbable(page_meta != get_zone_page_metadata((struct zone_free_element *)next_element)))
				panic("zalloc: next element pointer %p for element %p points to invalid element for zone %s\n",
					(void *)next_element, (void *)element, zone->zone_name);
		}
	}

	/* Remove this element from the free list */
	if (zone->use_page_list) {

		page_meta->elements = (struct zone_free_element *)next_element;
		page_meta->free_count--;

		if (zone->allows_foreign && !from_zone_map(element, zone->elem_size)) {
			if (page_meta->free_count == 0) {
				/* move to all used */
				remqueue((queue_entry_t)page_meta);
				enqueue_tail(&zone->pages.all_used, (queue_entry_t)page_meta);
			} else {
				/* no other list transitions */
			}
		} else if (page_meta->free_count == 0) {
			/* remove from intermediate or free, move to all_used */
			remqueue((queue_entry_t)page_meta);
			enqueue_tail(&zone->pages.all_used, (queue_entry_t)page_meta);
		} else if (page_meta->alloc_count == page_meta->free_count + 1) {
			/* remove from free, move to intermediate */
			remqueue((queue_entry_t)page_meta);
			enqueue_tail(&zone->pages.intermediate, (queue_entry_t)page_meta);
		}
	} else {
		zone->free_elements = (struct zone_free_element *)next_element;
	}
	zone->countfree--;
	zone->count++;
	zone->sum_count++;

	return element;
}


/*
 * End of zone poisoning
 */

/*
 * Fake zones for things that want to report via zprint but are not actually zones.
 */
struct fake_zone_info {
	const char* name;
	void (*init)(int);
	void (*query)(int *,
		     vm_size_t *, vm_size_t *, vm_size_t *, vm_size_t *,
		      uint64_t *, int *, int *, int *);
};

static const struct fake_zone_info fake_zones[] = {
};
static const unsigned int num_fake_zones =
	sizeof (fake_zones) / sizeof (fake_zones[0]);

/*
 * Zone info options
 */
boolean_t zinfo_per_task = FALSE;		/* enabled by -zinfop in boot-args */
#define ZINFO_SLOTS 200				/* for now */
#define ZONES_MAX (ZINFO_SLOTS - num_fake_zones - 1)

/*
 * Support for garbage collection of unused zone pages
 *
 * The kernel virtually allocates the "zone map" submap of the kernel
 * map. When an individual zone needs more storage, memory is allocated
 * out of the zone map, and the two-level "zone_page_table" is
 * on-demand expanded so that it has entries for those pages.
 * zone_page_init()/zone_page_alloc() initialize "alloc_count"
 * to the number of zone elements that occupy the zone page (which may
 * be a minimum of 1, including if a zone element spans multiple
 * pages).
 *
 * Asynchronously, the zone_gc() logic attempts to walk zone free
 * lists to see if all the elements on a zone page are free. If
 * "collect_count" (which it increments during the scan) matches
 * "alloc_count", the zone page is a candidate for collection and the
 * physical page is returned to the VM system. During this process, the
 * first word of the zone page is re-used to maintain a linked list of
 * to-be-collected zone pages.
 */
typedef uint32_t zone_page_index_t;
#define ZONE_PAGE_INDEX_INVALID ((zone_page_index_t)0xFFFFFFFFU)

struct zone_page_table_entry {
	volatile	uint16_t	alloc_count;
	volatile	uint16_t	collect_count;
};

#define	ZONE_PAGE_USED  0
#define ZONE_PAGE_UNUSED 0xffff

/* Forwards */
void		zone_page_init(
				vm_offset_t	addr,
				vm_size_t	size);

void		zone_page_alloc(
				vm_offset_t	addr,
				vm_size_t	size);

void		zone_page_free_element(
				zone_page_index_t	*free_page_head,
				zone_page_index_t	*free_page_tail,
				vm_offset_t	addr,
				vm_size_t	size);

void		zone_page_collect(
				vm_offset_t	addr,
				vm_size_t	size);

boolean_t	zone_page_collectable(
				vm_offset_t	addr,
				vm_size_t	size);

void		zone_page_keep(
				vm_offset_t	addr,
				vm_size_t	size);

void		zone_display_zprint(void);

zone_t		zone_find_largest(void);

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
void		zalloc_async(
				thread_call_param_t	p0,  
				thread_call_param_t	p1);

static thread_call_data_t call_async_alloc;

vm_map_t	zone_map = VM_MAP_NULL;

zone_t		zone_zone = ZONE_NULL;	/* the zone containing other zones */

zone_t		zinfo_zone = ZONE_NULL; /* zone of per-task zone info */

/*
 *	The VM system gives us an initial chunk of memory.
 *	It has to be big enough to allocate the zone_zone
 *	all the way through the pmap zone.
 */

vm_offset_t	zdata;
vm_size_t	zdata_size;
/*
 * Align elements that use the zone page list to 32 byte boundaries.
 */
#define ZONE_ELEMENT_ALIGNMENT 32

#define zone_wakeup(zone) thread_wakeup((event_t)(zone))
#define zone_sleep(zone)				\
	(void) lck_mtx_sleep(&(zone)->lock, LCK_SLEEP_SPIN, (event_t)(zone), THREAD_UNINT);

/*
 *	The zone_locks_grp allows for collecting lock statistics.
 *	All locks are associated to this group in zinit.
 *	Look at tools/lockstat for debugging lock contention.
 */

lck_grp_t	zone_locks_grp;
lck_grp_attr_t	zone_locks_grp_attr;

#define lock_zone_init(zone)				\
MACRO_BEGIN						\
	lck_attr_setdefault(&(zone)->lock_attr);			\
	lck_mtx_init_ext(&(zone)->lock, &(zone)->lock_ext,		\
	    &zone_locks_grp, &(zone)->lock_attr);			\
MACRO_END

#define lock_try_zone(zone)	lck_mtx_try_lock_spin(&zone->lock)

/*
 *	Garbage collection map information
 */
#define ZONE_PAGE_TABLE_FIRST_LEVEL_SIZE (32)
struct zone_page_table_entry * volatile zone_page_table[ZONE_PAGE_TABLE_FIRST_LEVEL_SIZE];
vm_size_t			zone_page_table_used_size;
unsigned int			zone_pages;
unsigned int                   zone_page_table_second_level_size;                      /* power of 2 */
unsigned int                   zone_page_table_second_level_shift_amount;

#define zone_page_table_first_level_slot(x)  ((x) >> zone_page_table_second_level_shift_amount)
#define zone_page_table_second_level_slot(x) ((x) & (zone_page_table_second_level_size - 1))

void   zone_page_table_expand(zone_page_index_t pindex);
struct zone_page_table_entry *zone_page_table_lookup(zone_page_index_t pindex);

/*
 *	Exclude more than one concurrent garbage collection
 */
decl_lck_mtx_data(, zone_gc_lock)

lck_attr_t      zone_gc_lck_attr;
lck_grp_t       zone_gc_lck_grp;
lck_grp_attr_t  zone_gc_lck_grp_attr;
lck_mtx_ext_t   zone_gc_lck_ext;

/*
 *	Protects first_zone, last_zone, num_zones,
 *	and the next_zone field of zones.
 */
decl_simple_lock_data(,	all_zones_lock)
zone_t			first_zone;
zone_t			*last_zone;
unsigned int		num_zones;

boolean_t zone_gc_allowed = TRUE;
boolean_t zone_gc_forced = FALSE;
boolean_t panic_include_zprint = FALSE;
boolean_t zone_gc_allowed_by_time_throttle = TRUE;

vm_offset_t panic_kext_memory_info = 0;
vm_size_t panic_kext_memory_size = 0;

#define ZALLOC_DEBUG_ZONEGC		0x00000001
#define ZALLOC_DEBUG_ZCRAM		0x00000002
uint32_t zalloc_debug = 0;

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

static int log_records;	/* size of the log, expressed in number of records */

#define MAX_ZONE_NAME	32	/* max length of a zone name we can take from the boot-args */

static char zone_name_to_log[MAX_ZONE_NAME] = "";	/* the zone name we're logging, if any */

/* Log allocations and frees to help debug a zone element corruption */
boolean_t       corruption_debug_flag    = FALSE;    /* enabled by "-zc" boot-arg */

/*
 * The number of records in the log is configurable via the zrecs parameter in boot-args.  Set this to 
 * the number of records you want in the log.  For example, "zrecs=1000" sets it to 1000 records.  Note
 * that the larger the size of the log, the slower the system will run due to linear searching in the log,
 * but one doesn't generally care about performance when tracking down a leak.  The log is capped at 8000
 * records since going much larger than this tends to make the system unresponsive and unbootable on small
 * memory configurations.  The default value is 4000 records.
 */

#if	defined(__LP64__)
#define ZRECORDS_MAX 		128000		/* Max records allowed in the log */
#else
#define ZRECORDS_MAX 		8000		/* Max records allowed in the log */
#endif
#define ZRECORDS_DEFAULT	4000		/* default records in log if zrecs is not specificed in boot-args */

/*
 * Each record in the log contains a pointer to the zone element it refers to,
 * and a small array to hold the pc's from the stack trace.  A
 * record is added to the log each time a zalloc() is done in the zone_of_interest.  For leak debugging,
 * the record is cleared when a zfree() is done.  For corruption debugging, the log tracks both allocs and frees.
 * If the log fills, old records are replaced as if it were a circular buffer.
 */


/*
 * Opcodes for the btlog operation field:
 */

#define ZOP_ALLOC	1
#define ZOP_FREE	0

/*
 * The allocation log and all the related variables are protected by the zone lock for the zone_of_interest
 */
static btlog_t *zlog_btlog;		/* the log itself, dynamically allocated when logging is enabled  */
static zone_t  zone_of_interest = NULL;		/* the zone being watched; corresponds to zone_name_to_log */

/*
 * Decide if we want to log this zone by doing a string compare between a zone name and the name
 * of the zone to log. Return true if the strings are equal, false otherwise.  Because it's not
 * possible to include spaces in strings passed in via the boot-args, a period in the logname will
 * match a space in the zone name.
 */

static int
log_this_zone(const char *zonename, const char *logname) 
{
	int len;
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

		if (*zc != *lc && !(*zc == ' ' && *lc == '.')) 
			break;

		/*
		 * The strings are equal so far.  If we're at the end, then it's a match.
		 */

		if (*zc == '\0')
			return TRUE;
	}

	return FALSE;
}


/*
 * Test if we want to log this zalloc/zfree event.  We log if this is the zone we're interested in and
 * the buffer for the records has been allocated.
 */

#define DO_LOGGING(z)		(zlog_btlog && (z) == zone_of_interest)

extern boolean_t kmem_alloc_ready;

#if CONFIG_ZLEAKS
#pragma mark -
#pragma mark Zone Leak Detection

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
#define ZLEAK_STATE_ENABLED		0x01	/* Zone leak monitoring should be turned on if zone_map fills up. */
#define ZLEAK_STATE_ACTIVE 		0x02	/* We are actively collecting traces. */
#define ZLEAK_STATE_ACTIVATING 		0x04	/* Some thread is doing setup; others should move along. */
#define ZLEAK_STATE_FAILED		0x08	/* Attempt to allocate tables failed.  We will not try again. */
uint32_t	zleak_state = 0;		/* State of collection, as above */

boolean_t	panic_include_ztrace	= FALSE;  	/* Enable zleak logging on panic */
vm_size_t 	zleak_global_tracking_threshold;	/* Size of zone map at which to start collecting data */
vm_size_t 	zleak_per_zone_tracking_threshold;	/* Size a zone will have before we will collect data on it */
unsigned int 	zleak_sample_factor	= 1000;		/* Allocations per sample attempt */

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
unsigned int z_alloc_recorded	= 0;
unsigned int z_trace_recorded	= 0;

/* Times zleak_log returned false due to not being able to acquire the lock */
unsigned int z_total_conflicts	= 0;


#pragma mark struct zallocation
/*
 * Structure for keeping track of an allocation
 * An allocation bucket is in use if its element is not NULL
 */
struct zallocation {
	uintptr_t		za_element;		/* the element that was zalloc'ed or zfree'ed, NULL if bucket unused */
	vm_size_t		za_size;			/* how much memory did this allocation take up? */
	uint32_t		za_trace_index;	/* index into ztraces for backtrace associated with allocation */
	/* TODO: #if this out */
	uint32_t		za_hit_count;		/* for determining effectiveness of hash function */
};

/* Size must be a power of two for the zhash to be able to just mask off bits instead of mod */
uint32_t zleak_alloc_buckets = CONFIG_ZLEAK_ALLOCATION_MAP_NUM;
uint32_t zleak_trace_buckets = CONFIG_ZLEAK_TRACE_MAP_NUM;

vm_size_t zleak_max_zonemap_size;

/* Hashmaps of allocations and their corresponding traces */
static struct zallocation*	zallocations;
static struct ztrace*		ztraces;

/* not static so that panic can see this, see kern/debug.c */
struct ztrace*				top_ztrace;

/* Lock to protect zallocations, ztraces, and top_ztrace from concurrent modification. */
static lck_spin_t			zleak_lock;
static lck_attr_t			zleak_lock_attr;
static lck_grp_t			zleak_lock_grp;
static lck_grp_attr_t			zleak_lock_grp_attr;

/*
 * Initializes the zone leak monitor.  Called from zone_init()
 */
static void 
zleak_init(vm_size_t max_zonemap_size) 
{
	char			scratch_buf[16];
	boolean_t		zleak_enable_flag = FALSE;

	zleak_max_zonemap_size = max_zonemap_size;
	zleak_global_tracking_threshold = max_zonemap_size / 2;	
	zleak_per_zone_tracking_threshold = zleak_global_tracking_threshold / 8;

	/* -zleakoff (flag to disable zone leak monitor) */
	if (PE_parse_boot_argn("-zleakoff", scratch_buf, sizeof(scratch_buf))) {
		zleak_enable_flag = FALSE;
		printf("zone leak detection disabled\n");
	} else {
		zleak_enable_flag = TRUE;
		printf("zone leak detection enabled\n");
	}
	
	/* zfactor=XXXX (override how often to sample the zone allocator) */
	if (PE_parse_boot_argn("zfactor", &zleak_sample_factor, sizeof(zleak_sample_factor))) {
		printf("Zone leak factor override: %u\n", zleak_sample_factor);
	}

	/* zleak-allocs=XXXX (override number of buckets in zallocations) */
	if (PE_parse_boot_argn("zleak-allocs", &zleak_alloc_buckets, sizeof(zleak_alloc_buckets))) {
		printf("Zone leak alloc buckets override: %u\n", zleak_alloc_buckets);
		/* uses 'is power of 2' trick: (0x01000 & 0x00FFF == 0) */
		if (zleak_alloc_buckets == 0 || (zleak_alloc_buckets & (zleak_alloc_buckets-1))) {
			printf("Override isn't a power of two, bad things might happen!\n");
		}
	}
	
	/* zleak-traces=XXXX (override number of buckets in ztraces) */
	if (PE_parse_boot_argn("zleak-traces", &zleak_trace_buckets, sizeof(zleak_trace_buckets))) {
		printf("Zone leak trace buckets override: %u\n", zleak_trace_buckets);
		/* uses 'is power of 2' trick: (0x01000 & 0x00FFF == 0) */
		if (zleak_trace_buckets == 0 || (zleak_trace_buckets & (zleak_trace_buckets-1))) {
			printf("Override isn't a power of two, bad things might happen!\n");
		}
	}
	
	/* allocate the zleak_lock */
	lck_grp_attr_setdefault(&zleak_lock_grp_attr);
	lck_grp_init(&zleak_lock_grp, "zleak_lock", &zleak_lock_grp_attr);
	lck_attr_setdefault(&zleak_lock_attr);
	lck_spin_init(&zleak_lock, &zleak_lock_grp, &zleak_lock_attr);
	
	if (zleak_enable_flag) {
		zleak_state = ZLEAK_STATE_ENABLED;
	}
}

#if CONFIG_ZLEAKS

/*
 * Support for kern.zleak.active sysctl - a simplified
 * version of the zleak_state variable.
 */
int
get_zleak_state(void)
{
	if (zleak_state & ZLEAK_STATE_FAILED)
		return (-1);
	if (zleak_state & ZLEAK_STATE_ACTIVE)
		return (1);
	return (0);
}

#endif


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
	
	struct zallocation* allocation	= &zallocations[hashaddr(addr, zleak_alloc_buckets)];
	
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
	
	if (trace->zt_size > 0 && bcmp(trace->zt_stack, bt, (depth * sizeof(uintptr_t))) != 0 ) {
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
		if (trace->zt_depth != 0) /* if this slot was previously used but not currently in use */
			z_trace_overwrites++;
		
		z_trace_recorded++;
		trace->zt_size			= allocation_size;
		memcpy(trace->zt_stack, bt, (depth * sizeof(uintptr_t)) );
		
		trace->zt_depth		= depth;
		trace->zt_collisions	= 0;
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

	allocation->za_element		= addr;
	allocation->za_trace_index	= trace_index;
	allocation->za_size		= allocation_size;
	
	z_alloc_recorded++;
	
	if (top_ztrace->zt_size < trace->zt_size)
		top_ztrace = trace;
	
	lck_spin_unlock(&zleak_lock);
	return TRUE;
}

/*
 * Free the allocation record and release the stacktrace.
 * This should be as fast as possible because it will be called for every free.
 */
static void
zleak_free(uintptr_t addr,
		   vm_size_t allocation_size) 
{
	if (addr == (uintptr_t) 0)
		return;
	
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

/*
 * This function captures a backtrace from the current stack and
 * returns the number of frames captured, limited by max_frames.
 * It's fast because it does no checking to make sure there isn't bad data.
 * Since it's only called from threads that we're going to keep executing,
 * if there's bad data we were going to die eventually.
 * If this function is inlined, it doesn't record the frame of the function it's inside.
 * (because there's no stack frame!)
 */

uint32_t
fastbacktrace(uintptr_t* bt, uint32_t max_frames)
{
	uintptr_t* frameptr = NULL, *frameptr_next = NULL;
	uintptr_t retaddr = 0;
	uint32_t frame_index = 0, frames = 0;
	uintptr_t kstackb, kstackt;
	thread_t cthread = current_thread();

	if (__improbable(cthread == NULL))
		return 0;

	kstackb = cthread->kernel_stack;
	kstackt = kstackb + kernel_stack_size;
	/* Load stack frame pointer (EBP on x86) into frameptr */
	frameptr = __builtin_frame_address(0);
	if (((uintptr_t)frameptr > kstackt) || ((uintptr_t)frameptr < kstackb))
		frameptr = NULL;

	while (frameptr != NULL && frame_index < max_frames ) {
		/* Next frame pointer is pointed to by the previous one */
		frameptr_next = (uintptr_t*) *frameptr;

		/* Bail if we see a zero in the stack frame, that means we've reached the top of the stack */
                /* That also means the return address is worthless, so don't record it */
		if (frameptr_next == NULL)
			break;
		/* Verify thread stack bounds */
		if (((uintptr_t)frameptr_next > kstackt) || ((uintptr_t)frameptr_next < kstackb))
			break;
		/* Pull return address from one spot above the frame pointer */
		retaddr = *(frameptr + 1);

		/* Store it in the backtrace array */
		bt[frame_index++] = retaddr;

		frameptr = frameptr_next;
	}

	/* Save the number of frames captured for return value */
	frames = frame_index;

	/* Fill in the rest of the backtrace with zeros */
	while (frame_index < max_frames)
		bt[frame_index++] = 0;

	return frames;
}

/* "Thomas Wang's 32/64 bit mix functions."  http://www.concentric.net/~Ttwang/tech/inthash.htm */
uintptr_t
hash_mix(uintptr_t x)
{
#ifndef __LP64__
	x += ~(x << 15);
	x ^=  (x >> 10);
	x +=  (x << 3 );
	x ^=  (x >> 6 );
	x += ~(x << 11);
	x ^=  (x >> 16);
#else
	x += ~(x << 32);
	x ^=  (x >> 22);
	x += ~(x << 13);
	x ^=  (x >> 8 );
	x +=  (x << 3 );
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
#pragma mark -

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
	const char	*name)		/* a name for the zone */
{
	zone_t		z;
	boolean_t	use_page_list = FALSE;

	if (zone_zone == ZONE_NULL) {

		z = (struct zone *)zdata;
		/* special handling in zcram() because the first element is being used */
	} else
		z = (zone_t) zalloc(zone_zone);

	if (z == ZONE_NULL)
		return(ZONE_NULL);

	/* Zone elements must fit both a next pointer and a backup pointer */
	vm_size_t  minimum_element_size = sizeof(vm_offset_t) * 2;
	if (size < minimum_element_size)
		size = minimum_element_size;

	/*
	 *  Round element size to a multiple of sizeof(pointer)
	 *  This also enforces that allocations will be aligned on pointer boundaries
	 */
	size = ((size-1) + sizeof(vm_offset_t)) -
	       ((size-1) % sizeof(vm_offset_t));

	if (alloc == 0)
		alloc = PAGE_SIZE;

	alloc = round_page(alloc);
	max   = round_page(max);

	/*
	 * we look for an allocation size with less than 1% waste
	 * up to 5 pages in size...
	 * otherwise, we look for an allocation size with least fragmentation
	 * in the range of 1 - 5 pages
	 * This size will be used unless
	 * the user suggestion is larger AND has less fragmentation
	 */
#if	ZONE_ALIAS_ADDR
	/* Favor PAGE_SIZE allocations unless we waste >10% space */
	if ((size < PAGE_SIZE) && (PAGE_SIZE % size <= PAGE_SIZE / 10))
		alloc = PAGE_SIZE;
	else
#endif
#if	defined(__LP64__)		
		if (((alloc % size) != 0) || (alloc > PAGE_SIZE * 8))
#endif
		{
		vm_size_t best, waste; unsigned int i;
		best  = PAGE_SIZE;
		waste = best % size;

		for (i = 1; i <= 5; i++) {
			vm_size_t tsize, twaste;

			tsize = i * PAGE_SIZE;

			if ((tsize % size) < (tsize / 100)) {
			        alloc = tsize;
				goto use_this_allocation;
			}
			twaste = tsize % size;
			if (twaste < waste)
				best = tsize, waste = twaste;
		}
		if (alloc <= best || (alloc % size >= waste))
			alloc = best;
	}
use_this_allocation:
	if (max && (max < alloc))
		max = alloc;

	/*
	 * Opt into page list tracking if we can reliably map an allocation
	 * to its page_metadata, and if the wastage in the tail of
	 * the allocation is not too large
	 */

	/* zone_zone can't use page metadata since the page metadata will overwrite zone metadata */
	if (alloc == PAGE_SIZE && zone_zone != ZONE_NULL) {
		vm_offset_t first_element_offset;
		size_t zone_page_metadata_size = sizeof(struct zone_page_metadata);

		if (zone_page_metadata_size % ZONE_ELEMENT_ALIGNMENT == 0) {
			first_element_offset = zone_page_metadata_size;
		} else {
			first_element_offset = zone_page_metadata_size + (ZONE_ELEMENT_ALIGNMENT - (zone_page_metadata_size % ZONE_ELEMENT_ALIGNMENT));
		}

		if (((PAGE_SIZE - first_element_offset) % size) <= PAGE_SIZE / 100) {
			use_page_list = TRUE;
		}
	}

	z->free_elements = NULL;
	queue_init(&z->pages.any_free_foreign);
	queue_init(&z->pages.all_free);
	queue_init(&z->pages.intermediate);
	queue_init(&z->pages.all_used);
	z->cur_size = 0;
	z->page_count = 0;
	z->max_size = max;
	z->elem_size = size;
	z->alloc_size = alloc;
	z->zone_name = name;
	z->count = 0;
	z->countfree = 0;
	z->sum_count = 0LL;
	z->doing_alloc_without_vm_priv = FALSE;
	z->doing_alloc_with_vm_priv = FALSE;
	z->doing_gc = FALSE;
	z->exhaustible = FALSE;
	z->collectable = TRUE;
	z->allows_foreign = FALSE;
	z->expandable  = TRUE;
	z->waiting = FALSE;
	z->async_pending = FALSE;
	z->caller_acct = TRUE;
	z->noencrypt = FALSE;
	z->no_callout = FALSE;
	z->async_prio_refill = FALSE;
	z->gzalloc_exempt = FALSE;
	z->alignment_required = FALSE;
	z->use_page_list = use_page_list;
	z->prio_refill_watermark = 0;
	z->zone_replenish_thread = NULL;
	z->zp_count = 0;
#if CONFIG_ZLEAKS
	z->zleak_capture = 0;
	z->zleak_on = FALSE;
#endif /* CONFIG_ZLEAKS */

#if	ZONE_DEBUG
	z->active_zones.next = z->active_zones.prev = NULL;	
	zone_debug_enable(z);
#endif	/* ZONE_DEBUG */
	lock_zone_init(z);

	/*
	 *	Add the zone to the all-zones list.
	 *	If we are tracking zone info per task, and we have
	 *	already used all the available stat slots, then keep
	 *	using the overflow zone slot.
	 */
	z->next_zone = ZONE_NULL;
	simple_lock(&all_zones_lock);
	*last_zone = z;
	last_zone = &z->next_zone;
	z->index = num_zones;
	if (zinfo_per_task) {
		if (num_zones > ZONES_MAX)
			z->index = ZONES_MAX;
	}
	num_zones++;
	simple_unlock(&all_zones_lock);

	/*
	 * Check if we should be logging this zone.  If so, remember the zone pointer.
	 */
	if (log_this_zone(z->zone_name, zone_name_to_log)) {
	 	zone_of_interest = z;
	}

	/*
	 * If we want to log a zone, see if we need to allocate buffer space for the log.  Some vm related zones are
	 * zinit'ed before we can do a kmem_alloc, so we have to defer allocation in that case.  kmem_alloc_ready is set to
	 * TRUE once enough of the VM system is up and running to allow a kmem_alloc to work.  If we want to log one
	 * of the VM related zones that's set up early on, we will skip allocation of the log until zinit is called again
	 * later on some other zone.  So note we may be allocating a buffer to log a zone other than the one being initialized
	 * right now.
	 */
	if (zone_of_interest != NULL && zlog_btlog == NULL && kmem_alloc_ready) {
		zlog_btlog = btlog_create(log_records, MAX_ZTRACE_DEPTH, NULL, NULL, NULL);
		if (zlog_btlog) {
			printf("zone: logging started for zone %s\n", zone_of_interest->zone_name);
		} else {
			printf("zone: couldn't allocate memory for zrecords, turning off zleak logging\n");
			zone_of_interest = NULL;
		}
	}
#if	CONFIG_GZALLOC	
	gzalloc_zone_init(z);
#endif
	return(z);
}
unsigned	zone_replenish_loops, zone_replenish_wakeups, zone_replenish_wakeups_initiated, zone_replenish_throttle_count;

static void zone_replenish_thread(zone_t);

/* High priority VM privileged thread used to asynchronously refill a designated
 * zone, such as the reserved VM map entry zone.
 */
static void zone_replenish_thread(zone_t z) {
	vm_size_t free_size;
	current_thread()->options |= TH_OPT_VMPRIV;

	for (;;) {
		lock_zone(z);
		assert(z->prio_refill_watermark != 0);
		while ((free_size = (z->cur_size - (z->count * z->elem_size))) < (z->prio_refill_watermark * z->elem_size)) {
			assert(z->doing_alloc_without_vm_priv == FALSE);
			assert(z->doing_alloc_with_vm_priv == FALSE);
			assert(z->async_prio_refill == TRUE);

			unlock_zone(z);
			int	zflags = KMA_KOBJECT|KMA_NOPAGEWAIT;
			vm_offset_t space, alloc_size;
			kern_return_t kr;
				
			if (vm_pool_low())
				alloc_size = round_page(z->elem_size);
			else
				alloc_size = z->alloc_size;
				
			if (z->noencrypt)
				zflags |= KMA_NOENCRYPT;
				
			kr = kernel_memory_allocate(zone_map, &space, alloc_size, 0, zflags, VM_KERN_MEMORY_ZONE);

			if (kr == KERN_SUCCESS) {
#if	ZONE_ALIAS_ADDR
				if (alloc_size == PAGE_SIZE)
					space = zone_alias_addr(space);
#endif
				zcram(z, space, alloc_size);
			} else if (kr == KERN_RESOURCE_SHORTAGE) {
				VM_PAGE_WAIT();
			} else if (kr == KERN_NO_SPACE) {
				kr = kernel_memory_allocate(kernel_map, &space, alloc_size, 0, zflags, VM_KERN_MEMORY_ZONE);
				if (kr == KERN_SUCCESS) {
#if	ZONE_ALIAS_ADDR
					if (alloc_size == PAGE_SIZE)
						space = zone_alias_addr(space);
#endif
					zcram(z, space, alloc_size);
				} else {
					assert_wait_timeout(&z->zone_replenish_thread, THREAD_UNINT, 1, 100 * NSEC_PER_USEC);
					thread_block(THREAD_CONTINUE_NULL);
				}
			}

			lock_zone(z);
			zone_replenish_loops++;
		}

		unlock_zone(z);
		/* Signal any potential throttled consumers, terminating
		 * their timer-bounded waits.
		 */
		thread_wakeup(z);

		assert_wait(&z->zone_replenish_thread, THREAD_UNINT);
		thread_block(THREAD_CONTINUE_NULL);
		zone_replenish_wakeups++;
	}
}

void
zone_prio_refill_configure(zone_t z, vm_size_t low_water_mark) {
	z->prio_refill_watermark = low_water_mark;

	z->async_prio_refill = TRUE;
	OSMemoryBarrier();
	kern_return_t tres = kernel_thread_start_priority((thread_continue_t)zone_replenish_thread, z, MAXPRI_KERNEL, &z->zone_replenish_thread);

	if (tres != KERN_SUCCESS) {
		panic("zone_prio_refill_configure, thread create: 0x%x", tres);
	}

	thread_deallocate(z->zone_replenish_thread);
}

/*
 *	Cram the given memory into the specified zone. Update the zone page count accordingly.
 */
void
zcram(
	zone_t		zone,
	vm_offset_t			newmem,
	vm_size_t		size)
{
	vm_size_t	elem_size;
	boolean_t   from_zm = FALSE;

	/* Basic sanity checks */
	assert(zone != ZONE_NULL && newmem != (vm_offset_t)0);
	assert(!zone->collectable || zone->allows_foreign
		|| (from_zone_map(newmem, size)));

	elem_size = zone->elem_size;

	if (from_zone_map(newmem, size))
		from_zm = TRUE;

	if (zalloc_debug & ZALLOC_DEBUG_ZCRAM)
		kprintf("zcram(%p[%s], 0x%lx%s, 0x%lx)\n", zone, zone->zone_name,
				(unsigned long)newmem, from_zm ? "" : "[F]", (unsigned long)size);

	if (from_zm && !zone->use_page_list)
		zone_page_init(newmem, size);

	ZONE_PAGE_COUNT_INCR(zone, (size / PAGE_SIZE));

	lock_zone(zone);

	if (zone->use_page_list) {
		struct zone_page_metadata *page_metadata;
		size_t zone_page_metadata_size = sizeof(struct zone_page_metadata);

		assert((newmem & PAGE_MASK) == 0);
		assert((size & PAGE_MASK) == 0);
		for (; size > 0; newmem += PAGE_SIZE, size -= PAGE_SIZE) {

			vm_size_t pos_in_page;
			page_metadata = (struct zone_page_metadata *)(newmem);
			
			page_metadata->pages.next = NULL;
			page_metadata->pages.prev = NULL;
			page_metadata->elements = NULL;
			page_metadata->zone = zone;
			page_metadata->alloc_count = 0;
			page_metadata->free_count = 0;

			enqueue_tail(&zone->pages.all_used, (queue_entry_t)page_metadata);

			vm_offset_t first_element_offset;
			if (zone_page_metadata_size % ZONE_ELEMENT_ALIGNMENT == 0){
				first_element_offset = zone_page_metadata_size;
			} else {
				first_element_offset = zone_page_metadata_size + (ZONE_ELEMENT_ALIGNMENT - (zone_page_metadata_size % ZONE_ELEMENT_ALIGNMENT));
			}

			for (pos_in_page = first_element_offset; (newmem + pos_in_page + elem_size) < (vm_offset_t)(newmem + PAGE_SIZE); pos_in_page += elem_size) {
				page_metadata->alloc_count++;
				zone->count++;	/* compensate for free_to_zone */
				free_to_zone(zone, newmem + pos_in_page, FALSE);
				zone->cur_size += elem_size;
			}
		}
	} else {
		while (size >= elem_size) {
			zone->count++;	/* compensate for free_to_zone */
			if (newmem == (vm_offset_t)zone) {
				/* Don't free zone_zone zone */
			} else {
				free_to_zone(zone, newmem, FALSE);
			}
			if (from_zm)
				zone_page_alloc(newmem, elem_size);
			size -= elem_size;
			newmem += elem_size;
			zone->cur_size += elem_size;
		}
	}
	unlock_zone(zone);
}


/*
 *	Steal memory for the zone package.  Called from
 *	vm_page_bootstrap().
 */
void
zone_steal_memory(void)
{
#if	CONFIG_GZALLOC
	gzalloc_configure();
#endif
	/* Request enough early memory to get to the pmap zone */
	zdata_size = 12 * sizeof(struct zone);
	zdata_size = round_page(zdata_size);
	zdata = (vm_offset_t)pmap_steal_memory(zdata_size);
}


/*
 * Fill a zone with enough memory to contain at least nelem elements.
 * Memory is obtained with kmem_alloc_kobject from the kernel_map.
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
	kr = kmem_alloc_kobject(kernel_map, &memory, size, VM_KERN_MEMORY_ZONE);
	if (kr != KERN_SUCCESS)
		return 0;

	zone_change(zone, Z_FOREIGN, TRUE);
	zcram(zone, memory, size);
	nalloc = (int)(size / zone->elem_size);
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
	char temp_buf[16];

	if (PE_parse_boot_argn("-zinfop", temp_buf, sizeof(temp_buf))) {
		zinfo_per_task = TRUE;
	}

	if (!PE_parse_boot_argn("zalloc_debug", &zalloc_debug, sizeof(zalloc_debug)))
		zalloc_debug = 0;

	/* Set up zone element poisoning */
	zp_init();

	/* should zlog log to debug zone corruption instead of leaks? */
	if (PE_parse_boot_argn("-zc", temp_buf, sizeof(temp_buf))) {
		corruption_debug_flag = TRUE;
	}	

	/*
	 * Check for and set up zone leak detection if requested via boot-args.  We recognized two
	 * boot-args:
	 *
	 *	zlog=<zone_to_log>
	 *	zrecs=<num_records_in_log>
	 *
	 * The zlog arg is used to specify the zone name that should be logged, and zrecs is used to
	 * control the size of the log.  If zrecs is not specified, a default value is used.
	 */

	if (PE_parse_boot_argn("zlog", zone_name_to_log, sizeof(zone_name_to_log)) == TRUE) {
		if (PE_parse_boot_argn("zrecs", &log_records, sizeof(log_records)) == TRUE) {

			/*
			 * Don't allow more than ZRECORDS_MAX records even if the user asked for more.
			 * This prevents accidentally hogging too much kernel memory and making the system
			 * unusable.
			 */

			log_records = MIN(ZRECORDS_MAX, log_records);

		} else {
			log_records = ZRECORDS_DEFAULT;
		}
	}

	simple_lock_init(&all_zones_lock, 0);

	first_zone = ZONE_NULL;
	last_zone = &first_zone;
	num_zones = 0;
	thread_call_setup(&call_async_alloc, zalloc_async, NULL);

	/* assertion: nobody else called zinit before us */
	assert(zone_zone == ZONE_NULL);
	
	/* initializing global lock group for zones */
	lck_grp_attr_setdefault(&zone_locks_grp_attr);
	lck_grp_init(&zone_locks_grp, "zone_locks", &zone_locks_grp_attr);

	zone_zone = zinit(sizeof(struct zone), 128 * sizeof(struct zone),
			  sizeof(struct zone), "zones");
	zone_change(zone_zone, Z_COLLECT, FALSE);
	zone_change(zone_zone, Z_CALLERACCT, FALSE);
	zone_change(zone_zone, Z_NOENCRYPT, TRUE);

	zcram(zone_zone, zdata, zdata_size);
	VM_PAGE_MOVE_STOLEN(atop_64(zdata_size));

	/* initialize fake zones and zone info if tracking by task */
	if (zinfo_per_task) {
		vm_size_t zisize = sizeof(zinfo_usage_store_t) * ZINFO_SLOTS;
		unsigned int i;

		for (i = 0; i < num_fake_zones; i++)
			fake_zones[i].init(ZINFO_SLOTS - num_fake_zones + i);
		zinfo_zone = zinit(zisize, zisize * CONFIG_TASK_MAX,
				   zisize, "per task zinfo");
		zone_change(zinfo_zone, Z_CALLERACCT, FALSE);
	}
}

void
zinfo_task_init(task_t task)
{
	if (zinfo_per_task) {
		task->tkm_zinfo = zalloc(zinfo_zone);
		memset(task->tkm_zinfo, 0, sizeof(zinfo_usage_store_t) * ZINFO_SLOTS);
	} else {
		task->tkm_zinfo = NULL;
	}
}

void
zinfo_task_free(task_t task)
{
	assert(task != kernel_task);
	if (task->tkm_zinfo != NULL) {
		zfree(zinfo_zone, task->tkm_zinfo);
		task->tkm_zinfo = NULL;
	}
}
		
/* Global initialization of Zone Allocator.
 * Runs after zone_bootstrap.
 */
void
zone_init(
	vm_size_t max_zonemap_size)
{
	kern_return_t	retval;
	vm_offset_t	zone_min;
	vm_offset_t	zone_max;

	retval = kmem_suballoc(kernel_map, &zone_min, max_zonemap_size,
			       FALSE, VM_FLAGS_ANYWHERE | VM_FLAGS_PERMANENT | VM_MAKE_TAG(VM_KERN_MEMORY_ZONE),
			       &zone_map);

	if (retval != KERN_SUCCESS)
		panic("zone_init: kmem_suballoc failed");
	zone_max = zone_min + round_page(max_zonemap_size);
#if	CONFIG_GZALLOC
	gzalloc_init(max_zonemap_size);
#endif
	/*
	 * Setup garbage collection information:
	 */
	zone_map_min_address = zone_min;
	zone_map_max_address = zone_max;

#if defined(__LP64__)
	/*
	 * ensure that any vm_page_t that gets created from
	 * the vm_page zone can be packed properly (see vm_page.h
	 * for the packing requirements
	 */
	if (VM_PAGE_UNPACK_PTR(VM_PAGE_PACK_PTR(zone_map_min_address)) != (vm_page_t)zone_map_min_address)
		panic("VM_PAGE_PACK_PTR failed on zone_map_min_address - %p", (void *)zone_map_min_address);

	if (VM_PAGE_UNPACK_PTR(VM_PAGE_PACK_PTR(zone_map_max_address)) != (vm_page_t)zone_map_max_address)
		panic("VM_PAGE_PACK_PTR failed on zone_map_max_address - %p", (void *)zone_map_max_address);
#endif

	zone_pages = (unsigned int)atop_kernel(zone_max - zone_min);
	zone_page_table_used_size = sizeof(zone_page_table);

	zone_page_table_second_level_size = 1;
	zone_page_table_second_level_shift_amount = 0;
	
	/*
	 * Find the power of 2 for the second level that allows
	 * the first level to fit in ZONE_PAGE_TABLE_FIRST_LEVEL_SIZE
	 * slots.
	 */
	while ((zone_page_table_first_level_slot(zone_pages-1)) >= ZONE_PAGE_TABLE_FIRST_LEVEL_SIZE) {
		zone_page_table_second_level_size <<= 1;
		zone_page_table_second_level_shift_amount++;
	}
	
	lck_grp_attr_setdefault(&zone_gc_lck_grp_attr);
	lck_grp_init(&zone_gc_lck_grp, "zone_gc", &zone_gc_lck_grp_attr);
	lck_attr_setdefault(&zone_gc_lck_attr);
	lck_mtx_init_ext(&zone_gc_lock, &zone_gc_lck_ext, &zone_gc_lck_grp, &zone_gc_lck_attr);
	
#if CONFIG_ZLEAKS
	/*
	 * Initialize the zone leak monitor
	 */
	zleak_init(max_zonemap_size);
#endif /* CONFIG_ZLEAKS */
}

void
zone_page_table_expand(zone_page_index_t pindex)
{
	unsigned int first_index;
	struct zone_page_table_entry * volatile * first_level_ptr;

	assert(pindex < zone_pages);

	first_index = zone_page_table_first_level_slot(pindex);
	first_level_ptr = &zone_page_table[first_index];

	if (*first_level_ptr == NULL) {
		/*
		 * We were able to verify the old first-level slot
		 * had NULL, so attempt to populate it.
		 */

		vm_offset_t second_level_array = 0;
		vm_size_t second_level_size = round_page(zone_page_table_second_level_size * sizeof(struct zone_page_table_entry));
		zone_page_index_t i;
		struct zone_page_table_entry *entry_array;

		if (kmem_alloc_kobject(zone_map, &second_level_array,
							   second_level_size, VM_KERN_MEMORY_OSFMK) != KERN_SUCCESS) {
			panic("zone_page_table_expand");
		}
		zone_map_table_page_count += (second_level_size / PAGE_SIZE);

		/*
		 * zone_gc() may scan the "zone_page_table" directly,
		 * so make sure any slots have a valid unused state.
		 */
		entry_array = (struct zone_page_table_entry *)second_level_array;
		for (i=0; i < zone_page_table_second_level_size; i++) {
			entry_array[i].alloc_count = ZONE_PAGE_UNUSED;
			entry_array[i].collect_count = 0;
		}

		if (OSCompareAndSwapPtr(NULL, entry_array, first_level_ptr)) {
			/* Old slot was NULL, replaced with expanded level */
			OSAddAtomicLong(second_level_size, &zone_page_table_used_size);
		} else {
			/* Old slot was not NULL, someone else expanded first */
			kmem_free(zone_map, second_level_array, second_level_size);
			zone_map_table_page_count -= (second_level_size / PAGE_SIZE);
		}
	} else {
		/* Old slot was not NULL, already been expanded */
	}
}

struct zone_page_table_entry *
zone_page_table_lookup(zone_page_index_t pindex)
{
	unsigned int first_index = zone_page_table_first_level_slot(pindex);
	struct zone_page_table_entry *second_level = zone_page_table[first_index];

	if (second_level) {
		return &second_level[zone_page_table_second_level_slot(pindex)];
	}

	return NULL;
}

extern volatile SInt32 kfree_nop_count;

#pragma mark -
#pragma mark zalloc_canblock

/*
 *	zalloc returns an element from the specified zone.
 */
static void *
zalloc_internal(
	zone_t	zone,
	boolean_t canblock,
	boolean_t nopagewait)
{
	vm_offset_t	addr = 0;
	kern_return_t	retval;
	uintptr_t	zbt[MAX_ZTRACE_DEPTH];	/* used in zone leak logging and zone leak detection */
	int 		numsaved = 0;
	boolean_t	zone_replenish_wakeup = FALSE, zone_alloc_throttle = FALSE;
#if	CONFIG_GZALLOC || ZONE_DEBUG	
	boolean_t	did_gzalloc = FALSE;
#endif
	thread_t thr = current_thread();
	boolean_t       check_poison = FALSE;
	boolean_t       set_doing_alloc_with_vm_priv = FALSE;

#if CONFIG_ZLEAKS
	uint32_t	zleak_tracedepth = 0;  /* log this allocation if nonzero */
#endif /* CONFIG_ZLEAKS */

	assert(zone != ZONE_NULL);

#if	CONFIG_GZALLOC
	addr = gzalloc_alloc(zone, canblock);
	did_gzalloc = (addr != 0);
#endif

	/*
	 * If zone logging is turned on and this is the zone we're tracking, grab a backtrace.
	 */
	if (__improbable(DO_LOGGING(zone)))
	        numsaved = OSBacktrace((void*) zbt, MAX_ZTRACE_DEPTH);

#if CONFIG_ZLEAKS
	/*
	 * Zone leak detection: capture a backtrace every zleak_sample_factor
	 * allocations in this zone.
	 */
	if (__improbable(zone->zleak_on && sample_counter(&zone->zleak_capture, zleak_sample_factor) == TRUE)) {
		/* Avoid backtracing twice if zone logging is on */
		if (numsaved == 0)
			zleak_tracedepth = fastbacktrace(zbt, MAX_ZTRACE_DEPTH);
		else
			zleak_tracedepth = numsaved;
	}
#endif /* CONFIG_ZLEAKS */

	lock_zone(zone);

	if (zone->async_prio_refill && zone->zone_replenish_thread) {
		    do {
			    vm_size_t zfreec = (zone->cur_size - (zone->count * zone->elem_size));
			    vm_size_t zrefillwm = zone->prio_refill_watermark * zone->elem_size;
			    zone_replenish_wakeup = (zfreec < zrefillwm);
			    zone_alloc_throttle = (zfreec < (zrefillwm / 2)) && ((thr->options & TH_OPT_VMPRIV) == 0);

			    if (zone_replenish_wakeup) {
				    zone_replenish_wakeups_initiated++;
				    unlock_zone(zone);
				    /* Signal the potentially waiting
				     * refill thread.
				     */
				    thread_wakeup(&zone->zone_replenish_thread);

				    /* Scheduling latencies etc. may prevent
				     * the refill thread from keeping up
				     * with demand. Throttle consumers
				     * when we fall below half the
				     * watermark, unless VM privileged
				     */
				    if (zone_alloc_throttle) {
					    zone_replenish_throttle_count++;
					    assert_wait_timeout(zone, THREAD_UNINT, 1, NSEC_PER_MSEC);
					    thread_block(THREAD_CONTINUE_NULL);
				    }
				    lock_zone(zone);
			    }
		    } while (zone_alloc_throttle == TRUE);
	}
	
	if (__probable(addr == 0))
		addr = try_alloc_from_zone(zone, &check_poison);


	while ((addr == 0) && canblock) {
		/*
 		 * zone is empty, try to expand it
		 * 
		 * Note that we now allow up to 2 threads (1 vm_privliged and 1 non-vm_privliged)
		 * to expand the zone concurrently...  this is necessary to avoid stalling
		 * vm_privileged threads running critical code necessary to continue compressing/swapping
		 * pages (i.e. making new free pages) from stalling behind non-vm_privileged threads
		 * waiting to acquire free pages when the vm_page_free_count is below the
		 * vm_page_free_reserved limit.
		 */
		if ((zone->doing_alloc_without_vm_priv || zone->doing_alloc_with_vm_priv) &&
		    (((thr->options & TH_OPT_VMPRIV) == 0) || zone->doing_alloc_with_vm_priv)) {
			/*
			 * This is a non-vm_privileged thread and a non-vm_privileged or
			 * a vm_privileged thread is already expanding the zone...
			 *    OR
			 * this is a vm_privileged thread and a vm_privileged thread is
			 * already expanding the zone...
			 *
			 * In either case wait for a thread to finish, then try again.
			 */
			zone->waiting = TRUE;
			zone_sleep(zone);
		} else if (zone->doing_gc) {
			/*
			 * zone_gc() is running. Since we need an element
			 * from the free list that is currently being
			 * collected, set the waiting bit and 
			 * wait for the GC process to finish
			 * before trying again
			 */
			zone->waiting = TRUE;
			zone_sleep(zone);
		} else {
			vm_offset_t space;
			vm_size_t alloc_size;
			int retry = 0;

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

					panic_include_zprint = TRUE;
#if CONFIG_ZLEAKS
					if (zleak_state & ZLEAK_STATE_ACTIVE)
						panic_include_ztrace = TRUE;
#endif /* CONFIG_ZLEAKS */
					panic("zalloc: zone \"%s\" empty.", zone->zone_name);
				}
			}
			if ((thr->options & TH_OPT_VMPRIV)) {
			        zone->doing_alloc_with_vm_priv = TRUE;
				set_doing_alloc_with_vm_priv = TRUE;
			} else {
			        zone->doing_alloc_without_vm_priv = TRUE;
			}
			unlock_zone(zone);

			for (;;) {
				int	zflags = KMA_KOBJECT|KMA_NOPAGEWAIT;

				if (vm_pool_low() || retry >= 1)
					alloc_size = 
						round_page(zone->elem_size);
				else
					alloc_size = zone->alloc_size;
				
				if (zone->noencrypt)
					zflags |= KMA_NOENCRYPT;
				
				retval = kernel_memory_allocate(zone_map, &space, alloc_size, 0, zflags, VM_KERN_MEMORY_ZONE);
				if (retval == KERN_SUCCESS) {
#if	ZONE_ALIAS_ADDR
					if (alloc_size == PAGE_SIZE)
						space = zone_alias_addr(space);
#endif
					
#if CONFIG_ZLEAKS
					if ((zleak_state & (ZLEAK_STATE_ENABLED | ZLEAK_STATE_ACTIVE)) == ZLEAK_STATE_ENABLED) {
						if (zone_map->size >= zleak_global_tracking_threshold) {
							kern_return_t kr;
							
							kr = zleak_activate();
							if (kr != KERN_SUCCESS) {
								printf("Failed to activate live zone leak debugging (%d).\n", kr);
							}
						}
					}
					
					if ((zleak_state & ZLEAK_STATE_ACTIVE) && !(zone->zleak_on)) {
						if (zone->cur_size > zleak_per_zone_tracking_threshold) {
							zone->zleak_on = TRUE;
						}	
					}
#endif /* CONFIG_ZLEAKS */
					zcram(zone, space, alloc_size);
					
					break;
				} else if (retval != KERN_RESOURCE_SHORTAGE) {
					retry++;
					
					if (retry == 2) {
						zone_gc(TRUE);
						printf("zalloc did gc\n");
						zone_display_zprint();
					}
					if (retry == 3) {
						panic_include_zprint = TRUE;
#if CONFIG_ZLEAKS
						if ((zleak_state & ZLEAK_STATE_ACTIVE)) {
							panic_include_ztrace = TRUE;
						}
#endif /* CONFIG_ZLEAKS */		
						if (retval == KERN_NO_SPACE) {
							zone_t zone_largest = zone_find_largest();
							panic("zalloc: zone map exhausted while allocating from zone %s, likely due to memory leak in zone %s (%lu total bytes, %d elements allocated)",
							zone->zone_name, zone_largest->zone_name,
							(unsigned long)zone_largest->cur_size, zone_largest->count);

						}
						panic("zalloc: \"%s\" (%d elements) retry fail %d, kfree_nop_count: %d", zone->zone_name, zone->count, retval, (int)kfree_nop_count);
					}
				} else {
					break;
				}
			}
			lock_zone(zone);

			if (set_doing_alloc_with_vm_priv == TRUE)
			        zone->doing_alloc_with_vm_priv = FALSE;
			else
			        zone->doing_alloc_without_vm_priv = FALSE; 
			
			if (zone->waiting) {
			        zone->waiting = FALSE;
				zone_wakeup(zone);
			}
			addr = try_alloc_from_zone(zone, &check_poison);
			if (addr == 0 &&
			    retval == KERN_RESOURCE_SHORTAGE) {
				if (nopagewait == TRUE)
					break;	/* out of the main while loop */
				unlock_zone(zone);

				VM_PAGE_WAIT();
				lock_zone(zone);
			}
		}
		if (addr == 0)
			addr = try_alloc_from_zone(zone, &check_poison);
	}

#if CONFIG_ZLEAKS
	/* Zone leak detection:
	 * If we're sampling this allocation, add it to the zleaks hash table. 
	 */
	if (addr && zleak_tracedepth > 0)  {
		/* Sampling can fail if another sample is happening at the same time in a different zone. */
		if (!zleak_log(zbt, addr, zleak_tracedepth, zone->elem_size)) {
			/* If it failed, roll back the counter so we sample the next allocation instead. */
			zone->zleak_capture = zleak_sample_factor;
		}
	}
#endif /* CONFIG_ZLEAKS */			
			
			
	if ((addr == 0) && (!canblock || nopagewait) && (zone->async_pending == FALSE) && (zone->no_callout == FALSE) && (zone->exhaustible == FALSE) && (!vm_pool_low())) {
		zone->async_pending = TRUE;
		unlock_zone(zone);
		thread_call_enter(&call_async_alloc);
		lock_zone(zone);
		addr = try_alloc_from_zone(zone, &check_poison);
	}

	/*
	 * See if we should be logging allocations in this zone.  Logging is rarely done except when a leak is
	 * suspected, so this code rarely executes.  We need to do this code while still holding the zone lock
	 * since it protects the various log related data structures.
	 */

	if (__improbable(DO_LOGGING(zone) && addr)) {
		btlog_add_entry(zlog_btlog, (void *)addr, ZOP_ALLOC, (void **)zbt, numsaved);
	}

	vm_offset_t     inner_size = zone->elem_size;
	
#if	ZONE_DEBUG
	if (!did_gzalloc && addr && zone_debug_enabled(zone)) {
		enqueue_tail(&zone->active_zones, (queue_entry_t)addr);
		addr += ZONE_DEBUG_OFFSET;
		inner_size -= ZONE_DEBUG_OFFSET;
	}
#endif

	unlock_zone(zone);

	if (__improbable(check_poison && addr)) {
		vm_offset_t *element_cursor  = ((vm_offset_t *) addr) + 1;
		vm_offset_t *backup  = get_backup_ptr(inner_size, (vm_offset_t *) addr);

		for ( ; element_cursor < backup ; element_cursor++)
			if (__improbable(*element_cursor != ZP_POISON))
				zone_element_was_modified_panic(zone,
				                                addr,
				                                *element_cursor,
				                                ZP_POISON,
				                                ((vm_offset_t)element_cursor) - addr);
	}

	if (addr) {
		/*
		 * Clear out the old next pointer and backup to avoid leaking the cookie
		 * and so that only values on the freelist have a valid cookie
		 */

		vm_offset_t *primary  = (vm_offset_t *) addr;
		vm_offset_t *backup   = get_backup_ptr(inner_size, primary);

		*primary = ZP_POISON;
		*backup  = ZP_POISON;
	}

	TRACE_MACHLEAKS(ZALLOC_CODE, ZALLOC_CODE_2, zone->elem_size, addr);

	if (addr) {
		task_t task;
		zinfo_usage_t zinfo;
		vm_size_t sz = zone->elem_size;

		if (zone->caller_acct)
			ledger_credit(thr->t_ledger, task_ledgers.tkm_private, sz);
		else
			ledger_credit(thr->t_ledger, task_ledgers.tkm_shared, sz);

		if ((task = thr->task) != NULL && (zinfo = task->tkm_zinfo) != NULL)
			OSAddAtomic64(sz, (int64_t *)&zinfo[zone->index].alloc);
	}
	return((void *)addr);
}


void *
zalloc(zone_t zone)
{
	return (zalloc_internal(zone, TRUE, FALSE));
}

void *
zalloc_noblock(zone_t zone)
{
	return (zalloc_internal(zone, FALSE, FALSE));
}

void *
zalloc_nopagewait(zone_t zone)
{
	return (zalloc_internal(zone, TRUE, TRUE));
}

void *
zalloc_canblock(zone_t zone, boolean_t canblock)
{
	return (zalloc_internal(zone, canblock, FALSE));
}


void
zalloc_async(
	__unused thread_call_param_t          p0,
	__unused thread_call_param_t p1)
{
	zone_t current_z = NULL, head_z;
	unsigned int max_zones, i;
	void *elt = NULL;
	boolean_t pending = FALSE;
	
	simple_lock(&all_zones_lock);
	head_z = first_zone;
	max_zones = num_zones;
	simple_unlock(&all_zones_lock);
	current_z = head_z;
	for (i = 0; i < max_zones; i++) {
		lock_zone(current_z);
		if (current_z->async_pending == TRUE) {
			current_z->async_pending = FALSE;
			pending = TRUE;
		}
		unlock_zone(current_z);

		if (pending == TRUE) {
			elt = zalloc_canblock(current_z, TRUE);
			zfree(current_z, elt);
			pending = FALSE;
		}
		/*
		 * This is based on assumption that zones never get
		 * freed once allocated and linked. 
		 * Hence a read outside of lock is OK.
		 */
		current_z = current_z->next_zone;
	}
}

/*
 *	zget returns an element from the specified zone
 *	and immediately returns nothing if there is nothing there.
 *
 *	This form should be used when you can not block (like when
 *	processing an interrupt).
 *
 *	XXX: It seems like only vm_page_grab_fictitious_common uses this, and its
 *  friend vm_page_more_fictitious can block, so it doesn't seem like 
 *  this is used for interrupts any more....
 */
void *
zget(
	register zone_t	zone)
{
	vm_offset_t	addr;
	boolean_t       check_poison = FALSE;
	
#if CONFIG_ZLEAKS
	uintptr_t	zbt[MAX_ZTRACE_DEPTH];		/* used for zone leak detection */
	uint32_t	zleak_tracedepth = 0;  /* log this allocation if nonzero */
#endif /* CONFIG_ZLEAKS */

	assert( zone != ZONE_NULL );

#if CONFIG_ZLEAKS
	/*
	 * Zone leak detection: capture a backtrace
	 */
	if (__improbable(zone->zleak_on && sample_counter(&zone->zleak_capture, zleak_sample_factor) == TRUE)) {
		zleak_tracedepth = fastbacktrace(zbt, MAX_ZTRACE_DEPTH);
	}
#endif /* CONFIG_ZLEAKS */

	if (!lock_try_zone(zone))
		return NULL;
	
	addr = try_alloc_from_zone(zone, &check_poison);

	vm_offset_t     inner_size = zone->elem_size;
	
#if	ZONE_DEBUG
	if (addr && zone_debug_enabled(zone)) {
		enqueue_tail(&zone->active_zones, (queue_entry_t)addr);
		addr += ZONE_DEBUG_OFFSET;
		inner_size -= ZONE_DEBUG_OFFSET;
	}
#endif	/* ZONE_DEBUG */
	
#if CONFIG_ZLEAKS
	/*
	 * Zone leak detection: record the allocation 
	 */
	if (zone->zleak_on && zleak_tracedepth > 0 && addr) {
		/* Sampling can fail if another sample is happening at the same time in a different zone. */
		if (!zleak_log(zbt, addr, zleak_tracedepth, zone->elem_size)) {
			/* If it failed, roll back the counter so we sample the next allocation instead. */
			zone->zleak_capture = zleak_sample_factor;
		}
	}
#endif /* CONFIG_ZLEAKS */
	
	unlock_zone(zone);

	if (__improbable(check_poison && addr)) {
		vm_offset_t *element_cursor  = ((vm_offset_t *) addr) + 1;
		vm_offset_t *backup  = get_backup_ptr(inner_size, (vm_offset_t *) addr);

		for ( ; element_cursor < backup ; element_cursor++)
			if (__improbable(*element_cursor != ZP_POISON))
				zone_element_was_modified_panic(zone,
				                                addr,
				                                *element_cursor,
				                                ZP_POISON,
				                                ((vm_offset_t)element_cursor) - addr);
	}

	if (addr) {
		/*
		 * Clear out the old next pointer and backup to avoid leaking the cookie
		 * and so that only values on the freelist have a valid cookie
		 */
		vm_offset_t *primary  = (vm_offset_t *) addr;
		vm_offset_t *backup   = get_backup_ptr(inner_size, primary);

		*primary = ZP_POISON;
		*backup  = ZP_POISON;
	}

	return((void *) addr);
}

/* Keep this FALSE by default.  Large memory machine run orders of magnitude
   slower in debug mode when true.  Use debugger to enable if needed */
/* static */ boolean_t zone_check = FALSE;

static void zone_check_freelist(zone_t zone, vm_offset_t elem)
{
	struct zone_free_element *this;
	struct zone_page_metadata *thispage;

	if (zone->use_page_list) {
		if (zone->allows_foreign) {
			for (thispage = (struct zone_page_metadata *)queue_first(&zone->pages.any_free_foreign);
				 !queue_end(&zone->pages.any_free_foreign, (queue_entry_t)thispage);
				 thispage = (struct zone_page_metadata *)queue_next((queue_chain_t *)thispage)) {
				for (this = thispage->elements;
					 this != NULL;
					 this = this->next) {
					if (!is_sane_zone_element(zone, (vm_address_t)this) || (vm_address_t)this == elem)
						panic("zone_check_freelist");
				}
			}
		}
		for (thispage = (struct zone_page_metadata *)queue_first(&zone->pages.all_free);
			 !queue_end(&zone->pages.all_free, (queue_entry_t)thispage);
			 thispage = (struct zone_page_metadata *)queue_next((queue_chain_t *)thispage)) {
			for (this = thispage->elements;
				 this != NULL;
				 this = this->next) {
				if (!is_sane_zone_element(zone, (vm_address_t)this) || (vm_address_t)this == elem)
					panic("zone_check_freelist");
			}
		}
		for (thispage = (struct zone_page_metadata *)queue_first(&zone->pages.intermediate);
			 !queue_end(&zone->pages.intermediate, (queue_entry_t)thispage);
			 thispage = (struct zone_page_metadata *)queue_next((queue_chain_t *)thispage)) {
			for (this = thispage->elements;
				 this != NULL;
				 this = this->next) {
				if (!is_sane_zone_element(zone, (vm_address_t)this) || (vm_address_t)this == elem)
					panic("zone_check_freelist");
			}
		}
	} else {
		for (this = zone->free_elements;
			 this != NULL;
			 this = this->next) {
			if (!is_sane_zone_element(zone, (vm_address_t)this) || (vm_address_t)this == elem)
				panic("zone_check_freelist");
		}
	}
}

static zone_t zone_last_bogus_zone = ZONE_NULL;
static vm_offset_t zone_last_bogus_elem = 0;

void
zfree(
	register zone_t	zone,
	void 		*addr)
{
	vm_offset_t	elem = (vm_offset_t) addr;
	uintptr_t	zbt[MAX_ZTRACE_DEPTH];			/* only used if zone logging is enabled via boot-args */
	int		numsaved = 0;
	boolean_t	gzfreed = FALSE;
	boolean_t       poison = FALSE;

	assert(zone != ZONE_NULL);

#if 1
	if (zone->use_page_list) {
		struct zone_page_metadata *page_meta = get_zone_page_metadata((struct zone_free_element *)addr);
		if (zone != page_meta->zone) {
			/*
			 * Something bad has happened. Someone tried to zfree a pointer but the metadata says it is from
			 * a different zone (or maybe it's from a zone that doesn't use page free lists at all). We can repair
			 * some cases of this, if:
			 * 1) The specified zone had use_page_list, and the true zone also has use_page_list set. In that case
			 *    we can swap the zone_t
			 * 2) The specified zone had use_page_list, but the true zone does not. In this case page_meta is garbage,
			 *    and dereferencing page_meta->zone might panic.
			 * To distinguish the two, we enumerate the zone list to match it up.
			 * We do not handle the case where an incorrect zone is passed that does not have use_page_list set,
			 * even if the true zone did have this set.
			 */
			zone_t fixed_zone = NULL;
			int fixed_i, max_zones;

			simple_lock(&all_zones_lock);
			max_zones = num_zones;
			fixed_zone = first_zone;
			simple_unlock(&all_zones_lock);

			for (fixed_i=0; fixed_i < max_zones; fixed_i++, fixed_zone = fixed_zone->next_zone) {
				if (fixed_zone == page_meta->zone && fixed_zone->use_page_list) {
					/* we can fix this */
					printf("Fixing incorrect zfree from zone %s to zone %s\n", zone->zone_name, fixed_zone->zone_name);
					zone = fixed_zone;
					break;
				}
			}
		}
	}
#endif

	/*
	 * If zone logging is turned on and this is the zone we're tracking, grab a backtrace.
	 */

	if (__improbable(DO_LOGGING(zone) && corruption_debug_flag))
		numsaved = OSBacktrace((void *)zbt, MAX_ZTRACE_DEPTH);

#if MACH_ASSERT
	/* Basic sanity checks */
	if (zone == ZONE_NULL || elem == (vm_offset_t)0)
		panic("zfree: NULL");
	/* zone_gc assumes zones are never freed */
	if (zone == zone_zone)
		panic("zfree: freeing to zone_zone breaks zone_gc!");
#endif

#if	CONFIG_GZALLOC	
	gzfreed = gzalloc_free(zone, addr);
#endif

	TRACE_MACHLEAKS(ZFREE_CODE, ZFREE_CODE_2, zone->elem_size, (uintptr_t)addr);

	if (__improbable(!gzfreed && zone->collectable && !zone->allows_foreign &&
		!from_zone_map(elem, zone->elem_size))) {
#if MACH_ASSERT
		panic("zfree: non-allocated memory in collectable zone!");
#endif
		zone_last_bogus_zone = zone;
		zone_last_bogus_elem = elem;
		return;
	}

	if ((zp_factor != 0 || zp_tiny_zone_limit != 0) && !gzfreed) {
		/*
		 * Poison the memory before it ends up on the freelist to catch
		 * use-after-free and use of uninitialized memory
		 *
		 * Always poison tiny zones' elements (limit is 0 if -no-zp is set)
		 * Also poison larger elements periodically
		 */

		vm_offset_t     inner_size = zone->elem_size;

#if	ZONE_DEBUG
		if (!gzfreed && zone_debug_enabled(zone)) {
			inner_size -= ZONE_DEBUG_OFFSET;
		}
#endif
		uint32_t sample_factor = zp_factor + (((uint32_t)inner_size) >> zp_scale);

		if (inner_size <= zp_tiny_zone_limit)
			poison = TRUE;
		else if (zp_factor != 0 && sample_counter(&zone->zp_count, sample_factor) == TRUE)
			poison = TRUE;

		if (__improbable(poison)) {

			/* memset_pattern{4|8} could help make this faster: <rdar://problem/4662004> */
			/* Poison everything but primary and backup */
			vm_offset_t *element_cursor  = ((vm_offset_t *) elem) + 1;
			vm_offset_t *backup   = get_backup_ptr(inner_size, (vm_offset_t *)elem);

			for ( ; element_cursor < backup; element_cursor++)
				*element_cursor = ZP_POISON;
		}
	}

	lock_zone(zone);

	/*
	 * See if we're doing logging on this zone.  There are two styles of logging used depending on
	 * whether we're trying to catch a leak or corruption.  See comments above in zalloc for details.
	 */

	if (__improbable(DO_LOGGING(zone))) {
		if (corruption_debug_flag) {
			/*
			 * We're logging to catch a corruption.  Add a record of this zfree operation
			 * to log.
			 */
			btlog_add_entry(zlog_btlog, (void *)addr, ZOP_FREE, (void **)zbt, numsaved);
		} else {
			/*
			 * We're logging to catch a leak. Remove any record we might have for this
			 * element since it's being freed.  Note that we may not find it if the buffer
			 * overflowed and that's OK.  Since the log is of a limited size, old records
			 * get overwritten if there are more zallocs than zfrees.
			 */
			btlog_remove_entries_for_element(zlog_btlog, (void *)addr);
		}
	}

#if	ZONE_DEBUG
	if (!gzfreed && zone_debug_enabled(zone)) {
		queue_t tmp_elem;

		elem -= ZONE_DEBUG_OFFSET;
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
		remqueue((queue_t) elem);
	}
#endif	/* ZONE_DEBUG */
	if (zone_check) {
		zone_check_freelist(zone, elem);
	}

	if (__probable(!gzfreed))
		free_to_zone(zone, elem, poison);

#if MACH_ASSERT
	if (zone->count < 0)
		panic("zfree: zone count underflow in zone %s while freeing element %p, possible cause: double frees or freeing memory that did not come from this zone",
		zone->zone_name, addr);
#endif
	

#if CONFIG_ZLEAKS
	/*
	 * Zone leak detection: un-track the allocation 
	 */
	if (zone->zleak_on) {
		zleak_free(elem, zone->elem_size);
	}
#endif /* CONFIG_ZLEAKS */
	
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

	{
		thread_t thr = current_thread();
		task_t task;
		zinfo_usage_t zinfo;
		vm_size_t sz = zone->elem_size;

		if (zone->caller_acct)
			ledger_debit(thr->t_ledger, task_ledgers.tkm_private, sz);
		else
			ledger_debit(thr->t_ledger, task_ledgers.tkm_shared, sz);

		if ((task = thr->task) != NULL && (zinfo = task->tkm_zinfo) != NULL)
			OSAddAtomic64(sz, (int64_t *)&zinfo[zone->index].free);
	}
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
	        case Z_NOENCRYPT:
			zone->noencrypt = value;
			break;
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
		case Z_CALLERACCT:
			zone->caller_acct = value;
			break;
		case Z_NOCALLOUT:
			zone->no_callout = value;
			break;
		case Z_GZALLOC_EXEMPT:
			zone->gzalloc_exempt = value;
#if	CONFIG_GZALLOC
			gzalloc_reconfigure(zone);
#endif
			break;
		case Z_ALIGNMENT_REQUIRED:
			zone->alignment_required = value;
			/*
			 * Disable the page list optimization here to provide
			 * more of an alignment guarantee. This prevents
			 * the alignment from being modified by the metadata stored
			 * at the beginning of the page.
			 */
			zone->use_page_list = FALSE;
#if	ZONE_DEBUG			
			zone_debug_disable(zone);
#endif
#if	CONFIG_GZALLOC
			gzalloc_reconfigure(zone);
#endif
			break;
		default:
			panic("Zone_change: Wrong Item Type!");
			/* break; */
	}
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
	free_count = zone->countfree;
	unlock_zone(zone);

	assert(free_count >= 0);

	return(free_count);
}

/*
 *  Zone garbage collection subroutines
 */

boolean_t
zone_page_collectable(
	vm_offset_t	addr,
	vm_size_t	size)
{
	struct zone_page_table_entry	*zp;
	zone_page_index_t i, j;

#if	ZONE_ALIAS_ADDR
	addr = zone_virtual_addr(addr);
#endif
#if MACH_ASSERT
	if (!from_zone_map(addr, size))
		panic("zone_page_collectable");
#endif

	i = (zone_page_index_t)atop_kernel(addr-zone_map_min_address);
	j = (zone_page_index_t)atop_kernel((addr+size-1) - zone_map_min_address);

	for (; i <= j; i++) {
		zp = zone_page_table_lookup(i);
		if (zp->collect_count == zp->alloc_count)
			return (TRUE);
	}

	return (FALSE);
}

void
zone_page_keep(
	vm_offset_t	addr,
	vm_size_t	size)
{
	struct zone_page_table_entry	*zp;
	zone_page_index_t i, j;

#if	ZONE_ALIAS_ADDR
	addr = zone_virtual_addr(addr);
#endif
#if MACH_ASSERT
	if (!from_zone_map(addr, size))
		panic("zone_page_keep");
#endif

	i = (zone_page_index_t)atop_kernel(addr-zone_map_min_address);
	j = (zone_page_index_t)atop_kernel((addr+size-1) - zone_map_min_address);

	for (; i <= j; i++) {
		zp = zone_page_table_lookup(i);
		zp->collect_count = 0;
	}
}

void
zone_page_collect(
	vm_offset_t	addr,
	vm_size_t	size)
{
	struct zone_page_table_entry	*zp;
	zone_page_index_t i, j;

#if	ZONE_ALIAS_ADDR
	addr = zone_virtual_addr(addr);
#endif
#if MACH_ASSERT
	if (!from_zone_map(addr, size))
		panic("zone_page_collect");
#endif

	i = (zone_page_index_t)atop_kernel(addr-zone_map_min_address);
	j = (zone_page_index_t)atop_kernel((addr+size-1) - zone_map_min_address);

	for (; i <= j; i++) {
		zp = zone_page_table_lookup(i);
		++zp->collect_count;
	}
}

void
zone_page_init(
	vm_offset_t	addr,
	vm_size_t	size)
{
	struct zone_page_table_entry	*zp;
	zone_page_index_t i, j;

#if	ZONE_ALIAS_ADDR
	addr = zone_virtual_addr(addr);
#endif
#if MACH_ASSERT
	if (!from_zone_map(addr, size))
		panic("zone_page_init");
#endif

	i = (zone_page_index_t)atop_kernel(addr-zone_map_min_address);
	j = (zone_page_index_t)atop_kernel((addr+size-1) - zone_map_min_address);

	for (; i <= j; i++) {
		/* make sure entry exists before marking unused */
		zone_page_table_expand(i);

		zp = zone_page_table_lookup(i);
		assert(zp);
		zp->alloc_count = ZONE_PAGE_UNUSED;
		zp->collect_count = 0;
	}
}

void
zone_page_alloc(
	vm_offset_t	addr,
	vm_size_t	size)
{
	struct zone_page_table_entry	*zp;
	zone_page_index_t i, j;

#if	ZONE_ALIAS_ADDR
	addr = zone_virtual_addr(addr);
#endif
#if MACH_ASSERT
	if (!from_zone_map(addr, size))
		panic("zone_page_alloc");
#endif

	i = (zone_page_index_t)atop_kernel(addr-zone_map_min_address);
	j = (zone_page_index_t)atop_kernel((addr+size-1) - zone_map_min_address);

	for (; i <= j; i++) {
		zp = zone_page_table_lookup(i);
		assert(zp);

		/*
		 * Set alloc_count to ZONE_PAGE_USED if
		 * it was previously set to ZONE_PAGE_UNUSED.
		 */
		if (zp->alloc_count == ZONE_PAGE_UNUSED)
			zp->alloc_count = ZONE_PAGE_USED;

		++zp->alloc_count;
	}
}

void
zone_page_free_element(
	zone_page_index_t	*free_page_head,
	zone_page_index_t	*free_page_tail,
	vm_offset_t	addr,
	vm_size_t	size)
{
	struct zone_page_table_entry	*zp;
	zone_page_index_t i, j;

#if	ZONE_ALIAS_ADDR
	addr = zone_virtual_addr(addr);
#endif
#if MACH_ASSERT
	if (!from_zone_map(addr, size))
		panic("zone_page_free_element");
#endif

	/* Clear out the old next and backup pointers */
	vm_offset_t *primary  = (vm_offset_t *) addr;
	vm_offset_t *backup   = get_backup_ptr(size, primary);

	*primary = ZP_POISON;
	*backup  = ZP_POISON;

	i = (zone_page_index_t)atop_kernel(addr-zone_map_min_address);
	j = (zone_page_index_t)atop_kernel((addr+size-1) - zone_map_min_address);

	for (; i <= j; i++) {
		zp = zone_page_table_lookup(i);

		if (zp->collect_count > 0)
			--zp->collect_count;
		if (--zp->alloc_count == 0) {
			vm_address_t        free_page_address;
			vm_address_t        prev_free_page_address;

			zp->alloc_count  = ZONE_PAGE_UNUSED;
			zp->collect_count = 0;


			/*
			 * This element was the last one on this page, re-use the page's
			 * storage for a page freelist
			 */
			free_page_address = zone_map_min_address + PAGE_SIZE * ((vm_size_t)i);
			*(zone_page_index_t *)free_page_address = ZONE_PAGE_INDEX_INVALID;

			if (*free_page_head == ZONE_PAGE_INDEX_INVALID) {
				*free_page_head = i;
				*free_page_tail = i;
			} else {
				prev_free_page_address = zone_map_min_address + PAGE_SIZE * ((vm_size_t)(*free_page_tail));
				*(zone_page_index_t *)prev_free_page_address = i;
				*free_page_tail = i;
			}
		}
	}
}


#define ZONEGC_SMALL_ELEMENT_SIZE 	4096

struct {
	uint64_t	zgc_invoked;
	uint64_t	zgc_bailed;
	uint32_t	pgs_freed;

	uint32_t	elems_collected,
				elems_freed,
				elems_kept;
} zgc_stats;

/*	Zone garbage collection
 *
 *	zone_gc will walk through all the free elements in all the
 *	zones that are marked collectable looking for reclaimable
 *	pages.  zone_gc is called by consider_zone_gc when the system
 *	begins to run out of memory.
 */
void
zone_gc(boolean_t all_zones)
{
	unsigned int	max_zones;
	zone_t			z;
	unsigned int	i;
	uint32_t 	old_pgs_freed;
	zone_page_index_t zone_free_page_head;
	zone_page_index_t zone_free_page_tail;
	thread_t	mythread = current_thread();

	lck_mtx_lock(&zone_gc_lock);

	zgc_stats.zgc_invoked++;
	old_pgs_freed = zgc_stats.pgs_freed;

	simple_lock(&all_zones_lock);
	max_zones = num_zones;
	z = first_zone;
	simple_unlock(&all_zones_lock);

	if (zalloc_debug & ZALLOC_DEBUG_ZONEGC)
		kprintf("zone_gc(all_zones=%s) starting...\n", all_zones ? "TRUE" : "FALSE");

	/*
	 * it's ok to allow eager kernel preemption while
	 * while holding a zone lock since it's taken
	 * as a spin lock (which prevents preemption)
	 */
	thread_set_eager_preempt(mythread);

#if MACH_ASSERT
	for (i = 0; i < zone_pages; i++) {
		struct zone_page_table_entry	*zp;
	
		zp = zone_page_table_lookup(i);
		assert(!zp || (zp->collect_count == 0));
	}
#endif /* MACH_ASSERT */

	for (i = 0; i < max_zones; i++, z = z->next_zone) {
		unsigned int			n, m;
		vm_size_t			elt_size, size_freed;
		struct zone_free_element	*elt, *base_elt, *base_prev, *prev, *scan, *keep, *tail;
		int				kmem_frees = 0, total_freed_pages = 0;
		struct zone_page_metadata		*page_meta;
		queue_head_t	page_meta_head;

		assert(z != ZONE_NULL);

		if (!z->collectable)
			continue;

		if (all_zones == FALSE && z->elem_size < ZONEGC_SMALL_ELEMENT_SIZE && !z->use_page_list)
			continue;

		lock_zone(z);

		elt_size = z->elem_size;

		/*
		 * Do a quick feasibility check before we scan the zone: 
		 * skip unless there is likelihood of getting pages back
		 * (i.e we need a whole allocation block's worth of free
		 * elements before we can garbage collect) and
		 * the zone has more than 10 percent of it's elements free
		 * or the element size is a multiple of the PAGE_SIZE 
		 */
		if ((elt_size & PAGE_MASK) && 
		    !z->use_page_list &&
		     (((z->cur_size - z->count * elt_size) <= (2 * z->alloc_size)) ||
		      ((z->cur_size - z->count * elt_size) <= (z->cur_size / 10)))) {
			unlock_zone(z);		
			continue;
		}

		z->doing_gc = TRUE;

		/*
		 * Snatch all of the free elements away from the zone.
		 */

		if (z->use_page_list) {
			queue_new_head(&z->pages.all_free, &page_meta_head, struct zone_page_metadata *, pages);
			queue_init(&z->pages.all_free);
		} else {
			scan = (void *)z->free_elements;
			z->free_elements = 0;
		}

		unlock_zone(z);

		if (z->use_page_list) {
			/*
			 * For zones that maintain page lists (which in turn
			 * track free elements on those pages), zone_gc()
			 * is incredibly easy, and we bypass all the logic
			 * for scanning elements and mapping them to
			 * collectable pages
			 */

			size_freed = 0;

			queue_iterate(&page_meta_head, page_meta, struct zone_page_metadata *, pages) {
				assert(from_zone_map((vm_address_t)page_meta, sizeof(*page_meta))); /* foreign elements should be in any_free_foreign */

				zgc_stats.elems_freed += page_meta->free_count;
				size_freed += elt_size * page_meta->free_count;
				zgc_stats.elems_collected += page_meta->free_count;
			}
			
			lock_zone(z);

			if (size_freed > 0) {
				z->cur_size -= size_freed;
				z->countfree -= size_freed/elt_size;
			}

			z->doing_gc = FALSE;
			if (z->waiting) {
				z->waiting = FALSE;
				zone_wakeup(z);
			}

			unlock_zone(z);

			if (queue_empty(&page_meta_head))
				continue;

			thread_clear_eager_preempt(mythread);

			while ((page_meta = (struct zone_page_metadata *)dequeue_head(&page_meta_head)) != NULL) {
				vm_address_t		free_page_address;

				free_page_address = trunc_page((vm_address_t)page_meta);
#if	ZONE_ALIAS_ADDR
				free_page_address = zone_virtual_addr(free_page_address);
#endif
				kmem_free(zone_map, free_page_address, PAGE_SIZE);
				ZONE_PAGE_COUNT_DECR(z, 1);
				total_freed_pages++;
				zgc_stats.pgs_freed += 1;
				
				if (++kmem_frees == 32) {
					thread_yield_internal(1);
					kmem_frees = 0;
				}
			}

			if (zalloc_debug & ZALLOC_DEBUG_ZONEGC)
				kprintf("zone_gc() of zone %s freed %lu elements, %d pages\n", z->zone_name, (unsigned long)size_freed/elt_size, total_freed_pages);

			thread_set_eager_preempt(mythread);
			continue; /* go to next zone */
		}

		/*
		 * Pass 1:
		 *
		 * Determine which elements we can attempt to collect
		 * and count them up in the page table.  Foreign elements
		 * are returned to the zone.
		 */

		prev = (void *)&scan;
		elt = scan;
		n = 0; tail = keep = NULL;

		zone_free_page_head = ZONE_PAGE_INDEX_INVALID;
		zone_free_page_tail = ZONE_PAGE_INDEX_INVALID;


		while (elt != NULL) {
			if (from_zone_map(elt, elt_size)) {
				zone_page_collect((vm_offset_t)elt, elt_size);

				prev = elt;
				elt = elt->next;

				++zgc_stats.elems_collected;
			}
			else {
				if (keep == NULL)
					keep = tail = elt;
				else {
					append_zone_element(z, tail, elt);
					tail = elt;
				}

				append_zone_element(z, prev, elt->next);
				elt = elt->next;
				append_zone_element(z, tail, NULL);
			}

			/*
			 * Dribble back the elements we are keeping.
			 * If there are none, give some elements that we haven't looked at yet
			 * back to the freelist so that others waiting on the zone don't get stuck
			 * for too long.  This might prevent us from recovering some memory,
			 * but allows us to avoid having to allocate new memory to serve requests
			 * while zone_gc has all the free memory tied up.
			 * <rdar://problem/3893406>
			 */

			if (++n >= 50) {
				if (z->waiting == TRUE) {
					/* z->waiting checked without lock held, rechecked below after locking */
					lock_zone(z);

					if (keep != NULL) {
						add_list_to_zone(z, keep, tail);
						tail = keep = NULL;
					} else {
						m =0;
						base_elt = elt;
						base_prev = prev;
						while ((elt != NULL) && (++m < 50)) { 
							prev = elt;
							elt = elt->next;
						}
						if (m !=0 ) {
							/* Extract the elements from the list and
							 * give them back */
							append_zone_element(z, prev, NULL);
							add_list_to_zone(z, base_elt, prev);
							append_zone_element(z, base_prev, elt);
							prev = base_prev;
						}
					}

					if (z->waiting) {
						z->waiting = FALSE;
						zone_wakeup(z);
					}

					unlock_zone(z);
				}
				n =0;
			}
		}

		/*
		 * Return any remaining elements.
		 */

		if (keep != NULL) {
			lock_zone(z);

			add_list_to_zone(z, keep, tail);

			if (z->waiting) {
				z->waiting = FALSE;
				zone_wakeup(z);
			}

			unlock_zone(z);
		}

		/*
		 * Pass 2:
		 *
		 * Determine which pages we can reclaim and
		 * free those elements.
		 */

		size_freed = 0;
		elt = scan;
		n = 0; tail = keep = NULL;

		while (elt != NULL) {
			if (zone_page_collectable((vm_offset_t)elt, elt_size)) {
				struct zone_free_element *next_elt = elt->next;

				size_freed += elt_size;

				/*
				 * If this is the last allocation on the page(s),
				 * we may use their storage to maintain the linked
				 * list of free-able pages. So store elt->next because
				 * "elt" may be scribbled over.
				 */
				zone_page_free_element(&zone_free_page_head, &zone_free_page_tail, (vm_offset_t)elt, elt_size);

				elt = next_elt;

				++zgc_stats.elems_freed;
			}
			else {
				zone_page_keep((vm_offset_t)elt, elt_size);

				if (keep == NULL)
					keep = tail = elt;
				else {
					append_zone_element(z, tail, elt);
					tail = elt;
				}

				elt = elt->next;
				append_zone_element(z, tail, NULL);

				++zgc_stats.elems_kept;
			}

			/*
			 * Dribble back the elements we are keeping,
			 * and update the zone size info.
			 */

			if (++n >= 50) {
				lock_zone(z);

				z->cur_size -= size_freed;
				z->countfree -= size_freed/elt_size;
				size_freed = 0;

				if (keep != NULL) {
					add_list_to_zone(z, keep, tail);
				}

				if (z->waiting) {
					z->waiting = FALSE;
					zone_wakeup(z);
				}

				unlock_zone(z);

				n = 0; tail = keep = NULL;
			}
		}

		/*
		 * Return any remaining elements, and update
		 * the zone size info.
		 */

		lock_zone(z);

		if (size_freed > 0 || keep != NULL) {

			z->cur_size -= size_freed;
			z->countfree -= size_freed/elt_size;

			if (keep != NULL) {
				add_list_to_zone(z, keep, tail);
			}

		}

		z->doing_gc = FALSE;
		if (z->waiting) {
			z->waiting = FALSE;
			zone_wakeup(z);
		}
		unlock_zone(z);

		if (zone_free_page_head == ZONE_PAGE_INDEX_INVALID)
			continue;

		/*
		 * we don't want to allow eager kernel preemption while holding the
		 * various locks taken in the kmem_free path of execution
		 */
		thread_clear_eager_preempt(mythread);


		/*
		 * This loop counts the number of pages that should be freed by the
		 * next loop that tries to coalesce the kmem_frees()
		 */
		uint32_t pages_to_free_count = 0;
		vm_address_t		fpa;
		zone_page_index_t index;
		for (index = zone_free_page_head; index != ZONE_PAGE_INDEX_INVALID;) {
			pages_to_free_count++;
			fpa = zone_map_min_address + PAGE_SIZE * ((vm_size_t)index);
			index = *(zone_page_index_t *)fpa;
		}

		/*
		 * Reclaim the pages we are freeing.
		 */
		while (zone_free_page_head != ZONE_PAGE_INDEX_INVALID) {
			zone_page_index_t	zind = zone_free_page_head;
			vm_address_t		free_page_address;
			int			page_count;

			/*
			 * Use the first word of the page about to be freed to find the next free page
			 */
			free_page_address = zone_map_min_address + PAGE_SIZE * ((vm_size_t)zind);
			zone_free_page_head = *(zone_page_index_t *)free_page_address;

			page_count = 1;
			total_freed_pages++;

			while (zone_free_page_head != ZONE_PAGE_INDEX_INVALID) {
				zone_page_index_t	next_zind = zone_free_page_head;
				vm_address_t		next_free_page_address;

				next_free_page_address = zone_map_min_address + PAGE_SIZE * ((vm_size_t)next_zind);

				if (next_free_page_address == (free_page_address - PAGE_SIZE)) {
					free_page_address = next_free_page_address;
				} else if (next_free_page_address != (free_page_address + (PAGE_SIZE * page_count)))
					break;

				zone_free_page_head = *(zone_page_index_t *)next_free_page_address;
				page_count++;
				total_freed_pages++;
			}
			kmem_free(zone_map, free_page_address, page_count * PAGE_SIZE);
			ZONE_PAGE_COUNT_DECR(z, page_count);
			zgc_stats.pgs_freed += page_count;
			pages_to_free_count -= page_count;

			if (++kmem_frees == 32) {
				thread_yield_internal(1);
				kmem_frees = 0;
			}
		}

		/* Check that we actually free the exact number of pages we were supposed to */
		assert(pages_to_free_count == 0);

		if (zalloc_debug & ZALLOC_DEBUG_ZONEGC)
			kprintf("zone_gc() of zone %s freed %lu elements, %d pages\n", z->zone_name, (unsigned long)size_freed/elt_size, total_freed_pages);

		thread_set_eager_preempt(mythread);
	}

	if (old_pgs_freed == zgc_stats.pgs_freed)
		zgc_stats.zgc_bailed++;

	thread_clear_eager_preempt(mythread);

	lck_mtx_unlock(&zone_gc_lock);

}

extern vm_offset_t kmapoff_kaddr;
extern unsigned int kmapoff_pgcnt;

/*
 *	consider_zone_gc:
 *
 *	Called by the pageout daemon when the system needs more free pages.
 */

void
consider_zone_gc(boolean_t force)
{
	boolean_t all_zones = FALSE;

	if (kmapoff_kaddr != 0) {
		/*
		 * One-time reclaim of kernel_map resources we allocated in
		 * early boot.
		 */
		(void) vm_deallocate(kernel_map,
		    kmapoff_kaddr, kmapoff_pgcnt * PAGE_SIZE_64);
		kmapoff_kaddr = 0;
	}

	if (zone_gc_allowed &&
	    (zone_gc_allowed_by_time_throttle ||
	     zone_gc_forced ||
	     force)) {
		if (zone_gc_allowed_by_time_throttle == TRUE) {
			zone_gc_allowed_by_time_throttle = FALSE;
			all_zones = TRUE;
		}
		zone_gc_forced = FALSE;

		zone_gc(all_zones);
	}
}

/*
 *	By default, don't attempt zone GC more frequently
 *	than once / 1 minutes.
 */
void
compute_zone_gc_throttle(void *arg __unused)
{
	zone_gc_allowed_by_time_throttle = TRUE;
}


#if CONFIG_TASK_ZONE_INFO

kern_return_t
task_zone_info(
	task_t			task,
	mach_zone_name_array_t	*namesp,
	mach_msg_type_number_t  *namesCntp,
	task_zone_info_array_t	*infop,
	mach_msg_type_number_t  *infoCntp)
{
	mach_zone_name_t	*names;
	vm_offset_t		names_addr;
	vm_size_t		names_size;
	task_zone_info_t	*info;
	vm_offset_t		info_addr;
	vm_size_t		info_size;
	unsigned int		max_zones, i;
	zone_t			z;
	mach_zone_name_t	*zn;
	task_zone_info_t    	*zi;
	kern_return_t		kr;

	vm_size_t		used;
	vm_map_copy_t		copy;


	if (task == TASK_NULL)
		return KERN_INVALID_TASK;

	/*
	 *	We assume that zones aren't freed once allocated.
	 *	We won't pick up any zones that are allocated later.
	 */

	simple_lock(&all_zones_lock);
	max_zones = (unsigned int)(num_zones + num_fake_zones);
	z = first_zone;
	simple_unlock(&all_zones_lock);

	names_size = round_page(max_zones * sizeof *names);
	kr = kmem_alloc_pageable(ipc_kernel_map,
				 &names_addr, names_size, VM_KERN_MEMORY_IPC);
	if (kr != KERN_SUCCESS)
		return kr;
	names = (mach_zone_name_t *) names_addr;

	info_size = round_page(max_zones * sizeof *info);
	kr = kmem_alloc_pageable(ipc_kernel_map,
				 &info_addr, info_size, VM_KERN_MEMORY_IPC);
	if (kr != KERN_SUCCESS) {
		kmem_free(ipc_kernel_map,
			  names_addr, names_size);
		return kr;
	}

	info = (task_zone_info_t *) info_addr;

	zn = &names[0];
	zi = &info[0];

	for (i = 0; i < max_zones - num_fake_zones; i++) {
		struct zone zcopy;

		assert(z != ZONE_NULL);

		lock_zone(z);
		zcopy = *z;
		unlock_zone(z);

		simple_lock(&all_zones_lock);
		z = z->next_zone;
		simple_unlock(&all_zones_lock);

		/* assuming here the name data is static */
		(void) strncpy(zn->mzn_name, zcopy.zone_name,
			       sizeof zn->mzn_name);
		zn->mzn_name[sizeof zn->mzn_name - 1] = '\0';

		zi->tzi_count = (uint64_t)zcopy.count;
		zi->tzi_cur_size = ptoa_64(zcopy.page_count);
		zi->tzi_max_size = (uint64_t)zcopy.max_size;
		zi->tzi_elem_size = (uint64_t)zcopy.elem_size;
		zi->tzi_alloc_size = (uint64_t)zcopy.alloc_size;
		zi->tzi_sum_size = zcopy.sum_count * zcopy.elem_size;
		zi->tzi_exhaustible = (uint64_t)zcopy.exhaustible;
		zi->tzi_collectable = (uint64_t)zcopy.collectable;
		zi->tzi_caller_acct = (uint64_t)zcopy.caller_acct;
		if (task->tkm_zinfo != NULL) {
			zi->tzi_task_alloc = task->tkm_zinfo[zcopy.index].alloc;
			zi->tzi_task_free = task->tkm_zinfo[zcopy.index].free;
		} else {
			zi->tzi_task_alloc = 0;
			zi->tzi_task_free = 0;
		}
		zn++;
		zi++;
	}

	/*
	 * loop through the fake zones and fill them using the specialized
	 * functions
	 */
	for (i = 0; i < num_fake_zones; i++) {
		int count, collectable, exhaustible, caller_acct, index;
		vm_size_t cur_size, max_size, elem_size, alloc_size;
		uint64_t sum_size;

		strncpy(zn->mzn_name, fake_zones[i].name, sizeof zn->mzn_name);
		zn->mzn_name[sizeof zn->mzn_name - 1] = '\0';
		fake_zones[i].query(&count, &cur_size,
				    &max_size, &elem_size,
				    &alloc_size, &sum_size,
				    &collectable, &exhaustible, &caller_acct);
		zi->tzi_count = (uint64_t)count;
		zi->tzi_cur_size = (uint64_t)cur_size;
		zi->tzi_max_size = (uint64_t)max_size;
		zi->tzi_elem_size = (uint64_t)elem_size;
		zi->tzi_alloc_size = (uint64_t)alloc_size;
		zi->tzi_sum_size = sum_size;
		zi->tzi_collectable = (uint64_t)collectable;
		zi->tzi_exhaustible = (uint64_t)exhaustible;
		zi->tzi_caller_acct = (uint64_t)caller_acct;
		if (task->tkm_zinfo != NULL) {
			index = ZINFO_SLOTS - num_fake_zones + i;
			zi->tzi_task_alloc = task->tkm_zinfo[index].alloc;
			zi->tzi_task_free = task->tkm_zinfo[index].free;
		} else {
			zi->tzi_task_alloc = 0;
			zi->tzi_task_free = 0;
		}
		zn++;
		zi++;
	}

	used = max_zones * sizeof *names;
	if (used != names_size)
		bzero((char *) (names_addr + used), names_size - used);

	kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)names_addr,
			   (vm_map_size_t)used, TRUE, &copy);
	assert(kr == KERN_SUCCESS);

	*namesp = (mach_zone_name_t *) copy;
	*namesCntp = max_zones;

	used = max_zones * sizeof *info;

	if (used != info_size)
		bzero((char *) (info_addr + used), info_size - used);

	kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)info_addr,
			   (vm_map_size_t)used, TRUE, &copy);
	assert(kr == KERN_SUCCESS);

	*infop = (task_zone_info_t *) copy;
	*infoCntp = max_zones;

	return KERN_SUCCESS;
}

#else	/* CONFIG_TASK_ZONE_INFO */

kern_return_t
task_zone_info(
	__unused task_t		task,
	__unused mach_zone_name_array_t *namesp,
	__unused mach_msg_type_number_t *namesCntp,
	__unused task_zone_info_array_t *infop,
	__unused mach_msg_type_number_t *infoCntp)
{
	return KERN_FAILURE;
}

#endif	/* CONFIG_TASK_ZONE_INFO */

kern_return_t
mach_zone_info(
	host_priv_t		host,
	mach_zone_name_array_t	*namesp,
	mach_msg_type_number_t  *namesCntp,
	mach_zone_info_array_t	*infop,
	mach_msg_type_number_t  *infoCntp)
{
	return (mach_memory_info(host, namesp, namesCntp, infop, infoCntp, NULL, NULL));
}

kern_return_t
mach_memory_info(
	host_priv_t		host,
	mach_zone_name_array_t	*namesp,
	mach_msg_type_number_t  *namesCntp,
	mach_zone_info_array_t	*infop,
	mach_msg_type_number_t  *infoCntp,
	mach_memory_info_array_t *memoryInfop,
	mach_msg_type_number_t   *memoryInfoCntp)
{
	mach_zone_name_t	*names;
	vm_offset_t		names_addr;
	vm_size_t		names_size;

	mach_zone_info_t	*info;
	vm_offset_t		info_addr;
	vm_size_t		info_size;

	mach_memory_info_t	*memory_info;
	vm_offset_t		memory_info_addr;
	vm_size_t		memory_info_size;
	vm_size_t		memory_info_vmsize;
        unsigned int		num_sites;

	unsigned int		max_zones, i;
	zone_t			z;
	mach_zone_name_t	*zn;
	mach_zone_info_t    	*zi;
	kern_return_t		kr;
	
	vm_size_t		used;
	vm_map_copy_t		copy;


	if (host == HOST_NULL)
		return KERN_INVALID_HOST;
#if CONFIG_DEBUGGER_FOR_ZONE_INFO
	if (!PE_i_can_has_debugger(NULL))
		return KERN_INVALID_HOST;
#endif

	/*
	 *	We assume that zones aren't freed once allocated.
	 *	We won't pick up any zones that are allocated later.
	 */

	simple_lock(&all_zones_lock);
	max_zones = (unsigned int)(num_zones + num_fake_zones);
	z = first_zone;
	simple_unlock(&all_zones_lock);

	names_size = round_page(max_zones * sizeof *names);
	kr = kmem_alloc_pageable(ipc_kernel_map,
				 &names_addr, names_size, VM_KERN_MEMORY_IPC);
	if (kr != KERN_SUCCESS)
		return kr;
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

	num_sites = 0;
	memory_info_addr = 0;
	if (memoryInfop && memoryInfoCntp)
	{
		num_sites = VM_KERN_MEMORY_COUNT + VM_KERN_COUNTER_COUNT;
		memory_info_size = num_sites * sizeof(*info);
		memory_info_vmsize = round_page(memory_info_size);
		kr = kmem_alloc_pageable(ipc_kernel_map,
					 &memory_info_addr, memory_info_vmsize, VM_KERN_MEMORY_IPC);
		if (kr != KERN_SUCCESS) {
			kmem_free(ipc_kernel_map,
				  names_addr, names_size);
			kmem_free(ipc_kernel_map,
				  info_addr, info_size);
			return kr;
		}

		kr = vm_map_wire(ipc_kernel_map, memory_info_addr, memory_info_addr + memory_info_vmsize,
				     VM_PROT_READ|VM_PROT_WRITE|VM_PROT_MEMORY_TAG_MAKE(VM_KERN_MEMORY_IPC), FALSE);
		assert(kr == KERN_SUCCESS);

		memory_info = (mach_memory_info_t *) memory_info_addr;
		vm_page_diagnose(memory_info, num_sites);

		kr = vm_map_unwire(ipc_kernel_map, memory_info_addr, memory_info_addr + memory_info_vmsize, FALSE);
		assert(kr == KERN_SUCCESS);
	}

	zn = &names[0];
	zi = &info[0];

	for (i = 0; i < max_zones - num_fake_zones; i++) {
		struct zone zcopy;

		assert(z != ZONE_NULL);

		lock_zone(z);
		zcopy = *z;
		unlock_zone(z);

		simple_lock(&all_zones_lock);
		z = z->next_zone;
		simple_unlock(&all_zones_lock);

		/* assuming here the name data is static */
		(void) strncpy(zn->mzn_name, zcopy.zone_name,
			       sizeof zn->mzn_name);
		zn->mzn_name[sizeof zn->mzn_name - 1] = '\0';

		zi->mzi_count = (uint64_t)zcopy.count;
		zi->mzi_cur_size = ptoa_64(zcopy.page_count);
		zi->mzi_max_size = (uint64_t)zcopy.max_size;
		zi->mzi_elem_size = (uint64_t)zcopy.elem_size;
		zi->mzi_alloc_size = (uint64_t)zcopy.alloc_size;
		zi->mzi_sum_size = zcopy.sum_count * zcopy.elem_size;
		zi->mzi_exhaustible = (uint64_t)zcopy.exhaustible;
		zi->mzi_collectable = (uint64_t)zcopy.collectable;
		zn++;
		zi++;
	}

	/*
	 * loop through the fake zones and fill them using the specialized
	 * functions
	 */
	for (i = 0; i < num_fake_zones; i++) {
		int count, collectable, exhaustible, caller_acct;
		vm_size_t cur_size, max_size, elem_size, alloc_size;
		uint64_t sum_size;

		strncpy(zn->mzn_name, fake_zones[i].name, sizeof zn->mzn_name);
		zn->mzn_name[sizeof zn->mzn_name - 1] = '\0';
		fake_zones[i].query(&count, &cur_size,
				    &max_size, &elem_size,
				    &alloc_size, &sum_size,
				    &collectable, &exhaustible, &caller_acct);
		zi->mzi_count = (uint64_t)count;
		zi->mzi_cur_size = (uint64_t)cur_size;
		zi->mzi_max_size = (uint64_t)max_size;
		zi->mzi_elem_size = (uint64_t)elem_size;
		zi->mzi_alloc_size = (uint64_t)alloc_size;
		zi->mzi_sum_size = sum_size;
		zi->mzi_collectable = (uint64_t)collectable;
		zi->mzi_exhaustible = (uint64_t)exhaustible;

		zn++;
		zi++;
	}

	used = max_zones * sizeof *names;
	if (used != names_size)
		bzero((char *) (names_addr + used), names_size - used);

	kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)names_addr,
			   (vm_map_size_t)used, TRUE, &copy);
	assert(kr == KERN_SUCCESS);

	*namesp = (mach_zone_name_t *) copy;
	*namesCntp = max_zones;

	used = max_zones * sizeof *info;

	if (used != info_size)
		bzero((char *) (info_addr + used), info_size - used);

	kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)info_addr,
			   (vm_map_size_t)used, TRUE, &copy);
	assert(kr == KERN_SUCCESS);

	*infop = (mach_zone_info_t *) copy;
	*infoCntp = max_zones;

	if (memoryInfop && memoryInfoCntp)
	{
		kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)memory_info_addr,
				   (vm_map_size_t)memory_info_size, TRUE, &copy);
		assert(kr == KERN_SUCCESS);

		*memoryInfop = (mach_memory_info_t *) copy;
		*memoryInfoCntp = num_sites;
	}

	return KERN_SUCCESS;
}

/*
 * host_zone_info - LEGACY user interface for Mach zone information
 * 		    Should use mach_zone_info() instead!
 */
kern_return_t
host_zone_info(
	host_priv_t		host,
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

	vm_size_t	used;
	vm_map_copy_t	copy;


	if (host == HOST_NULL)
		return KERN_INVALID_HOST;
#if CONFIG_DEBUGGER_FOR_ZONE_INFO
	if (!PE_i_can_has_debugger(NULL))
		return KERN_INVALID_HOST;
#endif

#if defined(__LP64__)
	if (!thread_is_64bit(current_thread()))
		return KERN_NOT_SUPPORTED;
#else
	if (thread_is_64bit(current_thread()))
		return KERN_NOT_SUPPORTED;
#endif

	/*
	 *	We assume that zones aren't freed once allocated.
	 *	We won't pick up any zones that are allocated later.
	 */

	simple_lock(&all_zones_lock);
	max_zones = (unsigned int)(num_zones + num_fake_zones);
	z = first_zone;
	simple_unlock(&all_zones_lock);

	names_size = round_page(max_zones * sizeof *names);
	kr = kmem_alloc_pageable(ipc_kernel_map,
				 &names_addr, names_size, VM_KERN_MEMORY_IPC);
	if (kr != KERN_SUCCESS)
		return kr;
	names = (zone_name_t *) names_addr;

	info_size = round_page(max_zones * sizeof *info);
	kr = kmem_alloc_pageable(ipc_kernel_map,
				 &info_addr, info_size, VM_KERN_MEMORY_IPC);
	if (kr != KERN_SUCCESS) {
		kmem_free(ipc_kernel_map,
			  names_addr, names_size);
		return kr;
	}

	info = (zone_info_t *) info_addr;

	zn = &names[0];
	zi = &info[0];

	for (i = 0; i < max_zones - num_fake_zones; i++) {
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
		zn->zn_name[sizeof zn->zn_name - 1] = '\0';

		zi->zi_count = zcopy.count;
		zi->zi_cur_size = ptoa(zcopy.page_count);
		zi->zi_max_size = zcopy.max_size;
		zi->zi_elem_size = zcopy.elem_size;
		zi->zi_alloc_size = zcopy.alloc_size;
		zi->zi_exhaustible = zcopy.exhaustible;
		zi->zi_collectable = zcopy.collectable;

		zn++;
		zi++;
	}

	/*
	 * loop through the fake zones and fill them using the specialized
	 * functions
	 */
	for (i = 0; i < num_fake_zones; i++) {
		int caller_acct;
		uint64_t sum_space;
		strncpy(zn->zn_name, fake_zones[i].name, sizeof zn->zn_name);
		zn->zn_name[sizeof zn->zn_name - 1] = '\0';
		fake_zones[i].query(&zi->zi_count, &zi->zi_cur_size,
				    &zi->zi_max_size, &zi->zi_elem_size,
				    &zi->zi_alloc_size, &sum_space,
				    &zi->zi_collectable, &zi->zi_exhaustible, &caller_acct);
		zn++;
		zi++;
	}

	used = max_zones * sizeof *names;
	if (used != names_size)
		bzero((char *) (names_addr + used), names_size - used);

	kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)names_addr,
			   (vm_map_size_t)used, TRUE, &copy);
	assert(kr == KERN_SUCCESS);

	*namesp = (zone_name_t *) copy;
	*namesCntp = max_zones;

	used = max_zones * sizeof *info;
	if (used != info_size)
		bzero((char *) (info_addr + used), info_size - used);

	kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)info_addr,
			   (vm_map_size_t)used, TRUE, &copy);
	assert(kr == KERN_SUCCESS);

	*infop = (zone_info_t *) copy;
	*infoCntp = max_zones;

	return KERN_SUCCESS;
}

kern_return_t
mach_zone_force_gc(
	host_t host)
{

	if (host == HOST_NULL)
		return KERN_INVALID_HOST;

	consider_zone_gc(TRUE);

	return (KERN_SUCCESS);
}

extern unsigned int stack_total;
extern unsigned long long stack_allocs;

#if defined(__i386__) || defined (__x86_64__)
extern unsigned int inuse_ptepages_count;
extern long long alloc_ptepages_count;
#endif

void zone_display_zprint()
{
	unsigned int    i;
	zone_t		the_zone;

	if(first_zone!=NULL) {
		the_zone = first_zone;
		for (i = 0; i < num_zones; i++) {
			if(the_zone->cur_size > (1024*1024)) {
				printf("%.20s:\t%lu\n",the_zone->zone_name,(uintptr_t)the_zone->cur_size);
			}

			if(the_zone->next_zone == NULL) {
				break;
			}

			the_zone = the_zone->next_zone;
		}
	}

	printf("Kernel Stacks:\t%lu\n",(uintptr_t)(kernel_stack_size * stack_total));

#if defined(__i386__) || defined (__x86_64__)
	printf("PageTables:\t%lu\n",(uintptr_t)(PAGE_SIZE * inuse_ptepages_count));
#endif

	printf("Kalloc.Large:\t%lu\n",(uintptr_t)kalloc_large_total);
}

zone_t
zone_find_largest(void)
{
	unsigned int    i;
	unsigned int    max_zones;
	zone_t 	        the_zone;
	zone_t          zone_largest;

	simple_lock(&all_zones_lock);
	the_zone = first_zone;
	max_zones = num_zones;
	simple_unlock(&all_zones_lock);
	
	zone_largest = the_zone;
	for (i = 0; i < max_zones; i++) {
		if (the_zone->cur_size > zone_largest->cur_size) {
			zone_largest = the_zone;
		}

		if (the_zone->next_zone == NULL) {
			break;
		}

		the_zone = the_zone->next_zone;
	}
	return zone_largest;
}

#if	ZONE_DEBUG

/* should we care about locks here ? */

#define zone_in_use(z) 	( z->count || z->free_elements \
						  || !queue_empty(&z->pages.all_free) \
						  || !queue_empty(&z->pages.intermediate) \
						  || (z->allows_foreign && !queue_empty(&z->pages.any_free_foreign)))

void
zone_debug_enable(
	zone_t		z)
{
	if (zone_debug_enabled(z) || zone_in_use(z) ||
	    z->alloc_size < (z->elem_size + ZONE_DEBUG_OFFSET))
		return;
	queue_init(&z->active_zones);
	z->elem_size += ZONE_DEBUG_OFFSET;
}

void
zone_debug_disable(
	zone_t		z)
{
	if (!zone_debug_enabled(z) || zone_in_use(z))
		return;
	z->elem_size -= ZONE_DEBUG_OFFSET;
	z->active_zones.next = z->active_zones.prev = NULL;
}


#endif	/* ZONE_DEBUG */
