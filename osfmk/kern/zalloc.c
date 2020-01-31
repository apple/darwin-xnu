/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
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

#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <mach/kern_return.h>
#include <mach/mach_host_server.h>
#include <mach/task_server.h>
#include <mach/machine/vm_types.h>
#include <mach/vm_map.h>
#include <mach/sdt.h>

#include <kern/bits.h>
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
#include <kern/zalloc.h>
#include <kern/kalloc.h>

#include <prng/random.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>

#include <pexpert/pexpert.h>

#include <machine/machparam.h>
#include <machine/machine_routines.h>  /* ml_cpu_get_info */

#include <libkern/OSDebug.h>
#include <libkern/OSAtomic.h>
#include <libkern/section_keywords.h>
#include <sys/kdebug.h>

#include <san/kasan.h>

/*
 *	The zone_locks_grp allows for collecting lock statistics.
 *	All locks are associated to this group in zinit.
 *	Look at tools/lockstat for debugging lock contention.
 */

lck_grp_t       zone_locks_grp;
lck_grp_attr_t  zone_locks_grp_attr;

/*
 *  ZONE_ALIAS_ADDR (deprecated)
 */

#define from_zone_map(addr, size) \
	((vm_offset_t)(addr)             >= zone_map_min_address && \
	((vm_offset_t)(addr) + size - 1) <  zone_map_max_address )

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

boolean_t zfree_poison_element(zone_t zone, vm_offset_t elem);
void zalloc_poison_element(boolean_t check_poison, zone_t zone, vm_offset_t addr);

#define ZP_DEFAULT_SAMPLING_FACTOR 16
#define ZP_DEFAULT_SCALE_FACTOR 4

/*
 *  A zp_factor of 0 indicates zone poisoning is disabled,
 *  however, we still poison zones smaller than zp_tiny_zone_limit (a cacheline).
 *  Passing the -no-zp boot-arg disables even this behavior.
 *  In all cases, we record and check the integrity of a backup pointer.
 */

/* set by zp-factor=N boot arg, zero indicates non-tiny poisoning disabled */
#if DEBUG
#define DEFAULT_ZP_FACTOR (1)
#else
#define DEFAULT_ZP_FACTOR (0)
#endif
uint32_t        zp_factor               = DEFAULT_ZP_FACTOR;

/* set by zp-scale=N boot arg, scales zp_factor by zone size */
uint32_t        zp_scale                = 0;

/* set in zp_init, zero indicates -no-zp boot-arg */
vm_size_t       zp_tiny_zone_limit      = 0;

/* initialized to a per-boot random value in zp_init */
uintptr_t       zp_poisoned_cookie      = 0;
uintptr_t       zp_nopoison_cookie      = 0;

#if VM_MAX_TAG_ZONES
boolean_t       zone_tagging_on;
#endif /* VM_MAX_TAG_ZONES */

SECURITY_READ_ONLY_LATE(boolean_t) copyio_zalloc_check = TRUE;
static struct bool_gen zone_bool_gen;

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

		if (rand_bits == 0x1) {
			zp_factor += 1;
		} else if (rand_bits == 0x2) {
			zp_factor -= 1;
		}
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
	if (zp_poisoned_cookie == zp_nopoison_cookie) {
		panic("early_random() is broken: %p and %p are not random\n",
		    (void *) zp_poisoned_cookie, (void *) zp_nopoison_cookie);
	}
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

/*
 * These macros are used to keep track of the number
 * of pages being used by the zone currently. The
 * z->page_count is not protected by the zone lock.
 */
#define ZONE_PAGE_COUNT_INCR(z, count)          \
{                                               \
	OSAddAtomic64(count, &(z->page_count)); \
}

#define ZONE_PAGE_COUNT_DECR(z, count)                  \
{                                                       \
	OSAddAtomic64(-count, &(z->page_count));        \
}

vm_map_t        zone_map = VM_MAP_NULL;

/* for is_sane_zone_element and garbage collection */

vm_offset_t     zone_map_min_address = 0;  /* initialized in zone_init */
vm_offset_t     zone_map_max_address = 0;

/* Globals for random boolean generator for elements in free list */
#define MAX_ENTROPY_PER_ZCRAM           4

/* VM region for all metadata structures */
vm_offset_t     zone_metadata_region_min = 0;
vm_offset_t     zone_metadata_region_max = 0;
decl_lck_mtx_data(static, zone_metadata_region_lck)
lck_attr_t      zone_metadata_lock_attr;
lck_mtx_ext_t   zone_metadata_region_lck_ext;

/* Helpful for walking through a zone's free element list. */
struct zone_free_element {
	struct zone_free_element *next;
	/* ... */
	/* void *backup_ptr; */
};

#if CONFIG_ZCACHE

#if !CONFIG_GZALLOC
bool use_caching = TRUE;
#else
bool use_caching = FALSE;
#endif /* !CONFIG_GZALLOC */

/*
 * Decides whether per-cpu zone caching is to be enabled for all zones.
 * Can be set to TRUE via the boot-arg '-zcache_all'.
 */
bool cache_all_zones = FALSE;

/*
 * Specifies a single zone to enable CPU caching for.
 * Can be set using boot-args: zcc_enable_for_zone_name=<zone>
 */
static char cache_zone_name[MAX_ZONE_NAME];

static inline bool
zone_caching_enabled(zone_t z)
{
	return z->cpu_cache_enabled && !z->tags && !z->zleak_on;
}

#endif /* CONFIG_ZCACHE */

/*
 *      Protects zone_array, num_zones, num_zones_in_use, and zone_empty_bitmap
 */
decl_simple_lock_data(, all_zones_lock)
unsigned int            num_zones_in_use;
unsigned int            num_zones;

#define MAX_ZONES       320
struct zone             zone_array[MAX_ZONES];

/* Used to keep track of empty slots in the zone_array */
bitmap_t zone_empty_bitmap[BITMAP_LEN(MAX_ZONES)];

#if DEBUG || DEVELOPMENT
/*
 * Used for sysctl kern.run_zone_test which is not thread-safe. Ensure only one thread goes through at a time.
 * Or we can end up with multiple test zones (if a second zinit() comes through before zdestroy()),  which could lead us to
 * run out of zones.
 */
decl_simple_lock_data(, zone_test_lock)
static boolean_t zone_test_running = FALSE;
static zone_t test_zone_ptr = NULL;
#endif /* DEBUG || DEVELOPMENT */

#define PAGE_METADATA_GET_ZINDEX(page_meta)                     \
	(page_meta->zindex)

#define PAGE_METADATA_GET_ZONE(page_meta)                               \
	(&(zone_array[page_meta->zindex]))

#define PAGE_METADATA_SET_ZINDEX(page_meta, index)              \
	page_meta->zindex = (index);

struct zone_page_metadata {
	queue_chain_t           pages; /* linkage pointer for metadata lists */

	/* Union for maintaining start of element free list and real metadata (for multipage allocations) */
	union {
		/*
		 * The start of the freelist can be maintained as a 32-bit offset instead of a pointer because
		 * the free elements would be at max ZONE_MAX_ALLOC_SIZE bytes away from the metadata. Offset
		 * from start of the allocation chunk to free element list head.
		 */
		uint32_t                freelist_offset;
		/*
		 * This field is used to lookup the real metadata for multipage allocations, where we mark the
		 * metadata for all pages except the first as "fake" metadata using MULTIPAGE_METADATA_MAGIC.
		 * Offset from this fake metadata to real metadata of allocation chunk (-ve offset).
		 */
		uint32_t                real_metadata_offset;
	};

	/*
	 * For the first page in the allocation chunk, this represents the total number of free elements in
	 * the chunk.
	 */
	uint16_t                        free_count;
	unsigned                        zindex     : ZINDEX_BITS;    /* Zone index within the zone_array */
	unsigned                        page_count : PAGECOUNT_BITS; /* Count of pages within the allocation chunk */
};

/* Macro to get page index (within zone_map) of page containing element */
#define PAGE_INDEX_FOR_ELEMENT(element)                         \
	(((vm_offset_t)trunc_page(element) - zone_map_min_address) / PAGE_SIZE)

/* Macro to get metadata structure given a page index in zone_map */
#define PAGE_METADATA_FOR_PAGE_INDEX(index)                     \
	(zone_metadata_region_min + ((index) * sizeof(struct zone_page_metadata)))

/* Macro to get index (within zone_map) for given metadata */
#define PAGE_INDEX_FOR_METADATA(page_meta)                      \
	(((vm_offset_t)page_meta - zone_metadata_region_min) / sizeof(struct zone_page_metadata))

/* Macro to get page for given page index in zone_map */
#define PAGE_FOR_PAGE_INDEX(index)                              \
	(zone_map_min_address + (PAGE_SIZE * (index)))

/* Macro to get the actual metadata for a given address */
#define PAGE_METADATA_FOR_ELEMENT(element)              \
	(struct zone_page_metadata *)(PAGE_METADATA_FOR_PAGE_INDEX(PAGE_INDEX_FOR_ELEMENT(element)))

/* Magic value to indicate empty element free list */
#define PAGE_METADATA_EMPTY_FREELIST            ((uint32_t)(~0))

vm_map_copy_t create_vm_map_copy(vm_offset_t start_addr, vm_size_t total_size, vm_size_t used_size);
boolean_t get_zone_info(zone_t z, mach_zone_name_t *zn, mach_zone_info_t *zi);
boolean_t is_zone_map_nearing_exhaustion(void);
extern void vm_pageout_garbage_collect(int collect);

static inline void *
page_metadata_get_freelist(struct zone_page_metadata *page_meta)
{
	assert(PAGE_METADATA_GET_ZINDEX(page_meta) != MULTIPAGE_METADATA_MAGIC);
	if (page_meta->freelist_offset == PAGE_METADATA_EMPTY_FREELIST) {
		return NULL;
	} else {
		if (from_zone_map(page_meta, sizeof(struct zone_page_metadata))) {
			return (void *)(PAGE_FOR_PAGE_INDEX(PAGE_INDEX_FOR_METADATA(page_meta)) + page_meta->freelist_offset);
		} else {
			return (void *)((vm_offset_t)page_meta + page_meta->freelist_offset);
		}
	}
}

static inline void
page_metadata_set_freelist(struct zone_page_metadata *page_meta, void *addr)
{
	assert(PAGE_METADATA_GET_ZINDEX(page_meta) != MULTIPAGE_METADATA_MAGIC);
	if (addr == NULL) {
		page_meta->freelist_offset = PAGE_METADATA_EMPTY_FREELIST;
	} else {
		if (from_zone_map(page_meta, sizeof(struct zone_page_metadata))) {
			page_meta->freelist_offset = (uint32_t)((vm_offset_t)(addr) - PAGE_FOR_PAGE_INDEX(PAGE_INDEX_FOR_METADATA(page_meta)));
		} else {
			page_meta->freelist_offset = (uint32_t)((vm_offset_t)(addr) - (vm_offset_t)page_meta);
		}
	}
}

static inline struct zone_page_metadata *
page_metadata_get_realmeta(struct zone_page_metadata *page_meta)
{
	assert(PAGE_METADATA_GET_ZINDEX(page_meta) == MULTIPAGE_METADATA_MAGIC);
	return (struct zone_page_metadata *)((vm_offset_t)page_meta - page_meta->real_metadata_offset);
}

static inline void
page_metadata_set_realmeta(struct zone_page_metadata *page_meta, struct zone_page_metadata *real_meta)
{
	assert(PAGE_METADATA_GET_ZINDEX(page_meta) == MULTIPAGE_METADATA_MAGIC);
	assert(PAGE_METADATA_GET_ZINDEX(real_meta) != MULTIPAGE_METADATA_MAGIC);
	assert((vm_offset_t)page_meta > (vm_offset_t)real_meta);
	vm_offset_t offset = (vm_offset_t)page_meta - (vm_offset_t)real_meta;
	assert(offset <= UINT32_MAX);
	page_meta->real_metadata_offset = (uint32_t)offset;
}

/* The backup pointer is stored in the last pointer-sized location in an element. */
static inline vm_offset_t *
get_backup_ptr(vm_size_t  elem_size,
    vm_offset_t *element)
{
	return (vm_offset_t *) ((vm_offset_t)element + elem_size - sizeof(vm_offset_t));
}

/*
 * Routine to populate a page backing metadata in the zone_metadata_region.
 * Must be called without the zone lock held as it might potentially block.
 */
static inline void
zone_populate_metadata_page(struct zone_page_metadata *page_meta)
{
	vm_offset_t page_metadata_begin = trunc_page(page_meta);
	vm_offset_t page_metadata_end = trunc_page((vm_offset_t)page_meta + sizeof(struct zone_page_metadata));

	for (; page_metadata_begin <= page_metadata_end; page_metadata_begin += PAGE_SIZE) {
#if !KASAN
		/*
		 * This can race with another thread doing a populate on the same metadata
		 * page, where we see an updated pmap but unmapped KASan shadow, causing a
		 * fault in the shadow when we first access the metadata page. Avoid this
		 * by always synchronizing on the zone_metadata_region lock with KASan.
		 */
		if (pmap_find_phys(kernel_pmap, (vm_map_address_t)page_metadata_begin)) {
			continue;
		}
#endif
		/* All updates to the zone_metadata_region are done under the zone_metadata_region_lck */
		lck_mtx_lock(&zone_metadata_region_lck);
		if (0 == pmap_find_phys(kernel_pmap, (vm_map_address_t)page_metadata_begin)) {
			kern_return_t __assert_only ret = kernel_memory_populate(zone_map,
			    page_metadata_begin,
			    PAGE_SIZE,
			    KMA_KOBJECT,
			    VM_KERN_MEMORY_OSFMK);

			/* should not fail with the given arguments */
			assert(ret == KERN_SUCCESS);
		}
		lck_mtx_unlock(&zone_metadata_region_lck);
	}
	return;
}

static inline uint16_t
get_metadata_alloc_count(struct zone_page_metadata *page_meta)
{
	assert(PAGE_METADATA_GET_ZINDEX(page_meta) != MULTIPAGE_METADATA_MAGIC);
	struct zone *z = PAGE_METADATA_GET_ZONE(page_meta);
	return (page_meta->page_count * PAGE_SIZE) / z->elem_size;
}

/*
 * Routine to lookup metadata for any given address.
 * If init is marked as TRUE, this should be called without holding the zone lock
 * since the initialization might block.
 */
static inline struct zone_page_metadata *
get_zone_page_metadata(struct zone_free_element *element, boolean_t init)
{
	struct zone_page_metadata *page_meta = 0;

	if (from_zone_map(element, sizeof(struct zone_free_element))) {
		page_meta = (struct zone_page_metadata *)(PAGE_METADATA_FOR_ELEMENT(element));
		if (init) {
			zone_populate_metadata_page(page_meta);
		}
	} else {
		page_meta = (struct zone_page_metadata *)(trunc_page((vm_offset_t)element));
	}
	if (init) {
		bzero((char *)page_meta, sizeof(struct zone_page_metadata));
	}
	return (PAGE_METADATA_GET_ZINDEX(page_meta) != MULTIPAGE_METADATA_MAGIC) ? page_meta : page_metadata_get_realmeta(page_meta);
}

/* Routine to get the page for a given metadata */
static inline vm_offset_t
get_zone_page(struct zone_page_metadata *page_meta)
{
	if (from_zone_map(page_meta, sizeof(struct zone_page_metadata))) {
		return (vm_offset_t)(PAGE_FOR_PAGE_INDEX(PAGE_INDEX_FOR_METADATA(page_meta)));
	} else {
		return (vm_offset_t)(trunc_page(page_meta));
	}
}

/*
 * ZTAGS
 */

#if VM_MAX_TAG_ZONES

// for zones with tagging enabled:

// calculate a pointer to the tag base entry,
// holding either a uint32_t the first tag offset for a page in the zone map,
// or two uint16_t tags if the page can only hold one or two elements

#define ZTAGBASE(zone, element) \
    (&((uint32_t *)zone_tagbase_min)[atop((element) - zone_map_min_address)])

// pointer to the tag for an element
#define ZTAG(zone, element)                                     \
    ({                                                          \
	vm_tag_t * result;                                      \
	if ((zone)->tags_inline) {                              \
	    result = (vm_tag_t *) ZTAGBASE((zone), (element));  \
	    if ((page_mask & element) >= (zone)->elem_size) result++;    \
	} else {                                                \
	    result =  &((vm_tag_t *)zone_tags_min)[ZTAGBASE((zone), (element))[0] + ((element) & page_mask) / (zone)->elem_size];   \
	}                                                       \
	result;                                                 \
    })


static vm_offset_t  zone_tagbase_min;
static vm_offset_t  zone_tagbase_max;
static vm_offset_t  zone_tagbase_map_size;
static vm_map_t     zone_tagbase_map;

static vm_offset_t  zone_tags_min;
static vm_offset_t  zone_tags_max;
static vm_offset_t  zone_tags_map_size;
static vm_map_t     zone_tags_map;

// simple heap allocator for allocating the tags for new memory

decl_lck_mtx_data(, ztLock)    /* heap lock */
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

static void
ztInit(vm_size_t max_zonemap_size, lck_grp_t * group)
{
	kern_return_t         ret;
	vm_map_kernel_flags_t vmk_flags;
	uint32_t              idx;

	lck_mtx_init(&ztLock, group, LCK_ATTR_NULL);

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
		count = (uint32_t)(size / zone->elem_size);
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
			tagbase[idx] = block + (uint32_t)((ptoa(idx) + (zone->elem_size - 1)) / zone->elem_size);
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
		count = (uint32_t)(size / zone->elem_size);
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
	zone_t z;
	uint32_t idx;

	simple_lock(&all_zones_lock, &zone_locks_grp);

	for (idx = 0; idx < num_zones; idx++) {
		z = &(zone_array[idx]);
		if (!z->tags) {
			continue;
		}
		if (tag_zone_index != z->tag_zone_index) {
			continue;
		}
		*elem_size = z->elem_size;
		break;
	}

	simple_unlock(&all_zones_lock);

	if (idx == num_zones) {
		idx = -1U;
	}

	return idx;
}

#endif /* VM_MAX_TAG_ZONES */

/* Routine to get the size of a zone allocated address. If the address doesnt belong to the
 * zone_map, returns 0.
 */
vm_size_t
zone_element_size(void *addr, zone_t *z)
{
	struct zone *src_zone;
	if (from_zone_map(addr, sizeof(void *))) {
		struct zone_page_metadata *page_meta = get_zone_page_metadata((struct zone_free_element *)addr, FALSE);
		src_zone = PAGE_METADATA_GET_ZONE(page_meta);
		if (z) {
			*z = src_zone;
		}
		return src_zone->elem_size;
	} else {
#if CONFIG_GZALLOC
		vm_size_t gzsize;
		if (gzalloc_element_size(addr, z, &gzsize)) {
			return gzsize;
		}
#endif /* CONFIG_GZALLOC */

		return 0;
	}
}

#if DEBUG || DEVELOPMENT

vm_size_t
zone_element_info(void *addr, vm_tag_t * ptag)
{
	vm_size_t     size = 0;
	vm_tag_t      tag = VM_KERN_MEMORY_NONE;
	struct zone * src_zone;

	if (from_zone_map(addr, sizeof(void *))) {
		struct zone_page_metadata *page_meta = get_zone_page_metadata((struct zone_free_element *)addr, FALSE);
		src_zone = PAGE_METADATA_GET_ZONE(page_meta);
#if VM_MAX_TAG_ZONES
		if (__improbable(src_zone->tags)) {
			tag = (ZTAG(src_zone, (vm_offset_t) addr)[0] >> 1);
		}
#endif /* VM_MAX_TAG_ZONES */
		size = src_zone->elem_size;
	} else {
#if CONFIG_GZALLOC
		gzalloc_element_size(addr, NULL, &size);
#endif /* CONFIG_GZALLOC */
	}
	*ptag = tag;
	return size;
}

#endif /* DEBUG || DEVELOPMENT */

/*
 * Zone checking helper function.
 * A pointer that satisfies these conditions is OK to be a freelist next pointer
 * A pointer that doesn't satisfy these conditions indicates corruption
 */
static inline boolean_t
is_sane_zone_ptr(zone_t         zone,
    vm_offset_t    addr,
    size_t         obj_size)
{
	/*  Must be aligned to pointer boundary */
	if (__improbable((addr & (sizeof(vm_offset_t) - 1)) != 0)) {
		return FALSE;
	}

	/*  Must be a kernel address */
	if (__improbable(!pmap_kernel_va(addr))) {
		return FALSE;
	}

	/*  Must be from zone map if the zone only uses memory from the zone_map */
	/*
	 *  TODO: Remove the zone->collectable check when every
	 *  zone using foreign memory is properly tagged with allows_foreign
	 */
	if (zone->collectable && !zone->allows_foreign) {
		/*  check if addr is from zone map */
		if (addr >= zone_map_min_address &&
		    (addr + obj_size - 1) < zone_map_max_address) {
			return TRUE;
		}

		return FALSE;
	}

	return TRUE;
}

static inline boolean_t
is_sane_zone_page_metadata(zone_t       zone,
    vm_offset_t  page_meta)
{
	/* NULL page metadata structures are invalid */
	if (page_meta == 0) {
		return FALSE;
	}
	return is_sane_zone_ptr(zone, page_meta, sizeof(struct zone_page_metadata));
}

static inline boolean_t
is_sane_zone_element(zone_t      zone,
    vm_offset_t addr)
{
	/*  NULL is OK because it indicates the tail of the list */
	if (addr == 0) {
		return TRUE;
	}
	return is_sane_zone_ptr(zone, addr, zone->elem_size);
}

/* Someone wrote to freed memory. */
static inline void
/* noreturn */
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
static void
/* noreturn */
backup_ptr_mismatch_panic(zone_t        zone,
    vm_offset_t   element,
    vm_offset_t   primary,
    vm_offset_t   backup)
{
	vm_offset_t likely_backup;
	vm_offset_t likely_primary;

	likely_primary = primary ^ zp_nopoison_cookie;
	boolean_t   sane_backup;
	boolean_t   sane_primary = is_sane_zone_element(zone, likely_primary);
	boolean_t   element_was_poisoned = (backup & 0x1) ? TRUE : FALSE;

#if defined(__LP64__)
	/* We can inspect the tag in the upper bits for additional confirmation */
	if ((backup & 0xFFFFFF0000000000) == 0xFACADE0000000000) {
		element_was_poisoned = TRUE;
	} else if ((backup & 0xFFFFFF0000000000) == 0xC0FFEE0000000000) {
		element_was_poisoned = FALSE;
	}
#endif

	if (element_was_poisoned) {
		likely_backup = backup ^ zp_poisoned_cookie;
		sane_backup = is_sane_zone_element(zone, likely_backup);
	} else {
		likely_backup = backup ^ zp_nopoison_cookie;
		sane_backup = is_sane_zone_element(zone, likely_backup);
	}

	/* The primary is definitely the corrupted one */
	if (!sane_primary && sane_backup) {
		zone_element_was_modified_panic(zone, element, primary, (likely_backup ^ zp_nopoison_cookie), 0);
	}

	/* The backup is definitely the corrupted one */
	if (sane_primary && !sane_backup) {
		zone_element_was_modified_panic(zone, element, backup,
		    (likely_primary ^ (element_was_poisoned ? zp_poisoned_cookie : zp_nopoison_cookie)),
		    zone->elem_size - sizeof(vm_offset_t));
	}

	/*
	 * Not sure which is the corrupted one.
	 * It's less likely that the backup pointer was overwritten with
	 * ( (sane address) ^ (valid cookie) ), so we'll guess that the
	 * primary pointer has been overwritten with a sane but incorrect address.
	 */
	if (sane_primary && sane_backup) {
		zone_element_was_modified_panic(zone, element, primary, (likely_backup ^ zp_nopoison_cookie), 0);
	}

	/* Neither are sane, so just guess. */
	zone_element_was_modified_panic(zone, element, primary, (likely_backup ^ zp_nopoison_cookie), 0);
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

	page_meta = get_zone_page_metadata((struct zone_free_element *)element, FALSE);
	assert(PAGE_METADATA_GET_ZONE(page_meta) == zone);
	old_head = (vm_offset_t)page_metadata_get_freelist(page_meta);

	if (__improbable(!is_sane_zone_element(zone, old_head))) {
		panic("zfree: invalid head pointer %p for freelist of zone %s\n",
		    (void *) old_head, zone->zone_name);
	}

	if (__improbable(!is_sane_zone_element(zone, element))) {
		panic("zfree: freeing invalid pointer %p to zone %s\n",
		    (void *) element, zone->zone_name);
	}

	if (__improbable(old_head == element)) {
		panic("zfree: double free of %p to zone %s\n",
		    (void *) element, zone->zone_name);
	}
	/*
	 * Always write a redundant next pointer
	 * So that it is more difficult to forge, xor it with a random cookie
	 * A poisoned element is indicated by using zp_poisoned_cookie
	 * instead of zp_nopoison_cookie
	 */

	*backup = old_head ^ (poison ? zp_poisoned_cookie : zp_nopoison_cookie);

	/*
	 * Insert this element at the head of the free list. We also xor the
	 * primary pointer with the zp_nopoison_cookie to make sure a free
	 * element does not provide the location of the next free element directly.
	 */
	*primary             = old_head ^ zp_nopoison_cookie;
	page_metadata_set_freelist(page_meta, (struct zone_free_element *)element);
	page_meta->free_count++;
	if (zone->allows_foreign && !from_zone_map(element, zone->elem_size)) {
		if (page_meta->free_count == 1) {
			/* first foreign element freed on page, move from all_used */
			re_queue_tail(&zone->pages.any_free_foreign, &(page_meta->pages));
		} else {
			/* no other list transitions */
		}
	} else if (page_meta->free_count == get_metadata_alloc_count(page_meta)) {
		/* whether the page was on the intermediate or all_used, queue, move it to free */
		re_queue_tail(&zone->pages.all_free, &(page_meta->pages));
		zone->count_all_free_pages += page_meta->page_count;
	} else if (page_meta->free_count == 1) {
		/* first free element on page, move from all_used */
		re_queue_tail(&zone->pages.intermediate, &(page_meta->pages));
	}
	zone->count--;
	zone->countfree++;

#if KASAN_ZALLOC
	kasan_poison_range(element, zone->elem_size, ASAN_HEAP_FREED);
#endif
}


/*
 * Removes an element from the zone's free list, returning 0 if the free list is empty.
 * Verifies that the next-pointer and backup next-pointer are intact,
 * and verifies that a poisoned element hasn't been modified.
 */
static inline vm_offset_t
try_alloc_from_zone(zone_t zone,
    vm_tag_t tag __unused,
    boolean_t* check_poison)
{
	vm_offset_t  element;
	struct zone_page_metadata *page_meta;

	*check_poison = FALSE;

	/* if zone is empty, bail */
	if (zone->allows_foreign && !queue_empty(&zone->pages.any_free_foreign)) {
		page_meta = (struct zone_page_metadata *)queue_first(&zone->pages.any_free_foreign);
	} else if (!queue_empty(&zone->pages.intermediate)) {
		page_meta = (struct zone_page_metadata *)queue_first(&zone->pages.intermediate);
	} else if (!queue_empty(&zone->pages.all_free)) {
		page_meta = (struct zone_page_metadata *)queue_first(&zone->pages.all_free);
		assert(zone->count_all_free_pages >= page_meta->page_count);
		zone->count_all_free_pages -= page_meta->page_count;
	} else {
		return 0;
	}
	/* Check if page_meta passes is_sane_zone_element */
	if (__improbable(!is_sane_zone_page_metadata(zone, (vm_offset_t)page_meta))) {
		panic("zalloc: invalid metadata structure %p for freelist of zone %s\n",
		    (void *) page_meta, zone->zone_name);
	}
	assert(PAGE_METADATA_GET_ZONE(page_meta) == zone);
	element = (vm_offset_t)page_metadata_get_freelist(page_meta);

	if (__improbable(!is_sane_zone_ptr(zone, element, zone->elem_size))) {
		panic("zfree: invalid head pointer %p for freelist of zone %s\n",
		    (void *) element, zone->zone_name);
	}

	vm_offset_t *primary = (vm_offset_t *) element;
	vm_offset_t *backup  = get_backup_ptr(zone->elem_size, primary);

	/*
	 * Since the primary next pointer is xor'ed with zp_nopoison_cookie
	 * for obfuscation, retrieve the original value back
	 */
	vm_offset_t  next_element          = *primary ^ zp_nopoison_cookie;
	vm_offset_t  next_element_primary  = *primary;
	vm_offset_t  next_element_backup   = *backup;

	/*
	 * backup_ptr_mismatch_panic will determine what next_element
	 * should have been, and print it appropriately
	 */
	if (__improbable(!is_sane_zone_element(zone, next_element))) {
		backup_ptr_mismatch_panic(zone, element, next_element_primary, next_element_backup);
	}

	/* Check the backup pointer for the regular cookie */
	if (__improbable(next_element != (next_element_backup ^ zp_nopoison_cookie))) {
		/* Check for the poisoned cookie instead */
		if (__improbable(next_element != (next_element_backup ^ zp_poisoned_cookie))) {
			/* Neither cookie is valid, corruption has occurred */
			backup_ptr_mismatch_panic(zone, element, next_element_primary, next_element_backup);
		}

		/*
		 * Element was marked as poisoned, so check its integrity before using it.
		 */
		*check_poison = TRUE;
	}

	/* Make sure the page_meta is at the correct offset from the start of page */
	if (__improbable(page_meta != get_zone_page_metadata((struct zone_free_element *)element, FALSE))) {
		panic("zalloc: Incorrect metadata %p found in zone %s page queue. Expected metadata: %p\n",
		    page_meta, zone->zone_name, get_zone_page_metadata((struct zone_free_element *)element, FALSE));
	}

	/* Make sure next_element belongs to the same page as page_meta */
	if (next_element) {
		if (__improbable(page_meta != get_zone_page_metadata((struct zone_free_element *)next_element, FALSE))) {
			panic("zalloc: next element pointer %p for element %p points to invalid element for zone %s\n",
			    (void *)next_element, (void *)element, zone->zone_name);
		}
	}

	/* Remove this element from the free list */
	page_metadata_set_freelist(page_meta, (struct zone_free_element *)next_element);
	page_meta->free_count--;

	if (page_meta->free_count == 0) {
		/* move to all used */
		re_queue_tail(&zone->pages.all_used, &(page_meta->pages));
	} else {
		if (!zone->allows_foreign || from_zone_map(element, zone->elem_size)) {
			if (get_metadata_alloc_count(page_meta) == page_meta->free_count + 1) {
				/* remove from free, move to intermediate */
				re_queue_tail(&zone->pages.intermediate, &(page_meta->pages));
			}
		}
	}
	zone->countfree--;
	zone->count++;
	zone->sum_count++;

#if VM_MAX_TAG_ZONES
	if (__improbable(zone->tags)) {
		// set the tag with b0 clear so the block remains inuse
		ZTAG(zone, element)[0] = (tag << 1);
	}
#endif /* VM_MAX_TAG_ZONES */


#if KASAN_ZALLOC
	kasan_poison_range(element, zone->elem_size, ASAN_VALID);
#endif

	return element;
}

/*
 * End of zone poisoning
 */

/*
 * Zone info options
 */
#define ZINFO_SLOTS     MAX_ZONES               /* for now */

zone_t          zone_find_largest(void);

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
void            zalloc_async(
	thread_call_param_t     p0,
	thread_call_param_t     p1);

static thread_call_data_t call_async_alloc;

/*
 * Align elements that use the zone page list to 32 byte boundaries.
 */
#define ZONE_ELEMENT_ALIGNMENT 32

#define zone_wakeup(zone) thread_wakeup((event_t)(zone))
#define zone_sleep(zone)                                \
	(void) lck_mtx_sleep(&(zone)->lock, LCK_SLEEP_SPIN_ALWAYS, (event_t)(zone), THREAD_UNINT);


#define lock_zone_init(zone)                            \
MACRO_BEGIN                                             \
	lck_attr_setdefault(&(zone)->lock_attr);                        \
	lck_mtx_init_ext(&(zone)->lock, &(zone)->lock_ext,              \
	    &zone_locks_grp, &(zone)->lock_attr);                       \
MACRO_END

#define lock_try_zone(zone)     lck_mtx_try_lock_spin(&zone->lock)

/*
 *	Exclude more than one concurrent garbage collection
 */
decl_lck_mtx_data(, zone_gc_lock)

lck_attr_t      zone_gc_lck_attr;
lck_grp_t       zone_gc_lck_grp;
lck_grp_attr_t  zone_gc_lck_grp_attr;
lck_mtx_ext_t   zone_gc_lck_ext;

boolean_t zone_gc_allowed = TRUE;
boolean_t panic_include_zprint = FALSE;

mach_memory_info_t *panic_kext_memory_info = NULL;
vm_size_t panic_kext_memory_size = 0;

#define ZALLOC_DEBUG_ZONEGC             0x00000001
#define ZALLOC_DEBUG_ZCRAM              0x00000002
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

static boolean_t log_records_init = FALSE;
static int log_records; /* size of the log, expressed in number of records */

#define MAX_NUM_ZONES_ALLOWED_LOGGING   10 /* Maximum 10 zones can be logged at once */

static int  max_num_zones_to_log = MAX_NUM_ZONES_ALLOWED_LOGGING;
static int  num_zones_logged = 0;

static char zone_name_to_log[MAX_ZONE_NAME] = "";       /* the zone name we're logging, if any */

/* Log allocations and frees to help debug a zone element corruption */
boolean_t       corruption_debug_flag    = DEBUG;    /* enabled by "-zc" boot-arg */
/* Making pointer scanning leaks detection possible for all zones */

#if DEBUG || DEVELOPMENT
boolean_t       leak_scan_debug_flag     = FALSE;    /* enabled by "-zl" boot-arg */
#endif /* DEBUG || DEVELOPMENT */


/*
 * The number of records in the log is configurable via the zrecs parameter in boot-args.  Set this to
 * the number of records you want in the log.  For example, "zrecs=10" sets it to 10 records. Since this
 * is the number of stacks suspected of leaking, we don't need many records.
 */

#if     defined(__LP64__)
#define ZRECORDS_MAX            2560            /* Max records allowed in the log */
#else
#define ZRECORDS_MAX            1536            /* Max records allowed in the log */
#endif
#define ZRECORDS_DEFAULT        1024            /* default records in log if zrecs is not specificed in boot-args */

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


/*
 * Test if we want to log this zalloc/zfree event.  We log if this is the zone we're interested in and
 * the buffer for the records has been allocated.
 */

#define DO_LOGGING(z)           (z->zone_logging == TRUE && z->zlog_btlog)

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
#define ZLEAK_STATE_ENABLED             0x01    /* Zone leak monitoring should be turned on if zone_map fills up. */
#define ZLEAK_STATE_ACTIVE              0x02    /* We are actively collecting traces. */
#define ZLEAK_STATE_ACTIVATING          0x04    /* Some thread is doing setup; others should move along. */
#define ZLEAK_STATE_FAILED              0x08    /* Attempt to allocate tables failed.  We will not try again. */
uint32_t        zleak_state = 0;                /* State of collection, as above */

boolean_t       panic_include_ztrace    = FALSE;        /* Enable zleak logging on panic */
vm_size_t       zleak_global_tracking_threshold;        /* Size of zone map at which to start collecting data */
vm_size_t       zleak_per_zone_tracking_threshold;      /* Size a zone will have before we will collect data on it */
unsigned int    zleak_sample_factor     = 1000;         /* Allocations per sample attempt */

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
unsigned int z_alloc_recorded   = 0;
unsigned int z_trace_recorded   = 0;

/* Times zleak_log returned false due to not being able to acquire the lock */
unsigned int z_total_conflicts  = 0;


#pragma mark struct zallocation
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
uint32_t zleak_alloc_buckets = CONFIG_ZLEAK_ALLOCATION_MAP_NUM;
uint32_t zleak_trace_buckets = CONFIG_ZLEAK_TRACE_MAP_NUM;

vm_size_t zleak_max_zonemap_size;

/* Hashmaps of allocations and their corresponding traces */
static struct zallocation*      zallocations;
static struct ztrace*           ztraces;

/* not static so that panic can see this, see kern/debug.c */
struct ztrace*                          top_ztrace;

/* Lock to protect zallocations, ztraces, and top_ztrace from concurrent modification. */
static lck_spin_t                       zleak_lock;
static lck_attr_t                       zleak_lock_attr;
static lck_grp_t                        zleak_lock_grp;
static lck_grp_attr_t                   zleak_lock_grp_attr;

/*
 * Initializes the zone leak monitor.  Called from zone_init()
 */
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
	if (zleak_state & ZLEAK_STATE_FAILED) {
		return -1;
	}
	if (zleak_state & ZLEAK_STATE_ACTIVE) {
		return 1;
	}
	return 0;
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

#endif /* CONFIG_ZLEAKS */

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

/* End of all leak-detection code */
#pragma mark -

#define ZONE_MAX_ALLOC_SIZE     (32 * 1024)
#define ZONE_ALLOC_FRAG_PERCENT(alloc_size, ele_size) (((alloc_size % ele_size) * 100) / alloc_size)

/* Used to manage copying in of new zone names */
static vm_offset_t zone_names_start;
static vm_offset_t zone_names_next;

static vm_size_t
compute_element_size(vm_size_t requested_size)
{
	vm_size_t element_size = requested_size;

	/* Zone elements must fit both a next pointer and a backup pointer */
	vm_size_t  minimum_element_size = sizeof(vm_offset_t) * 2;
	if (element_size < minimum_element_size) {
		element_size = minimum_element_size;
	}

	/*
	 *  Round element size to a multiple of sizeof(pointer)
	 *  This also enforces that allocations will be aligned on pointer boundaries
	 */
	element_size = ((element_size - 1) + sizeof(vm_offset_t)) -
	    ((element_size - 1) % sizeof(vm_offset_t));

	return element_size;
}

#if KASAN_ZALLOC

/*
 * Called from zinit().
 *
 * Fixes up the zone's element size to incorporate the redzones.
 */
static void
kasan_update_element_size_for_redzone(
	zone_t          zone,           /* the zone that needs to be updated */
	vm_size_t       *size,          /* requested zone element size */
	vm_size_t       *max,           /* maximum memory to use */
	const char      *name)          /* zone name */
{
	/* Expand the zone allocation size to include the redzones. For page-multiple
	 * zones add a full guard page because they likely require alignment. kalloc
	 * and fakestack handles its own KASan state, so ignore those zones. */
	/* XXX: remove this when zinit_with_options() is a thing */
	const char *kalloc_name = "kalloc.";
	const char *fakestack_name = "fakestack.";
	if (strncmp(name, kalloc_name, strlen(kalloc_name)) == 0) {
		zone->kasan_redzone = 0;
	} else if (strncmp(name, fakestack_name, strlen(fakestack_name)) == 0) {
		zone->kasan_redzone = 0;
	} else {
		if ((*size % PAGE_SIZE) != 0) {
			zone->kasan_redzone = KASAN_GUARD_SIZE;
		} else {
			zone->kasan_redzone = PAGE_SIZE;
		}
		*max = (*max / *size) * (*size + zone->kasan_redzone * 2);
		*size += zone->kasan_redzone * 2;
	}
}

/*
 * Called from zalloc_internal() to fix up the address of the newly
 * allocated element.
 *
 * Returns the element address skipping over the redzone on the left.
 */
static vm_offset_t
kasan_fixup_allocated_element_address(
	zone_t                  zone,   /* the zone the element belongs to */
	vm_offset_t             addr)   /* address of the element, including the redzone */
{
	/* Fixup the return address to skip the redzone */
	if (zone->kasan_redzone) {
		addr = kasan_alloc(addr, zone->elem_size,
		    zone->elem_size - 2 * zone->kasan_redzone, zone->kasan_redzone);
	}
	return addr;
}

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
	vm_size_t usersz = zone->elem_size - 2 * zone->kasan_redzone;
	vm_size_t sz = usersz;

	if (addr && zone->kasan_redzone) {
		kasan_check_free((vm_address_t)addr, usersz, KASAN_HEAP_ZALLOC);
		addr = (void *)kasan_dealloc((vm_address_t)addr, &sz);
		assert(sz == zone->elem_size);
	}
	if (addr && zone->kasan_quarantine) {
		kasan_free(&addr, &sz, KASAN_HEAP_ZALLOC, zonep, usersz, true);
		if (!addr) {
			return TRUE;
		}
	}
	*addrp = addr;
	return FALSE;
}

#endif /* KASAN_ZALLOC */

/*
 *	zinit initializes a new zone.  The zone data structures themselves
 *	are stored in a zone, which is initially a static structure that
 *	is initialized by zone_init.
 */

zone_t
zinit(
	vm_size_t       size,           /* the size of an element */
	vm_size_t       max,            /* maximum memory to use */
	vm_size_t       alloc,          /* allocation size */
	const char      *name)          /* a name for the zone */
{
	zone_t                  z;

	size = compute_element_size(size);

	simple_lock(&all_zones_lock, &zone_locks_grp);

	assert(num_zones < MAX_ZONES);
	assert(num_zones_in_use <= num_zones);

	/* If possible, find a previously zdestroy'ed zone in the zone_array that we can reuse instead of initializing a new zone. */
	for (int index = bitmap_first(zone_empty_bitmap, MAX_ZONES);
	    index >= 0 && index < (int)num_zones;
	    index = bitmap_next(zone_empty_bitmap, index)) {
		z = &(zone_array[index]);

		/*
		 * If the zone name and the element size are the same, we can just reuse the old zone struct.
		 * Otherwise hand out a new zone from the zone_array.
		 */
		if (!strcmp(z->zone_name, name)) {
			vm_size_t old_size = z->elem_size;
#if KASAN_ZALLOC
			old_size -= z->kasan_redzone * 2;
#endif
			if (old_size == size) {
				/* Clear the empty bit for this zone, increment num_zones_in_use, and mark the zone as valid again. */
				bitmap_clear(zone_empty_bitmap, index);
				num_zones_in_use++;
				z->zone_valid = TRUE;

				/* All other state is already set up since the zone was previously in use. Return early. */
				simple_unlock(&all_zones_lock);
				return z;
			}
		}
	}

	/* If we're here, it means we didn't find a zone above that we could simply reuse. Set up a new zone. */

	/* Clear the empty bit for the new zone */
	bitmap_clear(zone_empty_bitmap, num_zones);

	z = &(zone_array[num_zones]);
	z->index = num_zones;

	num_zones++;
	num_zones_in_use++;

	/*
	 * Initialize the zone lock here before dropping the all_zones_lock. Otherwise we could race with
	 * zalloc_async() and try to grab the zone lock before it has been initialized, causing a panic.
	 */
	lock_zone_init(z);

	simple_unlock(&all_zones_lock);

#if KASAN_ZALLOC
	kasan_update_element_size_for_redzone(z, &size, &max, name);
#endif

	max = round_page(max);

	vm_size_t best_alloc = PAGE_SIZE;

	if ((size % PAGE_SIZE) == 0) {
		/* zero fragmentation by definition */
		best_alloc = size;
	} else {
		vm_size_t alloc_size;
		for (alloc_size = (2 * PAGE_SIZE); alloc_size <= ZONE_MAX_ALLOC_SIZE; alloc_size += PAGE_SIZE) {
			if (ZONE_ALLOC_FRAG_PERCENT(alloc_size, size) < ZONE_ALLOC_FRAG_PERCENT(best_alloc, size)) {
				best_alloc = alloc_size;
			}
		}
	}

	alloc = best_alloc;
	if (max && (max < alloc)) {
		max = alloc;
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
	z->count = 0;
	z->countfree = 0;
	z->count_all_free_pages = 0;
	z->sum_count = 0LL;
	z->doing_alloc_without_vm_priv = FALSE;
	z->doing_alloc_with_vm_priv = FALSE;
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
	z->zone_replenishing = FALSE;
	z->prio_refill_watermark = 0;
	z->zone_replenish_thread = NULL;
	z->zp_count = 0;
	z->kasan_quarantine = TRUE;
	z->zone_valid = TRUE;
	z->cpu_cache_enabled = FALSE;

#if CONFIG_ZLEAKS
	z->zleak_capture = 0;
	z->zleak_on = FALSE;
#endif /* CONFIG_ZLEAKS */

	/*
	 * If the VM is ready to handle kmem_alloc requests, copy the zone name passed in.
	 *
	 * Else simply maintain a pointer to the name string. The only zones we'll actually have
	 * to do this for would be the VM-related zones that are created very early on before any
	 * kexts can be loaded (unloaded). So we should be fine with just a pointer in this case.
	 */
	if (kmem_alloc_ready) {
		size_t len = MIN(strlen(name) + 1, MACH_ZONE_NAME_MAX_LEN);

		if (zone_names_start == 0 || ((zone_names_next - zone_names_start) + len) > PAGE_SIZE) {
			printf("zalloc: allocating memory for zone names buffer\n");
			kern_return_t retval = kmem_alloc_kobject(kernel_map, &zone_names_start,
			    PAGE_SIZE, VM_KERN_MEMORY_OSFMK);
			if (retval != KERN_SUCCESS) {
				panic("zalloc: zone_names memory allocation failed");
			}
			bzero((char *)zone_names_start, PAGE_SIZE);
			zone_names_next = zone_names_start;
		}

		strlcpy((char *)zone_names_next, name, len);
		z->zone_name = (char *)zone_names_next;
		zone_names_next += len;
	} else {
		z->zone_name = name;
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

	if (num_zones_logged < max_num_zones_to_log) {
		int             i = 1; /* zlog0 isn't allowed. */
		boolean_t       zone_logging_enabled = FALSE;
		char            zlog_name[MAX_ZONE_NAME] = ""; /* Temp. buffer to create the strings zlog1, zlog2 etc... */

		while (i <= max_num_zones_to_log) {
			snprintf(zlog_name, MAX_ZONE_NAME, "zlog%d", i);

			if (PE_parse_boot_argn(zlog_name, zone_name_to_log, sizeof(zone_name_to_log)) == TRUE) {
				if (track_this_zone(z->zone_name, zone_name_to_log)) {
					if (z->zone_valid) {
						z->zone_logging = TRUE;
						zone_logging_enabled = TRUE;
						num_zones_logged++;
						break;
					}
				}
			}
			i++;
		}

		if (zone_logging_enabled == FALSE) {
			/*
			 * Backwards compat. with the old boot-arg used to specify single zone logging i.e. zlog
			 * Needs to happen after the newer zlogn checks because the prefix will match all the zlogn
			 * boot-args.
			 */
			if (PE_parse_boot_argn("zlog", zone_name_to_log, sizeof(zone_name_to_log)) == TRUE) {
				if (track_this_zone(z->zone_name, zone_name_to_log)) {
					if (z->zone_valid) {
						z->zone_logging = TRUE;
						zone_logging_enabled = TRUE;
						num_zones_logged++;
					}
				}
			}
		}

		if (log_records_init == FALSE && zone_logging_enabled == TRUE) {
			if (PE_parse_boot_argn("zrecs", &log_records, sizeof(log_records)) == TRUE) {
				/*
				 * Don't allow more than ZRECORDS_MAX records even if the user asked for more.
				 * This prevents accidentally hogging too much kernel memory and making the system
				 * unusable.
				 */

				log_records = MIN(ZRECORDS_MAX, log_records);
				log_records_init = TRUE;
			} else {
				log_records = ZRECORDS_DEFAULT;
				log_records_init = TRUE;
			}
		}

		/*
		 * If we want to log a zone, see if we need to allocate buffer space for the log.  Some vm related zones are
		 * zinit'ed before we can do a kmem_alloc, so we have to defer allocation in that case.  kmem_alloc_ready is set to
		 * TRUE once enough of the VM system is up and running to allow a kmem_alloc to work.  If we want to log one
		 * of the VM related zones that's set up early on, we will skip allocation of the log until zinit is called again
		 * later on some other zone.  So note we may be allocating a buffer to log a zone other than the one being initialized
		 * right now.
		 */
		if (kmem_alloc_ready) {
			zone_t curr_zone = NULL;
			unsigned int max_zones = 0, zone_idx = 0;

			simple_lock(&all_zones_lock, &zone_locks_grp);
			max_zones = num_zones;
			simple_unlock(&all_zones_lock);

			for (zone_idx = 0; zone_idx < max_zones; zone_idx++) {
				curr_zone = &(zone_array[zone_idx]);

				if (!curr_zone->zone_valid) {
					continue;
				}

				/*
				 * We work with the zone unlocked here because we could end up needing the zone lock to
				 * enable logging for this zone e.g. need a VM object to allocate memory to enable logging for the
				 * VM objects zone.
				 *
				 * We don't expect these zones to be needed at this early a time in boot and so take this chance.
				 */
				if (curr_zone->zone_logging && curr_zone->zlog_btlog == NULL) {
					curr_zone->zlog_btlog = btlog_create(log_records, MAX_ZTRACE_DEPTH, (corruption_debug_flag == FALSE) /* caller_will_remove_entries_for_element? */);

					if (curr_zone->zlog_btlog) {
						printf("zone: logging started for zone %s\n", curr_zone->zone_name);
					} else {
						printf("zone: couldn't allocate memory for zrecords, turning off zleak logging\n");
						curr_zone->zone_logging = FALSE;
					}
				}
			}
		}
	}

#if     CONFIG_GZALLOC
	gzalloc_zone_init(z);
#endif

#if     CONFIG_ZCACHE
	/* Check if boot-arg specified it should have a cache */
	if (cache_all_zones || track_this_zone(name, cache_zone_name)) {
		zone_change(z, Z_CACHING_ENABLED, TRUE);
	}
#endif

	return z;
}
unsigned        zone_replenish_loops, zone_replenish_wakeups, zone_replenish_wakeups_initiated, zone_replenish_throttle_count;

static void zone_replenish_thread(zone_t);

/* High priority VM privileged thread used to asynchronously refill a designated
 * zone, such as the reserved VM map entry zone.
 */
__attribute__((noreturn))
static void
zone_replenish_thread(zone_t z)
{
	vm_size_t free_size;
	current_thread()->options |= TH_OPT_VMPRIV;

	for (;;) {
		lock_zone(z);
		assert(z->zone_valid);
		z->zone_replenishing = TRUE;
		assert(z->prio_refill_watermark != 0);
		while ((free_size = (z->cur_size - (z->count * z->elem_size))) < (z->prio_refill_watermark * z->elem_size)) {
			assert(z->doing_alloc_without_vm_priv == FALSE);
			assert(z->doing_alloc_with_vm_priv == FALSE);
			assert(z->async_prio_refill == TRUE);

			unlock_zone(z);
			int     zflags = KMA_KOBJECT | KMA_NOPAGEWAIT;
			vm_offset_t space, alloc_size;
			kern_return_t kr;

			if (vm_pool_low()) {
				alloc_size = round_page(z->elem_size);
			} else {
				alloc_size = z->alloc_size;
			}

			if (z->noencrypt) {
				zflags |= KMA_NOENCRYPT;
			}

			/* Trigger jetsams via the vm_pageout_garbage_collect thread if we're running out of zone memory */
			if (is_zone_map_nearing_exhaustion()) {
				thread_wakeup((event_t) &vm_pageout_garbage_collect);
			}

			kr = kernel_memory_allocate(zone_map, &space, alloc_size, 0, zflags, VM_KERN_MEMORY_ZONE);

			if (kr == KERN_SUCCESS) {
				zcram(z, space, alloc_size);
			} else if (kr == KERN_RESOURCE_SHORTAGE) {
				VM_PAGE_WAIT();
			} else if (kr == KERN_NO_SPACE) {
				kr = kernel_memory_allocate(kernel_map, &space, alloc_size, 0, zflags, VM_KERN_MEMORY_ZONE);
				if (kr == KERN_SUCCESS) {
					zcram(z, space, alloc_size);
				} else {
					assert_wait_timeout(&z->zone_replenish_thread, THREAD_UNINT, 1, 100 * NSEC_PER_USEC);
					thread_block(THREAD_CONTINUE_NULL);
				}
			}

			lock_zone(z);
			assert(z->zone_valid);
			zone_replenish_loops++;
		}

		z->zone_replenishing = FALSE;
		/* Signal any potential throttled consumers, terminating
		 * their timer-bounded waits.
		 */
		thread_wakeup(z);

		assert_wait(&z->zone_replenish_thread, THREAD_UNINT);
		unlock_zone(z);
		thread_block(THREAD_CONTINUE_NULL);
		zone_replenish_wakeups++;
	}
}

void
zone_prio_refill_configure(zone_t z, vm_size_t low_water_mark)
{
	z->prio_refill_watermark = low_water_mark;

	z->async_prio_refill = TRUE;
	OSMemoryBarrier();
	kern_return_t tres = kernel_thread_start_priority((thread_continue_t)zone_replenish_thread, z, MAXPRI_KERNEL, &z->zone_replenish_thread);

	if (tres != KERN_SUCCESS) {
		panic("zone_prio_refill_configure, thread create: 0x%x", tres);
	}

	thread_deallocate(z->zone_replenish_thread);
}

void
zdestroy(zone_t z)
{
	unsigned int zindex;

	assert(z != NULL);

	lock_zone(z);
	assert(z->zone_valid);

	/* Assert that the zone does not have any allocations in flight */
	assert(z->doing_alloc_without_vm_priv == FALSE);
	assert(z->doing_alloc_with_vm_priv == FALSE);
	assert(z->async_pending == FALSE);
	assert(z->waiting == FALSE);
	assert(z->async_prio_refill == FALSE);

#if !KASAN_ZALLOC
	/*
	 * Unset the valid bit. We'll hit an assert failure on further operations on this zone, until zinit() is called again.
	 * Leave the zone valid for KASan as we will see zfree's on quarantined free elements even after the zone is destroyed.
	 */
	z->zone_valid = FALSE;
#endif
	unlock_zone(z);

#if CONFIG_ZCACHE
	/* Drain the per-cpu caches if caching is enabled for the zone. */
	if (zone_caching_enabled(z)) {
		panic("zdestroy: Zone caching enabled for zone %s", z->zone_name);
	}
#endif /* CONFIG_ZCACHE */

	/* Dump all the free elements */
	drop_free_elements(z);

#if     CONFIG_GZALLOC
	/* If the zone is gzalloc managed dump all the elements in the free cache */
	gzalloc_empty_free_cache(z);
#endif

	lock_zone(z);

#if !KASAN_ZALLOC
	/* Assert that all counts are zero */
	assert(z->count == 0);
	assert(z->countfree == 0);
	assert(z->cur_size == 0);
	assert(z->page_count == 0);
	assert(z->count_all_free_pages == 0);

	/* Assert that all queues except the foreign queue are empty. The zone allocator doesn't know how to free up foreign memory. */
	assert(queue_empty(&z->pages.all_used));
	assert(queue_empty(&z->pages.intermediate));
	assert(queue_empty(&z->pages.all_free));
#endif

	zindex = z->index;

	unlock_zone(z);

	simple_lock(&all_zones_lock, &zone_locks_grp);

	assert(!bitmap_test(zone_empty_bitmap, zindex));
	/* Mark the zone as empty in the bitmap */
	bitmap_set(zone_empty_bitmap, zindex);
	num_zones_in_use--;
	assert(num_zones_in_use > 0);

	simple_unlock(&all_zones_lock);
}

/* Initialize the metadata for an allocation chunk */
static inline void
zcram_metadata_init(vm_offset_t newmem, vm_size_t size, struct zone_page_metadata *chunk_metadata)
{
	struct zone_page_metadata *page_metadata;

	/* The first page is the real metadata for this allocation chunk. We mark the others as fake metadata */
	size -= PAGE_SIZE;
	newmem += PAGE_SIZE;

	for (; size > 0; newmem += PAGE_SIZE, size -= PAGE_SIZE) {
		page_metadata = get_zone_page_metadata((struct zone_free_element *)newmem, TRUE);
		assert(page_metadata != chunk_metadata);
		PAGE_METADATA_SET_ZINDEX(page_metadata, MULTIPAGE_METADATA_MAGIC);
		page_metadata_set_realmeta(page_metadata, chunk_metadata);
		page_metadata->free_count = 0;
	}
	return;
}


static void
random_free_to_zone(
	zone_t          zone,
	vm_offset_t     newmem,
	vm_offset_t     first_element_offset,
	int             element_count,
	unsigned int    *entropy_buffer)
{
	vm_offset_t     last_element_offset;
	vm_offset_t     element_addr;
	vm_size_t       elem_size;
	int             index;

	assert(element_count && element_count <= ZONE_CHUNK_MAXELEMENTS);
	elem_size = zone->elem_size;
	last_element_offset = first_element_offset + ((element_count * elem_size) - elem_size);
	for (index = 0; index < element_count; index++) {
		assert(first_element_offset <= last_element_offset);
		if (
#if DEBUG || DEVELOPMENT
			leak_scan_debug_flag || __improbable(zone->tags) ||
#endif /* DEBUG || DEVELOPMENT */
			random_bool_gen_bits(&zone_bool_gen, entropy_buffer, MAX_ENTROPY_PER_ZCRAM, 1)) {
			element_addr = newmem + first_element_offset;
			first_element_offset += elem_size;
		} else {
			element_addr = newmem + last_element_offset;
			last_element_offset -= elem_size;
		}
		if (element_addr != (vm_offset_t)zone) {
			zone->count++;  /* compensate for free_to_zone */
			free_to_zone(zone, element_addr, FALSE);
		}
		zone->cur_size += elem_size;
	}
}

/*
 *	Cram the given memory into the specified zone. Update the zone page count accordingly.
 */
void
zcram(
	zone_t          zone,
	vm_offset_t                     newmem,
	vm_size_t               size)
{
	vm_size_t       elem_size;
	boolean_t   from_zm = FALSE;
	int element_count;
	unsigned int entropy_buffer[MAX_ENTROPY_PER_ZCRAM] = { 0 };

	/* Basic sanity checks */
	assert(zone != ZONE_NULL && newmem != (vm_offset_t)0);
	assert(!zone->collectable || zone->allows_foreign
	    || (from_zone_map(newmem, size)));

	elem_size = zone->elem_size;

	KDBG(MACHDBG_CODE(DBG_MACH_ZALLOC, ZALLOC_ZCRAM) | DBG_FUNC_START, zone->index, size);

	if (from_zone_map(newmem, size)) {
		from_zm = TRUE;
	}

	if (!from_zm) {
		/* We cannot support elements larger than page size for foreign memory because we
		 * put metadata on the page itself for each page of foreign memory. We need to do
		 * this in order to be able to reach the metadata when any element is freed
		 */
		assert((zone->allows_foreign == TRUE) && (zone->elem_size <= (PAGE_SIZE - sizeof(struct zone_page_metadata))));
	}

	if (zalloc_debug & ZALLOC_DEBUG_ZCRAM) {
		kprintf("zcram(%p[%s], 0x%lx%s, 0x%lx)\n", zone, zone->zone_name,
		    (unsigned long)newmem, from_zm ? "" : "[F]", (unsigned long)size);
	}

	ZONE_PAGE_COUNT_INCR(zone, (size / PAGE_SIZE));

	/*
	 * Initialize the metadata for all pages. We dont need the zone lock
	 * here because we are not manipulating any zone related state yet.
	 */

	struct zone_page_metadata *chunk_metadata;
	size_t zone_page_metadata_size = sizeof(struct zone_page_metadata);

	assert((newmem & PAGE_MASK) == 0);
	assert((size & PAGE_MASK) == 0);

	chunk_metadata = get_zone_page_metadata((struct zone_free_element *)newmem, TRUE);
	chunk_metadata->pages.next = NULL;
	chunk_metadata->pages.prev = NULL;
	page_metadata_set_freelist(chunk_metadata, 0);
	PAGE_METADATA_SET_ZINDEX(chunk_metadata, zone->index);
	chunk_metadata->free_count = 0;
	assert((size / PAGE_SIZE) <= ZONE_CHUNK_MAXPAGES);
	chunk_metadata->page_count = (unsigned)(size / PAGE_SIZE);

	zcram_metadata_init(newmem, size, chunk_metadata);

#if VM_MAX_TAG_ZONES
	if (__improbable(zone->tags)) {
		assert(from_zm);
		ztMemoryAdd(zone, newmem, size);
	}
#endif /* VM_MAX_TAG_ZONES */

	lock_zone(zone);
	assert(zone->zone_valid);
	enqueue_tail(&zone->pages.all_used, &(chunk_metadata->pages));

	if (!from_zm) {
		/* We cannot support elements larger than page size for foreign memory because we
		 * put metadata on the page itself for each page of foreign memory. We need to do
		 * this in order to be able to reach the metadata when any element is freed
		 */

		for (; size > 0; newmem += PAGE_SIZE, size -= PAGE_SIZE) {
			vm_offset_t first_element_offset = 0;
			if (zone_page_metadata_size % ZONE_ELEMENT_ALIGNMENT == 0) {
				first_element_offset = zone_page_metadata_size;
			} else {
				first_element_offset = zone_page_metadata_size + (ZONE_ELEMENT_ALIGNMENT - (zone_page_metadata_size % ZONE_ELEMENT_ALIGNMENT));
			}
			element_count = (unsigned int)((PAGE_SIZE - first_element_offset) / elem_size);
			random_free_to_zone(zone, newmem, first_element_offset, element_count, entropy_buffer);
		}
	} else {
		element_count = (unsigned int)(size / elem_size);
		random_free_to_zone(zone, newmem, 0, element_count, entropy_buffer);
	}
	unlock_zone(zone);

	KDBG(MACHDBG_CODE(DBG_MACH_ZALLOC, ZALLOC_ZCRAM) | DBG_FUNC_END, zone->index);
}

/*
 * Fill a zone with enough memory to contain at least nelem elements.
 * Return the number of elements actually put into the zone, which may
 * be more than the caller asked for since the memory allocation is
 * rounded up to the next zone allocation size.
 */
int
zfill(
	zone_t  zone,
	int     nelem)
{
	kern_return_t kr;
	vm_offset_t     memory;

	vm_size_t alloc_size = zone->alloc_size;
	vm_size_t elem_per_alloc = alloc_size / zone->elem_size;
	vm_size_t nalloc = (nelem + elem_per_alloc - 1) / elem_per_alloc;

	/* Don't mix-and-match zfill with foreign memory */
	assert(!zone->allows_foreign);

	/* Trigger jetsams via the vm_pageout_garbage_collect thread if we're running out of zone memory */
	if (is_zone_map_nearing_exhaustion()) {
		thread_wakeup((event_t) &vm_pageout_garbage_collect);
	}

	kr = kernel_memory_allocate(zone_map, &memory, nalloc * alloc_size, 0, KMA_KOBJECT, VM_KERN_MEMORY_ZONE);
	if (kr != KERN_SUCCESS) {
		printf("%s: kernel_memory_allocate() of %lu bytes failed\n",
		    __func__, (unsigned long)(nalloc * alloc_size));
		return 0;
	}

	for (vm_size_t i = 0; i < nalloc; i++) {
		zcram(zone, memory + i * alloc_size, alloc_size);
	}

	return (int)(nalloc * elem_per_alloc);
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

	if (!PE_parse_boot_argn("zalloc_debug", &zalloc_debug, sizeof(zalloc_debug))) {
		zalloc_debug = 0;
	}

	/* Set up zone element poisoning */
	zp_init();

	random_bool_init(&zone_bool_gen);

	/* should zlog log to debug zone corruption instead of leaks? */
	if (PE_parse_boot_argn("-zc", temp_buf, sizeof(temp_buf))) {
		corruption_debug_flag = TRUE;
	}

#if DEBUG || DEVELOPMENT
	/* should perform zone element size checking in copyin/copyout? */
	if (PE_parse_boot_argn("-no-copyio-zalloc-check", temp_buf, sizeof(temp_buf))) {
		copyio_zalloc_check = FALSE;
	}
#if VM_MAX_TAG_ZONES
	/* enable tags for zones that ask for  */
	if (PE_parse_boot_argn("-zt", temp_buf, sizeof(temp_buf))) {
		zone_tagging_on = TRUE;
	}
#endif /* VM_MAX_TAG_ZONES */
	/* disable element location randomization in a page */
	if (PE_parse_boot_argn("-zl", temp_buf, sizeof(temp_buf))) {
		leak_scan_debug_flag = TRUE;
	}
#endif

	simple_lock_init(&all_zones_lock, 0);

	num_zones_in_use = 0;
	num_zones = 0;
	/* Mark all zones as empty */
	bitmap_full(zone_empty_bitmap, BITMAP_LEN(MAX_ZONES));
	zone_names_next = zone_names_start = 0;

#if DEBUG || DEVELOPMENT
	simple_lock_init(&zone_test_lock, 0);
#endif /* DEBUG || DEVELOPMENT */

	thread_call_setup(&call_async_alloc, zalloc_async, NULL);

	/* initializing global lock group for zones */
	lck_grp_attr_setdefault(&zone_locks_grp_attr);
	lck_grp_init(&zone_locks_grp, "zone_locks", &zone_locks_grp_attr);

	lck_attr_setdefault(&zone_metadata_lock_attr);
	lck_mtx_init_ext(&zone_metadata_region_lck, &zone_metadata_region_lck_ext, &zone_locks_grp, &zone_metadata_lock_attr);

#if     CONFIG_ZCACHE
	/* zcc_enable_for_zone_name=<zone>: enable per-cpu zone caching for <zone>. */
	if (PE_parse_boot_arg_str("zcc_enable_for_zone_name", cache_zone_name, sizeof(cache_zone_name))) {
		printf("zcache: caching enabled for zone %s\n", cache_zone_name);
	}

	/* -zcache_all: enable per-cpu zone caching for all zones, overrides 'zcc_enable_for_zone_name'. */
	if (PE_parse_boot_argn("-zcache_all", temp_buf, sizeof(temp_buf))) {
		cache_all_zones = TRUE;
		printf("zcache: caching enabled for all zones\n");
	}
#endif /* CONFIG_ZCACHE */
}

/*
 * We're being very conservative here and picking a value of 95%. We might need to lower this if
 * we find that we're not catching the problem and are still hitting zone map exhaustion panics.
 */
#define ZONE_MAP_JETSAM_LIMIT_DEFAULT 95

/*
 * Trigger zone-map-exhaustion jetsams if the zone map is X% full, where X=zone_map_jetsam_limit.
 * Can be set via boot-arg "zone_map_jetsam_limit". Set to 95% by default.
 */
unsigned int zone_map_jetsam_limit = ZONE_MAP_JETSAM_LIMIT_DEFAULT;

/*
 * Returns pid of the task with the largest number of VM map entries.
 */
extern pid_t find_largest_process_vm_map_entries(void);

/*
 * Callout to jetsam. If pid is -1, we wake up the memorystatus thread to do asynchronous kills.
 * For any other pid we try to kill that process synchronously.
 */
boolean_t memorystatus_kill_on_zone_map_exhaustion(pid_t pid);

void
get_zone_map_size(uint64_t *current_size, uint64_t *capacity)
{
	*current_size = zone_map->size;
	*capacity = vm_map_max(zone_map) - vm_map_min(zone_map);
}

void
get_largest_zone_info(char *zone_name, size_t zone_name_len, uint64_t *zone_size)
{
	zone_t largest_zone = zone_find_largest();
	strlcpy(zone_name, largest_zone->zone_name, zone_name_len);
	*zone_size = largest_zone->cur_size;
}

boolean_t
is_zone_map_nearing_exhaustion(void)
{
	uint64_t size = zone_map->size;
	uint64_t capacity = vm_map_max(zone_map) - vm_map_min(zone_map);
	if (size > ((capacity * zone_map_jetsam_limit) / 100)) {
		return TRUE;
	}
	return FALSE;
}

extern zone_t vm_map_entry_zone;
extern zone_t vm_object_zone;

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

	printf("zone_map_exhaustion: Zone map size %lld, capacity %lld [jetsam limit %d%%]\n", (uint64_t)zone_map->size,
	    (uint64_t)(vm_map_max(zone_map) - vm_map_min(zone_map)), zone_map_jetsam_limit);
	printf("zone_map_exhaustion: Largest zone %s, size %lu\n", largest_zone->zone_name, (uintptr_t)largest_zone->cur_size);

	/*
	 * We want to make sure we don't call this function from userspace. Or we could end up trying to synchronously kill the process
	 * whose context we're in, causing the system to hang.
	 */
	assert(current_task() == kernel_task);

	/*
	 * If vm_object_zone is the largest, check to see if the number of elements in vm_map_entry_zone is comparable. If so, consider
	 * vm_map_entry_zone as the largest. This lets us target a specific process to jetsam to quickly recover from the zone map bloat.
	 */
	if (largest_zone == vm_object_zone) {
		unsigned int vm_object_zone_count = vm_object_zone->count;
		unsigned int vm_map_entry_zone_count = vm_map_entry_zone->count;
		/* Is the VM map entries zone count >= 98% of the VM objects zone count? */
		if (vm_map_entry_zone_count >= ((vm_object_zone_count * VMENTRY_TO_VMOBJECT_COMPARISON_RATIO) / 100)) {
			largest_zone = vm_map_entry_zone;
			printf("zone_map_exhaustion: Picking VM map entries as the zone to target, size %lu\n", (uintptr_t)largest_zone->cur_size);
		}
	}

	/* TODO: Extend this to check for the largest process in other zones as well. */
	if (largest_zone == vm_map_entry_zone) {
		pid = find_largest_process_vm_map_entries();
	} else {
		printf("zone_map_exhaustion: Nothing to do for the largest zone [%s]. Waking up memorystatus thread.\n", largest_zone->zone_name);
	}
	if (!memorystatus_kill_on_zone_map_exhaustion(pid)) {
		printf("zone_map_exhaustion: Call to memorystatus failed, victim pid: %d\n", pid);
	}
}

/* Global initialization of Zone Allocator.
 * Runs after zone_bootstrap.
 */
void
zone_init(
	vm_size_t max_zonemap_size)
{
	kern_return_t   retval;
	vm_offset_t     zone_min;
	vm_offset_t     zone_max;
	vm_offset_t     zone_metadata_space;
	unsigned int    zone_pages;
	vm_map_kernel_flags_t vmk_flags;

#if VM_MAX_TAG_ZONES
	if (zone_tagging_on) {
		ztInit(max_zonemap_size, &zone_locks_grp);
	}
#endif

	vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
	vmk_flags.vmkf_permanent = TRUE;
	retval = kmem_suballoc(kernel_map, &zone_min, max_zonemap_size,
	    FALSE, VM_FLAGS_ANYWHERE, vmk_flags, VM_KERN_MEMORY_ZONE,
	    &zone_map);

	if (retval != KERN_SUCCESS) {
		panic("zone_init: kmem_suballoc failed");
	}
	zone_max = zone_min + round_page(max_zonemap_size);

#if     CONFIG_GZALLOC
	gzalloc_init(max_zonemap_size);
#endif

	/*
	 * Setup garbage collection information:
	 */
	zone_map_min_address = zone_min;
	zone_map_max_address = zone_max;

	zone_pages = (unsigned int)atop_kernel(zone_max - zone_min);
	zone_metadata_space = round_page(zone_pages * sizeof(struct zone_page_metadata));
	retval = kernel_memory_allocate(zone_map, &zone_metadata_region_min, zone_metadata_space,
	    0, KMA_KOBJECT | KMA_VAONLY | KMA_PERMANENT, VM_KERN_MEMORY_OSFMK);
	if (retval != KERN_SUCCESS) {
		panic("zone_init: zone_metadata_region initialization failed!");
	}
	zone_metadata_region_max = zone_metadata_region_min + zone_metadata_space;

#if defined(__LP64__)
	/*
	 * ensure that any vm_page_t that gets created from
	 * the vm_page zone can be packed properly (see vm_page.h
	 * for the packing requirements
	 */
	if ((vm_page_t)(VM_PAGE_UNPACK_PTR(VM_PAGE_PACK_PTR(zone_metadata_region_max))) != (vm_page_t)zone_metadata_region_max) {
		panic("VM_PAGE_PACK_PTR failed on zone_metadata_region_max - %p", (void *)zone_metadata_region_max);
	}

	if ((vm_page_t)(VM_PAGE_UNPACK_PTR(VM_PAGE_PACK_PTR(zone_map_max_address))) != (vm_page_t)zone_map_max_address) {
		panic("VM_PAGE_PACK_PTR failed on zone_map_max_address - %p", (void *)zone_map_max_address);
	}
#endif

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

#if VM_MAX_TAG_ZONES
	if (zone_tagging_on) {
		vm_allocation_zones_init();
	}
#endif

	int jetsam_limit_temp = 0;
	if (PE_parse_boot_argn("zone_map_jetsam_limit", &jetsam_limit_temp, sizeof(jetsam_limit_temp)) &&
	    jetsam_limit_temp > 0 && jetsam_limit_temp <= 100) {
		zone_map_jetsam_limit = jetsam_limit_temp;
	}
}

#pragma mark -
#pragma mark zalloc_canblock

extern boolean_t early_boot_complete;

void
zalloc_poison_element(boolean_t check_poison, zone_t zone, vm_offset_t addr)
{
	vm_offset_t     inner_size = zone->elem_size;
	if (__improbable(check_poison && addr)) {
		vm_offset_t *element_cursor  = ((vm_offset_t *) addr) + 1;
		vm_offset_t *backup  = get_backup_ptr(inner_size, (vm_offset_t *) addr);

		for (; element_cursor < backup; element_cursor++) {
			if (__improbable(*element_cursor != ZP_POISON)) {
				zone_element_was_modified_panic(zone,
				    addr,
				    *element_cursor,
				    ZP_POISON,
				    ((vm_offset_t)element_cursor) - addr);
			}
		}
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
}

/*
 *	zalloc returns an element from the specified zone.
 */
static void *
zalloc_internal(
	zone_t  zone,
	boolean_t canblock,
	boolean_t nopagewait,
	vm_size_t
#if !VM_MAX_TAG_ZONES
	__unused
#endif
	reqsize,
	vm_tag_t  tag)
{
	vm_offset_t     addr = 0;
	kern_return_t   retval;
	uintptr_t       zbt[MAX_ZTRACE_DEPTH];  /* used in zone leak logging and zone leak detection */
	unsigned int            numsaved = 0;
	boolean_t       zone_replenish_wakeup = FALSE, zone_alloc_throttle = FALSE;
	thread_t thr = current_thread();
	boolean_t       check_poison = FALSE;
	boolean_t       set_doing_alloc_with_vm_priv = FALSE;

#if CONFIG_ZLEAKS
	uint32_t        zleak_tracedepth = 0;  /* log this allocation if nonzero */
#endif /* CONFIG_ZLEAKS */

#if KASAN
	/*
	 * KASan uses zalloc() for fakestack, which can be called anywhere. However,
	 * we make sure these calls can never block.
	 */
	boolean_t irq_safe = FALSE;
	const char *fakestack_name = "fakestack.";
	if (strncmp(zone->zone_name, fakestack_name, strlen(fakestack_name)) == 0) {
		irq_safe = TRUE;
	}
#elif MACH_ASSERT
	/* In every other case, zalloc() from interrupt context is unsafe. */
	const boolean_t irq_safe = FALSE;
#endif

	assert(zone != ZONE_NULL);
	assert(irq_safe || ml_get_interrupts_enabled() || ml_is_quiescing() || debug_mode_active() || !early_boot_complete);

#if     CONFIG_GZALLOC
	addr = gzalloc_alloc(zone, canblock);
#endif
	/*
	 * If zone logging is turned on and this is the zone we're tracking, grab a backtrace.
	 */
	if (__improbable(DO_LOGGING(zone))) {
		numsaved = OSBacktrace((void*) zbt, MAX_ZTRACE_DEPTH);
	}

#if CONFIG_ZLEAKS
	/*
	 * Zone leak detection: capture a backtrace every zleak_sample_factor
	 * allocations in this zone.
	 */
	if (__improbable(zone->zleak_on && sample_counter(&zone->zleak_capture, zleak_sample_factor) == TRUE)) {
		/* Avoid backtracing twice if zone logging is on */
		if (numsaved == 0) {
			zleak_tracedepth = backtrace(zbt, MAX_ZTRACE_DEPTH);
		} else {
			zleak_tracedepth = numsaved;
		}
	}
#endif /* CONFIG_ZLEAKS */

#if VM_MAX_TAG_ZONES
	if (__improbable(zone->tags)) {
		vm_tag_will_update_zone(tag, zone->tag_zone_index);
	}
#endif /* VM_MAX_TAG_ZONES */

#if CONFIG_ZCACHE
	if (__probable(addr == 0)) {
		if (zone_caching_enabled(zone)) {
			addr = zcache_alloc_from_cpu_cache(zone);
			if (addr) {
#if KASAN_ZALLOC
				addr = kasan_fixup_allocated_element_address(zone, addr);
#endif
				DTRACE_VM2(zalloc, zone_t, zone, void*, addr);
				return (void *)addr;
			}
		}
	}
#endif /* CONFIG_ZCACHE */

	lock_zone(zone);
	assert(zone->zone_valid);

	if (zone->async_prio_refill && zone->zone_replenish_thread) {
		vm_size_t zfreec = (zone->cur_size - (zone->count * zone->elem_size));
		vm_size_t zrefillwm = zone->prio_refill_watermark * zone->elem_size;
		zone_replenish_wakeup = (zfreec < zrefillwm);
		zone_alloc_throttle = (((zfreec < (zrefillwm / 2)) && ((thr->options & TH_OPT_VMPRIV) == 0)) || (zfreec == 0));

		do {
			if (zone_replenish_wakeup) {
				zone_replenish_wakeups_initiated++;
				/* Signal the potentially waiting
				 * refill thread.
				 */
				thread_wakeup(&zone->zone_replenish_thread);

				/* We don't want to wait around for zone_replenish_thread to bump up the free count
				 * if we're in zone_gc(). This keeps us from deadlocking with zone_replenish_thread.
				 */
				if (thr->options & TH_OPT_ZONE_GC) {
					break;
				}

				unlock_zone(zone);
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
				assert(zone->zone_valid);
			}

			zfreec = (zone->cur_size - (zone->count * zone->elem_size));
			zrefillwm = zone->prio_refill_watermark * zone->elem_size;
			zone_replenish_wakeup = (zfreec < zrefillwm);
			zone_alloc_throttle = (((zfreec < (zrefillwm / 2)) && ((thr->options & TH_OPT_VMPRIV) == 0)) || (zfreec == 0));
		} while (zone_alloc_throttle == TRUE);
	}

	if (__probable(addr == 0)) {
		addr = try_alloc_from_zone(zone, tag, &check_poison);
	}

	/* If we're here because of zone_gc(), we didn't wait for zone_replenish_thread to finish.
	 * So we need to ensure that we did successfully grab an element. And we only need to assert
	 * this for zones that have a replenish thread configured (in this case, the Reserved VM map
	 * entries zone).
	 */
	if (thr->options & TH_OPT_ZONE_GC && zone->async_prio_refill) {
		assert(addr != 0);
	}

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
		} else {
			vm_offset_t space;
			vm_size_t alloc_size;
			int retry = 0;

			if ((zone->cur_size + zone->elem_size) >
			    zone->max_size) {
				if (zone->exhaustible) {
					break;
				}
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
					if (zleak_state & ZLEAK_STATE_ACTIVE) {
						panic_include_ztrace = TRUE;
					}
#endif /* CONFIG_ZLEAKS */
					panic("zalloc: zone \"%s\" empty.", zone->zone_name);
				}
			}
			/*
			 * It is possible that a BG thread is refilling/expanding the zone
			 * and gets pre-empted during that operation. That blocks all other
			 * threads from making progress leading to a watchdog timeout. To
			 * avoid that, boost the thread priority using the rwlock boost
			 */
			set_thread_rwlock_boost();

			if ((thr->options & TH_OPT_VMPRIV)) {
				zone->doing_alloc_with_vm_priv = TRUE;
				set_doing_alloc_with_vm_priv = TRUE;
			} else {
				zone->doing_alloc_without_vm_priv = TRUE;
			}
			unlock_zone(zone);

			for (;;) {
				int     zflags = KMA_KOBJECT | KMA_NOPAGEWAIT;

				if (vm_pool_low() || retry >= 1) {
					alloc_size =
					    round_page(zone->elem_size);
				} else {
					alloc_size = zone->alloc_size;
				}

				if (zone->noencrypt) {
					zflags |= KMA_NOENCRYPT;
				}

				/* Trigger jetsams via the vm_pageout_garbage_collect thread if we're running out of zone memory */
				if (is_zone_map_nearing_exhaustion()) {
					thread_wakeup((event_t) &vm_pageout_garbage_collect);
				}

				retval = kernel_memory_allocate(zone_map, &space, alloc_size, 0, zflags, VM_KERN_MEMORY_ZONE);
				if (retval == KERN_SUCCESS) {
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
						panic("zalloc: \"%s\" (%d elements) retry fail %d", zone->zone_name, zone->count, retval);
					}
				} else {
					break;
				}
			}
			lock_zone(zone);
			assert(zone->zone_valid);

			if (set_doing_alloc_with_vm_priv == TRUE) {
				zone->doing_alloc_with_vm_priv = FALSE;
			} else {
				zone->doing_alloc_without_vm_priv = FALSE;
			}

			if (zone->waiting) {
				zone->waiting = FALSE;
				zone_wakeup(zone);
			}
			clear_thread_rwlock_boost();

			addr = try_alloc_from_zone(zone, tag, &check_poison);
			if (addr == 0 &&
			    retval == KERN_RESOURCE_SHORTAGE) {
				if (nopagewait == TRUE) {
					break;  /* out of the main while loop */
				}
				unlock_zone(zone);

				VM_PAGE_WAIT();
				lock_zone(zone);
				assert(zone->zone_valid);
			}
		}
		if (addr == 0) {
			addr = try_alloc_from_zone(zone, tag, &check_poison);
		}
	}

#if CONFIG_ZLEAKS
	/* Zone leak detection:
	 * If we're sampling this allocation, add it to the zleaks hash table.
	 */
	if (addr && zleak_tracedepth > 0) {
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
		assert(zone->zone_valid);
		addr = try_alloc_from_zone(zone, tag, &check_poison);
	}

#if VM_MAX_TAG_ZONES
	if (__improbable(zone->tags) && addr) {
		if (reqsize) {
			reqsize = zone->elem_size - reqsize;
		}
		vm_tag_update_zone_size(tag, zone->tag_zone_index, zone->elem_size, reqsize);
	}
#endif /* VM_MAX_TAG_ZONES */

	unlock_zone(zone);

	if (__improbable(DO_LOGGING(zone) && addr)) {
		btlog_add_entry(zone->zlog_btlog, (void *)addr, ZOP_ALLOC, (void **)zbt, numsaved);
	}

	zalloc_poison_element(check_poison, zone, addr);

	if (addr) {
#if DEBUG || DEVELOPMENT
		if (__improbable(leak_scan_debug_flag && !(zone->elem_size & (sizeof(uintptr_t) - 1)))) {
			unsigned int count, idx;
			/* Fill element, from tail, with backtrace in reverse order */
			if (numsaved == 0) {
				numsaved = backtrace(zbt, MAX_ZTRACE_DEPTH);
			}
			count = (unsigned int)(zone->elem_size / sizeof(uintptr_t));
			if (count >= numsaved) {
				count = numsaved - 1;
			}
			for (idx = 0; idx < count; idx++) {
				((uintptr_t *)addr)[count - 1 - idx] = zbt[idx + 1];
			}
		}
#endif /* DEBUG || DEVELOPMENT */
	}

	TRACE_MACHLEAKS(ZALLOC_CODE, ZALLOC_CODE_2, zone->elem_size, addr);


#if KASAN_ZALLOC
	addr = kasan_fixup_allocated_element_address(zone, addr);
#endif

	DTRACE_VM2(zalloc, zone_t, zone, void*, addr);

	return (void *)addr;
}

void *
zalloc(zone_t zone)
{
	return zalloc_internal(zone, TRUE, FALSE, 0, VM_KERN_MEMORY_NONE);
}

void *
zalloc_noblock(zone_t zone)
{
	return zalloc_internal(zone, FALSE, FALSE, 0, VM_KERN_MEMORY_NONE);
}

void *
zalloc_nopagewait(zone_t zone)
{
	return zalloc_internal(zone, TRUE, TRUE, 0, VM_KERN_MEMORY_NONE);
}

void *
zalloc_canblock_tag(zone_t zone, boolean_t canblock, vm_size_t reqsize, vm_tag_t tag)
{
	return zalloc_internal(zone, canblock, FALSE, reqsize, tag);
}

void *
zalloc_canblock(zone_t zone, boolean_t canblock)
{
	return zalloc_internal(zone, canblock, FALSE, 0, VM_KERN_MEMORY_NONE);
}

void *
zalloc_attempt(zone_t zone)
{
	boolean_t check_poison = FALSE;
	vm_offset_t addr = try_alloc_from_zone(zone, VM_KERN_MEMORY_NONE, &check_poison);
	zalloc_poison_element(check_poison, zone, addr);
	return (void *)addr;
}

void
zfree_direct(zone_t zone, vm_offset_t elem)
{
	boolean_t       poison = zfree_poison_element(zone, elem);
	free_to_zone(zone, elem, poison);
}


void
zalloc_async(
	__unused thread_call_param_t          p0,
	__unused thread_call_param_t p1)
{
	zone_t current_z = NULL;
	unsigned int max_zones, i;
	void *elt = NULL;
	boolean_t pending = FALSE;

	simple_lock(&all_zones_lock, &zone_locks_grp);
	max_zones = num_zones;
	simple_unlock(&all_zones_lock);
	for (i = 0; i < max_zones; i++) {
		current_z = &(zone_array[i]);

		if (current_z->no_callout == TRUE) {
			/* async_pending will never be set */
			continue;
		}

		lock_zone(current_z);
		if (current_z->zone_valid && current_z->async_pending == TRUE) {
			current_z->async_pending = FALSE;
			pending = TRUE;
		}
		unlock_zone(current_z);

		if (pending == TRUE) {
			elt = zalloc_canblock_tag(current_z, TRUE, 0, VM_KERN_MEMORY_OSFMK);
			zfree(current_z, elt);
			pending = FALSE;
		}
	}
}

/*
 *	zget returns an element from the specified zone
 *	and immediately returns nothing if there is nothing there.
 */
void *
zget(
	zone_t  zone)
{
	return zalloc_internal(zone, FALSE, TRUE, 0, VM_KERN_MEMORY_NONE);
}

/* Keep this FALSE by default.  Large memory machine run orders of magnitude
 *  slower in debug mode when true.  Use debugger to enable if needed */
/* static */ boolean_t zone_check = FALSE;

static void
zone_check_freelist(zone_t zone, vm_offset_t elem)
{
	struct zone_free_element *this;
	struct zone_page_metadata *thispage;

	if (zone->allows_foreign) {
		for (thispage = (struct zone_page_metadata *)queue_first(&zone->pages.any_free_foreign);
		    !queue_end(&zone->pages.any_free_foreign, &(thispage->pages));
		    thispage = (struct zone_page_metadata *)queue_next(&(thispage->pages))) {
			for (this = page_metadata_get_freelist(thispage);
			    this != NULL;
			    this = this->next) {
				if (!is_sane_zone_element(zone, (vm_address_t)this) || (vm_address_t)this == elem) {
					panic("zone_check_freelist");
				}
			}
		}
	}
	for (thispage = (struct zone_page_metadata *)queue_first(&zone->pages.all_free);
	    !queue_end(&zone->pages.all_free, &(thispage->pages));
	    thispage = (struct zone_page_metadata *)queue_next(&(thispage->pages))) {
		for (this = page_metadata_get_freelist(thispage);
		    this != NULL;
		    this = this->next) {
			if (!is_sane_zone_element(zone, (vm_address_t)this) || (vm_address_t)this == elem) {
				panic("zone_check_freelist");
			}
		}
	}
	for (thispage = (struct zone_page_metadata *)queue_first(&zone->pages.intermediate);
	    !queue_end(&zone->pages.intermediate, &(thispage->pages));
	    thispage = (struct zone_page_metadata *)queue_next(&(thispage->pages))) {
		for (this = page_metadata_get_freelist(thispage);
		    this != NULL;
		    this = this->next) {
			if (!is_sane_zone_element(zone, (vm_address_t)this) || (vm_address_t)this == elem) {
				panic("zone_check_freelist");
			}
		}
	}
}

boolean_t
zfree_poison_element(zone_t zone, vm_offset_t elem)
{
	boolean_t       poison = FALSE;
	if (zp_factor != 0 || zp_tiny_zone_limit != 0) {
		/*
		 * Poison the memory before it ends up on the freelist to catch
		 * use-after-free and use of uninitialized memory
		 *
		 * Always poison tiny zones' elements (limit is 0 if -no-zp is set)
		 * Also poison larger elements periodically
		 */

		vm_offset_t     inner_size = zone->elem_size;

		uint32_t sample_factor = zp_factor + (((uint32_t)inner_size) >> zp_scale);

		if (inner_size <= zp_tiny_zone_limit) {
			poison = TRUE;
		} else if (zp_factor != 0 && sample_counter(&zone->zp_count, sample_factor) == TRUE) {
			poison = TRUE;
		}

		if (__improbable(poison)) {
			/* memset_pattern{4|8} could help make this faster: <rdar://problem/4662004> */
			/* Poison everything but primary and backup */
			vm_offset_t *element_cursor  = ((vm_offset_t *) elem) + 1;
			vm_offset_t *backup   = get_backup_ptr(inner_size, (vm_offset_t *)elem);

			for (; element_cursor < backup; element_cursor++) {
				*element_cursor = ZP_POISON;
			}
		}
	}
	return poison;
}
void
(zfree)(
	zone_t  zone,
	void            *addr)
{
	vm_offset_t     elem = (vm_offset_t) addr;
	uintptr_t       zbt[MAX_ZTRACE_DEPTH];                  /* only used if zone logging is enabled via boot-args */
	unsigned int            numsaved = 0;
	boolean_t       gzfreed = FALSE;
	boolean_t       poison = FALSE;
#if VM_MAX_TAG_ZONES
	vm_tag_t tag;
#endif /* VM_MAX_TAG_ZONES */

	assert(zone != ZONE_NULL);
	DTRACE_VM2(zfree, zone_t, zone, void*, addr);
#if KASAN_ZALLOC
	if (kasan_quarantine_freed_element(&zone, &addr)) {
		return;
	}
	elem = (vm_offset_t)addr;
#endif

	/*
	 * If zone logging is turned on and this is the zone we're tracking, grab a backtrace.
	 */

	if (__improbable(DO_LOGGING(zone) && corruption_debug_flag)) {
		numsaved = OSBacktrace((void *)zbt, MAX_ZTRACE_DEPTH);
	}

#if MACH_ASSERT
	/* Basic sanity checks */
	if (zone == ZONE_NULL || elem == (vm_offset_t)0) {
		panic("zfree: NULL");
	}
#endif

#if     CONFIG_GZALLOC
	gzfreed = gzalloc_free(zone, addr);
#endif

	if (!gzfreed) {
		struct zone_page_metadata *page_meta = get_zone_page_metadata((struct zone_free_element *)addr, FALSE);
		if (zone != PAGE_METADATA_GET_ZONE(page_meta)) {
			panic("Element %p from zone %s caught being freed to wrong zone %s\n", addr, PAGE_METADATA_GET_ZONE(page_meta)->zone_name, zone->zone_name);
		}
	}

	TRACE_MACHLEAKS(ZFREE_CODE, ZFREE_CODE_2, zone->elem_size, (uintptr_t)addr);

	if (__improbable(!gzfreed && zone->collectable && !zone->allows_foreign &&
	    !from_zone_map(elem, zone->elem_size))) {
		panic("zfree: non-allocated memory in collectable zone!");
	}

	if (!gzfreed) {
		poison = zfree_poison_element(zone, elem);
	}

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
			btlog_add_entry(zone->zlog_btlog, (void *)addr, ZOP_FREE, (void **)zbt, numsaved);
		} else {
			/*
			 * We're logging to catch a leak. Remove any record we might have for this
			 * element since it's being freed.  Note that we may not find it if the buffer
			 * overflowed and that's OK.  Since the log is of a limited size, old records
			 * get overwritten if there are more zallocs than zfrees.
			 */
			btlog_remove_entries_for_element(zone->zlog_btlog, (void *)addr);
		}
	}

#if CONFIG_ZCACHE
	if (zone_caching_enabled(zone)) {
		int __assert_only ret = zcache_free_to_cpu_cache(zone, addr);
		assert(ret != FALSE);
		return;
	}
#endif /* CONFIG_ZCACHE */

	lock_zone(zone);
	assert(zone->zone_valid);

	if (zone_check) {
		zone_check_freelist(zone, elem);
	}

	if (__probable(!gzfreed)) {
#if VM_MAX_TAG_ZONES
		if (__improbable(zone->tags)) {
			tag = (ZTAG(zone, elem)[0] >> 1);
			// set the tag with b0 clear so the block remains inuse
			ZTAG(zone, elem)[0] = 0xFFFE;
		}
#endif /* VM_MAX_TAG_ZONES */
		free_to_zone(zone, elem, poison);
	}

	if (__improbable(zone->count < 0)) {
		panic("zfree: zone count underflow in zone %s while freeing element %p, possible cause: double frees or freeing memory that did not come from this zone",
		    zone->zone_name, addr);
	}

#if CONFIG_ZLEAKS
	/*
	 * Zone leak detection: un-track the allocation
	 */
	if (zone->zleak_on) {
		zleak_free(elem, zone->elem_size);
	}
#endif /* CONFIG_ZLEAKS */

#if VM_MAX_TAG_ZONES
	if (__improbable(zone->tags) && __probable(!gzfreed)) {
		vm_tag_update_zone_size(tag, zone->tag_zone_index, -((int64_t)zone->elem_size), 0);
	}
#endif /* VM_MAX_TAG_ZONES */

	unlock_zone(zone);
}

/*	Change a zone's flags.
 *	This routine must be called immediately after zinit.
 */
void
zone_change(
	zone_t          zone,
	unsigned int    item,
	boolean_t       value)
{
	assert( zone != ZONE_NULL );
	assert( value == TRUE || value == FALSE );

	switch (item) {
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
	case Z_TAGS_ENABLED:
#if VM_MAX_TAG_ZONES
		{
			static int tag_zone_index;
			zone->tags = TRUE;
			zone->tags_inline = (((page_size + zone->elem_size - 1) / zone->elem_size) <= (sizeof(uint32_t) / sizeof(uint16_t)));
			zone->tag_zone_index = OSAddAtomic(1, &tag_zone_index);
		}
#endif /* VM_MAX_TAG_ZONES */
		break;
	case Z_GZALLOC_EXEMPT:
		zone->gzalloc_exempt = value;
#if     CONFIG_GZALLOC
		gzalloc_reconfigure(zone);
#endif
		break;
	case Z_ALIGNMENT_REQUIRED:
		zone->alignment_required = value;
#if KASAN_ZALLOC
		if (zone->kasan_redzone == KASAN_GUARD_SIZE) {
			/* Don't disturb alignment with the redzone for zones with
			 * specific alignment requirements. */
			zone->elem_size -= zone->kasan_redzone * 2;
			zone->kasan_redzone = 0;
		}
#endif
#if     CONFIG_GZALLOC
		gzalloc_reconfigure(zone);
#endif
		break;
	case Z_KASAN_QUARANTINE:
		zone->kasan_quarantine = value;
		break;
	case Z_CACHING_ENABLED:
#if     CONFIG_ZCACHE
		if (value == TRUE && use_caching) {
			if (zcache_ready()) {
				zcache_init(zone);
			} else {
				zone->cpu_cache_enable_when_ready = TRUE;
			}
		}
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

	return free_count;
}

/* Drops the elements in the free queue of a zone. Called by zone_gc() on each zone, and when a zone is zdestroy'ed. */
void
drop_free_elements(zone_t z)
{
	vm_size_t                                       elt_size, size_freed;
	unsigned int                                                    total_freed_pages = 0;
	uint64_t                                        old_all_free_count;
	struct zone_page_metadata       *page_meta;
	queue_head_t                            page_meta_head;

	lock_zone(z);
	if (queue_empty(&z->pages.all_free)) {
		unlock_zone(z);
		return;
	}

	/*
	 * Snatch all of the free elements away from the zone.
	 */
	elt_size = z->elem_size;
	old_all_free_count = z->count_all_free_pages;
	queue_new_head(&z->pages.all_free, &page_meta_head, struct zone_page_metadata *, pages);
	queue_init(&z->pages.all_free);
	z->count_all_free_pages = 0;
	unlock_zone(z);

	/* Iterate through all elements to find out size and count of elements we snatched */
	size_freed = 0;
	queue_iterate(&page_meta_head, page_meta, struct zone_page_metadata *, pages) {
		assert(from_zone_map((vm_address_t)page_meta, sizeof(*page_meta))); /* foreign elements should be in any_free_foreign */
		size_freed += elt_size * page_meta->free_count;
	}

	/* Update the zone size and free element count */
	lock_zone(z);
	z->cur_size -= size_freed;
	z->countfree -= size_freed / elt_size;
	unlock_zone(z);

	while ((page_meta = (struct zone_page_metadata *)dequeue_head(&page_meta_head)) != NULL) {
		vm_address_t        free_page_address;
		/* Free the pages for metadata and account for them */
		free_page_address = get_zone_page(page_meta);
		ZONE_PAGE_COUNT_DECR(z, page_meta->page_count);
		total_freed_pages += page_meta->page_count;
		old_all_free_count -= page_meta->page_count;
#if KASAN_ZALLOC
		kasan_poison_range(free_page_address, page_meta->page_count * PAGE_SIZE, ASAN_VALID);
#endif
#if VM_MAX_TAG_ZONES
		if (z->tags) {
			ztMemoryRemove(z, free_page_address, (page_meta->page_count * PAGE_SIZE));
		}
#endif /* VM_MAX_TAG_ZONES */
		kmem_free(zone_map, free_page_address, (page_meta->page_count * PAGE_SIZE));
		if (current_thread()->options & TH_OPT_ZONE_GC) {
			thread_yield_to_preemption();
		}
	}

	/* We freed all the pages from the all_free list for this zone */
	assert(old_all_free_count == 0);

	if (zalloc_debug & ZALLOC_DEBUG_ZONEGC) {
		kprintf("zone_gc() of zone %s freed %lu elements, %d pages\n", z->zone_name, (unsigned long)size_freed / elt_size, total_freed_pages);
	}
}

/*	Zone garbage collection
 *
 *	zone_gc will walk through all the free elements in all the
 *	zones that are marked collectable looking for reclaimable
 *	pages.  zone_gc is called by consider_zone_gc when the system
 *	begins to run out of memory.
 *
 *	We should ensure that zone_gc never blocks.
 */
void
zone_gc(boolean_t consider_jetsams)
{
	unsigned int    max_zones;
	zone_t                  z;
	unsigned int    i;

	if (consider_jetsams) {
		kill_process_in_largest_zone();
		/*
		 * If we do end up jetsamming something, we need to do a zone_gc so that
		 * we can reclaim free zone elements and update the zone map size.
		 * Fall through.
		 */
	}

	lck_mtx_lock(&zone_gc_lock);

	current_thread()->options |= TH_OPT_ZONE_GC;

	simple_lock(&all_zones_lock, &zone_locks_grp);
	max_zones = num_zones;
	simple_unlock(&all_zones_lock);

	if (zalloc_debug & ZALLOC_DEBUG_ZONEGC) {
		kprintf("zone_gc() starting...\n");
	}

	for (i = 0; i < max_zones; i++) {
		z = &(zone_array[i]);
		assert(z != ZONE_NULL);

		if (!z->collectable) {
			continue;
		}
#if CONFIG_ZCACHE
		if (zone_caching_enabled(z)) {
			zcache_drain_depot(z);
		}
#endif /* CONFIG_ZCACHE */
		if (queue_empty(&z->pages.all_free)) {
			continue;
		}

		drop_free_elements(z);
	}

	current_thread()->options &= ~TH_OPT_ZONE_GC;

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
consider_zone_gc(boolean_t consider_jetsams)
{
	if (kmapoff_kaddr != 0) {
		/*
		 * One-time reclaim of kernel_map resources we allocated in
		 * early boot.
		 */
		(void) vm_deallocate(kernel_map,
		    kmapoff_kaddr, kmapoff_pgcnt * PAGE_SIZE_64);
		kmapoff_kaddr = 0;
	}

	if (zone_gc_allowed) {
		zone_gc(consider_jetsams);
	}
}

/*
 * Creates a vm_map_copy_t to return to the caller of mach_* MIG calls
 * requesting zone information.
 * Frees unused pages towards the end of the region, and zero'es out unused
 * space on the last page.
 */
vm_map_copy_t
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

boolean_t
get_zone_info(
	zone_t                          z,
	mach_zone_name_t        *zn,
	mach_zone_info_t        *zi)
{
	struct zone zcopy;

	assert(z != ZONE_NULL);
	lock_zone(z);
	if (!z->zone_valid) {
		unlock_zone(z);
		return FALSE;
	}
	zcopy = *z;
	unlock_zone(z);

	if (zn != NULL) {
		/* assuming here the name data is static */
		(void) __nosan_strlcpy(zn->mzn_name, zcopy.zone_name,
		    strlen(zcopy.zone_name) + 1);
	}

	if (zi != NULL) {
		zi->mzi_count = (uint64_t)zcopy.count;
		zi->mzi_cur_size = ptoa_64(zcopy.page_count);
		zi->mzi_max_size = (uint64_t)zcopy.max_size;
		zi->mzi_elem_size = (uint64_t)zcopy.elem_size;
		zi->mzi_alloc_size = (uint64_t)zcopy.alloc_size;
		zi->mzi_sum_size = zcopy.sum_count * zcopy.elem_size;
		zi->mzi_exhaustible = (uint64_t)zcopy.exhaustible;
		zi->mzi_collectable = 0;
		if (zcopy.collectable) {
			SET_MZI_COLLECTABLE_BYTES(zi->mzi_collectable, ((uint64_t)zcopy.count_all_free_pages * PAGE_SIZE));
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

	simple_lock(&all_zones_lock, &zone_locks_grp);
	max_zones = (unsigned int)(num_zones);
	simple_unlock(&all_zones_lock);

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
	unsigned int max_zones, i;
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

	simple_lock(&all_zones_lock, &zone_locks_grp);
	max_zones = (unsigned int)(num_zones);
	simple_unlock(&all_zones_lock);

	zone_ptr = ZONE_NULL;
	for (i = 0; i < max_zones; i++) {
		zone_t z = &(zone_array[i]);
		assert(z != ZONE_NULL);

		/* Find the requested zone by name */
		if (track_this_zone(z->zone_name, name.mzn_name)) {
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
	unsigned int i, max_zones;
	uint64_t zones_collectable_bytes = 0;
	mach_zone_info_t zi;

	simple_lock(&all_zones_lock, &zone_locks_grp);
	max_zones = (unsigned int)(num_zones);
	simple_unlock(&all_zones_lock);

	for (i = 0; i < max_zones; i++) {
		if (get_zone_info(&(zone_array[i]), NULL, &zi)) {
			zones_collectable_bytes += GET_MZI_COLLECTABLE_BYTES(zi.mzi_collectable);
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
#if DEBUG || DEVELOPMENT
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

	simple_lock(&all_zones_lock, &zone_locks_grp);
	max_zones = (unsigned int)(num_zones);
	simple_unlock(&all_zones_lock);

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

#else /* DEBUG || DEVELOPMENT */
#pragma unused(host, namesp, namesCntp)
	return KERN_FAILURE;
#endif /* DEBUG || DEVELOPMENT */
}

kern_return_t
mach_zone_get_btlog_records(
	host_priv_t                             host,
	mach_zone_name_t                name,
	zone_btrecord_array_t   *recsp,
	mach_msg_type_number_t  *recsCntp)
{
#if DEBUG || DEVELOPMENT
	unsigned int max_zones, i, numrecs = 0;
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

	simple_lock(&all_zones_lock, &zone_locks_grp);
	max_zones = (unsigned int)(num_zones);
	simple_unlock(&all_zones_lock);

	zone_ptr = ZONE_NULL;
	for (i = 0; i < max_zones; i++) {
		zone_t z = &(zone_array[i]);
		assert(z != ZONE_NULL);

		/* Find the requested zone by name */
		if (track_this_zone(z->zone_name, name.mzn_name)) {
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
	zone_t                       zone;
	unsigned int         idx, num_info, max_zones;
	vm_offset_t                  memory_info_addr;
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

	simple_lock(&all_zones_lock, &zone_locks_grp);
	max_zones = num_zones;
	simple_unlock(&all_zones_lock);

	top_wired = total = zonestotal = 0;
	for (idx = 0; idx < max_zones; idx++) {
		zone = &(zone_array[idx]);
		assert(zone != ZONE_NULL);
		lock_zone(zone);
		zonestotal += ptoa_64(zone->page_count);
		unlock_zone(zone);
	}
	for (idx = 0; idx < num_info; idx++) {
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

	printf("vm_page_diagnose_check %qd of %qd, zones %qd, short 0x%qx\n", total, top_wired, zonestotal, top_wired - total);

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
	consider_zone_gc(FALSE);
#endif /* DEBUG || DEVELOPMENT */
	return KERN_SUCCESS;
}

extern unsigned int stack_total;
extern unsigned long long stack_allocs;

#if defined(__i386__) || defined (__x86_64__)
extern unsigned int inuse_ptepages_count;
extern long long alloc_ptepages_count;
#endif

zone_t
zone_find_largest(void)
{
	unsigned int    i;
	unsigned int    max_zones;
	zone_t          the_zone;
	zone_t          zone_largest;

	simple_lock(&all_zones_lock, &zone_locks_grp);
	max_zones = num_zones;
	simple_unlock(&all_zones_lock);

	zone_largest = &(zone_array[0]);
	for (i = 0; i < max_zones; i++) {
		the_zone = &(zone_array[i]);
		if (the_zone->cur_size > zone_largest->cur_size) {
			zone_largest = the_zone;
		}
	}
	return zone_largest;
}

#if     ZONE_DEBUG

/* should we care about locks here ? */

#define zone_in_use(z)  ( z->count || z->free_elements \
	                                          || !queue_empty(&z->pages.all_free) \
	                                          || !queue_empty(&z->pages.intermediate) \
	                                          || (z->allows_foreign && !queue_empty(&z->pages.any_free_foreign)))


#endif  /* ZONE_DEBUG */


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if DEBUG || DEVELOPMENT

static uintptr_t *
zone_copy_all_allocations_inqueue(zone_t z, queue_head_t * queue, uintptr_t * elems)
{
	struct zone_page_metadata *page_meta;
	vm_offset_t free, elements;
	vm_offset_t idx, numElements, freeCount, bytesAvail, metaSize;

	queue_iterate(queue, page_meta, struct zone_page_metadata *, pages)
	{
		elements = get_zone_page(page_meta);
		bytesAvail = ptoa(page_meta->page_count);
		freeCount = 0;
		if (z->allows_foreign && !from_zone_map(elements, z->elem_size)) {
			metaSize    = (sizeof(struct zone_page_metadata) + ZONE_ELEMENT_ALIGNMENT - 1) & ~(ZONE_ELEMENT_ALIGNMENT - 1);
			bytesAvail -= metaSize;
			elements   += metaSize;
		}
		numElements = bytesAvail / z->elem_size;
		// construct array of all possible elements
		for (idx = 0; idx < numElements; idx++) {
			elems[idx] = INSTANCE_PUT(elements + idx * z->elem_size);
		}
		// remove from the array all free elements
		free = (vm_offset_t)page_metadata_get_freelist(page_meta);
		while (free) {
			// find idx of free element
			for (idx = 0; (idx < numElements) && (elems[idx] != INSTANCE_PUT(free)); idx++) {
			}
			assert(idx < numElements);
			// remove it
			bcopy(&elems[idx + 1], &elems[idx], (numElements - (idx + 1)) * sizeof(elems[0]));
			numElements--;
			freeCount++;
			// next free element
			vm_offset_t *primary = (vm_offset_t *) free;
			free = *primary ^ zp_nopoison_cookie;
		}
		elems += numElements;
	}

	return elems;
}

kern_return_t
zone_leaks(const char * zoneName, uint32_t nameLen, leak_site_proc proc, void * refCon)
{
	uintptr_t         zbt[MAX_ZTRACE_DEPTH];
	zone_t        zone;
	uintptr_t *   array;
	uintptr_t *   next;
	uintptr_t     element, bt;
	uint32_t      idx, count, found;
	uint32_t      btidx, btcount, nobtcount, btfound;
	uint32_t      elemSize;
	uint64_t      maxElems;
	unsigned int  max_zones;
	kern_return_t kr;

	simple_lock(&all_zones_lock, &zone_locks_grp);
	max_zones = num_zones;
	simple_unlock(&all_zones_lock);

	for (idx = 0; idx < max_zones; idx++) {
		if (!strncmp(zoneName, zone_array[idx].zone_name, nameLen)) {
			break;
		}
	}
	if (idx >= max_zones) {
		return KERN_INVALID_NAME;
	}
	zone = &zone_array[idx];

	elemSize = (uint32_t) zone->elem_size;
	maxElems = ptoa(zone->page_count) / elemSize;

	if ((zone->alloc_size % elemSize)
	    && !leak_scan_debug_flag) {
		return KERN_INVALID_CAPABILITY;
	}

	kr = kmem_alloc_kobject(kernel_map, (vm_offset_t *) &array,
	    maxElems * sizeof(uintptr_t), VM_KERN_MEMORY_DIAG);
	if (KERN_SUCCESS != kr) {
		return kr;
	}

	lock_zone(zone);

	next = array;
	next = zone_copy_all_allocations_inqueue(zone, &zone->pages.any_free_foreign, next);
	next = zone_copy_all_allocations_inqueue(zone, &zone->pages.intermediate, next);
	next = zone_copy_all_allocations_inqueue(zone, &zone->pages.all_used, next);
	count = (uint32_t)(next - array);

	unlock_zone(zone);

	zone_leaks_scan(array, count, (uint32_t)zone->elem_size, &found);
	assert(found <= count);

	for (idx = 0; idx < count; idx++) {
		element = array[idx];
		if (kInstanceFlagReferenced & element) {
			continue;
		}
		element = INSTANCE_PUT(element) & ~kInstanceFlags;
	}

	if (zone->zlog_btlog && !corruption_debug_flag) {
		// btlog_copy_backtraces_for_elements will set kInstanceFlagReferenced on elements it found
		btlog_copy_backtraces_for_elements(zone->zlog_btlog, array, &count, elemSize, proc, refCon);
	}

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
		btcount = (typeof(btcount))(zone->elem_size / sizeof(uintptr_t));
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
kdp_is_in_zone(void *addr, const char *zone_name)
{
	zone_t z;
	return zone_element_size(addr, &z) && !strcmp(z->zone_name, zone_name);
}

boolean_t
run_zone_test(void)
{
	unsigned int i = 0, max_iter = 5;
	void * test_ptr;
	zone_t test_zone;

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
		if (test_zone_ptr == NULL && zone_free_count(test_zone) != 0) {
#else
		if (zone_free_count(test_zone) != 0) {
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

	printf("run_zone_test: Test passed\n");

	simple_lock(&zone_test_lock, &zone_locks_grp);
	zone_test_running = FALSE;
	simple_unlock(&zone_test_lock);

	return TRUE;
}

#endif /* DEBUG || DEVELOPMENT */
