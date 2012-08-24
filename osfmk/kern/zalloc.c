/*
 * Copyright (c) 2000-2011 Apple Inc. All rights reserved.
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

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>

#include <pexpert/pexpert.h>

#include <machine/machparam.h>

#include <libkern/OSDebug.h>
#include <libkern/OSAtomic.h>
#include <sys/kdebug.h>

/* 
 * Zone Corruption Debugging
 *
 * We perform three methods to detect use of a zone element after it's been freed. These
 * checks are enabled for every N'th element (counted per-zone) by specifying
 * "zp-factor=N" as a boot-arg. To turn this feature off, set "zp-factor=0" or "-no-zp".
 *
 * (1) Range-check the free-list "next" pointer for sanity.
 * (2) Store the pointer in two different words, one at the beginning of the freed element
 *     and one at the end, and compare them against each other when re-using the element,
 *     to detect modifications.
 * (3) Poison the freed memory by overwriting it with 0xdeadbeef, and check it when the
 *     memory is being reused to make sure it is still poisoned.
 *
 * As a result, each element (that is large enough to hold this data inside) must be marked
 * as either "ZP_POISONED" or "ZP_NOT_POISONED" in the first integer within the would-be
 * poisoned segment after the first free-list pointer.
 *
 * Performance slowdown is inversely proportional to the frequency with which you check
 * (as would be expected), with a 4-5% hit around N=1, down to ~0.3% at N=16 and just
 * "noise" at N=32 and higher. You can expect to find a 100% reproducible
 * bug in an average of N tries, with a standard deviation of about N, but you will probably
 * want to set "zp-factor=1" or "-zp" if you are attempting to reproduce a known bug.
 *
 *
 * Zone corruption logging
 *
 * You can also track where corruptions come from by using the boot-arguments:
 * "zlog=<zone name to log> -zc". Search for "Zone corruption logging" later in this
 * document for more implementation and usage information.
 */

#define ZP_POISON       0xdeadbeef
#define ZP_POISONED     0xfeedface
#define ZP_NOT_POISONED 0xbaddecaf

#if CONFIG_EMBEDDED
	#define ZP_DEFAULT_SAMPLING_FACTOR 0
#else /* CONFIG_EMBEDDED */
	#define ZP_DEFAULT_SAMPLING_FACTOR 16
#endif /* CONFIG_EMBEDDED */

uint32_t 	free_check_sample_factor = 0;		/* set by zp-factor=N boot arg */
boolean_t	corruption_debug_flag    = FALSE;	/* enabled by "-zc" boot-arg */

/* 
 * Zone checking helper macro.
 */
#define is_kernel_data_addr(a)	(!(a) || ((a) >= vm_min_kernel_address && !((a) & 0x3)))

/*
 * Frees the specified element, which is within the specified zone. If this
 * element should be poisoned and its free list checker should be set, both are
 * done here. These checks will only be enabled if the element size is at least
 * large enough to hold two vm_offset_t's and one uint32_t (to enable both types
 * of checks).
 */
static inline void
free_to_zone(zone_t zone, void *elem) {
	/* get the index of the first uint32_t beyond the 'next' pointer */
	unsigned int i = sizeof(vm_offset_t) / sizeof(uint32_t);
	
	/* should we run checks on this piece of memory? */
	if (free_check_sample_factor != 0 &&
	    zone->free_check_count++ % free_check_sample_factor == 0 &&
	    zone->elem_size >= (2 * sizeof(vm_offset_t) + sizeof(uint32_t))) {
		zone->free_check_count = 1;
		((uint32_t *) elem)[i] = ZP_POISONED;
		for (i++; i < zone->elem_size / sizeof(uint32_t); i++) {
			((uint32_t *) elem)[i] = ZP_POISON;
		}
		((vm_offset_t *) elem)[((zone->elem_size)/sizeof(vm_offset_t))-1] = zone->free_elements;
	} else {
		((uint32_t *) elem)[i] = ZP_NOT_POISONED;
	}
	
	/* maintain free list and decrement number of active objects in zone */
	((vm_offset_t *) elem)[0] = zone->free_elements;
	zone->free_elements = (vm_offset_t) elem;
	zone->count--;
}

/*
 * Allocates an element from the specifed zone, storing its address in the
 * return arg. This function will look for corruptions revealed through zone
 * poisoning and free list checks.
 */
static inline void
alloc_from_zone(zone_t zone, void **ret) {
	void *elem = (void *) zone->free_elements;
	if (elem != NULL) {
		/* get the index of the first uint32_t beyond the 'next' pointer */
		unsigned int i = sizeof(vm_offset_t) / sizeof(uint32_t);
		
		/* first int in data section must be ZP_POISONED or ZP_NOT_POISONED */
		if (((uint32_t *) elem)[i] == ZP_POISONED &&
		    zone->elem_size >= (2 * sizeof(vm_offset_t) + sizeof(uint32_t))) {
			/* check the free list pointers */
			if (!is_kernel_data_addr(((vm_offset_t *) elem)[0]) ||
			    ((vm_offset_t *) elem)[0] !=
			    ((vm_offset_t *) elem)[(zone->elem_size/sizeof(vm_offset_t))-1]) {
				panic("a freed zone element has been modified in zone: %s",
				      zone->zone_name);
			}
			
			/* check for poisoning in free space */
			for (i++;
			     i < zone->elem_size / sizeof(uint32_t) -
			         sizeof(vm_offset_t) / sizeof(uint32_t);
			     i++) {
				if (((uint32_t *) elem)[i] != ZP_POISON) {
					panic("a freed zone element has been modified in zone: %s",
					      zone->zone_name);
				}
			}
		} else if (((uint32_t *) elem)[i] != ZP_NOT_POISONED) {
			panic("a freed zone element has been modified in zone: %s",
			      zone->zone_name);
		}
		
		zone->count++;
		zone->sum_count++;
		zone->free_elements = ((vm_offset_t *) elem)[0];
	}
	*ret = elem;
}


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
	{
		.name = "kernel_stacks",
		.init = stack_fake_zone_init,
		.query = stack_fake_zone_info,
	},
	{
		.name = "page_tables",
		.init = pt_fake_zone_init,
		.query = pt_fake_zone_info,
	},
	{
		.name = "kalloc.large",
		.init = kalloc_fake_zone_init,
		.query = kalloc_fake_zone_info,
	},
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

void		zalloc_async(
				thread_call_param_t	p0,  
				thread_call_param_t	p1);

void		zone_display_zprint( void );

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

#define zone_wakeup(zone) thread_wakeup((event_t)(zone))
#define zone_sleep(zone)				\
	(void) lck_mtx_sleep(&(zone)->lock, LCK_SLEEP_SPIN, (event_t)(zone), THREAD_UNINT);


#define lock_zone_init(zone)				\
MACRO_BEGIN						\
	char _name[32];					\
	(void) snprintf(_name, sizeof (_name), "zone.%s", (zone)->zone_name); \
	lck_grp_attr_setdefault(&(zone)->lock_grp_attr);		\
	lck_grp_init(&(zone)->lock_grp, _name, &(zone)->lock_grp_attr);	\
	lck_attr_setdefault(&(zone)->lock_attr);			\
	lck_mtx_init_ext(&(zone)->lock, &(zone)->lock_ext,		\
	    &(zone)->lock_grp, &(zone)->lock_attr);			\
MACRO_END

#define lock_try_zone(zone)	lck_mtx_try_lock_spin(&zone->lock)

/*
 *	Garbage collection map information
 */
#define ZONE_PAGE_TABLE_FIRST_LEVEL_SIZE (32)
struct zone_page_table_entry * volatile zone_page_table[ZONE_PAGE_TABLE_FIRST_LEVEL_SIZE];
vm_size_t			zone_page_table_used_size;
vm_offset_t			zone_map_min_address;
vm_offset_t			zone_map_max_address;
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
decl_lck_mtx_data(,		zone_gc_lock)

lck_attr_t      zone_lck_attr;
lck_grp_t       zone_lck_grp;
lck_grp_attr_t  zone_lck_grp_attr;
lck_mtx_ext_t   zone_lck_ext;

#if	!ZONE_ALIAS_ADDR
#define from_zone_map(addr, size) \
	((vm_offset_t)(addr) >= zone_map_min_address && \
	 ((vm_offset_t)(addr) + size -1) <  zone_map_max_address)
#else
#define from_zone_map(addr, size) \
	((vm_offset_t)(zone_virtual_addr((vm_map_address_t)(uintptr_t)addr)) >= zone_map_min_address && \
	 ((vm_offset_t)(zone_virtual_addr((vm_map_address_t)(uintptr_t)addr)) + size -1) <  zone_map_max_address)
#endif

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
 * Each record in the log contains a pointer to the zone element it refers to, a "time" number that allows
 * the records to be ordered chronologically, and a small array to hold the pc's from the stack trace.  A
 * record is added to the log each time a zalloc() is done in the zone_of_interest.  For leak debugging,
 * the record is cleared when a zfree() is done.  For corruption debugging, the log tracks both allocs and frees.
 * If the log fills, old records are replaced as if it were a circular buffer.
 */

struct zrecord {
        void		*z_element;		/* the element that was zalloc'ed of zfree'ed */
        uint32_t	z_opcode:1,		/* whether it was a zalloc or zfree */
			z_time:31;		/* time index when operation was done */
        void		*z_pc[MAX_ZTRACE_DEPTH];	/* stack trace of caller */
};

/*
 * Opcodes for the z_opcode field:
 */

#define ZOP_ALLOC	1
#define ZOP_FREE	0

/*
 * The allocation log and all the related variables are protected by the zone lock for the zone_of_interest
 */

static struct zrecord *zrecords;		/* the log itself, dynamically allocated when logging is enabled  */
static int zcurrent  = 0;			/* index of the next slot in the log to use */
static int zrecorded = 0;			/* number of allocations recorded in the log */
static unsigned int ztime = 0;			/* a timestamp of sorts */
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

#define DO_LOGGING(z)		(zrecords && (z) == zone_of_interest)

extern boolean_t zlog_ready;

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
		printf("Zone leak factor override:%u\n", zleak_sample_factor);
	}

	/* zleak-allocs=XXXX (override number of buckets in zallocations) */
	if (PE_parse_boot_argn("zleak-allocs", &zleak_alloc_buckets, sizeof(zleak_alloc_buckets))) {
		printf("Zone leak alloc buckets override:%u\n", zleak_alloc_buckets);
		/* uses 'is power of 2' trick: (0x01000 & 0x00FFF == 0) */
		if (zleak_alloc_buckets == 0 || (zleak_alloc_buckets & (zleak_alloc_buckets-1))) {
			printf("Override isn't a power of two, bad things might happen!");
		}
	}
	
	/* zleak-traces=XXXX (override number of buckets in ztraces) */
	if (PE_parse_boot_argn("zleak-traces", &zleak_trace_buckets, sizeof(zleak_trace_buckets))) {
		printf("Zone leak trace buckets override:%u\n", zleak_trace_buckets);
		/* uses 'is power of 2' trick: (0x01000 & 0x00FFF == 0) */
		if (zleak_trace_buckets == 0 || (zleak_trace_buckets & (zleak_trace_buckets-1))) {
			printf("Override isn't a power of two, bad things might happen!");
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
	retval = kmem_alloc_kobject(kernel_map, (vm_offset_t*)&allocations_ptr, z_alloc_size);
	if (retval != KERN_SUCCESS) {
		goto fail;
	}

	retval = kmem_alloc_kobject(kernel_map, (vm_offset_t*)&traces_ptr, z_trace_size);
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

	if (zone_zone == ZONE_NULL) {

		z = (struct zone *)zdata;
		zdata += sizeof(*z);
		zdata_size -= sizeof(*z);
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
	 * we look for an allocation size with less than 1% waste
	 * up to 5 pages in size...
	 * otherwise, we look for an allocation size with least fragmentation
	 * in the range of 1 - 5 pages
	 * This size will be used unless
	 * the user suggestion is larger AND has less fragmentation
	 */
#if	ZONE_ALIAS_ADDR
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

	z->free_elements = 0;
	z->cur_size = 0;
	z->max_size = max;
	z->elem_size = size;
	z->alloc_size = alloc;
	z->zone_name = name;
	z->count = 0;
	z->sum_count = 0LL;
	z->doing_alloc = FALSE;
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
	z->prio_refill_watermark = 0;
	z->zone_replenish_thread = NULL;
#if CONFIG_ZLEAKS
	z->num_allocs = 0;
	z->num_frees = 0;
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
	thread_call_setup(&z->call_async_alloc, zalloc_async, z);
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
	 * zinit'ed before we can do a kmem_alloc, so we have to defer allocation in that case.  zlog_ready is set to
	 * TRUE once enough of the VM system is up and running to allow a kmem_alloc to work.  If we want to log one
	 * of the VM related zones that's set up early on, we will skip allocation of the log until zinit is called again
	 * later on some other zone.  So note we may be allocating a buffer to log a zone other than the one being initialized
	 * right now.
	 */
	if (zone_of_interest != NULL && zrecords == NULL && zlog_ready) {
		if (kmem_alloc(kernel_map, (vm_offset_t *)&zrecords, log_records * sizeof(struct zrecord)) == KERN_SUCCESS) {

			/*
			 * We got the memory for the log.  Zero it out since the code needs this to identify unused records.
			 * At this point, everything is set up and we're ready to start logging this zone.
			 */
	
			bzero((void *)zrecords, log_records * sizeof(struct zrecord));
			printf("zone: logging started for zone %s (%p)\n", zone_of_interest->zone_name, zone_of_interest);

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
unsigned	zone_replenish_loops, zone_replenish_wakeups, zone_replenish_wakeups_initiated;

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
			assert(z->doing_alloc == FALSE);
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
				
			kr = kernel_memory_allocate(zone_map, &space, alloc_size, 0, zflags);

			if (kr == KERN_SUCCESS) {
#if	ZONE_ALIAS_ADDR
				if (alloc_size == PAGE_SIZE)
					space = zone_alias_addr(space);
#endif
				zcram(z, space, alloc_size);
			} else if (kr == KERN_RESOURCE_SHORTAGE) {
				VM_PAGE_WAIT();
			} else if (kr == KERN_NO_SPACE) {
				kr = kernel_memory_allocate(kernel_map, &space, alloc_size, 0, zflags);
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
 *	Cram the given memory into the specified zone.
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

	if (from_zm)
		zone_page_init(newmem, size);

	lock_zone(zone);
	while (size >= elem_size) {
		free_to_zone(zone, (void *) newmem);
		if (from_zm)
			zone_page_alloc(newmem, elem_size);
		zone->count++;	/* compensate for free_to_zone */
		size -= elem_size;
		newmem += elem_size;
		zone->cur_size += elem_size;
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
	zdata = (vm_offset_t)pmap_steal_memory(round_page(zdata_size));
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
	kr = kmem_alloc_kobject(kernel_map, &memory, size);
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

	/* do we want corruption-style debugging with zlog? */
	if (PE_parse_boot_argn("-zc", temp_buf, sizeof(temp_buf))) {
		corruption_debug_flag = TRUE;
	}
	
	/* Set up zone poisoning */

	free_check_sample_factor = ZP_DEFAULT_SAMPLING_FACTOR;

	/* support for old zone poisoning boot-args */
	if (PE_parse_boot_argn("-zp", temp_buf, sizeof(temp_buf))) {
		free_check_sample_factor = 1;
	}
	if (PE_parse_boot_argn("-no-zp", temp_buf, sizeof(temp_buf))) {
		free_check_sample_factor = 0;
	}

	/* zp-factor=XXXX (override how often to poison freed zone elements) */
	if (PE_parse_boot_argn("zp-factor", &free_check_sample_factor, sizeof(free_check_sample_factor))) {
		printf("Zone poisoning factor override:%u\n", free_check_sample_factor);
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

	/* assertion: nobody else called zinit before us */
	assert(zone_zone == ZONE_NULL);
	zone_zone = zinit(sizeof(struct zone), 128 * sizeof(struct zone),
			  sizeof(struct zone), "zones");
	zone_change(zone_zone, Z_COLLECT, FALSE);
	zone_change(zone_zone, Z_CALLERACCT, FALSE);
	zone_change(zone_zone, Z_NOENCRYPT, TRUE);

	zcram(zone_zone, zdata, zdata_size);

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
		
void
zone_init(
	vm_size_t max_zonemap_size)
{
	kern_return_t	retval;
	vm_offset_t	zone_min;
	vm_offset_t	zone_max;

	retval = kmem_suballoc(kernel_map, &zone_min, max_zonemap_size,
			       FALSE, VM_FLAGS_ANYWHERE | VM_FLAGS_PERMANENT,
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
	
	lck_grp_attr_setdefault(&zone_lck_grp_attr);
	lck_grp_init(&zone_lck_grp, "zones", &zone_lck_grp_attr);
	lck_attr_setdefault(&zone_lck_attr);
	lck_mtx_init_ext(&zone_gc_lock, &zone_lck_ext, &zone_lck_grp, &zone_lck_attr);
	
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
							   second_level_size) != KERN_SUCCESS) {
			panic("zone_page_table_expand");
		}

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
void *
zalloc_canblock(
	register zone_t	zone,
	boolean_t canblock)
{
	vm_offset_t	addr = 0;
	kern_return_t	retval;
	uintptr_t	zbt[MAX_ZTRACE_DEPTH];	/* used in zone leak logging and zone leak detection */
	int 		numsaved = 0;
	int		i;
	boolean_t	zone_replenish_wakeup = FALSE;
	boolean_t	did_gzalloc;

	did_gzalloc = FALSE;
#if CONFIG_ZLEAKS
	uint32_t	zleak_tracedepth = 0;  /* log this allocation if nonzero */
#endif /* CONFIG_ZLEAKS */

	assert(zone != ZONE_NULL);

#if	CONFIG_GZALLOC
	addr = gzalloc_alloc(zone, canblock);
	did_gzalloc = (addr != 0);
#endif

	lock_zone(zone);

	/*
	 * If zone logging is turned on and this is the zone we're tracking, grab a backtrace.
	 */
	
	if (DO_LOGGING(zone))
	        numsaved = OSBacktrace((void*) zbt, MAX_ZTRACE_DEPTH);
	
#if CONFIG_ZLEAKS
	/* 
	 * Zone leak detection: capture a backtrace every zleak_sample_factor
	 * allocations in this zone. 
	 */
	if (zone->zleak_on && (zone->zleak_capture++ % zleak_sample_factor == 0)) {
		zone->zleak_capture = 1;
		
		/* Avoid backtracing twice if zone logging is on */
		if (numsaved == 0 )
			zleak_tracedepth = fastbacktrace(zbt, MAX_ZTRACE_DEPTH);
		else
			zleak_tracedepth = numsaved;
	}
#endif /* CONFIG_ZLEAKS */

	if (__probable(addr == 0))
		alloc_from_zone(zone, (void **) &addr);

	if (zone->async_prio_refill &&
	    ((zone->cur_size - (zone->count * zone->elem_size)) <
	    (zone->prio_refill_watermark * zone->elem_size))) {
		zone_replenish_wakeup = TRUE;
		zone_replenish_wakeups_initiated++;
	}

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
		} else if (zone->doing_gc) {
			/* zone_gc() is running. Since we need an element
			 * from the free list that is currently being
			 * collected, set the waiting bit and try to
			 * interrupt the GC process, and try again
			 * when we obtain the lock.
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
			zone->doing_alloc = TRUE;
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
				
				retval = kernel_memory_allocate(zone_map, &space, alloc_size, 0, zflags);
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
						/* TODO: Change this to something more descriptive, perhaps 
						 * 'zone_map exhausted' only if we get retval 3 (KERN_NO_SPACE).
						 */
						panic("zalloc: \"%s\" (%d elements) retry fail %d, kfree_nop_count: %d", zone->zone_name, zone->count, retval, (int)kfree_nop_count);
					}
				} else {
					break;
				}
			}
			lock_zone(zone);
			zone->doing_alloc = FALSE; 
			if (zone->waiting) {
				zone->waiting = FALSE;
				zone_wakeup(zone);
			}
			alloc_from_zone(zone, (void **) &addr);
			if (addr == 0 &&
				retval == KERN_RESOURCE_SHORTAGE) {
				unlock_zone(zone);
				
				VM_PAGE_WAIT();
				lock_zone(zone);
			}
		}
		if (addr == 0)
			alloc_from_zone(zone, (void **) &addr);
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
			
			
	/*
	 * See if we should be logging allocations in this zone.  Logging is rarely done except when a leak is
	 * suspected, so this code rarely executes.  We need to do this code while still holding the zone lock
	 * since it protects the various log related data structures.
	 */

	if (DO_LOGGING(zone) && addr) {

		/*
		 * Look for a place to record this new allocation.  We implement two different logging strategies
		 * depending on whether we're looking for the source of a zone leak or a zone corruption.  When looking
		 * for a leak, we want to log as many allocations as possible in order to clearly identify the leaker
		 * among all the records.  So we look for an unused slot in the log and fill that in before overwriting
		 * an old entry.  When looking for a corruption however, it's better to have a chronological log of all
		 * the allocations and frees done in the zone so that the history of operations for a specific zone 
		 * element can be inspected.  So in this case, we treat the log as a circular buffer and overwrite the
		 * oldest entry whenever a new one needs to be added.
		 *
		 * The corruption_debug_flag flag tells us what style of logging to do.  It's set if we're supposed to be
		 * doing corruption style logging (indicated via -zc in the boot-args).
		 */

		if (!corruption_debug_flag && zrecords[zcurrent].z_element && zrecorded < log_records) {

			/*
			 * If we get here, we're doing leak style logging and there's still some unused entries in
			 * the log (since zrecorded is smaller than the size of the log).  Look for an unused slot
			 * starting at zcurrent and wrap-around if we reach the end of the buffer.  If the buffer
			 * is already full, we just fall through and overwrite the element indexed by zcurrent.
		 	 */

			for (i = zcurrent; i < log_records; i++) {
			        if (zrecords[i].z_element == NULL) {
				        zcurrent = i;
				        goto empty_slot;
				}
			}

			for (i = 0; i < zcurrent; i++) {
			        if (zrecords[i].z_element == NULL) {
				        zcurrent = i;
				        goto empty_slot;
				}
			}
		 }
	
		/*
		 * Save a record of this allocation
		 */
	
empty_slot:
		  if (zrecords[zcurrent].z_element == NULL)
		        zrecorded++;
	
		  zrecords[zcurrent].z_element = (void *)addr;
		  zrecords[zcurrent].z_time = ztime++;
		  zrecords[zcurrent].z_opcode = ZOP_ALLOC;
			
		  for (i = 0; i < numsaved; i++)
		        zrecords[zcurrent].z_pc[i] = (void*) zbt[i];

		  for (; i < MAX_ZTRACE_DEPTH; i++)
			zrecords[zcurrent].z_pc[i] = 0;
	
		  zcurrent++;
	
		  if (zcurrent >= log_records)
		          zcurrent = 0;
	}

	if ((addr == 0) && !canblock && (zone->async_pending == FALSE) && (zone->no_callout == FALSE) && (zone->exhaustible == FALSE) && (!vm_pool_low())) {
		zone->async_pending = TRUE;
		unlock_zone(zone);
		thread_call_enter(&zone->call_async_alloc);
		lock_zone(zone);
		alloc_from_zone(zone, (void **) &addr);
	}

#if	ZONE_DEBUG
	if (!did_gzalloc && addr && zone_debug_enabled(zone)) {
		enqueue_tail(&zone->active_zones, (queue_entry_t)addr);
		addr += ZONE_DEBUG_OFFSET;
	}
#endif
	
#if CONFIG_ZLEAKS
	if (addr != 0) {
		zone->num_allocs++;
	}
#endif /* CONFIG_ZLEAKS */

	unlock_zone(zone);

	if (zone_replenish_wakeup)
		thread_wakeup(&zone->zone_replenish_thread);

	TRACE_MACHLEAKS(ZALLOC_CODE, ZALLOC_CODE_2, zone->elem_size, addr);

	if (addr) {
		thread_t thr = current_thread();
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
zalloc(
       register zone_t zone)
{
  return( zalloc_canblock(zone, TRUE) );
}

void *
zalloc_noblock(
	       register zone_t zone)
{
  return( zalloc_canblock(zone, FALSE) );
}

void
zalloc_async(
	thread_call_param_t          p0,
	__unused thread_call_param_t p1)
{
	void *elt;

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
	
#if CONFIG_ZLEAKS
	uintptr_t	zbt[MAX_ZTRACE_DEPTH];		/* used for zone leak detection */
	uint32_t	zleak_tracedepth = 0;  /* log this allocation if nonzero */
#endif /* CONFIG_ZLEAKS */

	assert( zone != ZONE_NULL );

	if (!lock_try_zone(zone))
		return NULL;
	
#if CONFIG_ZLEAKS
	/*
	 * Zone leak detection: capture a backtrace
	 */
	if (zone->zleak_on && (zone->zleak_capture++ % zleak_sample_factor == 0)) {
		zone->zleak_capture = 1;
		zleak_tracedepth = fastbacktrace(zbt, MAX_ZTRACE_DEPTH);
	}
#endif /* CONFIG_ZLEAKS */

	alloc_from_zone(zone, (void **) &addr);
#if	ZONE_DEBUG
	if (addr && zone_debug_enabled(zone)) {
		enqueue_tail(&zone->active_zones, (queue_entry_t)addr);
		addr += ZONE_DEBUG_OFFSET;
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
	
	if (addr != 0) {
		zone->num_allocs++;
	}
#endif /* CONFIG_ZLEAKS */
	
	unlock_zone(zone);

	return((void *) addr);
}

/* Keep this FALSE by default.  Large memory machine run orders of magnitude
   slower in debug mode when true.  Use debugger to enable if needed */
/* static */ boolean_t zone_check = FALSE;

static zone_t zone_last_bogus_zone = ZONE_NULL;
static vm_offset_t zone_last_bogus_elem = 0;

void
zfree(
	register zone_t	zone,
	void 		*addr)
{
	vm_offset_t	elem = (vm_offset_t) addr;
	void		*zbt[MAX_ZTRACE_DEPTH]; /* only used if zone logging is enabled via boot-args */
	int		numsaved = 0;
	boolean_t	gzfreed = FALSE;

	assert(zone != ZONE_NULL);

	/*
	 * If zone logging is turned on and this is the zone we're tracking, grab a backtrace.
	 */

	if (DO_LOGGING(zone))
		numsaved = OSBacktrace(&zbt[0], MAX_ZTRACE_DEPTH);

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

	lock_zone(zone);

	/*
	 * See if we're doing logging on this zone.  There are two styles of logging used depending on
	 * whether we're trying to catch a leak or corruption.  See comments above in zalloc for details.
	 */

	if (DO_LOGGING(zone)) {
	        int  i;

		if (corruption_debug_flag) {

			/*
			 * We're logging to catch a corruption.  Add a record of this zfree operation
			 * to log.
			 */

			if (zrecords[zcurrent].z_element == NULL)
				zrecorded++;

			zrecords[zcurrent].z_element = (void *)addr;
			zrecords[zcurrent].z_time = ztime++;
			zrecords[zcurrent].z_opcode = ZOP_FREE;

			for (i = 0; i < numsaved; i++)
				zrecords[zcurrent].z_pc[i] = zbt[i];

			for (; i < MAX_ZTRACE_DEPTH; i++)
				zrecords[zcurrent].z_pc[i] = 0;

			zcurrent++;

			if (zcurrent >= log_records)
				zcurrent = 0;

		} else {

			/*
			 * We're logging to catch a leak. Remove any record we might have for this
			 * element since it's being freed.  Note that we may not find it if the buffer
			 * overflowed and that's OK.  Since the log is of a limited size, old records
			 * get overwritten if there are more zallocs than zfrees.
			 */
	
		        for (i = 0; i < log_records; i++) {
			        if (zrecords[i].z_element == addr) {
				        zrecords[i].z_element = NULL;
					zcurrent = i;
					zrecorded--;
					break;
				}
			}
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
		vm_offset_t this;

		/* check the zone's consistency */

		for (this = zone->free_elements;
		     this != 0;
		     this = * (vm_offset_t *) this)
			if (!pmap_kernel_va(this) || this == elem)
				panic("zfree");
	}

	if (__probable(!gzfreed))
		free_to_zone(zone, (void *) elem);

#if MACH_ASSERT
	if (zone->count < 0)
		panic("zfree: count < 0!");
#endif
	

#if CONFIG_ZLEAKS
	zone->num_frees++;

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
	free_count = (integer_t)(zone->cur_size/zone->elem_size - zone->count);
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


/* This is used for walking through a zone's free element list.
 */
struct zone_free_element {
	struct zone_free_element * next;
};

/*
 * Add a linked list of pages starting at base back into the zone
 * free list. Tail points to the last element on the list.
 */
#define ADD_LIST_TO_ZONE(zone, base, tail)				\
MACRO_BEGIN								\
	(tail)->next = (void *)((zone)->free_elements);			\
	if ((zone)->elem_size >= (2 * sizeof(vm_offset_t) + sizeof(uint32_t))) {	\
		((vm_offset_t *)(tail))[((zone)->elem_size/sizeof(vm_offset_t))-1] =	\
			(zone)->free_elements;				\
	}								\
	(zone)->free_elements = (unsigned long)(base);			\
MACRO_END

/*
 * Add an element to the chain pointed to by prev.
 */
#define ADD_ELEMENT(zone, prev, elem)					\
MACRO_BEGIN								\
	(prev)->next = (elem);						\
	if ((zone)->elem_size >= (2 * sizeof(vm_offset_t) + sizeof(uint32_t))) {	\
		((vm_offset_t *)(prev))[((zone)->elem_size/sizeof(vm_offset_t))-1] =	\
			(vm_offset_t)(elem);	 			\
	}								\
MACRO_END

struct {
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
	zone_page_index_t zone_free_page_head;
	zone_page_index_t zone_free_page_tail;
	thread_t	mythread = current_thread();

	lck_mtx_lock(&zone_gc_lock);

	simple_lock(&all_zones_lock);
	max_zones = num_zones;
	z = first_zone;
	simple_unlock(&all_zones_lock);


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
		int				kmem_frees = 0;

		assert(z != ZONE_NULL);

		if (!z->collectable)
			continue;

		if (all_zones == FALSE && z->elem_size < PAGE_SIZE)
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
		     (((z->cur_size - z->count * elt_size) <= (2 * z->alloc_size)) ||
		      ((z->cur_size - z->count * elt_size) <= (z->cur_size / 10)))) {
			unlock_zone(z);		
			continue;
		}

		z->doing_gc = TRUE;

		/*
		 * Snatch all of the free elements away from the zone.
		 */

		scan = (void *)z->free_elements;
		z->free_elements = 0;

		unlock_zone(z);

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
					ADD_ELEMENT(z, tail, elt);
					tail = elt;
				}

				ADD_ELEMENT(z, prev, elt->next);
				elt = elt->next;
				ADD_ELEMENT(z, tail, NULL);
			}

			/*
			 * Dribble back the elements we are keeping.
			 */

			if (++n >= 50) {
				if (z->waiting == TRUE) {
					/* z->waiting checked without lock held, rechecked below after locking */
					lock_zone(z);

					if (keep != NULL) {
						ADD_LIST_TO_ZONE(z, keep, tail);
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
							ADD_LIST_TO_ZONE(z, base_elt, prev);
							ADD_ELEMENT(z, base_prev, elt);
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

			ADD_LIST_TO_ZONE(z, keep, tail);

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
					ADD_ELEMENT(z, tail, elt);
					tail = elt;
				}

				elt = elt->next;
				ADD_ELEMENT(z, tail, NULL);

				++zgc_stats.elems_kept;
			}

			/*
			 * Dribble back the elements we are keeping,
			 * and update the zone size info.
			 */

			if (++n >= 50) {
				lock_zone(z);

				z->cur_size -= size_freed;
				size_freed = 0;

				if (keep != NULL) {
					ADD_LIST_TO_ZONE(z, keep, tail);
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

			if (keep != NULL) {
				ADD_LIST_TO_ZONE(z, keep, tail);
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
			}
			kmem_free(zone_map, free_page_address, page_count * PAGE_SIZE);

			zgc_stats.pgs_freed += page_count;

			if (++kmem_frees == 32) {
				thread_yield_internal(1);
				kmem_frees = 0;
			}
		}
		thread_set_eager_preempt(mythread);
	}
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
				 &names_addr, names_size);
	if (kr != KERN_SUCCESS)
		return kr;
	names = (mach_zone_name_t *) names_addr;

	info_size = round_page(max_zones * sizeof *info);
	kr = kmem_alloc_pageable(ipc_kernel_map,
				 &info_addr, info_size);
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
		zi->tzi_cur_size = (uint64_t)zcopy.cur_size;
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
			   (vm_map_size_t)names_size, TRUE, &copy);
	assert(kr == KERN_SUCCESS);

	*namesp = (mach_zone_name_t *) copy;
	*namesCntp = max_zones;

	used = max_zones * sizeof *info;

	if (used != info_size)
		bzero((char *) (info_addr + used), info_size - used);

	kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)info_addr,
			   (vm_map_size_t)info_size, TRUE, &copy);
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
	mach_zone_name_t	*names;
	vm_offset_t		names_addr;
	vm_size_t		names_size;
	mach_zone_info_t	*info;
	vm_offset_t		info_addr;
	vm_size_t		info_size;
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
				 &names_addr, names_size);
	if (kr != KERN_SUCCESS)
		return kr;
	names = (mach_zone_name_t *) names_addr;

	info_size = round_page(max_zones * sizeof *info);
	kr = kmem_alloc_pageable(ipc_kernel_map,
				 &info_addr, info_size);
	if (kr != KERN_SUCCESS) {
		kmem_free(ipc_kernel_map,
			  names_addr, names_size);
		return kr;
	}

	info = (mach_zone_info_t *) info_addr;

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
		zi->mzi_cur_size = (uint64_t)zcopy.cur_size;
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
			   (vm_map_size_t)names_size, TRUE, &copy);
	assert(kr == KERN_SUCCESS);

	*namesp = (mach_zone_name_t *) copy;
	*namesCntp = max_zones;

	used = max_zones * sizeof *info;

	if (used != info_size)
		bzero((char *) (info_addr + used), info_size - used);

	kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)info_addr,
			   (vm_map_size_t)info_size, TRUE, &copy);
	assert(kr == KERN_SUCCESS);

	*infop = (mach_zone_info_t *) copy;
	*infoCntp = max_zones;

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
				 &names_addr, names_size);
	if (kr != KERN_SUCCESS)
		return kr;
	names = (zone_name_t *) names_addr;

	info_size = round_page(max_zones * sizeof *info);
	kr = kmem_alloc_pageable(ipc_kernel_map,
				 &info_addr, info_size);
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
		zi->zi_cur_size = zcopy.cur_size;
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
			   (vm_map_size_t)names_size, TRUE, &copy);
	assert(kr == KERN_SUCCESS);

	*namesp = (zone_name_t *) copy;
	*namesCntp = max_zones;

	used = max_zones * sizeof *info;
	if (used != info_size)
		bzero((char *) (info_addr + used), info_size - used);

	kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)info_addr,
			   (vm_map_size_t)info_size, TRUE, &copy);
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

#if	ZONE_DEBUG

/* should we care about locks here ? */

#define zone_in_use(z) 	( z->count || z->free_elements )

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
