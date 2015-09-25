/*
 * Copyright (c) 2000-2013 Apple Inc. All rights reserved.
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

#include <vm/vm_compressor.h>

#if CONFIG_PHANTOM_CACHE
#include <vm/vm_phantom_cache.h>
#endif

#include <vm/vm_map.h>
#include <vm/vm_pageout.h>
#include <vm/memory_object.h>
#include <mach/mach_host.h>		/* for host_info() */
#include <kern/ledger.h>

#include <default_pager/default_pager_alerts.h>
#include <default_pager/default_pager_object_server.h>

#include <IOKit/IOHibernatePrivate.h>

/*
 * vm_compressor_mode has a heirarchy of control to set its value.
 * boot-args are checked first, then device-tree, and finally
 * the default value that is defined below. See vm_fault_init() for
 * the boot-arg & device-tree code.
 */

extern ipc_port_t min_pages_trigger_port;
extern lck_mtx_t paging_segments_lock;
#define PSL_LOCK()		lck_mtx_lock(&paging_segments_lock)
#define PSL_UNLOCK()	lck_mtx_unlock(&paging_segments_lock)


int		vm_compressor_mode = VM_PAGER_COMPRESSOR_WITH_SWAP;
int		vm_scale = 16;


int		vm_compressor_is_active = 0;
int		vm_compression_limit = 0;

extern boolean_t vm_swap_up;
extern void	vm_pageout_io_throttle(void);

#if CHECKSUM_THE_DATA || CHECKSUM_THE_SWAP || CHECKSUM_THE_COMPRESSED_DATA
extern unsigned int hash_string(char *cp, int len);
#endif


struct c_slot {
	uint64_t	c_offset:C_SEG_OFFSET_BITS,
		        c_size:12,
		        c_packed_ptr:36;
#if CHECKSUM_THE_DATA
	unsigned int	c_hash_data;
#endif
#if CHECKSUM_THE_COMPRESSED_DATA
	unsigned int	c_hash_compressed_data;
#endif

};

#define UNPACK_C_SIZE(cs)	((cs->c_size == (PAGE_SIZE-1)) ? PAGE_SIZE : cs->c_size)
#define PACK_C_SIZE(cs, size)	(cs->c_size = ((size == PAGE_SIZE) ? PAGE_SIZE - 1 : size))


struct  c_slot_mapping {
        uint32_t        s_cseg:22, 	/* segment number + 1 */
			s_cindx:10;	/* index in the segment */
};

typedef struct c_slot_mapping *c_slot_mapping_t;


union c_segu {
	c_segment_t	c_seg;
	uint32_t	c_segno;
};



#define C_SLOT_PACK_PTR(ptr)		(((uintptr_t)ptr - (uintptr_t) VM_MIN_KERNEL_AND_KEXT_ADDRESS) >> 2)
#define C_SLOT_UNPACK_PTR(cslot)	((uintptr_t)(cslot->c_packed_ptr << 2) + (uintptr_t) VM_MIN_KERNEL_AND_KEXT_ADDRESS)


uint32_t	c_segment_count = 0;

uint64_t	c_generation_id = 0;
uint64_t	c_generation_id_flush_barrier;


#define		HIBERNATE_FLUSHING_SECS_TO_COMPLETE	120

boolean_t	hibernate_no_swapspace = FALSE;
clock_sec_t	hibernate_flushing_deadline = 0;


#if TRACK_BAD_C_SEGMENTS
queue_head_t	c_bad_list_head;
uint32_t	c_bad_count = 0;
#endif

queue_head_t	c_age_list_head;
queue_head_t	c_swapout_list_head;
queue_head_t	c_swappedin_list_head;
queue_head_t	c_swappedout_list_head;
queue_head_t	c_swappedout_sparse_list_head;

uint32_t	c_age_count = 0;
uint32_t	c_swapout_count = 0;
uint32_t	c_swappedin_count = 0;
uint32_t	c_swappedout_count = 0;
uint32_t	c_swappedout_sparse_count = 0;

queue_head_t	c_minor_list_head;
uint32_t	c_minor_count = 0;

union  c_segu	*c_segments;
caddr_t		c_segments_next_page;
boolean_t	c_segments_busy;
uint32_t	c_segments_available;
uint32_t	c_segments_limit;
uint32_t	c_segments_nearing_limit;
uint32_t	c_segment_pages_compressed;
uint32_t	c_segment_pages_compressed_limit;
uint32_t	c_segment_pages_compressed_nearing_limit;
uint32_t	c_free_segno_head = (uint32_t)-1;

uint32_t	vm_compressor_minorcompact_threshold_divisor = 10;
uint32_t	vm_compressor_majorcompact_threshold_divisor = 10;
uint32_t	vm_compressor_unthrottle_threshold_divisor = 10;
uint32_t	vm_compressor_catchup_threshold_divisor = 10;

#define		C_SEGMENTS_PER_PAGE	(PAGE_SIZE / sizeof(union c_segu))


lck_grp_attr_t	vm_compressor_lck_grp_attr;
lck_attr_t	vm_compressor_lck_attr;
lck_grp_t	vm_compressor_lck_grp;


#if __i386__ || __x86_64__
lck_mtx_t	*c_list_lock;
#else /* __i386__ || __x86_64__ */
lck_spin_t	*c_list_lock;
#endif /* __i386__ || __x86_64__ */

lck_rw_t	c_master_lock;
boolean_t	decompressions_blocked = FALSE;

zone_t		compressor_segment_zone;
int		c_compressor_swap_trigger = 0;

uint32_t	compressor_cpus;
char		*compressor_scratch_bufs;


clock_sec_t	start_of_sample_period_sec = 0;
clock_nsec_t	start_of_sample_period_nsec = 0;
clock_sec_t	start_of_eval_period_sec = 0;
clock_nsec_t	start_of_eval_period_nsec = 0;
uint32_t	sample_period_decompression_count = 0;
uint32_t	sample_period_compression_count = 0;
uint32_t	last_eval_decompression_count = 0;
uint32_t	last_eval_compression_count = 0;

#define		DECOMPRESSION_SAMPLE_MAX_AGE		(60 * 30)

uint32_t	swapout_target_age = 0;
uint32_t	age_of_decompressions_during_sample_period[DECOMPRESSION_SAMPLE_MAX_AGE];
uint32_t	overage_decompressions_during_sample_period = 0;

void		do_fastwake_warmup(void);
boolean_t	fastwake_warmup = FALSE;
boolean_t	fastwake_recording_in_progress = FALSE;
clock_sec_t	dont_trim_until_ts = 0;

uint64_t	c_segment_warmup_count;
uint64_t	first_c_segment_to_warm_generation_id = 0;
uint64_t	last_c_segment_to_warm_generation_id = 0;
boolean_t	hibernate_flushing = FALSE;

int64_t		c_segment_input_bytes __attribute__((aligned(8))) = 0;
int64_t		c_segment_compressed_bytes __attribute__((aligned(8))) = 0;
int64_t		compressor_bytes_used __attribute__((aligned(8))) = 0;
uint64_t	compressor_kvspace_used __attribute__((aligned(8))) = 0;
uint64_t	compressor_kvwaste_limit = 0;

static boolean_t compressor_needs_to_swap(void);
static void vm_compressor_swap_trigger_thread(void);
static void vm_compressor_do_delayed_compactions(boolean_t);
static void vm_compressor_compact_and_swap(boolean_t);
static void vm_compressor_age_swapped_in_segments(boolean_t);

boolean_t vm_compressor_low_on_space(void);

void compute_swapout_target_age(void);

boolean_t c_seg_major_compact(c_segment_t, c_segment_t);
boolean_t c_seg_major_compact_ok(c_segment_t, c_segment_t);

int  c_seg_minor_compaction_and_unlock(c_segment_t, boolean_t);
int  c_seg_do_minor_compaction_and_unlock(c_segment_t, boolean_t, boolean_t, boolean_t);
void c_seg_try_minor_compaction_and_unlock(c_segment_t c_seg);
void c_seg_need_delayed_compaction(c_segment_t);

void c_seg_move_to_sparse_list(c_segment_t);
void c_seg_insert_into_q(queue_head_t *, c_segment_t);

boolean_t c_seg_try_free(c_segment_t);
void	  c_seg_free(c_segment_t);
void	  c_seg_free_locked(c_segment_t);


uint64_t vm_available_memory(void);
uint64_t vm_compressor_pages_compressed(void);

extern unsigned int dp_pages_free, dp_pages_reserve;

uint64_t
vm_available_memory(void)
{
	return (((uint64_t)AVAILABLE_NON_COMPRESSED_MEMORY) * PAGE_SIZE_64);
}


uint64_t
vm_compressor_pages_compressed(void)
{
	return (c_segment_pages_compressed * PAGE_SIZE_64);
}


boolean_t
vm_compression_available(void)
{
	if ( !(COMPRESSED_PAGER_IS_ACTIVE || DEFAULT_FREEZER_COMPRESSED_PAGER_IS_ACTIVE))
		return (FALSE);

	if (c_segments_available >= c_segments_limit || c_segment_pages_compressed >= c_segment_pages_compressed_limit)
		return (FALSE);

	return (TRUE);
}


boolean_t
vm_compressor_low_on_space(void)
{
	if ((c_segment_pages_compressed > c_segment_pages_compressed_nearing_limit) ||
	    (c_segment_count > c_segments_nearing_limit))
		return (TRUE);

	return (FALSE);
}
	    

int
vm_wants_task_throttled(task_t task)
{
	if (task == kernel_task)
		return (0);

	if (vm_compressor_mode == COMPRESSED_PAGER_IS_ACTIVE || vm_compressor_mode == DEFAULT_FREEZER_COMPRESSED_PAGER_IS_ACTIVE) {
		if ((vm_compressor_low_on_space() || HARD_THROTTLE_LIMIT_REACHED()) &&
		    (unsigned int)pmap_compressed(task->map->pmap) > (c_segment_pages_compressed / 4))
			return (1);
	} else {
		if (((dp_pages_free + dp_pages_reserve < 2000) && VM_DYNAMIC_PAGING_ENABLED(memory_manager_default)) &&
		    get_task_resident_size(task) > (((AVAILABLE_NON_COMPRESSED_MEMORY) * PAGE_SIZE) / 5))
			return (1);
	}
	return (0);
}


void
vm_compressor_init_locks(void)
{
	lck_grp_attr_setdefault(&vm_compressor_lck_grp_attr);
	lck_grp_init(&vm_compressor_lck_grp, "vm_compressor", &vm_compressor_lck_grp_attr);
	lck_attr_setdefault(&vm_compressor_lck_attr);

	lck_rw_init(&c_master_lock, &vm_compressor_lck_grp, &vm_compressor_lck_attr);
}


void
vm_decompressor_lock(void)
{
	PAGE_REPLACEMENT_ALLOWED(TRUE);

	decompressions_blocked = TRUE;
	
	PAGE_REPLACEMENT_ALLOWED(FALSE);
}

void
vm_decompressor_unlock(void)
{
	PAGE_REPLACEMENT_ALLOWED(TRUE);

	decompressions_blocked = FALSE;

	PAGE_REPLACEMENT_ALLOWED(FALSE);

	thread_wakeup((event_t)&decompressions_blocked);
}



void
vm_compressor_init(void)
{
	thread_t	thread;
	struct c_slot	cs_dummy;
	c_slot_t cs  = &cs_dummy;

	/*
	 * ensure that any pointer that gets created from
	 * the vm_page zone can be packed properly
	 */
	cs->c_packed_ptr = C_SLOT_PACK_PTR(zone_map_min_address);

	if (C_SLOT_UNPACK_PTR(cs) != (uintptr_t)zone_map_min_address)
		panic("C_SLOT_UNPACK_PTR failed on zone_map_min_address - %p", (void *)zone_map_min_address);

	cs->c_packed_ptr = C_SLOT_PACK_PTR(zone_map_max_address);

	if (C_SLOT_UNPACK_PTR(cs) != (uintptr_t)zone_map_max_address)
		panic("C_SLOT_UNPACK_PTR failed on zone_map_max_address - %p", (void *)zone_map_max_address);


	assert((C_SEGMENTS_PER_PAGE * sizeof(union c_segu)) == PAGE_SIZE);

	PE_parse_boot_argn("vm_compression_limit", &vm_compression_limit, sizeof (vm_compression_limit));

	if (max_mem <= (3ULL * 1024ULL * 1024ULL * 1024ULL)) {
		vm_compressor_minorcompact_threshold_divisor = 11;
		vm_compressor_majorcompact_threshold_divisor = 13;
		vm_compressor_unthrottle_threshold_divisor = 20;
		vm_compressor_catchup_threshold_divisor = 35;
	} else {
		vm_compressor_minorcompact_threshold_divisor = 20;
		vm_compressor_majorcompact_threshold_divisor = 25;
		vm_compressor_unthrottle_threshold_divisor = 35;
		vm_compressor_catchup_threshold_divisor = 50;
	}
	/*
	 * vm_page_init_lck_grp is now responsible for calling vm_compressor_init_locks
	 * c_master_lock needs to be available early so that "vm_page_find_contiguous" can
	 * use PAGE_REPLACEMENT_ALLOWED to coordinate with the compressor.
	 */

#if __i386__ || __x86_64__
	c_list_lock = lck_mtx_alloc_init(&vm_compressor_lck_grp, &vm_compressor_lck_attr);
#else /* __i386__ || __x86_64__ */
	c_list_lock = lck_spin_alloc_init(&vm_compressor_lck_grp, &vm_compressor_lck_attr);
#endif /* __i386__ || __x86_64__ */

#if TRACK_BAD_C_SEGMENTS
	queue_init(&c_bad_list_head);
#endif
	queue_init(&c_age_list_head);
	queue_init(&c_minor_list_head);
	queue_init(&c_swapout_list_head);
	queue_init(&c_swappedin_list_head);
	queue_init(&c_swappedout_list_head);
	queue_init(&c_swappedout_sparse_list_head);

	compressor_segment_zone = zinit(sizeof (struct c_segment),
				      128000 * sizeof (struct c_segment),
				      8192, "compressor_segment");
	zone_change(compressor_segment_zone, Z_CALLERACCT, FALSE);
	zone_change(compressor_segment_zone, Z_NOENCRYPT, TRUE);

	
	c_free_segno_head = -1;
	c_segments_available = 0;

	if (vm_compression_limit == 0) {
		c_segment_pages_compressed_limit = (uint32_t)((max_mem / PAGE_SIZE)) * vm_scale;

#define	OLD_SWAP_LIMIT	(1024 * 1024 * 16)
#define MAX_SWAP_LIMIT	(1024 * 1024 * 128)
	
		if (c_segment_pages_compressed_limit > (OLD_SWAP_LIMIT))
			c_segment_pages_compressed_limit = OLD_SWAP_LIMIT;

		if (c_segment_pages_compressed_limit < (uint32_t)(max_mem / PAGE_SIZE_64))
		        c_segment_pages_compressed_limit = (uint32_t)(max_mem / PAGE_SIZE_64);
	} else {
		if (vm_compression_limit < MAX_SWAP_LIMIT)
			c_segment_pages_compressed_limit = vm_compression_limit;
		else
			c_segment_pages_compressed_limit = MAX_SWAP_LIMIT;
	}
	if ((c_segments_limit = c_segment_pages_compressed_limit / (C_SEG_BUFSIZE / PAGE_SIZE)) > C_SEG_MAX_LIMIT)
		c_segments_limit = C_SEG_MAX_LIMIT;

	c_segment_pages_compressed_nearing_limit = (c_segment_pages_compressed_limit * 98) / 100;
	c_segments_nearing_limit = (c_segments_limit * 98) / 100;

	compressor_kvwaste_limit = (vm_map_max(kernel_map) - vm_map_min(kernel_map)) / 16;

	c_segments_busy = FALSE;

	if (kernel_memory_allocate(kernel_map, (vm_offset_t *)(&c_segments), (sizeof(union c_segu) * c_segments_limit), 0, KMA_KOBJECT | KMA_VAONLY) != KERN_SUCCESS)
		panic("vm_compressor_init: kernel_memory_allocate failed\n");

	c_segments_next_page = (caddr_t)c_segments;

	{
		host_basic_info_data_t hinfo;
		mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;

#define BSD_HOST 1
		host_info((host_t)BSD_HOST, HOST_BASIC_INFO, (host_info_t)&hinfo, &count);

		compressor_cpus = hinfo.max_cpus;

		compressor_scratch_bufs = kalloc(compressor_cpus * WKdm_SCRATCH_BUF_SIZE);
	}

	if (kernel_thread_start_priority((thread_continue_t)vm_compressor_swap_trigger_thread, NULL,
					 BASEPRI_PREEMPT - 1, &thread) != KERN_SUCCESS) {
		panic("vm_compressor_swap_trigger_thread: create failed");
	}
	thread->options |= TH_OPT_VMPRIV;

	thread_deallocate(thread);

	assert(default_pager_init_flag == 0);
		
	if (vm_pageout_internal_start() != KERN_SUCCESS) {
		panic("vm_compressor_init: Failed to start the internal pageout thread.\n");
	}

	if ((vm_compressor_mode == VM_PAGER_COMPRESSOR_WITH_SWAP) ||
	    (vm_compressor_mode == VM_PAGER_FREEZER_COMPRESSOR_WITH_SWAP)) {
		vm_compressor_swap_init();
	}

	if (COMPRESSED_PAGER_IS_ACTIVE || DEFAULT_FREEZER_COMPRESSED_PAGER_IS_SWAPBACKED)
		vm_compressor_is_active = 1;

#if CONFIG_FREEZE
	memorystatus_freeze_enabled = TRUE;
#endif /* CONFIG_FREEZE */

	default_pager_init_flag = 1;

	vm_page_reactivate_all_throttled();
}


#if VALIDATE_C_SEGMENTS

static void
c_seg_validate(c_segment_t c_seg, boolean_t must_be_compact)
{
	int		c_indx;
	int32_t		bytes_used;
	int32_t		bytes_unused;
	uint32_t	c_rounded_size;
	uint32_t	c_size;
	c_slot_t	cs;

	if (c_seg->c_firstemptyslot < c_seg->c_nextslot) {
		c_indx = c_seg->c_firstemptyslot;
		cs = C_SEG_SLOT_FROM_INDEX(c_seg, c_indx);

		if (cs == NULL)
			panic("c_seg_validate:  no slot backing c_firstemptyslot");
	
		if (cs->c_size)
			panic("c_seg_validate:  c_firstemptyslot has non-zero size (%d)\n", cs->c_size);
	}
	bytes_used = 0;
	bytes_unused = 0;

	for (c_indx = 0; c_indx < c_seg->c_nextslot; c_indx++) {
		
		cs = C_SEG_SLOT_FROM_INDEX(c_seg, c_indx);

		c_size = UNPACK_C_SIZE(cs);

		c_rounded_size = (c_size + C_SEG_OFFSET_ALIGNMENT_MASK) & ~C_SEG_OFFSET_ALIGNMENT_MASK;

		bytes_used += c_rounded_size;

#if CHECKSUM_THE_COMPRESSED_DATA
		if (c_size && cs->c_hash_compressed_data != hash_string((char *)&c_seg->c_store.c_buffer[cs->c_offset], c_size))
			panic("compressed data doesn't match original");
#endif
	}

	if (bytes_used != c_seg->c_bytes_used)
		panic("c_seg_validate: bytes_used mismatch - found %d, segment has %d\n", bytes_used, c_seg->c_bytes_used);

	if (c_seg->c_bytes_used > C_SEG_OFFSET_TO_BYTES((int32_t)c_seg->c_nextoffset))
		panic("c_seg_validate: c_bytes_used > c_nextoffset - c_nextoffset = %d,  c_bytes_used = %d\n",
		      (int32_t)C_SEG_OFFSET_TO_BYTES((int32_t)c_seg->c_nextoffset), c_seg->c_bytes_used);

	if (must_be_compact) {
		if (c_seg->c_bytes_used != C_SEG_OFFSET_TO_BYTES((int32_t)c_seg->c_nextoffset))
			panic("c_seg_validate: c_bytes_used doesn't match c_nextoffset - c_nextoffset = %d,  c_bytes_used = %d\n",
			      (int32_t)C_SEG_OFFSET_TO_BYTES((int32_t)c_seg->c_nextoffset), c_seg->c_bytes_used);
	}
}

#endif


void
c_seg_need_delayed_compaction(c_segment_t c_seg)
{
	boolean_t	clear_busy = FALSE;

	if ( !lck_mtx_try_lock_spin_always(c_list_lock)) {
		C_SEG_BUSY(c_seg);
		
		lck_mtx_unlock_always(&c_seg->c_lock);
		lck_mtx_lock_spin_always(c_list_lock);
		lck_mtx_lock_spin_always(&c_seg->c_lock);

		clear_busy = TRUE;
	}
	if (!c_seg->c_on_minorcompact_q && !c_seg->c_ondisk && !c_seg->c_on_swapout_q) {
		queue_enter(&c_minor_list_head, c_seg, c_segment_t, c_list);
		c_seg->c_on_minorcompact_q = 1;
		c_minor_count++;
	}
	lck_mtx_unlock_always(c_list_lock);
	
	if (clear_busy == TRUE)
		C_SEG_WAKEUP_DONE(c_seg);
}


unsigned int c_seg_moved_to_sparse_list = 0;

void
c_seg_move_to_sparse_list(c_segment_t c_seg)
{
	boolean_t	clear_busy = FALSE;

	if ( !lck_mtx_try_lock_spin_always(c_list_lock)) {
		C_SEG_BUSY(c_seg);

		lck_mtx_unlock_always(&c_seg->c_lock);
		lck_mtx_lock_spin_always(c_list_lock);
		lck_mtx_lock_spin_always(&c_seg->c_lock);
		
		clear_busy = TRUE;
	}
	assert(c_seg->c_ondisk);
	assert(c_seg->c_on_swappedout_q);
	assert(!c_seg->c_on_swappedout_sparse_q);

	queue_remove(&c_swappedout_list_head, c_seg, c_segment_t, c_age_list);
	c_seg->c_on_swappedout_q = 0;
	c_swappedout_count--;

	c_seg_insert_into_q(&c_swappedout_sparse_list_head, c_seg);
	c_seg->c_on_swappedout_sparse_q = 1;
	c_swappedout_sparse_count++;

	c_seg_moved_to_sparse_list++;

	lck_mtx_unlock_always(c_list_lock);

	if (clear_busy == TRUE)
		C_SEG_WAKEUP_DONE(c_seg);
}


void
c_seg_insert_into_q(queue_head_t *qhead, c_segment_t c_seg)
{
	c_segment_t c_seg_next;

	if (queue_empty(qhead)) {
		queue_enter(qhead, c_seg, c_segment_t, c_age_list);
	} else {
		c_seg_next = (c_segment_t)queue_first(qhead);

		while (TRUE) {

			if (c_seg->c_generation_id < c_seg_next->c_generation_id) {
				queue_insert_before(qhead, c_seg, c_seg_next, c_segment_t, c_age_list);
				break;
			}
			c_seg_next = (c_segment_t) queue_next(&c_seg_next->c_age_list);
		
			if (queue_end(qhead, (queue_entry_t) c_seg_next)) {
				queue_enter(qhead, c_seg, c_segment_t, c_age_list);
				break;
			}
		}
	}
}


int try_minor_compaction_failed = 0;
int try_minor_compaction_succeeded = 0;

void
c_seg_try_minor_compaction_and_unlock(c_segment_t c_seg)
{

	assert(c_seg->c_on_minorcompact_q);
	/*
	 * c_seg is currently on the delayed minor compaction
	 * queue and we have c_seg locked... if we can get the
	 * c_list_lock w/o blocking (if we blocked we could deadlock
	 * because the lock order is c_list_lock then c_seg's lock)
	 * we'll pull it from the delayed list and free it directly
	 */
	if ( !lck_mtx_try_lock_spin_always(c_list_lock)) {
		/*
		 * c_list_lock is held, we need to bail
		 */
		try_minor_compaction_failed++;

		lck_mtx_unlock_always(&c_seg->c_lock);
	} else {
		try_minor_compaction_succeeded++;

		C_SEG_BUSY(c_seg);
		c_seg_do_minor_compaction_and_unlock(c_seg, TRUE, FALSE, FALSE);
	}
}


int
c_seg_do_minor_compaction_and_unlock(c_segment_t c_seg, boolean_t clear_busy, boolean_t need_list_lock, boolean_t disallow_page_replacement)
{
	int	c_seg_freed;

	assert(c_seg->c_busy);

	if (!c_seg->c_on_minorcompact_q) {
		if (clear_busy == TRUE)
			C_SEG_WAKEUP_DONE(c_seg);

		lck_mtx_unlock_always(&c_seg->c_lock);

		return (0);
	}
	queue_remove(&c_minor_list_head, c_seg, c_segment_t, c_list);
	c_seg->c_on_minorcompact_q = 0;
	c_minor_count--;
	
	lck_mtx_unlock_always(c_list_lock);

	if (disallow_page_replacement == TRUE) {
		lck_mtx_unlock_always(&c_seg->c_lock);

		PAGE_REPLACEMENT_DISALLOWED(TRUE);

		lck_mtx_lock_spin_always(&c_seg->c_lock);
	}
	c_seg_freed = c_seg_minor_compaction_and_unlock(c_seg, clear_busy);

	if (disallow_page_replacement == TRUE)
		PAGE_REPLACEMENT_DISALLOWED(FALSE);

	if (need_list_lock == TRUE)
		lck_mtx_lock_spin_always(c_list_lock);

	return (c_seg_freed);
}


void
c_seg_wait_on_busy(c_segment_t c_seg)
{
	c_seg->c_wanted = 1;
	assert_wait((event_t) (c_seg), THREAD_UNINT);

	lck_mtx_unlock_always(&c_seg->c_lock);
	thread_block(THREAD_CONTINUE_NULL);
}



int	try_free_succeeded = 0;
int	try_free_failed = 0;

boolean_t
c_seg_try_free(c_segment_t c_seg)
{
	/*
	 * c_seg is currently on the delayed minor compaction
	 * or the spapped out sparse queue and we have c_seg locked...
	 * if we can get the c_list_lock w/o blocking (if we blocked we
	 * could deadlock because the lock order is c_list_lock then c_seg's lock)
	 * we'll pull it from the appropriate queue and free it
	 */
	if ( !lck_mtx_try_lock_spin_always(c_list_lock)) {
		/*
		 * c_list_lock is held, we need to bail
		 */
		try_free_failed++;
		return (FALSE);
	}
	if (c_seg->c_on_minorcompact_q) {
		queue_remove(&c_minor_list_head, c_seg, c_segment_t, c_list);
		c_seg->c_on_minorcompact_q = 0;
		c_minor_count--;
	} else {
		assert(c_seg->c_on_swappedout_sparse_q);

		/*
		 * c_seg_free_locked will remove it from the swappedout sparse list
		 */
	}
	if (!c_seg->c_busy_swapping)
		C_SEG_BUSY(c_seg);

	c_seg_free_locked(c_seg);

	try_free_succeeded++;

	return (TRUE);
}


void
c_seg_free(c_segment_t c_seg)
{
	assert(c_seg->c_busy);

	lck_mtx_unlock_always(&c_seg->c_lock);
	lck_mtx_lock_spin_always(c_list_lock);
	lck_mtx_lock_spin_always(&c_seg->c_lock);

	c_seg_free_locked(c_seg);
}


void
c_seg_free_locked(c_segment_t c_seg)
{
	int		segno, i;
	int		pages_populated = 0;
	int32_t		*c_buffer = NULL;
	uint64_t	c_swap_handle = 0;

	assert(!c_seg->c_on_minorcompact_q);

	if (c_seg->c_on_age_q) {
		queue_remove(&c_age_list_head, c_seg, c_segment_t, c_age_list);
		c_seg->c_on_age_q = 0;
		c_age_count--;
	} else if (c_seg->c_on_swappedin_q) {
		queue_remove(&c_swappedin_list_head, c_seg, c_segment_t, c_age_list);
		c_seg->c_on_swappedin_q = 0;
		c_swappedin_count--;
	} else if (c_seg->c_on_swapout_q) {
		queue_remove(&c_swapout_list_head, c_seg, c_segment_t, c_age_list);
		c_seg->c_on_swapout_q = 0;
		c_swapout_count--;
		thread_wakeup((event_t)&compaction_swapper_running);
	} else if (c_seg->c_on_swappedout_q) {
		queue_remove(&c_swappedout_list_head, c_seg, c_segment_t, c_age_list);
		c_seg->c_on_swappedout_q = 0;
		c_swappedout_count--;
	} else if (c_seg->c_on_swappedout_sparse_q) {
		queue_remove(&c_swappedout_sparse_list_head, c_seg, c_segment_t, c_age_list);
		c_seg->c_on_swappedout_sparse_q = 0;
		c_swappedout_sparse_count--;
	}
#if TRACK_BAD_C_SEGMENTS
	else if (c_seg->c_on_bad_q) {
		queue_remove(&c_bad_list_head, c_seg, c_segment_t, c_age_list);
		c_seg->c_on_bad_q = 0;
		c_bad_count--;
	}
#endif
	segno = c_seg->c_mysegno;
	c_segments[segno].c_segno = c_free_segno_head;
	c_free_segno_head = segno;
	c_segment_count--;

	lck_mtx_unlock_always(c_list_lock);

	if (c_seg->c_wanted) {
		thread_wakeup((event_t) (c_seg));
		c_seg->c_wanted = 0;
	}
	if (c_seg->c_busy_swapping) {
		c_seg->c_must_free = 1;

		lck_mtx_unlock_always(&c_seg->c_lock);
		return;
	}
	if (c_seg->c_ondisk == 0) {
		pages_populated = (round_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset))) / PAGE_SIZE;

		c_buffer = c_seg->c_store.c_buffer;
		c_seg->c_store.c_buffer = NULL;
	} else {
                /*
                 * Free swap space on disk.
		 */
		c_swap_handle = c_seg->c_store.c_swap_handle;
		c_seg->c_store.c_swap_handle = (uint64_t)-1;
	}
	lck_mtx_unlock_always(&c_seg->c_lock);

	if (c_buffer) {
		if (pages_populated)
			kernel_memory_depopulate(kernel_map, (vm_offset_t) c_buffer, pages_populated * PAGE_SIZE, KMA_COMPRESSOR);

		kmem_free(kernel_map, (vm_offset_t) c_buffer, C_SEG_ALLOCSIZE);
		OSAddAtomic64(-C_SEG_ALLOCSIZE, &compressor_kvspace_used);

	} else if (c_swap_handle)
		vm_swap_free(c_swap_handle);


#if __i386__ || __x86_64__
	lck_mtx_destroy(&c_seg->c_lock, &vm_compressor_lck_grp);
#else /* __i386__ || __x86_64__ */
	lck_spin_destroy(&c_seg->c_lock, &vm_compressor_lck_grp);
#endif /* __i386__ || __x86_64__ */

	for (i = 0; i < C_SEG_SLOT_ARRAYS; i++) {
		if (c_seg->c_slots[i] == 0)
			break;

		kfree((char *)c_seg->c_slots[i], sizeof(struct c_slot) * C_SEG_SLOT_ARRAY_SIZE);
	}
	zfree(compressor_segment_zone, c_seg);
}


int c_seg_trim_page_count = 0;

void
c_seg_trim_tail(c_segment_t c_seg)
{
	c_slot_t	cs;
	uint32_t	c_size;
	uint32_t	c_offset;
	uint32_t	c_rounded_size;
	uint16_t	current_nextslot;
	uint32_t	current_populated_offset;

	if (c_seg->c_bytes_used == 0)
		return;
	current_nextslot = c_seg->c_nextslot;
	current_populated_offset = c_seg->c_populated_offset;
		
	while (c_seg->c_nextslot) {

		cs = C_SEG_SLOT_FROM_INDEX(c_seg, (c_seg->c_nextslot - 1));

		c_size = UNPACK_C_SIZE(cs);

		if (c_size) {
			if (current_nextslot != c_seg->c_nextslot) {
				c_rounded_size = (c_size + C_SEG_OFFSET_ALIGNMENT_MASK) & ~C_SEG_OFFSET_ALIGNMENT_MASK;
				c_offset = cs->c_offset + C_SEG_BYTES_TO_OFFSET(c_rounded_size);

				c_seg->c_nextoffset = c_offset;
				c_seg->c_populated_offset = (c_offset + (C_SEG_BYTES_TO_OFFSET(PAGE_SIZE) - 1)) & ~(C_SEG_BYTES_TO_OFFSET(PAGE_SIZE) - 1);

				if (c_seg->c_firstemptyslot > c_seg->c_nextslot)
					c_seg->c_firstemptyslot = c_seg->c_nextslot;

				c_seg_trim_page_count += ((round_page_32(C_SEG_OFFSET_TO_BYTES(current_populated_offset)) -
							   round_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset))) / PAGE_SIZE);
			}
			break;
		}		
		c_seg->c_nextslot--;
	}
	assert(c_seg->c_nextslot);
}


int
c_seg_minor_compaction_and_unlock(c_segment_t c_seg, boolean_t clear_busy)
{
	c_slot_mapping_t slot_ptr;
	uint32_t	c_offset = 0;
	uint32_t	old_populated_offset;
	uint32_t	c_rounded_size;
	uint32_t	c_size;
	int		c_indx = 0;
	int		i;
	c_slot_t	c_dst;
	c_slot_t	c_src;
	boolean_t	need_unlock = TRUE;

	assert(c_seg->c_busy);

#if VALIDATE_C_SEGMENTS
	c_seg_validate(c_seg, FALSE);
#endif
	if (c_seg->c_bytes_used == 0) {
		c_seg_free(c_seg);
		return (1);
	}
	if (c_seg->c_firstemptyslot >= c_seg->c_nextslot || C_SEG_UNUSED_BYTES(c_seg) < PAGE_SIZE)
		goto done;
		
#if VALIDATE_C_SEGMENTS
	c_seg->c_was_minor_compacted++;
#endif
	c_indx = c_seg->c_firstemptyslot;
	c_dst = C_SEG_SLOT_FROM_INDEX(c_seg, c_indx);
	
	old_populated_offset = c_seg->c_populated_offset;
	c_offset = c_dst->c_offset;

	for (i = c_indx + 1; i < c_seg->c_nextslot && c_offset < c_seg->c_nextoffset; i++) {

		c_src = C_SEG_SLOT_FROM_INDEX(c_seg, i);

		c_size = UNPACK_C_SIZE(c_src);

		if (c_size == 0)
			continue;

		memcpy(&c_seg->c_store.c_buffer[c_offset], &c_seg->c_store.c_buffer[c_src->c_offset], c_size);

#if CHECKSUM_THE_DATA
		c_dst->c_hash_data = c_src->c_hash_data;
#endif
#if CHECKSUM_THE_COMPRESSED_DATA
		c_dst->c_hash_compressed_data = c_src->c_hash_compressed_data;
#endif
		c_dst->c_size = c_src->c_size;
		c_dst->c_packed_ptr = c_src->c_packed_ptr;
		c_dst->c_offset = c_offset;

		slot_ptr = (c_slot_mapping_t)C_SLOT_UNPACK_PTR(c_dst);
		slot_ptr->s_cindx = c_indx;

		c_rounded_size = (c_size + C_SEG_OFFSET_ALIGNMENT_MASK) & ~C_SEG_OFFSET_ALIGNMENT_MASK;

		c_offset += C_SEG_BYTES_TO_OFFSET(c_rounded_size);
		PACK_C_SIZE(c_src, 0);
		c_indx++;

		c_dst = C_SEG_SLOT_FROM_INDEX(c_seg, c_indx);
	}
	c_seg->c_firstemptyslot = c_indx;
	c_seg->c_nextslot = c_indx;
	c_seg->c_nextoffset = c_offset;
	c_seg->c_populated_offset = (c_offset + (C_SEG_BYTES_TO_OFFSET(PAGE_SIZE) - 1)) & ~(C_SEG_BYTES_TO_OFFSET(PAGE_SIZE) - 1);
	c_seg->c_bytes_unused = 0;

#if VALIDATE_C_SEGMENTS
	c_seg_validate(c_seg, TRUE);
#endif

	if (old_populated_offset > c_seg->c_populated_offset) {
		uint32_t	gc_size;
		int32_t		*gc_ptr;

		gc_size = C_SEG_OFFSET_TO_BYTES(old_populated_offset - c_seg->c_populated_offset);
		gc_ptr = &c_seg->c_store.c_buffer[c_seg->c_populated_offset];

		lck_mtx_unlock_always(&c_seg->c_lock);

		kernel_memory_depopulate(kernel_map, (vm_offset_t)gc_ptr, gc_size, KMA_COMPRESSOR);

		if (clear_busy == TRUE)
			lck_mtx_lock_spin_always(&c_seg->c_lock);
		else
			need_unlock = FALSE;
	}
done:
	if (need_unlock == TRUE) {
		if (clear_busy == TRUE)
			C_SEG_WAKEUP_DONE(c_seg);

		lck_mtx_unlock_always(&c_seg->c_lock);
	}
	return (0);
}



struct {
	uint64_t asked_permission;
	uint64_t compactions;
	uint64_t moved_slots;
	uint64_t moved_bytes;
	uint64_t wasted_space_in_swapouts;
	uint64_t count_of_swapouts;
} c_seg_major_compact_stats;


#define C_MAJOR_COMPACTION_SIZE_APPROPRIATE	((C_SEG_BUFSIZE * 90) / 100)


boolean_t
c_seg_major_compact_ok(
	c_segment_t c_seg_dst,
	c_segment_t c_seg_src)
{

	c_seg_major_compact_stats.asked_permission++;

	if (c_seg_src->c_filling) {
		/*
		 * we're at or near the head... don't compact
		 */
		return (FALSE);
	}
	if (c_seg_src->c_bytes_used >= C_MAJOR_COMPACTION_SIZE_APPROPRIATE &&
	    c_seg_dst->c_bytes_used >= C_MAJOR_COMPACTION_SIZE_APPROPRIATE)
		return (FALSE);

	if (c_seg_dst->c_nextoffset >= C_SEG_OFF_LIMIT || c_seg_dst->c_nextslot >= C_SLOT_MAX) {
		/*
		 * destination segment is full... can't compact
		 */
		return (FALSE);
	}

	return (TRUE);
}


boolean_t
c_seg_major_compact(
	c_segment_t c_seg_dst,
	c_segment_t c_seg_src)
{
	c_slot_mapping_t slot_ptr;
	uint32_t	c_rounded_size;
	uint32_t	c_size;
	uint16_t	dst_slot;
	int		i;
	c_slot_t	c_dst;
	c_slot_t	c_src;
	int		slotarray;
	boolean_t	keep_compacting = TRUE;
	
	/*
	 * segments are not locked but they are both marked c_busy
	 * which keeps c_decompress from working on them...
	 * we can safely allocate new pages, move compressed data
	 * from c_seg_src to c_seg_dst and update both c_segment's
	 * state w/o holding the master lock
	 */

#if VALIDATE_C_SEGMENTS
	c_seg_dst->c_was_major_compacted++;
	c_seg_src->c_was_major_donor++;
#endif
	c_seg_major_compact_stats.compactions++;

	dst_slot = c_seg_dst->c_nextslot;

	for (i = 0; i < c_seg_src->c_nextslot; i++) {

		c_src = C_SEG_SLOT_FROM_INDEX(c_seg_src, i);

		c_size = UNPACK_C_SIZE(c_src);

		if (c_size == 0) {
			/* BATCH: move what we have so far; */
			continue;
		}

		if (C_SEG_OFFSET_TO_BYTES(c_seg_dst->c_populated_offset - c_seg_dst->c_nextoffset) < (unsigned) c_size) {
			/* doesn't fit */
			if ((C_SEG_OFFSET_TO_BYTES(c_seg_dst->c_populated_offset) == C_SEG_BUFSIZE)) {
				/* can't fit */
				keep_compacting = FALSE;
				break;
			}
			kernel_memory_populate(kernel_map,
					       (vm_offset_t) &c_seg_dst->c_store.c_buffer[c_seg_dst->c_populated_offset],
					       PAGE_SIZE,
					       KMA_COMPRESSOR);

			c_seg_dst->c_populated_offset += C_SEG_BYTES_TO_OFFSET(PAGE_SIZE);
			assert(C_SEG_OFFSET_TO_BYTES(c_seg_dst->c_populated_offset) <= C_SEG_BUFSIZE);
		}

		slotarray = C_SEG_SLOTARRAY_FROM_INDEX(c_seg_dst, c_seg_dst->c_nextslot);

		if (c_seg_dst->c_slots[slotarray] == 0) {
			KERNEL_DEBUG(0xe0400008 | DBG_FUNC_START, 0, 0, 0, 0, 0);
			c_seg_dst->c_slots[slotarray] = (struct c_slot *)
				kalloc(sizeof(struct c_slot) *
				       C_SEG_SLOT_ARRAY_SIZE);
			KERNEL_DEBUG(0xe0400008 | DBG_FUNC_END, 0, 0, 0, 0, 0);
		}
		c_dst = C_SEG_SLOT_FROM_INDEX(c_seg_dst, c_seg_dst->c_nextslot);

		memcpy(&c_seg_dst->c_store.c_buffer[c_seg_dst->c_nextoffset], &c_seg_src->c_store.c_buffer[c_src->c_offset], c_size);

		c_rounded_size = (c_size + C_SEG_OFFSET_ALIGNMENT_MASK) & ~C_SEG_OFFSET_ALIGNMENT_MASK;

		c_seg_major_compact_stats.moved_slots++;
		c_seg_major_compact_stats.moved_bytes += c_size;

#if CHECKSUM_THE_DATA
		c_dst->c_hash_data = c_src->c_hash_data;
#endif
#if CHECKSUM_THE_COMPRESSED_DATA
		c_dst->c_hash_compressed_data = c_src->c_hash_compressed_data;
#endif
		c_dst->c_size = c_src->c_size;
		c_dst->c_packed_ptr = c_src->c_packed_ptr;
		c_dst->c_offset = c_seg_dst->c_nextoffset;

		if (c_seg_dst->c_firstemptyslot == c_seg_dst->c_nextslot)
			c_seg_dst->c_firstemptyslot++;
		c_seg_dst->c_nextslot++;
		c_seg_dst->c_bytes_used += c_rounded_size;
		c_seg_dst->c_nextoffset += C_SEG_BYTES_TO_OFFSET(c_rounded_size);

		PACK_C_SIZE(c_src, 0);

		c_seg_src->c_bytes_used -= c_rounded_size;
		c_seg_src->c_bytes_unused += c_rounded_size;
		c_seg_src->c_firstemptyslot = 0;

		if (c_seg_dst->c_nextoffset >= C_SEG_OFF_LIMIT || c_seg_dst->c_nextslot >= C_SLOT_MAX) {
			/* dest segment is now full */
			keep_compacting = FALSE;
			break;
		}
	}
	if (dst_slot < c_seg_dst->c_nextslot) {

		PAGE_REPLACEMENT_ALLOWED(TRUE);
		/*
		 * we've now locked out c_decompress from 
		 * converting the slot passed into it into
		 * a c_segment_t which allows us to use 
		 * the backptr to change which c_segment and
		 * index the slot points to
		 */
		while (dst_slot < c_seg_dst->c_nextslot) {

			c_dst = C_SEG_SLOT_FROM_INDEX(c_seg_dst, dst_slot);
			
			slot_ptr = (c_slot_mapping_t)C_SLOT_UNPACK_PTR(c_dst);
			/* <csegno=0,indx=0> would mean "empty slot", so use csegno+1 */
			slot_ptr->s_cseg = c_seg_dst->c_mysegno + 1;
			slot_ptr->s_cindx = dst_slot++;
		}
		PAGE_REPLACEMENT_ALLOWED(FALSE);
	}
	return (keep_compacting);
}


uint64_t
vm_compressor_compute_elapsed_msecs(clock_sec_t end_sec, clock_nsec_t end_nsec, clock_sec_t start_sec, clock_nsec_t start_nsec)
{
        uint64_t end_msecs;
        uint64_t start_msecs;
  
	end_msecs = (end_sec * 1000) + end_nsec / 1000000;
	start_msecs = (start_sec * 1000) + start_nsec / 1000000;

	return (end_msecs - start_msecs);
}



uint32_t compressor_eval_period_in_msecs = 250;
uint32_t compressor_sample_min_in_msecs = 500;
uint32_t compressor_sample_max_in_msecs = 10000;
uint32_t compressor_thrashing_threshold_per_10msecs = 50;
uint32_t compressor_thrashing_min_per_10msecs = 20;

/* When true, reset sample data next chance we get. */
static boolean_t	compressor_need_sample_reset = FALSE;

extern uint32_t vm_page_filecache_min;


void
compute_swapout_target_age(void)
{
        clock_sec_t	cur_ts_sec;
        clock_nsec_t	cur_ts_nsec;
	uint32_t	min_operations_needed_in_this_sample;
	uint64_t	elapsed_msecs_in_eval;
	uint64_t	elapsed_msecs_in_sample;
	boolean_t	need_eval_reset = FALSE;

	clock_get_system_nanotime(&cur_ts_sec, &cur_ts_nsec);

	elapsed_msecs_in_sample = vm_compressor_compute_elapsed_msecs(cur_ts_sec, cur_ts_nsec, start_of_sample_period_sec, start_of_sample_period_nsec);

	if (compressor_need_sample_reset ||
	    elapsed_msecs_in_sample >= compressor_sample_max_in_msecs) {
		compressor_need_sample_reset = TRUE;
		need_eval_reset = TRUE;
		goto done;
	}
	elapsed_msecs_in_eval = vm_compressor_compute_elapsed_msecs(cur_ts_sec, cur_ts_nsec, start_of_eval_period_sec, start_of_eval_period_nsec);
	
	if (elapsed_msecs_in_eval < compressor_eval_period_in_msecs)
		goto done;
	need_eval_reset = TRUE;

	KERNEL_DEBUG(0xe0400020 | DBG_FUNC_START, elapsed_msecs_in_eval, sample_period_compression_count, sample_period_decompression_count, 0, 0);

	min_operations_needed_in_this_sample = (compressor_thrashing_min_per_10msecs * (uint32_t)elapsed_msecs_in_eval) / 10;

	if ((sample_period_compression_count - last_eval_compression_count) < min_operations_needed_in_this_sample ||
	    (sample_period_decompression_count - last_eval_decompression_count) < min_operations_needed_in_this_sample) {
		
		KERNEL_DEBUG(0xe0400020 | DBG_FUNC_END, sample_period_compression_count - last_eval_compression_count,
			     sample_period_decompression_count - last_eval_decompression_count, 0, 1, 0);

		swapout_target_age = 0;

		compressor_need_sample_reset = TRUE;
		need_eval_reset = TRUE;
		goto done;
	}
	last_eval_compression_count = sample_period_compression_count;
	last_eval_decompression_count = sample_period_decompression_count;

	if (elapsed_msecs_in_sample < compressor_sample_min_in_msecs) {

		KERNEL_DEBUG(0xe0400020 | DBG_FUNC_END, swapout_target_age, 0, 0, 5, 0);
		goto done;
	}
	if (sample_period_decompression_count > ((compressor_thrashing_threshold_per_10msecs * elapsed_msecs_in_sample) / 10)) {

		uint64_t	running_total;
		uint64_t	working_target;
		uint64_t	aging_target;
		uint32_t	oldest_age_of_csegs_sampled = 0;
		uint64_t	working_set_approximation = 0;

		swapout_target_age = 0;

		working_target = (sample_period_decompression_count / 100) * 95;		/* 95 percent */
		aging_target = (sample_period_decompression_count / 100) * 1;			/* 1 percent */
		running_total = 0;

		for (oldest_age_of_csegs_sampled = 0; oldest_age_of_csegs_sampled < DECOMPRESSION_SAMPLE_MAX_AGE; oldest_age_of_csegs_sampled++) {

			running_total += age_of_decompressions_during_sample_period[oldest_age_of_csegs_sampled];

			working_set_approximation += oldest_age_of_csegs_sampled * age_of_decompressions_during_sample_period[oldest_age_of_csegs_sampled];

			if (running_total >= working_target)
				break;
		}
		if (oldest_age_of_csegs_sampled < DECOMPRESSION_SAMPLE_MAX_AGE) {

			working_set_approximation = (working_set_approximation * 1000) / elapsed_msecs_in_sample;

			if (working_set_approximation < VM_PAGE_COMPRESSOR_COUNT) {

				running_total = overage_decompressions_during_sample_period;

				for (oldest_age_of_csegs_sampled = DECOMPRESSION_SAMPLE_MAX_AGE - 1; oldest_age_of_csegs_sampled; oldest_age_of_csegs_sampled--) {
					running_total += age_of_decompressions_during_sample_period[oldest_age_of_csegs_sampled];

					if (running_total >= aging_target)
						break;
				}
				swapout_target_age = (uint32_t)cur_ts_sec - oldest_age_of_csegs_sampled;

				KERNEL_DEBUG(0xe0400020 | DBG_FUNC_END, swapout_target_age, working_set_approximation, VM_PAGE_COMPRESSOR_COUNT, 2, 0);
			} else {
				KERNEL_DEBUG(0xe0400020 | DBG_FUNC_END, working_set_approximation, VM_PAGE_COMPRESSOR_COUNT, 0, 3, 0);
			}
		} else
			KERNEL_DEBUG(0xe0400020 | DBG_FUNC_END, working_target, running_total, 0, 4, 0);

		compressor_need_sample_reset = TRUE;
		need_eval_reset = TRUE;
	} else
		KERNEL_DEBUG(0xe0400020 | DBG_FUNC_END, sample_period_decompression_count, (compressor_thrashing_threshold_per_10msecs * elapsed_msecs_in_sample) / 10, 0, 6, 0);
done:
	if (compressor_need_sample_reset == TRUE) {
		bzero(age_of_decompressions_during_sample_period, sizeof(age_of_decompressions_during_sample_period));
		overage_decompressions_during_sample_period = 0;

		start_of_sample_period_sec = cur_ts_sec;
		start_of_sample_period_nsec = cur_ts_nsec;
		sample_period_decompression_count = 0;
		sample_period_compression_count = 0;
		last_eval_decompression_count = 0;
		last_eval_compression_count = 0;
		compressor_need_sample_reset = FALSE;
	}
	if (need_eval_reset == TRUE) {
		start_of_eval_period_sec = cur_ts_sec;
		start_of_eval_period_nsec = cur_ts_nsec;
	}
}


int		compaction_swapper_inited = 0;
int		compaction_swapper_init_now = 0;
int		compaction_swapper_running = 0;
int		compaction_swapper_abort = 0;


#if CONFIG_JETSAM
boolean_t	memorystatus_kill_on_VM_thrashing(boolean_t);
boolean_t	memorystatus_kill_on_FC_thrashing(boolean_t);
int		compressor_thrashing_induced_jetsam = 0;
int		filecache_thrashing_induced_jetsam = 0;
static boolean_t	vm_compressor_thrashing_detected = FALSE;
#endif /* CONFIG_JETSAM */

static boolean_t
compressor_needs_to_swap(void)
{
	boolean_t	should_swap = FALSE;

	if (vm_swap_up == TRUE) {
		if (COMPRESSOR_NEEDS_TO_SWAP()) {
			return (TRUE);
		}
		if (VM_PAGE_Q_THROTTLED(&vm_pageout_queue_external) && vm_page_anonymous_count < (vm_page_inactive_count / 20)) {
			return (TRUE);
		}
		if (vm_page_free_count < (vm_page_free_reserved - COMPRESSOR_FREE_RESERVED_LIMIT))
			return (TRUE);
	}
	compute_swapout_target_age();
			
	if (swapout_target_age) {
		c_segment_t	c_seg;

		lck_mtx_lock_spin_always(c_list_lock);

		if (!queue_empty(&c_age_list_head)) {

			c_seg = (c_segment_t) queue_first(&c_age_list_head);

			if (c_seg->c_creation_ts > swapout_target_age)
				swapout_target_age = 0;
		}
		lck_mtx_unlock_always(c_list_lock);
	}
#if CONFIG_PHANTOM_CACHE
	if (vm_phantom_cache_check_pressure())
		should_swap = TRUE;
#endif
	if (swapout_target_age)
		should_swap = TRUE;

	if (vm_swap_up == FALSE) {

		if (should_swap) {
#if CONFIG_JETSAM
			if (vm_compressor_thrashing_detected == FALSE) {
				vm_compressor_thrashing_detected = TRUE;
				
				if (swapout_target_age) {
					memorystatus_kill_on_VM_thrashing(TRUE /* async */);
					compressor_thrashing_induced_jetsam++;
				} else {
					memorystatus_kill_on_FC_thrashing(TRUE /* async */);
					filecache_thrashing_induced_jetsam++;
				}
				/*
				 * let the jetsam take precedence over
				 * any major compactions we might have
				 * been able to do... otherwise we run
				 * the risk of doing major compactions
				 * on segments we're about to free up
				 * due to the jetsam activity.
				 */
				should_swap = FALSE;
			}
#endif /* CONFIG_JETSAM */
		} else
			should_swap = COMPRESSOR_NEEDS_TO_MAJOR_COMPACT();
	}

	/*
	 * returning TRUE when swap_supported == FALSE
	 * will cause the major compaction engine to
	 * run, but will not trigger any swapping...
	 * segments that have been major compacted
	 * will be moved to the swapped_out_q
	 * but will not have the c_ondisk flag set
	 */
	return (should_swap);
}

#if CONFIG_JETSAM
/*
 * This function is called from the jetsam thread after killing something to
 * mitigate thrashing.
 *
 * We need to restart our thrashing detection heuristics since memory pressure
 * has potentially changed significantly, and we don't want to detect on old
 * data from before the jetsam.
 */
void
vm_thrashing_jetsam_done(void)
{
	vm_compressor_thrashing_detected = FALSE;

	/* Were we compressor-thrashing or filecache-thrashing? */
	if (swapout_target_age) {
		swapout_target_age = 0;
		compressor_need_sample_reset = TRUE;
	}
#if CONFIG_PHANTOM_CACHE
	else {
		vm_phantom_cache_restart_sample();
	}
#endif
}
#endif /* CONFIG_JETSAM */

uint32_t vm_wake_compactor_swapper_calls = 0;

void
vm_wake_compactor_swapper(void)
{
	boolean_t need_major_compaction = FALSE;

	if (compaction_swapper_running)
		return;

	if (c_minor_count == 0 && need_major_compaction == FALSE)
		return;

	lck_mtx_lock_spin_always(c_list_lock);

	fastwake_warmup = FALSE;

	if (compaction_swapper_running == 0) {
		vm_wake_compactor_swapper_calls++;

		thread_wakeup((event_t)&c_compressor_swap_trigger);
		
		compaction_swapper_running = 1;
	}
	lck_mtx_unlock_always(c_list_lock);
}


void
vm_consider_waking_compactor_swapper(void)
{
	boolean_t	need_wakeup = FALSE;

	if (compaction_swapper_running)
		return;

	if (!compaction_swapper_inited && !compaction_swapper_init_now) {
		compaction_swapper_init_now = 1;
		need_wakeup = TRUE;
	}

	if (c_minor_count && (COMPRESSOR_NEEDS_TO_MINOR_COMPACT())) {

		need_wakeup = TRUE;

	} else if (compressor_needs_to_swap()) {

		need_wakeup = TRUE;

	} else if (c_minor_count) {
		uint64_t	total_bytes;

		total_bytes = compressor_object->resident_page_count * PAGE_SIZE_64;

		if ((total_bytes - compressor_bytes_used) > total_bytes / 10)
			need_wakeup = TRUE;
	}
	if (need_wakeup == TRUE) {
			
		lck_mtx_lock_spin_always(c_list_lock);

		fastwake_warmup = FALSE;

		if (compaction_swapper_running == 0) {
			memoryshot(VM_WAKEUP_COMPACTOR_SWAPPER, DBG_FUNC_NONE);

			thread_wakeup((event_t)&c_compressor_swap_trigger);

			compaction_swapper_running = 1;
		}
		lck_mtx_unlock_always(c_list_lock);
	}
}


#define	C_SWAPOUT_LIMIT			4
#define	DELAYED_COMPACTIONS_PER_PASS	30

void
vm_compressor_do_delayed_compactions(boolean_t flush_all)
{
	c_segment_t	c_seg;
	int		number_compacted = 0;
	boolean_t	needs_to_swap = FALSE;


	lck_mtx_assert(c_list_lock, LCK_MTX_ASSERT_OWNED);

	while (!queue_empty(&c_minor_list_head) && needs_to_swap == FALSE) {
		
		c_seg = (c_segment_t)queue_first(&c_minor_list_head);
		
		lck_mtx_lock_spin_always(&c_seg->c_lock);

		if (c_seg->c_busy) {

			lck_mtx_unlock_always(c_list_lock);
			c_seg_wait_on_busy(c_seg);
			lck_mtx_lock_spin_always(c_list_lock);

			continue;
		}
		C_SEG_BUSY(c_seg);

		c_seg_do_minor_compaction_and_unlock(c_seg, TRUE, FALSE, TRUE);

		if (vm_swap_up == TRUE && (number_compacted++ > DELAYED_COMPACTIONS_PER_PASS)) {
			
			if ((flush_all == TRUE || compressor_needs_to_swap() == TRUE) && c_swapout_count < C_SWAPOUT_LIMIT)
				needs_to_swap = TRUE;

			number_compacted = 0;
		}
		lck_mtx_lock_spin_always(c_list_lock);
	}
}


#define C_SEGMENT_SWAPPEDIN_AGE_LIMIT	10

static void
vm_compressor_age_swapped_in_segments(boolean_t flush_all)
{
	c_segment_t	c_seg;
	clock_sec_t	now;
	clock_nsec_t	nsec;

	clock_get_system_nanotime(&now,  &nsec);
			
	while (!queue_empty(&c_swappedin_list_head)) {

		c_seg = (c_segment_t)queue_first(&c_swappedin_list_head);

		if (flush_all == FALSE && (now - c_seg->c_swappedin_ts) < C_SEGMENT_SWAPPEDIN_AGE_LIMIT)
			break;
			
		lck_mtx_lock_spin_always(&c_seg->c_lock);

		queue_remove(&c_swappedin_list_head, c_seg, c_segment_t, c_age_list);
		c_seg->c_on_swappedin_q = 0;
		c_swappedin_count--;

		c_seg_insert_into_q(&c_age_list_head, c_seg);
		c_seg->c_on_age_q = 1;
		c_age_count++;

		lck_mtx_unlock_always(&c_seg->c_lock);
	}
}


void
vm_compressor_flush(void)
{
	uint64_t	vm_swap_put_failures_at_start;
	wait_result_t	wait_result = 0;
	AbsoluteTime	startTime, endTime;
	clock_sec_t	now_sec;
	clock_nsec_t	now_nsec;
	uint64_t	nsec;

	HIBLOG("vm_compressor_flush - starting\n");

	clock_get_uptime(&startTime);

	lck_mtx_lock_spin_always(c_list_lock);

	fastwake_warmup = FALSE;
	compaction_swapper_abort = 1;

	while (compaction_swapper_running) {
		assert_wait((event_t)&compaction_swapper_running, THREAD_UNINT);

		lck_mtx_unlock_always(c_list_lock);
		
		thread_block(THREAD_CONTINUE_NULL);

		lck_mtx_lock_spin_always(c_list_lock);
	}
	compaction_swapper_abort = 0;
	compaction_swapper_running = 1;

	hibernate_flushing = TRUE;
	hibernate_no_swapspace = FALSE;
	c_generation_id_flush_barrier = c_generation_id + 1000;

	clock_get_system_nanotime(&now_sec, &now_nsec);
	hibernate_flushing_deadline = now_sec + HIBERNATE_FLUSHING_SECS_TO_COMPLETE;

	vm_swap_put_failures_at_start = vm_swap_put_failures;

	vm_compressor_compact_and_swap(TRUE);

	while (!queue_empty(&c_swapout_list_head)) {

		assert_wait_timeout((event_t) &compaction_swapper_running, THREAD_INTERRUPTIBLE, 5000, 1000*NSEC_PER_USEC);

		lck_mtx_unlock_always(c_list_lock);
		
		wait_result = thread_block(THREAD_CONTINUE_NULL);

		lck_mtx_lock_spin_always(c_list_lock);

		if (wait_result == THREAD_TIMED_OUT)
			break;
	}
	hibernate_flushing = FALSE;
	compaction_swapper_running = 0;

	if (vm_swap_put_failures > vm_swap_put_failures_at_start)
		HIBLOG("vm_compressor_flush failed to clean %llu segments - vm_page_compressor_count(%d)\n",
		       vm_swap_put_failures - vm_swap_put_failures_at_start, VM_PAGE_COMPRESSOR_COUNT);
	
	lck_mtx_unlock_always(c_list_lock);

        clock_get_uptime(&endTime);
        SUB_ABSOLUTETIME(&endTime, &startTime);
        absolutetime_to_nanoseconds(endTime, &nsec);

	HIBLOG("vm_compressor_flush completed - took %qd msecs\n", nsec / 1000000ULL);
}


extern void	vm_swap_file_set_tuneables(void);
int		compaction_swap_trigger_thread_awakened = 0;


static void
vm_compressor_swap_trigger_thread(void)
{
	/*
	 * compaction_swapper_init_now is set when the first call to
	 * vm_consider_waking_compactor_swapper is made from 
	 * vm_pageout_scan... since this function is called upon 
	 * thread creation, we want to make sure to delay adjusting
	 * the tuneables until we are awakened via vm_pageout_scan
	 * so that we are at a point where the vm_swapfile_open will
	 * be operating on the correct directory (in case the default
	 * of /var/vm/  is overridden by the dymanic_pager 
	 */
	if (compaction_swapper_init_now && !compaction_swapper_inited) {
		if (vm_compressor_mode == VM_PAGER_COMPRESSOR_WITH_SWAP)
			vm_swap_file_set_tuneables();

		compaction_swapper_inited = 1;
	}
	lck_mtx_lock_spin_always(c_list_lock);

	compaction_swap_trigger_thread_awakened++;

	vm_compressor_compact_and_swap(FALSE);

	assert_wait((event_t)&c_compressor_swap_trigger, THREAD_UNINT);

	compaction_swapper_running = 0;
	thread_wakeup((event_t)&compaction_swapper_running);

	lck_mtx_unlock_always(c_list_lock);
		
	thread_block((thread_continue_t)vm_compressor_swap_trigger_thread);
	
	/* NOTREACHED */
}


void
vm_compressor_record_warmup_start(void)
{
	c_segment_t	c_seg;

	lck_mtx_lock_spin_always(c_list_lock);

	if (first_c_segment_to_warm_generation_id == 0) {
		if (!queue_empty(&c_age_list_head)) {

			c_seg = (c_segment_t)queue_last(&c_age_list_head);

			first_c_segment_to_warm_generation_id = c_seg->c_generation_id;
		} else
			first_c_segment_to_warm_generation_id = 0;

		fastwake_recording_in_progress = TRUE;
	}
	lck_mtx_unlock_always(c_list_lock);
}


void 
vm_compressor_record_warmup_end(void)
{
	c_segment_t	c_seg;

	lck_mtx_lock_spin_always(c_list_lock);

	if (fastwake_recording_in_progress == TRUE) {

		if (!queue_empty(&c_age_list_head)) {

			c_seg = (c_segment_t)queue_last(&c_age_list_head);

			last_c_segment_to_warm_generation_id = c_seg->c_generation_id;
		} else
			last_c_segment_to_warm_generation_id = first_c_segment_to_warm_generation_id;

		fastwake_recording_in_progress = FALSE;

		HIBLOG("vm_compressor_record_warmup (%qd - %qd)\n", first_c_segment_to_warm_generation_id, last_c_segment_to_warm_generation_id);
	}
	lck_mtx_unlock_always(c_list_lock);
}


#define DELAY_TRIM_ON_WAKE_SECS		4

void
vm_compressor_delay_trim(void)
{
        clock_sec_t	sec;
	clock_nsec_t	nsec;

	clock_get_system_nanotime(&sec, &nsec);
	dont_trim_until_ts = sec + DELAY_TRIM_ON_WAKE_SECS;
}


void
vm_compressor_do_warmup(void)
{
	lck_mtx_lock_spin_always(c_list_lock);
	
	if (first_c_segment_to_warm_generation_id == last_c_segment_to_warm_generation_id) {
		first_c_segment_to_warm_generation_id = last_c_segment_to_warm_generation_id = 0;

		lck_mtx_unlock_always(c_list_lock);
		return;
	}

	if (compaction_swapper_running == 0) {

		fastwake_warmup = TRUE;
		compaction_swapper_running = 1;
		thread_wakeup((event_t)&c_compressor_swap_trigger);
	}
	lck_mtx_unlock_always(c_list_lock);
}


void
do_fastwake_warmup(void)
{
	uint64_t	my_thread_id;
	c_segment_t	c_seg = NULL;
	AbsoluteTime	startTime, endTime;
	uint64_t	nsec;


	HIBLOG("vm_compressor_fastwake_warmup (%qd - %qd) - starting\n", first_c_segment_to_warm_generation_id, last_c_segment_to_warm_generation_id);

	clock_get_uptime(&startTime);

	lck_mtx_unlock_always(c_list_lock);

	my_thread_id = current_thread()->thread_id;
	proc_set_task_policy_thread(kernel_task, my_thread_id,
				    TASK_POLICY_INTERNAL, TASK_POLICY_IO, THROTTLE_LEVEL_COMPRESSOR_TIER2);

	PAGE_REPLACEMENT_DISALLOWED(TRUE);

	lck_mtx_lock_spin_always(c_list_lock);

	while (!queue_empty(&c_swappedout_list_head) && fastwake_warmup == TRUE) {

		c_seg = (c_segment_t) queue_first(&c_swappedout_list_head);

		if (c_seg->c_generation_id < first_c_segment_to_warm_generation_id || 
		    c_seg->c_generation_id > last_c_segment_to_warm_generation_id)
			break;

		lck_mtx_lock_spin_always(&c_seg->c_lock);
		lck_mtx_unlock_always(c_list_lock);
		
		if (c_seg->c_busy) {
			PAGE_REPLACEMENT_DISALLOWED(FALSE);
			c_seg_wait_on_busy(c_seg);
			PAGE_REPLACEMENT_DISALLOWED(TRUE);
		} else {
			c_seg_swapin(c_seg, TRUE);

			lck_mtx_unlock_always(&c_seg->c_lock);
			c_segment_warmup_count++;

			PAGE_REPLACEMENT_DISALLOWED(FALSE);
			vm_pageout_io_throttle();
			PAGE_REPLACEMENT_DISALLOWED(TRUE);
		}
		lck_mtx_lock_spin_always(c_list_lock);
	}
	lck_mtx_unlock_always(c_list_lock);

	PAGE_REPLACEMENT_DISALLOWED(FALSE);

	proc_set_task_policy_thread(kernel_task, my_thread_id,
				    TASK_POLICY_INTERNAL, TASK_POLICY_IO, THROTTLE_LEVEL_COMPRESSOR_TIER0);

        clock_get_uptime(&endTime);
        SUB_ABSOLUTETIME(&endTime, &startTime);
        absolutetime_to_nanoseconds(endTime, &nsec);

	HIBLOG("vm_compressor_fastwake_warmup completed - took %qd msecs\n", nsec / 1000000ULL);

	lck_mtx_lock_spin_always(c_list_lock);

	first_c_segment_to_warm_generation_id = last_c_segment_to_warm_generation_id = 0;
}


void
vm_compressor_compact_and_swap(boolean_t flush_all)
{
	c_segment_t	c_seg, c_seg_next;
	boolean_t	keep_compacting;


	if (fastwake_warmup == TRUE) {
		uint64_t	starting_warmup_count;

		starting_warmup_count = c_segment_warmup_count;

		KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 11) | DBG_FUNC_START, c_segment_warmup_count,
				      first_c_segment_to_warm_generation_id, last_c_segment_to_warm_generation_id, 0, 0);
		do_fastwake_warmup();
		KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 11) | DBG_FUNC_END, c_segment_warmup_count, c_segment_warmup_count - starting_warmup_count, 0, 0, 0);

		fastwake_warmup = FALSE;
	}

	/*
	 * it's possible for the c_age_list_head to be empty if we
	 * hit our limits for growing the compressor pool and we subsequently
	 * hibernated... on the next hibernation we could see the queue as
	 * empty and not proceeed even though we have a bunch of segments on
	 * the swapped in queue that need to be dealt with.
	 */
	vm_compressor_do_delayed_compactions(flush_all);

	vm_compressor_age_swapped_in_segments(flush_all);


	while (!queue_empty(&c_age_list_head) && compaction_swapper_abort == 0) {

		if (hibernate_flushing == TRUE) {
			clock_sec_t	sec;
			clock_nsec_t	nsec;

			if (hibernate_should_abort()) {
				HIBLOG("vm_compressor_flush - hibernate_should_abort returned TRUE\n");
				break;
			}
			if (hibernate_no_swapspace == TRUE) {
				HIBLOG("vm_compressor_flush - out of swap space\n");
				break;
			}
			clock_get_system_nanotime(&sec, &nsec);
		
			if (sec > hibernate_flushing_deadline) {
				HIBLOG("vm_compressor_flush - failed to finish before deadline\n");
				break;
			}
		}
		if (c_swapout_count >= C_SWAPOUT_LIMIT) {

			assert_wait_timeout((event_t) &compaction_swapper_running, THREAD_INTERRUPTIBLE, 100, 1000*NSEC_PER_USEC);

			lck_mtx_unlock_always(c_list_lock);

			thread_block(THREAD_CONTINUE_NULL);

			lck_mtx_lock_spin_always(c_list_lock);
		}
		/*
		 * Minor compactions
		 */
		vm_compressor_do_delayed_compactions(flush_all);

		vm_compressor_age_swapped_in_segments(flush_all);

		if (c_swapout_count >= C_SWAPOUT_LIMIT) {
			/*
			 * we timed out on the above thread_block
			 * let's loop around and try again
			 * the timeout allows us to continue
			 * to do minor compactions to make
			 * more memory available
			 */
			continue;
		}

		/*
		 * Swap out segments?
		 */
		if (flush_all == FALSE) {
			boolean_t	needs_to_swap;

			lck_mtx_unlock_always(c_list_lock);

			needs_to_swap = compressor_needs_to_swap();

			lck_mtx_lock_spin_always(c_list_lock);
			
			if (needs_to_swap == FALSE)
				break;
		}
		if (queue_empty(&c_age_list_head))
			break;
		c_seg = (c_segment_t) queue_first(&c_age_list_head);

		if (flush_all == TRUE && c_seg->c_generation_id > c_generation_id_flush_barrier)
			break;

		if (c_seg->c_filling) {
			/*
			 * we're at or near the head... no more work to do
			 */
			break;
		}
		lck_mtx_lock_spin_always(&c_seg->c_lock);

		if (c_seg->c_busy) {

			lck_mtx_unlock_always(c_list_lock);
			c_seg_wait_on_busy(c_seg);
			lck_mtx_lock_spin_always(c_list_lock);

			continue;
		}
		C_SEG_BUSY(c_seg);

		if (c_seg_do_minor_compaction_and_unlock(c_seg, FALSE, TRUE, TRUE)) {
			/*
			 * found an empty c_segment and freed it
			 * so go grab the next guy in the queue
			 */
			continue;
		}
		/*
		 * Major compaction
		 */
		keep_compacting = TRUE;

		while (keep_compacting == TRUE) {
					
			assert(c_seg->c_busy);

			/* look for another segment to consolidate */

			c_seg_next = (c_segment_t) queue_next(&c_seg->c_age_list);
			
			if (queue_end(&c_age_list_head, (queue_entry_t)c_seg_next))
				break;

			if (c_seg_major_compact_ok(c_seg, c_seg_next) == FALSE)
				break;

			lck_mtx_lock_spin_always(&c_seg_next->c_lock);

			if (c_seg_next->c_busy) {

				lck_mtx_unlock_always(c_list_lock);
				c_seg_wait_on_busy(c_seg_next);
				lck_mtx_lock_spin_always(c_list_lock);

				continue;
			}
			/* grab that segment */
			C_SEG_BUSY(c_seg_next);

			if (c_seg_do_minor_compaction_and_unlock(c_seg_next, FALSE, TRUE, TRUE)) {
				/*
				 * found an empty c_segment and freed it
				 * so we can't continue to use c_seg_next
				 */
				continue;
			}

			/* unlock the list ... */
			lck_mtx_unlock_always(c_list_lock);

			/* do the major compaction */

			keep_compacting = c_seg_major_compact(c_seg, c_seg_next);

			PAGE_REPLACEMENT_DISALLOWED(TRUE);

			lck_mtx_lock_spin_always(&c_seg_next->c_lock);
			/*
			 * run a minor compaction on the donor segment
			 * since we pulled at least some of it's 
			 * data into our target...  if we've emptied
			 * it, now is a good time to free it which
			 * c_seg_minor_compaction_and_unlock also takes care of
			 *
			 * by passing TRUE, we ask for c_busy to be cleared
			 * and c_wanted to be taken care of
			 */
			c_seg_minor_compaction_and_unlock(c_seg_next, TRUE);

			PAGE_REPLACEMENT_DISALLOWED(FALSE);

			/* relock the list */
			lck_mtx_lock_spin_always(c_list_lock);

		} /* major compaction */

		c_seg_major_compact_stats.wasted_space_in_swapouts += C_SEG_BUFSIZE - c_seg->c_bytes_used;
		c_seg_major_compact_stats.count_of_swapouts++;

		lck_mtx_lock_spin_always(&c_seg->c_lock);

		assert(c_seg->c_busy);
		assert(c_seg->c_on_age_q);
		assert(!c_seg->c_on_minorcompact_q);

		queue_remove(&c_age_list_head, c_seg, c_segment_t, c_age_list);
		c_seg->c_on_age_q = 0;
		c_age_count--;

		if (vm_swap_up == TRUE) {
			queue_enter(&c_swapout_list_head, c_seg, c_segment_t, c_age_list);
			c_seg->c_on_swapout_q = 1;
			c_swapout_count++;
		} else {
			queue_enter(&c_swappedout_list_head, c_seg, c_segment_t, c_age_list);
			c_seg->c_on_swappedout_q = 1;
			c_swappedout_count++;
		}
		C_SEG_WAKEUP_DONE(c_seg);

		lck_mtx_unlock_always(&c_seg->c_lock);

		if (c_swapout_count) {
			lck_mtx_unlock_always(c_list_lock);

			thread_wakeup((event_t)&c_swapout_list_head);
			
			lck_mtx_lock_spin_always(c_list_lock);
		}
	}
}


static uint32_t	no_paging_space_action_in_progress = 0;
extern void memorystatus_send_low_swap_note(void);


static c_segment_t
c_seg_allocate(c_segment_t *current_chead)
{
        clock_sec_t	sec;
        clock_nsec_t	nsec;
	c_segment_t	c_seg;
	int		slotarray;

	if ( (c_seg = *current_chead) == NULL ) {
		uint32_t	c_segno;

		if (vm_compressor_low_on_space() || vm_swap_low_on_space()) {

			if (no_paging_space_action_in_progress == 0) {

				if (OSCompareAndSwap(0, 1, (UInt32 *)&no_paging_space_action_in_progress)) {

					if (no_paging_space_action()) {
						memorystatus_send_low_swap_note();
					}

					no_paging_space_action_in_progress = 0;
				}
			}
		}
		KERNEL_DEBUG(0xe0400004 | DBG_FUNC_START, 0, 0, 0, 0, 0);

		lck_mtx_lock_spin_always(c_list_lock);

		while (c_segments_busy == TRUE) {
			assert_wait((event_t) (&c_segments_busy), THREAD_UNINT);
	
			lck_mtx_unlock_always(c_list_lock);

			thread_block(THREAD_CONTINUE_NULL);

			lck_mtx_lock_spin_always(c_list_lock);
		}
		if (c_free_segno_head == (uint32_t)-1) {

			if (c_segments_available >= c_segments_limit || c_segment_pages_compressed >= c_segment_pages_compressed_limit) {
				lck_mtx_unlock_always(c_list_lock);

				KERNEL_DEBUG(0xe0400004 | DBG_FUNC_END, 0, 0, 0, 1, 0);
				return (NULL);
			}
			c_segments_busy = TRUE;
			lck_mtx_unlock_always(c_list_lock);

			kernel_memory_populate(kernel_map, (vm_offset_t)c_segments_next_page, PAGE_SIZE, KMA_KOBJECT);
			c_segments_next_page += PAGE_SIZE;

			for (c_segno = c_segments_available + 1; c_segno < (c_segments_available + C_SEGMENTS_PER_PAGE); c_segno++)
				c_segments[c_segno - 1].c_segno = c_segno;

			lck_mtx_lock_spin_always(c_list_lock);

			c_segments[c_segno - 1].c_segno = c_free_segno_head;
			c_free_segno_head = c_segments_available;
			c_segments_available += C_SEGMENTS_PER_PAGE;

			c_segments_busy = FALSE;
			thread_wakeup((event_t) (&c_segments_busy));
		}
		c_segno = c_free_segno_head;
		c_free_segno_head = c_segments[c_segno].c_segno;

		lck_mtx_unlock_always(c_list_lock);

		c_seg = (c_segment_t)zalloc(compressor_segment_zone);
		bzero((char *)c_seg, sizeof(struct c_segment));

		if (kernel_memory_allocate(kernel_map, (vm_offset_t *)(&c_seg->c_store.c_buffer), C_SEG_ALLOCSIZE, 0, KMA_COMPRESSOR | KMA_VAONLY) != KERN_SUCCESS) {
			zfree(compressor_segment_zone, c_seg);

			lck_mtx_lock_spin_always(c_list_lock);

			c_segments[c_segno].c_segno = c_free_segno_head;
			c_free_segno_head = c_segno;

			lck_mtx_unlock_always(c_list_lock);

			KERNEL_DEBUG(0xe0400004 | DBG_FUNC_END, 0, 0, 0, 2, 0);

			return (NULL);
		}
		OSAddAtomic64(C_SEG_ALLOCSIZE, &compressor_kvspace_used);

#if __i386__ || __x86_64__
		lck_mtx_init(&c_seg->c_lock, &vm_compressor_lck_grp, &vm_compressor_lck_attr);
#else /* __i386__ || __x86_64__ */
		lck_spin_init(&c_seg->c_lock, &vm_compressor_lck_grp, &vm_compressor_lck_attr);
#endif /* __i386__ || __x86_64__ */
	
		kernel_memory_populate(kernel_map, (vm_offset_t)(c_seg->c_store.c_buffer), 3 * PAGE_SIZE, KMA_COMPRESSOR);

		c_seg->c_populated_offset = C_SEG_BYTES_TO_OFFSET(3 * PAGE_SIZE);
		c_seg->c_firstemptyslot = C_SLOT_MAX;
		c_seg->c_mysegno = c_segno;
		c_seg->c_filling = 1;

		lck_mtx_lock_spin_always(c_list_lock);

		c_segment_count++;
		c_segments[c_segno].c_seg = c_seg;

		c_seg->c_generation_id = c_generation_id++;
		
		queue_enter(&c_age_list_head, c_seg, c_segment_t, c_age_list);
		c_seg->c_on_age_q = 1;
		c_age_count++;

		lck_mtx_unlock_always(c_list_lock);

		clock_get_system_nanotime(&sec, &nsec);
		c_seg->c_creation_ts = (uint32_t)sec;

		*current_chead = c_seg;

		KERNEL_DEBUG(0xe0400004 | DBG_FUNC_END, c_seg, 0, 0, 3, 0);
	}
	slotarray = C_SEG_SLOTARRAY_FROM_INDEX(c_seg, c_seg->c_nextslot);

	if (c_seg->c_slots[slotarray] == 0) {
		KERNEL_DEBUG(0xe0400008 | DBG_FUNC_START, 0, 0, 0, 0, 0);

		c_seg->c_slots[slotarray] = (struct c_slot *)kalloc(sizeof(struct c_slot) * C_SEG_SLOT_ARRAY_SIZE);

		KERNEL_DEBUG(0xe0400008 | DBG_FUNC_END, 0, 0, 0, 0, 0);
	}
		
	PAGE_REPLACEMENT_DISALLOWED(TRUE);

	lck_mtx_lock_spin_always(&c_seg->c_lock);

	return (c_seg);
}



static void
c_current_seg_filled(c_segment_t c_seg, c_segment_t *current_chead)
{
	uint32_t	unused_bytes;
	uint32_t	offset_to_depopulate;

	unused_bytes = trunc_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset - c_seg->c_nextoffset));

	if (unused_bytes) {

		offset_to_depopulate = C_SEG_BYTES_TO_OFFSET(round_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_nextoffset)));

		/*
		 *  release the extra physical page(s) at the end of the segment
		 */
		lck_mtx_unlock_always(&c_seg->c_lock);

		kernel_memory_depopulate(
			kernel_map,
			(vm_offset_t) &c_seg->c_store.c_buffer[offset_to_depopulate],
			unused_bytes,
			KMA_COMPRESSOR);

		lck_mtx_lock_spin_always(&c_seg->c_lock);

		c_seg->c_populated_offset = offset_to_depopulate;
	}
	c_seg->c_filling = 0;

	if (C_SEG_UNUSED_BYTES(c_seg) >= PAGE_SIZE)
		c_seg_need_delayed_compaction(c_seg);

	lck_mtx_unlock_always(&c_seg->c_lock);

	*current_chead = NULL;
}


/*
 * returns with c_seg locked
 */
void
c_seg_swapin_requeue(c_segment_t c_seg)
{
        clock_sec_t	sec;
        clock_nsec_t	nsec;

	clock_get_system_nanotime(&sec, &nsec);

	lck_mtx_lock_spin_always(c_list_lock);
	lck_mtx_lock_spin_always(&c_seg->c_lock);

	if (c_seg->c_on_swappedout_q) {
		queue_remove(&c_swappedout_list_head, c_seg, c_segment_t, c_age_list);
		c_seg->c_on_swappedout_q = 0;
		c_swappedout_count--;
	} else {
		assert(c_seg->c_on_swappedout_sparse_q);

		queue_remove(&c_swappedout_sparse_list_head, c_seg, c_segment_t, c_age_list);
		c_seg->c_on_swappedout_sparse_q = 0;
		c_swappedout_sparse_count--;
	}
	if (c_seg->c_store.c_buffer) {
		queue_enter(&c_swappedin_list_head, c_seg, c_segment_t, c_age_list);
		c_seg->c_on_swappedin_q = 1;
		c_swappedin_count++;
	}
#if TRACK_BAD_C_SEGMENTS
	else {
		queue_enter(&c_bad_list_head, c_seg, c_segment_t, c_age_list);
		c_seg->c_on_bad_q = 1;
		c_bad_count++;
	}
#endif
	c_seg->c_swappedin_ts = (uint32_t)sec;
	c_seg->c_ondisk = 0;
	c_seg->c_was_swapped_in = 1;

	lck_mtx_unlock_always(c_list_lock);
}



/*
 * c_seg has to be locked and is returned locked.
 * PAGE_REPLACMENT_DISALLOWED has to be TRUE on entry and is returned TRUE
 */

void
c_seg_swapin(c_segment_t c_seg, boolean_t force_minor_compaction)
{
	vm_offset_t	addr = 0;
	uint32_t	io_size = 0;
	uint64_t	f_offset;

#if !CHECKSUM_THE_SWAP
	if (c_seg->c_ondisk)
		c_seg_trim_tail(c_seg);
#endif
	io_size = round_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset));
	f_offset = c_seg->c_store.c_swap_handle;

	C_SEG_BUSY(c_seg);
	lck_mtx_unlock_always(&c_seg->c_lock);
	
	if (c_seg->c_ondisk) {

		PAGE_REPLACEMENT_DISALLOWED(FALSE);

		if (kernel_memory_allocate(kernel_map, &addr, C_SEG_ALLOCSIZE, 0, KMA_COMPRESSOR | KMA_VAONLY) != KERN_SUCCESS)
			panic("c_seg_swapin: kernel_memory_allocate failed\n");

		kernel_memory_populate(kernel_map, addr, io_size, KMA_COMPRESSOR);

		if (vm_swap_get(addr, f_offset, io_size) != KERN_SUCCESS) {
			PAGE_REPLACEMENT_DISALLOWED(TRUE);

			kernel_memory_depopulate(kernel_map, addr, io_size, KMA_COMPRESSOR);
			kmem_free(kernel_map, addr, C_SEG_ALLOCSIZE);

			c_seg->c_store.c_buffer = (int32_t*) NULL;
			c_seg->c_populated_offset = C_SEG_BYTES_TO_OFFSET(0);
		} else {
			c_seg->c_store.c_buffer = (int32_t*) addr;
#if ENCRYPTED_SWAP
			vm_swap_decrypt(c_seg);
#endif /* ENCRYPTED_SWAP */

#if CHECKSUM_THE_SWAP
			if (c_seg->cseg_swap_size != io_size)
				panic("swapin size doesn't match swapout size");

			if (c_seg->cseg_hash != hash_string((char*) c_seg->c_store.c_buffer, (int)io_size)) {
				panic("c_seg_swapin - Swap hash mismatch\n");
			}
#endif /* CHECKSUM_THE_SWAP */

			PAGE_REPLACEMENT_DISALLOWED(TRUE);

			if (force_minor_compaction == TRUE) {
				lck_mtx_lock_spin_always(&c_seg->c_lock);
			
				c_seg_minor_compaction_and_unlock(c_seg, FALSE);
			}
			OSAddAtomic64(c_seg->c_bytes_used, &compressor_bytes_used);
			OSAddAtomic64(C_SEG_ALLOCSIZE, &compressor_kvspace_used);
		}
	}
	c_seg_swapin_requeue(c_seg);

	C_SEG_WAKEUP_DONE(c_seg);
}


static int
c_compress_page(char *src, c_slot_mapping_t slot_ptr, c_segment_t *current_chead, char *scratch_buf)
{
	int		c_size;
	int		c_rounded_size = 0;
	int		max_csize;
	c_slot_t	cs;
	c_segment_t	c_seg;

	KERNEL_DEBUG(0xe0400000 | DBG_FUNC_START, *current_chead, 0, 0, 0, 0);
retry:
	if ((c_seg = c_seg_allocate(current_chead)) == NULL)
		return (1);
	/*
	 * returns with c_seg lock held
	 * and PAGE_REPLACEMENT_DISALLOWED(TRUE)
	 */
	cs = C_SEG_SLOT_FROM_INDEX(c_seg, c_seg->c_nextslot);

	cs->c_packed_ptr = C_SLOT_PACK_PTR(slot_ptr);
	assert(slot_ptr == (c_slot_mapping_t)C_SLOT_UNPACK_PTR(cs));

	cs->c_offset = c_seg->c_nextoffset;

	max_csize = C_SEG_BUFSIZE - C_SEG_OFFSET_TO_BYTES((int32_t)cs->c_offset);

	if (max_csize > PAGE_SIZE)
		max_csize = PAGE_SIZE;

	if (C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset -
				  c_seg->c_nextoffset)
	    < (unsigned) max_csize + PAGE_SIZE &&
	    (C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset)
	     < C_SEG_ALLOCSIZE)) {
		lck_mtx_unlock_always(&c_seg->c_lock);

		kernel_memory_populate(kernel_map,
				       (vm_offset_t) &c_seg->c_store.c_buffer[c_seg->c_populated_offset],
				       PAGE_SIZE,
				       KMA_COMPRESSOR);

		lck_mtx_lock_spin_always(&c_seg->c_lock);

		c_seg->c_populated_offset += C_SEG_BYTES_TO_OFFSET(PAGE_SIZE);
	}

#if CHECKSUM_THE_DATA
	cs->c_hash_data = hash_string(src, PAGE_SIZE);
#endif

	c_size = WKdm_compress_new((WK_word *)(uintptr_t)src, (WK_word *)(uintptr_t)&c_seg->c_store.c_buffer[cs->c_offset],
				  (WK_word *)(uintptr_t)scratch_buf, max_csize - 4);
	assert(c_size <= (max_csize - 4) && c_size >= -1);

	if (c_size == -1) {

		if (max_csize < PAGE_SIZE) {
			c_current_seg_filled(c_seg, current_chead);

			PAGE_REPLACEMENT_DISALLOWED(FALSE);

			goto retry;
		}
		c_size = PAGE_SIZE;

		memcpy(&c_seg->c_store.c_buffer[cs->c_offset], src, c_size);
	}
#if CHECKSUM_THE_COMPRESSED_DATA
	cs->c_hash_compressed_data = hash_string((char *)&c_seg->c_store.c_buffer[cs->c_offset], c_size);
#endif
	c_rounded_size = (c_size + C_SEG_OFFSET_ALIGNMENT_MASK) & ~C_SEG_OFFSET_ALIGNMENT_MASK;

	PACK_C_SIZE(cs, c_size);
	c_seg->c_bytes_used += c_rounded_size;
	c_seg->c_nextoffset += C_SEG_BYTES_TO_OFFSET(c_rounded_size);

	slot_ptr->s_cindx = c_seg->c_nextslot++;
	/* <csegno=0,indx=0> would mean "empty slot", so use csegno+1 */
	slot_ptr->s_cseg = c_seg->c_mysegno + 1; 

	if (c_seg->c_nextoffset >= C_SEG_OFF_LIMIT || c_seg->c_nextslot >= C_SLOT_MAX)
		c_current_seg_filled(c_seg, current_chead);
	else
		lck_mtx_unlock_always(&c_seg->c_lock);

	PAGE_REPLACEMENT_DISALLOWED(FALSE);

	OSAddAtomic64(c_rounded_size, &compressor_bytes_used);
	OSAddAtomic64(PAGE_SIZE, &c_segment_input_bytes);
	OSAddAtomic64(c_size, &c_segment_compressed_bytes);

	OSAddAtomic(1, &c_segment_pages_compressed);
	OSAddAtomic(1, &sample_period_compression_count);

	KERNEL_DEBUG(0xe0400000 | DBG_FUNC_END, *current_chead, c_size, c_segment_input_bytes, c_segment_compressed_bytes, 0);

	return (0);
}


static int
c_decompress_page(char *dst, volatile c_slot_mapping_t slot_ptr, int flags, int *zeroslot)
{
	c_slot_t	cs;
	c_segment_t	c_seg;
	int		c_indx;
	int		c_rounded_size;
	uint32_t	c_size;
	int		retval = 0;
	boolean_t	c_seg_has_data = TRUE;
	boolean_t	c_seg_swappedin = FALSE;
	boolean_t	need_unlock = TRUE;
	boolean_t	consider_defragmenting = FALSE;

ReTry:
	PAGE_REPLACEMENT_DISALLOWED(TRUE);

#if HIBERNATION
	/*
	 * if hibernation is enabled, it indicates (via a call
	 * to 'vm_decompressor_lock' that no further
	 * decompressions are allowed once it reaches
	 * the point of flushing all of the currently dirty
	 * anonymous memory through the compressor and out
	 * to disk... in this state we allow freeing of compressed
	 * pages and must honor the C_DONT_BLOCK case
	 */
	if (dst && decompressions_blocked == TRUE) {
		if (flags & C_DONT_BLOCK) {

			PAGE_REPLACEMENT_DISALLOWED(FALSE);

			*zeroslot = 0;
			return (-2);
		}
		/*
		 * it's safe to atomically assert and block behind the
		 * lock held in shared mode because "decompressions_blocked" is
		 * only set and cleared and the thread_wakeup done when the lock
		 * is held exclusively
		 */
		assert_wait((event_t)&decompressions_blocked, THREAD_UNINT);

		PAGE_REPLACEMENT_DISALLOWED(FALSE);

		thread_block(THREAD_CONTINUE_NULL);

		goto ReTry;
	}
#endif
	/* s_cseg is actually "segno+1" */
	c_seg = c_segments[slot_ptr->s_cseg - 1].c_seg;

	lck_mtx_lock_spin_always(&c_seg->c_lock);

	if (flags & C_DONT_BLOCK) {
		if (c_seg->c_busy || (c_seg->c_ondisk && dst)) {

			retval = -2;
			*zeroslot = 0;

			goto done;
		}
	}
	if (c_seg->c_busy) {

		PAGE_REPLACEMENT_DISALLOWED(FALSE);

		c_seg_wait_on_busy(c_seg);

		goto ReTry;
	}
	c_indx = slot_ptr->s_cindx;

	cs = C_SEG_SLOT_FROM_INDEX(c_seg, c_indx);

	c_size = UNPACK_C_SIZE(cs);

	c_rounded_size = (c_size + C_SEG_OFFSET_ALIGNMENT_MASK) & ~C_SEG_OFFSET_ALIGNMENT_MASK;

	if (dst) {
		uint32_t	age_of_cseg;
		clock_sec_t	cur_ts_sec;
		clock_nsec_t	cur_ts_nsec;

		if (c_seg->c_on_swappedout_q || c_seg->c_on_swappedout_sparse_q) {
			if (c_seg->c_ondisk)
				c_seg_swappedin = TRUE;
			c_seg_swapin(c_seg, FALSE);
		}		
		if (c_seg->c_store.c_buffer == NULL) {
			c_seg_has_data = FALSE;
			goto c_seg_invalid_data;
		}
#if CHECKSUM_THE_COMPRESSED_DATA
		if (cs->c_hash_compressed_data != hash_string((char *)&c_seg->c_store.c_buffer[cs->c_offset], c_size))
			panic("compressed data doesn't match original");
#endif
		if (c_rounded_size == PAGE_SIZE) {
			/*
			 * page wasn't compressible... just copy it out
			 */
			memcpy(dst, &c_seg->c_store.c_buffer[cs->c_offset], PAGE_SIZE);
		} else {
			uint32_t	my_cpu_no;
			char		*scratch_buf;

			/*
			 * we're behind the c_seg lock held in spin mode
			 * which means pre-emption is disabled... therefore
			 * the following sequence is atomic and safe
			 */
			my_cpu_no = cpu_number();

			assert(my_cpu_no < compressor_cpus);

			scratch_buf = &compressor_scratch_bufs[my_cpu_no * WKdm_SCRATCH_BUF_SIZE];
			WKdm_decompress_new((WK_word *)(uintptr_t)&c_seg->c_store.c_buffer[cs->c_offset],
					    (WK_word *)(uintptr_t)dst, (WK_word *)(uintptr_t)scratch_buf, c_size);
		}

#if CHECKSUM_THE_DATA
		if (cs->c_hash_data != hash_string(dst, PAGE_SIZE))
			panic("decompressed data doesn't match original");
#endif
		if (!c_seg->c_was_swapped_in) {

			clock_get_system_nanotime(&cur_ts_sec, &cur_ts_nsec);

			age_of_cseg = (uint32_t)cur_ts_sec - c_seg->c_creation_ts;

			if (age_of_cseg < DECOMPRESSION_SAMPLE_MAX_AGE)
				OSAddAtomic(1, &age_of_decompressions_during_sample_period[age_of_cseg]);
			else
				OSAddAtomic(1, &overage_decompressions_during_sample_period);

			OSAddAtomic(1, &sample_period_decompression_count);
		}
	} else {
		if (c_seg->c_store.c_buffer == NULL)
			c_seg_has_data = FALSE;
	}
c_seg_invalid_data:

	if (c_seg_has_data == TRUE) {
		if (c_seg_swappedin == TRUE)
			retval = 1;
		else
			retval = 0;
	} else
		retval = -1;

	if (flags & C_KEEP) {
		*zeroslot = 0;
		goto done;
	}
	c_seg->c_bytes_unused += c_rounded_size;
	c_seg->c_bytes_used -= c_rounded_size;
	PACK_C_SIZE(cs, 0);

	if (c_indx < c_seg->c_firstemptyslot)
		c_seg->c_firstemptyslot = c_indx;

	OSAddAtomic(-1, &c_segment_pages_compressed);

	if (c_seg_has_data == TRUE && !c_seg->c_ondisk) {
		/*
		 * c_ondisk == TRUE can occur when we're doing a
		 * free of a compressed page (i.e. dst == NULL)
		 */
		OSAddAtomic64(-c_rounded_size, &compressor_bytes_used);
	}
	if (!c_seg->c_filling) {
		if (c_seg->c_bytes_used == 0) {
			if (!c_seg->c_ondisk) {
				int	pages_populated;

				pages_populated = (round_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset))) / PAGE_SIZE;
				c_seg->c_populated_offset = C_SEG_BYTES_TO_OFFSET(0);

				if (pages_populated) {
					assert(c_seg->c_store.c_buffer != NULL);

					C_SEG_BUSY(c_seg);
					lck_mtx_unlock_always(&c_seg->c_lock);

					kernel_memory_depopulate(kernel_map, (vm_offset_t) c_seg->c_store.c_buffer, pages_populated * PAGE_SIZE, KMA_COMPRESSOR);

					lck_mtx_lock_spin_always(&c_seg->c_lock);
					C_SEG_WAKEUP_DONE(c_seg);
				}
				if (!c_seg->c_on_minorcompact_q && !c_seg->c_on_swapout_q)
					c_seg_need_delayed_compaction(c_seg);
			} else
				assert(c_seg->c_on_swappedout_sparse_q);

		} else if (c_seg->c_on_minorcompact_q) {

			if (C_SEG_INCORE_IS_SPARSE(c_seg)) {
				c_seg_try_minor_compaction_and_unlock(c_seg);
				need_unlock = FALSE;
			}
		} else if (!c_seg->c_ondisk) {

			if (c_seg_has_data == TRUE && !c_seg->c_on_swapout_q && C_SEG_UNUSED_BYTES(c_seg) >= PAGE_SIZE) {
				c_seg_need_delayed_compaction(c_seg);
			}
		} else if (!c_seg->c_on_swappedout_sparse_q && C_SEG_ONDISK_IS_SPARSE(c_seg)) {

			c_seg_move_to_sparse_list(c_seg);
			consider_defragmenting = TRUE;
		}
	}
done:
	if (need_unlock == TRUE)
		lck_mtx_unlock_always(&c_seg->c_lock);

	PAGE_REPLACEMENT_DISALLOWED(FALSE);

	if (consider_defragmenting == TRUE)
		vm_swap_consider_defragmenting();


	return (retval);
}


int
vm_compressor_get(ppnum_t pn, int *slot, int flags)
{
	char	*dst;
	int	zeroslot = 1;
	int	retval;

#if __x86_64__
	dst = PHYSMAP_PTOV((uint64_t)pn << (uint64_t)PAGE_SHIFT);
#else
#error "unsupported architecture"
#endif

	retval = c_decompress_page(dst, (c_slot_mapping_t)slot, flags, &zeroslot);

	/*
	 * zeroslot will be set to 0 by c_decompress_page if (flags & C_KEEP)
	 * or (flags & C_DONT_BLOCK) and we found 'c_busy' or 'c_ondisk' set
	 */
	if (zeroslot) {
		*slot = 0;
	}
	/*
	 * returns 0 if we successfully decompressed a page from a segment already in memory
	 * returns 1 if we had to first swap in the segment, before successfully decompressing the page
	 * returns -1 if we encountered an error swapping in the segment - decompression failed
	 * returns -2 if (flags & C_DONT_BLOCK) and we found 'c_busy' or 'c_ondisk' set
	 */
	return (retval);
}


int
vm_compressor_free(int *slot, int flags)
{
	int	zeroslot = 1;
	int	retval;

	assert(flags == 0 || flags == C_DONT_BLOCK);

	retval = c_decompress_page(NULL, (c_slot_mapping_t)slot, flags, &zeroslot);
	/*
	 * returns 0 if we successfully freed the specified compressed page
	 * returns -2 if (flags & C_DONT_BLOCK) and we found 'c_busy' set
	 */

	if (retval == 0)
		*slot = 0;

	return (retval);
}


int
vm_compressor_put(ppnum_t pn, int *slot, void  **current_chead, char *scratch_buf)
{
	char	*src;
	int	retval;

#if __x86_64__
	src = PHYSMAP_PTOV((uint64_t)pn << (uint64_t)PAGE_SHIFT);
#else
#error "unsupported architecture"
#endif
	retval = c_compress_page(src, (c_slot_mapping_t)slot, (c_segment_t *)current_chead, scratch_buf);

	return (retval);
}

void
vm_compressor_transfer(
	int	*dst_slot_p,
	int	*src_slot_p)
{
	c_slot_mapping_t	dst_slot, src_slot;
	c_segment_t		c_seg;
	int			c_indx;
	c_slot_t		cs;

	dst_slot = (c_slot_mapping_t) dst_slot_p;
	src_slot = (c_slot_mapping_t) src_slot_p;

Retry:
	PAGE_REPLACEMENT_DISALLOWED(TRUE);
	/* get segment for src_slot */
	c_seg = c_segments[src_slot->s_cseg -1].c_seg;
	/* lock segment */
	lck_mtx_lock_spin_always(&c_seg->c_lock);
	/* wait if it's busy */
	if (c_seg->c_busy) {
		PAGE_REPLACEMENT_DISALLOWED(FALSE);
		c_seg_wait_on_busy(c_seg);
		goto Retry;
	}
	/* find the c_slot */
	c_indx = src_slot->s_cindx;
	cs = C_SEG_SLOT_FROM_INDEX(c_seg, c_indx);
	/* point the c_slot back to dst_slot instead of src_slot */
	cs->c_packed_ptr = C_SLOT_PACK_PTR(dst_slot);
	/* transfer */
	*dst_slot_p = *src_slot_p;
	*src_slot_p = 0;
	lck_mtx_unlock_always(&c_seg->c_lock);
	PAGE_REPLACEMENT_DISALLOWED(FALSE);
}
