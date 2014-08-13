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

#include <kern/kalloc.h>
#include <vm/vm_compressor_pager.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_protos.h>
#include <vm/WKdm_new.h>
#include <vm/vm_object.h>
#include <machine/pmap.h>
#include <kern/locks.h>

#include <sys/kdebug.h>


#define C_SEG_OFFSET_BITS	16
#define C_SEG_BUFSIZE		(1024 * 256)
#define C_SEG_ALLOCSIZE		(C_SEG_BUFSIZE + PAGE_SIZE)
#define C_SEG_OFF_LIMIT		(C_SEG_BYTES_TO_OFFSET((C_SEG_BUFSIZE - 512)))

#define C_SEG_SLOT_ARRAYS	6
#define C_SEG_SLOT_ARRAY_SIZE	64		/* must be a power of 2 */
#define C_SEG_SLOT_ARRAY_MASK	(C_SEG_SLOT_ARRAY_SIZE - 1)
#define C_SLOT_MAX		(C_SEG_SLOT_ARRAYS * C_SEG_SLOT_ARRAY_SIZE)


#define CHECKSUM_THE_SWAP		0	/* Debug swap data */
#define CHECKSUM_THE_DATA		0	/* Debug compressor/decompressor data */
#define CHECKSUM_THE_COMPRESSED_DATA	0	/* Debug compressor/decompressor compressed data */
#define VALIDATE_C_SEGMENTS		0	/* Debug compaction */
#define TRACK_BAD_C_SEGMENTS		0	/* Debug I/O error handling */

struct c_segment {
#if __i386__ || __x86_64__
	lck_mtx_t	c_lock;
#else /* __i386__ || __x86_64__ */
	lck_spin_t	c_lock;
#endif /* __i386__ || __x86_64__ */
	queue_chain_t	c_age_list;
	queue_chain_t	c_list;

	uint64_t	c_generation_id;
	int32_t		c_bytes_used;
	int32_t		c_bytes_unused;
	
#define C_SEG_MAX_LIMIT		(1 << 19)	/* this needs to track the size of c_mysegno */
	uint32_t	c_mysegno:19,
		        c_filling:1,
		        c_busy:1,
		        c_busy_swapping:1,
			c_wanted:1,
		        c_must_free:1,
			c_ondisk:1,
		        c_was_swapped_in:1,
		        c_on_minorcompact_q:1,	/* can also be on the age_q or the swappedin_q */
		        c_on_age_q:1,		/* creation age ordered list of in-core segments that
						   are available to be major-compacted and swapped out */
		        c_on_swappedin_q:1,	/* allows us to age newly swapped in segments */
		        c_on_swapout_q:1,	/* this is a transient queue */
		        c_on_swappedout_q:1,	/* segment has been major-compacted and
						   possibly swapped out to disk (c_ondisk == 1) */
		        c_on_swappedout_sparse_q:1;	/* segment has become sparse and should be garbage
							   collected if too many segments reach this state */
	uint16_t	c_firstemptyslot;
	uint16_t	c_nextslot;
	uint32_t	c_nextoffset;
	uint32_t	c_populated_offset;

	uint32_t	c_creation_ts;
	uint32_t	c_swappedin_ts;

	union {
		int32_t *c_buffer;
		uint64_t c_swap_handle;
	} c_store;

#if TRACK_BAD_C_SEGMENTS
	uint32_t	c_on_bad_q;
#endif

#if 	VALIDATE_C_SEGMENTS
        uint32_t	c_was_minor_compacted;
        uint32_t	c_was_major_compacted;
	uint32_t	c_was_major_donor;
#endif
#if CHECKSUM_THE_SWAP	
	unsigned int	cseg_hash;
	unsigned int	cseg_swap_size;
#endif /* CHECKSUM_THE_SWAP */

	struct c_slot	*c_slots[C_SEG_SLOT_ARRAYS];
};


#define C_SEG_SLOT_FROM_INDEX(cseg, index)	(&(cseg->c_slots[index / C_SEG_SLOT_ARRAY_SIZE])[index & C_SEG_SLOT_ARRAY_MASK])
#define C_SEG_SLOTARRAY_FROM_INDEX(cseg, index)	(index / C_SEG_SLOT_ARRAY_SIZE)

#define	C_SEG_OFFSET_TO_BYTES(off)	((off) * (int) sizeof(int32_t))
#define C_SEG_BYTES_TO_OFFSET(bytes)	((bytes) / (int) sizeof(int32_t))

#define C_SEG_UNUSED_BYTES(cseg)	(cseg->c_bytes_unused + (C_SEG_OFFSET_TO_BYTES(cseg->c_populated_offset - cseg->c_nextoffset)))

#define C_SEG_OFFSET_ALIGNMENT_MASK	0x3

#define	C_SEG_ONDISK_IS_SPARSE(cseg)	((cseg->c_bytes_used < (C_SEG_BUFSIZE / 2)) ? 1 : 0)
#define C_SEG_INCORE_IS_SPARSE(cseg)	((C_SEG_UNUSED_BYTES(cseg) >= (C_SEG_BUFSIZE / 2)) ? 1 : 0)

#define C_SEG_WAKEUP_DONE(cseg)				\
	MACRO_BEGIN					\
	(cseg)->c_busy = 0;				\
	if ((cseg)->c_wanted) {				\
		(cseg)->c_wanted = 0;			\
		thread_wakeup((event_t) (cseg));	\
	}						\
	MACRO_END


typedef	struct c_segment *c_segment_t;
typedef struct c_slot	*c_slot_t;

uint64_t vm_compressor_total_compressions(void);
void vm_wake_compactor_swapper(void);
void vm_consider_waking_compactor_swapper(void);
void vm_compressor_flush(void);
void c_seg_free(c_segment_t);
void c_seg_free_locked(c_segment_t);
void c_seg_insert_into_age_q(c_segment_t);

void vm_decompressor_lock(void);
void vm_decompressor_unlock(void);

void vm_compressor_delay_trim(void);
void vm_compressor_do_warmup(void);
void vm_compressor_record_warmup_start(void);
void vm_compressor_record_warmup_end(void);

int			vm_low_on_space(void);
boolean_t		vm_compression_available(void);

extern void		vm_compressor_init_locks(void);
extern lck_rw_t		c_master_lock;

#if CRYPTO
extern void		vm_swap_decrypt(c_segment_t);
#endif /* CRYPTO */

extern kern_return_t	vm_swap_get(vm_offset_t, uint64_t, uint64_t);
extern void		vm_swap_free(uint64_t);
extern void		vm_swap_consider_defragmenting(void);

extern void		c_seg_swapin_requeue(c_segment_t);
extern void		c_seg_swapin(c_segment_t, boolean_t);
extern void		c_seg_wait_on_busy(c_segment_t);
extern void		c_seg_trim_tail(c_segment_t);

extern boolean_t	fastwake_recording_in_progress;
extern int		compaction_swapper_running;
extern uint64_t		vm_swap_put_failures;

extern queue_head_t	c_minor_list_head;
extern queue_head_t	c_age_list_head;
extern queue_head_t	c_swapout_list_head;
extern queue_head_t	c_swappedout_list_head;
extern queue_head_t	c_swappedout_sparse_list_head;

extern uint32_t		c_age_count;
extern uint32_t		c_swapout_count;
extern uint32_t		c_swappedout_count;
extern uint32_t		c_swappedout_sparse_count;

extern int64_t		compressor_bytes_used;
extern uint64_t		first_c_segment_to_warm_generation_id;
extern uint64_t		last_c_segment_to_warm_generation_id;
extern boolean_t	hibernate_flushing;
extern boolean_t	hibernate_no_swapspace;
extern uint32_t		swapout_target_age;

extern void c_seg_insert_into_q(queue_head_t *, c_segment_t);

extern uint32_t	vm_compressor_minorcompact_threshold_divisor;
extern uint32_t	vm_compressor_majorcompact_threshold_divisor;
extern uint32_t	vm_compressor_unthrottle_threshold_divisor;
extern uint32_t	vm_compressor_catchup_threshold_divisor;

#define PAGE_REPLACEMENT_DISALLOWED(enable)	(enable == TRUE ? lck_rw_lock_shared(&c_master_lock) : lck_rw_done(&c_master_lock))
#define PAGE_REPLACEMENT_ALLOWED(enable)	(enable == TRUE ? lck_rw_lock_exclusive(&c_master_lock) : lck_rw_done(&c_master_lock))


#define AVAILABLE_NON_COMPRESSED_MEMORY		(vm_page_active_count + vm_page_inactive_count + vm_page_free_count + vm_page_speculative_count)
#define AVAILABLE_MEMORY			(AVAILABLE_NON_COMPRESSED_MEMORY + VM_PAGE_COMPRESSOR_COUNT)

#define	VM_PAGE_COMPRESSOR_COMPACT_THRESHOLD		(((AVAILABLE_MEMORY) * 10) / (vm_compressor_minorcompact_threshold_divisor ? vm_compressor_minorcompact_threshold_divisor : 1))
#define	VM_PAGE_COMPRESSOR_SWAP_THRESHOLD		(((AVAILABLE_MEMORY) * 10) / (vm_compressor_majorcompact_threshold_divisor ? vm_compressor_majorcompact_threshold_divisor : 1))
#define	VM_PAGE_COMPRESSOR_SWAP_UNTHROTTLE_THRESHOLD	(((AVAILABLE_MEMORY) * 10) / (vm_compressor_unthrottle_threshold_divisor ? vm_compressor_unthrottle_threshold_divisor : 1))
#define VM_PAGE_COMPRESSOR_SWAP_CATCHUP_THRESHOLD	(((AVAILABLE_MEMORY) * 10) / (vm_compressor_catchup_threshold_divisor ? vm_compressor_catchup_threshold_divisor : 1))

#define COMPRESSOR_NEEDS_TO_SWAP() 		((AVAILABLE_NON_COMPRESSED_MEMORY < VM_PAGE_COMPRESSOR_SWAP_THRESHOLD) ? 1 : 0)

#define VM_PAGEOUT_SCAN_NEEDS_TO_THROTTLE()				\
	((vm_compressor_mode == VM_PAGER_COMPRESSOR_WITH_SWAP ||	\
	  vm_compressor_mode == VM_PAGER_FREEZER_COMPRESSOR_WITH_SWAP) && \
	 ((AVAILABLE_NON_COMPRESSED_MEMORY < VM_PAGE_COMPRESSOR_SWAP_CATCHUP_THRESHOLD) ? 1 : 0))
#define HARD_THROTTLE_LIMIT_REACHED()		((AVAILABLE_NON_COMPRESSED_MEMORY < (VM_PAGE_COMPRESSOR_SWAP_UNTHROTTLE_THRESHOLD) / 2) ? 1 : 0)
#define SWAPPER_NEEDS_TO_UNTHROTTLE()		((AVAILABLE_NON_COMPRESSED_MEMORY < VM_PAGE_COMPRESSOR_SWAP_UNTHROTTLE_THRESHOLD) ? 1 : 0)
#define COMPRESSOR_NEEDS_TO_MINOR_COMPACT()	((AVAILABLE_NON_COMPRESSED_MEMORY < VM_PAGE_COMPRESSOR_COMPACT_THRESHOLD) ? 1 : 0)
#define COMPRESSOR_NEEDS_TO_MAJOR_COMPACT()	((AVAILABLE_NON_COMPRESSED_MEMORY < VM_PAGE_COMPRESSOR_SWAP_THRESHOLD) ? 1 : 0)

#define COMPRESSOR_FREE_RESERVED_LIMIT		28

/*
 * Upward trajectory.
 */
extern boolean_t vm_compressor_low_on_space(void);

#define VM_PRESSURE_NORMAL_TO_WARNING()		((AVAILABLE_NON_COMPRESSED_MEMORY < VM_PAGE_COMPRESSOR_COMPACT_THRESHOLD) ? 1 : 0)
#define VM_PRESSURE_WARNING_TO_CRITICAL()	(vm_compressor_low_on_space() || (AVAILABLE_NON_COMPRESSED_MEMORY < ((12 * VM_PAGE_COMPRESSOR_SWAP_UNTHROTTLE_THRESHOLD) / 10)) ? 1 : 0)

/*
 * Downward trajectory.
 */
#define VM_PRESSURE_WARNING_TO_NORMAL()		((AVAILABLE_NON_COMPRESSED_MEMORY > ((12 * VM_PAGE_COMPRESSOR_COMPACT_THRESHOLD) / 10)) ? 1 : 0)
#define VM_PRESSURE_CRITICAL_TO_WARNING()	((AVAILABLE_NON_COMPRESSED_MEMORY > ((14 * VM_PAGE_COMPRESSOR_SWAP_UNTHROTTLE_THRESHOLD) / 10)) ? 1 : 0)

#define COMPRESSOR_SCRATCH_BUF_SIZE WKdm_SCRATCH_BUF_SIZE


#if __i386__ || __x86_64__
extern lck_mtx_t	*c_list_lock;
#else /* __i386__ || __x86_64__ */
extern lck_spin_t	*c_list_lock;
#endif /* __i386__ || __x86_64__ */
