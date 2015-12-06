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
#define	C_SEG_MAX_PAGES		(C_SEG_BUFSIZE / PAGE_SIZE)

#define C_SEG_OFF_LIMIT		(C_SEG_BYTES_TO_OFFSET((C_SEG_BUFSIZE - 128)))
#define C_SEG_ALLOCSIZE		(C_SEG_BUFSIZE)
#define C_SEG_MAX_POPULATE_SIZE	(4 * PAGE_SIZE)


#define CHECKSUM_THE_SWAP		0	/* Debug swap data */
#define CHECKSUM_THE_DATA		0	/* Debug compressor/decompressor data */
#define CHECKSUM_THE_COMPRESSED_DATA	0	/* Debug compressor/decompressor compressed data */
#define VALIDATE_C_SEGMENTS		0	/* Debug compaction */

#define RECORD_THE_COMPRESSED_DATA	0



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

#define	C_IS_EMPTY		0
#define	C_IS_FREE		1
#define	C_IS_FILLING		2
#define C_ON_AGE_Q		3
#define C_ON_SWAPOUT_Q		4
#define C_ON_SWAPPEDOUT_Q	5
#define	C_ON_SWAPPEDOUTSPARSE_Q	6
#define	C_ON_SWAPPEDIN_Q	7
#define	C_ON_MAJORCOMPACT_Q	8
#define	C_ON_BAD_Q		9


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
		        c_busy:1,
		        c_busy_swapping:1,
			c_wanted:1,
		        c_on_minorcompact_q:1,	/* can also be on the age_q, the majorcompact_q or the swappedin_q */

		        c_state:4,		/* what state is the segment in which dictates which q to find it on */
		        c_overage_swap:1,
		        c_reserved:4;

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

#if 	VALIDATE_C_SEGMENTS
        uint32_t	c_was_minor_compacted;
        uint32_t	c_was_major_compacted;
	uint32_t	c_was_major_donor;
#endif
#if CHECKSUM_THE_SWAP	
	unsigned int	cseg_hash;
	unsigned int	cseg_swap_size;
#endif /* CHECKSUM_THE_SWAP */

#if MACH_ASSERT
	thread_t	c_busy_for_thread;
#endif /* MACH_ASSERT */

	int		c_slot_var_array_len;
	struct	c_slot	*c_slot_var_array;
	struct	c_slot	c_slot_fixed_array[0];
};

#define C_SEG_SLOT_VAR_ARRAY_MIN_LEN	C_SEG_MAX_PAGES

extern	int		c_seg_fixed_array_len;
extern	vm_offset_t	c_buffers;
#define	C_SEG_BUFFER_ADDRESS(c_segno)	((c_buffers + ((uint64_t)c_segno * (uint64_t)C_SEG_ALLOCSIZE)))

#define C_SEG_SLOT_FROM_INDEX(cseg, index)	(index < c_seg_fixed_array_len ? &(cseg->c_slot_fixed_array[index]) : &(cseg->c_slot_var_array[index - c_seg_fixed_array_len]))

#define	C_SEG_OFFSET_TO_BYTES(off)	((off) * (int) sizeof(int32_t))
#define C_SEG_BYTES_TO_OFFSET(bytes)	((bytes) / (int) sizeof(int32_t))

#define C_SEG_UNUSED_BYTES(cseg)	(cseg->c_bytes_unused + (C_SEG_OFFSET_TO_BYTES(cseg->c_populated_offset - cseg->c_nextoffset)))

#define C_SEG_OFFSET_ALIGNMENT_MASK	0x3

#define	C_SEG_ONDISK_IS_SPARSE(cseg)	((cseg->c_bytes_used < (C_SEG_BUFSIZE / 2)) ? 1 : 0)
#define C_SEG_SHOULD_MINORCOMPACT(cseg)	((C_SEG_UNUSED_BYTES(cseg) >= (C_SEG_BUFSIZE / 3)) ? 1 : 0)
#define C_SEG_SHOULD_MAJORCOMPACT(cseg)	(((cseg->c_bytes_unused + (C_SEG_BUFSIZE - C_SEG_OFFSET_TO_BYTES(c_seg->c_nextoffset))) >= (C_SEG_BUFSIZE / 8)) ? 1 : 0)

#define C_SEG_IS_ONDISK(cseg)		((cseg->c_state == C_ON_SWAPPEDOUT_Q || cseg->c_state == C_ON_SWAPPEDOUTSPARSE_Q))


#define C_SEG_WAKEUP_DONE(cseg)				\
	MACRO_BEGIN					\
	assert((cseg)->c_busy);				\
	(cseg)->c_busy = 0;				\
	assert((cseg)->c_busy_for_thread != NULL);	\
	assert((((cseg)->c_busy_for_thread = NULL), TRUE));	\
	if ((cseg)->c_wanted) {				\
		(cseg)->c_wanted = 0;			\
		thread_wakeup((event_t) (cseg));	\
	}						\
	MACRO_END

#define C_SEG_BUSY(cseg)				\
	MACRO_BEGIN					\
	assert((cseg)->c_busy == 0);			\
	(cseg)->c_busy = 1;				\
	assert((cseg)->c_busy_for_thread == NULL);	\
	assert((((cseg)->c_busy_for_thread = current_thread()), TRUE));	\
	MACRO_END
	


typedef	struct c_segment *c_segment_t;
typedef struct c_slot	*c_slot_t;

uint64_t vm_compressor_total_compressions(void);
void vm_wake_compactor_swapper(void);
void vm_thrashing_jetsam_done(void);
void vm_consider_waking_compactor_swapper(void);
void vm_consider_swapping(void);
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

int			vm_wants_task_throttled(task_t);
boolean_t		vm_compression_available(void);

extern void		vm_compressor_swap_init(void);
extern void		vm_compressor_init_locks(void);
extern lck_rw_t		c_master_lock;

#if ENCRYPTED_SWAP
extern void		vm_swap_decrypt(c_segment_t);
#endif /* ENCRYPTED_SWAP */

extern int		vm_swap_low_on_space(void);
extern kern_return_t	vm_swap_get(vm_offset_t, uint64_t, uint64_t);
extern void		vm_swap_free(uint64_t);
extern void		vm_swap_consider_defragmenting(void);

extern void		c_seg_swapin_requeue(c_segment_t, boolean_t);
extern void		c_seg_swapin(c_segment_t, boolean_t);
extern void		c_seg_wait_on_busy(c_segment_t);
extern void		c_seg_trim_tail(c_segment_t);
extern void		c_seg_switch_state(c_segment_t, int, boolean_t);

extern boolean_t	fastwake_recording_in_progress;
extern int		compaction_swapper_running;
extern uint64_t		vm_swap_put_failures;

extern int		c_overage_swapped_count;
extern int		c_overage_swapped_limit;

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
extern uint64_t vm_compressor_compute_elapsed_msecs(clock_sec_t, clock_nsec_t, clock_sec_t, clock_nsec_t);

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
	(vm_compressor_mode == VM_PAGER_COMPRESSOR_WITH_SWAP &&		\
	 ((AVAILABLE_NON_COMPRESSED_MEMORY < VM_PAGE_COMPRESSOR_SWAP_CATCHUP_THRESHOLD) ? 1 : 0))
#define HARD_THROTTLE_LIMIT_REACHED()		((AVAILABLE_NON_COMPRESSED_MEMORY < (VM_PAGE_COMPRESSOR_SWAP_UNTHROTTLE_THRESHOLD) / 2) ? 1 : 0)
#define SWAPPER_NEEDS_TO_UNTHROTTLE()		((AVAILABLE_NON_COMPRESSED_MEMORY < VM_PAGE_COMPRESSOR_SWAP_UNTHROTTLE_THRESHOLD) ? 1 : 0)
#define COMPRESSOR_NEEDS_TO_MINOR_COMPACT()	((AVAILABLE_NON_COMPRESSED_MEMORY < VM_PAGE_COMPRESSOR_COMPACT_THRESHOLD) ? 1 : 0)

/*
 * indicate the need to do a major compaction if
 * the overall set of in-use compression segments
 * becomes sparse... on systems that support pressure
 * driven swapping, this will also cause swapouts to
 * be initiated.
 */
#define COMPRESSOR_NEEDS_TO_MAJOR_COMPACT()	(((c_segment_count >= (c_segments_nearing_limit / 8)) && \
						  ((c_segment_count * C_SEG_MAX_PAGES) - VM_PAGE_COMPRESSOR_COUNT) > \
						  ((c_segment_count / 8) * C_SEG_MAX_PAGES)) \
						 ? 1 : 0)

#define COMPRESSOR_FREE_RESERVED_LIMIT		128

#define COMPRESSOR_SCRATCH_BUF_SIZE WKdm_SCRATCH_BUF_SIZE


#if RECORD_THE_COMPRESSED_DATA
extern void 	 c_compressed_record_init(void);
extern void 	 c_compressed_record_write(char *, int);
#endif


#if __i386__ || __x86_64__
extern lck_mtx_t	*c_list_lock;
#else /* __i386__ || __x86_64__ */
extern lck_spin_t	*c_list_lock;
#endif /* __i386__ || __x86_64__ */
