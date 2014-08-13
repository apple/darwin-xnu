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

#include "vm_compressor_backing_store.h"
#include <vm/vm_protos.h>

#include <IOKit/IOHibernatePrivate.h>


boolean_t	compressor_store_stop_compaction = FALSE;
boolean_t	vm_swap_up = FALSE;
boolean_t	vm_swapfile_mgmt_needed = FALSE;

int		swapper_throttle = -1;
boolean_t	swapper_throttle_inited = FALSE;
uint64_t	vm_swapout_thread_id;

uint64_t	vm_swap_put_failures = 0;
uint64_t	vm_swap_get_failures = 0;
int		vm_num_swap_files = 0;
int		vm_swapout_thread_processed_segments = 0;
int		vm_swapout_thread_awakened = 0;
int		vm_swapfile_mgmt_thread_awakened = 0;
int		vm_swapfile_mgmt_thread_running = 0;

unsigned int	vm_swapfile_total_segs_alloced = 0;
unsigned int	vm_swapfile_total_segs_used = 0;


#define SWAP_READY	0x1	/* Swap file is ready to be used */
#define SWAP_RECLAIM	0x2	/* Swap file is marked to be reclaimed */
#define SWAP_WANTED	0x4	/* Swap file has waiters */
#define SWAP_REUSE	0x8	/* Swap file is on the Q and has a name. Reuse after init-ing.*/

struct swapfile{
	queue_head_t		swp_queue;	/* list of swap files */
	char			*swp_path;	/* saved pathname of swap file */
	struct vnode		*swp_vp;	/* backing vnode */
	uint64_t		swp_size;	/* size of this swap file */
	uint8_t			*swp_bitmap;	/* bitmap showing the alloced/freed slots in the swap file */
	unsigned int		swp_pathlen;	/* length of pathname */
	unsigned int		swp_nsegs;	/* #segments we can use */
	unsigned int		swp_nseginuse;	/* #segments in use */
	unsigned int		swp_index;	/* index of this swap file */
	unsigned int		swp_flags;	/* state of swap file */
	unsigned int		swp_free_hint;	/* offset of 1st free chunk */
	unsigned int		swp_io_count;	/* count of outstanding I/Os */
	c_segment_t		*swp_csegs;	/* back pointers to the c_segments. Used during swap reclaim. */

	struct trim_list	*swp_delayed_trim_list_head;
	unsigned int		swp_delayed_trim_count;
	boolean_t		swp_trim_supported;
};

queue_head_t	swf_global_queue;

#define		VM_SWAPFILE_DELAYED_TRIM_MAX	128

extern clock_sec_t	dont_trim_until_ts;
clock_sec_t		vm_swapfile_last_failed_to_create_ts = 0;

static void vm_swapout_thread_throttle_adjust(void);
static void vm_swap_free_now(struct swapfile *swf, uint64_t f_offset);
static void vm_swapout_thread(void);
static void vm_swapfile_mgmt_thread(void);
static void vm_swap_defragment();
static void vm_swap_handle_delayed_trims(boolean_t);
static void vm_swap_do_delayed_trim();


#define	VM_SWAPFILE_DELAYED_CREATE	30
#define	VM_SWAP_SHOULD_DEFRAGMENT()	(c_swappedout_sparse_count > (vm_swapfile_total_segs_used / 4) ? 1 : 0)
#define VM_SWAP_SHOULD_RECLAIM()	(((vm_swapfile_total_segs_alloced - vm_swapfile_total_segs_used) >= SWAPFILE_RECLAIM_THRESHOLD_SEGS) ? 1 : 0)
#define VM_SWAP_SHOULD_CREATE(cur_ts)	(((vm_swapfile_total_segs_alloced - vm_swapfile_total_segs_used) < (unsigned int)VM_SWAPFILE_HIWATER_SEGS) && \
					 ((cur_ts - vm_swapfile_last_failed_to_create_ts) > VM_SWAPFILE_DELAYED_CREATE) ? 1 : 0)
#define VM_SWAP_SHOULD_TRIM(swf)	((swf->swp_delayed_trim_count >= VM_SWAPFILE_DELAYED_TRIM_MAX) ? 1 : 0)


#define VM_SWAP_BUSY()	((c_swapout_count && (swapper_throttle == THROTTLE_LEVEL_COMPRESSOR_TIER1 || swapper_throttle == THROTTLE_LEVEL_COMPRESSOR_TIER0)) ? 1 : 0)


#if CHECKSUM_THE_SWAP
extern unsigned int hash_string(char *cp, int len);
#endif

#if CRYPTO
extern boolean_t		swap_crypt_ctx_initialized;
extern void 			swap_crypt_ctx_initialize(void);
extern const unsigned char	swap_crypt_null_iv[AES_BLOCK_SIZE];
extern aes_ctx			swap_crypt_ctx;
extern unsigned long 		vm_page_encrypt_counter;
extern unsigned long 		vm_page_decrypt_counter;
#endif /* CRYPTO */

extern void			vm_pageout_io_throttle(void);

struct swapfile *vm_swapfile_for_handle(uint64_t);

/*
 * Called with the vm_swap_data_lock held.
 */ 

struct swapfile *
vm_swapfile_for_handle(uint64_t f_offset) 
{
	
	uint64_t		file_offset = 0;
	unsigned int		swapfile_index = 0;
	struct swapfile*	swf = NULL;

	file_offset = (f_offset & SWAP_SLOT_MASK);	
	swapfile_index = (f_offset >> SWAP_DEVICE_SHIFT);

	swf = (struct swapfile*) queue_first(&swf_global_queue);

	while(queue_end(&swf_global_queue, (queue_entry_t)swf) == FALSE) {

		if (swapfile_index == swf->swp_index) {
			break;
		}

		swf = (struct swapfile*) queue_next(&swf->swp_queue);
	}

	if (queue_end(&swf_global_queue, (queue_entry_t) swf)) {
		swf = NULL;
	}

	return swf;
}

void
vm_swap_init()
{
	static boolean_t vm_swap_try_init = FALSE;
	thread_t	thread = NULL;

	if (vm_swap_try_init == TRUE) {
		return;
	}

	vm_swap_try_init = TRUE;

	lck_grp_attr_setdefault(&vm_swap_data_lock_grp_attr);
	lck_grp_init(&vm_swap_data_lock_grp,
		     "vm_swap_data",
		     &vm_swap_data_lock_grp_attr);
	lck_attr_setdefault(&vm_swap_data_lock_attr);
	lck_mtx_init_ext(&vm_swap_data_lock,
			 &vm_swap_data_lock_ext,
			 &vm_swap_data_lock_grp,
			 &vm_swap_data_lock_attr);

	queue_init(&swf_global_queue);

	if (vm_swap_create_file()) {
	
		if (kernel_thread_start_priority((thread_continue_t)vm_swapout_thread, NULL,
					 BASEPRI_PREEMPT - 1, &thread) != KERN_SUCCESS) {
			panic("vm_swapout_thread: create failed");
		}
		thread->options |= TH_OPT_VMPRIV;
		vm_swapout_thread_id = thread->thread_id;

		thread_deallocate(thread);

		if (kernel_thread_start_priority((thread_continue_t)vm_swapfile_mgmt_thread, NULL,
					 BASEPRI_PREEMPT - 1, &thread) != KERN_SUCCESS) {
			panic("vm_swapfile_mgmt_thread: create failed");
		}
		thread->options |= TH_OPT_VMPRIV;

		thread_deallocate(thread);
	
#if CRYPTO
		if (swap_crypt_ctx_initialized == FALSE) {
			swap_crypt_ctx_initialize();
		}
#endif /* CRYPTO */
		
		vm_swap_up = TRUE;

#if SANITY_CHECK_SWAP_ROUTINES
extern lck_attr_t	*vm_compressor_lck_attr;
extern lck_grp_t	*vm_compressor_lck_grp;

		/*
		 * Changes COMPRESSED_SWAP_CHUNK_SIZE to make it (4*KB).
		 * Changes MIN_SWAP_FILE_SIZE to (4*KB).
		 * Changes MAX_SWAP_FILE_SIZE to (4*KB).
		 * That will then cause the below allocations to create
		 * 4 new swap files and put/get/free from them.
		 */
		{
			c_segment_t	c_seg = NULL, c_seg1 = NULL, c_seg2 = NULL, c_seg3 = NULL;
			vm_offset_t	addr = 0;
			vm_offset_t	dup_addr = 0;
			kern_return_t	kr = KERN_SUCCESS;
			uint64_t	f_offset = 0;
			uint64_t	f_offset1 = 0;
			uint64_t	f_offset2 = 0;
			uint64_t	f_offset3 = 0;

			if ((kr = kernel_memory_allocate(kernel_map,
						&addr,
						4 * COMPRESSED_SWAP_CHUNK_SIZE,
						0,
						KMA_KOBJECT))) {
				printf("kernel_memory_allocate failed with %d\n", kr);
				goto done;
			}

			if ((kr = kernel_memory_allocate(kernel_map,
						&dup_addr,
						4 * COMPRESSED_SWAP_CHUNK_SIZE,
						0,
						KMA_KOBJECT))) {
				printf("kernel_memory_allocate failed with %d\n", kr);
				goto done;
			}

			c_seg = (c_segment_t) kalloc(sizeof(*c_seg));
			memset(c_seg, 0, sizeof(*c_seg));
#if __i386__ || __x86_64__
			lck_mtx_init(&c_seg->c_lock, vm_compressor_lck_grp, vm_compressor_lck_attr);
#else /* __i386__ || __x86_64__ */
			lck_spin_init(&c_seg->c_lock, vm_compressor_lck_grp, vm_compressor_lck_attr);
#endif /* __i386__ || __x86_64__ */
	

			c_seg1 = (c_segment_t) kalloc(sizeof(*c_seg));
			memset(c_seg1, 0, sizeof(*c_seg));
#if __i386__ || __x86_64__
			lck_mtx_init(&c_seg1->c_lock, vm_compressor_lck_grp, vm_compressor_lck_attr);
#else /* __i386__ || __x86_64__ */
			lck_spin_init(&c_seg1->c_lock, vm_compressor_lck_grp, vm_compressor_lck_attr);
#endif /* __i386__ || __x86_64__ */
	

			c_seg2 = (c_segment_t) kalloc(sizeof(*c_seg));
			memset(c_seg2, 0, sizeof(*c_seg));
#if __i386__ || __x86_64__
			lck_mtx_init(&c_seg2->c_lock, vm_compressor_lck_grp, vm_compressor_lck_attr);
#else /* __i386__ || __x86_64__ */
			lck_spin_init(&c_seg2->c_lock, vm_compressor_lck_grp, vm_compressor_lck_attr);
#endif /* __i386__ || __x86_64__ */
	

			c_seg3 = (c_segment_t) kalloc(sizeof(*c_seg));
			memset(c_seg3, 0, sizeof(*c_seg));
#if __i386__ || __x86_64__
			lck_mtx_init(&c_seg3->c_lock, vm_compressor_lck_grp, vm_compressor_lck_attr);
#else /* __i386__ || __x86_64__ */
			lck_spin_init(&c_seg3->c_lock, vm_compressor_lck_grp, vm_compressor_lck_attr);
#endif /* __i386__ || __x86_64__ */
	

			memset((void*)addr,  (int) 'a', PAGE_SIZE_64);
			memset((void*)(addr + PAGE_SIZE_64),  (int) 'b', PAGE_SIZE_64);
			memset((void*)(addr + (2 * PAGE_SIZE_64)),  (int) 'c', PAGE_SIZE_64);
			memset((void*)(addr + (3 * PAGE_SIZE_64)),  (int) 'd', PAGE_SIZE_64);

			vm_swap_put(addr, &f_offset, PAGE_SIZE_64, c_seg);
			c_seg->c_store.c_swap_handle = f_offset;

			vm_swap_put(addr + PAGE_SIZE_64, &f_offset1, PAGE_SIZE_64, c_seg1);
			c_seg1->c_store.c_swap_handle = f_offset1;

			vm_swap_put(addr + (2 * PAGE_SIZE_64), &f_offset2, PAGE_SIZE_64, c_seg2);
			c_seg2->c_store.c_swap_handle = f_offset2;

			vm_swap_put(addr + (3 * PAGE_SIZE_64), &f_offset3, PAGE_SIZE_64, c_seg3);
			c_seg3->c_store.c_swap_handle = f_offset3;
	
			//vm_swap_free(f_offset);
			vm_swap_get(dup_addr, f_offset, PAGE_SIZE_64);

			//vm_swap_free(f_offset1);
			vm_swap_reclaim();
			vm_swap_get(dup_addr + PAGE_SIZE_64, c_seg1->c_store.c_swap_handle, PAGE_SIZE_64);

			//vm_swap_free(f_offset2);
			vm_swap_reclaim();
			vm_swap_get(dup_addr + (2 * PAGE_SIZE_64), c_seg2->c_store.c_swap_handle, PAGE_SIZE_64);

			//vm_swap_free(f_offset3);
			vm_swap_reclaim();
			vm_swap_get(dup_addr + (3 * PAGE_SIZE_64), c_seg3->c_store.c_swap_handle, PAGE_SIZE_64);

			if (memcmp((void*)addr, (void*)dup_addr, PAGE_SIZE_64)) {
				panic("First page data mismatch\n");
				kr = KERN_FAILURE;
				goto done;
			}

			if (memcmp((void*)(addr + PAGE_SIZE_64), (void*)(dup_addr + PAGE_SIZE_64), PAGE_SIZE_64)) {
				panic("Second page data mismatch 0x%lx, 0x%lxn", addr, dup_addr);
				kr = KERN_FAILURE;
				goto done;
			}

			if (memcmp((void*)(addr + (2 * PAGE_SIZE_64)), (void*)(dup_addr + (2 * PAGE_SIZE_64)), PAGE_SIZE_64)) {
				panic("Third page data mismatch\n");
				kr = KERN_FAILURE;
				goto done;
			}

			if (memcmp((void*)(addr + (3 * PAGE_SIZE_64)), (void*)(dup_addr + (3 * PAGE_SIZE_64)), PAGE_SIZE_64)) {
				panic("Fourth page data mismatch 0x%lx, 0x%lxn", addr, dup_addr);
				kr = KERN_FAILURE;
				goto done;
			}

done:
			printf("Sanity check %s\n", ((kr != KERN_SUCCESS) ? "FAILED" : "SUCCEEDED"));
			kfree((void*)addr, 4 * COMPRESSED_SWAP_CHUNK_SIZE);
			addr = 0;
			kfree((void*)dup_addr, 4 * COMPRESSED_SWAP_CHUNK_SIZE);
			dup_addr = 0;
		}
#endif /* SANITY_CHECK_SWAP_ROUTINES */
	}
		
	printf("VM Swap Subsystem is %s\n", (vm_swap_up == TRUE) ? "ON" : "OFF"); 
}

#if CRYPTO
void
vm_swap_encrypt(c_segment_t c_seg)
{
	vm_offset_t	kernel_vaddr = 0;
	uint64_t	size = 0;

	union {
		unsigned char	aes_iv[AES_BLOCK_SIZE];
		void		*c_seg;
	} encrypt_iv;
	
	assert(swap_crypt_ctx_initialized);
	
	bzero(&encrypt_iv.aes_iv[0], sizeof (encrypt_iv.aes_iv));

	encrypt_iv.c_seg = (void*)c_seg;

	/* encrypt the "initial vector" */
	aes_encrypt_cbc((const unsigned char *) &encrypt_iv.aes_iv[0],
			swap_crypt_null_iv,
			1,
			&encrypt_iv.aes_iv[0],
			&swap_crypt_ctx.encrypt);

	kernel_vaddr = (vm_offset_t) c_seg->c_store.c_buffer;
	size = round_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset));

	/*
	 * Encrypt the c_segment.
	 */
	aes_encrypt_cbc((const unsigned char *) kernel_vaddr,
			&encrypt_iv.aes_iv[0],
			(unsigned int)(size / AES_BLOCK_SIZE),
			(unsigned char *) kernel_vaddr,
			&swap_crypt_ctx.encrypt);

	vm_page_encrypt_counter += (size/PAGE_SIZE_64);
}

void
vm_swap_decrypt(c_segment_t c_seg)
{

	vm_offset_t	kernel_vaddr = 0;
	uint64_t	size = 0;

	union {
		unsigned char	aes_iv[AES_BLOCK_SIZE];
		void		*c_seg;
	} decrypt_iv;
	
	
	assert(swap_crypt_ctx_initialized);

	/*
	 * Prepare an "initial vector" for the decryption.
	 * It has to be the same as the "initial vector" we
	 * used to encrypt that page.
	 */
	bzero(&decrypt_iv.aes_iv[0], sizeof (decrypt_iv.aes_iv));

	decrypt_iv.c_seg = (void*)c_seg;

	/* encrypt the "initial vector" */
	aes_encrypt_cbc((const unsigned char *) &decrypt_iv.aes_iv[0],
			swap_crypt_null_iv,
			1,
			&decrypt_iv.aes_iv[0],
			&swap_crypt_ctx.encrypt);
	
	kernel_vaddr = (vm_offset_t) c_seg->c_store.c_buffer;
	size = round_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset));

	/*
	 * Decrypt the c_segment.
	 */
	aes_decrypt_cbc((const unsigned char *) kernel_vaddr,
			&decrypt_iv.aes_iv[0],
			(unsigned int) (size / AES_BLOCK_SIZE),
			(unsigned char *) kernel_vaddr,
			&swap_crypt_ctx.decrypt);

	vm_page_decrypt_counter += (size/PAGE_SIZE_64);
}
#endif /* CRYPTO */


void
vm_swap_consider_defragmenting()
{
	if (compressor_store_stop_compaction == FALSE && !VM_SWAP_BUSY() && (VM_SWAP_SHOULD_DEFRAGMENT() || VM_SWAP_SHOULD_RECLAIM())) {

		if (!vm_swapfile_mgmt_thread_running) {
			lck_mtx_lock(&vm_swap_data_lock);

			if (!vm_swapfile_mgmt_thread_running)
				thread_wakeup((event_t) &vm_swapfile_mgmt_needed);

			lck_mtx_unlock(&vm_swap_data_lock);
		}
	}
}


int vm_swap_defragment_yielded = 0;
int vm_swap_defragment_swapin = 0;
int vm_swap_defragment_free = 0;
int vm_swap_defragment_busy = 0;


static void
vm_swap_defragment()
{
	c_segment_t	c_seg;

	/*
	 * have to grab the master lock w/o holding
	 * any locks in spin mode
	 */
	PAGE_REPLACEMENT_DISALLOWED(TRUE);

	lck_mtx_lock_spin_always(c_list_lock);
	
	while (!queue_empty(&c_swappedout_sparse_list_head)) {
		
		if (compressor_store_stop_compaction == TRUE || VM_SWAP_BUSY()) {
			vm_swap_defragment_yielded++;
			break;
		}
		c_seg = (c_segment_t)queue_first(&c_swappedout_sparse_list_head);

		lck_mtx_lock_spin_always(&c_seg->c_lock);

		assert(c_seg->c_on_swappedout_sparse_q);

		if (c_seg->c_busy) {
			lck_mtx_unlock_always(c_list_lock);

			PAGE_REPLACEMENT_DISALLOWED(FALSE);
			/*
			 * c_seg_wait_on_busy consumes c_seg->c_lock
			 */
			c_seg_wait_on_busy(c_seg);

			PAGE_REPLACEMENT_DISALLOWED(TRUE);

			lck_mtx_lock_spin_always(c_list_lock);

			vm_swap_defragment_busy++;
			continue;
		}
		if (c_seg->c_bytes_used == 0) {
			/*
			 * c_seg_free_locked consumes the c_list_lock
			 * and c_seg->c_lock
			 */
			c_seg_free_locked(c_seg);

			vm_swap_defragment_free++;
		} else {
			lck_mtx_unlock_always(c_list_lock);

			c_seg_swapin(c_seg, TRUE);
			lck_mtx_unlock_always(&c_seg->c_lock);

			vm_swap_defragment_swapin++;
		}
		PAGE_REPLACEMENT_DISALLOWED(FALSE);
		
		vm_pageout_io_throttle();

		/*
		 * because write waiters have privilege over readers,
		 * dropping and immediately retaking the master lock will 
		 * still allow any thread waiting to acquire the
		 * master lock exclusively an opportunity to take it
		 */
		PAGE_REPLACEMENT_DISALLOWED(TRUE);

		lck_mtx_lock_spin_always(c_list_lock);
	}
	lck_mtx_unlock_always(c_list_lock);

	PAGE_REPLACEMENT_DISALLOWED(FALSE);
}



static void
vm_swapfile_mgmt_thread(void)
{

	boolean_t	did_work = FALSE;
	clock_sec_t	sec;
	clock_nsec_t	nsec;

	vm_swapfile_mgmt_thread_awakened++;
	vm_swapfile_mgmt_thread_running = 1;

try_again:

	do {
		if (vm_swap_up == FALSE)
			break;
		did_work = FALSE;
		clock_get_system_nanotime(&sec, &nsec);

		/*
		 * walk through the list of swap files
		 * and do the delayed frees/trims for
		 * any swap file whose count of delayed
		 * frees is above the batch limit
		 */
		vm_swap_handle_delayed_trims(FALSE);

		if (VM_SWAP_SHOULD_CREATE(sec)) {
			if (vm_swap_create_file() == TRUE)
				did_work = TRUE;
			else {
				vm_swapfile_last_failed_to_create_ts = sec;
				HIBLOG("vm_swap_create_file failed @ %lu secs\n", sec);
			}
		}
		if (VM_SWAP_SHOULD_DEFRAGMENT()) {
			proc_set_task_policy_thread(kernel_task, current_thread()->thread_id,
						    TASK_POLICY_INTERNAL, TASK_POLICY_IO, THROTTLE_LEVEL_COMPRESSOR_TIER2);

			vm_swap_defragment();

			if (!VM_SWAP_BUSY())
				did_work = TRUE;

			proc_set_task_policy_thread(kernel_task, current_thread()->thread_id,
						    TASK_POLICY_INTERNAL, TASK_POLICY_IO, THROTTLE_LEVEL_COMPRESSOR_TIER1);
		}
		if (VM_SWAP_SHOULD_RECLAIM()) {
			proc_set_task_policy_thread(kernel_task, current_thread()->thread_id,
						    TASK_POLICY_INTERNAL, TASK_POLICY_IO, THROTTLE_LEVEL_COMPRESSOR_TIER2);

			vm_swap_defragment();
			vm_swap_reclaim();

			if (!VM_SWAP_BUSY())
				did_work = TRUE;

			proc_set_task_policy_thread(kernel_task, current_thread()->thread_id,
						    TASK_POLICY_INTERNAL, TASK_POLICY_IO, THROTTLE_LEVEL_COMPRESSOR_TIER1);
		}

	} while (did_work == TRUE);

	lck_mtx_lock(&vm_swap_data_lock);

	clock_get_system_nanotime(&sec, &nsec);

	if (vm_swap_up == TRUE && (VM_SWAP_SHOULD_CREATE(sec) || ((!VM_SWAP_BUSY() && compressor_store_stop_compaction == FALSE) &&
							       (VM_SWAP_SHOULD_DEFRAGMENT() || VM_SWAP_SHOULD_RECLAIM())))) {
		lck_mtx_unlock(&vm_swap_data_lock);
		goto try_again;
	}

	vm_swapfile_mgmt_thread_running = 0;

	assert_wait((event_t)&vm_swapfile_mgmt_needed, THREAD_UNINT);

	lck_mtx_unlock(&vm_swap_data_lock);

	thread_block((thread_continue_t)vm_swapfile_mgmt_thread);
	
	/* NOTREACHED */
}



int	  swapper_entered_T0 = 0;
int	  swapper_entered_T1 = 0;
int	  swapper_entered_T2 = 0;

static void
vm_swapout_thread_throttle_adjust(void)
{
	int swapper_throttle_new;

	if (swapper_throttle_inited == FALSE) {
		/*
		 * force this thread to be set to the correct
		 * throttling tier
		 */
		swapper_throttle_new = THROTTLE_LEVEL_COMPRESSOR_TIER2;
		swapper_throttle = THROTTLE_LEVEL_COMPRESSOR_TIER1;
		swapper_throttle_inited = TRUE;
		swapper_entered_T2++;
		goto done;
	}
	swapper_throttle_new = swapper_throttle;


	switch(swapper_throttle) {

	case THROTTLE_LEVEL_COMPRESSOR_TIER2:

		if (SWAPPER_NEEDS_TO_UNTHROTTLE() || swapout_target_age || hibernate_flushing == TRUE) {
			swapper_throttle_new = THROTTLE_LEVEL_COMPRESSOR_TIER1;
			swapper_entered_T1++;
			break;
		}
		break;

	case THROTTLE_LEVEL_COMPRESSOR_TIER1:

		if (VM_PAGEOUT_SCAN_NEEDS_TO_THROTTLE()) {
			swapper_throttle_new = THROTTLE_LEVEL_COMPRESSOR_TIER0;
			swapper_entered_T0++;
			break;
		}
		if (COMPRESSOR_NEEDS_TO_SWAP() == 0 && swapout_target_age == 0 && hibernate_flushing == FALSE) {
			swapper_throttle_new = THROTTLE_LEVEL_COMPRESSOR_TIER2;
			swapper_entered_T2++;
			break;
		}
		break;

	case THROTTLE_LEVEL_COMPRESSOR_TIER0:

		if (COMPRESSOR_NEEDS_TO_SWAP() == 0) {
			swapper_throttle_new = THROTTLE_LEVEL_COMPRESSOR_TIER2;
			swapper_entered_T2++;
			break;
		}
		if (SWAPPER_NEEDS_TO_UNTHROTTLE() == 0) {
			swapper_throttle_new = THROTTLE_LEVEL_COMPRESSOR_TIER1;
			swapper_entered_T1++;
			break;
		}
		break;
	}
done:
	if (swapper_throttle != swapper_throttle_new) {
		proc_set_task_policy_thread(kernel_task, vm_swapout_thread_id,
					    TASK_POLICY_INTERNAL, TASK_POLICY_IO, swapper_throttle_new);
		proc_set_task_policy_thread(kernel_task, vm_swapout_thread_id,
					    TASK_POLICY_INTERNAL, TASK_POLICY_PASSIVE_IO, TASK_POLICY_ENABLE);

		swapper_throttle = swapper_throttle_new;
	}
}


static void
vm_swapout_thread(void)
{
	uint64_t	f_offset = 0;
	uint32_t	size = 0;
	c_segment_t 	c_seg = NULL;
	kern_return_t	kr = KERN_SUCCESS;
	vm_offset_t	addr = 0;

	vm_swapout_thread_awakened++;

	lck_mtx_lock_spin_always(c_list_lock);

	while (!queue_empty(&c_swapout_list_head)) {
		
		c_seg = (c_segment_t)queue_first(&c_swapout_list_head);

		lck_mtx_lock_spin_always(&c_seg->c_lock);

		assert(c_seg->c_on_swapout_q);

		if (c_seg->c_busy) {
			lck_mtx_unlock_always(c_list_lock);

			c_seg_wait_on_busy(c_seg);

			lck_mtx_lock_spin_always(c_list_lock);

			continue;
		}
		queue_remove(&c_swapout_list_head, c_seg, c_segment_t, c_age_list);
		c_seg->c_on_swapout_q = 0;
		c_swapout_count--;

		vm_swapout_thread_processed_segments++;

		thread_wakeup((event_t)&compaction_swapper_running);

		size = round_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset));
		
		if (size == 0) {
			c_seg_free_locked(c_seg);
			goto c_seg_was_freed;
		}
		c_seg->c_busy = 1;
		c_seg->c_busy_swapping = 1;

		lck_mtx_unlock_always(c_list_lock);

		addr = (vm_offset_t) c_seg->c_store.c_buffer;

		lck_mtx_unlock_always(&c_seg->c_lock);

#if CHECKSUM_THE_SWAP	
		c_seg->cseg_hash = hash_string((char*)addr, (int)size);
		c_seg->cseg_swap_size = size;
#endif /* CHECKSUM_THE_SWAP */

#if CRYPTO
		vm_swap_encrypt(c_seg);
#endif /* CRYPTO */

		vm_swapout_thread_throttle_adjust();

		kr = vm_swap_put((vm_offset_t) addr, &f_offset, size, c_seg);

		PAGE_REPLACEMENT_DISALLOWED(TRUE);

		lck_mtx_lock_spin_always(c_list_lock);
		lck_mtx_lock_spin_always(&c_seg->c_lock);

	       	if (kr == KERN_SUCCESS) {

			if (C_SEG_ONDISK_IS_SPARSE(c_seg) && hibernate_flushing == FALSE) {

				c_seg_insert_into_q(&c_swappedout_sparse_list_head, c_seg);
				c_seg->c_on_swappedout_sparse_q = 1;
				c_swappedout_sparse_count++;

			} else {
				if (hibernate_flushing == TRUE && (c_seg->c_generation_id >= first_c_segment_to_warm_generation_id &&
								   c_seg->c_generation_id <= last_c_segment_to_warm_generation_id))
					queue_enter_first(&c_swappedout_list_head, c_seg, c_segment_t, c_age_list);
				else
					queue_enter(&c_swappedout_list_head, c_seg, c_segment_t, c_age_list);
				c_seg->c_on_swappedout_q = 1;
				c_swappedout_count++;
			}
			c_seg->c_store.c_swap_handle = f_offset;
			c_seg->c_ondisk = 1;

			VM_STAT_INCR_BY(swapouts, size >> PAGE_SHIFT);
			
			if (c_seg->c_bytes_used)
				OSAddAtomic64(-c_seg->c_bytes_used, &compressor_bytes_used);
		} else {
#if CRYPTO
			vm_swap_decrypt(c_seg);
#endif /* CRYPTO */
			c_seg_insert_into_q(&c_age_list_head, c_seg);
			c_seg->c_on_age_q = 1;
			c_age_count++;

			vm_swap_put_failures++;
		}
		lck_mtx_unlock_always(c_list_lock);

		c_seg->c_busy_swapping = 0;

		C_SEG_WAKEUP_DONE(c_seg);

		if (c_seg->c_must_free)
			c_seg_free(c_seg);
		else
			lck_mtx_unlock_always(&c_seg->c_lock);

		if (kr == KERN_SUCCESS)
			kernel_memory_depopulate(kernel_map, (vm_offset_t) addr, size, KMA_COMPRESSOR);

		PAGE_REPLACEMENT_DISALLOWED(FALSE);

		if (kr == KERN_SUCCESS)
			kmem_free(kernel_map, (vm_offset_t) addr, C_SEG_ALLOCSIZE);

		vm_pageout_io_throttle();
c_seg_was_freed:
		if (c_swapout_count == 0)
			vm_swap_consider_defragmenting();

		lck_mtx_lock_spin_always(c_list_lock);
	}

	assert_wait((event_t)&c_swapout_list_head, THREAD_UNINT);

	lck_mtx_unlock_always(c_list_lock);

	thread_block((thread_continue_t)vm_swapout_thread);
	
	/* NOTREACHED */
}

boolean_t
vm_swap_create_file()
{
	uint64_t	size = 0;
	int		namelen = 0;
	boolean_t	swap_file_created = FALSE;
	boolean_t	swap_file_reuse = FALSE;
	struct swapfile *swf = NULL;


	if (DEFAULT_PAGER_IS_ACTIVE || DEFAULT_FREEZER_IS_ACTIVE) {
	}

	/*
  	 * Any swapfile structure ready for re-use?
	 */	 
	
	lck_mtx_lock(&vm_swap_data_lock);

	swf = (struct swapfile*) queue_first(&swf_global_queue);

	while (queue_end(&swf_global_queue, (queue_entry_t)swf) == FALSE) {
		if (swf->swp_flags == SWAP_REUSE) {
			swap_file_reuse = TRUE;
			break;
		}			
		swf = (struct swapfile*) queue_next(&swf->swp_queue);
	}

	lck_mtx_unlock(&vm_swap_data_lock);

	if (swap_file_reuse == FALSE) {

		namelen = SWAPFILENAME_LEN + SWAPFILENAME_INDEX_LEN + 1;
			
		swf = (struct swapfile*) kalloc(sizeof *swf);
		memset(swf, 0, sizeof(*swf));

		swf->swp_index = vm_num_swap_files + 1;
		swf->swp_pathlen = namelen;
		swf->swp_path = (char*)kalloc(swf->swp_pathlen);

		memset(swf->swp_path, 0, namelen);

		snprintf(swf->swp_path, namelen, "%s%d", SWAP_FILE_NAME, vm_num_swap_files + 1);
	}

	vm_swapfile_open(swf->swp_path, &swf->swp_vp);

	if (swf->swp_vp == NULL) {
		if (swap_file_reuse == FALSE) {
			kfree(swf->swp_path, swf->swp_pathlen); 
			kfree(swf, sizeof *swf);
		}
		return FALSE;
	}
	size = MAX_SWAP_FILE_SIZE;

	while (size >= MIN_SWAP_FILE_SIZE) {

		if (vm_swapfile_preallocate(swf->swp_vp, &size) == 0) {

			int num_bytes_for_bitmap = 0;

			swap_file_created = TRUE;

			swf->swp_size = size;
			swf->swp_nsegs = (unsigned int) (size / COMPRESSED_SWAP_CHUNK_SIZE);
			swf->swp_nseginuse = 0;
			swf->swp_free_hint = 0;

			num_bytes_for_bitmap = MAX((swf->swp_nsegs >> 3) , 1);
			/*
			 * Allocate a bitmap that describes the
			 * number of segments held by this swapfile.
			 */
			swf->swp_bitmap = (uint8_t*)kalloc(num_bytes_for_bitmap);
			memset(swf->swp_bitmap, 0, num_bytes_for_bitmap);

			swf->swp_csegs = (c_segment_t *) kalloc(swf->swp_nsegs * sizeof(c_segment_t));
			memset(swf->swp_csegs, 0, (swf->swp_nsegs * sizeof(c_segment_t)));

			/*
			 * passing a NULL trim_list into vnode_trim_list
			 * will return ENOTSUP if trim isn't supported
			 * and 0 if it is
			 */
			if (vnode_trim_list(swf->swp_vp, NULL))
				swf->swp_trim_supported = FALSE;
			else
				swf->swp_trim_supported = TRUE;

			lck_mtx_lock(&vm_swap_data_lock);

			swf->swp_flags = SWAP_READY;

			if (swap_file_reuse == FALSE) {
				queue_enter(&swf_global_queue, swf, struct swapfile*, swp_queue);
			}
			
			vm_num_swap_files++;

			vm_swapfile_total_segs_alloced += swf->swp_nsegs;

			lck_mtx_unlock(&vm_swap_data_lock);

			thread_wakeup((event_t) &vm_num_swap_files);

			break;
		} else {

			size = size / 2;
		}
	}
	if (swap_file_created == FALSE) {

		vm_swapfile_close((uint64_t)(swf->swp_path), swf->swp_vp);

		swf->swp_vp = NULL;

		if (swap_file_reuse == FALSE) {
			kfree(swf->swp_path, swf->swp_pathlen); 
			kfree(swf, sizeof *swf);
		}
	}
	return swap_file_created;
}


kern_return_t
vm_swap_get(vm_offset_t addr, uint64_t f_offset, uint64_t size)
{
	struct swapfile *swf = NULL;
	uint64_t	file_offset = 0;
	int		retval;

	if (addr == 0) {
		return KERN_FAILURE;
	}

	lck_mtx_lock(&vm_swap_data_lock);

	swf = vm_swapfile_for_handle(f_offset);

	if (swf) {
		if ((swf->swp_flags & SWAP_READY) || (swf->swp_flags & SWAP_RECLAIM)) {

			swf->swp_io_count++;
			file_offset = (f_offset & SWAP_SLOT_MASK);

			lck_mtx_unlock(&vm_swap_data_lock);

		} else {

			lck_mtx_unlock(&vm_swap_data_lock);
			return KERN_FAILURE;
		}
	} else {
		
		lck_mtx_unlock(&vm_swap_data_lock);
		return KERN_FAILURE;
	}

	retval = vm_swapfile_io(swf->swp_vp, file_offset, addr, (int)(size / PAGE_SIZE_64), SWAP_READ);

	/*
	 * Free this slot in the swap structure.
	 */
	vm_swap_free(f_offset);

	lck_mtx_lock(&vm_swap_data_lock);
	swf->swp_io_count--;

	if ((swf->swp_flags & SWAP_WANTED) && swf->swp_io_count == 0) {
	
		swf->swp_flags &= ~SWAP_WANTED;
		thread_wakeup((event_t) &swf->swp_flags);
	}
	if (retval == 0)
		VM_STAT_INCR_BY(swapins, size >> PAGE_SHIFT);
	lck_mtx_unlock(&vm_swap_data_lock);

	if (retval == 0)
		return KERN_SUCCESS;
	else {
		vm_swap_get_failures++;
		return KERN_FAILURE;
	}
}

kern_return_t
vm_swap_put(vm_offset_t addr, uint64_t *f_offset, uint64_t size, c_segment_t c_seg)
{
	unsigned int	segidx = 0;
	struct swapfile *swf = NULL;
	uint64_t	file_offset = 0;
	uint64_t	swapfile_index = 0;
	unsigned int 	byte_for_segidx = 0;
	unsigned int 	offset_within_byte = 0;
	boolean_t	swf_eligible = FALSE;
	boolean_t	waiting = FALSE;
	int		error = 0;
	clock_sec_t	sec;
	clock_nsec_t	nsec;

	if (addr == 0 || f_offset == NULL) {
		return KERN_FAILURE;
	}

	lck_mtx_lock(&vm_swap_data_lock);

	swf = (struct swapfile*) queue_first(&swf_global_queue);

	while(queue_end(&swf_global_queue, (queue_entry_t)swf) == FALSE) {
	
		segidx = swf->swp_free_hint;

		swf_eligible = 	(swf->swp_flags & SWAP_READY) && (swf->swp_nseginuse < swf->swp_nsegs);

		if (swf_eligible) {

			while(segidx < swf->swp_nsegs) {
				
				byte_for_segidx = segidx >> 3;
				offset_within_byte = segidx % 8;
			
				if ((swf->swp_bitmap)[byte_for_segidx] & (1 << offset_within_byte)) {
					segidx++;
					continue;
				}
		
				(swf->swp_bitmap)[byte_for_segidx] |= (1 << offset_within_byte);

				file_offset = segidx * COMPRESSED_SWAP_CHUNK_SIZE;
				swf->swp_nseginuse++;
				swf->swp_io_count++;
				swapfile_index = swf->swp_index;

				vm_swapfile_total_segs_used++;

				clock_get_system_nanotime(&sec, &nsec);

				if (VM_SWAP_SHOULD_CREATE(sec) && !vm_swapfile_mgmt_thread_running)
					thread_wakeup((event_t) &vm_swapfile_mgmt_needed);

				lck_mtx_unlock(&vm_swap_data_lock);
		
				goto done;
			}
		}
		swf = (struct swapfile*) queue_next(&swf->swp_queue);
	}
	assert(queue_end(&swf_global_queue, (queue_entry_t) swf));
	
	/*
	 * we've run out of swap segments, but may not
	 * be in a position to immediately create a new swap
	 * file if we've recently failed to create due to a lack
	 * of free space in the root filesystem... we'll try
	 * to kick that create off, but in any event we're going
	 * to take a breather (up to 1 second) so that we're not caught in a tight
	 * loop back in "vm_compressor_compact_and_swap" trying to stuff
	 * segments into swap files only to have them immediately put back
	 * on the c_age queue due to vm_swap_put failing.
	 *
	 * if we're doing these puts due to a hibernation flush,
	 * no need to block... setting hibernate_no_swapspace to TRUE,
	 * will cause "vm_compressor_compact_and_swap" to immediately abort
	 */
	clock_get_system_nanotime(&sec, &nsec);

	if (VM_SWAP_SHOULD_CREATE(sec) && !vm_swapfile_mgmt_thread_running)
		thread_wakeup((event_t) &vm_swapfile_mgmt_needed);

	if (hibernate_flushing == FALSE || VM_SWAP_SHOULD_CREATE(sec)) {
		waiting = TRUE;
		assert_wait_timeout((event_t) &vm_num_swap_files, THREAD_INTERRUPTIBLE, 1000, 1000*NSEC_PER_USEC);
	} else
		hibernate_no_swapspace = TRUE;

	lck_mtx_unlock(&vm_swap_data_lock);

	if (waiting == TRUE)
		thread_block(THREAD_CONTINUE_NULL);

	return KERN_FAILURE;

done:	
	error = vm_swapfile_io(swf->swp_vp, file_offset, addr, (int) (size / PAGE_SIZE_64), SWAP_WRITE);

	lck_mtx_lock(&vm_swap_data_lock);

	swf->swp_csegs[segidx] = c_seg;

	swf->swp_io_count--;

	*f_offset = (swapfile_index << SWAP_DEVICE_SHIFT) | file_offset;

	if ((swf->swp_flags & SWAP_WANTED) && swf->swp_io_count == 0) {
	
		swf->swp_flags &= ~SWAP_WANTED;
		thread_wakeup((event_t) &swf->swp_flags);
	}

	lck_mtx_unlock(&vm_swap_data_lock);

#if SANITY_CHECK_SWAP_ROUTINES
	printf("Returned 0x%llx as offset\n", *f_offset);
#endif /* SANITY_CHECK_SWAP_ROUTINES */

	if (error) {
		vm_swap_free(*f_offset);

		return KERN_FAILURE;
	}
	return KERN_SUCCESS;
}



static void
vm_swap_free_now(struct swapfile *swf, uint64_t f_offset)
{
	uint64_t	file_offset = 0;
	unsigned int	segidx = 0;


	if ((swf->swp_flags & SWAP_READY) || (swf->swp_flags & SWAP_RECLAIM)) {

		unsigned int byte_for_segidx = 0;
		unsigned int offset_within_byte = 0;

		file_offset = (f_offset & SWAP_SLOT_MASK);
		segidx = (unsigned int) (file_offset / COMPRESSED_SWAP_CHUNK_SIZE);
			
		byte_for_segidx = segidx >> 3;
		offset_within_byte = segidx % 8;

		if ((swf->swp_bitmap)[byte_for_segidx] & (1 << offset_within_byte)) {
				
			(swf->swp_bitmap)[byte_for_segidx] &= ~(1 << offset_within_byte);

			swf->swp_csegs[segidx] = NULL;

			swf->swp_nseginuse--;
			vm_swapfile_total_segs_used--;

			if (segidx < swf->swp_free_hint) {
				swf->swp_free_hint = segidx;
			}
		}
		if (VM_SWAP_SHOULD_RECLAIM() && !vm_swapfile_mgmt_thread_running)
			thread_wakeup((event_t) &vm_swapfile_mgmt_needed);
	}
	lck_mtx_unlock(&vm_swap_data_lock);
}


uint32_t vm_swap_free_now_count = 0;
uint32_t vm_swap_free_delayed_count = 0;


void
vm_swap_free(uint64_t f_offset)
{
	struct swapfile *swf = NULL;
	struct trim_list *tl;
        clock_sec_t     sec;
        clock_nsec_t    nsec;

	lck_mtx_lock(&vm_swap_data_lock);

	swf = vm_swapfile_for_handle(f_offset);

	if (swf && (swf->swp_flags & (SWAP_READY | SWAP_RECLAIM))) {

		if (swf->swp_trim_supported == FALSE || (swf->swp_flags & SWAP_RECLAIM)) {
			/*
			 * don't delay the free if the underlying disk doesn't support
			 * trim, or we're in the midst of reclaiming this swap file since
			 * we don't want to move segments that are technically free
			 * but not yet handled by the delayed free mechanism
			 */
			vm_swap_free_now(swf, f_offset);

			vm_swap_free_now_count++;
			return;
		}
		tl = kalloc(sizeof(struct trim_list));

		tl->tl_offset = f_offset & SWAP_SLOT_MASK;
		tl->tl_length = COMPRESSED_SWAP_CHUNK_SIZE;

		tl->tl_next = swf->swp_delayed_trim_list_head;
		swf->swp_delayed_trim_list_head = tl;
		swf->swp_delayed_trim_count++;

		if (VM_SWAP_SHOULD_TRIM(swf) && !vm_swapfile_mgmt_thread_running) {
			clock_get_system_nanotime(&sec, &nsec);

			if (sec > dont_trim_until_ts)
				thread_wakeup((event_t) &vm_swapfile_mgmt_needed);
		}
		vm_swap_free_delayed_count++;
	}
	lck_mtx_unlock(&vm_swap_data_lock);
}	


static void
vm_swap_handle_delayed_trims(boolean_t force_now)
{
	struct swapfile *swf = NULL;

	/*
	 * because swap files are created or reclaimed on the
	 * same thread that calls this function, it's safe
	 * to iterate "swf_global_queue"  w/o holding
	 * the lock since those are the only 2 cases that can
	 * change the items on the "swf_global_queue"
	 */
	swf = (struct swapfile*) queue_first(&swf_global_queue);

	while (queue_end(&swf_global_queue, (queue_entry_t)swf) == FALSE) {

		assert(!(swf->swp_flags & SWAP_RECLAIM));

		if ((swf->swp_flags & SWAP_READY) && (force_now == TRUE || VM_SWAP_SHOULD_TRIM(swf)))
			vm_swap_do_delayed_trim(swf);

		swf = (struct swapfile*) queue_next(&swf->swp_queue);
	}
}


static void
vm_swap_do_delayed_trim(struct swapfile *swf)
{
	struct trim_list *tl, *tl_head;

	lck_mtx_lock(&vm_swap_data_lock);

	tl_head = swf->swp_delayed_trim_list_head;
	swf->swp_delayed_trim_list_head = NULL;
	swf->swp_delayed_trim_count = 0;

	lck_mtx_unlock(&vm_swap_data_lock);

	vnode_trim_list(swf->swp_vp, tl_head);
	
	while ((tl = tl_head) != NULL) {
		unsigned int	segidx = 0;
		unsigned int	byte_for_segidx = 0;
		unsigned int	offset_within_byte = 0;

		lck_mtx_lock(&vm_swap_data_lock);

		segidx = (unsigned int) (tl->tl_offset / COMPRESSED_SWAP_CHUNK_SIZE);
			
		byte_for_segidx = segidx >> 3;
		offset_within_byte = segidx % 8;

		if ((swf->swp_bitmap)[byte_for_segidx] & (1 << offset_within_byte)) {
				
			(swf->swp_bitmap)[byte_for_segidx] &= ~(1 << offset_within_byte);
			
			swf->swp_csegs[segidx] = NULL;

			swf->swp_nseginuse--;
			vm_swapfile_total_segs_used--;

			if (segidx < swf->swp_free_hint) {
				swf->swp_free_hint = segidx;
			}
		}
		lck_mtx_unlock(&vm_swap_data_lock);

		tl_head = tl->tl_next;

		kfree(tl, sizeof(struct trim_list));
	}		
}


void
vm_swap_flush()
{
	return;
}

int	vm_swap_reclaim_yielded = 0;

void
vm_swap_reclaim(void)
{
	vm_offset_t	addr = 0;
	unsigned int	segidx = 0;
	uint64_t	f_offset = 0;
	struct swapfile *swf = NULL;
	struct swapfile *smallest_swf = NULL;
	unsigned int	min_nsegs = 0;	
	unsigned int 	byte_for_segidx = 0;
	unsigned int 	offset_within_byte = 0;
	uint32_t	c_size = 0;

	c_segment_t	c_seg = NULL;
	
	if (kernel_memory_allocate(kernel_map, (vm_offset_t *)(&addr), C_SEG_BUFSIZE, 0, KMA_KOBJECT) != KERN_SUCCESS) {
		panic("vm_swap_reclaim: kernel_memory_allocate failed\n");
	}

	lck_mtx_lock(&vm_swap_data_lock);

	swf = (struct swapfile*) queue_first(&swf_global_queue);
	min_nsegs = MAX_SWAP_FILE_SIZE / COMPRESSED_SWAP_CHUNK_SIZE;
	smallest_swf = NULL;

	while (queue_end(&swf_global_queue, (queue_entry_t)swf) == FALSE) {

		if ((swf->swp_flags & SWAP_READY) && (swf->swp_nseginuse <= min_nsegs)) {

			smallest_swf = swf;
			min_nsegs = swf->swp_nseginuse;
		}			
		swf = (struct swapfile*) queue_next(&swf->swp_queue);
	}
	
	if (smallest_swf == NULL)
		goto done;

	swf = smallest_swf;


	swf->swp_flags &= ~SWAP_READY;
	swf->swp_flags |= SWAP_RECLAIM;

	if (swf->swp_delayed_trim_count) {

		lck_mtx_unlock(&vm_swap_data_lock);

		vm_swap_do_delayed_trim(swf);

		lck_mtx_lock(&vm_swap_data_lock);
	}
	segidx = 0;

	while (segidx < swf->swp_nsegs) {

ReTry_for_cseg:	
		if (compressor_store_stop_compaction == TRUE || (swf->swp_trim_supported == FALSE && VM_SWAP_BUSY())) {
			vm_swap_reclaim_yielded++;
			break;
		}
		/*
		 * Wait for outgoing I/Os.
		 */
		while (swf->swp_io_count) {

			swf->swp_flags |= SWAP_WANTED;

			assert_wait((event_t) &swf->swp_flags, THREAD_UNINT);
			lck_mtx_unlock(&vm_swap_data_lock);
		
			thread_block(THREAD_CONTINUE_NULL);
		
			lck_mtx_lock(&vm_swap_data_lock);
		}

		byte_for_segidx = segidx >> 3;
		offset_within_byte = segidx % 8;

		if (((swf->swp_bitmap)[byte_for_segidx] & (1 << offset_within_byte)) == 0) {

			segidx++;
			continue;
		}

		c_seg = swf->swp_csegs[segidx];

		lck_mtx_lock_spin_always(&c_seg->c_lock);

		assert(c_seg->c_ondisk);

		if (c_seg->c_busy) {

			c_seg->c_wanted = 1;
			
			assert_wait((event_t) (c_seg), THREAD_UNINT);
			lck_mtx_unlock_always(&c_seg->c_lock);
			
			lck_mtx_unlock(&vm_swap_data_lock);
			
			thread_block(THREAD_CONTINUE_NULL);

			lck_mtx_lock(&vm_swap_data_lock);
			
			goto ReTry_for_cseg;
		}
		(swf->swp_bitmap)[byte_for_segidx] &= ~(1 << offset_within_byte);

		f_offset = segidx * COMPRESSED_SWAP_CHUNK_SIZE;
		
		swf->swp_csegs[segidx] = NULL;
		swf->swp_nseginuse--;

		vm_swapfile_total_segs_used--;
			
		lck_mtx_unlock(&vm_swap_data_lock);
	
		if (c_seg->c_must_free) {

			c_seg_free(c_seg);
		} else {

			c_seg->c_busy = 1;
			c_seg->c_busy_swapping = 1;
#if !CHECKSUM_THE_SWAP
			c_seg_trim_tail(c_seg);
#endif

#if SANITY_CHECK_SWAP_ROUTINES

			c_size = COMPRESSED_SWAP_CHUNK_SIZE;

#else /* SANITY_CHECK_SWAP_ROUTINES */

			c_size = round_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset));
		
			assert(c_size <= C_SEG_BUFSIZE);

#endif /* SANITY_CHECK_SWAP_ROUTINES */
		
			lck_mtx_unlock_always(&c_seg->c_lock);

			if (vm_swapfile_io(swf->swp_vp, f_offset, addr, (int)(c_size / PAGE_SIZE_64), SWAP_READ)) {

				/*
				 * reading the data back in failed, so convert c_seg
				 * to a swapped in c_segment that contains no data
				 */
				c_seg->c_store.c_buffer = (int32_t *)NULL;
				c_seg_swapin_requeue(c_seg);

				goto swap_io_failed;
			}
			VM_STAT_INCR_BY(swapins, c_size >> PAGE_SHIFT);

			if (vm_swap_put(addr, &f_offset, c_size, c_seg)) {
				vm_offset_t	c_buffer;

				/*
				 * the put failed, so convert c_seg to a fully swapped in c_segment
				 * with valid data
				 */
				if (kernel_memory_allocate(kernel_map, &c_buffer, C_SEG_ALLOCSIZE, 0, KMA_COMPRESSOR | KMA_VAONLY) != KERN_SUCCESS)
					panic("vm_swap_reclaim: kernel_memory_allocate failed\n");
				kernel_memory_populate(kernel_map, c_buffer, c_size, KMA_COMPRESSOR);

				memcpy((char *)c_buffer, (char *)addr, c_size);

				c_seg->c_store.c_buffer = (int32_t *)c_buffer;
#if CRYPTO
				vm_swap_decrypt(c_seg);
#endif /* CRYPTO */
				c_seg_swapin_requeue(c_seg);

				OSAddAtomic64(c_seg->c_bytes_used, &compressor_bytes_used);

				goto swap_io_failed;
			}
			VM_STAT_INCR_BY(swapouts, c_size >> PAGE_SHIFT);

			lck_mtx_lock_spin_always(&c_seg->c_lock);
				
			assert(c_seg->c_ondisk);
			/*
			 * The c_seg will now know about the new location on disk.
			 */
			c_seg->c_store.c_swap_handle = f_offset;
swap_io_failed:
			c_seg->c_busy_swapping = 0;
		
			if (c_seg->c_must_free)
				c_seg_free(c_seg);
			else {
				C_SEG_WAKEUP_DONE(c_seg);
				
				lck_mtx_unlock_always(&c_seg->c_lock);
			}
		}
		lck_mtx_lock(&vm_swap_data_lock);
	}

	if (swf->swp_nseginuse) {

		swf->swp_flags &= ~SWAP_RECLAIM;
		swf->swp_flags |= SWAP_READY;

		goto done;
	}
	/*
  	 * We don't remove this inactive swf from the queue.
	 * That way, we can re-use it when needed again and
	 * preserve the namespace.
	 */	 
	//queue_remove(&swf_global_queue, swf, struct swapfile*, swp_queue);

	vm_num_swap_files--;

	vm_swapfile_total_segs_alloced -= swf->swp_nsegs;

	lck_mtx_unlock(&vm_swap_data_lock);

	vm_swapfile_close((uint64_t)(swf->swp_path), swf->swp_vp);

	kfree(swf->swp_csegs, swf->swp_nsegs * sizeof(c_segment_t));
	kfree(swf->swp_bitmap, MAX((swf->swp_nsegs >> 3), 1));
	
	lck_mtx_lock(&vm_swap_data_lock);

	swf->swp_vp = NULL;	
	swf->swp_size = 0;
	swf->swp_free_hint = 0;
	swf->swp_nsegs = 0;
	swf->swp_flags = SWAP_REUSE;

	thread_wakeup((event_t) &swf->swp_flags);
done:
	lck_mtx_unlock(&vm_swap_data_lock);

	kmem_free(kernel_map, (vm_offset_t) addr, C_SEG_BUFSIZE);
}


uint64_t
vm_swap_get_total_space(void)
{
	uint64_t total_space = 0;

	total_space = (uint64_t)vm_swapfile_total_segs_alloced * COMPRESSED_SWAP_CHUNK_SIZE;

	return total_space;
}

uint64_t
vm_swap_get_used_space(void)
{
	uint64_t used_space = 0;

	used_space = (uint64_t)vm_swapfile_total_segs_used * COMPRESSED_SWAP_CHUNK_SIZE;

	return used_space;
}

uint64_t
vm_swap_get_free_space(void)
{
	return (vm_swap_get_total_space() - vm_swap_get_used_space());
}
