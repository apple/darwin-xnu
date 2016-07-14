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
boolean_t	vm_swapfile_create_needed = FALSE;
boolean_t	vm_swapfile_gc_needed = FALSE;

int		swapper_throttle = -1;
boolean_t	swapper_throttle_inited = FALSE;
uint64_t	vm_swapout_thread_id;

uint64_t	vm_swap_put_failures = 0;
uint64_t	vm_swap_get_failures = 0;
int		vm_num_swap_files = 0;
int		vm_swapout_thread_processed_segments = 0;
int		vm_swapout_thread_awakened = 0;
int		vm_swapfile_create_thread_awakened = 0;
int		vm_swapfile_create_thread_running = 0;
int		vm_swapfile_gc_thread_awakened = 0;
int		vm_swapfile_gc_thread_running = 0;

int64_t		vm_swappin_avail = 0;
unsigned int	vm_swapfile_total_segs_alloced = 0;
unsigned int	vm_swapfile_total_segs_used = 0;


#define SWAP_READY	0x1	/* Swap file is ready to be used */
#define SWAP_RECLAIM	0x2	/* Swap file is marked to be reclaimed */
#define SWAP_WANTED	0x4	/* Swap file has waiters */
#define SWAP_REUSE	0x8	/* Swap file is on the Q and has a name. Reuse after init-ing.*/
#define SWAP_PINNED	0x10	/* Swap file is pinned (FusionDrive) */


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
};

queue_head_t	swf_global_queue;
boolean_t	swp_trim_supported = FALSE;

extern clock_sec_t	dont_trim_until_ts;
clock_sec_t		vm_swapfile_last_failed_to_create_ts = 0;
clock_sec_t		vm_swapfile_last_successful_create_ts = 0;
int			vm_swapfile_can_be_created = FALSE;
boolean_t		delayed_trim_handling_in_progress = FALSE;

static void vm_swapout_thread_throttle_adjust(void);
static void vm_swap_free_now(struct swapfile *swf, uint64_t f_offset);
static void vm_swapout_thread(void);
static void vm_swapfile_create_thread(void);
static void vm_swapfile_gc_thread(void);
static void vm_swap_defragment();
static void vm_swap_handle_delayed_trims(boolean_t);
static void vm_swap_do_delayed_trim();
static void vm_swap_wait_on_trim_handling_in_progress(void);



#define VM_MAX_SWAP_FILE_NUM		100
#define	VM_SWAPFILE_DELAYED_TRIM_MAX	128

#define	VM_SWAP_SHOULD_DEFRAGMENT()	(c_swappedout_sparse_count > (vm_swapfile_total_segs_used / 4) ? 1 : 0)
#define VM_SWAP_SHOULD_RECLAIM()	(((vm_swapfile_total_segs_alloced - vm_swapfile_total_segs_used) >= SWAPFILE_RECLAIM_THRESHOLD_SEGS) ? 1 : 0)
#define VM_SWAP_SHOULD_ABORT_RECLAIM()	(((vm_swapfile_total_segs_alloced - vm_swapfile_total_segs_used) <= SWAPFILE_RECLAIM_MINIMUM_SEGS) ? 1 : 0)
#define VM_SWAP_SHOULD_PIN(_size)	(vm_swappin_avail > 0 && vm_swappin_avail >= (int64_t)(_size))
#define VM_SWAP_SHOULD_CREATE(cur_ts)	((vm_num_swap_files < VM_MAX_SWAP_FILE_NUM) && ((vm_swapfile_total_segs_alloced - vm_swapfile_total_segs_used) < (unsigned int)VM_SWAPFILE_HIWATER_SEGS) && \
					 ((cur_ts - vm_swapfile_last_failed_to_create_ts) > VM_SWAPFILE_DELAYED_CREATE) ? 1 : 0)
#define VM_SWAP_SHOULD_TRIM(swf)	((swf->swp_delayed_trim_count >= VM_SWAPFILE_DELAYED_TRIM_MAX) ? 1 : 0)


#define	VM_SWAPFILE_DELAYED_CREATE	15

#define VM_SWAP_BUSY()	((c_swapout_count && (swapper_throttle == THROTTLE_LEVEL_COMPRESSOR_TIER1 || swapper_throttle == THROTTLE_LEVEL_COMPRESSOR_TIER0)) ? 1 : 0)


#if CHECKSUM_THE_SWAP
extern unsigned int hash_string(char *cp, int len);
#endif

#if RECORD_THE_COMPRESSED_DATA
boolean_t	c_compressed_record_init_done = FALSE;
int		c_compressed_record_write_error = 0;
struct vnode	*c_compressed_record_vp = NULL;
uint64_t	c_compressed_record_file_offset = 0;
void	c_compressed_record_init(void);
void	c_compressed_record_write(char *, int);
#endif

#if ENCRYPTED_SWAP
extern boolean_t		swap_crypt_ctx_initialized;
extern void 			swap_crypt_ctx_initialize(void);
extern const unsigned char	swap_crypt_null_iv[AES_BLOCK_SIZE];
extern aes_ctx			swap_crypt_ctx;
extern unsigned long 		vm_page_encrypt_counter;
extern unsigned long 		vm_page_decrypt_counter;
#endif /* ENCRYPTED_SWAP */

extern void			vm_pageout_io_throttle(void);
extern void			vm_pageout_reinit_tuneables(void);
extern void			vm_swap_file_set_tuneables(void);

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
vm_compressor_swap_init()
{
	thread_t	thread = NULL;

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

	
	if (kernel_thread_start_priority((thread_continue_t)vm_swapout_thread, NULL,
					 BASEPRI_PREEMPT - 1, &thread) != KERN_SUCCESS) {
		panic("vm_swapout_thread: create failed");
	}
	vm_swapout_thread_id = thread->thread_id;

	thread_deallocate(thread);

	if (kernel_thread_start_priority((thread_continue_t)vm_swapfile_create_thread, NULL,
				 BASEPRI_PREEMPT - 1, &thread) != KERN_SUCCESS) {
		panic("vm_swapfile_create_thread: create failed");
	}

	thread_deallocate(thread);

	if (kernel_thread_start_priority((thread_continue_t)vm_swapfile_gc_thread, NULL,
				 BASEPRI_PREEMPT - 1, &thread) != KERN_SUCCESS) {
		panic("vm_swapfile_gc_thread: create failed");
	}
	thread_deallocate(thread);

	proc_set_task_policy_thread(kernel_task, thread->thread_id,
				    TASK_POLICY_INTERNAL, TASK_POLICY_IO, THROTTLE_LEVEL_COMPRESSOR_TIER2);
	proc_set_task_policy_thread(kernel_task, thread->thread_id,
				    TASK_POLICY_INTERNAL, TASK_POLICY_PASSIVE_IO, TASK_POLICY_ENABLE);
	
#if ENCRYPTED_SWAP
	if (swap_crypt_ctx_initialized == FALSE) {
		swap_crypt_ctx_initialize();
	}
#endif /* ENCRYPTED_SWAP */
		
	memset(swapfilename, 0, MAX_SWAPFILENAME_LEN + 1);

	vm_swap_up = TRUE;

	printf("VM Swap Subsystem is %s\n", (vm_swap_up == TRUE) ? "ON" : "OFF"); 
}


#if RECORD_THE_COMPRESSED_DATA

void
c_compressed_record_init()
{
	if (c_compressed_record_init_done == FALSE) {
		vm_swapfile_open("/tmp/compressed_data", &c_compressed_record_vp);
		c_compressed_record_init_done = TRUE;
	}
}

void
c_compressed_record_write(char *buf, int size)
{
	if (c_compressed_record_write_error == 0) {
		c_compressed_record_write_error = vm_record_file_write(c_compressed_record_vp, c_compressed_record_file_offset, buf, size);
		c_compressed_record_file_offset += size;
	}
}
#endif



void
vm_swap_file_set_tuneables()
{
	struct	vnode *vp;
	char	*pathname;
	int	namelen;

	if (strlen(swapfilename) == 0) {
		/*
		 * If no swapfile name has been set, we'll
		 * use the default name.
		 *
		 * Also, this function is only called from the vm_pageout_scan thread
		 * via vm_consider_waking_compactor_swapper, 
		 * so we don't need to worry about a race in checking/setting the name here.
		 */
		strlcpy(swapfilename, SWAP_FILE_NAME, MAX_SWAPFILENAME_LEN);
	}
	namelen = (int)strlen(swapfilename) + SWAPFILENAME_INDEX_LEN + 1;
	pathname = (char*)kalloc(namelen);
	memset(pathname, 0, namelen);
	snprintf(pathname, namelen, "%s%d", swapfilename, 0);

	vm_swapfile_open(pathname, &vp);

	if (vp == NULL)
		goto done;

        if (vnode_pager_isSSD(vp) == FALSE)
		vm_pageout_reinit_tuneables();
	vnode_setswapmount(vp);
	vm_swappin_avail = vnode_getswappin_avail(vp);
	vm_swapfile_close((uint64_t)pathname, vp);
done:
	kfree(pathname, namelen);
}


#if ENCRYPTED_SWAP
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
#endif /* ENCRYPTED_SWAP */


void
vm_swap_consider_defragmenting()
{
	if (compressor_store_stop_compaction == FALSE && !VM_SWAP_BUSY() &&
	    (VM_SWAP_SHOULD_DEFRAGMENT() || VM_SWAP_SHOULD_RECLAIM())) {

		if (!vm_swapfile_gc_thread_running) {
			lck_mtx_lock(&vm_swap_data_lock);

			if (!vm_swapfile_gc_thread_running)
				thread_wakeup((event_t) &vm_swapfile_gc_needed);

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

		assert(c_seg->c_state == C_ON_SWAPPEDOUTSPARSE_Q);

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
			C_SEG_BUSY(c_seg);
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
vm_swapfile_create_thread(void)
{
	clock_sec_t	sec;
	clock_nsec_t	nsec;

	current_thread()->options |= TH_OPT_VMPRIV;

	vm_swapfile_create_thread_awakened++;
	vm_swapfile_create_thread_running = 1;

	while (TRUE) {
		/*
		 * walk through the list of swap files
		 * and do the delayed frees/trims for
		 * any swap file whose count of delayed
		 * frees is above the batch limit
		 */
		vm_swap_handle_delayed_trims(FALSE);

		lck_mtx_lock(&vm_swap_data_lock);

		clock_get_system_nanotime(&sec, &nsec);

		if (VM_SWAP_SHOULD_CREATE(sec) == 0)
			break;

		lck_mtx_unlock(&vm_swap_data_lock);

		if (vm_swap_create_file() == FALSE) {
			vm_swapfile_last_failed_to_create_ts = sec;
			HIBLOG("vm_swap_create_file failed @ %lu secs\n", (unsigned long)sec);

		} else
			vm_swapfile_last_successful_create_ts = sec;
	}
	vm_swapfile_create_thread_running = 0;

	assert_wait((event_t)&vm_swapfile_create_needed, THREAD_UNINT);

	lck_mtx_unlock(&vm_swap_data_lock);

	thread_block((thread_continue_t)vm_swapfile_create_thread);
	
	/* NOTREACHED */
}


static void
vm_swapfile_gc_thread(void)
{
	boolean_t	need_defragment;
	boolean_t	need_reclaim;

	vm_swapfile_gc_thread_awakened++;
	vm_swapfile_gc_thread_running = 1;

	while (TRUE) {

		lck_mtx_lock(&vm_swap_data_lock);
		
		if (VM_SWAP_BUSY() || compressor_store_stop_compaction == TRUE)
			break;

		need_defragment = FALSE;
		need_reclaim = FALSE;

		if (VM_SWAP_SHOULD_DEFRAGMENT())
			need_defragment = TRUE;

		if (VM_SWAP_SHOULD_RECLAIM()) {
			need_defragment = TRUE;
			need_reclaim = TRUE;
		}
		if (need_defragment == FALSE && need_reclaim == FALSE)
			break;

		lck_mtx_unlock(&vm_swap_data_lock);

		if (need_defragment == TRUE)
			vm_swap_defragment();
		if (need_reclaim == TRUE)
			vm_swap_reclaim();
	}
	vm_swapfile_gc_thread_running = 0;

	assert_wait((event_t)&vm_swapfile_gc_needed, THREAD_UNINT);

	lck_mtx_unlock(&vm_swap_data_lock);

	thread_block((thread_continue_t)vm_swapfile_gc_thread);
	
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


int vm_swapout_found_empty = 0;


static void
vm_swapout_thread(void)
{
	uint64_t	f_offset = 0;
	uint32_t	size = 0;
	c_segment_t 	c_seg = NULL;
	kern_return_t	kr = KERN_SUCCESS;
	vm_offset_t	addr = 0;

	current_thread()->options |= TH_OPT_VMPRIV;

	vm_swapout_thread_awakened++;

	lck_mtx_lock_spin_always(c_list_lock);

	while (!queue_empty(&c_swapout_list_head)) {
		
		c_seg = (c_segment_t)queue_first(&c_swapout_list_head);

		lck_mtx_lock_spin_always(&c_seg->c_lock);

		assert(c_seg->c_state == C_ON_SWAPOUT_Q);

		if (c_seg->c_busy) {
			lck_mtx_unlock_always(c_list_lock);

			c_seg_wait_on_busy(c_seg);

			lck_mtx_lock_spin_always(c_list_lock);

			continue;
		}
		vm_swapout_thread_processed_segments++;

		size = round_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset));
		
		if (size == 0) {
			assert(c_seg->c_bytes_used == 0);

			c_seg_switch_state(c_seg, C_IS_EMPTY, FALSE);
			lck_mtx_unlock_always(&c_seg->c_lock);
			lck_mtx_unlock_always(c_list_lock);

			vm_swapout_found_empty++;
			goto c_seg_is_empty;
		}
		C_SEG_BUSY(c_seg);
		c_seg->c_busy_swapping = 1;

		lck_mtx_unlock_always(c_list_lock);

		addr = (vm_offset_t) c_seg->c_store.c_buffer;

		lck_mtx_unlock_always(&c_seg->c_lock);

#if CHECKSUM_THE_SWAP	
		c_seg->cseg_hash = hash_string((char*)addr, (int)size);
		c_seg->cseg_swap_size = size;
#endif /* CHECKSUM_THE_SWAP */

#if ENCRYPTED_SWAP
		vm_swap_encrypt(c_seg);
#endif /* ENCRYPTED_SWAP */

		vm_swapout_thread_throttle_adjust();

		kr = vm_swap_put((vm_offset_t) addr, &f_offset, size, c_seg);

		PAGE_REPLACEMENT_DISALLOWED(TRUE);

		if (kr == KERN_SUCCESS) {
			kernel_memory_depopulate(kernel_map, (vm_offset_t) addr, size, KMA_COMPRESSOR);
		}
		lck_mtx_lock_spin_always(c_list_lock);
		lck_mtx_lock_spin_always(&c_seg->c_lock);

	       	if (kr == KERN_SUCCESS) {
			int		new_state = C_ON_SWAPPEDOUT_Q;
			boolean_t	insert_head = FALSE;

			if (hibernate_flushing == TRUE) {
				if (c_seg->c_generation_id >= first_c_segment_to_warm_generation_id &&
				    c_seg->c_generation_id <= last_c_segment_to_warm_generation_id)
					insert_head = TRUE;
			} else if (C_SEG_ONDISK_IS_SPARSE(c_seg))
				new_state = C_ON_SWAPPEDOUTSPARSE_Q;

			c_seg_switch_state(c_seg, new_state, insert_head);

			c_seg->c_store.c_swap_handle = f_offset;

			VM_STAT_INCR_BY(swapouts, size >> PAGE_SHIFT);
			
			if (c_seg->c_bytes_used)
				OSAddAtomic64(-c_seg->c_bytes_used, &compressor_bytes_used);
		} else {
#if ENCRYPTED_SWAP
			vm_swap_decrypt(c_seg);
#endif /* ENCRYPTED_SWAP */
			if (c_seg->c_overage_swap == TRUE) {
				c_seg->c_overage_swap = FALSE;
				c_overage_swapped_count--;
			}
			c_seg_switch_state(c_seg, C_ON_AGE_Q, FALSE);
		}
		lck_mtx_unlock_always(c_list_lock);

		c_seg->c_busy_swapping = 0;
		C_SEG_WAKEUP_DONE(c_seg);
		lck_mtx_unlock_always(&c_seg->c_lock);

		PAGE_REPLACEMENT_DISALLOWED(FALSE);

		vm_pageout_io_throttle();
c_seg_is_empty:
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
	boolean_t	swap_file_pin = FALSE;
	struct swapfile *swf = NULL;

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

		if (strlen(swapfilename) == 0) {
			/*
			 * If no swapfile name has been set, we'll
			 * use the default name.
			 *
			 * Also, this function is only called from the swapfile management thread.
			 * So we don't need to worry about a race in checking/setting the name here.
			 */

			strlcpy(swapfilename, SWAP_FILE_NAME, MAX_SWAPFILENAME_LEN);
		}

		namelen = (int)strlen(swapfilename) + SWAPFILENAME_INDEX_LEN + 1;
			
		swf = (struct swapfile*) kalloc(sizeof *swf);
		memset(swf, 0, sizeof(*swf));

		swf->swp_index = vm_num_swap_files + 1;
		swf->swp_pathlen = namelen;
		swf->swp_path = (char*)kalloc(swf->swp_pathlen);

		memset(swf->swp_path, 0, namelen);

		snprintf(swf->swp_path, namelen, "%s%d", swapfilename, vm_num_swap_files);
	}

	vm_swapfile_open(swf->swp_path, &swf->swp_vp);

	if (swf->swp_vp == NULL) {
		if (swap_file_reuse == FALSE) {
			kfree(swf->swp_path, swf->swp_pathlen); 
			kfree(swf, sizeof *swf);
		}
		return FALSE;
	}
	vm_swapfile_can_be_created = TRUE;

	size = MAX_SWAP_FILE_SIZE;

	while (size >= MIN_SWAP_FILE_SIZE) {

		swap_file_pin = VM_SWAP_SHOULD_PIN(size);

		if (vm_swapfile_preallocate(swf->swp_vp, &size, &swap_file_pin) == 0) {

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
			if (vnode_trim_list(swf->swp_vp, NULL, FALSE) == 0)
				swp_trim_supported = TRUE;

			lck_mtx_lock(&vm_swap_data_lock);

			swf->swp_flags = SWAP_READY;

			if (swap_file_reuse == FALSE) {
				queue_enter(&swf_global_queue, swf, struct swapfile*, swp_queue);
			}
			
			vm_num_swap_files++;

			vm_swapfile_total_segs_alloced += swf->swp_nsegs;

			if (swap_file_pin == TRUE) {
				swf->swp_flags |= SWAP_PINNED;
				vm_swappin_avail -= swf->swp_size;
			}

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
	int		retval = 0;

	if (addr == 0) {
		return KERN_FAILURE;
	}

	lck_mtx_lock(&vm_swap_data_lock);

	swf = vm_swapfile_for_handle(f_offset);

	if (swf == NULL || ( !(swf->swp_flags & SWAP_READY) && !(swf->swp_flags & SWAP_RECLAIM))) {
		retval = 1;
		goto done;
	}
	swf->swp_io_count++;

	lck_mtx_unlock(&vm_swap_data_lock);

	file_offset = (f_offset & SWAP_SLOT_MASK);
	retval = vm_swapfile_io(swf->swp_vp, file_offset, addr, (int)(size / PAGE_SIZE_64), SWAP_READ);

	if (retval == 0)
		VM_STAT_INCR_BY(swapins, size >> PAGE_SHIFT);
	else
		vm_swap_get_failures++;

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
done:
	lck_mtx_unlock(&vm_swap_data_lock);

	if (retval == 0)
		return KERN_SUCCESS;
	else
		return KERN_FAILURE;
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
	boolean_t	retried = FALSE;
	int		error = 0;
	clock_sec_t	sec;
	clock_nsec_t	nsec;

	if (addr == 0 || f_offset == NULL) {
		return KERN_FAILURE;
	}
retry:
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

				if (VM_SWAP_SHOULD_CREATE(sec) && !vm_swapfile_create_thread_running)
					thread_wakeup((event_t) &vm_swapfile_create_needed);

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

	if (VM_SWAP_SHOULD_CREATE(sec) && !vm_swapfile_create_thread_running)
		thread_wakeup((event_t) &vm_swapfile_create_needed);

	if (hibernate_flushing == FALSE || VM_SWAP_SHOULD_CREATE(sec)) {
		waiting = TRUE;
		assert_wait_timeout((event_t) &vm_num_swap_files, THREAD_INTERRUPTIBLE, 1000, 1000*NSEC_PER_USEC);
	} else
		hibernate_no_swapspace = TRUE;

	lck_mtx_unlock(&vm_swap_data_lock);

	if (waiting == TRUE) {
		thread_block(THREAD_CONTINUE_NULL);

		if (retried == FALSE && hibernate_flushing == TRUE) {
			retried = TRUE;
			goto retry;
		}
	}
	vm_swap_put_failures++;

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

	if (error) {
		vm_swap_free(*f_offset);

		vm_swap_put_failures++;

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
		if (VM_SWAP_SHOULD_RECLAIM() && !vm_swapfile_gc_thread_running)
			thread_wakeup((event_t) &vm_swapfile_gc_needed);
	}
}


uint32_t vm_swap_free_now_count = 0;
uint32_t vm_swap_free_delayed_count = 0;


void
vm_swap_free(uint64_t f_offset)
{
	struct swapfile *swf = NULL;
	struct trim_list *tl = NULL;
        clock_sec_t     sec;
        clock_nsec_t    nsec;

	if (swp_trim_supported == TRUE)
		tl = kalloc(sizeof(struct trim_list));

	lck_mtx_lock(&vm_swap_data_lock);

	swf = vm_swapfile_for_handle(f_offset);

	if (swf && (swf->swp_flags & (SWAP_READY | SWAP_RECLAIM))) {

		if (swp_trim_supported == FALSE || (swf->swp_flags & SWAP_RECLAIM)) {
			/*
			 * don't delay the free if the underlying disk doesn't support
			 * trim, or we're in the midst of reclaiming this swap file since
			 * we don't want to move segments that are technically free
			 * but not yet handled by the delayed free mechanism
			 */
			vm_swap_free_now(swf, f_offset);

			vm_swap_free_now_count++;
			goto done;
		}
		tl->tl_offset = f_offset & SWAP_SLOT_MASK;
		tl->tl_length = COMPRESSED_SWAP_CHUNK_SIZE;

		tl->tl_next = swf->swp_delayed_trim_list_head;
		swf->swp_delayed_trim_list_head = tl;
		swf->swp_delayed_trim_count++;
		tl = NULL;

		if (VM_SWAP_SHOULD_TRIM(swf) && !vm_swapfile_create_thread_running) {
			clock_get_system_nanotime(&sec, &nsec);

			if (sec > dont_trim_until_ts)
				thread_wakeup((event_t) &vm_swapfile_create_needed);
		}
		vm_swap_free_delayed_count++;
	}
done:
	lck_mtx_unlock(&vm_swap_data_lock);

	if (tl != NULL)
		kfree(tl, sizeof(struct trim_list));
}	


static void
vm_swap_wait_on_trim_handling_in_progress()
{
	while (delayed_trim_handling_in_progress == TRUE) {

		assert_wait((event_t) &delayed_trim_handling_in_progress, THREAD_UNINT);
		lck_mtx_unlock(&vm_swap_data_lock);
		
		thread_block(THREAD_CONTINUE_NULL);
		
		lck_mtx_lock(&vm_swap_data_lock);
	}
}


static void
vm_swap_handle_delayed_trims(boolean_t force_now)
{
	struct swapfile *swf = NULL;

	/*
	 * serialize the race between us and vm_swap_reclaim...
	 * if vm_swap_reclaim wins it will turn off SWAP_READY
	 * on the victim it has chosen... we can just skip over
	 * that file since vm_swap_reclaim will first process
	 * all of the delayed trims associated with it
	 */
	lck_mtx_lock(&vm_swap_data_lock);

	delayed_trim_handling_in_progress = TRUE;

	lck_mtx_unlock(&vm_swap_data_lock);

	/*
	 * no need to hold the lock to walk the swf list since
	 * vm_swap_create (the only place where we add to this list)
	 * is run on the same thread as this function
	 * and vm_swap_reclaim doesn't remove items from this list
	 * instead marking them with SWAP_REUSE for future re-use
	 */
	swf = (struct swapfile*) queue_first(&swf_global_queue);

	while (queue_end(&swf_global_queue, (queue_entry_t)swf) == FALSE) {

		if ((swf->swp_flags & SWAP_READY) && (force_now == TRUE || VM_SWAP_SHOULD_TRIM(swf))) {

			assert(!(swf->swp_flags & SWAP_RECLAIM));
			vm_swap_do_delayed_trim(swf);
		}
		swf = (struct swapfile*) queue_next(&swf->swp_queue);
	}
	lck_mtx_lock(&vm_swap_data_lock);

	delayed_trim_handling_in_progress = FALSE;
	thread_wakeup((event_t) &delayed_trim_handling_in_progress);

	if (VM_SWAP_SHOULD_RECLAIM() && !vm_swapfile_gc_thread_running)
		thread_wakeup((event_t) &vm_swapfile_gc_needed);

	lck_mtx_unlock(&vm_swap_data_lock);

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

	vnode_trim_list(swf->swp_vp, tl_head, TRUE);
	
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
	
	if (kernel_memory_allocate(kernel_map, (vm_offset_t *)(&addr), C_SEG_BUFSIZE, 0, KMA_KOBJECT, VM_KERN_MEMORY_COMPRESSOR) != KERN_SUCCESS) {
		panic("vm_swap_reclaim: kernel_memory_allocate failed\n");
	}

	lck_mtx_lock(&vm_swap_data_lock);

	/*
	 * if we're running the swapfile list looking for
	 * candidates with delayed trims, we need to
	 * wait before making our decision concerning
	 * the swapfile we want to reclaim
	 */
	vm_swap_wait_on_trim_handling_in_progress();

	/*
	 * from here until we knock down the SWAP_READY bit,
	 * we need to remain behind the vm_swap_data_lock...
	 * once that bit has been turned off, "vm_swap_handle_delayed_trims"
	 * will not consider this swapfile for processing
	 */
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
	        if (compressor_store_stop_compaction == TRUE || VM_SWAP_SHOULD_ABORT_RECLAIM() || VM_SWAP_BUSY()) {
			vm_swap_reclaim_yielded++;
			break;
		}

		byte_for_segidx = segidx >> 3;
		offset_within_byte = segidx % 8;

		if (((swf->swp_bitmap)[byte_for_segidx] & (1 << offset_within_byte)) == 0) {

			segidx++;
			continue;
		}

		c_seg = swf->swp_csegs[segidx];
		assert(c_seg);

		lck_mtx_lock_spin_always(&c_seg->c_lock);

		if (c_seg->c_busy) {
			/*
			 * a swapped out c_segment in the process of being freed will remain in the
			 * busy state until after the vm_swap_free is called on it... vm_swap_free
			 * takes the vm_swap_data_lock, so can't change the swap state until after
			 * we drop the vm_swap_data_lock... once we do, vm_swap_free will complete
			 * which will allow c_seg_free_locked to clear busy and wake up this thread...
			 * at that point, we re-look up the swap state which will now indicate that
			 * this c_segment no longer exists.
			 */
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

		assert(c_seg == swf->swp_csegs[segidx]);
		swf->swp_csegs[segidx] = NULL;
		swf->swp_nseginuse--;

		vm_swapfile_total_segs_used--;
			
		lck_mtx_unlock(&vm_swap_data_lock);

		assert(C_SEG_IS_ONDISK(c_seg));	

		C_SEG_BUSY(c_seg);
		c_seg->c_busy_swapping = 1;
#if !CHECKSUM_THE_SWAP
		c_seg_trim_tail(c_seg);
#endif
		c_size = round_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset));
		
		assert(c_size <= C_SEG_BUFSIZE && c_size);

		lck_mtx_unlock_always(&c_seg->c_lock);

		if (vm_swapfile_io(swf->swp_vp, f_offset, addr, (int)(c_size / PAGE_SIZE_64), SWAP_READ)) {

			/*
			 * reading the data back in failed, so convert c_seg
			 * to a swapped in c_segment that contains no data
			 */
			c_seg_swapin_requeue(c_seg, FALSE);
			/*
			 * returns with c_busy_swapping cleared
			 */

			vm_swap_get_failures++;
			goto swap_io_failed;
		}
		VM_STAT_INCR_BY(swapins, c_size >> PAGE_SHIFT);

		if (vm_swap_put(addr, &f_offset, c_size, c_seg)) {
			vm_offset_t	c_buffer;

			/*
			 * the put failed, so convert c_seg to a fully swapped in c_segment
			 * with valid data
			 */
			c_buffer = (vm_offset_t)C_SEG_BUFFER_ADDRESS(c_seg->c_mysegno);

			kernel_memory_populate(kernel_map, c_buffer, c_size, KMA_COMPRESSOR, VM_KERN_MEMORY_COMPRESSOR);

			memcpy((char *)c_buffer, (char *)addr, c_size);

			c_seg->c_store.c_buffer = (int32_t *)c_buffer;
#if ENCRYPTED_SWAP
			vm_swap_decrypt(c_seg);
#endif /* ENCRYPTED_SWAP */
			c_seg_swapin_requeue(c_seg, TRUE);
			/*
			 * returns with c_busy_swapping cleared
			 */
			OSAddAtomic64(c_seg->c_bytes_used, &compressor_bytes_used);

			goto swap_io_failed;
		}
		VM_STAT_INCR_BY(swapouts, c_size >> PAGE_SHIFT);

		lck_mtx_lock_spin_always(&c_seg->c_lock);
				
		assert(C_SEG_IS_ONDISK(c_seg));
		/*
		 * The c_seg will now know about the new location on disk.
		 */
		c_seg->c_store.c_swap_handle = f_offset;
		c_seg->c_busy_swapping = 0;
swap_io_failed:
		C_SEG_WAKEUP_DONE(c_seg);
				
		lck_mtx_unlock_always(&c_seg->c_lock);
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
	 * preserve the namespace. The delayed_trim processing
	 * is also dependent on us not removing swfs from the queue.
	 */	 
	//queue_remove(&swf_global_queue, swf, struct swapfile*, swp_queue);

	vm_num_swap_files--;

	vm_swapfile_total_segs_alloced -= swf->swp_nsegs;

	lck_mtx_unlock(&vm_swap_data_lock);

	vm_swapfile_close((uint64_t)(swf->swp_path), swf->swp_vp);

	kfree(swf->swp_csegs, swf->swp_nsegs * sizeof(c_segment_t));
	kfree(swf->swp_bitmap, MAX((swf->swp_nsegs >> 3), 1));
	
	lck_mtx_lock(&vm_swap_data_lock);

	if (swf->swp_flags & SWAP_PINNED) {
		vm_swappin_avail += swf->swp_size;
	}

	swf->swp_vp = NULL;	
	swf->swp_size = 0;
	swf->swp_free_hint = 0;
	swf->swp_nsegs = 0;
	swf->swp_flags = SWAP_REUSE;

done:
	thread_wakeup((event_t) &swf->swp_flags);
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


int
vm_swap_low_on_space(void)
{

	if (vm_num_swap_files == 0 && vm_swapfile_can_be_created == FALSE)
		return (0);

	if (((vm_swapfile_total_segs_alloced - vm_swapfile_total_segs_used) < ((unsigned int)VM_SWAPFILE_HIWATER_SEGS) / 8)) {

		if (vm_num_swap_files == 0 && !SWAPPER_NEEDS_TO_UNTHROTTLE())
			return (0);

		if (vm_swapfile_last_failed_to_create_ts >= vm_swapfile_last_successful_create_ts)
			return (1);
	}
	return (0);
}
