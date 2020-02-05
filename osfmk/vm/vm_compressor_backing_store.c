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
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>

#include <IOKit/IOHibernatePrivate.h>

#include <kern/policy_internal.h>

boolean_t       compressor_store_stop_compaction = FALSE;
boolean_t       vm_swapfile_create_needed = FALSE;
boolean_t       vm_swapfile_gc_needed = FALSE;

int             vm_swapper_throttle = -1;
uint64_t        vm_swapout_thread_id;

uint64_t        vm_swap_put_failures = 0; /* Likely failed I/O. Data is still in memory. */
uint64_t        vm_swap_get_failures = 0; /* Fatal */
uint64_t        vm_swap_put_failures_no_swap_file = 0; /* Possibly not fatal because we might just need a new swapfile. */
int             vm_num_swap_files_config = 0;
int             vm_num_swap_files = 0;
int             vm_num_pinned_swap_files = 0;
int             vm_swapout_thread_processed_segments = 0;
int             vm_swapout_thread_awakened = 0;
int             vm_swapfile_create_thread_awakened = 0;
int             vm_swapfile_create_thread_running = 0;
int             vm_swapfile_gc_thread_awakened = 0;
int             vm_swapfile_gc_thread_running = 0;

int64_t         vm_swappin_avail = 0;
boolean_t       vm_swappin_enabled = FALSE;
unsigned int    vm_swapfile_total_segs_alloced = 0;
unsigned int    vm_swapfile_total_segs_used = 0;

char            swapfilename[MAX_SWAPFILENAME_LEN + 1] = SWAP_FILE_NAME;

extern vm_map_t compressor_map;


#define SWAP_READY      0x1     /* Swap file is ready to be used */
#define SWAP_RECLAIM    0x2     /* Swap file is marked to be reclaimed */
#define SWAP_WANTED     0x4     /* Swap file has waiters */
#define SWAP_REUSE      0x8     /* Swap file is on the Q and has a name. Reuse after init-ing.*/
#define SWAP_PINNED     0x10    /* Swap file is pinned (FusionDrive) */


struct swapfile {
	queue_head_t            swp_queue;      /* list of swap files */
	char                    *swp_path;      /* saved pathname of swap file */
	struct vnode            *swp_vp;        /* backing vnode */
	uint64_t                swp_size;       /* size of this swap file */
	uint8_t                 *swp_bitmap;    /* bitmap showing the alloced/freed slots in the swap file */
	unsigned int            swp_pathlen;    /* length of pathname */
	unsigned int            swp_nsegs;      /* #segments we can use */
	unsigned int            swp_nseginuse;  /* #segments in use */
	unsigned int            swp_index;      /* index of this swap file */
	unsigned int            swp_flags;      /* state of swap file */
	unsigned int            swp_free_hint;  /* offset of 1st free chunk */
	unsigned int            swp_io_count;   /* count of outstanding I/Os */
	c_segment_t             *swp_csegs;     /* back pointers to the c_segments. Used during swap reclaim. */

	struct trim_list        *swp_delayed_trim_list_head;
	unsigned int            swp_delayed_trim_count;
};

queue_head_t    swf_global_queue;
boolean_t       swp_trim_supported = FALSE;

extern clock_sec_t      dont_trim_until_ts;
clock_sec_t             vm_swapfile_last_failed_to_create_ts = 0;
clock_sec_t             vm_swapfile_last_successful_create_ts = 0;
int                     vm_swapfile_can_be_created = FALSE;
boolean_t               delayed_trim_handling_in_progress = FALSE;

boolean_t               hibernate_in_progress_with_pinned_swap = FALSE;

static void vm_swapout_thread_throttle_adjust(void);
static void vm_swap_free_now(struct swapfile *swf, uint64_t f_offset);
static void vm_swapout_thread(void);
static void vm_swapfile_create_thread(void);
static void vm_swapfile_gc_thread(void);
static void vm_swap_defragment(void);
static void vm_swap_handle_delayed_trims(boolean_t);
static void vm_swap_do_delayed_trim(struct swapfile *);
static void vm_swap_wait_on_trim_handling_in_progress(void);


boolean_t vm_swap_force_defrag = FALSE, vm_swap_force_reclaim = FALSE;

#if CONFIG_EMBEDDED

#if DEVELOPMENT || DEBUG
#define VM_MAX_SWAP_FILE_NUM            100
#else /* DEVELOPMENT || DEBUG */
#define VM_MAX_SWAP_FILE_NUM            5
#endif /* DEVELOPMENT || DEBUG */

#define VM_SWAPFILE_DELAYED_TRIM_MAX    4

#define VM_SWAP_SHOULD_DEFRAGMENT()     (((vm_swap_force_defrag == TRUE) || (c_swappedout_sparse_count > (vm_swapfile_total_segs_used / 16))) ? 1 : 0)
#define VM_SWAP_SHOULD_PIN(_size)       FALSE
#define VM_SWAP_SHOULD_CREATE(cur_ts)   ((vm_num_swap_files < vm_num_swap_files_config) && ((vm_swapfile_total_segs_alloced - vm_swapfile_total_segs_used) < (unsigned int)VM_SWAPFILE_HIWATER_SEGS) && \
	                                 ((cur_ts - vm_swapfile_last_failed_to_create_ts) > VM_SWAPFILE_DELAYED_CREATE) ? 1 : 0)
#define VM_SWAP_SHOULD_TRIM(swf)        ((swf->swp_delayed_trim_count >= VM_SWAPFILE_DELAYED_TRIM_MAX) ? 1 : 0)

#else /* CONFIG_EMBEDDED */

#define VM_MAX_SWAP_FILE_NUM            100
#define VM_SWAPFILE_DELAYED_TRIM_MAX    128

#define VM_SWAP_SHOULD_DEFRAGMENT()     (((vm_swap_force_defrag == TRUE) || (c_swappedout_sparse_count > (vm_swapfile_total_segs_used / 4))) ? 1 : 0)
#define VM_SWAP_SHOULD_PIN(_size)       (vm_swappin_avail > 0 && vm_swappin_avail >= (int64_t)(_size))
#define VM_SWAP_SHOULD_CREATE(cur_ts)   ((vm_num_swap_files < vm_num_swap_files_config) && ((vm_swapfile_total_segs_alloced - vm_swapfile_total_segs_used) < (unsigned int)VM_SWAPFILE_HIWATER_SEGS) && \
	                                 ((cur_ts - vm_swapfile_last_failed_to_create_ts) > VM_SWAPFILE_DELAYED_CREATE) ? 1 : 0)
#define VM_SWAP_SHOULD_TRIM(swf)        ((swf->swp_delayed_trim_count >= VM_SWAPFILE_DELAYED_TRIM_MAX) ? 1 : 0)

#endif /* CONFIG_EMBEDDED */

#define VM_SWAP_SHOULD_RECLAIM()        (((vm_swap_force_reclaim == TRUE) || ((vm_swapfile_total_segs_alloced - vm_swapfile_total_segs_used) >= SWAPFILE_RECLAIM_THRESHOLD_SEGS)) ? 1 : 0)
#define VM_SWAP_SHOULD_ABORT_RECLAIM()  (((vm_swap_force_reclaim == FALSE) && ((vm_swapfile_total_segs_alloced - vm_swapfile_total_segs_used) <= SWAPFILE_RECLAIM_MINIMUM_SEGS)) ? 1 : 0)
#define VM_SWAPFILE_DELAYED_CREATE      15

#define VM_SWAP_BUSY()  ((c_swapout_count && (vm_swapper_throttle == THROTTLE_LEVEL_COMPRESSOR_TIER0)) ? 1 : 0)


#if CHECKSUM_THE_SWAP
extern unsigned int hash_string(char *cp, int len);
#endif

#if RECORD_THE_COMPRESSED_DATA
boolean_t       c_compressed_record_init_done = FALSE;
int             c_compressed_record_write_error = 0;
struct vnode    *c_compressed_record_vp = NULL;
uint64_t        c_compressed_record_file_offset = 0;
void    c_compressed_record_init(void);
void    c_compressed_record_write(char *, int);
#endif

extern void                     vm_pageout_io_throttle(void);

static struct swapfile *vm_swapfile_for_handle(uint64_t);

/*
 * Called with the vm_swap_data_lock held.
 */

static struct swapfile *
vm_swapfile_for_handle(uint64_t f_offset)
{
	uint64_t                file_offset = 0;
	unsigned int            swapfile_index = 0;
	struct swapfile*        swf = NULL;

	file_offset = (f_offset & SWAP_SLOT_MASK);
	swapfile_index = (f_offset >> SWAP_DEVICE_SHIFT);

	swf = (struct swapfile*) queue_first(&swf_global_queue);

	while (queue_end(&swf_global_queue, (queue_entry_t)swf) == FALSE) {
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

#if ENCRYPTED_SWAP

#include <libkern/crypto/aesxts.h>

extern int cc_rand_generate(void *, size_t);     /* from libkern/cyrpto/rand.h> */

boolean_t       swap_crypt_initialized;
void            swap_crypt_initialize(void);

symmetric_xts   xts_modectx;
uint32_t        swap_crypt_key1[8];   /* big enough for a 256 bit random key */
uint32_t        swap_crypt_key2[8];   /* big enough for a 256 bit random key */

#if DEVELOPMENT || DEBUG
boolean_t       swap_crypt_xts_tested = FALSE;
unsigned char   swap_crypt_test_page_ref[4096] __attribute__((aligned(4096)));
unsigned char   swap_crypt_test_page_encrypt[4096] __attribute__((aligned(4096)));
unsigned char   swap_crypt_test_page_decrypt[4096] __attribute__((aligned(4096)));
#endif /* DEVELOPMENT || DEBUG */

unsigned long   vm_page_encrypt_counter;
unsigned long   vm_page_decrypt_counter;


void
swap_crypt_initialize(void)
{
	uint8_t  *enckey1, *enckey2;
	int      keylen1, keylen2;
	int      error;

	assert(swap_crypt_initialized == FALSE);

	keylen1 = sizeof(swap_crypt_key1);
	enckey1 = (uint8_t *)&swap_crypt_key1;
	keylen2 = sizeof(swap_crypt_key2);
	enckey2 = (uint8_t *)&swap_crypt_key2;

	error = cc_rand_generate((void *)enckey1, keylen1);
	assert(!error);

	error = cc_rand_generate((void *)enckey2, keylen2);
	assert(!error);

	error = xts_start(0, NULL, enckey1, keylen1, enckey2, keylen2, 0, 0, &xts_modectx);
	assert(!error);

	swap_crypt_initialized = TRUE;

#if DEVELOPMENT || DEBUG
	uint8_t *encptr;
	uint8_t *decptr;
	uint8_t *refptr;
	uint8_t *iv;
	uint64_t ivnum[2];
	int size = 0;
	int i    = 0;
	int rc   = 0;

	assert(swap_crypt_xts_tested == FALSE);

	/*
	 * Validate the encryption algorithms.
	 *
	 * First initialize the test data.
	 */
	for (i = 0; i < 4096; i++) {
		swap_crypt_test_page_ref[i] = (char) i;
	}
	ivnum[0] = (uint64_t)0xaa;
	ivnum[1] = 0;
	iv = (uint8_t *)ivnum;

	refptr = (uint8_t *)swap_crypt_test_page_ref;
	encptr = (uint8_t *)swap_crypt_test_page_encrypt;
	decptr = (uint8_t *)swap_crypt_test_page_decrypt;
	size = 4096;

	/* encrypt */
	rc = xts_encrypt(refptr, size, encptr, iv, &xts_modectx);
	assert(!rc);

	/* compare result with original - should NOT match */
	for (i = 0; i < 4096; i++) {
		if (swap_crypt_test_page_encrypt[i] !=
		    swap_crypt_test_page_ref[i]) {
			break;
		}
	}
	assert(i != 4096);

	/* decrypt */
	rc = xts_decrypt(encptr, size, decptr, iv, &xts_modectx);
	assert(!rc);

	/* compare result with original */
	for (i = 0; i < 4096; i++) {
		if (swap_crypt_test_page_decrypt[i] !=
		    swap_crypt_test_page_ref[i]) {
			panic("encryption test failed");
		}
	}
	/* encrypt in place */
	rc = xts_encrypt(decptr, size, decptr, iv, &xts_modectx);
	assert(!rc);

	/* decrypt in place */
	rc = xts_decrypt(decptr, size, decptr, iv, &xts_modectx);
	assert(!rc);

	for (i = 0; i < 4096; i++) {
		if (swap_crypt_test_page_decrypt[i] !=
		    swap_crypt_test_page_ref[i]) {
			panic("in place encryption test failed");
		}
	}
	swap_crypt_xts_tested = TRUE;
#endif /* DEVELOPMENT || DEBUG */
}


void
vm_swap_encrypt(c_segment_t c_seg)
{
	uint8_t *ptr;
	uint8_t *iv;
	uint64_t ivnum[2];
	int size = 0;
	int rc   = 0;

	if (swap_crypt_initialized == FALSE) {
		swap_crypt_initialize();
	}

#if DEVELOPMENT || DEBUG
	C_SEG_MAKE_WRITEABLE(c_seg);
#endif
	ptr = (uint8_t *)c_seg->c_store.c_buffer;
	size = round_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset));

	ivnum[0] = (uint64_t)c_seg;
	ivnum[1] = 0;
	iv = (uint8_t *)ivnum;

	rc = xts_encrypt(ptr, size, ptr, iv, &xts_modectx);
	assert(!rc);

	vm_page_encrypt_counter += (size / PAGE_SIZE_64);

#if DEVELOPMENT || DEBUG
	C_SEG_WRITE_PROTECT(c_seg);
#endif
}

void
vm_swap_decrypt(c_segment_t c_seg)
{
	uint8_t *ptr;
	uint8_t *iv;
	uint64_t ivnum[2];
	int size = 0;
	int rc   = 0;

	assert(swap_crypt_initialized);

#if DEVELOPMENT || DEBUG
	C_SEG_MAKE_WRITEABLE(c_seg);
#endif
	ptr = (uint8_t *)c_seg->c_store.c_buffer;
	size = round_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset));

	ivnum[0] = (uint64_t)c_seg;
	ivnum[1] = 0;
	iv = (uint8_t *)ivnum;

	rc = xts_decrypt(ptr, size, ptr, iv, &xts_modectx);
	assert(!rc);

	vm_page_decrypt_counter += (size / PAGE_SIZE_64);

#if DEVELOPMENT || DEBUG
	C_SEG_WRITE_PROTECT(c_seg);
#endif
}
#endif /* ENCRYPTED_SWAP */


void
vm_compressor_swap_init()
{
	thread_t        thread = NULL;

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
	    BASEPRI_VM, &thread) != KERN_SUCCESS) {
		panic("vm_swapout_thread: create failed");
	}
	thread_set_thread_name(thread, "VM_swapout");
	vm_swapout_thread_id = thread->thread_id;

	thread_deallocate(thread);

	if (kernel_thread_start_priority((thread_continue_t)vm_swapfile_create_thread, NULL,
	    BASEPRI_VM, &thread) != KERN_SUCCESS) {
		panic("vm_swapfile_create_thread: create failed");
	}

	thread_set_thread_name(thread, "VM_swapfile_create");
	thread_deallocate(thread);

	if (kernel_thread_start_priority((thread_continue_t)vm_swapfile_gc_thread, NULL,
	    BASEPRI_VM, &thread) != KERN_SUCCESS) {
		panic("vm_swapfile_gc_thread: create failed");
	}
	thread_set_thread_name(thread, "VM_swapfile_gc");

	/*
	 * Swapfile garbage collection will need to allocate memory
	 * to complete its swap reclaim and in-memory compaction.
	 * So allow it to dip into the reserved VM page pool.
	 */
	thread_lock(thread);
	thread->options |= TH_OPT_VMPRIV;
	thread_unlock(thread);

	thread_deallocate(thread);

	proc_set_thread_policy_with_tid(kernel_task, thread->thread_id,
	    TASK_POLICY_INTERNAL, TASK_POLICY_IO, THROTTLE_LEVEL_COMPRESSOR_TIER2);
	proc_set_thread_policy_with_tid(kernel_task, thread->thread_id,
	    TASK_POLICY_INTERNAL, TASK_POLICY_PASSIVE_IO, TASK_POLICY_ENABLE);

#if CONFIG_EMBEDDED
	/*
	 * dummy value until the swap file gets created
	 * when we drive the first c_segment_t to the
	 * swapout queue... at that time we will
	 * know the true size we have to work with
	 */
	c_overage_swapped_limit = 16;
#endif

	vm_num_swap_files_config = VM_MAX_SWAP_FILE_NUM;

	printf("VM Swap Subsystem is ON\n");
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


int             compaction_swapper_inited = 0;

void
vm_compaction_swapper_do_init(void)
{
	struct  vnode *vp;
	char    *pathname;
	int     namelen;

	if (compaction_swapper_inited) {
		return;
	}

	if (vm_compressor_mode != VM_PAGER_COMPRESSOR_WITH_SWAP) {
		compaction_swapper_inited = 1;
		return;
	}
	lck_mtx_lock(&vm_swap_data_lock);

	if (!compaction_swapper_inited) {
		namelen = (int)strlen(swapfilename) + SWAPFILENAME_INDEX_LEN + 1;
		pathname = (char*)kalloc(namelen);
		memset(pathname, 0, namelen);
		snprintf(pathname, namelen, "%s%d", swapfilename, 0);

		vm_swapfile_open(pathname, &vp);

		if (vp) {
			if (vnode_pager_isSSD(vp) == FALSE) {
				/*
				 * swap files live on an HDD, so let's make sure to start swapping
				 * much earlier since we're not worried about SSD write-wear and
				 * we have so little write bandwidth to work with
				 * these values were derived expermentially by running the performance
				 * teams stock test for evaluating HDD performance against various
				 * combinations and looking and comparing overall results.
				 * Note that the > relationship between these 4 values must be maintained
				 */
				if (vm_compressor_minorcompact_threshold_divisor_overridden == 0) {
					vm_compressor_minorcompact_threshold_divisor = 15;
				}
				if (vm_compressor_majorcompact_threshold_divisor_overridden == 0) {
					vm_compressor_majorcompact_threshold_divisor = 18;
				}
				if (vm_compressor_unthrottle_threshold_divisor_overridden == 0) {
					vm_compressor_unthrottle_threshold_divisor = 24;
				}
				if (vm_compressor_catchup_threshold_divisor_overridden == 0) {
					vm_compressor_catchup_threshold_divisor = 30;
				}
			}
#if !CONFIG_EMBEDDED
			vnode_setswapmount(vp);
			vm_swappin_avail = vnode_getswappin_avail(vp);

			if (vm_swappin_avail) {
				vm_swappin_enabled = TRUE;
			}
#endif
			vm_swapfile_close((uint64_t)pathname, vp);
		}
		kfree(pathname, namelen);

		compaction_swapper_inited = 1;
	}
	lck_mtx_unlock(&vm_swap_data_lock);
}


void
vm_swap_consider_defragmenting(int flags)
{
	boolean_t force_defrag = (flags & VM_SWAP_FLAGS_FORCE_DEFRAG);
	boolean_t force_reclaim = (flags & VM_SWAP_FLAGS_FORCE_RECLAIM);

	if (compressor_store_stop_compaction == FALSE && !VM_SWAP_BUSY() &&
	    (force_defrag || force_reclaim || VM_SWAP_SHOULD_DEFRAGMENT() || VM_SWAP_SHOULD_RECLAIM())) {
		if (!vm_swapfile_gc_thread_running || force_defrag || force_reclaim) {
			lck_mtx_lock(&vm_swap_data_lock);

			if (force_defrag) {
				vm_swap_force_defrag = TRUE;
			}

			if (force_reclaim) {
				vm_swap_force_reclaim = TRUE;
			}

			if (!vm_swapfile_gc_thread_running) {
				thread_wakeup((event_t) &vm_swapfile_gc_needed);
			}

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
	c_segment_t     c_seg;

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

			if (c_seg_swapin(c_seg, TRUE, FALSE) == 0) {
				lck_mtx_unlock_always(&c_seg->c_lock);
			}

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
	clock_sec_t     sec;
	clock_nsec_t    nsec;

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

		if (hibernate_in_progress_with_pinned_swap == TRUE) {
			break;
		}

		if (compressor_store_stop_compaction == TRUE) {
			break;
		}

		clock_get_system_nanotime(&sec, &nsec);

		if (VM_SWAP_SHOULD_CREATE(sec) == 0) {
			break;
		}

		lck_mtx_unlock(&vm_swap_data_lock);

		if (vm_swap_create_file() == FALSE) {
			vm_swapfile_last_failed_to_create_ts = sec;
			HIBLOG("vm_swap_create_file failed @ %lu secs\n", (unsigned long)sec);
		} else {
			vm_swapfile_last_successful_create_ts = sec;
		}
	}
	vm_swapfile_create_thread_running = 0;

	if (hibernate_in_progress_with_pinned_swap == TRUE) {
		thread_wakeup((event_t)&hibernate_in_progress_with_pinned_swap);
	}

	if (compressor_store_stop_compaction == TRUE) {
		thread_wakeup((event_t)&compressor_store_stop_compaction);
	}

	assert_wait((event_t)&vm_swapfile_create_needed, THREAD_UNINT);

	lck_mtx_unlock(&vm_swap_data_lock);

	thread_block((thread_continue_t)vm_swapfile_create_thread);

	/* NOTREACHED */
}


#if HIBERNATION

kern_return_t
hibernate_pin_swap(boolean_t start)
{
	vm_compaction_swapper_do_init();

	if (start == FALSE) {
		lck_mtx_lock(&vm_swap_data_lock);
		hibernate_in_progress_with_pinned_swap = FALSE;
		lck_mtx_unlock(&vm_swap_data_lock);

		return KERN_SUCCESS;
	}
	if (vm_swappin_enabled == FALSE) {
		return KERN_SUCCESS;
	}

	lck_mtx_lock(&vm_swap_data_lock);

	hibernate_in_progress_with_pinned_swap = TRUE;

	while (vm_swapfile_create_thread_running || vm_swapfile_gc_thread_running) {
		assert_wait((event_t)&hibernate_in_progress_with_pinned_swap, THREAD_UNINT);

		lck_mtx_unlock(&vm_swap_data_lock);

		thread_block(THREAD_CONTINUE_NULL);

		lck_mtx_lock(&vm_swap_data_lock);
	}
	if (vm_num_swap_files > vm_num_pinned_swap_files) {
		hibernate_in_progress_with_pinned_swap = FALSE;
		lck_mtx_unlock(&vm_swap_data_lock);

		HIBLOG("hibernate_pin_swap failed - vm_num_swap_files = %d, vm_num_pinned_swap_files = %d\n",
		    vm_num_swap_files, vm_num_pinned_swap_files);
		return KERN_FAILURE;
	}
	lck_mtx_unlock(&vm_swap_data_lock);

	while (VM_SWAP_SHOULD_PIN(MAX_SWAP_FILE_SIZE)) {
		if (vm_swap_create_file() == FALSE) {
			break;
		}
	}
	return KERN_SUCCESS;
}
#endif

static void
vm_swapfile_gc_thread(void)
{
	boolean_t       need_defragment;
	boolean_t       need_reclaim;

	vm_swapfile_gc_thread_awakened++;
	vm_swapfile_gc_thread_running = 1;

	while (TRUE) {
		lck_mtx_lock(&vm_swap_data_lock);

		if (hibernate_in_progress_with_pinned_swap == TRUE) {
			break;
		}

		if (VM_SWAP_BUSY() || compressor_store_stop_compaction == TRUE) {
			break;
		}

		need_defragment = FALSE;
		need_reclaim = FALSE;

		if (VM_SWAP_SHOULD_DEFRAGMENT()) {
			need_defragment = TRUE;
		}

		if (VM_SWAP_SHOULD_RECLAIM()) {
			need_defragment = TRUE;
			need_reclaim = TRUE;
		}
		if (need_defragment == FALSE && need_reclaim == FALSE) {
			break;
		}

		vm_swap_force_defrag = FALSE;
		vm_swap_force_reclaim = FALSE;

		lck_mtx_unlock(&vm_swap_data_lock);

		if (need_defragment == TRUE) {
			vm_swap_defragment();
		}
		if (need_reclaim == TRUE) {
			vm_swap_reclaim();
		}
	}
	vm_swapfile_gc_thread_running = 0;

	if (hibernate_in_progress_with_pinned_swap == TRUE) {
		thread_wakeup((event_t)&hibernate_in_progress_with_pinned_swap);
	}

	if (compressor_store_stop_compaction == TRUE) {
		thread_wakeup((event_t)&compressor_store_stop_compaction);
	}

	assert_wait((event_t)&vm_swapfile_gc_needed, THREAD_UNINT);

	lck_mtx_unlock(&vm_swap_data_lock);

	thread_block((thread_continue_t)vm_swapfile_gc_thread);

	/* NOTREACHED */
}



#define   VM_SWAPOUT_LIMIT_T2P  4
#define   VM_SWAPOUT_LIMIT_T1P  4
#define   VM_SWAPOUT_LIMIT_T0P  6
#define   VM_SWAPOUT_LIMIT_T0   8
#define   VM_SWAPOUT_LIMIT_MAX  8

#define   VM_SWAPOUT_START      0
#define   VM_SWAPOUT_T2_PASSIVE 1
#define   VM_SWAPOUT_T1_PASSIVE 2
#define   VM_SWAPOUT_T0_PASSIVE 3
#define   VM_SWAPOUT_T0         4

int vm_swapout_state = VM_SWAPOUT_START;
int vm_swapout_limit = 1;

int vm_swapper_entered_T0  = 0;
int vm_swapper_entered_T0P = 0;
int vm_swapper_entered_T1P = 0;
int vm_swapper_entered_T2P = 0;


static void
vm_swapout_thread_throttle_adjust(void)
{
	switch (vm_swapout_state) {
	case VM_SWAPOUT_START:

		vm_swapper_throttle = THROTTLE_LEVEL_COMPRESSOR_TIER2;
		vm_swapper_entered_T2P++;

		proc_set_thread_policy_with_tid(kernel_task, vm_swapout_thread_id,
		    TASK_POLICY_INTERNAL, TASK_POLICY_IO, vm_swapper_throttle);
		proc_set_thread_policy_with_tid(kernel_task, vm_swapout_thread_id,
		    TASK_POLICY_INTERNAL, TASK_POLICY_PASSIVE_IO, TASK_POLICY_ENABLE);
		vm_swapout_limit = VM_SWAPOUT_LIMIT_T2P;
		vm_swapout_state = VM_SWAPOUT_T2_PASSIVE;

		break;

	case VM_SWAPOUT_T2_PASSIVE:

		if (SWAPPER_NEEDS_TO_UNTHROTTLE()) {
			vm_swapper_throttle = THROTTLE_LEVEL_COMPRESSOR_TIER0;
			vm_swapper_entered_T0P++;

			proc_set_thread_policy_with_tid(kernel_task, vm_swapout_thread_id,
			    TASK_POLICY_INTERNAL, TASK_POLICY_IO, vm_swapper_throttle);
			proc_set_thread_policy_with_tid(kernel_task, vm_swapout_thread_id,
			    TASK_POLICY_INTERNAL, TASK_POLICY_PASSIVE_IO, TASK_POLICY_ENABLE);
			vm_swapout_limit = VM_SWAPOUT_LIMIT_T0P;
			vm_swapout_state = VM_SWAPOUT_T0_PASSIVE;

			break;
		}
		if (swapout_target_age || hibernate_flushing == TRUE) {
			vm_swapper_throttle = THROTTLE_LEVEL_COMPRESSOR_TIER1;
			vm_swapper_entered_T1P++;

			proc_set_thread_policy_with_tid(kernel_task, vm_swapout_thread_id,
			    TASK_POLICY_INTERNAL, TASK_POLICY_IO, vm_swapper_throttle);
			proc_set_thread_policy_with_tid(kernel_task, vm_swapout_thread_id,
			    TASK_POLICY_INTERNAL, TASK_POLICY_PASSIVE_IO, TASK_POLICY_ENABLE);
			vm_swapout_limit = VM_SWAPOUT_LIMIT_T1P;
			vm_swapout_state = VM_SWAPOUT_T1_PASSIVE;
		}
		break;

	case VM_SWAPOUT_T1_PASSIVE:

		if (SWAPPER_NEEDS_TO_UNTHROTTLE()) {
			vm_swapper_throttle = THROTTLE_LEVEL_COMPRESSOR_TIER0;
			vm_swapper_entered_T0P++;

			proc_set_thread_policy_with_tid(kernel_task, vm_swapout_thread_id,
			    TASK_POLICY_INTERNAL, TASK_POLICY_IO, vm_swapper_throttle);
			proc_set_thread_policy_with_tid(kernel_task, vm_swapout_thread_id,
			    TASK_POLICY_INTERNAL, TASK_POLICY_PASSIVE_IO, TASK_POLICY_ENABLE);
			vm_swapout_limit = VM_SWAPOUT_LIMIT_T0P;
			vm_swapout_state = VM_SWAPOUT_T0_PASSIVE;

			break;
		}
		if (swapout_target_age == 0 && hibernate_flushing == FALSE) {
			vm_swapper_throttle = THROTTLE_LEVEL_COMPRESSOR_TIER2;
			vm_swapper_entered_T2P++;

			proc_set_thread_policy_with_tid(kernel_task, vm_swapout_thread_id,
			    TASK_POLICY_INTERNAL, TASK_POLICY_IO, vm_swapper_throttle);
			proc_set_thread_policy_with_tid(kernel_task, vm_swapout_thread_id,
			    TASK_POLICY_INTERNAL, TASK_POLICY_PASSIVE_IO, TASK_POLICY_ENABLE);
			vm_swapout_limit = VM_SWAPOUT_LIMIT_T2P;
			vm_swapout_state = VM_SWAPOUT_T2_PASSIVE;
		}
		break;

	case VM_SWAPOUT_T0_PASSIVE:

		if (SWAPPER_NEEDS_TO_RETHROTTLE()) {
			vm_swapper_throttle = THROTTLE_LEVEL_COMPRESSOR_TIER2;
			vm_swapper_entered_T2P++;

			proc_set_thread_policy_with_tid(kernel_task, vm_swapout_thread_id,
			    TASK_POLICY_INTERNAL, TASK_POLICY_IO, vm_swapper_throttle);
			proc_set_thread_policy_with_tid(kernel_task, vm_swapout_thread_id,
			    TASK_POLICY_INTERNAL, TASK_POLICY_PASSIVE_IO, TASK_POLICY_ENABLE);
			vm_swapout_limit = VM_SWAPOUT_LIMIT_T2P;
			vm_swapout_state = VM_SWAPOUT_T2_PASSIVE;

			break;
		}
		if (SWAPPER_NEEDS_TO_CATCHUP()) {
			vm_swapper_entered_T0++;

			proc_set_thread_policy_with_tid(kernel_task, vm_swapout_thread_id,
			    TASK_POLICY_INTERNAL, TASK_POLICY_PASSIVE_IO, TASK_POLICY_DISABLE);
			vm_swapout_limit = VM_SWAPOUT_LIMIT_T0;
			vm_swapout_state = VM_SWAPOUT_T0;
		}
		break;

	case VM_SWAPOUT_T0:

		if (SWAPPER_HAS_CAUGHTUP()) {
			vm_swapper_entered_T0P++;

			proc_set_thread_policy_with_tid(kernel_task, vm_swapout_thread_id,
			    TASK_POLICY_INTERNAL, TASK_POLICY_PASSIVE_IO, TASK_POLICY_ENABLE);
			vm_swapout_limit = VM_SWAPOUT_LIMIT_T0P;
			vm_swapout_state = VM_SWAPOUT_T0_PASSIVE;
		}
		break;
	}
}

int vm_swapout_found_empty = 0;

struct swapout_io_completion vm_swapout_ctx[VM_SWAPOUT_LIMIT_MAX];

int vm_swapout_soc_busy = 0;
int vm_swapout_soc_done = 0;


static struct swapout_io_completion *
vm_swapout_find_free_soc(void)
{
	int      i;

	for (i = 0; i < VM_SWAPOUT_LIMIT_MAX; i++) {
		if (vm_swapout_ctx[i].swp_io_busy == 0) {
			return &vm_swapout_ctx[i];
		}
	}
	assert(vm_swapout_soc_busy == VM_SWAPOUT_LIMIT_MAX);

	return NULL;
}

static struct swapout_io_completion *
vm_swapout_find_done_soc(void)
{
	int      i;

	if (vm_swapout_soc_done) {
		for (i = 0; i < VM_SWAPOUT_LIMIT_MAX; i++) {
			if (vm_swapout_ctx[i].swp_io_done) {
				return &vm_swapout_ctx[i];
			}
		}
	}
	return NULL;
}

static void
vm_swapout_complete_soc(struct swapout_io_completion *soc)
{
	kern_return_t  kr;

	if (soc->swp_io_error) {
		kr = KERN_FAILURE;
	} else {
		kr = KERN_SUCCESS;
	}

	lck_mtx_unlock_always(c_list_lock);

	vm_swap_put_finish(soc->swp_swf, &soc->swp_f_offset, soc->swp_io_error);
	vm_swapout_finish(soc->swp_c_seg, soc->swp_f_offset, soc->swp_c_size, kr);

	lck_mtx_lock_spin_always(c_list_lock);

	soc->swp_io_done = 0;
	soc->swp_io_busy = 0;

	vm_swapout_soc_busy--;
	vm_swapout_soc_done--;
}


static void
vm_swapout_thread(void)
{
	uint32_t        size = 0;
	c_segment_t     c_seg = NULL;
	kern_return_t   kr = KERN_SUCCESS;
	struct swapout_io_completion *soc;

	current_thread()->options |= TH_OPT_VMPRIV;

	vm_swapout_thread_awakened++;

	lck_mtx_lock_spin_always(c_list_lock);
again:
	while (!queue_empty(&c_swapout_list_head) && vm_swapout_soc_busy < vm_swapout_limit) {
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

			if (!c_seg->c_on_minorcompact_q) {
				c_seg_need_delayed_compaction(c_seg, TRUE);
			}

			c_seg_switch_state(c_seg, C_IS_EMPTY, FALSE);
			lck_mtx_unlock_always(&c_seg->c_lock);
			lck_mtx_unlock_always(c_list_lock);

			vm_swapout_found_empty++;
			goto c_seg_is_empty;
		}
		C_SEG_BUSY(c_seg);
		c_seg->c_busy_swapping = 1;

		c_seg_switch_state(c_seg, C_ON_SWAPIO_Q, FALSE);

		lck_mtx_unlock_always(c_list_lock);
		lck_mtx_unlock_always(&c_seg->c_lock);

#if CHECKSUM_THE_SWAP
		c_seg->cseg_hash = hash_string((char *)c_seg->c_store.c_buffer, (int)size);
		c_seg->cseg_swap_size = size;
#endif /* CHECKSUM_THE_SWAP */

#if ENCRYPTED_SWAP
		vm_swap_encrypt(c_seg);
#endif /* ENCRYPTED_SWAP */

		soc = vm_swapout_find_free_soc();
		assert(soc);

		soc->swp_upl_ctx.io_context = (void *)soc;
		soc->swp_upl_ctx.io_done = (void *)vm_swapout_iodone;
		soc->swp_upl_ctx.io_error = 0;

		kr = vm_swap_put((vm_offset_t)c_seg->c_store.c_buffer, &soc->swp_f_offset, size, c_seg, soc);

		if (kr != KERN_SUCCESS) {
			if (soc->swp_io_done) {
				lck_mtx_lock_spin_always(c_list_lock);

				soc->swp_io_done = 0;
				vm_swapout_soc_done--;

				lck_mtx_unlock_always(c_list_lock);
			}
			vm_swapout_finish(c_seg, soc->swp_f_offset, size, kr);
		} else {
			soc->swp_io_busy = 1;
			vm_swapout_soc_busy++;
		}

c_seg_is_empty:
		if (c_swapout_count == 0) {
			vm_swap_consider_defragmenting(VM_SWAP_FLAGS_NONE);
		}

		lck_mtx_lock_spin_always(c_list_lock);

		if ((soc = vm_swapout_find_done_soc())) {
			vm_swapout_complete_soc(soc);
		}
		lck_mtx_unlock_always(c_list_lock);

		vm_swapout_thread_throttle_adjust();
		vm_pageout_io_throttle();

		lck_mtx_lock_spin_always(c_list_lock);
	}
	if ((soc = vm_swapout_find_done_soc())) {
		vm_swapout_complete_soc(soc);
		goto again;
	}
	assert_wait((event_t)&c_swapout_list_head, THREAD_UNINT);

	lck_mtx_unlock_always(c_list_lock);

	thread_block((thread_continue_t)vm_swapout_thread);

	/* NOTREACHED */
}


void
vm_swapout_iodone(void *io_context, int error)
{
	struct swapout_io_completion *soc;

	soc = (struct swapout_io_completion *)io_context;

	lck_mtx_lock_spin_always(c_list_lock);

	soc->swp_io_done = 1;
	soc->swp_io_error = error;
	vm_swapout_soc_done++;

	thread_wakeup((event_t)&c_swapout_list_head);

	lck_mtx_unlock_always(c_list_lock);
}


static void
vm_swapout_finish(c_segment_t c_seg, uint64_t f_offset, uint32_t size, kern_return_t kr)
{
	PAGE_REPLACEMENT_DISALLOWED(TRUE);

	if (kr == KERN_SUCCESS) {
		kernel_memory_depopulate(compressor_map, (vm_offset_t)c_seg->c_store.c_buffer, size, KMA_COMPRESSOR);
	}
#if ENCRYPTED_SWAP
	else {
		vm_swap_decrypt(c_seg);
	}
#endif /* ENCRYPTED_SWAP */
	lck_mtx_lock_spin_always(c_list_lock);
	lck_mtx_lock_spin_always(&c_seg->c_lock);

	if (kr == KERN_SUCCESS) {
		int             new_state = C_ON_SWAPPEDOUT_Q;
		boolean_t       insert_head = FALSE;

		if (hibernate_flushing == TRUE) {
			if (c_seg->c_generation_id >= first_c_segment_to_warm_generation_id &&
			    c_seg->c_generation_id <= last_c_segment_to_warm_generation_id) {
				insert_head = TRUE;
			}
		} else if (C_SEG_ONDISK_IS_SPARSE(c_seg)) {
			new_state = C_ON_SWAPPEDOUTSPARSE_Q;
		}

		c_seg_switch_state(c_seg, new_state, insert_head);

		c_seg->c_store.c_swap_handle = f_offset;

		VM_STAT_INCR_BY(swapouts, size >> PAGE_SHIFT);

		if (c_seg->c_bytes_used) {
			OSAddAtomic64(-c_seg->c_bytes_used, &compressor_bytes_used);
		}
	} else {
		if (c_seg->c_overage_swap == TRUE) {
			c_seg->c_overage_swap = FALSE;
			c_overage_swapped_count--;
		}
		c_seg_switch_state(c_seg, C_ON_AGE_Q, FALSE);

		if (!c_seg->c_on_minorcompact_q && C_SEG_UNUSED_BYTES(c_seg) >= PAGE_SIZE) {
			c_seg_need_delayed_compaction(c_seg, TRUE);
		}
	}
	assert(c_seg->c_busy_swapping);
	assert(c_seg->c_busy);

	c_seg->c_busy_swapping = 0;
	lck_mtx_unlock_always(c_list_lock);

	C_SEG_WAKEUP_DONE(c_seg);
	lck_mtx_unlock_always(&c_seg->c_lock);

	PAGE_REPLACEMENT_DISALLOWED(FALSE);
}


boolean_t
vm_swap_create_file()
{
	uint64_t        size = 0;
	int             namelen = 0;
	boolean_t       swap_file_created = FALSE;
	boolean_t       swap_file_reuse = FALSE;
	boolean_t       swap_file_pin = FALSE;
	struct swapfile *swf = NULL;

	/*
	 * make sure we've got all the info we need
	 * to potentially pin a swap file... we could
	 * be swapping out due to hibernation w/o ever
	 * having run vm_pageout_scan, which is normally
	 * the trigger to do the init
	 */
	vm_compaction_swapper_do_init();

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

			num_bytes_for_bitmap = MAX((swf->swp_nsegs >> 3), 1);
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
			if (vnode_trim_list(swf->swp_vp, NULL, FALSE) == 0) {
				swp_trim_supported = TRUE;
			}

			lck_mtx_lock(&vm_swap_data_lock);

			swf->swp_flags = SWAP_READY;

			if (swap_file_reuse == FALSE) {
				queue_enter(&swf_global_queue, swf, struct swapfile*, swp_queue);
			}

			vm_num_swap_files++;

			vm_swapfile_total_segs_alloced += swf->swp_nsegs;

			if (swap_file_pin == TRUE) {
				vm_num_pinned_swap_files++;
				swf->swp_flags |= SWAP_PINNED;
				vm_swappin_avail -= swf->swp_size;
			}

			lck_mtx_unlock(&vm_swap_data_lock);

			thread_wakeup((event_t) &vm_num_swap_files);
#if CONFIG_EMBEDDED
			if (vm_num_swap_files == 1) {
				c_overage_swapped_limit = (uint32_t)size / C_SEG_BUFSIZE;

				if (VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
					c_overage_swapped_limit /= 2;
				}
			}
#endif
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
vm_swap_get(c_segment_t c_seg, uint64_t f_offset, uint64_t size)
{
	struct swapfile *swf = NULL;
	uint64_t        file_offset = 0;
	int             retval = 0;

	assert(c_seg->c_store.c_buffer);

	lck_mtx_lock(&vm_swap_data_lock);

	swf = vm_swapfile_for_handle(f_offset);

	if (swf == NULL || (!(swf->swp_flags & SWAP_READY) && !(swf->swp_flags & SWAP_RECLAIM))) {
		vm_swap_get_failures++;
		retval = 1;
		goto done;
	}
	swf->swp_io_count++;

	lck_mtx_unlock(&vm_swap_data_lock);

#if DEVELOPMENT || DEBUG
	C_SEG_MAKE_WRITEABLE(c_seg);
#endif
	file_offset = (f_offset & SWAP_SLOT_MASK);
	retval = vm_swapfile_io(swf->swp_vp, file_offset, (uint64_t)c_seg->c_store.c_buffer, (int)(size / PAGE_SIZE_64), SWAP_READ, NULL);

#if DEVELOPMENT || DEBUG
	C_SEG_WRITE_PROTECT(c_seg);
#endif
	if (retval == 0) {
		VM_STAT_INCR_BY(swapins, size >> PAGE_SHIFT);
	} else {
		vm_swap_get_failures++;
	}

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

	if (retval == 0) {
		return KERN_SUCCESS;
	} else {
		return KERN_FAILURE;
	}
}

kern_return_t
vm_swap_put(vm_offset_t addr, uint64_t *f_offset, uint32_t size, c_segment_t c_seg, struct swapout_io_completion *soc)
{
	unsigned int    segidx = 0;
	struct swapfile *swf = NULL;
	uint64_t        file_offset = 0;
	uint64_t        swapfile_index = 0;
	unsigned int    byte_for_segidx = 0;
	unsigned int    offset_within_byte = 0;
	boolean_t       swf_eligible = FALSE;
	boolean_t       waiting = FALSE;
	boolean_t       retried = FALSE;
	int             error = 0;
	clock_sec_t     sec;
	clock_nsec_t    nsec;
	void            *upl_ctx = NULL;

	if (addr == 0 || f_offset == NULL) {
		return KERN_FAILURE;
	}
retry:
	lck_mtx_lock(&vm_swap_data_lock);

	swf = (struct swapfile*) queue_first(&swf_global_queue);

	while (queue_end(&swf_global_queue, (queue_entry_t)swf) == FALSE) {
		segidx = swf->swp_free_hint;

		swf_eligible =  (swf->swp_flags & SWAP_READY) && (swf->swp_nseginuse < swf->swp_nsegs);

		if (swf_eligible) {
			while (segidx < swf->swp_nsegs) {
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
				swf->swp_csegs[segidx] = c_seg;

				swapfile_index = swf->swp_index;
				vm_swapfile_total_segs_used++;

				clock_get_system_nanotime(&sec, &nsec);

				if (VM_SWAP_SHOULD_CREATE(sec) && !vm_swapfile_create_thread_running) {
					thread_wakeup((event_t) &vm_swapfile_create_needed);
				}

				lck_mtx_unlock(&vm_swap_data_lock);

				goto issue_io;
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

	if (VM_SWAP_SHOULD_CREATE(sec) && !vm_swapfile_create_thread_running) {
		thread_wakeup((event_t) &vm_swapfile_create_needed);
	}

	if (hibernate_flushing == FALSE || VM_SWAP_SHOULD_CREATE(sec)) {
		waiting = TRUE;
		assert_wait_timeout((event_t) &vm_num_swap_files, THREAD_INTERRUPTIBLE, 1000, 1000 * NSEC_PER_USEC);
	} else {
		hibernate_no_swapspace = TRUE;
	}

	lck_mtx_unlock(&vm_swap_data_lock);

	if (waiting == TRUE) {
		thread_block(THREAD_CONTINUE_NULL);

		if (retried == FALSE && hibernate_flushing == TRUE) {
			retried = TRUE;
			goto retry;
		}
	}
	vm_swap_put_failures_no_swap_file++;

	return KERN_FAILURE;

issue_io:
	assert(c_seg->c_busy_swapping);
	assert(c_seg->c_busy);
	assert(!c_seg->c_on_minorcompact_q);

	*f_offset = (swapfile_index << SWAP_DEVICE_SHIFT) | file_offset;

	if (soc) {
		soc->swp_c_seg = c_seg;
		soc->swp_c_size = size;

		soc->swp_swf = swf;

		soc->swp_io_error = 0;
		soc->swp_io_done = 0;

		upl_ctx = (void *)&soc->swp_upl_ctx;
	}
	error = vm_swapfile_io(swf->swp_vp, file_offset, addr, (int) (size / PAGE_SIZE_64), SWAP_WRITE, upl_ctx);

	if (error || upl_ctx == NULL) {
		return vm_swap_put_finish(swf, f_offset, error);
	}

	return KERN_SUCCESS;
}

kern_return_t
vm_swap_put_finish(struct swapfile *swf, uint64_t *f_offset, int error)
{
	lck_mtx_lock(&vm_swap_data_lock);

	swf->swp_io_count--;

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
	uint64_t        file_offset = 0;
	unsigned int    segidx = 0;


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
		if (VM_SWAP_SHOULD_RECLAIM() && !vm_swapfile_gc_thread_running) {
			thread_wakeup((event_t) &vm_swapfile_gc_needed);
		}
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

	if (swp_trim_supported == TRUE) {
		tl = kalloc(sizeof(struct trim_list));
	}

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

			if (sec > dont_trim_until_ts) {
				thread_wakeup((event_t) &vm_swapfile_create_needed);
			}
		}
		vm_swap_free_delayed_count++;
	}
done:
	lck_mtx_unlock(&vm_swap_data_lock);

	if (tl != NULL) {
		kfree(tl, sizeof(struct trim_list));
	}
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

	if (VM_SWAP_SHOULD_RECLAIM() && !vm_swapfile_gc_thread_running) {
		thread_wakeup((event_t) &vm_swapfile_gc_needed);
	}

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
		unsigned int    segidx = 0;
		unsigned int    byte_for_segidx = 0;
		unsigned int    offset_within_byte = 0;

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

int     vm_swap_reclaim_yielded = 0;

void
vm_swap_reclaim(void)
{
	vm_offset_t     addr = 0;
	unsigned int    segidx = 0;
	uint64_t        f_offset = 0;
	struct swapfile *swf = NULL;
	struct swapfile *smallest_swf = NULL;
	unsigned int    min_nsegs = 0;
	unsigned int    byte_for_segidx = 0;
	unsigned int    offset_within_byte = 0;
	uint32_t        c_size = 0;

	c_segment_t     c_seg = NULL;

	if (kernel_memory_allocate(compressor_map, (vm_offset_t *)(&addr), C_SEG_BUFSIZE, 0, KMA_KOBJECT, VM_KERN_MEMORY_COMPRESSOR) != KERN_SUCCESS) {
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

	if (smallest_swf == NULL) {
		goto done;
	}

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

		if (vm_swapfile_io(swf->swp_vp, f_offset, addr, (int)(c_size / PAGE_SIZE_64), SWAP_READ, NULL)) {
			/*
			 * reading the data back in failed, so convert c_seg
			 * to a swapped in c_segment that contains no data
			 */
			c_seg_swapin_requeue(c_seg, FALSE, TRUE, FALSE);
			/*
			 * returns with c_busy_swapping cleared
			 */

			vm_swap_get_failures++;
			goto swap_io_failed;
		}
		VM_STAT_INCR_BY(swapins, c_size >> PAGE_SHIFT);

		if (vm_swap_put(addr, &f_offset, c_size, c_seg, NULL)) {
			vm_offset_t     c_buffer;

			/*
			 * the put failed, so convert c_seg to a fully swapped in c_segment
			 * with valid data
			 */
			c_buffer = (vm_offset_t)C_SEG_BUFFER_ADDRESS(c_seg->c_mysegno);

			kernel_memory_populate(compressor_map, c_buffer, c_size, KMA_COMPRESSOR, VM_KERN_MEMORY_COMPRESSOR);

			memcpy((char *)c_buffer, (char *)addr, c_size);

			c_seg->c_store.c_buffer = (int32_t *)c_buffer;
#if ENCRYPTED_SWAP
			vm_swap_decrypt(c_seg);
#endif /* ENCRYPTED_SWAP */
			c_seg_swapin_requeue(c_seg, TRUE, TRUE, FALSE);
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

		assert(c_seg->c_busy_swapping);
		c_seg->c_busy_swapping = 0;
swap_io_failed:
		assert(c_seg->c_busy);
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

	vm_swapfile_total_segs_alloced -= swf->swp_nsegs;

	lck_mtx_unlock(&vm_swap_data_lock);

	vm_swapfile_close((uint64_t)(swf->swp_path), swf->swp_vp);

	kfree(swf->swp_csegs, swf->swp_nsegs * sizeof(c_segment_t));
	kfree(swf->swp_bitmap, MAX((swf->swp_nsegs >> 3), 1));

	lck_mtx_lock(&vm_swap_data_lock);

	if (swf->swp_flags & SWAP_PINNED) {
		vm_num_pinned_swap_files--;
		vm_swappin_avail += swf->swp_size;
	}

	swf->swp_vp = NULL;
	swf->swp_size = 0;
	swf->swp_free_hint = 0;
	swf->swp_nsegs = 0;
	swf->swp_flags = SWAP_REUSE;

	vm_num_swap_files--;

done:
	thread_wakeup((event_t) &swf->swp_flags);
	lck_mtx_unlock(&vm_swap_data_lock);

	kmem_free(compressor_map, (vm_offset_t) addr, C_SEG_BUFSIZE);
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
	return vm_swap_get_total_space() - vm_swap_get_used_space();
}


int
vm_swap_low_on_space(void)
{
	if (vm_num_swap_files == 0 && vm_swapfile_can_be_created == FALSE) {
		return 0;
	}

	if (((vm_swapfile_total_segs_alloced - vm_swapfile_total_segs_used) < ((unsigned int)VM_SWAPFILE_HIWATER_SEGS) / 8)) {
		if (vm_num_swap_files == 0 && !SWAPPER_NEEDS_TO_UNTHROTTLE()) {
			return 0;
		}

		if (vm_swapfile_last_failed_to_create_ts >= vm_swapfile_last_successful_create_ts) {
			return 1;
		}
	}
	return 0;
}

boolean_t
vm_swap_files_pinned(void)
{
	boolean_t result;

	if (vm_swappin_enabled == FALSE) {
		return TRUE;
	}

	result = (vm_num_pinned_swap_files == vm_num_swap_files);

	return result;
}

#if CONFIG_FREEZE
boolean_t
vm_swap_max_budget(uint64_t *freeze_daily_budget)
{
	boolean_t       use_device_value = FALSE;
	struct swapfile *swf = NULL;

	if (vm_num_swap_files) {
		lck_mtx_lock(&vm_swap_data_lock);

		swf = (struct swapfile*) queue_first(&swf_global_queue);

		if (swf) {
			while (queue_end(&swf_global_queue, (queue_entry_t)swf) == FALSE) {
				if (swf->swp_flags == SWAP_READY) {
					assert(swf->swp_vp);

					if (vm_swap_vol_get_budget(swf->swp_vp, freeze_daily_budget) == 0) {
						use_device_value = TRUE;
					}
					break;
				}
				swf = (struct swapfile*) queue_next(&swf->swp_queue);
			}
		}

		lck_mtx_unlock(&vm_swap_data_lock);
	} else {
		/*
		 * This block is used for the initial budget value before any swap files
		 * are created. We create a temp swap file to get the budget.
		 */

		struct vnode *temp_vp = NULL;

		vm_swapfile_open(swapfilename, &temp_vp);

		if (temp_vp) {
			if (vm_swap_vol_get_budget(temp_vp, freeze_daily_budget) == 0) {
				use_device_value = TRUE;
			}

			vm_swapfile_close((uint64_t)&swapfilename, temp_vp);
			temp_vp = NULL;
		} else {
			*freeze_daily_budget = 0;
		}
	}

	return use_device_value;
}
#endif /* CONFIG_FREEZE */
