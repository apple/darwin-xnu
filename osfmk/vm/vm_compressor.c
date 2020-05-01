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
#include <vm/vm_compressor_algorithms.h>
#include <vm/vm_fault.h>
#include <vm/vm_protos.h>
#include <mach/mach_host.h>             /* for host_info() */
#include <kern/ledger.h>
#include <kern/policy_internal.h>
#include <kern/thread_group.h>
#include <san/kasan.h>

#if defined(__x86_64__)
#include <i386/misc_protos.h>
#endif
#if defined(__arm64__)
#include <arm/machine_routines.h>
#endif

#include <IOKit/IOHibernatePrivate.h>

extern boolean_t vm_darkwake_mode;

#if DEVELOPMENT || DEBUG
int do_cseg_wedge_thread(void);
int do_cseg_unwedge_thread(void);
static event_t debug_cseg_wait_event = NULL;
#endif /* DEVELOPMENT || DEBUG */

#if POPCOUNT_THE_COMPRESSED_DATA
boolean_t popcount_c_segs = TRUE;

static inline uint32_t
vmc_pop(uintptr_t ins, int sz)
{
	uint32_t rv = 0;

	if (__probable(popcount_c_segs == FALSE)) {
		return 0xDEAD707C;
	}

	while (sz >= 16) {
		uint32_t rv1, rv2;
		uint64_t *ins64 = (uint64_t *) ins;
		uint64_t *ins642 = (uint64_t *) (ins + 8);
		rv1 = __builtin_popcountll(*ins64);
		rv2 = __builtin_popcountll(*ins642);
		rv += rv1 + rv2;
		sz -= 16;
		ins += 16;
	}

	while (sz >= 4) {
		uint32_t *ins32 = (uint32_t *) ins;
		rv += __builtin_popcount(*ins32);
		sz -= 4;
		ins += 4;
	}

	while (sz > 0) {
		char *ins8 = (char *)ins;
		rv += __builtin_popcount(*ins8);
		sz--;
		ins++;
	}
	return rv;
}
#endif

#if VALIDATE_C_SEGMENTS
boolean_t validate_c_segs = TRUE;
#endif
/*
 * vm_compressor_mode has a heirarchy of control to set its value.
 * boot-args are checked first, then device-tree, and finally
 * the default value that is defined below. See vm_fault_init() for
 * the boot-arg & device-tree code.
 */

#if CONFIG_EMBEDDED

#if CONFIG_FREEZE
int             vm_compressor_mode = VM_PAGER_FREEZER_DEFAULT;

void            *freezer_chead; /* The chead used to track c_segs allocated for the exclusive use of holding just one task's compressed memory.*/
char            *freezer_compressor_scratch_buf = NULL;

extern int      c_freezer_swapout_page_count;      /* This count keeps track of the # of compressed pages holding just one task's compressed memory on the swapout queue. This count is used during each freeze i.e. on a per-task basis.*/

#else /* CONFIG_FREEZE */
int             vm_compressor_mode = VM_PAGER_NOT_CONFIGURED;
#endif /* CONFIG_FREEZE */

int             vm_scale = 1;

#else /* CONFIG_EMBEDDED */
int             vm_compressor_mode = VM_PAGER_COMPRESSOR_WITH_SWAP;
int             vm_scale = 16;

#endif /* CONFIG_EMBEDDED */

int             vm_compressor_is_active = 0;
int             vm_compression_limit = 0;
int             vm_compressor_available = 0;

extern void     vm_pageout_io_throttle(void);

#if CHECKSUM_THE_DATA || CHECKSUM_THE_SWAP || CHECKSUM_THE_COMPRESSED_DATA
extern unsigned int hash_string(char *cp, int len);
static unsigned int vmc_hash(char *, int);
boolean_t checksum_c_segs = TRUE;

unsigned int
vmc_hash(char *cp, int len)
{
	if (__probable(checksum_c_segs == FALSE)) {
		return 0xDEAD7A37;
	}
	return hash_string(cp, len);
}
#endif

#define UNPACK_C_SIZE(cs)       ((cs->c_size == (PAGE_SIZE-1)) ? PAGE_SIZE : cs->c_size)
#define PACK_C_SIZE(cs, size)   (cs->c_size = ((size == PAGE_SIZE) ? PAGE_SIZE - 1 : size))


struct c_sv_hash_entry {
	union {
		struct  {
			uint32_t        c_sv_he_ref;
			uint32_t        c_sv_he_data;
		} c_sv_he;
		uint64_t        c_sv_he_record;
	} c_sv_he_un;
};

#define he_ref  c_sv_he_un.c_sv_he.c_sv_he_ref
#define he_data c_sv_he_un.c_sv_he.c_sv_he_data
#define he_record c_sv_he_un.c_sv_he_record

#define C_SV_HASH_MAX_MISS      32
#define C_SV_HASH_SIZE          ((1 << 10))
#define C_SV_HASH_MASK          ((1 << 10) - 1)
#define C_SV_CSEG_ID            ((1 << 22) - 1)


union c_segu {
	c_segment_t     c_seg;
	uintptr_t       c_segno;
};



#define C_SLOT_PACK_PTR(ptr)            (((uintptr_t)ptr - (uintptr_t) KERNEL_PMAP_HEAP_RANGE_START) >> 2)
#define C_SLOT_UNPACK_PTR(cslot)        ((uintptr_t)(cslot->c_packed_ptr << 2) + (uintptr_t) KERNEL_PMAP_HEAP_RANGE_START)


uint32_t        c_segment_count = 0;
uint32_t        c_segment_count_max = 0;

uint64_t        c_generation_id = 0;
uint64_t        c_generation_id_flush_barrier;


#define         HIBERNATE_FLUSHING_SECS_TO_COMPLETE     120

boolean_t       hibernate_no_swapspace = FALSE;
clock_sec_t     hibernate_flushing_deadline = 0;


#if RECORD_THE_COMPRESSED_DATA
char    *c_compressed_record_sbuf;
char    *c_compressed_record_ebuf;
char    *c_compressed_record_cptr;
#endif


queue_head_t    c_age_list_head;
queue_head_t    c_swappedin_list_head;
queue_head_t    c_swapout_list_head;
queue_head_t    c_swapio_list_head;
queue_head_t    c_swappedout_list_head;
queue_head_t    c_swappedout_sparse_list_head;
queue_head_t    c_major_list_head;
queue_head_t    c_filling_list_head;
queue_head_t    c_bad_list_head;

uint32_t        c_age_count = 0;
uint32_t        c_swappedin_count = 0;
uint32_t        c_swapout_count = 0;
uint32_t        c_swapio_count = 0;
uint32_t        c_swappedout_count = 0;
uint32_t        c_swappedout_sparse_count = 0;
uint32_t        c_major_count = 0;
uint32_t        c_filling_count = 0;
uint32_t        c_empty_count = 0;
uint32_t        c_bad_count = 0;


queue_head_t    c_minor_list_head;
uint32_t        c_minor_count = 0;

int             c_overage_swapped_count = 0;
int             c_overage_swapped_limit = 0;

int             c_seg_fixed_array_len;
union  c_segu   *c_segments;
vm_offset_t     c_buffers;
vm_size_t       c_buffers_size;
caddr_t         c_segments_next_page;
boolean_t       c_segments_busy;
uint32_t        c_segments_available;
uint32_t        c_segments_limit;
uint32_t        c_segments_nearing_limit;

uint32_t        c_segment_svp_in_hash;
uint32_t        c_segment_svp_hash_succeeded;
uint32_t        c_segment_svp_hash_failed;
uint32_t        c_segment_svp_zero_compressions;
uint32_t        c_segment_svp_nonzero_compressions;
uint32_t        c_segment_svp_zero_decompressions;
uint32_t        c_segment_svp_nonzero_decompressions;

uint32_t        c_segment_noncompressible_pages;

uint32_t        c_segment_pages_compressed;
uint32_t        c_segment_pages_compressed_limit;
uint32_t        c_segment_pages_compressed_nearing_limit;
uint32_t        c_free_segno_head = (uint32_t)-1;

uint32_t        vm_compressor_minorcompact_threshold_divisor = 10;
uint32_t        vm_compressor_majorcompact_threshold_divisor = 10;
uint32_t        vm_compressor_unthrottle_threshold_divisor = 10;
uint32_t        vm_compressor_catchup_threshold_divisor = 10;

uint32_t        vm_compressor_minorcompact_threshold_divisor_overridden = 0;
uint32_t        vm_compressor_majorcompact_threshold_divisor_overridden = 0;
uint32_t        vm_compressor_unthrottle_threshold_divisor_overridden = 0;
uint32_t        vm_compressor_catchup_threshold_divisor_overridden = 0;

#define         C_SEGMENTS_PER_PAGE     (PAGE_SIZE / sizeof(union c_segu))


lck_grp_attr_t  vm_compressor_lck_grp_attr;
lck_attr_t      vm_compressor_lck_attr;
lck_grp_t       vm_compressor_lck_grp;
lck_mtx_t       *c_list_lock;
lck_rw_t        c_master_lock;
boolean_t       decompressions_blocked = FALSE;

zone_t          compressor_segment_zone;
int             c_compressor_swap_trigger = 0;

uint32_t        compressor_cpus;
char            *compressor_scratch_bufs;
char            *kdp_compressor_scratch_buf;
char            *kdp_compressor_decompressed_page;
addr64_t        kdp_compressor_decompressed_page_paddr;
ppnum_t         kdp_compressor_decompressed_page_ppnum;

clock_sec_t     start_of_sample_period_sec = 0;
clock_nsec_t    start_of_sample_period_nsec = 0;
clock_sec_t     start_of_eval_period_sec = 0;
clock_nsec_t    start_of_eval_period_nsec = 0;
uint32_t        sample_period_decompression_count = 0;
uint32_t        sample_period_compression_count = 0;
uint32_t        last_eval_decompression_count = 0;
uint32_t        last_eval_compression_count = 0;

#define         DECOMPRESSION_SAMPLE_MAX_AGE            (60 * 30)

boolean_t       vm_swapout_ripe_segments = FALSE;
uint32_t        vm_ripe_target_age = (60 * 60 * 48);

uint32_t        swapout_target_age = 0;
uint32_t        age_of_decompressions_during_sample_period[DECOMPRESSION_SAMPLE_MAX_AGE];
uint32_t        overage_decompressions_during_sample_period = 0;


void            do_fastwake_warmup(queue_head_t *, boolean_t);
boolean_t       fastwake_warmup = FALSE;
boolean_t       fastwake_recording_in_progress = FALSE;
clock_sec_t     dont_trim_until_ts = 0;

uint64_t        c_segment_warmup_count;
uint64_t        first_c_segment_to_warm_generation_id = 0;
uint64_t        last_c_segment_to_warm_generation_id = 0;
boolean_t       hibernate_flushing = FALSE;

int64_t         c_segment_input_bytes __attribute__((aligned(8))) = 0;
int64_t         c_segment_compressed_bytes __attribute__((aligned(8))) = 0;
int64_t         compressor_bytes_used __attribute__((aligned(8))) = 0;


struct c_sv_hash_entry c_segment_sv_hash_table[C_SV_HASH_SIZE]  __attribute__ ((aligned(8)));

static boolean_t compressor_needs_to_swap(void);
static void vm_compressor_swap_trigger_thread(void);
static void vm_compressor_do_delayed_compactions(boolean_t);
static void vm_compressor_compact_and_swap(boolean_t);
static void vm_compressor_age_swapped_in_segments(boolean_t);

#if !CONFIG_EMBEDDED
static void vm_compressor_take_paging_space_action(void);
#endif

void compute_swapout_target_age(void);

boolean_t c_seg_major_compact(c_segment_t, c_segment_t);
boolean_t c_seg_major_compact_ok(c_segment_t, c_segment_t);

int  c_seg_minor_compaction_and_unlock(c_segment_t, boolean_t);
int  c_seg_do_minor_compaction_and_unlock(c_segment_t, boolean_t, boolean_t, boolean_t);
void c_seg_try_minor_compaction_and_unlock(c_segment_t c_seg);

void c_seg_move_to_sparse_list(c_segment_t);
void c_seg_insert_into_q(queue_head_t *, c_segment_t);

uint64_t vm_available_memory(void);
uint64_t vm_compressor_pages_compressed(void);

/*
 * indicate the need to do a major compaction if
 * the overall set of in-use compression segments
 * becomes sparse... on systems that support pressure
 * driven swapping, this will also cause swapouts to
 * be initiated.
 */
static inline boolean_t
vm_compressor_needs_to_major_compact()
{
	uint32_t        incore_seg_count;

	incore_seg_count = c_segment_count - c_swappedout_count - c_swappedout_sparse_count;

	if ((c_segment_count >= (c_segments_nearing_limit / 8)) &&
	    ((incore_seg_count * C_SEG_MAX_PAGES) - VM_PAGE_COMPRESSOR_COUNT) >
	    ((incore_seg_count / 8) * C_SEG_MAX_PAGES)) {
		return 1;
	}
	return 0;
}


uint64_t
vm_available_memory(void)
{
	return ((uint64_t)AVAILABLE_NON_COMPRESSED_MEMORY) * PAGE_SIZE_64;
}


uint64_t
vm_compressor_pages_compressed(void)
{
	return c_segment_pages_compressed * PAGE_SIZE_64;
}


boolean_t
vm_compressor_low_on_space(void)
{
	if ((c_segment_pages_compressed > c_segment_pages_compressed_nearing_limit) ||
	    (c_segment_count > c_segments_nearing_limit)) {
		return TRUE;
	}

	return FALSE;
}


boolean_t
vm_compressor_out_of_space(void)
{
	if ((c_segment_pages_compressed >= c_segment_pages_compressed_limit) ||
	    (c_segment_count >= c_segments_limit)) {
		return TRUE;
	}

	return FALSE;
}


int
vm_wants_task_throttled(task_t task)
{
	if (task == kernel_task) {
		return 0;
	}

	if (VM_CONFIG_SWAP_IS_ACTIVE) {
		if ((vm_compressor_low_on_space() || HARD_THROTTLE_LIMIT_REACHED()) &&
		    (unsigned int)pmap_compressed(task->map->pmap) > (c_segment_pages_compressed / 4)) {
			return 1;
		}
	}
	return 0;
}


#if DEVELOPMENT || DEBUG
boolean_t kill_on_no_paging_space = FALSE; /* On compressor/swap exhaustion, kill the largest process regardless of
                                            * its chosen process policy. Controlled by a boot-arg of the same name. */
#endif /* DEVELOPMENT || DEBUG */

#if !CONFIG_EMBEDDED

static uint32_t no_paging_space_action_in_progress = 0;
extern void memorystatus_send_low_swap_note(void);

static void
vm_compressor_take_paging_space_action(void)
{
	if (no_paging_space_action_in_progress == 0) {
		if (OSCompareAndSwap(0, 1, (UInt32 *)&no_paging_space_action_in_progress)) {
			if (no_paging_space_action()) {
#if DEVELOPMENT || DEBUG
				if (kill_on_no_paging_space == TRUE) {
					/*
					 * Since we are choosing to always kill a process, we don't need the
					 * "out of application memory" dialog box in this mode. And, hence we won't
					 * send the knote.
					 */
					no_paging_space_action_in_progress = 0;
					return;
				}
#endif /* DEVELOPMENT || DEBUG */
				memorystatus_send_low_swap_note();
			}

			no_paging_space_action_in_progress = 0;
		}
	}
}
#endif /* !CONFIG_EMBEDDED */


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

static inline void
cslot_copy(c_slot_t cdst, c_slot_t csrc)
{
#if CHECKSUM_THE_DATA
	cdst->c_hash_data = csrc->c_hash_data;
#endif
#if CHECKSUM_THE_COMPRESSED_DATA
	cdst->c_hash_compressed_data = csrc->c_hash_compressed_data;
#endif
#if POPCOUNT_THE_COMPRESSED_DATA
	cdst->c_pop_cdata = csrc->c_pop_cdata;
#endif
	cdst->c_size = csrc->c_size;
	cdst->c_packed_ptr = csrc->c_packed_ptr;
#if defined(__arm__) || defined(__arm64__)
	cdst->c_codec = csrc->c_codec;
#endif
}

vm_map_t compressor_map;
uint64_t compressor_pool_max_size;
uint64_t compressor_pool_size;
uint32_t compressor_pool_multiplier;

#if DEVELOPMENT || DEBUG
/*
 * Compressor segments are write-protected in development/debug
 * kernels to help debug memory corruption.
 * In cases where performance is a concern, this can be disabled
 * via the boot-arg "-disable_cseg_write_protection".
 */
boolean_t write_protect_c_segs = TRUE;
int vm_compressor_test_seg_wp;
uint32_t vm_ktrace_enabled;
#endif /* DEVELOPMENT || DEBUG */

void
vm_compressor_init(void)
{
	thread_t        thread;
	struct c_slot   cs_dummy;
	c_slot_t cs  = &cs_dummy;
	int             c_segment_min_size;
	int             c_segment_padded_size;
	int             attempts = 1;
	kern_return_t   retval = KERN_SUCCESS;
	vm_offset_t     start_addr = 0;
	vm_size_t       c_segments_arr_size = 0, compressor_submap_size = 0;
	vm_map_kernel_flags_t vmk_flags;
#if RECORD_THE_COMPRESSED_DATA
	vm_size_t       c_compressed_record_sbuf_size = 0;
#endif /* RECORD_THE_COMPRESSED_DATA */

#if DEVELOPMENT || DEBUG
	char bootarg_name[32];
	if (PE_parse_boot_argn("-kill_on_no_paging_space", bootarg_name, sizeof(bootarg_name))) {
		kill_on_no_paging_space = TRUE;
	}
	if (PE_parse_boot_argn("-disable_cseg_write_protection", bootarg_name, sizeof(bootarg_name))) {
		write_protect_c_segs = FALSE;
	}
	int vmcval = 1;
	PE_parse_boot_argn("vm_compressor_validation", &vmcval, sizeof(vmcval));

	if (kern_feature_override(KF_COMPRSV_OVRD)) {
		vmcval = 0;
	}
	if (vmcval == 0) {
#if POPCOUNT_THE_COMPRESSED_DATA
		popcount_c_segs = FALSE;
#endif
#if CHECKSUM_THE_DATA || CHECKSUM_THE_COMPRESSED_DATA
		checksum_c_segs = FALSE;
#endif
#if VALIDATE_C_SEGMENTS
		validate_c_segs = FALSE;
#endif
		write_protect_c_segs = FALSE;
	}
#endif /* DEVELOPMENT || DEBUG */

	/*
	 * ensure that any pointer that gets created from
	 * the vm_page zone can be packed properly
	 */
	cs->c_packed_ptr = C_SLOT_PACK_PTR(zone_map_min_address);

	if (C_SLOT_UNPACK_PTR(cs) != (uintptr_t)zone_map_min_address) {
		panic("C_SLOT_UNPACK_PTR failed on zone_map_min_address - %p", (void *)zone_map_min_address);
	}

	cs->c_packed_ptr = C_SLOT_PACK_PTR(zone_map_max_address);

	if (C_SLOT_UNPACK_PTR(cs) != (uintptr_t)zone_map_max_address) {
		panic("C_SLOT_UNPACK_PTR failed on zone_map_max_address - %p", (void *)zone_map_max_address);
	}


	assert((C_SEGMENTS_PER_PAGE * sizeof(union c_segu)) == PAGE_SIZE);

	PE_parse_boot_argn("vm_compression_limit", &vm_compression_limit, sizeof(vm_compression_limit));

#ifdef CONFIG_EMBEDDED
	vm_compressor_minorcompact_threshold_divisor = 20;
	vm_compressor_majorcompact_threshold_divisor = 30;
	vm_compressor_unthrottle_threshold_divisor = 40;
	vm_compressor_catchup_threshold_divisor = 60;
#else
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
#endif
	/*
	 * vm_page_init_lck_grp is now responsible for calling vm_compressor_init_locks
	 * c_master_lock needs to be available early so that "vm_page_find_contiguous" can
	 * use PAGE_REPLACEMENT_ALLOWED to coordinate with the compressor.
	 */

	c_list_lock = lck_mtx_alloc_init(&vm_compressor_lck_grp, &vm_compressor_lck_attr);

	queue_init(&c_bad_list_head);
	queue_init(&c_age_list_head);
	queue_init(&c_minor_list_head);
	queue_init(&c_major_list_head);
	queue_init(&c_filling_list_head);
	queue_init(&c_swapout_list_head);
	queue_init(&c_swapio_list_head);
	queue_init(&c_swappedin_list_head);
	queue_init(&c_swappedout_list_head);
	queue_init(&c_swappedout_sparse_list_head);

	c_free_segno_head = -1;
	c_segments_available = 0;

	if (vm_compression_limit) {
		compressor_pool_size = (uint64_t)vm_compression_limit * PAGE_SIZE_64;
	}

	compressor_pool_max_size = C_SEG_MAX_LIMIT;
	compressor_pool_max_size *= C_SEG_BUFSIZE;

#if !CONFIG_EMBEDDED

	if (vm_compression_limit == 0) {
		if (max_mem <= (4ULL * 1024ULL * 1024ULL * 1024ULL)) {
			compressor_pool_size = 16ULL * max_mem;
		} else if (max_mem <= (8ULL * 1024ULL * 1024ULL * 1024ULL)) {
			compressor_pool_size = 8ULL * max_mem;
		} else if (max_mem <= (32ULL * 1024ULL * 1024ULL * 1024ULL)) {
			compressor_pool_size = 4ULL * max_mem;
		} else {
			compressor_pool_size = 2ULL * max_mem;
		}
	}
	if (max_mem <= (8ULL * 1024ULL * 1024ULL * 1024ULL)) {
		compressor_pool_multiplier = 1;
	} else if (max_mem <= (32ULL * 1024ULL * 1024ULL * 1024ULL)) {
		compressor_pool_multiplier = 2;
	} else {
		compressor_pool_multiplier = 4;
	}

#elif defined(__arm__)

#define VM_RESERVE_SIZE                 (1024 * 1024 * 256)
#define MAX_COMPRESSOR_POOL_SIZE        (1024 * 1024 * 450)

	if (compressor_pool_max_size > MAX_COMPRESSOR_POOL_SIZE) {
		compressor_pool_max_size = MAX_COMPRESSOR_POOL_SIZE;
	}

	if (vm_compression_limit == 0) {
		compressor_pool_size = ((kernel_map->max_offset - kernel_map->min_offset) - kernel_map->size) - VM_RESERVE_SIZE;
	}
	compressor_pool_multiplier = 1;

#elif defined(__arm64__) && defined(XNU_TARGET_OS_WATCH)

	/*
	 * On M9 watches the compressor can become big and can lead to
	 * churn in workingset resulting in audio drops. Setting a cap
	 * on the compressor size favors reclaiming unused memory
	 * sitting in idle band via jetsams
	 */

#define COMPRESSOR_CAP_PERCENTAGE        30ULL

	if (compressor_pool_max_size > max_mem) {
		compressor_pool_max_size = max_mem;
	}

	if (vm_compression_limit == 0) {
		compressor_pool_size = (max_mem * COMPRESSOR_CAP_PERCENTAGE) / 100ULL;
	}
	compressor_pool_multiplier = 1;

#else

	if (compressor_pool_max_size > max_mem) {
		compressor_pool_max_size = max_mem;
	}

	if (vm_compression_limit == 0) {
		compressor_pool_size = max_mem;
	}
	compressor_pool_multiplier = 1;
#endif
	if (compressor_pool_size > compressor_pool_max_size) {
		compressor_pool_size = compressor_pool_max_size;
	}

try_again:
	c_segments_limit = (uint32_t)(compressor_pool_size / (vm_size_t)(C_SEG_ALLOCSIZE));
	c_segments_nearing_limit = (uint32_t)(((uint64_t)c_segments_limit * 98ULL) / 100ULL);

	c_segment_pages_compressed_limit = (c_segments_limit * (C_SEG_BUFSIZE / PAGE_SIZE) * compressor_pool_multiplier);

	if (c_segment_pages_compressed_limit < (uint32_t)(max_mem / PAGE_SIZE)) {
		c_segment_pages_compressed_limit = (uint32_t)(max_mem / PAGE_SIZE);
	}

	c_segment_pages_compressed_nearing_limit = (uint32_t)(((uint64_t)c_segment_pages_compressed_limit * 98ULL) / 100ULL);

	/*
	 * Submap needs space for:
	 * - c_segments
	 * - c_buffers
	 * - swap reclaimations -- C_SEG_BUFSIZE
	 */
	c_segments_arr_size = vm_map_round_page((sizeof(union c_segu) * c_segments_limit), VM_MAP_PAGE_MASK(kernel_map));
	c_buffers_size = vm_map_round_page(((vm_size_t)C_SEG_ALLOCSIZE * (vm_size_t)c_segments_limit), VM_MAP_PAGE_MASK(kernel_map));

	compressor_submap_size = c_segments_arr_size + c_buffers_size + C_SEG_BUFSIZE;

#if RECORD_THE_COMPRESSED_DATA
	c_compressed_record_sbuf_size = (vm_size_t)C_SEG_ALLOCSIZE + (PAGE_SIZE * 2);
	compressor_submap_size += c_compressed_record_sbuf_size;
#endif /* RECORD_THE_COMPRESSED_DATA */

	vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
	vmk_flags.vmkf_permanent = TRUE;
	retval = kmem_suballoc(kernel_map, &start_addr, compressor_submap_size,
	    FALSE, VM_FLAGS_ANYWHERE, vmk_flags, VM_KERN_MEMORY_COMPRESSOR,
	    &compressor_map);

	if (retval != KERN_SUCCESS) {
		if (++attempts > 3) {
			panic("vm_compressor_init: kmem_suballoc failed - 0x%llx", (uint64_t)compressor_submap_size);
		}

		compressor_pool_size = compressor_pool_size / 2;

		kprintf("retrying creation of the compressor submap at 0x%llx bytes\n", compressor_pool_size);
		goto try_again;
	}
	if (kernel_memory_allocate(compressor_map, (vm_offset_t *)(&c_segments), (sizeof(union c_segu) * c_segments_limit), 0, KMA_KOBJECT | KMA_VAONLY | KMA_PERMANENT, VM_KERN_MEMORY_COMPRESSOR) != KERN_SUCCESS) {
		panic("vm_compressor_init: kernel_memory_allocate failed - c_segments\n");
	}
	if (kernel_memory_allocate(compressor_map, &c_buffers, c_buffers_size, 0, KMA_COMPRESSOR | KMA_VAONLY | KMA_PERMANENT, VM_KERN_MEMORY_COMPRESSOR) != KERN_SUCCESS) {
		panic("vm_compressor_init: kernel_memory_allocate failed - c_buffers\n");
	}


	c_segment_min_size = sizeof(struct c_segment) + (C_SEG_SLOT_VAR_ARRAY_MIN_LEN * sizeof(struct c_slot));

	for (c_segment_padded_size = 128; c_segment_padded_size < c_segment_min_size; c_segment_padded_size = c_segment_padded_size << 1) {
		;
	}

	compressor_segment_zone = zinit(c_segment_padded_size, c_segments_limit * c_segment_padded_size, PAGE_SIZE, "compressor_segment");
	zone_change(compressor_segment_zone, Z_CALLERACCT, FALSE);
	zone_change(compressor_segment_zone, Z_NOENCRYPT, TRUE);

	c_seg_fixed_array_len = (c_segment_padded_size - sizeof(struct c_segment)) / sizeof(struct c_slot);

	c_segments_busy = FALSE;

	c_segments_next_page = (caddr_t)c_segments;
	vm_compressor_algorithm_init();

	{
		host_basic_info_data_t hinfo;
		mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;

#define BSD_HOST 1
		host_info((host_t)BSD_HOST, HOST_BASIC_INFO, (host_info_t)&hinfo, &count);

		compressor_cpus = hinfo.max_cpus;
		compressor_scratch_bufs = kalloc_tag(compressor_cpus * vm_compressor_get_decode_scratch_size(), VM_KERN_MEMORY_COMPRESSOR);

		kdp_compressor_scratch_buf = kalloc_tag(vm_compressor_get_decode_scratch_size(), VM_KERN_MEMORY_COMPRESSOR);

		/*
		 * kdp_compressor_decompressed_page must be page aligned because we access
		 * it through the physical apperture by page number. kalloc() does not
		 * guarantee alignment.
		 */
		vm_offset_t addr;
		if (kernel_memory_allocate(kernel_map, &addr, PAGE_SIZE, 0, KMA_KOBJECT, VM_KERN_MEMORY_COMPRESSOR) != KERN_SUCCESS) {
			panic("vm_compressor_init: kernel_memory_allocate failed - kdp_compressor_decompressed_page\n");
		}
		assert((addr & PAGE_MASK) == 0);
		kdp_compressor_decompressed_page = (void *)addr;
		kdp_compressor_decompressed_page_paddr = kvtophys((vm_offset_t)kdp_compressor_decompressed_page);
		kdp_compressor_decompressed_page_ppnum = (ppnum_t) atop(kdp_compressor_decompressed_page_paddr);
	}
#if CONFIG_FREEZE
	freezer_compressor_scratch_buf = kalloc_tag(vm_compressor_get_encode_scratch_size(), VM_KERN_MEMORY_COMPRESSOR);
#endif

#if RECORD_THE_COMPRESSED_DATA
	if (kernel_memory_allocate(compressor_map, (vm_offset_t *)&c_compressed_record_sbuf, c_compressed_record_sbuf_size, 0, KMA_KOBJECT, VM_KERN_MEMORY_COMPRESSOR) != KERN_SUCCESS) {
		panic("vm_compressor_init: kernel_memory_allocate failed - c_compressed_record_sbuf\n");
	}

	c_compressed_record_cptr = c_compressed_record_sbuf;
	c_compressed_record_ebuf = c_compressed_record_sbuf + c_compressed_record_sbuf_size;
#endif

	if (kernel_thread_start_priority((thread_continue_t)vm_compressor_swap_trigger_thread, NULL,
	    BASEPRI_VM, &thread) != KERN_SUCCESS) {
		panic("vm_compressor_swap_trigger_thread: create failed");
	}
	thread_deallocate(thread);

	if (vm_pageout_internal_start() != KERN_SUCCESS) {
		panic("vm_compressor_init: Failed to start the internal pageout thread.\n");
	}
	if (VM_CONFIG_SWAP_IS_PRESENT) {
		vm_compressor_swap_init();
	}

	if (VM_CONFIG_COMPRESSOR_IS_ACTIVE) {
		vm_compressor_is_active = 1;
	}

#if CONFIG_FREEZE
	memorystatus_freeze_enabled = TRUE;
#endif /* CONFIG_FREEZE */

	vm_compressor_available = 1;

	vm_page_reactivate_all_throttled();
}


#if VALIDATE_C_SEGMENTS

static void
c_seg_validate(c_segment_t c_seg, boolean_t must_be_compact)
{
	int             c_indx;
	int32_t         bytes_used;
	uint32_t        c_rounded_size;
	uint32_t        c_size;
	c_slot_t        cs;

	if (__probable(validate_c_segs == FALSE)) {
		return;
	}
	if (c_seg->c_firstemptyslot < c_seg->c_nextslot) {
		c_indx = c_seg->c_firstemptyslot;
		cs = C_SEG_SLOT_FROM_INDEX(c_seg, c_indx);

		if (cs == NULL) {
			panic("c_seg_validate:  no slot backing c_firstemptyslot");
		}

		if (cs->c_size) {
			panic("c_seg_validate:  c_firstemptyslot has non-zero size (%d)\n", cs->c_size);
		}
	}
	bytes_used = 0;

	for (c_indx = 0; c_indx < c_seg->c_nextslot; c_indx++) {
		cs = C_SEG_SLOT_FROM_INDEX(c_seg, c_indx);

		c_size = UNPACK_C_SIZE(cs);

		c_rounded_size = (c_size + C_SEG_OFFSET_ALIGNMENT_MASK) & ~C_SEG_OFFSET_ALIGNMENT_MASK;

		bytes_used += c_rounded_size;

#if CHECKSUM_THE_COMPRESSED_DATA
		unsigned csvhash;
		if (c_size && cs->c_hash_compressed_data != (csvhash = vmc_hash((char *)&c_seg->c_store.c_buffer[cs->c_offset], c_size))) {
			addr64_t csvphys = kvtophys((vm_offset_t)&c_seg->c_store.c_buffer[cs->c_offset]);
			panic("Compressed data doesn't match original %p phys: 0x%llx %d %p %d %d 0x%x 0x%x", c_seg, csvphys, cs->c_offset, cs, c_indx, c_size, cs->c_hash_compressed_data, csvhash);
		}
#endif
#if POPCOUNT_THE_COMPRESSED_DATA
		unsigned csvpop;
		if (c_size) {
			uintptr_t csvaddr = (uintptr_t) &c_seg->c_store.c_buffer[cs->c_offset];
			if (cs->c_pop_cdata != (csvpop = vmc_pop(csvaddr, c_size))) {
				panic("Compressed data popcount doesn't match original, bit distance: %d %p (phys: %p) %p %p 0x%llx 0x%x 0x%x 0x%x", (csvpop - cs->c_pop_cdata), (void *)csvaddr, (void *) kvtophys(csvaddr), c_seg, cs, (uint64_t)cs->c_offset, c_size, csvpop, cs->c_pop_cdata);
			}
		}
#endif
	}

	if (bytes_used != c_seg->c_bytes_used) {
		panic("c_seg_validate: bytes_used mismatch - found %d, segment has %d\n", bytes_used, c_seg->c_bytes_used);
	}

	if (c_seg->c_bytes_used > C_SEG_OFFSET_TO_BYTES((int32_t)c_seg->c_nextoffset)) {
		panic("c_seg_validate: c_bytes_used > c_nextoffset - c_nextoffset = %d,  c_bytes_used = %d\n",
		    (int32_t)C_SEG_OFFSET_TO_BYTES((int32_t)c_seg->c_nextoffset), c_seg->c_bytes_used);
	}

	if (must_be_compact) {
		if (c_seg->c_bytes_used != C_SEG_OFFSET_TO_BYTES((int32_t)c_seg->c_nextoffset)) {
			panic("c_seg_validate: c_bytes_used doesn't match c_nextoffset - c_nextoffset = %d,  c_bytes_used = %d\n",
			    (int32_t)C_SEG_OFFSET_TO_BYTES((int32_t)c_seg->c_nextoffset), c_seg->c_bytes_used);
		}
	}
}

#endif


void
c_seg_need_delayed_compaction(c_segment_t c_seg, boolean_t c_list_lock_held)
{
	boolean_t       clear_busy = FALSE;

	if (c_list_lock_held == FALSE) {
		if (!lck_mtx_try_lock_spin_always(c_list_lock)) {
			C_SEG_BUSY(c_seg);

			lck_mtx_unlock_always(&c_seg->c_lock);
			lck_mtx_lock_spin_always(c_list_lock);
			lck_mtx_lock_spin_always(&c_seg->c_lock);

			clear_busy = TRUE;
		}
	}
	assert(c_seg->c_state != C_IS_FILLING);

	if (!c_seg->c_on_minorcompact_q && !(C_SEG_IS_ON_DISK_OR_SOQ(c_seg))) {
		queue_enter(&c_minor_list_head, c_seg, c_segment_t, c_list);
		c_seg->c_on_minorcompact_q = 1;
		c_minor_count++;
	}
	if (c_list_lock_held == FALSE) {
		lck_mtx_unlock_always(c_list_lock);
	}

	if (clear_busy == TRUE) {
		C_SEG_WAKEUP_DONE(c_seg);
	}
}


unsigned int c_seg_moved_to_sparse_list = 0;

void
c_seg_move_to_sparse_list(c_segment_t c_seg)
{
	boolean_t       clear_busy = FALSE;

	if (!lck_mtx_try_lock_spin_always(c_list_lock)) {
		C_SEG_BUSY(c_seg);

		lck_mtx_unlock_always(&c_seg->c_lock);
		lck_mtx_lock_spin_always(c_list_lock);
		lck_mtx_lock_spin_always(&c_seg->c_lock);

		clear_busy = TRUE;
	}
	c_seg_switch_state(c_seg, C_ON_SWAPPEDOUTSPARSE_Q, FALSE);

	c_seg_moved_to_sparse_list++;

	lck_mtx_unlock_always(c_list_lock);

	if (clear_busy == TRUE) {
		C_SEG_WAKEUP_DONE(c_seg);
	}
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
	if (!lck_mtx_try_lock_spin_always(c_list_lock)) {
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
	int     c_seg_freed;

	assert(c_seg->c_busy);
	assert(!C_SEG_IS_ON_DISK_OR_SOQ(c_seg));

	/*
	 * check for the case that can occur when we are not swapping
	 * and this segment has been major compacted in the past
	 * and moved to the majorcompact q to remove it from further
	 * consideration... if the occupancy falls too low we need
	 * to put it back on the age_q so that it will be considered
	 * in the next major compaction sweep... if we don't do this
	 * we will eventually run into the c_segments_limit
	 */
	if (c_seg->c_state == C_ON_MAJORCOMPACT_Q && C_SEG_SHOULD_MAJORCOMPACT_NOW(c_seg)) {
		c_seg_switch_state(c_seg, C_ON_AGE_Q, FALSE);
	}
	if (!c_seg->c_on_minorcompact_q) {
		if (clear_busy == TRUE) {
			C_SEG_WAKEUP_DONE(c_seg);
		}

		lck_mtx_unlock_always(&c_seg->c_lock);

		return 0;
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

	if (disallow_page_replacement == TRUE) {
		PAGE_REPLACEMENT_DISALLOWED(FALSE);
	}

	if (need_list_lock == TRUE) {
		lck_mtx_lock_spin_always(c_list_lock);
	}

	return c_seg_freed;
}

void
kdp_compressor_busy_find_owner(event64_t wait_event, thread_waitinfo_t *waitinfo)
{
	c_segment_t c_seg = (c_segment_t) wait_event;

	waitinfo->owner = thread_tid(c_seg->c_busy_for_thread);
	waitinfo->context = VM_KERNEL_UNSLIDE_OR_PERM(c_seg);
}

#if DEVELOPMENT || DEBUG
int
do_cseg_wedge_thread(void)
{
	struct c_segment c_seg;
	c_seg.c_busy_for_thread = current_thread();

	debug_cseg_wait_event = (event_t) &c_seg;

	thread_set_pending_block_hint(current_thread(), kThreadWaitCompressor);
	assert_wait((event_t) (&c_seg), THREAD_INTERRUPTIBLE);

	thread_block(THREAD_CONTINUE_NULL);

	return 0;
}

int
do_cseg_unwedge_thread(void)
{
	thread_wakeup(debug_cseg_wait_event);
	debug_cseg_wait_event = NULL;

	return 0;
}
#endif /* DEVELOPMENT || DEBUG */

void
c_seg_wait_on_busy(c_segment_t c_seg)
{
	c_seg->c_wanted = 1;

	thread_set_pending_block_hint(current_thread(), kThreadWaitCompressor);
	assert_wait((event_t) (c_seg), THREAD_UNINT);

	lck_mtx_unlock_always(&c_seg->c_lock);
	thread_block(THREAD_CONTINUE_NULL);
}


void
c_seg_switch_state(c_segment_t c_seg, int new_state, boolean_t insert_head)
{
	int     old_state = c_seg->c_state;

#if !CONFIG_EMBEDDED
#if     DEVELOPMENT || DEBUG
	if (new_state != C_IS_FILLING) {
		LCK_MTX_ASSERT(&c_seg->c_lock, LCK_MTX_ASSERT_OWNED);
	}
	LCK_MTX_ASSERT(c_list_lock, LCK_MTX_ASSERT_OWNED);
#endif
#endif /* !CONFIG_EMBEDDED */
	switch (old_state) {
	case C_IS_EMPTY:
		assert(new_state == C_IS_FILLING || new_state == C_IS_FREE);

		c_empty_count--;
		break;

	case C_IS_FILLING:
		assert(new_state == C_ON_AGE_Q || new_state == C_ON_SWAPOUT_Q);

		queue_remove(&c_filling_list_head, c_seg, c_segment_t, c_age_list);
		c_filling_count--;
		break;

	case C_ON_AGE_Q:
		assert(new_state == C_ON_SWAPOUT_Q || new_state == C_ON_MAJORCOMPACT_Q ||
		    new_state == C_IS_FREE);

		queue_remove(&c_age_list_head, c_seg, c_segment_t, c_age_list);
		c_age_count--;
		break;

	case C_ON_SWAPPEDIN_Q:
		assert(new_state == C_ON_AGE_Q || new_state == C_IS_FREE);

		queue_remove(&c_swappedin_list_head, c_seg, c_segment_t, c_age_list);
		c_swappedin_count--;
		break;

	case C_ON_SWAPOUT_Q:
		assert(new_state == C_ON_AGE_Q || new_state == C_IS_FREE || new_state == C_IS_EMPTY || new_state == C_ON_SWAPIO_Q);

		queue_remove(&c_swapout_list_head, c_seg, c_segment_t, c_age_list);
		thread_wakeup((event_t)&compaction_swapper_running);
		c_swapout_count--;
		break;

	case C_ON_SWAPIO_Q:
		assert(new_state == C_ON_SWAPPEDOUT_Q || new_state == C_ON_SWAPPEDOUTSPARSE_Q || new_state == C_ON_AGE_Q);

		queue_remove(&c_swapio_list_head, c_seg, c_segment_t, c_age_list);
		c_swapio_count--;
		break;

	case C_ON_SWAPPEDOUT_Q:
		assert(new_state == C_ON_SWAPPEDIN_Q || new_state == C_ON_AGE_Q ||
		    new_state == C_ON_SWAPPEDOUTSPARSE_Q ||
		    new_state == C_ON_BAD_Q || new_state == C_IS_EMPTY || new_state == C_IS_FREE);

		queue_remove(&c_swappedout_list_head, c_seg, c_segment_t, c_age_list);
		c_swappedout_count--;
		break;

	case C_ON_SWAPPEDOUTSPARSE_Q:
		assert(new_state == C_ON_SWAPPEDIN_Q || new_state == C_ON_AGE_Q ||
		    new_state == C_ON_BAD_Q || new_state == C_IS_EMPTY || new_state == C_IS_FREE);

		queue_remove(&c_swappedout_sparse_list_head, c_seg, c_segment_t, c_age_list);
		c_swappedout_sparse_count--;
		break;

	case C_ON_MAJORCOMPACT_Q:
		assert(new_state == C_ON_AGE_Q || new_state == C_IS_FREE);

		queue_remove(&c_major_list_head, c_seg, c_segment_t, c_age_list);
		c_major_count--;
		break;

	case C_ON_BAD_Q:
		assert(new_state == C_IS_FREE);

		queue_remove(&c_bad_list_head, c_seg, c_segment_t, c_age_list);
		c_bad_count--;
		break;

	default:
		panic("c_seg %p has bad c_state = %d\n", c_seg, old_state);
	}

	switch (new_state) {
	case C_IS_FREE:
		assert(old_state != C_IS_FILLING);

		break;

	case C_IS_EMPTY:
		assert(old_state == C_ON_SWAPOUT_Q || old_state == C_ON_SWAPPEDOUT_Q || old_state == C_ON_SWAPPEDOUTSPARSE_Q);

		c_empty_count++;
		break;

	case C_IS_FILLING:
		assert(old_state == C_IS_EMPTY);

		queue_enter(&c_filling_list_head, c_seg, c_segment_t, c_age_list);
		c_filling_count++;
		break;

	case C_ON_AGE_Q:
		assert(old_state == C_IS_FILLING || old_state == C_ON_SWAPPEDIN_Q ||
		    old_state == C_ON_SWAPOUT_Q || old_state == C_ON_SWAPIO_Q ||
		    old_state == C_ON_MAJORCOMPACT_Q || old_state == C_ON_SWAPPEDOUT_Q || old_state == C_ON_SWAPPEDOUTSPARSE_Q);

		if (old_state == C_IS_FILLING) {
			queue_enter(&c_age_list_head, c_seg, c_segment_t, c_age_list);
		} else {
			if (!queue_empty(&c_age_list_head)) {
				c_segment_t     c_first;

				c_first = (c_segment_t)queue_first(&c_age_list_head);
				c_seg->c_creation_ts = c_first->c_creation_ts;
			}
			queue_enter_first(&c_age_list_head, c_seg, c_segment_t, c_age_list);
		}
		c_age_count++;
		break;

	case C_ON_SWAPPEDIN_Q:
		assert(old_state == C_ON_SWAPPEDOUT_Q || old_state == C_ON_SWAPPEDOUTSPARSE_Q);

		if (insert_head == TRUE) {
			queue_enter_first(&c_swappedin_list_head, c_seg, c_segment_t, c_age_list);
		} else {
			queue_enter(&c_swappedin_list_head, c_seg, c_segment_t, c_age_list);
		}
		c_swappedin_count++;
		break;

	case C_ON_SWAPOUT_Q:
		assert(old_state == C_ON_AGE_Q || old_state == C_IS_FILLING);

		if (insert_head == TRUE) {
			queue_enter_first(&c_swapout_list_head, c_seg, c_segment_t, c_age_list);
		} else {
			queue_enter(&c_swapout_list_head, c_seg, c_segment_t, c_age_list);
		}
		c_swapout_count++;
		break;

	case C_ON_SWAPIO_Q:
		assert(old_state == C_ON_SWAPOUT_Q);

		if (insert_head == TRUE) {
			queue_enter_first(&c_swapio_list_head, c_seg, c_segment_t, c_age_list);
		} else {
			queue_enter(&c_swapio_list_head, c_seg, c_segment_t, c_age_list);
		}
		c_swapio_count++;
		break;

	case C_ON_SWAPPEDOUT_Q:
		assert(old_state == C_ON_SWAPIO_Q);

		if (insert_head == TRUE) {
			queue_enter_first(&c_swappedout_list_head, c_seg, c_segment_t, c_age_list);
		} else {
			queue_enter(&c_swappedout_list_head, c_seg, c_segment_t, c_age_list);
		}
		c_swappedout_count++;
		break;

	case C_ON_SWAPPEDOUTSPARSE_Q:
		assert(old_state == C_ON_SWAPIO_Q || old_state == C_ON_SWAPPEDOUT_Q);

		if (insert_head == TRUE) {
			queue_enter_first(&c_swappedout_sparse_list_head, c_seg, c_segment_t, c_age_list);
		} else {
			queue_enter(&c_swappedout_sparse_list_head, c_seg, c_segment_t, c_age_list);
		}

		c_swappedout_sparse_count++;
		break;

	case C_ON_MAJORCOMPACT_Q:
		assert(old_state == C_ON_AGE_Q);

		if (insert_head == TRUE) {
			queue_enter_first(&c_major_list_head, c_seg, c_segment_t, c_age_list);
		} else {
			queue_enter(&c_major_list_head, c_seg, c_segment_t, c_age_list);
		}
		c_major_count++;
		break;

	case C_ON_BAD_Q:
		assert(old_state == C_ON_SWAPPEDOUT_Q || old_state == C_ON_SWAPPEDOUTSPARSE_Q);

		if (insert_head == TRUE) {
			queue_enter_first(&c_bad_list_head, c_seg, c_segment_t, c_age_list);
		} else {
			queue_enter(&c_bad_list_head, c_seg, c_segment_t, c_age_list);
		}
		c_bad_count++;
		break;

	default:
		panic("c_seg %p requesting bad c_state = %d\n", c_seg, new_state);
	}
	c_seg->c_state = new_state;
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
	int             segno;
	int             pages_populated = 0;
	int32_t         *c_buffer = NULL;
	uint64_t        c_swap_handle = 0;

	assert(c_seg->c_busy);
	assert(c_seg->c_slots_used == 0);
	assert(!c_seg->c_on_minorcompact_q);
	assert(!c_seg->c_busy_swapping);

	if (c_seg->c_overage_swap == TRUE) {
		c_overage_swapped_count--;
		c_seg->c_overage_swap = FALSE;
	}
	if (!(C_SEG_IS_ONDISK(c_seg))) {
		c_buffer = c_seg->c_store.c_buffer;
	} else {
		c_swap_handle = c_seg->c_store.c_swap_handle;
	}

	c_seg_switch_state(c_seg, C_IS_FREE, FALSE);

	lck_mtx_unlock_always(c_list_lock);

	if (c_buffer) {
		pages_populated = (round_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset))) / PAGE_SIZE;
		c_seg->c_store.c_buffer = NULL;
	} else {
		c_seg->c_store.c_swap_handle = (uint64_t)-1;
	}

	lck_mtx_unlock_always(&c_seg->c_lock);

	if (c_buffer) {
		if (pages_populated) {
			kernel_memory_depopulate(compressor_map, (vm_offset_t) c_buffer, pages_populated * PAGE_SIZE, KMA_COMPRESSOR);
		}
	} else if (c_swap_handle) {
		/*
		 * Free swap space on disk.
		 */
		vm_swap_free(c_swap_handle);
	}
	lck_mtx_lock_spin_always(&c_seg->c_lock);
	/*
	 * c_seg must remain busy until
	 * after the call to vm_swap_free
	 */
	C_SEG_WAKEUP_DONE(c_seg);
	lck_mtx_unlock_always(&c_seg->c_lock);

	segno = c_seg->c_mysegno;

	lck_mtx_lock_spin_always(c_list_lock);
	/*
	 * because the c_buffer is now associated with the segno,
	 * we can't put the segno back on the free list until
	 * after we have depopulated the c_buffer range, or
	 * we run the risk of depopulating a range that is
	 * now being used in one of the compressor heads
	 */
	c_segments[segno].c_segno = c_free_segno_head;
	c_free_segno_head = segno;
	c_segment_count--;

	lck_mtx_unlock_always(c_list_lock);

	lck_mtx_destroy(&c_seg->c_lock, &vm_compressor_lck_grp);

	if (c_seg->c_slot_var_array_len) {
		kfree(c_seg->c_slot_var_array, sizeof(struct c_slot) * c_seg->c_slot_var_array_len);
	}

	zfree(compressor_segment_zone, c_seg);
}

#if DEVELOPMENT || DEBUG
int c_seg_trim_page_count = 0;
#endif

void
c_seg_trim_tail(c_segment_t c_seg)
{
	c_slot_t        cs;
	uint32_t        c_size;
	uint32_t        c_offset;
	uint32_t        c_rounded_size;
	uint16_t        current_nextslot;
	uint32_t        current_populated_offset;

	if (c_seg->c_bytes_used == 0) {
		return;
	}
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
				c_seg->c_populated_offset = (c_offset + (C_SEG_BYTES_TO_OFFSET(PAGE_SIZE) - 1)) &
				    ~(C_SEG_BYTES_TO_OFFSET(PAGE_SIZE) - 1);

				if (c_seg->c_firstemptyslot > c_seg->c_nextslot) {
					c_seg->c_firstemptyslot = c_seg->c_nextslot;
				}
#if DEVELOPMENT || DEBUG
				c_seg_trim_page_count += ((round_page_32(C_SEG_OFFSET_TO_BYTES(current_populated_offset)) -
				    round_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset))) /
				    PAGE_SIZE);
#endif
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
	uint32_t        c_offset = 0;
	uint32_t        old_populated_offset;
	uint32_t        c_rounded_size;
	uint32_t        c_size;
	int             c_indx = 0;
	int             i;
	c_slot_t        c_dst;
	c_slot_t        c_src;

	assert(c_seg->c_busy);

#if VALIDATE_C_SEGMENTS
	c_seg_validate(c_seg, FALSE);
#endif
	if (c_seg->c_bytes_used == 0) {
		c_seg_free(c_seg);
		return 1;
	}
	lck_mtx_unlock_always(&c_seg->c_lock);

	if (c_seg->c_firstemptyslot >= c_seg->c_nextslot || C_SEG_UNUSED_BYTES(c_seg) < PAGE_SIZE) {
		goto done;
	}

/* TODO: assert first emptyslot's c_size is actually 0 */

#if DEVELOPMENT || DEBUG
	C_SEG_MAKE_WRITEABLE(c_seg);
#endif

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

		if (c_size == 0) {
			continue;
		}

		c_rounded_size = (c_size + C_SEG_OFFSET_ALIGNMENT_MASK) & ~C_SEG_OFFSET_ALIGNMENT_MASK;
/* N.B.: This memcpy may be an overlapping copy */
		memcpy(&c_seg->c_store.c_buffer[c_offset], &c_seg->c_store.c_buffer[c_src->c_offset], c_rounded_size);

		cslot_copy(c_dst, c_src);
		c_dst->c_offset = c_offset;

		slot_ptr = (c_slot_mapping_t)C_SLOT_UNPACK_PTR(c_dst);
		slot_ptr->s_cindx = c_indx;

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
		uint32_t        gc_size;
		int32_t         *gc_ptr;

		gc_size = C_SEG_OFFSET_TO_BYTES(old_populated_offset - c_seg->c_populated_offset);
		gc_ptr = &c_seg->c_store.c_buffer[c_seg->c_populated_offset];

		kernel_memory_depopulate(compressor_map, (vm_offset_t)gc_ptr, gc_size, KMA_COMPRESSOR);
	}

#if DEVELOPMENT || DEBUG
	C_SEG_WRITE_PROTECT(c_seg);
#endif

done:
	if (clear_busy == TRUE) {
		lck_mtx_lock_spin_always(&c_seg->c_lock);
		C_SEG_WAKEUP_DONE(c_seg);
		lck_mtx_unlock_always(&c_seg->c_lock);
	}
	return 0;
}


static void
c_seg_alloc_nextslot(c_segment_t c_seg)
{
	struct c_slot   *old_slot_array = NULL;
	struct c_slot   *new_slot_array = NULL;
	int             newlen;
	int             oldlen;

	if (c_seg->c_nextslot < c_seg_fixed_array_len) {
		return;
	}

	if ((c_seg->c_nextslot - c_seg_fixed_array_len) >= c_seg->c_slot_var_array_len) {
		oldlen = c_seg->c_slot_var_array_len;
		old_slot_array = c_seg->c_slot_var_array;

		if (oldlen == 0) {
			newlen = C_SEG_SLOT_VAR_ARRAY_MIN_LEN;
		} else {
			newlen = oldlen * 2;
		}

		new_slot_array = (struct c_slot *)kalloc(sizeof(struct c_slot) * newlen);

		lck_mtx_lock_spin_always(&c_seg->c_lock);

		if (old_slot_array) {
			memcpy((char *)new_slot_array, (char *)old_slot_array, sizeof(struct c_slot) * oldlen);
		}

		c_seg->c_slot_var_array_len = newlen;
		c_seg->c_slot_var_array = new_slot_array;

		lck_mtx_unlock_always(&c_seg->c_lock);

		if (old_slot_array) {
			kfree(old_slot_array, sizeof(struct c_slot) * oldlen);
		}
	}
}



struct {
	uint64_t asked_permission;
	uint64_t compactions;
	uint64_t moved_slots;
	uint64_t moved_bytes;
	uint64_t wasted_space_in_swapouts;
	uint64_t count_of_swapouts;
	uint64_t count_of_freed_segs;
} c_seg_major_compact_stats;


#define C_MAJOR_COMPACTION_SIZE_APPROPRIATE     ((C_SEG_BUFSIZE * 90) / 100)


boolean_t
c_seg_major_compact_ok(
	c_segment_t c_seg_dst,
	c_segment_t c_seg_src)
{
	c_seg_major_compact_stats.asked_permission++;

	if (c_seg_src->c_bytes_used >= C_MAJOR_COMPACTION_SIZE_APPROPRIATE &&
	    c_seg_dst->c_bytes_used >= C_MAJOR_COMPACTION_SIZE_APPROPRIATE) {
		return FALSE;
	}

	if (c_seg_dst->c_nextoffset >= C_SEG_OFF_LIMIT || c_seg_dst->c_nextslot >= C_SLOT_MAX_INDEX) {
		/*
		 * destination segment is full... can't compact
		 */
		return FALSE;
	}

	return TRUE;
}


boolean_t
c_seg_major_compact(
	c_segment_t c_seg_dst,
	c_segment_t c_seg_src)
{
	c_slot_mapping_t slot_ptr;
	uint32_t        c_rounded_size;
	uint32_t        c_size;
	uint16_t        dst_slot;
	int             i;
	c_slot_t        c_dst;
	c_slot_t        c_src;
	boolean_t       keep_compacting = TRUE;

	/*
	 * segments are not locked but they are both marked c_busy
	 * which keeps c_decompress from working on them...
	 * we can safely allocate new pages, move compressed data
	 * from c_seg_src to c_seg_dst and update both c_segment's
	 * state w/o holding the master lock
	 */
#if DEVELOPMENT || DEBUG
	C_SEG_MAKE_WRITEABLE(c_seg_dst);
#endif

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
			int     size_to_populate;

			/* doesn't fit */
			size_to_populate = C_SEG_BUFSIZE - C_SEG_OFFSET_TO_BYTES(c_seg_dst->c_populated_offset);

			if (size_to_populate == 0) {
				/* can't fit */
				keep_compacting = FALSE;
				break;
			}
			if (size_to_populate > C_SEG_MAX_POPULATE_SIZE) {
				size_to_populate = C_SEG_MAX_POPULATE_SIZE;
			}

			kernel_memory_populate(compressor_map,
			    (vm_offset_t) &c_seg_dst->c_store.c_buffer[c_seg_dst->c_populated_offset],
			    size_to_populate,
			    KMA_COMPRESSOR,
			    VM_KERN_MEMORY_COMPRESSOR);

			c_seg_dst->c_populated_offset += C_SEG_BYTES_TO_OFFSET(size_to_populate);
			assert(C_SEG_OFFSET_TO_BYTES(c_seg_dst->c_populated_offset) <= C_SEG_BUFSIZE);
		}
		c_seg_alloc_nextslot(c_seg_dst);

		c_dst = C_SEG_SLOT_FROM_INDEX(c_seg_dst, c_seg_dst->c_nextslot);

		memcpy(&c_seg_dst->c_store.c_buffer[c_seg_dst->c_nextoffset], &c_seg_src->c_store.c_buffer[c_src->c_offset], c_size);

		c_rounded_size = (c_size + C_SEG_OFFSET_ALIGNMENT_MASK) & ~C_SEG_OFFSET_ALIGNMENT_MASK;

		c_seg_major_compact_stats.moved_slots++;
		c_seg_major_compact_stats.moved_bytes += c_size;

		cslot_copy(c_dst, c_src);
		c_dst->c_offset = c_seg_dst->c_nextoffset;

		if (c_seg_dst->c_firstemptyslot == c_seg_dst->c_nextslot) {
			c_seg_dst->c_firstemptyslot++;
		}
		c_seg_dst->c_slots_used++;
		c_seg_dst->c_nextslot++;
		c_seg_dst->c_bytes_used += c_rounded_size;
		c_seg_dst->c_nextoffset += C_SEG_BYTES_TO_OFFSET(c_rounded_size);

		PACK_C_SIZE(c_src, 0);

		c_seg_src->c_bytes_used -= c_rounded_size;
		c_seg_src->c_bytes_unused += c_rounded_size;
		c_seg_src->c_firstemptyslot = 0;

		assert(c_seg_src->c_slots_used);
		c_seg_src->c_slots_used--;

		if (c_seg_dst->c_nextoffset >= C_SEG_OFF_LIMIT || c_seg_dst->c_nextslot >= C_SLOT_MAX_INDEX) {
			/* dest segment is now full */
			keep_compacting = FALSE;
			break;
		}
	}
#if DEVELOPMENT || DEBUG
	C_SEG_WRITE_PROTECT(c_seg_dst);
#endif
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
	return keep_compacting;
}


uint64_t
vm_compressor_compute_elapsed_msecs(clock_sec_t end_sec, clock_nsec_t end_nsec, clock_sec_t start_sec, clock_nsec_t start_nsec)
{
	uint64_t end_msecs;
	uint64_t start_msecs;

	end_msecs = (end_sec * 1000) + end_nsec / 1000000;
	start_msecs = (start_sec * 1000) + start_nsec / 1000000;

	return end_msecs - start_msecs;
}



uint32_t compressor_eval_period_in_msecs = 250;
uint32_t compressor_sample_min_in_msecs = 500;
uint32_t compressor_sample_max_in_msecs = 10000;
uint32_t compressor_thrashing_threshold_per_10msecs = 50;
uint32_t compressor_thrashing_min_per_10msecs = 20;

/* When true, reset sample data next chance we get. */
static boolean_t        compressor_need_sample_reset = FALSE;


void
compute_swapout_target_age(void)
{
	clock_sec_t     cur_ts_sec;
	clock_nsec_t    cur_ts_nsec;
	uint32_t        min_operations_needed_in_this_sample;
	uint64_t        elapsed_msecs_in_eval;
	uint64_t        elapsed_msecs_in_sample;
	boolean_t       need_eval_reset = FALSE;

	clock_get_system_nanotime(&cur_ts_sec, &cur_ts_nsec);

	elapsed_msecs_in_sample = vm_compressor_compute_elapsed_msecs(cur_ts_sec, cur_ts_nsec, start_of_sample_period_sec, start_of_sample_period_nsec);

	if (compressor_need_sample_reset ||
	    elapsed_msecs_in_sample >= compressor_sample_max_in_msecs) {
		compressor_need_sample_reset = TRUE;
		need_eval_reset = TRUE;
		goto done;
	}
	elapsed_msecs_in_eval = vm_compressor_compute_elapsed_msecs(cur_ts_sec, cur_ts_nsec, start_of_eval_period_sec, start_of_eval_period_nsec);

	if (elapsed_msecs_in_eval < compressor_eval_period_in_msecs) {
		goto done;
	}
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
		uint64_t        running_total;
		uint64_t        working_target;
		uint64_t        aging_target;
		uint32_t        oldest_age_of_csegs_sampled = 0;
		uint64_t        working_set_approximation = 0;

		swapout_target_age = 0;

		working_target = (sample_period_decompression_count / 100) * 95;                /* 95 percent */
		aging_target = (sample_period_decompression_count / 100) * 1;                   /* 1 percent */
		running_total = 0;

		for (oldest_age_of_csegs_sampled = 0; oldest_age_of_csegs_sampled < DECOMPRESSION_SAMPLE_MAX_AGE; oldest_age_of_csegs_sampled++) {
			running_total += age_of_decompressions_during_sample_period[oldest_age_of_csegs_sampled];

			working_set_approximation += oldest_age_of_csegs_sampled * age_of_decompressions_during_sample_period[oldest_age_of_csegs_sampled];

			if (running_total >= working_target) {
				break;
			}
		}
		if (oldest_age_of_csegs_sampled < DECOMPRESSION_SAMPLE_MAX_AGE) {
			working_set_approximation = (working_set_approximation * 1000) / elapsed_msecs_in_sample;

			if (working_set_approximation < VM_PAGE_COMPRESSOR_COUNT) {
				running_total = overage_decompressions_during_sample_period;

				for (oldest_age_of_csegs_sampled = DECOMPRESSION_SAMPLE_MAX_AGE - 1; oldest_age_of_csegs_sampled; oldest_age_of_csegs_sampled--) {
					running_total += age_of_decompressions_during_sample_period[oldest_age_of_csegs_sampled];

					if (running_total >= aging_target) {
						break;
					}
				}
				swapout_target_age = (uint32_t)cur_ts_sec - oldest_age_of_csegs_sampled;

				KERNEL_DEBUG(0xe0400020 | DBG_FUNC_END, swapout_target_age, working_set_approximation, VM_PAGE_COMPRESSOR_COUNT, 2, 0);
			} else {
				KERNEL_DEBUG(0xe0400020 | DBG_FUNC_END, working_set_approximation, VM_PAGE_COMPRESSOR_COUNT, 0, 3, 0);
			}
		} else {
			KERNEL_DEBUG(0xe0400020 | DBG_FUNC_END, working_target, running_total, 0, 4, 0);
		}

		compressor_need_sample_reset = TRUE;
		need_eval_reset = TRUE;
	} else {
		KERNEL_DEBUG(0xe0400020 | DBG_FUNC_END, sample_period_decompression_count, (compressor_thrashing_threshold_per_10msecs * elapsed_msecs_in_sample) / 10, 0, 6, 0);
	}
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


int             compaction_swapper_init_now = 0;
int             compaction_swapper_running = 0;
int             compaction_swapper_awakened = 0;
int             compaction_swapper_abort = 0;


#if CONFIG_JETSAM
boolean_t       memorystatus_kill_on_VM_compressor_thrashing(boolean_t);
boolean_t       memorystatus_kill_on_VM_compressor_space_shortage(boolean_t);
boolean_t       memorystatus_kill_on_FC_thrashing(boolean_t);
int             compressor_thrashing_induced_jetsam = 0;
int             filecache_thrashing_induced_jetsam = 0;
static boolean_t        vm_compressor_thrashing_detected = FALSE;
#endif /* CONFIG_JETSAM */

static boolean_t
compressor_needs_to_swap(void)
{
	boolean_t       should_swap = FALSE;

	if (vm_swapout_ripe_segments == TRUE && c_overage_swapped_count < c_overage_swapped_limit) {
		c_segment_t     c_seg;
		clock_sec_t     now;
		clock_sec_t     age;
		clock_nsec_t    nsec;

		clock_get_system_nanotime(&now, &nsec);
		age = 0;

		lck_mtx_lock_spin_always(c_list_lock);

		if (!queue_empty(&c_age_list_head)) {
			c_seg = (c_segment_t) queue_first(&c_age_list_head);

			age = now - c_seg->c_creation_ts;
		}
		lck_mtx_unlock_always(c_list_lock);

		if (age >= vm_ripe_target_age) {
			return TRUE;
		}
	}
	if (VM_CONFIG_SWAP_IS_ACTIVE) {
		if (COMPRESSOR_NEEDS_TO_SWAP()) {
			return TRUE;
		}
		if (VM_PAGE_Q_THROTTLED(&vm_pageout_queue_external) && vm_page_anonymous_count < (vm_page_inactive_count / 20)) {
			return TRUE;
		}
		if (vm_page_free_count < (vm_page_free_reserved - (COMPRESSOR_FREE_RESERVED_LIMIT * 2))) {
			return TRUE;
		}
	}
	compute_swapout_target_age();

	if (swapout_target_age) {
		c_segment_t     c_seg;

		lck_mtx_lock_spin_always(c_list_lock);

		if (!queue_empty(&c_age_list_head)) {
			c_seg = (c_segment_t) queue_first(&c_age_list_head);

			if (c_seg->c_creation_ts > swapout_target_age) {
				swapout_target_age = 0;
			}
		}
		lck_mtx_unlock_always(c_list_lock);
	}
#if CONFIG_PHANTOM_CACHE
	if (vm_phantom_cache_check_pressure()) {
		should_swap = TRUE;
	}
#endif
	if (swapout_target_age) {
		should_swap = TRUE;
	}

#if CONFIG_JETSAM
	if (should_swap || vm_compressor_low_on_space() == TRUE) {
		if (vm_compressor_thrashing_detected == FALSE) {
			vm_compressor_thrashing_detected = TRUE;

			if (swapout_target_age || vm_compressor_low_on_space() == TRUE) {
				if (swapout_target_age) {
					/* The compressor is thrashing. */
					memorystatus_kill_on_VM_compressor_thrashing(TRUE /* async */);
				} else {
					/* The compressor is running low on space. */
					memorystatus_kill_on_VM_compressor_space_shortage(TRUE /* async */);
				}
				compressor_thrashing_induced_jetsam++;
			} else {
				memorystatus_kill_on_FC_thrashing(TRUE /* async */);
				filecache_thrashing_induced_jetsam++;
			}
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

	if (should_swap == FALSE) {
		/*
		 * vm_compressor_needs_to_major_compact returns true only if we're
		 * about to run out of available compressor segments... in this
		 * case, we absolutely need to run a major compaction even if
		 * we've just kicked off a jetsam or we don't otherwise need to
		 * swap... terminating objects releases
		 * pages back to the uncompressed cache, but does not guarantee
		 * that we will free up even a single compression segment
		 */
		should_swap = vm_compressor_needs_to_major_compact();
	}

	/*
	 * returning TRUE when swap_supported == FALSE
	 * will cause the major compaction engine to
	 * run, but will not trigger any swapping...
	 * segments that have been major compacted
	 * will be moved to the majorcompact queue
	 */
	return should_swap;
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
uint32_t vm_run_compactor_already_running = 0;
uint32_t vm_run_compactor_empty_minor_q = 0;
uint32_t vm_run_compactor_did_compact = 0;
uint32_t vm_run_compactor_waited = 0;

void
vm_run_compactor(void)
{
	if (c_segment_count == 0) {
		return;
	}

	lck_mtx_lock_spin_always(c_list_lock);

	if (c_minor_count == 0) {
		vm_run_compactor_empty_minor_q++;

		lck_mtx_unlock_always(c_list_lock);
		return;
	}
	if (compaction_swapper_running) {
		if (vm_pageout_state.vm_restricted_to_single_processor == FALSE) {
			vm_run_compactor_already_running++;

			lck_mtx_unlock_always(c_list_lock);
			return;
		}
		vm_run_compactor_waited++;

		assert_wait((event_t)&compaction_swapper_running, THREAD_UNINT);

		lck_mtx_unlock_always(c_list_lock);

		thread_block(THREAD_CONTINUE_NULL);

		return;
	}
	vm_run_compactor_did_compact++;

	fastwake_warmup = FALSE;
	compaction_swapper_running = 1;

	vm_compressor_do_delayed_compactions(FALSE);

	compaction_swapper_running = 0;

	lck_mtx_unlock_always(c_list_lock);

	thread_wakeup((event_t)&compaction_swapper_running);
}


void
vm_wake_compactor_swapper(void)
{
	if (compaction_swapper_running || compaction_swapper_awakened || c_segment_count == 0) {
		return;
	}

	if (c_minor_count || vm_compressor_needs_to_major_compact()) {
		lck_mtx_lock_spin_always(c_list_lock);

		fastwake_warmup = FALSE;

		if (compaction_swapper_running == 0 && compaction_swapper_awakened == 0) {
			vm_wake_compactor_swapper_calls++;

			compaction_swapper_awakened = 1;
			thread_wakeup((event_t)&c_compressor_swap_trigger);
		}
		lck_mtx_unlock_always(c_list_lock);
	}
}


void
vm_consider_swapping()
{
	c_segment_t     c_seg, c_seg_next;
	clock_sec_t     now;
	clock_nsec_t    nsec;

	assert(VM_CONFIG_SWAP_IS_PRESENT);

	lck_mtx_lock_spin_always(c_list_lock);

	compaction_swapper_abort = 1;

	while (compaction_swapper_running) {
		assert_wait((event_t)&compaction_swapper_running, THREAD_UNINT);

		lck_mtx_unlock_always(c_list_lock);

		thread_block(THREAD_CONTINUE_NULL);

		lck_mtx_lock_spin_always(c_list_lock);
	}
	compaction_swapper_abort = 0;
	compaction_swapper_running = 1;

	vm_swapout_ripe_segments = TRUE;

	if (!queue_empty(&c_major_list_head)) {
		clock_get_system_nanotime(&now, &nsec);

		c_seg = (c_segment_t)queue_first(&c_major_list_head);

		while (!queue_end(&c_major_list_head, (queue_entry_t)c_seg)) {
			if (c_overage_swapped_count >= c_overage_swapped_limit) {
				break;
			}

			c_seg_next = (c_segment_t) queue_next(&c_seg->c_age_list);

			if ((now - c_seg->c_creation_ts) >= vm_ripe_target_age) {
				lck_mtx_lock_spin_always(&c_seg->c_lock);

				c_seg_switch_state(c_seg, C_ON_AGE_Q, FALSE);

				lck_mtx_unlock_always(&c_seg->c_lock);
			}
			c_seg = c_seg_next;
		}
	}
	vm_compressor_compact_and_swap(FALSE);

	compaction_swapper_running = 0;

	vm_swapout_ripe_segments = FALSE;

	lck_mtx_unlock_always(c_list_lock);

	thread_wakeup((event_t)&compaction_swapper_running);
}


void
vm_consider_waking_compactor_swapper(void)
{
	boolean_t       need_wakeup = FALSE;

	if (c_segment_count == 0) {
		return;
	}

	if (compaction_swapper_running || compaction_swapper_awakened) {
		return;
	}

	if (!compaction_swapper_inited && !compaction_swapper_init_now) {
		compaction_swapper_init_now = 1;
		need_wakeup = TRUE;
	}

	if (c_minor_count && (COMPRESSOR_NEEDS_TO_MINOR_COMPACT())) {
		need_wakeup = TRUE;
	} else if (compressor_needs_to_swap()) {
		need_wakeup = TRUE;
	} else if (c_minor_count) {
		uint64_t        total_bytes;

		total_bytes = compressor_object->resident_page_count * PAGE_SIZE_64;

		if ((total_bytes - compressor_bytes_used) > total_bytes / 10) {
			need_wakeup = TRUE;
		}
	}
	if (need_wakeup == TRUE) {
		lck_mtx_lock_spin_always(c_list_lock);

		fastwake_warmup = FALSE;

		if (compaction_swapper_running == 0 && compaction_swapper_awakened == 0) {
			memoryshot(VM_WAKEUP_COMPACTOR_SWAPPER, DBG_FUNC_NONE);

			compaction_swapper_awakened = 1;
			thread_wakeup((event_t)&c_compressor_swap_trigger);
		}
		lck_mtx_unlock_always(c_list_lock);
	}
}


#define C_SWAPOUT_LIMIT                 4
#define DELAYED_COMPACTIONS_PER_PASS    30

void
vm_compressor_do_delayed_compactions(boolean_t flush_all)
{
	c_segment_t     c_seg;
	int             number_compacted = 0;
	boolean_t       needs_to_swap = FALSE;


#if !CONFIG_EMBEDDED
	LCK_MTX_ASSERT(c_list_lock, LCK_MTX_ASSERT_OWNED);
#endif /* !CONFIG_EMBEDDED */

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

		if (VM_CONFIG_SWAP_IS_ACTIVE && (number_compacted++ > DELAYED_COMPACTIONS_PER_PASS)) {
			if ((flush_all == TRUE || compressor_needs_to_swap() == TRUE) && c_swapout_count < C_SWAPOUT_LIMIT) {
				needs_to_swap = TRUE;
			}

			number_compacted = 0;
		}
		lck_mtx_lock_spin_always(c_list_lock);
	}
}


#define C_SEGMENT_SWAPPEDIN_AGE_LIMIT   10

static void
vm_compressor_age_swapped_in_segments(boolean_t flush_all)
{
	c_segment_t     c_seg;
	clock_sec_t     now;
	clock_nsec_t    nsec;

	clock_get_system_nanotime(&now, &nsec);

	while (!queue_empty(&c_swappedin_list_head)) {
		c_seg = (c_segment_t)queue_first(&c_swappedin_list_head);

		if (flush_all == FALSE && (now - c_seg->c_swappedin_ts) < C_SEGMENT_SWAPPEDIN_AGE_LIMIT) {
			break;
		}

		lck_mtx_lock_spin_always(&c_seg->c_lock);

		c_seg_switch_state(c_seg, C_ON_AGE_Q, FALSE);

		lck_mtx_unlock_always(&c_seg->c_lock);
	}
}


extern  int     vm_num_swap_files;
extern  int     vm_num_pinned_swap_files;
extern  int     vm_swappin_enabled;

extern  unsigned int    vm_swapfile_total_segs_used;
extern  unsigned int    vm_swapfile_total_segs_alloced;


void
vm_compressor_flush(void)
{
	uint64_t        vm_swap_put_failures_at_start;
	wait_result_t   wait_result = 0;
	AbsoluteTime    startTime, endTime;
	clock_sec_t     now_sec;
	clock_nsec_t    now_nsec;
	uint64_t        nsec;

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
		assert_wait_timeout((event_t) &compaction_swapper_running, THREAD_INTERRUPTIBLE, 5000, 1000 * NSEC_PER_USEC);

		lck_mtx_unlock_always(c_list_lock);

		wait_result = thread_block(THREAD_CONTINUE_NULL);

		lck_mtx_lock_spin_always(c_list_lock);

		if (wait_result == THREAD_TIMED_OUT) {
			break;
		}
	}
	hibernate_flushing = FALSE;
	compaction_swapper_running = 0;

	if (vm_swap_put_failures > vm_swap_put_failures_at_start) {
		HIBLOG("vm_compressor_flush failed to clean %llu segments - vm_page_compressor_count(%d)\n",
		    vm_swap_put_failures - vm_swap_put_failures_at_start, VM_PAGE_COMPRESSOR_COUNT);
	}

	lck_mtx_unlock_always(c_list_lock);

	thread_wakeup((event_t)&compaction_swapper_running);

	clock_get_uptime(&endTime);
	SUB_ABSOLUTETIME(&endTime, &startTime);
	absolutetime_to_nanoseconds(endTime, &nsec);

	HIBLOG("vm_compressor_flush completed - took %qd msecs - vm_num_swap_files = %d, vm_num_pinned_swap_files = %d, vm_swappin_enabled = %d\n",
	    nsec / 1000000ULL, vm_num_swap_files, vm_num_pinned_swap_files, vm_swappin_enabled);
}


int             compaction_swap_trigger_thread_awakened = 0;

static void
vm_compressor_swap_trigger_thread(void)
{
	current_thread()->options |= TH_OPT_VMPRIV;

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
	if (compaction_swapper_init_now) {
		vm_compaction_swapper_do_init();

		if (vm_pageout_state.vm_restricted_to_single_processor == TRUE) {
			thread_vm_bind_group_add();
		}
		thread_set_thread_name(current_thread(), "VM_cswap_trigger");
		compaction_swapper_init_now = 0;
	}
	lck_mtx_lock_spin_always(c_list_lock);

	compaction_swap_trigger_thread_awakened++;
	compaction_swapper_awakened = 0;

	if (compaction_swapper_running == 0) {
		compaction_swapper_running = 1;

		vm_compressor_compact_and_swap(FALSE);

		compaction_swapper_running = 0;
	}
	assert_wait((event_t)&c_compressor_swap_trigger, THREAD_UNINT);

	if (compaction_swapper_running == 0) {
		thread_wakeup((event_t)&compaction_swapper_running);
	}

	lck_mtx_unlock_always(c_list_lock);

	thread_block((thread_continue_t)vm_compressor_swap_trigger_thread);

	/* NOTREACHED */
}


void
vm_compressor_record_warmup_start(void)
{
	c_segment_t     c_seg;

	lck_mtx_lock_spin_always(c_list_lock);

	if (first_c_segment_to_warm_generation_id == 0) {
		if (!queue_empty(&c_age_list_head)) {
			c_seg = (c_segment_t)queue_last(&c_age_list_head);

			first_c_segment_to_warm_generation_id = c_seg->c_generation_id;
		} else {
			first_c_segment_to_warm_generation_id = 0;
		}

		fastwake_recording_in_progress = TRUE;
	}
	lck_mtx_unlock_always(c_list_lock);
}


void
vm_compressor_record_warmup_end(void)
{
	c_segment_t     c_seg;

	lck_mtx_lock_spin_always(c_list_lock);

	if (fastwake_recording_in_progress == TRUE) {
		if (!queue_empty(&c_age_list_head)) {
			c_seg = (c_segment_t)queue_last(&c_age_list_head);

			last_c_segment_to_warm_generation_id = c_seg->c_generation_id;
		} else {
			last_c_segment_to_warm_generation_id = first_c_segment_to_warm_generation_id;
		}

		fastwake_recording_in_progress = FALSE;

		HIBLOG("vm_compressor_record_warmup (%qd - %qd)\n", first_c_segment_to_warm_generation_id, last_c_segment_to_warm_generation_id);
	}
	lck_mtx_unlock_always(c_list_lock);
}


#define DELAY_TRIM_ON_WAKE_SECS         25

void
vm_compressor_delay_trim(void)
{
	clock_sec_t     sec;
	clock_nsec_t    nsec;

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

	if (compaction_swapper_running == 0 && compaction_swapper_awakened == 0) {
		fastwake_warmup = TRUE;

		compaction_swapper_awakened = 1;
		thread_wakeup((event_t)&c_compressor_swap_trigger);
	}
	lck_mtx_unlock_always(c_list_lock);
}

void
do_fastwake_warmup_all(void)
{
	lck_mtx_lock_spin_always(c_list_lock);

	if (queue_empty(&c_swappedout_list_head) && queue_empty(&c_swappedout_sparse_list_head)) {
		lck_mtx_unlock_always(c_list_lock);
		return;
	}

	fastwake_warmup = TRUE;

	do_fastwake_warmup(&c_swappedout_list_head, TRUE);

	do_fastwake_warmup(&c_swappedout_sparse_list_head, TRUE);

	fastwake_warmup = FALSE;

	lck_mtx_unlock_always(c_list_lock);
}

void
do_fastwake_warmup(queue_head_t *c_queue, boolean_t consider_all_cseg)
{
	c_segment_t     c_seg = NULL;
	AbsoluteTime    startTime, endTime;
	uint64_t        nsec;


	HIBLOG("vm_compressor_fastwake_warmup (%qd - %qd) - starting\n", first_c_segment_to_warm_generation_id, last_c_segment_to_warm_generation_id);

	clock_get_uptime(&startTime);

	lck_mtx_unlock_always(c_list_lock);

	proc_set_thread_policy(current_thread(),
	    TASK_POLICY_INTERNAL, TASK_POLICY_IO, THROTTLE_LEVEL_COMPRESSOR_TIER2);

	PAGE_REPLACEMENT_DISALLOWED(TRUE);

	lck_mtx_lock_spin_always(c_list_lock);

	while (!queue_empty(c_queue) && fastwake_warmup == TRUE) {
		c_seg = (c_segment_t) queue_first(c_queue);

		if (consider_all_cseg == FALSE) {
			if (c_seg->c_generation_id < first_c_segment_to_warm_generation_id ||
			    c_seg->c_generation_id > last_c_segment_to_warm_generation_id) {
				break;
			}

			if (vm_page_free_count < (AVAILABLE_MEMORY / 4)) {
				break;
			}
		}

		lck_mtx_lock_spin_always(&c_seg->c_lock);
		lck_mtx_unlock_always(c_list_lock);

		if (c_seg->c_busy) {
			PAGE_REPLACEMENT_DISALLOWED(FALSE);
			c_seg_wait_on_busy(c_seg);
			PAGE_REPLACEMENT_DISALLOWED(TRUE);
		} else {
			if (c_seg_swapin(c_seg, TRUE, FALSE) == 0) {
				lck_mtx_unlock_always(&c_seg->c_lock);
			}
			c_segment_warmup_count++;

			PAGE_REPLACEMENT_DISALLOWED(FALSE);
			vm_pageout_io_throttle();
			PAGE_REPLACEMENT_DISALLOWED(TRUE);
		}
		lck_mtx_lock_spin_always(c_list_lock);
	}
	lck_mtx_unlock_always(c_list_lock);

	PAGE_REPLACEMENT_DISALLOWED(FALSE);

	proc_set_thread_policy(current_thread(),
	    TASK_POLICY_INTERNAL, TASK_POLICY_IO, THROTTLE_LEVEL_COMPRESSOR_TIER0);

	clock_get_uptime(&endTime);
	SUB_ABSOLUTETIME(&endTime, &startTime);
	absolutetime_to_nanoseconds(endTime, &nsec);

	HIBLOG("vm_compressor_fastwake_warmup completed - took %qd msecs\n", nsec / 1000000ULL);

	lck_mtx_lock_spin_always(c_list_lock);

	if (consider_all_cseg == FALSE) {
		first_c_segment_to_warm_generation_id = last_c_segment_to_warm_generation_id = 0;
	}
}


void
vm_compressor_compact_and_swap(boolean_t flush_all)
{
	c_segment_t     c_seg, c_seg_next;
	boolean_t       keep_compacting;
	clock_sec_t     now;
	clock_nsec_t    nsec;


	if (fastwake_warmup == TRUE) {
		uint64_t        starting_warmup_count;

		starting_warmup_count = c_segment_warmup_count;

		KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 11) | DBG_FUNC_START, c_segment_warmup_count,
		    first_c_segment_to_warm_generation_id, last_c_segment_to_warm_generation_id, 0, 0);
		do_fastwake_warmup(&c_swappedout_list_head, FALSE);
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

	/*
	 * we only need to grab the timestamp once per
	 * invocation of this function since the
	 * timescale we're interested in is measured
	 * in days
	 */
	clock_get_system_nanotime(&now, &nsec);

	while (!queue_empty(&c_age_list_head) && compaction_swapper_abort == 0) {
		if (hibernate_flushing == TRUE) {
			clock_sec_t     sec;

			if (hibernate_should_abort()) {
				HIBLOG("vm_compressor_flush - hibernate_should_abort returned TRUE\n");
				break;
			}
			if (hibernate_no_swapspace == TRUE) {
				HIBLOG("vm_compressor_flush - out of swap space\n");
				break;
			}
			if (vm_swap_files_pinned() == FALSE) {
				HIBLOG("vm_compressor_flush - unpinned swap files\n");
				break;
			}
			if (hibernate_in_progress_with_pinned_swap == TRUE &&
			    (vm_swapfile_total_segs_alloced == vm_swapfile_total_segs_used)) {
				HIBLOG("vm_compressor_flush - out of pinned swap space\n");
				break;
			}
			clock_get_system_nanotime(&sec, &nsec);

			if (sec > hibernate_flushing_deadline) {
				HIBLOG("vm_compressor_flush - failed to finish before deadline\n");
				break;
			}
		}
		if (c_swapout_count >= C_SWAPOUT_LIMIT) {
			assert_wait_timeout((event_t) &compaction_swapper_running, THREAD_INTERRUPTIBLE, 100, 1000 * NSEC_PER_USEC);

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
			boolean_t       needs_to_swap;

			lck_mtx_unlock_always(c_list_lock);

			needs_to_swap = compressor_needs_to_swap();

#if !CONFIG_EMBEDDED
			if (needs_to_swap == TRUE && vm_swap_low_on_space()) {
				vm_compressor_take_paging_space_action();
			}
#endif /* !CONFIG_EMBEDDED */

			lck_mtx_lock_spin_always(c_list_lock);

			if (needs_to_swap == FALSE) {
				break;
			}
		}
		if (queue_empty(&c_age_list_head)) {
			break;
		}
		c_seg = (c_segment_t) queue_first(&c_age_list_head);

		assert(c_seg->c_state == C_ON_AGE_Q);

		if (flush_all == TRUE && c_seg->c_generation_id > c_generation_id_flush_barrier) {
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
			c_seg_major_compact_stats.count_of_freed_segs++;
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

			if (queue_end(&c_age_list_head, (queue_entry_t)c_seg_next)) {
				break;
			}

			assert(c_seg_next->c_state == C_ON_AGE_Q);

			if (c_seg_major_compact_ok(c_seg, c_seg_next) == FALSE) {
				break;
			}

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
				c_seg_major_compact_stats.count_of_freed_segs++;
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
			if (c_seg_minor_compaction_and_unlock(c_seg_next, TRUE)) {
				c_seg_major_compact_stats.count_of_freed_segs++;
			}

			PAGE_REPLACEMENT_DISALLOWED(FALSE);

			/* relock the list */
			lck_mtx_lock_spin_always(c_list_lock);
		} /* major compaction */

		lck_mtx_lock_spin_always(&c_seg->c_lock);

		assert(c_seg->c_busy);
		assert(!c_seg->c_on_minorcompact_q);

		if (VM_CONFIG_SWAP_IS_ACTIVE) {
			/*
			 * This mode of putting a generic c_seg on the swapout list is
			 * only supported when we have general swapping enabled
			 */
			c_seg_switch_state(c_seg, C_ON_SWAPOUT_Q, FALSE);
		} else {
			if ((vm_swapout_ripe_segments == TRUE && c_overage_swapped_count < c_overage_swapped_limit)) {
				assert(VM_CONFIG_SWAP_IS_PRESENT);
				/*
				 * we are running compressor sweeps with swap-behind
				 * make sure the c_seg has aged enough before swapping it
				 * out...
				 */
				if ((now - c_seg->c_creation_ts) >= vm_ripe_target_age) {
					c_seg->c_overage_swap = TRUE;
					c_overage_swapped_count++;
					c_seg_switch_state(c_seg, C_ON_SWAPOUT_Q, FALSE);
				}
			}
		}
		if (c_seg->c_state == C_ON_AGE_Q) {
			/*
			 * this c_seg didn't get moved to the swapout queue
			 * so we need to move it out of the way...
			 * we just did a major compaction on it so put it
			 * on that queue
			 */
			c_seg_switch_state(c_seg, C_ON_MAJORCOMPACT_Q, FALSE);
		} else {
			c_seg_major_compact_stats.wasted_space_in_swapouts += C_SEG_BUFSIZE - c_seg->c_bytes_used;
			c_seg_major_compact_stats.count_of_swapouts++;
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


static c_segment_t
c_seg_allocate(c_segment_t *current_chead)
{
	c_segment_t     c_seg;
	int             min_needed;
	int             size_to_populate;

#if !CONFIG_EMBEDDED
	if (vm_compressor_low_on_space()) {
		vm_compressor_take_paging_space_action();
	}
#endif /* !CONFIG_EMBEDDED */

	if ((c_seg = *current_chead) == NULL) {
		uint32_t        c_segno;

		lck_mtx_lock_spin_always(c_list_lock);

		while (c_segments_busy == TRUE) {
			assert_wait((event_t) (&c_segments_busy), THREAD_UNINT);

			lck_mtx_unlock_always(c_list_lock);

			thread_block(THREAD_CONTINUE_NULL);

			lck_mtx_lock_spin_always(c_list_lock);
		}
		if (c_free_segno_head == (uint32_t)-1) {
			uint32_t        c_segments_available_new;

			if (c_segments_available >= c_segments_limit || c_segment_pages_compressed >= c_segment_pages_compressed_limit) {
				lck_mtx_unlock_always(c_list_lock);

				return NULL;
			}
			c_segments_busy = TRUE;
			lck_mtx_unlock_always(c_list_lock);

			kernel_memory_populate(compressor_map, (vm_offset_t)c_segments_next_page,
			    PAGE_SIZE, KMA_KOBJECT, VM_KERN_MEMORY_COMPRESSOR);
			c_segments_next_page += PAGE_SIZE;

			c_segments_available_new = c_segments_available + C_SEGMENTS_PER_PAGE;

			if (c_segments_available_new > c_segments_limit) {
				c_segments_available_new = c_segments_limit;
			}

			for (c_segno = c_segments_available + 1; c_segno < c_segments_available_new; c_segno++) {
				c_segments[c_segno - 1].c_segno = c_segno;
			}

			lck_mtx_lock_spin_always(c_list_lock);

			c_segments[c_segno - 1].c_segno = c_free_segno_head;
			c_free_segno_head = c_segments_available;
			c_segments_available = c_segments_available_new;

			c_segments_busy = FALSE;
			thread_wakeup((event_t) (&c_segments_busy));
		}
		c_segno = c_free_segno_head;
		assert(c_segno >= 0 && c_segno < c_segments_limit);

		c_free_segno_head = (uint32_t)c_segments[c_segno].c_segno;

		/*
		 * do the rest of the bookkeeping now while we're still behind
		 * the list lock and grab our generation id now into a local
		 * so that we can install it once we have the c_seg allocated
		 */
		c_segment_count++;
		if (c_segment_count > c_segment_count_max) {
			c_segment_count_max = c_segment_count;
		}

		lck_mtx_unlock_always(c_list_lock);

		c_seg = (c_segment_t)zalloc(compressor_segment_zone);
		bzero((char *)c_seg, sizeof(struct c_segment));

		c_seg->c_store.c_buffer = (int32_t *)C_SEG_BUFFER_ADDRESS(c_segno);

		lck_mtx_init(&c_seg->c_lock, &vm_compressor_lck_grp, &vm_compressor_lck_attr);

		c_seg->c_state = C_IS_EMPTY;
		c_seg->c_firstemptyslot = C_SLOT_MAX_INDEX;
		c_seg->c_mysegno = c_segno;

		lck_mtx_lock_spin_always(c_list_lock);
		c_empty_count++;
		c_seg_switch_state(c_seg, C_IS_FILLING, FALSE);
		c_segments[c_segno].c_seg = c_seg;
		assert(c_segments[c_segno].c_segno > c_segments_available);
		lck_mtx_unlock_always(c_list_lock);

		*current_chead = c_seg;

#if DEVELOPMENT || DEBUG
		C_SEG_MAKE_WRITEABLE(c_seg);
#endif
	}
	c_seg_alloc_nextslot(c_seg);

	size_to_populate = C_SEG_ALLOCSIZE - C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset);

	if (size_to_populate) {
		min_needed = PAGE_SIZE + (C_SEG_ALLOCSIZE - C_SEG_BUFSIZE);

		if (C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset - c_seg->c_nextoffset) < (unsigned) min_needed) {
			if (size_to_populate > C_SEG_MAX_POPULATE_SIZE) {
				size_to_populate = C_SEG_MAX_POPULATE_SIZE;
			}

			OSAddAtomic64(size_to_populate / PAGE_SIZE, &vm_pageout_vminfo.vm_compressor_pages_grabbed);

			kernel_memory_populate(compressor_map,
			    (vm_offset_t) &c_seg->c_store.c_buffer[c_seg->c_populated_offset],
			    size_to_populate,
			    KMA_COMPRESSOR,
			    VM_KERN_MEMORY_COMPRESSOR);
		} else {
			size_to_populate = 0;
		}
	}
	PAGE_REPLACEMENT_DISALLOWED(TRUE);

	lck_mtx_lock_spin_always(&c_seg->c_lock);

	if (size_to_populate) {
		c_seg->c_populated_offset += C_SEG_BYTES_TO_OFFSET(size_to_populate);
	}

	return c_seg;
}

#if DEVELOPMENT || DEBUG
#if CONFIG_FREEZE
extern boolean_t memorystatus_freeze_to_memory;
#endif /* CONFIG_FREEZE */
#endif /* DEVELOPMENT || DEBUG */

static void
c_current_seg_filled(c_segment_t c_seg, c_segment_t *current_chead)
{
	uint32_t        unused_bytes;
	uint32_t        offset_to_depopulate;
	int             new_state = C_ON_AGE_Q;
	clock_sec_t     sec;
	clock_nsec_t    nsec;
	boolean_t       head_insert = FALSE;

	unused_bytes = trunc_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset - c_seg->c_nextoffset));

	if (unused_bytes) {
		offset_to_depopulate = C_SEG_BYTES_TO_OFFSET(round_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_nextoffset)));

		/*
		 *  release the extra physical page(s) at the end of the segment
		 */
		lck_mtx_unlock_always(&c_seg->c_lock);

		kernel_memory_depopulate(
			compressor_map,
			(vm_offset_t) &c_seg->c_store.c_buffer[offset_to_depopulate],
			unused_bytes,
			KMA_COMPRESSOR);

		lck_mtx_lock_spin_always(&c_seg->c_lock);

		c_seg->c_populated_offset = offset_to_depopulate;
	}
	assert(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset) <= C_SEG_BUFSIZE);

#if DEVELOPMENT || DEBUG
	{
		boolean_t       c_seg_was_busy = FALSE;

		if (!c_seg->c_busy) {
			C_SEG_BUSY(c_seg);
		} else {
			c_seg_was_busy = TRUE;
		}

		lck_mtx_unlock_always(&c_seg->c_lock);

		C_SEG_WRITE_PROTECT(c_seg);

		lck_mtx_lock_spin_always(&c_seg->c_lock);

		if (c_seg_was_busy == FALSE) {
			C_SEG_WAKEUP_DONE(c_seg);
		}
	}
#endif

#if CONFIG_FREEZE
	if (current_chead == (c_segment_t*)&freezer_chead &&
	    VM_CONFIG_SWAP_IS_PRESENT &&
	    VM_CONFIG_FREEZER_SWAP_IS_ACTIVE
#if DEVELOPMENT || DEBUG
	    && !memorystatus_freeze_to_memory
#endif /* DEVELOPMENT || DEBUG */
	    ) {
		new_state = C_ON_SWAPOUT_Q;
	}
#endif /* CONFIG_FREEZE */

	if (vm_darkwake_mode == TRUE) {
		new_state = C_ON_SWAPOUT_Q;
		head_insert = TRUE;
	}

	clock_get_system_nanotime(&sec, &nsec);
	c_seg->c_creation_ts = (uint32_t)sec;

	lck_mtx_lock_spin_always(c_list_lock);

	c_seg->c_generation_id = c_generation_id++;
	c_seg_switch_state(c_seg, new_state, head_insert);

#if CONFIG_FREEZE
	if (c_seg->c_state == C_ON_SWAPOUT_Q) {
		/*
		 * darkwake and freezer can't co-exist together
		 * We'll need to fix this accounting as a start.
		 */
		assert(vm_darkwake_mode == FALSE);
		c_freezer_swapout_page_count += (C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset)) / PAGE_SIZE_64;
	}
#endif /* CONFIG_FREEZE */

	if (c_seg->c_state == C_ON_AGE_Q && C_SEG_UNUSED_BYTES(c_seg) >= PAGE_SIZE) {
		c_seg_need_delayed_compaction(c_seg, TRUE);
	}

	lck_mtx_unlock_always(c_list_lock);

	if (c_seg->c_state == C_ON_SWAPOUT_Q) {
		thread_wakeup((event_t)&c_swapout_list_head);
	}

	*current_chead = NULL;
}


/*
 * returns with c_seg locked
 */
void
c_seg_swapin_requeue(c_segment_t c_seg, boolean_t has_data, boolean_t minor_compact_ok, boolean_t age_on_swapin_q)
{
	clock_sec_t     sec;
	clock_nsec_t    nsec;

	clock_get_system_nanotime(&sec, &nsec);

	lck_mtx_lock_spin_always(c_list_lock);
	lck_mtx_lock_spin_always(&c_seg->c_lock);

	assert(c_seg->c_busy_swapping);
	assert(c_seg->c_busy);

	c_seg->c_busy_swapping = 0;

	if (c_seg->c_overage_swap == TRUE) {
		c_overage_swapped_count--;
		c_seg->c_overage_swap = FALSE;
	}
	if (has_data == TRUE) {
		if (age_on_swapin_q == TRUE) {
			c_seg_switch_state(c_seg, C_ON_SWAPPEDIN_Q, FALSE);
		} else {
			c_seg_switch_state(c_seg, C_ON_AGE_Q, FALSE);
		}

		if (minor_compact_ok == TRUE && !c_seg->c_on_minorcompact_q && C_SEG_UNUSED_BYTES(c_seg) >= PAGE_SIZE) {
			c_seg_need_delayed_compaction(c_seg, TRUE);
		}
	} else {
		c_seg->c_store.c_buffer = (int32_t*) NULL;
		c_seg->c_populated_offset = C_SEG_BYTES_TO_OFFSET(0);

		c_seg_switch_state(c_seg, C_ON_BAD_Q, FALSE);
	}
	c_seg->c_swappedin_ts = (uint32_t)sec;

	lck_mtx_unlock_always(c_list_lock);
}



/*
 * c_seg has to be locked and is returned locked if the c_seg isn't freed
 * PAGE_REPLACMENT_DISALLOWED has to be TRUE on entry and is returned TRUE
 * c_seg_swapin returns 1 if the c_seg was freed, 0 otherwise
 */

int
c_seg_swapin(c_segment_t c_seg, boolean_t force_minor_compaction, boolean_t age_on_swapin_q)
{
	vm_offset_t     addr = 0;
	uint32_t        io_size = 0;
	uint64_t        f_offset;

	assert(C_SEG_IS_ONDISK(c_seg));

#if !CHECKSUM_THE_SWAP
	c_seg_trim_tail(c_seg);
#endif
	io_size = round_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset));
	f_offset = c_seg->c_store.c_swap_handle;

	C_SEG_BUSY(c_seg);
	c_seg->c_busy_swapping = 1;

	/*
	 * This thread is likely going to block for I/O.
	 * Make sure it is ready to run when the I/O completes because
	 * it needs to clear the busy bit on the c_seg so that other
	 * waiting threads can make progress too. To do that, boost
	 * the rwlock_count so that the priority is boosted.
	 */
	set_thread_rwlock_boost();
	lck_mtx_unlock_always(&c_seg->c_lock);

	PAGE_REPLACEMENT_DISALLOWED(FALSE);

	addr = (vm_offset_t)C_SEG_BUFFER_ADDRESS(c_seg->c_mysegno);
	c_seg->c_store.c_buffer = (int32_t*) addr;

	kernel_memory_populate(compressor_map, addr, io_size, KMA_COMPRESSOR, VM_KERN_MEMORY_COMPRESSOR);

	if (vm_swap_get(c_seg, f_offset, io_size) != KERN_SUCCESS) {
		PAGE_REPLACEMENT_DISALLOWED(TRUE);

		kernel_memory_depopulate(compressor_map, addr, io_size, KMA_COMPRESSOR);

		c_seg_swapin_requeue(c_seg, FALSE, TRUE, age_on_swapin_q);
	} else {
#if ENCRYPTED_SWAP
		vm_swap_decrypt(c_seg);
#endif /* ENCRYPTED_SWAP */

#if CHECKSUM_THE_SWAP
		if (c_seg->cseg_swap_size != io_size) {
			panic("swapin size doesn't match swapout size");
		}

		if (c_seg->cseg_hash != vmc_hash((char*) c_seg->c_store.c_buffer, (int)io_size)) {
			panic("c_seg_swapin - Swap hash mismatch\n");
		}
#endif /* CHECKSUM_THE_SWAP */

		PAGE_REPLACEMENT_DISALLOWED(TRUE);

		c_seg_swapin_requeue(c_seg, TRUE, force_minor_compaction == TRUE ? FALSE : TRUE, age_on_swapin_q);

		OSAddAtomic64(c_seg->c_bytes_used, &compressor_bytes_used);

		if (force_minor_compaction == TRUE) {
			if (c_seg_minor_compaction_and_unlock(c_seg, FALSE)) {
				/*
				 * c_seg was completely empty so it was freed,
				 * so be careful not to reference it again
				 *
				 * Drop the rwlock_count so that the thread priority
				 * is returned back to where it is supposed to be.
				 */
				clear_thread_rwlock_boost();
				return 1;
			}

			lck_mtx_lock_spin_always(&c_seg->c_lock);
		}
	}
	C_SEG_WAKEUP_DONE(c_seg);

	/*
	 * Drop the rwlock_count so that the thread priority
	 * is returned back to where it is supposed to be.
	 */
	clear_thread_rwlock_boost();

	return 0;
}


static void
c_segment_sv_hash_drop_ref(int hash_indx)
{
	struct c_sv_hash_entry o_sv_he, n_sv_he;

	while (1) {
		o_sv_he.he_record = c_segment_sv_hash_table[hash_indx].he_record;

		n_sv_he.he_ref = o_sv_he.he_ref - 1;
		n_sv_he.he_data = o_sv_he.he_data;

		if (OSCompareAndSwap64((UInt64)o_sv_he.he_record, (UInt64)n_sv_he.he_record, (UInt64 *) &c_segment_sv_hash_table[hash_indx].he_record) == TRUE) {
			if (n_sv_he.he_ref == 0) {
				OSAddAtomic(-1, &c_segment_svp_in_hash);
			}
			break;
		}
	}
}


static int
c_segment_sv_hash_insert(uint32_t data)
{
	int             hash_sindx;
	int             misses;
	struct c_sv_hash_entry o_sv_he, n_sv_he;
	boolean_t       got_ref = FALSE;

	if (data == 0) {
		OSAddAtomic(1, &c_segment_svp_zero_compressions);
	} else {
		OSAddAtomic(1, &c_segment_svp_nonzero_compressions);
	}

	hash_sindx = data & C_SV_HASH_MASK;

	for (misses = 0; misses < C_SV_HASH_MAX_MISS; misses++) {
		o_sv_he.he_record = c_segment_sv_hash_table[hash_sindx].he_record;

		while (o_sv_he.he_data == data || o_sv_he.he_ref == 0) {
			n_sv_he.he_ref = o_sv_he.he_ref + 1;
			n_sv_he.he_data = data;

			if (OSCompareAndSwap64((UInt64)o_sv_he.he_record, (UInt64)n_sv_he.he_record, (UInt64 *) &c_segment_sv_hash_table[hash_sindx].he_record) == TRUE) {
				if (n_sv_he.he_ref == 1) {
					OSAddAtomic(1, &c_segment_svp_in_hash);
				}
				got_ref = TRUE;
				break;
			}
			o_sv_he.he_record = c_segment_sv_hash_table[hash_sindx].he_record;
		}
		if (got_ref == TRUE) {
			break;
		}
		hash_sindx++;

		if (hash_sindx == C_SV_HASH_SIZE) {
			hash_sindx = 0;
		}
	}
	if (got_ref == FALSE) {
		return -1;
	}

	return hash_sindx;
}


#if RECORD_THE_COMPRESSED_DATA

static void
c_compressed_record_data(char *src, int c_size)
{
	if ((c_compressed_record_cptr + c_size + 4) >= c_compressed_record_ebuf) {
		panic("c_compressed_record_cptr >= c_compressed_record_ebuf");
	}

	*(int *)((void *)c_compressed_record_cptr) = c_size;

	c_compressed_record_cptr += 4;

	memcpy(c_compressed_record_cptr, src, c_size);
	c_compressed_record_cptr += c_size;
}
#endif


static int
c_compress_page(char *src, c_slot_mapping_t slot_ptr, c_segment_t *current_chead, char *scratch_buf)
{
	int             c_size;
	int             c_rounded_size = 0;
	int             max_csize;
	c_slot_t        cs;
	c_segment_t     c_seg;

	KERNEL_DEBUG(0xe0400000 | DBG_FUNC_START, *current_chead, 0, 0, 0, 0);
retry:
	if ((c_seg = c_seg_allocate(current_chead)) == NULL) {
		return 1;
	}
	/*
	 * returns with c_seg lock held
	 * and PAGE_REPLACEMENT_DISALLOWED(TRUE)...
	 * c_nextslot has been allocated and
	 * c_store.c_buffer populated
	 */
	assert(c_seg->c_state == C_IS_FILLING);

	cs = C_SEG_SLOT_FROM_INDEX(c_seg, c_seg->c_nextslot);

	cs->c_packed_ptr = C_SLOT_PACK_PTR(slot_ptr);
	assert(slot_ptr == (c_slot_mapping_t)C_SLOT_UNPACK_PTR(cs));

	cs->c_offset = c_seg->c_nextoffset;

	max_csize = C_SEG_BUFSIZE - C_SEG_OFFSET_TO_BYTES((int32_t)cs->c_offset);

	if (max_csize > PAGE_SIZE) {
		max_csize = PAGE_SIZE;
	}

#if CHECKSUM_THE_DATA
	cs->c_hash_data = vmc_hash(src, PAGE_SIZE);
#endif
	boolean_t incomp_copy = FALSE;
	int max_csize_adj = (max_csize - 4);

	if (vm_compressor_algorithm() != VM_COMPRESSOR_DEFAULT_CODEC) {
#if defined(__arm__) || defined(__arm64__)
		uint16_t ccodec = CINVALID;

		if (max_csize >= C_SEG_OFFSET_ALIGNMENT_BOUNDARY) {
			c_size = metacompressor((const uint8_t *) src,
			    (uint8_t *) &c_seg->c_store.c_buffer[cs->c_offset],
			    max_csize_adj, &ccodec,
			    scratch_buf, &incomp_copy);
#if C_SEG_OFFSET_ALIGNMENT_BOUNDARY > 4
			if (c_size > max_csize_adj) {
				c_size = -1;
			}
#endif
		} else {
			c_size = -1;
		}
		assert(ccodec == CCWK || ccodec == CCLZ4);
		cs->c_codec = ccodec;
#endif
	} else {
#if defined(__arm__) || defined(__arm64__)
		cs->c_codec = CCWK;
#endif
#if defined(__arm64__)
		__unreachable_ok_push
		if (PAGE_SIZE == 4096) {
			c_size = WKdm_compress_4k((WK_word *)(uintptr_t)src, (WK_word *)(uintptr_t)&c_seg->c_store.c_buffer[cs->c_offset],
			    (WK_word *)(uintptr_t)scratch_buf, max_csize_adj);
		} else {
			c_size = WKdm_compress_16k((WK_word *)(uintptr_t)src, (WK_word *)(uintptr_t)&c_seg->c_store.c_buffer[cs->c_offset],
			    (WK_word *)(uintptr_t)scratch_buf, max_csize_adj);
		}
		__unreachable_ok_pop
#else
		c_size = WKdm_compress_new((const WK_word *)(uintptr_t)src, (WK_word *)(uintptr_t)&c_seg->c_store.c_buffer[cs->c_offset],
		    (WK_word *)(uintptr_t)scratch_buf, max_csize_adj);
#endif
	}
	assertf(((c_size <= max_csize_adj) && (c_size >= -1)),
	    "c_size invalid (%d, %d), cur compressions: %d", c_size, max_csize_adj, c_segment_pages_compressed);

	if (c_size == -1) {
		if (max_csize < PAGE_SIZE) {
			c_current_seg_filled(c_seg, current_chead);
			assert(*current_chead == NULL);

			lck_mtx_unlock_always(&c_seg->c_lock);
			/* TODO: it may be worth requiring codecs to distinguish
			 * between incompressible inputs and failures due to
			 * budget exhaustion.
			 */
			PAGE_REPLACEMENT_DISALLOWED(FALSE);
			goto retry;
		}
		c_size = PAGE_SIZE;

		if (incomp_copy == FALSE) {
			memcpy(&c_seg->c_store.c_buffer[cs->c_offset], src, c_size);
		}

		OSAddAtomic(1, &c_segment_noncompressible_pages);
	} else if (c_size == 0) {
		int             hash_index;

		/*
		 * special case - this is a page completely full of a single 32 bit value
		 */
		hash_index = c_segment_sv_hash_insert(*(uint32_t *)(uintptr_t)src);

		if (hash_index != -1) {
			slot_ptr->s_cindx = hash_index;
			slot_ptr->s_cseg = C_SV_CSEG_ID;

			OSAddAtomic(1, &c_segment_svp_hash_succeeded);
#if RECORD_THE_COMPRESSED_DATA
			c_compressed_record_data(src, 4);
#endif
			goto sv_compression;
		}
		c_size = 4;

		memcpy(&c_seg->c_store.c_buffer[cs->c_offset], src, c_size);

		OSAddAtomic(1, &c_segment_svp_hash_failed);
	}

#if RECORD_THE_COMPRESSED_DATA
	c_compressed_record_data((char *)&c_seg->c_store.c_buffer[cs->c_offset], c_size);
#endif
#if CHECKSUM_THE_COMPRESSED_DATA
	cs->c_hash_compressed_data = vmc_hash((char *)&c_seg->c_store.c_buffer[cs->c_offset], c_size);
#endif
#if POPCOUNT_THE_COMPRESSED_DATA
	cs->c_pop_cdata = vmc_pop((uintptr_t) &c_seg->c_store.c_buffer[cs->c_offset], c_size);
#endif
	c_rounded_size = (c_size + C_SEG_OFFSET_ALIGNMENT_MASK) & ~C_SEG_OFFSET_ALIGNMENT_MASK;

	PACK_C_SIZE(cs, c_size);
	c_seg->c_bytes_used += c_rounded_size;
	c_seg->c_nextoffset += C_SEG_BYTES_TO_OFFSET(c_rounded_size);
	c_seg->c_slots_used++;

	slot_ptr->s_cindx = c_seg->c_nextslot++;
	/* <csegno=0,indx=0> would mean "empty slot", so use csegno+1 */
	slot_ptr->s_cseg = c_seg->c_mysegno + 1;

sv_compression:
	if (c_seg->c_nextoffset >= C_SEG_OFF_LIMIT || c_seg->c_nextslot >= C_SLOT_MAX_INDEX) {
		c_current_seg_filled(c_seg, current_chead);
		assert(*current_chead == NULL);
	}
	lck_mtx_unlock_always(&c_seg->c_lock);

	PAGE_REPLACEMENT_DISALLOWED(FALSE);

#if RECORD_THE_COMPRESSED_DATA
	if ((c_compressed_record_cptr - c_compressed_record_sbuf) >= C_SEG_ALLOCSIZE) {
		c_compressed_record_write(c_compressed_record_sbuf, (int)(c_compressed_record_cptr - c_compressed_record_sbuf));
		c_compressed_record_cptr = c_compressed_record_sbuf;
	}
#endif
	if (c_size) {
		OSAddAtomic64(c_size, &c_segment_compressed_bytes);
		OSAddAtomic64(c_rounded_size, &compressor_bytes_used);
	}
	OSAddAtomic64(PAGE_SIZE, &c_segment_input_bytes);

	OSAddAtomic(1, &c_segment_pages_compressed);
	OSAddAtomic(1, &sample_period_compression_count);

	KERNEL_DEBUG(0xe0400000 | DBG_FUNC_END, *current_chead, c_size, c_segment_input_bytes, c_segment_compressed_bytes, 0);

	return 0;
}

static inline void
sv_decompress(int32_t *ddst, int32_t pattern)
{
//	assert(__builtin_constant_p(PAGE_SIZE) != 0);
#if defined(__x86_64__)
	memset_word(ddst, pattern, PAGE_SIZE / sizeof(int32_t));
#elif defined(__arm64__)
	assert((PAGE_SIZE % 128) == 0);
	if (pattern == 0) {
		fill32_dczva((addr64_t)ddst, PAGE_SIZE);
	} else {
		fill32_nt((addr64_t)ddst, PAGE_SIZE, pattern);
	}
#else
	size_t          i;

	/* Unroll the pattern fill loop 4x to encourage the
	 * compiler to emit NEON stores, cf.
	 * <rdar://problem/25839866> Loop autovectorization
	 * anomalies.
	 */
	/* * We use separate loops for each PAGE_SIZE
	 * to allow the autovectorizer to engage, as PAGE_SIZE
	 * may not be a constant.
	 */

	__unreachable_ok_push
	if (PAGE_SIZE == 4096) {
		for (i = 0; i < (4096U / sizeof(int32_t)); i += 4) {
			*ddst++ = pattern;
			*ddst++ = pattern;
			*ddst++ = pattern;
			*ddst++ = pattern;
		}
	} else {
		assert(PAGE_SIZE == 16384);
		for (i = 0; i < (int)(16384U / sizeof(int32_t)); i += 4) {
			*ddst++ = pattern;
			*ddst++ = pattern;
			*ddst++ = pattern;
			*ddst++ = pattern;
		}
	}
	__unreachable_ok_pop
#endif
}

static int
c_decompress_page(char *dst, volatile c_slot_mapping_t slot_ptr, int flags, int *zeroslot)
{
	c_slot_t        cs;
	c_segment_t     c_seg;
	uint32_t        c_segno;
	int             c_indx;
	int             c_rounded_size;
	uint32_t        c_size;
	int             retval = 0;
	boolean_t       need_unlock = TRUE;
	boolean_t       consider_defragmenting = FALSE;
	boolean_t       kdp_mode = FALSE;

	if (__improbable(flags & C_KDP)) {
		if (not_in_kdp) {
			panic("C_KDP passed to decompress page from outside of debugger context");
		}

		assert((flags & C_KEEP) == C_KEEP);
		assert((flags & C_DONT_BLOCK) == C_DONT_BLOCK);

		if ((flags & (C_DONT_BLOCK | C_KEEP)) != (C_DONT_BLOCK | C_KEEP)) {
			return -2;
		}

		kdp_mode = TRUE;
		*zeroslot = 0;
	}

ReTry:
	if (__probable(!kdp_mode)) {
		PAGE_REPLACEMENT_DISALLOWED(TRUE);
	} else {
		if (kdp_lck_rw_lock_is_acquired_exclusive(&c_master_lock)) {
			return -2;
		}
	}

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
	if (__improbable(dst && decompressions_blocked == TRUE)) {
		if (flags & C_DONT_BLOCK) {
			if (__probable(!kdp_mode)) {
				PAGE_REPLACEMENT_DISALLOWED(FALSE);
			}

			*zeroslot = 0;
			return -2;
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
	c_segno = slot_ptr->s_cseg - 1;

	if (__improbable(c_segno >= c_segments_available)) {
		panic("c_decompress_page: c_segno %d >= c_segments_available %d, slot_ptr(%p), slot_data(%x)",
		    c_segno, c_segments_available, slot_ptr, *(int *)((void *)slot_ptr));
	}

	if (__improbable(c_segments[c_segno].c_segno < c_segments_available)) {
		panic("c_decompress_page: c_segno %d is free, slot_ptr(%p), slot_data(%x)",
		    c_segno, slot_ptr, *(int *)((void *)slot_ptr));
	}

	c_seg = c_segments[c_segno].c_seg;

	if (__probable(!kdp_mode)) {
		lck_mtx_lock_spin_always(&c_seg->c_lock);
	} else {
		if (kdp_lck_mtx_lock_spin_is_acquired(&c_seg->c_lock)) {
			return -2;
		}
	}

	assert(c_seg->c_state != C_IS_EMPTY && c_seg->c_state != C_IS_FREE);

	if (dst == NULL && c_seg->c_busy_swapping) {
		assert(c_seg->c_busy);

		goto bypass_busy_check;
	}
	if (flags & C_DONT_BLOCK) {
		if (c_seg->c_busy || (C_SEG_IS_ONDISK(c_seg) && dst)) {
			*zeroslot = 0;

			retval = -2;
			goto done;
		}
	}
	if (c_seg->c_busy) {
		PAGE_REPLACEMENT_DISALLOWED(FALSE);

		c_seg_wait_on_busy(c_seg);

		goto ReTry;
	}
bypass_busy_check:

	c_indx = slot_ptr->s_cindx;

	if (__improbable(c_indx >= c_seg->c_nextslot)) {
		panic("c_decompress_page: c_indx %d >= c_nextslot %d, c_seg(%p), slot_ptr(%p), slot_data(%x)",
		    c_indx, c_seg->c_nextslot, c_seg, slot_ptr, *(int *)((void *)slot_ptr));
	}

	cs = C_SEG_SLOT_FROM_INDEX(c_seg, c_indx);

	c_size = UNPACK_C_SIZE(cs);

	if (__improbable(c_size == 0)) {
		panic("c_decompress_page: c_size == 0, c_seg(%p), slot_ptr(%p), slot_data(%x)",
		    c_seg, slot_ptr, *(int *)((void *)slot_ptr));
	}

	c_rounded_size = (c_size + C_SEG_OFFSET_ALIGNMENT_MASK) & ~C_SEG_OFFSET_ALIGNMENT_MASK;

	if (dst) {
		uint32_t        age_of_cseg;
		clock_sec_t     cur_ts_sec;
		clock_nsec_t    cur_ts_nsec;

		if (C_SEG_IS_ONDISK(c_seg)) {
			assert(kdp_mode == FALSE);
			retval = c_seg_swapin(c_seg, FALSE, TRUE);
			assert(retval == 0);

			retval = 1;
		}
		if (c_seg->c_state == C_ON_BAD_Q) {
			assert(c_seg->c_store.c_buffer == NULL);
			*zeroslot = 0;

			retval = -1;
			goto done;
		}

#if POPCOUNT_THE_COMPRESSED_DATA
		unsigned csvpop;
		uintptr_t csvaddr = (uintptr_t) &c_seg->c_store.c_buffer[cs->c_offset];
		if (cs->c_pop_cdata != (csvpop = vmc_pop(csvaddr, c_size))) {
			panic("Compressed data popcount doesn't match original, bit distance: %d %p (phys: %p) %p %p 0x%x 0x%x 0x%x 0x%x", (csvpop - cs->c_pop_cdata), (void *)csvaddr, (void *) kvtophys(csvaddr), c_seg, cs, cs->c_offset, c_size, csvpop, cs->c_pop_cdata);
		}
#endif

#if CHECKSUM_THE_COMPRESSED_DATA
		unsigned csvhash;
		if (cs->c_hash_compressed_data != (csvhash = vmc_hash((char *)&c_seg->c_store.c_buffer[cs->c_offset], c_size))) {
			panic("Compressed data doesn't match original %p %p %u %u %u", c_seg, cs, c_size, cs->c_hash_compressed_data, csvhash);
		}
#endif
		if (c_rounded_size == PAGE_SIZE) {
			/*
			 * page wasn't compressible... just copy it out
			 */
			memcpy(dst, &c_seg->c_store.c_buffer[cs->c_offset], PAGE_SIZE);
		} else if (c_size == 4) {
			int32_t         data;
			int32_t         *dptr;

			/*
			 * page was populated with a single value
			 * that didn't fit into our fast hash
			 * so we packed it in as a single non-compressed value
			 * that we need to populate the page with
			 */
			dptr = (int32_t *)(uintptr_t)dst;
			data = *(int32_t *)(&c_seg->c_store.c_buffer[cs->c_offset]);
			sv_decompress(dptr, data);
		} else {
			uint32_t        my_cpu_no;
			char            *scratch_buf;

			if (__probable(!kdp_mode)) {
				/*
				 * we're behind the c_seg lock held in spin mode
				 * which means pre-emption is disabled... therefore
				 * the following sequence is atomic and safe
				 */
				my_cpu_no = cpu_number();

				assert(my_cpu_no < compressor_cpus);

				scratch_buf = &compressor_scratch_bufs[my_cpu_no * vm_compressor_get_decode_scratch_size()];
			} else {
				scratch_buf = kdp_compressor_scratch_buf;
			}

			if (vm_compressor_algorithm() != VM_COMPRESSOR_DEFAULT_CODEC) {
#if defined(__arm__) || defined(__arm64__)
				uint16_t c_codec = cs->c_codec;
				metadecompressor((const uint8_t *) &c_seg->c_store.c_buffer[cs->c_offset],
				    (uint8_t *)dst, c_size, c_codec, (void *)scratch_buf);
#endif
			} else {
#if defined(__arm64__)
				__unreachable_ok_push
				if (PAGE_SIZE == 4096) {
					WKdm_decompress_4k((WK_word *)(uintptr_t)&c_seg->c_store.c_buffer[cs->c_offset],
					    (WK_word *)(uintptr_t)dst, (WK_word *)(uintptr_t)scratch_buf, c_size);
				} else {
					WKdm_decompress_16k((WK_word *)(uintptr_t)&c_seg->c_store.c_buffer[cs->c_offset],
					    (WK_word *)(uintptr_t)dst, (WK_word *)(uintptr_t)scratch_buf, c_size);
				}
				__unreachable_ok_pop
#else
				WKdm_decompress_new((WK_word *)(uintptr_t)&c_seg->c_store.c_buffer[cs->c_offset],
				    (WK_word *)(uintptr_t)dst, (WK_word *)(uintptr_t)scratch_buf, c_size);
#endif
			}
		}

#if CHECKSUM_THE_DATA
		if (cs->c_hash_data != vmc_hash(dst, PAGE_SIZE)) {
#if     defined(__arm__) || defined(__arm64__)
			int32_t *dinput = &c_seg->c_store.c_buffer[cs->c_offset];
			panic("decompressed data doesn't match original cs: %p, hash: 0x%x, offset: %d, c_size: %d, c_rounded_size: %d, codec: %d, header: 0x%x 0x%x 0x%x", cs, cs->c_hash_data, cs->c_offset, c_size, c_rounded_size, cs->c_codec, *dinput, *(dinput + 1), *(dinput + 2));
#else
			panic("decompressed data doesn't match original cs: %p, hash: %d, offset: 0x%x, c_size: %d", cs, cs->c_hash_data, cs->c_offset, c_size);
#endif
		}
#endif
		if (c_seg->c_swappedin_ts == 0 && !kdp_mode) {
			clock_get_system_nanotime(&cur_ts_sec, &cur_ts_nsec);

			age_of_cseg = (uint32_t)cur_ts_sec - c_seg->c_creation_ts;
			if (age_of_cseg < DECOMPRESSION_SAMPLE_MAX_AGE) {
				OSAddAtomic(1, &age_of_decompressions_during_sample_period[age_of_cseg]);
			} else {
				OSAddAtomic(1, &overage_decompressions_during_sample_period);
			}

			OSAddAtomic(1, &sample_period_decompression_count);
		}
	}
	if (flags & C_KEEP) {
		*zeroslot = 0;
		goto done;
	}
	assert(kdp_mode == FALSE);

	c_seg->c_bytes_unused += c_rounded_size;
	c_seg->c_bytes_used -= c_rounded_size;

	assert(c_seg->c_slots_used);
	c_seg->c_slots_used--;

	PACK_C_SIZE(cs, 0);

	if (c_indx < c_seg->c_firstemptyslot) {
		c_seg->c_firstemptyslot = c_indx;
	}

	OSAddAtomic(-1, &c_segment_pages_compressed);

	if (c_seg->c_state != C_ON_BAD_Q && !(C_SEG_IS_ONDISK(c_seg))) {
		/*
		 * C_SEG_IS_ONDISK == TRUE can occur when we're doing a
		 * free of a compressed page (i.e. dst == NULL)
		 */
		OSAddAtomic64(-c_rounded_size, &compressor_bytes_used);
	}
	if (c_seg->c_busy_swapping) {
		/*
		 * bypass case for c_busy_swapping...
		 * let the swapin/swapout paths deal with putting
		 * the c_seg on the minor compaction queue if needed
		 */
		assert(c_seg->c_busy);
		goto done;
	}
	assert(!c_seg->c_busy);

	if (c_seg->c_state != C_IS_FILLING) {
		if (c_seg->c_bytes_used == 0) {
			if (!(C_SEG_IS_ONDISK(c_seg))) {
				int     pages_populated;

				pages_populated = (round_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset))) / PAGE_SIZE;
				c_seg->c_populated_offset = C_SEG_BYTES_TO_OFFSET(0);

				if (pages_populated) {
					assert(c_seg->c_state != C_ON_BAD_Q);
					assert(c_seg->c_store.c_buffer != NULL);

					C_SEG_BUSY(c_seg);
					lck_mtx_unlock_always(&c_seg->c_lock);

					kernel_memory_depopulate(compressor_map, (vm_offset_t) c_seg->c_store.c_buffer, pages_populated * PAGE_SIZE, KMA_COMPRESSOR);

					lck_mtx_lock_spin_always(&c_seg->c_lock);
					C_SEG_WAKEUP_DONE(c_seg);
				}
				if (!c_seg->c_on_minorcompact_q && c_seg->c_state != C_ON_SWAPOUT_Q && c_seg->c_state != C_ON_SWAPIO_Q) {
					c_seg_need_delayed_compaction(c_seg, FALSE);
				}
			} else {
				if (c_seg->c_state != C_ON_SWAPPEDOUTSPARSE_Q) {
					c_seg_move_to_sparse_list(c_seg);
					consider_defragmenting = TRUE;
				}
			}
		} else if (c_seg->c_on_minorcompact_q) {
			assert(c_seg->c_state != C_ON_BAD_Q);
			assert(!C_SEG_IS_ON_DISK_OR_SOQ(c_seg));

			if (C_SEG_SHOULD_MINORCOMPACT_NOW(c_seg)) {
				c_seg_try_minor_compaction_and_unlock(c_seg);
				need_unlock = FALSE;
			}
		} else if (!(C_SEG_IS_ONDISK(c_seg))) {
			if (c_seg->c_state != C_ON_BAD_Q && c_seg->c_state != C_ON_SWAPOUT_Q && c_seg->c_state != C_ON_SWAPIO_Q &&
			    C_SEG_UNUSED_BYTES(c_seg) >= PAGE_SIZE) {
				c_seg_need_delayed_compaction(c_seg, FALSE);
			}
		} else if (c_seg->c_state != C_ON_SWAPPEDOUTSPARSE_Q && C_SEG_ONDISK_IS_SPARSE(c_seg)) {
			c_seg_move_to_sparse_list(c_seg);
			consider_defragmenting = TRUE;
		}
	}
done:
	if (__improbable(kdp_mode)) {
		return retval;
	}

	if (need_unlock == TRUE) {
		lck_mtx_unlock_always(&c_seg->c_lock);
	}

	PAGE_REPLACEMENT_DISALLOWED(FALSE);

	if (consider_defragmenting == TRUE) {
		vm_swap_consider_defragmenting(VM_SWAP_FLAGS_NONE);
	}

#if CONFIG_EMBEDDED
	if ((c_minor_count && COMPRESSOR_NEEDS_TO_MINOR_COMPACT()) || vm_compressor_needs_to_major_compact()) {
		vm_wake_compactor_swapper();
	}
#endif

	return retval;
}


int
vm_compressor_get(ppnum_t pn, int *slot, int flags)
{
	c_slot_mapping_t  slot_ptr;
	char    *dst;
	int     zeroslot = 1;
	int     retval;

	dst = pmap_map_compressor_page(pn);
	slot_ptr = (c_slot_mapping_t)slot;

	assert(dst != NULL);

	if (slot_ptr->s_cseg == C_SV_CSEG_ID) {
		int32_t         data;
		int32_t         *dptr;

		/*
		 * page was populated with a single value
		 * that found a home in our hash table
		 * grab that value from the hash and populate the page
		 * that we need to populate the page with
		 */
		dptr = (int32_t *)(uintptr_t)dst;
		data = c_segment_sv_hash_table[slot_ptr->s_cindx].he_data;
		sv_decompress(dptr, data);
		if (!(flags & C_KEEP)) {
			c_segment_sv_hash_drop_ref(slot_ptr->s_cindx);

			OSAddAtomic(-1, &c_segment_pages_compressed);
			*slot = 0;
		}
		if (data) {
			OSAddAtomic(1, &c_segment_svp_nonzero_decompressions);
		} else {
			OSAddAtomic(1, &c_segment_svp_zero_decompressions);
		}

		pmap_unmap_compressor_page(pn, dst);
		return 0;
	}

	retval = c_decompress_page(dst, slot_ptr, flags, &zeroslot);

	/*
	 * zeroslot will be set to 0 by c_decompress_page if (flags & C_KEEP)
	 * or (flags & C_DONT_BLOCK) and we found 'c_busy' or 'C_SEG_IS_ONDISK' to be TRUE
	 */
	if (zeroslot) {
		*slot = 0;
	}

	pmap_unmap_compressor_page(pn, dst);

	/*
	 * returns 0 if we successfully decompressed a page from a segment already in memory
	 * returns 1 if we had to first swap in the segment, before successfully decompressing the page
	 * returns -1 if we encountered an error swapping in the segment - decompression failed
	 * returns -2 if (flags & C_DONT_BLOCK) and we found 'c_busy' or 'C_SEG_IS_ONDISK' to be true
	 */
	return retval;
}


int
vm_compressor_free(int *slot, int flags)
{
	c_slot_mapping_t  slot_ptr;
	int     zeroslot = 1;
	int     retval;

	assert(flags == 0 || flags == C_DONT_BLOCK);

	slot_ptr = (c_slot_mapping_t)slot;

	if (slot_ptr->s_cseg == C_SV_CSEG_ID) {
		c_segment_sv_hash_drop_ref(slot_ptr->s_cindx);
		OSAddAtomic(-1, &c_segment_pages_compressed);

		*slot = 0;
		return 0;
	}
	retval = c_decompress_page(NULL, slot_ptr, flags, &zeroslot);
	/*
	 * returns 0 if we successfully freed the specified compressed page
	 * returns -2 if (flags & C_DONT_BLOCK) and we found 'c_busy' set
	 */

	if (retval == 0) {
		*slot = 0;
	} else {
		assert(retval == -2);
	}

	return retval;
}


int
vm_compressor_put(ppnum_t pn, int *slot, void  **current_chead, char *scratch_buf)
{
	char    *src;
	int     retval;

	src = pmap_map_compressor_page(pn);
	assert(src != NULL);

	retval = c_compress_page(src, (c_slot_mapping_t)slot, (c_segment_t *)current_chead, scratch_buf);
	pmap_unmap_compressor_page(pn, src);

	return retval;
}

void
vm_compressor_transfer(
	int     *dst_slot_p,
	int     *src_slot_p)
{
	c_slot_mapping_t        dst_slot, src_slot;
	c_segment_t             c_seg;
	int                     c_indx;
	c_slot_t                cs;

	src_slot = (c_slot_mapping_t) src_slot_p;

	if (src_slot->s_cseg == C_SV_CSEG_ID) {
		*dst_slot_p = *src_slot_p;
		*src_slot_p = 0;
		return;
	}
	dst_slot = (c_slot_mapping_t) dst_slot_p;
Retry:
	PAGE_REPLACEMENT_DISALLOWED(TRUE);
	/* get segment for src_slot */
	c_seg = c_segments[src_slot->s_cseg - 1].c_seg;
	/* lock segment */
	lck_mtx_lock_spin_always(&c_seg->c_lock);
	/* wait if it's busy */
	if (c_seg->c_busy && !c_seg->c_busy_swapping) {
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

#if CONFIG_FREEZE

int     freezer_finished_filling = 0;

void
vm_compressor_finished_filling(
	void    **current_chead)
{
	c_segment_t     c_seg;

	if ((c_seg = *(c_segment_t *)current_chead) == NULL) {
		return;
	}

	assert(c_seg->c_state == C_IS_FILLING);

	lck_mtx_lock_spin_always(&c_seg->c_lock);

	c_current_seg_filled(c_seg, (c_segment_t *)current_chead);

	lck_mtx_unlock_always(&c_seg->c_lock);

	freezer_finished_filling++;
}


/*
 * This routine is used to transfer the compressed chunks from
 * the c_seg/cindx pointed to by slot_p into a new c_seg headed
 * by the current_chead and a new cindx within that c_seg.
 *
 * Currently, this routine is only used by the "freezer backed by
 * compressor with swap" mode to create a series of c_segs that
 * only contain compressed data belonging to one task. So, we
 * move a task's previously compressed data into a set of new
 * c_segs which will also hold the task's yet to be compressed data.
 */

kern_return_t
vm_compressor_relocate(
	void            **current_chead,
	int             *slot_p)
{
	c_slot_mapping_t        slot_ptr;
	c_slot_mapping_t        src_slot;
	uint32_t                c_rounded_size;
	uint32_t                c_size;
	uint16_t                dst_slot;
	c_slot_t                c_dst;
	c_slot_t                c_src;
	int                     c_indx;
	c_segment_t             c_seg_dst = NULL;
	c_segment_t             c_seg_src = NULL;
	kern_return_t           kr = KERN_SUCCESS;


	src_slot = (c_slot_mapping_t) slot_p;

	if (src_slot->s_cseg == C_SV_CSEG_ID) {
		/*
		 * no need to relocate... this is a page full of a single
		 * value which is hashed to a single entry not contained
		 * in a c_segment_t
		 */
		return kr;
	}

Relookup_dst:
	c_seg_dst = c_seg_allocate((c_segment_t *)current_chead);
	/*
	 * returns with c_seg lock held
	 * and PAGE_REPLACEMENT_DISALLOWED(TRUE)...
	 * c_nextslot has been allocated and
	 * c_store.c_buffer populated
	 */
	if (c_seg_dst == NULL) {
		/*
		 * Out of compression segments?
		 */
		kr = KERN_RESOURCE_SHORTAGE;
		goto out;
	}

	assert(c_seg_dst->c_busy == 0);

	C_SEG_BUSY(c_seg_dst);

	dst_slot = c_seg_dst->c_nextslot;

	lck_mtx_unlock_always(&c_seg_dst->c_lock);

Relookup_src:
	c_seg_src = c_segments[src_slot->s_cseg - 1].c_seg;

	assert(c_seg_dst != c_seg_src);

	lck_mtx_lock_spin_always(&c_seg_src->c_lock);

	if (C_SEG_IS_ONDISK(c_seg_src)) {
		/*
		 * A "thaw" can mark a process as eligible for
		 * another freeze cycle without bringing any of
		 * its swapped out c_segs back from disk (because
		 * that is done on-demand).
		 *
		 * If the src c_seg we find for our pre-compressed
		 * data is already on-disk, then we are dealing
		 * with an app's data that is already packed and
		 * swapped out. Don't do anything.
		 */

		PAGE_REPLACEMENT_DISALLOWED(FALSE);

		lck_mtx_unlock_always(&c_seg_src->c_lock);

		c_seg_src = NULL;

		goto out;
	}

	if (c_seg_src->c_busy) {
		PAGE_REPLACEMENT_DISALLOWED(FALSE);
		c_seg_wait_on_busy(c_seg_src);

		c_seg_src = NULL;

		PAGE_REPLACEMENT_DISALLOWED(TRUE);

		goto Relookup_src;
	}

	C_SEG_BUSY(c_seg_src);

	lck_mtx_unlock_always(&c_seg_src->c_lock);

	PAGE_REPLACEMENT_DISALLOWED(FALSE);

	/* find the c_slot */
	c_indx = src_slot->s_cindx;

	c_src = C_SEG_SLOT_FROM_INDEX(c_seg_src, c_indx);

	c_size = UNPACK_C_SIZE(c_src);

	assert(c_size);

	if (c_size > (uint32_t)(C_SEG_BUFSIZE - C_SEG_OFFSET_TO_BYTES((int32_t)c_seg_dst->c_nextoffset))) {
		/*
		 * This segment is full. We need a new one.
		 */

		PAGE_REPLACEMENT_DISALLOWED(TRUE);

		lck_mtx_lock_spin_always(&c_seg_src->c_lock);
		C_SEG_WAKEUP_DONE(c_seg_src);
		lck_mtx_unlock_always(&c_seg_src->c_lock);

		c_seg_src = NULL;

		lck_mtx_lock_spin_always(&c_seg_dst->c_lock);

		assert(c_seg_dst->c_busy);
		assert(c_seg_dst->c_state == C_IS_FILLING);
		assert(!c_seg_dst->c_on_minorcompact_q);

		c_current_seg_filled(c_seg_dst, (c_segment_t *)current_chead);
		assert(*current_chead == NULL);

		C_SEG_WAKEUP_DONE(c_seg_dst);

		lck_mtx_unlock_always(&c_seg_dst->c_lock);

		c_seg_dst = NULL;

		PAGE_REPLACEMENT_DISALLOWED(FALSE);

		goto Relookup_dst;
	}

	c_dst = C_SEG_SLOT_FROM_INDEX(c_seg_dst, c_seg_dst->c_nextslot);

	memcpy(&c_seg_dst->c_store.c_buffer[c_seg_dst->c_nextoffset], &c_seg_src->c_store.c_buffer[c_src->c_offset], c_size);
//is platform alignment actually necessary since wkdm aligns its output?
	c_rounded_size = (c_size + C_SEG_OFFSET_ALIGNMENT_MASK) & ~C_SEG_OFFSET_ALIGNMENT_MASK;

	cslot_copy(c_dst, c_src);
	c_dst->c_offset = c_seg_dst->c_nextoffset;

	if (c_seg_dst->c_firstemptyslot == c_seg_dst->c_nextslot) {
		c_seg_dst->c_firstemptyslot++;
	}

	c_seg_dst->c_slots_used++;
	c_seg_dst->c_nextslot++;
	c_seg_dst->c_bytes_used += c_rounded_size;
	c_seg_dst->c_nextoffset += C_SEG_BYTES_TO_OFFSET(c_rounded_size);


	PACK_C_SIZE(c_src, 0);

	c_seg_src->c_bytes_used -= c_rounded_size;
	c_seg_src->c_bytes_unused += c_rounded_size;

	assert(c_seg_src->c_slots_used);
	c_seg_src->c_slots_used--;

	if (c_indx < c_seg_src->c_firstemptyslot) {
		c_seg_src->c_firstemptyslot = c_indx;
	}

	c_dst = C_SEG_SLOT_FROM_INDEX(c_seg_dst, dst_slot);

	PAGE_REPLACEMENT_ALLOWED(TRUE);
	slot_ptr = (c_slot_mapping_t)C_SLOT_UNPACK_PTR(c_dst);
	/* <csegno=0,indx=0> would mean "empty slot", so use csegno+1 */
	slot_ptr->s_cseg = c_seg_dst->c_mysegno + 1;
	slot_ptr->s_cindx = dst_slot;

	PAGE_REPLACEMENT_ALLOWED(FALSE);

out:
	if (c_seg_src) {
		lck_mtx_lock_spin_always(&c_seg_src->c_lock);

		C_SEG_WAKEUP_DONE(c_seg_src);

		if (c_seg_src->c_bytes_used == 0 && c_seg_src->c_state != C_IS_FILLING) {
			if (!c_seg_src->c_on_minorcompact_q) {
				c_seg_need_delayed_compaction(c_seg_src, FALSE);
			}
		}

		lck_mtx_unlock_always(&c_seg_src->c_lock);
	}

	if (c_seg_dst) {
		PAGE_REPLACEMENT_DISALLOWED(TRUE);

		lck_mtx_lock_spin_always(&c_seg_dst->c_lock);

		if (c_seg_dst->c_nextoffset >= C_SEG_OFF_LIMIT || c_seg_dst->c_nextslot >= C_SLOT_MAX_INDEX) {
			/*
			 * Nearing or exceeded maximum slot and offset capacity.
			 */
			assert(c_seg_dst->c_busy);
			assert(c_seg_dst->c_state == C_IS_FILLING);
			assert(!c_seg_dst->c_on_minorcompact_q);

			c_current_seg_filled(c_seg_dst, (c_segment_t *)current_chead);
			assert(*current_chead == NULL);
		}

		C_SEG_WAKEUP_DONE(c_seg_dst);

		lck_mtx_unlock_always(&c_seg_dst->c_lock);

		c_seg_dst = NULL;

		PAGE_REPLACEMENT_DISALLOWED(FALSE);
	}

	return kr;
}
#endif /* CONFIG_FREEZE */
