/*
 * Copyright (c) 2000-2018 Apple Inc. All rights reserved.
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
 *	File:	vm_fault.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *
 *	Page fault handling module.
 */

#include <mach_cluster_stats.h>
#include <mach_pagemap.h>
#include <libkern/OSAtomic.h>

#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <mach/message.h>       /* for error codes */
#include <mach/vm_param.h>
#include <mach/vm_behavior.h>
#include <mach/memory_object.h>
/* For memory_object_data_{request,unlock} */
#include <mach/sdt.h>

#include <kern/kern_types.h>
#include <kern/host_statistics.h>
#include <kern/counters.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/host.h>
#include <kern/mach_param.h>
#include <kern/macro_help.h>
#include <kern/zalloc.h>
#include <kern/misc_protos.h>
#include <kern/policy_internal.h>

#include <vm/vm_compressor.h>
#include <vm/vm_compressor_pager.h>
#include <vm/vm_fault.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>
#include <vm/vm_external.h>
#include <vm/memory_object.h>
#include <vm/vm_purgeable_internal.h>   /* Needed by some vm_page.h macros */
#include <vm/vm_shared_region.h>

#include <sys/codesign.h>
#include <sys/reason.h>
#include <sys/signalvar.h>

#include <san/kasan.h>

#define VM_FAULT_CLASSIFY       0

#define TRACEFAULTPAGE 0 /* (TEST/DEBUG) */

int vm_protect_privileged_from_untrusted = 1;

unsigned int    vm_object_pagein_throttle = 16;

/*
 * We apply a hard throttle to the demand zero rate of tasks that we believe are running out of control which
 * kicks in when swap space runs out.  64-bit programs have massive address spaces and can leak enormous amounts
 * of memory if they're buggy and can run the system completely out of swap space.  If this happens, we
 * impose a hard throttle on them to prevent them from taking the last bit of memory left.  This helps
 * keep the UI active so that the user has a chance to kill the offending task before the system
 * completely hangs.
 *
 * The hard throttle is only applied when the system is nearly completely out of swap space and is only applied
 * to tasks that appear to be bloated.  When swap runs out, any task using more than vm_hard_throttle_threshold
 * will be throttled.  The throttling is done by giving the thread that's trying to demand zero a page a
 * delay of HARD_THROTTLE_DELAY microseconds before being allowed to try the page fault again.
 */

extern void throttle_lowpri_io(int);

extern struct vnode *vnode_pager_lookup_vnode(memory_object_t);

uint64_t vm_hard_throttle_threshold;


OS_ALWAYS_INLINE
boolean_t
NEED_TO_HARD_THROTTLE_THIS_TASK(void)
{
	return vm_wants_task_throttled(current_task()) ||
	       ((vm_page_free_count < vm_page_throttle_limit ||
	       HARD_THROTTLE_LIMIT_REACHED()) &&
	       proc_get_effective_thread_policy(current_thread(), TASK_POLICY_IO) >= THROTTLE_LEVEL_THROTTLED);
}

#define HARD_THROTTLE_DELAY     10000   /* 10000 us == 10 ms */
#define SOFT_THROTTLE_DELAY     200     /* 200 us == .2 ms */

#define VM_PAGE_CREATION_THROTTLE_PERIOD_SECS   6
#define VM_PAGE_CREATION_THROTTLE_RATE_PER_SEC  20000


#define VM_STAT_DECOMPRESSIONS()        \
MACRO_BEGIN                             \
	VM_STAT_INCR(decompressions);       \
	current_thread()->decompressions++; \
MACRO_END

boolean_t current_thread_aborted(void);

/* Forward declarations of internal routines. */
static kern_return_t vm_fault_wire_fast(
	vm_map_t        map,
	vm_map_offset_t va,
	vm_prot_t       prot,
	vm_tag_t        wire_tag,
	vm_map_entry_t  entry,
	pmap_t          pmap,
	vm_map_offset_t pmap_addr,
	ppnum_t         *physpage_p);

static kern_return_t vm_fault_internal(
	vm_map_t        map,
	vm_map_offset_t vaddr,
	vm_prot_t       caller_prot,
	boolean_t       change_wiring,
	vm_tag_t        wire_tag,
	int             interruptible,
	pmap_t          pmap,
	vm_map_offset_t pmap_addr,
	ppnum_t         *physpage_p);

static void vm_fault_copy_cleanup(
	vm_page_t       page,
	vm_page_t       top_page);

static void vm_fault_copy_dst_cleanup(
	vm_page_t       page);

#if     VM_FAULT_CLASSIFY
extern void vm_fault_classify(vm_object_t       object,
    vm_object_offset_t    offset,
    vm_prot_t             fault_type);

extern void vm_fault_classify_init(void);
#endif

unsigned long vm_pmap_enter_blocked = 0;
unsigned long vm_pmap_enter_retried = 0;

unsigned long vm_cs_validates = 0;
unsigned long vm_cs_revalidates = 0;
unsigned long vm_cs_query_modified = 0;
unsigned long vm_cs_validated_dirtied = 0;
unsigned long vm_cs_bitmap_validated = 0;
#if PMAP_CS
uint64_t vm_cs_defer_to_pmap_cs = 0;
uint64_t vm_cs_defer_to_pmap_cs_not = 0;
#endif /* PMAP_CS */

void vm_pre_fault(vm_map_offset_t, vm_prot_t);

extern char *kdp_compressor_decompressed_page;
extern addr64_t kdp_compressor_decompressed_page_paddr;
extern ppnum_t  kdp_compressor_decompressed_page_ppnum;

struct vmrtfr {
	int vmrtfr_maxi;
	int vmrtfr_curi;
	int64_t vmrtf_total;
	vm_rtfault_record_t *vm_rtf_records;
} vmrtfrs;
#define VMRTF_DEFAULT_BUFSIZE (4096)
#define VMRTF_NUM_RECORDS_DEFAULT (VMRTF_DEFAULT_BUFSIZE / sizeof(vm_rtfault_record_t))
int vmrtf_num_records = VMRTF_NUM_RECORDS_DEFAULT;

static void vm_rtfrecord_lock(void);
static void vm_rtfrecord_unlock(void);
static void vm_record_rtfault(thread_t, uint64_t, vm_map_offset_t, int);

lck_spin_t vm_rtfr_slock;
extern lck_grp_t vm_page_lck_grp_bucket;
extern lck_attr_t vm_page_lck_attr;

/*
 *	Routine:	vm_fault_init
 *	Purpose:
 *		Initialize our private data structures.
 */
void
vm_fault_init(void)
{
	int i, vm_compressor_temp;
	boolean_t need_default_val = TRUE;
	/*
	 * Choose a value for the hard throttle threshold based on the amount of ram.  The threshold is
	 * computed as a percentage of available memory, and the percentage used is scaled inversely with
	 * the amount of memory.  The percentage runs between 10% and 35%.  We use 35% for small memory systems
	 * and reduce the value down to 10% for very large memory configurations.  This helps give us a
	 * definition of a memory hog that makes more sense relative to the amount of ram in the machine.
	 * The formula here simply uses the number of gigabytes of ram to adjust the percentage.
	 */

	vm_hard_throttle_threshold = sane_size * (35 - MIN((int)(sane_size / (1024 * 1024 * 1024)), 25)) / 100;

	/*
	 * Configure compressed pager behavior. A boot arg takes precedence over a device tree entry.
	 */

	if (PE_parse_boot_argn("vm_compressor", &vm_compressor_temp, sizeof(vm_compressor_temp))) {
		for (i = 0; i < VM_PAGER_MAX_MODES; i++) {
			if (vm_compressor_temp > 0 &&
			    ((vm_compressor_temp & (1 << i)) == vm_compressor_temp)) {
				need_default_val = FALSE;
				vm_compressor_mode = vm_compressor_temp;
				break;
			}
		}
		if (need_default_val) {
			printf("Ignoring \"vm_compressor\" boot arg %d\n", vm_compressor_temp);
		}
	}
	if (need_default_val) {
		/* If no boot arg or incorrect boot arg, try device tree. */
		PE_get_default("kern.vm_compressor", &vm_compressor_mode, sizeof(vm_compressor_mode));
	}
	printf("\"vm_compressor_mode\" is %d\n", vm_compressor_mode);

	PE_parse_boot_argn("vm_protect_privileged_from_untrusted", &vm_protect_privileged_from_untrusted, sizeof(vm_protect_privileged_from_untrusted));
}

void
vm_rtfault_record_init(void)
{
	PE_parse_boot_argn("vm_rtfault_records", &vmrtf_num_records, sizeof(vmrtf_num_records));

	assert(vmrtf_num_records >= 1);
	vmrtf_num_records = MAX(vmrtf_num_records, 1);
	size_t kallocsz = vmrtf_num_records * sizeof(vm_rtfault_record_t);
	vmrtfrs.vm_rtf_records = kalloc(kallocsz);
	bzero(vmrtfrs.vm_rtf_records, kallocsz);
	vmrtfrs.vmrtfr_maxi = vmrtf_num_records - 1;
	lck_spin_init(&vm_rtfr_slock, &vm_page_lck_grp_bucket, &vm_page_lck_attr);
}
/*
 *	Routine:	vm_fault_cleanup
 *	Purpose:
 *		Clean up the result of vm_fault_page.
 *	Results:
 *		The paging reference for "object" is released.
 *		"object" is unlocked.
 *		If "top_page" is not null,  "top_page" is
 *		freed and the paging reference for the object
 *		containing it is released.
 *
 *	In/out conditions:
 *		"object" must be locked.
 */
void
vm_fault_cleanup(
	vm_object_t     object,
	vm_page_t       top_page)
{
	vm_object_paging_end(object);
	vm_object_unlock(object);

	if (top_page != VM_PAGE_NULL) {
		object = VM_PAGE_OBJECT(top_page);

		vm_object_lock(object);
		VM_PAGE_FREE(top_page);
		vm_object_paging_end(object);
		vm_object_unlock(object);
	}
}

#define ALIGNED(x) (((x) & (PAGE_SIZE_64 - 1)) == 0)


boolean_t       vm_page_deactivate_behind = TRUE;
/*
 * default sizes given VM_BEHAVIOR_DEFAULT reference behavior
 */
#define VM_DEFAULT_DEACTIVATE_BEHIND_WINDOW     128
#define VM_DEFAULT_DEACTIVATE_BEHIND_CLUSTER    16              /* don't make this too big... */
                                                                /* we use it to size an array on the stack */

int vm_default_behind = VM_DEFAULT_DEACTIVATE_BEHIND_WINDOW;

#define MAX_SEQUENTIAL_RUN      (1024 * 1024 * 1024)

/*
 * vm_page_is_sequential
 *
 * Determine if sequential access is in progress
 * in accordance with the behavior specified.
 * Update state to indicate current access pattern.
 *
 * object must have at least the shared lock held
 */
static
void
vm_fault_is_sequential(
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_behavior_t           behavior)
{
	vm_object_offset_t      last_alloc;
	int                     sequential;
	int                     orig_sequential;

	last_alloc = object->last_alloc;
	sequential = object->sequential;
	orig_sequential = sequential;

	switch (behavior) {
	case VM_BEHAVIOR_RANDOM:
		/*
		 * reset indicator of sequential behavior
		 */
		sequential = 0;
		break;

	case VM_BEHAVIOR_SEQUENTIAL:
		if (offset && last_alloc == offset - PAGE_SIZE_64) {
			/*
			 * advance indicator of sequential behavior
			 */
			if (sequential < MAX_SEQUENTIAL_RUN) {
				sequential += PAGE_SIZE;
			}
		} else {
			/*
			 * reset indicator of sequential behavior
			 */
			sequential = 0;
		}
		break;

	case VM_BEHAVIOR_RSEQNTL:
		if (last_alloc && last_alloc == offset + PAGE_SIZE_64) {
			/*
			 * advance indicator of sequential behavior
			 */
			if (sequential > -MAX_SEQUENTIAL_RUN) {
				sequential -= PAGE_SIZE;
			}
		} else {
			/*
			 * reset indicator of sequential behavior
			 */
			sequential = 0;
		}
		break;

	case VM_BEHAVIOR_DEFAULT:
	default:
		if (offset && last_alloc == (offset - PAGE_SIZE_64)) {
			/*
			 * advance indicator of sequential behavior
			 */
			if (sequential < 0) {
				sequential = 0;
			}
			if (sequential < MAX_SEQUENTIAL_RUN) {
				sequential += PAGE_SIZE;
			}
		} else if (last_alloc && last_alloc == (offset + PAGE_SIZE_64)) {
			/*
			 * advance indicator of sequential behavior
			 */
			if (sequential > 0) {
				sequential = 0;
			}
			if (sequential > -MAX_SEQUENTIAL_RUN) {
				sequential -= PAGE_SIZE;
			}
		} else {
			/*
			 * reset indicator of sequential behavior
			 */
			sequential = 0;
		}
		break;
	}
	if (sequential != orig_sequential) {
		if (!OSCompareAndSwap(orig_sequential, sequential, (UInt32 *)&object->sequential)) {
			/*
			 * if someone else has already updated object->sequential
			 * don't bother trying to update it or object->last_alloc
			 */
			return;
		}
	}
	/*
	 * I'd like to do this with a OSCompareAndSwap64, but that
	 * doesn't exist for PPC...  however, it shouldn't matter
	 * that much... last_alloc is maintained so that we can determine
	 * if a sequential access pattern is taking place... if only
	 * one thread is banging on this object, no problem with the unprotected
	 * update... if 2 or more threads are banging away, we run the risk of
	 * someone seeing a mangled update... however, in the face of multiple
	 * accesses, no sequential access pattern can develop anyway, so we
	 * haven't lost any real info.
	 */
	object->last_alloc = offset;
}


int vm_page_deactivate_behind_count = 0;

/*
 * vm_page_deactivate_behind
 *
 * Determine if sequential access is in progress
 * in accordance with the behavior specified.  If
 * so, compute a potential page to deactivate and
 * deactivate it.
 *
 * object must be locked.
 *
 * return TRUE if we actually deactivate a page
 */
static
boolean_t
vm_fault_deactivate_behind(
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_behavior_t           behavior)
{
	int             n;
	int             pages_in_run = 0;
	int             max_pages_in_run = 0;
	int             sequential_run;
	int             sequential_behavior = VM_BEHAVIOR_SEQUENTIAL;
	vm_object_offset_t      run_offset = 0;
	vm_object_offset_t      pg_offset = 0;
	vm_page_t       m;
	vm_page_t       page_run[VM_DEFAULT_DEACTIVATE_BEHIND_CLUSTER];

	pages_in_run = 0;
#if TRACEFAULTPAGE
	dbgTrace(0xBEEF0018, (unsigned int) object, (unsigned int) vm_fault_deactivate_behind); /* (TEST/DEBUG) */
#endif

	if (object == kernel_object || vm_page_deactivate_behind == FALSE) {
		/*
		 * Do not deactivate pages from the kernel object: they
		 * are not intended to become pageable.
		 * or we've disabled the deactivate behind mechanism
		 */
		return FALSE;
	}
	if ((sequential_run = object->sequential)) {
		if (sequential_run < 0) {
			sequential_behavior = VM_BEHAVIOR_RSEQNTL;
			sequential_run = 0 - sequential_run;
		} else {
			sequential_behavior = VM_BEHAVIOR_SEQUENTIAL;
		}
	}
	switch (behavior) {
	case VM_BEHAVIOR_RANDOM:
		break;
	case VM_BEHAVIOR_SEQUENTIAL:
		if (sequential_run >= (int)PAGE_SIZE) {
			run_offset = 0 - PAGE_SIZE_64;
			max_pages_in_run = 1;
		}
		break;
	case VM_BEHAVIOR_RSEQNTL:
		if (sequential_run >= (int)PAGE_SIZE) {
			run_offset = PAGE_SIZE_64;
			max_pages_in_run = 1;
		}
		break;
	case VM_BEHAVIOR_DEFAULT:
	default:
	{       vm_object_offset_t behind = vm_default_behind * PAGE_SIZE_64;

		/*
		 * determine if the run of sequential accesss has been
		 * long enough on an object with default access behavior
		 * to consider it for deactivation
		 */
		if ((uint64_t)sequential_run >= behind && (sequential_run % (VM_DEFAULT_DEACTIVATE_BEHIND_CLUSTER * PAGE_SIZE)) == 0) {
			/*
			 * the comparisons between offset and behind are done
			 * in this kind of odd fashion in order to prevent wrap around
			 * at the end points
			 */
			if (sequential_behavior == VM_BEHAVIOR_SEQUENTIAL) {
				if (offset >= behind) {
					run_offset = 0 - behind;
					pg_offset = PAGE_SIZE_64;
					max_pages_in_run = VM_DEFAULT_DEACTIVATE_BEHIND_CLUSTER;
				}
			} else {
				if (offset < -behind) {
					run_offset = behind;
					pg_offset = 0 - PAGE_SIZE_64;
					max_pages_in_run = VM_DEFAULT_DEACTIVATE_BEHIND_CLUSTER;
				}
			}
		}
		break;}
	}
	for (n = 0; n < max_pages_in_run; n++) {
		m = vm_page_lookup(object, offset + run_offset + (n * pg_offset));

		if (m && !m->vmp_laundry && !m->vmp_busy && !m->vmp_no_cache && (m->vmp_q_state != VM_PAGE_ON_THROTTLED_Q) && !m->vmp_fictitious && !m->vmp_absent) {
			page_run[pages_in_run++] = m;

			/*
			 * by not passing in a pmap_flush_context we will forgo any TLB flushing, local or otherwise...
			 *
			 * a TLB flush isn't really needed here since at worst we'll miss the reference bit being
			 * updated in the PTE if a remote processor still has this mapping cached in its TLB when the
			 * new reference happens. If no futher references happen on the page after that remote TLB flushes
			 * we'll see a clean, non-referenced page when it eventually gets pulled out of the inactive queue
			 * by pageout_scan, which is just fine since the last reference would have happened quite far
			 * in the past (TLB caches don't hang around for very long), and of course could just as easily
			 * have happened before we did the deactivate_behind.
			 */
			pmap_clear_refmod_options(VM_PAGE_GET_PHYS_PAGE(m), VM_MEM_REFERENCED, PMAP_OPTIONS_NOFLUSH, (void *)NULL);
		}
	}
	if (pages_in_run) {
		vm_page_lockspin_queues();

		for (n = 0; n < pages_in_run; n++) {
			m = page_run[n];

			vm_page_deactivate_internal(m, FALSE);

			vm_page_deactivate_behind_count++;
#if TRACEFAULTPAGE
			dbgTrace(0xBEEF0019, (unsigned int) object, (unsigned int) m);  /* (TEST/DEBUG) */
#endif
		}
		vm_page_unlock_queues();

		return TRUE;
	}
	return FALSE;
}


#if (DEVELOPMENT || DEBUG)
uint32_t        vm_page_creation_throttled_hard = 0;
uint32_t        vm_page_creation_throttled_soft = 0;
uint64_t        vm_page_creation_throttle_avoided = 0;
#endif /* DEVELOPMENT || DEBUG */

static int
vm_page_throttled(boolean_t page_kept)
{
	clock_sec_t     elapsed_sec;
	clock_sec_t     tv_sec;
	clock_usec_t    tv_usec;

	thread_t thread = current_thread();

	if (thread->options & TH_OPT_VMPRIV) {
		return 0;
	}

	if (thread->t_page_creation_throttled) {
		thread->t_page_creation_throttled = 0;

		if (page_kept == FALSE) {
			goto no_throttle;
		}
	}
	if (NEED_TO_HARD_THROTTLE_THIS_TASK()) {
#if (DEVELOPMENT || DEBUG)
		thread->t_page_creation_throttled_hard++;
		OSAddAtomic(1, &vm_page_creation_throttled_hard);
#endif /* DEVELOPMENT || DEBUG */
		return HARD_THROTTLE_DELAY;
	}

	if ((vm_page_free_count < vm_page_throttle_limit || (VM_CONFIG_COMPRESSOR_IS_PRESENT && SWAPPER_NEEDS_TO_UNTHROTTLE())) &&
	    thread->t_page_creation_count > (VM_PAGE_CREATION_THROTTLE_PERIOD_SECS * VM_PAGE_CREATION_THROTTLE_RATE_PER_SEC)) {
		if (vm_page_free_wanted == 0 && vm_page_free_wanted_privileged == 0) {
#if (DEVELOPMENT || DEBUG)
			OSAddAtomic64(1, &vm_page_creation_throttle_avoided);
#endif
			goto no_throttle;
		}
		clock_get_system_microtime(&tv_sec, &tv_usec);

		elapsed_sec = tv_sec - thread->t_page_creation_time;

		if (elapsed_sec <= VM_PAGE_CREATION_THROTTLE_PERIOD_SECS ||
		    (thread->t_page_creation_count / elapsed_sec) >= VM_PAGE_CREATION_THROTTLE_RATE_PER_SEC) {
			if (elapsed_sec >= (3 * VM_PAGE_CREATION_THROTTLE_PERIOD_SECS)) {
				/*
				 * we'll reset our stats to give a well behaved app
				 * that was unlucky enough to accumulate a bunch of pages
				 * over a long period of time a chance to get out of
				 * the throttled state... we reset the counter and timestamp
				 * so that if it stays under the rate limit for the next second
				 * it will be back in our good graces... if it exceeds it, it
				 * will remain in the throttled state
				 */
				thread->t_page_creation_time = tv_sec;
				thread->t_page_creation_count = VM_PAGE_CREATION_THROTTLE_RATE_PER_SEC * (VM_PAGE_CREATION_THROTTLE_PERIOD_SECS - 1);
			}
			VM_PAGEOUT_DEBUG(vm_page_throttle_count, 1);

			thread->t_page_creation_throttled = 1;

			if (VM_CONFIG_COMPRESSOR_IS_PRESENT && HARD_THROTTLE_LIMIT_REACHED()) {
#if (DEVELOPMENT || DEBUG)
				thread->t_page_creation_throttled_hard++;
				OSAddAtomic(1, &vm_page_creation_throttled_hard);
#endif /* DEVELOPMENT || DEBUG */
				return HARD_THROTTLE_DELAY;
			} else {
#if (DEVELOPMENT || DEBUG)
				thread->t_page_creation_throttled_soft++;
				OSAddAtomic(1, &vm_page_creation_throttled_soft);
#endif /* DEVELOPMENT || DEBUG */
				return SOFT_THROTTLE_DELAY;
			}
		}
		thread->t_page_creation_time = tv_sec;
		thread->t_page_creation_count = 0;
	}
no_throttle:
	thread->t_page_creation_count++;

	return 0;
}


/*
 * check for various conditions that would
 * prevent us from creating a ZF page...
 * cleanup is based on being called from vm_fault_page
 *
 * object must be locked
 * object == m->vmp_object
 */
static vm_fault_return_t
vm_fault_check(vm_object_t object, vm_page_t m, vm_page_t first_m, wait_interrupt_t interruptible_state, boolean_t page_throttle)
{
	int throttle_delay;

	if (object->shadow_severed ||
	    VM_OBJECT_PURGEABLE_FAULT_ERROR(object)) {
		/*
		 * Either:
		 * 1. the shadow chain was severed,
		 * 2. the purgeable object is volatile or empty and is marked
		 *    to fault on access while volatile.
		 * Just have to return an error at this point
		 */
		if (m != VM_PAGE_NULL) {
			VM_PAGE_FREE(m);
		}
		vm_fault_cleanup(object, first_m);

		thread_interrupt_level(interruptible_state);

		return VM_FAULT_MEMORY_ERROR;
	}
	if (page_throttle == TRUE) {
		if ((throttle_delay = vm_page_throttled(FALSE))) {
			/*
			 * we're throttling zero-fills...
			 * treat this as if we couldn't grab a page
			 */
			if (m != VM_PAGE_NULL) {
				VM_PAGE_FREE(m);
			}
			vm_fault_cleanup(object, first_m);

			VM_DEBUG_EVENT(vmf_check_zfdelay, VMF_CHECK_ZFDELAY, DBG_FUNC_NONE, throttle_delay, 0, 0, 0);

			delay(throttle_delay);

			if (current_thread_aborted()) {
				thread_interrupt_level(interruptible_state);
				return VM_FAULT_INTERRUPTED;
			}
			thread_interrupt_level(interruptible_state);

			return VM_FAULT_MEMORY_SHORTAGE;
		}
	}
	return VM_FAULT_SUCCESS;
}


/*
 * do the work to zero fill a page and
 * inject it into the correct paging queue
 *
 * m->vmp_object must be locked
 * page queue lock must NOT be held
 */
static int
vm_fault_zero_page(vm_page_t m, boolean_t no_zero_fill)
{
	int my_fault = DBG_ZERO_FILL_FAULT;
	vm_object_t     object;

	object = VM_PAGE_OBJECT(m);

	/*
	 * This is is a zero-fill page fault...
	 *
	 * Checking the page lock is a waste of
	 * time;  this page was absent, so
	 * it can't be page locked by a pager.
	 *
	 * we also consider it undefined
	 * with respect to instruction
	 * execution.  i.e. it is the responsibility
	 * of higher layers to call for an instruction
	 * sync after changing the contents and before
	 * sending a program into this area.  We
	 * choose this approach for performance
	 */
	m->vmp_pmapped = TRUE;

	m->vmp_cs_validated = FALSE;
	m->vmp_cs_tainted = FALSE;
	m->vmp_cs_nx = FALSE;

	if (no_zero_fill == TRUE) {
		my_fault = DBG_NZF_PAGE_FAULT;

		if (m->vmp_absent && m->vmp_busy) {
			return my_fault;
		}
	} else {
		vm_page_zero_fill(m);

		VM_STAT_INCR(zero_fill_count);
		DTRACE_VM2(zfod, int, 1, (uint64_t *), NULL);
	}
	assert(!m->vmp_laundry);
	assert(object != kernel_object);
	//assert(m->vmp_pageq.next == 0 && m->vmp_pageq.prev == 0);

	if (!VM_DYNAMIC_PAGING_ENABLED() &&
	    (object->purgable == VM_PURGABLE_DENY ||
	    object->purgable == VM_PURGABLE_NONVOLATILE ||
	    object->purgable == VM_PURGABLE_VOLATILE)) {
		vm_page_lockspin_queues();

		if (!VM_DYNAMIC_PAGING_ENABLED()) {
			assert(!VM_PAGE_WIRED(m));

			/*
			 * can't be on the pageout queue since we don't
			 * have a pager to try and clean to
			 */
			vm_page_queues_remove(m, TRUE);
			vm_page_check_pageable_safe(m);
			vm_page_queue_enter(&vm_page_queue_throttled, m, vmp_pageq);
			m->vmp_q_state = VM_PAGE_ON_THROTTLED_Q;
			vm_page_throttled_count++;
		}
		vm_page_unlock_queues();
	}
	return my_fault;
}


/*
 *	Routine:	vm_fault_page
 *	Purpose:
 *		Find the resident page for the virtual memory
 *		specified by the given virtual memory object
 *		and offset.
 *	Additional arguments:
 *		The required permissions for the page is given
 *		in "fault_type".  Desired permissions are included
 *		in "protection".
 *		fault_info is passed along to determine pagein cluster
 *		limits... it contains the expected reference pattern,
 *		cluster size if available, etc...
 *
 *		If the desired page is known to be resident (for
 *		example, because it was previously wired down), asserting
 *		the "unwiring" parameter will speed the search.
 *
 *		If the operation can be interrupted (by thread_abort
 *		or thread_terminate), then the "interruptible"
 *		parameter should be asserted.
 *
 *	Results:
 *		The page containing the proper data is returned
 *		in "result_page".
 *
 *	In/out conditions:
 *		The source object must be locked and referenced,
 *		and must donate one paging reference.  The reference
 *		is not affected.  The paging reference and lock are
 *		consumed.
 *
 *		If the call succeeds, the object in which "result_page"
 *		resides is left locked and holding a paging reference.
 *		If this is not the original object, a busy page in the
 *		original object is returned in "top_page", to prevent other
 *		callers from pursuing this same data, along with a paging
 *		reference for the original object.  The "top_page" should
 *		be destroyed when this guarantee is no longer required.
 *		The "result_page" is also left busy.  It is not removed
 *		from the pageout queues.
 *	Special Case:
 *		A return value of VM_FAULT_SUCCESS_NO_PAGE means that the
 *		fault succeeded but there's no VM page (i.e. the VM object
 *              does not actually hold VM pages, but device memory or
 *		large pages).  The object is still locked and we still hold a
 *		paging_in_progress reference.
 */
unsigned int vm_fault_page_blocked_access = 0;
unsigned int vm_fault_page_forced_retry = 0;

vm_fault_return_t
vm_fault_page(
	/* Arguments: */
	vm_object_t     first_object,   /* Object to begin search */
	vm_object_offset_t first_offset,        /* Offset into object */
	vm_prot_t       fault_type,     /* What access is requested */
	boolean_t       must_be_resident,/* Must page be resident? */
	boolean_t       caller_lookup,  /* caller looked up page */
	/* Modifies in place: */
	vm_prot_t       *protection,    /* Protection for mapping */
	vm_page_t       *result_page,   /* Page found, if successful */
	/* Returns: */
	vm_page_t       *top_page,      /* Page in top object, if
                                         * not result_page.  */
	int             *type_of_fault, /* if non-null, fill in with type of fault
                                         * COW, zero-fill, etc... returned in trace point */
	/* More arguments: */
	kern_return_t   *error_code,    /* code if page is in error */
	boolean_t       no_zero_fill,   /* don't zero fill absent pages */
	boolean_t       data_supply,    /* treat as data_supply if
                                         * it is a write fault and a full
                                         * page is provided */
	vm_object_fault_info_t fault_info)
{
	vm_page_t               m;
	vm_object_t             object;
	vm_object_offset_t      offset;
	vm_page_t               first_m;
	vm_object_t             next_object;
	vm_object_t             copy_object;
	boolean_t               look_for_page;
	boolean_t               force_fault_retry = FALSE;
	vm_prot_t               access_required = fault_type;
	vm_prot_t               wants_copy_flag;
	kern_return_t           wait_result;
	wait_interrupt_t        interruptible_state;
	boolean_t               data_already_requested = FALSE;
	vm_behavior_t           orig_behavior;
	vm_size_t               orig_cluster_size;
	vm_fault_return_t       error;
	int                     my_fault;
	uint32_t                try_failed_count;
	int                     interruptible; /* how may fault be interrupted? */
	int                     external_state = VM_EXTERNAL_STATE_UNKNOWN;
	memory_object_t         pager;
	vm_fault_return_t       retval;
	int                     grab_options;

/*
 * MUST_ASK_PAGER() evaluates to TRUE if the page specified by object/offset is
 * marked as paged out in the compressor pager or the pager doesn't exist.
 * Note also that if the pager for an internal object
 * has not been created, the pager is not invoked regardless of the value
 * of MUST_ASK_PAGER().
 *
 * PAGED_OUT() evaluates to TRUE if the page specified by the object/offset
 * is marked as paged out in the compressor pager.
 * PAGED_OUT() is used to determine if a page has already been pushed
 * into a copy object in order to avoid a redundant page out operation.
 */
#define MUST_ASK_PAGER(o, f, s)                                 \
	((s = VM_COMPRESSOR_PAGER_STATE_GET((o), (f))) != VM_EXTERNAL_STATE_ABSENT)

#define PAGED_OUT(o, f) \
	(VM_COMPRESSOR_PAGER_STATE_GET((o), (f)) == VM_EXTERNAL_STATE_EXISTS)

/*
 *	Recovery actions
 */
#define RELEASE_PAGE(m)                                 \
	MACRO_BEGIN                                     \
	PAGE_WAKEUP_DONE(m);                            \
	if ( !VM_PAGE_PAGEABLE(m)) {                    \
	        vm_page_lockspin_queues();              \
	        if ( !VM_PAGE_PAGEABLE(m)) {            \
	                if (VM_CONFIG_COMPRESSOR_IS_ACTIVE)     \
	                        vm_page_deactivate(m);          \
	                else                                    \
	                        vm_page_activate(m);            \
	        }                                               \
	        vm_page_unlock_queues();                        \
	}                                                       \
	MACRO_END

#if TRACEFAULTPAGE
	dbgTrace(0xBEEF0002, (unsigned int) first_object, (unsigned int) first_offset); /* (TEST/DEBUG) */
#endif

	interruptible = fault_info->interruptible;
	interruptible_state = thread_interrupt_level(interruptible);

	/*
	 *	INVARIANTS (through entire routine):
	 *
	 *	1)	At all times, we must either have the object
	 *		lock or a busy page in some object to prevent
	 *		some other thread from trying to bring in
	 *		the same page.
	 *
	 *		Note that we cannot hold any locks during the
	 *		pager access or when waiting for memory, so
	 *		we use a busy page then.
	 *
	 *	2)	To prevent another thread from racing us down the
	 *		shadow chain and entering a new page in the top
	 *		object before we do, we must keep a busy page in
	 *		the top object while following the shadow chain.
	 *
	 *	3)	We must increment paging_in_progress on any object
	 *		for which we have a busy page before dropping
	 *		the object lock
	 *
	 *	4)	We leave busy pages on the pageout queues.
	 *		If the pageout daemon comes across a busy page,
	 *		it will remove the page from the pageout queues.
	 */

	object = first_object;
	offset = first_offset;
	first_m = VM_PAGE_NULL;
	access_required = fault_type;

	/*
	 * default type of fault
	 */
	my_fault = DBG_CACHE_HIT_FAULT;

	while (TRUE) {
#if TRACEFAULTPAGE
		dbgTrace(0xBEEF0003, (unsigned int) 0, (unsigned int) 0);       /* (TEST/DEBUG) */
#endif

		grab_options = 0;
#if CONFIG_SECLUDED_MEMORY
		if (object->can_grab_secluded) {
			grab_options |= VM_PAGE_GRAB_SECLUDED;
		}
#endif /* CONFIG_SECLUDED_MEMORY */

		if (!object->alive) {
			/*
			 * object is no longer valid
			 * clean up and return error
			 */
			vm_fault_cleanup(object, first_m);
			thread_interrupt_level(interruptible_state);

			return VM_FAULT_MEMORY_ERROR;
		}

		if (!object->pager_created && object->phys_contiguous) {
			/*
			 * A physically-contiguous object without a pager:
			 * must be a "large page" object.  We do not deal
			 * with VM pages for this object.
			 */
			caller_lookup = FALSE;
			m = VM_PAGE_NULL;
			goto phys_contig_object;
		}

		if (object->blocked_access) {
			/*
			 * Access to this VM object has been blocked.
			 * Replace our "paging_in_progress" reference with
			 * a "activity_in_progress" reference and wait for
			 * access to be unblocked.
			 */
			caller_lookup = FALSE; /* no longer valid after sleep */
			vm_object_activity_begin(object);
			vm_object_paging_end(object);
			while (object->blocked_access) {
				vm_object_sleep(object,
				    VM_OBJECT_EVENT_UNBLOCKED,
				    THREAD_UNINT);
			}
			vm_fault_page_blocked_access++;
			vm_object_paging_begin(object);
			vm_object_activity_end(object);
		}

		/*
		 * See whether the page at 'offset' is resident
		 */
		if (caller_lookup == TRUE) {
			/*
			 * The caller has already looked up the page
			 * and gave us the result in "result_page".
			 * We can use this for the first lookup but
			 * it loses its validity as soon as we unlock
			 * the object.
			 */
			m = *result_page;
			caller_lookup = FALSE; /* no longer valid after that */
		} else {
			m = vm_page_lookup(object, offset);
		}
#if TRACEFAULTPAGE
		dbgTrace(0xBEEF0004, (unsigned int) m, (unsigned int) object);  /* (TEST/DEBUG) */
#endif
		if (m != VM_PAGE_NULL) {
			if (m->vmp_busy) {
				/*
				 * The page is being brought in,
				 * wait for it and then retry.
				 */
#if TRACEFAULTPAGE
				dbgTrace(0xBEEF0005, (unsigned int) m, (unsigned int) 0);       /* (TEST/DEBUG) */
#endif
				wait_result = PAGE_SLEEP(object, m, interruptible);

				counter(c_vm_fault_page_block_busy_kernel++);

				if (wait_result != THREAD_AWAKENED) {
					vm_fault_cleanup(object, first_m);
					thread_interrupt_level(interruptible_state);

					if (wait_result == THREAD_RESTART) {
						return VM_FAULT_RETRY;
					} else {
						return VM_FAULT_INTERRUPTED;
					}
				}
				continue;
			}
			if (m->vmp_laundry) {
				m->vmp_free_when_done = FALSE;

				if (!m->vmp_cleaning) {
					vm_pageout_steal_laundry(m, FALSE);
				}
			}
			if (VM_PAGE_GET_PHYS_PAGE(m) == vm_page_guard_addr) {
				/*
				 * Guard page: off limits !
				 */
				if (fault_type == VM_PROT_NONE) {
					/*
					 * The fault is not requesting any
					 * access to the guard page, so it must
					 * be just to wire or unwire it.
					 * Let's pretend it succeeded...
					 */
					m->vmp_busy = TRUE;
					*result_page = m;
					assert(first_m == VM_PAGE_NULL);
					*top_page = first_m;
					if (type_of_fault) {
						*type_of_fault = DBG_GUARD_FAULT;
					}
					thread_interrupt_level(interruptible_state);
					return VM_FAULT_SUCCESS;
				} else {
					/*
					 * The fault requests access to the
					 * guard page: let's deny that !
					 */
					vm_fault_cleanup(object, first_m);
					thread_interrupt_level(interruptible_state);
					return VM_FAULT_MEMORY_ERROR;
				}
			}

			if (m->vmp_error) {
				/*
				 * The page is in error, give up now.
				 */
#if TRACEFAULTPAGE
				dbgTrace(0xBEEF0006, (unsigned int) m, (unsigned int) error_code);      /* (TEST/DEBUG) */
#endif
				if (error_code) {
					*error_code = KERN_MEMORY_ERROR;
				}
				VM_PAGE_FREE(m);

				vm_fault_cleanup(object, first_m);
				thread_interrupt_level(interruptible_state);

				return VM_FAULT_MEMORY_ERROR;
			}
			if (m->vmp_restart) {
				/*
				 * The pager wants us to restart
				 * at the top of the chain,
				 * typically because it has moved the
				 * page to another pager, then do so.
				 */
#if TRACEFAULTPAGE
				dbgTrace(0xBEEF0007, (unsigned int) m, (unsigned int) 0);       /* (TEST/DEBUG) */
#endif
				VM_PAGE_FREE(m);

				vm_fault_cleanup(object, first_m);
				thread_interrupt_level(interruptible_state);

				return VM_FAULT_RETRY;
			}
			if (m->vmp_absent) {
				/*
				 * The page isn't busy, but is absent,
				 * therefore it's deemed "unavailable".
				 *
				 * Remove the non-existent page (unless it's
				 * in the top object) and move on down to the
				 * next object (if there is one).
				 */
#if TRACEFAULTPAGE
				dbgTrace(0xBEEF0008, (unsigned int) m, (unsigned int) object->shadow);  /* (TEST/DEBUG) */
#endif
				next_object = object->shadow;

				if (next_object == VM_OBJECT_NULL) {
					/*
					 * Absent page at bottom of shadow
					 * chain; zero fill the page we left
					 * busy in the first object, and free
					 * the absent page.
					 */
					assert(!must_be_resident);

					/*
					 * check for any conditions that prevent
					 * us from creating a new zero-fill page
					 * vm_fault_check will do all of the
					 * fault cleanup in the case of an error condition
					 * including resetting the thread_interrupt_level
					 */
					error = vm_fault_check(object, m, first_m, interruptible_state, (type_of_fault == NULL) ? TRUE : FALSE);

					if (error != VM_FAULT_SUCCESS) {
						return error;
					}

					if (object != first_object) {
						/*
						 * free the absent page we just found
						 */
						VM_PAGE_FREE(m);

						/*
						 * drop reference and lock on current object
						 */
						vm_object_paging_end(object);
						vm_object_unlock(object);

						/*
						 * grab the original page we
						 * 'soldered' in place and
						 * retake lock on 'first_object'
						 */
						m = first_m;
						first_m = VM_PAGE_NULL;

						object = first_object;
						offset = first_offset;

						vm_object_lock(object);
					} else {
						/*
						 * we're going to use the absent page we just found
						 * so convert it to a 'busy' page
						 */
						m->vmp_absent = FALSE;
						m->vmp_busy = TRUE;
					}
					if (fault_info->mark_zf_absent && no_zero_fill == TRUE) {
						m->vmp_absent = TRUE;
					}
					/*
					 * zero-fill the page and put it on
					 * the correct paging queue
					 */
					my_fault = vm_fault_zero_page(m, no_zero_fill);

					break;
				} else {
					if (must_be_resident) {
						vm_object_paging_end(object);
					} else if (object != first_object) {
						vm_object_paging_end(object);
						VM_PAGE_FREE(m);
					} else {
						first_m = m;
						m->vmp_absent = FALSE;
						m->vmp_busy = TRUE;

						vm_page_lockspin_queues();
						vm_page_queues_remove(m, FALSE);
						vm_page_unlock_queues();
					}

					offset += object->vo_shadow_offset;
					fault_info->lo_offset += object->vo_shadow_offset;
					fault_info->hi_offset += object->vo_shadow_offset;
					access_required = VM_PROT_READ;

					vm_object_lock(next_object);
					vm_object_unlock(object);
					object = next_object;
					vm_object_paging_begin(object);

					/*
					 * reset to default type of fault
					 */
					my_fault = DBG_CACHE_HIT_FAULT;

					continue;
				}
			}
			if ((m->vmp_cleaning)
			    && ((object != first_object) || (object->copy != VM_OBJECT_NULL))
			    && (fault_type & VM_PROT_WRITE)) {
				/*
				 * This is a copy-on-write fault that will
				 * cause us to revoke access to this page, but
				 * this page is in the process of being cleaned
				 * in a clustered pageout. We must wait until
				 * the cleaning operation completes before
				 * revoking access to the original page,
				 * otherwise we might attempt to remove a
				 * wired mapping.
				 */
#if TRACEFAULTPAGE
				dbgTrace(0xBEEF0009, (unsigned int) m, (unsigned int) offset);  /* (TEST/DEBUG) */
#endif
				/*
				 * take an extra ref so that object won't die
				 */
				vm_object_reference_locked(object);

				vm_fault_cleanup(object, first_m);

				counter(c_vm_fault_page_block_backoff_kernel++);
				vm_object_lock(object);
				assert(object->ref_count > 0);

				m = vm_page_lookup(object, offset);

				if (m != VM_PAGE_NULL && m->vmp_cleaning) {
					PAGE_ASSERT_WAIT(m, interruptible);

					vm_object_unlock(object);
					wait_result = thread_block(THREAD_CONTINUE_NULL);
					vm_object_deallocate(object);

					goto backoff;
				} else {
					vm_object_unlock(object);

					vm_object_deallocate(object);
					thread_interrupt_level(interruptible_state);

					return VM_FAULT_RETRY;
				}
			}
			if (type_of_fault == NULL && (m->vmp_q_state == VM_PAGE_ON_SPECULATIVE_Q) &&
			    !(fault_info != NULL && fault_info->stealth)) {
				/*
				 * If we were passed a non-NULL pointer for
				 * "type_of_fault", than we came from
				 * vm_fault... we'll let it deal with
				 * this condition, since it
				 * needs to see m->vmp_speculative to correctly
				 * account the pageins, otherwise...
				 * take it off the speculative queue, we'll
				 * let the caller of vm_fault_page deal
				 * with getting it onto the correct queue
				 *
				 * If the caller specified in fault_info that
				 * it wants a "stealth" fault, we also leave
				 * the page in the speculative queue.
				 */
				vm_page_lockspin_queues();
				if (m->vmp_q_state == VM_PAGE_ON_SPECULATIVE_Q) {
					vm_page_queues_remove(m, FALSE);
				}
				vm_page_unlock_queues();
			}
			assert(object == VM_PAGE_OBJECT(m));

			if (object->code_signed) {
				/*
				 * CODE SIGNING:
				 * We just paged in a page from a signed
				 * memory object but we don't need to
				 * validate it now.  We'll validate it if
				 * when it gets mapped into a user address
				 * space for the first time or when the page
				 * gets copied to another object as a result
				 * of a copy-on-write.
				 */
			}

			/*
			 * We mark the page busy and leave it on
			 * the pageout queues.  If the pageout
			 * deamon comes across it, then it will
			 * remove the page from the queue, but not the object
			 */
#if TRACEFAULTPAGE
			dbgTrace(0xBEEF000B, (unsigned int) m, (unsigned int) 0);       /* (TEST/DEBUG) */
#endif
			assert(!m->vmp_busy);
			assert(!m->vmp_absent);

			m->vmp_busy = TRUE;
			break;
		}


		/*
		 * we get here when there is no page present in the object at
		 * the offset we're interested in... we'll allocate a page
		 * at this point if the pager associated with
		 * this object can provide the data or we're the top object...
		 * object is locked;  m == NULL
		 */

		if (must_be_resident) {
			if (fault_type == VM_PROT_NONE &&
			    object == kernel_object) {
				/*
				 * We've been called from vm_fault_unwire()
				 * while removing a map entry that was allocated
				 * with KMA_KOBJECT and KMA_VAONLY.  This page
				 * is not present and there's nothing more to
				 * do here (nothing to unwire).
				 */
				vm_fault_cleanup(object, first_m);
				thread_interrupt_level(interruptible_state);

				return VM_FAULT_MEMORY_ERROR;
			}

			goto dont_look_for_page;
		}

		/* Don't expect to fault pages into the kernel object. */
		assert(object != kernel_object);

		data_supply = FALSE;

		look_for_page = (object->pager_created && (MUST_ASK_PAGER(object, offset, external_state) == TRUE) && !data_supply);

#if TRACEFAULTPAGE
		dbgTrace(0xBEEF000C, (unsigned int) look_for_page, (unsigned int) object);      /* (TEST/DEBUG) */
#endif
		if (!look_for_page && object == first_object && !object->phys_contiguous) {
			/*
			 * Allocate a new page for this object/offset pair as a placeholder
			 */
			m = vm_page_grab_options(grab_options);
#if TRACEFAULTPAGE
			dbgTrace(0xBEEF000D, (unsigned int) m, (unsigned int) object);  /* (TEST/DEBUG) */
#endif
			if (m == VM_PAGE_NULL) {
				vm_fault_cleanup(object, first_m);
				thread_interrupt_level(interruptible_state);

				return VM_FAULT_MEMORY_SHORTAGE;
			}

			if (fault_info && fault_info->batch_pmap_op == TRUE) {
				vm_page_insert_internal(m, object, offset, VM_KERN_MEMORY_NONE, FALSE, TRUE, TRUE, FALSE, NULL);
			} else {
				vm_page_insert(m, object, offset);
			}
		}
		if (look_for_page) {
			kern_return_t   rc;
			int             my_fault_type;

			/*
			 *	If the memory manager is not ready, we
			 *	cannot make requests.
			 */
			if (!object->pager_ready) {
#if TRACEFAULTPAGE
				dbgTrace(0xBEEF000E, (unsigned int) 0, (unsigned int) 0);       /* (TEST/DEBUG) */
#endif
				if (m != VM_PAGE_NULL) {
					VM_PAGE_FREE(m);
				}

				/*
				 * take an extra ref so object won't die
				 */
				vm_object_reference_locked(object);
				vm_fault_cleanup(object, first_m);
				counter(c_vm_fault_page_block_backoff_kernel++);

				vm_object_lock(object);
				assert(object->ref_count > 0);

				if (!object->pager_ready) {
					wait_result = vm_object_assert_wait(object, VM_OBJECT_EVENT_PAGER_READY, interruptible);

					vm_object_unlock(object);
					if (wait_result == THREAD_WAITING) {
						wait_result = thread_block(THREAD_CONTINUE_NULL);
					}
					vm_object_deallocate(object);

					goto backoff;
				} else {
					vm_object_unlock(object);
					vm_object_deallocate(object);
					thread_interrupt_level(interruptible_state);

					return VM_FAULT_RETRY;
				}
			}
			if (!object->internal && !object->phys_contiguous && object->paging_in_progress > vm_object_pagein_throttle) {
				/*
				 * If there are too many outstanding page
				 * requests pending on this external object, we
				 * wait for them to be resolved now.
				 */
#if TRACEFAULTPAGE
				dbgTrace(0xBEEF0010, (unsigned int) m, (unsigned int) 0);       /* (TEST/DEBUG) */
#endif
				if (m != VM_PAGE_NULL) {
					VM_PAGE_FREE(m);
				}
				/*
				 * take an extra ref so object won't die
				 */
				vm_object_reference_locked(object);

				vm_fault_cleanup(object, first_m);

				counter(c_vm_fault_page_block_backoff_kernel++);

				vm_object_lock(object);
				assert(object->ref_count > 0);

				if (object->paging_in_progress >= vm_object_pagein_throttle) {
					vm_object_assert_wait(object, VM_OBJECT_EVENT_PAGING_ONLY_IN_PROGRESS, interruptible);

					vm_object_unlock(object);
					wait_result = thread_block(THREAD_CONTINUE_NULL);
					vm_object_deallocate(object);

					goto backoff;
				} else {
					vm_object_unlock(object);
					vm_object_deallocate(object);
					thread_interrupt_level(interruptible_state);

					return VM_FAULT_RETRY;
				}
			}
			if (object->internal) {
				int compressed_count_delta;

				assert(VM_CONFIG_COMPRESSOR_IS_PRESENT);

				if (m == VM_PAGE_NULL) {
					/*
					 * Allocate a new page for this object/offset pair as a placeholder
					 */
					m = vm_page_grab_options(grab_options);
#if TRACEFAULTPAGE
					dbgTrace(0xBEEF000D, (unsigned int) m, (unsigned int) object);  /* (TEST/DEBUG) */
#endif
					if (m == VM_PAGE_NULL) {
						vm_fault_cleanup(object, first_m);
						thread_interrupt_level(interruptible_state);

						return VM_FAULT_MEMORY_SHORTAGE;
					}

					m->vmp_absent = TRUE;
					if (fault_info && fault_info->batch_pmap_op == TRUE) {
						vm_page_insert_internal(m, object, offset, VM_KERN_MEMORY_NONE, FALSE, TRUE, TRUE, FALSE, NULL);
					} else {
						vm_page_insert(m, object, offset);
					}
				}
				assert(m->vmp_busy);

				m->vmp_absent = TRUE;
				pager = object->pager;

				assert(object->paging_in_progress > 0);
				vm_object_unlock(object);

				rc = vm_compressor_pager_get(
					pager,
					offset + object->paging_offset,
					VM_PAGE_GET_PHYS_PAGE(m),
					&my_fault_type,
					0,
					&compressed_count_delta);

				if (type_of_fault == NULL) {
					int     throttle_delay;

					/*
					 * we weren't called from vm_fault, so we
					 * need to apply page creation throttling
					 * do it before we re-acquire any locks
					 */
					if (my_fault_type == DBG_COMPRESSOR_FAULT) {
						if ((throttle_delay = vm_page_throttled(TRUE))) {
							VM_DEBUG_EVENT(vmf_compressordelay, VMF_COMPRESSORDELAY, DBG_FUNC_NONE, throttle_delay, 0, 1, 0);
							delay(throttle_delay);
						}
					}
				}
				vm_object_lock(object);
				assert(object->paging_in_progress > 0);

				vm_compressor_pager_count(
					pager,
					compressed_count_delta,
					FALSE, /* shared_lock */
					object);

				switch (rc) {
				case KERN_SUCCESS:
					m->vmp_absent = FALSE;
					m->vmp_dirty = TRUE;
					if ((object->wimg_bits &
					    VM_WIMG_MASK) !=
					    VM_WIMG_USE_DEFAULT) {
						/*
						 * If the page is not cacheable,
						 * we can't let its contents
						 * linger in the data cache
						 * after the decompression.
						 */
						pmap_sync_page_attributes_phys(
							VM_PAGE_GET_PHYS_PAGE(m));
					} else {
						m->vmp_written_by_kernel = TRUE;
					}

					/*
					 * If the object is purgeable, its
					 * owner's purgeable ledgers have been
					 * updated in vm_page_insert() but the
					 * page was also accounted for in a
					 * "compressed purgeable" ledger, so
					 * update that now.
					 */
					if (((object->purgable !=
					    VM_PURGABLE_DENY) ||
					    object->vo_ledger_tag) &&
					    (object->vo_owner !=
					    NULL)) {
						/*
						 * One less compressed
						 * purgeable/tagged page.
						 */
						vm_object_owner_compressed_update(
							object,
							-1);
					}

					break;
				case KERN_MEMORY_FAILURE:
					m->vmp_unusual = TRUE;
					m->vmp_error = TRUE;
					m->vmp_absent = FALSE;
					break;
				case KERN_MEMORY_ERROR:
					assert(m->vmp_absent);
					break;
				default:
					panic("vm_fault_page(): unexpected "
					    "error %d from "
					    "vm_compressor_pager_get()\n",
					    rc);
				}
				PAGE_WAKEUP_DONE(m);

				rc = KERN_SUCCESS;
				goto data_requested;
			}
			my_fault_type = DBG_PAGEIN_FAULT;

			if (m != VM_PAGE_NULL) {
				VM_PAGE_FREE(m);
				m = VM_PAGE_NULL;
			}

#if TRACEFAULTPAGE
			dbgTrace(0xBEEF0012, (unsigned int) object, (unsigned int) 0);  /* (TEST/DEBUG) */
#endif

			/*
			 * It's possible someone called vm_object_destroy while we weren't
			 * holding the object lock.  If that has happened, then bail out
			 * here.
			 */

			pager = object->pager;

			if (pager == MEMORY_OBJECT_NULL) {
				vm_fault_cleanup(object, first_m);
				thread_interrupt_level(interruptible_state);
				return VM_FAULT_MEMORY_ERROR;
			}

			/*
			 * We have an absent page in place for the faulting offset,
			 * so we can release the object lock.
			 */

			if (object->object_is_shared_cache) {
				set_thread_rwlock_boost();
			}

			vm_object_unlock(object);

			/*
			 * If this object uses a copy_call strategy,
			 * and we are interested in a copy of this object
			 * (having gotten here only by following a
			 * shadow chain), then tell the memory manager
			 * via a flag added to the desired_access
			 * parameter, so that it can detect a race
			 * between our walking down the shadow chain
			 * and its pushing pages up into a copy of
			 * the object that it manages.
			 */
			if (object->copy_strategy == MEMORY_OBJECT_COPY_CALL && object != first_object) {
				wants_copy_flag = VM_PROT_WANTS_COPY;
			} else {
				wants_copy_flag = VM_PROT_NONE;
			}

			if (object->copy == first_object) {
				/*
				 * if we issue the memory_object_data_request in
				 * this state, we are subject to a deadlock with
				 * the underlying filesystem if it is trying to
				 * shrink the file resulting in a push of pages
				 * into the copy object...  that push will stall
				 * on the placeholder page, and if the pushing thread
				 * is holding a lock that is required on the pagein
				 * path (such as a truncate lock), we'll deadlock...
				 * to avoid this potential deadlock, we throw away
				 * our placeholder page before calling memory_object_data_request
				 * and force this thread to retry the vm_fault_page after
				 * we have issued the I/O.  the second time through this path
				 * we will find the page already in the cache (presumably still
				 * busy waiting for the I/O to complete) and then complete
				 * the fault w/o having to go through memory_object_data_request again
				 */
				assert(first_m != VM_PAGE_NULL);
				assert(VM_PAGE_OBJECT(first_m) == first_object);

				vm_object_lock(first_object);
				VM_PAGE_FREE(first_m);
				vm_object_paging_end(first_object);
				vm_object_unlock(first_object);

				first_m = VM_PAGE_NULL;
				force_fault_retry = TRUE;

				vm_fault_page_forced_retry++;
			}

			if (data_already_requested == TRUE) {
				orig_behavior = fault_info->behavior;
				orig_cluster_size = fault_info->cluster_size;

				fault_info->behavior = VM_BEHAVIOR_RANDOM;
				fault_info->cluster_size = PAGE_SIZE;
			}
			/*
			 * Call the memory manager to retrieve the data.
			 */
			rc = memory_object_data_request(
				pager,
				offset + object->paging_offset,
				PAGE_SIZE,
				access_required | wants_copy_flag,
				(memory_object_fault_info_t)fault_info);

			if (data_already_requested == TRUE) {
				fault_info->behavior = orig_behavior;
				fault_info->cluster_size = orig_cluster_size;
			} else {
				data_already_requested = TRUE;
			}

			DTRACE_VM2(maj_fault, int, 1, (uint64_t *), NULL);
#if TRACEFAULTPAGE
			dbgTrace(0xBEEF0013, (unsigned int) object, (unsigned int) rc); /* (TEST/DEBUG) */
#endif
			vm_object_lock(object);

			if (object->object_is_shared_cache) {
				clear_thread_rwlock_boost();
			}

data_requested:
			if (rc != KERN_SUCCESS) {
				vm_fault_cleanup(object, first_m);
				thread_interrupt_level(interruptible_state);

				return (rc == MACH_SEND_INTERRUPTED) ?
				       VM_FAULT_INTERRUPTED :
				       VM_FAULT_MEMORY_ERROR;
			} else {
				clock_sec_t     tv_sec;
				clock_usec_t    tv_usec;

				if (my_fault_type == DBG_PAGEIN_FAULT) {
					clock_get_system_microtime(&tv_sec, &tv_usec);
					current_thread()->t_page_creation_time = tv_sec;
					current_thread()->t_page_creation_count = 0;
				}
			}
			if ((interruptible != THREAD_UNINT) && (current_thread()->sched_flags & TH_SFLAG_ABORT)) {
				vm_fault_cleanup(object, first_m);
				thread_interrupt_level(interruptible_state);

				return VM_FAULT_INTERRUPTED;
			}
			if (force_fault_retry == TRUE) {
				vm_fault_cleanup(object, first_m);
				thread_interrupt_level(interruptible_state);

				return VM_FAULT_RETRY;
			}
			if (m == VM_PAGE_NULL && object->phys_contiguous) {
				/*
				 * No page here means that the object we
				 * initially looked up was "physically
				 * contiguous" (i.e. device memory).  However,
				 * with Virtual VRAM, the object might not
				 * be backed by that device memory anymore,
				 * so we're done here only if the object is
				 * still "phys_contiguous".
				 * Otherwise, if the object is no longer
				 * "phys_contiguous", we need to retry the
				 * page fault against the object's new backing
				 * store (different memory object).
				 */
phys_contig_object:
				goto done;
			}
			/*
			 * potentially a pagein fault
			 * if we make it through the state checks
			 * above, than we'll count it as such
			 */
			my_fault = my_fault_type;

			/*
			 * Retry with same object/offset, since new data may
			 * be in a different page (i.e., m is meaningless at
			 * this point).
			 */
			continue;
		}
dont_look_for_page:
		/*
		 * We get here if the object has no pager, or an existence map
		 * exists and indicates the page isn't present on the pager
		 * or we're unwiring a page.  If a pager exists, but there
		 * is no existence map, then the m->vmp_absent case above handles
		 * the ZF case when the pager can't provide the page
		 */
#if TRACEFAULTPAGE
		dbgTrace(0xBEEF0014, (unsigned int) object, (unsigned int) m);  /* (TEST/DEBUG) */
#endif
		if (object == first_object) {
			first_m = m;
		} else {
			assert(m == VM_PAGE_NULL);
		}

		next_object = object->shadow;

		if (next_object == VM_OBJECT_NULL) {
			/*
			 * we've hit the bottom of the shadown chain,
			 * fill the page in the top object with zeros.
			 */
			assert(!must_be_resident);

			if (object != first_object) {
				vm_object_paging_end(object);
				vm_object_unlock(object);

				object = first_object;
				offset = first_offset;
				vm_object_lock(object);
			}
			m = first_m;
			assert(VM_PAGE_OBJECT(m) == object);
			first_m = VM_PAGE_NULL;

			/*
			 * check for any conditions that prevent
			 * us from creating a new zero-fill page
			 * vm_fault_check will do all of the
			 * fault cleanup in the case of an error condition
			 * including resetting the thread_interrupt_level
			 */
			error = vm_fault_check(object, m, first_m, interruptible_state, (type_of_fault == NULL) ? TRUE : FALSE);

			if (error != VM_FAULT_SUCCESS) {
				return error;
			}

			if (m == VM_PAGE_NULL) {
				m = vm_page_grab_options(grab_options);

				if (m == VM_PAGE_NULL) {
					vm_fault_cleanup(object, VM_PAGE_NULL);
					thread_interrupt_level(interruptible_state);

					return VM_FAULT_MEMORY_SHORTAGE;
				}
				vm_page_insert(m, object, offset);
			}
			if (fault_info->mark_zf_absent && no_zero_fill == TRUE) {
				m->vmp_absent = TRUE;
			}

			my_fault = vm_fault_zero_page(m, no_zero_fill);

			break;
		} else {
			/*
			 * Move on to the next object.  Lock the next
			 * object before unlocking the current one.
			 */
			if ((object != first_object) || must_be_resident) {
				vm_object_paging_end(object);
			}

			offset += object->vo_shadow_offset;
			fault_info->lo_offset += object->vo_shadow_offset;
			fault_info->hi_offset += object->vo_shadow_offset;
			access_required = VM_PROT_READ;

			vm_object_lock(next_object);
			vm_object_unlock(object);

			object = next_object;
			vm_object_paging_begin(object);
		}
	}

	/*
	 *	PAGE HAS BEEN FOUND.
	 *
	 *	This page (m) is:
	 *		busy, so that we can play with it;
	 *		not absent, so that nobody else will fill it;
	 *		possibly eligible for pageout;
	 *
	 *	The top-level page (first_m) is:
	 *		VM_PAGE_NULL if the page was found in the
	 *		 top-level object;
	 *		busy, not absent, and ineligible for pageout.
	 *
	 *	The current object (object) is locked.  A paging
	 *	reference is held for the current and top-level
	 *	objects.
	 */

#if TRACEFAULTPAGE
	dbgTrace(0xBEEF0015, (unsigned int) object, (unsigned int) m);  /* (TEST/DEBUG) */
#endif
#if     EXTRA_ASSERTIONS
	assert(m->vmp_busy && !m->vmp_absent);
	assert((first_m == VM_PAGE_NULL) ||
	    (first_m->vmp_busy && !first_m->vmp_absent &&
	    !first_m->vmp_active && !first_m->vmp_inactive && !first_m->vmp_secluded));
#endif  /* EXTRA_ASSERTIONS */

	/*
	 * If the page is being written, but isn't
	 * already owned by the top-level object,
	 * we have to copy it into a new page owned
	 * by the top-level object.
	 */
	if (object != first_object) {
#if TRACEFAULTPAGE
		dbgTrace(0xBEEF0016, (unsigned int) object, (unsigned int) fault_type); /* (TEST/DEBUG) */
#endif
		if (fault_type & VM_PROT_WRITE) {
			vm_page_t copy_m;

			/*
			 * We only really need to copy if we
			 * want to write it.
			 */
			assert(!must_be_resident);

			/*
			 * If we try to collapse first_object at this
			 * point, we may deadlock when we try to get
			 * the lock on an intermediate object (since we
			 * have the bottom object locked).  We can't
			 * unlock the bottom object, because the page
			 * we found may move (by collapse) if we do.
			 *
			 * Instead, we first copy the page.  Then, when
			 * we have no more use for the bottom object,
			 * we unlock it and try to collapse.
			 *
			 * Note that we copy the page even if we didn't
			 * need to... that's the breaks.
			 */

			/*
			 * Allocate a page for the copy
			 */
			copy_m = vm_page_grab_options(grab_options);

			if (copy_m == VM_PAGE_NULL) {
				RELEASE_PAGE(m);

				vm_fault_cleanup(object, first_m);
				thread_interrupt_level(interruptible_state);

				return VM_FAULT_MEMORY_SHORTAGE;
			}

			vm_page_copy(m, copy_m);

			/*
			 * If another map is truly sharing this
			 * page with us, we have to flush all
			 * uses of the original page, since we
			 * can't distinguish those which want the
			 * original from those which need the
			 * new copy.
			 *
			 * XXXO If we know that only one map has
			 * access to this page, then we could
			 * avoid the pmap_disconnect() call.
			 */
			if (m->vmp_pmapped) {
				pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(m));
			}

			if (m->vmp_clustered) {
				VM_PAGE_COUNT_AS_PAGEIN(m);
				VM_PAGE_CONSUME_CLUSTERED(m);
			}
			assert(!m->vmp_cleaning);

			/*
			 * We no longer need the old page or object.
			 */
			RELEASE_PAGE(m);

			/*
			 * This check helps with marking the object as having a sequential pattern
			 * Normally we'll miss doing this below because this fault is about COW to
			 * the first_object i.e. bring page in from disk, push to object above but
			 * don't update the file object's sequential pattern.
			 */
			if (object->internal == FALSE) {
				vm_fault_is_sequential(object, offset, fault_info->behavior);
			}

			vm_object_paging_end(object);
			vm_object_unlock(object);

			my_fault = DBG_COW_FAULT;
			VM_STAT_INCR(cow_faults);
			DTRACE_VM2(cow_fault, int, 1, (uint64_t *), NULL);
			current_task()->cow_faults++;

			object = first_object;
			offset = first_offset;

			vm_object_lock(object);
			/*
			 * get rid of the place holder
			 * page that we soldered in earlier
			 */
			VM_PAGE_FREE(first_m);
			first_m = VM_PAGE_NULL;

			/*
			 * and replace it with the
			 * page we just copied into
			 */
			assert(copy_m->vmp_busy);
			vm_page_insert(copy_m, object, offset);
			SET_PAGE_DIRTY(copy_m, TRUE);

			m = copy_m;
			/*
			 * Now that we've gotten the copy out of the
			 * way, let's try to collapse the top object.
			 * But we have to play ugly games with
			 * paging_in_progress to do that...
			 */
			vm_object_paging_end(object);
			vm_object_collapse(object, offset, TRUE);
			vm_object_paging_begin(object);
		} else {
			*protection &= (~VM_PROT_WRITE);
		}
	}
	/*
	 * Now check whether the page needs to be pushed into the
	 * copy object.  The use of asymmetric copy on write for
	 * shared temporary objects means that we may do two copies to
	 * satisfy the fault; one above to get the page from a
	 * shadowed object, and one here to push it into the copy.
	 */
	try_failed_count = 0;

	while ((copy_object = first_object->copy) != VM_OBJECT_NULL) {
		vm_object_offset_t      copy_offset;
		vm_page_t               copy_m;

#if TRACEFAULTPAGE
		dbgTrace(0xBEEF0017, (unsigned int) copy_object, (unsigned int) fault_type);    /* (TEST/DEBUG) */
#endif
		/*
		 * If the page is being written, but hasn't been
		 * copied to the copy-object, we have to copy it there.
		 */
		if ((fault_type & VM_PROT_WRITE) == 0) {
			*protection &= ~VM_PROT_WRITE;
			break;
		}

		/*
		 * If the page was guaranteed to be resident,
		 * we must have already performed the copy.
		 */
		if (must_be_resident) {
			break;
		}

		/*
		 * Try to get the lock on the copy_object.
		 */
		if (!vm_object_lock_try(copy_object)) {
			vm_object_unlock(object);
			try_failed_count++;

			mutex_pause(try_failed_count);  /* wait a bit */
			vm_object_lock(object);

			continue;
		}
		try_failed_count = 0;

		/*
		 * Make another reference to the copy-object,
		 * to keep it from disappearing during the
		 * copy.
		 */
		vm_object_reference_locked(copy_object);

		/*
		 * Does the page exist in the copy?
		 */
		copy_offset = first_offset - copy_object->vo_shadow_offset;

		if (copy_object->vo_size <= copy_offset) {
			/*
			 * Copy object doesn't cover this page -- do nothing.
			 */
			;
		} else if ((copy_m = vm_page_lookup(copy_object, copy_offset)) != VM_PAGE_NULL) {
			/*
			 * Page currently exists in the copy object
			 */
			if (copy_m->vmp_busy) {
				/*
				 * If the page is being brought
				 * in, wait for it and then retry.
				 */
				RELEASE_PAGE(m);

				/*
				 * take an extra ref so object won't die
				 */
				vm_object_reference_locked(copy_object);
				vm_object_unlock(copy_object);
				vm_fault_cleanup(object, first_m);
				counter(c_vm_fault_page_block_backoff_kernel++);

				vm_object_lock(copy_object);
				assert(copy_object->ref_count > 0);
				VM_OBJ_RES_DECR(copy_object);
				vm_object_lock_assert_exclusive(copy_object);
				copy_object->ref_count--;
				assert(copy_object->ref_count > 0);
				copy_m = vm_page_lookup(copy_object, copy_offset);

				if (copy_m != VM_PAGE_NULL && copy_m->vmp_busy) {
					PAGE_ASSERT_WAIT(copy_m, interruptible);

					vm_object_unlock(copy_object);
					wait_result = thread_block(THREAD_CONTINUE_NULL);
					vm_object_deallocate(copy_object);

					goto backoff;
				} else {
					vm_object_unlock(copy_object);
					vm_object_deallocate(copy_object);
					thread_interrupt_level(interruptible_state);

					return VM_FAULT_RETRY;
				}
			}
		} else if (!PAGED_OUT(copy_object, copy_offset)) {
			/*
			 * If PAGED_OUT is TRUE, then the page used to exist
			 * in the copy-object, and has already been paged out.
			 * We don't need to repeat this. If PAGED_OUT is
			 * FALSE, then either we don't know (!pager_created,
			 * for example) or it hasn't been paged out.
			 * (VM_EXTERNAL_STATE_UNKNOWN||VM_EXTERNAL_STATE_ABSENT)
			 * We must copy the page to the copy object.
			 *
			 * Allocate a page for the copy
			 */
			copy_m = vm_page_alloc(copy_object, copy_offset);

			if (copy_m == VM_PAGE_NULL) {
				RELEASE_PAGE(m);

				VM_OBJ_RES_DECR(copy_object);
				vm_object_lock_assert_exclusive(copy_object);
				copy_object->ref_count--;
				assert(copy_object->ref_count > 0);

				vm_object_unlock(copy_object);
				vm_fault_cleanup(object, first_m);
				thread_interrupt_level(interruptible_state);

				return VM_FAULT_MEMORY_SHORTAGE;
			}
			/*
			 * Must copy page into copy-object.
			 */
			vm_page_copy(m, copy_m);

			/*
			 * If the old page was in use by any users
			 * of the copy-object, it must be removed
			 * from all pmaps.  (We can't know which
			 * pmaps use it.)
			 */
			if (m->vmp_pmapped) {
				pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(m));
			}

			if (m->vmp_clustered) {
				VM_PAGE_COUNT_AS_PAGEIN(m);
				VM_PAGE_CONSUME_CLUSTERED(m);
			}
			/*
			 * If there's a pager, then immediately
			 * page out this page, using the "initialize"
			 * option.  Else, we use the copy.
			 */
			if ((!copy_object->pager_ready)
			    || VM_COMPRESSOR_PAGER_STATE_GET(copy_object, copy_offset) == VM_EXTERNAL_STATE_ABSENT
			    ) {
				vm_page_lockspin_queues();
				assert(!m->vmp_cleaning);
				vm_page_activate(copy_m);
				vm_page_unlock_queues();

				SET_PAGE_DIRTY(copy_m, TRUE);
				PAGE_WAKEUP_DONE(copy_m);
			} else {
				assert(copy_m->vmp_busy == TRUE);
				assert(!m->vmp_cleaning);

				/*
				 * dirty is protected by the object lock
				 */
				SET_PAGE_DIRTY(copy_m, TRUE);

				/*
				 * The page is already ready for pageout:
				 * not on pageout queues and busy.
				 * Unlock everything except the
				 * copy_object itself.
				 */
				vm_object_unlock(object);

				/*
				 * Write the page to the copy-object,
				 * flushing it from the kernel.
				 */
				vm_pageout_initialize_page(copy_m);

				/*
				 * Since the pageout may have
				 * temporarily dropped the
				 * copy_object's lock, we
				 * check whether we'll have
				 * to deallocate the hard way.
				 */
				if ((copy_object->shadow != object) || (copy_object->ref_count == 1)) {
					vm_object_unlock(copy_object);
					vm_object_deallocate(copy_object);
					vm_object_lock(object);

					continue;
				}
				/*
				 * Pick back up the old object's
				 * lock.  [It is safe to do so,
				 * since it must be deeper in the
				 * object tree.]
				 */
				vm_object_lock(object);
			}

			/*
			 * Because we're pushing a page upward
			 * in the object tree, we must restart
			 * any faults that are waiting here.
			 * [Note that this is an expansion of
			 * PAGE_WAKEUP that uses the THREAD_RESTART
			 * wait result].  Can't turn off the page's
			 * busy bit because we're not done with it.
			 */
			if (m->vmp_wanted) {
				m->vmp_wanted = FALSE;
				thread_wakeup_with_result((event_t) m, THREAD_RESTART);
			}
		}
		/*
		 * The reference count on copy_object must be
		 * at least 2: one for our extra reference,
		 * and at least one from the outside world
		 * (we checked that when we last locked
		 * copy_object).
		 */
		vm_object_lock_assert_exclusive(copy_object);
		copy_object->ref_count--;
		assert(copy_object->ref_count > 0);

		VM_OBJ_RES_DECR(copy_object);
		vm_object_unlock(copy_object);

		break;
	}

done:
	*result_page = m;
	*top_page = first_m;

	if (m != VM_PAGE_NULL) {
		assert(VM_PAGE_OBJECT(m) == object);

		retval = VM_FAULT_SUCCESS;

		if (my_fault == DBG_PAGEIN_FAULT) {
			VM_PAGE_COUNT_AS_PAGEIN(m);

			if (object->internal) {
				my_fault = DBG_PAGEIND_FAULT;
			} else {
				my_fault = DBG_PAGEINV_FAULT;
			}

			/*
			 * evaluate access pattern and update state
			 * vm_fault_deactivate_behind depends on the
			 * state being up to date
			 */
			vm_fault_is_sequential(object, offset, fault_info->behavior);
			vm_fault_deactivate_behind(object, offset, fault_info->behavior);
		} else if (type_of_fault == NULL && my_fault == DBG_CACHE_HIT_FAULT) {
			/*
			 * we weren't called from vm_fault, so handle the
			 * accounting here for hits in the cache
			 */
			if (m->vmp_clustered) {
				VM_PAGE_COUNT_AS_PAGEIN(m);
				VM_PAGE_CONSUME_CLUSTERED(m);
			}
			vm_fault_is_sequential(object, offset, fault_info->behavior);
			vm_fault_deactivate_behind(object, offset, fault_info->behavior);
		} else if (my_fault == DBG_COMPRESSOR_FAULT || my_fault == DBG_COMPRESSOR_SWAPIN_FAULT) {
			VM_STAT_DECOMPRESSIONS();
		}
		if (type_of_fault) {
			*type_of_fault = my_fault;
		}
	} else {
		retval = VM_FAULT_SUCCESS_NO_VM_PAGE;
		assert(first_m == VM_PAGE_NULL);
		assert(object == first_object);
	}

	thread_interrupt_level(interruptible_state);

#if TRACEFAULTPAGE
	dbgTrace(0xBEEF001A, (unsigned int) VM_FAULT_SUCCESS, 0);       /* (TEST/DEBUG) */
#endif
	return retval;

backoff:
	thread_interrupt_level(interruptible_state);

	if (wait_result == THREAD_INTERRUPTED) {
		return VM_FAULT_INTERRUPTED;
	}
	return VM_FAULT_RETRY;

#undef  RELEASE_PAGE
}



/*
 * CODE SIGNING:
 * When soft faulting a page, we have to validate the page if:
 * 1. the page is being mapped in user space
 * 2. the page hasn't already been found to be "tainted"
 * 3. the page belongs to a code-signed object
 * 4. the page has not been validated yet or has been mapped for write.
 */
#define VM_FAULT_NEED_CS_VALIDATION(pmap, page, page_obj)               \
	((pmap) != kernel_pmap /*1*/ &&                                 \
	 !(page)->vmp_cs_tainted /*2*/ &&                                       \
	 (page_obj)->code_signed /*3*/ &&                                       \
	 (!(page)->vmp_cs_validated || (page)->vmp_wpmapped /*4*/ ))


/*
 * page queue lock must NOT be held
 * m->vmp_object must be locked
 *
 * NOTE: m->vmp_object could be locked "shared" only if we are called
 * from vm_fault() as part of a soft fault.  If so, we must be
 * careful not to modify the VM object in any way that is not
 * legal under a shared lock...
 */
extern int panic_on_cs_killed;
extern int proc_selfpid(void);
extern char *proc_name_address(void *p);
unsigned long cs_enter_tainted_rejected = 0;
unsigned long cs_enter_tainted_accepted = 0;
kern_return_t
vm_fault_enter(vm_page_t m,
    pmap_t pmap,
    vm_map_offset_t vaddr,
    vm_prot_t prot,
    vm_prot_t caller_prot,
    boolean_t wired,
    boolean_t change_wiring,
    vm_tag_t  wire_tag,
    vm_object_fault_info_t fault_info,
    boolean_t *need_retry,
    int *type_of_fault)
{
	kern_return_t   kr, pe_result;
	boolean_t       previously_pmapped = m->vmp_pmapped;
	boolean_t       must_disconnect = 0;
	boolean_t       map_is_switched, map_is_switch_protected;
	boolean_t       cs_violation;
	int             cs_enforcement_enabled;
	vm_prot_t       fault_type;
	vm_object_t     object;
	boolean_t       no_cache = fault_info->no_cache;
	boolean_t       cs_bypass = fault_info->cs_bypass;
	int             pmap_options = fault_info->pmap_options;

	fault_type = change_wiring ? VM_PROT_NONE : caller_prot;
	object = VM_PAGE_OBJECT(m);

	vm_object_lock_assert_held(object);

#if KASAN
	if (pmap == kernel_pmap) {
		kasan_notify_address(vaddr, PAGE_SIZE);
	}
#endif

	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_NOTOWNED);

	if (VM_PAGE_GET_PHYS_PAGE(m) == vm_page_guard_addr) {
		assert(m->vmp_fictitious);
		return KERN_SUCCESS;
	}

	if (*type_of_fault == DBG_ZERO_FILL_FAULT) {
		vm_object_lock_assert_exclusive(object);
	} else if ((fault_type & VM_PROT_WRITE) == 0 &&
	    (!m->vmp_wpmapped
#if VM_OBJECT_ACCESS_TRACKING
	    || object->access_tracking
#endif /* VM_OBJECT_ACCESS_TRACKING */
	    )) {
		/*
		 * This is not a "write" fault, so we
		 * might not have taken the object lock
		 * exclusively and we might not be able
		 * to update the "wpmapped" bit in
		 * vm_fault_enter().
		 * Let's just grant read access to
		 * the page for now and we'll
		 * soft-fault again if we need write
		 * access later...
		 */

		/* This had better not be a JIT page. */
		if (!pmap_has_prot_policy(prot)) {
			prot &= ~VM_PROT_WRITE;
		} else {
			assert(cs_bypass);
		}
	}
	if (m->vmp_pmapped == FALSE) {
		if (m->vmp_clustered) {
			if (*type_of_fault == DBG_CACHE_HIT_FAULT) {
				/*
				 * found it in the cache, but this
				 * is the first fault-in of the page (m->vmp_pmapped == FALSE)
				 * so it must have come in as part of
				 * a cluster... account 1 pagein against it
				 */
				if (object->internal) {
					*type_of_fault = DBG_PAGEIND_FAULT;
				} else {
					*type_of_fault = DBG_PAGEINV_FAULT;
				}

				VM_PAGE_COUNT_AS_PAGEIN(m);
			}
			VM_PAGE_CONSUME_CLUSTERED(m);
		}
	}

	if (*type_of_fault != DBG_COW_FAULT) {
		DTRACE_VM2(as_fault, int, 1, (uint64_t *), NULL);

		if (pmap == kernel_pmap) {
			DTRACE_VM2(kernel_asflt, int, 1, (uint64_t *), NULL);
		}
	}

	/* Validate code signature if necessary. */
	if (!cs_bypass &&
	    VM_FAULT_NEED_CS_VALIDATION(pmap, m, object)) {
		vm_object_lock_assert_exclusive(object);

		if (m->vmp_cs_validated) {
			vm_cs_revalidates++;
		}

		/* VM map is locked, so 1 ref will remain on VM object -
		 * so no harm if vm_page_validate_cs drops the object lock */

#if PMAP_CS
		if (fault_info->pmap_cs_associated &&
		    pmap_cs_enforced(pmap) &&
		    !m->vmp_cs_validated &&
		    !m->vmp_cs_tainted &&
		    !m->vmp_cs_nx &&
		    (prot & VM_PROT_EXECUTE) &&
		    (caller_prot & VM_PROT_EXECUTE)) {
			/*
			 * With pmap_cs, the pmap layer will validate the
			 * code signature for any executable pmap mapping.
			 * No need for us to validate this page too:
			 * in pmap_cs we trust...
			 */
			vm_cs_defer_to_pmap_cs++;
		} else {
			vm_cs_defer_to_pmap_cs_not++;
			vm_page_validate_cs(m);
		}
#else /* PMAP_CS */
		vm_page_validate_cs(m);
#endif /* PMAP_CS */
	}

#define page_immutable(m, prot) ((m)->vmp_cs_validated /*&& ((prot) & VM_PROT_EXECUTE)*/ )
#define page_nx(m) ((m)->vmp_cs_nx)

	map_is_switched = ((pmap != vm_map_pmap(current_task()->map)) &&
	    (pmap == vm_map_pmap(current_thread()->map)));
	map_is_switch_protected = current_thread()->map->switch_protect;

	/* If the map is switched, and is switch-protected, we must protect
	 * some pages from being write-faulted: immutable pages because by
	 * definition they may not be written, and executable pages because that
	 * would provide a way to inject unsigned code.
	 * If the page is immutable, we can simply return. However, we can't
	 * immediately determine whether a page is executable anywhere. But,
	 * we can disconnect it everywhere and remove the executable protection
	 * from the current map. We do that below right before we do the
	 * PMAP_ENTER.
	 */
	cs_enforcement_enabled = cs_process_enforcement(NULL);

	if (cs_enforcement_enabled && map_is_switched &&
	    map_is_switch_protected && page_immutable(m, prot) &&
	    (prot & VM_PROT_WRITE)) {
		return KERN_CODESIGN_ERROR;
	}

	if (cs_enforcement_enabled && page_nx(m) && (prot & VM_PROT_EXECUTE)) {
		if (cs_debug) {
			printf("page marked to be NX, not letting it be mapped EXEC\n");
		}
		return KERN_CODESIGN_ERROR;
	}

	/* A page could be tainted, or pose a risk of being tainted later.
	 * Check whether the receiving process wants it, and make it feel
	 * the consequences (that hapens in cs_invalid_page()).
	 * For CS Enforcement, two other conditions will
	 * cause that page to be tainted as well:
	 * - pmapping an unsigned page executable - this means unsigned code;
	 * - writeable mapping of a validated page - the content of that page
	 *   can be changed without the kernel noticing, therefore unsigned
	 *   code can be created
	 */
	if (cs_bypass) {
		/* code-signing is bypassed */
		cs_violation = FALSE;
	} else if (m->vmp_cs_tainted) {
		/* tainted page */
		cs_violation = TRUE;
	} else if (!cs_enforcement_enabled) {
		/* no further code-signing enforcement */
		cs_violation = FALSE;
	} else if (page_immutable(m, prot) &&
	    ((prot & VM_PROT_WRITE) ||
	    m->vmp_wpmapped)) {
		/*
		 * The page should be immutable, but is in danger of being
		 * modified.
		 * This is the case where we want policy from the code
		 * directory - is the page immutable or not? For now we have
		 * to assume that code pages will be immutable, data pages not.
		 * We'll assume a page is a code page if it has a code directory
		 * and we fault for execution.
		 * That is good enough since if we faulted the code page for
		 * writing in another map before, it is wpmapped; if we fault
		 * it for writing in this map later it will also be faulted for
		 * executing at the same time; and if we fault for writing in
		 * another map later, we will disconnect it from this pmap so
		 * we'll notice the change.
		 */
		cs_violation = TRUE;
	} else if (!m->vmp_cs_validated &&
	    (prot & VM_PROT_EXECUTE)
#if PMAP_CS
	    /*
	     * Executable pages will be validated by pmap_cs;
	     * in pmap_cs we trust...
	     * If pmap_cs is turned off, this is a code-signing
	     * violation.
	     */
	    && !(pmap_cs_enforced(pmap))
#endif /* PMAP_CS */
	    ) {
		cs_violation = TRUE;
	} else {
		cs_violation = FALSE;
	}

	if (cs_violation) {
		/* We will have a tainted page. Have to handle the special case
		 * of a switched map now. If the map is not switched, standard
		 * procedure applies - call cs_invalid_page().
		 * If the map is switched, the real owner is invalid already.
		 * There is no point in invalidating the switching process since
		 * it will not be executing from the map. So we don't call
		 * cs_invalid_page() in that case. */
		boolean_t reject_page, cs_killed;
		if (map_is_switched) {
			assert(pmap == vm_map_pmap(current_thread()->map));
			assert(!(prot & VM_PROT_WRITE) || (map_is_switch_protected == FALSE));
			reject_page = FALSE;
		} else {
			if (cs_debug > 5) {
				printf("vm_fault: signed: %s validate: %s tainted: %s wpmapped: %s prot: 0x%x\n",
				    object->code_signed ? "yes" : "no",
				    m->vmp_cs_validated ? "yes" : "no",
				    m->vmp_cs_tainted ? "yes" : "no",
				    m->vmp_wpmapped ? "yes" : "no",
				    (int)prot);
			}
			reject_page = cs_invalid_page((addr64_t) vaddr, &cs_killed);
		}

		if (reject_page) {
			/* reject the invalid page: abort the page fault */
			int                     pid;
			const char              *procname;
			task_t                  task;
			vm_object_t             file_object, shadow;
			vm_object_offset_t      file_offset;
			char                    *pathname, *filename;
			vm_size_t               pathname_len, filename_len;
			boolean_t               truncated_path;
#define __PATH_MAX 1024
			struct timespec         mtime, cs_mtime;
			int                     shadow_depth;
			os_reason_t             codesigning_exit_reason = OS_REASON_NULL;

			kr = KERN_CODESIGN_ERROR;
			cs_enter_tainted_rejected++;

			/* get process name and pid */
			procname = "?";
			task = current_task();
			pid = proc_selfpid();
			if (task->bsd_info != NULL) {
				procname = proc_name_address(task->bsd_info);
			}

			/* get file's VM object */
			file_object = object;
			file_offset = m->vmp_offset;
			for (shadow = file_object->shadow,
			    shadow_depth = 0;
			    shadow != VM_OBJECT_NULL;
			    shadow = file_object->shadow,
			    shadow_depth++) {
				vm_object_lock_shared(shadow);
				if (file_object != object) {
					vm_object_unlock(file_object);
				}
				file_offset += file_object->vo_shadow_offset;
				file_object = shadow;
			}

			mtime.tv_sec = 0;
			mtime.tv_nsec = 0;
			cs_mtime.tv_sec = 0;
			cs_mtime.tv_nsec = 0;

			/* get file's pathname and/or filename */
			pathname = NULL;
			filename = NULL;
			pathname_len = 0;
			filename_len = 0;
			truncated_path = FALSE;
			/* no pager -> no file -> no pathname, use "<nil>" in that case */
			if (file_object->pager != NULL) {
				pathname = (char *)kalloc(__PATH_MAX * 2);
				if (pathname) {
					pathname[0] = '\0';
					pathname_len = __PATH_MAX;
					filename = pathname + pathname_len;
					filename_len = __PATH_MAX;

					if (vnode_pager_get_object_name(file_object->pager,
					    pathname,
					    pathname_len,
					    filename,
					    filename_len,
					    &truncated_path) == KERN_SUCCESS) {
						/* safety first... */
						pathname[__PATH_MAX - 1] = '\0';
						filename[__PATH_MAX - 1] = '\0';

						vnode_pager_get_object_mtime(file_object->pager,
						    &mtime,
						    &cs_mtime);
					} else {
						kfree(pathname, __PATH_MAX * 2);
						pathname = NULL;
						filename = NULL;
						pathname_len = 0;
						filename_len = 0;
						truncated_path = FALSE;
					}
				}
			}
			printf("CODE SIGNING: process %d[%s]: "
			    "rejecting invalid page at address 0x%llx "
			    "from offset 0x%llx in file \"%s%s%s\" "
			    "(cs_mtime:%lu.%ld %s mtime:%lu.%ld) "
			    "(signed:%d validated:%d tainted:%d nx:%d "
			    "wpmapped:%d dirty:%d depth:%d)\n",
			    pid, procname, (addr64_t) vaddr,
			    file_offset,
			    (pathname ? pathname : "<nil>"),
			    (truncated_path ? "/.../" : ""),
			    (truncated_path ? filename : ""),
			    cs_mtime.tv_sec, cs_mtime.tv_nsec,
			    ((cs_mtime.tv_sec == mtime.tv_sec &&
			    cs_mtime.tv_nsec == mtime.tv_nsec)
			    ? "=="
			    : "!="),
			    mtime.tv_sec, mtime.tv_nsec,
			    object->code_signed,
			    m->vmp_cs_validated,
			    m->vmp_cs_tainted,
			    m->vmp_cs_nx,
			    m->vmp_wpmapped,
			    m->vmp_dirty,
			    shadow_depth);

			/*
			 * We currently only generate an exit reason if cs_invalid_page directly killed a process. If cs_invalid_page
			 * did not kill the process (more the case on desktop), vm_fault_enter will not satisfy the fault and whether the
			 * process dies is dependent on whether there is a signal handler registered for SIGSEGV and how that handler
			 * will deal with the segmentation fault.
			 */
			if (cs_killed) {
				KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXITREASON_CREATE) | DBG_FUNC_NONE,
				    pid, OS_REASON_CODESIGNING, CODESIGNING_EXIT_REASON_INVALID_PAGE, 0, 0);

				codesigning_exit_reason = os_reason_create(OS_REASON_CODESIGNING, CODESIGNING_EXIT_REASON_INVALID_PAGE);
				if (codesigning_exit_reason == NULL) {
					printf("vm_fault_enter: failed to allocate codesigning exit reason\n");
				} else {
					mach_vm_address_t data_addr = 0;
					struct codesigning_exit_reason_info *ceri = NULL;
					uint32_t reason_buffer_size_estimate = kcdata_estimate_required_buffer_size(1, sizeof(*ceri));

					if (os_reason_alloc_buffer_noblock(codesigning_exit_reason, reason_buffer_size_estimate)) {
						printf("vm_fault_enter: failed to allocate buffer for codesigning exit reason\n");
					} else {
						if (KERN_SUCCESS == kcdata_get_memory_addr(&codesigning_exit_reason->osr_kcd_descriptor,
						    EXIT_REASON_CODESIGNING_INFO, sizeof(*ceri), &data_addr)) {
							ceri = (struct codesigning_exit_reason_info *)data_addr;
							static_assert(__PATH_MAX == sizeof(ceri->ceri_pathname));

							ceri->ceri_virt_addr = vaddr;
							ceri->ceri_file_offset = file_offset;
							if (pathname) {
								strncpy((char *)&ceri->ceri_pathname, pathname, sizeof(ceri->ceri_pathname));
							} else {
								ceri->ceri_pathname[0] = '\0';
							}
							if (filename) {
								strncpy((char *)&ceri->ceri_filename, filename, sizeof(ceri->ceri_filename));
							} else {
								ceri->ceri_filename[0] = '\0';
							}
							ceri->ceri_path_truncated = (truncated_path);
							ceri->ceri_codesig_modtime_secs = cs_mtime.tv_sec;
							ceri->ceri_codesig_modtime_nsecs = cs_mtime.tv_nsec;
							ceri->ceri_page_modtime_secs = mtime.tv_sec;
							ceri->ceri_page_modtime_nsecs = mtime.tv_nsec;
							ceri->ceri_object_codesigned = (object->code_signed);
							ceri->ceri_page_codesig_validated = (m->vmp_cs_validated);
							ceri->ceri_page_codesig_tainted = (m->vmp_cs_tainted);
							ceri->ceri_page_codesig_nx = (m->vmp_cs_nx);
							ceri->ceri_page_wpmapped = (m->vmp_wpmapped);
							ceri->ceri_page_slid = 0;
							ceri->ceri_page_dirty = (m->vmp_dirty);
							ceri->ceri_page_shadow_depth = shadow_depth;
						} else {
#if DEBUG || DEVELOPMENT
							panic("vm_fault_enter: failed to allocate kcdata for codesigning exit reason");
#else
							printf("vm_fault_enter: failed to allocate kcdata for codesigning exit reason\n");
#endif /* DEBUG || DEVELOPMENT */
							/* Free the buffer */
							os_reason_alloc_buffer_noblock(codesigning_exit_reason, 0);
						}
					}
				}

				set_thread_exit_reason(current_thread(), codesigning_exit_reason, FALSE);
			}
			if (panic_on_cs_killed &&
			    object->object_is_shared_cache) {
				char *tainted_contents;
				vm_map_offset_t src_vaddr;
				src_vaddr = (vm_map_offset_t) phystokv((pmap_paddr_t)VM_PAGE_GET_PHYS_PAGE(m) << PAGE_SHIFT);
				tainted_contents = kalloc(PAGE_SIZE);
				bcopy((const char *)src_vaddr, tainted_contents, PAGE_SIZE);
				printf("CODE SIGNING: tainted page %p phys 0x%x phystokv 0x%llx copied to %p\n", m, VM_PAGE_GET_PHYS_PAGE(m), (uint64_t)src_vaddr, tainted_contents);
				panic("CODE SIGNING: process %d[%s]: "
				    "rejecting invalid page (phys#0x%x) at address 0x%llx "
				    "from offset 0x%llx in file \"%s%s%s\" "
				    "(cs_mtime:%lu.%ld %s mtime:%lu.%ld) "
				    "(signed:%d validated:%d tainted:%d nx:%d"
				    "wpmapped:%d dirty:%d depth:%d)\n",
				    pid, procname,
				    VM_PAGE_GET_PHYS_PAGE(m),
				    (addr64_t) vaddr,
				    file_offset,
				    (pathname ? pathname : "<nil>"),
				    (truncated_path ? "/.../" : ""),
				    (truncated_path ? filename : ""),
				    cs_mtime.tv_sec, cs_mtime.tv_nsec,
				    ((cs_mtime.tv_sec == mtime.tv_sec &&
				    cs_mtime.tv_nsec == mtime.tv_nsec)
				    ? "=="
				    : "!="),
				    mtime.tv_sec, mtime.tv_nsec,
				    object->code_signed,
				    m->vmp_cs_validated,
				    m->vmp_cs_tainted,
				    m->vmp_cs_nx,
				    m->vmp_wpmapped,
				    m->vmp_dirty,
				    shadow_depth);
			}

			if (file_object != object) {
				vm_object_unlock(file_object);
			}
			if (pathname_len != 0) {
				kfree(pathname, __PATH_MAX * 2);
				pathname = NULL;
				filename = NULL;
			}
		} else {
			/* proceed with the invalid page */
			kr = KERN_SUCCESS;
			if (!m->vmp_cs_validated &&
			    !object->code_signed) {
				/*
				 * This page has not been (fully) validated but
				 * does not belong to a code-signed object
				 * so it should not be forcefully considered
				 * as tainted.
				 * We're just concerned about it here because
				 * we've been asked to "execute" it but that
				 * does not mean that it should cause other
				 * accesses to fail.
				 * This happens when a debugger sets a
				 * breakpoint and we then execute code in
				 * that page.  Marking the page as "tainted"
				 * would cause any inspection tool ("leaks",
				 * "vmmap", "CrashReporter", ...) to get killed
				 * due to code-signing violation on that page,
				 * even though they're just reading it and not
				 * executing from it.
				 */
			} else {
				/*
				 * Page might have been tainted before or not;
				 * now it definitively is. If the page wasn't
				 * tainted, we must disconnect it from all
				 * pmaps later, to force existing mappings
				 * through that code path for re-consideration
				 * of the validity of that page.
				 */
				must_disconnect = !m->vmp_cs_tainted;
				m->vmp_cs_tainted = TRUE;
			}
			cs_enter_tainted_accepted++;
		}
		if (kr != KERN_SUCCESS) {
			if (cs_debug) {
				printf("CODESIGNING: vm_fault_enter(0x%llx): "
				    "*** INVALID PAGE ***\n",
				    (long long)vaddr);
			}
#if !SECURE_KERNEL
			if (cs_enforcement_panic) {
				panic("CODESIGNING: panicking on invalid page\n");
			}
#endif
		}
	} else {
		/* proceed with the valid page */
		kr = KERN_SUCCESS;
	}

	boolean_t       page_queues_locked = FALSE;
#define __VM_PAGE_LOCKSPIN_QUEUES_IF_NEEDED()   \
MACRO_BEGIN                                     \
	if (! page_queues_locked) {             \
	        page_queues_locked = TRUE;      \
	        vm_page_lockspin_queues();      \
	}                                       \
MACRO_END
#define __VM_PAGE_UNLOCK_QUEUES_IF_NEEDED()     \
MACRO_BEGIN                                     \
	if (page_queues_locked) {               \
	        page_queues_locked = FALSE;     \
	        vm_page_unlock_queues();        \
	}                                       \
MACRO_END

	/*
	 * Hold queues lock to manipulate
	 * the page queues.  Change wiring
	 * case is obvious.
	 */
	assert((m->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR) || object != compressor_object);

#if CONFIG_BACKGROUND_QUEUE
	vm_page_update_background_state(m);
#endif
	if (m->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR) {
		/*
		 * Compressor pages are neither wired
		 * nor pageable and should never change.
		 */
		assert(object == compressor_object);
	} else if (change_wiring) {
		__VM_PAGE_LOCKSPIN_QUEUES_IF_NEEDED();

		if (wired) {
			if (kr == KERN_SUCCESS) {
				vm_page_wire(m, wire_tag, TRUE);
			}
		} else {
			vm_page_unwire(m, TRUE);
		}
		/* we keep the page queues lock, if we need it later */
	} else {
		if (object->internal == TRUE) {
			/*
			 * don't allow anonymous pages on
			 * the speculative queues
			 */
			no_cache = FALSE;
		}
		if (kr != KERN_SUCCESS) {
			__VM_PAGE_LOCKSPIN_QUEUES_IF_NEEDED();
			vm_page_deactivate(m);
			/* we keep the page queues lock, if we need it later */
		} else if (((m->vmp_q_state == VM_PAGE_NOT_ON_Q) ||
		    (m->vmp_q_state == VM_PAGE_ON_SPECULATIVE_Q) ||
		    (m->vmp_q_state == VM_PAGE_ON_INACTIVE_CLEANED_Q) ||
		    ((m->vmp_q_state != VM_PAGE_ON_THROTTLED_Q) && no_cache)) &&
		    !VM_PAGE_WIRED(m)) {
			if (vm_page_local_q &&
			    (*type_of_fault == DBG_COW_FAULT ||
			    *type_of_fault == DBG_ZERO_FILL_FAULT)) {
				struct vpl      *lq;
				uint32_t        lid;

				assert(m->vmp_q_state == VM_PAGE_NOT_ON_Q);

				__VM_PAGE_UNLOCK_QUEUES_IF_NEEDED();
				vm_object_lock_assert_exclusive(object);

				/*
				 * we got a local queue to stuff this
				 * new page on...
				 * its safe to manipulate local and
				 * local_id at this point since we're
				 * behind an exclusive object lock and
				 * the page is not on any global queue.
				 *
				 * we'll use the current cpu number to
				 * select the queue note that we don't
				 * need to disable preemption... we're
				 * going to be behind the local queue's
				 * lock to do the real work
				 */
				lid = cpu_number();

				lq = &vm_page_local_q[lid].vpl_un.vpl;

				VPL_LOCK(&lq->vpl_lock);

				vm_page_check_pageable_safe(m);
				vm_page_queue_enter(&lq->vpl_queue, m, vmp_pageq);
				m->vmp_q_state = VM_PAGE_ON_ACTIVE_LOCAL_Q;
				m->vmp_local_id = lid;
				lq->vpl_count++;

				if (object->internal) {
					lq->vpl_internal_count++;
				} else {
					lq->vpl_external_count++;
				}

				VPL_UNLOCK(&lq->vpl_lock);

				if (lq->vpl_count > vm_page_local_q_soft_limit) {
					/*
					 * we're beyond the soft limit
					 * for the local queue
					 * vm_page_reactivate_local will
					 * 'try' to take the global page
					 * queue lock... if it can't
					 * that's ok... we'll let the
					 * queue continue to grow up
					 * to the hard limit... at that
					 * point we'll wait for the
					 * lock... once we've got the
					 * lock, we'll transfer all of
					 * the pages from the local
					 * queue to the global active
					 * queue
					 */
					vm_page_reactivate_local(lid, FALSE, FALSE);
				}
			} else {
				__VM_PAGE_LOCKSPIN_QUEUES_IF_NEEDED();

				/*
				 * test again now that we hold the
				 * page queue lock
				 */
				if (!VM_PAGE_WIRED(m)) {
					if (m->vmp_q_state == VM_PAGE_ON_INACTIVE_CLEANED_Q) {
						vm_page_queues_remove(m, FALSE);

						VM_PAGEOUT_DEBUG(vm_pageout_cleaned_reactivated, 1);
						VM_PAGEOUT_DEBUG(vm_pageout_cleaned_fault_reactivated, 1);
					}

					if (!VM_PAGE_ACTIVE_OR_INACTIVE(m) ||
					    no_cache) {
						/*
						 * If this is a no_cache mapping
						 * and the page has never been
						 * mapped before or was
						 * previously a no_cache page,
						 * then we want to leave pages
						 * in the speculative state so
						 * that they can be readily
						 * recycled if free memory runs
						 * low.  Otherwise the page is
						 * activated as normal.
						 */

						if (no_cache &&
						    (!previously_pmapped ||
						    m->vmp_no_cache)) {
							m->vmp_no_cache = TRUE;

							if (m->vmp_q_state != VM_PAGE_ON_SPECULATIVE_Q) {
								vm_page_speculate(m, FALSE);
							}
						} else if (!VM_PAGE_ACTIVE_OR_INACTIVE(m)) {
							vm_page_activate(m);
						}
					}
				}
				/* we keep the page queues lock, if we need it later */
			}
		}
	}
	/* we're done with the page queues lock, if we ever took it */
	__VM_PAGE_UNLOCK_QUEUES_IF_NEEDED();


	/* If we have a KERN_SUCCESS from the previous checks, we either have
	 * a good page, or a tainted page that has been accepted by the process.
	 * In both cases the page will be entered into the pmap.
	 * If the page is writeable, we need to disconnect it from other pmaps
	 * now so those processes can take note.
	 */
	if (kr == KERN_SUCCESS) {
		/*
		 * NOTE: we may only hold the vm_object lock SHARED
		 * at this point, so we need the phys_page lock to
		 * properly serialize updating the pmapped and
		 * xpmapped bits
		 */
		if ((prot & VM_PROT_EXECUTE) && !m->vmp_xpmapped) {
			ppnum_t phys_page = VM_PAGE_GET_PHYS_PAGE(m);

			pmap_lock_phys_page(phys_page);
			/*
			 * go ahead and take the opportunity
			 * to set 'pmapped' here so that we don't
			 * need to grab this lock a 2nd time
			 * just below
			 */
			m->vmp_pmapped = TRUE;

			if (!m->vmp_xpmapped) {
				m->vmp_xpmapped = TRUE;

				pmap_unlock_phys_page(phys_page);

				if (!object->internal) {
					OSAddAtomic(1, &vm_page_xpmapped_external_count);
				}

#if defined(__arm__) || defined(__arm64__)
				pmap_sync_page_data_phys(phys_page);
#else
				if (object->internal &&
				    object->pager != NULL) {
					/*
					 * This page could have been
					 * uncompressed by the
					 * compressor pager and its
					 * contents might be only in
					 * the data cache.
					 * Since it's being mapped for
					 * "execute" for the fist time,
					 * make sure the icache is in
					 * sync.
					 */
					assert(VM_CONFIG_COMPRESSOR_IS_PRESENT);
					pmap_sync_page_data_phys(phys_page);
				}
#endif
			} else {
				pmap_unlock_phys_page(phys_page);
			}
		} else {
			if (m->vmp_pmapped == FALSE) {
				ppnum_t phys_page = VM_PAGE_GET_PHYS_PAGE(m);

				pmap_lock_phys_page(phys_page);
				m->vmp_pmapped = TRUE;
				pmap_unlock_phys_page(phys_page);
			}
		}

		if (fault_type & VM_PROT_WRITE) {
			if (m->vmp_wpmapped == FALSE) {
				vm_object_lock_assert_exclusive(object);
				if (!object->internal && object->pager) {
					task_update_logical_writes(current_task(), PAGE_SIZE, TASK_WRITE_DEFERRED, vnode_pager_lookup_vnode(object->pager));
				}
				m->vmp_wpmapped = TRUE;
			}
			if (must_disconnect) {
				/*
				 * We can only get here
				 * because of the CSE logic
				 */
				assert(cs_enforcement_enabled);
				pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(m));
				/*
				 * If we are faulting for a write, we can clear
				 * the execute bit - that will ensure the page is
				 * checked again before being executable, which
				 * protects against a map switch.
				 * This only happens the first time the page
				 * gets tainted, so we won't get stuck here
				 * to make an already writeable page executable.
				 */
				if (!cs_bypass) {
					assert(!pmap_has_prot_policy(prot));
					prot &= ~VM_PROT_EXECUTE;
				}
			}
		}
		assert(VM_PAGE_OBJECT(m) == object);

#if VM_OBJECT_ACCESS_TRACKING
		if (object->access_tracking) {
			DTRACE_VM2(access_tracking, vm_map_offset_t, vaddr, int, fault_type);
			if (fault_type & VM_PROT_WRITE) {
				object->access_tracking_writes++;
				vm_object_access_tracking_writes++;
			} else {
				object->access_tracking_reads++;
				vm_object_access_tracking_reads++;
			}
		}
#endif /* VM_OBJECT_ACCESS_TRACKING */


#if PMAP_CS
pmap_enter_retry:
#endif
		/* Prevent a deadlock by not
		 * holding the object lock if we need to wait for a page in
		 * pmap_enter() - <rdar://problem/7138958> */
		PMAP_ENTER_OPTIONS(pmap, vaddr, m, prot, fault_type, 0,
		    wired,
		    pmap_options | PMAP_OPTIONS_NOWAIT,
		    pe_result);
#if PMAP_CS
		/*
		 * Retry without execute permission if we encountered a codesigning
		 * failure on a non-execute fault.  This allows applications which
		 * don't actually need to execute code to still map it for read access.
		 */
		if ((pe_result == KERN_CODESIGN_ERROR) && pmap_cs_enforced(pmap) &&
		    (prot & VM_PROT_EXECUTE) && !(caller_prot & VM_PROT_EXECUTE)) {
			prot &= ~VM_PROT_EXECUTE;
			goto pmap_enter_retry;
		}
#endif
#if __x86_64__
		if (pe_result == KERN_INVALID_ARGUMENT &&
		    pmap == PMAP_NULL &&
		    wired) {
			/*
			 * Wiring a page in a pmap-less VM map:
			 * VMware's "vmmon" kernel extension does this
			 * to grab pages.
			 * Let it proceed even though the PMAP_ENTER() failed.
			 */
			pe_result = KERN_SUCCESS;
		}
#endif /* __x86_64__ */

		if (pe_result == KERN_RESOURCE_SHORTAGE) {
			if (need_retry) {
				/*
				 * this will be non-null in the case where we hold the lock
				 * on the top-object in this chain... we can't just drop
				 * the lock on the object we're inserting the page into
				 * and recall the PMAP_ENTER since we can still cause
				 * a deadlock if one of the critical paths tries to
				 * acquire the lock on the top-object and we're blocked
				 * in PMAP_ENTER waiting for memory... our only recourse
				 * is to deal with it at a higher level where we can
				 * drop both locks.
				 */
				*need_retry = TRUE;
				vm_pmap_enter_retried++;
				goto after_the_pmap_enter;
			}
			/* The nonblocking version of pmap_enter did not succeed.
			 * and we don't need to drop other locks and retry
			 * at the level above us, so
			 * use the blocking version instead. Requires marking
			 * the page busy and unlocking the object */
			boolean_t was_busy = m->vmp_busy;

			vm_object_lock_assert_exclusive(object);

			m->vmp_busy = TRUE;
			vm_object_unlock(object);

			PMAP_ENTER_OPTIONS(pmap, vaddr, m, prot, fault_type,
			    0, wired,
			    pmap_options, pe_result);

			assert(VM_PAGE_OBJECT(m) == object);

			/* Take the object lock again. */
			vm_object_lock(object);

			/* If the page was busy, someone else will wake it up.
			 * Otherwise, we have to do it now. */
			assert(m->vmp_busy);
			if (!was_busy) {
				PAGE_WAKEUP_DONE(m);
			}
			vm_pmap_enter_blocked++;
		}

		kr = pe_result;
	}

after_the_pmap_enter:
	return kr;
}

void
vm_pre_fault(vm_map_offset_t vaddr, vm_prot_t prot)
{
	if (pmap_find_phys(current_map()->pmap, vaddr) == 0) {
		vm_fault(current_map(),      /* map */
		    vaddr,                   /* vaddr */
		    prot,                    /* fault_type */
		    FALSE,                   /* change_wiring */
		    VM_KERN_MEMORY_NONE,     /* tag - not wiring */
		    THREAD_UNINT,            /* interruptible */
		    NULL,                    /* caller_pmap */
		    0 /* caller_pmap_addr */);
	}
}


/*
 *	Routine:	vm_fault
 *	Purpose:
 *		Handle page faults, including pseudo-faults
 *		used to change the wiring status of pages.
 *	Returns:
 *		Explicit continuations have been removed.
 *	Implementation:
 *		vm_fault and vm_fault_page save mucho state
 *		in the moral equivalent of a closure.  The state
 *		structure is allocated when first entering vm_fault
 *		and deallocated when leaving vm_fault.
 */

extern int _map_enter_debug;
extern uint64_t get_current_unique_pid(void);

unsigned long vm_fault_collapse_total = 0;
unsigned long vm_fault_collapse_skipped = 0;


kern_return_t
vm_fault_external(
	vm_map_t        map,
	vm_map_offset_t vaddr,
	vm_prot_t       fault_type,
	boolean_t       change_wiring,
	int             interruptible,
	pmap_t          caller_pmap,
	vm_map_offset_t caller_pmap_addr)
{
	return vm_fault_internal(map, vaddr, fault_type, change_wiring, vm_tag_bt(),
	           interruptible, caller_pmap, caller_pmap_addr,
	           NULL);
}

kern_return_t
vm_fault(
	vm_map_t        map,
	vm_map_offset_t vaddr,
	vm_prot_t       fault_type,
	boolean_t       change_wiring,
	vm_tag_t        wire_tag,               /* if wiring must pass tag != VM_KERN_MEMORY_NONE */
	int             interruptible,
	pmap_t          caller_pmap,
	vm_map_offset_t caller_pmap_addr)
{
	return vm_fault_internal(map, vaddr, fault_type, change_wiring, wire_tag,
	           interruptible, caller_pmap, caller_pmap_addr,
	           NULL);
}

static boolean_t
current_proc_is_privileged(void)
{
	return csproc_get_platform_binary(current_proc());
}

uint64_t vm_copied_on_read = 0;

kern_return_t
vm_fault_internal(
	vm_map_t        map,
	vm_map_offset_t vaddr,
	vm_prot_t       caller_prot,
	boolean_t       change_wiring,
	vm_tag_t        wire_tag,               /* if wiring must pass tag != VM_KERN_MEMORY_NONE */
	int             interruptible,
	pmap_t          caller_pmap,
	vm_map_offset_t caller_pmap_addr,
	ppnum_t         *physpage_p)
{
	vm_map_version_t        version;        /* Map version for verificiation */
	boolean_t               wired;          /* Should mapping be wired down? */
	vm_object_t             object;         /* Top-level object */
	vm_object_offset_t      offset;         /* Top-level offset */
	vm_prot_t               prot;           /* Protection for mapping */
	vm_object_t             old_copy_object; /* Saved copy object */
	vm_page_t               result_page;    /* Result of vm_fault_page */
	vm_page_t               top_page;       /* Placeholder page */
	kern_return_t           kr;

	vm_page_t               m;      /* Fast access to result_page */
	kern_return_t           error_code;
	vm_object_t             cur_object;
	vm_object_t             m_object = NULL;
	vm_object_offset_t      cur_offset;
	vm_page_t               cur_m;
	vm_object_t             new_object;
	int                     type_of_fault;
	pmap_t                  pmap;
	wait_interrupt_t        interruptible_state;
	vm_map_t                real_map = map;
	vm_map_t                original_map = map;
	boolean_t               object_locks_dropped = FALSE;
	vm_prot_t               fault_type;
	vm_prot_t               original_fault_type;
	struct vm_object_fault_info fault_info = {};
	boolean_t               need_collapse = FALSE;
	boolean_t               need_retry = FALSE;
	boolean_t               *need_retry_ptr = NULL;
	int                     object_lock_type = 0;
	int                     cur_object_lock_type;
	vm_object_t             top_object = VM_OBJECT_NULL;
	vm_object_t             written_on_object = VM_OBJECT_NULL;
	memory_object_t         written_on_pager = NULL;
	vm_object_offset_t      written_on_offset = 0;
	int                     throttle_delay;
	int                     compressed_count_delta;
	int                     grab_options;
	boolean_t               need_copy;
	boolean_t               need_copy_on_read;
	vm_map_offset_t         trace_vaddr;
	vm_map_offset_t         trace_real_vaddr;
	vm_map_offset_t         real_vaddr;
	boolean_t               resilient_media_retry = FALSE;
	vm_object_t             resilient_media_object = VM_OBJECT_NULL;
	vm_object_offset_t      resilient_media_offset = (vm_object_offset_t)-1;

	real_vaddr = vaddr;
	trace_real_vaddr = vaddr;
	vaddr = vm_map_trunc_page(vaddr, PAGE_MASK);

	if (map == kernel_map) {
		trace_vaddr = VM_KERNEL_ADDRHIDE(vaddr);
		trace_real_vaddr = VM_KERNEL_ADDRHIDE(trace_real_vaddr);
	} else {
		trace_vaddr = vaddr;
	}

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    (MACHDBG_CODE(DBG_MACH_VM, 2)) | DBG_FUNC_START,
	    ((uint64_t)trace_vaddr >> 32),
	    trace_vaddr,
	    (map == kernel_map),
	    0,
	    0);

	if (get_preemption_level() != 0) {
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    (MACHDBG_CODE(DBG_MACH_VM, 2)) | DBG_FUNC_END,
		    ((uint64_t)trace_vaddr >> 32),
		    trace_vaddr,
		    KERN_FAILURE,
		    0,
		    0);

		return KERN_FAILURE;
	}

	thread_t cthread = current_thread();
	boolean_t rtfault = (cthread->sched_mode == TH_MODE_REALTIME);
	uint64_t fstart = 0;

	if (rtfault) {
		fstart = mach_continuous_time();
	}

	interruptible_state = thread_interrupt_level(interruptible);

	fault_type = (change_wiring ? VM_PROT_NONE : caller_prot);

	VM_STAT_INCR(faults);
	current_task()->faults++;
	original_fault_type = fault_type;

	need_copy = FALSE;
	if (fault_type & VM_PROT_WRITE) {
		need_copy = TRUE;
	}

	if (need_copy) {
		object_lock_type = OBJECT_LOCK_EXCLUSIVE;
	} else {
		object_lock_type = OBJECT_LOCK_SHARED;
	}

	cur_object_lock_type = OBJECT_LOCK_SHARED;

	if ((map == kernel_map) && (caller_prot & VM_PROT_WRITE)) {
		if (compressor_map) {
			if ((vaddr >= vm_map_min(compressor_map)) && (vaddr < vm_map_max(compressor_map))) {
				panic("Write fault on compressor map, va: %p type: %u bounds: %p->%p", (void *) vaddr, caller_prot, (void *) vm_map_min(compressor_map), (void *) vm_map_max(compressor_map));
			}
		}
	}
RetryFault:
	assert(written_on_object == VM_OBJECT_NULL);

	/*
	 * assume we will hit a page in the cache
	 * otherwise, explicitly override with
	 * the real fault type once we determine it
	 */
	type_of_fault = DBG_CACHE_HIT_FAULT;

	/*
	 *	Find the backing store object and offset into
	 *	it to begin the search.
	 */
	fault_type = original_fault_type;
	map = original_map;
	vm_map_lock_read(map);

	if (resilient_media_retry) {
		/*
		 * If we have to insert a fake zero-filled page to hide
		 * a media failure to provide the real page, we need to
		 * resolve any pending copy-on-write on this mapping.
		 * VM_PROT_COPY tells vm_map_lookup_locked() to deal
		 * with that even if this is not a "write" fault.
		 */
		need_copy = TRUE;
		object_lock_type = OBJECT_LOCK_EXCLUSIVE;
	}

	kr = vm_map_lookup_locked(&map, vaddr,
	    (fault_type | (need_copy ? VM_PROT_COPY : 0)),
	    object_lock_type, &version,
	    &object, &offset, &prot, &wired,
	    &fault_info,
	    &real_map);

	if (kr != KERN_SUCCESS) {
		vm_map_unlock_read(map);
		goto done;
	}
	pmap = real_map->pmap;
	fault_info.interruptible = interruptible;
	fault_info.stealth = FALSE;
	fault_info.io_sync = FALSE;
	fault_info.mark_zf_absent = FALSE;
	fault_info.batch_pmap_op = FALSE;

	if (resilient_media_retry) {
		/*
		 * We're retrying this fault after having detected a media
		 * failure from a "resilient_media" mapping.
		 * Check that the mapping is still pointing at the object
		 * that just failed to provide a page.
		 */
		assert(resilient_media_object != VM_OBJECT_NULL);
		assert(resilient_media_offset != (vm_object_offset_t)-1);
		if (object != VM_OBJECT_NULL &&
		    object == resilient_media_object &&
		    offset == resilient_media_offset &&
		    fault_info.resilient_media) {
			/*
			 * This mapping still points at the same object
			 * and is still "resilient_media": proceed in
			 * "recovery-from-media-failure" mode, where we'll
			 * insert a zero-filled page in the top object.
			 */
//                     printf("RESILIENT_MEDIA %s:%d recovering for object %p offset 0x%llx\n", __FUNCTION__, __LINE__, object, offset);
		} else {
			/* not recovering: reset state */
//                     printf("RESILIENT_MEDIA %s:%d no recovery resilient %d object %p/%p offset 0x%llx/0x%llx\n", __FUNCTION__, __LINE__, fault_info.resilient_media, object, resilient_media_object, offset, resilient_media_offset);
			resilient_media_retry = FALSE;
			/* release our extra reference on failed object */
//                     printf("FBDP %s:%d resilient_media_object %p deallocate\n", __FUNCTION__, __LINE__, resilient_media_object);
			vm_object_deallocate(resilient_media_object);
			resilient_media_object = VM_OBJECT_NULL;
			resilient_media_offset = (vm_object_offset_t)-1;
		}
	} else {
		assert(resilient_media_object == VM_OBJECT_NULL);
		resilient_media_offset = (vm_object_offset_t)-1;
	}

	/*
	 * If the page is wired, we must fault for the current protection
	 * value, to avoid further faults.
	 */
	if (wired) {
		fault_type = prot | VM_PROT_WRITE;
	}
	if (wired || need_copy) {
		/*
		 * since we're treating this fault as a 'write'
		 * we must hold the top object lock exclusively
		 */
		if (object_lock_type == OBJECT_LOCK_SHARED) {
			object_lock_type = OBJECT_LOCK_EXCLUSIVE;

			if (vm_object_lock_upgrade(object) == FALSE) {
				/*
				 * couldn't upgrade, so explictly
				 * take the lock exclusively
				 */
				vm_object_lock(object);
			}
		}
	}

#if     VM_FAULT_CLASSIFY
	/*
	 *	Temporary data gathering code
	 */
	vm_fault_classify(object, offset, fault_type);
#endif
	/*
	 *	Fast fault code.  The basic idea is to do as much as
	 *	possible while holding the map lock and object locks.
	 *      Busy pages are not used until the object lock has to
	 *	be dropped to do something (copy, zero fill, pmap enter).
	 *	Similarly, paging references aren't acquired until that
	 *	point, and object references aren't used.
	 *
	 *	If we can figure out what to do
	 *	(zero fill, copy on write, pmap enter) while holding
	 *	the locks, then it gets done.  Otherwise, we give up,
	 *	and use the original fault path (which doesn't hold
	 *	the map lock, and relies on busy pages).
	 *	The give up cases include:
	 *              - Have to talk to pager.
	 *		- Page is busy, absent or in error.
	 *		- Pager has locked out desired access.
	 *		- Fault needs to be restarted.
	 *		- Have to push page into copy object.
	 *
	 *	The code is an infinite loop that moves one level down
	 *	the shadow chain each time.  cur_object and cur_offset
	 *      refer to the current object being examined. object and offset
	 *	are the original object from the map.  The loop is at the
	 *	top level if and only if object and cur_object are the same.
	 *
	 *	Invariants:  Map lock is held throughout.  Lock is held on
	 *		original object and cur_object (if different) when
	 *		continuing or exiting loop.
	 *
	 */

#if defined(__arm64__)
	/*
	 * Fail if reading an execute-only page in a
	 * pmap that enforces execute-only protection.
	 */
	if (fault_type == VM_PROT_READ &&
	    (prot & VM_PROT_EXECUTE) &&
	    !(prot & VM_PROT_READ) &&
	    pmap_enforces_execute_only(pmap)) {
		vm_object_unlock(object);
		vm_map_unlock_read(map);
		if (real_map != map) {
			vm_map_unlock(real_map);
		}
		kr = KERN_PROTECTION_FAILURE;
		goto done;
	}
#endif

	/*
	 * If this page is to be inserted in a copy delay object
	 * for writing, and if the object has a copy, then the
	 * copy delay strategy is implemented in the slow fault page.
	 */
	if (object->copy_strategy == MEMORY_OBJECT_COPY_DELAY &&
	    object->copy != VM_OBJECT_NULL && (fault_type & VM_PROT_WRITE)) {
		goto handle_copy_delay;
	}

	cur_object = object;
	cur_offset = offset;

	grab_options = 0;
#if CONFIG_SECLUDED_MEMORY
	if (object->can_grab_secluded) {
		grab_options |= VM_PAGE_GRAB_SECLUDED;
	}
#endif /* CONFIG_SECLUDED_MEMORY */

	while (TRUE) {
		if (!cur_object->pager_created &&
		    cur_object->phys_contiguous) { /* superpage */
			break;
		}

		if (cur_object->blocked_access) {
			/*
			 * Access to this VM object has been blocked.
			 * Let the slow path handle it.
			 */
			break;
		}

		m = vm_page_lookup(cur_object, cur_offset);
		m_object = NULL;

		if (m != VM_PAGE_NULL) {
			m_object = cur_object;

			if (m->vmp_busy) {
				wait_result_t   result;

				/*
				 * in order to do the PAGE_ASSERT_WAIT, we must
				 * have object that 'm' belongs to locked exclusively
				 */
				if (object != cur_object) {
					if (cur_object_lock_type == OBJECT_LOCK_SHARED) {
						cur_object_lock_type = OBJECT_LOCK_EXCLUSIVE;

						if (vm_object_lock_upgrade(cur_object) == FALSE) {
							/*
							 * couldn't upgrade so go do a full retry
							 * immediately since we can no longer be
							 * certain about cur_object (since we
							 * don't hold a reference on it)...
							 * first drop the top object lock
							 */
							vm_object_unlock(object);

							vm_map_unlock_read(map);
							if (real_map != map) {
								vm_map_unlock(real_map);
							}

							goto RetryFault;
						}
					}
				} else if (object_lock_type == OBJECT_LOCK_SHARED) {
					object_lock_type = OBJECT_LOCK_EXCLUSIVE;

					if (vm_object_lock_upgrade(object) == FALSE) {
						/*
						 * couldn't upgrade, so explictly take the lock
						 * exclusively and go relookup the page since we
						 * will have dropped the object lock and
						 * a different thread could have inserted
						 * a page at this offset
						 * no need for a full retry since we're
						 * at the top level of the object chain
						 */
						vm_object_lock(object);

						continue;
					}
				}
				if ((m->vmp_q_state == VM_PAGE_ON_PAGEOUT_Q) && m_object->internal) {
					/*
					 * m->vmp_busy == TRUE and the object is locked exclusively
					 * if m->pageout_queue == TRUE after we acquire the
					 * queues lock, we are guaranteed that it is stable on
					 * the pageout queue and therefore reclaimable
					 *
					 * NOTE: this is only true for the internal pageout queue
					 * in the compressor world
					 */
					assert(VM_CONFIG_COMPRESSOR_IS_PRESENT);

					vm_page_lock_queues();

					if (m->vmp_q_state == VM_PAGE_ON_PAGEOUT_Q) {
						vm_pageout_throttle_up(m);
						vm_page_unlock_queues();

						PAGE_WAKEUP_DONE(m);
						goto reclaimed_from_pageout;
					}
					vm_page_unlock_queues();
				}
				if (object != cur_object) {
					vm_object_unlock(object);
				}

				vm_map_unlock_read(map);
				if (real_map != map) {
					vm_map_unlock(real_map);
				}

				result = PAGE_ASSERT_WAIT(m, interruptible);

				vm_object_unlock(cur_object);

				if (result == THREAD_WAITING) {
					result = thread_block(THREAD_CONTINUE_NULL);

					counter(c_vm_fault_page_block_busy_kernel++);
				}
				if (result == THREAD_AWAKENED || result == THREAD_RESTART) {
					goto RetryFault;
				}

				kr = KERN_ABORTED;
				goto done;
			}
reclaimed_from_pageout:
			if (m->vmp_laundry) {
				if (object != cur_object) {
					if (cur_object_lock_type == OBJECT_LOCK_SHARED) {
						cur_object_lock_type = OBJECT_LOCK_EXCLUSIVE;

						vm_object_unlock(object);
						vm_object_unlock(cur_object);

						vm_map_unlock_read(map);
						if (real_map != map) {
							vm_map_unlock(real_map);
						}

						goto RetryFault;
					}
				} else if (object_lock_type == OBJECT_LOCK_SHARED) {
					object_lock_type = OBJECT_LOCK_EXCLUSIVE;

					if (vm_object_lock_upgrade(object) == FALSE) {
						/*
						 * couldn't upgrade, so explictly take the lock
						 * exclusively and go relookup the page since we
						 * will have dropped the object lock and
						 * a different thread could have inserted
						 * a page at this offset
						 * no need for a full retry since we're
						 * at the top level of the object chain
						 */
						vm_object_lock(object);

						continue;
					}
				}
				vm_pageout_steal_laundry(m, FALSE);
			}

			if (VM_PAGE_GET_PHYS_PAGE(m) == vm_page_guard_addr) {
				/*
				 * Guard page: let the slow path deal with it
				 */
				break;
			}
			if (m->vmp_unusual && (m->vmp_error || m->vmp_restart || m->vmp_private || m->vmp_absent)) {
				/*
				 * Unusual case... let the slow path deal with it
				 */
				break;
			}
			if (VM_OBJECT_PURGEABLE_FAULT_ERROR(m_object)) {
				if (object != cur_object) {
					vm_object_unlock(object);
				}
				vm_map_unlock_read(map);
				if (real_map != map) {
					vm_map_unlock(real_map);
				}
				vm_object_unlock(cur_object);
				kr = KERN_MEMORY_ERROR;
				goto done;
			}
			assert(m_object == VM_PAGE_OBJECT(m));

			if (VM_FAULT_NEED_CS_VALIDATION(map->pmap, m, m_object) ||
			    (physpage_p != NULL && (prot & VM_PROT_WRITE))) {
upgrade_lock_and_retry:
				/*
				 * We might need to validate this page
				 * against its code signature, so we
				 * want to hold the VM object exclusively.
				 */
				if (object != cur_object) {
					if (cur_object_lock_type == OBJECT_LOCK_SHARED) {
						vm_object_unlock(object);
						vm_object_unlock(cur_object);

						cur_object_lock_type = OBJECT_LOCK_EXCLUSIVE;

						vm_map_unlock_read(map);
						if (real_map != map) {
							vm_map_unlock(real_map);
						}

						goto RetryFault;
					}
				} else if (object_lock_type == OBJECT_LOCK_SHARED) {
					object_lock_type = OBJECT_LOCK_EXCLUSIVE;

					if (vm_object_lock_upgrade(object) == FALSE) {
						/*
						 * couldn't upgrade, so explictly take the lock
						 * exclusively and go relookup the page since we
						 * will have dropped the object lock and
						 * a different thread could have inserted
						 * a page at this offset
						 * no need for a full retry since we're
						 * at the top level of the object chain
						 */
						vm_object_lock(object);

						continue;
					}
				}
			}
			/*
			 *	Two cases of map in faults:
			 *	    - At top level w/o copy object.
			 *	    - Read fault anywhere.
			 *		--> must disallow write.
			 */

			if (object == cur_object && object->copy == VM_OBJECT_NULL) {
				goto FastPmapEnter;
			}

			if (!need_copy &&
			    !fault_info.no_copy_on_read &&
			    cur_object != object &&
			    !cur_object->internal &&
			    !cur_object->pager_trusted &&
			    vm_protect_privileged_from_untrusted &&
			    !((prot & VM_PROT_EXECUTE) &&
			    cur_object->code_signed &&
			    cs_process_enforcement(NULL)) &&
			    current_proc_is_privileged()) {
				/*
				 * We're faulting on a page in "object" and
				 * went down the shadow chain to "cur_object"
				 * to find out that "cur_object"'s pager
				 * is not "trusted", i.e. we can not trust it
				 * to always return the same contents.
				 * Since the target is a "privileged" process,
				 * let's treat this as a copy-on-read fault, as
				 * if it was a copy-on-write fault.
				 * Once "object" gets a copy of this page, it
				 * won't have to rely on "cur_object" to
				 * provide the contents again.
				 *
				 * This is done by setting "need_copy" and
				 * retrying the fault from the top with the
				 * appropriate locking.
				 *
				 * Special case: if the mapping is executable
				 * and the untrusted object is code-signed and
				 * the process is "cs_enforced", we do not
				 * copy-on-read because that would break
				 * code-signing enforcement expectations (an
				 * executable page must belong to a code-signed
				 * object) and we can rely on code-signing
				 * to re-validate the page if it gets evicted
				 * and paged back in.
				 */
//				printf("COPY-ON-READ %s:%d map %p va 0x%llx page %p object %p offset 0x%llx UNTRUSTED: need copy-on-read!\n", __FUNCTION__, __LINE__, map, (uint64_t)vaddr, m, VM_PAGE_OBJECT(m), m->vmp_offset);
				vm_copied_on_read++;
				need_copy = TRUE;

				vm_object_unlock(object);
				vm_object_unlock(cur_object);
				object_lock_type = OBJECT_LOCK_EXCLUSIVE;
				vm_map_unlock_read(map);
				if (real_map != map) {
					vm_map_unlock(real_map);
				}
				goto RetryFault;
			}

			if (!(fault_type & VM_PROT_WRITE) && !need_copy) {
				if (!pmap_has_prot_policy(prot)) {
					prot &= ~VM_PROT_WRITE;
				} else {
					/*
					 * For a protection that the pmap cares
					 * about, we must hand over the full
					 * set of protections (so that the pmap
					 * layer can apply any desired policy).
					 * This means that cs_bypass must be
					 * set, as this can force us to pass
					 * RWX.
					 */
					assert(fault_info.cs_bypass);
				}

				if (object != cur_object) {
					/*
					 * We still need to hold the top object
					 * lock here to prevent a race between
					 * a read fault (taking only "shared"
					 * locks) and a write fault (taking
					 * an "exclusive" lock on the top
					 * object.
					 * Otherwise, as soon as we release the
					 * top lock, the write fault could
					 * proceed and actually complete before
					 * the read fault, and the copied page's
					 * translation could then be overwritten
					 * by the read fault's translation for
					 * the original page.
					 *
					 * Let's just record what the top object
					 * is and we'll release it later.
					 */
					top_object = object;

					/*
					 * switch to the object that has the new page
					 */
					object = cur_object;
					object_lock_type = cur_object_lock_type;
				}
FastPmapEnter:
				assert(m_object == VM_PAGE_OBJECT(m));

				/*
				 * prepare for the pmap_enter...
				 * object and map are both locked
				 * m contains valid data
				 * object == m->vmp_object
				 * cur_object == NULL or it's been unlocked
				 * no paging references on either object or cur_object
				 */
				if (top_object != VM_OBJECT_NULL || object_lock_type != OBJECT_LOCK_EXCLUSIVE) {
					need_retry_ptr = &need_retry;
				} else {
					need_retry_ptr = NULL;
				}

				if (caller_pmap) {
					kr = vm_fault_enter(m,
					    caller_pmap,
					    caller_pmap_addr,
					    prot,
					    caller_prot,
					    wired,
					    change_wiring,
					    wire_tag,
					    &fault_info,
					    need_retry_ptr,
					    &type_of_fault);
				} else {
					kr = vm_fault_enter(m,
					    pmap,
					    vaddr,
					    prot,
					    caller_prot,
					    wired,
					    change_wiring,
					    wire_tag,
					    &fault_info,
					    need_retry_ptr,
					    &type_of_fault);
				}
				{
					int     event_code = 0;

					if (m_object->internal) {
						event_code = (MACHDBG_CODE(DBG_MACH_WORKINGSET, VM_REAL_FAULT_ADDR_INTERNAL));
					} else if (m_object->object_is_shared_cache) {
						event_code = (MACHDBG_CODE(DBG_MACH_WORKINGSET, VM_REAL_FAULT_ADDR_SHAREDCACHE));
					} else {
						event_code = (MACHDBG_CODE(DBG_MACH_WORKINGSET, VM_REAL_FAULT_ADDR_EXTERNAL));
					}

					KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, event_code, trace_real_vaddr, (fault_info.user_tag << 16) | (caller_prot << 8) | type_of_fault, m->vmp_offset, get_current_unique_pid(), 0);
					if (need_retry == FALSE) {
						KDBG_FILTERED(MACHDBG_CODE(DBG_MACH_WORKINGSET, VM_REAL_FAULT_FAST), get_current_unique_pid(), 0, 0, 0, 0);
					}
					DTRACE_VM6(real_fault, vm_map_offset_t, real_vaddr, vm_map_offset_t, m->vmp_offset, int, event_code, int, caller_prot, int, type_of_fault, int, fault_info.user_tag);
				}
				if (kr == KERN_SUCCESS &&
				    physpage_p != NULL) {
					/* for vm_map_wire_and_extract() */
					*physpage_p = VM_PAGE_GET_PHYS_PAGE(m);
					if (prot & VM_PROT_WRITE) {
						vm_object_lock_assert_exclusive(m_object);
						m->vmp_dirty = TRUE;
					}
				}

				if (top_object != VM_OBJECT_NULL) {
					/*
					 * It's safe to drop the top object
					 * now that we've done our
					 * vm_fault_enter().  Any other fault
					 * in progress for that virtual
					 * address will either find our page
					 * and translation or put in a new page
					 * and translation.
					 */
					vm_object_unlock(top_object);
					top_object = VM_OBJECT_NULL;
				}

				if (need_collapse == TRUE) {
					vm_object_collapse(object, offset, TRUE);
				}

				if (need_retry == FALSE &&
				    (type_of_fault == DBG_PAGEIND_FAULT || type_of_fault == DBG_PAGEINV_FAULT || type_of_fault == DBG_CACHE_HIT_FAULT)) {
					/*
					 * evaluate access pattern and update state
					 * vm_fault_deactivate_behind depends on the
					 * state being up to date
					 */
					vm_fault_is_sequential(m_object, cur_offset, fault_info.behavior);

					vm_fault_deactivate_behind(m_object, cur_offset, fault_info.behavior);
				}
				/*
				 * That's it, clean up and return.
				 */
				if (m->vmp_busy) {
					PAGE_WAKEUP_DONE(m);
				}

				if (need_retry == FALSE && !m_object->internal && (fault_type & VM_PROT_WRITE)) {
					vm_object_paging_begin(m_object);

					assert(written_on_object == VM_OBJECT_NULL);
					written_on_object = m_object;
					written_on_pager = m_object->pager;
					written_on_offset = m_object->paging_offset + m->vmp_offset;
				}
				vm_object_unlock(object);

				vm_map_unlock_read(map);
				if (real_map != map) {
					vm_map_unlock(real_map);
				}

				if (need_retry == TRUE) {
					/*
					 * vm_fault_enter couldn't complete the PMAP_ENTER...
					 * at this point we don't hold any locks so it's safe
					 * to ask the pmap layer to expand the page table to
					 * accommodate this mapping... once expanded, we'll
					 * re-drive the fault which should result in vm_fault_enter
					 * being able to successfully enter the mapping this time around
					 */
					(void)pmap_enter_options(
						pmap, vaddr, 0, 0, 0, 0, 0,
						PMAP_OPTIONS_NOENTER, NULL);

					need_retry = FALSE;
					goto RetryFault;
				}
				goto done;
			}
			/*
			 * COPY ON WRITE FAULT
			 */
			assert(object_lock_type == OBJECT_LOCK_EXCLUSIVE);

			/*
			 * If objects match, then
			 * object->copy must not be NULL (else control
			 * would be in previous code block), and we
			 * have a potential push into the copy object
			 * with which we can't cope with here.
			 */
			if (cur_object == object) {
				/*
				 * must take the slow path to
				 * deal with the copy push
				 */
				break;
			}

			/*
			 * This is now a shadow based copy on write
			 * fault -- it requires a copy up the shadow
			 * chain.
			 */
			assert(m_object == VM_PAGE_OBJECT(m));

			if ((cur_object_lock_type == OBJECT_LOCK_SHARED) &&
			    VM_FAULT_NEED_CS_VALIDATION(NULL, m, m_object)) {
				goto upgrade_lock_and_retry;
			}

			/*
			 * Allocate a page in the original top level
			 * object. Give up if allocate fails.  Also
			 * need to remember current page, as it's the
			 * source of the copy.
			 *
			 * at this point we hold locks on both
			 * object and cur_object... no need to take
			 * paging refs or mark pages BUSY since
			 * we don't drop either object lock until
			 * the page has been copied and inserted
			 */
			cur_m = m;
			m = vm_page_grab_options(grab_options);
			m_object = NULL;

			if (m == VM_PAGE_NULL) {
				/*
				 * no free page currently available...
				 * must take the slow path
				 */
				break;
			}
			/*
			 * Now do the copy.  Mark the source page busy...
			 *
			 *	NOTE: This code holds the map lock across
			 *	the page copy.
			 */
			vm_page_copy(cur_m, m);
			vm_page_insert(m, object, offset);
			m_object = object;
			SET_PAGE_DIRTY(m, FALSE);

			/*
			 * Now cope with the source page and object
			 */
			if (object->ref_count > 1 && cur_m->vmp_pmapped) {
				pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(cur_m));
			}

			if (cur_m->vmp_clustered) {
				VM_PAGE_COUNT_AS_PAGEIN(cur_m);
				VM_PAGE_CONSUME_CLUSTERED(cur_m);
				vm_fault_is_sequential(cur_object, cur_offset, fault_info.behavior);
			}
			need_collapse = TRUE;

			if (!cur_object->internal &&
			    cur_object->copy_strategy == MEMORY_OBJECT_COPY_DELAY) {
				/*
				 * The object from which we've just
				 * copied a page is most probably backed
				 * by a vnode.  We don't want to waste too
				 * much time trying to collapse the VM objects
				 * and create a bottleneck when several tasks
				 * map the same file.
				 */
				if (cur_object->copy == object) {
					/*
					 * Shared mapping or no COW yet.
					 * We can never collapse a copy
					 * object into its backing object.
					 */
					need_collapse = FALSE;
				} else if (cur_object->copy == object->shadow &&
				    object->shadow->resident_page_count == 0) {
					/*
					 * Shared mapping after a COW occurred.
					 */
					need_collapse = FALSE;
				}
			}
			vm_object_unlock(cur_object);

			if (need_collapse == FALSE) {
				vm_fault_collapse_skipped++;
			}
			vm_fault_collapse_total++;

			type_of_fault = DBG_COW_FAULT;
			VM_STAT_INCR(cow_faults);
			DTRACE_VM2(cow_fault, int, 1, (uint64_t *), NULL);
			current_task()->cow_faults++;

			goto FastPmapEnter;
		} else {
			/*
			 * No page at cur_object, cur_offset... m == NULL
			 */
			if (cur_object->pager_created) {
				int     compressor_external_state = VM_EXTERNAL_STATE_UNKNOWN;

				if (MUST_ASK_PAGER(cur_object, cur_offset, compressor_external_state) == TRUE) {
					int             my_fault_type;
					int             c_flags = C_DONT_BLOCK;
					boolean_t       insert_cur_object = FALSE;

					/*
					 * May have to talk to a pager...
					 * if so, take the slow path by
					 * doing a 'break' from the while (TRUE) loop
					 *
					 * external_state will only be set to VM_EXTERNAL_STATE_EXISTS
					 * if the compressor is active and the page exists there
					 */
					if (compressor_external_state != VM_EXTERNAL_STATE_EXISTS) {
						break;
					}

					if (map == kernel_map || real_map == kernel_map) {
						/*
						 * can't call into the compressor with the kernel_map
						 * lock held, since the compressor may try to operate
						 * on the kernel map in order to return an empty c_segment
						 */
						break;
					}
					if (object != cur_object) {
						if (fault_type & VM_PROT_WRITE) {
							c_flags |= C_KEEP;
						} else {
							insert_cur_object = TRUE;
						}
					}
					if (insert_cur_object == TRUE) {
						if (cur_object_lock_type == OBJECT_LOCK_SHARED) {
							cur_object_lock_type = OBJECT_LOCK_EXCLUSIVE;

							if (vm_object_lock_upgrade(cur_object) == FALSE) {
								/*
								 * couldn't upgrade so go do a full retry
								 * immediately since we can no longer be
								 * certain about cur_object (since we
								 * don't hold a reference on it)...
								 * first drop the top object lock
								 */
								vm_object_unlock(object);

								vm_map_unlock_read(map);
								if (real_map != map) {
									vm_map_unlock(real_map);
								}

								goto RetryFault;
							}
						}
					} else if (object_lock_type == OBJECT_LOCK_SHARED) {
						object_lock_type = OBJECT_LOCK_EXCLUSIVE;

						if (object != cur_object) {
							/*
							 * we can't go for the upgrade on the top
							 * lock since the upgrade may block waiting
							 * for readers to drain... since we hold
							 * cur_object locked at this point, waiting
							 * for the readers to drain would represent
							 * a lock order inversion since the lock order
							 * for objects is the reference order in the
							 * shadown chain
							 */
							vm_object_unlock(object);
							vm_object_unlock(cur_object);

							vm_map_unlock_read(map);
							if (real_map != map) {
								vm_map_unlock(real_map);
							}

							goto RetryFault;
						}
						if (vm_object_lock_upgrade(object) == FALSE) {
							/*
							 * couldn't upgrade, so explictly take the lock
							 * exclusively and go relookup the page since we
							 * will have dropped the object lock and
							 * a different thread could have inserted
							 * a page at this offset
							 * no need for a full retry since we're
							 * at the top level of the object chain
							 */
							vm_object_lock(object);

							continue;
						}
					}
					m = vm_page_grab_options(grab_options);
					m_object = NULL;

					if (m == VM_PAGE_NULL) {
						/*
						 * no free page currently available...
						 * must take the slow path
						 */
						break;
					}

					/*
					 * The object is and remains locked
					 * so no need to take a
					 * "paging_in_progress" reference.
					 */
					boolean_t shared_lock;
					if ((object == cur_object &&
					    object_lock_type == OBJECT_LOCK_EXCLUSIVE) ||
					    (object != cur_object &&
					    cur_object_lock_type == OBJECT_LOCK_EXCLUSIVE)) {
						shared_lock = FALSE;
					} else {
						shared_lock = TRUE;
					}

					kr = vm_compressor_pager_get(
						cur_object->pager,
						(cur_offset +
						cur_object->paging_offset),
						VM_PAGE_GET_PHYS_PAGE(m),
						&my_fault_type,
						c_flags,
						&compressed_count_delta);

					vm_compressor_pager_count(
						cur_object->pager,
						compressed_count_delta,
						shared_lock,
						cur_object);

					if (kr != KERN_SUCCESS) {
						vm_page_release(m, FALSE);
						m = VM_PAGE_NULL;
						break;
					}
					m->vmp_dirty = TRUE;

					/*
					 * If the object is purgeable, its
					 * owner's purgeable ledgers will be
					 * updated in vm_page_insert() but the
					 * page was also accounted for in a
					 * "compressed purgeable" ledger, so
					 * update that now.
					 */
					if (object != cur_object &&
					    !insert_cur_object) {
						/*
						 * We're not going to insert
						 * the decompressed page into
						 * the object it came from.
						 *
						 * We're dealing with a
						 * copy-on-write fault on
						 * "object".
						 * We're going to decompress
						 * the page directly into the
						 * target "object" while
						 * keepin the compressed
						 * page for "cur_object", so
						 * no ledger update in that
						 * case.
						 */
					} else if (((cur_object->purgable ==
					    VM_PURGABLE_DENY) &&
					    (!cur_object->vo_ledger_tag)) ||
					    (cur_object->vo_owner ==
					    NULL)) {
						/*
						 * "cur_object" is not purgeable
						 * and is not ledger-taged, or
						 * there's no owner for it,
						 * so no owner's ledgers to
						 * update.
						 */
					} else {
						/*
						 * One less compressed
						 * purgeable/tagged page for
						 * cur_object's owner.
						 */
						vm_object_owner_compressed_update(
							cur_object,
							-1);
					}

					if (insert_cur_object) {
						vm_page_insert(m, cur_object, cur_offset);
						m_object = cur_object;
					} else {
						vm_page_insert(m, object, offset);
						m_object = object;
					}

					if ((m_object->wimg_bits & VM_WIMG_MASK) != VM_WIMG_USE_DEFAULT) {
						/*
						 * If the page is not cacheable,
						 * we can't let its contents
						 * linger in the data cache
						 * after the decompression.
						 */
						pmap_sync_page_attributes_phys(VM_PAGE_GET_PHYS_PAGE(m));
					}

					type_of_fault = my_fault_type;

					VM_STAT_DECOMPRESSIONS();

					if (cur_object != object) {
						if (insert_cur_object) {
							top_object = object;
							/*
							 * switch to the object that has the new page
							 */
							object = cur_object;
							object_lock_type = cur_object_lock_type;
						} else {
							vm_object_unlock(cur_object);
							cur_object = object;
						}
					}
					goto FastPmapEnter;
				}
				/*
				 * existence map present and indicates
				 * that the pager doesn't have this page
				 */
			}
			if (cur_object->shadow == VM_OBJECT_NULL ||
			    resilient_media_retry) {
				/*
				 * Zero fill fault.  Page gets
				 * inserted into the original object.
				 */
				if (cur_object->shadow_severed ||
				    VM_OBJECT_PURGEABLE_FAULT_ERROR(cur_object) ||
				    cur_object == compressor_object ||
				    cur_object == kernel_object ||
				    cur_object == vm_submap_object) {
					if (object != cur_object) {
						vm_object_unlock(cur_object);
					}
					vm_object_unlock(object);

					vm_map_unlock_read(map);
					if (real_map != map) {
						vm_map_unlock(real_map);
					}

					kr = KERN_MEMORY_ERROR;
					goto done;
				}
				if (cur_object != object) {
					vm_object_unlock(cur_object);

					cur_object = object;
				}
				if (object_lock_type == OBJECT_LOCK_SHARED) {
					object_lock_type = OBJECT_LOCK_EXCLUSIVE;

					if (vm_object_lock_upgrade(object) == FALSE) {
						/*
						 * couldn't upgrade so do a full retry on the fault
						 * since we dropped the object lock which
						 * could allow another thread to insert
						 * a page at this offset
						 */
						vm_map_unlock_read(map);
						if (real_map != map) {
							vm_map_unlock(real_map);
						}

						goto RetryFault;
					}
				}
				if (!object->internal) {
					panic("%s:%d should not zero-fill page at offset 0x%llx in external object %p", __FUNCTION__, __LINE__, (uint64_t)offset, object);
				}
				m = vm_page_alloc(object, offset);
				m_object = NULL;

				if (m == VM_PAGE_NULL) {
					/*
					 * no free page currently available...
					 * must take the slow path
					 */
					break;
				}
				m_object = object;

				/*
				 * Now zero fill page...
				 * the page is probably going to
				 * be written soon, so don't bother
				 * to clear the modified bit
				 *
				 *   NOTE: This code holds the map
				 *   lock across the zero fill.
				 */
				type_of_fault = vm_fault_zero_page(m, map->no_zero_fill);

				goto FastPmapEnter;
			}
			/*
			 * On to the next level in the shadow chain
			 */
			cur_offset += cur_object->vo_shadow_offset;
			new_object = cur_object->shadow;

			/*
			 * take the new_object's lock with the indicated state
			 */
			if (cur_object_lock_type == OBJECT_LOCK_SHARED) {
				vm_object_lock_shared(new_object);
			} else {
				vm_object_lock(new_object);
			}

			if (cur_object != object) {
				vm_object_unlock(cur_object);
			}

			cur_object = new_object;

			continue;
		}
	}
	/*
	 * Cleanup from fast fault failure.  Drop any object
	 * lock other than original and drop map lock.
	 */
	if (object != cur_object) {
		vm_object_unlock(cur_object);
	}

	/*
	 * must own the object lock exclusively at this point
	 */
	if (object_lock_type == OBJECT_LOCK_SHARED) {
		object_lock_type = OBJECT_LOCK_EXCLUSIVE;

		if (vm_object_lock_upgrade(object) == FALSE) {
			/*
			 * couldn't upgrade, so explictly
			 * take the lock exclusively
			 * no need to retry the fault at this
			 * point since "vm_fault_page" will
			 * completely re-evaluate the state
			 */
			vm_object_lock(object);
		}
	}

handle_copy_delay:
	vm_map_unlock_read(map);
	if (real_map != map) {
		vm_map_unlock(real_map);
	}

	if (__improbable(object == compressor_object ||
	    object == kernel_object ||
	    object == vm_submap_object)) {
		/*
		 * These objects are explicitly managed and populated by the
		 * kernel.  The virtual ranges backed by these objects should
		 * either have wired pages or "holes" that are not supposed to
		 * be accessed at all until they get explicitly populated.
		 * We should never have to resolve a fault on a mapping backed
		 * by one of these VM objects and providing a zero-filled page
		 * would be wrong here, so let's fail the fault and let the
		 * caller crash or recover.
		 */
		vm_object_unlock(object);
		kr = KERN_MEMORY_ERROR;
		goto done;
	}

	assert(object != compressor_object);
	assert(object != kernel_object);
	assert(object != vm_submap_object);

	if (resilient_media_retry) {
		/*
		 * We could get here if we failed to get a free page
		 * to zero-fill and had to take the slow path again.
		 * Reset our "recovery-from-failed-media" state.
		 */
		assert(resilient_media_object != VM_OBJECT_NULL);
		assert(resilient_media_offset != (vm_object_offset_t)-1);
		/* release our extra reference on failed object */
//             printf("FBDP %s:%d resilient_media_object %p deallocate\n", __FUNCTION__, __LINE__, resilient_media_object);
		vm_object_deallocate(resilient_media_object);
		resilient_media_object = VM_OBJECT_NULL;
		resilient_media_offset = (vm_object_offset_t)-1;
		resilient_media_retry = FALSE;
	}

	/*
	 * Make a reference to this object to
	 * prevent its disposal while we are messing with
	 * it.  Once we have the reference, the map is free
	 * to be diddled.  Since objects reference their
	 * shadows (and copies), they will stay around as well.
	 */
	vm_object_reference_locked(object);
	vm_object_paging_begin(object);

	set_thread_pagein_error(cthread, 0);
	error_code = 0;

	result_page = VM_PAGE_NULL;
	kr = vm_fault_page(object, offset, fault_type,
	    (change_wiring && !wired),
	    FALSE,                /* page not looked up */
	    &prot, &result_page, &top_page,
	    &type_of_fault,
	    &error_code, map->no_zero_fill,
	    FALSE, &fault_info);

	/*
	 * if kr != VM_FAULT_SUCCESS, then the paging reference
	 * has been dropped and the object unlocked... the ref_count
	 * is still held
	 *
	 * if kr == VM_FAULT_SUCCESS, then the paging reference
	 * is still held along with the ref_count on the original object
	 *
	 *	the object is returned locked with a paging reference
	 *
	 *	if top_page != NULL, then it's BUSY and the
	 *	object it belongs to has a paging reference
	 *	but is returned unlocked
	 */
	if (kr != VM_FAULT_SUCCESS &&
	    kr != VM_FAULT_SUCCESS_NO_VM_PAGE) {
		if (kr == VM_FAULT_MEMORY_ERROR &&
		    fault_info.resilient_media) {
			assertf(object->internal, "object %p", object);
			/*
			 * This fault failed but the mapping was
			 * "media resilient", so we'll retry the fault in
			 * recovery mode to get a zero-filled page in the
			 * top object.
			 * Keep the reference on the failing object so
			 * that we can check that the mapping is still
			 * pointing to it when we retry the fault.
			 */
//                     printf("RESILIENT_MEDIA %s:%d: object %p offset 0x%llx recover from media error 0x%x kr 0x%x top_page %p result_page %p\n", __FUNCTION__, __LINE__, object, offset, error_code, kr, top_page, result_page);
			assert(!resilient_media_retry); /* no double retry */
			assert(resilient_media_object == VM_OBJECT_NULL);
			assert(resilient_media_offset == (vm_object_offset_t)-1);
			resilient_media_retry = TRUE;
			resilient_media_object = object;
			resilient_media_offset = offset;
//                     printf("FBDP %s:%d resilient_media_object %p offset 0x%llx kept reference\n", __FUNCTION__, __LINE__, resilient_media_object, resilient_mmedia_offset);
			goto RetryFault;
		} else {
			/*
			 * we didn't succeed, lose the object reference
			 * immediately.
			 */
			vm_object_deallocate(object);
			object = VM_OBJECT_NULL; /* no longer valid */
		}

		/*
		 * See why we failed, and take corrective action.
		 */
		switch (kr) {
		case VM_FAULT_MEMORY_SHORTAGE:
			if (vm_page_wait((change_wiring) ?
			    THREAD_UNINT :
			    THREAD_ABORTSAFE)) {
				goto RetryFault;
			}
		/*
		 * fall thru
		 */
		case VM_FAULT_INTERRUPTED:
			kr = KERN_ABORTED;
			goto done;
		case VM_FAULT_RETRY:
			goto RetryFault;
		case VM_FAULT_MEMORY_ERROR:
			if (error_code) {
				kr = error_code;
			} else {
				kr = KERN_MEMORY_ERROR;
			}
			goto done;
		default:
			panic("vm_fault: unexpected error 0x%x from "
			    "vm_fault_page()\n", kr);
		}
	}
	m = result_page;
	m_object = NULL;

	if (m != VM_PAGE_NULL) {
		m_object = VM_PAGE_OBJECT(m);
		assert((change_wiring && !wired) ?
		    (top_page == VM_PAGE_NULL) :
		    ((top_page == VM_PAGE_NULL) == (m_object == object)));
	}

	/*
	 * What to do with the resulting page from vm_fault_page
	 * if it doesn't get entered into the physical map:
	 */
#define RELEASE_PAGE(m)                                 \
	MACRO_BEGIN                                     \
	PAGE_WAKEUP_DONE(m);                            \
	if ( !VM_PAGE_PAGEABLE(m)) {                    \
	        vm_page_lockspin_queues();              \
	        if ( !VM_PAGE_PAGEABLE(m))              \
	                vm_page_activate(m);            \
	        vm_page_unlock_queues();                \
	}                                               \
	MACRO_END


	object_locks_dropped = FALSE;
	/*
	 * We must verify that the maps have not changed
	 * since our last lookup. vm_map_verify() needs the
	 * map lock (shared) but we are holding object locks.
	 * So we do a try_lock() first and, if that fails, we
	 * drop the object locks and go in for the map lock again.
	 */
	if (!vm_map_try_lock_read(original_map)) {
		if (m != VM_PAGE_NULL) {
			old_copy_object = m_object->copy;
			vm_object_unlock(m_object);
		} else {
			old_copy_object = VM_OBJECT_NULL;
			vm_object_unlock(object);
		}

		object_locks_dropped = TRUE;

		vm_map_lock_read(original_map);
	}

	if ((map != original_map) || !vm_map_verify(map, &version)) {
		if (object_locks_dropped == FALSE) {
			if (m != VM_PAGE_NULL) {
				old_copy_object = m_object->copy;
				vm_object_unlock(m_object);
			} else {
				old_copy_object = VM_OBJECT_NULL;
				vm_object_unlock(object);
			}

			object_locks_dropped = TRUE;
		}

		/*
		 * no object locks are held at this point
		 */
		vm_object_t             retry_object;
		vm_object_offset_t      retry_offset;
		vm_prot_t               retry_prot;

		/*
		 * To avoid trying to write_lock the map while another
		 * thread has it read_locked (in vm_map_pageable), we
		 * do not try for write permission.  If the page is
		 * still writable, we will get write permission.  If it
		 * is not, or has been marked needs_copy, we enter the
		 * mapping without write permission, and will merely
		 * take another fault.
		 */
		map = original_map;

		kr = vm_map_lookup_locked(&map, vaddr,
		    fault_type & ~VM_PROT_WRITE,
		    OBJECT_LOCK_EXCLUSIVE, &version,
		    &retry_object, &retry_offset, &retry_prot,
		    &wired,
		    &fault_info,
		    &real_map);
		pmap = real_map->pmap;

		if (kr != KERN_SUCCESS) {
			vm_map_unlock_read(map);

			if (m != VM_PAGE_NULL) {
				assert(VM_PAGE_OBJECT(m) == m_object);

				/*
				 * retake the lock so that
				 * we can drop the paging reference
				 * in vm_fault_cleanup and do the
				 * PAGE_WAKEUP_DONE in RELEASE_PAGE
				 */
				vm_object_lock(m_object);

				RELEASE_PAGE(m);

				vm_fault_cleanup(m_object, top_page);
			} else {
				/*
				 * retake the lock so that
				 * we can drop the paging reference
				 * in vm_fault_cleanup
				 */
				vm_object_lock(object);

				vm_fault_cleanup(object, top_page);
			}
			vm_object_deallocate(object);

			goto done;
		}
		vm_object_unlock(retry_object);

		if ((retry_object != object) || (retry_offset != offset)) {
			vm_map_unlock_read(map);
			if (real_map != map) {
				vm_map_unlock(real_map);
			}

			if (m != VM_PAGE_NULL) {
				assert(VM_PAGE_OBJECT(m) == m_object);

				/*
				 * retake the lock so that
				 * we can drop the paging reference
				 * in vm_fault_cleanup and do the
				 * PAGE_WAKEUP_DONE in RELEASE_PAGE
				 */
				vm_object_lock(m_object);

				RELEASE_PAGE(m);

				vm_fault_cleanup(m_object, top_page);
			} else {
				/*
				 * retake the lock so that
				 * we can drop the paging reference
				 * in vm_fault_cleanup
				 */
				vm_object_lock(object);

				vm_fault_cleanup(object, top_page);
			}
			vm_object_deallocate(object);

			goto RetryFault;
		}
		/*
		 * Check whether the protection has changed or the object
		 * has been copied while we left the map unlocked.
		 */
		if (pmap_has_prot_policy(retry_prot)) {
			/* If the pmap layer cares, pass the full set. */
			prot = retry_prot;
		} else {
			prot &= retry_prot;
		}
	}

	if (object_locks_dropped == TRUE) {
		if (m != VM_PAGE_NULL) {
			vm_object_lock(m_object);

			if (m_object->copy != old_copy_object) {
				/*
				 * The copy object changed while the top-level object
				 * was unlocked, so take away write permission.
				 */
				assert(!pmap_has_prot_policy(prot));
				prot &= ~VM_PROT_WRITE;
			}
		} else {
			vm_object_lock(object);
		}

		object_locks_dropped = FALSE;
	}

	if (!need_copy &&
	    !fault_info.no_copy_on_read &&
	    m != VM_PAGE_NULL &&
	    VM_PAGE_OBJECT(m) != object &&
	    !VM_PAGE_OBJECT(m)->pager_trusted &&
	    vm_protect_privileged_from_untrusted &&
	    !((prot & VM_PROT_EXECUTE) &&
	    VM_PAGE_OBJECT(m)->code_signed &&
	    cs_process_enforcement(NULL)) &&
	    current_proc_is_privileged()) {
		/*
		 * We found the page we want in an "untrusted" VM object
		 * down the shadow chain.  Since the target is "privileged"
		 * we want to perform a copy-on-read of that page, so that the
		 * mapped object gets a stable copy and does not have to
		 * rely on the "untrusted" object to provide the same
		 * contents if the page gets reclaimed and has to be paged
		 * in again later on.
		 *
		 * Special case: if the mapping is executable and the untrusted
		 * object is code-signed and the process is "cs_enforced", we
		 * do not copy-on-read because that would break code-signing
		 * enforcement expectations (an executable page must belong
		 * to a code-signed object) and we can rely on code-signing
		 * to re-validate the page if it gets evicted and paged back in.
		 */
//		printf("COPY-ON-READ %s:%d map %p vaddr 0x%llx obj %p offset 0x%llx found page %p (obj %p offset 0x%llx) UNTRUSTED -> need copy-on-read\n", __FUNCTION__, __LINE__, map, (uint64_t)vaddr, object, offset, m, VM_PAGE_OBJECT(m), m->vmp_offset);
		vm_copied_on_read++;
		need_copy_on_read = TRUE;
		need_copy = TRUE;
	} else {
		need_copy_on_read = FALSE;
	}

	/*
	 * If we want to wire down this page, but no longer have
	 * adequate permissions, we must start all over.
	 * If we decided to copy-on-read, we must also start all over.
	 */
	if ((wired && (fault_type != (prot | VM_PROT_WRITE))) ||
	    need_copy_on_read) {
		vm_map_unlock_read(map);
		if (real_map != map) {
			vm_map_unlock(real_map);
		}

		if (m != VM_PAGE_NULL) {
			assert(VM_PAGE_OBJECT(m) == m_object);

			RELEASE_PAGE(m);

			vm_fault_cleanup(m_object, top_page);
		} else {
			vm_fault_cleanup(object, top_page);
		}

		vm_object_deallocate(object);

		goto RetryFault;
	}
	if (m != VM_PAGE_NULL) {
		/*
		 * Put this page into the physical map.
		 * We had to do the unlock above because pmap_enter
		 * may cause other faults.  The page may be on
		 * the pageout queues.  If the pageout daemon comes
		 * across the page, it will remove it from the queues.
		 */
		if (caller_pmap) {
			kr = vm_fault_enter(m,
			    caller_pmap,
			    caller_pmap_addr,
			    prot,
			    caller_prot,
			    wired,
			    change_wiring,
			    wire_tag,
			    &fault_info,
			    NULL,
			    &type_of_fault);
		} else {
			kr = vm_fault_enter(m,
			    pmap,
			    vaddr,
			    prot,
			    caller_prot,
			    wired,
			    change_wiring,
			    wire_tag,
			    &fault_info,
			    NULL,
			    &type_of_fault);
		}
		assert(VM_PAGE_OBJECT(m) == m_object);

		{
			int     event_code = 0;

			if (m_object->internal) {
				event_code = (MACHDBG_CODE(DBG_MACH_WORKINGSET, VM_REAL_FAULT_ADDR_INTERNAL));
			} else if (m_object->object_is_shared_cache) {
				event_code = (MACHDBG_CODE(DBG_MACH_WORKINGSET, VM_REAL_FAULT_ADDR_SHAREDCACHE));
			} else {
				event_code = (MACHDBG_CODE(DBG_MACH_WORKINGSET, VM_REAL_FAULT_ADDR_EXTERNAL));
			}

			KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, event_code, trace_real_vaddr, (fault_info.user_tag << 16) | (caller_prot << 8) | type_of_fault, m->vmp_offset, get_current_unique_pid(), 0);
			KDBG_FILTERED(MACHDBG_CODE(DBG_MACH_WORKINGSET, VM_REAL_FAULT_SLOW), get_current_unique_pid(), 0, 0, 0, 0);

			DTRACE_VM6(real_fault, vm_map_offset_t, real_vaddr, vm_map_offset_t, m->vmp_offset, int, event_code, int, caller_prot, int, type_of_fault, int, fault_info.user_tag);
		}
		if (kr != KERN_SUCCESS) {
			/* abort this page fault */
			vm_map_unlock_read(map);
			if (real_map != map) {
				vm_map_unlock(real_map);
			}
			PAGE_WAKEUP_DONE(m);
			vm_fault_cleanup(m_object, top_page);
			vm_object_deallocate(object);
			goto done;
		}
		if (physpage_p != NULL) {
			/* for vm_map_wire_and_extract() */
			*physpage_p = VM_PAGE_GET_PHYS_PAGE(m);
			if (prot & VM_PROT_WRITE) {
				vm_object_lock_assert_exclusive(m_object);
				m->vmp_dirty = TRUE;
			}
		}
	} else {
		vm_map_entry_t          entry;
		vm_map_offset_t         laddr;
		vm_map_offset_t         ldelta, hdelta;

		/*
		 * do a pmap block mapping from the physical address
		 * in the object
		 */

		if (real_map != map) {
			vm_map_unlock(real_map);
		}

		if (original_map != map) {
			vm_map_unlock_read(map);
			vm_map_lock_read(original_map);
			map = original_map;
		}
		real_map = map;

		laddr = vaddr;
		hdelta = 0xFFFFF000;
		ldelta = 0xFFFFF000;

		while (vm_map_lookup_entry(map, laddr, &entry)) {
			if (ldelta > (laddr - entry->vme_start)) {
				ldelta = laddr - entry->vme_start;
			}
			if (hdelta > (entry->vme_end - laddr)) {
				hdelta = entry->vme_end - laddr;
			}
			if (entry->is_sub_map) {
				laddr = ((laddr - entry->vme_start)
				    + VME_OFFSET(entry));
				vm_map_lock_read(VME_SUBMAP(entry));

				if (map != real_map) {
					vm_map_unlock_read(map);
				}
				if (entry->use_pmap) {
					vm_map_unlock_read(real_map);
					real_map = VME_SUBMAP(entry);
				}
				map = VME_SUBMAP(entry);
			} else {
				break;
			}
		}

		if (vm_map_lookup_entry(map, laddr, &entry) &&
		    (VME_OBJECT(entry) != NULL) &&
		    (VME_OBJECT(entry) == object)) {
			int superpage;

			if (!object->pager_created &&
			    object->phys_contiguous &&
			    VME_OFFSET(entry) == 0 &&
			    (entry->vme_end - entry->vme_start == object->vo_size) &&
			    VM_MAP_PAGE_ALIGNED(entry->vme_start, (object->vo_size - 1))) {
				superpage = VM_MEM_SUPERPAGE;
			} else {
				superpage = 0;
			}

			if (superpage && physpage_p) {
				/* for vm_map_wire_and_extract() */
				*physpage_p = (ppnum_t)
				    ((((vm_map_offset_t)
				    object->vo_shadow_offset)
				    + VME_OFFSET(entry)
				    + (laddr - entry->vme_start))
				    >> PAGE_SHIFT);
			}

			if (caller_pmap) {
				/*
				 * Set up a block mapped area
				 */
				assert((uint32_t)((ldelta + hdelta) >> PAGE_SHIFT) == ((ldelta + hdelta) >> PAGE_SHIFT));
				kr = pmap_map_block(caller_pmap,
				    (addr64_t)(caller_pmap_addr - ldelta),
				    (ppnum_t)((((vm_map_offset_t) (VME_OBJECT(entry)->vo_shadow_offset)) +
				    VME_OFFSET(entry) + (laddr - entry->vme_start) - ldelta) >> PAGE_SHIFT),
				    (uint32_t)((ldelta + hdelta) >> PAGE_SHIFT), prot,
				    (VM_WIMG_MASK & (int)object->wimg_bits) | superpage, 0);

				if (kr != KERN_SUCCESS) {
					goto cleanup;
				}
			} else {
				/*
				 * Set up a block mapped area
				 */
				assert((uint32_t)((ldelta + hdelta) >> PAGE_SHIFT) == ((ldelta + hdelta) >> PAGE_SHIFT));
				kr = pmap_map_block(real_map->pmap,
				    (addr64_t)(vaddr - ldelta),
				    (ppnum_t)((((vm_map_offset_t)(VME_OBJECT(entry)->vo_shadow_offset)) +
				    VME_OFFSET(entry) + (laddr - entry->vme_start) - ldelta) >> PAGE_SHIFT),
				    (uint32_t)((ldelta + hdelta) >> PAGE_SHIFT), prot,
				    (VM_WIMG_MASK & (int)object->wimg_bits) | superpage, 0);

				if (kr != KERN_SUCCESS) {
					goto cleanup;
				}
			}
		}
	}

	/*
	 * Success
	 */
	kr = KERN_SUCCESS;

	/*
	 * TODO: could most of the done cases just use cleanup?
	 */
cleanup:
	/*
	 * Unlock everything, and return
	 */
	vm_map_unlock_read(map);
	if (real_map != map) {
		vm_map_unlock(real_map);
	}

	if (m != VM_PAGE_NULL) {
		assert(VM_PAGE_OBJECT(m) == m_object);

		if (!m_object->internal && (fault_type & VM_PROT_WRITE)) {
			vm_object_paging_begin(m_object);

			assert(written_on_object == VM_OBJECT_NULL);
			written_on_object = m_object;
			written_on_pager = m_object->pager;
			written_on_offset = m_object->paging_offset + m->vmp_offset;
		}
		PAGE_WAKEUP_DONE(m);

		vm_fault_cleanup(m_object, top_page);
	} else {
		vm_fault_cleanup(object, top_page);
	}

	vm_object_deallocate(object);

#undef  RELEASE_PAGE

done:
	thread_interrupt_level(interruptible_state);

	if (resilient_media_object != VM_OBJECT_NULL) {
		assert(resilient_media_retry);
		assert(resilient_media_offset != (vm_object_offset_t)-1);
		/* release extra reference on failed object */
//             printf("FBDP %s:%d resilient_media_object %p deallocate\n", __FUNCTION__, __LINE__, resilient_media_object);
		vm_object_deallocate(resilient_media_object);
		resilient_media_object = VM_OBJECT_NULL;
		resilient_media_offset = (vm_object_offset_t)-1;
		resilient_media_retry = FALSE;
	}
	assert(!resilient_media_retry);

	/*
	 * Only I/O throttle on faults which cause a pagein/swapin.
	 */
	if ((type_of_fault == DBG_PAGEIND_FAULT) || (type_of_fault == DBG_PAGEINV_FAULT) || (type_of_fault == DBG_COMPRESSOR_SWAPIN_FAULT)) {
		throttle_lowpri_io(1);
	} else {
		if (kr == KERN_SUCCESS && type_of_fault != DBG_CACHE_HIT_FAULT && type_of_fault != DBG_GUARD_FAULT) {
			if ((throttle_delay = vm_page_throttled(TRUE))) {
				if (vm_debug_events) {
					if (type_of_fault == DBG_COMPRESSOR_FAULT) {
						VM_DEBUG_EVENT(vmf_compressordelay, VMF_COMPRESSORDELAY, DBG_FUNC_NONE, throttle_delay, 0, 0, 0);
					} else if (type_of_fault == DBG_COW_FAULT) {
						VM_DEBUG_EVENT(vmf_cowdelay, VMF_COWDELAY, DBG_FUNC_NONE, throttle_delay, 0, 0, 0);
					} else {
						VM_DEBUG_EVENT(vmf_zfdelay, VMF_ZFDELAY, DBG_FUNC_NONE, throttle_delay, 0, 0, 0);
					}
				}
				delay(throttle_delay);
			}
		}
	}

	if (written_on_object) {
		vnode_pager_dirtied(written_on_pager, written_on_offset, written_on_offset + PAGE_SIZE_64);

		vm_object_lock(written_on_object);
		vm_object_paging_end(written_on_object);
		vm_object_unlock(written_on_object);

		written_on_object = VM_OBJECT_NULL;
	}

	if (rtfault) {
		vm_record_rtfault(cthread, fstart, trace_vaddr, type_of_fault);
	}

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    (MACHDBG_CODE(DBG_MACH_VM, 2)) | DBG_FUNC_END,
	    ((uint64_t)trace_vaddr >> 32),
	    trace_vaddr,
	    kr,
	    type_of_fault,
	    0);

	return kr;
}

/*
 *	vm_fault_wire:
 *
 *	Wire down a range of virtual addresses in a map.
 */
kern_return_t
vm_fault_wire(
	vm_map_t        map,
	vm_map_entry_t  entry,
	vm_prot_t       prot,
	vm_tag_t        wire_tag,
	pmap_t          pmap,
	vm_map_offset_t pmap_addr,
	ppnum_t         *physpage_p)
{
	vm_map_offset_t va;
	vm_map_offset_t end_addr = entry->vme_end;
	kern_return_t   rc;

	assert(entry->in_transition);

	if ((VME_OBJECT(entry) != NULL) &&
	    !entry->is_sub_map &&
	    VME_OBJECT(entry)->phys_contiguous) {
		return KERN_SUCCESS;
	}

	/*
	 *	Inform the physical mapping system that the
	 *	range of addresses may not fault, so that
	 *	page tables and such can be locked down as well.
	 */

	pmap_pageable(pmap, pmap_addr,
	    pmap_addr + (end_addr - entry->vme_start), FALSE);

	/*
	 *	We simulate a fault to get the page and enter it
	 *	in the physical map.
	 */

	for (va = entry->vme_start; va < end_addr; va += PAGE_SIZE) {
		rc = vm_fault_wire_fast(map, va, prot, wire_tag, entry, pmap,
		    pmap_addr + (va - entry->vme_start),
		    physpage_p);
		if (rc != KERN_SUCCESS) {
			rc = vm_fault_internal(map, va, prot, TRUE, wire_tag,
			    ((pmap == kernel_pmap)
			    ? THREAD_UNINT
			    : THREAD_ABORTSAFE),
			    pmap,
			    (pmap_addr +
			    (va - entry->vme_start)),
			    physpage_p);
			DTRACE_VM2(softlock, int, 1, (uint64_t *), NULL);
		}

		if (rc != KERN_SUCCESS) {
			struct vm_map_entry     tmp_entry = *entry;

			/* unwire wired pages */
			tmp_entry.vme_end = va;
			vm_fault_unwire(map,
			    &tmp_entry, FALSE, pmap, pmap_addr);

			return rc;
		}
	}
	return KERN_SUCCESS;
}

/*
 *	vm_fault_unwire:
 *
 *	Unwire a range of virtual addresses in a map.
 */
void
vm_fault_unwire(
	vm_map_t        map,
	vm_map_entry_t  entry,
	boolean_t       deallocate,
	pmap_t          pmap,
	vm_map_offset_t pmap_addr)
{
	vm_map_offset_t va;
	vm_map_offset_t end_addr = entry->vme_end;
	vm_object_t             object;
	struct vm_object_fault_info fault_info = {};
	unsigned int    unwired_pages;

	object = (entry->is_sub_map) ? VM_OBJECT_NULL : VME_OBJECT(entry);

	/*
	 * If it's marked phys_contiguous, then vm_fault_wire() didn't actually
	 * do anything since such memory is wired by default.  So we don't have
	 * anything to undo here.
	 */

	if (object != VM_OBJECT_NULL && object->phys_contiguous) {
		return;
	}

	fault_info.interruptible = THREAD_UNINT;
	fault_info.behavior = entry->behavior;
	fault_info.user_tag = VME_ALIAS(entry);
	if (entry->iokit_acct ||
	    (!entry->is_sub_map && !entry->use_pmap)) {
		fault_info.pmap_options |= PMAP_OPTIONS_ALT_ACCT;
	}
	fault_info.lo_offset = VME_OFFSET(entry);
	fault_info.hi_offset = (entry->vme_end - entry->vme_start) + VME_OFFSET(entry);
	fault_info.no_cache = entry->no_cache;
	fault_info.stealth = TRUE;

	unwired_pages = 0;

	/*
	 *	Since the pages are wired down, we must be able to
	 *	get their mappings from the physical map system.
	 */

	for (va = entry->vme_start; va < end_addr; va += PAGE_SIZE) {
		if (object == VM_OBJECT_NULL) {
			if (pmap) {
				pmap_change_wiring(pmap,
				    pmap_addr + (va - entry->vme_start), FALSE);
			}
			(void) vm_fault(map, va, VM_PROT_NONE,
			    TRUE, VM_KERN_MEMORY_NONE, THREAD_UNINT, pmap, pmap_addr);
		} else {
			vm_prot_t       prot;
			vm_page_t       result_page;
			vm_page_t       top_page;
			vm_object_t     result_object;
			vm_fault_return_t result;

			/* cap cluster size at maximum UPL size */
			upl_size_t cluster_size;
			if (os_sub_overflow(end_addr, va, &cluster_size)) {
				cluster_size = 0 - (upl_size_t)PAGE_SIZE;
			}
			fault_info.cluster_size = cluster_size;

			do {
				prot = VM_PROT_NONE;

				vm_object_lock(object);
				vm_object_paging_begin(object);
				result_page = VM_PAGE_NULL;
				result = vm_fault_page(
					object,
					(VME_OFFSET(entry) +
					(va - entry->vme_start)),
					VM_PROT_NONE, TRUE,
					FALSE, /* page not looked up */
					&prot, &result_page, &top_page,
					(int *)0,
					NULL, map->no_zero_fill,
					FALSE, &fault_info);
			} while (result == VM_FAULT_RETRY);

			/*
			 * If this was a mapping to a file on a device that has been forcibly
			 * unmounted, then we won't get a page back from vm_fault_page().  Just
			 * move on to the next one in case the remaining pages are mapped from
			 * different objects.  During a forced unmount, the object is terminated
			 * so the alive flag will be false if this happens.  A forced unmount will
			 * will occur when an external disk is unplugged before the user does an
			 * eject, so we don't want to panic in that situation.
			 */

			if (result == VM_FAULT_MEMORY_ERROR && !object->alive) {
				continue;
			}

			if (result == VM_FAULT_MEMORY_ERROR &&
			    object == kernel_object) {
				/*
				 * This must have been allocated with
				 * KMA_KOBJECT and KMA_VAONLY and there's
				 * no physical page at this offset.
				 * We're done (no page to free).
				 */
				assert(deallocate);
				continue;
			}

			if (result != VM_FAULT_SUCCESS) {
				panic("vm_fault_unwire: failure");
			}

			result_object = VM_PAGE_OBJECT(result_page);

			if (deallocate) {
				assert(VM_PAGE_GET_PHYS_PAGE(result_page) !=
				    vm_page_fictitious_addr);
				pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(result_page));
				if (VM_PAGE_WIRED(result_page)) {
					unwired_pages++;
				}
				VM_PAGE_FREE(result_page);
			} else {
				if ((pmap) && (VM_PAGE_GET_PHYS_PAGE(result_page) != vm_page_guard_addr)) {
					pmap_change_wiring(pmap,
					    pmap_addr + (va - entry->vme_start), FALSE);
				}


				if (VM_PAGE_WIRED(result_page)) {
					vm_page_lockspin_queues();
					vm_page_unwire(result_page, TRUE);
					vm_page_unlock_queues();
					unwired_pages++;
				}
				if (entry->zero_wired_pages) {
					pmap_zero_page(VM_PAGE_GET_PHYS_PAGE(result_page));
					entry->zero_wired_pages = FALSE;
				}

				PAGE_WAKEUP_DONE(result_page);
			}
			vm_fault_cleanup(result_object, top_page);
		}
	}

	/*
	 *	Inform the physical mapping system that the range
	 *	of addresses may fault, so that page tables and
	 *	such may be unwired themselves.
	 */

	pmap_pageable(pmap, pmap_addr,
	    pmap_addr + (end_addr - entry->vme_start), TRUE);

	if (kernel_object == object) {
		vm_tag_update_size(fault_info.user_tag, -ptoa_64(unwired_pages));
	}
}

/*
 *	vm_fault_wire_fast:
 *
 *	Handle common case of a wire down page fault at the given address.
 *	If successful, the page is inserted into the associated physical map.
 *	The map entry is passed in to avoid the overhead of a map lookup.
 *
 *	NOTE: the given address should be truncated to the
 *	proper page address.
 *
 *	KERN_SUCCESS is returned if the page fault is handled; otherwise,
 *	a standard error specifying why the fault is fatal is returned.
 *
 *	The map in question must be referenced, and remains so.
 *	Caller has a read lock on the map.
 *
 *	This is a stripped version of vm_fault() for wiring pages.  Anything
 *	other than the common case will return KERN_FAILURE, and the caller
 *	is expected to call vm_fault().
 */
static kern_return_t
vm_fault_wire_fast(
	__unused vm_map_t       map,
	vm_map_offset_t va,
	__unused vm_prot_t       caller_prot,
	vm_tag_t        wire_tag,
	vm_map_entry_t  entry,
	pmap_t          pmap,
	vm_map_offset_t pmap_addr,
	ppnum_t         *physpage_p)
{
	vm_object_t             object;
	vm_object_offset_t      offset;
	vm_page_t               m;
	vm_prot_t               prot;
	thread_t                thread = current_thread();
	int                     type_of_fault;
	kern_return_t           kr;
	struct vm_object_fault_info fault_info = {};

	VM_STAT_INCR(faults);

	if (thread != THREAD_NULL && thread->task != TASK_NULL) {
		thread->task->faults++;
	}

/*
 *	Recovery actions
 */

#undef  RELEASE_PAGE
#define RELEASE_PAGE(m) {                               \
	PAGE_WAKEUP_DONE(m);                            \
	vm_page_lockspin_queues();                      \
	vm_page_unwire(m, TRUE);                        \
	vm_page_unlock_queues();                        \
}


#undef  UNLOCK_THINGS
#define UNLOCK_THINGS   {                               \
	vm_object_paging_end(object);                      \
	vm_object_unlock(object);                          \
}

#undef  UNLOCK_AND_DEALLOCATE
#define UNLOCK_AND_DEALLOCATE   {                       \
	UNLOCK_THINGS;                                  \
	vm_object_deallocate(object);                   \
}
/*
 *	Give up and have caller do things the hard way.
 */

#define GIVE_UP {                                       \
	UNLOCK_AND_DEALLOCATE;                          \
	return(KERN_FAILURE);                           \
}


	/*
	 *	If this entry is not directly to a vm_object, bail out.
	 */
	if (entry->is_sub_map) {
		assert(physpage_p == NULL);
		return KERN_FAILURE;
	}

	/*
	 *	Find the backing store object and offset into it.
	 */

	object = VME_OBJECT(entry);
	offset = (va - entry->vme_start) + VME_OFFSET(entry);
	prot = entry->protection;

	/*
	 *	Make a reference to this object to prevent its
	 *	disposal while we are messing with it.
	 */

	vm_object_lock(object);
	vm_object_reference_locked(object);
	vm_object_paging_begin(object);

	/*
	 *	INVARIANTS (through entire routine):
	 *
	 *	1)	At all times, we must either have the object
	 *		lock or a busy page in some object to prevent
	 *		some other thread from trying to bring in
	 *		the same page.
	 *
	 *	2)	Once we have a busy page, we must remove it from
	 *		the pageout queues, so that the pageout daemon
	 *		will not grab it away.
	 *
	 */

	/*
	 *	Look for page in top-level object.  If it's not there or
	 *	there's something going on, give up.
	 */
	m = vm_page_lookup(object, offset);
	if ((m == VM_PAGE_NULL) || (m->vmp_busy) ||
	    (m->vmp_unusual && (m->vmp_error || m->vmp_restart || m->vmp_absent))) {
		GIVE_UP;
	}
	if (m->vmp_fictitious &&
	    VM_PAGE_GET_PHYS_PAGE(m) == vm_page_guard_addr) {
		/*
		 * Guard pages are fictitious pages and are never
		 * entered into a pmap, so let's say it's been wired...
		 */
		kr = KERN_SUCCESS;
		goto done;
	}

	/*
	 *	Wire the page down now.  All bail outs beyond this
	 *	point must unwire the page.
	 */

	vm_page_lockspin_queues();
	vm_page_wire(m, wire_tag, TRUE);
	vm_page_unlock_queues();

	/*
	 *	Mark page busy for other threads.
	 */
	assert(!m->vmp_busy);
	m->vmp_busy = TRUE;
	assert(!m->vmp_absent);

	/*
	 *	Give up if the page is being written and there's a copy object
	 */
	if ((object->copy != VM_OBJECT_NULL) && (prot & VM_PROT_WRITE)) {
		RELEASE_PAGE(m);
		GIVE_UP;
	}

	fault_info.user_tag = VME_ALIAS(entry);
	fault_info.pmap_options = 0;
	if (entry->iokit_acct ||
	    (!entry->is_sub_map && !entry->use_pmap)) {
		fault_info.pmap_options |= PMAP_OPTIONS_ALT_ACCT;
	}

	/*
	 *	Put this page into the physical map.
	 */
	type_of_fault = DBG_CACHE_HIT_FAULT;
	kr = vm_fault_enter(m,
	    pmap,
	    pmap_addr,
	    prot,
	    prot,
	    TRUE,                  /* wired */
	    FALSE,                 /* change_wiring */
	    wire_tag,
	    &fault_info,
	    NULL,
	    &type_of_fault);
	if (kr != KERN_SUCCESS) {
		RELEASE_PAGE(m);
		GIVE_UP;
	}

done:
	/*
	 *	Unlock everything, and return
	 */

	if (physpage_p) {
		/* for vm_map_wire_and_extract() */
		if (kr == KERN_SUCCESS) {
			assert(object == VM_PAGE_OBJECT(m));
			*physpage_p = VM_PAGE_GET_PHYS_PAGE(m);
			if (prot & VM_PROT_WRITE) {
				vm_object_lock_assert_exclusive(object);
				m->vmp_dirty = TRUE;
			}
		} else {
			*physpage_p = 0;
		}
	}

	PAGE_WAKEUP_DONE(m);
	UNLOCK_AND_DEALLOCATE;

	return kr;
}

/*
 *	Routine:	vm_fault_copy_cleanup
 *	Purpose:
 *		Release a page used by vm_fault_copy.
 */

static void
vm_fault_copy_cleanup(
	vm_page_t       page,
	vm_page_t       top_page)
{
	vm_object_t     object = VM_PAGE_OBJECT(page);

	vm_object_lock(object);
	PAGE_WAKEUP_DONE(page);
	if (!VM_PAGE_PAGEABLE(page)) {
		vm_page_lockspin_queues();
		if (!VM_PAGE_PAGEABLE(page)) {
			vm_page_activate(page);
		}
		vm_page_unlock_queues();
	}
	vm_fault_cleanup(object, top_page);
}

static void
vm_fault_copy_dst_cleanup(
	vm_page_t       page)
{
	vm_object_t     object;

	if (page != VM_PAGE_NULL) {
		object = VM_PAGE_OBJECT(page);
		vm_object_lock(object);
		vm_page_lockspin_queues();
		vm_page_unwire(page, TRUE);
		vm_page_unlock_queues();
		vm_object_paging_end(object);
		vm_object_unlock(object);
	}
}

/*
 *	Routine:	vm_fault_copy
 *
 *	Purpose:
 *		Copy pages from one virtual memory object to another --
 *		neither the source nor destination pages need be resident.
 *
 *		Before actually copying a page, the version associated with
 *		the destination address map wil be verified.
 *
 *	In/out conditions:
 *		The caller must hold a reference, but not a lock, to
 *		each of the source and destination objects and to the
 *		destination map.
 *
 *	Results:
 *		Returns KERN_SUCCESS if no errors were encountered in
 *		reading or writing the data.  Returns KERN_INTERRUPTED if
 *		the operation was interrupted (only possible if the
 *		"interruptible" argument is asserted).  Other return values
 *		indicate a permanent error in copying the data.
 *
 *		The actual amount of data copied will be returned in the
 *		"copy_size" argument.  In the event that the destination map
 *		verification failed, this amount may be less than the amount
 *		requested.
 */
kern_return_t
vm_fault_copy(
	vm_object_t             src_object,
	vm_object_offset_t      src_offset,
	vm_map_size_t           *copy_size,             /* INOUT */
	vm_object_t             dst_object,
	vm_object_offset_t      dst_offset,
	vm_map_t                dst_map,
	vm_map_version_t         *dst_version,
	int                     interruptible)
{
	vm_page_t               result_page;

	vm_page_t               src_page;
	vm_page_t               src_top_page;
	vm_prot_t               src_prot;

	vm_page_t               dst_page;
	vm_page_t               dst_top_page;
	vm_prot_t               dst_prot;

	vm_map_size_t           amount_left;
	vm_object_t             old_copy_object;
	vm_object_t             result_page_object = NULL;
	kern_return_t           error = 0;
	vm_fault_return_t       result;

	vm_map_size_t           part_size;
	struct vm_object_fault_info fault_info_src = {};
	struct vm_object_fault_info fault_info_dst = {};

	/*
	 * In order not to confuse the clustered pageins, align
	 * the different offsets on a page boundary.
	 */

#define RETURN(x)                                       \
	MACRO_BEGIN                                     \
	*copy_size -= amount_left;                      \
	MACRO_RETURN(x);                                \
	MACRO_END

	amount_left = *copy_size;

	fault_info_src.interruptible = interruptible;
	fault_info_src.behavior = VM_BEHAVIOR_SEQUENTIAL;
	fault_info_src.lo_offset = vm_object_trunc_page(src_offset);
	fault_info_src.hi_offset = fault_info_src.lo_offset + amount_left;
	fault_info_src.stealth = TRUE;

	fault_info_dst.interruptible = interruptible;
	fault_info_dst.behavior = VM_BEHAVIOR_SEQUENTIAL;
	fault_info_dst.lo_offset = vm_object_trunc_page(dst_offset);
	fault_info_dst.hi_offset = fault_info_dst.lo_offset + amount_left;
	fault_info_dst.stealth = TRUE;

	do { /* while (amount_left > 0) */
		/*
		 * There may be a deadlock if both source and destination
		 * pages are the same. To avoid this deadlock, the copy must
		 * start by getting the destination page in order to apply
		 * COW semantics if any.
		 */

RetryDestinationFault:;

		dst_prot = VM_PROT_WRITE | VM_PROT_READ;

		vm_object_lock(dst_object);
		vm_object_paging_begin(dst_object);

		/* cap cluster size at maximum UPL size */
		upl_size_t cluster_size;
		if (os_convert_overflow(amount_left, &cluster_size)) {
			cluster_size = 0 - (upl_size_t)PAGE_SIZE;
		}
		fault_info_dst.cluster_size = cluster_size;

		dst_page = VM_PAGE_NULL;
		result = vm_fault_page(dst_object,
		    vm_object_trunc_page(dst_offset),
		    VM_PROT_WRITE | VM_PROT_READ,
		    FALSE,
		    FALSE,                    /* page not looked up */
		    &dst_prot, &dst_page, &dst_top_page,
		    (int *)0,
		    &error,
		    dst_map->no_zero_fill,
		    FALSE, &fault_info_dst);
		switch (result) {
		case VM_FAULT_SUCCESS:
			break;
		case VM_FAULT_RETRY:
			goto RetryDestinationFault;
		case VM_FAULT_MEMORY_SHORTAGE:
			if (vm_page_wait(interruptible)) {
				goto RetryDestinationFault;
			}
		/* fall thru */
		case VM_FAULT_INTERRUPTED:
			RETURN(MACH_SEND_INTERRUPTED);
		case VM_FAULT_SUCCESS_NO_VM_PAGE:
			/* success but no VM page: fail the copy */
			vm_object_paging_end(dst_object);
			vm_object_unlock(dst_object);
		/*FALLTHROUGH*/
		case VM_FAULT_MEMORY_ERROR:
			if (error) {
				return error;
			} else {
				return KERN_MEMORY_ERROR;
			}
		default:
			panic("vm_fault_copy: unexpected error 0x%x from "
			    "vm_fault_page()\n", result);
		}
		assert((dst_prot & VM_PROT_WRITE) != VM_PROT_NONE);

		assert(dst_object == VM_PAGE_OBJECT(dst_page));
		old_copy_object = dst_object->copy;

		/*
		 * There exists the possiblity that the source and
		 * destination page are the same.  But we can't
		 * easily determine that now.  If they are the
		 * same, the call to vm_fault_page() for the
		 * destination page will deadlock.  To prevent this we
		 * wire the page so we can drop busy without having
		 * the page daemon steal the page.  We clean up the
		 * top page  but keep the paging reference on the object
		 * holding the dest page so it doesn't go away.
		 */

		vm_page_lockspin_queues();
		vm_page_wire(dst_page, VM_KERN_MEMORY_OSFMK, TRUE);
		vm_page_unlock_queues();
		PAGE_WAKEUP_DONE(dst_page);
		vm_object_unlock(dst_object);

		if (dst_top_page != VM_PAGE_NULL) {
			vm_object_lock(dst_object);
			VM_PAGE_FREE(dst_top_page);
			vm_object_paging_end(dst_object);
			vm_object_unlock(dst_object);
		}

RetrySourceFault:;

		if (src_object == VM_OBJECT_NULL) {
			/*
			 *	No source object.  We will just
			 *	zero-fill the page in dst_object.
			 */
			src_page = VM_PAGE_NULL;
			result_page = VM_PAGE_NULL;
		} else {
			vm_object_lock(src_object);
			src_page = vm_page_lookup(src_object,
			    vm_object_trunc_page(src_offset));
			if (src_page == dst_page) {
				src_prot = dst_prot;
				result_page = VM_PAGE_NULL;
			} else {
				src_prot = VM_PROT_READ;
				vm_object_paging_begin(src_object);

				/* cap cluster size at maximum UPL size */
				if (os_convert_overflow(amount_left, &cluster_size)) {
					cluster_size = 0 - (upl_size_t)PAGE_SIZE;
				}
				fault_info_src.cluster_size = cluster_size;

				result_page = VM_PAGE_NULL;
				result = vm_fault_page(
					src_object,
					vm_object_trunc_page(src_offset),
					VM_PROT_READ, FALSE,
					FALSE, /* page not looked up */
					&src_prot,
					&result_page, &src_top_page,
					(int *)0, &error, FALSE,
					FALSE, &fault_info_src);

				switch (result) {
				case VM_FAULT_SUCCESS:
					break;
				case VM_FAULT_RETRY:
					goto RetrySourceFault;
				case VM_FAULT_MEMORY_SHORTAGE:
					if (vm_page_wait(interruptible)) {
						goto RetrySourceFault;
					}
				/* fall thru */
				case VM_FAULT_INTERRUPTED:
					vm_fault_copy_dst_cleanup(dst_page);
					RETURN(MACH_SEND_INTERRUPTED);
				case VM_FAULT_SUCCESS_NO_VM_PAGE:
					/* success but no VM page: fail */
					vm_object_paging_end(src_object);
					vm_object_unlock(src_object);
				/*FALLTHROUGH*/
				case VM_FAULT_MEMORY_ERROR:
					vm_fault_copy_dst_cleanup(dst_page);
					if (error) {
						return error;
					} else {
						return KERN_MEMORY_ERROR;
					}
				default:
					panic("vm_fault_copy(2): unexpected "
					    "error 0x%x from "
					    "vm_fault_page()\n", result);
				}

				result_page_object = VM_PAGE_OBJECT(result_page);
				assert((src_top_page == VM_PAGE_NULL) ==
				    (result_page_object == src_object));
			}
			assert((src_prot & VM_PROT_READ) != VM_PROT_NONE);
			vm_object_unlock(result_page_object);
		}

		vm_map_lock_read(dst_map);

		if (!vm_map_verify(dst_map, dst_version)) {
			vm_map_unlock_read(dst_map);
			if (result_page != VM_PAGE_NULL && src_page != dst_page) {
				vm_fault_copy_cleanup(result_page, src_top_page);
			}
			vm_fault_copy_dst_cleanup(dst_page);
			break;
		}
		assert(dst_object == VM_PAGE_OBJECT(dst_page));

		vm_object_lock(dst_object);

		if (dst_object->copy != old_copy_object) {
			vm_object_unlock(dst_object);
			vm_map_unlock_read(dst_map);
			if (result_page != VM_PAGE_NULL && src_page != dst_page) {
				vm_fault_copy_cleanup(result_page, src_top_page);
			}
			vm_fault_copy_dst_cleanup(dst_page);
			break;
		}
		vm_object_unlock(dst_object);

		/*
		 *	Copy the page, and note that it is dirty
		 *	immediately.
		 */

		if (!page_aligned(src_offset) ||
		    !page_aligned(dst_offset) ||
		    !page_aligned(amount_left)) {
			vm_object_offset_t      src_po,
			    dst_po;

			src_po = src_offset - vm_object_trunc_page(src_offset);
			dst_po = dst_offset - vm_object_trunc_page(dst_offset);

			if (dst_po > src_po) {
				part_size = PAGE_SIZE - dst_po;
			} else {
				part_size = PAGE_SIZE - src_po;
			}
			if (part_size > (amount_left)) {
				part_size = amount_left;
			}

			if (result_page == VM_PAGE_NULL) {
				assert((vm_offset_t) dst_po == dst_po);
				assert((vm_size_t) part_size == part_size);
				vm_page_part_zero_fill(dst_page,
				    (vm_offset_t) dst_po,
				    (vm_size_t) part_size);
			} else {
				assert((vm_offset_t) src_po == src_po);
				assert((vm_offset_t) dst_po == dst_po);
				assert((vm_size_t) part_size == part_size);
				vm_page_part_copy(result_page,
				    (vm_offset_t) src_po,
				    dst_page,
				    (vm_offset_t) dst_po,
				    (vm_size_t)part_size);
				if (!dst_page->vmp_dirty) {
					vm_object_lock(dst_object);
					SET_PAGE_DIRTY(dst_page, TRUE);
					vm_object_unlock(dst_object);
				}
			}
		} else {
			part_size = PAGE_SIZE;

			if (result_page == VM_PAGE_NULL) {
				vm_page_zero_fill(dst_page);
			} else {
				vm_object_lock(result_page_object);
				vm_page_copy(result_page, dst_page);
				vm_object_unlock(result_page_object);

				if (!dst_page->vmp_dirty) {
					vm_object_lock(dst_object);
					SET_PAGE_DIRTY(dst_page, TRUE);
					vm_object_unlock(dst_object);
				}
			}
		}

		/*
		 *	Unlock everything, and return
		 */

		vm_map_unlock_read(dst_map);

		if (result_page != VM_PAGE_NULL && src_page != dst_page) {
			vm_fault_copy_cleanup(result_page, src_top_page);
		}
		vm_fault_copy_dst_cleanup(dst_page);

		amount_left -= part_size;
		src_offset += part_size;
		dst_offset += part_size;
	} while (amount_left > 0);

	RETURN(KERN_SUCCESS);
#undef  RETURN

	/*NOTREACHED*/
}

#if     VM_FAULT_CLASSIFY
/*
 *	Temporary statistics gathering support.
 */

/*
 *	Statistics arrays:
 */
#define VM_FAULT_TYPES_MAX      5
#define VM_FAULT_LEVEL_MAX      8

int     vm_fault_stats[VM_FAULT_TYPES_MAX][VM_FAULT_LEVEL_MAX];

#define VM_FAULT_TYPE_ZERO_FILL 0
#define VM_FAULT_TYPE_MAP_IN    1
#define VM_FAULT_TYPE_PAGER     2
#define VM_FAULT_TYPE_COPY      3
#define VM_FAULT_TYPE_OTHER     4


void
vm_fault_classify(vm_object_t           object,
    vm_object_offset_t    offset,
    vm_prot_t             fault_type)
{
	int             type, level = 0;
	vm_page_t       m;

	while (TRUE) {
		m = vm_page_lookup(object, offset);
		if (m != VM_PAGE_NULL) {
			if (m->vmp_busy || m->vmp_error || m->vmp_restart || m->vmp_absent) {
				type = VM_FAULT_TYPE_OTHER;
				break;
			}
			if (((fault_type & VM_PROT_WRITE) == 0) ||
			    ((level == 0) && object->copy == VM_OBJECT_NULL)) {
				type = VM_FAULT_TYPE_MAP_IN;
				break;
			}
			type = VM_FAULT_TYPE_COPY;
			break;
		} else {
			if (object->pager_created) {
				type = VM_FAULT_TYPE_PAGER;
				break;
			}
			if (object->shadow == VM_OBJECT_NULL) {
				type = VM_FAULT_TYPE_ZERO_FILL;
				break;
			}

			offset += object->vo_shadow_offset;
			object = object->shadow;
			level++;
			continue;
		}
	}

	if (level > VM_FAULT_LEVEL_MAX) {
		level = VM_FAULT_LEVEL_MAX;
	}

	vm_fault_stats[type][level] += 1;

	return;
}

/* cleanup routine to call from debugger */

void
vm_fault_classify_init(void)
{
	int type, level;

	for (type = 0; type < VM_FAULT_TYPES_MAX; type++) {
		for (level = 0; level < VM_FAULT_LEVEL_MAX; level++) {
			vm_fault_stats[type][level] = 0;
		}
	}

	return;
}
#endif  /* VM_FAULT_CLASSIFY */

vm_offset_t
kdp_lightweight_fault(vm_map_t map, vm_offset_t cur_target_addr)
{
	vm_map_entry_t  entry;
	vm_object_t     object;
	vm_offset_t     object_offset;
	vm_page_t       m;
	int             compressor_external_state, compressed_count_delta;
	int             compressor_flags = (C_DONT_BLOCK | C_KEEP | C_KDP);
	int             my_fault_type = VM_PROT_READ;
	kern_return_t   kr;

	if (not_in_kdp) {
		panic("kdp_lightweight_fault called from outside of debugger context");
	}

	assert(map != VM_MAP_NULL);

	assert((cur_target_addr & PAGE_MASK) == 0);
	if ((cur_target_addr & PAGE_MASK) != 0) {
		return 0;
	}

	if (kdp_lck_rw_lock_is_acquired_exclusive(&map->lock)) {
		return 0;
	}

	if (!vm_map_lookup_entry(map, cur_target_addr, &entry)) {
		return 0;
	}

	if (entry->is_sub_map) {
		return 0;
	}

	object = VME_OBJECT(entry);
	if (object == VM_OBJECT_NULL) {
		return 0;
	}

	object_offset = cur_target_addr - entry->vme_start + VME_OFFSET(entry);

	while (TRUE) {
		if (kdp_lck_rw_lock_is_acquired_exclusive(&object->Lock)) {
			return 0;
		}

		if (object->pager_created && (object->paging_in_progress ||
		    object->activity_in_progress)) {
			return 0;
		}

		m = kdp_vm_page_lookup(object, object_offset);

		if (m != VM_PAGE_NULL) {
			if ((object->wimg_bits & VM_WIMG_MASK) != VM_WIMG_DEFAULT) {
				return 0;
			}

			if (m->vmp_laundry || m->vmp_busy || m->vmp_free_when_done || m->vmp_absent || m->vmp_error || m->vmp_cleaning ||
			    m->vmp_overwriting || m->vmp_restart || m->vmp_unusual) {
				return 0;
			}

			assert(!m->vmp_private);
			if (m->vmp_private) {
				return 0;
			}

			assert(!m->vmp_fictitious);
			if (m->vmp_fictitious) {
				return 0;
			}

			assert(m->vmp_q_state != VM_PAGE_USED_BY_COMPRESSOR);
			if (m->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR) {
				return 0;
			}

			return ptoa(VM_PAGE_GET_PHYS_PAGE(m));
		}

		compressor_external_state = VM_EXTERNAL_STATE_UNKNOWN;

		if (object->pager_created && MUST_ASK_PAGER(object, object_offset, compressor_external_state)) {
			if (compressor_external_state == VM_EXTERNAL_STATE_EXISTS) {
				kr = vm_compressor_pager_get(object->pager, (object_offset + object->paging_offset),
				    kdp_compressor_decompressed_page_ppnum, &my_fault_type,
				    compressor_flags, &compressed_count_delta);
				if (kr == KERN_SUCCESS) {
					return kdp_compressor_decompressed_page_paddr;
				} else {
					return 0;
				}
			}
		}

		if (object->shadow == VM_OBJECT_NULL) {
			return 0;
		}

		object_offset += object->vo_shadow_offset;
		object = object->shadow;
	}
}

/*
 * vm_page_validate_cs_fast():
 * Performs a few quick checks to determine if the page's code signature
 * really needs to be fully validated.  It could:
 *	1. have been modified (i.e. automatically tainted),
 *	2. have already been validated,
 *	3. have already been found to be tainted,
 *	4. no longer have a backing store.
 * Returns FALSE if the page needs to be fully validated.
 */
static boolean_t
vm_page_validate_cs_fast(
	vm_page_t       page)
{
	vm_object_t     object;

	object = VM_PAGE_OBJECT(page);
	vm_object_lock_assert_held(object);

	if (page->vmp_wpmapped && !page->vmp_cs_tainted) {
		/*
		 * This page was mapped for "write" access sometime in the
		 * past and could still be modifiable in the future.
		 * Consider it tainted.
		 * [ If the page was already found to be "tainted", no
		 * need to re-validate. ]
		 */
		vm_object_lock_assert_exclusive(object);
		page->vmp_cs_validated = TRUE;
		page->vmp_cs_tainted = TRUE;
		if (cs_debug) {
			printf("CODESIGNING: %s: "
			    "page %p obj %p off 0x%llx "
			    "was modified\n",
			    __FUNCTION__,
			    page, object, page->vmp_offset);
		}
		vm_cs_validated_dirtied++;
	}

	if (page->vmp_cs_validated || page->vmp_cs_tainted) {
		return TRUE;
	}
	vm_object_lock_assert_exclusive(object);

#if CHECK_CS_VALIDATION_BITMAP
	kern_return_t kr;

	kr = vnode_pager_cs_check_validation_bitmap(
		object->pager,
		page->vmp_offset + object->paging_offset,
		CS_BITMAP_CHECK);
	if (kr == KERN_SUCCESS) {
		page->vmp_cs_validated = TRUE;
		page->vmp_cs_tainted = FALSE;
		vm_cs_bitmap_validated++;
		return TRUE;
	}
#endif /* CHECK_CS_VALIDATION_BITMAP */

	if (!object->alive || object->terminating || object->pager == NULL) {
		/*
		 * The object is terminating and we don't have its pager
		 * so we can't validate the data...
		 */
		return TRUE;
	}

	/* we need to really validate this page */
	vm_object_lock_assert_exclusive(object);
	return FALSE;
}

void
vm_page_validate_cs_mapped_slow(
	vm_page_t       page,
	const void      *kaddr)
{
	vm_object_t             object;
	memory_object_offset_t  mo_offset;
	memory_object_t         pager;
	struct vnode            *vnode;
	boolean_t               validated;
	unsigned                tainted;

	assert(page->vmp_busy);
	object = VM_PAGE_OBJECT(page);
	vm_object_lock_assert_exclusive(object);

	vm_cs_validates++;

	/*
	 * Since we get here to validate a page that was brought in by
	 * the pager, we know that this pager is all setup and ready
	 * by now.
	 */
	assert(object->code_signed);
	assert(!object->internal);
	assert(object->pager != NULL);
	assert(object->pager_ready);

	pager = object->pager;
	assert(object->paging_in_progress);
	vnode = vnode_pager_lookup_vnode(pager);
	mo_offset = page->vmp_offset + object->paging_offset;

	/* verify the SHA1 hash for this page */
	tainted = 0;
	validated = cs_validate_range(vnode,
	    pager,
	    mo_offset,
	    (const void *)((const char *)kaddr),
	    PAGE_SIZE_64,
	    &tainted);

	if (tainted & CS_VALIDATE_TAINTED) {
		page->vmp_cs_tainted = TRUE;
	}
	if (tainted & CS_VALIDATE_NX) {
		page->vmp_cs_nx = TRUE;
	}
	if (validated) {
		page->vmp_cs_validated = TRUE;
	}

#if CHECK_CS_VALIDATION_BITMAP
	if (page->vmp_cs_validated && !page->vmp_cs_tainted) {
		vnode_pager_cs_check_validation_bitmap(object->pager,
		    mo_offset,
		    CS_BITMAP_SET);
	}
#endif /* CHECK_CS_VALIDATION_BITMAP */
}

void
vm_page_validate_cs_mapped(
	vm_page_t       page,
	const void      *kaddr)
{
	if (!vm_page_validate_cs_fast(page)) {
		vm_page_validate_cs_mapped_slow(page, kaddr);
	}
}

void
vm_page_validate_cs(
	vm_page_t       page)
{
	vm_object_t             object;
	vm_object_offset_t      offset;
	vm_map_offset_t         koffset;
	vm_map_size_t           ksize;
	vm_offset_t             kaddr;
	kern_return_t           kr;
	boolean_t               busy_page;
	boolean_t               need_unmap;

	object = VM_PAGE_OBJECT(page);
	vm_object_lock_assert_held(object);

	if (vm_page_validate_cs_fast(page)) {
		return;
	}
	vm_object_lock_assert_exclusive(object);

	assert(object->code_signed);
	offset = page->vmp_offset;

	busy_page = page->vmp_busy;
	if (!busy_page) {
		/* keep page busy while we map (and unlock) the VM object */
		page->vmp_busy = TRUE;
	}

	/*
	 * Take a paging reference on the VM object
	 * to protect it from collapse or bypass,
	 * and keep it from disappearing too.
	 */
	vm_object_paging_begin(object);

	/* map the page in the kernel address space */
	ksize = PAGE_SIZE_64;
	koffset = 0;
	need_unmap = FALSE;
	kr = vm_paging_map_object(page,
	    object,
	    offset,
	    VM_PROT_READ,
	    FALSE,                       /* can't unlock object ! */
	    &ksize,
	    &koffset,
	    &need_unmap);
	if (kr != KERN_SUCCESS) {
		panic("%s: could not map page: 0x%x\n", __FUNCTION__, kr);
	}
	kaddr = CAST_DOWN(vm_offset_t, koffset);

	/* validate the mapped page */
	vm_page_validate_cs_mapped_slow(page, (const void *) kaddr);

	assert(page->vmp_busy);
	assert(object == VM_PAGE_OBJECT(page));
	vm_object_lock_assert_exclusive(object);

	if (!busy_page) {
		PAGE_WAKEUP_DONE(page);
	}
	if (need_unmap) {
		/* unmap the map from the kernel address space */
		vm_paging_unmap_object(object, koffset, koffset + ksize);
		koffset = 0;
		ksize = 0;
		kaddr = 0;
	}
	vm_object_paging_end(object);
}

void
vm_page_validate_cs_mapped_chunk(
	vm_page_t       page,
	const void      *kaddr,
	vm_offset_t     chunk_offset,
	vm_size_t       chunk_size,
	boolean_t       *validated_p,
	unsigned        *tainted_p)
{
	vm_object_t             object;
	vm_object_offset_t      offset, offset_in_page;
	memory_object_t         pager;
	struct vnode            *vnode;
	boolean_t               validated;
	unsigned                tainted;

	*validated_p = FALSE;
	*tainted_p = 0;

	assert(page->vmp_busy);
	object = VM_PAGE_OBJECT(page);
	vm_object_lock_assert_exclusive(object);

	assert(object->code_signed);
	offset = page->vmp_offset;

	if (!object->alive || object->terminating || object->pager == NULL) {
		/*
		 * The object is terminating and we don't have its pager
		 * so we can't validate the data...
		 */
		return;
	}
	/*
	 * Since we get here to validate a page that was brought in by
	 * the pager, we know that this pager is all setup and ready
	 * by now.
	 */
	assert(!object->internal);
	assert(object->pager != NULL);
	assert(object->pager_ready);

	pager = object->pager;
	assert(object->paging_in_progress);
	vnode = vnode_pager_lookup_vnode(pager);

	/* verify the signature for this chunk */
	offset_in_page = chunk_offset;
	assert(offset_in_page < PAGE_SIZE);

	tainted = 0;
	validated = cs_validate_range(vnode,
	    pager,
	    (object->paging_offset +
	    offset +
	    offset_in_page),
	    (const void *)((const char *)kaddr
	    + offset_in_page),
	    chunk_size,
	    &tainted);
	if (validated) {
		*validated_p = TRUE;
	}
	if (tainted) {
		*tainted_p = tainted;
	}
}

static void
vm_rtfrecord_lock(void)
{
	lck_spin_lock(&vm_rtfr_slock);
}

static void
vm_rtfrecord_unlock(void)
{
	lck_spin_unlock(&vm_rtfr_slock);
}

unsigned int
vmrtfaultinfo_bufsz(void)
{
	return vmrtf_num_records * sizeof(vm_rtfault_record_t);
}

#include <kern/backtrace.h>

static void
vm_record_rtfault(thread_t cthread, uint64_t fstart, vm_map_offset_t fault_vaddr, int type_of_fault)
{
	uint64_t fend = mach_continuous_time();

	uint64_t cfpc = 0;
	uint64_t ctid = cthread->thread_id;
	uint64_t cupid = get_current_unique_pid();

	uintptr_t bpc = 0;
	int btr = 0;
	bool u64 = false;

	/* Capture a single-frame backtrace; this extracts just the program
	 * counter at the point of the fault into "bpc", and should perform no
	 * further user stack traversals, thus avoiding copyin()s and further
	 * faults.
	 */
	unsigned int bfrs = backtrace_thread_user(cthread, &bpc, 1U, &btr, &u64, NULL);

	if ((btr == 0) && (bfrs > 0)) {
		cfpc = bpc;
	}

	assert((fstart != 0) && fend >= fstart);
	vm_rtfrecord_lock();
	assert(vmrtfrs.vmrtfr_curi <= vmrtfrs.vmrtfr_maxi);

	vmrtfrs.vmrtf_total++;
	vm_rtfault_record_t *cvmr = &vmrtfrs.vm_rtf_records[vmrtfrs.vmrtfr_curi++];

	cvmr->rtfabstime = fstart;
	cvmr->rtfduration = fend - fstart;
	cvmr->rtfaddr = fault_vaddr;
	cvmr->rtfpc = cfpc;
	cvmr->rtftype = type_of_fault;
	cvmr->rtfupid = cupid;
	cvmr->rtftid = ctid;

	if (vmrtfrs.vmrtfr_curi > vmrtfrs.vmrtfr_maxi) {
		vmrtfrs.vmrtfr_curi = 0;
	}

	vm_rtfrecord_unlock();
}

int
vmrtf_extract(uint64_t cupid, __unused boolean_t isroot, int vrecordsz, void *vrecords, int *vmrtfrv)
{
	vm_rtfault_record_t *cvmrd = vrecords;
	size_t residue = vrecordsz;
	int numextracted = 0;
	boolean_t early_exit = FALSE;

	vm_rtfrecord_lock();

	for (int vmfi = 0; vmfi <= vmrtfrs.vmrtfr_maxi; vmfi++) {
		if (residue < sizeof(vm_rtfault_record_t)) {
			early_exit = TRUE;
			break;
		}

		if (vmrtfrs.vm_rtf_records[vmfi].rtfupid != cupid) {
#if     DEVELOPMENT || DEBUG
			if (isroot == FALSE) {
				continue;
			}
#else
			continue;
#endif /* DEVDEBUG */
		}

		*cvmrd = vmrtfrs.vm_rtf_records[vmfi];
		cvmrd++;
		residue -= sizeof(vm_rtfault_record_t);
		numextracted++;
	}

	vm_rtfrecord_unlock();

	*vmrtfrv = numextracted;
	return early_exit;
}
