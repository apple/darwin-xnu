/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
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
 *	File:	vm/vm_pageout.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	The proverbial page-out daemon.
 */

#include <stdint.h>

#include <debug.h>
#include <mach_pagemap.h>
#include <mach_cluster_stats.h>

#include <mach/mach_types.h>
#include <mach/memory_object.h>
#include <mach/memory_object_default.h>
#include <mach/memory_object_control_server.h>
#include <mach/mach_host_server.h>
#include <mach/upl.h>
#include <mach/vm_map.h>
#include <mach/vm_param.h>
#include <mach/vm_statistics.h>
#include <mach/sdt.h>

#include <kern/kern_types.h>
#include <kern/counters.h>
#include <kern/host_statistics.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/sched.h>
#include <kern/thread.h>
#include <kern/kalloc.h>
#include <kern/policy_internal.h>
#include <kern/thread_group.h>

#include <machine/vm_tuning.h>
#include <machine/commpage.h>

#include <vm/pmap.h>
#include <vm/vm_compressor_pager.h>
#include <vm/vm_fault.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h> /* must be last */
#include <vm/memory_object.h>
#include <vm/vm_purgeable_internal.h>
#include <vm/vm_shared_region.h>
#include <vm/vm_compressor.h>

#include <san/kasan.h>

#if CONFIG_PHANTOM_CACHE
#include <vm/vm_phantom_cache.h>
#endif

#if UPL_DEBUG
#include <libkern/OSDebug.h>
#endif

extern int cs_debug;

extern void mbuf_drain(boolean_t);

#if VM_PRESSURE_EVENTS
#if CONFIG_JETSAM
extern unsigned int memorystatus_available_pages;
extern unsigned int memorystatus_available_pages_pressure;
extern unsigned int memorystatus_available_pages_critical;
#else /* CONFIG_JETSAM */
extern uint64_t memorystatus_available_pages;
extern uint64_t memorystatus_available_pages_pressure;
extern uint64_t memorystatus_available_pages_critical;
#endif /* CONFIG_JETSAM */

extern unsigned int memorystatus_frozen_count;
extern unsigned int memorystatus_suspended_count;
extern vm_pressure_level_t memorystatus_vm_pressure_level;

extern lck_mtx_t memorystatus_jetsam_fg_band_lock;
extern uint32_t memorystatus_jetsam_fg_band_waiters;

void vm_pressure_response(void);
extern void consider_vm_pressure_events(void);

#define MEMORYSTATUS_SUSPENDED_THRESHOLD  4
#endif /* VM_PRESSURE_EVENTS */

thread_t  vm_pageout_scan_thread = THREAD_NULL;
boolean_t vps_dynamic_priority_enabled = FALSE;

#ifndef VM_PAGEOUT_BURST_INACTIVE_THROTTLE  /* maximum iterations of the inactive queue w/o stealing/cleaning a page */
#ifdef  CONFIG_EMBEDDED
#define VM_PAGEOUT_BURST_INACTIVE_THROTTLE 1024
#else
#define VM_PAGEOUT_BURST_INACTIVE_THROTTLE 4096
#endif
#endif

#ifndef VM_PAGEOUT_DEADLOCK_RELIEF
#define VM_PAGEOUT_DEADLOCK_RELIEF 100  /* number of pages to move to break deadlock */
#endif

#ifndef VM_PAGE_LAUNDRY_MAX
#define VM_PAGE_LAUNDRY_MAX     128UL   /* maximum pageouts on a given pageout queue */
#endif  /* VM_PAGEOUT_LAUNDRY_MAX */

#ifndef VM_PAGEOUT_BURST_WAIT
#define VM_PAGEOUT_BURST_WAIT   1       /* milliseconds */
#endif  /* VM_PAGEOUT_BURST_WAIT */

#ifndef VM_PAGEOUT_EMPTY_WAIT
#define VM_PAGEOUT_EMPTY_WAIT   50      /* milliseconds */
#endif  /* VM_PAGEOUT_EMPTY_WAIT */

#ifndef VM_PAGEOUT_DEADLOCK_WAIT
#define VM_PAGEOUT_DEADLOCK_WAIT 100    /* milliseconds */
#endif  /* VM_PAGEOUT_DEADLOCK_WAIT */

#ifndef VM_PAGEOUT_IDLE_WAIT
#define VM_PAGEOUT_IDLE_WAIT    10      /* milliseconds */
#endif  /* VM_PAGEOUT_IDLE_WAIT */

#ifndef VM_PAGEOUT_SWAP_WAIT
#define VM_PAGEOUT_SWAP_WAIT    10      /* milliseconds */
#endif  /* VM_PAGEOUT_SWAP_WAIT */


#ifndef VM_PAGE_SPECULATIVE_TARGET
#define VM_PAGE_SPECULATIVE_TARGET(total) ((total) * 1 / (100 / vm_pageout_state.vm_page_speculative_percentage))
#endif /* VM_PAGE_SPECULATIVE_TARGET */


/*
 *	To obtain a reasonable LRU approximation, the inactive queue
 *	needs to be large enough to give pages on it a chance to be
 *	referenced a second time.  This macro defines the fraction
 *	of active+inactive pages that should be inactive.
 *	The pageout daemon uses it to update vm_page_inactive_target.
 *
 *	If vm_page_free_count falls below vm_page_free_target and
 *	vm_page_inactive_count is below vm_page_inactive_target,
 *	then the pageout daemon starts running.
 */

#ifndef VM_PAGE_INACTIVE_TARGET
#define VM_PAGE_INACTIVE_TARGET(avail)  ((avail) * 1 / 2)
#endif  /* VM_PAGE_INACTIVE_TARGET */

/*
 *	Once the pageout daemon starts running, it keeps going
 *	until vm_page_free_count meets or exceeds vm_page_free_target.
 */

#ifndef VM_PAGE_FREE_TARGET
#ifdef  CONFIG_EMBEDDED
#define VM_PAGE_FREE_TARGET(free)       (15 + (free) / 100)
#else
#define VM_PAGE_FREE_TARGET(free)       (15 + (free) / 80)
#endif
#endif  /* VM_PAGE_FREE_TARGET */


/*
 *	The pageout daemon always starts running once vm_page_free_count
 *	falls below vm_page_free_min.
 */

#ifndef VM_PAGE_FREE_MIN
#ifdef  CONFIG_EMBEDDED
#define VM_PAGE_FREE_MIN(free)          (10 + (free) / 200)
#else
#define VM_PAGE_FREE_MIN(free)          (10 + (free) / 100)
#endif
#endif  /* VM_PAGE_FREE_MIN */

#ifdef  CONFIG_EMBEDDED
#define VM_PAGE_FREE_RESERVED_LIMIT     100
#define VM_PAGE_FREE_MIN_LIMIT          1500
#define VM_PAGE_FREE_TARGET_LIMIT       2000
#else
#define VM_PAGE_FREE_RESERVED_LIMIT     1700
#define VM_PAGE_FREE_MIN_LIMIT          3500
#define VM_PAGE_FREE_TARGET_LIMIT       4000
#endif

/*
 *	When vm_page_free_count falls below vm_page_free_reserved,
 *	only vm-privileged threads can allocate pages.  vm-privilege
 *	allows the pageout daemon and default pager (and any other
 *	associated threads needed for default pageout) to continue
 *	operation by dipping into the reserved pool of pages.
 */

#ifndef VM_PAGE_FREE_RESERVED
#define VM_PAGE_FREE_RESERVED(n)        \
	((unsigned) (6 * VM_PAGE_LAUNDRY_MAX) + (n))
#endif  /* VM_PAGE_FREE_RESERVED */

/*
 *	When we dequeue pages from the inactive list, they are
 *	reactivated (ie, put back on the active queue) if referenced.
 *	However, it is possible to starve the free list if other
 *	processors are referencing pages faster than we can turn off
 *	the referenced bit.  So we limit the number of reactivations
 *	we will make per call of vm_pageout_scan().
 */
#define VM_PAGE_REACTIVATE_LIMIT_MAX 20000

#ifndef VM_PAGE_REACTIVATE_LIMIT
#ifdef  CONFIG_EMBEDDED
#define VM_PAGE_REACTIVATE_LIMIT(avail) (VM_PAGE_INACTIVE_TARGET(avail) / 2)
#else
#define VM_PAGE_REACTIVATE_LIMIT(avail) (MAX((avail) * 1 / 20,VM_PAGE_REACTIVATE_LIMIT_MAX))
#endif
#endif  /* VM_PAGE_REACTIVATE_LIMIT */
#define VM_PAGEOUT_INACTIVE_FORCE_RECLAIM       1000

extern boolean_t hibernate_cleaning_in_progress;

/*
 * Forward declarations for internal routines.
 */
struct cq {
	struct vm_pageout_queue *q;
	void                    *current_chead;
	char                    *scratch_buf;
	int                     id;
};

struct cq ciq[MAX_COMPRESSOR_THREAD_COUNT];


#if VM_PRESSURE_EVENTS
void vm_pressure_thread(void);

boolean_t VM_PRESSURE_NORMAL_TO_WARNING(void);
boolean_t VM_PRESSURE_WARNING_TO_CRITICAL(void);

boolean_t VM_PRESSURE_WARNING_TO_NORMAL(void);
boolean_t VM_PRESSURE_CRITICAL_TO_WARNING(void);
#endif

void vm_pageout_garbage_collect(int);
static void vm_pageout_iothread_external(void);
static void vm_pageout_iothread_internal(struct cq *cq);
static void vm_pageout_adjust_eq_iothrottle(struct vm_pageout_queue *, boolean_t);

extern void vm_pageout_continue(void);
extern void vm_pageout_scan(void);

void vm_tests(void); /* forward */

boolean_t vm_pageout_running = FALSE;

uint32_t vm_page_upl_tainted = 0;
uint32_t vm_page_iopl_tainted = 0;

#if !CONFIG_EMBEDDED
static boolean_t vm_pageout_waiter  = FALSE;
#endif /* !CONFIG_EMBEDDED */


#if DEVELOPMENT || DEBUG
struct vm_pageout_debug vm_pageout_debug;
#endif
struct vm_pageout_vminfo vm_pageout_vminfo;
struct vm_pageout_state  vm_pageout_state;
struct vm_config         vm_config;

struct  vm_pageout_queue vm_pageout_queue_internal __attribute__((aligned(VM_PACKED_POINTER_ALIGNMENT)));
struct  vm_pageout_queue vm_pageout_queue_external __attribute__((aligned(VM_PACKED_POINTER_ALIGNMENT)));

int         vm_upl_wait_for_pages = 0;
vm_object_t vm_pageout_scan_wants_object = VM_OBJECT_NULL;

boolean_t(*volatile consider_buffer_cache_collect)(int) = NULL;

int     vm_debug_events = 0;

lck_grp_t vm_pageout_lck_grp;

#if CONFIG_MEMORYSTATUS
extern boolean_t memorystatus_kill_on_VM_page_shortage(boolean_t async);

uint32_t vm_pageout_memorystatus_fb_factor_nr = 5;
uint32_t vm_pageout_memorystatus_fb_factor_dr = 2;

#endif



/*
 *	Routine:	vm_pageout_object_terminate
 *	Purpose:
 *		Destroy the pageout_object, and perform all of the
 *		required cleanup actions.
 *
 *	In/Out conditions:
 *		The object must be locked, and will be returned locked.
 */
void
vm_pageout_object_terminate(
	vm_object_t     object)
{
	vm_object_t     shadow_object;

	/*
	 * Deal with the deallocation (last reference) of a pageout object
	 * (used for cleaning-in-place) by dropping the paging references/
	 * freeing pages in the original object.
	 */

	assert(object->pageout);
	shadow_object = object->shadow;
	vm_object_lock(shadow_object);

	while (!vm_page_queue_empty(&object->memq)) {
		vm_page_t               p, m;
		vm_object_offset_t      offset;

		p = (vm_page_t) vm_page_queue_first(&object->memq);

		assert(p->vmp_private);
		assert(p->vmp_free_when_done);
		p->vmp_free_when_done = FALSE;
		assert(!p->vmp_cleaning);
		assert(!p->vmp_laundry);

		offset = p->vmp_offset;
		VM_PAGE_FREE(p);
		p = VM_PAGE_NULL;

		m = vm_page_lookup(shadow_object,
		    offset + object->vo_shadow_offset);

		if (m == VM_PAGE_NULL) {
			continue;
		}

		assert((m->vmp_dirty) || (m->vmp_precious) ||
		    (m->vmp_busy && m->vmp_cleaning));

		/*
		 * Handle the trusted pager throttle.
		 * Also decrement the burst throttle (if external).
		 */
		vm_page_lock_queues();
		if (m->vmp_q_state == VM_PAGE_ON_PAGEOUT_Q) {
			vm_pageout_throttle_up(m);
		}

		/*
		 * Handle the "target" page(s). These pages are to be freed if
		 * successfully cleaned. Target pages are always busy, and are
		 * wired exactly once. The initial target pages are not mapped,
		 * (so cannot be referenced or modified) but converted target
		 * pages may have been modified between the selection as an
		 * adjacent page and conversion to a target.
		 */
		if (m->vmp_free_when_done) {
			assert(m->vmp_busy);
			assert(m->vmp_q_state == VM_PAGE_IS_WIRED);
			assert(m->vmp_wire_count == 1);
			m->vmp_cleaning = FALSE;
			m->vmp_free_when_done = FALSE;
			/*
			 * Revoke all access to the page. Since the object is
			 * locked, and the page is busy, this prevents the page
			 * from being dirtied after the pmap_disconnect() call
			 * returns.
			 *
			 * Since the page is left "dirty" but "not modifed", we
			 * can detect whether the page was redirtied during
			 * pageout by checking the modify state.
			 */
			if (pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(m)) & VM_MEM_MODIFIED) {
				SET_PAGE_DIRTY(m, FALSE);
			} else {
				m->vmp_dirty = FALSE;
			}

			if (m->vmp_dirty) {
				vm_page_unwire(m, TRUE);        /* reactivates */
				VM_STAT_INCR(reactivations);
				PAGE_WAKEUP_DONE(m);
			} else {
				vm_page_free(m);  /* clears busy, etc. */
			}
			vm_page_unlock_queues();
			continue;
		}
		/*
		 * Handle the "adjacent" pages. These pages were cleaned in
		 * place, and should be left alone.
		 * If prep_pin_count is nonzero, then someone is using the
		 * page, so make it active.
		 */
		if ((m->vmp_q_state == VM_PAGE_NOT_ON_Q) && !m->vmp_private) {
			if (m->vmp_reference) {
				vm_page_activate(m);
			} else {
				vm_page_deactivate(m);
			}
		}
		if (m->vmp_overwriting) {
			/*
			 * the (COPY_OUT_FROM == FALSE) request_page_list case
			 */
			if (m->vmp_busy) {
				/*
				 * We do not re-set m->vmp_dirty !
				 * The page was busy so no extraneous activity
				 * could have occurred. COPY_INTO is a read into the
				 * new pages. CLEAN_IN_PLACE does actually write
				 * out the pages but handling outside of this code
				 * will take care of resetting dirty. We clear the
				 * modify however for the Programmed I/O case.
				 */
				pmap_clear_modify(VM_PAGE_GET_PHYS_PAGE(m));

				m->vmp_busy = FALSE;
				m->vmp_absent = FALSE;
			} else {
				/*
				 * alternate (COPY_OUT_FROM == FALSE) request_page_list case
				 * Occurs when the original page was wired
				 * at the time of the list request
				 */
				assert(VM_PAGE_WIRED(m));
				vm_page_unwire(m, TRUE);        /* reactivates */
			}
			m->vmp_overwriting = FALSE;
		} else {
			m->vmp_dirty = FALSE;
		}
		m->vmp_cleaning = FALSE;

		/*
		 * Wakeup any thread waiting for the page to be un-cleaning.
		 */
		PAGE_WAKEUP(m);
		vm_page_unlock_queues();
	}
	/*
	 * Account for the paging reference taken in vm_paging_object_allocate.
	 */
	vm_object_activity_end(shadow_object);
	vm_object_unlock(shadow_object);

	assert(object->ref_count == 0);
	assert(object->paging_in_progress == 0);
	assert(object->activity_in_progress == 0);
	assert(object->resident_page_count == 0);
	return;
}

/*
 * Routine:	vm_pageclean_setup
 *
 * Purpose:	setup a page to be cleaned (made non-dirty), but not
 *		necessarily flushed from the VM page cache.
 *		This is accomplished by cleaning in place.
 *
 *		The page must not be busy, and new_object
 *		must be locked.
 *
 */
static void
vm_pageclean_setup(
	vm_page_t               m,
	vm_page_t               new_m,
	vm_object_t             new_object,
	vm_object_offset_t      new_offset)
{
	assert(!m->vmp_busy);
#if 0
	assert(!m->vmp_cleaning);
#endif

	pmap_clear_modify(VM_PAGE_GET_PHYS_PAGE(m));

	/*
	 * Mark original page as cleaning in place.
	 */
	m->vmp_cleaning = TRUE;
	SET_PAGE_DIRTY(m, FALSE);
	m->vmp_precious = FALSE;

	/*
	 * Convert the fictitious page to a private shadow of
	 * the real page.
	 */
	assert(new_m->vmp_fictitious);
	assert(VM_PAGE_GET_PHYS_PAGE(new_m) == vm_page_fictitious_addr);
	new_m->vmp_fictitious = FALSE;
	new_m->vmp_private = TRUE;
	new_m->vmp_free_when_done = TRUE;
	VM_PAGE_SET_PHYS_PAGE(new_m, VM_PAGE_GET_PHYS_PAGE(m));

	vm_page_lockspin_queues();
	vm_page_wire(new_m, VM_KERN_MEMORY_NONE, TRUE);
	vm_page_unlock_queues();

	vm_page_insert_wired(new_m, new_object, new_offset, VM_KERN_MEMORY_NONE);
	assert(!new_m->vmp_wanted);
	new_m->vmp_busy = FALSE;
}

/*
 *	Routine:	vm_pageout_initialize_page
 *	Purpose:
 *		Causes the specified page to be initialized in
 *		the appropriate memory object. This routine is used to push
 *		pages into a copy-object when they are modified in the
 *		permanent object.
 *
 *		The page is moved to a temporary object and paged out.
 *
 *	In/out conditions:
 *		The page in question must not be on any pageout queues.
 *		The object to which it belongs must be locked.
 *		The page must be busy, but not hold a paging reference.
 *
 *	Implementation:
 *		Move this page to a completely new object.
 */
void
vm_pageout_initialize_page(
	vm_page_t       m)
{
	vm_object_t             object;
	vm_object_offset_t      paging_offset;
	memory_object_t         pager;

	assert(VM_CONFIG_COMPRESSOR_IS_PRESENT);

	object = VM_PAGE_OBJECT(m);

	assert(m->vmp_busy);
	assert(object->internal);

	/*
	 *	Verify that we really want to clean this page
	 */
	assert(!m->vmp_absent);
	assert(!m->vmp_error);
	assert(m->vmp_dirty);

	/*
	 *	Create a paging reference to let us play with the object.
	 */
	paging_offset = m->vmp_offset + object->paging_offset;

	if (m->vmp_absent || m->vmp_error || m->vmp_restart || (!m->vmp_dirty && !m->vmp_precious)) {
		panic("reservation without pageout?"); /* alan */

		VM_PAGE_FREE(m);
		vm_object_unlock(object);

		return;
	}

	/*
	 * If there's no pager, then we can't clean the page.  This should
	 * never happen since this should be a copy object and therefore not
	 * an external object, so the pager should always be there.
	 */

	pager = object->pager;

	if (pager == MEMORY_OBJECT_NULL) {
		panic("missing pager for copy object");

		VM_PAGE_FREE(m);
		return;
	}

	/*
	 * set the page for future call to vm_fault_list_request
	 */
	pmap_clear_modify(VM_PAGE_GET_PHYS_PAGE(m));
	SET_PAGE_DIRTY(m, FALSE);

	/*
	 * keep the object from collapsing or terminating
	 */
	vm_object_paging_begin(object);
	vm_object_unlock(object);

	/*
	 *	Write the data to its pager.
	 *	Note that the data is passed by naming the new object,
	 *	not a virtual address; the pager interface has been
	 *	manipulated to use the "internal memory" data type.
	 *	[The object reference from its allocation is donated
	 *	to the eventual recipient.]
	 */
	memory_object_data_initialize(pager, paging_offset, PAGE_SIZE);

	vm_object_lock(object);
	vm_object_paging_end(object);
}


/*
 * vm_pageout_cluster:
 *
 * Given a page, queue it to the appropriate I/O thread,
 * which will page it out and attempt to clean adjacent pages
 * in the same operation.
 *
 * The object and queues must be locked. We will take a
 * paging reference to prevent deallocation or collapse when we
 * release the object lock back at the call site.  The I/O thread
 * is responsible for consuming this reference
 *
 * The page must not be on any pageout queue.
 */
#if DEVELOPMENT || DEBUG
vmct_stats_t vmct_stats;

int32_t vmct_active = 0;
uint64_t vm_compressor_epoch_start = 0;
uint64_t vm_compressor_epoch_stop = 0;

typedef enum vmct_state_t {
	VMCT_IDLE,
	VMCT_AWAKENED,
	VMCT_ACTIVE,
} vmct_state_t;
vmct_state_t vmct_state[MAX_COMPRESSOR_THREAD_COUNT];
#endif


void
vm_pageout_cluster(vm_page_t m)
{
	vm_object_t     object = VM_PAGE_OBJECT(m);
	struct          vm_pageout_queue *q;

	VM_PAGE_CHECK(m);
	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	vm_object_lock_assert_exclusive(object);

	/*
	 * Only a certain kind of page is appreciated here.
	 */
	assert((m->vmp_dirty || m->vmp_precious) && (!VM_PAGE_WIRED(m)));
	assert(!m->vmp_cleaning && !m->vmp_laundry);
	assert(m->vmp_q_state == VM_PAGE_NOT_ON_Q);

	/*
	 * protect the object from collapse or termination
	 */
	vm_object_activity_begin(object);

	if (object->internal == TRUE) {
		assert(VM_CONFIG_COMPRESSOR_IS_PRESENT);

		m->vmp_busy = TRUE;

		q = &vm_pageout_queue_internal;
	} else {
		q = &vm_pageout_queue_external;
	}

	/*
	 * pgo_laundry count is tied to the laundry bit
	 */
	m->vmp_laundry = TRUE;
	q->pgo_laundry++;

	m->vmp_q_state = VM_PAGE_ON_PAGEOUT_Q;
	vm_page_queue_enter(&q->pgo_pending, m, vmp_pageq);

	if (q->pgo_idle == TRUE) {
		q->pgo_idle = FALSE;
		thread_wakeup((event_t) &q->pgo_pending);
	}
	VM_PAGE_CHECK(m);
}


/*
 * A page is back from laundry or we are stealing it back from
 * the laundering state.  See if there are some pages waiting to
 * go to laundry and if we can let some of them go now.
 *
 * Object and page queues must be locked.
 */
void
vm_pageout_throttle_up(
	vm_page_t       m)
{
	struct vm_pageout_queue *q;
	vm_object_t      m_object;

	m_object = VM_PAGE_OBJECT(m);

	assert(m_object != VM_OBJECT_NULL);
	assert(m_object != kernel_object);

	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);
	vm_object_lock_assert_exclusive(m_object);

	if (m_object->internal == TRUE) {
		q = &vm_pageout_queue_internal;
	} else {
		q = &vm_pageout_queue_external;
	}

	if (m->vmp_q_state == VM_PAGE_ON_PAGEOUT_Q) {
		vm_page_queue_remove(&q->pgo_pending, m, vmp_pageq);
		m->vmp_q_state = VM_PAGE_NOT_ON_Q;

		VM_PAGE_ZERO_PAGEQ_ENTRY(m);

		vm_object_activity_end(m_object);

		VM_PAGEOUT_DEBUG(vm_page_steal_pageout_page, 1);
	}
	if (m->vmp_laundry == TRUE) {
		m->vmp_laundry = FALSE;
		q->pgo_laundry--;

		if (q->pgo_throttled == TRUE) {
			q->pgo_throttled = FALSE;
			thread_wakeup((event_t) &q->pgo_laundry);
		}
		if (q->pgo_draining == TRUE && q->pgo_laundry == 0) {
			q->pgo_draining = FALSE;
			thread_wakeup((event_t) (&q->pgo_laundry + 1));
		}
		VM_PAGEOUT_DEBUG(vm_pageout_throttle_up_count, 1);
	}
}


static void
vm_pageout_throttle_up_batch(
	struct vm_pageout_queue *q,
	int             batch_cnt)
{
	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);

	VM_PAGEOUT_DEBUG(vm_pageout_throttle_up_count, batch_cnt);

	q->pgo_laundry -= batch_cnt;

	if (q->pgo_throttled == TRUE) {
		q->pgo_throttled = FALSE;
		thread_wakeup((event_t) &q->pgo_laundry);
	}
	if (q->pgo_draining == TRUE && q->pgo_laundry == 0) {
		q->pgo_draining = FALSE;
		thread_wakeup((event_t) (&q->pgo_laundry + 1));
	}
}



/*
 * VM memory pressure monitoring.
 *
 * vm_pageout_scan() keeps track of the number of pages it considers and
 * reclaims, in the currently active vm_pageout_stat[vm_pageout_stat_now].
 *
 * compute_memory_pressure() is called every second from compute_averages()
 * and moves "vm_pageout_stat_now" forward, to start accumulating the number
 * of recalimed pages in a new vm_pageout_stat[] bucket.
 *
 * mach_vm_pressure_monitor() collects past statistics about memory pressure.
 * The caller provides the number of seconds ("nsecs") worth of statistics
 * it wants, up to 30 seconds.
 * It computes the number of pages reclaimed in the past "nsecs" seconds and
 * also returns the number of pages the system still needs to reclaim at this
 * moment in time.
 */
#if DEVELOPMENT || DEBUG
#define VM_PAGEOUT_STAT_SIZE    (30 * 8) + 1
#else
#define VM_PAGEOUT_STAT_SIZE    (1 * 8) + 1
#endif
struct vm_pageout_stat {
	unsigned long vm_page_active_count;
	unsigned long vm_page_speculative_count;
	unsigned long vm_page_inactive_count;
	unsigned long vm_page_anonymous_count;

	unsigned long vm_page_free_count;
	unsigned long vm_page_wire_count;
	unsigned long vm_page_compressor_count;

	unsigned long vm_page_pages_compressed;
	unsigned long vm_page_pageable_internal_count;
	unsigned long vm_page_pageable_external_count;
	unsigned long vm_page_xpmapped_external_count;

	unsigned int pages_grabbed;
	unsigned int pages_freed;

	unsigned int pages_compressed;
	unsigned int pages_grabbed_by_compressor;
	unsigned int failed_compressions;

	unsigned int pages_evicted;
	unsigned int pages_purged;

	unsigned int considered;
	unsigned int considered_bq_internal;
	unsigned int considered_bq_external;

	unsigned int skipped_external;
	unsigned int filecache_min_reactivations;

	unsigned int freed_speculative;
	unsigned int freed_cleaned;
	unsigned int freed_internal;
	unsigned int freed_external;

	unsigned int cleaned_dirty_external;
	unsigned int cleaned_dirty_internal;

	unsigned int inactive_referenced;
	unsigned int inactive_nolock;
	unsigned int reactivation_limit_exceeded;
	unsigned int forced_inactive_reclaim;

	unsigned int throttled_internal_q;
	unsigned int throttled_external_q;

	unsigned int phantom_ghosts_found;
	unsigned int phantom_ghosts_added;
} vm_pageout_stats[VM_PAGEOUT_STAT_SIZE] = {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, };

unsigned int vm_pageout_stat_now = 0;

#define VM_PAGEOUT_STAT_BEFORE(i) \
	(((i) == 0) ? VM_PAGEOUT_STAT_SIZE - 1 : (i) - 1)
#define VM_PAGEOUT_STAT_AFTER(i) \
	(((i) == VM_PAGEOUT_STAT_SIZE - 1) ? 0 : (i) + 1)

#if VM_PAGE_BUCKETS_CHECK
int vm_page_buckets_check_interval = 80; /* in eighths of a second */
#endif /* VM_PAGE_BUCKETS_CHECK */


void
record_memory_pressure(void);
void
record_memory_pressure(void)
{
	unsigned int vm_pageout_next;

#if VM_PAGE_BUCKETS_CHECK
	/* check the consistency of VM page buckets at regular interval */
	static int counter = 0;
	if ((++counter % vm_page_buckets_check_interval) == 0) {
		vm_page_buckets_check();
	}
#endif /* VM_PAGE_BUCKETS_CHECK */

	vm_pageout_state.vm_memory_pressure =
	    vm_pageout_stats[VM_PAGEOUT_STAT_BEFORE(vm_pageout_stat_now)].freed_speculative +
	    vm_pageout_stats[VM_PAGEOUT_STAT_BEFORE(vm_pageout_stat_now)].freed_cleaned +
	    vm_pageout_stats[VM_PAGEOUT_STAT_BEFORE(vm_pageout_stat_now)].freed_internal +
	    vm_pageout_stats[VM_PAGEOUT_STAT_BEFORE(vm_pageout_stat_now)].freed_external;

	commpage_set_memory_pressure((unsigned int)vm_pageout_state.vm_memory_pressure );

	/* move "now" forward */
	vm_pageout_next = VM_PAGEOUT_STAT_AFTER(vm_pageout_stat_now);

	bzero(&vm_pageout_stats[vm_pageout_next], sizeof(struct vm_pageout_stat));

	vm_pageout_stat_now = vm_pageout_next;
}


/*
 * IMPORTANT
 * mach_vm_ctl_page_free_wanted() is called indirectly, via
 * mach_vm_pressure_monitor(), when taking a stackshot. Therefore,
 * it must be safe in the restricted stackshot context. Locks and/or
 * blocking are not allowable.
 */
unsigned int
mach_vm_ctl_page_free_wanted(void)
{
	unsigned int page_free_target, page_free_count, page_free_wanted;

	page_free_target = vm_page_free_target;
	page_free_count = vm_page_free_count;
	if (page_free_target > page_free_count) {
		page_free_wanted = page_free_target - page_free_count;
	} else {
		page_free_wanted = 0;
	}

	return page_free_wanted;
}


/*
 * IMPORTANT:
 * mach_vm_pressure_monitor() is called when taking a stackshot, with
 * wait_for_pressure FALSE, so that code path must remain safe in the
 * restricted stackshot context. No blocking or locks are allowable.
 * on that code path.
 */

kern_return_t
mach_vm_pressure_monitor(
	boolean_t       wait_for_pressure,
	unsigned int    nsecs_monitored,
	unsigned int    *pages_reclaimed_p,
	unsigned int    *pages_wanted_p)
{
	wait_result_t   wr;
	unsigned int    vm_pageout_then, vm_pageout_now;
	unsigned int    pages_reclaimed;
	unsigned int    units_of_monitor;

	units_of_monitor = 8 * nsecs_monitored;
	/*
	 * We don't take the vm_page_queue_lock here because we don't want
	 * vm_pressure_monitor() to get in the way of the vm_pageout_scan()
	 * thread when it's trying to reclaim memory.  We don't need fully
	 * accurate monitoring anyway...
	 */

	if (wait_for_pressure) {
		/* wait until there's memory pressure */
		while (vm_page_free_count >= vm_page_free_target) {
			wr = assert_wait((event_t) &vm_page_free_wanted,
			    THREAD_INTERRUPTIBLE);
			if (wr == THREAD_WAITING) {
				wr = thread_block(THREAD_CONTINUE_NULL);
			}
			if (wr == THREAD_INTERRUPTED) {
				return KERN_ABORTED;
			}
			if (wr == THREAD_AWAKENED) {
				/*
				 * The memory pressure might have already
				 * been relieved but let's not block again
				 * and let's report that there was memory
				 * pressure at some point.
				 */
				break;
			}
		}
	}

	/* provide the number of pages the system wants to reclaim */
	if (pages_wanted_p != NULL) {
		*pages_wanted_p = mach_vm_ctl_page_free_wanted();
	}

	if (pages_reclaimed_p == NULL) {
		return KERN_SUCCESS;
	}

	/* provide number of pages reclaimed in the last "nsecs_monitored" */
	vm_pageout_now = vm_pageout_stat_now;
	pages_reclaimed = 0;
	for (vm_pageout_then =
	    VM_PAGEOUT_STAT_BEFORE(vm_pageout_now);
	    vm_pageout_then != vm_pageout_now &&
	    units_of_monitor-- != 0;
	    vm_pageout_then =
	    VM_PAGEOUT_STAT_BEFORE(vm_pageout_then)) {
		pages_reclaimed += vm_pageout_stats[vm_pageout_then].freed_speculative;
		pages_reclaimed += vm_pageout_stats[vm_pageout_then].freed_cleaned;
		pages_reclaimed += vm_pageout_stats[vm_pageout_then].freed_internal;
		pages_reclaimed += vm_pageout_stats[vm_pageout_then].freed_external;
	}
	*pages_reclaimed_p = pages_reclaimed;

	return KERN_SUCCESS;
}



#if DEVELOPMENT || DEBUG

static void
vm_pageout_disconnect_all_pages_in_queue(vm_page_queue_head_t *, int);

/*
 * condition variable used to make sure there is
 * only a single sweep going on at a time
 */
boolean_t       vm_pageout_disconnect_all_pages_active = FALSE;


void
vm_pageout_disconnect_all_pages()
{
	vm_page_lock_queues();

	if (vm_pageout_disconnect_all_pages_active == TRUE) {
		vm_page_unlock_queues();
		return;
	}
	vm_pageout_disconnect_all_pages_active = TRUE;
	vm_page_unlock_queues();

	vm_pageout_disconnect_all_pages_in_queue(&vm_page_queue_throttled, vm_page_throttled_count);
	vm_pageout_disconnect_all_pages_in_queue(&vm_page_queue_anonymous, vm_page_anonymous_count);
	vm_pageout_disconnect_all_pages_in_queue(&vm_page_queue_active, vm_page_active_count);

	vm_pageout_disconnect_all_pages_active = FALSE;
}


void
vm_pageout_disconnect_all_pages_in_queue(vm_page_queue_head_t *q, int qcount)
{
	vm_page_t       m;
	vm_object_t     t_object = NULL;
	vm_object_t     l_object = NULL;
	vm_object_t     m_object = NULL;
	int             delayed_unlock = 0;
	int             try_failed_count = 0;
	int             disconnected_count = 0;
	int             paused_count = 0;
	int             object_locked_count = 0;

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (MACHDBG_CODE(DBG_MACH_WORKINGSET, VM_DISCONNECT_ALL_PAGE_MAPPINGS)) | DBG_FUNC_START,
	    q, qcount, 0, 0, 0);

	vm_page_lock_queues();

	while (qcount && !vm_page_queue_empty(q)) {
		LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);

		m = (vm_page_t) vm_page_queue_first(q);
		m_object = VM_PAGE_OBJECT(m);

		/*
		 * check to see if we currently are working
		 * with the same object... if so, we've
		 * already got the lock
		 */
		if (m_object != l_object) {
			/*
			 * the object associated with candidate page is
			 * different from the one we were just working
			 * with... dump the lock if we still own it
			 */
			if (l_object != NULL) {
				vm_object_unlock(l_object);
				l_object = NULL;
			}
			if (m_object != t_object) {
				try_failed_count = 0;
			}

			/*
			 * Try to lock object; since we've alread got the
			 * page queues lock, we can only 'try' for this one.
			 * if the 'try' fails, we need to do a mutex_pause
			 * to allow the owner of the object lock a chance to
			 * run...
			 */
			if (!vm_object_lock_try_scan(m_object)) {
				if (try_failed_count > 20) {
					goto reenter_pg_on_q;
				}
				vm_page_unlock_queues();
				mutex_pause(try_failed_count++);
				vm_page_lock_queues();
				delayed_unlock = 0;

				paused_count++;

				t_object = m_object;
				continue;
			}
			object_locked_count++;

			l_object = m_object;
		}
		if (!m_object->alive || m->vmp_cleaning || m->vmp_laundry || m->vmp_busy || m->vmp_absent || m->vmp_error || m->vmp_free_when_done) {
			/*
			 * put it back on the head of its queue
			 */
			goto reenter_pg_on_q;
		}
		if (m->vmp_pmapped == TRUE) {
			pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(m));

			disconnected_count++;
		}
reenter_pg_on_q:
		vm_page_queue_remove(q, m, vmp_pageq);
		vm_page_queue_enter(q, m, vmp_pageq);

		qcount--;
		try_failed_count = 0;

		if (delayed_unlock++ > 128) {
			if (l_object != NULL) {
				vm_object_unlock(l_object);
				l_object = NULL;
			}
			lck_mtx_yield(&vm_page_queue_lock);
			delayed_unlock = 0;
		}
	}
	if (l_object != NULL) {
		vm_object_unlock(l_object);
		l_object = NULL;
	}
	vm_page_unlock_queues();

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (MACHDBG_CODE(DBG_MACH_WORKINGSET, VM_DISCONNECT_ALL_PAGE_MAPPINGS)) | DBG_FUNC_END,
	    q, disconnected_count, object_locked_count, paused_count, 0);
}

#endif


static void
vm_pageout_page_queue(vm_page_queue_head_t *, int);

/*
 * condition variable used to make sure there is
 * only a single sweep going on at a time
 */
boolean_t       vm_pageout_anonymous_pages_active = FALSE;


void
vm_pageout_anonymous_pages()
{
	if (VM_CONFIG_COMPRESSOR_IS_PRESENT) {
		vm_page_lock_queues();

		if (vm_pageout_anonymous_pages_active == TRUE) {
			vm_page_unlock_queues();
			return;
		}
		vm_pageout_anonymous_pages_active = TRUE;
		vm_page_unlock_queues();

		vm_pageout_page_queue(&vm_page_queue_throttled, vm_page_throttled_count);
		vm_pageout_page_queue(&vm_page_queue_anonymous, vm_page_anonymous_count);
		vm_pageout_page_queue(&vm_page_queue_active, vm_page_active_count);

		if (VM_CONFIG_SWAP_IS_PRESENT) {
			vm_consider_swapping();
		}

		vm_page_lock_queues();
		vm_pageout_anonymous_pages_active = FALSE;
		vm_page_unlock_queues();
	}
}


void
vm_pageout_page_queue(vm_page_queue_head_t *q, int qcount)
{
	vm_page_t       m;
	vm_object_t     t_object = NULL;
	vm_object_t     l_object = NULL;
	vm_object_t     m_object = NULL;
	int             delayed_unlock = 0;
	int             try_failed_count = 0;
	int             refmod_state;
	int             pmap_options;
	struct          vm_pageout_queue *iq;
	ppnum_t         phys_page;


	iq = &vm_pageout_queue_internal;

	vm_page_lock_queues();

	while (qcount && !vm_page_queue_empty(q)) {
		LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);

		if (VM_PAGE_Q_THROTTLED(iq)) {
			if (l_object != NULL) {
				vm_object_unlock(l_object);
				l_object = NULL;
			}
			iq->pgo_draining = TRUE;

			assert_wait((event_t) (&iq->pgo_laundry + 1), THREAD_INTERRUPTIBLE);
			vm_page_unlock_queues();

			thread_block(THREAD_CONTINUE_NULL);

			vm_page_lock_queues();
			delayed_unlock = 0;
			continue;
		}
		m = (vm_page_t) vm_page_queue_first(q);
		m_object = VM_PAGE_OBJECT(m);

		/*
		 * check to see if we currently are working
		 * with the same object... if so, we've
		 * already got the lock
		 */
		if (m_object != l_object) {
			if (!m_object->internal) {
				goto reenter_pg_on_q;
			}

			/*
			 * the object associated with candidate page is
			 * different from the one we were just working
			 * with... dump the lock if we still own it
			 */
			if (l_object != NULL) {
				vm_object_unlock(l_object);
				l_object = NULL;
			}
			if (m_object != t_object) {
				try_failed_count = 0;
			}

			/*
			 * Try to lock object; since we've alread got the
			 * page queues lock, we can only 'try' for this one.
			 * if the 'try' fails, we need to do a mutex_pause
			 * to allow the owner of the object lock a chance to
			 * run...
			 */
			if (!vm_object_lock_try_scan(m_object)) {
				if (try_failed_count > 20) {
					goto reenter_pg_on_q;
				}
				vm_page_unlock_queues();
				mutex_pause(try_failed_count++);
				vm_page_lock_queues();
				delayed_unlock = 0;

				t_object = m_object;
				continue;
			}
			l_object = m_object;
		}
		if (!m_object->alive || m->vmp_cleaning || m->vmp_laundry || m->vmp_busy || m->vmp_absent || m->vmp_error || m->vmp_free_when_done) {
			/*
			 * page is not to be cleaned
			 * put it back on the head of its queue
			 */
			goto reenter_pg_on_q;
		}
		phys_page = VM_PAGE_GET_PHYS_PAGE(m);

		if (m->vmp_reference == FALSE && m->vmp_pmapped == TRUE) {
			refmod_state = pmap_get_refmod(phys_page);

			if (refmod_state & VM_MEM_REFERENCED) {
				m->vmp_reference = TRUE;
			}
			if (refmod_state & VM_MEM_MODIFIED) {
				SET_PAGE_DIRTY(m, FALSE);
			}
		}
		if (m->vmp_reference == TRUE) {
			m->vmp_reference = FALSE;
			pmap_clear_refmod_options(phys_page, VM_MEM_REFERENCED, PMAP_OPTIONS_NOFLUSH, (void *)NULL);
			goto reenter_pg_on_q;
		}
		if (m->vmp_pmapped == TRUE) {
			if (m->vmp_dirty || m->vmp_precious) {
				pmap_options = PMAP_OPTIONS_COMPRESSOR;
			} else {
				pmap_options = PMAP_OPTIONS_COMPRESSOR_IFF_MODIFIED;
			}
			refmod_state = pmap_disconnect_options(phys_page, pmap_options, NULL);
			if (refmod_state & VM_MEM_MODIFIED) {
				SET_PAGE_DIRTY(m, FALSE);
			}
		}

		if (!m->vmp_dirty && !m->vmp_precious) {
			vm_page_unlock_queues();
			VM_PAGE_FREE(m);
			vm_page_lock_queues();
			delayed_unlock = 0;

			goto next_pg;
		}
		if (!m_object->pager_initialized || m_object->pager == MEMORY_OBJECT_NULL) {
			if (!m_object->pager_initialized) {
				vm_page_unlock_queues();

				vm_object_collapse(m_object, (vm_object_offset_t) 0, TRUE);

				if (!m_object->pager_initialized) {
					vm_object_compressor_pager_create(m_object);
				}

				vm_page_lock_queues();
				delayed_unlock = 0;
			}
			if (!m_object->pager_initialized || m_object->pager == MEMORY_OBJECT_NULL) {
				goto reenter_pg_on_q;
			}
			/*
			 * vm_object_compressor_pager_create will drop the object lock
			 * which means 'm' may no longer be valid to use
			 */
			continue;
		}
		/*
		 * we've already factored out pages in the laundry which
		 * means this page can't be on the pageout queue so it's
		 * safe to do the vm_page_queues_remove
		 */
		vm_page_queues_remove(m, TRUE);

		LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);

		vm_pageout_cluster(m);

		goto next_pg;

reenter_pg_on_q:
		vm_page_queue_remove(q, m, vmp_pageq);
		vm_page_queue_enter(q, m, vmp_pageq);
next_pg:
		qcount--;
		try_failed_count = 0;

		if (delayed_unlock++ > 128) {
			if (l_object != NULL) {
				vm_object_unlock(l_object);
				l_object = NULL;
			}
			lck_mtx_yield(&vm_page_queue_lock);
			delayed_unlock = 0;
		}
	}
	if (l_object != NULL) {
		vm_object_unlock(l_object);
		l_object = NULL;
	}
	vm_page_unlock_queues();
}



/*
 * function in BSD to apply I/O throttle to the pageout thread
 */
extern void vm_pageout_io_throttle(void);

#define VM_PAGEOUT_SCAN_HANDLE_REUSABLE_PAGE(m, obj)                    \
	MACRO_BEGIN                                                     \
	/* \
	 * If a "reusable" page somehow made it back into \
	 * the active queue, it's been re-used and is not \
	 * quite re-usable. \
	 * If the VM object was "all_reusable", consider it \
	 * as "all re-used" instead of converting it to \
	 * "partially re-used", which could be expensive. \
	 */                                                             \
	assert(VM_PAGE_OBJECT((m)) == (obj));                           \
	if ((m)->vmp_reusable ||                                        \
	    (obj)->all_reusable) {                                      \
	        vm_object_reuse_pages((obj),                            \
	                              (m)->vmp_offset,                  \
	                              (m)->vmp_offset + PAGE_SIZE_64,   \
	                              FALSE);                           \
	}                                                               \
	MACRO_END


#define VM_PAGEOUT_DELAYED_UNLOCK_LIMIT         64
#define VM_PAGEOUT_DELAYED_UNLOCK_LIMIT_MAX     1024

#define FCS_IDLE                0
#define FCS_DELAYED             1
#define FCS_DEADLOCK_DETECTED   2

struct flow_control {
	int             state;
	mach_timespec_t ts;
};


#if CONFIG_BACKGROUND_QUEUE
uint64_t vm_pageout_rejected_bq_internal = 0;
uint64_t vm_pageout_rejected_bq_external = 0;
uint64_t vm_pageout_skipped_bq_internal = 0;
#endif

#define ANONS_GRABBED_LIMIT     2


#if 0
static void vm_pageout_delayed_unlock(int *, int *, vm_page_t *);
#endif
static void vm_pageout_prepare_to_block(vm_object_t *, int *, vm_page_t *, int *, int);

#define VM_PAGEOUT_PB_NO_ACTION                         0
#define VM_PAGEOUT_PB_CONSIDER_WAKING_COMPACTOR_SWAPPER 1
#define VM_PAGEOUT_PB_THREAD_YIELD                      2


#if 0
static void
vm_pageout_delayed_unlock(int *delayed_unlock, int *local_freed, vm_page_t *local_freeq)
{
	if (*local_freeq) {
		vm_page_unlock_queues();

		VM_DEBUG_CONSTANT_EVENT(
			vm_pageout_freelist, VM_PAGEOUT_FREELIST, DBG_FUNC_START,
			vm_page_free_count, 0, 0, 1);

		vm_page_free_list(*local_freeq, TRUE);

		VM_DEBUG_CONSTANT_EVENT(vm_pageout_freelist, VM_PAGEOUT_FREELIST, DBG_FUNC_END,
		    vm_page_free_count, *local_freed, 0, 1);

		*local_freeq = NULL;
		*local_freed = 0;

		vm_page_lock_queues();
	} else {
		lck_mtx_yield(&vm_page_queue_lock);
	}
	*delayed_unlock = 1;
}
#endif


static void
vm_pageout_prepare_to_block(vm_object_t *object, int *delayed_unlock,
    vm_page_t *local_freeq, int *local_freed, int action)
{
	vm_page_unlock_queues();

	if (*object != NULL) {
		vm_object_unlock(*object);
		*object = NULL;
	}
	if (*local_freeq) {
		vm_page_free_list(*local_freeq, TRUE);

		*local_freeq = NULL;
		*local_freed = 0;
	}
	*delayed_unlock = 1;

	switch (action) {
	case VM_PAGEOUT_PB_CONSIDER_WAKING_COMPACTOR_SWAPPER:
		vm_consider_waking_compactor_swapper();
		break;
	case VM_PAGEOUT_PB_THREAD_YIELD:
		thread_yield_internal(1);
		break;
	case VM_PAGEOUT_PB_NO_ACTION:
	default:
		break;
	}
	vm_page_lock_queues();
}


static struct vm_pageout_vminfo last;

uint64_t last_vm_page_pages_grabbed = 0;

extern  uint32_t c_segment_pages_compressed;

extern uint64_t shared_region_pager_reclaimed;
extern struct memory_object_pager_ops shared_region_pager_ops;

void
update_vm_info(void)
{
	uint64_t tmp;

	vm_pageout_stats[vm_pageout_stat_now].vm_page_active_count = vm_page_active_count;
	vm_pageout_stats[vm_pageout_stat_now].vm_page_speculative_count = vm_page_speculative_count;
	vm_pageout_stats[vm_pageout_stat_now].vm_page_inactive_count = vm_page_inactive_count;
	vm_pageout_stats[vm_pageout_stat_now].vm_page_anonymous_count = vm_page_anonymous_count;

	vm_pageout_stats[vm_pageout_stat_now].vm_page_free_count = vm_page_free_count;
	vm_pageout_stats[vm_pageout_stat_now].vm_page_wire_count = vm_page_wire_count;
	vm_pageout_stats[vm_pageout_stat_now].vm_page_compressor_count = VM_PAGE_COMPRESSOR_COUNT;

	vm_pageout_stats[vm_pageout_stat_now].vm_page_pages_compressed = c_segment_pages_compressed;
	vm_pageout_stats[vm_pageout_stat_now].vm_page_pageable_internal_count = vm_page_pageable_internal_count;
	vm_pageout_stats[vm_pageout_stat_now].vm_page_pageable_external_count = vm_page_pageable_external_count;
	vm_pageout_stats[vm_pageout_stat_now].vm_page_xpmapped_external_count = vm_page_xpmapped_external_count;


	tmp = vm_pageout_vminfo.vm_pageout_considered_page;
	vm_pageout_stats[vm_pageout_stat_now].considered = (unsigned int)(tmp - last.vm_pageout_considered_page);
	last.vm_pageout_considered_page = tmp;

	tmp = vm_pageout_vminfo.vm_pageout_compressions;
	vm_pageout_stats[vm_pageout_stat_now].pages_compressed = (unsigned int)(tmp - last.vm_pageout_compressions);
	last.vm_pageout_compressions = tmp;

	tmp = vm_pageout_vminfo.vm_compressor_failed;
	vm_pageout_stats[vm_pageout_stat_now].failed_compressions = (unsigned int)(tmp - last.vm_compressor_failed);
	last.vm_compressor_failed = tmp;

	tmp = vm_pageout_vminfo.vm_compressor_pages_grabbed;
	vm_pageout_stats[vm_pageout_stat_now].pages_grabbed_by_compressor = (unsigned int)(tmp - last.vm_compressor_pages_grabbed);
	last.vm_compressor_pages_grabbed = tmp;

	tmp = vm_pageout_vminfo.vm_phantom_cache_found_ghost;
	vm_pageout_stats[vm_pageout_stat_now].phantom_ghosts_found = (unsigned int)(tmp - last.vm_phantom_cache_found_ghost);
	last.vm_phantom_cache_found_ghost = tmp;

	tmp = vm_pageout_vminfo.vm_phantom_cache_added_ghost;
	vm_pageout_stats[vm_pageout_stat_now].phantom_ghosts_added = (unsigned int)(tmp - last.vm_phantom_cache_added_ghost);
	last.vm_phantom_cache_added_ghost = tmp;

	tmp = get_pages_grabbed_count();
	vm_pageout_stats[vm_pageout_stat_now].pages_grabbed = (unsigned int)(tmp - last_vm_page_pages_grabbed);
	last_vm_page_pages_grabbed = tmp;

	tmp = vm_pageout_vminfo.vm_page_pages_freed;
	vm_pageout_stats[vm_pageout_stat_now].pages_freed = (unsigned int)(tmp - last.vm_page_pages_freed);
	last.vm_page_pages_freed = tmp;


	if (vm_pageout_stats[vm_pageout_stat_now].considered) {
		tmp = vm_pageout_vminfo.vm_pageout_pages_evicted;
		vm_pageout_stats[vm_pageout_stat_now].pages_evicted = (unsigned int)(tmp - last.vm_pageout_pages_evicted);
		last.vm_pageout_pages_evicted = tmp;

		tmp = vm_pageout_vminfo.vm_pageout_pages_purged;
		vm_pageout_stats[vm_pageout_stat_now].pages_purged = (unsigned int)(tmp - last.vm_pageout_pages_purged);
		last.vm_pageout_pages_purged = tmp;

		tmp = vm_pageout_vminfo.vm_pageout_freed_speculative;
		vm_pageout_stats[vm_pageout_stat_now].freed_speculative = (unsigned int)(tmp - last.vm_pageout_freed_speculative);
		last.vm_pageout_freed_speculative = tmp;

		tmp = vm_pageout_vminfo.vm_pageout_freed_external;
		vm_pageout_stats[vm_pageout_stat_now].freed_external = (unsigned int)(tmp - last.vm_pageout_freed_external);
		last.vm_pageout_freed_external = tmp;

		tmp = vm_pageout_vminfo.vm_pageout_inactive_referenced;
		vm_pageout_stats[vm_pageout_stat_now].inactive_referenced = (unsigned int)(tmp - last.vm_pageout_inactive_referenced);
		last.vm_pageout_inactive_referenced = tmp;

		tmp = vm_pageout_vminfo.vm_pageout_scan_inactive_throttled_external;
		vm_pageout_stats[vm_pageout_stat_now].throttled_external_q = (unsigned int)(tmp - last.vm_pageout_scan_inactive_throttled_external);
		last.vm_pageout_scan_inactive_throttled_external = tmp;

		tmp = vm_pageout_vminfo.vm_pageout_inactive_dirty_external;
		vm_pageout_stats[vm_pageout_stat_now].cleaned_dirty_external = (unsigned int)(tmp - last.vm_pageout_inactive_dirty_external);
		last.vm_pageout_inactive_dirty_external = tmp;

		tmp = vm_pageout_vminfo.vm_pageout_freed_cleaned;
		vm_pageout_stats[vm_pageout_stat_now].freed_cleaned = (unsigned int)(tmp - last.vm_pageout_freed_cleaned);
		last.vm_pageout_freed_cleaned = tmp;

		tmp = vm_pageout_vminfo.vm_pageout_inactive_nolock;
		vm_pageout_stats[vm_pageout_stat_now].inactive_nolock = (unsigned int)(tmp - last.vm_pageout_inactive_nolock);
		last.vm_pageout_inactive_nolock = tmp;

		tmp = vm_pageout_vminfo.vm_pageout_scan_inactive_throttled_internal;
		vm_pageout_stats[vm_pageout_stat_now].throttled_internal_q = (unsigned int)(tmp - last.vm_pageout_scan_inactive_throttled_internal);
		last.vm_pageout_scan_inactive_throttled_internal = tmp;

		tmp = vm_pageout_vminfo.vm_pageout_skipped_external;
		vm_pageout_stats[vm_pageout_stat_now].skipped_external = (unsigned int)(tmp - last.vm_pageout_skipped_external);
		last.vm_pageout_skipped_external = tmp;

		tmp = vm_pageout_vminfo.vm_pageout_reactivation_limit_exceeded;
		vm_pageout_stats[vm_pageout_stat_now].reactivation_limit_exceeded = (unsigned int)(tmp - last.vm_pageout_reactivation_limit_exceeded);
		last.vm_pageout_reactivation_limit_exceeded = tmp;

		tmp = vm_pageout_vminfo.vm_pageout_inactive_force_reclaim;
		vm_pageout_stats[vm_pageout_stat_now].forced_inactive_reclaim = (unsigned int)(tmp - last.vm_pageout_inactive_force_reclaim);
		last.vm_pageout_inactive_force_reclaim = tmp;

		tmp = vm_pageout_vminfo.vm_pageout_freed_internal;
		vm_pageout_stats[vm_pageout_stat_now].freed_internal = (unsigned int)(tmp - last.vm_pageout_freed_internal);
		last.vm_pageout_freed_internal = tmp;

		tmp = vm_pageout_vminfo.vm_pageout_considered_bq_internal;
		vm_pageout_stats[vm_pageout_stat_now].considered_bq_internal = (unsigned int)(tmp - last.vm_pageout_considered_bq_internal);
		last.vm_pageout_considered_bq_internal = tmp;

		tmp = vm_pageout_vminfo.vm_pageout_considered_bq_external;
		vm_pageout_stats[vm_pageout_stat_now].considered_bq_external = (unsigned int)(tmp - last.vm_pageout_considered_bq_external);
		last.vm_pageout_considered_bq_external = tmp;

		tmp = vm_pageout_vminfo.vm_pageout_filecache_min_reactivated;
		vm_pageout_stats[vm_pageout_stat_now].filecache_min_reactivations = (unsigned int)(tmp - last.vm_pageout_filecache_min_reactivated);
		last.vm_pageout_filecache_min_reactivated = tmp;

		tmp = vm_pageout_vminfo.vm_pageout_inactive_dirty_internal;
		vm_pageout_stats[vm_pageout_stat_now].cleaned_dirty_internal = (unsigned int)(tmp - last.vm_pageout_inactive_dirty_internal);
		last.vm_pageout_inactive_dirty_internal = tmp;
	}

	KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, VM_INFO1)) | DBG_FUNC_NONE,
	    vm_pageout_stats[vm_pageout_stat_now].vm_page_active_count,
	    vm_pageout_stats[vm_pageout_stat_now].vm_page_speculative_count,
	    vm_pageout_stats[vm_pageout_stat_now].vm_page_inactive_count,
	    vm_pageout_stats[vm_pageout_stat_now].vm_page_anonymous_count,
	    0);

	KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, VM_INFO2)) | DBG_FUNC_NONE,
	    vm_pageout_stats[vm_pageout_stat_now].vm_page_free_count,
	    vm_pageout_stats[vm_pageout_stat_now].vm_page_wire_count,
	    vm_pageout_stats[vm_pageout_stat_now].vm_page_compressor_count,
	    0,
	    0);

	KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, VM_INFO3)) | DBG_FUNC_NONE,
	    vm_pageout_stats[vm_pageout_stat_now].vm_page_pages_compressed,
	    vm_pageout_stats[vm_pageout_stat_now].vm_page_pageable_internal_count,
	    vm_pageout_stats[vm_pageout_stat_now].vm_page_pageable_external_count,
	    vm_pageout_stats[vm_pageout_stat_now].vm_page_xpmapped_external_count,
	    0);

	if (vm_pageout_stats[vm_pageout_stat_now].considered ||
	    vm_pageout_stats[vm_pageout_stat_now].pages_compressed ||
	    vm_pageout_stats[vm_pageout_stat_now].failed_compressions) {
		KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, VM_INFO4)) | DBG_FUNC_NONE,
		    vm_pageout_stats[vm_pageout_stat_now].considered,
		    vm_pageout_stats[vm_pageout_stat_now].freed_speculative,
		    vm_pageout_stats[vm_pageout_stat_now].freed_external,
		    vm_pageout_stats[vm_pageout_stat_now].inactive_referenced,
		    0);

		KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, VM_INFO5)) | DBG_FUNC_NONE,
		    vm_pageout_stats[vm_pageout_stat_now].throttled_external_q,
		    vm_pageout_stats[vm_pageout_stat_now].cleaned_dirty_external,
		    vm_pageout_stats[vm_pageout_stat_now].freed_cleaned,
		    vm_pageout_stats[vm_pageout_stat_now].inactive_nolock,
		    0);

		KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, VM_INFO6)) | DBG_FUNC_NONE,
		    vm_pageout_stats[vm_pageout_stat_now].throttled_internal_q,
		    vm_pageout_stats[vm_pageout_stat_now].pages_compressed,
		    vm_pageout_stats[vm_pageout_stat_now].pages_grabbed_by_compressor,
		    vm_pageout_stats[vm_pageout_stat_now].skipped_external,
		    0);

		KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, VM_INFO7)) | DBG_FUNC_NONE,
		    vm_pageout_stats[vm_pageout_stat_now].reactivation_limit_exceeded,
		    vm_pageout_stats[vm_pageout_stat_now].forced_inactive_reclaim,
		    vm_pageout_stats[vm_pageout_stat_now].failed_compressions,
		    vm_pageout_stats[vm_pageout_stat_now].freed_internal,
		    0);

		KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, VM_INFO8)) | DBG_FUNC_NONE,
		    vm_pageout_stats[vm_pageout_stat_now].considered_bq_internal,
		    vm_pageout_stats[vm_pageout_stat_now].considered_bq_external,
		    vm_pageout_stats[vm_pageout_stat_now].filecache_min_reactivations,
		    vm_pageout_stats[vm_pageout_stat_now].cleaned_dirty_internal,
		    0);
	}
	KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, VM_INFO9)) | DBG_FUNC_NONE,
	    vm_pageout_stats[vm_pageout_stat_now].pages_grabbed,
	    vm_pageout_stats[vm_pageout_stat_now].pages_freed,
	    vm_pageout_stats[vm_pageout_stat_now].phantom_ghosts_found,
	    vm_pageout_stats[vm_pageout_stat_now].phantom_ghosts_added,
	    0);

	record_memory_pressure();
}

extern boolean_t hibernation_vmqueues_inspection;

/*
 * Return values for functions called by vm_pageout_scan
 * that control its flow.
 *
 * PROCEED -- vm_pageout_scan will keep making forward progress.
 * DONE_RETURN -- page demand satisfied, work is done -> vm_pageout_scan returns.
 * NEXT_ITERATION -- restart the 'for' loop in vm_pageout_scan aka continue.
 */

#define VM_PAGEOUT_SCAN_PROCEED                 (0)
#define VM_PAGEOUT_SCAN_DONE_RETURN             (1)
#define VM_PAGEOUT_SCAN_NEXT_ITERATION          (2)

/*
 * This function is called only from vm_pageout_scan and
 * it moves overflow secluded pages (one-at-a-time) to the
 * batched 'local' free Q or active Q.
 */
static void
vps_deal_with_secluded_page_overflow(vm_page_t *local_freeq, int *local_freed)
{
#if CONFIG_SECLUDED_MEMORY
	/*
	 * Deal with secluded_q overflow.
	 */
	if (vm_page_secluded_count > vm_page_secluded_target) {
		vm_page_t secluded_page;

		/*
		 * SECLUDED_AGING_BEFORE_ACTIVE:
		 * Excess secluded pages go to the active queue and
		 * will later go to the inactive queue.
		 */
		assert((vm_page_secluded_count_free +
		    vm_page_secluded_count_inuse) ==
		    vm_page_secluded_count);
		secluded_page = (vm_page_t)vm_page_queue_first(&vm_page_queue_secluded);
		assert(secluded_page->vmp_q_state == VM_PAGE_ON_SECLUDED_Q);

		vm_page_queues_remove(secluded_page, FALSE);
		assert(!secluded_page->vmp_fictitious);
		assert(!VM_PAGE_WIRED(secluded_page));

		if (secluded_page->vmp_object == 0) {
			/* transfer to free queue */
			assert(secluded_page->vmp_busy);
			secluded_page->vmp_snext = *local_freeq;
			*local_freeq = secluded_page;
			*local_freed += 1;
		} else {
			/* transfer to head of active queue */
			vm_page_enqueue_active(secluded_page, FALSE);
			secluded_page = VM_PAGE_NULL;
		}
	}
#else /* CONFIG_SECLUDED_MEMORY */

#pragma unused(local_freeq)
#pragma unused(local_freed)

	return;

#endif /* CONFIG_SECLUDED_MEMORY */
}

/*
 * This function is called only from vm_pageout_scan and
 * it initializes the loop targets for vm_pageout_scan().
 */
static void
vps_init_page_targets(void)
{
	/*
	 * LD TODO: Other page targets should be calculated here too.
	 */
	vm_page_anonymous_min = vm_page_inactive_target / 20;

	if (vm_pageout_state.vm_page_speculative_percentage > 50) {
		vm_pageout_state.vm_page_speculative_percentage = 50;
	} else if (vm_pageout_state.vm_page_speculative_percentage <= 0) {
		vm_pageout_state.vm_page_speculative_percentage = 1;
	}

	vm_pageout_state.vm_page_speculative_target = VM_PAGE_SPECULATIVE_TARGET(vm_page_active_count +
	    vm_page_inactive_count);
}

/*
 * This function is called only from vm_pageout_scan and
 * it purges a single VM object at-a-time and will either
 * make vm_pageout_scan() restart the loop or keeping moving forward.
 */
static int
vps_purge_object()
{
	int             force_purge;

	assert(available_for_purge >= 0);
	force_purge = 0; /* no force-purging */

#if VM_PRESSURE_EVENTS
	vm_pressure_level_t pressure_level;

	pressure_level = memorystatus_vm_pressure_level;

	if (pressure_level > kVMPressureNormal) {
		if (pressure_level >= kVMPressureCritical) {
			force_purge = vm_pageout_state.memorystatus_purge_on_critical;
		} else if (pressure_level >= kVMPressureUrgent) {
			force_purge = vm_pageout_state.memorystatus_purge_on_urgent;
		} else if (pressure_level >= kVMPressureWarning) {
			force_purge = vm_pageout_state.memorystatus_purge_on_warning;
		}
	}
#endif /* VM_PRESSURE_EVENTS */

	if (available_for_purge || force_purge) {
		memoryshot(VM_PAGEOUT_PURGEONE, DBG_FUNC_START);

		VM_DEBUG_EVENT(vm_pageout_purgeone, VM_PAGEOUT_PURGEONE, DBG_FUNC_START, vm_page_free_count, 0, 0, 0);
		if (vm_purgeable_object_purge_one(force_purge, C_DONT_BLOCK)) {
			VM_PAGEOUT_DEBUG(vm_pageout_purged_objects, 1);
			VM_DEBUG_EVENT(vm_pageout_purgeone, VM_PAGEOUT_PURGEONE, DBG_FUNC_END, vm_page_free_count, 0, 0, 0);
			memoryshot(VM_PAGEOUT_PURGEONE, DBG_FUNC_END);

			return VM_PAGEOUT_SCAN_NEXT_ITERATION;
		}
		VM_DEBUG_EVENT(vm_pageout_purgeone, VM_PAGEOUT_PURGEONE, DBG_FUNC_END, 0, 0, 0, -1);
		memoryshot(VM_PAGEOUT_PURGEONE, DBG_FUNC_END);
	}

	return VM_PAGEOUT_SCAN_PROCEED;
}

/*
 * This function is called only from vm_pageout_scan and
 * it will try to age the next speculative Q if the oldest
 * one is empty.
 */
static int
vps_age_speculative_queue(boolean_t force_speculative_aging)
{
#define DELAY_SPECULATIVE_AGE   1000

	/*
	 * try to pull pages from the aging bins...
	 * see vm_page.h for an explanation of how
	 * this mechanism works
	 */
	boolean_t                       can_steal = FALSE;
	int                             num_scanned_queues;
	static int                      delay_speculative_age = 0; /* depends the # of times we go through the main pageout_scan loop.*/
	mach_timespec_t                 ts;
	struct vm_speculative_age_q     *aq;
	struct vm_speculative_age_q     *sq;

	sq = &vm_page_queue_speculative[VM_PAGE_SPECULATIVE_AGED_Q];

	aq = &vm_page_queue_speculative[speculative_steal_index];

	num_scanned_queues = 0;
	while (vm_page_queue_empty(&aq->age_q) &&
	    num_scanned_queues++ != VM_PAGE_MAX_SPECULATIVE_AGE_Q) {
		speculative_steal_index++;

		if (speculative_steal_index > VM_PAGE_MAX_SPECULATIVE_AGE_Q) {
			speculative_steal_index = VM_PAGE_MIN_SPECULATIVE_AGE_Q;
		}

		aq = &vm_page_queue_speculative[speculative_steal_index];
	}

	if (num_scanned_queues == VM_PAGE_MAX_SPECULATIVE_AGE_Q + 1) {
		/*
		 * XXX We've scanned all the speculative
		 * queues but still haven't found one
		 * that is not empty, even though
		 * vm_page_speculative_count is not 0.
		 */
		if (!vm_page_queue_empty(&sq->age_q)) {
			return VM_PAGEOUT_SCAN_NEXT_ITERATION;
		}
#if DEVELOPMENT || DEBUG
		panic("vm_pageout_scan: vm_page_speculative_count=%d but queues are empty", vm_page_speculative_count);
#endif
		/* readjust... */
		vm_page_speculative_count = 0;
		/* ... and continue */
		return VM_PAGEOUT_SCAN_NEXT_ITERATION;
	}

	if (vm_page_speculative_count > vm_pageout_state.vm_page_speculative_target || force_speculative_aging == TRUE) {
		can_steal = TRUE;
	} else {
		if (!delay_speculative_age) {
			mach_timespec_t ts_fully_aged;

			ts_fully_aged.tv_sec = (VM_PAGE_MAX_SPECULATIVE_AGE_Q * vm_pageout_state.vm_page_speculative_q_age_ms) / 1000;
			ts_fully_aged.tv_nsec = ((VM_PAGE_MAX_SPECULATIVE_AGE_Q * vm_pageout_state.vm_page_speculative_q_age_ms) % 1000)
			    * 1000 * NSEC_PER_USEC;

			ADD_MACH_TIMESPEC(&ts_fully_aged, &aq->age_ts);

			clock_sec_t sec;
			clock_nsec_t nsec;
			clock_get_system_nanotime(&sec, &nsec);
			ts.tv_sec = (unsigned int) sec;
			ts.tv_nsec = nsec;

			if (CMP_MACH_TIMESPEC(&ts, &ts_fully_aged) >= 0) {
				can_steal = TRUE;
			} else {
				delay_speculative_age++;
			}
		} else {
			delay_speculative_age++;
			if (delay_speculative_age == DELAY_SPECULATIVE_AGE) {
				delay_speculative_age = 0;
			}
		}
	}
	if (can_steal == TRUE) {
		vm_page_speculate_ageit(aq);
	}

	return VM_PAGEOUT_SCAN_PROCEED;
}

/*
 * This function is called only from vm_pageout_scan and
 * it evicts a single VM object from the cache.
 */
static int inline
vps_object_cache_evict(vm_object_t *object_to_unlock)
{
	static int                      cache_evict_throttle = 0;
	struct vm_speculative_age_q     *sq;

	sq = &vm_page_queue_speculative[VM_PAGE_SPECULATIVE_AGED_Q];

	if (vm_page_queue_empty(&sq->age_q) && cache_evict_throttle == 0) {
		int     pages_evicted;

		if (*object_to_unlock != NULL) {
			vm_object_unlock(*object_to_unlock);
			*object_to_unlock = NULL;
		}
		KERNEL_DEBUG_CONSTANT(0x13001ec | DBG_FUNC_START, 0, 0, 0, 0, 0);

		pages_evicted = vm_object_cache_evict(100, 10);

		KERNEL_DEBUG_CONSTANT(0x13001ec | DBG_FUNC_END, pages_evicted, 0, 0, 0, 0);

		if (pages_evicted) {
			vm_pageout_vminfo.vm_pageout_pages_evicted += pages_evicted;

			VM_DEBUG_EVENT(vm_pageout_cache_evict, VM_PAGEOUT_CACHE_EVICT, DBG_FUNC_NONE,
			    vm_page_free_count, pages_evicted, vm_pageout_vminfo.vm_pageout_pages_evicted, 0);
			memoryshot(VM_PAGEOUT_CACHE_EVICT, DBG_FUNC_NONE);

			/*
			 * we just freed up to 100 pages,
			 * so go back to the top of the main loop
			 * and re-evaulate the memory situation
			 */
			return VM_PAGEOUT_SCAN_NEXT_ITERATION;
		} else {
			cache_evict_throttle = 1000;
		}
	}
	if (cache_evict_throttle) {
		cache_evict_throttle--;
	}

	return VM_PAGEOUT_SCAN_PROCEED;
}


/*
 * This function is called only from vm_pageout_scan and
 * it calculates the filecache min. that needs to be maintained
 * as we start to steal pages.
 */
static void
vps_calculate_filecache_min(void)
{
	int divisor = vm_pageout_state.vm_page_filecache_min_divisor;

#if CONFIG_JETSAM
	/*
	 * don't let the filecache_min fall below 15% of available memory
	 * on systems with an active compressor that isn't nearing its
	 * limits w/r to accepting new data
	 *
	 * on systems w/o the compressor/swapper, the filecache is always
	 * a very large percentage of the AVAILABLE_NON_COMPRESSED_MEMORY
	 * since most (if not all) of the anonymous pages are in the
	 * throttled queue (which isn't counted as available) which
	 * effectively disables this filter
	 */
	if (vm_compressor_low_on_space() || divisor == 0) {
		vm_pageout_state.vm_page_filecache_min = 0;
	} else {
		vm_pageout_state.vm_page_filecache_min =
		    ((AVAILABLE_NON_COMPRESSED_MEMORY) * 10) / divisor;
	}
#else
	if (vm_compressor_out_of_space() || divisor == 0) {
		vm_pageout_state.vm_page_filecache_min = 0;
	} else {
		/*
		 * don't let the filecache_min fall below the specified critical level
		 */
		vm_pageout_state.vm_page_filecache_min =
		    ((AVAILABLE_NON_COMPRESSED_MEMORY) * 10) / divisor;
	}
#endif
	if (vm_page_free_count < (vm_page_free_reserved / 4)) {
		vm_pageout_state.vm_page_filecache_min = 0;
	}
}

/*
 * This function is called only from vm_pageout_scan and
 * it updates the flow control time to detect if VM pageoutscan
 * isn't making progress.
 */
static void
vps_flow_control_reset_deadlock_timer(struct flow_control *flow_control)
{
	mach_timespec_t ts;
	clock_sec_t sec;
	clock_nsec_t nsec;

	ts.tv_sec = vm_pageout_state.vm_pageout_deadlock_wait / 1000;
	ts.tv_nsec = (vm_pageout_state.vm_pageout_deadlock_wait % 1000) * 1000 * NSEC_PER_USEC;
	clock_get_system_nanotime(&sec, &nsec);
	flow_control->ts.tv_sec = (unsigned int) sec;
	flow_control->ts.tv_nsec = nsec;
	ADD_MACH_TIMESPEC(&flow_control->ts, &ts);

	flow_control->state = FCS_DELAYED;

	vm_pageout_vminfo.vm_pageout_scan_inactive_throttled_internal++;
}

/*
 * This function is called only from vm_pageout_scan and
 * it is the flow control logic of VM pageout scan which
 * controls if it should block and for how long.
 * Any blocking of vm_pageout_scan happens ONLY in this function.
 */
static int
vps_flow_control(struct flow_control *flow_control, int *anons_grabbed, vm_object_t *object, int *delayed_unlock,
    vm_page_t *local_freeq, int *local_freed, int *vm_pageout_deadlock_target, unsigned int inactive_burst_count)
{
	boolean_t       exceeded_burst_throttle = FALSE;
	unsigned int    msecs = 0;
	uint32_t        inactive_external_count;
	mach_timespec_t ts;
	struct  vm_pageout_queue *iq;
	struct  vm_pageout_queue *eq;
	struct  vm_speculative_age_q *sq;

	iq = &vm_pageout_queue_internal;
	eq = &vm_pageout_queue_external;
	sq = &vm_page_queue_speculative[VM_PAGE_SPECULATIVE_AGED_Q];

	/*
	 * Sometimes we have to pause:
	 *	1) No inactive pages - nothing to do.
	 *	2) Loop control - no acceptable pages found on the inactive queue
	 *         within the last vm_pageout_burst_inactive_throttle iterations
	 *	3) Flow control - default pageout queue is full
	 */
	if (vm_page_queue_empty(&vm_page_queue_inactive) &&
	    vm_page_queue_empty(&vm_page_queue_anonymous) &&
	    vm_page_queue_empty(&vm_page_queue_cleaned) &&
	    vm_page_queue_empty(&sq->age_q)) {
		VM_PAGEOUT_DEBUG(vm_pageout_scan_empty_throttle, 1);
		msecs = vm_pageout_state.vm_pageout_empty_wait;
	} else if (inactive_burst_count >=
	    MIN(vm_pageout_state.vm_pageout_burst_inactive_throttle,
	    (vm_page_inactive_count +
	    vm_page_speculative_count))) {
		VM_PAGEOUT_DEBUG(vm_pageout_scan_burst_throttle, 1);
		msecs = vm_pageout_state.vm_pageout_burst_wait;

		exceeded_burst_throttle = TRUE;
	} else if (VM_PAGE_Q_THROTTLED(iq) &&
	    VM_DYNAMIC_PAGING_ENABLED()) {
		clock_sec_t sec;
		clock_nsec_t nsec;

		switch (flow_control->state) {
		case FCS_IDLE:
			if ((vm_page_free_count + *local_freed) < vm_page_free_target &&
			    vm_pageout_state.vm_restricted_to_single_processor == FALSE) {
				/*
				 * since the compressor is running independently of vm_pageout_scan
				 * let's not wait for it just yet... as long as we have a healthy supply
				 * of filecache pages to work with, let's keep stealing those.
				 */
				inactive_external_count = vm_page_inactive_count - vm_page_anonymous_count;

				if (vm_page_pageable_external_count > vm_pageout_state.vm_page_filecache_min &&
				    (inactive_external_count >= VM_PAGE_INACTIVE_TARGET(vm_page_pageable_external_count))) {
					*anons_grabbed = ANONS_GRABBED_LIMIT;
					VM_PAGEOUT_DEBUG(vm_pageout_scan_throttle_deferred, 1);
					return VM_PAGEOUT_SCAN_PROCEED;
				}
			}

			vps_flow_control_reset_deadlock_timer(flow_control);
			msecs = vm_pageout_state.vm_pageout_deadlock_wait;

			break;

		case FCS_DELAYED:
			clock_get_system_nanotime(&sec, &nsec);
			ts.tv_sec = (unsigned int) sec;
			ts.tv_nsec = nsec;

			if (CMP_MACH_TIMESPEC(&ts, &flow_control->ts) >= 0) {
				/*
				 * the pageout thread for the default pager is potentially
				 * deadlocked since the
				 * default pager queue has been throttled for more than the
				 * allowable time... we need to move some clean pages or dirty
				 * pages belonging to the external pagers if they aren't throttled
				 * vm_page_free_wanted represents the number of threads currently
				 * blocked waiting for pages... we'll move one page for each of
				 * these plus a fixed amount to break the logjam... once we're done
				 * moving this number of pages, we'll re-enter the FSC_DELAYED state
				 * with a new timeout target since we have no way of knowing
				 * whether we've broken the deadlock except through observation
				 * of the queue associated with the default pager... we need to
				 * stop moving pages and allow the system to run to see what
				 * state it settles into.
				 */

				*vm_pageout_deadlock_target = vm_pageout_state.vm_pageout_deadlock_relief +
				    vm_page_free_wanted + vm_page_free_wanted_privileged;
				VM_PAGEOUT_DEBUG(vm_pageout_scan_deadlock_detected, 1);
				flow_control->state = FCS_DEADLOCK_DETECTED;
				thread_wakeup((event_t) &vm_pageout_garbage_collect);
				return VM_PAGEOUT_SCAN_PROCEED;
			}
			/*
			 * just resniff instead of trying
			 * to compute a new delay time... we're going to be
			 * awakened immediately upon a laundry completion,
			 * so we won't wait any longer than necessary
			 */
			msecs = vm_pageout_state.vm_pageout_idle_wait;
			break;

		case FCS_DEADLOCK_DETECTED:
			if (*vm_pageout_deadlock_target) {
				return VM_PAGEOUT_SCAN_PROCEED;
			}

			vps_flow_control_reset_deadlock_timer(flow_control);
			msecs = vm_pageout_state.vm_pageout_deadlock_wait;

			break;
		}
	} else {
		/*
		 * No need to pause...
		 */
		return VM_PAGEOUT_SCAN_PROCEED;
	}

	vm_pageout_scan_wants_object = VM_OBJECT_NULL;

	vm_pageout_prepare_to_block(object, delayed_unlock, local_freeq, local_freed,
	    VM_PAGEOUT_PB_CONSIDER_WAKING_COMPACTOR_SWAPPER);

	if (vm_page_free_count >= vm_page_free_target) {
		/*
		 * we're here because
		 *  1) someone else freed up some pages while we had
		 *     the queues unlocked above
		 * and we've hit one of the 3 conditions that
		 * cause us to pause the pageout scan thread
		 *
		 * since we already have enough free pages,
		 * let's avoid stalling and return normally
		 *
		 * before we return, make sure the pageout I/O threads
		 * are running throttled in case there are still requests
		 * in the laundry... since we have enough free pages
		 * we don't need the laundry to be cleaned in a timely
		 * fashion... so let's avoid interfering with foreground
		 * activity
		 *
		 * we don't want to hold vm_page_queue_free_lock when
		 * calling vm_pageout_adjust_eq_iothrottle (since it
		 * may cause other locks to be taken), we do the intitial
		 * check outside of the lock.  Once we take the lock,
		 * we recheck the condition since it may have changed.
		 * if it has, no problem, we will make the threads
		 * non-throttled before actually blocking
		 */
		vm_pageout_adjust_eq_iothrottle(eq, TRUE);
	}
	lck_mtx_lock(&vm_page_queue_free_lock);

	if (vm_page_free_count >= vm_page_free_target &&
	    (vm_page_free_wanted == 0) && (vm_page_free_wanted_privileged == 0)) {
		return VM_PAGEOUT_SCAN_DONE_RETURN;
	}
	lck_mtx_unlock(&vm_page_queue_free_lock);

	if ((vm_page_free_count + vm_page_cleaned_count) < vm_page_free_target) {
		/*
		 * we're most likely about to block due to one of
		 * the 3 conditions that cause vm_pageout_scan to
		 * not be able to make forward progress w/r
		 * to providing new pages to the free queue,
		 * so unthrottle the I/O threads in case we
		 * have laundry to be cleaned... it needs
		 * to be completed ASAP.
		 *
		 * even if we don't block, we want the io threads
		 * running unthrottled since the sum of free +
		 * clean pages is still under our free target
		 */
		vm_pageout_adjust_eq_iothrottle(eq, FALSE);
	}
	if (vm_page_cleaned_count > 0 && exceeded_burst_throttle == FALSE) {
		/*
		 * if we get here we're below our free target and
		 * we're stalling due to a full laundry queue or
		 * we don't have any inactive pages other then
		 * those in the clean queue...
		 * however, we have pages on the clean queue that
		 * can be moved to the free queue, so let's not
		 * stall the pageout scan
		 */
		flow_control->state = FCS_IDLE;
		return VM_PAGEOUT_SCAN_PROCEED;
	}
	if (flow_control->state == FCS_DELAYED && !VM_PAGE_Q_THROTTLED(iq)) {
		flow_control->state = FCS_IDLE;
		return VM_PAGEOUT_SCAN_PROCEED;
	}

	VM_CHECK_MEMORYSTATUS;

	if (flow_control->state != FCS_IDLE) {
		VM_PAGEOUT_DEBUG(vm_pageout_scan_throttle, 1);
	}

	iq->pgo_throttled = TRUE;
	assert_wait_timeout((event_t) &iq->pgo_laundry, THREAD_INTERRUPTIBLE, msecs, 1000 * NSEC_PER_USEC);

	counter(c_vm_pageout_scan_block++);

	vm_page_unlock_queues();

	assert(vm_pageout_scan_wants_object == VM_OBJECT_NULL);

	VM_DEBUG_EVENT(vm_pageout_thread_block, VM_PAGEOUT_THREAD_BLOCK, DBG_FUNC_START,
	    iq->pgo_laundry, iq->pgo_maxlaundry, msecs, 0);
	memoryshot(VM_PAGEOUT_THREAD_BLOCK, DBG_FUNC_START);

	thread_block(THREAD_CONTINUE_NULL);

	VM_DEBUG_EVENT(vm_pageout_thread_block, VM_PAGEOUT_THREAD_BLOCK, DBG_FUNC_END,
	    iq->pgo_laundry, iq->pgo_maxlaundry, msecs, 0);
	memoryshot(VM_PAGEOUT_THREAD_BLOCK, DBG_FUNC_END);

	vm_page_lock_queues();

	iq->pgo_throttled = FALSE;

	vps_init_page_targets();

	return VM_PAGEOUT_SCAN_NEXT_ITERATION;
}

/*
 * This function is called only from vm_pageout_scan and
 * it will find and return the most appropriate page to be
 * reclaimed.
 */
static int
vps_choose_victim_page(vm_page_t *victim_page, int *anons_grabbed, boolean_t *grab_anonymous, boolean_t force_anonymous,
    boolean_t *is_page_from_bg_q, unsigned int reactivated_this_call)
{
	vm_page_t                       m = NULL;
	vm_object_t                     m_object = VM_OBJECT_NULL;
	uint32_t                        inactive_external_count;
	struct vm_speculative_age_q     *sq;
	struct vm_pageout_queue         *iq;
	int                             retval = VM_PAGEOUT_SCAN_PROCEED;

	sq = &vm_page_queue_speculative[VM_PAGE_SPECULATIVE_AGED_Q];
	iq = &vm_pageout_queue_internal;

	while (1) {
		*is_page_from_bg_q = FALSE;

		m = NULL;
		m_object = VM_OBJECT_NULL;

		if (VM_DYNAMIC_PAGING_ENABLED()) {
			assert(vm_page_throttled_count == 0);
			assert(vm_page_queue_empty(&vm_page_queue_throttled));
		}

		/*
		 * Try for a clean-queue inactive page.
		 * These are pages that vm_pageout_scan tried to steal earlier, but
		 * were dirty and had to be cleaned.  Pick them up now that they are clean.
		 */
		if (!vm_page_queue_empty(&vm_page_queue_cleaned)) {
			m = (vm_page_t) vm_page_queue_first(&vm_page_queue_cleaned);

			assert(m->vmp_q_state == VM_PAGE_ON_INACTIVE_CLEANED_Q);

			break;
		}

		/*
		 * The next most eligible pages are ones we paged in speculatively,
		 * but which have not yet been touched and have been aged out.
		 */
		if (!vm_page_queue_empty(&sq->age_q)) {
			m = (vm_page_t) vm_page_queue_first(&sq->age_q);

			assert(m->vmp_q_state == VM_PAGE_ON_SPECULATIVE_Q);

			if (!m->vmp_dirty || force_anonymous == FALSE) {
				break;
			} else {
				m = NULL;
			}
		}

#if CONFIG_BACKGROUND_QUEUE
		if (vm_page_background_mode != VM_PAGE_BG_DISABLED && (vm_page_background_count > vm_page_background_target)) {
			vm_object_t     bg_m_object = NULL;

			m = (vm_page_t) vm_page_queue_first(&vm_page_queue_background);

			bg_m_object = VM_PAGE_OBJECT(m);

			if (!VM_PAGE_PAGEABLE(m)) {
				/*
				 * This page is on the background queue
				 * but not on a pageable queue.  This is
				 * likely a transient state and whoever
				 * took it out of its pageable queue
				 * will likely put it back on a pageable
				 * queue soon but we can't deal with it
				 * at this point, so let's ignore this
				 * page.
				 */
			} else if (force_anonymous == FALSE || bg_m_object->internal) {
				if (bg_m_object->internal &&
				    (VM_PAGE_Q_THROTTLED(iq) ||
				    vm_compressor_out_of_space() == TRUE ||
				    vm_page_free_count < (vm_page_free_reserved / 4))) {
					vm_pageout_skipped_bq_internal++;
				} else {
					*is_page_from_bg_q = TRUE;

					if (bg_m_object->internal) {
						vm_pageout_vminfo.vm_pageout_considered_bq_internal++;
					} else {
						vm_pageout_vminfo.vm_pageout_considered_bq_external++;
					}
					break;
				}
			}
		}
#endif /* CONFIG_BACKGROUND_QUEUE */

		inactive_external_count = vm_page_inactive_count - vm_page_anonymous_count;

		if ((vm_page_pageable_external_count < vm_pageout_state.vm_page_filecache_min || force_anonymous == TRUE) ||
		    (inactive_external_count < VM_PAGE_INACTIVE_TARGET(vm_page_pageable_external_count))) {
			*grab_anonymous = TRUE;
			*anons_grabbed = 0;

			vm_pageout_vminfo.vm_pageout_skipped_external++;
			goto want_anonymous;
		}
		*grab_anonymous = (vm_page_anonymous_count > vm_page_anonymous_min);

#if CONFIG_JETSAM
		/* If the file-backed pool has accumulated
		 * significantly more pages than the jetsam
		 * threshold, prefer to reclaim those
		 * inline to minimise compute overhead of reclaiming
		 * anonymous pages.
		 * This calculation does not account for the CPU local
		 * external page queues, as those are expected to be
		 * much smaller relative to the global pools.
		 */

		struct vm_pageout_queue *eq = &vm_pageout_queue_external;

		if (*grab_anonymous == TRUE && !VM_PAGE_Q_THROTTLED(eq)) {
			if (vm_page_pageable_external_count >
			    vm_pageout_state.vm_page_filecache_min) {
				if ((vm_page_pageable_external_count *
				    vm_pageout_memorystatus_fb_factor_dr) >
				    (memorystatus_available_pages_critical *
				    vm_pageout_memorystatus_fb_factor_nr)) {
					*grab_anonymous = FALSE;

					VM_PAGEOUT_DEBUG(vm_grab_anon_overrides, 1);
				}
			}
			if (*grab_anonymous) {
				VM_PAGEOUT_DEBUG(vm_grab_anon_nops, 1);
			}
		}
#endif /* CONFIG_JETSAM */

want_anonymous:
		if (*grab_anonymous == FALSE || *anons_grabbed >= ANONS_GRABBED_LIMIT || vm_page_queue_empty(&vm_page_queue_anonymous)) {
			if (!vm_page_queue_empty(&vm_page_queue_inactive)) {
				m = (vm_page_t) vm_page_queue_first(&vm_page_queue_inactive);

				assert(m->vmp_q_state == VM_PAGE_ON_INACTIVE_EXTERNAL_Q);
				*anons_grabbed = 0;

				if (vm_page_pageable_external_count < vm_pageout_state.vm_page_filecache_min) {
					if (!vm_page_queue_empty(&vm_page_queue_anonymous)) {
						if ((++reactivated_this_call % 100)) {
							vm_pageout_vminfo.vm_pageout_filecache_min_reactivated++;

							vm_page_activate(m);
							VM_STAT_INCR(reactivations);
#if CONFIG_BACKGROUND_QUEUE
#if DEVELOPMENT || DEBUG
							if (*is_page_from_bg_q == TRUE) {
								if (m_object->internal) {
									vm_pageout_rejected_bq_internal++;
								} else {
									vm_pageout_rejected_bq_external++;
								}
							}
#endif /* DEVELOPMENT || DEBUG */
#endif /* CONFIG_BACKGROUND_QUEUE */
							vm_pageout_state.vm_pageout_inactive_used++;

							m = NULL;
							retval = VM_PAGEOUT_SCAN_NEXT_ITERATION;

							break;
						}

						/*
						 * steal 1% of the file backed pages even if
						 * we are under the limit that has been set
						 * for a healthy filecache
						 */
					}
				}
				break;
			}
		}
		if (!vm_page_queue_empty(&vm_page_queue_anonymous)) {
			m = (vm_page_t) vm_page_queue_first(&vm_page_queue_anonymous);

			assert(m->vmp_q_state == VM_PAGE_ON_INACTIVE_INTERNAL_Q);
			*anons_grabbed += 1;

			break;
		}

		m = NULL;
	}

	*victim_page = m;

	return retval;
}

/*
 * This function is called only from vm_pageout_scan and
 * it will put a page back on the active/inactive queue
 * if we can't reclaim it for some reason.
 */
static void
vps_requeue_page(vm_page_t m, int page_prev_q_state, __unused boolean_t page_from_bg_q)
{
	if (page_prev_q_state == VM_PAGE_ON_SPECULATIVE_Q) {
		vm_page_enqueue_inactive(m, FALSE);
	} else {
		vm_page_activate(m);
	}

#if CONFIG_BACKGROUND_QUEUE
#if DEVELOPMENT || DEBUG
	vm_object_t m_object = VM_PAGE_OBJECT(m);

	if (page_from_bg_q == TRUE) {
		if (m_object->internal) {
			vm_pageout_rejected_bq_internal++;
		} else {
			vm_pageout_rejected_bq_external++;
		}
	}
#endif /* DEVELOPMENT || DEBUG */
#endif /* CONFIG_BACKGROUND_QUEUE */
}

/*
 * This function is called only from vm_pageout_scan and
 * it will try to grab the victim page's VM object (m_object)
 * which differs from the previous victim page's object (object).
 */
static int
vps_switch_object(vm_page_t m, vm_object_t m_object, vm_object_t *object, int page_prev_q_state, boolean_t avoid_anon_pages, boolean_t page_from_bg_q)
{
	struct vm_speculative_age_q *sq;

	sq = &vm_page_queue_speculative[VM_PAGE_SPECULATIVE_AGED_Q];

	/*
	 * the object associated with candidate page is
	 * different from the one we were just working
	 * with... dump the lock if we still own it
	 */
	if (*object != NULL) {
		vm_object_unlock(*object);
		*object = NULL;
	}
	/*
	 * Try to lock object; since we've alread got the
	 * page queues lock, we can only 'try' for this one.
	 * if the 'try' fails, we need to do a mutex_pause
	 * to allow the owner of the object lock a chance to
	 * run... otherwise, we're likely to trip over this
	 * object in the same state as we work our way through
	 * the queue... clumps of pages associated with the same
	 * object are fairly typical on the inactive and active queues
	 */
	if (!vm_object_lock_try_scan(m_object)) {
		vm_page_t m_want = NULL;

		vm_pageout_vminfo.vm_pageout_inactive_nolock++;

		if (page_prev_q_state == VM_PAGE_ON_INACTIVE_CLEANED_Q) {
			VM_PAGEOUT_DEBUG(vm_pageout_cleaned_nolock, 1);
		}

		pmap_clear_reference(VM_PAGE_GET_PHYS_PAGE(m));

		m->vmp_reference = FALSE;

		if (!m_object->object_is_shared_cache) {
			/*
			 * don't apply this optimization if this is the shared cache
			 * object, it's too easy to get rid of very hot and important
			 * pages...
			 * m->vmp_object must be stable since we hold the page queues lock...
			 * we can update the scan_collisions field sans the object lock
			 * since it is a separate field and this is the only spot that does
			 * a read-modify-write operation and it is never executed concurrently...
			 * we can asynchronously set this field to 0 when creating a UPL, so it
			 * is possible for the value to be a bit non-determistic, but that's ok
			 * since it's only used as a hint
			 */
			m_object->scan_collisions = 1;
		}
		if (!vm_page_queue_empty(&vm_page_queue_cleaned)) {
			m_want = (vm_page_t) vm_page_queue_first(&vm_page_queue_cleaned);
		} else if (!vm_page_queue_empty(&sq->age_q)) {
			m_want = (vm_page_t) vm_page_queue_first(&sq->age_q);
		} else if ((avoid_anon_pages || vm_page_queue_empty(&vm_page_queue_anonymous)) &&
		    !vm_page_queue_empty(&vm_page_queue_inactive)) {
			m_want = (vm_page_t) vm_page_queue_first(&vm_page_queue_inactive);
		} else if (!vm_page_queue_empty(&vm_page_queue_anonymous)) {
			m_want = (vm_page_t) vm_page_queue_first(&vm_page_queue_anonymous);
		}

		/*
		 * this is the next object we're going to be interested in
		 * try to make sure its available after the mutex_pause
		 * returns control
		 */
		if (m_want) {
			vm_pageout_scan_wants_object = VM_PAGE_OBJECT(m_want);
		}

		vps_requeue_page(m, page_prev_q_state, page_from_bg_q);

		return VM_PAGEOUT_SCAN_NEXT_ITERATION;
	} else {
		*object = m_object;
		vm_pageout_scan_wants_object = VM_OBJECT_NULL;
	}

	return VM_PAGEOUT_SCAN_PROCEED;
}

/*
 * This function is called only from vm_pageout_scan and
 * it notices that pageout scan may be rendered ineffective
 * due to a FS deadlock and will jetsam a process if possible.
 * If jetsam isn't supported, it'll move the page to the active
 * queue to try and get some different pages pushed onwards so
 * we can try to get out of this scenario.
 */
static void
vps_deal_with_throttled_queues(vm_page_t m, vm_object_t *object, uint32_t *vm_pageout_inactive_external_forced_reactivate_limit,
    int *delayed_unlock, boolean_t *force_anonymous, __unused boolean_t is_page_from_bg_q)
{
	struct  vm_pageout_queue *eq;
	vm_object_t cur_object = VM_OBJECT_NULL;

	cur_object = *object;

	eq = &vm_pageout_queue_external;

	if (cur_object->internal == FALSE) {
		/*
		 * we need to break up the following potential deadlock case...
		 *  a) The external pageout thread is stuck on the truncate lock for a file that is being extended i.e. written.
		 *  b) The thread doing the writing is waiting for pages while holding the truncate lock
		 *  c) Most of the pages in the inactive queue belong to this file.
		 *
		 * we are potentially in this deadlock because...
		 *  a) the external pageout queue is throttled
		 *  b) we're done with the active queue and moved on to the inactive queue
		 *  c) we've got a dirty external page
		 *
		 * since we don't know the reason for the external pageout queue being throttled we
		 * must suspect that we are deadlocked, so move the current page onto the active queue
		 * in an effort to cause a page from the active queue to 'age' to the inactive queue
		 *
		 * if we don't have jetsam configured (i.e. we have a dynamic pager), set
		 * 'force_anonymous' to TRUE to cause us to grab a page from the cleaned/anonymous
		 * pool the next time we select a victim page... if we can make enough new free pages,
		 * the deadlock will break, the external pageout queue will empty and it will no longer
		 * be throttled
		 *
		 * if we have jetsam configured, keep a count of the pages reactivated this way so
		 * that we can try to find clean pages in the active/inactive queues before
		 * deciding to jetsam a process
		 */
		vm_pageout_vminfo.vm_pageout_scan_inactive_throttled_external++;

		vm_page_check_pageable_safe(m);
		assert(m->vmp_q_state == VM_PAGE_NOT_ON_Q);
		vm_page_queue_enter(&vm_page_queue_active, m, vmp_pageq);
		m->vmp_q_state = VM_PAGE_ON_ACTIVE_Q;
		vm_page_active_count++;
		vm_page_pageable_external_count++;

		vm_pageout_adjust_eq_iothrottle(eq, FALSE);

#if CONFIG_MEMORYSTATUS && CONFIG_JETSAM

#pragma unused(force_anonymous)

		*vm_pageout_inactive_external_forced_reactivate_limit -= 1;

		if (*vm_pageout_inactive_external_forced_reactivate_limit <= 0) {
			*vm_pageout_inactive_external_forced_reactivate_limit = vm_page_active_count + vm_page_inactive_count;
			/*
			 * Possible deadlock scenario so request jetsam action
			 */

			assert(cur_object);
			vm_object_unlock(cur_object);

			cur_object = VM_OBJECT_NULL;

			/*
			 * VM pageout scan needs to know we have dropped this lock and so set the
			 * object variable we got passed in to NULL.
			 */
			*object = VM_OBJECT_NULL;

			vm_page_unlock_queues();

			VM_DEBUG_CONSTANT_EVENT(vm_pageout_jetsam, VM_PAGEOUT_JETSAM, DBG_FUNC_START,
			    vm_page_active_count, vm_page_inactive_count, vm_page_free_count, vm_page_free_count);

			/* Kill first suitable process. If this call returned FALSE, we might have simply purged a process instead. */
			if (memorystatus_kill_on_VM_page_shortage(FALSE) == TRUE) {
				VM_PAGEOUT_DEBUG(vm_pageout_inactive_external_forced_jetsam_count, 1);
			}

			VM_DEBUG_CONSTANT_EVENT(vm_pageout_jetsam, VM_PAGEOUT_JETSAM, DBG_FUNC_END,
			    vm_page_active_count, vm_page_inactive_count, vm_page_free_count, vm_page_free_count);

			vm_page_lock_queues();
			*delayed_unlock = 1;
		}
#else /* CONFIG_MEMORYSTATUS && CONFIG_JETSAM */

#pragma unused(vm_pageout_inactive_external_forced_reactivate_limit)
#pragma unused(delayed_unlock)

		*force_anonymous = TRUE;
#endif /* CONFIG_MEMORYSTATUS && CONFIG_JETSAM */
	} else {
		vm_page_activate(m);
		VM_STAT_INCR(reactivations);

#if CONFIG_BACKGROUND_QUEUE
#if DEVELOPMENT || DEBUG
		if (is_page_from_bg_q == TRUE) {
			if (cur_object->internal) {
				vm_pageout_rejected_bq_internal++;
			} else {
				vm_pageout_rejected_bq_external++;
			}
		}
#endif /* DEVELOPMENT || DEBUG */
#endif /* CONFIG_BACKGROUND_QUEUE */

		vm_pageout_state.vm_pageout_inactive_used++;
	}
}


void
vm_page_balance_inactive(int max_to_move)
{
	vm_page_t m;

	LCK_MTX_ASSERT(&vm_page_queue_lock, LCK_MTX_ASSERT_OWNED);

	if (hibernation_vmqueues_inspection == TRUE) {
		/*
		 * It is likely that the hibernation code path is
		 * dealing with these very queues as we are about
		 * to move pages around in/from them and completely
		 * change the linkage of the pages.
		 *
		 * And so we skip the rebalancing of these queues.
		 */
		return;
	}
	vm_page_inactive_target = VM_PAGE_INACTIVE_TARGET(vm_page_active_count +
	    vm_page_inactive_count +
	    vm_page_speculative_count);

	while (max_to_move-- && (vm_page_inactive_count + vm_page_speculative_count) < vm_page_inactive_target) {
		VM_PAGEOUT_DEBUG(vm_pageout_balanced, 1);

		m = (vm_page_t) vm_page_queue_first(&vm_page_queue_active);

		assert(m->vmp_q_state == VM_PAGE_ON_ACTIVE_Q);
		assert(!m->vmp_laundry);
		assert(VM_PAGE_OBJECT(m) != kernel_object);
		assert(VM_PAGE_GET_PHYS_PAGE(m) != vm_page_guard_addr);

		DTRACE_VM2(scan, int, 1, (uint64_t *), NULL);

		/*
		 * by not passing in a pmap_flush_context we will forgo any TLB flushing, local or otherwise...
		 *
		 * a TLB flush isn't really needed here since at worst we'll miss the reference bit being
		 * updated in the PTE if a remote processor still has this mapping cached in its TLB when the
		 * new reference happens. If no futher references happen on the page after that remote TLB flushes
		 * we'll see a clean, non-referenced page when it eventually gets pulled out of the inactive queue
		 * by pageout_scan, which is just fine since the last reference would have happened quite far
		 * in the past (TLB caches don't hang around for very long), and of course could just as easily
		 * have happened before we moved the page
		 */
		if (m->vmp_pmapped == TRUE) {
			pmap_clear_refmod_options(VM_PAGE_GET_PHYS_PAGE(m), VM_MEM_REFERENCED, PMAP_OPTIONS_NOFLUSH, (void *)NULL);
		}

		/*
		 * The page might be absent or busy,
		 * but vm_page_deactivate can handle that.
		 * FALSE indicates that we don't want a H/W clear reference
		 */
		vm_page_deactivate_internal(m, FALSE);
	}
}


/*
 *	vm_pageout_scan does the dirty work for the pageout daemon.
 *	It returns with both vm_page_queue_free_lock and vm_page_queue_lock
 *	held and vm_page_free_wanted == 0.
 */
void
vm_pageout_scan(void)
{
	unsigned int loop_count = 0;
	unsigned int inactive_burst_count = 0;
	unsigned int reactivated_this_call;
	unsigned int reactivate_limit;
	vm_page_t   local_freeq = NULL;
	int         local_freed = 0;
	int         delayed_unlock;
	int         delayed_unlock_limit = 0;
	int         refmod_state = 0;
	int     vm_pageout_deadlock_target = 0;
	struct  vm_pageout_queue *iq;
	struct  vm_pageout_queue *eq;
	struct  vm_speculative_age_q *sq;
	struct  flow_control    flow_control = { .state = 0, .ts = { .tv_sec = 0, .tv_nsec = 0 } };
	boolean_t inactive_throttled = FALSE;
	vm_object_t     object = NULL;
	uint32_t        inactive_reclaim_run;
	boolean_t       grab_anonymous = FALSE;
	boolean_t       force_anonymous = FALSE;
	boolean_t       force_speculative_aging = FALSE;
	int             anons_grabbed = 0;
	int             page_prev_q_state = 0;
	boolean_t       page_from_bg_q = FALSE;
	uint32_t        vm_pageout_inactive_external_forced_reactivate_limit = 0;
	vm_object_t     m_object = VM_OBJECT_NULL;
	int             retval = 0;
	boolean_t       lock_yield_check = FALSE;


	VM_DEBUG_CONSTANT_EVENT(vm_pageout_scan, VM_PAGEOUT_SCAN, DBG_FUNC_START,
	    vm_pageout_vminfo.vm_pageout_freed_speculative,
	    vm_pageout_state.vm_pageout_inactive_clean,
	    vm_pageout_vminfo.vm_pageout_inactive_dirty_internal,
	    vm_pageout_vminfo.vm_pageout_inactive_dirty_external);

	flow_control.state = FCS_IDLE;
	iq = &vm_pageout_queue_internal;
	eq = &vm_pageout_queue_external;
	sq = &vm_page_queue_speculative[VM_PAGE_SPECULATIVE_AGED_Q];

	/* Ask the pmap layer to return any pages it no longer needs. */
	uint64_t pmap_wired_pages_freed = pmap_release_pages_fast();

	vm_page_lock_queues();

	vm_page_wire_count -= pmap_wired_pages_freed;

	delayed_unlock = 1;

	/*
	 *	Calculate the max number of referenced pages on the inactive
	 *	queue that we will reactivate.
	 */
	reactivated_this_call = 0;
	reactivate_limit = VM_PAGE_REACTIVATE_LIMIT(vm_page_active_count +
	    vm_page_inactive_count);
	inactive_reclaim_run = 0;

	vm_pageout_inactive_external_forced_reactivate_limit = vm_page_active_count + vm_page_inactive_count;

	/*
	 *	We must limit the rate at which we send pages to the pagers
	 *	so that we don't tie up too many pages in the I/O queues.
	 *	We implement a throttling mechanism using the laundry count
	 *      to limit the number of pages outstanding to the default
	 *	and external pagers.  We can bypass the throttles and look
	 *	for clean pages if the pageout queues don't drain in a timely
	 *	fashion since this may indicate that the pageout paths are
	 *	stalled waiting for memory, which only we can provide.
	 */

	vps_init_page_targets();
	assert(object == NULL);
	assert(delayed_unlock != 0);

	for (;;) {
		vm_page_t m;

		DTRACE_VM2(rev, int, 1, (uint64_t *), NULL);

		if (lock_yield_check) {
			lock_yield_check = FALSE;

			if (delayed_unlock++ > delayed_unlock_limit) {
				int freed = local_freed;

				vm_pageout_prepare_to_block(&object, &delayed_unlock, &local_freeq, &local_freed,
				    VM_PAGEOUT_PB_CONSIDER_WAKING_COMPACTOR_SWAPPER);
				if (freed == 0) {
					lck_mtx_yield(&vm_page_queue_lock);
				}
			} else if (vm_pageout_scan_wants_object) {
				vm_page_unlock_queues();
				mutex_pause(0);
				vm_page_lock_queues();
			}
		}

		if (vm_upl_wait_for_pages < 0) {
			vm_upl_wait_for_pages = 0;
		}

		delayed_unlock_limit = VM_PAGEOUT_DELAYED_UNLOCK_LIMIT + vm_upl_wait_for_pages;

		if (delayed_unlock_limit > VM_PAGEOUT_DELAYED_UNLOCK_LIMIT_MAX) {
			delayed_unlock_limit = VM_PAGEOUT_DELAYED_UNLOCK_LIMIT_MAX;
		}

		vps_deal_with_secluded_page_overflow(&local_freeq, &local_freed);

		assert(delayed_unlock);

		/*
		 * maintain our balance
		 */
		vm_page_balance_inactive(1);


		/**********************************************************************
		* above this point we're playing with the active and secluded queues
		* below this point we're playing with the throttling mechanisms
		* and the inactive queue
		**********************************************************************/

		if (vm_page_free_count + local_freed >= vm_page_free_target) {
			vm_pageout_scan_wants_object = VM_OBJECT_NULL;

			vm_pageout_prepare_to_block(&object, &delayed_unlock, &local_freeq, &local_freed,
			    VM_PAGEOUT_PB_CONSIDER_WAKING_COMPACTOR_SWAPPER);
			/*
			 * make sure the pageout I/O threads are running
			 * throttled in case there are still requests
			 * in the laundry... since we have met our targets
			 * we don't need the laundry to be cleaned in a timely
			 * fashion... so let's avoid interfering with foreground
			 * activity
			 */
			vm_pageout_adjust_eq_iothrottle(eq, TRUE);

			lck_mtx_lock(&vm_page_queue_free_lock);

			if ((vm_page_free_count >= vm_page_free_target) &&
			    (vm_page_free_wanted == 0) && (vm_page_free_wanted_privileged == 0)) {
				/*
				 * done - we have met our target *and*
				 * there is no one waiting for a page.
				 */
return_from_scan:
				assert(vm_pageout_scan_wants_object == VM_OBJECT_NULL);

				VM_DEBUG_CONSTANT_EVENT(vm_pageout_scan, VM_PAGEOUT_SCAN, DBG_FUNC_NONE,
				    vm_pageout_state.vm_pageout_inactive,
				    vm_pageout_state.vm_pageout_inactive_used, 0, 0);
				VM_DEBUG_CONSTANT_EVENT(vm_pageout_scan, VM_PAGEOUT_SCAN, DBG_FUNC_END,
				    vm_pageout_vminfo.vm_pageout_freed_speculative,
				    vm_pageout_state.vm_pageout_inactive_clean,
				    vm_pageout_vminfo.vm_pageout_inactive_dirty_internal,
				    vm_pageout_vminfo.vm_pageout_inactive_dirty_external);

				return;
			}
			lck_mtx_unlock(&vm_page_queue_free_lock);
		}

		/*
		 * Before anything, we check if we have any ripe volatile
		 * objects around. If so, try to purge the first object.
		 * If the purge fails, fall through to reclaim a page instead.
		 * If the purge succeeds, go back to the top and reevalute
		 * the new memory situation.
		 */
		retval = vps_purge_object();

		if (retval == VM_PAGEOUT_SCAN_NEXT_ITERATION) {
			/*
			 * Success
			 */
			if (object != NULL) {
				vm_object_unlock(object);
				object = NULL;
			}

			lock_yield_check = FALSE;
			continue;
		}

		/*
		 * If our 'aged' queue is empty and we have some speculative pages
		 * in the other queues, let's go through and see if we need to age
		 * them.
		 *
		 * If we succeeded in aging a speculative Q or just that everything
		 * looks normal w.r.t queue age and queue counts, we keep going onward.
		 *
		 * If, for some reason, we seem to have a mismatch between the spec.
		 * page count and the page queues, we reset those variables and
		 * restart the loop (LD TODO: Track this better?).
		 */
		if (vm_page_queue_empty(&sq->age_q) && vm_page_speculative_count) {
			retval = vps_age_speculative_queue(force_speculative_aging);

			if (retval == VM_PAGEOUT_SCAN_NEXT_ITERATION) {
				lock_yield_check = FALSE;
				continue;
			}
		}
		force_speculative_aging = FALSE;

		/*
		 * Check to see if we need to evict objects from the cache.
		 *
		 * Note: 'object' here doesn't have anything to do with
		 * the eviction part. We just need to make sure we have dropped
		 * any object lock we might be holding if we need to go down
		 * into the eviction logic.
		 */
		retval = vps_object_cache_evict(&object);

		if (retval == VM_PAGEOUT_SCAN_NEXT_ITERATION) {
			lock_yield_check = FALSE;
			continue;
		}


		/*
		 * Calculate our filecache_min that will affect the loop
		 * going forward.
		 */
		vps_calculate_filecache_min();

		/*
		 * LD TODO: Use a structure to hold all state variables for a single
		 * vm_pageout_scan iteration and pass that structure to this function instead.
		 */
		retval = vps_flow_control(&flow_control, &anons_grabbed, &object,
		    &delayed_unlock, &local_freeq, &local_freed,
		    &vm_pageout_deadlock_target, inactive_burst_count);

		if (retval == VM_PAGEOUT_SCAN_NEXT_ITERATION) {
			if (loop_count >= vm_page_inactive_count) {
				loop_count = 0;
			}

			inactive_burst_count = 0;

			assert(object == NULL);
			assert(delayed_unlock != 0);

			lock_yield_check = FALSE;
			continue;
		} else if (retval == VM_PAGEOUT_SCAN_DONE_RETURN) {
			goto return_from_scan;
		}

		flow_control.state = FCS_IDLE;

		vm_pageout_inactive_external_forced_reactivate_limit = MIN((vm_page_active_count + vm_page_inactive_count),
		    vm_pageout_inactive_external_forced_reactivate_limit);
		loop_count++;
		inactive_burst_count++;
		vm_pageout_state.vm_pageout_inactive++;

		/*
		 * Choose a victim.
		 */

		m = NULL;
		retval = vps_choose_victim_page(&m, &anons_grabbed, &grab_anonymous, force_anonymous, &page_from_bg_q, reactivated_this_call);

		if (m == NULL) {
			if (retval == VM_PAGEOUT_SCAN_NEXT_ITERATION) {
				reactivated_this_call++;

				inactive_burst_count = 0;

				if (page_prev_q_state == VM_PAGE_ON_INACTIVE_CLEANED_Q) {
					VM_PAGEOUT_DEBUG(vm_pageout_cleaned_reactivated, 1);
				}

				lock_yield_check = TRUE;
				continue;
			}

			/*
			 * if we've gotten here, we have no victim page.
			 * check to see if we've not finished balancing the queues
			 * or we have a page on the aged speculative queue that we
			 * skipped due to force_anonymous == TRUE.. or we have
			 * speculative  pages that we can prematurely age... if
			 * one of these cases we'll keep going, else panic
			 */
			force_anonymous = FALSE;
			VM_PAGEOUT_DEBUG(vm_pageout_no_victim, 1);

			if (!vm_page_queue_empty(&sq->age_q)) {
				lock_yield_check = TRUE;
				continue;
			}

			if (vm_page_speculative_count) {
				force_speculative_aging = TRUE;
				lock_yield_check = TRUE;
				continue;
			}
			panic("vm_pageout: no victim");

			/* NOTREACHED */
		}

		assert(VM_PAGE_PAGEABLE(m));
		m_object = VM_PAGE_OBJECT(m);
		force_anonymous = FALSE;

		page_prev_q_state = m->vmp_q_state;
		/*
		 * we just found this page on one of our queues...
		 * it can't also be on the pageout queue, so safe
		 * to call vm_page_queues_remove
		 */
		vm_page_queues_remove(m, TRUE);

		assert(!m->vmp_laundry);
		assert(!m->vmp_private);
		assert(!m->vmp_fictitious);
		assert(m_object != kernel_object);
		assert(VM_PAGE_GET_PHYS_PAGE(m) != vm_page_guard_addr);

		vm_pageout_vminfo.vm_pageout_considered_page++;

		DTRACE_VM2(scan, int, 1, (uint64_t *), NULL);

		/*
		 * check to see if we currently are working
		 * with the same object... if so, we've
		 * already got the lock
		 */
		if (m_object != object) {
			boolean_t avoid_anon_pages = (grab_anonymous == FALSE || anons_grabbed >= ANONS_GRABBED_LIMIT);

			/*
			 * vps_switch_object() will always drop the 'object' lock first
			 * and then try to acquire the 'm_object' lock. So 'object' has to point to
			 * either 'm_object' or NULL.
			 */
			retval = vps_switch_object(m, m_object, &object, page_prev_q_state, avoid_anon_pages, page_from_bg_q);

			if (retval == VM_PAGEOUT_SCAN_NEXT_ITERATION) {
				lock_yield_check = TRUE;
				continue;
			}
		}
		assert(m_object == object);
		assert(VM_PAGE_OBJECT(m) == m_object);

		if (m->vmp_busy) {
			/*
			 *	Somebody is already playing with this page.
			 *	Put it back on the appropriate queue
			 *
			 */
			VM_PAGEOUT_DEBUG(vm_pageout_inactive_busy, 1);

			if (page_prev_q_state == VM_PAGE_ON_INACTIVE_CLEANED_Q) {
				VM_PAGEOUT_DEBUG(vm_pageout_cleaned_busy, 1);
			}

			vps_requeue_page(m, page_prev_q_state, page_from_bg_q);

			lock_yield_check = TRUE;
			continue;
		}

		/*
		 *   if (m->vmp_cleaning && !m->vmp_free_when_done)
		 *	If already cleaning this page in place
		 *	just leave if off the paging queues.
		 *	We can leave the page mapped, and upl_commit_range
		 *	will put it on the clean queue.
		 *
		 *   if (m->vmp_free_when_done && !m->vmp_cleaning)
		 *	an msync INVALIDATE is in progress...
		 *	this page has been marked for destruction
		 *      after it has been cleaned,
		 *      but not yet gathered into a UPL
		 *	where 'cleaning' will be set...
		 *	just leave it off the paging queues
		 *
		 *   if (m->vmp_free_when_done && m->vmp_clenaing)
		 *	an msync INVALIDATE is in progress
		 *	and the UPL has already gathered this page...
		 *	just leave it off the paging queues
		 */
		if (m->vmp_free_when_done || m->vmp_cleaning) {
			lock_yield_check = TRUE;
			continue;
		}


		/*
		 *	If it's absent, in error or the object is no longer alive,
		 *	we can reclaim the page... in the no longer alive case,
		 *	there are 2 states the page can be in that preclude us
		 *	from reclaiming it - busy or cleaning - that we've already
		 *	dealt with
		 */
		if (m->vmp_absent || m->vmp_error || !object->alive) {
			if (m->vmp_absent) {
				VM_PAGEOUT_DEBUG(vm_pageout_inactive_absent, 1);
			} else if (!object->alive) {
				VM_PAGEOUT_DEBUG(vm_pageout_inactive_notalive, 1);
			} else {
				VM_PAGEOUT_DEBUG(vm_pageout_inactive_error, 1);
			}
reclaim_page:
			if (vm_pageout_deadlock_target) {
				VM_PAGEOUT_DEBUG(vm_pageout_scan_inactive_throttle_success, 1);
				vm_pageout_deadlock_target--;
			}

			DTRACE_VM2(dfree, int, 1, (uint64_t *), NULL);

			if (object->internal) {
				DTRACE_VM2(anonfree, int, 1, (uint64_t *), NULL);
			} else {
				DTRACE_VM2(fsfree, int, 1, (uint64_t *), NULL);
			}
			assert(!m->vmp_cleaning);
			assert(!m->vmp_laundry);

			if (!object->internal &&
			    object->pager != NULL &&
			    object->pager->mo_pager_ops == &shared_region_pager_ops) {
				shared_region_pager_reclaimed++;
			}

			m->vmp_busy = TRUE;

			/*
			 * remove page from object here since we're already
			 * behind the object lock... defer the rest of the work
			 * we'd normally do in vm_page_free_prepare_object
			 * until 'vm_page_free_list' is called
			 */
			if (m->vmp_tabled) {
				vm_page_remove(m, TRUE);
			}

			assert(m->vmp_pageq.next == 0 && m->vmp_pageq.prev == 0);
			m->vmp_snext = local_freeq;
			local_freeq = m;
			local_freed++;

			if (page_prev_q_state == VM_PAGE_ON_SPECULATIVE_Q) {
				vm_pageout_vminfo.vm_pageout_freed_speculative++;
			} else if (page_prev_q_state == VM_PAGE_ON_INACTIVE_CLEANED_Q) {
				vm_pageout_vminfo.vm_pageout_freed_cleaned++;
			} else if (page_prev_q_state == VM_PAGE_ON_INACTIVE_INTERNAL_Q) {
				vm_pageout_vminfo.vm_pageout_freed_internal++;
			} else {
				vm_pageout_vminfo.vm_pageout_freed_external++;
			}

			inactive_burst_count = 0;

			lock_yield_check = TRUE;
			continue;
		}
		if (object->copy == VM_OBJECT_NULL) {
			/*
			 * No one else can have any interest in this page.
			 * If this is an empty purgable object, the page can be
			 * reclaimed even if dirty.
			 * If the page belongs to a volatile purgable object, we
			 * reactivate it if the compressor isn't active.
			 */
			if (object->purgable == VM_PURGABLE_EMPTY) {
				if (m->vmp_pmapped == TRUE) {
					/* unmap the page */
					refmod_state = pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(m));
					if (refmod_state & VM_MEM_MODIFIED) {
						SET_PAGE_DIRTY(m, FALSE);
					}
				}
				if (m->vmp_dirty || m->vmp_precious) {
					/* we saved the cost of cleaning this page ! */
					vm_page_purged_count++;
				}
				goto reclaim_page;
			}

			if (VM_CONFIG_COMPRESSOR_IS_ACTIVE) {
				/*
				 * With the VM compressor, the cost of
				 * reclaiming a page is much lower (no I/O),
				 * so if we find a "volatile" page, it's better
				 * to let it get compressed rather than letting
				 * it occupy a full page until it gets purged.
				 * So no need to check for "volatile" here.
				 */
			} else if (object->purgable == VM_PURGABLE_VOLATILE) {
				/*
				 * Avoid cleaning a "volatile" page which might
				 * be purged soon.
				 */

				/* if it's wired, we can't put it on our queue */
				assert(!VM_PAGE_WIRED(m));

				/* just stick it back on! */
				reactivated_this_call++;

				if (page_prev_q_state == VM_PAGE_ON_INACTIVE_CLEANED_Q) {
					VM_PAGEOUT_DEBUG(vm_pageout_cleaned_volatile_reactivated, 1);
				}

				goto reactivate_page;
			}
		}
		/*
		 *	If it's being used, reactivate.
		 *	(Fictitious pages are either busy or absent.)
		 *	First, update the reference and dirty bits
		 *	to make sure the page is unreferenced.
		 */
		refmod_state = -1;

		if (m->vmp_reference == FALSE && m->vmp_pmapped == TRUE) {
			refmod_state = pmap_get_refmod(VM_PAGE_GET_PHYS_PAGE(m));

			if (refmod_state & VM_MEM_REFERENCED) {
				m->vmp_reference = TRUE;
			}
			if (refmod_state & VM_MEM_MODIFIED) {
				SET_PAGE_DIRTY(m, FALSE);
			}
		}

		if (m->vmp_reference || m->vmp_dirty) {
			/* deal with a rogue "reusable" page */
			VM_PAGEOUT_SCAN_HANDLE_REUSABLE_PAGE(m, m_object);
		}

		if (vm_pageout_state.vm_page_xpmapped_min_divisor == 0) {
			vm_pageout_state.vm_page_xpmapped_min = 0;
		} else {
			vm_pageout_state.vm_page_xpmapped_min = (vm_page_external_count * 10) / vm_pageout_state.vm_page_xpmapped_min_divisor;
		}

		if (!m->vmp_no_cache &&
		    page_from_bg_q == FALSE &&
		    (m->vmp_reference || (m->vmp_xpmapped && !object->internal &&
		    (vm_page_xpmapped_external_count < vm_pageout_state.vm_page_xpmapped_min)))) {
			/*
			 * The page we pulled off the inactive list has
			 * been referenced.  It is possible for other
			 * processors to be touching pages faster than we
			 * can clear the referenced bit and traverse the
			 * inactive queue, so we limit the number of
			 * reactivations.
			 */
			if (++reactivated_this_call >= reactivate_limit) {
				vm_pageout_vminfo.vm_pageout_reactivation_limit_exceeded++;
			} else if (++inactive_reclaim_run >= VM_PAGEOUT_INACTIVE_FORCE_RECLAIM) {
				vm_pageout_vminfo.vm_pageout_inactive_force_reclaim++;
			} else {
				uint32_t isinuse;

				if (page_prev_q_state == VM_PAGE_ON_INACTIVE_CLEANED_Q) {
					VM_PAGEOUT_DEBUG(vm_pageout_cleaned_reference_reactivated, 1);
				}

				vm_pageout_vminfo.vm_pageout_inactive_referenced++;
reactivate_page:
				if (!object->internal && object->pager != MEMORY_OBJECT_NULL &&
				    vnode_pager_get_isinuse(object->pager, &isinuse) == KERN_SUCCESS && !isinuse) {
					/*
					 * no explict mappings of this object exist
					 * and it's not open via the filesystem
					 */
					vm_page_deactivate(m);
					VM_PAGEOUT_DEBUG(vm_pageout_inactive_deactivated, 1);
				} else {
					/*
					 * The page was/is being used, so put back on active list.
					 */
					vm_page_activate(m);
					VM_STAT_INCR(reactivations);
					inactive_burst_count = 0;
				}
#if CONFIG_BACKGROUND_QUEUE
#if DEVELOPMENT || DEBUG
				if (page_from_bg_q == TRUE) {
					if (m_object->internal) {
						vm_pageout_rejected_bq_internal++;
					} else {
						vm_pageout_rejected_bq_external++;
					}
				}
#endif /* DEVELOPMENT || DEBUG */
#endif /* CONFIG_BACKGROUND_QUEUE */

				if (page_prev_q_state == VM_PAGE_ON_INACTIVE_CLEANED_Q) {
					VM_PAGEOUT_DEBUG(vm_pageout_cleaned_reactivated, 1);
				}
				vm_pageout_state.vm_pageout_inactive_used++;

				lock_yield_check = TRUE;
				continue;
			}
			/*
			 * Make sure we call pmap_get_refmod() if it
			 * wasn't already called just above, to update
			 * the dirty bit.
			 */
			if ((refmod_state == -1) && !m->vmp_dirty && m->vmp_pmapped) {
				refmod_state = pmap_get_refmod(VM_PAGE_GET_PHYS_PAGE(m));
				if (refmod_state & VM_MEM_MODIFIED) {
					SET_PAGE_DIRTY(m, FALSE);
				}
			}
		}

		/*
		 * we've got a candidate page to steal...
		 *
		 * m->vmp_dirty is up to date courtesy of the
		 * preceding check for m->vmp_reference... if
		 * we get here, then m->vmp_reference had to be
		 * FALSE (or possibly "reactivate_limit" was
		 * exceeded), but in either case we called
		 * pmap_get_refmod() and updated both
		 * m->vmp_reference and m->vmp_dirty
		 *
		 * if it's dirty or precious we need to
		 * see if the target queue is throtttled
		 * it if is, we need to skip over it by moving it back
		 * to the end of the inactive queue
		 */

		inactive_throttled = FALSE;

		if (m->vmp_dirty || m->vmp_precious) {
			if (object->internal) {
				if (VM_PAGE_Q_THROTTLED(iq)) {
					inactive_throttled = TRUE;
				}
			} else if (VM_PAGE_Q_THROTTLED(eq)) {
				inactive_throttled = TRUE;
			}
		}
throttle_inactive:
		if (!VM_DYNAMIC_PAGING_ENABLED() &&
		    object->internal && m->vmp_dirty &&
		    (object->purgable == VM_PURGABLE_DENY ||
		    object->purgable == VM_PURGABLE_NONVOLATILE ||
		    object->purgable == VM_PURGABLE_VOLATILE)) {
			vm_page_check_pageable_safe(m);
			assert(m->vmp_q_state == VM_PAGE_NOT_ON_Q);
			vm_page_queue_enter(&vm_page_queue_throttled, m, vmp_pageq);
			m->vmp_q_state = VM_PAGE_ON_THROTTLED_Q;
			vm_page_throttled_count++;

			VM_PAGEOUT_DEBUG(vm_pageout_scan_reclaimed_throttled, 1);

			inactive_burst_count = 0;

			lock_yield_check = TRUE;
			continue;
		}
		if (inactive_throttled == TRUE) {
			vps_deal_with_throttled_queues(m, &object, &vm_pageout_inactive_external_forced_reactivate_limit,
			    &delayed_unlock, &force_anonymous, page_from_bg_q);

			inactive_burst_count = 0;

			if (page_prev_q_state == VM_PAGE_ON_INACTIVE_CLEANED_Q) {
				VM_PAGEOUT_DEBUG(vm_pageout_cleaned_reactivated, 1);
			}

			lock_yield_check = TRUE;
			continue;
		}

		/*
		 * we've got a page that we can steal...
		 * eliminate all mappings and make sure
		 * we have the up-to-date modified state
		 *
		 * if we need to do a pmap_disconnect then we
		 * need to re-evaluate m->vmp_dirty since the pmap_disconnect
		 * provides the true state atomically... the
		 * page was still mapped up to the pmap_disconnect
		 * and may have been dirtied at the last microsecond
		 *
		 * Note that if 'pmapped' is FALSE then the page is not
		 * and has not been in any map, so there is no point calling
		 * pmap_disconnect().  m->vmp_dirty could have been set in anticipation
		 * of likely usage of the page.
		 */
		if (m->vmp_pmapped == TRUE) {
			int pmap_options;

			/*
			 * Don't count this page as going into the compressor
			 * if any of these are true:
			 * 1) compressed pager isn't enabled
			 * 2) Freezer enabled device with compressed pager
			 *    backend (exclusive use) i.e. most of the VM system
			 *    (including vm_pageout_scan) has no knowledge of
			 *    the compressor
			 * 3) This page belongs to a file and hence will not be
			 *    sent into the compressor
			 */
			if (!VM_CONFIG_COMPRESSOR_IS_ACTIVE ||
			    object->internal == FALSE) {
				pmap_options = 0;
			} else if (m->vmp_dirty || m->vmp_precious) {
				/*
				 * VM knows that this page is dirty (or
				 * precious) and needs to be compressed
				 * rather than freed.
				 * Tell the pmap layer to count this page
				 * as "compressed".
				 */
				pmap_options = PMAP_OPTIONS_COMPRESSOR;
			} else {
				/*
				 * VM does not know if the page needs to
				 * be preserved but the pmap layer might tell
				 * us if any mapping has "modified" it.
				 * Let's the pmap layer to count this page
				 * as compressed if and only if it has been
				 * modified.
				 */
				pmap_options =
				    PMAP_OPTIONS_COMPRESSOR_IFF_MODIFIED;
			}
			refmod_state = pmap_disconnect_options(VM_PAGE_GET_PHYS_PAGE(m),
			    pmap_options,
			    NULL);
			if (refmod_state & VM_MEM_MODIFIED) {
				SET_PAGE_DIRTY(m, FALSE);
			}
		}

		/*
		 * reset our count of pages that have been reclaimed
		 * since the last page was 'stolen'
		 */
		inactive_reclaim_run = 0;

		/*
		 *	If it's clean and not precious, we can free the page.
		 */
		if (!m->vmp_dirty && !m->vmp_precious) {
			vm_pageout_state.vm_pageout_inactive_clean++;

			/*
			 * OK, at this point we have found a page we are going to free.
			 */
#if CONFIG_PHANTOM_CACHE
			if (!object->internal) {
				vm_phantom_cache_add_ghost(m);
			}
#endif
			goto reclaim_page;
		}

		/*
		 * The page may have been dirtied since the last check
		 * for a throttled target queue (which may have been skipped
		 * if the page was clean then).  With the dirty page
		 * disconnected here, we can make one final check.
		 */
		if (object->internal) {
			if (VM_PAGE_Q_THROTTLED(iq)) {
				inactive_throttled = TRUE;
			}
		} else if (VM_PAGE_Q_THROTTLED(eq)) {
			inactive_throttled = TRUE;
		}

		if (inactive_throttled == TRUE) {
			goto throttle_inactive;
		}

#if VM_PRESSURE_EVENTS
#if CONFIG_JETSAM

		/*
		 * If Jetsam is enabled, then the sending
		 * of memory pressure notifications is handled
		 * from the same thread that takes care of high-water
		 * and other jetsams i.e. the memorystatus_thread.
		 */

#else /* CONFIG_JETSAM */

		vm_pressure_response();

#endif /* CONFIG_JETSAM */
#endif /* VM_PRESSURE_EVENTS */

		if (page_prev_q_state == VM_PAGE_ON_SPECULATIVE_Q) {
			VM_PAGEOUT_DEBUG(vm_pageout_speculative_dirty, 1);
		}

		if (object->internal) {
			vm_pageout_vminfo.vm_pageout_inactive_dirty_internal++;
		} else {
			vm_pageout_vminfo.vm_pageout_inactive_dirty_external++;
		}

		/*
		 * internal pages will go to the compressor...
		 * external pages will go to the appropriate pager to be cleaned
		 * and upon completion will end up on 'vm_page_queue_cleaned' which
		 * is a preferred queue to steal from
		 */
		vm_pageout_cluster(m);
		inactive_burst_count = 0;

		/*
		 * back to top of pageout scan loop
		 */
	}
}


void
vm_page_free_reserve(
	int pages)
{
	int             free_after_reserve;

	if (VM_CONFIG_COMPRESSOR_IS_PRESENT) {
		if ((vm_page_free_reserved + pages + COMPRESSOR_FREE_RESERVED_LIMIT) >= (VM_PAGE_FREE_RESERVED_LIMIT + COMPRESSOR_FREE_RESERVED_LIMIT)) {
			vm_page_free_reserved = VM_PAGE_FREE_RESERVED_LIMIT + COMPRESSOR_FREE_RESERVED_LIMIT;
		} else {
			vm_page_free_reserved += (pages + COMPRESSOR_FREE_RESERVED_LIMIT);
		}
	} else {
		if ((vm_page_free_reserved + pages) >= VM_PAGE_FREE_RESERVED_LIMIT) {
			vm_page_free_reserved = VM_PAGE_FREE_RESERVED_LIMIT;
		} else {
			vm_page_free_reserved += pages;
		}
	}
	free_after_reserve = vm_pageout_state.vm_page_free_count_init - vm_page_free_reserved;

	vm_page_free_min = vm_page_free_reserved +
	    VM_PAGE_FREE_MIN(free_after_reserve);

	if (vm_page_free_min > VM_PAGE_FREE_MIN_LIMIT) {
		vm_page_free_min = VM_PAGE_FREE_MIN_LIMIT;
	}

	vm_page_free_target = vm_page_free_reserved +
	    VM_PAGE_FREE_TARGET(free_after_reserve);

	if (vm_page_free_target > VM_PAGE_FREE_TARGET_LIMIT) {
		vm_page_free_target = VM_PAGE_FREE_TARGET_LIMIT;
	}

	if (vm_page_free_target < vm_page_free_min + 5) {
		vm_page_free_target = vm_page_free_min + 5;
	}

	vm_page_throttle_limit = vm_page_free_target - (vm_page_free_target / 2);
}

/*
 *	vm_pageout is the high level pageout daemon.
 */

void
vm_pageout_continue(void)
{
	DTRACE_VM2(pgrrun, int, 1, (uint64_t *), NULL);
	VM_PAGEOUT_DEBUG(vm_pageout_scan_event_counter, 1);

	lck_mtx_lock(&vm_page_queue_free_lock);
	vm_pageout_running = TRUE;
	lck_mtx_unlock(&vm_page_queue_free_lock);

	vm_pageout_scan();
	/*
	 * we hold both the vm_page_queue_free_lock
	 * and the vm_page_queues_lock at this point
	 */
	assert(vm_page_free_wanted == 0);
	assert(vm_page_free_wanted_privileged == 0);
	assert_wait((event_t) &vm_page_free_wanted, THREAD_UNINT);

	vm_pageout_running = FALSE;
#if !CONFIG_EMBEDDED
	if (vm_pageout_waiter) {
		vm_pageout_waiter = FALSE;
		thread_wakeup((event_t)&vm_pageout_waiter);
	}
#endif /* !CONFIG_EMBEDDED */

	lck_mtx_unlock(&vm_page_queue_free_lock);
	vm_page_unlock_queues();

	counter(c_vm_pageout_block++);
	thread_block((thread_continue_t)vm_pageout_continue);
	/*NOTREACHED*/
}

#if !CONFIG_EMBEDDED
kern_return_t
vm_pageout_wait(uint64_t deadline)
{
	kern_return_t kr;

	lck_mtx_lock(&vm_page_queue_free_lock);
	for (kr = KERN_SUCCESS; vm_pageout_running && (KERN_SUCCESS == kr);) {
		vm_pageout_waiter = TRUE;
		if (THREAD_AWAKENED != lck_mtx_sleep_deadline(
			    &vm_page_queue_free_lock, LCK_SLEEP_DEFAULT,
			    (event_t) &vm_pageout_waiter, THREAD_UNINT, deadline)) {
			kr = KERN_OPERATION_TIMED_OUT;
		}
	}
	lck_mtx_unlock(&vm_page_queue_free_lock);

	return kr;
}
#endif /* !CONFIG_EMBEDDED */


static void
vm_pageout_iothread_external_continue(struct vm_pageout_queue *q)
{
	vm_page_t       m = NULL;
	vm_object_t     object;
	vm_object_offset_t offset;
	memory_object_t pager;

	/* On systems with a compressor, the external IO thread clears its
	 * VM privileged bit to accommodate large allocations (e.g. bulk UPL
	 * creation)
	 */
	if (vm_pageout_state.vm_pageout_internal_iothread != THREAD_NULL) {
		current_thread()->options &= ~TH_OPT_VMPRIV;
	}

	vm_page_lockspin_queues();

	while (!vm_page_queue_empty(&q->pgo_pending)) {
		q->pgo_busy = TRUE;
		vm_page_queue_remove_first(&q->pgo_pending, m, vmp_pageq);

		assert(m->vmp_q_state == VM_PAGE_ON_PAGEOUT_Q);
		VM_PAGE_CHECK(m);
		/*
		 * grab a snapshot of the object and offset this
		 * page is tabled in so that we can relookup this
		 * page after we've taken the object lock - these
		 * fields are stable while we hold the page queues lock
		 * but as soon as we drop it, there is nothing to keep
		 * this page in this object... we hold an activity_in_progress
		 * on this object which will keep it from terminating
		 */
		object = VM_PAGE_OBJECT(m);
		offset = m->vmp_offset;

		m->vmp_q_state = VM_PAGE_NOT_ON_Q;
		VM_PAGE_ZERO_PAGEQ_ENTRY(m);

		vm_page_unlock_queues();

		vm_object_lock(object);

		m = vm_page_lookup(object, offset);

		if (m == NULL || m->vmp_busy || m->vmp_cleaning ||
		    !m->vmp_laundry || (m->vmp_q_state != VM_PAGE_NOT_ON_Q)) {
			/*
			 * it's either the same page that someone else has
			 * started cleaning (or it's finished cleaning or
			 * been put back on the pageout queue), or
			 * the page has been freed or we have found a
			 * new page at this offset... in all of these cases
			 * we merely need to release the activity_in_progress
			 * we took when we put the page on the pageout queue
			 */
			vm_object_activity_end(object);
			vm_object_unlock(object);

			vm_page_lockspin_queues();
			continue;
		}
		pager = object->pager;

		if (pager == MEMORY_OBJECT_NULL) {
			/*
			 * This pager has been destroyed by either
			 * memory_object_destroy or vm_object_destroy, and
			 * so there is nowhere for the page to go.
			 */
			if (m->vmp_free_when_done) {
				/*
				 * Just free the page... VM_PAGE_FREE takes
				 * care of cleaning up all the state...
				 * including doing the vm_pageout_throttle_up
				 */
				VM_PAGE_FREE(m);
			} else {
				vm_page_lockspin_queues();

				vm_pageout_throttle_up(m);
				vm_page_activate(m);

				vm_page_unlock_queues();

				/*
				 *	And we are done with it.
				 */
			}
			vm_object_activity_end(object);
			vm_object_unlock(object);

			vm_page_lockspin_queues();
			continue;
		}
#if 0
		/*
		 * we don't hold the page queue lock
		 * so this check isn't safe to make
		 */
		VM_PAGE_CHECK(m);
#endif
		/*
		 * give back the activity_in_progress reference we
		 * took when we queued up this page and replace it
		 * it with a paging_in_progress reference that will
		 * also hold the paging offset from changing and
		 * prevent the object from terminating
		 */
		vm_object_activity_end(object);
		vm_object_paging_begin(object);
		vm_object_unlock(object);

		/*
		 * Send the data to the pager.
		 * any pageout clustering happens there
		 */
		memory_object_data_return(pager,
		    m->vmp_offset + object->paging_offset,
		    PAGE_SIZE,
		    NULL,
		    NULL,
		    FALSE,
		    FALSE,
		    0);

		vm_object_lock(object);
		vm_object_paging_end(object);
		vm_object_unlock(object);

		vm_pageout_io_throttle();

		vm_page_lockspin_queues();
	}
	q->pgo_busy = FALSE;
	q->pgo_idle = TRUE;

	assert_wait((event_t) &q->pgo_pending, THREAD_UNINT);
	vm_page_unlock_queues();

	thread_block_parameter((thread_continue_t)vm_pageout_iothread_external_continue, (void *) q);
	/*NOTREACHED*/
}


#define         MAX_FREE_BATCH          32
uint32_t vm_compressor_time_thread; /* Set via sysctl to record time accrued by
                                     * this thread.
                                     */


void
vm_pageout_iothread_internal_continue(struct cq *);
void
vm_pageout_iothread_internal_continue(struct cq *cq)
{
	struct vm_pageout_queue *q;
	vm_page_t       m = NULL;
	boolean_t       pgo_draining;
	vm_page_t   local_q;
	int         local_cnt;
	vm_page_t   local_freeq = NULL;
	int         local_freed = 0;
	int         local_batch_size;
#if DEVELOPMENT || DEBUG
	int       ncomps = 0;
	boolean_t marked_active = FALSE;
#endif
	KERNEL_DEBUG(0xe040000c | DBG_FUNC_END, 0, 0, 0, 0, 0);

	q = cq->q;
	local_batch_size = q->pgo_maxlaundry / (vm_pageout_state.vm_compressor_thread_count * 2);

#if RECORD_THE_COMPRESSED_DATA
	if (q->pgo_laundry) {
		c_compressed_record_init();
	}
#endif
	while (TRUE) {
		int     pages_left_on_q = 0;

		local_cnt = 0;
		local_q = NULL;

		KERNEL_DEBUG(0xe0400014 | DBG_FUNC_START, 0, 0, 0, 0, 0);

		vm_page_lock_queues();
#if DEVELOPMENT || DEBUG
		if (marked_active == FALSE) {
			vmct_active++;
			vmct_state[cq->id] = VMCT_ACTIVE;
			marked_active = TRUE;
			if (vmct_active == 1) {
				vm_compressor_epoch_start = mach_absolute_time();
			}
		}
#endif
		KERNEL_DEBUG(0xe0400014 | DBG_FUNC_END, 0, 0, 0, 0, 0);

		KERNEL_DEBUG(0xe0400018 | DBG_FUNC_START, q->pgo_laundry, 0, 0, 0, 0);

		while (!vm_page_queue_empty(&q->pgo_pending) && local_cnt < local_batch_size) {
			vm_page_queue_remove_first(&q->pgo_pending, m, vmp_pageq);
			assert(m->vmp_q_state == VM_PAGE_ON_PAGEOUT_Q);
			VM_PAGE_CHECK(m);

			m->vmp_q_state = VM_PAGE_NOT_ON_Q;
			VM_PAGE_ZERO_PAGEQ_ENTRY(m);
			m->vmp_laundry = FALSE;

			m->vmp_snext = local_q;
			local_q = m;
			local_cnt++;
		}
		if (local_q == NULL) {
			break;
		}

		q->pgo_busy = TRUE;

		if ((pgo_draining = q->pgo_draining) == FALSE) {
			vm_pageout_throttle_up_batch(q, local_cnt);
			pages_left_on_q = q->pgo_laundry;
		} else {
			pages_left_on_q = q->pgo_laundry - local_cnt;
		}

		vm_page_unlock_queues();

#if !RECORD_THE_COMPRESSED_DATA
		if (pages_left_on_q >= local_batch_size && cq->id < (vm_pageout_state.vm_compressor_thread_count - 1)) {
			thread_wakeup((event_t) ((uintptr_t)&q->pgo_pending + cq->id + 1));
		}
#endif
		KERNEL_DEBUG(0xe0400018 | DBG_FUNC_END, q->pgo_laundry, 0, 0, 0, 0);

		while (local_q) {
			KERNEL_DEBUG(0xe0400024 | DBG_FUNC_START, local_cnt, 0, 0, 0, 0);

			m = local_q;
			local_q = m->vmp_snext;
			m->vmp_snext = NULL;

			if (vm_pageout_compress_page(&cq->current_chead, cq->scratch_buf, m) == KERN_SUCCESS) {
#if DEVELOPMENT || DEBUG
				ncomps++;
#endif
				KERNEL_DEBUG(0xe0400024 | DBG_FUNC_END, local_cnt, 0, 0, 0, 0);

				m->vmp_snext = local_freeq;
				local_freeq = m;
				local_freed++;

				if (local_freed >= MAX_FREE_BATCH) {
					OSAddAtomic64(local_freed, &vm_pageout_vminfo.vm_pageout_compressions);

					vm_page_free_list(local_freeq, TRUE);

					local_freeq = NULL;
					local_freed = 0;
				}
			}
#if !CONFIG_JETSAM
			while (vm_page_free_count < COMPRESSOR_FREE_RESERVED_LIMIT) {
				kern_return_t   wait_result;
				int             need_wakeup = 0;

				if (local_freeq) {
					OSAddAtomic64(local_freed, &vm_pageout_vminfo.vm_pageout_compressions);

					vm_page_free_list(local_freeq, TRUE);
					local_freeq = NULL;
					local_freed = 0;

					continue;
				}
				lck_mtx_lock_spin(&vm_page_queue_free_lock);

				if (vm_page_free_count < COMPRESSOR_FREE_RESERVED_LIMIT) {
					if (vm_page_free_wanted_privileged++ == 0) {
						need_wakeup = 1;
					}
					wait_result = assert_wait((event_t)&vm_page_free_wanted_privileged, THREAD_UNINT);

					lck_mtx_unlock(&vm_page_queue_free_lock);

					if (need_wakeup) {
						thread_wakeup((event_t)&vm_page_free_wanted);
					}

					if (wait_result == THREAD_WAITING) {
						thread_block(THREAD_CONTINUE_NULL);
					}
				} else {
					lck_mtx_unlock(&vm_page_queue_free_lock);
				}
			}
#endif
		}
		if (local_freeq) {
			OSAddAtomic64(local_freed, &vm_pageout_vminfo.vm_pageout_compressions);

			vm_page_free_list(local_freeq, TRUE);
			local_freeq = NULL;
			local_freed = 0;
		}
		if (pgo_draining == TRUE) {
			vm_page_lockspin_queues();
			vm_pageout_throttle_up_batch(q, local_cnt);
			vm_page_unlock_queues();
		}
	}
	KERNEL_DEBUG(0xe040000c | DBG_FUNC_START, 0, 0, 0, 0, 0);

	/*
	 * queue lock is held and our q is empty
	 */
	q->pgo_busy = FALSE;
	q->pgo_idle = TRUE;

	assert_wait((event_t) ((uintptr_t)&q->pgo_pending + cq->id), THREAD_UNINT);
#if DEVELOPMENT || DEBUG
	if (marked_active == TRUE) {
		vmct_active--;
		vmct_state[cq->id] = VMCT_IDLE;

		if (vmct_active == 0) {
			vm_compressor_epoch_stop = mach_absolute_time();
			assertf(vm_compressor_epoch_stop >= vm_compressor_epoch_start,
			    "Compressor epoch non-monotonic: 0x%llx -> 0x%llx",
			    vm_compressor_epoch_start, vm_compressor_epoch_stop);
			/* This interval includes intervals where one or more
			 * compressor threads were pre-empted
			 */
			vmct_stats.vmct_cthreads_total += vm_compressor_epoch_stop - vm_compressor_epoch_start;
		}
	}
#endif
	vm_page_unlock_queues();
#if DEVELOPMENT || DEBUG
	if (__improbable(vm_compressor_time_thread)) {
		vmct_stats.vmct_runtimes[cq->id] = thread_get_runtime_self();
		vmct_stats.vmct_pages[cq->id] += ncomps;
		vmct_stats.vmct_iterations[cq->id]++;
		if (ncomps > vmct_stats.vmct_maxpages[cq->id]) {
			vmct_stats.vmct_maxpages[cq->id] = ncomps;
		}
		if (ncomps < vmct_stats.vmct_minpages[cq->id]) {
			vmct_stats.vmct_minpages[cq->id] = ncomps;
		}
	}
#endif

	KERNEL_DEBUG(0xe0400018 | DBG_FUNC_END, 0, 0, 0, 0, 0);

	thread_block_parameter((thread_continue_t)vm_pageout_iothread_internal_continue, (void *) cq);
	/*NOTREACHED*/
}


kern_return_t
vm_pageout_compress_page(void **current_chead, char *scratch_buf, vm_page_t m)
{
	vm_object_t     object;
	memory_object_t pager;
	int             compressed_count_delta;
	kern_return_t   retval;

	object = VM_PAGE_OBJECT(m);

	assert(!m->vmp_free_when_done);
	assert(!m->vmp_laundry);

	pager = object->pager;

	if (!object->pager_initialized || pager == MEMORY_OBJECT_NULL) {
		KERNEL_DEBUG(0xe0400010 | DBG_FUNC_START, object, pager, 0, 0, 0);

		vm_object_lock(object);

		/*
		 * If there is no memory object for the page, create
		 * one and hand it to the compression pager.
		 */

		if (!object->pager_initialized) {
			vm_object_collapse(object, (vm_object_offset_t) 0, TRUE);
		}
		if (!object->pager_initialized) {
			vm_object_compressor_pager_create(object);
		}

		pager = object->pager;

		if (!object->pager_initialized || pager == MEMORY_OBJECT_NULL) {
			/*
			 * Still no pager for the object,
			 * or the pager has been destroyed.
			 * Reactivate the page.
			 *
			 * Should only happen if there is no
			 * compression pager
			 */
			PAGE_WAKEUP_DONE(m);

			vm_page_lockspin_queues();
			vm_page_activate(m);
			VM_PAGEOUT_DEBUG(vm_pageout_dirty_no_pager, 1);
			vm_page_unlock_queues();

			/*
			 *	And we are done with it.
			 */
			vm_object_activity_end(object);
			vm_object_unlock(object);

			return KERN_FAILURE;
		}
		vm_object_unlock(object);

		KERNEL_DEBUG(0xe0400010 | DBG_FUNC_END, object, pager, 0, 0, 0);
	}
	assert(object->pager_initialized && pager != MEMORY_OBJECT_NULL);
	assert(object->activity_in_progress > 0);

	retval = vm_compressor_pager_put(
		pager,
		m->vmp_offset + object->paging_offset,
		VM_PAGE_GET_PHYS_PAGE(m),
		current_chead,
		scratch_buf,
		&compressed_count_delta);

	vm_object_lock(object);

	assert(object->activity_in_progress > 0);
	assert(VM_PAGE_OBJECT(m) == object);
	assert( !VM_PAGE_WIRED(m));

	vm_compressor_pager_count(pager,
	    compressed_count_delta,
	    FALSE,                       /* shared_lock */
	    object);

	if (retval == KERN_SUCCESS) {
		/*
		 * If the object is purgeable, its owner's
		 * purgeable ledgers will be updated in
		 * vm_page_remove() but the page still
		 * contributes to the owner's memory footprint,
		 * so account for it as such.
		 */
		if ((object->purgable != VM_PURGABLE_DENY ||
		    object->vo_ledger_tag) &&
		    object->vo_owner != NULL) {
			/* one more compressed purgeable/tagged page */
			vm_object_owner_compressed_update(object,
			    +1);
		}
		VM_STAT_INCR(compressions);

		if (m->vmp_tabled) {
			vm_page_remove(m, TRUE);
		}
	} else {
		PAGE_WAKEUP_DONE(m);

		vm_page_lockspin_queues();

		vm_page_activate(m);
		vm_pageout_vminfo.vm_compressor_failed++;

		vm_page_unlock_queues();
	}
	vm_object_activity_end(object);
	vm_object_unlock(object);

	return retval;
}


static void
vm_pageout_adjust_eq_iothrottle(struct vm_pageout_queue *eq, boolean_t req_lowpriority)
{
	uint32_t        policy;

	if (hibernate_cleaning_in_progress == TRUE) {
		req_lowpriority = FALSE;
	}

	if (eq->pgo_inited == TRUE && eq->pgo_lowpriority != req_lowpriority) {
		vm_page_unlock_queues();

		if (req_lowpriority == TRUE) {
			policy = THROTTLE_LEVEL_PAGEOUT_THROTTLED;
			DTRACE_VM(laundrythrottle);
		} else {
			policy = THROTTLE_LEVEL_PAGEOUT_UNTHROTTLED;
			DTRACE_VM(laundryunthrottle);
		}
		proc_set_thread_policy_with_tid(kernel_task, eq->pgo_tid,
		    TASK_POLICY_EXTERNAL, TASK_POLICY_IO, policy);

		eq->pgo_lowpriority = req_lowpriority;

		vm_page_lock_queues();
	}
}


static void
vm_pageout_iothread_external(void)
{
	thread_t        self = current_thread();

	self->options |= TH_OPT_VMPRIV;

	DTRACE_VM2(laundrythrottle, int, 1, (uint64_t *), NULL);

	proc_set_thread_policy(self, TASK_POLICY_EXTERNAL,
	    TASK_POLICY_IO, THROTTLE_LEVEL_PAGEOUT_THROTTLED);

	vm_page_lock_queues();

	vm_pageout_queue_external.pgo_tid = self->thread_id;
	vm_pageout_queue_external.pgo_lowpriority = TRUE;
	vm_pageout_queue_external.pgo_inited = TRUE;

	vm_page_unlock_queues();

	vm_pageout_iothread_external_continue(&vm_pageout_queue_external);

	/*NOTREACHED*/
}


static void
vm_pageout_iothread_internal(struct cq *cq)
{
	thread_t        self = current_thread();

	self->options |= TH_OPT_VMPRIV;

	vm_page_lock_queues();

	vm_pageout_queue_internal.pgo_tid = self->thread_id;
	vm_pageout_queue_internal.pgo_lowpriority = TRUE;
	vm_pageout_queue_internal.pgo_inited = TRUE;

	vm_page_unlock_queues();

	if (vm_pageout_state.vm_restricted_to_single_processor == TRUE) {
		thread_vm_bind_group_add();
	}



	thread_set_thread_name(current_thread(), "VM_compressor");
#if DEVELOPMENT || DEBUG
	vmct_stats.vmct_minpages[cq->id] = INT32_MAX;
#endif
	vm_pageout_iothread_internal_continue(cq);

	/*NOTREACHED*/
}

kern_return_t
vm_set_buffer_cleanup_callout(boolean_t (*func)(int))
{
	if (OSCompareAndSwapPtr(NULL, func, (void * volatile *) &consider_buffer_cache_collect)) {
		return KERN_SUCCESS;
	} else {
		return KERN_FAILURE; /* Already set */
	}
}

extern boolean_t        memorystatus_manual_testing_on;
extern unsigned int     memorystatus_level;


#if VM_PRESSURE_EVENTS

boolean_t vm_pressure_events_enabled = FALSE;

void
vm_pressure_response(void)
{
	vm_pressure_level_t     old_level = kVMPressureNormal;
	int                     new_level = -1;
	unsigned int            total_pages;
	uint64_t                available_memory = 0;

	if (vm_pressure_events_enabled == FALSE) {
		return;
	}

#if CONFIG_EMBEDDED

	available_memory = (uint64_t) memorystatus_available_pages;

#else /* CONFIG_EMBEDDED */

	available_memory = (uint64_t) AVAILABLE_NON_COMPRESSED_MEMORY;
	memorystatus_available_pages = (uint64_t) AVAILABLE_NON_COMPRESSED_MEMORY;

#endif /* CONFIG_EMBEDDED */

	total_pages = (unsigned int) atop_64(max_mem);
#if CONFIG_SECLUDED_MEMORY
	total_pages -= vm_page_secluded_count;
#endif /* CONFIG_SECLUDED_MEMORY */
	memorystatus_level = (unsigned int) ((available_memory * 100) / total_pages);

	if (memorystatus_manual_testing_on) {
		return;
	}

	old_level = memorystatus_vm_pressure_level;

	switch (memorystatus_vm_pressure_level) {
	case kVMPressureNormal:
	{
		if (VM_PRESSURE_WARNING_TO_CRITICAL()) {
			new_level = kVMPressureCritical;
		} else if (VM_PRESSURE_NORMAL_TO_WARNING()) {
			new_level = kVMPressureWarning;
		}
		break;
	}

	case kVMPressureWarning:
	case kVMPressureUrgent:
	{
		if (VM_PRESSURE_WARNING_TO_NORMAL()) {
			new_level = kVMPressureNormal;
		} else if (VM_PRESSURE_WARNING_TO_CRITICAL()) {
			new_level = kVMPressureCritical;
		}
		break;
	}

	case kVMPressureCritical:
	{
		if (VM_PRESSURE_WARNING_TO_NORMAL()) {
			new_level = kVMPressureNormal;
		} else if (VM_PRESSURE_CRITICAL_TO_WARNING()) {
			new_level = kVMPressureWarning;
		}
		break;
	}

	default:
		return;
	}

	if (new_level != -1) {
		memorystatus_vm_pressure_level = (vm_pressure_level_t) new_level;

		if (new_level != (int) old_level) {
			VM_DEBUG_CONSTANT_EVENT(vm_pressure_level_change, VM_PRESSURE_LEVEL_CHANGE, DBG_FUNC_NONE,
			    new_level, old_level, 0, 0);
		}

		if ((memorystatus_vm_pressure_level != kVMPressureNormal) || (old_level != memorystatus_vm_pressure_level)) {
			if (vm_pageout_state.vm_pressure_thread_running == FALSE) {
				thread_wakeup(&vm_pressure_thread);
			}

			if (old_level != memorystatus_vm_pressure_level) {
				thread_wakeup(&vm_pageout_state.vm_pressure_changed);
			}
		}
	}
}
#endif /* VM_PRESSURE_EVENTS */

/*
 * Function called by a kernel thread to either get the current pressure level or
 * wait until memory pressure changes from a given level.
 */
kern_return_t
mach_vm_pressure_level_monitor(__unused boolean_t wait_for_pressure, __unused unsigned int *pressure_level)
{
#if !VM_PRESSURE_EVENTS

	return KERN_FAILURE;

#else /* VM_PRESSURE_EVENTS */

	wait_result_t       wr = 0;
	vm_pressure_level_t old_level = memorystatus_vm_pressure_level;

	if (pressure_level == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (*pressure_level == kVMPressureJetsam) {
		if (!wait_for_pressure) {
			return KERN_INVALID_ARGUMENT;
		}

		lck_mtx_lock(&memorystatus_jetsam_fg_band_lock);
		wr = assert_wait((event_t)&memorystatus_jetsam_fg_band_waiters,
		    THREAD_INTERRUPTIBLE);
		if (wr == THREAD_WAITING) {
			++memorystatus_jetsam_fg_band_waiters;
			lck_mtx_unlock(&memorystatus_jetsam_fg_band_lock);
			wr = thread_block(THREAD_CONTINUE_NULL);
		} else {
			lck_mtx_unlock(&memorystatus_jetsam_fg_band_lock);
		}
		if (wr != THREAD_AWAKENED) {
			return KERN_ABORTED;
		}
		*pressure_level = kVMPressureJetsam;
		return KERN_SUCCESS;
	}

	if (wait_for_pressure == TRUE) {
		while (old_level == *pressure_level) {
			wr = assert_wait((event_t) &vm_pageout_state.vm_pressure_changed,
			    THREAD_INTERRUPTIBLE);
			if (wr == THREAD_WAITING) {
				wr = thread_block(THREAD_CONTINUE_NULL);
			}
			if (wr == THREAD_INTERRUPTED) {
				return KERN_ABORTED;
			}

			if (wr == THREAD_AWAKENED) {
				old_level = memorystatus_vm_pressure_level;
			}
		}
	}

	*pressure_level = old_level;
	return KERN_SUCCESS;
#endif /* VM_PRESSURE_EVENTS */
}

#if VM_PRESSURE_EVENTS
void
vm_pressure_thread(void)
{
	static boolean_t thread_initialized = FALSE;

	if (thread_initialized == TRUE) {
		vm_pageout_state.vm_pressure_thread_running = TRUE;
		consider_vm_pressure_events();
		vm_pageout_state.vm_pressure_thread_running = FALSE;
	}

	thread_set_thread_name(current_thread(), "VM_pressure");
	thread_initialized = TRUE;
	assert_wait((event_t) &vm_pressure_thread, THREAD_UNINT);
	thread_block((thread_continue_t)vm_pressure_thread);
}
#endif /* VM_PRESSURE_EVENTS */


/*
 * called once per-second via "compute_averages"
 */
void
compute_pageout_gc_throttle(__unused void *arg)
{
	if (vm_pageout_vminfo.vm_pageout_considered_page != vm_pageout_state.vm_pageout_considered_page_last) {
		vm_pageout_state.vm_pageout_considered_page_last = vm_pageout_vminfo.vm_pageout_considered_page;

		thread_wakeup((event_t) &vm_pageout_garbage_collect);
	}
}

/*
 * vm_pageout_garbage_collect can also be called when the zone allocator needs
 * to call zone_gc on a different thread in order to trigger zone-map-exhaustion
 * jetsams. We need to check if the zone map size is above its jetsam limit to
 * decide if this was indeed the case.
 *
 * We need to do this on a different thread because of the following reasons:
 *
 * 1. In the case of synchronous jetsams, the leaking process can try to jetsam
 * itself causing the system to hang. We perform synchronous jetsams if we're
 * leaking in the VM map entries zone, so the leaking process could be doing a
 * zalloc for a VM map entry while holding its vm_map lock, when it decides to
 * jetsam itself. We also need the vm_map lock on the process termination path,
 * which would now lead the dying process to deadlock against itself.
 *
 * 2. The jetsam path might need to allocate zone memory itself. We could try
 * using the non-blocking variant of zalloc for this path, but we can still
 * end up trying to do a kernel_memory_allocate when the zone_map is almost
 * full.
 */

extern boolean_t is_zone_map_nearing_exhaustion(void);

void
vm_pageout_garbage_collect(int collect)
{
	if (collect) {
		if (is_zone_map_nearing_exhaustion()) {
			/*
			 * Woken up by the zone allocator for zone-map-exhaustion jetsams.
			 *
			 * Bail out after calling zone_gc (which triggers the
			 * zone-map-exhaustion jetsams). If we fall through, the subsequent
			 * operations that clear out a bunch of caches might allocate zone
			 * memory themselves (for eg. vm_map operations would need VM map
			 * entries). Since the zone map is almost full at this point, we
			 * could end up with a panic. We just need to quickly jetsam a
			 * process and exit here.
			 *
			 * It could so happen that we were woken up to relieve memory
			 * pressure and the zone map also happened to be near its limit at
			 * the time, in which case we'll skip out early. But that should be
			 * ok; if memory pressure persists, the thread will simply be woken
			 * up again.
			 */
			consider_zone_gc(TRUE);
		} else {
			/* Woken up by vm_pageout_scan or compute_pageout_gc_throttle. */
			boolean_t buf_large_zfree = FALSE;
			boolean_t first_try = TRUE;

			stack_collect();

			consider_machine_collect();
			mbuf_drain(FALSE);

			do {
				if (consider_buffer_cache_collect != NULL) {
					buf_large_zfree = (*consider_buffer_cache_collect)(0);
				}
				if (first_try == TRUE || buf_large_zfree == TRUE) {
					/*
					 * consider_zone_gc should be last, because the other operations
					 * might return memory to zones.
					 */
					consider_zone_gc(FALSE);
				}
				first_try = FALSE;
			} while (buf_large_zfree == TRUE && vm_page_free_count < vm_page_free_target);

			consider_machine_adjust();
		}
	}

	assert_wait((event_t) &vm_pageout_garbage_collect, THREAD_UNINT);

	thread_block_parameter((thread_continue_t) vm_pageout_garbage_collect, (void *)1);
	/*NOTREACHED*/
}


#if VM_PAGE_BUCKETS_CHECK
#if VM_PAGE_FAKE_BUCKETS
extern vm_map_offset_t vm_page_fake_buckets_start, vm_page_fake_buckets_end;
#endif /* VM_PAGE_FAKE_BUCKETS */
#endif /* VM_PAGE_BUCKETS_CHECK */



void
vm_set_restrictions()
{
	int vm_restricted_to_single_processor = 0;

	if (PE_parse_boot_argn("vm_restricted_to_single_processor", &vm_restricted_to_single_processor, sizeof(vm_restricted_to_single_processor))) {
		kprintf("Overriding vm_restricted_to_single_processor to %d\n", vm_restricted_to_single_processor);
		vm_pageout_state.vm_restricted_to_single_processor = (vm_restricted_to_single_processor ? TRUE : FALSE);
	} else {
		host_basic_info_data_t hinfo;
		mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;

#define BSD_HOST 1
		host_info((host_t)BSD_HOST, HOST_BASIC_INFO, (host_info_t)&hinfo, &count);

		assert(hinfo.max_cpus > 0);

		if (hinfo.max_cpus <= 3) {
			/*
			 * on systems with a limited number of CPUS, bind the
			 * 4 major threads that can free memory and that tend to use
			 * a fair bit of CPU under pressured conditions to a single processor.
			 * This insures that these threads don't hog all of the available CPUs
			 * (important for camera launch), while allowing them to run independently
			 * w/r to locks... the 4 threads are
			 * vm_pageout_scan,  vm_pageout_iothread_internal (compressor),
			 * vm_compressor_swap_trigger_thread (minor and major compactions),
			 * memorystatus_thread (jetsams).
			 *
			 * the first time the thread is run, it is responsible for checking the
			 * state of vm_restricted_to_single_processor, and if TRUE it calls
			 * thread_bind_master...  someday this should be replaced with a group
			 * scheduling mechanism and KPI.
			 */
			vm_pageout_state.vm_restricted_to_single_processor = TRUE;
		} else {
			vm_pageout_state.vm_restricted_to_single_processor = FALSE;
		}
	}
}

void
vm_pageout(void)
{
	thread_t        self = current_thread();
	thread_t        thread;
	kern_return_t   result;
	spl_t           s;

	/*
	 * Set thread privileges.
	 */
	s = splsched();

	vm_pageout_scan_thread = self;

#if CONFIG_VPS_DYNAMIC_PRIO

	int             vps_dynprio_bootarg = 0;

	if (PE_parse_boot_argn("vps_dynamic_priority_enabled", &vps_dynprio_bootarg, sizeof(vps_dynprio_bootarg))) {
		vps_dynamic_priority_enabled = (vps_dynprio_bootarg ? TRUE : FALSE);
		kprintf("Overriding vps_dynamic_priority_enabled to %d\n", vps_dynamic_priority_enabled);
	} else {
		if (vm_pageout_state.vm_restricted_to_single_processor == TRUE) {
			vps_dynamic_priority_enabled = TRUE;
		} else {
			vps_dynamic_priority_enabled = FALSE;
		}
	}

	if (vps_dynamic_priority_enabled) {
		sched_set_kernel_thread_priority(self, MAXPRI_THROTTLE);
		thread_set_eager_preempt(self);
	} else {
		sched_set_kernel_thread_priority(self, BASEPRI_VM);
	}

#else /* CONFIG_VPS_DYNAMIC_PRIO */

	vps_dynamic_priority_enabled = FALSE;
	sched_set_kernel_thread_priority(self, BASEPRI_VM);

#endif /* CONFIG_VPS_DYNAMIC_PRIO */

	thread_lock(self);
	self->options |= TH_OPT_VMPRIV;
	thread_unlock(self);

	if (!self->reserved_stack) {
		self->reserved_stack = self->kernel_stack;
	}

	if (vm_pageout_state.vm_restricted_to_single_processor == TRUE &&
	    vps_dynamic_priority_enabled == FALSE) {
		thread_vm_bind_group_add();
	}




	splx(s);

	thread_set_thread_name(current_thread(), "VM_pageout_scan");

	/*
	 *	Initialize some paging parameters.
	 */

	vm_pageout_state.vm_pressure_thread_running = FALSE;
	vm_pageout_state.vm_pressure_changed = FALSE;
	vm_pageout_state.memorystatus_purge_on_warning = 2;
	vm_pageout_state.memorystatus_purge_on_urgent = 5;
	vm_pageout_state.memorystatus_purge_on_critical = 8;
	vm_pageout_state.vm_page_speculative_q_age_ms = VM_PAGE_SPECULATIVE_Q_AGE_MS;
	vm_pageout_state.vm_page_speculative_percentage = 5;
	vm_pageout_state.vm_page_speculative_target = 0;

	vm_pageout_state.vm_pageout_external_iothread = THREAD_NULL;
	vm_pageout_state.vm_pageout_internal_iothread = THREAD_NULL;

	vm_pageout_state.vm_pageout_swap_wait = 0;
	vm_pageout_state.vm_pageout_idle_wait = 0;
	vm_pageout_state.vm_pageout_empty_wait = 0;
	vm_pageout_state.vm_pageout_burst_wait = 0;
	vm_pageout_state.vm_pageout_deadlock_wait = 0;
	vm_pageout_state.vm_pageout_deadlock_relief = 0;
	vm_pageout_state.vm_pageout_burst_inactive_throttle = 0;

	vm_pageout_state.vm_pageout_inactive = 0;
	vm_pageout_state.vm_pageout_inactive_used = 0;
	vm_pageout_state.vm_pageout_inactive_clean = 0;

	vm_pageout_state.vm_memory_pressure = 0;
	vm_pageout_state.vm_page_filecache_min = 0;
#if CONFIG_JETSAM
	vm_pageout_state.vm_page_filecache_min_divisor = 70;
	vm_pageout_state.vm_page_xpmapped_min_divisor = 40;
#else
	vm_pageout_state.vm_page_filecache_min_divisor = 27;
	vm_pageout_state.vm_page_xpmapped_min_divisor = 36;
#endif
	vm_pageout_state.vm_page_free_count_init = vm_page_free_count;

	vm_pageout_state.vm_pageout_considered_page_last = 0;

	if (vm_pageout_state.vm_pageout_swap_wait == 0) {
		vm_pageout_state.vm_pageout_swap_wait = VM_PAGEOUT_SWAP_WAIT;
	}

	if (vm_pageout_state.vm_pageout_idle_wait == 0) {
		vm_pageout_state.vm_pageout_idle_wait = VM_PAGEOUT_IDLE_WAIT;
	}

	if (vm_pageout_state.vm_pageout_burst_wait == 0) {
		vm_pageout_state.vm_pageout_burst_wait = VM_PAGEOUT_BURST_WAIT;
	}

	if (vm_pageout_state.vm_pageout_empty_wait == 0) {
		vm_pageout_state.vm_pageout_empty_wait = VM_PAGEOUT_EMPTY_WAIT;
	}

	if (vm_pageout_state.vm_pageout_deadlock_wait == 0) {
		vm_pageout_state.vm_pageout_deadlock_wait = VM_PAGEOUT_DEADLOCK_WAIT;
	}

	if (vm_pageout_state.vm_pageout_deadlock_relief == 0) {
		vm_pageout_state.vm_pageout_deadlock_relief = VM_PAGEOUT_DEADLOCK_RELIEF;
	}

	if (vm_pageout_state.vm_pageout_burst_inactive_throttle == 0) {
		vm_pageout_state.vm_pageout_burst_inactive_throttle = VM_PAGEOUT_BURST_INACTIVE_THROTTLE;
	}
	/*
	 * even if we've already called vm_page_free_reserve
	 * call it again here to insure that the targets are
	 * accurately calculated (it uses vm_page_free_count_init)
	 * calling it with an arg of 0 will not change the reserve
	 * but will re-calculate free_min and free_target
	 */
	if (vm_page_free_reserved < VM_PAGE_FREE_RESERVED(processor_count)) {
		vm_page_free_reserve((VM_PAGE_FREE_RESERVED(processor_count)) - vm_page_free_reserved);
	} else {
		vm_page_free_reserve(0);
	}


	vm_page_queue_init(&vm_pageout_queue_external.pgo_pending);
	vm_pageout_queue_external.pgo_maxlaundry = VM_PAGE_LAUNDRY_MAX;
	vm_pageout_queue_external.pgo_laundry = 0;
	vm_pageout_queue_external.pgo_idle = FALSE;
	vm_pageout_queue_external.pgo_busy = FALSE;
	vm_pageout_queue_external.pgo_throttled = FALSE;
	vm_pageout_queue_external.pgo_draining = FALSE;
	vm_pageout_queue_external.pgo_lowpriority = FALSE;
	vm_pageout_queue_external.pgo_tid = -1;
	vm_pageout_queue_external.pgo_inited = FALSE;

	vm_page_queue_init(&vm_pageout_queue_internal.pgo_pending);
	vm_pageout_queue_internal.pgo_maxlaundry = 0;
	vm_pageout_queue_internal.pgo_laundry = 0;
	vm_pageout_queue_internal.pgo_idle = FALSE;
	vm_pageout_queue_internal.pgo_busy = FALSE;
	vm_pageout_queue_internal.pgo_throttled = FALSE;
	vm_pageout_queue_internal.pgo_draining = FALSE;
	vm_pageout_queue_internal.pgo_lowpriority = FALSE;
	vm_pageout_queue_internal.pgo_tid = -1;
	vm_pageout_queue_internal.pgo_inited = FALSE;

	/* internal pageout thread started when default pager registered first time */
	/* external pageout and garbage collection threads started here */

	result = kernel_thread_start_priority((thread_continue_t)vm_pageout_iothread_external, NULL,
	    BASEPRI_VM,
	    &vm_pageout_state.vm_pageout_external_iothread);
	if (result != KERN_SUCCESS) {
		panic("vm_pageout_iothread_external: create failed");
	}
	thread_set_thread_name(vm_pageout_state.vm_pageout_external_iothread, "VM_pageout_external_iothread");
	thread_deallocate(vm_pageout_state.vm_pageout_external_iothread);

	result = kernel_thread_start_priority((thread_continue_t)vm_pageout_garbage_collect, NULL,
	    BASEPRI_DEFAULT,
	    &thread);
	if (result != KERN_SUCCESS) {
		panic("vm_pageout_garbage_collect: create failed");
	}
	thread_set_thread_name(thread, "VM_pageout_garbage_collect");
	thread_deallocate(thread);

#if VM_PRESSURE_EVENTS
	result = kernel_thread_start_priority((thread_continue_t)vm_pressure_thread, NULL,
	    BASEPRI_DEFAULT,
	    &thread);

	if (result != KERN_SUCCESS) {
		panic("vm_pressure_thread: create failed");
	}

	thread_deallocate(thread);
#endif

	vm_object_reaper_init();


	bzero(&vm_config, sizeof(vm_config));

	switch (vm_compressor_mode) {
	case VM_PAGER_DEFAULT:
		printf("mapping deprecated VM_PAGER_DEFAULT to VM_PAGER_COMPRESSOR_WITH_SWAP\n");

	case VM_PAGER_COMPRESSOR_WITH_SWAP:
		vm_config.compressor_is_present = TRUE;
		vm_config.swap_is_present = TRUE;
		vm_config.compressor_is_active = TRUE;
		vm_config.swap_is_active = TRUE;
		break;

	case VM_PAGER_COMPRESSOR_NO_SWAP:
		vm_config.compressor_is_present = TRUE;
		vm_config.swap_is_present = TRUE;
		vm_config.compressor_is_active = TRUE;
		break;

	case VM_PAGER_FREEZER_DEFAULT:
		printf("mapping deprecated VM_PAGER_FREEZER_DEFAULT to VM_PAGER_FREEZER_COMPRESSOR_NO_SWAP\n");

	case VM_PAGER_FREEZER_COMPRESSOR_NO_SWAP:
		vm_config.compressor_is_present = TRUE;
		vm_config.swap_is_present = TRUE;
		break;

	case VM_PAGER_COMPRESSOR_NO_SWAP_PLUS_FREEZER_COMPRESSOR_WITH_SWAP:
		vm_config.compressor_is_present = TRUE;
		vm_config.swap_is_present = TRUE;
		vm_config.compressor_is_active = TRUE;
		vm_config.freezer_swap_is_active = TRUE;
		break;

	case VM_PAGER_NOT_CONFIGURED:
		break;

	default:
		printf("unknown compressor mode - %x\n", vm_compressor_mode);
		break;
	}
	if (VM_CONFIG_COMPRESSOR_IS_PRESENT) {
		vm_compressor_pager_init();
	}

#if VM_PRESSURE_EVENTS
	vm_pressure_events_enabled = TRUE;
#endif /* VM_PRESSURE_EVENTS */

#if CONFIG_PHANTOM_CACHE
	vm_phantom_cache_init();
#endif
#if VM_PAGE_BUCKETS_CHECK
#if VM_PAGE_FAKE_BUCKETS
	printf("**** DEBUG: protecting fake buckets [0x%llx:0x%llx]\n",
	    (uint64_t) vm_page_fake_buckets_start,
	    (uint64_t) vm_page_fake_buckets_end);
	pmap_protect(kernel_pmap,
	    vm_page_fake_buckets_start,
	    vm_page_fake_buckets_end,
	    VM_PROT_READ);
//	*(char *) vm_page_fake_buckets_start = 'x';	/* panic! */
#endif /* VM_PAGE_FAKE_BUCKETS */
#endif /* VM_PAGE_BUCKETS_CHECK */

#if VM_OBJECT_TRACKING
	vm_object_tracking_init();
#endif /* VM_OBJECT_TRACKING */

	vm_tests();

	vm_pageout_continue();

	/*
	 * Unreached code!
	 *
	 * The vm_pageout_continue() call above never returns, so the code below is never
	 * executed.  We take advantage of this to declare several DTrace VM related probe
	 * points that our kernel doesn't have an analog for.  These are probe points that
	 * exist in Solaris and are in the DTrace documentation, so people may have written
	 * scripts that use them.  Declaring the probe points here means their scripts will
	 * compile and execute which we want for portability of the scripts, but since this
	 * section of code is never reached, the probe points will simply never fire.  Yes,
	 * this is basically a hack.  The problem is the DTrace probe points were chosen with
	 * Solaris specific VM events in mind, not portability to different VM implementations.
	 */

	DTRACE_VM2(execfree, int, 1, (uint64_t *), NULL);
	DTRACE_VM2(execpgin, int, 1, (uint64_t *), NULL);
	DTRACE_VM2(execpgout, int, 1, (uint64_t *), NULL);
	DTRACE_VM2(pgswapin, int, 1, (uint64_t *), NULL);
	DTRACE_VM2(pgswapout, int, 1, (uint64_t *), NULL);
	DTRACE_VM2(swapin, int, 1, (uint64_t *), NULL);
	DTRACE_VM2(swapout, int, 1, (uint64_t *), NULL);
	/*NOTREACHED*/
}



kern_return_t
vm_pageout_internal_start(void)
{
	kern_return_t   result;
	int             i;
	host_basic_info_data_t hinfo;

	assert(VM_CONFIG_COMPRESSOR_IS_PRESENT);

	mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;
#define BSD_HOST 1
	host_info((host_t)BSD_HOST, HOST_BASIC_INFO, (host_info_t)&hinfo, &count);

	assert(hinfo.max_cpus > 0);

	lck_grp_init(&vm_pageout_lck_grp, "vm_pageout", LCK_GRP_ATTR_NULL);

#if CONFIG_EMBEDDED
	vm_pageout_state.vm_compressor_thread_count = 1;
#else
	if (hinfo.max_cpus > 4) {
		vm_pageout_state.vm_compressor_thread_count = 2;
	} else {
		vm_pageout_state.vm_compressor_thread_count = 1;
	}
#endif
	PE_parse_boot_argn("vmcomp_threads", &vm_pageout_state.vm_compressor_thread_count,
	    sizeof(vm_pageout_state.vm_compressor_thread_count));

	if (vm_pageout_state.vm_compressor_thread_count >= hinfo.max_cpus) {
		vm_pageout_state.vm_compressor_thread_count = hinfo.max_cpus - 1;
	}
	if (vm_pageout_state.vm_compressor_thread_count <= 0) {
		vm_pageout_state.vm_compressor_thread_count = 1;
	} else if (vm_pageout_state.vm_compressor_thread_count > MAX_COMPRESSOR_THREAD_COUNT) {
		vm_pageout_state.vm_compressor_thread_count = MAX_COMPRESSOR_THREAD_COUNT;
	}

	vm_pageout_queue_internal.pgo_maxlaundry = (vm_pageout_state.vm_compressor_thread_count * 4) * VM_PAGE_LAUNDRY_MAX;

	PE_parse_boot_argn("vmpgoi_maxlaundry", &vm_pageout_queue_internal.pgo_maxlaundry, sizeof(vm_pageout_queue_internal.pgo_maxlaundry));

	for (i = 0; i < vm_pageout_state.vm_compressor_thread_count; i++) {
		ciq[i].id = i;
		ciq[i].q = &vm_pageout_queue_internal;
		ciq[i].current_chead = NULL;
		ciq[i].scratch_buf = kalloc(COMPRESSOR_SCRATCH_BUF_SIZE);

		result = kernel_thread_start_priority((thread_continue_t)vm_pageout_iothread_internal, (void *)&ciq[i],
		    BASEPRI_VM, &vm_pageout_state.vm_pageout_internal_iothread);

		if (result == KERN_SUCCESS) {
			thread_deallocate(vm_pageout_state.vm_pageout_internal_iothread);
		} else {
			break;
		}
	}
	return result;
}

#if CONFIG_IOSCHED
/*
 * To support I/O Expedite for compressed files we mark the upls with special flags.
 * The way decmpfs works is that we create a big upl which marks all the pages needed to
 * represent the compressed file as busy. We tag this upl with the flag UPL_DECMP_REQ. Decmpfs
 * then issues smaller I/Os for compressed I/Os, deflates them and puts the data into the pages
 * being held in the big original UPL. We mark each of these smaller UPLs with the flag
 * UPL_DECMP_REAL_IO. Any outstanding real I/O UPL is tracked by the big req upl using the
 * decmp_io_upl field (in the upl structure). This link is protected in the forward direction
 * by the req upl lock (the reverse link doesnt need synch. since we never inspect this link
 * unless the real I/O upl is being destroyed).
 */


static void
upl_set_decmp_info(upl_t upl, upl_t src_upl)
{
	assert((src_upl->flags & UPL_DECMP_REQ) != 0);

	upl_lock(src_upl);
	if (src_upl->decmp_io_upl) {
		/*
		 * If there is already an alive real I/O UPL, ignore this new UPL.
		 * This case should rarely happen and even if it does, it just means
		 * that we might issue a spurious expedite which the driver is expected
		 * to handle.
		 */
		upl_unlock(src_upl);
		return;
	}
	src_upl->decmp_io_upl = (void *)upl;
	src_upl->ref_count++;

	upl->flags |= UPL_DECMP_REAL_IO;
	upl->decmp_io_upl = (void *)src_upl;
	upl_unlock(src_upl);
}
#endif /* CONFIG_IOSCHED */

#if UPL_DEBUG
int     upl_debug_enabled = 1;
#else
int     upl_debug_enabled = 0;
#endif

static upl_t
upl_create(int type, int flags, upl_size_t size)
{
	upl_t   upl;
	vm_size_t       page_field_size = 0;
	int     upl_flags = 0;
	vm_size_t       upl_size  = sizeof(struct upl);

	size = round_page_32(size);

	if (type & UPL_CREATE_LITE) {
		page_field_size = (atop(size) + 7) >> 3;
		page_field_size = (page_field_size + 3) & 0xFFFFFFFC;

		upl_flags |= UPL_LITE;
	}
	if (type & UPL_CREATE_INTERNAL) {
		upl_size += sizeof(struct upl_page_info) * atop(size);

		upl_flags |= UPL_INTERNAL;
	}
	upl = (upl_t)kalloc(upl_size + page_field_size);

	if (page_field_size) {
		bzero((char *)upl + upl_size, page_field_size);
	}

	upl->flags = upl_flags | flags;
	upl->kaddr = (vm_offset_t)0;
	upl->size = 0;
	upl->map_object = NULL;
	upl->ref_count = 1;
	upl->ext_ref_count = 0;
	upl->highest_page = 0;
	upl_lock_init(upl);
	upl->vector_upl = NULL;
	upl->associated_upl = NULL;
	upl->upl_iodone = NULL;
#if CONFIG_IOSCHED
	if (type & UPL_CREATE_IO_TRACKING) {
		upl->upl_priority = proc_get_effective_thread_policy(current_thread(), TASK_POLICY_IO);
	}

	upl->upl_reprio_info = 0;
	upl->decmp_io_upl = 0;
	if ((type & UPL_CREATE_INTERNAL) && (type & UPL_CREATE_EXPEDITE_SUP)) {
		/* Only support expedite on internal UPLs */
		thread_t        curthread = current_thread();
		upl->upl_reprio_info = (uint64_t *)kalloc(sizeof(uint64_t) * atop(size));
		bzero(upl->upl_reprio_info, (sizeof(uint64_t) * atop(size)));
		upl->flags |= UPL_EXPEDITE_SUPPORTED;
		if (curthread->decmp_upl != NULL) {
			upl_set_decmp_info(upl, curthread->decmp_upl);
		}
	}
#endif
#if CONFIG_IOSCHED || UPL_DEBUG
	if ((type & UPL_CREATE_IO_TRACKING) || upl_debug_enabled) {
		upl->upl_creator = current_thread();
		upl->uplq.next = 0;
		upl->uplq.prev = 0;
		upl->flags |= UPL_TRACKED_BY_OBJECT;
	}
#endif

#if UPL_DEBUG
	upl->ubc_alias1 = 0;
	upl->ubc_alias2 = 0;

	upl->upl_state = 0;
	upl->upl_commit_index = 0;
	bzero(&upl->upl_commit_records[0], sizeof(upl->upl_commit_records));

	(void) OSBacktrace(&upl->upl_create_retaddr[0], UPL_DEBUG_STACK_FRAMES);
#endif /* UPL_DEBUG */

	return upl;
}

static void
upl_destroy(upl_t upl)
{
	int     page_field_size;  /* bit field in word size buf */
	int     size;

	if (upl->ext_ref_count) {
		panic("upl(%p) ext_ref_count", upl);
	}

#if CONFIG_IOSCHED
	if ((upl->flags & UPL_DECMP_REAL_IO) && upl->decmp_io_upl) {
		upl_t src_upl;
		src_upl = upl->decmp_io_upl;
		assert((src_upl->flags & UPL_DECMP_REQ) != 0);
		upl_lock(src_upl);
		src_upl->decmp_io_upl = NULL;
		upl_unlock(src_upl);
		upl_deallocate(src_upl);
	}
#endif /* CONFIG_IOSCHED */

#if CONFIG_IOSCHED || UPL_DEBUG
	if ((upl->flags & UPL_TRACKED_BY_OBJECT) && !(upl->flags & UPL_VECTOR)) {
		vm_object_t     object;

		if (upl->flags & UPL_SHADOWED) {
			object = upl->map_object->shadow;
		} else {
			object = upl->map_object;
		}

		vm_object_lock(object);
		queue_remove(&object->uplq, upl, upl_t, uplq);
		vm_object_activity_end(object);
		vm_object_collapse(object, 0, TRUE);
		vm_object_unlock(object);
	}
#endif
	/*
	 * drop a reference on the map_object whether or
	 * not a pageout object is inserted
	 */
	if (upl->flags & UPL_SHADOWED) {
		vm_object_deallocate(upl->map_object);
	}

	if (upl->flags & UPL_DEVICE_MEMORY) {
		size = PAGE_SIZE;
	} else {
		size = upl->size;
	}
	page_field_size = 0;

	if (upl->flags & UPL_LITE) {
		page_field_size = ((size / PAGE_SIZE) + 7) >> 3;
		page_field_size = (page_field_size + 3) & 0xFFFFFFFC;
	}
	upl_lock_destroy(upl);
	upl->vector_upl = (vector_upl_t) 0xfeedbeef;

#if CONFIG_IOSCHED
	if (upl->flags & UPL_EXPEDITE_SUPPORTED) {
		kfree(upl->upl_reprio_info, sizeof(uint64_t) * (size / PAGE_SIZE));
	}
#endif

	if (upl->flags & UPL_INTERNAL) {
		kfree(upl,
		    sizeof(struct upl) +
		    (sizeof(struct upl_page_info) * (size / PAGE_SIZE))
		    + page_field_size);
	} else {
		kfree(upl, sizeof(struct upl) + page_field_size);
	}
}

void
upl_deallocate(upl_t upl)
{
	upl_lock(upl);

	if (--upl->ref_count == 0) {
		if (vector_upl_is_valid(upl)) {
			vector_upl_deallocate(upl);
		}
		upl_unlock(upl);

		if (upl->upl_iodone) {
			upl_callout_iodone(upl);
		}

		upl_destroy(upl);
	} else {
		upl_unlock(upl);
	}
}

#if CONFIG_IOSCHED
void
upl_mark_decmp(upl_t upl)
{
	if (upl->flags & UPL_TRACKED_BY_OBJECT) {
		upl->flags |= UPL_DECMP_REQ;
		upl->upl_creator->decmp_upl = (void *)upl;
	}
}

void
upl_unmark_decmp(upl_t upl)
{
	if (upl && (upl->flags & UPL_DECMP_REQ)) {
		upl->upl_creator->decmp_upl = NULL;
	}
}

#endif /* CONFIG_IOSCHED */

#define VM_PAGE_Q_BACKING_UP(q)         \
	((q)->pgo_laundry >= (((q)->pgo_maxlaundry * 8) / 10))

boolean_t must_throttle_writes(void);

boolean_t
must_throttle_writes()
{
	if (VM_PAGE_Q_BACKING_UP(&vm_pageout_queue_external) &&
	    vm_page_pageable_external_count > (AVAILABLE_NON_COMPRESSED_MEMORY * 6) / 10) {
		return TRUE;
	}

	return FALSE;
}


/*
 *	Routine:	vm_object_upl_request
 *	Purpose:
 *		Cause the population of a portion of a vm_object.
 *		Depending on the nature of the request, the pages
 *		returned may be contain valid data or be uninitialized.
 *		A page list structure, listing the physical pages
 *		will be returned upon request.
 *		This function is called by the file system or any other
 *		supplier of backing store to a pager.
 *		IMPORTANT NOTE: The caller must still respect the relationship
 *		between the vm_object and its backing memory object.  The
 *		caller MUST NOT substitute changes in the backing file
 *		without first doing a memory_object_lock_request on the
 *		target range unless it is know that the pages are not
 *		shared with another entity at the pager level.
 *		Copy_in_to:
 *			if a page list structure is present
 *			return the mapped physical pages, where a
 *			page is not present, return a non-initialized
 *			one.  If the no_sync bit is turned on, don't
 *			call the pager unlock to synchronize with other
 *			possible copies of the page. Leave pages busy
 *			in the original object, if a page list structure
 *			was specified.  When a commit of the page list
 *			pages is done, the dirty bit will be set for each one.
 *		Copy_out_from:
 *			If a page list structure is present, return
 *			all mapped pages.  Where a page does not exist
 *			map a zero filled one. Leave pages busy in
 *			the original object.  If a page list structure
 *			is not specified, this call is a no-op.
 *
 *		Note:  access of default pager objects has a rather interesting
 *		twist.  The caller of this routine, presumably the file system
 *		page cache handling code, will never actually make a request
 *		against a default pager backed object.  Only the default
 *		pager will make requests on backing store related vm_objects
 *		In this way the default pager can maintain the relationship
 *		between backing store files (abstract memory objects) and
 *		the vm_objects (cache objects), they support.
 *
 */

__private_extern__ kern_return_t
vm_object_upl_request(
	vm_object_t             object,
	vm_object_offset_t      offset,
	upl_size_t              size,
	upl_t                   *upl_ptr,
	upl_page_info_array_t   user_page_list,
	unsigned int            *page_list_count,
	upl_control_flags_t     cntrl_flags,
	vm_tag_t                tag)
{
	vm_page_t               dst_page = VM_PAGE_NULL;
	vm_object_offset_t      dst_offset;
	upl_size_t              xfer_size;
	unsigned int            size_in_pages;
	boolean_t               dirty;
	boolean_t               hw_dirty;
	upl_t                   upl = NULL;
	unsigned int            entry;
	vm_page_t               alias_page = NULL;
	int                     refmod_state = 0;
	wpl_array_t             lite_list = NULL;
	vm_object_t             last_copy_object;
	struct  vm_page_delayed_work    dw_array[DEFAULT_DELAYED_WORK_LIMIT];
	struct  vm_page_delayed_work    *dwp;
	int                     dw_count;
	int                     dw_limit;
	int                     io_tracking_flag = 0;
	int                     grab_options;
	int                     page_grab_count = 0;
	ppnum_t                 phys_page;
	pmap_flush_context      pmap_flush_context_storage;
	boolean_t               pmap_flushes_delayed = FALSE;
#if DEVELOPMENT || DEBUG
	task_t                  task = current_task();
#endif /* DEVELOPMENT || DEBUG */

	if (cntrl_flags & ~UPL_VALID_FLAGS) {
		/*
		 * For forward compatibility's sake,
		 * reject any unknown flag.
		 */
		return KERN_INVALID_VALUE;
	}
	if ((!object->internal) && (object->paging_offset != 0)) {
		panic("vm_object_upl_request: external object with non-zero paging offset\n");
	}
	if (object->phys_contiguous) {
		panic("vm_object_upl_request: contiguous object specified\n");
	}

	VM_DEBUG_CONSTANT_EVENT(vm_object_upl_request, VM_UPL_REQUEST, DBG_FUNC_START, size, cntrl_flags, 0, 0);

	if (size > MAX_UPL_SIZE_BYTES) {
		size = MAX_UPL_SIZE_BYTES;
	}

	if ((cntrl_flags & UPL_SET_INTERNAL) && page_list_count != NULL) {
		*page_list_count = MAX_UPL_SIZE_BYTES >> PAGE_SHIFT;
	}

#if CONFIG_IOSCHED || UPL_DEBUG
	if (object->io_tracking || upl_debug_enabled) {
		io_tracking_flag |= UPL_CREATE_IO_TRACKING;
	}
#endif
#if CONFIG_IOSCHED
	if (object->io_tracking) {
		io_tracking_flag |= UPL_CREATE_EXPEDITE_SUP;
	}
#endif

	if (cntrl_flags & UPL_SET_INTERNAL) {
		if (cntrl_flags & UPL_SET_LITE) {
			upl = upl_create(UPL_CREATE_INTERNAL | UPL_CREATE_LITE | io_tracking_flag, 0, size);

			user_page_list = (upl_page_info_t *) (((uintptr_t)upl) + sizeof(struct upl));
			lite_list = (wpl_array_t)
			    (((uintptr_t)user_page_list) +
			    ((size / PAGE_SIZE) * sizeof(upl_page_info_t)));
			if (size == 0) {
				user_page_list = NULL;
				lite_list = NULL;
			}
		} else {
			upl = upl_create(UPL_CREATE_INTERNAL | io_tracking_flag, 0, size);

			user_page_list = (upl_page_info_t *) (((uintptr_t)upl) + sizeof(struct upl));
			if (size == 0) {
				user_page_list = NULL;
			}
		}
	} else {
		if (cntrl_flags & UPL_SET_LITE) {
			upl = upl_create(UPL_CREATE_EXTERNAL | UPL_CREATE_LITE | io_tracking_flag, 0, size);

			lite_list = (wpl_array_t) (((uintptr_t)upl) + sizeof(struct upl));
			if (size == 0) {
				lite_list = NULL;
			}
		} else {
			upl = upl_create(UPL_CREATE_EXTERNAL | io_tracking_flag, 0, size);
		}
	}
	*upl_ptr = upl;

	if (user_page_list) {
		user_page_list[0].device = FALSE;
	}

	if (cntrl_flags & UPL_SET_LITE) {
		upl->map_object = object;
	} else {
		upl->map_object = vm_object_allocate(size);
		/*
		 * No neeed to lock the new object: nobody else knows
		 * about it yet, so it's all ours so far.
		 */
		upl->map_object->shadow = object;
		upl->map_object->pageout = TRUE;
		upl->map_object->can_persist = FALSE;
		upl->map_object->copy_strategy = MEMORY_OBJECT_COPY_NONE;
		upl->map_object->vo_shadow_offset = offset;
		upl->map_object->wimg_bits = object->wimg_bits;

		VM_PAGE_GRAB_FICTITIOUS(alias_page);

		upl->flags |= UPL_SHADOWED;
	}
	if (cntrl_flags & UPL_FOR_PAGEOUT) {
		upl->flags |= UPL_PAGEOUT;
	}

	vm_object_lock(object);
	vm_object_activity_begin(object);

	grab_options = 0;
#if CONFIG_SECLUDED_MEMORY
	if (object->can_grab_secluded) {
		grab_options |= VM_PAGE_GRAB_SECLUDED;
	}
#endif /* CONFIG_SECLUDED_MEMORY */

	/*
	 * we can lock in the paging_offset once paging_in_progress is set
	 */
	upl->size = size;
	upl->offset = offset + object->paging_offset;

#if CONFIG_IOSCHED || UPL_DEBUG
	if (object->io_tracking || upl_debug_enabled) {
		vm_object_activity_begin(object);
		queue_enter(&object->uplq, upl, upl_t, uplq);
	}
#endif
	if ((cntrl_flags & UPL_WILL_MODIFY) && object->copy != VM_OBJECT_NULL) {
		/*
		 * Honor copy-on-write obligations
		 *
		 * The caller is gathering these pages and
		 * might modify their contents.  We need to
		 * make sure that the copy object has its own
		 * private copies of these pages before we let
		 * the caller modify them.
		 */
		vm_object_update(object,
		    offset,
		    size,
		    NULL,
		    NULL,
		    FALSE,              /* should_return */
		    MEMORY_OBJECT_COPY_SYNC,
		    VM_PROT_NO_CHANGE);

		VM_PAGEOUT_DEBUG(upl_cow, 1);
		VM_PAGEOUT_DEBUG(upl_cow_pages, (size >> PAGE_SHIFT));
	}
	/*
	 * remember which copy object we synchronized with
	 */
	last_copy_object = object->copy;
	entry = 0;

	xfer_size = size;
	dst_offset = offset;
	size_in_pages = size / PAGE_SIZE;

	dwp = &dw_array[0];
	dw_count = 0;
	dw_limit = DELAYED_WORK_LIMIT(DEFAULT_DELAYED_WORK_LIMIT);

	if (vm_page_free_count > (vm_page_free_target + size_in_pages) ||
	    object->resident_page_count < ((MAX_UPL_SIZE_BYTES * 2) >> PAGE_SHIFT)) {
		object->scan_collisions = 0;
	}

	if ((cntrl_flags & UPL_WILL_MODIFY) && must_throttle_writes() == TRUE) {
		boolean_t       isSSD = FALSE;

#if CONFIG_EMBEDDED
		isSSD = TRUE;
#else
		vnode_pager_get_isSSD(object->pager, &isSSD);
#endif
		vm_object_unlock(object);

		OSAddAtomic(size_in_pages, &vm_upl_wait_for_pages);

		if (isSSD == TRUE) {
			delay(1000 * size_in_pages);
		} else {
			delay(5000 * size_in_pages);
		}
		OSAddAtomic(-size_in_pages, &vm_upl_wait_for_pages);

		vm_object_lock(object);
	}

	while (xfer_size) {
		dwp->dw_mask = 0;

		if ((alias_page == NULL) && !(cntrl_flags & UPL_SET_LITE)) {
			vm_object_unlock(object);
			VM_PAGE_GRAB_FICTITIOUS(alias_page);
			vm_object_lock(object);
		}
		if (cntrl_flags & UPL_COPYOUT_FROM) {
			upl->flags |= UPL_PAGE_SYNC_DONE;

			if (((dst_page = vm_page_lookup(object, dst_offset)) == VM_PAGE_NULL) ||
			    dst_page->vmp_fictitious ||
			    dst_page->vmp_absent ||
			    dst_page->vmp_error ||
			    dst_page->vmp_cleaning ||
			    (VM_PAGE_WIRED(dst_page))) {
				if (user_page_list) {
					user_page_list[entry].phys_addr = 0;
				}

				goto try_next_page;
			}
			phys_page = VM_PAGE_GET_PHYS_PAGE(dst_page);

			/*
			 * grab this up front...
			 * a high percentange of the time we're going to
			 * need the hardware modification state a bit later
			 * anyway... so we can eliminate an extra call into
			 * the pmap layer by grabbing it here and recording it
			 */
			if (dst_page->vmp_pmapped) {
				refmod_state = pmap_get_refmod(phys_page);
			} else {
				refmod_state = 0;
			}

			if ((refmod_state & VM_MEM_REFERENCED) && VM_PAGE_INACTIVE(dst_page)) {
				/*
				 * page is on inactive list and referenced...
				 * reactivate it now... this gets it out of the
				 * way of vm_pageout_scan which would have to
				 * reactivate it upon tripping over it
				 */
				dwp->dw_mask |= DW_vm_page_activate;
			}
			if (cntrl_flags & UPL_RET_ONLY_DIRTY) {
				/*
				 * we're only asking for DIRTY pages to be returned
				 */
				if (dst_page->vmp_laundry || !(cntrl_flags & UPL_FOR_PAGEOUT)) {
					/*
					 * if we were the page stolen by vm_pageout_scan to be
					 * cleaned (as opposed to a buddy being clustered in
					 * or this request is not being driven by a PAGEOUT cluster
					 * then we only need to check for the page being dirty or
					 * precious to decide whether to return it
					 */
					if (dst_page->vmp_dirty || dst_page->vmp_precious || (refmod_state & VM_MEM_MODIFIED)) {
						goto check_busy;
					}
					goto dont_return;
				}
				/*
				 * this is a request for a PAGEOUT cluster and this page
				 * is merely along for the ride as a 'buddy'... not only
				 * does it have to be dirty to be returned, but it also
				 * can't have been referenced recently...
				 */
				if ((hibernate_cleaning_in_progress == TRUE ||
				    (!((refmod_state & VM_MEM_REFERENCED) || dst_page->vmp_reference) ||
				    (dst_page->vmp_q_state == VM_PAGE_ON_THROTTLED_Q))) &&
				    ((refmod_state & VM_MEM_MODIFIED) || dst_page->vmp_dirty || dst_page->vmp_precious)) {
					goto check_busy;
				}
dont_return:
				/*
				 * if we reach here, we're not to return
				 * the page... go on to the next one
				 */
				if (dst_page->vmp_laundry == TRUE) {
					/*
					 * if we get here, the page is not 'cleaning' (filtered out above).
					 * since it has been referenced, remove it from the laundry
					 * so we don't pay the cost of an I/O to clean a page
					 * we're just going to take back
					 */
					vm_page_lockspin_queues();

					vm_pageout_steal_laundry(dst_page, TRUE);
					vm_page_activate(dst_page);

					vm_page_unlock_queues();
				}
				if (user_page_list) {
					user_page_list[entry].phys_addr = 0;
				}

				goto try_next_page;
			}
check_busy:
			if (dst_page->vmp_busy) {
				if (cntrl_flags & UPL_NOBLOCK) {
					if (user_page_list) {
						user_page_list[entry].phys_addr = 0;
					}
					dwp->dw_mask = 0;

					goto try_next_page;
				}
				/*
				 * someone else is playing with the
				 * page.  We will have to wait.
				 */
				PAGE_SLEEP(object, dst_page, THREAD_UNINT);

				continue;
			}
			if (dst_page->vmp_q_state == VM_PAGE_ON_PAGEOUT_Q) {
				vm_page_lockspin_queues();

				if (dst_page->vmp_q_state == VM_PAGE_ON_PAGEOUT_Q) {
					/*
					 * we've buddied up a page for a clustered pageout
					 * that has already been moved to the pageout
					 * queue by pageout_scan... we need to remove
					 * it from the queue and drop the laundry count
					 * on that queue
					 */
					vm_pageout_throttle_up(dst_page);
				}
				vm_page_unlock_queues();
			}
			hw_dirty = refmod_state & VM_MEM_MODIFIED;
			dirty = hw_dirty ? TRUE : dst_page->vmp_dirty;

			if (phys_page > upl->highest_page) {
				upl->highest_page = phys_page;
			}

			assert(!pmap_is_noencrypt(phys_page));

			if (cntrl_flags & UPL_SET_LITE) {
				unsigned int    pg_num;

				pg_num = (unsigned int) ((dst_offset - offset) / PAGE_SIZE);
				assert(pg_num == (dst_offset - offset) / PAGE_SIZE);
				lite_list[pg_num >> 5] |= 1U << (pg_num & 31);

				if (hw_dirty) {
					if (pmap_flushes_delayed == FALSE) {
						pmap_flush_context_init(&pmap_flush_context_storage);
						pmap_flushes_delayed = TRUE;
					}
					pmap_clear_refmod_options(phys_page,
					    VM_MEM_MODIFIED,
					    PMAP_OPTIONS_NOFLUSH | PMAP_OPTIONS_CLEAR_WRITE,
					    &pmap_flush_context_storage);
				}

				/*
				 * Mark original page as cleaning
				 * in place.
				 */
				dst_page->vmp_cleaning = TRUE;
				dst_page->vmp_precious = FALSE;
			} else {
				/*
				 * use pageclean setup, it is more
				 * convenient even for the pageout
				 * cases here
				 */
				vm_object_lock(upl->map_object);
				vm_pageclean_setup(dst_page, alias_page, upl->map_object, size - xfer_size);
				vm_object_unlock(upl->map_object);

				alias_page->vmp_absent = FALSE;
				alias_page = NULL;
			}
			if (dirty) {
				SET_PAGE_DIRTY(dst_page, FALSE);
			} else {
				dst_page->vmp_dirty = FALSE;
			}

			if (!dirty) {
				dst_page->vmp_precious = TRUE;
			}

			if (!(cntrl_flags & UPL_CLEAN_IN_PLACE)) {
				if (!VM_PAGE_WIRED(dst_page)) {
					dst_page->vmp_free_when_done = TRUE;
				}
			}
		} else {
			if ((cntrl_flags & UPL_WILL_MODIFY) && object->copy != last_copy_object) {
				/*
				 * Honor copy-on-write obligations
				 *
				 * The copy object has changed since we
				 * last synchronized for copy-on-write.
				 * Another copy object might have been
				 * inserted while we released the object's
				 * lock.  Since someone could have seen the
				 * original contents of the remaining pages
				 * through that new object, we have to
				 * synchronize with it again for the remaining
				 * pages only.  The previous pages are "busy"
				 * so they can not be seen through the new
				 * mapping.  The new mapping will see our
				 * upcoming changes for those previous pages,
				 * but that's OK since they couldn't see what
				 * was there before.  It's just a race anyway
				 * and there's no guarantee of consistency or
				 * atomicity.  We just don't want new mappings
				 * to see both the *before* and *after* pages.
				 */
				if (object->copy != VM_OBJECT_NULL) {
					vm_object_update(
						object,
						dst_offset,/* current offset */
						xfer_size, /* remaining size */
						NULL,
						NULL,
						FALSE,     /* should_return */
						MEMORY_OBJECT_COPY_SYNC,
						VM_PROT_NO_CHANGE);

					VM_PAGEOUT_DEBUG(upl_cow_again, 1);
					VM_PAGEOUT_DEBUG(upl_cow_again_pages, (xfer_size >> PAGE_SHIFT));
				}
				/*
				 * remember the copy object we synced with
				 */
				last_copy_object = object->copy;
			}
			dst_page = vm_page_lookup(object, dst_offset);

			if (dst_page != VM_PAGE_NULL) {
				if ((cntrl_flags & UPL_RET_ONLY_ABSENT)) {
					/*
					 * skip over pages already present in the cache
					 */
					if (user_page_list) {
						user_page_list[entry].phys_addr = 0;
					}

					goto try_next_page;
				}
				if (dst_page->vmp_fictitious) {
					panic("need corner case for fictitious page");
				}

				if (dst_page->vmp_busy || dst_page->vmp_cleaning) {
					/*
					 * someone else is playing with the
					 * page.  We will have to wait.
					 */
					PAGE_SLEEP(object, dst_page, THREAD_UNINT);

					continue;
				}
				if (dst_page->vmp_laundry) {
					vm_pageout_steal_laundry(dst_page, FALSE);
				}
			} else {
				if (object->private) {
					/*
					 * This is a nasty wrinkle for users
					 * of upl who encounter device or
					 * private memory however, it is
					 * unavoidable, only a fault can
					 * resolve the actual backing
					 * physical page by asking the
					 * backing device.
					 */
					if (user_page_list) {
						user_page_list[entry].phys_addr = 0;
					}

					goto try_next_page;
				}
				if (object->scan_collisions) {
					/*
					 * the pageout_scan thread is trying to steal
					 * pages from this object, but has run into our
					 * lock... grab 2 pages from the head of the object...
					 * the first is freed on behalf of pageout_scan, the
					 * 2nd is for our own use... we use vm_object_page_grab
					 * in both cases to avoid taking pages from the free
					 * list since we are under memory pressure and our
					 * lock on this object is getting in the way of
					 * relieving it
					 */
					dst_page = vm_object_page_grab(object);

					if (dst_page != VM_PAGE_NULL) {
						vm_page_release(dst_page,
						    FALSE);
					}

					dst_page = vm_object_page_grab(object);
				}
				if (dst_page == VM_PAGE_NULL) {
					/*
					 * need to allocate a page
					 */
					dst_page = vm_page_grab_options(grab_options);
					if (dst_page != VM_PAGE_NULL) {
						page_grab_count++;
					}
				}
				if (dst_page == VM_PAGE_NULL) {
					if ((cntrl_flags & (UPL_RET_ONLY_ABSENT | UPL_NOBLOCK)) == (UPL_RET_ONLY_ABSENT | UPL_NOBLOCK)) {
						/*
						 * we don't want to stall waiting for pages to come onto the free list
						 * while we're already holding absent pages in this UPL
						 * the caller will deal with the empty slots
						 */
						if (user_page_list) {
							user_page_list[entry].phys_addr = 0;
						}

						goto try_next_page;
					}
					/*
					 * no pages available... wait
					 * then try again for the same
					 * offset...
					 */
					vm_object_unlock(object);

					OSAddAtomic(size_in_pages, &vm_upl_wait_for_pages);

					VM_DEBUG_EVENT(vm_upl_page_wait, VM_UPL_PAGE_WAIT, DBG_FUNC_START, vm_upl_wait_for_pages, 0, 0, 0);

					VM_PAGE_WAIT();
					OSAddAtomic(-size_in_pages, &vm_upl_wait_for_pages);

					VM_DEBUG_EVENT(vm_upl_page_wait, VM_UPL_PAGE_WAIT, DBG_FUNC_END, vm_upl_wait_for_pages, 0, 0, 0);

					vm_object_lock(object);

					continue;
				}
				vm_page_insert(dst_page, object, dst_offset);

				dst_page->vmp_absent = TRUE;
				dst_page->vmp_busy = FALSE;

				if (cntrl_flags & UPL_RET_ONLY_ABSENT) {
					/*
					 * if UPL_RET_ONLY_ABSENT was specified,
					 * than we're definitely setting up a
					 * upl for a clustered read/pagein
					 * operation... mark the pages as clustered
					 * so upl_commit_range can put them on the
					 * speculative list
					 */
					dst_page->vmp_clustered = TRUE;

					if (!(cntrl_flags & UPL_FILE_IO)) {
						VM_STAT_INCR(pageins);
					}
				}
			}
			phys_page = VM_PAGE_GET_PHYS_PAGE(dst_page);

			dst_page->vmp_overwriting = TRUE;

			if (dst_page->vmp_pmapped) {
				if (!(cntrl_flags & UPL_FILE_IO)) {
					/*
					 * eliminate all mappings from the
					 * original object and its prodigy
					 */
					refmod_state = pmap_disconnect(phys_page);
				} else {
					refmod_state = pmap_get_refmod(phys_page);
				}
			} else {
				refmod_state = 0;
			}

			hw_dirty = refmod_state & VM_MEM_MODIFIED;
			dirty = hw_dirty ? TRUE : dst_page->vmp_dirty;

			if (cntrl_flags & UPL_SET_LITE) {
				unsigned int    pg_num;

				pg_num = (unsigned int) ((dst_offset - offset) / PAGE_SIZE);
				assert(pg_num == (dst_offset - offset) / PAGE_SIZE);
				lite_list[pg_num >> 5] |= 1U << (pg_num & 31);

				if (hw_dirty) {
					pmap_clear_modify(phys_page);
				}

				/*
				 * Mark original page as cleaning
				 * in place.
				 */
				dst_page->vmp_cleaning = TRUE;
				dst_page->vmp_precious = FALSE;
			} else {
				/*
				 * use pageclean setup, it is more
				 * convenient even for the pageout
				 * cases here
				 */
				vm_object_lock(upl->map_object);
				vm_pageclean_setup(dst_page, alias_page, upl->map_object, size - xfer_size);
				vm_object_unlock(upl->map_object);

				alias_page->vmp_absent = FALSE;
				alias_page = NULL;
			}

			if (cntrl_flags & UPL_REQUEST_SET_DIRTY) {
				upl->flags &= ~UPL_CLEAR_DIRTY;
				upl->flags |= UPL_SET_DIRTY;
				dirty = TRUE;
				/*
				 * Page belonging to a code-signed object is about to
				 * be written. Mark it tainted and disconnect it from
				 * all pmaps so processes have to fault it back in and
				 * deal with the tainted bit.
				 */
				if (object->code_signed && dst_page->vmp_cs_tainted == FALSE) {
					dst_page->vmp_cs_tainted = TRUE;
					vm_page_upl_tainted++;
					if (dst_page->vmp_pmapped) {
						refmod_state = pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(dst_page));
						if (refmod_state & VM_MEM_REFERENCED) {
							dst_page->vmp_reference = TRUE;
						}
					}
				}
			} else if (cntrl_flags & UPL_CLEAN_IN_PLACE) {
				/*
				 * clean in place for read implies
				 * that a write will be done on all
				 * the pages that are dirty before
				 * a upl commit is done.  The caller
				 * is obligated to preserve the
				 * contents of all pages marked dirty
				 */
				upl->flags |= UPL_CLEAR_DIRTY;
			}
			dst_page->vmp_dirty = dirty;

			if (!dirty) {
				dst_page->vmp_precious = TRUE;
			}

			if (!VM_PAGE_WIRED(dst_page)) {
				/*
				 * deny access to the target page while
				 * it is being worked on
				 */
				dst_page->vmp_busy = TRUE;
			} else {
				dwp->dw_mask |= DW_vm_page_wire;
			}

			/*
			 * We might be about to satisfy a fault which has been
			 * requested. So no need for the "restart" bit.
			 */
			dst_page->vmp_restart = FALSE;
			if (!dst_page->vmp_absent && !(cntrl_flags & UPL_WILL_MODIFY)) {
				/*
				 * expect the page to be used
				 */
				dwp->dw_mask |= DW_set_reference;
			}
			if (cntrl_flags & UPL_PRECIOUS) {
				if (object->internal) {
					SET_PAGE_DIRTY(dst_page, FALSE);
					dst_page->vmp_precious = FALSE;
				} else {
					dst_page->vmp_precious = TRUE;
				}
			} else {
				dst_page->vmp_precious = FALSE;
			}
		}
		if (dst_page->vmp_busy) {
			upl->flags |= UPL_HAS_BUSY;
		}

		if (phys_page > upl->highest_page) {
			upl->highest_page = phys_page;
		}
		assert(!pmap_is_noencrypt(phys_page));
		if (user_page_list) {
			user_page_list[entry].phys_addr = phys_page;
			user_page_list[entry].free_when_done    = dst_page->vmp_free_when_done;
			user_page_list[entry].absent    = dst_page->vmp_absent;
			user_page_list[entry].dirty     = dst_page->vmp_dirty;
			user_page_list[entry].precious  = dst_page->vmp_precious;
			user_page_list[entry].device    = FALSE;
			user_page_list[entry].needed    = FALSE;
			if (dst_page->vmp_clustered == TRUE) {
				user_page_list[entry].speculative = (dst_page->vmp_q_state == VM_PAGE_ON_SPECULATIVE_Q) ? TRUE : FALSE;
			} else {
				user_page_list[entry].speculative = FALSE;
			}
			user_page_list[entry].cs_validated = dst_page->vmp_cs_validated;
			user_page_list[entry].cs_tainted = dst_page->vmp_cs_tainted;
			user_page_list[entry].cs_nx = dst_page->vmp_cs_nx;
			user_page_list[entry].mark      = FALSE;
		}
		/*
		 * if UPL_RET_ONLY_ABSENT is set, then
		 * we are working with a fresh page and we've
		 * just set the clustered flag on it to
		 * indicate that it was drug in as part of a
		 * speculative cluster... so leave it alone
		 */
		if (!(cntrl_flags & UPL_RET_ONLY_ABSENT)) {
			/*
			 * someone is explicitly grabbing this page...
			 * update clustered and speculative state
			 *
			 */
			if (dst_page->vmp_clustered) {
				VM_PAGE_CONSUME_CLUSTERED(dst_page);
			}
		}
try_next_page:
		if (dwp->dw_mask) {
			if (dwp->dw_mask & DW_vm_page_activate) {
				VM_STAT_INCR(reactivations);
			}

			VM_PAGE_ADD_DELAYED_WORK(dwp, dst_page, dw_count);

			if (dw_count >= dw_limit) {
				vm_page_do_delayed_work(object, tag, &dw_array[0], dw_count);

				dwp = &dw_array[0];
				dw_count = 0;
			}
		}
		entry++;
		dst_offset += PAGE_SIZE_64;
		xfer_size -= PAGE_SIZE;
	}
	if (dw_count) {
		vm_page_do_delayed_work(object, tag, &dw_array[0], dw_count);
	}

	if (alias_page != NULL) {
		VM_PAGE_FREE(alias_page);
	}
	if (pmap_flushes_delayed == TRUE) {
		pmap_flush(&pmap_flush_context_storage);
	}

	if (page_list_count != NULL) {
		if (upl->flags & UPL_INTERNAL) {
			*page_list_count = 0;
		} else if (*page_list_count > entry) {
			*page_list_count = entry;
		}
	}
#if UPL_DEBUG
	upl->upl_state = 1;
#endif
	vm_object_unlock(object);

	VM_DEBUG_CONSTANT_EVENT(vm_object_upl_request, VM_UPL_REQUEST, DBG_FUNC_END, page_grab_count, 0, 0, 0);
#if DEVELOPMENT || DEBUG
	if (task != NULL) {
		ledger_credit(task->ledger, task_ledgers.pages_grabbed_upl, page_grab_count);
	}
#endif /* DEVELOPMENT || DEBUG */

	return KERN_SUCCESS;
}

/*
 *	Routine:	vm_object_super_upl_request
 *	Purpose:
 *		Cause the population of a portion of a vm_object
 *		in much the same way as memory_object_upl_request.
 *		Depending on the nature of the request, the pages
 *		returned may be contain valid data or be uninitialized.
 *		However, the region may be expanded up to the super
 *		cluster size provided.
 */

__private_extern__ kern_return_t
vm_object_super_upl_request(
	vm_object_t object,
	vm_object_offset_t      offset,
	upl_size_t              size,
	upl_size_t              super_cluster,
	upl_t                   *upl,
	upl_page_info_t         *user_page_list,
	unsigned int            *page_list_count,
	upl_control_flags_t     cntrl_flags,
	vm_tag_t                tag)
{
	if (object->paging_offset > offset || ((cntrl_flags & UPL_VECTOR) == UPL_VECTOR)) {
		return KERN_FAILURE;
	}

	assert(object->paging_in_progress);
	offset = offset - object->paging_offset;

	if (super_cluster > size) {
		vm_object_offset_t      base_offset;
		upl_size_t              super_size;
		vm_object_size_t        super_size_64;

		base_offset = (offset & ~((vm_object_offset_t) super_cluster - 1));
		super_size = (offset + size) > (base_offset + super_cluster) ? super_cluster << 1 : super_cluster;
		super_size_64 = ((base_offset + super_size) > object->vo_size) ? (object->vo_size - base_offset) : super_size;
		super_size = (upl_size_t) super_size_64;
		assert(super_size == super_size_64);

		if (offset > (base_offset + super_size)) {
			panic("vm_object_super_upl_request: Missed target pageout"
			    " %#llx,%#llx, %#x, %#x, %#x, %#llx\n",
			    offset, base_offset, super_size, super_cluster,
			    size, object->paging_offset);
		}
		/*
		 * apparently there is a case where the vm requests a
		 * page to be written out who's offset is beyond the
		 * object size
		 */
		if ((offset + size) > (base_offset + super_size)) {
			super_size_64 = (offset + size) - base_offset;
			super_size = (upl_size_t) super_size_64;
			assert(super_size == super_size_64);
		}

		offset = base_offset;
		size = super_size;
	}
	return vm_object_upl_request(object, offset, size, upl, user_page_list, page_list_count, cntrl_flags, tag);
}

#if CONFIG_EMBEDDED
int cs_executable_create_upl = 0;
extern int proc_selfpid(void);
extern char *proc_name_address(void *p);
#endif /* CONFIG_EMBEDDED */

kern_return_t
vm_map_create_upl(
	vm_map_t                map,
	vm_map_address_t        offset,
	upl_size_t              *upl_size,
	upl_t                   *upl,
	upl_page_info_array_t   page_list,
	unsigned int            *count,
	upl_control_flags_t     *flags,
	vm_tag_t                tag)
{
	vm_map_entry_t          entry;
	upl_control_flags_t     caller_flags;
	int                     force_data_sync;
	int                     sync_cow_data;
	vm_object_t             local_object;
	vm_map_offset_t         local_offset;
	vm_map_offset_t         local_start;
	kern_return_t           ret;

	assert(page_aligned(offset));

	caller_flags = *flags;

	if (caller_flags & ~UPL_VALID_FLAGS) {
		/*
		 * For forward compatibility's sake,
		 * reject any unknown flag.
		 */
		return KERN_INVALID_VALUE;
	}
	force_data_sync = (caller_flags & UPL_FORCE_DATA_SYNC);
	sync_cow_data = !(caller_flags & UPL_COPYOUT_FROM);

	if (upl == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

REDISCOVER_ENTRY:
	vm_map_lock_read(map);

	if (!vm_map_lookup_entry(map, offset, &entry)) {
		vm_map_unlock_read(map);
		return KERN_FAILURE;
	}

	if ((entry->vme_end - offset) < *upl_size) {
		*upl_size = (upl_size_t) (entry->vme_end - offset);
		assert(*upl_size == entry->vme_end - offset);
	}

	if (caller_flags & UPL_QUERY_OBJECT_TYPE) {
		*flags = 0;

		if (!entry->is_sub_map &&
		    VME_OBJECT(entry) != VM_OBJECT_NULL) {
			if (VME_OBJECT(entry)->private) {
				*flags = UPL_DEV_MEMORY;
			}

			if (VME_OBJECT(entry)->phys_contiguous) {
				*flags |= UPL_PHYS_CONTIG;
			}
		}
		vm_map_unlock_read(map);
		return KERN_SUCCESS;
	}

	if (VME_OBJECT(entry) == VM_OBJECT_NULL ||
	    !VME_OBJECT(entry)->phys_contiguous) {
		if (*upl_size > MAX_UPL_SIZE_BYTES) {
			*upl_size = MAX_UPL_SIZE_BYTES;
		}
	}

	/*
	 *      Create an object if necessary.
	 */
	if (VME_OBJECT(entry) == VM_OBJECT_NULL) {
		if (vm_map_lock_read_to_write(map)) {
			goto REDISCOVER_ENTRY;
		}

		VME_OBJECT_SET(entry,
		    vm_object_allocate((vm_size_t)
		    (entry->vme_end -
		    entry->vme_start)));
		VME_OFFSET_SET(entry, 0);
		assert(entry->use_pmap);

		vm_map_lock_write_to_read(map);
	}

	if (!(caller_flags & UPL_COPYOUT_FROM) &&
	    !entry->is_sub_map &&
	    !(entry->protection & VM_PROT_WRITE)) {
		vm_map_unlock_read(map);
		return KERN_PROTECTION_FAILURE;
	}

#if CONFIG_EMBEDDED
	if (map->pmap != kernel_pmap &&
	    (caller_flags & UPL_COPYOUT_FROM) &&
	    (entry->protection & VM_PROT_EXECUTE) &&
	    !(entry->protection & VM_PROT_WRITE)) {
		vm_offset_t     kaddr;
		vm_size_t       ksize;

		/*
		 * We're about to create a read-only UPL backed by
		 * memory from an executable mapping.
		 * Wiring the pages would result in the pages being copied
		 * (due to the "MAP_PRIVATE" mapping) and no longer
		 * code-signed, so no longer eligible for execution.
		 * Instead, let's copy the data into a kernel buffer and
		 * create the UPL from this kernel buffer.
		 * The kernel buffer is then freed, leaving the UPL holding
		 * the last reference on the VM object, so the memory will
		 * be released when the UPL is committed.
		 */

		vm_map_unlock_read(map);
		/* allocate kernel buffer */
		ksize = round_page(*upl_size);
		kaddr = 0;
		ret = kmem_alloc_pageable(kernel_map,
		    &kaddr,
		    ksize,
		    tag);
		if (ret == KERN_SUCCESS) {
			/* copyin the user data */
			assert(page_aligned(offset));
			ret = copyinmap(map, offset, (void *)kaddr, *upl_size);
		}
		if (ret == KERN_SUCCESS) {
			if (ksize > *upl_size) {
				/* zero out the extra space in kernel buffer */
				memset((void *)(kaddr + *upl_size),
				    0,
				    ksize - *upl_size);
			}
			/* create the UPL from the kernel buffer */
			ret = vm_map_create_upl(kernel_map, kaddr, upl_size,
			    upl, page_list, count, flags, tag);
		}
		if (kaddr != 0) {
			/* free the kernel buffer */
			kmem_free(kernel_map, kaddr, ksize);
			kaddr = 0;
			ksize = 0;
		}
#if DEVELOPMENT || DEBUG
		DTRACE_VM4(create_upl_from_executable,
		    vm_map_t, map,
		    vm_map_address_t, offset,
		    upl_size_t, *upl_size,
		    kern_return_t, ret);
#endif /* DEVELOPMENT || DEBUG */
		return ret;
	}
#endif /* CONFIG_EMBEDDED */

	local_object = VME_OBJECT(entry);
	assert(local_object != VM_OBJECT_NULL);

	if (!entry->is_sub_map &&
	    !entry->needs_copy &&
	    *upl_size != 0 &&
	    local_object->vo_size > *upl_size && /* partial UPL */
	    entry->wired_count == 0 && /* No COW for entries that are wired */
	    (map->pmap != kernel_pmap) && /* alias checks */
	    (vm_map_entry_should_cow_for_true_share(entry) /* case 1 */
	    ||
	    ( /* case 2 */
		    local_object->internal &&
		    (local_object->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC) &&
		    local_object->ref_count > 1))) {
		vm_prot_t       prot;

		/*
		 * Case 1:
		 * Set up the targeted range for copy-on-write to avoid
		 * applying true_share/copy_delay to the entire object.
		 *
		 * Case 2:
		 * This map entry covers only part of an internal
		 * object.  There could be other map entries covering
		 * other areas of this object and some of these map
		 * entries could be marked as "needs_copy", which
		 * assumes that the object is COPY_SYMMETRIC.
		 * To avoid marking this object as COPY_DELAY and
		 * "true_share", let's shadow it and mark the new
		 * (smaller) object as "true_share" and COPY_DELAY.
		 */

		if (vm_map_lock_read_to_write(map)) {
			goto REDISCOVER_ENTRY;
		}
		vm_map_lock_assert_exclusive(map);
		assert(VME_OBJECT(entry) == local_object);

		vm_map_clip_start(map,
		    entry,
		    vm_map_trunc_page(offset,
		    VM_MAP_PAGE_MASK(map)));
		vm_map_clip_end(map,
		    entry,
		    vm_map_round_page(offset + *upl_size,
		    VM_MAP_PAGE_MASK(map)));
		if ((entry->vme_end - offset) < *upl_size) {
			*upl_size = (upl_size_t) (entry->vme_end - offset);
			assert(*upl_size == entry->vme_end - offset);
		}

		prot = entry->protection & ~VM_PROT_WRITE;
		if (override_nx(map, VME_ALIAS(entry)) && prot) {
			prot |= VM_PROT_EXECUTE;
		}
		vm_object_pmap_protect(local_object,
		    VME_OFFSET(entry),
		    entry->vme_end - entry->vme_start,
		    ((entry->is_shared ||
		    map->mapped_in_other_pmaps)
		    ? PMAP_NULL
		    : map->pmap),
		    entry->vme_start,
		    prot);

		assert(entry->wired_count == 0);

		/*
		 * Lock the VM object and re-check its status: if it's mapped
		 * in another address space, we could still be racing with
		 * another thread holding that other VM map exclusively.
		 */
		vm_object_lock(local_object);
		if (local_object->true_share) {
			/* object is already in proper state: no COW needed */
			assert(local_object->copy_strategy !=
			    MEMORY_OBJECT_COPY_SYMMETRIC);
		} else {
			/* not true_share: ask for copy-on-write below */
			assert(local_object->copy_strategy ==
			    MEMORY_OBJECT_COPY_SYMMETRIC);
			entry->needs_copy = TRUE;
		}
		vm_object_unlock(local_object);

		vm_map_lock_write_to_read(map);
	}

	if (entry->needs_copy) {
		/*
		 * Honor copy-on-write for COPY_SYMMETRIC
		 * strategy.
		 */
		vm_map_t                local_map;
		vm_object_t             object;
		vm_object_offset_t      new_offset;
		vm_prot_t               prot;
		boolean_t               wired;
		vm_map_version_t        version;
		vm_map_t                real_map;
		vm_prot_t               fault_type;

		local_map = map;

		if (caller_flags & UPL_COPYOUT_FROM) {
			fault_type = VM_PROT_READ | VM_PROT_COPY;
			vm_counters.create_upl_extra_cow++;
			vm_counters.create_upl_extra_cow_pages +=
			    (entry->vme_end - entry->vme_start) / PAGE_SIZE;
		} else {
			fault_type = VM_PROT_WRITE;
		}
		if (vm_map_lookup_locked(&local_map,
		    offset, fault_type,
		    OBJECT_LOCK_EXCLUSIVE,
		    &version, &object,
		    &new_offset, &prot, &wired,
		    NULL,
		    &real_map) != KERN_SUCCESS) {
			if (fault_type == VM_PROT_WRITE) {
				vm_counters.create_upl_lookup_failure_write++;
			} else {
				vm_counters.create_upl_lookup_failure_copy++;
			}
			vm_map_unlock_read(local_map);
			return KERN_FAILURE;
		}
		if (real_map != map) {
			vm_map_unlock(real_map);
		}
		vm_map_unlock_read(local_map);

		vm_object_unlock(object);

		goto REDISCOVER_ENTRY;
	}

	if (entry->is_sub_map) {
		vm_map_t        submap;

		submap = VME_SUBMAP(entry);
		local_start = entry->vme_start;
		local_offset = VME_OFFSET(entry);

		vm_map_reference(submap);
		vm_map_unlock_read(map);

		ret = vm_map_create_upl(submap,
		    local_offset + (offset - local_start),
		    upl_size, upl, page_list, count, flags, tag);
		vm_map_deallocate(submap);

		return ret;
	}

	if (sync_cow_data &&
	    (VME_OBJECT(entry)->shadow ||
	    VME_OBJECT(entry)->copy)) {
		local_object = VME_OBJECT(entry);
		local_start = entry->vme_start;
		local_offset = VME_OFFSET(entry);

		vm_object_reference(local_object);
		vm_map_unlock_read(map);

		if (local_object->shadow && local_object->copy) {
			vm_object_lock_request(local_object->shadow,
			    ((vm_object_offset_t)
			    ((offset - local_start) +
			    local_offset) +
			    local_object->vo_shadow_offset),
			    *upl_size, FALSE,
			    MEMORY_OBJECT_DATA_SYNC,
			    VM_PROT_NO_CHANGE);
		}
		sync_cow_data = FALSE;
		vm_object_deallocate(local_object);

		goto REDISCOVER_ENTRY;
	}
	if (force_data_sync) {
		local_object = VME_OBJECT(entry);
		local_start = entry->vme_start;
		local_offset = VME_OFFSET(entry);

		vm_object_reference(local_object);
		vm_map_unlock_read(map);

		vm_object_lock_request(local_object,
		    ((vm_object_offset_t)
		    ((offset - local_start) +
		    local_offset)),
		    (vm_object_size_t)*upl_size,
		    FALSE,
		    MEMORY_OBJECT_DATA_SYNC,
		    VM_PROT_NO_CHANGE);

		force_data_sync = FALSE;
		vm_object_deallocate(local_object);

		goto REDISCOVER_ENTRY;
	}
	if (VME_OBJECT(entry)->private) {
		*flags = UPL_DEV_MEMORY;
	} else {
		*flags = 0;
	}

	if (VME_OBJECT(entry)->phys_contiguous) {
		*flags |= UPL_PHYS_CONTIG;
	}

	local_object = VME_OBJECT(entry);
	local_offset = VME_OFFSET(entry);
	local_start = entry->vme_start;

#if CONFIG_EMBEDDED
	/*
	 * Wiring will copy the pages to the shadow object.
	 * The shadow object will not be code-signed so
	 * attempting to execute code from these copied pages
	 * would trigger a code-signing violation.
	 */
	if (entry->protection & VM_PROT_EXECUTE) {
#if MACH_ASSERT
		printf("pid %d[%s] create_upl out of executable range from "
		    "0x%llx to 0x%llx: side effects may include "
		    "code-signing violations later on\n",
		    proc_selfpid(),
		    (current_task()->bsd_info
		    ? proc_name_address(current_task()->bsd_info)
		    : "?"),
		    (uint64_t) entry->vme_start,
		    (uint64_t) entry->vme_end);
#endif /* MACH_ASSERT */
		DTRACE_VM2(cs_executable_create_upl,
		    uint64_t, (uint64_t)entry->vme_start,
		    uint64_t, (uint64_t)entry->vme_end);
		cs_executable_create_upl++;
	}
#endif /* CONFIG_EMBEDDED */

	vm_object_lock(local_object);

	/*
	 * Ensure that this object is "true_share" and "copy_delay" now,
	 * while we're still holding the VM map lock.  After we unlock the map,
	 * anything could happen to that mapping, including some copy-on-write
	 * activity.  We need to make sure that the IOPL will point at the
	 * same memory as the mapping.
	 */
	if (local_object->true_share) {
		assert(local_object->copy_strategy !=
		    MEMORY_OBJECT_COPY_SYMMETRIC);
	} else if (local_object != kernel_object &&
	    local_object != compressor_object &&
	    !local_object->phys_contiguous) {
#if VM_OBJECT_TRACKING_OP_TRUESHARE
		if (!local_object->true_share &&
		    vm_object_tracking_inited) {
			void *bt[VM_OBJECT_TRACKING_BTDEPTH];
			int num = 0;
			num = OSBacktrace(bt,
			    VM_OBJECT_TRACKING_BTDEPTH);
			btlog_add_entry(vm_object_tracking_btlog,
			    local_object,
			    VM_OBJECT_TRACKING_OP_TRUESHARE,
			    bt,
			    num);
		}
#endif /* VM_OBJECT_TRACKING_OP_TRUESHARE */
		local_object->true_share = TRUE;
		if (local_object->copy_strategy ==
		    MEMORY_OBJECT_COPY_SYMMETRIC) {
			local_object->copy_strategy = MEMORY_OBJECT_COPY_DELAY;
		}
	}

	vm_object_reference_locked(local_object);
	vm_object_unlock(local_object);

	vm_map_unlock_read(map);

	ret = vm_object_iopl_request(local_object,
	    ((vm_object_offset_t)
	    ((offset - local_start) + local_offset)),
	    *upl_size,
	    upl,
	    page_list,
	    count,
	    caller_flags,
	    tag);
	vm_object_deallocate(local_object);

	return ret;
}

/*
 * Internal routine to enter a UPL into a VM map.
 *
 * JMM - This should just be doable through the standard
 * vm_map_enter() API.
 */
kern_return_t
vm_map_enter_upl(
	vm_map_t                map,
	upl_t                   upl,
	vm_map_offset_t         *dst_addr)
{
	vm_map_size_t           size;
	vm_object_offset_t      offset;
	vm_map_offset_t         addr;
	vm_page_t               m;
	kern_return_t           kr;
	int                     isVectorUPL = 0, curr_upl = 0;
	upl_t                   vector_upl = NULL;
	vm_offset_t             vector_upl_dst_addr = 0;
	vm_map_t                vector_upl_submap = NULL;
	upl_offset_t            subupl_offset = 0;
	upl_size_t              subupl_size = 0;

	if (upl == UPL_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((isVectorUPL = vector_upl_is_valid(upl))) {
		int mapped = 0, valid_upls = 0;
		vector_upl = upl;

		upl_lock(vector_upl);
		for (curr_upl = 0; curr_upl < MAX_VECTOR_UPL_ELEMENTS; curr_upl++) {
			upl =  vector_upl_subupl_byindex(vector_upl, curr_upl );
			if (upl == NULL) {
				continue;
			}
			valid_upls++;
			if (UPL_PAGE_LIST_MAPPED & upl->flags) {
				mapped++;
			}
		}

		if (mapped) {
			if (mapped != valid_upls) {
				panic("Only %d of the %d sub-upls within the Vector UPL are alread mapped\n", mapped, valid_upls);
			} else {
				upl_unlock(vector_upl);
				return KERN_FAILURE;
			}
		}

		kr = kmem_suballoc(map, &vector_upl_dst_addr, vector_upl->size, FALSE,
		    VM_FLAGS_ANYWHERE, VM_MAP_KERNEL_FLAGS_NONE, VM_KERN_MEMORY_NONE,
		    &vector_upl_submap);
		if (kr != KERN_SUCCESS) {
			panic("Vector UPL submap allocation failed\n");
		}
		map = vector_upl_submap;
		vector_upl_set_submap(vector_upl, vector_upl_submap, vector_upl_dst_addr);
		curr_upl = 0;
	} else {
		upl_lock(upl);
	}

process_upl_to_enter:
	if (isVectorUPL) {
		if (curr_upl == MAX_VECTOR_UPL_ELEMENTS) {
			*dst_addr = vector_upl_dst_addr;
			upl_unlock(vector_upl);
			return KERN_SUCCESS;
		}
		upl =  vector_upl_subupl_byindex(vector_upl, curr_upl++ );
		if (upl == NULL) {
			goto process_upl_to_enter;
		}

		vector_upl_get_iostate(vector_upl, upl, &subupl_offset, &subupl_size);
		*dst_addr = (vm_map_offset_t)(vector_upl_dst_addr + (vm_map_offset_t)subupl_offset);
	} else {
		/*
		 * check to see if already mapped
		 */
		if (UPL_PAGE_LIST_MAPPED & upl->flags) {
			upl_unlock(upl);
			return KERN_FAILURE;
		}
	}
	if ((!(upl->flags & UPL_SHADOWED)) &&
	    ((upl->flags & UPL_HAS_BUSY) ||
	    !((upl->flags & (UPL_DEVICE_MEMORY | UPL_IO_WIRE)) || (upl->map_object->phys_contiguous)))) {
		vm_object_t             object;
		vm_page_t               alias_page;
		vm_object_offset_t      new_offset;
		unsigned int            pg_num;
		wpl_array_t             lite_list;

		if (upl->flags & UPL_INTERNAL) {
			lite_list = (wpl_array_t)
			    ((((uintptr_t)upl) + sizeof(struct upl))
			    + ((upl->size / PAGE_SIZE) * sizeof(upl_page_info_t)));
		} else {
			lite_list = (wpl_array_t)(((uintptr_t)upl) + sizeof(struct upl));
		}
		object = upl->map_object;
		upl->map_object = vm_object_allocate(upl->size);

		vm_object_lock(upl->map_object);

		upl->map_object->shadow = object;
		upl->map_object->pageout = TRUE;
		upl->map_object->can_persist = FALSE;
		upl->map_object->copy_strategy = MEMORY_OBJECT_COPY_NONE;
		upl->map_object->vo_shadow_offset = upl->offset - object->paging_offset;
		upl->map_object->wimg_bits = object->wimg_bits;
		offset = upl->map_object->vo_shadow_offset;
		new_offset = 0;
		size = upl->size;

		upl->flags |= UPL_SHADOWED;

		while (size) {
			pg_num = (unsigned int) (new_offset / PAGE_SIZE);
			assert(pg_num == new_offset / PAGE_SIZE);

			if (lite_list[pg_num >> 5] & (1U << (pg_num & 31))) {
				VM_PAGE_GRAB_FICTITIOUS(alias_page);

				vm_object_lock(object);

				m = vm_page_lookup(object, offset);
				if (m == VM_PAGE_NULL) {
					panic("vm_upl_map: page missing\n");
				}

				/*
				 * Convert the fictitious page to a private
				 * shadow of the real page.
				 */
				assert(alias_page->vmp_fictitious);
				alias_page->vmp_fictitious = FALSE;
				alias_page->vmp_private = TRUE;
				alias_page->vmp_free_when_done = TRUE;
				/*
				 * since m is a page in the upl it must
				 * already be wired or BUSY, so it's
				 * safe to assign the underlying physical
				 * page to the alias
				 */
				VM_PAGE_SET_PHYS_PAGE(alias_page, VM_PAGE_GET_PHYS_PAGE(m));

				vm_object_unlock(object);

				vm_page_lockspin_queues();
				vm_page_wire(alias_page, VM_KERN_MEMORY_NONE, TRUE);
				vm_page_unlock_queues();

				vm_page_insert_wired(alias_page, upl->map_object, new_offset, VM_KERN_MEMORY_NONE);

				assert(!alias_page->vmp_wanted);
				alias_page->vmp_busy = FALSE;
				alias_page->vmp_absent = FALSE;
			}
			size -= PAGE_SIZE;
			offset += PAGE_SIZE_64;
			new_offset += PAGE_SIZE_64;
		}
		vm_object_unlock(upl->map_object);
	}
	if (upl->flags & UPL_SHADOWED) {
		offset = 0;
	} else {
		offset = upl->offset - upl->map_object->paging_offset;
	}

	size = upl->size;

	vm_object_reference(upl->map_object);

	if (!isVectorUPL) {
		*dst_addr = 0;
		/*
		 * NEED A UPL_MAP ALIAS
		 */
		kr = vm_map_enter(map, dst_addr, (vm_map_size_t)size, (vm_map_offset_t) 0,
		    VM_FLAGS_ANYWHERE, VM_MAP_KERNEL_FLAGS_NONE, VM_KERN_MEMORY_OSFMK,
		    upl->map_object, offset, FALSE,
		    VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);

		if (kr != KERN_SUCCESS) {
			vm_object_deallocate(upl->map_object);
			upl_unlock(upl);
			return kr;
		}
	} else {
		kr = vm_map_enter(map, dst_addr, (vm_map_size_t)size, (vm_map_offset_t) 0,
		    VM_FLAGS_FIXED, VM_MAP_KERNEL_FLAGS_NONE, VM_KERN_MEMORY_OSFMK,
		    upl->map_object, offset, FALSE,
		    VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);
		if (kr) {
			panic("vm_map_enter failed for a Vector UPL\n");
		}
	}
	vm_object_lock(upl->map_object);

	for (addr = *dst_addr; size > 0; size -= PAGE_SIZE, addr += PAGE_SIZE) {
		m = vm_page_lookup(upl->map_object, offset);

		if (m) {
			m->vmp_pmapped = TRUE;

			/* CODE SIGNING ENFORCEMENT: page has been wpmapped,
			 * but only in kernel space. If this was on a user map,
			 * we'd have to set the wpmapped bit. */
			/* m->vmp_wpmapped = TRUE; */
			assert(map->pmap == kernel_pmap);

			PMAP_ENTER(map->pmap, addr, m, VM_PROT_DEFAULT, VM_PROT_NONE, 0, TRUE, kr);

			assert(kr == KERN_SUCCESS);
#if KASAN
			kasan_notify_address(addr, PAGE_SIZE_64);
#endif
		}
		offset += PAGE_SIZE_64;
	}
	vm_object_unlock(upl->map_object);

	/*
	 * hold a reference for the mapping
	 */
	upl->ref_count++;
	upl->flags |= UPL_PAGE_LIST_MAPPED;
	upl->kaddr = (vm_offset_t) *dst_addr;
	assert(upl->kaddr == *dst_addr);

	if (isVectorUPL) {
		goto process_upl_to_enter;
	}

	upl_unlock(upl);

	return KERN_SUCCESS;
}

/*
 * Internal routine to remove a UPL mapping from a VM map.
 *
 * XXX - This should just be doable through a standard
 * vm_map_remove() operation.  Otherwise, implicit clean-up
 * of the target map won't be able to correctly remove
 * these (and release the reference on the UPL).  Having
 * to do this means we can't map these into user-space
 * maps yet.
 */
kern_return_t
vm_map_remove_upl(
	vm_map_t        map,
	upl_t           upl)
{
	vm_address_t    addr;
	upl_size_t      size;
	int             isVectorUPL = 0, curr_upl = 0;
	upl_t           vector_upl = NULL;

	if (upl == UPL_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((isVectorUPL = vector_upl_is_valid(upl))) {
		int     unmapped = 0, valid_upls = 0;
		vector_upl = upl;
		upl_lock(vector_upl);
		for (curr_upl = 0; curr_upl < MAX_VECTOR_UPL_ELEMENTS; curr_upl++) {
			upl =  vector_upl_subupl_byindex(vector_upl, curr_upl );
			if (upl == NULL) {
				continue;
			}
			valid_upls++;
			if (!(UPL_PAGE_LIST_MAPPED & upl->flags)) {
				unmapped++;
			}
		}

		if (unmapped) {
			if (unmapped != valid_upls) {
				panic("%d of the %d sub-upls within the Vector UPL is/are not mapped\n", unmapped, valid_upls);
			} else {
				upl_unlock(vector_upl);
				return KERN_FAILURE;
			}
		}
		curr_upl = 0;
	} else {
		upl_lock(upl);
	}

process_upl_to_remove:
	if (isVectorUPL) {
		if (curr_upl == MAX_VECTOR_UPL_ELEMENTS) {
			vm_map_t v_upl_submap;
			vm_offset_t v_upl_submap_dst_addr;
			vector_upl_get_submap(vector_upl, &v_upl_submap, &v_upl_submap_dst_addr);

			vm_map_remove(map, v_upl_submap_dst_addr, v_upl_submap_dst_addr + vector_upl->size, VM_MAP_REMOVE_NO_FLAGS);
			vm_map_deallocate(v_upl_submap);
			upl_unlock(vector_upl);
			return KERN_SUCCESS;
		}

		upl =  vector_upl_subupl_byindex(vector_upl, curr_upl++ );
		if (upl == NULL) {
			goto process_upl_to_remove;
		}
	}

	if (upl->flags & UPL_PAGE_LIST_MAPPED) {
		addr = upl->kaddr;
		size = upl->size;

		assert(upl->ref_count > 1);
		upl->ref_count--;               /* removing mapping ref */

		upl->flags &= ~UPL_PAGE_LIST_MAPPED;
		upl->kaddr = (vm_offset_t) 0;

		if (!isVectorUPL) {
			upl_unlock(upl);

			vm_map_remove(
				map,
				vm_map_trunc_page(addr,
				VM_MAP_PAGE_MASK(map)),
				vm_map_round_page(addr + size,
				VM_MAP_PAGE_MASK(map)),
				VM_MAP_REMOVE_NO_FLAGS);
			return KERN_SUCCESS;
		} else {
			/*
			 * If it's a Vectored UPL, we'll be removing the entire
			 * submap anyways, so no need to remove individual UPL
			 * element mappings from within the submap
			 */
			goto process_upl_to_remove;
		}
	}
	upl_unlock(upl);

	return KERN_FAILURE;
}


kern_return_t
upl_commit_range(
	upl_t                   upl,
	upl_offset_t            offset,
	upl_size_t              size,
	int                     flags,
	upl_page_info_t         *page_list,
	mach_msg_type_number_t  count,
	boolean_t               *empty)
{
	upl_size_t              xfer_size, subupl_size = size;
	vm_object_t             shadow_object;
	vm_object_t             object;
	vm_object_t             m_object;
	vm_object_offset_t      target_offset;
	upl_offset_t            subupl_offset = offset;
	int                     entry;
	wpl_array_t             lite_list;
	int                     occupied;
	int                     clear_refmod = 0;
	int                     pgpgout_count = 0;
	struct  vm_page_delayed_work    dw_array[DEFAULT_DELAYED_WORK_LIMIT];
	struct  vm_page_delayed_work    *dwp;
	int                     dw_count;
	int                     dw_limit;
	int                     isVectorUPL = 0;
	upl_t                   vector_upl = NULL;
	boolean_t               should_be_throttled = FALSE;

	vm_page_t               nxt_page = VM_PAGE_NULL;
	int                     fast_path_possible = 0;
	int                     fast_path_full_commit = 0;
	int                     throttle_page = 0;
	int                     unwired_count = 0;
	int                     local_queue_count = 0;
	vm_page_t               first_local, last_local;

	*empty = FALSE;

	if (upl == UPL_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (count == 0) {
		page_list = NULL;
	}

	if ((isVectorUPL = vector_upl_is_valid(upl))) {
		vector_upl = upl;
		upl_lock(vector_upl);
	} else {
		upl_lock(upl);
	}

process_upl_to_commit:

	if (isVectorUPL) {
		size = subupl_size;
		offset = subupl_offset;
		if (size == 0) {
			upl_unlock(vector_upl);
			return KERN_SUCCESS;
		}
		upl =  vector_upl_subupl_byoffset(vector_upl, &offset, &size);
		if (upl == NULL) {
			upl_unlock(vector_upl);
			return KERN_FAILURE;
		}
		page_list = UPL_GET_INTERNAL_PAGE_LIST_SIMPLE(upl);
		subupl_size -= size;
		subupl_offset += size;
	}

#if UPL_DEBUG
	if (upl->upl_commit_index < UPL_DEBUG_COMMIT_RECORDS) {
		(void) OSBacktrace(&upl->upl_commit_records[upl->upl_commit_index].c_retaddr[0], UPL_DEBUG_STACK_FRAMES);

		upl->upl_commit_records[upl->upl_commit_index].c_beg = offset;
		upl->upl_commit_records[upl->upl_commit_index].c_end = (offset + size);

		upl->upl_commit_index++;
	}
#endif
	if (upl->flags & UPL_DEVICE_MEMORY) {
		xfer_size = 0;
	} else if ((offset + size) <= upl->size) {
		xfer_size = size;
	} else {
		if (!isVectorUPL) {
			upl_unlock(upl);
		} else {
			upl_unlock(vector_upl);
		}
		return KERN_FAILURE;
	}
	if (upl->flags & UPL_SET_DIRTY) {
		flags |= UPL_COMMIT_SET_DIRTY;
	}
	if (upl->flags & UPL_CLEAR_DIRTY) {
		flags |= UPL_COMMIT_CLEAR_DIRTY;
	}

	if (upl->flags & UPL_INTERNAL) {
		lite_list = (wpl_array_t) ((((uintptr_t)upl) + sizeof(struct upl))
		    + ((upl->size / PAGE_SIZE) * sizeof(upl_page_info_t)));
	} else {
		lite_list = (wpl_array_t) (((uintptr_t)upl) + sizeof(struct upl));
	}

	object = upl->map_object;

	if (upl->flags & UPL_SHADOWED) {
		vm_object_lock(object);
		shadow_object = object->shadow;
	} else {
		shadow_object = object;
	}
	entry = offset / PAGE_SIZE;
	target_offset = (vm_object_offset_t)offset;

	assert(!(target_offset & PAGE_MASK));
	assert(!(xfer_size & PAGE_MASK));

	if (upl->flags & UPL_KERNEL_OBJECT) {
		vm_object_lock_shared(shadow_object);
	} else {
		vm_object_lock(shadow_object);
	}

	VM_OBJECT_WIRED_PAGE_UPDATE_START(shadow_object);

	if (upl->flags & UPL_ACCESS_BLOCKED) {
		assert(shadow_object->blocked_access);
		shadow_object->blocked_access = FALSE;
		vm_object_wakeup(object, VM_OBJECT_EVENT_UNBLOCKED);
	}

	if (shadow_object->code_signed) {
		/*
		 * CODE SIGNING:
		 * If the object is code-signed, do not let this UPL tell
		 * us if the pages are valid or not.  Let the pages be
		 * validated by VM the normal way (when they get mapped or
		 * copied).
		 */
		flags &= ~UPL_COMMIT_CS_VALIDATED;
	}
	if (!page_list) {
		/*
		 * No page list to get the code-signing info from !?
		 */
		flags &= ~UPL_COMMIT_CS_VALIDATED;
	}
	if (!VM_DYNAMIC_PAGING_ENABLED() && shadow_object->internal) {
		should_be_throttled = TRUE;
	}

	dwp = &dw_array[0];
	dw_count = 0;
	dw_limit = DELAYED_WORK_LIMIT(DEFAULT_DELAYED_WORK_LIMIT);

	if ((upl->flags & UPL_IO_WIRE) &&
	    !(flags & UPL_COMMIT_FREE_ABSENT) &&
	    !isVectorUPL &&
	    shadow_object->purgable != VM_PURGABLE_VOLATILE &&
	    shadow_object->purgable != VM_PURGABLE_EMPTY) {
		if (!vm_page_queue_empty(&shadow_object->memq)) {
			if (size == shadow_object->vo_size) {
				nxt_page = (vm_page_t)vm_page_queue_first(&shadow_object->memq);
				fast_path_full_commit = 1;
			}
			fast_path_possible = 1;

			if (!VM_DYNAMIC_PAGING_ENABLED() && shadow_object->internal &&
			    (shadow_object->purgable == VM_PURGABLE_DENY ||
			    shadow_object->purgable == VM_PURGABLE_NONVOLATILE ||
			    shadow_object->purgable == VM_PURGABLE_VOLATILE)) {
				throttle_page = 1;
			}
		}
	}
	first_local = VM_PAGE_NULL;
	last_local = VM_PAGE_NULL;

	while (xfer_size) {
		vm_page_t       t, m;

		dwp->dw_mask = 0;
		clear_refmod = 0;

		m = VM_PAGE_NULL;

		if (upl->flags & UPL_LITE) {
			unsigned int    pg_num;

			if (nxt_page != VM_PAGE_NULL) {
				m = nxt_page;
				nxt_page = (vm_page_t)vm_page_queue_next(&nxt_page->vmp_listq);
				target_offset = m->vmp_offset;
			}
			pg_num = (unsigned int) (target_offset / PAGE_SIZE);
			assert(pg_num == target_offset / PAGE_SIZE);

			if (lite_list[pg_num >> 5] & (1U << (pg_num & 31))) {
				lite_list[pg_num >> 5] &= ~(1U << (pg_num & 31));

				if (!(upl->flags & UPL_KERNEL_OBJECT) && m == VM_PAGE_NULL) {
					m = vm_page_lookup(shadow_object, target_offset + (upl->offset - shadow_object->paging_offset));
				}
			} else {
				m = NULL;
			}
		}
		if (upl->flags & UPL_SHADOWED) {
			if ((t = vm_page_lookup(object, target_offset)) != VM_PAGE_NULL) {
				t->vmp_free_when_done = FALSE;

				VM_PAGE_FREE(t);

				if (!(upl->flags & UPL_KERNEL_OBJECT) && m == VM_PAGE_NULL) {
					m = vm_page_lookup(shadow_object, target_offset + object->vo_shadow_offset);
				}
			}
		}
		if (m == VM_PAGE_NULL) {
			goto commit_next_page;
		}

		m_object = VM_PAGE_OBJECT(m);

		if (m->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR) {
			assert(m->vmp_busy);

			dwp->dw_mask |= (DW_clear_busy | DW_PAGE_WAKEUP);
			goto commit_next_page;
		}

		if (flags & UPL_COMMIT_CS_VALIDATED) {
			/*
			 * CODE SIGNING:
			 * Set the code signing bits according to
			 * what the UPL says they should be.
			 */
			m->vmp_cs_validated = page_list[entry].cs_validated;
			m->vmp_cs_tainted = page_list[entry].cs_tainted;
			m->vmp_cs_nx = page_list[entry].cs_nx;
		}
		if (flags & UPL_COMMIT_WRITTEN_BY_KERNEL) {
			m->vmp_written_by_kernel = TRUE;
		}

		if (upl->flags & UPL_IO_WIRE) {
			if (page_list) {
				page_list[entry].phys_addr = 0;
			}

			if (flags & UPL_COMMIT_SET_DIRTY) {
				SET_PAGE_DIRTY(m, FALSE);
			} else if (flags & UPL_COMMIT_CLEAR_DIRTY) {
				m->vmp_dirty = FALSE;

				if (!(flags & UPL_COMMIT_CS_VALIDATED) &&
				    m->vmp_cs_validated && !m->vmp_cs_tainted) {
					/*
					 * CODE SIGNING:
					 * This page is no longer dirty
					 * but could have been modified,
					 * so it will need to be
					 * re-validated.
					 */
					m->vmp_cs_validated = FALSE;

					VM_PAGEOUT_DEBUG(vm_cs_validated_resets, 1);

					pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(m));
				}
				clear_refmod |= VM_MEM_MODIFIED;
			}
			if (upl->flags & UPL_ACCESS_BLOCKED) {
				/*
				 * We blocked access to the pages in this UPL.
				 * Clear the "busy" bit and wake up any waiter
				 * for this page.
				 */
				dwp->dw_mask |= (DW_clear_busy | DW_PAGE_WAKEUP);
			}
			if (fast_path_possible) {
				assert(m_object->purgable != VM_PURGABLE_EMPTY);
				assert(m_object->purgable != VM_PURGABLE_VOLATILE);
				if (m->vmp_absent) {
					assert(m->vmp_q_state == VM_PAGE_NOT_ON_Q);
					assert(m->vmp_wire_count == 0);
					assert(m->vmp_busy);

					m->vmp_absent = FALSE;
					dwp->dw_mask |= (DW_clear_busy | DW_PAGE_WAKEUP);
				} else {
					if (m->vmp_wire_count == 0) {
						panic("wire_count == 0, m = %p, obj = %p\n", m, shadow_object);
					}
					assert(m->vmp_q_state == VM_PAGE_IS_WIRED);

					/*
					 * XXX FBDP need to update some other
					 * counters here (purgeable_wired_count)
					 * (ledgers), ...
					 */
					assert(m->vmp_wire_count > 0);
					m->vmp_wire_count--;

					if (m->vmp_wire_count == 0) {
						m->vmp_q_state = VM_PAGE_NOT_ON_Q;
						unwired_count++;
					}
				}
				if (m->vmp_wire_count == 0) {
					assert(m->vmp_pageq.next == 0 && m->vmp_pageq.prev == 0);

					if (last_local == VM_PAGE_NULL) {
						assert(first_local == VM_PAGE_NULL);

						last_local = m;
						first_local = m;
					} else {
						assert(first_local != VM_PAGE_NULL);

						m->vmp_pageq.next = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(first_local);
						first_local->vmp_pageq.prev = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(m);
						first_local = m;
					}
					local_queue_count++;

					if (throttle_page) {
						m->vmp_q_state = VM_PAGE_ON_THROTTLED_Q;
					} else {
						if (flags & UPL_COMMIT_INACTIVATE) {
							if (shadow_object->internal) {
								m->vmp_q_state = VM_PAGE_ON_INACTIVE_INTERNAL_Q;
							} else {
								m->vmp_q_state = VM_PAGE_ON_INACTIVE_EXTERNAL_Q;
							}
						} else {
							m->vmp_q_state = VM_PAGE_ON_ACTIVE_Q;
						}
					}
				}
			} else {
				if (flags & UPL_COMMIT_INACTIVATE) {
					dwp->dw_mask |= DW_vm_page_deactivate_internal;
					clear_refmod |= VM_MEM_REFERENCED;
				}
				if (m->vmp_absent) {
					if (flags & UPL_COMMIT_FREE_ABSENT) {
						dwp->dw_mask |= DW_vm_page_free;
					} else {
						m->vmp_absent = FALSE;
						dwp->dw_mask |= (DW_clear_busy | DW_PAGE_WAKEUP);

						if (!(dwp->dw_mask & DW_vm_page_deactivate_internal)) {
							dwp->dw_mask |= DW_vm_page_activate;
						}
					}
				} else {
					dwp->dw_mask |= DW_vm_page_unwire;
				}
			}
			goto commit_next_page;
		}
		assert(m->vmp_q_state != VM_PAGE_USED_BY_COMPRESSOR);

		if (page_list) {
			page_list[entry].phys_addr = 0;
		}

		/*
		 * make sure to clear the hardware
		 * modify or reference bits before
		 * releasing the BUSY bit on this page
		 * otherwise we risk losing a legitimate
		 * change of state
		 */
		if (flags & UPL_COMMIT_CLEAR_DIRTY) {
			m->vmp_dirty = FALSE;

			clear_refmod |= VM_MEM_MODIFIED;
		}
		if (m->vmp_laundry) {
			dwp->dw_mask |= DW_vm_pageout_throttle_up;
		}

		if (VM_PAGE_WIRED(m)) {
			m->vmp_free_when_done = FALSE;
		}

		if (!(flags & UPL_COMMIT_CS_VALIDATED) &&
		    m->vmp_cs_validated && !m->vmp_cs_tainted) {
			/*
			 * CODE SIGNING:
			 * This page is no longer dirty
			 * but could have been modified,
			 * so it will need to be
			 * re-validated.
			 */
			m->vmp_cs_validated = FALSE;

			VM_PAGEOUT_DEBUG(vm_cs_validated_resets, 1);

			pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(m));
		}
		if (m->vmp_overwriting) {
			/*
			 * the (COPY_OUT_FROM == FALSE) request_page_list case
			 */
			if (m->vmp_busy) {
#if CONFIG_PHANTOM_CACHE
				if (m->vmp_absent && !m_object->internal) {
					dwp->dw_mask |= DW_vm_phantom_cache_update;
				}
#endif
				m->vmp_absent = FALSE;

				dwp->dw_mask |= DW_clear_busy;
			} else {
				/*
				 * alternate (COPY_OUT_FROM == FALSE) page_list case
				 * Occurs when the original page was wired
				 * at the time of the list request
				 */
				assert(VM_PAGE_WIRED(m));

				dwp->dw_mask |= DW_vm_page_unwire; /* reactivates */
			}
			m->vmp_overwriting = FALSE;
		}
		m->vmp_cleaning = FALSE;

		if (m->vmp_free_when_done) {
			/*
			 * With the clean queue enabled, UPL_PAGEOUT should
			 * no longer set the pageout bit. Its pages now go
			 * to the clean queue.
			 *
			 * We don't use the cleaned Q anymore and so this
			 * assert isn't correct. The code for the clean Q
			 * still exists and might be used in the future. If we
			 * go back to the cleaned Q, we will re-enable this
			 * assert.
			 *
			 * assert(!(upl->flags & UPL_PAGEOUT));
			 */
			assert(!m_object->internal);

			m->vmp_free_when_done = FALSE;

			if ((flags & UPL_COMMIT_SET_DIRTY) ||
			    (m->vmp_pmapped && (pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(m)) & VM_MEM_MODIFIED))) {
				/*
				 * page was re-dirtied after we started
				 * the pageout... reactivate it since
				 * we don't know whether the on-disk
				 * copy matches what is now in memory
				 */
				SET_PAGE_DIRTY(m, FALSE);

				dwp->dw_mask |= DW_vm_page_activate | DW_PAGE_WAKEUP;

				if (upl->flags & UPL_PAGEOUT) {
					VM_STAT_INCR(reactivations);
					DTRACE_VM2(pgrec, int, 1, (uint64_t *), NULL);
				}
			} else {
				/*
				 * page has been successfully cleaned
				 * go ahead and free it for other use
				 */
				if (m_object->internal) {
					DTRACE_VM2(anonpgout, int, 1, (uint64_t *), NULL);
				} else {
					DTRACE_VM2(fspgout, int, 1, (uint64_t *), NULL);
				}
				m->vmp_dirty = FALSE;
				m->vmp_busy = TRUE;

				dwp->dw_mask |= DW_vm_page_free;
			}
			goto commit_next_page;
		}
		/*
		 * It is a part of the semantic of COPYOUT_FROM
		 * UPLs that a commit implies cache sync
		 * between the vm page and the backing store
		 * this can be used to strip the precious bit
		 * as well as clean
		 */
		if ((upl->flags & UPL_PAGE_SYNC_DONE) || (flags & UPL_COMMIT_CLEAR_PRECIOUS)) {
			m->vmp_precious = FALSE;
		}

		if (flags & UPL_COMMIT_SET_DIRTY) {
			SET_PAGE_DIRTY(m, FALSE);
		} else {
			m->vmp_dirty = FALSE;
		}

		/* with the clean queue on, move *all* cleaned pages to the clean queue */
		if (hibernate_cleaning_in_progress == FALSE && !m->vmp_dirty && (upl->flags & UPL_PAGEOUT)) {
			pgpgout_count++;

			VM_STAT_INCR(pageouts);
			DTRACE_VM2(pgout, int, 1, (uint64_t *), NULL);

			dwp->dw_mask |= DW_enqueue_cleaned;
		} else if (should_be_throttled == TRUE && (m->vmp_q_state == VM_PAGE_NOT_ON_Q)) {
			/*
			 * page coming back in from being 'frozen'...
			 * it was dirty before it was frozen, so keep it so
			 * the vm_page_activate will notice that it really belongs
			 * on the throttle queue and put it there
			 */
			SET_PAGE_DIRTY(m, FALSE);
			dwp->dw_mask |= DW_vm_page_activate;
		} else {
			if ((flags & UPL_COMMIT_INACTIVATE) && !m->vmp_clustered && (m->vmp_q_state != VM_PAGE_ON_SPECULATIVE_Q)) {
				dwp->dw_mask |= DW_vm_page_deactivate_internal;
				clear_refmod |= VM_MEM_REFERENCED;
			} else if (!VM_PAGE_PAGEABLE(m)) {
				if (m->vmp_clustered || (flags & UPL_COMMIT_SPECULATE)) {
					dwp->dw_mask |= DW_vm_page_speculate;
				} else if (m->vmp_reference) {
					dwp->dw_mask |= DW_vm_page_activate;
				} else {
					dwp->dw_mask |= DW_vm_page_deactivate_internal;
					clear_refmod |= VM_MEM_REFERENCED;
				}
			}
		}
		if (upl->flags & UPL_ACCESS_BLOCKED) {
			/*
			 * We blocked access to the pages in this URL.
			 * Clear the "busy" bit on this page before we
			 * wake up any waiter.
			 */
			dwp->dw_mask |= DW_clear_busy;
		}
		/*
		 * Wakeup any thread waiting for the page to be un-cleaning.
		 */
		dwp->dw_mask |= DW_PAGE_WAKEUP;

commit_next_page:
		if (clear_refmod) {
			pmap_clear_refmod(VM_PAGE_GET_PHYS_PAGE(m), clear_refmod);
		}

		target_offset += PAGE_SIZE_64;
		xfer_size -= PAGE_SIZE;
		entry++;

		if (dwp->dw_mask) {
			if (dwp->dw_mask & ~(DW_clear_busy | DW_PAGE_WAKEUP)) {
				VM_PAGE_ADD_DELAYED_WORK(dwp, m, dw_count);

				if (dw_count >= dw_limit) {
					vm_page_do_delayed_work(shadow_object, VM_KERN_MEMORY_NONE, &dw_array[0], dw_count);

					dwp = &dw_array[0];
					dw_count = 0;
				}
			} else {
				if (dwp->dw_mask & DW_clear_busy) {
					m->vmp_busy = FALSE;
				}

				if (dwp->dw_mask & DW_PAGE_WAKEUP) {
					PAGE_WAKEUP(m);
				}
			}
		}
	}
	if (dw_count) {
		vm_page_do_delayed_work(shadow_object, VM_KERN_MEMORY_NONE, &dw_array[0], dw_count);
	}

	if (fast_path_possible) {
		assert(shadow_object->purgable != VM_PURGABLE_VOLATILE);
		assert(shadow_object->purgable != VM_PURGABLE_EMPTY);

		if (local_queue_count || unwired_count) {
			if (local_queue_count) {
				vm_page_t       first_target;
				vm_page_queue_head_t    *target_queue;

				if (throttle_page) {
					target_queue = &vm_page_queue_throttled;
				} else {
					if (flags & UPL_COMMIT_INACTIVATE) {
						if (shadow_object->internal) {
							target_queue = &vm_page_queue_anonymous;
						} else {
							target_queue = &vm_page_queue_inactive;
						}
					} else {
						target_queue = &vm_page_queue_active;
					}
				}
				/*
				 * Transfer the entire local queue to a regular LRU page queues.
				 */
				vm_page_lockspin_queues();

				first_target = (vm_page_t) vm_page_queue_first(target_queue);

				if (vm_page_queue_empty(target_queue)) {
					target_queue->prev = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(last_local);
				} else {
					first_target->vmp_pageq.prev = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(last_local);
				}

				target_queue->next = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(first_local);
				first_local->vmp_pageq.prev = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(target_queue);
				last_local->vmp_pageq.next = VM_PAGE_CONVERT_TO_QUEUE_ENTRY(first_target);

				/*
				 * Adjust the global page counts.
				 */
				if (throttle_page) {
					vm_page_throttled_count += local_queue_count;
				} else {
					if (flags & UPL_COMMIT_INACTIVATE) {
						if (shadow_object->internal) {
							vm_page_anonymous_count += local_queue_count;
						}
						vm_page_inactive_count += local_queue_count;

						token_new_pagecount += local_queue_count;
					} else {
						vm_page_active_count += local_queue_count;
					}

					if (shadow_object->internal) {
						vm_page_pageable_internal_count += local_queue_count;
					} else {
						vm_page_pageable_external_count += local_queue_count;
					}
				}
			} else {
				vm_page_lockspin_queues();
			}
			if (unwired_count) {
				vm_page_wire_count -= unwired_count;
				VM_CHECK_MEMORYSTATUS;
			}
			vm_page_unlock_queues();

			VM_OBJECT_WIRED_PAGE_COUNT(shadow_object, -unwired_count);
		}
	}
	occupied = 1;

	if (upl->flags & UPL_DEVICE_MEMORY) {
		occupied = 0;
	} else if (upl->flags & UPL_LITE) {
		int     pg_num;
		int     i;

		occupied = 0;

		if (!fast_path_full_commit) {
			pg_num = upl->size / PAGE_SIZE;
			pg_num = (pg_num + 31) >> 5;

			for (i = 0; i < pg_num; i++) {
				if (lite_list[i] != 0) {
					occupied = 1;
					break;
				}
			}
		}
	} else {
		if (vm_page_queue_empty(&upl->map_object->memq)) {
			occupied = 0;
		}
	}
	if (occupied == 0) {
		/*
		 * If this UPL element belongs to a Vector UPL and is
		 * empty, then this is the right function to deallocate
		 * it. So go ahead set the *empty variable. The flag
		 * UPL_COMMIT_NOTIFY_EMPTY, from the caller's point of view
		 * should be considered relevant for the Vector UPL and not
		 * the internal UPLs.
		 */
		if ((upl->flags & UPL_COMMIT_NOTIFY_EMPTY) || isVectorUPL) {
			*empty = TRUE;
		}

		if (object == shadow_object && !(upl->flags & UPL_KERNEL_OBJECT)) {
			/*
			 * this is not a paging object
			 * so we need to drop the paging reference
			 * that was taken when we created the UPL
			 * against this object
			 */
			vm_object_activity_end(shadow_object);
			vm_object_collapse(shadow_object, 0, TRUE);
		} else {
			/*
			 * we dontated the paging reference to
			 * the map object... vm_pageout_object_terminate
			 * will drop this reference
			 */
		}
	}
	VM_OBJECT_WIRED_PAGE_UPDATE_END(shadow_object, shadow_object->wire_tag);
	vm_object_unlock(shadow_object);
	if (object != shadow_object) {
		vm_object_unlock(object);
	}

	if (!isVectorUPL) {
		upl_unlock(upl);
	} else {
		/*
		 * If we completed our operations on an UPL that is
		 * part of a Vectored UPL and if empty is TRUE, then
		 * we should go ahead and deallocate this UPL element.
		 * Then we check if this was the last of the UPL elements
		 * within that Vectored UPL. If so, set empty to TRUE
		 * so that in ubc_upl_commit_range or ubc_upl_commit, we
		 * can go ahead and deallocate the Vector UPL too.
		 */
		if (*empty == TRUE) {
			*empty = vector_upl_set_subupl(vector_upl, upl, 0);
			upl_deallocate(upl);
		}
		goto process_upl_to_commit;
	}
	if (pgpgout_count) {
		DTRACE_VM2(pgpgout, int, pgpgout_count, (uint64_t *), NULL);
	}

	return KERN_SUCCESS;
}

kern_return_t
upl_abort_range(
	upl_t                   upl,
	upl_offset_t            offset,
	upl_size_t              size,
	int                     error,
	boolean_t               *empty)
{
	upl_page_info_t         *user_page_list = NULL;
	upl_size_t              xfer_size, subupl_size = size;
	vm_object_t             shadow_object;
	vm_object_t             object;
	vm_object_offset_t      target_offset;
	upl_offset_t            subupl_offset = offset;
	int                     entry;
	wpl_array_t             lite_list;
	int                     occupied;
	struct  vm_page_delayed_work    dw_array[DEFAULT_DELAYED_WORK_LIMIT];
	struct  vm_page_delayed_work    *dwp;
	int                     dw_count;
	int                     dw_limit;
	int                     isVectorUPL = 0;
	upl_t                   vector_upl = NULL;

	*empty = FALSE;

	if (upl == UPL_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((upl->flags & UPL_IO_WIRE) && !(error & UPL_ABORT_DUMP_PAGES)) {
		return upl_commit_range(upl, offset, size, UPL_COMMIT_FREE_ABSENT, NULL, 0, empty);
	}

	if ((isVectorUPL = vector_upl_is_valid(upl))) {
		vector_upl = upl;
		upl_lock(vector_upl);
	} else {
		upl_lock(upl);
	}

process_upl_to_abort:
	if (isVectorUPL) {
		size = subupl_size;
		offset = subupl_offset;
		if (size == 0) {
			upl_unlock(vector_upl);
			return KERN_SUCCESS;
		}
		upl =  vector_upl_subupl_byoffset(vector_upl, &offset, &size);
		if (upl == NULL) {
			upl_unlock(vector_upl);
			return KERN_FAILURE;
		}
		subupl_size -= size;
		subupl_offset += size;
	}

	*empty = FALSE;

#if UPL_DEBUG
	if (upl->upl_commit_index < UPL_DEBUG_COMMIT_RECORDS) {
		(void) OSBacktrace(&upl->upl_commit_records[upl->upl_commit_index].c_retaddr[0], UPL_DEBUG_STACK_FRAMES);

		upl->upl_commit_records[upl->upl_commit_index].c_beg = offset;
		upl->upl_commit_records[upl->upl_commit_index].c_end = (offset + size);
		upl->upl_commit_records[upl->upl_commit_index].c_aborted = 1;

		upl->upl_commit_index++;
	}
#endif
	if (upl->flags & UPL_DEVICE_MEMORY) {
		xfer_size = 0;
	} else if ((offset + size) <= upl->size) {
		xfer_size = size;
	} else {
		if (!isVectorUPL) {
			upl_unlock(upl);
		} else {
			upl_unlock(vector_upl);
		}

		return KERN_FAILURE;
	}
	if (upl->flags & UPL_INTERNAL) {
		lite_list = (wpl_array_t)
		    ((((uintptr_t)upl) + sizeof(struct upl))
		    + ((upl->size / PAGE_SIZE) * sizeof(upl_page_info_t)));

		user_page_list = (upl_page_info_t *) (((uintptr_t)upl) + sizeof(struct upl));
	} else {
		lite_list = (wpl_array_t)
		    (((uintptr_t)upl) + sizeof(struct upl));
	}
	object = upl->map_object;

	if (upl->flags & UPL_SHADOWED) {
		vm_object_lock(object);
		shadow_object = object->shadow;
	} else {
		shadow_object = object;
	}

	entry = offset / PAGE_SIZE;
	target_offset = (vm_object_offset_t)offset;

	assert(!(target_offset & PAGE_MASK));
	assert(!(xfer_size & PAGE_MASK));

	if (upl->flags & UPL_KERNEL_OBJECT) {
		vm_object_lock_shared(shadow_object);
	} else {
		vm_object_lock(shadow_object);
	}

	if (upl->flags & UPL_ACCESS_BLOCKED) {
		assert(shadow_object->blocked_access);
		shadow_object->blocked_access = FALSE;
		vm_object_wakeup(object, VM_OBJECT_EVENT_UNBLOCKED);
	}

	dwp = &dw_array[0];
	dw_count = 0;
	dw_limit = DELAYED_WORK_LIMIT(DEFAULT_DELAYED_WORK_LIMIT);

	if ((error & UPL_ABORT_DUMP_PAGES) && (upl->flags & UPL_KERNEL_OBJECT)) {
		panic("upl_abort_range: kernel_object being DUMPED");
	}

	while (xfer_size) {
		vm_page_t       t, m;
		unsigned int    pg_num;
		boolean_t       needed;

		pg_num = (unsigned int) (target_offset / PAGE_SIZE);
		assert(pg_num == target_offset / PAGE_SIZE);

		needed = FALSE;

		if (user_page_list) {
			needed = user_page_list[pg_num].needed;
		}

		dwp->dw_mask = 0;
		m = VM_PAGE_NULL;

		if (upl->flags & UPL_LITE) {
			if (lite_list[pg_num >> 5] & (1U << (pg_num & 31))) {
				lite_list[pg_num >> 5] &= ~(1U << (pg_num & 31));

				if (!(upl->flags & UPL_KERNEL_OBJECT)) {
					m = vm_page_lookup(shadow_object, target_offset +
					    (upl->offset - shadow_object->paging_offset));
				}
			}
		}
		if (upl->flags & UPL_SHADOWED) {
			if ((t = vm_page_lookup(object, target_offset)) != VM_PAGE_NULL) {
				t->vmp_free_when_done = FALSE;

				VM_PAGE_FREE(t);

				if (m == VM_PAGE_NULL) {
					m = vm_page_lookup(shadow_object, target_offset + object->vo_shadow_offset);
				}
			}
		}
		if ((upl->flags & UPL_KERNEL_OBJECT)) {
			goto abort_next_page;
		}

		if (m != VM_PAGE_NULL) {
			assert(m->vmp_q_state != VM_PAGE_USED_BY_COMPRESSOR);

			if (m->vmp_absent) {
				boolean_t must_free = TRUE;

				/*
				 * COPYOUT = FALSE case
				 * check for error conditions which must
				 * be passed back to the pages customer
				 */
				if (error & UPL_ABORT_RESTART) {
					m->vmp_restart = TRUE;
					m->vmp_absent = FALSE;
					m->vmp_unusual = TRUE;
					must_free = FALSE;
				} else if (error & UPL_ABORT_UNAVAILABLE) {
					m->vmp_restart = FALSE;
					m->vmp_unusual = TRUE;
					must_free = FALSE;
				} else if (error & UPL_ABORT_ERROR) {
					m->vmp_restart = FALSE;
					m->vmp_absent = FALSE;
					m->vmp_error = TRUE;
					m->vmp_unusual = TRUE;
					must_free = FALSE;
				}
				if (m->vmp_clustered && needed == FALSE) {
					/*
					 * This page was a part of a speculative
					 * read-ahead initiated by the kernel
					 * itself.  No one is expecting this
					 * page and no one will clean up its
					 * error state if it ever becomes valid
					 * in the future.
					 * We have to free it here.
					 */
					must_free = TRUE;
				}
				m->vmp_cleaning = FALSE;

				if (m->vmp_overwriting && !m->vmp_busy) {
					/*
					 * this shouldn't happen since
					 * this is an 'absent' page, but
					 * it doesn't hurt to check for
					 * the 'alternate' method of
					 * stabilizing the page...
					 * we will mark 'busy' to be cleared
					 * in the following code which will
					 * take care of the primary stabilzation
					 * method (i.e. setting 'busy' to TRUE)
					 */
					dwp->dw_mask |= DW_vm_page_unwire;
				}
				m->vmp_overwriting = FALSE;

				dwp->dw_mask |= (DW_clear_busy | DW_PAGE_WAKEUP);

				if (must_free == TRUE) {
					dwp->dw_mask |= DW_vm_page_free;
				} else {
					dwp->dw_mask |= DW_vm_page_activate;
				}
			} else {
				/*
				 * Handle the trusted pager throttle.
				 */
				if (m->vmp_laundry) {
					dwp->dw_mask |= DW_vm_pageout_throttle_up;
				}

				if (upl->flags & UPL_ACCESS_BLOCKED) {
					/*
					 * We blocked access to the pages in this UPL.
					 * Clear the "busy" bit and wake up any waiter
					 * for this page.
					 */
					dwp->dw_mask |= DW_clear_busy;
				}
				if (m->vmp_overwriting) {
					if (m->vmp_busy) {
						dwp->dw_mask |= DW_clear_busy;
					} else {
						/*
						 * deal with the 'alternate' method
						 * of stabilizing the page...
						 * we will either free the page
						 * or mark 'busy' to be cleared
						 * in the following code which will
						 * take care of the primary stabilzation
						 * method (i.e. setting 'busy' to TRUE)
						 */
						dwp->dw_mask |= DW_vm_page_unwire;
					}
					m->vmp_overwriting = FALSE;
				}
				m->vmp_free_when_done = FALSE;
				m->vmp_cleaning = FALSE;

				if (error & UPL_ABORT_DUMP_PAGES) {
					pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(m));

					dwp->dw_mask |= DW_vm_page_free;
				} else {
					if (!(dwp->dw_mask & DW_vm_page_unwire)) {
						if (error & UPL_ABORT_REFERENCE) {
							/*
							 * we've been told to explictly
							 * reference this page... for
							 * file I/O, this is done by
							 * implementing an LRU on the inactive q
							 */
							dwp->dw_mask |= DW_vm_page_lru;
						} else if (!VM_PAGE_PAGEABLE(m)) {
							dwp->dw_mask |= DW_vm_page_deactivate_internal;
						}
					}
					dwp->dw_mask |= DW_PAGE_WAKEUP;
				}
			}
		}
abort_next_page:
		target_offset += PAGE_SIZE_64;
		xfer_size -= PAGE_SIZE;
		entry++;

		if (dwp->dw_mask) {
			if (dwp->dw_mask & ~(DW_clear_busy | DW_PAGE_WAKEUP)) {
				VM_PAGE_ADD_DELAYED_WORK(dwp, m, dw_count);

				if (dw_count >= dw_limit) {
					vm_page_do_delayed_work(shadow_object, VM_KERN_MEMORY_NONE, &dw_array[0], dw_count);

					dwp = &dw_array[0];
					dw_count = 0;
				}
			} else {
				if (dwp->dw_mask & DW_clear_busy) {
					m->vmp_busy = FALSE;
				}

				if (dwp->dw_mask & DW_PAGE_WAKEUP) {
					PAGE_WAKEUP(m);
				}
			}
		}
	}
	if (dw_count) {
		vm_page_do_delayed_work(shadow_object, VM_KERN_MEMORY_NONE, &dw_array[0], dw_count);
	}

	occupied = 1;

	if (upl->flags & UPL_DEVICE_MEMORY) {
		occupied = 0;
	} else if (upl->flags & UPL_LITE) {
		int     pg_num;
		int     i;

		pg_num = upl->size / PAGE_SIZE;
		pg_num = (pg_num + 31) >> 5;
		occupied = 0;

		for (i = 0; i < pg_num; i++) {
			if (lite_list[i] != 0) {
				occupied = 1;
				break;
			}
		}
	} else {
		if (vm_page_queue_empty(&upl->map_object->memq)) {
			occupied = 0;
		}
	}
	if (occupied == 0) {
		/*
		 * If this UPL element belongs to a Vector UPL and is
		 * empty, then this is the right function to deallocate
		 * it. So go ahead set the *empty variable. The flag
		 * UPL_COMMIT_NOTIFY_EMPTY, from the caller's point of view
		 * should be considered relevant for the Vector UPL and
		 * not the internal UPLs.
		 */
		if ((upl->flags & UPL_COMMIT_NOTIFY_EMPTY) || isVectorUPL) {
			*empty = TRUE;
		}

		if (object == shadow_object && !(upl->flags & UPL_KERNEL_OBJECT)) {
			/*
			 * this is not a paging object
			 * so we need to drop the paging reference
			 * that was taken when we created the UPL
			 * against this object
			 */
			vm_object_activity_end(shadow_object);
			vm_object_collapse(shadow_object, 0, TRUE);
		} else {
			/*
			 * we dontated the paging reference to
			 * the map object... vm_pageout_object_terminate
			 * will drop this reference
			 */
		}
	}
	vm_object_unlock(shadow_object);
	if (object != shadow_object) {
		vm_object_unlock(object);
	}

	if (!isVectorUPL) {
		upl_unlock(upl);
	} else {
		/*
		 * If we completed our operations on an UPL that is
		 * part of a Vectored UPL and if empty is TRUE, then
		 * we should go ahead and deallocate this UPL element.
		 * Then we check if this was the last of the UPL elements
		 * within that Vectored UPL. If so, set empty to TRUE
		 * so that in ubc_upl_abort_range or ubc_upl_abort, we
		 * can go ahead and deallocate the Vector UPL too.
		 */
		if (*empty == TRUE) {
			*empty = vector_upl_set_subupl(vector_upl, upl, 0);
			upl_deallocate(upl);
		}
		goto process_upl_to_abort;
	}

	return KERN_SUCCESS;
}


kern_return_t
upl_abort(
	upl_t   upl,
	int     error)
{
	boolean_t       empty;

	if (upl == UPL_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	return upl_abort_range(upl, 0, upl->size, error, &empty);
}


/* an option on commit should be wire */
kern_return_t
upl_commit(
	upl_t                   upl,
	upl_page_info_t         *page_list,
	mach_msg_type_number_t  count)
{
	boolean_t       empty;

	if (upl == UPL_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	return upl_commit_range(upl, 0, upl->size, 0, page_list, count, &empty);
}


void
iopl_valid_data(
	upl_t    upl,
	vm_tag_t tag)
{
	vm_object_t     object;
	vm_offset_t     offset;
	vm_page_t       m, nxt_page = VM_PAGE_NULL;
	upl_size_t      size;
	int             wired_count = 0;

	if (upl == NULL) {
		panic("iopl_valid_data: NULL upl");
	}
	if (vector_upl_is_valid(upl)) {
		panic("iopl_valid_data: vector upl");
	}
	if ((upl->flags & (UPL_DEVICE_MEMORY | UPL_SHADOWED | UPL_ACCESS_BLOCKED | UPL_IO_WIRE | UPL_INTERNAL)) != UPL_IO_WIRE) {
		panic("iopl_valid_data: unsupported upl, flags = %x", upl->flags);
	}

	object = upl->map_object;

	if (object == kernel_object || object == compressor_object) {
		panic("iopl_valid_data: object == kernel or compressor");
	}

	if (object->purgable == VM_PURGABLE_VOLATILE ||
	    object->purgable == VM_PURGABLE_EMPTY) {
		panic("iopl_valid_data: object %p purgable %d",
		    object, object->purgable);
	}

	size = upl->size;

	vm_object_lock(object);
	VM_OBJECT_WIRED_PAGE_UPDATE_START(object);

	if (object->vo_size == size && object->resident_page_count == (size / PAGE_SIZE)) {
		nxt_page = (vm_page_t)vm_page_queue_first(&object->memq);
	} else {
		offset = 0 + upl->offset - object->paging_offset;
	}

	while (size) {
		if (nxt_page != VM_PAGE_NULL) {
			m = nxt_page;
			nxt_page = (vm_page_t)vm_page_queue_next(&nxt_page->vmp_listq);
		} else {
			m = vm_page_lookup(object, offset);
			offset += PAGE_SIZE;

			if (m == VM_PAGE_NULL) {
				panic("iopl_valid_data: missing expected page at offset %lx", (long)offset);
			}
		}
		if (m->vmp_busy) {
			if (!m->vmp_absent) {
				panic("iopl_valid_data: busy page w/o absent");
			}

			if (m->vmp_pageq.next || m->vmp_pageq.prev) {
				panic("iopl_valid_data: busy+absent page on page queue");
			}
			if (m->vmp_reusable) {
				panic("iopl_valid_data: %p is reusable", m);
			}

			m->vmp_absent = FALSE;
			m->vmp_dirty = TRUE;
			assert(m->vmp_q_state == VM_PAGE_NOT_ON_Q);
			assert(m->vmp_wire_count == 0);
			m->vmp_wire_count++;
			assert(m->vmp_wire_count);
			if (m->vmp_wire_count == 1) {
				m->vmp_q_state = VM_PAGE_IS_WIRED;
				wired_count++;
			} else {
				panic("iopl_valid_data: %p already wired\n", m);
			}

			PAGE_WAKEUP_DONE(m);
		}
		size -= PAGE_SIZE;
	}
	if (wired_count) {
		VM_OBJECT_WIRED_PAGE_COUNT(object, wired_count);
		assert(object->resident_page_count >= object->wired_page_count);

		/* no need to adjust purgeable accounting for this object: */
		assert(object->purgable != VM_PURGABLE_VOLATILE);
		assert(object->purgable != VM_PURGABLE_EMPTY);

		vm_page_lockspin_queues();
		vm_page_wire_count += wired_count;
		vm_page_unlock_queues();
	}
	VM_OBJECT_WIRED_PAGE_UPDATE_END(object, tag);
	vm_object_unlock(object);
}


void
vm_object_set_pmap_cache_attr(
	vm_object_t             object,
	upl_page_info_array_t   user_page_list,
	unsigned int            num_pages,
	boolean_t               batch_pmap_op)
{
	unsigned int    cache_attr = 0;

	cache_attr = object->wimg_bits & VM_WIMG_MASK;
	assert(user_page_list);
	if (cache_attr != VM_WIMG_USE_DEFAULT) {
		PMAP_BATCH_SET_CACHE_ATTR(object, user_page_list, cache_attr, num_pages, batch_pmap_op);
	}
}


boolean_t       vm_object_iopl_wire_full(vm_object_t, upl_t, upl_page_info_array_t, wpl_array_t, upl_control_flags_t, vm_tag_t);
kern_return_t   vm_object_iopl_wire_empty(vm_object_t, upl_t, upl_page_info_array_t, wpl_array_t, upl_control_flags_t, vm_tag_t, vm_object_offset_t *, int, int*);



boolean_t
vm_object_iopl_wire_full(vm_object_t object, upl_t upl, upl_page_info_array_t user_page_list,
    wpl_array_t lite_list, upl_control_flags_t cntrl_flags, vm_tag_t tag)
{
	vm_page_t       dst_page;
	unsigned int    entry;
	int             page_count;
	int             delayed_unlock = 0;
	boolean_t       retval = TRUE;
	ppnum_t         phys_page;

	vm_object_lock_assert_exclusive(object);
	assert(object->purgable != VM_PURGABLE_VOLATILE);
	assert(object->purgable != VM_PURGABLE_EMPTY);
	assert(object->pager == NULL);
	assert(object->copy == NULL);
	assert(object->shadow == NULL);

	page_count = object->resident_page_count;
	dst_page = (vm_page_t)vm_page_queue_first(&object->memq);

	vm_page_lock_queues();

	while (page_count--) {
		if (dst_page->vmp_busy ||
		    dst_page->vmp_fictitious ||
		    dst_page->vmp_absent ||
		    dst_page->vmp_error ||
		    dst_page->vmp_cleaning ||
		    dst_page->vmp_restart ||
		    dst_page->vmp_laundry) {
			retval = FALSE;
			goto done;
		}
		if ((cntrl_flags & UPL_REQUEST_FORCE_COHERENCY) && dst_page->vmp_written_by_kernel == TRUE) {
			retval = FALSE;
			goto done;
		}
		dst_page->vmp_reference = TRUE;

		vm_page_wire(dst_page, tag, FALSE);

		if (!(cntrl_flags & UPL_COPYOUT_FROM)) {
			SET_PAGE_DIRTY(dst_page, FALSE);
		}
		entry = (unsigned int)(dst_page->vmp_offset / PAGE_SIZE);
		assert(entry >= 0 && entry < object->resident_page_count);
		lite_list[entry >> 5] |= 1U << (entry & 31);

		phys_page = VM_PAGE_GET_PHYS_PAGE(dst_page);

		if (phys_page > upl->highest_page) {
			upl->highest_page = phys_page;
		}

		if (user_page_list) {
			user_page_list[entry].phys_addr = phys_page;
			user_page_list[entry].absent    = dst_page->vmp_absent;
			user_page_list[entry].dirty     = dst_page->vmp_dirty;
			user_page_list[entry].free_when_done   = dst_page->vmp_free_when_done;
			user_page_list[entry].precious  = dst_page->vmp_precious;
			user_page_list[entry].device    = FALSE;
			user_page_list[entry].speculative = FALSE;
			user_page_list[entry].cs_validated = FALSE;
			user_page_list[entry].cs_tainted = FALSE;
			user_page_list[entry].cs_nx     = FALSE;
			user_page_list[entry].needed    = FALSE;
			user_page_list[entry].mark      = FALSE;
		}
		if (delayed_unlock++ > 256) {
			delayed_unlock = 0;
			lck_mtx_yield(&vm_page_queue_lock);

			VM_CHECK_MEMORYSTATUS;
		}
		dst_page = (vm_page_t)vm_page_queue_next(&dst_page->vmp_listq);
	}
done:
	vm_page_unlock_queues();

	VM_CHECK_MEMORYSTATUS;

	return retval;
}


kern_return_t
vm_object_iopl_wire_empty(vm_object_t object, upl_t upl, upl_page_info_array_t user_page_list,
    wpl_array_t lite_list, upl_control_flags_t cntrl_flags, vm_tag_t tag, vm_object_offset_t *dst_offset,
    int page_count, int* page_grab_count)
{
	vm_page_t       dst_page;
	boolean_t       no_zero_fill = FALSE;
	int             interruptible;
	int             pages_wired = 0;
	int             pages_inserted = 0;
	int             entry = 0;
	uint64_t        delayed_ledger_update = 0;
	kern_return_t   ret = KERN_SUCCESS;
	int             grab_options;
	ppnum_t         phys_page;

	vm_object_lock_assert_exclusive(object);
	assert(object->purgable != VM_PURGABLE_VOLATILE);
	assert(object->purgable != VM_PURGABLE_EMPTY);
	assert(object->pager == NULL);
	assert(object->copy == NULL);
	assert(object->shadow == NULL);

	if (cntrl_flags & UPL_SET_INTERRUPTIBLE) {
		interruptible = THREAD_ABORTSAFE;
	} else {
		interruptible = THREAD_UNINT;
	}

	if (cntrl_flags & (UPL_NOZEROFILL | UPL_NOZEROFILLIO)) {
		no_zero_fill = TRUE;
	}

	grab_options = 0;
#if CONFIG_SECLUDED_MEMORY
	if (object->can_grab_secluded) {
		grab_options |= VM_PAGE_GRAB_SECLUDED;
	}
#endif /* CONFIG_SECLUDED_MEMORY */

	while (page_count--) {
		while ((dst_page = vm_page_grab_options(grab_options))
		    == VM_PAGE_NULL) {
			OSAddAtomic(page_count, &vm_upl_wait_for_pages);

			VM_DEBUG_EVENT(vm_iopl_page_wait, VM_IOPL_PAGE_WAIT, DBG_FUNC_START, vm_upl_wait_for_pages, 0, 0, 0);

			if (vm_page_wait(interruptible) == FALSE) {
				/*
				 * interrupted case
				 */
				OSAddAtomic(-page_count, &vm_upl_wait_for_pages);

				VM_DEBUG_EVENT(vm_iopl_page_wait, VM_IOPL_PAGE_WAIT, DBG_FUNC_END, vm_upl_wait_for_pages, 0, 0, -1);

				ret = MACH_SEND_INTERRUPTED;
				goto done;
			}
			OSAddAtomic(-page_count, &vm_upl_wait_for_pages);

			VM_DEBUG_EVENT(vm_iopl_page_wait, VM_IOPL_PAGE_WAIT, DBG_FUNC_END, vm_upl_wait_for_pages, 0, 0, 0);
		}
		if (no_zero_fill == FALSE) {
			vm_page_zero_fill(dst_page);
		} else {
			dst_page->vmp_absent = TRUE;
		}

		dst_page->vmp_reference = TRUE;

		if (!(cntrl_flags & UPL_COPYOUT_FROM)) {
			SET_PAGE_DIRTY(dst_page, FALSE);
		}
		if (dst_page->vmp_absent == FALSE) {
			assert(dst_page->vmp_q_state == VM_PAGE_NOT_ON_Q);
			assert(dst_page->vmp_wire_count == 0);
			dst_page->vmp_wire_count++;
			dst_page->vmp_q_state = VM_PAGE_IS_WIRED;
			assert(dst_page->vmp_wire_count);
			pages_wired++;
			PAGE_WAKEUP_DONE(dst_page);
		}
		pages_inserted++;

		vm_page_insert_internal(dst_page, object, *dst_offset, tag, FALSE, TRUE, TRUE, TRUE, &delayed_ledger_update);

		lite_list[entry >> 5] |= 1U << (entry & 31);

		phys_page = VM_PAGE_GET_PHYS_PAGE(dst_page);

		if (phys_page > upl->highest_page) {
			upl->highest_page = phys_page;
		}

		if (user_page_list) {
			user_page_list[entry].phys_addr = phys_page;
			user_page_list[entry].absent    = dst_page->vmp_absent;
			user_page_list[entry].dirty     = dst_page->vmp_dirty;
			user_page_list[entry].free_when_done    = FALSE;
			user_page_list[entry].precious  = FALSE;
			user_page_list[entry].device    = FALSE;
			user_page_list[entry].speculative = FALSE;
			user_page_list[entry].cs_validated = FALSE;
			user_page_list[entry].cs_tainted = FALSE;
			user_page_list[entry].cs_nx     = FALSE;
			user_page_list[entry].needed    = FALSE;
			user_page_list[entry].mark      = FALSE;
		}
		entry++;
		*dst_offset += PAGE_SIZE_64;
	}
done:
	if (pages_wired) {
		vm_page_lockspin_queues();
		vm_page_wire_count += pages_wired;
		vm_page_unlock_queues();
	}
	if (pages_inserted) {
		if (object->internal) {
			OSAddAtomic(pages_inserted, &vm_page_internal_count);
		} else {
			OSAddAtomic(pages_inserted, &vm_page_external_count);
		}
	}
	if (delayed_ledger_update) {
		task_t          owner;
		int             ledger_idx_volatile;
		int             ledger_idx_nonvolatile;
		int             ledger_idx_volatile_compressed;
		int             ledger_idx_nonvolatile_compressed;
		boolean_t       do_footprint;

		owner = VM_OBJECT_OWNER(object);
		assert(owner);

		vm_object_ledger_tag_ledgers(object,
		    &ledger_idx_volatile,
		    &ledger_idx_nonvolatile,
		    &ledger_idx_volatile_compressed,
		    &ledger_idx_nonvolatile_compressed,
		    &do_footprint);

		/* more non-volatile bytes */
		ledger_credit(owner->ledger,
		    ledger_idx_nonvolatile,
		    delayed_ledger_update);
		if (do_footprint) {
			/* more footprint */
			ledger_credit(owner->ledger,
			    task_ledgers.phys_footprint,
			    delayed_ledger_update);
		}
	}

	assert(page_grab_count);
	*page_grab_count = pages_inserted;

	return ret;
}



kern_return_t
vm_object_iopl_request(
	vm_object_t             object,
	vm_object_offset_t      offset,
	upl_size_t              size,
	upl_t                   *upl_ptr,
	upl_page_info_array_t   user_page_list,
	unsigned int            *page_list_count,
	upl_control_flags_t     cntrl_flags,
	vm_tag_t                tag)
{
	vm_page_t               dst_page;
	vm_object_offset_t      dst_offset;
	upl_size_t              xfer_size;
	upl_t                   upl = NULL;
	unsigned int            entry;
	wpl_array_t             lite_list = NULL;
	int                     no_zero_fill = FALSE;
	unsigned int            size_in_pages;
	int                     page_grab_count = 0;
	u_int32_t               psize;
	kern_return_t           ret;
	vm_prot_t               prot;
	struct vm_object_fault_info fault_info = {};
	struct  vm_page_delayed_work    dw_array[DEFAULT_DELAYED_WORK_LIMIT];
	struct  vm_page_delayed_work    *dwp;
	int                     dw_count;
	int                     dw_limit;
	int                     dw_index;
	boolean_t               caller_lookup;
	int                     io_tracking_flag = 0;
	int                     interruptible;
	ppnum_t                 phys_page;

	boolean_t               set_cache_attr_needed = FALSE;
	boolean_t               free_wired_pages = FALSE;
	boolean_t               fast_path_empty_req = FALSE;
	boolean_t               fast_path_full_req = FALSE;

#if DEVELOPMENT || DEBUG
	task_t                  task = current_task();
#endif /* DEVELOPMENT || DEBUG */

	if (cntrl_flags & ~UPL_VALID_FLAGS) {
		/*
		 * For forward compatibility's sake,
		 * reject any unknown flag.
		 */
		return KERN_INVALID_VALUE;
	}
	if (vm_lopage_needed == FALSE) {
		cntrl_flags &= ~UPL_NEED_32BIT_ADDR;
	}

	if (cntrl_flags & UPL_NEED_32BIT_ADDR) {
		if ((cntrl_flags & (UPL_SET_IO_WIRE | UPL_SET_LITE)) != (UPL_SET_IO_WIRE | UPL_SET_LITE)) {
			return KERN_INVALID_VALUE;
		}

		if (object->phys_contiguous) {
			if ((offset + object->vo_shadow_offset) >= (vm_object_offset_t)max_valid_dma_address) {
				return KERN_INVALID_ADDRESS;
			}

			if (((offset + object->vo_shadow_offset) + size) >= (vm_object_offset_t)max_valid_dma_address) {
				return KERN_INVALID_ADDRESS;
			}
		}
	}
	if (cntrl_flags & (UPL_NOZEROFILL | UPL_NOZEROFILLIO)) {
		no_zero_fill = TRUE;
	}

	if (cntrl_flags & UPL_COPYOUT_FROM) {
		prot = VM_PROT_READ;
	} else {
		prot = VM_PROT_READ | VM_PROT_WRITE;
	}

	if ((!object->internal) && (object->paging_offset != 0)) {
		panic("vm_object_iopl_request: external object with non-zero paging offset\n");
	}

	VM_DEBUG_CONSTANT_EVENT(vm_object_iopl_request, VM_IOPL_REQUEST, DBG_FUNC_START, size, cntrl_flags, prot, 0);

#if CONFIG_IOSCHED || UPL_DEBUG
	if ((object->io_tracking && object != kernel_object) || upl_debug_enabled) {
		io_tracking_flag |= UPL_CREATE_IO_TRACKING;
	}
#endif

#if CONFIG_IOSCHED
	if (object->io_tracking) {
		/* Check if we're dealing with the kernel object. We do not support expedite on kernel object UPLs */
		if (object != kernel_object) {
			io_tracking_flag |= UPL_CREATE_EXPEDITE_SUP;
		}
	}
#endif

	if (object->phys_contiguous) {
		psize = PAGE_SIZE;
	} else {
		psize = size;
	}

	if (cntrl_flags & UPL_SET_INTERNAL) {
		upl = upl_create(UPL_CREATE_INTERNAL | UPL_CREATE_LITE | io_tracking_flag, UPL_IO_WIRE, psize);

		user_page_list = (upl_page_info_t *) (((uintptr_t)upl) + sizeof(struct upl));
		lite_list = (wpl_array_t) (((uintptr_t)user_page_list) +
		    ((psize / PAGE_SIZE) * sizeof(upl_page_info_t)));
		if (size == 0) {
			user_page_list = NULL;
			lite_list = NULL;
		}
	} else {
		upl = upl_create(UPL_CREATE_LITE | io_tracking_flag, UPL_IO_WIRE, psize);

		lite_list = (wpl_array_t) (((uintptr_t)upl) + sizeof(struct upl));
		if (size == 0) {
			lite_list = NULL;
		}
	}
	if (user_page_list) {
		user_page_list[0].device = FALSE;
	}
	*upl_ptr = upl;

	if (cntrl_flags & UPL_NOZEROFILLIO) {
		DTRACE_VM4(upl_nozerofillio,
		    vm_object_t, object,
		    vm_object_offset_t, offset,
		    upl_size_t, size,
		    upl_t, upl);
	}

	upl->map_object = object;
	upl->size = size;

	size_in_pages = size / PAGE_SIZE;

	if (object == kernel_object &&
	    !(cntrl_flags & (UPL_NEED_32BIT_ADDR | UPL_BLOCK_ACCESS))) {
		upl->flags |= UPL_KERNEL_OBJECT;
#if UPL_DEBUG
		vm_object_lock(object);
#else
		vm_object_lock_shared(object);
#endif
	} else {
		vm_object_lock(object);
		vm_object_activity_begin(object);
	}
	/*
	 * paging in progress also protects the paging_offset
	 */
	upl->offset = offset + object->paging_offset;

	if (cntrl_flags & UPL_BLOCK_ACCESS) {
		/*
		 * The user requested that access to the pages in this UPL
		 * be blocked until the UPL is commited or aborted.
		 */
		upl->flags |= UPL_ACCESS_BLOCKED;
	}

#if CONFIG_IOSCHED || UPL_DEBUG
	if (upl->flags & UPL_TRACKED_BY_OBJECT) {
		vm_object_activity_begin(object);
		queue_enter(&object->uplq, upl, upl_t, uplq);
	}
#endif

	if (object->phys_contiguous) {
		if (upl->flags & UPL_ACCESS_BLOCKED) {
			assert(!object->blocked_access);
			object->blocked_access = TRUE;
		}

		vm_object_unlock(object);

		/*
		 * don't need any shadow mappings for this one
		 * since it is already I/O memory
		 */
		upl->flags |= UPL_DEVICE_MEMORY;

		upl->highest_page = (ppnum_t) ((offset + object->vo_shadow_offset + size - 1) >> PAGE_SHIFT);

		if (user_page_list) {
			user_page_list[0].phys_addr = (ppnum_t) ((offset + object->vo_shadow_offset) >> PAGE_SHIFT);
			user_page_list[0].device = TRUE;
		}
		if (page_list_count != NULL) {
			if (upl->flags & UPL_INTERNAL) {
				*page_list_count = 0;
			} else {
				*page_list_count = 1;
			}
		}

		VM_DEBUG_CONSTANT_EVENT(vm_object_iopl_request, VM_IOPL_REQUEST, DBG_FUNC_END, page_grab_count, KERN_SUCCESS, 0, 0);
#if DEVELOPMENT || DEBUG
		if (task != NULL) {
			ledger_credit(task->ledger, task_ledgers.pages_grabbed_iopl, page_grab_count);
		}
#endif /* DEVELOPMENT || DEBUG */
		return KERN_SUCCESS;
	}
	if (object != kernel_object && object != compressor_object) {
		/*
		 * Protect user space from future COW operations
		 */
#if VM_OBJECT_TRACKING_OP_TRUESHARE
		if (!object->true_share &&
		    vm_object_tracking_inited) {
			void *bt[VM_OBJECT_TRACKING_BTDEPTH];
			int num = 0;

			num = OSBacktrace(bt,
			    VM_OBJECT_TRACKING_BTDEPTH);
			btlog_add_entry(vm_object_tracking_btlog,
			    object,
			    VM_OBJECT_TRACKING_OP_TRUESHARE,
			    bt,
			    num);
		}
#endif /* VM_OBJECT_TRACKING_OP_TRUESHARE */

		vm_object_lock_assert_exclusive(object);
		object->true_share = TRUE;

		if (object->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC) {
			object->copy_strategy = MEMORY_OBJECT_COPY_DELAY;
		}
	}

	if (!(cntrl_flags & UPL_COPYOUT_FROM) &&
	    object->copy != VM_OBJECT_NULL) {
		/*
		 * Honor copy-on-write obligations
		 *
		 * The caller is gathering these pages and
		 * might modify their contents.  We need to
		 * make sure that the copy object has its own
		 * private copies of these pages before we let
		 * the caller modify them.
		 *
		 * NOTE: someone else could map the original object
		 * after we've done this copy-on-write here, and they
		 * could then see an inconsistent picture of the memory
		 * while it's being modified via the UPL.  To prevent this,
		 * we would have to block access to these pages until the
		 * UPL is released.  We could use the UPL_BLOCK_ACCESS
		 * code path for that...
		 */
		vm_object_update(object,
		    offset,
		    size,
		    NULL,
		    NULL,
		    FALSE,              /* should_return */
		    MEMORY_OBJECT_COPY_SYNC,
		    VM_PROT_NO_CHANGE);
		VM_PAGEOUT_DEBUG(iopl_cow, 1);
		VM_PAGEOUT_DEBUG(iopl_cow_pages, (size >> PAGE_SHIFT));
	}
	if (!(cntrl_flags & (UPL_NEED_32BIT_ADDR | UPL_BLOCK_ACCESS)) &&
	    object->purgable != VM_PURGABLE_VOLATILE &&
	    object->purgable != VM_PURGABLE_EMPTY &&
	    object->copy == NULL &&
	    size == object->vo_size &&
	    offset == 0 &&
	    object->shadow == NULL &&
	    object->pager == NULL) {
		if (object->resident_page_count == size_in_pages) {
			assert(object != compressor_object);
			assert(object != kernel_object);
			fast_path_full_req = TRUE;
		} else if (object->resident_page_count == 0) {
			assert(object != compressor_object);
			assert(object != kernel_object);
			fast_path_empty_req = TRUE;
			set_cache_attr_needed = TRUE;
		}
	}

	if (cntrl_flags & UPL_SET_INTERRUPTIBLE) {
		interruptible = THREAD_ABORTSAFE;
	} else {
		interruptible = THREAD_UNINT;
	}

	entry = 0;

	xfer_size = size;
	dst_offset = offset;
	dw_count = 0;

	if (fast_path_full_req) {
		if (vm_object_iopl_wire_full(object, upl, user_page_list, lite_list, cntrl_flags, tag) == TRUE) {
			goto finish;
		}
		/*
		 * we couldn't complete the processing of this request on the fast path
		 * so fall through to the slow path and finish up
		 */
	} else if (fast_path_empty_req) {
		if (cntrl_flags & UPL_REQUEST_NO_FAULT) {
			ret = KERN_MEMORY_ERROR;
			goto return_err;
		}
		ret = vm_object_iopl_wire_empty(object, upl, user_page_list, lite_list, cntrl_flags, tag, &dst_offset, size_in_pages, &page_grab_count);

		if (ret) {
			free_wired_pages = TRUE;
			goto return_err;
		}
		goto finish;
	}

	fault_info.behavior = VM_BEHAVIOR_SEQUENTIAL;
	fault_info.lo_offset = offset;
	fault_info.hi_offset = offset + xfer_size;
	fault_info.mark_zf_absent = TRUE;
	fault_info.interruptible = interruptible;
	fault_info.batch_pmap_op = TRUE;

	dwp = &dw_array[0];
	dw_limit = DELAYED_WORK_LIMIT(DEFAULT_DELAYED_WORK_LIMIT);

	while (xfer_size) {
		vm_fault_return_t       result;

		dwp->dw_mask = 0;

		if (fast_path_full_req) {
			/*
			 * if we get here, it means that we ran into a page
			 * state we couldn't handle in the fast path and
			 * bailed out to the slow path... since the order
			 * we look at pages is different between the 2 paths,
			 * the following check is needed to determine whether
			 * this page was already processed in the fast path
			 */
			if (lite_list[entry >> 5] & (1 << (entry & 31))) {
				goto skip_page;
			}
		}
		dst_page = vm_page_lookup(object, dst_offset);

		if (dst_page == VM_PAGE_NULL ||
		    dst_page->vmp_busy ||
		    dst_page->vmp_error ||
		    dst_page->vmp_restart ||
		    dst_page->vmp_absent ||
		    dst_page->vmp_fictitious) {
			if (object == kernel_object) {
				panic("vm_object_iopl_request: missing/bad page in kernel object\n");
			}
			if (object == compressor_object) {
				panic("vm_object_iopl_request: missing/bad page in compressor object\n");
			}

			if (cntrl_flags & UPL_REQUEST_NO_FAULT) {
				ret = KERN_MEMORY_ERROR;
				goto return_err;
			}
			set_cache_attr_needed = TRUE;

			/*
			 * We just looked up the page and the result remains valid
			 * until the object lock is release, so send it to
			 * vm_fault_page() (as "dst_page"), to avoid having to
			 * look it up again there.
			 */
			caller_lookup = TRUE;

			do {
				vm_page_t       top_page;
				kern_return_t   error_code;

				fault_info.cluster_size = xfer_size;

				vm_object_paging_begin(object);

				result = vm_fault_page(object, dst_offset,
				    prot | VM_PROT_WRITE, FALSE,
				    caller_lookup,
				    &prot, &dst_page, &top_page,
				    (int *)0,
				    &error_code, no_zero_fill,
				    FALSE, &fault_info);

				/* our lookup is no longer valid at this point */
				caller_lookup = FALSE;

				switch (result) {
				case VM_FAULT_SUCCESS:
					page_grab_count++;

					if (!dst_page->vmp_absent) {
						PAGE_WAKEUP_DONE(dst_page);
					} else {
						/*
						 * we only get back an absent page if we
						 * requested that it not be zero-filled
						 * because we are about to fill it via I/O
						 *
						 * absent pages should be left BUSY
						 * to prevent them from being faulted
						 * into an address space before we've
						 * had a chance to complete the I/O on
						 * them since they may contain info that
						 * shouldn't be seen by the faulting task
						 */
					}
					/*
					 *	Release paging references and
					 *	top-level placeholder page, if any.
					 */
					if (top_page != VM_PAGE_NULL) {
						vm_object_t local_object;

						local_object = VM_PAGE_OBJECT(top_page);

						/*
						 * comparing 2 packed pointers
						 */
						if (top_page->vmp_object != dst_page->vmp_object) {
							vm_object_lock(local_object);
							VM_PAGE_FREE(top_page);
							vm_object_paging_end(local_object);
							vm_object_unlock(local_object);
						} else {
							VM_PAGE_FREE(top_page);
							vm_object_paging_end(local_object);
						}
					}
					vm_object_paging_end(object);
					break;

				case VM_FAULT_RETRY:
					vm_object_lock(object);
					break;

				case VM_FAULT_MEMORY_SHORTAGE:
					OSAddAtomic((size_in_pages - entry), &vm_upl_wait_for_pages);

					VM_DEBUG_EVENT(vm_iopl_page_wait, VM_IOPL_PAGE_WAIT, DBG_FUNC_START, vm_upl_wait_for_pages, 0, 0, 0);

					if (vm_page_wait(interruptible)) {
						OSAddAtomic(-(size_in_pages - entry), &vm_upl_wait_for_pages);

						VM_DEBUG_EVENT(vm_iopl_page_wait, VM_IOPL_PAGE_WAIT, DBG_FUNC_END, vm_upl_wait_for_pages, 0, 0, 0);
						vm_object_lock(object);

						break;
					}
					OSAddAtomic(-(size_in_pages - entry), &vm_upl_wait_for_pages);

					VM_DEBUG_EVENT(vm_iopl_page_wait, VM_IOPL_PAGE_WAIT, DBG_FUNC_END, vm_upl_wait_for_pages, 0, 0, -1);

				/* fall thru */

				case VM_FAULT_INTERRUPTED:
					error_code = MACH_SEND_INTERRUPTED;
				case VM_FAULT_MEMORY_ERROR:
memory_error:
					ret = (error_code ? error_code: KERN_MEMORY_ERROR);

					vm_object_lock(object);
					goto return_err;

				case VM_FAULT_SUCCESS_NO_VM_PAGE:
					/* success but no page: fail */
					vm_object_paging_end(object);
					vm_object_unlock(object);
					goto memory_error;

				default:
					panic("vm_object_iopl_request: unexpected error"
					    " 0x%x from vm_fault_page()\n", result);
				}
			} while (result != VM_FAULT_SUCCESS);
		}
		phys_page = VM_PAGE_GET_PHYS_PAGE(dst_page);

		if (upl->flags & UPL_KERNEL_OBJECT) {
			goto record_phys_addr;
		}

		if (dst_page->vmp_q_state == VM_PAGE_USED_BY_COMPRESSOR) {
			dst_page->vmp_busy = TRUE;
			goto record_phys_addr;
		}

		if (dst_page->vmp_cleaning) {
			/*
			 * Someone else is cleaning this page in place.
			 * In theory, we should be able to  proceed and use this
			 * page but they'll probably end up clearing the "busy"
			 * bit on it in upl_commit_range() but they didn't set
			 * it, so they would clear our "busy" bit and open
			 * us to race conditions.
			 * We'd better wait for the cleaning to complete and
			 * then try again.
			 */
			VM_PAGEOUT_DEBUG(vm_object_iopl_request_sleep_for_cleaning, 1);
			PAGE_SLEEP(object, dst_page, THREAD_UNINT);
			continue;
		}
		if (dst_page->vmp_laundry) {
			vm_pageout_steal_laundry(dst_page, FALSE);
		}

		if ((cntrl_flags & UPL_NEED_32BIT_ADDR) &&
		    phys_page >= (max_valid_dma_address >> PAGE_SHIFT)) {
			vm_page_t       low_page;
			int             refmod;

			/*
			 * support devices that can't DMA above 32 bits
			 * by substituting pages from a pool of low address
			 * memory for any pages we find above the 4G mark
			 * can't substitute if the page is already wired because
			 * we don't know whether that physical address has been
			 * handed out to some other 64 bit capable DMA device to use
			 */
			if (VM_PAGE_WIRED(dst_page)) {
				ret = KERN_PROTECTION_FAILURE;
				goto return_err;
			}
			low_page = vm_page_grablo();

			if (low_page == VM_PAGE_NULL) {
				ret = KERN_RESOURCE_SHORTAGE;
				goto return_err;
			}
			/*
			 * from here until the vm_page_replace completes
			 * we musn't drop the object lock... we don't
			 * want anyone refaulting this page in and using
			 * it after we disconnect it... we want the fault
			 * to find the new page being substituted.
			 */
			if (dst_page->vmp_pmapped) {
				refmod = pmap_disconnect(phys_page);
			} else {
				refmod = 0;
			}

			if (!dst_page->vmp_absent) {
				vm_page_copy(dst_page, low_page);
			}

			low_page->vmp_reference = dst_page->vmp_reference;
			low_page->vmp_dirty     = dst_page->vmp_dirty;
			low_page->vmp_absent    = dst_page->vmp_absent;

			if (refmod & VM_MEM_REFERENCED) {
				low_page->vmp_reference = TRUE;
			}
			if (refmod & VM_MEM_MODIFIED) {
				SET_PAGE_DIRTY(low_page, FALSE);
			}

			vm_page_replace(low_page, object, dst_offset);

			dst_page = low_page;
			/*
			 * vm_page_grablo returned the page marked
			 * BUSY... we don't need a PAGE_WAKEUP_DONE
			 * here, because we've never dropped the object lock
			 */
			if (!dst_page->vmp_absent) {
				dst_page->vmp_busy = FALSE;
			}

			phys_page = VM_PAGE_GET_PHYS_PAGE(dst_page);
		}
		if (!dst_page->vmp_busy) {
			dwp->dw_mask |= DW_vm_page_wire;
		}

		if (cntrl_flags & UPL_BLOCK_ACCESS) {
			/*
			 * Mark the page "busy" to block any future page fault
			 * on this page in addition to wiring it.
			 * We'll also remove the mapping
			 * of all these pages before leaving this routine.
			 */
			assert(!dst_page->vmp_fictitious);
			dst_page->vmp_busy = TRUE;
		}
		/*
		 * expect the page to be used
		 * page queues lock must be held to set 'reference'
		 */
		dwp->dw_mask |= DW_set_reference;

		if (!(cntrl_flags & UPL_COPYOUT_FROM)) {
			SET_PAGE_DIRTY(dst_page, TRUE);
			/*
			 * Page belonging to a code-signed object is about to
			 * be written. Mark it tainted and disconnect it from
			 * all pmaps so processes have to fault it back in and
			 * deal with the tainted bit.
			 */
			if (object->code_signed && dst_page->vmp_cs_tainted == FALSE) {
				dst_page->vmp_cs_tainted = TRUE;
				vm_page_iopl_tainted++;
				if (dst_page->vmp_pmapped) {
					int refmod = pmap_disconnect(VM_PAGE_GET_PHYS_PAGE(dst_page));
					if (refmod & VM_MEM_REFERENCED) {
						dst_page->vmp_reference = TRUE;
					}
				}
			}
		}
		if ((cntrl_flags & UPL_REQUEST_FORCE_COHERENCY) && dst_page->vmp_written_by_kernel == TRUE) {
			pmap_sync_page_attributes_phys(phys_page);
			dst_page->vmp_written_by_kernel = FALSE;
		}

record_phys_addr:
		if (dst_page->vmp_busy) {
			upl->flags |= UPL_HAS_BUSY;
		}

		lite_list[entry >> 5] |= 1U << (entry & 31);

		if (phys_page > upl->highest_page) {
			upl->highest_page = phys_page;
		}

		if (user_page_list) {
			user_page_list[entry].phys_addr = phys_page;
			user_page_list[entry].free_when_done    = dst_page->vmp_free_when_done;
			user_page_list[entry].absent    = dst_page->vmp_absent;
			user_page_list[entry].dirty     = dst_page->vmp_dirty;
			user_page_list[entry].precious  = dst_page->vmp_precious;
			user_page_list[entry].device    = FALSE;
			user_page_list[entry].needed    = FALSE;
			if (dst_page->vmp_clustered == TRUE) {
				user_page_list[entry].speculative = (dst_page->vmp_q_state == VM_PAGE_ON_SPECULATIVE_Q) ? TRUE : FALSE;
			} else {
				user_page_list[entry].speculative = FALSE;
			}
			user_page_list[entry].cs_validated = dst_page->vmp_cs_validated;
			user_page_list[entry].cs_tainted = dst_page->vmp_cs_tainted;
			user_page_list[entry].cs_nx = dst_page->vmp_cs_nx;
			user_page_list[entry].mark      = FALSE;
		}
		if (object != kernel_object && object != compressor_object) {
			/*
			 * someone is explicitly grabbing this page...
			 * update clustered and speculative state
			 *
			 */
			if (dst_page->vmp_clustered) {
				VM_PAGE_CONSUME_CLUSTERED(dst_page);
			}
		}
skip_page:
		entry++;
		dst_offset += PAGE_SIZE_64;
		xfer_size -= PAGE_SIZE;

		if (dwp->dw_mask) {
			VM_PAGE_ADD_DELAYED_WORK(dwp, dst_page, dw_count);

			if (dw_count >= dw_limit) {
				vm_page_do_delayed_work(object, tag, &dw_array[0], dw_count);

				dwp = &dw_array[0];
				dw_count = 0;
			}
		}
	}
	assert(entry == size_in_pages);

	if (dw_count) {
		vm_page_do_delayed_work(object, tag, &dw_array[0], dw_count);
	}
finish:
	if (user_page_list && set_cache_attr_needed == TRUE) {
		vm_object_set_pmap_cache_attr(object, user_page_list, size_in_pages, TRUE);
	}

	if (page_list_count != NULL) {
		if (upl->flags & UPL_INTERNAL) {
			*page_list_count = 0;
		} else if (*page_list_count > size_in_pages) {
			*page_list_count = size_in_pages;
		}
	}
	vm_object_unlock(object);

	if (cntrl_flags & UPL_BLOCK_ACCESS) {
		/*
		 * We've marked all the pages "busy" so that future
		 * page faults will block.
		 * Now remove the mapping for these pages, so that they
		 * can't be accessed without causing a page fault.
		 */
		vm_object_pmap_protect(object, offset, (vm_object_size_t)size,
		    PMAP_NULL, 0, VM_PROT_NONE);
		assert(!object->blocked_access);
		object->blocked_access = TRUE;
	}

	VM_DEBUG_CONSTANT_EVENT(vm_object_iopl_request, VM_IOPL_REQUEST, DBG_FUNC_END, page_grab_count, KERN_SUCCESS, 0, 0);
#if DEVELOPMENT || DEBUG
	if (task != NULL) {
		ledger_credit(task->ledger, task_ledgers.pages_grabbed_iopl, page_grab_count);
	}
#endif /* DEVELOPMENT || DEBUG */
	return KERN_SUCCESS;

return_err:
	dw_index = 0;

	for (; offset < dst_offset; offset += PAGE_SIZE) {
		boolean_t need_unwire;

		dst_page = vm_page_lookup(object, offset);

		if (dst_page == VM_PAGE_NULL) {
			panic("vm_object_iopl_request: Wired page missing. \n");
		}

		/*
		 * if we've already processed this page in an earlier
		 * dw_do_work, we need to undo the wiring... we will
		 * leave the dirty and reference bits on if they
		 * were set, since we don't have a good way of knowing
		 * what the previous state was and we won't get here
		 * under any normal circumstances...  we will always
		 * clear BUSY and wakeup any waiters via vm_page_free
		 * or PAGE_WAKEUP_DONE
		 */
		need_unwire = TRUE;

		if (dw_count) {
			if (dw_array[dw_index].dw_m == dst_page) {
				/*
				 * still in the deferred work list
				 * which means we haven't yet called
				 * vm_page_wire on this page
				 */
				need_unwire = FALSE;

				dw_index++;
				dw_count--;
			}
		}
		vm_page_lock_queues();

		if (dst_page->vmp_absent || free_wired_pages == TRUE) {
			vm_page_free(dst_page);

			need_unwire = FALSE;
		} else {
			if (need_unwire == TRUE) {
				vm_page_unwire(dst_page, TRUE);
			}

			PAGE_WAKEUP_DONE(dst_page);
		}
		vm_page_unlock_queues();

		if (need_unwire == TRUE) {
			VM_STAT_INCR(reactivations);
		}
	}
#if UPL_DEBUG
	upl->upl_state = 2;
#endif
	if (!(upl->flags & UPL_KERNEL_OBJECT)) {
		vm_object_activity_end(object);
		vm_object_collapse(object, 0, TRUE);
	}
	vm_object_unlock(object);
	upl_destroy(upl);

	VM_DEBUG_CONSTANT_EVENT(vm_object_iopl_request, VM_IOPL_REQUEST, DBG_FUNC_END, page_grab_count, ret, 0, 0);
#if DEVELOPMENT || DEBUG
	if (task != NULL) {
		ledger_credit(task->ledger, task_ledgers.pages_grabbed_iopl, page_grab_count);
	}
#endif /* DEVELOPMENT || DEBUG */
	return ret;
}

kern_return_t
upl_transpose(
	upl_t           upl1,
	upl_t           upl2)
{
	kern_return_t           retval;
	boolean_t               upls_locked;
	vm_object_t             object1, object2;

	if (upl1 == UPL_NULL || upl2 == UPL_NULL || upl1 == upl2 || ((upl1->flags & UPL_VECTOR) == UPL_VECTOR) || ((upl2->flags & UPL_VECTOR) == UPL_VECTOR)) {
		return KERN_INVALID_ARGUMENT;
	}

	upls_locked = FALSE;

	/*
	 * Since we need to lock both UPLs at the same time,
	 * avoid deadlocks by always taking locks in the same order.
	 */
	if (upl1 < upl2) {
		upl_lock(upl1);
		upl_lock(upl2);
	} else {
		upl_lock(upl2);
		upl_lock(upl1);
	}
	upls_locked = TRUE;     /* the UPLs will need to be unlocked */

	object1 = upl1->map_object;
	object2 = upl2->map_object;

	if (upl1->offset != 0 || upl2->offset != 0 ||
	    upl1->size != upl2->size) {
		/*
		 * We deal only with full objects, not subsets.
		 * That's because we exchange the entire backing store info
		 * for the objects: pager, resident pages, etc...  We can't do
		 * only part of it.
		 */
		retval = KERN_INVALID_VALUE;
		goto done;
	}

	/*
	 * Tranpose the VM objects' backing store.
	 */
	retval = vm_object_transpose(object1, object2,
	    (vm_object_size_t) upl1->size);

	if (retval == KERN_SUCCESS) {
		/*
		 * Make each UPL point to the correct VM object, i.e. the
		 * object holding the pages that the UPL refers to...
		 */
#if CONFIG_IOSCHED || UPL_DEBUG
		if ((upl1->flags & UPL_TRACKED_BY_OBJECT) || (upl2->flags & UPL_TRACKED_BY_OBJECT)) {
			vm_object_lock(object1);
			vm_object_lock(object2);
		}
		if (upl1->flags & UPL_TRACKED_BY_OBJECT) {
			queue_remove(&object1->uplq, upl1, upl_t, uplq);
		}
		if (upl2->flags & UPL_TRACKED_BY_OBJECT) {
			queue_remove(&object2->uplq, upl2, upl_t, uplq);
		}
#endif
		upl1->map_object = object2;
		upl2->map_object = object1;

#if CONFIG_IOSCHED || UPL_DEBUG
		if (upl1->flags & UPL_TRACKED_BY_OBJECT) {
			queue_enter(&object2->uplq, upl1, upl_t, uplq);
		}
		if (upl2->flags & UPL_TRACKED_BY_OBJECT) {
			queue_enter(&object1->uplq, upl2, upl_t, uplq);
		}
		if ((upl1->flags & UPL_TRACKED_BY_OBJECT) || (upl2->flags & UPL_TRACKED_BY_OBJECT)) {
			vm_object_unlock(object2);
			vm_object_unlock(object1);
		}
#endif
	}

done:
	/*
	 * Cleanup.
	 */
	if (upls_locked) {
		upl_unlock(upl1);
		upl_unlock(upl2);
		upls_locked = FALSE;
	}

	return retval;
}

void
upl_range_needed(
	upl_t           upl,
	int             index,
	int             count)
{
	upl_page_info_t *user_page_list;
	int             size_in_pages;

	if (!(upl->flags & UPL_INTERNAL) || count <= 0) {
		return;
	}

	size_in_pages = upl->size / PAGE_SIZE;

	user_page_list = (upl_page_info_t *) (((uintptr_t)upl) + sizeof(struct upl));

	while (count-- && index < size_in_pages) {
		user_page_list[index++].needed = TRUE;
	}
}


/*
 * Reserve of virtual addresses in the kernel address space.
 * We need to map the physical pages in the kernel, so that we
 * can call the code-signing or slide routines with a kernel
 * virtual address.  We keep this pool of pre-allocated kernel
 * virtual addresses so that we don't have to scan the kernel's
 * virtaul address space each time we need to work with
 * a physical page.
 */
decl_simple_lock_data(, vm_paging_lock);
#define VM_PAGING_NUM_PAGES     64
vm_map_offset_t vm_paging_base_address = 0;
boolean_t       vm_paging_page_inuse[VM_PAGING_NUM_PAGES] = { FALSE, };
int             vm_paging_max_index = 0;
int             vm_paging_page_waiter = 0;
int             vm_paging_page_waiter_total = 0;

unsigned long   vm_paging_no_kernel_page = 0;
unsigned long   vm_paging_objects_mapped = 0;
unsigned long   vm_paging_pages_mapped = 0;
unsigned long   vm_paging_objects_mapped_slow = 0;
unsigned long   vm_paging_pages_mapped_slow = 0;

void
vm_paging_map_init(void)
{
	kern_return_t   kr;
	vm_map_offset_t page_map_offset;
	vm_map_entry_t  map_entry;

	assert(vm_paging_base_address == 0);

	/*
	 * Initialize our pool of pre-allocated kernel
	 * virtual addresses.
	 */
	page_map_offset = 0;
	kr = vm_map_find_space(kernel_map,
	    &page_map_offset,
	    VM_PAGING_NUM_PAGES * PAGE_SIZE,
	    0,
	    0,
	    VM_MAP_KERNEL_FLAGS_NONE,
	    VM_KERN_MEMORY_NONE,
	    &map_entry);
	if (kr != KERN_SUCCESS) {
		panic("vm_paging_map_init: kernel_map full\n");
	}
	VME_OBJECT_SET(map_entry, kernel_object);
	VME_OFFSET_SET(map_entry, page_map_offset);
	map_entry->protection = VM_PROT_NONE;
	map_entry->max_protection = VM_PROT_NONE;
	map_entry->permanent = TRUE;
	vm_object_reference(kernel_object);
	vm_map_unlock(kernel_map);

	assert(vm_paging_base_address == 0);
	vm_paging_base_address = page_map_offset;
}

/*
 * vm_paging_map_object:
 *	Maps part of a VM object's pages in the kernel
 *      virtual address space, using the pre-allocated
 *	kernel virtual addresses, if possible.
 * Context:
 *      The VM object is locked.  This lock will get
 *      dropped and re-acquired though, so the caller
 *      must make sure the VM object is kept alive
 *	(by holding a VM map that has a reference
 *      on it, for example, or taking an extra reference).
 *      The page should also be kept busy to prevent
 *	it from being reclaimed.
 */
kern_return_t
vm_paging_map_object(
	vm_page_t               page,
	vm_object_t             object,
	vm_object_offset_t      offset,
	vm_prot_t               protection,
	boolean_t               can_unlock_object,
	vm_map_size_t           *size,          /* IN/OUT */
	vm_map_offset_t         *address,       /* OUT */
	boolean_t               *need_unmap)    /* OUT */
{
	kern_return_t           kr;
	vm_map_offset_t         page_map_offset;
	vm_map_size_t           map_size;
	vm_object_offset_t      object_offset;
	int                     i;

	if (page != VM_PAGE_NULL && *size == PAGE_SIZE) {
		/* use permanent 1-to-1 kernel mapping of physical memory ? */
		*address = (vm_map_offset_t)
		    phystokv((pmap_paddr_t)VM_PAGE_GET_PHYS_PAGE(page) << PAGE_SHIFT);
		*need_unmap = FALSE;
		return KERN_SUCCESS;

		assert(page->vmp_busy);
		/*
		 * Use one of the pre-allocated kernel virtual addresses
		 * and just enter the VM page in the kernel address space
		 * at that virtual address.
		 */
		simple_lock(&vm_paging_lock, &vm_pageout_lck_grp);

		/*
		 * Try and find an available kernel virtual address
		 * from our pre-allocated pool.
		 */
		page_map_offset = 0;
		for (;;) {
			for (i = 0; i < VM_PAGING_NUM_PAGES; i++) {
				if (vm_paging_page_inuse[i] == FALSE) {
					page_map_offset =
					    vm_paging_base_address +
					    (i * PAGE_SIZE);
					break;
				}
			}
			if (page_map_offset != 0) {
				/* found a space to map our page ! */
				break;
			}

			if (can_unlock_object) {
				/*
				 * If we can afford to unlock the VM object,
				 * let's take the slow path now...
				 */
				break;
			}
			/*
			 * We can't afford to unlock the VM object, so
			 * let's wait for a space to become available...
			 */
			vm_paging_page_waiter_total++;
			vm_paging_page_waiter++;
			kr = assert_wait((event_t)&vm_paging_page_waiter, THREAD_UNINT);
			if (kr == THREAD_WAITING) {
				simple_unlock(&vm_paging_lock);
				kr = thread_block(THREAD_CONTINUE_NULL);
				simple_lock(&vm_paging_lock, &vm_pageout_lck_grp);
			}
			vm_paging_page_waiter--;
			/* ... and try again */
		}

		if (page_map_offset != 0) {
			/*
			 * We found a kernel virtual address;
			 * map the physical page to that virtual address.
			 */
			if (i > vm_paging_max_index) {
				vm_paging_max_index = i;
			}
			vm_paging_page_inuse[i] = TRUE;
			simple_unlock(&vm_paging_lock);

			page->vmp_pmapped = TRUE;

			/*
			 * Keep the VM object locked over the PMAP_ENTER
			 * and the actual use of the page by the kernel,
			 * or this pmap mapping might get undone by a
			 * vm_object_pmap_protect() call...
			 */
			PMAP_ENTER(kernel_pmap,
			    page_map_offset,
			    page,
			    protection,
			    VM_PROT_NONE,
			    0,
			    TRUE,
			    kr);
			assert(kr == KERN_SUCCESS);
			vm_paging_objects_mapped++;
			vm_paging_pages_mapped++;
			*address = page_map_offset;
			*need_unmap = TRUE;

#if KASAN
			kasan_notify_address(page_map_offset, PAGE_SIZE);
#endif

			/* all done and mapped, ready to use ! */
			return KERN_SUCCESS;
		}

		/*
		 * We ran out of pre-allocated kernel virtual
		 * addresses.  Just map the page in the kernel
		 * the slow and regular way.
		 */
		vm_paging_no_kernel_page++;
		simple_unlock(&vm_paging_lock);
	}

	if (!can_unlock_object) {
		*address = 0;
		*size = 0;
		*need_unmap = FALSE;
		return KERN_NOT_SUPPORTED;
	}

	object_offset = vm_object_trunc_page(offset);
	map_size = vm_map_round_page(*size,
	    VM_MAP_PAGE_MASK(kernel_map));

	/*
	 * Try and map the required range of the object
	 * in the kernel_map
	 */

	vm_object_reference_locked(object);     /* for the map entry */
	vm_object_unlock(object);

	kr = vm_map_enter(kernel_map,
	    address,
	    map_size,
	    0,
	    VM_FLAGS_ANYWHERE,
	    VM_MAP_KERNEL_FLAGS_NONE,
	    VM_KERN_MEMORY_NONE,
	    object,
	    object_offset,
	    FALSE,
	    protection,
	    VM_PROT_ALL,
	    VM_INHERIT_NONE);
	if (kr != KERN_SUCCESS) {
		*address = 0;
		*size = 0;
		*need_unmap = FALSE;
		vm_object_deallocate(object);   /* for the map entry */
		vm_object_lock(object);
		return kr;
	}

	*size = map_size;

	/*
	 * Enter the mapped pages in the page table now.
	 */
	vm_object_lock(object);
	/*
	 * VM object must be kept locked from before PMAP_ENTER()
	 * until after the kernel is done accessing the page(s).
	 * Otherwise, the pmap mappings in the kernel could be
	 * undone by a call to vm_object_pmap_protect().
	 */

	for (page_map_offset = 0;
	    map_size != 0;
	    map_size -= PAGE_SIZE_64, page_map_offset += PAGE_SIZE_64) {
		page = vm_page_lookup(object, offset + page_map_offset);
		if (page == VM_PAGE_NULL) {
			printf("vm_paging_map_object: no page !?");
			vm_object_unlock(object);
			kr = vm_map_remove(kernel_map, *address, *size,
			    VM_MAP_REMOVE_NO_FLAGS);
			assert(kr == KERN_SUCCESS);
			*address = 0;
			*size = 0;
			*need_unmap = FALSE;
			vm_object_lock(object);
			return KERN_MEMORY_ERROR;
		}
		page->vmp_pmapped = TRUE;

		//assert(pmap_verify_free(VM_PAGE_GET_PHYS_PAGE(page)));
		PMAP_ENTER(kernel_pmap,
		    *address + page_map_offset,
		    page,
		    protection,
		    VM_PROT_NONE,
		    0,
		    TRUE,
		    kr);
		assert(kr == KERN_SUCCESS);
#if KASAN
		kasan_notify_address(*address + page_map_offset, PAGE_SIZE);
#endif
	}

	vm_paging_objects_mapped_slow++;
	vm_paging_pages_mapped_slow += (unsigned long) (map_size / PAGE_SIZE_64);

	*need_unmap = TRUE;

	return KERN_SUCCESS;
}

/*
 * vm_paging_unmap_object:
 *	Unmaps part of a VM object's pages from the kernel
 *      virtual address space.
 * Context:
 *      The VM object is locked.  This lock will get
 *      dropped and re-acquired though.
 */
void
vm_paging_unmap_object(
	vm_object_t     object,
	vm_map_offset_t start,
	vm_map_offset_t end)
{
	kern_return_t   kr;
	int             i;

	if ((vm_paging_base_address == 0) ||
	    (start < vm_paging_base_address) ||
	    (end > (vm_paging_base_address
	    + (VM_PAGING_NUM_PAGES * PAGE_SIZE)))) {
		/*
		 * We didn't use our pre-allocated pool of
		 * kernel virtual address.  Deallocate the
		 * virtual memory.
		 */
		if (object != VM_OBJECT_NULL) {
			vm_object_unlock(object);
		}
		kr = vm_map_remove(kernel_map, start, end,
		    VM_MAP_REMOVE_NO_FLAGS);
		if (object != VM_OBJECT_NULL) {
			vm_object_lock(object);
		}
		assert(kr == KERN_SUCCESS);
	} else {
		/*
		 * We used a kernel virtual address from our
		 * pre-allocated pool.  Put it back in the pool
		 * for next time.
		 */
		assert(end - start == PAGE_SIZE);
		i = (int) ((start - vm_paging_base_address) >> PAGE_SHIFT);
		assert(i >= 0 && i < VM_PAGING_NUM_PAGES);

		/* undo the pmap mapping */
		pmap_remove(kernel_pmap, start, end);

		simple_lock(&vm_paging_lock, &vm_pageout_lck_grp);
		vm_paging_page_inuse[i] = FALSE;
		if (vm_paging_page_waiter) {
			thread_wakeup(&vm_paging_page_waiter);
		}
		simple_unlock(&vm_paging_lock);
	}
}


/*
 * page->vmp_object must be locked
 */
void
vm_pageout_steal_laundry(vm_page_t page, boolean_t queues_locked)
{
	if (!queues_locked) {
		vm_page_lockspin_queues();
	}

	page->vmp_free_when_done = FALSE;
	/*
	 * need to drop the laundry count...
	 * we may also need to remove it
	 * from the I/O paging queue...
	 * vm_pageout_throttle_up handles both cases
	 *
	 * the laundry and pageout_queue flags are cleared...
	 */
	vm_pageout_throttle_up(page);

	if (!queues_locked) {
		vm_page_unlock_queues();
	}
}

upl_t
vector_upl_create(vm_offset_t upl_offset)
{
	int     vector_upl_size  = sizeof(struct _vector_upl);
	int i = 0;
	upl_t   upl;
	vector_upl_t vector_upl = (vector_upl_t)kalloc(vector_upl_size);

	upl = upl_create(0, UPL_VECTOR, 0);
	upl->vector_upl = vector_upl;
	upl->offset = upl_offset;
	vector_upl->size = 0;
	vector_upl->offset = upl_offset;
	vector_upl->invalid_upls = 0;
	vector_upl->num_upls = 0;
	vector_upl->pagelist = NULL;

	for (i = 0; i < MAX_VECTOR_UPL_ELEMENTS; i++) {
		vector_upl->upl_iostates[i].size = 0;
		vector_upl->upl_iostates[i].offset = 0;
	}
	return upl;
}

void
vector_upl_deallocate(upl_t upl)
{
	if (upl) {
		vector_upl_t vector_upl = upl->vector_upl;
		if (vector_upl) {
			if (vector_upl->invalid_upls != vector_upl->num_upls) {
				panic("Deallocating non-empty Vectored UPL\n");
			}
			kfree(vector_upl->pagelist, (sizeof(struct upl_page_info) * (vector_upl->size / PAGE_SIZE)));
			vector_upl->invalid_upls = 0;
			vector_upl->num_upls = 0;
			vector_upl->pagelist = NULL;
			vector_upl->size = 0;
			vector_upl->offset = 0;
			kfree(vector_upl, sizeof(struct _vector_upl));
			vector_upl = (vector_upl_t)0xfeedfeed;
		} else {
			panic("vector_upl_deallocate was passed a non-vectored upl\n");
		}
	} else {
		panic("vector_upl_deallocate was passed a NULL upl\n");
	}
}

boolean_t
vector_upl_is_valid(upl_t upl)
{
	if (upl && ((upl->flags & UPL_VECTOR) == UPL_VECTOR)) {
		vector_upl_t vector_upl = upl->vector_upl;
		if (vector_upl == NULL || vector_upl == (vector_upl_t)0xfeedfeed || vector_upl == (vector_upl_t)0xfeedbeef) {
			return FALSE;
		} else {
			return TRUE;
		}
	}
	return FALSE;
}

boolean_t
vector_upl_set_subupl(upl_t upl, upl_t subupl, uint32_t io_size)
{
	if (vector_upl_is_valid(upl)) {
		vector_upl_t vector_upl = upl->vector_upl;

		if (vector_upl) {
			if (subupl) {
				if (io_size) {
					if (io_size < PAGE_SIZE) {
						io_size = PAGE_SIZE;
					}
					subupl->vector_upl = (void*)vector_upl;
					vector_upl->upl_elems[vector_upl->num_upls++] = subupl;
					vector_upl->size += io_size;
					upl->size += io_size;
				} else {
					uint32_t i = 0, invalid_upls = 0;
					for (i = 0; i < vector_upl->num_upls; i++) {
						if (vector_upl->upl_elems[i] == subupl) {
							break;
						}
					}
					if (i == vector_upl->num_upls) {
						panic("Trying to remove sub-upl when none exists");
					}

					vector_upl->upl_elems[i] = NULL;
					invalid_upls = os_atomic_inc(&(vector_upl)->invalid_upls,
					    relaxed);
					if (invalid_upls == vector_upl->num_upls) {
						return TRUE;
					} else {
						return FALSE;
					}
				}
			} else {
				panic("vector_upl_set_subupl was passed a NULL upl element\n");
			}
		} else {
			panic("vector_upl_set_subupl was passed a non-vectored upl\n");
		}
	} else {
		panic("vector_upl_set_subupl was passed a NULL upl\n");
	}

	return FALSE;
}

void
vector_upl_set_pagelist(upl_t upl)
{
	if (vector_upl_is_valid(upl)) {
		uint32_t i = 0;
		vector_upl_t vector_upl = upl->vector_upl;

		if (vector_upl) {
			vm_offset_t pagelist_size = 0, cur_upl_pagelist_size = 0;

			vector_upl->pagelist = (upl_page_info_array_t)kalloc(sizeof(struct upl_page_info) * (vector_upl->size / PAGE_SIZE));

			for (i = 0; i < vector_upl->num_upls; i++) {
				cur_upl_pagelist_size = sizeof(struct upl_page_info) * vector_upl->upl_elems[i]->size / PAGE_SIZE;
				bcopy(UPL_GET_INTERNAL_PAGE_LIST_SIMPLE(vector_upl->upl_elems[i]), (char*)vector_upl->pagelist + pagelist_size, cur_upl_pagelist_size);
				pagelist_size += cur_upl_pagelist_size;
				if (vector_upl->upl_elems[i]->highest_page > upl->highest_page) {
					upl->highest_page = vector_upl->upl_elems[i]->highest_page;
				}
			}
			assert( pagelist_size == (sizeof(struct upl_page_info) * (vector_upl->size / PAGE_SIZE)));
		} else {
			panic("vector_upl_set_pagelist was passed a non-vectored upl\n");
		}
	} else {
		panic("vector_upl_set_pagelist was passed a NULL upl\n");
	}
}

upl_t
vector_upl_subupl_byindex(upl_t upl, uint32_t index)
{
	if (vector_upl_is_valid(upl)) {
		vector_upl_t vector_upl = upl->vector_upl;
		if (vector_upl) {
			if (index < vector_upl->num_upls) {
				return vector_upl->upl_elems[index];
			}
		} else {
			panic("vector_upl_subupl_byindex was passed a non-vectored upl\n");
		}
	}
	return NULL;
}

upl_t
vector_upl_subupl_byoffset(upl_t upl, upl_offset_t *upl_offset, upl_size_t *upl_size)
{
	if (vector_upl_is_valid(upl)) {
		uint32_t i = 0;
		vector_upl_t vector_upl = upl->vector_upl;

		if (vector_upl) {
			upl_t subupl = NULL;
			vector_upl_iostates_t subupl_state;

			for (i = 0; i < vector_upl->num_upls; i++) {
				subupl = vector_upl->upl_elems[i];
				subupl_state = vector_upl->upl_iostates[i];
				if (*upl_offset <= (subupl_state.offset + subupl_state.size - 1)) {
					/* We could have been passed an offset/size pair that belongs
					 * to an UPL element that has already been committed/aborted.
					 * If so, return NULL.
					 */
					if (subupl == NULL) {
						return NULL;
					}
					if ((subupl_state.offset + subupl_state.size) < (*upl_offset + *upl_size)) {
						*upl_size = (subupl_state.offset + subupl_state.size) - *upl_offset;
						if (*upl_size > subupl_state.size) {
							*upl_size = subupl_state.size;
						}
					}
					if (*upl_offset >= subupl_state.offset) {
						*upl_offset -= subupl_state.offset;
					} else if (i) {
						panic("Vector UPL offset miscalculation\n");
					}
					return subupl;
				}
			}
		} else {
			panic("vector_upl_subupl_byoffset was passed a non-vectored UPL\n");
		}
	}
	return NULL;
}

void
vector_upl_get_submap(upl_t upl, vm_map_t *v_upl_submap, vm_offset_t *submap_dst_addr)
{
	*v_upl_submap = NULL;

	if (vector_upl_is_valid(upl)) {
		vector_upl_t vector_upl = upl->vector_upl;
		if (vector_upl) {
			*v_upl_submap = vector_upl->submap;
			*submap_dst_addr = vector_upl->submap_dst_addr;
		} else {
			panic("vector_upl_get_submap was passed a non-vectored UPL\n");
		}
	} else {
		panic("vector_upl_get_submap was passed a null UPL\n");
	}
}

void
vector_upl_set_submap(upl_t upl, vm_map_t submap, vm_offset_t submap_dst_addr)
{
	if (vector_upl_is_valid(upl)) {
		vector_upl_t vector_upl = upl->vector_upl;
		if (vector_upl) {
			vector_upl->submap = submap;
			vector_upl->submap_dst_addr = submap_dst_addr;
		} else {
			panic("vector_upl_get_submap was passed a non-vectored UPL\n");
		}
	} else {
		panic("vector_upl_get_submap was passed a NULL UPL\n");
	}
}

void
vector_upl_set_iostate(upl_t upl, upl_t subupl, upl_offset_t offset, upl_size_t size)
{
	if (vector_upl_is_valid(upl)) {
		uint32_t i = 0;
		vector_upl_t vector_upl = upl->vector_upl;

		if (vector_upl) {
			for (i = 0; i < vector_upl->num_upls; i++) {
				if (vector_upl->upl_elems[i] == subupl) {
					break;
				}
			}

			if (i == vector_upl->num_upls) {
				panic("setting sub-upl iostate when none exists");
			}

			vector_upl->upl_iostates[i].offset = offset;
			if (size < PAGE_SIZE) {
				size = PAGE_SIZE;
			}
			vector_upl->upl_iostates[i].size = size;
		} else {
			panic("vector_upl_set_iostate was passed a non-vectored UPL\n");
		}
	} else {
		panic("vector_upl_set_iostate was passed a NULL UPL\n");
	}
}

void
vector_upl_get_iostate(upl_t upl, upl_t subupl, upl_offset_t *offset, upl_size_t *size)
{
	if (vector_upl_is_valid(upl)) {
		uint32_t i = 0;
		vector_upl_t vector_upl = upl->vector_upl;

		if (vector_upl) {
			for (i = 0; i < vector_upl->num_upls; i++) {
				if (vector_upl->upl_elems[i] == subupl) {
					break;
				}
			}

			if (i == vector_upl->num_upls) {
				panic("getting sub-upl iostate when none exists");
			}

			*offset = vector_upl->upl_iostates[i].offset;
			*size = vector_upl->upl_iostates[i].size;
		} else {
			panic("vector_upl_get_iostate was passed a non-vectored UPL\n");
		}
	} else {
		panic("vector_upl_get_iostate was passed a NULL UPL\n");
	}
}

void
vector_upl_get_iostate_byindex(upl_t upl, uint32_t index, upl_offset_t *offset, upl_size_t *size)
{
	if (vector_upl_is_valid(upl)) {
		vector_upl_t vector_upl = upl->vector_upl;
		if (vector_upl) {
			if (index < vector_upl->num_upls) {
				*offset = vector_upl->upl_iostates[index].offset;
				*size = vector_upl->upl_iostates[index].size;
			} else {
				*offset = *size = 0;
			}
		} else {
			panic("vector_upl_get_iostate_byindex was passed a non-vectored UPL\n");
		}
	} else {
		panic("vector_upl_get_iostate_byindex was passed a NULL UPL\n");
	}
}

upl_page_info_t *
upl_get_internal_vectorupl_pagelist(upl_t upl)
{
	return ((vector_upl_t)(upl->vector_upl))->pagelist;
}

void *
upl_get_internal_vectorupl(upl_t upl)
{
	return upl->vector_upl;
}

vm_size_t
upl_get_internal_pagelist_offset(void)
{
	return sizeof(struct upl);
}

void
upl_clear_dirty(
	upl_t           upl,
	boolean_t       value)
{
	if (value) {
		upl->flags |= UPL_CLEAR_DIRTY;
	} else {
		upl->flags &= ~UPL_CLEAR_DIRTY;
	}
}

void
upl_set_referenced(
	upl_t           upl,
	boolean_t       value)
{
	upl_lock(upl);
	if (value) {
		upl->ext_ref_count++;
	} else {
		if (!upl->ext_ref_count) {
			panic("upl_set_referenced not %p\n", upl);
		}
		upl->ext_ref_count--;
	}
	upl_unlock(upl);
}

#if CONFIG_IOSCHED
void
upl_set_blkno(
	upl_t           upl,
	vm_offset_t     upl_offset,
	int             io_size,
	int64_t         blkno)
{
	int i, j;
	if ((upl->flags & UPL_EXPEDITE_SUPPORTED) == 0) {
		return;
	}

	assert(upl->upl_reprio_info != 0);
	for (i = (int)(upl_offset / PAGE_SIZE), j = 0; j < io_size; i++, j += PAGE_SIZE) {
		UPL_SET_REPRIO_INFO(upl, i, blkno, io_size);
	}
}
#endif

void inline
memoryshot(unsigned int event, unsigned int control)
{
	if (vm_debug_events) {
		KERNEL_DEBUG_CONSTANT1((MACHDBG_CODE(DBG_MACH_VM_PRESSURE, event)) | control,
		    vm_page_active_count, vm_page_inactive_count,
		    vm_page_free_count, vm_page_speculative_count,
		    vm_page_throttled_count);
	} else {
		(void) event;
		(void) control;
	}
}

#ifdef MACH_BSD

boolean_t
upl_device_page(upl_page_info_t *upl)
{
	return UPL_DEVICE_PAGE(upl);
}
boolean_t
upl_page_present(upl_page_info_t *upl, int index)
{
	return UPL_PAGE_PRESENT(upl, index);
}
boolean_t
upl_speculative_page(upl_page_info_t *upl, int index)
{
	return UPL_SPECULATIVE_PAGE(upl, index);
}
boolean_t
upl_dirty_page(upl_page_info_t *upl, int index)
{
	return UPL_DIRTY_PAGE(upl, index);
}
boolean_t
upl_valid_page(upl_page_info_t *upl, int index)
{
	return UPL_VALID_PAGE(upl, index);
}
ppnum_t
upl_phys_page(upl_page_info_t *upl, int index)
{
	return UPL_PHYS_PAGE(upl, index);
}

void
upl_page_set_mark(upl_page_info_t *upl, int index, boolean_t v)
{
	upl[index].mark = v;
}

boolean_t
upl_page_get_mark(upl_page_info_t *upl, int index)
{
	return upl[index].mark;
}

void
vm_countdirtypages(void)
{
	vm_page_t m;
	int dpages;
	int pgopages;
	int precpages;


	dpages = 0;
	pgopages = 0;
	precpages = 0;

	vm_page_lock_queues();
	m = (vm_page_t) vm_page_queue_first(&vm_page_queue_inactive);
	do {
		if (m == (vm_page_t)0) {
			break;
		}

		if (m->vmp_dirty) {
			dpages++;
		}
		if (m->vmp_free_when_done) {
			pgopages++;
		}
		if (m->vmp_precious) {
			precpages++;
		}

		assert(VM_PAGE_OBJECT(m) != kernel_object);
		m = (vm_page_t) vm_page_queue_next(&m->vmp_pageq);
		if (m == (vm_page_t)0) {
			break;
		}
	} while (!vm_page_queue_end(&vm_page_queue_inactive, (vm_page_queue_entry_t) m));
	vm_page_unlock_queues();

	vm_page_lock_queues();
	m = (vm_page_t) vm_page_queue_first(&vm_page_queue_throttled);
	do {
		if (m == (vm_page_t)0) {
			break;
		}

		dpages++;
		assert(m->vmp_dirty);
		assert(!m->vmp_free_when_done);
		assert(VM_PAGE_OBJECT(m) != kernel_object);
		m = (vm_page_t) vm_page_queue_next(&m->vmp_pageq);
		if (m == (vm_page_t)0) {
			break;
		}
	} while (!vm_page_queue_end(&vm_page_queue_throttled, (vm_page_queue_entry_t) m));
	vm_page_unlock_queues();

	vm_page_lock_queues();
	m = (vm_page_t) vm_page_queue_first(&vm_page_queue_anonymous);
	do {
		if (m == (vm_page_t)0) {
			break;
		}

		if (m->vmp_dirty) {
			dpages++;
		}
		if (m->vmp_free_when_done) {
			pgopages++;
		}
		if (m->vmp_precious) {
			precpages++;
		}

		assert(VM_PAGE_OBJECT(m) != kernel_object);
		m = (vm_page_t) vm_page_queue_next(&m->vmp_pageq);
		if (m == (vm_page_t)0) {
			break;
		}
	} while (!vm_page_queue_end(&vm_page_queue_anonymous, (vm_page_queue_entry_t) m));
	vm_page_unlock_queues();

	printf("IN Q: %d : %d : %d\n", dpages, pgopages, precpages);

	dpages = 0;
	pgopages = 0;
	precpages = 0;

	vm_page_lock_queues();
	m = (vm_page_t) vm_page_queue_first(&vm_page_queue_active);

	do {
		if (m == (vm_page_t)0) {
			break;
		}
		if (m->vmp_dirty) {
			dpages++;
		}
		if (m->vmp_free_when_done) {
			pgopages++;
		}
		if (m->vmp_precious) {
			precpages++;
		}

		assert(VM_PAGE_OBJECT(m) != kernel_object);
		m = (vm_page_t) vm_page_queue_next(&m->vmp_pageq);
		if (m == (vm_page_t)0) {
			break;
		}
	} while (!vm_page_queue_end(&vm_page_queue_active, (vm_page_queue_entry_t) m));
	vm_page_unlock_queues();

	printf("AC Q: %d : %d : %d\n", dpages, pgopages, precpages);
}
#endif /* MACH_BSD */


#if CONFIG_IOSCHED
int
upl_get_cached_tier(upl_t  upl)
{
	assert(upl);
	if (upl->flags & UPL_TRACKED_BY_OBJECT) {
		return upl->upl_priority;
	}
	return -1;
}
#endif /* CONFIG_IOSCHED */


void
upl_callout_iodone(upl_t upl)
{
	struct upl_io_completion *upl_ctx = upl->upl_iodone;

	if (upl_ctx) {
		void    (*iodone_func)(void *, int) = upl_ctx->io_done;

		assert(upl_ctx->io_done);

		(*iodone_func)(upl_ctx->io_context, upl_ctx->io_error);
	}
}

void
upl_set_iodone(upl_t upl, void *upl_iodone)
{
	upl->upl_iodone = (struct upl_io_completion *)upl_iodone;
}

void
upl_set_iodone_error(upl_t upl, int error)
{
	struct upl_io_completion *upl_ctx = upl->upl_iodone;

	if (upl_ctx) {
		upl_ctx->io_error = error;
	}
}


ppnum_t
upl_get_highest_page(
	upl_t                      upl)
{
	return upl->highest_page;
}

upl_size_t
upl_get_size(
	upl_t                      upl)
{
	return upl->size;
}

upl_t
upl_associated_upl(upl_t upl)
{
	return upl->associated_upl;
}

void
upl_set_associated_upl(upl_t upl, upl_t associated_upl)
{
	upl->associated_upl = associated_upl;
}

struct vnode *
upl_lookup_vnode(upl_t upl)
{
	if (!upl->map_object->internal) {
		return vnode_pager_lookup_vnode(upl->map_object->pager);
	} else {
		return NULL;
	}
}

#if UPL_DEBUG
kern_return_t
upl_ubc_alias_set(upl_t upl, uintptr_t alias1, uintptr_t alias2)
{
	upl->ubc_alias1 = alias1;
	upl->ubc_alias2 = alias2;
	return KERN_SUCCESS;
}
int
upl_ubc_alias_get(upl_t upl, uintptr_t * al, uintptr_t * al2)
{
	if (al) {
		*al = upl->ubc_alias1;
	}
	if (al2) {
		*al2 = upl->ubc_alias2;
	}
	return KERN_SUCCESS;
}
#endif /* UPL_DEBUG */

#if VM_PRESSURE_EVENTS
/*
 * Upward trajectory.
 */
extern boolean_t vm_compressor_low_on_space(void);

boolean_t
VM_PRESSURE_NORMAL_TO_WARNING(void)
{
	if (!VM_CONFIG_COMPRESSOR_IS_ACTIVE) {
		/* Available pages below our threshold */
		if (memorystatus_available_pages < memorystatus_available_pages_pressure) {
			/* No frozen processes to kill */
			if (memorystatus_frozen_count == 0) {
				/* Not enough suspended processes available. */
				if (memorystatus_suspended_count < MEMORYSTATUS_SUSPENDED_THRESHOLD) {
					return TRUE;
				}
			}
		}
		return FALSE;
	} else {
		return (AVAILABLE_NON_COMPRESSED_MEMORY < VM_PAGE_COMPRESSOR_COMPACT_THRESHOLD) ? 1 : 0;
	}
}

boolean_t
VM_PRESSURE_WARNING_TO_CRITICAL(void)
{
	if (!VM_CONFIG_COMPRESSOR_IS_ACTIVE) {
		/* Available pages below our threshold */
		if (memorystatus_available_pages < memorystatus_available_pages_critical) {
			return TRUE;
		}
		return FALSE;
	} else {
		return vm_compressor_low_on_space() || (AVAILABLE_NON_COMPRESSED_MEMORY < ((12 * VM_PAGE_COMPRESSOR_SWAP_UNTHROTTLE_THRESHOLD) / 10)) ? 1 : 0;
	}
}

/*
 * Downward trajectory.
 */
boolean_t
VM_PRESSURE_WARNING_TO_NORMAL(void)
{
	if (!VM_CONFIG_COMPRESSOR_IS_ACTIVE) {
		/* Available pages above our threshold */
		unsigned int target_threshold = (unsigned int) (memorystatus_available_pages_pressure + ((15 * memorystatus_available_pages_pressure) / 100));
		if (memorystatus_available_pages > target_threshold) {
			return TRUE;
		}
		return FALSE;
	} else {
		return (AVAILABLE_NON_COMPRESSED_MEMORY > ((12 * VM_PAGE_COMPRESSOR_COMPACT_THRESHOLD) / 10)) ? 1 : 0;
	}
}

boolean_t
VM_PRESSURE_CRITICAL_TO_WARNING(void)
{
	if (!VM_CONFIG_COMPRESSOR_IS_ACTIVE) {
		/* Available pages above our threshold */
		unsigned int target_threshold = (unsigned int)(memorystatus_available_pages_critical + ((15 * memorystatus_available_pages_critical) / 100));
		if (memorystatus_available_pages > target_threshold) {
			return TRUE;
		}
		return FALSE;
	} else {
		return (AVAILABLE_NON_COMPRESSED_MEMORY > ((14 * VM_PAGE_COMPRESSOR_SWAP_UNTHROTTLE_THRESHOLD) / 10)) ? 1 : 0;
	}
}
#endif /* VM_PRESSURE_EVENTS */



#define VM_TEST_COLLAPSE_COMPRESSOR             0
#define VM_TEST_WIRE_AND_EXTRACT                0
#define VM_TEST_PAGE_WIRE_OVERFLOW_PANIC        0
#if __arm64__
#define VM_TEST_KERNEL_OBJECT_FAULT             0
#endif /* __arm64__ */
#define VM_TEST_DEVICE_PAGER_TRANSPOSE          (DEVELOPMENT || DEBUG)

#if VM_TEST_COLLAPSE_COMPRESSOR
extern boolean_t vm_object_collapse_compressor_allowed;
#include <IOKit/IOLib.h>
static void
vm_test_collapse_compressor(void)
{
	vm_object_size_t        backing_size, top_size;
	vm_object_t             backing_object, top_object;
	vm_map_offset_t         backing_offset, top_offset;
	unsigned char           *backing_address, *top_address;
	kern_return_t           kr;

	printf("VM_TEST_COLLAPSE_COMPRESSOR:\n");

	/* create backing object */
	backing_size = 15 * PAGE_SIZE;
	backing_object = vm_object_allocate(backing_size);
	assert(backing_object != VM_OBJECT_NULL);
	printf("VM_TEST_COLLAPSE_COMPRESSOR: created backing object %p\n",
	    backing_object);
	/* map backing object */
	backing_offset = 0;
	kr = vm_map_enter(kernel_map, &backing_offset, backing_size, 0,
	    VM_FLAGS_ANYWHERE, VM_MAP_KERNEL_FLAGS_NONE,
	    backing_object, 0, FALSE,
	    VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	assert(kr == KERN_SUCCESS);
	backing_address = (unsigned char *) backing_offset;
	printf("VM_TEST_COLLAPSE_COMPRESSOR: "
	    "mapped backing object %p at 0x%llx\n",
	    backing_object, (uint64_t) backing_offset);
	/* populate with pages to be compressed in backing object */
	backing_address[0x1 * PAGE_SIZE] = 0xB1;
	backing_address[0x4 * PAGE_SIZE] = 0xB4;
	backing_address[0x7 * PAGE_SIZE] = 0xB7;
	backing_address[0xa * PAGE_SIZE] = 0xBA;
	backing_address[0xd * PAGE_SIZE] = 0xBD;
	printf("VM_TEST_COLLAPSE_COMPRESSOR: "
	    "populated pages to be compressed in "
	    "backing_object %p\n", backing_object);
	/* compress backing object */
	vm_object_pageout(backing_object);
	printf("VM_TEST_COLLAPSE_COMPRESSOR: compressing backing_object %p\n",
	    backing_object);
	/* wait for all the pages to be gone */
	while (*(volatile int *)&backing_object->resident_page_count != 0) {
		IODelay(10);
	}
	printf("VM_TEST_COLLAPSE_COMPRESSOR: backing_object %p compressed\n",
	    backing_object);
	/* populate with pages to be resident in backing object */
	backing_address[0x0 * PAGE_SIZE] = 0xB0;
	backing_address[0x3 * PAGE_SIZE] = 0xB3;
	backing_address[0x6 * PAGE_SIZE] = 0xB6;
	backing_address[0x9 * PAGE_SIZE] = 0xB9;
	backing_address[0xc * PAGE_SIZE] = 0xBC;
	printf("VM_TEST_COLLAPSE_COMPRESSOR: "
	    "populated pages to be resident in "
	    "backing_object %p\n", backing_object);
	/* leave the other pages absent */
	/* mess with the paging_offset of the backing_object */
	assert(backing_object->paging_offset == 0);
	backing_object->paging_offset = 0x3000;

	/* create top object */
	top_size = 9 * PAGE_SIZE;
	top_object = vm_object_allocate(top_size);
	assert(top_object != VM_OBJECT_NULL);
	printf("VM_TEST_COLLAPSE_COMPRESSOR: created top object %p\n",
	    top_object);
	/* map top object */
	top_offset = 0;
	kr = vm_map_enter(kernel_map, &top_offset, top_size, 0,
	    VM_FLAGS_ANYWHERE, VM_MAP_KERNEL_FLAGS_NONE,
	    top_object, 0, FALSE,
	    VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
	assert(kr == KERN_SUCCESS);
	top_address = (unsigned char *) top_offset;
	printf("VM_TEST_COLLAPSE_COMPRESSOR: "
	    "mapped top object %p at 0x%llx\n",
	    top_object, (uint64_t) top_offset);
	/* populate with pages to be compressed in top object */
	top_address[0x3 * PAGE_SIZE] = 0xA3;
	top_address[0x4 * PAGE_SIZE] = 0xA4;
	top_address[0x5 * PAGE_SIZE] = 0xA5;
	printf("VM_TEST_COLLAPSE_COMPRESSOR: "
	    "populated pages to be compressed in "
	    "top_object %p\n", top_object);
	/* compress top object */
	vm_object_pageout(top_object);
	printf("VM_TEST_COLLAPSE_COMPRESSOR: compressing top_object %p\n",
	    top_object);
	/* wait for all the pages to be gone */
	while (top_object->resident_page_count != 0) {
		IODelay(10);
	}
	printf("VM_TEST_COLLAPSE_COMPRESSOR: top_object %p compressed\n",
	    top_object);
	/* populate with pages to be resident in top object */
	top_address[0x0 * PAGE_SIZE] = 0xA0;
	top_address[0x1 * PAGE_SIZE] = 0xA1;
	top_address[0x2 * PAGE_SIZE] = 0xA2;
	printf("VM_TEST_COLLAPSE_COMPRESSOR: "
	    "populated pages to be resident in "
	    "top_object %p\n", top_object);
	/* leave the other pages absent */

	/* link the 2 objects */
	vm_object_reference(backing_object);
	top_object->shadow = backing_object;
	top_object->vo_shadow_offset = 0x3000;
	printf("VM_TEST_COLLAPSE_COMPRESSOR: linked %p and %p\n",
	    top_object, backing_object);

	/* unmap backing object */
	vm_map_remove(kernel_map,
	    backing_offset,
	    backing_offset + backing_size,
	    VM_MAP_REMOVE_NO_FLAGS);
	printf("VM_TEST_COLLAPSE_COMPRESSOR: "
	    "unmapped backing_object %p [0x%llx:0x%llx]\n",
	    backing_object,
	    (uint64_t) backing_offset,
	    (uint64_t) (backing_offset + backing_size));

	/* collapse */
	printf("VM_TEST_COLLAPSE_COMPRESSOR: collapsing %p\n", top_object);
	vm_object_lock(top_object);
	vm_object_collapse(top_object, 0, FALSE);
	vm_object_unlock(top_object);
	printf("VM_TEST_COLLAPSE_COMPRESSOR: collapsed %p\n", top_object);

	/* did it work? */
	if (top_object->shadow != VM_OBJECT_NULL) {
		printf("VM_TEST_COLLAPSE_COMPRESSOR: not collapsed\n");
		printf("VM_TEST_COLLAPSE_COMPRESSOR: FAIL\n");
		if (vm_object_collapse_compressor_allowed) {
			panic("VM_TEST_COLLAPSE_COMPRESSOR: FAIL\n");
		}
	} else {
		/* check the contents of the mapping */
		unsigned char expect[9] =
		{ 0xA0, 0xA1, 0xA2,             /* resident in top */
		  0xA3, 0xA4, 0xA5,             /* compressed in top */
		  0xB9,         /* resident in backing + shadow_offset */
		  0xBD,         /* compressed in backing + shadow_offset + paging_offset */
		  0x00 };                       /* absent in both */
		unsigned char actual[9];
		unsigned int i, errors;

		errors = 0;
		for (i = 0; i < sizeof(actual); i++) {
			actual[i] = (unsigned char) top_address[i * PAGE_SIZE];
			if (actual[i] != expect[i]) {
				errors++;
			}
		}
		printf("VM_TEST_COLLAPSE_COMPRESSOR: "
		    "actual [%x %x %x %x %x %x %x %x %x] "
		    "expect [%x %x %x %x %x %x %x %x %x] "
		    "%d errors\n",
		    actual[0], actual[1], actual[2], actual[3],
		    actual[4], actual[5], actual[6], actual[7],
		    actual[8],
		    expect[0], expect[1], expect[2], expect[3],
		    expect[4], expect[5], expect[6], expect[7],
		    expect[8],
		    errors);
		if (errors) {
			panic("VM_TEST_COLLAPSE_COMPRESSOR: FAIL\n");
		} else {
			printf("VM_TEST_COLLAPSE_COMPRESSOR: PASS\n");
		}
	}
}
#else /* VM_TEST_COLLAPSE_COMPRESSOR */
#define vm_test_collapse_compressor()
#endif /* VM_TEST_COLLAPSE_COMPRESSOR */

#if VM_TEST_WIRE_AND_EXTRACT
extern ledger_template_t        task_ledger_template;
#include <mach/mach_vm.h>
extern ppnum_t vm_map_get_phys_page(vm_map_t map,
    vm_offset_t offset);
static void
vm_test_wire_and_extract(void)
{
	ledger_t                ledger;
	vm_map_t                user_map, wire_map;
	mach_vm_address_t       user_addr, wire_addr;
	mach_vm_size_t          user_size, wire_size;
	mach_vm_offset_t        cur_offset;
	vm_prot_t               cur_prot, max_prot;
	ppnum_t                 user_ppnum, wire_ppnum;
	kern_return_t           kr;

	ledger = ledger_instantiate(task_ledger_template,
	    LEDGER_CREATE_ACTIVE_ENTRIES);
	user_map = vm_map_create(pmap_create_options(ledger, 0, PMAP_CREATE_64BIT),
	    0x100000000ULL,
	    0x200000000ULL,
	    TRUE);
	wire_map = vm_map_create(NULL,
	    0x100000000ULL,
	    0x200000000ULL,
	    TRUE);
	user_addr = 0;
	user_size = 0x10000;
	kr = mach_vm_allocate(user_map,
	    &user_addr,
	    user_size,
	    VM_FLAGS_ANYWHERE);
	assert(kr == KERN_SUCCESS);
	wire_addr = 0;
	wire_size = user_size;
	kr = mach_vm_remap(wire_map,
	    &wire_addr,
	    wire_size,
	    0,
	    VM_FLAGS_ANYWHERE,
	    user_map,
	    user_addr,
	    FALSE,
	    &cur_prot,
	    &max_prot,
	    VM_INHERIT_NONE);
	assert(kr == KERN_SUCCESS);
	for (cur_offset = 0;
	    cur_offset < wire_size;
	    cur_offset += PAGE_SIZE) {
		kr = vm_map_wire_and_extract(wire_map,
		    wire_addr + cur_offset,
		    VM_PROT_DEFAULT | VM_PROT_MEMORY_TAG_MAKE(VM_KERN_MEMORY_OSFMK),
		    TRUE,
		    &wire_ppnum);
		assert(kr == KERN_SUCCESS);
		user_ppnum = vm_map_get_phys_page(user_map,
		    user_addr + cur_offset);
		printf("VM_TEST_WIRE_AND_EXTRACT: kr=0x%x "
		    "user[%p:0x%llx:0x%x] wire[%p:0x%llx:0x%x]\n",
		    kr,
		    user_map, user_addr + cur_offset, user_ppnum,
		    wire_map, wire_addr + cur_offset, wire_ppnum);
		if (kr != KERN_SUCCESS ||
		    wire_ppnum == 0 ||
		    wire_ppnum != user_ppnum) {
			panic("VM_TEST_WIRE_AND_EXTRACT: FAIL\n");
		}
	}
	cur_offset -= PAGE_SIZE;
	kr = vm_map_wire_and_extract(wire_map,
	    wire_addr + cur_offset,
	    VM_PROT_DEFAULT,
	    TRUE,
	    &wire_ppnum);
	assert(kr == KERN_SUCCESS);
	printf("VM_TEST_WIRE_AND_EXTRACT: re-wire kr=0x%x "
	    "user[%p:0x%llx:0x%x] wire[%p:0x%llx:0x%x]\n",
	    kr,
	    user_map, user_addr + cur_offset, user_ppnum,
	    wire_map, wire_addr + cur_offset, wire_ppnum);
	if (kr != KERN_SUCCESS ||
	    wire_ppnum == 0 ||
	    wire_ppnum != user_ppnum) {
		panic("VM_TEST_WIRE_AND_EXTRACT: FAIL\n");
	}

	printf("VM_TEST_WIRE_AND_EXTRACT: PASS\n");
}
#else /* VM_TEST_WIRE_AND_EXTRACT */
#define vm_test_wire_and_extract()
#endif /* VM_TEST_WIRE_AND_EXTRACT */

#if VM_TEST_PAGE_WIRE_OVERFLOW_PANIC
static void
vm_test_page_wire_overflow_panic(void)
{
	vm_object_t object;
	vm_page_t page;

	printf("VM_TEST_PAGE_WIRE_OVERFLOW_PANIC: starting...\n");

	object = vm_object_allocate(PAGE_SIZE);
	vm_object_lock(object);
	page = vm_page_alloc(object, 0x0);
	vm_page_lock_queues();
	do {
		vm_page_wire(page, 1, FALSE);
	} while (page->wire_count != 0);
	vm_page_unlock_queues();
	vm_object_unlock(object);
	panic("FBDP(%p,%p): wire_count overflow not detected\n",
	    object, page);
}
#else /* VM_TEST_PAGE_WIRE_OVERFLOW_PANIC */
#define vm_test_page_wire_overflow_panic()
#endif /* VM_TEST_PAGE_WIRE_OVERFLOW_PANIC */

#if __arm64__ && VM_TEST_KERNEL_OBJECT_FAULT
extern int copyinframe(vm_address_t fp, char *frame, boolean_t is64bit);
static void
vm_test_kernel_object_fault(void)
{
	kern_return_t kr;
	vm_offset_t stack;
	uintptr_t frameb[2];
	int ret;

	kr = kernel_memory_allocate(kernel_map, &stack,
	    kernel_stack_size + (2 * PAGE_SIZE),
	    0,
	    (KMA_KSTACK | KMA_KOBJECT |
	    KMA_GUARD_FIRST | KMA_GUARD_LAST),
	    VM_KERN_MEMORY_STACK);
	if (kr != KERN_SUCCESS) {
		panic("VM_TEST_KERNEL_OBJECT_FAULT: kernel_memory_allocate kr 0x%x\n", kr);
	}
	ret = copyinframe((uintptr_t)stack, (char *)frameb, TRUE);
	if (ret != 0) {
		printf("VM_TEST_KERNEL_OBJECT_FAULT: PASS\n");
	} else {
		printf("VM_TEST_KERNEL_OBJECT_FAULT: FAIL\n");
	}
	vm_map_remove(kernel_map,
	    stack,
	    stack + kernel_stack_size + (2 * PAGE_SIZE),
	    VM_MAP_REMOVE_KUNWIRE);
	stack = 0;
}
#else /* __arm64__ && VM_TEST_KERNEL_OBJECT_FAULT */
#define vm_test_kernel_object_fault()
#endif /* __arm64__ && VM_TEST_KERNEL_OBJECT_FAULT */

#if VM_TEST_DEVICE_PAGER_TRANSPOSE
static void
vm_test_device_pager_transpose(void)
{
	memory_object_t device_pager;
	vm_object_t     anon_object, device_object;
	vm_size_t       size;
	vm_map_offset_t device_mapping;
	kern_return_t   kr;

	size = 3 * PAGE_SIZE;
	anon_object = vm_object_allocate(size);
	assert(anon_object != VM_OBJECT_NULL);
	device_pager = device_pager_setup(NULL, 0, size, 0);
	assert(device_pager != NULL);
	device_object = memory_object_to_vm_object(device_pager);
	assert(device_object != VM_OBJECT_NULL);
#if 0
	/*
	 * Can't actually map this, since another thread might do a
	 * vm_map_enter() that gets coalesced into this object, which
	 * would cause the test to fail.
	 */
	vm_map_offset_t anon_mapping = 0;
	kr = vm_map_enter(kernel_map, &anon_mapping, size, 0,
	    VM_FLAGS_ANYWHERE, VM_MAP_KERNEL_FLAGS_NONE, VM_KERN_MEMORY_NONE,
	    anon_object, 0, FALSE, VM_PROT_DEFAULT, VM_PROT_ALL,
	    VM_INHERIT_DEFAULT);
	assert(kr == KERN_SUCCESS);
#endif
	device_mapping = 0;
	kr = vm_map_enter_mem_object(kernel_map, &device_mapping, size, 0,
	    VM_FLAGS_ANYWHERE,
	    VM_MAP_KERNEL_FLAGS_NONE,
	    VM_KERN_MEMORY_NONE,
	    (void *)device_pager, 0, FALSE,
	    VM_PROT_DEFAULT, VM_PROT_ALL,
	    VM_INHERIT_DEFAULT);
	assert(kr == KERN_SUCCESS);
	memory_object_deallocate(device_pager);

	vm_object_lock(anon_object);
	vm_object_activity_begin(anon_object);
	anon_object->blocked_access = TRUE;
	vm_object_unlock(anon_object);
	vm_object_lock(device_object);
	vm_object_activity_begin(device_object);
	device_object->blocked_access = TRUE;
	vm_object_unlock(device_object);

	assert(anon_object->ref_count == 1);
	assert(!anon_object->named);
	assert(device_object->ref_count == 2);
	assert(device_object->named);

	kr = vm_object_transpose(device_object, anon_object, size);
	assert(kr == KERN_SUCCESS);

	vm_object_lock(anon_object);
	vm_object_activity_end(anon_object);
	anon_object->blocked_access = FALSE;
	vm_object_unlock(anon_object);
	vm_object_lock(device_object);
	vm_object_activity_end(device_object);
	device_object->blocked_access = FALSE;
	vm_object_unlock(device_object);

	assert(anon_object->ref_count == 2);
	assert(anon_object->named);
#if 0
	kr = vm_deallocate(kernel_map, anon_mapping, size);
	assert(kr == KERN_SUCCESS);
#endif
	assert(device_object->ref_count == 1);
	assert(!device_object->named);
	kr = vm_deallocate(kernel_map, device_mapping, size);
	assert(kr == KERN_SUCCESS);

	printf("VM_TEST_DEVICE_PAGER_TRANSPOSE: PASS\n");
}
#else /* VM_TEST_DEVICE_PAGER_TRANSPOSE */
#define vm_test_device_pager_transpose()
#endif /* VM_TEST_DEVICE_PAGER_TRANSPOSE */

void
vm_tests(void)
{
	vm_test_collapse_compressor();
	vm_test_wire_and_extract();
	vm_test_page_wire_overflow_panic();
	vm_test_kernel_object_fault();
	vm_test_device_pager_transpose();
}
