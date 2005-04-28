/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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
#include <mach_kdb.h>
#include <advisory_pageout.h>

#include <mach/mach_types.h>
#include <mach/memory_object.h>
#include <mach/memory_object_default.h>
#include <mach/memory_object_control_server.h>
#include <mach/mach_host_server.h>
#include <mach/upl.h>
#include <mach/vm_map.h>
#include <mach/vm_param.h>
#include <mach/vm_statistics.h>

#include <kern/kern_types.h>
#include <kern/counters.h>
#include <kern/host_statistics.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/thread.h>
#include <kern/xpr.h>
#include <kern/kalloc.h>

#include <machine/vm_tuning.h>

#include <vm/pmap.h>
#include <vm/vm_fault.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h> /* must be last */

/*
 * ENCRYPTED SWAP:
 */
#ifdef __ppc__
#include <ppc/mappings.h>
#endif /* __ppc__ */
#include <../bsd/crypto/aes/aes.h>

extern ipc_port_t	memory_manager_default;


#ifndef VM_PAGEOUT_BURST_ACTIVE_THROTTLE
#define VM_PAGEOUT_BURST_ACTIVE_THROTTLE  10000  /* maximum iterations of the active queue to move pages to inactive */
#endif

#ifndef VM_PAGEOUT_BURST_INACTIVE_THROTTLE
#define VM_PAGEOUT_BURST_INACTIVE_THROTTLE 4096  /* maximum iterations of the inactive queue w/o stealing/cleaning a page */
#endif

#ifndef VM_PAGEOUT_DEADLOCK_RELIEF
#define VM_PAGEOUT_DEADLOCK_RELIEF 100	/* number of pages to move to break deadlock */
#endif

#ifndef VM_PAGEOUT_INACTIVE_RELIEF
#define VM_PAGEOUT_INACTIVE_RELIEF 50	/* minimum number of pages to move to the inactive q */
#endif

#ifndef	VM_PAGE_LAUNDRY_MAX
#define	VM_PAGE_LAUNDRY_MAX	16UL	/* maximum pageouts on a given pageout queue */
#endif	/* VM_PAGEOUT_LAUNDRY_MAX */

#ifndef	VM_PAGEOUT_BURST_WAIT
#define	VM_PAGEOUT_BURST_WAIT	30	/* milliseconds per page */
#endif	/* VM_PAGEOUT_BURST_WAIT */

#ifndef	VM_PAGEOUT_EMPTY_WAIT
#define VM_PAGEOUT_EMPTY_WAIT	200	/* milliseconds */
#endif	/* VM_PAGEOUT_EMPTY_WAIT */

#ifndef	VM_PAGEOUT_DEADLOCK_WAIT
#define VM_PAGEOUT_DEADLOCK_WAIT	300	/* milliseconds */
#endif	/* VM_PAGEOUT_DEADLOCK_WAIT */

#ifndef	VM_PAGEOUT_IDLE_WAIT
#define VM_PAGEOUT_IDLE_WAIT	10	/* milliseconds */
#endif	/* VM_PAGEOUT_IDLE_WAIT */


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

#ifndef	VM_PAGE_INACTIVE_TARGET
#define	VM_PAGE_INACTIVE_TARGET(avail)	((avail) * 1 / 3)
#endif	/* VM_PAGE_INACTIVE_TARGET */

/*
 *	Once the pageout daemon starts running, it keeps going
 *	until vm_page_free_count meets or exceeds vm_page_free_target.
 */

#ifndef	VM_PAGE_FREE_TARGET
#define	VM_PAGE_FREE_TARGET(free)	(15 + (free) / 80)
#endif	/* VM_PAGE_FREE_TARGET */

/*
 *	The pageout daemon always starts running once vm_page_free_count
 *	falls below vm_page_free_min.
 */

#ifndef	VM_PAGE_FREE_MIN
#define	VM_PAGE_FREE_MIN(free)	(10 + (free) / 100)
#endif	/* VM_PAGE_FREE_MIN */

/*
 *	When vm_page_free_count falls below vm_page_free_reserved,
 *	only vm-privileged threads can allocate pages.  vm-privilege
 *	allows the pageout daemon and default pager (and any other
 *	associated threads needed for default pageout) to continue
 *	operation by dipping into the reserved pool of pages.
 */

#ifndef	VM_PAGE_FREE_RESERVED
#define	VM_PAGE_FREE_RESERVED(n)	\
	((6 * VM_PAGE_LAUNDRY_MAX) + (n))
#endif	/* VM_PAGE_FREE_RESERVED */


/*
 * must hold the page queues lock to
 * manipulate this structure
 */
struct vm_pageout_queue {
        queue_head_t	pgo_pending;	/* laundry pages to be processed by pager's iothread */
        unsigned int	pgo_laundry;	/* current count of laundry pages on queue or in flight */
        unsigned int	pgo_maxlaundry;

        unsigned int	pgo_idle:1,	/* iothread is blocked waiting for work to do */
	                pgo_busy:1,     /* iothread is currently processing request from pgo_pending */
			pgo_throttled:1,/* vm_pageout_scan thread needs a wakeup when pgo_laundry drops */
			:0;
};

#define VM_PAGE_Q_THROTTLED(q)		\
        ((q)->pgo_laundry >= (q)->pgo_maxlaundry)


/*
 * Exported variable used to broadcast the activation of the pageout scan
 * Working Set uses this to throttle its use of pmap removes.  In this
 * way, code which runs within memory in an uncontested context does
 * not keep encountering soft faults.
 */

unsigned int	vm_pageout_scan_event_counter = 0;

/*
 * Forward declarations for internal routines.
 */

static void vm_pageout_garbage_collect(int);
static void vm_pageout_iothread_continue(struct vm_pageout_queue *);
static void vm_pageout_iothread_external(void);
static void vm_pageout_iothread_internal(void);
static void vm_pageout_queue_steal(vm_page_t);

extern void vm_pageout_continue(void);
extern void vm_pageout_scan(void);

unsigned int vm_pageout_reserved_internal = 0;
unsigned int vm_pageout_reserved_really = 0;

unsigned int vm_pageout_idle_wait = 0;		/* milliseconds */
unsigned int vm_pageout_empty_wait = 0;		/* milliseconds */
unsigned int vm_pageout_burst_wait = 0;		/* milliseconds */
unsigned int vm_pageout_deadlock_wait = 0;	/* milliseconds */
unsigned int vm_pageout_deadlock_relief = 0;
unsigned int vm_pageout_inactive_relief = 0;
unsigned int vm_pageout_burst_active_throttle = 0;
unsigned int vm_pageout_burst_inactive_throttle = 0;

/*
 *	Protection against zero fill flushing live working sets derived
 *	from existing backing store and files
 */
unsigned int vm_accellerate_zf_pageout_trigger = 400;
unsigned int vm_zf_iterator;
unsigned int vm_zf_iterator_count = 40;
unsigned int last_page_zf;
unsigned int vm_zf_count = 0;

/*
 *	These variables record the pageout daemon's actions:
 *	how many pages it looks at and what happens to those pages.
 *	No locking needed because only one thread modifies the variables.
 */

unsigned int vm_pageout_active = 0;		/* debugging */
unsigned int vm_pageout_inactive = 0;		/* debugging */
unsigned int vm_pageout_inactive_throttled = 0;	/* debugging */
unsigned int vm_pageout_inactive_forced = 0;	/* debugging */
unsigned int vm_pageout_inactive_nolock = 0;	/* debugging */
unsigned int vm_pageout_inactive_avoid = 0;	/* debugging */
unsigned int vm_pageout_inactive_busy = 0;	/* debugging */
unsigned int vm_pageout_inactive_absent = 0;	/* debugging */
unsigned int vm_pageout_inactive_used = 0;	/* debugging */
unsigned int vm_pageout_inactive_clean = 0;	/* debugging */
unsigned int vm_pageout_inactive_dirty = 0;	/* debugging */
unsigned int vm_pageout_dirty_no_pager = 0;	/* debugging */
unsigned int vm_pageout_purged_objects = 0;	/* debugging */
unsigned int vm_stat_discard = 0;		/* debugging */
unsigned int vm_stat_discard_sent = 0;		/* debugging */
unsigned int vm_stat_discard_failure = 0;	/* debugging */
unsigned int vm_stat_discard_throttle = 0;	/* debugging */

unsigned int vm_pageout_scan_active_throttled = 0;
unsigned int vm_pageout_scan_inactive_throttled = 0;
unsigned int vm_pageout_scan_throttle = 0;			/* debugging */
unsigned int vm_pageout_scan_burst_throttle = 0;		/* debugging */
unsigned int vm_pageout_scan_empty_throttle = 0;		/* debugging */
unsigned int vm_pageout_scan_deadlock_detected = 0;		/* debugging */
unsigned int vm_pageout_scan_active_throttle_success = 0;	/* debugging */
unsigned int vm_pageout_scan_inactive_throttle_success = 0;	/* debugging */
/*
 * Backing store throttle when BS is exhausted
 */
unsigned int	vm_backing_store_low = 0;

unsigned int vm_pageout_out_of_line  = 0;
unsigned int vm_pageout_in_place  = 0;

/*
 * ENCRYPTED SWAP:
 * counters and statistics...
 */
unsigned long vm_page_decrypt_counter = 0;
unsigned long vm_page_decrypt_for_upl_counter = 0;
unsigned long vm_page_encrypt_counter = 0;
unsigned long vm_page_encrypt_abort_counter = 0;
unsigned long vm_page_encrypt_already_encrypted_counter = 0;
boolean_t vm_pages_encrypted = FALSE; /* are there encrypted pages ? */


struct	vm_pageout_queue vm_pageout_queue_internal;
struct	vm_pageout_queue vm_pageout_queue_external;


/*
 *	Routine:	vm_backing_store_disable
 *	Purpose:
 *		Suspend non-privileged threads wishing to extend
 *		backing store when we are low on backing store
 *		(Synchronized by caller)
 */
void
vm_backing_store_disable(
	boolean_t	disable)
{
	if(disable) {
		vm_backing_store_low = 1;
	} else {
		if(vm_backing_store_low) {
			vm_backing_store_low = 0;
			thread_wakeup((event_t) &vm_backing_store_low);
		}
	}
}


/*
 *	Routine:	vm_pageout_object_allocate
 *	Purpose:
 *		Allocate an object for use as out-of-line memory in a
 *		data_return/data_initialize message.
 *		The page must be in an unlocked object.
 *
 *		If the page belongs to a trusted pager, cleaning in place
 *		will be used, which utilizes a special "pageout object"
 *		containing private alias pages for the real page frames.
 *		Untrusted pagers use normal out-of-line memory.
 */
vm_object_t
vm_pageout_object_allocate(
	vm_page_t		m,
	vm_size_t		size,
	vm_object_offset_t	offset)
{
	vm_object_t	object = m->object;
	vm_object_t 	new_object;

	assert(object->pager_ready);

	new_object = vm_object_allocate(size);

	if (object->pager_trusted) {
		assert (offset < object->size);

		vm_object_lock(new_object);
		new_object->pageout = TRUE;
		new_object->shadow = object;
		new_object->can_persist = FALSE;
		new_object->copy_strategy = MEMORY_OBJECT_COPY_NONE;
		new_object->shadow_offset = offset;
		vm_object_unlock(new_object);

		/*
		 * Take a paging reference on the object. This will be dropped
		 * in vm_pageout_object_terminate()
		 */
		vm_object_lock(object);
		vm_object_paging_begin(object);
		vm_page_lock_queues();
		vm_page_unlock_queues();
		vm_object_unlock(object);

		vm_pageout_in_place++;
	} else
		vm_pageout_out_of_line++;
	return(new_object);
}

#if MACH_CLUSTER_STATS
unsigned long vm_pageout_cluster_dirtied = 0;
unsigned long vm_pageout_cluster_cleaned = 0;
unsigned long vm_pageout_cluster_collisions = 0;
unsigned long vm_pageout_cluster_clusters = 0;
unsigned long vm_pageout_cluster_conversions = 0;
unsigned long vm_pageout_target_collisions = 0;
unsigned long vm_pageout_target_page_dirtied = 0;
unsigned long vm_pageout_target_page_freed = 0;
#define CLUSTER_STAT(clause)	clause
#else	/* MACH_CLUSTER_STATS */
#define CLUSTER_STAT(clause)
#endif	/* MACH_CLUSTER_STATS */

/* 
 *	Routine:	vm_pageout_object_terminate
 *	Purpose:
 *		Destroy the pageout_object allocated by
 *		vm_pageout_object_allocate(), and perform all of the
 *		required cleanup actions.
 * 
 *	In/Out conditions:
 *		The object must be locked, and will be returned locked.
 */
void
vm_pageout_object_terminate(
	vm_object_t	object)
{
	vm_object_t	shadow_object;
	boolean_t	shadow_internal;

	/*
	 * Deal with the deallocation (last reference) of a pageout object
	 * (used for cleaning-in-place) by dropping the paging references/
	 * freeing pages in the original object.
	 */

	assert(object->pageout);
	shadow_object = object->shadow;
	vm_object_lock(shadow_object);
	shadow_internal = shadow_object->internal;

	while (!queue_empty(&object->memq)) {
		vm_page_t 		p, m;
		vm_object_offset_t	offset;

		p = (vm_page_t) queue_first(&object->memq);

		assert(p->private);
		assert(p->pageout);
		p->pageout = FALSE;
		assert(!p->cleaning);

		offset = p->offset;
		VM_PAGE_FREE(p);
		p = VM_PAGE_NULL;

		m = vm_page_lookup(shadow_object,
			offset + object->shadow_offset);

		if(m == VM_PAGE_NULL)
			continue;
		assert(m->cleaning);
		/* used as a trigger on upl_commit etc to recognize the */
		/* pageout daemon's subseqent desire to pageout a cleaning */
		/* page.  When the bit is on the upl commit code will   */
		/* respect the pageout bit in the target page over the  */
		/* caller's page list indication */
		m->dump_cleaning = FALSE;

		/*
		 * Account for the paging reference taken when
		 * m->cleaning was set on this page.
		 */
		vm_object_paging_end(shadow_object);
		assert((m->dirty) || (m->precious) ||
				(m->busy && m->cleaning));

		/*
		 * Handle the trusted pager throttle.
		 * Also decrement the burst throttle (if external).
		 */
		vm_page_lock_queues();
		if (m->laundry) {
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
		if (m->pageout) {
			assert(m->busy);
			assert(m->wire_count == 1);
			m->cleaning = FALSE;
			m->pageout = FALSE;
#if MACH_CLUSTER_STATS
			if (m->wanted) vm_pageout_target_collisions++;
#endif
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
			if (pmap_disconnect(m->phys_page) & VM_MEM_MODIFIED)
			      m->dirty = TRUE;
			else
			      m->dirty = FALSE;

			if (m->dirty) {
				CLUSTER_STAT(vm_pageout_target_page_dirtied++;)
				vm_page_unwire(m);/* reactivates */
				VM_STAT(reactivations++);
				PAGE_WAKEUP_DONE(m);
			} else {
				CLUSTER_STAT(vm_pageout_target_page_freed++;)
				vm_page_free(m);/* clears busy, etc. */
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
		if (!m->active && !m->inactive && !m->private) {
			if (m->reference)
				vm_page_activate(m);
			else
				vm_page_deactivate(m);
		}
		if((m->busy) && (m->cleaning)) {

			/* the request_page_list case, (COPY_OUT_FROM FALSE) */
			m->busy = FALSE;

			/* We do not re-set m->dirty ! */
			/* The page was busy so no extraneous activity     */
			/* could have occurred. COPY_INTO is a read into the */
			/* new pages. CLEAN_IN_PLACE does actually write   */
			/* out the pages but handling outside of this code */
			/* will take care of resetting dirty. We clear the */
			/* modify however for the Programmed I/O case.     */ 
			pmap_clear_modify(m->phys_page);
			if(m->absent) {
				m->absent = FALSE;
				if(shadow_object->absent_count == 1)
					vm_object_absent_release(shadow_object);
				else
					shadow_object->absent_count--;
			}
			m->overwriting = FALSE;
		} else if (m->overwriting) {
			/* alternate request page list, write to page_list */
			/* case.  Occurs when the original page was wired  */
			/* at the time of the list request */
			assert(m->wire_count != 0);
			vm_page_unwire(m);/* reactivates */
			m->overwriting = FALSE;
		} else {
		/*
		 * Set the dirty state according to whether or not the page was
		 * modified during the pageout. Note that we purposefully do
		 * NOT call pmap_clear_modify since the page is still mapped.
		 * If the page were to be dirtied between the 2 calls, this
		 * this fact would be lost. This code is only necessary to
		 * maintain statistics, since the pmap module is always
		 * consulted if m->dirty is false.
		 */
#if MACH_CLUSTER_STATS
			m->dirty = pmap_is_modified(m->phys_page);

			if (m->dirty)	vm_pageout_cluster_dirtied++;
			else		vm_pageout_cluster_cleaned++;
			if (m->wanted)	vm_pageout_cluster_collisions++;
#else
			m->dirty = 0;
#endif
		}
		m->cleaning = FALSE;

		/*
		 * Wakeup any thread waiting for the page to be un-cleaning.
		 */
		PAGE_WAKEUP(m);
		vm_page_unlock_queues();
	}
	/*
	 * Account for the paging reference taken in vm_paging_object_allocate.
	 */
	vm_object_paging_end(shadow_object);
	vm_object_unlock(shadow_object);

	assert(object->ref_count == 0);
	assert(object->paging_in_progress == 0);
	assert(object->resident_page_count == 0);
	return;
}

/*
 *	Routine:	vm_pageout_setup
 *	Purpose:
 *		Set up a page for pageout (clean & flush).
 *
 *		Move the page to a new object, as part of which it will be
 *		sent to its memory manager in a memory_object_data_write or
 *		memory_object_initialize message.
 *
 *		The "new_object" and "new_offset" arguments
 *		indicate where the page should be moved.
 *
 *	In/Out conditions:
 *		The page in question must not be on any pageout queues,
 *		and must be busy.  The object to which it belongs
 *		must be unlocked, and the caller must hold a paging
 *		reference to it.  The new_object must not be locked.
 *
 *		This routine returns a pointer to a place-holder page,
 *		inserted at the same offset, to block out-of-order
 *		requests for the page.  The place-holder page must
 *		be freed after the data_write or initialize message
 *		has been sent.
 *
 *		The original page is put on a paging queue and marked
 *		not busy on exit.
 */
vm_page_t
vm_pageout_setup(
	register vm_page_t	m,
	register vm_object_t	new_object,
	vm_object_offset_t	new_offset)
{
	register vm_object_t	old_object = m->object;
	vm_object_offset_t	paging_offset;
	vm_object_offset_t	offset;
	register vm_page_t	holding_page;
	register vm_page_t	new_m;
	boolean_t		need_to_wire = FALSE;


        XPR(XPR_VM_PAGEOUT,
     "vm_pageout_setup, obj 0x%X off 0x%X page 0x%X new obj 0x%X offset 0x%X\n",
                (integer_t)m->object, (integer_t)m->offset, 
		(integer_t)m, (integer_t)new_object, 
		(integer_t)new_offset);
	assert(m && m->busy && !m->absent && !m->fictitious && !m->error &&
		!m->restart);

	assert(m->dirty || m->precious);

	/*
	 *	Create a place-holder page where the old one was, to prevent
	 *	attempted pageins of this page while we're unlocked.
	 */
	VM_PAGE_GRAB_FICTITIOUS(holding_page);

	vm_object_lock(old_object);

	offset = m->offset;
	paging_offset = offset + old_object->paging_offset;

	if (old_object->pager_trusted) {
		/*
		 * This pager is trusted, so we can clean this page
		 * in place. Leave it in the old object, and mark it
		 * cleaning & pageout.
		 */
		new_m = holding_page;
		holding_page = VM_PAGE_NULL;

		/*
		 * Set up new page to be private shadow of real page.
		 */
		new_m->phys_page = m->phys_page;
		new_m->fictitious = FALSE;
		new_m->pageout = TRUE;

		/*
		 * Mark real page as cleaning (indicating that we hold a
		 * paging reference to be released via m_o_d_r_c) and
		 * pageout (indicating that the page should be freed
		 * when the pageout completes).
		 */
		pmap_clear_modify(m->phys_page);
		vm_page_lock_queues();
		new_m->private = TRUE;
		vm_page_wire(new_m);
		m->cleaning = TRUE;
		m->pageout = TRUE;

		vm_page_wire(m);
		assert(m->wire_count == 1);
		vm_page_unlock_queues();

		m->dirty = TRUE;
		m->precious = FALSE;
		m->page_lock = VM_PROT_NONE;
		m->unusual = FALSE;
		m->unlock_request = VM_PROT_NONE;
	} else {
		/*
		 * Cannot clean in place, so rip the old page out of the
		 * object, and stick the holding page in. Set new_m to the
		 * page in the new object.
		 */
		vm_page_lock_queues();
		VM_PAGE_QUEUES_REMOVE(m);
		vm_page_remove(m);

		vm_page_insert(holding_page, old_object, offset);
		vm_page_unlock_queues();

		m->dirty = TRUE;
		m->precious = FALSE;
		new_m = m;
		new_m->page_lock = VM_PROT_NONE;
		new_m->unlock_request = VM_PROT_NONE;

		if (old_object->internal)
			need_to_wire = TRUE;
	}
	/*
	 *	Record that this page has been written out
	 */
#if	MACH_PAGEMAP
	vm_external_state_set(old_object->existence_map, offset);
#endif	/* MACH_PAGEMAP */

	vm_object_unlock(old_object);

	vm_object_lock(new_object);

	/*
	 *	Put the page into the new object. If it is a not wired
	 *	(if it's the real page) it will be activated.
	 */

	vm_page_lock_queues();
	vm_page_insert(new_m, new_object, new_offset);
	if (need_to_wire)
		vm_page_wire(new_m);
	else
		vm_page_activate(new_m);
	PAGE_WAKEUP_DONE(new_m);
	vm_page_unlock_queues();

	vm_object_unlock(new_object);

	/*
	 *	Return the placeholder page to simplify cleanup.
	 */
	return (holding_page);
}

/*
 * Routine:	vm_pageclean_setup
 *
 * Purpose:	setup a page to be cleaned (made non-dirty), but not
 *		necessarily flushed from the VM page cache.
 *		This is accomplished by cleaning in place.
 *
 *		The page must not be busy, and the object and page
 *		queues must be locked.
 *		
 */
void
vm_pageclean_setup(
	vm_page_t		m,
	vm_page_t		new_m,
	vm_object_t		new_object,
	vm_object_offset_t	new_offset)
{
	vm_object_t old_object = m->object;
	assert(!m->busy);
	assert(!m->cleaning);

	XPR(XPR_VM_PAGEOUT,
    "vm_pageclean_setup, obj 0x%X off 0x%X page 0x%X new 0x%X new_off 0x%X\n",
		(integer_t)old_object, m->offset, (integer_t)m, 
		(integer_t)new_m, new_offset);

	pmap_clear_modify(m->phys_page);
	vm_object_paging_begin(old_object);

	/*
	 *	Record that this page has been written out
	 */
#if	MACH_PAGEMAP
	vm_external_state_set(old_object->existence_map, m->offset);
#endif	/*MACH_PAGEMAP*/

	/*
	 * Mark original page as cleaning in place.
	 */
	m->cleaning = TRUE;
	m->dirty = TRUE;
	m->precious = FALSE;

	/*
	 * Convert the fictitious page to a private shadow of
	 * the real page.
	 */
	assert(new_m->fictitious);
	new_m->fictitious = FALSE;
	new_m->private = TRUE;
	new_m->pageout = TRUE;
	new_m->phys_page = m->phys_page;
	vm_page_wire(new_m);

	vm_page_insert(new_m, new_object, new_offset);
	assert(!new_m->wanted);
	new_m->busy = FALSE;
}

void
vm_pageclean_copy(
	vm_page_t		m,
	vm_page_t		new_m,
	vm_object_t		new_object,
	vm_object_offset_t	new_offset)
{
	XPR(XPR_VM_PAGEOUT,
	"vm_pageclean_copy, page 0x%X new_m 0x%X new_obj 0x%X offset 0x%X\n",
		m, new_m, new_object, new_offset, 0);

	assert((!m->busy) && (!m->cleaning));

	assert(!new_m->private && !new_m->fictitious);

	pmap_clear_modify(m->phys_page);

	m->busy = TRUE;
	vm_object_paging_begin(m->object);
	vm_page_unlock_queues();
	vm_object_unlock(m->object);

	/*
	 * Copy the original page to the new page.
	 */
	vm_page_copy(m, new_m);

	/*
	 * Mark the old page as clean. A request to pmap_is_modified
	 * will get the right answer.
	 */
	vm_object_lock(m->object);
	m->dirty = FALSE;

	vm_object_paging_end(m->object);

	vm_page_lock_queues();
	if (!m->active && !m->inactive)
		vm_page_activate(m);
	PAGE_WAKEUP_DONE(m);

	vm_page_insert(new_m, new_object, new_offset);
	vm_page_activate(new_m);
	new_m->busy = FALSE;	/* No other thread can be waiting */
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
	vm_page_t	m)
{
	vm_object_t		object;
	vm_object_offset_t	paging_offset;
	vm_page_t		holding_page;


	XPR(XPR_VM_PAGEOUT,
		"vm_pageout_initialize_page, page 0x%X\n",
		(integer_t)m, 0, 0, 0, 0);
	assert(m->busy);

	/*
	 *	Verify that we really want to clean this page
	 */
	assert(!m->absent);
	assert(!m->error);
	assert(m->dirty);

	/*
	 *	Create a paging reference to let us play with the object.
	 */
	object = m->object;
	paging_offset = m->offset + object->paging_offset;
	vm_object_paging_begin(object);
	if (m->absent || m->error || m->restart ||
	    (!m->dirty && !m->precious)) {
		VM_PAGE_FREE(m);
		panic("reservation without pageout?"); /* alan */
	     vm_object_unlock(object);
		return;
	}

	/* set the page for future call to vm_fault_list_request */
	holding_page = NULL;
	vm_page_lock_queues();
	pmap_clear_modify(m->phys_page);
	m->dirty = TRUE;
	m->busy = TRUE;
	m->list_req_pending = TRUE;
	m->cleaning = TRUE;
	m->pageout = TRUE;
	vm_page_wire(m);
	vm_page_unlock_queues();
	vm_object_unlock(object);

	/*
	 *	Write the data to its pager.
	 *	Note that the data is passed by naming the new object,
	 *	not a virtual address; the pager interface has been
	 *	manipulated to use the "internal memory" data type.
	 *	[The object reference from its allocation is donated
	 *	to the eventual recipient.]
	 */
	memory_object_data_initialize(object->pager,
					paging_offset,
					PAGE_SIZE);

	vm_object_lock(object);
}

#if	MACH_CLUSTER_STATS
#define MAXCLUSTERPAGES	16
struct {
	unsigned long pages_in_cluster;
	unsigned long pages_at_higher_offsets;
	unsigned long pages_at_lower_offsets;
} cluster_stats[MAXCLUSTERPAGES];
#endif	/* MACH_CLUSTER_STATS */

boolean_t allow_clustered_pageouts = FALSE;

/*
 * vm_pageout_cluster:
 *
 * Given a page, queue it to the appropriate I/O thread,
 * which will page it out and attempt to clean adjacent pages
 * in the same operation.
 *
 * The page must be busy, and the object and queues locked. We will take a
 * paging reference to prevent deallocation or collapse when we
 * release the object lock back at the call site.  The I/O thread
 * is responsible for consuming this reference
 *
 * The page must not be on any pageout queue.
 */

void
vm_pageout_cluster(vm_page_t m)
{
	vm_object_t	object = m->object;
        struct		vm_pageout_queue *q;


	XPR(XPR_VM_PAGEOUT,
		"vm_pageout_cluster, object 0x%X offset 0x%X page 0x%X\n",
		(integer_t)object, m->offset, (integer_t)m, 0, 0);

	/*
	 * Only a certain kind of page is appreciated here.
	 */
	assert(m->busy && (m->dirty || m->precious) && (m->wire_count == 0));
	assert(!m->cleaning && !m->pageout && !m->inactive && !m->active);

	/*
	 * protect the object from collapse - 
	 * locking in the object's paging_offset.
	 */
	vm_object_paging_begin(object);

	/*
	 * set the page for future call to vm_fault_list_request
	 * page should already be marked busy
	 */
	vm_page_wire(m);
	m->list_req_pending = TRUE;
	m->cleaning = TRUE;
	m->pageout = TRUE;
        m->laundry = TRUE;

	if (object->internal == TRUE)
	        q = &vm_pageout_queue_internal;
	else
	        q = &vm_pageout_queue_external;
	q->pgo_laundry++;

	m->pageout_queue = TRUE;
	queue_enter(&q->pgo_pending, m, vm_page_t, pageq);
	
	if (q->pgo_idle == TRUE) {
	        q->pgo_idle = FALSE;
	        thread_wakeup((event_t) &q->pgo_pending);
	}
}


unsigned long vm_pageout_throttle_up_count = 0;

/*
 * A page is back from laundry.  See if there are some pages waiting to
 * go to laundry and if we can let some of them go now.
 *
 * Object and page queues must be locked.
 */
void
vm_pageout_throttle_up(
	vm_page_t	m)
{
        struct vm_pageout_queue *q;

	vm_pageout_throttle_up_count++;

	assert(m->laundry);
	assert(m->object != VM_OBJECT_NULL);
	assert(m->object != kernel_object);

	if (m->object->internal == TRUE)
	        q = &vm_pageout_queue_internal;
	else
	        q = &vm_pageout_queue_external;

	m->laundry = FALSE;
	q->pgo_laundry--;

	if (q->pgo_throttled == TRUE) {
	        q->pgo_throttled = FALSE;
	        thread_wakeup((event_t) &q->pgo_laundry);
	}
}


/*
 *	vm_pageout_scan does the dirty work for the pageout daemon.
 *	It returns with vm_page_queue_free_lock held and
 *	vm_page_free_wanted == 0.
 */

#define DELAYED_UNLOCK_LIMIT  (3 * MAX_UPL_TRANSFER)

#define	FCS_IDLE		0
#define FCS_DELAYED		1
#define FCS_DEADLOCK_DETECTED	2

struct flow_control {
        int		state;
        mach_timespec_t	ts;
};

extern kern_return_t	sysclk_gettime(mach_timespec_t *);


void
vm_pageout_scan(void)
{
	unsigned int loop_count = 0;
	unsigned int inactive_burst_count = 0;
	unsigned int active_burst_count = 0;
	vm_page_t   local_freeq = 0;
	int         local_freed = 0;
	int         delayed_unlock = 0;
	int         need_internal_inactive = 0;
	int	    refmod_state = 0;
        int	vm_pageout_deadlock_target = 0;
	struct	vm_pageout_queue *iq;
	struct	vm_pageout_queue *eq;
	struct  flow_control	flow_control;
        boolean_t active_throttled = FALSE;
        boolean_t inactive_throttled = FALSE;
	mach_timespec_t		ts;
	unsigned int msecs = 0;
	vm_object_t	object;
	

	flow_control.state = FCS_IDLE;
	iq = &vm_pageout_queue_internal;
	eq = &vm_pageout_queue_external;

        XPR(XPR_VM_PAGEOUT, "vm_pageout_scan\n", 0, 0, 0, 0, 0);

/*???*/	/*
	 *	We want to gradually dribble pages from the active queue
	 *	to the inactive queue.  If we let the inactive queue get
	 *	very small, and then suddenly dump many pages into it,
	 *	those pages won't get a sufficient chance to be referenced
	 *	before we start taking them from the inactive queue.
	 *
	 *	We must limit the rate at which we send pages to the pagers.
	 *	data_write messages consume memory, for message buffers and
	 *	for map-copy objects.  If we get too far ahead of the pagers,
	 *	we can potentially run out of memory.
	 *
	 *	We can use the laundry count to limit directly the number
	 *	of pages outstanding to the default pager.  A similar
	 *	strategy for external pagers doesn't work, because
	 *	external pagers don't have to deallocate the pages sent them,
	 *	and because we might have to send pages to external pagers
	 *	even if they aren't processing writes.  So we also
	 *	use a burst count to limit writes to external pagers.
	 *
	 *	When memory is very tight, we can't rely on external pagers to
	 *	clean pages.  They probably aren't running, because they
	 *	aren't vm-privileged.  If we kept sending dirty pages to them,
	 *	we could exhaust the free list.
	 */
	vm_page_lock_queues();
	delayed_unlock = 1;


Restart:
	/*
	 *	Recalculate vm_page_inactivate_target.
	 */
	vm_page_inactive_target = VM_PAGE_INACTIVE_TARGET(vm_page_active_count +
							  vm_page_inactive_count);
	object = NULL;

	for (;;) {
		vm_page_t m;

		if (delayed_unlock == 0)
		        vm_page_lock_queues();

		active_burst_count = vm_page_active_count;

		if (active_burst_count > vm_pageout_burst_active_throttle)
		        active_burst_count = vm_pageout_burst_active_throttle;

		/*
		 *	Move pages from active to inactive.
		 */
		while ((need_internal_inactive ||
			   vm_page_inactive_count < vm_page_inactive_target) &&
		       !queue_empty(&vm_page_queue_active) &&
		       ((active_burst_count--) > 0)) {

			vm_pageout_active++;

			m = (vm_page_t) queue_first(&vm_page_queue_active);

			assert(m->active && !m->inactive);
			assert(!m->laundry);
			assert(m->object != kernel_object);

			/*
			 * Try to lock object; since we've already got the
			 * page queues lock, we can only 'try' for this one.
			 * if the 'try' fails, we need to do a mutex_pause
			 * to allow the owner of the object lock a chance to
			 * run... otherwise, we're likely to trip over this
			 * object in the same state as we work our way through
			 * the queue... clumps of pages associated with the same
			 * object are fairly typical on the inactive and active queues
			 */
			if (m->object != object) {
			        if (object != NULL) {
				        vm_object_unlock(object);
					object = NULL;
				}
			        if (!vm_object_lock_try(m->object)) {
				        /*
					 * move page to end of active queue and continue
					 */
				        queue_remove(&vm_page_queue_active, m,
						     vm_page_t, pageq);
					queue_enter(&vm_page_queue_active, m,
						    vm_page_t, pageq);
					
					goto done_with_activepage;
				}
				object = m->object;
			}
			/*
			 * if the page is BUSY, then we pull it
			 * off the active queue and leave it alone.
			 * when BUSY is cleared, it will get stuck
			 * back on the appropriate queue
			 */
			if (m->busy) {
				queue_remove(&vm_page_queue_active, m,
					     vm_page_t, pageq);
				m->pageq.next = NULL;
				m->pageq.prev = NULL;

				if (!m->fictitious)
					vm_page_active_count--;
				m->active = FALSE;

				goto done_with_activepage;
			}
			if (need_internal_inactive) {
			        /*
				 * If we're unable to make forward progress
				 * with the current set of pages on the 
				 * inactive queue due to busy objects or
				 * throttled pageout queues, then 
				 * move a page that is already clean
				 * or belongs to a pageout queue that
				 * isn't currently throttled
				 */
			        active_throttled = FALSE;

			        if (object->internal) {
				        if ((VM_PAGE_Q_THROTTLED(iq) || !IP_VALID(memory_manager_default)))
					        active_throttled = TRUE;
				} else if (VM_PAGE_Q_THROTTLED(eq)) {
				                active_throttled = TRUE;
				}
				if (active_throttled == TRUE) {
				        if (!m->dirty) {
					        refmod_state = pmap_get_refmod(m->phys_page);
		  
						if (refmod_state & VM_MEM_REFERENCED)
						        m->reference = TRUE;
						if (refmod_state & VM_MEM_MODIFIED)
						        m->dirty = TRUE;
					}
					if (m->dirty || m->precious) {
					        /*
						 * page is dirty and targets a THROTTLED queue
						 * so all we can do is move it back to the
						 * end of the active queue to get it out
						 * of the way
						 */
						queue_remove(&vm_page_queue_active, m,
							     vm_page_t, pageq);
						queue_enter(&vm_page_queue_active, m,
							    vm_page_t, pageq);

						vm_pageout_scan_active_throttled++;

						goto done_with_activepage;
					}
				}
				vm_pageout_scan_active_throttle_success++;
				need_internal_inactive--;
			}
			/*
			 *	Deactivate the page while holding the object
			 *	locked, so we know the page is still not busy.
			 *	This should prevent races between pmap_enter
			 *	and pmap_clear_reference.  The page might be
			 *	absent or fictitious, but vm_page_deactivate
			 *	can handle that.
			 */
			vm_page_deactivate(m);
done_with_activepage:
			if (delayed_unlock++ > DELAYED_UNLOCK_LIMIT) {

			        if (object != NULL) {
				        vm_object_unlock(object);
					object = NULL;
				}
			        if (local_freeq) {
				        vm_page_free_list(local_freeq);
					
					local_freeq = 0;
					local_freed = 0;
				}
			        delayed_unlock = 0;
			        vm_page_unlock_queues();

				mutex_pause();
				vm_page_lock_queues();
				/*
				 * continue the while loop processing
				 * the active queue... need to hold
				 * the page queues lock
				 */
				continue;
			}
		}



		/**********************************************************************
		 * above this point we're playing with the active queue
		 * below this point we're playing with the throttling mechanisms
		 * and the inactive queue
		 **********************************************************************/



		/*
		 *	We are done if we have met our target *and*
		 *	nobody is still waiting for a page.
		 */
		if (vm_page_free_count + local_freed >= vm_page_free_target) {
			if (object != NULL) {
			        vm_object_unlock(object);
				object = NULL;
			}
			if (local_freeq) {
			        vm_page_free_list(local_freeq);
					
				local_freeq = 0;
				local_freed = 0;
			}
		        mutex_lock(&vm_page_queue_free_lock);

			if ((vm_page_free_count >= vm_page_free_target) &&
			          (vm_page_free_wanted == 0)) {

			        vm_page_unlock_queues();

				thread_wakeup((event_t) &vm_pageout_garbage_collect);
				return;
			}
			mutex_unlock(&vm_page_queue_free_lock);
		}


		/*
		 * Sometimes we have to pause:
		 *	1) No inactive pages - nothing to do.
		 *	2) Flow control - default pageout queue is full
		 *	3) Loop control - no acceptable pages found on the inactive queue
		 *         within the last vm_pageout_burst_inactive_throttle iterations
		 */
		if ((queue_empty(&vm_page_queue_inactive) && queue_empty(&vm_page_queue_zf))) {
		        vm_pageout_scan_empty_throttle++;
			msecs = vm_pageout_empty_wait;
			goto vm_pageout_scan_delay;

		} else if (inactive_burst_count >= vm_pageout_burst_inactive_throttle) {
		        vm_pageout_scan_burst_throttle++;
			msecs = vm_pageout_burst_wait;
			goto vm_pageout_scan_delay;

		} else if (VM_PAGE_Q_THROTTLED(iq)) {

		        switch (flow_control.state) {

			case FCS_IDLE:
reset_deadlock_timer:
			        ts.tv_sec = vm_pageout_deadlock_wait / 1000;
				ts.tv_nsec = (vm_pageout_deadlock_wait % 1000) * 1000 * NSEC_PER_USEC;
				sysclk_gettime(&flow_control.ts);
				ADD_MACH_TIMESPEC(&flow_control.ts, &ts);
				
				flow_control.state = FCS_DELAYED;
				msecs = vm_pageout_deadlock_wait;

				break;
					
			case FCS_DELAYED:
			        sysclk_gettime(&ts);

				if (CMP_MACH_TIMESPEC(&ts, &flow_control.ts) >= 0) {
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
					 * stop moving pagings and allow the system to run to see what
					 * state it settles into.
					 */
				        vm_pageout_deadlock_target = vm_pageout_deadlock_relief + vm_page_free_wanted;
					vm_pageout_scan_deadlock_detected++;
					flow_control.state = FCS_DEADLOCK_DETECTED;

					thread_wakeup((event_t) &vm_pageout_garbage_collect);
					goto consider_inactive;
				}
				/*
				 * just resniff instead of trying
				 * to compute a new delay time... we're going to be
				 * awakened immediately upon a laundry completion,
				 * so we won't wait any longer than necessary
				 */
				msecs = vm_pageout_idle_wait;
				break;

			case FCS_DEADLOCK_DETECTED:
			        if (vm_pageout_deadlock_target)
				        goto consider_inactive;
				goto reset_deadlock_timer;

			}
			vm_pageout_scan_throttle++;
			iq->pgo_throttled = TRUE;
vm_pageout_scan_delay:
			if (object != NULL) {
			        vm_object_unlock(object);
				object = NULL;
			}
			if (local_freeq) {
			        vm_page_free_list(local_freeq);
					
				local_freeq = 0;
				local_freed = 0;
			}
			assert_wait_timeout((event_t) &iq->pgo_laundry, THREAD_INTERRUPTIBLE, msecs, 1000*NSEC_PER_USEC);

			counter(c_vm_pageout_scan_block++);

			vm_page_unlock_queues();
				
			thread_block(THREAD_CONTINUE_NULL);

			vm_page_lock_queues();
			delayed_unlock = 1;

			iq->pgo_throttled = FALSE;

			if (loop_count >= vm_page_inactive_count) {
			        if (VM_PAGE_Q_THROTTLED(eq) || VM_PAGE_Q_THROTTLED(iq)) {
					/*
					 * Make sure we move enough "appropriate"
					 * pages to the inactive queue before trying
					 * again.
					 */
					need_internal_inactive = vm_pageout_inactive_relief;
				}
				loop_count = 0;
			}
			inactive_burst_count = 0;

			goto Restart;
			/*NOTREACHED*/
		}


		flow_control.state = FCS_IDLE;
consider_inactive:
		loop_count++;
		inactive_burst_count++;
		vm_pageout_inactive++;

		if (!queue_empty(&vm_page_queue_inactive)) {
		        m = (vm_page_t) queue_first(&vm_page_queue_inactive);
			
			if (m->clustered && (m->no_isync == TRUE)) {
			        goto use_this_page;
			}
		}
		if (vm_zf_count < vm_accellerate_zf_pageout_trigger) {
			vm_zf_iterator = 0;
		} else {
			last_page_zf = 0;
			if((vm_zf_iterator+=1) >= vm_zf_iterator_count) {
					vm_zf_iterator = 0;
			}
		}
		if (queue_empty(&vm_page_queue_zf) ||
				(((last_page_zf) || (vm_zf_iterator == 0)) &&
				!queue_empty(&vm_page_queue_inactive))) {
			m = (vm_page_t) queue_first(&vm_page_queue_inactive);
			last_page_zf = 0;
		} else {
			m = (vm_page_t) queue_first(&vm_page_queue_zf);
			last_page_zf = 1;
		}
use_this_page:
		assert(!m->active && m->inactive);
		assert(!m->laundry);
		assert(m->object != kernel_object);

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
		if (m->object != object) {
		        if (object != NULL) {
			        vm_object_unlock(object);
				object = NULL;
			}
			if (!vm_object_lock_try(m->object)) {
			        /*
				 *	Move page to end and continue.
				 * 	Don't re-issue ticket
				 */
			        if (m->zero_fill) {
				        queue_remove(&vm_page_queue_zf, m,
						     vm_page_t, pageq);
					queue_enter(&vm_page_queue_zf, m,
						    vm_page_t, pageq);
				} else {
				        queue_remove(&vm_page_queue_inactive, m,
						     vm_page_t, pageq);
					queue_enter(&vm_page_queue_inactive, m,
						    vm_page_t, pageq);
				}
				vm_pageout_inactive_nolock++;

				/*
				 * force us to dump any collected free pages
				 * and to pause before moving on
				 */
				delayed_unlock = DELAYED_UNLOCK_LIMIT + 1;

				goto done_with_inactivepage;
			}
			object = m->object;
		}
		/*
		 * If the page belongs to a purgable object with no pending copies
		 * against it, then we reap all of the pages in the object
		 * and note that the object has been "emptied".  It'll be up to the
		 * application the discover this and recreate its contents if desired.
		 */
		if ((object->purgable == VM_OBJECT_PURGABLE_VOLATILE ||
		     object->purgable == VM_OBJECT_PURGABLE_EMPTY) &&
		    object->copy == VM_OBJECT_NULL) {

			(void) vm_object_purge(object);
			vm_pageout_purged_objects++;
			/*
			 * we've just taken all of the pages from this object,
			 * so drop the lock now since we're not going to find
			 * any more pages belonging to it anytime soon
			 */
		        vm_object_unlock(object);
			object = NULL;

			inactive_burst_count = 0;

			goto done_with_inactivepage;
		}

		/*
		 *	Paging out pages of external objects which
		 *	are currently being created must be avoided.
		 *	The pager may claim for memory, thus leading to a
		 *	possible dead lock between it and the pageout thread,
		 *	if such pages are finally chosen. The remaining assumption
		 *	is that there will finally be enough available pages in the
		 *	inactive pool to page out in order to satisfy all memory
		 *	claimed by the thread which concurrently creates the pager.
		 */
		if (!object->pager_initialized && object->pager_created) {
			/*
			 *	Move page to end and continue, hoping that
			 *	there will be enough other inactive pages to
			 *	page out so that the thread which currently
			 *	initializes the pager will succeed.
			 *	Don't re-grant the ticket, the page should
			 *	pulled from the queue and paged out whenever
			 *	one of its logically adjacent fellows is
			 *	targeted.
			 */
			if (m->zero_fill) {
				queue_remove(&vm_page_queue_zf, m,
					     vm_page_t, pageq);
				queue_enter(&vm_page_queue_zf, m,
					    vm_page_t, pageq);
				last_page_zf = 1;
				vm_zf_iterator = vm_zf_iterator_count - 1;
			} else {
				queue_remove(&vm_page_queue_inactive, m,
					     vm_page_t, pageq);
				queue_enter(&vm_page_queue_inactive, m,
					    vm_page_t, pageq);
				last_page_zf = 0;
				vm_zf_iterator = 1;
			}
			vm_pageout_inactive_avoid++;

			goto done_with_inactivepage;
		}
		/*
		 *	Remove the page from the inactive list.
		 */
		if (m->zero_fill) {
			queue_remove(&vm_page_queue_zf, m, vm_page_t, pageq);
		} else {
			queue_remove(&vm_page_queue_inactive, m, vm_page_t, pageq);
		}
		m->pageq.next = NULL;
		m->pageq.prev = NULL;
		m->inactive = FALSE;
		if (!m->fictitious)
			vm_page_inactive_count--;

		if (m->busy || !object->alive) {
			/*
			 *	Somebody is already playing with this page.
			 *	Leave it off the pageout queues.
			 */
			vm_pageout_inactive_busy++;

			goto done_with_inactivepage;
		}

		/*
		 *	If it's absent or in error, we can reclaim the page.
		 */

		if (m->absent || m->error) {
			vm_pageout_inactive_absent++;
reclaim_page:
			if (vm_pageout_deadlock_target) {
				vm_pageout_scan_inactive_throttle_success++;
			        vm_pageout_deadlock_target--;
			}
			if (m->tabled)
			        vm_page_remove(m);    /* clears tabled, object, offset */
			if (m->absent)
			        vm_object_absent_release(object);

			assert(m->pageq.next == NULL &&
			       m->pageq.prev == NULL);
			m->pageq.next = (queue_entry_t)local_freeq;
			local_freeq = m;
			local_freed++;

			inactive_burst_count = 0;

			goto done_with_inactivepage;
		}

		assert(!m->private);
		assert(!m->fictitious);

		/*
		 *	If already cleaning this page in place, convert from
		 *	"adjacent" to "target". We can leave the page mapped,
		 *	and vm_pageout_object_terminate will determine whether
		 *	to free or reactivate.
		 */

		if (m->cleaning) {
			m->busy = TRUE;
			m->pageout = TRUE;
			m->dump_cleaning = TRUE;
			vm_page_wire(m);

			CLUSTER_STAT(vm_pageout_cluster_conversions++);

			inactive_burst_count = 0;

			goto done_with_inactivepage;
		}

		/*
		 *	If it's being used, reactivate.
		 *	(Fictitious pages are either busy or absent.)
		 */
		if ( (!m->reference) ) {
		        refmod_state = pmap_get_refmod(m->phys_page);
		  
		        if (refmod_state & VM_MEM_REFERENCED)
			        m->reference = TRUE;
		        if (refmod_state & VM_MEM_MODIFIED)
			        m->dirty = TRUE;
		}
		if (m->reference) {
was_referenced:
			vm_page_activate(m);
			VM_STAT(reactivations++);

			vm_pageout_inactive_used++;
			last_page_zf = 0;
			inactive_burst_count = 0;

			goto done_with_inactivepage;
		}

                XPR(XPR_VM_PAGEOUT,
                "vm_pageout_scan, replace object 0x%X offset 0x%X page 0x%X\n",
                (integer_t)object, (integer_t)m->offset, (integer_t)m, 0,0);

		/*
		 * we've got a candidate page to steal...
		 *
		 * m->dirty is up to date courtesy of the
		 * preceding check for m->reference... if 
		 * we get here, then m->reference had to be
		 * FALSE which means we did a pmap_get_refmod
		 * and updated both m->reference and m->dirty
		 *
		 * if it's dirty or precious we need to
		 * see if the target queue is throtttled
		 * it if is, we need to skip over it by moving it back
		 * to the end of the inactive queue
		 */
		inactive_throttled = FALSE;

		if (m->dirty || m->precious) {
		        if (object->internal) {
			        if ((VM_PAGE_Q_THROTTLED(iq) || !IP_VALID(memory_manager_default)))
				        inactive_throttled = TRUE;
			} else if (VM_PAGE_Q_THROTTLED(eq)) {
			                inactive_throttled = TRUE;
			}
		}
		if (inactive_throttled == TRUE) {
			if (m->zero_fill) {
			        queue_enter(&vm_page_queue_zf, m,
					    vm_page_t, pageq);
			} else {
			        queue_enter(&vm_page_queue_inactive, m,
					    vm_page_t, pageq);
			}
			if (!m->fictitious)
			        vm_page_inactive_count++;
			m->inactive = TRUE;

			vm_pageout_scan_inactive_throttled++;

			goto done_with_inactivepage;
		}
		/*
		 * we've got a page that we can steal...
		 * eliminate all mappings and make sure
		 * we have the up-to-date modified state
		 * first take the page BUSY, so that no new
		 * mappings can be made
		 */
		m->busy = TRUE;
		
		/*
		 * if we need to do a pmap_disconnect then we
		 * need to re-evaluate m->dirty since the pmap_disconnect
		 * provides the true state atomically... the 
		 * page was still mapped up to the pmap_disconnect
		 * and may have been dirtied at the last microsecond
		 *
		 * we also check for the page being referenced 'late'
		 * if it was, we first need to do a WAKEUP_DONE on it
		 * since we already set m->busy = TRUE, before 
		 * going off to reactivate it
		 *
		 * if we don't need the pmap_disconnect, then
		 * m->dirty is up to date courtesy of the
		 * earlier check for m->reference... if 
		 * we get here, then m->reference had to be
		 * FALSE which means we did a pmap_get_refmod
		 * and updated both m->reference and m->dirty...
		 */
		if (m->no_isync == FALSE) {
		        refmod_state = pmap_disconnect(m->phys_page);

		        if (refmod_state & VM_MEM_MODIFIED)
			        m->dirty = TRUE;
		        if (refmod_state & VM_MEM_REFERENCED) {
			        m->reference = TRUE;

				PAGE_WAKEUP_DONE(m);
				goto was_referenced;
			}
		}
		/*
		 *	If it's clean and not precious, we can free the page.
		 */
		if (!m->dirty && !m->precious) {
			vm_pageout_inactive_clean++;
			goto reclaim_page;
		}
		vm_pageout_cluster(m);

		vm_pageout_inactive_dirty++;

		inactive_burst_count = 0;

done_with_inactivepage:
		if (delayed_unlock++ > DELAYED_UNLOCK_LIMIT) {

		        if (object != NULL) {
			        vm_object_unlock(object);
				object = NULL;
			}
		        if (local_freeq) {
			        vm_page_free_list(local_freeq);
				
				local_freeq = 0;
				local_freed = 0;
			}
		        delayed_unlock = 0;
			vm_page_unlock_queues();
			mutex_pause();
		}
		/*
		 * back to top of pageout scan loop
		 */
	}
}


int vm_page_free_count_init;

void
vm_page_free_reserve(
	int pages)
{
	int		free_after_reserve;

	vm_page_free_reserved += pages;

	free_after_reserve = vm_page_free_count_init - vm_page_free_reserved;

	vm_page_free_min = vm_page_free_reserved +
		VM_PAGE_FREE_MIN(free_after_reserve);

	vm_page_free_target = vm_page_free_reserved +
		VM_PAGE_FREE_TARGET(free_after_reserve);

	if (vm_page_free_target < vm_page_free_min + 5)
		vm_page_free_target = vm_page_free_min + 5;
}

/*
 *	vm_pageout is the high level pageout daemon.
 */

void
vm_pageout_continue(void)
{
	vm_pageout_scan_event_counter++;
	vm_pageout_scan();
	/* we hold vm_page_queue_free_lock now */
	assert(vm_page_free_wanted == 0);
	assert_wait((event_t) &vm_page_free_wanted, THREAD_UNINT);
	mutex_unlock(&vm_page_queue_free_lock);

	counter(c_vm_pageout_block++);
	thread_block((thread_continue_t)vm_pageout_continue);
	/*NOTREACHED*/
}


/*
 * must be called with the
 * queues and object locks held
 */
static void
vm_pageout_queue_steal(vm_page_t m)
{
        struct vm_pageout_queue *q;

	if (m->object->internal == TRUE)
	        q = &vm_pageout_queue_internal;
	else
	        q = &vm_pageout_queue_external;

	m->laundry = FALSE;
	m->pageout_queue = FALSE;
	queue_remove(&q->pgo_pending, m, vm_page_t, pageq);

	m->pageq.next = NULL;
	m->pageq.prev = NULL;

	vm_object_paging_end(m->object);

	q->pgo_laundry--;
}


#ifdef FAKE_DEADLOCK

#define FAKE_COUNT	5000

int internal_count = 0;
int fake_deadlock = 0;

#endif

static void
vm_pageout_iothread_continue(struct vm_pageout_queue *q)
{
	vm_page_t	m = NULL;
	vm_object_t	object;
	boolean_t	need_wakeup;

	vm_page_lock_queues();

        while ( !queue_empty(&q->pgo_pending) ) {

		   q->pgo_busy = TRUE;
		   queue_remove_first(&q->pgo_pending, m, vm_page_t, pageq);
		   m->pageout_queue = FALSE;
		   vm_page_unlock_queues();

		   m->pageq.next = NULL;
		   m->pageq.prev = NULL;
#ifdef FAKE_DEADLOCK
		   if (q == &vm_pageout_queue_internal) {
		           vm_offset_t addr;
			   int	pg_count;

			   internal_count++;

			   if ((internal_count == FAKE_COUNT)) {

				   pg_count = vm_page_free_count + vm_page_free_reserved;

			           if (kmem_alloc(kernel_map, &addr, PAGE_SIZE * pg_count) == KERN_SUCCESS) {
				           kmem_free(kernel_map, addr, PAGE_SIZE * pg_count);
				   }
				   internal_count = 0;
				   fake_deadlock++;
			   }
		   }
#endif
		   object = m->object;

		   if (!object->pager_initialized) {
		           vm_object_lock(object);

			   /*
			    *	If there is no memory object for the page, create
			    *	one and hand it to the default pager.
			    */

			   if (!object->pager_initialized)
			           vm_object_collapse(object, (vm_object_offset_t)0);
			   if (!object->pager_initialized)
			           vm_object_pager_create(object);
			   if (!object->pager_initialized) {
			           /*
				    *	Still no pager for the object.
				    *	Reactivate the page.
				    *
				    *	Should only happen if there is no
				    *	default pager.
				    */
			           m->list_req_pending = FALSE;
				   m->cleaning = FALSE;
				   m->pageout = FALSE;
				   vm_page_unwire(m);

				   vm_pageout_throttle_up(m);

			           vm_page_lock_queues();
				   vm_pageout_dirty_no_pager++;
				   vm_page_activate(m);
				   vm_page_unlock_queues();

				   /*
				    *	And we are done with it.
				    */
				   PAGE_WAKEUP_DONE(m);

			           vm_object_paging_end(object);
				   vm_object_unlock(object);

				   vm_page_lock_queues();
				   continue;
			   } else if (object->pager == MEMORY_OBJECT_NULL) {
			           /*
				    * This pager has been destroyed by either
				    * memory_object_destroy or vm_object_destroy, and
				    * so there is nowhere for the page to go.
				    * Just free the page... VM_PAGE_FREE takes
				    * care of cleaning up all the state...
				    * including doing the vm_pageout_throttle_up
				    */
			           VM_PAGE_FREE(m);

			           vm_object_paging_end(object);
				   vm_object_unlock(object);

				   vm_page_lock_queues();
				   continue;
			   }
			   vm_object_unlock(object);
		   }
		   /*
		    * we expect the paging_in_progress reference to have
		    * already been taken on the object before it was added
		    * to the appropriate pageout I/O queue... this will
		    * keep the object from being terminated and/or the 
		    * paging_offset from changing until the I/O has 
		    * completed... therefore no need to lock the object to
		    * pull the paging_offset from it.
		    *
		    * Send the data to the pager.
		    * any pageout clustering happens there
		    */
		   memory_object_data_return(object->pager,
					     m->offset + object->paging_offset,
					     PAGE_SIZE,
					     NULL,
					     NULL,
					     FALSE,
					     FALSE,
					     0);

		   vm_object_lock(object);
		   vm_object_paging_end(object);
		   vm_object_unlock(object);

		   vm_page_lock_queues();
	}
	assert_wait((event_t) q, THREAD_UNINT);


	if (q->pgo_throttled == TRUE && !VM_PAGE_Q_THROTTLED(q)) {
	        q->pgo_throttled = FALSE;
		need_wakeup = TRUE;
	} else
		need_wakeup = FALSE;

	q->pgo_busy = FALSE;
	q->pgo_idle = TRUE;
	vm_page_unlock_queues();

	if (need_wakeup == TRUE)
	        thread_wakeup((event_t) &q->pgo_laundry);

	thread_block_parameter((thread_continue_t)vm_pageout_iothread_continue, (void *) &q->pgo_pending);
	/*NOTREACHED*/
}


static void
vm_pageout_iothread_external(void)
{

	vm_pageout_iothread_continue(&vm_pageout_queue_external);
	/*NOTREACHED*/
}


static void
vm_pageout_iothread_internal(void)
{
	thread_t	self = current_thread();

	self->options |= TH_OPT_VMPRIV;

	vm_pageout_iothread_continue(&vm_pageout_queue_internal);
	/*NOTREACHED*/
}

static void
vm_pageout_garbage_collect(int collect)
{
	if (collect) {
		stack_collect();

		/*
		 * consider_zone_gc should be last, because the other operations
		 * might return memory to zones.
		 */
		consider_machine_collect();
		consider_zone_gc();

		consider_machine_adjust();
	}

	assert_wait((event_t) &vm_pageout_garbage_collect, THREAD_UNINT);

	thread_block_parameter((thread_continue_t) vm_pageout_garbage_collect, (void *)1);
	/*NOTREACHED*/
}



void
vm_pageout(void)
{
	thread_t	self = current_thread();
	thread_t	thread;
	kern_return_t	result;
	spl_t		s;

	/*
	 * Set thread privileges.
	 */
	s = splsched();
	thread_lock(self);
	self->priority = BASEPRI_PREEMPT - 1;
	set_sched_pri(self, self->priority);
	thread_unlock(self);
	splx(s);

	/*
	 *	Initialize some paging parameters.
	 */

	if (vm_pageout_idle_wait == 0)
		vm_pageout_idle_wait = VM_PAGEOUT_IDLE_WAIT;

	if (vm_pageout_burst_wait == 0)
		vm_pageout_burst_wait = VM_PAGEOUT_BURST_WAIT;

	if (vm_pageout_empty_wait == 0)
		vm_pageout_empty_wait = VM_PAGEOUT_EMPTY_WAIT;

	if (vm_pageout_deadlock_wait == 0)
		vm_pageout_deadlock_wait = VM_PAGEOUT_DEADLOCK_WAIT;

	if (vm_pageout_deadlock_relief == 0)
		vm_pageout_deadlock_relief = VM_PAGEOUT_DEADLOCK_RELIEF;

	if (vm_pageout_inactive_relief == 0)
		vm_pageout_inactive_relief = VM_PAGEOUT_INACTIVE_RELIEF;

	if (vm_pageout_burst_active_throttle == 0)
	        vm_pageout_burst_active_throttle = VM_PAGEOUT_BURST_ACTIVE_THROTTLE;

	if (vm_pageout_burst_inactive_throttle == 0)
	        vm_pageout_burst_inactive_throttle = VM_PAGEOUT_BURST_INACTIVE_THROTTLE;

	/*
	 * Set kernel task to low backing store privileged 
	 * status
	 */
	task_lock(kernel_task);
	kernel_task->priv_flags |= VM_BACKING_STORE_PRIV;
	task_unlock(kernel_task);

	vm_page_free_count_init = vm_page_free_count;
	vm_zf_iterator = 0;
	/*
	 * even if we've already called vm_page_free_reserve
	 * call it again here to insure that the targets are
	 * accurately calculated (it uses vm_page_free_count_init)
	 * calling it with an arg of 0 will not change the reserve
	 * but will re-calculate free_min and free_target
	 */
	if (vm_page_free_reserved < VM_PAGE_FREE_RESERVED(processor_count)) {
		vm_page_free_reserve((VM_PAGE_FREE_RESERVED(processor_count)) - vm_page_free_reserved);
	} else
		vm_page_free_reserve(0);


	queue_init(&vm_pageout_queue_external.pgo_pending);
	vm_pageout_queue_external.pgo_maxlaundry = VM_PAGE_LAUNDRY_MAX;
	vm_pageout_queue_external.pgo_laundry = 0;
	vm_pageout_queue_external.pgo_idle = FALSE;
	vm_pageout_queue_external.pgo_busy = FALSE;
	vm_pageout_queue_external.pgo_throttled = FALSE;

	queue_init(&vm_pageout_queue_internal.pgo_pending);
	vm_pageout_queue_internal.pgo_maxlaundry = VM_PAGE_LAUNDRY_MAX;
	vm_pageout_queue_internal.pgo_laundry = 0;
	vm_pageout_queue_internal.pgo_idle = FALSE;
	vm_pageout_queue_internal.pgo_busy = FALSE;
	vm_pageout_queue_internal.pgo_throttled = FALSE;


	result = kernel_thread_start_priority((thread_continue_t)vm_pageout_iothread_internal, NULL, BASEPRI_PREEMPT - 1, &thread);
	if (result != KERN_SUCCESS)
		panic("vm_pageout_iothread_internal: create failed");

	thread_deallocate(thread);


	result = kernel_thread_start_priority((thread_continue_t)vm_pageout_iothread_external, NULL, BASEPRI_PREEMPT - 1, &thread);
	if (result != KERN_SUCCESS)
		panic("vm_pageout_iothread_external: create failed");

	thread_deallocate(thread);


	result = kernel_thread_start_priority((thread_continue_t)vm_pageout_garbage_collect, NULL, BASEPRI_PREEMPT - 2, &thread);
	if (result != KERN_SUCCESS)
		panic("vm_pageout_garbage_collect: create failed");

	thread_deallocate(thread);


	vm_pageout_continue();
	/*NOTREACHED*/
}


static upl_t
upl_create(
	int		   flags,
	upl_size_t       size)
{
	upl_t	upl;
	int	page_field_size;  /* bit field in word size buf */

	page_field_size = 0;
	if (flags & UPL_CREATE_LITE) {
		page_field_size = ((size/PAGE_SIZE) + 7) >> 3;
		page_field_size = (page_field_size + 3) & 0xFFFFFFFC;
	}
	if(flags & UPL_CREATE_INTERNAL) {
		upl = (upl_t)kalloc(sizeof(struct upl)
			+ (sizeof(struct upl_page_info)*(size/PAGE_SIZE))
			+ page_field_size);
	} else {
		upl = (upl_t)kalloc(sizeof(struct upl) + page_field_size);
	}
	upl->flags = 0;
	upl->src_object = NULL;
	upl->kaddr = (vm_offset_t)0;
	upl->size = 0;
	upl->map_object = NULL;
	upl->ref_count = 1;
	upl_lock_init(upl);
#ifdef UPL_DEBUG
	upl->ubc_alias1 = 0;
	upl->ubc_alias2 = 0;
#endif /* UPL_DEBUG */
	return(upl);
}

static void
upl_destroy(
	upl_t	upl)
{
	int	page_field_size;  /* bit field in word size buf */

#ifdef UPL_DEBUG
	{
		upl_t	upl_ele;
		vm_object_t	object;
		if (upl->map_object->pageout) {
			object = upl->map_object->shadow;
		} else {
			object = upl->map_object;
		}
		vm_object_lock(object);
		queue_iterate(&object->uplq, upl_ele, upl_t, uplq) {
			if(upl_ele == upl) {
				queue_remove(&object->uplq, 
						upl_ele, upl_t, uplq);
				break;
			}
		}
		vm_object_unlock(object);
	}
#endif /* UPL_DEBUG */
	/* drop a reference on the map_object whether or */
	/* not a pageout object is inserted */
	if(upl->map_object->pageout)
		vm_object_deallocate(upl->map_object);

	page_field_size = 0;
	if (upl->flags & UPL_LITE) {
		page_field_size = ((upl->size/PAGE_SIZE) + 7) >> 3;
		page_field_size = (page_field_size + 3) & 0xFFFFFFFC;
	}
	if(upl->flags & UPL_INTERNAL) {
		kfree(upl,
		      sizeof(struct upl) + 
		      (sizeof(struct upl_page_info) * (upl->size/PAGE_SIZE))
		      + page_field_size);
	} else {
		kfree(upl, sizeof(struct upl) + page_field_size);
	}
}

void uc_upl_dealloc(upl_t upl);
__private_extern__ void
uc_upl_dealloc(
	upl_t	upl)
{
	upl->ref_count -= 1;
	if(upl->ref_count == 0) {
		upl_destroy(upl);
	}
}

void
upl_deallocate(
	upl_t	upl)
{
	
	upl->ref_count -= 1;
	if(upl->ref_count == 0) {
		upl_destroy(upl);
	}
}

/*
 * Statistics about UPL enforcement of copy-on-write obligations.
 */
unsigned long upl_cow = 0;
unsigned long upl_cow_again = 0;
unsigned long upl_cow_contiguous = 0;
unsigned long upl_cow_pages = 0;
unsigned long upl_cow_again_pages = 0;
unsigned long upl_cow_contiguous_pages = 0;

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
	vm_object_t		object,
	vm_object_offset_t	offset,
	upl_size_t		size,
	upl_t			*upl_ptr,
	upl_page_info_array_t	user_page_list,
	unsigned int		*page_list_count,
	int			cntrl_flags)
{
	vm_page_t		dst_page = VM_PAGE_NULL;
	vm_object_offset_t	dst_offset = offset;
	upl_size_t		xfer_size = size;
	boolean_t		do_m_lock = FALSE;
	boolean_t		dirty;
	boolean_t		hw_dirty;
	upl_t			upl = NULL;
	unsigned int		entry;
#if MACH_CLUSTER_STATS
	boolean_t		encountered_lrp = FALSE;
#endif
	vm_page_t		alias_page = NULL;
	int			page_ticket; 
        int			refmod_state;
	wpl_array_t 		lite_list = NULL;
	vm_object_t		last_copy_object;


	if (cntrl_flags & ~UPL_VALID_FLAGS) {
		/*
		 * For forward compatibility's sake,
		 * reject any unknown flag.
		 */
		return KERN_INVALID_VALUE;
	}

	page_ticket = (cntrl_flags & UPL_PAGE_TICKET_MASK)
					>> UPL_PAGE_TICKET_SHIFT;

	if(((size/PAGE_SIZE) > MAX_UPL_TRANSFER) && !object->phys_contiguous) {
		size = MAX_UPL_TRANSFER * PAGE_SIZE;
	}

	if(cntrl_flags & UPL_SET_INTERNAL)
		if(page_list_count != NULL)
			*page_list_count = MAX_UPL_TRANSFER;

	if((!object->internal) && (object->paging_offset != 0))
		panic("vm_object_upl_request: vnode object with non-zero paging offset\n");

	if((cntrl_flags & UPL_COPYOUT_FROM) && (upl_ptr == NULL)) {
		return KERN_SUCCESS;
	}

	vm_object_lock(object);
	vm_object_paging_begin(object);
	vm_object_unlock(object);

	if(upl_ptr) {
		if(cntrl_flags & UPL_SET_INTERNAL) {
			if(cntrl_flags & UPL_SET_LITE) {
				uintptr_t page_field_size;
				upl = upl_create(
					UPL_CREATE_INTERNAL | UPL_CREATE_LITE,
					size);
				user_page_list = (upl_page_info_t *)
				   (((uintptr_t)upl) + sizeof(struct upl));
				lite_list = (wpl_array_t)
					(((uintptr_t)user_page_list) + 
					((size/PAGE_SIZE) * 
						sizeof(upl_page_info_t)));
				page_field_size = ((size/PAGE_SIZE) + 7) >> 3;
				page_field_size = 
					(page_field_size + 3) & 0xFFFFFFFC;
				bzero((char *)lite_list, page_field_size);
				upl->flags = 
					UPL_LITE | UPL_INTERNAL;
			} else {
				upl = upl_create(UPL_CREATE_INTERNAL, size);
				user_page_list = (upl_page_info_t *)
					(((uintptr_t)upl) + sizeof(struct upl));
				upl->flags = UPL_INTERNAL;
			}
		} else {
			if(cntrl_flags & UPL_SET_LITE) {
				uintptr_t page_field_size;
				upl = upl_create(UPL_CREATE_LITE, size);
				lite_list = (wpl_array_t)
				   (((uintptr_t)upl) + sizeof(struct upl));
				page_field_size = ((size/PAGE_SIZE) + 7) >> 3;
				page_field_size = 
					(page_field_size + 3) & 0xFFFFFFFC;
				bzero((char *)lite_list, page_field_size);
				upl->flags = UPL_LITE;
			} else {
				upl = upl_create(UPL_CREATE_EXTERNAL, size);
				upl->flags = 0;
			}
		}

		if (object->phys_contiguous) {
			if ((cntrl_flags & UPL_WILL_MODIFY) &&
			    object->copy != VM_OBJECT_NULL) {
				/* Honor copy-on-write obligations */

				/*
				 * XXX FBDP
				 * We could still have a race...
				 * A is here building the UPL for a write().
				 * A pushes the pages to the current copy
				 * object.
				 * A returns the UPL to the caller.
				 * B comes along and establishes another
				 * private mapping on this object, inserting 
				 * a new copy object between the original
				 * object and the old copy object.
				 * B reads a page and gets the original contents
				 * from the original object.
				 * A modifies the page in the original object.
				 * B reads the page again and sees A's changes,
				 * which is wrong...
				 *
				 * The problem is that the pages are not
				 * marked "busy" in the original object, so
				 * nothing prevents B from reading it before
				 * before A's changes are completed.
				 *
				 * The "paging_in_progress" might protect us
				 * from the insertion of a new copy object
				 * though...  To be verified.
				 */
				vm_object_lock_request(object,
						       offset,
						       size,
						       FALSE,
						       MEMORY_OBJECT_COPY_SYNC,
						       VM_PROT_NO_CHANGE);
				upl_cow_contiguous++;
				upl_cow_contiguous_pages += size >> PAGE_SHIFT;
			}

			upl->map_object = object;
			/* don't need any shadow mappings for this one */
			/* since it is already I/O memory */
			upl->flags |= UPL_DEVICE_MEMORY;


			/* paging_in_progress protects paging_offset */
			upl->offset = offset + object->paging_offset;
			upl->size = size;
			*upl_ptr = upl;
			if(user_page_list) {
				user_page_list[0].phys_addr = 
				   (offset + object->shadow_offset)>>PAGE_SHIFT;
				user_page_list[0].device = TRUE;
			}

			if(page_list_count != NULL) {
				if (upl->flags & UPL_INTERNAL) {
					*page_list_count = 0;
				} else {
					*page_list_count = 1;
				}
			}

			return KERN_SUCCESS;
		}

		if(user_page_list)
			user_page_list[0].device = FALSE;

		if(cntrl_flags & UPL_SET_LITE) {
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
			upl->map_object->copy_strategy = 
					MEMORY_OBJECT_COPY_NONE;
			upl->map_object->shadow_offset = offset;
			upl->map_object->wimg_bits = object->wimg_bits;
		}

	}
	if (!(cntrl_flags & UPL_SET_LITE)) {
		VM_PAGE_GRAB_FICTITIOUS(alias_page);
	}

	/*
	 * ENCRYPTED SWAP:
	 * Just mark the UPL as "encrypted" here.
	 * We'll actually encrypt the pages later,
	 * in upl_encrypt(), when the caller has
	 * selected which pages need to go to swap.
	 */
	if (cntrl_flags & UPL_ENCRYPT) {
		upl->flags |= UPL_ENCRYPTED;
	}
	if (cntrl_flags & UPL_FOR_PAGEOUT) {
		upl->flags |= UPL_PAGEOUT;
	}
	vm_object_lock(object);

	/* we can lock in the paging_offset once paging_in_progress is set */
	if(upl_ptr) {
		upl->size = size;
		upl->offset = offset + object->paging_offset;
		*upl_ptr = upl;
#ifdef UPL_DEBUG
		queue_enter(&object->uplq, upl, upl_t, uplq);
#endif /* UPL_DEBUG */
	}

	if ((cntrl_flags & UPL_WILL_MODIFY) &&
	    object->copy != VM_OBJECT_NULL) {
		/* Honor copy-on-write obligations */

		/*
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
				 FALSE,	/* should_return */
				 MEMORY_OBJECT_COPY_SYNC,
				 VM_PROT_NO_CHANGE);
		upl_cow++;
		upl_cow_pages += size >> PAGE_SHIFT;
		
	}
	/* remember which copy object we synchronized with */
	last_copy_object = object->copy;

	entry = 0;
	if(cntrl_flags & UPL_COPYOUT_FROM) {
		upl->flags |= UPL_PAGE_SYNC_DONE;

		while (xfer_size) {
			if((alias_page == NULL) && 
				!(cntrl_flags & UPL_SET_LITE)) {
				vm_object_unlock(object);
				VM_PAGE_GRAB_FICTITIOUS(alias_page);
				vm_object_lock(object);
			}
			if ( ((dst_page = vm_page_lookup(object, dst_offset)) == VM_PAGE_NULL) ||
				dst_page->fictitious ||
				dst_page->absent ||
				dst_page->error ||
			       (dst_page->wire_count && !dst_page->pageout) ||

			     ((!dst_page->inactive) && (cntrl_flags & UPL_FOR_PAGEOUT) &&
			       (dst_page->page_ticket != page_ticket) && 
			      ((dst_page->page_ticket+1) != page_ticket)) ) {

				if (user_page_list)
					user_page_list[entry].phys_addr = 0;
			} else { 
			        /*
				 * grab this up front...
				 * a high percentange of the time we're going to
				 * need the hardware modification state a bit later
				 * anyway... so we can eliminate an extra call into
				 * the pmap layer by grabbing it here and recording it
				 */
			        refmod_state = pmap_get_refmod(dst_page->phys_page);
					
			        if (cntrl_flags & UPL_RET_ONLY_DIRTY) {
				        /*
					 * we're only asking for DIRTY pages to be returned
					 */

				        if (dst_page->list_req_pending || !(cntrl_flags & UPL_FOR_PAGEOUT)) {
					        /*
						 * if we were the page stolen by vm_pageout_scan to be
						 * cleaned (as opposed to a buddy being clustered in 
						 * or this request is not being driven by a PAGEOUT cluster
						 * then we only need to check for the page being diry or
						 * precious to decide whether to return it
						 */
					        if (dst_page->dirty || dst_page->precious ||
						    (refmod_state & VM_MEM_MODIFIED)) {
						        goto check_busy;
						}
					}
					/*
					 * this is a request for a PAGEOUT cluster and this page
					 * is merely along for the ride as a 'buddy'... not only
					 * does it have to be dirty to be returned, but it also
					 * can't have been referenced recently... note that we've
					 * already filtered above based on whether this page is
					 * currently on the inactive queue or it meets the page
					 * ticket (generation count) check
					 */
					if ( !(refmod_state & VM_MEM_REFERENCED) && 
					     ((refmod_state & VM_MEM_MODIFIED) ||
					      dst_page->dirty || dst_page->precious) ) {
					        goto check_busy;
					}
					/*
					 * if we reach here, we're not to return
					 * the page... go on to the next one
					 */
					if (user_page_list)
					        user_page_list[entry].phys_addr = 0;
					entry++;
					dst_offset += PAGE_SIZE_64;
					xfer_size -= PAGE_SIZE;
					continue;
				}
check_busy:			
				if(dst_page->busy && 
					(!(dst_page->list_req_pending && 
						dst_page->pageout))) {
					if(cntrl_flags & UPL_NOBLOCK) {
						if(user_page_list) {
					   		user_page_list[entry].phys_addr = 0;
						}
						entry++;
						dst_offset += PAGE_SIZE_64;
						xfer_size -= PAGE_SIZE;
						continue;
					}
					/*
					 * someone else is playing with the
					 * page.  We will have to wait.
					 */
					PAGE_SLEEP(object, dst_page, THREAD_UNINT);
					continue;
				}
				/* Someone else already cleaning the page? */
				if((dst_page->cleaning || dst_page->absent ||
					dst_page->wire_count != 0) && 
					!dst_page->list_req_pending) {
				   if(user_page_list) {
					   user_page_list[entry].phys_addr = 0;
				   }
				   entry++;
				   dst_offset += PAGE_SIZE_64;
				   xfer_size -= PAGE_SIZE;
				   continue;
				}
				/* eliminate all mappings from the */
				/* original object and its prodigy */
				
				vm_page_lock_queues();

				if (dst_page->pageout_queue == TRUE)
				        /*
					 * we've buddied up a page for a clustered pageout
					 * that has already been moved to the pageout
					 * queue by pageout_scan... we need to remove
					 * it from the queue and drop the laundry count
					 * on that queue
					 */
				        vm_pageout_queue_steal(dst_page);
#if MACH_CLUSTER_STATS
				/* pageout statistics gathering.  count  */
				/* all the pages we will page out that   */
				/* were not counted in the initial       */
				/* vm_pageout_scan work                  */
				if(dst_page->list_req_pending)
					encountered_lrp = TRUE;
				if((dst_page->dirty ||
					(dst_page->object->internal &&
					dst_page->precious)) &&
					(dst_page->list_req_pending 
					== FALSE)) {
					if(encountered_lrp) {
						CLUSTER_STAT
						(pages_at_higher_offsets++;)
					} else {
						CLUSTER_STAT
						(pages_at_lower_offsets++;)
					}
				}
#endif
				/* Turn off busy indication on pending */
				/* pageout.  Note: we can only get here */
				/* in the request pending case.  */
				dst_page->list_req_pending = FALSE;
				dst_page->busy = FALSE;
				dst_page->cleaning = FALSE;

			        hw_dirty = refmod_state & VM_MEM_MODIFIED;
				dirty = hw_dirty ? TRUE : dst_page->dirty;

				if(cntrl_flags & UPL_SET_LITE) {
					int	pg_num;
					pg_num = (dst_offset-offset)/PAGE_SIZE;
					lite_list[pg_num>>5] |= 
							1 << (pg_num & 31);
					if (hw_dirty)
					        pmap_clear_modify(dst_page->phys_page);
					/*
					 * Record that this page has been 
					 * written out
					 */
#if     MACH_PAGEMAP
					vm_external_state_set(
						object->existence_map, 
						dst_page->offset);
#endif  /*MACH_PAGEMAP*/

					/*
					 * Mark original page as cleaning 
					 * in place.
					 */
					dst_page->cleaning = TRUE;
					dst_page->dirty = TRUE;
					dst_page->precious = FALSE;
				} else {
					/* use pageclean setup, it is more */
					/* convenient even for the pageout */
					/* cases here */

				        vm_object_lock(upl->map_object);
					vm_pageclean_setup(dst_page, 
						alias_page, upl->map_object, 
						size - xfer_size);
				        vm_object_unlock(upl->map_object);

					alias_page->absent = FALSE;
					alias_page = NULL;
				}
						
				if(!dirty) {
					dst_page->dirty = FALSE;
					dst_page->precious = TRUE;
				}

				if(dst_page->pageout)
					dst_page->busy = TRUE;

				if ( (cntrl_flags & UPL_ENCRYPT) ) {
				        /*
					 * ENCRYPTED SWAP:
					 * We want to deny access to the target page
					 * because its contents are about to be
					 * encrypted and the user would be very
					 * confused to see encrypted data instead
					 * of their data.
					 */
					dst_page->busy = TRUE;
				}
				if ( !(cntrl_flags & UPL_CLEAN_IN_PLACE) ) {
					/*
					 * deny access to the target page
					 * while it is being worked on
					 */
					if ((!dst_page->pageout) &&
					    (dst_page->wire_count == 0)) {
						dst_page->busy = TRUE;
						dst_page->pageout = TRUE;
						vm_page_wire(dst_page);
					}
				}

				if(user_page_list) {
					user_page_list[entry].phys_addr
						= dst_page->phys_page;
					user_page_list[entry].dirty =   
							dst_page->dirty;
					user_page_list[entry].pageout =
							dst_page->pageout;
					user_page_list[entry].absent =
							dst_page->absent;
					user_page_list[entry].precious =
							dst_page->precious;
				}
				vm_page_unlock_queues();

				/*
				 * ENCRYPTED SWAP:
				 * The caller is gathering this page and might
				 * access its contents later on.  Decrypt the
				 * page before adding it to the UPL, so that
				 * the caller never sees encrypted data.
				 */
				if (! (cntrl_flags & UPL_ENCRYPT) &&
				    dst_page->encrypted) {
					assert(dst_page->busy);

					vm_page_decrypt(dst_page, 0);
					vm_page_decrypt_for_upl_counter++;

					/*
					 * Retry this page, since anything
					 * could have changed while we were
					 * decrypting.
					 */
					continue;
				}
			}
			entry++;
			dst_offset += PAGE_SIZE_64;
			xfer_size -= PAGE_SIZE;
		}
	} else {
		while (xfer_size) {
			if((alias_page == NULL) && 
				!(cntrl_flags & UPL_SET_LITE)) {
				vm_object_unlock(object);
				VM_PAGE_GRAB_FICTITIOUS(alias_page);
				vm_object_lock(object);
			}

			if ((cntrl_flags & UPL_WILL_MODIFY) &&
			    object->copy != last_copy_object) {
				/* Honor copy-on-write obligations */

				/*
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
						FALSE,	   /* should_return */
						MEMORY_OBJECT_COPY_SYNC,
						VM_PROT_NO_CHANGE);
					upl_cow_again++;
					upl_cow_again_pages +=
						xfer_size >> PAGE_SHIFT;
				}
				/* remember the copy object we synced with */
				last_copy_object = object->copy;
			}

			dst_page = vm_page_lookup(object, dst_offset);
			
			if(dst_page != VM_PAGE_NULL) {
			        if((cntrl_flags & UPL_RET_ONLY_ABSENT) &&
				        !((dst_page->list_req_pending)
					        && (dst_page->absent))) {
				        /* we are doing extended range */
				        /* requests.  we want to grab  */
				        /* pages around some which are */
				        /* already present.  */
				        if(user_page_list) {
					        user_page_list[entry].phys_addr = 0;
					}
					entry++;
					dst_offset += PAGE_SIZE_64;
					xfer_size -= PAGE_SIZE;
					continue;
				}
				if((dst_page->cleaning) && 
				   !(dst_page->list_req_pending)) {
					/*someone else is writing to the */
					/* page.  We will have to wait.  */
					PAGE_SLEEP(object,dst_page,THREAD_UNINT);
					continue;
				}
				if ((dst_page->fictitious && 
				     dst_page->list_req_pending)) {
					/* dump the fictitious page */
					dst_page->list_req_pending = FALSE;
					dst_page->clustered = FALSE;

					vm_page_lock_queues();
					vm_page_free(dst_page);
					vm_page_unlock_queues();

					dst_page = NULL;
				} else if ((dst_page->absent && 
					    dst_page->list_req_pending)) {
					/* the default_pager case */
					dst_page->list_req_pending = FALSE;
					dst_page->busy = FALSE;
				}
			}
			if(dst_page == VM_PAGE_NULL) {
				if(object->private) {
					/* 
					 * This is a nasty wrinkle for users 
					 * of upl who encounter device or 
					 * private memory however, it is 
					 * unavoidable, only a fault can
					 * reslove the actual backing
					 * physical page by asking the
					 * backing device.
					 */
					if(user_page_list) {
						user_page_list[entry].phys_addr = 0;
					}
					entry++;
					dst_offset += PAGE_SIZE_64;
					xfer_size -= PAGE_SIZE;
					continue;
				}
				/* need to allocate a page */
		 		dst_page = vm_page_alloc(object, dst_offset);
				if (dst_page == VM_PAGE_NULL) {
					vm_object_unlock(object);
					VM_PAGE_WAIT();
					vm_object_lock(object);
					continue;
				}
				dst_page->busy = FALSE;
#if 0
				if(cntrl_flags & UPL_NO_SYNC) {
					dst_page->page_lock = 0;
					dst_page->unlock_request = 0;
				}
#endif
				if(cntrl_flags & UPL_RET_ONLY_ABSENT) {
				        /*
					 * if UPL_RET_ONLY_ABSENT was specified,
					 * than we're definitely setting up a
					 * upl for a clustered read/pagein 
					 * operation... mark the pages as clustered
					 * so vm_fault can correctly attribute them
					 * to the 'pagein' bucket the first time
					 * a fault happens on them
					 */
				        dst_page->clustered = TRUE;
				}
				dst_page->absent = TRUE;
				object->absent_count++;
			}
#if 1
			if(cntrl_flags & UPL_NO_SYNC) {
				dst_page->page_lock = 0;
				dst_page->unlock_request = 0;
			}
#endif /* 1 */

			/*
			 * ENCRYPTED SWAP:
			 */
			if (cntrl_flags & UPL_ENCRYPT) {
				/*
				 * The page is going to be encrypted when we
				 * get it from the pager, so mark it so.
				 */
				dst_page->encrypted = TRUE;
			} else {
				/*
				 * Otherwise, the page will not contain
				 * encrypted data.
				 */
				dst_page->encrypted = FALSE;
			}

			dst_page->overwriting = TRUE;
			if(dst_page->fictitious) {
				panic("need corner case for fictitious page");
			}
			if(dst_page->page_lock) {
				do_m_lock = TRUE;
			}
			if(upl_ptr) {

				/* eliminate all mappings from the */
				/* original object and its prodigy */
				
				if(dst_page->busy) {
					/*someone else is playing with the */
					/* page.  We will have to wait.    */
					PAGE_SLEEP(object, dst_page, THREAD_UNINT);
					continue;
				}
				vm_page_lock_queues();

				if( !(cntrl_flags & UPL_FILE_IO))
				        hw_dirty = pmap_disconnect(dst_page->phys_page) & VM_MEM_MODIFIED;
				else
				        hw_dirty = pmap_get_refmod(dst_page->phys_page) & VM_MEM_MODIFIED;
				dirty = hw_dirty ? TRUE : dst_page->dirty;

				if(cntrl_flags & UPL_SET_LITE) {
					int	pg_num;
					pg_num = (dst_offset-offset)/PAGE_SIZE;
					lite_list[pg_num>>5] |= 
							1 << (pg_num & 31);
					if (hw_dirty)
					        pmap_clear_modify(dst_page->phys_page);
					/*
					 * Record that this page has been 
					 * written out
					 */
#if     MACH_PAGEMAP
					vm_external_state_set(
						object->existence_map, 
						dst_page->offset);
#endif  /*MACH_PAGEMAP*/

					/*
					 * Mark original page as cleaning 
					 * in place.
					 */
					dst_page->cleaning = TRUE;
					dst_page->dirty = TRUE;
					dst_page->precious = FALSE;
				} else {
					/* use pageclean setup, it is more */
					/* convenient even for the pageout */
					/* cases here */
				        vm_object_lock(upl->map_object);
					vm_pageclean_setup(dst_page, 
						alias_page, upl->map_object, 
						size - xfer_size);
				        vm_object_unlock(upl->map_object);

					alias_page->absent = FALSE;
					alias_page = NULL;
				}

				if(cntrl_flags & UPL_CLEAN_IN_PLACE) {
					/* clean in place for read implies   */
					/* that a write will be done on all  */
					/* the pages that are dirty before   */
					/* a upl commit is done.  The caller */
					/* is obligated to preserve the      */
					/* contents of all pages marked      */
					/* dirty. */
					upl->flags |= UPL_CLEAR_DIRTY;
				}

				if(!dirty) {
					dst_page->dirty = FALSE;
					dst_page->precious = TRUE;
				}
						
				if (dst_page->wire_count == 0) {
				   /* deny access to the target page while */
				   /* it is being worked on */
					dst_page->busy = TRUE;
				} else {
			 		vm_page_wire(dst_page);
				}
				if(cntrl_flags & UPL_RET_ONLY_ABSENT) {
				        /*
					 * expect the page not to be used
					 * since it's coming in as part
					 * of a cluster and could be 
					 * speculative... pages that
					 * are 'consumed' will get a
					 * hardware reference
					 */
				        dst_page->reference = FALSE;
				} else {
				        /*
					 * expect the page to be used
					 */
				        dst_page->reference = TRUE;
				}
				dst_page->precious = 
					(cntrl_flags & UPL_PRECIOUS) 
							? TRUE : FALSE;
				if(user_page_list) {
					user_page_list[entry].phys_addr
						= dst_page->phys_page;
					user_page_list[entry].dirty =
							dst_page->dirty;
					user_page_list[entry].pageout =
				   			dst_page->pageout;
					user_page_list[entry].absent =
				   			dst_page->absent;
					user_page_list[entry].precious =
							dst_page->precious;
				}
				vm_page_unlock_queues();
			}
			entry++;
			dst_offset += PAGE_SIZE_64;
			xfer_size -= PAGE_SIZE;
		}
	}

	if (upl->flags & UPL_INTERNAL) {
		if(page_list_count != NULL)
			*page_list_count = 0;
	} else if (*page_list_count > entry) {
		if(page_list_count != NULL)
			*page_list_count = entry;
	}

	if(alias_page != NULL) {
		vm_page_lock_queues();
		vm_page_free(alias_page);
		vm_page_unlock_queues();
	}

	if(do_m_lock) {
	   vm_prot_t	access_required;
	   /* call back all associated pages from other users of the pager */
	   /* all future updates will be on data which is based on the     */
	   /* changes we are going to make here. Note: it is assumed that  */
	   /* we already hold copies of the data so we will not be seeing  */
	   /* an avalanche of incoming data from the pager */
	   access_required = (cntrl_flags & UPL_COPYOUT_FROM) 
					? VM_PROT_READ : VM_PROT_WRITE;
	   while (TRUE) {
		kern_return_t	rc;

		if(!object->pager_ready) {
		   wait_result_t wait_result;

		   wait_result = vm_object_sleep(object, 
						VM_OBJECT_EVENT_PAGER_READY,
						THREAD_UNINT);
		   if (wait_result !=  THREAD_AWAKENED) {
		   	vm_object_unlock(object);
		   	return KERN_FAILURE;
		   }
		   continue;
		}

		vm_object_unlock(object);
		rc = memory_object_data_unlock(
			object->pager,
			dst_offset + object->paging_offset,
			size,
			access_required);
		if (rc != KERN_SUCCESS && rc != MACH_SEND_INTERRUPTED)
			return KERN_FAILURE;
		vm_object_lock(object);

		if (rc == KERN_SUCCESS)
			break;
	   }

	   /* lets wait on the last page requested */
	   /* NOTE: we will have to update lock completed routine to signal */
	   if(dst_page != VM_PAGE_NULL && 
		(access_required & dst_page->page_lock) != access_required) {
	   	PAGE_ASSERT_WAIT(dst_page, THREAD_UNINT);
	   	vm_object_unlock(object);
	   	thread_block(THREAD_CONTINUE_NULL);
		return KERN_SUCCESS;
	   }
	}

	vm_object_unlock(object);
	return KERN_SUCCESS;
}

/* JMM - Backward compatability for now */
kern_return_t
vm_fault_list_request(			/* forward */
	memory_object_control_t		control,
	vm_object_offset_t	offset,
	upl_size_t		size,
	upl_t			*upl_ptr,
	upl_page_info_t		**user_page_list_ptr,
	int			page_list_count,
	int			cntrl_flags);
kern_return_t
vm_fault_list_request(
	memory_object_control_t		control,
	vm_object_offset_t	offset,
	upl_size_t		size,
	upl_t			*upl_ptr,
	upl_page_info_t		**user_page_list_ptr,
	int			page_list_count,
	int			cntrl_flags)
{
	int			local_list_count;
	upl_page_info_t		*user_page_list;
	kern_return_t		kr;

	if (user_page_list_ptr != NULL) {
		local_list_count = page_list_count;
		user_page_list = *user_page_list_ptr;
	} else {
		local_list_count = 0;
		user_page_list = NULL;
	}
	kr =  memory_object_upl_request(control,
				offset,
				size,
				upl_ptr,
				user_page_list,
				&local_list_count,
				cntrl_flags);

	if(kr != KERN_SUCCESS)
		return kr;

	if ((user_page_list_ptr != NULL) && (cntrl_flags & UPL_INTERNAL)) {
		*user_page_list_ptr = UPL_GET_INTERNAL_PAGE_LIST(*upl_ptr);
	}

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
	vm_object_offset_t	offset,
	upl_size_t		size,
	upl_size_t		super_cluster,
	upl_t			*upl,
	upl_page_info_t		*user_page_list,
	unsigned int		*page_list_count,
	int			cntrl_flags)
{
	vm_page_t	target_page;
	int		ticket;


	if(object->paging_offset > offset)
		return KERN_FAILURE;

	assert(object->paging_in_progress);
	offset = offset - object->paging_offset;

	if(cntrl_flags & UPL_FOR_PAGEOUT) {
	  
	        vm_object_lock(object);

		if((target_page = vm_page_lookup(object, offset))
							!= VM_PAGE_NULL) {
			ticket = target_page->page_ticket;
			cntrl_flags = cntrl_flags & ~(int)UPL_PAGE_TICKET_MASK;
			cntrl_flags = cntrl_flags | 
				((ticket << UPL_PAGE_TICKET_SHIFT) 
							& UPL_PAGE_TICKET_MASK);
		}
	        vm_object_unlock(object);
	}

	if (super_cluster > size) {

		vm_object_offset_t	base_offset;
		upl_size_t		super_size;

		base_offset = (offset &  
			~((vm_object_offset_t) super_cluster - 1));
		super_size = (offset+size) > (base_offset + super_cluster) ?
				super_cluster<<1 : super_cluster;
		super_size = ((base_offset + super_size) > object->size) ? 
				(object->size - base_offset) : super_size;
		if(offset > (base_offset + super_size))
		   panic("vm_object_super_upl_request: Missed target pageout"
			 " %#llx,%#llx, %#x, %#x, %#x, %#llx\n",
			 offset, base_offset, super_size, super_cluster,
			 size, object->paging_offset);
		/*
		 * apparently there is a case where the vm requests a
		 * page to be written out who's offset is beyond the
		 * object size
		 */
		if((offset + size) > (base_offset + super_size))
		   super_size = (offset + size) - base_offset;

		offset = base_offset;
		size = super_size;
	}
	return vm_object_upl_request(object, offset, size,
				     upl, user_page_list, page_list_count,
				     cntrl_flags);
}

				 
kern_return_t
vm_map_create_upl(
	vm_map_t		map,
	vm_map_address_t	offset,
	upl_size_t		*upl_size,
	upl_t			*upl,
	upl_page_info_array_t	page_list,
	unsigned int		*count,
	int			*flags)
{
	vm_map_entry_t	entry;
	int		caller_flags;
	int		force_data_sync;
	int		sync_cow_data;
	vm_object_t	local_object;
	vm_map_offset_t	local_offset;
	vm_map_offset_t	local_start;
	kern_return_t	ret;

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

	if(upl == NULL)
		return KERN_INVALID_ARGUMENT;


REDISCOVER_ENTRY:
	vm_map_lock(map);
	if (vm_map_lookup_entry(map, offset, &entry)) {
		if (entry->object.vm_object == VM_OBJECT_NULL ||
			!entry->object.vm_object->phys_contiguous) {
        		if((*upl_size/page_size) > MAX_UPL_TRANSFER) {
               			*upl_size = MAX_UPL_TRANSFER * page_size;
			}
		}
		if((entry->vme_end - offset) < *upl_size) {
			*upl_size = entry->vme_end - offset;
		}
		if (caller_flags & UPL_QUERY_OBJECT_TYPE) {
			if (entry->object.vm_object == VM_OBJECT_NULL) {
				*flags = 0;
			} else if (entry->object.vm_object->private) {
				*flags = UPL_DEV_MEMORY;
				if (entry->object.vm_object->phys_contiguous) {
					*flags |= UPL_PHYS_CONTIG;
				}
			} else  {
				*flags = 0;
			}
			vm_map_unlock(map);
			return KERN_SUCCESS;
		}
		/*
		 *      Create an object if necessary.
		 */
		if (entry->object.vm_object == VM_OBJECT_NULL) {
			entry->object.vm_object = vm_object_allocate(
				(vm_size_t)(entry->vme_end - entry->vme_start));
			entry->offset = 0;
		}
		if (!(caller_flags & UPL_COPYOUT_FROM)) {
			if (!(entry->protection & VM_PROT_WRITE)) {
				vm_map_unlock(map);
				return KERN_PROTECTION_FAILURE;
			}
			if (entry->needs_copy)  {
				vm_map_t		local_map;
				vm_object_t		object;
				vm_map_offset_t		offset_hi;
				vm_map_offset_t		offset_lo;
				vm_object_offset_t	new_offset;
				vm_prot_t		prot;
				boolean_t		wired;
				vm_behavior_t		behavior;
				vm_map_version_t	version;
				vm_map_t		real_map;

				local_map = map;
				vm_map_lock_write_to_read(map);
				if(vm_map_lookup_locked(&local_map,
					offset, VM_PROT_WRITE,
					&version, &object,
					&new_offset, &prot, &wired,
					&behavior, &offset_lo,
					&offset_hi, &real_map)) {
					vm_map_unlock(local_map);
					return KERN_FAILURE;
				}
				if (real_map != map) {
					vm_map_unlock(real_map);
				}
				vm_object_unlock(object);
				vm_map_unlock(local_map);

				goto REDISCOVER_ENTRY;
			}
		}
		if (entry->is_sub_map) {
			vm_map_t	submap;

			submap = entry->object.sub_map;
			local_start = entry->vme_start;
			local_offset = entry->offset;
			vm_map_reference(submap);
			vm_map_unlock(map);

			ret = (vm_map_create_upl(submap, 
				local_offset + (offset - local_start), 
				upl_size, upl, page_list, count, 
				flags));

			vm_map_deallocate(submap);
			return ret;
		}
					
		if (sync_cow_data) {
			if (entry->object.vm_object->shadow
				    || entry->object.vm_object->copy) {

				local_object = entry->object.vm_object;
				local_start = entry->vme_start;
				local_offset = entry->offset;
				vm_object_reference(local_object);
				vm_map_unlock(map);

				if (entry->object.vm_object->shadow && 
					   entry->object.vm_object->copy) {
				   vm_object_lock_request(
					local_object->shadow,
					(vm_object_offset_t)
					((offset - local_start) +
					 local_offset) +
					local_object->shadow_offset,
					*upl_size, FALSE, 
					MEMORY_OBJECT_DATA_SYNC,
					VM_PROT_NO_CHANGE);
				}
				sync_cow_data = FALSE;
				vm_object_deallocate(local_object);
				goto REDISCOVER_ENTRY;
			}
		}

		if (force_data_sync) {

			local_object = entry->object.vm_object;
			local_start = entry->vme_start;
			local_offset = entry->offset;
			vm_object_reference(local_object);
		        vm_map_unlock(map);

			vm_object_lock_request(
				   local_object,
				   (vm_object_offset_t)
				   ((offset - local_start) + local_offset),
				   (vm_object_size_t)*upl_size, FALSE, 
				   MEMORY_OBJECT_DATA_SYNC,
				   VM_PROT_NO_CHANGE);
			force_data_sync = FALSE;
			vm_object_deallocate(local_object);
			goto REDISCOVER_ENTRY;
		}

		if(!(entry->object.vm_object->private)) {
			if(*upl_size > (MAX_UPL_TRANSFER*PAGE_SIZE))
				*upl_size = (MAX_UPL_TRANSFER*PAGE_SIZE);
			if(entry->object.vm_object->phys_contiguous) {
				*flags = UPL_PHYS_CONTIG;
			} else {
				*flags = 0;
			}
		} else {
			*flags = UPL_DEV_MEMORY | UPL_PHYS_CONTIG;
		}
		local_object = entry->object.vm_object;
		local_offset = entry->offset;
		local_start = entry->vme_start;
		vm_object_reference(local_object);
		vm_map_unlock(map);
		if(caller_flags & UPL_SET_IO_WIRE) {
			ret = (vm_object_iopl_request(local_object, 
				(vm_object_offset_t)
				   ((offset - local_start) 
						+ local_offset),
				*upl_size,
				upl,
				page_list,
				count,
				caller_flags));
		} else {
			ret = (vm_object_upl_request(local_object, 
				(vm_object_offset_t)
				   ((offset - local_start) 
						+ local_offset),
				*upl_size,
				upl,
				page_list,
				count,
				caller_flags));
		}
		vm_object_deallocate(local_object);
		return(ret);
	} 

	vm_map_unlock(map);
	return(KERN_FAILURE);

}

/*
 * Internal routine to enter a UPL into a VM map.
 * 
 * JMM - This should just be doable through the standard
 * vm_map_enter() API.
 */
kern_return_t
vm_map_enter_upl(
	vm_map_t		map, 
	upl_t			upl, 
	vm_map_offset_t	*dst_addr)
{
	vm_map_size_t	 	size;
	vm_object_offset_t 	offset;
	vm_map_offset_t		addr;
	vm_page_t		m;
	kern_return_t		kr;

	if (upl == UPL_NULL)
		return KERN_INVALID_ARGUMENT;

	upl_lock(upl);

	/* check to see if already mapped */
	if(UPL_PAGE_LIST_MAPPED & upl->flags) {
		upl_unlock(upl);
		return KERN_FAILURE;
	}

	if((!(upl->map_object->pageout)) && 	
		!((upl->flags & (UPL_DEVICE_MEMORY | UPL_IO_WIRE)) ||
					(upl->map_object->phys_contiguous))) {
		vm_object_t 		object;
		vm_page_t		alias_page;
		vm_object_offset_t	new_offset;
		int			pg_num;
		wpl_array_t 		lite_list;

		if(upl->flags & UPL_INTERNAL) {
			lite_list = (wpl_array_t) 
				((((uintptr_t)upl) + sizeof(struct upl))
				+ ((upl->size/PAGE_SIZE) 
						* sizeof(upl_page_info_t)));
		} else {
			lite_list = (wpl_array_t)
				(((uintptr_t)upl) + sizeof(struct upl));
		}
		object = upl->map_object;
		upl->map_object = vm_object_allocate(upl->size);
		vm_object_lock(upl->map_object);
		upl->map_object->shadow = object;
		upl->map_object->pageout = TRUE;
		upl->map_object->can_persist = FALSE;
		upl->map_object->copy_strategy = 
				MEMORY_OBJECT_COPY_NONE;
		upl->map_object->shadow_offset = 
				upl->offset - object->paging_offset;
		upl->map_object->wimg_bits = object->wimg_bits;
		offset = upl->map_object->shadow_offset;
		new_offset = 0;
		size = upl->size;

		vm_object_lock(object);

		while(size) {
		   pg_num = (new_offset)/PAGE_SIZE;
		   if(lite_list[pg_num>>5] & (1 << (pg_num & 31))) {
			vm_object_unlock(object);
			VM_PAGE_GRAB_FICTITIOUS(alias_page);
			vm_object_lock(object);
			m = vm_page_lookup(object, offset);
			if (m == VM_PAGE_NULL) {
				panic("vm_upl_map: page missing\n");
			}

			vm_object_paging_begin(object);

			/*
 		 	* Convert the fictitious page to a private 
			 * shadow of the real page.
			 */
			assert(alias_page->fictitious);
			alias_page->fictitious = FALSE;
			alias_page->private = TRUE;
			alias_page->pageout = TRUE;
			alias_page->phys_page = m->phys_page;

		        vm_page_lock_queues();
			vm_page_wire(alias_page);
		        vm_page_unlock_queues();

			/*
			 * ENCRYPTED SWAP:
			 * The virtual page ("m") has to be wired in some way
			 * here or its physical page ("m->phys_page") could
			 * be recycled at any time.
			 * Assuming this is enforced by the caller, we can't
			 * get an encrypted page here.  Since the encryption
			 * key depends on the VM page's "pager" object and
			 * the "paging_offset", we couldn't handle 2 pageable
			 * VM pages (with different pagers and paging_offsets)
			 * sharing the same physical page:  we could end up
			 * encrypting with one key (via one VM page) and
			 * decrypting with another key (via the alias VM page).
			 */
			ASSERT_PAGE_DECRYPTED(m);

			vm_page_insert(alias_page, 
					upl->map_object, new_offset);
			assert(!alias_page->wanted);
			alias_page->busy = FALSE;
			alias_page->absent = FALSE;
		   }

		   size -= PAGE_SIZE;
		   offset += PAGE_SIZE_64;
		   new_offset += PAGE_SIZE_64;
		}
		vm_object_unlock(object);
		vm_object_unlock(upl->map_object);
	}
	if ((upl->flags & (UPL_DEVICE_MEMORY | UPL_IO_WIRE)) || upl->map_object->phys_contiguous)
	        offset = upl->offset - upl->map_object->paging_offset;
	else
	        offset = 0;

	size = upl->size;
	
	vm_object_lock(upl->map_object);
	upl->map_object->ref_count++;
	vm_object_res_reference(upl->map_object);
	vm_object_unlock(upl->map_object);

	*dst_addr = 0;


	/* NEED A UPL_MAP ALIAS */
	kr = vm_map_enter(map, dst_addr, (vm_map_size_t)size, (vm_map_offset_t) 0,
		VM_FLAGS_ANYWHERE, upl->map_object, offset, FALSE,
		VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);

	if (kr != KERN_SUCCESS) {
		upl_unlock(upl);
		return(kr);
	}

	vm_object_lock(upl->map_object);

	for(addr=*dst_addr; size > 0; size-=PAGE_SIZE,addr+=PAGE_SIZE) {
		m = vm_page_lookup(upl->map_object, offset);
		if(m) {
		   unsigned int	cache_attr;
		   cache_attr = ((unsigned int)m->object->wimg_bits) & VM_WIMG_MASK;
	
		   PMAP_ENTER(map->pmap, addr,
				m, VM_PROT_ALL, 
				cache_attr, TRUE);
		}
		offset+=PAGE_SIZE_64;
	}
	vm_object_unlock(upl->map_object);

	upl->ref_count++;  /* hold a reference for the mapping */
	upl->flags |= UPL_PAGE_LIST_MAPPED;
	upl->kaddr = *dst_addr;
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
	vm_map_t	map, 
	upl_t		upl)
{
	vm_address_t	addr;
	upl_size_t	size;

	if (upl == UPL_NULL)
		return KERN_INVALID_ARGUMENT;

	upl_lock(upl);
	if(upl->flags & UPL_PAGE_LIST_MAPPED) {
		addr = upl->kaddr;
		size = upl->size;
		assert(upl->ref_count > 1);
		upl->ref_count--;		/* removing mapping ref */
		upl->flags &= ~UPL_PAGE_LIST_MAPPED;
		upl->kaddr = (vm_offset_t) 0;
		upl_unlock(upl);

		vm_map_remove(  map,
				vm_map_trunc_page(addr),
				vm_map_round_page(addr + size),
				VM_MAP_NO_FLAGS);
		return KERN_SUCCESS;
	}
	upl_unlock(upl);
	return KERN_FAILURE;
}

kern_return_t
upl_commit_range(
	upl_t			upl, 
	upl_offset_t		offset, 
	upl_size_t		size,
	int			flags,
	upl_page_info_t		*page_list,
	mach_msg_type_number_t	count,
	boolean_t		*empty) 
{
	upl_size_t		xfer_size = size;
	vm_object_t		shadow_object;
	vm_object_t		object = upl->map_object;
	vm_object_offset_t	target_offset;
	int			entry;
	wpl_array_t 		lite_list;
	int			occupied;
	int                     delayed_unlock = 0;
	int			clear_refmod = 0;
	boolean_t		shadow_internal;

	*empty = FALSE;

	if (upl == UPL_NULL)
		return KERN_INVALID_ARGUMENT;


	if (count == 0)
		page_list = NULL;

	if (object->pageout) {
		shadow_object = object->shadow;
	} else {
		shadow_object = object;
	}

	upl_lock(upl);

	if (upl->flags & UPL_ACCESS_BLOCKED) {
		/*
		 * We used this UPL to block access to the pages by marking
		 * them "busy".  Now we need to clear the "busy" bit to allow
		 * access to these pages again.
		 */
		flags |= UPL_COMMIT_ALLOW_ACCESS;
	}

	if (upl->flags & UPL_CLEAR_DIRTY)
	        flags |= UPL_COMMIT_CLEAR_DIRTY;

	if (upl->flags & UPL_DEVICE_MEMORY) {
		xfer_size = 0;
	} else if ((offset + size) > upl->size) {
		upl_unlock(upl);
		return KERN_FAILURE;
	}

	if (upl->flags & UPL_INTERNAL) {
		lite_list = (wpl_array_t) 
			((((uintptr_t)upl) + sizeof(struct upl))
			+ ((upl->size/PAGE_SIZE) * sizeof(upl_page_info_t)));
	} else {
		lite_list = (wpl_array_t)
			(((uintptr_t)upl) + sizeof(struct upl));
	}
	if (object != shadow_object)
	        vm_object_lock(object);
	vm_object_lock(shadow_object);

	shadow_internal = shadow_object->internal;

	entry = offset/PAGE_SIZE;
	target_offset = (vm_object_offset_t)offset;

	while (xfer_size) {
		vm_page_t	t,m;
		upl_page_info_t *p;

		m = VM_PAGE_NULL;

		if (upl->flags & UPL_LITE) {
		        int	pg_num;

			pg_num = target_offset/PAGE_SIZE;

			if (lite_list[pg_num>>5] & (1 << (pg_num & 31))) {
			        lite_list[pg_num>>5] &= ~(1 << (pg_num & 31));
				m = vm_page_lookup(shadow_object,
						   target_offset + (upl->offset - 
								    shadow_object->paging_offset));
			}
		}
		if (object->pageout) {
			if ((t = vm_page_lookup(object, target_offset))	!= NULL) {
				t->pageout = FALSE;

				if (delayed_unlock) {
				        delayed_unlock = 0;
					vm_page_unlock_queues();
				}
				VM_PAGE_FREE(t);

				if (m == NULL) {
					m = vm_page_lookup(
					    shadow_object, 
					    target_offset + 
						object->shadow_offset);
				}
				if (m != VM_PAGE_NULL)
					vm_object_paging_end(m->object);
			}
		}
		if (m != VM_PAGE_NULL) {

		   clear_refmod = 0;

		   if (upl->flags & UPL_IO_WIRE) {

		        if (delayed_unlock == 0)
			        vm_page_lock_queues();

			vm_page_unwire(m);

		        if (delayed_unlock++ > DELAYED_UNLOCK_LIMIT) {
			        delayed_unlock = 0;
			        vm_page_unlock_queues();
			}
		   	if (page_list) {
				page_list[entry].phys_addr = 0;
			}
		   	if (flags & UPL_COMMIT_SET_DIRTY) {
				m->dirty = TRUE;
		   	} else if (flags & UPL_COMMIT_CLEAR_DIRTY) {
				m->dirty = FALSE;
				clear_refmod |= VM_MEM_MODIFIED;
		   	}
		   	if (flags & UPL_COMMIT_INACTIVATE) {
				m->reference = FALSE;
				clear_refmod |= VM_MEM_REFERENCED;
              			vm_page_deactivate(m);
			}
			if (clear_refmod)
			        pmap_clear_refmod(m->phys_page, clear_refmod);

			if (flags & UPL_COMMIT_ALLOW_ACCESS) {
				/*
				 * We blocked access to the pages in this UPL.
				 * Clear the "busy" bit and wake up any waiter
				 * for this page.
				 */
				PAGE_WAKEUP_DONE(m);
			}

			target_offset += PAGE_SIZE_64;
			xfer_size -= PAGE_SIZE;
			entry++;
			continue;
		   }
		   if (delayed_unlock == 0)
		        vm_page_lock_queues();
		   /*
		    * make sure to clear the hardware
		    * modify or reference bits before
		    * releasing the BUSY bit on this page
		    * otherwise we risk losing a legitimate
		    * change of state
		    */
		   if (flags & UPL_COMMIT_CLEAR_DIRTY) {
			m->dirty = FALSE;
			clear_refmod |= VM_MEM_MODIFIED;
		   }
		   if (flags & UPL_COMMIT_INACTIVATE)
			clear_refmod |= VM_MEM_REFERENCED;

		   if (clear_refmod)
		        pmap_clear_refmod(m->phys_page, clear_refmod);

		   if (page_list) {
			p = &(page_list[entry]);
			if(p->phys_addr && p->pageout && !m->pageout) {
				m->busy = TRUE;
				m->pageout = TRUE;
				vm_page_wire(m);
			} else if (page_list[entry].phys_addr &&
					!p->pageout && m->pageout &&
					!m->dump_cleaning) {
				m->pageout = FALSE;
				m->absent = FALSE;
				m->overwriting = FALSE;
				vm_page_unwire(m);
				PAGE_WAKEUP_DONE(m);
			}
			page_list[entry].phys_addr = 0;
		   }
		   m->dump_cleaning = FALSE;
		   if(m->laundry) {
			   vm_pageout_throttle_up(m);
		   }
		   if(m->pageout) {
		      m->cleaning = FALSE;
		      m->pageout = FALSE;
#if MACH_CLUSTER_STATS
		      if (m->wanted) vm_pageout_target_collisions++;
#endif
		      if (pmap_disconnect(m->phys_page) & VM_MEM_MODIFIED)
			      m->dirty = TRUE;
		      else
			      m->dirty = FALSE;

		      if(m->dirty) {
                              vm_page_unwire(m);/* reactivates */

			      if (upl->flags & UPL_PAGEOUT) {
				      CLUSTER_STAT(vm_pageout_target_page_dirtied++;)
				      VM_STAT(reactivations++);
			      }
                              PAGE_WAKEUP_DONE(m);
              	      } else {
                            vm_page_free(m);/* clears busy, etc. */
 
			    if (upl->flags & UPL_PAGEOUT) {
			            CLUSTER_STAT(vm_pageout_target_page_freed++;)

			            if (page_list[entry].dirty)
				            VM_STAT(pageouts++);
			    }
       		      }
		      if (delayed_unlock++ > DELAYED_UNLOCK_LIMIT) {
			    delayed_unlock = 0;
			    vm_page_unlock_queues();
		      }
		      target_offset += PAGE_SIZE_64;
		      xfer_size -= PAGE_SIZE;
		      entry++;
                      continue;
		   }
#if MACH_CLUSTER_STATS
                   m->dirty = pmap_is_modified(m->phys_page);

                   if (m->dirty)   vm_pageout_cluster_dirtied++;
                   else            vm_pageout_cluster_cleaned++;
                   if (m->wanted)  vm_pageout_cluster_collisions++;
#else
                   m->dirty = 0;
#endif

                   if((m->busy) && (m->cleaning)) {
                   	/* the request_page_list case */
			if(m->absent) {
				m->absent = FALSE;
				if(shadow_object->absent_count == 1)
				      vm_object_absent_release(shadow_object);
				else
				      shadow_object->absent_count--;
			}
			m->overwriting = FALSE;
                        m->busy = FALSE;
                        m->dirty = FALSE;
                   } else if (m->overwriting) {
		         /* alternate request page list, write to 
		          * page_list case.  Occurs when the original
		          * page was wired at the time of the list
		          * request */
		         assert(m->wire_count != 0);
		         vm_page_unwire(m);/* reactivates */
		         m->overwriting = FALSE;
		   }
                   m->cleaning = FALSE;

		   /* It is a part of the semantic of COPYOUT_FROM */
		   /* UPLs that a commit implies cache sync 	      */
		   /* between the vm page and the backing store    */
		   /* this can be used to strip the precious bit   */
		   /* as well as clean */
		   if (upl->flags & UPL_PAGE_SYNC_DONE)
		         m->precious = FALSE;

		   if (flags & UPL_COMMIT_SET_DIRTY)
			m->dirty = TRUE;

		   if (flags & UPL_COMMIT_INACTIVATE) {
			m->reference = FALSE;
              		vm_page_deactivate(m);
		   } else if (!m->active && !m->inactive) {
                	if (m->reference)
				vm_page_activate(m);
			else
				vm_page_deactivate(m);
		   }

		   if (flags & UPL_COMMIT_ALLOW_ACCESS) {
			   /*
			    * We blocked access to the pages in this URL.
			    * Clear the "busy" bit on this page before we
			    * wake up any waiter.
			    */
                           m->busy = FALSE;
		   }

                   /*
                    * Wakeup any thread waiting for the page to be un-cleaning.
                    */
                   PAGE_WAKEUP(m);

		   if (delayed_unlock++ > DELAYED_UNLOCK_LIMIT) {
		         delayed_unlock = 0;
			 vm_page_unlock_queues();
		   }
		}
		target_offset += PAGE_SIZE_64;
		xfer_size -= PAGE_SIZE;
		entry++;
	}
	if (delayed_unlock)
	        vm_page_unlock_queues();

	occupied = 1;

	if (upl->flags & UPL_DEVICE_MEMORY)  {
		occupied = 0;
	} else if (upl->flags & UPL_LITE) {
		int	pg_num;
		int	i;
		pg_num = upl->size/PAGE_SIZE;
		pg_num = (pg_num + 31) >> 5;
		occupied = 0;
		for(i= 0; i<pg_num; i++) {
			if(lite_list[i] != 0) {
				occupied = 1;
				break;
			}
		}
	} else {
		if(queue_empty(&upl->map_object->memq)) {
			occupied = 0;
		}
	}

	if(occupied == 0) {
		if(upl->flags & UPL_COMMIT_NOTIFY_EMPTY) {
			*empty = TRUE;
		}
		if(object == shadow_object)
			vm_object_paging_end(shadow_object);
	}
	vm_object_unlock(shadow_object);
	if (object != shadow_object)
	        vm_object_unlock(object);
	upl_unlock(upl);

	return KERN_SUCCESS;
}

kern_return_t
upl_abort_range(
	upl_t			upl, 
	upl_offset_t		offset, 
	upl_size_t		size,
	int			error,
	boolean_t		*empty) 
{
	upl_size_t		xfer_size = size;
	vm_object_t		shadow_object;
	vm_object_t		object = upl->map_object;
	vm_object_offset_t	target_offset;
	int			entry;
	wpl_array_t 	 	lite_list;
	int			occupied;
	boolean_t		shadow_internal;

	*empty = FALSE;

	if (upl == UPL_NULL)
		return KERN_INVALID_ARGUMENT;

	if (upl->flags & UPL_IO_WIRE) {
		return upl_commit_range(upl, 
			offset, size, 0, 
			NULL, 0, empty);
	}

	if(object->pageout) {
		shadow_object = object->shadow;
	} else {
		shadow_object = object;
	}

	upl_lock(upl);
	if(upl->flags & UPL_DEVICE_MEMORY) {
		xfer_size = 0;
	} else if ((offset + size) > upl->size) {
		upl_unlock(upl);
		return KERN_FAILURE;
	}
	if (object != shadow_object)
	        vm_object_lock(object);
	vm_object_lock(shadow_object);

	shadow_internal = shadow_object->internal;

	if(upl->flags & UPL_INTERNAL) {
		lite_list = (wpl_array_t) 
			((((uintptr_t)upl) + sizeof(struct upl))
			+ ((upl->size/PAGE_SIZE) * sizeof(upl_page_info_t)));
	} else {
		lite_list = (wpl_array_t) 
			(((uintptr_t)upl) + sizeof(struct upl));
	}

	entry = offset/PAGE_SIZE;
	target_offset = (vm_object_offset_t)offset;
	while(xfer_size) {
		vm_page_t	t,m;

		m = VM_PAGE_NULL;
		if(upl->flags & UPL_LITE) {
			int	pg_num;
			pg_num = target_offset/PAGE_SIZE;
			if(lite_list[pg_num>>5] & (1 << (pg_num & 31))) {
				lite_list[pg_num>>5] &= ~(1 << (pg_num & 31));
				m = vm_page_lookup(shadow_object,
					target_offset + (upl->offset - 
						shadow_object->paging_offset));
			}
		}
		if(object->pageout) {
			if ((t = vm_page_lookup(object, target_offset))
								!= NULL) {
				t->pageout = FALSE;
				VM_PAGE_FREE(t);
				if(m == NULL) {
					m = vm_page_lookup(
					    shadow_object, 
					    target_offset + 
						object->shadow_offset);
				}
				if(m != VM_PAGE_NULL)
					vm_object_paging_end(m->object);
			}
		}
		if(m != VM_PAGE_NULL) {
			vm_page_lock_queues();
			if(m->absent) {
			        boolean_t must_free = TRUE;

				/* COPYOUT = FALSE case */
				/* check for error conditions which must */
				/* be passed back to the pages customer  */
				if(error & UPL_ABORT_RESTART) {
					m->restart = TRUE;
					m->absent = FALSE;
					vm_object_absent_release(m->object);
					m->page_error = KERN_MEMORY_ERROR;
					m->error = TRUE;
					must_free = FALSE;
				} else if(error & UPL_ABORT_UNAVAILABLE) {
					m->restart = FALSE;
					m->unusual = TRUE;
					must_free = FALSE;
				} else if(error & UPL_ABORT_ERROR) {
					m->restart = FALSE;
					m->absent = FALSE;
					vm_object_absent_release(m->object);
					m->page_error = KERN_MEMORY_ERROR;
					m->error = TRUE;
					must_free = FALSE;
				}

				/*
				 * ENCRYPTED SWAP:
				 * If the page was already encrypted,
				 * we don't really need to decrypt it
				 * now.  It will get decrypted later,
				 * on demand, as soon as someone needs
				 * to access its contents.
				 */

				m->cleaning = FALSE;
				m->overwriting = FALSE;
				PAGE_WAKEUP_DONE(m);

				if (must_free == TRUE) {
					vm_page_free(m);
				} else {
					vm_page_activate(m);
				}
				vm_page_unlock_queues();

				target_offset += PAGE_SIZE_64;
				xfer_size -= PAGE_SIZE;
				entry++;
				continue;
			}
			/*                          
		 	* Handle the trusted pager throttle.
		 	*/                     
			if (m->laundry) {
				vm_pageout_throttle_up(m);
			}         
			if(m->pageout) {
				assert(m->busy);
				assert(m->wire_count == 1);
				m->pageout = FALSE;
				vm_page_unwire(m);
			}
			m->dump_cleaning = FALSE;
			m->cleaning = FALSE;
			m->overwriting = FALSE;
#if	MACH_PAGEMAP
			vm_external_state_clr(
				m->object->existence_map, m->offset);
#endif	/* MACH_PAGEMAP */
			if(error & UPL_ABORT_DUMP_PAGES) {
				vm_page_free(m);
				pmap_disconnect(m->phys_page);
			} else {
				PAGE_WAKEUP_DONE(m);
			}
			vm_page_unlock_queues();
		}
		target_offset += PAGE_SIZE_64;
		xfer_size -= PAGE_SIZE;
		entry++;
	}
	occupied = 1;
	if (upl->flags & UPL_DEVICE_MEMORY)  {
		occupied = 0;
	} else if (upl->flags & UPL_LITE) {
		int	pg_num;
		int	i;
		pg_num = upl->size/PAGE_SIZE;
		pg_num = (pg_num + 31) >> 5;
		occupied = 0;
		for(i= 0; i<pg_num; i++) {
			if(lite_list[i] != 0) {
				occupied = 1;
				break;
			}
		}
	} else {
		if(queue_empty(&upl->map_object->memq)) {
			occupied = 0;
		}
	}

	if(occupied == 0) {
		if(upl->flags & UPL_COMMIT_NOTIFY_EMPTY) {
			*empty = TRUE;
		}
		if(object == shadow_object)
			vm_object_paging_end(shadow_object);
	}
	vm_object_unlock(shadow_object);
	if (object != shadow_object)
	        vm_object_unlock(object);

	upl_unlock(upl);

	return KERN_SUCCESS;
}

kern_return_t
upl_abort(
	upl_t	upl,
	int	error)
{
	vm_object_t		object = NULL;
	vm_object_t		shadow_object = NULL;
	vm_object_offset_t	offset;
	vm_object_offset_t	shadow_offset;
	vm_object_offset_t	target_offset;
	upl_size_t		i;
	wpl_array_t		lite_list;
	vm_page_t		t,m;
	int			occupied;
	boolean_t		shadow_internal;

	if (upl == UPL_NULL)
		return KERN_INVALID_ARGUMENT;

	if (upl->flags & UPL_IO_WIRE) {
		boolean_t	empty;
		return upl_commit_range(upl, 
			0, upl->size, 0, 
			NULL, 0, &empty);
	}

	upl_lock(upl);
	if(upl->flags & UPL_DEVICE_MEMORY) {
		upl_unlock(upl);
		return KERN_SUCCESS;
	}

	object = upl->map_object;

	if (object == NULL) {
		panic("upl_abort: upl object is not backed by an object");
		upl_unlock(upl);
		return KERN_INVALID_ARGUMENT;
	}

	if(object->pageout) {
		shadow_object = object->shadow;
		shadow_offset = object->shadow_offset;
	} else {
		shadow_object = object;
		shadow_offset = upl->offset - object->paging_offset;
	}

	if(upl->flags & UPL_INTERNAL) {
		lite_list = (wpl_array_t)
			((((uintptr_t)upl) + sizeof(struct upl))
			+ ((upl->size/PAGE_SIZE) * sizeof(upl_page_info_t)));
	} else {
		lite_list = (wpl_array_t)
			(((uintptr_t)upl) + sizeof(struct upl));
	}
	offset = 0;

	if (object != shadow_object)
	        vm_object_lock(object);
	vm_object_lock(shadow_object);

	shadow_internal = shadow_object->internal;

	for(i = 0; i<(upl->size); i+=PAGE_SIZE, offset += PAGE_SIZE_64) {
		m = VM_PAGE_NULL;
		target_offset = offset + shadow_offset;
		if(upl->flags & UPL_LITE) {
			int	pg_num;
			pg_num = offset/PAGE_SIZE;
			if(lite_list[pg_num>>5] & (1 << (pg_num & 31))) {
				lite_list[pg_num>>5] &= ~(1 << (pg_num & 31));
				m = vm_page_lookup(
					shadow_object, target_offset);
			}
		}
		if(object->pageout) {
			if ((t = vm_page_lookup(object, offset)) != NULL) {
				t->pageout = FALSE;
				VM_PAGE_FREE(t);
				if(m == NULL) {
					m = vm_page_lookup(
					    shadow_object, target_offset);
				}
				if(m != VM_PAGE_NULL)
					vm_object_paging_end(m->object);
			}
		}
		if(m != VM_PAGE_NULL) {
			vm_page_lock_queues();
			if(m->absent) {
			        boolean_t must_free = TRUE;

				/* COPYOUT = FALSE case */
				/* check for error conditions which must */
				/* be passed back to the pages customer  */
				if(error & UPL_ABORT_RESTART) {
					m->restart = TRUE;
					m->absent = FALSE;
					vm_object_absent_release(m->object);
					m->page_error = KERN_MEMORY_ERROR;
					m->error = TRUE;
					must_free = FALSE;
				} else if(error & UPL_ABORT_UNAVAILABLE) {
					m->restart = FALSE;
					m->unusual = TRUE;
					must_free = FALSE;
				} else if(error & UPL_ABORT_ERROR) {
					m->restart = FALSE;
					m->absent = FALSE;
					vm_object_absent_release(m->object);
					m->page_error = KERN_MEMORY_ERROR;
					m->error = TRUE;
					must_free = FALSE;
				}

				/*
				 * ENCRYPTED SWAP:
				 * If the page was already encrypted,
				 * we don't really need to decrypt it
				 * now.  It will get decrypted later,
				 * on demand, as soon as someone needs
				 * to access its contents.
				 */

				m->cleaning = FALSE;
				m->overwriting = FALSE;
				PAGE_WAKEUP_DONE(m);

				if (must_free == TRUE) {
					vm_page_free(m);
				} else {
					vm_page_activate(m);
				}
				vm_page_unlock_queues();
				continue;
			}
			/*                          
			 * Handle the trusted pager throttle.
			 */                     
			if (m->laundry) { 
				vm_pageout_throttle_up(m);
			}         
			if(m->pageout) {
				assert(m->busy);
				assert(m->wire_count == 1);
				m->pageout = FALSE;
				vm_page_unwire(m);
			}
			m->dump_cleaning = FALSE;
			m->cleaning = FALSE;
			m->overwriting = FALSE;
#if	MACH_PAGEMAP
			vm_external_state_clr(
				m->object->existence_map, m->offset);
#endif	/* MACH_PAGEMAP */
			if(error & UPL_ABORT_DUMP_PAGES) {
				vm_page_free(m);
				pmap_disconnect(m->phys_page);
			} else {
				PAGE_WAKEUP_DONE(m);
			}
			vm_page_unlock_queues();
		}
	}
	occupied = 1;
	if (upl->flags & UPL_DEVICE_MEMORY)  {
		occupied = 0;
	} else if (upl->flags & UPL_LITE) {
		int	pg_num;
		int	j;
		pg_num = upl->size/PAGE_SIZE;
		pg_num = (pg_num + 31) >> 5;
		occupied = 0;
		for(j= 0; j<pg_num; j++) {
			if(lite_list[j] != 0) {
				occupied = 1;
				break;
			}
		}
	} else {
		if(queue_empty(&upl->map_object->memq)) {
			occupied = 0;
		}
	}

	if(occupied == 0) {
		if(object == shadow_object)
			vm_object_paging_end(shadow_object);
	}
	vm_object_unlock(shadow_object);
	if (object != shadow_object)
	        vm_object_unlock(object);

	upl_unlock(upl);
	return KERN_SUCCESS;
}

/* an option on commit should be wire */
kern_return_t
upl_commit(
	upl_t			upl,
	upl_page_info_t		*page_list,
	mach_msg_type_number_t	count)
{
	if (upl == UPL_NULL)
		return KERN_INVALID_ARGUMENT;

	if(upl->flags & (UPL_LITE | UPL_IO_WIRE)) {
		boolean_t	empty;
		return upl_commit_range(upl, 0, upl->size, 0, 
					page_list, count, &empty);
	}

	if (count == 0)
		page_list = NULL;

	upl_lock(upl);
	if (upl->flags & UPL_DEVICE_MEMORY)
		page_list = NULL;

	if (upl->flags & UPL_ENCRYPTED) {
		/*
		 * ENCRYPTED SWAP:
		 * This UPL was encrypted, but we don't need
		 * to decrypt here.  We'll decrypt each page
		 * later, on demand, as soon as someone needs
		 * to access the page's contents.
		 */
	}

	if ((upl->flags & UPL_CLEAR_DIRTY) ||
		(upl->flags & UPL_PAGE_SYNC_DONE) || page_list) {
		vm_object_t	shadow_object = upl->map_object->shadow;
		vm_object_t	object = upl->map_object;
		vm_object_offset_t target_offset;
		upl_size_t	xfer_end;
		int		entry;

		vm_page_t	t, m;
		upl_page_info_t	*p;

		if (object != shadow_object)
		        vm_object_lock(object);
		vm_object_lock(shadow_object);

		entry = 0;
		target_offset = object->shadow_offset;
		xfer_end = upl->size + object->shadow_offset;

		while(target_offset < xfer_end) {

			if ((t = vm_page_lookup(object, 
				target_offset - object->shadow_offset))
				== NULL) {
				target_offset += PAGE_SIZE_64;
				entry++;
				continue;
			}

			m = vm_page_lookup(shadow_object, target_offset);
			if(m != VM_PAGE_NULL) {
			    /*
			     * ENCRYPTED SWAP:
			     * If this page was encrypted, we
			     * don't need to decrypt it here.
			     * We'll decrypt it later, on demand,
			     * as soon as someone needs to access
			     * its contents.
			     */

			    if (upl->flags & UPL_CLEAR_DIRTY) {
				pmap_clear_modify(m->phys_page);
				m->dirty = FALSE;
			    }
			    /* It is a part of the semantic of */
			    /* COPYOUT_FROM UPLs that a commit */
			    /* implies cache sync between the  */
			    /* vm page and the backing store   */
			    /* this can be used to strip the   */
			    /* precious bit as well as clean   */
			    if (upl->flags & UPL_PAGE_SYNC_DONE)
				m->precious = FALSE;

			   if(page_list) {
			   	p = &(page_list[entry]);
			   	if(page_list[entry].phys_addr &&
						p->pageout && !m->pageout) {
					vm_page_lock_queues();
					m->busy = TRUE;
					m->pageout = TRUE;
					vm_page_wire(m);
					vm_page_unlock_queues();
			   	} else if (page_list[entry].phys_addr &&
						!p->pageout && m->pageout &&
						!m->dump_cleaning) {
					vm_page_lock_queues();
					m->pageout = FALSE;
					m->absent = FALSE;
					m->overwriting = FALSE;
					vm_page_unwire(m);
					PAGE_WAKEUP_DONE(m);
					vm_page_unlock_queues();
			   	}
			   	page_list[entry].phys_addr = 0;
			   }
			}
			target_offset += PAGE_SIZE_64;
			entry++;
		}
		vm_object_unlock(shadow_object);
		if (object != shadow_object)
		        vm_object_unlock(object);

	}
	if (upl->flags & UPL_DEVICE_MEMORY)  {
		vm_object_lock(upl->map_object->shadow);
		if(upl->map_object == upl->map_object->shadow)
			vm_object_paging_end(upl->map_object->shadow);
		vm_object_unlock(upl->map_object->shadow);
	}
	upl_unlock(upl);
	return KERN_SUCCESS;
}



kern_return_t
vm_object_iopl_request(
	vm_object_t		object,
	vm_object_offset_t	offset,
	upl_size_t		size,
	upl_t			*upl_ptr,
	upl_page_info_array_t	user_page_list,
	unsigned int		*page_list_count,
	int			cntrl_flags)
{
	vm_page_t		dst_page;
	vm_object_offset_t	dst_offset = offset;
	upl_size_t		xfer_size = size;
	upl_t			upl = NULL;
	unsigned int		entry;
	wpl_array_t 		lite_list = NULL;
	int			page_field_size;
	int                     delayed_unlock = 0;
	int			no_zero_fill = FALSE;
	vm_page_t		alias_page = NULL;
	kern_return_t		ret;
	vm_prot_t		prot;


	if (cntrl_flags & ~UPL_VALID_FLAGS) {
		/*
		 * For forward compatibility's sake,
		 * reject any unknown flag.
		 */
		return KERN_INVALID_VALUE;
	}

	if (cntrl_flags & UPL_ENCRYPT) {
		/*
		 * ENCRYPTED SWAP:
		 * The paging path doesn't use this interface,
		 * so we don't support the UPL_ENCRYPT flag
		 * here.  We won't encrypt the pages.
		 */
		assert(! (cntrl_flags & UPL_ENCRYPT));
	}

	if (cntrl_flags & UPL_NOZEROFILL)
	        no_zero_fill = TRUE;

	if (cntrl_flags & UPL_COPYOUT_FROM)
		prot = VM_PROT_READ;
	else
		prot = VM_PROT_READ | VM_PROT_WRITE;

	if(((size/page_size) > MAX_UPL_TRANSFER) && !object->phys_contiguous) {
		size = MAX_UPL_TRANSFER * page_size;
	}

	if(cntrl_flags & UPL_SET_INTERNAL)
		if(page_list_count != NULL)
			*page_list_count = MAX_UPL_TRANSFER;
	if(((cntrl_flags & UPL_SET_INTERNAL) && !(object->phys_contiguous)) &&
	   ((page_list_count != NULL) && (*page_list_count != 0)
				&& *page_list_count < (size/page_size)))
		return KERN_INVALID_ARGUMENT;

	if((!object->internal) && (object->paging_offset != 0))
		panic("vm_object_upl_request: vnode object with non-zero paging offset\n");

	if(object->phys_contiguous) {
		/* No paging operations are possible against this memory */
		/* and so no need for map object, ever */
		cntrl_flags |= UPL_SET_LITE;
	}

	if(upl_ptr) {
		if(cntrl_flags & UPL_SET_INTERNAL) {
			if(cntrl_flags & UPL_SET_LITE) {
				upl = upl_create(
					UPL_CREATE_INTERNAL | UPL_CREATE_LITE,
					size);
				user_page_list = (upl_page_info_t *)
				   (((uintptr_t)upl) + sizeof(struct upl));
				lite_list = (wpl_array_t)
					(((uintptr_t)user_page_list) + 
					((size/PAGE_SIZE) * 
						sizeof(upl_page_info_t)));
				page_field_size = ((size/PAGE_SIZE) + 7) >> 3;
				page_field_size = 
					(page_field_size + 3) & 0xFFFFFFFC;
				bzero((char *)lite_list, page_field_size);
				upl->flags = 
					UPL_LITE | UPL_INTERNAL | UPL_IO_WIRE;
			} else {
				upl = upl_create(UPL_CREATE_INTERNAL, size);
				user_page_list = (upl_page_info_t *)
					(((uintptr_t)upl) 
						+ sizeof(struct upl));
				upl->flags = UPL_INTERNAL | UPL_IO_WIRE;
			}
		} else {
			if(cntrl_flags & UPL_SET_LITE) {
				upl = upl_create(UPL_CREATE_LITE, size);
				lite_list = (wpl_array_t)
				   (((uintptr_t)upl) + sizeof(struct upl));
				page_field_size = ((size/PAGE_SIZE) + 7) >> 3;
				page_field_size = 
					(page_field_size + 3) & 0xFFFFFFFC;
				bzero((char *)lite_list, page_field_size);
				upl->flags = UPL_LITE | UPL_IO_WIRE;
			} else {
				upl = upl_create(UPL_CREATE_EXTERNAL, size);
				upl->flags = UPL_IO_WIRE;
			}
		}

		if(object->phys_contiguous) {
			upl->map_object = object;
			/* don't need any shadow mappings for this one */
			/* since it is already I/O memory */
			upl->flags |= UPL_DEVICE_MEMORY;

			vm_object_lock(object);
			vm_object_paging_begin(object);
			vm_object_unlock(object);

			/* paging in progress also protects the paging_offset */
			upl->offset = offset + object->paging_offset;
			upl->size = size;
			*upl_ptr = upl;
			if(user_page_list) {
				user_page_list[0].phys_addr = 
				  (offset + object->shadow_offset)>>PAGE_SHIFT;
				user_page_list[0].device = TRUE;
			}

			if(page_list_count != NULL) {
				if (upl->flags & UPL_INTERNAL) {
					*page_list_count = 0;
				} else {
					*page_list_count = 1;
				}
			}
			return KERN_SUCCESS;
		}
		if(user_page_list)
			user_page_list[0].device = FALSE;
			
		if(cntrl_flags & UPL_SET_LITE) {
			upl->map_object = object;
		} else {
			upl->map_object = vm_object_allocate(size);
			vm_object_lock(upl->map_object);
			upl->map_object->shadow = object;
			upl->map_object->pageout = TRUE;
			upl->map_object->can_persist = FALSE;
			upl->map_object->copy_strategy = 
					MEMORY_OBJECT_COPY_NONE;
			upl->map_object->shadow_offset = offset;
			upl->map_object->wimg_bits = object->wimg_bits;
			vm_object_unlock(upl->map_object);
		}
	}
	vm_object_lock(object);
	vm_object_paging_begin(object);

	if (!object->phys_contiguous) {
		/* Protect user space from future COW operations */
		object->true_share = TRUE;
		if (object->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC)
			object->copy_strategy = MEMORY_OBJECT_COPY_DELAY;
	}

	/* we can lock the upl offset now that paging_in_progress is set */
	if(upl_ptr) {
		upl->size = size;
		upl->offset = offset + object->paging_offset;
		*upl_ptr = upl;
#ifdef UPL_DEBUG
		queue_enter(&object->uplq, upl, upl_t, uplq);
#endif /* UPL_DEBUG */
	}

	if (cntrl_flags & UPL_BLOCK_ACCESS) {
		/*
		 * The user requested that access to the pages in this URL
		 * be blocked until the UPL is commited or aborted.
		 */
		upl->flags |= UPL_ACCESS_BLOCKED;
	}

	entry = 0;
	while (xfer_size) {
		if((alias_page == NULL) && !(cntrl_flags & UPL_SET_LITE)) {
		        if (delayed_unlock) {
			        delayed_unlock = 0;
			        vm_page_unlock_queues();
			}
			vm_object_unlock(object);
			VM_PAGE_GRAB_FICTITIOUS(alias_page);
			vm_object_lock(object);
		}
		dst_page = vm_page_lookup(object, dst_offset);

		/*
		 * ENCRYPTED SWAP:
		 * If the page is encrypted, we need to decrypt it,
		 * so force a soft page fault.
		 */
		if ((dst_page == VM_PAGE_NULL) || (dst_page->busy) ||
		    (dst_page->encrypted) ||
		    (dst_page->unusual && (dst_page->error || 
					   dst_page->restart ||
					   dst_page->absent ||
					   dst_page->fictitious ||
					   (prot & dst_page->page_lock)))) {
			vm_fault_return_t	result;
		   do {
			vm_page_t	top_page;
			kern_return_t	error_code;
			int		interruptible;

			vm_object_offset_t	lo_offset = offset;
			vm_object_offset_t	hi_offset = offset + size;


		        if (delayed_unlock) {
			        delayed_unlock = 0;
			        vm_page_unlock_queues();
			}

			if(cntrl_flags & UPL_SET_INTERRUPTIBLE) {
				interruptible = THREAD_ABORTSAFE;
			} else {
				interruptible = THREAD_UNINT;
			}

			result = vm_fault_page(object, dst_offset,
				prot | VM_PROT_WRITE, FALSE, 
				interruptible,
				lo_offset, hi_offset,
				VM_BEHAVIOR_SEQUENTIAL,
				&prot, &dst_page, &top_page,
			        (int *)0,
				&error_code, no_zero_fill, FALSE, NULL, 0);

			switch(result) {
			case VM_FAULT_SUCCESS:

				PAGE_WAKEUP_DONE(dst_page);

				/*
				 *	Release paging references and
				 *	top-level placeholder page, if any.
				 */

				if(top_page != VM_PAGE_NULL) {
					vm_object_t local_object;
					local_object = 
						top_page->object;
					if(top_page->object 
						!= dst_page->object) {
						vm_object_lock(
							local_object);
						VM_PAGE_FREE(top_page);
						vm_object_paging_end(
							local_object);
						vm_object_unlock(
							local_object);
					} else {
						VM_PAGE_FREE(top_page);
						vm_object_paging_end(
							local_object);
					}
				}

				break;
			
				
			case VM_FAULT_RETRY:
				vm_object_lock(object);
				vm_object_paging_begin(object);
				break;

			case VM_FAULT_FICTITIOUS_SHORTAGE:
				vm_page_more_fictitious();
				vm_object_lock(object);
				vm_object_paging_begin(object);
				break;

			case VM_FAULT_MEMORY_SHORTAGE:
				if (vm_page_wait(interruptible)) {
					vm_object_lock(object);
					vm_object_paging_begin(object);
					break;
				}
				/* fall thru */

			case VM_FAULT_INTERRUPTED:
				error_code = MACH_SEND_INTERRUPTED;
			case VM_FAULT_MEMORY_ERROR:
				ret = (error_code ? error_code:
					KERN_MEMORY_ERROR);
				vm_object_lock(object);
				for(; offset < dst_offset;
						offset += PAGE_SIZE) {
				   dst_page = vm_page_lookup(
						object, offset);
				   if(dst_page == VM_PAGE_NULL)
					panic("vm_object_iopl_request: Wired pages missing. \n");
				   vm_page_lock_queues();
				   vm_page_unwire(dst_page);
				   vm_page_unlock_queues();
				   VM_STAT(reactivations++);
				}
				vm_object_unlock(object);
				upl_destroy(upl);
			   	return ret;
			}
		   } while ((result != VM_FAULT_SUCCESS) 
				|| (result == VM_FAULT_INTERRUPTED));
		}
		if (delayed_unlock == 0)
		        vm_page_lock_queues();
		vm_page_wire(dst_page);

		if (cntrl_flags & UPL_BLOCK_ACCESS) {
			/*
			 * Mark the page "busy" to block any future page fault
			 * on this page.  We'll also remove the mapping
			 * of all these pages before leaving this routine.
			 */
			assert(!dst_page->fictitious);
			dst_page->busy = TRUE;
		}

		if (upl_ptr) {
			if (cntrl_flags & UPL_SET_LITE) {
				int	pg_num;
				pg_num = (dst_offset-offset)/PAGE_SIZE;
				lite_list[pg_num>>5] |= 1 << (pg_num & 31);
			} else {
				/*
	 			 * Convert the fictitious page to a 
				 * private shadow of the real page.
	 			 */
				assert(alias_page->fictitious);
				alias_page->fictitious = FALSE;
				alias_page->private = TRUE;
				alias_page->pageout = TRUE;
				alias_page->phys_page = dst_page->phys_page;
				vm_page_wire(alias_page);

				vm_page_insert(alias_page, 
					upl->map_object, size - xfer_size);
				assert(!alias_page->wanted);
				alias_page->busy = FALSE;
				alias_page->absent = FALSE;
			}

			/* expect the page to be used */
			dst_page->reference = TRUE;

	   		if (!(cntrl_flags & UPL_COPYOUT_FROM))
				dst_page->dirty = TRUE;
			alias_page = NULL;

			if (user_page_list) {
				user_page_list[entry].phys_addr
					= dst_page->phys_page;
				user_page_list[entry].dirty =
						dst_page->dirty;
				user_page_list[entry].pageout =
			   			dst_page->pageout;
				user_page_list[entry].absent =
			   			dst_page->absent;
				user_page_list[entry].precious =
						dst_page->precious;
			}
		}
		if (delayed_unlock++ > DELAYED_UNLOCK_LIMIT) {
		        delayed_unlock = 0;
			vm_page_unlock_queues();
		}
		entry++;
		dst_offset += PAGE_SIZE_64;
		xfer_size -= PAGE_SIZE;
	}
	if (delayed_unlock)
	        vm_page_unlock_queues();

	if (upl->flags & UPL_INTERNAL) {
		if(page_list_count != NULL)
			*page_list_count = 0;
	} else if (*page_list_count > entry) {
		if(page_list_count != NULL)
			*page_list_count = entry;
	}

	if (alias_page != NULL) {
		vm_page_lock_queues();
		vm_page_free(alias_page);
		vm_page_unlock_queues();
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
	}

	return KERN_SUCCESS;
}

kern_return_t
upl_transpose(
	upl_t		upl1,
	upl_t		upl2)
{
	kern_return_t		retval;
	boolean_t		upls_locked;
	vm_object_t		object1, object2;

	if (upl1 == UPL_NULL || upl2 == UPL_NULL || upl1 == upl2) {
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
	upls_locked = TRUE;	/* the UPLs will need to be unlocked */

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
		upl1->map_object = object2;
		upl2->map_object = object1;
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

/*
 * ENCRYPTED SWAP:
 *
 * Rationale:  the user might have some encrypted data on disk (via
 * FileVault or any other mechanism).  That data is then decrypted in
 * memory, which is safe as long as the machine is secure.  But that
 * decrypted data in memory could be paged out to disk by the default
 * pager.  The data would then be stored on disk in clear (not encrypted)
 * and it could be accessed by anyone who gets physical access to the
 * disk (if the laptop or the disk gets stolen for example).  This weakens
 * the security offered by FileVault.
 *
 * Solution:  the default pager will optionally request that all the
 * pages it gathers for pageout be encrypted, via the UPL interfaces,
 * before it sends this UPL to disk via the vnode_pageout() path.
 * 
 * Notes:
 * 
 * To avoid disrupting the VM LRU algorithms, we want to keep the
 * clean-in-place mechanisms, which allow us to send some extra pages to 
 * swap (clustering) without actually removing them from the user's
 * address space.  We don't want the user to unknowingly access encrypted
 * data, so we have to actually remove the encrypted pages from the page
 * table.  When the user accesses the data, the hardware will fail to
 * locate the virtual page in its page table and will trigger a page
 * fault.  We can then decrypt the page and enter it in the page table
 * again.  Whenever we allow the user to access the contents of a page,
 * we have to make sure it's not encrypted.
 *
 * 
 */
/*
 * ENCRYPTED SWAP:
 * Reserve of virtual addresses in the kernel address space.
 * We need to map the physical pages in the kernel, so that we
 * can call the encryption/decryption routines with a kernel
 * virtual address.  We keep this pool of pre-allocated kernel
 * virtual addresses so that we don't have to scan the kernel's
 * virtaul address space each time we need to encrypt or decrypt
 * a physical page.
 * It would be nice to be able to encrypt and decrypt in physical
 * mode but that might not always be more efficient...
 */
decl_simple_lock_data(,vm_paging_lock)
#define VM_PAGING_NUM_PAGES	64
vm_map_offset_t vm_paging_base_address = 0;
boolean_t	vm_paging_page_inuse[VM_PAGING_NUM_PAGES] = { FALSE, };
int		vm_paging_max_index = 0;
unsigned long	vm_paging_no_kernel_page = 0;
unsigned long	vm_paging_objects_mapped = 0;
unsigned long	vm_paging_pages_mapped = 0;
unsigned long	vm_paging_objects_mapped_slow = 0;
unsigned long	vm_paging_pages_mapped_slow = 0;

/*
 * ENCRYPTED SWAP:
 * vm_paging_map_object:
 *	Maps part of a VM object's pages in the kernel
 * 	virtual address space, using the pre-allocated
 *	kernel virtual addresses, if possible.
 * Context:
 * 	The VM object is locked.  This lock will get
 * 	dropped and re-acquired though.
 */
kern_return_t
vm_paging_map_object(
	vm_map_offset_t		*address,
	vm_page_t		page,
	vm_object_t		object,
	vm_object_offset_t	offset,
	vm_map_size_t		*size)
{
	kern_return_t		kr;
	vm_map_offset_t		page_map_offset;
	vm_map_size_t		map_size;
	vm_object_offset_t	object_offset;
#ifdef __ppc__
	int			i;
	vm_map_entry_t		map_entry;
#endif /* __ppc__ */


#ifdef __ppc__
	if (page != VM_PAGE_NULL && *size == PAGE_SIZE) {
		/*
		 * Optimization for the PowerPC.
		 * Use one of the pre-allocated kernel virtual addresses
		 * and just enter the VM page in the kernel address space
		 * at that virtual address.
		 */
		vm_object_unlock(object);
		simple_lock(&vm_paging_lock);

		if (vm_paging_base_address == 0) {
			/*
			 * Initialize our pool of pre-allocated kernel
			 * virtual addresses.
			 */
			simple_unlock(&vm_paging_lock);
			page_map_offset = 0;
			kr = vm_map_find_space(kernel_map,
					       &page_map_offset,
					       VM_PAGING_NUM_PAGES * PAGE_SIZE,
					       0,
					       &map_entry);
			if (kr != KERN_SUCCESS) {
				panic("vm_paging_map_object: "
				      "kernel_map full\n");
			}
			map_entry->object.vm_object = kernel_object;
			map_entry->offset =
				page_map_offset - VM_MIN_KERNEL_ADDRESS;
			vm_object_reference(kernel_object);
			vm_map_unlock(kernel_map);

			simple_lock(&vm_paging_lock);
			if (vm_paging_base_address != 0) {
				/* someone raced us and won: undo */
				simple_unlock(&vm_paging_lock);
				kr = vm_map_remove(kernel_map,
						   page_map_offset,
						   page_map_offset + 
						   (VM_PAGING_NUM_PAGES
						    * PAGE_SIZE),
						   VM_MAP_NO_FLAGS);
				assert(kr == KERN_SUCCESS);
				simple_lock(&vm_paging_lock);
			} else {
				vm_paging_base_address = page_map_offset;
			}
		}

		/*
		 * Try and find an available kernel virtual address
		 * from our pre-allocated pool.
		 */
		page_map_offset = 0;
		for (i = 0; i < VM_PAGING_NUM_PAGES; i++) {
			if (vm_paging_page_inuse[i] == FALSE) {
				page_map_offset = vm_paging_base_address +
					(i * PAGE_SIZE);
				break;
			}
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
			pmap_map_block(kernel_pmap,
				       page_map_offset,
				       page->phys_page,
				       PAGE_SIZE,
				       VM_PROT_DEFAULT,
				       ((int) page->object->wimg_bits &
					VM_WIMG_MASK),
				       0);
			vm_paging_objects_mapped++;
			vm_paging_pages_mapped++; 
			*address = page_map_offset;
			vm_object_lock(object);

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
		vm_object_lock(object);
	}
#endif /* __ppc__ */

	object_offset = vm_object_trunc_page(offset);
	map_size = vm_map_round_page(*size);

	/*
	 * Try and map the required range of the object
	 * in the kernel_map
	 */

	/* don't go beyond the object's end... */
	if (object_offset >= object->size) {
		map_size = 0;
	} else if (map_size > object->size - offset) {
		map_size = object->size - offset;
	}

	vm_object_reference_locked(object);	/* for the map entry */
	vm_object_unlock(object);

	kr = vm_map_enter(kernel_map,
			  address,
			  map_size,
			  0,
			  VM_FLAGS_ANYWHERE,
			  object,
			  object_offset,
			  FALSE,
			  VM_PROT_DEFAULT,
			  VM_PROT_ALL,
			  VM_INHERIT_NONE);
	if (kr != KERN_SUCCESS) {
		*address = 0;
		*size = 0;
		vm_object_deallocate(object);	/* for the map entry */
		return kr;
	}

	*size = map_size;

	/*
	 * Enter the mapped pages in the page table now.
	 */
	vm_object_lock(object);
	for (page_map_offset = 0;
	     map_size != 0;
	     map_size -= PAGE_SIZE_64, page_map_offset += PAGE_SIZE_64) {
		unsigned int	cache_attr;

		page = vm_page_lookup(object, offset + page_map_offset);
		if (page == VM_PAGE_NULL) {
			panic("vm_paging_map_object: no page !?");
		}
		if (page->no_isync == TRUE) {
			pmap_sync_page_data_phys(page->phys_page);
		}
		cache_attr = ((unsigned int) object->wimg_bits) & VM_WIMG_MASK;

		PMAP_ENTER(kernel_pmap,
			   *address + page_map_offset,
			   page,
			   VM_PROT_DEFAULT,
			   cache_attr,
			   FALSE);
	}
			   
	vm_paging_objects_mapped_slow++;
	vm_paging_pages_mapped_slow += map_size / PAGE_SIZE_64;

	return KERN_SUCCESS;
}

/*
 * ENCRYPTED SWAP:
 * vm_paging_unmap_object:
 *	Unmaps part of a VM object's pages from the kernel
 * 	virtual address space.
 * Context:
 * 	The VM object is locked.  This lock will get
 * 	dropped and re-acquired though.
 */
void
vm_paging_unmap_object(
	vm_object_t	object,
	vm_map_offset_t	start,
	vm_map_offset_t	end)
{
	kern_return_t	kr;
#ifdef __ppc__
	int		i;
#endif /* __ppc__ */

	if ((vm_paging_base_address != 0) &&
	    ((start < vm_paging_base_address) ||
	     (end > (vm_paging_base_address
		     + (VM_PAGING_NUM_PAGES * PAGE_SIZE))))) {
		/*
		 * We didn't use our pre-allocated pool of
		 * kernel virtual address.  Deallocate the
		 * virtual memory.
		 */
		if (object != VM_OBJECT_NULL) {
			vm_object_unlock(object);
		}
		kr = vm_map_remove(kernel_map, start, end, VM_MAP_NO_FLAGS);
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
#ifdef __ppc__
		assert(end - start == PAGE_SIZE);
		i = (start - vm_paging_base_address) >> PAGE_SHIFT;

		/* undo the pmap mapping */
		mapping_remove(kernel_pmap, start);

		simple_lock(&vm_paging_lock);
		vm_paging_page_inuse[i] = FALSE;
		simple_unlock(&vm_paging_lock);
#endif /* __ppc__ */
	}
}

/*
 * Encryption data.
 * "iv" is the "initial vector".  Ideally, we want to
 * have a different one for each page we encrypt, so that
 * crackers can't find encryption patterns too easily.
 */
#define SWAP_CRYPT_AES_KEY_SIZE	128	/* XXX 192 and 256 don't work ! */
boolean_t		swap_crypt_ctx_initialized = FALSE;
aes_32t 		swap_crypt_key[8]; /* big enough for a 256 key */
aes_ctx			swap_crypt_ctx;
const unsigned char	swap_crypt_null_iv[AES_BLOCK_SIZE] = {0xa, };

#if DEBUG
boolean_t		swap_crypt_ctx_tested = FALSE;
unsigned char swap_crypt_test_page_ref[4096] __attribute__((aligned(4096)));
unsigned char swap_crypt_test_page_encrypt[4096] __attribute__((aligned(4096)));
unsigned char swap_crypt_test_page_decrypt[4096] __attribute__((aligned(4096)));
#endif /* DEBUG */

extern u_long random(void);

/*
 * Initialize the encryption context: key and key size.
 */
void swap_crypt_ctx_initialize(void); /* forward */
void
swap_crypt_ctx_initialize(void)
{
	unsigned int	i;

	/*
	 * No need for locking to protect swap_crypt_ctx_initialized
	 * because the first use of encryption will come from the
	 * pageout thread (we won't pagein before there's been a pageout)
	 * and there's only one pageout thread.
	 */
	if (swap_crypt_ctx_initialized == FALSE) {
		for (i = 0;
		     i < (sizeof (swap_crypt_key) /
			  sizeof (swap_crypt_key[0]));
		     i++) {
			swap_crypt_key[i] = random();
		}
		aes_encrypt_key((const unsigned char *) swap_crypt_key,
				SWAP_CRYPT_AES_KEY_SIZE,
				&swap_crypt_ctx.encrypt);
		aes_decrypt_key((const unsigned char *) swap_crypt_key,
				SWAP_CRYPT_AES_KEY_SIZE,
				&swap_crypt_ctx.decrypt);
		swap_crypt_ctx_initialized = TRUE;
	}

#if DEBUG
	/*
	 * Validate the encryption algorithms.
	 */
	if (swap_crypt_ctx_tested == FALSE) {
		/* initialize */
		for (i = 0; i < 4096; i++) {
			swap_crypt_test_page_ref[i] = (char) i;
		}
		/* encrypt */
		aes_encrypt_cbc(swap_crypt_test_page_ref,
				swap_crypt_null_iv,
				PAGE_SIZE / AES_BLOCK_SIZE,
				swap_crypt_test_page_encrypt,
				&swap_crypt_ctx.encrypt);
		/* decrypt */
		aes_decrypt_cbc(swap_crypt_test_page_encrypt,
				swap_crypt_null_iv,
				PAGE_SIZE / AES_BLOCK_SIZE,
				swap_crypt_test_page_decrypt,
				&swap_crypt_ctx.decrypt);
		/* compare result with original */
		for (i = 0; i < 4096; i ++) {
			if (swap_crypt_test_page_decrypt[i] !=
			    swap_crypt_test_page_ref[i]) {
				panic("encryption test failed");
			}
		}

		/* encrypt again */
		aes_encrypt_cbc(swap_crypt_test_page_decrypt,
				swap_crypt_null_iv,
				PAGE_SIZE / AES_BLOCK_SIZE,
				swap_crypt_test_page_decrypt,
				&swap_crypt_ctx.encrypt);
		/* decrypt in place */
		aes_decrypt_cbc(swap_crypt_test_page_decrypt,
				swap_crypt_null_iv,
				PAGE_SIZE / AES_BLOCK_SIZE,
				swap_crypt_test_page_decrypt,
				&swap_crypt_ctx.decrypt);
		for (i = 0; i < 4096; i ++) {
			if (swap_crypt_test_page_decrypt[i] !=
			    swap_crypt_test_page_ref[i]) {
				panic("in place encryption test failed");
			}
		}

		swap_crypt_ctx_tested = TRUE;
	}
#endif /* DEBUG */
}

/*
 * ENCRYPTED SWAP:
 * vm_page_encrypt:
 * 	Encrypt the given page, for secure paging.
 * 	The page might already be mapped at kernel virtual
 * 	address "kernel_mapping_offset".  Otherwise, we need
 * 	to map it.
 * 
 * Context:
 * 	The page's object is locked, but this lock will be released
 * 	and re-acquired.
 * 	The page is busy and not accessible by users (not entered in any pmap).
 */
void
vm_page_encrypt(
	vm_page_t	page,
	vm_map_offset_t	kernel_mapping_offset)
{
        int			clear_refmod = 0;
	kern_return_t		kr;
	boolean_t		page_was_referenced;
	boolean_t		page_was_modified;
	vm_map_size_t		kernel_mapping_size;
	vm_offset_t		kernel_vaddr;
	union {
		unsigned char	aes_iv[AES_BLOCK_SIZE];
		struct {
			memory_object_t		pager_object;
			vm_object_offset_t	paging_offset;
		} vm;
	} encrypt_iv;

	if (! vm_pages_encrypted) {
		vm_pages_encrypted = TRUE;
	}

	assert(page->busy);
	assert(page->dirty || page->precious);
	
	if (page->encrypted) {
		/*
		 * Already encrypted: no need to do it again.
		 */
		vm_page_encrypt_already_encrypted_counter++;
		return;
	}
	ASSERT_PAGE_DECRYPTED(page);

	/*
	 * Gather the "reference" and "modified" status of the page.
	 * We'll restore these values after the encryption, so that
	 * the encryption is transparent to the rest of the system
	 * and doesn't impact the VM's LRU logic.
	 */
	page_was_referenced =
		(page->reference || pmap_is_referenced(page->phys_page));
	page_was_modified = 
		(page->dirty || pmap_is_modified(page->phys_page));

	if (kernel_mapping_offset == 0) {
		/*
		 * The page hasn't already been mapped in kernel space
		 * by the caller.  Map it now, so that we can access
		 * its contents and encrypt them.
		 */
		kernel_mapping_size = PAGE_SIZE;
		kr = vm_paging_map_object(&kernel_mapping_offset,
					  page,
					  page->object,
					  page->offset,
					  &kernel_mapping_size);
		if (kr != KERN_SUCCESS) {
			panic("vm_page_encrypt: "
			      "could not map page in kernel: 0x%x\n",
			      kr);
		}
	} else {
		kernel_mapping_size = 0;
	}
	kernel_vaddr = CAST_DOWN(vm_offset_t, kernel_mapping_offset);

	if (swap_crypt_ctx_initialized == FALSE) {
		swap_crypt_ctx_initialize();
	}
	assert(swap_crypt_ctx_initialized);

	/*
	 * Prepare an "initial vector" for the encryption.
	 * We use the "pager" and the "paging_offset" for that
	 * page to obfuscate the encrypted data a bit more and
	 * prevent crackers from finding patterns that they could
	 * use to break the key.
	 */
	bzero(&encrypt_iv.aes_iv[0], sizeof (encrypt_iv.aes_iv));
	encrypt_iv.vm.pager_object = page->object->pager;
	encrypt_iv.vm.paging_offset =
		page->object->paging_offset + page->offset;

	vm_object_unlock(page->object);

	/* encrypt the "initial vector" */
	aes_encrypt_cbc((const unsigned char *) &encrypt_iv.aes_iv[0],
			swap_crypt_null_iv,
			1,
			&encrypt_iv.aes_iv[0],
			&swap_crypt_ctx.encrypt);
		  
	/*
	 * Encrypt the page.
	 */
	aes_encrypt_cbc((const unsigned char *) kernel_vaddr,
			&encrypt_iv.aes_iv[0],
			PAGE_SIZE / AES_BLOCK_SIZE,
			(unsigned char *) kernel_vaddr,
			&swap_crypt_ctx.encrypt);

	vm_page_encrypt_counter++;

	vm_object_lock(page->object);

	/*
	 * Unmap the page from the kernel's address space,
	 * if we had to map it ourselves.  Otherwise, let
	 * the caller undo the mapping if needed.
	 */
	if (kernel_mapping_size != 0) {
		vm_paging_unmap_object(page->object,
				       kernel_mapping_offset,
				       kernel_mapping_offset + kernel_mapping_size);
	}

	/*
	 * Restore the "reference" and "modified" bits.
	 * This should clean up any impact the encryption had
	 * on them.
	 */
	if (! page_was_referenced) {
		clear_refmod |= VM_MEM_REFERENCED;
		page->reference = FALSE;
	}
	if (! page_was_modified) {
		clear_refmod |= VM_MEM_MODIFIED;
		page->dirty = FALSE;
	}
	if (clear_refmod)
	        pmap_clear_refmod(page->phys_page, clear_refmod);

	page->encrypted = TRUE;
}

/*
 * ENCRYPTED SWAP:
 * vm_page_decrypt:
 * 	Decrypt the given page.
 * 	The page might already be mapped at kernel virtual
 * 	address "kernel_mapping_offset".  Otherwise, we need
 * 	to map it.
 *
 * Context:
 *	The page's VM object is locked but will be unlocked and relocked.
 * 	The page is busy and not accessible by users (not entered in any pmap).
 */
void
vm_page_decrypt(
	vm_page_t	page,
	vm_map_offset_t	kernel_mapping_offset)
{
        int			clear_refmod = 0;
	kern_return_t		kr;
	vm_map_size_t		kernel_mapping_size;
	vm_offset_t		kernel_vaddr;
	boolean_t		page_was_referenced;
	union {
		unsigned char	aes_iv[AES_BLOCK_SIZE];
		struct {
			memory_object_t		pager_object;
			vm_object_offset_t	paging_offset;
		} vm;
	} decrypt_iv;

	assert(page->busy);
	assert(page->encrypted);

	/*
	 * Gather the "reference" status of the page.
	 * We'll restore its value after the decryption, so that
	 * the decryption is transparent to the rest of the system
	 * and doesn't impact the VM's LRU logic.
	 */
	page_was_referenced =
		(page->reference || pmap_is_referenced(page->phys_page));

	if (kernel_mapping_offset == 0) {
		/*
		 * The page hasn't already been mapped in kernel space
		 * by the caller.  Map it now, so that we can access
		 * its contents and decrypt them.
		 */
		kernel_mapping_size = PAGE_SIZE;
		kr = vm_paging_map_object(&kernel_mapping_offset,
					  page,
					  page->object,
					  page->offset,
					  &kernel_mapping_size);
		if (kr != KERN_SUCCESS) {
			panic("vm_page_decrypt: "
			      "could not map page in kernel: 0x%x\n");
		}
	} else {
		kernel_mapping_size = 0;
	}
	kernel_vaddr = CAST_DOWN(vm_offset_t, kernel_mapping_offset);

	assert(swap_crypt_ctx_initialized);

	/*
	 * Prepare an "initial vector" for the decryption.
	 * It has to be the same as the "initial vector" we
	 * used to encrypt that page.
	 */
	bzero(&decrypt_iv.aes_iv[0], sizeof (decrypt_iv.aes_iv));
	decrypt_iv.vm.pager_object = page->object->pager;
	decrypt_iv.vm.paging_offset =
		page->object->paging_offset + page->offset;

	vm_object_unlock(page->object);

	/* encrypt the "initial vector" */
	aes_encrypt_cbc((const unsigned char *) &decrypt_iv.aes_iv[0],
			swap_crypt_null_iv,
			1,
			&decrypt_iv.aes_iv[0],
			&swap_crypt_ctx.encrypt);

	/*
	 * Decrypt the page.
	 */
	aes_decrypt_cbc((const unsigned char *) kernel_vaddr,
			&decrypt_iv.aes_iv[0],
			PAGE_SIZE / AES_BLOCK_SIZE,
			(unsigned char *) kernel_vaddr,
			&swap_crypt_ctx.decrypt);
	vm_page_decrypt_counter++;

	vm_object_lock(page->object);

	/*
	 * Unmap the page from the kernel's address space,
	 * if we had to map it ourselves.  Otherwise, let
	 * the caller undo the mapping if needed.
	 */
	if (kernel_mapping_size != 0) {
		vm_paging_unmap_object(page->object,
				       kernel_vaddr,
				       kernel_vaddr + PAGE_SIZE);
	}

	/*
	 * After decryption, the page is actually clean.
	 * It was encrypted as part of paging, which "cleans"
	 * the "dirty" pages.
	 * Noone could access it after it was encrypted
	 * and the decryption doesn't count.
	 */
	page->dirty = FALSE;
	clear_refmod = VM_MEM_MODIFIED;

	/* restore the "reference" bit */
	if (! page_was_referenced) {
		page->reference = FALSE;
		clear_refmod |= VM_MEM_REFERENCED;
	}
	pmap_clear_refmod(page->phys_page, clear_refmod);

	page->encrypted = FALSE;

	/*
	 * We've just modified the page's contents via the data cache and part
	 * of the new contents might still be in the cache and not yet in RAM.
	 * Since the page is now available and might get gathered in a UPL to
	 * be part of a DMA transfer from a driver that expects the memory to
	 * be coherent at this point, we have to flush the data cache.
	 */
	pmap_sync_page_data_phys(page->phys_page);
	/*
	 * Since the page is not mapped yet, some code might assume that it
	 * doesn't need to invalidate the instruction cache when writing to
	 * that page.  That code relies on "no_isync" being set, so that the
	 * caches get syncrhonized when the page is first mapped.  So we need
	 * to set "no_isync" here too, despite the fact that we just
	 * synchronized the caches above...
	 */
	page->no_isync = TRUE;
}

unsigned long upl_encrypt_upls = 0;
unsigned long upl_encrypt_pages = 0;

/*
 * ENCRYPTED SWAP:
 *
 * upl_encrypt:
 * 	Encrypts all the pages in the UPL, within the specified range.
 *
 */
void
upl_encrypt(
	upl_t			upl,
	upl_offset_t		crypt_offset,
	upl_size_t		crypt_size)
{
	upl_size_t		upl_size;
	upl_offset_t		upl_offset;
	vm_object_t		upl_object;
	vm_page_t		page;
	vm_object_t		shadow_object;
	vm_object_offset_t	shadow_offset;
	vm_object_offset_t	paging_offset;
	vm_object_offset_t	base_offset;

	upl_encrypt_upls++;
	upl_encrypt_pages += crypt_size / PAGE_SIZE;

	upl_lock(upl);

	upl_object = upl->map_object;
	upl_offset = upl->offset;
	upl_size = upl->size;

	upl_unlock(upl);

	vm_object_lock(upl_object);

	/*
	 * Find the VM object that contains the actual pages.
	 */
	if (upl_object->pageout) {
		shadow_object = upl_object->shadow;
		/*
		 * The offset in the shadow object is actually also
		 * accounted for in upl->offset.  It possibly shouldn't be
		 * this way, but for now don't account for it twice.
		 */
		shadow_offset = 0;
		assert(upl_object->paging_offset == 0);	/* XXX ? */
		vm_object_lock(shadow_object);
	} else {
		shadow_object = upl_object;
		shadow_offset = 0;
	}

	paging_offset = shadow_object->paging_offset;
	vm_object_paging_begin(shadow_object);

	if (shadow_object != upl_object) {
		vm_object_unlock(shadow_object);
	}
	vm_object_unlock(upl_object);

	base_offset = shadow_offset;
	base_offset += upl_offset;
	base_offset += crypt_offset;
	base_offset -= paging_offset;
	/*
	 * Unmap the pages, so that nobody can continue accessing them while
	 * they're encrypted.  After that point, all accesses to these pages
	 * will cause a page fault and block while the page is being encrypted
	 * (busy).  After the encryption completes, any access will cause a
	 * page fault and the page gets decrypted at that time.
	 */
	assert(crypt_offset + crypt_size <= upl_size);
	vm_object_pmap_protect(shadow_object, 
			       base_offset,
			       (vm_object_size_t)crypt_size,
			       PMAP_NULL,
			       0,
			       VM_PROT_NONE);

	/* XXX FBDP could the object have changed significantly here ? */
	vm_object_lock(shadow_object);

	for (upl_offset = 0;
	     upl_offset < crypt_size;
	     upl_offset += PAGE_SIZE) {
		page = vm_page_lookup(shadow_object,
				      base_offset + upl_offset);
		if (page == VM_PAGE_NULL) {
			panic("upl_encrypt: "
			      "no page for (obj=%p,off=%lld+%d)!\n",
			      shadow_object,
			      base_offset,
			      upl_offset);
		}
		vm_page_encrypt(page, 0);
	}

	vm_object_paging_end(shadow_object);
	vm_object_unlock(shadow_object);
}

vm_size_t
upl_get_internal_pagelist_offset(void)
{
	return sizeof(struct upl);
}

void
upl_set_dirty(
	upl_t	upl)
{
	upl->flags |= UPL_CLEAR_DIRTY;
}

void
upl_clear_dirty(
	upl_t	upl)
{
	upl->flags &= ~UPL_CLEAR_DIRTY;
}


#ifdef MACH_BSD

boolean_t  upl_page_present(upl_page_info_t *upl, int index)
{
	return(UPL_PAGE_PRESENT(upl, index));
}
boolean_t  upl_dirty_page(upl_page_info_t *upl, int index)
{
	return(UPL_DIRTY_PAGE(upl, index));
}
boolean_t  upl_valid_page(upl_page_info_t *upl, int index)
{
	return(UPL_VALID_PAGE(upl, index));
}
ppnum_t  upl_phys_page(upl_page_info_t *upl, int index)
{
	return(UPL_PHYS_PAGE(upl, index));
}

void
vm_countdirtypages(void)
{
	vm_page_t m;
	int dpages;
	int pgopages;
	int precpages;


	dpages=0;
	pgopages=0;
	precpages=0;

	vm_page_lock_queues();
	m = (vm_page_t) queue_first(&vm_page_queue_inactive);
	do {
		if (m ==(vm_page_t )0) break;

		if(m->dirty) dpages++;
		if(m->pageout) pgopages++;
		if(m->precious) precpages++;

		assert(m->object != kernel_object);
		m = (vm_page_t) queue_next(&m->pageq);
		if (m ==(vm_page_t )0) break;

	} while (!queue_end(&vm_page_queue_inactive,(queue_entry_t) m));
	vm_page_unlock_queues();

	vm_page_lock_queues();
	m = (vm_page_t) queue_first(&vm_page_queue_zf);
	do {
		if (m ==(vm_page_t )0) break;

		if(m->dirty) dpages++;
		if(m->pageout) pgopages++;
		if(m->precious) precpages++;

		assert(m->object != kernel_object);
		m = (vm_page_t) queue_next(&m->pageq);
		if (m ==(vm_page_t )0) break;

	} while (!queue_end(&vm_page_queue_zf,(queue_entry_t) m));
	vm_page_unlock_queues();

	printf("IN Q: %d : %d : %d\n", dpages, pgopages, precpages);

	dpages=0;
	pgopages=0;
	precpages=0;

	vm_page_lock_queues();
	m = (vm_page_t) queue_first(&vm_page_queue_active);

	do {
		if(m == (vm_page_t )0) break;
		if(m->dirty) dpages++;
		if(m->pageout) pgopages++;
		if(m->precious) precpages++;

		assert(m->object != kernel_object);
		m = (vm_page_t) queue_next(&m->pageq);
		if(m == (vm_page_t )0) break;

	} while (!queue_end(&vm_page_queue_active,(queue_entry_t) m));
	vm_page_unlock_queues();

	printf("AC Q: %d : %d : %d\n", dpages, pgopages, precpages);

}
#endif /* MACH_BSD */

#ifdef UPL_DEBUG
kern_return_t  upl_ubc_alias_set(upl_t upl, unsigned int alias1, unsigned int alias2)
{
	upl->ubc_alias1 = alias1;
	upl->ubc_alias2 = alias2;
	return KERN_SUCCESS;
}
int  upl_ubc_alias_get(upl_t upl, unsigned int * al, unsigned int * al2)
{
	if(al)
		*al = upl->ubc_alias1;
	if(al2)
		*al2 = upl->ubc_alias2;
	return KERN_SUCCESS;
}
#endif /* UPL_DEBUG */



#if	MACH_KDB
#include <ddb/db_output.h>
#include <ddb/db_print.h>
#include <vm/vm_print.h>

#define	printf	kdbprintf
void		db_pageout(void);

void
db_vm(void)
{

	iprintf("VM Statistics:\n");
	db_indent += 2;
	iprintf("pages:\n");
	db_indent += 2;
	iprintf("activ %5d  inact %5d  free  %5d",
		vm_page_active_count, vm_page_inactive_count,
		vm_page_free_count);
	printf("   wire  %5d  gobbl %5d\n",
	       vm_page_wire_count, vm_page_gobble_count);
	db_indent -= 2;
	iprintf("target:\n");
	db_indent += 2;
	iprintf("min   %5d  inact %5d  free  %5d",
		vm_page_free_min, vm_page_inactive_target,
		vm_page_free_target);
	printf("   resrv %5d\n", vm_page_free_reserved);
	db_indent -= 2;
	iprintf("pause:\n");
	db_pageout();
	db_indent -= 2;
}

#if	MACH_COUNTERS
extern int c_laundry_pages_freed;
#endif	/* MACH_COUNTERS */

void
db_pageout(void)
{
	iprintf("Pageout Statistics:\n");
	db_indent += 2;
	iprintf("active %5d  inactv %5d\n",
		vm_pageout_active, vm_pageout_inactive);
	iprintf("nolock %5d  avoid  %5d  busy   %5d  absent %5d\n",
		vm_pageout_inactive_nolock, vm_pageout_inactive_avoid,
		vm_pageout_inactive_busy, vm_pageout_inactive_absent);
	iprintf("used   %5d  clean  %5d  dirty  %5d\n",
		vm_pageout_inactive_used, vm_pageout_inactive_clean,
		vm_pageout_inactive_dirty);
#if	MACH_COUNTERS
	iprintf("laundry_pages_freed %d\n", c_laundry_pages_freed);
#endif	/* MACH_COUNTERS */
#if	MACH_CLUSTER_STATS
	iprintf("Cluster Statistics:\n");
	db_indent += 2;
	iprintf("dirtied   %5d   cleaned  %5d   collisions  %5d\n",
		vm_pageout_cluster_dirtied, vm_pageout_cluster_cleaned,
		vm_pageout_cluster_collisions);
	iprintf("clusters  %5d   conversions  %5d\n",
		vm_pageout_cluster_clusters, vm_pageout_cluster_conversions);
	db_indent -= 2;
	iprintf("Target Statistics:\n");
	db_indent += 2;
	iprintf("collisions   %5d   page_dirtied  %5d   page_freed  %5d\n",
		vm_pageout_target_collisions, vm_pageout_target_page_dirtied,
		vm_pageout_target_page_freed);
	db_indent -= 2;
#endif	/* MACH_CLUSTER_STATS */
	db_indent -= 2;
}

#endif	/* MACH_KDB */
