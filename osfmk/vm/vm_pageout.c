/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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

#include <mach_pagemap.h>
#include <mach_cluster_stats.h>
#include <mach_kdb.h>
#include <advisory_pageout.h>

#include <mach/mach_types.h>
#include <mach/memory_object.h>
#include <mach/memory_object_default.h>
#include <mach/memory_object_control_server.h>
#include <mach/mach_host_server.h>
#include <mach/vm_param.h>
#include <mach/vm_statistics.h>
#include <kern/host_statistics.h>
#include <kern/counters.h>
#include <kern/thread.h>
#include <kern/xpr.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <machine/vm_tuning.h>
#include <kern/misc_protos.h>

extern ipc_port_t	memory_manager_default;

#ifndef	VM_PAGE_LAUNDRY_MAX
#define	VM_PAGE_LAUNDRY_MAX	6	/* outstanding DMM page cleans */
#endif	/* VM_PAGEOUT_LAUNDRY_MAX */

#ifndef	VM_PAGEOUT_BURST_MAX
#define	VM_PAGEOUT_BURST_MAX	32	/* simultaneous EMM page cleans */
#endif	/* VM_PAGEOUT_BURST_MAX */

#ifndef	VM_PAGEOUT_DISCARD_MAX
#define	VM_PAGEOUT_DISCARD_MAX	68	/* simultaneous EMM page cleans */
#endif	/* VM_PAGEOUT_DISCARD_MAX */

#ifndef	VM_PAGEOUT_BURST_WAIT
#define	VM_PAGEOUT_BURST_WAIT	30	/* milliseconds per page */
#endif	/* VM_PAGEOUT_BURST_WAIT */

#ifndef	VM_PAGEOUT_EMPTY_WAIT
#define VM_PAGEOUT_EMPTY_WAIT	200	/* milliseconds */
#endif	/* VM_PAGEOUT_EMPTY_WAIT */

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
#define	VM_PAGE_FREE_RESERVED	\
	((16 * VM_PAGE_LAUNDRY_MAX) + NCPUS)
#endif	/* VM_PAGE_FREE_RESERVED */

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
extern void vm_pageout_continue(void);
extern void vm_pageout_scan(void);
extern void vm_pageout_throttle(vm_page_t m);
extern vm_page_t vm_pageout_cluster_page(
			vm_object_t		object,
			vm_object_offset_t	offset,
			boolean_t		precious_clean);

unsigned int vm_pageout_reserved_internal = 0;
unsigned int vm_pageout_reserved_really = 0;

unsigned int vm_page_laundry_max = 0;		/* # of clusters outstanding */
unsigned int vm_page_laundry_min = 0;
unsigned int vm_pageout_burst_max = 0;
unsigned int vm_pageout_burst_wait = 0;		/* milliseconds per page */
unsigned int vm_pageout_empty_wait = 0;		/* milliseconds */
unsigned int vm_pageout_burst_min = 0;
unsigned int vm_pageout_pause_count = 0;
unsigned int vm_pageout_pause_max = 0;
unsigned int vm_free_page_pause = 100; 		/* milliseconds */

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
unsigned int vm_stat_discard = 0;		/* debugging */
unsigned int vm_stat_discard_sent = 0;		/* debugging */
unsigned int vm_stat_discard_failure = 0;	/* debugging */
unsigned int vm_stat_discard_throttle = 0;	/* debugging */
unsigned int vm_pageout_scan_active_emm_throttle = 0;		/* debugging */
unsigned int vm_pageout_scan_active_emm_throttle_success = 0;	/* debugging */
unsigned int vm_pageout_scan_active_emm_throttle_failure = 0;	/* debugging */
unsigned int vm_pageout_scan_inactive_emm_throttle = 0;		/* debugging */
unsigned int vm_pageout_scan_inactive_emm_throttle_success = 0;	/* debugging */
unsigned int vm_pageout_scan_inactive_emm_throttle_failure = 0;	/* debugging */


unsigned int vm_pageout_out_of_line  = 0;
unsigned int vm_pageout_in_place  = 0;
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

	if (object->pager_trusted || object->internal)
		vm_pageout_throttle(m);

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

	/*
	 * Deal with the deallocation (last reference) of a pageout object
	 * (used for cleaning-in-place) by dropping the paging references/
	 * freeing pages in the original object.
	 */

	assert(object->pageout);
	shadow_object = object->shadow;
	vm_object_lock(shadow_object);

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
		 */
		vm_page_lock_queues();
		if (m->laundry) {
		    vm_page_laundry_count--;
		    m->laundry = FALSE;
		    if (vm_page_laundry_count < vm_page_laundry_min) {
			vm_page_laundry_min = 0;
			thread_wakeup((event_t) &vm_page_laundry_count);
		    }
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
			 * from being dirtied after the pmap_is_modified() call
			 * returns.
			 */
			pmap_page_protect(m->phys_addr, VM_PROT_NONE);

			/*
			 * Since the page is left "dirty" but "not modifed", we
			 * can detect whether the page was redirtied during
			 * pageout by checking the modify state.
			 */
			m->dirty = pmap_is_modified(m->phys_addr);

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
			/* could have occured. COPY_INTO is a read into the */
			/* new pages. CLEAN_IN_PLACE does actually write   */
			/* out the pages but handling outside of this code */
			/* will take care of resetting dirty. We clear the */
			/* modify however for the Programmed I/O case.     */ 
			pmap_clear_modify(m->phys_addr);
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
			m->dirty = pmap_is_modified(m->phys_addr);

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
	register vm_page_t	new_page;
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
		new_m->phys_addr = m->phys_addr;
		new_m->fictitious = FALSE;
		new_m->pageout = TRUE;

		/*
		 * Mark real page as cleaning (indicating that we hold a
		 * paging reference to be released via m_o_d_r_c) and
		 * pageout (indicating that the page should be freed
		 * when the pageout completes).
		 */
		pmap_clear_modify(m->phys_addr);
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

	pmap_clear_modify(m->phys_addr);
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
	new_m->phys_addr = m->phys_addr;
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

	pmap_clear_modify(m->phys_addr);

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
	vm_map_copy_t		copy;
	vm_object_t		new_object;
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
	vm_object_unlock(object);
	if (m->absent || m->error || m->restart ||
	    (!m->dirty && !m->precious)) {
		VM_PAGE_FREE(m);
		panic("reservation without pageout?"); /* alan */
		return;
	}

	/* set the page for future call to vm_fault_list_request */
	holding_page = NULL;
	vm_object_lock(m->object);
	vm_page_lock_queues();
	pmap_clear_modify(m->phys_addr);
	m->dirty = TRUE;
       	m->busy = TRUE;
       	m->list_req_pending = TRUE;
       	m->cleaning = TRUE;
	m->pageout = TRUE;
	vm_page_wire(m);
	vm_page_unlock_queues();
	vm_object_unlock(m->object);
	vm_pageout_throttle(m);

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
 * Given a page, page it out, and attempt to clean adjacent pages
 * in the same operation.
 *
 * The page must be busy, and the object unlocked w/ paging reference
 * to prevent deallocation or collapse. The page must not be on any
 * pageout queue.
 */
void
vm_pageout_cluster(
	vm_page_t m)
{
	vm_object_t	object = m->object;
	vm_object_offset_t offset = m->offset;	/* from vm_object start */
	vm_object_offset_t paging_offset = m->offset + object->paging_offset;
	vm_object_t	new_object;
	vm_object_offset_t new_offset;
	vm_size_t	cluster_size;
	vm_object_offset_t cluster_offset;	/* from memory_object start */
	vm_object_offset_t cluster_lower_bound;	/* from vm_object_start */
	vm_object_offset_t cluster_upper_bound;	/* from vm_object_start */
	vm_object_offset_t cluster_start, cluster_end;/* from vm_object start */
	vm_object_offset_t offset_within_cluster;
	vm_size_t	length_of_data;
	vm_page_t	friend, holding_page;
	kern_return_t	rc;
	boolean_t	precious_clean = TRUE;
	int		pages_in_cluster;

	CLUSTER_STAT(int pages_at_higher_offsets = 0;)
	CLUSTER_STAT(int pages_at_lower_offsets = 0;)

	XPR(XPR_VM_PAGEOUT,
		"vm_pageout_cluster, object 0x%X offset 0x%X page 0x%X\n",
		(integer_t)object, offset, (integer_t)m, 0, 0);

	CLUSTER_STAT(vm_pageout_cluster_clusters++;)
	/*
	 * Only a certain kind of page is appreciated here.
	 */
	assert(m->busy && (m->dirty || m->precious) && (m->wire_count == 0));
	assert(!m->cleaning && !m->pageout && !m->inactive && !m->active);

	vm_object_lock(object);
	cluster_size = object->cluster_size;

	assert(cluster_size >= PAGE_SIZE);
	if (cluster_size < PAGE_SIZE) cluster_size = PAGE_SIZE;
	assert(object->pager_created && object->pager_initialized);
	assert(object->internal || object->pager_ready);

	if (m->precious && !m->dirty)
		precious_clean = TRUE;

	if (!object->pager_trusted || !allow_clustered_pageouts)
		cluster_size = PAGE_SIZE;
	vm_object_unlock(object);

	cluster_offset = paging_offset & (vm_object_offset_t)(cluster_size - 1);
			/* bytes from beginning of cluster */
	/* 
	 * Due to unaligned mappings, we have to be careful
	 * of negative offsets into the VM object. Clip the cluster 
	 * boundary to the VM object, not the memory object.
	 */
	if (offset > cluster_offset) {
		cluster_lower_bound = offset - cluster_offset;
						/* from vm_object */
	} else {
		cluster_lower_bound = 0;
	}
	cluster_upper_bound = (offset - cluster_offset) + 
				(vm_object_offset_t)cluster_size;

	/* set the page for future call to vm_fault_list_request */
	holding_page = NULL;
	vm_object_lock(m->object);
	vm_page_lock_queues();
       	m->busy = TRUE;
       	m->list_req_pending = TRUE;
       	m->cleaning = TRUE;
	m->pageout = TRUE;
	vm_page_wire(m);
	vm_page_unlock_queues();
	vm_object_unlock(m->object);
	vm_pageout_throttle(m);

	/*
	 * Search backward for adjacent eligible pages to clean in 
	 * this operation.
	 */

	cluster_start = offset;
	if (offset) {	/* avoid wrap-around at zero */
	    for (cluster_start = offset - PAGE_SIZE_64;
		cluster_start >= cluster_lower_bound;
		cluster_start -= PAGE_SIZE_64) {
		assert(cluster_size > PAGE_SIZE);

		vm_object_lock(object);
		vm_page_lock_queues();

		if ((friend = vm_pageout_cluster_page(object, cluster_start,
				precious_clean)) == VM_PAGE_NULL) {
			vm_page_unlock_queues();
			vm_object_unlock(object);
			break;
		}
		new_offset = (cluster_start + object->paging_offset)
				& (cluster_size - 1);

		assert(new_offset < cluster_offset);
       		m->list_req_pending = TRUE;
       		m->cleaning = TRUE;
/* do nothing except advance the write request, all we really need to */
/* do is push the target page and let the code at the other end decide */
/* what is really the right size */
		if (vm_page_free_count <= vm_page_free_reserved) {
       			m->busy = TRUE;
			m->pageout = TRUE;
			vm_page_wire(m);
		}

		vm_page_unlock_queues();
		vm_object_unlock(object);
		if(m->dirty || m->object->internal) {
			CLUSTER_STAT(pages_at_lower_offsets++;)
		}

	    }
	    cluster_start += PAGE_SIZE_64;
	}
	assert(cluster_start >= cluster_lower_bound);
	assert(cluster_start <= offset);
	/*
	 * Search forward for adjacent eligible pages to clean in 
	 * this operation.
	 */
	for (cluster_end = offset + PAGE_SIZE_64;
		cluster_end < cluster_upper_bound;
		cluster_end += PAGE_SIZE_64) {
		assert(cluster_size > PAGE_SIZE);

		vm_object_lock(object);
		vm_page_lock_queues();

		if ((friend = vm_pageout_cluster_page(object, cluster_end,
				precious_clean)) == VM_PAGE_NULL) {
			vm_page_unlock_queues();
			vm_object_unlock(object);
			break;
		}
		new_offset = (cluster_end + object->paging_offset)
				& (cluster_size - 1);

		assert(new_offset < cluster_size);
       		m->list_req_pending = TRUE;
       		m->cleaning = TRUE;
/* do nothing except advance the write request, all we really need to */
/* do is push the target page and let the code at the other end decide */
/* what is really the right size */
		if (vm_page_free_count <= vm_page_free_reserved) {
       			m->busy = TRUE;
			m->pageout = TRUE;
			vm_page_wire(m);
		}

		vm_page_unlock_queues();
		vm_object_unlock(object);
		
		if(m->dirty || m->object->internal) {
			CLUSTER_STAT(pages_at_higher_offsets++;)
		}
	}
	assert(cluster_end <= cluster_upper_bound);
	assert(cluster_end >= offset + PAGE_SIZE);

	/*
	 * (offset - cluster_offset) is beginning of cluster_object
	 * relative to vm_object start.
	 */
	offset_within_cluster = cluster_start - (offset - cluster_offset);
	length_of_data = cluster_end - cluster_start;

	assert(offset_within_cluster < cluster_size);
	assert((offset_within_cluster + length_of_data) <= cluster_size);

	rc = KERN_SUCCESS;
	assert(rc == KERN_SUCCESS);

	pages_in_cluster = length_of_data/PAGE_SIZE;

#if	MACH_CLUSTER_STATS
	(cluster_stats[pages_at_lower_offsets].pages_at_lower_offsets)++;
	(cluster_stats[pages_at_higher_offsets].pages_at_higher_offsets)++;
	(cluster_stats[pages_in_cluster].pages_in_cluster)++;
#endif	/* MACH_CLUSTER_STATS */

	/*
	 * Send the data to the pager.
	 */
	paging_offset = cluster_start + object->paging_offset;

	rc = memory_object_data_return(object->pager,
				       paging_offset,
				       length_of_data,
				       !precious_clean,
				       FALSE);

	vm_object_lock(object);
	vm_object_paging_end(object);

	if (holding_page) {
		assert(!object->pager_trusted);
		VM_PAGE_FREE(holding_page);
		vm_object_paging_end(object);
	}

	vm_object_unlock(object);
}

/*
 *	Trusted pager throttle.
 *	Object must be unlocked, page queues must be unlocked.
 */
void
vm_pageout_throttle(
	register vm_page_t m)
{
	vm_page_lock_queues();
	assert(!m->laundry);
	m->laundry = TRUE;
	while (vm_page_laundry_count >= vm_page_laundry_max) {
		/*
		 * Set the threshold for when vm_page_free()
		 * should wake us up.
		 */
		vm_page_laundry_min = vm_page_laundry_max/2;

		assert_wait((event_t) &vm_page_laundry_count, THREAD_UNINT);
		vm_page_unlock_queues();

		/*
		 * Pause to let the default pager catch up.
		 */
		thread_block((void (*)(void)) 0);
		vm_page_lock_queues();
	}
	vm_page_laundry_count++;
	vm_page_unlock_queues();
}

/*
 * The global variable vm_pageout_clean_active_pages controls whether
 * active pages are considered valid to be cleaned in place during a
 * clustered pageout. Performance measurements are necessary to determine
 * the best policy.
 */
int vm_pageout_clean_active_pages = 1;
/*
 * vm_pageout_cluster_page: [Internal]
 *
 * return a vm_page_t to the page at (object,offset) if it is appropriate
 * to clean in place. Pages that are non-existent, busy, absent, already
 * cleaning, or not dirty are not eligible to be cleaned as an adjacent
 * page in a cluster.
 *
 * The object must be locked on entry, and remains locked throughout
 * this call.
 */

vm_page_t
vm_pageout_cluster_page(
	vm_object_t 		object,
	vm_object_offset_t 	offset,
	boolean_t 		precious_clean)
{
	vm_page_t m;

	XPR(XPR_VM_PAGEOUT,
		"vm_pageout_cluster_page, object 0x%X offset 0x%X\n",
		(integer_t)object, offset, 0, 0, 0);

	if ((m = vm_page_lookup(object, offset)) == VM_PAGE_NULL)
		return(VM_PAGE_NULL);

	if (m->busy || m->absent || m->cleaning || 
	    (m->wire_count != 0) || m->error)
		return(VM_PAGE_NULL);

	if (vm_pageout_clean_active_pages) {
		if (!m->active && !m->inactive) return(VM_PAGE_NULL);
	} else {
		if (!m->inactive) return(VM_PAGE_NULL);
	}

	assert(!m->private);
	assert(!m->fictitious);

	if (!m->dirty) m->dirty = pmap_is_modified(m->phys_addr);

	if (precious_clean) {
		if (!m->precious || !m->dirty)
			return(VM_PAGE_NULL);
	} else {
		if (!m->dirty)
			return(VM_PAGE_NULL);
	}
	return(m);
}

/*
 *	vm_pageout_scan does the dirty work for the pageout daemon.
 *	It returns with vm_page_queue_free_lock held and
 *	vm_page_free_wanted == 0.
 */
extern void vm_pageout_scan_continue(void);	/* forward; */

void
vm_pageout_scan(void)
{
	unsigned int burst_count;
	boolean_t now = FALSE;
	unsigned int laundry_pages;
	boolean_t need_more_inactive_pages;
	unsigned int	loop_detect;

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
	 *	we could exhaust the free list.  However, we can't just ignore
	 *	pages belonging to external objects, because there might be no
	 *	pages belonging to internal objects.  Hence, we get the page
	 *	into an internal object and then immediately double-page it,
	 *	sending it to the default pager.
	 *
	 *	consider_zone_gc should be last, because the other operations
	 *	might return memory to zones.
	 */


    Restart:

#if	THREAD_SWAPPER
	mutex_lock(&vm_page_queue_free_lock);
	now = (vm_page_free_count < vm_page_free_min);
	mutex_unlock(&vm_page_queue_free_lock);

	swapout_threads(now);
#endif	/* THREAD_SWAPPER */

	stack_collect();
	consider_task_collect();
	consider_thread_collect();
	consider_zone_gc();
	consider_machine_collect();

	loop_detect = vm_page_active_count + vm_page_inactive_count;
#if 0
	if (vm_page_free_count <= vm_page_free_reserved) {
		need_more_inactive_pages = TRUE;
	} else {
		need_more_inactive_pages = FALSE;
	}
#else
	need_more_inactive_pages = FALSE;
#endif

	for (burst_count = 0;;) {
		register vm_page_t m;
		register vm_object_t object;

		/*
		 *	Recalculate vm_page_inactivate_target.
		 */

		vm_page_lock_queues();
		vm_page_inactive_target =
			VM_PAGE_INACTIVE_TARGET(vm_page_active_count +
						vm_page_inactive_count);

		/*
		 *	Move pages from active to inactive.
		 */

		while ((vm_page_inactive_count < vm_page_inactive_target ||
			need_more_inactive_pages) &&
		       !queue_empty(&vm_page_queue_active)) {
			register vm_object_t object;

			vm_pageout_active++;
			m = (vm_page_t) queue_first(&vm_page_queue_active);

			/*
			 * If we're getting really low on memory,
			 * try selecting a page that will go 
			 * directly to the default_pager.
			 * If there are no such pages, we have to
			 * page out a page backed by an EMM,
			 * so that the default_pager can recover
			 * it eventually.
			 */
			if (need_more_inactive_pages && 
				(IP_VALID(memory_manager_default))) {
				vm_pageout_scan_active_emm_throttle++;
				do {
					assert(m->active && !m->inactive);
					object = m->object;

					if (vm_object_lock_try(object)) {
#if 0
						if (object->pager_trusted ||
						    object->internal) {
							/* found one ! */
							vm_pageout_scan_active_emm_throttle_success++;
							goto object_locked_active;
						}
#else
					vm_pageout_scan_active_emm_throttle_success++;
							goto object_locked_active;
#endif
						vm_object_unlock(object);
					}
					m = (vm_page_t) queue_next(&m->pageq);
				} while (!queue_end(&vm_page_queue_active,
						    (queue_entry_t) m));
				if (queue_end(&vm_page_queue_active,
					      (queue_entry_t) m)) {
					vm_pageout_scan_active_emm_throttle_failure++;
					m = (vm_page_t)
						queue_first(&vm_page_queue_active);
				}
			}

			assert(m->active && !m->inactive);

			object = m->object;
			if (!vm_object_lock_try(object)) {
				/*
				 *	Move page to end and continue.
				 */

				queue_remove(&vm_page_queue_active, m,
					     vm_page_t, pageq);
				queue_enter(&vm_page_queue_active, m,
					    vm_page_t, pageq);
				vm_page_unlock_queues();

				mutex_pause();
				vm_page_lock_queues();
				continue;
			}

		    object_locked_active:
			/*
			 *	If the page is busy, then we pull it
			 *	off the active queue and leave it alone.
			 */

			if (m->busy) {
				vm_object_unlock(object);
				queue_remove(&vm_page_queue_active, m,
					     vm_page_t, pageq);
				m->active = FALSE;
				if (!m->fictitious)
					vm_page_active_count--;
				continue;
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
			vm_object_unlock(object);
		}

		/*
		 *	We are done if we have met our target *and*
		 *	nobody is still waiting for a page.
		 */
		if (vm_page_free_count >= vm_page_free_target) {
		        mutex_lock(&vm_page_queue_free_lock);
			if ((vm_page_free_count >= vm_page_free_target) &&
			          (vm_page_free_wanted == 0)) {
			        vm_page_unlock_queues();
				break;
			}
			mutex_unlock(&vm_page_queue_free_lock);
		}
		/*
		 * Sometimes we have to pause:
		 *	1) No inactive pages - nothing to do.
		 *	2) Flow control - wait for untrusted pagers to catch up.
		 */

		if (queue_empty(&vm_page_queue_inactive) ||
		    ((--loop_detect) == 0)	||
		    (burst_count >= vm_pageout_burst_max)) {
			unsigned int pages, msecs;
			int wait_result;

			consider_machine_adjust();
			/*
			 *	vm_pageout_burst_wait is msecs/page.
			 *	If there is nothing for us to do, we wait
			 *	at least vm_pageout_empty_wait msecs.
			 */
			pages = burst_count;
	
			if (loop_detect == 0) {
				printf("Warning: No physical memory suitable for pageout or reclaim, pageout thread temporarily going to sleep\n");
				msecs = vm_free_page_pause;
			}
			else {
				msecs = burst_count * vm_pageout_burst_wait;
			}

			if (queue_empty(&vm_page_queue_inactive) &&
			    (msecs < vm_pageout_empty_wait))
				msecs = vm_pageout_empty_wait;
			vm_page_unlock_queues();

			assert_wait_timeout(msecs, THREAD_INTERRUPTIBLE);
			counter(c_vm_pageout_scan_block++);

			/*
			 *	Unfortunately, we don't have call_continuation
			 *	so we can't rely on tail-recursion.
			 */
			wait_result = thread_block((void (*)(void)) 0);
			if (wait_result != THREAD_TIMED_OUT)
				thread_cancel_timer();
			vm_pageout_scan_continue();

			goto Restart;
			/*NOTREACHED*/
		}

		vm_pageout_inactive++;
		m = (vm_page_t) queue_first(&vm_page_queue_inactive);

		if ((vm_page_free_count <= vm_page_free_reserved) && 
				(IP_VALID(memory_manager_default))) {
			/*
			 * We're really low on memory. Try to select a page that
			 * would go directly to the default_pager.
			 * If there are no such pages, we have to page out a 
			 * page backed by an EMM, so that the default_pager
			 * can recover it eventually.
			 */
			vm_pageout_scan_inactive_emm_throttle++;
			do {
				assert(!m->active && m->inactive);
				object = m->object;

				if (vm_object_lock_try(object)) {
#if 0
					if (object->pager_trusted ||
					    object->internal) {
						/* found one ! */
						vm_pageout_scan_inactive_emm_throttle_success++;
						goto object_locked_inactive;
					}
#else
				vm_pageout_scan_inactive_emm_throttle_success++;
						goto object_locked_inactive;
#endif /* 0 */
					vm_object_unlock(object);
				}
				m = (vm_page_t) queue_next(&m->pageq);
			} while (!queue_end(&vm_page_queue_inactive,
					    (queue_entry_t) m));
			if (queue_end(&vm_page_queue_inactive,
				      (queue_entry_t) m)) {
				vm_pageout_scan_inactive_emm_throttle_failure++;
				/*
				 * We should check the "active" queue
				 * for good candidates to page out.
				 */
				need_more_inactive_pages = TRUE;

				m = (vm_page_t)
					queue_first(&vm_page_queue_inactive);
			}
		}

		assert(!m->active && m->inactive);
		object = m->object;

		/*
		 *	Try to lock object; since we've got the
		 *	page queues lock, we can only try for this one.
		 */

		if (!vm_object_lock_try(object)) {
			/*
			 *	Move page to end and continue.
			 * 	Don't re-issue ticket
			 */
			queue_remove(&vm_page_queue_inactive, m,
				     vm_page_t, pageq);
			queue_enter(&vm_page_queue_inactive, m,
				    vm_page_t, pageq);
			vm_page_unlock_queues();

			mutex_pause();
			vm_pageout_inactive_nolock++;
			continue;
		}

	    object_locked_inactive:
		/*
		 *	Paging out pages of objects which pager is being
		 *	created by another thread must be avoided, because
		 *	this thread may claim for memory, thus leading to a
		 *	possible dead lock between it and the pageout thread
		 *	which will wait for pager creation, if such pages are
		 *	finally chosen. The remaining assumption is that there
		 *	will finally be enough available pages in the inactive
		 *	pool to page out in order to satisfy all memory claimed
		 *	by the thread which concurrently creates the pager.
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
			queue_remove(&vm_page_queue_inactive, m,
				     vm_page_t, pageq);
			queue_enter(&vm_page_queue_inactive, m,
				    vm_page_t, pageq);
			vm_page_unlock_queues();
			vm_object_unlock(object);
			vm_pageout_inactive_avoid++;
			continue;
		}

		/*
		 *	Remove the page from the inactive list.
		 */

		queue_remove(&vm_page_queue_inactive, m, vm_page_t, pageq);
		m->inactive = FALSE;
		if (!m->fictitious)
			vm_page_inactive_count--;

		if (m->busy || !object->alive) {
			/*
			 *	Somebody is already playing with this page.
			 *	Leave it off the pageout queues.
			 */

			vm_page_unlock_queues();
			vm_object_unlock(object);
			vm_pageout_inactive_busy++;
			continue;
		}

		/*
		 *	If it's absent or in error, we can reclaim the page.
		 */

		if (m->absent || m->error) {
			vm_pageout_inactive_absent++;
		    reclaim_page:
			vm_page_free(m);
			vm_page_unlock_queues();
			vm_object_unlock(object);
			continue;
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
#if	MACH_CLUSTER_STATS
			vm_pageout_cluster_conversions++;
#endif
			m->busy = TRUE;
			m->pageout = TRUE;
			m->dump_cleaning = TRUE;
			vm_page_wire(m);
			vm_object_unlock(object);
			vm_page_unlock_queues();
			continue;
		}

		/*
		 *	If it's being used, reactivate.
		 *	(Fictitious pages are either busy or absent.)
		 */

		if (m->reference || pmap_is_referenced(m->phys_addr)) {
			vm_pageout_inactive_used++;
		    reactivate_page:
#if	ADVISORY_PAGEOUT
			if (m->discard_request) {
				m->discard_request = FALSE;
			}
#endif	/* ADVISORY_PAGEOUT */
			vm_object_unlock(object);
			vm_page_activate(m);
			VM_STAT(reactivations++);
			vm_page_unlock_queues();
			continue;
		}

#if	ADVISORY_PAGEOUT
		if (object->advisory_pageout) {
			boolean_t		do_throttle;
			memory_object_t		pager;
			vm_object_offset_t	discard_offset;

			if (m->discard_request) {
				vm_stat_discard_failure++;
				goto mandatory_pageout;
			}

			assert(object->pager_initialized);
			m->discard_request = TRUE;
			pager = object->pager;

			/* system-wide throttle */
			do_throttle = (vm_page_free_count <=
				       vm_page_free_reserved);

#if 0
			/*
			 * JMM - Do we need a replacement throttle
			 * mechanism for pagers?
			 */
			if (!do_throttle) {
				/* throttle on this pager */
				/* XXX lock ordering ? */
				ip_lock(port);
				do_throttle= imq_full(&port->ip_messages);
				ip_unlock(port);
			}
#endif

			if (do_throttle) {
				vm_stat_discard_throttle++;
#if 0
				/* ignore this page and skip to next */
				vm_page_unlock_queues();
				vm_object_unlock(object);
				continue;
#else
				/* force mandatory pageout */
				goto mandatory_pageout;
#endif
			}

			/* proceed with discard_request */
			vm_page_activate(m);
			vm_stat_discard++;
			VM_STAT(reactivations++);
			discard_offset = m->offset + object->paging_offset;
			vm_stat_discard_sent++;
			vm_page_unlock_queues();
			vm_object_unlock(object);

/*
			memory_object_discard_request(object->pager,
						      discard_offset,
						      PAGE_SIZE);
*/
			continue;
		}
	mandatory_pageout:
#endif	/* ADVISORY_PAGEOUT */
			
                XPR(XPR_VM_PAGEOUT,
                "vm_pageout_scan, replace object 0x%X offset 0x%X page 0x%X\n",
                (integer_t)object, (integer_t)m->offset, (integer_t)m, 0,0);

		/*
		 *	Eliminate all mappings.
		 */

		m->busy = TRUE;
		pmap_page_protect(m->phys_addr, VM_PROT_NONE);

		if (!m->dirty)
			m->dirty = pmap_is_modified(m->phys_addr);
		/*
		 *	If it's clean and not precious, we can free the page.
		 */

		if (!m->dirty && !m->precious) {
			vm_pageout_inactive_clean++;
			goto reclaim_page;
		}
		vm_page_unlock_queues();

		/*
		 *	If there is no memory object for the page, create
		 *	one and hand it to the default pager.
		 */

		if (!object->pager_initialized)
			vm_object_collapse(object);
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
			vm_page_lock_queues();
			vm_page_activate(m);
			vm_page_unlock_queues();

			/*
			 *	And we are done with it.
			 */
			PAGE_WAKEUP_DONE(m);
			vm_object_unlock(object);

			/*
			 * break here to get back to the preemption
			 * point in the outer loop so that we don't
			 * spin forever if there is no default pager.
			 */
			vm_pageout_dirty_no_pager++;
			/*
			 * Well there's no pager, but we can still reclaim
			 * free pages out of the inactive list.  Go back
			 * to top of loop and look for suitable pages.
			 */
			continue;
		}

		if ((object->pager_initialized) && 
		    (object->pager == MEMORY_OBJECT_NULL)) {
			/*
			 * This pager has been destroyed by either
			 * memory_object_destroy or vm_object_destroy, and
			 * so there is nowhere for the page to go.
			 * Just free the page.
			 */
			VM_PAGE_FREE(m);
			vm_object_unlock(object);
			continue;
		}

		vm_pageout_inactive_dirty++;
/*
		if (!object->internal)
			burst_count++;
*/
		vm_object_paging_begin(object);
		vm_object_unlock(object);
		vm_pageout_cluster(m);	/* flush it */
	}
	consider_machine_adjust();
}

counter(unsigned int	c_vm_pageout_scan_continue = 0;)

void
vm_pageout_scan_continue(void)
{
	/*
	 *	We just paused to let the pagers catch up.
	 *	If vm_page_laundry_count is still high,
	 *	then we aren't waiting long enough.
	 *	If we have paused some vm_pageout_pause_max times without
	 *	adjusting vm_pageout_burst_wait, it might be too big,
	 *	so we decrease it.
	 */

	vm_page_lock_queues();
	counter(++c_vm_pageout_scan_continue);
	if (vm_page_laundry_count > vm_pageout_burst_min) {
		vm_pageout_burst_wait++;
		vm_pageout_pause_count = 0;
	} else if (++vm_pageout_pause_count > vm_pageout_pause_max) {
		vm_pageout_burst_wait = (vm_pageout_burst_wait * 3) / 4;
		if (vm_pageout_burst_wait < 1)
			vm_pageout_burst_wait = 1;
		vm_pageout_pause_count = 0;
	}
	vm_page_unlock_queues();
}

void vm_page_free_reserve(int pages);
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
vm_pageout(void)
{
	thread_t	self = current_thread();
	spl_t		s;

	/*
	 * Set thread privileges.
	 */
	self->vm_privilege = TRUE;
	stack_privilege(self);

	s = splsched();
	thread_lock(self);

	self->priority = BASEPRI_PREEMPT - 1;
	self->sched_pri = self->priority;

	thread_unlock(self);
	splx(s);

	/*
	 *	Initialize some paging parameters.
	 */

	if (vm_page_laundry_max == 0)
		vm_page_laundry_max = VM_PAGE_LAUNDRY_MAX;

	if (vm_pageout_burst_max == 0)
		vm_pageout_burst_max = VM_PAGEOUT_BURST_MAX;

	if (vm_pageout_burst_wait == 0)
		vm_pageout_burst_wait = VM_PAGEOUT_BURST_WAIT;

	if (vm_pageout_empty_wait == 0)
		vm_pageout_empty_wait = VM_PAGEOUT_EMPTY_WAIT;

	vm_page_free_count_init = vm_page_free_count;
	/*
	 * even if we've already called vm_page_free_reserve
	 * call it again here to insure that the targets are
	 * accurately calculated (it uses vm_page_free_count_init)
	 * calling it with an arg of 0 will not change the reserve
	 * but will re-calculate free_min and free_target
	 */
	if (vm_page_free_reserved < VM_PAGE_FREE_RESERVED)
		vm_page_free_reserve(VM_PAGE_FREE_RESERVED - vm_page_free_reserved);
	else
		vm_page_free_reserve(0);

	/*
	 *	vm_pageout_scan will set vm_page_inactive_target.
	 *
	 *	The pageout daemon is never done, so loop forever.
	 *	We should call vm_pageout_scan at least once each
	 *	time we are woken, even if vm_page_free_wanted is
	 *	zero, to check vm_page_free_target and
	 *	vm_page_inactive_target.
	 */
	for (;;) {
		vm_pageout_scan_event_counter++;
		vm_pageout_scan();
		/* we hold vm_page_queue_free_lock now */
		assert(vm_page_free_wanted == 0);
		assert_wait((event_t) &vm_page_free_wanted, THREAD_UNINT);
		mutex_unlock(&vm_page_queue_free_lock);
		counter(c_vm_pageout_block++);
		thread_block((void (*)(void)) 0);
	}
	/*NOTREACHED*/
}


static upl_t
upl_create(
	   boolean_t	internal,
	   vm_size_t       size)
{
	upl_t	upl;

	if(internal) {
		upl = (upl_t)kalloc(sizeof(struct upl)
			+ (sizeof(struct upl_page_info)*(size/page_size)));
	} else {
		upl = (upl_t)kalloc(sizeof(struct upl));
	}
	upl->flags = 0;
	upl->src_object = NULL;
	upl->kaddr = (vm_offset_t)0;
	upl->size = 0;
	upl->map_object = NULL;
	upl->ref_count = 1;
	upl_lock_init(upl);
#ifdef UBC_DEBUG
	upl->ubc_alias1 = 0;
	upl->ubc_alias2 = 0;
#endif /* UBC_DEBUG */
	return(upl);
}

static void
upl_destroy(
	upl_t	upl)
{

#ifdef UBC_DEBUG
	{
		upl_t	upl_ele;
		vm_object_lock(upl->map_object->shadow);
		queue_iterate(&upl->map_object->shadow->uplq, 
						upl_ele, upl_t, uplq) {
			if(upl_ele == upl) {
				queue_remove(&upl->map_object->shadow->uplq, 
					upl_ele, upl_t, uplq);
				break;
			}
		}
		vm_object_unlock(upl->map_object->shadow);
	}
#endif /* UBC_DEBUG */
#ifdef notdefcdy
	if(!(upl->flags & UPL_DEVICE_MEMORY))
#endif
		vm_object_deallocate(upl->map_object);
	if(upl->flags & UPL_INTERNAL) {
		kfree((vm_offset_t)upl,
			sizeof(struct upl) + 
			(sizeof(struct upl_page_info) * (upl->size/page_size)));
	} else {
		kfree((vm_offset_t)upl, sizeof(struct upl));
	}
}

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
	vm_object_offset_t		offset,
	vm_size_t			size,
	upl_t			*upl_ptr,
	upl_page_info_array_t	user_page_list,
	unsigned int		*page_list_count,
	int				cntrl_flags)
{
	vm_page_t		dst_page;
	vm_object_offset_t	dst_offset = offset;
	vm_size_t		xfer_size = size;
	boolean_t		do_m_lock = FALSE;
	boolean_t		dirty;
	upl_t			upl = NULL;
	int			entry;
	boolean_t		encountered_lrp = FALSE;

	vm_page_t		alias_page = NULL;
	int			page_ticket; 


	page_ticket = (cntrl_flags & UPL_PAGE_TICKET_MASK)
					>> UPL_PAGE_TICKET_SHIFT;

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

	if((cntrl_flags & UPL_COPYOUT_FROM) && (upl_ptr == NULL)) {
		return KERN_SUCCESS;
	}
	if(upl_ptr) {
		if(cntrl_flags & UPL_SET_INTERNAL) {
			upl = upl_create(TRUE, size);
			user_page_list = (upl_page_info_t *)
				(((vm_offset_t)upl) + sizeof(struct upl));
			upl->flags |= UPL_INTERNAL;
		} else {
			upl = upl_create(FALSE, size);
		}
		if(object->phys_contiguous) {
			upl->size = size;
			upl->offset = offset + object->paging_offset;
			*upl_ptr = upl;
			if(user_page_list) {
				user_page_list[0].phys_addr = 
					offset + object->shadow_offset;
				user_page_list[0].device = TRUE;
			}
			upl->map_object = vm_object_allocate(size);
			vm_object_lock(upl->map_object);
			upl->map_object->shadow = object;
			upl->flags = UPL_DEVICE_MEMORY | UPL_INTERNAL;
			upl->map_object->pageout = TRUE;
			upl->map_object->can_persist = FALSE;
			upl->map_object->copy_strategy
					= MEMORY_OBJECT_COPY_NONE;
			upl->map_object->shadow_offset = offset;
			vm_object_unlock(upl->map_object);
			return KERN_SUCCESS;
		}
		
			
		upl->map_object = vm_object_allocate(size);
		vm_object_lock(upl->map_object);
		upl->map_object->shadow = object;
		upl->size = size;
		upl->offset = offset + object->paging_offset;
		upl->map_object->pageout = TRUE;
		upl->map_object->can_persist = FALSE;
		upl->map_object->copy_strategy = MEMORY_OBJECT_COPY_NONE;
		upl->map_object->shadow_offset = offset;
		vm_object_unlock(upl->map_object);
		*upl_ptr = upl;
	}
	VM_PAGE_GRAB_FICTITIOUS(alias_page);
	vm_object_lock(object);
#ifdef UBC_DEBUG
	if(upl_ptr)
		queue_enter(&object->uplq, upl, upl_t, uplq);
#endif /* UBC_DEBUG */
	vm_object_paging_begin(object);
	entry = 0;
	if(cntrl_flags & UPL_COPYOUT_FROM) {
		upl->flags |= UPL_PAGE_SYNC_DONE;
		while (xfer_size) {
			if(alias_page == NULL) {
				vm_object_unlock(object);
				VM_PAGE_GRAB_FICTITIOUS(alias_page);
				vm_object_lock(object);
			}
			if(((dst_page = vm_page_lookup(object, 
				dst_offset)) == VM_PAGE_NULL) ||
				dst_page->fictitious ||
				dst_page->absent ||
				dst_page->error ||
				(dst_page->wire_count != 0 && 
							!dst_page->pageout) ||
				((!(dst_page->dirty || dst_page->precious ||
				      pmap_is_modified(dst_page->phys_addr)))
				      && (cntrl_flags & UPL_RET_ONLY_DIRTY)) ||
				((!(dst_page->inactive))
					&& (dst_page->page_ticket != page_ticket)
					&& ((dst_page->page_ticket+1) != page_ticket)
					&& (cntrl_flags & UPL_PAGEOUT)) ||
				((!dst_page->list_req_pending) && 
					(cntrl_flags & UPL_RET_ONLY_DIRTY) &&
					pmap_is_referenced(dst_page->phys_addr))) {
				if(user_page_list)
					user_page_list[entry].phys_addr = 0;
			} else {
				
				if(dst_page->busy && 
					(!(dst_page->list_req_pending && 
						dst_page->pageout))) {
					if(cntrl_flags & UPL_NOBLOCK) {
						if(user_page_list)
					   		user_page_list[entry]
								.phys_addr = 0;
						entry++;
						dst_offset += PAGE_SIZE_64;
						xfer_size -= PAGE_SIZE;
						continue;
					}
					/*someone else is playing with the */
					/* page.  We will have to wait.    */
					PAGE_ASSERT_WAIT(
						dst_page, THREAD_UNINT);
					vm_object_unlock(object);
					thread_block((void(*)(void))0);
					vm_object_lock(object);
					continue;
				}
				/* Someone else already cleaning the page? */
				if((dst_page->cleaning || dst_page->absent ||
					dst_page->wire_count != 0) && 
					!dst_page->list_req_pending) {
				   if(user_page_list)
					   user_page_list[entry].phys_addr = 0;
				   entry++;
				   dst_offset += PAGE_SIZE_64;
				   xfer_size -= PAGE_SIZE;
				   continue;
				}
				/* eliminate all mappings from the */
				/* original object and its prodigy */
				
				vm_page_lock_queues();
				pmap_page_protect(dst_page->phys_addr, 
								VM_PROT_NONE);

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

				/* Turn off busy indication on pending */
				/* pageout.  Note: we can only get here */
				/* in the request pending case.  */
				dst_page->list_req_pending = FALSE;
				dst_page->busy = FALSE;
				dst_page->cleaning = FALSE;

				dirty = pmap_is_modified(dst_page->phys_addr);
				dirty = dirty ? TRUE : dst_page->dirty;

				/* use pageclean setup, it is more convenient */
				/* even for the pageout cases here */
				vm_pageclean_setup(dst_page, alias_page,
					upl->map_object, size - xfer_size);
						
				if(!dirty) {
					dst_page->dirty = FALSE;
					dst_page->precious = TRUE;
				}

				if(dst_page->pageout)
					dst_page->busy = TRUE;

				alias_page->absent = FALSE;
				alias_page = NULL;
				if((!(cntrl_flags & UPL_CLEAN_IN_PLACE)) 
					|| (cntrl_flags & UPL_PAGEOUT)) {
					/* deny access to the target page */
					/* while it is being worked on    */
					if((!dst_page->pageout) &&
						(dst_page->wire_count == 0)) {
						dst_page->busy = TRUE;
						dst_page->pageout = TRUE;
						vm_page_wire(dst_page);
					}
				}
				if(user_page_list) {
					user_page_list[entry].phys_addr
						= dst_page->phys_addr;
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
	} else {
		while (xfer_size) {
			if(alias_page == NULL) {
				vm_object_unlock(object);
				VM_PAGE_GRAB_FICTITIOUS(alias_page);
				vm_object_lock(object);
			}
			dst_page = vm_page_lookup(object, dst_offset);
			if(dst_page != VM_PAGE_NULL) {
				if((dst_page->cleaning) && 
				   !(dst_page->list_req_pending)) {
					/*someone else is writing to the */
					/* page.  We will have to wait.  */
					PAGE_ASSERT_WAIT(dst_page,THREAD_UNINT);
					vm_object_unlock(object);
					thread_block((void(*)(void))0);
					vm_object_lock(object);
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
				} else if ((dst_page->absent && 
					    dst_page->list_req_pending)) {
					/* the default_pager case */
					dst_page->list_req_pending = FALSE;
					dst_page->busy = FALSE;
					dst_page->clustered = FALSE;
				}
			}
			if((dst_page = vm_page_lookup(object, dst_offset)) ==
			   VM_PAGE_NULL) {
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
					if(user_page_list)
						user_page_list[entry]
							.phys_addr = 0;
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
				dst_page->absent = TRUE;
				object->absent_count++;
			}
#if 1
			if(cntrl_flags & UPL_NO_SYNC) {
				dst_page->page_lock = 0;
				dst_page->unlock_request = 0;
			}
#endif /* 1 */
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
					PAGE_ASSERT_WAIT(
						dst_page, THREAD_UNINT);
					vm_object_unlock(object);
					thread_block((void(*)(void))0);
					vm_object_lock(object);
					continue;
				}
				
				vm_page_lock_queues();
				pmap_page_protect(dst_page->phys_addr, 
								VM_PROT_NONE);
				dirty = pmap_is_modified(dst_page->phys_addr);
				dirty = dirty ? TRUE : dst_page->dirty;

				vm_pageclean_setup(dst_page, alias_page,
					upl->map_object, size - xfer_size);

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
				/* expect the page to be used */
				dst_page->reference = TRUE;
				dst_page->precious = 
					(cntrl_flags & UPL_PRECIOUS) 
							? TRUE : FALSE;
				alias_page->absent = FALSE;
				alias_page = NULL;
				if(user_page_list) {
					user_page_list[entry].phys_addr
						= dst_page->phys_addr;
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
		thread_t	thread;

		if(!object->pager_ready) {
		   thread = current_thread();
		   vm_object_assert_wait(object, 
				VM_OBJECT_EVENT_PAGER_READY, THREAD_UNINT);
		   vm_object_unlock(object);
		   thread_block((void (*)(void))0);
		   if (thread->wait_result !=  THREAD_AWAKENED) {
		      return(KERN_FAILURE);
		   }
		   vm_object_lock(object);
		   continue;
		}

		vm_object_unlock(object);

		if (rc = memory_object_data_unlock(
			object->pager,
			dst_offset + object->paging_offset,
			size,
			access_required)) {
			if (rc == MACH_SEND_INTERRUPTED) 
				continue;
			else
				return KERN_FAILURE;
		}
		break;
		
	   }
	   /* lets wait on the last page requested */
	   /* NOTE: we will have to update lock completed routine to signal */
	   if(dst_page != VM_PAGE_NULL && 
		(access_required & dst_page->page_lock) != access_required) {
	   	PAGE_ASSERT_WAIT(dst_page, THREAD_UNINT);
	   	thread_block((void (*)(void))0);
	   	vm_object_lock(object);
	   }
	}
	vm_object_unlock(object);
	return KERN_SUCCESS;
}

/* JMM - Backward compatability for now */
kern_return_t
vm_fault_list_request(
	memory_object_control_t		control,
	vm_object_offset_t	offset,
	vm_size_t		size,
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
	vm_size_t		size,
	vm_size_t		super_cluster,
	upl_t			*upl,
	upl_page_info_t		*user_page_list,
	unsigned int		*page_list_count,
	int			cntrl_flags)
{
	vm_page_t	target_page;
	int		ticket;

	if(object->paging_offset > offset)
		return KERN_FAILURE;

	offset = offset - object->paging_offset;
	if(cntrl_flags & UPL_PAGEOUT) {
		if((target_page = vm_page_lookup(object, offset))
							!= VM_PAGE_NULL) {
			ticket = target_page->page_ticket;
			cntrl_flags = cntrl_flags & ~(int)UPL_PAGE_TICKET_MASK;
			cntrl_flags = cntrl_flags | 
				((ticket << UPL_PAGE_TICKET_SHIFT) 
							& UPL_PAGE_TICKET_MASK);
		}
	}


/* turns off super cluster exercised by the default_pager */
/*
super_cluster = size;
*/
	if ((super_cluster > size) && 
			(vm_page_free_count > vm_page_free_reserved)) {

		vm_object_offset_t	base_offset;
		vm_size_t		super_size;

		base_offset = (offset &  
			~((vm_object_offset_t) super_cluster - 1));
		super_size = (offset+size) > (base_offset + super_cluster) ?
				super_cluster<<1 : super_cluster;
		super_size = ((base_offset + super_size) > object->size) ? 
				(object->size - base_offset) : super_size;
		if(offset > (base_offset + super_size))
		   panic("vm_object_super_upl_request: Missed target pageout 0x%x,0x%x, 0x%x, 0x%x, 0x%x, 0x%x\n", offset, base_offset, super_size, super_cluster, size, object->paging_offset);
		/* apparently there is a case where the vm requests a */
		/* page to be written out who's offset is beyond the  */
		/* object size */
		if((offset + size) > (base_offset + super_size))
		   super_size = (offset + size) - base_offset;

		offset = base_offset;
		size = super_size;
	}
	vm_object_upl_request(object, offset, size,
				  upl, user_page_list, page_list_count,
				  cntrl_flags);
}


kern_return_t
vm_upl_map(
	vm_map_t	map, 
	upl_t		upl, 
	vm_offset_t	*dst_addr)
{
	vm_size_t	 	size;
	vm_object_offset_t 	offset;
	vm_offset_t		addr;
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

	offset = 0;  /* Always map the entire object */
	size = upl->size;
	
	vm_object_lock(upl->map_object);
	upl->map_object->ref_count++;
	vm_object_res_reference(upl->map_object);
	vm_object_unlock(upl->map_object);

	*dst_addr = 0;


	/* NEED A UPL_MAP ALIAS */
	kr = vm_map_enter(map, dst_addr, size, (vm_offset_t) 0, TRUE,
		upl->map_object, offset, FALSE,
		VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);

	if (kr != KERN_SUCCESS) {
		upl_unlock(upl);
		return(kr);
	}

	for(addr=*dst_addr; size > 0; size-=PAGE_SIZE,addr+=PAGE_SIZE) {
		m = vm_page_lookup(upl->map_object, offset);
		if(m) {
			PMAP_ENTER(map->pmap, addr, m, VM_PROT_ALL, TRUE);
		}
		offset+=PAGE_SIZE_64;
	}
	upl->ref_count++;  /* hold a reference for the mapping */
	upl->flags |= UPL_PAGE_LIST_MAPPED;
	upl->kaddr = *dst_addr;
	upl_unlock(upl);
	return KERN_SUCCESS;
}
	

kern_return_t
vm_upl_unmap(
	vm_map_t	map, 
	upl_t		upl)
{
	vm_address_t	addr;
	vm_size_t	size;

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

		vm_deallocate(map, addr, size);
		return KERN_SUCCESS;
	}
	upl_unlock(upl);
	return KERN_FAILURE;
}

kern_return_t
upl_commit_range(
	upl_t			upl, 
	vm_offset_t		offset, 
	vm_size_t		size,
	int			flags,
	upl_page_info_t		*page_list,
	mach_msg_type_number_t	count,
	boolean_t		*empty) 
{
	vm_size_t		xfer_size = size;
	vm_object_t		shadow_object = upl->map_object->shadow;
	vm_object_t		object = upl->map_object;
	vm_object_offset_t	target_offset;
	vm_object_offset_t	page_offset;
	int			entry;

	*empty = FALSE;

	if (upl == UPL_NULL)
		return KERN_INVALID_ARGUMENT;

	if (count == 0)
		page_list = NULL;

	upl_lock(upl);
	if(upl->flags & UPL_DEVICE_MEMORY) {
		xfer_size = 0;
	} else if ((offset + size) > upl->size) {
		upl_unlock(upl);
		return KERN_FAILURE;
	}

	vm_object_lock(shadow_object);

	entry = offset/PAGE_SIZE;
	target_offset = (vm_object_offset_t)offset;
	while(xfer_size) {
		vm_page_t	t,m;
		upl_page_info_t *p;

		if((t = vm_page_lookup(object, target_offset)) != NULL) {

			t->pageout = FALSE;
			page_offset = t->offset;
			VM_PAGE_FREE(t);
			t = VM_PAGE_NULL;
			m = vm_page_lookup(shadow_object, 
					page_offset + object->shadow_offset);
			if(m != VM_PAGE_NULL) {
			   vm_object_paging_end(shadow_object);
			   vm_page_lock_queues();
			   if ((upl->flags & UPL_CLEAR_DIRTY) ||
					(flags & UPL_COMMIT_CLEAR_DIRTY)) {
				pmap_clear_modify(m->phys_addr);
				m->dirty = FALSE;
			   }
			   if(page_list) {
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
			      vm_page_laundry_count--;
			      m->laundry = FALSE;
			      if (vm_page_laundry_count < vm_page_laundry_min) {
			         vm_page_laundry_min = 0;
			         thread_wakeup((event_t) 
					     &vm_page_laundry_count);
			      }
			   }
			   if(m->pageout) {
			      m->cleaning = FALSE;
			      m->pageout = FALSE;
#if MACH_CLUSTER_STATS
			      if (m->wanted) vm_pageout_target_collisions++;
#endif
			      pmap_page_protect(m->phys_addr, VM_PROT_NONE);
			      m->dirty = pmap_is_modified(m->phys_addr);
			      if(m->dirty) {
			         CLUSTER_STAT(
			              vm_pageout_target_page_dirtied++;)
                                 vm_page_unwire(m);/* reactivates */
                                 VM_STAT(reactivations++);
                                 PAGE_WAKEUP_DONE(m);
                       	      } else {
                                    CLUSTER_STAT(
				               vm_pageout_target_page_freed++;)
                                    vm_page_free(m);/* clears busy, etc. */
				    VM_STAT(pageouts++);
                        	 }
                        	 vm_page_unlock_queues();
				 target_offset += PAGE_SIZE_64;
				 xfer_size -= PAGE_SIZE;
				 entry++;
                                 continue;
			   }
			      if (flags & UPL_COMMIT_INACTIVATE) {
                                      vm_page_deactivate(m);
				      m->reference = FALSE;
				      pmap_clear_reference(m->phys_addr);
			      } else if (!m->active && !m->inactive) {
                                   if (m->reference)
                                      vm_page_activate(m);
                                   else
                                      vm_page_deactivate(m);
                              }
#if MACH_CLUSTER_STATS
                              m->dirty = pmap_is_modified(m->phys_addr);

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
                              }
			      else if (m->overwriting) {
			         /* alternate request page list, write to 
			         /* page_list case.  Occurs when the original
			         /* page was wired at the time of the list
			         /* request */
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

			      if (flags & UPL_COMMIT_SET_DIRTY) {
				 m->dirty = TRUE;
			      }
                              /*
                               * Wakeup any thread waiting for the page to be un-cleaning.
                               */
                              PAGE_WAKEUP(m);
                              vm_page_unlock_queues();

			}
		}
		target_offset += PAGE_SIZE_64;
		xfer_size -= PAGE_SIZE;
		entry++;
	}

	vm_object_unlock(shadow_object);
	if(flags & UPL_COMMIT_NOTIFY_EMPTY) {
		if((upl->flags & UPL_DEVICE_MEMORY) 
				|| (queue_empty(&upl->map_object->memq)))
			*empty = TRUE;
	}
	upl_unlock(upl);

	return KERN_SUCCESS;
}

kern_return_t
upl_abort_range(
	upl_t			upl, 
	vm_offset_t		offset, 
	vm_size_t		size,
	int			error,
	boolean_t		*empty) 
{
	vm_size_t		xfer_size = size;
	vm_object_t		shadow_object = upl->map_object->shadow;
	vm_object_t		object = upl->map_object;
	vm_object_offset_t	target_offset;
	vm_object_offset_t	page_offset;
	int			entry;

	*empty = FALSE;

	if (upl == UPL_NULL)
		return KERN_INVALID_ARGUMENT;

	upl_lock(upl);
	if(upl->flags & UPL_DEVICE_MEMORY) {
		xfer_size = 0;
	} else if ((offset + size) > upl->size) {
		upl_unlock(upl);
		return KERN_FAILURE;
	}

	vm_object_lock(shadow_object);

	entry = offset/PAGE_SIZE;
	target_offset = (vm_object_offset_t)offset;
	while(xfer_size) {
		vm_page_t	t,m;
		upl_page_info_t *p;

		if((t = vm_page_lookup(object, target_offset)) != NULL) {

			t->pageout = FALSE;
			page_offset = t->offset;
			VM_PAGE_FREE(t);
			t = VM_PAGE_NULL;
			m = vm_page_lookup(shadow_object, 
					page_offset + object->shadow_offset);
		   if(m != VM_PAGE_NULL) {
			vm_object_paging_end(m->object);
			vm_page_lock_queues();
			if(m->absent) {
				/* COPYOUT = FALSE case */
				/* check for error conditions which must */
				/* be passed back to the pages customer  */
				if(error & UPL_ABORT_RESTART) {
					m->restart = TRUE;
					m->absent = FALSE;
					vm_object_absent_release(m->object);
					m->page_error = KERN_MEMORY_ERROR;
					m->error = TRUE;
				} else if(error & UPL_ABORT_UNAVAILABLE) {
					m->restart = FALSE;
					m->unusual = TRUE;
					m->clustered = FALSE;
				} else if(error & UPL_ABORT_ERROR) {
					m->restart = FALSE;
					m->absent = FALSE;
					vm_object_absent_release(m->object);
					m->page_error = KERN_MEMORY_ERROR;
					m->error = TRUE;
				} else if(error & UPL_ABORT_DUMP_PAGES) {
					m->clustered = TRUE;	
				} else {
					m->clustered = TRUE;
				}
				

				m->cleaning = FALSE;
				m->overwriting = FALSE;
				PAGE_WAKEUP_DONE(m);
				if(m->clustered) {
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
    				vm_page_laundry_count--;
    				m->laundry = FALSE;  
    				if (vm_page_laundry_count 
						< vm_page_laundry_min) {
					vm_page_laundry_min = 0;
					thread_wakeup((event_t) 
						&vm_page_laundry_count); 
				}                    
			}         
			if(m->pageout) {
				assert(m->busy);
				assert(m->wire_count == 1);
				m->pageout = FALSE;
				vm_page_unwire(m);
			}
			m->dump_cleaning = FALSE;
			m->cleaning = FALSE;
			m->busy = FALSE;
			m->overwriting = FALSE;
#if	MACH_PAGEMAP
			vm_external_state_clr(
				m->object->existence_map, m->offset);
#endif	/* MACH_PAGEMAP */
			if(error & UPL_ABORT_DUMP_PAGES) {
				vm_page_free(m);
				pmap_page_protect(m->phys_addr, VM_PROT_NONE);
			} else {
				PAGE_WAKEUP(m);
			}
			vm_page_unlock_queues();
		}
	   }
	   target_offset += PAGE_SIZE_64;
	   xfer_size -= PAGE_SIZE;
	   entry++;
	}
	vm_object_unlock(shadow_object);
	if(error & UPL_ABORT_NOTIFY_EMPTY) {
		if((upl->flags & UPL_DEVICE_MEMORY) 
				|| (queue_empty(&upl->map_object->memq)))
			*empty = TRUE;
	}
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
	int			i;
	vm_page_t		t,m;

	if (upl == UPL_NULL)
		return KERN_INVALID_ARGUMENT;

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

	shadow_object = upl->map_object->shadow;
	shadow_offset = upl->map_object->shadow_offset;
	offset = 0;
	vm_object_lock(shadow_object);
	for(i = 0; i<(upl->size); i+=PAGE_SIZE, offset += PAGE_SIZE_64) {
	    if((t = vm_page_lookup(object,offset)) != NULL) {
		target_offset = t->offset + shadow_offset;
		if((m = vm_page_lookup(shadow_object, target_offset)) != NULL) {
			vm_object_paging_end(m->object);
			vm_page_lock_queues();
			if(m->absent) {
				/* COPYOUT = FALSE case */
				/* check for error conditions which must */
				/* be passed back to the pages customer  */
				if(error & UPL_ABORT_RESTART) {
					m->restart = TRUE;
					m->absent = FALSE;
					vm_object_absent_release(m->object);
					m->page_error = KERN_MEMORY_ERROR;
					m->error = TRUE;
				} else if(error & UPL_ABORT_UNAVAILABLE) {
					m->restart = FALSE;
					m->unusual = TRUE;
					m->clustered = FALSE;
				} else if(error & UPL_ABORT_ERROR) {
					m->restart = FALSE;
					m->absent = FALSE;
					vm_object_absent_release(m->object);
					m->page_error = KERN_MEMORY_ERROR;
					m->error = TRUE;
				} else if(error & UPL_ABORT_DUMP_PAGES) {
					m->clustered = TRUE;	
				} else {
					m->clustered = TRUE;
				}
				
				m->cleaning = FALSE;
				m->overwriting = FALSE;
				PAGE_WAKEUP_DONE(m);
				if(m->clustered) {
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
    				vm_page_laundry_count--;
    				m->laundry = FALSE;  
    				if (vm_page_laundry_count 
						< vm_page_laundry_min) {
					vm_page_laundry_min = 0;
					thread_wakeup((event_t) 
						&vm_page_laundry_count); 
				}                    
			}         
			if(m->pageout) {
				assert(m->busy);
				assert(m->wire_count == 1);
				m->pageout = FALSE;
				vm_page_unwire(m);
			}
			m->dump_cleaning = FALSE;
			m->cleaning = FALSE;
			m->busy = FALSE;
			m->overwriting = FALSE;
#if	MACH_PAGEMAP
			vm_external_state_clr(
				m->object->existence_map, m->offset);
#endif	/* MACH_PAGEMAP */
			if(error & UPL_ABORT_DUMP_PAGES) {
				vm_page_free(m);
				pmap_page_protect(m->phys_addr, VM_PROT_NONE);
			} else {
				PAGE_WAKEUP(m);
			}
			vm_page_unlock_queues();
		}
	   }
	}
	vm_object_unlock(shadow_object);
	/* Remove all the pages from the map object so */
	/* vm_pageout_object_terminate will work properly. */
	while (!queue_empty(&upl->map_object->memq)) {
		vm_page_t p;

		p = (vm_page_t) queue_first(&upl->map_object->memq);

		assert(p->private);
		assert(p->pageout);
		p->pageout = FALSE;
		assert(!p->cleaning);

		VM_PAGE_FREE(p);
	}
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

	if (count == 0)
		page_list = NULL;

	upl_lock(upl);
	if (upl->flags & UPL_DEVICE_MEMORY)
		page_list = NULL;
	if ((upl->flags & UPL_CLEAR_DIRTY) ||
		(upl->flags & UPL_PAGE_SYNC_DONE)) {
		vm_object_t	shadow_object = upl->map_object->shadow;
		vm_object_t	object = upl->map_object;
		vm_object_offset_t target_offset;
		vm_size_t	xfer_end;

		vm_page_t	t,m;

		vm_object_lock(shadow_object);

		target_offset = object->shadow_offset;
		xfer_end = upl->size + object->shadow_offset;

		while(target_offset < xfer_end) {
			if ((t = vm_page_lookup(object, 
				target_offset - object->shadow_offset))
				!= NULL) {
				m = vm_page_lookup(
					shadow_object, target_offset);
				if(m != VM_PAGE_NULL) {
					if (upl->flags & UPL_CLEAR_DIRTY) {
						pmap_clear_modify(m->phys_addr);
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
				}
			}
			target_offset += PAGE_SIZE_64;
		}
		vm_object_unlock(shadow_object);
	}
	if (page_list) {
		vm_object_t	shadow_object = upl->map_object->shadow;
		vm_object_t	object = upl->map_object;
		vm_object_offset_t target_offset;
		vm_size_t	xfer_end;
		int		entry;

		vm_page_t	t, m;
		upl_page_info_t	*p;

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
			target_offset += PAGE_SIZE_64;
			entry++;
		}

		vm_object_unlock(shadow_object);
	}
	upl_unlock(upl);
	return KERN_SUCCESS;
}

vm_size_t
upl_get_internal_pagelist_offset()
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
vm_offset_t  upl_phys_page(upl_page_info_t *upl, int index)
{
	return((vm_offset_t)UPL_PHYS_PAGE(upl, index));
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

		m = (vm_page_t) queue_next(&m->pageq);
		if (m ==(vm_page_t )0) break;

	} while (!queue_end(&vm_page_queue_inactive,(queue_entry_t) m));
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

		m = (vm_page_t) queue_next(&m->pageq);
		if(m == (vm_page_t )0) break;

	} while (!queue_end(&vm_page_queue_active,(queue_entry_t) m));
	vm_page_unlock_queues();

	printf("AC Q: %d : %d : %d\n", dpages, pgopages, precpages);

}
#endif /* MACH_BSD */

#ifdef UBC_DEBUG
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
#endif /* UBC_DEBUG */



#if	MACH_KDB
#include <ddb/db_output.h>
#include <ddb/db_print.h>
#include <vm/vm_print.h>

#define	printf	kdbprintf
extern int	db_indent;
void		db_pageout(void);

void
db_vm(void)
{
	extern int vm_page_gobble_count;

	iprintf("VM Statistics:\n");
	db_indent += 2;
	iprintf("pages:\n");
	db_indent += 2;
	iprintf("activ %5d  inact %5d  free  %5d",
		vm_page_active_count, vm_page_inactive_count,
		vm_page_free_count);
	printf("   wire  %5d  gobbl %5d\n",
	       vm_page_wire_count, vm_page_gobble_count);
	iprintf("laund %5d\n",
		vm_page_laundry_count);
	db_indent -= 2;
	iprintf("target:\n");
	db_indent += 2;
	iprintf("min   %5d  inact %5d  free  %5d",
		vm_page_free_min, vm_page_inactive_target,
		vm_page_free_target);
	printf("   resrv %5d\n", vm_page_free_reserved);
	db_indent -= 2;

	iprintf("burst:\n");
	db_indent += 2;
	iprintf("max   %5d  min   %5d  wait  %5d   empty %5d\n",
		  vm_pageout_burst_max, vm_pageout_burst_min,
		  vm_pageout_burst_wait, vm_pageout_empty_wait);
	db_indent -= 2;
	iprintf("pause:\n");
	db_indent += 2;
	iprintf("count %5d  max   %5d\n",
		vm_pageout_pause_count, vm_pageout_pause_max);
#if	MACH_COUNTERS
	iprintf("scan_continue called %8d\n", c_vm_pageout_scan_continue);
#endif	/* MACH_COUNTERS */
	db_indent -= 2;
	db_pageout();
	db_indent -= 2;
}

void
db_pageout(void)
{
#if	MACH_COUNTERS
	extern int c_laundry_pages_freed;
#endif	/* MACH_COUNTERS */

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

#endif	/* MACH_KDB */
