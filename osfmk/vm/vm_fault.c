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
 *	File:	vm_fault.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *
 *	Page fault handling module.
 */
#ifdef MACH_BSD
/* remove after component interface available */
extern int	vnode_pager_workaround;
extern int	device_pager_workaround;
#endif

#include <mach_cluster_stats.h>
#include <mach_pagemap.h>
#include <mach_kdb.h>

#include <vm/vm_fault.h>
#include <mach/kern_return.h>
#include <mach/message.h>	/* for error codes */
#include <kern/host_statistics.h>
#include <kern/counters.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/host.h>
#include <kern/xpr.h>
#include <ppc/proc_reg.h>
#include <ppc/pmap_internals.h>
#include <vm/task_working_set.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/pmap.h>
#include <vm/vm_pageout.h>
#include <mach/vm_param.h>
#include <mach/vm_behavior.h>
#include <mach/memory_object.h>
				/* For memory_object_data_{request,unlock} */
#include <kern/mach_param.h>
#include <kern/macro_help.h>
#include <kern/zalloc.h>
#include <kern/misc_protos.h>

#include <sys/kdebug.h>

#define VM_FAULT_CLASSIFY	0
#define VM_FAULT_STATIC_CONFIG	1

#define TRACEFAULTPAGE 0 /* (TEST/DEBUG) */

int		vm_object_absent_max = 50;

int		vm_fault_debug = 0;
boolean_t	vm_page_deactivate_behind = TRUE;


#if	!VM_FAULT_STATIC_CONFIG
boolean_t	vm_fault_dirty_handling = FALSE;
boolean_t	vm_fault_interruptible = FALSE;
boolean_t	software_reference_bits = TRUE;
#endif

#if	MACH_KDB
extern struct db_watchpoint *db_watchpoint_list;
#endif	/* MACH_KDB */

/* Forward declarations of internal routines. */
extern kern_return_t vm_fault_wire_fast(
				vm_map_t	map,
				vm_offset_t	va,
				vm_map_entry_t	entry,
				pmap_t		pmap);

extern void vm_fault_continue(void);

extern void vm_fault_copy_cleanup(
				vm_page_t	page,
				vm_page_t	top_page);

extern void vm_fault_copy_dst_cleanup(
				vm_page_t	page);

#if	VM_FAULT_CLASSIFY
extern void vm_fault_classify(vm_object_t	object,
			  vm_object_offset_t	offset,
			  vm_prot_t		fault_type);

extern void vm_fault_classify_init(void);
#endif

/*
 *	Routine:	vm_fault_init
 *	Purpose:
 *		Initialize our private data structures.
 */
void
vm_fault_init(void)
{
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
	register vm_object_t	object,
	register vm_page_t	top_page)
{
	vm_object_paging_end(object);
	vm_object_unlock(object);

	if (top_page != VM_PAGE_NULL) {
	    object = top_page->object;
	    vm_object_lock(object);
	    VM_PAGE_FREE(top_page);
	    vm_object_paging_end(object);
	    vm_object_unlock(object);
	}
}

#if	MACH_CLUSTER_STATS
#define MAXCLUSTERPAGES 16
struct {
	unsigned long pages_in_cluster;
	unsigned long pages_at_higher_offsets;
	unsigned long pages_at_lower_offsets;
} cluster_stats_in[MAXCLUSTERPAGES];
#define CLUSTER_STAT(clause)	clause
#define CLUSTER_STAT_HIGHER(x)	\
	((cluster_stats_in[(x)].pages_at_higher_offsets)++)
#define CLUSTER_STAT_LOWER(x)	\
	 ((cluster_stats_in[(x)].pages_at_lower_offsets)++)
#define CLUSTER_STAT_CLUSTER(x)	\
	((cluster_stats_in[(x)].pages_in_cluster)++)
#else	/* MACH_CLUSTER_STATS */
#define CLUSTER_STAT(clause)
#endif	/* MACH_CLUSTER_STATS */

/* XXX - temporary */
boolean_t vm_allow_clustered_pagein = FALSE;
int vm_pagein_cluster_used = 0;

/* 
 * Prepage default sizes given VM_BEHAVIOR_DEFAULT reference behavior 
 */
int vm_default_ahead = 1;	/* Number of pages to prepage ahead */
int vm_default_behind = 0;	/* Number of pages to prepage behind */

#define ALIGNED(x) (((x) & (PAGE_SIZE_64 - 1)) == 0)

/*
 *	Routine:	vm_fault_page
 *	Purpose:
 *		Find the resident page for the virtual memory
 *		specified by the given virtual memory object
 *		and offset.
 *	Additional arguments:
 *		The required permissions for the page is given
 *		in "fault_type".  Desired permissions are included
 *		in "protection".  The minimum and maximum valid offsets
 *		within the object for the relevant map entry are
 *		passed in "lo_offset" and "hi_offset" respectively and
 *		the expected page reference pattern is passed in "behavior".
 *		These three parameters are used to determine pagein cluster 
 *		limits.
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
 */

vm_fault_return_t
vm_fault_page(
	/* Arguments: */
	vm_object_t	first_object,	/* Object to begin search */
	vm_object_offset_t first_offset,	/* Offset into object */
	vm_prot_t	fault_type,	/* What access is requested */
	boolean_t	must_be_resident,/* Must page be resident? */
	int		interruptible,	/* how may fault be interrupted? */
	vm_object_offset_t lo_offset,	/* Map entry start */
	vm_object_offset_t hi_offset,	/* Map entry end */
	vm_behavior_t	behavior,	/* Page reference behavior */
	/* Modifies in place: */
	vm_prot_t	*protection,	/* Protection for mapping */
	/* Returns: */
	vm_page_t	*result_page,	/* Page found, if successful */
	vm_page_t	*top_page,	/* Page in top object, if
					 * not result_page.  */
	int             *type_of_fault, /* if non-null, fill in with type of fault
					 * COW, zero-fill, etc... returned in trace point */
	/* More arguments: */
	kern_return_t	*error_code,	/* code if page is in error */
	boolean_t	no_zero_fill,	/* don't zero fill absent pages */
	boolean_t	data_supply,	/* treat as data_supply if 
					 * it is a write fault and a full
					 * page is provided */
	vm_map_t	map,
	vm_offset_t	vaddr)
{
	register
	vm_page_t		m;
	register
	vm_object_t		object;
	register
	vm_object_offset_t	offset;
	vm_page_t		first_m;
	vm_object_t		next_object;
	vm_object_t		copy_object;
	boolean_t		look_for_page;
	vm_prot_t		access_required = fault_type;
	vm_prot_t		wants_copy_flag;
	vm_size_t		cluster_size, length;
	vm_object_offset_t	cluster_offset;
	vm_object_offset_t	cluster_start, cluster_end, paging_offset;
	vm_object_offset_t	align_offset;
	CLUSTER_STAT(int pages_at_higher_offsets;)
	CLUSTER_STAT(int pages_at_lower_offsets;)
	kern_return_t	wait_result;
	thread_t		cur_thread;
	boolean_t		interruptible_state;
	boolean_t               bumped_pagein = FALSE;


#if	MACH_PAGEMAP
/*
 * MACH page map - an optional optimization where a bit map is maintained
 * by the VM subsystem for internal objects to indicate which pages of
 * the object currently reside on backing store.  This existence map
 * duplicates information maintained by the vnode pager.  It is 
 * created at the time of the first pageout against the object, i.e. 
 * at the same time pager for the object is created.  The optimization
 * is designed to eliminate pager interaction overhead, if it is 
 * 'known' that the page does not exist on backing store.
 *
 * LOOK_FOR() evaluates to TRUE if the page specified by object/offset is 
 * either marked as paged out in the existence map for the object or no 
 * existence map exists for the object.  LOOK_FOR() is one of the
 * criteria in the decision to invoke the pager.   It is also used as one
 * of the criteria to terminate the scan for adjacent pages in a clustered
 * pagein operation.  Note that LOOK_FOR() always evaluates to TRUE for
 * permanent objects.  Note also that if the pager for an internal object 
 * has not been created, the pager is not invoked regardless of the value 
 * of LOOK_FOR() and that clustered pagein scans are only done on an object
 * for which a pager has been created.
 *
 * PAGED_OUT() evaluates to TRUE if the page specified by the object/offset
 * is marked as paged out in the existence map for the object.  PAGED_OUT()
 * PAGED_OUT() is used to determine if a page has already been pushed
 * into a copy object in order to avoid a redundant page out operation.
 */
#define LOOK_FOR(o, f) (vm_external_state_get((o)->existence_map, (f)) \
			!= VM_EXTERNAL_STATE_ABSENT)
#define PAGED_OUT(o, f) (vm_external_state_get((o)->existence_map, (f)) \
			== VM_EXTERNAL_STATE_EXISTS)
#else /* MACH_PAGEMAP */
/*
 * If the MACH page map optimization is not enabled,
 * LOOK_FOR() always evaluates to TRUE.  The pager will always be 
 * invoked to resolve missing pages in an object, assuming the pager 
 * has been created for the object.  In a clustered page operation, the 
 * absence of a page on backing backing store cannot be used to terminate 
 * a scan for adjacent pages since that information is available only in 
 * the pager.  Hence pages that may not be paged out are potentially 
 * included in a clustered request.  The vnode pager is coded to deal 
 * with any combination of absent/present pages in a clustered 
 * pagein request.  PAGED_OUT() always evaluates to FALSE, i.e. the pager
 * will always be invoked to push a dirty page into a copy object assuming
 * a pager has been created.  If the page has already been pushed, the
 * pager will ingore the new request.
 */
#define LOOK_FOR(o, f) TRUE
#define PAGED_OUT(o, f) FALSE
#endif /* MACH_PAGEMAP */

/*
 *	Recovery actions
 */
#define PREPARE_RELEASE_PAGE(m)				\
	MACRO_BEGIN					\
	vm_page_lock_queues();				\
	MACRO_END

#define DO_RELEASE_PAGE(m)				\
	MACRO_BEGIN					\
	PAGE_WAKEUP_DONE(m);				\
	if (!m->active && !m->inactive)			\
		vm_page_activate(m);			\
	vm_page_unlock_queues();			\
	MACRO_END

#define RELEASE_PAGE(m)					\
	MACRO_BEGIN					\
	PREPARE_RELEASE_PAGE(m);			\
	DO_RELEASE_PAGE(m);				\
	MACRO_END

#if TRACEFAULTPAGE
	dbgTrace(0xBEEF0002, (unsigned int) first_object, (unsigned int) first_offset);	/* (TEST/DEBUG) */
#endif



#if	!VM_FAULT_STATIC_CONFIG
	if (vm_fault_dirty_handling
#if	MACH_KDB
		/*
		 *	If there are watchpoints set, then
		 *	we don't want to give away write permission
		 *	on a read fault.  Make the task write fault,
		 *	so that the watchpoint code notices the access.
		 */
	    || db_watchpoint_list
#endif	/* MACH_KDB */
	    ) {
		/*
		 *	If we aren't asking for write permission,
		 *	then don't give it away.  We're using write
		 *	faults to set the dirty bit.
		 */
		if (!(fault_type & VM_PROT_WRITE))
			*protection &= ~VM_PROT_WRITE;
	}

	if (!vm_fault_interruptible)
		interruptible = THREAD_UNINT;
#else	/* STATIC_CONFIG */
#if	MACH_KDB
		/*
		 *	If there are watchpoints set, then
		 *	we don't want to give away write permission
		 *	on a read fault.  Make the task write fault,
		 *	so that the watchpoint code notices the access.
		 */
	    if (db_watchpoint_list) {
		/*
		 *	If we aren't asking for write permission,
		 *	then don't give it away.  We're using write
		 *	faults to set the dirty bit.
		 */
		if (!(fault_type & VM_PROT_WRITE))
			*protection &= ~VM_PROT_WRITE;
	}

#endif	/* MACH_KDB */
#endif	/* STATIC_CONFIG */

	cur_thread = current_thread();

	interruptible_state = cur_thread->interruptible;
	if (interruptible == THREAD_UNINT)
		cur_thread->interruptible = FALSE;
 
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
	 *		Note also that we aren't as concerned about more than
	 *		one thread attempting to memory_object_data_unlock
	 *		the same page at once, so we don't hold the page
	 *		as busy then, but do record the highest unlock
	 *		value so far.  [Unlock requests may also be delivered
	 *		out of order.]
	 *
	 *	2)	To prevent another thread from racing us down the
	 *		shadow chain and entering a new page in the top
	 *		object before we do, we must keep a busy page in
	 *		the top object while following the shadow chain.
	 *
	 *	3)	We must increment paging_in_progress on any object
	 *		for which we have a busy page
	 *
	 *	4)	We leave busy pages on the pageout queues.
	 *		If the pageout daemon comes across a busy page,
	 *		it will remove the page from the pageout queues.
	 */

	/*
	 *	Search for the page at object/offset.
	 */

	object = first_object;
	offset = first_offset;
	first_m = VM_PAGE_NULL;
	access_required = fault_type;

	XPR(XPR_VM_FAULT,
		"vm_f_page: obj 0x%X, offset 0x%X, type %d, prot %d\n",
		(integer_t)object, offset, fault_type, *protection, 0);

	/*
	 *	See whether this page is resident
	 */

	while (TRUE) {
#if TRACEFAULTPAGE
		dbgTrace(0xBEEF0003, (unsigned int) 0, (unsigned int) 0);	/* (TEST/DEBUG) */
#endif
		if (!object->alive) {
			vm_fault_cleanup(object, first_m);
			cur_thread->interruptible = interruptible_state;
			return(VM_FAULT_MEMORY_ERROR);
		}
		m = vm_page_lookup(object, offset);
#if TRACEFAULTPAGE
		dbgTrace(0xBEEF0004, (unsigned int) m, (unsigned int) object);	/* (TEST/DEBUG) */
#endif
		if (m != VM_PAGE_NULL) {
			/*
			 *	If the page was pre-paged as part of a
			 *	cluster, record the fact.
			 */
			if (m->clustered) {
				vm_pagein_cluster_used++;
				m->clustered = FALSE;
			}

			/*
			 *	If the page is being brought in,
			 *	wait for it and then retry.
			 *
			 *	A possible optimization: if the page
			 *	is known to be resident, we can ignore
			 *	pages that are absent (regardless of
			 *	whether they're busy).
			 */

			if (m->busy) {
#if TRACEFAULTPAGE
				dbgTrace(0xBEEF0005, (unsigned int) m, (unsigned int) 0);	/* (TEST/DEBUG) */
#endif
				PAGE_ASSERT_WAIT(m, interruptible);
				vm_object_unlock(object);
				XPR(XPR_VM_FAULT,
				    "vm_f_page: block busy obj 0x%X, offset 0x%X, page 0x%X\n",
					(integer_t)object, offset,
					(integer_t)m, 0, 0);
				counter(c_vm_fault_page_block_busy_kernel++);
				wait_result = thread_block((void (*)(void))0);

				vm_object_lock(object);
				if (wait_result != THREAD_AWAKENED) {
					vm_fault_cleanup(object, first_m);
					cur_thread->interruptible = interruptible_state;
					if (wait_result == THREAD_RESTART)
					  {
						return(VM_FAULT_RETRY);
					  }
					else
					  {
						return(VM_FAULT_INTERRUPTED);
					  }
				}
				continue;
			}

			/*
			 *	If the page is in error, give up now.
			 */

			if (m->error) {
#if TRACEFAULTPAGE
				dbgTrace(0xBEEF0006, (unsigned int) m, (unsigned int) error_code);	/* (TEST/DEBUG) */
#endif
				if (error_code)
					*error_code = m->page_error;
				VM_PAGE_FREE(m);
				vm_fault_cleanup(object, first_m);
				cur_thread->interruptible = interruptible_state;
				return(VM_FAULT_MEMORY_ERROR);
			}

			/*
			 *	If the pager wants us to restart
			 *	at the top of the chain,
			 *	typically because it has moved the
			 *	page to another pager, then do so.
			 */

			if (m->restart) {
#if TRACEFAULTPAGE
				dbgTrace(0xBEEF0007, (unsigned int) m, (unsigned int) 0);	/* (TEST/DEBUG) */
#endif
				VM_PAGE_FREE(m);
				vm_fault_cleanup(object, first_m);
				cur_thread->interruptible = interruptible_state;
				return(VM_FAULT_RETRY);
			}

			/*
			 *	If the page isn't busy, but is absent,
			 *	then it was deemed "unavailable".
			 */

			if (m->absent) {
				/*
				 * Remove the non-existent page (unless it's
				 * in the top object) and move on down to the
				 * next object (if there is one).
				 */
#if TRACEFAULTPAGE
				dbgTrace(0xBEEF0008, (unsigned int) m, (unsigned int) object->shadow);	/* (TEST/DEBUG) */
#endif

				next_object = object->shadow;
				if (next_object == VM_OBJECT_NULL) {
					vm_page_t real_m;

					assert(!must_be_resident);

					if (object->shadow_severed) {
						vm_fault_cleanup(
							object, first_m);
						cur_thread->interruptible = interruptible_state;
						return VM_FAULT_MEMORY_ERROR;
					}

					/*
					 * Absent page at bottom of shadow
					 * chain; zero fill the page we left
					 * busy in the first object, and flush
					 * the absent page.  But first we
					 * need to allocate a real page.
					 */
					if (VM_PAGE_THROTTLED() ||
					    (real_m = vm_page_grab()) == VM_PAGE_NULL) {
						vm_fault_cleanup(object, first_m);
						cur_thread->interruptible = interruptible_state;
						return(VM_FAULT_MEMORY_SHORTAGE);
					}

					XPR(XPR_VM_FAULT,
	      "vm_f_page: zero obj 0x%X, off 0x%X, page 0x%X, first_obj 0x%X\n",
						(integer_t)object, offset,
						(integer_t)m,
						(integer_t)first_object, 0);
					if (object != first_object) {
						VM_PAGE_FREE(m);
						vm_object_paging_end(object);
						vm_object_unlock(object);
						object = first_object;
						offset = first_offset;
						m = first_m;
						first_m = VM_PAGE_NULL;
						vm_object_lock(object);
					}

					VM_PAGE_FREE(m);
					assert(real_m->busy);
					vm_page_insert(real_m, object, offset);
					m = real_m;

					/*
					 *  Drop the lock while zero filling
					 *  page.  Then break because this
					 *  is the page we wanted.  Checking
					 *  the page lock is a waste of time;
					 *  this page was either absent or
					 *  newly allocated -- in both cases
					 *  it can't be page locked by a pager.
					 */
					m->no_isync = FALSE;

					if (!no_zero_fill) {
						vm_object_unlock(object);
						vm_page_zero_fill(m);
						if (type_of_fault)
						        *type_of_fault = DBG_ZERO_FILL_FAULT;
						VM_STAT(zero_fill_count++);

						if (bumped_pagein == TRUE) {
						        VM_STAT(pageins--);
							current_task()->pageins--;
    						}
						vm_object_lock(object);
					}
					pmap_clear_modify(m->phys_addr);
					vm_page_lock_queues();
					VM_PAGE_QUEUES_REMOVE(m);
					m->page_ticket = vm_page_ticket;
					vm_page_ticket_roll++;
					if(vm_page_ticket_roll == 
						VM_PAGE_TICKETS_IN_ROLL) {
						vm_page_ticket_roll = 0;
						if(vm_page_ticket == 
						     VM_PAGE_TICKET_ROLL_IDS)
							vm_page_ticket= 0;
						else
							vm_page_ticket++;
					}
					queue_enter(&vm_page_queue_inactive, 
							m, vm_page_t, pageq);
					m->inactive = TRUE;
					vm_page_inactive_count++;
					vm_page_unlock_queues();
					break;
				} else {
					if (must_be_resident) {
						vm_object_paging_end(object);
					} else if (object != first_object) {
						vm_object_paging_end(object);
						VM_PAGE_FREE(m);
					} else {
						first_m = m;
						m->absent = FALSE;
						m->unusual = FALSE;
						vm_object_absent_release(object);
						m->busy = TRUE;

						vm_page_lock_queues();
						VM_PAGE_QUEUES_REMOVE(m);
						vm_page_unlock_queues();
					}
					XPR(XPR_VM_FAULT,
					    "vm_f_page: unavail obj 0x%X, off 0x%X, next_obj 0x%X, newoff 0x%X\n",
						(integer_t)object, offset,
						(integer_t)next_object,
						offset+object->shadow_offset,0);
					offset += object->shadow_offset;
					hi_offset += object->shadow_offset;
					lo_offset += object->shadow_offset;
					access_required = VM_PROT_READ;
					vm_object_lock(next_object);
					vm_object_unlock(object);
					object = next_object;
					vm_object_paging_begin(object);
					continue;
				}
			}

			if ((m->cleaning)
				&& ((object != first_object) ||
				    (object->copy != VM_OBJECT_NULL))
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
				dbgTrace(0xBEEF0009, (unsigned int) m, (unsigned int) offset);	/* (TEST/DEBUG) */
#endif
				XPR(XPR_VM_FAULT,
				    "vm_f_page: cleaning obj 0x%X, offset 0x%X, page 0x%X\n",
					(integer_t)object, offset,
					(integer_t)m, 0, 0);
				/* take an extra ref so that object won't die */
				assert(object->ref_count > 0);
				object->ref_count++;
				vm_object_res_reference(object);
				vm_fault_cleanup(object, first_m);
				counter(c_vm_fault_page_block_backoff_kernel++);
				vm_object_lock(object);
				assert(object->ref_count > 0);
				m = vm_page_lookup(object, offset);
				if (m != VM_PAGE_NULL && m->cleaning) {
					PAGE_ASSERT_WAIT(m, interruptible);
					vm_object_unlock(object);
					wait_result = thread_block((void (*)(void)) 0);
					vm_object_deallocate(object);
					goto backoff;
				} else {
					vm_object_unlock(object);
					vm_object_deallocate(object);
					cur_thread->interruptible = interruptible_state;
					return VM_FAULT_RETRY;
				}
			}

			/*
			 *	If the desired access to this page has
			 *	been locked out, request that it be unlocked.
			 */

			if (access_required & m->page_lock) {
				if ((access_required & m->unlock_request) != access_required) {
					vm_prot_t	new_unlock_request;
					kern_return_t	rc;
					
#if TRACEFAULTPAGE
					dbgTrace(0xBEEF000A, (unsigned int) m, (unsigned int) object->pager_ready);	/* (TEST/DEBUG) */
#endif
					if (!object->pager_ready) {
					XPR(XPR_VM_FAULT,
					    "vm_f_page: ready wait acc_req %d, obj 0x%X, offset 0x%X, page 0x%X\n",
						access_required,
						(integer_t)object, offset,
						(integer_t)m, 0);
						/* take an extra ref */
						assert(object->ref_count > 0);
						object->ref_count++;
						vm_object_res_reference(object);
						vm_fault_cleanup(object,
								 first_m);
						counter(c_vm_fault_page_block_backoff_kernel++);
						vm_object_lock(object);
						assert(object->ref_count > 0);
						if (!object->pager_ready) {
							vm_object_assert_wait(
								object,
								VM_OBJECT_EVENT_PAGER_READY,
								interruptible);
							vm_object_unlock(object);
							wait_result = thread_block((void (*)(void))0);
							vm_object_deallocate(object);
							goto backoff;
						} else {
							vm_object_unlock(object);
							vm_object_deallocate(object);
							cur_thread->interruptible = interruptible_state;
							return VM_FAULT_RETRY;
						}
					}

					new_unlock_request = m->unlock_request =
						(access_required | m->unlock_request);
					vm_object_unlock(object);
					XPR(XPR_VM_FAULT,
					    "vm_f_page: unlock obj 0x%X, offset 0x%X, page 0x%X, unl_req %d\n",
					(integer_t)object, offset,
					(integer_t)m, new_unlock_request, 0);
					if ((rc = memory_object_data_unlock(
						object->pager,
						offset + object->paging_offset,
						PAGE_SIZE,
						new_unlock_request))
					     != KERN_SUCCESS) {
						if (vm_fault_debug)
					     	    printf("vm_fault: memory_object_data_unlock failed\n");
						vm_object_lock(object);
						vm_fault_cleanup(object, first_m);
						cur_thread->interruptible = interruptible_state;
						return((rc == MACH_SEND_INTERRUPTED) ?
							VM_FAULT_INTERRUPTED :
							VM_FAULT_MEMORY_ERROR);
					}
					vm_object_lock(object);
					continue;
				}

				XPR(XPR_VM_FAULT,
	"vm_f_page: access wait acc_req %d, obj 0x%X, offset 0x%X, page 0x%X\n",
					access_required, (integer_t)object,
					offset, (integer_t)m, 0);
				/* take an extra ref so object won't die */
				assert(object->ref_count > 0);
				object->ref_count++;
				vm_object_res_reference(object);
				vm_fault_cleanup(object, first_m);
				counter(c_vm_fault_page_block_backoff_kernel++);
				vm_object_lock(object);
				assert(object->ref_count > 0);
				m = vm_page_lookup(object, offset);
				if (m != VM_PAGE_NULL && 
				    (access_required & m->page_lock) &&
				    !((access_required & m->unlock_request) != access_required)) {
					PAGE_ASSERT_WAIT(m, interruptible);
					vm_object_unlock(object);
					wait_result = thread_block((void (*)(void)) 0);
					vm_object_deallocate(object);
					goto backoff;
				} else {
					vm_object_unlock(object);
					vm_object_deallocate(object);
					cur_thread->interruptible = interruptible_state;
					return VM_FAULT_RETRY;
				}
			}
			/*
			 *	We mark the page busy and leave it on
			 *	the pageout queues.  If the pageout
			 *	deamon comes across it, then it will
			 *	remove the page.
			 */

#if TRACEFAULTPAGE
			dbgTrace(0xBEEF000B, (unsigned int) m, (unsigned int) 0);	/* (TEST/DEBUG) */
#endif

#if	!VM_FAULT_STATIC_CONFIG
			if (!software_reference_bits) {
				vm_page_lock_queues();
				if (m->inactive)
					vm_stat.reactivations++;

				VM_PAGE_QUEUES_REMOVE(m);
				vm_page_unlock_queues();
			}
#endif
			XPR(XPR_VM_FAULT,
			    "vm_f_page: found page obj 0x%X, offset 0x%X, page 0x%X\n",
				(integer_t)object, offset, (integer_t)m, 0, 0);
			assert(!m->busy);
			m->busy = TRUE;
			assert(!m->absent);
			break;
		}

		look_for_page =
			(object->pager_created) &&
			  LOOK_FOR(object, offset) &&
			    (!data_supply);

#if TRACEFAULTPAGE
		dbgTrace(0xBEEF000C, (unsigned int) look_for_page, (unsigned int) object);	/* (TEST/DEBUG) */
#endif
		if ((look_for_page || (object == first_object))
			 	&& !must_be_resident 
				&& !(object->phys_contiguous))  {
			/*
			 *	Allocate a new page for this object/offset
			 *	pair.
			 */

			m = vm_page_grab_fictitious();
#if TRACEFAULTPAGE
			dbgTrace(0xBEEF000D, (unsigned int) m, (unsigned int) object);	/* (TEST/DEBUG) */
#endif
			if (m == VM_PAGE_NULL) {
				vm_fault_cleanup(object, first_m);
				cur_thread->interruptible = interruptible_state;
				return(VM_FAULT_FICTITIOUS_SHORTAGE);
			}
			vm_page_insert(m, object, offset);
		}

		if ((look_for_page && !must_be_resident)) {
			kern_return_t	rc;

			/*
			 *	If the memory manager is not ready, we
			 *	cannot make requests.
			 */
			if (!object->pager_ready) {
#if TRACEFAULTPAGE
				dbgTrace(0xBEEF000E, (unsigned int) 0, (unsigned int) 0);	/* (TEST/DEBUG) */
#endif
				if(m != VM_PAGE_NULL)
					VM_PAGE_FREE(m);
				XPR(XPR_VM_FAULT,
				"vm_f_page: ready wait obj 0x%X, offset 0x%X\n",
					(integer_t)object, offset, 0, 0, 0);
				/* take an extra ref so object won't die */
				assert(object->ref_count > 0);
				object->ref_count++;
				vm_object_res_reference(object);
				vm_fault_cleanup(object, first_m);
				counter(c_vm_fault_page_block_backoff_kernel++);
				vm_object_lock(object);
				assert(object->ref_count > 0);
				if (!object->pager_ready) {
					vm_object_assert_wait(object,
							      VM_OBJECT_EVENT_PAGER_READY,
							      interruptible);
					vm_object_unlock(object);
					wait_result = thread_block((void (*)(void))0);
					vm_object_deallocate(object);
					goto backoff;
				} else {
					vm_object_unlock(object);
					vm_object_deallocate(object);
					cur_thread->interruptible = interruptible_state;
					return VM_FAULT_RETRY;
				}
			}

			if(object->phys_contiguous) {
				if(m != VM_PAGE_NULL) {
					VM_PAGE_FREE(m);
					m = VM_PAGE_NULL;
				}
				goto no_clustering;
			}
			if (object->internal) {
				/*
				 *	Requests to the default pager
				 *	must reserve a real page in advance,
				 *	because the pager's data-provided
				 *	won't block for pages.  IMPORTANT:
				 *	this acts as a throttling mechanism
				 *	for data_requests to the default
				 *	pager.
				 */

#if TRACEFAULTPAGE
				dbgTrace(0xBEEF000F, (unsigned int) m, (unsigned int) 0);	/* (TEST/DEBUG) */
#endif
				if (m->fictitious && !vm_page_convert(m)) {
					VM_PAGE_FREE(m);
					vm_fault_cleanup(object, first_m);
					cur_thread->interruptible = interruptible_state;
					return(VM_FAULT_MEMORY_SHORTAGE);
				}
			} else if (object->absent_count >
						vm_object_absent_max) {
				/*
				 *	If there are too many outstanding page
				 *	requests pending on this object, we
				 *	wait for them to be resolved now.
				 */

#if TRACEFAULTPAGE
				dbgTrace(0xBEEF0010, (unsigned int) m, (unsigned int) 0);	/* (TEST/DEBUG) */
#endif
				if(m != VM_PAGE_NULL)
					VM_PAGE_FREE(m);
				/* take an extra ref so object won't die */
				assert(object->ref_count > 0);
				object->ref_count++;
				vm_object_res_reference(object);
				vm_fault_cleanup(object, first_m);
				counter(c_vm_fault_page_block_backoff_kernel++);
				vm_object_lock(object);
				assert(object->ref_count > 0);
				if (object->absent_count > vm_object_absent_max) {
					vm_object_absent_assert_wait(object,
								     interruptible);
					vm_object_unlock(object);
					wait_result = thread_block((void (*)(void))0);
					vm_object_deallocate(object);
					goto backoff;
				} else {
					vm_object_unlock(object);
					vm_object_deallocate(object);
					cur_thread->interruptible = interruptible_state;
					return VM_FAULT_RETRY;
				}
			}

			/*
			 *	Indicate that the page is waiting for data
			 *	from the memory manager.
			 */

			if(m != VM_PAGE_NULL) {

				m->list_req_pending = TRUE;
				m->absent = TRUE;
				m->unusual = TRUE;
				object->absent_count++;

			}

			cluster_start = offset;
			length = PAGE_SIZE;
			cluster_size = object->cluster_size;

			/*
			 * Skip clustered pagein if it is globally disabled 
			 * or random page reference behavior is expected
			 * for the address range containing the faulting 
			 * address or the object paging block size is
			 * equal to the page size.
			 */
			if (!vm_allow_clustered_pagein ||
			     behavior == VM_BEHAVIOR_RANDOM ||
			     m == VM_PAGE_NULL ||
			     cluster_size == PAGE_SIZE) {
				cluster_start = trunc_page_64(cluster_start);
				goto no_clustering;
			}

			assert(offset >= lo_offset);
			assert(offset < hi_offset);
			assert(ALIGNED(object->paging_offset));
			assert(cluster_size >= PAGE_SIZE);

#if TRACEFAULTPAGE
			dbgTrace(0xBEEF0011, (unsigned int) m, (unsigned int) 0);	/* (TEST/DEBUG) */
#endif
			/*
			 * Decide whether to scan ahead or behind for
			 * additional pages contiguous to the faulted
			 * page in the same paging block.  The decision
			 * is based on system wide globals and the
			 * expected page reference behavior of the
			 * address range contained the faulting address.
			 * First calculate some constants.
			 */
			paging_offset = offset + object->paging_offset;
			cluster_offset = paging_offset & (cluster_size - 1);
			align_offset = paging_offset&(PAGE_SIZE_64-1);
			if (align_offset != 0) {
				cluster_offset = trunc_page_64(cluster_offset);
			}

#define SPANS_CLUSTER(x) ((((x) - align_offset) & (vm_object_offset_t)(cluster_size - 1)) == 0)

			/*
			 * Backward scan only if reverse sequential
			 * behavior has been specified
			 */
			CLUSTER_STAT(pages_at_lower_offsets = 0;)
			if (((vm_default_behind != 0 && 
			     behavior == VM_BEHAVIOR_DEFAULT) ||
			     behavior == VM_BEHAVIOR_RSEQNTL) && offset) {
			    vm_object_offset_t cluster_bot;

			    /*
			     * Calculate lower search boundary.
			     * Exclude pages that span a cluster boundary.
			     * Clip to start of map entry.
			     * For default page reference behavior, scan
			     * default pages behind.
			     */
			    cluster_bot = (offset > cluster_offset) ?
					    offset - cluster_offset : offset;
			    if (align_offset != 0) {
				if ((cluster_bot < offset) &&
				    SPANS_CLUSTER(cluster_bot)) {
					cluster_bot += PAGE_SIZE_64;
				}
			    }
			    if (behavior == VM_BEHAVIOR_DEFAULT) {
				vm_object_offset_t 
					bot = (vm_object_offset_t)
						(vm_default_behind * PAGE_SIZE);

				if (cluster_bot < (offset - bot))
					cluster_bot = offset - bot;
			    }
			    if (lo_offset > cluster_bot)
				cluster_bot = lo_offset;

			    for ( cluster_start = offset - PAGE_SIZE_64;
				 (cluster_start >= cluster_bot) &&
				 (cluster_start != 
					(align_offset - PAGE_SIZE_64));
				  cluster_start -= PAGE_SIZE_64) {
				assert(cluster_size > PAGE_SIZE_64);
retry_cluster_backw:
				if (!LOOK_FOR(object, cluster_start) ||
				    vm_page_lookup(object, cluster_start)
						!= VM_PAGE_NULL) {
					break;
				}
				if (object->internal) {
					/*
					 * need to acquire a real page in
					 * advance because this acts as
					 * a throttling mechanism for
					 * data_requests to the default
					 * pager.  If this fails, give up
					 * trying to find any more pages
					 * in the cluster and send off the
					 * request for what we already have.
					 */
					if ((m = vm_page_grab())
							== VM_PAGE_NULL) {
					    cluster_start += PAGE_SIZE_64;
					    cluster_end = offset + PAGE_SIZE_64;
					    goto give_up;
					}
				} else if ((m = vm_page_grab_fictitious())
						== VM_PAGE_NULL) {
					vm_object_unlock(object);
					vm_page_more_fictitious();
					vm_object_lock(object);
					goto retry_cluster_backw;
				}
				m->absent = TRUE;
				m->unusual = TRUE;
				m->clustered = TRUE;
				m->list_req_pending = TRUE;

				vm_page_insert(m, object, cluster_start);
				CLUSTER_STAT(pages_at_lower_offsets++;)
			        object->absent_count++;
			    }
			    cluster_start += PAGE_SIZE_64;
			    assert(cluster_start >= cluster_bot);
			}
			assert(cluster_start <= offset);

			/*
			 * Forward scan if default or sequential behavior
			 * specified
			 */
		       	CLUSTER_STAT(pages_at_higher_offsets = 0;)
			if ((behavior == VM_BEHAVIOR_DEFAULT && 
			     vm_default_ahead != 0) ||
			     behavior == VM_BEHAVIOR_SEQUENTIAL) {
			    vm_object_offset_t cluster_top;

			    /*
			     * Calculate upper search boundary.
			     * Exclude pages that span a cluster boundary.
			     * Clip to end of map entry.
			     * For default page reference behavior, scan
			     * default pages ahead.
			     */
			    cluster_top = (offset + cluster_size) - 
					  cluster_offset;
			    if (align_offset != 0) {
				if ((cluster_top > (offset + PAGE_SIZE_64)) &&
				    SPANS_CLUSTER(cluster_top)) {
					cluster_top -= PAGE_SIZE_64;
				}
			    }
			    if (behavior == VM_BEHAVIOR_DEFAULT) {
				vm_object_offset_t top = (vm_object_offset_t)
				     ((vm_default_ahead*PAGE_SIZE)+PAGE_SIZE);

				if (cluster_top > (offset + top))
					cluster_top =  offset + top;
			    }
			    if (cluster_top > hi_offset)
					cluster_top = hi_offset;

			    for (cluster_end = offset + PAGE_SIZE_64;
				 cluster_end < cluster_top;
				 cluster_end += PAGE_SIZE_64) {
			        assert(cluster_size > PAGE_SIZE);
retry_cluster_forw:
			        if (!LOOK_FOR(object, cluster_end) ||
				    vm_page_lookup(object, cluster_end)
						!= VM_PAGE_NULL) {
					break;
				}
				if (object->internal) {
					/*
					 * need to acquire a real page in
					 * advance because this acts as
					 * a throttling mechanism for
					 * data_requests to the default
					 * pager.  If this fails, give up
					 * trying to find any more pages
					 * in the cluster and send off the
					 * request for what we already have.
					 */
					if ((m = vm_page_grab())
							== VM_PAGE_NULL) {
					    break;
					}
			        } else if ((m = vm_page_grab_fictitious())
				       	        == VM_PAGE_NULL) {
				    vm_object_unlock(object);
				    vm_page_more_fictitious();
				    vm_object_lock(object);
				    goto retry_cluster_forw;
			        }
			        m->absent = TRUE;
				m->unusual = TRUE;
			        m->clustered = TRUE;
				m->list_req_pending = TRUE;

			        vm_page_insert(m, object, cluster_end);
				CLUSTER_STAT(pages_at_higher_offsets++;)
				object->absent_count++;
			    }
			    assert(cluster_end <= cluster_top);
			}
			else {
				cluster_end = offset + PAGE_SIZE_64;
			}
give_up:
			assert(cluster_end >= offset + PAGE_SIZE_64);
			length = cluster_end - cluster_start;

#if	MACH_CLUSTER_STATS
			CLUSTER_STAT_HIGHER(pages_at_higher_offsets);
			CLUSTER_STAT_LOWER(pages_at_lower_offsets);
			CLUSTER_STAT_CLUSTER(length/PAGE_SIZE);
#endif	/* MACH_CLUSTER_STATS */

no_clustering:
			/* 
			 * lengthen the cluster by the pages in the working set
			 */
			if((map != NULL) && 
				(current_task()->dynamic_working_set != 0)) {
				cluster_end = cluster_start + length;
				/* tws values for start and end are just a 
				 * suggestions.  Therefore, as long as
				 * build_cluster does not use pointers or
				 * take action based on values that
				 * could be affected by re-entrance we
				 * do not need to take the map lock.
				 */
				tws_build_cluster((tws_hash_t)
					current_task()->dynamic_working_set,
					object, &cluster_start,
					&cluster_end, 0x16000);
				length = cluster_end - cluster_start;
			}
#if TRACEFAULTPAGE
			dbgTrace(0xBEEF0012, (unsigned int) object, (unsigned int) 0);	/* (TEST/DEBUG) */
#endif
			/*
			 *	We have a busy page, so we can
			 *	release the object lock.
			 */
			vm_object_unlock(object);

			/*
			 *	Call the memory manager to retrieve the data.
			 */

			if (type_of_fault)
			        *type_of_fault = DBG_PAGEIN_FAULT;
			VM_STAT(pageins++);
			current_task()->pageins++;
			bumped_pagein = TRUE;

			/*
			 *	If this object uses a copy_call strategy,
			 *	and we are interested in a copy of this object
			 *	(having gotten here only by following a
			 *	shadow chain), then tell the memory manager
			 *	via a flag added to the desired_access
			 *	parameter, so that it can detect a race
			 *	between our walking down the shadow chain
			 *	and its pushing pages up into a copy of
			 *	the object that it manages.
			 */

			if (object->copy_strategy == MEMORY_OBJECT_COPY_CALL &&
			    object != first_object) {
				wants_copy_flag = VM_PROT_WANTS_COPY;
			} else {
				wants_copy_flag = VM_PROT_NONE;
			}

			XPR(XPR_VM_FAULT,
			    "vm_f_page: data_req obj 0x%X, offset 0x%X, page 0x%X, acc %d\n",
				(integer_t)object, offset, (integer_t)m,
				access_required | wants_copy_flag, 0);

			rc = memory_object_data_request(object->pager, 
					cluster_start +	object->paging_offset, 
					length,
					access_required | wants_copy_flag);


#if TRACEFAULTPAGE
			dbgTrace(0xBEEF0013, (unsigned int) object, (unsigned int) rc);	/* (TEST/DEBUG) */
#endif
			if (rc != KERN_SUCCESS) {
				if (rc != MACH_SEND_INTERRUPTED
				    && vm_fault_debug)
					printf("%s(0x%x, 0x%x, 0x%x, 0x%x) failed, rc=%d\n",
						"memory_object_data_request",
						object->pager,
						cluster_start + object->paging_offset, 
						length, access_required, rc);
				/*
				 *	Don't want to leave a busy page around,
				 *	but the data request may have blocked,
				 *	so check if it's still there and busy.
				 */
				if(!object->phys_contiguous) {
				   vm_object_lock(object);
				   for (; length; length -= PAGE_SIZE,
				      cluster_start += PAGE_SIZE_64) {
				      vm_page_t p;
				      if ((p = vm_page_lookup(object,
								cluster_start))
				            && p->absent && p->busy
				            && p != first_m) {
				         VM_PAGE_FREE(p);
				      }
				   }
				}
				vm_fault_cleanup(object, first_m);
				cur_thread->interruptible = interruptible_state;
				return((rc == MACH_SEND_INTERRUPTED) ?
					VM_FAULT_INTERRUPTED :
					VM_FAULT_MEMORY_ERROR);
			} else {
#ifdef notdefcdy
				tws_hash_line_t	line;
				task_t		task;

		   		task = current_task();
				
		   		if((map != NULL) && 
					(task->dynamic_working_set != 0)) {
					if(tws_lookup
						((tws_hash_t)
						task->dynamic_working_set,
						offset, object,
						&line) == KERN_SUCCESS) {
						tws_line_signal((tws_hash_t)
						task->dynamic_working_set, 
							map, line, vaddr);
					}
				}
#endif
			}
			
			/*
			 * Retry with same object/offset, since new data may
			 * be in a different page (i.e., m is meaningless at
			 * this point).
			 */
			vm_object_lock(object);
			if ((interruptible != THREAD_UNINT) && 
			    (current_thread()->state & TH_ABORT)) {
				vm_fault_cleanup(object, first_m);
				cur_thread->interruptible = interruptible_state;
				return(VM_FAULT_INTERRUPTED);
			}
			if(m == VM_PAGE_NULL)
				break;
			continue;
		}

		/*
		 * The only case in which we get here is if
		 * object has no pager (or unwiring).  If the pager doesn't
		 * have the page this is handled in the m->absent case above
		 * (and if you change things here you should look above).
		 */
#if TRACEFAULTPAGE
		dbgTrace(0xBEEF0014, (unsigned int) object, (unsigned int) m);	/* (TEST/DEBUG) */
#endif
		if (object == first_object)
			first_m = m;
		else
			assert(m == VM_PAGE_NULL);

		XPR(XPR_VM_FAULT,
		    "vm_f_page: no pager obj 0x%X, offset 0x%X, page 0x%X, next_obj 0x%X\n",
			(integer_t)object, offset, (integer_t)m,
			(integer_t)object->shadow, 0);
		/*
		 *	Move on to the next object.  Lock the next
		 *	object before unlocking the current one.
		 */
		next_object = object->shadow;
		if (next_object == VM_OBJECT_NULL) {
			assert(!must_be_resident);
			/*
			 *	If there's no object left, fill the page
			 *	in the top object with zeros.  But first we
			 *	need to allocate a real page.
			 */

			if (object != first_object) {
				vm_object_paging_end(object);
				vm_object_unlock(object);

				object = first_object;
				offset = first_offset;
				vm_object_lock(object);
			}

			m = first_m;
			assert(m->object == object);
			first_m = VM_PAGE_NULL;

			if (object->shadow_severed) {
				VM_PAGE_FREE(m);
				vm_fault_cleanup(object, VM_PAGE_NULL);
				cur_thread->interruptible = interruptible_state;
				return VM_FAULT_MEMORY_ERROR;
			}

			if (VM_PAGE_THROTTLED() ||
			    (m->fictitious && !vm_page_convert(m))) {
				VM_PAGE_FREE(m);
				vm_fault_cleanup(object, VM_PAGE_NULL);
				cur_thread->interruptible = interruptible_state;
				return(VM_FAULT_MEMORY_SHORTAGE);
			}
			m->no_isync = FALSE;

			if (!no_zero_fill) {
				vm_object_unlock(object);
				vm_page_zero_fill(m);
				if (type_of_fault)
				        *type_of_fault = DBG_ZERO_FILL_FAULT;
				VM_STAT(zero_fill_count++);

				if (bumped_pagein == TRUE) {
				        VM_STAT(pageins--);
					current_task()->pageins--;
				}
				vm_object_lock(object);
			}
			vm_page_lock_queues();
			VM_PAGE_QUEUES_REMOVE(m);
			m->page_ticket = vm_page_ticket;
			vm_page_ticket_roll++;
			if(vm_page_ticket_roll == VM_PAGE_TICKETS_IN_ROLL) {
				vm_page_ticket_roll = 0;
				if(vm_page_ticket == 
					VM_PAGE_TICKET_ROLL_IDS)
					vm_page_ticket= 0;
				else
					vm_page_ticket++;
			}
			queue_enter(&vm_page_queue_inactive, 
						m, vm_page_t, pageq);
			m->inactive = TRUE;
			vm_page_inactive_count++;
			vm_page_unlock_queues();
			pmap_clear_modify(m->phys_addr);
			break;
		}
		else {
			if ((object != first_object) || must_be_resident)
				vm_object_paging_end(object);
			offset += object->shadow_offset;
			hi_offset += object->shadow_offset;
			lo_offset += object->shadow_offset;
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
	dbgTrace(0xBEEF0015, (unsigned int) object, (unsigned int) m);	/* (TEST/DEBUG) */
#endif
#if	EXTRA_ASSERTIONS
	if(m != VM_PAGE_NULL) {
		assert(m->busy && !m->absent);
		assert((first_m == VM_PAGE_NULL) ||
			(first_m->busy && !first_m->absent &&
			 !first_m->active && !first_m->inactive));
	}
#endif	/* EXTRA_ASSERTIONS */

	XPR(XPR_VM_FAULT,
       "vm_f_page: FOUND obj 0x%X, off 0x%X, page 0x%X, 1_obj 0x%X, 1_m 0x%X\n",
		(integer_t)object, offset, (integer_t)m,
		(integer_t)first_object, (integer_t)first_m);
	/*
	 *	If the page is being written, but isn't
	 *	already owned by the top-level object,
	 *	we have to copy it into a new page owned
	 *	by the top-level object.
	 */

	if ((object != first_object) && (m != VM_PAGE_NULL)) {
	    	/*
		 *	We only really need to copy if we
		 *	want to write it.
		 */

#if TRACEFAULTPAGE
			dbgTrace(0xBEEF0016, (unsigned int) object, (unsigned int) fault_type);	/* (TEST/DEBUG) */
#endif
	    	if (fault_type & VM_PROT_WRITE) {
			vm_page_t copy_m;

			assert(!must_be_resident);

			/*
			 *	If we try to collapse first_object at this
			 *	point, we may deadlock when we try to get
			 *	the lock on an intermediate object (since we
			 *	have the bottom object locked).  We can't
			 *	unlock the bottom object, because the page
			 *	we found may move (by collapse) if we do.
			 *
			 *	Instead, we first copy the page.  Then, when
			 *	we have no more use for the bottom object,
			 *	we unlock it and try to collapse.
			 *
			 *	Note that we copy the page even if we didn't
			 *	need to... that's the breaks.
			 */

			/*
			 *	Allocate a page for the copy
			 */
			copy_m = vm_page_grab();
			if (copy_m == VM_PAGE_NULL) {
				RELEASE_PAGE(m);
				vm_fault_cleanup(object, first_m);
				cur_thread->interruptible = interruptible_state;
				return(VM_FAULT_MEMORY_SHORTAGE);
			}


			XPR(XPR_VM_FAULT,
			    "vm_f_page: page_copy obj 0x%X, offset 0x%X, m 0x%X, copy_m 0x%X\n",
				(integer_t)object, offset,
				(integer_t)m, (integer_t)copy_m, 0);
			vm_page_copy(m, copy_m);

			/*
			 *	If another map is truly sharing this
			 *	page with us, we have to flush all
			 *	uses of the original page, since we
			 *	can't distinguish those which want the
			 *	original from those which need the
			 *	new copy.
			 *
			 *	XXXO If we know that only one map has
			 *	access to this page, then we could
			 *	avoid the pmap_page_protect() call.
			 */

			vm_page_lock_queues();
			assert(!m->cleaning);
			pmap_page_protect(m->phys_addr, VM_PROT_NONE);
			vm_page_deactivate(m);
			copy_m->dirty = TRUE;
			/*
			 * Setting reference here prevents this fault from
			 * being counted as a (per-thread) reactivate as well
			 * as a copy-on-write.
			 */
			first_m->reference = TRUE;
			vm_page_unlock_queues();

			/*
			 *	We no longer need the old page or object.
			 */

			PAGE_WAKEUP_DONE(m);
			vm_object_paging_end(object);
			vm_object_unlock(object);

			if (type_of_fault)
			        *type_of_fault = DBG_COW_FAULT;
			VM_STAT(cow_faults++);
			current_task()->cow_faults++;
			object = first_object;
			offset = first_offset;

			vm_object_lock(object);
			VM_PAGE_FREE(first_m);
			first_m = VM_PAGE_NULL;
			assert(copy_m->busy);
			vm_page_insert(copy_m, object, offset);
			m = copy_m;

			/*
			 *      Now that we've gotten the copy out of the
			 *      way, let's try to collapse the top object.
			 *      But we have to play ugly games with
			 *      paging_in_progress to do that...
			 */     

			vm_object_paging_end(object); 
			vm_object_collapse(object);
			vm_object_paging_begin(object);

		}
		else {
		    	*protection &= (~VM_PROT_WRITE);
		}
	}

	/*
	 *	Now check whether the page needs to be pushed into the
	 *	copy object.  The use of asymmetric copy on write for
	 *	shared temporary objects means that we may do two copies to
	 *	satisfy the fault; one above to get the page from a
	 *	shadowed object, and one here to push it into the copy.
	 */

	while (first_object->copy_strategy == MEMORY_OBJECT_COPY_DELAY &&
	       (copy_object = first_object->copy) != VM_OBJECT_NULL &&
		   (m!= VM_PAGE_NULL)) {
		vm_object_offset_t	copy_offset;
		vm_page_t		copy_m;

#if TRACEFAULTPAGE
		dbgTrace(0xBEEF0017, (unsigned int) copy_object, (unsigned int) fault_type);	/* (TEST/DEBUG) */
#endif
		/*
		 *	If the page is being written, but hasn't been
		 *	copied to the copy-object, we have to copy it there.
		 */

		if ((fault_type & VM_PROT_WRITE) == 0) {
			*protection &= ~VM_PROT_WRITE;
			break;
		}

		/*
		 *	If the page was guaranteed to be resident,
		 *	we must have already performed the copy.
		 */

		if (must_be_resident)
			break;

		/*
		 *	Try to get the lock on the copy_object.
		 */
		if (!vm_object_lock_try(copy_object)) {
			vm_object_unlock(object);

			mutex_pause();	/* wait a bit */

			vm_object_lock(object);
			continue;
		}

		/*
		 *	Make another reference to the copy-object,
		 *	to keep it from disappearing during the
		 *	copy.
		 */
		assert(copy_object->ref_count > 0);
		copy_object->ref_count++;
		VM_OBJ_RES_INCR(copy_object);

		/*
		 *	Does the page exist in the copy?
		 */
		copy_offset = first_offset - copy_object->shadow_offset;
		if (copy_object->size <= copy_offset)
			/*
			 * Copy object doesn't cover this page -- do nothing.
			 */
			;
		else if ((copy_m =
			vm_page_lookup(copy_object, copy_offset)) != VM_PAGE_NULL) {
			/* Page currently exists in the copy object */
			if (copy_m->busy) {
				/*
				 *	If the page is being brought
				 *	in, wait for it and then retry.
				 */
				RELEASE_PAGE(m);
				/* take an extra ref so object won't die */
				assert(copy_object->ref_count > 0);
				copy_object->ref_count++;
				vm_object_res_reference(copy_object);
				vm_object_unlock(copy_object);
				vm_fault_cleanup(object, first_m);
				counter(c_vm_fault_page_block_backoff_kernel++);
				vm_object_lock(copy_object);
				assert(copy_object->ref_count > 0);
				VM_OBJ_RES_DECR(copy_object);
				copy_object->ref_count--;
				assert(copy_object->ref_count > 0);
				copy_m = vm_page_lookup(copy_object, copy_offset);
				if (copy_m != VM_PAGE_NULL && copy_m->busy) {
					PAGE_ASSERT_WAIT(copy_m, interruptible);
					vm_object_unlock(copy_object);
					wait_result = thread_block((void (*)(void))0);
					vm_object_deallocate(copy_object);
					goto backoff;
				} else {
					vm_object_unlock(copy_object);
					vm_object_deallocate(copy_object);
					cur_thread->interruptible = interruptible_state;
					return VM_FAULT_RETRY;
				}
			}
		}
		else if (!PAGED_OUT(copy_object, copy_offset)) {
			/*
			 * If PAGED_OUT is TRUE, then the page used to exist
			 * in the copy-object, and has already been paged out.
			 * We don't need to repeat this. If PAGED_OUT is
			 * FALSE, then either we don't know (!pager_created,
			 * for example) or it hasn't been paged out.
			 * (VM_EXTERNAL_STATE_UNKNOWN||VM_EXTERNAL_STATE_ABSENT)
			 * We must copy the page to the copy object.
			 */

			/*
			 *	Allocate a page for the copy
			 */
			copy_m = vm_page_alloc(copy_object, copy_offset);
			if (copy_m == VM_PAGE_NULL) {
				RELEASE_PAGE(m);
				VM_OBJ_RES_DECR(copy_object);
				copy_object->ref_count--;
				assert(copy_object->ref_count > 0);
				vm_object_unlock(copy_object);
				vm_fault_cleanup(object, first_m);
				cur_thread->interruptible = interruptible_state;
				return(VM_FAULT_MEMORY_SHORTAGE);
			}

			/*
			 *	Must copy page into copy-object.
			 */

			vm_page_copy(m, copy_m);
			
			/*
			 *	If the old page was in use by any users
			 *	of the copy-object, it must be removed
			 *	from all pmaps.  (We can't know which
			 *	pmaps use it.)
			 */

			vm_page_lock_queues();
			assert(!m->cleaning);
			pmap_page_protect(m->phys_addr, VM_PROT_NONE);
			copy_m->dirty = TRUE;
			vm_page_unlock_queues();

			/*
			 *	If there's a pager, then immediately
			 *	page out this page, using the "initialize"
			 *	option.  Else, we use the copy.
			 */

		 	if 
#if	MACH_PAGEMAP
			  ((!copy_object->pager_created) ||
				vm_external_state_get(
					copy_object->existence_map, copy_offset)
				== VM_EXTERNAL_STATE_ABSENT)
#else
			  (!copy_object->pager_created)
#endif
				{
				vm_page_lock_queues();
				vm_page_activate(copy_m);
				vm_page_unlock_queues();
				PAGE_WAKEUP_DONE(copy_m);
			} 
			else {
				assert(copy_m->busy == TRUE);

				/*
				 *	The page is already ready for pageout:
				 *	not on pageout queues and busy.
				 *	Unlock everything except the
				 *	copy_object itself.
				 */

				vm_object_unlock(object);

				/*
				 *	Write the page to the copy-object,
				 *	flushing it from the kernel.
				 */

				vm_pageout_initialize_page(copy_m);

				/*
				 *	Since the pageout may have
				 *	temporarily dropped the
				 *	copy_object's lock, we
				 *	check whether we'll have
				 *	to deallocate the hard way.
				 */

				if ((copy_object->shadow != object) ||
				    (copy_object->ref_count == 1)) {
					vm_object_unlock(copy_object);
					vm_object_deallocate(copy_object);
					vm_object_lock(object);
					continue;
				}

				/*
				 *	Pick back up the old object's
				 *	lock.  [It is safe to do so,
				 *	since it must be deeper in the
				 *	object tree.]
				 */

				vm_object_lock(object);
			}

			/*
			 *	Because we're pushing a page upward
			 *	in the object tree, we must restart
			 *	any faults that are waiting here.
			 *	[Note that this is an expansion of
			 *	PAGE_WAKEUP that uses the THREAD_RESTART
			 *	wait result].  Can't turn off the page's
			 *	busy bit because we're not done with it.
			 */
			 
			if (m->wanted) {
				m->wanted = FALSE;
				thread_wakeup_with_result((event_t) m,
					THREAD_RESTART);
			}
		}

		/*
		 *	The reference count on copy_object must be
		 *	at least 2: one for our extra reference,
		 *	and at least one from the outside world
		 *	(we checked that when we last locked
		 *	copy_object).
		 */
		copy_object->ref_count--;
		assert(copy_object->ref_count > 0);
		VM_OBJ_RES_DECR(copy_object);	
		vm_object_unlock(copy_object);

		break;
	}

	*result_page = m;
	*top_page = first_m;

	XPR(XPR_VM_FAULT,
		"vm_f_page: DONE obj 0x%X, offset 0x%X, m 0x%X, first_m 0x%X\n",
		(integer_t)object, offset, (integer_t)m, (integer_t)first_m, 0);
	/*
	 *	If the page can be written, assume that it will be.
	 *	[Earlier, we restrict the permission to allow write
	 *	access only if the fault so required, so we don't
	 *	mark read-only data as dirty.]
	 */

#if	!VM_FAULT_STATIC_CONFIG
	if (vm_fault_dirty_handling && (*protection & VM_PROT_WRITE) && 
			(m != VM_PAGE_NULL)) {
		m->dirty = TRUE;
	}
#endif
#if TRACEFAULTPAGE
	dbgTrace(0xBEEF0018, (unsigned int) object, (unsigned int) vm_page_deactivate_behind);	/* (TEST/DEBUG) */
#endif
	if (vm_page_deactivate_behind) {
		if (offset && /* don't underflow */
			(object->last_alloc == (offset - PAGE_SIZE_64))) {
			m = vm_page_lookup(object, object->last_alloc);
			if ((m != VM_PAGE_NULL) && !m->busy) {
				vm_page_lock_queues();
				vm_page_deactivate(m);
				vm_page_unlock_queues();
			}
#if TRACEFAULTPAGE
			dbgTrace(0xBEEF0019, (unsigned int) object, (unsigned int) m);	/* (TEST/DEBUG) */
#endif
		}
		object->last_alloc = offset;
	}
#if TRACEFAULTPAGE
	dbgTrace(0xBEEF001A, (unsigned int) VM_FAULT_SUCCESS, 0);	/* (TEST/DEBUG) */
#endif
	cur_thread->interruptible = interruptible_state;
	if(*result_page == VM_PAGE_NULL) {
		vm_object_unlock(object);
	}
	return(VM_FAULT_SUCCESS);

#if 0
    block_and_backoff:
	vm_fault_cleanup(object, first_m);

	counter(c_vm_fault_page_block_backoff_kernel++);
	thread_block((void (*)(void))0);
#endif

    backoff:
	cur_thread->interruptible = interruptible_state;
	if (wait_result == THREAD_INTERRUPTED)
		return VM_FAULT_INTERRUPTED;
	return VM_FAULT_RETRY;

#undef	RELEASE_PAGE
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

kern_return_t
vm_fault(
	vm_map_t	map,
	vm_offset_t	vaddr,
	vm_prot_t	fault_type,
	boolean_t	change_wiring,
	int		interruptible)
{
	vm_map_version_t	version;	/* Map version for verificiation */
	boolean_t		wired;		/* Should mapping be wired down? */
	vm_object_t		object;		/* Top-level object */
	vm_object_offset_t	offset;		/* Top-level offset */
	vm_prot_t		prot;		/* Protection for mapping */
	vm_behavior_t		behavior;	/* Expected paging behavior */
	vm_object_offset_t	lo_offset, hi_offset;
	vm_object_t		old_copy_object; /* Saved copy object */
	vm_page_t		result_page;	/* Result of vm_fault_page */
	vm_page_t		top_page;	/* Placeholder page */
	kern_return_t		kr;

	register
	vm_page_t		m;	/* Fast access to result_page */
	kern_return_t		error_code;	/* page error reasons */
	register
	vm_object_t		cur_object;
	register
	vm_object_offset_t	cur_offset;
	vm_page_t		cur_m;
	vm_object_t		new_object;
	int                     type_of_fault;
	vm_map_t		pmap_map = map;
	vm_map_t		original_map = map;
	pmap_t			pmap = NULL;
	boolean_t		funnel_set = FALSE;
	funnel_t		*curflock;
	thread_t 		cur_thread;
	boolean_t		interruptible_state;
	

	KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, 0)) | DBG_FUNC_START,
			      vaddr,
			      0,
			      0,
			      0,
			      0);

	cur_thread = current_thread();

	interruptible_state = cur_thread->interruptible;
	if (interruptible == THREAD_UNINT)
		cur_thread->interruptible = FALSE;

	/*
	 * assume we will hit a page in the cache
	 * otherwise, explicitly override with
	 * the real fault type once we determine it
	 */
	type_of_fault = DBG_CACHE_HIT_FAULT;

	VM_STAT(faults++);
	current_task()->faults++;

	/*
	 * drop funnel if it is already held. Then restore while returning
	 */
	if ((cur_thread->funnel_state & TH_FN_OWNED) == TH_FN_OWNED) {
		funnel_set = TRUE;
		curflock = cur_thread->funnel_lock;
		thread_funnel_set( curflock , FALSE);
	}
         
    RetryFault: ;

	/*
	 *	Find the backing store object and offset into
	 *	it to begin the search.
	 */
	map = original_map;
	vm_map_lock_read(map);
	kr = vm_map_lookup_locked(&map, vaddr, fault_type, &version,
				&object, &offset,
				&prot, &wired,
				&behavior, &lo_offset, &hi_offset, &pmap_map);

	pmap = pmap_map->pmap;

	if (kr != KERN_SUCCESS) {
		vm_map_unlock_read(map);
		goto done;
	}

	/*
	 *	If the page is wired, we must fault for the current protection
	 *	value, to avoid further faults.
	 */

	if (wired)
		fault_type = prot | VM_PROT_WRITE;

#if	VM_FAULT_CLASSIFY
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
	 * 		- Have to talk to pager.
	 *		- Page is busy, absent or in error.
	 *		- Pager has locked out desired access.
	 *		- Fault needs to be restarted.
	 *		- Have to push page into copy object.
	 *
	 *	The code is an infinite loop that moves one level down
	 *	the shadow chain each time.  cur_object and cur_offset
	 * 	refer to the current object being examined. object and offset
	 *	are the original object from the map.  The loop is at the
	 *	top level if and only if object and cur_object are the same.
	 *
	 *	Invariants:  Map lock is held throughout.  Lock is held on
	 *		original object and cur_object (if different) when
	 *		continuing or exiting loop.
	 *
	 */


	/*
	 *	If this page is to be inserted in a copy delay object
	 *	for writing, and if the object has a copy, then the
	 *	copy delay strategy is implemented in the slow fault page.
	 */
	if (object->copy_strategy != MEMORY_OBJECT_COPY_DELAY ||
	    object->copy == VM_OBJECT_NULL ||
	    (fault_type & VM_PROT_WRITE) == 0) {
	cur_object = object;
	cur_offset = offset;

	while (TRUE) {
		m = vm_page_lookup(cur_object, cur_offset);
		if (m != VM_PAGE_NULL) {
			if (m->busy)
				break;

			if (m->unusual && (m->error || m->restart || m->private
			    || m->absent || (fault_type & m->page_lock))) {

			/*
				 *	Unusual case. Give up.
				 */
				break;
			}

			/*
			 *	Two cases of map in faults:
			 *	    - At top level w/o copy object.
			 *	    - Read fault anywhere.
			 *		--> must disallow write.
			 */

			if (object == cur_object &&
			    object->copy == VM_OBJECT_NULL)
				goto FastMapInFault;

			if ((fault_type & VM_PROT_WRITE) == 0) {

				prot &= ~VM_PROT_WRITE;

				/*
				 *	Set up to map the page ...
				 *	mark the page busy, drop
				 *	locks and take a paging reference
				 *	on the object with the page.
				 */	

			  	if (object != cur_object) {
					vm_object_unlock(object);
					object = cur_object;
				}
FastMapInFault:
				m->busy = TRUE;

				vm_object_paging_begin(object);
				vm_object_unlock(object);

FastPmapEnter:
				/*
				 *	Check a couple of global reasons to
				 *	be conservative about write access.
				 *	Then do the pmap_enter.
				 */
#if	!VM_FAULT_STATIC_CONFIG
				if (vm_fault_dirty_handling
#if	MACH_KDB
				    || db_watchpoint_list
#endif
				    && (fault_type & VM_PROT_WRITE) == 0)
					prot &= ~VM_PROT_WRITE;
#else	/* STATIC_CONFIG */
#if	MACH_KDB
				if (db_watchpoint_list
				    && (fault_type & VM_PROT_WRITE) == 0)
					prot &= ~VM_PROT_WRITE;
#endif	/* MACH_KDB */
#endif	/* STATIC_CONFIG */
				if (m->no_isync == TRUE)
				        pmap_sync_caches_phys(m->phys_addr);

				PMAP_ENTER(pmap, vaddr, m, prot, wired);
				{
				   tws_hash_line_t	line;
				   task_t		task;

				   task = current_task();
				   if((map != NULL) && 
					(task->dynamic_working_set != 0)) {
					if(tws_lookup
						((tws_hash_t)
						task->dynamic_working_set,
						cur_offset, object,
						&line) != KERN_SUCCESS) {
					   	if(tws_insert((tws_hash_t)
						   task->dynamic_working_set,
						   m->offset, m->object,
						   vaddr, pmap_map) 
							== KERN_NO_SPACE) {
						   tws_expand_working_set(
						      task->dynamic_working_set,
						      TWS_HASH_LINE_COUNT);
						}
					}
				   }
				}
				/*
				 *	Grab the object lock to manipulate
				 *	the page queues.  Change wiring
				 *	case is obvious.  In soft ref bits
				 *	case activate page only if it fell
				 *	off paging queues, otherwise just
				 *	activate it if it's inactive.
				 *
				 *	NOTE: original vm_fault code will
				 *	move active page to back of active
				 *	queue.  This code doesn't.
				 */
				vm_object_lock(object);
				vm_page_lock_queues();

				if (m->clustered) {
				        vm_pagein_cluster_used++;
					m->clustered = FALSE;
				}
				/* 
				 * we did the isync above (if needed)... we're clearing
				 * the flag here to avoid holding a lock
				 * while calling pmap functions, however
				 * we need hold the object lock before
				 * we can modify the flag
				 */
				m->no_isync = FALSE;
				m->reference = TRUE;

				if (change_wiring) {
					if (wired)
						vm_page_wire(m);
					else
						vm_page_unwire(m);
				}
#if VM_FAULT_STATIC_CONFIG
				else {
					if (!m->active && !m->inactive)
					        vm_page_activate(m);
				}
#else				
				else if (software_reference_bits) {
					if (!m->active && !m->inactive)
						vm_page_activate(m);
				}
				else if (!m->active) {
					vm_page_activate(m);
				}
#endif
				vm_page_unlock_queues();

				/*
				 *	That's it, clean up and return.
				 */
				PAGE_WAKEUP_DONE(m);
				vm_object_paging_end(object);
				vm_object_unlock(object);
				vm_map_unlock_read(map);
				if(pmap_map != map)
					vm_map_unlock(pmap_map);

				if (funnel_set) {
					thread_funnel_set( curflock, TRUE);
					funnel_set = FALSE;
				}
				cur_thread->interruptible = interruptible_state;

				KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, 0)) | DBG_FUNC_END,
						      vaddr,
						      type_of_fault,
						      KERN_SUCCESS,
						      0,
						      0);
				return KERN_SUCCESS;
			}

			/*
			 *	Copy on write fault.  If objects match, then
			 *	object->copy must not be NULL (else control
			 *	would be in previous code block), and we
			 *	have a potential push into the copy object
			 *	with which we won't cope here.
			 */

			if (cur_object == object)
				break;

			/*
			 *	This is now a shadow based copy on write
			 *	fault -- it requires a copy up the shadow
			 *	chain.
			 *
			 *	Allocate a page in the original top level
			 *	object. Give up if allocate fails.  Also
			 *	need to remember current page, as it's the
			 *	source of the copy.
			 */
			cur_m = m;
			m = vm_page_grab();
			if (m == VM_PAGE_NULL) {
				break;
			}

			/*
			 *	Now do the copy.  Mark the source busy
			 *	and take out paging references on both
			 *	objects.
			 *
			 *	NOTE: This code holds the map lock across
			 *	the page copy.
			 */

			cur_m->busy = TRUE;
			vm_page_copy(cur_m, m);
			vm_page_insert(m, object, offset);

			vm_object_paging_begin(cur_object);
			vm_object_paging_begin(object);

			type_of_fault = DBG_COW_FAULT;
			VM_STAT(cow_faults++);
			current_task()->cow_faults++;

			/*
			 *	Now cope with the source page and object
			 *	If the top object has a ref count of 1
			 *	then no other map can access it, and hence
			 *	it's not necessary to do the pmap_page_protect.
			 */


			vm_page_lock_queues();
			vm_page_deactivate(cur_m);
			m->dirty = TRUE;
			pmap_page_protect(cur_m->phys_addr,
						  VM_PROT_NONE);
			vm_page_unlock_queues();

			PAGE_WAKEUP_DONE(cur_m);
			vm_object_paging_end(cur_object);
			vm_object_unlock(cur_object);

			/*      
			 *      Slight hack to call vm_object collapse
			 *      and then reuse common map in code. 
			 *      note that the object lock was taken above.
			 */     
 
			vm_object_paging_end(object); 
			vm_object_collapse(object);
			vm_object_paging_begin(object);
			vm_object_unlock(object);

			goto FastPmapEnter;
		}
		else {

			/*
			 *	No page at cur_object, cur_offset
			 */

			if (cur_object->pager_created) {

				/*
				 *	Have to talk to the pager.  Give up.
				 */

				break;
			}


			if (cur_object->shadow == VM_OBJECT_NULL) {

				if (cur_object->shadow_severed) {
					vm_object_paging_end(object);
					vm_object_unlock(object);
					vm_map_unlock_read(map);
					if(pmap_map != map)
						vm_map_unlock(pmap_map);

					if (funnel_set) {
						thread_funnel_set( curflock, TRUE);
						funnel_set = FALSE;
					}
					cur_thread->interruptible = interruptible_state;

					return VM_FAULT_MEMORY_ERROR;
				}

				/*
				 *	Zero fill fault.  Page gets
				 *	filled in top object. Insert
				 *	page, then drop any lower lock.
				 *	Give up if no page.
				 */
				if ((vm_page_free_target - 
				   ((vm_page_free_target-vm_page_free_min)>>2))
						> vm_page_free_count) {
					break;
				}
				m = vm_page_alloc(object, offset);
				if (m == VM_PAGE_NULL) {
					break;
				}
				/*
				 * This is a zero-fill or initial fill
				 * page fault.  As such, we consider it
				 * undefined with respect to instruction
				 * execution.  i.e. it is the responsibility
				 * of higher layers to call for an instruction
				 * sync after changing the contents and before
				 * sending a program into this area.  We 
				 * choose this approach for performance
				 */

				m->no_isync = FALSE;

			  	if (cur_object != object)
					vm_object_unlock(cur_object);

				vm_object_paging_begin(object);
				vm_object_unlock(object);

				/*
				 *	Now zero fill page and map it.
				 *	the page is probably going to 
				 *	be written soon, so don't bother
				 *      to clear the modified bit
				 *
				 *	NOTE: This code holds the map
				 *	lock across the zero fill.
				 */

				if (!map->no_zero_fill) {
					vm_page_zero_fill(m);
					type_of_fault = DBG_ZERO_FILL_FAULT;
					VM_STAT(zero_fill_count++);
				}
				vm_page_lock_queues();
				VM_PAGE_QUEUES_REMOVE(m);

				m->page_ticket = vm_page_ticket;
				vm_page_ticket_roll++;
				if(vm_page_ticket_roll == 
						VM_PAGE_TICKETS_IN_ROLL) {
					vm_page_ticket_roll = 0;
					if(vm_page_ticket == 
						VM_PAGE_TICKET_ROLL_IDS)
						vm_page_ticket= 0;
					else
						vm_page_ticket++;
				}

				queue_enter(&vm_page_queue_inactive, 
							m, vm_page_t, pageq);
				m->inactive = TRUE;
				vm_page_inactive_count++;
				vm_page_unlock_queues();
				goto FastPmapEnter;
		        }

			/*
			 *	On to the next level
			 */

			cur_offset += cur_object->shadow_offset;
			new_object = cur_object->shadow;
			vm_object_lock(new_object);
			if (cur_object != object)
				vm_object_unlock(cur_object);
			cur_object = new_object;

			continue;
		}
	}

	/*
	 *	Cleanup from fast fault failure.  Drop any object
	 *	lock other than original and drop map lock.
	 */

	if (object != cur_object)
		vm_object_unlock(cur_object);
	}
	vm_map_unlock_read(map);
	if(pmap_map != map)
		vm_map_unlock(pmap_map);

   	/*
	 *	Make a reference to this object to
	 *	prevent its disposal while we are messing with
	 *	it.  Once we have the reference, the map is free
	 *	to be diddled.  Since objects reference their
	 *	shadows (and copies), they will stay around as well.
	 */

	assert(object->ref_count > 0);
	object->ref_count++;
	vm_object_res_reference(object);
	vm_object_paging_begin(object);

	XPR(XPR_VM_FAULT,"vm_fault -> vm_fault_page\n",0,0,0,0,0);
	kr = vm_fault_page(object, offset, fault_type,
			   (change_wiring && !wired),
			   interruptible,
			   lo_offset, hi_offset, behavior,
			   &prot, &result_page, &top_page,
			   &type_of_fault,
			   &error_code, map->no_zero_fill, FALSE, map, vaddr);

	/*
	 *	If we didn't succeed, lose the object reference immediately.
	 */

	if (kr != VM_FAULT_SUCCESS)
		vm_object_deallocate(object);

	/*
	 *	See why we failed, and take corrective action.
	 */

	switch (kr) {
		case VM_FAULT_SUCCESS:
			break;
		case VM_FAULT_MEMORY_SHORTAGE:
			if (vm_page_wait((change_wiring) ? 
					 THREAD_UNINT :
					 THREAD_ABORTSAFE))
				goto RetryFault;
			/* fall thru */
		case VM_FAULT_INTERRUPTED:
			kr = KERN_ABORTED;
			goto done;
		case VM_FAULT_RETRY:
			goto RetryFault;
		case VM_FAULT_FICTITIOUS_SHORTAGE:
			vm_page_more_fictitious();
			goto RetryFault;
		case VM_FAULT_MEMORY_ERROR:
			if (error_code)
				kr = error_code;
			else
				kr = KERN_MEMORY_ERROR;
			goto done;
	}

	m = result_page;

	if(m != VM_PAGE_NULL) {
		assert((change_wiring && !wired) ?
	   	    (top_page == VM_PAGE_NULL) :
	   	    ((top_page == VM_PAGE_NULL) == (m->object == object)));
	}

	/*
	 *	How to clean up the result of vm_fault_page.  This
	 *	happens whether the mapping is entered or not.
	 */

#define UNLOCK_AND_DEALLOCATE				\
	MACRO_BEGIN					\
	vm_fault_cleanup(m->object, top_page);		\
	vm_object_deallocate(object);			\
	MACRO_END

	/*
	 *	What to do with the resulting page from vm_fault_page
	 *	if it doesn't get entered into the physical map:
	 */

#define RELEASE_PAGE(m)					\
	MACRO_BEGIN					\
	PAGE_WAKEUP_DONE(m);				\
	vm_page_lock_queues();				\
	if (!m->active && !m->inactive)			\
		vm_page_activate(m);			\
	vm_page_unlock_queues();			\
	MACRO_END

	/*
	 *	We must verify that the maps have not changed
	 *	since our last lookup.
	 */

	if(m != VM_PAGE_NULL) {
		old_copy_object = m->object->copy;

		vm_object_unlock(m->object);
	} else {
		old_copy_object = VM_OBJECT_NULL;
	}
	if ((map != original_map) || !vm_map_verify(map, &version)) {
		vm_object_t		retry_object;
		vm_object_offset_t	retry_offset;
		vm_prot_t		retry_prot;

		/*
		 *	To avoid trying to write_lock the map while another
		 *	thread has it read_locked (in vm_map_pageable), we
		 *	do not try for write permission.  If the page is
		 *	still writable, we will get write permission.  If it
		 *	is not, or has been marked needs_copy, we enter the
		 *	mapping without write permission, and will merely
		 *	take another fault.
		 */
		map = original_map;
		vm_map_lock_read(map);
		kr = vm_map_lookup_locked(&map, vaddr,
				   fault_type & ~VM_PROT_WRITE, &version,
				   &retry_object, &retry_offset, &retry_prot,
				   &wired, &behavior, &lo_offset, &hi_offset,
				   &pmap_map);
		pmap = pmap_map->pmap;

		if (kr != KERN_SUCCESS) {
			vm_map_unlock_read(map);
			if(m != VM_PAGE_NULL) {
				vm_object_lock(m->object);
				RELEASE_PAGE(m);
				UNLOCK_AND_DEALLOCATE;
			} else {
				vm_object_deallocate(object);
			}
			goto done;
		}

		vm_object_unlock(retry_object);
		if(m != VM_PAGE_NULL) {
			vm_object_lock(m->object);
		} else {
			vm_object_lock(object);
		}

		if ((retry_object != object) ||
		    (retry_offset != offset)) {
			vm_map_unlock_read(map);
			if(pmap_map != map)
				vm_map_unlock(pmap_map);
			if(m != VM_PAGE_NULL) {
				RELEASE_PAGE(m);
				UNLOCK_AND_DEALLOCATE;
			} else {
				vm_object_deallocate(object);
			}
			goto RetryFault;
		}

		/*
		 *	Check whether the protection has changed or the object
		 *	has been copied while we left the map unlocked.
		 */
		prot &= retry_prot;
		if(m != VM_PAGE_NULL) {
			vm_object_unlock(m->object);
		} else {
			vm_object_unlock(object);
		}
	}
	if(m != VM_PAGE_NULL) {
		vm_object_lock(m->object);
	} else {
		vm_object_lock(object);
	}

	/*
	 *	If the copy object changed while the top-level object
	 *	was unlocked, then we must take away write permission.
	 */

	if(m != VM_PAGE_NULL) {
		if (m->object->copy != old_copy_object)
			prot &= ~VM_PROT_WRITE;
	}

	/*
	 *	If we want to wire down this page, but no longer have
	 *	adequate permissions, we must start all over.
	 */

	if (wired && (fault_type != (prot|VM_PROT_WRITE))) {
		vm_map_verify_done(map, &version);
		if(pmap_map != map)
			vm_map_unlock(pmap_map);
		if(m != VM_PAGE_NULL) {
			RELEASE_PAGE(m);
			UNLOCK_AND_DEALLOCATE;
		} else {
			vm_object_deallocate(object);
		}
		goto RetryFault;
	}

	/*
	 *	Put this page into the physical map.
	 *	We had to do the unlock above because pmap_enter
	 *	may cause other faults.  The page may be on
	 *	the pageout queues.  If the pageout daemon comes
	 *	across the page, it will remove it from the queues.
	 */
	if (m != VM_PAGE_NULL) {
		if (m->no_isync == TRUE) {
		        pmap_sync_caches_phys(m->phys_addr);

		        m->no_isync = FALSE;
		}
	        vm_object_unlock(m->object);

		PMAP_ENTER(pmap, vaddr, m, prot, wired);
		{
			tws_hash_line_t	line;
			task_t		task;

			   task = current_task();
			   if((map != NULL) && 
				(task->dynamic_working_set != 0)) {
				if(tws_lookup
					((tws_hash_t)
					task->dynamic_working_set,
					m->offset, m->object,
					&line) != KERN_SUCCESS) {
				   	tws_insert((tws_hash_t)
					   task->dynamic_working_set,
					   m->offset, m->object, 
					   vaddr, pmap_map);
				   	if(tws_insert((tws_hash_t)
						   task->dynamic_working_set,
						   m->offset, m->object,
						   vaddr, pmap_map) 
								== KERN_NO_SPACE) {
						tws_expand_working_set(
					 		task->dynamic_working_set, 
							TWS_HASH_LINE_COUNT);
					}
				}
			}
		}
	} else {

/*  if __ppc__  not working until figure out phys copy on block maps */
#ifdef notdefcdy
		int	memattr;
		struct	phys_entry	*pp;
		/* 
		 * do a pmap block mapping from the physical address
		 * in the object 
		 */
		if(pp = pmap_find_physentry(
			(vm_offset_t)object->shadow_offset)) {
			memattr = ((pp->pte1 & 0x00000078) >> 3); 
		} else {
			memattr = PTE_WIMG_UNCACHED_COHERENT_GUARDED;
		}

		pmap_map_block(pmap, vaddr, 
			(vm_offset_t)object->shadow_offset, 
			object->size, prot, 
			memattr, 0); /* Set up a block mapped area */
//#else
		vm_offset_t	off;
        	for (off = 0; off < object->size; off += page_size) {   
                	pmap_enter(pmap, vaddr + off, 
				object->shadow_offset + off, prot, TRUE);
        		/* Map it in */
        	}
#endif

	}

	/*
	 *	If the page is not wired down and isn't already
	 *	on a pageout queue, then put it where the
	 *	pageout daemon can find it.
	 */
	if(m != VM_PAGE_NULL) {
		vm_object_lock(m->object);
		vm_page_lock_queues();

		if (change_wiring) {
			if (wired)
				vm_page_wire(m);
			else
				vm_page_unwire(m);
		}
#if	VM_FAULT_STATIC_CONFIG
		else {
			if (!m->active && !m->inactive)
				vm_page_activate(m);
			m->reference = TRUE;
		}
#else
		else if (software_reference_bits) {
			if (!m->active && !m->inactive)
				vm_page_activate(m);
			m->reference = TRUE;
		} else {
			vm_page_activate(m);
		}
#endif
		vm_page_unlock_queues();
	}

	/*
	 *	Unlock everything, and return
	 */

	vm_map_verify_done(map, &version);
	if(pmap_map != map)
		vm_map_unlock(pmap_map);
	if(m != VM_PAGE_NULL) {
		PAGE_WAKEUP_DONE(m);
		UNLOCK_AND_DEALLOCATE;
	} else {
		vm_fault_cleanup(object, top_page);
		vm_object_deallocate(object);
	}
	kr = KERN_SUCCESS;

#undef	UNLOCK_AND_DEALLOCATE
#undef	RELEASE_PAGE

    done:
	if (funnel_set) {
		thread_funnel_set( curflock, TRUE);
		funnel_set = FALSE;
	}
	cur_thread->interruptible = interruptible_state;

	KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, 0)) | DBG_FUNC_END,
			      vaddr,
			      type_of_fault,
			      kr,
			      0,
			      0);
	return(kr);
}

/*
 *	vm_fault_wire:
 *
 *	Wire down a range of virtual addresses in a map.
 */
kern_return_t
vm_fault_wire(
	vm_map_t	map,
	vm_map_entry_t	entry,
	pmap_t		pmap)
{

	register vm_offset_t	va;
	register vm_offset_t	end_addr = entry->vme_end;
	register kern_return_t	rc;

	assert(entry->in_transition);

	/*
	 *	Inform the physical mapping system that the
	 *	range of addresses may not fault, so that
	 *	page tables and such can be locked down as well.
	 */

	pmap_pageable(pmap, entry->vme_start, end_addr, FALSE);

	/*
	 *	We simulate a fault to get the page and enter it
	 *	in the physical map.
	 */

	for (va = entry->vme_start; va < end_addr; va += PAGE_SIZE) {
		if ((rc = vm_fault_wire_fast(
				map, va, entry, pmap)) != KERN_SUCCESS) {
			rc = vm_fault(map, va, VM_PROT_NONE, TRUE, 
			              (pmap == kernel_pmap) ? THREAD_UNINT : THREAD_ABORTSAFE);
		}

		if (rc != KERN_SUCCESS) {
			struct vm_map_entry	tmp_entry = *entry;

			/* unwire wired pages */
			tmp_entry.vme_end = va;
			vm_fault_unwire(map, &tmp_entry, FALSE, pmap);

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
	vm_map_t	map,
	vm_map_entry_t	entry,
	boolean_t	deallocate,
	pmap_t		pmap)
{
	register vm_offset_t	va;
	register vm_offset_t	end_addr = entry->vme_end;
	vm_object_t		object;

	object = (entry->is_sub_map)
			? VM_OBJECT_NULL : entry->object.vm_object;

	/*
	 *	Since the pages are wired down, we must be able to
	 *	get their mappings from the physical map system.
	 */

	for (va = entry->vme_start; va < end_addr; va += PAGE_SIZE) {
		pmap_change_wiring(pmap, va, FALSE);

		if (object == VM_OBJECT_NULL) {
			(void) vm_fault(map, va, VM_PROT_NONE, TRUE, THREAD_UNINT);
		} else {
		 	vm_prot_t	prot;
			vm_page_t	result_page;
			vm_page_t	top_page;
			vm_object_t	result_object;
			vm_fault_return_t result;

			do {
				prot = VM_PROT_NONE;

				vm_object_lock(object);
				vm_object_paging_begin(object);
				XPR(XPR_VM_FAULT,
					"vm_fault_unwire -> vm_fault_page\n",
					0,0,0,0,0);
			 	result = vm_fault_page(object,
						entry->offset +
						  (va - entry->vme_start),
						VM_PROT_NONE, TRUE,
						THREAD_UNINT,
					        entry->offset,
						entry->offset +
						       (entry->vme_end
							- entry->vme_start),
						entry->behavior,
						&prot,
						&result_page,
						&top_page,
						(int *)0,
						0, map->no_zero_fill, 
						FALSE, NULL, 0);
			} while (result == VM_FAULT_RETRY);

			if (result != VM_FAULT_SUCCESS)
				panic("vm_fault_unwire: failure");

			result_object = result_page->object;
			if (deallocate) {
				assert(!result_page->fictitious);
				pmap_page_protect(result_page->phys_addr,
						VM_PROT_NONE);
				VM_PAGE_FREE(result_page);
			} else {
				vm_page_lock_queues();
				vm_page_unwire(result_page);
				vm_page_unlock_queues();
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

	pmap_pageable(pmap, entry->vme_start, end_addr, TRUE);

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
kern_return_t
vm_fault_wire_fast(
	vm_map_t	map,
	vm_offset_t	va,
	vm_map_entry_t	entry,
	pmap_t		pmap)
{
	vm_object_t		object;
	vm_object_offset_t	offset;
	register vm_page_t	m;
	vm_prot_t		prot;
	thread_act_t           	thr_act;

	VM_STAT(faults++);

	if((thr_act=current_act()) && (thr_act->task != TASK_NULL))
	  thr_act->task->faults++;

/*
 *	Recovery actions
 */

#undef	RELEASE_PAGE
#define RELEASE_PAGE(m)	{				\
	PAGE_WAKEUP_DONE(m);				\
	vm_page_lock_queues();				\
	vm_page_unwire(m);				\
	vm_page_unlock_queues();			\
}


#undef	UNLOCK_THINGS
#define UNLOCK_THINGS	{				\
	object->paging_in_progress--;			\
	vm_object_unlock(object);			\
}

#undef	UNLOCK_AND_DEALLOCATE
#define UNLOCK_AND_DEALLOCATE	{			\
	UNLOCK_THINGS;					\
	vm_object_deallocate(object);			\
}
/*
 *	Give up and have caller do things the hard way.
 */

#define GIVE_UP {					\
	UNLOCK_AND_DEALLOCATE;				\
	return(KERN_FAILURE);				\
}


	/*
	 *	If this entry is not directly to a vm_object, bail out.
	 */
	if (entry->is_sub_map)
		return(KERN_FAILURE);

	/*
	 *	Find the backing store object and offset into it.
	 */

	object = entry->object.vm_object;
	offset = (va - entry->vme_start) + entry->offset;
	prot = entry->protection;

   	/*
	 *	Make a reference to this object to prevent its
	 *	disposal while we are messing with it.
	 */

	vm_object_lock(object);
	assert(object->ref_count > 0);
	object->ref_count++;
	vm_object_res_reference(object);
	object->paging_in_progress++;

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
	if ((m == VM_PAGE_NULL) || (m->busy) || 
	    (m->unusual && ( m->error || m->restart || m->absent ||
				prot & m->page_lock))) {

		GIVE_UP;
	}

	/*
	 *	Wire the page down now.  All bail outs beyond this
	 *	point must unwire the page.  
	 */

	vm_page_lock_queues();
	vm_page_wire(m);
	vm_page_unlock_queues();

	/*
	 *	Mark page busy for other threads.
	 */
	assert(!m->busy);
	m->busy = TRUE;
	assert(!m->absent);

	/*
	 *	Give up if the page is being written and there's a copy object
	 */
	if ((object->copy != VM_OBJECT_NULL) && (prot & VM_PROT_WRITE)) {
		RELEASE_PAGE(m);
		GIVE_UP;
	}

	/*
	 *	Put this page into the physical map.
	 *	We have to unlock the object because pmap_enter
	 *	may cause other faults.   
	 */
	if (m->no_isync == TRUE) {
	        pmap_sync_caches_phys(m->phys_addr);

		m->no_isync = FALSE;
	}
	vm_object_unlock(object);

	PMAP_ENTER(pmap, va, m, prot, TRUE);

	/*
	 *	Must relock object so that paging_in_progress can be cleared.
	 */
	vm_object_lock(object);

	/*
	 *	Unlock everything, and return
	 */

	PAGE_WAKEUP_DONE(m);
	UNLOCK_AND_DEALLOCATE;

	return(KERN_SUCCESS);

}

/*
 *	Routine:	vm_fault_copy_cleanup
 *	Purpose:
 *		Release a page used by vm_fault_copy.
 */

void
vm_fault_copy_cleanup(
	vm_page_t	page,
	vm_page_t	top_page)
{
	vm_object_t	object = page->object;

	vm_object_lock(object);
	PAGE_WAKEUP_DONE(page);
	vm_page_lock_queues();
	if (!page->active && !page->inactive)
		vm_page_activate(page);
	vm_page_unlock_queues();
	vm_fault_cleanup(object, top_page);
}

void
vm_fault_copy_dst_cleanup(
	vm_page_t	page)
{
	vm_object_t	object;

	if (page != VM_PAGE_NULL) {
		object = page->object;
		vm_object_lock(object);
		vm_page_lock_queues();
		vm_page_unwire(page);
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
	vm_object_t		src_object,
	vm_object_offset_t	src_offset,
	vm_size_t		*src_size,		/* INOUT */
	vm_object_t		dst_object,
	vm_object_offset_t	dst_offset,
	vm_map_t		dst_map,
	vm_map_version_t	 *dst_version,
	int			interruptible)
{
	vm_page_t		result_page;
	
	vm_page_t		src_page;
	vm_page_t		src_top_page;
	vm_prot_t		src_prot;

	vm_page_t		dst_page;
	vm_page_t		dst_top_page;
	vm_prot_t		dst_prot;

	vm_size_t		amount_left;
	vm_object_t		old_copy_object;
	kern_return_t		error = 0;

	vm_size_t		part_size;

	/*
	 * In order not to confuse the clustered pageins, align
	 * the different offsets on a page boundary.
	 */
	vm_object_offset_t	src_lo_offset = trunc_page_64(src_offset);
	vm_object_offset_t	dst_lo_offset = trunc_page_64(dst_offset);
	vm_object_offset_t	src_hi_offset = round_page_64(src_offset + *src_size);
	vm_object_offset_t	dst_hi_offset = round_page_64(dst_offset + *src_size);

#define	RETURN(x)					\
	MACRO_BEGIN					\
	*src_size -= amount_left;			\
	MACRO_RETURN(x);				\
	MACRO_END

	amount_left = *src_size;
	do { /* while (amount_left > 0) */
		/*
		 * There may be a deadlock if both source and destination
		 * pages are the same. To avoid this deadlock, the copy must
		 * start by getting the destination page in order to apply
		 * COW semantics if any.
		 */

	RetryDestinationFault: ;

		dst_prot = VM_PROT_WRITE|VM_PROT_READ;

		vm_object_lock(dst_object);
		vm_object_paging_begin(dst_object);

		XPR(XPR_VM_FAULT,"vm_fault_copy -> vm_fault_page\n",0,0,0,0,0);
		switch (vm_fault_page(dst_object,
				      trunc_page_64(dst_offset),
				      VM_PROT_WRITE|VM_PROT_READ,
				      FALSE,
				      interruptible,
				      dst_lo_offset,
				      dst_hi_offset,
				      VM_BEHAVIOR_SEQUENTIAL,
				      &dst_prot,
				      &dst_page,
				      &dst_top_page,
				      (int *)0,
				      &error,
				      dst_map->no_zero_fill,
				      FALSE, NULL, 0)) {
		case VM_FAULT_SUCCESS:
			break;
		case VM_FAULT_RETRY:
			goto RetryDestinationFault;
		case VM_FAULT_MEMORY_SHORTAGE:
			if (vm_page_wait(interruptible))
				goto RetryDestinationFault;
			/* fall thru */
		case VM_FAULT_INTERRUPTED:
			RETURN(MACH_SEND_INTERRUPTED);
		case VM_FAULT_FICTITIOUS_SHORTAGE:
			vm_page_more_fictitious();
			goto RetryDestinationFault;
		case VM_FAULT_MEMORY_ERROR:
			if (error)
				return (error);
			else
				return(KERN_MEMORY_ERROR);
		}
		assert ((dst_prot & VM_PROT_WRITE) != VM_PROT_NONE);

		old_copy_object = dst_page->object->copy;

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

		vm_page_lock_queues();
		vm_page_wire(dst_page);
		vm_page_unlock_queues();
		PAGE_WAKEUP_DONE(dst_page);
		vm_object_unlock(dst_page->object);

		if (dst_top_page != VM_PAGE_NULL) {
			vm_object_lock(dst_object);
			VM_PAGE_FREE(dst_top_page);
			vm_object_paging_end(dst_object);
			vm_object_unlock(dst_object);
		}

	RetrySourceFault: ;

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
						  trunc_page_64(src_offset));
			if (src_page == dst_page) {
				src_prot = dst_prot;
				result_page = VM_PAGE_NULL;
			} else {
				src_prot = VM_PROT_READ;
				vm_object_paging_begin(src_object);

				XPR(XPR_VM_FAULT,
					"vm_fault_copy(2) -> vm_fault_page\n",
					0,0,0,0,0);
				switch (vm_fault_page(src_object, 
						      trunc_page_64(src_offset),
						      VM_PROT_READ, 
						      FALSE, 
						      interruptible,
						      src_lo_offset,
						      src_hi_offset,
						      VM_BEHAVIOR_SEQUENTIAL,
						      &src_prot, 
						      &result_page,
						      &src_top_page,
						      (int *)0,
						      &error,
						      FALSE,
						      FALSE, NULL, 0)) {

				case VM_FAULT_SUCCESS:
					break;
				case VM_FAULT_RETRY:
					goto RetrySourceFault;
				case VM_FAULT_MEMORY_SHORTAGE:
					if (vm_page_wait(interruptible))
						goto RetrySourceFault;
					/* fall thru */
				case VM_FAULT_INTERRUPTED:
					vm_fault_copy_dst_cleanup(dst_page);
					RETURN(MACH_SEND_INTERRUPTED);
				case VM_FAULT_FICTITIOUS_SHORTAGE:
					vm_page_more_fictitious();
					goto RetrySourceFault;
				case VM_FAULT_MEMORY_ERROR:
					vm_fault_copy_dst_cleanup(dst_page);
					if (error)
						return (error);
					else
						return(KERN_MEMORY_ERROR);
				}


				assert((src_top_page == VM_PAGE_NULL) ==
				       (result_page->object == src_object));
			}
			assert ((src_prot & VM_PROT_READ) != VM_PROT_NONE);
			vm_object_unlock(result_page->object);
		}

		if (!vm_map_verify(dst_map, dst_version)) {
			if (result_page != VM_PAGE_NULL && src_page != dst_page)
				vm_fault_copy_cleanup(result_page, src_top_page);
			vm_fault_copy_dst_cleanup(dst_page);
			break;
		}

		vm_object_lock(dst_page->object);

		if (dst_page->object->copy != old_copy_object) {
			vm_object_unlock(dst_page->object);
			vm_map_verify_done(dst_map, dst_version);
			if (result_page != VM_PAGE_NULL && src_page != dst_page)
				vm_fault_copy_cleanup(result_page, src_top_page);
			vm_fault_copy_dst_cleanup(dst_page);
			break;
		}
		vm_object_unlock(dst_page->object);

		/*
		 *	Copy the page, and note that it is dirty
		 *	immediately.
		 */

		if (!page_aligned(src_offset) ||
			!page_aligned(dst_offset) ||
			!page_aligned(amount_left)) {

			vm_object_offset_t	src_po,
						dst_po;

			src_po = src_offset - trunc_page_64(src_offset);
			dst_po = dst_offset - trunc_page_64(dst_offset);

			if (dst_po > src_po) {
				part_size = PAGE_SIZE - dst_po;
			} else {
				part_size = PAGE_SIZE - src_po;
			}
			if (part_size > (amount_left)){
				part_size = amount_left;
			}

			if (result_page == VM_PAGE_NULL) {
				vm_page_part_zero_fill(dst_page,
							dst_po, part_size);
			} else {
				vm_page_part_copy(result_page, src_po,
					dst_page, dst_po, part_size);
				if(!dst_page->dirty){
					vm_object_lock(dst_object);
					dst_page->dirty = TRUE;
					vm_object_unlock(dst_page->object);
				}

			}
		} else {
			part_size = PAGE_SIZE;

			if (result_page == VM_PAGE_NULL)
				vm_page_zero_fill(dst_page);
			else{
				vm_page_copy(result_page, dst_page);
				if(!dst_page->dirty){
					vm_object_lock(dst_object);
					dst_page->dirty = TRUE;
					vm_object_unlock(dst_page->object);
				}
			}

		}

		/*
		 *	Unlock everything, and return
		 */

		vm_map_verify_done(dst_map, dst_version);

		if (result_page != VM_PAGE_NULL && src_page != dst_page)
			vm_fault_copy_cleanup(result_page, src_top_page);
		vm_fault_copy_dst_cleanup(dst_page);

		amount_left -= part_size;
		src_offset += part_size;
		dst_offset += part_size;
	} while (amount_left > 0);

	RETURN(KERN_SUCCESS);
#undef	RETURN

	/*NOTREACHED*/	
}

#ifdef	notdef

/*
 *	Routine:	vm_fault_page_overwrite
 *
 *	Description:
 *		A form of vm_fault_page that assumes that the
 *		resulting page will be overwritten in its entirety,
 *		making it unnecessary to obtain the correct *contents*
 *		of the page.
 *
 *	Implementation:
 *		XXX Untested.  Also unused.  Eventually, this technology
 *		could be used in vm_fault_copy() to advantage.
 */
vm_fault_return_t
vm_fault_page_overwrite(
	register
	vm_object_t		dst_object,
	vm_object_offset_t	dst_offset,
	vm_page_t		*result_page)	/* OUT */
{
	register
	vm_page_t	dst_page;
	kern_return_t	wait_result;

#define	interruptible	THREAD_UNINT	/* XXX */

	while (TRUE) {
		/*
		 *	Look for a page at this offset
		 */

		while ((dst_page = vm_page_lookup(dst_object, dst_offset))
				 == VM_PAGE_NULL) {
			/*
			 *	No page, no problem... just allocate one.
			 */

			dst_page = vm_page_alloc(dst_object, dst_offset);
			if (dst_page == VM_PAGE_NULL) {
				vm_object_unlock(dst_object);
				VM_PAGE_WAIT();
				vm_object_lock(dst_object);
				continue;
			}

			/*
			 *	Pretend that the memory manager
			 *	write-protected the page.
			 *
			 *	Note that we will be asking for write
			 *	permission without asking for the data
			 *	first.
			 */

			dst_page->overwriting = TRUE;
			dst_page->page_lock = VM_PROT_WRITE;
			dst_page->absent = TRUE;
			dst_page->unusual = TRUE;
			dst_object->absent_count++;

			break;

			/*
			 *	When we bail out, we might have to throw
			 *	away the page created here.
			 */

#define	DISCARD_PAGE						\
	MACRO_BEGIN						\
	vm_object_lock(dst_object);				\
	dst_page = vm_page_lookup(dst_object, dst_offset);	\
	if ((dst_page != VM_PAGE_NULL) && dst_page->overwriting) \
	   	VM_PAGE_FREE(dst_page);				\
	vm_object_unlock(dst_object);				\
	MACRO_END
		}

		/*
		 *	If the page is write-protected...
		 */

		if (dst_page->page_lock & VM_PROT_WRITE) {
			/*
			 *	... and an unlock request hasn't been sent
			 */

			if ( ! (dst_page->unlock_request & VM_PROT_WRITE)) {
				vm_prot_t	u;
				kern_return_t	rc;

				/*
				 *	... then send one now.
				 */

				if (!dst_object->pager_ready) {
					vm_object_assert_wait(dst_object,
						VM_OBJECT_EVENT_PAGER_READY,
						interruptible);
					vm_object_unlock(dst_object);
					wait_result = thread_block((void (*)(void))0);
					if (wait_result != THREAD_AWAKENED) {
						DISCARD_PAGE;
						return(VM_FAULT_INTERRUPTED);
					}
					continue;
				}

				u = dst_page->unlock_request |= VM_PROT_WRITE;
				vm_object_unlock(dst_object);

				if ((rc = memory_object_data_unlock(
						dst_object->pager,
						dst_offset + dst_object->paging_offset,
						PAGE_SIZE,
						u)) != KERN_SUCCESS) {
					if (vm_fault_debug)
				     	    printf("vm_object_overwrite: memory_object_data_unlock failed\n");
					DISCARD_PAGE;
					return((rc == MACH_SEND_INTERRUPTED) ?
						VM_FAULT_INTERRUPTED :
						VM_FAULT_MEMORY_ERROR);
				}
				vm_object_lock(dst_object);
				continue;
			}

			/* ... fall through to wait below */
		} else {
			/*
			 *	If the page isn't being used for other
			 *	purposes, then we're done.
			 */
			if ( ! (dst_page->busy || dst_page->absent ||
				dst_page->error || dst_page->restart) )
				break;
		}

		PAGE_ASSERT_WAIT(dst_page, interruptible);
		vm_object_unlock(dst_object);
		wait_result = thread_block((void (*)(void))0);
		if (wait_result != THREAD_AWAKENED) {
			DISCARD_PAGE;
			return(VM_FAULT_INTERRUPTED);
		}
	}

	*result_page = dst_page;
	return(VM_FAULT_SUCCESS);

#undef	interruptible
#undef	DISCARD_PAGE
}

#endif	/* notdef */

#if	VM_FAULT_CLASSIFY
/*
 *	Temporary statistics gathering support.
 */

/*
 *	Statistics arrays:
 */
#define VM_FAULT_TYPES_MAX	5
#define	VM_FAULT_LEVEL_MAX	8

int	vm_fault_stats[VM_FAULT_TYPES_MAX][VM_FAULT_LEVEL_MAX];

#define	VM_FAULT_TYPE_ZERO_FILL	0
#define	VM_FAULT_TYPE_MAP_IN	1
#define	VM_FAULT_TYPE_PAGER	2
#define	VM_FAULT_TYPE_COPY	3
#define	VM_FAULT_TYPE_OTHER	4


void
vm_fault_classify(vm_object_t		object,
		  vm_object_offset_t	offset,
		  vm_prot_t		fault_type)
{
	int		type, level = 0;
	vm_page_t	m;

	while (TRUE) {
		m = vm_page_lookup(object, offset);
		if (m != VM_PAGE_NULL) {		
			if (m->busy || m->error || m->restart || m->absent ||
			    fault_type & m->page_lock) {
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
		}
		else {
			if (object->pager_created) {
				type = VM_FAULT_TYPE_PAGER;
				break;
			}
			if (object->shadow == VM_OBJECT_NULL) {
				type = VM_FAULT_TYPE_ZERO_FILL;
				break;
		        }

			offset += object->shadow_offset;
			object = object->shadow;
			level++;
			continue;
		}
	}

	if (level > VM_FAULT_LEVEL_MAX)
		level = VM_FAULT_LEVEL_MAX;

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
#endif	/* VM_FAULT_CLASSIFY */
