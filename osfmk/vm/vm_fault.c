/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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
#include <mach_kdb.h>
#include <libkern/OSAtomic.h>

#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <mach/message.h>	/* for error codes */
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
#include <kern/xpr.h>
#include <kern/mach_param.h>
#include <kern/macro_help.h>
#include <kern/zalloc.h>
#include <kern/misc_protos.h>

#include <ppc/proc_reg.h>

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
#include <vm/vm_purgeable_internal.h>	/* Needed by some vm_page.h macros */

#include <sys/kdebug.h>

#define VM_FAULT_CLASSIFY	0

#define TRACEFAULTPAGE 0 /* (TEST/DEBUG) */

int	vm_object_pagein_throttle = 16;

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

boolean_t thread_is_io_throttled(void);

uint64_t vm_hard_throttle_threshold;

extern unsigned int dp_pages_free, dp_pages_reserve;

#define NEED_TO_HARD_THROTTLE_THIS_TASK() 	(((dp_pages_free + dp_pages_reserve < 2000) && \
						 (get_task_resident_size(current_task()) > vm_hard_throttle_threshold) && \
						 (current_task() != kernel_task) && IP_VALID(memory_manager_default)) || \
						 (vm_page_free_count < vm_page_throttle_limit && thread_is_io_throttled() && \
						  (get_task_resident_size(current_task()) > vm_hard_throttle_threshold)))


#define HARD_THROTTLE_DELAY	10000	/* 10000 us == 10 ms */


extern int cs_debug;

#if	MACH_KDB
extern struct db_watchpoint *db_watchpoint_list;
#endif	/* MACH_KDB */

boolean_t current_thread_aborted(void);

/* Forward declarations of internal routines. */
extern kern_return_t vm_fault_wire_fast(
				vm_map_t	map,
				vm_map_offset_t	va,
				vm_map_entry_t	entry,
				pmap_t		pmap,
				vm_map_offset_t	pmap_addr);

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


unsigned long vm_cs_validates = 0;
unsigned long vm_cs_revalidates = 0;
unsigned long vm_cs_query_modified = 0;
unsigned long vm_cs_validated_dirtied = 0;

#if CONFIG_ENFORCE_SIGNED_CODE
int cs_enforcement_disable=0;
#else
static const int cs_enforcement_disable=1;
#endif

/*
 *	Routine:	vm_fault_init
 *	Purpose:
 *		Initialize our private data structures.
 */
void
vm_fault_init(void)
{
#if !SECURE_KERNEL
#if CONFIG_ENFORCE_SIGNED_CODE
	PE_parse_boot_argn("cs_enforcement_disable", &cs_enforcement_disable, 
			   sizeof (cs_enforcement_disable));
#endif
	PE_parse_boot_argn("cs_debug", &cs_debug, sizeof (cs_debug));
#endif

	/*
	 * Choose a value for the hard throttle threshold based on the amount of ram.  The threshold is
	 * computed as a percentage of available memory, and the percentage used is scaled inversely with
	 * the amount of memory.  The pertange runs between 10% and 35%.  We use 35% for small memory systems
	 * and reduce the value down to 10% for very large memory configurations.  This helps give us a
	 * definition of a memory hog that makes more sense relative to the amount of ram in the machine.
	 * The formula here simply uses the number of gigabytes of ram to adjust the percentage.
	 */

	vm_hard_throttle_threshold = sane_size * (35 - MIN((int)(sane_size / (1024*1024*1024)), 25)) / 100;
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

#define ALIGNED(x) (((x) & (PAGE_SIZE_64 - 1)) == 0)


boolean_t	vm_page_deactivate_behind = TRUE;
/* 
 * default sizes given VM_BEHAVIOR_DEFAULT reference behavior 
 */
#define VM_DEFAULT_DEACTIVATE_BEHIND_WINDOW	128
#define VM_DEFAULT_DEACTIVATE_BEHIND_CLUSTER	16		/* don't make this too big... */
                                                                /* we use it to size an array on the stack */

int vm_default_behind = VM_DEFAULT_DEACTIVATE_BEHIND_WINDOW;

#define MAX_SEQUENTIAL_RUN	(1024 * 1024 * 1024)

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
	vm_object_t		object,
	vm_object_offset_t	offset,
	vm_behavior_t		behavior)
{
        vm_object_offset_t	last_alloc;
	int			sequential;
	int			orig_sequential;

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
		        if (sequential < MAX_SEQUENTIAL_RUN)
			        sequential += PAGE_SIZE;
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
		        if (sequential > -MAX_SEQUENTIAL_RUN)
			        sequential -= PAGE_SIZE;
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
		        if (sequential < 0)
			        sequential = 0;
		        if (sequential < MAX_SEQUENTIAL_RUN)
			        sequential += PAGE_SIZE;

		} else if (last_alloc && last_alloc == (offset + PAGE_SIZE_64)) {
		        /*
			 * advance indicator of sequential behavior
			 */
		        if (sequential > 0)
			        sequential = 0;
		        if (sequential > -MAX_SEQUENTIAL_RUN)
			        sequential -= PAGE_SIZE;
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
	vm_object_t		object,
	vm_object_offset_t	offset,
	vm_behavior_t		behavior)
{
	int		n;
	int		pages_in_run = 0;
	int		max_pages_in_run = 0;
	int		sequential_run;
	int		sequential_behavior = VM_BEHAVIOR_SEQUENTIAL;
	vm_object_offset_t	run_offset = 0;
	vm_object_offset_t	pg_offset = 0;
	vm_page_t	m;
	vm_page_t	page_run[VM_DEFAULT_DEACTIVATE_BEHIND_CLUSTER];

	pages_in_run = 0;
#if TRACEFAULTPAGE
	dbgTrace(0xBEEF0018, (unsigned int) object, (unsigned int) vm_fault_deactivate_behind);	/* (TEST/DEBUG) */
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
	{	vm_object_offset_t behind = vm_default_behind * PAGE_SIZE_64;

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
		break;
	}
	}
        for (n = 0; n < max_pages_in_run; n++) {
		m = vm_page_lookup(object, offset + run_offset + (n * pg_offset));

		if (m && !m->busy && !m->no_cache && !m->throttled && !m->fictitious && !m->absent) {
			page_run[pages_in_run++] = m;
			pmap_clear_reference(m->phys_page);
		}
	}
	if (pages_in_run) {
		vm_page_lockspin_queues();

		for (n = 0; n < pages_in_run; n++) {

			m = page_run[n];

			vm_page_deactivate_internal(m, FALSE);

			vm_page_deactivate_behind_count++;
#if TRACEFAULTPAGE
			dbgTrace(0xBEEF0019, (unsigned int) object, (unsigned int) m);	/* (TEST/DEBUG) */
#endif
		}
		vm_page_unlock_queues();

		return TRUE;
	}
	return FALSE;
}


static boolean_t
vm_page_throttled(void)
{
        clock_sec_t     elapsed_sec;
        clock_sec_t     tv_sec;
        clock_usec_t    tv_usec;
	
	thread_t thread = current_thread();
	
	if (thread->options & TH_OPT_VMPRIV)
		return (FALSE);

	thread->t_page_creation_count++;

	if (NEED_TO_HARD_THROTTLE_THIS_TASK())
		return (TRUE);

	if (vm_page_free_count < vm_page_throttle_limit &&
	    thread->t_page_creation_count > vm_page_creation_throttle) {

		clock_get_system_microtime(&tv_sec, &tv_usec);

		elapsed_sec = tv_sec - thread->t_page_creation_time;

		if (elapsed_sec <= 6 || (thread->t_page_creation_count / elapsed_sec) >= (vm_page_creation_throttle / 6)) {

			if (elapsed_sec >= 60) {
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
				thread->t_page_creation_count = (vm_page_creation_throttle / 6) * 5;
			}
			++vm_page_throttle_count;

			return (TRUE);
		}
		thread->t_page_creation_time = tv_sec;
		thread->t_page_creation_count = 0;
	}
	return (FALSE);
}


/*
 * check for various conditions that would
 * prevent us from creating a ZF page...
 * cleanup is based on being called from vm_fault_page
 *
 * object must be locked
 * object == m->object
 */
static vm_fault_return_t
vm_fault_check(vm_object_t object, vm_page_t m, vm_page_t first_m, boolean_t interruptible_state)
{
        if (object->shadow_severed ||
	    VM_OBJECT_PURGEABLE_FAULT_ERROR(object)) {
	        /*
		 * Either:
		 * 1. the shadow chain was severed,
		 * 2. the purgeable object is volatile or empty and is marked
		 *    to fault on access while volatile.
		 * Just have to return an error at this point
		 */
	        if (m != VM_PAGE_NULL)
		        VM_PAGE_FREE(m);
		vm_fault_cleanup(object, first_m);

		thread_interrupt_level(interruptible_state);

		return (VM_FAULT_MEMORY_ERROR);
	}
	if (vm_backing_store_low) {
	        /*
		 * are we protecting the system from
		 * backing store exhaustion.  If so
		 * sleep unless we are privileged.
		 */
	        if (!(current_task()->priv_flags & VM_BACKING_STORE_PRIV)) {

			if (m != VM_PAGE_NULL)
			        VM_PAGE_FREE(m);
			vm_fault_cleanup(object, first_m);

		        assert_wait((event_t)&vm_backing_store_low, THREAD_UNINT);

			thread_block(THREAD_CONTINUE_NULL);
			thread_interrupt_level(interruptible_state);

			return (VM_FAULT_RETRY);
		}
	}
	if (vm_page_throttled()) {
	        /*
		 * we're throttling zero-fills...
		 * treat this as if we couldn't grab a page
		 */
	        if (m != VM_PAGE_NULL)
		        VM_PAGE_FREE(m);
		vm_fault_cleanup(object, first_m);

		if (NEED_TO_HARD_THROTTLE_THIS_TASK()) {
			delay(HARD_THROTTLE_DELAY);

			if (current_thread_aborted()) {
				thread_interrupt_level(interruptible_state);
				return VM_FAULT_INTERRUPTED;
			}
		}

		thread_interrupt_level(interruptible_state);

		return (VM_FAULT_MEMORY_SHORTAGE);
	}
	return (VM_FAULT_SUCCESS);
}


/*
 * do the work to zero fill a page and
 * inject it into the correct paging queue
 *
 * m->object must be locked
 * page queue lock must NOT be held
 */
static int
vm_fault_zero_page(vm_page_t m, boolean_t no_zero_fill)
{
        int my_fault = DBG_ZERO_FILL_FAULT;

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
	m->pmapped = TRUE;

	m->cs_validated = FALSE;
	m->cs_tainted = FALSE;

	if (no_zero_fill == TRUE)
	        my_fault = DBG_NZF_PAGE_FAULT;
	else {
		vm_page_zero_fill(m);

		VM_STAT_INCR(zero_fill_count);
		DTRACE_VM2(zfod, int, 1, (uint64_t *), NULL);
	}
	assert(!m->laundry);
	assert(m->object != kernel_object);
	//assert(m->pageq.next == NULL && m->pageq.prev == NULL);

	if (!IP_VALID(memory_manager_default) &&
		(m->object->purgable == VM_PURGABLE_DENY ||
		 m->object->purgable == VM_PURGABLE_NONVOLATILE ||
		 m->object->purgable == VM_PURGABLE_VOLATILE )) {
		vm_page_lockspin_queues();

                queue_enter(&vm_page_queue_throttled, m, vm_page_t, pageq);
                m->throttled = TRUE;
                vm_page_throttled_count++;

		vm_page_unlock_queues();
	} else {
		if (current_thread()->t_page_creation_count > vm_page_creation_throttle) {
			m->zero_fill = TRUE;
			VM_ZF_COUNT_INCR();
		}
	}
	return (my_fault);
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
 * 		does not actually hold VM pages, but device memory or
 *		large pages).  The object is still locked and we still hold a
 *		paging_in_progress reference.
 */
unsigned int vm_fault_page_blocked_access = 0;

vm_fault_return_t
vm_fault_page(
	/* Arguments: */
	vm_object_t	first_object,	/* Object to begin search */
	vm_object_offset_t first_offset,	/* Offset into object */
	vm_prot_t	fault_type,	/* What access is requested */
	boolean_t	must_be_resident,/* Must page be resident? */
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
#if MACH_PAGEMAP
	boolean_t	data_supply,	/* treat as data_supply if 
					 * it is a write fault and a full
					 * page is provided */
#else
	__unused boolean_t data_supply,
#endif
	vm_object_fault_info_t fault_info)
{
	vm_page_t		m;
	vm_object_t		object;
	vm_object_offset_t	offset;
	vm_page_t		first_m;
	vm_object_t		next_object;
	vm_object_t		copy_object;
	boolean_t		look_for_page;
	vm_prot_t		access_required = fault_type;
	vm_prot_t		wants_copy_flag;
	CLUSTER_STAT(int pages_at_higher_offsets;)
	CLUSTER_STAT(int pages_at_lower_offsets;)
	kern_return_t		wait_result;
	boolean_t		interruptible_state;
	vm_fault_return_t	error;
	int			my_fault;
	uint32_t		try_failed_count;
	int			interruptible; /* how may fault be interrupted? */
	memory_object_t		pager;
	vm_fault_return_t	retval;

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
 * MUST_ASK_PAGER() evaluates to TRUE if the page specified by object/offset is 
 * either marked as paged out in the existence map for the object or no 
 * existence map exists for the object.  MUST_ASK_PAGER() is one of the
 * criteria in the decision to invoke the pager.   It is also used as one
 * of the criteria to terminate the scan for adjacent pages in a clustered
 * pagein operation.  Note that MUST_ASK_PAGER() always evaluates to TRUE for
 * permanent objects.  Note also that if the pager for an internal object 
 * has not been created, the pager is not invoked regardless of the value 
 * of MUST_ASK_PAGER() and that clustered pagein scans are only done on an object
 * for which a pager has been created.
 *
 * PAGED_OUT() evaluates to TRUE if the page specified by the object/offset
 * is marked as paged out in the existence map for the object.  PAGED_OUT()
 * PAGED_OUT() is used to determine if a page has already been pushed
 * into a copy object in order to avoid a redundant page out operation.
 */
#if MACH_PAGEMAP
#define MUST_ASK_PAGER(o, f) (vm_external_state_get((o)->existence_map, (f)) \
			!= VM_EXTERNAL_STATE_ABSENT)
#define PAGED_OUT(o, f) (vm_external_state_get((o)->existence_map, (f)) \
			== VM_EXTERNAL_STATE_EXISTS)
#else
#define MUST_ASK_PAGER(o, f) (TRUE)
#define PAGED_OUT(o, f) (FALSE)
#endif

/*
 *	Recovery actions
 */
#define RELEASE_PAGE(m)					\
	MACRO_BEGIN					\
	PAGE_WAKEUP_DONE(m);				\
	if (!m->active && !m->inactive && !m->throttled) {		\
		vm_page_lockspin_queues();				\
		if (!m->active && !m->inactive && !m->throttled)	\
			vm_page_activate(m);				\
		vm_page_unlock_queues();				\
	}								\
	MACRO_END

#if TRACEFAULTPAGE
	dbgTrace(0xBEEF0002, (unsigned int) first_object, (unsigned int) first_offset);	/* (TEST/DEBUG) */
#endif


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


	XPR(XPR_VM_FAULT,
		"vm_f_page: obj 0x%X, offset 0x%X, type %d, prot %d\n",
		object, offset, fault_type, *protection, 0);

	/*
	 * default type of fault
	 */
	my_fault = DBG_CACHE_HIT_FAULT;

	while (TRUE) {
#if TRACEFAULTPAGE
		dbgTrace(0xBEEF0003, (unsigned int) 0, (unsigned int) 0);	/* (TEST/DEBUG) */
#endif
		if (!object->alive) {
		        /*
			 * object is no longer valid
			 * clean up and return error
			 */
			vm_fault_cleanup(object, first_m);
			thread_interrupt_level(interruptible_state);

			return (VM_FAULT_MEMORY_ERROR);
		}

		if (!object->pager_created && object->phys_contiguous) {
			/*
			 * A physically-contiguous object without a pager:
			 * must be a "large page" object.  We do not deal
			 * with VM pages for this object.
			 */
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
		m = vm_page_lookup(object, offset);
#if TRACEFAULTPAGE
		dbgTrace(0xBEEF0004, (unsigned int) m, (unsigned int) object);	/* (TEST/DEBUG) */
#endif
		if (m != VM_PAGE_NULL) {

			if (m->busy) {
			        /*
				 * The page is being brought in,
				 * wait for it and then retry.
				 *
				 * A possible optimization: if the page
				 * is known to be resident, we can ignore
				 * pages that are absent (regardless of
				 * whether they're busy).
				 */
#if TRACEFAULTPAGE
				dbgTrace(0xBEEF0005, (unsigned int) m, (unsigned int) 0);	/* (TEST/DEBUG) */
#endif
				wait_result = PAGE_SLEEP(object, m, interruptible);
				XPR(XPR_VM_FAULT,
				    "vm_f_page: block busy obj 0x%X, offset 0x%X, page 0x%X\n",
					object, offset,
					m, 0, 0);
				counter(c_vm_fault_page_block_busy_kernel++);

				if (wait_result != THREAD_AWAKENED) {
					vm_fault_cleanup(object, first_m);
					thread_interrupt_level(interruptible_state);

					if (wait_result == THREAD_RESTART)
					        return (VM_FAULT_RETRY);
					else
						return (VM_FAULT_INTERRUPTED);
				}
				continue;
			}

			if (m->phys_page == vm_page_guard_addr) {
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
					m->busy = TRUE;
					*result_page = m;
					assert(first_m == VM_PAGE_NULL);
					*top_page = first_m;
					if (type_of_fault)
						*type_of_fault = DBG_GUARD_FAULT;
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

			if (m->error) {
			        /*
				 * The page is in error, give up now.
				 */
#if TRACEFAULTPAGE
				dbgTrace(0xBEEF0006, (unsigned int) m, (unsigned int) error_code);	/* (TEST/DEBUG) */
#endif
				if (error_code)
				        *error_code = KERN_MEMORY_ERROR;
				VM_PAGE_FREE(m);

				vm_fault_cleanup(object, first_m);
				thread_interrupt_level(interruptible_state);

				return (VM_FAULT_MEMORY_ERROR);
			}
			if (m->restart) {
			        /*
				 * The pager wants us to restart
				 * at the top of the chain,
				 * typically because it has moved the
				 * page to another pager, then do so.
				 */
#if TRACEFAULTPAGE
				dbgTrace(0xBEEF0007, (unsigned int) m, (unsigned int) 0);	/* (TEST/DEBUG) */
#endif
				VM_PAGE_FREE(m);

				vm_fault_cleanup(object, first_m);
				thread_interrupt_level(interruptible_state);

				return (VM_FAULT_RETRY);
			}
			if (m->absent) {
			        /*
				 * The page isn't busy, but is absent,
				 * therefore it's deemed "unavailable".
				 *
				 * Remove the non-existent page (unless it's
				 * in the top object) and move on down to the
				 * next object (if there is one).
				 */
#if TRACEFAULTPAGE
				dbgTrace(0xBEEF0008, (unsigned int) m, (unsigned int) object->shadow);	/* (TEST/DEBUG) */
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
					error = vm_fault_check(object, m, first_m, interruptible_state);

					if (error != VM_FAULT_SUCCESS)
					        return (error);

					XPR(XPR_VM_FAULT,
					    "vm_f_page: zero obj 0x%X, off 0x%X, page 0x%X, first_obj 0x%X\n",
						object, offset,
						m,
						first_object, 0);

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
					        m->absent = FALSE;
						m->busy = TRUE;
					}
					/*
					 * zero-fill the page and put it on
					 * the correct paging queue
					 */
					my_fault = vm_fault_zero_page(m, no_zero_fill);

					break;
				} else {
					if (must_be_resident)
						vm_object_paging_end(object);
					else if (object != first_object) {
						vm_object_paging_end(object);
						VM_PAGE_FREE(m);
					} else {
						first_m = m;
						m->absent = FALSE;
						m->busy = TRUE;

						vm_page_lockspin_queues();
						VM_PAGE_QUEUES_REMOVE(m);
						vm_page_unlock_queues();
					}
					XPR(XPR_VM_FAULT,
					    "vm_f_page: unavail obj 0x%X, off 0x%X, next_obj 0x%X, newoff 0x%X\n",
						object, offset,
						next_object,
						offset+object->shadow_offset,0);

					offset += object->shadow_offset;
					fault_info->lo_offset += object->shadow_offset;
					fault_info->hi_offset += object->shadow_offset;
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
			if ((m->cleaning)
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
				dbgTrace(0xBEEF0009, (unsigned int) m, (unsigned int) offset);	/* (TEST/DEBUG) */
#endif
				XPR(XPR_VM_FAULT,
				    "vm_f_page: cleaning obj 0x%X, offset 0x%X, page 0x%X\n",
					object, offset,
					m, 0, 0);
				/*
				 * take an extra ref so that object won't die
				 */
				vm_object_reference_locked(object);

				vm_fault_cleanup(object, first_m);
				
				counter(c_vm_fault_page_block_backoff_kernel++);
				vm_object_lock(object);
				assert(object->ref_count > 0);

				m = vm_page_lookup(object, offset);

				if (m != VM_PAGE_NULL && m->cleaning) {
					PAGE_ASSERT_WAIT(m, interruptible);

					vm_object_unlock(object);
					wait_result = thread_block(THREAD_CONTINUE_NULL);
					vm_object_deallocate(object);

					goto backoff;
				} else {
					vm_object_unlock(object);

					vm_object_deallocate(object);
					thread_interrupt_level(interruptible_state);

					return (VM_FAULT_RETRY);
				}
			}
			if (type_of_fault == NULL && m->speculative &&
			    !(fault_info != NULL && fault_info->stealth)) {
			        /*
				 * If we were passed a non-NULL pointer for
				 * "type_of_fault", than we came from
				 * vm_fault... we'll let it deal with
				 * this condition, since it
				 * needs to see m->speculative to correctly
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
			        VM_PAGE_QUEUES_REMOVE(m);
			        vm_page_unlock_queues();
			}

			if (m->encrypted) {
				/*
				 * ENCRYPTED SWAP:
				 * the user needs access to a page that we
				 * encrypted before paging it out.
				 * Decrypt the page now.
				 * Keep it busy to prevent anyone from
				 * accessing it during the decryption.
				 */
				m->busy = TRUE;
				vm_page_decrypt(m, 0);
				assert(object == m->object);
				assert(m->busy);
				PAGE_WAKEUP_DONE(m);

				/*
				 * Retry from the top, in case
				 * something changed while we were
				 * decrypting.
				 */
				continue;
			}
			ASSERT_PAGE_DECRYPTED(m);

			if (m->object->code_signed) {
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
			dbgTrace(0xBEEF000B, (unsigned int) m, (unsigned int) 0);	/* (TEST/DEBUG) */
#endif
			XPR(XPR_VM_FAULT,
			    "vm_f_page: found page obj 0x%X, offset 0x%X, page 0x%X\n",
				object, offset, m, 0, 0);
			assert(!m->busy);
			assert(!m->absent);

			m->busy = TRUE;
			break;
		}
		

		/*
		 * we get here when there is no page present in the object at
		 * the offset we're interested in... we'll allocate a page
		 * at this point if the pager associated with
		 * this object can provide the data or we're the top object...
		 * object is locked;  m == NULL
		 */
		look_for_page =	(object->pager_created && (MUST_ASK_PAGER(object, offset) == TRUE) && !data_supply);
		
#if TRACEFAULTPAGE
		dbgTrace(0xBEEF000C, (unsigned int) look_for_page, (unsigned int) object);	/* (TEST/DEBUG) */
#endif
		if ((look_for_page || (object == first_object)) && !must_be_resident && !object->phys_contiguous) {
			/*
			 * Allocate a new page for this object/offset pair
			 */
			m = vm_page_grab();
#if TRACEFAULTPAGE
			dbgTrace(0xBEEF000D, (unsigned int) m, (unsigned int) object);	/* (TEST/DEBUG) */
#endif
			if (m == VM_PAGE_NULL) {

				vm_fault_cleanup(object, first_m);
				thread_interrupt_level(interruptible_state);

				return (VM_FAULT_MEMORY_SHORTAGE);
			}
			vm_page_insert(m, object, offset);
		}
		if (look_for_page && !must_be_resident) {
			kern_return_t	rc;

			/*
			 *	If the memory manager is not ready, we
			 *	cannot make requests.
			 */
			if (!object->pager_ready) {
#if TRACEFAULTPAGE
				dbgTrace(0xBEEF000E, (unsigned int) 0, (unsigned int) 0);	/* (TEST/DEBUG) */
#endif
				if (m != VM_PAGE_NULL)
				        VM_PAGE_FREE(m);

				XPR(XPR_VM_FAULT,
				"vm_f_page: ready wait obj 0x%X, offset 0x%X\n",
					object, offset, 0, 0, 0);

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
					if (wait_result == THREAD_WAITING)
						wait_result = thread_block(THREAD_CONTINUE_NULL);
					vm_object_deallocate(object);

					goto backoff;
				} else {
					vm_object_unlock(object);
					vm_object_deallocate(object);
					thread_interrupt_level(interruptible_state);

					return (VM_FAULT_RETRY);
				}
			}
			if (!object->internal && !object->phys_contiguous && object->paging_in_progress > vm_object_pagein_throttle) {
				/*
				 * If there are too many outstanding page
				 * requests pending on this external object, we
				 * wait for them to be resolved now.
				 */
#if TRACEFAULTPAGE
				dbgTrace(0xBEEF0010, (unsigned int) m, (unsigned int) 0);	/* (TEST/DEBUG) */
#endif
				if (m != VM_PAGE_NULL)
					VM_PAGE_FREE(m);
				/*
				 * take an extra ref so object won't die
				 */
				vm_object_reference_locked(object);

				vm_fault_cleanup(object, first_m);

				counter(c_vm_fault_page_block_backoff_kernel++);

				vm_object_lock(object);
				assert(object->ref_count > 0);

				if (object->paging_in_progress > vm_object_pagein_throttle) {
				        vm_object_assert_wait(object, VM_OBJECT_EVENT_PAGING_IN_PROGRESS, interruptible);

					vm_object_unlock(object);
					wait_result = thread_block(THREAD_CONTINUE_NULL);
					vm_object_deallocate(object);

					goto backoff;
				} else {
					vm_object_unlock(object);
					vm_object_deallocate(object);
					thread_interrupt_level(interruptible_state);

					return (VM_FAULT_RETRY);
				}
			}
			if (m != VM_PAGE_NULL) {
			        /*
				 * Indicate that the page is waiting for data
				 * from the memory manager.
				 */
			        m->list_req_pending = TRUE;
				m->absent = TRUE;
			}

#if TRACEFAULTPAGE
			dbgTrace(0xBEEF0012, (unsigned int) object, (unsigned int) 0);	/* (TEST/DEBUG) */
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
			if (object->copy_strategy == MEMORY_OBJECT_COPY_CALL && object != first_object)
				wants_copy_flag = VM_PROT_WANTS_COPY;
			else
				wants_copy_flag = VM_PROT_NONE;

			XPR(XPR_VM_FAULT,
			    "vm_f_page: data_req obj 0x%X, offset 0x%X, page 0x%X, acc %d\n",
				object, offset, m,
				access_required | wants_copy_flag, 0);

			/*
			 * Call the memory manager to retrieve the data.
			 */
			rc = memory_object_data_request(
				pager,
				offset + object->paging_offset,
				PAGE_SIZE,
				access_required | wants_copy_flag,
				(memory_object_fault_info_t)fault_info);

#if TRACEFAULTPAGE
			dbgTrace(0xBEEF0013, (unsigned int) object, (unsigned int) rc);	/* (TEST/DEBUG) */
#endif
			vm_object_lock(object);

			if (rc != KERN_SUCCESS) {

				vm_fault_cleanup(object, first_m);
				thread_interrupt_level(interruptible_state);

				return ((rc == MACH_SEND_INTERRUPTED) ?
					VM_FAULT_INTERRUPTED :
					VM_FAULT_MEMORY_ERROR);
			} else {
				clock_sec_t     tv_sec;
				clock_usec_t    tv_usec;
			
				clock_get_system_microtime(&tv_sec, &tv_usec);
				current_thread()->t_page_creation_time = tv_sec;
				current_thread()->t_page_creation_count = 0;
			}
			if ((interruptible != THREAD_UNINT) && (current_thread()->sched_mode & TH_MODE_ABORT)) {

				vm_fault_cleanup(object, first_m);
				thread_interrupt_level(interruptible_state);

				return (VM_FAULT_INTERRUPTED);
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
			my_fault = DBG_PAGEIN_FAULT;

			/*
			 * Retry with same object/offset, since new data may
			 * be in a different page (i.e., m is meaningless at
			 * this point).
			 */
			continue;
		}

		/*
		 * We get here if the object has no pager, or an existence map 
		 * exists and indicates the page isn't present on the pager
		 * or we're unwiring a page.  If a pager exists, but there
		 * is no existence map, then the m->absent case above handles
		 * the ZF case when the pager can't provide the page
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
			object, offset, m,
			object->shadow, 0);

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
			assert(m->object == object);
			first_m = VM_PAGE_NULL;

			/*
			 * check for any conditions that prevent
			 * us from creating a new zero-fill page
			 * vm_fault_check will do all of the 
			 * fault cleanup in the case of an error condition
			 * including resetting the thread_interrupt_level
			 */
			error = vm_fault_check(object, m, first_m, interruptible_state);

			if (error != VM_FAULT_SUCCESS)
			        return (error);

			if (m == VM_PAGE_NULL) {
				m = vm_page_grab();

				if (m == VM_PAGE_NULL) {
					vm_fault_cleanup(object, VM_PAGE_NULL);
					thread_interrupt_level(interruptible_state);

					return (VM_FAULT_MEMORY_SHORTAGE);
				}
				vm_page_insert(m, object, offset);
			}
			my_fault = vm_fault_zero_page(m, no_zero_fill);

			break;

		} else {
		        /*
			 * Move on to the next object.  Lock the next
			 * object before unlocking the current one.
			 */
			if ((object != first_object) || must_be_resident)
				vm_object_paging_end(object);

			offset += object->shadow_offset;
			fault_info->lo_offset += object->shadow_offset;
			fault_info->hi_offset += object->shadow_offset;
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
	assert(m->busy && !m->absent);
	assert((first_m == VM_PAGE_NULL) ||
	       (first_m->busy && !first_m->absent &&
		!first_m->active && !first_m->inactive));
#endif	/* EXTRA_ASSERTIONS */

	/*
	 * ENCRYPTED SWAP:
	 * If we found a page, we must have decrypted it before we
	 * get here...
	 */
	ASSERT_PAGE_DECRYPTED(m);

	XPR(XPR_VM_FAULT,
	    "vm_f_page: FOUND obj 0x%X, off 0x%X, page 0x%X, 1_obj 0x%X, 1_m 0x%X\n",
		object, offset, m,
		first_object, first_m);

	/*
	 * If the page is being written, but isn't
	 * already owned by the top-level object,
	 * we have to copy it into a new page owned
	 * by the top-level object.
	 */
	if (object != first_object) {

#if TRACEFAULTPAGE
		dbgTrace(0xBEEF0016, (unsigned int) object, (unsigned int) fault_type);	/* (TEST/DEBUG) */
#endif
	    	if (fault_type & VM_PROT_WRITE) {
			vm_page_t copy_m;

			/*
			 * We only really need to copy if we
			 * want to write it.
			 */
			assert(!must_be_resident);

			/*
			 * are we protecting the system from
			 * backing store exhaustion.  If so
			 * sleep unless we are privileged.
			 */
			if (vm_backing_store_low) {
				if (!(current_task()->priv_flags & VM_BACKING_STORE_PRIV)) {

					RELEASE_PAGE(m);
					vm_fault_cleanup(object, first_m);

					assert_wait((event_t)&vm_backing_store_low, THREAD_UNINT);

					thread_block(THREAD_CONTINUE_NULL);
					thread_interrupt_level(interruptible_state);

					return (VM_FAULT_RETRY);
				}
			}
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
			copy_m = vm_page_grab();

			if (copy_m == VM_PAGE_NULL) {
				RELEASE_PAGE(m);

				vm_fault_cleanup(object, first_m);
				thread_interrupt_level(interruptible_state);

				return (VM_FAULT_MEMORY_SHORTAGE);
			}
			XPR(XPR_VM_FAULT,
			    "vm_f_page: page_copy obj 0x%X, offset 0x%X, m 0x%X, copy_m 0x%X\n",
				object, offset,
				m, copy_m, 0);

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
			if (m->pmapped)
			        pmap_disconnect(m->phys_page);

			assert(!m->cleaning);

			/*
			 * We no longer need the old page or object.
			 */
			PAGE_WAKEUP_DONE(m);
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
			assert(copy_m->busy);
			vm_page_insert(copy_m, object, offset);
			copy_m->dirty = TRUE;

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

		} else
		    	*protection &= (~VM_PROT_WRITE);
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
		vm_object_offset_t	copy_offset;
		vm_page_t		copy_m;

#if TRACEFAULTPAGE
		dbgTrace(0xBEEF0017, (unsigned int) copy_object, (unsigned int) fault_type);	/* (TEST/DEBUG) */
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
		if (must_be_resident)
			break;

		/*
		 * Try to get the lock on the copy_object.
		 */
		if (!vm_object_lock_try(copy_object)) {

			vm_object_unlock(object);
			try_failed_count++;

			mutex_pause(try_failed_count);	/* wait a bit */
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
		copy_offset = first_offset - copy_object->shadow_offset;

		if (copy_object->size <= copy_offset)
			/*
			 * Copy object doesn't cover this page -- do nothing.
			 */
			;
		else if ((copy_m = vm_page_lookup(copy_object, copy_offset)) != VM_PAGE_NULL) {
			/*
			 * Page currently exists in the copy object
			 */
			if (copy_m->busy) {
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
				/*
				 * ENCRYPTED SWAP:
				 * it's OK if the "copy_m" page is encrypted,
				 * because we're not moving it nor handling its
				 * contents.
				 */
				if (copy_m != VM_PAGE_NULL && copy_m->busy) {
					PAGE_ASSERT_WAIT(copy_m, interruptible);

					vm_object_unlock(copy_object);
					wait_result = thread_block(THREAD_CONTINUE_NULL);
					vm_object_deallocate(copy_object);

					goto backoff;
				} else {
					vm_object_unlock(copy_object);
					vm_object_deallocate(copy_object);
					thread_interrupt_level(interruptible_state);

					return (VM_FAULT_RETRY);
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

			if (vm_backing_store_low) {
			        /*
				 * we are protecting the system from
				 * backing store exhaustion.  If so
				 * sleep unless we are privileged.
				 */
				if (!(current_task()->priv_flags & VM_BACKING_STORE_PRIV)) {
					assert_wait((event_t)&vm_backing_store_low, THREAD_UNINT);

					RELEASE_PAGE(m);
					VM_OBJ_RES_DECR(copy_object);
					vm_object_lock_assert_exclusive(copy_object);
					copy_object->ref_count--;
					assert(copy_object->ref_count > 0);

					vm_object_unlock(copy_object);
					vm_fault_cleanup(object, first_m);
					thread_block(THREAD_CONTINUE_NULL);
					thread_interrupt_level(interruptible_state);

					return (VM_FAULT_RETRY);
				}
			}
			/*
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

				return (VM_FAULT_MEMORY_SHORTAGE);
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
			if (m->pmapped)
			        pmap_disconnect(m->phys_page);

			/*
			 * If there's a pager, then immediately
			 * page out this page, using the "initialize"
			 * option.  Else, we use the copy.
			 */
		 	if ((!copy_object->pager_created)
#if MACH_PAGEMAP
			    || vm_external_state_get(copy_object->existence_map, copy_offset) == VM_EXTERNAL_STATE_ABSENT
#endif
			    ) {

				vm_page_lockspin_queues();
				assert(!m->cleaning);
				vm_page_activate(copy_m);
				vm_page_unlock_queues();

				copy_m->dirty = TRUE;
				PAGE_WAKEUP_DONE(copy_m);
			} 
			else {
				assert(copy_m->busy == TRUE);
				assert(!m->cleaning);

				/*
				 * dirty is protected by the object lock
				 */
				copy_m->dirty = TRUE;

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
			if (m->wanted) {
				m->wanted = FALSE;
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

	XPR(XPR_VM_FAULT,
		"vm_f_page: DONE obj 0x%X, offset 0x%X, m 0x%X, first_m 0x%X\n",
		object, offset, m, first_m, 0);

	if (m != VM_PAGE_NULL) {
		retval = VM_FAULT_SUCCESS;
		if (my_fault == DBG_PAGEIN_FAULT) {

			VM_STAT_INCR(pageins);
			DTRACE_VM2(pgin, int, 1, (uint64_t *), NULL);
			DTRACE_VM2(maj_fault, int, 1, (uint64_t *), NULL);
			current_task()->pageins++;

			if (m->object->internal) {
				DTRACE_VM2(anonpgin, int, 1, (uint64_t *), NULL);
				my_fault = DBG_PAGEIND_FAULT;
			} else {
				DTRACE_VM2(fspgin, int, 1, (uint64_t *), NULL);
				my_fault = DBG_PAGEINV_FAULT;
			}

		        /*
			 * evaluate access pattern and update state
			 * vm_fault_deactivate_behind depends on the
			 * state being up to date
			 */
		        vm_fault_is_sequential(object, offset, fault_info->behavior);

			vm_fault_deactivate_behind(object, offset, fault_info->behavior);
		}
		if (type_of_fault)
		        *type_of_fault = my_fault;
	} else {
		retval = VM_FAULT_SUCCESS_NO_VM_PAGE;
		assert(first_m == VM_PAGE_NULL);
		assert(object == first_object);
	}

	thread_interrupt_level(interruptible_state);

#if TRACEFAULTPAGE
	dbgTrace(0xBEEF001A, (unsigned int) VM_FAULT_SUCCESS, 0);	/* (TEST/DEBUG) */
#endif
	return retval;

backoff:
	thread_interrupt_level(interruptible_state);

	if (wait_result == THREAD_INTERRUPTED)
		return (VM_FAULT_INTERRUPTED);
	return (VM_FAULT_RETRY);

#undef	RELEASE_PAGE
}



/*
 * CODE SIGNING:
 * When soft faulting a page, we have to validate the page if:
 * 1. the page is being mapped in user space
 * 2. the page hasn't already been found to be "tainted"
 * 3. the page belongs to a code-signed object
 * 4. the page has not been validated yet or has been mapped for write.
 */
#define VM_FAULT_NEED_CS_VALIDATION(pmap, page)				\
	((pmap) != kernel_pmap /*1*/ &&					\
	 !(page)->cs_tainted /*2*/ &&					\
	 (page)->object->code_signed /*3*/ &&				\
	 (!(page)->cs_validated || (page)->wpmapped /*4*/))


/*
 * page queue lock must NOT be held
 * m->object must be locked
 *
 * NOTE: m->object could be locked "shared" only if we are called
 * from vm_fault() as part of a soft fault.  If so, we must be
 * careful not to modify the VM object in any way that is not
 * legal under a shared lock...
 */
unsigned long cs_enter_tainted_rejected = 0;
unsigned long cs_enter_tainted_accepted = 0;
kern_return_t
vm_fault_enter(vm_page_t m,
	       pmap_t pmap,
	       vm_map_offset_t vaddr,
	       vm_prot_t prot,
	       boolean_t wired,
	       boolean_t change_wiring,
	       boolean_t no_cache,
	       int *type_of_fault)
{
	unsigned int	cache_attr;
	kern_return_t	kr;
	boolean_t	previously_pmapped = m->pmapped;
	boolean_t	must_disconnect = 0;
	boolean_t	map_is_switched, map_is_switch_protected;
	
	vm_object_lock_assert_held(m->object);
#if DEBUG
	lck_mtx_assert(&vm_page_queue_lock, LCK_MTX_ASSERT_NOTOWNED);
#endif /* DEBUG */

	if (m->phys_page == vm_page_guard_addr) {
		assert(m->fictitious);
		return KERN_SUCCESS;
	}

        cache_attr = ((unsigned int)m->object->wimg_bits) & VM_WIMG_MASK;

	if (m->pmapped == FALSE) {
		/*
		 * This is the first time this page is being
		 * mapped in an address space (pmapped == FALSE).
		 *
		 * Part of that page may still be in the data cache
		 * and not flushed to memory.  In case we end up
		 * accessing that page via the instruction cache,
		 * we need to ensure that the 2 caches are in sync.
		 */
		pmap_sync_page_data_phys(m->phys_page);

		if ((*type_of_fault == DBG_CACHE_HIT_FAULT) && m->clustered) {
		        /*
			 * found it in the cache, but this
			 * is the first fault-in of the page (m->pmapped == FALSE)
			 * so it must have come in as part of
			 * a cluster... account 1 pagein against it
			 */
		        VM_STAT_INCR(pageins);
			DTRACE_VM2(pgin, int, 1, (uint64_t *), NULL);

			if (m->object->internal) {
				DTRACE_VM2(anonpgin, int, 1, (uint64_t *), NULL);
				*type_of_fault = DBG_PAGEIND_FAULT;
			} else {
				DTRACE_VM2(fspgin, int, 1, (uint64_t *), NULL);
				*type_of_fault = DBG_PAGEINV_FAULT;
			}

			current_task()->pageins++;
		}
		VM_PAGE_CONSUME_CLUSTERED(m);

	} else if (cache_attr != VM_WIMG_DEFAULT)
	        pmap_sync_page_attributes_phys(m->phys_page);

	if (*type_of_fault != DBG_COW_FAULT) {
		DTRACE_VM2(as_fault, int, 1, (uint64_t *), NULL);

		if (pmap == kernel_pmap) {
			DTRACE_VM2(kernel_asflt, int, 1, (uint64_t *), NULL);
		}
	}

	/* Validate code signature if necessary. */
	if (VM_FAULT_NEED_CS_VALIDATION(pmap, m)) {
		vm_object_lock_assert_exclusive(m->object);

		if (m->cs_validated) {
			vm_cs_revalidates++;
		}

		/* VM map is locked, so 1 ref will remain on VM object - 
		 * so no harm if vm_page_validate_cs drops the object lock */
		vm_page_validate_cs(m);
	}

#define page_immutable(m,prot) ((m)->cs_validated /*&& ((prot) & VM_PROT_EXECUTE)*/)

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
	if(!cs_enforcement_disable && map_is_switched && 
	   map_is_switch_protected && page_immutable(m, prot) && 
	   (prot & VM_PROT_WRITE))
	{
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
	if (m->cs_tainted ||
	    ( !cs_enforcement_disable &&
	     (/* The page is unsigned and wants to be executable */
	      (!m->cs_validated && (prot & VM_PROT_EXECUTE))  ||
	      /* The page should be immutable, but is in danger of being modified
		* This is the case where we want policy from the code directory -
		* is the page immutable or not? For now we have to assume that 
		* code pages will be immutable, data pages not.
		* We'll assume a page is a code page if it has a code directory 
		* and we fault for execution.
		* That is good enough since if we faulted the code page for
		* writing in another map before, it is wpmapped; if we fault
		* it for writing in this map later it will also be faulted for executing 
		* at the same time; and if we fault for writing in another map
		* later, we will disconnect it from this pmap so we'll notice
		* the change.
		*/
	      (page_immutable(m, prot) && ((prot & VM_PROT_WRITE) || m->wpmapped))
	      ))
		) 
	{
		/* We will have a tainted page. Have to handle the special case
		 * of a switched map now. If the map is not switched, standard
		 * procedure applies - call cs_invalid_page().
		 * If the map is switched, the real owner is invalid already.
		 * There is no point in invalidating the switching process since
		 * it will not be executing from the map. So we don't call
		 * cs_invalid_page() in that case. */
		boolean_t reject_page;
		if(map_is_switched) { 
			assert(pmap==vm_map_pmap(current_thread()->map));
			assert(!(prot & VM_PROT_WRITE) || (map_is_switch_protected == FALSE));
			reject_page = FALSE;
		} else {
			reject_page = cs_invalid_page((addr64_t) vaddr);
		}
		
		if (reject_page) {
			/* reject the tainted page: abort the page fault */
			kr = KERN_CODESIGN_ERROR;
			cs_enter_tainted_rejected++;
		} else {
			/* proceed with the tainted page */
			kr = KERN_SUCCESS;
			/* Page might have been tainted before or not; now it
			 * definitively is. If the page wasn't tainted, we must
			 * disconnect it from all pmaps later. */
			must_disconnect = !m->cs_tainted;
			m->cs_tainted = TRUE;
			cs_enter_tainted_accepted++;
		}
		if (cs_debug || kr != KERN_SUCCESS) {
			printf("CODESIGNING: vm_fault_enter(0x%llx): "
			       "page %p obj %p off 0x%llx *** INVALID PAGE ***\n",
			       (long long)vaddr, m, m->object, m->offset);
		}
		
	} else {
		/* proceed with the valid page */
		kr = KERN_SUCCESS;
	}

	/* If we have a KERN_SUCCESS from the previous checks, we either have
	 * a good page, or a tainted page that has been accepted by the process.
	 * In both cases the page will be entered into the pmap.
	 * If the page is writeable, we need to disconnect it from other pmaps
	 * now so those processes can take note.
	 */
	if (kr == KERN_SUCCESS) {
	        /*
		 * NOTE: we may only hold the vm_object lock SHARED
		 * at this point, but the update of pmapped is ok
		 * since this is the ONLY bit updated behind the SHARED
		 * lock... however, we need to figure out how to do an atomic
		 * update on a bit field to make this less fragile... right
		 * now I don't know how to coerce 'C' to give me the offset info
		 * that's needed for an AtomicCompareAndSwap
		 */
		m->pmapped = TRUE;
		if (prot & VM_PROT_WRITE) {
			vm_object_lock_assert_exclusive(m->object);
			m->wpmapped = TRUE;
			if(must_disconnect) {
				/* We can only get here 
				 * because of the CSE logic */
				assert(cs_enforcement_disable == FALSE);
				pmap_disconnect(m->phys_page);
				/* If we are faulting for a write, we can clear
				 * the execute bit - that will ensure the page is
				 * checked again before being executable, which
				 * protects against a map switch.
				 * This only happens the first time the page
				 * gets tainted, so we won't get stuck here 
				 * to make an already writeable page executable. */
				prot &= ~VM_PROT_EXECUTE;
			}
		}
		PMAP_ENTER(pmap, vaddr, m, prot, cache_attr, wired);
	}

	/*
	 * Hold queues lock to manipulate
	 * the page queues.  Change wiring
	 * case is obvious.
	 */
	if (change_wiring) {
	        vm_page_lockspin_queues();

		if (wired) {
			if (kr == KERN_SUCCESS) {
				vm_page_wire(m);
			}
		} else {
		        vm_page_unwire(m);
		}
		vm_page_unlock_queues();

	} else {
	        if (kr != KERN_SUCCESS) {
		        vm_page_lockspin_queues();
		        vm_page_deactivate(m);
		        vm_page_unlock_queues();
		} else {
		        if (((!m->active && !m->inactive) || no_cache) && !VM_PAGE_WIRED(m) && !m->throttled) {

				if ( vm_page_local_q && !no_cache && (*type_of_fault == DBG_COW_FAULT || *type_of_fault == DBG_ZERO_FILL_FAULT) ) {
					struct vpl	*lq;
					uint32_t	lid;

					/*
					 * we got a local queue to stuff this new page on...
					 * its safe to manipulate local and local_id at this point
					 * since we're behind an exclusive object lock and the
					 * page is not on any global queue.
					 *
					 * we'll use the current cpu number to select the queue
					 * note that we don't need to disable preemption... we're
					 * going to behind the local queue's lock to do the real 
					 * work
					 */
					lid = cpu_number();

					lq = &vm_page_local_q[lid].vpl_un.vpl;

					VPL_LOCK(&lq->vpl_lock);

					queue_enter(&lq->vpl_queue, m, vm_page_t, pageq);
					m->local = TRUE;
					m->local_id = lid;
					lq->vpl_count++;
					
					VPL_UNLOCK(&lq->vpl_lock);

					if (lq->vpl_count > vm_page_local_q_soft_limit) {
						/*
						 * we're beyond the soft limit for the local queue
						 * vm_page_reactivate_local will 'try' to take
						 * the global page queue lock... if it can't that's
						 * ok... we'll let the queue continue to grow up
						 * to the hard limit... at that point we'll wait
						 * for the lock... once we've got the lock, we'll
						 * transfer all of the pages from the local queue
						 * to the global active queue
						 */
						vm_page_reactivate_local(lid, FALSE, FALSE);
					}
					return kr;
				}

			        vm_page_lockspin_queues();
				/*
				 * test again now that we hold the page queue lock
				 */
				if (((!m->active && !m->inactive) || no_cache) && !VM_PAGE_WIRED(m)) {

					/*
					 * If this is a no_cache mapping and the page has never been
					 * mapped before or was previously a no_cache page, then we
					 * want to leave pages in the speculative state so that they
					 * can be readily recycled if free memory runs low.  Otherwise
					 * the page is activated as normal. 
					 */

					if (no_cache && (!previously_pmapped || m->no_cache)) {
						m->no_cache = TRUE;

						if (m->active || m->inactive)
							VM_PAGE_QUEUES_REMOVE(m);

						if (!m->speculative) 
							vm_page_speculate(m, TRUE);

					} else if (!m->active && !m->inactive)
						vm_page_activate(m);

				}

				vm_page_unlock_queues();
			}
		}
	}
	return kr;
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

unsigned long vm_fault_collapse_total = 0;
unsigned long vm_fault_collapse_skipped = 0;

kern_return_t
vm_fault(
	vm_map_t	map,
	vm_map_offset_t	vaddr,
	vm_prot_t	fault_type,
	boolean_t	change_wiring,
	int		interruptible,
	pmap_t		caller_pmap,
	vm_map_offset_t	caller_pmap_addr)
{
	vm_map_version_t	version;	/* Map version for verificiation */
	boolean_t		wired;		/* Should mapping be wired down? */
	vm_object_t		object;		/* Top-level object */
	vm_object_offset_t	offset;		/* Top-level offset */
	vm_prot_t		prot;		/* Protection for mapping */
	vm_object_t		old_copy_object; /* Saved copy object */
	vm_page_t		result_page;	/* Result of vm_fault_page */
	vm_page_t		top_page;	/* Placeholder page */
	kern_return_t		kr;

	vm_page_t		m;	/* Fast access to result_page */
	kern_return_t		error_code;
	vm_object_t		cur_object;
	vm_object_offset_t	cur_offset;
	vm_page_t		cur_m;
	vm_object_t		new_object;
	int                     type_of_fault;
	pmap_t			pmap;
	boolean_t		interruptible_state;
	vm_map_t		real_map = map;
	vm_map_t		original_map = map;
	vm_prot_t		original_fault_type;
	struct vm_object_fault_info fault_info;
	boolean_t		need_collapse = FALSE;
	int			object_lock_type = 0;
	int			cur_object_lock_type;
	vm_object_t		top_object = VM_OBJECT_NULL;


	KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, 2)) | DBG_FUNC_START,
			      (int)((uint64_t)vaddr >> 32),
			      (int)vaddr,
			      0,
			      0,
			      0);

	if (get_preemption_level() != 0) {
	        KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, 2)) | DBG_FUNC_END,
				      (int)((uint64_t)vaddr >> 32),
				      (int)vaddr,
				      KERN_FAILURE,
				      0,
				      0);

		return (KERN_FAILURE);
	}
	
	interruptible_state = thread_interrupt_level(interruptible);

	VM_STAT_INCR(faults);
	current_task()->faults++;
	original_fault_type = fault_type;

	if (fault_type & VM_PROT_WRITE)
	        object_lock_type = OBJECT_LOCK_EXCLUSIVE;
	else
	        object_lock_type = OBJECT_LOCK_SHARED;

	cur_object_lock_type = OBJECT_LOCK_SHARED;

RetryFault:
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

	kr = vm_map_lookup_locked(&map, vaddr, fault_type,
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

	/*
	 * If the page is wired, we must fault for the current protection
	 * value, to avoid further faults.
	 */
	if (wired) {
		fault_type = prot | VM_PROT_WRITE;
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
	 * If this page is to be inserted in a copy delay object
	 * for writing, and if the object has a copy, then the
	 * copy delay strategy is implemented in the slow fault page.
	 */
	if (object->copy_strategy == MEMORY_OBJECT_COPY_DELAY &&
	    object->copy != VM_OBJECT_NULL && (fault_type & VM_PROT_WRITE))
	        goto handle_copy_delay;

	cur_object = object;
	cur_offset = offset;

	while (TRUE) {
		if (!cur_object->pager_created &&
		    cur_object->phys_contiguous) /* superpage */
			break;

		if (cur_object->blocked_access) {
			/*
			 * Access to this VM object has been blocked.
			 * Let the slow path handle it.
			 */
			break;
		}

		m = vm_page_lookup(cur_object, cur_offset);

		if (m != VM_PAGE_NULL) {
			if (m->busy) {
			        wait_result_t	result;

				/*
				 * in order to do the PAGE_ASSERT_WAIT, we must
				 * have object that 'm' belongs to locked exclusively
				 */
				if (object != cur_object) {
				        vm_object_unlock(object);

					if (cur_object_lock_type == OBJECT_LOCK_SHARED) {

					        cur_object_lock_type = OBJECT_LOCK_EXCLUSIVE;

						if (vm_object_lock_upgrade(cur_object) == FALSE) {
						        /*
							 * couldn't upgrade so go do a full retry
							 * immediately since we've already dropped
							 * the top object lock associated with this page
							 * and the current one got dropped due to the
							 * failed upgrade... the state is no longer valid
							 */
						        vm_map_unlock_read(map);
							if (real_map != map)
							        vm_map_unlock(real_map);

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
				vm_map_unlock_read(map);
				if (real_map != map)
				        vm_map_unlock(real_map);

				result = PAGE_ASSERT_WAIT(m, interruptible);

				vm_object_unlock(cur_object);

				if (result == THREAD_WAITING) {
				        result = thread_block(THREAD_CONTINUE_NULL);

					counter(c_vm_fault_page_block_busy_kernel++);
				}
				if (result == THREAD_AWAKENED || result == THREAD_RESTART)
				        goto RetryFault;

				kr = KERN_ABORTED;
				goto done;
			}
			if (m->phys_page == vm_page_guard_addr) {
				/*
				 * Guard page: let the slow path deal with it
				 */
				break;
			}
			if (m->unusual && (m->error || m->restart || m->private || m->absent)) {
			        /*
				 * Unusual case... let the slow path deal with it
				 */
				break;
			}
			if (VM_OBJECT_PURGEABLE_FAULT_ERROR(m->object)) {
				if (object != cur_object)
					vm_object_unlock(object);
				vm_map_unlock_read(map);
				if (real_map != map)
				        vm_map_unlock(real_map);
				vm_object_unlock(cur_object);
				kr = KERN_MEMORY_ERROR;
				goto done;
			}

			if (m->encrypted) {
				/*
				 * ENCRYPTED SWAP:
				 * We've soft-faulted (because it's not in the page
				 * table) on an encrypted page.
				 * Keep the page "busy" so that no one messes with
				 * it during the decryption.
				 * Release the extra locks we're holding, keep only
				 * the page's VM object lock.
				 *
				 * in order to set 'busy' on 'm', we must
				 * have object that 'm' belongs to locked exclusively
				 */
			        if (object != cur_object) {
					vm_object_unlock(object);

					if (cur_object_lock_type == OBJECT_LOCK_SHARED) {

					        cur_object_lock_type = OBJECT_LOCK_EXCLUSIVE;

						if (vm_object_lock_upgrade(cur_object) == FALSE) {
						        /*
							 * couldn't upgrade so go do a full retry
							 * immediately since we've already dropped
							 * the top object lock associated with this page
							 * and the current one got dropped due to the
							 * failed upgrade... the state is no longer valid
							 */
						        vm_map_unlock_read(map);
							if (real_map != map)
							        vm_map_unlock(real_map);

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
				m->busy = TRUE;

				vm_map_unlock_read(map);
				if (real_map != map) 
					vm_map_unlock(real_map);

				vm_page_decrypt(m, 0);

				assert(m->busy);
				PAGE_WAKEUP_DONE(m);

				vm_object_unlock(cur_object);
				/*
				 * Retry from the top, in case anything
				 * changed while we were decrypting...
				 */
				goto RetryFault;
			}
			ASSERT_PAGE_DECRYPTED(m);

			if (VM_FAULT_NEED_CS_VALIDATION(map->pmap, m)) {
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
						if (real_map != map)
							vm_map_unlock(real_map);

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
				if ((fault_type & VM_PROT_WRITE) == 0) {
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
					prot &= ~VM_PROT_WRITE;
				}
				goto FastPmapEnter;
			}

			if ((fault_type & VM_PROT_WRITE) == 0) {

				prot &= ~VM_PROT_WRITE;

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
				/*
				 * prepare for the pmap_enter...
				 * object and map are both locked
				 * m contains valid data
				 * object == m->object
				 * cur_object == NULL or it's been unlocked
				 * no paging references on either object or cur_object
				 */
#if	MACH_KDB
				if (db_watchpoint_list && (fault_type & VM_PROT_WRITE) == 0)
					prot &= ~VM_PROT_WRITE;
#endif
				if (caller_pmap) {
				        kr = vm_fault_enter(m,
							    caller_pmap,
							    caller_pmap_addr,
							    prot,
							    wired,
							    change_wiring,
							    fault_info.no_cache,
							    &type_of_fault);
				} else {
				        kr = vm_fault_enter(m,
							    pmap,
							    vaddr,
							    prot,
							    wired,
							    change_wiring,
							    fault_info.no_cache,
							    &type_of_fault);
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

				if (need_collapse == TRUE)
				        vm_object_collapse(object, offset, TRUE);

				if (type_of_fault == DBG_PAGEIND_FAULT || type_of_fault == DBG_PAGEINV_FAULT || type_of_fault == DBG_CACHE_HIT_FAULT) {
				        /*
					 * evaluate access pattern and update state
					 * vm_fault_deactivate_behind depends on the
					 * state being up to date
					 */
				        vm_fault_is_sequential(object, cur_offset, fault_info.behavior);

					vm_fault_deactivate_behind(object, cur_offset, fault_info.behavior);
				}
				/*
				 * That's it, clean up and return.
				 */
				if (m->busy)
				        PAGE_WAKEUP_DONE(m);

				vm_object_unlock(object);

				vm_map_unlock_read(map);
				if (real_map != map)
					vm_map_unlock(real_map);

				goto done;
			}
			/*
			 * COPY ON WRITE FAULT
			 */
			assert(object_lock_type == OBJECT_LOCK_EXCLUSIVE);

			if (vm_page_throttled()) {
				/*
				 * drop all of our locks...
				 * wait until the free queue is
				 * pumped back up and then
				 * redrive the fault
				 */
				if (object != cur_object)
					vm_object_unlock(cur_object);
				vm_object_unlock(object);
				vm_map_unlock_read(map);
				if (real_map != map)
					vm_map_unlock(real_map);

				if (NEED_TO_HARD_THROTTLE_THIS_TASK())
					delay(HARD_THROTTLE_DELAY);

				if (!current_thread_aborted() && vm_page_wait((change_wiring) ? 
						 THREAD_UNINT :
						 THREAD_ABORTSAFE))
					goto RetryFault;
				kr = KERN_ABORTED;
				goto done;
			}
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
			 *
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
			m = vm_page_grab();

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
			m->dirty = TRUE;

			/*
			 * Now cope with the source page and object
			 */
			if (object->ref_count > 1 && cur_m->pmapped)
			        pmap_disconnect(cur_m->phys_page);

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

			if (need_collapse == FALSE)
			        vm_fault_collapse_skipped++;
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
			        if (MUST_ASK_PAGER(cur_object, cur_offset) == TRUE) {
				        /*
					 * May have to talk to a pager...
					 * take the slow path.
					 */
				        break;
				}
				/*
				 * existence map present and indicates
				 * that the pager doesn't have this page
				 */
			}
			if (cur_object->shadow == VM_OBJECT_NULL) {
				/*
				 * Zero fill fault.  Page gets
				 * inserted into the original object.
				 */
				if (cur_object->shadow_severed ||
				    VM_OBJECT_PURGEABLE_FAULT_ERROR(cur_object))
				{
					if (object != cur_object)
					        vm_object_unlock(cur_object);
					vm_object_unlock(object);

					vm_map_unlock_read(map);
					if (real_map != map)
						vm_map_unlock(real_map);

					kr = KERN_MEMORY_ERROR;
					goto done;
				}
				if (vm_page_throttled()) {
					/*
					 * drop all of our locks...
					 * wait until the free queue is
					 * pumped back up and then
					 * redrive the fault
					 */
					if (object != cur_object)
						vm_object_unlock(cur_object);
					vm_object_unlock(object);
					vm_map_unlock_read(map);
					if (real_map != map)
						vm_map_unlock(real_map);

					if (NEED_TO_HARD_THROTTLE_THIS_TASK())
						delay(HARD_THROTTLE_DELAY);

					if (!current_thread_aborted() && vm_page_wait((change_wiring) ? 
							 THREAD_UNINT :
							 THREAD_ABORTSAFE))
						goto RetryFault;
					kr = KERN_ABORTED;
					goto done;
				}
				if (vm_backing_store_low) {
				        /*
					 * we are protecting the system from
					 * backing store exhaustion... 
					 * must take the slow path if we're
					 * not privileged
					 */
					if (!(current_task()->priv_flags & VM_BACKING_STORE_PRIV))
					        break;
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
						if (real_map != map)
						        vm_map_unlock(real_map);

						goto RetryFault;
					}
				}
				m = vm_page_alloc(object, offset);

				if (m == VM_PAGE_NULL) {
				        /*
					 * no free page currently available...
					 * must take the slow path
					 */
					break;
				}

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
			cur_offset += cur_object->shadow_offset;
			new_object = cur_object->shadow;

			/*
			 * take the new_object's lock with the indicated state
			 */
			if (cur_object_lock_type == OBJECT_LOCK_SHARED)
			        vm_object_lock_shared(new_object);
			else
			        vm_object_lock(new_object);

			if (cur_object != object)
				vm_object_unlock(cur_object);

			cur_object = new_object;

			continue;
		}
	}
	/*
	 * Cleanup from fast fault failure.  Drop any object
	 * lock other than original and drop map lock.
	 */
	if (object != cur_object)
		vm_object_unlock(cur_object);

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
	if (real_map != map)
		vm_map_unlock(real_map);

   	/*
	 * Make a reference to this object to
	 * prevent its disposal while we are messing with
	 * it.  Once we have the reference, the map is free
	 * to be diddled.  Since objects reference their
	 * shadows (and copies), they will stay around as well.
	 */
	vm_object_reference_locked(object);
	vm_object_paging_begin(object);

	XPR(XPR_VM_FAULT,"vm_fault -> vm_fault_page\n",0,0,0,0,0);

	error_code = 0;

	kr = vm_fault_page(object, offset, fault_type,
			   (change_wiring && !wired),
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
	        /*
		 * we didn't succeed, lose the object reference immediately.
		 */
		vm_object_deallocate(object);

		/*
		 * See why we failed, and take corrective action.
		 */
		switch (kr) {
		case VM_FAULT_MEMORY_SHORTAGE:
			if (vm_page_wait((change_wiring) ? 
					 THREAD_UNINT :
					 THREAD_ABORTSAFE))
				goto RetryFault;
			/*
			 * fall thru
			 */
		case VM_FAULT_INTERRUPTED:
			kr = KERN_ABORTED;
			goto done;
		case VM_FAULT_RETRY:
			goto RetryFault;
		case VM_FAULT_MEMORY_ERROR:
			if (error_code)
				kr = error_code;
			else
				kr = KERN_MEMORY_ERROR;
			goto done;
		default:
			panic("vm_fault: unexpected error 0x%x from "
			      "vm_fault_page()\n", kr);
		}
	}
	m = result_page;

	if (m != VM_PAGE_NULL) {
		assert((change_wiring && !wired) ?
	   	    (top_page == VM_PAGE_NULL) :
	   	    ((top_page == VM_PAGE_NULL) == (m->object == object)));
	}

	/*
	 * What to do with the resulting page from vm_fault_page
	 * if it doesn't get entered into the physical map:
	 */
#define RELEASE_PAGE(m)					\
	MACRO_BEGIN					\
	PAGE_WAKEUP_DONE(m);				\
	if (!m->active && !m->inactive && !m->throttled) {		\
		vm_page_lockspin_queues();				\
		if (!m->active && !m->inactive && !m->throttled)	\
			vm_page_activate(m);				\
		vm_page_unlock_queues();				\
	}								\
	MACRO_END

	/*
	 * We must verify that the maps have not changed
	 * since our last lookup.
	 */
	if (m != VM_PAGE_NULL) {
		old_copy_object = m->object->copy;
		vm_object_unlock(m->object);
	} else {
		old_copy_object = VM_OBJECT_NULL;
		vm_object_unlock(object);
	}

	/*
	 * no object locks are held at this point
	 */
	if ((map != original_map) || !vm_map_verify(map, &version)) {
		vm_object_t		retry_object;
		vm_object_offset_t	retry_offset;
		vm_prot_t		retry_prot;

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
		vm_map_lock_read(map);

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
			        /*
				 * retake the lock so that
				 * we can drop the paging reference
				 * in vm_fault_cleanup and do the
				 * PAGE_WAKEUP_DONE in RELEASE_PAGE
				 */
				vm_object_lock(m->object);

				RELEASE_PAGE(m);

				vm_fault_cleanup(m->object, top_page);
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
			if (real_map != map)
				vm_map_unlock(real_map);

			if (m != VM_PAGE_NULL) {
			        /*
				 * retake the lock so that
				 * we can drop the paging reference
				 * in vm_fault_cleanup and do the
				 * PAGE_WAKEUP_DONE in RELEASE_PAGE
				 */
			        vm_object_lock(m->object);

				RELEASE_PAGE(m);

				vm_fault_cleanup(m->object, top_page);
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
		prot &= retry_prot;
	}
	if (m != VM_PAGE_NULL) {
		vm_object_lock(m->object);

		if (m->object->copy != old_copy_object) {
		        /*
			 * The copy object changed while the top-level object
			 * was unlocked, so take away write permission.
			 */
			prot &= ~VM_PROT_WRITE;
		}
	} else
		vm_object_lock(object);

	/*
	 * If we want to wire down this page, but no longer have
	 * adequate permissions, we must start all over.
	 */
	if (wired && (fault_type != (prot | VM_PROT_WRITE))) {

		vm_map_verify_done(map, &version);
		if (real_map != map)
			vm_map_unlock(real_map);

		if (m != VM_PAGE_NULL) {
			RELEASE_PAGE(m);

			vm_fault_cleanup(m->object, top_page);
		} else
		        vm_fault_cleanup(object, top_page);

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
					    wired,
					    change_wiring,
					    fault_info.no_cache,
					    &type_of_fault);
		} else {
			kr = vm_fault_enter(m,
					    pmap,
					    vaddr,
					    prot,
					    wired,
					    change_wiring,
					    fault_info.no_cache,
					    &type_of_fault);
		}
		if (kr != KERN_SUCCESS) {
			/* abort this page fault */
			vm_map_verify_done(map, &version);
			if (real_map != map)
				vm_map_unlock(real_map);
			PAGE_WAKEUP_DONE(m);
			vm_fault_cleanup(m->object, top_page);
			vm_object_deallocate(object);
			goto done;
		}
	} else {

		vm_map_entry_t		entry;
		vm_map_offset_t		laddr;
		vm_map_offset_t		ldelta, hdelta;

		/* 
		 * do a pmap block mapping from the physical address
		 * in the object 
		 */

#ifdef ppc
		/* While we do not worry about execution protection in   */
		/* general, certian pages may have instruction execution */
		/* disallowed.  We will check here, and if not allowed   */
		/* to execute, we return with a protection failure.      */

		if ((fault_type & VM_PROT_EXECUTE) &&
			(!pmap_eligible_for_execute((ppnum_t)(object->shadow_offset >> 12)))) {

			vm_map_verify_done(map, &version);

			if (real_map != map)
				vm_map_unlock(real_map);

			vm_fault_cleanup(object, top_page);
			vm_object_deallocate(object);

			kr = KERN_PROTECTION_FAILURE;
			goto done;
		}
#endif	/* ppc */

		if (real_map != map)
			vm_map_unlock(real_map);

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
			if (ldelta > (laddr - entry->vme_start))
				ldelta = laddr - entry->vme_start;
			if (hdelta > (entry->vme_end - laddr))
				hdelta = entry->vme_end - laddr;
			if (entry->is_sub_map) {
				
				laddr = (laddr - entry->vme_start) 
							+ entry->offset;
				vm_map_lock_read(entry->object.sub_map);

				if (map != real_map)
					vm_map_unlock_read(map);
				if (entry->use_pmap) {
					vm_map_unlock_read(real_map);
					real_map = entry->object.sub_map;
				}
				map = entry->object.sub_map;
				
			} else {
				break;
			}
		}

		if (vm_map_lookup_entry(map, laddr, &entry) && 
					(entry->object.vm_object != NULL) &&
					(entry->object.vm_object == object)) {

			int superpage = (!object->pager_created && object->phys_contiguous)? VM_MEM_SUPERPAGE : 0;
			if (caller_pmap) {
				/*
				 * Set up a block mapped area
				 */
				assert((uint32_t)((ldelta + hdelta) >> 12) == ((ldelta + hdelta) >> 12));
				pmap_map_block(caller_pmap, 
					       (addr64_t)(caller_pmap_addr - ldelta), 
					       (ppnum_t)((((vm_map_offset_t) (entry->object.vm_object->shadow_offset)) +
							  entry->offset + (laddr - entry->vme_start) - ldelta) >> 12),
					       (uint32_t)((ldelta + hdelta) >> 12), prot, 
					       (VM_WIMG_MASK & (int)object->wimg_bits) | superpage, 0);
			} else { 
				/*
				 * Set up a block mapped area
				 */
				assert((uint32_t)((ldelta + hdelta) >> 12) == ((ldelta + hdelta) >> 12));
				pmap_map_block(real_map->pmap, 
					       (addr64_t)(vaddr - ldelta), 
					       (ppnum_t)((((vm_map_offset_t)(entry->object.vm_object->shadow_offset)) +
							  entry->offset + (laddr - entry->vme_start) - ldelta) >> 12),
					       (uint32_t)((ldelta + hdelta) >> 12), prot, 
					       (VM_WIMG_MASK & (int)object->wimg_bits) | superpage, 0);
			}
		}
	}

	/*
	 * Unlock everything, and return
	 */
	vm_map_verify_done(map, &version);
	if (real_map != map)
		vm_map_unlock(real_map);

	if (m != VM_PAGE_NULL) {
		PAGE_WAKEUP_DONE(m);

		vm_fault_cleanup(m->object, top_page);
	} else
	        vm_fault_cleanup(object, top_page);

	vm_object_deallocate(object);

#undef	RELEASE_PAGE

	kr = KERN_SUCCESS;
done:
	thread_interrupt_level(interruptible_state);

	KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, 2)) | DBG_FUNC_END,
			      (int)((uint64_t)vaddr >> 32),
			      (int)vaddr,
			      kr,
			      type_of_fault,
			      0);

	return (kr);
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
	pmap_t		pmap,
	vm_map_offset_t	pmap_addr)
{

	register vm_map_offset_t	va;
	register vm_map_offset_t	end_addr = entry->vme_end;
	register kern_return_t	rc;

	assert(entry->in_transition);

	if ((entry->object.vm_object != NULL) && 
			!entry->is_sub_map && 
			entry->object.vm_object->phys_contiguous) {
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
		if ((rc = vm_fault_wire_fast(
			map, va, entry, pmap, 
			pmap_addr + (va - entry->vme_start)
			)) != KERN_SUCCESS) {
			rc = vm_fault(map, va, VM_PROT_NONE, TRUE, 
			  	(pmap == kernel_pmap) ? 
					THREAD_UNINT : THREAD_ABORTSAFE, 
				pmap, pmap_addr + (va - entry->vme_start));
			DTRACE_VM2(softlock, int, 1, (uint64_t *), NULL);
		}

		if (rc != KERN_SUCCESS) {
			struct vm_map_entry	tmp_entry = *entry;

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
	vm_map_t	map,
	vm_map_entry_t	entry,
	boolean_t	deallocate,
	pmap_t		pmap,
	vm_map_offset_t	pmap_addr)
{
	register vm_map_offset_t	va;
	register vm_map_offset_t	end_addr = entry->vme_end;
	vm_object_t		object;
	struct vm_object_fault_info fault_info;

	object = (entry->is_sub_map)
			? VM_OBJECT_NULL : entry->object.vm_object;

	/*
	 * If it's marked phys_contiguous, then vm_fault_wire() didn't actually
	 * do anything since such memory is wired by default.  So we don't have
	 * anything to undo here.
	 */

	if (object != VM_OBJECT_NULL && object->phys_contiguous)
		return;

	fault_info.interruptible = THREAD_UNINT;
	fault_info.behavior = entry->behavior;
	fault_info.user_tag = entry->alias;
	fault_info.lo_offset = entry->offset;
	fault_info.hi_offset = (entry->vme_end - entry->vme_start) + entry->offset;
	fault_info.no_cache = entry->no_cache;
	fault_info.stealth = TRUE;

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
					TRUE, THREAD_UNINT, pmap, pmap_addr);
		} else {
		 	vm_prot_t	prot;
			vm_page_t	result_page;
			vm_page_t	top_page;
			vm_object_t	result_object;
			vm_fault_return_t result;

			if (end_addr - va > (vm_size_t) -1) {
				/* 32-bit overflow */
				fault_info.cluster_size = (vm_size_t) (0 - PAGE_SIZE);
			} else {
				fault_info.cluster_size = (vm_size_t) (end_addr - va);
				assert(fault_info.cluster_size == end_addr - va);
			}

			do {
				prot = VM_PROT_NONE;

				vm_object_lock(object);
				vm_object_paging_begin(object);
				XPR(XPR_VM_FAULT,
					"vm_fault_unwire -> vm_fault_page\n",
					0,0,0,0,0);
			 	result = vm_fault_page(
					object,
					entry->offset + (va - entry->vme_start),
					VM_PROT_NONE, TRUE,
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

			if (result == VM_FAULT_MEMORY_ERROR && !object->alive)
				continue;

			if (result != VM_FAULT_SUCCESS)
				panic("vm_fault_unwire: failure");

			result_object = result_page->object;

			if ((pmap) && (result_page->phys_page != vm_page_guard_addr)) {
				pmap_change_wiring(pmap, 
						   pmap_addr + (va - entry->vme_start), FALSE);
			}
			if (deallocate) {
				assert(result_page->phys_page !=
				       vm_page_fictitious_addr);
				pmap_disconnect(result_page->phys_page);
				VM_PAGE_FREE(result_page);
			} else {
				if (VM_PAGE_WIRED(result_page)) {
					vm_page_lockspin_queues();
					vm_page_unwire(result_page);
					vm_page_unlock_queues();
				}
				if(entry->zero_wired_pages) {
					pmap_zero_page(result_page->phys_page);
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
	__unused vm_map_t	map,
	vm_map_offset_t	va,
	vm_map_entry_t	entry,
	pmap_t			pmap,
	vm_map_offset_t	pmap_addr)
{
	vm_object_t		object;
	vm_object_offset_t	offset;
	register vm_page_t	m;
	vm_prot_t		prot;
	thread_t           	thread = current_thread();
	int			type_of_fault;
	kern_return_t		kr;

	VM_STAT_INCR(faults);

	if (thread != THREAD_NULL && thread->task != TASK_NULL)
	  thread->task->faults++;

/*
 *	Recovery actions
 */

#undef	RELEASE_PAGE
#define RELEASE_PAGE(m)	{				\
	PAGE_WAKEUP_DONE(m);				\
	vm_page_lockspin_queues();			\
	vm_page_unwire(m);				\
	vm_page_unlock_queues();			\
}


#undef	UNLOCK_THINGS
#define UNLOCK_THINGS	{				\
	vm_object_paging_end(object);			   \
	vm_object_unlock(object);			   \
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
	 * ENCRYPTED SWAP: use the slow fault path, since we'll need to
	 * decrypt the page before wiring it down.
	 */
	m = vm_page_lookup(object, offset);
	if ((m == VM_PAGE_NULL) || (m->busy) || (m->encrypted) ||
	    (m->unusual && ( m->error || m->restart || m->absent))) {

		GIVE_UP;
	}
	ASSERT_PAGE_DECRYPTED(m);

	if (m->fictitious &&
	    m->phys_page == vm_page_guard_addr) {
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
	 */
	type_of_fault = DBG_CACHE_HIT_FAULT;
	kr = vm_fault_enter(m,
			    pmap,
			    pmap_addr,
			    prot,
			    TRUE,
			    FALSE,
			    FALSE,
			    &type_of_fault);

done:
	/*
	 *	Unlock everything, and return
	 */

	PAGE_WAKEUP_DONE(m);
	UNLOCK_AND_DEALLOCATE;

	return kr;

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
	if (!page->active && !page->inactive && !page->throttled) {
		vm_page_lockspin_queues();
		if (!page->active && !page->inactive && !page->throttled)
			vm_page_activate(page);
		vm_page_unlock_queues();
	}
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
		vm_page_lockspin_queues();
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
	vm_map_size_t		*copy_size,		/* INOUT */
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

	vm_map_size_t		amount_left;
	vm_object_t		old_copy_object;
	kern_return_t		error = 0;
	vm_fault_return_t	result;

	vm_map_size_t		part_size;
	struct vm_object_fault_info fault_info_src;
	struct vm_object_fault_info fault_info_dst;

	/*
	 * In order not to confuse the clustered pageins, align
	 * the different offsets on a page boundary.
	 */

#define	RETURN(x)					\
	MACRO_BEGIN					\
	*copy_size -= amount_left;			\
	MACRO_RETURN(x);				\
	MACRO_END

	amount_left = *copy_size;

	fault_info_src.interruptible = interruptible;
	fault_info_src.behavior = VM_BEHAVIOR_SEQUENTIAL;
	fault_info_src.user_tag  = 0;
	fault_info_src.lo_offset = vm_object_trunc_page(src_offset);
	fault_info_src.hi_offset = fault_info_src.lo_offset + amount_left;
	fault_info_src.no_cache   = FALSE;
	fault_info_src.stealth = TRUE;

	fault_info_dst.interruptible = interruptible;
	fault_info_dst.behavior = VM_BEHAVIOR_SEQUENTIAL;
	fault_info_dst.user_tag  = 0;
	fault_info_dst.lo_offset = vm_object_trunc_page(dst_offset);
	fault_info_dst.hi_offset = fault_info_dst.lo_offset + amount_left;
	fault_info_dst.no_cache   = FALSE;
	fault_info_dst.stealth = TRUE;

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

		if (amount_left > (vm_size_t) -1) {
			/* 32-bit overflow */
			fault_info_dst.cluster_size = (vm_size_t) (0 - PAGE_SIZE);
		} else {
			fault_info_dst.cluster_size = (vm_size_t) amount_left;
			assert(fault_info_dst.cluster_size == amount_left);
		}

		XPR(XPR_VM_FAULT,"vm_fault_copy -> vm_fault_page\n",0,0,0,0,0);
		result = vm_fault_page(dst_object,
				       vm_object_trunc_page(dst_offset),
				       VM_PROT_WRITE|VM_PROT_READ,
				       FALSE,
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
			if (vm_page_wait(interruptible))
				goto RetryDestinationFault;
			/* fall thru */
		case VM_FAULT_INTERRUPTED:
			RETURN(MACH_SEND_INTERRUPTED);
		case VM_FAULT_SUCCESS_NO_VM_PAGE:
			/* success but no VM page: fail the copy */
			vm_object_paging_end(dst_object);
			vm_object_unlock(dst_object);
			/*FALLTHROUGH*/
		case VM_FAULT_MEMORY_ERROR:
			if (error)
				return (error);
			else
				return(KERN_MEMORY_ERROR);
		default:
			panic("vm_fault_copy: unexpected error 0x%x from "
			      "vm_fault_page()\n", result);
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

		vm_page_lockspin_queues();
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
						  vm_object_trunc_page(src_offset));
			if (src_page == dst_page) {
				src_prot = dst_prot;
				result_page = VM_PAGE_NULL;
			} else {
				src_prot = VM_PROT_READ;
				vm_object_paging_begin(src_object);

				if (amount_left > (vm_size_t) -1) {
					/* 32-bit overflow */
					fault_info_src.cluster_size = (vm_size_t) (0 - PAGE_SIZE);
				} else {
					fault_info_src.cluster_size = (vm_size_t) amount_left;
					assert(fault_info_src.cluster_size == amount_left);
				}

				XPR(XPR_VM_FAULT,
					"vm_fault_copy(2) -> vm_fault_page\n",
					0,0,0,0,0);
				result = vm_fault_page(
					src_object, 
					vm_object_trunc_page(src_offset),
					VM_PROT_READ, FALSE,
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
					if (vm_page_wait(interruptible))
						goto RetrySourceFault;
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
					if (error)
						return (error);
					else
						return(KERN_MEMORY_ERROR);
				default:
					panic("vm_fault_copy(2): unexpected "
					      "error 0x%x from "
					      "vm_fault_page()\n", result);
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

			src_po = src_offset - vm_object_trunc_page(src_offset);
			dst_po = dst_offset - vm_object_trunc_page(dst_offset);

			if (dst_po > src_po) {
				part_size = PAGE_SIZE - dst_po;
			} else {
				part_size = PAGE_SIZE - src_po;
			}
			if (part_size > (amount_left)){
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
		        if (m->busy || m->error || m->restart || m->absent) {
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


extern int cs_validation;

void
vm_page_validate_cs_mapped(
	vm_page_t	page,
	const void 	*kaddr)
{
	vm_object_t		object;
	vm_object_offset_t	offset;
	kern_return_t		kr;
	memory_object_t		pager;
	void			*blobs;
	boolean_t		validated, tainted;

	assert(page->busy);
	vm_object_lock_assert_exclusive(page->object);

	if (!cs_validation) {
		return;
	}

	if (page->wpmapped && !page->cs_tainted) {
		/*
		 * This page was mapped for "write" access sometime in the
		 * past and could still be modifiable in the future.
		 * Consider it tainted.
		 * [ If the page was already found to be "tainted", no
		 * need to re-validate. ]
		 */
		page->cs_validated = TRUE;
		page->cs_tainted = TRUE;
		if (cs_debug) {
			printf("CODESIGNING: vm_page_validate_cs: "
			       "page %p obj %p off 0x%llx "
			       "was modified\n",
			       page, page->object, page->offset);
		}
		vm_cs_validated_dirtied++;
	}

	if (page->cs_validated) {
		return;
	}

	vm_cs_validates++;

	object = page->object;
	assert(object->code_signed);
	offset = page->offset;

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
	kr = vnode_pager_get_object_cs_blobs(pager, &blobs);
	if (kr != KERN_SUCCESS) {
		blobs = NULL;
	}

	/* verify the SHA1 hash for this page */
	validated = cs_validate_page(blobs,
				     offset + object->paging_offset,
				     (const void *)kaddr,
				     &tainted);

	page->cs_validated = validated;
	if (validated) {
		page->cs_tainted = tainted;
	}
}

void
vm_page_validate_cs(
	vm_page_t	page)
{
	vm_object_t		object;
	vm_object_offset_t	offset;
	vm_map_offset_t		koffset;
	vm_map_size_t		ksize;
	vm_offset_t		kaddr;
	kern_return_t		kr;
	boolean_t		busy_page;

	vm_object_lock_assert_held(page->object);

	if (!cs_validation) {
		return;
	}

	if (page->wpmapped && !page->cs_tainted) {
		vm_object_lock_assert_exclusive(page->object);

		/*
		 * This page was mapped for "write" access sometime in the
		 * past and could still be modifiable in the future.
		 * Consider it tainted.
		 * [ If the page was already found to be "tainted", no
		 * need to re-validate. ]
		 */
		page->cs_validated = TRUE;
		page->cs_tainted = TRUE;
		if (cs_debug) {
			printf("CODESIGNING: vm_page_validate_cs: "
			       "page %p obj %p off 0x%llx "
			       "was modified\n",
			       page, page->object, page->offset);
		}
		vm_cs_validated_dirtied++;
	}

	if (page->cs_validated) {
		return;
	}

	vm_object_lock_assert_exclusive(page->object);

	object = page->object;
	assert(object->code_signed);
	offset = page->offset;

	busy_page = page->busy;
	if (!busy_page) {
		/* keep page busy while we map (and unlock) the VM object */
		page->busy = TRUE;
	}
	
	/*
	 * Take a paging reference on the VM object
	 * to protect it from collapse or bypass,
	 * and keep it from disappearing too.
	 */
	vm_object_paging_begin(object);

	/* map the page in the kernel address space */
	koffset = 0;
	ksize = PAGE_SIZE_64;
	kr = vm_paging_map_object(&koffset,
				  page,
				  object,
				  offset,
				  &ksize,
				  VM_PROT_READ,
				  FALSE); /* can't unlock object ! */
	if (kr != KERN_SUCCESS) {
		panic("vm_page_validate_cs: could not map page: 0x%x\n", kr);
	}
	kaddr = CAST_DOWN(vm_offset_t, koffset);

	/* validate the mapped page */
	vm_page_validate_cs_mapped(page, (const void *) kaddr);

	assert(page->busy);
	assert(object == page->object);
	vm_object_lock_assert_exclusive(object);

	if (!busy_page) {
		PAGE_WAKEUP_DONE(page);
	}
	if (koffset != 0) {
		/* unmap the map from the kernel address space */
		vm_paging_unmap_object(object, koffset, koffset + ksize);
		koffset = 0;
		ksize = 0;
		kaddr = 0;
	}
	vm_object_paging_end(object);
}
