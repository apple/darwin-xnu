/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
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
 *	File:	vm/memory_object.c
 *	Author:	Michael Wayne Young
 *
 *	External memory management interface control functions.
 */

#include <advisory_pageout.h>

/*
 *	Interface dependencies:
 */

#include <mach/std_types.h>	/* For pointer_t */
#include <mach/mach_types.h>

#include <mach/mig.h>
#include <mach/kern_return.h>
#include <mach/memory_object.h>
#include <mach/memory_object_default.h>
#include <mach/memory_object_control_server.h>
#include <mach/host_priv_server.h>
#include <mach/boolean.h>
#include <mach/vm_prot.h>
#include <mach/message.h>

/*
 *	Implementation dependencies:
 */
#include <string.h>		/* For memcpy() */

#include <kern/xpr.h>		
#include <kern/host.h>
#include <kern/thread.h>	/* For current_thread() */
#include <kern/ipc_mig.h>
#include <kern/misc_protos.h>

#include <vm/vm_object.h>
#include <vm/vm_fault.h>
#include <vm/memory_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/pmap.h>		/* For pmap_clear_modify */
#include <vm/vm_kern.h>		/* For kernel_map, vm_move */
#include <vm/vm_map.h>		/* For vm_map_pageable */

#if	MACH_PAGEMAP
#include <vm/vm_external.h>
#endif	/* MACH_PAGEMAP */


memory_object_default_t	memory_manager_default = MEMORY_OBJECT_DEFAULT_NULL;
vm_size_t		memory_manager_default_cluster = 0;
decl_mutex_data(,	memory_manager_default_lock)

/*
 *	Forward ref to file-local function:
 */
boolean_t
vm_object_update(vm_object_t, vm_object_offset_t, 
		vm_size_t, memory_object_return_t, int, vm_prot_t);


/*
 *	Routine:	memory_object_should_return_page
 *
 *	Description:
 *		Determine whether the given page should be returned,
 *		based on the page's state and on the given return policy.
 *
 *		We should return the page if one of the following is true:
 *
 *		1. Page is dirty and should_return is not RETURN_NONE.
 *		2. Page is precious and should_return is RETURN_ALL.
 *		3. Should_return is RETURN_ANYTHING.
 *
 *		As a side effect, m->dirty will be made consistent
 *		with pmap_is_modified(m), if should_return is not
 *		MEMORY_OBJECT_RETURN_NONE.
 */

#define	memory_object_should_return_page(m, should_return) \
    (should_return != MEMORY_OBJECT_RETURN_NONE && \
     (((m)->dirty || ((m)->dirty = pmap_is_modified((m)->phys_addr))) || \
      ((m)->precious && (should_return) == MEMORY_OBJECT_RETURN_ALL) || \
      (should_return) == MEMORY_OBJECT_RETURN_ANYTHING))

typedef	int	memory_object_lock_result_t;

#define MEMORY_OBJECT_LOCK_RESULT_DONE          0
#define MEMORY_OBJECT_LOCK_RESULT_MUST_BLOCK    1
#define MEMORY_OBJECT_LOCK_RESULT_MUST_CLEAN    2
#define MEMORY_OBJECT_LOCK_RESULT_MUST_RETURN   3

memory_object_lock_result_t memory_object_lock_page(
				vm_page_t		m,
				memory_object_return_t	should_return,
				boolean_t		should_flush,
				vm_prot_t		prot);

/*
 *	Routine:	memory_object_lock_page
 *
 *	Description:
 *		Perform the appropriate lock operations on the
 *		given page.  See the description of
 *		"memory_object_lock_request" for the meanings
 *		of the arguments.
 *
 *		Returns an indication that the operation
 *		completed, blocked, or that the page must
 *		be cleaned.
 */
memory_object_lock_result_t
memory_object_lock_page(
	vm_page_t		m,
	memory_object_return_t	should_return,
	boolean_t		should_flush,
	vm_prot_t		prot)
{
        XPR(XPR_MEMORY_OBJECT,
            "m_o_lock_page, page 0x%X rtn %d flush %d prot %d\n",
            (integer_t)m, should_return, should_flush, prot, 0);

	/*
	 *	If we cannot change access to the page,
	 *	either because a mapping is in progress
	 *	(busy page) or because a mapping has been
	 *	wired, then give up.
	 */

	if (m->busy || m->cleaning)
		return(MEMORY_OBJECT_LOCK_RESULT_MUST_BLOCK);

	/*
	 *	Don't worry about pages for which the kernel
	 *	does not have any data.
	 */

	if (m->absent || m->error || m->restart) {
		if(m->error && should_flush) {
			/* dump the page, pager wants us to */
			/* clean it up and there is no      */
			/* relevant data to return */
			if(m->wire_count == 0) {
				VM_PAGE_FREE(m);
				return(MEMORY_OBJECT_LOCK_RESULT_DONE);
			}
		} else {
			return(MEMORY_OBJECT_LOCK_RESULT_DONE);
		}
	}

	assert(!m->fictitious);

	if (m->wire_count != 0) {
		/*
		 *	If no change would take place
		 *	anyway, return successfully.
		 *
		 *	No change means:
		 *		Not flushing AND
		 *		No change to page lock [2 checks]  AND
		 *		Should not return page
		 *
		 * XXX	This doesn't handle sending a copy of a wired
		 * XXX	page to the pager, but that will require some
		 * XXX	significant surgery.
		 */
		if (!should_flush &&
		    (m->page_lock == prot || prot == VM_PROT_NO_CHANGE) &&
		    ! memory_object_should_return_page(m, should_return)) {

			/*
			 *	Restart page unlock requests,
			 *	even though no change took place.
			 *	[Memory managers may be expecting
			 *	to see new requests.]
			 */
			m->unlock_request = VM_PROT_NONE;
			PAGE_WAKEUP(m);

			return(MEMORY_OBJECT_LOCK_RESULT_DONE);
		}

		return(MEMORY_OBJECT_LOCK_RESULT_MUST_BLOCK);
	}

	/*
	 *	If the page is to be flushed, allow
	 *	that to be done as part of the protection.
	 */

	if (should_flush)
		prot = VM_PROT_ALL;

	/*
	 *	Set the page lock.
	 *
	 *	If we are decreasing permission, do it now;
	 *	let the fault handler take care of increases
	 *	(pmap_page_protect may not increase protection).
	 */

	if (prot != VM_PROT_NO_CHANGE) {
		if ((m->page_lock ^ prot) & prot) {
			pmap_page_protect(m->phys_addr, VM_PROT_ALL & ~prot);
		}
#if 0
		/* code associated with the vestigial 
		 * memory_object_data_unlock
		 */
		m->page_lock = prot;
		m->lock_supplied = TRUE;
		if (prot != VM_PROT_NONE)
			m->unusual = TRUE;
		else
			m->unusual = FALSE;

		/*
		 *	Restart any past unlock requests, even if no
		 *	change resulted.  If the manager explicitly
		 *	requested no protection change, then it is assumed
		 *	to be remembering past requests.
		 */

		m->unlock_request = VM_PROT_NONE;
#endif /* 0 */
		PAGE_WAKEUP(m);
	}

	/*
	 *	Handle page returning.
	 */

	if (memory_object_should_return_page(m, should_return)) {

		/*
		 *	If we weren't planning
		 *	to flush the page anyway,
		 *	we may need to remove the
		 *	page from the pageout
		 *	system and from physical
		 *	maps now.
		 */
		
		vm_page_lock_queues();
		VM_PAGE_QUEUES_REMOVE(m);
		vm_page_unlock_queues();

		if (!should_flush)
			pmap_page_protect(m->phys_addr, VM_PROT_NONE);

		if (m->dirty)
			return(MEMORY_OBJECT_LOCK_RESULT_MUST_CLEAN);
		else
			return(MEMORY_OBJECT_LOCK_RESULT_MUST_RETURN);
	}

	/*
	 *	Handle flushing
	 */

	if (should_flush) {
		VM_PAGE_FREE(m);
	} else {
		extern boolean_t vm_page_deactivate_hint;

		/*
		 *	XXX Make clean but not flush a paging hint,
		 *	and deactivate the pages.  This is a hack
		 *	because it overloads flush/clean with
		 *	implementation-dependent meaning.  This only
		 *	happens to pages that are already clean.
		 */

		if (vm_page_deactivate_hint &&
		    (should_return != MEMORY_OBJECT_RETURN_NONE)) {
			vm_page_lock_queues();
			vm_page_deactivate(m);
			vm_page_unlock_queues();
		}
	}

	return(MEMORY_OBJECT_LOCK_RESULT_DONE);
}

#define LIST_REQ_PAGEOUT_PAGES(object, data_cnt, action, po) \
MACRO_BEGIN								\
									\
	register int		i;                                      \
	register vm_page_t	hp;					\
									\
	vm_object_unlock(object);					\
									\
	   	(void) memory_object_data_return(object->pager,		\
		po,							\
		data_cnt,						\
		(action == MEMORY_OBJECT_LOCK_RESULT_MUST_CLEAN),	\
		!should_flush);                                 	\
									\
	vm_object_lock(object);						\
MACRO_END

/*
 *	Routine:	memory_object_lock_request [user interface]
 *
 *	Description:
 *		Control use of the data associated with the given
 *		memory object.  For each page in the given range,
 *		perform the following operations, in order:
 *			1)  restrict access to the page (disallow
 *			    forms specified by "prot");
 *			2)  return data to the manager (if "should_return"
 *			    is RETURN_DIRTY and the page is dirty, or
 * 			    "should_return" is RETURN_ALL and the page
 *			    is either dirty or precious); and,
 *			3)  flush the cached copy (if "should_flush"
 *			    is asserted).
 *		The set of pages is defined by a starting offset
 *		("offset") and size ("size").  Only pages with the
 *		same page alignment as the starting offset are
 *		considered.
 *
 *		A single acknowledgement is sent (to the "reply_to"
 *		port) when these actions are complete.  If successful,
 *		the naked send right for reply_to is consumed.
 */

kern_return_t
memory_object_lock_request(
	memory_object_control_t		control,
	memory_object_offset_t		offset,
	memory_object_size_t		size,
	memory_object_return_t		should_return,
	int				flags,
	vm_prot_t			prot)
{
	vm_object_t	object;
	vm_object_offset_t	original_offset = offset;
	boolean_t		should_flush=flags & MEMORY_OBJECT_DATA_FLUSH;

        XPR(XPR_MEMORY_OBJECT,
	    "m_o_lock_request, control 0x%X off 0x%X size 0x%X flags %X prot %X\n",
	    (integer_t)control, offset, size, 
 	    (((should_return&1)<<1)|should_flush), prot);

	/*
	 *	Check for bogus arguments.
	 */
	object = memory_object_control_to_vm_object(control);
	if (object == VM_OBJECT_NULL)
		return (KERN_INVALID_ARGUMENT);

	if ((prot & ~VM_PROT_ALL) != 0 && prot != VM_PROT_NO_CHANGE)
		return (KERN_INVALID_ARGUMENT);

	size = round_page(size);

	/*
	 *	Lock the object, and acquire a paging reference to
	 *	prevent the memory_object reference from being released.
	 */
	vm_object_lock(object);
	vm_object_paging_begin(object);
	offset -= object->paging_offset;

	(void)vm_object_update(object,
		offset, size, should_return, flags, prot);

	vm_object_paging_end(object);
	vm_object_unlock(object);

	return (KERN_SUCCESS);
}

/*
 *	memory_object_release_name:  [interface]
 *
 *	Enforces name semantic on memory_object reference count decrement
 *	This routine should not be called unless the caller holds a name
 *	reference gained through the memory_object_named_create or the
 *	memory_object_rename call.
 *	If the TERMINATE_IDLE flag is set, the call will return if the
 *	reference count is not 1. i.e. idle with the only remaining reference
 *	being the name.
 *	If the decision is made to proceed the name field flag is set to
 *	false and the reference count is decremented.  If the RESPECT_CACHE
 *	flag is set and the reference count has gone to zero, the 
 *	memory_object is checked to see if it is cacheable otherwise when
 *	the reference count is zero, it is simply terminated.
 */

kern_return_t
memory_object_release_name(
	memory_object_control_t	control,
	int				flags)
{
	vm_object_t	object;

	object = memory_object_control_to_vm_object(control);
	if (object == VM_OBJECT_NULL)
		return (KERN_INVALID_ARGUMENT);

	return vm_object_release_name(object, flags);
}



/*
 *	Routine:	memory_object_destroy [user interface]
 *	Purpose:
 *		Shut down a memory object, despite the
 *		presence of address map (or other) references
 *		to the vm_object.
 */
kern_return_t
memory_object_destroy(
	memory_object_control_t	control,
	kern_return_t		reason)
{
	vm_object_t		object;

	object = memory_object_control_to_vm_object(control);
	if (object == VM_OBJECT_NULL)
		return (KERN_INVALID_ARGUMENT);

	return (vm_object_destroy(object, reason));
}

/*
 *	Routine:	vm_object_sync
 *
 *	Kernel internal function to synch out pages in a given
 *	range within an object to its memory manager.  Much the
 *	same as memory_object_lock_request but page protection
 *	is not changed.
 *
 *	If the should_flush and should_return flags are true pages
 *	are flushed, that is dirty & precious pages are written to
 *	the memory manager and then discarded.  If should_return
 *	is false, only precious pages are returned to the memory
 *	manager.
 *
 *	If should flush is false and should_return true, the memory
 *	manager's copy of the pages is updated.  If should_return
 *	is also false, only the precious pages are updated.  This
 *	last option is of limited utility.
 *
 *	Returns:
 *	FALSE		if no pages were returned to the pager
 *	TRUE		otherwise.
 */

boolean_t
vm_object_sync(
	vm_object_t		object,
	vm_object_offset_t	offset,
	vm_size_t		size,
	boolean_t		should_flush,
	boolean_t		should_return)
{
	boolean_t	rv;

        XPR(XPR_VM_OBJECT,
            "vm_o_sync, object 0x%X, offset 0x%X size 0x%x flush %d rtn %d\n",
            (integer_t)object, offset, size, should_flush, should_return);

	/*
	 * Lock the object, and acquire a paging reference to
	 * prevent the memory_object and control ports from
	 * being destroyed.
	 */
	vm_object_lock(object);
	vm_object_paging_begin(object);

	rv = vm_object_update(object, offset, size,
		(should_return) ?
			MEMORY_OBJECT_RETURN_ALL :
			MEMORY_OBJECT_RETURN_NONE,
		(should_flush) ?
			MEMORY_OBJECT_DATA_FLUSH : 0,
		VM_PROT_NO_CHANGE);


	vm_object_paging_end(object);
	vm_object_unlock(object);
	return rv;
}

/*
 *	Routine:	vm_object_update
 *	Description:
 *		Work function for m_o_lock_request(), vm_o_sync().
 *
 *		Called with object locked and paging ref taken.
 */
kern_return_t
vm_object_update(
	register vm_object_t		object,
	register vm_object_offset_t	offset,
	register vm_size_t		size,
	memory_object_return_t		should_return,
	int				flags,
	vm_prot_t			prot)
{
	register vm_page_t	m;
	vm_page_t		holding_page;
	vm_size_t		original_size = size;
	vm_object_offset_t	paging_offset = 0;
	vm_object_t		copy_object;
	vm_size_t		data_cnt = 0;
	vm_object_offset_t	last_offset = offset;
	memory_object_lock_result_t	page_lock_result;
	memory_object_lock_result_t	pageout_action;
	boolean_t		data_returned = FALSE;
	boolean_t		update_cow;
	boolean_t		should_flush = flags & MEMORY_OBJECT_DATA_FLUSH;
	boolean_t		pending_pageout = FALSE;

	/*
	 *	To avoid blocking while scanning for pages, save
	 *	dirty pages to be cleaned all at once.
	 *
	 *	XXXO A similar strategy could be used to limit the
	 *	number of times that a scan must be restarted for
	 *	other reasons.  Those pages that would require blocking
	 *	could be temporarily collected in another list, or
	 *	their offsets could be recorded in a small array.
	 */

	/*
	 * XXX	NOTE: May want to consider converting this to a page list
	 * XXX	vm_map_copy interface.  Need to understand object
	 * XXX	coalescing implications before doing so.
	 */

	update_cow = ((flags & MEMORY_OBJECT_DATA_FLUSH) 
			&& (!(flags & MEMORY_OBJECT_DATA_NO_CHANGE) &&
					!(flags & MEMORY_OBJECT_DATA_PURGE)))
				|| (flags & MEMORY_OBJECT_COPY_SYNC);
			

	if((((copy_object = object->copy) != NULL) && update_cow) ||
					(flags & MEMORY_OBJECT_DATA_SYNC)) {
		vm_size_t		i;
		vm_size_t		copy_size;
		vm_object_offset_t	copy_offset;
		vm_prot_t		prot;
		vm_page_t		page;
		vm_page_t		top_page;
		kern_return_t		error = 0;

		if(copy_object != NULL) {
		   /* translate offset with respect to shadow's offset */
		   copy_offset = (offset >= copy_object->shadow_offset)?
			offset - copy_object->shadow_offset :
			(vm_object_offset_t) 0;
		   if(copy_offset > copy_object->size)
			copy_offset = copy_object->size;

		   /* clip size with respect to shadow offset */
		   copy_size = (offset >= copy_object->shadow_offset) ?
			size : size - (copy_object->shadow_offset - offset);

		   if(copy_size <= 0) {
			copy_size = 0;
		   } else {
			copy_size = ((copy_offset + copy_size) 
				<= copy_object->size) ?
				copy_size : copy_object->size - copy_offset;
		   }
		   /* check for a copy_offset which is beyond the end of */
		   /* the copy_object */
		   if(copy_size < 0)
			copy_size = 0;

		   copy_size+=offset;

		   vm_object_unlock(object);
		   vm_object_lock(copy_object);
		} else {
			copy_object = object;

			copy_size   = offset + size;
			copy_offset = offset;
		}

		vm_object_paging_begin(copy_object);
		for (i=copy_offset; i<copy_size; i+=PAGE_SIZE) {
	RETRY_COW_OF_LOCK_REQUEST:
			prot = 	VM_PROT_WRITE|VM_PROT_READ;
			switch (vm_fault_page(copy_object, i, 
				VM_PROT_WRITE|VM_PROT_READ,
				FALSE,
				THREAD_UNINT,
				copy_offset,
				copy_offset+copy_size,
				VM_BEHAVIOR_SEQUENTIAL,
				&prot,
				&page,
				&top_page,
				(int *)0,
				&error,
			        FALSE,
				FALSE, NULL, 0)) {

			case VM_FAULT_SUCCESS:
				if(top_page) {
					vm_fault_cleanup(
						page->object, top_page);
					PAGE_WAKEUP_DONE(page);
					vm_page_lock_queues();
					if (!page->active && !page->inactive)
						vm_page_activate(page);
					vm_page_unlock_queues();
					vm_object_lock(copy_object);
					vm_object_paging_begin(copy_object);
				} else {
					PAGE_WAKEUP_DONE(page);
					vm_page_lock_queues();
					if (!page->active && !page->inactive)
						vm_page_activate(page);
					vm_page_unlock_queues();
				}
				break;
			case VM_FAULT_RETRY:
				prot = 	VM_PROT_WRITE|VM_PROT_READ;
				vm_object_lock(copy_object);
				vm_object_paging_begin(copy_object);
				goto RETRY_COW_OF_LOCK_REQUEST;
			case VM_FAULT_INTERRUPTED:
				prot = 	VM_PROT_WRITE|VM_PROT_READ;
				vm_object_lock(copy_object);
				vm_object_paging_begin(copy_object);
				goto RETRY_COW_OF_LOCK_REQUEST;
			case VM_FAULT_MEMORY_SHORTAGE:
				VM_PAGE_WAIT();
				prot = 	VM_PROT_WRITE|VM_PROT_READ;
				vm_object_lock(copy_object);
				vm_object_paging_begin(copy_object);
				goto RETRY_COW_OF_LOCK_REQUEST;
			case VM_FAULT_FICTITIOUS_SHORTAGE:
				vm_page_more_fictitious();
				prot = 	VM_PROT_WRITE|VM_PROT_READ;
				vm_object_lock(copy_object);
				vm_object_paging_begin(copy_object);
				goto RETRY_COW_OF_LOCK_REQUEST;
			case VM_FAULT_MEMORY_ERROR:
				vm_object_lock(object);
				goto BYPASS_COW_COPYIN;
			}

		}
		vm_object_paging_end(copy_object);
		if(copy_object != object) {
			vm_object_unlock(copy_object);
			vm_object_lock(object);
		}
	}
	if((flags & (MEMORY_OBJECT_DATA_SYNC | MEMORY_OBJECT_COPY_SYNC))) {
			return KERN_SUCCESS;
	}
	if(((copy_object = object->copy) != NULL) && 
					(flags & MEMORY_OBJECT_DATA_PURGE)) {
		copy_object->shadow_severed = TRUE;
		copy_object->shadowed = FALSE;
		copy_object->shadow = NULL;
		/* delete the ref the COW was holding on the target object */
		vm_object_deallocate(object);
	}
BYPASS_COW_COPYIN:

	for (;
	     size != 0;
	     size -= PAGE_SIZE, offset += PAGE_SIZE_64)
	{
	    /*
	     *	Limit the number of pages to be cleaned at once.
	     */
	    if (pending_pageout &&
		    data_cnt >= PAGE_SIZE * DATA_WRITE_MAX)
	    {
 		LIST_REQ_PAGEOUT_PAGES(object, data_cnt, 
				pageout_action, paging_offset);
		data_cnt = 0;
		pending_pageout = FALSE;
	    }

	    while ((m = vm_page_lookup(object, offset)) != VM_PAGE_NULL) {
		page_lock_result = memory_object_lock_page(m, should_return,
					should_flush, prot);

		XPR(XPR_MEMORY_OBJECT,
                    "m_o_update: lock_page, obj 0x%X offset 0x%X result %d\n",
                    (integer_t)object, offset, page_lock_result, 0, 0);

		switch (page_lock_result)
		{
		    case MEMORY_OBJECT_LOCK_RESULT_DONE:
			/*
			 *	End of a cluster of dirty pages.
			 */
			if(pending_pageout) {
 	    		    	LIST_REQ_PAGEOUT_PAGES(object, 
					data_cnt, pageout_action, 
					paging_offset);
				data_cnt = 0;
				pending_pageout = FALSE;
				continue;
			}
			break;

		    case MEMORY_OBJECT_LOCK_RESULT_MUST_BLOCK:
			/*
			 *	Since it is necessary to block,
			 *	clean any dirty pages now.
			 */
			if(pending_pageout) {
 	    		    	LIST_REQ_PAGEOUT_PAGES(object,
					data_cnt, pageout_action, 
					paging_offset);
				pending_pageout = FALSE;
				data_cnt = 0;
				continue;
			}

			PAGE_SLEEP(object, m, THREAD_UNINT);
			continue;

		    case MEMORY_OBJECT_LOCK_RESULT_MUST_CLEAN:
		    case MEMORY_OBJECT_LOCK_RESULT_MUST_RETURN:
			/*
			 * The clean and return cases are similar.
			 *
			 */

			/*
			 * if this would form a discontiguous block,
			 * clean the old pages and start anew.
			 *
			 */

			/*
			 * Mark the page busy since we unlock the
			 * object below.
			 */
			m->busy = TRUE;
			if (pending_pageout &&
			    (last_offset != offset ||
			     pageout_action != page_lock_result)) {
 	    			LIST_REQ_PAGEOUT_PAGES(object, 
						data_cnt, pageout_action, 
						paging_offset);
				pending_pageout = FALSE;
				data_cnt = 0;
			}
			m->busy = FALSE;
			holding_page = VM_PAGE_NULL;
			if(m->cleaning) {
				PAGE_SLEEP(object, m, THREAD_UNINT);
				continue;
			}
			if(!pending_pageout) {
				pending_pageout = TRUE;
				pageout_action = page_lock_result;
				paging_offset = offset;
			}
			if (should_flush) {
				vm_page_lock_queues();
				m->list_req_pending = TRUE;
				m->cleaning = TRUE;
				m->busy = TRUE;
				m->pageout = TRUE;
				vm_page_wire(m);
				vm_page_unlock_queues();
			} else {
				/*
				 * Clean but do not flush
				 */
				vm_page_lock_queues();
				m->list_req_pending = TRUE;
				m->cleaning = TRUE;
				vm_page_unlock_queues();

			}
			vm_object_unlock(object);


			data_cnt += PAGE_SIZE;
			last_offset = offset + PAGE_SIZE_64;
			data_returned = TRUE;

			vm_object_lock(object);
			break;
		}
		break;
	    }
	}

	/*
	 *	We have completed the scan for applicable pages.
	 *	Clean any pages that have been saved.
	 */
	if (pending_pageout) {
 	    LIST_REQ_PAGEOUT_PAGES(object,
				data_cnt, pageout_action, paging_offset);
	}
	return (data_returned);
}

/*
 *	Routine:	memory_object_synchronize_completed [user interface]
 *
 *	Tell kernel that previously synchronized data
 *	(memory_object_synchronize) has been queue or placed on the
 *	backing storage.
 *
 *	Note: there may be multiple synchronize requests for a given
 *	memory object outstanding but they will not overlap.
 */

kern_return_t
memory_object_synchronize_completed(
	memory_object_control_t	control,
	memory_object_offset_t	offset,
	vm_offset_t			length)
{
	vm_object_t			object;
	msync_req_t			msr;

        XPR(XPR_MEMORY_OBJECT,
	    "m_o_sync_completed, object 0x%X, offset 0x%X length 0x%X\n",
	    (integer_t)object, offset, length, 0, 0);

	/*
	 *      Look for bogus arguments
	 */

	object = memory_object_control_to_vm_object(control);
	if (object == VM_OBJECT_NULL)
		return (KERN_INVALID_ARGUMENT);

	vm_object_lock(object);

/*
 *	search for sync request structure
 */
	queue_iterate(&object->msr_q, msr, msync_req_t, msr_q) {
 		if (msr->offset == offset && msr->length == length) {
			queue_remove(&object->msr_q, msr, msync_req_t, msr_q);
			break;
		}
        }/* queue_iterate */

	if (queue_end(&object->msr_q, (queue_entry_t)msr)) {
		vm_object_unlock(object);
		return KERN_INVALID_ARGUMENT;
	}

	msr_lock(msr);
	vm_object_unlock(object);
	msr->flag = VM_MSYNC_DONE;
	msr_unlock(msr);
	thread_wakeup((event_t) msr);

	return KERN_SUCCESS;
}/* memory_object_synchronize_completed */

static kern_return_t
vm_object_set_attributes_common(
	vm_object_t	object,
	boolean_t	may_cache,
	memory_object_copy_strategy_t copy_strategy,
	boolean_t	temporary,
	vm_size_t	cluster_size,
        boolean_t	silent_overwrite,
	boolean_t	advisory_pageout)
{
	boolean_t	object_became_ready;

        XPR(XPR_MEMORY_OBJECT,
	    "m_o_set_attr_com, object 0x%X flg %x strat %d\n",
	    (integer_t)object, (may_cache&1)|((temporary&1)<1), copy_strategy, 0, 0);

	if (object == VM_OBJECT_NULL)
		return(KERN_INVALID_ARGUMENT);

	/*
	 *	Verify the attributes of importance
	 */

	switch(copy_strategy) {
		case MEMORY_OBJECT_COPY_NONE:
		case MEMORY_OBJECT_COPY_DELAY:
			break;
		default:
			return(KERN_INVALID_ARGUMENT);
	}

#if	!ADVISORY_PAGEOUT
	if (silent_overwrite || advisory_pageout)
		return(KERN_INVALID_ARGUMENT);

#endif	/* !ADVISORY_PAGEOUT */
	if (may_cache)
		may_cache = TRUE;
	if (temporary)
		temporary = TRUE;
	if (cluster_size != 0) {
		int	pages_per_cluster;
		pages_per_cluster = atop(cluster_size);
		/*
		 * Cluster size must be integral multiple of page size,
		 * and be a power of 2 number of pages.
		 */
		if ((cluster_size & (PAGE_SIZE-1)) ||
		    ((pages_per_cluster-1) & pages_per_cluster))
			return KERN_INVALID_ARGUMENT;
	}

	vm_object_lock(object);

	/*
	 *	Copy the attributes
	 */
	assert(!object->internal);
	object_became_ready = !object->pager_ready;
	object->copy_strategy = copy_strategy;
	object->can_persist = may_cache;
	object->temporary = temporary;
	object->silent_overwrite = silent_overwrite;
	object->advisory_pageout = advisory_pageout;
	if (cluster_size == 0)
		cluster_size = PAGE_SIZE;
	object->cluster_size = cluster_size;

	assert(cluster_size >= PAGE_SIZE &&
	       cluster_size % PAGE_SIZE == 0);

	/*
	 *	Wake up anyone waiting for the ready attribute
	 *	to become asserted.
	 */

	if (object_became_ready) {
		object->pager_ready = TRUE;
		vm_object_wakeup(object, VM_OBJECT_EVENT_PAGER_READY);
	}

	vm_object_unlock(object);

	return(KERN_SUCCESS);
}

/*
 *	Set the memory object attribute as provided.
 *
 *	XXX This routine cannot be completed until the vm_msync, clean 
 *	     in place, and cluster work is completed. See ifdef notyet
 *	     below and note that vm_object_set_attributes_common()
 *	     may have to be expanded.
 */
kern_return_t
memory_object_change_attributes(
	memory_object_control_t		control,
	memory_object_flavor_t		flavor,
	memory_object_info_t		attributes,
	mach_msg_type_number_t		count)
{
	vm_object_t             	object;
	kern_return_t   		result = KERN_SUCCESS;
	boolean_t       		temporary;
	boolean_t       		may_cache;
	boolean_t       		invalidate;
	vm_size_t			cluster_size;
	memory_object_copy_strategy_t	copy_strategy;
	boolean_t       		silent_overwrite;
	boolean_t			advisory_pageout;

	object = memory_object_control_to_vm_object(control);
	if (object == VM_OBJECT_NULL)
		return (KERN_INVALID_ARGUMENT);

	vm_object_lock(object);

	temporary = object->temporary;
	may_cache = object->can_persist;
	copy_strategy = object->copy_strategy;
	silent_overwrite = object->silent_overwrite;
	advisory_pageout = object->advisory_pageout;
#if notyet
	invalidate = object->invalidate;
#endif
	cluster_size = object->cluster_size;
	vm_object_unlock(object);	

	switch (flavor) {
	    case OLD_MEMORY_OBJECT_BEHAVIOR_INFO:
	    {
                old_memory_object_behave_info_t     behave;

                if (count != OLD_MEMORY_OBJECT_BEHAVE_INFO_COUNT) {
                        result = KERN_INVALID_ARGUMENT;
                        break;
                }

                behave = (old_memory_object_behave_info_t) attributes;

		temporary = behave->temporary;
		invalidate = behave->invalidate;
		copy_strategy = behave->copy_strategy;

		break;
	    }

	    case MEMORY_OBJECT_BEHAVIOR_INFO:
	    {
                memory_object_behave_info_t     behave;

                if (count != MEMORY_OBJECT_BEHAVE_INFO_COUNT) {
                        result = KERN_INVALID_ARGUMENT;
                        break;
                }

                behave = (memory_object_behave_info_t) attributes;

		temporary = behave->temporary;
		invalidate = behave->invalidate;
		copy_strategy = behave->copy_strategy;
		silent_overwrite = behave->silent_overwrite;
		advisory_pageout = behave->advisory_pageout;
		break;
	    }

	    case MEMORY_OBJECT_PERFORMANCE_INFO:
	    {
		memory_object_perf_info_t	perf;

                if (count != MEMORY_OBJECT_PERF_INFO_COUNT) {
                        result = KERN_INVALID_ARGUMENT;
                        break;
                }

                perf = (memory_object_perf_info_t) attributes;

		may_cache = perf->may_cache;
		cluster_size = round_page(perf->cluster_size);

		break;
	    }

	    case OLD_MEMORY_OBJECT_ATTRIBUTE_INFO:
	    {
		old_memory_object_attr_info_t	attr;

                if (count != OLD_MEMORY_OBJECT_ATTR_INFO_COUNT) {
                        result = KERN_INVALID_ARGUMENT;
                        break;
                }

		attr = (old_memory_object_attr_info_t) attributes;

                may_cache = attr->may_cache;
                copy_strategy = attr->copy_strategy;
		cluster_size = page_size;

		break;
	    }

	    case MEMORY_OBJECT_ATTRIBUTE_INFO:
	    {
		memory_object_attr_info_t	attr;

                if (count != MEMORY_OBJECT_ATTR_INFO_COUNT) {
                        result = KERN_INVALID_ARGUMENT;
                        break;
                }

		attr = (memory_object_attr_info_t) attributes;

		copy_strategy = attr->copy_strategy;
                may_cache = attr->may_cache_object;
		cluster_size = attr->cluster_size;
		temporary = attr->temporary;

		break;
	    }

	    default:
		result = KERN_INVALID_ARGUMENT;
		break;
	}

	if (result != KERN_SUCCESS)
		return(result);

	if (copy_strategy == MEMORY_OBJECT_COPY_TEMPORARY) {
		copy_strategy = MEMORY_OBJECT_COPY_DELAY;
		temporary = TRUE;
	} else {
		temporary = FALSE;
	}

	/*
	 * XXX	may_cache may become a tri-valued variable to handle
	 * XXX	uncache if not in use.
	 */
	return (vm_object_set_attributes_common(object,
						     may_cache,
						     copy_strategy,
						     temporary,
						     cluster_size,
						     silent_overwrite,
						     advisory_pageout));
}

kern_return_t
memory_object_get_attributes(
        memory_object_control_t	control,
        memory_object_flavor_t 	flavor,
	memory_object_info_t	attributes,	/* pointer to OUT array */
	mach_msg_type_number_t	*count)		/* IN/OUT */
{
	kern_return_t 		ret = KERN_SUCCESS;
	vm_object_t		object;

	object = memory_object_control_to_vm_object(control);
	if (object == VM_OBJECT_NULL)
		return (KERN_INVALID_ARGUMENT);

        vm_object_lock(object);

	switch (flavor) {
	    case OLD_MEMORY_OBJECT_BEHAVIOR_INFO:
	    {
		old_memory_object_behave_info_t	behave;

		if (*count < OLD_MEMORY_OBJECT_BEHAVE_INFO_COUNT) {
			ret = KERN_INVALID_ARGUMENT;
			break;
		}

		behave = (old_memory_object_behave_info_t) attributes;
		behave->copy_strategy = object->copy_strategy;
		behave->temporary = object->temporary;
#if notyet	/* remove when vm_msync complies and clean in place fini */
                behave->invalidate = object->invalidate;
#else
		behave->invalidate = FALSE;
#endif

		*count = OLD_MEMORY_OBJECT_BEHAVE_INFO_COUNT;
		break;
	    }

	    case MEMORY_OBJECT_BEHAVIOR_INFO:
	    {
		memory_object_behave_info_t	behave;

		if (*count < MEMORY_OBJECT_BEHAVE_INFO_COUNT) {
                        ret = KERN_INVALID_ARGUMENT;
                        break;
                }

                behave = (memory_object_behave_info_t) attributes;
                behave->copy_strategy = object->copy_strategy;
		behave->temporary = object->temporary;
#if notyet	/* remove when vm_msync complies and clean in place fini */
                behave->invalidate = object->invalidate;
#else
		behave->invalidate = FALSE;
#endif
		behave->advisory_pageout = object->advisory_pageout;
		behave->silent_overwrite = object->silent_overwrite;
                *count = MEMORY_OBJECT_BEHAVE_INFO_COUNT;
		break;
	    }

	    case MEMORY_OBJECT_PERFORMANCE_INFO:
	    {
		memory_object_perf_info_t	perf;

		if (*count < MEMORY_OBJECT_PERF_INFO_COUNT) {
			ret = KERN_INVALID_ARGUMENT;
			break;
		}

		perf = (memory_object_perf_info_t) attributes;
		perf->cluster_size = object->cluster_size;
		perf->may_cache = object->can_persist;

		*count = MEMORY_OBJECT_PERF_INFO_COUNT;
		break;
	    }

            case OLD_MEMORY_OBJECT_ATTRIBUTE_INFO:
            {
                old_memory_object_attr_info_t       attr;

                if (*count < OLD_MEMORY_OBJECT_ATTR_INFO_COUNT) {
                        ret = KERN_INVALID_ARGUMENT;
                        break;
                }

                attr = (old_memory_object_attr_info_t) attributes;
        	attr->may_cache = object->can_persist;
        	attr->copy_strategy = object->copy_strategy;

                *count = OLD_MEMORY_OBJECT_ATTR_INFO_COUNT;
                break;
            }

            case MEMORY_OBJECT_ATTRIBUTE_INFO:
            {
                memory_object_attr_info_t       attr;

                if (*count < MEMORY_OBJECT_ATTR_INFO_COUNT) {
                        ret = KERN_INVALID_ARGUMENT;
                        break;
                }

                attr = (memory_object_attr_info_t) attributes;
        	attr->copy_strategy = object->copy_strategy;
		attr->cluster_size = object->cluster_size;
        	attr->may_cache_object = object->can_persist;
		attr->temporary = object->temporary;

                *count = MEMORY_OBJECT_ATTR_INFO_COUNT;
                break;
            }

	    default:
		ret = KERN_INVALID_ARGUMENT;
		break;
	}

        vm_object_unlock(object);

        return(ret);
}


/*  
 *	Routine:	memory_object_upl_request [interface]
 *	Purpose:
 *		Cause the population of a portion of a vm_object.
 *		Depending on the nature of the request, the pages
 *		returned may be contain valid data or be uninitialized.
 *
 */

kern_return_t
memory_object_upl_request(
	memory_object_control_t	control,
	memory_object_offset_t	offset,
	vm_size_t		size,
	upl_t			*upl_ptr,
	upl_page_info_array_t	user_page_list,
	unsigned int		*page_list_count,
	int			cntrl_flags)
{
	vm_object_t		object;

	object = memory_object_control_to_vm_object(control);
	if (object == VM_OBJECT_NULL)
		return (KERN_INVALID_ARGUMENT);

	return vm_object_upl_request(object,
				     offset,
				     size,
				     upl_ptr,
				     user_page_list,
				     page_list_count,
				     cntrl_flags);
}

/*  
 *	Routine:	memory_object_super_upl_request [interface]
 *	Purpose:
 *		Cause the population of a portion of a vm_object
 *		in much the same way as memory_object_upl_request.
 *		Depending on the nature of the request, the pages
 *		returned may be contain valid data or be uninitialized.
 *		However, the region may be expanded up to the super
 *		cluster size provided.
 */

kern_return_t
memory_object_super_upl_request(
	memory_object_control_t control,
	memory_object_offset_t	offset,
	vm_size_t		size,
	vm_size_t		super_cluster,
	upl_t			*upl,
	upl_page_info_t		*user_page_list,
	unsigned int		*page_list_count,
	int			cntrl_flags)
{
	vm_object_t		object;

	object = memory_object_control_to_vm_object(control);
	if (object == VM_OBJECT_NULL)
		return (KERN_INVALID_ARGUMENT);

	return vm_object_super_upl_request(object,
					   offset,
					   size,
					   super_cluster,
					   upl,
					   user_page_list,
					   page_list_count,
					   cntrl_flags);
}

int vm_stat_discard_cleared_reply = 0;
int vm_stat_discard_cleared_unset = 0;
int vm_stat_discard_cleared_too_late = 0;



/*
 *	Routine:	host_default_memory_manager [interface]
 *	Purpose:
 *		set/get the default memory manager port and default cluster
 *		size.
 *
 *		If successful, consumes the supplied naked send right.
 */
kern_return_t
host_default_memory_manager(
	host_priv_t		host_priv,
	memory_object_default_t	*default_manager,
	vm_size_t		cluster_size)
{
	memory_object_default_t current_manager;
	memory_object_default_t new_manager;
	memory_object_default_t returned_manager;

	if (host_priv == HOST_PRIV_NULL)
		return(KERN_INVALID_HOST);

	assert(host_priv == &realhost);

	new_manager = *default_manager;
	mutex_lock(&memory_manager_default_lock);
	current_manager = memory_manager_default;

	if (new_manager == MEMORY_OBJECT_DEFAULT_NULL) {
		/*
		 *	Retrieve the current value.
		 */
		memory_object_default_reference(current_manager);
		returned_manager = current_manager;
	} else {
		/*
		 *	Retrieve the current value,
		 *	and replace it with the supplied value.
		 *	We return the old reference to the caller
		 *	but we have to take a reference on the new
		 *	one.
		 */

		returned_manager = current_manager;
		memory_manager_default = new_manager;
		memory_object_default_reference(new_manager);

		if (cluster_size % PAGE_SIZE != 0) {
#if 0
			mutex_unlock(&memory_manager_default_lock);
			return KERN_INVALID_ARGUMENT;
#else
			cluster_size = round_page(cluster_size);
#endif
		}
		memory_manager_default_cluster = cluster_size;

		/*
		 *	In case anyone's been waiting for a memory
		 *	manager to be established, wake them up.
		 */

		thread_wakeup((event_t) &memory_manager_default);
	}

	mutex_unlock(&memory_manager_default_lock);

	*default_manager = returned_manager;
	return(KERN_SUCCESS);
}

/*
 *	Routine:	memory_manager_default_reference
 *	Purpose:
 *		Returns a naked send right for the default
 *		memory manager.  The returned right is always
 *		valid (not IP_NULL or IP_DEAD).
 */

__private_extern__ memory_object_default_t
memory_manager_default_reference(
	vm_size_t	*cluster_size)
{
	memory_object_default_t current_manager;

	mutex_lock(&memory_manager_default_lock);
	current_manager = memory_manager_default;
	while (current_manager == MEMORY_OBJECT_DEFAULT_NULL) {
		wait_result_t res;

		res = thread_sleep_mutex((event_t) &memory_manager_default,
					 &memory_manager_default_lock,
					 THREAD_UNINT);
		assert(res == THREAD_AWAKENED);
		current_manager = memory_manager_default;
	}
	memory_object_default_reference(current_manager);
	*cluster_size = memory_manager_default_cluster;
	mutex_unlock(&memory_manager_default_lock);

	return current_manager;
}

/*
 *	Routine:	memory_manager_default_check
 *
 *	Purpose:
 *		Check whether a default memory manager has been set
 *		up yet, or not. Returns KERN_SUCCESS if dmm exists,
 *		and KERN_FAILURE if dmm does not exist.
 *
 *		If there is no default memory manager, log an error,
 *		but only the first time.
 *
 */
__private_extern__ kern_return_t
memory_manager_default_check(void)
{
	memory_object_default_t current;

	mutex_lock(&memory_manager_default_lock);
	current = memory_manager_default;
	if (current == MEMORY_OBJECT_DEFAULT_NULL) {
		static boolean_t logged;	/* initialized to 0 */
		boolean_t	complain = !logged;
		logged = TRUE;
		mutex_unlock(&memory_manager_default_lock);
		if (complain)
			printf("Warning: No default memory manager\n");
		return(KERN_FAILURE);
	} else {
		mutex_unlock(&memory_manager_default_lock);
		return(KERN_SUCCESS);
	}
}

__private_extern__ void
memory_manager_default_init(void)
{
	memory_manager_default = MEMORY_OBJECT_DEFAULT_NULL;
	mutex_init(&memory_manager_default_lock, ETAP_VM_MEMMAN);
}


void
memory_object_deactivate_pages(
	vm_object_t		object,
	vm_object_offset_t	offset,
	vm_object_size_t	size,
	boolean_t               kill_page)
{
	vm_object_t		orig_object;
	int pages_moved = 0;
	int pages_found = 0;

	/*
	 * entered with object lock held, acquire a paging reference to
	 * prevent the memory_object and control ports from
	 * being destroyed.
	 */
	orig_object = object;

	for (;;) {
	        register vm_page_t	m;
	        vm_object_offset_t	toffset;
		vm_object_size_t	tsize;

	        vm_object_paging_begin(object);
		vm_page_lock_queues();

		for (tsize = size, toffset = offset; tsize; tsize -= PAGE_SIZE, toffset += PAGE_SIZE) {

		        if ((m = vm_page_lookup(object, toffset)) != VM_PAGE_NULL) {

			        pages_found++;

				if ((m->wire_count == 0) && (!m->private) && (!m->gobbled) && (!m->busy)) {

					m->reference = FALSE;
					pmap_clear_reference(m->phys_addr);

					if ((kill_page) && (object->internal)) {
				        	m->precious = FALSE;
					        m->dirty = FALSE;
						pmap_clear_modify(m->phys_addr);
						vm_external_state_clr(object->existence_map, offset);
					}
					VM_PAGE_QUEUES_REMOVE(m);

					if(m->zero_fill) {
						queue_enter_first(
							&vm_page_queue_zf, 
							m, vm_page_t, pageq);
					} else {
						queue_enter_first(
							&vm_page_queue_inactive, 
							m, vm_page_t, pageq);
					}

					m->inactive = TRUE;
					if (!m->fictitious)  
					        vm_page_inactive_count++;

					pages_moved++;
				}
			}
		}
		vm_page_unlock_queues();
		vm_object_paging_end(object);

		if (object->shadow) {
		        vm_object_t	tmp_object;

			kill_page = 0;

		        offset += object->shadow_offset;

		        tmp_object = object->shadow;
		        vm_object_lock(tmp_object);

			if (object != orig_object)
			        vm_object_unlock(object);
			object = tmp_object;
		} else
		        break;
	}
	if (object != orig_object)
	        vm_object_unlock(object);
}

/* Allow manipulation of individual page state.  This is actually part of */
/* the UPL regimen but takes place on the object rather than on a UPL */

kern_return_t
memory_object_page_op(
	memory_object_control_t	control,
	memory_object_offset_t	offset,
	int			ops,
	vm_offset_t		*phys_entry,
	int			*flags)
{
	vm_object_t		object;
	vm_page_t		dst_page;


	object = memory_object_control_to_vm_object(control);
	if (object == VM_OBJECT_NULL)
		return (KERN_INVALID_ARGUMENT);

	vm_object_lock(object);

	if(ops & UPL_POP_PHYSICAL) {
		if(object->phys_contiguous) {
			if (phys_entry) {
				*phys_entry = (vm_offset_t)
						object->shadow_offset;
			}
			vm_object_unlock(object);
			return KERN_SUCCESS;
		} else {
			vm_object_unlock(object);
			return KERN_INVALID_OBJECT;
		}
	}

	while(TRUE) {
		if(object->phys_contiguous) {
			vm_object_unlock(object);
			return KERN_INVALID_OBJECT;
		}

		if((dst_page = vm_page_lookup(object,offset)) == VM_PAGE_NULL) {
			vm_object_unlock(object);
			return KERN_FAILURE;
		}

		/* Sync up on getting the busy bit */
		if((dst_page->busy || dst_page->cleaning) && 
			   (((ops & UPL_POP_SET) && 
			   (ops & UPL_POP_BUSY)) || (ops & UPL_POP_DUMP))) {
			/* someone else is playing with the page, we will */
			/* have to wait */
			PAGE_SLEEP(object, dst_page, THREAD_UNINT);
			continue;
		}

		if (ops & UPL_POP_DUMP) {
		  vm_page_lock_queues();
                  vm_page_free(dst_page);
		  vm_page_unlock_queues();
		  break;
		}

		if (flags) {
		        *flags = 0;

			/* Get the condition of flags before requested ops */
			/* are undertaken */

			if(dst_page->dirty) *flags |= UPL_POP_DIRTY;
			if(dst_page->pageout) *flags |= UPL_POP_PAGEOUT;
			if(dst_page->precious) *flags |= UPL_POP_PRECIOUS;
			if(dst_page->absent) *flags |= UPL_POP_ABSENT;
			if(dst_page->busy) *flags |= UPL_POP_BUSY;
		}
		if (phys_entry)
			*phys_entry = dst_page->phys_addr;
	
		/* The caller should have made a call either contingent with */
		/* or prior to this call to set UPL_POP_BUSY */
		if(ops & UPL_POP_SET) {
			/* The protection granted with this assert will */
			/* not be complete.  If the caller violates the */
			/* convention and attempts to change page state */
			/* without first setting busy we may not see it */
			/* because the page may already be busy.  However */
			/* if such violations occur we will assert sooner */
			/* or later. */
			assert(dst_page->busy || (ops & UPL_POP_BUSY));
			if (ops & UPL_POP_DIRTY) dst_page->dirty = TRUE;
			if (ops & UPL_POP_PAGEOUT) dst_page->pageout = TRUE;
			if (ops & UPL_POP_PRECIOUS) dst_page->precious = TRUE;
			if (ops & UPL_POP_ABSENT) dst_page->absent = TRUE;
			if (ops & UPL_POP_BUSY) dst_page->busy = TRUE;
		}

		if(ops & UPL_POP_CLR) {
			assert(dst_page->busy);
			if (ops & UPL_POP_DIRTY) dst_page->dirty = FALSE;
			if (ops & UPL_POP_PAGEOUT) dst_page->pageout = FALSE;
			if (ops & UPL_POP_PRECIOUS) dst_page->precious = FALSE;
			if (ops & UPL_POP_ABSENT) dst_page->absent = FALSE;
			if (ops & UPL_POP_BUSY) {
			        dst_page->busy = FALSE;
				PAGE_WAKEUP(dst_page);
			}
		}
		break;
	}

	vm_object_unlock(object);
	return KERN_SUCCESS;
				
}

static zone_t mem_obj_control_zone;

__private_extern__ void
memory_object_control_bootstrap(void)
{
	int	i;

	i = (vm_size_t) sizeof (struct memory_object_control);
	mem_obj_control_zone = zinit (i, 8192*i, 4096, "mem_obj_control");
	return;
}

__private_extern__ memory_object_control_t
memory_object_control_allocate(
	vm_object_t		object)
{		       
	memory_object_control_t control;

	control = (memory_object_control_t)zalloc(mem_obj_control_zone);
	if (control != MEMORY_OBJECT_CONTROL_NULL)
		control->object = object;
	return (control);
}

__private_extern__ void
memory_object_control_collapse(
	memory_object_control_t control,		       
	vm_object_t		object)
{		       
	assert((control->object != VM_OBJECT_NULL) &&
	       (control->object != object));
	control->object = object;
}

__private_extern__ vm_object_t
memory_object_control_to_vm_object(
	memory_object_control_t	control)
{
	if (control == MEMORY_OBJECT_CONTROL_NULL)
		return VM_OBJECT_NULL;

	return (control->object);
}

memory_object_control_t
convert_port_to_mo_control(
	mach_port_t	port)
{
	return MEMORY_OBJECT_CONTROL_NULL;
}


mach_port_t
convert_mo_control_to_port(
	memory_object_control_t	control)
{
	return MACH_PORT_NULL;
}

void
memory_object_control_reference(
	memory_object_control_t	control)
{
	return;
}

/*
 * We only every issue one of these references, so kill it
 * when that gets released (should switch the real reference
 * counting in true port-less EMMI).
 */
void
memory_object_control_deallocate(
	memory_object_control_t	control)
{
	zfree(mem_obj_control_zone, (vm_offset_t)control);
}

void
memory_object_control_disable(
	memory_object_control_t	control)
{
	assert(control->object != VM_OBJECT_NULL);
	control->object = VM_OBJECT_NULL;
}

void
memory_object_default_reference(
	memory_object_default_t dmm)
{
	ipc_port_make_send(dmm);
}

void
memory_object_default_deallocate(
	memory_object_default_t dmm)
{
	ipc_port_release_send(dmm);
}

memory_object_t
convert_port_to_memory_object(
	mach_port_t	port)
{
	return (MEMORY_OBJECT_NULL);
}


mach_port_t
convert_memory_object_to_port(
	memory_object_t	object)
{
	return (MACH_PORT_NULL);
}

#ifdef MACH_BSD
/* remove after component interface available */
extern int	vnode_pager_workaround;
extern int	device_pager_workaround;
#endif


/* Routine memory_object_reference */
void memory_object_reference(
	memory_object_t memory_object)
{
extern void   dp_memory_object_reference(memory_object_t);

#ifdef	MACH_BSD
 extern void   vnode_pager_reference(memory_object_t);
 extern void   device_pager_reference(memory_object_t);

		if(memory_object->pager == &vnode_pager_workaround) {
			vnode_pager_reference(memory_object);
		} else if(memory_object->pager == &device_pager_workaround) {
			device_pager_reference(memory_object);
		} else
#endif
			dp_memory_object_reference(memory_object);
}

/* Routine memory_object_deallocate */
void memory_object_deallocate(
	memory_object_t memory_object)
{
extern void   dp_memory_object_deallocate(memory_object_t);

#ifdef	MACH_BSD
 extern void   vnode_pager_deallocate(memory_object_t);
 extern void   device_pager_deallocate(memory_object_t);

		if(memory_object->pager == &vnode_pager_workaround) {
			vnode_pager_deallocate(memory_object);
		} else if(memory_object->pager == &device_pager_workaround) {
			device_pager_deallocate(memory_object);
		} else
#endif
			dp_memory_object_deallocate(memory_object);
}


/* Routine memory_object_init */
kern_return_t memory_object_init
(
	memory_object_t memory_object,
	memory_object_control_t memory_control,
	vm_size_t memory_object_page_size
)
{
extern kern_return_t   dp_memory_object_init(memory_object_t,
					     memory_object_control_t,
					     vm_size_t);
#ifdef	MACH_BSD
extern kern_return_t   vnode_pager_init(memory_object_t,
					memory_object_control_t,
					vm_size_t);
extern kern_return_t   device_pager_init(memory_object_t,
					memory_object_control_t,
					vm_size_t);

		if(memory_object->pager == &vnode_pager_workaround) {
			return vnode_pager_init(memory_object,
				memory_control,
				memory_object_page_size);
		} else if(memory_object->pager == &device_pager_workaround) {
			return device_pager_init(memory_object,
				memory_control,
				memory_object_page_size);
		} else
#endif
			return dp_memory_object_init(memory_object,
				memory_control,
				memory_object_page_size);
}

/* Routine memory_object_terminate */
kern_return_t memory_object_terminate
(
	memory_object_t memory_object
)
{
extern	kern_return_t dp_memory_object_terminate(memory_object_t);

#ifdef	MACH_BSD
extern	kern_return_t vnode_pager_terminate(memory_object_t);
extern	kern_return_t device_pager_terminate(memory_object_t);

	if(memory_object->pager == &vnode_pager_workaround) {
		return vnode_pager_terminate(memory_object);
	} else if(memory_object->pager == &device_pager_workaround) {
		return device_pager_terminate(memory_object);
	} else
#endif
		return dp_memory_object_terminate(memory_object);
}

/* Routine memory_object_data_request */
kern_return_t memory_object_data_request
(
	memory_object_t memory_object,
	memory_object_offset_t offset,
	vm_size_t length,
	vm_prot_t desired_access
)
{
extern	kern_return_t   dp_memory_object_data_request(memory_object_t, 
			memory_object_offset_t, vm_size_t, vm_prot_t);

#ifdef	MACH_BSD
extern	kern_return_t   vnode_pager_data_request(memory_object_t, 
			memory_object_offset_t, vm_size_t, vm_prot_t);
extern	kern_return_t   device_pager_data_request(memory_object_t, 
			memory_object_offset_t, vm_size_t, vm_prot_t);

		if (memory_object->pager == &vnode_pager_workaround) {
	        	return vnode_pager_data_request(memory_object, 
				      offset, 
				      length,
				      desired_access);
		} else if (memory_object->pager == &device_pager_workaround) {
	        	return device_pager_data_request(memory_object, 
				      offset, 
				      length,
				      desired_access);
		} else
#endif
	       		return dp_memory_object_data_request(memory_object, 
					offset, 
					length,
					desired_access);
}

/* Routine memory_object_data_return */
kern_return_t memory_object_data_return
(
	memory_object_t memory_object,
	memory_object_offset_t offset,
	vm_size_t size,
	boolean_t dirty,
	boolean_t kernel_copy
)
{
  extern kern_return_t dp_memory_object_data_return(memory_object_t,
						    memory_object_offset_t,
						    vm_size_t,
						    boolean_t,
						    boolean_t);
#ifdef MACH_BSD
  extern kern_return_t vnode_pager_data_return(memory_object_t,
						    memory_object_offset_t,
						    vm_size_t,
						    boolean_t,
						    boolean_t);
  extern kern_return_t device_pager_data_return(memory_object_t,
						    memory_object_offset_t,
						    vm_size_t,
						    boolean_t,
						    boolean_t);

	if (memory_object->pager == &vnode_pager_workaround) {
		return vnode_pager_data_return(memory_object,
				       offset,
				       size,
				       dirty,
				       kernel_copy);
	} else if (memory_object->pager == &device_pager_workaround) {
		return device_pager_data_return(memory_object,
				       offset,
				       size,
				       dirty,
				       kernel_copy);
	} else
#endif
		return dp_memory_object_data_return(memory_object,
				       offset,
				       size,
				       dirty,
				       kernel_copy);
}

/* Routine memory_object_data_initialize */
kern_return_t memory_object_data_initialize
(
	memory_object_t memory_object,
	memory_object_offset_t offset,
	vm_size_t size
)
{

  extern kern_return_t dp_memory_object_data_initialize(memory_object_t,
						    memory_object_offset_t,
						    vm_size_t);
#ifdef MACH_BSD
  extern kern_return_t vnode_pager_data_initialize(memory_object_t,
						    memory_object_offset_t,
						    vm_size_t);
  extern kern_return_t device_pager_data_initialize(memory_object_t,
						    memory_object_offset_t,
						    vm_size_t);

	if (memory_object->pager == &vnode_pager_workaround) {
		return vnode_pager_data_initialize(memory_object,
				       offset,
				       size);
	} else if (memory_object->pager == &device_pager_workaround) {
		return device_pager_data_initialize(memory_object,
				       offset,
				       size);
	} else
#endif
		return dp_memory_object_data_initialize(memory_object,
				       offset,
				       size);
}

/* Routine memory_object_data_unlock */
kern_return_t memory_object_data_unlock
(
	memory_object_t memory_object,
	memory_object_offset_t offset,
	vm_size_t size,
	vm_prot_t desired_access
)
{
  extern kern_return_t dp_memory_object_data_unlock(memory_object_t,
						    memory_object_offset_t,
						    vm_size_t,
						    vm_prot_t);
#ifdef MACH_BSD
  extern kern_return_t vnode_pager_data_unlock(memory_object_t,
						    memory_object_offset_t,
						    vm_size_t,
						    vm_prot_t);
  extern kern_return_t device_pager_data_unlock(memory_object_t,
						    memory_object_offset_t,
						    vm_size_t,
						    vm_prot_t);

	if (memory_object->pager == &vnode_pager_workaround) {
		return vnode_pager_data_unlock(memory_object,
				       offset,
				       size,
				       desired_access);
	} else if (memory_object->pager == &device_pager_workaround) {
		return device_pager_data_unlock(memory_object,
				       offset,
				       size,
				       desired_access);
	} else
#endif
		return dp_memory_object_data_unlock(memory_object,
				       offset,
				       size,
				       desired_access);

}

/* Routine memory_object_synchronize */
kern_return_t memory_object_synchronize
(
	memory_object_t memory_object,
	memory_object_offset_t offset,
	vm_size_t size,
	vm_sync_t sync_flags
)
{
  extern kern_return_t dp_memory_object_data_synchronize(memory_object_t,
						    memory_object_offset_t,
						    vm_size_t,
						    vm_sync_t);
#ifdef MACH_BSD
  extern kern_return_t vnode_pager_data_synchronize(memory_object_t,
						    memory_object_offset_t,
						    vm_size_t,
						    vm_sync_t);
  extern kern_return_t device_pager_data_synchronize(memory_object_t,
						    memory_object_offset_t,
						    vm_size_t,
						    vm_sync_t);

	if (memory_object->pager == &vnode_pager_workaround) {
                	return vnode_pager_synchronize(
				memory_object,
				offset,
				size,
				sync_flags);
	} else if (memory_object->pager == &device_pager_workaround) {
                	return device_pager_synchronize(
				memory_object,
				offset,
				size,
				sync_flags);
	} else
#endif
			return dp_memory_object_synchronize(
				memory_object,
				offset,
				size,
				sync_flags);
}

/* Routine memory_object_unmap */
kern_return_t memory_object_unmap
(
	memory_object_t memory_object
)
{
	extern kern_return_t dp_memory_object_unmap(memory_object_t);
#ifdef MACH_BSD
	extern kern_return_t vnode_pager_unmap(memory_object_t);
	extern kern_return_t device_pager_unmap(memory_object_t);

	if (memory_object->pager == &vnode_pager_workaround) {
                	return vnode_pager_unmap(memory_object);
	} else if (memory_object->pager == &device_pager_workaround) {
                	return device_pager_unmap(memory_object);
	} else
#endif
			return dp_memory_object_unmap(memory_object);
}

/* Routine memory_object_create */
kern_return_t memory_object_create
(
	memory_object_default_t default_memory_manager,
	vm_size_t new_memory_object_size,
	memory_object_t *new_memory_object
)
{
extern kern_return_t default_pager_memory_object_create(memory_object_default_t,
							vm_size_t,
							memory_object_t *);

	return default_pager_memory_object_create(default_memory_manager,
						  new_memory_object_size,
						  new_memory_object);
}

