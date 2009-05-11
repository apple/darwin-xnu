/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
#include <vm/vm_purgeable_internal.h>	/* Needed by some vm_page.h macros */

#if	MACH_PAGEMAP
#include <vm/vm_external.h>
#endif	/* MACH_PAGEMAP */

#include <vm/vm_protos.h>


memory_object_default_t	memory_manager_default = MEMORY_OBJECT_DEFAULT_NULL;
decl_mutex_data(,	memory_manager_default_lock)


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
     (((m)->dirty || ((m)->dirty = pmap_is_modified((m)->phys_page))) || \
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

	/*
	 *	If the page is wired, just clean or return the page if needed.
	 *	Wired pages don't get flushed or disconnected from the pmap.
	 */

	if (m->wire_count != 0) {
		if (memory_object_should_return_page(m, should_return)) {
			if (m->dirty)
				return(MEMORY_OBJECT_LOCK_RESULT_MUST_CLEAN);
			else
				return(MEMORY_OBJECT_LOCK_RESULT_MUST_RETURN);
		}

		return(MEMORY_OBJECT_LOCK_RESULT_DONE);
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
	        pmap_page_protect(m->phys_page, VM_PROT_ALL & ~prot);

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
		
		vm_page_lockspin_queues();
		VM_PAGE_QUEUES_REMOVE(m);
		vm_page_unlock_queues();

		if (!should_flush)
			pmap_disconnect(m->phys_page);

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

#define LIST_REQ_PAGEOUT_PAGES(object, data_cnt, action, po, ro, ioerr, iosync)    \
MACRO_BEGIN								\
									\
        register int            upl_flags;                              \
	memory_object_t		pager;					\
				                   			\
	if ((pager = (object)->pager) != MEMORY_OBJECT_NULL) {		\
		vm_object_paging_begin(object);				\
		vm_object_unlock(object);				\
									\
                if (iosync)                                     	\
                        upl_flags = UPL_MSYNC | UPL_IOSYNC;     	\
                else                                            	\
                        upl_flags = UPL_MSYNC;                  	\
				                   			\
	   	(void) memory_object_data_return(pager,			\
			po,						\
			data_cnt,					\
	                ro,                                             \
	                ioerr,                                          \
			(action) == MEMORY_OBJECT_LOCK_RESULT_MUST_CLEAN,\
			!should_flush,                                  \
			upl_flags);                                 	\
									\
		vm_object_lock(object);					\
		vm_object_paging_end(object);				\
	}								\
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
	memory_object_offset_t	*	resid_offset,
	int			*	io_errno,
	memory_object_return_t		should_return,
	int				flags,
	vm_prot_t			prot)
{
	vm_object_t	object;
	__unused boolean_t should_flush;

	should_flush = flags & MEMORY_OBJECT_DATA_FLUSH;

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

	size = round_page_64(size);

	/*
	 *	Lock the object, and acquire a paging reference to
	 *	prevent the memory_object reference from being released.
	 */
	vm_object_lock(object);
	vm_object_paging_begin(object);
	offset -= object->paging_offset;

	(void)vm_object_update(object,
		offset, size, resid_offset, io_errno, should_return, flags, prot);

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
	vm_object_size_t	size,
	boolean_t		should_flush,
	boolean_t		should_return,
	boolean_t		should_iosync)
{
	boolean_t	rv;
	int             flags;

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

	if (should_flush)
	        flags = MEMORY_OBJECT_DATA_FLUSH;
	else
	        flags = 0;

	if (should_iosync)
	        flags |= MEMORY_OBJECT_IO_SYNC;

	rv = vm_object_update(object, offset, (vm_object_size_t)size, NULL, NULL,
		(should_return) ?
			MEMORY_OBJECT_RETURN_ALL :
			MEMORY_OBJECT_RETURN_NONE,
		flags,
		VM_PROT_NO_CHANGE);


	vm_object_paging_end(object);
	vm_object_unlock(object);
	return rv;
}




static int
vm_object_update_extent(
        vm_object_t		object,
        vm_object_offset_t	offset,
	vm_object_offset_t	offset_end,
	vm_object_offset_t	*offset_resid,
	int			*io_errno,
        boolean_t		should_flush,
	memory_object_return_t	should_return,
        boolean_t		should_iosync, 
        vm_prot_t		prot)
{
        vm_page_t	m;
        int		retval = 0;
	vm_size_t	data_cnt = 0;
	vm_object_offset_t	paging_offset = 0;
	vm_object_offset_t	last_offset = offset;
        memory_object_lock_result_t	page_lock_result;
	memory_object_lock_result_t	pageout_action;
	
	pageout_action = MEMORY_OBJECT_LOCK_RESULT_DONE;

	for (;
	     offset < offset_end && object->resident_page_count;
	     offset += PAGE_SIZE_64) {

	        /*
		 * Limit the number of pages to be cleaned at once.
		 */
	        if (data_cnt >= PAGE_SIZE * MAX_UPL_TRANSFER) {
		        LIST_REQ_PAGEOUT_PAGES(object, data_cnt, 
					       pageout_action, paging_offset, offset_resid, io_errno, should_iosync);
			data_cnt = 0;
		}

		while ((m = vm_page_lookup(object, offset)) != VM_PAGE_NULL) {
		        page_lock_result = memory_object_lock_page(m, should_return, should_flush, prot);

			XPR(XPR_MEMORY_OBJECT,
			    "m_o_update: lock_page, obj 0x%X offset 0x%X result %d\n",
			    (integer_t)object, offset, page_lock_result, 0, 0);

			switch (page_lock_result)
			{
			  case MEMORY_OBJECT_LOCK_RESULT_DONE:
			    /*
			     *	End of a cluster of dirty pages.
			     */
			    if (data_cnt) {
			            LIST_REQ_PAGEOUT_PAGES(object, 
							   data_cnt, pageout_action, 
							   paging_offset, offset_resid, io_errno, should_iosync);
				    data_cnt = 0;
				    continue;
			    }
			    break;

			  case MEMORY_OBJECT_LOCK_RESULT_MUST_BLOCK:
			    /*
			     *	Since it is necessary to block,
			     *	clean any dirty pages now.
			     */
			    if (data_cnt) {
			            LIST_REQ_PAGEOUT_PAGES(object,
							   data_cnt, pageout_action, 
							   paging_offset, offset_resid, io_errno, should_iosync);
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
			     * if this would form a discontiguous block,
			     * clean the old pages and start anew.
			     *
			     * Mark the page busy since we will unlock the
			     * object if we issue the LIST_REQ_PAGEOUT
			     */
			    m->busy = TRUE;
			    if (data_cnt && 
				((last_offset != offset) || (pageout_action != page_lock_result))) {
			            LIST_REQ_PAGEOUT_PAGES(object, 
							   data_cnt, pageout_action, 
							   paging_offset, offset_resid, io_errno, should_iosync);
				    data_cnt = 0;
			    }
			    m->busy = FALSE;

			    if (m->cleaning) {
			            PAGE_SLEEP(object, m, THREAD_UNINT);
				    continue;
			    }
			    if (data_cnt == 0) {
			            pageout_action = page_lock_result;
				    paging_offset = offset;
			    }
			    data_cnt += PAGE_SIZE;
			    last_offset = offset + PAGE_SIZE_64;

			    vm_page_lockspin_queues();
			    /*
			     * Clean
			     */
			    m->list_req_pending = TRUE;
			    m->cleaning = TRUE;

			    if (should_flush &&
				/* let's no flush a wired page... */
				!m->wire_count) {
			            /*
				     * and add additional state
				     * for the flush
				     */
				    m->busy = TRUE;
				    m->pageout = TRUE;
				    vm_page_wire(m);
			    }
			    vm_page_unlock_queues();

			    retval = 1;
			    break;
			}
			break;
		}
	}
	/*
	 *	We have completed the scan for applicable pages.
	 *	Clean any pages that have been saved.
	 */
	if (data_cnt) {
	        LIST_REQ_PAGEOUT_PAGES(object,
				       data_cnt, pageout_action, paging_offset, offset_resid, io_errno, should_iosync);
	}
	return (retval);
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
	register vm_object_size_t	size,
	register vm_object_offset_t	*resid_offset,
	int				*io_errno,
	memory_object_return_t		should_return,
	int				flags,
	vm_prot_t			protection)
{
        vm_object_t		copy_object = VM_OBJECT_NULL;
	boolean_t		data_returned = FALSE;
	boolean_t		update_cow;
	boolean_t		should_flush = (flags & MEMORY_OBJECT_DATA_FLUSH) ? TRUE : FALSE;
	boolean_t		should_iosync = (flags & MEMORY_OBJECT_IO_SYNC) ? TRUE : FALSE;
	int			num_of_extents;
	int			n;
#define MAX_EXTENTS	8
#define EXTENT_SIZE	(1024 * 1024 * 256)
#define RESIDENT_LIMIT	(1024 * 32)
	struct extent {
	        vm_object_offset_t e_base;
	        vm_object_offset_t e_min;
	        vm_object_offset_t e_max;
	} extents[MAX_EXTENTS];

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
			
	if (update_cow || (flags & (MEMORY_OBJECT_DATA_PURGE | MEMORY_OBJECT_DATA_SYNC))) {
	        int collisions = 0;

	        while ((copy_object = object->copy) != VM_OBJECT_NULL) {
		        /*
			 * need to do a try here since we're swimming upstream
			 * against the normal lock ordering... however, we need
			 * to hold the object stable until we gain control of the
			 * copy object so we have to be careful how we approach this
			 */
		        if (vm_object_lock_try(copy_object)) {
			       /*
				* we 'won' the lock on the copy object...
				* no need to hold the object lock any longer...
				* take a real reference on the copy object because
				* we're going to call vm_fault_page on it which may
				* under certain conditions drop the lock and the paging
				* reference we're about to take... the reference
				* will keep the copy object from going away if that happens
				*/
			       vm_object_unlock(object);
			       vm_object_reference_locked(copy_object);
			       break;
			}
			vm_object_unlock(object);

			collisions++;
			mutex_pause(collisions);

			vm_object_lock(object);
		}
	}
	if ((copy_object != VM_OBJECT_NULL && update_cow) || (flags & MEMORY_OBJECT_DATA_SYNC)) {
		vm_map_size_t		i;
		vm_map_size_t		copy_size;
		vm_map_offset_t		copy_offset;
		vm_prot_t		prot;
		vm_page_t		page;
		vm_page_t		top_page;
		kern_return_t		error = 0;
		struct vm_object_fault_info fault_info;

		if (copy_object != VM_OBJECT_NULL) {
		        /*
			 * translate offset with respect to shadow's offset
			 */
		        copy_offset = (offset >= copy_object->shadow_offset) ?
			  (vm_map_offset_t)(offset - copy_object->shadow_offset) :
			  (vm_map_offset_t) 0;

			if (copy_offset > copy_object->size)
			        copy_offset = copy_object->size;

			/*
			 * clip size with respect to shadow offset
			 */
			if (offset >= copy_object->shadow_offset) {
			        copy_size = size;
			} else if (size >= copy_object->shadow_offset - offset) {
			        copy_size = size - (copy_object->shadow_offset - offset);
			} else {
			        copy_size = 0;
			}
			
			if (copy_offset + copy_size > copy_object->size) {
			        if (copy_object->size >= copy_offset) {
				        copy_size = copy_object->size - copy_offset;
				} else {
				        copy_size = 0;
				}
			}
			copy_size+=copy_offset;

		} else {
			copy_object = object;

			copy_size   = offset + size;
			copy_offset = offset;
		}
		fault_info.interruptible = THREAD_UNINT;
		fault_info.behavior  = VM_BEHAVIOR_SEQUENTIAL;
		fault_info.user_tag  = 0;
		fault_info.lo_offset = copy_offset;
		fault_info.hi_offset = copy_size;
		fault_info.no_cache   = FALSE;

		vm_object_paging_begin(copy_object);

		for (i = copy_offset; i < copy_size; i += PAGE_SIZE) {
	RETRY_COW_OF_LOCK_REQUEST:
			fault_info.cluster_size = copy_size - i;

			prot = 	VM_PROT_WRITE|VM_PROT_READ;
			switch (vm_fault_page(copy_object, i, 
				VM_PROT_WRITE|VM_PROT_READ,
				FALSE,
				&prot,
				&page,
				&top_page,
				(int *)0,
				&error,
			        FALSE,
		                FALSE, &fault_info)) {

			case VM_FAULT_SUCCESS:
				if (top_page) {
					vm_fault_cleanup(
						page->object, top_page);
					vm_object_lock(copy_object);
					vm_object_paging_begin(copy_object);
				}
				vm_page_lock_queues();
				if (!page->active && !page->inactive)
					vm_page_deactivate(page);
				vm_page_unlock_queues();

				PAGE_WAKEUP_DONE(page);
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
			        if (object != copy_object)
				        vm_object_deallocate(copy_object);
				vm_object_lock(object);
				goto BYPASS_COW_COPYIN;
			}

		}
		vm_object_paging_end(copy_object);
	}
	if ((flags & (MEMORY_OBJECT_DATA_SYNC | MEMORY_OBJECT_COPY_SYNC))) {
	        if (copy_object != VM_OBJECT_NULL && copy_object != object) {
			vm_object_unlock(copy_object);
		        vm_object_deallocate(copy_object);
			vm_object_lock(object);
		}
		return KERN_SUCCESS;
	}
	if (copy_object != VM_OBJECT_NULL && copy_object != object) {
	        if ((flags & MEMORY_OBJECT_DATA_PURGE)) {
		        copy_object->shadow_severed = TRUE;
			copy_object->shadowed = FALSE;
			copy_object->shadow = NULL;
			/*
			 * delete the ref the COW was holding on the target object
			 */
			vm_object_deallocate(object);
		}
		vm_object_unlock(copy_object);
	        vm_object_deallocate(copy_object);
		vm_object_lock(object);
	}
BYPASS_COW_COPYIN:

	/*
	 * when we have a really large range to check relative
	 * to the number of actual resident pages, we'd like
	 * to use the resident page list to drive our checks
	 * however, the object lock will get dropped while processing
	 * the page which means the resident queue can change which
	 * means we can't walk the queue as we process the pages
	 * we also want to do the processing in offset order to allow
	 * 'runs' of pages to be collected if we're being told to 
	 * flush to disk... the resident page queue is NOT ordered.
	 * 
	 * a temporary solution (until we figure out how to deal with
	 * large address spaces more generically) is to pre-flight
	 * the resident page queue (if it's small enough) and develop
	 * a collection of extents (that encompass actual resident pages)
	 * to visit.  This will at least allow us to deal with some of the
	 * more pathological cases in a more efficient manner.  The current
	 * worst case (a single resident page at the end of an extremely large
	 * range) can take minutes to complete for ranges in the terrabyte
	 * category... since this routine is called when truncating a file,
	 * and we currently support files up to 16 Tbytes in size, this
	 * is not a theoretical problem
	 */

	if ((object->resident_page_count < RESIDENT_LIMIT) && 
	    (atop_64(size) > (unsigned)(object->resident_page_count/(8 * MAX_EXTENTS)))) {
		vm_page_t		next;
		vm_object_offset_t	start;
		vm_object_offset_t	end;
		vm_object_size_t	e_mask;
		vm_page_t               m;

		start = offset;
		end   = offset + size;
		num_of_extents = 0;
		e_mask = ~((vm_object_size_t)(EXTENT_SIZE - 1));

		m = (vm_page_t) queue_first(&object->memq);

		while (!queue_end(&object->memq, (queue_entry_t) m)) {
			next = (vm_page_t) queue_next(&m->listq);

			if ((m->offset >= start) && (m->offset < end)) {
			        /*
				 * this is a page we're interested in
				 * try to fit it into a current extent
				 */
			        for (n = 0; n < num_of_extents; n++) {
				        if ((m->offset & e_mask) == extents[n].e_base) {
					        /*
						 * use (PAGE_SIZE - 1) to determine the
						 * max offset so that we don't wrap if
						 * we're at the last page of the space
						 */
					        if (m->offset < extents[n].e_min)
						        extents[n].e_min = m->offset;
						else if ((m->offset + (PAGE_SIZE - 1)) > extents[n].e_max)
						        extents[n].e_max = m->offset + (PAGE_SIZE - 1);
					        break;
					}
				}
				if (n == num_of_extents) {
				        /*
					 * didn't find a current extent that can encompass
					 * this page
					 */
				        if (n < MAX_EXTENTS) {
					        /*
						 * if we still have room, 
						 * create a new extent
						 */
					        extents[n].e_base = m->offset & e_mask;
						extents[n].e_min  = m->offset;
						extents[n].e_max  = m->offset + (PAGE_SIZE - 1);

						num_of_extents++;
					} else {
						/*
						 * no room to create a new extent...
						 * fall back to a single extent based
						 * on the min and max page offsets 
						 * we find in the range we're interested in...
						 * first, look through the extent list and
						 * develop the overall min and max for the
						 * pages we've looked at up to this point
						 */						
					        for (n = 1; n < num_of_extents; n++) {
						        if (extents[n].e_min < extents[0].e_min)
						                extents[0].e_min = extents[n].e_min;
							if (extents[n].e_max > extents[0].e_max)
						                extents[0].e_max = extents[n].e_max;
						}
						/*
						 * now setup to run through the remaining pages
						 * to determine the overall min and max
						 * offset for the specified range
						 */
						extents[0].e_base = 0;
						e_mask = 0;
						num_of_extents = 1;

						/*
						 * by continuing, we'll reprocess the
						 * page that forced us to abandon trying
						 * to develop multiple extents
						 */
						continue;
					}
				}
			}
			m = next;
		}
	} else {
	        extents[0].e_min = offset;
		extents[0].e_max = offset + (size - 1);

		num_of_extents = 1;
	}
	for (n = 0; n < num_of_extents; n++) {
	        if (vm_object_update_extent(object, extents[n].e_min, extents[n].e_max, resid_offset, io_errno,
					    should_flush, should_return, should_iosync, protection))
		        data_returned = TRUE;
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

	object = memory_object_control_to_vm_object(control);

        XPR(XPR_MEMORY_OBJECT,
	    "m_o_sync_completed, object 0x%X, offset 0x%X length 0x%X\n",
	    (integer_t)object, offset, length, 0, 0);

	/*
	 *      Look for bogus arguments
	 */

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
		perf->cluster_size = PAGE_SIZE;
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
		attr->cluster_size = PAGE_SIZE;
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


kern_return_t
memory_object_iopl_request(
	ipc_port_t		port,
	memory_object_offset_t	offset,
	upl_size_t		*upl_size,
	upl_t			*upl_ptr,
	upl_page_info_array_t	user_page_list,
	unsigned int		*page_list_count,
	int			*flags)
{
	vm_object_t		object;
	kern_return_t		ret;
	int			caller_flags;

	caller_flags = *flags;

	if (caller_flags & ~UPL_VALID_FLAGS) {
		/*
		 * For forward compatibility's sake,
		 * reject any unknown flag.
		 */
		return KERN_INVALID_VALUE;
	}

	if (ip_kotype(port) == IKOT_NAMED_ENTRY) {
		vm_named_entry_t	named_entry;

		named_entry = (vm_named_entry_t)port->ip_kobject;
		/* a few checks to make sure user is obeying rules */
		if(*upl_size == 0) {
			if(offset >= named_entry->size)
				return(KERN_INVALID_RIGHT);
			*upl_size = named_entry->size - offset;
		}
		if(caller_flags & UPL_COPYOUT_FROM) {
			if((named_entry->protection & VM_PROT_READ) 
						!= VM_PROT_READ) {
				return(KERN_INVALID_RIGHT);
			}
		} else {
			if((named_entry->protection & 
				(VM_PROT_READ | VM_PROT_WRITE)) 
				!= (VM_PROT_READ | VM_PROT_WRITE)) {
				return(KERN_INVALID_RIGHT);
			}
		}
		if(named_entry->size < (offset + *upl_size))
			return(KERN_INVALID_ARGUMENT);

		/* the callers parameter offset is defined to be the */
		/* offset from beginning of named entry offset in object */
		offset = offset + named_entry->offset;

		if(named_entry->is_sub_map) 
			return (KERN_INVALID_ARGUMENT);
		
		named_entry_lock(named_entry);

		if (named_entry->is_pager) {
			object = vm_object_enter(named_entry->backing.pager, 
					named_entry->offset + named_entry->size, 
					named_entry->internal, 
					FALSE,
					FALSE);
			if (object == VM_OBJECT_NULL) {
				named_entry_unlock(named_entry);
				return(KERN_INVALID_OBJECT);
			}

			/* JMM - drop reference on pager here? */

			/* create an extra reference for the named entry */
			vm_object_lock(object);
			vm_object_reference_locked(object);
			named_entry->backing.object = object;
			named_entry->is_pager = FALSE;
			named_entry_unlock(named_entry);

			/* wait for object to be ready */
			while (!object->pager_ready) {
				vm_object_wait(object,
						VM_OBJECT_EVENT_PAGER_READY,
						THREAD_UNINT);
				vm_object_lock(object);
			}
			vm_object_unlock(object);
		} else {
			/* This is the case where we are going to map */
			/* an already mapped object.  If the object is */
			/* not ready it is internal.  An external     */
			/* object cannot be mapped until it is ready  */
			/* we can therefore avoid the ready check     */
			/* in this case.  */
			object = named_entry->backing.object;
			vm_object_reference(object);
			named_entry_unlock(named_entry);
		}
	} else if (ip_kotype(port) == IKOT_MEM_OBJ_CONTROL) {
		memory_object_control_t	control;
		control = (memory_object_control_t) port;
		if (control == NULL)
			return (KERN_INVALID_ARGUMENT);
		object = memory_object_control_to_vm_object(control);
		if (object == VM_OBJECT_NULL)
			return (KERN_INVALID_ARGUMENT);
		vm_object_reference(object);
	} else {
		return KERN_INVALID_ARGUMENT;
	}
	if (object == VM_OBJECT_NULL)
		return (KERN_INVALID_ARGUMENT);

	if (!object->private) {
		if (*upl_size > (MAX_UPL_TRANSFER*PAGE_SIZE))
			*upl_size = (MAX_UPL_TRANSFER*PAGE_SIZE);
		if (object->phys_contiguous) {
			*flags = UPL_PHYS_CONTIG;
		} else {
			*flags = 0;
		}
	} else {
		*flags = UPL_DEV_MEMORY | UPL_PHYS_CONTIG;
	}

	ret = vm_object_iopl_request(object,
				     offset,
				     *upl_size,
				     upl_ptr,
				     user_page_list,
				     page_list_count,
				     caller_flags);
	vm_object_deallocate(object);
	return ret;
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
	upl_size_t		size,
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
	upl_size_t		size,
	upl_size_t		super_cluster,
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

kern_return_t
memory_object_cluster_size(memory_object_control_t control, memory_object_offset_t *start,
			   vm_size_t *length, memory_object_fault_info_t fault_info)
{
	vm_object_t		object;

	object = memory_object_control_to_vm_object(control);

	if (object == VM_OBJECT_NULL || object->paging_offset > *start)
		return (KERN_INVALID_ARGUMENT);

	*start -= object->paging_offset;

	vm_object_cluster_size(object, (vm_object_offset_t *)start, length, (vm_object_fault_info_t)fault_info);

	*start += object->paging_offset;

	return (KERN_SUCCESS);
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
	__unused memory_object_cluster_size_t cluster_size)
{
	memory_object_default_t current_manager;
	memory_object_default_t new_manager;
	memory_object_default_t returned_manager;
	kern_return_t result = KERN_SUCCESS;

	if (host_priv == HOST_PRIV_NULL)
		return(KERN_INVALID_HOST);

	assert(host_priv == &realhost);

	new_manager = *default_manager;
	mutex_lock(&memory_manager_default_lock);
	current_manager = memory_manager_default;
	returned_manager = MEMORY_OBJECT_DEFAULT_NULL;

	if (new_manager == MEMORY_OBJECT_DEFAULT_NULL) {
		/*
		 *	Retrieve the current value.
		 */
		returned_manager = current_manager;
		memory_object_default_reference(returned_manager);
	} else {

		/*
		 *	If this is the first non-null manager, start
		 *	up the internal pager support.
		 */
		if (current_manager == MEMORY_OBJECT_DEFAULT_NULL) {
			result = vm_pageout_internal_start();
			if (result != KERN_SUCCESS)
				goto out;
		}

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

		/*
		 *	In case anyone's been waiting for a memory
		 *	manager to be established, wake them up.
		 */

		thread_wakeup((event_t) &memory_manager_default);
	}
 out:
	mutex_unlock(&memory_manager_default_lock);

	*default_manager = returned_manager;
	return(result);
}

/*
 *	Routine:	memory_manager_default_reference
 *	Purpose:
 *		Returns a naked send right for the default
 *		memory manager.  The returned right is always
 *		valid (not IP_NULL or IP_DEAD).
 */

__private_extern__ memory_object_default_t
memory_manager_default_reference(void)
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
	mutex_init(&memory_manager_default_lock, 0);
}



/* Allow manipulation of individual page state.  This is actually part of */
/* the UPL regimen but takes place on the object rather than on a UPL */

kern_return_t
memory_object_page_op(
	memory_object_control_t	control,
	memory_object_offset_t	offset,
	int			ops,
	ppnum_t			*phys_entry,
	int			*flags)
{
	vm_object_t		object;

	object = memory_object_control_to_vm_object(control);
	if (object == VM_OBJECT_NULL)
		return (KERN_INVALID_ARGUMENT);

	return vm_object_page_op(object, offset, ops, phys_entry, flags);
}

/*
 * memory_object_range_op offers performance enhancement over 
 * memory_object_page_op for page_op functions which do not require page 
 * level state to be returned from the call.  Page_op was created to provide 
 * a low-cost alternative to page manipulation via UPLs when only a single 
 * page was involved.  The range_op call establishes the ability in the _op 
 * family of functions to work on multiple pages where the lack of page level
 * state handling allows the caller to avoid the overhead of the upl structures.
 */

kern_return_t
memory_object_range_op(
	memory_object_control_t	control,
	memory_object_offset_t	offset_beg,
	memory_object_offset_t	offset_end,
	int                     ops,
	int                     *range)
{
	vm_object_t		object;

	object = memory_object_control_to_vm_object(control);
	if (object == VM_OBJECT_NULL)
		return (KERN_INVALID_ARGUMENT);

	return vm_object_range_op(object,
				  offset_beg,
				  offset_end,
				  ops,
				  range);
}


kern_return_t
memory_object_pages_resident(
	memory_object_control_t	control,
	boolean_t			*	has_pages_resident)
{
	vm_object_t		object;

	*has_pages_resident = FALSE;

	object = memory_object_control_to_vm_object(control);
	if (object == VM_OBJECT_NULL)
		return (KERN_INVALID_ARGUMENT);

	if (object->resident_page_count)
		*has_pages_resident = TRUE;
	
	return (KERN_SUCCESS);
}

kern_return_t
memory_object_signed(
	memory_object_control_t	control,
	boolean_t		is_signed)
{
	vm_object_t	object;

	object = memory_object_control_to_vm_object(control);
	if (object == VM_OBJECT_NULL)
		return KERN_INVALID_ARGUMENT;

	vm_object_lock(object);
	object->code_signed = is_signed;
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
	if (control != MEMORY_OBJECT_CONTROL_NULL) {
		control->moc_object = object;
		control->moc_ikot = IKOT_MEM_OBJ_CONTROL; /* fake ip_kotype */
	}
	return (control);
}

__private_extern__ void
memory_object_control_collapse(
	memory_object_control_t control,		       
	vm_object_t		object)
{		       
	assert((control->moc_object != VM_OBJECT_NULL) &&
	       (control->moc_object != object));
	control->moc_object = object;
}

__private_extern__ vm_object_t
memory_object_control_to_vm_object(
	memory_object_control_t	control)
{
	if (control == MEMORY_OBJECT_CONTROL_NULL ||
	    control->moc_ikot != IKOT_MEM_OBJ_CONTROL)
		return VM_OBJECT_NULL;

	return (control->moc_object);
}

memory_object_control_t
convert_port_to_mo_control(
	__unused mach_port_t	port)
{
	return MEMORY_OBJECT_CONTROL_NULL;
}


mach_port_t
convert_mo_control_to_port(
	__unused memory_object_control_t	control)
{
	return MACH_PORT_NULL;
}

void
memory_object_control_reference(
	__unused memory_object_control_t	control)
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
	zfree(mem_obj_control_zone, control);
}

void
memory_object_control_disable(
	memory_object_control_t	control)
{
	assert(control->moc_object != VM_OBJECT_NULL);
	control->moc_object = VM_OBJECT_NULL;
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
	__unused mach_port_t	port)
{
	return (MEMORY_OBJECT_NULL);
}


mach_port_t
convert_memory_object_to_port(
	__unused memory_object_t	object)
{
	return (MACH_PORT_NULL);
}


/* Routine memory_object_reference */
void memory_object_reference(
	memory_object_t memory_object)
{
	(memory_object->mo_pager_ops->memory_object_reference)(
		memory_object);
}

/* Routine memory_object_deallocate */
void memory_object_deallocate(
	memory_object_t memory_object)
{
	(memory_object->mo_pager_ops->memory_object_deallocate)(
		 memory_object);
}


/* Routine memory_object_init */
kern_return_t memory_object_init
(
	memory_object_t memory_object,
	memory_object_control_t memory_control,
	memory_object_cluster_size_t memory_object_page_size
)
{
	return (memory_object->mo_pager_ops->memory_object_init)(
		memory_object,
		memory_control,
		memory_object_page_size);
}

/* Routine memory_object_terminate */
kern_return_t memory_object_terminate
(
	memory_object_t memory_object
)
{
	return (memory_object->mo_pager_ops->memory_object_terminate)(
		memory_object);
}

/* Routine memory_object_data_request */
kern_return_t memory_object_data_request
(
	memory_object_t memory_object,
	memory_object_offset_t offset,
	memory_object_cluster_size_t length,
	vm_prot_t desired_access,
	memory_object_fault_info_t fault_info
)
{
	return (memory_object->mo_pager_ops->memory_object_data_request)(
		memory_object,
		offset, 
		length,
		desired_access,
		fault_info);
}

/* Routine memory_object_data_return */
kern_return_t memory_object_data_return
(
	memory_object_t memory_object,
	memory_object_offset_t offset,
	vm_size_t size,
	memory_object_offset_t *resid_offset,
	int	*io_error,
	boolean_t dirty,
	boolean_t kernel_copy,
	int	upl_flags
)
{
	return (memory_object->mo_pager_ops->memory_object_data_return)(
		memory_object,
		offset,
		size,
		resid_offset,
		io_error,
		dirty,
		kernel_copy,
		upl_flags);
}

/* Routine memory_object_data_initialize */
kern_return_t memory_object_data_initialize
(
	memory_object_t memory_object,
	memory_object_offset_t offset,
	vm_size_t size
)
{
	return (memory_object->mo_pager_ops->memory_object_data_initialize)(
		memory_object,
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
	return (memory_object->mo_pager_ops->memory_object_data_unlock)(
		memory_object,
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
	return (memory_object->mo_pager_ops->memory_object_synchronize)(
		memory_object,
		offset,
		size,
		sync_flags);
}


/*
 * memory_object_map() is called by VM (in vm_map_enter() and its variants)
 * each time a "named" VM object gets mapped directly or indirectly
 * (copy-on-write mapping).  A "named" VM object has an extra reference held
 * by the pager to keep it alive until the pager decides that the 
 * memory object (and its VM object) can be reclaimed.
 * VM calls memory_object_last_unmap() (in vm_object_deallocate()) when all
 * the mappings of that memory object have been removed.
 *
 * For a given VM object, calls to memory_object_map() and memory_object_unmap()
 * are serialized (through object->mapping_in_progress), to ensure that the
 * pager gets a consistent view of the mapping status of the memory object.
 *
 * This allows the pager to keep track of how many times a memory object
 * has been mapped and with which protections, to decide when it can be
 * reclaimed.
 */

/* Routine memory_object_map */
kern_return_t memory_object_map
(
	memory_object_t memory_object,
	vm_prot_t prot
)
{
	return (memory_object->mo_pager_ops->memory_object_map)(
		memory_object,
		prot);
}

/* Routine memory_object_last_unmap */
kern_return_t memory_object_last_unmap
(
	memory_object_t memory_object
)
{
	return (memory_object->mo_pager_ops->memory_object_last_unmap)(
		memory_object);
}

/* Routine memory_object_create */
kern_return_t memory_object_create
(
	memory_object_default_t default_memory_manager,
	vm_size_t new_memory_object_size,
	memory_object_t *new_memory_object
)
{
	return default_pager_memory_object_create(default_memory_manager,
						  new_memory_object_size,
						  new_memory_object);
}

upl_t
convert_port_to_upl(
	ipc_port_t	port)
{
	upl_t upl;

	ip_lock(port);
	if (!ip_active(port) || (ip_kotype(port) != IKOT_UPL)) {
			ip_unlock(port);
			return (upl_t)NULL;
	}
	upl = (upl_t) port->ip_kobject;
	ip_unlock(port);
	upl_lock(upl);
	upl->ref_count+=1;
	upl_unlock(upl);
	return upl;
}

mach_port_t
convert_upl_to_port(
	__unused upl_t		upl)
{
	return MACH_PORT_NULL;
}

__private_extern__ void
upl_no_senders(
	__unused ipc_port_t				port,
	__unused mach_port_mscount_t	mscount)
{
	return;
}
