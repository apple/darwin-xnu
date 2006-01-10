/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
 * Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
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
 *	File:	vm/vm_page.h
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Resident memory system definitions.
 */

#ifndef	_VM_VM_PAGE_H_
#define _VM_VM_PAGE_H_

#include <debug.h>

#include <mach/boolean.h>
#include <mach/vm_prot.h>
#include <mach/vm_param.h>
#include <vm/vm_object.h>
#include <kern/queue.h>
#include <kern/lock.h>

#include <kern/macro_help.h>

/* 
 * Each page entered on the inactive queue obtains a ticket from a
 * particular ticket roll.  Pages granted tickets from a particular 
 * roll  generally flow through the queue as a group.  In this way when a
 * page with a ticket from a particular roll is pulled from the top of the
 * queue it is extremely likely that the pages near the top will have tickets
 * from the same or adjacent rolls.  In this way the proximity to the top
 * of the queue can be loosely ascertained by determining the identity of
 * the roll the pages ticket came from. 
 */


extern unsigned int	vm_page_ticket_roll;
extern unsigned int	vm_page_ticket;


#define VM_PAGE_TICKETS_IN_ROLL  512
#define VM_PAGE_TICKET_ROLL_IDS  16

/*
 *	Management of resident (logical) pages.
 *
 *	A small structure is kept for each resident
 *	page, indexed by page number.  Each structure
 *	is an element of several lists:
 *
 *		A hash table bucket used to quickly
 *		perform object/offset lookups
 *
 *		A list of all pages for a given object,
 *		so they can be quickly deactivated at
 *		time of deallocation.
 *
 *		An ordered list of pages due for pageout.
 *
 *	In addition, the structure contains the object
 *	and offset to which this page belongs (for pageout),
 *	and sundry status bits.
 *
 *	Fields in this structure are locked either by the lock on the
 *	object that the page belongs to (O) or by the lock on the page
 *	queues (P).  [Some fields require that both locks be held to
 *	change that field; holding either lock is sufficient to read.]
 */

struct vm_page {
	queue_chain_t	pageq;		/* queue info for FIFO
					 * queue or free list (P) */
	queue_chain_t	listq;		/* all pages in same object (O) */
	struct vm_page	*next;		/* VP bucket link (O) */

	vm_object_t	object;		/* which object am I in (O&P) */
	vm_object_offset_t offset;	/* offset into that object (O,P) */

	/*
	 * The following word of flags is protected
	 * by the "page queues" lock.
	 */
	unsigned int	wire_count:16,	/* how many wired down maps use me? (O&P) */
			page_ticket:4,	/* age of the page on the       */
					/* inactive queue.		    */
	/* boolean_t */	inactive:1,	/* page is in inactive list (P) */
			active:1,	/* page is in active list (P) */
			pageout_queue:1,/* page is on queue for pageout (P) */
			laundry:1,	/* page is being cleaned now (P)*/
			free:1,		/* page is on free list (P) */
			reference:1,	/* page has been used (P) */
			pageout:1,	/* page wired & busy for pageout (P) */
			gobbled:1,      /* page used internally (P) */
			private:1,	/* Page should not be returned to
					 *  the free list (P) */
			zero_fill:1,
			:0;

	/*
	 * The following word of flags is protected
	 * by the "VM object" lock.
	 */
	unsigned int
	                page_error:8,   /* error from I/O operations */
	/* boolean_t */	busy:1,		/* page is in transit (O) */
			wanted:1,	/* someone is waiting for page (O) */
			tabled:1,	/* page is in VP table (O) */
			fictitious:1,	/* Physical page doesn't exist (O) */
			no_isync:1,     /* page has not been instruction synced */
			absent:1,	/* Data has been requested, but is
					 *  not yet available (O) */
			error:1,	/* Data manager was unable to provide
					 *  data due to error (O) */
			dirty:1,	/* Page must be cleaned (O) */
			cleaning:1,	/* Page clean has begun (O) */
			precious:1,	/* Page is precious; data must be
					 *  returned even if clean (O) */
			clustered:1,	/* page is not the faulted page (O) */
			overwriting:1,  /* Request to unlock has been made
					 * without having data. (O)
					 * [See vm_fault_page_overwrite] */
			restart:1,	/* Page was pushed higher in shadow
					   chain by copy_call-related pagers;
					   start again at top of chain */
			lock_supplied:1,/* protection supplied by pager (O) */
	/* vm_prot_t */	page_lock:3,	/* Uses prohibited by pager (O) */
	/* vm_prot_t */	unlock_request:3,/* Outstanding unlock request (O) */
			unusual:1,	/* Page is absent, error, restart or
					   page locked */
			encrypted:1,	/* encrypted for secure swap (O) */
			list_req_pending:1, /* pagein/pageout alt mechanism */
					    /* allows creation of list      */
					    /* requests on pages that are   */
					    /* actively being paged.        */
			dump_cleaning:1;   /* set by the pageout daemon when */
					   /* a page being cleaned is       */
					   /* encountered and targeted as   */
					   /* a pageout candidate           */
        /* we've used up all 32 bits */

	ppnum_t		phys_page;	/* Physical address of page, passed
					 *  to pmap_enter (read-only) */
};

#define DEBUG_ENCRYPTED_SWAP	1
#if DEBUG_ENCRYPTED_SWAP
#define ASSERT_PAGE_DECRYPTED(page) 					\
	MACRO_BEGIN							\
	if ((page)->encrypted) {					\
		panic("VM page %p should not be encrypted here\n",	\
		      (page));						\
	}								\
	MACRO_END
#else	/* DEBUG_ENCRYPTED_SWAP */
#define ASSERT_PAGE_DECRYPTED(page) assert(!(page)->encrypted)
#endif	/* DEBUG_ENCRYPTED_SWAP */

typedef struct vm_page	*vm_page_t;

#define VM_PAGE_NULL		((vm_page_t) 0)
#define NEXT_PAGE(m)		((vm_page_t) (m)->pageq.next)
#define NEXT_PAGE_PTR(m)	((vm_page_t *) &(m)->pageq.next)

/*
 * XXX	The unusual bit should not be necessary.  Most of the bit
 * XXX	fields above really want to be masks.
 */

/*
 *	For debugging, this macro can be defined to perform
 *	some useful check on a page structure.
 */

#define VM_PAGE_CHECK(mem)

/*
 *	Each pageable resident page falls into one of three lists:
 *
 *	free	
 *		Available for allocation now.
 *	inactive
 *		Not referenced in any map, but still has an
 *		object/offset-page mapping, and may be dirty.
 *		This is the list of pages that should be
 *		paged out next.
 *	active
 *		A list of pages which have been placed in
 *		at least one physical map.  This list is
 *		ordered, in LRU-like fashion.
 */

extern
vm_page_t	vm_page_queue_free;	/* memory free queue */
extern
vm_page_t	vm_page_queue_fictitious;	/* fictitious free queue */
extern
queue_head_t	vm_page_queue_active;	/* active memory queue */
extern
queue_head_t	vm_page_queue_inactive;	/* inactive memory queue */
queue_head_t	vm_page_queue_zf;	/* inactive memory queue for zero fill */

extern
vm_offset_t	first_phys_addr;	/* physical address for first_page */
extern
vm_offset_t	last_phys_addr;		/* physical address for last_page */

extern
unsigned int	vm_page_free_count;	/* How many pages are free? */
extern
unsigned int	vm_page_fictitious_count;/* How many fictitious pages are free? */
extern
unsigned int	vm_page_active_count;	/* How many pages are active? */
extern
unsigned int	vm_page_inactive_count;	/* How many pages are inactive? */
extern
unsigned int	vm_page_wire_count;	/* How many pages are wired? */
extern
unsigned int	vm_page_free_target;	/* How many do we want free? */
extern
unsigned int	vm_page_free_min;	/* When to wakeup pageout */
extern
unsigned int	vm_page_inactive_target;/* How many do we want inactive? */
extern
unsigned int	vm_page_free_reserved;	/* How many pages reserved to do pageout */
extern
unsigned int	vm_page_throttled_count;/* Count of zero-fill allocations throttled */
extern
unsigned int	vm_page_gobble_count;

extern
unsigned int	vm_page_purgeable_count;/* How many pages are purgeable now ? */
extern
uint64_t	vm_page_purged_count;	/* How many pages got purged so far ? */

decl_mutex_data(,vm_page_queue_lock)
				/* lock on active and inactive page queues */
decl_mutex_data(,vm_page_queue_free_lock)
				/* lock on free page queue */

extern unsigned int	vm_page_free_wanted;
				/* how many threads are waiting for memory */

extern vm_offset_t	vm_page_fictitious_addr;
				/* (fake) phys_addr of fictitious pages */

extern boolean_t	vm_page_deactivate_hint;

/*
 * Prototypes for functions exported by this module.
 */
extern void		vm_page_bootstrap(
					vm_offset_t	*startp,
					vm_offset_t	*endp);

extern void		vm_page_module_init(void);

extern void		vm_page_create(
					ppnum_t		start,
					ppnum_t		end);

extern vm_page_t	vm_page_lookup(
					vm_object_t		object,
					vm_object_offset_t	offset);

extern vm_page_t	vm_page_grab_fictitious(void);

extern void		vm_page_release_fictitious(
					vm_page_t page);

extern boolean_t	vm_page_convert(
					vm_page_t	page);

extern void		vm_page_more_fictitious(void);

extern int		vm_pool_low(void);

extern vm_page_t	vm_page_grab(void);

extern void		vm_page_release(
					vm_page_t	page);

extern boolean_t	vm_page_wait(
					int		interruptible );

extern vm_page_t	vm_page_alloc(
					vm_object_t		object,
					vm_object_offset_t	offset);

extern void		vm_page_init(
					vm_page_t	page,
					ppnum_t		phys_page);

extern void		vm_page_free(
					vm_page_t	page);

extern void		vm_page_activate(
					vm_page_t	page);

extern void		vm_page_deactivate(
					vm_page_t	page);

extern void		vm_page_rename(
					vm_page_t		page,
					vm_object_t		new_object,
					vm_object_offset_t	new_offset);

extern void		vm_page_insert(
					vm_page_t		page,
					vm_object_t		object,
					vm_object_offset_t	offset);

extern void		vm_page_replace(
					vm_page_t		mem,
					vm_object_t		object,
					vm_object_offset_t	offset);

extern void		vm_page_remove(
					vm_page_t	page);

extern void		vm_page_zero_fill(
					vm_page_t	page);

extern void		vm_page_part_zero_fill(
					vm_page_t	m,
					vm_offset_t	m_pa,
					vm_size_t	len);

extern void		vm_page_copy(
					vm_page_t	src_page,
					vm_page_t	dest_page);

extern void		vm_page_part_copy(
					vm_page_t	src_m,
					vm_offset_t	src_pa,
					vm_page_t	dst_m,
					vm_offset_t	dst_pa,
					vm_size_t	len);

extern void		vm_page_wire(
					vm_page_t	page);

extern void		vm_page_unwire(
					vm_page_t	page);

extern void		vm_set_page_size(void);

extern void		vm_page_gobble(
				        vm_page_t      page);

/*
 *	Functions implemented as macros. m->wanted and m->busy are
 *	protected by the object lock.
 */

#define PAGE_ASSERT_WAIT(m, interruptible)			\
		(((m)->wanted = TRUE),				\
		 assert_wait((event_t) (m), (interruptible)))

#define PAGE_SLEEP(o, m, interruptible)				\
		(((m)->wanted = TRUE),				\
		 thread_sleep_vm_object((o), (m), (interruptible)))

#define PAGE_WAKEUP_DONE(m)					\
		MACRO_BEGIN					\
		(m)->busy = FALSE;				\
		if ((m)->wanted) {				\
			(m)->wanted = FALSE;			\
			thread_wakeup((event_t) (m));		\
		}						\
		MACRO_END

#define PAGE_WAKEUP(m)						\
		MACRO_BEGIN					\
		if ((m)->wanted) {				\
			(m)->wanted = FALSE;			\
			thread_wakeup((event_t) (m));		\
		}						\
		MACRO_END

#define VM_PAGE_FREE(p) 			\
		MACRO_BEGIN			\
		vm_page_lock_queues();		\
		vm_page_free(p);		\
		vm_page_unlock_queues();	\
		MACRO_END

#define VM_PAGE_GRAB_FICTITIOUS(M)					\
		MACRO_BEGIN						\
		while ((M = vm_page_grab_fictitious()) == VM_PAGE_NULL)	\
			vm_page_more_fictitious();			\
		MACRO_END

#define VM_PAGE_THROTTLED()						\
		(vm_page_free_count < vm_page_free_min &&		\
		 !(current_thread()->options & TH_OPT_VMPRIV) && 			\
		 ++vm_page_throttled_count)

#define	VM_PAGE_WAIT()		((void)vm_page_wait(THREAD_UNINT))

#define vm_page_lock_queues()	mutex_lock(&vm_page_queue_lock)
#define vm_page_unlock_queues()	mutex_unlock(&vm_page_queue_lock)

#define VM_PAGE_QUEUES_REMOVE(mem)				\
	MACRO_BEGIN						\
	assert(!mem->laundry);					\
	if (mem->active) {					\
		assert(mem->object != kernel_object);		\
		assert(!mem->inactive);				\
		queue_remove(&vm_page_queue_active,		\
			mem, vm_page_t, pageq);			\
		mem->pageq.next = NULL;				\
		mem->pageq.prev = NULL;			       	\
		mem->active = FALSE;				\
		if (!mem->fictitious)				\
			vm_page_active_count--;			\
	}							\
								\
	if (mem->inactive) {					\
		assert(mem->object != kernel_object);		\
		assert(!mem->active);				\
		if (mem->zero_fill) {				\
			queue_remove(&vm_page_queue_zf,		\
			mem, vm_page_t, pageq);			\
		} else {					\
			queue_remove(&vm_page_queue_inactive,	\
			mem, vm_page_t, pageq);			\
		}						\
		mem->pageq.next = NULL;				\
		mem->pageq.prev = NULL;			       	\
		mem->inactive = FALSE;				\
		if (!mem->fictitious)				\
			vm_page_inactive_count--;		\
	}							\
	MACRO_END

#endif	/* _VM_VM_PAGE_H_ */
