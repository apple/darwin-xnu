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
#include <vm/vm_options.h>

#include <mach/boolean.h>
#include <mach/vm_prot.h>
#include <mach/vm_param.h>
#include <vm/vm_object.h>
#include <kern/queue.h>
#include <kern/lock.h>

#include <kern/macro_help.h>
#include <libkern/OSAtomic.h>


/* 
 * VM_PAGE_MIN_SPECULATIVE_AGE_Q through VM_PAGE_MAX_SPECULATIVE_AGE_Q
 * represents a set of aging bins that are 'protected'...
 *
 * VM_PAGE_SPECULATIVE_AGED_Q is a list of the speculative pages that have
 * not yet been 'claimed' but have been aged out of the protective bins
 * this occurs in vm_page_speculate when it advances to the next bin 
 * and discovers that it is still occupied... at that point, all of the
 * pages in that bin are moved to the VM_PAGE_SPECULATIVE_AGED_Q.  the pages
 * in that bin are all guaranteed to have reached at least the maximum age
 * we allow for a protected page... they can be older if there is no
 * memory pressure to pull them from the bin, or there are no new speculative pages
 * being generated to push them out.
 * this list is the one that vm_pageout_scan will prefer when looking 
 * for pages to move to the underweight free list
 * 
 * VM_PAGE_MAX_SPECULATIVE_AGE_Q * VM_PAGE_SPECULATIVE_Q_AGE_MS
 * defines the amount of time a speculative page is normally
 * allowed to live in the 'protected' state (i.e. not available
 * to be stolen if vm_pageout_scan is running and looking for
 * pages)...  however, if the total number of speculative pages
 * in the protected state exceeds our limit (defined in vm_pageout.c)
 * and there are none available in VM_PAGE_SPECULATIVE_AGED_Q, then
 * vm_pageout_scan is allowed to steal pages from the protected
 * bucket even if they are underage.
 *
 * vm_pageout_scan is also allowed to pull pages from a protected
 * bin if the bin has reached the "age of consent" we've set
 */
#define VM_PAGE_MAX_SPECULATIVE_AGE_Q	10
#define VM_PAGE_MIN_SPECULATIVE_AGE_Q	1
#define VM_PAGE_SPECULATIVE_AGED_Q	0

#define VM_PAGE_SPECULATIVE_Q_AGE_MS	500

struct vm_speculative_age_q {
	/*
	 * memory queue for speculative pages via clustered pageins
	 */
        queue_head_t	age_q;
        mach_timespec_t	age_ts;
};



extern
struct vm_speculative_age_q	vm_page_queue_speculative[];

extern int			speculative_steal_index;
extern int			speculative_age_index;
extern unsigned int		vm_page_speculative_q_age_ms;


#define	VM_PAGE_COMPRESSOR_COUNT	(compressor_object->resident_page_count)

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
	queue_chain_t	pageq;		/* queue info for FIFO */
					/* queue or free list (P) */

	queue_chain_t	listq;		/* all pages in same object (O) */
	struct vm_page	*next;		/* VP bucket link (O) */

	vm_object_t	object;		/* which object am I in (O&P) */
	vm_object_offset_t offset;	/* offset into that object (O,P) */

	/*
	 * The following word of flags is protected
	 * by the "page queues" lock.
	 *
	 * we use the 'wire_count' field to store the local
	 * queue id if local queues are enabled...
	 * see the comments at 'VM_PAGE_QUEUES_REMOVE' as to
	 * why this is safe to do
	 */
#define local_id wire_count
	unsigned int	wire_count:16,	/* how many wired down maps use me? (O&P) */
	/* boolean_t */	active:1,	/* page is in active list (P) */
			inactive:1,	/* page is in inactive list (P) */
			clean_queue:1,	/* page is in pre-cleaned list (P) */
		        local:1,	/* page is in one of the local queues (P) */
			speculative:1,	/* page is in speculative list (P) */
			throttled:1,	/* pager is not responding or doesn't exist(P) */
			free:1,		/* page is on free list (P) */
			pageout_queue:1,/* page is on queue for pageout (P) */
			laundry:1,	/* page is being cleaned now (P)*/
			reference:1,	/* page has been used (P) */
			gobbled:1,      /* page used internally (P) */
			private:1,	/* Page should not be returned to
					 *  the free list (P) */
			no_cache:1,	/* page is not to be cached and should
					 * be reused ahead of other pages (P) */
		        xpmapped:1,
			__unused_pageq_bits:2;	/* 2 bits available here */

	ppnum_t		phys_page;	/* Physical address of page, passed
					 *  to pmap_enter (read-only) */

	/*
	 * The following word of flags is protected
	 * by the "VM object" lock.
	 */
	unsigned int
	/* boolean_t */	busy:1,		/* page is in transit (O) */
			wanted:1,	/* someone is waiting for page (O) */
			tabled:1,	/* page is in VP table (O) */
			hashed:1,	/* page is in vm_page_buckets[]
					   (O) + the bucket lock */
			fictitious:1,	/* Physical page doesn't exist (O) */
	/*
	 * IMPORTANT: the "pmapped" bit can be turned on while holding the
	 * VM object "shared" lock.  See vm_fault_enter().
	 * This is OK as long as it's the only bit in this bit field that
	 * can be updated without holding the VM object "exclusive" lock.
	 */
			pmapped:1,     	/* page has been entered at some
					 * point into a pmap (O **shared**) */
			wpmapped:1,     /* page has been entered at some
					 * point into a pmap for write (O) */
			pageout:1,	/* page wired & busy for pageout (O) */
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
			unusual:1,	/* Page is absent, error, restart or
					   page locked */
			encrypted:1,	/* encrypted for secure swap (O) */
			encrypted_cleaning:1,	/* encrypting page */
			cs_validated:1,    /* code-signing: page was checked */	
			cs_tainted:1,	   /* code-signing: page is tainted */
			reusable:1,
		        lopage:1,
			slid:1,
			was_dirty:1,	/* was this page previously dirty? */
		        compressor:1,	/* page owned by compressor pool */
		        written_by_kernel:1,	/* page was written by kernel (i.e. decompressed) */
			__unused_object_bits:5;	/* 5 bits available here */

#if __LP64__
	unsigned int __unused_padding;	/* Pad structure explicitly
					* to 8-byte multiple for LP64 */
#endif
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


typedef struct vm_locks_array {
	char	pad  __attribute__ ((aligned (64)));
	lck_mtx_t	vm_page_queue_lock2 __attribute__ ((aligned (64)));
	lck_mtx_t	vm_page_queue_free_lock2 __attribute__ ((aligned (64)));
	char	pad2  __attribute__ ((aligned (64)));
} vm_locks_array_t;


#define VM_PAGE_WIRED(m)	((!(m)->local && (m)->wire_count))
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

#define VM_PAGE_CHECK(mem)			\
	MACRO_BEGIN				\
	VM_PAGE_QUEUES_ASSERT(mem, 1);		\
	MACRO_END

/*     Page coloring:
 *
 *     The free page list is actually n lists, one per color,
 *     where the number of colors is a function of the machine's
 *     cache geometry set at system initialization.  To disable
 *     coloring, set vm_colors to 1 and vm_color_mask to 0.
 *     The boot-arg "colors" may be used to override vm_colors.
 *     Note that there is little harm in having more colors than needed.
 */
 
#define MAX_COLORS      128
#define	DEFAULT_COLORS	32

extern
unsigned int	vm_colors;		/* must be in range 1..MAX_COLORS */
extern
unsigned int	vm_color_mask;		/* must be (vm_colors-1) */
extern
unsigned int	vm_cache_geometry_colors; /* optimal #colors based on cache geometry */

/*
 * Wired memory is a very limited resource and we can't let users exhaust it
 * and deadlock the entire system.  We enforce the following limits:
 * 
 * vm_user_wire_limit (default: all memory minus vm_global_no_user_wire_amount)
 * 	how much memory can be user-wired in one user task
 *
 * vm_global_user_wire_limit (default: same as vm_user_wire_limit)
 * 	how much memory can be user-wired in all user tasks
 *
 * vm_global_no_user_wire_amount (default: VM_NOT_USER_WIREABLE)
 *	how much memory must remain user-unwired at any time
 */
#define VM_NOT_USER_WIREABLE (64*1024*1024)	/* 64MB */
extern
vm_map_size_t	vm_user_wire_limit;
extern
vm_map_size_t	vm_global_user_wire_limit;
extern
vm_map_size_t	vm_global_no_user_wire_amount;

/*
 *	Each pageable resident page falls into one of three lists:
 *
 *	free	
 *		Available for allocation now.  The free list is
 *		actually an array of lists, one per color.
 *	inactive
 *		Not referenced in any map, but still has an
 *		object/offset-page mapping, and may be dirty.
 *		This is the list of pages that should be
 *		paged out next.  There are actually two
 *		inactive lists, one for pages brought in from
 *		disk or other backing store, and another
 *		for "zero-filled" pages.  See vm_pageout_scan()
 *		for the distinction and usage.
 *	active
 *		A list of pages which have been placed in
 *		at least one physical map.  This list is
 *		ordered, in LRU-like fashion.
 */


#define VPL_LOCK_SPIN 1

struct vpl {
	unsigned int	vpl_count;
	unsigned int	vpl_internal_count;
	unsigned int	vpl_external_count;
	queue_head_t	vpl_queue;
#ifdef	VPL_LOCK_SPIN
	lck_spin_t	vpl_lock;
#else
	lck_mtx_t	vpl_lock;
	lck_mtx_ext_t	vpl_lock_ext;
#endif
};

struct	vplq {
	union {
		char   cache_line_pad[128];
		struct vpl vpl;
	} vpl_un;
};
extern
unsigned int	vm_page_local_q_count;
extern
struct vplq	*vm_page_local_q;
extern
unsigned int	vm_page_local_q_soft_limit;
extern
unsigned int	vm_page_local_q_hard_limit;
extern
vm_locks_array_t vm_page_locks;

extern
queue_head_t	vm_page_queue_free[MAX_COLORS];	/* memory free queue */
extern
queue_head_t	vm_lopage_queue_free;		/* low memory free queue */
extern
queue_head_t	vm_page_queue_active;	/* active memory queue */
extern
queue_head_t	vm_page_queue_inactive;	/* inactive memory queue for normal pages */
extern
queue_head_t    vm_page_queue_cleaned; /* clean-queue inactive memory */
extern
queue_head_t	vm_page_queue_anonymous;	/* inactive memory queue for anonymous pages */
extern
queue_head_t	vm_page_queue_throttled;	/* memory queue for throttled pageout pages */

extern
vm_offset_t	first_phys_addr;	/* physical address for first_page */
extern
vm_offset_t	last_phys_addr;		/* physical address for last_page */

extern
unsigned int	vm_page_free_count;	/* How many pages are free? (sum of all colors) */
extern
unsigned int	vm_page_fictitious_count;/* How many fictitious pages are free? */
extern
unsigned int	vm_page_active_count;	/* How many pages are active? */
extern
unsigned int	vm_page_inactive_count;	/* How many pages are inactive? */
extern
unsigned int    vm_page_cleaned_count; /* How many pages are in the clean queue? */
extern
unsigned int	vm_page_throttled_count;/* How many inactives are throttled */
extern
unsigned int	vm_page_speculative_count;	/* How many speculative pages are unclaimed? */
extern unsigned int	vm_page_pageable_internal_count;
extern unsigned int	vm_page_pageable_external_count;
extern
unsigned int	vm_page_external_count;	/* How many pages are file-backed? */
extern
unsigned int	vm_page_internal_count;	/* How many pages are anonymous? */
extern
unsigned int	vm_page_wire_count;		/* How many pages are wired? */
extern
unsigned int	vm_page_wire_count_initial;	/* How many pages wired at startup */
extern
unsigned int	vm_page_free_target;	/* How many do we want free? */
extern
unsigned int	vm_page_free_min;	/* When to wakeup pageout */
extern
unsigned int	vm_page_throttle_limit;	/* When to throttle new page creation */
extern
uint32_t	vm_page_creation_throttle;	/* When to throttle new page creation */
extern
unsigned int	vm_page_inactive_target;/* How many do we want inactive? */
extern
unsigned int	vm_page_anonymous_min;	/* When it's ok to pre-clean */
extern
unsigned int	vm_page_inactive_min;   /* When do wakeup pageout */
extern
unsigned int	vm_page_free_reserved;	/* How many pages reserved to do pageout */
extern
unsigned int	vm_page_throttle_count;	/* Count of page allocations throttled */
extern
unsigned int	vm_page_gobble_count;

#if DEVELOPMENT || DEBUG
extern
unsigned int	vm_page_speculative_used;
#endif

extern
unsigned int	vm_page_purgeable_count;/* How many pages are purgeable now ? */
extern
unsigned int	vm_page_purgeable_wired_count;/* How many purgeable pages are wired now ? */
extern
uint64_t	vm_page_purged_count;	/* How many pages got purged so far ? */

extern unsigned int	vm_page_free_wanted;
				/* how many threads are waiting for memory */

extern unsigned int	vm_page_free_wanted_privileged;
				/* how many VM privileged threads are waiting for memory */

extern ppnum_t	vm_page_fictitious_addr;
				/* (fake) phys_addr of fictitious pages */

extern ppnum_t	vm_page_guard_addr;
				/* (fake) phys_addr of guard pages */


extern boolean_t	vm_page_deactivate_hint;

extern int		vm_compressor_mode;

/*
   0 = all pages avail ( default. )
   1 = disable high mem ( cap max pages to 4G)
   2 = prefer himem
*/   
extern int		vm_himemory_mode;

extern boolean_t	vm_lopage_needed;
extern uint32_t		vm_lopage_free_count;
extern uint32_t		vm_lopage_free_limit;
extern uint32_t		vm_lopage_lowater;
extern boolean_t	vm_lopage_refill;
extern uint64_t		max_valid_dma_address;
extern ppnum_t		max_valid_low_ppnum;

/*
 * Prototypes for functions exported by this module.
 */
extern void		vm_page_bootstrap(
					vm_offset_t	*startp,
					vm_offset_t	*endp);

extern void		vm_page_module_init(void);
					
extern void		vm_page_init_local_q(void);

extern void		vm_page_create(
					ppnum_t		start,
					ppnum_t		end);

extern vm_page_t	vm_page_lookup(
					vm_object_t		object,
					vm_object_offset_t	offset);

extern vm_page_t	vm_page_grab_fictitious(void);

extern vm_page_t	vm_page_grab_guard(void);

extern void		vm_page_release_fictitious(
					vm_page_t page);

extern void		vm_page_more_fictitious(void);

extern int		vm_pool_low(void);

extern vm_page_t	vm_page_grab(void);

extern vm_page_t	vm_page_grablo(void);

extern void		vm_page_release(
					vm_page_t	page);

extern boolean_t	vm_page_wait(
					int		interruptible );

extern vm_page_t	vm_page_alloc(
					vm_object_t		object,
					vm_object_offset_t	offset);

extern vm_page_t	vm_page_alloclo(
					vm_object_t		object,
					vm_object_offset_t	offset);

extern vm_page_t	vm_page_alloc_guard(
	vm_object_t		object,
	vm_object_offset_t	offset);

extern void		vm_page_init(
					vm_page_t	page,
					ppnum_t		phys_page,
					boolean_t 	lopage);

extern void		vm_page_free(
	                                vm_page_t	page);

extern void		vm_page_free_unlocked(
	                                vm_page_t	page,
					boolean_t	remove_from_hash);

extern void		vm_page_activate(
					vm_page_t	page);

extern void		vm_page_deactivate(
					vm_page_t	page);

extern void		vm_page_deactivate_internal(
	                                vm_page_t	page,
					boolean_t	clear_hw_reference);

extern void		vm_page_enqueue_cleaned(vm_page_t page);

extern void		vm_page_lru(
					vm_page_t	page);

extern void		vm_page_speculate(
					vm_page_t	page,
					boolean_t	new);

extern void		vm_page_speculate_ageit(
					struct vm_speculative_age_q *aq);

extern void		vm_page_reactivate_all_throttled(void);

extern void		vm_page_reactivate_local(uint32_t lid, boolean_t force, boolean_t nolocks);

extern void		vm_page_rename(
					vm_page_t		page,
					vm_object_t		new_object,
					vm_object_offset_t	new_offset,
					boolean_t		encrypted_ok);

extern void		vm_page_insert(
					vm_page_t		page,
					vm_object_t		object,
					vm_object_offset_t	offset);

extern void		vm_page_insert_internal(
					vm_page_t		page,
					vm_object_t		object,
					vm_object_offset_t	offset,
					boolean_t		queues_lock_held,
					boolean_t		insert_in_hash,
					boolean_t		batch_pmap_op);

extern void		vm_page_replace(
					vm_page_t		mem,
					vm_object_t		object,
					vm_object_offset_t	offset);

extern void		vm_page_remove(
	                                vm_page_t	page,
					boolean_t	remove_from_hash);

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
	                                vm_page_t	page,
					boolean_t	queueit);

extern void		vm_set_page_size(void);

extern void		vm_page_gobble(
				        vm_page_t      page);

extern void		vm_page_validate_cs(vm_page_t	page);
extern void		vm_page_validate_cs_mapped(
	vm_page_t	page,
	const void	*kaddr);

extern void		vm_page_free_prepare_queues(
					vm_page_t	page);

extern void		vm_page_free_prepare_object(
	                                vm_page_t	page,
					boolean_t	remove_from_hash);

#if CONFIG_JETSAM
extern void memorystatus_pages_update(unsigned int pages_avail);

#define VM_CHECK_MEMORYSTATUS do { \
	memorystatus_pages_update(		\
      		vm_page_external_count + \
		vm_page_free_count +		\
      		(VM_DYNAMIC_PAGING_ENABLED(memory_manager_default) ? 0 : vm_page_purgeable_count) \
		); \
	} while(0)

#else /* CONFIG_JETSAM */


extern void vm_pressure_response(void);

#define VM_CHECK_MEMORYSTATUS	vm_pressure_response()


#endif /* CONFIG_JETSAM */

/*
 *	Functions implemented as macros. m->wanted and m->busy are
 *	protected by the object lock.
 */

#define SET_PAGE_DIRTY(m, set_pmap_modified)				\
		MACRO_BEGIN						\
		vm_page_t __page__ = (m);				\
		__page__->dirty = TRUE;					\
		MACRO_END

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
		vm_page_free_unlocked(p, TRUE);	\
		MACRO_END

#define VM_PAGE_GRAB_FICTITIOUS(M)					\
		MACRO_BEGIN						\
		while ((M = vm_page_grab_fictitious()) == VM_PAGE_NULL)	\
			vm_page_more_fictitious();			\
		MACRO_END

#define	VM_PAGE_WAIT()		((void)vm_page_wait(THREAD_UNINT))

#define vm_page_queue_lock (vm_page_locks.vm_page_queue_lock2)
#define vm_page_queue_free_lock (vm_page_locks.vm_page_queue_free_lock2)

#define vm_page_lock_queues()	lck_mtx_lock(&vm_page_queue_lock)
#define vm_page_unlock_queues()	lck_mtx_unlock(&vm_page_queue_lock)

#define vm_page_lockspin_queues()	lck_mtx_lock_spin(&vm_page_queue_lock)
#define vm_page_trylockspin_queues()	lck_mtx_try_lock_spin(&vm_page_queue_lock)
#define vm_page_lockconvert_queues()	lck_mtx_convert_spin(&vm_page_queue_lock)

#ifdef	VPL_LOCK_SPIN
#define VPL_LOCK_INIT(vlq, vpl_grp, vpl_attr) lck_spin_init(&vlq->vpl_lock, vpl_grp, vpl_attr)
#define VPL_LOCK(vpl) lck_spin_lock(vpl)
#define VPL_UNLOCK(vpl) lck_spin_unlock(vpl)
#else
#define VPL_LOCK_INIT(vlq, vpl_grp, vpl_attr) lck_mtx_init_ext(&vlq->vpl_lock, &vlq->vpl_lock_ext, vpl_grp, vpl_attr)
#define VPL_LOCK(vpl) lck_mtx_lock_spin(vpl)
#define VPL_UNLOCK(vpl) lck_mtx_unlock(vpl)
#endif

#if MACH_ASSERT
extern void vm_page_queues_assert(vm_page_t mem, int val);
#define VM_PAGE_QUEUES_ASSERT(mem, val)	vm_page_queues_assert((mem), (val))
#else
#define VM_PAGE_QUEUES_ASSERT(mem, val)
#endif


/*
 * 'vm_fault_enter' will place newly created pages (zero-fill and COW) onto the
 * local queues if they exist... its the only spot in the system where we add pages
 * to those queues...  once on those queues, those pages can only move to one of the
 * global page queues or the free queues... they NEVER move from local q to local q.
 * the 'local' state is stable when VM_PAGE_QUEUES_REMOVE is called since we're behind
 * the global vm_page_queue_lock at this point...  we still need to take the local lock
 * in case this operation is being run on a different CPU then the local queue's identity,
 * but we don't have to worry about the page moving to a global queue or becoming wired
 * while we're grabbing the local lock since those operations would require the global
 * vm_page_queue_lock to be held, and we already own it.
 *
 * this is why its safe to utilze the wire_count field in the vm_page_t as the local_id...
 * 'wired' and local are ALWAYS mutually exclusive conditions.
 */

#define VM_PAGE_QUEUES_REMOVE(mem)				\
	MACRO_BEGIN						\
	boolean_t	was_pageable;				\
								\
	VM_PAGE_QUEUES_ASSERT(mem, 1);				\
	assert(!mem->laundry);					\
/*								\
 *	if (mem->pageout_queue)					\
 * 		NOTE: VM_PAGE_QUEUES_REMOVE does not deal with removing pages from the pageout queue...	\
 * 		the caller is responsible for determing if the page is on that queue, and if so, must	\
 * 		either first remove it (it needs both the page queues lock and the object lock to do	\
 * 		this via vm_pageout_steal_laundry), or avoid the call to VM_PAGE_QUEUES_REMOVE		\
 */								\
	if (mem->local) {					\
		struct vpl	*lq;				\
		assert(mem->object != kernel_object);		\
		assert(mem->object != compressor_object);	\
		assert(!mem->inactive && !mem->speculative);	\
		assert(!mem->active && !mem->throttled);	\
		assert(!mem->clean_queue);			\
		assert(!mem->fictitious);			\
		lq = &vm_page_local_q[mem->local_id].vpl_un.vpl;	\
		VPL_LOCK(&lq->vpl_lock);			\
		queue_remove(&lq->vpl_queue,			\
			     mem, vm_page_t, pageq);		\
		mem->local = FALSE;				\
		mem->local_id = 0;				\
		lq->vpl_count--;				\
		if (mem->object->internal) {			\
			lq->vpl_internal_count--;		\
		} else {					\
			lq->vpl_external_count--;		\
		}						\
		VPL_UNLOCK(&lq->vpl_lock);			\
		was_pageable = FALSE;				\
	}							\
								\
	else if (mem->active) {					\
		assert(mem->object != kernel_object);		\
		assert(mem->object != compressor_object);	\
		assert(!mem->inactive && !mem->speculative);	\
		assert(!mem->clean_queue);			\
		assert(!mem->throttled);			\
		assert(!mem->fictitious);			\
		queue_remove(&vm_page_queue_active,		\
			mem, vm_page_t, pageq);			\
		mem->active = FALSE;				\
		vm_page_active_count--;				\
		was_pageable = TRUE;				\
	}							\
								\
	else if (mem->inactive) {				\
		assert(mem->object != kernel_object);		\
		assert(mem->object != compressor_object);	\
		assert(!mem->active && !mem->speculative);	\
		assert(!mem->throttled);			\
		assert(!mem->fictitious);			\
		vm_page_inactive_count--;			\
		if (mem->clean_queue) {				\
			queue_remove(&vm_page_queue_cleaned,	\
                        mem, vm_page_t, pageq);			\
			mem->clean_queue = FALSE;		\
			vm_page_cleaned_count--;		\
		} else {					\
			if (mem->object->internal) {		\
				queue_remove(&vm_page_queue_anonymous,	\
				mem, vm_page_t, pageq);		\
				vm_page_anonymous_count--;	\
			} else {				\
				queue_remove(&vm_page_queue_inactive,	\
				mem, vm_page_t, pageq);		\
			}					\
			vm_purgeable_q_advance_all();		\
		}						\
		mem->inactive = FALSE;				\
		was_pageable = TRUE;				\
	}							\
								\
	else if (mem->throttled) {				\
		assert(mem->object != compressor_object);	\
		assert(!mem->active && !mem->inactive);		\
		assert(!mem->speculative);			\
		assert(!mem->fictitious);			\
		queue_remove(&vm_page_queue_throttled,		\
			     mem, vm_page_t, pageq);		\
		mem->throttled = FALSE;				\
		vm_page_throttled_count--;			\
		was_pageable = FALSE;				\
	}							\
								\
	else if (mem->speculative) {				\
		assert(mem->object != compressor_object);	\
		assert(!mem->active && !mem->inactive);		\
		assert(!mem->throttled);			\
		assert(!mem->fictitious);			\
                remque(&mem->pageq);				\
		mem->speculative = FALSE;			\
		vm_page_speculative_count--;			\
		was_pageable = TRUE;				\
	}							\
								\
	else if (mem->pageq.next || mem->pageq.prev) {		\
		was_pageable = FALSE;				\
		panic("VM_PAGE_QUEUES_REMOVE: unmarked page on Q");	\
	} else {						\
		was_pageable = FALSE;				\
	}							\
								\
	mem->pageq.next = NULL;					\
	mem->pageq.prev = NULL;					\
	VM_PAGE_QUEUES_ASSERT(mem, 0);				\
	if (was_pageable) {					\
		if (mem->object->internal) {			\
			vm_page_pageable_internal_count--;	\
		} else {					\
			vm_page_pageable_external_count--;	\
		}						\
	}							\
	MACRO_END


#define VM_PAGE_ENQUEUE_INACTIVE(mem, first)			\
	MACRO_BEGIN						\
	VM_PAGE_QUEUES_ASSERT(mem, 0);				\
	assert(!mem->fictitious);				\
	assert(!mem->laundry);					\
	assert(!mem->pageout_queue);				\
	if (mem->object->internal) {				\
		if (first == TRUE)				\
			queue_enter_first(&vm_page_queue_anonymous, mem, vm_page_t, pageq);	\
		else						\
			queue_enter(&vm_page_queue_anonymous, mem, vm_page_t, pageq);		\
		vm_page_anonymous_count++;			\
		vm_page_pageable_internal_count++;		\
	} else {						\
		if (first == TRUE)				\
			queue_enter_first(&vm_page_queue_inactive, mem, vm_page_t, pageq); \
		else						\
			queue_enter(&vm_page_queue_inactive, mem, vm_page_t, pageq);	\
		vm_page_pageable_external_count++;			\
	}							\
	mem->inactive = TRUE;					\
	vm_page_inactive_count++;				\
	token_new_pagecount++;					\
	MACRO_END


#if DEVELOPMENT || DEBUG
#define VM_PAGE_SPECULATIVE_USED_ADD()				\
	MACRO_BEGIN						\
	OSAddAtomic(1, &vm_page_speculative_used);	\
	MACRO_END
#else
#define	VM_PAGE_SPECULATIVE_USED_ADD()
#endif


#define VM_PAGE_CONSUME_CLUSTERED(mem)				\
	MACRO_BEGIN						\
	if (mem->clustered) {					\
	        assert(mem->object);				\
	        mem->object->pages_used++;			\
		mem->clustered = FALSE;				\
		VM_PAGE_SPECULATIVE_USED_ADD();			\
	}							\
	MACRO_END


	
#define DW_vm_page_unwire		0x01
#define DW_vm_page_wire			0x02
#define DW_vm_page_free			0x04
#define DW_vm_page_activate		0x08
#define DW_vm_page_deactivate_internal	0x10
#define DW_vm_page_speculate	 	0x20
#define DW_vm_page_lru		 	0x40
#define DW_vm_pageout_throttle_up	0x80
#define DW_PAGE_WAKEUP			0x100
#define DW_clear_busy			0x200
#define DW_clear_reference		0x400
#define DW_set_reference		0x800
#define DW_move_page			0x1000
#define DW_VM_PAGE_QUEUES_REMOVE	0x2000
#define DW_enqueue_cleaned      	0x4000

struct vm_page_delayed_work {
	vm_page_t	dw_m;
	int		dw_mask;
};

void vm_page_do_delayed_work(vm_object_t object, struct vm_page_delayed_work *dwp, int dw_count);

extern unsigned int vm_max_delayed_work_limit;

#define DEFAULT_DELAYED_WORK_LIMIT	32

#define DELAYED_WORK_LIMIT(max)	((vm_max_delayed_work_limit >= max ? max : vm_max_delayed_work_limit))

/*
 * vm_page_do_delayed_work may need to drop the object lock...
 * if it does, we need the pages it's looking at to
 * be held stable via the busy bit, so if busy isn't already
 * set, we need to set it and ask vm_page_do_delayed_work
 * to clear it and wakeup anyone that might have blocked on
 * it once we're done processing the page.
 */

#define VM_PAGE_ADD_DELAYED_WORK(dwp, mem, dw_cnt)		\
	MACRO_BEGIN						\
	if (mem->busy == FALSE) {				\
		mem->busy = TRUE;				\
		if ( !(dwp->dw_mask & DW_vm_page_free))		\
			dwp->dw_mask |= (DW_clear_busy | DW_PAGE_WAKEUP); \
	}							\
	dwp->dw_m = mem;					\
	dwp++;							\
	dw_cnt++;						\
	MACRO_END

extern vm_page_t vm_object_page_grab(vm_object_t);

#if VM_PAGE_BUCKETS_CHECK
extern void vm_page_buckets_check(void);
#endif /* VM_PAGE_BUCKETS_CHECK */

#endif	/* _VM_VM_PAGE_H_ */
