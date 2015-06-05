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
 *	File:	vm/vm_pageout.h
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1986
 *
 *	Declarations for the pageout daemon interface.
 */

#ifndef	_VM_VM_PAGEOUT_H_
#define _VM_VM_PAGEOUT_H_

#ifdef	KERNEL_PRIVATE

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/machine/vm_types.h>
#include <mach/memory_object_types.h>

#include <kern/kern_types.h>
#include <kern/locks.h>

#include <libkern/OSAtomic.h>


#include <vm/vm_options.h>

#ifdef	MACH_KERNEL_PRIVATE
#include <vm/vm_page.h>
#endif

#include <sys/kdebug.h>

#define VM_PAGE_AVAILABLE_COUNT()		((unsigned int)(vm_page_cleaned_count))

/* externally manipulated counters */
extern unsigned int vm_pageout_cleaned_reactivated, vm_pageout_cleaned_fault_reactivated, vm_pageout_cleaned_commit_reactivated;

#if CONFIG_FREEZE
extern boolean_t memorystatus_freeze_enabled;
#define VM_DYNAMIC_PAGING_ENABLED(port) (COMPRESSED_PAGER_IS_ACTIVE || (memorystatus_freeze_enabled == FALSE && IP_VALID(port)))
#else
#define VM_DYNAMIC_PAGING_ENABLED(port) (COMPRESSED_PAGER_IS_ACTIVE || IP_VALID(port))
#endif

#if VM_PRESSURE_EVENTS
extern boolean_t vm_pressure_events_enabled;
#endif /* VM_PRESSURE_EVENTS */

extern int	vm_debug_events;

#define VMF_CHECK_ZFDELAY		0x100
#define VMF_COWDELAY			0x101
#define VMF_ZFDELAY			0x102
#define VMF_COMPRESSORDELAY		0x103

#define VM_PAGEOUT_SCAN			0x104
#define VM_PAGEOUT_BALANCE		0x105
#define VM_PAGEOUT_FREELIST		0x106
#define VM_PAGEOUT_PURGEONE		0x107
#define VM_PAGEOUT_CACHE_EVICT		0x108
#define VM_PAGEOUT_THREAD_BLOCK		0x109
#define VM_PAGEOUT_JETSAM		0x10A

#define VM_UPL_PAGE_WAIT		0x120
#define VM_IOPL_PAGE_WAIT		0x121
#define VM_PAGE_WAIT_BLOCK		0x122

#if CONFIG_IOSCHED
#define VM_PAGE_SLEEP			0x123
#define VM_PAGE_EXPEDITE		0x124
#endif

#define VM_PRESSURE_EVENT		0x130
#define VM_EXECVE			0x131
#define VM_WAKEUP_COMPACTOR_SWAPPER	0x132

#define VM_DEBUG_EVENT(name, event, control, arg1, arg2, arg3, arg4)	\
	MACRO_BEGIN						\
	if (vm_debug_events) {					\
		KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, event)) | control, arg1, arg2, arg3, arg4, 0); \
	}							\
	MACRO_END

extern void memoryshot(unsigned int event, unsigned int control);

extern kern_return_t vm_map_create_upl(
	vm_map_t		map,
	vm_map_address_t	offset,
	upl_size_t		*upl_size,
	upl_t			*upl,
	upl_page_info_array_t	page_list,
	unsigned int		*count,
	int			*flags);

extern ppnum_t upl_get_highest_page(
	upl_t			upl);

extern upl_size_t upl_get_size(
	upl_t			upl);

extern void iopl_valid_data(
	upl_t			upl_ptr);

#ifndef	MACH_KERNEL_PRIVATE
typedef struct vm_page	*vm_page_t;
#endif

extern void                vm_page_free_list(
                            vm_page_t	mem,
                            boolean_t	prepare_object);

extern kern_return_t      vm_page_alloc_list(
                            int         page_count,
                            int			flags,
                            vm_page_t * list);

extern void               vm_page_set_offset(vm_page_t page, vm_object_offset_t offset);
extern vm_object_offset_t vm_page_get_offset(vm_page_t page);
extern ppnum_t            vm_page_get_phys_page(vm_page_t page);
extern vm_page_t          vm_page_get_next(vm_page_t page);

extern kern_return_t	mach_vm_pressure_level_monitor(boolean_t wait_for_pressure, unsigned int *pressure_level);

#ifdef	MACH_KERNEL_PRIVATE

#include <vm/vm_page.h>

extern unsigned int	vm_pageout_scan_event_counter;
extern unsigned int	vm_page_anonymous_count;


/*
 * must hold the page queues lock to
 * manipulate this structure
 */
struct vm_pageout_queue {
        queue_head_t	pgo_pending;	/* laundry pages to be processed by pager's iothread */
        unsigned int	pgo_laundry;	/* current count of laundry pages on queue or in flight */
        unsigned int	pgo_maxlaundry;
	uint64_t	pgo_tid;	/* thread ID of I/O thread that services this queue */
	uint8_t		pgo_lowpriority; /* iothread is set to use low priority I/O */

        unsigned int	pgo_idle:1,	/* iothread is blocked waiting for work to do */
	                pgo_busy:1,     /* iothread is currently processing request from pgo_pending */
			pgo_throttled:1,/* vm_pageout_scan thread needs a wakeup when pgo_laundry drops */
		        pgo_draining:1,
			pgo_inited:1,
			:0;
};

#define VM_PAGE_Q_THROTTLED(q)		\
        ((q)->pgo_laundry >= (q)->pgo_maxlaundry)

extern struct	vm_pageout_queue	vm_pageout_queue_internal;
extern struct	vm_pageout_queue	vm_pageout_queue_external;


/*
 *	Routines exported to Mach.
 */
extern void		vm_pageout(void);

extern kern_return_t	vm_pageout_internal_start(void);

extern void		vm_pageout_object_terminate(
					vm_object_t	object);

extern void		vm_pageout_cluster(
	                                vm_page_t	m,
					boolean_t	pageout);

extern void		vm_pageout_initialize_page(
					vm_page_t	m);

extern void		vm_pageclean_setup(
					vm_page_t		m,
					vm_page_t		new_m,
					vm_object_t		new_object,
					vm_object_offset_t	new_offset);

/* UPL exported routines and structures */

#define upl_lock_init(object)	lck_mtx_init(&(object)->Lock, &vm_object_lck_grp, &vm_object_lck_attr)
#define upl_lock_destroy(object)	lck_mtx_destroy(&(object)->Lock, &vm_object_lck_grp)
#define upl_lock(object)	lck_mtx_lock(&(object)->Lock)
#define upl_unlock(object)	lck_mtx_unlock(&(object)->Lock)
#define upl_try_lock(object) 	lck_mtx_try_lock(&(object)->Lock)

#define MAX_VECTOR_UPL_ELEMENTS	8

struct _vector_upl_iostates{
	upl_offset_t offset;
	upl_size_t   size;
};

typedef struct _vector_upl_iostates vector_upl_iostates_t;

struct _vector_upl {
	upl_size_t		size;
	uint32_t		num_upls;
	uint32_t		invalid_upls;
	uint32_t		_reserved;
	vm_map_t		submap;
	vm_offset_t		submap_dst_addr;
	vm_object_offset_t	offset;
	upl_t			upl_elems[MAX_VECTOR_UPL_ELEMENTS];	
	upl_page_info_array_t	pagelist;	
	vector_upl_iostates_t	upl_iostates[MAX_VECTOR_UPL_ELEMENTS]; 
};

typedef struct _vector_upl* vector_upl_t;

/* universal page list structure */

#if UPL_DEBUG
#define	UPL_DEBUG_STACK_FRAMES	16
#define UPL_DEBUG_COMMIT_RECORDS 4

struct ucd {
	upl_offset_t	c_beg;
	upl_offset_t	c_end;
	int		c_aborted;
	void *		c_retaddr[UPL_DEBUG_STACK_FRAMES];
};
#endif


struct upl {
	decl_lck_mtx_data(,	Lock)	/* Synchronization */
	int		ref_count;
	int		ext_ref_count;
	int		flags;
	vm_object_t	src_object; /* object derived from */
	vm_object_offset_t offset;
	upl_size_t	size;	    /* size in bytes of the address space */
	vm_offset_t	kaddr;      /* secondary mapping in kernel */
	vm_object_t	map_object;
	ppnum_t		highest_page;
	void*		vector_upl;
#if CONFIG_IOSCHED
	int 		upl_priority;
	uint64_t        *upl_reprio_info;
	void 		*decmp_io_upl;
#endif
#if CONFIG_IOSCHED || UPL_DEBUG
	thread_t        upl_creator;
	queue_chain_t	uplq;	    /* List of outstanding upls on an obj */
#endif
#if	UPL_DEBUG
	uintptr_t	ubc_alias1;
	uintptr_t 	ubc_alias2;
		
	uint32_t	upl_state;
	uint32_t	upl_commit_index;
	void	*upl_create_retaddr[UPL_DEBUG_STACK_FRAMES];

	struct  ucd	upl_commit_records[UPL_DEBUG_COMMIT_RECORDS];
#endif	/* UPL_DEBUG */
};

/* upl struct flags */
#define UPL_PAGE_LIST_MAPPED	0x1
#define UPL_KERNEL_MAPPED 	0x2
#define	UPL_CLEAR_DIRTY		0x4
#define UPL_COMPOSITE_LIST	0x8
#define UPL_INTERNAL		0x10
#define UPL_PAGE_SYNC_DONE	0x20
#define UPL_DEVICE_MEMORY	0x40
#define UPL_PAGEOUT		0x80
#define UPL_LITE		0x100
#define UPL_IO_WIRE		0x200
#define UPL_ACCESS_BLOCKED	0x400
#define UPL_ENCRYPTED		0x800
#define UPL_SHADOWED		0x1000
#define UPL_KERNEL_OBJECT	0x2000
#define UPL_VECTOR		0x4000
#define UPL_SET_DIRTY		0x8000
#define UPL_HAS_BUSY		0x10000
#define UPL_TRACKED_BY_OBJECT	0x20000
#define UPL_EXPEDITE_SUPPORTED 	0x40000
#define UPL_DECMP_REQ 		0x80000
#define UPL_DECMP_REAL_IO 	0x100000

/* flags for upl_create flags parameter */
#define UPL_CREATE_EXTERNAL	0
#define UPL_CREATE_INTERNAL	0x1
#define UPL_CREATE_LITE		0x2
#define UPL_CREATE_IO_TRACKING	0x4
#define UPL_CREATE_EXPEDITE_SUP 0x8

extern upl_t vector_upl_create(vm_offset_t);
extern void vector_upl_deallocate(upl_t);
extern boolean_t vector_upl_is_valid(upl_t);
extern boolean_t vector_upl_set_subupl(upl_t, upl_t, u_int32_t);
extern void vector_upl_set_pagelist(upl_t);
extern void vector_upl_set_submap(upl_t, vm_map_t, vm_offset_t);
extern void vector_upl_get_submap(upl_t, vm_map_t*, vm_offset_t*);
extern void vector_upl_set_iostate(upl_t, upl_t, upl_offset_t, upl_size_t);
extern void vector_upl_get_iostate(upl_t, upl_t, upl_offset_t*, upl_size_t*);
extern void vector_upl_get_iostate_byindex(upl_t, uint32_t, upl_offset_t*, upl_size_t*);
extern upl_t vector_upl_subupl_byindex(upl_t , uint32_t);
extern upl_t vector_upl_subupl_byoffset(upl_t , upl_offset_t*, upl_size_t*);

extern void vm_object_set_pmap_cache_attr(
		vm_object_t		object,
		upl_page_info_array_t	user_page_list,
		unsigned int		num_pages,
		boolean_t		batch_pmap_op);

extern kern_return_t vm_object_iopl_request(
	vm_object_t		object,
	vm_object_offset_t	offset,
	upl_size_t		size,
	upl_t			*upl_ptr,
	upl_page_info_array_t	user_page_list,
	unsigned int		*page_list_count,
	int			cntrl_flags);

extern kern_return_t vm_object_super_upl_request(
	vm_object_t		object,
	vm_object_offset_t	offset,
	upl_size_t		size,
	upl_size_t		super_cluster,
	upl_t			*upl,
	upl_page_info_t		*user_page_list,
	unsigned int		*page_list_count,
	int			cntrl_flags);

/* should be just a regular vm_map_enter() */
extern kern_return_t vm_map_enter_upl(
	vm_map_t		map, 
	upl_t			upl, 
	vm_map_offset_t		*dst_addr);

/* should be just a regular vm_map_remove() */
extern kern_return_t vm_map_remove_upl(
	vm_map_t		map, 
	upl_t			upl);

/* wired  page list structure */
typedef uint32_t *wpl_array_t;

extern void vm_page_free_reserve(int pages);

extern void vm_pageout_throttle_down(vm_page_t page);
extern void vm_pageout_throttle_up(vm_page_t page);

/*
 * ENCRYPTED SWAP:
 */
extern void upl_encrypt(
	upl_t			upl,
	upl_offset_t		crypt_offset,
	upl_size_t		crypt_size);
extern void vm_page_encrypt(
	vm_page_t		page,
	vm_map_offset_t		kernel_map_offset);
extern boolean_t vm_pages_encrypted; /* are there encrypted pages ? */
extern void vm_page_decrypt(
	vm_page_t		page,
	vm_map_offset_t		kernel_map_offset);
extern kern_return_t vm_paging_map_object(
	vm_page_t		page,
	vm_object_t		object,
	vm_object_offset_t	offset,
	vm_prot_t		protection,
	boolean_t		can_unlock_object,
	vm_map_size_t		*size,		/* IN/OUT */
	vm_map_offset_t		*address,	/* OUT */
	boolean_t		*need_unmap);	/* OUT */
extern void vm_paging_unmap_object(
	vm_object_t		object,
	vm_map_offset_t		start,
	vm_map_offset_t		end);
decl_simple_lock_data(extern, vm_paging_lock)

/*
 * Backing store throttle when BS is exhausted
 */
extern unsigned int    vm_backing_store_low;

extern void vm_pageout_steal_laundry(
	vm_page_t page, 
	boolean_t queues_locked);
	
extern boolean_t vm_page_is_slideable(vm_page_t m);

extern kern_return_t vm_page_slide(vm_page_t page, vm_map_offset_t kernel_mapping_offset);
#endif  /* MACH_KERNEL_PRIVATE */

#if UPL_DEBUG
extern kern_return_t  upl_ubc_alias_set(
	upl_t upl,
	uintptr_t alias1,
	uintptr_t alias2);
extern int  upl_ubc_alias_get(
	upl_t upl,
	uintptr_t * al,
	uintptr_t * al2);
#endif /* UPL_DEBUG */

extern void vm_countdirtypages(void);

extern void vm_backing_store_disable(
			boolean_t	suspend);

extern kern_return_t upl_transpose(
	upl_t	upl1,
	upl_t	upl2);

extern kern_return_t mach_vm_pressure_monitor(
	boolean_t	wait_for_pressure,
	unsigned int	nsecs_monitored,
	unsigned int	*pages_reclaimed_p,
	unsigned int	*pages_wanted_p);

extern kern_return_t
vm_set_buffer_cleanup_callout(
	boolean_t	(*func)(int));

struct vm_page_stats_reusable {
	SInt32		reusable_count;
	uint64_t	reusable;
	uint64_t	reused;
	uint64_t	reused_wire;
	uint64_t	reused_remove;
	uint64_t	all_reusable_calls;
	uint64_t	partial_reusable_calls;
	uint64_t	all_reuse_calls;
	uint64_t	partial_reuse_calls;
	uint64_t	reusable_pages_success;
	uint64_t	reusable_pages_failure;
	uint64_t	reusable_pages_shared;
	uint64_t	reuse_pages_success;
	uint64_t	reuse_pages_failure;
	uint64_t	can_reuse_success;
	uint64_t	can_reuse_failure;
	uint64_t	reusable_reclaimed;
};
extern struct vm_page_stats_reusable vm_page_stats_reusable;
	
extern int hibernate_flush_memory(void);
extern void hibernate_reset_stats(void);
extern void hibernate_create_paddr_map(void);

extern int vm_compressor_mode;
extern int vm_compressor_thread_count;

#define VM_PAGER_DEFAULT				0x1	/* Use default pager. */
#define VM_PAGER_COMPRESSOR_NO_SWAP			0x2	/* In-core compressor only. */
#define VM_PAGER_COMPRESSOR_WITH_SWAP			0x4	/* In-core compressor + swap backend. */
#define VM_PAGER_FREEZER_DEFAULT			0x8	/* Freezer backed by default pager.*/
#define VM_PAGER_FREEZER_COMPRESSOR_NO_SWAP		0x10	/* Freezer backed by in-core compressor only i.e. frozen data remain in-core compressed.*/
#define VM_PAGER_FREEZER_COMPRESSOR_WITH_SWAP		0x20	/* Freezer backed by in-core compressor with swap support too.*/

#define VM_PAGER_MAX_MODES				6	/* Total number of vm compressor modes supported */

#define DEFAULT_PAGER_IS_ACTIVE		((vm_compressor_mode & VM_PAGER_DEFAULT) == VM_PAGER_DEFAULT)

#define COMPRESSED_PAGER_IS_ACTIVE	(vm_compressor_mode & (VM_PAGER_COMPRESSOR_NO_SWAP | VM_PAGER_COMPRESSOR_WITH_SWAP))

#define DEFAULT_FREEZER_IS_ACTIVE	((vm_compressor_mode & VM_PAGER_FREEZER_DEFAULT) == VM_PAGER_FREEZER_DEFAULT)

#define DEFAULT_FREEZER_COMPRESSED_PAGER_IS_ACTIVE		(vm_compressor_mode & (VM_PAGER_FREEZER_COMPRESSOR_NO_SWAP | VM_PAGER_FREEZER_COMPRESSOR_WITH_SWAP))
#define DEFAULT_FREEZER_COMPRESSED_PAGER_IS_SWAPLESS		((vm_compressor_mode & VM_PAGER_FREEZER_COMPRESSOR_NO_SWAP) == VM_PAGER_FREEZER_COMPRESSOR_NO_SWAP)
#define DEFAULT_FREEZER_COMPRESSED_PAGER_IS_SWAPBACKED		((vm_compressor_mode & VM_PAGER_FREEZER_COMPRESSOR_WITH_SWAP) == VM_PAGER_FREEZER_COMPRESSOR_WITH_SWAP)


#endif	/* KERNEL_PRIVATE */

#endif	/* _VM_VM_PAGEOUT_H_ */
