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
 *	File:	memory_object.h
 *	Author:	Michael Wayne Young
 *
 *	External memory management interface definition.
 */

#ifndef	_MACH_MEMORY_OBJECT_TYPES_H_
#define _MACH_MEMORY_OBJECT_TYPES_H_

/*
 *	User-visible types used in the external memory
 *	management interface:
 */

#include <mach/port.h>
#include <mach/vm_types.h>
#include <mach/machine/vm_types.h>

#define VM_64_BIT_DATA_OBJECTS
#define	SHARED_LIBRARY_SERVER_SUPPORTED
#define GLOBAL_SHARED_TEXT_SEGMENT 0x70000000
#define GLOBAL_SHARED_DATA_SEGMENT 0x80000000
#define GLOBAL_SHARED_SEGMENT_MASK 0xF0000000

typedef mach_port_t	memory_object_default_t;

typedef	mach_port_t	memory_object_t;
					/* A memory object ... */
					/*  Used by the kernel to retrieve */
					/*  or store data */

typedef	mach_port_t	memory_object_control_t;
					/* Provided to a memory manager; ... */
					/*  used to control a memory object */

typedef	mach_port_t	memory_object_name_t;
					/* Used to describe the memory ... */
					/*  object in vm_regions() calls */

typedef mach_port_t     memory_object_rep_t;
					/* Per-client handle for mem object */
					/*  Used by user programs to specify */
					/*  the object to map */

typedef	int		memory_object_copy_strategy_t;
					/* How memory manager handles copy: */
#define		MEMORY_OBJECT_COPY_NONE		0
					/* ... No special support */
#define		MEMORY_OBJECT_COPY_CALL		1
					/* ... Make call on memory manager */
#define		MEMORY_OBJECT_COPY_DELAY 	2
					/* ... Memory manager doesn't
					 *     change data externally.
					 */
#define		MEMORY_OBJECT_COPY_TEMPORARY 	3
					/* ... Memory manager doesn't
					 *     change data externally, and
					 *     doesn't need to see changes.
					 */
#define		MEMORY_OBJECT_COPY_SYMMETRIC 	4
					/* ... Memory manager doesn't
					 *     change data externally,
					 *     doesn't need to see changes,
					 *     and object will not be
					 *     multiply mapped.
					 *
					 *     XXX
					 *     Not yet safe for non-kernel use.
					 */

#define		MEMORY_OBJECT_COPY_INVALID	5
					/* ...	An invalid copy strategy,
					 *	for external objects which
					 *	have not been initialized.
					 *	Allows copy_strategy to be
					 *	examined without also
					 *	examining pager_ready and
					 *	internal.
					 */

typedef	int		memory_object_return_t;
					/* Which pages to return to manager
					   this time (lock_request) */
#define		MEMORY_OBJECT_RETURN_NONE	0
					/* ... don't return any. */
#define		MEMORY_OBJECT_RETURN_DIRTY	1
					/* ... only dirty pages. */
#define		MEMORY_OBJECT_RETURN_ALL	2
					/* ... dirty and precious pages. */
#define		MEMORY_OBJECT_RETURN_ANYTHING	3
					/* ... any resident page. */

#define		MEMORY_OBJECT_NULL	MACH_PORT_NULL

/* 
 *	Data lock request flags
 */

#define		MEMORY_OBJECT_DATA_FLUSH 	0x1
#define		MEMORY_OBJECT_DATA_NO_CHANGE	0x2
#define		MEMORY_OBJECT_DATA_PURGE	0x4
#define		MEMORY_OBJECT_COPY_SYNC		0x8
#define		MEMORY_OBJECT_DATA_SYNC		0x10

/*
 *	Types for the memory object flavor interfaces
 */

#define MEMORY_OBJECT_INFO_MAX      (1024) 
typedef int     *memory_object_info_t;      
typedef int	 memory_object_flavor_t;
typedef int      memory_object_info_data_t[MEMORY_OBJECT_INFO_MAX];


#define OLD_MEMORY_OBJECT_BEHAVIOR_INFO 	10	
#define MEMORY_OBJECT_PERFORMANCE_INFO	11
#define OLD_MEMORY_OBJECT_ATTRIBUTE_INFO	12
#define MEMORY_OBJECT_ATTRIBUTE_INFO	14
#define MEMORY_OBJECT_BEHAVIOR_INFO 	15	


struct old_memory_object_behave_info {
	memory_object_copy_strategy_t	copy_strategy;	
	boolean_t			temporary;
	boolean_t			invalidate;
};

struct memory_object_perf_info {
	vm_size_t			cluster_size;
	boolean_t			may_cache;
};

struct old_memory_object_attr_info {			/* old attr list */
        boolean_t       		object_ready;
        boolean_t       		may_cache;
        memory_object_copy_strategy_t 	copy_strategy;
};

struct memory_object_attr_info {
	memory_object_copy_strategy_t	copy_strategy;
	vm_offset_t			cluster_size;
	boolean_t			may_cache_object;
	boolean_t			temporary;
};

struct memory_object_behave_info {
	memory_object_copy_strategy_t	copy_strategy;	
	boolean_t			temporary;
	boolean_t			invalidate;
	boolean_t			silent_overwrite;
	boolean_t			advisory_pageout;
};

typedef struct old_memory_object_behave_info *old_memory_object_behave_info_t;
typedef struct old_memory_object_behave_info old_memory_object_behave_info_data_t;

typedef struct memory_object_behave_info *memory_object_behave_info_t;
typedef struct memory_object_behave_info memory_object_behave_info_data_t;

typedef struct memory_object_perf_info 	*memory_object_perf_info_t;
typedef struct memory_object_perf_info	memory_object_perf_info_data_t;

typedef struct old_memory_object_attr_info *old_memory_object_attr_info_t;
typedef struct old_memory_object_attr_info old_memory_object_attr_info_data_t;

typedef struct memory_object_attr_info	*memory_object_attr_info_t;
typedef struct memory_object_attr_info	memory_object_attr_info_data_t;

#define OLD_MEMORY_OBJECT_BEHAVE_INFO_COUNT   	\
                (sizeof(old_memory_object_behave_info_data_t)/sizeof(int))
#define MEMORY_OBJECT_BEHAVE_INFO_COUNT   	\
                (sizeof(memory_object_behave_info_data_t)/sizeof(int))
#define MEMORY_OBJECT_PERF_INFO_COUNT		\
		(sizeof(memory_object_perf_info_data_t)/sizeof(int))
#define OLD_MEMORY_OBJECT_ATTR_INFO_COUNT		\
		(sizeof(old_memory_object_attr_info_data_t)/sizeof(int))
#define MEMORY_OBJECT_ATTR_INFO_COUNT		\
		(sizeof(memory_object_attr_info_data_t)/sizeof(int))

#define invalid_memory_object_flavor(f)					\
	(f != MEMORY_OBJECT_ATTRIBUTE_INFO && 				\
	 f != MEMORY_OBJECT_PERFORMANCE_INFO && 			\
	 f != OLD_MEMORY_OBJECT_BEHAVIOR_INFO &&			\
	 f != MEMORY_OBJECT_BEHAVIOR_INFO &&				\
	 f != OLD_MEMORY_OBJECT_ATTRIBUTE_INFO)



/*
 *  Even before we have components, we do not want to export upl internal
 *  structure to non mach components.
 */
#ifndef	MACH_KERNEL_PRIVATE
#ifdef KERNEL_PRIVATE
typedef struct {
	unsigned int opaque;
	} * upl_t;
#else
typedef mach_port_t		upl_t; 
#endif /* KERNEL_PRIVATE */
#endif

#define MAX_UPL_TRANSFER 64

struct upl_page_info {
	vm_offset_t	phys_addr;
        unsigned int
                        pageout:1,      /* page is to be removed on commit */
                        absent:1,       /* No valid data in this page */
                        dirty:1,        /* Page must be cleaned (O) */
			precious:1,     /* must be cleaned, we have only copy */
			device:1,	/* no page data, mapped dev memory */
                        :0;		/* force to long boundary */
};

typedef struct upl_page_info	upl_page_info_t;

typedef unsigned long long	memory_object_offset_t;
typedef unsigned long long	memory_object_size_t;
typedef upl_page_info_t		*upl_page_list_ptr_t;
typedef mach_port_t		upl_object_t;



/* upl invocation flags */

#define UPL_COPYOUT_FROM	0x1
#define UPL_PRECIOUS		0x2
#define UPL_NO_SYNC		0x4
#define UPL_CLEAN_IN_PLACE	0x8
#define UPL_NOBLOCK		0x10
#define UPL_RET_ONLY_DIRTY	0x20
#define UPL_SET_INTERNAL	0x40

/* upl abort error flags */
#define UPL_ABORT_RESTART	0x1
#define UPL_ABORT_UNAVAILABLE	0x2
#define UPL_ABORT_ERROR		0x4
#define UPL_ABORT_FREE_ON_EMPTY	0x8
#define UPL_ABORT_DUMP_PAGES	0x10

/* upl pages check flags */
#define UPL_CHECK_DIRTY         0x1

/* upl pagein/pageout  flags */
#define UPL_IOSYNC	0x1
#define UPL_NOCOMMIT	0x2
#define UPL_NORDAHEAD   0x4

/* upl commit flags */
#define UPL_COMMIT_FREE_ON_EMPTY	0x1
#define UPL_COMMIT_CLEAR_DIRTY		0x2
#define UPL_COMMIT_SET_DIRTY		0x4
#define UPL_COMMIT_INACTIVATE		0x8

/* flags for return of state from vm_map_get_upl,  vm_upl address space */
/* based call */
#define UPL_DEV_MEMORY			0x1
#define UPL_PHYS_CONTIG			0x2


/* access macros for upl_t */

#define UPL_DEVICE_PAGE(upl) \
	(((upl)[(index)].phys_addr != 0) ? (!((upl)[0].device)) : FALSE)

#define UPL_PAGE_PRESENT(upl, index)  \
	((upl)[(index)].phys_addr != 0)

#define UPL_PHYS_PAGE(upl, index) \
	(((upl)[(index)].phys_addr != 0) ?  \
			((upl)[(index)].phys_addr) : (vm_offset_t)NULL)

#define UPL_DIRTY_PAGE(upl, index) \
	(((upl)[(index)].phys_addr != 0) ? ((upl)[(index)].dirty) : FALSE)

#define UPL_PRECIOUS_PAGE(upl, index) \
	(((upl)[(index)].phys_addr != 0) ? ((upl)[(index)].precious) : FALSE)

#define UPL_VALID_PAGE(upl, index) \
	(((upl)[(index)].phys_addr != 0) ? (!((upl)[(index)].absent)) : FALSE)

#define UPL_SET_PAGE_FREE_ON_COMMIT(upl, index) \
	if ((upl)[(index)].phys_addr != 0)     \
		((upl)[(index)].pageout) =  TRUE

#define UPL_CLR_PAGE_FREE_ON_COMMIT(upl, index) \
	if ((upl)[(index)].phys_addr != 0)     \
		((upl)[(index)].pageout) =  FALSE


#ifdef KERNEL_PRIVATE
/*
 * iokit code doesn't include prerequisite header files, thus the
 * !defined(IOKIT).  But osfmk code defines IOKIT!  Thus the
 * defined(MACH_KERNEL).  To clean this gorp up "just" fix all
 * iokit & driver code to include the prereqs.
 */
#if !defined(IOKIT) || defined(MACH_KERNEL)
#include <mach/error.h>

/* The call prototyped below is used strictly by UPL_GET_INTERNAL_PAGE_LIST */

extern vm_size_t	upl_offset_to_pagelist;
extern vm_size_t upl_get_internal_pagelist_offset();

/* UPL_GET_INTERNAL_PAGE_LIST is only valid on internal objects where the */
/* list request was made with the UPL_INTERNAL flag */

#define UPL_GET_INTERNAL_PAGE_LIST(upl) \
	((upl_page_info_t *)((upl_offset_to_pagelist == 0) ?  \
	(unsigned int)upl + (unsigned int)(upl_offset_to_pagelist = upl_get_internal_pagelist_offset()): \
	(unsigned int)upl + (unsigned int)upl_offset_to_pagelist))

extern kern_return_t	vm_fault_list_request(
					vm_object_t		object,
					vm_object_offset_t	offset,
					vm_size_t		size,
					upl_t			*upl,
					upl_page_info_t	      **user_page_list,
					int			page_list_count,
					int			cntrol_flags);

extern kern_return_t	upl_system_list_request(
					vm_object_t		object,
					vm_object_offset_t	offset,
					vm_size_t		size,
					vm_size_t		super_size,
					upl_t			*upl,
					upl_page_info_t	      **user_page_list,
					int			page_list_count,
					int			cntrol_flags);

extern kern_return_t	upl_map(
					vm_map_t	map,
					upl_t		upl,
					vm_offset_t	*dst_addr);

extern kern_return_t	upl_un_map(
					vm_map_t	map,
					upl_t		upl);

extern kern_return_t	upl_commit_range(
					upl_t		upl,
					vm_offset_t	offset,
					vm_size_t	size,
					boolean_t	free_on_empty,
					upl_page_info_t	*page_list);

extern kern_return_t	upl_commit(
					upl_t		upl,
					upl_page_info_t	*page_list);

extern upl_t		upl_create(
					boolean_t	internal);

extern void 		upl_destroy(
					upl_t		page_list);

extern kern_return_t	upl_abort(
					upl_t		page_list,
					int		error);

extern kern_return_t	upl_abort_range(
					upl_t		page_list,
					vm_offset_t	offset,
					vm_size_t	size,
					int		error);

extern void upl_set_dirty(
       					 upl_t   upl);

extern void upl_clear_dirty(
       					 upl_t   upl);



extern kern_return_t memory_object_page_op(
					vm_object_t		object,
					vm_object_offset_t	offset,
					int			ops,
					vm_offset_t		*phys_entry,
					int			*flags);

extern kern_return_t memory_object_release_name(
					vm_object_t	object,
					int		flags);

extern kern_return_t vm_map_get_upl(
					vm_map_t	map,
					vm_offset_t	offset,
					vm_size_t	*upl_size,
					upl_t		*upl,
					upl_page_info_t	**page_list,
					int		*count,
					int		*flags,
					int             force_data_sync);

extern kern_return_t vm_region_clone(
					ipc_port_t	src_region,
					ipc_port_t	dst_region);

extern kern_return_t vm_map_region_replace(
					vm_map_t	target_map,
					ipc_port_t	old_region,
					ipc_port_t	new_region,
					vm_offset_t	start,  
					vm_offset_t	end);




#ifndef MACH_KERNEL_PRIVATE

/* address space shared region descriptor */

typedef void *shared_region_mapping_t;
typedef void *vm_named_entry_t;

extern kern_return_t memory_object_destroy_named(
					vm_object_t	object,
					kern_return_t	reason);

extern kern_return_t memory_object_lock_request_named(
					vm_object_t		object,
					vm_object_offset_t	offset,
					memory_object_size_t	size,
					memory_object_return_t	should_return,
					int			flags,
					int			prot,
					ipc_port_t		reply_to);

extern kern_return_t memory_object_change_attributes_named(
        				vm_object_t             object,
        				memory_object_flavor_t  flavor,
					memory_object_info_t	attributes,
					int			count,
        				int              	reply_to,
        				int    			reply_to_type);

extern kern_return_t memory_object_create_named(
					ipc_port_t	port,
					vm_size_t	size,
					vm_object_t	*object_ptr);

/*
extern kern_return_t vm_get_shared_region(
					task_t	task,
					shared_region_mapping_t	*shared_region);

extern kern_return_t vm_set_shared_region(
					task_t	task,
					shared_region_mapping_t	shared_region);
*/

extern kern_return_t shared_region_mapping_info(
				shared_region_mapping_t	shared_region,
				ipc_port_t		*text_region,
				vm_size_t		*text_size,
				ipc_port_t		*data_region,
				vm_size_t		*data_size,
				vm_offset_t		*region_mappings,
				vm_offset_t		*client_base,
				vm_offset_t		*alternate_base,
				vm_offset_t		*alternate_next,
				int			*flags,
				shared_region_mapping_t	*next);

extern kern_return_t shared_region_mapping_create(
				ipc_port_t		text_region,
				vm_size_t		text_size,
				ipc_port_t		data_region,
				vm_size_t		data_size,
				vm_offset_t		region_mappings,
				vm_offset_t		client_base,
				shared_region_mapping_t	*shared_region);

extern kern_return_t shared_region_mapping_ref(
				shared_region_mapping_t	shared_region);

extern kern_return_t shared_region_mapping_dealloc(
				shared_region_mapping_t	shared_region);

extern kern_return_t
shared_region_object_chain_attach(
				shared_region_mapping_t	target_region,
				shared_region_mapping_t	object_chain);


#endif MACH_KERNEL_PRIVATE


/* 
 * Flags for the UPL page ops routine.  This routine is not exported
 * out of the kernel at the moment and so the defs live here.
 */


#define UPL_POP_DIRTY		0x1
#define UPL_POP_PAGEOUT		0x2
#define UPL_POP_PRECIOUS	0x4
#define UPL_POP_ABSENT		0x8
#define UPL_POP_BUSY		0x10

#define UPL_POP_DUMP            0x20000000
#define UPL_POP_SET		0x40000000
#define UPL_POP_CLR		0x80000000

/*
 * Used to support options on memory_object_release_name call
 */

#define MEMORY_OBJECT_TERMINATE_IDLE	0x1
#define MEMORY_OBJECT_RESPECT_CACHE	0x2
#define MEMORY_OBJECT_RELEASE_NO_OP	0x4


#endif /* !defined(IOKIT) || defined(MACH_KERNEL) */
#endif /* KERNEL_PRIVATE */



#endif	/* _MACH_MEMORY_OBJECT_TYPES_H_ */
