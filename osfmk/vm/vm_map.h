/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
 *	File:	vm/vm_map.h
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Virtual memory map module definitions.
 *
 * Contributors:
 *	avie, dlb, mwyoung
 */

#ifndef	_VM_VM_MAP_H_
#define _VM_VM_MAP_H_

#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <mach/boolean.h>
#include <mach/vm_types.h>
#include <mach/vm_prot.h>
#include <mach/vm_inherit.h>
#include <mach/vm_behavior.h>
#include <vm/pmap.h>

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE

#ifndef MACH_KERNEL_PRIVATE

#ifdef __APPLE_API_OBSOLETE
extern void     kernel_vm_map_reference(vm_map_t map);
#endif /* __APPLE_API_OBSOLETE */

extern void	vm_map_reference(vm_map_t	map);
extern vm_map_t current_map(void);

#else /* MACH_KERNEL_PRIVATE */

#include <cpus.h>
#include <task_swapper.h>
#include <mach_assert.h>

#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <kern/lock.h>
#include <kern/zalloc.h>
#include <kern/macro_help.h>

#include <kern/thread_act.h>

#define current_map_fast()	(current_act_fast()->map)
#define	current_map()		(current_map_fast())

/*
 *	Types defined:
 *
 *	vm_map_t		the high-level address map data structure.
 *	vm_map_entry_t		an entry in an address map.
 *	vm_map_version_t	a timestamp of a map, for use with vm_map_lookup
 *	vm_map_copy_t		represents memory copied from an address map,
 *				 used for inter-map copy operations
 */
typedef struct vm_map_entry	*vm_map_entry_t;


/*
 *	Type:		vm_map_object_t [internal use only]
 *
 *	Description:
 *		The target of an address mapping, either a virtual
 *		memory object or a sub map (of the kernel map).
 */
typedef union vm_map_object {
	struct vm_object	*vm_object;	/* object object */
	struct vm_map		*sub_map;	/* belongs to another map */
} vm_map_object_t;

#define named_entry_lock_init(object)   mutex_init(&(object)->Lock, ETAP_VM_OBJ)
#define named_entry_lock(object)          mutex_lock(&(object)->Lock)
#define named_entry_unlock(object)        mutex_unlock(&(object)->Lock)   

/*
 *	Type:		vm_named_entry_t [internal use only]
 *
 *	Description:
 *		Description of a mapping to a memory cache object.
 *
 *	Implementation:
 *		While the handle to this object is used as a means to map
 * 		and pass around the right to map regions backed by pagers
 *		of all sorts, the named_entry itself is only manipulated
 *		by the kernel.  Named entries hold information on the
 *		right to map a region of a cached object.  Namely,
 *		the target cache object, the beginning and ending of the
 *		region to be mapped, and the permissions, (read, write)
 *		with which it can be mapped.
 *
 */

struct vm_named_entry {
	decl_mutex_data(,	Lock)		/* Synchronization */
	vm_object_t		object;		/* object I point to */
	vm_object_offset_t	offset;		/* offset into object */
	union {
		memory_object_t		pager;	/* amo pager port */
		vm_map_t		map;	/* map backing submap */
	} backing;
	unsigned int		size;		/* size of region */
	unsigned int		protection;	/* access permissions */
	int			ref_count;	/* Number of references */
	unsigned int
	/* boolean_t */		internal:1,	/* is an internal object */
	/* boolean_t */		is_sub_map:1;	/* is object is a submap? */
};

/*
 *	Type:		vm_map_entry_t [internal use only]
 *
 *	Description:
 *		A single mapping within an address map.
 *
 *	Implementation:
 *		Address map entries consist of start and end addresses,
 *		a VM object (or sub map) and offset into that object,
 *		and user-exported inheritance and protection information.
 *		Control information for virtual copy operations is also
 *		stored in the address map entry.
 */
struct vm_map_links {
	struct vm_map_entry	*prev;		/* previous entry */
	struct vm_map_entry	*next;		/* next entry */
	vm_offset_t		start;		/* start address */
	vm_offset_t		end;		/* end address */
};

struct vm_map_entry {
	struct vm_map_links	links;		/* links to other entries */
#define vme_prev		links.prev
#define vme_next		links.next
#define vme_start		links.start
#define vme_end			links.end
	union vm_map_object	object;		/* object I point to */
	vm_object_offset_t	offset;		/* offset into object */
	unsigned int
	/* boolean_t */		is_shared:1,	/* region is shared */
	/* boolean_t */		is_sub_map:1,	/* Is "object" a submap? */
	/* boolean_t */		in_transition:1, /* Entry being changed */
	/* boolean_t */		needs_wakeup:1,  /* Waiters on in_transition */
	/* vm_behavior_t */	behavior:2,	/* user paging behavior hint */
		/* behavior is not defined for submap type */
	/* boolean_t */		needs_copy:1,	/* object need to be copied? */
		/* Only in task maps: */
	/* vm_prot_t */		protection:3,	/* protection code */
	/* vm_prot_t */		max_protection:3,/* maximum protection */
	/* vm_inherit_t */	inheritance:2,	/* inheritance */
	/* nested pmap */	use_pmap:1,	/* nested pmaps */
	/* user alias */        alias:8;
	unsigned short		wired_count;	/* can be paged if = 0 */
	unsigned short		user_wired_count; /* for vm_wire */
};

/*
 * wired_counts are unsigned short.  This value is used to safeguard
 * against any mishaps due to runaway user programs.
 */
#define MAX_WIRE_COUNT		65535



/*
 *	Type:		struct vm_map_header
 *
 *	Description:
 *		Header for a vm_map and a vm_map_copy.
 */
struct vm_map_header {
	struct vm_map_links	links;		/* first, last, min, max */
	int			nentries;	/* Number of entries */
	boolean_t		entries_pageable;
						/* are map entries pageable? */
};

/*
 *	Type:		vm_map_t [exported; contents invisible]
 *
 *	Description:
 *		An address map -- a directory relating valid
 *		regions of a task's address space to the corresponding
 *		virtual memory objects.
 *
 *	Implementation:
 *		Maps are doubly-linked lists of map entries, sorted
 *		by address.  One hint is used to start
 *		searches again from the last successful search,
 *		insertion, or removal.  Another hint is used to
 *		quickly find free space.
 */
struct vm_map {
	lock_t			lock;		/* uni- and smp-lock */
	struct vm_map_header	hdr;		/* Map entry header */
#define min_offset		hdr.links.start	/* start of range */
#define max_offset		hdr.links.end	/* end of range */
	pmap_t			pmap;		/* Physical map */
	vm_size_t		size;		/* virtual size */
	int			ref_count;	/* Reference count */
#if	TASK_SWAPPER
	int			res_count;	/* Residence count (swap) */
	int			sw_state;	/* Swap state */
#endif	/* TASK_SWAPPER */
	decl_mutex_data(,	s_lock)		/* Lock ref, res, hint fields */
	vm_map_entry_t		hint;		/* hint for quick lookups */
	vm_map_entry_t		first_free;	/* First free space hint */
	boolean_t		wait_for_space;	/* Should callers wait
						   for space? */
	boolean_t		wiring_required;/* All memory wired? */
	boolean_t		no_zero_fill;	/* No zero fill absent pages */
	boolean_t		mapped;		/* has this map been mapped */
	unsigned int		timestamp;	/* Version number */
} ;

#define vm_map_to_entry(map)	((struct vm_map_entry *) &(map)->hdr.links)
#define vm_map_first_entry(map)	((map)->hdr.links.next)
#define vm_map_last_entry(map)	((map)->hdr.links.prev)

#if	TASK_SWAPPER
/*
 * VM map swap states.  There are no transition states.
 */
#define MAP_SW_IN	 1	/* map is swapped in; residence count > 0 */
#define MAP_SW_OUT	 2	/* map is out (res_count == 0 */
#endif	/* TASK_SWAPPER */

/*
 *	Type:		vm_map_version_t [exported; contents invisible]
 *
 *	Description:
 *		Map versions may be used to quickly validate a previous
 *		lookup operation.
 *
 *	Usage note:
 *		Because they are bulky objects, map versions are usually
 *		passed by reference.
 *
 *	Implementation:
 *		Just a timestamp for the main map.
 */
typedef struct vm_map_version {
	unsigned int	main_timestamp;
} vm_map_version_t;

/*
 *	Type:		vm_map_copy_t [exported; contents invisible]
 *
 *	Description:
 *		A map copy object represents a region of virtual memory
 *		that has been copied from an address map but is still
 *		in transit.
 *
 *		A map copy object may only be used by a single thread
 *		at a time.
 *
 *	Implementation:
 * 		There are three formats for map copy objects.  
 *		The first is very similar to the main
 *		address map in structure, and as a result, some
 *		of the internal maintenance functions/macros can
 *		be used with either address maps or map copy objects.
 *
 *		The map copy object contains a header links
 *		entry onto which the other entries that represent
 *		the region are chained.
 *
 *		The second format is a single vm object.  This is used
 *		primarily in the pageout path.  The third format is a
 *		list of vm pages.  An optional continuation provides
 *		a hook to be called to obtain more of the memory,
 *		or perform other operations.  The continuation takes 3
 *		arguments, a saved arg buffer, a pointer to a new vm_map_copy
 *		(returned) and an abort flag (abort if TRUE).
 */

#define VM_MAP_COPY_PAGE_LIST_MAX	20
#define	VM_MAP_COPY_PAGE_LIST_MAX_SIZE	(VM_MAP_COPY_PAGE_LIST_MAX * PAGE_SIZE)


/*
 *	Options for vm_map_copyin_page_list.
 */

#define	VM_MAP_COPYIN_OPT_VM_PROT		0x7
#define	VM_MAP_COPYIN_OPT_SRC_DESTROY		0x8
#define	VM_MAP_COPYIN_OPT_STEAL_PAGES		0x10
#define	VM_MAP_COPYIN_OPT_PMAP_ENTER		0x20
#define	VM_MAP_COPYIN_OPT_NO_ZERO_FILL		0x40

/*
 *	Continuation structures for vm_map_copyin_page_list.
 */
typedef	struct {
	vm_map_t	map;
	vm_offset_t	src_addr;
	vm_size_t	src_len;
	vm_offset_t	destroy_addr;
	vm_size_t	destroy_len;
	int		options;
}  vm_map_copyin_args_data_t, *vm_map_copyin_args_t;

#define	VM_MAP_COPYIN_ARGS_NULL	((vm_map_copyin_args_t) 0)


/* vm_map_copy_cont_t is a type definition/prototype
 * for the cont function pointer in vm_map_copy structure.
 */
typedef kern_return_t (*vm_map_copy_cont_t)(
				vm_map_copyin_args_t,
				vm_map_copy_t *);

#define	VM_MAP_COPY_CONT_NULL	((vm_map_copy_cont_t) 0)

struct vm_map_copy {
	int			type;
#define VM_MAP_COPY_ENTRY_LIST		1
#define VM_MAP_COPY_OBJECT		2
#define VM_MAP_COPY_KERNEL_BUFFER	3
	vm_object_offset_t	offset;
	vm_size_t		size;
	union {
	    struct vm_map_header	hdr;	/* ENTRY_LIST */
	    struct {				/* OBJECT */
	    	vm_object_t		object;
		vm_size_t		index;	/* record progress as pages
						 * are moved from object to
						 * page list; must be zero
						 * when first invoking
						 * vm_map_object_to_page_list
						 */
	    } c_o;
	    struct {				/* KERNEL_BUFFER */
		vm_offset_t		kdata;
		vm_size_t		kalloc_size;  /* size of this copy_t */
	    } c_k;
	} c_u;
};


#define cpy_hdr			c_u.hdr

#define cpy_object		c_u.c_o.object
#define	cpy_index		c_u.c_o.index

#define cpy_kdata		c_u.c_k.kdata
#define cpy_kalloc_size		c_u.c_k.kalloc_size


/*
 *	Useful macros for entry list copy objects
 */

#define vm_map_copy_to_entry(copy)		\
		((struct vm_map_entry *) &(copy)->cpy_hdr.links)
#define vm_map_copy_first_entry(copy)		\
		((copy)->cpy_hdr.links.next)
#define vm_map_copy_last_entry(copy)		\
		((copy)->cpy_hdr.links.prev)

/*
 *	Macros:		vm_map_lock, etc. [internal use only]
 *	Description:
 *		Perform locking on the data portion of a map.
 *	When multiple maps are to be locked, order by map address.
 *	(See vm_map.c::vm_remap())
 */

#define vm_map_lock_init(map)						\
	((map)->timestamp = 0 ,						\
	lock_init(&(map)->lock, TRUE, ETAP_VM_MAP, ETAP_VM_MAP_I))

#define vm_map_lock(map)		lock_write(&(map)->lock)
#define vm_map_unlock(map)						\
		((map)->timestamp++ ,	lock_write_done(&(map)->lock))
#define vm_map_lock_read(map)		lock_read(&(map)->lock)
#define vm_map_unlock_read(map)		lock_read_done(&(map)->lock)
#define vm_map_lock_write_to_read(map)					\
		((map)->timestamp++ ,	lock_write_to_read(&(map)->lock))
#define vm_map_lock_read_to_write(map)	lock_read_to_write(&(map)->lock)

extern zone_t		vm_map_copy_zone; /* zone for vm_map_copy structures */

/*
 *	Exported procedures that operate on vm_map_t.
 */

/* Initialize the module */
extern void		vm_map_init(void);

/* Allocate a range in the specified virtual address map and
 * return the entry allocated for that range. */
extern kern_return_t vm_map_find_space(
				vm_map_t	map,
				vm_offset_t	*address,	/* OUT */
				vm_size_t	size,
				vm_offset_t	mask,
				vm_map_entry_t	*o_entry);	/* OUT */

/* Lookup map entry containing or the specified address in the given map */
extern boolean_t	vm_map_lookup_entry(
				vm_map_t	map,
				vm_offset_t	address,
				vm_map_entry_t	*entry);	/* OUT */

/* Find the VM object, offset, and protection for a given virtual address
 * in the specified map, assuming a page fault of the	type specified. */
extern kern_return_t	vm_map_lookup_locked(
				vm_map_t	*var_map,	/* IN/OUT */
				vm_offset_t	vaddr,
				vm_prot_t	fault_type,
				vm_map_version_t *out_version,	/* OUT */
				vm_object_t	*object,	/* OUT */
				vm_object_offset_t *offset,	/* OUT */
				vm_prot_t	*out_prot,	/* OUT */
				boolean_t	*wired,		/* OUT */
				int		*behavior,	/* OUT */
				vm_object_offset_t *lo_offset,	/* OUT */
				vm_object_offset_t *hi_offset,	/* OUT */
				vm_map_t	*pmap_map);	/* OUT */

/* Verifies that the map has not changed since the given version. */
extern boolean_t	vm_map_verify(
				vm_map_t	 map,
				vm_map_version_t *version);	/* REF */

/* Split a vm_map_entry into 2 entries */
extern void		_vm_map_clip_start(
				struct vm_map_header	*map_header,
				vm_map_entry_t		entry,
				vm_offset_t		start);

extern vm_map_entry_t	vm_map_entry_insert(
				vm_map_t		map,
				vm_map_entry_t		insp_entry,
				vm_offset_t		start,
				vm_offset_t		end,
				vm_object_t		object,
				vm_object_offset_t	offset,
				boolean_t		needs_copy,
				boolean_t		is_shared,
				boolean_t		in_transition,
				vm_prot_t		cur_protection,
				vm_prot_t		max_protection,
				vm_behavior_t		behavior,
				vm_inherit_t		inheritance,
				unsigned		wired_count);

extern kern_return_t	vm_remap_extract(
				vm_map_t	map,
				vm_offset_t	addr,
				vm_size_t	size,
				boolean_t	copy,
				struct vm_map_header *map_header,
				vm_prot_t	*cur_protection,
				vm_prot_t	*max_protection,
				vm_inherit_t	inheritance,
				boolean_t	pageable);

extern kern_return_t	vm_remap_range_allocate(
				vm_map_t	map,
				vm_offset_t	*address,
				vm_size_t	size,
				vm_offset_t	mask,
				boolean_t	anywhere,
				vm_map_entry_t	*map_entry);

extern kern_return_t	vm_remap_extract(
				vm_map_t	map,
				vm_offset_t	addr,
				vm_size_t	size,
				boolean_t	copy,
				struct vm_map_header *map_header,
				vm_prot_t	*cur_protection,
				vm_prot_t	*max_protection,
				vm_inherit_t	inheritance,
				boolean_t	pageable);

extern kern_return_t	vm_remap_range_allocate(
				vm_map_t	map,
				vm_offset_t	*address,
				vm_size_t	size,
				vm_offset_t	mask,
				boolean_t	anywhere,
				vm_map_entry_t	*map_entry);

/*
 *	Functions implemented as macros
 */
#define		vm_map_min(map)		((map)->min_offset)
						/* Lowest valid address in
						 * a map */

#define		vm_map_max(map)		((map)->max_offset)
						/* Highest valid address */

#define		vm_map_pmap(map)	((map)->pmap)
						/* Physical map associated
						 * with this address map */

#define		vm_map_verify_done(map, version)    vm_map_unlock_read(map)
						/* Operation that required
						 * a verified lookup is
						 * now complete */

/*
 * Macros/functions for map residence counts and swapin/out of vm maps
 */
#if	TASK_SWAPPER

#if	MACH_ASSERT
/* Gain a reference to an existing map */
extern void		vm_map_reference(
				vm_map_t	map);
/* Lose a residence count */
extern void		vm_map_res_deallocate(
				vm_map_t	map);
/* Gain a residence count on a map */
extern void		vm_map_res_reference(
				vm_map_t	map);
/* Gain reference & residence counts to possibly swapped-out map */
extern void		vm_map_reference_swap(
				vm_map_t	map);

#else	/* MACH_ASSERT */

#define vm_map_reference(map)			\
MACRO_BEGIN					\
	vm_map_t Map = (map);			\
	if (Map) {				\
		mutex_lock(&Map->s_lock);	\
		Map->res_count++;		\
		Map->ref_count++;		\
		mutex_unlock(&Map->s_lock);	\
	}					\
MACRO_END

#define vm_map_res_reference(map)		\
MACRO_BEGIN					\
	vm_map_t Lmap = (map);			\
	if (Lmap->res_count == 0) {		\
		mutex_unlock(&Lmap->s_lock);	\
		vm_map_lock(Lmap);		\
		vm_map_swapin(Lmap);		\
		mutex_lock(&Lmap->s_lock);	\
		++Lmap->res_count;		\
		vm_map_unlock(Lmap);		\
	} else					\
		++Lmap->res_count;		\
MACRO_END

#define vm_map_res_deallocate(map)		\
MACRO_BEGIN					\
	vm_map_t Map = (map);			\
	if (--Map->res_count == 0) {		\
		mutex_unlock(&Map->s_lock);	\
		vm_map_lock(Map);		\
		vm_map_swapout(Map);		\
		vm_map_unlock(Map);		\
		mutex_lock(&Map->s_lock);	\
	}					\
MACRO_END

#define vm_map_reference_swap(map)	\
MACRO_BEGIN				\
	vm_map_t Map = (map);		\
	mutex_lock(&Map->s_lock);	\
	++Map->ref_count;		\
	vm_map_res_reference(Map);	\
	mutex_unlock(&Map->s_lock);	\
MACRO_END
#endif 	/* MACH_ASSERT */

extern void		vm_map_swapin(
				vm_map_t	map);

extern void		vm_map_swapout(
				vm_map_t	map);

#else	/* TASK_SWAPPER */

#define vm_map_reference(map)			\
MACRO_BEGIN					\
	vm_map_t Map = (map);			\
	if (Map) {				\
		mutex_lock(&Map->s_lock);	\
		Map->ref_count++;		\
		mutex_unlock(&Map->s_lock);	\
	}					\
MACRO_END

#define vm_map_reference_swap(map)	vm_map_reference(map)
#define vm_map_res_reference(map)
#define vm_map_res_deallocate(map)

#endif	/* TASK_SWAPPER */

/*
 *	Submap object.  Must be used to create memory to be put
 *	in a submap by vm_map_submap.
 */
extern vm_object_t	vm_submap_object;

/*
 *	Wait and wakeup macros for in_transition map entries.
 */
#define vm_map_entry_wait(map, interruptible)    	\
	((map)->timestamp++ ,				\
	 thread_sleep_lock_write((event_t)&(map)->hdr,  \
			 &(map)->lock, interruptible))


#define vm_map_entry_wakeup(map)        thread_wakeup((event_t)(&(map)->hdr))


#define	vm_map_ref_fast(map)				\
	MACRO_BEGIN					\
	mutex_lock(&map->s_lock);			\
	map->ref_count++;				\
	vm_map_res_reference(map);			\
	mutex_unlock(&map->s_lock);			\
	MACRO_END

#define	vm_map_dealloc_fast(map)			\
	MACRO_BEGIN					\
	register int c;					\
							\
	mutex_lock(&map->s_lock);			\
	c = --map->ref_count;				\
	if (c > 0)					\
		vm_map_res_deallocate(map);		\
	mutex_unlock(&map->s_lock);			\
	if (c == 0)					\
		vm_map_destroy(map);			\
	MACRO_END


/* simplify map entries */
extern void		vm_map_simplify(
				vm_map_t	map,
				vm_offset_t	start);

/* Steal all the pages from a vm_map_copy page_list */
extern void		vm_map_copy_steal_pages(
				vm_map_copy_t	copy);

/* Discard a copy without using it */
extern void		vm_map_copy_discard(
				vm_map_copy_t	copy);

/* Move the information in a map copy object to a new map copy object */
extern vm_map_copy_t	vm_map_copy_copy(
				vm_map_copy_t	copy);

/* Overwrite existing memory with a copy */
extern kern_return_t	vm_map_copy_overwrite(
				vm_map_t	dst_map,
				vm_offset_t	dst_addr,
				vm_map_copy_t	copy,
				int		interruptible);

/* Create a copy object from an object. */
extern kern_return_t	vm_map_copyin_object(
				vm_object_t		object,
				vm_object_offset_t	offset,
				vm_object_size_t	size,
				vm_map_copy_t		*copy_result); /* OUT */

extern vm_map_t		vm_map_switch(
				vm_map_t	map);

extern int		vm_map_copy_cont_is_valid(
				vm_map_copy_t	copy);


#define VM_MAP_ENTRY_NULL	((vm_map_entry_t) 0)


/* Enter a mapping */
extern kern_return_t	vm_map_enter(
				vm_map_t		map,
				vm_offset_t		*address,
				vm_size_t		size,
				vm_offset_t		mask,
				int			flags,
				vm_object_t		object,
				vm_object_offset_t	offset,
				boolean_t		needs_copy,
				vm_prot_t		cur_protection,
				vm_prot_t		max_protection,
				vm_inherit_t		inheritance);

extern	kern_return_t	vm_map_write_user(
				vm_map_t	map,
				vm_offset_t	src_addr,
				vm_offset_t	dst_addr,
				vm_size_t	size);

extern	kern_return_t	vm_map_read_user(
				vm_map_t	map,
				vm_offset_t	src_addr,
				vm_offset_t	dst_addr,
				vm_size_t	size);

/* Create a new task map using an existing task map as a template. */
extern vm_map_t		vm_map_fork(
				vm_map_t	old_map);

/* Change inheritance */
extern kern_return_t	vm_map_inherit(
				vm_map_t	map,
				vm_offset_t	start,
				vm_offset_t	end,
				vm_inherit_t	new_inheritance);

/* Add or remove machine-dependent attributes from map regions */
extern kern_return_t	vm_map_machine_attribute(
				vm_map_t	map,
				vm_offset_t	address,
				vm_size_t	size,
				vm_machine_attribute_t	attribute,
				vm_machine_attribute_val_t* value); /* IN/OUT */
/* Set paging behavior */
extern kern_return_t	vm_map_behavior_set(
				vm_map_t	map,
				vm_offset_t	start,
				vm_offset_t	end,
				vm_behavior_t	new_behavior);

extern kern_return_t	vm_map_submap(
				vm_map_t	map,
				vm_offset_t	start,
				vm_offset_t	end,
				vm_map_t	submap,
				vm_offset_t	offset,
				boolean_t	use_pmap);


#endif /* MACH_KERNEL_PRIVATE */

/* Create an empty map */
extern vm_map_t		vm_map_create(
				pmap_t		pmap,
				vm_offset_t	min,
				vm_offset_t	max,
				boolean_t	pageable);

/* Get rid of a map */
extern void		vm_map_destroy(
				vm_map_t	map);
/* Lose a reference */
extern void		vm_map_deallocate(
				vm_map_t	map);

/* Change protection */
extern kern_return_t	vm_map_protect(
				vm_map_t	map,
				vm_offset_t	start,
				vm_offset_t	end,
				vm_prot_t	new_prot,
				boolean_t	set_max);

/* wire down a region */
extern kern_return_t	vm_map_wire(
				vm_map_t	map,
				vm_offset_t	start,
				vm_offset_t	end,
				vm_prot_t	access_type,
				boolean_t	user_wire);

/* unwire a region */
extern kern_return_t	vm_map_unwire(
				vm_map_t	map,
				vm_offset_t	start,
				vm_offset_t	end,
				boolean_t	user_wire);

/* Deallocate a region */
extern kern_return_t	vm_map_remove(
				vm_map_t	map,
				vm_offset_t	start,
				vm_offset_t	end,
				boolean_t	flags);

/* Place a copy into a map */
extern kern_return_t	vm_map_copyout(
				vm_map_t	dst_map,
				vm_offset_t	*dst_addr,	/* OUT */
				vm_map_copy_t	copy);

extern kern_return_t	vm_map_copyin_common(
				vm_map_t	src_map,
				vm_offset_t	src_addr,
				vm_size_t	len,
				boolean_t	src_destroy,
				boolean_t	src_volatile,
				vm_map_copy_t	*copy_result,	/* OUT */
				boolean_t	use_maxprot);

extern kern_return_t vm_region_clone(
				ipc_port_t	src_region,
				ipc_port_t	dst_region);

extern kern_return_t vm_map_region_replace(
				vm_map_t	target_map,
				ipc_port_t	old_region,
				ipc_port_t	new_region,
				vm_offset_t	start,  
				vm_offset_t	end);

extern boolean_t vm_map_check_protection(
				vm_map_t	map,
				vm_offset_t	start,
				vm_offset_t	end,
				vm_prot_t	protection);

/*
 *	Macros to invoke vm_map_copyin_common.  vm_map_copyin is the
 *	usual form; it handles a copyin based on the current protection
 *	(current protection == VM_PROT_NONE) is a failure.
 *	vm_map_copyin_maxprot handles a copyin based on maximum possible
 *	access.  The difference is that a region with no current access
 *	BUT possible maximum access is rejected by vm_map_copyin(), but
 *	returned by vm_map_copyin_maxprot.
 */
#define	vm_map_copyin(src_map, src_addr, len, src_destroy, copy_result) \
		vm_map_copyin_common(src_map, src_addr, len, src_destroy, \
					FALSE, copy_result, FALSE)

#define vm_map_copyin_maxprot(src_map, \
			      src_addr, len, src_destroy, copy_result) \
		vm_map_copyin_common(src_map, src_addr, len, src_destroy, \
					FALSE, copy_result, TRUE)

/*
 * Flags for vm_map_remove() and vm_map_delete()
 */
#define	VM_MAP_NO_FLAGS	  		0x0
#define	VM_MAP_REMOVE_KUNWIRE	  	0x1
#define	VM_MAP_REMOVE_INTERRUPTIBLE  	0x2
#define	VM_MAP_REMOVE_WAIT_FOR_KWIRE  	0x4

/*
 * Backing store throttle when BS is exhausted
 */
extern unsigned int    vm_backing_store_low;

extern void vm_backing_store_disable(
			boolean_t	suspend);


#endif  /* __APPLE_API_PRIVATE */
 
#endif	/* _VM_VM_MAP_H_ */

