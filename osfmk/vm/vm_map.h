/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
#include <mach/vm_param.h>
#include <vm/pmap.h>

#ifdef	KERNEL_PRIVATE

#include <sys/cdefs.h>

__BEGIN_DECLS

extern void	vm_map_reference(vm_map_t	map);
extern vm_map_t current_map(void);

__END_DECLS

#ifdef	MACH_KERNEL_PRIVATE

#include <task_swapper.h>
#include <mach_assert.h>

#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <kern/lock.h>
#include <kern/zalloc.h>
#include <kern/macro_help.h>

#include <kern/thread.h>

#define current_map_fast()	(current_thread()->map)
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
#define VM_MAP_ENTRY_NULL	((vm_map_entry_t) 0)


/*
 *	Type:		vm_map_object_t [internal use only]
 *
 *	Description:
 *		The target of an address mapping, either a virtual
 *		memory object or a sub map (of the kernel map).
 */
typedef union vm_map_object {
	vm_object_t		vm_object;	/* object object */
	vm_map_t		sub_map;	/* belongs to another map */
} vm_map_object_t;

#define named_entry_lock_init(object)   mutex_init(&(object)->Lock, 0)
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
	union {
		vm_object_t	object;		/* object I point to */
		memory_object_t	pager;		/* amo pager port */
		vm_map_t	map;		/* map backing submap */
	} backing;
	vm_object_offset_t	offset;		/* offset into object */
	vm_object_size_t	size;		/* size of region */
	vm_prot_t		protection;	/* access permissions */
	int			ref_count;	/* Number of references */
	unsigned int				/* Is backing.xxx : */
	/* boolean_t */		internal:1,	/* ... an internal object */
	/* boolean_t */		is_sub_map:1,	/* ... a submap? */
	/* boolean_t */		is_pager:1;	/* ... a pager port */
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
	vm_map_offset_t		start;		/* start address */
	vm_map_offset_t		end;		/* end address */
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
	/* boolean_t */		use_pmap:1,	/* nested pmaps */
	/* unsigned char */	alias:8,	/* user alias */
	/* unsigned char */	pad:8;		/* available bits */
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
	vm_map_size_t		size;		/* virtual size */
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
 *		The second format is a single vm object.  This was used
 *		primarily in the pageout path - but is not currently used
 *		except for placeholder copy objects (see vm_map_copy_copy()).
 *
 *		The third format is a kernel buffer copy object - for data
 * 		small enough that physical copies were the most efficient
 *		method.
 */

struct vm_map_copy {
	int			type;
#define VM_MAP_COPY_ENTRY_LIST		1
#define VM_MAP_COPY_OBJECT		2
#define VM_MAP_COPY_KERNEL_BUFFER	3
	vm_object_offset_t	offset;
	vm_map_size_t		size;
	union {
	    struct vm_map_header	hdr;	/* ENTRY_LIST */
	    vm_object_t			object; /* OBJECT */
	    struct {				
		void			*kdata;	      /* KERNEL_BUFFER */
		vm_size_t		kalloc_size;  /* size of this copy_t */
	    } c_k;
	} c_u;
};


#define cpy_hdr			c_u.hdr

#define cpy_object		c_u.object

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
	lock_init(&(map)->lock, TRUE, 0, 0))

#define vm_map_lock(map)		lock_write(&(map)->lock)
#define vm_map_unlock(map)						\
		((map)->timestamp++ ,	lock_write_done(&(map)->lock))
#define vm_map_lock_read(map)		lock_read(&(map)->lock)
#define vm_map_unlock_read(map)		lock_read_done(&(map)->lock)
#define vm_map_lock_write_to_read(map)					\
		((map)->timestamp++ ,	lock_write_to_read(&(map)->lock))
#define vm_map_lock_read_to_write(map)	lock_read_to_write(&(map)->lock)

/*
 *	Exported procedures that operate on vm_map_t.
 */

/* Initialize the module */
extern void		vm_map_init(void);

/* Allocate a range in the specified virtual address map and
 * return the entry allocated for that range. */
extern kern_return_t vm_map_find_space(
				vm_map_t		map,
				vm_map_address_t	*address,	/* OUT */
				vm_map_size_t		size,
				vm_map_offset_t		mask,
				vm_map_entry_t		*o_entry);	/* OUT */

/* Lookup map entry containing or the specified address in the given map */
extern boolean_t	vm_map_lookup_entry(
				vm_map_t		map,
				vm_map_address_t	address,
				vm_map_entry_t		*entry);	/* OUT */

/* Find the VM object, offset, and protection for a given virtual address
 * in the specified map, assuming a page fault of the	type specified. */
extern kern_return_t	vm_map_lookup_locked(
				vm_map_t		*var_map,	/* IN/OUT */
				vm_map_address_t	vaddr,
				vm_prot_t		fault_type,
				vm_map_version_t 	*out_version,	/* OUT */
				vm_object_t		*object,	/* OUT */
				vm_object_offset_t 	*offset,	/* OUT */
				vm_prot_t		*out_prot,	/* OUT */
				boolean_t		*wired,		/* OUT */
				int			*behavior,	/* OUT */
				vm_map_offset_t		*lo_offset,	/* OUT */
				vm_map_offset_t		*hi_offset,	/* OUT */
				vm_map_t		*real_map);	/* OUT */

/* Verifies that the map has not changed since the given version. */
extern boolean_t	vm_map_verify(
				vm_map_t	 	map,
				vm_map_version_t 	*version);	/* REF */

extern vm_map_entry_t	vm_map_entry_insert(
				vm_map_t		map,
				vm_map_entry_t		insp_entry,
				vm_map_offset_t		start,
				vm_map_offset_t		end,
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


/*
 *	Functions implemented as macros
 */
#define		vm_map_min(map)	((map)->min_offset)
						/* Lowest valid address in
						 * a map */

#define		vm_map_max(map)	((map)->max_offset)
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

#define vm_map_reference(map)		\
MACRO_BEGIN					\
	vm_map_t Map = (map);		\
	if (Map) {				\
		mutex_lock(&Map->s_lock);	\
		Map->res_count++;		\
		Map->ref_count++;		\
		mutex_unlock(&Map->s_lock);	\
	}					\
MACRO_END

#define vm_map_res_reference(map)		\
MACRO_BEGIN					\
	vm_map_t Lmap = (map);		\
	if (Lmap->res_count == 0) {		\
		mutex_unlock(&Lmap->s_lock);\
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
	vm_map_t Map = (map);		\
	if (--Map->res_count == 0) {	\
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


#define vm_map_entry_wakeup(map)        \
	thread_wakeup((event_t)(&(map)->hdr))


#define	vm_map_ref_fast(map)			\
	MACRO_BEGIN					\
	mutex_lock(&map->s_lock);			\
	map->ref_count++;				\
	vm_map_res_reference(map);			\
	mutex_unlock(&map->s_lock);			\
	MACRO_END

#define	vm_map_dealloc_fast(map)		\
	MACRO_BEGIN					\
	register int c;				\
							\
	mutex_lock(&map->s_lock);			\
	c = --map->ref_count;			\
	if (c > 0)					\
		vm_map_res_deallocate(map);		\
	mutex_unlock(&map->s_lock);			\
	if (c == 0)					\
		vm_map_destroy(map);			\
	MACRO_END


/* simplify map entries */
extern void		vm_map_simplify_entry(
	vm_map_t	map,
	vm_map_entry_t	this_entry);
extern void		vm_map_simplify(
				vm_map_t		map,
				vm_map_offset_t		start);

/* Move the information in a map copy object to a new map copy object */
extern vm_map_copy_t	vm_map_copy_copy(
				vm_map_copy_t           copy);

/* Create a copy object from an object. */
extern kern_return_t	vm_map_copyin_object(
				vm_object_t		object,
				vm_object_offset_t	offset,
				vm_object_size_t	size,
				vm_map_copy_t		*copy_result); /* OUT */

/* Enter a mapping */
extern kern_return_t	vm_map_enter(
				vm_map_t		map,
				vm_map_offset_t		*address,
				vm_map_size_t		size,
				vm_map_offset_t		mask,
				int			flags,
				vm_object_t		object,
				vm_object_offset_t	offset,
				boolean_t		needs_copy,
				vm_prot_t		cur_protection,
				vm_prot_t		max_protection,
				vm_inherit_t		inheritance);

/* XXX should go away - replaced with regular enter of contig object */
extern  kern_return_t	vm_map_enter_cpm(
				vm_map_t		map,
				vm_map_address_t	*addr,
				vm_map_size_t		size,
				int			flags);

extern kern_return_t vm_map_remap(
				vm_map_t		target_map,
				vm_map_offset_t		*address,
				vm_map_size_t		size,
				vm_map_offset_t		mask,
				boolean_t		anywhere,
				vm_map_t		src_map,
				vm_map_offset_t		memory_address,
				boolean_t		copy,
				vm_prot_t		*cur_protection,
				vm_prot_t		*max_protection,
				vm_inherit_t		inheritance);


/*
 * Read and write from a kernel buffer to a specified map.
 */
extern	kern_return_t	vm_map_write_user(
				vm_map_t		map,
				void			*src_p,
				vm_map_offset_t		dst_addr,
				vm_size_t		size);

extern	kern_return_t	vm_map_read_user(
				vm_map_t		map,
				vm_map_offset_t		src_addr,
				void			*dst_p,
				vm_size_t		size);

/* Create a new task map using an existing task map as a template. */
extern vm_map_t		vm_map_fork(
				vm_map_t		old_map);

/* Change inheritance */
extern kern_return_t	vm_map_inherit(
				vm_map_t		map,
				vm_map_offset_t		start,
				vm_map_offset_t		end,
				vm_inherit_t		new_inheritance);

/* Add or remove machine-dependent attributes from map regions */
extern kern_return_t	vm_map_machine_attribute(
				vm_map_t		map,
				vm_map_offset_t		start,
				vm_map_offset_t		end,
				vm_machine_attribute_t	attribute,
				vm_machine_attribute_val_t* value); /* IN/OUT */

extern kern_return_t	vm_map_msync(
				vm_map_t		map,
				vm_map_address_t	address,
				vm_map_size_t		size,
				vm_sync_t		sync_flags);

/* Set paging behavior */
extern kern_return_t	vm_map_behavior_set(
				vm_map_t		map,
				vm_map_offset_t		start,
				vm_map_offset_t		end,
				vm_behavior_t		new_behavior);

extern kern_return_t vm_map_purgable_control(
				vm_map_t		map,
				vm_map_offset_t		address,
				vm_purgable_t		control,
				int			*state);

extern kern_return_t vm_map_region(
				vm_map_t		 map,
				vm_map_offset_t		*address,
				vm_map_size_t		*size,
				vm_region_flavor_t	 flavor,
				vm_region_info_t	 info,
				mach_msg_type_number_t	*count,
				mach_port_t		*object_name);

extern kern_return_t vm_map_region_recurse_64(
				vm_map_t		 map,
				vm_map_offset_t		*address,
				vm_map_size_t		*size,
				natural_t	 	*nesting_depth,
				vm_region_submap_info_64_t info,
				mach_msg_type_number_t  *count);

extern kern_return_t vm_map_page_info(
				vm_map_t		map,
				vm_map_offset_t		offset,
				int			*disposition,
				int			*ref_count);

extern kern_return_t	vm_map_submap(
				vm_map_t		map,
				vm_map_offset_t		start,
				vm_map_offset_t		end,
				vm_map_t		submap,
				vm_map_offset_t		offset,
				boolean_t		use_pmap);

extern void vm_map_submap_pmap_clean(
	vm_map_t	map,
	vm_map_offset_t	start,
	vm_map_offset_t	end,
	vm_map_t	sub_map,
	vm_map_offset_t	offset);

/* Convert from a map entry port to a map */
extern vm_map_t convert_port_entry_to_map(
	ipc_port_t	port);

/* Convert from a port to a vm_object */
extern vm_object_t convert_port_entry_to_object(
	ipc_port_t	port);


#endif /* MACH_KERNEL_PRIVATE */

__BEGIN_DECLS

/* Create an empty map */
extern vm_map_t		vm_map_create(
				pmap_t			pmap,
				vm_map_offset_t 	min_off,
				vm_map_offset_t 	max_off,
				boolean_t		pageable);

/* Get rid of a map */
extern void		vm_map_destroy(
				vm_map_t		map);
/* Lose a reference */
extern void		vm_map_deallocate(
				vm_map_t		map);

extern vm_map_t		vm_map_switch(
				vm_map_t		map);

/* Change protection */
extern kern_return_t	vm_map_protect(
				vm_map_t		map,
				vm_map_offset_t		start,
				vm_map_offset_t		end,
				vm_prot_t		new_prot,
				boolean_t		set_max);

/* Check protection */
extern boolean_t vm_map_check_protection(
				vm_map_t		map,
				vm_map_offset_t		start,
				vm_map_offset_t		end,
				vm_prot_t		protection);

/* wire down a region */
extern kern_return_t	vm_map_wire(
				vm_map_t		map,
				vm_map_offset_t		start,
				vm_map_offset_t		end,
				vm_prot_t		access_type,
				boolean_t		user_wire);

/* unwire a region */
extern kern_return_t	vm_map_unwire(
				vm_map_t		map,
				vm_map_offset_t		start,
				vm_map_offset_t		end,
				boolean_t		user_wire);

/* Deallocate a region */
extern kern_return_t	vm_map_remove(
				vm_map_t		map,
				vm_map_offset_t		start,
				vm_map_offset_t		end,
				boolean_t		flags);

/* Discard a copy without using it */
extern void		vm_map_copy_discard(
				vm_map_copy_t		copy);

/* Overwrite existing memory with a copy */
extern kern_return_t	vm_map_copy_overwrite(
				vm_map_t                dst_map,
				vm_map_address_t        dst_addr,
				vm_map_copy_t           copy,
				int                     interruptible);

/* Place a copy into a map */
extern kern_return_t	vm_map_copyout(
				vm_map_t		dst_map,
				vm_map_address_t	*dst_addr,	/* OUT */
				vm_map_copy_t		copy);

extern kern_return_t	vm_map_copyin_common(
				vm_map_t		src_map,
				vm_map_address_t	src_addr,
				vm_map_size_t		len,
				boolean_t		src_destroy,
				boolean_t		src_volatile,
				vm_map_copy_t		*copy_result,	/* OUT */
				boolean_t		use_maxprot);

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
 * Macros for rounding and truncation of vm_map offsets and sizes
 */
#define vm_map_round_page(x) (((vm_map_offset_t)(x) + PAGE_MASK) & ~((signed)PAGE_MASK))
#define vm_map_trunc_page(x) ((vm_map_offset_t)(x) & ~((signed)PAGE_MASK))	

/*
 * Flags for vm_map_remove() and vm_map_delete()
 */
#define	VM_MAP_NO_FLAGS	  		0x0
#define	VM_MAP_REMOVE_KUNWIRE	  	0x1
#define	VM_MAP_REMOVE_INTERRUPTIBLE  	0x2
#define	VM_MAP_REMOVE_WAIT_FOR_KWIRE  	0x4
#define VM_MAP_REMOVE_SAVE_ENTRIES	0x8

/* Support for shared regions */
extern kern_return_t vm_region_clone(
				ipc_port_t		src_region,
				ipc_port_t		dst_region);

extern kern_return_t vm_map_region_replace(
				vm_map_t		target_map,
				ipc_port_t		old_region,
				ipc_port_t		new_region,
				vm_map_offset_t		start,  
				vm_map_offset_t		end);

/* Support for UPLs from vm_maps */

extern kern_return_t vm_map_get_upl(
				vm_map_t		target_map,
				vm_address_t		address,
				vm_size_t		*size,
				upl_t			*upl,
				upl_page_info_array_t	page_info,
				mach_msg_type_number_t	*page_infoCnt,
				integer_t		*flags,
				integer_t		force_data_sync);

__END_DECLS

#endif	/* KERNEL_PRIVATE */
 
#endif	/* _VM_VM_MAP_H_ */
