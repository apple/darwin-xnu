/*
 * Copyright (c) 2009 Apple Inc. All rights reserved.
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

#include <vm/vm_map_store_ll.h>

boolean_t
first_free_is_valid_ll( vm_map_t map )
{
	vm_map_entry_t	entry, next;
	entry = vm_map_to_entry(map);
	next = entry->vme_next;
	while (vm_map_trunc_page(next->vme_start,
				 VM_MAP_PAGE_MASK(map)) ==
	       vm_map_trunc_page(entry->vme_end,
				 VM_MAP_PAGE_MASK(map)) ||
	       (vm_map_trunc_page(next->vme_start,
				  VM_MAP_PAGE_MASK(map)) ==
		vm_map_trunc_page(entry->vme_start,
				  VM_MAP_PAGE_MASK(map)) &&
		next != vm_map_to_entry(map))) {
		entry = next;
		next = entry->vme_next;
		if (entry == vm_map_to_entry(map))
			break;
	}
	if (map->first_free != entry) {
		printf("Bad first_free for map %p: %p should be %p\n",
		       map, map->first_free, entry);
		return FALSE;
	}
	return TRUE;
}

/*
 *	UPDATE_FIRST_FREE:
 *
 *	Updates the map->first_free pointer to the
 *	entry immediately before the first hole in the map.
 * 	The map should be locked.
 */
#define UPDATE_FIRST_FREE_LL(map, new_first_free)			\
	MACRO_BEGIN							\
	if( map->disable_vmentry_reuse == FALSE){			\
		vm_map_t	UFF_map;				\
		vm_map_entry_t	UFF_first_free;				\
		vm_map_entry_t	UFF_next_entry;				\
		UFF_map = (map);					\
		UFF_first_free = (new_first_free);			\
		UFF_next_entry = UFF_first_free->vme_next;		\
		while (vm_map_trunc_page(UFF_next_entry->vme_start,	\
					 VM_MAP_PAGE_MASK(UFF_map)) ==	\
		       vm_map_trunc_page(UFF_first_free->vme_end,	\
					 VM_MAP_PAGE_MASK(UFF_map)) ||	\
		       (vm_map_trunc_page(UFF_next_entry->vme_start,	\
					  VM_MAP_PAGE_MASK(UFF_map)) ==	\
			vm_map_trunc_page(UFF_first_free->vme_start,	\
					  VM_MAP_PAGE_MASK(UFF_map)) &&	\
			UFF_next_entry != vm_map_to_entry(UFF_map))) {	\
			UFF_first_free = UFF_next_entry;		\
			UFF_next_entry = UFF_first_free->vme_next;	\
			if (UFF_first_free == vm_map_to_entry(UFF_map))	\
				break;					\
		}							\
		UFF_map->first_free = UFF_first_free;			\
		assert(first_free_is_valid(UFF_map));			\
	}								\
	MACRO_END

#define _vm_map_entry_link_ll(hdr, after_where, entry)			\
	MACRO_BEGIN							\
	if (entry->map_aligned) {					\
		assert(VM_MAP_PAGE_ALIGNED((entry->vme_start),		\
					   VM_MAP_HDR_PAGE_MASK((hdr))));\
		assert(VM_MAP_PAGE_ALIGNED((entry->vme_end),		\
					   VM_MAP_HDR_PAGE_MASK((hdr))));\
	}								\
	(hdr)->nentries++;						\
	(entry)->vme_prev = (after_where);				\
	(entry)->vme_next = (after_where)->vme_next;			\
	(entry)->vme_prev->vme_next = (entry)->vme_next->vme_prev = (entry); \
	MACRO_END

#define _vm_map_entry_unlink_ll(hdr, entry)				\
	MACRO_BEGIN							\
	(hdr)->nentries--;						\
	(entry)->vme_next->vme_prev = (entry)->vme_prev; 		\
	(entry)->vme_prev->vme_next = (entry)->vme_next; 		\
	MACRO_END
/*
 *	Macro:		vm_map_copy_insert
 *	
 *	Description:
 *		Link a copy chain ("copy") into a map at the
 *		specified location (after "where").
 *	Side effects:
 *		The copy chain is destroyed.
 *	Warning:
 *		The arguments are evaluated multiple times.
 */
#define	_vm_map_copy_insert_ll(map, where, copy)				\
MACRO_BEGIN								\
	vm_map_t VMCI_map;						\
	vm_map_entry_t VMCI_where;					\
	vm_map_copy_t VMCI_copy;					\
	VMCI_map = (map);						\
	VMCI_where = (where);						\
	VMCI_copy = (copy);						\
	((VMCI_where->vme_next)->vme_prev = vm_map_copy_last_entry(VMCI_copy))\
		->vme_next = (VMCI_where->vme_next);			\
	((VMCI_where)->vme_next = vm_map_copy_first_entry(VMCI_copy))	\
		->vme_prev = VMCI_where;				\
	VMCI_map->hdr.nentries += VMCI_copy->cpy_hdr.nentries;		\
	update_first_free_ll(VMCI_map, VMCI_map->first_free);		\
MACRO_END



void
vm_map_store_init_ll( __unused struct vm_map_header *hdr)
{
	return;
}

/*
 *	vm_map_lookup_entry_ll:	[ internal use only ]
 *	Use the linked list to find the map entry containing (or
 *	immediately preceding) the specified address
 *	in the given map; the entry is returned
 *	in the "entry" parameter.  The boolean
 *	result indicates whether the address is
 *	actually contained in the map.
 */
boolean_t
vm_map_store_lookup_entry_ll(
	register vm_map_t		map,
	register vm_map_offset_t	address,
	vm_map_entry_t		*entry)		/* OUT */
{
	register vm_map_entry_t		cur;
	register vm_map_entry_t		last;

	/*
	 *	Start looking either from the head of the
	 *	list, or from the hint.
	 */
	cur = map->hint;

	if (cur == vm_map_to_entry(map))
		cur = cur->vme_next;

	if (address >= cur->vme_start) {
		/*
		 *	Go from hint to end of list.
		 *
		 *	But first, make a quick check to see if
		 *	we are already looking at the entry we
		 *	want (which is usually the case).
		 *	Note also that we don't need to save the hint
		 *	here... it is the same hint (unless we are
		 *	at the header, in which case the hint didn't
		 *	buy us anything anyway).
		 */
		last = vm_map_to_entry(map);
		if ((cur != last) && (cur->vme_end > address)) {
			*entry = cur;
			return(TRUE);
		}
	}
	else {
		/*
		 *	Go from start to hint, *inclusively*
		 */
		last = cur->vme_next;
		cur = vm_map_first_entry(map);
	}

	/*
	 *	Search linearly
	 */

	while (cur != last) {
		if (cur->vme_end > address) {
			if (address >= cur->vme_start) {
				/*
				 *	Save this lookup for future
				 *	hints, and return
				 */

				*entry = cur;
				SAVE_HINT_MAP_READ(map, cur);

				return(TRUE);
			}
			break;
		}
		cur = cur->vme_next;
	}
	*entry = cur->vme_prev;
	SAVE_HINT_MAP_READ(map, *entry);

	return(FALSE);
}

void
vm_map_store_entry_link_ll( struct vm_map_header *mapHdr, vm_map_entry_t after_where, vm_map_entry_t entry)
{
	_vm_map_entry_link_ll( mapHdr, after_where, entry);
}

void
vm_map_store_entry_unlink_ll( struct vm_map_header *mapHdr, vm_map_entry_t entry)
{
	_vm_map_entry_unlink_ll( mapHdr, entry);
}

void
vm_map_store_copy_insert_ll( vm_map_t map, vm_map_entry_t after_where, vm_map_copy_t copy)
{
	_vm_map_copy_insert_ll( map, after_where, copy);
}

void
vm_map_store_copy_reset_ll( vm_map_copy_t copy, __unused vm_map_entry_t entry, __unused int nentries)
{
	copy->cpy_hdr.nentries = 0;
	vm_map_copy_first_entry(copy) =
		vm_map_copy_last_entry(copy) =
			vm_map_copy_to_entry(copy);

}

void
update_first_free_ll( vm_map_t map, vm_map_entry_t new_first_free)
{
	UPDATE_FIRST_FREE_LL( map, new_first_free);
}

