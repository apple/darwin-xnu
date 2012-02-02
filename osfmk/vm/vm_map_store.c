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

#include <vm/vm_map_store.h>

#if MACH_ASSERT
boolean_t
first_free_is_valid_store( vm_map_t map )
{
	return(first_free_is_valid_ll( map ));
}
#endif

void
vm_map_store_init( struct vm_map_header *hdr )
{
	vm_map_store_init_ll( hdr );
#ifdef VM_MAP_STORE_USE_RB
	vm_map_store_init_rb( hdr );
#endif
}

boolean_t
vm_map_store_lookup_entry(
	register vm_map_t		map,
	register vm_map_offset_t	address,
	vm_map_entry_t		*entry)		/* OUT */
{
#ifdef VM_MAP_STORE_USE_LL
	return (vm_map_store_lookup_entry_ll( map, address, entry ));
#elif defined VM_MAP_STORE_USE_RB
	return (vm_map_store_lookup_entry_rb( map, address, entry ));
#endif
}

void
vm_map_store_update( vm_map_t map, vm_map_entry_t entry, int update_type )
{
	switch (update_type) {
		case VM_MAP_ENTRY_CREATE:
			break;
		case VM_MAP_ENTRY_DELETE:
			if((entry) == (map)->first_free) {
				(map)->first_free = vm_map_to_entry(map);
			}
			if((entry) == (map)->hint) {
				(map)->hint = vm_map_to_entry(map);
			}
			break;
		default:
			break;
	}
}

void	vm_map_store_copy_insert( vm_map_t map, vm_map_entry_t after_where, vm_map_copy_t copy)
{
	vm_map_store_copy_insert_ll(map, after_where, copy);
#ifdef VM_MAP_STORE_USE_RB
	vm_map_store_copy_insert_rb(map, after_where, copy);
#endif
}

/*
 *	vm_map_entry_{un,}link:
 *
 *	Insert/remove entries from maps (or map copies).
 *	The _vm_map_store_entry_{un,}link variants are used at
 *	some places where updating first_free is not needed &
 *	copy maps are being modified. Also note the first argument
 *	is the map header.
 *	Modifying the vm_map_store_entry_{un,}link functions to 
 *	deal with these call sites made the interface confusing
 *	and clunky.
 */

void
_vm_map_store_entry_link( struct vm_map_header * mapHdr, vm_map_entry_t after_where, vm_map_entry_t entry)
{
	assert(entry->vme_start < entry->vme_end);
	vm_map_store_entry_link_ll(mapHdr, after_where, entry);
#ifdef VM_MAP_STORE_USE_RB
	vm_map_store_entry_link_rb(mapHdr, after_where, entry);
#endif
}

void
vm_map_store_entry_link( vm_map_t map, vm_map_entry_t after_where, vm_map_entry_t entry)
{
	vm_map_t VMEL_map;
	vm_map_entry_t VMEL_entry;
	VMEL_map = (map);
	VMEL_entry = (entry);
	
	_vm_map_store_entry_link(&VMEL_map->hdr, after_where, VMEL_entry);
	if( VMEL_map->disable_vmentry_reuse == TRUE ) {
		UPDATE_HIGHEST_ENTRY_END( VMEL_map, VMEL_entry);
	} else {
		update_first_free_ll(VMEL_map, VMEL_map->first_free);
#ifdef VM_MAP_STORE_USE_RB
		update_first_free_rb(VMEL_map, VMEL_map->first_free);
#endif
	}
}

void
_vm_map_store_entry_unlink( struct vm_map_header * mapHdr, vm_map_entry_t entry)
{
	vm_map_store_entry_unlink_ll(mapHdr, entry);
#ifdef VM_MAP_STORE_USE_RB
	vm_map_store_entry_unlink_rb(mapHdr, entry);
#endif
}

void
vm_map_store_entry_unlink( vm_map_t map, vm_map_entry_t entry)
{
	vm_map_t VMEU_map;
	vm_map_entry_t VMEU_entry;
	vm_map_entry_t VMEU_first_free;
	VMEU_map = (map);
	VMEU_entry = (entry);
	if (VMEU_entry->vme_start <= VMEU_map->first_free->vme_start){
		VMEU_first_free = VMEU_entry->vme_prev;		
	} else	{
		VMEU_first_free = VMEU_map->first_free;
	}
	
	_vm_map_store_entry_unlink(&VMEU_map->hdr, VMEU_entry);
	update_first_free_ll(VMEU_map, VMEU_first_free);
#ifdef VM_MAP_STORE_USE_RB
	update_first_free_rb(VMEU_map, VMEU_first_free);
#endif
}

void
vm_map_store_copy_reset( vm_map_copy_t copy,vm_map_entry_t entry)
{
	int nentries = copy->cpy_hdr.nentries;
	vm_map_store_copy_reset_ll(copy, entry, nentries);
#ifdef VM_MAP_STORE_USE_RB
	vm_map_store_copy_reset_rb(copy, entry, nentries);
#endif
}

void
vm_map_store_update_first_free( vm_map_t map, vm_map_entry_t first_free)
{
	update_first_free_ll(map, first_free);
#ifdef VM_MAP_STORE_USE_RB
	update_first_free_rb(map, first_free);
#endif
}
