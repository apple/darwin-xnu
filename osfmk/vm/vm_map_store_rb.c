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

#include <vm/vm_map_store_rb.h>

RB_GENERATE(rb_head, vm_map_store, entry, rb_node_compare);

#define VME_FOR_STORE( store)	\
	(vm_map_entry_t)(((unsigned long)store) - ((unsigned long)sizeof(struct vm_map_links)))

void
vm_map_store_init_rb( struct vm_map_header* hdr )
{
	RB_INIT(&(hdr->rb_head_store));
}

int rb_node_compare(struct vm_map_store *node, struct vm_map_store *parent)
{
	vm_map_entry_t vme_c;
	vm_map_entry_t vme_p;

	vme_c = VME_FOR_STORE(node);
	vme_p =  VME_FOR_STORE(parent);
	if (vme_c->vme_start < vme_p->vme_start)
		return -1;
	if (vme_c->vme_start >= vme_p->vme_end)
		return 1;
	return 0;
}

void vm_map_store_walk_rb( vm_map_t map, vm_map_entry_t *wrong_vme, vm_map_entry_t *vm_entry)
{
	struct vm_map_header hdr = map->hdr;
	struct vm_map_store *rb_entry = RB_ROOT(&(hdr.rb_head_store));
	vm_map_entry_t cur = *vm_entry;

	rb_entry = RB_FIND( rb_head, &(hdr.rb_head_store), &(cur->store));	
	if(rb_entry == NULL)
		panic("NO SUCH ENTRY %p. Gave back %p", *vm_entry, *wrong_vme);
	else
		panic("Cur: %p, L: %p, R: %p",  VME_FOR_STORE(rb_entry),  VME_FOR_STORE(RB_LEFT(rb_entry,entry)),  VME_FOR_STORE(RB_RIGHT(rb_entry,entry)));
}


boolean_t vm_map_store_lookup_entry_rb( vm_map_t map, vm_map_offset_t address, vm_map_entry_t *vm_entry)
{
	struct vm_map_header hdr = map->hdr;
	struct vm_map_store *rb_entry = RB_ROOT(&(hdr.rb_head_store));
	vm_map_entry_t cur = vm_map_to_entry(map);
	vm_map_entry_t prev = VM_MAP_ENTRY_NULL;

	while (rb_entry != (struct vm_map_store*)NULL) {
       		cur =  VME_FOR_STORE(rb_entry);
		if(cur == VM_MAP_ENTRY_NULL)
			panic("no entry");
		if (address >= cur->vme_start) {
			if (address < cur->vme_end) {
				*vm_entry = cur;
				return TRUE;
			}
			rb_entry = RB_RIGHT(rb_entry, entry);
			prev = cur;
		} else {
			rb_entry = RB_LEFT(rb_entry, entry);
		}
	}
	if( prev == VM_MAP_ENTRY_NULL){
		prev = vm_map_to_entry(map);
	}
	*vm_entry = prev;
	return FALSE;
}

void 	vm_map_store_entry_link_rb( struct vm_map_header *mapHdr, __unused vm_map_entry_t after_where, vm_map_entry_t entry)
{
	struct rb_head *rbh = &(mapHdr->rb_head_store);
	struct vm_map_store *store = &(entry->store);
	struct vm_map_store *tmp_store;
	if((tmp_store = RB_INSERT( rb_head, rbh, store )) != NULL) {
		panic("VMSEL: INSERT FAILED: 0x%lx, 0x%lx, 0x%lx, 0x%lx", (uintptr_t)entry->vme_start, (uintptr_t)entry->vme_end,
				(uintptr_t)(VME_FOR_STORE(tmp_store))->vme_start,  (uintptr_t)(VME_FOR_STORE(tmp_store))->vme_end);
	}
}

void	vm_map_store_entry_unlink_rb( struct vm_map_header *mapHdr, vm_map_entry_t entry)
{
	struct rb_head *rbh = &(mapHdr->rb_head_store);
	struct vm_map_store *rb_entry;
	struct vm_map_store *store = &(entry->store);
	
	rb_entry = RB_FIND( rb_head, rbh, store);	
	if(rb_entry == NULL)
		panic("NO ENTRY TO DELETE");
	RB_REMOVE( rb_head, rbh, store );
}

void	vm_map_store_copy_insert_rb( vm_map_t map, __unused vm_map_entry_t after_where, vm_map_copy_t copy)
{
	struct vm_map_header *mapHdr = &(map->hdr);
	struct rb_head *rbh = &(mapHdr->rb_head_store);
	struct vm_map_store *store;
	vm_map_entry_t entry = vm_map_copy_first_entry(copy);
	int inserted=0, nentries = copy->cpy_hdr.nentries;
		
	while (entry != vm_map_copy_to_entry(copy) && nentries > 0) {		
		vm_map_entry_t prev = entry;
		store = &(entry->store);
		if( RB_INSERT( rb_head, rbh, store ) != NULL){
			panic("VMSCIR1: INSERT FAILED: %d: %p, %p, %p, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx",inserted, prev, entry, vm_map_copy_to_entry(copy), 
					(uintptr_t)prev->vme_start,  (uintptr_t)prev->vme_end,  (uintptr_t)entry->vme_start,  (uintptr_t)entry->vme_end,  
					 (uintptr_t)(VME_FOR_STORE(rbh->rbh_root))->vme_start,  (uintptr_t)(VME_FOR_STORE(rbh->rbh_root))->vme_end);
		} else {
#if MAP_ENTRY_INSERTION_DEBUG
			fastbacktrace(&entry->vme_insertion_bt[0],
				      (sizeof (entry->vme_insertion_bt) / sizeof (uintptr_t)));
#endif
			entry = entry->vme_next;
			inserted++;
			nentries--;
		}
	}
}

void
vm_map_store_copy_reset_rb( vm_map_copy_t copy, vm_map_entry_t entry, int nentries )
{
	struct vm_map_header *mapHdr = &(copy->cpy_hdr);
	struct rb_head *rbh = &(mapHdr->rb_head_store);
	struct vm_map_store *store;
	int deleted=0;
		
	while (entry != vm_map_copy_to_entry(copy) && nentries > 0) {		
		store = &(entry->store);
		RB_REMOVE( rb_head, rbh, store );
		entry = entry->vme_next;
		deleted++;
		nentries--;
	}
}

void	update_first_free_rb( __unused vm_map_t map, __unused vm_map_entry_t entry)
{
	return ;
}

