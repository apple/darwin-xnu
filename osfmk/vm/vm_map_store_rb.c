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

#include <kern/backtrace.h>
#include <vm/vm_map_store_rb.h>

RB_GENERATE(rb_head, vm_map_store, entry, rb_node_compare);

#define VME_FOR_STORE( store)   \
	(vm_map_entry_t)(((unsigned long)store) - ((unsigned long)sizeof(struct vm_map_links)))

void
vm_map_store_init_rb( struct vm_map_header* hdr )
{
	RB_INIT(&(hdr->rb_head_store));
}

int
rb_node_compare(struct vm_map_store *node, struct vm_map_store *parent)
{
	vm_map_entry_t vme_c;
	vm_map_entry_t vme_p;

	vme_c = VME_FOR_STORE(node);
	vme_p =  VME_FOR_STORE(parent);
	if (vme_c->vme_start < vme_p->vme_start) {
		return -1;
	}
	if (vme_c->vme_start >= vme_p->vme_end) {
		return 1;
	}
	return 0;
}

__dead2
void
vm_map_store_walk_rb(vm_map_t map, vm_map_entry_t *wrong_vme, vm_map_entry_t *vm_entry)
{
	struct vm_map_header *hdr = &map->hdr;
	struct vm_map_store  *rb_entry = RB_ROOT(&hdr->rb_head_store);
	vm_map_entry_t       cur = *vm_entry;

	rb_entry = RB_FIND(rb_head, &hdr->rb_head_store, &(cur->store));
	if (rb_entry == NULL) {
		panic("NO SUCH ENTRY %p. Gave back %p", *vm_entry, *wrong_vme);
	} else {
		panic("Cur: %p, L: %p, R: %p", VME_FOR_STORE(rb_entry), VME_FOR_STORE(RB_LEFT(rb_entry, entry)), VME_FOR_STORE(RB_RIGHT(rb_entry, entry)));
	}
}


boolean_t
vm_map_store_lookup_entry_rb(vm_map_t map, vm_map_offset_t address, vm_map_entry_t *vm_entry)
{
	struct vm_map_header *hdr = &map->hdr;
	struct vm_map_store  *rb_entry = RB_ROOT(&hdr->rb_head_store);
	vm_map_entry_t       cur = vm_map_to_entry(map);
	vm_map_entry_t       prev = VM_MAP_ENTRY_NULL;

	while (rb_entry != (struct vm_map_store*)NULL) {
		cur =  VME_FOR_STORE(rb_entry);
		if (cur == VM_MAP_ENTRY_NULL) {
			panic("no entry");
		}
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
	if (prev == VM_MAP_ENTRY_NULL) {
		prev = vm_map_to_entry(map);
	}
	*vm_entry = prev;
	return FALSE;
}

void
vm_map_store_entry_link_rb( struct vm_map_header *mapHdr, __unused vm_map_entry_t after_where, vm_map_entry_t entry)
{
	struct rb_head *rbh = &(mapHdr->rb_head_store);
	struct vm_map_store *store = &(entry->store);
	struct vm_map_store *tmp_store;
	if ((tmp_store = RB_INSERT( rb_head, rbh, store )) != NULL) {
		panic("VMSEL: INSERT FAILED: 0x%lx, 0x%lx, 0x%lx, 0x%lx", (uintptr_t)entry->vme_start, (uintptr_t)entry->vme_end,
		    (uintptr_t)(VME_FOR_STORE(tmp_store))->vme_start, (uintptr_t)(VME_FOR_STORE(tmp_store))->vme_end);
	}
}

void
vm_map_store_entry_unlink_rb( struct vm_map_header *mapHdr, vm_map_entry_t entry)
{
	struct rb_head *rbh = &(mapHdr->rb_head_store);
	struct vm_map_store *rb_entry;
	struct vm_map_store *store = &(entry->store);

	rb_entry = RB_FIND( rb_head, rbh, store);
	if (rb_entry == NULL) {
		panic("NO ENTRY TO DELETE");
	}
	RB_REMOVE( rb_head, rbh, store );
}

void
vm_map_store_copy_reset_rb( vm_map_copy_t copy, vm_map_entry_t entry, int nentries )
{
	struct vm_map_header *mapHdr = &(copy->cpy_hdr);
	struct rb_head *rbh = &(mapHdr->rb_head_store);
	struct vm_map_store *store;
	int deleted = 0;

	while (entry != vm_map_copy_to_entry(copy) && nentries > 0) {
		store = &(entry->store);
		RB_REMOVE( rb_head, rbh, store );
		entry = entry->vme_next;
		deleted++;
		nentries--;
	}
}

extern zone_t   vm_map_holes_zone;      /* zone for vm map holes (vm_map_links) structures */

void
vm_map_combine_hole(vm_map_t map, vm_map_entry_t hole_entry);
void
vm_map_combine_hole(__unused vm_map_t map, vm_map_entry_t hole_entry)
{
	vm_map_entry_t middle_hole_entry, last_hole_entry;

	hole_entry->vme_end = hole_entry->vme_next->vme_end;

	middle_hole_entry = hole_entry->vme_next;
	last_hole_entry = middle_hole_entry->vme_next;

	assert(last_hole_entry->vme_prev == middle_hole_entry);
	assert(middle_hole_entry->vme_end != last_hole_entry->vme_start);

	last_hole_entry->vme_prev = hole_entry;
	hole_entry->vme_next = last_hole_entry;

	middle_hole_entry->vme_prev = NULL;
	middle_hole_entry->vme_next = NULL;

	zfree(vm_map_holes_zone, middle_hole_entry);

	assert(hole_entry->vme_start < hole_entry->vme_end);
	assert(last_hole_entry->vme_start < last_hole_entry->vme_end);
}


void
vm_map_delete_hole(vm_map_t map, vm_map_entry_t hole_entry);
void
vm_map_delete_hole(vm_map_t map, vm_map_entry_t hole_entry)
{
	if (hole_entry == CAST_TO_VM_MAP_ENTRY(map->holes_list)) {
		if (hole_entry->vme_next == CAST_TO_VM_MAP_ENTRY(map->holes_list)) {
			map->holes_list = NULL;
			SAVE_HINT_HOLE_WRITE(map, NULL);
		} else {
			vm_map_entry_t l_next, l_prev;

			l_next = (vm_map_entry_t) map->holes_list->next;
			l_prev = (vm_map_entry_t) map->holes_list->prev;
			map->holes_list = (struct vm_map_links*) l_next;

			l_next->vme_prev = l_prev;
			l_prev->vme_next = l_next;

			SAVE_HINT_HOLE_WRITE(map, (struct vm_map_links*) l_next);
		}
	} else {
		SAVE_HINT_HOLE_WRITE(map, (struct vm_map_links*) hole_entry->vme_prev);

		hole_entry->vme_prev->vme_next = hole_entry->vme_next;
		hole_entry->vme_next->vme_prev = hole_entry->vme_prev;
	}

	hole_entry->vme_next = NULL;
	hole_entry->vme_prev = NULL;
	zfree(vm_map_holes_zone, hole_entry);
}


/*
 * For Debugging.
 */

#if DEBUG
extern int vm_check_map_sanity;

static void
check_map_sanity(vm_map_t map, vm_map_entry_t old_hole_entry)
{
	vm_map_entry_t  hole_entry, next_hole_entry;
	vm_map_entry_t  map_entry, next_map_entry;

	if (map->holes_list == NULL) {
		return;
	}

	hole_entry = CAST_DOWN(vm_map_entry_t, map->holes_list);
	next_hole_entry = hole_entry->vme_next;

	map_entry = vm_map_first_entry(map);
	next_map_entry = map_entry->vme_next;

	while (map_entry->vme_start > hole_entry->vme_start) {
		hole_entry = next_hole_entry;
		next_hole_entry = hole_entry->vme_next;

		if (hole_entry == CAST_DOWN(vm_map_entry_t, map->holes_list)) {
			break;
		}
	}

	while (map_entry != vm_map_to_entry(map)) {
		if (map_entry->vme_start >= map->max_offset) {
			break;
		}

		if (map_entry->vme_end != map_entry->vme_next->vme_start) {
			if (map_entry->vme_next == vm_map_to_entry(map)) {
				break;
			}

			if (hole_entry->vme_start != map_entry->vme_end) {
				panic("hole_entry not aligned %p(0x%llx), %p (0x%llx), %p", hole_entry, (unsigned long long)hole_entry->vme_start, map_entry->vme_next, (unsigned long long)map_entry->vme_end, old_hole_entry);
				assert(hole_entry->vme_start == map_entry->vme_end);
			}

			if (hole_entry->vme_end != map_entry->vme_next->vme_start) {
				panic("hole_entry not next aligned %p(0x%llx), %p (0x%llx), %p", hole_entry, (unsigned long long)hole_entry->vme_end, map_entry->vme_next, (unsigned long long)map_entry->vme_next->vme_start, old_hole_entry);
				assert(hole_entry->vme_end == map_entry->vme_next->vme_start);
			}

			hole_entry = next_hole_entry;
			next_hole_entry = hole_entry->vme_next;

			if (hole_entry == CAST_DOWN(vm_map_entry_t, map->holes_list)) {
				break;
			}
		}

		map_entry = map_entry->vme_next;
	}
}

/*
 * For debugging.
 */
static void
copy_hole_info(vm_map_entry_t hole_entry, vm_map_entry_t old_hole_entry)
{
	old_hole_entry->vme_prev = hole_entry->vme_prev;
	old_hole_entry->vme_next = hole_entry->vme_next;
	old_hole_entry->vme_start = hole_entry->vme_start;
	old_hole_entry->vme_end = hole_entry->vme_end;
}
#endif /* DEBUG */

void
update_holes_on_entry_deletion(vm_map_t map, vm_map_entry_t old_entry);
void
update_holes_on_entry_deletion(vm_map_t map, vm_map_entry_t old_entry)
{
	/*
	 * Dealing with the deletion of an older entry.
	 */

	vm_map_entry_t          hole_entry, next_hole_entry;
#if DEBUG
	struct vm_map_entry     old_hole_entry;
#endif /* DEBUG */
	boolean_t               create_new_hole = TRUE;

	hole_entry = CAST_TO_VM_MAP_ENTRY(map->hole_hint);

	if (hole_entry) {
		if (hole_entry->vme_end == old_entry->vme_start) {
			/*
			 * Found a hole right after above our entry.
			 * Hit.
			 */
		} else if (hole_entry->vme_start == old_entry->vme_end) {
			if (hole_entry != CAST_TO_VM_MAP_ENTRY(map->holes_list)) {
				/*
				 * Found a hole right after below our entry but
				 * make sure we don't erroneously extend backwards.
				 *
				 * Hit.
				 */

				hole_entry = hole_entry->vme_prev;
			}
		} else if (hole_entry->vme_start > old_entry->vme_end) {
			/*
			 * Useless hint. Start from the top.
			 */

			hole_entry = CAST_TO_VM_MAP_ENTRY(map->holes_list);
		}

		if (hole_entry != CAST_TO_VM_MAP_ENTRY(map->holes_list)) {
			if (hole_entry->vme_start > old_entry->vme_start) {
				panic("Hole hint failed: Hole entry start: 0x%llx, entry start: 0x%llx, map hole start: 0x%llx, map hint start: 0x%llx\n",
				    (unsigned long long)hole_entry->vme_start,
				    (unsigned long long)old_entry->vme_start,
				    (unsigned long long)map->holes_list->start,
				    (unsigned long long)map->hole_hint->start);
			}
			if (hole_entry->vme_end > old_entry->vme_start) {
				panic("Hole hint failed: Hole entry end: 0x%llx, entry start: 0x%llx, map hole start: 0x%llx, map hint start: 0x%llx\n",
				    (unsigned long long)hole_entry->vme_end,
				    (unsigned long long)old_entry->vme_start,
				    (unsigned long long)map->holes_list->start,
				    (unsigned long long)map->hole_hint->start);
			}
		}

		while (1) {
			next_hole_entry = hole_entry->vme_next;

			/*
			 * Hole is right above the entry.
			 */
			if (hole_entry->vme_end == old_entry->vme_start) {
#if DEBUG
				copy_hole_info(hole_entry, &old_hole_entry);
#endif /* DEBUG */

				/*
				 * Is there another hole right below the entry?
				 * Can we combine holes?
				 */

				if (old_entry->vme_end == hole_entry->vme_next->vme_start) {
					vm_map_combine_hole(map, hole_entry);
				} else {
					hole_entry->vme_end = old_entry->vme_end;
				}
				create_new_hole = FALSE;
#if DEBUG
				if (vm_check_map_sanity) {
					check_map_sanity(map, &old_hole_entry);
				}
#endif /* DEBUG */
				break;
			}

			/*
			 * Hole is right below the entry.
			 */
			if (hole_entry->vme_start == old_entry->vme_end) {
#if DEBUG
				copy_hole_info(hole_entry, &old_hole_entry);
#endif /* DEBUG */

				hole_entry->vme_start = old_entry->vme_start;
				create_new_hole = FALSE;

#if DEBUG
				if (vm_check_map_sanity) {
					check_map_sanity(map, &old_hole_entry);
				}
#endif /* DEBUG */
				break;
			}

			/*
			 * Hole is beyond our entry. Let's go back to the last hole
			 * before our entry so we have the right place to link up the
			 * new hole that will be needed.
			 */
			if (hole_entry->vme_start > old_entry->vme_end) {
#if DEBUG
				copy_hole_info(hole_entry, &old_hole_entry);
#endif /* DEBUG */

				if (hole_entry != CAST_TO_VM_MAP_ENTRY(map->holes_list)) {
					assert(hole_entry->vme_start != old_entry->vme_start);
					hole_entry = hole_entry->vme_prev;
				}
				break;
			}

			hole_entry = next_hole_entry;

			if (hole_entry == CAST_TO_VM_MAP_ENTRY(map->holes_list)) {
				hole_entry = hole_entry->vme_prev;
				break;
			}
		}
	}

	if (create_new_hole) {
		struct vm_map_links     *new_hole_entry = NULL;
		vm_map_entry_t          l_next, l_prev;

		new_hole_entry = zalloc(vm_map_holes_zone);

		/*
		 * First hole in the map?
		 * OR
		 * A hole that is located above the current first hole in the map?
		 */
		if (map->holes_list == NULL || (hole_entry == CAST_TO_VM_MAP_ENTRY(map->holes_list) && hole_entry->vme_start > old_entry->vme_start)) {
			if (map->holes_list == NULL) {
				map->holes_list = new_hole_entry;
				new_hole_entry->prev = new_hole_entry->next = CAST_TO_VM_MAP_ENTRY(map->holes_list);
			} else {
				l_next = CAST_TO_VM_MAP_ENTRY(map->holes_list);
				l_prev = map->holes_list->prev;
				map->holes_list = new_hole_entry;
				new_hole_entry->next = l_next;
				new_hole_entry->prev = l_prev;

				l_prev->vme_next = l_next->vme_prev = CAST_TO_VM_MAP_ENTRY(new_hole_entry);
			}
		} else {
			l_next = hole_entry->vme_next;
			l_prev = hole_entry->vme_next->vme_prev;

			new_hole_entry->prev = hole_entry;
			new_hole_entry->next = l_next;

			hole_entry->vme_next = CAST_TO_VM_MAP_ENTRY(new_hole_entry);
			l_next->vme_prev = CAST_TO_VM_MAP_ENTRY(new_hole_entry);
		}

		new_hole_entry->start = old_entry->vme_start;
		new_hole_entry->end = old_entry->vme_end;

		hole_entry = CAST_TO_VM_MAP_ENTRY(new_hole_entry);

		assert(new_hole_entry->start < new_hole_entry->end);
	}

#if DEBUG
	if (vm_check_map_sanity) {
		check_map_sanity(map, &old_hole_entry);
	}
#endif /* DEBUG */

	SAVE_HINT_HOLE_WRITE(map, (struct vm_map_links*) hole_entry);
	return;
}


void
update_holes_on_entry_creation(vm_map_t map, vm_map_entry_t new_entry);
void
update_holes_on_entry_creation(vm_map_t map, vm_map_entry_t new_entry)
{
	vm_map_entry_t                  hole_entry, next_hole_entry;
#if DEBUG
	struct vm_map_entry             old_hole_entry;
	vm_map_entry_t                  tmp_entry;
	boolean_t                               check_map_with_hole_sanity = TRUE;
#endif /* DEBUG */

	/*
	 * Case A: The entry is aligned exactly with the start and end of the hole.
	 *	   This will delete the hole.
	 *
	 * Case B: The entry is completely within a hole but NOT aligned with the start/end of the hole.
	 *	   This  will split a hole.
	 *
	 * Case C: The entry overlaps with the hole. The entry could be extending upwards (C1) or downwards (C2).
	 *	   This will reduce the size of the hole or delete the hole completely if it is smaller than the entry.
	 */

	hole_entry = CAST_TO_VM_MAP_ENTRY(map->holes_list);
	assert(hole_entry);
	next_hole_entry = hole_entry->vme_next;

	while (1) {
#if DEBUG
		/*
		 * If the entry doesn't exist in the RB tree, we are likely dealing with copy maps where
		 * the entries belonging to the copy map are linked into the list of entries silently and
		 * then added to the RB-tree later on.
		 * So sanity checks are useless in that case.
		 */
		check_map_with_hole_sanity = vm_map_lookup_entry(map, new_entry->vme_start, &tmp_entry);
#endif /* DEBUG */

		if (hole_entry->vme_start == new_entry->vme_start &&
		    hole_entry->vme_end == new_entry->vme_end) {
			/* Case A */
#if DEBUG
			copy_hole_info(hole_entry, &old_hole_entry);
#endif /* DEBUG */

			/*
			 * This check makes sense only for regular maps, not copy maps.
			 * With a regular map, the VM entry is first linked and then
			 * the hole is deleted. So the check below, which makes sure that
			 * the map's bounds are being respected, is valid.
			 * But for copy maps, the hole is deleted before the VM entry is
			 * linked (vm_map_store_copy_insert) and so this check is invalid.
			 *
			 *  if (hole_entry == (vm_map_entry_t) map->holes_list) {
			 *
			 *       if (hole_entry->vme_next == (vm_map_entry_t) map->holes_list) {
			 *
			 *               next_hole_entry = vm_map_last_entry(map);
			 *               assert(next_hole_entry->vme_end >= map->max_offset);
			 *       }
			 *  }
			 */

			vm_map_delete_hole(map, hole_entry);

#if DEBUG
			if (vm_check_map_sanity && check_map_with_hole_sanity) {
				check_map_sanity(map, &old_hole_entry);
			}
#endif /* DEBUG */
			return;
		} else if (hole_entry->vme_start < new_entry->vme_start &&
		    hole_entry->vme_end > new_entry->vme_end) {
			/* Case B */
			struct vm_map_links *new_hole_entry = NULL;

			new_hole_entry = zalloc(vm_map_holes_zone);

#if DEBUG
			copy_hole_info(hole_entry, &old_hole_entry);
#endif /* DEBUG */

			new_hole_entry->prev = hole_entry;
			new_hole_entry->next = hole_entry->vme_next;
			hole_entry->vme_next->vme_prev = CAST_TO_VM_MAP_ENTRY(new_hole_entry);
			hole_entry->vme_next = CAST_TO_VM_MAP_ENTRY(new_hole_entry);

			new_hole_entry->start = new_entry->vme_end;
			new_hole_entry->end = hole_entry->vme_end;
			hole_entry->vme_end = new_entry->vme_start;

			assert(hole_entry->vme_start < hole_entry->vme_end);
			assert(new_hole_entry->start < new_hole_entry->end);

#if DEBUG
			if (vm_check_map_sanity && check_map_with_hole_sanity) {
				check_map_sanity(map, &old_hole_entry);
			}
#endif /* DEBUG */

			SAVE_HINT_HOLE_WRITE(map, (struct vm_map_links*) hole_entry);
			return;
		} else if ((new_entry->vme_start <= hole_entry->vme_start) && (hole_entry->vme_start < new_entry->vme_end)) {
			/*
			 * Case C1: Entry moving upwards and a part/full hole lies within the bounds of the entry.
			 */

#if DEBUG
			copy_hole_info(hole_entry, &old_hole_entry);
#endif /* DEBUG */

			if (hole_entry->vme_end <= new_entry->vme_end) {
				vm_map_delete_hole(map, hole_entry);
			} else {
				hole_entry->vme_start = new_entry->vme_end;
				SAVE_HINT_HOLE_WRITE(map, (struct vm_map_links*) hole_entry);
			}

#if DEBUG
			if (vm_check_map_sanity && check_map_with_hole_sanity) {
				check_map_sanity(map, &old_hole_entry);
			}
#endif /* DEBUG */

			return;
		} else if ((new_entry->vme_start < hole_entry->vme_end) && (hole_entry->vme_end <= new_entry->vme_end)) {
			/*
			 * Case C2: Entry moving downwards and a part/full hole lies within the bounds of the entry.
			 */

#if DEBUG
			copy_hole_info(hole_entry, &old_hole_entry);
#endif /* DEBUG */

			if (hole_entry->vme_start >= new_entry->vme_start) {
				vm_map_delete_hole(map, hole_entry);
			} else {
				hole_entry->vme_end = new_entry->vme_start;
				SAVE_HINT_HOLE_WRITE(map, (struct vm_map_links*) hole_entry);
			}

#if DEBUG
			if (vm_check_map_sanity && check_map_with_hole_sanity) {
				check_map_sanity(map, &old_hole_entry);
			}
#endif /* DEBUG */

			return;
		}

		hole_entry = next_hole_entry;
		next_hole_entry = hole_entry->vme_next;

		if (hole_entry == CAST_TO_VM_MAP_ENTRY(map->holes_list)) {
			break;
		}
	}

	panic("Illegal action: h1: %p, s:0x%llx, e:0x%llx...h2:%p, s:0x%llx, e:0x%llx...h3:0x%p, s:0x%llx, e:0x%llx\n",
	    hole_entry->vme_prev,
	    (unsigned long long)hole_entry->vme_prev->vme_start,
	    (unsigned long long)hole_entry->vme_prev->vme_end,
	    hole_entry,
	    (unsigned long long)hole_entry->vme_start,
	    (unsigned long long)hole_entry->vme_end,
	    hole_entry->vme_next,
	    (unsigned long long)hole_entry->vme_next->vme_start,
	    (unsigned long long)hole_entry->vme_next->vme_end);
}

void
update_first_free_rb(vm_map_t map, vm_map_entry_t entry, boolean_t new_entry_creation)
{
	if (map->holelistenabled) {
		/*
		 * Holes can be used to track ranges all the way up to MACH_VM_MAX_ADDRESS or more (e.g. kernel map).
		 */
		vm_map_offset_t max_valid_offset = (map->max_offset > MACH_VM_MAX_ADDRESS) ? map->max_offset : MACH_VM_MAX_ADDRESS;

		/*
		 * Clipping an entry will not result in the creation/deletion/modification of
		 * a hole. Those calls pass NULL for their target entry.
		 */
		if (entry == NULL) {
			return;
		}

		/*
		 * Commpage is pinned beyond the map's max offset. That shouldn't affect the
		 * holes within the bounds of the map.
		 */
		if (vm_map_trunc_page(entry->vme_start, VM_MAP_PAGE_MASK(map)) >= max_valid_offset) {
			return;
		}

		/*
		 *
		 * Note:
		 *
		 * - A new entry has already been added to the map
		 * OR
		 * - An older entry has already been deleted from the map
		 *
		 * We are updating the hole list after the fact (except in one special case involving copy maps).
		 *
		 */

		if (new_entry_creation) {
			update_holes_on_entry_creation(map, entry);
		} else {
			update_holes_on_entry_deletion(map, entry);
		}
	}
}
