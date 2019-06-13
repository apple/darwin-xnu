/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
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
 *	File:	ipc/ipc_entry.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Primitive functions to manipulate translation entries.
 */

#include <mach_debug.h>

#include <mach/kern_return.h>
#include <mach/port.h>
#include <kern/assert.h>
#include <kern/sched_prim.h>
#include <kern/zalloc.h>
#include <kern/misc_protos.h>
#include <ipc/port.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_hash.h>
#include <ipc/ipc_table.h>
#include <ipc/ipc_port.h>
#include <string.h>
#include <sys/kdebug.h>

/*
 *	Routine:	ipc_entry_lookup
 *	Purpose:
 *		Searches for an entry, given its name.
 *	Conditions:
 *		The space must be read or write locked throughout.
 *		The space must be active.
 */

ipc_entry_t
ipc_entry_lookup(
	ipc_space_t		space,
	mach_port_name_t	name)
{
	mach_port_index_t index;
	ipc_entry_t entry;

	assert(is_active(space));

	index = MACH_PORT_INDEX(name);
	if (index <  space->is_table_size) {
                entry = &space->is_table[index];
		if (IE_BITS_GEN(entry->ie_bits) != MACH_PORT_GEN(name) ||
		    IE_BITS_TYPE(entry->ie_bits) == MACH_PORT_TYPE_NONE) {
			entry = IE_NULL;		
		}
	}
	else {
		entry = IE_NULL;
	}

	assert((entry == IE_NULL) || IE_BITS_TYPE(entry->ie_bits));
	return entry;
}


/*
 *	Routine:	ipc_entries_hold
 *	Purpose:
 *		Verifies that there are at least 'entries_needed'
 *		free list members
 *	Conditions:
 *		The space is write-locked and active throughout.
 *		An object may be locked.  Will not allocate memory.
 *	Returns:
 *		KERN_SUCCESS		Free entries were found.
 *		KERN_NO_SPACE		No entry allocated.
 */

kern_return_t
ipc_entries_hold(
	ipc_space_t		space,
	uint32_t		entries_needed)
{

	ipc_entry_t table;
	mach_port_index_t next_free = 0;
	uint32_t i;

	assert(is_active(space));

	table = &space->is_table[0];

	for (i = 0; i < entries_needed; i++) {
		next_free = table[next_free].ie_next;
		if (next_free == 0) {
			return KERN_NO_SPACE;
		}
		assert(next_free < space->is_table_size);
		assert(table[next_free].ie_object == IO_NULL);
	}
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_entry_claim
 *	Purpose:
 *		Take formal ownership of a held entry.
 *	Conditions:
 *		The space is write-locked and active throughout.
 *		An object may be locked.  Will not allocate memory.
 *
 * 	Note: The returned entry must be marked as modified before
 * 	      releasing the space lock
 */

kern_return_t
ipc_entry_claim(
	ipc_space_t		space,
	mach_port_name_t	*namep,
	ipc_entry_t		*entryp)
{
	ipc_entry_t entry;
	ipc_entry_t table;
	mach_port_index_t first_free;
	mach_port_gen_t gen;
	mach_port_name_t new_name;

	table = &space->is_table[0];

	first_free = table->ie_next;
	assert(first_free != 0);

	entry = &table[first_free];
	table->ie_next = entry->ie_next;
	space->is_table_free--;

	assert(table->ie_next < space->is_table_size);

	/*
	 *	Initialize the new entry: increment gencount and reset
	 *	rollover point if it rolled over, and clear ie_request.
	 */
	gen = ipc_entry_new_gen(entry->ie_bits);
	if (__improbable(ipc_entry_gen_rolled(entry->ie_bits, gen))) {
		ipc_entry_bits_t roll = ipc_space_get_rollpoint(space);
		gen = ipc_entry_new_rollpoint(roll);
	}
	entry->ie_bits = gen;
	entry->ie_request = IE_REQ_NONE;

	/*
	 *	The new name can't be MACH_PORT_NULL because index
	 *	is non-zero.  It can't be MACH_PORT_DEAD because
	 *	the table isn't allowed to grow big enough.
	 *	(See comment in ipc/ipc_table.h.)
	 */
	new_name = MACH_PORT_MAKE(first_free, gen);
	assert(MACH_PORT_VALID(new_name));
	*namep = new_name;
	*entryp = entry;

	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_entry_get
 *	Purpose:
 *		Tries to allocate an entry out of the space.
 *	Conditions:
 *		The space is write-locked and active throughout.
 *		An object may be locked.  Will not allocate memory.
 *	Returns:
 *		KERN_SUCCESS		A free entry was found.
 *		KERN_NO_SPACE		No entry allocated.
 */

kern_return_t
ipc_entry_get(
	ipc_space_t		space,
	mach_port_name_t	*namep,
	ipc_entry_t		*entryp)
{
	kern_return_t kr;

	kr = ipc_entries_hold(space, 1);
	if (KERN_SUCCESS != kr)
		return kr;

	return ipc_entry_claim(space, namep, entryp);
}

/*
 *	Routine:	ipc_entry_alloc
 *	Purpose:
 *		Allocate an entry out of the space.
 *	Conditions:
 *		The space is not locked before, but it is write-locked after
 *		if the call is successful.  May allocate memory.
 *	Returns:
 *		KERN_SUCCESS		An entry was allocated.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_NO_SPACE		No room for an entry in the space.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory for an entry.
 */

kern_return_t
ipc_entry_alloc(
	ipc_space_t		space,
	mach_port_name_t	*namep,
	ipc_entry_t		*entryp)
{
	kern_return_t kr;

	is_write_lock(space);

	for (;;) {
		if (!is_active(space)) {
			is_write_unlock(space);
			return KERN_INVALID_TASK;
		}

		kr = ipc_entry_get(space, namep, entryp);
		if (kr == KERN_SUCCESS)
			return kr;

		kr = ipc_entry_grow_table(space, ITS_SIZE_NONE);
		if (kr != KERN_SUCCESS)
			return kr; /* space is unlocked */
	}
}

/*
 *	Routine:	ipc_entry_alloc_name
 *	Purpose:
 *		Allocates/finds an entry with a specific name.
 *		If an existing entry is returned, its type will be nonzero.
 *	Conditions:
 *		The space is not locked before, but it is write-locked after
 *		if the call is successful.  May allocate memory.
 *	Returns:
 *		KERN_SUCCESS		Found existing entry with same name.
 *		KERN_SUCCESS		Allocated a new entry.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 *		KERN_FAILURE		Couldn't allocate requested name.
 */

kern_return_t
ipc_entry_alloc_name(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		*entryp)
{
	mach_port_index_t index = MACH_PORT_INDEX(name);
	mach_port_gen_t gen = MACH_PORT_GEN(name);

	if (index > ipc_table_max_entries())
		return KERN_NO_SPACE;

	assert(MACH_PORT_VALID(name));


	is_write_lock(space);

	for (;;) {
		ipc_entry_t entry;

		if (!is_active(space)) {
			is_write_unlock(space);
			return KERN_INVALID_TASK;
		}

		/*
		 *	If we are under the table cutoff,
		 *	there are usually four cases:
		 *		1) The entry is reserved (index 0)
		 *		2) The entry is inuse, for the same name
		 *		3) The entry is inuse, for a different name
		 *		4) The entry is free
		 *	For a task with a "fast" IPC space, we disallow
		 *	cases 1) and 3), because ports cannot be renamed.
		 */
		if (index < space->is_table_size) {
			ipc_entry_t table = space->is_table;

			entry = &table[index];

			if (index == 0) {
				/* case #1 - the entry is reserved */
				assert(!IE_BITS_TYPE(entry->ie_bits));
				assert(!IE_BITS_GEN(entry->ie_bits));
				is_write_unlock(space);				
				return KERN_FAILURE;
			} else if (IE_BITS_TYPE(entry->ie_bits)) {
				if (IE_BITS_GEN(entry->ie_bits) == gen) {
					/* case #2 -- the entry is inuse, for the same name */
					*entryp = entry;
					return KERN_SUCCESS;
				} else {
					/* case #3 -- the entry is inuse, for a different name. */
					/* Collisions are not allowed */
					is_write_unlock(space);					
					return KERN_FAILURE;
				}
			} else {
				mach_port_index_t free_index, next_index;

				/*
				 *      case #4 -- the entry is free
				 *	Rip the entry out of the free list.
				 */

				for (free_index = 0;
				     (next_index = table[free_index].ie_next)
							!= index;
				     free_index = next_index)
					continue;

				table[free_index].ie_next =
					table[next_index].ie_next;
				space->is_table_free--;

				/* mark the previous entry modified - reconstructing the name */
				ipc_entry_modified(space, 
						   MACH_PORT_MAKE(free_index, 
						   	IE_BITS_GEN(table[free_index].ie_bits)),
						   &table[free_index]);

				entry->ie_bits = gen;
				entry->ie_request = IE_REQ_NONE;
				*entryp = entry;

				assert(entry->ie_object == IO_NULL);
				return KERN_SUCCESS;
			}
		}

		/*
		 *      We grow the table so that the name
		 *	index fits in the array space.
		 *      Because the space will be unlocked,
		 *      we must restart.
		 */
                kern_return_t kr;
		kr = ipc_entry_grow_table(space, index + 1);
		assert(kr != KERN_NO_SPACE);
		if (kr != KERN_SUCCESS) {
			/* space is unlocked */
			return kr;
		}
		continue;
	}
}

/*
 *	Routine:	ipc_entry_dealloc
 *	Purpose:
 *		Deallocates an entry from a space.
 *	Conditions:
 *		The space must be write-locked throughout.
 *		The space must be active.
 */

void
ipc_entry_dealloc(
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_entry_t		entry)
{
	ipc_entry_t table;
	ipc_entry_num_t size;
	mach_port_index_t index;

	assert(is_active(space));
	assert(entry->ie_object == IO_NULL);
	assert(entry->ie_request == IE_REQ_NONE);

#if 1
	if (entry->ie_request != IE_REQ_NONE)
		panic("ipc_entry_dealloc()\n");
#endif

	index = MACH_PORT_INDEX(name);
	table = space->is_table;
	size = space->is_table_size;

	if ((index < size) && (entry == &table[index])) {
		assert(IE_BITS_GEN(entry->ie_bits) == MACH_PORT_GEN(name));
		entry->ie_bits &= (IE_BITS_GEN_MASK | IE_BITS_ROLL_MASK);
		entry->ie_next = table->ie_next;
		table->ie_next = index;
		space->is_table_free++;
	} else {
		/*
		 * Nothing to do.  The entry does not match
		 * so there is nothing to deallocate.
		 */
                assert(index < size);
		assert(entry == &table[index]);
		assert(IE_BITS_GEN(entry->ie_bits) == MACH_PORT_GEN(name));
	}
	ipc_entry_modified(space, name, entry);
}

/*
 *	Routine:	ipc_entry_modified
 *	Purpose:
 *		Note that an entry was modified in a space.
 *	Conditions:
 *		Assumes exclusive write access to the space,
 *		either through a write lock or being the cleaner
 *		on an inactive space.
 */

void
ipc_entry_modified(
	ipc_space_t		space,
	mach_port_name_t	name,
	__assert_only ipc_entry_t entry)
{
	ipc_entry_t table;
	ipc_entry_num_t size;
	mach_port_index_t index;

	index = MACH_PORT_INDEX(name);
	table = space->is_table;
	size = space->is_table_size;

	assert(index < size);
	assert(entry == &table[index]);

	assert(space->is_low_mod <= size);
	assert(space->is_high_mod < size);

	if (index < space->is_low_mod)
		space->is_low_mod = index;
	if (index > space->is_high_mod)
		space->is_high_mod = index;

	KERNEL_DEBUG_CONSTANT(
		MACHDBG_CODE(DBG_MACH_IPC,MACH_IPC_PORT_ENTRY_MODIFY) | DBG_FUNC_NONE,
		space->is_task ? task_pid(space->is_task) : 0,
		name,
		entry->ie_bits,
		0,
		0);
}

#define IPC_ENTRY_GROW_STATS 1
#if IPC_ENTRY_GROW_STATS
static uint64_t ipc_entry_grow_count = 0;
static uint64_t ipc_entry_grow_rescan = 0;
static uint64_t ipc_entry_grow_rescan_max = 0;
static uint64_t ipc_entry_grow_rescan_entries = 0;
static uint64_t ipc_entry_grow_rescan_entries_max = 0;
static uint64_t	ipc_entry_grow_freelist_entries = 0;
static uint64_t	ipc_entry_grow_freelist_entries_max = 0;
#endif

/*
 *	Routine:	ipc_entry_grow_table
 *	Purpose:
 *		Grows the table in a space.
 *	Conditions:
 *		The space must be write-locked and active before.
 *		If successful, the space is also returned locked.
 *		On failure, the space is returned unlocked.
 *		Allocates memory.
 *	Returns:
 *		KERN_SUCCESS		Grew the table.
 *		KERN_SUCCESS		Somebody else grew the table.
 *		KERN_SUCCESS		The space died.
 *		KERN_NO_SPACE		Table has maximum size already.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate a new table.
 */

kern_return_t
ipc_entry_grow_table(
	ipc_space_t		space,
	ipc_table_elems_t	target_size)
{
	ipc_entry_num_t osize, size, nsize, psize;

	ipc_entry_t otable, table;
	ipc_table_size_t oits, its, nits;
	mach_port_index_t i, free_index;
	mach_port_index_t low_mod, hi_mod;
	ipc_table_index_t sanity;
#if IPC_ENTRY_GROW_STATS
	uint64_t rescan_count = 0;
#endif
	assert(is_active(space));

	if (is_growing(space)) {
		/*
		 *	Somebody else is growing the table.
		 *	We just wait for them to finish.
		 */

		is_write_sleep(space);
		return KERN_SUCCESS;
	}

	otable = space->is_table;
		
	its = space->is_table_next;
	size = its->its_size;
		
	/*
	 * Since is_table_next points to the next natural size
	 * we can identify the current size entry.
	 */
	oits = its - 1;
	osize = oits->its_size;
		
	/*
	 * If there is no target size, then the new size is simply
	 * specified by is_table_next.  If there is a target
	 * size, then search for the next entry.
	 */
	if (target_size != ITS_SIZE_NONE) {
		if (target_size <= osize) {
			/* the space is locked */			
			return KERN_SUCCESS;
		}

		psize = osize;
		while ((psize != size) && (target_size > size)) {
			psize = size;
			its++;
			size = its->its_size;
		}
		if (psize == size) {
			is_write_unlock(space);
			return KERN_NO_SPACE;
		}
	}

	if (osize == size) {
		is_write_unlock(space);
		return KERN_NO_SPACE;
	}
 
	nits = its + 1;
	nsize = nits->its_size;
	assert((osize < size) && (size <= nsize));

	/*
	 * We'll attempt to grow the table.
	 *
	 * Because we will be copying without the space lock, reset
	 * the lowest_mod index to just beyond the end of the current
	 * table.  Modification of entries (other than hashes) will
	 * bump this downward, and we only have to reprocess entries
	 * above that mark.  Eventually, we'll get done.
	 */
	is_start_growing(space);
	space->is_low_mod = osize;
	space->is_high_mod = 0;
#if IPC_ENTRY_GROW_STATS
	ipc_entry_grow_count++;
#endif
	is_write_unlock(space);

	table = it_entries_alloc(its);
	if (table == IE_NULL) {
		is_write_lock(space);
		is_done_growing(space);
		is_write_unlock(space);
		thread_wakeup((event_t) space);
		return KERN_RESOURCE_SHORTAGE;
	}

	ipc_space_rand_freelist(space, table, osize, size);

	/* clear out old entries in new table */
	memset((void *)table, 0, osize * sizeof(*table));

	low_mod = 0;
	hi_mod = osize - 1;
 rescan:	
	/*
	 * Within the range of the table that changed, determine what we
	 * have to take action on. For each entry, take a snapshot of the
	 * corresponding entry in the old table (so it won't change
	 * during this iteration). The snapshot may not be self-consistent
	 * (if we caught it in the middle of being changed), so be very
	 * cautious with the values.
	 */
	for (i = low_mod; i <= hi_mod; i++) {
		ipc_entry_t entry = &table[i];
		struct ipc_entry osnap = otable[i]; 

		if (entry->ie_object != osnap.ie_object ||
		    IE_BITS_TYPE(entry->ie_bits) != IE_BITS_TYPE(osnap.ie_bits)) {
			
			if (entry->ie_object != IO_NULL &&
			    IE_BITS_TYPE(entry->ie_bits) == MACH_PORT_TYPE_SEND)
				ipc_hash_table_delete(table, size, entry->ie_object, i, entry);

			entry->ie_object = osnap.ie_object;
			entry->ie_bits = osnap.ie_bits;
			entry->ie_request = osnap.ie_request; /* or ie_next */

			if (entry->ie_object != IO_NULL &&
			    IE_BITS_TYPE(entry->ie_bits) == MACH_PORT_TYPE_SEND)
				ipc_hash_table_insert(table, size, entry->ie_object, i, entry);
		} else {
			assert(entry->ie_object == osnap.ie_object);
			entry->ie_bits = osnap.ie_bits;
			entry->ie_request = osnap.ie_request; /* or ie_next */
		}

	}
	table[0].ie_next = otable[0].ie_next;  /* always rebase the freelist */

	/*
	 * find the end of the freelist (should be short). But be careful,
	 * the list items can change so only follow through truly free entries
	 * (no problem stopping short in those cases, because we'll rescan).
	 */
	free_index = 0;
	for (sanity = 0; sanity < osize; sanity++) {
		if (table[free_index].ie_object != IPC_OBJECT_NULL)
			break;
		i = table[free_index].ie_next;
		if (i == 0 || i >= osize)
			break;
		free_index = i;
	}
#if IPC_ENTRY_GROW_STATS
	ipc_entry_grow_freelist_entries += sanity;
	if (sanity > ipc_entry_grow_freelist_entries_max)
		ipc_entry_grow_freelist_entries_max = sanity;
#endif
		
	is_write_lock(space);

	/*
	 *	We need to do a wakeup on the space,
	 *	to rouse waiting threads.  We defer
	 *	this until the space is unlocked,
	 *	because we don't want them to spin.
	 */

	if (!is_active(space)) {
		/*
		 *	The space died while it was unlocked.
		 */

		is_done_growing(space);
		is_write_unlock(space);
		thread_wakeup((event_t) space);
		it_entries_free(its, table);
		is_write_lock(space);
		return KERN_SUCCESS;
	}

	/* If the space changed while unlocked, go back and process the changes */
	if (space->is_low_mod < osize) {
		assert(space->is_high_mod > 0);
		low_mod = space->is_low_mod;
		space->is_low_mod = osize;
		hi_mod = space->is_high_mod;
		space->is_high_mod = 0;
		is_write_unlock(space);
#if IPC_ENTRY_GROW_STATS
		rescan_count++;
		if (rescan_count > ipc_entry_grow_rescan_max)
			ipc_entry_grow_rescan_max = rescan_count;

		ipc_entry_grow_rescan++;
		ipc_entry_grow_rescan_entries += hi_mod - low_mod + 1;
		if (hi_mod - low_mod + 1 > ipc_entry_grow_rescan_entries_max)
			ipc_entry_grow_rescan_entries_max = hi_mod - low_mod + 1;
#endif
		goto rescan;
	}

	/* link new free entries onto the rest of the freelist */
	assert(table[free_index].ie_next == 0 &&
	       table[free_index].ie_object == IO_NULL);
	table[free_index].ie_next = osize;

	assert(space->is_table == otable);
	assert((space->is_table_next == its) ||
	    (target_size != ITS_SIZE_NONE));
	assert(space->is_table_size == osize);

	space->is_table = table;
	space->is_table_size = size;
	space->is_table_next = nits;
	space->is_table_free += size - osize;

	is_done_growing(space);
	is_write_unlock(space);

	thread_wakeup((event_t) space);

	/*
	 *	Now we need to free the old table.
	 */
	it_entries_free(oits, otable);
	is_write_lock(space);

	return KERN_SUCCESS;
}


/*
 *	Routine:	ipc_entry_name_mask
 *	Purpose:
 *		Ensure a mach port name has the default ipc entry
 *		generation bits set. This can be used to ensure that
 *		a name passed in by user space matches names generated
 *		by the kernel.
 *	Conditions:
 *		None.
 *	Returns:
 *		'name' input with default generation bits masked or added
 *		as appropriate.
 */
mach_port_name_t
ipc_entry_name_mask(mach_port_name_t name)
{
#ifndef NO_PORT_GEN
	static mach_port_name_t null_name = MACH_PORT_MAKE(0, IE_BITS_GEN_MASK + IE_BITS_GEN_ONE);
	return name | null_name;
#else
	static mach_port_name_t null_name = MACH_PORT_MAKE(0, ~(IE_BITS_GEN_MASK + IE_BITS_GEN_ONE));
	return name & ~null_name;
#endif
}
