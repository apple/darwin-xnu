/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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
 *	File:	ipc/ipc_space.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Functions to manipulate IPC capability spaces.
 */

#include <mach_kdb.h>

#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/port.h>
#include <kern/assert.h>
#include <kern/sched_prim.h>
#include <kern/zalloc.h>
#include <ipc/port.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_splay.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_hash.h>
#include <ipc/ipc_table.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_right.h>
#include <string.h>

zone_t ipc_space_zone;
ipc_space_t ipc_space_kernel;
ipc_space_t ipc_space_reply;
#if	MACH_KDB
ipc_space_t default_pager_space;
#endif	/* MACH_KDB */

/*
 *	Routine:	ipc_space_reference
 *	Routine:	ipc_space_release
 *	Purpose:
 *		Function versions of the IPC space macros.
 *		The "is_" cover macros can be defined to use the
 *		macros or the functions, as desired.
 */

void
ipc_space_reference(
	ipc_space_t	space)
{
	ipc_space_reference_macro(space);
}

void
ipc_space_release(
	ipc_space_t	space)
{
	ipc_space_release_macro(space);
}

/*
 *	Routine:	ipc_space_create
 *	Purpose:
 *		Creates a new IPC space.
 *
 *		The new space has two references, one for the caller
 *		and one because it is active.
 *	Conditions:
 *		Nothing locked.  Allocates memory.
 *	Returns:
 *		KERN_SUCCESS		Created a space.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
ipc_space_create(
	ipc_table_size_t	initial,
	ipc_space_t		*spacep)
{
	ipc_space_t space;
	ipc_entry_t table;
	ipc_entry_num_t new_size;
	mach_port_index_t index;

	space = is_alloc();
	if (space == IS_NULL)
		return KERN_RESOURCE_SHORTAGE;

	table = it_entries_alloc(initial);
	if (table == IE_NULL) {
		is_free(space);
		return KERN_RESOURCE_SHORTAGE;
	}

	new_size = initial->its_size;
	memset((void *) table, 0, new_size * sizeof(struct ipc_entry));

	/*
	 *	Initialize the free list in the table.
	 *	Add the entries in reverse order, and
	 *	set the generation number to -1, so that
	 *	initial allocations produce "natural" names.
	 */
	for (index = 0; index < new_size; index++) {
		ipc_entry_t entry = &table[index];

		entry->ie_bits = IE_BITS_GEN_MASK;
		entry->ie_next = index+1;
	}
	table[new_size-1].ie_next = 0;

	is_ref_lock_init(space);
	space->is_references = 2;

	is_lock_init(space);
	space->is_active = TRUE;
	space->is_growing = FALSE;
	space->is_table = table;
	space->is_table_size = new_size;
	space->is_table_next = initial+1;

	ipc_splay_tree_init(&space->is_tree);
	space->is_tree_total = 0;
	space->is_tree_small = 0;
	space->is_tree_hash = 0;

	*spacep = space;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_space_create_special
 *	Purpose:
 *		Create a special space.  A special space
 *		doesn't hold rights in the normal way.
 *		Instead it is place-holder for holding
 *		disembodied (naked) receive rights.
 *		See ipc_port_alloc_special/ipc_port_dealloc_special.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Created a space.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
ipc_space_create_special(
	ipc_space_t	*spacep)
{
	ipc_space_t space;

	space = is_alloc();
	if (space == IS_NULL)
		return KERN_RESOURCE_SHORTAGE;

	is_ref_lock_init(space);
	space->is_references = 1;

	is_lock_init(space);
	space->is_active = FALSE;

	*spacep = space;
	return KERN_SUCCESS;
}

/*
 * ipc_space_clean - remove all port references from an ipc space.
 *
 * In order to follow the traditional semantic, ipc_space_destroy
 * will not destroy the entire port table of a shared space.  Instead
 * it will simply clear its own sub-space.
 */
void
ipc_space_clean(
	ipc_space_t space)
{
	ipc_tree_entry_t tentry;
	ipc_entry_t table;
	ipc_entry_num_t size;
	mach_port_index_t index;

	/*
	 *	If somebody is trying to grow the table,
	 *	we must wait until they finish and figure
	 *	out the space died.
	 */
	is_write_lock(space);
	while (space->is_growing)
		is_write_sleep(space);

	/*
	 *	Now we can futz with it	since we have the write lock.
	 */
#if	MACH_KDB
	if (space == default_pager_space)
		default_pager_space = IS_NULL;
#endif	/* MACH_KDB */

	table = space->is_table;
	size = space->is_table_size;

	for (index = 0; index < size; index++) {
		ipc_entry_t entry = &table[index];
		mach_port_type_t type;

		type = IE_BITS_TYPE(entry->ie_bits);
		if (type != MACH_PORT_TYPE_NONE) {
			mach_port_name_t name =	MACH_PORT_MAKE(index,
						IE_BITS_GEN(entry->ie_bits));
			ipc_right_destroy(space, name, entry);
		}
	}

	/*
	 * JMM - Now the table is cleaned out.  We don't bother shrinking the
	 * size of the table at this point, but we probably should if it is
	 * really large.  Lets just clean up the splay tree.
	 */
 start_splay:
	for (tentry = ipc_splay_traverse_start(&space->is_tree);
	     tentry != ITE_NULL;
	     tentry = ipc_splay_traverse_next(&space->is_tree, TRUE)) {
		int i;
		mach_port_type_t type;
		mach_port_name_t name = tentry->ite_name;

		type = IE_BITS_TYPE(tentry->ite_bits);
		/*
		 * If it is a real right, then destroy it.  This will have the
		 * side effect of removing it from the splay, so start over.
		 */
		if(type != MACH_PORT_TYPE_NONE) {
			ipc_splay_traverse_finish(&space->is_tree);
			ipc_right_destroy(space, name, &tentry->ite_entry);
			goto start_splay;
		}
	}
	ipc_splay_traverse_finish(&space->is_tree);
	is_write_unlock(space);
}


/*
 *	Routine:	ipc_space_destroy
 *	Purpose:
 *		Marks the space as dead and cleans up the entries.
 *		Does nothing if the space is already dead.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_space_destroy(
	ipc_space_t	space)
{
	boolean_t active;
	ipc_tree_entry_t tentry;
	ipc_entry_t table;
	ipc_entry_num_t size;
	mach_port_index_t index;

	assert(space != IS_NULL);

	is_write_lock(space);
	active = space->is_active;
	space->is_active = FALSE;
	is_write_unlock(space);

	if (!active)
		return;


	/*
	 *	If somebody is trying to grow the table,
	 *	we must wait until they finish and figure
	 *	out the space died.
	 */
	is_read_lock(space);
	while (space->is_growing)
		is_read_sleep(space);

	is_read_unlock(space);
	/*
	 *	Now we can futz with it	unlocked.
	 */
#if	MACH_KDB
	if (space == default_pager_space)
		default_pager_space = IS_NULL;
#endif	/* MACH_KDB */

	table = space->is_table;
	size = space->is_table_size;

	for (index = 0; index < size; index++) {
		ipc_entry_t entry = &table[index];
		mach_port_type_t type;

		type = IE_BITS_TYPE(entry->ie_bits);
		if (type != MACH_PORT_TYPE_NONE) {
			mach_port_name_t name;

			name = MACH_PORT_MAKE(index,
					      IE_BITS_GEN(entry->ie_bits));
			ipc_right_clean(space, name, entry);
		}
	}

	it_entries_free(space->is_table_next-1, table);
	space->is_table_size = 0;

	for (tentry = ipc_splay_traverse_start(&space->is_tree);
	     tentry != ITE_NULL;
	     tentry = ipc_splay_traverse_next(&space->is_tree, TRUE)) {
		mach_port_type_t type;
		mach_port_name_t name = tentry->ite_name;

		type = IE_BITS_TYPE(tentry->ite_bits);
		assert(type != MACH_PORT_TYPE_NONE);

		ipc_right_clean(space, name, &tentry->ite_entry);

		if(type == MACH_PORT_TYPE_SEND)
			ipc_hash_global_delete(space, tentry->ite_object,
					       name, tentry);
	}
	ipc_splay_traverse_finish(&space->is_tree);

	/*
	 *	Because the space is now dead,
	 *	we must release the "active" reference for it.
	 *	Our caller still has his reference.
	 */
	is_release(space);
}
