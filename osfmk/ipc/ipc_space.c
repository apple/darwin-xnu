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
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
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

#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/port.h>
#include <kern/assert.h>
#include <kern/sched_prim.h>
#include <kern/zalloc.h>
#include <ipc/port.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_hash.h>
#include <ipc/ipc_table.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_right.h>
#include <prng/random.h>
#include <string.h>

/* Remove this in the future so port names are less predictable. */
#define CONFIG_SEMI_RANDOM_ENTRIES
#ifdef CONFIG_SEMI_RANDOM_ENTRIES
#define NUM_SEQ_ENTRIES 8
#endif

zone_t ipc_space_zone;
ipc_space_t ipc_space_kernel;
ipc_space_t ipc_space_reply;

/*
 *	Routine:	ipc_space_reference
 *	Routine:	ipc_space_release
 *	Purpose:
 *		Function versions of the IPC space inline reference.
 */

void
ipc_space_reference(
	ipc_space_t	space)
{
	is_reference(space);
}

void
ipc_space_release(
	ipc_space_t	space)
{
	is_release(space);
}

/* 	Routine:		ipc_space_get_rollpoint
 * 	Purpose:
 * 		Generate a new gencount rollover point from a space's entropy pool
 */
ipc_entry_bits_t
ipc_space_get_rollpoint(
	ipc_space_t	space)
{
	return random_bool_gen_bits(
			&space->bool_gen,
			&space->is_entropy[0],
			IS_ENTROPY_CNT,
			IE_BITS_ROLL_BITS);
}

/*
 *	Routine:	ipc_entry_rand_freelist
 *	Purpose:
 *		Pseudo-randomly permute the order of entries in an IPC space
 *	Arguments:
 *		space:	the ipc space to initialize.
 *		table:	the corresponding ipc table to initialize.
 *		bottom:	the start of the range to initialize (inclusive).
 *		top:	the end of the range to initialize (noninclusive).
 */
void
ipc_space_rand_freelist(
	ipc_space_t		space,
	ipc_entry_t		table,
	mach_port_index_t	bottom,
	mach_port_index_t	top)
{
	int at_start = (bottom == 0);
#ifdef CONFIG_SEMI_RANDOM_ENTRIES
	/*
	 * Only make sequential entries at the start of the table, and not when
	 * we're growing the space.
	 */
	ipc_entry_num_t total = 0;
#endif

	/* First entry in the free list is always free, and is the start of the free list. */
	mach_port_index_t curr = bottom;
	bottom++;
	top--;

	/*
	 *	Initialize the free list in the table.
	 *	Add the entries in pseudo-random order and randomly set the generation
	 *	number, in order to frustrate attacks involving port name reuse.
	 */
	while (bottom <= top) {
		ipc_entry_t entry = &table[curr];
		int which;
#ifdef CONFIG_SEMI_RANDOM_ENTRIES
		/*
		 * XXX: This is a horrible hack to make sure that randomizing the port
		 * doesn't break programs that might have (sad) hard-coded values for
		 * certain port names.
		 */
		if (at_start && total++ < NUM_SEQ_ENTRIES)
			which = 0;
		else
#endif
			which = random_bool_gen_bits(
						&space->bool_gen,
						&space->is_entropy[0],
						IS_ENTROPY_CNT,
						1);

		mach_port_index_t next;
		if (which) {
			next = top;
			top--;
		} else {
			next = bottom;
			bottom++;
		}

		/*
		 * The entry's gencount will roll over on its first allocation, at which
		 * point a random rollover will be set for the entry.
		 */
		entry->ie_bits = IE_BITS_GEN_MASK;
		entry->ie_next   = next;
		entry->ie_object = IO_NULL;
		entry->ie_index  = 0;
		curr = next;
	}
	table[curr].ie_next   = 0;
	table[curr].ie_object = IO_NULL;
	table[curr].ie_index  = 0;
	table[curr].ie_bits   = IE_BITS_GEN_MASK;

	/* The freelist head should always have generation number set to 0 */
	if (at_start) {
		table[0].ie_bits = 0;
	}
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

	/* Set to 0 so entropy pool refills */
	memset((void *) space->is_entropy, 0, sizeof(space->is_entropy));

	random_bool_init(&space->bool_gen);
	ipc_space_rand_freelist(space, table, 0, new_size);

	is_lock_init(space);
	space->is_bits = 2; /* 2 refs, active, not growing */
	space->is_table_size = new_size;
	space->is_table_free = new_size - 1;
	space->is_table = table;
	space->is_table_next = initial+1;
	space->is_task = NULL;
	space->is_low_mod = new_size;
	space->is_high_mod = 0;
	space->is_node_id = HOST_LOCAL_NODE; /* HOST_LOCAL_NODE, except proxy spaces */

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

	is_lock_init(space);

	space->is_bits       = IS_INACTIVE | 1; /* 1 ref, not active, not growing */
	space->is_table      = IE_NULL;
	space->is_task       = TASK_NULL;
	space->is_table_next = 0;
	space->is_low_mod    = 0;
	space->is_high_mod   = 0;
	space->is_node_id = HOST_LOCAL_NODE; /* HOST_LOCAL_NODE, except proxy spaces */

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
	ipc_entry_t table;
	ipc_entry_num_t size;
	mach_port_index_t index;

	/*
	 *	If somebody is trying to grow the table,
	 *	we must wait until they finish and figure
	 *	out the space died.
	 */
 retry:
	is_write_lock(space);
	while (is_growing(space))
		is_write_sleep(space);

	if (!is_active(space)) {
		is_write_unlock(space);
		return;
	}

	/*
	 *	Now we can futz with it	since we have the write lock.
	 */

	table = space->is_table;
	size = space->is_table_size;

	for (index = 0; index < size; index++) {
		ipc_entry_t entry = &table[index];
		mach_port_type_t type;

		type = IE_BITS_TYPE(entry->ie_bits);
		if (type != MACH_PORT_TYPE_NONE) {
			mach_port_name_t name =	MACH_PORT_MAKE(index,
						IE_BITS_GEN(entry->ie_bits));
			ipc_right_destroy(space, name, entry, FALSE, 0); /* unlocks space */
			goto retry;
		}
	}

        /*
	 * JMM - Now the table is cleaned out.  We don't bother shrinking the
	 * size of the table at this point, but we probably should if it is
	 * really large.
	 */
	
	is_write_unlock(space);
}


/*
 *	Routine:	ipc_space_terminate
 *	Purpose:
 *		Marks the space as dead and cleans up the entries.
 *		Does nothing if the space is already dead.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_space_terminate(
	ipc_space_t	space)
{
	ipc_entry_t table;
	ipc_entry_num_t size;
	mach_port_index_t index;

	assert(space != IS_NULL);

	is_write_lock(space);
	if (!is_active(space)) {
		is_write_unlock(space);
		return;
	}
	is_mark_inactive(space);

	/*
	 *	If somebody is trying to grow the table,
	 *	we must wait until they finish and figure
	 *	out the space died.
	 */
	while (is_growing(space))
		is_write_sleep(space);

	is_write_unlock(space);


	/*
	 *	Now we can futz with it	unlocked.
	 */

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
			ipc_right_terminate(space, name, entry);
		}
	}

	it_entries_free(space->is_table_next-1, table);
	space->is_table_size = 0;
	space->is_table_free = 0;

	/*
	 *	Because the space is now dead,
	 *	we must release the "active" reference for it.
	 *	Our caller still has his reference.
	 */
	is_release(space);
}


