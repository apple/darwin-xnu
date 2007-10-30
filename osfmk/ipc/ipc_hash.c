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
 *	File:	ipc/ipc_hash.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Entry hash table operations.
 */

#include <mach/boolean.h>
#include <mach/port.h>
#include <kern/lock.h>
#include <kern/kalloc.h>
#include <ipc/port.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_hash.h>
#include <ipc/ipc_init.h>

#include <mach_ipc_debug.h>

#if	MACH_IPC_DEBUG
#include <mach/kern_return.h>
#include <mach_debug/hash_info.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#endif	/* MACH_IPC_DEBUG */

/*
 * Forward declarations 
 */

/* Lookup (space, obj) in global hash table */
boolean_t ipc_hash_global_lookup(
	ipc_space_t		space,
	ipc_object_t		obj,
	mach_port_name_t	*namep,
	ipc_tree_entry_t	*entryp);

/* Insert an entry into the global reverse hash table */
void ipc_hash_global_insert(
	ipc_space_t		space,
	ipc_object_t		obj,
	mach_port_name_t	name,
	ipc_tree_entry_t	entry);

/* Delete an entry from the local reverse hash table */
void ipc_hash_local_delete(
	ipc_space_t		space,
	ipc_object_t		obj,
	mach_port_index_t	index,
	ipc_entry_t		entry);

/*
 *	Routine:	ipc_hash_lookup
 *	Purpose:
 *		Converts (space, obj) -> (name, entry).
 *		Returns TRUE if an entry was found.
 *	Conditions:
 *		The space must be locked (read or write) throughout.
 */

boolean_t
ipc_hash_lookup(
	ipc_space_t		space,
	ipc_object_t		obj,
	mach_port_name_t	*namep,
	ipc_entry_t		*entryp)
{
	boolean_t 	rv;

	rv = ipc_hash_local_lookup(space, obj, namep, entryp);
	if (!rv) {
		assert(!is_fast_space(space) || space->is_tree_hash == 0);
		if (space->is_tree_hash > 0)
			rv = ipc_hash_global_lookup(space, obj, namep,
				(ipc_tree_entry_t *) entryp);
	}
	return (rv);
}

/*
 *	Routine:	ipc_hash_insert
 *	Purpose:
 *		Inserts an entry into the appropriate reverse hash table,
 *		so that ipc_hash_lookup will find it.
 *	Conditions:
 *		The space must be write-locked.
 */

void
ipc_hash_insert(
	ipc_space_t		space,
	ipc_object_t		obj,
	mach_port_name_t	name,
	ipc_entry_t		entry)
{
	mach_port_index_t index;

	index = MACH_PORT_INDEX(name);
	if ((index < space->is_table_size) &&
	    (entry == &space->is_table[index]))
		ipc_hash_local_insert(space, obj, index, entry);
	else {
		assert(!is_fast_space(space));
		ipc_hash_global_insert(space, obj, name,
				       (ipc_tree_entry_t) entry);
	}
}

/*
 *	Routine:	ipc_hash_delete
 *	Purpose:
 *		Deletes an entry from the appropriate reverse hash table.
 *	Conditions:
 *		The space must be write-locked.
 */

void
ipc_hash_delete(
	ipc_space_t		space,
	ipc_object_t		obj,
	mach_port_name_t	name,
	ipc_entry_t		entry)
{
	mach_port_index_t index;

	index = MACH_PORT_INDEX(name);
	if ((index < space->is_table_size) &&
	    (entry == &space->is_table[index]))
		ipc_hash_local_delete(space, obj, index, entry);
	else {
		assert(!is_fast_space(space));
		ipc_hash_global_delete(space, obj, name,
				       (ipc_tree_entry_t) entry);
	}
}

/*
 *	The global reverse hash table holds splay tree entries.
 *	It is a simple open-chaining hash table with singly-linked buckets.
 *	Each bucket is locked separately, with an exclusive lock.
 *	Within each bucket, move-to-front is used.
 */

typedef natural_t ipc_hash_index_t;

ipc_hash_index_t ipc_hash_global_size;
ipc_hash_index_t ipc_hash_global_mask;

#define IH_GLOBAL_HASH(space, obj)					\
	(((((ipc_hash_index_t) ((vm_offset_t)space)) >> 4) +		\
	  (((ipc_hash_index_t) ((vm_offset_t)obj)) >> 6)) &		\
	 ipc_hash_global_mask)

typedef struct ipc_hash_global_bucket {
	decl_mutex_data(,	ihgb_lock_data)
	ipc_tree_entry_t	ihgb_head;
} *ipc_hash_global_bucket_t;

#define	IHGB_NULL	((ipc_hash_global_bucket_t) 0)

#define	ihgb_lock_init(ihgb)	mutex_init(&(ihgb)->ihgb_lock_data, 0)
#define	ihgb_lock(ihgb)		mutex_lock(&(ihgb)->ihgb_lock_data)
#define	ihgb_unlock(ihgb)	mutex_unlock(&(ihgb)->ihgb_lock_data)

ipc_hash_global_bucket_t ipc_hash_global_table;

/*
 *	Routine:	ipc_hash_global_lookup
 *	Purpose:
 *		Converts (space, obj) -> (name, entry).
 *		Looks in the global table, for splay tree entries.
 *		Returns TRUE if an entry was found.
 *	Conditions:
 *		The space must be locked (read or write) throughout.
 */

boolean_t
ipc_hash_global_lookup(
	ipc_space_t			space,
	ipc_object_t			obj,
	mach_port_name_t		*namep,
	ipc_tree_entry_t		*entryp)
{
	ipc_hash_global_bucket_t bucket;
	ipc_tree_entry_t this, *last;

	assert(space != IS_NULL);
	assert(obj != IO_NULL);

	assert(!is_fast_space(space));
	bucket = &ipc_hash_global_table[IH_GLOBAL_HASH(space, obj)];
	ihgb_lock(bucket);

	if ((this = bucket->ihgb_head) != ITE_NULL) {
		if ((this->ite_object == obj) &&
		    (this->ite_space == space)) {
			/* found it at front; no need to move */

			*namep = this->ite_name;
			*entryp = this;
		} else for (last = &this->ite_next;
			    (this = *last) != ITE_NULL;
			    last = &this->ite_next) {
			if ((this->ite_object == obj) &&
			    (this->ite_space == space)) {
				/* found it; move to front */

				*last = this->ite_next;
				this->ite_next = bucket->ihgb_head;
				bucket->ihgb_head = this;

				*namep = this->ite_name;
				*entryp = this;
				break;
			}
		}
	}

	ihgb_unlock(bucket);
	return this != ITE_NULL;
}

/*
 *	Routine:	ipc_hash_global_insert
 *	Purpose:
 *		Inserts an entry into the global reverse hash table.
 *	Conditions:
 *		The space must be write-locked.
 */

void
ipc_hash_global_insert(
	ipc_space_t				space,
	ipc_object_t				obj,
	__assert_only mach_port_name_t	name,
	ipc_tree_entry_t			entry)
{
	ipc_hash_global_bucket_t bucket;

	assert(!is_fast_space(space));
	assert(entry->ite_name == name);
	assert(space != IS_NULL);
	assert(entry->ite_space == space);
	assert(obj != IO_NULL);
	assert(entry->ite_object == obj);

	space->is_tree_hash++;
	assert(space->is_tree_hash <= space->is_tree_total);

	bucket = &ipc_hash_global_table[IH_GLOBAL_HASH(space, obj)];
	ihgb_lock(bucket);

	/* insert at front of bucket */

	entry->ite_next = bucket->ihgb_head;
	bucket->ihgb_head = entry;

	ihgb_unlock(bucket);
}

/*
 *	Routine:	ipc_hash_global_delete
 *	Purpose:
 *		Deletes an entry from the global reverse hash table.
 *	Conditions:
 *		The space must be write-locked.
 */

void
ipc_hash_global_delete(
	ipc_space_t				space,
	ipc_object_t				obj,
	__assert_only mach_port_name_t	name,
	ipc_tree_entry_t			entry)
{
	ipc_hash_global_bucket_t bucket;
	ipc_tree_entry_t this, *last;

	assert(!is_fast_space(space));
	assert(entry->ite_name == name);
	assert(space != IS_NULL);
	assert(entry->ite_space == space);
	assert(obj != IO_NULL);
	assert(entry->ite_object == obj);

	assert(space->is_tree_hash > 0);
	space->is_tree_hash--;

	bucket = &ipc_hash_global_table[IH_GLOBAL_HASH(space, obj)];
	ihgb_lock(bucket);

	for (last = &bucket->ihgb_head;
	     (this = *last) != ITE_NULL;
	     last = &this->ite_next) {
		if (this == entry) {
			/* found it; remove from bucket */

			*last = this->ite_next;
			break;
		}
	}
	assert(this != ITE_NULL);

	ihgb_unlock(bucket);
}

/*
 *	Each space has a local reverse hash table, which holds
 *	entries from the space's table.  In fact, the hash table
 *	just uses a field (ie_index) in the table itself.
 *
 *	The local hash table is an open-addressing hash table,
 *	which means that when a collision occurs, instead of
 *	throwing the entry into a bucket, the entry is rehashed
 *	to another position in the table.  In this case the rehash
 *	is very simple: linear probing (ie, just increment the position).
 *	This simple rehash makes deletions tractable (they're still a pain),
 *	but it means that collisions tend to build up into clumps.
 *
 *	Because at least one entry in the table (index 0) is always unused,
 *	there will always be room in the reverse hash table.  If a table
 *	with n slots gets completely full, the reverse hash table will
 *	have one giant clump of n-1 slots and one free slot somewhere.
 *	Because entries are only entered into the reverse table if they
 *	are pure send rights (not receive, send-once, port-set,
 *	or dead-name rights), and free entries of course aren't entered,
 *	I expect the reverse hash table won't get unreasonably full.
 *
 *	Ordered hash tables (Amble & Knuth, Computer Journal, v. 17, no. 2,
 *	pp. 135-142.) may be desirable here.  They can dramatically help
 *	unsuccessful lookups.  But unsuccessful lookups are almost always
 *	followed by insertions, and those slow down somewhat.  They
 *	also can help deletions somewhat.  Successful lookups aren't affected.
 *	So possibly a small win; probably nothing significant.
 */

#define	IH_LOCAL_HASH(obj, size)				\
		((((mach_port_index_t) (obj)) >> 6) % (size))

/*
 *	Routine:	ipc_hash_local_lookup
 *	Purpose:
 *		Converts (space, obj) -> (name, entry).
 *		Looks in the space's local table, for table entries.
 *		Returns TRUE if an entry was found.
 *	Conditions:
 *		The space must be locked (read or write) throughout.
 */

boolean_t
ipc_hash_local_lookup(
	ipc_space_t		space,
	ipc_object_t		obj,
	mach_port_name_t	*namep,
	ipc_entry_t		*entryp)
{
	ipc_entry_t table;
	ipc_entry_num_t size;
	mach_port_index_t hindex, index;

	assert(space != IS_NULL);
	assert(obj != IO_NULL);

	table = space->is_table;
	size = space->is_table_size;
	hindex = IH_LOCAL_HASH(obj, size);

	/*
	 *	Ideally, table[hindex].ie_index is the name we want.
	 *	However, must check ie_object to verify this,
	 *	because collisions can happen.  In case of a collision,
	 *	search farther along in the clump.
	 */

	while ((index = table[hindex].ie_index) != 0) {
		ipc_entry_t entry = &table[index];

		if (entry->ie_object == obj) {
			*entryp = entry;
			*namep = MACH_PORT_MAKE(index,
						IE_BITS_GEN(entry->ie_bits));
			return TRUE;
		}

		if (++hindex == size)
			hindex = 0;
	}

	return FALSE;
}

/*
 *	Routine:	ipc_hash_local_insert
 *	Purpose:
 *		Inserts an entry into the space's reverse hash table.
 *	Conditions:
 *		The space must be write-locked.
 */

void
ipc_hash_local_insert(
	ipc_space_t			space,
	ipc_object_t			obj,
	mach_port_index_t		index,
	__assert_only ipc_entry_t	entry)
{
	ipc_entry_t table;
	ipc_entry_num_t size;
	mach_port_index_t hindex;

	assert(index != 0);
	assert(space != IS_NULL);
	assert(obj != IO_NULL);

	table = space->is_table;
	size = space->is_table_size;
	hindex = IH_LOCAL_HASH(obj, size);

	assert(entry == &table[index]);
	assert(entry->ie_object == obj);

	/*
	 *	We want to insert at hindex, but there may be collisions.
	 *	If a collision occurs, search for the end of the clump
	 *	and insert there.
	 */

	while (table[hindex].ie_index != 0) {
		if (++hindex == size)
			hindex = 0;
	}

	table[hindex].ie_index = index;
}

/*
 *	Routine:	ipc_hash_local_delete
 *	Purpose:
 *		Deletes an entry from the space's reverse hash table.
 *	Conditions:
 *		The space must be write-locked.
 */

void
ipc_hash_local_delete(
	ipc_space_t			space,
	ipc_object_t			obj,
	mach_port_index_t		index,
	__assert_only ipc_entry_t	entry)
{
	ipc_entry_t table;
	ipc_entry_num_t size;
	mach_port_index_t hindex, dindex;

	assert(index != MACH_PORT_NULL);
	assert(space != IS_NULL);
	assert(obj != IO_NULL);

	table = space->is_table;
	size = space->is_table_size;
	hindex = IH_LOCAL_HASH(obj, size);

	assert(entry == &table[index]);
	assert(entry->ie_object == obj);

	/*
	 *	First check we have the right hindex for this index.
	 *	In case of collision, we have to search farther
	 *	along in this clump.
	 */

	while (table[hindex].ie_index != index) {
		if (++hindex == size)
			hindex = 0;
	}

	/*
	 *	Now we want to set table[hindex].ie_index = 0.
	 *	But if we aren't the last index in a clump,
	 *	this might cause problems for lookups of objects
	 *	farther along in the clump that are displaced
	 *	due to collisions.  Searches for them would fail
	 *	at hindex instead of succeeding.
	 *
	 *	So we must check the clump after hindex for objects
	 *	that are so displaced, and move one up to the new hole.
	 *
	 *		hindex - index of new hole in the clump
	 *		dindex - index we are checking for a displaced object
	 *
	 *	When we move a displaced object up into the hole,
	 *	it creates a new hole, and we have to repeat the process
	 *	until we get to the end of the clump.
	 */

	for (dindex = hindex; index != 0; hindex = dindex) {
		for (;;) {
			mach_port_index_t tindex;
			ipc_object_t tobj;

			if (++dindex == size)
				dindex = 0;
			assert(dindex != hindex);

			/* are we at the end of the clump? */

			index = table[dindex].ie_index;
			if (index == 0)
				break;

			/* is this a displaced object? */

			tobj = table[index].ie_object;
			assert(tobj != IO_NULL);
			tindex = IH_LOCAL_HASH(tobj, size);

			if ((dindex < hindex) ?
			    ((dindex < tindex) && (tindex <= hindex)) :
			    ((dindex < tindex) || (tindex <= hindex)))
				break;
		}

		table[hindex].ie_index = index;
	}
}

/*
 *	Routine:	ipc_hash_init
 *	Purpose:
 *		Initialize the reverse hash table implementation.
 */

void
ipc_hash_init(void)
{
	ipc_hash_index_t i;

	/* if not configured, initialize ipc_hash_global_size */

	if (ipc_hash_global_size == 0) {
		ipc_hash_global_size = ipc_tree_entry_max >> 8;
		if (ipc_hash_global_size < 32)
			ipc_hash_global_size = 32;
	}

	/* make sure it is a power of two */

	ipc_hash_global_mask = ipc_hash_global_size - 1;
	if ((ipc_hash_global_size & ipc_hash_global_mask) != 0) {
		natural_t bit;

		/* round up to closest power of two */

		for (bit = 1;; bit <<= 1) {
			ipc_hash_global_mask |= bit;
			ipc_hash_global_size = ipc_hash_global_mask + 1;

			if ((ipc_hash_global_size & ipc_hash_global_mask) == 0)
				break;
		}
	}

	/* allocate ipc_hash_global_table */

	ipc_hash_global_table = (ipc_hash_global_bucket_t)
		kalloc((vm_size_t) (ipc_hash_global_size *
				    sizeof(struct ipc_hash_global_bucket)));
	assert(ipc_hash_global_table != IHGB_NULL);

	/* and initialize it */

	for (i = 0; i < ipc_hash_global_size; i++) {
		ipc_hash_global_bucket_t bucket;

		bucket = &ipc_hash_global_table[i];
		ihgb_lock_init(bucket);
		bucket->ihgb_head = ITE_NULL;
	}
}

#if	MACH_IPC_DEBUG

/*
 *	Routine:	ipc_hash_size
 *	Purpose:
 *		Return the size of the global reverse hash table.
 */
natural_t
ipc_hash_size(void)
{
	return ipc_hash_global_size;
}

/*
 *	Routine:	ipc_hash_info
 *	Purpose:
 *		Return information about the global reverse hash table.
 *		Fills the buffer with as much information as possible
 *		and returns the desired size of the buffer.
 *	Conditions:
 *		Nothing locked.  The caller should provide
 *		possibly-pageable memory.
 */


ipc_hash_index_t
ipc_hash_info(
	hash_info_bucket_t	*info,
	natural_t		count)
{
	ipc_hash_index_t i;

	if (ipc_hash_global_size < count)
		count = ipc_hash_global_size;

	for (i = 0; i < count; i++) {
		ipc_hash_global_bucket_t bucket = &ipc_hash_global_table[i];
		unsigned int bucket_count = 0;
		ipc_tree_entry_t entry;

		ihgb_lock(bucket);
		for (entry = bucket->ihgb_head;
		     entry != ITE_NULL;
		     entry = entry->ite_next)
			bucket_count++;
		ihgb_unlock(bucket);

		/* don't touch pageable memory while holding locks */
		info[i].hib_count = bucket_count;
	}

	return ipc_hash_global_size;
}

#endif	/* MACH_IPC_DEBUG */
