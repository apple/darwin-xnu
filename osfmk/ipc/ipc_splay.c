/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:28  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:26:16  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.6.1  1994/09/23  02:11:47  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:30:41  ezf]
 *
 * Revision 1.1.2.3  1993/07/22  16:17:25  rod
 * 	Add ANSI prototypes.  CR #9523.
 * 	[1993/07/22  13:33:20  rod]
 * 
 * Revision 1.1.2.2  1993/06/02  23:33:40  jeffc
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:11:07  jeffc]
 * 
 * Revision 1.1  1992/09/30  02:08:11  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.5  91/10/09  16:10:41  af
 * 	 Revision 2.4.2.1  91/09/16  10:16:00  rpd
 * 	 	Added MACH_PORT_SMALLEST, MACH_PORT_LARGEST definitions to reduce lint.
 * 	 	[91/09/02            rpd]
 * 
 * Revision 2.4.2.1  91/09/16  10:16:00  rpd
 * 	Added MACH_PORT_SMALLEST, MACH_PORT_LARGEST definitions to reduce lint.
 * 	[91/09/02            rpd]
 * 
 * Revision 2.4  91/05/14  16:37:08  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/02/05  17:23:52  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  15:51:43  mrt]
 * 
 * Revision 2.2  90/06/02  14:51:49  rpd
 * 	Created for new IPC.
 * 	[90/03/26  21:03:46  rpd]
 * 
 */
/* CMU_ENDHIST */
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
 *	File:	ipc/ipc_splay.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Primitive splay tree operations.
 */

#include <mach/port.h>
#include <kern/assert.h>
#include <kern/macro_help.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_splay.h>

/*
 *	Splay trees are self-adjusting binary search trees.
 *	They have the following attractive properties:
 *		1) Space efficient; only two pointers per entry.
 *		2) Robust performance; amortized O(log n) per operation.
 *		3) Recursion not needed.
 *	This makes them a good fall-back data structure for those
 *	entries that don't fit into the lookup table.
 *
 *	The paper by Sleator and Tarjan, JACM v. 32, no. 3, pp. 652-686,
 *	describes the splaying operation.  ipc_splay_prim_lookup
 *	and ipc_splay_prim_assemble implement the top-down splay
 *	described on p. 669.
 *
 *	The tree is stored in an unassembled form.  If ist_root is null,
 *	then the tree has no entries.  Otherwise, ist_name records
 *	the value used for the last lookup.  ist_root points to the
 *	middle tree obtained from the top-down splay.  ist_ltree and
 *	ist_rtree point to left and right subtrees, whose entries
 *	are all smaller (larger) than those in the middle tree.
 *	ist_ltreep and ist_rtreep are pointers to fields in the
 *	left and right subtrees.  ist_ltreep points to the rchild field
 *	of the largest entry in ltree, and ist_rtreep points to the
 *	lchild field of the smallest entry in rtree.  The pointed-to
 *	fields aren't initialized.  If the left (right) subtree is null,
 *	then ist_ltreep (ist_rtreep) points to the ist_ltree (ist_rtree)
 *	field in the splay structure itself.
 *
 *	The primary advantage of the unassembled form is that repeated
 *	unsuccessful lookups are efficient.  In particular, an unsuccessful
 *	lookup followed by an insert only requires one splaying operation.
 *
 *	The traversal algorithm works via pointer inversion.
 *	When descending down the tree, child pointers are reversed
 *	to point back to the parent entry.  When ascending,
 *	the pointers are restored to their original value.
 *
 *	The biggest potential problem with the splay tree implementation
 *	is that the operations, even lookup, require an exclusive lock.
 *	If IPC spaces are protected with exclusive locks, then
 *	the splay tree doesn't require its own lock, and ist_lock/ist_unlock
 *	needn't do anything.  If IPC spaces are protected with read/write
 *	locks then ist_lock/ist_unlock should provide exclusive access.
 *
 *	If it becomes important to let lookups run in parallel,
 *	or if the restructuring makes lookups too expensive, then
 *	there is hope.  Use a read/write lock on the splay tree.
 *	Keep track of the number of entries in the tree.  When doing
 *	a lookup, first try a non-restructuring lookup with a read lock held,
 *	with a bound (based on log of size of the tree) on the number of
 *	entries to traverse.  If the lookup runs up against the bound,
 *	then take a write lock and do a reorganizing lookup.
 *	This way, if lookups only access roughly balanced parts
 *	of the tree, then lookups run in parallel and do no restructuring.
 *
 *	The traversal algorithm currently requires an exclusive lock.
 *	If that is a problem, the tree could be changed from an lchild/rchild
 *	representation to a leftmost child/right sibling representation.
 *	In conjunction with non-restructing lookups, this would let
 *	lookups and traversals all run in parallel.  But this representation
 *	is more complicated and would slow down the operations.
 */

/*
 *	Boundary values to hand to ipc_splay_prim_lookup:
 */

#define	MACH_PORT_SMALLEST	((mach_port_name_t) 0)
#define MACH_PORT_LARGEST	((mach_port_name_t) ~0)

/*
 *	Routine:	ipc_splay_prim_lookup
 *	Purpose:
 *		Searches for the node labeled name in the splay tree.
 *		Returns three nodes (treep, ltreep, rtreep) and
 *		two pointers to nodes (ltreepp, rtreepp).
 *
 *		ipc_splay_prim_lookup splits the supplied tree into
 *		three subtrees, left, middle, and right, returned
 *		in ltreep, treep, and rtreep.
 *
 *		If name is present in the tree, then it is at
 *		the root of the middle tree.  Otherwise, the root
 *		of the middle tree is the last node traversed.
 *
 *		ipc_splay_prim_lookup returns a pointer into
 *		the left subtree, to the rchild field of its
 *		largest node, in ltreepp.  It returns a pointer
 *		into the right subtree, to the lchild field of its
 *		smallest node, in rtreepp.
 */

static void
ipc_splay_prim_lookup(
	mach_port_name_t	name,
	ipc_tree_entry_t	tree,
	ipc_tree_entry_t	*treep,
	ipc_tree_entry_t	*ltreep,
	ipc_tree_entry_t	**ltreepp,
	ipc_tree_entry_t	*rtreep,
	ipc_tree_entry_t	**rtreepp)
{
	mach_port_name_t tname;			/* temp name */
	ipc_tree_entry_t lchild, rchild;	/* temp child pointers */

	assert(tree != ITE_NULL);

#define	link_left					\
MACRO_BEGIN						\
	*ltreep = tree;					\
	ltreep = &tree->ite_rchild;			\
	tree = *ltreep;					\
MACRO_END

#define	link_right					\
MACRO_BEGIN						\
	*rtreep = tree;					\
	rtreep = &tree->ite_lchild;			\
	tree = *rtreep;					\
MACRO_END

#define rotate_left					\
MACRO_BEGIN						\
	ipc_tree_entry_t temp = tree;			\
							\
	tree = temp->ite_rchild;			\
	temp->ite_rchild = tree->ite_lchild;		\
	tree->ite_lchild = temp;			\
MACRO_END

#define rotate_right					\
MACRO_BEGIN						\
	ipc_tree_entry_t temp = tree;			\
							\
	tree = temp->ite_lchild;			\
	temp->ite_lchild = tree->ite_rchild;		\
	tree->ite_rchild = temp;			\
MACRO_END

	while (name != (tname = tree->ite_name)) {
		if (name < tname) {
			/* descend to left */

			lchild = tree->ite_lchild;
			if (lchild == ITE_NULL)
				break;
			tname = lchild->ite_name;

			if ((name < tname) &&
			    (lchild->ite_lchild != ITE_NULL))
				rotate_right;
			link_right;
			if ((name > tname) &&
			    (lchild->ite_rchild != ITE_NULL))
				link_left;
		} else {
			/* descend to right */

			rchild = tree->ite_rchild;
			if (rchild == ITE_NULL)
				break;
			tname = rchild->ite_name;

			if ((name > tname) &&
			    (rchild->ite_rchild != ITE_NULL))
				rotate_left;
			link_left;
			if ((name < tname) &&
			    (rchild->ite_lchild != ITE_NULL))
				link_right;
		}

		assert(tree != ITE_NULL);
	}

	*treep = tree;
	*ltreepp = ltreep;
	*rtreepp = rtreep;

#undef	link_left
#undef	link_right
#undef	rotate_left
#undef	rotate_right
}

/*
 *	Routine:	ipc_splay_prim_assemble
 *	Purpose:
 *		Assembles the results of ipc_splay_prim_lookup
 *		into a splay tree with the found node at the root.
 *
 *		ltree and rtree are by-reference so storing
 *		through ltreep and rtreep can change them.
 */

static void
ipc_splay_prim_assemble(
	ipc_tree_entry_t	tree,
	ipc_tree_entry_t	*ltree,
	ipc_tree_entry_t	*ltreep,
	ipc_tree_entry_t	*rtree,
	ipc_tree_entry_t	*rtreep)
{
	assert(tree != ITE_NULL);

	*ltreep = tree->ite_lchild;
	*rtreep = tree->ite_rchild;

	tree->ite_lchild = *ltree;
	tree->ite_rchild = *rtree;
}

/*
 *	Routine:	ipc_splay_tree_init
 *	Purpose:
 *		Initialize a raw splay tree for use.
 */

void
ipc_splay_tree_init(
	ipc_splay_tree_t	splay)
{
	splay->ist_root = ITE_NULL;
}

/*
 *	Routine:	ipc_splay_tree_pick
 *	Purpose:
 *		Picks and returns a random entry in a splay tree.
 *		Returns FALSE if the splay tree is empty.
 */

boolean_t
ipc_splay_tree_pick(
	ipc_splay_tree_t	splay,
	mach_port_name_t	*namep,
	ipc_tree_entry_t	*entryp)
{
	ipc_tree_entry_t root;

	ist_lock(splay);

	root = splay->ist_root;
	if (root != ITE_NULL) {
		*namep = root->ite_name;
		*entryp = root;
	}

	ist_unlock(splay);

	return root != ITE_NULL;
}

/*
 *	Routine:	ipc_splay_tree_lookup
 *	Purpose:
 *		Finds an entry in a splay tree.
 *		Returns ITE_NULL if not found.
 */

ipc_tree_entry_t
ipc_splay_tree_lookup(
	ipc_splay_tree_t	splay,
	mach_port_name_t	name)
{
	ipc_tree_entry_t root;

	ist_lock(splay);

	root = splay->ist_root;
	if (root != ITE_NULL) {
		if (splay->ist_name != name) {
			ipc_splay_prim_assemble(root,
				&splay->ist_ltree, splay->ist_ltreep,
				&splay->ist_rtree, splay->ist_rtreep);
			ipc_splay_prim_lookup(name, root, &root,
				&splay->ist_ltree, &splay->ist_ltreep,
				&splay->ist_rtree, &splay->ist_rtreep);
			splay->ist_name = name;
			splay->ist_root = root;
		}

		if (name != root->ite_name)
			root = ITE_NULL;
	}

	ist_unlock(splay);

	return root;
}

/*
 *	Routine:	ipc_splay_tree_insert
 *	Purpose:
 *		Inserts a new entry into a splay tree.
 *		The caller supplies a new entry.
 *		The name can't already be present in the tree.
 */

void
ipc_splay_tree_insert(
	ipc_splay_tree_t	splay,
	mach_port_name_t	name,
	ipc_tree_entry_t	entry)
{
	ipc_tree_entry_t root;

	assert(entry != ITE_NULL);

	ist_lock(splay);

	root = splay->ist_root;
	if (root == ITE_NULL) {
		entry->ite_lchild = ITE_NULL;
		entry->ite_rchild = ITE_NULL;
	} else {
		if (splay->ist_name != name) {
			ipc_splay_prim_assemble(root,
				&splay->ist_ltree, splay->ist_ltreep,
				&splay->ist_rtree, splay->ist_rtreep);
			ipc_splay_prim_lookup(name, root, &root,
				&splay->ist_ltree, &splay->ist_ltreep,
				&splay->ist_rtree, &splay->ist_rtreep);
		}

		assert(root->ite_name != name);

		if (name < root->ite_name) {
			assert(root->ite_lchild == ITE_NULL);

			*splay->ist_ltreep = ITE_NULL;
			*splay->ist_rtreep = root;
		} else {
			assert(root->ite_rchild == ITE_NULL);

			*splay->ist_ltreep = root;
			*splay->ist_rtreep = ITE_NULL;
		}

		entry->ite_lchild = splay->ist_ltree;
		entry->ite_rchild = splay->ist_rtree;
	}

	entry->ite_name = name;
	splay->ist_root = entry;
	splay->ist_name = name;
	splay->ist_ltreep = &splay->ist_ltree;
	splay->ist_rtreep = &splay->ist_rtree;

	ist_unlock(splay);
}

/*
 *	Routine:	ipc_splay_tree_delete
 *	Purpose:
 *		Deletes an entry from a splay tree.
 *		The name must be present in the tree.
 *		Frees the entry.
 *
 *		The "entry" argument isn't currently used.
 *		Other implementations might want it, though.
 */

void
ipc_splay_tree_delete(
	ipc_splay_tree_t	splay,
	mach_port_name_t	name,
	ipc_tree_entry_t	entry)
{
	ipc_tree_entry_t root, saved;

	ist_lock(splay);

	root = splay->ist_root;
	assert(root != ITE_NULL);

	if (splay->ist_name != name) {
		ipc_splay_prim_assemble(root,
			&splay->ist_ltree, splay->ist_ltreep,
			&splay->ist_rtree, splay->ist_rtreep);
		ipc_splay_prim_lookup(name, root, &root,
			&splay->ist_ltree, &splay->ist_ltreep,
			&splay->ist_rtree, &splay->ist_rtreep);
	}

	assert(root->ite_name == name);
	assert(root == entry);

	*splay->ist_ltreep = root->ite_lchild;
	*splay->ist_rtreep = root->ite_rchild;
	ite_free(root);

	root = splay->ist_ltree;
	saved = splay->ist_rtree;

	if (root == ITE_NULL)
		root = saved;
	else if (saved != ITE_NULL) {
		/*
		 *	Find the largest node in the left subtree, and splay it
		 *	to the root.  Then add the saved right subtree.
		 */

		ipc_splay_prim_lookup(MACH_PORT_LARGEST, root, &root,
			&splay->ist_ltree, &splay->ist_ltreep,
			&splay->ist_rtree, &splay->ist_rtreep);
		ipc_splay_prim_assemble(root,
			&splay->ist_ltree, splay->ist_ltreep,
			&splay->ist_rtree, splay->ist_rtreep);

		assert(root->ite_rchild == ITE_NULL);
		root->ite_rchild = saved;
	}

	splay->ist_root = root;
	if (root != ITE_NULL) {
		splay->ist_name = root->ite_name;
		splay->ist_ltreep = &splay->ist_ltree;
		splay->ist_rtreep = &splay->ist_rtree;
	}

	ist_unlock(splay);
}

/*
 *	Routine:	ipc_splay_tree_split
 *	Purpose:
 *		Split a splay tree.  Puts all entries smaller than "name"
 *		into a new tree, "small".
 *
 *		Doesn't do locking on "small", because nobody else
 *		should be fiddling with the uninitialized tree.
 */

void
ipc_splay_tree_split(
	ipc_splay_tree_t	splay,
	mach_port_name_t	name,
	ipc_splay_tree_t	small)
{
	ipc_tree_entry_t root;

	ipc_splay_tree_init(small);

	ist_lock(splay);

	root = splay->ist_root;
	if (root != ITE_NULL) {
		/* lookup name, to get it (or last traversed) to the top */

		if (splay->ist_name != name) {
			ipc_splay_prim_assemble(root,
				&splay->ist_ltree, splay->ist_ltreep,
				&splay->ist_rtree, splay->ist_rtreep);
			ipc_splay_prim_lookup(name, root, &root,
				&splay->ist_ltree, &splay->ist_ltreep,
				&splay->ist_rtree, &splay->ist_rtreep);
		}

		if (root->ite_name < name) {
			/* root goes into small */

			*splay->ist_ltreep = root->ite_lchild;
			*splay->ist_rtreep = ITE_NULL;
			root->ite_lchild = splay->ist_ltree;
			assert(root->ite_rchild == ITE_NULL);

			small->ist_root = root;
			small->ist_name = root->ite_name;
			small->ist_ltreep = &small->ist_ltree;
			small->ist_rtreep = &small->ist_rtree;

			/* rtree goes into splay */

			root = splay->ist_rtree;
			splay->ist_root = root;
			if (root != ITE_NULL) {
				splay->ist_name = root->ite_name;
				splay->ist_ltreep = &splay->ist_ltree;
				splay->ist_rtreep = &splay->ist_rtree;
			}
		} else {
			/* root stays in splay */

			*splay->ist_ltreep = root->ite_lchild;
			root->ite_lchild = ITE_NULL;

			splay->ist_root = root;
			splay->ist_name = name;
			splay->ist_ltreep = &splay->ist_ltree;

			/* ltree goes into small */

			root = splay->ist_ltree;
			small->ist_root = root;
			if (root != ITE_NULL) {
				small->ist_name = root->ite_name;
				small->ist_ltreep = &small->ist_ltree;
				small->ist_rtreep = &small->ist_rtree;
			}
		}		
	}

	ist_unlock(splay);
}

/*
 *	Routine:	ipc_splay_tree_join
 *	Purpose:
 *		Joins two splay trees.  Merges the entries in "small",
 *		which must all be smaller than the entries in "splay",
 *		into "splay".
 */

void
ipc_splay_tree_join(
	ipc_splay_tree_t	splay,
	ipc_splay_tree_t	small)
{
	ipc_tree_entry_t sroot;

	/* pull entries out of small */

	ist_lock(small);

	sroot = small->ist_root;
	if (sroot != ITE_NULL) {
		ipc_splay_prim_assemble(sroot,
			&small->ist_ltree, small->ist_ltreep,
			&small->ist_rtree, small->ist_rtreep);
		small->ist_root = ITE_NULL;
	}

	ist_unlock(small);

	/* put entries, if any, into splay */

	if (sroot != ITE_NULL) {
		ipc_tree_entry_t root;

		ist_lock(splay);

		root = splay->ist_root;
		if (root == ITE_NULL) {
			root = sroot;
		} else {
			/* get smallest entry in splay tree to top */

			if (splay->ist_name != MACH_PORT_SMALLEST) {
				ipc_splay_prim_assemble(root,
					&splay->ist_ltree, splay->ist_ltreep,
					&splay->ist_rtree, splay->ist_rtreep);
				ipc_splay_prim_lookup(MACH_PORT_SMALLEST,
					root, &root,
					&splay->ist_ltree, &splay->ist_ltreep,
					&splay->ist_rtree, &splay->ist_rtreep);
			}

			ipc_splay_prim_assemble(root,
				&splay->ist_ltree, splay->ist_ltreep,
				&splay->ist_rtree, splay->ist_rtreep);

			assert(root->ite_lchild == ITE_NULL);
			assert(sroot->ite_name < root->ite_name);
			root->ite_lchild = sroot;
		}

		splay->ist_root = root;
		splay->ist_name = root->ite_name;
		splay->ist_ltreep = &splay->ist_ltree;
		splay->ist_rtreep = &splay->ist_rtree;

		ist_unlock(splay);
	}
}

/*
 *	Routine:	ipc_splay_tree_bounds
 *	Purpose:
 *		Given a name, returns the largest value present
 *		in the tree that is smaller than or equal to the name,
 *		or ~0 if no such value exists.  Similarly, returns
 *		the smallest value present that is greater than or
 *		equal to the name, or 0 if no such value exists.
 *
 *		Hence, if
 *		lower = upper, then lower = name = upper
 *				and name is present in the tree
 *		lower = ~0 and upper = 0,
 *				then the tree is empty
 *		lower = ~0 and upper > 0, then name < upper
 *				and upper is smallest value in tree
 *		lower < ~0 and upper = 0, then lower < name
 *				and lower is largest value in tree
 *		lower < ~0 and upper > 0, then lower < name < upper
 *				and they are tight bounds on name
 *
 *		(Note MACH_PORT_SMALLEST = 0 and MACH_PORT_LARGEST = ~0.)
 */

void
ipc_splay_tree_bounds(
	ipc_splay_tree_t	splay,
	mach_port_name_t	name,
	mach_port_name_t	*lowerp, 
	mach_port_name_t	*upperp)
{
	ipc_tree_entry_t root;

	ist_lock(splay);

	root = splay->ist_root;
	if (root == ITE_NULL) {
		*lowerp = MACH_PORT_LARGEST;
		*upperp = MACH_PORT_SMALLEST;
	} else {
		mach_port_name_t rname;

		if (splay->ist_name != name) {
			ipc_splay_prim_assemble(root,
				&splay->ist_ltree, splay->ist_ltreep,
				&splay->ist_rtree, splay->ist_rtreep);
			ipc_splay_prim_lookup(name, root, &root,
				&splay->ist_ltree, &splay->ist_ltreep,
				&splay->ist_rtree, &splay->ist_rtreep);
			splay->ist_name = name;
			splay->ist_root = root;
		}

		rname = root->ite_name;

		/*
		 *	OK, it's a hack.  We convert the ltreep and rtreep
		 *	pointers back into real entry pointers,
		 *	so we can pick the names out of the entries.
		 */

		if (rname <= name)
			*lowerp = rname;
		else if (splay->ist_ltreep == &splay->ist_ltree)
			*lowerp = MACH_PORT_LARGEST;
		else {
			ipc_tree_entry_t entry;

			entry = (ipc_tree_entry_t)
				((char *)splay->ist_ltreep -
				 ((char *)&root->ite_rchild -
				  (char *)root));
			*lowerp = entry->ite_name;
		}

		if (rname >= name)
			*upperp = rname;
		else if (splay->ist_rtreep == &splay->ist_rtree)
			*upperp = MACH_PORT_SMALLEST;
		else {
			ipc_tree_entry_t entry;

			entry = (ipc_tree_entry_t)
				((char *)splay->ist_rtreep -
				 ((char *)&root->ite_lchild -
				  (char *)root));
			*upperp = entry->ite_name;
		}
	}

	ist_unlock(splay);
}

/*
 *	Routine:	ipc_splay_traverse_start
 *	Routine:	ipc_splay_traverse_next
 *	Routine:	ipc_splay_traverse_finish
 *	Purpose:
 *		Perform a symmetric order traversal of a splay tree.
 *	Usage:
 *		for (entry = ipc_splay_traverse_start(splay);
 *		     entry != ITE_NULL;
 *		     entry = ipc_splay_traverse_next(splay, delete)) {
 *			do something with entry
 *		}
 *		ipc_splay_traverse_finish(splay);
 *
 *		If "delete" is TRUE, then the current entry
 *		is removed from the tree and deallocated.
 *
 *		During the traversal, the splay tree is locked.
 */

ipc_tree_entry_t
ipc_splay_traverse_start(
	ipc_splay_tree_t	splay)
{
	ipc_tree_entry_t current, parent;

	ist_lock(splay);

	current = splay->ist_root;
	if (current != ITE_NULL) {
		ipc_splay_prim_assemble(current,
			&splay->ist_ltree, splay->ist_ltreep,
			&splay->ist_rtree, splay->ist_rtreep);

		parent = ITE_NULL;

		while (current->ite_lchild != ITE_NULL) {
			ipc_tree_entry_t next;

			next = current->ite_lchild;
			current->ite_lchild = parent;
			parent = current;
			current = next;
		}

		splay->ist_ltree = current;
		splay->ist_rtree = parent;
	}

	return current;
}

ipc_tree_entry_t
ipc_splay_traverse_next(
	ipc_splay_tree_t	splay,
	boolean_t		delete)
{
	ipc_tree_entry_t current, parent;

	/* pick up where traverse_entry left off */

	current = splay->ist_ltree;
	parent = splay->ist_rtree;
	assert(current != ITE_NULL);

	if (!delete)
		goto traverse_right;

	/* we must delete current and patch the tree */

	if (current->ite_lchild == ITE_NULL) {
		if (current->ite_rchild == ITE_NULL) {
			/* like traverse_back, but with deletion */

			if (parent == ITE_NULL) {
				ite_free(current);

				splay->ist_root = ITE_NULL;
				return ITE_NULL;
			}

			if (current->ite_name < parent->ite_name) {
				ite_free(current);

				current = parent;
				parent = current->ite_lchild;
				current->ite_lchild = ITE_NULL;
				goto traverse_entry;
			} else {
				ite_free(current);

				current = parent;
				parent = current->ite_rchild;
				current->ite_rchild = ITE_NULL;
				goto traverse_back;
			}
		} else {
			ipc_tree_entry_t prev;

			prev = current;
			current = current->ite_rchild;
			ite_free(prev);
			goto traverse_left;
		}
	} else {
		if (current->ite_rchild == ITE_NULL) {
			ipc_tree_entry_t prev;

			prev = current;
			current = current->ite_lchild;
			ite_free(prev);
			goto traverse_back;
		} else {
			ipc_tree_entry_t prev;
			ipc_tree_entry_t ltree, rtree;
			ipc_tree_entry_t *ltreep, *rtreep;

			/* replace current with largest of left children */

			prev = current;
			ipc_splay_prim_lookup(MACH_PORT_LARGEST,
				current->ite_lchild, &current,
				&ltree, &ltreep, &rtree, &rtreep);
			ipc_splay_prim_assemble(current,
				&ltree, ltreep, &rtree, rtreep);

			assert(current->ite_rchild == ITE_NULL);
			current->ite_rchild = prev->ite_rchild;
			ite_free(prev);
			goto traverse_right;
		}
	}
	/*NOTREACHED*/

	/*
	 *	A state machine:  for each entry, we
	 *		1) traverse left subtree
	 *		2) traverse the entry
	 *		3) traverse right subtree
	 *		4) traverse back to parent
	 */

    traverse_left:
	if (current->ite_lchild != ITE_NULL) {
		ipc_tree_entry_t next;

		next = current->ite_lchild;
		current->ite_lchild = parent;
		parent = current;
		current = next;
		goto traverse_left;
	}

    traverse_entry:
	splay->ist_ltree = current;
	splay->ist_rtree = parent;
	return current;

    traverse_right:
	if (current->ite_rchild != ITE_NULL) {
		ipc_tree_entry_t next;

		next = current->ite_rchild;
		current->ite_rchild = parent;
		parent = current;
		current = next;
		goto traverse_left;
	}

    traverse_back:
	if (parent == ITE_NULL) {
		splay->ist_root = current;
		return ITE_NULL;
	}

	if (current->ite_name < parent->ite_name) {
		ipc_tree_entry_t prev;

		prev = current;
		current = parent;
		parent = current->ite_lchild;
		current->ite_lchild = prev;
		goto traverse_entry;
	} else {
		ipc_tree_entry_t prev;

		prev = current;
		current = parent;
		parent = current->ite_rchild;
		current->ite_rchild = prev;
		goto traverse_back;
	}
}

void
ipc_splay_traverse_finish(
	ipc_splay_tree_t	splay)
{
	ipc_tree_entry_t root;

	root = splay->ist_root;
	if (root != ITE_NULL) {
		splay->ist_name = root->ite_name;
		splay->ist_ltreep = &splay->ist_ltree;
		splay->ist_rtreep = &splay->ist_rtree;
	}

	ist_unlock(splay);
}

