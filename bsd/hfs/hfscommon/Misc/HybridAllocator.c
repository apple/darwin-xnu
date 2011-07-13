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

#if CONFIG_HFS_ALLOC_RBTREE

#define assert(a) { if (!(a)) { panic("File "__FILE__", line %d: assertion '%s' failed.\n", __LINE__, #a); } }

//#include <sys/systm.h>
#include "../../hfs_macos_defs.h"
#include "../headers/HybridAllocator.h"

#define bool Boolean

#define ALLOC_DEBUG 0

/*
 * The rb_wrap macro in RedBlackTree.h automatically generates the source for a variety of functions that 
 * operate on the red-black trees.  The bodies of these automatically generated functions are the corresponding 
 * macro from RedBlackTree.h.  For example, the extent_tree_length_new() function invokes the rb_new() macro.
 * We re-define actual wrapper functions around them so that we can re-name them and adjust the functions 
 * that are available to the allocator in VolumeAllocation.c. 
 *
 * Here are the functions that get automatically generated:
 * Offset-Tree Functions:
 *
 * initialize the tree
 * static void				extent_tree_offset_new(extent_tree_offset_t * tree)
 *
 * Get the first node in the tree.  If it is empty, return NULL
 * static extent_node_t*	extent_tree_offset_first (extent_tree_offset_t * tree)
 *
 * Get the last node in the tree.  If it is empty, return NULL
 * static extent_node_t*	extent_tree_offset_last (extent_tree_offset_t * tree)
 *
 * From a given extent_node_t, grab the next one.  If no next exists, return NULL
 * static extent_node_t*	extent_tree_offset_next (extent_tree_offset_t * tree, extent_node_t * node)
 *
 * From a given extent_node_t, grab the previous.  If no prev exists, return NULL
 * static extent_node_t*	extent_tree_offset_prev(extent_tree_offset_t * tree, extent_node_t * node)
 *  
 * Find a extent_node_t with the specified key (search by offset). If it does not exist, return NULL
 * static extent_node_t*	extent_tree_offset_search(extent_tree_offset_t * tree, extent_node_t * key)
 *
 * Find an extent node_t withthe specified key (offset).  If it does not exist, 
 * either grab the next node, if possible, or return NULL
 * static extent_node_t*	extent_tree_offset_nsearch(extent_tree_offset_t * tree, extent_node_t * key)
 *
 * Find an extent_node_t with the specified key (offset).  If it does not exist,
 * either grab the previous node, if possible, or return NULL
 * static extent_node_t*	extent_tree_offset_psearch(extent_tree_offset_t * tree, extent_node_t * key)
 *
 * Insert the specified node into the tree.
 * static void				extent_tree_offset_insert(extent_tree_offset_t * tree, extent_node_t * node)
 * 
 * Remove the specified node from the tree. 
 * static void				extent_tree_offset_remove(extent_tree_offset_t * tree, extent_node_t * node)
 * 
 */


/* Static Functions only used in this file */
static int32_t
extent_tree_internal_alloc_space(extent_tree_offset_t *offset_tree, 
								 u_int32_t size, u_int32_t offset, extent_node_t *node);

/*
 * cmp_offset_node
 * 
 * Compare the extents in two nodes by offset.
 * 
 * Returns: 
 * -1 if node 1's offset < node 2's offset.
 *  1 if node 1's offset > node 2's offset.
 */

__private_extern__ int
cmp_offset_node(extent_node_t *node_1, extent_node_t *node_2) {
	u_int32_t addr_1 = node_1->offset;
	u_int32_t addr_2 = node_2->offset;
	
	return ((addr_1 > addr_2) - (addr_1 < addr_2));
}

/*
 * Allocate a new red-black tree node.
 * 
 * Currently, we get memory from the M_TEMP zone.
 * TODO: Need to get our own zone to avoid bloating the M_TEMP zone.
 */
__private_extern__ extent_node_t *
alloc_node(u_int32_t length, u_int32_t offset) {
	extent_node_t *node;
	MALLOC(node, extent_node_t *, sizeof(extent_node_t), M_TEMP, M_WAITOK);
	
	if (node) {
		node->offset = offset;
		node->length = length;
		node->offset_next = NULL;
	}
	return node;
}

/*
 * De-allocate a red-black tree node.  
 * 
 * Currently, this goes back to the M_TEMP zone.
 * TODO: May need to adjust this if we pull memory out of our own zone.
 */
__private_extern__ void
free_node(extent_node_t *node) {
	FREE(node, M_TEMP);
}

/*
 * rb_wrap is a macro found in the rb.h header file.  It builds functions that operate on
 * the red-black tree based upon the types specified here. This code will build red-black tree
 * search functions that operate on extent_node_t's and use cmp_length_node to do length searches.
 * It uses cmp_offset_node to do offset searches.  Ties are broken by offset. This will generate 
 * the functions specified above. 
 */

rb_wrap(__attribute__ ((unused)) static, extent_tree_offset_, extent_tree_offset_t, extent_node_t, offset_link, cmp_offset_node)


/*
 * Create a new extent tree, composed of links sorted by offset.
 */
__private_extern__ void
extent_tree_init(extent_tree_offset_t *offset_tree)
{
	extent_node_t *node = NULL;
	extent_tree_offset_new(offset_tree);
	
	node = extent_tree_off_first (offset_tree);
	if (node) {
		node->offset_next = NULL;
	}
}

/*
 * Destroy an extent tree
 * 
 * This function finds the first node in the specified red-black tree, then 
 * uses the embedded linked list to walk through the tree in O(n) time and destroy
 * all of its nodes.
 */
__private_extern__ void
extent_tree_destroy(extent_tree_offset_t *off_tree) {
	extent_node_t *node = NULL;
	extent_node_t *next = NULL;
	
	node = extent_tree_offset_first (off_tree);
	
	while (node) {
		next = node->offset_next;
		extent_tree_offset_remove (off_tree, node);
		free_node (node);
		node = next;
	}
}

/* 
 * Search the extent tree by offset. The "key" argument is only used to extract
 * the offset and length information.  Its link fields are not used in the underlying
 * tree code.
 */
__private_extern__ extent_node_t *
extent_tree_off_search(extent_tree_offset_t *tree, extent_node_t *key) {
	return extent_tree_offset_search(tree, key);
}

/*
 * Search the extent tree by offset, finding the next node in the tree
 * if the specified one does not exist.  The "key" argument is only used to extract
 * the offset and length information.  Its link fields are not used in the underlying
 * tree code.
 */
__private_extern__ extent_node_t *
extent_tree_off_search_next(extent_tree_offset_t *offset_tree, extent_node_t *key) {
	
	return extent_tree_offset_nsearch (offset_tree, key);
}

/*
 * Search the extent tree by offset to find a starting position.  Then, do a linear search
 * through the list of free extents to find the first free extent in the tree that has size 
 * greater than or equal to the specified size.  The "key" argument is only used to extract
 * the offset and length information.  Its link fields are not used in the underlying
 * tree code.
 */
__private_extern__ extent_node_t *
extent_tree_off_search_nextWithSize (extent_tree_offset_t *offset_tree, extent_node_t *key) {
	
	extent_node_t *current;
	
	u_int32_t min_size = key->length;
	
	current = extent_tree_offset_nsearch (offset_tree, key);
	
	while (current) {
		if (current->length >= min_size) {
			return current;
		}
		current = current->offset_next;
	}
	
	/* return NULL if no free extent of suitable size could be found. */
	return NULL;
}


/*
 * Search the extent tree by offset, finding the previous node in the tree
 * if the specified one does not exist.  The "key" argument is only used to extract
 * the offset and length information.  Its link fields are not used in the underlying
 * tree code.
 */
__private_extern__ extent_node_t *
extent_tree_off_search_prev(extent_tree_offset_t *offset_tree, extent_node_t *key) {
	
	return extent_tree_offset_psearch (offset_tree, key);
}


/*
 * Find the first node in the extent tree, by offset.  This will be the first 
 * free space region relative to the start of the disk. 
 */
__private_extern__ extent_node_t *
extent_tree_off_first (extent_tree_offset_t *offset_tree) {
	return extent_tree_offset_first(offset_tree);
}

/*
 * From a given tree node (sorted by offset), get the next node in the tree. 
 */
__private_extern__ extent_node_t *
extent_tree_off_next(extent_tree_offset_t * tree, extent_node_t *node)
{
	return extent_tree_offset_next(tree, node);
}

/*
 * From a given tree node (sorted by offset), get the previous node in the tree. 
 */
__private_extern__ extent_node_t *
extent_tree_off_prev(extent_tree_offset_t * tree, extent_node_t *node)
{
	return extent_tree_offset_prev(tree, node);
}


/*
 * For a node of a given offset and size, remove it from the extent tree and
 * insert a new node that:
 * 
 *	A) increase its offset by that of the node we just removed
 *  B) decreases its size by that of the node we just removed.
 *
 * NOTE: Callers must ensure that the 'size' specified is less than or equal to the
 * length of the extent represented by node.  The node pointer must point to an 
 * extant node in the tree, as it will be removed from the tree.
 */
static int32_t
extent_tree_internal_alloc_space(extent_tree_offset_t *offset_tree, u_int32_t size, 
								 u_int32_t offset, extent_node_t *node)
{
	if (node) {
		extent_node_t *prev = NULL;
		extent_node_t *next = NULL;
		
		if( ALLOC_DEBUG ) {
			assert ((size <= node->length));
			assert ((offset == node->offset));
		}
		
		prev = extent_tree_offset_prev(offset_tree, node);
		
		/*
		 * Note that, unless the node is exactly the size of the amount of space
		 * requested, we do not need to remove it from the offset tree, now matter
		 * how much space we remove from the node.  Remember that the offset tree is
		 * sorting the extents based on their offsets, and that each node is a discrete 
		 * chunk of free space.
		 * 
		 * If node A has offset B, with length C, in the offset tree, by definition, there 
		 * can be no other node in the extent tree within the range {B, B+C}.  If there were,
		 * we'd have overlapped extents. 
		 * 
		 * So in the normal case, we'll just update the offset node in place with the new offset
		 * and size.
		 * 
		 * Otherwise, if we have an exact match, then just remove the node altogether.  Don't forget 
		 * to update the next pointer for the linked list if applicable.
		 */
		if (node->length == size) {
			next = node->offset_next;
			extent_tree_offset_remove(offset_tree, node);
			free_node(node);
			if (prev) {
				prev->offset_next = next;
			}
		}
		else {
			node->offset = node->offset + size;
			node->length -= size;
			/* The next pointer does not change since we keep the node in place */
		}
		return 0;
	}	
	return -1;
}

/*
 * Search the extent tree for a region of free space after the specified 
 * offset and attempt to allocate it.  
 *
 * This is expected to be used by attempts to grow a file contiguously.  If we 
 * start at a file's EOF, then we can try to allocate space immediately after it 
 * if it's available. This function specifies a tail (the offset), and then passes it 
 * into extent_tree_offset_search. Note that this is not the search_prev or search_next 
 * variant, so if no node exists at the specified offset we'll fail out.  
 *
 */

__private_extern__ int32_t
extent_tree_offset_alloc_space(extent_tree_offset_t *offset_tree, u_int32_t size, u_int32_t offset) {
	extent_node_t search_sentinel = { .offset = offset };
	extent_node_t *node = extent_tree_offset_search(offset_tree, &search_sentinel);
	if (node && (node->length < size)) {
		/* It's too small. Fail the allocation */
		if ( ALLOC_DEBUG ) { 
			printf("HFS Allocator: internal_alloc_space, ptr (%p) node->length (%d), node->offset (%d), off(%d), size (%d) \n", 
				   node, node->length, node->offset, offset, size);
		}
		return -1;		
	}
	return extent_tree_internal_alloc_space(offset_tree, size, offset, node);
}


/*
 * Search the extent tree for a region of free space at the specified 
 * offset and attempt to allocate it.  
 * 
 * This is a little bit more involved than the previous function.  It is intended for use when
 * we may be allocating space from the middle of an existing extent node.
 *
 */


__private_extern__ int32_t
extent_tree_offset_alloc_unaligned(extent_tree_offset_t *offset_tree, u_int32_t size, u_int32_t offset) {
	extent_node_t search_sentinel = { .offset = offset };
	extent_node_t *node= NULL;
	
	node = extent_tree_off_search_prev(offset_tree, &search_sentinel);
	
	if (node == NULL) {
		return -1;
	}
	
	if (node && (node->length < size)) {
		/* It's too small. Fail the allocation */
		if ( ALLOC_DEBUG ) { 
			printf("HFS Allocator: internal_alloc_space, ptr (%p) node->length (%d), node->offset (%d), off(%d), size (%d) \n", 
				   node, node->length, node->offset, offset, size);
		}
		return -1;		
	}

	/* Now see if we need to split this node because we're not allocating from the beginning */
	if (offset != node->offset) {
		
		if (ALLOC_DEBUG) {
			assert ((offset + size) <= (node->offset + node->length));
			if (node->offset_next) {
				assert ((offset > node->offset) && (offset < node->offset_next->offset));
			}
		}
		
		u_int32_t end = node->offset + node->length;
		node->length = offset - node->offset;
		
		/* 
		 * Do we need to create a new node?  If our extent we're carving away ends earlier than 
		 * the current extent's length, then yes - we do.
		 */		
		if ((offset + size) < (end)) {
			u_int32_t newoff = offset + size;
			u_int32_t newlen = end - newoff;

			extent_node_t* newnode = alloc_node(newlen, newoff);
			extent_tree_offset_insert(offset_tree, newnode);
			
			extent_node_t *next = extent_tree_offset_next(offset_tree, newnode);
			newnode->offset_next = next;
			node->offset_next = newnode;
		}
		
		return 0;
	}
	else {
		return extent_tree_internal_alloc_space(offset_tree, size, offset, node);
	}
}



/*
 * Mark an extent of space as being free.  This means we need to insert 
 * this extent into our tree.
 *
 * Search the offset tree, based on the new offset that we construct by adding 
 * the length of our extent to be freed to its offset.  If something exists at 
 * that offset, then we coalesce the nodes.  In this case, we do not need to adjust 
 * the offset tree because our extent we wanted to add could not have been in the tree.
 *
 * If no node existed at the specified offset, then create a new one and insert it 
 * into the tree.
 * 
 * Finally, search based on the node that would precede our newly created/inserted one.
 * If possible, coalesce the previous node into our new one.  
 *
 * We return the node which we are modifying in this function.  
 */

__private_extern__ extent_node_t *
extent_tree_free_space(extent_tree_offset_t *offset_tree, u_int32_t size, u_int32_t offset)
{
	extent_node_t *prev = NULL;
	extent_node_t *node = NULL;	
	extent_node_t *next = NULL;
	extent_node_t search_sentinel = { .offset = size + offset };
	
	node = extent_tree_offset_nsearch(offset_tree, &search_sentinel);
	/* Insert our node into the tree, and coalesce with the next one if necessary */
	
	if ((node) && (node->offset == search_sentinel.offset)) {
        node->offset = offset;
        node->length += size;
		next = node->offset_next;
    }
	else {
		node = alloc_node(size, offset);
        assert(node);
        extent_tree_offset_insert(offset_tree, node);
		
		/* Find the next entry in the tree, if applicable. */
		next = extent_tree_offset_next(offset_tree, node);
		node->offset_next = next;
	}
	
	/* Coalesce with the previous if necessary */
	prev = extent_tree_offset_prev(offset_tree, node);
	if (prev && (prev->offset + prev->length) == offset) {
        extent_tree_offset_remove(offset_tree, prev);
        node->offset = prev->offset;
        node->length += prev->length;		
        free_node(prev);
		prev = extent_tree_offset_prev(offset_tree, node);
    }
	
	/* Update the next pointer for the previous entry (if necessary) */
	if (prev) {
		prev->offset_next = node;
	}
	
	return node;
}

/*
 * Remove the specified node from the offset_tree.  Note that the parameter node
 * must be an extant node in the tree.  This function is used by the allocator when
 * we are resizing a volume and need to directly manipulate the contents of the red-black
 * tree without going through the normal allocation and deallocation routines.
 */
__private_extern__ void 
extent_tree_remove_node (extent_tree_offset_t *offset_tree, extent_node_t * node) {
	
	if (node) {
		/* Just remove the entry from the tree */
		extent_tree_offset_remove(offset_tree, node);
	}
	return;
	
}



#if ALLOC_DEBUG 
/*
 * For each node in the tree, print out its length and block offset.
 */
__private_extern__ void
extent_tree_offset_print(extent_tree_offset_t *offset_tree)
{
	extent_node_t *node = NULL;
	
	node = extent_tree_offset_first(offset_tree);
	while (node) {
		printf("length: %u, offset: %u\n", node->length, node->offset);
		node = node->offset_next;
	}
}
#endif

#endif
