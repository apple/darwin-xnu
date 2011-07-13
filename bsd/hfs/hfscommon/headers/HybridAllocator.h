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


#ifndef __HYBRID_ALLOC__
#define __HYBRID_ALLOC__

#include <sys/types.h>
#include "RedBlackTree.h"

typedef struct extent_node extent_node_t;

struct extent_node
{
	u_int32_t length;
	u_int32_t offset;
	struct extent_node *offset_next;
	rb_node(extent_node_t) offset_link;
};

typedef rb_tree(extent_node_t) extent_tree_offset_t;

extern extent_node_t *
alloc_node(u_int32_t length, u_int32_t offset);

extern void
free_node(extent_node_t *node); 

extern extent_node_t *
extent_tree_free_space( extent_tree_offset_t *offset_tree, u_int32_t size, u_int32_t offset);

extern void
extent_tree_offset_print(extent_tree_offset_t *offset_tree);

extern int32_t
extent_tree_offset_alloc_space(extent_tree_offset_t *offset_tree, u_int32_t size, u_int32_t offset);

extern int32_t
extent_tree_offset_alloc_unaligned(extent_tree_offset_t *tree, u_int32_t size, u_int32_t offset);


extern void
extent_tree_remove_node (extent_tree_offset_t *offset_tree, extent_node_t * node);

extern extent_node_t *
extent_tree_off_first (extent_tree_offset_t *offset_tree);

extern extent_node_t *
extent_tree_off_search(extent_tree_offset_t *offset_tree, extent_node_t *node);

extern extent_node_t *
extent_tree_off_search_next(extent_tree_offset_t *offset_tree, extent_node_t *node);

extern extent_node_t*
extent_tree_off_search_nextWithSize (extent_tree_offset_t *offset_tree, extent_node_t *node);

extern extent_node_t *
extent_tree_off_search_prev(extent_tree_offset_t *offset_tree, extent_node_t *node);

extern extent_node_t *
extent_tree_off_next(extent_tree_offset_t *offset_tree, extent_node_t *node);

extern extent_node_t *
extent_tree_off_prev(extent_tree_offset_t *offset_tree, extent_node_t *node);

extern void
extent_tree_init(extent_tree_offset_t *offset_tree);

extern void
extent_tree_destroy(extent_tree_offset_t *offset_tree);

extern int
cmp_offset_node(extent_node_t *node_1, extent_node_t *node_2);


#endif
