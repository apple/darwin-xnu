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
 */

/*
 *	File:	vm/task_working_set.h
 *	Author:	Chris Youngworth
 *	Date:	2001
 *
 *	Working set detection and maintainence module
 *
 */

#ifndef	_VM_TASK_WORKING_SET_H_
#define _VM_TASK_WORKING_SET_H_

#include <kern/queue.h>
#include <vm/vm_object.h>

/* task working set */

#define tws_lock(tws)		mutex_lock(&(tws)->lock)
#define tws_lock_try(tws)	mutex_try(&(tws)->lock)
#define tws_unlock(tws)		mutex_unlock(&(tws)->lock)


#define	TWS_ARRAY_SIZE	8
#define TWS_HASH_LINE_COUNT 32
/* start out size to allow monitoring of working set without excessive use */
/* of wired memory resource. */
#define TWS_SMALL_HASH_LINE_COUNT 4 

/*
#define do_tws_hash(object,offset, rows, lines) \
		((((natural_t)(object)) +  \
		(((natural_t)(offset)) >> 11) + \
					(((natural_t)(offset)) >> 12)) & \
			((2 * rows * lines) -1))
*/
/*
 * do not think of changing this hash unless you understand the implications
 * for the hash element page_cache field 
 */
#define do_tws_hash(object,offset, rows, lines) \
		(((((natural_t)(object)) >> 2) +  \
			((natural_t)(object) >> 12) + \
			((natural_t)(((vm_object_offset_t)(offset)) >> 12) \
						& 0xFFFFFFFFFFFFFFE0)) & \
			((2 * rows * lines) -1))
/*
#define do_tws_hash(object,offset, rows, lines) \
		(((((natural_t)(object)) >> 2) +  \
			((natural_t)(object) << 5) + \
			((natural_t)(((vm_object_offset_t)(offset)) >> 17))) & \
			((2 * rows * lines) -1))
*/


#define alt_tws_hash(addr, rows, lines) \
		((((natural_t)(addr)) >> 12) & \
		((2 * rows * lines) -1))

struct tws_hash_ele {
	vm_object_t		object;
	vm_object_offset_t	offset;
	unsigned int		page_cache;
	vm_offset_t		page_addr;
	int			line;
	vm_map_t		map;
};
typedef struct tws_hash_ele *tws_hash_ele_t;

#define TWS_HASH_OFF_MASK ((vm_object_offset_t)0xFFFFFFFFFFFE0000)
#define TWS_INDEX_MASK ((vm_object_offset_t)0x000000000001F000)

struct tws_hash_line {
	int		ele_count;
	struct tws_hash_ele	list[TWS_ARRAY_SIZE];
};
typedef struct tws_hash_line *tws_hash_line_t;

#define TWS_HASH_STYLE_DEFAULT	0x0
#define TWS_HASH_STYLE_BASIC	0x1
#define TWS_HASH_STYLE_SIGNAL	0x2


#define TWS_HASH_EXPANSION_MAX	5
#define TWS_MAX_REHASH 2


struct tws_hash {
	decl_mutex_data(,lock)          /* tws_hash's lock */
	int		style;

	int		current_line;
	unsigned int	pageout_count;
	int		line_count;

	int		number_of_lines;
	int		number_of_elements;
	int		expansion_count;
	unsigned int	time_of_creation;

	int		lookup_count;
	int		insert_count;

	tws_hash_ele_t	*table[TWS_HASH_EXPANSION_MAX];
	tws_hash_ele_t	*alt_table[TWS_HASH_EXPANSION_MAX];
	struct tws_hash_line	*cache[TWS_HASH_EXPANSION_MAX];
}; 

typedef struct tws_hash *tws_hash_t;


extern tws_hash_t tws_hash_create();

extern void tws_hash_line_clear(
			tws_hash_t	tws,
			tws_hash_line_t hash_line, 
			boolean_t live);

extern kern_return_t tws_lookup(
			tws_hash_t		tws,	
			vm_object_offset_t	offset, 
			vm_object_t		object,
			tws_hash_line_t		 *line);

extern kern_return_t tws_insert(
			tws_hash_t		tws, 
			vm_object_offset_t	offset,
			vm_object_t		object,
			vm_offset_t		page_addr,
			vm_map_t		map);

extern void tws_build_cluster(
			tws_hash_t		tws,
			vm_object_t		object,
			vm_object_offset_t	*start,
			vm_object_offset_t	*end,
			vm_size_t		max_length);

extern tws_line_signal(
		tws_hash_t	tws,
		vm_map_t	map,
		tws_hash_line_t hash_line,
		vm_offset_t	target_page);

extern void tws_hash_destroy(
		tws_hash_t	tws);

extern void tws_hash_clear(
		tws_hash_t	tws);

kern_return_t	task_working_set_create(                
		task_t  task,
		unsigned int lines,
		unsigned int rows,
		unsigned int style);

kern_return_t	tws_expand_working_set(
		vm_offset_t	old_tws,
		int		line_count);


#endif  /* _VM_TASK_WORKING_SET_H_ */
