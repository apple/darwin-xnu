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
 *	File:	vm/task_working_set.c
 *	Author:	Chris Youngworth
 *	Date:	2001
 *
 *	Working set detection and maintainence module
 */


#include <mach/rpc.h>
#include <vm/task_working_set.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <kern/sched.h>

extern unsigned sched_tick;

/* Note:  all of the routines below depend on the associated map lock for */
/* synchronization, the map lock will be on when the routines are called  */
/* and on when they return */

tws_hash_t
tws_hash_create(
	unsigned int lines, 
	unsigned int rows,
	unsigned int style)
{
	tws_hash_t	tws;
	int		i,j;

	
	if ((style != TWS_HASH_STYLE_BASIC) &&
			(style != TWS_HASH_STYLE_BASIC)) {
		return((tws_hash_t)NULL);
	}

	
	tws = (tws_hash_t)(kalloc(sizeof(struct tws_hash)));
	if(tws == (tws_hash_t)NULL)
		return tws;

	if((tws->table[0] = (tws_hash_ele_t *)
			kalloc(sizeof(tws_hash_ele_t) * 2 * lines * rows)) 
								== NULL) {
		kfree((vm_offset_t)tws, sizeof(struct tws_hash));
		return (tws_hash_t)NULL;
	}
	if((tws->alt_table[0] = (tws_hash_ele_t *)
			kalloc(sizeof(tws_hash_ele_t) * 2 * lines * rows))
								== NULL) {
		kfree((vm_offset_t)tws, sizeof(struct tws_hash));
		kfree((vm_offset_t)tws->table[0], sizeof(tws_hash_ele_t) 
				* 2 * lines * rows);
		return (tws_hash_t)NULL;
	}
	if((tws->cache[0] = (struct tws_hash_line *)
			kalloc(sizeof(struct tws_hash_line) * lines))
								== NULL) {
		kfree((vm_offset_t)tws, sizeof(struct tws_hash));
		kfree((vm_offset_t)tws->table[0], sizeof(tws_hash_ele_t) 
				* 2 * lines * rows);
		kfree((vm_offset_t)tws->alt_table[0], sizeof(tws_hash_ele_t) 
				* 2 * lines * rows);
		return (tws_hash_t)NULL;
	}

	/* most defaults are such that a bzero will initialize */
	bzero((char *)tws->table[0],sizeof(tws_hash_ele_t)
                                	* 2 * lines * rows);
	bzero((char *)tws->alt_table[0],sizeof(tws_hash_ele_t)
                                	* 2 * lines * rows);
	bzero((char *)tws->cache[0], sizeof(struct tws_hash_line) 
					* lines);

	mutex_init(&tws->lock, ETAP_VM_MAP);
	tws->style = style;
	tws->current_line = 0;
	tws->pageout_count = 0;
	tws->line_count = 0;
	tws->number_of_lines = lines;
	tws->number_of_elements = rows;
	tws->expansion_count = 1;
	tws->lookup_count = 0;
	tws->insert_count = 0;
	tws->time_of_creation = sched_tick;

	return tws;
}

int	newtest = 0;
void
tws_hash_line_clear(
	tws_hash_t	tws,
	tws_hash_line_t hash_line, 
	boolean_t live)
{
	struct tws_hash_ele	*hash_ele;
	int			index;
	unsigned int		i, j, k;
	int			alt_index;
	int			dump_pmap;
	int			hash_loop;


	if(tws->line_count < tws->number_of_lines) {
		tws->line_count++;
		dump_pmap = 1;
	} else {
		if(tws->pageout_count != vm_pageout_scan_event_counter) {
			tws->pageout_count = 
				vm_pageout_scan_event_counter;
			tws->line_count = 0;
			dump_pmap = 1;
		} else {
			dump_pmap = 0;
		}
	}
	hash_line->ele_count = 0;
	for (i=0; i<tws->number_of_elements; i++) {
	   hash_loop = 0;
	   hash_ele = &(hash_line->list[i]);
	   if(hash_ele->object != 0) {
		vm_offset_t	vaddr_off = 0;
		vm_object_offset_t local_off = 0;

		for (j = 0x1; j != 0; j = j<<1) {
			if(j & hash_ele->page_cache) {
				unsigned int	alt_index;
				alt_index = alt_tws_hash(
					hash_ele->page_addr + vaddr_off,
					tws->number_of_elements, 
					tws->number_of_lines);
				for(k = 0; k < tws->expansion_count; k++) {
				 if(tws->alt_table[k][alt_index] == hash_ele) {
					tws->alt_table[k][alt_index] = 0;
				 }
				}
				vaddr_off += PAGE_SIZE;
		   	}
		}

		if((hash_ele->map != NULL) && (live)) {
			vm_page_t	p;

			for (j = 0x1; j != 0; j = j<<1) {
			   if(j & hash_ele->page_cache) {
				p = vm_page_lookup(hash_ele->object, 
						hash_ele->offset + local_off);
				if((p != NULL) && (p->wire_count == 0) 
						&& (dump_pmap == 1)) {
					pmap_remove_some_phys((pmap_t)
						vm_map_pmap(hash_ele->map),
						p->phys_addr);
				}
			   }
			   local_off += PAGE_SIZE_64;
			}
		}
		if(tws->style == TWS_HASH_STYLE_SIGNAL) {
			vm_object_deallocate(hash_ele->object);
			vm_map_deallocate(hash_ele->map);
		}

		index = do_tws_hash(hash_ele->object, hash_ele->offset,
				tws->number_of_elements, tws->number_of_lines);

		while (hash_loop < TWS_MAX_REHASH) {
			for(k = 0; k < tws->expansion_count; k++) {
				if((tws->table[k][index] != 0) && 
					(tws->table[k][index] == hash_ele)) {
					tws->table[k][index] = 0;
					break;
				}
				if(k < tws->expansion_count)
					break;
			}
			index += 17;
			if(index >= (2 * 
				tws->number_of_lines 
					* tws->number_of_elements)) {
				index = index - (2 * 
					tws->number_of_lines 
					* tws->number_of_elements);
			}
			hash_loop++;
		}
		hash_ele->object = 0;
		hash_ele->page_cache = 0;

if(newtest != 0) {
	if (hash_loop == TWS_MAX_REHASH) {
		panic("tws_hash_line_clear: Cache and Hash out of sync\n");
	}
}
	   }
	}
}

kern_return_t
tws_lookup(
	tws_hash_t		tws,	
	vm_object_offset_t	offset, 
	vm_object_t		object,
	tws_hash_line_t		 *line) 
{
	struct tws_hash_ele	*hash_ele;
	int			index;
	int			k;
	int			loop;

	/* don't cache private objects */
	if(object->private)
		return KERN_SUCCESS;

	if(!tws_lock_try(tws)) {
		return KERN_FAILURE;
	}

	index = do_tws_hash(object, offset, 
			tws->number_of_elements, tws->number_of_lines);
	loop = 0;

	tws->lookup_count++; 
	if(tws->lookup_count == 0)
		tws->insert_count = 0;
	while (loop < TWS_MAX_REHASH) {
	   for(k=0; k<tws->expansion_count; k++) {
	      if((hash_ele = tws->table[k][index]) != 0) {
		if((hash_ele->offset == (offset & TWS_HASH_OFF_MASK)) 
				&& (hash_ele->object == object)) {
			vm_offset_t	pagenum;

			pagenum = (vm_offset_t)
				(offset & TWS_INDEX_MASK);
			pagenum = pagenum >> 12;
			
			if((1<<pagenum) & hash_ele->page_cache) {
				int	  	set; 
				int		ele_line;

				set = hash_ele->line/tws->number_of_lines;
				ele_line = hash_ele->line - set;
				*line = &tws->cache[k][ele_line];
				tws_unlock(tws);
				return KERN_SUCCESS;
			}
		}
	      }
	   }
	   index += 17;
	   if(index >= (2 * tws->number_of_lines * tws->number_of_elements)) {
		index = index -
			(2 * tws->number_of_lines * tws->number_of_elements);
	   }
	   loop++;
	}
	tws_unlock(tws);
	return KERN_FAILURE;
}

kern_return_t
tws_expand_working_set(
	vm_offset_t	tws, 
	int		line_count)
{
	tws_hash_t		new_tws;
	tws_hash_t		old_tws;
	unsigned int		i,j,k;
	struct	tws_hash	temp;

	old_tws = (tws_hash_t)tws;

	/* Note we do an elaborate dance to preserve the header that */
	/* task is pointing to.  In this way we can avoid taking a task */
	/* lock every time we want to access the tws */

	if (old_tws->number_of_lines >= line_count) {
		return KERN_FAILURE;
	}
	if((new_tws = tws_hash_create(line_count, 
			old_tws->number_of_elements, old_tws->style)) == 0) {
		return(KERN_NO_SPACE);
	}
	tws_lock(old_tws);
	
	for(i = 0; i<old_tws->number_of_lines; i++) {
	   for(j = 0; j<old_tws->number_of_elements; j++) {
	      for(k = 0; k<old_tws->expansion_count; k++) {
		tws_hash_ele_t		entry;
		vm_object_offset_t	paddr;
		unsigned int		page_index;
		entry = &old_tws->cache[k][i].list[j];
		if(entry->object != 0) {
			paddr = 0;
			for(page_index = 1; page_index != 0; 
					page_index = page_index << 1); {
				if (entry->page_cache & page_index) {
					tws_insert(new_tws, 
						entry->offset+paddr,
						entry->object, 
						entry->page_addr+paddr, 
						entry->map);
				}
				paddr+=PAGE_SIZE;
			}
		
		}
	     }
	   }
	}

	temp.style = new_tws->style;
	temp.current_line = new_tws->current_line;
	temp.pageout_count = new_tws->pageout_count;
	temp.line_count = new_tws->line_count;
	temp.number_of_lines = new_tws->number_of_lines;
	temp.number_of_elements = new_tws->number_of_elements;
	temp.expansion_count = new_tws->expansion_count;
	temp.lookup_count = new_tws->lookup_count;
	temp.insert_count = new_tws->insert_count;
	for(i = 0; i<new_tws->expansion_count; i++) {
		temp.table[i] = new_tws->table[i];
		temp.alt_table[i] = new_tws->alt_table[i];
		temp.cache[i] = new_tws->cache[i];
	}

	new_tws->style = old_tws->style;
	new_tws->current_line = old_tws->current_line;
	new_tws->pageout_count = old_tws->pageout_count;
	new_tws->line_count = old_tws->line_count;
	new_tws->number_of_lines = old_tws->number_of_lines;
	new_tws->number_of_elements = old_tws->number_of_elements;
	new_tws->expansion_count = old_tws->expansion_count;
	new_tws->lookup_count = old_tws->lookup_count;
	new_tws->insert_count = old_tws->insert_count;
	for(i = 0; i<old_tws->expansion_count; i++) {
		new_tws->table[i] = old_tws->table[i];
		new_tws->alt_table[i] = old_tws->alt_table[i];
		new_tws->cache[i] = old_tws->cache[i];
	}
	
	old_tws->style = temp.style;
	old_tws->current_line = temp.current_line;
	old_tws->pageout_count = temp.pageout_count;
	old_tws->line_count = temp.line_count;
	old_tws->number_of_lines = temp.number_of_lines;
	old_tws->number_of_elements = temp.number_of_elements;
	old_tws->expansion_count = temp.expansion_count;
	old_tws->lookup_count = temp.lookup_count;
	old_tws->insert_count = temp.insert_count;
	for(i = 0; i<temp.expansion_count; i++) {
		old_tws->table[i] = temp.table[i];
		old_tws->alt_table[i] = temp.alt_table[i];
		old_tws->cache[i] = temp.cache[i];
	}

	tws_hash_destroy(new_tws);
	tws_unlock(old_tws);
	return	KERN_SUCCESS;
}

kern_return_t
tws_insert(
	tws_hash_t		tws, 
	vm_object_offset_t	offset,
	vm_object_t		object,
	vm_offset_t		page_addr,
	vm_map_t		map)
{
	queue_t 		bucket;
	struct tws_hash_ele	*new_entry;
	unsigned int		index;
	unsigned int		alt_index;
	unsigned int		ele_index;
	unsigned int		page_index;
	int			i,k;
	int			alt_k;
	int			alt_hash_count;
	int			current_line;
	int			set;
	int			hash_loop;

	if(!tws_lock_try(tws)) {
		return KERN_FAILURE;
	}
	tws->insert_count++;
	current_line = 0xFFFFFFFF;

	/* This next bit of code, the and alternate hash */
	/* are all made necessary because of IPC COW     */

	alt_index = alt_tws_hash(page_addr,
			tws->number_of_elements, tws->number_of_lines);

	for(alt_k=0; alt_k<tws->expansion_count; alt_k++) {
		new_entry = tws->alt_table[alt_k][alt_index];
		if((new_entry == 0) || (new_entry->object == 0)) {
			tws->alt_table[alt_k][alt_index] = 0;
			continue;
		}
		if(!((new_entry->offset == (offset & TWS_HASH_OFF_MASK)) 
			&& (new_entry->object == object))) {

			tws->alt_table[alt_k][alt_index] = 0;

			index = do_tws_hash(
				new_entry->object, new_entry->offset,
				tws->number_of_elements, tws->number_of_lines);

			hash_loop = 0;
			while (hash_loop < TWS_MAX_REHASH) {

		           for(k=0; k<tws->expansion_count; k++) {
			   	if(tws->table[k][index] == new_entry) {
					break;
				}
			   }

			   if(k == tws->expansion_count) {
				index+=17;
				if(index >= (2 * tws->number_of_lines 
						* tws->number_of_elements)) {
					index = index - 
						(2 * tws->number_of_lines 
						* tws->number_of_elements);
				}
		   	   } else {
				break;
		   	   }
		   	   hash_loop++;

			}
			if((k < tws->expansion_count) && 
					(tws->table[k][index] == new_entry)) {
				page_index = (offset & TWS_INDEX_MASK) >> 12;
				new_entry->page_cache &= 
					~((unsigned int)(1 << page_index));

				if(new_entry->page_cache == 0) {

					if(tws->style == 
						TWS_HASH_STYLE_SIGNAL) {
						vm_object_deallocate(
							new_entry->object);
						vm_map_deallocate(
							new_entry->map);
					}
					new_entry->object = 0;
					tws->table[k][index] = 0;
					current_line = new_entry->line;
					set = current_line/tws->number_of_lines;
					current_line = current_line - 
						(set * tws->number_of_lines);
					tws->cache[set]
						[current_line].ele_count--;
				}

			}
			break;
		}
	}

	index = do_tws_hash(object, offset, 
			tws->number_of_elements, tws->number_of_lines);
	alt_hash_count = 0;
	/* we will do MAX_REHASH hash attempts and then give up */
	while (alt_hash_count < TWS_MAX_REHASH) {
		for(k=0; k<tws->expansion_count; k++) {
	   		new_entry = tws->table[k][index];
			if(new_entry == NULL)
				continue;
			if((new_entry->object == object) && 
				(new_entry->offset == 
				(offset & TWS_HASH_OFF_MASK))) {
				new_entry->page_cache |= 
				(1<<(((vm_offset_t)
				(offset & TWS_INDEX_MASK))>>12));
				tws->alt_table[k][alt_index] =  new_entry;
				tws_unlock(tws);
				return KERN_SUCCESS;
			}
	   	}

		alt_hash_count += 1;
		index += 17;
		if(index >= (2 * 
			tws->number_of_lines * tws->number_of_elements))
			index = index - 
			(2 * tws->number_of_lines * tws->number_of_elements);
	}
	alt_hash_count = 0;
	index = do_tws_hash(object, offset,
			tws->number_of_elements, tws->number_of_lines);
	while (alt_hash_count < TWS_MAX_REHASH) {
		for(k=0; k<tws->expansion_count; k++) {
	   		new_entry = tws->table[k][index];
			if(new_entry == NULL)
				break;
	   	}

		if (k<tws->expansion_count)
			break;

		alt_hash_count += 1;
		index += 17;
		if(index >= (2 * 
			tws->number_of_lines * tws->number_of_elements))
			index = index - 
			(2 * tws->number_of_lines * tws->number_of_elements);
	}

	if(alt_hash_count == TWS_MAX_REHASH) {
		tws_unlock(tws);
		return KERN_FAILURE;
	}

	if(tws->style == TWS_HASH_STYLE_SIGNAL) {
		vm_object_reference(object);
		vm_map_reference(map);
	}

	if(current_line == 0xFFFFFFFF) {

		current_line = tws->current_line;
		set = current_line/tws->number_of_lines;
		current_line = current_line - (set * tws->number_of_lines);

		if(tws->cache[set][current_line].ele_count 
					>= tws->number_of_elements) {
			current_line++;
			tws->current_line++;
			if(current_line == tws->number_of_lines) {
				set++;
				current_line = 0;
				if (set == tws->expansion_count) {
				   if((tws->lookup_count <
				      (2 * tws->insert_count)) &&
				      (set<TWS_HASH_EXPANSION_MAX)) {
				      tws->lookup_count = 0;
				      tws->insert_count = 0;
				      if(tws->number_of_lines 
						< TWS_HASH_LINE_COUNT) {
					tws->current_line--;
					tws_unlock(tws);
					return KERN_NO_SPACE;
				      }
				      if((tws->table[set] = (tws_hash_ele_t *)
				         kalloc(sizeof(tws_hash_ele_t) 
						* 2 * tws->number_of_lines 
						* tws->number_of_elements)) 
								== NULL) {
				         set = 0;
				      } else if((tws->alt_table[set] = 
						(tws_hash_ele_t *)
			 			kalloc(sizeof(tws_hash_ele_t)
						* 2 * tws->number_of_lines 
						* tws->number_of_elements)) 
								== NULL) {
				         kfree((vm_offset_t)tws->table[set], 
						sizeof(tws_hash_ele_t) 
				       		* 2 * tws->number_of_lines 
						* tws->number_of_elements);
				         tws->table[set] = NULL;
				         set = 0;

				      } else if((tws->cache[set] = 
						(struct tws_hash_line *)
						kalloc(sizeof
						(struct tws_hash_line) 
						* tws->number_of_lines)) 
								== NULL) {
				         kfree((vm_offset_t)tws->table[set], 
							sizeof(tws_hash_ele_t) 
				               		* 2 * tws->number_of_lines 
							* tws->number_of_elements);
				         kfree((vm_offset_t)tws->alt_table[set], 
							sizeof(tws_hash_ele_t) 
				               		* 2 * tws->number_of_lines 
							* tws->number_of_elements);
				         tws->table[set] = NULL;
				         set = 0;
							
				      } else {
				         bzero((char *)tws->table[set], 
						sizeof(tws_hash_ele_t) 
						* 2 * tws->number_of_lines 
						* tws->number_of_elements);
				         bzero((char *)tws->alt_table[set], 
						sizeof(tws_hash_ele_t) 
						* 2 * tws->number_of_lines 
						* tws->number_of_elements);
				         bzero((char *)tws->cache[set], 
						sizeof(struct tws_hash_line) 
						* tws->number_of_lines);
				      }
				   } else {
				      tws->lookup_count = 0;
				      tws->insert_count = 0;
				      set = 0;
				   }
				}
				tws->current_line = set * tws->number_of_lines;
			}
			if(set < tws->expansion_count) {
			   tws_hash_line_clear(tws, 
				&(tws->cache[set][current_line]), TRUE);
			   if(tws->cache[set][current_line].ele_count 
						>= tws->number_of_elements) {
				if(tws->style == TWS_HASH_STYLE_SIGNAL) {
					vm_object_deallocate(object);
					vm_map_deallocate(map);
				}
				tws_unlock(tws);
				return KERN_FAILURE;
			   }
			} else {
				tws->expansion_count++;
			}
		}
	}

	ele_index = 0;
	for(i = 0; i<tws->number_of_elements; i++) {
		if(tws->cache[set][current_line].
			list[ele_index].object == 0) {
			break;
		}
		ele_index++;
		if(ele_index >= tws->number_of_elements)
			ele_index = 0;
		
	}

	if(i == tws->number_of_elements) 
		panic("tws_insert: no free elements");


	tws->cache[set][current_line].list[ele_index].object = object;
	tws->cache[set][current_line].list[ele_index].offset = 
						offset & TWS_HASH_OFF_MASK;
	tws->cache[set][current_line].
		list[ele_index].page_addr = page_addr & TWS_HASH_OFF_MASK;
	tws->cache[set][current_line].list[ele_index].map = map;
	tws->cache[set][current_line].list[ele_index].line = 
			current_line + (set * tws->number_of_lines);
	tws->cache[set][current_line].list[ele_index].page_cache =
			 1<<(((vm_offset_t)(offset & TWS_INDEX_MASK))>>12);

	tws->table[k][index] = &tws->cache[set][current_line].list[ele_index];
	for(alt_k=0; alt_k<tws->expansion_count; alt_k++) {
		if(tws->alt_table[alt_k][alt_index] == 0) {
			tws->alt_table[alt_k][alt_index] = 
				&tws->cache[set][current_line].list[ele_index];
			break;
		}
	}
	tws->cache[set][current_line].ele_count++;

	tws_unlock(tws);
	return KERN_SUCCESS;
}

/* 
 * tws_build_cluster
 * lengthen the cluster of pages by the number of pages encountered in the 
 * working set up to the limit requested by the caller.  The object needs
 * to be locked on entry.  The map does not because the tws_lookup function
 * is used only to find if their is an entry in the cache.  No transient
 * data from the cache is de-referenced.
 *
 */
#if	MACH_PAGEMAP
/*
 * MACH page map - an optional optimization where a bit map is maintained
 * by the VM subsystem for internal objects to indicate which pages of
 * the object currently reside on backing store.  This existence map
 * duplicates information maintained by the vnode pager.  It is 
 * created at the time of the first pageout against the object, i.e. 
 * at the same time pager for the object is created.  The optimization
 * is designed to eliminate pager interaction overhead, if it is 
 * 'known' that the page does not exist on backing store.
 *
 * LOOK_FOR() evaluates to TRUE if the page specified by object/offset is 
 * either marked as paged out in the existence map for the object or no 
 * existence map exists for the object.  LOOK_FOR() is one of the
 * criteria in the decision to invoke the pager.   It is also used as one
 * of the criteria to terminate the scan for adjacent pages in a clustered
 * pagein operation.  Note that LOOK_FOR() always evaluates to TRUE for
 * permanent objects.  Note also that if the pager for an internal object 
 * has not been created, the pager is not invoked regardless of the value 
 * of LOOK_FOR() and that clustered pagein scans are only done on an object
 * for which a pager has been created.
 *
 * PAGED_OUT() evaluates to TRUE if the page specified by the object/offset
 * is marked as paged out in the existence map for the object.  PAGED_OUT()
 * PAGED_OUT() is used to determine if a page has already been pushed
 * into a copy object in order to avoid a redundant page out operation.
 */
#define LOOK_FOR(o, f) (vm_external_state_get((o)->existence_map, (f)) \
			!= VM_EXTERNAL_STATE_ABSENT)
#define PAGED_OUT(o, f) (vm_external_state_get((o)->existence_map, (f)) \
			== VM_EXTERNAL_STATE_EXISTS)
#else /* MACH_PAGEMAP */
/*
 * If the MACH page map optimization is not enabled,
 * LOOK_FOR() always evaluates to TRUE.  The pager will always be 
 * invoked to resolve missing pages in an object, assuming the pager 
 * has been created for the object.  In a clustered page operation, the 
 * absence of a page on backing backing store cannot be used to terminate 
 * a scan for adjacent pages since that information is available only in 
 * the pager.  Hence pages that may not be paged out are potentially 
 * included in a clustered request.  The vnode pager is coded to deal 
 * with any combination of absent/present pages in a clustered 
 * pagein request.  PAGED_OUT() always evaluates to FALSE, i.e. the pager
 * will always be invoked to push a dirty page into a copy object assuming
 * a pager has been created.  If the page has already been pushed, the
 * pager will ingore the new request.
 */
#define LOOK_FOR(o, f) TRUE
#define PAGED_OUT(o, f) FALSE
#endif /* MACH_PAGEMAP */

void
tws_build_cluster(
		tws_hash_t		tws,
		vm_object_t		object,
		vm_object_offset_t	*start,
		vm_object_offset_t	*end,
		vm_size_t		max_length)
{
	tws_hash_line_t		line;
	task_t			task;
	vm_object_offset_t	before = *start;
	vm_object_offset_t	after =  *end;
	vm_size_t		length =  (vm_size_t)(*end - *start);
	vm_page_t		m;
	kern_return_t		kret;
	vm_object_offset_t	object_size;
	int		pre_heat_size;
	int		age_of_cache;

	if((object->private) || !(object->pager))
		return;

	if (!object->internal) {
		kret = vnode_pager_get_object_size(
       		 	object->pager,
			&object_size);
	} else {
		object_size = object->size;
	}
	/*
	 * determine age of cache in seconds
	 */
	age_of_cache = ((sched_tick - tws->time_of_creation) >> SCHED_TICK_SHIFT);
	
	if (object->internal || age_of_cache > 15 || (age_of_cache > 5 && vm_page_free_count < (vm_page_free_target * 2 ))) {
	        pre_heat_size = 0;
	} else {
	        if (object_size > (vm_object_offset_t)(1024 * 1024))
	                pre_heat_size = 8 * PAGE_SIZE;
	        else if (object_size > (vm_object_offset_t)(128 * 1024))
	                pre_heat_size = 4 * PAGE_SIZE;
	        else
	                pre_heat_size = 2 * PAGE_SIZE;
	}

	while ((length < max_length) &&
		(object_size >= 
			(after + PAGE_SIZE_64))) {

		if(length >= pre_heat_size)
		   {
		   if(tws_lookup(tws, after, object, 
				&line) != KERN_SUCCESS) {
			vm_object_offset_t	extend;
				
			extend = after + PAGE_SIZE_64;
			if(tws_lookup(tws, extend, object, 
						&line) != KERN_SUCCESS) {
				break;
			}
		  }
		 }
	        if (((object->existence_map != NULL)
					&& (!LOOK_FOR(object, after))) ||
				    	(vm_page_lookup(object, after)
						!= VM_PAGE_NULL)) {
			break;
		}
		if (object->internal) {
			/*
			 * need to acquire a real page in
			 * advance because this acts as
			 * a throttling mechanism for
			 * data_requests to the default
			 * pager.  If this fails, give up
			 * trying to find any more pages
			 * in the cluster and send off the
			 * request for what we already have.
			 */
			if ((m = vm_page_grab()) == VM_PAGE_NULL) {
				break;
			}
	        } else if ((m = vm_page_grab_fictitious())
			       	        == VM_PAGE_NULL) {
			break;
		}
		m->absent = TRUE;
		m->unusual = TRUE;
	        m->clustered = TRUE;
		m->list_req_pending = TRUE;

	        vm_page_insert(m, object, after);
		object->absent_count++;
		after += PAGE_SIZE_64;
		length += PAGE_SIZE;
	}
	*end = after;
	while (length < max_length) {
		if (before == 0) 
			break;
		before -= PAGE_SIZE_64;

		if(length >= pre_heat_size)
		   {

		   if(tws_lookup(tws, before, object, 
				&line) != KERN_SUCCESS) {
			vm_object_offset_t	extend;
				
			extend = before;
			if (extend == 0)
				break;
			extend -= PAGE_SIZE_64;
			if(tws_lookup(tws, extend, object, 
					&line) != KERN_SUCCESS) {
				break;
			}
		  }
		 }
		if (((object->existence_map != NULL) 
					&& (!LOOK_FOR(object, before))) ||
				    	(vm_page_lookup(object, before)
						!= VM_PAGE_NULL)) {
			break;
		}
		if (object->internal) {
			/*
			 * need to acquire a real page in
			 * advance because this acts as
			 * a throttling mechanism for
			 * data_requests to the default
			 * pager.  If this fails, give up
			 * trying to find any more pages
			 * in the cluster and send off the
			 * request for what we already have.
			 */
			if ((m = vm_page_grab()) == VM_PAGE_NULL) {
				break;
			}
	        } else if ((m = vm_page_grab_fictitious())
			       	        == VM_PAGE_NULL) {
			break;
	        }
	        m->absent = TRUE;
		m->unusual = TRUE;
	        m->clustered = TRUE;
		m->list_req_pending = TRUE;

	        vm_page_insert(m, object, before);
		object->absent_count++;
		*start -= PAGE_SIZE_64;
		length += PAGE_SIZE;
	}
}

tws_line_signal(
	tws_hash_t	tws,
	vm_map_t	map,
	tws_hash_line_t hash_line,
	vm_offset_t	target_page)
{
	unsigned int		i,j;
	vm_object_t		object;
	vm_object_offset_t	offset;
	vm_object_offset_t	before;
	vm_object_offset_t	after;
	struct tws_hash_ele	*element;
	vm_page_t		m,p;
	kern_return_t		rc;

	if(tws->style != TWS_HASH_STYLE_SIGNAL)
		return;

	vm_map_lock(map);
	for (i=0; i<tws->number_of_elements; i++) {

		vm_object_offset_t local_off = 0;

		if(hash_line->list[i].object == 0)
			continue;

		element = &hash_line->list[i];

		if (element->page_addr == target_page)
			continue;

		j = 1;
		while (j != 0) {
			if(j & element->page_cache)
				break;
			j << 1;
			local_off += PAGE_SIZE_64;
		}
		object = element->object;
		offset = element->offset + local_off;

		/* first try a fast test to speed up no-op signal */
		if (((p = vm_page_lookup(object, offset)) != NULL) 
			|| (object->pager == NULL) 
			|| (object->shadow_severed)) {
			continue;
		}	

		if((!object->alive) || 
			(!object->pager_created) || (!object->pager_ready))
			continue;

                if (object->internal) { 
			if (object->existence_map == NULL) {
				if (object->shadow)
					continue;
			} else {
				if(!LOOK_FOR(object, offset))
					continue;
			}
		}

		vm_object_reference(object);
		vm_map_unlock(map);
			
		if(object->internal) {
			m = vm_page_grab();
		} else {
			m = vm_page_grab_fictitious();
		}

		if(m == NULL) {
			vm_object_deallocate(object);
			vm_map_lock(map);
			continue;
		}

		vm_object_lock(object);
		if (((p = vm_page_lookup(object, offset)) != NULL) 
			|| (object->pager == NULL) 
			|| (object->shadow_severed)) {
			VM_PAGE_FREE(m);
			vm_object_unlock(object);
			vm_object_deallocate(object);
			vm_map_lock(map);
			continue;
		}

		vm_page_insert(m, object, offset);

		if (object->absent_count > vm_object_absent_max) {
			VM_PAGE_FREE(m);
			vm_object_unlock(object);
			vm_object_deallocate(object);
			vm_map_lock(map);
			break;
		}
		m->list_req_pending = TRUE; 
		m->absent = TRUE; 
		m->unusual = TRUE; 
		object->absent_count++;

		before = offset;
		after = offset + PAGE_SIZE_64;
		tws_build_cluster(tws, object, &before, &after, 0x16000);
		vm_object_unlock(object);

		rc = memory_object_data_request(object->pager, 
				before + object->paging_offset, 
				(vm_size_t)(after - before), VM_PROT_READ);
		if (rc != KERN_SUCCESS) {
			offset = before;
			vm_object_lock(object);
			while (offset < after) {
                        	m = vm_page_lookup(object, offset);
				if(m && m->absent && m->busy)
					VM_PAGE_FREE(m);
				offset += PAGE_SIZE;
			}
			vm_object_unlock(object);
			vm_object_deallocate(object);
		} else {
			vm_object_deallocate(object);
		}
		vm_map_lock(map);
		continue;
	}
	vm_map_unlock(map);
}



void
tws_hash_destroy(tws_hash_t	tws)
{
	int	i,k;
	vm_size_t	cache_size;

	for (i=0; i<tws->number_of_lines; i++) {
		for(k=0; k<tws->expansion_count; k++) {
			/* clear the object refs */
			tws_hash_line_clear(tws, &(tws->cache[k][i]), FALSE);
		}
	}
	i = 0;
	while (i < tws->expansion_count) {
		
		kfree((vm_offset_t)tws->table[i], sizeof(tws_hash_ele_t) 
				* 2 * tws->number_of_lines 
				* tws->number_of_elements);
		kfree((vm_offset_t)tws->alt_table[i], sizeof(tws_hash_ele_t) 
				* 2 * tws->number_of_lines 
				* tws->number_of_elements);
		kfree((vm_offset_t)tws->cache[i], sizeof(struct tws_hash_line) 
				* tws->number_of_lines);
		i++;
	}
	kfree((vm_offset_t)tws, sizeof(struct tws_hash));
}

void
tws_hash_clear(tws_hash_t	tws)
{
	int	i, k;

	for (i=0; i<tws->number_of_lines; i++) {
		for(k=0; k<tws->expansion_count; k++) {
			/* clear the object refs */
			tws_hash_line_clear(tws, &(tws->cache[k][i]), FALSE);
		}
	}
}

kern_return_t
task_working_set_create(
	task_t	task, 
	unsigned int lines, 
	unsigned int rows,
	unsigned int style)
{

	if (lines == 0) {
		lines = TWS_HASH_LINE_COUNT;
	}
	if (rows == 0) {
		rows = TWS_ARRAY_SIZE;
	}
	if (style == TWS_HASH_STYLE_DEFAULT) {
		style = TWS_HASH_STYLE_BASIC;
	}
	task_lock(task);
	if(task->dynamic_working_set != 0) {
		task_unlock(task);
		return(KERN_FAILURE);
	} else if((task->dynamic_working_set 
		= (vm_offset_t) tws_hash_create(lines, rows, style)) == 0) {
		task_unlock(task);
		return(KERN_NO_SPACE);
	}
	task_unlock(task);
	return KERN_SUCCESS;
}
