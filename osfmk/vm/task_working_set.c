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
 */
/*
 *	File:	vm/task_working_set.c
 *	Author:	Chris Youngworth
 *	Date:	2001
 *
 *	Working set detection and maintainence module
 */


#include <mach/mach_types.h>
#include <mach/memory_object.h>
#include <mach/shared_memory_server.h>
#include <vm/task_working_set.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <kern/sched.h>
#include <kern/kalloc.h>

#include <vm/vm_protos.h>

/*
 * LP64todo - Task Working Set Support is for 32-bit only
 */
extern zone_t lsf_zone;

/* declarations for internal use only routines */
int	startup_miss = 0;

tws_hash_t
tws_hash_create(
	unsigned int lines,
	unsigned int rows,
	unsigned int style);

kern_return_t
tws_write_startup_file(
	task_t		task,
	int		fid,
	int		mod,
	char		*name,
	unsigned int	string_length);

kern_return_t
tws_read_startup_file(
	task_t		task,
	tws_startup_t	startup,
	vm_offset_t	cache_size);

tws_startup_t
tws_create_startup_list(
	tws_hash_t	tws);

unsigned int
tws_startup_list_lookup(
        tws_startup_t   startup,
        vm_offset_t     addr);

kern_return_t
tws_internal_startup_send(
	tws_hash_t	tws);

void
tws_hash_line_clear(
	tws_hash_t	tws,
	tws_hash_line_t hash_line,
	vm_object_t	object,
	boolean_t live);

void
tws_hash_clear(
	tws_hash_t	tws);

void
tws_traverse_address_hash_list (
	tws_hash_t 		tws, 
	unsigned int		index,
	vm_offset_t		page_addr,
	vm_object_t		object,
	vm_object_offset_t	offset,
	vm_map_t		map,
	tws_hash_ptr_t		*target_ele,
	tws_hash_ptr_t		**previous_ptr,
	tws_hash_ptr_t		**free_list,
	unsigned int		exclusive_addr);

void
tws_traverse_object_hash_list (
	tws_hash_t 		tws, 
	unsigned int		index,
	vm_object_t		object,
	vm_object_offset_t	offset,
	unsigned int		pagemask,
	tws_hash_ptr_t		*target_ele,
	tws_hash_ptr_t		**previous_ptr,
	tws_hash_ptr_t		**free_list);

tws_hash_ptr_t
new_addr_hash(
	tws_hash_t tws, 
	unsigned int set, 
	unsigned int index);

tws_hash_ptr_t
new_obj_hash(
	tws_hash_t tws, 
	unsigned int set, 
	unsigned int index);

int tws_test_for_community(
		tws_hash_t		tws, 
		vm_object_t		object, 
		vm_object_offset_t	offset, 
		unsigned int		threshold, 
		unsigned int		*pagemask);

kern_return_t
tws_internal_lookup(
	tws_hash_t		tws,	
	vm_object_offset_t	offset, 
	vm_object_t		object,
	tws_hash_line_t		 *line);

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
	
	if ((style != TWS_HASH_STYLE_BASIC) &&
			(style != TWS_HASH_STYLE_BASIC)) {
		return((tws_hash_t)NULL);
	}

	
	tws = (tws_hash_t)(kalloc(sizeof(struct tws_hash)));
	if(tws == (tws_hash_t)NULL)
		return tws;

	if((tws->table[0] = (tws_hash_ptr_t *)
			kalloc(sizeof(tws_hash_ptr_t) * lines * rows)) 
								== NULL) {
		kfree(tws, sizeof(struct tws_hash));
		return (tws_hash_t)NULL;
	}
	if((tws->table_ele[0] = (tws_hash_ptr_t)
			kalloc(sizeof(struct tws_hash_ptr) * lines * rows)) 
								== NULL) {
		kfree(tws->table[0], sizeof(tws_hash_ptr_t) * lines * rows);
		kfree(tws, sizeof(struct tws_hash));
		return (tws_hash_t)NULL;
	}
	if((tws->alt_ele[0] = (tws_hash_ptr_t)
			kalloc(sizeof(struct tws_hash_ptr) * lines * rows))
								== NULL) {
		kfree(tws->table[0], sizeof(tws_hash_ptr_t) * lines * rows);
		kfree(tws->table_ele[0],
		      sizeof(struct tws_hash_ptr) * lines * rows);
		kfree(tws, sizeof(struct tws_hash));
		return (tws_hash_t)NULL;
	}
	if((tws->cache[0] = (struct tws_hash_line *)
			kalloc(sizeof(struct tws_hash_line) * lines))
								== NULL) {
		kfree(tws->table[0], sizeof(tws_hash_ptr_t) * lines * rows);
		kfree(tws->table_ele[0],
		      sizeof(struct tws_hash_ptr) * lines * rows);
		kfree(tws->alt_ele[0],
		      sizeof(struct tws_hash_ptr) * lines * rows);
		kfree(tws, sizeof(struct tws_hash));
		return (tws_hash_t)NULL;
	}
	tws->free_hash_ele[0] = (tws_hash_ptr_t)0;
	tws->obj_free_count[0] = 0;
	tws->addr_free_count[0] = 0;

	/* most defaults are such that a bzero will initialize */
	bzero((char *)tws->table[0],sizeof(tws_hash_ptr_t)
                                	* lines * rows);
	bzero((char *)tws->table_ele[0],sizeof(struct tws_hash_ptr)
                                	* lines * rows);
	bzero((char *)tws->alt_ele[0],sizeof(struct tws_hash_ptr)
                                	* lines * rows);
	bzero((char *)tws->cache[0], sizeof(struct tws_hash_line) 
					* lines);

	mutex_init(&tws->lock, 0);
	tws->style = style;
	tws->current_line = 0;
	tws->pageout_count = 0;
	tws->line_count = 0;
	tws->startup_cache = NULL;
	tws->startup_name = NULL;
	tws->number_of_lines = lines;
	tws->number_of_elements = rows;
	tws->expansion_count = 1;
	tws->lookup_count = 0;
	tws->insert_count = 0;
	tws->time_of_creation = sched_tick;

	return tws;
}


extern vm_page_t
vm_page_lookup_nohint(vm_object_t object, vm_object_offset_t offset);


void
tws_hash_line_clear(
	tws_hash_t	tws,
	tws_hash_line_t hash_line,
	__unused vm_object_t	object,
	boolean_t live)
{
	struct tws_hash_ele	*hash_ele;
	struct tws_hash_ptr	**trailer;
	struct tws_hash_ptr	**free_list;
	tws_hash_ele_t		addr_ele;
	int			index;
	unsigned int		i, j;
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
	
			vm_object_offset_t local_off = 0;
			tws_hash_ptr_t	cache_ele;
	
			index = alt_tws_hash(
				hash_ele->page_addr & TWS_ADDR_OFF_MASK,
				tws->number_of_elements, 
				tws->number_of_lines);
	
			tws_traverse_address_hash_list(tws, index, 
				hash_ele->page_addr, hash_ele->object,
				hash_ele->offset, hash_ele->map,
				&cache_ele, &trailer, &free_list, 0);
			if(cache_ele != NULL) {
				addr_ele = (tws_hash_ele_t)((unsigned int)
				   (cache_ele->element) & ~TWS_ADDR_HASH);
				if(addr_ele != hash_ele)
					panic("tws_hash_line_clear:"
						" out of sync\n");
				cache_ele->element = 0;
				*trailer = cache_ele->next;
				cache_ele->next = *free_list;
				*free_list = cache_ele;
			}
	
			index = alt_tws_hash(
				(hash_ele->page_addr - 0x1f000) 
						& TWS_ADDR_OFF_MASK,
				tws->number_of_elements, 
				tws->number_of_lines);

			tws_traverse_address_hash_list(tws, index, 
				hash_ele->page_addr, hash_ele->object, 
				hash_ele->offset, hash_ele->map,
				&cache_ele, &trailer, &free_list, 0);

			if(cache_ele != NULL) {
				addr_ele = (tws_hash_ele_t)((unsigned int)
				   (cache_ele->element) & ~TWS_ADDR_HASH);
				if(addr_ele != hash_ele)
					panic("tws_hash_line_clear: "
						"out of sync\n");
				cache_ele->element = 0;
				*trailer = cache_ele->next;
				cache_ele->next = *free_list;
				*free_list = cache_ele;
			}
	
	
			if((hash_ele->map != NULL) && (live)) {
				vm_page_t	p;
				
#if 0
				if (object != hash_ele->object) {
				    if (object)
				        vm_object_unlock(object);
				    vm_object_lock(hash_ele->object);
				}
#endif
				if (dump_pmap == 1) {
				    for (j = 0x1; j != 0; j = j<<1) {
				        if(j & hash_ele->page_cache) {
					    p = vm_page_lookup_nohint(hash_ele->object, 
								      hash_ele->offset + local_off);
					    if((p != NULL) && (p->wire_count == 0)) {
					        pmap_remove_some_phys((pmap_t)vm_map_pmap(current_map()),
								      p->phys_page);
					    }
					}
					local_off += PAGE_SIZE_64;
				    }
				}
#if 0
				if (object != hash_ele->object) {
				    vm_object_unlock(hash_ele->object);
				    if (object)
				        vm_object_lock(object);
				}
#endif
			}
	
			if(tws->style == TWS_HASH_STYLE_SIGNAL) {
				vm_object_deallocate(hash_ele->object);
				vm_map_deallocate(hash_ele->map);
			}

			index = do_tws_hash(hash_ele->object, hash_ele->offset,
					tws->number_of_elements, 
					tws->number_of_lines);

			tws_traverse_object_hash_list(tws,
				index, hash_ele->object, hash_ele->offset,
				0xFFFFFFFF, &cache_ele, &trailer, &free_list);
			if((cache_ele != NULL) && (cache_ele->element == hash_ele)) {
				cache_ele->element = 0;
				*trailer = cache_ele->next;
				cache_ele->next = *free_list;
				*free_list = cache_ele;
			}
			hash_ele->object = 0;
		}
	}
}

kern_return_t
tws_internal_lookup(
	tws_hash_t		tws,	
	vm_object_offset_t	offset, 
	vm_object_t		object,
	tws_hash_line_t		 *line) 
{
	int			index;
	int			loop;
	int		  	set; 
	int			ele_line;
	vm_offset_t		pagenum;
	tws_hash_ptr_t		cache_ele;
	tws_hash_ptr_t		*trailer;
	tws_hash_ptr_t		*free_list;

	/* don't cache private objects */
	if(object->private)
		return KERN_SUCCESS;

	index = do_tws_hash(object, offset, 
			tws->number_of_elements, tws->number_of_lines);
	loop = 0;

	tws->lookup_count++; 
	if(tws->lookup_count == 0)
		tws->insert_count = 0;
	if(tws->startup_name != NULL) {
		int age_of_cache;
		age_of_cache = ((sched_tick 
			- tws->time_of_creation) >> SCHED_TICK_SHIFT);
       		if (age_of_cache > 45) {
			return KERN_OPERATION_TIMED_OUT;
		}
	}

	if(tws->lookup_count > (4 * tws->expansion_count 
			* tws->number_of_elements * tws->number_of_lines) &&
			(tws->lookup_count > (2 * tws->insert_count))) {
		if(tws->startup_cache) {
			int age_of_cache;
			age_of_cache = ((sched_tick 
				- tws->time_of_creation) >> SCHED_TICK_SHIFT);
	        	if (age_of_cache > 45) {
				return KERN_OPERATION_TIMED_OUT;
			}
      		}
	}

	pagenum = (vm_offset_t)(offset & TWS_INDEX_MASK);
	pagenum = pagenum >> 12;
	pagenum = 1 << pagenum;  /* get the appropriate page in 32 page block */
	tws_traverse_object_hash_list(tws, index, object, offset, pagenum,
		&cache_ele, &trailer, &free_list);
	if(cache_ele != NULL) {
		set = cache_ele->element->line/tws->number_of_lines;
		ele_line = cache_ele->element->line - set;
		*line = &tws->cache[set][ele_line];
		return KERN_SUCCESS;
	}

	return KERN_FAILURE;


}

kern_return_t
tws_lookup(
	tws_hash_t		tws,	
	vm_object_offset_t	offset, 
	vm_object_t		object,
	tws_hash_line_t		 *line) 
{
	kern_return_t kr;

	if(!tws_lock_try(tws)) {
		return KERN_FAILURE;
	}
	kr = tws_internal_lookup(tws,
		offset, object, line);
	tws_unlock(tws);
	return kr;
}

kern_return_t
tws_expand_working_set(
	tws_hash_t	old_tws, 
	unsigned int	line_count,
	boolean_t	dump_data)
{
	tws_hash_t		new_tws;
	unsigned int		i,j,k;
	struct	tws_hash	temp;

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
	
	if(!dump_data) {
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
					page_index = page_index << 1) {
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
		temp.obj_free_count[i] = new_tws->obj_free_count[i];
		temp.addr_free_count[i] = new_tws->addr_free_count[i];
		temp.free_hash_ele[i] = new_tws->free_hash_ele[i];
		temp.table[i] = new_tws->table[i];
		temp.table_ele[i] = new_tws->table_ele[i];
		temp.alt_ele[i] = new_tws->alt_ele[i];
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
		new_tws->obj_free_count[i] = old_tws->obj_free_count[i];
		new_tws->addr_free_count[i] = old_tws->addr_free_count[i];
		new_tws->free_hash_ele[i] = old_tws->free_hash_ele[i];
		new_tws->table[i] = old_tws->table[i];
		new_tws->table_ele[i] = old_tws->table_ele[i];
		new_tws->alt_ele[i] = old_tws->alt_ele[i];
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
		old_tws->obj_free_count[i] = temp.obj_free_count[i];;
		old_tws->addr_free_count[i] = temp.addr_free_count[i];;
		old_tws->free_hash_ele[i] = NULL;
		old_tws->table[i] = temp.table[i];
		old_tws->table_ele[i] = temp.table_ele[i];
		old_tws->alt_ele[i] = temp.alt_ele[i];
		old_tws->cache[i] = temp.cache[i];
	}

	tws_hash_destroy(new_tws);
	tws_unlock(old_tws);
	return	KERN_SUCCESS;
}

tws_hash_t	test_tws = 0;

kern_return_t
tws_insert(
	tws_hash_t		tws, 
	vm_object_offset_t	offset,
	vm_object_t		object,
	vm_offset_t		page_addr,
	vm_map_t		map)
{
	unsigned int		index;
	unsigned int		alt_index;
	unsigned int		index_enum[2];
	unsigned int		ele_index;
	tws_hash_ptr_t		cache_ele;
	tws_hash_ptr_t		obj_ele = NULL;
	tws_hash_ptr_t		addr_ele = NULL;
	tws_hash_ptr_t		*trailer;
	tws_hash_ptr_t		*free_list;
	tws_hash_ele_t		target_element = NULL;
	unsigned int		i;
	unsigned int		current_line;
	unsigned int		set;
	int			ctr;
	unsigned int		startup_cache_line;
        int			age_of_cache = 0;

	if(!tws_lock_try(tws)) {
		return KERN_FAILURE;
	}
	tws->insert_count++;
	current_line = 0xFFFFFFFF;
	set = 0;

	startup_cache_line = 0;

	if (tws->startup_cache) {
	        vm_offset_t	startup_page_addr;

	        startup_page_addr = page_addr - (offset - (offset & TWS_HASH_OFF_MASK));

		age_of_cache = ((sched_tick - tws->time_of_creation) >> SCHED_TICK_SHIFT);

		startup_cache_line = tws_startup_list_lookup(tws->startup_cache, startup_page_addr);
	}
	/* This next bit of code, the and alternate hash */
	/* are all made necessary because of IPC COW     */

	/* Note: the use of page_addr modified by delta from offset */
	/* frame base means we may miss some previous entries.  However */
	/* we will not miss the present entry.  This is most important */
	/* in avoiding duplication of entries against long lived non-cow */
	/* objects */
	index_enum[0] = alt_tws_hash(
			page_addr & TWS_ADDR_OFF_MASK,
			tws->number_of_elements, tws->number_of_lines);

	index_enum[1] = alt_tws_hash(
			(page_addr - 0x1f000) & TWS_ADDR_OFF_MASK,
			tws->number_of_elements, tws->number_of_lines);

	for(ctr = 0; ctr < 2;) {
		tws_hash_ele_t	resident;
		tws_traverse_address_hash_list(tws, 
				index_enum[ctr], page_addr, NULL,
				0, NULL,
				&cache_ele, &trailer, &free_list, 1);
		if(cache_ele != NULL) {
			/* found one */
			resident = (tws_hash_ele_t)((unsigned int)
					cache_ele->element & ~TWS_ADDR_HASH);
	   		if((object == resident->object) &&
				resident->offset == 
					(offset & TWS_HASH_OFF_MASK)) {
				/* This is our object/offset */
				resident->page_cache 
						|= startup_cache_line;
	      			resident->page_cache |= 
				   (1<<(((vm_offset_t)
				   (offset & TWS_INDEX_MASK))>>12));
				tws_unlock(tws);
				if (age_of_cache > 45)
					return KERN_OPERATION_TIMED_OUT;
				return KERN_SUCCESS;
			}
	   		if((object->shadow ==
				resident->object) && 
				((resident->offset 
				+ object->shadow_offset) 
				== (offset & TWS_HASH_OFF_MASK))) {
				/* if we just shadowed, inherit */
				/* access pattern from  parent */
				startup_cache_line |= 
				   resident->page_cache;
				/* thow out old entry */
				resident->page_cache = 0;
				break;
			} else {
	      			resident->page_cache &= 
				   ~(1<<(((vm_offset_t)(page_addr 
					- resident->page_addr))
				   	>>12));
			}
			/* Throw out old entry if there are no */
			/* more pages in cache */
			if(resident->page_cache == 0) {
				/* delete addr hash entry */
				cache_ele->element = 0;
				*trailer = cache_ele->next;
				cache_ele->next = *free_list;
				*free_list = cache_ele;
				/* go after object hash */
				index = do_tws_hash(
					resident->object, 
					resident->offset,
					tws->number_of_elements, 
					tws->number_of_lines);
				tws_traverse_object_hash_list(tws,
					index, resident->object, 
					resident->offset,
					0xFFFFFFFF, &cache_ele,
					&trailer, &free_list);
				if(cache_ele != NULL) {
					if(tws->style == 
					   TWS_HASH_STYLE_SIGNAL) {
						vm_object_deallocate(
						   cache_ele->element->object);
						vm_map_deallocate(
						   cache_ele->element->map);
					}
					current_line = 
					   cache_ele->element->line;
					set = current_line
						/tws->number_of_lines;
					current_line -= set *
						tws->number_of_lines;
					if(cache_ele->element->object != 0) {
						cache_ele->element->object = 0;
						tws->cache[set]
							[current_line].ele_count--;
					}
					cache_ele->element = 0;
					*trailer = cache_ele->next;
					cache_ele->next = *free_list;
					*free_list = cache_ele;
				}
			}
			continue;
		}
		ctr+=1;
	}

	/* 
	 * We may or may not have a current line setting coming out of
	 * the code above.  If we have a current line it means we can
	 * choose to back-fill the spot vacated by a previous entry.
	 * We have yet to do a definitive check using the original obj/off
	 * We will do that now and override the current line if we
	 * find an element
	 */

	index = do_tws_hash(object, offset, 
			tws->number_of_elements, tws->number_of_lines);

	alt_index = index_enum[0];

	tws_traverse_object_hash_list(tws, index, object, offset,
			0xFFFFFFFF, &cache_ele, &trailer, &free_list);
	if(cache_ele != NULL) {
		obj_ele = cache_ele;
		current_line = cache_ele->element->line;
		set = current_line/tws->number_of_lines;
		current_line -= set * tws->number_of_lines;
		target_element = cache_ele->element;

		/* Now check to see if we have a hash addr for it */
		tws_traverse_address_hash_list(tws, 
				alt_index, obj_ele->element->page_addr,
				obj_ele->element->object,
				obj_ele->element->offset,
				obj_ele->element->map,
				&cache_ele, &trailer, &free_list, 0);
		if(cache_ele != NULL) {
			addr_ele = cache_ele;
		} else  {
			addr_ele = new_addr_hash(tws, set, alt_index);
			/* if cannot allocate just do without */
			/* we'll get it next time around */
		}
	}



	if(tws->style == TWS_HASH_STYLE_SIGNAL) {
		vm_object_reference(object);
		vm_map_reference(map);
	}

	if(current_line == 0xFFFFFFFF) {
		current_line = tws->current_line;
		set = current_line/tws->number_of_lines;
		current_line = current_line - (set * tws->number_of_lines);

#ifdef notdef
		if(cache_full) {
			tws->current_line = tws->number_of_lines - 1;
		}
#endif
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
				      /* object persistence is guaranteed by */
				      /* an elevated paging or object        */
				      /* reference count in the caller. */
				      vm_object_unlock(object);
				      if((tws->table[set] = (tws_hash_ptr_t *)
				         kalloc(sizeof(tws_hash_ptr_t) 
						* tws->number_of_lines 
						* tws->number_of_elements)) 
								== NULL) {
				         set = 0;
				      } else if((tws->table_ele[set] = 
					(tws_hash_ptr_t)
				         kalloc(sizeof(struct tws_hash_ptr) 
						* tws->number_of_lines 
						* tws->number_of_elements)) 
								== NULL) {
				         kfree(tws->table[set], 
					       sizeof(tws_hash_ptr_t) 
					       * tws->number_of_lines 
					       * tws->number_of_elements);
				         set = 0;
				      } else if((tws->alt_ele[set] = 
						(tws_hash_ptr_t)
			 		 kalloc(sizeof(struct tws_hash_ptr)
						* tws->number_of_lines 
						* tws->number_of_elements)) 
								== NULL) {
				         kfree(tws->table_ele[set], 
					       sizeof(struct tws_hash_ptr) 
					       * tws->number_of_lines 
					       * tws->number_of_elements);
				         kfree(tws->table[set], 
					       sizeof(tws_hash_ptr_t) 
				       		* tws->number_of_lines 
						* tws->number_of_elements);
				         tws->table[set] = NULL;
				         set = 0;

				      } else if((tws->cache[set] = 
						(struct tws_hash_line *)
						kalloc(sizeof
						(struct tws_hash_line) 
						* tws->number_of_lines)) 
								== NULL) {
				         kfree(tws->alt_ele[set], 
					       sizeof(struct tws_hash_ptr) 
					       * tws->number_of_lines 
					       * tws->number_of_elements);
					 kfree(tws->table_ele[set], 
					       sizeof(struct tws_hash_ptr) 
					       * tws->number_of_lines 
					       * tws->number_of_elements);
				         kfree(tws->table[set], 
					       sizeof(tws_hash_ptr_t) 
					       * tws->number_of_lines 
					       * tws->number_of_elements);
				         tws->table[set] = NULL;
				         set = 0;
							
				      } else {
					 tws->free_hash_ele[set] = 
							(tws_hash_ptr_t)0;
					 tws->obj_free_count[set] = 0;
					 tws->addr_free_count[set] = 0;
				         bzero((char *)tws->table[set], 
						sizeof(tws_hash_ptr_t) 
						* tws->number_of_lines 
						* tws->number_of_elements);
				         bzero((char *)tws->table_ele[set], 
						sizeof(struct tws_hash_ptr) 
						* tws->number_of_lines 
						* tws->number_of_elements);
				         bzero((char *)tws->alt_ele[set], 
						sizeof(struct tws_hash_ptr) 
						* tws->number_of_lines 
						* tws->number_of_elements);
				         bzero((char *)tws->cache[set], 
						sizeof(struct tws_hash_line) 
						* tws->number_of_lines);
				      }
				      vm_object_lock(object);
				   } else {
				      if (tws->startup_name != NULL) {
						tws->current_line--;

						age_of_cache = ((sched_tick - tws->time_of_creation) >> SCHED_TICK_SHIFT);

						tws_unlock(tws);

						if (age_of_cache > 45)
						        return KERN_OPERATION_TIMED_OUT;

						return KERN_FAILURE;
				      }
				      tws->lookup_count = 0;
				      tws->insert_count = 0;
				      set = 0;
				   }
				}
				tws->current_line = set * tws->number_of_lines;
			}
			if(set < tws->expansion_count) {
			   tws_hash_line_clear(tws, 
				&(tws->cache[set][current_line]), object, TRUE);
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


	/* set object hash element */
	if(obj_ele == NULL) {
		obj_ele = new_obj_hash(tws, set, index);
		if(obj_ele == NULL) {
			tws->cache[set][current_line].ele_count 
				= tws->number_of_elements;
			tws_unlock(tws);
			return KERN_FAILURE;
		}
	}

	/* set address hash element */
	if(addr_ele == NULL) {
		addr_ele = new_addr_hash(tws, set, alt_index);
	}

	if(target_element == NULL) {
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

		target_element = 
			&(tws->cache[set][current_line].list[ele_index]);

		tws->cache[set][current_line].ele_count++;
	}

	obj_ele->element = target_element;
	if(addr_ele) {
		addr_ele->element = (tws_hash_ele_t)
			(((unsigned int)target_element) | TWS_ADDR_HASH);
	}
	target_element->object = object;
	target_element->offset = offset & TWS_HASH_OFF_MASK;
	target_element->page_addr = 
			page_addr - (offset - (offset & TWS_HASH_OFF_MASK));
	target_element->map = map;
	target_element->line = 
			current_line + (set * tws->number_of_lines);

	target_element->page_cache |= startup_cache_line;
	target_element->page_cache |= 1<<(((vm_offset_t)(offset & TWS_INDEX_MASK))>>12);

	tws_unlock(tws);

	if (age_of_cache > 45)
		return KERN_OPERATION_TIMED_OUT;

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
	vm_object_offset_t	before = *start;
	vm_object_offset_t	after =  *end;
	vm_object_offset_t	original_start = *start;
	vm_object_offset_t	original_end = *end;
	vm_size_t		length =  (vm_size_t)(*end - *start);
	vm_page_t		m;
	kern_return_t		kret;
	vm_object_offset_t	object_size;
	int			age_of_cache;
	vm_size_t		pre_heat_size;
	unsigned int		ele_cache;
	unsigned int		end_cache = 0;
	unsigned int		start_cache = 0;
	unsigned int		memory_scarce = 0;

	if((object->private) || !(object->pager))
		return;

	if (!object->internal) {
		/* XXX FBDP !internal doesn't mean vnode pager */
		kret = vnode_pager_get_object_size(
       		 	object->pager,
			&object_size);
		if (kret != KERN_SUCCESS) {
			object_size = object->size;
		}
	} else {
		object_size = object->size;
	}

	if((!tws) || (!tws_lock_try(tws))) {
		return;
	}
	age_of_cache = ((sched_tick 
			- tws->time_of_creation) >> SCHED_TICK_SHIFT);

	if (vm_page_free_count < (2 * vm_page_free_target))
	        memory_scarce = 1;

	/* When pre-heat files are not available, resort to speculation */
	/* based on size of file */

	if (tws->startup_cache || object->internal || age_of_cache > 45) {
		pre_heat_size = 0;
	} else {
		if (object_size > (vm_object_offset_t)(1024 * 1024))
			pre_heat_size = 8 * PAGE_SIZE;
		else if (object_size > (vm_object_offset_t)(128 * 1024))
			pre_heat_size = 4 * PAGE_SIZE;
		else
			pre_heat_size = 2 * PAGE_SIZE;
	}

       	if (tws->startup_cache) {
	        int target_page_count;

		if (memory_scarce)
		        target_page_count = 16;
		else
		        target_page_count = 4;

	        if (tws_test_for_community(tws, object, *start, target_page_count, &ele_cache))
		{
	                start_cache = ele_cache;
			*start = *start & TWS_HASH_OFF_MASK;
			*end = *start + (32 * PAGE_SIZE_64);

			if (*end > object_size) {
				*end = round_page_64(object_size);
				max_length = 0;
			} else
			        end_cache = ele_cache;

			while (max_length > ((*end - *start) + (32 * PAGE_SIZE))) {
			        int	expanded;

				expanded = 0;
				after = *end;

				if ((after + (32 * PAGE_SIZE_64)) <= object_size &&
				    (tws_test_for_community(tws, object, after, 8, &ele_cache))) {

					*end = after + (32 * PAGE_SIZE_64);
					end_cache = ele_cache;
					expanded = 1;
				}
				if (max_length < ((*end - *start) + (32 * PAGE_SIZE_64))) {
					break;
				}
				if (*start) {
				        before = (*start - PAGE_SIZE_64) & TWS_HASH_OFF_MASK;

					if (tws_test_for_community(tws, object, before, 8, &ele_cache)) {

					        *start = before;
						start_cache = ele_cache;
						expanded = 1;
					}
				}
				if (expanded == 0)
					break;
			}
			if (end_cache)
			        *end -= PAGE_SIZE_64;

			if (start_cache != 0) {
				unsigned int mask;

				for (mask = 1; mask != 0; mask = mask << 1) {
			        	if (*start == original_start)
				        	break;
					if (!(start_cache & mask))
						*start += PAGE_SIZE_64;
					else
						break;
				}
			}
			if (end_cache != 0) {
				unsigned int mask;

				for (mask = 0x80000000; 
						mask != 0; mask = mask >> 1) {
			        	if (*end == original_end)
				       		 break;
					if (!(end_cache & mask))
						*end -= PAGE_SIZE_64;
					else
						break;
				}
			}
			tws_unlock(tws);

			if (*end < original_end)
			        *end = original_end;
			return;
		}
	}

	while ((length < max_length) &&
		(object_size >= 
			(after + PAGE_SIZE_64))) {
		if(length >= pre_heat_size) {
		   if(tws_internal_lookup(tws, after, object,
				&line) != KERN_SUCCESS) {
			vm_object_offset_t	extend;
				
			extend = after + PAGE_SIZE_64;
			if(tws_internal_lookup(tws, extend, object,
						&line) != KERN_SUCCESS) {
				break;
			}
		   }
		}

	        if ((object->existence_map != NULL)
					&& (!LOOK_FOR(object, after))) {
			break;
		} 

		if (vm_page_lookup(object, after) != VM_PAGE_NULL) {
			/*
			 * don't bridge resident pages
			 */
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

		if(length >= pre_heat_size) {
		   if(tws_internal_lookup(tws, before, object,
				&line) != KERN_SUCCESS) {
			vm_object_offset_t	extend;
				
			extend = before;
			if (extend == 0)
				break;
			extend -= PAGE_SIZE_64;
			if(tws_internal_lookup(tws, extend, object,
					&line) != KERN_SUCCESS) {
				break;
			}
		   }
		}
		if ((object->existence_map != NULL) 
					&& (!LOOK_FOR(object, before))) {
			break;
		}

		if (vm_page_lookup(object, before) != VM_PAGE_NULL) {
			/*
			 * don't bridge resident pages
			 */
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
	tws_unlock(tws);
}

void
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
			j <<= 1;
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

/* tws locked on entry */

tws_startup_t
tws_create_startup_list(
	tws_hash_t	tws)
{

	tws_startup_t		startup;
	unsigned int		i,j,k;
	unsigned int		total_elements;
	unsigned int		startup_size;
	unsigned int		sindex;
	unsigned int		hash_index;
	tws_startup_ptr_t	element;

	total_elements = tws->expansion_count *
			(tws->number_of_lines * tws->number_of_elements);

	startup_size = sizeof(struct tws_startup) 
			+ (total_elements * sizeof(tws_startup_ptr_t *))
			+ (total_elements * sizeof(struct tws_startup_ptr))
			+ (total_elements * sizeof(struct tws_startup_ele));
	startup = (tws_startup_t)(kalloc(startup_size));

	if(startup == NULL)
		return startup;

	bzero((char *) startup, startup_size);

	startup->table = (tws_startup_ptr_t *)
		(((int)startup) + (sizeof(struct tws_startup)));
	startup->ele = (struct tws_startup_ptr *)
			(((vm_offset_t)startup->table) + 
			(total_elements * sizeof(tws_startup_ptr_t)));

	startup->array = (struct tws_startup_ele *)
			(((vm_offset_t)startup->ele) + 
			(total_elements * sizeof(struct tws_startup_ptr)));

	startup->tws_hash_size = startup_size;
	startup->ele_count = 0;  /* burn first hash ele, else we can't tell from zero */
	startup->array_size = total_elements;
	startup->hash_count = 1;

	sindex = 0;
	
	
	for(i = 0; i<tws->number_of_lines; i++) {
	   for(j = 0; j<tws->number_of_elements; j++) {
	      for(k = 0; k<tws->expansion_count; k++) {
		tws_hash_ele_t		entry;
		unsigned int		hash_retry;
		vm_offset_t		addr;

		entry = &tws->cache[k][i].list[j];
		addr = entry->page_addr;
		hash_retry = 0;
		if(entry->object != 0) {
			/* get a hash element */
			hash_index = do_startup_hash(addr, 
						startup->array_size);

			if(startup->hash_count < total_elements) {
				element = &(startup->ele[startup->hash_count]);
				startup->hash_count += 1;
			} else {
				/* exit we're out of elements */
				break;
			}
			/* place the hash element */
			element->next = startup->table[hash_index];
			startup->table[hash_index] = (tws_startup_ptr_t)
				((int)element - (int)&startup->ele[0]);

			/* set entry OFFSET in hash element */
			element->element =  (tws_startup_ele_t)
				((int)&startup->array[sindex] - 
						(int)&startup->array[0]);
		
			startup->array[sindex].page_addr = entry->page_addr;
			startup->array[sindex].page_cache = entry->page_cache;
			startup->ele_count++;
			sindex++;
		
		}
	     }
	   }
	}

	return startup;
}


/*
 * Returns an entire cache line.  The line is deleted from the startup
 * cache on return. The caller can check startup->ele_count for an empty
 * list. Access synchronization is the responsibility of the caller.
 */

unsigned int
tws_startup_list_lookup(
	tws_startup_t	startup,
	vm_offset_t	addr)
{
	unsigned int		hash_index;
	unsigned int		page_cache_bits;
	unsigned int		startup_shift;
	tws_startup_ele_t	entry;
	vm_offset_t		next_addr;
	tws_startup_ptr_t	element;
	tws_startup_ptr_t	base_ele;
	tws_startup_ptr_t	*previous_ptr;

	page_cache_bits = 0;

	hash_index = do_startup_hash(addr, startup->array_size);

	if(((unsigned int)&(startup->table[hash_index])) >= ((unsigned int)startup + startup->tws_hash_size)) {
		return page_cache_bits = 0;
	}
	element = (tws_startup_ptr_t)((int)startup->table[hash_index] +
			(int)&startup->ele[0]);
	base_ele = element;
	previous_ptr = &(startup->table[hash_index]);
	while(element > &startup->ele[0]) {
		if (((int)element + sizeof(struct tws_startup_ptr))
			> ((int)startup + startup->tws_hash_size))  {
			return page_cache_bits;
		}
		entry = (tws_startup_ele_t)
			((int)element->element 
				+ (int)&startup->array[0]);
		if((((int)entry + sizeof(struct tws_startup_ele))
			> ((int)startup + startup->tws_hash_size)) 
				|| ((int)entry < (int)startup))  {
			return page_cache_bits;
		}
		if ((addr >= entry->page_addr) && 
			(addr <= (entry->page_addr + 0x1F000))) {
			startup_shift = (addr - entry->page_addr)>>12;
			page_cache_bits |= entry->page_cache >> startup_shift;
			/* don't dump the pages, unless the addresses */
			/* line up perfectly.  The cache may be used */
			/* by other mappings */
			entry->page_cache &= (1 << startup_shift) - 1;
			if(addr == entry->page_addr) {
				if(base_ele == element) {
					base_ele = (tws_startup_ptr_t)
						((int)element->next 
						+ (int)&startup->ele[0]);
					startup->table[hash_index] = element->next;
					element = base_ele;
				} else {
					*previous_ptr = element->next;
					element = (tws_startup_ptr_t)
						((int)*previous_ptr 
						+ (int)&startup->ele[0]);
				}
				entry->page_addr = 0;
				startup->ele_count--;
				continue;
			}
		}
		next_addr = addr + 0x1F000;
		if ((next_addr >= entry->page_addr) && 
			(next_addr <= (entry->page_addr + 0x1F000))) {
			startup_shift = (next_addr - entry->page_addr)>>12;
			page_cache_bits |= entry->page_cache << (0x1F - startup_shift);
			entry->page_cache &= ~((1 << (startup_shift + 1)) - 1);
			if(entry->page_cache == 0) {
				if(base_ele == element) {
					base_ele = (tws_startup_ptr_t)
						((int)element->next 
						+ (int)&startup->ele[0]);
					startup->table[hash_index] = element->next;
					element = base_ele;
				} else {
					*previous_ptr = element->next;
					element = (tws_startup_ptr_t)
						((int)*previous_ptr 
						+ (int)&startup->ele[0]);
				}
				entry->page_addr = 0;
				startup->ele_count--;
				continue;
			}
		}
		previous_ptr = &(element->next);
		element = (tws_startup_ptr_t) 
			((int) element->next + (int) &startup->ele[0]);
	}

	return page_cache_bits;
}

kern_return_t
tws_send_startup_info(
		task_t		task)
{

	tws_hash_t		tws;

	task_lock(task);
	tws = task->dynamic_working_set;
	task_unlock(task);
	if(tws == NULL) {
		return KERN_FAILURE;
	}
	return tws_internal_startup_send(tws);
}


kern_return_t
tws_internal_startup_send(
		tws_hash_t	tws)
{

	tws_startup_t 		scache;

	if(tws == NULL) {
		return KERN_FAILURE;
	}
	tws_lock(tws);
	/* used to signal write or release depending on state of tws */
	if(tws->startup_cache) {
		vm_offset_t	startup_buf;
		vm_size_t	size;
		startup_buf = (vm_offset_t)tws->startup_cache;
		size = tws->startup_cache->tws_hash_size;
		tws->startup_cache = 0;
		tws_unlock(tws);
		kmem_free(kernel_map, startup_buf, size);
		return KERN_SUCCESS;
	}
   	if(tws->startup_name == NULL) {
		tws_unlock(tws);
		return KERN_FAILURE;
	}
	scache = tws_create_startup_list(tws);
	if(scache == NULL)
		return KERN_FAILURE;
	bsd_write_page_cache_file(tws->uid, tws->startup_name, 
				  (caddr_t) scache, scache->tws_hash_size, 
				  tws->mod, tws->fid);
	kfree(scache, scache->tws_hash_size);
	kfree(tws->startup_name, tws->startup_name_length);
	tws->startup_name = NULL;
	tws_unlock(tws);
	return KERN_SUCCESS;
}

kern_return_t
tws_handle_startup_file(
		task_t			task,
		unsigned int		uid,
		char			*app_name,
		void			*app_vp,
		boolean_t		*new_info)

{
		tws_startup_t	startup;
		vm_offset_t	cache_size;	
		kern_return_t	error;
		int		fid;
		int		mod;
		
		*new_info = FALSE;
		/* don't pre-heat kernel task */
		if(task == kernel_task)
			return KERN_SUCCESS;
		error = bsd_read_page_cache_file(uid, &fid, 
					&mod, app_name, 
					app_vp,
					(vm_offset_t *) &startup, 
					&cache_size);
		if(error) {
			return KERN_FAILURE;
		}
		if(startup == NULL) {
			/* Entry for app does not exist, make */
			/* one */
			/* we will want our own copy of the shared */
			/* regions to pick up a true picture of all */
			/* the pages we will touch. */
			if((lsf_zone->count * lsf_zone->elem_size) 
						> (lsf_zone->max_size >> 1)) {
				/* We don't want to run out of shared memory */
				/* map entries by starting too many private versions */
				/* of the shared library structures */
				return KERN_SUCCESS;
			}
			*new_info = TRUE;

			error = tws_write_startup_file(task, 
					fid, mod, app_name, uid);
			if(error)
				return error;

		} else {
			error = tws_read_startup_file(task, 
						(tws_startup_t)startup, 
						cache_size);
			if(error) {
				kmem_free(kernel_map, 
					(vm_offset_t)startup, cache_size); 
				return error;
			}
		}
		return KERN_SUCCESS;
}

kern_return_t
tws_write_startup_file(
		task_t			task,
		int			fid,
		int			mod,
		char			*name,
		unsigned int		uid)
{
		tws_hash_t		tws;
		unsigned int		string_length;

		string_length = strlen(name);

restart:
		task_lock(task);
		tws = task->dynamic_working_set;
		task_unlock(task);

		if(tws == NULL) {
			kern_return_t error;

			/* create a dynamic working set of normal size */
			if((error = task_working_set_create(task, 0, 0, TWS_HASH_STYLE_DEFAULT)) != KERN_SUCCESS)
				return error;
			/* we need to reset tws and relock */
			goto restart;
		}
		tws_lock(tws);

		if(tws->startup_name != NULL) {
			tws_unlock(tws);
			return KERN_FAILURE;
		}

		tws->startup_name = (char *)
			kalloc((string_length + 1) * (sizeof(char)));
		if(tws->startup_name == NULL) {
			tws_unlock(tws);
			return KERN_FAILURE;
		}

		bcopy(name, (char *)tws->startup_name, string_length + 1);
		tws->startup_name_length = (string_length + 1) * sizeof(char);
		tws->uid = uid;
		tws->fid = fid;
		tws->mod = mod;

		tws_unlock(tws);
		return KERN_SUCCESS;
}

unsigned long tws_read_startup_file_rejects = 0;

kern_return_t
tws_read_startup_file(
		task_t			task,
		tws_startup_t		startup,
		vm_offset_t		cache_size)
{
		tws_hash_t		tws;
		int			lines;
		int			old_exp_count;
		unsigned int		ele_count;

restart:
		task_lock(task);
		tws = task->dynamic_working_set;

		/* create a dynamic working set to match file size */

		/* start with total size of the data we got from app_profile */
		ele_count = cache_size;
		/* skip the startup header */
		ele_count -= sizeof(struct tws_startup); 
		/*
		 * For each startup cache entry, we have one of these:
		 *	tws_startup_ptr_t startup->table[];
		 * 	struct tws_startup_ptr startup->ele[];
		 *	struct tws_startup_ele startup->array[];
		 */
		ele_count /= (sizeof (tws_startup_ptr_t) +
			      sizeof (struct tws_startup_ptr) +
			      sizeof (struct tws_startup_ele));

		/*
		 * Sanity check: make sure the value for startup->array_size
		 * that we read from the app_profile file matches the size
		 * of the data we read from disk.  If it doesn't match, we
		 * can't trust the data and we just drop it all.
		 */
		if (cache_size < sizeof(struct tws_startup) ||
		    startup->array_size != ele_count) {
			tws_read_startup_file_rejects++;
			task_unlock(task);
			kmem_free(kernel_map, (vm_offset_t)startup, cache_size); 
			return(KERN_SUCCESS);
		}

		/*
		 * We'll create the task working set with the default row size
		 * (TWS_ARRAY_SIZE), so this will give us the number of lines
		 * we need to store all the data from the app_profile startup
		 * cache.
		 */
		lines = ele_count / TWS_ARRAY_SIZE;

		if(lines <= TWS_SMALL_HASH_LINE_COUNT) {
			lines = TWS_SMALL_HASH_LINE_COUNT;
			task_unlock(task);
			kmem_free(kernel_map, (vm_offset_t)startup, cache_size); 
			return(KERN_SUCCESS);
		} else {
			old_exp_count = lines/TWS_HASH_LINE_COUNT;
			if((old_exp_count * TWS_HASH_LINE_COUNT) != lines) {
				lines = (old_exp_count + 1) 
						* TWS_HASH_LINE_COUNT;
			}
			if(tws == NULL) {
				kern_return_t error;

				task_unlock(task);
				if ((error = task_working_set_create(task, lines, 0, TWS_HASH_STYLE_DEFAULT)) != KERN_SUCCESS)
					return error;
				/* we need to reset tws and relock */
				goto restart;
			} else {
				task_unlock(task);
				tws_expand_working_set(
					(void *)tws, lines, TRUE);
			}
		}
		
		tws_lock(tws);
		
		if(tws->startup_cache != NULL) {
			tws_unlock(tws);
			return KERN_FAILURE;
		}


		/* now need to fix up internal table pointers */
		startup->table = (tws_startup_ptr_t *)
			(((int)startup) + (sizeof(struct tws_startup)));
		startup->ele = (struct tws_startup_ptr *)
			(((vm_offset_t)startup->table) + 
			(startup->array_size * sizeof(tws_startup_ptr_t)));
		startup->array = (struct tws_startup_ele *)
			(((vm_offset_t)startup->ele) + 
			(startup->array_size * sizeof(struct tws_startup_ptr)));
		/* the allocation size and file size should be the same */
		/* just in case their not, make sure we dealloc correctly  */
		startup->tws_hash_size = cache_size;

		tws->startup_cache = startup;
		tws_unlock(tws);
		return KERN_SUCCESS;
}


void
tws_hash_ws_flush(tws_hash_t tws) {
	tws_startup_t 		scache;
	if(tws == NULL) {
		return;
	}
	tws_lock(tws);
	if(tws->startup_name != NULL) {
		scache = tws_create_startup_list(tws);
		if(scache == NULL) {
			/* dump the name cache, we'll */
			/* get it next time */
			kfree(tws->startup_name, tws->startup_name_length);
			tws->startup_name = NULL;
			tws_unlock(tws);
			return;
		}
		bsd_write_page_cache_file(tws->uid, tws->startup_name, 
				(caddr_t) scache, scache->tws_hash_size, 
				tws->mod, tws->fid);
		kfree(scache, scache->tws_hash_size);
		kfree(tws->startup_name, tws->startup_name_length);
		tws->startup_name = NULL;
	}
	tws_unlock(tws);
	return;
}

void
tws_hash_destroy(tws_hash_t	tws)
{
	unsigned int	i,k;

	if(tws->startup_cache != NULL) {
		kmem_free(kernel_map,
			(vm_offset_t)tws->startup_cache, 
			tws->startup_cache->tws_hash_size);
		tws->startup_cache = NULL;
	}
	if(tws->startup_name != NULL) {
		tws_internal_startup_send(tws);
	}
	for (i=0; i<tws->number_of_lines; i++) {
		for(k=0; k<tws->expansion_count; k++) {
			/* clear the object refs */
			tws_hash_line_clear(tws, &(tws->cache[k][i]), NULL, FALSE);
		}
	}
	i = 0;
	while (i < tws->expansion_count) {
		
		kfree(tws->table[i],
		      sizeof(tws_hash_ptr_t) 
		      * tws->number_of_lines 
		      * tws->number_of_elements);
		kfree(tws->table_ele[i], 
		      sizeof(struct tws_hash_ptr) 
		      * tws->number_of_lines 
		      * tws->number_of_elements);
		kfree(tws->alt_ele[i], 
		      sizeof(struct tws_hash_ptr) 
		      * tws->number_of_lines 
		      * tws->number_of_elements);
		kfree(tws->cache[i],
		      sizeof(struct tws_hash_line) * tws->number_of_lines);
		i++;
	}
	if(tws->startup_name != NULL) {
		kfree(tws->startup_name, tws->startup_name_length);
	}
	kfree(tws, sizeof(struct tws_hash));
}

void
tws_hash_clear(tws_hash_t	tws)
{
	unsigned int	i, k;

	for (i=0; i<tws->number_of_lines; i++) {
		for(k=0; k<tws->expansion_count; k++) {
			/* clear the object refs */
			tws_hash_line_clear(tws, &(tws->cache[k][i]), NULL, FALSE);
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
	} else if((task->dynamic_working_set =
		tws_hash_create(lines, rows, style)) == 0) {
		task_unlock(task);
		return(KERN_NO_SPACE);
	}
	task_unlock(task);
	return KERN_SUCCESS;
}


/* Internal use only routines */


/* 
 * internal sub-function for address space lookup
 * returns the target element and the address of the
 * previous pointer  The previous pointer is the address 
 * of the pointer pointing to the target element.
 * TWS must be locked
 */

void
tws_traverse_address_hash_list (
	tws_hash_t 		tws, 
	unsigned int		index,
	vm_offset_t		page_addr,
	vm_object_t		object,
	vm_object_offset_t	offset,
	vm_map_t		map,
	tws_hash_ptr_t		*target_ele,
	tws_hash_ptr_t		**previous_ptr,
	tws_hash_ptr_t		**free_list,
	unsigned int		exclusive_addr)
{
	unsigned int	k;
	tws_hash_ptr_t	cache_ele;
	tws_hash_ptr_t	base_ele;

	*target_ele = NULL;
	*previous_ptr = NULL;

	for(k=0; k<tws->expansion_count; k++) {
		tws_hash_ele_t ele;
		cache_ele = tws->table[k][index];
		base_ele = cache_ele;
		*previous_ptr = (tws_hash_ptr_t *)&(tws->table[k][index]);
		while(cache_ele != NULL) {
			if(((unsigned int)
				cache_ele->element & TWS_ADDR_HASH) == 0) {
				*previous_ptr = (tws_hash_ptr_t *)&(cache_ele->next);
				cache_ele = cache_ele->next;
				continue;
			}
			ele = (tws_hash_ele_t)((unsigned int)
				cache_ele->element & ~TWS_ADDR_HASH);
			if ((ele == 0) || (ele->object == 0)) {
				/* A little clean-up of empty elements */
				cache_ele->element = 0;
				if(base_ele == cache_ele) {
					base_ele = cache_ele->next;
					tws->table[k][index] = cache_ele->next;
					cache_ele->next = tws->free_hash_ele[k];
					tws->free_hash_ele[k] = cache_ele;
					cache_ele = base_ele;
				} else {
					**previous_ptr = cache_ele->next;
					cache_ele->next = tws->free_hash_ele[k];
					tws->free_hash_ele[k] = cache_ele;
					cache_ele = **previous_ptr;
				}
				continue;
			}
	
			if ((ele->page_addr <= page_addr) 
				&& (page_addr <= (ele->page_addr + 
				(vm_offset_t)TWS_INDEX_MASK))
				&& ((object == NULL) 
					|| ((object == ele->object)
					&& (offset == ele->offset)
					&& (map == ele->map)))) {
				if(exclusive_addr) {
					int delta;
					delta = ((page_addr - ele->page_addr)
					 >> 12);
					if((1 << delta) & ele->page_cache) {
						/* We've found a match */
						*target_ele = cache_ele;
						*free_list = 
						   (tws_hash_ptr_t *)
						   &(tws->free_hash_ele[k]);
						return;
					}
				} else {
					/* We've found a match */
					*target_ele = cache_ele;
					*free_list = (tws_hash_ptr_t *)
						&(tws->free_hash_ele[k]);
					return;
				}
			}
			*previous_ptr = (tws_hash_ptr_t *)&(cache_ele->next);
			cache_ele = cache_ele->next;
		}
	}
}


/* 
 * internal sub-function for object space lookup
 * returns the target element and the address of the
 * previous pointer  The previous pointer is the address 
 * of the pointer pointing to the target element.
 * TWS must be locked
 */


void
tws_traverse_object_hash_list (
	tws_hash_t 		tws, 
	unsigned int		index,
	vm_object_t		object,
	vm_object_offset_t	offset,
	unsigned int		pagemask,
	tws_hash_ptr_t		*target_ele,
	tws_hash_ptr_t		**previous_ptr,
	tws_hash_ptr_t		**free_list)
{
	unsigned int	k;
	tws_hash_ptr_t	cache_ele;
	tws_hash_ptr_t	base_ele;

	*target_ele = NULL;
	*previous_ptr = NULL;

	for(k=0; k<tws->expansion_count; k++) {
		cache_ele = tws->table[k][index];
		base_ele = cache_ele;
		*previous_ptr = &(tws->table[k][index]);
		while(cache_ele != NULL) {
			if((((unsigned int)cache_ele->element) 
						& TWS_ADDR_HASH) != 0) {
				*previous_ptr = &(cache_ele->next);
				cache_ele = cache_ele->next;
				continue;
			}
			if ((cache_ele->element == 0) || 
				(cache_ele->element->object == 0)) {
				/* A little clean-up of empty elements */
				cache_ele->element = 0;
				if(base_ele == cache_ele) {
					base_ele = cache_ele->next;
					tws->table[k][index] = cache_ele->next;
					cache_ele->next = tws->free_hash_ele[k];
					tws->free_hash_ele[k] = cache_ele;
					cache_ele = tws->table[k][index];
				} else {
					**previous_ptr = cache_ele->next;
					cache_ele->next = tws->free_hash_ele[k];
					tws->free_hash_ele[k] = cache_ele;
					cache_ele = **previous_ptr;
				}
				continue;
			}
			if ((cache_ele->element->object == object)
				&& (cache_ele->element->offset == 
				(offset - (offset & ~TWS_HASH_OFF_MASK)))) {
				if((cache_ele->element->page_cache & pagemask) 
					|| (pagemask == 0xFFFFFFFF)) {
					/* We've found a match */
					*target_ele = cache_ele;
					*free_list = &(tws->free_hash_ele[k]);
					return;
				}
			}
			*previous_ptr = (tws_hash_ptr_t *)&(cache_ele->next);
			cache_ele = cache_ele->next;
		}
	}
}


/*
 * For a given object/offset, discover whether the indexed 32 page frame 
 * containing the object/offset exists and if their are at least threshold
 * pages present.  Returns true if population meets threshold.
 */
int 
tws_test_for_community(
		tws_hash_t		tws, 
		vm_object_t		object, 
		vm_object_offset_t	offset, 
		unsigned int		threshold, 
		unsigned int		*pagemask) 
{
	int	index;
	tws_hash_ptr_t	cache_ele;
	tws_hash_ptr_t	*trailer;
	tws_hash_ptr_t	*free_list;
	int		community = 0;

	index = do_tws_hash(object, offset, 
			tws->number_of_elements, tws->number_of_lines);
	tws_traverse_object_hash_list(tws, index, object, offset, 0xFFFFFFFF,
		&cache_ele, &trailer, &free_list);

	if(cache_ele != NULL) {
		int i;
		unsigned int ctr;
		ctr = 0;
		for(i=1; i!=0; i=i<<1) {
			if(i & cache_ele->element->page_cache)
				ctr++;
			if(ctr == threshold) {
				community = 1;
				*pagemask = cache_ele->element->page_cache;
				break;
			}
		}
	}

	return community;
	
}


/* 
 * Gets new hash element for object hash from free pools
 * TWS must be locked
 */

tws_hash_ptr_t
new_obj_hash(
	tws_hash_t tws, 
	unsigned int set, 
	unsigned int index)
{
	tws_hash_ptr_t element;

	if(tws->obj_free_count[set] < tws->number_of_lines * tws->number_of_elements) {
		element = &(tws->table_ele[set][tws->obj_free_count[set]]);
		tws->obj_free_count[set]+=1;
	} else if(tws->free_hash_ele[set] == NULL) {
		return NULL;
	} else {
		element = tws->free_hash_ele[set];
		if(element == NULL)
			return element;
		tws->free_hash_ele[set] = tws->free_hash_ele[set]->next;
	}
	element->element = 0;
	element->next = tws->table[set][index];
	tws->table[set][index] = element;
	return element;
}

/* 
 * Gets new hash element for addr hash from free pools
 * TWS must be locked
 */

tws_hash_ptr_t
new_addr_hash(
	tws_hash_t tws, 
	unsigned int set, 
	unsigned int index)
{
	tws_hash_ptr_t element;

	if(tws->addr_free_count[set] 
			< tws->number_of_lines * tws->number_of_elements) {
		element = &(tws->alt_ele[set][tws->addr_free_count[set]]);
		tws->addr_free_count[set]+=1;
	} else if(tws->free_hash_ele[set] == NULL) {
		return NULL;
	} else {
		element = tws->free_hash_ele[set];
		if(element == NULL)
			return element;
		tws->free_hash_ele[set] = tws->free_hash_ele[set]->next;
	}
	element->element = (tws_hash_ele_t)TWS_ADDR_HASH;
	element->next = tws->table[set][index];
	tws->table[set][index] = element;
	return element;
}
