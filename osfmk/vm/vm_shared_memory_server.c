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
 *
 *	File: vm/vm_shared_memory_server.c
 *	Author: Chris Youngworth
 *
 *      Support routines for an in-kernel shared memory allocator
 */

#include <ipc/ipc_port.h>
#include <kern/thread.h>
#include <kern/zalloc.h>
#include <mach/kern_return.h>
#include <mach/vm_inherit.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>

#include <mach/shared_memory_server.h>
#include <vm/vm_shared_memory_server.h>

/* forward declarations */
static kern_return_t           
shared_file_init(               
        ipc_port_t      *shared_text_region_handle,
        vm_size_t       text_region_size,
        ipc_port_t      *shared_data_region_handle,
        vm_size_t       data_region_size, 
        vm_offset_t     *shared_file_mapping_array);

static load_struct_t  *
lsf_hash_lookup(   
        queue_head_t    		*hash_table,
        void    			*file_object,  
        vm_offset_t                     recognizableOffset,
        int     			size,
	boolean_t			alternate,
	shared_region_task_mappings_t	sm_info);

static load_struct_t *
lsf_hash_delete(
        void            		*file_object,
	vm_offset_t			base_offset,
	shared_region_task_mappings_t	sm_info);

static void    
lsf_hash_insert(
        load_struct_t   *entry,
	shared_region_task_mappings_t	sm_info);

static kern_return_t                   
lsf_load(
        vm_offset_t		 	mapped_file,
        vm_size_t      			mapped_file_size,
        vm_offset_t    			*base_address,
        sf_mapping_t   			*mappings,
        int            			map_cnt,
        void           			*file_object,
        int           			flags,
	shared_region_task_mappings_t	sm_info);

static void
lsf_unload(
        void     			*file_object,
	vm_offset_t			base_offset,
	shared_region_task_mappings_t	sm_info);


#define load_file_hash(file_object, size) \
		((((natural_t)file_object) & 0xffffff) % size)

/* Implementation */
vm_offset_t		shared_file_text_region;
vm_offset_t		shared_file_data_region;

ipc_port_t		shared_text_region_handle;
ipc_port_t		shared_data_region_handle;
vm_offset_t		shared_file_mapping_array = 0;

shared_region_mapping_t default_environment_shared_regions = NULL;
static decl_mutex_data(,default_regions_list_lock_data)

#define default_regions_list_lock()		\
		mutex_lock(&default_regions_list_lock_data)
#define default_regions_list_lock_try()	\
		mutex_try(&default_regions_list_lock_data)
#define default_regions_list_unlock()	\
		mutex_unlock(&default_regions_list_lock_data)


ipc_port_t		sfma_handle = NULL;
zone_t          	lsf_zone;

int		shared_file_available_hash_ele;

/* com region support */
ipc_port_t		com_region_handle = NULL;
vm_map_t		com_region_map = NULL;
vm_size_t		com_region_size = 0x7000;
shared_region_mapping_t	com_mapping_resource = NULL;

#define		GLOBAL_COM_REGION_BASE 0xFFFF8000

/* called for the non-default, private branch shared region support */
/* system default fields for fs_base and system supported are not   */
/* relevant as the system default flag is not set */
kern_return_t
shared_file_create_system_region(
		shared_region_mapping_t	*shared_region)
{
	ipc_port_t		text_handle;
	ipc_port_t		data_handle;
	long			text_size;
	long			data_size;
	vm_offset_t		mapping_array;
	kern_return_t		kret;

	text_size = 0x10000000;
	data_size = 0x10000000;

	kret = shared_file_init(&text_handle,
			text_size, &data_handle, data_size, &mapping_array);
	if(kret)
		return kret;
	kret = shared_region_mapping_create(text_handle,
			text_size, data_handle, data_size, mapping_array,
			GLOBAL_SHARED_TEXT_SEGMENT, shared_region, 
			SHARED_ALTERNATE_LOAD_BASE, SHARED_ALTERNATE_LOAD_BASE);
	if(kret)
		return kret;
	(*shared_region)->flags = 0;
	if(com_mapping_resource) {
        	shared_region_mapping_ref(com_mapping_resource);
        	(*shared_region)->next = com_mapping_resource;
	}

	return KERN_SUCCESS;
}

/*
 * load a new default for a specified environment into the default share
 * regions list.  If a previous default exists for the envrionment specification
 * it is returned along with its reference.  It is expected that the new
 * sytem region structure passes a reference.
 */

shared_region_mapping_t
update_default_shared_region(
		shared_region_mapping_t new_system_region)
{
	shared_region_mapping_t old_system_region;
	unsigned int fs_base;
	unsigned int system;

	fs_base = new_system_region->fs_base;
	system = new_system_region->system;
	new_system_region->flags |= SHARED_REGION_SYSTEM;
	default_regions_list_lock();
	old_system_region = default_environment_shared_regions;

	if((old_system_region != NULL) && 
		(old_system_region->fs_base == fs_base) &&
			(old_system_region->system == system)) {
		new_system_region->default_env_list =
			old_system_region->default_env_list;
		default_environment_shared_regions = new_system_region;
		default_regions_list_unlock();
		old_system_region->flags |= SHARED_REGION_STALE;
		return old_system_region;
	}
	if (old_system_region) {
	   while(old_system_region->default_env_list != NULL) {
		if((old_system_region->default_env_list->fs_base == fs_base) &&
		      (old_system_region->default_env_list->system == system)) {
			new_system_region->default_env_list =
			   		old_system_region->default_env_list
						->default_env_list;
			old_system_region->default_env_list = 
					new_system_region;
			default_regions_list_unlock();
			old_system_region->flags |= SHARED_REGION_STALE;
			return old_system_region;
		}
		old_system_region = old_system_region->default_env_list;
	   }
	}
	/* If we get here, we are at the end of the system list and we */
	/* did not find a pre-existing entry */
	if(old_system_region) {
		old_system_region->default_env_list = new_system_region;
	} else {
		default_environment_shared_regions = new_system_region;
	}
	default_regions_list_unlock();
	return NULL;
}

/* 
 * lookup a system_shared_region for the environment specified.  If one is
 * found, it is returned along with a reference against the structure
 */

shared_region_mapping_t
lookup_default_shared_region(
		unsigned int fs_base,
		unsigned int system)
{
	shared_region_mapping_t	system_region;
	default_regions_list_lock();
	system_region = default_environment_shared_regions;

	while(system_region != NULL) {
		if((system_region->fs_base == fs_base) &&
		      	(system_region->system == system)) {
			break;
		}
		system_region = system_region->default_env_list;
	}
	if(system_region)
		shared_region_mapping_ref(system_region);
	default_regions_list_unlock();
	return system_region;
}

/*
 * remove a system_region default if it appears in the default regions list. 
 * Drop a reference on removal.
 */

void
remove_default_shared_region(
		shared_region_mapping_t system_region)
{
	shared_region_mapping_t old_system_region;
	unsigned int fs_base;
	unsigned int system;

	default_regions_list_lock();
	old_system_region = default_environment_shared_regions;

	if(old_system_region == NULL) {
		default_regions_list_unlock();
		return;
	}

	if (old_system_region == system_region) {
		default_environment_shared_regions 
			= old_system_region->default_env_list;
		old_system_region->flags |= SHARED_REGION_STALE;
               	shared_region_mapping_dealloc(old_system_region);
		default_regions_list_unlock();
		return;
	}

	while(old_system_region->default_env_list != NULL) {
		if(old_system_region->default_env_list == system_region) {
			shared_region_mapping_t dead_region;
			dead_region = old_system_region->default_env_list;
			old_system_region->default_env_list = 
				old_system_region->default_env_list->default_env_list;
			dead_region->flags |= SHARED_REGION_STALE;
               		shared_region_mapping_dealloc(dead_region);
			default_regions_list_unlock();
			return;
		}
		old_system_region = old_system_region->default_env_list;
	}
	default_regions_list_unlock();
}

void
remove_all_shared_regions()
{
	shared_region_mapping_t system_region;
	shared_region_mapping_t next_system_region;

	default_regions_list_lock();
	system_region = default_environment_shared_regions;

	if(system_region == NULL) {
		default_regions_list_unlock();
		return;
	}

	while(system_region != NULL) {
		next_system_region = system_region->default_env_list;
		system_region->flags |= SHARED_REGION_STALE;
               	shared_region_mapping_dealloc(system_region);
		system_region = next_system_region;
	}
	default_environment_shared_regions = NULL;
	default_regions_list_unlock();
}
		
/* shared_com_boot_time_init initializes the common page shared data and */
/* text region.  This region is semi independent of the split libs       */
/* and so its policies have to be handled differently by the code that   */
/* manipulates the mapping of shared region environments.  However,      */
/* the shared region delivery system supports both */
shared_com_boot_time_init()
{
	kern_return_t		 kret;
	vm_named_entry_t	named_entry;

	if(com_region_handle) {
		panic("shared_com_boot_time_init: "
			"com_region_handle already set\n");
	}

	/* create com page region */
	if(kret = vm_region_object_create(kernel_map, 
			com_region_size, 
			&com_region_handle)) {
		panic("shared_com_boot_time_init: "
				"unable to create comm page\n");
		return;
	}
	/* now set export the underlying region/map */
	named_entry = (vm_named_entry_t)com_region_handle->ip_kobject;
	com_region_map = named_entry->backing.map;
	/* wrap the com region in its own shared file mapping structure */
	shared_region_mapping_create(com_region_handle,
		com_region_size, NULL, 0, 0,
		GLOBAL_COM_REGION_BASE, &com_mapping_resource,
		0, 0);

}

shared_file_boot_time_init(
		unsigned int fs_base, 
		unsigned int system)
{
	long			shared_text_region_size;
	long			shared_data_region_size;
	shared_region_mapping_t	new_system_region;
	shared_region_mapping_t	old_default_env;

	shared_text_region_size = 0x10000000;
	shared_data_region_size = 0x10000000;
	shared_file_init(&shared_text_region_handle,
		shared_text_region_size, &shared_data_region_handle,
		shared_data_region_size, &shared_file_mapping_array);
	
	shared_region_mapping_create(shared_text_region_handle,
		shared_text_region_size, shared_data_region_handle,
		shared_data_region_size, shared_file_mapping_array,
		GLOBAL_SHARED_TEXT_SEGMENT, &new_system_region,
		SHARED_ALTERNATE_LOAD_BASE, SHARED_ALTERNATE_LOAD_BASE);

	new_system_region->fs_base = fs_base;
	new_system_region->system = system;
	new_system_region->flags = SHARED_REGION_SYSTEM;

	/* grab an extra reference for the caller */
	/* remember to grab before call to update */
	shared_region_mapping_ref(new_system_region);
	old_default_env = update_default_shared_region(new_system_region);
	/* hold an extra reference because these are the system */
	/* shared regions. */
	if(old_default_env)
        	shared_region_mapping_dealloc(old_default_env);
	if(com_mapping_resource == NULL) {
		shared_com_boot_time_init();
	}
	shared_region_mapping_ref(com_mapping_resource);
	new_system_region->next = com_mapping_resource;
	vm_set_shared_region(current_task(), new_system_region);
}


/* called at boot time, allocates two regions, each 256 megs in size */
/* these regions are later mapped into task spaces, allowing them to */
/* share the contents of the regions.  shared_file_init is part of   */
/* a shared_memory_server which not only allocates the backing maps  */
/* but also coordinates requests for space.  */


static kern_return_t
shared_file_init(
	ipc_port_t	*shared_text_region_handle,
	vm_size_t 	text_region_size, 
	ipc_port_t	*shared_data_region_handle,
	vm_size_t 	data_region_size,
	vm_offset_t	*mapping_array)
{
	vm_offset_t		aligned_address;
	shared_file_info_t	*sf_head;
	vm_offset_t		table_mapping_address;
	int			data_table_size;
	int			hash_size;
	int			i;
	kern_return_t		kret;

	vm_object_t		buf_object;
	vm_map_entry_t		entry;
	vm_size_t		alloced;
	vm_offset_t		b;
	vm_page_t		p;

	/* create text and data maps/regions */
	if(kret = vm_region_object_create(kernel_map, 
				text_region_size, 
				shared_text_region_handle)) {
		
		return kret;
	}
	if(kret = vm_region_object_create(kernel_map, 
				data_region_size, 
				shared_data_region_handle)) {
		ipc_port_release_send(*shared_text_region_handle);
		return kret;
	}

	data_table_size = data_region_size >> 9;
	hash_size = data_region_size >> 14;
	table_mapping_address = data_region_size - data_table_size;

	if(shared_file_mapping_array == 0) {
		buf_object = vm_object_allocate(data_table_size);

		if(vm_map_find_space(kernel_map, &shared_file_mapping_array, 
				data_table_size, 0, &entry) != KERN_SUCCESS) {
			panic("shared_file_init: no space");
		}
		*mapping_array = shared_file_mapping_array;
		vm_map_unlock(kernel_map);
		entry->object.vm_object = buf_object;
		entry->offset = 0;

		for (b = *mapping_array, alloced = 0; 
			   alloced < (hash_size +
				round_page_32(sizeof(struct sf_mapping)));
			   alloced += PAGE_SIZE,  b += PAGE_SIZE) {
			vm_object_lock(buf_object);
			p = vm_page_alloc(buf_object, alloced);
			if (p == VM_PAGE_NULL) {
				panic("shared_file_init: no space");
			} 	
			p->busy = FALSE;
			vm_object_unlock(buf_object);
			pmap_enter(kernel_pmap, b, p->phys_page,
				VM_PROT_READ | VM_PROT_WRITE, 
				((unsigned int)(p->object->wimg_bits)) 
							& VM_WIMG_MASK,
				TRUE);
		}


		/* initialize loaded file array */
		sf_head = (shared_file_info_t *)*mapping_array;
		sf_head->hash = (queue_head_t *) 
				(((int)*mapping_array) + 
					sizeof(struct shared_file_info));
		sf_head->hash_size = hash_size/sizeof(queue_head_t);
		mutex_init(&(sf_head->lock), (ETAP_VM_MAP));
		sf_head->hash_init = FALSE;


		mach_make_memory_entry(kernel_map, &data_table_size, 
			*mapping_array, VM_PROT_READ, &sfma_handle,
			NULL);

		if (vm_map_wire(kernel_map, *mapping_array, 
			*mapping_array + 
 			   (hash_size + round_page_32(sizeof(struct sf_mapping))),
		   	VM_PROT_DEFAULT, FALSE) != KERN_SUCCESS) {
			panic("shared_file_init: No memory for data table");
		}

		lsf_zone = zinit(sizeof(struct load_file_ele), 
			data_table_size - 
			   (hash_size + round_page_32(sizeof(struct sf_mapping))),
			0, "load_file_server"); 

		zone_change(lsf_zone, Z_EXHAUST, TRUE);
		zone_change(lsf_zone, Z_COLLECT, FALSE);
		zone_change(lsf_zone, Z_EXPAND, FALSE);
		zone_change(lsf_zone, Z_FOREIGN, TRUE);

		/* initialize the global default environment lock */
		mutex_init(&default_regions_list_lock_data, ETAP_NO_TRACE);

	} else {
		*mapping_array = shared_file_mapping_array;
	}

	vm_map(((vm_named_entry_t)
			(*shared_data_region_handle)->ip_kobject)->backing.map,
			&table_mapping_address,
			data_table_size, 0, SHARED_LIB_ALIAS, 
			sfma_handle, 0, FALSE, 
			VM_PROT_READ, VM_PROT_READ, VM_INHERIT_NONE);

}

/* A call made from user space, copyin_shared_file requires the user to */
/* provide the address and size of a mapped file, the full path name of */
/* that file and a list of offsets to be mapped into shared memory.     */
/* By requiring that the file be pre-mapped, copyin_shared_file can     */
/* guarantee that the file is neither deleted nor changed after the user */
/* begins the call.  */

kern_return_t
copyin_shared_file(
	vm_offset_t	mapped_file,
	vm_size_t	mapped_file_size,
	vm_offset_t	*base_address, 
	int 		map_cnt,
	sf_mapping_t	*mappings,
	memory_object_control_t	file_control,
	shared_region_task_mappings_t	sm_info,
	int		*flags)
{
	vm_object_t	file_object;
	vm_map_entry_t		entry;
	shared_file_info_t	*shared_file_header;
	load_struct_t		*file_entry;
	loaded_mapping_t	*file_mapping;
	boolean_t		alternate;
	int			i;
	kern_return_t		ret;

	/* wire hash entry pool only as needed, since we are the only */
	/* users, we take a few liberties with the population of our  */
	/* zone. */
	static int			allocable_hash_pages;
	static vm_offset_t		hash_cram_address;
	

	shared_file_header = (shared_file_info_t *)sm_info->region_mappings;

	mutex_lock(&shared_file_header->lock);

	/* If this is the first call to this routine, take the opportunity */
	/* to initialize the hash table which will be used to look-up      */
	/* mappings based on the file object */ 

	if(shared_file_header->hash_init == FALSE) {
		vm_size_t	hash_table_size;
		vm_size_t	hash_table_offset;
		
		hash_table_size = (shared_file_header->hash_size) 
						* sizeof(struct queue_entry);
		hash_table_offset = hash_table_size + 
					round_page_32(sizeof(struct sf_mapping));
		for (i = 0; i < shared_file_header->hash_size; i++)
            		queue_init(&shared_file_header->hash[i]);

		allocable_hash_pages = 
			((hash_table_size<<5) - hash_table_offset)/PAGE_SIZE;
		hash_cram_address = 
			sm_info->region_mappings + hash_table_offset;
		shared_file_available_hash_ele = 0;

		shared_file_header->hash_init = TRUE;
	}

	if ((shared_file_available_hash_ele < 20) && (allocable_hash_pages)) {
		int cram_size;

		cram_size = allocable_hash_pages > 3 ? 
					3 : allocable_hash_pages;
		allocable_hash_pages -= cram_size;
		cram_size = cram_size * PAGE_SIZE;
		if (vm_map_wire(kernel_map, hash_cram_address,
				hash_cram_address+cram_size, 
				VM_PROT_DEFAULT, FALSE) != KERN_SUCCESS) {
			panic("shared_file_init: No memory for data table");
		}
		zcram(lsf_zone, hash_cram_address, cram_size);
		shared_file_available_hash_ele 
				+= cram_size/sizeof(struct load_file_ele);
		hash_cram_address += cram_size;
	}

	
	/* Find the entry in the map associated with the current mapping */
	/* of the file object */
	file_object = memory_object_control_to_vm_object(file_control);
	if(vm_map_lookup_entry(current_map(), mapped_file, &entry)) {
		vm_object_t	mapped_object;
		if(entry->is_sub_map) {
			mutex_unlock(&shared_file_header->lock);
			return KERN_INVALID_ADDRESS;
		}
		mapped_object = entry->object.vm_object;
		while(mapped_object->shadow != NULL) {
			mapped_object = mapped_object->shadow;
		}
		/* check to see that the file object passed is indeed the */
		/* same as the mapped object passed */
		if(file_object != mapped_object) {
			if(sm_info->flags & SHARED_REGION_SYSTEM) {
				mutex_unlock(&shared_file_header->lock);
				return KERN_PROTECTION_FAILURE;
			} else {
				file_object = mapped_object;
			}
		}
	} else {
		mutex_unlock(&shared_file_header->lock);
		return KERN_INVALID_ADDRESS;
	}

	alternate = (*flags & ALTERNATE_LOAD_SITE) ? TRUE : FALSE;

	if (file_entry = lsf_hash_lookup(shared_file_header->hash, 
			(void *) file_object, mappings[0].file_offset, shared_file_header->hash_size, 
			alternate, sm_info)) {
		/* File is loaded, check the load manifest for exact match */
		/* we simplify by requiring that the elements be the same  */
		/* size and in the same order rather than checking for     */
		/* semantic equivalence. */

		/* If the file is being loaded in the alternate        */
		/* area, one load to alternate is allowed per mapped   */
		/* object the base address is passed back to the       */
		/* caller and the mappings field is filled in.  If the */
		/* caller does not pass the precise mappings_cnt       */
		/* and the Alternate is already loaded, an error       */
		/* is returned.  */
		i = 0;
		file_mapping = file_entry->mappings;
		while(file_mapping != NULL) {
			if(i>=map_cnt) {
				mutex_unlock(&shared_file_header->lock);
				return KERN_INVALID_ARGUMENT;
			}
			if(((mappings[i].mapping_offset)
						& SHARED_DATA_REGION_MASK) !=
						file_mapping->mapping_offset ||
					mappings[i].size != 
						file_mapping->size ||	
					mappings[i].file_offset != 
						file_mapping->file_offset ||	
					mappings[i].protection != 
						file_mapping->protection) {
				break;
			}
			file_mapping = file_mapping->next;
			i++;
		}
		if(i!=map_cnt) {
			mutex_unlock(&shared_file_header->lock);
			return KERN_INVALID_ARGUMENT;
		}
		*base_address = (*base_address & ~SHARED_TEXT_REGION_MASK) 
						+ file_entry->base_address;
		*flags = SF_PREV_LOADED;
		mutex_unlock(&shared_file_header->lock);
		return KERN_SUCCESS;
	} else {
		/* File is not loaded, lets attempt to load it */
		ret = lsf_load(mapped_file, mapped_file_size, base_address,
					     mappings, map_cnt, 
					     (void *)file_object, 
					     *flags, sm_info);
		*flags = 0;
		if(ret == KERN_NO_SPACE) {
			shared_region_mapping_t	regions;
			shared_region_mapping_t	system_region;
			regions = (shared_region_mapping_t)sm_info->self;
			regions->flags |= SHARED_REGION_FULL;
			system_region = lookup_default_shared_region(
				regions->fs_base, regions->system);
			if(system_region == regions) {
				shared_region_mapping_t	new_system_shared_regions;
				shared_file_boot_time_init(
					regions->fs_base, regions->system);
				/* current task must stay with its current */
				/* regions, drop count on system_shared_region */
				/* and put back our original set */
				vm_get_shared_region(current_task(), 
						&new_system_shared_regions);
                		shared_region_mapping_dealloc(
						new_system_shared_regions);
				vm_set_shared_region(current_task(), regions);
			}
			if(system_region != NULL) {
                		shared_region_mapping_dealloc(system_region);
			}
		}
		mutex_unlock(&shared_file_header->lock);
		return ret;
	}
}

/* A hash lookup function for the list of loaded files in      */
/* shared_memory_server space.  */

static load_struct_t  *
lsf_hash_lookup(
	queue_head_t			*hash_table,
	void				*file_object,
  vm_offset_t                           recognizableOffset,
	int				size,
	boolean_t			alternate,
	shared_region_task_mappings_t	sm_info)
{
	register queue_t	bucket;
	load_struct_t		*entry;
	shared_region_mapping_t	target_region;
	int			depth;
	
	bucket = &(hash_table[load_file_hash((int)file_object, size)]);
	for (entry = (load_struct_t *)queue_first(bucket);
		!queue_end(bucket, &entry->links);
		entry = (load_struct_t *)queue_next(&entry->links)) {

		if ((entry->file_object == (int) file_object) &&
                    (entry->file_offset != recognizableOffset)) {
                }
		if ((entry->file_object == (int)file_object) &&
                    (entry->file_offset == recognizableOffset)) {
		   target_region = (shared_region_mapping_t)sm_info->self;
		   depth = target_region->depth;
		   while(target_region) {
		      if((!(sm_info->self)) ||
				((target_region == entry->regions_instance) &&
				(target_region->depth >= entry->depth))) {
			if(alternate) {
				if (entry->base_address >= 
						sm_info->alternate_base) 
					return entry;
			} else {
				if (entry->base_address < 
						sm_info->alternate_base) 
					return entry;
			}
		      }
		      if(target_region->object_chain) {
		         target_region = (shared_region_mapping_t)
			    target_region->object_chain->object_chain_region;
		         depth = target_region->object_chain->depth;
		      } else {
			target_region = NULL;
		      }
		   }
		}
	}

	return (load_struct_t *)0;
}

load_struct_t *
lsf_remove_regions_mappings(
	shared_region_mapping_t	region,
	shared_region_task_mappings_t	sm_info)
{
	int			i;
	register queue_t	bucket;
	shared_file_info_t	*shared_file_header;
	load_struct_t		*entry;
	load_struct_t		*next_entry;
	load_struct_t		*prev_entry;

	shared_file_header = (shared_file_info_t *)sm_info->region_mappings;

	mutex_lock(&shared_file_header->lock);
	if(shared_file_header->hash_init == FALSE) {
		mutex_unlock(&shared_file_header->lock);
		return NULL;
	}
	for(i = 0;  i<shared_file_header->hash_size; i++) {
		bucket = &shared_file_header->hash[i];
		for (entry = (load_struct_t *)queue_first(bucket);
			!queue_end(bucket, &entry->links);) {
		   next_entry = (load_struct_t *)queue_next(&entry->links);
		   if(region == entry->regions_instance) {
			lsf_unload((void *)entry->file_object, 
					entry->base_address, sm_info);
		   }
		   entry = next_entry;
		}
	}
	mutex_unlock(&shared_file_header->lock);
}

/* Removes a map_list, (list of loaded extents) for a file from     */
/* the loaded file hash table.  */

static load_struct_t *
lsf_hash_delete(
	void		*file_object,
	vm_offset_t	base_offset,
	shared_region_task_mappings_t	sm_info)
{
	register queue_t	bucket;
	shared_file_info_t	*shared_file_header;
	load_struct_t		*entry;
	load_struct_t		*prev_entry;

	shared_file_header = (shared_file_info_t *)sm_info->region_mappings;

	bucket = &shared_file_header->hash
	     [load_file_hash((int)file_object, shared_file_header->hash_size)];

	for (entry = (load_struct_t *)queue_first(bucket);
		!queue_end(bucket, &entry->links);
		entry = (load_struct_t *)queue_next(&entry->links)) {
		if((!(sm_info->self)) || ((shared_region_mapping_t)
				sm_info->self == entry->regions_instance)) {
			if ((entry->file_object == (int) file_object)  &&
				(entry->base_address == base_offset)) {
				queue_remove(bucket, entry, 
						load_struct_ptr_t, links);
				return entry;
			}
		}
	}

	return (load_struct_t *)0;
}

/* Inserts a new map_list, (list of loaded file extents), into the */
/* server loaded file hash table. */

static void
lsf_hash_insert(
	load_struct_t			*entry,
	shared_region_task_mappings_t	sm_info)
{
	shared_file_info_t *shared_file_header;

	shared_file_header = (shared_file_info_t *)sm_info->region_mappings;
	queue_enter(&shared_file_header->hash
			[load_file_hash(entry->file_object, 
					shared_file_header->hash_size)],
			entry, load_struct_ptr_t, links);
}
	
/* Looks up the file type requested.  If already loaded and the */
/* file extents are an exact match, returns Success.  If not    */
/* loaded attempts to load the file extents at the given offsets */
/* if any extent fails to load or if the file was already loaded */
/* in a different configuration, lsf_load fails.                 */

static kern_return_t
lsf_load(
	vm_offset_t	mapped_file,
	vm_size_t	mapped_file_size,
	vm_offset_t	*base_address, 
	sf_mapping_t	*mappings,
	int		map_cnt,
	void		*file_object,
	int		flags,
	shared_region_task_mappings_t	sm_info)
{

	load_struct_t		*entry;
	vm_map_copy_t		copy_object;
	loaded_mapping_t	*file_mapping;
	loaded_mapping_t	**tptr;
	int			i;
	ipc_port_t	local_map;
	vm_offset_t	original_alt_load_next;
	vm_offset_t	alternate_load_next;

	entry = (load_struct_t *)zalloc(lsf_zone);
	shared_file_available_hash_ele--;
	entry->file_object = (int)file_object;
	entry->mapping_cnt = map_cnt;
	entry->mappings = NULL;
	entry->links.prev = (queue_entry_t) 0;
	entry->links.next = (queue_entry_t) 0;
	entry->regions_instance = (shared_region_mapping_t)sm_info->self;
	entry->depth=((shared_region_mapping_t)sm_info->self)->depth;
        entry->file_offset = mappings[0].file_offset;

	lsf_hash_insert(entry, sm_info);
	tptr = &(entry->mappings);


	alternate_load_next = sm_info->alternate_next;
	original_alt_load_next = alternate_load_next;
	if (flags & ALTERNATE_LOAD_SITE) {
		int 	max_loadfile_offset;

		*base_address = ((*base_address) & ~SHARED_TEXT_REGION_MASK) +
						sm_info->alternate_next;
		max_loadfile_offset = 0;
		for(i = 0; i<map_cnt; i++) {
			if(((mappings[i].mapping_offset 
				& SHARED_TEXT_REGION_MASK)+ mappings[i].size) >
				max_loadfile_offset) {
				max_loadfile_offset = 
					(mappings[i].mapping_offset 
						& SHARED_TEXT_REGION_MASK)
						+ mappings[i].size;
			}
		}
		if((alternate_load_next + round_page_32(max_loadfile_offset)) >=
			(sm_info->data_size - (sm_info->data_size>>9))) {

			return KERN_NO_SPACE;
		}
		alternate_load_next += round_page_32(max_loadfile_offset);

	} else {
		if (((*base_address) & SHARED_TEXT_REGION_MASK) > 
					sm_info->alternate_base) {
			entry->base_address = 
				(*base_address) & SHARED_TEXT_REGION_MASK;
			lsf_unload(file_object, entry->base_address, sm_info);
			return KERN_INVALID_ARGUMENT;
		} 
	}

	entry->base_address = (*base_address) & SHARED_TEXT_REGION_MASK;

        // Sanity check the mappings -- make sure we don't stray across the
        // alternate boundary.  If any bit of a library that we're not trying
        // to load in the alternate load space strays across that boundary,
        // return KERN_INVALID_ARGUMENT immediately so that the caller can
        // try to load it in the alternate shared area.  We do this to avoid
        // a nasty case: if a library tries to load so that it crosses the
        // boundary, it'll occupy a bit of the alternate load area without
        // the kernel being aware.  When loads into the alternate load area
        // at the first free address are tried, the load will fail.
        // Thus, a single library straddling the boundary causes all sliding
        // libraries to fail to load.  This check will avoid such a case.
        
        if (!(flags & ALTERNATE_LOAD_SITE)) {
 	  for (i = 0; i<map_cnt;i++) {
            vm_offset_t region_mask;
            vm_address_t region_start;
            vm_address_t region_end;
 
            if ((mappings[i].protection & VM_PROT_WRITE) == 0) {
 // mapping offsets are relative to start of shared segments.
              region_mask = SHARED_TEXT_REGION_MASK;
              region_start = (mappings[i].mapping_offset & region_mask)+entry->base_address;
              region_end = (mappings[i].size + region_start);
              if (region_end >= SHARED_ALTERNATE_LOAD_BASE) {
                // No library is permitted to load so any bit of it is in the 
                // shared alternate space.  If they want it loaded, they can put
                // it in the alternate space explicitly.
printf("Library trying to load across alternate shared region boundary -- denied!\n");
                return KERN_INVALID_ARGUMENT;
              }
            } else {
              // rw section?
              region_mask = SHARED_DATA_REGION_MASK;
              region_start = (mappings[i].mapping_offset & region_mask)+entry->base_address;
              region_end = (mappings[i].size + region_start);
              if (region_end >= SHARED_ALTERNATE_LOAD_BASE) {
printf("Library trying to load across alternate shared region boundary-- denied!\n");
               return KERN_INVALID_ARGUMENT;
              }
            } // write?
          } // for
        } // if not alternate load site.
 
	/* copyin mapped file data */
	for(i = 0; i<map_cnt; i++) {
		vm_offset_t	target_address;
		vm_offset_t	region_mask;

		if(mappings[i].protection & VM_PROT_COW) {
			local_map = (ipc_port_t)sm_info->data_region;
			region_mask = SHARED_DATA_REGION_MASK;
			if((mappings[i].mapping_offset 
				& GLOBAL_SHARED_SEGMENT_MASK) != 0x10000000) {
				lsf_unload(file_object, 
					entry->base_address, sm_info);
				return KERN_INVALID_ARGUMENT;
			}
		} else {
			region_mask = SHARED_TEXT_REGION_MASK;
			local_map = (ipc_port_t)sm_info->text_region;
			if(mappings[i].mapping_offset 
					& GLOBAL_SHARED_SEGMENT_MASK)  {
				lsf_unload(file_object, 
					entry->base_address, sm_info);
				return KERN_INVALID_ARGUMENT;
			}
		}
		if(!(mappings[i].protection & VM_PROT_ZF)
				&& ((mapped_file + mappings[i].file_offset + 
				mappings[i].size) > 
				(mapped_file + mapped_file_size))) {
			lsf_unload(file_object, entry->base_address, sm_info);
			return KERN_INVALID_ARGUMENT;
		}
		target_address = ((mappings[i].mapping_offset) & region_mask)
					+ entry->base_address;
		if(vm_allocate(((vm_named_entry_t)local_map->ip_kobject)
				->backing.map, &target_address,
				mappings[i].size, FALSE)) {
			lsf_unload(file_object, entry->base_address, sm_info);
			return KERN_FAILURE;
		}
		target_address = ((mappings[i].mapping_offset) & region_mask)
					+ entry->base_address;
		if(!(mappings[i].protection & VM_PROT_ZF)) {
		   if(vm_map_copyin(current_map(), 
			mapped_file + mappings[i].file_offset, 
			round_page_32(mappings[i].size), FALSE, &copy_object)) {
			vm_deallocate(((vm_named_entry_t)local_map->ip_kobject)
			      ->backing.map, target_address, mappings[i].size);
			lsf_unload(file_object, entry->base_address, sm_info);
			return KERN_FAILURE;
		   }
		   if(vm_map_copy_overwrite(((vm_named_entry_t)
			local_map->ip_kobject)->backing.map, target_address,
			copy_object, FALSE)) {
			vm_deallocate(((vm_named_entry_t)local_map->ip_kobject)
			     ->backing.map, target_address, mappings[i].size);
			lsf_unload(file_object, entry->base_address, sm_info);
			return KERN_FAILURE;
		   }
		}
		vm_map_protect(((vm_named_entry_t)local_map->ip_kobject)
				->backing.map, target_address,
				round_page_32(target_address + mappings[i].size),
				(mappings[i].protection & 
					(VM_PROT_READ | VM_PROT_EXECUTE)),
				TRUE);
		vm_map_protect(((vm_named_entry_t)local_map->ip_kobject)
				->backing.map, target_address,
				round_page_32(target_address + mappings[i].size),
				(mappings[i].protection & 
					(VM_PROT_READ | VM_PROT_EXECUTE)),
				FALSE);
		file_mapping = (loaded_mapping_t *)zalloc(lsf_zone);
		if(file_mapping == 0) 
			panic("lsf_load: OUT OF MAPPINGS!");
		shared_file_available_hash_ele--;
		file_mapping->mapping_offset = (mappings[i].mapping_offset) 
								& region_mask;
		file_mapping->size = mappings[i].size;
		file_mapping->file_offset = mappings[i].file_offset;
		file_mapping->protection = mappings[i].protection;
		file_mapping->next = NULL;
		*tptr = file_mapping;
		tptr = &(file_mapping->next);
	}
	shared_region_mapping_set_alt_next(sm_info->self, alternate_load_next);
	return KERN_SUCCESS;
			
}


/* finds the file_object extent list in the shared memory hash table       */
/* If one is found the associated extents in shared memory are deallocated */
/* and the extent list is freed */

static void
lsf_unload(
	void			*file_object,
	vm_offset_t	        base_offset,
	shared_region_task_mappings_t	sm_info)
{
	load_struct_t		*entry;
	ipc_port_t		local_map;
	loaded_mapping_t	*map_ele;
	loaded_mapping_t	*back_ptr;

	entry = lsf_hash_delete(file_object, base_offset, sm_info);
	if(entry) {
		map_ele = entry->mappings;
		while(map_ele != NULL) {
			if(map_ele->protection & VM_PROT_COW) {
				local_map = (ipc_port_t)sm_info->data_region;
			} else {
				local_map = (ipc_port_t)sm_info->text_region;
			}
			vm_deallocate(((vm_named_entry_t)local_map->ip_kobject)
					->backing.map, entry->base_address + 
					map_ele->mapping_offset,
					map_ele->size);
			back_ptr = map_ele;
			map_ele = map_ele->next;
			zfree(lsf_zone, (vm_offset_t)back_ptr);
		        shared_file_available_hash_ele++;
		}
		zfree(lsf_zone, (vm_offset_t)entry);
	        shared_file_available_hash_ele++;
	}
}

/* integer is from 1 to 100 and represents percent full */
unsigned int
lsf_mapping_pool_gauge()
{
	return ((lsf_zone->count * lsf_zone->elem_size) * 100)/lsf_zone->max_size;
}
