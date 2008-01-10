/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
 *
 *	File: vm/vm_shared_memory_server.c
 *	Author: Chris Youngworth
 *
 *      Support routines for an in-kernel shared memory allocator
 */

#include <debug.h>

#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <mach/vm_inherit.h>
#include <mach/vm_map.h>
#include <machine/cpu_capabilities.h>

#include <kern/kern_types.h>
#include <kern/ipc_kobject.h>
#include <kern/thread.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>

#include <ipc/ipc_types.h>
#include <ipc/ipc_port.h>

#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_protos.h>

#include <mach/mach_vm.h>
#include <mach/shared_memory_server.h>
#include <vm/vm_shared_memory_server.h>

int shared_region_trace_level = SHARED_REGION_TRACE_ERROR;

#if DEBUG
int lsf_debug = 0;
int lsf_alloc_debug = 0;
#define LSF_DEBUG(args)				\
	MACRO_BEGIN				\
	if (lsf_debug) {			\
		kprintf args;			\
	}					\
	MACRO_END
#define LSF_ALLOC_DEBUG(args)			\
	MACRO_BEGIN				\
	if (lsf_alloc_debug) {			\
		kprintf args;			\
	}					\
	MACRO_END
#else /* DEBUG */
#define LSF_DEBUG(args)
#define LSF_ALLOC_DEBUG(args)
#endif /* DEBUG */

/* forward declarations */
static kern_return_t
shared_region_object_create(
	vm_size_t		size,
	ipc_port_t		*object_handle);

static kern_return_t
shared_region_mapping_dealloc_lock(
	shared_region_mapping_t	shared_region,
	int need_sfh_lock,
	int need_drl_lock);


static kern_return_t           
shared_file_init(               
        ipc_port_t      *text_region_handle,
        vm_size_t       text_region_size,
        ipc_port_t      *data_region_handle,
        vm_size_t       data_region_size, 
        vm_offset_t     *file_mapping_array);

static kern_return_t
shared_file_header_init(
	shared_file_info_t	*shared_file_header);

static load_struct_t  *
lsf_hash_lookup(   
        queue_head_t    		*hash_table,
        void    			*file_object,  
        vm_offset_t                     recognizableOffset,
        int     			size,
	boolean_t			regular,
	boolean_t			alternate,
	shared_region_task_mappings_t	sm_info);

static load_struct_t *
lsf_hash_delete(
	load_struct_t			*target_entry, /* optional */
        void            		*file_object,
	vm_offset_t			base_offset,
	shared_region_task_mappings_t	sm_info);

static void    
lsf_hash_insert(
        load_struct_t   *entry,
	shared_region_task_mappings_t	sm_info);

static kern_return_t
lsf_slide(
	unsigned int			map_cnt,
	struct shared_file_mapping_np	*mappings,
	shared_region_task_mappings_t	sm_info,
	mach_vm_offset_t		*base_offset_p);

static kern_return_t
lsf_map(
	struct shared_file_mapping_np	*mappings,
	int				map_cnt,
	void				*file_control,
	memory_object_size_t		file_size,
	shared_region_task_mappings_t	sm_info,
	mach_vm_offset_t		base_offset,
	mach_vm_offset_t		*slide_p);

static void
lsf_unload(
        void     			*file_object,
	vm_offset_t			base_offset,
	shared_region_task_mappings_t	sm_info);

static void
lsf_deallocate(
	load_struct_t			*target_entry,	/* optional */
        void     			*file_object,
	vm_offset_t			base_offset,
	shared_region_task_mappings_t	sm_info,
	boolean_t			unload);


#define load_file_hash(file_object, size) \
		((((natural_t)file_object) & 0xffffff) % size)

/* Implementation */
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
ipc_port_t		com_region_handle32 = NULL;
ipc_port_t		com_region_handle64 = NULL;
vm_map_t		com_region_map32 = NULL;
vm_map_t		com_region_map64 = NULL;
vm_size_t		com_region_size32 = _COMM_PAGE32_AREA_LENGTH;
vm_size_t		com_region_size64 = _COMM_PAGE64_AREA_LENGTH;
shared_region_mapping_t	com_mapping_resource = NULL;


#if DEBUG
int shared_region_debug = 0;
#endif /* DEBUG */


kern_return_t
vm_get_shared_region(
	task_t	task,
	shared_region_mapping_t	*shared_region)
{
	*shared_region = (shared_region_mapping_t) task->system_shared_region;
	if (*shared_region) {
		assert((*shared_region)->ref_count > 0);
	}
	SHARED_REGION_DEBUG(("vm_get_shared_region(task=%p) -> %p\n",
			     task, *shared_region));
	return KERN_SUCCESS;
}

kern_return_t
vm_set_shared_region(
	task_t	task,
	shared_region_mapping_t	shared_region)
{
	shared_region_mapping_t old_region;

	SHARED_REGION_DEBUG(("vm_set_shared_region(task=%p, "
			     "shared_region=%p[%x,%x,%x])\n",
			     task, shared_region,
			     shared_region ? shared_region->fs_base : 0,
			     shared_region ? shared_region->system : 0,
			     shared_region ? shared_region->flags : 0));
	if (shared_region) {
		assert(shared_region->ref_count > 0);
	}

	old_region = task->system_shared_region;
	SHARED_REGION_TRACE(
		SHARED_REGION_TRACE_INFO,
		("shared_region: %p set_region(task=%p)"
		 "old=%p[%x,%x,%x], new=%p[%x,%x,%x]\n",
		 current_thread(), task,
		 old_region,
		 old_region ? old_region->fs_base : 0,
		 old_region ? old_region->system : 0,
		 old_region ? old_region->flags : 0,
		 shared_region,
		 shared_region ? shared_region->fs_base : 0,
		 shared_region ? shared_region->system : 0,
		 shared_region ? shared_region->flags : 0));

	task->system_shared_region = shared_region;
	return KERN_SUCCESS;
}

/*
 * shared_region_object_chain_detach:
 *
 * Mark the shared region as being detached or standalone.  This means
 * that we won't keep track of which file is mapped and how, for this shared
 * region.  And we don't have a "shadow" shared region.
 * This is used when we clone a private shared region and we intend to remove
 * some mappings from it.  It won't need to maintain mappings info because it's
 * now private.  It can't have a "shadow" shared region because we don't want
 * to see the shadow of the mappings we're about to remove.
 */
void
shared_region_object_chain_detached(
	shared_region_mapping_t		target_region)
{
	shared_region_mapping_lock(target_region);
	target_region->flags |= SHARED_REGION_STANDALONE;
	shared_region_mapping_unlock(target_region);
}

/*
 * shared_region_object_chain_attach:
 *
 * Link "target_region" to "object_chain_region".  "object_chain_region"
 * is treated as a shadow of "target_region" for the purpose of looking up
 * mappings.  Since the "target_region" preserves all the mappings of the
 * older "object_chain_region", we won't duplicate all the mappings info and
 * we'll just lookup the next region in the "object_chain" if we can't find
 * what we're looking for in the "target_region".  See lsf_hash_lookup().
 */
kern_return_t
shared_region_object_chain_attach(
	shared_region_mapping_t		target_region,
	shared_region_mapping_t		object_chain_region)
{
	shared_region_object_chain_t	object_ele;
	
	SHARED_REGION_DEBUG(("shared_region_object_chain_attach("
			     "target_region=%p, object_chain_region=%p\n",
			     target_region, object_chain_region));
	assert(target_region->ref_count > 0);
	assert(object_chain_region->ref_count > 0);
	if(target_region->object_chain)
		return KERN_FAILURE;
	object_ele = (shared_region_object_chain_t)
			kalloc(sizeof (struct shared_region_object_chain));
	shared_region_mapping_lock(object_chain_region);
	target_region->object_chain = object_ele;
	object_ele->object_chain_region = object_chain_region;
	object_ele->next = object_chain_region->object_chain;
	object_ele->depth = object_chain_region->depth;
	object_chain_region->depth++;
	target_region->alternate_next = object_chain_region->alternate_next;
	shared_region_mapping_unlock(object_chain_region);
	return KERN_SUCCESS;
}

/* LP64todo - need 64-bit safe version */
kern_return_t
shared_region_mapping_create(
	ipc_port_t		text_region,
	vm_size_t		text_size,
	ipc_port_t		data_region,
	vm_size_t		data_size,
	vm_offset_t		region_mappings,
	vm_offset_t		client_base,
	shared_region_mapping_t	*shared_region,
	vm_offset_t		alt_base,
	vm_offset_t		alt_next,
	int			fs_base,
	int			system)
{
	SHARED_REGION_DEBUG(("shared_region_mapping_create()\n"));
	*shared_region = (shared_region_mapping_t) 
			kalloc(sizeof (struct shared_region_mapping));
	if(*shared_region == NULL) {
		SHARED_REGION_DEBUG(("shared_region_mapping_create: "
				     "failure\n"));
		return KERN_FAILURE;
	}
	shared_region_mapping_lock_init((*shared_region));
	(*shared_region)->text_region = text_region;
	(*shared_region)->text_size = text_size;
	(*shared_region)->fs_base = fs_base;
	(*shared_region)->system = system;
	(*shared_region)->data_region = data_region;
	(*shared_region)->data_size = data_size;
	(*shared_region)->region_mappings = region_mappings;
	(*shared_region)->client_base = client_base;
	(*shared_region)->ref_count = 1;
	(*shared_region)->next = NULL;
	(*shared_region)->object_chain = NULL;
	(*shared_region)->self = *shared_region;
	(*shared_region)->flags = 0;
	(*shared_region)->depth = 0;
	(*shared_region)->default_env_list = NULL;
	(*shared_region)->alternate_base = alt_base;
	(*shared_region)->alternate_next = alt_next;
	SHARED_REGION_DEBUG(("shared_region_mapping_create -> %p\n",
			     *shared_region));
	return KERN_SUCCESS;
}

/* LP64todo - need 64-bit safe version */
kern_return_t
shared_region_mapping_info(
	shared_region_mapping_t	shared_region,
	ipc_port_t		*text_region,
	vm_size_t		*text_size,
	ipc_port_t		*data_region,
	vm_size_t		*data_size,
	vm_offset_t		*region_mappings,
	vm_offset_t		*client_base,
	vm_offset_t		*alt_base,
	vm_offset_t		*alt_next,
	unsigned int		*fs_base,
	unsigned int		*system,
	int			*flags,
	shared_region_mapping_t	*next)
{
	shared_region_mapping_lock(shared_region);

	SHARED_REGION_DEBUG(("shared_region_mapping_info(shared_region=%p)\n",
			     shared_region));
	assert(shared_region->ref_count > 0);
	*text_region = shared_region->text_region;
	*text_size = shared_region->text_size;
	*data_region = shared_region->data_region;
	*data_size = shared_region->data_size;
	*region_mappings = shared_region->region_mappings;
	*client_base = shared_region->client_base;
	*alt_base = shared_region->alternate_base;
	*alt_next = shared_region->alternate_next;
	*flags = shared_region->flags;
	*fs_base = shared_region->fs_base;
	*system = shared_region->system;
	*next = shared_region->next;

	shared_region_mapping_unlock(shared_region);
	
	return KERN_SUCCESS;
}

kern_return_t
shared_region_mapping_ref(
	shared_region_mapping_t	shared_region)
{
	SHARED_REGION_DEBUG(("shared_region_mapping_ref(shared_region=%p): "
			     "ref_count=%d + 1\n",
			     shared_region,
			     shared_region ? shared_region->ref_count : 0));
	if(shared_region == NULL)
		return KERN_SUCCESS;
	assert(shared_region->ref_count > 0);
	hw_atomic_add(&shared_region->ref_count, 1);
	return KERN_SUCCESS;
}

static kern_return_t
shared_region_mapping_dealloc_lock(
	shared_region_mapping_t	shared_region,
	int need_sfh_lock,
	int need_drl_lock)
{
	struct shared_region_task_mappings sm_info;
	shared_region_mapping_t next = NULL;
	unsigned int ref_count;

	SHARED_REGION_DEBUG(("shared_region_mapping_dealloc_lock"
			     "(shared_region=%p,%d,%d) ref_count=%d\n",
			     shared_region, need_sfh_lock, need_drl_lock,
			     shared_region ? shared_region->ref_count : 0));
	while (shared_region) {
		SHARED_REGION_DEBUG(("shared_region_mapping_dealloc_lock(%p): "
				     "ref_count=%d\n",
				     shared_region, shared_region->ref_count));
		assert(shared_region->ref_count > 0);
		if ((ref_count = 
			  hw_atomic_sub(&shared_region->ref_count, 1)) == 0) {
			shared_region_mapping_lock(shared_region);

			sm_info.text_region = shared_region->text_region;
			sm_info.text_size = shared_region->text_size;
			sm_info.data_region = shared_region->data_region;
			sm_info.data_size = shared_region->data_size;
			sm_info.region_mappings = shared_region->region_mappings;
			sm_info.client_base = shared_region->client_base;
			sm_info.alternate_base = shared_region->alternate_base;
			sm_info.alternate_next = shared_region->alternate_next;
			sm_info.flags = shared_region->flags;
			sm_info.self = (vm_offset_t)shared_region;

			if(shared_region->region_mappings) {
				lsf_remove_regions_mappings_lock(shared_region, &sm_info, need_sfh_lock);
			}
			if(((vm_named_entry_t)
				(shared_region->text_region->ip_kobject))
                                                        ->backing.map->pmap) {
			    pmap_remove(((vm_named_entry_t)
				(shared_region->text_region->ip_kobject))
							->backing.map->pmap, 
				sm_info.client_base, 
				sm_info.client_base + sm_info.text_size);
			}
			ipc_port_release_send(shared_region->text_region);
			if(shared_region->data_region)
				ipc_port_release_send(shared_region->data_region);
			if (shared_region->object_chain) {
				next = shared_region->object_chain->object_chain_region;
				kfree(shared_region->object_chain,
				      sizeof (struct shared_region_object_chain));
			} else {
				next = NULL;
			}
			shared_region_mapping_unlock(shared_region);
			SHARED_REGION_DEBUG(
				("shared_region_mapping_dealloc_lock(%p): "
				 "freeing\n",
				 shared_region));
			bzero((void *)shared_region,
			      sizeof (*shared_region)); /* FBDP debug */
			kfree(shared_region,
				sizeof (struct shared_region_mapping));
			shared_region = next;
		} else {
			/* Stale indicates that a system region is no */
			/* longer in the default environment list.    */
			if((ref_count == 1) && 
			  (shared_region->flags & SHARED_REGION_SYSTEM)
			  && !(shared_region->flags & SHARED_REGION_STALE)) {
				SHARED_REGION_DEBUG(
					("shared_region_mapping_dealloc_lock"
					 "(%p): removing stale\n",
					 shared_region));
				remove_default_shared_region_lock(shared_region,need_sfh_lock, need_drl_lock);
			}
			break;
		}
	}
	SHARED_REGION_DEBUG(("shared_region_mapping_dealloc_lock(%p): done\n",
			     shared_region));
	return KERN_SUCCESS;
}

/*
 * Stub function; always indicates that the lock needs to be taken in the
 * call to lsf_remove_regions_mappings_lock().
 */
kern_return_t
shared_region_mapping_dealloc(
	shared_region_mapping_t	shared_region)
{
	SHARED_REGION_DEBUG(("shared_region_mapping_dealloc"
			     "(shared_region=%p)\n",
			     shared_region));
	if (shared_region) {
		assert(shared_region->ref_count > 0);
	}
	return shared_region_mapping_dealloc_lock(shared_region, 1, 1);
}

static 
kern_return_t
shared_region_object_create(
	vm_size_t		size,
	ipc_port_t		*object_handle)
{
	vm_named_entry_t	user_entry;
	ipc_port_t		user_handle;

	ipc_port_t	previous;
	vm_map_t	new_map;
	
	user_entry = (vm_named_entry_t) 
			kalloc(sizeof (struct vm_named_entry));
	if(user_entry == NULL) {
		return KERN_FAILURE;
	}
	named_entry_lock_init(user_entry);
	user_handle = ipc_port_alloc_kernel();


	ip_lock(user_handle);

	/* make a sonce right */
	user_handle->ip_sorights++;
	ip_reference(user_handle);

	user_handle->ip_destination = IP_NULL;
	user_handle->ip_receiver_name = MACH_PORT_NULL;
	user_handle->ip_receiver = ipc_space_kernel;

	/* make a send right */
        user_handle->ip_mscount++;
        user_handle->ip_srights++;
        ip_reference(user_handle);

	ipc_port_nsrequest(user_handle, 1, user_handle, &previous);
	/* nsrequest unlocks user_handle */

	/* Create a named object based on a submap of specified size */

	new_map = vm_map_create(pmap_create(0, FALSE), 0, size, TRUE);
	user_entry->backing.map = new_map;
	user_entry->internal = TRUE;
	user_entry->is_sub_map = TRUE;
	user_entry->is_pager = FALSE;
	user_entry->offset = 0;
	user_entry->protection = VM_PROT_ALL;
	user_entry->size = size;
	user_entry->ref_count = 1;

	ipc_kobject_set(user_handle, (ipc_kobject_t) user_entry,
							IKOT_NAMED_ENTRY);
	*object_handle = user_handle;
	return KERN_SUCCESS;
}

/* called for the non-default, private branch shared region support */
/* system default fields for fs_base and system supported are not   */
/* relevant as the system default flag is not set */
kern_return_t
shared_file_create_system_region(
	shared_region_mapping_t	*shared_region,
	int			fs_base,
	int			system)
{
	ipc_port_t		text_handle;
	ipc_port_t		data_handle;
	long			text_size;
	long			data_size;
	vm_offset_t		mapping_array;
	kern_return_t		kret;

	SHARED_REGION_DEBUG(("shared_file_create_system_region()\n"));

	text_size = 0x10000000;
	data_size = 0x10000000;

	kret = shared_file_init(&text_handle,
			text_size, &data_handle, data_size, &mapping_array);
	if(kret) {
		SHARED_REGION_DEBUG(("shared_file_create_system_region: "
				     "shared_file_init failed kret=0x%x\n",
				     kret));
		return kret;
	}
	kret = shared_region_mapping_create(text_handle, text_size,
					    data_handle, data_size,
					    mapping_array,
					    GLOBAL_SHARED_TEXT_SEGMENT,
					    shared_region, 
					    SHARED_ALTERNATE_LOAD_BASE,
					    SHARED_ALTERNATE_LOAD_BASE,
					    fs_base,
					    system);
	if(kret) {
		SHARED_REGION_DEBUG(("shared_file_create_system_region: "
				     "shared_region_mapping_create failed "
				     "kret=0x%x\n",
				     kret));
		return kret;
	}
	(*shared_region)->flags = 0;
	if(com_mapping_resource) {
        	shared_region_mapping_ref(com_mapping_resource);
        	(*shared_region)->next = com_mapping_resource;
	}

	SHARED_REGION_DEBUG(("shared_file_create_system_region() "
			     "-> shared_region=%p\n",
			     *shared_region));
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

	SHARED_REGION_DEBUG(("update_default_shared_region(new=%p)\n",
			     new_system_region));
	assert(new_system_region->ref_count > 0);
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
		old_system_region->default_env_list = NULL;
		default_environment_shared_regions = new_system_region;
		old_system_region->flags |= SHARED_REGION_STALE;
		default_regions_list_unlock();
		SHARED_REGION_DEBUG(("update_default_shared_region(%p): "
				     "old=%p stale 1\n",
				     new_system_region, old_system_region));
		assert(old_system_region->ref_count > 0);
		return old_system_region;
	}
	if (old_system_region) {
	   while(old_system_region->default_env_list != NULL) {
		if((old_system_region->default_env_list->fs_base == fs_base) &&
		      (old_system_region->default_env_list->system == system)) {
			shared_region_mapping_t tmp_system_region;

			tmp_system_region =
				old_system_region->default_env_list;
			new_system_region->default_env_list =
			   		tmp_system_region->default_env_list;
			tmp_system_region->default_env_list = NULL;
			old_system_region->default_env_list = 
					new_system_region;
			old_system_region = tmp_system_region;
			old_system_region->flags |= SHARED_REGION_STALE;
			default_regions_list_unlock();
			SHARED_REGION_DEBUG(("update_default_shared_region(%p)"
					     ": old=%p stale 2\n",
					     new_system_region,
					     old_system_region));
			assert(old_system_region->ref_count > 0);
			return old_system_region;
		}
		old_system_region = old_system_region->default_env_list;
	   }
	}
	/* If we get here, we are at the end of the system list and we */
	/* did not find a pre-existing entry */
	if(old_system_region) {
		SHARED_REGION_DEBUG(("update_default_system_region(%p): "
				     "adding after old=%p\n",
				     new_system_region, old_system_region));
		assert(old_system_region->ref_count > 0);
		old_system_region->default_env_list = new_system_region;
	} else {
		SHARED_REGION_DEBUG(("update_default_system_region(%p): "
				     "new default\n",
				     new_system_region));
		default_environment_shared_regions = new_system_region;
	}
	assert(new_system_region->ref_count > 0);
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

	SHARED_REGION_DEBUG(("lookup_default_shared_region"
			     "(base=0x%x, system=0x%x)\n",
			     fs_base, system));
	while(system_region != NULL) {
		SHARED_REGION_DEBUG(("lookup_default_shared_region(0x%x, 0x%x)"
				     ": system_region=%p base=0x%x system=0x%x"
				     " ref_count=%d\n",
				     fs_base, system, system_region,
				     system_region->fs_base,
				     system_region->system,
				     system_region->ref_count));
		assert(system_region->ref_count > 0);
		if((system_region->fs_base == fs_base) &&
		      	(system_region->system == system)) {
			break;
		}
		system_region = system_region->default_env_list;
	}
	if(system_region)
		shared_region_mapping_ref(system_region);
	default_regions_list_unlock();
	SHARED_REGION_DEBUG(("lookup_default_system_region(0x%x,0x%x) -> %p\n",
			     system_region));
	return system_region;
}

/*
 * remove a system_region default if it appears in the default regions list. 
 * Drop a reference on removal.
 */

__private_extern__ void
remove_default_shared_region_lock(
		shared_region_mapping_t system_region,
		int need_sfh_lock,
		int need_drl_lock)
{
	shared_region_mapping_t old_system_region;

	SHARED_REGION_DEBUG(("remove_default_shared_region_lock"
			     "(system_region=%p, %d, %d)\n",
			     system_region, need_sfh_lock, need_drl_lock));
	if (need_drl_lock) {
		default_regions_list_lock();
	}
	old_system_region = default_environment_shared_regions;

	if(old_system_region == NULL) {
		SHARED_REGION_DEBUG(("remove_default_shared_region_lock(%p)"
				     "-> default_env=NULL\n",
				     system_region));
		if (need_drl_lock) {
			default_regions_list_unlock();
		}
		return;
	}

	SHARED_REGION_DEBUG(("remove_default_shared_region_lock(%p): "
			     "default_env=%p\n",
			     system_region, old_system_region));
	assert(old_system_region->ref_count > 0);
	if (old_system_region == system_region) {
		default_environment_shared_regions 
			= old_system_region->default_env_list;
		old_system_region->default_env_list = NULL;
		old_system_region->flags |= SHARED_REGION_STALE;
		SHARED_REGION_DEBUG(("remove_default_shared_region_lock(%p): "
				     "old=%p ref_count=%d STALE\n",
				     system_region, old_system_region,
				     old_system_region->ref_count));
               	shared_region_mapping_dealloc_lock(old_system_region,
						   need_sfh_lock,
						   0);
		if (need_drl_lock) {
			default_regions_list_unlock();
		}
		return;
	}

	while(old_system_region->default_env_list != NULL) {
		SHARED_REGION_DEBUG(("remove_default_shared_region_lock(%p): "
				     "old=%p->default_env=%p\n",
				     system_region, old_system_region,
				     old_system_region->default_env_list));
		assert(old_system_region->default_env_list->ref_count > 0);
		if(old_system_region->default_env_list == system_region) {
			shared_region_mapping_t dead_region;
			dead_region = old_system_region->default_env_list;
			old_system_region->default_env_list = 
				dead_region->default_env_list;
			dead_region->default_env_list = NULL;
			dead_region->flags |= SHARED_REGION_STALE;
			SHARED_REGION_DEBUG(
				("remove_default_shared_region_lock(%p): "
				 "dead=%p ref_count=%d stale\n",
				 system_region, dead_region,
				 dead_region->ref_count));
               		shared_region_mapping_dealloc_lock(dead_region,
							   need_sfh_lock,
							   0);
			if (need_drl_lock) {
				default_regions_list_unlock();
			}
			return;
		}
		old_system_region = old_system_region->default_env_list;
	}
	if (need_drl_lock) {
		default_regions_list_unlock();
	}
}

/*
 * Symbol compatability; we believe shared_region_mapping_dealloc_lock() is
 * the only caller.  Remove this stub function and the corresponding symbol
 * export for Merlot.
 */
void
remove_default_shared_region(
		shared_region_mapping_t system_region)
{
	SHARED_REGION_DEBUG(("remove_default_shared_region(%p)\n",
			     system_region));
	if (system_region) {
		assert(system_region->ref_count > 0);
	}
	remove_default_shared_region_lock(system_region, 1, 1);
}

void
remove_all_shared_regions(void)
{
	shared_region_mapping_t system_region;
	shared_region_mapping_t next_system_region;

	SHARED_REGION_DEBUG(("***** REMOVE_ALL_SHARED_REGIONS()\n"));
	LSF_ALLOC_DEBUG(("***** REMOVE_ALL_SHARED_REGIONS()\n"));
	LSF_DEBUG(("***** REMOVE_ALL_SHARED_REGIONS()\n"));
	default_regions_list_lock();
	system_region = default_environment_shared_regions;

	if(system_region == NULL) {
		default_regions_list_unlock();
		return;
	}

	while(system_region != NULL) {
		next_system_region = system_region->default_env_list;
		system_region->default_env_list = NULL;
		system_region->flags |= SHARED_REGION_STALE;
		SHARED_REGION_DEBUG(("remove_all_shared_regions(): "
				     "%p ref_count=%d stale\n",
				     system_region, system_region->ref_count));
		assert(system_region->ref_count > 0);
               	shared_region_mapping_dealloc_lock(system_region, 1, 0);
		system_region = next_system_region;
	}
	default_environment_shared_regions = NULL;
	default_regions_list_unlock();
	SHARED_REGION_DEBUG(("***** remove_all_shared_regions() done\n"));
	LSF_ALLOC_DEBUG(("***** remove_all_shared_regions() done\n"));
	LSF_DEBUG(("***** remove_all_shared_regions() done\n"));
}
		
/* shared_com_boot_time_init initializes the common page shared data and */
/* text region.  This region is semi independent of the split libs       */
/* and so its policies have to be handled differently by the code that   */
/* manipulates the mapping of shared region environments.  However,      */
/* the shared region delivery system supports both */
void shared_com_boot_time_init(void);	/* forward */
void
shared_com_boot_time_init(void)
{
	kern_return_t		 kret;
	vm_named_entry_t	named_entry;

	SHARED_REGION_DEBUG(("shared_com_boot_time_init()\n"));
	if(com_region_handle32) {
		panic("shared_com_boot_time_init: "
			"com_region_handle32 already set\n");
	}
	if(com_region_handle64) {
		panic("shared_com_boot_time_init: "
			"com_region_handle64 already set\n");
	}

	/* create com page regions, 1 each for 32 and 64-bit code  */
	if((kret = shared_region_object_create(
			com_region_size32, 
			&com_region_handle32))) {
		panic("shared_com_boot_time_init: "
				"unable to create 32-bit comm page\n");
		return;
	}
	if((kret = shared_region_object_create(
			com_region_size64, 
			&com_region_handle64))) {
		panic("shared_com_boot_time_init: "
				"unable to create 64-bit comm page\n");
		return;
	}
	
	/* now set export the underlying region/map */
	named_entry = (vm_named_entry_t)com_region_handle32->ip_kobject;
	com_region_map32 = named_entry->backing.map;
	named_entry = (vm_named_entry_t)com_region_handle64->ip_kobject;
	com_region_map64 = named_entry->backing.map;
	
	/* wrap the com region in its own shared file mapping structure */
	/* 64-bit todo: call "shared_region_mapping_create" on com_region_handle64 */
	kret = shared_region_mapping_create(com_region_handle32,
					    com_region_size32,
					    NULL, 0, 0,
					    _COMM_PAGE_BASE_ADDRESS,
					    &com_mapping_resource,
					    0, 0,
					    ENV_DEFAULT_ROOT, cpu_type());
	if (kret) {
	  panic("shared_region_mapping_create failed for commpage");
	}
}

void
shared_file_boot_time_init(
		unsigned int fs_base, 
		unsigned int system)
{
	mach_port_t		text_region_handle;
	mach_port_t		data_region_handle;
	long			text_region_size;
	long			data_region_size;
	shared_region_mapping_t	new_system_region;
	shared_region_mapping_t	old_default_env;

	SHARED_REGION_DEBUG(("shared_file_boot_time_init"
			     "(base=0x%x,system=0x%x)\n",
			     fs_base, system));
	text_region_size = 0x10000000;
	data_region_size = 0x10000000;
	shared_file_init(&text_region_handle,
			 text_region_size,
			 &data_region_handle,
			 data_region_size,
			 &shared_file_mapping_array);
	
	shared_region_mapping_create(text_region_handle,
				     text_region_size,
				     data_region_handle,
				     data_region_size,
				     shared_file_mapping_array,
				     GLOBAL_SHARED_TEXT_SEGMENT,
				     &new_system_region,
				     SHARED_ALTERNATE_LOAD_BASE,
				     SHARED_ALTERNATE_LOAD_BASE,
				     fs_base, system);

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
	SHARED_REGION_DEBUG(("shared_file_boot_time_init(0x%x,0x%x) done\n",
			     fs_base, system));
}


/* called at boot time, allocates two regions, each 256 megs in size */
/* these regions are later mapped into task spaces, allowing them to */
/* share the contents of the regions.  shared_file_init is part of   */
/* a shared_memory_server which not only allocates the backing maps  */
/* but also coordinates requests for space.  */


static kern_return_t
shared_file_init(
	ipc_port_t	*text_region_handle,
	vm_size_t 	text_region_size, 
	ipc_port_t	*data_region_handle,
	vm_size_t 	data_region_size,
	vm_offset_t	*file_mapping_array)
{
	shared_file_info_t	*sf_head;
	vm_size_t		data_table_size;
	int			hash_size;
	kern_return_t		kret;

	vm_object_t		buf_object;
	vm_map_entry_t		entry;
	vm_size_t		alloced;
	vm_offset_t		b;
	vm_page_t		p;

	SHARED_REGION_DEBUG(("shared_file_init()\n"));
	/* create text and data maps/regions */
	kret = shared_region_object_create(
				       text_region_size, 
				       text_region_handle);
	if (kret) {
		return kret;
	}
	kret = shared_region_object_create(
				       data_region_size, 
				       data_region_handle);
	if (kret) {
		ipc_port_release_send(*text_region_handle);
		return kret;
	}

	data_table_size = data_region_size >> 9;
	hash_size = data_region_size >> 14;

	if(shared_file_mapping_array == 0) {
		vm_map_address_t map_addr;
		buf_object = vm_object_allocate(data_table_size);

		if(vm_map_find_space(kernel_map, &map_addr,
				     data_table_size, 0, 0, &entry)
		   != KERN_SUCCESS) {
			panic("shared_file_init: no space");
		}
		shared_file_mapping_array = CAST_DOWN(vm_offset_t, map_addr);
		*file_mapping_array = shared_file_mapping_array;
		vm_map_unlock(kernel_map);
		entry->object.vm_object = buf_object;
		entry->offset = 0;

		for (b = *file_mapping_array, alloced = 0; 
			   alloced < (hash_size +
				round_page(sizeof(struct sf_mapping)));
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
		sf_head = (shared_file_info_t *)*file_mapping_array;
		sf_head->hash = (queue_head_t *) 
				(((int)*file_mapping_array) + 
					sizeof(struct shared_file_info));
		sf_head->hash_size = hash_size/sizeof(queue_head_t);
		mutex_init(&(sf_head->lock), 0);
		sf_head->hash_init = FALSE;


		mach_make_memory_entry(kernel_map, &data_table_size, 
			*file_mapping_array, VM_PROT_READ, &sfma_handle,
			NULL);

		if (vm_map_wire(kernel_map, 
			vm_map_trunc_page(*file_mapping_array),
			vm_map_round_page(*file_mapping_array + 
					  hash_size + 
					  round_page(sizeof(struct sf_mapping))),
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
		mutex_init(&default_regions_list_lock_data, 0);

	} else {
		*file_mapping_array = shared_file_mapping_array;
	}

	SHARED_REGION_DEBUG(("shared_file_init() done\n"));
	return KERN_SUCCESS;
}

static kern_return_t
shared_file_header_init(
	shared_file_info_t		*shared_file_header)
{
	vm_size_t		hash_table_size;
	vm_size_t		hash_table_offset;
	int			i;
	/* wire hash entry pool only as needed, since we are the only */
	/* users, we take a few liberties with the population of our  */
	/* zone. */
	static int		allocable_hash_pages;
	static vm_offset_t	hash_cram_address;
	
		
	hash_table_size = shared_file_header->hash_size 
		* sizeof (struct queue_entry);
	hash_table_offset = hash_table_size + 
		round_page(sizeof (struct sf_mapping));
	for (i = 0; i < shared_file_header->hash_size; i++)
		queue_init(&shared_file_header->hash[i]);

	allocable_hash_pages = (((hash_table_size << 5) - hash_table_offset)
				/ PAGE_SIZE);
	hash_cram_address = ((vm_offset_t) shared_file_header)
		+ hash_table_offset;
	shared_file_available_hash_ele = 0;

	shared_file_header->hash_init = TRUE;

	if ((shared_file_available_hash_ele < 20) && (allocable_hash_pages)) {
		int cram_pages, cram_size;

		cram_pages = allocable_hash_pages > 3 ? 
					3 : allocable_hash_pages;
		cram_size = cram_pages * PAGE_SIZE;
		if (vm_map_wire(kernel_map, hash_cram_address,
				hash_cram_address + cram_size, 
				VM_PROT_DEFAULT, FALSE) != KERN_SUCCESS) {
			SHARED_REGION_TRACE(
				SHARED_REGION_TRACE_ERROR,
				("shared_region: shared_file_header_init: "
				 "No memory for data table\n"));
			return KERN_NO_SPACE;
		}
		allocable_hash_pages -= cram_pages;
		zcram(lsf_zone, (void *) hash_cram_address, cram_size);
		shared_file_available_hash_ele 
				+= cram_size/sizeof(struct load_file_ele);
		hash_cram_address += cram_size;
	}

	return KERN_SUCCESS;
}


extern void shared_region_dump_file_entry(
	int		trace_level,
	load_struct_t	*entry);	/* forward */

void shared_region_dump_file_entry(
	int		trace_level,
	load_struct_t	*entry)
{
	int			i;
	loaded_mapping_t	*mapping;

	if (trace_level > shared_region_trace_level) {
		return;
	}
	printf("shared region: %p: "
	       "file_entry %p  base_address=0x%x  file_offset=0x%x  "
	       "%d mappings\n",
	       current_thread(), entry,
	       entry->base_address, entry->file_offset, entry->mapping_cnt);
	mapping = entry->mappings;
	for (i = 0; i < entry->mapping_cnt; i++) {
		printf("shared region: %p:\t#%d: "
		       "offset=0x%x size=0x%x file_offset=0x%x prot=%d\n",
		       current_thread(),
		       i,
		       mapping->mapping_offset,
		       mapping->size,
		       mapping->file_offset,
		       mapping->protection);
		mapping = mapping->next;
	}
}

extern void shared_region_dump_mappings(
	int				trace_level,
	struct shared_file_mapping_np	*mappings,
	int				map_cnt,
	mach_vm_offset_t		base_offset);	/* forward */

void shared_region_dump_mappings(
	int				trace_level,
	struct shared_file_mapping_np	*mappings,
	int				map_cnt,
	mach_vm_offset_t		base_offset)
{
	int	i;

	if (trace_level > shared_region_trace_level) {
		return;
	}

	printf("shared region: %p: %d mappings  base_offset=0x%llx\n",
	       current_thread(), map_cnt, (uint64_t) base_offset);
	for (i = 0; i < map_cnt; i++) {
		printf("shared region: %p:\t#%d: "
		       "addr=0x%llx, size=0x%llx, file_offset=0x%llx, "
		       "prot=(%d,%d)\n",
		       current_thread(),
		       i,
		       (uint64_t) mappings[i].sfm_address,
		       (uint64_t) mappings[i].sfm_size,
		       (uint64_t) mappings[i].sfm_file_offset,
		       mappings[i].sfm_max_prot,
		       mappings[i].sfm_init_prot);
	}
}

extern void shared_region_dump_conflict_info(
	int		trace_level,
	vm_map_t	map,
	vm_map_offset_t	offset,
	vm_map_size_t	size);	/* forward */

void
shared_region_dump_conflict_info(
	int		trace_level,
	vm_map_t	map,
	vm_map_offset_t	offset,
	vm_map_size_t	size)
{
	vm_map_entry_t	entry;
	vm_object_t	object;
	memory_object_t	mem_object;
	kern_return_t	kr;
	char		*filename;

	if (trace_level > shared_region_trace_level) {
		return;
	}

	object = VM_OBJECT_NULL;

	vm_map_lock_read(map);
	if (!vm_map_lookup_entry(map, offset, &entry)) {
		entry = entry->vme_next;
	}
	
	if (entry != vm_map_to_entry(map)) {
		if (entry->is_sub_map) {
			printf("shared region: %p: conflict with submap "
			       "at 0x%llx size 0x%llx !?\n",
			       current_thread(),
			       (uint64_t) offset,
			       (uint64_t) size);
			goto done;
		}

		object = entry->object.vm_object;
		if (object == VM_OBJECT_NULL) {
			printf("shared region: %p: conflict with NULL object "
			       "at 0x%llx size 0x%llx !?\n",
			       current_thread(),
			       (uint64_t) offset,
			       (uint64_t) size);
			object = VM_OBJECT_NULL;
			goto done;
		}

		vm_object_lock(object);
		while (object->shadow != VM_OBJECT_NULL) {
			vm_object_t	shadow;

			shadow = object->shadow;
			vm_object_lock(shadow);
			vm_object_unlock(object);
			object = shadow;
		}

		if (object->internal) {
			printf("shared region: %p: conflict with anonymous "
			       "at 0x%llx size 0x%llx\n",
			       current_thread(),
			       (uint64_t) offset,
			       (uint64_t) size);
			goto done;
		}
		if (! object->pager_ready) {
			printf("shared region: %p: conflict with uninitialized "
			       "at 0x%llx size 0x%llx\n",
			       current_thread(),
			       (uint64_t) offset,
			       (uint64_t) size);
			goto done;
		}

		mem_object = object->pager;

		/*
		 * XXX FBDP: "!internal" doesn't mean it's a vnode pager...
		 */
		kr = vnode_pager_get_object_filename(mem_object,
						     &filename);
		if (kr != KERN_SUCCESS) {
			filename = NULL;
		}
		printf("shared region: %p: conflict with '%s' "
		       "at 0x%llx size 0x%llx\n",
		       current_thread(),
		       filename ? filename : "<unknown>",
		       (uint64_t) offset,
		       (uint64_t) size);
	}
done:
	if (object != VM_OBJECT_NULL) {
		vm_object_unlock(object);
	}
	vm_map_unlock_read(map);
}

/*
 * map_shared_file:
 *
 * Attempt to map a split library into the shared region.  Check if the mappings
 * are already in place.
 */
kern_return_t
map_shared_file(
	int 				map_cnt,
	struct shared_file_mapping_np 	*mappings,
	memory_object_control_t		file_control,
	memory_object_size_t		file_size,
	shared_region_task_mappings_t	sm_info,
	mach_vm_offset_t		base_offset,
	mach_vm_offset_t		*slide_p)
{
	vm_object_t		file_object;
	shared_file_info_t	*shared_file_header;
	load_struct_t		*file_entry;
	loaded_mapping_t	*file_mapping;
	int			i;
	kern_return_t		ret;
	mach_vm_offset_t	slide;

	SHARED_REGION_DEBUG(("map_shared_file()\n"));

	shared_file_header = (shared_file_info_t *)sm_info->region_mappings;

	mutex_lock(&shared_file_header->lock);

	/* If this is the first call to this routine, take the opportunity */
	/* to initialize the hash table which will be used to look-up      */
	/* mappings based on the file object */ 

	if(shared_file_header->hash_init == FALSE) {
		ret = shared_file_header_init(shared_file_header);
		if (ret != KERN_SUCCESS) {
			SHARED_REGION_TRACE(
				SHARED_REGION_TRACE_ERROR,
				("shared_region: %p: map_shared_file: "
				 "shared_file_header_init() failed kr=0x%x\n",
				 current_thread(), ret));
			mutex_unlock(&shared_file_header->lock);
			return KERN_NO_SPACE;
		}
	}

	
	/* Find the entry in the map associated with the current mapping */
	/* of the file object */
	file_object = memory_object_control_to_vm_object(file_control);

	file_entry = lsf_hash_lookup(shared_file_header->hash, 
				     (void *) file_object,
				     mappings[0].sfm_file_offset,
				     shared_file_header->hash_size, 
				     TRUE, TRUE, sm_info);
	if (file_entry) {
		/* File is loaded, check the load manifest for exact match */
		/* we simplify by requiring that the elements be the same  */
		/* size and in the same order rather than checking for     */
		/* semantic equivalence. */

		i = 0;
		file_mapping = file_entry->mappings;
		while(file_mapping != NULL) {
			if(i>=map_cnt) {
				SHARED_REGION_TRACE(
					SHARED_REGION_TRACE_CONFLICT,
					("shared_region: %p: map_shared_file: "
					 "already mapped with "
					 "more than %d mappings\n",
					 current_thread(), map_cnt));
				shared_region_dump_file_entry(
					SHARED_REGION_TRACE_INFO,
					file_entry);
				shared_region_dump_mappings(
					SHARED_REGION_TRACE_INFO,
					mappings, map_cnt, base_offset);

				mutex_unlock(&shared_file_header->lock);
				return KERN_INVALID_ARGUMENT;
			}
			if(((mappings[i].sfm_address)
			    & SHARED_DATA_REGION_MASK) !=
			   file_mapping->mapping_offset ||
			   mappings[i].sfm_size != file_mapping->size ||	
			   mappings[i].sfm_file_offset != file_mapping->file_offset ||	
			   mappings[i].sfm_init_prot != file_mapping->protection) {
				SHARED_REGION_TRACE(
					SHARED_REGION_TRACE_CONFLICT,
					("shared_region: %p: "
					 "mapping #%d differs\n",
					 current_thread(), i));
				shared_region_dump_file_entry(
					SHARED_REGION_TRACE_INFO,
					file_entry);
				shared_region_dump_mappings(
					SHARED_REGION_TRACE_INFO,
					mappings, map_cnt, base_offset);

				break;
			}
			file_mapping = file_mapping->next;
			i++;
		}
		if(i!=map_cnt) {
			SHARED_REGION_TRACE(
				SHARED_REGION_TRACE_CONFLICT,
				("shared_region: %p: map_shared_file: "
				 "already mapped with "
				 "%d mappings instead of %d\n",
				 current_thread(), i, map_cnt));
			shared_region_dump_file_entry(
				SHARED_REGION_TRACE_INFO,
				file_entry);
			shared_region_dump_mappings(
				SHARED_REGION_TRACE_INFO,
				mappings, map_cnt, base_offset);

			mutex_unlock(&shared_file_header->lock);
			return KERN_INVALID_ARGUMENT;
		}

		slide = file_entry->base_address - base_offset; 
		if (slide_p != NULL) {
			/*
			 * File already mapped but at different address,
			 * and the caller is OK with the sliding.
			 */
			*slide_p = slide;
			ret = KERN_SUCCESS;
		} else {
			/*
			 * The caller doesn't want any sliding.  The file needs
			 * to be mapped at the requested address or not mapped.
			 */
			if (slide != 0) {
				/*
				 * The file is already mapped but at a different
				 * address.
				 * We fail.
				 * XXX should we attempt to load at
				 * requested address too ?
				 */
				ret = KERN_FAILURE;
				SHARED_REGION_TRACE(
					SHARED_REGION_TRACE_CONFLICT,
					("shared_region: %p: "
					 "map_shared_file: already mapped, "
					 "would need to slide 0x%llx\n",
					 current_thread(),
					 slide));
			} else {
				/*
				 * The file is already mapped at the correct
				 * address.
				 * We're done !
				 */
				ret = KERN_SUCCESS;
			}
		}
		mutex_unlock(&shared_file_header->lock);
		return ret;
	} else {
		/* File is not loaded, lets attempt to load it */
		ret = lsf_map(mappings, map_cnt, 
			      (void *)file_control, 
			      file_size,
			      sm_info,
			      base_offset,
			      slide_p);
		if(ret == KERN_NO_SPACE) {
			shared_region_mapping_t	regions;
			shared_region_mapping_t	system_region;
			regions = (shared_region_mapping_t)sm_info->self;
			regions->flags |= SHARED_REGION_FULL;
			system_region = lookup_default_shared_region(
				regions->fs_base, regions->system);
			if (system_region == regions) {
				shared_region_mapping_t	new_system_shared_region;
				shared_file_boot_time_init(
					regions->fs_base, regions->system);
				/* current task must stay with its current */
				/* regions, drop count on system_shared_region */
				/* and put back our original set */
				vm_get_shared_region(current_task(), 
						&new_system_shared_region);
                		shared_region_mapping_dealloc_lock(
					new_system_shared_region, 0, 1);
				vm_set_shared_region(current_task(), regions);
			} else if (system_region != NULL) {
                		shared_region_mapping_dealloc_lock(
					system_region, 0, 1);
			}
		}
		mutex_unlock(&shared_file_header->lock);
		return ret;
	}
}

/*
 * shared_region_cleanup:
 *
 * Deallocates all the mappings in the shared region, except those explicitly
 * specified in the "ranges" set of address ranges.
 */
kern_return_t
shared_region_cleanup(
	unsigned int			range_count,
	struct shared_region_range_np	*ranges,
	shared_region_task_mappings_t	sm_info)
{
	kern_return_t		kr;
	ipc_port_t		region_handle;
	vm_named_entry_t	region_named_entry;
	vm_map_t		text_submap, data_submap, submap, next_submap;
	unsigned int		i_range;
	vm_map_offset_t		range_start, range_end;
	vm_map_offset_t		submap_base, submap_end, submap_offset;
	vm_map_size_t		delete_size;

	struct shared_region_range_np	tmp_range;
	unsigned int			sort_index, sorted_index;
	vm_map_offset_t			sort_min_address;
	unsigned int			sort_min_index;

	/*
	 * Since we want to deallocate the holes between the "ranges",
	 * sort the array by increasing addresses.
	 */
	for (sorted_index = 0;
	     sorted_index < range_count;
	     sorted_index++) {

		/* first remaining entry is our new starting point */
		sort_min_index = sorted_index;
		sort_min_address = ranges[sort_min_index].srr_address;

		/* find the lowest mapping_offset in the remaining entries */
		for (sort_index = sorted_index + 1;
		     sort_index < range_count;
		     sort_index++) {
			if (ranges[sort_index].srr_address < sort_min_address) {
				/* lowest address so far... */
				sort_min_index = sort_index;
				sort_min_address =
					ranges[sort_min_index].srr_address;
			}
		}

		if (sort_min_index != sorted_index) {
			/* swap entries */
			tmp_range = ranges[sort_min_index];
			ranges[sort_min_index] = ranges[sorted_index];
			ranges[sorted_index] = tmp_range;
		}
	}

	region_handle = (ipc_port_t) sm_info->text_region;
	region_named_entry = (vm_named_entry_t) region_handle->ip_kobject;
	text_submap = region_named_entry->backing.map;

	region_handle = (ipc_port_t) sm_info->data_region;
	region_named_entry = (vm_named_entry_t) region_handle->ip_kobject;
	data_submap = region_named_entry->backing.map;

	submap = text_submap;
	next_submap = submap;
	submap_base = sm_info->client_base;
	submap_offset = 0;
	submap_end = submap_base + sm_info->text_size;
	for (i_range = 0;
	     i_range < range_count;
	     i_range++) {

		/* get the next range of addresses to keep */
		range_start = ranges[i_range].srr_address;
		range_end = range_start + ranges[i_range].srr_size;
		/* align them to page boundaries */
		range_start = vm_map_trunc_page(range_start);
		range_end = vm_map_round_page(range_end);

		/* make sure we don't go beyond the submap's boundaries */
		if (range_start < submap_base) {
			range_start = submap_base;
		} else if (range_start >= submap_end) {
			range_start = submap_end;
		}
		if (range_end < submap_base) {
			range_end = submap_base;
		} else if (range_end >= submap_end) {
			range_end = submap_end;
		}

		if (range_start > submap_base + submap_offset) {
			/*
			 * Deallocate everything between the last offset in the
			 * submap and the start of this range.
			 */
			delete_size = range_start -
				(submap_base + submap_offset);
			(void) vm_deallocate(submap,
					     submap_offset,
					     delete_size);
		} else {
			delete_size = 0;
		}

		/* skip to the end of the range */
		submap_offset += delete_size + (range_end - range_start);

		if (submap_base + submap_offset >= submap_end) {
			/* get to next submap */

			if (submap == data_submap) {
				/* no other submap after data: done ! */
				break;
			}

			/* get original range again */
			range_start = ranges[i_range].srr_address;
			range_end = range_start + ranges[i_range].srr_size;
			range_start = vm_map_trunc_page(range_start);
			range_end = vm_map_round_page(range_end);

			if (range_end > submap_end) {
				/*
				 * This last range overlaps with the next
				 * submap.  We need to process it again
				 * after switching submaps.  Otherwise, we'll
				 * just continue with the next range.
				 */
				i_range--;
			}

			if (submap == text_submap) {
				/*
				 * Switch to the data submap.
				 */
				submap = data_submap;
				submap_offset = 0;
				submap_base = sm_info->client_base + 
					sm_info->text_size;
				submap_end = submap_base + sm_info->data_size;
			}
		}
	}

	if (submap_base + submap_offset < submap_end) {
		/* delete remainder of this submap, from "offset" to the end */
		(void) vm_deallocate(submap,
				     submap_offset,
				     submap_end - submap_base - submap_offset);
		/* if nothing to keep in data submap, delete it all */
		if (submap == text_submap) {
			submap = data_submap;
			submap_offset = 0;
			submap_base = sm_info->client_base + sm_info->text_size;
			submap_end = submap_base + sm_info->data_size;
			(void) vm_deallocate(data_submap,
					     0,
					     submap_end - submap_base);
		}
	}

	kr = KERN_SUCCESS;
	return kr;
}

/* A hash lookup function for the list of loaded files in      */
/* shared_memory_server space.  */

static load_struct_t  *
lsf_hash_lookup(
	queue_head_t			*hash_table,
	void				*file_object,
	vm_offset_t			recognizableOffset,
	int				size,
	boolean_t			regular,
	boolean_t			alternate,
	shared_region_task_mappings_t	sm_info)
{
	register queue_t	bucket;
	load_struct_t		*entry;
	shared_region_mapping_t	target_region;
	int			depth;
	
	LSF_DEBUG(("lsf_hash_lookup: table=%p, file=%p, offset=0x%x size=0x%x "
		   "reg=%d alt=%d sm_info=%p\n",
		   hash_table, file_object, recognizableOffset, size,
		   regular, alternate, sm_info));

	bucket = &(hash_table[load_file_hash((int)file_object, size)]);
	for (entry = (load_struct_t *)queue_first(bucket);
		!queue_end(bucket, &entry->links);
		entry = (load_struct_t *)queue_next(&entry->links)) {

		if ((entry->file_object == (int)file_object) &&
                    (entry->file_offset == recognizableOffset)) {
		   target_region = (shared_region_mapping_t)sm_info->self;
		   depth = target_region->depth;
		   while(target_region) {
		      if((!(sm_info->self)) ||
				((target_region == entry->regions_instance) &&
				(target_region->depth >= entry->depth))) {
			if(alternate &&
			   entry->base_address >= sm_info->alternate_base) {
				LSF_DEBUG(("lsf_hash_lookup: "
					   "alt=%d found entry %p "
					   "(base=0x%x "
					   "alt_base=0x%x)\n",
					   alternate, entry,
					   entry->base_address,
					   sm_info->alternate_base));
				return entry;
			}
		        if (regular &&
			    entry->base_address < sm_info->alternate_base) {
				LSF_DEBUG(("lsf_hash_lookup: "
					   "reg=%d found entry %p "
					   "(base=0x%x "
					   "alt_base=0x%x)\n",
					   regular, entry,
					   entry->base_address,
					   sm_info->alternate_base));
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

	LSF_DEBUG(("lsf_hash_lookup: table=%p, file=%p, offset=0x%x size=0x%x "
		   "reg=%d alt=%d sm_info=%p NOT FOUND\n",
		   hash_table, file_object, recognizableOffset, size,
		   regular, alternate, sm_info));
	return (load_struct_t *)0;
}

__private_extern__ load_struct_t *
lsf_remove_regions_mappings_lock(
	shared_region_mapping_t	region,
	shared_region_task_mappings_t	sm_info,
	int need_sfh_lock)
{
	int			i;
	register queue_t	bucket;
	shared_file_info_t	*shared_file_header;
	load_struct_t		*entry;
	load_struct_t		*next_entry;

	shared_file_header = (shared_file_info_t *)sm_info->region_mappings;

	LSF_DEBUG(("lsf_remove_regions_mappings_lock(region=%p,sm_info=%p) "
		   "sfh=%p\n",
		   region, sm_info, shared_file_header));
	if (need_sfh_lock)
		mutex_lock(&shared_file_header->lock);
	if(shared_file_header->hash_init == FALSE) {
		if (need_sfh_lock)
			mutex_unlock(&shared_file_header->lock);
		LSF_DEBUG(("lsf_remove_regions_mappings_lock"
			   "(region=%p,sm_info=%p): not inited\n",
			   region, sm_info));
		return NULL;
	}
	for(i = 0;  i<shared_file_header->hash_size; i++) {
		bucket = &shared_file_header->hash[i];
		for (entry = (load_struct_t *)queue_first(bucket);
			!queue_end(bucket, &entry->links);) {
		   next_entry = (load_struct_t *)queue_next(&entry->links);
		   if(region == entry->regions_instance) {
			   LSF_DEBUG(("lsf_remove_regions_mapping_lock: "
				      "entry %p region %p: "
				      "unloading\n",
				      entry, region));
			   lsf_unload((void *)entry->file_object, 
					entry->base_address, sm_info);
		   } else {
			   LSF_DEBUG(("lsf_remove_regions_mapping_lock: "
				      "entry %p region %p target region %p: "
				      "not unloading\n",
				      entry, entry->regions_instance, region));
		   }
			   
		   entry = next_entry;
		}
	}
	if (need_sfh_lock)
		mutex_unlock(&shared_file_header->lock);
	LSF_DEBUG(("lsf_removed_regions_mapping_lock done\n"));

	return NULL;	/* XXX */
}

/*
 * Symbol compatability; we believe shared_region_mapping_dealloc() is the
 * only caller.  Remove this stub function and the corresponding symbol
 * export for Merlot.
 */
load_struct_t *
lsf_remove_regions_mappings(
	shared_region_mapping_t	region,
	shared_region_task_mappings_t	sm_info)
{
	return lsf_remove_regions_mappings_lock(region, sm_info, 1);
}

/* Removes a map_list, (list of loaded extents) for a file from     */
/* the loaded file hash table.  */

static load_struct_t *
lsf_hash_delete(
	load_struct_t	*target_entry,	/* optional:  NULL if not relevant */
	void		*file_object,
	vm_offset_t	base_offset,
	shared_region_task_mappings_t	sm_info)
{
	register queue_t	bucket;
	shared_file_info_t	*shared_file_header;
	load_struct_t		*entry;

	LSF_DEBUG(("lsf_hash_delete(target=%p,file=%p,base=0x%x,sm_info=%p)\n",
		   target_entry, file_object, base_offset, sm_info));

	shared_file_header = (shared_file_info_t *)sm_info->region_mappings;

	bucket = &shared_file_header->hash
	     [load_file_hash((int)file_object, shared_file_header->hash_size)];

	for (entry = (load_struct_t *)queue_first(bucket);
		!queue_end(bucket, &entry->links);
		entry = (load_struct_t *)queue_next(&entry->links)) {
		if((!(sm_info->self)) || ((shared_region_mapping_t)
				sm_info->self == entry->regions_instance)) {
			if ((target_entry == NULL ||
			     entry == target_entry) &&
			    (entry->file_object == (int) file_object)  &&
			    (entry->base_address == base_offset)) {
				queue_remove(bucket, entry, 
						load_struct_ptr_t, links);
				LSF_DEBUG(("lsf_hash_delete: found it\n"));
				return entry;
			}
		}
	}

	LSF_DEBUG(("lsf_hash_delete; not found\n"));
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

	LSF_DEBUG(("lsf_hash_insert(entry=%p,sm_info=%p): file=%p base=0x%x\n",
		   entry, sm_info, entry->file_object, entry->base_address));

	shared_file_header = (shared_file_info_t *)sm_info->region_mappings;
	queue_enter(&shared_file_header->hash
			[load_file_hash(entry->file_object, 
					shared_file_header->hash_size)],
			entry, load_struct_ptr_t, links);
}
	


/*
 * lsf_slide:
 *
 * Look in the shared region, starting from the end, for a place to fit all the
 * mappings while respecting their relative offsets.
 */
static kern_return_t
lsf_slide(
	unsigned int			map_cnt,
	struct shared_file_mapping_np	*mappings_in,
	shared_region_task_mappings_t	sm_info,
	mach_vm_offset_t		*base_offset_p)
{
	mach_vm_offset_t 		max_mapping_offset;
	int 			       	i;
	vm_map_entry_t			map_entry, prev_entry, next_entry;
	mach_vm_offset_t		prev_hole_start, prev_hole_end;
	mach_vm_offset_t		mapping_offset, mapping_end_offset;
	mach_vm_offset_t		base_offset;
	mach_vm_size_t			mapping_size;
	mach_vm_offset_t		wiggle_room, wiggle;
	vm_map_t			text_map, data_map, map;
	vm_named_entry_t		region_entry;
	ipc_port_t			region_handle;
	kern_return_t			kr;

	struct shared_file_mapping_np	*mappings, tmp_mapping;
	unsigned int			sort_index, sorted_index;
	vm_map_offset_t			sort_min_address;
	unsigned int			sort_min_index;

	/*
	 * Sort the mappings array, so that we can try and fit them in
	 * in the right order as we progress along the VM maps.
	 *
	 * We can't modify the original array (the original order is
	 * important when doing lookups of the mappings), so copy it first.
	 */

	kr = kmem_alloc(kernel_map,
			(vm_offset_t *) &mappings,
			(vm_size_t) (map_cnt * sizeof (mappings[0])));
	if (kr != KERN_SUCCESS) {
		return KERN_NO_SPACE;
	}

	bcopy(mappings_in, mappings, map_cnt * sizeof (mappings[0]));

	max_mapping_offset = 0;
	for (sorted_index = 0;
	     sorted_index < map_cnt;
	     sorted_index++) {

		/* first remaining entry is our new starting point */
		sort_min_index = sorted_index;
		mapping_end_offset = ((mappings[sort_min_index].sfm_address &
				       SHARED_TEXT_REGION_MASK) +
				      mappings[sort_min_index].sfm_size);
		sort_min_address = mapping_end_offset;
		/* compute the highest mapping_offset as well... */
		if (mapping_end_offset > max_mapping_offset) {
			max_mapping_offset = mapping_end_offset;
		}
		/* find the lowest mapping_offset in the remaining entries */
		for (sort_index = sorted_index + 1;
		     sort_index < map_cnt;
		     sort_index++) {

			mapping_end_offset =
				((mappings[sort_index].sfm_address &
				  SHARED_TEXT_REGION_MASK) +
				 mappings[sort_index].sfm_size);

			if (mapping_end_offset < sort_min_address) {
				/* lowest mapping_offset so far... */
				sort_min_index = sort_index;
				sort_min_address = mapping_end_offset;
			}
		}
		if (sort_min_index != sorted_index) {
			/* swap entries */
			tmp_mapping = mappings[sort_min_index];
			mappings[sort_min_index] = mappings[sorted_index];
			mappings[sorted_index] = tmp_mapping;
		}

	}

	max_mapping_offset = vm_map_round_page(max_mapping_offset);

	/* start from the end of the shared area */
	base_offset = sm_info->text_size;

	/* can all the mappings fit ? */
	if (max_mapping_offset > base_offset) {
		kmem_free(kernel_map,
			  (vm_offset_t) mappings,
			  map_cnt * sizeof (mappings[0]));
		return KERN_FAILURE;
	}

	/*
	 * Align the last mapping to the end of the submaps
	 * and start from there.
	 */
	base_offset -= max_mapping_offset;

	region_handle = (ipc_port_t) sm_info->text_region;
	region_entry = (vm_named_entry_t) region_handle->ip_kobject;
	text_map = region_entry->backing.map;

	region_handle = (ipc_port_t) sm_info->data_region;
	region_entry = (vm_named_entry_t) region_handle->ip_kobject;
	data_map = region_entry->backing.map;

	vm_map_lock_read(text_map);
	vm_map_lock_read(data_map);

start_over:
	/*
	 * At first, we can wiggle all the way from our starting point
	 * (base_offset) towards the start of the map (0), if needed.
	 */
	wiggle_room = base_offset;

	for (i = (signed) map_cnt - 1; i >= 0; i--) {
		if (mappings[i].sfm_size == 0) {
			/* nothing to map here... */
			continue;
		}
		if (mappings[i].sfm_init_prot & VM_PROT_COW) {
			/* copy-on-write mappings are in the data submap */
			map = data_map;
		} else {
			/* other mappings are in the text submap */
			map = text_map;
		}
		/* get the offset within the appropriate submap */
		mapping_offset = (mappings[i].sfm_address &
				  SHARED_TEXT_REGION_MASK);
		mapping_size = mappings[i].sfm_size;
		mapping_end_offset = mapping_offset + mapping_size;
		mapping_offset = vm_map_trunc_page(mapping_offset);
		mapping_end_offset = vm_map_round_page(mapping_end_offset);
		mapping_size = mapping_end_offset - mapping_offset;

		for (;;) {
			if (vm_map_lookup_entry(map,
						base_offset + mapping_offset,
						&map_entry)) {
				/*
				 * The start address for that mapping
				 * is already mapped: no fit.
				 * Locate the hole immediately before this map
				 * entry.
				 */
				prev_hole_end = map_entry->vme_start;
				prev_entry = map_entry->vme_prev;
				if (prev_entry == vm_map_to_entry(map)) {
					/* no previous entry */
					prev_hole_start = map->min_offset;
				} else {
					/* previous entry ends here */
					prev_hole_start = prev_entry->vme_end;
				}
			} else {
				/*
				 * The start address for that mapping is not
				 * mapped.
				 * Locate the start and end of the hole
				 * at that location.
				 */
				/* map_entry is the previous entry */
				if (map_entry == vm_map_to_entry(map)) {
					/* no previous entry */
					prev_hole_start = map->min_offset;
				} else {
					/* previous entry ends there */
					prev_hole_start = map_entry->vme_end;
				}
				next_entry = map_entry->vme_next;
				if (next_entry == vm_map_to_entry(map)) {
					/* no next entry */
					prev_hole_end = map->max_offset;
				} else {
					prev_hole_end = next_entry->vme_start;
				}
			}

			if (prev_hole_end <= base_offset + mapping_offset) {
				/* hole is to our left: try and wiggle to fit */
				wiggle = base_offset + mapping_offset - prev_hole_end + mapping_size;
				if (wiggle > base_offset) {
					/* we're getting out of the map */
					kr = KERN_FAILURE;
					goto done;
				}
				base_offset -= wiggle;
				if (wiggle > wiggle_room) {
					/* can't wiggle that much: start over */
					goto start_over;
				}
				/* account for the wiggling done */
				wiggle_room -= wiggle;
			}

			if (prev_hole_end >
			    base_offset + mapping_offset + mapping_size) {
				/*
				 * The hole extends further to the right
				 * than what we need.  Ignore the extra space.
				 */
				prev_hole_end =	(base_offset + mapping_offset +
						 mapping_size);
			}

			if (prev_hole_end <
			    base_offset + mapping_offset + mapping_size) {
				/*
				 * The hole is not big enough to establish
				 * the mapping right there:  wiggle towards
				 * the beginning of the hole so that the end
				 * of our mapping fits in the hole...
				 */
				wiggle = base_offset + mapping_offset
					+ mapping_size - prev_hole_end;
				if (wiggle > base_offset) {
					/* we're getting out of the map */
					kr = KERN_FAILURE;
					goto done;
				}
				base_offset -= wiggle;
				if (wiggle > wiggle_room) {
					/* can't wiggle that much: start over */
					goto start_over;
				}
				/* account for the wiggling done */
				wiggle_room -= wiggle;

				/* keep searching from this new base */
				continue;
			}

			if (prev_hole_start > base_offset + mapping_offset) {
				/* no hole found: keep looking */
				continue;
			}

			/* compute wiggling room at this hole */
			wiggle = base_offset + mapping_offset - prev_hole_start;
			if (wiggle < wiggle_room) {
				/* less wiggle room than before... */
				wiggle_room = wiggle;
			}

			/* found a hole that fits: skip to next mapping */
			break;
		} /* while we look for a hole */
	} /* for each mapping */

	*base_offset_p = base_offset;
	kr = KERN_SUCCESS;

done:
	vm_map_unlock_read(text_map);
	vm_map_unlock_read(data_map);

	kmem_free(kernel_map,
		  (vm_offset_t) mappings,
		  map_cnt * sizeof (mappings[0]));

	return kr;
}

/*
 * lsf_map:
 *
 * Attempt to establish the mappings for a split library into the shared region.
 */
static kern_return_t
lsf_map(
	struct shared_file_mapping_np	*mappings,
	int				map_cnt,
	void				*file_control,
	memory_object_offset_t		file_size,
	shared_region_task_mappings_t	sm_info,
	mach_vm_offset_t		base_offset,
	mach_vm_offset_t		*slide_p)
{
	load_struct_t		*entry;
	loaded_mapping_t	*file_mapping;
	loaded_mapping_t	**tptr;
	ipc_port_t		region_handle;
	vm_named_entry_t	region_entry;
	mach_port_t		map_port;
	vm_object_t		file_object;
	kern_return_t		kr;
	int			i;
	mach_vm_offset_t	original_base_offset;
	mach_vm_size_t		total_size;

	/* get the VM object from the file's memory object handle */
	file_object = memory_object_control_to_vm_object(file_control);

	original_base_offset = base_offset;

	LSF_DEBUG(("lsf_map"
		   "(cnt=%d,file=%p,sm_info=%p)"
		   "\n",
		   map_cnt, file_object,
		   sm_info));

restart_after_slide:
	/* get a new "load_struct_t" to described the mappings for that file */
	entry = (load_struct_t *)zalloc(lsf_zone);
	LSF_ALLOC_DEBUG(("lsf_map: entry=%p map_cnt=%d\n", entry, map_cnt));
	LSF_DEBUG(("lsf_map"
		   "(cnt=%d,file=%p,sm_info=%p) "
		   "entry=%p\n",
		   map_cnt, file_object,
		   sm_info, entry));
	if (entry == NULL) {
		SHARED_REGION_TRACE(
			SHARED_REGION_TRACE_ERROR,
			("shared_region: %p: "
			 "lsf_map: unable to allocate entry\n",
			 current_thread()));
		return KERN_NO_SPACE;
	}
	shared_file_available_hash_ele--;
	entry->file_object = (int)file_object;
	entry->mapping_cnt = map_cnt;
	entry->mappings = NULL;
	entry->links.prev = (queue_entry_t) 0;
	entry->links.next = (queue_entry_t) 0;
	entry->regions_instance = (shared_region_mapping_t)sm_info->self;
	entry->depth=((shared_region_mapping_t)sm_info->self)->depth;
        entry->file_offset = mappings[0].sfm_file_offset;

	/* insert the new file entry in the hash table, for later lookups */
	lsf_hash_insert(entry, sm_info);

	/* where we should add the next mapping description for that file */
	tptr = &(entry->mappings);

	entry->base_address = base_offset;
	total_size = 0;

	/* establish each requested mapping */
	for (i = 0; i < map_cnt; i++) {
		mach_vm_offset_t	target_address;
		mach_vm_offset_t	region_mask;

		if (mappings[i].sfm_init_prot & VM_PROT_COW) {
			region_handle = (ipc_port_t)sm_info->data_region;
			region_mask = SHARED_DATA_REGION_MASK;
			if ((((mappings[i].sfm_address + base_offset)
			      & GLOBAL_SHARED_SEGMENT_MASK) != 0x10000000) ||
			    (((mappings[i].sfm_address + base_offset +
			       mappings[i].sfm_size - 1)
			      & GLOBAL_SHARED_SEGMENT_MASK) != 0x10000000)) {
				SHARED_REGION_TRACE(
					SHARED_REGION_TRACE_ERROR,
					("shared_region: %p: lsf_map: "
					 "RW mapping #%d not in segment",
					 current_thread(), i));
				shared_region_dump_mappings(
					SHARED_REGION_TRACE_ERROR,
					mappings, map_cnt, base_offset);

				lsf_deallocate(entry,
					       file_object, 
					       entry->base_address,
					       sm_info,
					       TRUE);
				return KERN_INVALID_ARGUMENT;
			}
		} else {
			region_mask = SHARED_TEXT_REGION_MASK;
			region_handle = (ipc_port_t)sm_info->text_region;
			if (((mappings[i].sfm_address + base_offset)
			     & GLOBAL_SHARED_SEGMENT_MASK) ||
			    ((mappings[i].sfm_address + base_offset +
			      mappings[i].sfm_size - 1)
			     & GLOBAL_SHARED_SEGMENT_MASK)) {
				SHARED_REGION_TRACE(
					SHARED_REGION_TRACE_ERROR,
					("shared_region: %p: lsf_map: "
					 "RO mapping #%d not in segment",
					 current_thread(), i));
				shared_region_dump_mappings(
					SHARED_REGION_TRACE_ERROR,
					mappings, map_cnt, base_offset);

				lsf_deallocate(entry,
					       file_object, 
					       entry->base_address,
					       sm_info,
					       TRUE);
				return KERN_INVALID_ARGUMENT;
			}
		}
		if (!(mappings[i].sfm_init_prot & VM_PROT_ZF) &&
		    ((mappings[i].sfm_file_offset + mappings[i].sfm_size) >
		     (file_size))) {
			SHARED_REGION_TRACE(
				SHARED_REGION_TRACE_ERROR,
				("shared_region: %p: lsf_map: "
				 "ZF mapping #%d beyond EOF",
				 current_thread(), i));
			shared_region_dump_mappings(SHARED_REGION_TRACE_ERROR,
						    mappings, map_cnt,
						    base_offset);


			lsf_deallocate(entry,
				       file_object,
				       entry->base_address,
				       sm_info,
				       TRUE);
			return KERN_INVALID_ARGUMENT;
		}
		target_address = entry->base_address +
			((mappings[i].sfm_address) & region_mask);
		if (mappings[i].sfm_init_prot & VM_PROT_ZF) {
			map_port = MACH_PORT_NULL;
		} else {
			map_port = (ipc_port_t) file_object->pager;
		}
		region_entry = (vm_named_entry_t) region_handle->ip_kobject;

		total_size += mappings[i].sfm_size;
		if (mappings[i].sfm_size == 0) {
			/* nothing to map... */
			kr = KERN_SUCCESS;
		} else {
			kr = mach_vm_map(
				region_entry->backing.map,
				&target_address,
				vm_map_round_page(mappings[i].sfm_size),
				0,
				VM_FLAGS_FIXED,
				map_port,
				mappings[i].sfm_file_offset,
				TRUE,
				(mappings[i].sfm_init_prot &
				 (VM_PROT_READ|VM_PROT_EXECUTE)),
				(mappings[i].sfm_max_prot &
				 (VM_PROT_READ|VM_PROT_EXECUTE)),
				VM_INHERIT_DEFAULT);
		}
		if (kr != KERN_SUCCESS) {
			vm_offset_t old_base_address;

			old_base_address = entry->base_address;
			lsf_deallocate(entry,
				       file_object,
				       entry->base_address,
				       sm_info,
				       TRUE);
			entry = NULL;

			if (slide_p != NULL) {
				/*
				 * Requested mapping failed but the caller
				 * is OK with sliding the library in the
				 * shared region, so let's try and slide it...
				 */

				SHARED_REGION_TRACE(
					SHARED_REGION_TRACE_CONFLICT,
					("shared_region: %p: lsf_map: "
					 "mapping #%d failed to map, "
					 "kr=0x%x, sliding...\n",
					 current_thread(), i, kr));
				shared_region_dump_mappings(
					SHARED_REGION_TRACE_INFO,
					mappings, map_cnt, base_offset);
				shared_region_dump_conflict_info(
					SHARED_REGION_TRACE_CONFLICT,
					region_entry->backing.map,
					(old_base_address +
					 ((mappings[i].sfm_address)
					  & region_mask)),
					vm_map_round_page(mappings[i].sfm_size));

				/* lookup an appropriate spot */
				kr = lsf_slide(map_cnt, mappings,
					       sm_info, &base_offset);
				if (kr == KERN_SUCCESS) {
					/* try and map it there ... */
					goto restart_after_slide;
				}
				/* couldn't slide ... */
			}
			       
			SHARED_REGION_TRACE(
				SHARED_REGION_TRACE_CONFLICT,
				("shared_region: %p: lsf_map: "
				 "mapping #%d failed to map, "
				 "kr=0x%x, no sliding\n",
				 current_thread(), i, kr));
			shared_region_dump_mappings(
				SHARED_REGION_TRACE_INFO,
				mappings, map_cnt, base_offset);
			shared_region_dump_conflict_info(
				SHARED_REGION_TRACE_CONFLICT,
				region_entry->backing.map,
				(old_base_address +
				 ((mappings[i].sfm_address)
				  & region_mask)),
				vm_map_round_page(mappings[i].sfm_size));
			return KERN_FAILURE;
		}

		/* record this mapping */
		file_mapping = (loaded_mapping_t *)zalloc(lsf_zone);
		if (file_mapping == NULL) {
			lsf_deallocate(entry,
				       file_object,
				       entry->base_address,
				       sm_info,
				       TRUE);
			SHARED_REGION_TRACE(
				SHARED_REGION_TRACE_ERROR,
				("shared_region: %p: "
				 "lsf_map: unable to allocate mapping\n",
				 current_thread()));
			return KERN_NO_SPACE;
		}
		shared_file_available_hash_ele--;
		file_mapping->mapping_offset = (mappings[i].sfm_address) 
								& region_mask;
		file_mapping->size = mappings[i].sfm_size;
		file_mapping->file_offset = mappings[i].sfm_file_offset;
		file_mapping->protection = mappings[i].sfm_init_prot;
		file_mapping->next = NULL;
		LSF_DEBUG(("lsf_map: file_mapping %p "
			   "for offset=0x%x size=0x%x\n",
			   file_mapping, file_mapping->mapping_offset,
			   file_mapping->size));

		/* and link it to the file entry */
		*tptr = file_mapping;

		/* where to put the next mapping's description */
		tptr = &(file_mapping->next);
	}

	if (slide_p != NULL) {
		*slide_p = base_offset - original_base_offset;
	}

	if ((sm_info->flags & SHARED_REGION_STANDALONE) ||
	    (total_size == 0)) {
		/*
		 * Two cases:
		 * 1. we have a standalone and private shared region, so we
		 * don't really need to keep the information about each file
		 * and each mapping.  Just deallocate it all.
		 * 2. the total size of the mappings is 0, so nothing at all
		 * was mapped.  Let's not waste kernel resources to describe
		 * nothing.
		 *
		 * XXX we still have the hash table, though...
		 */
		lsf_deallocate(entry, file_object, entry->base_address, sm_info,
			       FALSE);
	}

	LSF_DEBUG(("lsf_map: done\n"));
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
	lsf_deallocate(NULL, file_object, base_offset, sm_info, TRUE);
}

/*
 * lsf_deallocate:
 *
 * Deallocates all the "shared region" internal data structures describing
 * the file and its mappings.
 * Also deallocate the actual file mappings if requested ("unload" arg).
 */
static void
lsf_deallocate(
	load_struct_t		*target_entry,
	void			*file_object,
	vm_offset_t		base_offset,
	shared_region_task_mappings_t	sm_info,
	boolean_t		unload)
{
	load_struct_t		*entry;
	loaded_mapping_t	*map_ele;
	loaded_mapping_t	*back_ptr;
	kern_return_t		kr;

	LSF_DEBUG(("lsf_deallocate(target=%p,file=%p,base=0x%x,sm_info=%p,unload=%d)\n",
		   target_entry, file_object, base_offset, sm_info, unload));
	entry = lsf_hash_delete(target_entry,
				file_object,
				base_offset,
				sm_info);
	if (entry) {
		map_ele = entry->mappings;
		while(map_ele != NULL) {
			if (unload) {
				ipc_port_t		region_handle;
				vm_named_entry_t	region_entry;

				if(map_ele->protection & VM_PROT_COW) {
					region_handle = (ipc_port_t)
						sm_info->data_region;
				} else {
					region_handle = (ipc_port_t)
						sm_info->text_region;
				}
				region_entry = (vm_named_entry_t)
					region_handle->ip_kobject;
				
				kr = vm_deallocate(region_entry->backing.map,
						   (entry->base_address + 
						    map_ele->mapping_offset),
						   map_ele->size);
				assert(kr == KERN_SUCCESS);
			}
			back_ptr = map_ele;
			map_ele = map_ele->next;
			LSF_DEBUG(("lsf_deallocate: freeing mapping %p "
				   "offset 0x%x size 0x%x\n",
				   back_ptr, back_ptr->mapping_offset,
				   back_ptr->size));
			zfree(lsf_zone, back_ptr);
			shared_file_available_hash_ele++;
		}
		LSF_DEBUG(("lsf_deallocate: freeing entry %p\n", entry));
		LSF_ALLOC_DEBUG(("lsf_deallocate: entry=%p", entry));
		zfree(lsf_zone, entry);
	        shared_file_available_hash_ele++;
	}
	LSF_DEBUG(("lsf_deallocate: done\n"));
}

/* integer is from 1 to 100 and represents percent full */
unsigned int
lsf_mapping_pool_gauge(void)
{
	return ((lsf_zone->count * lsf_zone->elem_size) * 100)/lsf_zone->max_size;
}
