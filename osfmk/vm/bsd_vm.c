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

#include <sys/errno.h>
#include <kern/host.h>
#include <mach/mach_types.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_pageout.h>
#include <mach/kern_return.h>
#include <mach/memory_object_types.h>
#include <mach/port.h>
#include <mach/policy.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>
#include <kern/thread.h>
#include <vm/vm_pageout.h>


/* BSD VM COMPONENT INTERFACES */
int
get_map_nentries(
	vm_map_t);

vm_offset_t
get_map_start(
	vm_map_t);

vm_offset_t
get_map_end(
	vm_map_t);

/*
 * 
 */
int
get_map_nentries(
	vm_map_t map)
{
	return(map->hdr.nentries);
}

/*
 * 
 */
vm_offset_t
get_map_start(
	vm_map_t map)
{
	return(vm_map_first_entry(map)->vme_start);
}

/*
 * 
 */
vm_offset_t
get_map_end(
	vm_map_t map)
{
	return(vm_map_last_entry(map)->vme_end);
}

/* 
 * BSD VNODE PAGER 
 */

/* until component support available */
int	vnode_pager_workaround;

typedef int vnode_port_t;

typedef struct vnode_pager {
	ipc_port_t pager;			/* pager */
	ipc_port_t pager_handle;	/* pager handle */
	ipc_port_t vm_obj_handle;	/* memory object's control handle */
	vnode_port_t vnode_handle;	/* vnode handle */
} *vnode_pager_t;

typedef struct vnode_port_entry {
	queue_chain_t	links; 		/* queue links */
	ipc_port_t	name;			/* port name */
	vnode_pager_t	pager_rec;	/* pager record */
} *vnode_port_entry_t;


#define         VNODE_PORT_HASH_COUNT   127
#define         vnode_port_hash(name_port) \
                        (((int)(name_port) & 0xffffff) % VNODE_PORT_HASH_COUNT)

queue_head_t	vnode_port_hashtable[VNODE_PORT_HASH_COUNT];
zone_t			vnode_port_hash_zone;
decl_simple_lock_data(,vnode_port_hash_lock)


ipc_port_t
trigger_name_to_port(
	mach_port_t);

void 
vnode_pager_bootstrap(
	void);

void
vnode_pager_alloc_map(
	void);

ipc_port_t
vnode_pager_setup(
	vnode_port_t,
	ipc_port_t);

ipc_port_t
vnode_pager_lookup(
	vnode_port_t,
	ipc_port_t);

kern_return_t
vnode_pager_init(
	ipc_port_t, 
	ipc_port_t, 
	vm_size_t);

kern_return_t
vnode_pager_data_request( 
	ipc_port_t, 
	ipc_port_t,
	vm_object_offset_t, 
	vm_size_t, 
	vm_prot_t);

kern_return_t
vnode_pager_data_return(
	ipc_port_t,
	ipc_port_t,
	vm_object_offset_t,
	pointer_t,
	vm_size_t,
	boolean_t,
	boolean_t);

void
vnode_pager_no_senders(
	ipc_port_t,
	mach_port_mscount_t);

kern_return_t
vnode_pager_terminate(
	ipc_port_t,
	ipc_port_t);

kern_return_t
vnode_pager_cluster_read(
	vnode_pager_t, 
	vm_object_offset_t, 
	vm_size_t);

void
vnode_pager_cluster_write(
	vnode_pager_t,
	vm_object_offset_t,
	vm_size_t);

kern_return_t
memory_object_change_attributes(
        vm_object_t,
        memory_object_flavor_t,
        memory_object_info_t,
        mach_msg_type_number_t,
        ipc_port_t,
        mach_msg_type_name_t);

int    
vnode_pagein(
	vnode_port_t,
	upl_t,
	vm_offset_t,
	vm_object_offset_t, 
	int, 
	int,
	int *);
int    
vnode_pageout(
	vnode_port_t,
	upl_t,
	vm_offset_t,
	vm_object_offset_t, 
	int, 
	int,
	int *);

vnode_pager_t
vnode_object_create(
	vnode_port_t	vp);

void
vnode_port_hash_init(void);

void
vnode_port_hash_insert(
	ipc_port_t,   
	vnode_pager_t);

vnode_pager_t
vnode_port_hash_lookup(
	ipc_port_t);

void
vnode_port_hash_delete(
	ipc_port_t);

void
vnode_pager_release_from_cache(
	int	*cnt);

zone_t	vnode_pager_zone;


#define	VNODE_PAGER_NULL	((vnode_pager_t) 0)

/* TODO: Should be set dynamically by vnode_pager_init() */
#define CLUSTER_SHIFT 	1

/* TODO: Should be set dynamically by vnode_pager_bootstrap() */
#define	MAX_VNODE		10000


#if DEBUG
int pagerdebug=0;

#define PAGER_ALL		0xffffffff
#define	PAGER_INIT		0x00000001
#define	PAGER_PAGEIN	0x00000002

#define PAGER_DEBUG(LEVEL, A) {if ((pagerdebug & LEVEL)==LEVEL){printf A;}}
#else
#define PAGER_DEBUG(LEVEL, A)
#endif

/*
 *	Routine:	macx_triggers
 *	Function:
 *		Syscall interface to set the call backs for low and
 *		high water marks.
 */
int
macx_triggers(
	int	hi_water,
	int	low_water,
	int	flags,
	mach_port_t	trigger_name)
{
	kern_return_t kr;
	ipc_port_t		default_pager_port = MACH_PORT_NULL;
	ipc_port_t		trigger_port;

	kr = host_default_memory_manager(host_priv_self(), 
					&default_pager_port, 0);
	if(kr != KERN_SUCCESS) {
		return EINVAL;
	}
	trigger_port = trigger_name_to_port(trigger_name);
	if(trigger_port == NULL) {
		return EINVAL;
	}
        /* trigger_port is locked and active */
        ip_unlock(trigger_port);
	default_pager_triggers(default_pager_port, 
			hi_water, low_water, flags, trigger_port);
	ipc_port_make_send(trigger_port); 

	/*
	 * Set thread scheduling priority and policy for the current thread
	 * it is assumed for the time being that the thread setting the alert
	 * is the same one which will be servicing it. 
	 */
	{
		struct policy_timeshare_base	 fifo_base;
		struct policy_timeshare_limit fifo_limit;
		policy_base_t 	base;
		processor_set_t	pset;
		policy_limit_t	limit;

		pset = (current_thread())->processor_set;  
		base = (policy_base_t) &fifo_base;
		limit = (policy_limit_t) &fifo_limit;
		fifo_limit.max_priority = fifo_base.base_priority = MAXPRI_STANDARD;
		thread_set_policy((current_thread())->top_act, pset, POLICY_FIFO, base, POLICY_TIMESHARE_BASE_COUNT, limit, POLICY_TIMESHARE_LIMIT_COUNT);
	}
 
	current_thread()->vm_privilege = TRUE;
}

/*
 *
 */
ipc_port_t
trigger_name_to_port(
	mach_port_t	trigger_name)
{
	ipc_port_t	trigger_port;
	ipc_space_t	space;

	if (trigger_name == 0)
		return (NULL);

	space  = current_space();
	if(ipc_port_translate_receive(space, (mach_port_name_t)trigger_name, 
						&trigger_port) != KERN_SUCCESS)
		return (NULL);
	return trigger_port;
}

/*
 *
 */
void
vnode_pager_bootstrap(void)
{
	register vm_size_t      size;

	size = (vm_size_t) sizeof(struct vnode_pager);
	vnode_pager_zone = zinit(size, (vm_size_t) MAX_VNODE*size,
				PAGE_SIZE, "vnode pager structures");
	vnode_port_hash_init();

	return;
}

/*
 *
 */
ipc_port_t
vnode_pager_setup(
	vnode_port_t	vp,
	ipc_port_t	pager)
{
	vnode_pager_t	vnode_object;
	kern_return_t	kr;
	ipc_port_t	previous;

	if (pager &&
	    (vnode_object = vnode_port_hash_lookup(pager))) {
		if (vnode_object->vnode_handle == vp) 
			return(pager);
	}

	vnode_object = vnode_object_create(vp);
	if (vnode_object == VNODE_PAGER_NULL)
		panic("vnode_pager_setup: vnode_object_create() failed");

	vnode_object->pager = ipc_port_alloc_kernel();
	assert (vnode_object->pager != IP_NULL);
	pager_mux_hash_insert(vnode_object->pager, 
			(rpc_subsystem_t)&vnode_pager_workaround);

	vnode_object->pager_handle = ipc_port_make_send(vnode_object->pager);

	vnode_port_hash_insert(vnode_object->pager_handle, vnode_object);

	ipc_port_make_sonce(vnode_object->pager);
	ip_lock(vnode_object->pager);	/* unlocked in nsrequest below */
	ipc_port_nsrequest(vnode_object->pager, 1, vnode_object->pager, &previous);

	PAGER_DEBUG(PAGER_INIT, ("vnode_pager_setup: vp %x pager %x vnode_pager %x\n", vp, vnode_object->pager_handle, vnode_object));

	ubc_setpager( vp, vnode_object->pager_handle);
	return(vnode_object->pager_handle);
}

/*
 *
 */
ipc_port_t
vnode_pager_lookup(
	vnode_port_t    vp,
	ipc_port_t	pager)
{
	vnode_pager_t	vnode_object;
	kern_return_t	kr;

	if (pager &&
	    (vnode_object = vnode_port_hash_lookup(pager))) {
		if (vnode_object->vnode_handle == vp) 
			return(vnode_object->vm_obj_handle);
		else 
			return NULL;
	}
	else 
		return NULL;
}

/*
 *
 */
kern_return_t
vnode_pager_init(ipc_port_t pager, 
		ipc_port_t pager_request, 
		vm_size_t pg_size)
{
	vnode_pager_t   vnode_object;
	kern_return_t   kr;
	memory_object_attr_info_data_t  attributes;
	vm_object_t	vm_object;


	PAGER_DEBUG(PAGER_ALL, ("vnode_pager_init: %x, %x, %x\n", pager, pager_request, pg_size));

	vnode_object = vnode_port_hash_lookup(pager);
	if (vnode_object == VNODE_PAGER_NULL)
		panic("vnode_pager_init: lookup failed");

	vnode_object->vm_obj_handle = pager_request;

	vm_object = vm_object_lookup(pager_request);

	if (vm_object == VM_OBJECT_NULL)
		panic("vnode_pager_init: vm_object_lookup() failed");

	attributes.copy_strategy = MEMORY_OBJECT_COPY_DELAY;
	/* attributes.cluster_size = (1 << (CLUSTER_SHIFT + PAGE_SHIFT));*/
	attributes.cluster_size = (1 << (PAGE_SHIFT));
	attributes.may_cache_object = TRUE;
	attributes.temporary = TRUE;

	kr = memory_object_change_attributes(
					vm_object,
					MEMORY_OBJECT_ATTRIBUTE_INFO,
					(memory_object_info_t) &attributes,
					MEMORY_OBJECT_ATTR_INFO_COUNT,
					MACH_PORT_NULL, 0);
	if (kr != KERN_SUCCESS)
		panic("vnode_pager_init: memory_object_change_attributes() failed");

	return(KERN_SUCCESS);
}

/*
 *
 */
kern_return_t
vnode_pager_data_return(
        ipc_port_t		mem_obj,
        ipc_port_t		control_port,
        vm_object_offset_t	offset,
        pointer_t		addr,
        vm_size_t		data_cnt,
        boolean_t		dirty,
        boolean_t		kernel_copy)  
{
	register vnode_pager_t	vnode_object;

	vnode_object = vnode_port_hash_lookup(mem_obj);
	if (vnode_object == VNODE_PAGER_NULL)
		panic("vnode_pager_data_return: lookup failed");

	vnode_pager_cluster_write(vnode_object, offset, data_cnt);

	return KERN_SUCCESS;
}

/*
 *
 */
kern_return_t	
vnode_pager_data_request(
	ipc_port_t		mem_obj,
	ipc_port_t		mem_obj_control,
	vm_object_offset_t	offset,
	vm_size_t		length,
	vm_prot_t		protection_required)
{
	register vnode_pager_t	vnode_object;

	PAGER_DEBUG(PAGER_ALL, ("vnode_pager_data_request: %x, %x, %x, %x, %x\n", mem_obj, mem_obj_control, offset, length, protection_required));

	vnode_object = vnode_port_hash_lookup(mem_obj);

	PAGER_DEBUG(PAGER_PAGEIN, ("vnode_pager_data_request: %x, %x, %x, %x, %x, vnode_object %x\n", mem_obj, mem_obj_control, offset, length, protection_required, vnode_object));
		
	if (vnode_object == VNODE_PAGER_NULL)
		panic("vnode_pager_data_request: lookup failed");

	vnode_pager_cluster_read(vnode_object, offset, length);

	return KERN_SUCCESS;
}

/*
 *
 */
void
vnode_pager_no_senders(
	ipc_port_t	mem_obj,
	mach_port_mscount_t mscount)
{
	register vnode_pager_t	vnode_object;

	PAGER_DEBUG(PAGER_ALL, ("vnode_pager_nosenders: %x, %x\n", mem_obj, mscount));

	vnode_object = vnode_port_hash_lookup(mem_obj);
	if (vnode_object == VNODE_PAGER_NULL)
		panic("vnode_pager_no_senders: lookup failed");

	assert(vnode_object->pager_handle == mem_obj);

	pager_mux_hash_delete((ipc_port_t) vnode_object->pager_handle);
	ipc_port_dealloc_kernel(vnode_object->pager);
	vnode_port_hash_delete(vnode_object->pager_handle);
	if (vnode_object->vnode_handle != (vnode_port_t) NULL) {
		vnode_pager_vrele(vnode_object->vnode_handle);
	}
	zfree(vnode_pager_zone, (vm_offset_t) vnode_object);

	return;
}

/*
 *
 */
kern_return_t
vnode_pager_terminate(
	ipc_port_t	mem_obj,
	ipc_port_t	mem_obj_control)
{
	register vnode_pager_t	vnode_object;

	PAGER_DEBUG(PAGER_ALL, ("vnode_pager_terminate: %x, %x\n", mem_obj, mem_obj_control));

	vnode_object = vnode_port_hash_lookup(mem_obj);
	if (vnode_object == VNODE_PAGER_NULL)
		panic("vnode_pager_terminate: lookup failed");

	assert(vnode_object->pager_handle == mem_obj);

	/* release extra send right created by the fact that the caller */
	/* of vnode_pager_setup does not establish a mapping between a  */
	/* cache object and the mem_obj (AMO).  When a subsequent vm_map */
	/* is done, vm_map will bump the send right count */
	ipc_port_release_send(mem_obj);

	/* release a send right because terminate is called directly and */
	/* not through IPC, the right won't disappear quietly */
	ipc_port_release_send(mem_obj);

	ipc_port_dealloc_kernel(mem_obj_control);

	return(KERN_SUCCESS);
}

/*
 *
 */
kern_return_t
vnode_pager_synchronize(
	ipc_port_t		pager,
	ipc_port_t		pager_request,
	vm_object_offset_t	offset,
	vm_offset_t		length,
	vm_sync_t		sync_flags)
{
	memory_object_synchronize_completed(vm_object_lookup(pager_request), offset, length);

	return (KERN_SUCCESS);
}

/*
 *
 */
void
vnode_pager_cluster_write(
	vnode_pager_t		vnode_object,
	vm_object_offset_t	offset,
	vm_size_t		cnt)
{
	int		error = 0;
	int		local_error = 0;
	int		kret;
	int		size;

	if (cnt & PAGE_MASK) {
		panic("vs_cluster_write: cnt not a multiple of PAGE_SIZE");
	}
	size = (cnt < (PAGE_SIZE*32)) ? cnt : (PAGE_SIZE*32); /* effective min */
	
	while (cnt) {

		kret = vnode_pageout(vnode_object->vnode_handle, (upl_t )NULL, (vm_offset_t)NULL, offset, size, 0, &local_error);

		if (local_error != 0) {
			error = local_error;
			local_error = 0;
		}
		cnt -= size;
		offset += size;
	}
#if 0
	if (error != 0)
		return(KERN_FAILURE);
	
	return(KERN_SUCCESS);
#endif /* 0 */
}


/*
 *
 */
kern_return_t
vnode_pager_cluster_read(
	vnode_pager_t		vnode_object,
	vm_object_offset_t	offset,
	vm_size_t		cnt)
{
	int		error = 0;
	int		local_error = 0;
	int		kret;
	int		size;

	if(cnt & PAGE_MASK) {
		panic("vs_cluster_read: cnt not a multiple of PAGE_SIZE");
	}

	size = PAGE_SIZE;

	while (cnt) {

		kret = vnode_pagein(vnode_object->vnode_handle, (upl_t)NULL, (vm_offset_t)NULL, offset, size, 0, &local_error);

		if (local_error != 0) {
			error = local_error;
			local_error = 0;
		}
		cnt -= size;
		offset += size;
	}
	if (error != 0)
		return(KERN_FAILURE);

	return(KERN_SUCCESS);

}


/*
 *
 */
void
vnode_pager_release_from_cache(
		int	*cnt)
{
	memory_object_free_from_cache(
			&realhost, (int)&vnode_pager_workaround, cnt);
}

/*
 *
 */
vnode_pager_t
vnode_object_create(
        vnode_port_t   vp)
{
	register vnode_pager_t  vnode_object;

	vnode_object = (struct vnode_pager *) zalloc(vnode_pager_zone);
	if (vnode_object == VNODE_PAGER_NULL)
		return(VNODE_PAGER_NULL);
	vnode_object->pager_handle = IP_NULL;
	vnode_object->vm_obj_handle = IP_NULL;
	vnode_object->vnode_handle = vp;

	return(vnode_object);
}

/*
 *
 */
void
vnode_port_hash_init(void)
{
	register vm_size_t	size;
	register int		i;


	size = (vm_size_t) sizeof(struct vnode_port_entry);

	vnode_port_hash_zone = zinit(size,
				     (vm_size_t) MAX_VNODE * size,
				     PAGE_SIZE, "vnode_pager port hash");

	for (i = 0; i < VNODE_PORT_HASH_COUNT; i++) 
		queue_init(&vnode_port_hashtable[i]);

	simple_lock_init(&vnode_port_hash_lock,ETAP_NO_TRACE);
}

/*
 *
 */
void
vnode_port_hash_insert(
	ipc_port_t		name_port,
	vnode_pager_t	rec)
{
	register vnode_port_entry_t	new_entry;

	new_entry = (vnode_port_entry_t) zalloc(vnode_port_hash_zone);
	/*
	 * TODO: Delete the following check once MAX_VNODE is removed 
	 */
	if (!new_entry)
		panic("vnode_port_hash_insert: no space");
	new_entry->name = name_port;
	new_entry->pager_rec = rec;

	simple_lock(&vnode_port_hash_lock);
	queue_enter(&vnode_port_hashtable[vnode_port_hash(name_port)],
			new_entry, vnode_port_entry_t, links);
	simple_unlock(&vnode_port_hash_lock);
}

/*
 *
 */
vnode_pager_t
vnode_port_hash_lookup(
	ipc_port_t	 name_port)
{
	register queue_t 		bucket;
	register vnode_port_entry_t	entry;
	vnode_pager_t			rec;

	bucket = (queue_t) &vnode_port_hashtable[vnode_port_hash(name_port)];

	simple_lock(&vnode_port_hash_lock);
	entry = (vnode_port_entry_t) queue_first(bucket);
	while (!queue_end(bucket,&entry->links)) {
		if (entry->name == name_port) {
			rec = entry->pager_rec;
			simple_unlock(&vnode_port_hash_lock);
			return(rec);
		}
		entry = (vnode_port_entry_t)queue_next(&entry->links);
	}
	simple_unlock(&vnode_port_hash_lock);
	return(VNODE_PAGER_NULL);
}

/*
 *
 */
void
vnode_port_hash_delete(
	ipc_port_t name_port)
{
	register queue_t bucket;
	register vnode_port_entry_t entry;

	bucket = (queue_t) &vnode_port_hashtable[vnode_port_hash(name_port)];

	simple_lock(&vnode_port_hash_lock);
	entry = (vnode_port_entry_t) queue_first(bucket);
	while (!queue_end(bucket,&entry->links)) {
		if (entry->name == name_port) {
			queue_remove(bucket, entry, vnode_port_entry_t,links);
			simple_unlock(&vnode_port_hash_lock);
			zfree(vnode_port_hash_zone, (vm_offset_t) entry);
			return;
		}
		entry = (vnode_port_entry_t)queue_next(&entry->links);
	}
	simple_unlock(&vnode_port_hash_lock);
}
