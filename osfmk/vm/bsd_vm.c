/*
 * Copyright (c) 2000-2001 Apple Computer, Inc. All rights reserved.
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
#include <vm/memory_object.h>
#include <vm/vm_pageout.h>

#include <default_pager/default_pager_types.h>

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
	int 			*pager;		/* pager workaround pointer  */
	unsigned int		pager_ikot;	/* JMM: fake ip_kotype()     */
	unsigned int		ref_count;	/* reference count	     */
	memory_object_control_t control_handle;	/* mem object control handle */
	vnode_port_t 		vnode_handle;	/* vnode handle 	     */
} *vnode_pager_t;


ipc_port_t
trigger_name_to_port(
	mach_port_t);

void 
vnode_pager_bootstrap(
	void);

void
vnode_pager_alloc_map(
	void);

memory_object_t
vnode_pager_setup(
	vnode_port_t,
	memory_object_t);


kern_return_t
vnode_pager_init(
	memory_object_t, 
	memory_object_control_t, 
	vm_size_t);

kern_return_t
vnode_pager_get_object_size(
	memory_object_t,
	memory_object_offset_t *);

kern_return_t
vnode_pager_data_request( 
	memory_object_t, 
	memory_object_offset_t, 
	vm_size_t, 
	vm_prot_t);

kern_return_t
vnode_pager_data_return(
	memory_object_t,
	memory_object_offset_t,
	vm_size_t,
	boolean_t,
	boolean_t);

kern_return_t
vnode_pager_data_initialize(
	memory_object_t,
	memory_object_offset_t,
	vm_size_t);

void
vnode_pager_deallocate(
	memory_object_t);

kern_return_t
vnode_pager_terminate(
	memory_object_t);

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

vm_object_offset_t
vnode_pager_get_filesize(
	vnode_port_t);

vnode_pager_t
vnode_object_create(
	vnode_port_t	vp);

vnode_pager_t
vnode_pager_lookup(
	memory_object_t);

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
	memory_object_default_t	default_pager;
	ipc_port_t		trigger_port;

	default_pager = MEMORY_OBJECT_DEFAULT_NULL;
	kr = host_default_memory_manager(host_priv_self(), 
					&default_pager, 0);
	if(kr != KERN_SUCCESS) {
		return EINVAL;
	}
	if (flags & HI_WAT_ALERT) {
		trigger_port = trigger_name_to_port(trigger_name);
		if(trigger_port == NULL) {
			return EINVAL;
		}
		/* trigger_port is locked and active */
		ipc_port_make_send_locked(trigger_port); 
		/* now unlocked */
		default_pager_triggers(default_pager, 
				       hi_water, low_water,
				       HI_WAT_ALERT, trigger_port);
	}

	if (flags & LO_WAT_ALERT) {
		trigger_port = trigger_name_to_port(trigger_name);
		if(trigger_port == NULL) {
			return EINVAL;
		}
		/* trigger_port is locked and active */
		ipc_port_make_send_locked(trigger_port);
		/* and now its unlocked */
		default_pager_triggers(default_pager, 
				       hi_water, low_water,
				       LO_WAT_ALERT, trigger_port);
	}

	/*
	 * Set thread scheduling priority and policy for the current thread
	 * it is assumed for the time being that the thread setting the alert
	 * is the same one which will be servicing it.
	 *
	 * XXX This does not belong in the kernel XXX
	 */
	{
		thread_precedence_policy_data_t		pre;
		thread_extended_policy_data_t		ext;

		ext.timeshare = FALSE;
		pre.importance = INT32_MAX;

		thread_policy_set(current_act(),
							THREAD_EXTENDED_POLICY, (thread_policy_t)&ext,
									THREAD_EXTENDED_POLICY_COUNT);

		thread_policy_set(current_act(),
							THREAD_PRECEDENCE_POLICY, (thread_policy_t)&pre,
									THREAD_PRECEDENCE_POLICY_COUNT);
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
	return;
}

/*
 *
 */
memory_object_t
vnode_pager_setup(
	vnode_port_t	vp,
	memory_object_t	pager)
{
	vnode_pager_t	vnode_object;

	vnode_object = vnode_object_create(vp);
	if (vnode_object == VNODE_PAGER_NULL)
		panic("vnode_pager_setup: vnode_object_create() failed");
	return((memory_object_t)vnode_object);
}

/*
 *
 */
kern_return_t
vnode_pager_init(memory_object_t mem_obj, 
		memory_object_control_t control, 
		vm_size_t pg_size)
{
	vnode_pager_t   vnode_object;
	kern_return_t   kr;
	memory_object_attr_info_data_t  attributes;


	PAGER_DEBUG(PAGER_ALL, ("vnode_pager_init: %x, %x, %x\n", pager, pager_request, pg_size));

	if (control == MEMORY_OBJECT_CONTROL_NULL)
		return KERN_INVALID_ARGUMENT;

	vnode_object = vnode_pager_lookup(mem_obj);

	memory_object_control_reference(control);
	vnode_object->control_handle = control;

	attributes.copy_strategy = MEMORY_OBJECT_COPY_DELAY;
	/* attributes.cluster_size = (1 << (CLUSTER_SHIFT + PAGE_SHIFT));*/
	attributes.cluster_size = (1 << (PAGE_SHIFT));
	attributes.may_cache_object = TRUE;
	attributes.temporary = TRUE;

	kr = memory_object_change_attributes(
					control,
					MEMORY_OBJECT_ATTRIBUTE_INFO,
					(memory_object_info_t) &attributes,
					MEMORY_OBJECT_ATTR_INFO_COUNT);
	if (kr != KERN_SUCCESS)
		panic("vnode_pager_init: memory_object_change_attributes() failed");

	return(KERN_SUCCESS);
}

/*
 *
 */
kern_return_t
vnode_pager_data_return(
        memory_object_t		mem_obj,
        memory_object_offset_t	offset,
        vm_size_t		data_cnt,
        boolean_t		dirty,
        boolean_t		kernel_copy)  
{
	register vnode_pager_t	vnode_object;

	vnode_object = vnode_pager_lookup(mem_obj);

	vnode_pager_cluster_write(vnode_object, offset, data_cnt);

	return KERN_SUCCESS;
}

kern_return_t
vnode_pager_data_initialize(
        memory_object_t		mem_obj,
        memory_object_offset_t	offset,
        vm_size_t		data_cnt)
{
	return KERN_FAILURE;
}

kern_return_t
vnode_pager_data_unlock(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	vm_size_t		size,
	vm_prot_t		desired_access)
{
	return KERN_FAILURE;
}

kern_return_t
vnode_pager_get_object_size(
	memory_object_t		mem_obj,
	memory_object_offset_t	*length)
{
	vnode_pager_t	vnode_object;

	vnode_object = vnode_pager_lookup(mem_obj);

	*length = vnode_pager_get_filesize(vnode_object->vnode_handle);
	return KERN_SUCCESS;
}

/*
 *
 */
kern_return_t	
vnode_pager_data_request(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	vm_size_t		length,
	vm_prot_t		protection_required)
{
	register vnode_pager_t	vnode_object;

	PAGER_DEBUG(PAGER_ALL, ("vnode_pager_data_request: %x, %x, %x, %x\n", mem_obj, offset, length, protection_required));

	vnode_object = vnode_pager_lookup(mem_obj);

	PAGER_DEBUG(PAGER_PAGEIN, ("vnode_pager_data_request: %x, %x, %x, %x, vnode_object %x\n", mem_obj, offset, length, protection_required, vnode_object));
		
	vnode_pager_cluster_read(vnode_object, offset, length);

	return KERN_SUCCESS;
}

/*
 *
 */
void
vnode_pager_reference(
	memory_object_t		mem_obj)
{	
	register vnode_pager_t	vnode_object;
	unsigned int		new_ref_count;

	vnode_object = vnode_pager_lookup(mem_obj);
	new_ref_count = hw_atomic_add(&vnode_object->ref_count, 1);
	assert(new_ref_count > 1);
}

/*
 *
 */
void
vnode_pager_deallocate(
	memory_object_t		mem_obj)
{
	register vnode_pager_t	vnode_object;

	PAGER_DEBUG(PAGER_ALL, ("vnode_pager_deallocate: %x\n", mem_obj));

	vnode_object = vnode_pager_lookup(mem_obj);

	if (hw_atomic_sub(&vnode_object->ref_count, 1) == 0) {
		if (vnode_object->vnode_handle != (vnode_port_t) NULL) {
			vnode_pager_vrele(vnode_object->vnode_handle);
		}
		zfree(vnode_pager_zone, (vm_offset_t) vnode_object);
	}
	return;
}

/*
 *
 */
kern_return_t
vnode_pager_terminate(
	memory_object_t	mem_obj)
{
	PAGER_DEBUG(PAGER_ALL, ("vnode_pager_terminate: %x\n", mem_obj));

	return(KERN_SUCCESS);
}

/*
 *
 */
kern_return_t
vnode_pager_synchronize(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	vm_size_t		length,
	vm_sync_t		sync_flags)
{
	register vnode_pager_t	vnode_object;

	PAGER_DEBUG(PAGER_ALL, ("vnode_pager_synchronize: %x\n", mem_obj));

	vnode_object = vnode_pager_lookup(mem_obj);

	memory_object_synchronize_completed(vnode_object->control_handle, offset, length);

	return (KERN_SUCCESS);
}

/*
 *
 */
kern_return_t
vnode_pager_unmap(
	memory_object_t		mem_obj)
{
	register vnode_pager_t	vnode_object;

	PAGER_DEBUG(PAGER_ALL, ("vnode_pager_unmap: %x\n", mem_obj));

	vnode_object = vnode_pager_lookup(mem_obj);

	ubc_unmap(vnode_object->vnode_handle);
	return KERN_SUCCESS;
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

		kret = vnode_pageout(vnode_object->vnode_handle, 
			(upl_t )NULL, (vm_offset_t)NULL, 
			offset, size, 0, &local_error);
/*
		if(kret == PAGER_ABSENT) {
			Need to work out the defs here, 1 corresponds to 
			PAGER_ABSENT defined in bsd/vm/vm_pager.h  However, 
			we should not be including that file here it is a 
			layering violation.
*/
		if(kret == 1) {
			int	uplflags;
			upl_t	upl = NULL;
			int	count = 0;
			kern_return_t	kr;

        		uplflags = (UPL_NO_SYNC | UPL_CLEAN_IN_PLACE |
					UPL_SET_INTERNAL | UPL_COPYOUT_FROM);
		        count = 0;
        		kr = memory_object_upl_request(
					vnode_object->control_handle, 
					offset, size, &upl, NULL, &count, uplflags);
			if(kr != KERN_SUCCESS) {
				panic("vnode_pager_cluster_write: upl request failed\n");
			}
			upl_abort(upl, 0);
			upl_deallocate(upl);

			error = 0;
			local_error = 0;
		}

		if (local_error != 0) {
			error = local_error;
			local_error = 0;
		}
		cnt -= size;
		offset += size;
		size = (cnt < (PAGE_SIZE*32)) ? cnt : (PAGE_SIZE*32); /* effective min */
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

	if(cnt & PAGE_MASK) {
		panic("vs_cluster_read: cnt not a multiple of PAGE_SIZE");
	}

	kret = vnode_pagein(vnode_object->vnode_handle, (upl_t)NULL, (vm_offset_t)NULL, offset, cnt, 0, &local_error);
/*
	if(kret == PAGER_ABSENT) {
	Need to work out the defs here, 1 corresponds to PAGER_ABSENT 
	defined in bsd/vm/vm_pager.h  However, we should not be including 
	that file here it is a layering violation.
*/
	if(kret == 1) {
			int	uplflags;
			upl_t	upl = NULL;
			int	count = 0;
			kern_return_t	kr;

        		uplflags = (UPL_NO_SYNC | 
				UPL_CLEAN_IN_PLACE | UPL_SET_INTERNAL);
		        count = 0;
        		kr = memory_object_upl_request(
				vnode_object->control_handle, offset, cnt,
				&upl, NULL, &count, uplflags);
			if(kr != KERN_SUCCESS) {
				panic("vnode_pager_cluster_read: upl request failed\n");
			}
			upl_abort(upl, 0);
			upl_deallocate(upl);

		error = 1;
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
			&realhost, &vnode_pager_workaround, cnt);
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

	/*
	 * The vm_map call takes both named entry ports and raw memory
	 * objects in the same parameter.  We need to make sure that
	 * vm_map does not see this object as a named entry port.  So,
	 * we reserve the second word in the object for a fake ip_kotype
	 * setting - that will tell vm_map to use it as a memory object.
	 */
	vnode_object->pager = &vnode_pager_workaround;
	vnode_object->pager_ikot = IKOT_MEMORY_OBJECT;
	vnode_object->ref_count = 1;
	vnode_object->control_handle = MEMORY_OBJECT_CONTROL_NULL;
	vnode_object->vnode_handle = vp;

	return(vnode_object);
}

/*
 *
 */
vnode_pager_t
vnode_pager_lookup(
	memory_object_t	 name)
{
	vnode_pager_t	vnode_object;

	vnode_object = (vnode_pager_t)name;
	assert(vnode_object->pager == &vnode_pager_workaround);
	return (vnode_object);
}

