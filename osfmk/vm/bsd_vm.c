/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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

#include <sys/errno.h>

#include <mach/mach_types.h>
#include <mach/mach_traps.h>
#include <mach/host_priv.h>
#include <mach/kern_return.h>
#include <mach/memory_object_control.h>
#include <mach/memory_object_types.h>
#include <mach/port.h>
#include <mach/policy.h>
#include <mach/upl.h>
#include <mach/thread_act.h>

#include <kern/host.h>
#include <kern/thread.h>

#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>

#include <default_pager/default_pager_types.h>
#include <default_pager/default_pager_object_server.h>

#include <vm/vm_map.h>
#include <vm/vm_pageout.h>
#include <vm/memory_object.h>
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>

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

mach_vm_offset_t
mach_get_vm_start(vm_map_t map)
{
	return( vm_map_first_entry(map)->vme_start);
}

mach_vm_offset_t
mach_get_vm_end(vm_map_t map)
{
	return( vm_map_last_entry(map)->vme_end);
}

/*
 * Legacy routines to get the start and end for a vm_map_t.  They
 * return them in the vm_offset_t format.  So, they should only be
 * called on maps that are the same size as the kernel map for
 * accurate results.
 */
vm_offset_t
get_vm_start(
	vm_map_t map)
{
	return(CAST_DOWN(vm_offset_t, vm_map_first_entry(map)->vme_start));
}

vm_offset_t
get_vm_end(
	vm_map_t map)
{
	return(CAST_DOWN(vm_offset_t, vm_map_last_entry(map)->vme_end));
}

/* 
 * BSD VNODE PAGER 
 */

const struct memory_object_pager_ops vnode_pager_ops = {
	vnode_pager_reference,
	vnode_pager_deallocate,
	vnode_pager_init,
	vnode_pager_terminate,
	vnode_pager_data_request,
	vnode_pager_data_return,
	vnode_pager_data_initialize,
	vnode_pager_data_unlock,
	vnode_pager_synchronize,
	vnode_pager_unmap,
	"vnode pager"
};

typedef struct vnode_pager {
	memory_object_pager_ops_t pager_ops;	/* == &vnode_pager_ops	     */
	unsigned int		pager_ikot;	/* JMM: fake ip_kotype()     */
	unsigned int		ref_count;	/* reference count	     */
	memory_object_control_t control_handle;	/* mem object control handle */
	struct vnode		*vnode_handle;	/* vnode handle 	     */
} *vnode_pager_t;


ipc_port_t
trigger_name_to_port(			/* forward */
	mach_port_t);

kern_return_t
vnode_pager_cluster_read(		/* forward */
	vnode_pager_t, 
	vm_object_offset_t, 
	vm_size_t);

void
vnode_pager_cluster_write(		/* forward */
	vnode_pager_t,
	vm_object_offset_t,
	vm_size_t,
	vm_object_offset_t *,
	int *,
	int);


vnode_pager_t
vnode_object_create(			/* forward */
	struct vnode *);

vnode_pager_t
vnode_pager_lookup(			/* forward */
	memory_object_t);

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
	struct macx_triggers_args *args)
{
	int	hi_water = args->hi_water;
	int	low_water = args->low_water;
	int	flags = args->flags;
	mach_port_t	trigger_name = args->alert_port;
	kern_return_t kr;
	memory_object_default_t	default_pager;
	ipc_port_t		trigger_port;

	default_pager = MEMORY_OBJECT_DEFAULT_NULL;
	kr = host_default_memory_manager(host_priv_self(), 
					&default_pager, 0);
	if(kr != KERN_SUCCESS) {
		return EINVAL;
	}

	if ((flags & SWAP_ENCRYPT_ON) &&
	    (flags & SWAP_ENCRYPT_OFF)) {
		/* can't have it both ways */
		return EINVAL;
	}

       if (default_pager_init_flag == 0) {
               start_def_pager(NULL);
               default_pager_init_flag = 1;
       }

	if (flags & SWAP_ENCRYPT_ON) {
		/* ENCRYPTED SWAP: tell default_pager to encrypt */
		default_pager_triggers(default_pager,
				       0, 0,
				       SWAP_ENCRYPT_ON,
				       IP_NULL);
	} else if (flags & SWAP_ENCRYPT_OFF) {
		/* ENCRYPTED SWAP: tell default_pager not to encrypt */
		default_pager_triggers(default_pager,
				       0, 0,
				       SWAP_ENCRYPT_OFF,
				       IP_NULL);
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

		thread_policy_set(current_thread(),
				  THREAD_EXTENDED_POLICY,
				  (thread_policy_t)&ext,
				  THREAD_EXTENDED_POLICY_COUNT);

		thread_policy_set(current_thread(),
				  THREAD_PRECEDENCE_POLICY,
				  (thread_policy_t)&pre,
				  THREAD_PRECEDENCE_POLICY_COUNT);
	}
 
	current_thread()->options |= TH_OPT_VMPRIV;

	return 0;
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


extern int	uiomove64(addr64_t, int, void *);
#define	MAX_RUN	32

int
memory_object_control_uiomove(
	memory_object_control_t	control,
	memory_object_offset_t	offset,
	void		*	uio,
	int			start_offset,
	int			io_requested,
	int			mark_dirty)
{
	vm_object_t		object;
	vm_page_t		dst_page;
	int			xsize;
	int			retval = 0;
	int			cur_run;
	int			cur_needed;
	int			i;
	vm_page_t		page_run[MAX_RUN];


	object = memory_object_control_to_vm_object(control);
	if (object == VM_OBJECT_NULL) {
		return (0);
	}
	assert(!object->internal);

	vm_object_lock(object);

	if (mark_dirty && object->copy != VM_OBJECT_NULL) {
		/*
		 * We can't modify the pages without honoring
		 * copy-on-write obligations first, so fall off
		 * this optimized path and fall back to the regular
		 * path.
		 */
		vm_object_unlock(object);
		return 0;
	}
	    
	while (io_requested && retval == 0) {

		cur_needed = (start_offset + io_requested + (PAGE_SIZE - 1)) / PAGE_SIZE;

		if (cur_needed > MAX_RUN)
		        cur_needed = MAX_RUN;

		for (cur_run = 0; cur_run < cur_needed; ) {

		        if ((dst_page = vm_page_lookup(object, offset)) == VM_PAGE_NULL)
			        break;
			/*
			 * Sync up on getting the busy bit
			 */
			if ((dst_page->busy || dst_page->cleaning)) {
			        /*
				 * someone else is playing with the page... if we've
				 * already collected pages into this run, go ahead
				 * and process now, we can't block on this
				 * page while holding other pages in the BUSY state
				 * otherwise we will wait
				 */
			        if (cur_run)
				        break;
			        PAGE_SLEEP(object, dst_page, THREAD_UNINT);
				continue;
			}
			/*
			 * this routine is only called when copying
			 * to/from real files... no need to consider
			 * encrypted swap pages
			 */
			assert(!dst_page->encrypted);

		        if (mark_dirty)
			        dst_page->dirty = TRUE;
			dst_page->busy = TRUE;

			page_run[cur_run++] = dst_page;

			offset += PAGE_SIZE_64;
		}
		if (cur_run == 0)
		        /*
			 * we hit a 'hole' in the cache
			 * we bail at this point
			 * we'll unlock the object below
			 */
		        break;
		vm_object_unlock(object);

		for (i = 0; i < cur_run; i++) {
		  
		        dst_page = page_run[i];

			if ((xsize = PAGE_SIZE - start_offset) > io_requested)
			        xsize = io_requested;

			if ( (retval = uiomove64((addr64_t)(((addr64_t)(dst_page->phys_page) << 12) + start_offset), xsize, uio)) )
			        break;

			io_requested -= xsize;
			start_offset = 0;
		}
		vm_object_lock(object);

		for (i = 0; i < cur_run; i++) {
		        dst_page = page_run[i];

			PAGE_WAKEUP_DONE(dst_page);
		}
	}
	vm_object_unlock(object);

	return (retval);
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
#ifdef __i386__
	apple_protect_pager_bootstrap();
#endif	/* __i386__ */
	return;
}

/*
 *
 */
memory_object_t
vnode_pager_setup(
	struct vnode	*vp,
	__unused memory_object_t	pager)
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
#if !DEBUG
		 __unused
#endif
		 vm_size_t pg_size)
{
	vnode_pager_t   vnode_object;
	kern_return_t   kr;
	memory_object_attr_info_data_t  attributes;


	PAGER_DEBUG(PAGER_ALL, ("vnode_pager_init: %p, %p, %x\n", mem_obj, control, pg_size));

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
        memory_object_offset_t	*resid_offset,
	int			*io_error,
	__unused boolean_t		dirty,
	__unused boolean_t		kernel_copy,
	int			upl_flags)  
{
	register vnode_pager_t	vnode_object;

	vnode_object = vnode_pager_lookup(mem_obj);

	vnode_pager_cluster_write(vnode_object, offset, data_cnt, resid_offset, io_error, upl_flags);

	return KERN_SUCCESS;
}

kern_return_t
vnode_pager_data_initialize(
	__unused memory_object_t		mem_obj,
	__unused memory_object_offset_t	offset,
	__unused vm_size_t		data_cnt)
{
	panic("vnode_pager_data_initialize");
	return KERN_FAILURE;
}

kern_return_t
vnode_pager_data_unlock(
	__unused memory_object_t		mem_obj,
	__unused memory_object_offset_t	offset,
	__unused vm_size_t		size,
	__unused vm_prot_t		desired_access)
{
	return KERN_FAILURE;
}

kern_return_t
vnode_pager_get_object_size(
	memory_object_t		mem_obj,
	memory_object_offset_t	*length)
{
	vnode_pager_t	vnode_object;

	if (mem_obj->mo_pager_ops != &vnode_pager_ops) {
		*length = 0;
		return KERN_INVALID_ARGUMENT;
	}

	vnode_object = vnode_pager_lookup(mem_obj);

	*length = vnode_pager_get_filesize(vnode_object->vnode_handle);
	return KERN_SUCCESS;
}

kern_return_t
vnode_pager_get_object_pathname(
	memory_object_t		mem_obj,
	char			*pathname,
	vm_size_t		*length_p)
{
	vnode_pager_t	vnode_object;

	if (mem_obj->mo_pager_ops != &vnode_pager_ops) {
		return KERN_INVALID_ARGUMENT;
	}

	vnode_object = vnode_pager_lookup(mem_obj);

	return vnode_pager_get_pathname(vnode_object->vnode_handle,
					pathname,
					length_p);
}

kern_return_t
vnode_pager_get_object_filename(
	memory_object_t	mem_obj,
	char		**filename)
{
	vnode_pager_t	vnode_object;

	if (mem_obj->mo_pager_ops != &vnode_pager_ops) {
		return KERN_INVALID_ARGUMENT;
	}

	vnode_object = vnode_pager_lookup(mem_obj);

	return vnode_pager_get_filename(vnode_object->vnode_handle,
					filename);
}

/*
 *
 */
kern_return_t	
vnode_pager_data_request(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	vm_size_t		length,
#if !DEBUG
	__unused
#endif
vm_prot_t		protection_required)
{
	register vnode_pager_t	vnode_object;

	PAGER_DEBUG(PAGER_ALL, ("vnode_pager_data_request: %x, %x, %x, %x\n", mem_obj, offset, length, protection_required));

	vnode_object = vnode_pager_lookup(mem_obj);

	PAGER_DEBUG(PAGER_PAGEIN, ("vnode_pager_data_request: %x, %x, %x, %x, vnode_object %x\n", mem_obj, offset, length, protection_required, vnode_object));
		
	return vnode_pager_cluster_read(vnode_object, offset, length);
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
		if (vnode_object->vnode_handle != NULL) {
			vnode_pager_vrele(vnode_object->vnode_handle);
		}
		zfree(vnode_pager_zone, vnode_object);
	}
	return;
}

/*
 *
 */
kern_return_t
vnode_pager_terminate(
#if !DEBUG
	__unused
#endif
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
	__unused vm_sync_t		sync_flags)
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
	vm_size_t		cnt,
	vm_object_offset_t   *	resid_offset,
	int		     *  io_error,
	int			upl_flags)
{
        vm_size_t       size;
	upl_t	        upl = NULL;
	int             request_flags;
	int		errno;

	if (upl_flags & UPL_MSYNC) {

	        upl_flags |= UPL_VNODE_PAGER;

		if ( (upl_flags & UPL_IOSYNC) && io_error)
		        upl_flags |= UPL_KEEPCACHED;

	        while (cnt) {
		        kern_return_t   kr;

			size = (cnt < (PAGE_SIZE * MAX_UPL_TRANSFER)) ? cnt : (PAGE_SIZE * MAX_UPL_TRANSFER); /* effective max */

			request_flags = UPL_RET_ONLY_DIRTY | UPL_COPYOUT_FROM | UPL_CLEAN_IN_PLACE |
			                UPL_SET_INTERNAL | UPL_SET_LITE;

			kr = memory_object_upl_request(vnode_object->control_handle, 
						       offset, size, &upl, NULL, NULL, request_flags);
			if (kr != KERN_SUCCESS)
			        panic("vnode_pager_cluster_write: upl request failed\n");

			vnode_pageout(vnode_object->vnode_handle, 
				      upl, (vm_offset_t)0, offset, size, upl_flags, &errno);

			if ( (upl_flags & UPL_KEEPCACHED) ) {
			        if ( (*io_error = errno) )
				        break;
			}
			cnt    -= size;
			offset += size;
		}
		if (resid_offset)
			*resid_offset = offset;

	} else {
	        vm_object_offset_t      vnode_size;
	        vm_object_offset_t	base_offset;
		vm_object_t             object;
		vm_page_t               target_page;
		int                     ticket;

	        /*
		 * this is the pageout path
		 */
		vnode_size = vnode_pager_get_filesize(vnode_object->vnode_handle);

		if (vnode_size > (offset + PAGE_SIZE)) {
		        /*
			 * preset the maximum size of the cluster
			 * and put us on a nice cluster boundary...
			 * and then clip the size to insure we
			 * don't request past the end of the underlying file
			 */
		        size = PAGE_SIZE * MAX_UPL_TRANSFER;
		        base_offset = offset & ~((signed)(size - 1));

			if ((base_offset + size) > vnode_size)
			        size = round_page_32(((vm_size_t)(vnode_size - base_offset)));
		} else {
		        /*
			 * we've been requested to page out a page beyond the current
			 * end of the 'file'... don't try to cluster in this case...
			 * we still need to send this page through because it might
			 * be marked precious and the underlying filesystem may need
			 * to do something with it (besides page it out)...
			 */
		        base_offset = offset;
			size = PAGE_SIZE;
		}
		object = memory_object_control_to_vm_object(vnode_object->control_handle);

		if (object == VM_OBJECT_NULL)
		        panic("vnode_pager_cluster_write: NULL vm_object in control handle\n");

		request_flags = UPL_NOBLOCK | UPL_FOR_PAGEOUT | UPL_CLEAN_IN_PLACE |
		                UPL_RET_ONLY_DIRTY | UPL_COPYOUT_FROM |
		                UPL_SET_INTERNAL | UPL_SET_LITE;

		vm_object_lock(object);

		if ((target_page = vm_page_lookup(object, offset)) != VM_PAGE_NULL) {
		        /*
			 * only pick up pages whose ticket number matches
			 * the ticket number of the page orginally targeted
			 * for pageout
			 */
			ticket = target_page->page_ticket;

			request_flags |= ((ticket << UPL_PAGE_TICKET_SHIFT) & UPL_PAGE_TICKET_MASK);
		}
		vm_object_unlock(object);

		vm_object_upl_request(object, base_offset, size,
				      &upl, NULL, NULL, request_flags);
		if (upl == NULL)
		        panic("vnode_pager_cluster_write: upl request failed\n");

	        vnode_pageout(vnode_object->vnode_handle,
			       upl, (vm_offset_t)0, upl->offset, upl->size, UPL_VNODE_PAGER, NULL);
	}
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
	int		local_error = 0;
	int		kret;

	assert(! (cnt & PAGE_MASK));

	kret = vnode_pagein(vnode_object->vnode_handle,
			    (upl_t) NULL,
			    (vm_offset_t) NULL,
			    offset,
			    cnt,
			    0,
			    &local_error);
/*
	if(kret == PAGER_ABSENT) {
	Need to work out the defs here, 1 corresponds to PAGER_ABSENT 
	defined in bsd/vm/vm_pager.h  However, we should not be including 
	that file here it is a layering violation.
*/
	if (kret == 1) {
		int	uplflags;
		upl_t	upl = NULL;
		unsigned int	count = 0;
		kern_return_t	kr;

		uplflags = (UPL_NO_SYNC |
			    UPL_CLEAN_IN_PLACE |
			    UPL_SET_INTERNAL);
		count = 0;
		kr = memory_object_upl_request(vnode_object->control_handle,
					       offset, cnt,
					       &upl, NULL, &count, uplflags);
		if (kr == KERN_SUCCESS) {
			upl_abort(upl, 0);
			upl_deallocate(upl);
		} else {
			/*
			 * We couldn't gather the page list, probably
			 * because the memory object doesn't have a link
			 * to a VM object anymore (forced unmount, for
			 * example).  Just return an error to the vm_fault()
			 * path and let it handle it.
			 */
		}

		return KERN_FAILURE;
	}

	return KERN_SUCCESS;

}


/*
 *
 */
void
vnode_pager_release_from_cache(
		int	*cnt)
{
	memory_object_free_from_cache(
			&realhost, &vnode_pager_ops, cnt);
}

/*
 *
 */
vnode_pager_t
vnode_object_create(
        struct vnode *vp)
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
	vnode_object->pager_ops = &vnode_pager_ops;
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
	assert(vnode_object->pager_ops == &vnode_pager_ops);
	return (vnode_object);
}


/*********************** proc_info implementation *************/

#include <sys/bsdtask_info.h>

static int fill_vnodeinfoforaddr( vm_map_entry_t entry, uint32_t * vnodeaddr, uint32_t * vid);


int
fill_procregioninfo(task_t task, uint64_t arg, struct proc_regioninfo_internal *pinfo, uint32_t  *vnodeaddr, uint32_t  *vid)
{

	vm_map_t map = task->map;
	vm_map_offset_t	address = (vm_map_offset_t )arg;
	vm_map_entry_t		tmp_entry;
	vm_map_entry_t		entry;
	vm_map_offset_t		start;
	vm_region_extended_info_data_t extended;
	vm_region_top_info_data_t top;


	if (map == VM_MAP_NULL) 
		return(0);

	    vm_map_lock_read(map);

	    start = address;
	    if (!vm_map_lookup_entry(map, start, &tmp_entry)) {
		if ((entry = tmp_entry->vme_next) == vm_map_to_entry(map)) {
			vm_map_unlock_read(map);
		   	return(0);
		}
	    } else {
		entry = tmp_entry;
	    }

	    start = entry->vme_start;

	    pinfo->pri_offset = entry->offset;
	    pinfo->pri_protection = entry->protection;
	    pinfo->pri_max_protection = entry->max_protection;
	    pinfo->pri_inheritance = entry->inheritance;
	    pinfo->pri_behavior = entry->behavior;
	    pinfo->pri_user_wired_count = entry->user_wired_count;
	    pinfo->pri_user_tag = entry->alias;

	    if (entry->is_sub_map) {
		pinfo->pri_flags |= PROC_REGION_SUBMAP;
	    } else {
		if (entry->is_shared)
			pinfo->pri_flags |= PROC_REGION_SHARED;
	    }


	    extended.protection = entry->protection;
	    extended.user_tag = entry->alias;
	    extended.pages_resident = 0;
	    extended.pages_swapped_out = 0;
	    extended.pages_shared_now_private = 0;
	    extended.pages_dirtied = 0;
	    extended.external_pager = 0;
	    extended.shadow_depth = 0;

	    vm_map_region_walk(map, start, entry, entry->offset, entry->vme_end - start, &extended);

	    if (extended.external_pager && extended.ref_count == 2 && extended.share_mode == SM_SHARED)
	            extended.share_mode = SM_PRIVATE;

	    top.private_pages_resident = 0;
	    top.shared_pages_resident = 0;
	    vm_map_region_top_walk(entry, &top);

	
	    pinfo->pri_pages_resident = extended.pages_resident;
	    pinfo->pri_pages_shared_now_private = extended.pages_shared_now_private;
	    pinfo->pri_pages_swapped_out = extended.pages_swapped_out;
	    pinfo->pri_pages_dirtied = extended.pages_dirtied;
	    pinfo->pri_ref_count = extended.ref_count;
	    pinfo->pri_shadow_depth = extended.shadow_depth;
	    pinfo->pri_share_mode = extended.share_mode;

	    pinfo->pri_private_pages_resident = top.private_pages_resident;
	    pinfo->pri_shared_pages_resident = top.shared_pages_resident;
	    pinfo->pri_obj_id = top.obj_id;
		
	    pinfo->pri_address = (uint64_t)start;
	    pinfo->pri_size = (uint64_t)(entry->vme_end - start);
	    pinfo->pri_depth = 0;
	
	    if ((vnodeaddr != 0) && (entry->is_sub_map == 0)) {
		*vnodeaddr = (uint32_t)0;

		if (fill_vnodeinfoforaddr(entry, vnodeaddr, vid) ==0) {
			vm_map_unlock_read(map);
			return(1);
		}
	    }

	    vm_map_unlock_read(map);
	    return(1);
}

static int
fill_vnodeinfoforaddr(
	vm_map_entry_t			entry,
	uint32_t * vnodeaddr,
	uint32_t * vid)
{
	vm_object_t	top_object, object;
	memory_object_t memory_object;
	memory_object_pager_ops_t pager_ops;
	kern_return_t	kr;
	int		shadow_depth;


	if (entry->is_sub_map) {
		return(0);
	} else {
		/*
		 * The last object in the shadow chain has the
		 * relevant pager information.
		 */
		top_object = entry->object.vm_object;
		if (top_object == VM_OBJECT_NULL) {
			object = VM_OBJECT_NULL;
			shadow_depth = 0;
		} else {
			vm_object_lock(top_object);
			for (object = top_object, shadow_depth = 0;
			     object->shadow != VM_OBJECT_NULL;
			     object = object->shadow, shadow_depth++) {
				vm_object_lock(object->shadow);
				vm_object_unlock(object);
			}
		}
	}

	if (object == VM_OBJECT_NULL) {
		return(0);
	} else if (object->internal) {
		vm_object_unlock(object);
		return(0);
	} else if (! object->pager_ready ||
		   object->terminating ||
		   ! object->alive) {
		vm_object_unlock(object);
		return(0);
	} else {
		memory_object = object->pager;
		pager_ops = memory_object->mo_pager_ops;
		if (pager_ops == &vnode_pager_ops) {
			kr = vnode_pager_get_object_vnode(
				memory_object,
				vnodeaddr, vid);
			if (kr != KERN_SUCCESS) {
				vm_object_unlock(object);
				return(0);
			}
		} else {
			vm_object_unlock(object);
			return(0);
		}
	}
	vm_object_unlock(object);
	return(1);
}

kern_return_t 
vnode_pager_get_object_vnode (
	memory_object_t		mem_obj,
	uint32_t * vnodeaddr,
	uint32_t * vid)
{
	vnode_pager_t	vnode_object;

	vnode_object = vnode_pager_lookup(mem_obj);
	if (vnode_object->vnode_handle)  {
		*vnodeaddr = (uint32_t)vnode_object->vnode_handle;
		*vid = (uint32_t)vnode_vid((void *)vnode_object->vnode_handle);	

		return(KERN_SUCCESS);
	}
	
	return(KERN_FAILURE);
}

