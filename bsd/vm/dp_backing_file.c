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

#include <mach/boolean.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/proc.h>
#include <sys/buf.h>
#include <sys/uio.h>
#include <sys/vnode.h>
#include <sys/namei.h>
#include <sys/ubc.h>

#include <mach/mach_types.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <kern/host.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <libkern/libkern.h>
#include <sys/malloc.h>

#include <vm/vnode_pager.h>

/*
 * temporary support for delayed instantiation
 * of default_pager
 */
int default_pager_init_flag = 0;

struct bs_map		bs_port_table[MAX_BACKING_STORE] = { 
	{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},
	{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},
	{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},
	{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},
	{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},
	{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},
	{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},
	{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},
	{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},
	{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0}};

/* ###################################################### */


#include <kern/assert.h>

/*
 *	Routine:	macx_swapon
 *	Function:
 *		Syscall interface to add a file to backing store
 */
int
macx_swapon(
	char 	*filename,
	int	flags,
	long	size,
	long	priority)
{
	struct vnode		*vp = 0; 
	struct nameidata 	nd, *ndp;
	struct proc		*p =  current_proc();
	pager_file_t		pf;
	register int		error;
	kern_return_t		kr;
	mach_port_t		backing_store;
	memory_object_default_t	default_pager;
	int			i;
	boolean_t		funnel_state;

	struct vattr	vattr;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	ndp = &nd;

	if ((error = suser(p->p_ucred, &p->p_acflag)))
		goto swapon_bailout;

	if(default_pager_init_flag == 0) {
		start_def_pager(NULL);
		default_pager_init_flag = 1;
	}

	/*
	 * Get a vnode for the paging area.
	 */
	NDINIT(ndp, LOOKUP, FOLLOW | LOCKLEAF, UIO_USERSPACE,
	    filename, p);

	if ((error = namei(ndp)))
		goto swapon_bailout;
	vp = ndp->ni_vp;

	if (vp->v_type != VREG) {
		error = EINVAL;
	        VOP_UNLOCK(vp, 0, p);
		goto swapon_bailout;
	}
	UBCINFOCHECK("macx_swapon", vp);

	if (error = VOP_GETATTR(vp, &vattr, p->p_ucred, p)) {
	        VOP_UNLOCK(vp, 0, p);
		goto swapon_bailout;
	}

	if (vattr.va_size < (u_quad_t)size) {
		vattr_null(&vattr);
		vattr.va_size = (u_quad_t)size;
		error = VOP_SETATTR(vp, &vattr, p->p_ucred, p);
		if (error) {
			VOP_UNLOCK(vp, 0, p);
			goto swapon_bailout;
		}
	}

	/* add new backing store to list */
	i = 0;
	while(bs_port_table[i].vp != 0) {
		if(i == MAX_BACKING_STORE)
			break;
		i++;
	}
	if(i == MAX_BACKING_STORE) {
	   	error = ENOMEM;
	        VOP_UNLOCK(vp, 0, p);
		goto swapon_bailout;
	}

	/* remember the vnode. This vnode has namei() reference */
	bs_port_table[i].vp = vp;
	
	/*
	 * Look to see if we are already paging to this file.
	 */
	/* make certain the copy send of kernel call will work */
	default_pager = MEMORY_OBJECT_DEFAULT_NULL;
	kr = host_default_memory_manager(host_priv_self(), &default_pager, 0);
	if(kr != KERN_SUCCESS) {
	   error = EAGAIN;
	   VOP_UNLOCK(vp, 0, p);
	   bs_port_table[i].vp = 0;
	   goto swapon_bailout;
	}

	kr = default_pager_backing_store_create(default_pager, 
					-1, /* default priority */
					0, /* default cluster size */
					&backing_store);
	memory_object_default_deallocate(default_pager);

	if(kr != KERN_SUCCESS) {
	   error = ENOMEM;
	   VOP_UNLOCK(vp, 0, p);
	   bs_port_table[i].vp = 0;
	   goto swapon_bailout;
	}

	/*
	 * NOTE: we are able to supply PAGE_SIZE here instead of
	 *	an actual record size or block number because:
	 *	a: we do not support offsets from the beginning of the
	 *		file (allowing for non page size/record modulo offsets.
	 *	b: because allow paging will be done modulo page size
	 */

	VOP_UNLOCK(vp, 0, p);
	kr = default_pager_add_file(backing_store, vp, PAGE_SIZE, 
			((int)vattr.va_size)/PAGE_SIZE);
	if(kr != KERN_SUCCESS) {
	   bs_port_table[i].vp = 0;
	   if(kr == KERN_INVALID_ARGUMENT)
		error = EINVAL;
	   else 
		error = ENOMEM;
	   goto swapon_bailout;
	}
	bs_port_table[i].bs = (void *)backing_store;
	error = 0;
	if (!ubc_hold(vp))
		panic("macx_swapon: hold");

	/* Mark this vnode as being used for swapfile */
	SET(vp->v_flag, VSWAP);

	/*
	 * take an extra reference on the vnode to keep
	 * vnreclaim() away from this vnode.
	 */
	VREF(vp);

	/* Hold on to the namei  reference to the paging file vnode */
	vp = 0;

swapon_bailout:
	if (vp) {
		vrele(vp);
	}
	(void) thread_funnel_set(kernel_flock, FALSE);
	return(error);
}

/*
 *	Routine:	macx_swapoff
 *	Function:
 *		Syscall interface to remove a file from backing store
 */
int
macx_swapoff(
	char 	*filename,
	int	flags)
{
	kern_return_t	kr;
	mach_port_t	backing_store;

	struct vnode		*vp = 0; 
	struct nameidata 	nd, *ndp;
	struct proc		*p =  current_proc();
	int			i;
	int			error;
	boolean_t		funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	backing_store = NULL;
	ndp = &nd;

	if ((error = suser(p->p_ucred, &p->p_acflag)))
		goto swapoff_bailout;

	/*
	 * Get the vnode for the paging area.
	 */
	NDINIT(ndp, LOOKUP, FOLLOW | LOCKLEAF, UIO_USERSPACE,
	    filename, p);

	if ((error = namei(ndp)))
		goto swapoff_bailout;
	vp = ndp->ni_vp;

	if (vp->v_type != VREG) {
		error = EINVAL;
		VOP_UNLOCK(vp, 0, p);
		goto swapoff_bailout;
	}

	for(i = 0; i < MAX_BACKING_STORE; i++) {
		if(bs_port_table[i].vp == vp) {
			backing_store; 
			break;
		}
	}
	if (i == MAX_BACKING_STORE) {
		error = EINVAL;
		VOP_UNLOCK(vp, 0, p);
		goto swapoff_bailout;
	}
	backing_store = (mach_port_t)bs_port_table[i].bs;

	VOP_UNLOCK(vp, 0, p);
	kr = default_pager_backing_store_delete(backing_store);
	switch (kr) {
		case KERN_SUCCESS:
			error = 0;
			bs_port_table[i].vp = 0;
			ubc_rele(vp);
			/* This vnode is no longer used for swapfile */
			CLR(vp->v_flag, VSWAP);

			/* get rid of macx_swapon() namei() reference */
			vrele(vp);

			/* get rid of macx_swapon() "extra" reference */
			vrele(vp);
			break;
		case KERN_FAILURE:
			error = EAGAIN;
			break;
		default:
			error = EAGAIN;
			break;
	}

swapoff_bailout:
	/* get rid of macx_swapoff() namei() reference */
	if (vp)
		vrele(vp);

	(void) thread_funnel_set(kernel_flock, FALSE);
	return(error);
}
