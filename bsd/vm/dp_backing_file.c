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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/buf.h>
#include <sys/uio.h>
#include <sys/vnode_internal.h>
#include <sys/namei.h>
#include <sys/ubc_internal.h>
#include <sys/malloc.h>

#include <default_pager/default_pager_types.h>
#include <default_pager/default_pager_object.h>

#include <bsm/audit_kernel.h>
#include <bsm/audit_kevents.h>

#include <mach/mach_types.h>
#include <mach/host_priv.h>
#include <mach/mach_traps.h>
#include <mach/boolean.h>

#include <kern/kern_types.h>
#include <kern/host.h>
#include <kern/task.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <kern/assert.h>

#include <libkern/libkern.h>

#include <vm/vm_pageout.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vnode_pager.h>
#include <vm/vm_protos.h>

extern thread_t current_act(void);

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


/*
 *	Routine:	macx_backing_store_recovery
 *	Function:
 *		Syscall interface to set a tasks privilege
 *		level so that it is not subject to 
 *		macx_backing_store_suspend
 */
int
macx_backing_store_recovery(
	struct macx_backing_store_recovery_args *args)
{
	int		pid = args->pid;
	int		error;
	struct proc	*p =  current_proc();
	boolean_t	funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	if ((error = suser(kauth_cred_get(), 0)))
		goto backing_store_recovery_return;

	/* for now restrict backing_store_recovery */
	/* usage to only present task */
	if(pid != proc_selfpid()) {
		error = EINVAL;
		goto backing_store_recovery_return;
	}

	task_backing_store_privileged(p->task);

backing_store_recovery_return:
	(void) thread_funnel_set(kernel_flock, FALSE);
	return(error);
}

/*
 *	Routine:	macx_backing_store_suspend
 *	Function:
 *		Syscall interface to stop new demand for 
 *		backing store when backing store is low
 */

int
macx_backing_store_suspend(
	struct macx_backing_store_suspend_args *args)
{
	boolean_t	suspend = args->suspend;
	int		error;
	boolean_t	funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	if ((error = suser(kauth_cred_get(), 0)))
		goto backing_store_suspend_return;

	vm_backing_store_disable(suspend);

backing_store_suspend_return:
	(void) thread_funnel_set(kernel_flock, FALSE);
	return(error);
}

/*
 *	Routine:	macx_swapon
 *	Function:
 *		Syscall interface to add a file to backing store
 */
int
macx_swapon(
	struct macx_swapon_args *args)
{
	int			size = args->size;
	vnode_t			vp = (vnode_t)NULL; 
	struct nameidata 	nd, *ndp;
	struct proc		*p =  current_proc();
	register int		error;
	kern_return_t		kr;
	mach_port_t		backing_store;
	memory_object_default_t	default_pager;
	int			i;
	boolean_t		funnel_state;
	off_t			file_size;
	struct vfs_context	context;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	AUDIT_MACH_SYSCALL_ENTER(AUE_SWAPON);
	AUDIT_ARG(value, args->priority);

	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	ndp = &nd;

	if ((error = suser(kauth_cred_get(), 0)))
		goto swapon_bailout;

	if(default_pager_init_flag == 0) {
		start_def_pager(NULL);
		default_pager_init_flag = 1;
	}

	/*
	 * Get a vnode for the paging area.
	 */
	NDINIT(ndp, LOOKUP, FOLLOW | LOCKLEAF | AUDITVNPATH1,
	       ((IS_64BIT_PROCESS(p)) ? UIO_USERSPACE64 : UIO_USERSPACE32),
	       CAST_USER_ADDR_T(args->filename), &context);

	if ((error = namei(ndp)))
		goto swapon_bailout;
	nameidone(ndp);
	vp = ndp->ni_vp;

	if (vp->v_type != VREG) {
		error = EINVAL;
		goto swapon_bailout;
	}
	UBCINFOCHECK("macx_swapon", vp);

	/* get file size */
	if ((error = vnode_size(vp, &file_size, &context)) != 0)
		goto swapon_bailout;

	/* resize to desired size if it's too small */
	if ((file_size < (off_t)size) && ((error = vnode_setsize(vp, (off_t)size, 0, &context)) != 0))
		goto swapon_bailout;

	/* add new backing store to list */
	i = 0;
	while(bs_port_table[i].vp != 0) {
		if(i == MAX_BACKING_STORE)
			break;
		i++;
	}
	if(i == MAX_BACKING_STORE) {
	   	error = ENOMEM;
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

	kr = default_pager_add_file(backing_store, (vnode_ptr_t) vp,
				PAGE_SIZE, (int)(file_size/PAGE_SIZE));
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

	/* Mark this vnode as being used for swapfile */
	SET(vp->v_flag, VSWAP);

	ubc_setthreadcred(vp, p, current_thread());

	/*
	 * take a long term reference on the vnode to keep
	 * vnreclaim() away from this vnode.
	 */
	vnode_ref(vp);

swapon_bailout:
	if (vp) {
		vnode_put(vp);
	}
	(void) thread_funnel_set(kernel_flock, FALSE);
	AUDIT_MACH_SYSCALL_EXIT(error);
	return(error);
}

/*
 *	Routine:	macx_swapoff
 *	Function:
 *		Syscall interface to remove a file from backing store
 */
int
macx_swapoff(
	struct macx_swapoff_args *args)
{
	__unused int	flags = args->flags;
	kern_return_t	kr;
	mach_port_t	backing_store;

	struct vnode		*vp = 0; 
	struct nameidata 	nd, *ndp;
	struct proc		*p =  current_proc();
	int			i;
	int			error;
	boolean_t		funnel_state;
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	AUDIT_MACH_SYSCALL_ENTER(AUE_SWAPOFF);

	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	backing_store = NULL;
	ndp = &nd;

	if ((error = suser(kauth_cred_get(), 0)))
		goto swapoff_bailout;

	/*
	 * Get the vnode for the paging area.
	 */
	NDINIT(ndp, LOOKUP, FOLLOW | LOCKLEAF | AUDITVNPATH1,
	       ((IS_64BIT_PROCESS(p)) ? UIO_USERSPACE64 : UIO_USERSPACE32),
	       CAST_USER_ADDR_T(args->filename), &context);

	if ((error = namei(ndp)))
		goto swapoff_bailout;
	nameidone(ndp);
	vp = ndp->ni_vp;

	if (vp->v_type != VREG) {
		error = EINVAL;
		goto swapoff_bailout;
	}

	for(i = 0; i < MAX_BACKING_STORE; i++) {
		if(bs_port_table[i].vp == vp) {
			break;
		}
	}
	if (i == MAX_BACKING_STORE) {
		error = EINVAL;
		goto swapoff_bailout;
	}
	backing_store = (mach_port_t)bs_port_table[i].bs;

	kr = default_pager_backing_store_delete(backing_store);
	switch (kr) {
		case KERN_SUCCESS:
			error = 0;
			bs_port_table[i].vp = 0;
			/* This vnode is no longer used for swapfile */
			CLR(vp->v_flag, VSWAP);

			/* get rid of macx_swapon() "long term" reference */
			vnode_rele(vp);

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
		vnode_put(vp);

	(void) thread_funnel_set(kernel_flock, FALSE);
	AUDIT_MACH_SYSCALL_EXIT(error);
	return(error);
}

/*
 *	Routine:	macx_swapinfo
 *	Function:
 *		Syscall interface to get general swap statistics
 */
int
macx_swapinfo(
	memory_object_size_t	*total_p,
	memory_object_size_t	*avail_p,
	vm_size_t		*pagesize_p,
	boolean_t		*encrypted_p)
{
	int			error;
	memory_object_default_t	default_pager;
	default_pager_info_64_t	dpi64;
	kern_return_t		kr;

	error = 0;

	/*
	 * Get a handle on the default pager.
	 */
	default_pager = MEMORY_OBJECT_DEFAULT_NULL;
	kr = host_default_memory_manager(host_priv_self(), &default_pager, 0);
	if (kr != KERN_SUCCESS) {
		error = EAGAIN;	/* XXX why EAGAIN ? */
		goto done;
	}
	if (default_pager == MEMORY_OBJECT_DEFAULT_NULL) {
		/*
		 * The default pager has not initialized yet,
		 * so it can't be using any swap space at all.
		 */
		*total_p = 0;
		*avail_p = 0;
		*pagesize_p = 0;
		*encrypted_p = FALSE;
		goto done;
	}
	
	/*
	 * Get swap usage data from default pager.
	 */
	kr = default_pager_info_64(default_pager, &dpi64);
	if (kr != KERN_SUCCESS) {
		error = ENOTSUP;
		goto done;
	}

	/*
	 * Provide default pager info to caller.
	 */
	*total_p = dpi64.dpi_total_space;
	*avail_p = dpi64.dpi_free_space;
	*pagesize_p = dpi64.dpi_page_size;
	if (dpi64.dpi_flags & DPI_ENCRYPTED) {
		*encrypted_p = TRUE;
	} else {
		*encrypted_p = FALSE;
	}

done:
	if (default_pager != MEMORY_OBJECT_DEFAULT_NULL) {
		/* release our handle on default pager */
		memory_object_default_deallocate(default_pager);
	}
	return error;
}
