/*
 * Copyright (c) 2000-2010 Apple Inc. All rights reserved.
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
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
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
#include <sys/user.h>
#if CONFIG_PROTECT
#include <sys/cprotect.h>
#endif

#include <default_pager/default_pager_types.h>
#include <default_pager/default_pager_object.h>

#include <security/audit/audit.h>
#include <bsm/audit_kevents.h>

#include <mach/mach_types.h>
#include <mach/host_priv.h>
#include <mach/mach_traps.h>
#include <mach/boolean.h>

#include <kern/kern_types.h>
#include <kern/locks.h>
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
#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

#include <pexpert/pexpert.h>

void macx_init(void);

static lck_grp_t *macx_lock_group;
static lck_mtx_t *macx_lock;

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
 *	Routine:	macx_init
 *	Function:
 *		Initialize locks so that only one caller can change
 *      state at a time.
 */
void
macx_init(void)
{
	macx_lock_group = lck_grp_alloc_init("macx", NULL);
	macx_lock = lck_mtx_alloc_init(macx_lock_group, NULL);
}

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

	lck_mtx_lock(macx_lock);
	if ((error = suser(kauth_cred_get(), 0)))
		goto backing_store_suspend_return;

	/* Multiple writers protected by macx_lock */
	vm_backing_store_disable(suspend);

backing_store_suspend_return:
	lck_mtx_unlock(macx_lock);
	return(error);
}

extern boolean_t backing_store_stop_compaction;
extern boolean_t compressor_store_stop_compaction;

/*
 *	Routine:	macx_backing_store_compaction
 *	Function:
 *		Turn compaction of swap space on or off.  This is
 *		used during shutdown/restart so	that the kernel 
 *		doesn't waste time compacting swap files that are 
 *		about to be deleted anyway.  Compaction	is always 
 *		on by default when the system comes up and is turned 
 *		off when a shutdown/restart is requested.  It is 
 *		re-enabled if the shutdown/restart is aborted for any reason.
 *
 *  This routine assumes macx_lock has been locked by macx_triggers ->
 *      mach_macx_triggers -> macx_backing_store_compaction
 */

int
macx_backing_store_compaction(int flags)
{
	int error;

	lck_mtx_assert(macx_lock, LCK_MTX_ASSERT_OWNED);
	if ((error = suser(kauth_cred_get(), 0)))
		return error;

	if (flags & SWAP_COMPACT_DISABLE) {
		backing_store_stop_compaction = TRUE;
		compressor_store_stop_compaction = TRUE;

		kprintf("backing_store_stop_compaction = TRUE\n");

	} else if (flags & SWAP_COMPACT_ENABLE) {
		backing_store_stop_compaction = FALSE;
		compressor_store_stop_compaction = FALSE;

		kprintf("backing_store_stop_compaction = FALSE\n");
	}

	return 0;
}

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
	int	error;

	lck_mtx_lock(macx_lock);
	error = suser(kauth_cred_get(), 0);
	if (error)
		return error;

	error = mach_macx_triggers(args);
	
	lck_mtx_unlock(macx_lock);
	return error;
}


extern boolean_t dp_isssd;

/*
 * In the compressed pager world, the swapfiles are created by the kernel.
 * Well, all except the first one. That swapfile is absorbed by the kernel at
 * the end of the macx_swapon function (if swap is enabled). That's why
 * we allow the first invocation of macx_swapon to succeed.
 *
 * If the compressor pool is running low, the kernel messages the dynamic pager
 * on the port it has registered with the kernel. That port can transport 1 of 2
 * pieces of information to dynamic pager: create a swapfile or delete a swapfile.
 *
 * We choose to transmit the former. So, that message tells dynamic pager
 * to create a swapfile and activate it by calling macx_swapon. 
 *
 * We deny this new macx_swapon request. That leads dynamic pager to interpret the
 * failure as a serious error and notify all it's clients that swap is running low.
 * That's how we get the loginwindow "Resume / Force Quit Applications" dialog to appear.
 *
 * NOTE: 
 * If the kernel has already created multiple swapfiles by the time the compressor
 * pool is running low (and it has to play this trick), dynamic pager won't be able to
 * create a file in user-space and, that too will lead to a similar notification blast
 * to all of it's clients. So, that behaves as desired too.
 */
boolean_t	macx_swapon_allowed = TRUE;

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
	register int		error;
	kern_return_t		kr;
	mach_port_t		backing_store;
	memory_object_default_t	default_pager;
	int			i;
	off_t			file_size;
	vfs_context_t		ctx = vfs_context_current();
	struct proc		*p =  current_proc();
	int			dp_cluster_size;

	AUDIT_MACH_SYSCALL_ENTER(AUE_SWAPON);
	AUDIT_ARG(value32, args->priority);
	
	lck_mtx_lock(macx_lock);

	if (COMPRESSED_PAGER_IS_ACTIVE) {
		if (macx_swapon_allowed == FALSE) {
			error = EINVAL;
			goto swapon_bailout;
		} else {
			macx_swapon_allowed = FALSE;
			error = 0;
			goto swapon_bailout;
		}
	}

	ndp = &nd;

	if ((error = suser(kauth_cred_get(), 0)))
		goto swapon_bailout;

	/*
	 * Get a vnode for the paging area.
	 */
	NDINIT(ndp, LOOKUP, OP_LOOKUP, FOLLOW | LOCKLEAF | AUDITVNPATH1,
	       ((IS_64BIT_PROCESS(p)) ? UIO_USERSPACE64 : UIO_USERSPACE32),
	       (user_addr_t) args->filename, ctx);

	if ((error = namei(ndp)))
		goto swapon_bailout;
	nameidone(ndp);
	vp = ndp->ni_vp;

	if (vp->v_type != VREG) {
		error = EINVAL;
		goto swapon_bailout;
	}

	/* get file size */
	if ((error = vnode_size(vp, &file_size, ctx)) != 0)
		goto swapon_bailout;
#if CONFIG_MACF
	vnode_lock(vp);
	error = mac_system_check_swapon(vfs_context_ucred(ctx), vp);
	vnode_unlock(vp);
	if (error)
		goto swapon_bailout;
#endif

	/* resize to desired size if it's too small */
	if ((file_size < (off_t)size) && ((error = vnode_setsize(vp, (off_t)size, 0, ctx)) != 0))
		goto swapon_bailout;

#if CONFIG_PROTECT
	{
		/* initialize content protection keys manually */
		if ((error = cp_handle_vnop(vp, CP_WRITE_ACCESS, 0)) != 0) {
			goto swapon_bailout;
 		}
	}
#endif


	if (default_pager_init_flag == 0) {
		start_def_pager(NULL);
		default_pager_init_flag = 1;
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

	if ((dp_isssd = vnode_pager_isSSD(vp)) == TRUE) {
		/*
		 * keep the cluster size small since the
		 * seek cost is effectively 0 which means
		 * we don't care much about fragmentation
		 */
		dp_cluster_size = 2 * PAGE_SIZE;
	} else {
		/*
		 * use the default cluster size
		 */
		dp_cluster_size = 0;
	}
	kr = default_pager_backing_store_create(default_pager, 
					-1, /* default priority */
					dp_cluster_size,
					&backing_store);
	memory_object_default_deallocate(default_pager);

	if(kr != KERN_SUCCESS) {
	   error = ENOMEM;
	   bs_port_table[i].vp = 0;
	   goto swapon_bailout;
	}

	/* Mark this vnode as being used for swapfile */
	vnode_lock_spin(vp);
	SET(vp->v_flag, VSWAP);
	vnode_unlock(vp);

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

	   /* This vnode is not to be used for swapfile */
	   vnode_lock_spin(vp);
	   CLR(vp->v_flag, VSWAP);
	   vnode_unlock(vp);

	   goto swapon_bailout;
	}
	bs_port_table[i].bs = (void *)backing_store;
	error = 0;

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
	lck_mtx_unlock(macx_lock);
	AUDIT_MACH_SYSCALL_EXIT(error);

	if (error)
		printf("macx_swapon FAILED - %d\n", error);
	else
		printf("macx_swapon SUCCESS\n");

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
	vfs_context_t ctx = vfs_context_current();
	int			orig_iopol_disk;

	AUDIT_MACH_SYSCALL_ENTER(AUE_SWAPOFF);

	lck_mtx_lock(macx_lock);
	
	backing_store = NULL;
	ndp = &nd;

	if ((error = suser(kauth_cred_get(), 0)))
		goto swapoff_bailout;

	/*
	 * Get the vnode for the paging area.
	 */
	NDINIT(ndp, LOOKUP, OP_LOOKUP, FOLLOW | LOCKLEAF | AUDITVNPATH1,
	       ((IS_64BIT_PROCESS(p)) ? UIO_USERSPACE64 : UIO_USERSPACE32),
	       (user_addr_t) args->filename, ctx);

	if ((error = namei(ndp)))
		goto swapoff_bailout;
	nameidone(ndp);
	vp = ndp->ni_vp;

	if (vp->v_type != VREG) {
		error = EINVAL;
		goto swapoff_bailout;
	}
#if CONFIG_MACF
	vnode_lock(vp);
	error = mac_system_check_swapoff(vfs_context_ucred(ctx), vp);
	vnode_unlock(vp);
	if (error)
		goto swapoff_bailout;
#endif

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

	orig_iopol_disk = proc_get_task_policy(current_task(), current_thread(),
	                                       TASK_POLICY_INTERNAL, TASK_POLICY_IOPOL);

	proc_set_task_policy(current_task(), current_thread(), TASK_POLICY_INTERNAL,
	                     TASK_POLICY_IOPOL, IOPOL_THROTTLE);

	kr = default_pager_backing_store_delete(backing_store);

	proc_set_task_policy(current_task(), current_thread(), TASK_POLICY_INTERNAL,
	                     TASK_POLICY_IOPOL, orig_iopol_disk);

	switch (kr) {
		case KERN_SUCCESS:
			error = 0;
			bs_port_table[i].vp = 0;
			/* This vnode is no longer used for swapfile */
			vnode_lock_spin(vp);
			CLR(vp->v_flag, VSWAP);
			vnode_unlock(vp);

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
	lck_mtx_unlock(macx_lock);
	AUDIT_MACH_SYSCALL_EXIT(error);

	if (error)
		printf("macx_swapoff FAILED - %d\n", error);
	else
		printf("macx_swapoff SUCCESS\n");

	return(error);
}

/*
 *	Routine:	macx_swapinfo
 *	Function:
 *		Syscall interface to get general swap statistics
 */
extern uint64_t vm_swap_get_total_space(void);
extern uint64_t vm_swap_get_used_space(void);
extern uint64_t vm_swap_get_free_space(void);
extern boolean_t vm_swap_up;

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
	if (COMPRESSED_PAGER_IS_ACTIVE) {

		if (vm_swap_up == TRUE) {

			*total_p = vm_swap_get_total_space();
			*avail_p = vm_swap_get_free_space();
			*pagesize_p = (vm_size_t)PAGE_SIZE_64;
			*encrypted_p = TRUE;

		} else {

			*total_p = 0;
			*avail_p = 0;
			*pagesize_p = 0;
			*encrypted_p = FALSE;
		}
	} else {

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
	}
	return error;
}
