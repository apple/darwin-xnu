/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1998-1999 Apple Computer, Inc.  All rights reserved.
 *
 *  File:  vfs/vfs_support.c
 *
 *	The default VFS routines. A VFS plugin can use these
 *	functions in case it does not want to implement all. These functions
 *	take care of releasing locks and free up memory that they are
 *	supposed to.
 *
 *	nop_* routines always return 0 [success]
 *	err_* routines always return EOPNOTSUPP
 *
 *	This file could be auto-generated from vnode_if.src. but that needs
 *	support for freeing cnp.
 *
 * HISTORY
 *  15-Jul-1998 Earsh Nandkeshwar (earsh@apple.com)
 *      Fixed up readdirattr for its existance now.
 *  18-Aug-1998 Umesh Vaishampayan (umeshv@apple.com)
 *      Created.
 */

#include <vfs/vfs_support.h>


struct vop_create_args /* {
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
	struct vattr *a_vap;
} */;

int
nop_create(struct vop_create_args *ap)
{
#if DIAGNOSTIC
	if ((ap->a_cnp->cn_flags & HASBUF) == 0)
		panic("nop_create: no name");
#endif
	VOP_ABORTOP(ap->a_dvp, ap->a_cnp);
	vput(ap->a_dvp);
	return (0);
}

int
err_create(struct vop_create_args *ap)
{
	(void)nop_create(ap);
	return (EOPNOTSUPP);
}


struct vop_whiteout_args /* {
	struct vnode *a_dvp;
	struct componentname *a_cnp;
	int a_flags;
} */;

int
nop_whiteout(struct vop_whiteout_args *ap)
{
	return (0);
}

int
err_whiteout(struct vop_whiteout_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_mknod_args /* {
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
	struct vattr *a_vap;
} */;

int
nop_mknod(struct vop_mknod_args *ap)
{
#if DIAGNOSTIC
	if ((ap->a_cnp->cn_flags & HASBUF) == 0)
		panic("nop_mknod: no name");
#endif
	VOP_ABORTOP(ap->a_dvp, ap->a_cnp);
	vput(ap->a_dvp);
	return (0);
}

int
err_mknod(struct vop_mknod_args *ap)
{
	(void)nop_mknod(ap);
	return (EOPNOTSUPP);
}


struct vop_mkcomplex_args /* {
	struct vnode *a_dvp,
	struct vnode **a_vpp,
	struct componentname *a_cnp,
	struct vattr *a_vap,
	u_long a_type)
} */;

int
nop_mkcomplex(struct vop_mkcomplex_args *ap)
{
#if DIAGNOSTIC
	if ((ap->a_cnp->cn_flags & HASBUF) == 0)
		panic("nop_mkcomplex: no name");
#endif
	VOP_ABORTOP(ap->a_dvp, ap->a_cnp);
	vput(ap->a_dvp);
	return (0);
}

int
err_mkcomplex(struct vop_mkcomplex_args *ap)
{
	(void)nop_mkcomplex(ap);
	return (EOPNOTSUPP);
}


struct vop_open_args /* {
	struct vnode *a_vp;
	int  a_mode;
	struct ucred *a_cred;
	struct proc *a_p;
} */;

int
nop_open(struct vop_open_args *ap)
{
	return (0);
}

int
err_open(struct vop_open_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_close_args /* {
	struct vnode *a_vp;
	int  a_fflag;
	struct ucred *a_cred;
	struct proc *a_p;
} */;

int
nop_close(struct vop_close_args *ap)
{
	return (0);
}

int
err_close(struct vop_close_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_access_args /* {
	struct vnode *a_vp;
	int  a_mode;
	struct ucred *a_cred;
	struct proc *a_p;
} */;

int
nop_access(struct vop_access_args *ap)
{
	return (0);
}

int
err_access(struct vop_access_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_getattr_args /* {
	struct vnode *a_vp;
	struct vattr *a_vap;
	struct ucred *a_cred;
	struct proc *a_p;
} */;

int
nop_getattr(struct vop_getattr_args *ap)
{
	return (0);
}

int
err_getattr(struct vop_getattr_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_setattr_args /* {
	struct vnode *a_vp;
	struct vattr *a_vap;
	struct ucred *a_cred;
	struct proc *a_p;
} */;

int
nop_setattr(struct vop_setattr_args *ap)
{
	return (0);
}

int
err_setattr(struct vop_setattr_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_getattrlist_args /* {
	struct vnode *a_vp;
	struct attrlist *a_alist;
	struct uio *a_uio;
	struct ucred *a_cred;
	struct proc *a_p;
} */;

int
nop_getattrlist(struct vop_getattrlist_args *ap)
{
	return (0);
}

int
err_getattrlist(struct vop_getattrlist_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_setattrlist_args /* {
	struct vnode *a_vp;
	struct attrlist *a_alist;
	struct uio *a_uio;
	struct ucred *a_cred;
	struct proc *a_p;
} */;

int
nop_setattrlist(struct vop_setattrlist_args *ap)
{
	return (0);
}

int
err_setattrlist(struct vop_setattrlist_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_read_args /*  {
	struct vnode *a_vp;
	struct uio *a_uio;
	int a_ioflag;
	struct ucred *a_cred;
} */;

int
nop_read(struct vop_read_args *ap)
{
	return (0);
}

int
err_read(struct vop_read_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_write_args /*  {
	struct vnode *a_vp;
	struct uio *a_uio;
	int a_ioflag;
	struct ucred *a_cred;
} */;

int
nop_write(struct vop_write_args *ap)
{
	return (0);
}

int
err_write(struct vop_write_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_lease_args /* {
	struct vnode *a_vp;
	struct proc *a_p;
	struct ucred *a_cred;
	int a_flag;
} */;

int
nop_lease(struct vop_lease_args *ap)
{
	return (0);
}

int
err_lease(struct vop_lease_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_ioctl_args /* {
	struct vnode *a_vp;
	u_long a_command;
	caddr_t a_data;
	int a_fflag;
	struct ucred *a_cred;
	struct proc *a_p;
} */;

int
nop_ioctl(struct vop_ioctl_args *ap)
{
	return (0);
}

int
err_ioctl(struct vop_ioctl_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_select_args /* {
	struct vnode *a_vp;
	int a_which;
	int a_fflags;
	struct ucred *a_cred;
	void *a_wql;
	struct proc *a_p;
} */;

int
nop_select(struct vop_select_args *ap)
{
	return (0);
}

int
err_select(struct vop_select_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_exchange_args /* {
	struct vnode *a_fvp;
	struct vnode *a_tvp;
	struct ucred *a_cred;
	struct proc *a_p;
} */;

int
nop_exchange(struct vop_exchange_args *ap)
{
	return (0);
}

int
err_exchange(struct vop_exchange_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_revoke_args /* {
	struct vnode *a_vp;
	int a_flags;
} */;

int
nop_revoke(struct vop_revoke_args *ap)
{
	return (vop_revoke(ap));
}

int
err_revoke(struct vop_revoke_args *ap)
{
	(void)nop_revoke(ap);
	return (EOPNOTSUPP);
}


struct vop_mmap_args /* {
	struct vnode *a_vp;
	int a_fflags;
	struct ucred *a_cred;
	struct proc *a_p;
} */;

int
nop_mmap(struct vop_mmap_args *ap)
{
	return (0);
}

int
err_mmap(struct vop_mmap_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_fsync_args /* {
	struct vnode *a_vp;
	struct ucred *a_cred;
	int a_waitfor;
	struct proc *a_p;
} */;

int
nop_fsync(struct vop_fsync_args *ap)
{
	return (0);
}

int
err_fsync(struct vop_fsync_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_seek_args /* {
	struct vnode *a_vp;
	off_t a_oldoff;
	off_t a_newoff;
	struct ucred *a_cred;
} */;

int
nop_seek(struct vop_seek_args *ap)
{
	return (0);
}

int
err_seek(struct vop_seek_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_remove_args /* {
	struct vnode *a_dvp;
	struct vnode *a_vp;
	struct componentname *a_cnp;
} */;

int
nop_remove(struct vop_remove_args *ap)
{
	if (ap->a_dvp == ap->a_vp)
		vrele(ap->a_vp);
	else
		vput(ap->a_vp);
	vput(ap->a_dvp);
	return (0);
}

int
err_remove(struct vop_remove_args *ap)
{
	(void)nop_remove(ap);
	return (EOPNOTSUPP);
}


struct vop_link_args /* {
	struct vnode *a_vp;
	struct vnode *a_tdvp;
	struct componentname *a_cnp;
} */;

int
nop_link(struct vop_link_args *ap)
{
#if DIAGNOSTIC
	if ((ap->a_cnp->cn_flags & HASBUF) == 0)
		panic("nop_link: no name");
#endif
	VOP_ABORTOP(ap->a_tdvp, ap->a_cnp);
	vput(ap->a_tdvp);
	return (0);
}

int
err_link(struct vop_link_args *ap)
{
	(void)nop_link(ap);
	return (EOPNOTSUPP);
}


struct vop_rename_args /* {
	struct vnode *a_fdvp;
	struct vnode *a_fvp;
	struct componentname *a_fcnp;
	struct vnode *a_tdvp;
	struct vnode *a_tvp;
	struct componentname *a_tcnp;
} */;

int
nop_rename(struct vop_rename_args *ap)
{
#if DIAGNOSTIC
	if ((ap->a_tcnp->cn_flags & HASBUF) == 0 ||
	    (ap->a_fcnp->cn_flags & HASBUF) == 0)
		panic("nop_rename: no name");
#endif
	VOP_ABORTOP(ap->a_tdvp, ap->a_tcnp);
	if (ap->a_tdvp == ap->a_tvp)
		vrele(ap->a_tdvp);
	else
		vput(ap->a_tdvp);
	if (ap->a_tvp)
		vput(ap->a_tvp);
	VOP_ABORTOP(ap->a_fdvp, ap->a_fcnp);
	vrele(ap->a_fdvp);
	vrele(ap->a_fvp);
	return (0);
}

int
err_rename(struct vop_rename_args *ap)
{
	(void)nop_rename(ap);
	return (EOPNOTSUPP);
}


struct vop_mkdir_args /* {
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
	struct vattr *a_vap;
} */;

int
nop_mkdir(struct vop_mkdir_args *ap)
{
#if DIAGNOSTIC
	if ((ap->a_cnp->cn_flags & HASBUF) == 0)
		panic("nop_mkdir: no name");
#endif
	VOP_ABORTOP(ap->a_dvp, ap->a_cnp);
	vput(ap->a_dvp);
	return (0);
}

int
err_mkdir(struct vop_mkdir_args *ap)
{
	(void)nop_mkdir(ap);
	return (EOPNOTSUPP);
}


struct vop_rmdir_args /* {
	struct vnode *a_dvp;
	struct vnode *a_vp;
	struct componentname *a_cnp;
} */;

int
nop_rmdir(struct vop_rmdir_args *ap)
{
	vput(ap->a_dvp);
	vput(ap->a_vp);
	return (0);
}

int
err_rmdir(struct vop_rmdir_args *ap)
{
	(void)nop_rmdir(ap);
	return (EOPNOTSUPP);
}


struct vop_symlink_args /* {
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
	struct vattr *a_vap;
	char *a_target;
} */;

int
nop_symlink(struct vop_symlink_args *ap)
{
#if DIAGNOSTIC
	if ((ap->a_cnp->cn_flags & HASBUF) == 0)
		panic("nop_symlink: no name");
#endif
	VOP_ABORTOP(ap->a_dvp, ap->a_cnp);
	vput(ap->a_dvp);
	return (0);
}

int
err_symlink(struct vop_symlink_args *ap)
{
	(void)nop_symlink(ap);
	return (EOPNOTSUPP);
}


struct vop_readdir_args /* {
	struct vnode *a_vp;
	struct uio *a_uio;
	struct ucred *a_cred;
	int *a_eofflag;
	int *a_ncookies;
	u_long **a_cookies;
} */;

int
nop_readdir(struct vop_readdir_args *ap)
{
	return (0);
}

int
err_readdir(struct vop_readdir_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_readdirattr_args /* {
	struct vnode *a_vp;
	struct attrlist *a_alist;
	struct uio *a_uio;
	u_long a_maxcount;
        u_long a_options;
        int *a_newstate;
	int *a_eofflag;
   	u_long *a_actualcount;
	u_long **a_cookies;
	struct ucred *a_cred;
} */;

int
nop_readdirattr(struct vop_readdirattr_args *ap)
{
        *(ap->a_actualcount) = 0;
        *(ap->a_eofflag) = 0;
	return (0);
}

int
err_readdirattr(struct vop_readdirattr_args *ap)
{
       (void)nop_readdirattr(ap);
	return (EOPNOTSUPP);
}


struct vop_readlink_args /* {
	struct vnode *vp;
	struct uio *uio;
	struct ucred *cred;
} */;

int
nop_readlink(struct vop_readlink_args *ap)
{
	return (0);
}

int
err_readlink(struct vop_readlink_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_abortop_args /* {
	struct vnode *a_dvp;
	struct componentname *a_cnp;
} */;

int
nop_abortop(struct vop_abortop_args *ap)
{
	if ((ap->a_cnp->cn_flags & (HASBUF | SAVESTART)) == HASBUF) {
		char *tmp = ap->a_cnp->cn_pnbuf;
		ap->a_cnp->cn_pnbuf = NULL;
		ap->a_cnp->cn_flags &= ~HASBUF;
		FREE_ZONE(tmp, ap->a_cnp->cn_pnlen, M_NAMEI);
	}

	return (0);
}

int
err_abortop(struct vop_abortop_args *ap)
{
	(void)nop_abortop(ap);
	return (EOPNOTSUPP);
}


struct vop_inactive_args /* {
	struct vnode *a_vp;
	struct proc *a_p;
} */;

int
nop_inactive(struct vop_inactive_args *ap)
{
	VOP_UNLOCK(ap->a_vp, 0, ap->a_p);
	return (0);
}

int
err_inactive(struct vop_inactive_args *ap)
{
	(void)nop_inactive(ap);
	return (EOPNOTSUPP);
}


struct vop_reclaim_args /* {
	struct vnode *a_vp;
	struct proc *a_p;
} */;

int
nop_reclaim(struct vop_reclaim_args *ap)
{
	return (0);
}

int
err_reclaim(struct vop_reclaim_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_lock_args /* {
	struct vnode *a_vp;
	int a_flags;
	struct proc *a_p;
} */;

int
nop_lock(struct vop_lock_args *ap)
{
	return (vop_nolock(ap));
}

int
err_lock(struct vop_lock_args *ap)
{
	(void)nop_lock(ap);
	return (EOPNOTSUPP);
}


struct vop_unlock_args /* {
	struct vnode *a_vp;
	int a_flags;
	struct proc *a_p;
} */;

int
nop_unlock(struct vop_unlock_args *ap)
{
	return (vop_nounlock(ap));
}

int
err_unlock(struct vop_unlock_args *ap)
{
	(void)nop_unlock(ap);
	return (EOPNOTSUPP);
}


struct vop_bmap_args /* {
	struct vnode *vp;
	daddr_t bn;
	struct vnode **vpp;
	daddr_t *bnp;
	int *runp;
} */;

int
nop_bmap(struct vop_bmap_args *ap)
{
	return (0);
}

int
err_bmap(struct vop_bmap_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_strategy_args /* {
	struct buf *a_bp;
} */;

int
nop_strategy(struct vop_strategy_args *ap)
{
	return (0);
}

int
err_strategy(struct vop_strategy_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_print_args /* {
	struct vnode *a_vp;
} */;

int
nop_print(struct vop_print_args *ap)
{
	return (0);
}

int
err_print(struct vop_print_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_islocked_args /* {
	struct vnode *a_vp;
} */;

int
nop_islocked(struct vop_islocked_args *ap)
{
	return (vop_noislocked(ap));
}

int
err_islocked(struct vop_islocked_args *ap)
{
	(void)nop_islocked(ap);
	return (EOPNOTSUPP);
}


struct vop_pathconf_args /* {
	struct vnode *a_vp;
	int a_name;
	register_t *a_retval;
} */;

int
nop_pathconf(struct vop_pathconf_args *ap)
{
	return (0);
}

int
err_pathconf(struct vop_pathconf_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_advlock_args /* {
	struct vnode *a_vp;
	caddr_t a_id;
	int a_op;
	struct flock *a_fl;
	int a_flags;
} */;

int
nop_advlock(struct vop_advlock_args *ap)
{
	return (0);
}

int
err_advlock(struct vop_advlock_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_blkatoff_args /* {
	struct vnode *a_vp;
	off_t a_offset;
	char **a_res;
	struct buf **a_bpp;
} */;

int
nop_blkatoff(struct vop_blkatoff_args *ap)
{
	*ap->a_bpp = NULL;
	return (0);
}

int
err_blkatoff(struct vop_blkatoff_args *ap)
{
	(void)nop_blkatoff(ap);
	return (EOPNOTSUPP);
}


struct vop_valloc_args /* {
	struct vnode *a_pvp;
	int a_mode;
	struct ucred *a_cred;
	struct vnode **a_vpp;
} */;

int
nop_valloc(struct vop_valloc_args *ap)
{
	*ap->a_vpp = NULL;
	return (0);
}

int
err_valloc(struct vop_valloc_args *ap)
{
	(void)nop_valloc(ap);
	return (EOPNOTSUPP);
}


struct vop_reallocblks_args /* {
	struct vnode *a_vp;
	struct cluster_save *a_buflist;
} */;

int
nop_reallocblks(struct vop_reallocblks_args *ap)
{
	return (0);
}

int
err_reallocblks(struct vop_reallocblks_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_vfree_args /* {
	struct vnode *a_pvp;
	ino_t a_ino;
	int a_mode;
} */;

int
nop_vfree(struct vop_vfree_args *ap)
{
	return (0);
}

int
err_vfree(struct vop_vfree_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_truncate_args /* {
	struct vnode *a_vp;
	off_t a_length;
	int a_flags;
	struct ucred *a_cred;
	struct proc *a_p;
} */;

int
nop_truncate(struct vop_truncate_args *ap)
{
	return (0);
}

int
err_truncate(struct vop_truncate_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_allocate_args /* {
	struct vnode *a_vp;
	off_t a_length;
	u_int32_t a_flags;
	off_t *a_bytesallocated;
	off_t a_offset;
	struct ucred *a_cred;
	struct proc *a_p;
} */;

int
nop_allocate(struct vop_allocate_args *ap)
{
	*(ap->a_bytesallocated) = 0;
	return (0);
}

int
err_allocate(struct vop_allocate_args *ap)
{
	(void)nop_allocate(ap);
	return (EOPNOTSUPP);
}


struct vop_update_args /* {
	struct vnode *a_vp;
	struct timeval *a_access;
	struct timeval *a_modify;
	int a_waitfor;
} */;

int
nop_update(struct vop_update_args *ap)
{
	return (0);
}

int
err_update(struct vop_update_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_pgrd_args /* {
	struct vnode *a_vp;
	struct uio *a_uio;
	struct ucred *a_cred;
} */;

int
nop_pgrd(struct vop_pgrd_args *ap)
{
	return (0);
}

int
err_pgrd(struct vop_pgrd_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_pgwr_args /* {
	struct vnode *a_vp;
	struct uio *a_uio;
	struct ucred *a_cred;
	vm_offset_t	a_offset;
} */;

int
nop_pgwr(struct vop_pgwr_args *ap)
{
	return (0);
}

int
err_pgwr(struct vop_pgwr_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_bwrite_args /* {
	struct buf *a_bp;
} */;

int
nop_bwrite(struct vop_bwrite_args *ap)
{
	return (bwrite(ap->a_bp));
}

int
err_bwrite(struct vop_bwrite_args *ap)
{
	return (EOPNOTSUPP);
}


struct vop_pagein_args /* {
	   	struct vnode 	*a_vp,
	   	upl_t		a_pl,
		vm_offset_t	a_pl_offset,
		off_t		a_foffset,
		size_t		a_size,
		struct ucred	*a_cred,
		int		a_flags
} */;

int
nop_pagein(struct vop_pagein_args *ap)
{
	ubc_upl_abort(ap->a_pl, UPL_ABORT_ERROR);
	return (0);
}

int
err_pagein(struct vop_pagein_args *ap)
{
	ubc_upl_abort(ap->a_pl, UPL_ABORT_ERROR);
	return (EOPNOTSUPP);
}


struct vop_pageout_args /* {
	   	struct vnode 	*a_vp,
	   	upl_t		a_pl,
		vm_offset_t	a_pl_offset,
		off_t		a_foffset,
		size_t		a_size,
		struct ucred	*a_cred,
		int		a_flags
} */;

int
nop_pageout(struct vop_pageout_args *ap)
{
	ubc_upl_abort(ap->a_pl, UPL_ABORT_ERROR);
	return (0);
}

int
err_pageout(struct vop_pageout_args *ap)
{
	ubc_upl_abort(ap->a_pl, UPL_ABORT_ERROR);
	return (EOPNOTSUPP);
}


struct vop_devblocksize_args /* {
	struct vnode *a_vp;
	register_t *a_retval;
} */;

int
nop_devblocksize(struct vop_devblocksize_args *ap)
{
	/* XXX default value because the call sites do not check error */
	*ap->a_retval = 512;
	return (0);
}

int
err_devblocksize(struct vop_devblocksize_args *ap)
{
	(void)nop_devblocksize(ap);
	return (EOPNOTSUPP);
}


struct vop_searchfs /* {
	struct vnode *a_vp;
	void *a_searchparams1;
	void *a_searchparams2;
	struct attrlist *a_searchattrs;
	u_long a_maxmatches;
	struct timeval *a_timelimit;
	struct attrlist *a_returnattrs;
	u_long *a_nummatches;
	u_long a_scriptcode;
	u_long a_options;
	struct uio	*a_uio;
	struct searchstate	*a_searchstate;
} */;

int
nop_searchfs(struct vop_searchfs_args *ap)
{
	*(ap->a_nummatches) = 0;
	return (0);
}

int
err_searchfs(struct vop_searchfs_args *ap)
{
	(void)nop_searchfs(ap);
	return (EOPNOTSUPP);
}

struct vop_copyfile_args /*{
        struct vnodeop_desc *a_desc;
        struct vnode *a_fvp;
        struct vnode *a_tdvp;
        struct vnode *a_tvp;
        struct componentname *a_tcnp;
        int a_flags;
}*/; 

int
nop_copyfile(struct vop_copyfile_args *ap)
{
	if (ap->a_tdvp == ap->a_tvp)
		vrele(ap->a_tdvp);
	else
		vput(ap->a_tdvp);
	if (ap->a_tvp)
		vput(ap->a_tvp);
	vrele(ap->a_fvp);
	return (0);
}


int
err_copyfile(struct vop_copyfile_args *ap)
{
	(void)nop_copyfile(ap);
	return (EOPNOTSUPP);
}


struct vop_blktooff_args /* {
	struct vnode *a_vp;
	daddr_t a_lblkno;
	off_t *a_offset;    
} */;

int
nop_blktooff(struct vop_blktooff_args *ap)
{
	*ap->a_offset = (off_t)-1;	/* failure */
	return (0);
}

int
err_blktooff(struct vop_blktooff_args *ap)
{
	(void)nop_blktooff(ap);
	return (EOPNOTSUPP);
}

struct vop_offtoblk_args /* {
	struct vnode *a_vp;
	off_t a_offset;    
	daddr_t *a_lblkno;
} */;

int
nop_offtoblk(struct vop_offtoblk_args *ap)
{
	*ap->a_lblkno = (daddr_t)-1;	/* failure */
	return (0);
}

int
err_offtoblk(struct vop_offtoblk_args *ap)
{
	(void)nop_offtoblk(ap);
	return (EOPNOTSUPP);
}

struct vop_cmap_args /* {
	struct vnode *a_vp;
	off_t a_foffset;
	size_t a_size;
	daddr_t *a_bpn;
	size_t *a_run;
	void *a_poff;
} */;

int nop_cmap(struct vop_cmap_args *ap)
{
	return (0);
}

int err_cmap(struct vop_cmap_args *ap)
{
	return (EOPNOTSUPP);
}

