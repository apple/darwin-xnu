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
/*	$NetBSD: mfs_vnops.c,v 1.5 1994/12/14 13:03:52 mycroft Exp $	*/

/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)mfs_vnops.c	8.5 (Berkeley) 7/28/94
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/buf.h>
#include <sys/map.h>
#include <sys/vnode.h>
#include <sys/malloc.h>

#include <miscfs/specfs/specdev.h>

#include <machine/vmparam.h>

#include <ufs/mfs/mfsnode.h>
#include <ufs/mfs/mfsiom.h>
#include <ufs/mfs/mfs_extern.h>

/*
 * mfs vnode operations.
 */

#define VOPFUNC int (*)(void *)

int (**mfs_vnodeop_p)(void *);
struct vnodeopv_entry_desc mfs_vnodeop_entries[] = {
	{ &vop_default_desc, (VOPFUNC)vn_default_error },
	{ &vop_lookup_desc, (VOPFUNC)mfs_lookup },		/* lookup */
	{ &vop_create_desc, (VOPFUNC)mfs_create },		/* create */
	{ &vop_mknod_desc, (VOPFUNC)mfs_mknod },		/* mknod */
	{ &vop_open_desc, (VOPFUNC)mfs_open },			/* open */
	{ &vop_close_desc, (VOPFUNC)mfs_close },		/* close */
	{ &vop_access_desc, (VOPFUNC)mfs_access },		/* access */
	{ &vop_getattr_desc, (VOPFUNC)mfs_getattr },		/* getattr */
	{ &vop_setattr_desc, (VOPFUNC)mfs_setattr },		/* setattr */
	{ &vop_read_desc, (VOPFUNC)mfs_read },			/* read */
	{ &vop_write_desc, (VOPFUNC)mfs_write },		/* write */
	{ &vop_ioctl_desc, (VOPFUNC)mfs_ioctl },		/* ioctl */
	{ &vop_select_desc, (VOPFUNC)mfs_select },		/* select */
	{ &vop_mmap_desc, (VOPFUNC)mfs_mmap },			/* mmap */
	{ &vop_fsync_desc, (VOPFUNC)spec_fsync },		/* fsync */
	{ &vop_seek_desc, (VOPFUNC)mfs_seek },			/* seek */
	{ &vop_remove_desc, (VOPFUNC)mfs_remove },		/* remove */
	{ &vop_link_desc, (VOPFUNC)mfs_link },			/* link */
	{ &vop_rename_desc, (VOPFUNC)mfs_rename },		/* rename */
	{ &vop_mkdir_desc, (VOPFUNC)mfs_mkdir },		/* mkdir */
	{ &vop_rmdir_desc, (VOPFUNC)mfs_rmdir },		/* rmdir */
	{ &vop_symlink_desc, (VOPFUNC)mfs_symlink },		/* symlink */
	{ &vop_readdir_desc, (VOPFUNC)mfs_readdir },		/* readdir */
	{ &vop_readlink_desc, (VOPFUNC)mfs_readlink },		/* readlink */
	{ &vop_abortop_desc, (VOPFUNC)mfs_abortop },		/* abortop */
	{ &vop_inactive_desc, (VOPFUNC)mfs_inactive },		/* inactive */
	{ &vop_reclaim_desc, (VOPFUNC)mfs_reclaim },		/* reclaim */
	{ &vop_lock_desc, (VOPFUNC)mfs_lock },			/* lock */
	{ &vop_unlock_desc, (VOPFUNC)mfs_unlock },		/* unlock */
	{ &vop_bmap_desc, (VOPFUNC)mfs_bmap },			/* bmap */
	{ &vop_strategy_desc, (VOPFUNC)mfs_strategy },		/* strategy */
	{ &vop_print_desc, (VOPFUNC)mfs_print },		/* print */
	{ &vop_islocked_desc, (VOPFUNC)mfs_islocked },		/* islocked */
	{ &vop_pathconf_desc, (VOPFUNC)mfs_pathconf },		/* pathconf */
	{ &vop_advlock_desc, (VOPFUNC)mfs_advlock },		/* advlock */
	{ &vop_blkatoff_desc, (VOPFUNC)mfs_blkatoff },		/* blkatoff */
	{ &vop_valloc_desc, (VOPFUNC)mfs_valloc },		/* valloc */
	{ &vop_vfree_desc, (VOPFUNC)mfs_vfree },		/* vfree */
	{ &vop_truncate_desc, (VOPFUNC)mfs_truncate },		/* truncate */
	{ &vop_update_desc, (VOPFUNC)mfs_update },		/* update */
	{ &vop_bwrite_desc, (VOPFUNC)mfs_bwrite },		/* bwrite */
	{ &vop_pgrd_desc, (VOPFUNC)mfs_pgrg },			/* pager read */
	{ &vop_pgwr_desc, (VOPFUNC)mfs_pgwr },			/* pager write */
	{ (struct vnodeop_desc*)NULL, (int(*)())NULL }
};
struct vnodeopv_desc mfs_vnodeop_opv_desc =
	{ &mfs_vnodeop_p, mfs_vnodeop_entries };

/*
 * Vnode Operations.
 *
 * Open called to allow memory filesystem to initialize and
 * validate before actual IO. Record our process identifier
 * so we can tell when we are doing I/O to ourself.
 */
/* ARGSUSED */
int
mfs_open(ap)
	struct vop_open_args /* {
		struct vnode *a_vp;
		int  a_mode;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{

	if (ap->a_vp->v_type != VBLK) {
		panic("mfs_ioctl not VBLK");
		/* NOTREACHED */
	}
	return (0);
}

/*
 * Ioctl operation.
 */
/* ARGSUSED */
int
mfs_ioctl(ap)
	struct vop_ioctl_args /* {
		struct vnode *a_vp;
		u_long a_command;
		caddr_t  a_data;
		int  a_fflag;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{

	return (ENOTTY);
}

/*
 * Pass I/O requests to the memory filesystem process.
 */
int
mfs_strategy(ap)
	struct vop_strategy_args /* {
		struct buf *a_bp;
	} */ *ap;
{
	register struct buf *bp = ap->a_bp;
	register struct mfsnode *mfsp;
	struct vnode *vp;
	struct proc *p = curproc;		/* XXX */

	if (!vfinddev(bp->b_dev, VBLK, &vp) || vp->v_usecount == 0)
		panic("mfs_strategy: bad dev");
	mfsp = VTOMFS(vp);
	/* check for mini-root access */
	if (mfsp->mfs_pid == 0) {
		caddr_t base;

		base = mfsp->mfs_baseoff + (bp->b_blkno << DEV_BSHIFT);
		if (bp->b_flags & B_READ)
			bcopy(base, bp->b_data, bp->b_bcount);
		else
			bcopy(bp->b_data, base, bp->b_bcount);
		biodone(bp);
	} else if (mfsp->mfs_pid == p->p_pid) {
		mfs_doio(bp, mfsp->mfs_baseoff);
	} else {
		bp->b_actf = mfsp->mfs_buflist;
		mfsp->mfs_buflist = bp;
		wakeup((caddr_t)vp);
	}
	return (0);
}

/*
 * Memory file system I/O.
 *
 * Trivial on the HP since buffer has already been mapping into KVA space.
 */
void
mfs_doio(bp, base)
	register struct buf *bp;
	caddr_t base;
{

	base += (bp->b_blkno << DEV_BSHIFT);
	if (bp->b_flags & B_READ)
		bp->b_error = copyin(base, bp->b_data, bp->b_bcount);
	else
		bp->b_error = copyout(bp->b_data, base, bp->b_bcount);
	if (bp->b_error)
		bp->b_flags |= B_ERROR;
	biodone(bp);
}

/*
 * This is a noop, simply returning what one has been given.
 */
int
mfs_bmap(ap)
	struct vop_bmap_args /* {
		struct vnode *a_vp;
		daddr_t  a_bn;
		struct vnode **a_vpp;
		daddr_t *a_bnp;
		int *a_runp;
	} */ *ap;
{

	if (ap->a_vpp != NULL)
		*ap->a_vpp = ap->a_vp;
	if (ap->a_bnp != NULL)
		*ap->a_bnp = ap->a_bn;
	return (0);
}

/*
 * Memory filesystem close routine
 */
/* ARGSUSED */
int
mfs_close(ap)
	struct vop_close_args /* {
		struct vnode *a_vp;
		int  a_fflag;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	register struct mfsnode *mfsp = VTOMFS(vp);
	register struct buf *bp;
	int error;

	/*
	 * Finish any pending I/O requests.
	 */
	while (bp = mfsp->mfs_buflist) {
		mfsp->mfs_buflist = bp->b_actf;
		mfs_doio(bp, mfsp->mfs_baseoff);
		wakeup((caddr_t)bp);
	}
	/*
	 * On last close of a memory filesystem
	 * we must invalidate any in core blocks, so that
	 * we can, free up its vnode.
	 */
	if (error = vinvalbuf(vp, 1, ap->a_cred, ap->a_p, 0, 0))
		return (error);
	/*
	 * There should be no way to have any more uses of this
	 * vnode, so if we find any other uses, it is a panic.
	 */
	if (vp->v_usecount > 1)
		printf("mfs_close: ref count %d > 1\n", vp->v_usecount);
	if (vp->v_usecount > 1 || mfsp->mfs_buflist)
		panic("mfs_close");
	/*
	 * Send a request to the filesystem server to exit.
	 */
	mfsp->mfs_buflist = (struct buf *)(-1);
	wakeup((caddr_t)vp);
	return (0);
}

/*
 * Memory filesystem inactive routine
 */
/* ARGSUSED */
int
mfs_inactive(ap)
	struct vop_inactive_args /* {
		struct vnode *a_vp;
	} */ *ap;
{
	register struct mfsnode *mfsp = VTOMFS(ap->a_vp);

	if (mfsp->mfs_buflist && mfsp->mfs_buflist != (struct buf *)(-1))
		panic("mfs_inactive: not inactive (mfs_buflist %x)",
			mfsp->mfs_buflist);
	return (0);
}

/*
 * Reclaim a memory filesystem devvp so that it can be reused.
 */
int
mfs_reclaim(ap)
	struct vop_reclaim_args /* {
		struct vnode *a_vp;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;

	FREE(vp->v_data, M_MFSNODE);
	vp->v_data = NULL;
	return (0);
}

/*
 * Print out the contents of an mfsnode.
 */
int
mfs_print(ap)
	struct vop_print_args /* {
		struct vnode *a_vp;
	} */ *ap;
{
	register struct mfsnode *mfsp = VTOMFS(ap->a_vp);

	printf("tag VT_MFS, pid %d, base %d, size %d\n", mfsp->mfs_pid,
		mfsp->mfs_baseoff, mfsp->mfs_size);
	return (0);
}

/*
 * Block device bad operation
 */
int
mfs_badop()
{

	panic("mfs_badop called\n");
	/* NOTREACHED */
}

/*
 * Memory based filesystem initialization.
 */
mfs_init()
{

}
