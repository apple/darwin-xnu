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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
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
 *	@(#)dead_vnops.c	8.3 (Berkeley) 5/14/95
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/errno.h>
#include <sys/namei.h>
#include <sys/buf.h>
#include <vfs/vfs_support.h>

/*
 * Prototypes for dead operations on vnodes.
 */
int	dead_badop(),
	dead_ebadf();
int	dead_lookup __P((struct vop_lookup_args *));
#define dead_create ((int (*) __P((struct  vop_create_args *)))dead_badop)
#define dead_mknod ((int (*) __P((struct  vop_mknod_args *)))dead_badop)
int	dead_open __P((struct vop_open_args *));
#define dead_close ((int (*) __P((struct  vop_close_args *)))nullop)
#define dead_access ((int (*) __P((struct  vop_access_args *)))dead_ebadf)
#define dead_getattr ((int (*) __P((struct  vop_getattr_args *)))dead_ebadf)
#define dead_setattr ((int (*) __P((struct  vop_setattr_args *)))dead_ebadf)
int	dead_read __P((struct vop_read_args *));
int	dead_write __P((struct vop_write_args *));
int	dead_ioctl __P((struct vop_ioctl_args *));
int	dead_select __P((struct vop_select_args *));
#define dead_mmap ((int (*) __P((struct  vop_mmap_args *)))dead_badop)
#define dead_fsync ((int (*) __P((struct  vop_fsync_args *)))nullop)
#define dead_seek ((int (*) __P((struct  vop_seek_args *)))nullop)
#define dead_remove ((int (*) __P((struct  vop_remove_args *)))dead_badop)
#define dead_link ((int (*) __P((struct  vop_link_args *)))dead_badop)
#define dead_rename ((int (*) __P((struct  vop_rename_args *)))dead_badop)
#define dead_mkdir ((int (*) __P((struct  vop_mkdir_args *)))dead_badop)
#define dead_rmdir ((int (*) __P((struct  vop_rmdir_args *)))dead_badop)
#define dead_symlink ((int (*) __P((struct  vop_symlink_args *)))dead_badop)
#define dead_readdir ((int (*) __P((struct  vop_readdir_args *)))dead_ebadf)
#define dead_readlink ((int (*) __P((struct  vop_readlink_args *)))dead_ebadf)
#define dead_abortop ((int (*) __P((struct  vop_abortop_args *)))dead_badop)
#define dead_inactive ((int (*) __P((struct  vop_inactive_args *)))nullop)
#define dead_reclaim ((int (*) __P((struct  vop_reclaim_args *)))nullop)
int	dead_lock __P((struct vop_lock_args *));
#define dead_unlock ((int (*) __P((struct  vop_unlock_args *)))nullop)
int	dead_bmap __P((struct vop_bmap_args *));
int	dead_strategy __P((struct vop_strategy_args *));
int	dead_print __P((struct vop_print_args *));
#define dead_islocked ((int (*) __P((struct  vop_islocked_args *)))nullop)
#define dead_pathconf ((int (*) __P((struct  vop_pathconf_args *)))dead_ebadf)
#define dead_advlock ((int (*) __P((struct  vop_advlock_args *)))dead_ebadf)
#define dead_blkatoff ((int (*) __P((struct  vop_blkatoff_args *)))dead_badop)
#define dead_valloc ((int (*) __P((struct  vop_valloc_args *)))dead_badop)
#define dead_vfree ((int (*) __P((struct  vop_vfree_args *)))dead_badop)
#define dead_truncate ((int (*) __P((struct  vop_truncate_args *)))nullop)
#define dead_update ((int (*) __P((struct  vop_update_args *)))nullop)
#define dead_bwrite ((int (*) __P((struct  vop_bwrite_args *)))nullop)
int	dead_pagein __P((struct vop_pagein_args *));
int	dead_pageout __P((struct vop_pageout_args *));
int dead_blktooff __P((struct vop_blktooff_args *));
int dead_offtoblk __P((struct vop_offtoblk_args *));
int dead_cmap __P((struct vop_cmap_args *));

#define VOPFUNC int (*)(void *)
int (**dead_vnodeop_p)(void *);
struct vnodeopv_entry_desc dead_vnodeop_entries[] = {
	{ &vop_default_desc, (VOPFUNC)vn_default_error },
	{ &vop_lookup_desc, (VOPFUNC)dead_lookup },	/* lookup */
	{ &vop_create_desc, (VOPFUNC)dead_create },	/* create */
	{ &vop_mknod_desc, (VOPFUNC)dead_mknod },	/* mknod */
	{ &vop_open_desc, (VOPFUNC)dead_open },		/* open */
	{ &vop_close_desc, (VOPFUNC)dead_close },	/* close */
	{ &vop_access_desc, (VOPFUNC)dead_access },	/* access */
	{ &vop_getattr_desc, (VOPFUNC)dead_getattr },	/* getattr */
	{ &vop_setattr_desc, (VOPFUNC)dead_setattr },	/* setattr */
	{ &vop_read_desc, (VOPFUNC)dead_read },		/* read */
	{ &vop_write_desc, (VOPFUNC)dead_write },	/* write */
	{ &vop_ioctl_desc, (VOPFUNC)dead_ioctl },	/* ioctl */
	{ &vop_select_desc, (VOPFUNC)dead_select },	/* select */
	{ &vop_mmap_desc, (VOPFUNC)dead_mmap },		/* mmap */
	{ &vop_fsync_desc, (VOPFUNC)dead_fsync },	/* fsync */
	{ &vop_seek_desc, (VOPFUNC)dead_seek },		/* seek */
	{ &vop_remove_desc, (VOPFUNC)dead_remove },	/* remove */
	{ &vop_link_desc, (VOPFUNC)dead_link },		/* link */
	{ &vop_rename_desc, (VOPFUNC)dead_rename },	/* rename */
	{ &vop_mkdir_desc, (VOPFUNC)dead_mkdir },	/* mkdir */
	{ &vop_rmdir_desc, (VOPFUNC)dead_rmdir },	/* rmdir */
	{ &vop_symlink_desc, (VOPFUNC)dead_symlink },	/* symlink */
	{ &vop_readdir_desc, (VOPFUNC)dead_readdir },	/* readdir */
	{ &vop_readlink_desc, (VOPFUNC)dead_readlink },	/* readlink */
	{ &vop_abortop_desc, (VOPFUNC)dead_abortop },	/* abortop */
	{ &vop_inactive_desc, (VOPFUNC)dead_inactive },	/* inactive */
	{ &vop_reclaim_desc, (VOPFUNC)dead_reclaim },	/* reclaim */
	{ &vop_lock_desc, (VOPFUNC)dead_lock },		/* lock */
	{ &vop_unlock_desc, (VOPFUNC)dead_unlock },	/* unlock */
	{ &vop_bmap_desc, (VOPFUNC)dead_bmap },		/* bmap */
	{ &vop_strategy_desc, (VOPFUNC)dead_strategy },	/* strategy */
	{ &vop_print_desc, (VOPFUNC)dead_print },	/* print */
	{ &vop_islocked_desc, (VOPFUNC)dead_islocked },	/* islocked */
	{ &vop_pathconf_desc, (VOPFUNC)dead_pathconf },	/* pathconf */
	{ &vop_advlock_desc, (VOPFUNC)dead_advlock },	/* advlock */
	{ &vop_blkatoff_desc, (VOPFUNC)dead_blkatoff },	/* blkatoff */
	{ &vop_valloc_desc, (VOPFUNC)dead_valloc },	/* valloc */
	{ &vop_vfree_desc, (VOPFUNC)dead_vfree },	/* vfree */
	{ &vop_truncate_desc, (VOPFUNC)dead_truncate },	/* truncate */
	{ &vop_update_desc, (VOPFUNC)dead_update },	/* update */
	{ &vop_bwrite_desc, (VOPFUNC)dead_bwrite },	/* bwrite */
	{ &vop_pagein_desc, (VOPFUNC)err_pagein },	/* Pagein */
	{ &vop_pageout_desc, (VOPFUNC)err_pageout },	/* Pageout */
        { &vop_copyfile_desc, (VOPFUNC)err_copyfile },	/* Copyfile */
	{ &vop_blktooff_desc, (VOPFUNC)dead_blktooff },	/* blktooff */
	{ &vop_offtoblk_desc, (VOPFUNC)dead_offtoblk },	/* offtoblk */
  	{ &vop_cmap_desc, (VOPFUNC)dead_cmap },		/* cmap */
	{ (struct vnodeop_desc*)NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc dead_vnodeop_opv_desc =
	{ &dead_vnodeop_p, dead_vnodeop_entries };

/*
 * Trivial lookup routine that always fails.
 */
/* ARGSUSED */
int
dead_lookup(ap)
	struct vop_lookup_args /* {
		struct vnode * a_dvp;
		struct vnode ** a_vpp;
		struct componentname * a_cnp;
	} */ *ap;
{

	*ap->a_vpp = NULL;
	return (ENOTDIR);
}

/*
 * Open always fails as if device did not exist.
 */
/* ARGSUSED */
int
dead_open(ap)
	struct vop_open_args /* {
		struct vnode *a_vp;
		int  a_mode;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{

	return (ENXIO);
}

/*
 * Vnode op for read
 */
/* ARGSUSED */
int
dead_read(ap)
	struct vop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{

	if (chkvnlock(ap->a_vp))
		panic("dead_read: lock");
	/*
	 * Return EOF for character devices, EIO for others
	 */
	if (ap->a_vp->v_type != VCHR)
		return (EIO);
	return (0);
}

/*
 * Vnode op for write
 */
/* ARGSUSED */
int
dead_write(ap)
	struct vop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{

	if (chkvnlock(ap->a_vp))
		panic("dead_write: lock");
	return (EIO);
}

/*
 * Device ioctl operation.
 */
/* ARGSUSED */
int
dead_ioctl(ap)
	struct vop_ioctl_args /* {
		struct vnode *a_vp;
		u_long a_command;
		caddr_t  a_data;
		int  a_fflag;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{

	if (!chkvnlock(ap->a_vp))
		return (EBADF);
	return (VCALL(ap->a_vp, VOFFSET(vop_ioctl), ap));
}

/* ARGSUSED */
int
dead_select(ap)
	struct vop_select_args /* {
		struct vnode *a_vp;
		int  a_which;
		int  a_fflags;
		struct ucred *a_cred;
		void *a_wql;
		struct proc *a_p;
	} */ *ap;
{

	/*
	 * Let the user find out that the descriptor is gone.
	 */
	return (1);
}

/*
 * Just call the device strategy routine
 */
int
dead_strategy(ap)
	struct vop_strategy_args /* {
		struct buf *a_bp;
	} */ *ap;
{

	if (ap->a_bp->b_vp == NULL || !chkvnlock(ap->a_bp->b_vp)) {
		ap->a_bp->b_flags |= B_ERROR;
		biodone(ap->a_bp);
		return (EIO);
	}
	return (VOP_STRATEGY(ap->a_bp));
}

/*
 * Wait until the vnode has finished changing state.
 */
int
dead_lock(ap)
	struct vop_lock_args /* {
		struct vnode *a_vp;
	} */ *ap;
{

	struct vnode *vp = ap->a_vp;

	/*
	 * Since we are not using the lock manager, we must clear
	 * the interlock here.
	 */
	if (ap->a_flags & LK_INTERLOCK) {
		simple_unlock(&vp->v_interlock);
		ap->a_flags &= ~LK_INTERLOCK;
	}
	if (!chkvnlock(ap->a_vp))
		return (0);
	return (VCALL(ap->a_vp, VOFFSET(vop_lock), ap));
}

/*
 * Wait until the vnode has finished changing state.
 */
int
dead_bmap(ap)
	struct vop_bmap_args /* {
		struct vnode *a_vp;
		daddr_t  a_bn;
		struct vnode **a_vpp;
		daddr_t *a_bnp;
		int *a_runp;
	} */ *ap;
{

	if (!chkvnlock(ap->a_vp))
		return (EIO);
	return (VOP_BMAP(ap->a_vp, ap->a_bn, ap->a_vpp, ap->a_bnp, ap->a_runp));
}

/*
 * Wait until the vnode has finished changing state.
 */
int
dead_cmap(ap)
	struct vop_cmap_args /* {
		struct vnode *a_vp;
		off_t a_foffset;
		size_t a_size;
		daddr_t *a_bpn;
		size_t *a_run;
		void *a_poff;
	} */ *ap;
{

	if (!chkvnlock(ap->a_vp))
		return (EIO);
	return (VOP_CMAP(ap->a_vp, ap->a_foffset, ap->a_size, ap->a_bpn, ap->a_run, ap->a_poff));
}

/*
 * Print out the contents of a dead vnode.
 */
/* ARGSUSED */
int
dead_print(ap)
	struct vop_print_args /* {
		struct vnode *a_vp;
	} */ *ap;
{

	printf("tag VT_NON, dead vnode\n");
}

/*
 * Empty vnode failed operation
 */
int
dead_ebadf()
{

	return (EBADF);
}

/*
 * Empty vnode bad operation
 */
int
dead_badop()
{

	panic("dead_badop called");
	/* NOTREACHED */
}

/*
 * Empty vnode null operation
 */
int
dead_nullop()
{

	return (0);
}

/*
 * We have to wait during times when the vnode is
 * in a state of change.
 */
int
chkvnlock(vp)
	register struct vnode *vp;
{
	int locked = 0;

	while (vp->v_flag & VXLOCK) {
		vp->v_flag |= VXWANT;
		sleep((caddr_t)vp, PINOD);
		locked = 1;
	}
	return (locked);
}


/* Blktooff */
int
dead_blktooff(ap)
	struct vop_blktooff_args /* {
		struct vnode *a_vp;
		daddr_t a_lblkno;
		off_t *a_offset;    
	} */ *ap;
{
    if (!chkvnlock(ap->a_vp))
		return (EIO);

	*ap->a_offset = (off_t)-1;	/* failure */
	return (0);
}
/* Blktooff */
int
dead_offtoblk(ap)
struct vop_offtoblk_args /* {
	struct vnode *a_vp;
	off_t a_offset;    
	daddr_t *a_lblkno;
	} */ *ap;
{
    if (!chkvnlock(ap->a_vp))
		return (EIO);

	*ap->a_lblkno = (daddr_t)-1;	/* failure */
	return (0);
}
