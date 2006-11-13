/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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
#include <sys/vnode_internal.h>
#include <sys/errno.h>
#include <sys/namei.h>
#include <sys/buf.h>
#include <vfs/vfs_support.h>

/*
 * Prototypes for dead operations on vnodes.
 */
int	dead_badop(void *);
int	dead_ebadf(void *);
int	dead_lookup(struct vnop_lookup_args *);
#define dead_create (int (*)(struct  vnop_create_args *))dead_badop
#define dead_mknod (int (*)(struct  vnop_mknod_args *))dead_badop
int	dead_open(struct vnop_open_args *);
#define dead_close (int (*)(struct  vnop_close_args *))nullop
#define dead_access (int (*)(struct  vnop_access_args *))dead_ebadf
#define dead_getattr (int (*)(struct  vnop_getattr_args *))dead_ebadf
#define dead_setattr (int (*)(struct  vnop_setattr_args *))dead_ebadf
int	dead_read(struct vnop_read_args *);
int	dead_write(struct vnop_write_args *);
int	dead_ioctl(struct vnop_ioctl_args *);
int	dead_select(struct vnop_select_args *);
#define dead_mmap (int (*)(struct  vnop_mmap_args *))dead_badop
#define dead_fsync (int (*)(struct  vnop_fsync_args *))nullop
#define dead_remove (int (*)(struct  vnop_remove_args ))dead_badop
#define dead_link (int (*)(struct  vnop_link_args *))dead_badop
#define dead_rename (int (*)(struct  vnop_rename_args *))dead_badop
#define dead_mkdir (int (*)(struct  vnop_mkdir_args *))dead_badop
#define dead_rmdir (int (*)(struct  vnop_rmdir_args *))dead_badop
#define dead_symlink (int (*)(struct  vnop_symlink_args *))dead_badop
#define dead_readdir (int (*)(struct  vnop_readdir_args *))dead_ebadf
#define dead_readlink (int (*)(struct  vnop_readlink_args *))dead_ebadf
#define dead_inactive (int (*)(struct  vnop_inactive_args *))nullop
#define dead_reclaim (int (*)(struct  vnop_reclaim_args *))nullop
int	dead_strategy(struct vnop_strategy_args *);
#define dead_pathconf (int (*)(struct  vnop_pathconf_args *))dead_ebadf
#define dead_advlock (int (*)(struct  vnop_advlock_args *))dead_ebadf
#define dead_bwrite (int (*)(struct  vnop_bwrite_args *))nullop
int	dead_pagein(struct vnop_pagein_args *);
int	dead_pageout(struct vnop_pageout_args *);
int dead_blktooff(struct vnop_blktooff_args *);
int dead_offtoblk(struct vnop_offtoblk_args *);
int dead_blockmap(struct vnop_blockmap_args *);

#define VOPFUNC int (*)(void *)
int (**dead_vnodeop_p)(void *);
struct vnodeopv_entry_desc dead_vnodeop_entries[] = {
	{ &vnop_default_desc, (VOPFUNC)vn_default_error },
	{ &vnop_lookup_desc, (VOPFUNC)dead_lookup },	/* lookup */
	{ &vnop_create_desc, (VOPFUNC)dead_create },	/* create */
	{ &vnop_open_desc, (VOPFUNC)dead_open },		/* open */
	{ &vnop_mknod_desc, (VOPFUNC)dead_mknod },		/* mknod */
	{ &vnop_close_desc, (VOPFUNC)dead_close },	/* close */
	{ &vnop_access_desc, (VOPFUNC)dead_access },	/* access */
	{ &vnop_getattr_desc, (VOPFUNC)dead_getattr },	/* getattr */
	{ &vnop_setattr_desc, (VOPFUNC)dead_setattr },	/* setattr */
	{ &vnop_read_desc, (VOPFUNC)dead_read },		/* read */
	{ &vnop_write_desc, (VOPFUNC)dead_write },	/* write */
	{ &vnop_ioctl_desc, (VOPFUNC)dead_ioctl },	/* ioctl */
	{ &vnop_select_desc, (VOPFUNC)dead_select },	/* select */
	{ &vnop_mmap_desc, (VOPFUNC)dead_mmap },		/* mmap */
	{ &vnop_fsync_desc, (VOPFUNC)dead_fsync },	/* fsync */
	{ &vnop_remove_desc, (VOPFUNC)dead_remove },	/* remove */
	{ &vnop_link_desc, (VOPFUNC)dead_link },		/* link */
	{ &vnop_rename_desc, (VOPFUNC)dead_rename },	/* rename */
	{ &vnop_mkdir_desc, (VOPFUNC)dead_mkdir },	/* mkdir */
	{ &vnop_rmdir_desc, (VOPFUNC)dead_rmdir },	/* rmdir */
	{ &vnop_symlink_desc, (VOPFUNC)dead_symlink },	/* symlink */
	{ &vnop_readdir_desc, (VOPFUNC)dead_readdir },	/* readdir */
	{ &vnop_readlink_desc, (VOPFUNC)dead_readlink },	/* readlink */
	{ &vnop_inactive_desc, (VOPFUNC)dead_inactive },	/* inactive */
	{ &vnop_reclaim_desc, (VOPFUNC)dead_reclaim },	/* reclaim */
	{ &vnop_strategy_desc, (VOPFUNC)dead_strategy },	/* strategy */
	{ &vnop_pathconf_desc, (VOPFUNC)dead_pathconf },	/* pathconf */
	{ &vnop_advlock_desc, (VOPFUNC)dead_advlock },	/* advlock */
	{ &vnop_bwrite_desc, (VOPFUNC)dead_bwrite },	/* bwrite */
	{ &vnop_pagein_desc, (VOPFUNC)err_pagein },	/* Pagein */
	{ &vnop_pageout_desc, (VOPFUNC)err_pageout },	/* Pageout */
        { &vnop_copyfile_desc, (VOPFUNC)err_copyfile },	/* Copyfile */
	{ &vnop_blktooff_desc, (VOPFUNC)dead_blktooff },	/* blktooff */
	{ &vnop_offtoblk_desc, (VOPFUNC)dead_offtoblk },	/* offtoblk */
  	{ &vnop_blockmap_desc, (VOPFUNC)dead_blockmap },		/* blockmap */
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
	struct vnop_lookup_args /* {
		struct vnode * a_dvp;
		struct vnode ** a_vpp;
		struct componentname * a_cnp;
		vfs_context_t a_context;
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
	struct vnop_open_args /* {
		struct vnode *a_vp;
		int  a_mode;
		vfs_context_t a_context;
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
	struct vnop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		vfs_context_t a_context;
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
	struct vnop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		vfs_context_t a_context;
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
	struct vnop_ioctl_args /* {
		struct vnode *a_vp;
		u_long a_command;
		caddr_t  a_data;
		int  a_fflag;
		vfs_context_t a_context;
	} */ *ap;
{

	if (!chkvnlock(ap->a_vp))
		return (EBADF);
	return (VCALL(ap->a_vp, VOFFSET(vnop_ioctl), ap));
}

/* ARGSUSED */
int
dead_select(ap)
	struct vnop_select_args /* {
		struct vnode *a_vp;
		int  a_which;
		int  a_fflags;
		kauth_cred_t a_cred;
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
	struct vnop_strategy_args /* {
		struct buf *a_bp;
	} */ *ap;
{

	if (buf_vnode(ap->a_bp) == NULL || !chkvnlock(buf_vnode(ap->a_bp))) {
	        buf_seterror(ap->a_bp, EIO);
		buf_biodone(ap->a_bp);
		return (EIO);
	}
	return (VNOP_STRATEGY(ap->a_bp));
}

/*
 * Wait until the vnode has finished changing state.
 */
int
dead_blockmap(ap)
	struct vnop_blockmap_args /* {
		struct vnode *a_vp;
		off_t a_foffset;
		size_t a_size;
		daddr64_t *a_bpn;
		size_t *a_run;
		void *a_poff;
		int flags;
		vfs_context_t a_context;
	} */ *ap;
{

	if (!chkvnlock(ap->a_vp))
		return (EIO);
	return (VNOP_BLOCKMAP(ap->a_vp, ap->a_foffset, ap->a_size, ap->a_bpn,
	                 ap->a_run, ap->a_poff, ap->a_flags, ap->a_context));
}

/*
 * Empty vnode failed operation
 */
/* ARGSUSED */
int
dead_ebadf(void *dummy)
{

	return (EBADF);
}

/*
 * Empty vnode bad operation
 */
/* ARGSUSED */
int
dead_badop(void *dummy)
{

	panic("dead_badop called");
	/* NOTREACHED */
}

/*
 * Empty vnode null operation
 */
/* ARGSUSED */
int
dead_nullop(void *dummy)
{

	return (0);
}

/*
 * We have to wait during times when the vnode is
 * in a state of change.
 */
int
chkvnlock(__unused vnode_t vp)
{
	return (0);
}


/* Blktooff */
int
dead_blktooff(ap)
	struct vnop_blktooff_args /* {
		struct vnode *a_vp;
		daddr64_t a_lblkno;
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
struct vnop_offtoblk_args /* {
	struct vnode *a_vp;
	off_t a_offset;    
	daddr64_t *a_lblkno;
	} */ *ap;
{
    if (!chkvnlock(ap->a_vp))
		return (EIO);

	*ap->a_lblkno = (daddr64_t)-1;	/* failure */
	return (0);
}
