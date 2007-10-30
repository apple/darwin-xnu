/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1989, 1993
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
 *	@(#)ffs_vnops.c	8.15 (Berkeley) 5/14/95
 */

#include <rev_endian_fs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/resourcevar.h>
#include <sys/kernel.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/proc.h>
#include <sys/conf.h>
#include <sys/mount_internal.h>
#include <sys/vnode_internal.h>
#include <sys/malloc.h>
#include <sys/ubc.h>
#include <sys/quota.h>

#include <sys/vm.h>
#include <vfs/vfs_support.h>

#include <miscfs/specfs/specdev.h>
#include <miscfs/fifofs/fifo.h>

#include <ufs/ufs/quota.h>
#include <ufs/ufs/inode.h>
#include <ufs/ufs/dir.h>
#include <ufs/ufs/ufsmount.h>
#include <ufs/ufs/ufs_extern.h>

#include <ufs/ffs/fs.h>
#include <ufs/ffs/ffs_extern.h>
#if REV_ENDIAN_FS
#include <ufs/ufs/ufs_byte_order.h>
#endif /* REV_ENDIAN_FS */

#define VOPFUNC int (*)(void *)

/* Global vfs data structures for ufs. */
int (**ffs_vnodeop_p)(void *);
struct vnodeopv_entry_desc ffs_vnodeop_entries[] = {
	{ &vnop_default_desc, (VOPFUNC)vn_default_error },
	{ &vnop_lookup_desc, (VOPFUNC)ufs_lookup },		/* lookup */
	{ &vnop_create_desc, (VOPFUNC)ufs_create },		/* create */
	{ &vnop_whiteout_desc, (VOPFUNC)ufs_whiteout },		/* whiteout */
	{ &vnop_mknod_desc, (VOPFUNC)ufs_mknod },		/* mknod */
	{ &vnop_open_desc, (VOPFUNC)ufs_open },			/* open */
	{ &vnop_close_desc, (VOPFUNC)ufs_close },		/* close */
	{ &vnop_getattr_desc, (VOPFUNC)ufs_getattr },		/* getattr */
	{ &vnop_setattr_desc, (VOPFUNC)ufs_setattr },		/* setattr */
	{ &vnop_read_desc, (VOPFUNC)ffs_read },			/* read */
	{ &vnop_write_desc, (VOPFUNC)ffs_write },		/* write */
	{ &vnop_ioctl_desc, (VOPFUNC)ufs_ioctl },		/* ioctl */
	{ &vnop_select_desc, (VOPFUNC)ufs_select },		/* select */
	{ &vnop_revoke_desc, (VOPFUNC)ufs_revoke },		/* revoke */
	{ &vnop_mmap_desc, (VOPFUNC)ufs_mmap },			/* mmap */
	{ &vnop_fsync_desc, (VOPFUNC)ffs_fsync },		/* fsync */
	{ &vnop_remove_desc, (VOPFUNC)ufs_remove },		/* remove */
	{ &vnop_link_desc, (VOPFUNC)ufs_link },			/* link */
	{ &vnop_rename_desc, (VOPFUNC)ufs_rename },		/* rename */
	{ &vnop_mkdir_desc, (VOPFUNC)ufs_mkdir },		/* mkdir */
	{ &vnop_rmdir_desc, (VOPFUNC)ufs_rmdir },		/* rmdir */
	{ &vnop_symlink_desc, (VOPFUNC)ufs_symlink },		/* symlink */
	{ &vnop_readdir_desc, (VOPFUNC)ufs_readdir },		/* readdir */
	{ &vnop_readlink_desc, (VOPFUNC)ufs_readlink },		/* readlink */
	{ &vnop_inactive_desc, (VOPFUNC)ufs_inactive },		/* inactive */
	{ &vnop_reclaim_desc, (VOPFUNC)ffs_reclaim },		/* reclaim */
	{ &vnop_strategy_desc, (VOPFUNC)ufs_strategy },		/* strategy */
	{ &vnop_pathconf_desc, (VOPFUNC)ufs_pathconf },		/* pathconf */
	{ &vnop_advlock_desc, (VOPFUNC)err_advlock },		/* advlock */
	{ &vnop_bwrite_desc, (VOPFUNC)vn_bwrite },
	{ &vnop_pagein_desc, (VOPFUNC)ffs_pagein },		/* Pagein */
	{ &vnop_pageout_desc, (VOPFUNC)ffs_pageout },		/* Pageout */
	{ &vnop_copyfile_desc, (VOPFUNC)err_copyfile },		/* Copy File */
	{ &vnop_blktooff_desc, (VOPFUNC)ffs_blktooff },		/* blktooff */
	{ &vnop_offtoblk_desc, (VOPFUNC)ffs_offtoblk },		/* offtoblk */
	{ &vnop_blockmap_desc, (VOPFUNC)ufs_blockmap },		/* blockmap */
	{ &vnop_kqfilt_add_desc, (VOPFUNC)ufs_kqfilt_add },  /* kqfilt_add */
	{ (struct vnodeop_desc*)NULL, (int(*)())NULL }
};
struct vnodeopv_desc ffs_vnodeop_opv_desc =
	{ &ffs_vnodeop_p, ffs_vnodeop_entries };

int (**ffs_specop_p)(void *);
struct vnodeopv_entry_desc ffs_specop_entries[] = {
	{ &vnop_default_desc, (VOPFUNC)vn_default_error },
	{ &vnop_lookup_desc, (VOPFUNC)spec_lookup },		/* lookup */
	{ &vnop_create_desc, (VOPFUNC)spec_create },		/* create */
	{ &vnop_mknod_desc, (VOPFUNC)spec_mknod },		/* mknod */
	{ &vnop_open_desc, (VOPFUNC)spec_open },			/* open */
	{ &vnop_close_desc, (VOPFUNC)ufsspec_close },		/* close */
	{ &vnop_getattr_desc, (VOPFUNC)ufs_getattr },		/* getattr */
	{ &vnop_setattr_desc, (VOPFUNC)ufs_setattr },		/* setattr */
	{ &vnop_read_desc, (VOPFUNC)ufsspec_read },		/* read */
	{ &vnop_write_desc, (VOPFUNC)ufsspec_write },		/* write */
	{ &vnop_ioctl_desc, (VOPFUNC)spec_ioctl },		/* ioctl */
	{ &vnop_select_desc, (VOPFUNC)spec_select },		/* select */
	{ &vnop_revoke_desc, (VOPFUNC)spec_revoke },		/* revoke */
	{ &vnop_mmap_desc, (VOPFUNC)spec_mmap },			/* mmap */
	{ &vnop_fsync_desc, (VOPFUNC)ffs_fsync },		/* fsync */
	{ &vnop_remove_desc, (VOPFUNC)spec_remove },		/* remove */
	{ &vnop_link_desc, (VOPFUNC)spec_link },			/* link */
	{ &vnop_rename_desc, (VOPFUNC)spec_rename },		/* rename */
	{ &vnop_mkdir_desc, (VOPFUNC)spec_mkdir },		/* mkdir */
	{ &vnop_rmdir_desc, (VOPFUNC)spec_rmdir },		/* rmdir */
	{ &vnop_symlink_desc, (VOPFUNC)spec_symlink },		/* symlink */
	{ &vnop_readdir_desc, (VOPFUNC)spec_readdir },		/* readdir */
	{ &vnop_readlink_desc, (VOPFUNC)spec_readlink },		/* readlink */
	{ &vnop_inactive_desc, (VOPFUNC)ufs_inactive },		/* inactive */
	{ &vnop_reclaim_desc, (VOPFUNC)ffs_reclaim },		/* reclaim */
	{ &vnop_strategy_desc, (VOPFUNC)spec_strategy },		/* strategy */
	{ &vnop_pathconf_desc, (VOPFUNC)spec_pathconf },		/* pathconf */
	{ &vnop_advlock_desc, (VOPFUNC)err_advlock },		/* advlock */
	{ &vnop_bwrite_desc, (VOPFUNC)vn_bwrite },
	{ &vnop_pagein_desc, (VOPFUNC)ffs_pagein },		/* Pagein */
	{ &vnop_pageout_desc, (VOPFUNC)ffs_pageout },		/* Pageout */
	{ &vnop_copyfile_desc, (VOPFUNC)err_copyfile },		/* Copy File */
	{ &vnop_blktooff_desc, (VOPFUNC)ffs_blktooff },		/* blktooff */
	{ &vnop_offtoblk_desc, (VOPFUNC)ffs_offtoblk },		/* offtoblk */
	{ &vnop_blockmap_desc, (VOPFUNC)spec_blockmap },	/* blockmap */
	{ (struct vnodeop_desc*)NULL, (int(*)())NULL }
};
struct vnodeopv_desc ffs_specop_opv_desc =
	{ &ffs_specop_p, ffs_specop_entries };

#if FIFO
int (**ffs_fifoop_p)(void *);
struct vnodeopv_entry_desc ffs_fifoop_entries[] = {
	{ &vnop_default_desc, (VOPFUNC)vn_default_error },
	{ &vnop_lookup_desc, (VOPFUNC)fifo_lookup },		/* lookup */
	{ &vnop_create_desc, (VOPFUNC)fifo_create },		/* create */
	{ &vnop_mknod_desc, (VOPFUNC)fifo_mknod },		/* mknod */
	{ &vnop_open_desc, (VOPFUNC)fifo_open },			/* open */
	{ &vnop_close_desc, (VOPFUNC)ufsfifo_close },		/* close */
	{ &vnop_getattr_desc, (VOPFUNC)ufs_getattr },		/* getattr */
	{ &vnop_setattr_desc, (VOPFUNC)ufs_setattr },		/* setattr */
	{ &vnop_read_desc, (VOPFUNC)ufsfifo_read },		/* read */
	{ &vnop_write_desc, (VOPFUNC)ufsfifo_write },		/* write */
	{ &vnop_ioctl_desc, (VOPFUNC)fifo_ioctl },		/* ioctl */
	{ &vnop_select_desc, (VOPFUNC)fifo_select },		/* select */
	{ &vnop_revoke_desc, (VOPFUNC)fifo_revoke },		/* revoke */
	{ &vnop_mmap_desc, (VOPFUNC)fifo_mmap },			/* mmap */
	{ &vnop_fsync_desc, (VOPFUNC)ffs_fsync },		/* fsync */
	{ &vnop_remove_desc, (VOPFUNC)fifo_remove },		/* remove */
	{ &vnop_link_desc, (VOPFUNC)fifo_link },			/* link */
	{ &vnop_rename_desc, (VOPFUNC)fifo_rename },		/* rename */
	{ &vnop_mkdir_desc, (VOPFUNC)fifo_mkdir },		/* mkdir */
	{ &vnop_rmdir_desc, (VOPFUNC)fifo_rmdir },		/* rmdir */
	{ &vnop_symlink_desc, (VOPFUNC)fifo_symlink },		/* symlink */
	{ &vnop_readdir_desc, (VOPFUNC)fifo_readdir },		/* readdir */
	{ &vnop_readlink_desc, (VOPFUNC)fifo_readlink },		/* readlink */
	{ &vnop_inactive_desc, (VOPFUNC)ufs_inactive },		/* inactive */
	{ &vnop_reclaim_desc, (VOPFUNC)ffs_reclaim },		/* reclaim */
	{ &vnop_strategy_desc, (VOPFUNC)fifo_strategy },		/* strategy */
	{ &vnop_pathconf_desc, (VOPFUNC)fifo_pathconf },		/* pathconf */
	{ &vnop_advlock_desc, (VOPFUNC)err_advlock },		/* advlock */
	{ &vnop_bwrite_desc, (VOPFUNC)vn_bwrite },
	{ &vnop_pagein_desc, (VOPFUNC)ffs_pagein },		/* Pagein */
	{ &vnop_pageout_desc, (VOPFUNC)ffs_pageout },		/* Pageout */
	{ &vnop_copyfile_desc, (VOPFUNC)err_copyfile },		/*  Copy File */
	{ &vnop_blktooff_desc, (VOPFUNC)ffs_blktooff },		/* blktooff */
	{ &vnop_offtoblk_desc, (VOPFUNC)ffs_offtoblk },		/* offtoblk */
	{ &vnop_blockmap_desc, (VOPFUNC)ufs_blockmap },		/* blockmap */
	{ &vnop_kqfilt_add_desc, (VOPFUNC)ufsfifo_kqfilt_add },  /* kqfilt_add */
	{ (struct vnodeop_desc*)NULL, (int(*)())NULL }
};
struct vnodeopv_desc ffs_fifoop_opv_desc =
	{ &ffs_fifoop_p, ffs_fifoop_entries };
#endif /* FIFO */

/*
 * Enabling cluster read/write operations.
 */
int doclusterread = 0;
int doclusterwrite = 0;

#include <ufs/ufs/ufs_readwrite.c>

/*
 * Synch an open file.
 */
/* ARGSUSED */
int
ffs_fsync(ap)
	struct vnop_fsync_args /* {
		struct vnode *a_vp;
		int a_waitfor;
		vfs_context_t a_context;
	} */ *ap;
{
        return(ffs_fsync_internal(ap->a_vp, ap->a_waitfor));
}


int
ffs_fsync_internal(vnode_t vp, int waitfor)
{
	struct timeval tv;
	int wait = (waitfor == MNT_WAIT);

	/*
	 * Write out any clusters.
	 */
	cluster_push(vp, 0);

	/*
	 * Flush all dirty buffers associated with a vnode.
	 */
	buf_flushdirtyblks(vp, wait, 0, "ffs_fsync");
	microtime(&tv);

	return (ffs_update(vp, &tv, &tv, wait));
}

/*
 * Reclaim an inode so that it can be used for other purposes.
 */
int
ffs_reclaim(ap)
	struct vnop_reclaim_args /* {
		struct vnode *a_vp;
		vfs_context_t a_context;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	int error;

	if ( (error = ufs_reclaim(vp, vfs_context_proc(ap->a_context))) )
		return (error);

	FREE_ZONE(vnode_fsnode(vp), sizeof (struct inode), M_FFSNODE);

	vnode_clearfsnode(vp);

	return (0);
}

/* Blktooff converts a logical block number to a file offset */
int
ffs_blktooff(ap)
	struct vnop_blktooff_args /* {
		struct vnode *a_vp;
		daddr64_t a_lblkno;
		off_t *a_offset;    
	} */ *ap;
{
	register struct inode *ip;
	register FS *fs;

	if (ap->a_vp == NULL)
		return (EINVAL);

	fs = VTOI(ap->a_vp)->I_FS;

	*ap->a_offset = (off_t)lblktosize(fs, ap->a_lblkno);

	return (0);
}

/* Blktooff converts a logical block number to a file offset */
int
ffs_offtoblk(ap)
	struct vnop_offtoblk_args /* {
		struct vnode *a_vp;
		off_t a_offset;    
		daddr64_t *a_lblkno;
	} */ *ap;
{
	register FS *fs;

	if (ap->a_vp == NULL)
		return (EINVAL);

	fs = VTOI(ap->a_vp)->I_FS;

	*ap->a_lblkno = (daddr64_t)lblkno(fs, ap->a_offset);

	return (0);
}
