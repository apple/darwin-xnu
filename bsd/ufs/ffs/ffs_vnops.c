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
#include <sys/buf.h>
#include <sys/proc.h>
#include <sys/conf.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/ubc.h>
#include <sys/quota.h>

#include <sys/vm.h>
#include <vfs/vfs_support.h>

#include <miscfs/specfs/specdev.h>
#include <miscfs/fifofs/fifo.h>

#include <ufs/ufs/lockf.h>
#include <ufs/ufs/quota.h>
#include <ufs/ufs/inode.h>
#include <ufs/ufs/dir.h>
#include <ufs/ufs/ufsmount.h>
#include <ufs/ufs/ufs_extern.h>

#include <ufs/ffs/fs.h>
#include <ufs/ffs/ffs_extern.h>
#if REV_ENDIAN_FS
#include <ufs/ufs/ufs_byte_order.h>
#include <architecture/byte_order.h>
#endif /* REV_ENDIAN_FS */

#define VOPFUNC int (*)(void *)

/* Global vfs data structures for ufs. */
int (**ffs_vnodeop_p)(void *);
struct vnodeopv_entry_desc ffs_vnodeop_entries[] = {
	{ &vop_default_desc, (VOPFUNC)vn_default_error },
	{ &vop_lookup_desc, (VOPFUNC)ufs_lookup },		/* lookup */
	{ &vop_create_desc, (VOPFUNC)ufs_create },		/* create */
	{ &vop_whiteout_desc, (VOPFUNC)ufs_whiteout },		/* whiteout */
	{ &vop_mknod_desc, (VOPFUNC)ufs_mknod },		/* mknod */
	{ &vop_open_desc, (VOPFUNC)ufs_open },			/* open */
	{ &vop_close_desc, (VOPFUNC)ufs_close },		/* close */
	{ &vop_access_desc, (VOPFUNC)ufs_access },		/* access */
	{ &vop_getattr_desc, (VOPFUNC)ufs_getattr },		/* getattr */
	{ &vop_setattr_desc, (VOPFUNC)ufs_setattr },		/* setattr */
	{ &vop_read_desc, (VOPFUNC)ffs_read },			/* read */
	{ &vop_write_desc, (VOPFUNC)ffs_write },		/* write */
	{ &vop_lease_desc, (VOPFUNC)ufs_lease_check },		/* lease */
	{ &vop_ioctl_desc, (VOPFUNC)ufs_ioctl },		/* ioctl */
	{ &vop_select_desc, (VOPFUNC)ufs_select },		/* select */
	{ &vop_revoke_desc, (VOPFUNC)ufs_revoke },		/* revoke */
	{ &vop_mmap_desc, (VOPFUNC)ufs_mmap },			/* mmap */
	{ &vop_fsync_desc, (VOPFUNC)ffs_fsync },		/* fsync */
	{ &vop_seek_desc, (VOPFUNC)ufs_seek },			/* seek */
	{ &vop_remove_desc, (VOPFUNC)ufs_remove },		/* remove */
	{ &vop_link_desc, (VOPFUNC)ufs_link },			/* link */
	{ &vop_rename_desc, (VOPFUNC)ufs_rename },		/* rename */
	{ &vop_mkdir_desc, (VOPFUNC)ufs_mkdir },		/* mkdir */
	{ &vop_rmdir_desc, (VOPFUNC)ufs_rmdir },		/* rmdir */
	{ &vop_symlink_desc, (VOPFUNC)ufs_symlink },		/* symlink */
	{ &vop_readdir_desc, (VOPFUNC)ufs_readdir },		/* readdir */
	{ &vop_readlink_desc, (VOPFUNC)ufs_readlink },		/* readlink */
	{ &vop_abortop_desc, (VOPFUNC)ufs_abortop },		/* abortop */
	{ &vop_inactive_desc, (VOPFUNC)ufs_inactive },		/* inactive */
	{ &vop_reclaim_desc, (VOPFUNC)ffs_reclaim },		/* reclaim */
	{ &vop_lock_desc, (VOPFUNC)ufs_lock },			/* lock */
	{ &vop_unlock_desc, (VOPFUNC)ufs_unlock },		/* unlock */
	{ &vop_bmap_desc, (VOPFUNC)ufs_bmap },			/* bmap */
	{ &vop_strategy_desc, (VOPFUNC)ufs_strategy },		/* strategy */
	{ &vop_print_desc, (VOPFUNC)ufs_print },		/* print */
	{ &vop_islocked_desc, (VOPFUNC)ufs_islocked },		/* islocked */
	{ &vop_pathconf_desc, (VOPFUNC)ufs_pathconf },		/* pathconf */
	{ &vop_advlock_desc, (VOPFUNC)ufs_advlock },		/* advlock */
	{ &vop_blkatoff_desc, (VOPFUNC)ffs_blkatoff },		/* blkatoff */
	{ &vop_valloc_desc, (VOPFUNC)ffs_valloc },		/* valloc */
	{ &vop_reallocblks_desc, (VOPFUNC)ffs_reallocblks },	/* reallocblks */
	{ &vop_vfree_desc, (VOPFUNC)ffs_vfree },		/* vfree */
	{ &vop_truncate_desc, (VOPFUNC)ffs_truncate },		/* truncate */
	{ &vop_update_desc, (VOPFUNC)ffs_update },		/* update */
	{ &vop_bwrite_desc, (VOPFUNC)vn_bwrite },
	{ &vop_pagein_desc, (VOPFUNC)ffs_pagein },		/* Pagein */
	{ &vop_pageout_desc, (VOPFUNC)ffs_pageout },		/* Pageout */
	{ &vop_copyfile_desc, (VOPFUNC)err_copyfile },		/* Copy File */
	{ &vop_blktooff_desc, (VOPFUNC)ffs_blktooff },		/* blktooff */
	{ &vop_offtoblk_desc, (VOPFUNC)ffs_offtoblk },		/* offtoblk */
	{ &vop_cmap_desc, (VOPFUNC)ufs_cmap },			/* cmap */
	{ (struct vnodeop_desc*)NULL, (int(*)())NULL }
};
struct vnodeopv_desc ffs_vnodeop_opv_desc =
	{ &ffs_vnodeop_p, ffs_vnodeop_entries };

int (**ffs_specop_p)(void *);
struct vnodeopv_entry_desc ffs_specop_entries[] = {
	{ &vop_default_desc, (VOPFUNC)vn_default_error },
	{ &vop_lookup_desc, (VOPFUNC)spec_lookup },		/* lookup */
	{ &vop_create_desc, (VOPFUNC)spec_create },		/* create */
	{ &vop_mknod_desc, (VOPFUNC)spec_mknod },		/* mknod */
	{ &vop_open_desc, (VOPFUNC)spec_open },			/* open */
	{ &vop_close_desc, (VOPFUNC)ufsspec_close },		/* close */
	{ &vop_access_desc, (VOPFUNC)ufs_access },		/* access */
	{ &vop_getattr_desc, (VOPFUNC)ufs_getattr },		/* getattr */
	{ &vop_setattr_desc, (VOPFUNC)ufs_setattr },		/* setattr */
	{ &vop_read_desc, (VOPFUNC)ufsspec_read },		/* read */
	{ &vop_write_desc, (VOPFUNC)ufsspec_write },		/* write */
	{ &vop_lease_desc, (VOPFUNC)spec_lease_check },		/* lease */
	{ &vop_ioctl_desc, (VOPFUNC)spec_ioctl },		/* ioctl */
	{ &vop_select_desc, (VOPFUNC)spec_select },		/* select */
	{ &vop_revoke_desc, (VOPFUNC)spec_revoke },		/* revoke */
	{ &vop_mmap_desc, (VOPFUNC)spec_mmap },			/* mmap */
	{ &vop_fsync_desc, (VOPFUNC)ffs_fsync },		/* fsync */
	{ &vop_seek_desc, (VOPFUNC)spec_seek },			/* seek */
	{ &vop_remove_desc, (VOPFUNC)spec_remove },		/* remove */
	{ &vop_link_desc, (VOPFUNC)spec_link },			/* link */
	{ &vop_rename_desc, (VOPFUNC)spec_rename },		/* rename */
	{ &vop_mkdir_desc, (VOPFUNC)spec_mkdir },		/* mkdir */
	{ &vop_rmdir_desc, (VOPFUNC)spec_rmdir },		/* rmdir */
	{ &vop_symlink_desc, (VOPFUNC)spec_symlink },		/* symlink */
	{ &vop_readdir_desc, (VOPFUNC)spec_readdir },		/* readdir */
	{ &vop_readlink_desc, (VOPFUNC)spec_readlink },		/* readlink */
	{ &vop_abortop_desc, (VOPFUNC)spec_abortop },		/* abortop */
	{ &vop_inactive_desc, (VOPFUNC)ufs_inactive },		/* inactive */
	{ &vop_reclaim_desc, (VOPFUNC)ffs_reclaim },		/* reclaim */
	{ &vop_lock_desc, (VOPFUNC)ufs_lock },			/* lock */
	{ &vop_unlock_desc, (VOPFUNC)ufs_unlock },		/* unlock */
	{ &vop_bmap_desc, (VOPFUNC)spec_bmap },			/* bmap */
	{ &vop_strategy_desc, (VOPFUNC)spec_strategy },		/* strategy */
	{ &vop_print_desc, (VOPFUNC)ufs_print },		/* print */
	{ &vop_islocked_desc, (VOPFUNC)ufs_islocked },		/* islocked */
	{ &vop_pathconf_desc, (VOPFUNC)spec_pathconf },		/* pathconf */
	{ &vop_advlock_desc, (VOPFUNC)spec_advlock },		/* advlock */
	{ &vop_blkatoff_desc, (VOPFUNC)spec_blkatoff },		/* blkatoff */
	{ &vop_valloc_desc, (VOPFUNC)spec_valloc },		/* valloc */
	{ &vop_reallocblks_desc, (VOPFUNC)spec_reallocblks },	/* reallocblks */
	{ &vop_vfree_desc, (VOPFUNC)ffs_vfree },		/* vfree */
	{ &vop_truncate_desc, (VOPFUNC)spec_truncate },		/* truncate */
	{ &vop_update_desc, (VOPFUNC)ffs_update },		/* update */
	{ &vop_bwrite_desc, (VOPFUNC)vn_bwrite },
	{ &vop_devblocksize_desc, (VOPFUNC)spec_devblocksize },	/* devblocksize */
	{ &vop_pagein_desc, (VOPFUNC)ffs_pagein },		/* Pagein */
	{ &vop_pageout_desc, (VOPFUNC)ffs_pageout },		/* Pageout */
	{ &vop_copyfile_desc, (VOPFUNC)err_copyfile },		/* Copy File */
	{ &vop_blktooff_desc, (VOPFUNC)ffs_blktooff },		/* blktooff */
	{ &vop_offtoblk_desc, (VOPFUNC)ffs_offtoblk },		/* offtoblk */
	{ &vop_cmap_desc, (VOPFUNC)spec_cmap },			/* cmap */
	{ (struct vnodeop_desc*)NULL, (int(*)())NULL }
};
struct vnodeopv_desc ffs_specop_opv_desc =
	{ &ffs_specop_p, ffs_specop_entries };

#if FIFO
int (**ffs_fifoop_p)(void *);
struct vnodeopv_entry_desc ffs_fifoop_entries[] = {
	{ &vop_default_desc, (VOPFUNC)vn_default_error },
	{ &vop_lookup_desc, (VOPFUNC)fifo_lookup },		/* lookup */
	{ &vop_create_desc, (VOPFUNC)fifo_create },		/* create */
	{ &vop_mknod_desc, (VOPFUNC)fifo_mknod },		/* mknod */
	{ &vop_open_desc, (VOPFUNC)fifo_open },			/* open */
	{ &vop_close_desc, (VOPFUNC)ufsfifo_close },		/* close */
	{ &vop_access_desc, (VOPFUNC)ufs_access },		/* access */
	{ &vop_getattr_desc, (VOPFUNC)ufs_getattr },		/* getattr */
	{ &vop_setattr_desc, (VOPFUNC)ufs_setattr },		/* setattr */
	{ &vop_read_desc, (VOPFUNC)ufsfifo_read },		/* read */
	{ &vop_write_desc, (VOPFUNC)ufsfifo_write },		/* write */
	{ &vop_lease_desc, (VOPFUNC)fifo_lease_check },		/* lease */
	{ &vop_ioctl_desc, (VOPFUNC)fifo_ioctl },		/* ioctl */
	{ &vop_select_desc, (VOPFUNC)fifo_select },		/* select */
	{ &vop_revoke_desc, (VOPFUNC)fifo_revoke },		/* revoke */
	{ &vop_mmap_desc, (VOPFUNC)fifo_mmap },			/* mmap */
	{ &vop_fsync_desc, (VOPFUNC)ffs_fsync },		/* fsync */
	{ &vop_seek_desc, (VOPFUNC)fifo_seek },			/* seek */
	{ &vop_remove_desc, (VOPFUNC)fifo_remove },		/* remove */
	{ &vop_link_desc, (VOPFUNC)fifo_link },			/* link */
	{ &vop_rename_desc, (VOPFUNC)fifo_rename },		/* rename */
	{ &vop_mkdir_desc, (VOPFUNC)fifo_mkdir },		/* mkdir */
	{ &vop_rmdir_desc, (VOPFUNC)fifo_rmdir },		/* rmdir */
	{ &vop_symlink_desc, (VOPFUNC)fifo_symlink },		/* symlink */
	{ &vop_readdir_desc, (VOPFUNC)fifo_readdir },		/* readdir */
	{ &vop_readlink_desc, (VOPFUNC)fifo_readlink },		/* readlink */
	{ &vop_abortop_desc, (VOPFUNC)fifo_abortop },		/* abortop */
	{ &vop_inactive_desc, (VOPFUNC)ufs_inactive },		/* inactive */
	{ &vop_reclaim_desc, (VOPFUNC)ffs_reclaim },		/* reclaim */
	{ &vop_lock_desc, (VOPFUNC)ufs_lock },			/* lock */
	{ &vop_unlock_desc, (VOPFUNC)ufs_unlock },		/* unlock */
	{ &vop_bmap_desc, (VOPFUNC)fifo_bmap },			/* bmap */
	{ &vop_strategy_desc, (VOPFUNC)fifo_strategy },		/* strategy */
	{ &vop_print_desc, (VOPFUNC)ufs_print },		/* print */
	{ &vop_islocked_desc, (VOPFUNC)ufs_islocked },		/* islocked */
	{ &vop_pathconf_desc, (VOPFUNC)fifo_pathconf },		/* pathconf */
	{ &vop_advlock_desc, (VOPFUNC)fifo_advlock },		/* advlock */
	{ &vop_blkatoff_desc, (VOPFUNC)fifo_blkatoff },		/* blkatoff */
	{ &vop_valloc_desc, (VOPFUNC)fifo_valloc },		/* valloc */
	{ &vop_reallocblks_desc, (VOPFUNC)fifo_reallocblks },	/* reallocblks */
	{ &vop_vfree_desc, (VOPFUNC)ffs_vfree },		/* vfree */
	{ &vop_truncate_desc, (VOPFUNC)fifo_truncate },		/* truncate */
	{ &vop_update_desc, (VOPFUNC)ffs_update },		/* update */
	{ &vop_bwrite_desc, (VOPFUNC)vn_bwrite },
	{ &vop_pagein_desc, (VOPFUNC)ffs_pagein },		/* Pagein */
	{ &vop_pageout_desc, (VOPFUNC)ffs_pageout },		/* Pageout */
	{ &vop_copyfile_desc, (VOPFUNC)err_copyfile },		/*  Copy File */
	{ &vop_blktooff_desc, (VOPFUNC)ffs_blktooff },		/* blktooff */
	{ &vop_offtoblk_desc, (VOPFUNC)ffs_offtoblk },		/* offtoblk */
	{ &vop_cmap_desc, (VOPFUNC)ufs_cmap },			/* cmap */
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
	struct vop_fsync_args /* {
		struct vnode *a_vp;
		struct ucred *a_cred;
		int a_waitfor;
		struct proc *a_p;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	register struct buf *bp;
	struct timeval tv;
	struct buf *nbp;
	int s;
	struct inode *ip = VTOI(vp);
	int retry = 0;

	/*
	 * Write out any clusters.
	 */
	cluster_push(vp);

	/*
	 * Flush all dirty buffers associated with a vnode.
	 */
loop:
	s = splbio();
	for (bp = vp->v_dirtyblkhd.lh_first; bp; bp = nbp) {
		nbp = bp->b_vnbufs.le_next;
		if ((bp->b_flags & B_BUSY))
			continue;
		if ((bp->b_flags & B_DELWRI) == 0)
			panic("ffs_fsync: not dirty");
		bremfree(bp);
		bp->b_flags |= B_BUSY;
		splx(s);
		/*
		 * Wait for I/O associated with indirect blocks to complete,
		 * since there is no way to quickly wait for them below.
		 */
		if (bp->b_vp == vp || ap->a_waitfor == MNT_NOWAIT)
			(void) bawrite(bp);
		else
			(void) bwrite(bp);
		goto loop;
	}

	if (ap->a_waitfor == MNT_WAIT) {
		while (vp->v_numoutput) {
			vp->v_flag |= VBWAIT;
			tsleep((caddr_t)&vp->v_numoutput, PRIBIO + 1, "ffs_fsync", 0);
		}

		if (vp->v_dirtyblkhd.lh_first) {
			/* still have some dirty buffers */
			if (retry++ > 10) {
				vprint("ffs_fsync: dirty", vp);
				splx(s);
				/*
				 * Looks like the requests are not
				 * getting queued to the driver.
				 * Retrying here causes a cpu bound loop.
				 * Yield to the other threads and hope
				 * for the best.
				 */
				(void)tsleep((caddr_t)&vp->v_numoutput,
						PRIBIO + 1, "ffs_fsync", hz/10);
				retry = 0;
			} else {
				splx(s);
			}
			/* try again */
			goto loop;
		}
	}
	splx(s);
	tv = time;
	return (VOP_UPDATE(ap->a_vp, &tv, &tv, ap->a_waitfor == MNT_WAIT));
}

/*
 * Reclaim an inode so that it can be used for other purposes.
 */
int
ffs_reclaim(ap)
	struct vop_reclaim_args /* {
		struct vnode *a_vp;
		struct proc *a_p;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	int error;

	if (error = ufs_reclaim(vp, ap->a_p))
		return (error);
	FREE_ZONE(vp->v_data, sizeof (struct inode),
			VFSTOUFS(vp->v_mount)->um_devvp->v_tag == VT_MFS ?
					M_MFSNODE : M_FFSNODE);
	vp->v_data = NULL;
	return (0);
}

/* Blktooff converts a logical block number to a file offset */
int
ffs_blktooff(ap)
	struct vop_blktooff_args /* {
		struct vnode *a_vp;
		daddr_t a_lblkno;
		off_t *a_offset;    
	} */ *ap;
{
	register struct inode *ip;
	register FS *fs;
	ufs_daddr_t bn;


	if (ap->a_vp == NULL)
		return (EINVAL);

	ip = VTOI(ap->a_vp);
	fs = ip->I_FS;
	bn = ap->a_lblkno;

	if ((long)bn < 0) {
		panic("-ve blkno in ffs_blktooff");
		bn = -(long)bn;
	}

	*ap->a_offset = (off_t)lblktosize(fs, bn);
	return (0);
}

/* Blktooff converts a logical block number to a file offset */
int
ffs_offtoblk(ap)
	struct vop_offtoblk_args /* {
		struct vnode *a_vp;
		off_t a_offset;    
		daddr_t *a_lblkno;
	} */ *ap;
{
	register struct inode *ip;
    register FS *fs;

	if (ap->a_vp == NULL)
		return (EINVAL);

	ip = VTOI(ap->a_vp);
	fs = ip->I_FS;

	*ap->a_lblkno = (daddr_t)lblkno(fs, ap->a_offset);
	return (0);
}
