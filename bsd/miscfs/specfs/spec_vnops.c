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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1989, 1993, 1995
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
 *	@(#)spec_vnops.c	8.14 (Berkeley) 5/21/95
 */

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/buf.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/malloc.h>
#include <sys/disk.h>
#include <miscfs/specfs/specdev.h>
#include <vfs/vfs_support.h>

#include <sys/kdebug.h>

struct vnode *speclisth[SPECHSZ];

/* symbolic sleep message strings for devices */
char	devopn[] = "devopn";
char	devio[] = "devio";
char	devwait[] = "devwait";
char	devin[] = "devin";
char	devout[] = "devout";
char	devioc[] = "devioc";
char	devcls[] = "devcls";

#define VOPFUNC int (*)(void *)

int (**spec_vnodeop_p)(void *);
struct vnodeopv_entry_desc spec_vnodeop_entries[] = {
	{ &vop_default_desc, (VOPFUNC)vn_default_error },
	{ &vop_lookup_desc, (VOPFUNC)spec_lookup },		/* lookup */
	{ &vop_create_desc, (VOPFUNC)err_create },		/* create */
	{ &vop_mknod_desc, (VOPFUNC)err_mknod },		/* mknod */
	{ &vop_open_desc, (VOPFUNC)spec_open },			/* open */
	{ &vop_close_desc, (VOPFUNC)spec_close },		/* close */
	{ &vop_access_desc, (VOPFUNC)spec_access },		/* access */
	{ &vop_getattr_desc, (VOPFUNC)spec_getattr },		/* getattr */
	{ &vop_setattr_desc, (VOPFUNC)spec_setattr },		/* setattr */
	{ &vop_read_desc, (VOPFUNC)spec_read },			/* read */
	{ &vop_write_desc, (VOPFUNC)spec_write },		/* write */
	{ &vop_lease_desc, (VOPFUNC)nop_lease },		/* lease */
	{ &vop_ioctl_desc, (VOPFUNC)spec_ioctl },		/* ioctl */
	{ &vop_select_desc, (VOPFUNC)spec_select },		/* select */
	{ &vop_revoke_desc, (VOPFUNC)nop_revoke },		/* revoke */
	{ &vop_mmap_desc, (VOPFUNC)err_mmap },			/* mmap */
	{ &vop_fsync_desc, (VOPFUNC)spec_fsync },		/* fsync */
	{ &vop_seek_desc, (VOPFUNC)err_seek },			/* seek */
	{ &vop_remove_desc, (VOPFUNC)err_remove },		/* remove */
	{ &vop_link_desc, (VOPFUNC)err_link },			/* link */
	{ &vop_rename_desc, (VOPFUNC)err_rename },		/* rename */
	{ &vop_mkdir_desc, (VOPFUNC)err_mkdir },		/* mkdir */
	{ &vop_rmdir_desc, (VOPFUNC)err_rmdir },		/* rmdir */
	{ &vop_symlink_desc, (VOPFUNC)err_symlink },		/* symlink */
	{ &vop_readdir_desc, (VOPFUNC)err_readdir },		/* readdir */
	{ &vop_readlink_desc, (VOPFUNC)err_readlink },		/* readlink */
	{ &vop_abortop_desc, (VOPFUNC)err_abortop },		/* abortop */
	{ &vop_inactive_desc, (VOPFUNC)nop_inactive },		/* inactive */
	{ &vop_reclaim_desc, (VOPFUNC)nop_reclaim },		/* reclaim */
	{ &vop_lock_desc, (VOPFUNC)nop_lock },			/* lock */
	{ &vop_unlock_desc, (VOPFUNC)nop_unlock },		/* unlock */
	{ &vop_bmap_desc, (VOPFUNC)spec_bmap },			/* bmap */
	{ &vop_strategy_desc, (VOPFUNC)spec_strategy },		/* strategy */
	{ &vop_print_desc, (VOPFUNC)spec_print },		/* print */
	{ &vop_islocked_desc, (VOPFUNC)nop_islocked },		/* islocked */
	{ &vop_pathconf_desc, (VOPFUNC)spec_pathconf },		/* pathconf */
	{ &vop_advlock_desc, (VOPFUNC)err_advlock },		/* advlock */
	{ &vop_blkatoff_desc, (VOPFUNC)err_blkatoff },		/* blkatoff */
	{ &vop_valloc_desc, (VOPFUNC)err_valloc },		/* valloc */
	{ &vop_vfree_desc, (VOPFUNC)err_vfree },		/* vfree */
	{ &vop_truncate_desc, (VOPFUNC)nop_truncate },		/* truncate */
	{ &vop_update_desc, (VOPFUNC)nop_update },		/* update */
	{ &vop_bwrite_desc, (VOPFUNC)spec_bwrite },		/* bwrite */
	{ &vop_devblocksize_desc, (VOPFUNC)spec_devblocksize }, /* devblocksize */
	{ &vop_pagein_desc, (VOPFUNC)err_pagein },		/* Pagein */
	{ &vop_pageout_desc, (VOPFUNC)err_pageout },		/* Pageout */
        { &vop_copyfile_desc, (VOPFUNC)err_copyfile },		/* Copyfile */
	{ &vop_blktooff_desc, (VOPFUNC)spec_blktooff },		/* blktooff */
	{ &vop_offtoblk_desc, (VOPFUNC)spec_offtoblk },		/* offtoblk */
	{ &vop_cmap_desc, (VOPFUNC)spec_cmap },		/* cmap */
	{ (struct vnodeop_desc*)NULL, (int(*)())NULL }
};
struct vnodeopv_desc spec_vnodeop_opv_desc =
	{ &spec_vnodeop_p, spec_vnodeop_entries };

/*
 * Trivial lookup routine that always fails.
 */
int
spec_lookup(ap)
	struct vop_lookup_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
	} */ *ap;
{

	*ap->a_vpp = NULL;
	return (ENOTDIR);
}

void
set_blocksize(struct vnode *vp, dev_t dev)
{
    int (*size)();
    int rsize;

    if ((major(dev) < nblkdev) && (size = bdevsw[major(dev)].d_psize)) {
        rsize = (*size)(dev);
	if (rsize <= 0)        /* did size fail? */
	    vp->v_specsize = DEV_BSIZE;
	else
	    vp->v_specsize = rsize;
    }
    else
	    vp->v_specsize = DEV_BSIZE;
}

void
set_fsblocksize(struct vnode *vp)
{
	
	if (vp->v_type == VBLK) {
		dev_t dev = (dev_t)vp->v_rdev;
		int maj = major(dev);

		if ((u_int)maj >= nblkdev)
			return;

		set_blocksize(vp, dev);
	}

}


/*
 * Open a special file.
 */
/* ARGSUSED */
spec_open(ap)
	struct vop_open_args /* {
		struct vnode *a_vp;
		int  a_mode;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	struct proc *p = ap->a_p;
	struct vnode *bvp, *vp = ap->a_vp;
	dev_t bdev, dev = (dev_t)vp->v_rdev;
	int maj = major(dev);
	int error;

	/*
	 * Don't allow open if fs is mounted -nodev.
	 */
	if (vp->v_mount && (vp->v_mount->mnt_flag & MNT_NODEV))
		return (ENXIO);

	switch (vp->v_type) {

	case VCHR:
		if ((u_int)maj >= nchrdev)
			return (ENXIO);
		if (ap->a_cred != FSCRED && (ap->a_mode & FWRITE)) {
			/*
			 * When running in very secure mode, do not allow
			 * opens for writing of any disk character devices.
			 */
			if (securelevel >= 2 && isdisk(dev, VCHR))
				return (EPERM);
			/*
			 * When running in secure mode, do not allow opens
			 * for writing of /dev/mem, /dev/kmem, or character
			 * devices whose corresponding block devices are
			 * currently mounted.
			 */
			if (securelevel >= 1) {
				if ((bdev = chrtoblk(dev)) != NODEV &&
				    vfinddev(bdev, VBLK, &bvp) &&
				    bvp->v_usecount > 0 &&
				    (error = vfs_mountedon(bvp)))
					return (error);
				if (iskmemdev(dev))
					return (EPERM);
			}
		}
		if (cdevsw[maj].d_type == D_TTY)
			vp->v_flag |= VISTTY;
		VOP_UNLOCK(vp, 0, p);
		error = (*cdevsw[maj].d_open)(dev, ap->a_mode, S_IFCHR, p);
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
		return (error);

	case VBLK:
		if ((u_int)maj >= nblkdev)
			return (ENXIO);
		/*
		 * When running in very secure mode, do not allow
		 * opens for writing of any disk block devices.
		 */
		if (securelevel >= 2 && ap->a_cred != FSCRED &&
		    (ap->a_mode & FWRITE) && bdevsw[maj].d_type == D_DISK)
			return (EPERM);
		/*
		 * Do not allow opens of block devices that are
		 * currently mounted.
		 */
		if (error = vfs_mountedon(vp))
			return (error);
		error = (*bdevsw[maj].d_open)(dev, ap->a_mode, S_IFBLK, p);
		if (!error) {
		    u_int64_t blkcnt;
		    u_int32_t blksize;

		    set_blocksize(vp, dev);

		    /*
		     * Cache the size in bytes of the block device for later
		     * use by spec_write().
		     */
		    vp->v_specdevsize = (u_int64_t)0;	/* Default: Can't get */
		    if (!VOP_IOCTL(vp, DKIOCGETBLOCKSIZE, (caddr_t)&blksize, 0, NOCRED, p)) {
			/* Switch to 512 byte sectors (temporarily) */
			u_int32_t size512 = 512;

			if (!VOP_IOCTL(vp, DKIOCSETBLOCKSIZE, (caddr_t)&size512, FWRITE, NOCRED, p)) {
			    /* Get the number of 512 byte physical blocks. */
			    if (!VOP_IOCTL(vp, DKIOCGETBLOCKCOUNT, (caddr_t)&blkcnt, 0, NOCRED, p)) {
				vp->v_specdevsize = blkcnt * (u_int64_t)size512;
			    }
			}
			/* If it doesn't set back, we can't recover */
			if (VOP_IOCTL(vp, DKIOCSETBLOCKSIZE, (caddr_t)&blksize, FWRITE, NOCRED, p))
			    error = ENXIO;
		    }
		}
		return(error);
	}
	return (0);
}

/*
 * Vnode op for read
 */
/* ARGSUSED */
spec_read(ap)
	struct vop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	register struct uio *uio = ap->a_uio;
 	struct proc *p = uio->uio_procp;
	struct buf *bp;
	daddr_t bn, nextbn;
	long bsize, bscale;
	int devBlockSize=0;
	int n, on, majordev, (*ioctl)();
	int error = 0;
	dev_t dev;

#if DIAGNOSTIC
	if (uio->uio_rw != UIO_READ)
		panic("spec_read mode");
	if (uio->uio_segflg == UIO_USERSPACE && uio->uio_procp != current_proc())
		panic("spec_read proc");
#endif
	if (uio->uio_resid == 0)
		return (0);

	switch (vp->v_type) {

	case VCHR:
		VOP_UNLOCK(vp, 0, p);
		error = (*cdevsw[major(vp->v_rdev)].d_read)
			(vp->v_rdev, uio, ap->a_ioflag);
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
		return (error);

	case VBLK:
		if (uio->uio_offset < 0)
			return (EINVAL);

		dev = vp->v_rdev;

		devBlockSize = vp->v_specsize;

		if (devBlockSize > PAGE_SIZE) 
			return (EINVAL);

	        bscale = PAGE_SIZE / devBlockSize;
		bsize = bscale * devBlockSize;

		do {
			on = uio->uio_offset % bsize;

			bn = (uio->uio_offset / devBlockSize) &~ (bscale - 1);
			
			if (vp->v_lastr + bscale == bn) {
			        nextbn = bn + bscale;
				error = breadn(vp, bn, (int)bsize, &nextbn,
					       (int *)&bsize, 1, NOCRED, &bp);
			} else
			        error = bread(vp, bn, (int)bsize, NOCRED, &bp);

			vp->v_lastr = bn;
			n = bsize - bp->b_resid;
			if ((on > n) || error) {
			        if (!error)
				        error = EINVAL;
				brelse(bp);
				return (error);
			}
			n = min((unsigned)(n  - on), uio->uio_resid);

			error = uiomove((char *)bp->b_data + on, n, uio);
			if (n + on == bsize)
				bp->b_flags |= B_AGE;
			brelse(bp);
		} while (error == 0 && uio->uio_resid > 0 && n != 0);
		return (error);

	default:
		panic("spec_read type");
	}
	/* NOTREACHED */
}

/*
 * Vnode op for write
 */
/* ARGSUSED */
spec_write(ap)
	struct vop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	register struct uio *uio = ap->a_uio;
	struct proc *p = uio->uio_procp;
	struct buf *bp;
	daddr_t bn;
	int bsize, blkmask, bscale;
	register int io_sync;
	register int io_size;
	int devBlockSize=0;
	register int n, on;
	int error = 0;
	dev_t dev;

#if DIAGNOSTIC
	if (uio->uio_rw != UIO_WRITE)
		panic("spec_write mode");
	if (uio->uio_segflg == UIO_USERSPACE && uio->uio_procp != current_proc())
		panic("spec_write proc");
#endif

	switch (vp->v_type) {

	case VCHR:
		VOP_UNLOCK(vp, 0, p);
		error = (*cdevsw[major(vp->v_rdev)].d_write)
			(vp->v_rdev, uio, ap->a_ioflag);
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
		return (error);

	case VBLK:
		if (uio->uio_resid == 0)
			return (0);
		if (uio->uio_offset < 0)
			return (EINVAL);

		io_sync = (ap->a_ioflag & IO_SYNC);
		io_size = uio->uio_resid;

		dev = (vp->v_rdev);

		devBlockSize = vp->v_specsize;
		if (devBlockSize > PAGE_SIZE)
			return(EINVAL);

	        bscale = PAGE_SIZE / devBlockSize;
		blkmask = bscale - 1;
		bsize = bscale * devBlockSize;
		

		do {
			bn = (uio->uio_offset / devBlockSize) &~ blkmask;
			on = uio->uio_offset % bsize;

			n = min((unsigned)(bsize - on), uio->uio_resid);

			/*
			 * Use getblk() as an optimization IFF:
			 *
			 * 1)	We are reading exactly a block on a block
			 *	aligned boundary
			 * 2)	We know the size of the device from spec_open
			 * 3)	The read doesn't span the end of the device
			 *
			 * Otherwise, we fall back on bread().
			 */
			if (n == bsize &&
			    vp->v_specdevsize != (u_int64_t)0 &&
			    (uio->uio_offset + (u_int64_t)n) > vp->v_specdevsize) {
			    /* reduce the size of the read to what is there */
			    n = (uio->uio_offset + (u_int64_t)n) - vp->v_specdevsize;
			}

			if (n == bsize)
			        bp = getblk(vp, bn, bsize, 0, 0, BLK_WRITE);
			else
			        error = bread(vp, bn, bsize, NOCRED, &bp);

			/* Translate downstream error for upstream, if needed */
			if (!error) {
				error = bp->b_error;
				if (!error && (bp->b_flags & B_ERROR) != 0) {
					error = EIO;
				}
			}
			if (error) {
				brelse(bp);
				return (error);
			}
			n = min(n, bsize - bp->b_resid);

			error = uiomove((char *)bp->b_data + on, n, uio);

			bp->b_flags |= B_AGE;

			if (io_sync) 
			        bwrite(bp);
			else {
			        if ((n + on) == bsize)
				        bawrite(bp);
				else
				        bdwrite(bp);
			}
		} while (error == 0 && uio->uio_resid > 0 && n != 0);
		return (error);

	default:
		panic("spec_write type");
	}
	/* NOTREACHED */
}

/*
 * Device ioctl operation.
 */
/* ARGSUSED */
spec_ioctl(ap)
	struct vop_ioctl_args /* {
		struct vnode *a_vp;
		int  a_command;
		caddr_t  a_data;
		int  a_fflag;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	dev_t dev = ap->a_vp->v_rdev;

	switch (ap->a_vp->v_type) {

	case VCHR:
		return ((*cdevsw[major(dev)].d_ioctl)(dev, ap->a_command, ap->a_data,
		    ap->a_fflag, ap->a_p));

	case VBLK:
		if (ap->a_command == 0 && (int)ap->a_data == B_TAPE)
			if (bdevsw[major(dev)].d_type == D_TAPE)
				return (0);
			else
				return (1);
		return ((*bdevsw[major(dev)].d_ioctl)(dev, ap->a_command, ap->a_data,
		   ap->a_fflag, ap->a_p));

	default:
		panic("spec_ioctl");
		/* NOTREACHED */
	}
}

/* ARGSUSED */
spec_select(ap)
	struct vop_select_args /* {
		struct vnode *a_vp;
		int  a_which;
		int  a_fflags;
		struct ucred *a_cred;
		void * a_wql;
		struct proc *a_p;
	} */ *ap;
{
	register dev_t dev;

	switch (ap->a_vp->v_type) {

	default:
		return (1);		/* XXX */

	case VCHR:
		dev = ap->a_vp->v_rdev;
		return (*cdevsw[major(dev)].d_select)(dev, ap->a_which, ap->a_wql, ap->a_p);
	}
}
/*
 * Synch buffers associated with a block device
 */
/* ARGSUSED */
int
spec_fsync(ap)
	struct vop_fsync_args /* {
		struct vnode *a_vp;
		struct ucred *a_cred;
		int  a_waitfor;
		struct proc *a_p;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	register struct buf *bp;
	struct buf *nbp;
	int s;

	if (vp->v_type == VCHR)
		return (0);
	/*
	 * Flush all dirty buffers associated with a block device.
	 */
loop:
	s = splbio();
	for (bp = vp->v_dirtyblkhd.lh_first; bp; bp = nbp) {
		nbp = bp->b_vnbufs.le_next;
		// XXXdbg - don't flush locked blocks.  they may be journaled.
		if ((bp->b_flags & B_BUSY) || (bp->b_flags & B_LOCKED))
			continue;
		if ((bp->b_flags & B_DELWRI) == 0)
			panic("spec_fsync: not dirty");
		bremfree(bp);
		bp->b_flags |= B_BUSY;
		splx(s);
		bawrite(bp);
		goto loop;
	}
	if (ap->a_waitfor == MNT_WAIT) {
		while (vp->v_numoutput) {
			vp->v_flag |= VBWAIT;
			tsleep((caddr_t)&vp->v_numoutput, PRIBIO + 1, "spec_fsync", 0);
		}
#if DIAGNOSTIC
		if (vp->v_dirtyblkhd.lh_first) {
			vprint("spec_fsync: dirty", vp);
			splx(s);
			goto loop;
		}
#endif
	}
	splx(s);
	return (0);
}

/*
 * Just call the device strategy routine
 */
spec_strategy(ap)
	struct vop_strategy_args /* {
		struct buf *a_bp;
	} */ *ap;
{
        struct buf *bp;
	extern int hard_throttle_on_root;

        bp = ap->a_bp;

        if (kdebug_enable) {
            int    code = 0;

            if (bp->b_flags & B_READ)
                code |= DKIO_READ;
            if (bp->b_flags & B_ASYNC)
                code |= DKIO_ASYNC;

            if (bp->b_flags & B_META)
                code |= DKIO_META;
            else if (bp->b_flags & (B_PGIN | B_PAGEOUT))
                code |= DKIO_PAGING;

            KERNEL_DEBUG_CONSTANT(FSDBG_CODE(DBG_DKRW, code) | DBG_FUNC_NONE,
				(unsigned int)bp, bp->b_dev, bp->b_blkno, bp->b_bcount, 0);
        }
	if ((bp->b_flags & B_PGIN) && (bp->b_vp->v_mount->mnt_kern_flag & MNTK_ROOTDEV))
	       hard_throttle_on_root = 1;

        (*bdevsw[major(bp->b_dev)].d_strategy)(bp);
        return (0);
}

/*
 * This is a noop, simply returning what one has been given.
 */
spec_bmap(ap)
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
		*ap->a_bnp = ap->a_bn * (PAGE_SIZE / ap->a_vp->v_specsize);
	if (ap->a_runp != NULL)
		*ap->a_runp = (MAXPHYSIO / PAGE_SIZE) - 1;
	return (0);
}

/*
 * This is a noop, simply returning what one has been given.
 */
spec_cmap(ap)
	struct vop_cmap_args /* {
		struct vnode *a_vp;
		off_t a_offset;    
		size_t a_size;
		daddr_t *a_bpn;
		size_t *a_run;
		void *a_poff;
	} */ *ap;
{
	return (EOPNOTSUPP);
}


/*
 * Device close routine
 */
/* ARGSUSED */
spec_close(ap)
	struct vop_close_args /* {
		struct vnode *a_vp;
		int  a_fflag;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	dev_t dev = vp->v_rdev;
	int (*devclose) __P((dev_t, int, int, struct proc *));
	int mode, error;

	switch (vp->v_type) {

	case VCHR:
		/*
		 * Hack: a tty device that is a controlling terminal
		 * has a reference from the session structure.
		 * We cannot easily tell that a character device is
		 * a controlling terminal, unless it is the closing
		 * process' controlling terminal.  In that case,
		 * if the reference count is 2 (this last descriptor
		 * plus the session), release the reference from the session.
		 */
		if (vcount(vp) == 2 && ap->a_p &&
		    vp == ap->a_p->p_session->s_ttyvp) {
			ap->a_p->p_session->s_ttyvp = NULL;
			vrele(vp);
		}
		/*
		 * If the vnode is locked, then we are in the midst
		 * of forcably closing the device, otherwise we only
		 * close on last reference.
		 */
		if (vcount(vp) > 1 && (vp->v_flag & VXLOCK) == 0)
			return (0);
		devclose = cdevsw[major(dev)].d_close;
		mode = S_IFCHR;
		break;

	case VBLK:
#ifdef DEVFS_IMPLEMENTS_LOCKING
		/*
		 * On last close of a block device (that isn't mounted)
		 * we must invalidate any in core blocks, so that
		 * we can, for instance, change floppy disks.
		 */
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, ap->a_p);
		error = vinvalbuf(vp, V_SAVE, ap->a_cred, ap->a_p, 0, 0);
		VOP_UNLOCK(vp, 0, ap->a_p);
		if (error)
			return (error);
		/*
		 * We do not want to really close the device if it
		 * is still in use unless we are trying to close it
		 * forcibly. Since every use (buffer, vnode, swap, cmap)
		 * holds a reference to the vnode, and because we mark
		 * any other vnodes that alias this device, when the
		 * sum of the reference counts on all the aliased
		 * vnodes descends to one, we are on last close.
		 */
		if (vcount(vp) > 1 && (vp->v_flag & VXLOCK) == 0)
			return (0);
#else /* DEVFS_IMPLEMENTS_LOCKING */
		/*
		 * We do not want to really close the device if it
		 * is still in use unless we are trying to close it
		 * forcibly. Since every use (buffer, vnode, swap, cmap)
		 * holds a reference to the vnode, and because we mark
		 * any other vnodes that alias this device, when the
		 * sum of the reference counts on all the aliased
		 * vnodes descends to one, we are on last close.
		 */
		if (vcount(vp) > 1 && (vp->v_flag & VXLOCK) == 0)
			return (0);

		/*
		 * On last close of a block device (that isn't mounted)
		 * we must invalidate any in core blocks, so that
		 * we can, for instance, change floppy disks.
		 */
		error = vinvalbuf(vp, V_SAVE, ap->a_cred, ap->a_p, 0, 0);
		if (error)
			return (error);
#endif /* DEVFS_IMPLEMENTS_LOCKING */
		devclose = bdevsw[major(dev)].d_close;
		mode = S_IFBLK;
		break;

	default:
		panic("spec_close: not special");
	}

	return ((*devclose)(dev, ap->a_fflag, mode, ap->a_p));
}

/*
 * Print out the contents of a special device vnode.
 */
spec_print(ap)
	struct vop_print_args /* {
		struct vnode *a_vp;
	} */ *ap;
{

	printf("tag VT_NON, dev %d, %d\n", major(ap->a_vp->v_rdev),
		minor(ap->a_vp->v_rdev));
}

/*
 * Return POSIX pathconf information applicable to special devices.
 */
spec_pathconf(ap)
	struct vop_pathconf_args /* {
		struct vnode *a_vp;
		int a_name;
		int *a_retval;
	} */ *ap;
{

	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*ap->a_retval = LINK_MAX;
		return (0);
	case _PC_MAX_CANON:
		*ap->a_retval = MAX_CANON;
		return (0);
	case _PC_MAX_INPUT:
		*ap->a_retval = MAX_INPUT;
		return (0);
	case _PC_PIPE_BUF:
		*ap->a_retval = PIPE_BUF;
		return (0);
	case _PC_CHOWN_RESTRICTED:
		*ap->a_retval = 1;
		return (0);
	case _PC_VDISABLE:
		*ap->a_retval = _POSIX_VDISABLE;
		return (0);
	default:
		return (EINVAL);
	}
	/* NOTREACHED */
}

int
spec_devblocksize(ap)
        struct vop_devblocksize_args /* {
	        struct vnode *a_vp;
	        int *a_retval;
        } */ *ap;
{
        *ap->a_retval = (ap->a_vp->v_specsize);
        return (0);
}

/*
 * Special device failed operation
 */
spec_ebadf()
{

	return (EBADF);
}

/*
 * Special device bad operation
 */
spec_badop()
{

	panic("spec_badop called");
	/* NOTREACHED */
}

/* Blktooff derives file offset from logical block number */
int
spec_blktooff(ap)
	struct vop_blktooff_args /* {
		struct vnode *a_vp;
		daddr_t a_lblkno;
		off_t *a_offset;    
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;

	switch (vp->v_type) {
	case VCHR:
		*ap->a_offset = (off_t)-1; /* failure */
		return (EOPNOTSUPP);

	case VBLK:
		printf("spec_blktooff: not implemented for VBLK\n");
		*ap->a_offset = (off_t)-1; /* failure */
		return (EOPNOTSUPP);

	default:
		panic("spec_blktooff type");
	}
	/* NOTREACHED */
}

/* Offtoblk derives logical block number from file offset */
int
spec_offtoblk(ap)
	struct vop_offtoblk_args /* {
		struct vnode *a_vp;
		off_t a_offset;    
		daddr_t *a_lblkno;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;

	switch (vp->v_type) {
	case VCHR:
		*ap->a_lblkno = (daddr_t)-1; /* failure */
		return (EOPNOTSUPP);

	case VBLK:
		printf("spec_offtoblk: not implemented for VBLK\n");
		*ap->a_lblkno = (daddr_t)-1; /* failure */
		return (EOPNOTSUPP);

	default:
		panic("spec_offtoblk type");
	}
	/* NOTREACHED */
}
