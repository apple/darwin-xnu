/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/buf_internal.h>
#include <sys/mount_internal.h>
#include <sys/namei.h>
#include <sys/vnode_internal.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/user.h>
#include <sys/malloc.h>
#include <sys/disk.h>
#include <sys/uio_internal.h>
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
	{ &vnop_default_desc, (VOPFUNC)vn_default_error },
	{ &vnop_lookup_desc, (VOPFUNC)spec_lookup },		/* lookup */
	{ &vnop_create_desc, (VOPFUNC)err_create },		/* create */
	{ &vnop_mknod_desc, (VOPFUNC)err_mknod },		/* mknod */
	{ &vnop_open_desc, (VOPFUNC)spec_open },			/* open */
	{ &vnop_close_desc, (VOPFUNC)spec_close },		/* close */
	{ &vnop_access_desc, (VOPFUNC)spec_access },		/* access */
	{ &vnop_getattr_desc, (VOPFUNC)spec_getattr },		/* getattr */
	{ &vnop_setattr_desc, (VOPFUNC)spec_setattr },		/* setattr */
	{ &vnop_read_desc, (VOPFUNC)spec_read },			/* read */
	{ &vnop_write_desc, (VOPFUNC)spec_write },		/* write */
	{ &vnop_ioctl_desc, (VOPFUNC)spec_ioctl },		/* ioctl */
	{ &vnop_select_desc, (VOPFUNC)spec_select },		/* select */
	{ &vnop_revoke_desc, (VOPFUNC)nop_revoke },		/* revoke */
	{ &vnop_mmap_desc, (VOPFUNC)err_mmap },			/* mmap */
	{ &vnop_fsync_desc, (VOPFUNC)spec_fsync },		/* fsync */
	{ &vnop_remove_desc, (VOPFUNC)err_remove },		/* remove */
	{ &vnop_link_desc, (VOPFUNC)err_link },			/* link */
	{ &vnop_rename_desc, (VOPFUNC)err_rename },		/* rename */
	{ &vnop_mkdir_desc, (VOPFUNC)err_mkdir },		/* mkdir */
	{ &vnop_rmdir_desc, (VOPFUNC)err_rmdir },		/* rmdir */
	{ &vnop_symlink_desc, (VOPFUNC)err_symlink },		/* symlink */
	{ &vnop_readdir_desc, (VOPFUNC)err_readdir },		/* readdir */
	{ &vnop_readlink_desc, (VOPFUNC)err_readlink },		/* readlink */
	{ &vnop_inactive_desc, (VOPFUNC)nop_inactive },		/* inactive */
	{ &vnop_reclaim_desc, (VOPFUNC)nop_reclaim },		/* reclaim */
	{ &vnop_strategy_desc, (VOPFUNC)spec_strategy },		/* strategy */
	{ &vnop_pathconf_desc, (VOPFUNC)spec_pathconf },		/* pathconf */
	{ &vnop_advlock_desc, (VOPFUNC)err_advlock },		/* advlock */
	{ &vnop_bwrite_desc, (VOPFUNC)spec_bwrite },		/* bwrite */
	{ &vnop_pagein_desc, (VOPFUNC)err_pagein },		/* Pagein */
	{ &vnop_pageout_desc, (VOPFUNC)err_pageout },		/* Pageout */
        { &vnop_copyfile_desc, (VOPFUNC)err_copyfile },		/* Copyfile */
	{ &vnop_blktooff_desc, (VOPFUNC)spec_blktooff },		/* blktooff */
	{ &vnop_offtoblk_desc, (VOPFUNC)spec_offtoblk },		/* offtoblk */
	{ &vnop_blockmap_desc, (VOPFUNC)spec_blockmap },		/* blockmap */
	{ (struct vnodeop_desc*)NULL, (int(*)())NULL }
};
struct vnodeopv_desc spec_vnodeop_opv_desc =
	{ &spec_vnodeop_p, spec_vnodeop_entries };


static void set_blocksize(vnode_t, dev_t);


/*
 * Trivial lookup routine that always fails.
 */
int
spec_lookup(ap)
	struct vnop_lookup_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		vfs_context_t a_context;
	} */ *ap;
{

	*ap->a_vpp = NULL;
	return (ENOTDIR);
}

static void
set_blocksize(struct vnode *vp, dev_t dev)
{
    int (*size)(dev_t);
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

		if ((u_int)maj >= (u_int)nblkdev)
			return;

		vnode_lock(vp);
		set_blocksize(vp, dev);
		vnode_unlock(vp);
	}

}


/*
 * Open a special file.
 */
int
spec_open(ap)
	struct vnop_open_args /* {
		struct vnode *a_vp;
		int  a_mode;
		vfs_context_t a_context;
	} */ *ap;
{
	struct proc *p = vfs_context_proc(ap->a_context);
	kauth_cred_t cred = vfs_context_ucred(ap->a_context);
	struct vnode *vp = ap->a_vp;
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
		if ((u_int)maj >= (u_int)nchrdev)
			return (ENXIO);
		if (cred != FSCRED && (ap->a_mode & FWRITE)) {
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
				if ((bdev = chrtoblk(dev)) != NODEV && check_mountedon(bdev, VBLK, &error))
					return (error);
				if (iskmemdev(dev))
					return (EPERM);
			}
		}
		if (cdevsw[maj].d_type == D_TTY) {
			vnode_lock(vp);
			vp->v_flag |= VISTTY;
			vnode_unlock(vp);
		}
		error = (*cdevsw[maj].d_open)(dev, ap->a_mode, S_IFCHR, p);
		return (error);

	case VBLK:
		if ((u_int)maj >= (u_int)nblkdev)
			return (ENXIO);
		/*
		 * When running in very secure mode, do not allow
		 * opens for writing of any disk block devices.
		 */
		if (securelevel >= 2 && cred != FSCRED &&
		    (ap->a_mode & FWRITE) && bdevsw[maj].d_type == D_DISK)
			return (EPERM);
		/*
		 * Do not allow opens of block devices that are
		 * currently mounted.
		 */
		if ( (error = vfs_mountedon(vp)) )
			return (error);
		error = (*bdevsw[maj].d_open)(dev, ap->a_mode, S_IFBLK, p);
		if (!error) {
		    u_int64_t blkcnt;
		    u_int32_t blksize;
			int setsize = 0;
			u_int32_t size512 = 512;


		    if (!VNOP_IOCTL(vp, DKIOCGETBLOCKSIZE, (caddr_t)&blksize, 0, ap->a_context)) {
				/* Switch to 512 byte sectors (temporarily) */

				if (!VNOP_IOCTL(vp, DKIOCSETBLOCKSIZE, (caddr_t)&size512, FWRITE, ap->a_context)) {
			    	/* Get the number of 512 byte physical blocks. */
			    	if (!VNOP_IOCTL(vp, DKIOCGETBLOCKCOUNT, (caddr_t)&blkcnt, 0, ap->a_context)) {
						setsize = 1;
			    	}
				}
				/* If it doesn't set back, we can't recover */
				if (VNOP_IOCTL(vp, DKIOCSETBLOCKSIZE, (caddr_t)&blksize, FWRITE, ap->a_context))
			    	error = ENXIO;
		    }


			vnode_lock(vp);
		    set_blocksize(vp, dev);

		    /*
		     * Cache the size in bytes of the block device for later
		     * use by spec_write().
		     */
			if (setsize)
				vp->v_specdevsize = blkcnt * (u_int64_t)size512;
			else
		    	vp->v_specdevsize = (u_int64_t)0;	/* Default: Can't get */
			
			vnode_unlock(vp);

		}
		return(error);
	default:
	        panic("spec_open type");
	}
	return (0);
}

/*
 * Vnode op for read
 */
int
spec_read(ap)
	struct vnop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		vfs_context_t a_context;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	register struct uio *uio = ap->a_uio;
	struct buf *bp;
	daddr64_t bn, nextbn;
	long bsize, bscale;
	int devBlockSize=0;
	int n, on;
	int error = 0;
	dev_t dev;

#if DIAGNOSTIC
	if (uio->uio_rw != UIO_READ)
		panic("spec_read mode");
	if (UIO_SEG_IS_USER_SPACE(uio->uio_segflg))
		panic("spec_read proc");
#endif
	if (uio_resid(uio) == 0)
		return (0);

	switch (vp->v_type) {

	case VCHR:
		error = (*cdevsw[major(vp->v_rdev)].d_read)
			(vp->v_rdev, uio, ap->a_ioflag);
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

			bn = (daddr64_t)((uio->uio_offset / devBlockSize) &~ (bscale - 1));
			
			if (vp->v_speclastr + bscale == bn) {
			        nextbn = bn + bscale;
				error = buf_breadn(vp, bn, (int)bsize, &nextbn,
					       (int *)&bsize, 1, NOCRED, &bp);
			} else
			        error = buf_bread(vp, bn, (int)bsize, NOCRED, &bp);

			vnode_lock(vp);
			vp->v_speclastr = bn;
			vnode_unlock(vp);

			n = bsize - buf_resid(bp);
			if ((on > n) || error) {
			        if (!error)
				        error = EINVAL;
				buf_brelse(bp);
				return (error);
			}
			// LP64todo - fix this!
			n = min((unsigned)(n  - on), uio_resid(uio));

			error = uiomove((char *)buf_dataptr(bp) + on, n, uio);
			if (n + on == bsize)
				buf_markaged(bp);
			buf_brelse(bp);
		} while (error == 0 && uio_resid(uio) > 0 && n != 0);
		return (error);

	default:
		panic("spec_read type");
	}
	/* NOTREACHED */

	return (0);
}

/*
 * Vnode op for write
 */
int
spec_write(ap)
	struct vnop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		vfs_context_t a_context;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	register struct uio *uio = ap->a_uio;
	struct buf *bp;
	daddr64_t bn;
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
	if (UIO_SEG_IS_USER_SPACE(uio->uio_segflg))
		panic("spec_write proc");
#endif

	switch (vp->v_type) {

	case VCHR:
		error = (*cdevsw[major(vp->v_rdev)].d_write)
			(vp->v_rdev, uio, ap->a_ioflag);
		return (error);

	case VBLK:
		if (uio_resid(uio) == 0)
			return (0);
		if (uio->uio_offset < 0)
			return (EINVAL);

		io_sync = (ap->a_ioflag & IO_SYNC);
		// LP64todo - fix this!
		io_size = uio_resid(uio);

		dev = (vp->v_rdev);

		devBlockSize = vp->v_specsize;
		if (devBlockSize > PAGE_SIZE)
			return(EINVAL);

	        bscale = PAGE_SIZE / devBlockSize;
		blkmask = bscale - 1;
		bsize = bscale * devBlockSize;
		

		do {
			bn = (daddr64_t)((uio->uio_offset / devBlockSize) &~ blkmask);
			on = uio->uio_offset % bsize;

			// LP64todo - fix this!
			n = min((unsigned)(bsize - on), uio_resid(uio));

			/*
			 * Use buf_getblk() as an optimization IFF:
			 *
			 * 1)	We are reading exactly a block on a block
			 *	aligned boundary
			 * 2)	We know the size of the device from spec_open
			 * 3)	The read doesn't span the end of the device
			 *
			 * Otherwise, we fall back on buf_bread().
			 */
			if (n == bsize &&
			    vp->v_specdevsize != (u_int64_t)0 &&
			    (uio->uio_offset + (u_int64_t)n) > vp->v_specdevsize) {
			    /* reduce the size of the read to what is there */
			    n = (uio->uio_offset + (u_int64_t)n) - vp->v_specdevsize;
			}

			if (n == bsize)
			        bp = buf_getblk(vp, bn, bsize, 0, 0, BLK_WRITE);
			else
			        error = (int)buf_bread(vp, bn, bsize, NOCRED, &bp);

			/* Translate downstream error for upstream, if needed */
			if (!error)
				error = (int)buf_error(bp);
			if (error) {
				buf_brelse(bp);
				return (error);
			}
			n = min(n, bsize - buf_resid(bp));

			error = uiomove((char *)buf_dataptr(bp) + on, n, uio);
			if (error) {
				buf_brelse(bp);
				return (error);
			}
			buf_markaged(bp);

			if (io_sync) 
			        error = buf_bwrite(bp);
			else {
			        if ((n + on) == bsize)
				        error = buf_bawrite(bp);
				else
				        error = buf_bdwrite(bp);
			}
		} while (error == 0 && uio_resid(uio) > 0 && n != 0);
		return (error);

	default:
		panic("spec_write type");
	}
	/* NOTREACHED */

	return (0);
}

/*
 * Device ioctl operation.
 */
int
spec_ioctl(ap)
	struct vnop_ioctl_args /* {
		struct vnode *a_vp;
		int  a_command;
		caddr_t  a_data;
		int  a_fflag;
		vfs_context_t a_context;
	} */ *ap;
{
	proc_t p = vfs_context_proc(ap->a_context);
	dev_t dev = ap->a_vp->v_rdev;

	switch (ap->a_vp->v_type) {

	case VCHR:
		return ((*cdevsw[major(dev)].d_ioctl)(dev, ap->a_command, ap->a_data,
		    ap->a_fflag, p));

	case VBLK:
	        if (ap->a_command == 0 && (int)ap->a_data == B_TAPE) {
			if (bdevsw[major(dev)].d_type == D_TAPE)
				return (0);
			else
				return (1);
		}
		return ((*bdevsw[major(dev)].d_ioctl)(dev, ap->a_command, ap->a_data,
		   ap->a_fflag, p));

	default:
		panic("spec_ioctl");
		/* NOTREACHED */
	}
	return (0);
}

int
spec_select(ap)
	struct vnop_select_args /* {
		struct vnode *a_vp;
		int  a_which;
		int  a_fflags;
		void * a_wql;
		vfs_context_t a_context;
	} */ *ap;
{
	proc_t p = vfs_context_proc(ap->a_context);
	register dev_t dev;

	switch (ap->a_vp->v_type) {

	default:
		return (1);		/* XXX */

	case VCHR:
		dev = ap->a_vp->v_rdev;
		return (*cdevsw[major(dev)].d_select)(dev, ap->a_which, ap->a_wql, p);
	}
}

/*
 * Synch buffers associated with a block device
 */
int
spec_fsync_internal(vnode_t vp, int waitfor, __unused vfs_context_t context)
{
	if (vp->v_type == VCHR)
		return (0);
	/*
	 * Flush all dirty buffers associated with a block device.
	 */
	buf_flushdirtyblks(vp, waitfor == MNT_WAIT, 0, (char *)"spec_fsync");

	return (0);
}

int
spec_fsync(ap)
	struct vnop_fsync_args /* {
		struct vnode *a_vp;
		int  a_waitfor;
		vfs_context_t a_context;
	} */ *ap;
{
	return spec_fsync_internal(ap->a_vp, ap->a_waitfor, ap->a_context);
}

/*
 * Just call the device strategy routine
 */
extern int hard_throttle_on_root;


#define LOWPRI_DELAY_MSECS	200
#define LOWPRI_WINDOW_MSECS	200

int 	lowpri_IO_window_msecs = LOWPRI_WINDOW_MSECS;
int 	lowpri_IO_delay_msecs  = LOWPRI_DELAY_MSECS;

struct timeval last_normal_IO_timestamp;
struct timeval last_lowpri_IO_timestamp;
struct timeval lowpri_IO_window = { 0, LOWPRI_WINDOW_MSECS * 1000 };

int
spec_strategy(ap)
	struct vnop_strategy_args /* {
		struct buf *a_bp;
	} */ *ap;
{
        buf_t	bp;
	int	bflags;
	dev_t	bdev;
	proc_t	p;
        struct timeval elapsed;

        bp = ap->a_bp;
	bdev = buf_device(bp);
	bflags = buf_flags(bp);

        if (kdebug_enable) {
	        int    code = 0;

		if (bflags & B_READ)
		        code |= DKIO_READ;
		if (bflags & B_ASYNC)
		        code |= DKIO_ASYNC;

		if (bflags & B_META)
		        code |= DKIO_META;
		else if (bflags & B_PAGEIO)
		        code |= DKIO_PAGING;

		KERNEL_DEBUG_CONSTANT(FSDBG_CODE(DBG_DKRW, code) | DBG_FUNC_NONE,
				      (unsigned int)bp, bdev, (int)buf_blkno(bp), buf_count(bp), 0);
        }
	if (((bflags & (B_PAGEIO | B_READ)) == (B_PAGEIO | B_READ)) &&
	    (buf_vnode(bp)->v_mount->mnt_kern_flag & MNTK_ROOTDEV))
	        hard_throttle_on_root = 1;

	if ( lowpri_IO_delay_msecs && lowpri_IO_window_msecs ) {
	        p = current_proc();

	        if ( (p == NULL) || !(p->p_lflag & P_LLOW_PRI_IO)) {
		        if (!(p->p_lflag & P_LBACKGROUND_IO))
			        microuptime(&last_normal_IO_timestamp);
		} else {
		        microuptime(&last_lowpri_IO_timestamp);

			elapsed = last_lowpri_IO_timestamp;
			timevalsub(&elapsed, &last_normal_IO_timestamp);

			lowpri_IO_window.tv_sec  = lowpri_IO_window_msecs / 1000;
			lowpri_IO_window.tv_usec = (lowpri_IO_window_msecs % 1000) * 1000;

			if (timevalcmp(&elapsed, &lowpri_IO_window, <)) {
			        struct uthread	*ut;

				/*
				 * I'd really like to do the IOSleep here, but
				 * we may be holding all kinds of filesystem related locks
				 * and the pages for this I/O marked 'busy'...
				 * we don't want to cause a normal task to block on
				 * one of these locks while we're throttling a task marked
				 * for low priority I/O... we'll mark the uthread and
				 * do the delay just before we return from the system
				 * call that triggered this I/O or from vnode_pagein
				 */
				ut = get_bsdthread_info(current_thread());
				ut->uu_lowpri_delay = lowpri_IO_delay_msecs;
			}
		}
	}
        (*bdevsw[major(bdev)].d_strategy)(bp);

        return (0);
}


/*
 * This is a noop, simply returning what one has been given.
 */
int
spec_blockmap(__unused struct vnop_blockmap_args *ap)
{
	return (ENOTSUP);
}


/*
 * Device close routine
 */
int
spec_close(ap)
	struct vnop_close_args /* {
		struct vnode *a_vp;
		int  a_fflag;
		vfs_context_t a_context;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	dev_t dev = vp->v_rdev;
	int (*devclose)(dev_t, int, int, struct proc *);
	int mode, error;
	struct proc *p = vfs_context_proc(ap->a_context);

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
		if (vcount(vp) == 2 && p &&
		    vp == p->p_session->s_ttyvp) {
			p->p_session->s_ttyvp = NULL;
			vnode_rele(vp);
		}
		/*
		 * close on last reference.
		 */
		if (vcount(vp) > 1)
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
	        if ((error = spec_fsync_internal(vp, MNT_WAIT, ap->a_context)))
		        return (error);

		error = buf_invalidateblks(vp, BUF_WRITE_DATA, 0, 0);
		if (error)
			return (error);
		/*
		 * Since every use (buffer, vnode, swap, blockmap)
		 * holds a reference to the vnode, and because we mark
		 * any other vnodes that alias this device, when the
		 * sum of the reference counts on all the aliased
		 * vnodes descends to one, we are on last close.
		 */
		if (vcount(vp) > 1)
			return (0);
#else /* DEVFS_IMPLEMENTS_LOCKING */
		/*
		 * Since every use (buffer, vnode, swap, blockmap)
		 * holds a reference to the vnode, and because we mark
		 * any other vnodes that alias this device, when the
		 * sum of the reference counts on all the aliased
		 * vnodes descends to one, we are on last close.
		 */
		if (vcount(vp) > 1)
			return (0);

		/*
		 * On last close of a block device (that isn't mounted)
		 * we must invalidate any in core blocks, so that
		 * we can, for instance, change floppy disks.
		 */
	        if ((error = spec_fsync_internal(vp, MNT_WAIT, ap->a_context)))
		        return (error);

		error = buf_invalidateblks(vp, BUF_WRITE_DATA, 0, 0);
		if (error)
			return (error);
#endif /* DEVFS_IMPLEMENTS_LOCKING */
		devclose = bdevsw[major(dev)].d_close;
		mode = S_IFBLK;
		break;

	default:
		panic("spec_close: not special");
	}

	return ((*devclose)(dev, ap->a_fflag, mode, p));
}

/*
 * Return POSIX pathconf information applicable to special devices.
 */
int
spec_pathconf(ap)
	struct vnop_pathconf_args /* {
		struct vnode *a_vp;
		int a_name;
		int *a_retval;
		vfs_context_t a_context;
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

/*
 * Special device failed operation
 */
int
spec_ebadf(__unused void *dummy)
{

	return (EBADF);
}

/*
 * Special device bad operation
 */
int
spec_badop()
{

	panic("spec_badop called");
	/* NOTREACHED */
}

/* Blktooff derives file offset from logical block number */
int
spec_blktooff(ap)
	struct vnop_blktooff_args /* {
		struct vnode *a_vp;
		daddr64_t a_lblkno;
		off_t *a_offset;    
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;

	switch (vp->v_type) {
	case VCHR:
		*ap->a_offset = (off_t)-1; /* failure */
		return (ENOTSUP);

	case VBLK:
		printf("spec_blktooff: not implemented for VBLK\n");
		*ap->a_offset = (off_t)-1; /* failure */
		return (ENOTSUP);

	default:
		panic("spec_blktooff type");
	}
	/* NOTREACHED */

	return (0);
}

/* Offtoblk derives logical block number from file offset */
int
spec_offtoblk(ap)
	struct vnop_offtoblk_args /* {
		struct vnode *a_vp;
		off_t a_offset;    
		daddr64_t *a_lblkno;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;

	switch (vp->v_type) {
	case VCHR:
		*ap->a_lblkno = (daddr64_t)-1; /* failure */
		return (ENOTSUP);

	case VBLK:
		printf("spec_offtoblk: not implemented for VBLK\n");
		*ap->a_lblkno = (daddr64_t)-1; /* failure */
		return (ENOTSUP);

	default:
		panic("spec_offtoblk type");
	}
	/* NOTREACHED */

	return (0);
}
