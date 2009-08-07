/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
#include <sys/resource.h>
#include <miscfs/specfs/specdev.h>
#include <vfs/vfs_support.h>

#include <sys/kdebug.h>

/* XXX following three prototypes should be in a header file somewhere */
extern int	isdisk(dev_t dev, int type);
extern dev_t	chrtoblk(dev_t dev);
extern int	iskmemdev(dev_t dev);

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
spec_lookup(struct vnop_lookup_args *ap)
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
spec_open(struct vnop_open_args *ap)
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
spec_read(struct vnop_read_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
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

			error = uiomove((char *)0 + buf_dataptr(bp) + on, n, uio);
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
spec_write(struct vnop_write_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct buf *bp;
	daddr64_t bn;
	int bsize, blkmask, bscale;
	int io_sync;
	int io_size;
	int devBlockSize=0;
	int n, on;
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

			error = uiomove((char *)0 + buf_dataptr(bp) + on, n, uio);
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
spec_ioctl(struct vnop_ioctl_args *ap)
{
	proc_t p = vfs_context_proc(ap->a_context);
	dev_t dev = ap->a_vp->v_rdev;

	switch (ap->a_vp->v_type) {

	case VCHR:
		return ((*cdevsw[major(dev)].d_ioctl)(dev, ap->a_command, ap->a_data,
		    ap->a_fflag, p));

	case VBLK:
	        if (ap->a_command == 0 && (unsigned int)ap->a_data == B_TAPE) {
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
spec_select(struct vnop_select_args *ap)
{
	proc_t p = vfs_context_proc(ap->a_context);
	dev_t dev;

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
	buf_flushdirtyblks(vp, waitfor == MNT_WAIT, 0, "spec_fsync");

	return (0);
}

int
spec_fsync(struct vnop_fsync_args *ap)
{
	return spec_fsync_internal(ap->a_vp, ap->a_waitfor, ap->a_context);
}

/*
 * Just call the device strategy routine
 */
extern int hard_throttle_on_root;
void IOSleep(int);

// the low priority process may wait for at most LOWPRI_MAX_DELAY millisecond
#define LOWPRI_INITIAL_WINDOW_MSECS 100
#define LOWPRI_WINDOW_MSECS_INC	50
#define LOWPRI_MAX_WINDOW_MSECS 200
#define LOWPRI_MAX_WAITING_MSECS 200
#define LOWPRI_SLEEP_INTERVAL 5

struct _throttle_io_info_t {
	struct timeval	last_normal_IO_timestamp;
	struct timeval  last_IO_timestamp;
	SInt32 numthreads_throttling;
};

struct _throttle_io_info_t _throttle_io_info[LOWPRI_MAX_NUM_DEV];
int 	lowpri_IO_initial_window_msecs  = LOWPRI_INITIAL_WINDOW_MSECS;
int 	lowpri_IO_window_msecs_inc  = LOWPRI_WINDOW_MSECS_INC;
int 	lowpri_max_window_msecs  = LOWPRI_MAX_WINDOW_MSECS;
int     lowpri_max_waiting_msecs = LOWPRI_MAX_WAITING_MSECS;

SYSCTL_INT(_debug, OID_AUTO, lowpri_IO_initial_window_msecs, CTLFLAG_RW, &lowpri_IO_initial_window_msecs, LOWPRI_INITIAL_WINDOW_MSECS, "");
SYSCTL_INT(_debug, OID_AUTO, lowpri_IO_window_inc, CTLFLAG_RW, &lowpri_IO_window_msecs_inc, LOWPRI_INITIAL_WINDOW_MSECS, "");
SYSCTL_INT(_debug, OID_AUTO, lowpri_max_window_msecs, CTLFLAG_RW, &lowpri_max_window_msecs, LOWPRI_INITIAL_WINDOW_MSECS, "");
SYSCTL_INT(_debug, OID_AUTO, lowpri_max_waiting_msecs, CTLFLAG_RW, &lowpri_max_waiting_msecs, LOWPRI_INITIAL_WINDOW_MSECS, "");

void
throttle_info_get_last_io_time(mount_t mp, struct timeval *tv)
{
	size_t devbsdunit;
		
	devbsdunit = mp->mnt_devbsdunit;

	if (devbsdunit < LOWPRI_MAX_NUM_DEV) {
		*tv = _throttle_io_info[devbsdunit].last_IO_timestamp;
	} else {
		memset(tv, 0, sizeof(*tv));
	}
}

void
update_last_io_time(mount_t mp)
{
	size_t devbsdunit;
		
	devbsdunit = mp->mnt_devbsdunit;

	if (devbsdunit < LOWPRI_MAX_NUM_DEV) {
		microuptime(&_throttle_io_info[devbsdunit].last_IO_timestamp);
	}
}

int throttle_io_will_be_throttled(int lowpri_window_msecs, size_t devbsdunit)
{
	struct timeval elapsed;
	int elapsed_msecs;

	microuptime(&elapsed);
	timevalsub(&elapsed, &_throttle_io_info[devbsdunit].last_normal_IO_timestamp);
	elapsed_msecs = elapsed.tv_sec * 1000 + elapsed.tv_usec / 1000;

	if (lowpri_window_msecs == -1) // use the max waiting time
		lowpri_window_msecs = lowpri_max_waiting_msecs;

	return elapsed_msecs < lowpri_window_msecs;
}

void throttle_lowpri_io(boolean_t ok_to_sleep)
{
	int i;
	int max_try_num;
	struct uthread *ut;

	ut = get_bsdthread_info(current_thread());

	if (ut->uu_lowpri_window == 0)
		return;

	max_try_num = lowpri_max_waiting_msecs / LOWPRI_SLEEP_INTERVAL * MAX(1, _throttle_io_info[ut->uu_devbsdunit].numthreads_throttling);

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 97)) | DBG_FUNC_START,
		     ut->uu_lowpri_window, 0, 0, 0, 0);

	if (ok_to_sleep == TRUE) {
		for (i=0; i<max_try_num; i++) {
			if (throttle_io_will_be_throttled(ut->uu_lowpri_window, ut->uu_devbsdunit)) {
				IOSleep(LOWPRI_SLEEP_INTERVAL);
			} else {
				break;
			}
		}
	}
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 97)) | DBG_FUNC_END,
		     ut->uu_lowpri_window, i*5, 0, 0, 0);
	SInt32 oldValue;
	oldValue = OSDecrementAtomic(&_throttle_io_info[ut->uu_devbsdunit].numthreads_throttling);
	ut->uu_lowpri_window = 0;

	if (oldValue <= 0) {
		panic("%s: numthreads negative", __func__);
	}
}

int throttle_get_io_policy(struct uthread **ut)
{
	int policy = IOPOL_DEFAULT;
	proc_t p = current_proc();

	*ut = get_bsdthread_info(current_thread());
		
	if (p != NULL)
		policy = p->p_iopol_disk;

	if (*ut != NULL) {
		// the I/O policy of the thread overrides that of the process
		// unless the I/O policy of the thread is default
		if ((*ut)->uu_iopol_disk != IOPOL_DEFAULT)
			policy = (*ut)->uu_iopol_disk;
	}
	return policy;
}

int
spec_strategy(struct vnop_strategy_args *ap)
{
        buf_t	bp;
	int	bflags;
	dev_t	bdev;

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

	if (lowpri_IO_initial_window_msecs) {
		struct uthread	*ut;
		int policy;
		int is_throttleable_io = 0;
		int is_passive_io = 0;
		size_t devbsdunit;
		SInt32 oldValue;

		policy = throttle_get_io_policy(&ut);

		switch (policy) {
		case IOPOL_DEFAULT:
		case IOPOL_NORMAL:
			break;
		case IOPOL_THROTTLE:
			is_throttleable_io = 1;
			break;
		case IOPOL_PASSIVE:
			is_passive_io = 1;
			break;
		default:
			printf("unknown I/O policy %d", policy);
			break;
		}

		if (!is_throttleable_io && ISSET(bflags, B_PASSIVE))
		    is_passive_io |= 1;

		if (buf_vnode(bp)->v_mount != NULL)
			devbsdunit = buf_vnode(bp)->v_mount->mnt_devbsdunit;
		else
			devbsdunit = LOWPRI_MAX_NUM_DEV - 1;
		if (!is_throttleable_io) {
			if (!is_passive_io){
				microuptime(&_throttle_io_info[devbsdunit].last_normal_IO_timestamp);
			}
		} else {
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
			if (ut->uu_lowpri_window == 0) {
				ut->uu_devbsdunit = devbsdunit;
				oldValue = OSIncrementAtomic(&_throttle_io_info[devbsdunit].numthreads_throttling);
				if (oldValue < 0) {
					panic("%s: numthreads negative", __func__);
				}
				ut->uu_lowpri_window = lowpri_IO_initial_window_msecs;
				ut->uu_lowpri_window += lowpri_IO_window_msecs_inc * oldValue;
			} else {
				if (ut->uu_devbsdunit != devbsdunit) { // the thread sends I/Os to different devices within the same system call
					// keep track of the numthreads in the right device
					OSDecrementAtomic(&_throttle_io_info[ut->uu_devbsdunit].numthreads_throttling);
					OSIncrementAtomic(&_throttle_io_info[devbsdunit].numthreads_throttling);
					ut->uu_devbsdunit = devbsdunit;
				}
				int numthreads = MAX(1, _throttle_io_info[devbsdunit].numthreads_throttling);
				ut->uu_lowpri_window += lowpri_IO_window_msecs_inc * numthreads;
				if (ut->uu_lowpri_window > lowpri_max_window_msecs * numthreads)
					ut->uu_lowpri_window = lowpri_max_window_msecs * numthreads;
			}
		}
	}

	if ((bflags & B_READ) == 0) {
		size_t devbsdunit;

		if (buf_vnode(bp)->v_mount != NULL)
			devbsdunit = buf_vnode(bp)->v_mount->mnt_devbsdunit;
		else
			devbsdunit = LOWPRI_MAX_NUM_DEV - 1;
		
		microuptime(&_throttle_io_info[devbsdunit].last_IO_timestamp);
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
spec_close(struct vnop_close_args *ap)
{
	struct vnode *vp = ap->a_vp;
	dev_t dev = vp->v_rdev;
	int (*devclose)(dev_t, int, int, struct proc *);
	int mode, error;
	int flags = ap->a_fflag;
	struct proc *p = vfs_context_proc(ap->a_context);
	struct session *sessp;

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
		sessp = proc_session(p);
		if (sessp != SESSION_NULL) {
			if ((vcount(vp) == 2) && 
		    		(vp == sessp->s_ttyvp)) {
				session_lock(sessp);
				sessp->s_ttyvp = NULL;
				sessp->s_ttyvid = 0;
				sessp->s_ttyp = NULL;
				sessp->s_ttypgrpid = NO_PID;
				session_unlock(sessp);
				vnode_rele(vp);
			}
			session_rele(sessp);
		}

		devclose = cdevsw[major(dev)].d_close;
		mode = S_IFCHR;
		/*
		 * close on last reference or on vnode revoke call
		 */
		if ((flags & IO_REVOKE) != 0)
			break;
		if (vcount(vp) > 1)
			return (0);
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
		if (vcount(vp) > 0)
			return (0);
#else /* DEVFS_IMPLEMENTS_LOCKING */
		/*
		 * Since every use (buffer, vnode, swap, blockmap)
		 * holds a reference to the vnode, and because we mark
		 * any other vnodes that alias this device, when the
		 * sum of the reference counts on all the aliased
		 * vnodes descends to one, we are on last close.
		 */
		if (vcount(vp) > 0)
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
		return(EBADF);
	}

	return ((*devclose)(dev, flags, mode, p));
}

/*
 * Return POSIX pathconf information applicable to special devices.
 */
int
spec_pathconf(struct vnop_pathconf_args *ap)
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
		*ap->a_retval = 200112;		/* _POSIX_CHOWN_RESTRICTED */
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

/* Blktooff derives file offset from logical block number */
int
spec_blktooff(struct vnop_blktooff_args *ap)
{
	struct vnode *vp = ap->a_vp;

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
spec_offtoblk(struct vnop_offtoblk_args *ap)
{
	struct vnode *vp = ap->a_vp;

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
