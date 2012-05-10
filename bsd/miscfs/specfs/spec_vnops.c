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
#include <sys/vnode_internal.h>
#include <sys/file_internal.h>
#include <sys/namei.h>
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
#include <kern/assert.h>
#include <kern/task.h>

#include <sys/kdebug.h>

/* XXX following three prototypes should be in a header file somewhere */
extern dev_t	chrtoblk(dev_t dev);
extern int	iskmemdev(dev_t dev);
extern int	bpfkqfilter(dev_t dev, struct knote *kn);
extern int	ptsd_kqfilter(dev_t dev, struct knote *kn);

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


struct _throttle_io_info_t {
	struct timeval	last_normal_IO_timestamp;
	struct timeval	last_IO_timestamp;
	SInt32 numthreads_throttling;
	SInt32 refcnt;
	SInt32 alloc;
};

struct _throttle_io_info_t _throttle_io_info[LOWPRI_MAX_NUM_DEV];

static void throttle_info_update_internal(void *throttle_info, int flags, boolean_t isssd);



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
		
		devsw_lock(dev, S_IFCHR);
		error = (*cdevsw[maj].d_open)(dev, ap->a_mode, S_IFCHR, p);

		if (error == 0) {
			vp->v_specinfo->si_opencount++;
		}

		devsw_unlock(dev, S_IFCHR);

		if (error == 0 && cdevsw[maj].d_type == D_DISK && !vp->v_un.vu_specinfo->si_initted) {
			int	isssd = 0;
			uint64_t throttle_mask = 0;
			uint32_t devbsdunit = 0;

			if (VNOP_IOCTL(vp, DKIOCGETTHROTTLEMASK, (caddr_t)&throttle_mask, 0, NULL) == 0) {
			
				if (VNOP_IOCTL(vp, DKIOCISSOLIDSTATE, (caddr_t)&isssd, 0, ap->a_context) == 0) {
					/*
					 * as a reasonable approximation, only use the lowest bit of the mask
					 * to generate a disk unit number
					 */
					devbsdunit = num_trailing_0(throttle_mask);

					vnode_lock(vp);
					
					vp->v_un.vu_specinfo->si_isssd = isssd;
					vp->v_un.vu_specinfo->si_devbsdunit = devbsdunit;
					vp->v_un.vu_specinfo->si_throttle_mask = throttle_mask;
					vp->v_un.vu_specinfo->si_throttleable = 1;
					vp->v_un.vu_specinfo->si_initted = 1;

					vnode_unlock(vp);
				}
			}
			if (vp->v_un.vu_specinfo->si_initted == 0) {
				vnode_lock(vp);
				vp->v_un.vu_specinfo->si_initted = 1;
				vnode_unlock(vp);
			}
		}
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

		devsw_lock(dev, S_IFBLK);
		error = (*bdevsw[maj].d_open)(dev, ap->a_mode, S_IFBLK, p);
		if (!error) {
			vp->v_specinfo->si_opencount++;
		}
		devsw_unlock(dev, S_IFBLK);

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
                if (cdevsw[major(vp->v_rdev)].d_type == D_DISK && vp->v_un.vu_specinfo->si_throttleable) {
			struct _throttle_io_info_t *throttle_info;

			throttle_info = &_throttle_io_info[vp->v_un.vu_specinfo->si_devbsdunit];

			throttle_info_update_internal(throttle_info, 0, vp->v_un.vu_specinfo->si_isssd);
                }

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
spec_write(struct vnop_write_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct buf *bp;
	daddr64_t bn;
	int bsize, blkmask, bscale;
	int io_sync;
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
                if (cdevsw[major(vp->v_rdev)].d_type == D_DISK && vp->v_un.vu_specinfo->si_throttleable) {
			struct _throttle_io_info_t *throttle_info;

			throttle_info = &_throttle_io_info[vp->v_un.vu_specinfo->si_devbsdunit];

			throttle_info_update_internal(throttle_info, 0, vp->v_un.vu_specinfo->si_isssd);

			microuptime(&throttle_info->last_IO_timestamp);
                }

		error = (*cdevsw[major(vp->v_rdev)].d_write)
			(vp->v_rdev, uio, ap->a_ioflag);

		return (error);

	case VBLK:
		if (uio_resid(uio) == 0)
			return (0);
		if (uio->uio_offset < 0)
			return (EINVAL);

		io_sync = (ap->a_ioflag & IO_SYNC);

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
spec_ioctl(struct vnop_ioctl_args *ap)
{
	proc_t p = vfs_context_proc(ap->a_context);
	dev_t dev = ap->a_vp->v_rdev;
	int	retval = 0;

	KERNEL_DEBUG_CONSTANT(FSDBG_CODE(DBG_IOCTL, 0) | DBG_FUNC_START,
			      (unsigned int)dev, (unsigned int)ap->a_command, (unsigned int)ap->a_fflag, (unsigned int)ap->a_vp->v_type, 0);

	switch (ap->a_vp->v_type) {

	case VCHR:
		retval = (*cdevsw[major(dev)].d_ioctl)(dev, ap->a_command, ap->a_data,
						       ap->a_fflag, p);
		break;

	case VBLK:
		retval = (*bdevsw[major(dev)].d_ioctl)(dev, ap->a_command, ap->a_data,
						       ap->a_fflag, p);
		break;

	default:
		panic("spec_ioctl");
		/* NOTREACHED */
	}
	KERNEL_DEBUG_CONSTANT(FSDBG_CODE(DBG_IOCTL, 0) | DBG_FUNC_END,
			      (unsigned int)dev, (unsigned int)ap->a_command, (unsigned int)ap->a_fflag, retval, 0);

	return (retval);
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

static int filt_specattach(struct knote *kn);

int
spec_kqfilter(vnode_t vp, struct knote *kn)
{
	dev_t dev;
	int err = EINVAL;

	/*
	 * For a few special kinds of devices, we can attach knotes.
	 * Each filter function must check whether the dev type matches it.
	 */
	dev = vnode_specrdev(vp);

	if (vnode_istty(vp)) {
		/* We can hook into TTYs... */
		err = filt_specattach(kn);
	} else {
		/* Try a bpf device, as defined in bsd/net/bpf.c */
		err = bpfkqfilter(dev, kn);
	}

	return err;
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
	buf_flushdirtyblks(vp, (waitfor == MNT_WAIT || waitfor == MNT_DWAIT), 0, "spec_fsync");

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

#if CONFIG_EMBEDDED
#define LOWPRI_SLEEP_INTERVAL 5
#else
#define LOWPRI_SLEEP_INTERVAL 2
#endif

int 	lowpri_IO_initial_window_msecs  = LOWPRI_INITIAL_WINDOW_MSECS;
int 	lowpri_IO_window_msecs_inc  = LOWPRI_WINDOW_MSECS_INC;
int 	lowpri_max_window_msecs  = LOWPRI_MAX_WINDOW_MSECS;
int     lowpri_max_waiting_msecs = LOWPRI_MAX_WAITING_MSECS;

#if 0 
#define DEBUG_ALLOC_THROTTLE_INFO(format, debug_info, args...)	\
        do {                                                    \
               if ((debug_info)->alloc)                           \
               printf("%s: "format, __FUNCTION__, ## args);     \
       } while(0)

#else 
#define DEBUG_ALLOC_THROTTLE_INFO(format, debug_info, args...)
#endif

SYSCTL_INT(_debug, OID_AUTO, lowpri_IO_initial_window_msecs, CTLFLAG_RW | CTLFLAG_LOCKED, &lowpri_IO_initial_window_msecs, LOWPRI_INITIAL_WINDOW_MSECS, "");
SYSCTL_INT(_debug, OID_AUTO, lowpri_IO_window_inc, CTLFLAG_RW | CTLFLAG_LOCKED, &lowpri_IO_window_msecs_inc, LOWPRI_INITIAL_WINDOW_MSECS, "");
SYSCTL_INT(_debug, OID_AUTO, lowpri_max_window_msecs, CTLFLAG_RW | CTLFLAG_LOCKED, &lowpri_max_window_msecs, LOWPRI_INITIAL_WINDOW_MSECS, "");
SYSCTL_INT(_debug, OID_AUTO, lowpri_max_waiting_msecs, CTLFLAG_RW | CTLFLAG_LOCKED, &lowpri_max_waiting_msecs, LOWPRI_INITIAL_WINDOW_MSECS, "");

/*
 * throttled I/O helper function
 * convert the index of the lowest set bit to a device index
 */
int
num_trailing_0(uint64_t n)
{
	/*
	 * since in most cases the number of trailing 0s is very small,
     * we simply counting sequentially from the lowest bit
	 */
	if (n == 0)
		return sizeof(n) * 8;
	int count = 0;
	while (!ISSET(n, 1)) {
		n >>= 1;
		++count;
	}
	return count;
}

/*
 * Release the reference and if the item was allocated and this is the last
 * reference then free it.
 *
 * This routine always returns the old value.
 */
static int
throttle_info_rel(struct _throttle_io_info_t *info)
{
	SInt32 oldValue = OSDecrementAtomic(&info->refcnt);

	DEBUG_ALLOC_THROTTLE_INFO("refcnt = %d info = %p\n", 
		info, (int)(oldValue -1), info );

	/* The reference count just went negative, very bad */
	if (oldValue == 0)
		panic("throttle info ref cnt went negative!");

	/* 
	 * Once reference count is zero, no one else should be able to take a 
	 * reference 
	 */
	if ((info->refcnt == 0) && (info->alloc)) {
		DEBUG_ALLOC_THROTTLE_INFO("Freeing info = %p\n", info, info );
		FREE(info, M_TEMP); 
	}
	return oldValue;
}

/*
 * Just take a reference on the throttle info structure.
 *
 * This routine always returns the old value.
 */
static SInt32
throttle_info_ref(struct _throttle_io_info_t *info)
{
	SInt32 oldValue = OSIncrementAtomic(&info->refcnt);

	DEBUG_ALLOC_THROTTLE_INFO("refcnt = %d info = %p\n", 
		info, (int)(oldValue -1), info );
	/* Allocated items should never have a reference of zero */
	if (info->alloc && (oldValue == 0))
		panic("Taking a reference without calling create throttle info!\n");

	return oldValue;
}

/*
 * KPI routine
 *
 * Create and take a reference on a throttle info structure and return a
 * pointer for the file system to use when calling throttle_info_update.
 * Calling file system must have a matching release for every create.
 */
void *
throttle_info_create(void)
{
	struct _throttle_io_info_t *info; 

	MALLOC(info, struct _throttle_io_info_t *, sizeof(*info), M_TEMP, M_ZERO | M_WAITOK);
	/* Should never happen but just in case */
	if (info == NULL)
		return NULL;
	/* Mark that this one was allocated and needs to be freed */
	DEBUG_ALLOC_THROTTLE_INFO("Creating info = %p\n", info, info );
	info->alloc = TRUE;
	/* Take a reference */
	OSIncrementAtomic(&info->refcnt);
	return info;
}

/*
 * KPI routine
 *
 * Release the throttle info pointer if all the reference are gone. Should be 
 * called to release reference taken by throttle_info_create 
 */ 
void
throttle_info_release(void *throttle_info)
{
	DEBUG_ALLOC_THROTTLE_INFO("Releaseing info = %p\n",
		(struct _throttle_io_info_t *)throttle_info,
		(struct _throttle_io_info_t *)throttle_info);
	if (throttle_info) /* Just to be careful */
		throttle_info_rel(throttle_info);
}

/*
 * KPI routine
 *
 * File Systems that create an info structure, need to call this routine in
 * their mount routine (used by cluster code). File Systems that call this in
 * their mount routines must call throttle_info_mount_rel in their unmount
 * routines. 
 */
void 
throttle_info_mount_ref(mount_t mp, void *throttle_info)
{
	if ((throttle_info == NULL) || (mp == NULL))
		return;
	throttle_info_ref(throttle_info);
	/* We already have a reference release it before adding the new one */
	if (mp->mnt_throttle_info)
		throttle_info_rel(mp->mnt_throttle_info);
	mp->mnt_throttle_info = throttle_info;
}

/*
 * Private KPI routine
 *
 * return a handle for accessing throttle_info given a throttle_mask.  The
 * handle must be released by throttle_info_rel_by_mask
 */
int
throttle_info_ref_by_mask(uint64_t throttle_mask,
						  throttle_info_handle_t *throttle_info_handle)
{
	int dev_index;
	struct _throttle_io_info_t *info;

	if (throttle_info_handle == NULL)
		return EINVAL;
	
	dev_index = num_trailing_0(throttle_mask);
	info = &_throttle_io_info[dev_index];
	throttle_info_ref(info);
	*(struct _throttle_io_info_t**)throttle_info_handle = info;
	return 0;
}

/*
 * Private KPI routine
 *
 * release the handle obtained by throttle_info_ref_by_mask
 */
void
throttle_info_rel_by_mask(throttle_info_handle_t throttle_info_handle)
{
	/* for now the handle is just a pointer to _throttle_io_info_t */
	throttle_info_rel((struct _throttle_io_info_t*)throttle_info_handle);
}

/*
 * KPI routine
 *
 * File Systems that throttle_info_mount_ref, must call this routine in their
 * umount routine.
 */ 
void
throttle_info_mount_rel(mount_t mp)
{
	if (mp->mnt_throttle_info)
		throttle_info_rel(mp->mnt_throttle_info);
	mp->mnt_throttle_info = NULL;
}

void
throttle_info_get_last_io_time(mount_t mp, struct timeval *tv)
{
    	struct _throttle_io_info_t *info;

	if (mp == NULL)
	    info = &_throttle_io_info[LOWPRI_MAX_NUM_DEV - 1];
	else if (mp->mnt_throttle_info == NULL)
	    info = &_throttle_io_info[mp->mnt_devbsdunit];
	else
	    info = mp->mnt_throttle_info;

	*tv = info->last_IO_timestamp;
}

void
update_last_io_time(mount_t mp)
{
    	struct _throttle_io_info_t *info;
		
	if (mp == NULL)
	    info = &_throttle_io_info[LOWPRI_MAX_NUM_DEV - 1];
	else if (mp->mnt_throttle_info == NULL)
	    info = &_throttle_io_info[mp->mnt_devbsdunit];
	else
	    info = mp->mnt_throttle_info;

	microuptime(&info->last_IO_timestamp);
}


#if CONFIG_EMBEDDED

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
#else

int throttle_get_io_policy(__unused struct uthread **ut)
{
	*ut = get_bsdthread_info(current_thread());

	return (proc_get_task_selfdiskacc());
}
#endif


static int
throttle_io_will_be_throttled_internal(int lowpri_window_msecs, void * throttle_info)
{
    	struct _throttle_io_info_t *info = throttle_info;
	struct timeval elapsed;
	int elapsed_msecs;
	int policy;
	struct uthread	*ut;

	policy = throttle_get_io_policy(&ut);

	if (ut->uu_throttle_bc == FALSE && policy != IOPOL_THROTTLE)
		return (0);

	microuptime(&elapsed);
	timevalsub(&elapsed, &info->last_normal_IO_timestamp);
	elapsed_msecs = elapsed.tv_sec * 1000 + elapsed.tv_usec / 1000;

	if (lowpri_window_msecs == -1) // use the max waiting time
		lowpri_window_msecs = lowpri_max_waiting_msecs;

	return elapsed_msecs < lowpri_window_msecs;
}

/* 
 * If we have a mount point and it has a throttle info pointer then
 * use it to do the check, otherwise use the device unit number to find
 * the correct throttle info array element.
 */
int
throttle_io_will_be_throttled(int lowpri_window_msecs, mount_t mp)
{
    	void *info;

	/* Should we just return zero if no mount point */
	if (mp == NULL)
	    info = &_throttle_io_info[LOWPRI_MAX_NUM_DEV - 1];
	else if (mp->mnt_throttle_info == NULL)
	    info = &_throttle_io_info[mp->mnt_devbsdunit];
	else
	    info = mp->mnt_throttle_info;
	return throttle_io_will_be_throttled_internal(lowpri_window_msecs, info);
}

uint32_t
throttle_lowpri_io(int sleep_amount)
{
	int sleep_cnt = 0;
	int numthreads_throttling;
	int max_try_num;
	struct uthread *ut;
	struct _throttle_io_info_t *info;
	int max_waiting_msecs;

	ut = get_bsdthread_info(current_thread());

	if ((ut->uu_lowpri_window == 0) || (ut->uu_throttle_info == NULL))
		goto done;

	info = ut->uu_throttle_info;

	if (sleep_amount != 0) {
#if CONFIG_EMBEDDED
		max_waiting_msecs = lowpri_max_waiting_msecs;
#else 
		if (ut->uu_throttle_isssd == TRUE)
		        max_waiting_msecs = lowpri_max_waiting_msecs / 100;
		else
			max_waiting_msecs = lowpri_max_waiting_msecs;
#endif
		if (max_waiting_msecs < LOWPRI_SLEEP_INTERVAL)
		        max_waiting_msecs = LOWPRI_SLEEP_INTERVAL;

		numthreads_throttling = info->numthreads_throttling + MIN(10, MAX(1, sleep_amount)) - 1;
		max_try_num = max_waiting_msecs / LOWPRI_SLEEP_INTERVAL * MAX(1, numthreads_throttling);

		for (sleep_cnt = 0; sleep_cnt < max_try_num; sleep_cnt++) {
			if (throttle_io_will_be_throttled_internal(ut->uu_lowpri_window, info)) {
				if (sleep_cnt == 0) {
					KERNEL_DEBUG_CONSTANT((FSDBG_CODE(DBG_FSRW, 97)) | DBG_FUNC_START,
							      ut->uu_lowpri_window, max_try_num, numthreads_throttling, 0, 0);
				}
				IOSleep(LOWPRI_SLEEP_INTERVAL);
    				DEBUG_ALLOC_THROTTLE_INFO("sleeping because of info = %p\n", info, info );
			} else {
				break;
			}
		}
		if (sleep_cnt) {
			KERNEL_DEBUG_CONSTANT((FSDBG_CODE(DBG_FSRW, 97)) | DBG_FUNC_END,
					      ut->uu_lowpri_window, sleep_cnt, 0, 0, 0);
		}
	}
	SInt32 oldValue;
	oldValue = OSDecrementAtomic(&info->numthreads_throttling);

	if (oldValue <= 0) {
		panic("%s: numthreads negative", __func__);
	}
done:
	ut->uu_lowpri_window = 0;
	if (ut->uu_throttle_info)
		throttle_info_rel(ut->uu_throttle_info);
	ut->uu_throttle_info = NULL;
	ut->uu_throttle_bc = FALSE;

	return (sleep_cnt * LOWPRI_SLEEP_INTERVAL);
}

/*
 * KPI routine
 *
 * set a kernel thread's IO policy.  policy can be:
 * IOPOL_NORMAL, IOPOL_THROTTLE, IOPOL_PASSIVE
 *
 * explanations about these policies are in the man page of setiopolicy_np
 */
void throttle_set_thread_io_policy(int policy)
{
#if !CONFIG_EMBEDDED
	proc_apply_thread_selfdiskacc(policy);
#else /* !CONFIG_EMBEDDED */
	struct uthread *ut;
	ut = get_bsdthread_info(current_thread());
	ut->uu_iopol_disk = policy;
#endif /* !CONFIG_EMBEDDED */
}


static
void throttle_info_reset_window(struct uthread *ut)
{
	struct _throttle_io_info_t *info;

	info = ut->uu_throttle_info;

	OSDecrementAtomic(&info->numthreads_throttling);
	throttle_info_rel(info);
	ut->uu_throttle_info = NULL;
	ut->uu_lowpri_window = 0;
}

static
void throttle_info_set_initial_window(struct uthread *ut, struct _throttle_io_info_t *info, boolean_t isssd, boolean_t BC_throttle)
{
	SInt32 oldValue;

	ut->uu_throttle_info = info;
	throttle_info_ref(info);
	DEBUG_ALLOC_THROTTLE_INFO("updating info = %p\n", info, info );

	oldValue = OSIncrementAtomic(&info->numthreads_throttling);
	if (oldValue < 0) {
		panic("%s: numthreads negative", __func__);
	}
	ut->uu_lowpri_window = lowpri_IO_initial_window_msecs;
	ut->uu_lowpri_window += lowpri_IO_window_msecs_inc * oldValue;
	ut->uu_throttle_isssd = isssd;
	ut->uu_throttle_bc = BC_throttle;
}


static
void throttle_info_update_internal(void *throttle_info, int flags, boolean_t isssd)
{
	struct _throttle_io_info_t *info = throttle_info;
	struct uthread	*ut;
	int policy;
	int is_throttleable_io = 0;
	int is_passive_io = 0;

	if (!lowpri_IO_initial_window_msecs || (info == NULL))
		return;
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

	if (!is_throttleable_io && ISSET(flags, B_PASSIVE))
		is_passive_io |= 1;

	if (!is_throttleable_io) {
		if (!is_passive_io){
			microuptime(&info->last_normal_IO_timestamp);
		}
	} else if (ut) {
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
		if (ut->uu_lowpri_window == 0)
			throttle_info_set_initial_window(ut, info, isssd, FALSE);
		else {
			/* The thread sends I/Os to different devices within the same system call */
			if (ut->uu_throttle_info != info) {
				struct _throttle_io_info_t *old_info = ut->uu_throttle_info;

				// keep track of the numthreads in the right device
				OSDecrementAtomic(&old_info->numthreads_throttling);
				OSIncrementAtomic(&info->numthreads_throttling);

				DEBUG_ALLOC_THROTTLE_INFO("switching from info = %p\n", old_info, old_info );
				DEBUG_ALLOC_THROTTLE_INFO("switching to info = %p\n", info, info );
				/* This thread no longer needs a reference on that throttle info */
				throttle_info_rel(ut->uu_throttle_info);
				ut->uu_throttle_info = info;
				/* Need to take a reference on this throttle info */
				throttle_info_ref(ut->uu_throttle_info);
			}
			int numthreads = MAX(1, info->numthreads_throttling);
			ut->uu_lowpri_window += lowpri_IO_window_msecs_inc * numthreads;
			if (ut->uu_lowpri_window > lowpri_max_window_msecs * numthreads)
				ut->uu_lowpri_window = lowpri_max_window_msecs * numthreads;

			if (isssd == FALSE) {
				/*
				 * we're here because we've actually issued I/Os to different devices...
				 * if at least one of them was a non SSD, then thottle the thread
				 * using the policy for non SSDs
				 */
				ut->uu_throttle_isssd = FALSE;
			}
		}
	}
}

/*
 * KPI routine
 *
 * this is usually called before every I/O, used for throttled I/O
 * book keeping.  This routine has low overhead and does not sleep
 */
void throttle_info_update(void *throttle_info, int flags)
{
	throttle_info_update_internal(throttle_info, flags, FALSE);
}

/*
 * KPI routine
 *
 * this is usually called before every I/O, used for throttled I/O
 * book keeping.  This routine has low overhead and does not sleep
 */
void throttle_info_update_by_mask(void *throttle_info_handle, int flags)
{
	void *throttle_info = throttle_info_handle;
	/* for now we only use the lowest bit of the throttle mask, so the
	 * handle is the same as the throttle_info.  Later if we store a
	 * set of throttle infos in the handle, we will want to loop through
	 * them and call throttle_info_update in a loop
	 */
	throttle_info_update(throttle_info, flags);
}

extern int ignore_is_ssd;

int
spec_strategy(struct vnop_strategy_args *ap)
{
        buf_t	bp;
	int	bflags;
	int	policy;
	dev_t	bdev;
	uthread_t ut;
	mount_t mp;
	int strategy_ret;
	struct _throttle_io_info_t *throttle_info;
	boolean_t isssd = FALSE;

        bp = ap->a_bp;
	bdev = buf_device(bp);
	mp = buf_vnode(bp)->v_mount;

	policy = throttle_get_io_policy(&ut);

	if (policy == IOPOL_THROTTLE) {
		bp->b_flags |= B_THROTTLED_IO;
		bp->b_attr.ba_flags |= BA_THROTTLED_IO;
		bp->b_flags &= ~B_PASSIVE;
	} else if (policy == IOPOL_PASSIVE)
		bp->b_flags |= B_PASSIVE;

	bflags = bp->b_flags;

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

		if (bflags & B_THROTTLED_IO)
			code |= DKIO_THROTTLE;
		else if (bflags & B_PASSIVE)
			code |= DKIO_PASSIVE;

		KERNEL_DEBUG_CONSTANT(FSDBG_CODE(DBG_DKRW, code) | DBG_FUNC_NONE,
				      bp, bdev, (int)buf_blkno(bp), buf_count(bp), 0);
        }
	if (((bflags & (B_IOSTREAMING | B_PAGEIO | B_READ)) == (B_PAGEIO | B_READ)) &&
	    mp && (mp->mnt_kern_flag & MNTK_ROOTDEV))
	        hard_throttle_on_root = 1;

	if (mp != NULL) {
		if ((mp->mnt_kern_flag & MNTK_SSD) && !ignore_is_ssd)
			isssd = TRUE;
		throttle_info = &_throttle_io_info[mp->mnt_devbsdunit];
	} else
		throttle_info = &_throttle_io_info[LOWPRI_MAX_NUM_DEV - 1];

	throttle_info_update_internal(throttle_info, bflags, isssd);

	if ((bflags & B_READ) == 0) {
		microuptime(&throttle_info->last_IO_timestamp);
		if (mp) {
			INCR_PENDING_IO(buf_count(bp), mp->mnt_pending_write_size);
		}
	} else if (mp) {
		INCR_PENDING_IO(buf_count(bp), mp->mnt_pending_read_size);
	}
	/*
	 * The BootCache may give us special information about
	 * the IO, so it returns special values that we check
	 * for here.
	 *
	 * IO_SATISFIED_BY_CACHE
	 * The read has been satisfied by the boot cache. Don't
	 * throttle the thread unnecessarily.
	 *
	 * IO_SHOULD_BE_THROTTLED
	 * The boot cache is playing back a playlist and this IO
	 * cut through. Throttle it so we're not cutting through
	 * the boot cache too often.
	 *
	 * Note that typical strategy routines are defined with
	 * a void return so we'll get garbage here. In the 
	 * unlikely case the garbage matches our special return
	 * value, it's not a big deal since we're only adjusting
	 * the throttling delay.
 	 */
#define IO_SATISFIED_BY_CACHE  ((int)0xcafefeed)
#define IO_SHOULD_BE_THROTTLED ((int)0xcafebeef)
	typedef	int strategy_fcn_ret_t(struct buf *bp);
	
	strategy_ret = (*(strategy_fcn_ret_t*)bdevsw[major(bdev)].d_strategy)(bp);
	
	if ((IO_SATISFIED_BY_CACHE == strategy_ret) && (ut->uu_lowpri_window != 0) && (ut->uu_throttle_info != NULL)) {
		/*
		 * If this was a throttled IO satisfied by the boot cache,
		 * don't delay the thread.
		 */
		throttle_info_reset_window(ut);

	} else if ((IO_SHOULD_BE_THROTTLED == strategy_ret) && (ut->uu_lowpri_window == 0) && (ut->uu_throttle_info == NULL)) {
		/*
		 * If the boot cache indicates this IO should be throttled,
		 * delay the thread.
		 */
		throttle_info_set_initial_window(ut, throttle_info, isssd, TRUE);
	}
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
	int error = 0;
	int flags = ap->a_fflag;
	struct proc *p = vfs_context_proc(ap->a_context);
	struct session *sessp;
	int do_rele = 0;

	switch (vp->v_type) {

	case VCHR:
		/*
		 * Hack: a tty device that is a controlling terminal
		 * has a reference from the session structure.
		 * We cannot easily tell that a character device is
		 * a controlling terminal, unless it is the closing
		 * process' controlling terminal.  In that case,
		 * if the reference count is 1 (this is the very
	     * last close)
		 */
		sessp = proc_session(p);
		if (sessp != SESSION_NULL) {
			if ((vcount(vp) == 1) && 
		    		(vp == sessp->s_ttyvp)) {

				session_lock(sessp);
				if (vp == sessp->s_ttyvp) {
					sessp->s_ttyvp = NULL;
					sessp->s_ttyvid = 0;
					sessp->s_ttyp = TTY_NULL;
					sessp->s_ttypgrpid = NO_PID;
					do_rele = 1;
				} 
				session_unlock(sessp);

				if (do_rele) {
					vnode_rele(vp);
				}
			}
			session_rele(sessp);
		}

		devsw_lock(dev, S_IFCHR);

		vp->v_specinfo->si_opencount--;

		if (vp->v_specinfo->si_opencount < 0) {
			panic("Negative open count?");
		}
		/*
		 * close on last reference or on vnode revoke call
		 */
		if ((vcount(vp) > 0) && ((flags & IO_REVOKE) == 0)) {
			devsw_unlock(dev, S_IFCHR);
			return (0);
		}	
		
		error = cdevsw[major(dev)].d_close(dev, flags, S_IFCHR, p);

		devsw_unlock(dev, S_IFCHR);
		break;

	case VBLK:
		/*
		 * If there is more than one outstanding open, don't
		 * send the close to the device.
		 */
		devsw_lock(dev, S_IFBLK);
		if (vcount(vp) > 1) {
			vp->v_specinfo->si_opencount--;
			devsw_unlock(dev, S_IFBLK);
			return (0);
		}
		devsw_unlock(dev, S_IFBLK);

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

		devsw_lock(dev, S_IFBLK);

		vp->v_specinfo->si_opencount--;
		
		if (vp->v_specinfo->si_opencount < 0) {
			panic("Negative open count?");
		}

		if (vcount(vp) > 0) {
			devsw_unlock(dev, S_IFBLK);
			return (0);
		}

		error = bdevsw[major(dev)].d_close(dev, flags, S_IFBLK, p);

		devsw_unlock(dev, S_IFBLK);
		break;

	default:
		panic("spec_close: not special");
		return(EBADF);
	}

	return error;
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

static void filt_specdetach(struct knote *kn);
static int filt_spec(struct knote *kn, long hint);
static unsigned filt_specpeek(struct knote *kn);

struct filterops spec_filtops = {
	.f_isfd 	= 1,
        .f_attach 	= filt_specattach,
        .f_detach 	= filt_specdetach,
        .f_event 	= filt_spec,
	.f_peek 	= filt_specpeek
};

static int
filter_to_seltype(int16_t filter)
{
	switch (filter) {
	case EVFILT_READ: 
		return FREAD;
	case EVFILT_WRITE:
		return FWRITE;
		break;
	default:
		panic("filt_to_seltype(): invalid filter %d\n", filter);
		return 0;
	}
}

static int 
filt_specattach(struct knote *kn)
{
	vnode_t vp;
	dev_t dev;

	vp = (vnode_t)kn->kn_fp->f_fglob->fg_data; /* Already have iocount, and vnode is alive */

	assert(vnode_ischr(vp));

	dev = vnode_specrdev(vp);

	if (major(dev) > nchrdev) {
		return ENXIO;
	}

	if ((cdevsw_flags[major(dev)] & CDEVSW_SELECT_KQUEUE) == 0) {
		return EINVAL;
	}

	/* Resulting wql is safe to unlink even if it has never been linked */
	kn->kn_hook = wait_queue_link_allocate();
	if (kn->kn_hook == NULL) {
		return EAGAIN;
	}

	kn->kn_fop = &spec_filtops;
	kn->kn_hookid = vnode_vid(vp);

	knote_markstayqueued(kn);

	return 0;
}

static void 
filt_specdetach(struct knote *kn)
{
	kern_return_t ret;

	/* 
	 * Given wait queue link and wait queue set, unlink.  This is subtle.
	 * If the device has been revoked from under us, selclearthread() will
	 * have removed our link from the kqueue's wait queue set, which 
	 * wait_queue_set_unlink_one() will detect and handle.
	 */
	ret = wait_queue_set_unlink_one(kn->kn_kq->kq_wqs, kn->kn_hook);
	if (ret != KERN_SUCCESS) {
		panic("filt_specdetach(): failed to unlink wait queue link.");
	}

	(void)wait_queue_link_free(kn->kn_hook);
	kn->kn_hook = NULL;
	kn->kn_status &= ~KN_STAYQUEUED;
}

static int 
filt_spec(struct knote *kn, long hint)
{
	vnode_t vp;
	uthread_t uth;
	wait_queue_set_t old_wqs;
	vfs_context_t ctx;
	int selres;
	int error;
	int use_offset;
	dev_t dev;
	uint64_t flags;

	assert(kn->kn_hook != NULL);

	if (hint != 0) {
		panic("filt_spec(): nonzero hint?");
	}

	uth = get_bsdthread_info(current_thread());
	ctx = vfs_context_current();
	vp = (vnode_t)kn->kn_fp->f_fglob->fg_data;

	error = vnode_getwithvid(vp, kn->kn_hookid);
	if (error != 0) {
		kn->kn_flags |= (EV_EOF | EV_ONESHOT);
		return 1;
	}
	
	dev = vnode_specrdev(vp);
	flags = cdevsw_flags[major(dev)];
	use_offset = ((flags & CDEVSW_USE_OFFSET) != 0);
	assert((flags & CDEVSW_SELECT_KQUEUE) != 0);

	/* Trick selrecord() into hooking kqueue's wait queue set into device wait queue */
	old_wqs = uth->uu_wqset;
	uth->uu_wqset = kn->kn_kq->kq_wqs;
	selres = VNOP_SELECT(vp, filter_to_seltype(kn->kn_filter), 0, kn->kn_hook, ctx);
	uth->uu_wqset = old_wqs;

	if (use_offset) {
		if (kn->kn_fp->f_fglob->fg_offset >= (uint32_t)selres) {
			kn->kn_data = 0;
		} else {
			kn->kn_data = ((uint32_t)selres) - kn->kn_fp->f_fglob->fg_offset;
		}
	} else {
		kn->kn_data = selres;
	}

	vnode_put(vp);

	return (kn->kn_data != 0);
}

static unsigned
filt_specpeek(struct knote *kn)
{
	vnode_t vp;
	uthread_t uth;
	wait_queue_set_t old_wqs;
	vfs_context_t ctx;
	int error, selres;
	
	uth = get_bsdthread_info(current_thread());
	ctx = vfs_context_current();
	vp = (vnode_t)kn->kn_fp->f_fglob->fg_data;

	error = vnode_getwithvid(vp, kn->kn_hookid);
	if (error != 0) {
		return 1; /* Just like VNOP_SELECT() on recycled vnode */
	}

	/*
	 * Why pass the link here?  Because we may not have registered in the past...
	 */
	old_wqs = uth->uu_wqset;
	uth->uu_wqset = kn->kn_kq->kq_wqs;
	selres = VNOP_SELECT(vp, filter_to_seltype(kn->kn_filter), 0, kn->kn_hook, ctx);
	uth->uu_wqset = old_wqs;

	vnode_put(vp);
	return selres;
}

