
/*
 * Copyright (c) 1988 University of Utah.
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department.
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
 * from: Utah Hdr: vn.c 1.13 94/04/02
 *
 *	from: @(#)vn.c	8.6 (Berkeley) 4/1/94
 * $FreeBSD: src/sys/dev/vn/vn.c,v 1.105.2.4 2001/11/18 07:11:00 dillon Exp $
 */

/*
 * Vnode disk driver.
 *
 * Block/character interface to a vnode.  Allows one to treat a file
 * as a disk (e.g. build a filesystem in it, mount it, etc.).
 *
 * NOTE 1: This uses the VOP_BMAP/VOP_STRATEGY interface to the vnode
 * instead of a simple VOP_RDWR.  We do this to avoid distorting the
 * local buffer cache.
 *
 * NOTE 2: There is a security issue involved with this driver.
 * Once mounted all access to the contents of the "mapped" file via
 * the special file is controlled by the permissions on the special
 * file, the protection of the mapped file is ignored (effectively,
 * by using root credentials in all transactions).
 *
 * NOTE 3: Doesn't interact with leases, should it?
 */

#include "vndevice.h"

#if NVNDEVICE > 0

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/buf.h>
#include <sys/malloc.h>
#include <sys/vnode.h>
#include <sys/fcntl.h>
#include <sys/conf.h>
#include <sys/disk.h>
#include <sys/stat.h>
#include <sys/conf.h>

#include <sys/vnioctl.h>

#include <sys/vm.h>

#include <vm/vm_pager.h>
#include <vm/vm_pageout.h>
#include <mach/memory_object_types.h>

#include <miscfs/devfs/devfs.h>

extern void
vfs_io_maxsegsize(struct vnode	*vp,
		  int	flags,	/* B_READ or B_WRITE */
		  int	*maxsegsize);

extern void
vfs_io_attributes(struct vnode	*vp,
		  int	flags,	/* B_READ or B_WRITE */
		  int	*iosize,
		  int	*vectors);

#include "shadow.h"

static ioctl_fcn_t		vnioctl_chr;
static ioctl_fcn_t		vnioctl_blk;
static open_close_fcn_t		vnopen;
static open_close_fcn_t		vnclose;
static psize_fcn_t		vnsize;
static strategy_fcn_t		vnstrategy;
static read_write_fcn_t		vnread;
static read_write_fcn_t		vnwrite;

static int	vndevice_bdev_major;
static int	vndevice_cdev_major;

/*
 * cdevsw
 *	D_DISK		we want to look like a disk
 *	D_CANFREE	We support B_FREEBUF
 */

static struct bdevsw vn_bdevsw = {
	/* open */	vnopen,
	/* close */	vnclose,
	/* strategy */	vnstrategy,
	/* ioctl */	vnioctl_blk,
	/* dump */	eno_dump,
	/* psize */	vnsize,
	/* flags */	D_DISK,
};

static struct cdevsw vn_cdevsw = {
	/* open */	vnopen,
	/* close */	vnclose,
	/* read */	vnread,
	/* write */	vnwrite,
	/* ioctl */	vnioctl_chr,
	/* stop */	eno_stop,
	/* reset */	eno_reset,
	/* ttys */	0,
	/* select */	eno_select,
	/* mmap */	eno_mmap,
	/* strategy */	eno_strat,
	/* getc */	eno_getc,
	/* putc */	eno_putc,
	/* flags */	D_DISK,
};

struct vn_softc {
	u_int64_t	sc_fsize;	/* file size in bytes 		*/
	u_int64_t	sc_size;	/* size of vn, sc_secsize scale	*/
	int		sc_flags;	/* flags 			*/
	int		sc_secsize;	/* sector size			*/
	struct vnode	*sc_vp;		/* vnode if not NULL		*/
	int		sc_open_flags;
	struct vnode	*sc_shadow_vp;	/* shadow vnode if not NULL	*/
	shadow_map_t *	sc_shadow_map;	/* shadow map if not NULL	*/
	struct ucred	*sc_cred;	/* credentials 			*/
	u_long		sc_options;	/* options 			*/
	void *		sc_bdev;
	void *		sc_cdev;
} vn_table[NVNDEVICE];

#define ROOT_IMAGE_UNIT	0

/* sc_flags */
#define VNF_INITED	0x01
#define	VNF_READONLY	0x02

static u_long	vn_options;

#define IFOPT(vn,opt) if (((vn)->sc_options|vn_options) & (opt))
#define TESTOPT(vn,opt) (((vn)->sc_options|vn_options) & (opt))

static int	vnsetcred (struct vn_softc *vn, struct proc *p);
static void	vnclear (struct vn_softc *vn);

static int
vniocattach_file(struct vn_softc *vn,
		 struct vn_ioctl *vio,
		 dev_t dev,
		 int in_kernel,
		 struct proc *p);
static int
vniocattach_shadow(struct vn_softc * vn,
		   struct vn_ioctl *vio,
		   dev_t dev,
		   int in_kernel,
		   struct proc *p);
static __inline__
vnunit(dev_t dev)
{
	return (minor(dev));
}

static	int
vnclose(dev_t dev, int flags, int devtype, struct proc *p)
{
	return (0);
}

static	int
vnopen(dev_t dev, int flags, int devtype, struct proc *p)
{
	struct vn_softc *vn;
	int unit;

	unit = vnunit(dev);
	if (vnunit(dev) >= NVNDEVICE) {
		return (ENXIO);
	}
	vn = vn_table + unit;
	if ((flags & FWRITE) && (vn->sc_flags & VNF_READONLY))
		return (EACCES);

	return(0);
}

static int 
vnread(dev_t dev, struct uio *uio, int ioflag)
{
	struct proc * 		p = current_proc();
	int 			status;
	struct vn_softc *	vn;
	int 			unit;

	unit = vnunit(dev);
	if (vnunit(dev) >= NVNDEVICE) {
		return (ENXIO);
	}
	vn = vn_table + unit;
	if ((vn->sc_flags & VNF_INITED) == 0) {
		return (ENXIO);
	}
	if (vn->sc_shadow_vp != NULL) {
		return (ENODEV);
	}
	vn_lock(vn->sc_vp, LK_EXCLUSIVE | LK_RETRY, p);
	status = VOP_READ(vn->sc_vp, uio, ioflag, vn->sc_cred);
	VOP_UNLOCK(vn->sc_vp, 0, p);

	return (status);
}

static int 
vnwrite(dev_t dev, struct uio *uio, int ioflag)
{
	struct proc * 		p = current_proc();
	int 			status;
	struct vn_softc *	vn;
	int 			unit;

	unit = vnunit(dev);
	if (vnunit(dev) >= NVNDEVICE) {
		return (ENXIO);
	}
	vn = vn_table + unit;
	if ((vn->sc_flags & VNF_INITED) == 0) {
		return (ENXIO);
	}
	if (vn->sc_shadow_vp != NULL) {
		return (ENODEV);
	}
	if (vn->sc_flags & VNF_READONLY) {
		return (EROFS);
	}

	vn_lock(vn->sc_vp, LK_EXCLUSIVE | LK_RETRY, p);
	status = VOP_WRITE(vn->sc_vp, uio, ioflag, vn->sc_cred);
	VOP_UNLOCK(vn->sc_vp, 0, p);

	return (status);
}

static boolean_t
bp_is_mapped(struct buf * bp, vm_offset_t * vaddr)
{
	boolean_t	is_mapped = FALSE;

	if (bp->b_flags & B_NEED_IODONE) {
		struct buf * 	real_bp = (struct buf *)bp->b_real_bp;

		if (real_bp && real_bp->b_data) {
			*vaddr = (vm_offset_t)real_bp->b_data;
			is_mapped = TRUE;
		}
	}
	return (is_mapped);
}

static __inline__ int
file_io(struct vnode * vp, struct ucred * cred,
	enum uio_rw op, char * base, off_t offset, long count,
	struct proc * p, long * resid)
{
	struct uio 		auio;
	struct iovec 		aiov;
	int			error;

	bzero(&auio, sizeof(auio));
	aiov.iov_base = base;
	aiov.iov_len = count;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_offset = offset;
	auio.uio_rw = op;
	auio.uio_resid = count;
	auio.uio_procp = p;
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	if (op == UIO_READ)
		error = VOP_READ(vp, &auio, IO_SYNC, cred);
	else
		error = VOP_WRITE(vp, &auio, IO_SYNC, cred);
	VOP_UNLOCK(vp, 0, p);
	*resid = auio.uio_resid;
	return (error);
}

static int
shadow_read(struct vn_softc * vn, struct buf * bp, char * base, struct proc * p)
{
	int 		error = 0;
	u_long		offset;
	boolean_t	read_shadow;
	u_long		resid;
	u_long		start = 0;

	offset = bp->b_blkno;
	resid = bp->b_bcount / vn->sc_secsize;

	while (resid > 0) {
		u_long		temp_resid;
		u_long		this_offset;
		u_long		this_resid;
		struct vnode *	vp;

		read_shadow = shadow_map_read(vn->sc_shadow_map,
					      offset, resid,
					      &this_offset, &this_resid);
		if (read_shadow) {
			vp = vn->sc_shadow_vp;
		}
		else {
			vp = vn->sc_vp;
		}
		error = file_io(vp, vn->sc_cred, UIO_READ, base + start,
				(off_t)this_offset * vn->sc_secsize,
				this_resid * vn->sc_secsize, p, &temp_resid);
		if (error)
			break;
		temp_resid = this_resid - temp_resid / vn->sc_secsize;
		if (temp_resid == 0) {
			static int printed = 0;
			printf("vn device: shadow_write zero length read (printed %d)\n", printed);
			printed++;
			break;
		}
		resid -= temp_resid;
		offset += temp_resid;
		start += temp_resid * vn->sc_secsize;;
	}
	bp->b_resid = resid * vn->sc_secsize;
	return (error);
}

static int
shadow_write(struct vn_softc * vn, struct buf * bp, char * base, 
	     struct proc * p)
{
	int 		error = 0;
	u_long		offset;
	boolean_t	shadow_grew;
	u_long		resid;
	u_long		start = 0;

	offset = bp->b_blkno;
	resid = bp->b_bcount / vn->sc_secsize;

	while (resid > 0) {
		u_long		temp_resid;
		u_long		this_offset;
		u_long		this_resid;
		struct vnode *	vp;

		shadow_grew = shadow_map_write(vn->sc_shadow_map, 
					       offset, resid, 
					       &this_offset, &this_resid);
		if (shadow_grew) {
#if 0
			off_t	size;
			/* truncate the file to its new length before write */
			size = (off_t)shadow_map_shadow_size(vn->sc_shadow_map) 
				* vn->sc_secsize;
			vn_lock(vn->sc_shadow_vp, LK_EXCLUSIVE | LK_RETRY, p);
			VOP_TRUNCATE(vn->sc_shadow_vp, size,
				     IO_SYNC, vn->sc_cred, p);
			VOP_UNLOCK(vn->sc_shadow_vp, 0, p);
#endif
		}
		error = file_io(vn->sc_shadow_vp, vn->sc_cred, UIO_WRITE, 
				base + start,
				(off_t)this_offset * vn->sc_secsize,
				this_resid * vn->sc_secsize, p, &temp_resid);
		if (error) {
			break;
		}
		temp_resid = this_resid - temp_resid / vn->sc_secsize;
		if (temp_resid == 0) {
			static int printed = 0;
			printf("vn device: shadow_write zero length write (printed %d)\n", printed);
			printed++;
			break;
		}
		resid -= temp_resid;
		offset += temp_resid;
		start += temp_resid * vn->sc_secsize;;
	}
	bp->b_resid = resid * vn->sc_secsize;
	return (error);
}

static int
vn_readwrite_io(struct vn_softc * vn, struct buf * bp)
{
	int			error = 0;
	char *			iov_base;
	boolean_t		need_unmap = FALSE;
	struct proc * 		p = current_proc();
	vm_offset_t 		vaddr = NULL;
	
	if (bp->b_flags & B_VECTORLIST) {
		if (bp_is_mapped(bp, &vaddr) == FALSE) {
			if (ubc_upl_map(bp->b_pagelist, &vaddr) 
			    != KERN_SUCCESS) {
				panic("vn device: ubc_upl_map failed");
			}
			else {
				need_unmap = TRUE;
			}
		}
	}
	if (error)
		return (error);

	if (vaddr != NULL)
		iov_base = (caddr_t)(vaddr + bp->b_uploffset);
	else
		iov_base = bp->b_data;
	if (vn->sc_shadow_vp == NULL) {
		error = file_io(vn->sc_vp, vn->sc_cred,
				bp->b_flags & B_READ ? UIO_READ : UIO_WRITE,
				iov_base, (off_t)bp->b_blkno * vn->sc_secsize,
				bp->b_bcount, p, &bp->b_resid);
	}
	else {
		if (bp->b_flags & B_READ)
			error = shadow_read(vn, bp, iov_base, p);
		else
			error = shadow_write(vn, bp, iov_base, p);
		if (error == 0)
			bp->b_resid = 0;

	}
	if (need_unmap) {
		ubc_upl_unmap(bp->b_pagelist);
	}
	return (error);
}

static void
vnstrategy(struct buf *bp)
{
	struct vn_softc *vn;
	int error = 0;
	long sz;	/* in sc_secsize chunks */

	vn = vn_table + vnunit(bp->b_dev);
	if ((vn->sc_flags & VNF_INITED) == 0) {
		bp->b_error = ENXIO;
		bp->b_flags |= B_ERROR;
		biodone(bp);
		return;
	}

	bp->b_resid = bp->b_bcount;
	/*
	 * Check for required alignment.  Transfers must be a valid
	 * multiple of the sector size.
	 */
	if (bp->b_bcount % vn->sc_secsize != 0 ||
	    bp->b_blkno % (vn->sc_secsize / DEV_BSIZE) != 0) {
		bp->b_error = EINVAL;
		bp->b_flags |= B_ERROR | B_INVAL;
		biodone(bp);
		return;
	}
	sz = howmany(bp->b_bcount, vn->sc_secsize);

	/*
	 * If out of bounds return an error.  If at the EOF point,
	 * simply read or write less.
	 */
	if (bp->b_blkno >= vn->sc_size) {
		if (bp->b_blkno > vn->sc_size) {
			bp->b_error = EINVAL;
			bp->b_flags |= B_ERROR | B_INVAL;
		}
		biodone(bp);
		return;
	}
	/*
	 * If the request crosses EOF, truncate the request.
	 */
	if ((bp->b_blkno + sz) > vn->sc_size) {
		bp->b_bcount = (vn->sc_size - bp->b_blkno) * vn->sc_secsize;
		bp->b_resid = bp->b_bcount;
	}

	if (vn->sc_vp) {
		error = vn_readwrite_io(vn, bp);
		if (error) {
			bp->b_error = error;
			bp->b_flags |= B_ERROR;
		}
		biodone(bp);
	}
	else {
		bp->b_flags |= B_ERROR;
		bp->b_error = EINVAL;
		biodone(bp);
	}
}

/* ARGSUSED */
static	int
vnioctl(dev_t dev, u_long cmd, caddr_t data, int flag, struct proc *p,
	int is_char)
{
	struct vn_softc *vn;
	struct vn_ioctl *vio;
	int error;
	u_long *f;
	int num = 0;
	u_int64_t * o;
	int unit;
	int size = 0;

	unit = vnunit(dev);
	if (vnunit(dev) >= NVNDEVICE) {
		return (ENXIO);
	}
	vn = vn_table + unit;
	error = suser(p->p_ucred, &p->p_acflag);
	if (error)
		return (error);

	vio = (struct vn_ioctl *)data;
	f = (u_long*)data;
	o = (u_int64_t *)data;
	switch (cmd) {
	case VNIOCDETACH:
	case DKIOCGETBLOCKSIZE:
        case DKIOCSETBLOCKSIZE:
	case DKIOCGETMAXBLOCKCOUNTREAD:
	case DKIOCGETMAXBLOCKCOUNTWRITE:
	case DKIOCGETMAXSEGMENTCOUNTREAD:
	case DKIOCGETMAXSEGMENTCOUNTWRITE:
	case DKIOCGETMAXSEGMENTBYTECOUNTREAD:
	case DKIOCGETMAXSEGMENTBYTECOUNTWRITE:
	case DKIOCGETBLOCKCOUNT:
	case DKIOCGETBLOCKCOUNT32:
		if ((vn->sc_flags & VNF_INITED) == 0) {
			return (ENXIO);
		}
		break;
	default:
		break;
	}
	switch (cmd) {
	case DKIOCGETMAXBLOCKCOUNTREAD:
		vfs_io_attributes(vn->sc_vp, B_READ, &size, &num);
		*o = size / vn->sc_secsize;
		break;
	case DKIOCGETMAXBLOCKCOUNTWRITE:
		vfs_io_attributes(vn->sc_vp, B_WRITE, &size, &num);
		*o = size / vn->sc_secsize;
		break;
	case DKIOCGETMAXBYTECOUNTREAD:
		vfs_io_attributes(vn->sc_vp, B_READ, &size, &num);
		*o = size;
		break;
	case DKIOCGETMAXBYTECOUNTWRITE:
		vfs_io_attributes(vn->sc_vp, B_WRITE, &size, &num);
		*o = size;
		break;
	case DKIOCGETMAXSEGMENTCOUNTREAD:
		vfs_io_attributes(vn->sc_vp, B_READ, &size, &num);
		*o = num;
		break;
	case DKIOCGETMAXSEGMENTCOUNTWRITE:
		vfs_io_attributes(vn->sc_vp, B_WRITE, &size, &num);
		*o = num;
		break;
	case DKIOCGETMAXSEGMENTBYTECOUNTREAD:
		vfs_io_maxsegsize(vn->sc_vp, B_READ, &size);
		*o = size;
		break;
	case DKIOCGETMAXSEGMENTBYTECOUNTWRITE:
		vfs_io_maxsegsize(vn->sc_vp, B_WRITE, &size);
		*o = size;
		break;
        case DKIOCGETBLOCKSIZE:
		*f = vn->sc_secsize;
		break;
        case DKIOCSETBLOCKSIZE:
		if (is_char) {
			/* can only set block size on block device */
			return (ENODEV);
		}
		if (vn->sc_shadow_vp != NULL) {
			/* can't set the block size if already shadowing */
			return (EBUSY);
		}
		if (*f < DEV_BSIZE) {
			return (EINVAL);
		}
		vn->sc_secsize = *f;
		/* recompute the size in terms of the new blocksize */
		vn->sc_size = vn->sc_fsize / vn->sc_secsize;
		break;
	case DKIOCISWRITABLE:
		*f = 1;
		break;
	case DKIOCGETBLOCKCOUNT32:
		*f = vn->sc_size;
		break;
	case DKIOCGETBLOCKCOUNT:
		*o = vn->sc_size;
		break;
	case VNIOCSHADOW:
		if (vn->sc_shadow_vp != NULL) {
			return (EBUSY);
		}
		if (vn->sc_vp == NULL) {
			/* much be attached before we can shadow */
			return (EINVAL);
		}
		if (vio->vn_file == NULL) {
			return (EINVAL);
		}
		error = vniocattach_shadow(vn, vio, dev, 0, p);
		break;

	case VNIOCATTACH:
		if (is_char) {
			/* attach only on block device */
			return (ENODEV);
		}
		if (vn->sc_flags & VNF_INITED) {
			return (EBUSY);
		}
		if (vio->vn_file == NULL) {
			return (EINVAL);
		}
		error = vniocattach_file(vn, vio, dev, 0, p);
		break;

	case VNIOCDETACH:
		if (is_char) {
			/* detach only on block device */
			return (ENODEV);
		}
		/* Note: spec_open won't open a mounted block device */

		/*
		 * XXX handle i/o in progress.  Return EBUSY, or wait, or
		 * flush the i/o.
		 * XXX handle multiple opens of the device.  Return EBUSY,
		 * or revoke the fd's.
		 * How are these problems handled for removable and failing
		 * hardware devices? (Hint: They are not)
		 */
		vnclear(vn);
		break;

	case VNIOCGSET:
		vn_options |= *f;
		*f = vn_options;
		break;

	case VNIOCGCLEAR:
		vn_options &= ~(*f);
		*f = vn_options;
		break;

	case VNIOCUSET:
		vn->sc_options |= *f;
		*f = vn->sc_options;
		break;

	case VNIOCUCLEAR:
		vn->sc_options &= ~(*f);
		*f = vn->sc_options;
		break;

	default:
		error = ENOTTY;
		break;
	}
	return(error);
}

static	int
vnioctl_chr(dev_t dev, u_long cmd, caddr_t data, int flag, struct proc *p)
{
	return (vnioctl(dev, cmd, data, flag, p, TRUE));
}

static	int
vnioctl_blk(dev_t dev, u_long cmd, caddr_t data, int flag, struct proc *p)
{
	return (vnioctl(dev, cmd, data, flag, p, FALSE));
}

/*
 *	vniocattach_file:
 *
 *	Attach a file to a VN partition.  Return the size in the vn_size
 *	field.
 */

static int
vniocattach_file(struct vn_softc *vn,
		 struct vn_ioctl *vio,
		 dev_t dev,
		 int in_kernel,
		 struct proc *p)
{
	struct vattr vattr;
	struct nameidata nd;
	int error, flags;
	
	flags = FREAD|FWRITE;
	if (in_kernel) {
		NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, vio->vn_file, p);
	}
	else {
		NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, vio->vn_file, p);
	}
	error = vn_open(&nd, flags, 0);
	if (error) {
		if (error != EACCES && error != EPERM && error != EROFS)
			return (error);
		flags &= ~FWRITE;
		if (in_kernel) {
			NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, 
			       vio->vn_file, p);
		}
		else {
			NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, 
			       vio->vn_file, p);
		}
		error = vn_open(&nd, flags, 0);
		if (error)
			return (error);
	}
	if (nd.ni_vp->v_type != VREG) {
		error = EINVAL;
	}
	else if (ubc_isinuse(nd.ni_vp, 1)) {
		error = EBUSY;
	}
	else {
		error = VOP_GETATTR(nd.ni_vp, &vattr, p->p_ucred, p);
	}
	if (error != 0) {
		VOP_UNLOCK(nd.ni_vp, 0, p);
		(void) vn_close(nd.ni_vp, flags, p->p_ucred, p);
		return (error);
	}
	vn->sc_vp = nd.ni_vp;
	vn->sc_vp->v_flag |= VNOCACHE_DATA;
	VOP_UNLOCK(nd.ni_vp, 0, p);

	vn->sc_open_flags = flags;

	/*
	 * If the size is specified, override the file attributes.  Note that
	 * the vn_size argument is in PAGE_SIZE sized blocks.
	 */
#if 0
	if (vio->vn_size)
		vn->sc_size = (quad_t)vio->vn_size * PAGE_SIZE / vn->sc_secsize;
	else
		vn->sc_size = vattr.va_size / vn->sc_secsize;
#endif
	vn->sc_secsize = DEV_BSIZE;
	vn->sc_fsize = vattr.va_size;
	vn->sc_size = vattr.va_size / vn->sc_secsize;
	error = vnsetcred(vn, p);
	if (error) {
		(void) vn_close(nd.ni_vp, flags, p->p_ucred, p);
		return(error);
	}
	{
		dev_t	cdev = makedev(vndevice_cdev_major, 
				       minor(dev));
		vn->sc_cdev = devfs_make_node(cdev, DEVFS_CHAR,
					      UID_ROOT, GID_OPERATOR, 
					      0600, "rvn%d", 
					      minor(dev));
	}
	vn->sc_flags |= VNF_INITED;
	if (flags == FREAD)
		vn->sc_flags |= VNF_READONLY;
	return(0);
}

static int
vniocattach_shadow(vn, vio, dev, in_kernel, p)
	struct vn_softc *vn;
	struct vn_ioctl *vio;
	dev_t dev;
	int in_kernel;
	struct proc *p;
{
	struct vattr vattr;
	struct nameidata nd;
	int error, flags;
	shadow_map_t *	map;
	
	flags = FREAD|FWRITE;
	if (in_kernel) {
		NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, vio->vn_file, p);
	}
	else {
		NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, vio->vn_file, p);
	}
	error = vn_open(&nd, flags, 0);
	if (error) {
		/* shadow MUST be writable! */
		return (error);
	}
	if (nd.ni_vp->v_type != VREG ||
	    (error = VOP_GETATTR(nd.ni_vp, &vattr, p->p_ucred, p))) {
		VOP_UNLOCK(nd.ni_vp, 0, p);
		(void) vn_close(nd.ni_vp, flags, p->p_ucred, p);
		return (error ? error : EINVAL);
	}
	vn->sc_shadow_vp = nd.ni_vp;
	vn->sc_shadow_vp->v_flag |= VNOCACHE_DATA;
	VOP_UNLOCK(nd.ni_vp, 0, p);

	map = shadow_map_create(vn->sc_fsize, vattr.va_size,
				0, vn->sc_secsize);
	if (map == NULL) {
		(void) vn_close(nd.ni_vp, flags, p->p_ucred, p);
		vn->sc_shadow_vp = NULL;
		return (ENOMEM);
	}
	vn->sc_shadow_map = map;
	vn->sc_flags &= ~VNF_READONLY; /* we're now read/write */
	return(0);
}

int
vndevice_root_image(char * path, char devname[], dev_t * dev_p)
{
	int 			error = 0;
	int			flags;
	struct vn_softc *	vn;
	struct vn_ioctl 	vio;

	vio.vn_file = path;
	vio.vn_size = 0;

	vn = vn_table + ROOT_IMAGE_UNIT;
	*dev_p = makedev(vndevice_bdev_major, 
			 ROOT_IMAGE_UNIT);
	sprintf(devname, "vn%d", ROOT_IMAGE_UNIT);
	error = vniocattach_file(vn, &vio, *dev_p, 1, current_proc());
	return (error);
}

/*
 * Duplicate the current processes' credentials.  Since we are called only
 * as the result of a SET ioctl and only root can do that, any future access
 * to this "disk" is essentially as root.  Note that credentials may change
 * if some other uid can write directly to the mapped file (NFS).
 */
int
vnsetcred(struct vn_softc *vn, struct proc * p)
{
	char *tmpbuf;
	int error = 0;
	struct proc * current_proc();
	struct ucred * cred = p->p_ucred;

	/*
	 * Set credits in our softc
	 */

	if (vn->sc_cred)
		crfree(vn->sc_cred);
	vn->sc_cred = crdup(cred);

	/*
	 * Horrible kludge to establish credentials for NFS  XXX.
	 */

	if (vn->sc_vp) {
		struct uio auio;
		struct iovec aiov;

		tmpbuf = _MALLOC(vn->sc_secsize, M_TEMP, M_WAITOK);
		bzero(&auio, sizeof(auio));

		aiov.iov_base = tmpbuf;
		aiov.iov_len = vn->sc_secsize;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = 0;
		auio.uio_rw = UIO_READ;
		auio.uio_segflg = UIO_SYSSPACE;
		auio.uio_resid = aiov.iov_len;
		vn_lock(vn->sc_vp, LK_EXCLUSIVE | LK_RETRY, p);
		error = VOP_READ(vn->sc_vp, &auio, 0, vn->sc_cred);
		VOP_UNLOCK(vn->sc_vp, 0, p);
		FREE(tmpbuf, M_TEMP);
	}
	return (error);
}

void
vnclear(struct vn_softc *vn)
{
	int		flags;
	struct proc *	p = current_proc();		/* XXX */

	if (vn->sc_vp != NULL) {
		(void)vn_close(vn->sc_vp, vn->sc_open_flags, vn->sc_cred, p);
		vn->sc_vp = NULL;
	}
	if (vn->sc_shadow_vp != NULL) {
		(void)vn_close(vn->sc_shadow_vp, FREAD | FWRITE, 
			       vn->sc_cred, p);
		vn->sc_shadow_vp = NULL;
	}
	if (vn->sc_shadow_map != NULL) {
		shadow_map_free(vn->sc_shadow_map);
		vn->sc_shadow_map = NULL;
	}
	vn->sc_flags = ~(VNF_INITED | VNF_READONLY);
	if (vn->sc_cred) {
		crfree(vn->sc_cred);
		vn->sc_cred = NULL;
	}
	vn->sc_size = 0;
	vn->sc_fsize = 0;
	if (vn->sc_cdev) {
		devfs_remove(vn->sc_cdev);
		vn->sc_cdev = NULL;
	}
}

static	int
vnsize(dev_t dev)
{
	struct vn_softc *vn;
	int unit;

	unit = vnunit(dev);
	if (vnunit(dev) >= NVNDEVICE) {
		return (ENXIO);
	}
	vn = vn_table + unit;

	if ((vn->sc_flags & VNF_INITED) == 0)
		return(-1);

	return(vn->sc_secsize);
}

#define CDEV_MAJOR 	-1
#define BDEV_MAJOR 	-1
static int vndevice_inited = 0;

void 
vndevice_init()
{
	int 	i;

	if (vndevice_inited)
		return;
	vndevice_bdev_major = bdevsw_add(BDEV_MAJOR, &vn_bdevsw);

	if (vndevice_bdev_major < 0) {
		printf("vndevice_init: bdevsw_add() returned %d\n",
		       vndevice_bdev_major);
		return;
	}
	vndevice_cdev_major = cdevsw_add_with_bdev(CDEV_MAJOR, &vn_cdevsw,
						   vndevice_bdev_major);
	if (vndevice_cdev_major < 0) {
		printf("vndevice_init: cdevsw_add() returned %d\n",
		       vndevice_cdev_major);
		return;
	}
	for (i = 0; i < NVNDEVICE; i++) {
		dev_t	dev = makedev(vndevice_bdev_major, i);
		vn_table[i].sc_bdev = devfs_make_node(dev, DEVFS_BLOCK,
						      UID_ROOT, GID_OPERATOR, 
						      0600, "vn%d", 
						      i);
		if (vn_table[i].sc_bdev == NULL)
			printf("vninit: devfs_make_node failed!\n");
	}
}
#endif /* NVNDEVICE */
