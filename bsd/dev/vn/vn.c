/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 * NOTE 1: This uses the vnop_blockmap/vnop_strategy interface to the vnode
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
#include <sys/kauth.h>
#include <sys/buf.h>
#include <sys/malloc.h>
#include <sys/vnode_internal.h>
#include <sys/fcntl.h>
#include <sys/conf.h>
#include <sys/disk.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/uio_internal.h>

#include <sys/vnioctl.h>

#include <sys/vm.h>

#include <vm/vm_pager.h>
#include <mach/memory_object_types.h>

#include <miscfs/devfs/devfs.h>


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
	u_long		sc_secsize;	/* sector size			*/
	struct vnode	*sc_vp;		/* vnode if not NULL		*/
	uint32_t	sc_vid;
	int		sc_open_flags;
	struct vnode	*sc_shadow_vp;	/* shadow vnode if not NULL	*/
	uint32_t	sc_shadow_vid;
	shadow_map_t *	sc_shadow_map;	/* shadow map if not NULL	*/
	kauth_cred_t sc_cred;	/* credentials 			*/
	u_int32_t	sc_options;	/* options 			*/
	void *		sc_bdev;
	void *		sc_cdev;
} vn_table[NVNDEVICE];

#define ROOT_IMAGE_UNIT	0

/* sc_flags */
#define VNF_INITED	0x01
#define	VNF_READONLY	0x02

static u_int32_t	vn_options;

#define IFOPT(vn,opt) if (((vn)->sc_options|vn_options) & (opt))
#define TESTOPT(vn,opt) (((vn)->sc_options|vn_options) & (opt))

static int	setcred(struct vnode * vp, struct proc * p, 
			kauth_cred_t cred);
static void	vnclear (struct vn_softc *vn, struct proc * p);
static void vn_ioctl_to_64(struct vn_ioctl *from, struct user_vn_ioctl *to);
void vndevice_init(void);
int vndevice_root_image(char * path, char devname[], dev_t * dev_p);

static int
vniocattach_file(struct vn_softc *vn,
		 struct user_vn_ioctl *vniop,
		 dev_t dev,
		 int in_kernel,
		 struct proc *p);
static int
vniocattach_shadow(struct vn_softc * vn,
		   struct user_vn_ioctl *vniop,
		   dev_t dev,
		   int in_kernel,
		   struct proc *p);
static __inline__ int
vnunit(dev_t dev)
{
	return (minor(dev));
}

static	int
vnclose(__unused dev_t dev, __unused int flags, 
		__unused int devtype, __unused struct proc *p)
{
	return (0);
}

static	int
vnopen(dev_t dev, int flags, __unused int devtype, __unused struct proc *p)
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
file_io(struct vnode * vp, struct vfs_context * context_p, 
	enum uio_rw op, char * base, off_t offset, user_ssize_t count,
	user_ssize_t * resid)
{
	uio_t 		auio;
	int		error;
	char		uio_buf[UIO_SIZEOF(1)];
	
	auio = uio_createwithbuffer(1, offset, UIO_SYSSPACE, op, 
				    &uio_buf[0], sizeof(uio_buf));
	uio_addiov(auio, CAST_USER_ADDR_T(base), count);
	if (op == UIO_READ)
		error = VNOP_READ(vp, auio, IO_SYNC, context_p);
	else
		error = VNOP_WRITE(vp, auio, IO_SYNC, context_p);

	if (resid != NULL) {
		*resid = uio_resid(auio);
	}
	return (error);
}

static __inline__ off_t
block_round(off_t o, int blocksize)
{
	return ((o + blocksize - 1) / blocksize);
}

static __inline__ off_t
block_truncate(off_t o, int blocksize)
{
	return (o / blocksize);
}

static __inline__ int
block_remainder(off_t o, int blocksize)
{
	return (o % blocksize);
}

static int
vnread_shadow(struct vn_softc * vn, struct uio *uio, int ioflag, 
	      struct vfs_context * context_p)
{
	u_long		blocksize = vn->sc_secsize;
	int 		error = 0;
	off_t		offset;
	user_ssize_t	resid;
	off_t		orig_offset;
	user_ssize_t	orig_resid;

	orig_resid = resid = uio_resid(uio);
	orig_offset = offset = uio_offset(uio);

	while (resid > 0) {
		u_long		remainder;
		u_long		this_block_number;
		u_long		this_block_count;
		off_t		this_offset;
		user_ssize_t	this_resid;
		struct vnode *	vp;

		/* figure out which blocks to read */
		remainder = block_remainder(offset, blocksize);
		if (shadow_map_read(vn->sc_shadow_map,
				    block_truncate(offset, blocksize),
				    block_round(resid + remainder, blocksize),
				    &this_block_number, &this_block_count)) {
			vp = vn->sc_shadow_vp;
		}
		else {
			vp = vn->sc_vp;
		}

		/* read the blocks (or parts thereof) */
		this_offset = (off_t)this_block_number * blocksize + remainder;
		uio_setoffset(uio, this_offset);
		this_resid = this_block_count * blocksize - remainder;
		if (this_resid > resid) {
			this_resid = resid;
		}
		uio_setresid(uio, this_resid);
		error = VNOP_READ(vp, uio, ioflag, context_p);
		if (error) {
			break;
		}

		/* figure out how much we actually read */
		this_resid -= uio_resid(uio);
		if (this_resid == 0) {
			printf("vn device: vnread_shadow zero length read\n");
			break;
		}
		resid -= this_resid;
		offset += this_resid;
	}
	uio_setresid(uio, resid);
	uio_setoffset(uio, offset);
	return (error);
}

static int
vncopy_block_to_shadow(struct vn_softc * vn, struct vfs_context * context_p,
		       u_long file_block, u_long shadow_block)
{
	int	error;
	char *	tmpbuf;

	tmpbuf = _MALLOC(vn->sc_secsize, M_TEMP, M_WAITOK);
	if (tmpbuf == NULL) {
	    return (ENOMEM);
	}
	/* read one block from file at file_block offset */
	error = file_io(vn->sc_vp, context_p, UIO_READ,
			tmpbuf, (off_t)file_block * vn->sc_secsize, 
			vn->sc_secsize, NULL);
	if (error) {
		goto done;
	}
	/* write one block to shadow file at shadow_block offset */
	error = file_io(vn->sc_shadow_vp, context_p, UIO_WRITE,
			tmpbuf, (off_t)shadow_block * vn->sc_secsize, 
			vn->sc_secsize, NULL);
 done:
	FREE(tmpbuf, M_TEMP);
	return (error);
}

enum {
	FLAGS_FIRST_BLOCK_PARTIAL = 0x1,
	FLAGS_LAST_BLOCK_PARTIAL = 0x2
};

static int
vnwrite_shadow(struct vn_softc * vn, struct uio *uio, int ioflag, 
	       struct vfs_context * context_p)
{
	u_long		blocksize = vn->sc_secsize;
	int 		error = 0;
	user_ssize_t	resid;
	off_t		offset;

	resid = uio_resid(uio);
	offset = uio_offset(uio);

	while (resid > 0) {
		int		flags = 0;
		u_long		offset_block_number;
		u_long		remainder;
		u_long		resid_block_count;
		u_long		shadow_block_count;
		u_long		shadow_block_number;
		user_ssize_t	this_resid;

		/* figure out which blocks to write */
		offset_block_number = block_truncate(offset, blocksize);
		remainder = block_remainder(offset, blocksize);
		resid_block_count = block_round(resid + remainder, blocksize);
		/* figure out if the first or last blocks are partial writes */
		if (remainder > 0
		    && !shadow_map_is_written(vn->sc_shadow_map,
					      offset_block_number)) {
			/* the first block is a partial write */
			flags |= FLAGS_FIRST_BLOCK_PARTIAL;
		}
		if (resid_block_count > 1
		    && !shadow_map_is_written(vn->sc_shadow_map,
					      offset_block_number
					      + resid_block_count - 1)
		    && block_remainder(offset + resid, blocksize) > 0) {
			/* the last block is a partial write */
			flags |= FLAGS_LAST_BLOCK_PARTIAL;
		}
		if (shadow_map_write(vn->sc_shadow_map,
				     offset_block_number, resid_block_count,
				     &shadow_block_number, 
				     &shadow_block_count)) {
			/* shadow file is growing */
#if 0
			/* truncate the file to its new length before write */
			off_t	size;
			size = (off_t)shadow_map_shadow_size(vn->sc_shadow_map) 
				* vn->sc_secsize;
			vnode_setsize(vn->sc_shadow_vp, size, IO_SYNC, 
				      context_p);
#endif 0
		}
		/* write the blocks (or parts thereof) */
		uio_setoffset(uio, (off_t)
			      shadow_block_number * blocksize + remainder);
		this_resid = (off_t)shadow_block_count * blocksize - remainder;
		if (this_resid >= resid) {
			this_resid = resid;
			if ((flags & FLAGS_LAST_BLOCK_PARTIAL) != 0) {
				/* copy the last block to the shadow */
				u_long 	d;
				u_long	s;

				s = offset_block_number 
					+ resid_block_count - 1;
				d = shadow_block_number 
					+ shadow_block_count - 1;
				error = vncopy_block_to_shadow(vn, context_p,
							       s, d);
				if (error) {
					printf("vnwrite_shadow: failed to copy"
					       " block %d to shadow block %d\n",
					       s, d);
					break;
				}
			}
		}
		uio_setresid(uio, this_resid);
		if ((flags & FLAGS_FIRST_BLOCK_PARTIAL) != 0) {
			/* copy the first block to the shadow */
			error = vncopy_block_to_shadow(vn, context_p,
						       offset_block_number,
						       shadow_block_number);
			if (error) {
				printf("vnwrite_shadow: failed to"
				       " copy block %d to shadow block %d\n", 
				       offset_block_number, 
				       shadow_block_number);
				break;
			}
		}
		error = VNOP_WRITE(vn->sc_shadow_vp, uio, ioflag, context_p);
		if (error) {
			break;
		}
		/* figure out how much we actually wrote */
		this_resid -= uio_resid(uio);
		if (this_resid == 0) {
			printf("vn device: vnwrite_shadow zero length write\n");
			break;
		}
		resid -= this_resid;
		offset += this_resid;
	}
	uio_setresid(uio, resid);
	uio_setoffset(uio, offset);
	return (error);
}

static int 
vnread(dev_t dev, struct uio *uio, int ioflag)
{
	struct vfs_context  	context; 		
	int 			error = 0;
	boolean_t   		funnel_state;
	off_t			offset;
	struct proc *		p;
	user_ssize_t		resid;
	struct vn_softc *	vn;
	int 			unit;

	unit = vnunit(dev);
	if (vnunit(dev) >= NVNDEVICE) {
		return (ENXIO);
	}
	p = current_proc();
	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	vn = vn_table + unit;
	if ((vn->sc_flags & VNF_INITED) == 0) {
		error = ENXIO;
		goto done;
	}
	error = vnode_getwithvid(vn->sc_vp, vn->sc_vid);
	if (error != 0) {
		/* the vnode is no longer available, abort */
		error = ENXIO;
		vnclear(vn, p);
		goto done;
	}

	resid = uio_resid(uio);
	offset = uio_offset(uio);

	/*
	 * If out of bounds return an error.  If at the EOF point,
	 * simply read less.
	 */
	if (offset >= (off_t)vn->sc_fsize) {
		if (offset > (off_t)vn->sc_fsize) {
			error = EINVAL;
		}
		goto done;
	}
	/*
	 * If the request crosses EOF, truncate the request.
	 */
	if ((offset + resid) > (off_t)vn->sc_fsize) {
		resid = vn->sc_fsize - offset;
		uio_setresid(uio, resid);
	}

	context.vc_proc = p;
	context.vc_ucred = vn->sc_cred;
	if (vn->sc_shadow_vp != NULL) {
		error = vnode_getwithvid(vn->sc_shadow_vp,
					 vn->sc_shadow_vid);
		if (error != 0) {
			/* the vnode is no longer available, abort */
			error = ENXIO;
			vnode_put(vn->sc_vp);
			vnclear(vn, p);
			goto done;
		}
		error = vnread_shadow(vn, uio, ioflag, &context);
		vnode_put(vn->sc_shadow_vp);
	} else {
		error = VNOP_READ(vn->sc_vp, uio, ioflag, &context);
	}
	vnode_put(vn->sc_vp);
 done:
	(void) thread_funnel_set(kernel_flock, funnel_state);
	return (error);
}

static int 
vnwrite(dev_t dev, struct uio *uio, int ioflag)
{
	struct vfs_context  	context;
	int 			error;
	boolean_t   		funnel_state;
	off_t			offset;
	struct proc *		p;
	user_ssize_t		resid;
	struct vn_softc *	vn;
	int 			unit;

	unit = vnunit(dev);
	if (vnunit(dev) >= NVNDEVICE) {
		return (ENXIO);
	}
	p = current_proc();
	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	vn = vn_table + unit;
	if ((vn->sc_flags & VNF_INITED) == 0) {
		error = ENXIO;
		goto done;
	}
	if (vn->sc_flags & VNF_READONLY) {
		error = EROFS;
		goto done;
	}
	error = vnode_getwithvid(vn->sc_vp, vn->sc_vid);
	if (error != 0) {
		/* the vnode is no longer available, abort */
		error = ENXIO;
		vnclear(vn, p);
		goto done;
	}
	resid = uio_resid(uio);
	offset = uio_offset(uio);

	/*
	 * If out of bounds return an error.  If at the EOF point,
	 * simply write less.
	 */
	if (offset >= (off_t)vn->sc_fsize) {
		if (offset > (off_t)vn->sc_fsize) {
			error = EINVAL;
		}
		goto done;
	}
	/*
	 * If the request crosses EOF, truncate the request.
	 */
	if ((offset + resid) > (off_t)vn->sc_fsize) {
		resid = (off_t)vn->sc_fsize - offset;
		uio_setresid(uio, resid);
	}

	context.vc_proc = p;
	context.vc_ucred = vn->sc_cred;

	if (vn->sc_shadow_vp != NULL) {
		error = vnode_getwithvid(vn->sc_shadow_vp,
					 vn->sc_shadow_vid);
		if (error != 0) {
			/* the vnode is no longer available, abort */
			error = ENXIO;
			vnode_put(vn->sc_vp);
			vnclear(vn, p);
			goto done;
		}
		error = vnwrite_shadow(vn, uio, ioflag, &context);
		vnode_put(vn->sc_shadow_vp);
	} else {
		error = VNOP_WRITE(vn->sc_vp, uio, ioflag, &context);
	}
	vnode_put(vn->sc_vp);
 done:
	(void) thread_funnel_set(kernel_flock, funnel_state);
	return (error);
}

static int
shadow_read(struct vn_softc * vn, struct buf * bp, char * base, struct proc * p)
{
	u_long		blocksize = vn->sc_secsize;
	struct vfs_context  context; 
	int 		error = 0;
	u_long		offset;
	boolean_t	read_shadow;
	u_long		resid;
	u_long		start = 0;

	context.vc_proc = p;
	context.vc_ucred = vn->sc_cred;
	offset = buf_blkno(bp);
	resid =  buf_resid(bp) / blocksize;
	while (resid > 0) {
		user_ssize_t	temp_resid;
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
		error = file_io(vp, &context, UIO_READ, base + start,
				(off_t)this_offset * blocksize,
				(user_ssize_t)this_resid * blocksize, 
				&temp_resid);
		if (error) {
			break;
		}
		this_resid -= (temp_resid / blocksize);
		if (this_resid == 0) {
			printf("vn device: shadow_read zero length read\n");
			break;
		}
		resid -= this_resid;
		offset += this_resid;
		start += this_resid * blocksize;
	}
	buf_setresid(bp, resid * blocksize);
	return (error);
}

static int
shadow_write(struct vn_softc * vn, struct buf * bp, char * base, 
	     struct proc * p)
{
	u_long		blocksize = vn->sc_secsize;
	struct vfs_context  context; 
	int 		error = 0;
	u_long		offset;
	boolean_t	shadow_grew;
	u_long		resid;
	u_long		start = 0;

	context.vc_proc = p;
	context.vc_ucred = vn->sc_cred;
	offset = buf_blkno(bp);
	resid =  buf_resid(bp) / blocksize;
	while (resid > 0) {
		user_ssize_t	temp_resid;
		u_long		this_offset;
		u_long		this_resid;

		shadow_grew = shadow_map_write(vn->sc_shadow_map, 
					       offset, resid, 
					       &this_offset, &this_resid);
		if (shadow_grew) {
#if 0
			off_t	size;
			/* truncate the file to its new length before write */
			size = (off_t)shadow_map_shadow_size(vn->sc_shadow_map) 
				* blocksize;
			vnode_setsize(vn->sc_shadow_vp, size, IO_SYNC,
				      &context);
#endif
		}
		error = file_io(vn->sc_shadow_vp, &context, UIO_WRITE, 
				base + start,
				(off_t)this_offset * blocksize,
				(user_ssize_t)this_resid * blocksize, 
				&temp_resid);
		if (error) {
			break;
		}
		this_resid -= (temp_resid / blocksize);
		if (this_resid == 0) {
			printf("vn device: shadow_write zero length write\n");
			break;
		}
		resid -= this_resid;
		offset += this_resid;
		start += this_resid * blocksize;
	}
	buf_setresid(bp, resid * blocksize);
	return (error);
}

static int
vn_readwrite_io(struct vn_softc * vn, struct buf * bp, struct proc * p)
{
	int			error = 0;
	char *			iov_base;
	caddr_t 		vaddr;
	

	if (buf_map(bp, &vaddr)) 
	        panic("vn device: buf_map failed");
	iov_base = (char *)vaddr;

	if (vn->sc_shadow_vp == NULL) {
		struct vfs_context  	context; 
	        user_ssize_t		temp_resid;

		context.vc_proc = p;
		context.vc_ucred = vn->sc_cred;

		error = file_io(vn->sc_vp, &context,
				buf_flags(bp) & B_READ ? UIO_READ : UIO_WRITE,
				iov_base,
				(off_t)buf_blkno(bp) * vn->sc_secsize,
				buf_resid(bp), &temp_resid);
		buf_setresid(bp, temp_resid);
	}
	else {
		if (buf_flags(bp) & B_READ)
			error = shadow_read(vn, bp, iov_base, p);
		else
			error = shadow_write(vn, bp, iov_base, p);
	}
	buf_unmap(bp);

	return (error);
}

static void
vnstrategy(struct buf *bp)
{
	struct vn_softc *vn;
	int error = 0;
	long sz;	/* in sc_secsize chunks */
	daddr64_t blk_num;
	boolean_t   		funnel_state;
	struct proc * 		p = current_proc();
	struct vnode *		shadow_vp = NULL;
	struct vnode *		vp = NULL;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	vn = vn_table + vnunit(buf_device(bp));
	if ((vn->sc_flags & VNF_INITED) == 0) {
		error = ENXIO;
		goto done;
	}

	buf_setresid(bp, buf_count(bp));
	/*
	 * Check for required alignment.  Transfers must be a valid
	 * multiple of the sector size.
	 */
	blk_num = buf_blkno(bp);
	if (buf_count(bp) % vn->sc_secsize != 0) {
		error = EINVAL;
		goto done;
	}
	sz = howmany(buf_count(bp), vn->sc_secsize);

	/*
	 * If out of bounds return an error.  If at the EOF point,
	 * simply read or write less.
	 */
	if (blk_num >= 0 && (u_int64_t)blk_num >= vn->sc_size) {
		if (blk_num > 0 && (u_int64_t)blk_num > vn->sc_size) {
			error = EINVAL;
		}
		goto done;
	}
	/*
	 * If the request crosses EOF, truncate the request.
	 */
	if ((blk_num + sz) > 0 && ((u_int64_t)(blk_num + sz)) > vn->sc_size) {
		buf_setcount(bp, (vn->sc_size - blk_num) * vn->sc_secsize);
		buf_setresid(bp, buf_count(bp));
	}
	vp = vn->sc_vp;
	if (vp == NULL) {
		error = ENXIO;
		goto done;
	}
	error = vnode_getwithvid(vp, vn->sc_vid);
	if (error != 0) {
		/* the vnode is no longer available, abort */
		error = ENXIO;
		vnclear(vn, p);
		goto done;
	}
	shadow_vp = vn->sc_shadow_vp;
	if (shadow_vp != NULL) {
		error = vnode_getwithvid(shadow_vp,
					 vn->sc_shadow_vid);
		if (error != 0) {
			/* the vnode is no longer available, abort */
			error = ENXIO;
			vnode_put(vn->sc_vp);
			vnclear(vn, p);
			goto done;
		}
	}
	error = vn_readwrite_io(vn, bp, p);
	vnode_put(vp);
	if (shadow_vp != NULL) {
		vnode_put(shadow_vp);
	}

 done:
	(void) thread_funnel_set(kernel_flock, funnel_state);
	if (error) {
	        buf_seterror(bp, error);
	}
	buf_biodone(bp);
	return;
}

/* ARGSUSED */
static	int
vnioctl(dev_t dev, u_long cmd, caddr_t data,
	__unused int flag, struct proc *p,
	int is_char)
{
	struct vn_softc *vn;
	struct user_vn_ioctl *viop;
	int error;
	u_int32_t *f;
	u_int64_t * o;
	int unit;
	struct vfsioattr ioattr;
	struct user_vn_ioctl user_vnio;
	boolean_t   		funnel_state;

	unit = vnunit(dev);
	if (vnunit(dev) >= NVNDEVICE) {
		return (ENXIO);
	}

	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	vn = vn_table + unit;
	error = proc_suser(p);
	if (error) {
		goto done;
	}

	viop = (struct user_vn_ioctl *)data;
	f = (u_int32_t *)data;
	o = (u_int64_t *)data;
	switch (cmd) {
	case VNIOCDETACH:
	case VNIOCDETACH64:
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
			error = ENXIO;
			goto done;
		}
		break;
	default:
		break;
	}

	if (vn->sc_vp != NULL)
		vfs_ioattr(vnode_mount(vn->sc_vp), &ioattr);
	else
		bzero(&ioattr, sizeof(ioattr));

	switch (cmd) {
	case DKIOCISVIRTUAL:
		*f = 1;
		break;
	case DKIOCGETMAXBLOCKCOUNTREAD:
		*o = ioattr.io_maxreadcnt / vn->sc_secsize;
		break;
	case DKIOCGETMAXBLOCKCOUNTWRITE:
		*o = ioattr.io_maxwritecnt / vn->sc_secsize;
		break;
	case DKIOCGETMAXBYTECOUNTREAD:
		*o = ioattr.io_maxreadcnt;
		break;
	case DKIOCGETMAXBYTECOUNTWRITE:
		*o = ioattr.io_maxwritecnt;
		break;
	case DKIOCGETMAXSEGMENTCOUNTREAD:
		*o = ioattr.io_segreadcnt;
		break;
	case DKIOCGETMAXSEGMENTCOUNTWRITE:
		*o = ioattr.io_segwritecnt;
		break;
	case DKIOCGETMAXSEGMENTBYTECOUNTREAD:
		*o = ioattr.io_maxsegreadsize;
		break;
	case DKIOCGETMAXSEGMENTBYTECOUNTWRITE:
		*o = ioattr.io_maxsegwritesize;
		break;
	case DKIOCGETBLOCKSIZE:
	        *f = vn->sc_secsize;
		break;
	case DKIOCSETBLOCKSIZE:
		if (is_char) {
			/* can only set block size on block device */
			error = ENODEV;
			break;
		}
		if (*f < DEV_BSIZE) {
			error = EINVAL;
			break;
		}
		if (vn->sc_shadow_vp != NULL) {
			if (*f == (unsigned)vn->sc_secsize) {
				break;
			}
			/* can't change the block size if already shadowing */
			error = EBUSY;
			break;
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
	case VNIOCSHADOW64:
		if (vn->sc_shadow_vp != NULL) {
			error = EBUSY;
			break;
		}
		if (vn->sc_vp == NULL) {
			/* much be attached before we can shadow */
			error = EINVAL;
			break;
		}
		if (!proc_is64bit(p)) {
			/* downstream code expects LP64 version of vn_ioctl structure */
			vn_ioctl_to_64((struct vn_ioctl *)viop, &user_vnio);
			viop = &user_vnio;
		}
		if (viop->vn_file == USER_ADDR_NULL) {
			error = EINVAL;
			break;
		}
		error = vniocattach_shadow(vn, viop, dev, 0, p);
		break;

	case VNIOCATTACH:
	case VNIOCATTACH64:
		if (is_char) {
			/* attach only on block device */
			error = ENODEV;
			break;
		}
		if (vn->sc_flags & VNF_INITED) {
			error = EBUSY;
			break;
		}
		if (!proc_is64bit(p)) {
			/* downstream code expects LP64 version of vn_ioctl structure */
			vn_ioctl_to_64((struct vn_ioctl *)viop, &user_vnio);
			viop = &user_vnio;
		}
		if (viop->vn_file == USER_ADDR_NULL) {
			error = EINVAL;
			break;
		}
		error = vniocattach_file(vn, viop, dev, 0, p);
		break;

	case VNIOCDETACH:
	case VNIOCDETACH64:
		if (is_char) {
			/* detach only on block device */
			error = ENODEV;
			break;
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
		vnclear(vn, p);
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
 done:
	(void) thread_funnel_set(kernel_flock, funnel_state);
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
		 struct user_vn_ioctl *vniop,
		 dev_t dev,
		 int in_kernel,
		 struct proc *p)
{
	dev_t	cdev;
	struct vfs_context context;
	kauth_cred_t cred;
	struct nameidata nd;
	off_t file_size;
	int error, flags;

	context.vc_proc = p;
	context.vc_ucred = proc_ucred(p);
	
	flags = FREAD|FWRITE;
	if (in_kernel) {
		NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE32, vniop->vn_file, &context);
	}
	else {
		NDINIT(&nd, LOOKUP, FOLLOW, 
			   (IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32), 
			   vniop->vn_file, &context);
	}
	/* vn_open gives both long- and short-term references */
	error = vn_open(&nd, flags, 0);
	if (error) {
		if (error != EACCES && error != EPERM && error != EROFS)
			return (error);
		flags &= ~FWRITE;
		if (in_kernel) {
			NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE32, 
			       vniop->vn_file, &context);
		}
		else {
			NDINIT(&nd, LOOKUP, FOLLOW, 
				   (IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32), 
			       vniop->vn_file, &context);
		}
		error = vn_open(&nd, flags, 0);
		if (error)
			return (error);
	}
	if (nd.ni_vp->v_type != VREG) {
		error = EINVAL;
	}
	else {
		error = vnode_size(nd.ni_vp, &file_size, &context);
	}
	if (error != 0) {
		(void) vn_close(nd.ni_vp, flags, proc_ucred(p), p);
		vnode_put(nd.ni_vp);
		return (error);
	}
	cred = kauth_cred_proc_ref(p);
	nd.ni_vp->v_flag |= VNOCACHE_DATA;
	error = setcred(nd.ni_vp, p, cred);
	if (error) {
		(void)vn_close(nd.ni_vp, flags, proc_ucred(p), p);
		vnode_put(nd.ni_vp);
		kauth_cred_rele(cred);
		return(error);
	}
	vn->sc_secsize = DEV_BSIZE;
	vn->sc_fsize = file_size;
	vn->sc_size = file_size / vn->sc_secsize;
	vn->sc_vp = nd.ni_vp;
	vn->sc_vid = vnode_vid(nd.ni_vp);
	vn->sc_open_flags = flags;
	vn->sc_cred = cred;
	cdev = makedev(vndevice_cdev_major, minor(dev));
	vn->sc_cdev = devfs_make_node(cdev, DEVFS_CHAR,
				      UID_ROOT, GID_OPERATOR, 
				      0600, "rvn%d", 
				      minor(dev));
	vn->sc_flags |= VNF_INITED;
	if (flags == FREAD)
		vn->sc_flags |= VNF_READONLY;
	/* lose the short-term reference */
	vnode_put(nd.ni_vp);
	return(0);
}

static int
vniocattach_shadow(struct vn_softc *vn, struct user_vn_ioctl *vniop, 
				   __unused int dev, int in_kernel, struct proc *p)
{
	struct vfs_context context;
	struct nameidata nd;
	int error, flags;
	shadow_map_t *	map;
	off_t file_size;

	context.vc_proc = p;
	context.vc_ucred = proc_ucred(p);
	
	flags = FREAD|FWRITE;
	if (in_kernel) {
		NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE32, vniop->vn_file, &context);
	}
	else {
		NDINIT(&nd, LOOKUP, FOLLOW, 
			   (IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32), 
			   vniop->vn_file, &context);
	}
	/* vn_open gives both long- and short-term references */
	error = vn_open(&nd, flags, 0);
	if (error) {
		/* shadow MUST be writable! */
		return (error);
	}
	if (nd.ni_vp->v_type != VREG 
	    || (error = vnode_size(nd.ni_vp, &file_size, &context))) {
		(void)vn_close(nd.ni_vp, flags, proc_ucred(p), p);
		vnode_put(nd.ni_vp);
		return (error ? error : EINVAL);
	}
	map = shadow_map_create(vn->sc_fsize, file_size,
				0, vn->sc_secsize);
	if (map == NULL) {
		(void)vn_close(nd.ni_vp, flags, proc_ucred(p), p);
		vnode_put(nd.ni_vp);
		vn->sc_shadow_vp = NULL;
		return (ENOMEM);
	}
	vn->sc_shadow_vp = nd.ni_vp;
	vn->sc_shadow_vid = vnode_vid(nd.ni_vp);
	vn->sc_shadow_vp->v_flag |= VNOCACHE_DATA;
	vn->sc_shadow_map = map;
	vn->sc_flags &= ~VNF_READONLY; /* we're now read/write */

	/* lose the short-term reference */
	vnode_put(nd.ni_vp);
	return(0);
}

int
vndevice_root_image(char * path, char devname[], dev_t * dev_p)
{
	int 			error = 0;
	struct vn_softc *		vn;
	struct user_vn_ioctl 	vnio;

	vnio.vn_file = CAST_USER_ADDR_T(path);
	vnio.vn_size = 0;

	vn = vn_table + ROOT_IMAGE_UNIT;
	*dev_p = makedev(vndevice_bdev_major, 
			 ROOT_IMAGE_UNIT);
	sprintf(devname, "vn%d", ROOT_IMAGE_UNIT);
	error = vniocattach_file(vn, &vnio, *dev_p, 1, current_proc());
	return (error);
}

/*
 * Duplicate the current processes' credentials.  Since we are called only
 * as the result of a SET ioctl and only root can do that, any future access
 * to this "disk" is essentially as root.  Note that credentials may change
 * if some other uid can write directly to the mapped file (NFS).
 */
static int
setcred(struct vnode * vp, struct proc * p, kauth_cred_t cred)
{
	char *tmpbuf;
	int error = 0;
	struct vfs_context  context; 		

	/*
	 * Horrible kludge to establish credentials for NFS  XXX.
	 */
	context.vc_proc = p;
	context.vc_ucred = cred;
	tmpbuf = _MALLOC(DEV_BSIZE, M_TEMP, M_WAITOK);
	error = file_io(vp, &context, UIO_READ, tmpbuf, 0, DEV_BSIZE, NULL);
	FREE(tmpbuf, M_TEMP);
	return (error);
}

void
vnclear(struct vn_softc *vn, struct proc * p)
{
	if (vn->sc_vp != NULL) {
		/* release long-term reference */
		(void)vn_close(vn->sc_vp, vn->sc_open_flags, vn->sc_cred, p);
		vn->sc_vp = NULL;
	}
	if (vn->sc_shadow_vp != NULL) {
		/* release long-term reference */
		(void)vn_close(vn->sc_shadow_vp, FREAD | FWRITE, 
			       vn->sc_cred, p);
		vn->sc_shadow_vp = NULL;
	}
	if (vn->sc_shadow_map != NULL) {
		shadow_map_free(vn->sc_shadow_map);
		vn->sc_shadow_map = NULL;
	}
	vn->sc_flags &= ~(VNF_INITED | VNF_READONLY);
	if (vn->sc_cred) {
		kauth_cred_rele(vn->sc_cred);
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
	int	secsize;
	struct vn_softc *vn;
	int unit;
	boolean_t   		funnel_state;

	unit = vnunit(dev);
	if (vnunit(dev) >= NVNDEVICE) {
		return (-1);
	}

	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	vn = vn_table + unit;
	if ((vn->sc_flags & VNF_INITED) == 0)
		secsize = -1;
	else
		secsize = vn->sc_secsize;
	(void) thread_funnel_set(kernel_flock, funnel_state);
	return (secsize);
}

#define CDEV_MAJOR 	-1
#define BDEV_MAJOR 	-1
static int vndevice_inited = 0;

void 
vndevice_init(void)
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

static void 
vn_ioctl_to_64(struct vn_ioctl *from, struct user_vn_ioctl *to) 
{
	to->vn_file = CAST_USER_ADDR_T(from->vn_file);
	to->vn_size = from->vn_size;
	to->vn_control = from->vn_control;
}

#endif /* NVNDEVICE */
