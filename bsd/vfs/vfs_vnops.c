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
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	@(#)vfs_vnops.c	8.14 (Berkeley) 6/15/95
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/buf.h>
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <sys/ubc.h>
#include <sys/conf.h>
#include <sys/disk.h>

#include <vm/vm_kern.h>

#include <miscfs/specfs/specdev.h>

static int vn_closefile __P((struct file *fp, struct proc *p));
static int vn_ioctl __P((struct file *fp, u_long com, caddr_t data,
		struct proc *p));
static int vn_read __P((struct file *fp, struct uio *uio,
		struct ucred *cred, int flags, struct proc *p));
static int vn_write __P((struct file *fp, struct uio *uio,
		struct ucred *cred, int flags, struct proc *p));
static int vn_select __P(( struct file *fp, int which, void * wql,
		struct proc *p));

struct 	fileops vnops =
	{ vn_read, vn_write, vn_ioctl, vn_select, vn_closefile };

/*
 * Common code for vnode open operations.
 * Check permissions, and call the VOP_OPEN or VOP_CREATE routine.
 */
int
vn_open(ndp, fmode, cmode)
	register struct nameidata *ndp;
	int fmode, cmode;
{
	register struct vnode *vp;
	register struct proc *p = ndp->ni_cnd.cn_proc;
	register struct ucred *cred = p->p_ucred;
	struct vattr vat;
	struct vattr *vap = &vat;
	int error;
	int didhold = 0;

	if (fmode & O_CREAT) {
		ndp->ni_cnd.cn_nameiop = CREATE;
		ndp->ni_cnd.cn_flags = LOCKPARENT | LOCKLEAF;
		if ((fmode & O_EXCL) == 0)
			ndp->ni_cnd.cn_flags |= FOLLOW;
		bwillwrite();
		if (error = namei(ndp))
			return (error);
		if (ndp->ni_vp == NULL) {
			VATTR_NULL(vap);
			vap->va_type = VREG;
			vap->va_mode = cmode;
			if (fmode & O_EXCL)
				vap->va_vaflags |= VA_EXCLUSIVE;
			VOP_LEASE(ndp->ni_dvp, p, cred, LEASE_WRITE);
			if (error = VOP_CREATE(ndp->ni_dvp, &ndp->ni_vp,
			    &ndp->ni_cnd, vap))
				return (error);
			fmode &= ~O_TRUNC;
			vp = ndp->ni_vp;
		} else {
			VOP_ABORTOP(ndp->ni_dvp, &ndp->ni_cnd);
			if (ndp->ni_dvp == ndp->ni_vp)
				vrele(ndp->ni_dvp);
			else
				vput(ndp->ni_dvp);
			ndp->ni_dvp = NULL;
			vp = ndp->ni_vp;
			if (fmode & O_EXCL) {
				error = EEXIST;
				goto bad;
			}
			fmode &= ~O_CREAT;
		}
	} else {
		ndp->ni_cnd.cn_nameiop = LOOKUP;
		ndp->ni_cnd.cn_flags = FOLLOW | LOCKLEAF;
		if (error = namei(ndp))
			return (error);
		vp = ndp->ni_vp;
	}
	if (vp->v_type == VSOCK) {
		error = EOPNOTSUPP;
		goto bad;
	}

#if DIAGNOSTIC
	if (UBCINFOMISSING(vp))
		panic("vn_open: ubc_info_init");
#endif /* DIAGNOSTIC */

	if (UBCINFOEXISTS(vp) && ((didhold = ubc_hold(vp)) == 0)) {
		error = ENOENT;
		goto bad;
	}

	if ((fmode & O_CREAT) == 0) {
		if (fmode & FREAD && fmode & (FWRITE | O_TRUNC)) {
			int err = 0;
			if (vp->v_type == VDIR)
				err = EISDIR;
			else
				err = vn_writechk(vp);
			if (err && !(error = VOP_ACCESS(vp, VREAD, cred, p)))
				error = err;
			if (error || (error = VOP_ACCESS(vp, VREAD|VWRITE,
							 cred, p)))
				goto bad;
		} else if (fmode & FREAD) {
			if ((error = VOP_ACCESS(vp, VREAD, cred, p)))
				goto bad;
		} else if (fmode & (FWRITE | O_TRUNC)) {
			if (vp->v_type == VDIR) {
				error = EISDIR;
				goto bad;
			}
			if ((error = vn_writechk(vp)) ||
			    (error = VOP_ACCESS(vp, VWRITE, cred, p)))
				goto bad;
		}
	}
	if (fmode & O_TRUNC) {
		VOP_UNLOCK(vp, 0, p);				/* XXX */
		VOP_LEASE(vp, p, cred, LEASE_WRITE);
		(void)vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);	/* XXX */
		VATTR_NULL(vap);
		vap->va_size = 0;
		if (error = VOP_SETATTR(vp, vap, cred, p))
			goto bad;
	}

	if (error = VOP_OPEN(vp, fmode, cred, p)) {
		goto bad;
	}

	if (fmode & FWRITE)
		if (++vp->v_writecount <= 0)
			panic("vn_open: v_writecount");
	return (0);
bad:
	VOP_UNLOCK(vp, 0, p);
	if (didhold)
		ubc_rele(vp);
	vrele(vp);
	return (error);
}

/*
 * Check for write permissions on the specified vnode.
 * Prototype text segments cannot be written.
 */
int
vn_writechk(vp)
	register struct vnode *vp;
{

	/*
	 * If there's shared text associated with
	 * the vnode, try to free it up once.  If
	 * we fail, we can't allow writing.
	 */
#if 0
	/* XXXXX Not sure we need this */
	if (vp->v_flag & VTEXT)
		return (ETXTBSY);
#endif /* 0 */
	return (0);
}

/*
 * Vnode close call
 */
int
vn_close(vp, flags, cred, p)
	register struct vnode *vp;
	int flags;
	struct ucred *cred;
	struct proc *p;
{
	int error;

	if (flags & FWRITE)
		vp->v_writecount--;
	error = VOP_CLOSE(vp, flags, cred, p);
	ubc_rele(vp);
	vrele(vp);
	return (error);
}

/*
 * Package up an I/O request on a vnode into a uio and do it.
 */
int
vn_rdwr(rw, vp, base, len, offset, segflg, ioflg, cred, aresid, p)
	enum uio_rw rw;
	struct vnode *vp;
	caddr_t base;
	int len;
	off_t offset;
	enum uio_seg segflg;
	int ioflg;
	struct ucred *cred;
	int *aresid;
	struct proc *p;
{
	struct uio auio;
	struct iovec aiov;
	int error=0;

	 /* FIXME XXX */
	if ((ioflg & IO_NODELOCKED) == 0)
		(void)vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	aiov.iov_base = base;
	aiov.iov_len = len;
	auio.uio_resid = len;
	auio.uio_offset = offset;
	auio.uio_segflg = segflg;
	auio.uio_rw = rw;
	auio.uio_procp = p;

	if (rw == UIO_READ)
		error = VOP_READ(vp, &auio, ioflg, cred);
	 else 
		error = VOP_WRITE(vp, &auio, ioflg, cred);

	if (aresid)
		*aresid = auio.uio_resid;
	else
		if (auio.uio_resid && error == 0)
			error = EIO;
	if ((ioflg & IO_NODELOCKED) == 0)
		VOP_UNLOCK(vp, 0, p);
	return (error);
}

/*
 * File table vnode read routine.
 */
static int
vn_read(fp, uio, cred, flags, p)
	struct file *fp;
	struct uio *uio;
	struct ucred *cred;
	int flags;
	struct proc *p;
{
	struct vnode *vp;
	int error, ioflag;
	off_t count;

	if (p != uio->uio_procp)
		panic("vn_read: uio_procp does not match p");

	vp = (struct vnode *)fp->f_data;
	ioflag = 0;
	if (fp->f_flag & FNONBLOCK)
		ioflag |= IO_NDELAY;
	VOP_LEASE(vp, p, cred, LEASE_READ);
	error = vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	if (error)
		return (error);
	if ((flags & FOF_OFFSET) == 0)
		uio->uio_offset = fp->f_offset;
	count = uio->uio_resid;

	if(UBCINFOEXISTS(vp)) {
		memory_object_t	pager;
		struct iovec    *iov;
		off_t		file_off;
		kern_return_t	kr = KERN_SUCCESS;
		kern_return_t	ret = KERN_SUCCESS;
		int		count;

		pager = (memory_object_t)ubc_getpager(vp);
		file_off = uio->uio_offset;
		iov = uio->uio_iov;
		count = uio->uio_iovcnt;
		while(count) {
			kr = vm_conflict_check(current_map(), 
				(vm_offset_t)iov->iov_base, iov->iov_len, 
				pager, file_off);
			if(kr == KERN_ALREADY_WAITING) {
				if((count != uio->uio_iovcnt) &&
				   (ret != KERN_ALREADY_WAITING)) {
					error = EINVAL;
					goto done;
				}
				ret = KERN_ALREADY_WAITING;
			} else if (kr != KERN_SUCCESS) {
				error = EINVAL;
				goto done;
			}
			if(kr != ret) {
				error = EINVAL;
				goto done;
			}
			file_off += iov->iov_len;
			iov++;
			count--;
		}
		if(ret == KERN_ALREADY_WAITING) {
			uio->uio_resid = 0;
			if ((flags & FOF_OFFSET) == 0)
				fp->f_offset += 
					count - uio->uio_resid;
			error = 0;
			goto done;
		}
	}
	error = VOP_READ(vp, uio, ioflag, cred);
	if ((flags & FOF_OFFSET) == 0)
		fp->f_offset += count - uio->uio_resid;
done:
	VOP_UNLOCK(vp, 0, p);
	return (error);
}


/*
 * File table vnode write routine.
 */
static int
vn_write(fp, uio, cred, flags, p)
	struct file *fp;
	struct uio *uio;
	struct ucred *cred;
	int flags;
	struct proc *p;
{
	struct vnode *vp;
	int error, ioflag;
	off_t count;

	if (p != uio->uio_procp)
		panic("vn_write: uio_procp does not match p");

	vp = (struct vnode *)fp->f_data;
	ioflag = IO_UNIT;
	if (vp->v_type == VREG)
		bwillwrite();
	if (vp->v_type == VREG && (fp->f_flag & O_APPEND))
		ioflag |= IO_APPEND;
	if (fp->f_flag & FNONBLOCK)
		ioflag |= IO_NDELAY;
	if ((fp->f_flag & O_FSYNC) ||
		(vp->v_mount && (vp->v_mount->mnt_flag & MNT_SYNCHRONOUS)))
		ioflag |= IO_SYNC;
	VOP_LEASE(vp, p, cred, LEASE_WRITE);
	error = vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	if (error)
		return (error);
	if ((flags & FOF_OFFSET) == 0) {
		uio->uio_offset = fp->f_offset;
		count = uio->uio_resid;
	}

	if(UBCINFOEXISTS(vp)) {
		memory_object_t		pager;
		struct iovec		*iov;
		off_t			file_off;
		kern_return_t		kr = KERN_SUCCESS;
		kern_return_t		ret = KERN_SUCCESS;
		int			count;

		pager = (memory_object_t)ubc_getpager(vp);
		file_off = uio->uio_offset;
		iov = uio->uio_iov;
		count = uio->uio_iovcnt;
		while(count) {
			kr = vm_conflict_check(current_map(), 
				(vm_offset_t)iov->iov_base, 
				iov->iov_len, pager, file_off);
			if(kr == KERN_ALREADY_WAITING) {
				if((count != uio->uio_iovcnt) &&
				   (ret != KERN_ALREADY_WAITING)) {
					error = EINVAL;
					goto done;
				}
				ret = KERN_ALREADY_WAITING;
			} else if (kr != KERN_SUCCESS) {
				error = EINVAL;
				goto done;
			}
			if(kr != ret) {
				error = EINVAL;
				goto done;
			}
			file_off += iov->iov_len;
			iov++;
			count--;
		}
		if(ret == KERN_ALREADY_WAITING) {
			uio->uio_resid = 0;
			if ((flags & FOF_OFFSET) == 0)
				fp->f_offset += 
					count - uio->uio_resid;
			error = 0;
			goto done;
		}
	}
	error = VOP_WRITE(vp, uio, ioflag, cred);

	if ((flags & FOF_OFFSET) == 0) {
		if (ioflag & IO_APPEND)
			fp->f_offset = uio->uio_offset;
		else
			fp->f_offset += count - uio->uio_resid;
	}

	/*
	 * Set the credentials on successful writes
	 */
	if ((error == 0) && (vp->v_tag == VT_NFS) && (UBCINFOEXISTS(vp))) {
		ubc_setcred(vp, p);
	}

done:
	VOP_UNLOCK(vp, 0, p);
	return (error);
}

/*
 * File table vnode stat routine.
 */
int
vn_stat(vp, sb, p)
	struct vnode *vp;
	register struct stat *sb;
	struct proc *p;
{
	struct vattr vattr;
	register struct vattr *vap;
	int error;
	u_short mode;

	vap = &vattr;
	error = VOP_GETATTR(vp, vap, p->p_ucred, p);
	if (error)
		return (error);
	/*
	 * Copy from vattr table
	 */
	sb->st_dev = vap->va_fsid;
	sb->st_ino = vap->va_fileid;
	mode = vap->va_mode;
	switch (vp->v_type) {
	case VREG:
		mode |= S_IFREG;
		break;
	case VDIR:
		mode |= S_IFDIR;
		break;
	case VBLK:
		mode |= S_IFBLK;
		break;
	case VCHR:
		mode |= S_IFCHR;
		break;
	case VLNK:
		mode |= S_IFLNK;
		break;
	case VSOCK:
		mode |= S_IFSOCK;
		break;
	case VFIFO:
		mode |= S_IFIFO;
		break;
	default:
		return (EBADF);
	};
	sb->st_mode = mode;
	sb->st_nlink = vap->va_nlink;
	sb->st_uid = vap->va_uid;
	sb->st_gid = vap->va_gid;
	sb->st_rdev = vap->va_rdev;
	sb->st_size = vap->va_size;
	sb->st_atimespec = vap->va_atime;
	sb->st_mtimespec = vap->va_mtime;
	sb->st_ctimespec = vap->va_ctime;
	sb->st_blksize = vap->va_blocksize;
	sb->st_flags = vap->va_flags;
	/* Do not give the generation number out to unpriviledged users */
	if (suser(p->p_ucred, &p->p_acflag))
		sb->st_gen = 0; 
	else
		sb->st_gen = vap->va_gen;
	sb->st_blocks = vap->va_bytes / S_BLKSIZE;
	return (0);
}

/*
 * File table vnode ioctl routine.
 */
static int
vn_ioctl(fp, com, data, p)
	struct file *fp;
	u_long com;
	caddr_t data;
	struct proc *p;
{
	register struct vnode *vp = ((struct vnode *)fp->f_data);
	struct vattr vattr;
	int error;
	struct vnode *ttyvp;
	
	switch (vp->v_type) {

	case VREG:
	case VDIR:
		if (com == FIONREAD) {
			if (error = VOP_GETATTR(vp, &vattr, p->p_ucred, p))
				return (error);
			*(int *)data = vattr.va_size - fp->f_offset;
			return (0);
		}
		if (com == FIONBIO || com == FIOASYNC)	/* XXX */
			return (0);			/* XXX */
		/* fall into ... */

	default:
		return (ENOTTY);

	case VFIFO:
	case VCHR:
	case VBLK:

	  /* Should not be able to set block size from user space */
	  if(com == DKIOCSETBLOCKSIZE)
	    return (EPERM);
	  
	  if (com == FIODTYPE) {
	    if (vp->v_type == VBLK) {
	      if (major(vp->v_rdev) >= nblkdev)
		return (ENXIO);
	      *(int *)data = bdevsw[major(vp->v_rdev)].d_type;
	    } else if (vp->v_type == VCHR) {
	      if (major(vp->v_rdev) >= nchrdev)
		return (ENXIO);
	      *(int *)data = cdevsw[major(vp->v_rdev)].d_type;
	    } else {
	      return (ENOTTY);
	    }
	    return (0);
	  }
	  error = VOP_IOCTL(vp, com, data, fp->f_flag, p->p_ucred, p);
	  if (error == 0 && com == TIOCSCTTY) {
	    VREF(vp);
	    ttyvp = p->p_session->s_ttyvp;
	    p->p_session->s_ttyvp = vp;
	    if (ttyvp)
	      vrele(ttyvp);
	  }
	  return (error);
	}
}

/*
 * File table vnode select routine.
 */
static int
vn_select(fp, which, wql, p)
	struct file *fp;
	int which;
	void * wql;
	struct proc *p;
{

	return(VOP_SELECT(((struct vnode *)fp->f_data), which, fp->f_flag,
		fp->f_cred, wql, p));
}

/*
 * Check that the vnode is still valid, and if so
 * acquire requested lock.
 */
int
vn_lock(vp, flags, p)
	struct vnode *vp;
	int flags;
	struct proc *p;
{
	int error;
	
	do {
		if ((flags & LK_INTERLOCK) == 0)
			simple_lock(&vp->v_interlock);
		if (vp->v_flag & VXLOCK) {
			while (vp->v_flag & VXLOCK) {
				vp->v_flag |= VXWANT;
				simple_unlock(&vp->v_interlock);
				(void)tsleep((caddr_t)vp, PINOD, "vn_lock", 0);
			}
			error = ENOENT;
		} else {
			error = VOP_LOCK(vp, flags | LK_INTERLOCK, p);
			if (error == 0)
				return (error);
		}
		flags &= ~LK_INTERLOCK;
	} while (flags & LK_RETRY);
	return (error);
}

/*
 * File table vnode close routine.
 */
static int
vn_closefile(fp, p)
	struct file *fp;
	struct proc *p;
{

	return (vn_close(((struct vnode *)fp->f_data), fp->f_flag,
		fp->f_cred, p));
}
