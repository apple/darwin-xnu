/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software donated to Berkeley by
 * Jan-Simon Pendry.
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
 *	@(#)fdesc_vnops.c	8.17 (Berkeley) 5/22/95
 *
 */

/*
 * /dev/fd Filesystem
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/proc.h>
#include <sys/kernel.h>	/* boottime */
#include <sys/resourcevar.h>
#include <sys/filedesc.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/buf.h>
#include <sys/dirent.h>
#include <sys/ubc.h>
#include <miscfs/fdesc/fdesc.h>
#include <vfs/vfs_support.h>

#define FDL_WANT	0x01
#define FDL_LOCKED	0x02
static int fdcache_lock;


#if (FD_STDIN != FD_STDOUT-1) || (FD_STDOUT != FD_STDERR-1)
FD_STDIN, FD_STDOUT, FD_STDERR must be a sequence n, n+1, n+2
#endif

#define	NFDCACHE 3

#define FD_NHASH(ix) \
	(&fdhashtbl[(ix) & fdhash])
LIST_HEAD(fdhashhead, fdescnode) *fdhashtbl;
u_long fdhash;

/*
 * Initialise cache headers
 */
fdesc_init(vfsp)
	struct vfsconf *vfsp;
{

	fdhashtbl = hashinit(NFDCACHE, M_CACHE, &fdhash);
}

int
fdesc_allocvp(ftype, ix, mp, vpp)
	fdntype ftype;
	int ix;
	struct mount *mp;
	struct vnode **vpp;
{
	struct proc *p = current_proc();	/* XXX */
	struct fdhashhead *fc;
	struct fdescnode *fd;
	int error = 0;

	fc = FD_NHASH(ix);
loop:
	for (fd = fc->lh_first; fd != 0; fd = fd->fd_hash.le_next) {
		if (fd->fd_ix == ix && fd->fd_vnode->v_mount == mp) {
			if (vget(fd->fd_vnode, 0, p))
				goto loop;
			*vpp = fd->fd_vnode;
			return (error);
		}
	}

	/*
	 * otherwise lock the array while we call getnewvnode
	 * since that can block.
	 */ 
	if (fdcache_lock & FDL_LOCKED) {
		fdcache_lock |= FDL_WANT;
		sleep((caddr_t) &fdcache_lock, PINOD);
		goto loop;
	}
	fdcache_lock |= FDL_LOCKED;

	MALLOC(fd, void *, sizeof(struct fdescnode), M_TEMP, M_WAITOK);
	error = getnewvnode(VT_FDESC, mp, fdesc_vnodeop_p, vpp);
	if (error) {
		FREE(fd, M_TEMP);
		goto out;
	}
	(*vpp)->v_data = fd;
	fd->fd_vnode = *vpp;
	fd->fd_type = ftype;
	fd->fd_fd = -1;
	fd->fd_link = 0;
	fd->fd_ix = ix;
	LIST_INSERT_HEAD(fc, fd, fd_hash);

out:
	fdcache_lock &= ~FDL_LOCKED;

	if (fdcache_lock & FDL_WANT) {
		fdcache_lock &= ~FDL_WANT;
		wakeup((caddr_t) &fdcache_lock);
	}

	return (error);
}

/*
 * vp is the current namei directory
 * ndp is the name to locate in that directory...
 */
int
fdesc_lookup(ap)
	struct vop_lookup_args /* {
		struct vnode * a_dvp;
		struct vnode ** a_vpp;
		struct componentname * a_cnp;
	} */ *ap;
{
	struct vnode **vpp = ap->a_vpp;
	struct vnode *dvp = ap->a_dvp;
	struct componentname *cnp = ap->a_cnp;
	char *pname = cnp->cn_nameptr;
	struct proc *p = cnp->cn_proc;
	int nfiles = p->p_fd->fd_nfiles;
	unsigned fd;
	int error;
	struct vnode *fvp;
	char *ln;

	VOP_UNLOCK(dvp, 0, p);
	if (cnp->cn_namelen == 1 && *pname == '.') {
		*vpp = dvp;
		VREF(dvp);	
		vn_lock(dvp, LK_SHARED | LK_RETRY, p);
		return (0);
	}

	switch (VTOFDESC(dvp)->fd_type) {
	default:
	case Flink:
	case Fdesc:
		error = ENOTDIR;
		goto bad;

	case Froot:
		if (cnp->cn_namelen == 2 && bcmp(pname, "fd", 2) == 0) {
			error = fdesc_allocvp(Fdevfd, FD_DEVFD, dvp->v_mount, &fvp);
			if (error)
				goto bad;
			*vpp = fvp;
			fvp->v_type = VDIR;
			vn_lock(fvp, LK_SHARED | LK_RETRY, p);
			return (0);
		}

		ln = 0;
		switch (cnp->cn_namelen) {
		case 5:
			if (bcmp(pname, "stdin", 5) == 0) {
				ln = "fd/0";
				fd = FD_STDIN;
			}
			break;
		case 6:
			if (bcmp(pname, "stdout", 6) == 0) {
				ln = "fd/1";
				fd = FD_STDOUT;
			} else
			if (bcmp(pname, "stderr", 6) == 0) {
				ln = "fd/2";
				fd = FD_STDERR;
			}
			break;
		}

		if (ln) {
			error = fdesc_allocvp(Flink, fd, dvp->v_mount, &fvp);
			if (error)
				goto bad;
			VTOFDESC(fvp)->fd_link = ln;
			*vpp = fvp;
			fvp->v_type = VLNK;
			vn_lock(fvp, LK_SHARED | LK_RETRY, p);
			return (0);
		} else {
			error = ENOENT;
			goto bad;
		}

		/* FALL THROUGH */

	case Fdevfd:
		if (cnp->cn_namelen == 2 && bcmp(pname, "..", 2) == 0) {
			if (error = fdesc_root(dvp->v_mount, vpp))
				goto bad;
			return (0);
		}

		fd = 0;
		while (*pname >= '0' && *pname <= '9') {
			fd = 10 * fd + *pname++ - '0';
			if (fd >= nfiles)
				break;
		}

		if (*pname != '\0') {
			error = ENOENT;
			goto bad;
		}

		if (fd >= nfiles ||
				*fdfile(p, fd) == NULL ||
				(*fdflags(p, fd) & UF_RESERVED)) {
			error = EBADF;
			goto bad;
		}

		error = fdesc_allocvp(Fdesc, FD_DESC+fd, dvp->v_mount, &fvp);
		if (error)
			goto bad;
		VTOFDESC(fvp)->fd_fd = fd;
		vn_lock(fvp, LK_SHARED | LK_RETRY, p);
		*vpp = fvp;
		return (0);
	}

bad:;
	vn_lock(dvp, LK_SHARED | LK_RETRY, p);
	*vpp = NULL;
	return (error);
}

int
fdesc_open(ap)
	struct vop_open_args /* {
		struct vnode *a_vp;
		int  a_mode;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	int error = 0;

	switch (VTOFDESC(vp)->fd_type) {
	case Fdesc:
		/*
		 * XXX Kludge: set p->p_dupfd to contain the value of the
		 * the file descriptor being sought for duplication. The error 
		 * return ensures that the vnode for this device will be
		 * released by vn_open. Open will detect this special error and
		 * take the actions in dupfdopen.  Other callers of vn_open or
		 * VOP_OPEN will simply report the error.
		 */
		ap->a_p->p_dupfd = VTOFDESC(vp)->fd_fd;	/* XXX */
		error = ENODEV;
		break;

	}

	return (error);
}

static int
fdesc_attr(fd, vap, cred, p)
	int fd;
	struct vattr *vap;
	struct ucred *cred;
	struct proc *p;
{
	struct file *fp;
	struct stat stb;
	int error;

	if (error = fdgetf(p, fd, &fp))
		return (error);
	switch (fp->f_type) {
	case DTYPE_VNODE:
		error = VOP_GETATTR((struct vnode *) fp->f_data, vap, cred, p);
		if (error == 0 && vap->va_type == VDIR) {
			/*
			 * directories can cause loops in the namespace,
			 * so turn off the 'x' bits to avoid trouble.
			 */
			vap->va_mode &= ~((VEXEC)|(VEXEC>>3)|(VEXEC>>6));
		}
		break;

	case DTYPE_SOCKET:
		error = soo_stat((struct socket *)fp->f_data, &stb);
		if (error == 0) {
			vattr_null(vap);
			vap->va_type = VSOCK;
			vap->va_mode = stb.st_mode;
			vap->va_nlink = stb.st_nlink;
			vap->va_uid = stb.st_uid;
			vap->va_gid = stb.st_gid;
			vap->va_fsid = stb.st_dev;
			vap->va_fileid = stb.st_ino;
			vap->va_size = stb.st_size;
			vap->va_blocksize = stb.st_blksize;
			vap->va_atime = stb.st_atimespec;
			vap->va_mtime = stb.st_mtimespec;
			vap->va_ctime = stb.st_ctimespec;
			vap->va_gen = stb.st_gen;
			vap->va_flags = stb.st_flags;
			vap->va_rdev = stb.st_rdev;
			vap->va_bytes = stb.st_blocks * stb.st_blksize;
		}
		break;

	default:
		return (EBADF);
		break;
	}

	return (error);
}

int
fdesc_getattr(ap)
	struct vop_getattr_args /* {
		struct vnode *a_vp;
		struct vattr *a_vap;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;
	unsigned fd;
	int error = 0;

	switch (VTOFDESC(vp)->fd_type) {
	case Froot:
	case Fdevfd:
	case Flink:
		bzero((caddr_t) vap, sizeof(*vap));
		vattr_null(vap);
		vap->va_fileid = VTOFDESC(vp)->fd_ix;

		vap->va_uid = 0;
		vap->va_gid = 0;
		vap->va_fsid = vp->v_mount->mnt_stat.f_fsid.val[0];
		vap->va_blocksize = DEV_BSIZE;
		vap->va_atime.tv_sec = boottime.tv_sec;
		vap->va_atime.tv_nsec = 0;
		vap->va_mtime = vap->va_atime;
		vap->va_ctime = vap->va_mtime;
		vap->va_gen = 0;
		vap->va_flags = 0;
		vap->va_rdev = 0;
		vap->va_bytes = 0;

		switch (VTOFDESC(vp)->fd_type) {
		case Flink:
			vap->va_mode = S_IRUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH;
			vap->va_type = VLNK;
			vap->va_nlink = 1;
			vap->va_size = strlen(VTOFDESC(vp)->fd_link);
			break;

		default:
			vap->va_mode = S_IRUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH;
			vap->va_type = VDIR;
			vap->va_nlink = 2;
			vap->va_size = DEV_BSIZE;
			break;
		}
		break;

	case Fdesc:
		fd = VTOFDESC(vp)->fd_fd;
		error = fdesc_attr(fd, vap, ap->a_cred, ap->a_p);
		break;

	default:
		return (EBADF);
		break;	
	}

	if (error == 0) {
		vp->v_type = vap->va_type;
	}

	return (error);
}

int
fdesc_setattr(ap)
	struct vop_setattr_args /* {
		struct vnode *a_vp;
		struct vattr *a_vap;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	struct file *fp;
	unsigned fd;
	int error;

	/*
	 * Can't mess with the root vnode
	 */
	switch (VTOFDESC(ap->a_vp)->fd_type) {
	case Fdesc:
		break;

	default:
		return (EACCES);
	}

	fd = VTOFDESC(ap->a_vp)->fd_fd;
	if (error = fdgetf(ap->a_p, fd, &fp))
		return (error);

	/*
	 * Can setattr the underlying vnode, but not sockets!
	 */
	switch (fp->f_type) {
	case DTYPE_VNODE:
		error = VOP_SETATTR((struct vnode *) fp->f_data, ap->a_vap, ap->a_cred, ap->a_p);
		break;

	case DTYPE_SOCKET:
		error = 0;
		break;

	default:
		kprintf("fp->f_type = %d\n", fp->f_type);
        error = EBADF;
		break;
	}

	return (error);
}

#define UIO_MX 16

static struct dirtmp {
	u_long d_fileno;
	u_short d_reclen;
	u_short d_namlen;
	char d_name[8];
} rootent[] = {
	{ FD_DEVFD, UIO_MX, 2, "fd" },
	{ FD_STDIN, UIO_MX, 5, "stdin" },
	{ FD_STDOUT, UIO_MX, 6, "stdout" },
	{ FD_STDERR, UIO_MX, 6, "stderr" },
	{ 0 }
};

int
fdesc_readdir(ap)
	struct vop_readdir_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		struct ucred *a_cred;
		int *a_eofflag;
		u_long *a_cookies;
		int a_ncookies;
	} */ *ap;
{
	struct uio *uio = ap->a_uio;
	struct proc *p = uio->uio_procp;
	int i, error;

	/*
	 * We don't allow exporting fdesc mounts, and currently local
	 * requests do not need cookies.
	 */
	if (ap->a_ncookies)
		return (EINVAL);

	switch (VTOFDESC(ap->a_vp)->fd_type) {
	case Fdesc:
		return (ENOTDIR);

	default:
		break;
	}

	if (VTOFDESC(ap->a_vp)->fd_type == Froot) {
		struct dirent d;
		struct dirent *dp = &d;
		struct dirtmp *dt;
		int fd;

		i = uio->uio_offset / UIO_MX;
		error = 0;

		while (uio->uio_resid > 0) {
			dt = &rootent[i];
			if (dt->d_fileno == 0) {
				/**eofflagp = 1;*/
				break;
			}
			i++;
			
			switch (dt->d_fileno) {
			case FD_STDIN:
			case FD_STDOUT:
			case FD_STDERR:
				fd = dt->d_fileno - FD_STDIN;
				if (fd >= p->p_fd->fd_nfiles)
					continue;
				if (*fdfile(p, fd) == NULL &&
						!(*fdflags(p, fd) &
							UF_RESERVED))
					continue;
				break;
			}
			bzero((caddr_t) dp, UIO_MX);
			dp->d_fileno = dt->d_fileno;
			dp->d_namlen = dt->d_namlen;
			dp->d_type = DT_UNKNOWN;
			dp->d_reclen = dt->d_reclen;
			bcopy(dt->d_name, dp->d_name, dp->d_namlen+1);
			error = uiomove((caddr_t) dp, UIO_MX, uio);
			if (error)
				break;
		}
		uio->uio_offset = i * UIO_MX;
		return (error);
	}

	i = uio->uio_offset / UIO_MX;
	error = 0;
	while (uio->uio_resid > 0) {
		if (i >= p->p_fd->fd_nfiles)
			break;

		if (*fdfile(p, i) != NULL && !(*fdflags(p, i) & UF_RESERVED)) {
			struct dirent d;
			struct dirent *dp = &d;

			bzero((caddr_t) dp, UIO_MX);

			dp->d_namlen = sprintf(dp->d_name, "%d", i);
			dp->d_reclen = UIO_MX;
			dp->d_type = DT_UNKNOWN;
			dp->d_fileno = i + FD_STDIN;
			/*
			 * And ship to userland
			 */
			error = uiomove((caddr_t) dp, UIO_MX, uio);
			if (error)
				break;
		}
		i++;
	}

	uio->uio_offset = i * UIO_MX;
	return (error);
}

int
fdesc_readlink(ap)
	struct vop_readlink_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		struct ucred *a_cred;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	int error;

	if (vp->v_type != VLNK)
		return (EPERM);

	if (VTOFDESC(vp)->fd_type == Flink) {
		char *ln = VTOFDESC(vp)->fd_link;
		error = uiomove(ln, strlen(ln), ap->a_uio);
	} else {
		error = EOPNOTSUPP;
	}

	return (error);
}

int
fdesc_read(ap)
	struct vop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{

	return (EOPNOTSUPP);
}

int
fdesc_write(ap)
	struct vop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{
	return (EOPNOTSUPP);
}

int
fdesc_ioctl(ap)
	struct vop_ioctl_args /* {
		struct vnode *a_vp;
		int  a_command;
		caddr_t  a_data;
		int  a_fflag;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	return (EOPNOTSUPP);
}

int
fdesc_select(ap)
	struct vop_select_args /* {
		struct vnode *a_vp;
		int  a_which;
		int  a_fflags;
		struct ucred *a_cred;
		void *a_wql;
		struct proc *a_p;
	} */ *ap;
{
	return (EOPNOTSUPP);
}

int
fdesc_inactive(ap)
	struct vop_inactive_args /* {
		struct vnode *a_vp;
		struct proc *a_p;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;

	/*
	 * Clear out the v_type field to avoid
	 * nasty things happening in vgone().
	 */
	VOP_UNLOCK(vp, 0, ap->a_p);
	vp->v_type = VNON;
	return (0);
}

int
fdesc_reclaim(ap)
	struct vop_reclaim_args /* {
		struct vnode *a_vp;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct fdescnode *fd = VTOFDESC(vp);

	LIST_REMOVE(fd, fd_hash);
	FREE(vp->v_data, M_TEMP);
	vp->v_data = 0;

	return (0);
}

/*
 * Return POSIX pathconf information applicable to special devices.
 */
fdesc_pathconf(ap)
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

/*
 * Print out the contents of a /dev/fd vnode.
 */
/* ARGSUSED */
int
fdesc_print(ap)
	struct vop_print_args /* {
		struct vnode *a_vp;
	} */ *ap;
{

	printf("tag VT_NON, fdesc vnode\n");
	return (0);
}

/*void*/
int
fdesc_vfree(ap)
	struct vop_vfree_args /* {
		struct vnode *a_pvp;
		ino_t a_ino;
		int a_mode;
	} */ *ap;
{

	return (0);
}

/*
 * /dev/fd "should never get here" operation
 */
int
fdesc_badop()
{

	return (ENOTSUP);
	/* NOTREACHED */
}

#define VOPFUNC int (*)(void *)

#define fdesc_create ((int (*) __P((struct  vop_create_args *)))eopnotsupp)
#define fdesc_mknod ((int (*) __P((struct  vop_mknod_args *)))eopnotsupp)
#define fdesc_close ((int (*) __P((struct  vop_close_args *)))nullop)
#define fdesc_access ((int (*) __P((struct  vop_access_args *)))nullop)
#define fdesc_mmap ((int (*) __P((struct  vop_mmap_args *)))eopnotsupp)
#define	fdesc_revoke vop_revoke
#define fdesc_fsync ((int (*) __P((struct  vop_fsync_args *)))nullop)
#define fdesc_seek ((int (*) __P((struct  vop_seek_args *)))nullop)
#define fdesc_remove ((int (*) __P((struct  vop_remove_args *)))eopnotsupp)
#define fdesc_link ((int (*) __P((struct  vop_link_args *)))eopnotsupp)
#define fdesc_rename ((int (*) __P((struct  vop_rename_args *)))eopnotsupp)
#define fdesc_mkdir ((int (*) __P((struct  vop_mkdir_args *)))eopnotsupp)
#define fdesc_rmdir ((int (*) __P((struct  vop_rmdir_args *)))eopnotsupp)
#define fdesc_symlink ((int (*) __P((struct vop_symlink_args *)))eopnotsupp)
#define fdesc_abortop ((int (*) __P((struct  vop_abortop_args *)))nop_abortop)
#define fdesc_lock ((int (*) __P((struct  vop_lock_args *)))vop_nolock)
#define fdesc_unlock ((int (*) __P((struct  vop_unlock_args *)))vop_nounlock)
#define fdesc_bmap ((int (*) __P((struct  vop_bmap_args *)))fdesc_badop)
#define fdesc_strategy ((int (*) __P((struct  vop_strategy_args *)))fdesc_badop)
#define fdesc_islocked \
	((int (*) __P((struct vop_islocked_args *)))vop_noislocked)
#define fdesc_advlock ((int (*) __P((struct vop_advlock_args *)))eopnotsupp)
#define fdesc_blkatoff \
	((int (*) __P((struct  vop_blkatoff_args *)))eopnotsupp)
#define fdesc_valloc ((int(*) __P(( \
		struct vnode *pvp, \
		int mode, \
		struct ucred *cred, \
		struct vnode **vpp))) eopnotsupp)
#define fdesc_truncate \
	((int (*) __P((struct  vop_truncate_args *)))eopnotsupp)
#define fdesc_update ((int (*) __P((struct  vop_update_args *)))eopnotsupp)
#define fdesc_bwrite ((int (*) __P((struct  vop_bwrite_args *)))eopnotsupp)
#define fdesc_blktooff ((int (*) __P((struct  vop_blktooff_args *)))eopnotsupp)
#define fdesc_offtoblk ((int (*) __P((struct  vop_offtoblk_args *)))eopnotsupp)
#define fdesc_cmap ((int (*) __P((struct  vop_cmap_args *)))eopnotsupp)

int (**fdesc_vnodeop_p)(void *);
struct vnodeopv_entry_desc fdesc_vnodeop_entries[] = {
	{ &vop_default_desc, (VOPFUNC)vn_default_error },
	{ &vop_lookup_desc, (VOPFUNC)fdesc_lookup },	/* lookup */
	{ &vop_create_desc, (VOPFUNC)fdesc_create },	/* create */
	{ &vop_mknod_desc, (VOPFUNC)fdesc_mknod },	/* mknod */
	{ &vop_open_desc, (VOPFUNC)fdesc_open },	/* open */
	{ &vop_close_desc, (VOPFUNC)fdesc_close },	/* close */
	{ &vop_access_desc, (VOPFUNC)fdesc_access },	/* access */
	{ &vop_getattr_desc, (VOPFUNC)fdesc_getattr },	/* getattr */
	{ &vop_setattr_desc, (VOPFUNC)fdesc_setattr },	/* setattr */
	{ &vop_read_desc, (VOPFUNC)fdesc_read },	/* read */
	{ &vop_write_desc, (VOPFUNC)fdesc_write },	/* write */
	{ &vop_ioctl_desc, (VOPFUNC)fdesc_ioctl },	/* ioctl */
	{ &vop_select_desc, (VOPFUNC)fdesc_select },	/* select */
	{ &vop_revoke_desc, (VOPFUNC)fdesc_revoke },	/* revoke */
	{ &vop_mmap_desc, (VOPFUNC)fdesc_mmap },	/* mmap */
	{ &vop_fsync_desc, (VOPFUNC)fdesc_fsync },	/* fsync */
	{ &vop_seek_desc, (VOPFUNC)fdesc_seek },	/* seek */
	{ &vop_remove_desc, (VOPFUNC)fdesc_remove },	/* remove */
	{ &vop_link_desc, (VOPFUNC)fdesc_link },	/* link */
	{ &vop_rename_desc, (VOPFUNC)fdesc_rename },	/* rename */
	{ &vop_mkdir_desc, (VOPFUNC)fdesc_mkdir },	/* mkdir */
	{ &vop_rmdir_desc, (VOPFUNC)fdesc_rmdir },	/* rmdir */
	{ &vop_symlink_desc, (VOPFUNC)fdesc_symlink },	/* symlink */
	{ &vop_readdir_desc, (VOPFUNC)fdesc_readdir },	/* readdir */
	{ &vop_readlink_desc, (VOPFUNC)fdesc_readlink },/* readlink */
	{ &vop_abortop_desc, (VOPFUNC)fdesc_abortop },	/* abortop */
	{ &vop_inactive_desc, (VOPFUNC)fdesc_inactive },/* inactive */
	{ &vop_reclaim_desc, (VOPFUNC)fdesc_reclaim },	/* reclaim */
	{ &vop_lock_desc, (VOPFUNC)fdesc_lock },	/* lock */
	{ &vop_unlock_desc, (VOPFUNC)fdesc_unlock },	/* unlock */
	{ &vop_bmap_desc, (VOPFUNC)fdesc_bmap },	/* bmap */
	{ &vop_strategy_desc, (VOPFUNC)fdesc_strategy },	/* strategy */
	{ &vop_print_desc, (VOPFUNC)fdesc_print },	/* print */
	{ &vop_islocked_desc, (VOPFUNC)fdesc_islocked },	/* islocked */
	{ &vop_pathconf_desc, (VOPFUNC)fdesc_pathconf },	/* pathconf */
	{ &vop_advlock_desc, (VOPFUNC)fdesc_advlock },	/* advlock */
	{ &vop_blkatoff_desc, (VOPFUNC)fdesc_blkatoff },	/* blkatoff */
	{ &vop_valloc_desc, (VOPFUNC)fdesc_valloc },	/* valloc */
	{ &vop_vfree_desc, (VOPFUNC)fdesc_vfree },	/* vfree */
	{ &vop_truncate_desc, (VOPFUNC)fdesc_truncate },	/* truncate */
	{ &vop_update_desc, (VOPFUNC)fdesc_update },	/* update */
	{ &vop_bwrite_desc, (VOPFUNC)fdesc_bwrite },	/* bwrite */
	{ &vop_pagein_desc, (VOPFUNC)err_pagein },	/* pagein */
	{ &vop_pageout_desc, (VOPFUNC)err_pageout },	/* pageout */
        { &vop_copyfile_desc, (VOPFUNC)err_copyfile },	/* Copyfile */
	{ &vop_blktooff_desc, (VOPFUNC)fdesc_blktooff },	/* blktooff */
	{ &vop_blktooff_desc, (VOPFUNC)fdesc_offtoblk },	/* offtoblk */
	{ &vop_cmap_desc, (VOPFUNC)fdesc_cmap },	/* cmap */
	{ (struct vnodeop_desc*)NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc fdesc_vnodeop_opv_desc =
	{ &fdesc_vnodeop_p, fdesc_vnodeop_entries };
