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
/* Copyright (c) 1995, 1997 Apple Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1989, 1991, 1993
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
 *	@(#)kern_descrip.c	8.8 (Berkeley) 2/14/95
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/malloc.h>
#include <sys/syslog.h>
#include <sys/unistd.h>
#include <sys/resourcevar.h>

#include <sys/mount.h>

/*
 * Descriptor management.
 */
struct filelist filehead;	/* head of list of open files */
int nfiles;			/* actual number of open files */

static int frele_internal(struct file *);

/*
 * System calls on descriptors.
 */
/* ARGSUSED */
int
getdtablesize(p, uap, retval)
	struct proc *p;
	void *uap;
	register_t *retval;
{
	*retval = min((int)p->p_rlimit[RLIMIT_NOFILE].rlim_cur, maxfiles);
	return (0);
}

/* ARGSUSED */
int
ogetdtablesize(p, uap, retval)
	struct proc *p;
	void *uap;
	register_t *retval;
{
	*retval = min((int)p->p_rlimit[RLIMIT_NOFILE].rlim_cur, NOFILE);
	return (0);
}

static __inline__
void _fdrelse(fdp, fd)
	register struct filedesc *fdp;
	register int fd;
{
	if (fd < fdp->fd_freefile)
		fdp->fd_freefile = fd;
#if DIAGNOSTIC
	if (fd > fdp->fd_lastfile)
		panic("fdrelse: fd_lastfile inconsistent");
#endif
	fdp->fd_ofiles[fd] = NULL;
	fdp->fd_ofileflags[fd] = 0;
	while ((fd = fdp->fd_lastfile) > 0 &&
			fdp->fd_ofiles[fd] == NULL &&
			!(fdp->fd_ofileflags[fd] & UF_RESERVED))
		fdp->fd_lastfile--;
}

/*
 * Duplicate a file descriptor.
 */
struct dup_args {
	u_int	fd;
};
/* ARGSUSED */
int
dup(p, uap, retval)
	struct proc *p;
	struct dup_args *uap;
	register_t *retval;
{
	register struct filedesc *fdp = p->p_fd;
	register int old = uap->fd;
	int new, error;

	if ((u_int)old >= fdp->fd_nfiles ||
			fdp->fd_ofiles[old] == NULL ||
			(fdp->fd_ofileflags[old] & UF_RESERVED))
		return (EBADF);
	if (error = fdalloc(p, 0, &new))
		return (error);
	return (finishdup(fdp, old, new, retval));
}

/*
 * Duplicate a file descriptor to a particular value.
 */
struct dup2_args {
	u_int	from;
	u_int	to;
};
/* ARGSUSED */
int
dup2(p, uap, retval)
	struct proc *p;
	struct dup2_args *uap;
	register_t *retval;
{
	register struct filedesc *fdp = p->p_fd;
	register int old = uap->from, new = uap->to;
	int i, error;

	if ((u_int)old >= fdp->fd_nfiles ||
		fdp->fd_ofiles[old] == NULL ||
		(fdp->fd_ofileflags[old] & UF_RESERVED) ||
	    (u_int)new >= p->p_rlimit[RLIMIT_NOFILE].rlim_cur ||
	    (u_int)new >= maxfiles)
		return (EBADF);
	if (old == new) {
		*retval = new;
		return (0);
	}
	if ((u_int)new >= fdp->fd_nfiles) {
		if (error = fdalloc(p, new, &i))
			return (error);
		if (new != i) {
			_fdrelse(fdp, i);
			goto closeit;
		}
	} else {
		struct file **fpp;
		char flags;
closeit:
		if ((flags = fdp->fd_ofileflags[new]) & UF_RESERVED)
			return (EBADF);
		fdp->fd_ofileflags[new] = (flags & ~UF_MAPPED) | UF_RESERVED;
		/*
		 * dup2() must succeed even if the close has an error.
		 */
		if (*(fpp = &fdp->fd_ofiles[new])) {
			struct file *fp = *fpp;

			*fpp = NULL;
			(void) closef(fp, p);
		}
	}
	return (finishdup(fdp, old, new, retval));
}

/*
 * The file control system call.
 */
struct fcntl_args {
	int	fd;
	int	cmd;
	int	arg;
};
/* ARGSUSED */
int
fcntl(p, uap, retval)
	struct proc *p;
	register struct fcntl_args *uap;
	register_t *retval;
{
	int fd = uap->fd;
	register struct filedesc *fdp = p->p_fd;
	register struct file *fp;
	register char *pop;
	struct vnode *vp, *devvp;
	int i, tmp, error, error2, flg = F_POSIX;
	struct flock fl;
	fstore_t alloc_struct;    /* structure for allocate command */
	u_int32_t alloc_flags = 0;
	off_t offset;       	  /* used for F_SETSIZE */
	int newmin;
	struct radvisory ra_struct;
	fbootstraptransfer_t fbt_struct; /* for F_READBOOTSTRAP and F_WRITEBOOTSTRAP */
	struct log2phys l2p_struct;    /* structure for allocate command */
	daddr_t	lbn, bn;
	int devBlockSize = 0;

	if ((u_int)fd >= fdp->fd_nfiles ||
			(fp = fdp->fd_ofiles[fd]) == NULL ||
			(fdp->fd_ofileflags[fd] & UF_RESERVED))
		return (EBADF);
	pop = &fdp->fd_ofileflags[fd];
	switch (uap->cmd) {

	case F_DUPFD:
		newmin = (long)uap->arg;
		if ((u_int)newmin >= p->p_rlimit[RLIMIT_NOFILE].rlim_cur ||
		    (u_int)newmin >= maxfiles)
			return (EINVAL);
		if (error = fdalloc(p, newmin, &i))
			return (error);
		return (finishdup(fdp, fd, i, retval));

	case F_GETFD:
		*retval = (*pop & UF_EXCLOSE)? 1 : 0;
		return (0);

	case F_SETFD:
		*pop = (*pop &~ UF_EXCLOSE) |
			((long)(uap->arg) & 1)? UF_EXCLOSE : 0;
		return (0);

	case F_GETFL:
		*retval = OFLAGS(fp->f_flag);
		return (0);

	case F_SETFL:
		fp->f_flag &= ~FCNTLFLAGS;
		fp->f_flag |= FFLAGS((long)uap->arg) & FCNTLFLAGS;
		tmp = fp->f_flag & FNONBLOCK;
		error = fo_ioctl(fp, FIONBIO, (caddr_t)&tmp, p);
		if (error)
			return (error);
		tmp = fp->f_flag & FASYNC;
		error = fo_ioctl(fp, FIOASYNC, (caddr_t)&tmp, p);
		if (!error)
			return (0);
		fp->f_flag &= ~FNONBLOCK;
		tmp = 0;
		(void)fo_ioctl(fp, FIONBIO, (caddr_t)&tmp, p);
		return (error);

	case F_GETOWN:
		if (fp->f_type == DTYPE_SOCKET) {
			*retval = ((struct socket *)fp->f_data)->so_pgid;
			return (0);
		}
		error = fo_ioctl(fp, (int)TIOCGPGRP, (caddr_t)retval, p);
		*retval = -*retval;
		return (error);

	case F_SETOWN:
		if (fp->f_type == DTYPE_SOCKET) {
			((struct socket *)fp->f_data)->so_pgid =
			    (long)uap->arg;
			return (0);
		}
		if ((long)uap->arg <= 0) {
			uap->arg = (int)(-(long)(uap->arg));
		} else {
			struct proc *p1 = pfind((long)uap->arg);
			if (p1 == 0)
				return (ESRCH);
			uap->arg = (int)p1->p_pgrp->pg_id;
		}
		return (fo_ioctl(fp, (int)TIOCSPGRP, (caddr_t)&uap->arg, p));

	case F_SETLKW:
		flg |= F_WAIT;
		/* Fall into F_SETLK */

	case F_SETLK:
		if (fp->f_type != DTYPE_VNODE)
			return (EBADF);
		vp = (struct vnode *)fp->f_data;
		/* Copy in the lock structure */
		error = copyin((caddr_t)uap->arg, (caddr_t)&fl,
		    sizeof (fl));
		if (error)
			return (error);
		if (fl.l_whence == SEEK_CUR)
			fl.l_start += fp->f_offset;
		switch (fl.l_type) {

		case F_RDLCK:
			if ((fp->f_flag & FREAD) == 0)
				return (EBADF);
			p->p_flag |= P_ADVLOCK;
			return (VOP_ADVLOCK(vp, (caddr_t)p, F_SETLK, &fl, flg));

		case F_WRLCK:
			if ((fp->f_flag & FWRITE) == 0)
				return (EBADF);
			p->p_flag |= P_ADVLOCK;
			return (VOP_ADVLOCK(vp, (caddr_t)p, F_SETLK, &fl, flg));

		case F_UNLCK:
			return (VOP_ADVLOCK(vp, (caddr_t)p, F_UNLCK, &fl,
				F_POSIX));

		default:
			return (EINVAL);
		}

	case F_GETLK:
		if (fp->f_type != DTYPE_VNODE)
			return (EBADF);
		vp = (struct vnode *)fp->f_data;
		/* Copy in the lock structure */
		error = copyin((caddr_t)uap->arg, (caddr_t)&fl,
		    sizeof (fl));
		if (error)
			return (error);
		if (fl.l_whence == SEEK_CUR)
			fl.l_start += fp->f_offset;
		if (error = VOP_ADVLOCK(vp, (caddr_t)p, F_GETLK, &fl, F_POSIX))
			return (error);
		return (copyout((caddr_t)&fl, (caddr_t)uap->arg,
		    sizeof (fl)));

	case F_PREALLOCATE:
		if (fp->f_type != DTYPE_VNODE)
			return (EBADF);

		/* make sure that we have write permission */
		if ((fp->f_flag & FWRITE) == 0)
			return (EBADF);

		error = copyin((caddr_t)uap->arg, (caddr_t)&alloc_struct,
		    sizeof (alloc_struct));
		if (error)
			return (error);

		/* now set the space allocated to 0 */
		alloc_struct.fst_bytesalloc = 0;
		
		/*
		 * Do some simple parameter checking
		 */

		/* set up the flags */

		alloc_flags |= PREALLOCATE;
		
		if (alloc_struct.fst_flags & F_ALLOCATECONTIG)
			alloc_flags |= ALLOCATECONTIG;

		if (alloc_struct.fst_flags & F_ALLOCATEALL)
			alloc_flags |= ALLOCATEALL;

		/*
		 * Do any position mode specific stuff.  The only
		 * position mode  supported now is PEOFPOSMODE
		 */

		switch (alloc_struct.fst_posmode) {
	
		case F_PEOFPOSMODE:
			if (alloc_struct.fst_offset != 0)
				return (EINVAL);

			alloc_flags |= ALLOCATEFROMPEOF;
			break;

		case F_VOLPOSMODE:
			if (alloc_struct.fst_offset <= 0)
				return (EINVAL);

			alloc_flags |= ALLOCATEFROMVOL;
			break;

		default:
			return(EINVAL);
		}

		vp = (struct vnode *)fp->f_data;

		/* lock the vnode and call allocate to get the space */
		error = vn_lock(vp, LK_EXCLUSIVE|LK_RETRY, p);
		if (error)
			return (error);
		error = VOP_ALLOCATE(vp,alloc_struct.fst_length,alloc_flags,
				     &alloc_struct.fst_bytesalloc, alloc_struct.fst_offset,
				     fp->f_cred, p);
		VOP_UNLOCK(vp, 0, p);

		if (error2 = copyout((caddr_t)&alloc_struct,
						(caddr_t)uap->arg,
						sizeof (alloc_struct))) {
			if (error)
				return(error);
			else
				return(error2);
		}
		return(error);
		
	case F_SETSIZE:
		if (fp->f_type != DTYPE_VNODE)
			return (EBADF);
		
		error = copyin((caddr_t)uap->arg, (caddr_t)&offset,
					sizeof (off_t));
		if (error)
			return (error);

		/*
		 * Make sure that we are root.  Growing a file
		 * without zero filling the data is a security hole 
		 * root would have access anyway so we'll allow it
		 */

		if (!is_suser())
			return (EACCES);

		vp = (struct vnode *)fp->f_data;

		/* lock the vnode and call allocate to get the space */
		error = vn_lock(vp, LK_EXCLUSIVE|LK_RETRY, p);
		if (error)
			return (error);
		error = VOP_TRUNCATE(vp,offset,IO_NOZEROFILL,fp->f_cred,p);
		VOP_UNLOCK(vp,0,p);
		return(error);

	case F_RDAHEAD:
		if (fp->f_type != DTYPE_VNODE)
			return (EBADF);
		vp = (struct vnode *)fp->f_data;

		simple_lock(&vp->v_interlock);
		if (uap->arg)
			vp->v_flag &= ~VRAOFF;
		else
			vp->v_flag |= VRAOFF;
		simple_unlock(&vp->v_interlock);
		return (0);

	case F_NOCACHE:
		if (fp->f_type != DTYPE_VNODE)
			return (EBADF);
		vp = (struct vnode *)fp->f_data;

		simple_lock(&vp->v_interlock);
		if (uap->arg)
			vp->v_flag |= VNOCACHE_DATA;
		else
			vp->v_flag &= ~VNOCACHE_DATA;
		simple_unlock(&vp->v_interlock);
		return (0);

	case F_RDADVISE:
		if (fp->f_type != DTYPE_VNODE)
			return (EBADF);
		vp = (struct vnode *)fp->f_data;

		if (error = copyin((caddr_t)uap->arg,
					(caddr_t)&ra_struct, sizeof (ra_struct)))
			return(error);
		return (VOP_IOCTL(vp, 1, (caddr_t)&ra_struct, 0, fp->f_cred, p));

	case F_READBOOTSTRAP:
	case F_WRITEBOOTSTRAP:
		if (fp->f_type != DTYPE_VNODE)
			return (EBADF);

		error = copyin((caddr_t)uap->arg, (caddr_t)&fbt_struct,
				sizeof (fbt_struct));
		if (error)
			return (error);

		if (uap->cmd == F_WRITEBOOTSTRAP) {
		  /*
		   * Make sure that we are root.  Updating the
		   * bootstrap on a disk could be a security hole
		   */
			if (!is_suser())
				return (EACCES);
		}

		vp = (struct vnode *)fp->f_data;
		if (vp->v_tag != VT_HFS)	/* XXX */
			error = EINVAL;
		else {
			/* lock the vnode and call VOP_IOCTL to handle the I/O */
			error = vn_lock(vp, LK_EXCLUSIVE|LK_RETRY, p);
			if (error)
				return (error);
			error = VOP_IOCTL(vp, (uap->cmd == F_WRITEBOOTSTRAP) ? 3 : 2,
					(caddr_t)&fbt_struct, 0, fp->f_cred, p);
			VOP_UNLOCK(vp,0,p);
		}
		return(error);

	case F_LOG2PHYS:
		if (fp->f_type != DTYPE_VNODE)
			return (EBADF);
		vp = (struct vnode *)fp->f_data;
		error = vn_lock(vp, LK_EXCLUSIVE|LK_RETRY, p);
		if (error)
			return (error);
		if (VOP_OFFTOBLK(vp, fp->f_offset, &lbn))
			panic("fcntl LOG2PHYS OFFTOBLK");
		if (VOP_BLKTOOFF(vp, lbn, &offset))
			panic("fcntl LOG2PHYS BLKTOOFF1");
		error = VOP_BMAP(vp, lbn, &devvp, &bn, 0);
		VOP_DEVBLOCKSIZE(devvp, &devBlockSize);
		VOP_UNLOCK(vp, 0, p);
		if (!error) {
			l2p_struct.l2p_flags = 0;	/* for now */
			l2p_struct.l2p_contigbytes = 0;	/* for now */
			l2p_struct.l2p_devoffset = bn * devBlockSize;
			l2p_struct.l2p_devoffset += fp->f_offset - offset;
			error = copyout((caddr_t)&l2p_struct,
					(caddr_t)uap->arg,
					sizeof (l2p_struct));
		}
		return (error);

	default:
		return (EINVAL);
	}
	/* NOTREACHED */
}

/*
 * Common code for dup, dup2, and fcntl(F_DUPFD).
 */
int
finishdup(fdp, old, new, retval)
	register struct filedesc *fdp;
	register int old, new;
	register_t *retval;
{
	register struct file *fp;

	if ((fp = fdp->fd_ofiles[old]) == NULL ||
			(fdp->fd_ofileflags[old] & UF_RESERVED)) {
		_fdrelse(fdp, new);
		return (EBADF);
	}
	fdp->fd_ofiles[new] = fp;
	fdp->fd_ofileflags[new] = fdp->fd_ofileflags[old] &~ UF_EXCLOSE;
	(void)fref(fp);
	if (new > fdp->fd_lastfile)
		fdp->fd_lastfile = new;
	*retval = new;
	return (0);
}

/*
 * Close a file descriptor.
 */
struct close_args {
	int	fd;
};
/* ARGSUSED */
int
close(p, uap, retval)
	struct proc *p;
	struct close_args *uap;
	register_t *retval;
{
	int fd = uap->fd;
	register struct filedesc *fdp = p->p_fd;
	register struct file *fp;

	if ((u_int)fd >= fdp->fd_nfiles ||
			(fp = fdp->fd_ofiles[fd]) == NULL ||
			(fdp->fd_ofileflags[fd] & UF_RESERVED))
		return (EBADF);
	_fdrelse(fdp, fd);
	return (closef(fp, p));
}

/*
 * Return status information about a file descriptor.
 */
struct fstat_args {
	int	fd;
	struct	stat *sb;
};
/* ARGSUSED */
int
fstat(p, uap, retval)
	struct proc *p;
	register struct fstat_args *uap;
	register_t *retval;
{
	int fd = uap->fd;
	register struct filedesc *fdp = p->p_fd;
	register struct file *fp;
	struct stat ub;
	int error;

	if ((u_int)fd >= fdp->fd_nfiles ||
			(fp = fdp->fd_ofiles[fd]) == NULL ||
			(fdp->fd_ofileflags[fd] & UF_RESERVED))
		return (EBADF);
	switch (fp->f_type) {

	case DTYPE_VNODE:
		error = vn_stat((struct vnode *)fp->f_data, &ub, p);
		break;

	case DTYPE_SOCKET:
		error = soo_stat((struct socket *)fp->f_data, &ub);
		break;

	case DTYPE_PSXSHM:
		error = pshm_stat((void *)fp->f_data, &ub);
		break;
	default:
		panic("fstat");
		/*NOTREACHED*/
	}
	if (error == 0)
		error = copyout((caddr_t)&ub, (caddr_t)uap->sb,
		    sizeof (ub));
	return (error);
}

#if COMPAT_43
/*
 * Return status information about a file descriptor.
 */
struct ofstat_args {
	int	fd;
	struct	ostat *sb;
};
/* ARGSUSED */
ofstat(p, uap, retval)
	struct proc *p;
	register struct ofstat_args *uap;
	register_t *retval;
{
	int fd = uap->fd;
	register struct filedesc *fdp = p->p_fd;
	register struct file *fp;
	struct stat ub;
	struct ostat oub;
	int error;

	if ((u_int)fd >= fdp->fd_nfiles ||
			(fp = fdp->fd_ofiles[fd]) == NULL ||
			(fdp->fd_ofileflags[fd] & UF_RESERVED))
		return (EBADF);
	switch (fp->f_type) {

	case DTYPE_VNODE:
		error = vn_stat((struct vnode *)fp->f_data, &ub, p);
		break;

	case DTYPE_SOCKET:
		error = soo_stat((struct socket *)fp->f_data, &ub);
		break;

	default:
		panic("ofstat");
		/*NOTREACHED*/
	}
	cvtstat(&ub, &oub);
	if (error == 0)
		error = copyout((caddr_t)&oub, (caddr_t)uap->sb,
		    sizeof (oub));
	return (error);
}
#endif /* COMPAT_43 */

/*
 * Return pathconf information about a file descriptor.
 */
struct fpathconf_args {
	int	fd;
	int	name;
};
/* ARGSUSED */
fpathconf(p, uap, retval)
	struct proc *p;
	register struct fpathconf_args *uap;
	register_t *retval;
{
	int fd = uap->fd;
	struct filedesc *fdp = p->p_fd;
	struct file *fp;
	struct vnode *vp;

	if ((u_int)fd >= fdp->fd_nfiles ||
			(fp = fdp->fd_ofiles[fd]) == NULL ||
			(fdp->fd_ofileflags[fd] & UF_RESERVED))
		return (EBADF);
	switch (fp->f_type) {

	case DTYPE_SOCKET:
		if (uap->name != _PC_PIPE_BUF)
			return (EINVAL);
		*retval = PIPE_BUF;
		return (0);

	case DTYPE_VNODE:
		vp = (struct vnode *)fp->f_data;
		return (VOP_PATHCONF(vp, uap->name, retval));

	default:
		panic("fpathconf");
	}
	/*NOTREACHED*/
}

/*
 * Allocate a file descriptor for the process.
 */
int fdexpand;

int
fdalloc(p, want, result)
	struct proc *p;
	int want;
	int *result;
{
	register struct filedesc *fdp = p->p_fd;
	register int i;
	int lim, last, nfiles, oldnfiles;
	struct file **newofiles, **ofiles;
	char *newofileflags, *ofileflags;

	/*
	 * Search for a free descriptor starting at the higher
	 * of want or fd_freefile.  If that fails, consider
	 * expanding the ofile array.
	 */
	lim = min((int)p->p_rlimit[RLIMIT_NOFILE].rlim_cur, maxfiles);
	for (;;) {
		last = min(fdp->fd_nfiles, lim);
		if ((i = want) < fdp->fd_freefile)
			i = fdp->fd_freefile;
		ofiles = &fdp->fd_ofiles[i];
		ofileflags = &fdp->fd_ofileflags[i];
		for (; i < last; i++) {
			if (*ofiles == NULL && !(*ofileflags & UF_RESERVED)) {
				*ofileflags = UF_RESERVED;
				if (i > fdp->fd_lastfile)
					fdp->fd_lastfile = i;
				if (want <= fdp->fd_freefile)
					fdp->fd_freefile = i;
				*result = i;
				return (0);
			}
			ofiles++; ofileflags++;
		}

		/*
		 * No space in current array.  Expand?
		 */
		if (fdp->fd_nfiles >= lim)
			return (EMFILE);
		if (fdp->fd_nfiles < NDEXTENT)
			nfiles = NDEXTENT;
		else
			nfiles = 2 * fdp->fd_nfiles;
		/* Enforce lim */
		if (nfiles > lim)
			nfiles = lim;
		MALLOC_ZONE(newofiles, struct file **,
				nfiles * OFILESIZE, M_OFILETABL, M_WAITOK);
		if (fdp->fd_nfiles >= nfiles) {
			FREE_ZONE(newofiles, nfiles * OFILESIZE, M_OFILETABL);
			continue;
		}
		newofileflags = (char *) &newofiles[nfiles];
		/*
		 * Copy the existing ofile and ofileflags arrays
		 * and zero the new portion of each array.
		 */
		oldnfiles = fdp->fd_nfiles;
		(void) memcpy(newofiles, fdp->fd_ofiles,
				oldnfiles * sizeof *fdp->fd_ofiles);
		(void) memset(&newofiles[oldnfiles], 0,
				(nfiles - oldnfiles) * sizeof *fdp->fd_ofiles);

		(void) memcpy(newofileflags, fdp->fd_ofileflags,
				oldnfiles * sizeof *fdp->fd_ofileflags);
		(void) memset(&newofileflags[oldnfiles], 0,
				(nfiles - oldnfiles) *
						sizeof *fdp->fd_ofileflags);
		ofiles = fdp->fd_ofiles;
		fdp->fd_ofiles = newofiles;
		fdp->fd_ofileflags = newofileflags;
		fdp->fd_nfiles = nfiles;
		FREE_ZONE(ofiles, oldnfiles * OFILESIZE, M_OFILETABL);
		fdexpand++;
	}
}

/*
 * Check to see whether n user file descriptors
 * are available to the process p.
 */
int
fdavail(p, n)
	struct proc *p;
	register int n;
{
	register struct filedesc *fdp = p->p_fd;
	register struct file **fpp;
	register char *flags;
	register int i, lim;

	lim = min((int)p->p_rlimit[RLIMIT_NOFILE].rlim_cur, maxfiles);
	if ((i = lim - fdp->fd_nfiles) > 0 && (n -= i) <= 0)
		return (1);
	fpp = &fdp->fd_ofiles[fdp->fd_freefile];
	flags = &fdp->fd_ofileflags[fdp->fd_freefile];
	for (i = fdp->fd_nfiles - fdp->fd_freefile; --i >= 0; fpp++, flags++)
		if (*fpp == NULL && !(*flags & UF_RESERVED) && --n <= 0)
			return (1);
	return (0);
}

void
fdrelse(p, fd)
	struct proc *p;
	int fd;
{
	_fdrelse(p->p_fd, fd);
}

int
fdgetf(p, fd, resultfp)
	register struct proc *p;
	register int fd;
	struct file **resultfp;
{
	register struct filedesc *fdp = p->p_fd;
	struct file *fp;

	if ((u_int)fd >= fdp->fd_nfiles ||
			(fp = fdp->fd_ofiles[fd]) == NULL ||
			(fdp->fd_ofileflags[fd] & UF_RESERVED))
		return (EBADF);

	if (resultfp)
		*resultfp = fp;
	return (0);
}

/*
 * Create a new open file structure and allocate
 * a file decriptor for the process that refers to it.
 */
int
falloc(p, resultfp, resultfd)
	register struct proc *p;
	struct file **resultfp;
	int *resultfd;
{
	register struct file *fp, *fq;
	int error, i;

	if (error = fdalloc(p, 0, &i))
		return (error);
	if (nfiles >= maxfiles) {
		tablefull("file");
		return (ENFILE);
	}
	/*
	 * Allocate a new file descriptor.
	 * If the process has file descriptor zero open, add to the list
	 * of open files at that point, otherwise put it at the front of
	 * the list of open files.
	 */
	nfiles++;
	MALLOC_ZONE(fp, struct file *, sizeof(struct file), M_FILE, M_WAITOK);
	bzero(fp, sizeof(struct file));
	if (fq = p->p_fd->fd_ofiles[0]) {
		LIST_INSERT_AFTER(fq, fp, f_list);
	} else {
		LIST_INSERT_HEAD(&filehead, fp, f_list);
	}
	p->p_fd->fd_ofiles[i] = fp;
	fp->f_count = 1;
	fp->f_cred = p->p_ucred;
	crhold(fp->f_cred);
	if (resultfp)
		*resultfp = fp;
	if (resultfd)
		*resultfd = i;
	return (0);
}

/*
 * Free a file structure.
 */
void
ffree(fp)
	register struct file *fp;
{
	register struct file *fq;
	struct ucred *cred;

	LIST_REMOVE(fp, f_list);
	cred = fp->f_cred;
	if (cred != NOCRED) {
		fp->f_cred = NOCRED;
		crfree(cred);
	}

	nfiles--;
	memset(fp, 0xff, sizeof *fp);
	fp->f_count = (short)0xffff;

	FREE_ZONE(fp, sizeof *fp, M_FILE);
}

void
fdexec(p)
	struct proc *p;
{
	register struct filedesc *fdp = p->p_fd;
	register int i = fdp->fd_lastfile;
	register struct file **fpp = &fdp->fd_ofiles[i];
	register char *flags = &fdp->fd_ofileflags[i];

	while (i >= 0) {
		if ((*flags & (UF_RESERVED|UF_EXCLOSE)) == UF_EXCLOSE) {
			register struct file *fp = *fpp;

			*fpp = NULL; *flags = 0;
			if (i == fdp->fd_lastfile && i > 0)
				fdp->fd_lastfile--;
			closef(fp, p);
		}
		else
			*flags &= ~UF_MAPPED;

		i--; fpp--; flags--;
	}
}

/*
 * Copy a filedesc structure.
 */
struct filedesc *
fdcopy(p)
	struct proc *p;
{
	register struct filedesc *newfdp, *fdp = p->p_fd;
	register int i;

	MALLOC_ZONE(newfdp, struct filedesc *,
			sizeof *newfdp, M_FILEDESC, M_WAITOK);
	(void) memcpy(newfdp, fdp, sizeof *newfdp);
	VREF(newfdp->fd_cdir);
	if (newfdp->fd_rdir)
		VREF(newfdp->fd_rdir);
	newfdp->fd_refcnt = 1;

	/*
	 * If the number of open files fits in the internal arrays
	 * of the open file structure, use them, otherwise allocate
	 * additional memory for the number of descriptors currently
	 * in use.
	 */
	if (newfdp->fd_lastfile < NDFILE)
		i = NDFILE;
	else {
		/*
		 * Compute the smallest multiple of NDEXTENT needed
		 * for the file descriptors currently in use,
		 * allowing the table to shrink.
		 */
		i = newfdp->fd_nfiles;
		while (i > 2 * NDEXTENT && i > newfdp->fd_lastfile * 2)
			i /= 2;
	}
	MALLOC_ZONE(newfdp->fd_ofiles, struct file **,
				i * OFILESIZE, M_OFILETABL, M_WAITOK);
	newfdp->fd_ofileflags = (char *) &newfdp->fd_ofiles[i];
	newfdp->fd_nfiles = i;
	if (fdp->fd_nfiles > 0) {
		register struct file **fpp;
		register char *flags;

		(void) memcpy(newfdp->fd_ofiles, fdp->fd_ofiles,
					i * sizeof *fdp->fd_ofiles);
		(void) memcpy(newfdp->fd_ofileflags, fdp->fd_ofileflags,
					i * sizeof *fdp->fd_ofileflags);

		fpp = newfdp->fd_ofiles;
		flags = newfdp->fd_ofileflags;
		for (i = newfdp->fd_lastfile; i-- >= 0; fpp++, flags++)
			if (*fpp != NULL && !(*flags & UF_RESERVED)) {
				(void)fref(*fpp);
			} else {
				*fpp = NULL;
				*flags = 0;
			}
	} else
		(void) memset(newfdp->fd_ofiles, 0, i * OFILESIZE);

	return (newfdp);
}

/*
 * Release a filedesc structure.
 */
void
fdfree(p)
	struct proc *p;
{
	struct filedesc *fdp;
	struct file **fpp;
	int i;
	struct vnode *tvp;

	if ((fdp = p->p_fd) == NULL)
		return;
	if (--fdp->fd_refcnt > 0)
		return;
	p->p_fd = NULL;
	if (fdp->fd_nfiles > 0) {
		fpp = fdp->fd_ofiles;
		for (i = fdp->fd_lastfile; i-- >= 0; fpp++)
			if (*fpp)
				(void) closef(*fpp, p);
		FREE_ZONE(fdp->fd_ofiles,
				fdp->fd_nfiles * OFILESIZE, M_OFILETABL);
	}
	tvp = fdp->fd_cdir;
	fdp->fd_cdir = NULL;
	vrele(tvp);
	if (fdp->fd_rdir) {
		tvp = fdp->fd_rdir;
		fdp->fd_rdir = NULL;
		vrele(tvp);
	}
	FREE_ZONE(fdp, sizeof *fdp, M_FILEDESC);
}

static int
closef_finish(fp, p)
	register struct file *fp;
	register struct proc *p;
{
	struct vnode *vp;
	struct flock lf;
	int error;

	if ((fp->f_flag & FHASLOCK) && fp->f_type == DTYPE_VNODE) {
		lf.l_whence = SEEK_SET;
		lf.l_start = 0;
		lf.l_len = 0;
		lf.l_type = F_UNLCK;
		vp = (struct vnode *)fp->f_data;
		(void) VOP_ADVLOCK(vp, (caddr_t)fp, F_UNLCK, &lf, F_FLOCK);
	}
	if (fp->f_ops)
		error = fo_close(fp, p);
	else
		error = 0;
	ffree(fp);
	return (error);
}

/*
 * Internal form of close.
 * Decrement reference count on file structure.
 * Note: p may be NULL when closing a file
 * that was being passed in a message.
 */
int
closef(fp, p)
	register struct file *fp;
	register struct proc *p;
{
	struct vnode *vp;
	struct flock lf;
	int error;

	if (fp == NULL)
		return (0);
	/*
	 * POSIX record locking dictates that any close releases ALL
	 * locks owned by this process.  This is handled by setting
	 * a flag in the unlock to free ONLY locks obeying POSIX
	 * semantics, and not to free BSD-style file locks.
	 * If the descriptor was in a message, POSIX-style locks
	 * aren't passed with the descriptor.
	 */
	if (p && (p->p_flag & P_ADVLOCK) && fp->f_type == DTYPE_VNODE) {
		lf.l_whence = SEEK_SET;
		lf.l_start = 0;
		lf.l_len = 0;
		lf.l_type = F_UNLCK;
		vp = (struct vnode *)fp->f_data;
		(void) VOP_ADVLOCK(vp, (caddr_t)p, F_UNLCK, &lf, F_POSIX);
	}
	if (frele_internal(fp) > 0)
		return (0);
	return(closef_finish(fp, p));
}

/*
 * Apply an advisory lock on a file descriptor.
 *
 * Just attempt to get a record lock of the requested type on
 * the entire file (l_whence = SEEK_SET, l_start = 0, l_len = 0).
 */
struct flock_args {
	int	fd;
	int	how;
};
/* ARGSUSED */
int
flock(p, uap, retval)
	struct proc *p;
	register struct flock_args *uap;
	register_t *retval;
{
	int fd = uap->fd;
	int how = uap->how;
	register struct filedesc *fdp = p->p_fd;
	register struct file *fp;
	struct vnode *vp;
	struct flock lf;

	if ((u_int)fd >= fdp->fd_nfiles ||
			(fp = fdp->fd_ofiles[fd]) == NULL ||
			(fdp->fd_ofileflags[fd] & UF_RESERVED))
		return (EBADF);
	if (fp->f_type != DTYPE_VNODE)
		return (EOPNOTSUPP);
	vp = (struct vnode *)fp->f_data;
	lf.l_whence = SEEK_SET;
	lf.l_start = 0;
	lf.l_len = 0;
	if (how & LOCK_UN) {
		lf.l_type = F_UNLCK;
		fp->f_flag &= ~FHASLOCK;
		return (VOP_ADVLOCK(vp, (caddr_t)fp, F_UNLCK, &lf, F_FLOCK));
	}
	if (how & LOCK_EX)
		lf.l_type = F_WRLCK;
	else if (how & LOCK_SH)
		lf.l_type = F_RDLCK;
	else
		return (EBADF);
	fp->f_flag |= FHASLOCK;
	if (how & LOCK_NB)
		return (VOP_ADVLOCK(vp, (caddr_t)fp, F_SETLK, &lf, F_FLOCK));
	return (VOP_ADVLOCK(vp, (caddr_t)fp, F_SETLK, &lf, F_FLOCK|F_WAIT));
}

/*
 * File Descriptor pseudo-device driver (/dev/fd/).
 *
 * Opening minor device N dup()s the file (if any) connected to file
 * descriptor N belonging to the calling process.  Note that this driver
 * consists of only the ``open()'' routine, because all subsequent
 * references to this file will be direct to the other driver.
 */
/* ARGSUSED */
int
fdopen(dev, mode, type, p)
	dev_t dev;
	int mode, type;
	struct proc *p;
{

	/*
	 * XXX Kludge: set curproc->p_dupfd to contain the value of the
	 * the file descriptor being sought for duplication. The error 
	 * return ensures that the vnode for this device will be released
	 * by vn_open. Open will detect this special error and take the
	 * actions in dupfdopen below. Other callers of vn_open or VOP_OPEN
	 * will simply report the error.
	 */
	p->p_dupfd = minor(dev);
	return (ENODEV);
}

/*
 * Duplicate the specified descriptor to a free descriptor.
 */
int
dupfdopen(fdp, indx, dfd, mode, error)
	register struct filedesc *fdp;
	register int indx, dfd;
	int mode;
	int error;
{
	register struct file *wfp;
	struct file *fp;

	/*
	 * If the to-be-dup'd fd number is greater than the allowed number
	 * of file descriptors, or the fd to be dup'd has already been
	 * closed, reject.  Note, check for new == old is necessary as
	 * falloc could allocate an already closed to-be-dup'd descriptor
	 * as the new descriptor.
	 */
	fp = fdp->fd_ofiles[indx];
	if ((u_int)dfd >= fdp->fd_nfiles ||
			(wfp = fdp->fd_ofiles[dfd]) == NULL || wfp == fp ||
			(fdp->fd_ofileflags[dfd] & UF_RESERVED))
		return (EBADF);

	/*
	 * There are two cases of interest here.
	 *
	 * For ENODEV simply dup (dfd) to file descriptor
	 * (indx) and return.
	 *
	 * For ENXIO steal away the file structure from (dfd) and
	 * store it in (indx).  (dfd) is effectively closed by
	 * this operation.
	 *
	 * Any other error code is just returned.
	 */
	switch (error) {
	case ENODEV:
		/*
		 * Check that the mode the file is being opened for is a
		 * subset of the mode of the existing descriptor.
		 */
		if (((mode & (FREAD|FWRITE)) | wfp->f_flag) != wfp->f_flag)
			return (EACCES);
		(void)fref(wfp);
		if (indx > fdp->fd_lastfile)
			fdp->fd_lastfile = indx;;
		fdp->fd_ofiles[indx] = wfp;
		fdp->fd_ofileflags[indx] = fdp->fd_ofileflags[dfd];
		return (0);

	case ENXIO:
		/*
		 * Steal away the file pointer from dfd, and stuff it into indx.
		 */
		if (indx > fdp->fd_lastfile)
			fdp->fd_lastfile = indx;;
		fdp->fd_ofiles[indx] = fdp->fd_ofiles[dfd];
		fdp->fd_ofileflags[indx] = fdp->fd_ofileflags[dfd];
		_fdrelse(fdp, dfd);
		return (0);

	default:
		return (error);
	}
	/* NOTREACHED */
}

/* Reference manipulation routines for the file structure */

int
fref(struct file *fp)
{
	if (fp->f_count == (short)0xffff)
		return (-1);
	if (++fp->f_count <= 0)
		panic("fref: f_count");
	return ((int)fp->f_count);
}

static int 
frele_internal(struct file *fp)
{
	if (fp->f_count == (short)0xffff)
		panic("frele: stale");
	if (--fp->f_count < 0)
		panic("frele: count < 0");
	return ((int)fp->f_count);
}


int
frele(struct file *fp)
{
	int count;
	funnel_t * fnl;
	extern int disable_funnel;

	fnl = thread_funnel_get();
	/*
	 * If the funnels are merged then atleast a funnel should be held
	 * else frele should come in with kernel funnel only
	 */
	if (!disable_funnel && (fnl != kernel_flock)) {
		panic("frele: kernel funnel not held");

	} else if  (fnl == THR_FUNNEL_NULL) {
		panic("frele: no funnel held");
	}

	if ((count = frele_internal(fp)) == 0) {
		/* some one closed the fd while we were blocked */
		(void)closef_finish(fp, current_proc());
	}
	return(count);
}

int
fcount(struct file *fp)
{
	if (fp->f_count == (short)0xffff)
		panic("fcount: stale");
	return ((int)fp->f_count);
}

