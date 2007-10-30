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
#include <sys/vnode_internal.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/file_internal.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/syslog.h>
#include <sys/unistd.h>
#include <sys/resourcevar.h>
#include <sys/aio_kern.h>
#include <sys/ev.h>
#include <kern/lock.h>

#include <bsm/audit_kernel.h>

#include <sys/mount_internal.h>
#include <sys/kdebug.h>
#include <sys/sysproto.h>
#include <sys/pipe.h>
#include <kern/kern_types.h>
#include <kern/kalloc.h>
#include <libkern/OSAtomic.h>

struct psemnode;
struct pshmnode;

int fdopen(dev_t dev, int mode, int type, struct proc *p);
int ogetdtablesize(struct proc *p, void *uap, register_t *retval);
int finishdup(struct proc * p, struct filedesc *fdp, int old, int new, register_t *retval);

int closef(struct fileglob *fg, struct proc *p);
int falloc_locked(struct proc *p, struct fileproc **resultfp, int *resultfd, int locked);
void fddrop(struct proc *p, int fd);
int fdgetf_noref(struct proc *p, int fd, struct fileproc **resultfp);
void fg_drop(struct fileproc * fp);
void fg_free(struct fileglob *fg);
void fg_ref(struct fileproc * fp);
int fp_getfpshm(struct proc *p, int fd, struct fileproc **resultfp, struct pshmnode  **resultpshm);

static int closef_finish(struct fileproc *fp, struct fileglob *fg, struct proc *p);

extern void file_lock_init(void);
extern int is_suser(void);
extern int kqueue_stat(struct fileproc *fp, struct stat *st, struct proc *p);
extern int soo_stat(struct socket *so, struct stat *ub);
extern int vn_path_package_check(vnode_t vp, char *path, int pathlen, int *component);

extern kauth_scope_t	kauth_scope_fileop;

#define f_flag f_fglob->fg_flag
#define f_type f_fglob->fg_type
#define f_msgcount f_fglob->fg_msgcount
#define f_cred f_fglob->fg_cred
#define f_ops f_fglob->fg_ops
#define f_offset f_fglob->fg_offset
#define f_data f_fglob->fg_data
/*
 * Descriptor management.
 */
struct filelist filehead;	/* head of list of open files */
struct fmsglist fmsghead;	/* head of list of open files */
struct fmsglist fmsg_ithead;	/* head of list of open files */
int nfiles;			/* actual number of open files */


lck_grp_attr_t * file_lck_grp_attr;
lck_grp_t * file_lck_grp;
lck_attr_t * file_lck_attr;

lck_mtx_t * uipc_lock;
lck_mtx_t * file_iterate_lcok;
lck_mtx_t * file_flist_lock;


void
file_lock_init(void)
{

	/* allocate file lock group attribute and group */
	file_lck_grp_attr= lck_grp_attr_alloc_init();
	lck_grp_attr_setstat(file_lck_grp_attr);

	file_lck_grp = lck_grp_alloc_init("file",  file_lck_grp_attr);

	/* Allocate file lock attribute */
	file_lck_attr = lck_attr_alloc_init();
	//lck_attr_setdebug(file_lck_attr);

	uipc_lock = lck_mtx_alloc_init(file_lck_grp, file_lck_attr);
	file_iterate_lcok = lck_mtx_alloc_init(file_lck_grp, file_lck_attr);
	file_flist_lock = lck_mtx_alloc_init(file_lck_grp, file_lck_attr);

	

}


void
proc_fdlock(struct proc *p)
{
	lck_mtx_lock(&p->p_fdmlock);
}

void
proc_fdunlock(struct proc *p)
{
	lck_mtx_unlock(&p->p_fdmlock);
}

/*
 * System calls on descriptors.
 */

int
getdtablesize(struct proc *p, __unused struct getdtablesize_args *uap, register_t *retval)
{
	proc_fdlock(p);
	*retval = min((int)p->p_rlimit[RLIMIT_NOFILE].rlim_cur, maxfiles);
	proc_fdunlock(p);

	return (0);
}

int
ogetdtablesize(struct proc *p, __unused void *uap, register_t *retval)
{
	proc_fdlock(p);
	*retval = min((int)p->p_rlimit[RLIMIT_NOFILE].rlim_cur, NOFILE);
	proc_fdunlock(p);

	return (0);
}

static __inline__ void
_fdrelse(struct filedesc *fdp, int fd)
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
	struct fileproc *fp;

	proc_fdlock(p);
	if ( (error = fp_lookup(p, old, &fp, 1)) ) {
		proc_fdunlock(p);
		return(error);
	}
	if ( (error = fdalloc(p, 0, &new)) ) {
		fp_drop(p, old, fp, 1);
		proc_fdunlock(p);
		return (error);
	}
	error = finishdup(p, fdp, old, new, retval);
	fp_drop(p, old, fp, 1);
	proc_fdunlock(p);

	return (error);
}

/*
 * Duplicate a file descriptor to a particular value.
 */
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
	struct fileproc *fp;

	proc_fdlock(p);

	if ( (error = fp_lookup(p, old, &fp, 1)) ) {
		proc_fdunlock(p);
		return(error);
	}
	if (new < 0 ||
		new >= p->p_rlimit[RLIMIT_NOFILE].rlim_cur ||
	    new >= maxfiles) {
		fp_drop(p, old, fp, 1);
		proc_fdunlock(p);
		return (EBADF);
	}
	if (old == new) {
		fp_drop(p, old, fp, 1);
		*retval = new;
		proc_fdunlock(p);
		return (0);
	}
	if (new < 0 || new >= fdp->fd_nfiles) {
		if ( (error = fdalloc(p, new, &i)) ) {
			fp_drop(p, old, fp, 1);
			proc_fdunlock(p);
			return (error);
		}
		if (new != i) {
			_fdrelse(fdp, i);
			goto closeit;
		}
	} else {
		struct fileproc **fpp;
		char flags;
closeit:
		flags = fdp->fd_ofileflags[new];
		if ((flags & (UF_RESERVED | UF_CLOSING)) == UF_RESERVED) {
			fp_drop(p, old, fp, 1);
			proc_fdunlock(p);
			return (EBADF);
		}

		/*
		 * dup2() must succeed even if the close has an error.
		 */
		if (*(fpp = &fdp->fd_ofiles[new])) {
			struct fileproc *nfp = *fpp;

			close_internal(p, new, nfp, (CLOSEINT_LOCKED | CLOSEINT_WAITONCLOSE | CLOSEINT_NOFDRELSE | CLOSEINT_NOFDNOREF));
			*fpp = NULL;
		}
	}
	error = finishdup(p, fdp, old, new, retval);
	fp_drop(p, old, fp, 1);
	proc_fdunlock(p);

	return(error);
}

/*
 * The file control system call.
 */
int
fcntl(p, uap, retval)
	struct proc *p;
	struct fcntl_args *uap;
	register_t *retval;
{
	int fd = uap->fd;
	struct filedesc *fdp = p->p_fd;
	struct fileproc *fp;
	char *pop;
	struct vnode *vp;
	int i, tmp, error, error2, flg = F_POSIX;
	struct flock fl;
	struct vfs_context context;
	off_t offset;
	int newmin;
	daddr64_t lbn, bn;
	int devBlockSize = 0;
	unsigned int fflag;
	user_addr_t argp;

	AUDIT_ARG(fd, uap->fd);
	AUDIT_ARG(cmd, uap->cmd);

	proc_fdlock(p);
	if ( (error = fp_lookup(p, fd, &fp, 1)) ) {
		proc_fdunlock(p);
		return(error);
	}
	context.vc_proc = p;
	context.vc_ucred = fp->f_cred;
	if (proc_is64bit(p)) {
		argp = uap->arg;
	}
	else {
		/* since the arg parameter is defined as a long but may be either
		 * a long or a pointer we must take care to handle sign extension 
		 * issues.  Our sys call munger will sign extend a long when we are
		 * called from a 32-bit process.  Since we can never have an address
		 * greater than 32-bits from a 32-bit process we lop off the top 
		 * 32-bits to avoid getting the wrong address
		 */
		argp = CAST_USER_ADDR_T(uap->arg);
	}

	pop = &fdp->fd_ofileflags[fd];

	switch (uap->cmd) {

	case F_DUPFD:
		newmin = CAST_DOWN(int, uap->arg);
		if ((u_int)newmin >= p->p_rlimit[RLIMIT_NOFILE].rlim_cur ||
		    newmin >= maxfiles) {
			error = EINVAL;
			goto out;
		}
		if ( (error = fdalloc(p, newmin, &i)) )
			goto out;
		error = finishdup(p, fdp, fd, i, retval);
		goto out;

	case F_GETFD:
		*retval = (*pop & UF_EXCLOSE)? 1 : 0;
		error = 0;
		goto out;

	case F_SETFD:
		*pop = (*pop &~ UF_EXCLOSE) |
			(uap->arg & 1)? UF_EXCLOSE : 0;
		error = 0;
		goto out;

	case F_GETFL:
		*retval = OFLAGS(fp->f_flag);
		error = 0;
		goto out;

	case F_SETFL:
		fp->f_flag &= ~FCNTLFLAGS;
		tmp = CAST_DOWN(int, uap->arg);
		fp->f_flag |= FFLAGS(tmp) & FCNTLFLAGS;
		tmp = fp->f_flag & FNONBLOCK;
		error = fo_ioctl(fp, FIONBIO, (caddr_t)&tmp, p);
		if (error)
			goto out;
		tmp = fp->f_flag & FASYNC;
		error = fo_ioctl(fp, FIOASYNC, (caddr_t)&tmp, p);
		if (!error)
			goto out;
		fp->f_flag &= ~FNONBLOCK;
		tmp = 0;
		(void)fo_ioctl(fp, FIONBIO, (caddr_t)&tmp, p);
		goto out;

	case F_GETOWN:
		if (fp->f_type == DTYPE_SOCKET) {
			*retval = ((struct socket *)fp->f_data)->so_pgid;
			error = 0;
			goto out;
		}
		error = fo_ioctl(fp, (int)TIOCGPGRP, (caddr_t)retval, p);
		*retval = -*retval;
		goto out;

	case F_SETOWN:
		tmp = CAST_DOWN(pid_t, uap->arg);
		if (fp->f_type == DTYPE_SOCKET) {
			((struct socket *)fp->f_data)->so_pgid = tmp;
			error =0;
			goto out;
		}
		if (fp->f_type == DTYPE_PIPE) {
			error =  fo_ioctl(fp, (int)TIOCSPGRP, (caddr_t)&tmp, p);
			goto out;
		}

		if (tmp <= 0) {
			tmp = -tmp;
		} else {
			struct proc *p1 = pfind(tmp);
			if (p1 == 0) {
				error = ESRCH;
				goto out;
			}
			tmp = (int)p1->p_pgrp->pg_id;
		}
		error =  fo_ioctl(fp, (int)TIOCSPGRP, (caddr_t)&tmp, p);
		goto out;

	case F_SETLKW:
		flg |= F_WAIT;
		/* Fall into F_SETLK */

	case F_SETLK:
		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;

		fflag = fp->f_flag;
		offset = fp->f_offset;
		proc_fdunlock(p);

		/* Copy in the lock structure */
		error = copyin(argp, (caddr_t)&fl, sizeof (fl));
		if (error) {
			goto outdrop;
		}
		if ( (error = vnode_getwithref(vp)) ) {
			goto outdrop;
		}
		if (fl.l_whence == SEEK_CUR)
			fl.l_start += offset;

		switch (fl.l_type) {

		case F_RDLCK:
			if ((fflag & FREAD) == 0) {
				(void)vnode_put(vp);
				error = EBADF;
				goto outdrop;
			}
			OSBitOrAtomic(P_LADVLOCK, &p->p_ladvflag);
			error = VNOP_ADVLOCK(vp, (caddr_t)p, F_SETLK, &fl, flg, &context);
			(void)vnode_put(vp);
			goto outdrop;

		case F_WRLCK:
			if ((fflag & FWRITE) == 0) {
				(void)vnode_put(vp);
				error = EBADF;
				goto outdrop;
			}
			OSBitOrAtomic(P_LADVLOCK, &p->p_ladvflag);
			error = VNOP_ADVLOCK(vp, (caddr_t)p, F_SETLK, &fl, flg, &context);
			(void)vnode_put(vp);
			goto outdrop;

		case F_UNLCK:
			error = VNOP_ADVLOCK(vp, (caddr_t)p, F_UNLCK, &fl,
				F_POSIX, &context);
			(void)vnode_put(vp);
			goto outdrop;

		default:
			(void)vnode_put(vp);
			error = EINVAL;
			goto outdrop;
		}

	case F_GETLK:
		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;

		offset = fp->f_offset;
		proc_fdunlock(p);

		/* Copy in the lock structure */
		error = copyin(argp, (caddr_t)&fl, sizeof (fl));
		if (error)
			goto outdrop;

		if ( (error = vnode_getwithref(vp)) == 0 ) {
			if (fl.l_whence == SEEK_CUR)
			        fl.l_start += offset;

			error = VNOP_ADVLOCK(vp, (caddr_t)p, F_GETLK, &fl, F_POSIX, &context);

			(void)vnode_put(vp);

			if (error == 0)
				error = copyout((caddr_t)&fl, argp, sizeof (fl));
		}
		goto outdrop;

	case F_PREALLOCATE: {
		fstore_t alloc_struct;    /* structure for allocate command */
		u_int32_t alloc_flags = 0;

		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}

		vp = (struct vnode *)fp->f_data;
		proc_fdunlock(p);

		/* make sure that we have write permission */
		if ((fp->f_flag & FWRITE) == 0) {
			error = EBADF;
			goto outdrop;
		}

		error = copyin(argp, (caddr_t)&alloc_struct, sizeof (alloc_struct));
		if (error)
			goto outdrop;

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
			if (alloc_struct.fst_offset != 0) {
				error = EINVAL;
				goto outdrop;
			}

			alloc_flags |= ALLOCATEFROMPEOF;
			break;

		case F_VOLPOSMODE:
			if (alloc_struct.fst_offset <= 0) {
				error = EINVAL;
				goto outdrop;
			}

			alloc_flags |= ALLOCATEFROMVOL;
			break;

		default: {
			error = EINVAL;
			goto outdrop;
			}
		}
		if ( (error = vnode_getwithref(vp)) == 0 ) {
		        /*
			 * call allocate to get the space
			 */
		        error = VNOP_ALLOCATE(vp,alloc_struct.fst_length,alloc_flags,
					      &alloc_struct.fst_bytesalloc, alloc_struct.fst_offset,
					      &context);
			(void)vnode_put(vp);

			error2 = copyout((caddr_t)&alloc_struct, argp, sizeof (alloc_struct));

			if (error == 0)
				error = error2;
		}
		goto outdrop;
		
		}
	case F_SETSIZE:
		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		proc_fdunlock(p);

		error = copyin(argp, (caddr_t)&offset, sizeof (off_t));
		if (error)
			goto outdrop;

		/*
		 * Make sure that we are root.  Growing a file
		 * without zero filling the data is a security hole 
		 * root would have access anyway so we'll allow it
		 */

		if (!is_suser()) {
			error = EACCES;
			goto outdrop;
		}
		vp = (struct vnode *)fp->f_data;

		if ( (error = vnode_getwithref(vp)) == 0 ) {
		        /*
			 * set the file size
			 */
		        error = vnode_setsize(vp, offset, IO_NOZEROFILL, &context);

			(void)vnode_put(vp);
		}
		goto outdrop;

	case F_RDAHEAD:
		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;
		proc_fdunlock(p);

		if ( (error = vnode_getwithref(vp)) == 0) {
		        if (uap->arg)
			        vnode_clearnoreadahead(vp);
			else
			        vnode_setnoreadahead(vp);

			(void)vnode_put(vp);
		}
		goto outdrop;

	case F_NOCACHE:
		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;
		proc_fdunlock(p);

		if ( (error = vnode_getwithref(vp)) == 0 ) {
		        if (uap->arg)
			        vnode_setnocache(vp);
			else
			        vnode_clearnocache(vp);

			(void)vnode_put(vp);
		}
		goto outdrop;

	case F_GLOBAL_NOCACHE:
		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;
		proc_fdunlock(p);

		if ( (error = vnode_getwithref(vp)) == 0 ) {

		        *retval = vnode_isnocache(vp);

		        if (uap->arg)
			        vnode_setnocache(vp);
			else
			        vnode_clearnocache(vp);

			(void)vnode_put(vp);
		}
		goto outdrop;

	case F_RDADVISE: {
		struct radvisory ra_struct;

		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;
		proc_fdunlock(p);

		if ( (error = copyin(argp, (caddr_t)&ra_struct, sizeof (ra_struct))) )
			goto outdrop;
		if ( (error = vnode_getwithref(vp)) == 0 ) {
		        error = VNOP_IOCTL(vp, F_RDADVISE, (caddr_t)&ra_struct, 0, &context);

			(void)vnode_put(vp);
		}
		goto outdrop;
		}

	case F_READBOOTSTRAP:
	case F_WRITEBOOTSTRAP: {
		fbootstraptransfer_t fbt_struct;
		user_fbootstraptransfer_t user_fbt_struct;
		int	sizeof_struct;
		caddr_t boot_structp;

		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;
		proc_fdunlock(p);

		if (IS_64BIT_PROCESS(p)) {
			sizeof_struct = sizeof(user_fbt_struct);
			boot_structp = (caddr_t) &user_fbt_struct;
		}
		else {
			sizeof_struct = sizeof(fbt_struct);
			boot_structp = (caddr_t) &fbt_struct;
		}
		error = copyin(argp, boot_structp, sizeof_struct);
		if (error)
			goto outdrop;
		if ( (error = vnode_getwithref(vp)) ) {
			goto outdrop;
		}
		if (uap->cmd == F_WRITEBOOTSTRAP) {
		        /*
			 * Make sure that we are root.  Updating the
			 * bootstrap on a disk could be a security hole
			 */
			if (!is_suser()) {
				(void)vnode_put(vp);
				error = EACCES;
				goto outdrop;
			}
		}
		if (strcmp(vnode_mount(vp)->mnt_vfsstat.f_fstypename, "hfs") != 0) {
			error = EINVAL;
		} else {
			/*
			 * call vnop_ioctl to handle the I/O
			 */
			error = VNOP_IOCTL(vp, uap->cmd, boot_structp, 0, &context);
		}
		(void)vnode_put(vp);
		goto outdrop;
	}
	case F_LOG2PHYS: {
		struct log2phys l2p_struct;    /* structure for allocate command */

		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;
		proc_fdunlock(p);
		if ( (error = vnode_getwithref(vp)) ) {
			goto outdrop;
		}
		error = VNOP_OFFTOBLK(vp, fp->f_offset, &lbn);
		if (error) {
			(void)vnode_put(vp);
			goto outdrop;
		}
		error = VNOP_BLKTOOFF(vp, lbn, &offset);
		if (error) {
			(void)vnode_put(vp);
			goto outdrop;
		}
		devBlockSize = vfs_devblocksize(vnode_mount(vp));

		error = VNOP_BLOCKMAP(vp, offset, devBlockSize, &bn, NULL, NULL, 0, &context);

		(void)vnode_put(vp);

		if (!error) {
			l2p_struct.l2p_flags = 0;	/* for now */
			l2p_struct.l2p_contigbytes = 0;	/* for now */
			l2p_struct.l2p_devoffset = bn * devBlockSize;
			l2p_struct.l2p_devoffset += fp->f_offset - offset;
			error = copyout((caddr_t)&l2p_struct, argp, sizeof (l2p_struct));
		}
		goto outdrop;
		}
	case F_GETPATH: {
		char *pathbufp;
		int pathlen;

		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;
		proc_fdunlock(p);

		pathlen = MAXPATHLEN;
		MALLOC(pathbufp, char *, pathlen, M_TEMP, M_WAITOK);
		if (pathbufp == NULL) {
			error = ENOMEM;
			goto outdrop;
		}
		if ( (error = vnode_getwithref(vp)) == 0 ) {
		        error = vn_getpath(vp, pathbufp, &pathlen);
		        (void)vnode_put(vp);

			if (error == 0)
			        error = copyout((caddr_t)pathbufp, argp, pathlen);
		}
		FREE(pathbufp, M_TEMP);
		goto outdrop;
	}

	case F_PATHPKG_CHECK: {
		char *pathbufp;
		size_t pathlen;

		if (fp->f_type != DTYPE_VNODE) {
		        error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;
		proc_fdunlock(p);

		pathlen = MAXPATHLEN;
		pathbufp = kalloc(MAXPATHLEN);

		if ( (error = copyinstr(argp, pathbufp, MAXPATHLEN, &pathlen)) == 0 ) {
		        if ( (error = vnode_getwithref(vp)) == 0 ) {
			        error = vn_path_package_check(vp, pathbufp, pathlen, retval);

				(void)vnode_put(vp);
			}
		}
		kfree(pathbufp, MAXPATHLEN);
		goto outdrop;
	}

	case F_CHKCLEAN:   // used by regression tests to see if all dirty pages got cleaned by fsync()
	case F_FULLFSYNC:  // fsync + flush the journal + DKIOCSYNCHRONIZECACHE
	case F_FREEZE_FS:  // freeze all other fs operations for the fs of this fd
	case F_THAW_FS: {  // thaw all frozen fs operations for the fs of this fd
		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;
		proc_fdunlock(p);

		if ( (error = vnode_getwithref(vp)) == 0 ) {
		        error = VNOP_IOCTL(vp, uap->cmd, (caddr_t)NULL, 0, &context);

			(void)vnode_put(vp);
		}
		break;
	}
	    
	default:
		if (uap->cmd < FCNTL_FS_SPECIFIC_BASE) {
			error = EINVAL;
			goto out;
		}

		// if it's a fs-specific fcntl() then just pass it through

		if (fp->f_type != DTYPE_VNODE) {
			error = EBADF;
			goto out;
		}
		vp = (struct vnode *)fp->f_data;
		proc_fdunlock(p);

		if ( (error = vnode_getwithref(vp)) == 0 ) {
			error = VNOP_IOCTL(vp, uap->cmd, CAST_DOWN(caddr_t, argp), 0, &context);

			(void)vnode_put(vp);
		}
		break;
	
	}

outdrop:
	AUDIT_ARG(vnpath_withref, vp, ARG_VNODE1);
	fp_drop(p, fd, fp, 0);
	return(error);
out:
	fp_drop(p, fd, fp, 1);
	proc_fdunlock(p);
	return(error);
}

/*
 * Common code for dup, dup2, and fcntl(F_DUPFD).
 */
int
finishdup(struct proc * p, struct filedesc *fdp, int old, int new, register_t *retval)
{
	struct fileproc *nfp;
	struct fileproc *ofp;

	if ((ofp = fdp->fd_ofiles[old]) == NULL ||
			(fdp->fd_ofileflags[old] & UF_RESERVED)) {
		_fdrelse(fdp, new);
		return (EBADF);
	}
	fg_ref(ofp);
	proc_fdunlock(p);

	MALLOC_ZONE(nfp, struct fileproc *, sizeof(struct fileproc), M_FILEPROC, M_WAITOK);
	bzero(nfp, sizeof(struct fileproc));

	proc_fdlock(p);
	nfp->f_flags = ofp->f_flags;
	nfp->f_fglob = ofp->f_fglob;
	nfp->f_iocount = 0;

	fdp->fd_ofiles[new] = nfp;
	fdp->fd_ofileflags[new] = fdp->fd_ofileflags[old] &~ UF_EXCLOSE;
	if (new > fdp->fd_lastfile)
		fdp->fd_lastfile = new;
	*retval = new;
	return (0);
}


int
close(struct proc *p, struct close_args *uap, __unused register_t *retval)
{
	struct fileproc *fp;
	int fd = uap->fd;
	int error =0;

	AUDIT_SYSCLOSE(p, fd);

	proc_fdlock(p);

	if ( (error = fp_lookup(p,fd,&fp, 1)) ) {
		proc_fdunlock(p);
		return(error);
	}

	error = close_internal(p, fd, fp, CLOSEINT_LOCKED | CLOSEINT_WAITONCLOSE);

	proc_fdunlock(p);

	return(error);
}


/*
 * Close a file descriptor.
 */
int
close_internal(struct proc *p, int fd, struct fileproc *fp, int flags)
{
	struct filedesc *fdp = p->p_fd;
	int error =0;
	int locked = flags & CLOSEINT_LOCKED;
	int waitonclose = flags & CLOSEINT_WAITONCLOSE;
	int norelse = flags & CLOSEINT_NOFDRELSE;
	int nofdref = flags & CLOSEINT_NOFDNOREF;
	int slpstate = PRIBIO;

	if (!locked)
		proc_fdlock(p);

	/* Keep people from using the filedesc while we are closing it */
	fdp->fd_ofileflags[fd] |= UF_RESERVED;

	fdp->fd_ofileflags[fd] |= UF_CLOSING;


	if ((waitonclose && ((fp->f_flags & FP_CLOSING) == FP_CLOSING))) {
			if (nofdref == 0)
				fp_drop(p, fd, fp, 1);
			fp->f_flags |= FP_WAITCLOSE;
			if (!locked)
				slpstate |= PDROP;
			msleep(&fp->f_flags, &p->p_fdmlock, slpstate, "close wait",0) ;	
			return(EBADF);
	}

	fp->f_flags |= FP_CLOSING;
	if (nofdref)
		fp->f_iocount++;

	if ( (fp->f_flags & FP_AIOISSUED) || kauth_authorize_fileop_has_listeners() ) {

	        proc_fdunlock(p);

		if ( (fp->f_type == DTYPE_VNODE) && kauth_authorize_fileop_has_listeners() ) {
		        /*
			 * call out to allow 3rd party notification of close. 
			 * Ignore result of kauth_authorize_fileop call.
			 */
		        if (vnode_getwithref((vnode_t)fp->f_data) == 0) {
		        	u_int	fileop_flags = 0;
		        	if ((fp->f_flags & FP_WRITTEN) != 0)
		        		fileop_flags |= KAUTH_FILEOP_CLOSE_MODIFIED;
			        kauth_authorize_fileop(fp->f_fglob->fg_cred, KAUTH_FILEOP_CLOSE, 
						       (uintptr_t)fp->f_data, (uintptr_t)fileop_flags);
				vnode_put((vnode_t)fp->f_data);
			}
		}
		if (fp->f_flags & FP_AIOISSUED)
		        /*
			 * cancel all async IO requests that can be cancelled.
			 */
		        _aio_close( p, fd );

		proc_fdlock(p);
	}

	if (fd < fdp->fd_knlistsize)
		knote_fdclose(p, fd);

	if (fp->f_flags & FP_WAITEVENT) 
		(void)waitevent_close(p, fp);

	if ((fp->f_flags & FP_INCHRREAD) == 0)
		fileproc_drain(p, fp);
	if (norelse == 0)
		_fdrelse(fdp, fd);
	error = closef_locked(fp, fp->f_fglob, p);
	if ((fp->f_flags & FP_WAITCLOSE) == FP_WAITCLOSE)
		wakeup(&fp->f_flags);
	fp->f_flags &= ~(FP_WAITCLOSE | FP_CLOSING);

	if (!locked)
		proc_fdunlock(p);

	FREE_ZONE(fp, sizeof *fp, M_FILEPROC);	
	return(error);
}

/*
 * Return status information about a file descriptor.
 *
 * XXX switch on node type is bogus; need a stat in struct fileops instead.
 */
static int
fstat1(struct proc *p, int fd, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size)
{
	struct fileproc *fp;
	struct stat sb;
	struct user_stat user_sb;
	int error, my_size;
	int funnel_state;
	file_type_t type;
	caddr_t data;
	kauth_filesec_t fsec;
	ssize_t xsecurity_bufsize;
	int entrycount;
	struct vfs_context context;


	AUDIT_ARG(fd, fd);

	if ((error = fp_lookup(p, fd, &fp, 0)) != 0)
		return(error);
	type = fp->f_type;
	data = fp->f_data;
	fsec = KAUTH_FILESEC_NONE;

	switch (type) {

	case DTYPE_VNODE:
		context.vc_proc = current_proc();
		context.vc_ucred = kauth_cred_get();
		if ((error = vnode_getwithref((vnode_t)data)) == 0) {
			/*
			 * If the caller has the file open, and is not requesting extended security,
			 * we are going to let them get the basic stat information.
			 */
			if (xsecurity == USER_ADDR_NULL) {
				error = vn_stat_noauth((vnode_t)data, &sb, NULL, &context);
			} else {
				error = vn_stat((vnode_t)data, &sb, &fsec, &context);
			}

			AUDIT_ARG(vnpath, (struct vnode *)data, ARG_VNODE1);
			(void)vnode_put((vnode_t)data);
		}
		break;

	case DTYPE_SOCKET:
		error = soo_stat((struct socket *)data, &sb);
		break;

	case DTYPE_PIPE:
		error = pipe_stat((void *)data, &sb);
		break;

	case DTYPE_PSXSHM:
		error = pshm_stat((void *)data, &sb);
		break;

	case DTYPE_KQUEUE:
	        funnel_state = thread_funnel_set(kernel_flock, TRUE);
		error = kqueue_stat(fp, &sb, p);
		thread_funnel_set(kernel_flock, funnel_state);
		break;

	default:
		error = EBADF;
		goto out;
	}
	/* Zap spare fields */
	sb.st_lspare = 0;
	sb.st_qspare[0] = 0LL;
	sb.st_qspare[1] = 0LL;
	if (error == 0) {
		caddr_t sbp;
		if (IS_64BIT_PROCESS(current_proc())) {
			munge_stat(&sb, &user_sb); 
			my_size = sizeof(user_sb);
			sbp = (caddr_t)&user_sb;
		}
		else {
			my_size = sizeof(sb);
			sbp = (caddr_t)&sb;
		}
		error = copyout(sbp, ub, my_size);
	}

	/* caller wants extended security information? */
	if (xsecurity != USER_ADDR_NULL) {

		/* did we get any? */
		 if (fsec == KAUTH_FILESEC_NONE) {
			if (susize(xsecurity_size, 0) != 0) {
				error = EFAULT;
				goto out;
			}
		} else {
			/* find the user buffer size */
			xsecurity_bufsize = fusize(xsecurity_size);

			/* copy out the actual data size */
			if (susize(xsecurity_size, KAUTH_FILESEC_COPYSIZE(fsec)) != 0) {
				error = EFAULT;
				goto out;
			}

			/* if the caller supplied enough room, copy out to it */
			if (xsecurity_bufsize >= KAUTH_FILESEC_COPYSIZE(fsec))
				error = copyout(fsec, xsecurity, KAUTH_FILESEC_COPYSIZE(fsec));
		}
	}
out:
	fp_drop(p, fd, fp, 0);
	if (fsec != NULL)
		kauth_filesec_free(fsec);
	return (error);
}

int
fstat_extended(struct proc *p, struct fstat_extended_args *uap, __unused register_t *retval)
{
	return(fstat1(p, uap->fd, uap->ub, uap->xsecurity, uap->xsecurity_size));
}
 
int
fstat(struct proc *p, register struct fstat_args *uap, __unused register_t *retval)
{
	return(fstat1(p, uap->fd, uap->ub, 0, 0));
}

/*
 * Return pathconf information about a file descriptor.
 */
int
fpathconf(p, uap, retval)
	struct proc *p;
	register struct fpathconf_args *uap;
	register_t *retval;
{
	int fd = uap->fd;
	struct fileproc *fp;
	struct vnode *vp;
	struct vfs_context context;
	int error = 0;
	file_type_t type;
	caddr_t data;


	AUDIT_ARG(fd, uap->fd);
	if ( (error = fp_lookup(p, fd, &fp, 0)) )
		return(error);
	type = fp->f_type;
	data = fp->f_data;

	switch (type) {

	case DTYPE_SOCKET:
	        if (uap->name != _PC_PIPE_BUF) {
		        error = EINVAL;
			goto out;
		}
		*retval = PIPE_BUF;
		error = 0;
		goto out;

	case DTYPE_PIPE:
	        *retval = PIPE_BUF;
		error = 0;
		goto out;

	case DTYPE_VNODE:
		vp = (struct vnode *)data;

		if ( (error = vnode_getwithref(vp)) == 0) {
		        AUDIT_ARG(vnpath, vp, ARG_VNODE1);

			context.vc_proc = p;
			context.vc_ucred = kauth_cred_get();

			error = vn_pathconf(vp, uap->name, retval, &context);

			(void)vnode_put(vp);
		}
		goto out;

	case DTYPE_PSXSHM:
	case DTYPE_PSXSEM:
	case DTYPE_KQUEUE:
	case DTYPE_FSEVENTS:
		error = EINVAL;
		goto out;

	}
	/*NOTREACHED*/
out:
	fp_drop(p, fd, fp, 0);
	return(error);
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
	int lim, last, numfiles, oldnfiles;
	struct fileproc **newofiles, **ofiles;
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
			numfiles = NDEXTENT;
		else
			numfiles = 2 * fdp->fd_nfiles;
		/* Enforce lim */
		if (numfiles > lim)
			numfiles = lim;
		proc_fdunlock(p);
		MALLOC_ZONE(newofiles, struct fileproc **,
				numfiles * OFILESIZE, M_OFILETABL, M_WAITOK);
		proc_fdlock(p);
		if (newofiles == NULL) {
			return (ENOMEM);
		}
		if (fdp->fd_nfiles >= numfiles) {
			FREE_ZONE(newofiles, numfiles * OFILESIZE, M_OFILETABL);
			continue;
		}
		newofileflags = (char *) &newofiles[numfiles];
		/*
		 * Copy the existing ofile and ofileflags arrays
		 * and zero the new portion of each array.
		 */
		oldnfiles = fdp->fd_nfiles;
		(void) memcpy(newofiles, fdp->fd_ofiles,
				oldnfiles * sizeof *fdp->fd_ofiles);
		(void) memset(&newofiles[oldnfiles], 0,
				(numfiles - oldnfiles) * sizeof *fdp->fd_ofiles);

		(void) memcpy(newofileflags, fdp->fd_ofileflags,
				oldnfiles * sizeof *fdp->fd_ofileflags);
		(void) memset(&newofileflags[oldnfiles], 0,
				(numfiles - oldnfiles) *
						sizeof *fdp->fd_ofileflags);
		ofiles = fdp->fd_ofiles;
		fdp->fd_ofiles = newofiles;
		fdp->fd_ofileflags = newofileflags;
		fdp->fd_nfiles = numfiles;
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
	int n;
{
	struct filedesc *fdp = p->p_fd;
	struct fileproc **fpp;
	char *flags;
	int i, lim;

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

void
fddrop(p, fd)
	struct proc *p;
	int fd;
{
	struct filedesc *fdp = p->p_fd;
	struct fileproc *fp;

	if (fd < fdp->fd_freefile)
		fdp->fd_freefile = fd;
#if DIAGNOSTIC
	if (fd > fdp->fd_lastfile)
		panic("fdrelse: fd_lastfile inconsistent");
#endif
	fp = fdp->fd_ofiles[fd];
	fdp->fd_ofiles[fd] = NULL;
	fdp->fd_ofileflags[fd] = 0;

	while ((fd = fdp->fd_lastfile) > 0 &&
			fdp->fd_ofiles[fd] == NULL &&
			!(fdp->fd_ofileflags[fd] & UF_RESERVED))
		fdp->fd_lastfile--;
	FREE_ZONE(fp, sizeof *fp, M_FILEPROC);
}


int
fdgetf_noref(p, fd, resultfp)
	struct proc *p;
	int fd;
	struct fileproc **resultfp;
{
	struct filedesc *fdp = p->p_fd;
	struct fileproc *fp;

	if (fd < 0 || fd >= fdp->fd_nfiles ||
			(fp = fdp->fd_ofiles[fd]) == NULL ||
			(fdp->fd_ofileflags[fd] & UF_RESERVED)) {
		return (EBADF);
	}
	if (resultfp)
		*resultfp = fp;
	return (0);
}


/* should be called only when proc_fdlock is held */
void
fp_setflags(proc_t p, struct fileproc * fp, int flags)
{
	proc_fdlock(p);
	fp->f_flags |= flags;
	proc_fdunlock(p);
}

void
fp_clearflags(proc_t p, struct fileproc * fp, int flags)
{

	proc_fdlock(p);
	if (fp)
		fp->f_flags &= ~flags;
	proc_fdunlock(p);
}

int
fp_getfvp(p, fd, resultfp, resultvp)
	struct proc *p;
	int fd;
	struct fileproc **resultfp;
	struct vnode  **resultvp;
{
	struct filedesc *fdp = p->p_fd;
	struct fileproc *fp;

	proc_fdlock(p);
	if (fd < 0 || fd >= fdp->fd_nfiles ||
			(fp = fdp->fd_ofiles[fd]) == NULL ||
			(fdp->fd_ofileflags[fd] & UF_RESERVED)) {
		proc_fdunlock(p);
		return (EBADF);
	}
	if (fp->f_type != DTYPE_VNODE) {
		proc_fdunlock(p);
		return(ENOTSUP);
	}
	fp->f_iocount++;

	if (resultfp)
		*resultfp = fp;
	if (resultvp)
		*resultvp = (struct vnode *)fp->f_data;
	proc_fdunlock(p);

	return (0);
}


/*
 * Returns:	EBADF			The file descriptor is invalid
 *		EOPNOTSUPP		The file descriptor is not a socket
 *		0			Success
 *
 * Notes:	EOPNOTSUPP should probably be ENOTSOCK; this function is only
 *		ever called from accept1().
 */
int
fp_getfsock(p, fd, resultfp, results)
	struct proc *p;
	int fd;
	struct fileproc **resultfp;
	struct socket  **results;
{
	struct filedesc *fdp = p->p_fd;
	struct fileproc *fp;

	proc_fdlock(p);
	if (fd < 0 || fd >= fdp->fd_nfiles ||
			(fp = fdp->fd_ofiles[fd]) == NULL ||
			(fdp->fd_ofileflags[fd] & UF_RESERVED)) {
		proc_fdunlock(p);
		return (EBADF);
	}
	if (fp->f_type != DTYPE_SOCKET) {
		proc_fdunlock(p);
		return(EOPNOTSUPP);
	}
	fp->f_iocount++;

	if (resultfp)
		*resultfp = fp;
	if (results)
		*results = (struct socket *)fp->f_data;
	proc_fdunlock(p);

	return (0);
}


int
fp_getfkq(p, fd, resultfp, resultkq)
	struct proc *p;
	int fd;
	struct fileproc **resultfp;
	struct kqueue  **resultkq;
{
	struct filedesc *fdp = p->p_fd;
	struct fileproc *fp;

	proc_fdlock(p);
	if ( fd < 0 || fd >= fdp->fd_nfiles ||
			(fp = fdp->fd_ofiles[fd]) == NULL ||
			(fdp->fd_ofileflags[fd] & UF_RESERVED)) {
		proc_fdunlock(p);
		return (EBADF);
	}
	if (fp->f_type != DTYPE_KQUEUE) {
		proc_fdunlock(p);
		return(EBADF);
	}
	fp->f_iocount++;

	if (resultfp)
		*resultfp = fp;
	if (resultkq)
		*resultkq = (struct kqueue *)fp->f_data;
	proc_fdunlock(p);

	return (0);
}

int
fp_getfpshm(p, fd, resultfp, resultpshm)
	struct proc *p;
	int fd;
	struct fileproc **resultfp;
	struct pshmnode  **resultpshm;
{
	struct filedesc *fdp = p->p_fd;
	struct fileproc *fp;

	proc_fdlock(p);
	if (fd < 0 || fd >= fdp->fd_nfiles ||
			(fp = fdp->fd_ofiles[fd]) == NULL ||
			(fdp->fd_ofileflags[fd] & UF_RESERVED)) {
		proc_fdunlock(p);
		return (EBADF);
	}
	if (fp->f_type != DTYPE_PSXSHM) {

		proc_fdunlock(p);
		return(EBADF);
	}
	fp->f_iocount++;

	if (resultfp)
		*resultfp = fp;
	if (resultpshm)
		*resultpshm = (struct pshmnode *)fp->f_data;
	proc_fdunlock(p);

	return (0);
}


int
fp_getfpsem(p, fd, resultfp, resultpsem)
	struct proc *p;
	int fd;
	struct fileproc **resultfp;
	struct psemnode  **resultpsem;
{
	struct filedesc *fdp = p->p_fd;
	struct fileproc *fp;

	proc_fdlock(p);
	if (fd < 0 || fd >= fdp->fd_nfiles ||
			(fp = fdp->fd_ofiles[fd]) == NULL ||
			(fdp->fd_ofileflags[fd] & UF_RESERVED)) {
		proc_fdunlock(p);
		return (EBADF);
	}
	if (fp->f_type != DTYPE_PSXSEM) {
		proc_fdunlock(p);
		return(EBADF);
	}
	fp->f_iocount++;

	if (resultfp)
		*resultfp = fp;
	if (resultpsem)
		*resultpsem = (struct psemnode *)fp->f_data;
	proc_fdunlock(p);

	return (0);
}
int
fp_lookup(p, fd, resultfp, locked)
	struct proc *p;
	int fd;
	struct fileproc **resultfp;
	int locked;
{
	struct filedesc *fdp = p->p_fd;
	struct fileproc *fp;

	if (!locked)
		proc_fdlock(p);
	if (fd < 0 || fd >= fdp->fd_nfiles ||
			(fp = fdp->fd_ofiles[fd]) == NULL ||
			(fdp->fd_ofileflags[fd] & UF_RESERVED)) {
		if (!locked)
			proc_fdunlock(p);
		return (EBADF);
	}
	fp->f_iocount++;

	if (resultfp)
		*resultfp = fp;
	if (!locked)
		proc_fdunlock(p);
		
	return (0);
}

int
fp_drop_written(proc_t p, int fd, struct fileproc *fp)
{
        int error;

	proc_fdlock(p);

	fp->f_flags |= FP_WRITTEN;
	
	error = fp_drop(p, fd, fp, 1);

	proc_fdunlock(p);
		
	return (error);
}


int
fp_drop_event(proc_t p, int fd, struct fileproc *fp)
{
        int error;

	proc_fdlock(p);

	fp->f_flags |= FP_WAITEVENT;
	
	error = fp_drop(p, fd, fp, 1);

	proc_fdunlock(p);
		
	return (error);
}

int
fp_drop(p, fd, fp, locked)
	struct proc *p;
	int fd;
	struct fileproc *fp;
	int locked;
{
	struct filedesc *fdp = p->p_fd;

	if (!locked)
		proc_fdlock(p);
	 if ((fp == FILEPROC_NULL) && (fd < 0 || fd >= fdp->fd_nfiles ||
			(fp = fdp->fd_ofiles[fd]) == NULL ||
			((fdp->fd_ofileflags[fd] & UF_RESERVED) &&
			 !(fdp->fd_ofileflags[fd] & UF_CLOSING)))) {
		if (!locked)
			proc_fdunlock(p);
		return (EBADF);
	}
	fp->f_iocount--;

	if (p->p_fpdrainwait && fp->f_iocount == 0) {
	        p->p_fpdrainwait = 0;
	        wakeup(&p->p_fpdrainwait);
	}
	if (!locked)
		proc_fdunlock(p);
		
	return (0);
}

int
file_vnode(int fd, struct vnode **vpp)
{
	struct proc * p = current_proc();
	struct fileproc *fp;
	int error;
	
	proc_fdlock(p);
	if ( (error = fp_lookup(p, fd, &fp, 1)) ) {
		proc_fdunlock(p);
		return(error);
	}
	if (fp->f_type != DTYPE_VNODE) {
		fp_drop(p, fd, fp,1);
		proc_fdunlock(p);
		return(EINVAL);
	}
	*vpp = (struct vnode *)fp->f_data;
	proc_fdunlock(p);

	return(0);
}


int
file_socket(int fd, struct socket **sp)
{
	struct proc * p = current_proc();
	struct fileproc *fp;
	int error;
	
	proc_fdlock(p);
	if ( (error = fp_lookup(p, fd, &fp, 1)) ) {
		proc_fdunlock(p);
		return(error);
	}
	if (fp->f_type != DTYPE_SOCKET) {
		fp_drop(p, fd, fp,1);
		proc_fdunlock(p);
		return(ENOTSOCK);
	}
	*sp = (struct socket *)fp->f_data;
	proc_fdunlock(p);

	return(0);
}

int
file_flags(int fd, int * flags)
{

	struct proc * p = current_proc();
	struct fileproc *fp;
	int error;
	
	proc_fdlock(p);
	if ( (error = fp_lookup(p, fd, &fp, 1)) ) {
		proc_fdunlock(p);
		return(error);
	}
	*flags = (int)fp->f_flag;
	fp_drop(p, fd, fp,1);
	proc_fdunlock(p);

	return(0);
}


int 
file_drop(int fd)
{
	struct fileproc *fp;
	struct proc *p = current_proc();

	proc_fdlock(p);
	if (fd < 0 || fd >= p->p_fd->fd_nfiles ||
			(fp = p->p_fd->fd_ofiles[fd]) == NULL ||
			((p->p_fd->fd_ofileflags[fd] & UF_RESERVED) &&
			 !(p->p_fd->fd_ofileflags[fd] & UF_CLOSING))) {
		proc_fdunlock(p);
		return (EBADF);
	}
	fp->f_iocount --;

	if (p->p_fpdrainwait && fp->f_iocount == 0) {
	        p->p_fpdrainwait = 0;
	        wakeup(&p->p_fpdrainwait);
	}
	proc_fdunlock(p);
	return(0);


}

int
falloc(p, resultfp, resultfd )
	struct proc *p;
	struct fileproc **resultfp;
	int *resultfd;
{
	int error;

	proc_fdlock(p);
	error = falloc_locked(p, resultfp, resultfd, 1);
	proc_fdunlock(p);

	return(error);
}
/*
 * Create a new open file structure and allocate
 * a file decriptor for the process that refers to it.
 */
int
falloc_locked(p, resultfp, resultfd, locked)
	struct proc *p;
	struct fileproc **resultfp;
	int *resultfd;
	int locked;
{
	struct fileproc *fp, *fq;
	struct fileglob *fg;
	int error, nfd;

	if (!locked)
		proc_fdlock(p);
	if ( (error = fdalloc(p, 0, &nfd)) ) {
		if (!locked)
			proc_fdunlock(p);
		return (error);
	}
	if (nfiles >= maxfiles) {
		if (!locked)
			proc_fdunlock(p);
		tablefull("file");
		return (ENFILE);
	}
	/*
	 * Allocate a new file descriptor.
	 * If the process has file descriptor zero open, add to the list
	 * of open files at that point, otherwise put it at the front of
	 * the list of open files.
	 */
	proc_fdunlock(p);

	MALLOC_ZONE(fp, struct fileproc *, sizeof(struct fileproc), M_FILEPROC, M_WAITOK);
	MALLOC_ZONE(fg, struct fileglob *, sizeof(struct fileglob), M_FILEGLOB, M_WAITOK);
	bzero(fp, sizeof(struct fileproc));
	bzero(fg, sizeof(struct fileglob));
	lck_mtx_init(&fg->fg_lock, file_lck_grp, file_lck_attr);

	fp->f_iocount = 1;
	fg->fg_count = 1;
	fp->f_fglob = fg;

	proc_fdlock(p);

	fp->f_cred = kauth_cred_proc_ref(p);

	lck_mtx_lock(file_flist_lock);

	nfiles++;

	if ( (fq = p->p_fd->fd_ofiles[0]) ) {
		LIST_INSERT_AFTER(fq->f_fglob, fg, f_list);
	} else {
		LIST_INSERT_HEAD(&filehead, fg, f_list);
	}
	lck_mtx_unlock(file_flist_lock);

	p->p_fd->fd_ofiles[nfd] = fp;

	if (!locked)
		proc_fdunlock(p);

	if (resultfp)
		*resultfp = fp;
	if (resultfd)
		*resultfd = nfd;

	return (0);
}

/*
 * Free a file structure.
 */
void
fg_free(fg)
	struct fileglob *fg;
{
	kauth_cred_t cred;

	lck_mtx_lock(file_flist_lock);
	LIST_REMOVE(fg, f_list);
	nfiles--;
	lck_mtx_unlock(file_flist_lock);

	cred = fg->fg_cred;
	if (cred != NOCRED) {
		fg->fg_cred = NOCRED;
		kauth_cred_rele(cred);
	}
	lck_mtx_destroy(&fg->fg_lock, file_lck_grp);

	FREE_ZONE(fg, sizeof *fg, M_FILEGLOB);
}

void
fdexec(p)
	struct proc *p;
{
	struct filedesc *fdp = p->p_fd;
	int i = fdp->fd_lastfile;
	struct fileproc **fpp = &fdp->fd_ofiles[i];
	char *flags = &fdp->fd_ofileflags[i];
	int funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, FALSE);
	proc_fdlock(p);

	while (i >= 0) {
		if ((*flags & (UF_RESERVED|UF_EXCLOSE)) == UF_EXCLOSE) {
			struct fileproc *fp = *fpp;

                        if (i < fdp->fd_knlistsize)
                                knote_fdclose(p, i);

			*fpp = NULL; *flags = 0;
			if (i == fdp->fd_lastfile && i > 0)
				fdp->fd_lastfile--;
			closef_locked(fp, fp->f_fglob, p);
			FREE_ZONE(fp, sizeof *fp, M_FILEPROC);
		}

		i--; fpp--; flags--;
	}
	proc_fdunlock(p);
	thread_funnel_set(kernel_flock, funnel_state);
}

/*
 * Copy a filedesc structure.
 */
struct filedesc *
fdcopy(p)
	struct proc *p;
{
	struct filedesc *newfdp, *fdp = p->p_fd;
	int i;
	struct fileproc *ofp, *fp;
	vnode_t	v_dir;

	MALLOC_ZONE(newfdp, struct filedesc *,
			sizeof *newfdp, M_FILEDESC, M_WAITOK);
	if (newfdp == NULL)
		return(NULL);

	proc_fdlock(p);

	/*
	 * the FD_CHROOT flag will be inherited via this copy
	 */
	(void) memcpy(newfdp, fdp, sizeof *newfdp);

	/*
	 * for both fd_cdir and fd_rdir make sure we get
	 * a valid reference... if we can't, than set
	 * set the pointer(s) to NULL in the child... this
	 * will keep us from using a non-referenced vp
	 * and allows us to do the vnode_rele only on
	 * a properly referenced vp
	 */
	if ( (v_dir = newfdp->fd_cdir) ) {
	        if (vnode_getwithref(v_dir) == 0) {
		        if ( (vnode_ref(v_dir)) )
			        newfdp->fd_cdir = NULL;
			vnode_put(v_dir);
		} else
		        newfdp->fd_cdir = NULL;
	}
	if (newfdp->fd_cdir == NULL && fdp->fd_cdir) {
	        /*
		 * we couldn't get a new reference on
		 * the current working directory being
		 * inherited... we might as well drop
		 * our reference from the parent also
		 * since the vnode has gone DEAD making
		 * it useless... by dropping it we'll
		 * be that much closer to recyling it
		 */
	        vnode_rele(fdp->fd_cdir);
		fdp->fd_cdir = NULL;
	}

	if ( (v_dir = newfdp->fd_rdir) ) {
		if (vnode_getwithref(v_dir) == 0) {
			if ( (vnode_ref(v_dir)) )
			        newfdp->fd_rdir = NULL;
			vnode_put(v_dir);
		} else
		        newfdp->fd_rdir = NULL;
	}
	if (newfdp->fd_rdir == NULL && fdp->fd_rdir) {
	        /*
		 * we couldn't get a new reference on
		 * the root directory being
		 * inherited... we might as well drop
		 * our reference from the parent also
		 * since the vnode has gone DEAD making
		 * it useless... by dropping it we'll
		 * be that much closer to recyling it
		 */
	        vnode_rele(fdp->fd_rdir);
		fdp->fd_rdir = NULL;
	}
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
	proc_fdunlock(p);

	MALLOC_ZONE(newfdp->fd_ofiles, struct fileproc **,
				i * OFILESIZE, M_OFILETABL, M_WAITOK);
	if (newfdp->fd_ofiles == NULL) {
		if (newfdp->fd_cdir)
		        vnode_rele(newfdp->fd_cdir);
		if (newfdp->fd_rdir)
			vnode_rele(newfdp->fd_rdir);

		FREE_ZONE(newfdp, sizeof *newfdp, M_FILEDESC);
		return(NULL);
	}
	proc_fdlock(p);

	newfdp->fd_ofileflags = (char *) &newfdp->fd_ofiles[i];
	newfdp->fd_nfiles = i;

	if (fdp->fd_nfiles > 0) {
		struct fileproc **fpp;
		char *flags;

		(void) memcpy(newfdp->fd_ofiles, fdp->fd_ofiles,
					i * sizeof *fdp->fd_ofiles);
		(void) memcpy(newfdp->fd_ofileflags, fdp->fd_ofileflags,
					i * sizeof *fdp->fd_ofileflags);

		/*
		 * kq descriptors cannot be copied.
		 */
		if (newfdp->fd_knlistsize != -1) {
			fpp = &newfdp->fd_ofiles[newfdp->fd_lastfile];
			for (i = newfdp->fd_lastfile; i >= 0; i--, fpp--) {
				if (*fpp != NULL && (*fpp)->f_type == DTYPE_KQUEUE) {
					*fpp = NULL;
					if (i < newfdp->fd_freefile)
						newfdp->fd_freefile = i;
				}
				if (*fpp == NULL && i == newfdp->fd_lastfile && i > 0)
					newfdp->fd_lastfile--;
			}
			newfdp->fd_knlist = NULL;
			newfdp->fd_knlistsize = -1;
			newfdp->fd_knhash = NULL;
			newfdp->fd_knhashmask = 0;
		}
		fpp = newfdp->fd_ofiles;
		flags = newfdp->fd_ofileflags;

		for (i = newfdp->fd_lastfile; i-- >= 0; fpp++, flags++)
			if ((ofp = *fpp) != NULL && !(*flags & UF_RESERVED)) {
				MALLOC_ZONE(fp, struct fileproc *, sizeof(struct fileproc), M_FILEPROC, M_WAITOK);
				bzero(fp, sizeof(struct fileproc));
				fp->f_flags = ofp->f_flags;
				//fp->f_iocount = ofp->f_iocount;
				fp->f_iocount = 0;
				fp->f_fglob = ofp->f_fglob;
				(void)fg_ref(fp);
				*fpp = fp;
			} else {
				*fpp = NULL;
				*flags = 0;
			}
	} else
		(void) memset(newfdp->fd_ofiles, 0, i * OFILESIZE);

	proc_fdunlock(p);
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
	struct fileproc *fp;
	int i;

	proc_fdlock(p);

	/* Certain daemons might not have file descriptors */
	fdp = p->p_fd;

	if ((fdp == NULL) || (--fdp->fd_refcnt > 0)) {
	        proc_fdunlock(p);
		return;
	}
	if (fdp->fd_refcnt == 0xffff)
	        panic("fdfree: bad fd_refcnt");

	/* Last reference: the structure can't change out from under us */

	if (fdp->fd_nfiles > 0 && fdp->fd_ofiles) {
	        for (i = fdp->fd_lastfile; i >= 0; i--) {
			if ((fp = fdp->fd_ofiles[i]) != NULL) {
			  
			  if (fdp->fd_ofileflags[i] & UF_RESERVED)
			    panic("fdfree: found fp with UF_RESERVED\n");

				/* closef drops the iocount ... */
				if ((fp->f_flags & FP_INCHRREAD) != 0) 
					fp->f_iocount++;
			    fdp->fd_ofiles[i] = NULL;
				fdp->fd_ofileflags[i] |= UF_RESERVED;

				if (i < fdp->fd_knlistsize)
					knote_fdclose(p, i);
				if (fp->f_flags & FP_WAITEVENT) 
					(void)waitevent_close(p, fp);
				(void) closef_locked(fp, fp->f_fglob, p);
				FREE_ZONE(fp, sizeof *fp, M_FILEPROC);
			}
		}
		FREE_ZONE(fdp->fd_ofiles, fdp->fd_nfiles * OFILESIZE, M_OFILETABL);
		fdp->fd_ofiles = NULL;
		fdp->fd_nfiles = 0;
	}        

	proc_fdunlock(p);
	
	if (fdp->fd_cdir)
	        vnode_rele(fdp->fd_cdir);
	if (fdp->fd_rdir)
		vnode_rele(fdp->fd_rdir);

	proc_fdlock(p);
	p->p_fd = NULL;
	proc_fdunlock(p);

	if (fdp->fd_knlist)
		FREE(fdp->fd_knlist, M_KQUEUE);
	if (fdp->fd_knhash)
		FREE(fdp->fd_knhash, M_KQUEUE);

	FREE_ZONE(fdp, sizeof *fdp, M_FILEDESC);
}

static int
closef_finish(fp, fg, p)
	struct fileproc *fp;
	struct fileglob *fg;
	struct proc *p;
{
	struct vnode *vp;
	struct flock lf;
	int error;
	struct vfs_context context;

	if ((fg->fg_flag & FHASLOCK) && fg->fg_type == DTYPE_VNODE) {
		lf.l_whence = SEEK_SET;
		lf.l_start = 0;
		lf.l_len = 0;
		lf.l_type = F_UNLCK;
		vp = (struct vnode *)fg->fg_data;
		context.vc_proc = p;
		context.vc_ucred = fg->fg_cred;

		(void) VNOP_ADVLOCK(vp, (caddr_t)fg, F_UNLCK, &lf, F_FLOCK, &context);
	}
	if (fg->fg_ops)
		error = fo_close(fg, p);
	else
		error = 0;

	if (((fp != (struct fileproc *)0) && ((fp->f_flags & FP_INCHRREAD) != 0))) {
	        proc_fdlock(p);
		if ( ((fp->f_flags & FP_INCHRREAD) != 0) ) {
		        fileproc_drain(p, fp);
		}
		proc_fdunlock(p);
	}
	fg_free(fg);

	return (error);
}

int
closef(fg, p)
	struct fileglob *fg;
	struct proc *p;
{
	int error;

	proc_fdlock(p);
	error = closef_locked((struct fileproc *)0, fg, p);
	proc_fdunlock(p);

	return(error);
}
/*
 * Internal form of close.
 * Decrement reference count on file structure.
 * Note: p may be NULL when closing a file
 * that was being passed in a message.
 */
int
closef_locked(fp, fg, p)
	struct fileproc *fp;
	struct fileglob *fg;
	struct proc *p;
{
	struct vnode *vp;
	struct flock lf;
	struct vfs_context context;
	int error;

	if (fg == NULL) {
		return (0);
	}
	/*
	 * POSIX record locking dictates that any close releases ALL
	 * locks owned by this process.  This is handled by setting
	 * a flag in the unlock to free ONLY locks obeying POSIX
	 * semantics, and not to free BSD-style file locks.
	 * If the descriptor was in a message, POSIX-style locks
	 * aren't passed with the descriptor.
	 */
	if (p && (p->p_ladvflag & P_LADVLOCK) && fg->fg_type == DTYPE_VNODE) {
		proc_fdunlock(p);

		lf.l_whence = SEEK_SET;
		lf.l_start = 0;
		lf.l_len = 0;
		lf.l_type = F_UNLCK;
		vp = (struct vnode *)fg->fg_data;

		if ( (error = vnode_getwithref(vp)) == 0 ) {
		        context.vc_proc = p;
			context.vc_ucred = fg->fg_cred;
			(void) VNOP_ADVLOCK(vp, (caddr_t)p, F_UNLCK, &lf, F_POSIX, &context);

			(void)vnode_put(vp);
		}
		proc_fdlock(p);
	}
	lck_mtx_lock(&fg->fg_lock);
	fg->fg_count--;

	if (fg->fg_count > 0) {
		lck_mtx_unlock(&fg->fg_lock);
		return (0);
	}
	if (fg->fg_count != 0)
		panic("fg: being freed with bad fg_count (%d)", fg, fg->fg_count);

	if (fp && (fp->f_flags & FP_WRITTEN))
	        fg->fg_flag |= FWASWRITTEN;

	fg->fg_lflags |= FG_TERM;
	lck_mtx_unlock(&fg->fg_lock);

	proc_fdunlock(p);
	error = closef_finish(fp, fg, p);
	proc_fdlock(p);

	return(error);
}


extern int selwait;
void
fileproc_drain(struct proc *p, struct fileproc * fp)
{
	fp->f_iocount-- ; /* (the one the close holds) */

	while (fp->f_iocount) {
		if (((fp->f_flags & FP_INSELECT)== FP_INSELECT)) {
			wait_queue_wakeup_all((wait_queue_t)fp->f_waddr, &selwait, THREAD_INTERRUPTED);
		} else  {
			if (fp->f_fglob->fg_ops->fo_drain) {
				(*fp->f_fglob->fg_ops->fo_drain)(fp, p);
			}
		}
		p->p_fpdrainwait = 1;

		msleep(&p->p_fpdrainwait, &p->p_fdmlock, PRIBIO, "fpdrain",0);

		//panic("successful wait after drain\n");
	}
}

int
fp_free(struct proc * p, int fd, struct fileproc * fp)
{
        proc_fdlock(p);
	fdrelse(p, fd);
        proc_fdunlock(p);

	fg_free(fp->f_fglob);
	FREE_ZONE(fp, sizeof *fp, M_FILEPROC);
}


/*
 * Apply an advisory lock on a file descriptor.
 *
 * Just attempt to get a record lock of the requested type on
 * the entire file (l_whence = SEEK_SET, l_start = 0, l_len = 0).
 */
int
flock(struct proc *p, register struct flock_args *uap, __unused register_t *retval)
{
	int fd = uap->fd;
	int how = uap->how;
	struct fileproc *fp;
	struct vnode *vp;
	struct flock lf;
	struct vfs_context context;
	int error=0;

	AUDIT_ARG(fd, uap->fd);
	if ( (error = fp_getfvp(p, fd, &fp, &vp)) ) {
		return(error);
	}
	if ( (error = vnode_getwithref(vp)) ) {
		goto out1;
	}
	AUDIT_ARG(vnpath, vp, ARG_VNODE1);

	context.vc_proc = p;
	context.vc_ucred = fp->f_cred;

	lf.l_whence = SEEK_SET;
	lf.l_start = 0;
	lf.l_len = 0;
	if (how & LOCK_UN) {
		lf.l_type = F_UNLCK;
		fp->f_flag &= ~FHASLOCK;
		error = VNOP_ADVLOCK(vp, (caddr_t)fp->f_fglob, F_UNLCK, &lf, F_FLOCK, &context);
		goto out;
	}
	if (how & LOCK_EX)
		lf.l_type = F_WRLCK;
	else if (how & LOCK_SH)
		lf.l_type = F_RDLCK;
	else {
	        error = EBADF;
		goto out;
	}
	fp->f_flag |= FHASLOCK;
	if (how & LOCK_NB) {
		error = VNOP_ADVLOCK(vp, (caddr_t)fp->f_fglob, F_SETLK, &lf, F_FLOCK, &context);
		goto out;	
	}
	error = VNOP_ADVLOCK(vp, (caddr_t)fp->f_fglob, F_SETLK, &lf, F_FLOCK|F_WAIT, &context);
out:
	(void)vnode_put(vp);
out1:
	fp_drop(p, fd, fp, 0);
	return(error);

}

/*
 * File Descriptor pseudo-device driver (/dev/fd/).
 *
 * Opening minor device N dup()s the file (if any) connected to file
 * descriptor N belonging to the calling process.  Note that this driver
 * consists of only the ``open()'' routine, because all subsequent
 * references to this file will be direct to the other driver.
 */
int
fdopen(dev_t dev, __unused int mode, __unused int type, struct proc *p)
{

	/*
	 * XXX Kludge: set curproc->p_dupfd to contain the value of the
	 * the file descriptor being sought for duplication. The error 
	 * return ensures that the vnode for this device will be released
	 * by vn_open. Open will detect this special error and take the
	 * actions in dupfdopen below. Other callers of vn_open or vnop_open
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
	struct fileproc *wfp;
	struct fileproc *fp;
	struct proc * p = current_proc();

	/*
	 * If the to-be-dup'd fd number is greater than the allowed number
	 * of file descriptors, or the fd to be dup'd has already been
	 * closed, reject.  Note, check for new == old is necessary as
	 * falloc could allocate an already closed to-be-dup'd descriptor
	 * as the new descriptor.
	 */
	proc_fdlock(p);

	fp = fdp->fd_ofiles[indx];
	if (dfd < 0 || dfd >= fdp->fd_nfiles ||
			(wfp = fdp->fd_ofiles[dfd]) == NULL || wfp == fp ||
	                (fdp->fd_ofileflags[dfd] & UF_RESERVED)) {

	        proc_fdunlock(p);
		return (EBADF);
	}
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
	        if (((mode & (FREAD|FWRITE)) | wfp->f_flag) != wfp->f_flag) {
		        proc_fdunlock(p);
			return (EACCES);
		}
		if (indx > fdp->fd_lastfile)
			fdp->fd_lastfile = indx;
		(void)fg_ref(wfp);

		if (fp->f_fglob)
		        fg_free(fp->f_fglob);
		fp->f_fglob = wfp->f_fglob;

		fdp->fd_ofileflags[indx] = fdp->fd_ofileflags[dfd];

	        proc_fdunlock(p);
		return (0);

	case ENXIO:
		/*
		 * Steal away the file pointer from dfd, and stuff it into indx.
		 */
		if (indx > fdp->fd_lastfile)
			fdp->fd_lastfile = indx;

		if (fp->f_fglob)
		        fg_free(fp->f_fglob);
		fp->f_fglob = wfp->f_fglob;

		fdp->fd_ofileflags[indx] = fdp->fd_ofileflags[dfd];
		_fdrelse(fdp, dfd);

	        proc_fdunlock(p);

		FREE_ZONE(wfp, sizeof *fp, M_FILEPROC);	

		return (0);

	default:
	        proc_fdunlock(p);
		return (error);
	}
	/* NOTREACHED */
}

void
fg_ref(struct fileproc * fp)
{
	struct fileglob *fg;

	fg = fp->f_fglob;

	lck_mtx_lock(&fg->fg_lock);
	fg->fg_count++;
	lck_mtx_unlock(&fg->fg_lock);
}

void
fg_drop(struct fileproc * fp)
{
	struct fileglob *fg;

	fg = fp->f_fglob;
	lck_mtx_lock(&fg->fg_lock);
	fg->fg_count--;
	lck_mtx_unlock(&fg->fg_lock);
}


void
fg_insertuipc(struct fileglob * fg)
{
int insertque = 0;

	lck_mtx_lock(&fg->fg_lock);

	while (fg->fg_lflags & FG_RMMSGQ) {
		fg->fg_lflags |= FG_WRMMSGQ;
		msleep(&fg->fg_lflags, &fg->fg_lock, 0, "fg_insertuipc", 0);
	}

	fg->fg_count++;
	fg->fg_msgcount++;
	if (fg->fg_msgcount == 1) {
		fg->fg_lflags |= FG_INSMSGQ;
		insertque=1;
	}
	lck_mtx_unlock(&fg->fg_lock);

	if (insertque) {
		lck_mtx_lock(uipc_lock);
		LIST_INSERT_HEAD(&fmsghead, fg, f_msglist);
		lck_mtx_unlock(uipc_lock);
		lck_mtx_lock(&fg->fg_lock);
		fg->fg_lflags &= ~FG_INSMSGQ;
		if (fg->fg_lflags & FG_WINSMSGQ) {
			fg->fg_lflags &= ~FG_WINSMSGQ;
			wakeup(&fg->fg_lflags);
		}
		lck_mtx_unlock(&fg->fg_lock);
	}

}

void
fg_removeuipc(struct fileglob * fg)
{
int removeque = 0;

	lck_mtx_lock(&fg->fg_lock);
	while (fg->fg_lflags & FG_INSMSGQ) {
		fg->fg_lflags |= FG_WINSMSGQ;
		msleep(&fg->fg_lflags, &fg->fg_lock, 0, "fg_removeuipc", 0);
	}
	fg->fg_msgcount--;
	if (fg->fg_msgcount == 0) {
		fg->fg_lflags |= FG_RMMSGQ;
		removeque=1;
	}
	lck_mtx_unlock(&fg->fg_lock);

	if (removeque) {
		lck_mtx_lock(uipc_lock);
		LIST_REMOVE(fg, f_msglist);
		lck_mtx_unlock(uipc_lock);
		lck_mtx_lock(&fg->fg_lock);
		fg->fg_lflags &= ~FG_RMMSGQ;
		if (fg->fg_lflags & FG_WRMMSGQ) {
			fg->fg_lflags &= ~FG_WRMMSGQ;
			wakeup(&fg->fg_lflags);
		}
		lck_mtx_unlock(&fg->fg_lock);
	}
}


int
fo_read(struct fileproc *fp, struct uio *uio, kauth_cred_t cred, int flags, struct proc *p)
{
	return ((*fp->f_ops->fo_read)(fp, uio, cred, flags, p));
}

int
fo_write(struct fileproc *fp, struct uio *uio, kauth_cred_t cred, int flags, struct proc *p)
{
	return((*fp->f_ops->fo_write)(fp, uio, cred, flags, p));
}

int 
fo_ioctl(struct fileproc *fp, u_long com, caddr_t data, struct proc *p)
{
int error;

	proc_fdunlock(p);
	error = (*fp->f_ops->fo_ioctl)(fp, com, data, p);
	proc_fdlock(p);
	return(error);
}       

int
fo_select(struct fileproc *fp, int which, void *wql, struct proc *p)
{       
	return((*fp->f_ops->fo_select)(fp, which, wql, p));
}

int
fo_close(struct fileglob *fg, struct proc *p)
{       
	return((*fg->fg_ops->fo_close)(fg, p));
}

int
fo_kqfilter(struct fileproc *fp, struct knote *kn, struct proc *p)
{
        return ((*fp->f_ops->fo_kqfilter)(fp, kn, p));
}

